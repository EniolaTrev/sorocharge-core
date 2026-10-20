//! The facilitator side of x402: `/verify`, `/settle`, and `/supported`.
//!
//! These are plain async functions operating on already-deserialized
//! request/response types, not an HTTP server — wiring them to the actual
//! `/verify`, `/settle`, `/supported` HTTP paths is left to whatever web
//! framework the embedding application already uses. This mirrors
//! `sorocharge-signer`'s own non-goal ("not a general-purpose Soroban
//! contract client" / "not a CLI"): this crate translates wire formats, it
//! does not also ship a server.

use std::collections::BTreeMap;

use sorocharge_signer::{
    network_id_hash, verify_entry, verify_transfer_effects, Address, ChargeParams, SignedEntry,
    Signer,
};
use stellar_xdr::{
    AccountId, Limits, PublicKey, ReadXdr, ScAddress, SequenceNumber, SorobanCredentials,
    TransactionEnvelope, TransactionExt, Uint256,
};

use crate::error::X402Error;
use crate::network::caip2_for_passphrase;
use crate::tx::{parse_payment_transaction, rebuild_for_settlement, sign_transaction};
use crate::types::{
    SettleRequest, SettlementResponse, SupportedKind, SupportedResponse, VerifyRequest,
    VerifyResponse,
};

/// Fallback average Stellar ledger close time, used to convert
/// `maxTimeoutSeconds` into a ledger count when a live network estimate
/// isn't available. Matches the spec's own fallback.
const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;
/// The default safety ceiling on a settlement's simulation-derived fee, per
/// the spec's suggested default.
const DEFAULT_MAX_TRANSACTION_FEE_STROOPS: i64 = 50_000;
/// The spec's required minimum inclusion buffer added to the simulated
/// resource fee.
pub const MIN_INCLUSION_BUFFER_STROOPS: i64 = 100;

/// Facilitator configuration: the fee-safety ceiling and inclusion buffer
/// the spec makes an operator-configurable circuit breaker rather than a
/// protocol constant.
///
/// # Examples
///
/// ```rust
/// use sorocharge_x402::FacilitatorConfig;
///
/// let config = FacilitatorConfig {
///     max_transaction_fee_stroops: 100_000,
///     inclusion_buffer_stroops: 200,
/// };
///
/// assert_eq!(config.max_transaction_fee_stroops, 100_000);
/// assert_eq!(config.inclusion_buffer_stroops, 200);
/// ```
#[derive(Debug, Clone)]
pub struct FacilitatorConfig {
    pub max_transaction_fee_stroops: i64,
    pub inclusion_buffer_stroops: i64,
}

impl Default for FacilitatorConfig {
    fn default() -> Self {
        Self {
            max_transaction_fee_stroops: DEFAULT_MAX_TRANSACTION_FEE_STROOPS,
            inclusion_buffer_stroops: MIN_INCLUSION_BUFFER_STROOPS,
        }
    }
}

fn credential_address(credentials: &SorobanCredentials) -> Option<Address> {
    match credentials {
        SorobanCredentials::Address(c) => Some(c.address.clone()),
        SorobanCredentials::AddressV2(c) => Some(c.address.clone()),
        SorobanCredentials::SourceAccount | SorobanCredentials::AddressWithDelegates(_) => None,
    }
}

/// The x402 facilitator: verifies and settles `exact`-scheme payments on
/// Stellar, sponsoring transaction fees from its own account.
pub struct Facilitator<'a> {
    rpc: &'a stellar_rpc_client::Client,
    signer: &'a dyn Signer,
    network_passphrase: String,
    config: FacilitatorConfig,
}

impl<'a> Facilitator<'a> {
    /// `signer` is the facilitator's own fee-paying key: the account that
    /// becomes every settled transaction's source account.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sorocharge_signer::{Address, Signer, SorochargeError};
    /// use sorocharge_x402::{Facilitator, FacilitatorConfig};
    ///
    /// struct FeePayer {
    ///     address: Address,
    /// }
    ///
    /// impl Signer for FeePayer {
    ///     fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
    ///         todo!("ed25519-sign the sha256 preimage with this fee-paying key")
    ///     }
    ///
    ///     fn address(&self) -> Address {
    ///         self.address.clone()
    ///     }
    /// }
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let rpc: stellar_rpc_client::Client = todo!("a Stellar RPC client pointed at your endpoint");
    /// # let signer = FeePayer {
    /// #     address: "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7".parse()?,
    /// # };
    /// let facilitator = Facilitator::new(
    ///     &rpc,
    ///     &signer,
    ///     "Test SDF Network ; September 2015".to_string(),
    ///     FacilitatorConfig::default(),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        signer: &'a dyn Signer,
        network_passphrase: String,
        config: FacilitatorConfig,
    ) -> Self {
        Self {
            rpc,
            signer,
            network_passphrase,
            config,
        }
    }

    fn facilitator_address(&self) -> Address {
        self.signer.address()
    }

    /// Decodes and structurally validates a payment, without touching
    /// chain state beyond a read-only simulation. Returns the parsed
    /// transaction pieces alongside the `ChargeParams` a caller can hand to
    /// `sorocharge_signer::verify_entry` — which this function has already
    /// called once, so a passing return here already carries a verified
    /// signature.
    async fn validate(
        &self,
        request: &VerifyRequest,
    ) -> Result<
        (
            stellar_xdr::Transaction,
            stellar_xdr::SorobanAuthorizationEntry,
            ChargeParams,
        ),
        X402Error,
    > {
        if request.x402_version != 2 {
            return Err(X402Error::InvalidPaymentPayload {
                reason: format!("unsupported x402Version {}", request.x402_version),
            });
        }
        if request.payment_payload.accepted.scheme != "exact"
            || request.payment_requirements.scheme != "exact"
        {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "expected scheme \"exact\"".to_string(),
            });
        }
        if request.payment_payload.accepted.network != request.payment_requirements.network {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "payload.accepted.network does not match paymentRequirements.network"
                    .to_string(),
            });
        }
        let expected_network = caip2_for_passphrase(&self.network_passphrase)?;
        if request.payment_requirements.network != expected_network {
            return Err(X402Error::UnsupportedNetwork {
                network: request.payment_requirements.network.clone(),
            });
        }

        let envelope = TransactionEnvelope::from_xdr_base64(
            &request.payment_payload.payload.transaction,
            Limits::none(),
        )
        .map_err(|e| X402Error::XdrDecodingFailed {
            reason: e.to_string(),
        })?;
        let (transfer, tx, auth_entry) = parse_payment_transaction(&envelope)?;

        let facilitator = self.facilitator_address();
        if let Some(op) = tx.operations.first() {
            if let Some(op_source) = &op.source_account {
                if tx_source_matches(op_source, &facilitator) {
                    return Err(X402Error::FacilitatorAddressConflict);
                }
            }
        }
        if tx_source_matches(&tx.source_account, &facilitator) {
            return Err(X402Error::FacilitatorAddressConflict);
        }
        if transfer.from == facilitator {
            return Err(X402Error::FacilitatorAddressConflict);
        }
        if credential_address(&auth_entry.credentials).as_ref() == Some(&facilitator) {
            return Err(X402Error::FacilitatorAddressConflict);
        }

        let requirements = &request.payment_requirements;
        let asset_contract =
            requirements
                .asset
                .parse()
                .map_err(|_| X402Error::InvalidPaymentPayload {
                    reason: format!("invalid asset address: {}", requirements.asset),
                })?;
        let amount = requirements
            .amount
            .parse()
            .map_err(|_| X402Error::InvalidPaymentPayload {
                reason: format!("invalid amount: {}", requirements.amount),
            })?;
        let recipient =
            requirements
                .pay_to
                .parse()
                .map_err(|_| X402Error::InvalidPaymentPayload {
                    reason: format!("invalid payTo address: {}", requirements.pay_to),
                })?;

        if transfer.asset_contract != asset_contract
            || transfer.amount != amount
            || transfer.to != recipient
        {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "transaction's transfer does not match paymentRequirements".to_string(),
            });
        }

        let current_ledger = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?
            .sequence;

        // The spec: "the auth entry expiration ledger MUST NOT exceed
        // currentLedger + ceil(maxTimeoutSeconds / estimatedLedgerSeconds)."
        // This is also what verify_entry's ExpirationExceedsAllowance check
        // enforces against expected.valid_until_ledger, so it has to be the
        // real cap, not a placeholder.
        let max_timeout_ledgers = requirements
            .max_timeout_seconds
            .div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS);
        let valid_until_ledger =
            // max_timeout_ledgers is the result of dividing max_timeout_seconds by
            // 5 (estimated ledger seconds). The result fits in u32 because even
            // very large timeout values (e.g. 2^31-1 seconds / 5 ≈ 4e8) still
            // produce a value that fits, but we defensively cap at u32::MAX
            // rather than error out, since the downstream verify_entry check
            // against valid_until_ledger will still catch any genuine overflow.
            current_ledger.saturating_add(u32::try_from(max_timeout_ledgers).unwrap_or(u32::MAX));

        let params = ChargeParams {
            asset_contract,
            amount,
            payer: transfer.from.clone(),
            recipient,
            valid_until_ledger,
        };
        verify_entry(
            &SignedEntry::from_xdr(auth_entry.clone()),
            &params,
            current_ledger,
            &self.network_passphrase,
        )
        .map_err(|e| X402Error::InvalidPaymentPayload {
            reason: e.to_string(),
        })?;

        let simulation = self
            .rpc
            .simulate_transaction_envelope(&envelope, None)
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        if let Some(error) = simulation.error {
            return Err(X402Error::InvalidPaymentPayload {
                reason: format!("simulation failed: {error}"),
            });
        }
        verify_transfer_effects(
            &simulation.events,
            &params.asset_contract,
            &params.payer,
            &params.recipient,
            params.amount,
        )
        .map_err(|e| X402Error::InvalidPaymentPayload {
            reason: e.to_string(),
        })?;

        Ok((tx, auth_entry, params))
    }

    /// `POST /verify`: read-only validation, per spec §7.1.
    pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, X402Error> {
        match self.validate(request).await {
            Ok((_, _, params)) => Ok(VerifyResponse {
                is_valid: true,
                invalid_reason: None,
                payer: Some(params.payer.to_string()),
            }),
            Err(e) => Ok(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(e.to_string()),
                payer: None,
            }),
        }
    }

    /// `POST /settle`: performs full verification independently (per spec:
    /// "`/settle` MUST NOT assume prior verification"), then rebuilds the
    /// transaction with the facilitator as source account, re-simulates to
    /// derive a fresh fee and resource footprint, signs, submits, and polls
    /// for confirmation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sorocharge_signer::{Address, Signer, SorochargeError};
    /// use sorocharge_x402::{Facilitator, FacilitatorConfig, SettleRequest, StellarExtra, PaymentPayload, PaymentRequirements, StellarPayload};
    ///
    /// struct FeePayer {
    ///     address: Address,
    /// }
    ///
    /// impl Signer for FeePayer {
    ///     fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
    ///         Ok([0u8; 64])
    ///     }
    ///
    ///     fn address(&self) -> Address {
    ///         self.address.clone()
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let rpc = stellar_rpc_client::Client::new("https://soroban-testnet.stellar.org:443")?;
    ///     let signer = FeePayer {
    ///         address: "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7".parse()?,
    ///     };
    ///     let facilitator = Facilitator::new(
    ///         &rpc,
    ///         &signer,
    ///         "Test SDF Network ; September 2015".to_string(),
    ///         FacilitatorConfig::default(),
    ///     );
    ///
    ///     let requirements = PaymentRequirements {
    ///         scheme: "exact".to_string(),
    ///         network: "stellar:testnet".to_string(),
    ///         amount: "42000000".to_string(),
    ///         asset: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH".to_string(),
    ///         pay_to: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N".to_string(),
    ///         max_timeout_seconds: 60,
    ///         extra: StellarExtra { are_fees_sponsored: true },
    ///     };
    ///     let request = SettleRequest {
    ///         x402_version: 2,
    ///         payment_payload: PaymentPayload {
    ///             x402_version: 2,
    ///             resource: None,
    ///             accepted: requirements.clone(),
    ///             payload: StellarPayload { transaction: "AAAAAgAAAAA=".to_string() },
    ///             extensions: serde_json::Map::new(),
    ///         },
    ///         payment_requirements: requirements,
    ///     };
    ///
    ///     let _response = facilitator.settle(&request).await;
    ///     Ok(())
    /// }
    /// ```
    pub async fn settle(&self, request: &SettleRequest) -> Result<SettlementResponse, X402Error> {
        let network = request.payment_requirements.network.clone();
        let (tx, _auth_entry, params) = match self.validate(request).await {
            Ok(v) => v,
            Err(e) => {
                return Ok(SettlementResponse {
                    success: false,
                    error_reason: Some(e.to_string()),
                    payer: None,
                    transaction: String::new(),
                    network,
                    amount: None,
                });
            }
        };

        let ScAddress::Account(facilitator_account_id) = self.facilitator_address() else {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some("facilitator signer must be an Ed25519 account".to_string()),
                payer: None,
                transaction: String::new(),
                network,
                amount: None,
            });
        };

        let account = self
            .rpc
            .get_account(&self.facilitator_address().to_string())
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        let next_seq_num = SequenceNumber(account.seq_num.0 + 1);

        // Refresh Soroban resource data and fee from a settle-time
        // simulation of the tx as the facilitator will actually submit it
        // (same operations/auth, facilitator source/sequence).
        let unsigned_for_sim = rebuild_for_settlement(
            &tx,
            facilitator_account_id.clone(),
            0,
            next_seq_num.clone(),
            TransactionExt::V0,
        );
        let sim_envelope = TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
            tx: unsigned_for_sim,
            signatures: Default::default(),
        });
        let simulation = self
            .rpc
            .simulate_transaction_envelope(&sim_envelope, None)
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        if let Some(error) = simulation.error {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some(format!("settlement simulation failed: {error}")),
                payer: Some(params.payer.to_string()),
                transaction: String::new(),
                network,
                amount: None,
            });
        }
        if let Err(e) = verify_transfer_effects(
            &simulation.events,
            &params.asset_contract,
            &params.payer,
            &params.recipient,
            params.amount,
        ) {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some(format!("settlement effects rejected: {e}")),
                payer: Some(params.payer.to_string()),
                transaction: String::new(),
                network,
                amount: None,
            });
        }

        let fee = i64::try_from(simulation.min_resource_fee)
            .unwrap_or(i64::MAX)
            // simulation.min_resource_fee is u64; i64::MAX is 9.2e18 while
            // u64::MAX is 1.8e19, so the conversion can lose the top bit.
            // However, realistic Stellar resource fees are always orders of
            // magnitude below this ceiling. The unwrap_or(i64::MAX) ensures we
            // never silently saturate to a wrong value; instead we get i64::MAX
            // which will then fail the fee > ceiling check (since 2^63-1 > 50_000),
            // causing the settlement to be refused rather than submitting a
            // transaction with a spuriously high fee.
            .saturating_add(self.config.inclusion_buffer_stroops);
        if fee > self.config.max_transaction_fee_stroops {
            return Err(X402Error::FeeExceedsCeiling {
                fee_stroops: fee,
                ceiling_stroops: self.config.max_transaction_fee_stroops,
            });
        }
        let soroban_data = stellar_xdr::SorobanTransactionData::from_xdr_base64(
            &simulation.transaction_data,
            Limits::none(),
        )
        .map_err(|e| X402Error::XdrDecodingFailed {
            reason: e.to_string(),
        })?;

        let final_tx = rebuild_for_settlement(
            &tx,
            facilitator_account_id,
            u32::try_from(fee).unwrap_or(u32::MAX), // fee is i64 from the simulation + inclusion buffer. u32::MAX is
            // 4.3e9 stroops (~0.039 XLM). Real Stellar fees are typically
            // < 10_000 stroops. unwrap_or(u32::MAX) ensures we never silently
            // saturate a fee that's genuinely too high; the FeeExceedsCeiling
            // check above will already have refused such cases. If fee somehow
            // exceeds u32::MAX (extremely unlikely), the transaction won't be
            // submited with an maximal fee rather than erroring out of band.
            next_seq_num,
            TransactionExt::V1(soroban_data),
        );

        let network_id = network_id_hash(&self.network_passphrase);
        let signed_envelope = sign_transaction(final_tx, self.signer, network_id)?;
        let TransactionEnvelope::Tx(signed_v1) = &signed_envelope else {
            unreachable!("sign_transaction always returns a v1 envelope")
        };

        let response = self
            .rpc
            .send_transaction_polling(&TransactionEnvelope::Tx(signed_v1.clone()))
            .await
            .map_err(|e| X402Error::SettlementFailed {
                reason: e.to_string(),
            })?;

        let transaction_hash = response.tx_hash.unwrap_or_default();
        Ok(SettlementResponse {
            success: response.status == "SUCCESS",
            error_reason: if response.status == "SUCCESS" {
                None
            } else {
                Some(response.status)
            },
            payer: Some(params.payer.to_string()),
            transaction: transaction_hash,
            network,
            amount: Some(params.amount.to_string()),
        })
    }

    /// `GET /supported`: advertises `exact` on whichever Stellar network
    /// this facilitator instance was configured for, and its own signer
    /// address.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sorocharge_x402::{Facilitator, FacilitatorConfig};
    /// use sorocharge_signer::{Address, Signer, SorochargeError};
    /// use stellar_rpc_client::Client as RpcClient;
    /// use stellar_xdr::{BytesM, Signature};
    ///
    /// struct DummySigner;
    /// impl Signer for DummySigner {
    ///     fn address(&self) -> Address {
    ///         "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
    ///             .parse()
    ///             .unwrap()
    ///     }
    ///     fn sign_preimage(&self, _: &[u8]) -> std::result::Result<[u8; 64], SorochargeError> {
    ///         Ok([0u8; 64])
    ///     }
    /// }
    ///
    /// let rpc = RpcClient::new("https://soroban-testnet.stellar.org").unwrap();
    /// let signer = DummySigner;
    /// let facilitator = Facilitator::new(
    ///     &rpc,
    ///     &signer,
    ///     "Test SDF Network ; September 2015".to_string(),
    ///     FacilitatorConfig::default(),
    /// );
    ///
    /// let supported = facilitator.supported();
    /// assert_eq!(supported.kinds.len(), 1);
    /// assert_eq!(supported.kinds[0].scheme, "exact");
    /// assert_eq!(supported.kinds[0].network, "stellar:testnet");
    /// ```
    #[must_use]
    pub fn supported(&self) -> SupportedResponse {
        let network = caip2_for_passphrase(&self.network_passphrase)
            .unwrap_or("stellar:testnet")
            .to_string();
        let mut signers = BTreeMap::new();
        signers.insert(
            "stellar:*".to_string(),
            vec![self.facilitator_address().to_string()],
        );
        SupportedResponse {
            kinds: vec![SupportedKind {
                x402_version: 2,
                scheme: "exact".to_string(),
                network,
            }],
            extensions: vec![],
            signers,
        }
    }
}

fn tx_source_matches(source: &stellar_xdr::MuxedAccount, address: &Address) -> bool {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(address_bytes)))) =
        address
    else {
        return false;
    };
    match source {
        stellar_xdr::MuxedAccount::Ed25519(Uint256(bytes)) => bytes == address_bytes,
        stellar_xdr::MuxedAccount::MuxedEd25519(m) => &m.ed25519.0 == address_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{transfer_event_xdr, MockRpc, TestSigner};
    use crate::tx::build_payment_transaction_envelope;
    use crate::types::{
        PaymentPayload, PaymentRequirements, StellarExtra, StellarPayload, VerifyRequest,
    };
    use sorocharge_signer::{build_charge_entry, sign_entry, ChargeParams, CredentialKind};
    use stellar_xdr::{MuxedAccount, ReadXdr, TransactionV1Envelope, WriteXdr};

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const CAIP2: &str = "stellar:testnet";
    const CURRENT_LEDGER: u32 = 1_000;
    const ACCOUNT_SEQ_NUM: i64 = 7;
    const ASSET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
    const RECIPIENT: &str = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N";
    const AMOUNT: i128 = 42_000_000;

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".to_string(),
            network: CAIP2.to_string(),
            amount: AMOUNT.to_string(),
            asset: ASSET.to_string(),
            pay_to: RECIPIENT.to_string(),
            max_timeout_seconds: 60,
            extra: StellarExtra {
                are_fees_sponsored: true,
            },
        }
    }

    fn charge_params(payer: &Address) -> ChargeParams {
        ChargeParams {
            asset_contract: ASSET.parse().expect("asset contract"),
            amount: AMOUNT,
            payer: payer.clone(),
            recipient: RECIPIENT.parse().expect("recipient"),
            // Within `currentLedger + ceil(60 / 5)`, so `verify_entry`'s
            // expiry and allowance checks both pass.
            valid_until_ledger: CURRENT_LEDGER + 10,
        }
    }

    /// Builds a `/verify`- or `/settle`-shaped request whose payment payload
    /// carries a real signed envelope for `params`.
    fn request_for(params: &ChargeParams, signer: &TestSigner) -> VerifyRequest {
        let unsigned = build_charge_entry(params, CredentialKind::Legacy).expect("build entry");
        let signed = sign_entry(unsigned, signer, NETWORK).expect("sign entry");
        let envelope =
            build_payment_transaction_envelope(params, &signed).expect("payment envelope");
        let transaction = envelope
            .to_xdr_base64(Limits::none())
            .expect("encode envelope");
        let requirements = requirements();
        VerifyRequest {
            x402_version: 2,
            payment_payload: PaymentPayload {
                x402_version: 2,
                resource: None,
                accepted: requirements.clone(),
                payload: StellarPayload { transaction },
                extensions: serde_json::Map::new(),
            },
            payment_requirements: requirements,
        }
    }

    /// The simulation events the facilitator's `verify_transfer_effects` check
    /// expects: exactly one transfer matching `params`.
    fn events_for(params: &ChargeParams) -> Vec<String> {
        vec![transfer_event_xdr(
            &params.asset_contract,
            &params.payer,
            &params.recipient,
            params.amount,
        )]
    }

    /// A payment naming a CAIP-2 network identifier with no mapping on this
    /// facilitator must fail as `UnsupportedNetwork`, carrying the offending
    /// identifier back — not as a generic payload or signature error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_network_identifier_with_no_caip2_mapping() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let mut request = request_for(&params, &payer);
        // Keep the payload and the requirements consistent with each other so
        // the failure is the unknown CAIP-2 identifier itself, not a
        // payload/requirements mismatch.
        request.payment_requirements.network = "stellar:bogus".to_string();
        request.payment_payload.accepted.network = "stellar:bogus".to_string();

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        match facilitator.validate(&request).await {
            Err(X402Error::UnsupportedNetwork { network }) => {
                assert_eq!(network, "stellar:bogus");
            }
            other => panic!("expected UnsupportedNetwork, got {other:?}"),
        }
        assert!(
            rpc.methods().is_empty(),
            "an unknown network must fail before any RPC call"
        );
    }

    /// A verify request whose payload does not have the expected shape (here:
    /// a non-`exact` scheme) must fail as exactly `InvalidPaymentPayload`,
    /// carrying the reason back — not as any other `X402Error` variant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_malformed_payload_as_invalid_payment_payload() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let mut request = request_for(&params, &payer);
        request.payment_payload.accepted.scheme = "upfront".to_string();

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        match facilitator.validate(&request).await {
            Err(X402Error::InvalidPaymentPayload { reason }) => {
                assert!(
                    reason.contains("exact"),
                    "expected the scheme-shape reason, got {reason:?}"
                );
            }
            other => panic!("expected InvalidPaymentPayload, got {other:?}"),
        }
        assert!(
            rpc.methods().is_empty(),
            "a malformed payload must fail before any RPC call"
        );
    }

    /// The facilitator must refuse any payment whose transfer `from` is its
    /// own fee-sponsoring address — the trick that would make it move its own
    /// funds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_transfer_from_the_facilitators_own_address() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let params = charge_params(&facilitator_signer.address());
        let request = request_for(&params, &facilitator_signer);

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        let result = facilitator.validate(&request).await;
        assert!(
            matches!(result, Err(X402Error::FacilitatorAddressConflict)),
            "expected FacilitatorAddressConflict, got {result:?}"
        );
    }

    /// A settle-time simulation whose fee (plus inclusion buffer) exceeds the
    /// configured ceiling must be refused, not submitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_simulated_fee_above_the_configured_ceiling() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let request = request_for(&params, &payer);

        // 60_000 + the default 100-stroop inclusion buffer > the default
        // 50_000 ceiling.
        let rpc =
            MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 60_000, events_for(&params)).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        let result = facilitator.settle(&request).await;
        match result {
            Err(X402Error::FeeExceedsCeiling {
                fee_stroops,
                ceiling_stroops,
            }) => {
                assert_eq!(fee_stroops, 60_100);
                assert_eq!(ceiling_stroops, 50_000);
            }
            other => panic!("expected FeeExceedsCeiling, got {other:?}"),
        }
    }

    /// A Stellar RPC call failing during validation must surface as exactly
    /// `RpcFailed`, carrying the underlying reason — not as a payload error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn maps_a_failing_rpc_call_to_rpc_failed() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let request = request_for(&params, &payer);

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        rpc.fail_method("getLatestLedger");
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        match facilitator.validate(&request).await {
            Err(X402Error::RpcFailed { reason }) => {
                assert!(
                    reason.contains("forced getLatestLedger failure"),
                    "expected the RPC error to be carried back, got {reason:?}"
                );
            }
            other => panic!("expected RpcFailed, got {other:?}"),
        }
    }

    /// Verification succeeding but submission failing on the RPC must surface
    /// as exactly `SettlementFailed`, not `RpcFailed` or a payload error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn maps_a_failing_submission_to_settlement_failed() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let request = request_for(&params, &payer);

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        rpc.fail_method("sendTransaction");
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        match facilitator.settle(&request).await {
            Err(X402Error::SettlementFailed { reason }) => {
                assert!(
                    reason.contains("forced sendTransaction failure"),
                    "expected the submission error to be carried back, got {reason:?}"
                );
            }
            other => panic!("expected SettlementFailed, got {other:?}"),
        }
        assert!(
            rpc.methods().contains(&"simulateTransaction".to_string()),
            "verification must have succeeded before submission failed"
        );
    }

    /// Settlement must rebuild the transaction around the facilitator's own
    /// account, sequence number, and simulation-derived fee — never the
    /// client's all-zeros placeholder values.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settle_rebuilds_with_the_facilitators_account_sequence_and_fee() {
        let facilitator_signer = TestSigner::from_seed([0x22; 32]);
        let payer = TestSigner::from_seed([0x33; 32]);
        let params = charge_params(&payer.address());
        let request = request_for(&params, &payer);

        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM, 100, events_for(&params)).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let facilitator = Facilitator::new(
            &rpc_client,
            &facilitator_signer,
            NETWORK.to_string(),
            FacilitatorConfig::default(),
        );

        let response = facilitator
            .settle(&request)
            .await
            .expect("settle should succeed");
        assert!(response.success, "settle should succeed: {response:?}");

        assert_eq!(
            rpc.methods(),
            vec![
                "getLatestLedger".to_string(),
                "simulateTransaction".to_string(),
                "getLedgerEntries".to_string(),
                "simulateTransaction".to_string(),
                "sendTransaction".to_string(),
                "getTransaction".to_string(),
            ],
            "settlement must resolve the latest ledger and simulate during validation, \
             then read the facilitator account, re-simulate, submit, and poll"
        );

        let submitted = rpc.submitted_transactions();
        assert_eq!(
            submitted.len(),
            1,
            "exactly one transaction should be submitted"
        );
        let envelope = TransactionEnvelope::from_xdr_base64(&submitted[0], Limits::none())
            .expect("decode the submitted envelope");
        let TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) = envelope else {
            panic!("expected a v1 envelope");
        };

        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            facilitator_key,
        )))) = facilitator_signer.address()
        else {
            panic!("facilitator signer must be an ed25519 account");
        };
        assert_eq!(
            tx.source_account,
            MuxedAccount::Ed25519(Uint256(facilitator_key)),
            "the submitted transaction must be sourced from the facilitator's account"
        );
        assert_ne!(
            tx.source_account,
            MuxedAccount::Ed25519(Uint256([0u8; 32])),
            "the client's all-zeros placeholder source must not survive settlement"
        );
        assert_eq!(
            tx.seq_num,
            SequenceNumber(ACCOUNT_SEQ_NUM + 1),
            "the sequence number must come from the facilitator's account, not the placeholder zero"
        );
        assert_eq!(
            tx.fee, 200,
            "the fee must be the simulation's 100 stroops plus the 100-stroop inclusion buffer, not the placeholder zero"
        );
        assert!(
            matches!(tx.ext, TransactionExt::V1(_)),
            "the rebuilt transaction must carry the simulation's Soroban resource data"
        );
        assert_eq!(tx.operations.len(), 1, "the operation must be preserved");
    }
}
