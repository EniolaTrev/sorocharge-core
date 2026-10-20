use stellar_xdr::{
    Int128Parts, InvokeContractArgs, Limits, ScAddress, ScSymbol, ScVal, ScVec,
    SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    SorobanDelegateSignature, VecM, WriteXdr,
};

use crate::error::SorochargeError;

/// A Soroban account or contract address, as it appears inside XDR structures.
///
/// This is the same `ScAddress` the network itself uses, not a
/// library-specific wrapper: `sorocharge-signer` never re-encodes addresses
/// in a shape the reference SDKs don't also produce.
pub type Address = ScAddress;

/// Decodes a SEP-23 strkey (`G...` account, `C...` contract, `M...` muxed
/// account) into an [`Address`].
///
/// The protocol adapters this library serves receive addresses as JSON
/// strings, while every structure built, signed, and verified here carries
/// an `ScAddress`. `str.parse::<Address>()` already rejects anything that
/// isn't a decodable address — this wrapper exists so that failure is
/// reported as [`SorochargeError::InvalidAddress`] carrying the offending
/// string, the one variant a caller can act on ("this input was never an
/// address") rather than a generic parse error, per the constraint that
/// every public error variant is distinct enough to act on differently.
///
/// # Errors
///
/// Returns [`SorochargeError::InvalidAddress`] with `strkey` set to the
/// input string whenever it fails to decode into an [`ScAddress`]: bad
/// length, bad base32, a broken checksum, or a well-formed strkey of a
/// type that is not an address (e.g. a secret key).
pub fn parse_address(strkey: &str) -> Result<Address, SorochargeError> {
    strkey
        .parse::<Address>()
        .map_err(|_| SorochargeError::InvalidAddress {
            strkey: strkey.to_owned(),
        })
}

/// The parameters of a single SEP-41 transfer this library will build, sign,
/// or verify an authorization entry for.
///
/// `amount` is `i128` base units (never a float) to match SEP-41's transfer
/// signature exactly, and `valid_until_ledger` is a ledger number (never
/// wall-clock time) because that is what Soroban authorization expiry
/// actually checks on-chain.
///
/// # Examples
///
/// ```rust
/// use sorocharge_signer::ChargeParams;
/// use stellar_xdr::ScAddress;
///
/// let asset_contract: ScAddress = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
///     .parse()
///     .expect("valid contract address");
/// let payer: ScAddress = "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
///     .parse()
///     .expect("valid payer address");
/// let recipient: ScAddress = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
///     .parse()
///     .expect("valid recipient address");
///
/// let params = ChargeParams {
///     asset_contract,
///     amount: 1_000_000,
///     payer,
///     recipient,
///     valid_until_ledger: 123_456,
/// };
///
/// assert_eq!(params.amount, 1_000_000);
/// assert_eq!(params.recipient.to_string(), "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N");
/// assert_eq!(params.valid_until_ledger, 123_456);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeParams {
    /// The SEP-41 Stellar Asset Contract (SAC) address being transferred.
    pub asset_contract: Address,
    /// The transfer amount, in the asset's base units.
    pub amount: i128,
    /// The address authorizing the transfer (the `from` of the SEP-41 `transfer`).
    pub payer: Address,
    /// The address receiving the transfer (the `to` of the SEP-41 `transfer`).
    pub recipient: Address,
    /// The last ledger sequence for which this authorization is valid.
    pub valid_until_ledger: u32,
}

/// Which `SorobanCredentials` shape a charge entry should be built and
/// signed for.
///
/// This mirrors `SorobanCredentialsType` one-for-one except for
/// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, which has no signature to build or
/// verify and so is out of scope for a payment-authorization library: every
/// charge here is authorized by an explicit `Address`, never implicitly by
/// the transaction's source account.
///
/// # Examples
///
/// ```rust
/// use sorocharge_signer::CredentialKind;
/// use stellar_xdr::ScAddress;
///
/// let signer_a: ScAddress = "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
///     .parse()
///     .expect("valid signer address");
/// let signer_b: ScAddress = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
///     .parse()
///     .expect("valid signer address");
///
/// let credential = CredentialKind::Delegated {
///     signers: vec![signer_a, signer_b],
/// };
///
/// match credential {
///     CredentialKind::Delegated { signers } => assert_eq!(signers.len(), 2),
///     _ => panic!("expected delegated signers"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKind {
    /// `SOROBAN_CREDENTIALS_ADDRESS`: a single ed25519 signature over the
    /// legacy (pre-CAP-71) authorization preimage.
    Legacy,
    /// `SOROBAN_CREDENTIALS_ADDRESS_V2` (CAP-71): a single ed25519 signature
    /// over the address-bound authorization preimage. Mandatory from
    /// protocol 28 onward.
    AddressV2,
    /// `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71 delegated
    /// signers): the payer address's credential is satisfied by signatures
    /// from one or more delegate addresses instead of, or in addition to,
    /// the payer's own key.
    Delegated { signers: Vec<Address> },
}

/// A constructed `SorobanAuthorizationEntry` for a SEP-41 transfer, before it
/// carries a signature.
///
/// The credentials' `signature` field is the empty-vector placeholder
/// (`ScVal::Vec(Some(ScVec(..)))` with no elements) that `sign_entry` fills
/// in, matching the shape the reference SDK builds prior to signing.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use sorocharge_signer::{build_charge_entry, parse_address, ChargeParams, CredentialKind};
/// use stellar_xdr::SorobanCredentials;
///
/// let params = ChargeParams {
///     asset_contract: parse_address("CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH")?,
///     amount: 1_500_000,
///     payer: parse_address("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7")?,
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 100_000,
/// };
///
/// let unsigned = build_charge_entry(&params, CredentialKind::AddressV2)?;
/// assert!(matches!(
///     &unsigned.as_xdr().credentials,
///     SorobanCredentials::AddressV2(_)
/// ));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEntry(pub(crate) SorobanAuthorizationEntry);

impl UnsignedEntry {
    /// The wrapped `SorobanAuthorizationEntry`, for callers that need to
    /// inspect or serialize it directly (e.g. golden-vector tests).
    #[must_use]
    pub fn as_xdr(&self) -> &SorobanAuthorizationEntry {
        &self.0
    }
}

/// The empty-vector signature placeholder used before an entry is signed,
/// matching the reference SDK's own unsigned-entry convention
/// (`ScVal.scvVec([])`, not `scvVoid()`).
fn empty_signature_placeholder() -> ScVal {
    ScVal::Vec(Some(ScVec(VecM::default())))
}

/// Builds the `SorobanAddressCredentials` payload shared by `Legacy` and
/// `AddressV2`: the two credential kinds carry an identical struct and
/// differ only in which `SorobanCredentials` union arm wraps it.
fn build_address_credentials(params: &ChargeParams, nonce: i64) -> SorobanAddressCredentials {
    SorobanAddressCredentials {
        address: params.payer.clone(),
        nonce,
        signature_expiration_ledger: params.valid_until_ledger,
        signature: empty_signature_placeholder(),
    }
}

/// Builds `SorobanAddressCredentialsWithDelegates` for a `Delegated`
/// credential: `signers` become the (possibly multiple) delegate nodes,
/// sorted by their XDR-encoded address bytes ascending and checked for
/// duplicates, exactly as CAP-71-01 requires and as the reference SDK's
/// `buildWithDelegatesEntry` does — a network host rejects an entry whose
/// delegates aren't sorted, and a duplicate delegate can never be
/// meaningfully satisfied. The top-level and per-delegate signatures are
/// `ScVal::Void` placeholders, matching `buildWithDelegatesEntry`'s own
/// unsigned default (the plain `Address`/`AddressV2` credentials use an
/// empty-vector placeholder instead; the two builders simply chose
/// different placeholder values, and this library matches each one).
fn build_delegated_credentials(
    params: &ChargeParams,
    nonce: i64,
    signers: &[Address],
) -> Result<SorobanAddressCredentialsWithDelegates, SorochargeError> {
    if signers.is_empty() {
        return Err(SorochargeError::EmptyDelegateSigners);
    }

    let mut keyed: Vec<(Vec<u8>, Address)> = signers
        .iter()
        .map(|address| {
            address
                .to_xdr(Limits::none())
                .map(|bytes| (bytes, address.clone()))
                .map_err(|e| SorochargeError::XdrEncodingFailed {
                    reason: format!("failed to encode delegate address: {e}"),
                })
        })
        .collect::<Result<_, _>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(SorochargeError::DuplicateDelegateSigner);
        }
    }

    let delegate_nodes: Vec<SorobanDelegateSignature> = keyed
        .into_iter()
        .map(|(_, address)| SorobanDelegateSignature {
            address,
            signature: ScVal::Void,
            nested_delegates: VecM::default(),
        })
        .collect();
    let delegates: VecM<SorobanDelegateSignature> =
        delegate_nodes
            .try_into()
            .map_err(|_| SorochargeError::XdrEncodingFailed {
                reason: "too many delegate signers for a single credential".to_string(),
            })?;

    let address_credentials = SorobanAddressCredentials {
        address: params.payer.clone(),
        nonce,
        signature_expiration_ledger: params.valid_until_ledger,
        signature: ScVal::Void,
    };

    Ok(SorobanAddressCredentialsWithDelegates {
        address_credentials,
        delegates,
    })
}

/// Builds the `InvokeContractArgs` for a SEP-41 `transfer(from, to, amount)`
/// call, the single invocation every charge entry this library produces
/// authorizes.
fn build_transfer_invocation(
    params: &ChargeParams,
) -> Result<SorobanAuthorizedInvocation, SorochargeError> {
    let function_name =
        ScSymbol(
            "transfer"
                .try_into()
                .map_err(|_| SorochargeError::XdrEncodingFailed {
                    reason: "function name \"transfer\" does not fit SCSymbol".to_string(),
                })?,
        );
    let amount_parts = Int128Parts {
        hi: (params.amount >> 64) as i64,
        lo: (params.amount & (u64::MAX as i128)) as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(params.payer.clone()),
        ScVal::Address(params.recipient.clone()),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .map_err(|_| SorochargeError::XdrEncodingFailed {
        reason: "transfer args exceed SCVal array limit".to_string(),
    })?;
    let function = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
        contract_address: params.asset_contract.clone(),
        function_name,
        args,
    });
    Ok(SorobanAuthorizedInvocation {
        function,
        sub_invocations: VecM::default(),
    })
}

/// Generates a nonce with `getrandom`. The nonce only needs to be
/// unpredictable and unique per entry to prevent replay; it carries no
/// cryptographic weight of its own — the entry's signature is what the
/// network actually verifies.
fn random_nonce() -> Result<i64, SorochargeError> {
    let bits = getrandom::u64().map_err(|e| SorochargeError::XdrEncodingFailed {
        reason: format!("failed to generate nonce: {e}"),
    })?;
    Ok(bits as i64)
}

/// Builds an unsigned `SorobanAuthorizationEntry` authorizing a SEP-41
/// `transfer` for `params`, in the shape dictated by `credential`.
///
/// The nonce is generated internally with a fresh source of randomness on
/// every call — it exists to make each authorization unique, not to encode
/// caller-supplied state, so exposing it as a parameter would only invite
/// accidental reuse.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedCredentialType`] for a
/// `credential` this build of the library does not yet construct XDR for,
/// and [`SorochargeError::XdrEncodingFailed`] if a value can't be encoded
/// into its XDR-constrained shape (e.g. a `VecM` length limit).
///
/// # Example
///
/// ```no_run
/// use sorocharge_signer::{build_charge_entry, parse_address, ChargeParams, CredentialKind};
///
/// # fn main() -> Result<(), sorocharge_signer::SorochargeError> {
/// let params = ChargeParams {
///     // The asset contract being pulled from (an `ScAddress` — `C...` for
///     // a issued Soroban asset token, `G...` for a native-XLM-like stub).
///     asset_contract: parse_address("GCX7DRGVA2GIN3IBOQDNZZTL3PQKUPBAJ3EPZXVOEVNGA4V5PV4NCRAA")?,
///     amount: 1_500_000, // 1.5 XLM, in stroops (7 decimal digits)
///     payer: parse_address("GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7")?,
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 100_000,
/// };
///
/// let unsigned = build_charge_entry(&params, CredentialKind::Legacy)?;
/// // `unsigned` is an `UnsignedEntry`; pass it to `sign_entry` next to
/// // produce the signed `SorobanAuthorizationEntry`.
/// # Ok(())
/// # }
/// ```
pub fn build_charge_entry(
    params: &ChargeParams,
    credential: CredentialKind,
) -> Result<UnsignedEntry, SorochargeError> {
    let nonce = random_nonce()?;
    build_charge_entry_with_nonce(params, credential, nonce)
}

/// The deterministic core of [`build_charge_entry`], with the nonce taken as
/// an explicit argument rather than generated. Not part of the public API:
/// callers cannot control the nonce, but golden-vector tests need to pin it
/// to diff against a fixture generated with the same fixed nonce.
pub(crate) fn build_charge_entry_with_nonce(
    params: &ChargeParams,
    credential: CredentialKind,
    nonce: i64,
) -> Result<UnsignedEntry, SorochargeError> {
    if params.amount <= 0 {
        return Err(SorochargeError::AmountNonPositive);
    }
    let root_invocation = build_transfer_invocation(params)?;
    let credentials = match credential {
        CredentialKind::Legacy => {
            SorobanCredentials::Address(build_address_credentials(params, nonce))
        }
        CredentialKind::AddressV2 => {
            SorobanCredentials::AddressV2(build_address_credentials(params, nonce))
        }
        CredentialKind::Delegated { signers } => SorobanCredentials::AddressWithDelegates(
            build_delegated_credentials(params, nonce, &signers)?,
        ),
    };

    Ok(UnsignedEntry(SorobanAuthorizationEntry {
        credentials,
        root_invocation,
    }))
}

#[cfg(test)]
mod golden_vector_tests {
    use super::*;
    use crate::sign::{sign_entry, Signer};
    use crate::verify::verify_entry;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use serde::Deserialize;
    use stellar_xdr::{Limits, ReadXdr, WriteXdr};

    /// Diffs `build_charge_entry`'s XDR output against a fixture generated
    /// from the pinned `@stellar/stellar-sdk` (see
    /// `tests/golden_vectors/generate.mjs` at the repo root). A signing
    /// library that "looks right" but hasn't been byte-diffed against the
    /// reference implementation is not done.
    #[derive(Deserialize)]
    struct Fixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        valid_until_ledger: u32,
        nonce: String,
        #[serde(default)]
        delegate_signers: Vec<String>,
        unsigned_entry_xdr_base64: String,
    }

    fn load_fixture(name: &str) -> Fixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
    }

    /// Encodes each address to its XDR bytes — the exact sort key the
    /// reference SDK's `buildWithDelegatesEntry` uses for delegate nodes,
    /// and the key [`build_delegated_credentials`] mirrors.
    fn xdr_encoded_addresses(addresses: &[ScAddress]) -> Vec<Vec<u8>> {
        addresses
            .iter()
            .map(|address| {
                address
                    .to_xdr(Limits::none())
                    .expect("an ScAddress always encodes to XDR")
            })
            .collect()
    }

    #[test]
    fn legacy_transfer_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("legacy_transfer");

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();

        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::Legacy, nonce)
            .expect("build_charge_entry_with_nonce should succeed for legacy credentials");

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's unsigned entry XDR must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }

    #[test]
    fn address_v2_transfer_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("address_v2_transfer");

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();

        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::AddressV2, nonce)
            .expect("build_charge_entry_with_nonce should succeed for AddressV2 credentials");

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's AddressV2 unsigned entry XDR must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }

    #[test]
    fn delegated_transfer_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("delegated_transfer");

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();
        let signers: Vec<ScAddress> = fixture
            .delegate_signers
            .iter()
            .map(|s| s.parse::<ScAddress>().unwrap())
            .collect();
        assert!(
            signers.len() >= 2,
            "fixture should exercise more than one delegate signer"
        );

        let unsigned =
            build_charge_entry_with_nonce(&params, CredentialKind::Delegated { signers }, nonce)
                .expect("build_charge_entry_with_nonce should succeed for Delegated credentials");

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's Delegated unsigned entry XDR (including delegate sort order) must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }

    /// The three-signer fixture is what actually proves the sort: its
    /// signers are listed in the exact reverse of their XDR-encoded byte
    /// order (a G-address string sort would give a third, different order),
    /// so the builder must reorder by XDR bytes to reproduce the reference
    /// SDK's output. The two-signer fixture's input already happens to be
    /// ascending, so it cannot distinguish "sorted" from "never touched".
    #[test]
    fn delegated_transfer_with_unsorted_signers_is_sorted_by_xdr_address_bytes() {
        let fixture = load_fixture("delegated_transfer_many_signers");

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();
        let signers: Vec<ScAddress> = fixture
            .delegate_signers
            .iter()
            .map(|s| s.parse::<ScAddress>().unwrap())
            .collect();
        assert!(
            signers.len() >= 3,
            "fixture should exercise more than the minimum two delegate signers, got {}",
            signers.len()
        );

        // The fixture only proves a sort happened if its input isn't
        // already in ascending order to begin with.
        let input_bytes = xdr_encoded_addresses(&signers);
        let mut ascending_bytes = input_bytes.clone();
        ascending_bytes.sort();
        assert_ne!(
            input_bytes, ascending_bytes,
            "fixture delegate_signers must be listed in deliberately unsorted order, or this test proves nothing about sorting"
        );

        let unsigned =
            build_charge_entry_with_nonce(&params, CredentialKind::Delegated { signers }, nonce)
                .expect("build_charge_entry_with_nonce should succeed for Delegated credentials");

        let SorobanCredentials::AddressWithDelegates(built) = &unsigned.as_xdr().credentials else {
            panic!("built entry should carry AddressWithDelegates credentials");
        };
        let output_bytes: Vec<Vec<u8>> = built
            .delegates
            .iter()
            .map(|delegate| {
                delegate
                    .address
                    .to_xdr(Limits::none())
                    .expect("an ScAddress always encodes to XDR")
            })
            .collect();
        assert!(
            output_bytes.windows(2).all(|pair| pair[0] < pair[1]),
            "delegate nodes must be strictly ascending by XDR-encoded address bytes, got {output_bytes:?}"
        );
        assert_eq!(
            output_bytes, ascending_bytes,
            "delegate nodes must be exactly the input signers reordered, never a different set"
        );

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's three-signer Delegated unsigned entry XDR (including delegate sort order) must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }

    #[test]
    fn delegated_credential_rejects_empty_signers() {
        let params = ChargeParams {
            asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
                .parse()
                .unwrap(),
            amount: 1,
            payer: "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
                .parse()
                .unwrap(),
            recipient: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
                .parse()
                .unwrap(),
            valid_until_ledger: 1,
        };

        let result = build_charge_entry_with_nonce(
            &params,
            CredentialKind::Delegated { signers: vec![] },
            1,
        );

        assert_eq!(result, Err(SorochargeError::EmptyDelegateSigners));
    }

    #[test]
    fn delegated_credential_rejects_duplicate_signers() {
        let payer: ScAddress = "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
            .parse()
            .unwrap();
        let params = ChargeParams {
            asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
                .parse()
                .unwrap(),
            amount: 1,
            payer: payer.clone(),
            recipient: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
                .parse()
                .unwrap(),
            valid_until_ledger: 1,
        };

        let result = build_charge_entry_with_nonce(
            &params,
            CredentialKind::Delegated {
                signers: vec![payer.clone(), payer],
            },
            1,
        );

        assert_eq!(result, Err(SorochargeError::DuplicateDelegateSigner));
    }

    /// The duplicate is deliberately non-adjacent in the input, so it is
    /// only caught because [`build_delegated_credentials`] sorts by
    /// XDR-encoded address bytes *before* scanning for duplicates — the
    /// same order the reference SDK's `buildWithDelegatesEntry` dedups in.
    /// With only two signers a duplicate is trivially adjacent either way,
    /// which is why this case needs three.
    #[test]
    fn delegated_credential_rejects_duplicate_signers_after_sorting() {
        let first: ScAddress = "GDDIEJRXY7JRB3CXMJ56AC5CLHJFG5E7JKXWIRDQZ756KORV64ZEEQ3N"
            .parse()
            .unwrap();
        let second: ScAddress = "GDLVS6J3XQJ2FAM2QJ6HNLNW7OUKJGXOAB7UT4WQTEWZTOBFVUWERBG7"
            .parse()
            .unwrap();
        let params = ChargeParams {
            asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
                .parse()
                .unwrap(),
            amount: 1,
            payer: "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
                .parse()
                .unwrap(),
            recipient: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
                .parse()
                .unwrap(),
            valid_until_ledger: 1,
        };

        let result = build_charge_entry_with_nonce(
            &params,
            CredentialKind::Delegated {
                signers: vec![first.clone(), second, first],
            },
            1,
        );

        assert_eq!(result, Err(SorochargeError::DuplicateDelegateSigner));
    }

    /// Pulls the `Int128Parts` the built entry encodes the transfer amount
    /// as — the exact hi/lo split [`build_transfer_invocation`] produces,
    /// and the structure a boundary off-by-one would hide in.
    fn encoded_amount_parts(entry: &SorobanAuthorizationEntry) -> Int128Parts {
        let SorobanAuthorizedFunction::ContractFn(invoke) = &entry.root_invocation.function else {
            panic!("built entry should authorize a single contract call");
        };
        let [ScVal::Address(_), ScVal::Address(_), ScVal::I128(parts)] = invoke.args.as_slice()
        else {
            panic!("transfer invocation should carry (from, to, I128 amount) args");
        };
        parts.clone()
    }

    /// Diffs a built unsigned entry's XDR against its fixture byte for
    /// byte, the same proof of reference-SDK equivalence every other
    /// golden vector in this module provides.
    fn assert_matches_fixture_xdr(unsigned: &UnsignedEntry, fixture: &Fixture) {
        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's unsigned entry XDR must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }

    /// The smallest possible positive transfer: 1 base unit, whose hi/lo
    /// split is `(0, 1)` — the lower boundary of `Int128Parts`, where an
    /// off-by-one that dropped or shifted the lowest bit would silently
    /// corrupt the amount to 0 (or 2^64) without any mid-range fixture
    /// noticing.
    #[test]
    fn legacy_transfer_of_one_base_unit_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("legacy_transfer_min_amount");
        assert_eq!(
            fixture.amount, "1",
            "fixture must pin the lower i128 amount boundary"
        );

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();

        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::Legacy, nonce)
            .expect("build_charge_entry_with_nonce should succeed for a 1-base-unit transfer");

        let parts = encoded_amount_parts(unsigned.as_xdr());
        assert_eq!(
            (parts.hi, parts.lo),
            (0, 1),
            "amount 1 must encode as Int128Parts {{ hi: 0, lo: 1 }}"
        );

        assert_matches_fixture_xdr(&unsigned, &fixture);
    }

    /// The largest representable transfer: `i128::MAX`, whose hi/lo split
    /// is `(i64::MAX, u64::MAX)` — the upper boundary, where every bit of
    /// both halves is set, so a sign-extension, mask-width, or shift error
    /// in the split (or in `verify_entry`'s reassembly) yields a different
    /// value.
    #[test]
    fn legacy_transfer_of_i128_max_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("legacy_transfer_max_amount");
        assert_eq!(
            fixture.amount,
            i128::MAX.to_string(),
            "fixture must pin the upper i128 amount boundary"
        );

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();

        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::Legacy, nonce)
            .expect("build_charge_entry_with_nonce should succeed for an i128::MAX transfer");

        let parts = encoded_amount_parts(unsigned.as_xdr());
        assert_eq!(
            (parts.hi, parts.lo),
            (i64::MAX, u64::MAX),
            "amount i128::MAX must encode as Int128Parts {{ hi: i64::MAX, lo: u64::MAX }}"
        );

        assert_matches_fixture_xdr(&unsigned, &fixture);
    }

    /// An ed25519 signer for the fixture payer, using the same 32-byte seed
    /// `generate.mjs` derives that payer from, so build→sign→verify runs
    /// end-to-end on one key.
    struct FixedSeedPayerSigner {
        signing_key: SigningKey,
        address: Address,
    }

    impl Signer for FixedSeedPayerSigner {
        fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
            Ok(self.signing_key.sign(preimage).to_bytes())
        }

        fn address(&self) -> Address {
            self.address.clone()
        }
    }

    /// Round-trips a boundary amount through the exact public path a caller
    /// uses — [`build_charge_entry`] (with its real, random nonce),
    /// [`sign_entry`], [`verify_entry`] — and then re-verifies with a
    /// one-unit-smaller expectation to prove verification compares all 128
    /// bits exactly. [`verify_entry`] reassembles `Int128Parts` back into
    /// an `i128` before comparing, so `Ok(())` here proves the amount
    /// survived the split and reassembly unchanged at this boundary.
    fn assert_amount_round_trips_unchanged(amount: i128) {
        let fixture = load_fixture("legacy_transfer");
        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount,
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let network_passphrase = "Test SDF Network ; September 2015";
        let current_ledger = params.valid_until_ledger - 1;

        let unsigned = build_charge_entry(&params, CredentialKind::Legacy)
            .expect("build_charge_entry should succeed for any positive i128 amount");

        let parts = encoded_amount_parts(unsigned.as_xdr());
        assert_eq!(
            (i128::from(parts.hi) << 64) | i128::from(parts.lo),
            amount,
            "the built entry's Int128Parts must reassemble to exactly the amount passed in"
        );

        let signer = FixedSeedPayerSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let signed = sign_entry(unsigned, &signer, network_passphrase)
            .expect("sign_entry should succeed for the fixture payer's key");

        assert_eq!(
            verify_entry(&signed, &params, current_ledger, network_passphrase),
            Ok(()),
            "verify_entry must accept an entry whose amount matches exactly"
        );

        // Rejected off by exactly one unit: proof the check compares the
        // full 128-bit amount, not a truncated or rounded half of it.
        // Steps up rather than down (except at i128::MAX, where up would
        // overflow) to stay clear of the AmountNonPositive check, which
        // fires first for a non-positive expectation.
        let mut off_by_one = params.clone();
        off_by_one.amount = if amount < i128::MAX {
            amount + 1
        } else {
            amount - 1
        };
        assert_eq!(
            verify_entry(&signed, &off_by_one, current_ledger, network_passphrase),
            Err(SorochargeError::AmountMismatch),
            "verify_entry must reject an expectation exactly one base unit away from the boundary"
        );
    }

    #[test]
    fn amount_one_round_trips_unchanged_through_build_sign_and_verify() {
        assert_amount_round_trips_unchanged(1);
    }

    #[test]
    fn amount_i128_max_round_trips_unchanged_through_build_sign_and_verify() {
        assert_amount_round_trips_unchanged(i128::MAX);
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    /// A real account strkey with its final character swapped, which breaks
    /// only the CRC16 checksum: the input is still 56 base32 characters
    /// shaped like a `G...` address, but it must fail to decode into an
    /// `ScAddress`. The failure has to surface as exactly
    /// `Err(SorochargeError::InvalidAddress)` carrying the original string —
    /// the assertion compares the whole `Result`, so returning any other
    /// variant fails the test with a readable diff instead of passing.
    #[test]
    fn strkey_that_fails_to_decode_returns_invalid_address() {
        let strkey = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64M";

        // Guard the fixture itself: the test proves nothing if this string
        // ever starts decoding into an ScAddress.
        assert!(
            strkey.parse::<Address>().is_err(),
            "fixture must be a strkey that fails to decode into an ScAddress"
        );

        let result = parse_address(strkey);

        assert_eq!(
            result,
            Err(SorochargeError::InvalidAddress {
                strkey: strkey.to_owned(),
            })
        );
    }
}
