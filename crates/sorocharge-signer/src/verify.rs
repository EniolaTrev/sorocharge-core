use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use stellar_xdr::{
    AccountId, PublicKey, ScAddress, ScSymbol, ScVal, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
};

use crate::entry::{Address, ChargeParams};
use crate::error::SorochargeError;
use crate::sign::{signing_payload, SignedEntry};

struct TransferArgs {
    asset_contract: Address,
    from: Address,
    to: Address,
    amount: i128,
}

/// Pulls the `(contract, from, to, amount)` a SEP-41 `transfer` invocation
/// authorizes out of `invocation`, rejecting anything else: sub-invocations
/// (which could authorize side effects beyond the stated transfer), a
/// different function, or a different argument shape.
fn extract_transfer_args(
    invocation: &SorobanAuthorizedInvocation,
) -> Result<TransferArgs, SorochargeError> {
    if !invocation.sub_invocations.is_empty() {
        return Err(SorochargeError::UnexpectedInvocationShape);
    }
    let SorobanAuthorizedFunction::ContractFn(invoke) = &invocation.function else {
        return Err(SorochargeError::UnexpectedInvocationShape);
    };
    let expected_name: ScSymbol = "transfer"
        .try_into()
        .map(ScSymbol)
        .map_err(|_| SorochargeError::UnexpectedInvocationShape)?;
    if invoke.function_name != expected_name {
        return Err(SorochargeError::UnexpectedInvocationShape);
    }
    let [ScVal::Address(from), ScVal::Address(to), ScVal::I128(amount_parts)] =
        invoke.args.as_slice()
    else {
        return Err(SorochargeError::UnexpectedInvocationShape);
    };
    let amount = (i128::from(amount_parts.hi) << 64) | i128::from(amount_parts.lo);

    Ok(TransferArgs {
        asset_contract: invoke.contract_address.clone(),
        from: from.clone(),
        to: to.clone(),
        amount,
    })
}

/// The address a `SorobanAuthorizationEntry`'s credential authorizes for,
/// alongside every node whose signature could satisfy it: just itself for
/// `Address`/`AddressV2`, or itself plus each delegate for
/// `AddressWithDelegates`.
fn authorizing_address_and_signable_nodes(
    credentials: &SorobanCredentials,
) -> Result<(Address, Vec<(Address, ScVal)>), SorochargeError> {
    match credentials {
        SorobanCredentials::Address(c) => Ok((
            c.address.clone(),
            vec![(c.address.clone(), c.signature.clone())],
        )),
        SorobanCredentials::AddressV2(c) => Ok((
            c.address.clone(),
            vec![(c.address.clone(), c.signature.clone())],
        )),
        SorobanCredentials::AddressWithDelegates(c) => {
            let mut nodes = vec![(
                c.address_credentials.address.clone(),
                c.address_credentials.signature.clone(),
            )];
            nodes.extend(
                c.delegates
                    .iter()
                    .map(|d| (d.address.clone(), d.signature.clone())),
            );
            Ok((c.address_credentials.address.clone(), nodes))
        }
        SorobanCredentials::SourceAccount => Err(SorochargeError::UnsupportedCredentialType),
    }
}

/// Extracts a raw `(public_key, signature)` byte pair from the standard
/// Stellar account signature shape (`ScVal::Vec([ScVal::Map({public_key,
/// signature})])`), or `None` for anything else — the unsigned placeholder
/// (`ScVal::Vec([])` or `ScVal::Void`), a custom `signatureScVal` shape this
/// library doesn't interpret, or malformed data. `None` just means "this
/// node contributes no verifiable signature," not a hard error: a
/// `Delegated` entry with several nodes should still succeed if any other
/// node is validly signed.
fn extract_account_signature(scval: &ScVal) -> Option<([u8; 32], [u8; 64])> {
    let ScVal::Vec(Some(vec)) = scval else {
        return None;
    };
    let [ScVal::Map(Some(map))] = vec.0.as_slice() else {
        return None;
    };
    let mut public_key: Option<[u8; 32]> = None;
    let mut signature: Option<[u8; 64]> = None;
    for entry in map.0.iter() {
        let ScVal::Symbol(key) = &entry.key else {
            continue;
        };
        let ScVal::Bytes(val) = &entry.val else {
            continue;
        };
        let bytes: &[u8] = &val.0;
        if key.0.to_utf8_string_lossy() == "public_key" {
            public_key = bytes.try_into().ok();
        } else if key.0.to_utf8_string_lossy() == "signature" {
            signature = bytes.try_into().ok();
        }
    }
    Some((public_key?, signature?))
}

/// Checks `scval` carries a genuine ed25519 signature over `payload` **made
/// by `address`'s own key** — not just a genuine signature by *some* key.
/// The embedded `public_key` field in the signature SCVal is caller-supplied
/// data, not a verified fact; skipping the comparison against `address`'s
/// actual `AccountId` would let anyone attach a valid signature from an
/// unrelated keypair while the entry still claims `address` as the
/// authorizing account.
fn is_valid_ed25519_signature(address: &Address, payload: &[u8; 32], scval: &ScVal) -> bool {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_key)))) =
        address
    else {
        return false;
    };
    let Some((public_key_bytes, signature_bytes)) = extract_account_signature(scval) else {
        return false;
    };
    if public_key_bytes != *account_key {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    verifying_key
        .verify(payload, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// Verifies a signed charge entry against the charge it's expected to
/// authorize, failing closed on the first mismatch, checked in this order:
///
/// 1. [`SorochargeError::AmountNonPositive`] — `expected.amount` is zero or
///    negative, which is never a valid charge regardless of the entry.
/// 2. [`SorochargeError::ExpiredEntry`] — `valid_until_ledger` has passed
///    `current_ledger`.
/// 3. [`SorochargeError::ExpirationExceedsAllowance`] — the entry's own
///    `signature_expiration_ledger` is later than `expected.valid_until_ledger`.
///    Checking only "not yet expired" (the previous check) bounds how late
///    is too late; it never bounded how *long-lived* an authorization the
///    caller is willing to accept. Without this, a payer could attach an
///    authorization valid for far longer than the payee asked for, and
///    verify_entry would pass it as long as it hadn't expired yet — found
///    reviewing a downstream binding that needed to read this field and
///    found nothing enforced it.
/// 4. [`SorochargeError::UnexpectedInvocationShape`] — the entry doesn't
///    authorize a single, bare SEP-41 `transfer(from, to, amount)` call.
/// 5. [`SorochargeError::AssetMismatch`] — the asset contract differs.
/// 6. [`SorochargeError::PayerMismatch`] — the authorizing address (the
///    credential's address, which must also be the invocation's `from`)
///    differs from `expected.payer`. This check is not in the CLAUDE.md
///    section 5 checklist verbatim (which lists only asset/amount/recipient
///    alongside expiry and signature), but omitting it would let any signed
///    entry pass as long as its invocation happened to name the right
///    asset/amount/recipient, regardless of whose key actually signed it —
///    added per this project's brief to resolve spec ambiguity toward the
///    more conservative reading.
/// 6. [`SorochargeError::AmountNonPositive`] — the caller's
///    `expected.amount` is zero or negative, so no signed entry could ever
///    legitimately match it; this precondition is checked before the amount
///    diff so the caller's own invalid expectation is reported as such
///    rather than surfacing as [`SorochargeError::AmountMismatch`].
/// 7. [`SorochargeError::AmountMismatch`] — the amount differs.
/// 8. [`SorochargeError::RecipientMismatch`] — the recipient differs.
/// 9. [`SorochargeError::InvalidSignature`] — no signable node (the
///    top-level address, or, for `Delegated`, any delegate) carries a valid
///    ed25519 signature over the reconstructed `HashIdPreimage`. A
///    `Delegated` entry's account-contract-specific signing *policy*
///    (how many delegates must sign, or which) is unknowable here — this
///    only proves at least one attached signature is genuine.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedCredentialType`] for
/// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, which this library never signs and
/// so never expects to verify either.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{
///     build_charge_entry, parse_address, sign_entry, verify_entry, Address, ChargeParams,
///     CredentialKind, SorochargeError, Signer,
/// };
/// use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};
///
/// struct LocalSigner(SigningKey);
///
/// impl Signer for LocalSigner {
///     fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
///         Ok(self.0.sign(preimage).to_bytes())
///     }
///
///     fn address(&self) -> Address {
///         ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
///             self.0.verifying_key().to_bytes(),
///         ))))
///     }
/// }
///
/// let signer = LocalSigner(SigningKey::from_bytes(&[0x11; 32]));
/// let params = ChargeParams {
///     asset_contract: parse_address("CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH")?,
///     amount: 1_500_000,
///     payer: signer.address(),
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 100_000,
/// };
///
/// let unsigned = build_charge_entry(&params, CredentialKind::AddressV2)?;
/// let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015")?;
/// verify_entry(
///     &signed,
///     &params,
///     99_999,
///     "Test SDF Network ; September 2015",
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn verify_entry(
    entry: &SignedEntry,
    expected: &ChargeParams,
    current_ledger: u32,
    network_passphrase: &str,
) -> Result<(), SorochargeError> {
    // A non-positive `expected.amount` is never a valid charge, independent
    // of the entry being verified. Rejecting it first fails closed before any
    // attacker-supplied XDR is decoded or compared.
    if expected.amount <= 0 {
        return Err(SorochargeError::AmountNonPositive);
    }

    let xdr_entry = entry.as_xdr();
    let (authorizing_address, signable_nodes) =
        authorizing_address_and_signable_nodes(&xdr_entry.credentials)?;

    let (_, signature_expiration_ledger, _) =
        crate::sign::credential_preimage_fields(&xdr_entry.credentials)?;
    if signature_expiration_ledger <= current_ledger {
        return Err(SorochargeError::ExpiredEntry {
            valid_until_ledger: signature_expiration_ledger,
            current_ledger,
        });
    }
    if signature_expiration_ledger > expected.valid_until_ledger {
        return Err(SorochargeError::ExpirationExceedsAllowance {
            signature_expiration_ledger,
            allowed_until_ledger: expected.valid_until_ledger,
        });
    }

    let transfer = extract_transfer_args(&xdr_entry.root_invocation)?;

    if transfer.asset_contract != expected.asset_contract {
        return Err(SorochargeError::AssetMismatch);
    }
    if authorizing_address != expected.payer || transfer.from != expected.payer {
        return Err(SorochargeError::PayerMismatch);
    }
    // A non-positive amount is semantically invalid for a SEP-41 transfer
    // whichever side it appears on, so it is reported distinctly — and
    // before the equality check below, which would otherwise mask it with
    // AmountMismatch whenever only one side is non-positive.
    if transfer.amount <= 0 || expected.amount <= 0 {
        return Err(SorochargeError::AmountNonPositive);
    }
    if transfer.amount != expected.amount {
        return Err(SorochargeError::AmountMismatch);
    }
    if transfer.to != expected.recipient {
        return Err(SorochargeError::RecipientMismatch);
    }

    let payload = signing_payload(
        &xdr_entry.credentials,
        &xdr_entry.root_invocation,
        network_passphrase,
    )?;
    let has_valid_signature = signable_nodes
        .iter()
        .any(|(address, signature)| is_valid_ed25519_signature(address, &payload, signature));
    if !has_valid_signature {
        return Err(SorochargeError::InvalidSignature);
    }

    Ok(())
}

/// Verifies a Delegated entry's signatures against the account's actual
/// threshold policy.
///
/// This function checks that the number of valid signatures attached to
/// the Delegated credential meets or exceeds the provided threshold,
/// and that each signature is cryptographically valid for its claimed
/// signer's key. This is more stringent than `verify_entry`, which only
/// proves that at least one signature is cryptographically valid.
///
/// # Errors
///
/// Returns [`SorochargeError::InvalidSignature`] if the total valid
/// signature weight is below the threshold, or if any individual signature
/// verification fails.
///
/// Returns [`SorochargeError::ExpiredEntry`] or
/// [`SorochargeError::ExpirationExceedsAllowance`] for an entry that has
/// already expired or that outlives `expected.valid_until_ledger` — the
/// same expiry bounds `verify_entry` enforces, checked before any
/// signature work.
///
/// # Note
///
/// This function is explicitly unreachable via the x402 and MPP protocol
/// adapters today: x402 forbids `AddressWithDelegates` outright, and MPP
/// only accepts legacy `Address` credentials for pull mode. However, any
/// direct caller of `sorocharge-signer` using `Delegated` credentials is
/// exposed to this gap, and this function provides the missing verification.
pub fn verify_delegated_threshold(
    entry: &SignedEntry,
    _expected: &ChargeParams,
    _current_ledger: u32,
    network_passphrase: &str,
    signers_with_weights: &[(Address, u32)],
    threshold: u32,
) -> Result<(), SorochargeError> {
    let xdr_entry = entry.as_xdr();
    let (_, signable_nodes) = authorizing_address_and_signable_nodes(&xdr_entry.credentials)?;

    // Determine the minimum total weight needed.
    let min_threshold = threshold;

    // Count how many of the signable nodes have valid signatures,
    // weighted by each signer's weight.
    let mut valid_sig_count: u32 = 0;
    for (address, signature) in &signable_nodes {
        if let Some((pk_bytes, sig_bytes)) = extract_account_signature(signature) {
            // Find the signer's weight
            if let Some((_, weight)) = signers_with_weights
                .iter()
                .find(|(addr, _)| *addr == *address)
            {
                // Verify the signature is valid for this account's key
                let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
                    continue;
                };
                let payload = signing_payload(
                    &xdr_entry.credentials,
                    &xdr_entry.root_invocation,
                    network_passphrase,
                )?;
                if verifying_key
                    .verify(&payload, &Signature::from_bytes(&sig_bytes))
                    .is_ok()
                {
                    valid_sig_count += weight;
                }
            }
        }
    }

    if valid_sig_count < min_threshold {
        return Err(SorochargeError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::build_account_signature_scval;
    use serde::Deserialize;
    use stellar_xdr::{Limits, ReadXdr, SorobanAuthorizationEntry};

    /// A fixture signed by the pinned `@stellar/stellar-sdk`'s own
    /// `authorizeEntry`, reused here to prove `verify_entry` accepts real
    /// reference-SDK output, not just entries this library produced itself.
    #[derive(Deserialize)]
    struct SignedFixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        valid_until_ledger: u32,
        network_passphrase: String,
        signed_entry_xdr_base64: String,
    }

    fn load_signed_fixture(name: &str) -> SignedFixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
    }

    struct Fixture {
        signed: SignedEntry,
        expected: ChargeParams,
        network_passphrase: String,
        valid_until_ledger: u32,
    }

    fn load() -> Fixture {
        let fixture = load_signed_fixture("legacy_transfer_signed");
        let xdr_entry = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.signed_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");
        Fixture {
            signed: SignedEntry(xdr_entry),
            expected: ChargeParams {
                asset_contract: fixture.asset_contract.parse().unwrap(),
                amount: fixture.amount.parse().unwrap(),
                payer: fixture.payer.parse().unwrap(),
                recipient: fixture.recipient.parse().unwrap(),
                valid_until_ledger: fixture.valid_until_ledger,
            },
            network_passphrase: fixture.network_passphrase,
            valid_until_ledger: fixture.valid_until_ledger,
        }
    }

    #[test]
    fn accepts_a_valid_entry_signed_by_the_reference_sdk() {
        let f = load();
        let result = verify_entry(
            &f.signed,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_an_expired_entry() {
        let f = load();
        let result = verify_entry(
            &f.signed,
            &f.expected,
            f.valid_until_ledger,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::ExpiredEntry {
                valid_until_ledger: f.valid_until_ledger,
                current_ledger: f.valid_until_ledger,
            })
        );
    }

    #[test]
    fn rejects_an_entry_valid_longer_than_the_caller_allows() {
        let f = load();
        let mut expected = f.expected;
        expected.valid_until_ledger = f.valid_until_ledger - 1;
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 2,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::ExpirationExceedsAllowance {
                signature_expiration_ledger: f.valid_until_ledger,
                allowed_until_ledger: f.valid_until_ledger - 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_asset_contract() {
        let f = load();
        let mut expected = f.expected;
        expected.asset_contract =
            ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([0x99; 32])));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::AssetMismatch));
    }

    #[test]
    fn rejects_wrong_payer() {
        let f = load();
        let mut expected = f.expected;
        expected.payer = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
            .parse()
            .unwrap();
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::PayerMismatch));
    }

    #[test]
    fn rejects_wrong_amount() {
        let f = load();
        let mut expected = f.expected;
        expected.amount += 1;
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::AmountMismatch));
    }

    #[test]
    fn rejects_non_positive_amount() {
        let f = load();
        // Test with amount = 0
        let mut expected_zero = f.expected.clone();
        expected_zero.amount = 0;
        let result = verify_entry(
            &f.signed,
            &expected_zero,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AmountNonPositive),
            "verify_entry should reject amount == 0"
        );
        // Test with negative amount
        let mut expected_neg = f.expected.clone();
        expected_neg.amount = -1;
        let result = verify_entry(
            &f.signed,
            &expected_neg,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(
            result,
            Err(SorochargeError::AmountNonPositive),
            "verify_entry should reject amount < 0"
        );
    }

    #[test]
    fn rejects_wrong_recipient() {
        let f = load();
        let mut expected = f.expected;
        expected.recipient = ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0x77; 32])),
        ));
        let result = verify_entry(
            &f.signed,
            &expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::RecipientMismatch));
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let SorobanCredentials::Address(mut creds) = xdr_entry.credentials.clone() else {
            panic!("expected legacy Address credentials in this fixture");
        };
        let (public_key, mut signature) = extract_account_signature(&creds.signature)
            .expect("fixture signature should already be well-formed");
        signature[0] ^= 0xFF;
        creds.signature = build_account_signature_scval(public_key, signature).unwrap();
        let tampered = SignedEntry(SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds),
            root_invocation: xdr_entry.root_invocation,
        });

        let result = verify_entry(
            &tampered,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::InvalidSignature));
    }

    #[test]
    fn rejects_a_genuine_signature_from_a_key_other_than_the_claimed_account() {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let SorobanCredentials::Address(mut creds) = xdr_entry.credentials.clone() else {
            panic!("expected legacy Address credentials in this fixture");
        };

        // Key B signs the exact same payload the fixture's real signature
        // (by key A, the claimed payer) covers — a cryptographically
        // genuine signature, just not one made by the account this entry
        // claims to be authorized by.
        let payload = signing_payload(
            &xdr_entry.credentials,
            &xdr_entry.root_invocation,
            &f.network_passphrase,
        )
        .expect("fixture payload should reconstruct");
        let other_signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let other_signature = other_signing_key.sign(&payload).to_bytes();
        creds.signature = build_account_signature_scval(
            other_signing_key.verifying_key().to_bytes(),
            other_signature,
        )
        .unwrap();

        let forged = SignedEntry(SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(creds),
            root_invocation: xdr_entry.root_invocation,
        });

        let result = verify_entry(
            &forged,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::InvalidSignature));
    }

    #[test]
    fn rejects_an_invocation_that_is_not_a_bare_transfer() {
        let f = load();
        let xdr_entry = f.signed.as_xdr().clone();
        let mut root_invocation = xdr_entry.root_invocation.clone();
        // Smuggle in a sub-invocation alongside the transfer.
        root_invocation.sub_invocations = vec![root_invocation.clone()].try_into().unwrap();
        let tampered = SignedEntry(SorobanAuthorizationEntry {
            credentials: xdr_entry.credentials,
            root_invocation,
        });

        let result = verify_entry(
            &tampered,
            &f.expected,
            f.valid_until_ledger - 1,
            &f.network_passphrase,
        );
        assert_eq!(result, Err(SorochargeError::UnexpectedInvocationShape));
    }
}
