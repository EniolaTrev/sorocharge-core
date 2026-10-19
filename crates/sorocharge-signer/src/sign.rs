use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, PublicKey, ScAddress, ScBytes, ScMap,
    ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAddressCredentialsWithDelegates,
    SorobanAuthorizationEntry, SorobanCredentials, Uint256, VecM, WriteXdr,
};

use stellar_xdr::SorobanAuthorizedInvocation;

use crate::entry::{Address, UnsignedEntry};
use crate::error::SorochargeError;

/// A source of ed25519 signatures, plus the address it signs for.
///
/// Implementations wrap a signing key already in memory (or a remote
/// signing callback); this library does not manage keys.
///
/// # Examples
///
/// A signer can wrap an in-memory Ed25519 key. This deterministic key is for
/// the example only; applications should supply their own key source.
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{Address, SorochargeError, Signer};
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
/// let signature = signer.sign_preimage(&[0x42; 32])?;
/// assert_eq!(signature.len(), 64);
/// # Ok(())
/// # }
/// ```
pub trait Signer: Send + Sync {
    /// Signs `preimage` — the 32-byte sha256 digest of the entry's
    /// `HashIdPreimage` — and returns the raw 64-byte ed25519 signature.
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError>;
    /// The Ed25519 account address (`G...`) this signer signs for. Used to
    /// build the standard `{public_key, signature}` credential signature
    /// and to find which credential node (top-level address, or a
    /// delegate) this signature belongs to.
    fn address(&self) -> Address;
}

/// A `SorobanAuthorizationEntry` that carries a valid signature on the node
/// matching its signer's address, ready to serialize to XDR and submit.
///
/// # Examples
///
/// Build and sign a transfer authorization, then inspect its XDR entry:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{
///     build_charge_entry, parse_address, sign_entry, Address, ChargeParams, CredentialKind,
///     SorochargeError, Signer,
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
///     amount: 1_500,
///     payer: signer.address(),
///     recipient: parse_address("GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N")?,
///     valid_until_ledger: 1_000,
/// };
/// let unsigned = build_charge_entry(&params, CredentialKind::AddressV2)?;
/// let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015")?;
/// let xdr_entry = signed.as_xdr();
/// assert!(matches!(
///     &xdr_entry.credentials,
///     stellar_xdr::SorobanCredentials::AddressV2(_)
/// ));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEntry(pub(crate) SorobanAuthorizationEntry);

impl SignedEntry {
    /// The wrapped `SorobanAuthorizationEntry`, ready to attach to an
    /// `InvokeHostFunction` operation.
    #[must_use]
    pub fn as_xdr(&self) -> &SorobanAuthorizationEntry {
        &self.0
    }

    /// Wraps an entry that already carries a signature — typically one a
    /// facilitator or payee received over the wire from a payer, rather
    /// than one this process signed itself — so it can be checked with
    /// [`crate::verify_entry`].
    ///
    /// This performs no validation: it does not check the entry actually
    /// carries a non-placeholder signature, let alone a valid one.
    /// `verify_entry` is what proves that.
    #[must_use]
    pub fn from_xdr(entry: SorobanAuthorizationEntry) -> Self {
        Self(entry)
    }
}

/// The 32-byte SHA-256 of a network passphrase — Stellar's `network_id`,
/// the value binding every signed transaction and authorization entry to
/// exactly one network.
///
/// Exported so the protocol crates' settlement paths derive the same value
/// this crate bakes into each signing payload, rather than each carrying
/// its own copy of the identical five lines (a drift risk this project's
/// "one audited signing engine, not two" brief exists to prevent).
#[must_use]
pub fn network_id_hash(network_passphrase: &str) -> [u8; 32] {
    Sha256::digest(network_passphrase.as_bytes()).into()
}

fn compute_network_id(network_passphrase: &str) -> Hash {
    Hash(network_id_hash(network_passphrase))
}

/// The `(nonce, signature_expiration_ledger, address-bound-to)` fields a
/// `HashIdPreimage` needs, read from whichever `SorobanCredentials` variant
/// `credentials` is. `address_bound_to` is `None` for `Legacy` (whose
/// preimage does not bind an address) and `Some` for `AddressV2` and
/// `AddressWithDelegates` (CAP-71's address-bound preimage).
pub(crate) fn credential_preimage_fields(
    credentials: &SorobanCredentials,
) -> Result<(i64, u32, Option<Address>), SorochargeError> {
    match credentials {
        SorobanCredentials::Address(c) => Ok((c.nonce, c.signature_expiration_ledger, None)),
        SorobanCredentials::AddressV2(c) => Ok((
            c.nonce,
            c.signature_expiration_ledger,
            Some(c.address.clone()),
        )),
        SorobanCredentials::AddressWithDelegates(c) => Ok((
            c.address_credentials.nonce,
            c.address_credentials.signature_expiration_ledger,
            Some(c.address_credentials.address.clone()),
        )),
        SorobanCredentials::SourceAccount => Err(SorochargeError::UnsupportedCredentialType),
    }
}

/// The sha256 digest of the entry's `HashIdPreimage` — the payload every
/// credential's signature (top-level or delegate) is computed over. Shared
/// by `sign_entry` (which signs it) and `verify_entry` (which checks
/// signatures against it), so the two can never reconstruct it differently.
pub(crate) fn signing_payload(
    credentials: &SorobanCredentials,
    root_invocation: &SorobanAuthorizedInvocation,
    network_passphrase: &str,
) -> Result<[u8; 32], SorochargeError> {
    let (nonce, signature_expiration_ledger, address_bound_to) =
        credential_preimage_fields(credentials)?;
    let network_id = compute_network_id(network_passphrase);

    let preimage = match address_bound_to {
        None => HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce,
            signature_expiration_ledger,
            invocation: root_invocation.clone(),
        }),
        Some(address) => HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id,
                nonce,
                signature_expiration_ledger,
                address,
                invocation: root_invocation.clone(),
            },
        ),
    };

    let preimage_bytes =
        preimage
            .to_xdr(Limits::none())
            .map_err(|e| SorochargeError::XdrEncodingFailed {
                reason: format!("failed to encode HashIdPreimage: {e}"),
            })?;
    Ok(Sha256::digest(&preimage_bytes).into())
}

/// Builds the standard Stellar account signature: a one-element vector
/// holding a `{public_key, signature}` map, as `__check_auth` for a plain
/// `G...` account expects. `signer`'s address must be an `Ed25519` account,
/// not a contract — a contract address has no key to attach here.
pub(crate) fn build_account_signature_scval(
    public_key: [u8; 32],
    signature: [u8; 64],
) -> Result<ScVal, SorochargeError> {
    let xdr_encoding_failed = |reason: &str| SorochargeError::XdrEncodingFailed {
        reason: reason.to_string(),
    };

    let public_key_entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol(
            "public_key"
                .try_into()
                .map_err(|_| xdr_encoding_failed("\"public_key\" symbol"))?,
        )),
        val: ScVal::Bytes(ScBytes(
            public_key
                .to_vec()
                .try_into()
                .map_err(|_| xdr_encoding_failed("public key bytes"))?,
        )),
    };
    let signature_entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol(
            "signature"
                .try_into()
                .map_err(|_| xdr_encoding_failed("\"signature\" symbol"))?,
        )),
        val: ScVal::Bytes(ScBytes(
            signature
                .to_vec()
                .try_into()
                .map_err(|_| xdr_encoding_failed("signature bytes"))?,
        )),
    };

    // Canonical SCMap order: entries sorted by key, and "public_key" < "signature".
    let map: VecM<ScMapEntry> = vec![public_key_entry, signature_entry]
        .try_into()
        .map_err(|_| xdr_encoding_failed("signature map"))?;
    let vec: VecM<ScVal> = vec![ScVal::Map(Some(ScMap(map)))]
        .try_into()
        .map_err(|_| xdr_encoding_failed("signature vector"))?;
    Ok(ScVal::Vec(Some(ScVec(vec))))
}

/// Writes `signature_scval` onto whichever node of `credentials` (top-level
/// address, or one delegate) has address `target`, leaving every other node
/// untouched.
///
/// A `Delegated` entry with more than one required signer needs one
/// `sign_entry` call per signer; each call targets exactly the node whose
/// address matches that signer, mirroring the reference SDK's `forAddress`
/// targeting. Accumulating multiple delegates' signatures across separate
/// calls is not supported by this function alone (its input/output types
/// are both single-shot), and is intentionally left for a caller-level
/// merge step rather than guessed at here.
fn sign_matching_node(
    credentials: SorobanCredentials,
    target: &Address,
    signature_scval: ScVal,
) -> Result<SorobanCredentials, SorochargeError> {
    match credentials {
        SorobanCredentials::Address(mut c) if &c.address == target => {
            c.signature = signature_scval;
            Ok(SorobanCredentials::Address(c))
        }
        SorobanCredentials::AddressV2(mut c) if &c.address == target => {
            c.signature = signature_scval;
            Ok(SorobanCredentials::AddressV2(c))
        }
        SorobanCredentials::AddressWithDelegates(c) => {
            sign_with_delegates(c, target, signature_scval)
                .map(SorobanCredentials::AddressWithDelegates)
        }
        SorobanCredentials::Address(_)
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::SourceAccount => Err(SorochargeError::NoMatchingCredentialNode),
    }
}

fn sign_with_delegates(
    mut credentials: SorobanAddressCredentialsWithDelegates,
    target: &Address,
    signature_scval: ScVal,
) -> Result<SorobanAddressCredentialsWithDelegates, SorochargeError> {
    if &credentials.address_credentials.address == target {
        credentials.address_credentials.signature = signature_scval;
        return Ok(credentials);
    }

    let mut matched = false;
    let signed_delegates: Vec<_> = credentials
        .delegates
        .into_iter()
        .map(|mut delegate| {
            if !matched && &delegate.address == target {
                delegate.signature = signature_scval.clone();
                matched = true;
            }
            delegate
        })
        .collect();

    if !matched {
        return Err(SorochargeError::NoMatchingCredentialNode);
    }

    credentials.delegates =
        signed_delegates
            .try_into()
            .map_err(|_| SorochargeError::XdrEncodingFailed {
                reason: "delegate list exceeds XDR limit".to_string(),
            })?;
    Ok(credentials)
}

/// Signs an unsigned charge entry, producing a [`SignedEntry`] ready to
/// submit.
///
/// The signature is written to whichever credential node — the top-level
/// address, or (for `Delegated`) one delegate — has an address matching
/// `signer.address()`. The signing payload is the sha256 of the entry's
/// `HashIdPreimage`, reconstructed for the entry's actual credential type:
/// the legacy, non-address-bound preimage for `Legacy`, and the CAP-71
/// address-bound preimage for `AddressV2` and `Delegated`.
///
/// `network_passphrase` is hashed into the preimage's `network_id`: the
/// signing payload is network-bound, so signing for the wrong network
/// produces a signature the intended network's host will reject (and,
/// worse, one that could be replayed if the wrong passphrase were reused
/// across networks) — this is why it is a required argument here rather
/// than assumed.
///
/// # Errors
///
/// Returns [`SorochargeError::NoMatchingCredentialNode`] if `signer`'s
/// address matches no signable node in `entry`, and
/// [`SorochargeError::SigningFailed`] if `signer` itself fails, or is not
/// an Ed25519 account address.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use ed25519_dalek::{Signer as DalekSigner, SigningKey};
/// use sorocharge_signer::{
///     build_charge_entry, parse_address, sign_entry, Address, ChargeParams, CredentialKind,
///     SorochargeError, Signer,
/// };
/// use stellar_xdr::{AccountId, PublicKey, ScAddress, SorobanCredentials, Uint256};
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
/// assert!(matches!(
///     &signed.as_xdr().credentials,
///     SorobanCredentials::AddressV2(_)
/// ));
/// # Ok(())
/// # }
/// ```
pub fn sign_entry(
    entry: UnsignedEntry,
    signer: &dyn Signer,
    network_passphrase: &str,
) -> Result<SignedEntry, SorochargeError> {
    let SorobanAuthorizationEntry {
        credentials,
        root_invocation,
    } = entry.0;

    let target = signer.address();
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key)))) =
        target.clone()
    else {
        return Err(SorochargeError::SigningFailed {
            reason: "signer address must be an Ed25519 account (G...), not a contract".to_string(),
        });
    };

    let payload = signing_payload(&credentials, &root_invocation, network_passphrase)?;
    let raw_signature = signer.sign_preimage(&payload)?;
    let signature_scval = build_account_signature_scval(public_key, raw_signature)?;

    let signed_credentials = sign_matching_node(credentials, &target, signature_scval)?;

    Ok(SignedEntry(SorobanAuthorizationEntry {
        credentials: signed_credentials,
        root_invocation,
    }))
}

#[cfg(test)]
mod golden_vector_tests {
    use super::*;
    use crate::entry::{build_charge_entry_with_nonce, ChargeParams, CredentialKind};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use serde::Deserialize;
    use stellar_xdr::ReadXdr;

    /// Diffs `sign_entry`'s XDR output — including the signature it
    /// produces — against a fixture signed by the pinned
    /// `@stellar/stellar-sdk`'s own `authorizeEntry`.
    #[derive(Deserialize)]
    struct SignedFixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        valid_until_ledger: u32,
        nonce: String,
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

    /// A fixed-seed ed25519 signer matching the `payerKeypair` that
    /// `generate.mjs` derives via `Keypair.fromRawEd25519Seed`, so both
    /// sides sign with the identical key.
    struct FixedSeedSigner {
        signing_key: SigningKey,
        address: Address,
    }

    impl Signer for FixedSeedSigner {
        fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
            Ok(self.signing_key.sign(preimage).to_bytes())
        }

        fn address(&self) -> Address {
            self.address.clone()
        }
    }

    #[test]
    fn legacy_sign_entry_matches_reference_sdk_byte_for_byte() {
        let fixture = load_signed_fixture("legacy_transfer_signed");

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

        // The same 32-byte seed generate.mjs passes to Keypair.fromRawEd25519Seed
        // for the payer, so both sides sign with the identical key.
        let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let signer = FixedSeedSigner {
            signing_key,
            address: params.payer.clone(),
        };

        let signed = sign_entry(unsigned, &signer, &fixture.network_passphrase)
            .expect("sign_entry should succeed against a matching signer address");

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.signed_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = signed
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("signed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's signed entry XDR (including the ed25519 signature) must be byte-identical to @stellar/stellar-sdk 17.2.0's authorizeEntry output"
        );
    }

    #[test]
    fn sign_entry_rejects_signer_for_a_different_address() {
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
        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::Legacy, 1).unwrap();

        // A signer for an address other than the payer's.
        let signing_key = SigningKey::from_bytes(&[0x99u8; 32]);
        let wrong_address: Address = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
            .parse()
            .unwrap();
        let signer = FixedSeedSigner {
            signing_key,
            address: wrong_address,
        };

        let result = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015");

        assert_eq!(
            result.unwrap_err(),
            SorochargeError::NoMatchingCredentialNode
        );
    }
}

#[cfg(test)]
mod network_id_tests {
    use super::network_id_hash;

    /// Locks the exported `network_id_hash` to Stellar's well-known network
    /// IDs, so the protocol crates' settlement paths are provably hashing a
    /// passphrase to the same value this crate already bakes into every
    /// signing payload.
    #[test]
    fn matches_the_well_known_stellar_network_ids() {
        assert_eq!(
            network_id_hash("Test SDF Network ; September 2015"),
            [
                0xce, 0xe0, 0x30, 0x2d, 0x59, 0x84, 0x4d, 0x32, 0xbd, 0xca, 0x91, 0x5c, 0x82, 0x03,
                0xdd, 0x44, 0xb3, 0x3f, 0xbb, 0x7e, 0xdc, 0x19, 0x05, 0x1e, 0xa3, 0x7a, 0xbe, 0xdf,
                0x28, 0xec, 0xd4, 0x72,
            ]
        );
        assert_eq!(
            network_id_hash("Public Global Stellar Network ; September 2015"),
            [
                0x7a, 0xc3, 0x39, 0x97, 0x54, 0x4e, 0x31, 0x75, 0xd2, 0x66, 0xbd, 0x02, 0x24, 0x39,
                0xb2, 0x2c, 0xdb, 0x16, 0x50, 0x8c, 0x01, 0x16, 0x3f, 0x26, 0xe5, 0xcb, 0x2a, 0x3e,
                0x10, 0x45, 0xa9, 0x79,
            ]
        );
    }
}
