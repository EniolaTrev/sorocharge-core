//! JSON wire types for MPP's `draft-stellar-charge-00`, layered on the base
//! `draft-httpauth-payment-01` auth scheme and `draft-payment-intent-charge-00`
//! charge intent (all in `tempoxyz/mpp-specs`). Field names and shapes are
//! copied verbatim from those specs, not inferred.
//!
//! ## Per-field length bounds
//!
//! A `WWW-Authenticate: Payment` challenge and an `Authorization: Payment`
//! credential are attacker-influenced input on the payer client, and the
//! `request` echoed back inside a credential is attacker-influenced input on
//! the server, so an overall message-size cap alone is not enough: a
//! malicious peer could spend the entire allowed size on a single field. The
//! free-text fields reachable from those messages — `Challenge.realm`,
//! `Challenge.description`, and `ChargeRequest.description` — therefore carry
//! an explicit per-field maximum (the `MAX_*` constants below), enforced
//! **while deserializing**: an over-long field fails decoding with an error
//! naming the offending field and both lengths — it is never silently
//! truncated. This is a defense-in-depth complement to any overall
//! body-size cap, not a duplicate of it. Machine payloads with no meaningful
//! small bound — the base64url `Challenge.request` blob and the
//! `Payload::Transaction` envelope — are deliberately left out.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Per-field maximum lengths, in UTF-8 bytes.
// ---------------------------------------------------------------------------
//
// Bytes, not characters, because the budget these protect is a byte
// budget: an overall message cap counts bytes, and so must the per-field
// bounds that complement it. Each bound is enforced on deserialize via the
// `deserialize_*` helpers below, so every path that parses these wire types
// — decoding a received credential, re-reading the echoed `request` during
// settlement, and anything a caller wires up — gets the check for free.

/// Maximum UTF-8 byte length of `Challenge::realm`.
///
/// A realm is a host or short display string (`"api.example.com"` in the
/// spec's own examples) that also has to fit in the `WWW-Authenticate`
/// header alongside the id and the base64url `request`; 253 matches the
/// maximum DNS name length, leaving room for any realistic realm without
/// admitting free text.
pub const MAX_REALM_LEN: usize = 253;

/// Maximum UTF-8 byte length of `Challenge::description` and
/// `ChargeRequest::description`.
///
/// A paragraph-plus of human-readable text; the spec's own examples are
/// single short sentences. Deliberately the same value as
/// `sorocharge-x402`'s `MAX_DESCRIPTION_LEN`, so one number bounds the
/// same-named field in both protocol crates.
pub const MAX_DESCRIPTION_LEN: usize = 2048;

/// Rejects `value` if it exceeds `max` bytes, naming the field and both
/// lengths in the error so the receiver can tell which field broke the
/// limit and by how much. Shared by every bounded field.
fn enforce_max<E>(value: String, field: &str, max: usize) -> Result<String, E>
where
    E: serde::de::Error,
{
    let len = value.len();
    if len > max {
        return Err(E::custom(format!(
            "field `{field}` exceeds its maximum length of {max} bytes (got {len} bytes)"
        )));
    }
    Ok(value)
}

/// Deserializes one bounded string field: decode, then apply
/// `enforce_max`. A value within the limit is returned byte-for-byte
/// unchanged — the bound rejects over-long input, it never truncates.
fn bounded_string<'de, D>(deserializer: D, field: &str, max: usize) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    enforce_max::<D::Error>(String::deserialize(deserializer)?, field, max)
}

/// `bounded_string` for an optional field: absent/`null` decode to
/// `None`; a present value obeys the same limit.
fn bounded_opt_string<'de, D>(
    deserializer: D,
    field: &str,
    max: usize,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => enforce_max::<D::Error>(value, field, max).map(Some),
        None => Ok(None),
    }
}

fn deserialize_realm<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "realm", MAX_REALM_LEN)
}

/// Used by both `Challenge::description` and `ChargeRequest::description` —
/// same field name, same limit, same error text.
fn deserialize_description<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_opt_string(deserializer, "description", MAX_DESCRIPTION_LEN)
}

/// The Stellar-specific `methodDetails` object inside a charge request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MethodDetails {
    /// CAIP-2 Stellar chain identifier: `"stellar:pubnet"` or `"stellar:testnet"`.
    pub network: String,
    /// If `true`, the server sponsors transaction fees (pull mode only).
    #[serde(default)]
    pub fee_payer: bool,
}

/// The `request` object carried (base64url + JCS-encoded) in a challenge's
/// `request` auth-param: the shared "charge" intent fields plus Stellar's
/// `methodDetails`.
///
/// `description` carries a per-field maximum length (see
/// [`MAX_DESCRIPTION_LEN`]), enforced on deserialize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChargeRequest {
    /// Stringified non-negative integer, SEP-41 base units.
    pub amount: String,
    /// The SEP-41 token contract address (`C...`).
    pub currency: String,
    /// The recipient's Stellar account address (`G...`).
    pub recipient: String,
    /// Free-text description of the charge. Bounded by
    /// [`MAX_DESCRIPTION_LEN`] bytes, enforced on deserialize.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_description"
    )]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub method_details: MethodDetails,
}

/// The challenge auth-params, as echoed in a credential's `challenge`
/// object. `request` here is the still-encoded base64url string, not the
/// decoded `ChargeRequest` — the credential must echo it byte-for-byte for
/// challenge-binding verification.
///
/// `realm` and `description` carry per-field maximum lengths (see
/// [`MAX_REALM_LEN`] and [`MAX_DESCRIPTION_LEN`]), enforced on deserialize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub id: String,
    /// The realm the challenge was issued for, e.g. `"api.example.com"`.
    /// Bounded by [`MAX_REALM_LEN`] bytes, enforced on deserialize.
    #[serde(deserialize_with = "deserialize_realm")]
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    /// Free-text description of the challenge. Bounded by
    /// [`MAX_DESCRIPTION_LEN`] bytes, enforced on deserialize.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_description"
    )]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// The Stellar-specific `payload` of a credential, keyed by `type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Payload {
    /// Pull mode (default): a base64-encoded `TransactionEnvelope`.
    Transaction { transaction: String },
    /// Push mode (fallback): a 64-character hex transaction hash, for a
    /// transaction the client already broadcast itself.
    Hash { hash: String },
}

/// The full credential sent in the `Authorization` (or
/// `Payment-Authorization`) header, base64url-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub challenge: Challenge,
    pub payload: Payload,
    /// The payer's identity, recommended as a `did:pkh` DID, e.g.
    /// `did:pkh:stellar:testnet:GABC...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The `Payment-Receipt` header payload on a successful settlement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Always `"stellar"`.
    pub method: String,
    /// The settled transaction hash.
    pub reference: String,
    /// Always `"success"` — receipts are only issued on success.
    pub status: String,
    /// RFC 3339 settlement timestamp.
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `draft-stellar-charge-00`'s `methodDetails` example.
    const CHARGE_REQUEST_JSON: &str = r#"
    {
      "amount": "10000000",
      "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4W",
      "recipient": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU",
      "description": "API access fee",
      "methodDetails": {
        "network": "stellar:testnet",
        "feePayer": true
      }
    }
    "#;

    /// Verbatim from the same spec's pull-mode "Transaction Payload" example.
    const CREDENTIAL_JSON: &str = r#"
    {
      "challenge": {
        "id": "kM9xPqWvT2nJrHsY4aDfEb",
        "realm": "api.example.com",
        "method": "stellar",
        "intent": "charge",
        "request": "eyJ...",
        "expires": "2025-02-05T12:05:00Z"
      },
      "payload": {
        "type": "transaction",
        "transaction": "AAAAAgAAAABriIN4..."
      },
      "source": "did:pkh:stellar:testnet:GABC..."
    }
    "#;

    /// Verbatim from the same spec's push-mode "Hash Payload" example.
    const HASH_CREDENTIAL_JSON: &str = r#"
    {
      "challenge": {
        "id": "pT7yHnKmQ2wErXsZ5vCbNl",
        "realm": "api.example.com",
        "method": "stellar",
        "intent": "charge",
        "request": "eyJ...",
        "expires": "2025-02-05T12:05:00Z"
      },
      "payload": {
        "type": "hash",
        "hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
      },
      "source": "did:pkh:stellar:testnet:GABC..."
    }
    "#;

    #[test]
    fn charge_request_matches_spec_example_field_for_field() {
        let parsed: ChargeRequest = serde_json::from_str(CHARGE_REQUEST_JSON).unwrap();
        assert_eq!(parsed.amount, "10000000");
        assert_eq!(parsed.currency, "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4W");
        assert_eq!(parsed.recipient, "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU");
        assert_eq!(parsed.description.as_deref(), Some("API access fee"));
        assert_eq!(parsed.method_details.network, "stellar:testnet");
        assert!(parsed.method_details.fee_payer);

        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in [
            "amount",
            "currency",
            "recipient",
            "description",
            "methodDetails",
        ] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
        assert!(value["methodDetails"].get("feePayer").is_some());
    }

    #[test]
    fn transaction_credential_matches_spec_example_field_for_field() {
        let parsed: Credential = serde_json::from_str(CREDENTIAL_JSON).unwrap();
        assert_eq!(parsed.challenge.id, "kM9xPqWvT2nJrHsY4aDfEb");
        assert_eq!(parsed.challenge.method, "stellar");
        assert_eq!(parsed.challenge.intent, "charge");
        assert_eq!(
            parsed.source.as_deref(),
            Some("did:pkh:stellar:testnet:GABC...")
        );
        match parsed.payload {
            Payload::Transaction { transaction } => {
                assert!(transaction.starts_with("AAAAAgAAAABriIN4"));
            }
            Payload::Hash { .. } => panic!("expected a transaction payload"),
        }
    }

    #[test]
    fn hash_credential_matches_spec_example_field_for_field() {
        let parsed: Credential = serde_json::from_str(HASH_CREDENTIAL_JSON).unwrap();
        match parsed.payload {
            Payload::Hash { hash } => {
                assert_eq!(hash.len(), 64);
            }
            Payload::Transaction { .. } => panic!("expected a hash payload"),
        }
    }

    /// A minimal but complete `Challenge` body in which only `realm` and
    /// `description` vary, so each length test varies exactly one field.
    fn challenge_json(realm: &str, description: Option<String>) -> String {
        serde_json::json!({
            "id": "kM9xPqWvT2nJrHsY4aDfEb",
            "realm": realm,
            "method": "stellar",
            "intent": "charge",
            "request": "eyJ...",
            "description": description,
        })
        .to_string()
    }

    /// A complete `ChargeRequest` body in which only `description` varies.
    fn charge_request_json(description: String) -> String {
        serde_json::json!({
            "amount": "10000000",
            "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4W",
            "recipient": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU",
            "description": description,
            "methodDetails": {
                "network": "stellar:testnet",
                "feePayer": true,
            },
        })
        .to_string()
    }

    /// Deserializes `json` as `T` and asserts it fails with exactly the
    /// field-specific length error. The failure itself is the proof that an
    /// over-long field is rejected rather than silently truncated — a
    /// truncating implementation would have decoded successfully.
    fn assert_field_too_long<T>(json: &str, field: &str, max: usize, actual: usize)
    where
        T: serde::de::DeserializeOwned + std::fmt::Debug,
    {
        let err = serde_json::from_str::<T>(json)
            .expect_err("an over-long field must be rejected, not accepted or truncated");
        let msg = err.to_string();
        let expected = format!(
            "field `{field}` exceeds its maximum length of {max} bytes (got {actual} bytes)"
        );
        assert!(
            msg.contains(&expected),
            "expected error containing {expected:?}, got: {msg}"
        );
    }

    #[test]
    fn oversized_challenge_realm_is_rejected_with_specific_error() {
        let json = challenge_json(&"r".repeat(MAX_REALM_LEN + 1), None);
        assert_field_too_long::<Challenge>(&json, "realm", MAX_REALM_LEN, MAX_REALM_LEN + 1);
    }

    #[test]
    fn oversized_challenge_description_is_rejected_with_specific_error() {
        let json = challenge_json("api.example.com", Some("d".repeat(MAX_DESCRIPTION_LEN + 1)));
        assert_field_too_long::<Challenge>(
            &json,
            "description",
            MAX_DESCRIPTION_LEN,
            MAX_DESCRIPTION_LEN + 1,
        );
    }

    #[test]
    fn oversized_charge_request_description_is_rejected_with_specific_error() {
        let json = charge_request_json("d".repeat(MAX_DESCRIPTION_LEN + 1));
        assert_field_too_long::<ChargeRequest>(
            &json,
            "description",
            MAX_DESCRIPTION_LEN,
            MAX_DESCRIPTION_LEN + 1,
        );
    }

    #[test]
    fn bounded_fields_exactly_at_their_maximum_length_are_accepted_verbatim() {
        let realm = "r".repeat(MAX_REALM_LEN);
        let description = "d".repeat(MAX_DESCRIPTION_LEN);

        let challenge: Challenge =
            serde_json::from_str(&challenge_json(&realm, Some(description.clone())))
                .expect("at-limit values must decode");
        assert_eq!(challenge.realm, realm);
        assert_eq!(challenge.description.as_deref(), Some(description.as_str()));

        let request: ChargeRequest =
            serde_json::from_str(&charge_request_json(description.clone()))
                .expect("at-limit values must decode");
        assert_eq!(request.description.as_deref(), Some(description.as_str()));

        // An absent or null description still decodes to `None`.
        let challenge: Challenge = serde_json::from_str(&challenge_json(&realm, None))
            .expect("null description must decode");
        assert_eq!(challenge.description, None);
    }

    #[test]
    fn length_bounds_count_utf8_bytes_not_characters() {
        // "é" is two UTF-8 bytes: MAX_DESCRIPTION_LEN / 2 + 1 of them exceed
        // the bound in bytes while sitting well within it in characters. The
        // byte count is what protects the byte budget, so the byte count wins.
        let description = "é".repeat(MAX_DESCRIPTION_LEN / 2 + 1); // 1025 chars = 2050 bytes
        let json = challenge_json("api.example.com", Some(description));
        assert_field_too_long::<Challenge>(
            &json,
            "description",
            MAX_DESCRIPTION_LEN,
            MAX_DESCRIPTION_LEN + 2,
        );
    }
}
