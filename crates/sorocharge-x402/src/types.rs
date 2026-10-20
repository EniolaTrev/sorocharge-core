//! JSON wire types for the x402 protocol v2, scoped to the Stellar `exact`
//! scheme (`specs/schemes/exact/scheme_exact_stellar.md` in
//! `x402-foundation/x402`). Field names and shapes are copied verbatim from
//! that spec, not inferred — this crate does not invent wire formats for a
//! protocol it doesn't own.
//!
//! ## Per-field length bounds
//!
//! A `402` response body is attacker-influenced input on the client side
//! (and a `/verify`/`/settle` request body is on the facilitator side), so
//! an overall response-body size cap alone is not enough: a malicious or
//! compromised resource server could spend the entire allowed body size on
//! a single field. Every string field reachable from a `PaymentRequired`
//! body therefore carries an explicit per-field maximum (the `MAX_*`
//! constants below), enforced **while deserializing**: an over-long field
//! fails decoding with an error naming the offending field and both
//! lengths — it is never silently truncated. This is a defense-in-depth
//! complement to the overall body-size cap, not a duplicate of it. The
//! base64 `StellarPayload.transaction` envelope and `extensions` blobs are
//! deliberately left to that overall cap: they are machine payloads with
//! no meaningful small bound.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Per-field maximum lengths, in UTF-8 bytes.
// ---------------------------------------------------------------------------
//
// Bytes, not characters, because the budget these protect is a byte
// budget: the overall response-body cap counts bytes, and so must the
// per-field bounds that complement it. Each bound is enforced on
// deserialize via the `deserialize_*` helpers below, so every path that
// parses these wire types — client `PAYMENT-REQUIRED` header parsing,
// facilitator request bodies, and anything a caller wires up — gets the
// check for free.

/// Maximum UTF-8 byte length of `ResourceInfo::url`.
///
/// Generous for real-world resource URLs — twice the classic ~2 KiB
/// practical-URL ceiling, while staying well below the 8 KiB HTTP
/// header-buffer limit most servers impose on the `PAYMENT-REQUIRED`
/// header that carries this JSON.
pub const MAX_URL_LEN: usize = 4096;

/// Maximum UTF-8 byte length of `ResourceInfo::description`.
///
/// A paragraph-plus of human-readable text; the x402 spec's own examples
/// are single short sentences.
pub const MAX_DESCRIPTION_LEN: usize = 2048;

/// Maximum UTF-8 byte length of `ResourceInfo::mime_type`.
///
/// Long enough for any registered media type plus parameters
/// (`application/vnd.api+json; charset=utf-8`), short enough to rule out
/// free text smuggled into the field.
pub const MAX_MIME_TYPE_LEN: usize = 256;

/// Maximum UTF-8 byte length of `PaymentRequired::error`.
pub const MAX_ERROR_MESSAGE_LEN: usize = 1024;

/// Maximum UTF-8 byte length of `PaymentRequirements::scheme`.
///
/// What this crate implements is `"exact"`; the bound leaves room for
/// other short scheme identifiers without admitting free text.
pub const MAX_SCHEME_LEN: usize = 32;

/// Maximum UTF-8 byte length of `PaymentRequirements::network`.
///
/// CAIP-2 identifiers (`"stellar:pubnet"`, `"stellar:testnet"`) are
/// short by construction.
pub const MAX_NETWORK_LEN: usize = 64;

/// Maximum UTF-8 byte length of `PaymentRequirements::amount`.
///
/// A decimal string of base units; an `i128` is at most 39 digits, so 64
/// leaves generous headroom for sign/formatting while ruling out a digit
/// string long enough to dominate the response budget.
pub const MAX_AMOUNT_LEN: usize = 64;

/// Maximum UTF-8 byte length of the SEP-41 strkey fields
/// `PaymentRequirements::asset` and `PaymentRequirements::pay_to`.
///
/// Canonical `C...`/`G...` strkeys are 56 base32 characters and muxed
/// `M...` addresses are only a little longer; 128 leaves headroom for
/// future strkey types without admitting free text.
pub const MAX_STRKEY_LEN: usize = 128;

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

fn deserialize_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "url", MAX_URL_LEN)
}

fn deserialize_description<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_opt_string(deserializer, "description", MAX_DESCRIPTION_LEN)
}

fn deserialize_mime_type<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_opt_string(deserializer, "mimeType", MAX_MIME_TYPE_LEN)
}

fn deserialize_error_message<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_opt_string(deserializer, "error", MAX_ERROR_MESSAGE_LEN)
}

fn deserialize_scheme<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "scheme", MAX_SCHEME_LEN)
}

fn deserialize_network<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "network", MAX_NETWORK_LEN)
}

fn deserialize_amount<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "amount", MAX_AMOUNT_LEN)
}

fn deserialize_asset<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "asset", MAX_STRKEY_LEN)
}

fn deserialize_pay_to<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_string(deserializer, "payTo", MAX_STRKEY_LEN)
}

/// The protected resource a `PaymentRequired`/`PaymentPayload` concerns.
///
/// All three string fields carry per-field maximum lengths (see the
/// `MAX_*` constants), enforced on deserialize.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// The protected resource's URL. Bounded by `MAX_URL_LEN` bytes.
    #[serde(deserialize_with = "deserialize_url")]
    pub url: String,
    /// Human-readable text describing what payment unlocks. Bounded by
    /// `MAX_DESCRIPTION_LEN` bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_description"
    )]
    pub description: Option<String>,
    /// The resource's media type. Bounded by `MAX_MIME_TYPE_LEN` bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_mime_type"
    )]
    pub mime_type: Option<String>,
}

/// The `extra` object the `exact` scheme on Stellar requires inside each
/// `PaymentRequirements` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StellarExtra {
    /// Whether the facilitator sponsors transaction fees. Per the spec this
    /// is "currently always true"; a non-sponsored flow does not exist yet.
    pub are_fees_sponsored: bool,
}

/// One acceptable way to pay, as carried in `PaymentRequired.accepts[]` and
/// echoed back in `PaymentPayload.accepted`.
///
/// Its string fields are bounded too: an `accepts[]` entry is attacker-
/// influenced input on both the client and facilitator sides, and no
/// single field may spend the whole response-body budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Always `"exact"` for what this crate implements. Bounded by
    /// `MAX_SCHEME_LEN` bytes.
    #[serde(deserialize_with = "deserialize_scheme")]
    pub scheme: String,
    /// CAIP-2 identifier: `"stellar:pubnet"` or `"stellar:testnet"`.
    /// Bounded by `MAX_NETWORK_LEN` bytes.
    #[serde(deserialize_with = "deserialize_network")]
    pub network: String,
    /// Required amount, in the asset's atomic (base) units, as a decimal
    /// string. Bounded by `MAX_AMOUNT_LEN` bytes.
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: String,
    /// The SEP-41 SAC contract address (`C...`). Bounded by
    /// `MAX_STRKEY_LEN` bytes.
    #[serde(deserialize_with = "deserialize_asset")]
    pub asset: String,
    /// The recipient account address (`G...`). Bounded by
    /// `MAX_STRKEY_LEN` bytes.
    #[serde(deserialize_with = "deserialize_pay_to")]
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: StellarExtra,
}

/// The `402 Payment Required` response body, carried base64-encoded in the
/// `PAYMENT-REQUIRED` header.
///
/// # Examples
///
/// ```rust
/// use sorocharge_x402::PaymentRequired;
///
/// let json = r#"
/// {
///   "x402Version": 2,
///   "resource": {
///     "url": "https://example.com/weather",
///     "description": "Access to protected content",
///     "mimeType": "application/json"
///   },
///   "accepts": [
///     {
///       "scheme": "exact",
///       "network": "stellar:testnet",
///       "amount": "10000000",
///       "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
///       "payTo": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO",
///       "maxTimeoutSeconds": 60,
///       "extra": {
///         "areFeesSponsored": true
///       }
///     }
///   ]
/// }
/// "#;
///
/// let payment_required: PaymentRequired = serde_json::from_str(json).unwrap();
/// assert_eq!(payment_required.x402_version, 2);
/// assert_eq!(payment_required.resource.url, "https://example.com/weather");
/// assert_eq!(payment_required.accepts.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    /// Protocol version identifier; always `2` for what this crate speaks.
    pub x402_version: u32,
    /// Human-readable failure detail from the resource server. Bounded by
    /// `MAX_ERROR_MESSAGE_LEN` bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_error_message"
    )]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The Stellar `exact` scheme's `payload` field: a base64-encoded XDR
/// `TransactionEnvelope` with a single `invokeHostFunction` operation and
/// signed authorization entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StellarPayload {
    pub transaction: String,
}

/// The credential a client sends back, carried base64-encoded in the
/// `PAYMENT-SIGNATURE` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: StellarPayload,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The result of on-chain settlement, carried base64-encoded in the
/// `PAYMENT-RESPONSE` header, and returned as the JSON body of a
/// facilitator's `/settle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// The transaction hash, or an empty string if none was broadcast.
    pub transaction: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// The JSON body a facilitator's `/verify` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// The JSON body a resource server sends to a facilitator's `/verify` or
/// `/settle` (identical shape for both, per spec §7.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub x402_version: u32,
    pub payment_payload: PaymentPayload,
    pub payment_requirements: PaymentRequirements,
}

/// `/settle` takes the identical request shape as `/verify`.
pub type SettleRequest = VerifyRequest;

/// One entry in a facilitator's `/supported` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
}

/// The JSON body a facilitator's `/supported` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<String>,
    /// CAIP-2 pattern (e.g. `"stellar:*"`) to the facilitator's signer
    /// addresses.
    pub signers: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `specs/schemes/exact/scheme_exact_stellar.md`'s
    /// `PaymentRequirements` example in `x402-foundation/x402`.
    const PAYMENT_REQUIREMENTS_JSON: &str = r#"
    {
      "scheme": "exact",
      "network": "stellar:testnet",
      "amount": "10000000",
      "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
      "payTo": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO",
      "maxTimeoutSeconds": 60,
      "extra": {
        "areFeesSponsored": true
      }
    }
    "#;

    /// Verbatim from the same spec's "Full `PaymentPayload` object" example.
    const PAYMENT_PAYLOAD_JSON: &str = r#"
    {
      "x402Version": 2,
      "resource": {
        "url": "https://example.com/weather",
        "description": "Access to protected content",
        "mimeType": "application/json"
      },
      "accepted": {
        "scheme": "exact",
        "network": "stellar:testnet",
        "amount": "10000000",
        "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
        "payTo": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO",
        "maxTimeoutSeconds": 60,
        "extra": {
          "areFeesSponsored": true
        }
      },
      "payload": {
        "transaction": "AAAAAgAAAABriIN4poutFUmHfB6FbFJu8GgXoPPTGQWREqFpPfvO1AAAAAAAAAAAAAAAAAAAAA..."
      }
    }
    "#;

    /// Verbatim from the same spec's `SettlementResponse` example.
    const SETTLEMENT_RESPONSE_JSON: &str = r#"
    {
      "success": true,
      "transaction": "a1b2c3d4e5f6...",
      "network": "stellar:testnet",
      "payer": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO"
    }
    "#;

    #[test]
    fn payment_requirements_matches_spec_example_field_for_field() {
        let parsed: PaymentRequirements = serde_json::from_str(PAYMENT_REQUIREMENTS_JSON).unwrap();
        assert_eq!(parsed.scheme, "exact");
        assert_eq!(parsed.network, "stellar:testnet");
        assert_eq!(parsed.amount, "10000000");
        assert_eq!(
            parsed.asset,
            "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"
        );
        assert_eq!(
            parsed.pay_to,
            "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO"
        );
        assert_eq!(parsed.max_timeout_seconds, 60);
        assert!(parsed.extra.are_fees_sponsored);

        // Round-trip: re-serializing must reproduce the spec's exact field names.
        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in [
            "scheme",
            "network",
            "amount",
            "asset",
            "payTo",
            "maxTimeoutSeconds",
            "extra",
        ] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
        assert!(value["extra"].get("areFeesSponsored").is_some());
    }

    #[test]
    fn payment_payload_matches_spec_example_field_for_field() {
        let parsed: PaymentPayload = serde_json::from_str(PAYMENT_PAYLOAD_JSON).unwrap();
        assert_eq!(parsed.x402_version, 2);
        assert_eq!(
            parsed.resource.as_ref().unwrap().url,
            "https://example.com/weather"
        );
        assert_eq!(parsed.accepted.scheme, "exact");
        assert!(parsed.payload.transaction.starts_with("AAAAAgAAAABriIN4"));

        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in ["x402Version", "resource", "accepted", "payload"] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
    }

    #[test]
    fn settlement_response_matches_spec_example_field_for_field() {
        let parsed: SettlementResponse = serde_json::from_str(SETTLEMENT_RESPONSE_JSON).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.transaction, "a1b2c3d4e5f6...");
        assert_eq!(parsed.network, "stellar:testnet");
        assert_eq!(
            parsed.payer.as_deref(),
            Some("GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO")
        );
    }

    /// Wraps `resource` (and an optional `error`) in a minimal but
    /// complete `PaymentRequired` body, reusing the spec's own `accepts[0]`
    /// example so each length test varies exactly one field.
    fn payment_required_json(resource: serde_json::Value, error: Option<String>) -> String {
        let accepts: serde_json::Value = serde_json::from_str(PAYMENT_REQUIREMENTS_JSON)
            .expect("the spec's own example must parse");
        serde_json::json!({
            "x402Version": 2,
            "error": error,
            "resource": resource,
            "accepts": [accepts],
            "extensions": {},
        })
        .to_string()
    }

    /// Deserializes `json` and asserts it fails with exactly the
    /// field-specific length error. The failure itself is the proof that
    /// an over-long field is rejected rather than silently truncated — a
    /// truncating implementation would have decoded successfully.
    fn assert_field_too_long(json: &str, field: &str, max: usize, actual: usize) {
        let err = serde_json::from_str::<PaymentRequired>(json)
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
    fn oversized_description_is_rejected_not_truncated() {
        let json = payment_required_json(
            serde_json::json!({
                "url": "https://example.com/weather",
                "description": "d".repeat(MAX_DESCRIPTION_LEN + 1),
            }),
            None,
        );
        assert_field_too_long(
            &json,
            "description",
            MAX_DESCRIPTION_LEN,
            MAX_DESCRIPTION_LEN + 1,
        );
    }

    #[test]
    fn oversized_url_is_rejected_with_specific_error() {
        let json = payment_required_json(
            serde_json::json!({ "url": "u".repeat(MAX_URL_LEN + 1) }),
            None,
        );
        assert_field_too_long(&json, "url", MAX_URL_LEN, MAX_URL_LEN + 1);
    }

    #[test]
    fn oversized_mime_type_is_rejected_with_specific_error() {
        let json = payment_required_json(
            serde_json::json!({
                "url": "https://example.com/weather",
                "mimeType": "m".repeat(MAX_MIME_TYPE_LEN + 1),
            }),
            None,
        );
        assert_field_too_long(&json, "mimeType", MAX_MIME_TYPE_LEN, MAX_MIME_TYPE_LEN + 1);
    }

    #[test]
    fn oversized_payment_required_error_is_rejected_with_specific_error() {
        let json = payment_required_json(
            serde_json::json!({ "url": "https://example.com/weather" }),
            Some("e".repeat(MAX_ERROR_MESSAGE_LEN + 1)),
        );
        assert_field_too_long(
            &json,
            "error",
            MAX_ERROR_MESSAGE_LEN,
            MAX_ERROR_MESSAGE_LEN + 1,
        );
    }

    #[test]
    fn oversized_payment_requirements_fields_are_rejected_with_specific_error() {
        let base: serde_json::Value = serde_json::from_str(PAYMENT_REQUIREMENTS_JSON)
            .expect("the spec's own example must parse");
        for (field, max) in [
            ("scheme", MAX_SCHEME_LEN),
            ("network", MAX_NETWORK_LEN),
            ("amount", MAX_AMOUNT_LEN),
            ("asset", MAX_STRKEY_LEN),
            ("payTo", MAX_STRKEY_LEN),
        ] {
            let mut accepts = base.clone();
            accepts[field] = "x".repeat(max + 1).into();
            let json = serde_json::json!({
                "x402Version": 2,
                "resource": { "url": "https://example.com/weather" },
                "accepts": [accepts],
                "extensions": {},
            })
            .to_string();
            assert_field_too_long(&json, field, max, max + 1);
        }
    }

    #[test]
    fn fields_exactly_at_their_maximum_length_are_accepted_verbatim() {
        let url = "u".repeat(MAX_URL_LEN);
        let description = "d".repeat(MAX_DESCRIPTION_LEN);
        let mime_type = "m".repeat(MAX_MIME_TYPE_LEN);
        let error = "e".repeat(MAX_ERROR_MESSAGE_LEN);
        let json = payment_required_json(
            serde_json::json!({
                "url": &url,
                "description": &description,
                "mimeType": &mime_type,
            }),
            Some(error.clone()),
        );

        let parsed: PaymentRequired =
            serde_json::from_str(&json).expect("at-limit values must decode");
        assert_eq!(parsed.resource.url, url);
        assert_eq!(
            parsed.resource.description.as_deref(),
            Some(description.as_str())
        );
        assert_eq!(
            parsed.resource.mime_type.as_deref(),
            Some(mime_type.as_str())
        );
        assert_eq!(parsed.error.as_deref(), Some(error.as_str()));

        // `accepts[]` entries at their bounds decode verbatim too.
        let mut accepts: serde_json::Value = serde_json::from_str(PAYMENT_REQUIREMENTS_JSON)
            .expect("the spec's own example must parse");
        accepts["scheme"] = "s".repeat(MAX_SCHEME_LEN).into();
        accepts["network"] = "n".repeat(MAX_NETWORK_LEN).into();
        accepts["amount"] = "1".repeat(MAX_AMOUNT_LEN).into();
        accepts["asset"] = "a".repeat(MAX_STRKEY_LEN).into();
        accepts["payTo"] = "p".repeat(MAX_STRKEY_LEN).into();
        let json = serde_json::json!({
            "x402Version": 2,
            "resource": { "url": "https://example.com/weather" },
            "accepts": [accepts],
            "extensions": {},
        })
        .to_string();
        let parsed: PaymentRequired =
            serde_json::from_str(&json).expect("at-limit values must decode");
        assert_eq!(parsed.accepts[0].scheme, "s".repeat(MAX_SCHEME_LEN));
        assert_eq!(parsed.accepts[0].network, "n".repeat(MAX_NETWORK_LEN));
        assert_eq!(parsed.accepts[0].amount, "1".repeat(MAX_AMOUNT_LEN));
        assert_eq!(parsed.accepts[0].asset, "a".repeat(MAX_STRKEY_LEN));
        assert_eq!(parsed.accepts[0].pay_to, "p".repeat(MAX_STRKEY_LEN));
    }

    #[test]
    fn length_limits_count_utf8_bytes_not_characters() {
        // "é" is two UTF-8 bytes: 1025 of them exceed MAX_DESCRIPTION_LEN in
        // bytes while sitting well within it in characters. The byte count
        // is what protects the byte budget, so the byte count wins.
        let description = "é".repeat(MAX_DESCRIPTION_LEN / 2 + 1); // 1025 chars = 2050 bytes
        let json = payment_required_json(
            serde_json::json!({
                "url": "https://example.com/weather",
                "description": &description,
            }),
            None,
        );
        assert_field_too_long(
            &json,
            "description",
            MAX_DESCRIPTION_LEN,
            MAX_DESCRIPTION_LEN + 2,
        );
    }
}
