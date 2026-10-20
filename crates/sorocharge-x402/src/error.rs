use core::fmt;

use sorocharge_signer::SorochargeError;

/// Every failure `sorocharge-x402` can produce, on either the client or the
/// facilitator side. Each variant names one specific, actionable failure —
/// no bare `String` or `anyhow::Error` at this boundary, and no catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X402Error {
    /// The underlying HTTP request itself failed (connection, TLS, timeout).
    HttpRequestFailed { reason: String },
    /// The resource responded with neither `402` (payment required) nor
    /// `200` (already paid / free), which this client does not know how to
    /// continue from.
    UnexpectedStatus { status: u16 },
    /// A `402` response carried no `PAYMENT-REQUIRED` header.
    MissingPaymentRequiredHeader,
    /// The `PAYMENT-REQUIRED` header's value did not base64-decode to valid
    /// `PaymentRequired` JSON.
    InvalidPaymentRequired { reason: String },
    /// None of the server's `accepts[]` entries name the `exact` scheme on
    /// a Stellar network this client supports (`stellar:pubnet` /
    /// `stellar:testnet`, matched against the network passphrase given).
    NoAcceptablePaymentRequirements,
    /// A network identifier this crate does not have a CAIP-2 mapping for.
    UnsupportedNetwork { network: String },
    /// `sorocharge-signer` failed to build or sign the charge entry.
    Signing(SorochargeError),
    /// Building the wrapping `TransactionEnvelope` failed (a value did not
    /// fit its XDR-constrained shape).
    XdrEncodingFailed { reason: String },
    /// The `PAYMENT-SIGNATURE` (or `/verify` / `/settle` request) payload's
    /// JSON did not deserialize into the expected shape.
    InvalidPaymentPayload { reason: String },
    /// The submitted transaction's XDR failed to decode.
    XdrDecodingFailed { reason: String },
    /// The transaction does not authorize a single, bare SEP-41
    /// `transfer(from, to, amount)` call — wrong operation count, wrong
    /// function, wrong argument count/types, or a smuggled sub-invocation.
    UnexpectedTransactionShape { reason: String },
    /// An authorization entry used a credential type the `exact` scheme on
    /// Stellar forbids (`sorobanCredentialsSourceAccount` or
    /// `sorobanCredentialsAddressWithDelegates`).
    ForbiddenCredentialType,
    /// The facilitator's own address appeared where the spec's safety
    /// checks forbid it (transaction source, operation source, `from`
    /// argument, or an authorization entry) — a sign of an attempt to trick
    /// the fee-sponsoring facilitator into an unintended transfer.
    FacilitatorAddressConflict,
    /// A call to Stellar RPC (simulate, send, get-transaction, get-ledger)
    /// failed.
    RpcFailed { reason: String },
    /// The settlement-time simulation-derived fee exceeded the configured
    /// safety ceiling.
    FeeExceedsCeiling {
        fee_stroops: i64,
        ceiling_stroops: i64,
    },
    /// Verification succeeded but on-chain settlement failed.
    SettlementFailed { reason: String },
}

impl fmt::Display for X402Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpRequestFailed { reason } => write!(f, "HTTP request failed: {reason}"),
            Self::UnexpectedStatus { status } => {
                write!(f, "unexpected HTTP status {status} (expected 402 or 200)")
            }
            Self::MissingPaymentRequiredHeader => {
                write!(f, "402 response is missing the PAYMENT-REQUIRED header")
            }
            Self::InvalidPaymentRequired { reason } => {
                write!(f, "invalid PAYMENT-REQUIRED header: {reason}")
            }
            Self::NoAcceptablePaymentRequirements => write!(
                f,
                "no accepts[] entry names the exact scheme on a supported Stellar network"
            ),
            Self::UnsupportedNetwork { network } => {
                write!(f, "unsupported network: {network}")
            }
            Self::Signing(e) => write!(f, "signing failed: {e}"),
            Self::XdrEncodingFailed { reason } => write!(f, "XDR encoding failed: {reason}"),
            Self::InvalidPaymentPayload { reason } => {
                write!(f, "invalid payment payload: {reason}")
            }
            Self::XdrDecodingFailed { reason } => write!(f, "XDR decoding failed: {reason}"),
            Self::UnexpectedTransactionShape { reason } => {
                write!(f, "unexpected transaction shape: {reason}")
            }
            Self::ForbiddenCredentialType => write!(
                f,
                "authorization entry uses a credential type the exact scheme on Stellar forbids"
            ),
            Self::FacilitatorAddressConflict => write!(
                f,
                "facilitator's own address appears where the safety checks forbid it"
            ),
            Self::RpcFailed { reason } => write!(f, "Stellar RPC call failed: {reason}"),
            Self::FeeExceedsCeiling {
                fee_stroops,
                ceiling_stroops,
            } => write!(
                f,
                "settlement fee {fee_stroops} stroops exceeds ceiling {ceiling_stroops} stroops"
            ),
            Self::SettlementFailed { reason } => write!(f, "settlement failed: {reason}"),
        }
    }
}

impl std::error::Error for X402Error {}

impl From<SorochargeError> for X402Error {
    fn from(e: SorochargeError) -> Self {
        Self::Signing(e)
    }
}
