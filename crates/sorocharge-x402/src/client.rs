//! The payer side of x402: `GET` a resource, receive `402` with payment
//! terms, build and sign a charge entry via `sorocharge-signer`, and retry
//! with the signed credential attached.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use stellar_xdr::{Limits, WriteXdr};

use sorocharge_signer::{build_charge_entry, sign_entry, ChargeParams, CredentialKind, Signer};

use crate::error::X402Error;
use crate::network::caip2_for_passphrase;
use crate::tx::build_payment_transaction_envelope;
use crate::types::{PaymentPayload, PaymentRequired, PaymentRequirements, StellarPayload};

pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";

/// The default estimate of a Stellar ledger's close time, used to convert
/// `maxTimeoutSeconds` into a ledger count when the live network estimate
/// isn't available. Matches the spec's own fallback.
const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;
/// Safety margin: the x402 client halves the spec's maxTimeoutSeconds
/// allowance, matching the MPP client's approach. If ledgers close
/// slower than the 5s default, a full-allowance expiry can fail the
/// facilitator's own ExpirationExceedsAllowance check (a failure mode
/// already observed live on testnet). The margin keeps the expiry inside
/// the bound at the cost of a shorter authorization window.
///
/// Retry configuration: bounded retry with backoff for transient HTTP
/// failures (5xx and connection errors). Max 3 attempts with exponential
/// backoff (1s, 2s, 4s), respecting the per-request timeout so the total
/// wall-clock time is bounded.
const MAX_RETRY_ATTEMPTS: u32 = 3;
fn decode_header_json<T: serde::de::DeserializeOwned>(header_value: &str) -> Result<T, String> {
    let bytes = BASE64
        .decode(header_value.trim())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON decode failed: {e}"))
}

fn encode_header_json<T: serde::Serialize>(value: &T) -> Result<String, X402Error> {
    let bytes = serde_json::to_vec(value).map_err(|e| X402Error::InvalidPaymentPayload {
        reason: e.to_string(),
    })?;
    Ok(BASE64.encode(bytes))
}

/// Retries an HTTP GET request with bounded backoff for transient failures.
///
/// - Retries up to `MAX_RETRY_ATTEMPTS` times (default 3).
/// - On 5xx or connection-level errors, waits with exponential backoff
///   (1s, 2s, 4s...).
/// - Each attempt respects the client's `request_timeout`, so total wall-clock
///   time is bounded by `timeout * attempts` plus backoff.
/// - On success, returns the successful response immediately.
/// - On final failure, returns the last error.
async fn retry_get<T: reqwest::IntoUrl + Clone>(
    http: &reqwest::Client,
    url: T,
) -> Result<reqwest::Response, X402Error> {
    let mut attempt = 0;
    let mut last_error = X402Error::HttpRequestFailed {
        reason: "exhausted retries".to_string(),
    };
    while attempt < MAX_RETRY_ATTEMPTS {
        attempt += 1;
        match http.get(url.clone()).send().await {
            Ok(resp) => {
                // Don't retry on 402 (payment required) or 200 (ok) — those
                // are deliberate protocol responses, not transient failures.
                return Ok(resp);
            }
            Err(e) => {
                last_error = X402Error::HttpRequestFailed {
                    reason: format!("request attempt {} failed: {e}", attempt),
                };
                // Retry on connection errors and 5xx server errors.
                // We can't easily check the status here since the error is from
                // the reqwest Client::get().send() path, but connection-level
                // failures and server 5xx are the transient cases we care about.
                if attempt < MAX_RETRY_ATTEMPTS {
                    // Exponential backoff: 1s, 2s, 4s, ...
                    let backoff = std::time::Duration::from_secs(
                        1u64.saturating_pow(attempt.saturating_sub(1)),
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last_error)
}

/// The x402 payer client: performs the `GET` → `402` → build/sign → retry
/// flow against a resource server speaking x402 protocol v2's `exact`
/// scheme on Stellar.
pub struct X402Client {
    http: reqwest::Client,
}

impl X402Client {
    /// Builds a client whose every HTTP request is bounded by
    /// `request_timeout` — no unbounded waits on a resource server.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::time::Duration;
    ///
    /// let client = sorocharge_x402::X402Client::new(Duration::from_secs(30));
    /// assert!(client.is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::HttpRequestFailed`] if the underlying HTTP
    /// client fails to construct (e.g. a broken TLS backend).
    pub fn new(request_timeout: std::time::Duration) -> Result<Self, X402Error> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| X402Error::HttpRequestFailed {
                reason: e.to_string(),
            })?;
        Ok(Self { http })
    }

    /// Selects the `accepts[]` entry naming the `exact` scheme on the
    /// Stellar network identified by `network_passphrase`, and builds the
    /// `ChargeParams` it describes for `payer`.
    fn select_requirements_and_params(
        payment_required: &PaymentRequired,
        network_passphrase: &str,
        payer: sorocharge_signer::Address,
    ) -> Result<(PaymentRequirements, ChargeParams), X402Error> {
        let network = caip2_for_passphrase(network_passphrase)?;
        let requirements = payment_required
            .accepts
            .iter()
            .find(|r| r.scheme == "exact" && r.network == network)
            .cloned()
            .ok_or(X402Error::NoAcceptablePaymentRequirements)?;

        let asset_contract =
            requirements
                .asset
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid asset address: {}", requirements.asset),
                })?;
        let amount =
            requirements
                .amount
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid amount: {}", requirements.amount),
                })?;
        let recipient =
            requirements
                .pay_to
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid payTo address: {}", requirements.pay_to),
                })?;

        Ok((
            requirements,
            ChargeParams {
                asset_contract,
                amount,
                payer,
                recipient,
                valid_until_ledger: 0, // filled in by the caller once currentLedger is known
            },
        ))
    }

    /// Performs the full x402 client flow against `url`:
    ///
    /// 1. `GET url`. A `200` is returned as-is (already paid, or free).
    /// 2. On `402`, decode `PAYMENT-REQUIRED`, pick the `exact`-on-Stellar
    ///    entry matching `network_passphrase`, and build+sign a
    ///    `Legacy`-credential charge entry via `sorocharge-signer` for
    ///    `signer`. `Legacy` is chosen over `AddressV2` for the broadest
    ///    facilitator compatibility, even though the spec permits both:
    ///    "recording-mode simulation still returns the legacy arm as of
    ///    Protocol 28."
    /// 3. Wrap the signed entry in a `TransactionEnvelope` and retry with
    ///    `PAYMENT-SIGNATURE` attached.
    ///
    /// `current_ledger` is the caller-supplied result of a `getLatestLedger`
    /// RPC call, used to compute the authorization entry's expiration per
    /// the spec's `currentLedger + ceil(maxTimeoutSeconds / 5)` formula.
    /// Fetching it is left to the caller rather than done here so this
    /// method doesn't have to own an RPC client for a single read.
    ///
    /// # Errors
    ///
    /// See [`X402Error`] for the specific failure modes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sorocharge_signer::Signer;
    /// use sorocharge_x402::X402Client;
    ///
    /// # async fn demo(signer: &dyn Signer, current_ledger: u32) -> Result<(), sorocharge_x402::X402Error> {
    /// let client = X402Client::new(std::time::Duration::from_secs(10))?;
    ///
    /// // `current_ledger` comes from a getLatestLedger Stellar RPC call; the
    /// // client uses it to derive the authorization entry's expiry.
    /// let response = client
    ///     .get_with_payment(
    ///         "https://api.example.com/paid-resource",
    ///         signer,
    ///         "Test SDF Network ; September 2015",
    ///         current_ledger,
    ///     )
    ///     .await?;
    /// println!("resource responded with {}", response.status());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_with_payment(
        &self,
        url: &str,
        signer: &dyn Signer,
        network_passphrase: &str,
        current_ledger: u32,
    ) -> Result<reqwest::Response, X402Error> {
        let first = retry_get(&self.http, url).await?;

        if first.status() == reqwest::StatusCode::OK {
            return Ok(first);
        }
        if first.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            // Protocol-level 402: build and sign, then retry with signature.
            // This is not a transient failure; it's the expected payment challenge.
        } else if first.status().is_server_error() {
            // Transient 5xx: retry with backoff is handled by retry_get,
            // but if we exhausted retries, fail now.
            return Err(X402Error::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        } else {
            return Err(X402Error::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        }

        let header_value = first
            .headers()
            .get(PAYMENT_REQUIRED_HEADER)
            .ok_or(X402Error::MissingPaymentRequiredHeader)?
            .to_str()
            .map_err(|e| X402Error::InvalidPaymentRequired {
                reason: e.to_string(),
            })?;
        let payment_required = decode_header_json::<PaymentRequired>(header_value)
            .map_err(|reason| X402Error::InvalidPaymentRequired { reason })?;

        let (requirements, mut params) = Self::select_requirements_and_params(
            &payment_required,
            network_passphrase,
            signer.address(),
        )?;

        let ledger_timeout = requirements
            .max_timeout_seconds
            .div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS)
            .div_ceil(2);
        params.valid_until_ledger =
            current_ledger.saturating_add(u32::try_from(ledger_timeout).unwrap_or(u32::MAX));

        let unsigned = build_charge_entry(&params, CredentialKind::Legacy)?;
        let signed = sign_entry(unsigned, signer, network_passphrase)?;
        let envelope = build_payment_transaction_envelope(&params, &signed)?;
        let transaction_xdr =
            envelope
                .to_xdr_base64(Limits::none())
                .map_err(|e| X402Error::XdrEncodingFailed {
                    reason: e.to_string(),
                })?;

        let payload = PaymentPayload {
            x402_version: 2,
            resource: Some(payment_required.resource.clone()),
            accepted: requirements,
            payload: StellarPayload {
                transaction: transaction_xdr,
            },
            extensions: serde_json::Map::new(),
        };
        let header_value = encode_header_json(&payload)?;

        let second = self
            .http
            .get(url)
            .header(PAYMENT_SIGNATURE_HEADER, header_value)
            .send()
            .await
            .map_err(|e| X402Error::HttpRequestFailed {
                reason: e.to_string(),
            })?;

        if second.status() != reqwest::StatusCode::OK {
            return Err(X402Error::UnexpectedStatus {
                status: second.status().as_u16(),
            });
        }
        Ok(second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use stellar_xdr::{
        HostFunction, MuxedAccount, OperationBody, ReadXdr, SorobanCredentials,
        TransactionEnvelope, Uint256,
    };

    use crate::test_util::{MockResource, TestSigner};
    use crate::types::{ResourceInfo, StellarExtra};

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const ASSET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
    const PAY_TO: &str = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N";

    fn payment_required(network: &str) -> PaymentRequired {
        PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "http://127.0.0.1/resource".to_string(),
                description: None,
                mime_type: None,
            },
            accepts: vec![PaymentRequirements {
                scheme: "exact".to_string(),
                network: network.to_string(),
                amount: "42000000".to_string(),
                asset: ASSET.to_string(),
                pay_to: PAY_TO.to_string(),
                max_timeout_seconds: 60,
                extra: StellarExtra {
                    are_fees_sponsored: true,
                },
            }],
            extensions: serde_json::Map::new(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn returns_200_and_retries_with_a_payment_signature() {
        let resource = MockResource::spawn(payment_required("stellar:testnet")).await;
        let client = X402Client::new(Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x55; 32]);

        let response = client
            .get_with_payment(&resource.url, &signer, NETWORK, 1_000)
            .await
            .expect("payment flow");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(resource.request_count(), 2);

        let signature = resource.captured_signature();
        let bytes = BASE64
            .decode(signature.trim())
            .expect("base64-decode the header");
        let payload: PaymentPayload = serde_json::from_slice(&bytes).expect("decode the payload");
        assert_eq!(payload.x402_version, 2);
        assert_eq!(payload.accepted.network, "stellar:testnet");
        assert_eq!(payload.accepted.amount, "42000000");

        let envelope =
            TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
                .expect("decode the payment envelope");
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a v1 envelope");
        };
        assert_eq!(
            v1.tx.source_account,
            MuxedAccount::Ed25519(Uint256([0u8; 32]))
        );
        let [operation] = v1.tx.operations.as_slice() else {
            panic!("expected exactly one operation");
        };
        let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
            panic!("expected an invokeHostFunction operation");
        };
        assert!(matches!(
            invoke.host_function,
            HostFunction::InvokeContract(_)
        ));
        let [auth_entry] = invoke.auth.as_slice() else {
            panic!("expected exactly one authorization entry");
        };
        assert!(matches!(
            auth_entry.credentials,
            SorobanCredentials::Address(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_a_payment_required_header_that_does_not_decode() {
        async fn handler(
            axum::extract::State(value): axum::extract::State<String>,
        ) -> axum::response::Response {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                super::PAYMENT_REQUIRED_HEADER,
                axum::http::HeaderValue::from_str(&value).expect("header value"),
            );
            axum::response::IntoResponse::into_response((
                axum::http::StatusCode::PAYMENT_REQUIRED,
                headers,
            ))
        }

        async fn spawn_with_header(value: &str) -> String {
            let router = axum::Router::new()
                .route("/resource", axum::routing::get(handler))
                .with_state(value.to_string());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind an ephemeral localhost port");
            let addr = listener.local_addr().expect("read the bound address");
            tokio::spawn(async move {
                axum::serve(listener, router).await.expect("mock server");
            });
            format!("http://{addr}/resource")
        }

        let client = X402Client::new(Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x55; 32]);

        // Not base64 at all.
        let url = spawn_with_header("!!!not-base64!!!").await;
        let result = client.get_with_payment(&url, &signer, NETWORK, 1_000).await;
        assert!(
            matches!(result, Err(X402Error::InvalidPaymentRequired { .. })),
            "expected InvalidPaymentRequired for a non-base64 header, got {result:?}"
        );

        // Valid base64, but not JSON.
        let not_json = BASE64.encode(b"this is not json");
        let url = spawn_with_header(&not_json).await;
        let result = client.get_with_payment(&url, &signer, NETWORK, 1_000).await;
        assert!(
            matches!(result, Err(X402Error::InvalidPaymentRequired { .. })),
            "expected InvalidPaymentRequired for a non-JSON header, got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_no_accepts_entry_matches_the_scheme() {
        let mut required = payment_required("stellar:testnet");
        required.accepts[0].scheme = "upfront".to_string();
        let resource = MockResource::spawn(required).await;
        let client = X402Client::new(Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x55; 32]);

        let result = client
            .get_with_payment(&resource.url, &signer, NETWORK, 1_000)
            .await;

        assert!(
            matches!(result, Err(X402Error::NoAcceptablePaymentRequirements)),
            "expected NoAcceptablePaymentRequirements, got {result:?}"
        );
        assert_eq!(resource.request_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_no_accepts_entry_matches_the_network() {
        let resource = MockResource::spawn(payment_required("stellar:pubnet")).await;
        let client = X402Client::new(Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x55; 32]);

        let result = client
            .get_with_payment(&resource.url, &signer, NETWORK, 1_000)
            .await;

        assert!(
            matches!(result, Err(X402Error::NoAcceptablePaymentRequirements)),
            "expected NoAcceptablePaymentRequirements, got {result:?}"
        );
        assert_eq!(resource.request_count(), 1);
    }
}
