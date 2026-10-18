//! Test-only doubles for `X402Client`'s orchestration tests: a mock x402
//! resource server (402 with `PAYMENT-REQUIRED`, then 200 on the signed
//! retry) and a deterministic signer.
//!
//! The client is a `reqwest::Client` with no trait seam, so the resource
//! server is stood in for at the HTTP boundary rather than behind a trait —
//! the real transport and header shapes are exercised without changing any
//! public signature.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde_json::{json, Value};
use sorocharge_signer::{Address, Signer, SorochargeError};
use stellar_xdr::{
    AccountEntry, AccountId, ContractEvent, ContractEventBody, ContractEventType, ContractEventV0,
    ContractId, DiagnosticEvent, ExtensionPoint, Int128Parts, LedgerEntryData, Limits, PublicKey,
    ScAddress, ScSymbol, ScVal, SequenceNumber, SorobanTransactionData, Uint256, VecM, WriteXdr,
};

use crate::client::{PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER};
use crate::types::PaymentRequired;

/// A deterministic ed25519 signer whose reported address is derived from its
/// own key.
pub(crate) struct TestSigner {
    signing_key: SigningKey,
    address: Address,
}

impl TestSigner {
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            public_key,
        ))));
        Self {
            signing_key,
            address,
        }
    }
}

impl Signer for TestSigner {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
        Ok(self.signing_key.sign(preimage).to_bytes())
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}

/// A mock x402 resource server: `402` with a `PAYMENT-REQUIRED` header when
/// no `PAYMENT-SIGNATURE` is present, `200` (capturing the header) when it
/// is.
pub(crate) struct MockResource {
    pub(crate) url: String,
    pub(crate) state: Arc<MockResourceState>,
}

pub(crate) struct MockResourceState {
    payment_required: PaymentRequired,
    captured: Mutex<Option<String>>,
    requests: Mutex<u32>,
}

impl MockResource {
    pub(crate) async fn spawn(payment_required: PaymentRequired) -> Self {
        let state = Arc::new(MockResourceState {
            payment_required,
            captured: Mutex::new(None),
            requests: Mutex::new(0),
        });
        let router = Router::new()
            .route("/resource", get(handle_resource))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral localhost port");
        let addr = listener.local_addr().expect("read the bound address");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock server");
        });
        Self {
            url: format!("http://{addr}/resource"),
            state,
        }
    }

    /// The `PAYMENT-SIGNATURE` header value the client sent on its retry.
    pub(crate) fn captured_signature(&self) -> String {
        self.state
            .captured
            .lock()
            .expect("captured lock")
            .clone()
            .expect("the client should have sent a PAYMENT-SIGNATURE header")
    }

    /// How many requests the resource received (1 = only the challenge).
    pub(crate) fn request_count(&self) -> u32 {
        *self.state.requests.lock().expect("requests lock")
    }
}

async fn handle_resource(
    State(state): State<Arc<MockResourceState>>,
    headers: HeaderMap,
) -> Response {
    *state.requests.lock().expect("requests lock") += 1;

    if let Some(signature) = headers.get(PAYMENT_SIGNATURE_HEADER) {
        *state.captured.lock().expect("captured lock") =
            Some(signature.to_str().expect("header is ASCII").to_string());
        return (StatusCode::OK, "paid resource body\n").into_response();
    }

    let encoded = BASE64
        .encode(serde_json::to_vec(&state.payment_required).expect("serialize PaymentRequired"));
    let mut out = HeaderMap::new();
    out.insert(
        PAYMENT_REQUIRED_HEADER,
        HeaderValue::from_str(&encoded).expect("base64 is a valid header value"),
    );
    (StatusCode::PAYMENT_REQUIRED, out).into_response()
}

/// A valid 64-hex transaction hash the mock RPC echoes back for
/// `sendTransaction` / `getTransaction`.
const MOCK_TX_HASH: &str = "abababababababababababababababababababababababababababababababab";

/// A mock Stellar RPC JSON-RPC endpoint for the facilitator's tests.
///
/// `Facilitator` holds a concrete `stellar_rpc_client::Client`, so the only
/// seam without changing its public signature is the HTTP endpoint the client
/// talks to: this serves the handful of methods `validate`/`settle` call and
/// records what was submitted, exercising the real transport and JSON shapes.
pub(crate) struct MockRpc {
    pub(crate) url: String,
    pub(crate) state: Arc<MockRpcState>,
}

pub(crate) struct MockRpcState {
    latest_ledger: u32,
    account_seq_num: i64,
    min_resource_fee: u64,
    events: Vec<String>,
    methods: Mutex<Vec<String>>,
    submitted: Mutex<Vec<String>>,
    failing_method: Mutex<Option<String>>,
}

impl MockRpc {
    /// `min_resource_fee` is what every `simulateTransaction` reports;
    /// `events` is returned verbatim as the simulation's diagnostic events
    /// (the facilitator checks them with `verify_transfer_effects`).
    pub(crate) async fn spawn(
        latest_ledger: u32,
        account_seq_num: i64,
        min_resource_fee: u64,
        events: Vec<String>,
    ) -> Self {
        let state = Arc::new(MockRpcState {
            latest_ledger,
            account_seq_num,
            min_resource_fee,
            events,
            methods: Mutex::new(Vec::new()),
            submitted: Mutex::new(Vec::new()),
            failing_method: Mutex::new(None),
        });
        let router = Router::new()
            .route("/", post(handle_rpc))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral localhost port");
        let addr = listener.local_addr().expect("read the bound address");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock rpc server");
        });
        Self {
            url: format!("http://{addr}/"),
            state,
        }
    }

    /// The JSON-RPC methods the facilitator called, in order.
    /// Makes every later call to `method` answer with a JSON-RPC error
    /// instead of its normal result, so tests can exercise RPC failure paths.
    pub(crate) fn fail_method(&self, method: &str) {
        *self.state.failing_method.lock().expect("failing lock") = Some(method.to_string());
    }

    pub(crate) fn methods(&self) -> Vec<String> {
        self.state.methods.lock().expect("methods lock").clone()
    }

    /// The base64 `TransactionEnvelope`s handed to `sendTransaction`, in
    /// order — i.e. exactly what the facilitator broadcast.
    pub(crate) fn submitted_transactions(&self) -> Vec<String> {
        self.state.submitted.lock().expect("submitted lock").clone()
    }
}

async fn handle_rpc(
    State(state): State<Arc<MockRpcState>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    state
        .methods
        .lock()
        .expect("methods lock")
        .push(method.clone());

    let failing = state
        .failing_method
        .lock()
        .expect("failing lock")
        .as_deref()
        == Some(method.as_str());
    if failing {
        return Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": format!("mock RPC forced {method} failure") }
        }));
    }
    let result = match method.as_str() {
        "getLatestLedger" => json!({
            "id": "mock-ledger",
            "protocolVersion": 28,
            "sequence": state.latest_ledger,
        }),
        "getLedgerEntries" => {
            let account = AccountEntry {
                seq_num: SequenceNumber(state.account_seq_num),
                ..Default::default()
            };
            let xdr = LedgerEntryData::Account(account)
                .to_xdr_base64(Limits::none())
                .expect("encode a ledger entry");
            json!({
                "entries": [{
                    "key": "",
                    "xdr": xdr,
                    "lastModifiedLedgerSeq": state.latest_ledger,
                }],
                "latestLedger": i64::from(state.latest_ledger),
            })
        }
        "simulateTransaction" => {
            let transaction_data = SorobanTransactionData::default()
                .to_xdr_base64(Limits::none())
                .expect("encode transaction data");
            json!({
                "minResourceFee": state.min_resource_fee.to_string(),
                "transactionData": transaction_data,
                "events": state.events,
                "latestLedger": state.latest_ledger,
            })
        }
        "sendTransaction" => {
            if let Some(tx) = request
                .get("params")
                .and_then(|params| params.get("transaction"))
                .and_then(Value::as_str)
            {
                state
                    .submitted
                    .lock()
                    .expect("submitted lock")
                    .push(tx.to_string());
            }
            json!({
                "hash": MOCK_TX_HASH,
                "status": "SUCCESS",
                "latestLedger": state.latest_ledger,
                "latestLedgerCloseTime": "0",
            })
        }
        "getTransaction" => json!({
            "status": "SUCCESS",
            "txHash": MOCK_TX_HASH,
            "latestLedger": state.latest_ledger,
        }),
        other => json!({
            "error": { "code": -32601, "message": format!("mock RPC has no method {other}") }
        }),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// Encodes a `DiagnosticEvent` for a SEP-41 `transfer` of `amount` from
/// `from` to `to` on `asset_contract`, in exactly the shape the live Stellar
/// host emits and `verify_transfer_effects` accepts. Used to make the mock
/// RPC's simulation report the balance change the facilitator expects.
pub(crate) fn transfer_event_xdr(
    asset_contract: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> String {
    let ScAddress::Contract(ContractId(asset_hash)) = asset_contract else {
        panic!("asset_contract must be a contract address");
    };
    let topics: VecM<ScVal> = vec![
        ScVal::Symbol(ScSymbol(
            "transfer".try_into().expect("\"transfer\" fits ScSymbol"),
        )),
        ScVal::Address(from.clone()),
        ScVal::Address(to.clone()),
    ]
    .try_into()
    .expect("three transfer topics fit VecM");
    let event = DiagnosticEvent {
        in_successful_contract_call: true,
        event: ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(asset_hash.clone())),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics,
                data: ScVal::I128(Int128Parts {
                    hi: (amount >> 64) as i64,
                    lo: (amount & (u64::MAX as i128)) as u64,
                }),
            }),
        },
    };
    event
        .to_xdr_base64(Limits::none())
        .expect("encode a diagnostic event")
}
