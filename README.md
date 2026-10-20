# sorocharge-core

[![CI](https://github.com/sorocharge/sorocharge-core/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sorocharge/sorocharge-core/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Rust crates for building, signing, and verifying Soroban authorization
entries that pay for things — one signing engine, two HTTP payment
protocols on top of it: **[x402](https://github.com/x402-foundation/x402)**
and **[MPP](https://paymentauth.org/)**'s `draft-stellar-charge-00`.

📖 **[Full documentation](https://sorocharge.github.io/sorocharge-core/)** — architecture,
protocol mechanics, integration guides, and the complete API reference.

```
sorocharge-signer   the shared engine: build/sign/verify a SEP-41 transfer
                     authorization entry, for every CAP-71 credential shape
sorocharge-x402      x402 protocol v2, "exact" scheme, on Stellar
sorocharge-mpp       MPP's "stellar" payment method, "charge" intent
```

`sorocharge-x402` and `sorocharge-mpp` depend on `sorocharge-signer`;
`sorocharge-signer` depends on neither of them, and knows nothing about
either protocol's wire format.

## What's implemented

- **`sorocharge-signer`**: building, signing, and verifying a
  `SorobanAuthorizationEntry` for a single SEP-41 `transfer(from, to,
  amount)`, across all three CAP-71 credential shapes — legacy
  `SorobanAddressCredentials`, CAP-71 V2 (`AddressV2`), and delegated
  signers (`AddressWithDelegates`). Every function that produces XDR is
  diffed byte-for-byte in CI against fixtures generated from the pinned
  `@stellar/stellar-sdk` (see [`tests/golden_vectors/`](tests/golden_vectors)) —
  this is the proof that what this crate builds is the same bytes the
  reference SDK would produce for the same inputs.
- **`sorocharge-x402`**: the payer client (`GET` → `402` → build+sign →
  retry) and the facilitator side (`verify`/`settle`/`supported`, as plain
  functions — not a bundled HTTP server) for x402 protocol v2's `exact`
  scheme on Stellar.
- **`sorocharge-mpp`**: the payer client and the server side (challenge
  issuance, verification, settlement) for MPP's `draft-stellar-charge-00`
  `"stellar"` payment method, `"charge"` intent — both pull mode (sponsored
  and unsponsored) and push mode.

## What's deliberately not implemented

**MPP session/channel mode is not implemented, and isn't planned for this
repository.** It's a different signing primitive entirely — a raw ed25519
signature over a `one-way-channel` Soroban contract's `prepare_commitment`
output, not a `SorobanAuthorizationEntry` at all — and its formal spec was
still being drafted at the time this project's brief was written. Only
MPP's charge-intent mode (`draft-stellar-charge-00`) is covered here.

Also out of scope, by design: key management (callers supply a `Signer`
they already control), a general-purpose Soroban contract client, and a
CLI (the `examples/` binaries are dev-dependency-gated demos, not a shipped
product).

## Install

Not yet published to crates.io — depend on the tagged commit directly:

```toml
[dependencies]
sorocharge-signer = { git = "https://github.com/sorocharge/sorocharge-core", tag = "v0.1.0" }
sorocharge-x402   = { git = "https://github.com/sorocharge/sorocharge-core", tag = "v0.1.0" }   # if you're doing x402
sorocharge-mpp    = { git = "https://github.com/sorocharge/sorocharge-core", tag = "v0.1.0" }   # if you're doing MPP
```

## Quickstart: x402

Pay for an x402-protected resource:

```rust
use std::time::Duration;
use sorocharge_x402::X402Client;

let client = X402Client::new(Duration::from_secs(30))?;
let current_ledger = rpc.get_latest_ledger().await?.sequence;

let response = client
    .get_with_payment(
        "https://api.example.com/premium-data",
        &my_signer,                                  // impl sorocharge_signer::Signer
        "Test SDF Network ; September 2015",
        current_ledger,
    )
    .await?;
```

Run a facilitator's `/verify` and `/settle` behind your own HTTP framework:

```rust
use sorocharge_x402::{Facilitator, FacilitatorConfig};

let facilitator = Facilitator::new(
    &rpc,                                             // &stellar_rpc_client::Client
    &facilitator_signer,                              // the fee-sponsoring key
    "Test SDF Network ; September 2015".to_string(),
    FacilitatorConfig::default(),
);

let verify_response = facilitator.verify(&verify_request).await?;
if verify_response.is_valid {
    let settlement = facilitator.settle(&settle_request).await?;
}
```

See [`crates/sorocharge-x402/examples/`](crates/sorocharge-x402/examples)
for complete, runnable versions of both.

## Quickstart: MPP

Pay for an MPP `"stellar"`/`"charge"`-protected resource:

```rust
use std::time::Duration;
use sorocharge_mpp::MppClient;

let client = MppClient::new(&rpc, Duration::from_secs(30))?;

let response = client
    .get_with_payment(
        "https://api.example.com/agent-endpoint",
        &my_signer,                                  // impl sorocharge_signer::Signer
        "Test SDF Network ; September 2015",
    )
    .await?;
```

Issue a challenge and settle a received credential:

```rust
use sorocharge_mpp::{MppServer, MppServerConfig};

let server = MppServer::new(
    &rpc,
    &server_signer,                                   // the fee-sponsoring key, for sponsored charges
    "Test SDF Network ; September 2015".to_string(),
    MppServerConfig::default(),
);

let header = server.build_challenge_header(&id, &realm, &charge_request, expires)?;
// ... send `WWW-Authenticate: {header}` in your 402 response ...

let receipt = server
    .settle_credential(&credential, &charge_request, chrono::Utc::now(), already_consumed)
    .await?;
```

`MppServer` doesn't own challenge storage, HMAC challenge-binding, or a
replay-protection set — `draft-stellar-charge-00` itself scopes to the
Stellar-specific request/payload/verification, leaving generic challenge
tracking to whatever the base `draft-httpauth-payment-01` layer your
application already runs. See
[`crates/sorocharge-mpp/examples/`](crates/sorocharge-mpp/examples).

## Money and security defaults worth knowing

- Amounts are always `i128` base units — never a float, anywhere.
- Expiry is always a ledger number (`valid_until_ledger: u32`), never
  wall-clock time, matching how Soroban authorization expiry actually
  works on-chain.
- `sorocharge-x402`'s client defaults to the legacy (non-V2) credential
  type for the broadest facilitator compatibility, even though the spec
  permits `AddressV2` too. `sorocharge-mpp` always uses the legacy
  credential type — `draft-stellar-charge-00` permits nothing else.
- Neither protocol crate ever emits a delegated-signer
  (`AddressWithDelegates`) credential: x402's `exact` scheme on Stellar
  explicitly forbids it, and MPP's spec doesn't mention it at all.
- `sign_entry` and `verify_entry` both take an explicit
  `network_passphrase`: the signature payload is network-bound
  (`sha256(network_passphrase)` is baked into what gets signed), so there
  is no default network and no way to accidentally sign for the wrong one.

## Development

```sh
cargo test --workspace                 # unit + golden-vector tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Golden vectors are generated by a pinned `@stellar/stellar-sdk` version
(dev-only Node tooling, never a runtime dependency of the Rust crates):

```sh
cd tests/golden_vectors
npm ci
node generate.mjs
git diff --exit-code fixtures   # fixtures should already be committed and unchanged
```

## Fuzzing

Each crate has a [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
harness under its `fuzz/` directory, covering the exact boundaries where
untrusted network data meets this library:

| Crate | Target | Boundary |
|---|---|---|
| `sorocharge-signer` | `verify_entry` | `SorobanAuthorizationEntry` decode → `SignedEntry::from_xdr` → `verify_entry` |
| `sorocharge-x402` | `parse_payment_transaction` | `TransactionEnvelope` decode → x402's payment parser |
| `sorocharge-mpp` | `parse_payment_transaction` | `TransactionEnvelope` decode → MPP's payment parser |

Each target asserts only that arbitrary bytes never panic — malformed input
must return a typed error, never crash the embedding process. Corpora are
seeded from the golden-vector fixtures (signer) and real signed envelopes
produced by the test suites (x402, MPP).

`cargo-fuzz` requires **nightly** Rust. That requirement is scoped to the
`fuzz/` directories (`fuzz/rust-toolchain.toml`) and does not affect the
library's stable toolchain pin. Because rustup resolves its toolchain from the
current directory, run `cargo fuzz` from inside the `fuzz/` directory so that
file is honored:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd crates/sorocharge-signer/fuzz   # or sorocharge-x402/fuzz / sorocharge-mpp/fuzz
cargo fuzz run verify_entry        # or parse_payment_transaction
```

A bounded run is wired into CI as a nightly job (not on every PR). See each
crate's `fuzz/README.md` for how to extend its corpus.

## License

Apache-2.0
