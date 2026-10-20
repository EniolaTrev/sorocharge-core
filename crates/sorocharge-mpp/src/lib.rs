//! `sorocharge-mpp`: the client and server sides of MPP's
//! `draft-stellar-charge-00` `"stellar"`/`"charge"` payment method, built
//! on `sorocharge-signer`.
//!
//! MPP session/channel mode — a different signing primitive entirely (a raw
//! ed25519 signature over a `one-way-channel` contract's
//! `prepare_commitment` output, no `SorobanAuthorizationEntry` involved) —
//! is out of scope for this crate.

#![deny(unsafe_code)]

mod client;
mod error;
mod header;
mod network;
mod server;
mod tx;
mod types;

#[cfg(test)]
mod test_util;

pub use client::MppClient;
pub use error::MppError;
pub use server::{MppServer, MppServerConfig};
pub use types::{
    Challenge, ChargeRequest, Credential, MethodDetails, Payload, Receipt, MAX_DESCRIPTION_LEN,
    MAX_REALM_LEN,
};
