use crate::MppError;
use sorocharge_signer::SorochargeError;

/// The CAIP-2 identifier for a network passphrase.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedNetwork`] for any passphrase other than
/// mainnet's or testnet's.
pub fn caip2_for_passphrase(network_passphrase: &str) -> Result<&'static str, MppError> {
    sorocharge_signer::caip2_for_passphrase(network_passphrase).map_err(|e| match e {
        SorochargeError::UnsupportedNetwork { network } => MppError::UnsupportedNetwork { network },
        other => MppError::Signing(other),
    })
}
