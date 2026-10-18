use crate::SorochargeError;

const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Maps a Stellar network passphrase to its CAIP-2 identifier.
///
/// Exists so the x402 and MPP adapters share one mapping instead of each
/// keeping a copy that could drift. Any passphrase other than mainnet's or
/// testnet's fails closed rather than guessing a network.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedNetwork`] for any other passphrase.
pub fn caip2_for_passphrase(network_passphrase: &str) -> Result<&'static str, SorochargeError> {
    match network_passphrase {
        PUBNET_PASSPHRASE => Ok("stellar:pubnet"),
        TESTNET_PASSPHRASE => Ok("stellar:testnet"),
        other => Err(SorochargeError::UnsupportedNetwork {
            network: other.to_string(),
        }),
    }
}
