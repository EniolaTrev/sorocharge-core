use crate::X402Error;
use sorocharge_signer::SorochargeError;

/// The CAIP-2 identifier for a network passphrase.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedNetwork`] for any passphrase other than
/// mainnet's or testnet's.
pub fn caip2_for_passphrase(network_passphrase: &str) -> Result<&'static str, X402Error> {
    sorocharge_signer::caip2_for_passphrase(network_passphrase).map_err(|e| match e {
        SorochargeError::UnsupportedNetwork { network } => {
            X402Error::UnsupportedNetwork { network }
        }
        other => X402Error::Signing(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passphrase with no CAIP-2 mapping must surface as exactly
    /// `UnsupportedNetwork`, carrying the offending identifier back so a
    /// caller can tell it apart from every other `X402Error` variant.
    #[test]
    fn rejects_a_passphrase_with_no_caip2_mapping() {
        let unknown = "Future SDF Network ; September 2035";

        match caip2_for_passphrase(unknown) {
            Err(X402Error::UnsupportedNetwork { network }) => {
                assert_eq!(network, unknown);
            }
            other => panic!("expected UnsupportedNetwork, got {other:?}"),
        }
    }
}
