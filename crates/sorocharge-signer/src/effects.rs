use stellar_xdr::{
    ContractEventBody, ContractEventType, ContractId, DiagnosticEvent, Limits, ReadXdr, ScAddress,
    ScVal,
};

use crate::entry::Address;
use crate::error::SorochargeError;

/// Event names that move a balance. A SEP-41 transfer is the only one a
/// payment is allowed to produce; the rest are reported as unexpected.
const BALANCE_EVENT_NAMES: [&str; 4] = ["transfer", "mint", "burn", "clawback"];

fn symbol_name(value: &ScVal) -> Option<String> {
    match value {
        ScVal::Symbol(sym) => Some(sym.0.to_utf8_string_lossy()),
        _ => None,
    }
}

fn i128_from_scval(value: &ScVal) -> Option<i128> {
    match value {
        ScVal::I128(parts) => Some((i128::from(parts.hi) << 64) | i128::from(parts.lo)),
        _ => None,
    }
}

/// Checks that a simulation's events describe exactly one balance change:
/// the expected SEP-41 transfer of `amount` from `payer` to `recipient` on
/// `asset_contract`.
///
/// Any other balance-moving event fails the check — a transfer to a different
/// party, a second transfer, a mint, a burn, a clawback, or any balance event
/// from a contract other than the asset. The spec asks for exactly this
/// ("any other balance change MUST cause verification to fail"), and it
/// matters most when the fee-sponsoring server is the party that signs.
///
/// `events` are base64 `DiagnosticEvent` XDR, as returned by a simulation.
/// The transfer shape checked here (`[transfer, from, to]` topics, `i128`
/// data) is the one the live Stellar host emits for a Stellar Asset
/// Contract transfer; it's verified against a real testnet transaction in
/// this crate's tests.
///
/// # Examples
///
/// ```rust
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Fixture {
///     asset_contract: String,
///     payer: String,
///     recipient: String,
///     amount: String,
///     diagnostic_events_xdr_base64: Vec<String>,
/// }
///
/// let fixture: Fixture = serde_json::from_str(include_str!(
///     concat!(
///         env!("CARGO_MANIFEST_DIR"),
///         "/../../tests/golden_vectors/fixtures/sac_native_transfer_events.json"
///     )
/// ))
/// .unwrap();
///
/// let asset = fixture.asset_contract.parse().unwrap();
/// let payer = fixture.payer.parse().unwrap();
/// let recipient = fixture.recipient.parse().unwrap();
/// let amount = fixture.amount.parse().unwrap();
///
/// sorocharge_signer::verify_transfer_effects(
///     &fixture.diagnostic_events_xdr_base64,
///     &asset,
///     &payer,
///     &recipient,
///     amount,
/// )
/// .unwrap();
/// ```
///
/// # Errors
///
/// - [`SorochargeError::SimulationEventsMalformed`] if an event does not
///   decode, or a balance event lacks the expected topics or data.
/// - [`SorochargeError::UnexpectedBalanceChange`] for any extra or
///   out-of-place balance movement.
/// - [`SorochargeError::ExpectedTransferMissing`] if the expected transfer
///   does not appear.
pub fn verify_transfer_effects(
    events: &[String],
    asset_contract: &Address,
    payer: &Address,
    recipient: &Address,
    amount: i128,
) -> Result<(), SorochargeError> {
    let ScAddress::Contract(ContractId(asset_hash)) = asset_contract else {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: "asset address is not a contract".to_string(),
        });
    };

    let mut transfers: Vec<(Address, Address, i128)> = Vec::new();
    for encoded in events {
        let event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).map_err(|e| {
            SorochargeError::SimulationEventsMalformed {
                reason: format!("event does not decode: {e}"),
            }
        })?;
        if event.event.type_ != ContractEventType::Contract {
            continue;
        }
        let ContractEventBody::V0(body) = &event.event.body;
        let Some(name) = body.topics.first().and_then(symbol_name) else {
            continue;
        };
        if !BALANCE_EVENT_NAMES.contains(&name.as_str()) {
            continue;
        }

        let from_asset = matches!(&event.event.contract_id, Some(ContractId(h)) if h == asset_hash);
        if !from_asset {
            return Err(SorochargeError::UnexpectedBalanceChange {
                reason: format!("balance event \"{name}\" from a contract other than the asset"),
            });
        }
        if name != "transfer" {
            return Err(SorochargeError::UnexpectedBalanceChange {
                reason: format!("\"{name}\" event in a payment"),
            });
        }
        let (Some(ScVal::Address(from)), Some(ScVal::Address(to))) =
            (body.topics.get(1), body.topics.get(2))
        else {
            return Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event lacks from/to address topics".to_string(),
            });
        };
        let Some(event_amount) = i128_from_scval(&body.data) else {
            return Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event data is not an i128".to_string(),
            });
        };
        transfers.push((from.clone(), to.clone(), event_amount));
    }

    if transfers.is_empty() {
        return Err(SorochargeError::ExpectedTransferMissing);
    }
    if transfers.len() > 1 {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: format!("{} transfer events, expected exactly one", transfers.len()),
        });
    }
    let (from, to, event_amount) = &transfers[0];
    if from != payer || to != recipient || *event_amount != amount {
        return Err(SorochargeError::UnexpectedBalanceChange {
            reason: "the transfer differs from the expected payer, recipient, or amount"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use stellar_xdr::{ContractEventBody as Body, ScSymbol, VecM, WriteXdr};

    #[derive(Deserialize)]
    struct Fixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        diagnostic_events_xdr_base64: Vec<String>,
    }

    fn load() -> Fixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/sac_native_transfer_events.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn is_transfer_event(encoded: &str) -> bool {
        let event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).unwrap();
        let Body::V0(v0) = &event.event.body;
        event.event.type_ == ContractEventType::Contract
            && v0.topics.first().and_then(symbol_name).as_deref() == Some("transfer")
    }

    /// Rewrites the first contract-transfer event through `edit`, returning its encoding.
    fn edited_transfer(encoded: &str, edit: impl FnOnce(&mut DiagnosticEvent)) -> String {
        let mut event = DiagnosticEvent::from_xdr_base64(encoded, Limits::none()).unwrap();
        edit(&mut event);
        event.to_xdr_base64(Limits::none()).unwrap()
    }

    fn expected(f: &Fixture) -> (Address, Address, Address, i128) {
        (
            f.asset_contract.parse().unwrap(),
            f.payer.parse().unwrap(),
            f.recipient.parse().unwrap(),
            f.amount.parse().unwrap(),
        )
    }

    #[test]
    fn accepts_the_real_testnet_transfer() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_a_transfer_of_the_wrong_amount() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &recipient,
            amount + 1,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_a_transfer_to_someone_else() {
        let f = load();
        let (asset, payer, _recipient, amount) = expected(&f);
        let other: Address = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
            .parse()
            .unwrap();
        let result = verify_transfer_effects(
            &f.diagnostic_events_xdr_base64,
            &asset,
            &payer,
            &other,
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_when_the_expected_transfer_is_absent() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let without: Vec<String> = f
            .diagnostic_events_xdr_base64
            .iter()
            .filter(|e| !is_transfer_event(e))
            .cloned()
            .collect();
        let result = verify_transfer_effects(&without, &asset, &payer, &recipient, amount);
        assert_eq!(result, Err(SorochargeError::ExpectedTransferMissing));
    }

    /// A simulation that emitted nothing at all is the one missing-transfer
    /// input the fixture-based test above cannot construct: it must surface
    /// as `ExpectedTransferMissing`, not as a malformed or unexpected event.
    #[test]
    fn rejects_a_simulation_with_no_events_at_all() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(&[], &asset, &payer, &recipient, amount);
        assert_eq!(result, Err(SorochargeError::ExpectedTransferMissing));
    }

    #[test]
    fn rejects_a_second_transfer_event() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let transfer = events
            .iter()
            .find(|e| is_transfer_event(e))
            .unwrap()
            .clone();
        events.push(transfer);
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_a_mint_event_even_with_the_transfer_present() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            let mut topics: Vec<ScVal> = v0.topics.to_vec();
            topics[0] = ScVal::Symbol(ScSymbol("mint".try_into().unwrap()));
            v0.topics = VecM::try_from(topics).unwrap();
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_a_balance_event_from_another_contract() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        events[idx] = edited_transfer(&events[idx], |ev| {
            ev.event.contract_id = Some(ContractId(stellar_xdr::Hash([0x42; 32])));
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert!(matches!(
            result,
            Err(SorochargeError::UnexpectedBalanceChange { .. })
        ));
    }

    #[test]
    fn rejects_an_event_that_does_not_decode() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let result = verify_transfer_effects(
            &["not-base64!!".to_string()],
            &asset,
            &payer,
            &recipient,
            amount,
        );
        assert!(matches!(
            result,
            Err(SorochargeError::SimulationEventsMalformed { .. })
        ));
    }

    #[test]
    fn rejects_a_transfer_event_lacking_from_to_address_topics() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        // Keep only the "transfer" symbol topic, dropping the from/to addresses.
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            v0.topics = VecM::try_from(vec![v0.topics[0].clone()]).unwrap();
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert_eq!(
            result,
            Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event lacks from/to address topics".to_string(),
            })
        );
    }

    #[test]
    fn rejects_a_transfer_event_whose_data_is_not_an_i128() {
        let f = load();
        let (asset, payer, recipient, amount) = expected(&f);
        let mut events = f.diagnostic_events_xdr_base64.clone();
        let idx = events.iter().position(|e| is_transfer_event(e)).unwrap();
        // The transfer amount must be an ScVal::I128; anything else is malformed.
        events[idx] = edited_transfer(&events[idx], |ev| {
            let Body::V0(v0) = &mut ev.event.body;
            v0.data = ScVal::I64(1_000_000);
        });
        let result = verify_transfer_effects(&events, &asset, &payer, &recipient, amount);
        assert_eq!(
            result,
            Err(SorochargeError::SimulationEventsMalformed {
                reason: "transfer event data is not an i128".to_string(),
            })
        );
    }
}
