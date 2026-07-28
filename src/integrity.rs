use crate::error::AppError;
use crate::model::{Event, EventData, Receipt, VerificationReport};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_lower(&digest[..])
}

/// Hashes a serializable value using `CmdTrail`'s domain-separated encoding.
///
/// # Errors
///
/// Returns an error when the value cannot be serialized to canonical JSON bytes.
pub fn hash_serializable<T: Serialize + ?Sized>(
    domain: &str,
    value: &T,
) -> Result<String, AppError> {
    let encoded = serde_jcs::to_vec(value).map_err(|_| {
        AppError::io(
            "canonical_serialization_failed",
            "could not serialize RFC 8785 integrity material",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"cmdtrail.integrity.v1\0");
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(encoded);
    let digest = hasher.finalize();
    Ok(hex_lower(&digest[..]))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Appends and seals one event onto an existing hash chain.
///
/// # Errors
///
/// Returns an error when the event cannot be serialized for hashing.
pub fn append_event(
    events: &mut Vec<Event>,
    observed_at_unix_ms: u64,
    event_data: EventData,
) -> Result<(), AppError> {
    let previous = events.last().map(|event| event.event_sha256.clone());
    let mut event = Event {
        sequence: u64::try_from(events.len()).unwrap_or(u64::MAX),
        observed_at_unix_ms,
        previous_event_sha256: previous,
        event: event_data,
        event_sha256: String::new(),
    };
    event.event_sha256 = hash_event(&event)?;
    events.push(event);
    Ok(())
}

/// Finalizes all aggregate digests and the derived receipt identifier.
///
/// # Errors
///
/// Returns an error when the receipt or event array cannot be serialized.
pub fn finalize_receipt(receipt: &mut Receipt) -> Result<(), AppError> {
    receipt.events_sha256 = hash_serializable("events", &receipt.events)?;
    receipt.event_chain_head_sha256 = receipt
        .events
        .last()
        .map_or_else(String::new, |event| event.event_sha256.clone());
    receipt.receipt_id.clear();
    receipt.receipt_sha256.clear();
    let digest = hash_serializable("receipt", receipt)?;
    receipt.receipt_id = format!("ct_{}", &digest[..24]);
    receipt.receipt_sha256 = digest;
    Ok(())
}

#[must_use]
pub fn verify_receipt(receipt: &Receipt) -> VerificationReport {
    let mut errors = Vec::new();
    let schema_supported = receipt.schema_version == crate::RECEIPT_SCHEMA;
    if !schema_supported {
        errors.push("unsupported_schema".to_owned());
    }

    let expected_events_digest = hash_serializable("events", &receipt.events);
    let events_digest_valid = expected_events_digest
        .as_ref()
        .is_ok_and(|digest| digest == &receipt.events_sha256);
    if !events_digest_valid {
        errors.push("events_digest_mismatch".to_owned());
    }

    let mut previous: Option<&str> = None;
    let mut event_chain_valid = true;
    for (index, event) in receipt.events.iter().enumerate() {
        let sequence_valid = event.sequence == u64::try_from(index).unwrap_or(u64::MAX);
        let previous_valid = event.previous_event_sha256.as_deref() == previous;
        let digest_valid = hash_event(event)
            .as_ref()
            .is_ok_and(|digest| digest == &event.event_sha256);
        if !(sequence_valid && previous_valid && digest_valid) {
            event_chain_valid = false;
            break;
        }
        previous = Some(&event.event_sha256);
    }
    let head_valid = receipt.event_chain_head_sha256
        == receipt
            .events
            .last()
            .map_or("", |event| event.event_sha256.as_str());
    event_chain_valid &= head_valid;
    if !event_chain_valid {
        errors.push("event_chain_invalid".to_owned());
    }

    let mut material = receipt.clone();
    material.receipt_id.clear();
    material.receipt_sha256.clear();
    let expected_receipt_digest = hash_serializable("receipt", &material);
    let receipt_digest_valid = expected_receipt_digest
        .as_ref()
        .is_ok_and(|digest| digest == &receipt.receipt_sha256);
    if !receipt_digest_valid {
        errors.push("receipt_digest_mismatch".to_owned());
    }
    let receipt_id_valid = expected_receipt_digest
        .as_ref()
        .is_ok_and(|digest| receipt.receipt_id == format!("ct_{}", &digest[..24]));
    if !receipt_id_valid {
        errors.push("receipt_id_mismatch".to_owned());
    }

    VerificationReport {
        schema_version: "cmdtrail.verification.v1".to_owned(),
        tool_version: crate::VERSION.to_owned(),
        receipt_id: Some(receipt.receipt_id.clone()),
        integrity_valid: schema_supported
            && receipt_digest_valid
            && receipt_id_valid
            && events_digest_valid
            && event_chain_valid,
        receipt_digest_valid,
        receipt_id_valid,
        events_digest_valid,
        event_chain_valid,
        schema_supported,
        errors,
    }
}

fn hash_event(event: &Event) -> Result<String, AppError> {
    let mut material = event.clone();
    material.event_sha256.clear();
    hash_serializable("event", &material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CommandOutcome, CommandState};
    use serde::Serialize;

    #[derive(Serialize)]
    struct OutOfOrderKeys {
        b: u8,
        a: u8,
    }

    #[test]
    fn hash_uses_rfc_8785_key_order_and_domain_envelope() {
        let digest =
            hash_serializable("test", &OutOfOrderKeys { b: 1, a: 2 }).expect("hash should compute");
        assert_eq!(
            digest,
            "34054ca1f55ff11643a74f7cb867ffaeb2e4ed85a5db402f67a13378a33f0155"
        );
    }

    #[test]
    fn event_chain_detects_tampering() {
        let mut events = Vec::new();
        append_event(
            &mut events,
            1,
            EventData::CommandFinished(CommandOutcome {
                state: CommandState::Exited,
                exit_code: Some(0),
                signal: None,
                success: true,
                spawn_error_kind: None,
            }),
        )
        .expect("event should seal");
        assert_eq!(events.len(), 1);
        let original = events[0].event_sha256.clone();
        events[0].observed_at_unix_ms = 2;
        assert_ne!(
            hash_event(&events[0]).expect("hash should compute"),
            original
        );
    }
}
