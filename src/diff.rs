use crate::error::{AppError, ExitClass};
use crate::integrity::verify_receipt;
use crate::model::{ChangedEffect, DiffResult, EffectKey, EventData, FileEffect, Receipt};
use std::collections::{BTreeMap, BTreeSet};

/// Compares the retained effects in two integrity-verified receipts.
///
/// # Errors
///
/// Returns an integrity error when either receipt fails verification.
pub fn diff_receipts(before: &Receipt, after: &Receipt) -> Result<DiffResult, AppError> {
    ensure_verified(before)?;
    ensure_verified(after)?;
    let before_effects = effects(before);
    let after_effects = effects(after);
    let keys = before_effects
        .keys()
        .chain(after_effects.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut added_effects = Vec::new();
    let mut removed_effects = Vec::new();
    let mut changed_effects = Vec::new();
    for key in keys {
        match (before_effects.get(&key), after_effects.get(&key)) {
            (None, Some(_)) => added_effects.push(key),
            (Some(_), None) => removed_effects.push(key),
            (Some(before_effect), Some(after_effect)) if before_effect != after_effect => {
                changed_effects.push(ChangedEffect {
                    key,
                    before: before_effect.clone(),
                    after: after_effect.clone(),
                });
            }
            _ => {}
        }
    }

    Ok(DiffResult {
        schema_version: "cmdtrail.diff.v1",
        tool_version: crate::VERSION,
        before_receipt_id: before.receipt_id.clone(),
        after_receipt_id: after.receipt_id.clone(),
        added_effects,
        removed_effects,
        changed_effects,
        command_outcome_changed: before.command.outcome != after.command.outcome,
        capability_declaration_changed: before.capabilities != after.capabilities,
    })
}

fn ensure_verified(receipt: &Receipt) -> Result<(), AppError> {
    if verify_receipt(receipt).integrity_valid {
        Ok(())
    } else {
        Err(AppError::new(
            ExitClass::Integrity,
            "receipt_integrity_invalid",
            "a receipt failed integrity verification and cannot be compared",
        ))
    }
}

fn effects(receipt: &Receipt) -> BTreeMap<EffectKey, FileEffect> {
    receipt
        .events
        .iter()
        .filter_map(|event| match &event.event {
            EventData::FileEffect(effect) => {
                let key = EffectKey {
                    root_id: effect.root_id.clone(),
                    path_handle: effect.path_handle.clone(),
                    display_path: effect.display_path.clone(),
                    effect: effect.effect.clone(),
                };
                Some((key, effect.as_ref().clone()))
            }
            _ => None,
        })
        .collect()
}
