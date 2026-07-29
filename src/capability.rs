use crate::model::{Capability, CoverageLevel};
use serde::Serialize;
use std::collections::BTreeMap;

#[must_use]
pub fn portable_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            name: "direct_process_lifecycle".to_owned(),
            level: CoverageLevel::Full,
            backend: "std_process".to_owned(),
            reason: "records spawn outcome and direct child exit, timeout, or interruption".to_owned(),
        },
        Capability {
            name: "descendant_process_tree".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "portable_snapshot".to_owned(),
            reason: "v0.1 does not instrument descendant process start, exec, parentage, or exit"
                .to_owned(),
        },
        Capability {
            name: "persistent_filesystem_delta".to_owned(),
            level: CoverageLevel::Partial,
            backend: "portable_pre_post_snapshot".to_owned(),
            reason: "detects retained metadata and bounded content-digest differences under declared roots; transient effects and process attribution are not observed".to_owned(),
        },
        Capability {
            name: "network_connections".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "portable_snapshot".to_owned(),
            reason: "v0.1 does not instrument network connect or accept operations".to_owned(),
        },
        Capability {
            name: "listening_ports".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "portable_snapshot".to_owned(),
            reason: "v0.1 does not inspect socket lifecycle or listening ports".to_owned(),
        },
        Capability {
            name: "resource_totals".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "portable_snapshot".to_owned(),
            reason: "portable per-command CPU, memory, and I/O totals are not collected".to_owned(),
        },
        Capability {
            name: "delayed_descendant_effects".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "portable_snapshot".to_owned(),
            reason: "the post-snapshot begins after the direct child exits and does not wait for detached descendants".to_owned(),
        },
        Capability {
            name: "payload_capture".to_owned(),
            level: CoverageLevel::Unavailable,
            backend: "privacy_default".to_owned(),
            reason: "stdout, stderr, environment values, file contents, and network payloads are not captured".to_owned(),
        },
    ]
}

#[derive(Debug, Serialize)]
pub struct CapabilitiesDocument {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub backend: &'static str,
    pub supported_platforms: Vec<&'static str>,
    pub capabilities: Vec<Capability>,
    pub safety_defaults: BTreeMap<&'static str, &'static str>,
}

#[must_use]
pub fn capabilities_document() -> CapabilitiesDocument {
    CapabilitiesDocument {
        schema_version: "cmdtrail.capabilities.v1",
        tool_version: crate::VERSION,
        backend: "portable_pre_post_snapshot",
        supported_platforms: vec![
            "linux-x86_64",
            "macos-x86_64",
            "macos-aarch64",
            "windows-x86_64",
        ],
        capabilities: portable_capabilities(),
        safety_defaults: BTreeMap::from([
            ("argument_handling", "direct_exec_only_mandatory_separator"),
            ("environment_capture", "disabled"),
            ("file_content_capture", "disabled_digest_only"),
            ("output", "new_private_file_no_overwrite"),
            (
                "path_display",
                "relative_with_sensitive_components_redacted",
            ),
            (
                "receipt_integrity",
                "sha256_event_chain_and_canonical_receipt",
            ),
            (
                "receipt_recovery",
                "preflight_then_no_clobber_recovery_with_do_not_retry",
            ),
            ("unavailable_capabilities", "declared_not_inferred"),
        ]),
    }
}

#[derive(Debug, Serialize)]
pub struct ContractDocument {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub commands: Vec<&'static str>,
    pub stdout: &'static str,
    pub stderr: &'static str,
    pub exit_codes: BTreeMap<u8, &'static str>,
    pub receipt_schema: &'static str,
    pub integrity_algorithm: &'static str,
    pub record_child_failure_semantics: &'static str,
}

#[must_use]
pub fn contract_document() -> ContractDocument {
    ContractDocument {
        schema_version: "cmdtrail.contract.v1",
        tool_version: crate::VERSION,
        commands: vec![
            "record",
            "show",
            "diff",
            "verify",
            "schema",
            "capabilities",
            "contract",
            "completions",
        ],
        stdout: "one JSON document on successful data commands; completion scripts for completions",
        stderr: "observed-command stdout/stderr passthrough followed by one cmdtrail.error.v1 JSON document on runtime failure",
        exit_codes: BTreeMap::from([
            (0, "operation_succeeded; record also uses 0 when the observed command fails but a receipt is written"),
            (1, "io_or_receipt_storage"),
            (2, "usage_or_clap_help_error"),
            (3, "receipt_integrity_failure"),
            (4, "configured_or_input_limit"),
            (5, "command_execution_setup_failure_without_receipt"),
            (6, "post_execution_receipt_failure_do_not_retry"),
        ]),
        receipt_schema: crate::RECEIPT_SCHEMA,
        integrity_algorithm: "RFC 8785 JCS plus SHA-256 with cmdtrail.integrity.v1 domain separation",
        record_child_failure_semantics: "inspect command.outcome; receipt creation success is distinct from observed command success",
    }
}

#[derive(Debug, Serialize)]
pub struct SchemaDocument {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub receipt_schema: &'static str,
    pub event_types: Vec<&'static str>,
    pub command_states: Vec<&'static str>,
    pub file_effects: Vec<&'static str>,
    pub coverage_levels: Vec<&'static str>,
    pub integrity: BTreeMap<&'static str, &'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<&'static str, &'static str>>,
}

#[must_use]
pub fn schema_document(brief: bool) -> SchemaDocument {
    SchemaDocument {
        schema_version: "cmdtrail.schema.v1",
        tool_version: crate::VERSION,
        receipt_schema: crate::RECEIPT_SCHEMA,
        event_types: vec!["command_requested", "command_finished", "file_effect"],
        command_states: vec![
            "exited",
            "signaled",
            "timed_out",
            "interrupted",
            "spawn_failed",
            "observer_failed",
        ],
        file_effects: vec!["created", "modified", "deleted", "type_changed"],
        coverage_levels: vec!["full", "partial", "unavailable", "unknown"],
        integrity: BTreeMap::from([
            ("events", "RFC 8785 JCS parsed events array SHA-256"),
            (
                "event_chain",
                "sequence and previous_event_sha256 bound into each event SHA-256",
            ),
            (
                "receipt",
                "RFC 8785 JCS parsed receipt with empty receipt_id and receipt_sha256",
            ),
            (
                "receipt_id",
                "ct_ plus first 24 hexadecimal characters of receipt_sha256",
            ),
        ]),
        fields: (!brief).then(|| {
            BTreeMap::from([
                ("platform", "operating system, architecture, and family"),
                (
                    "command",
                    "redacted displays, omitted secret digests, redacted command fingerprint, and direct-child outcome",
                ),
                (
                    "observation",
                    "backend, time envelope, working-directory handle, and blind spots",
                ),
                (
                    "capabilities",
                    "effective coverage level, backend, and reason per capability",
                ),
                (
                    "limits",
                    "configured snapshot, event, hashing, and timeout bounds",
                ),
                (
                    "roots",
                    "opaque root handles plus before/after scan statistics",
                ),
                (
                    "events",
                    "bounded hash-chained command lifecycle and filesystem delta facts",
                ),
                (
                    "summary",
                    "command state, effect counts, drops, errors, and completeness",
                ),
                (
                    "redaction",
                    "applied privacy defaults and their limitations",
                ),
            ])
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_contract_declares_post_execution_receipt_recovery() {
        let contract = contract_document();
        assert_eq!(
            contract.exit_codes.get(&6),
            Some(&"post_execution_receipt_failure_do_not_retry")
        );
        let capabilities = capabilities_document();
        assert_eq!(
            capabilities.safety_defaults.get("receipt_recovery"),
            Some(&"preflight_then_no_clobber_recovery_with_do_not_retry")
        );
    }
}
