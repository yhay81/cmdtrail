use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: String,
    pub tool_version: String,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub platform: PlatformInfo,
    pub command: CommandRecord,
    pub observation: Observation,
    pub capabilities: Vec<Capability>,
    pub limits: LimitsRecord,
    pub roots: Vec<RootRecord>,
    pub events: Vec<Event>,
    pub events_sha256: String,
    pub event_chain_head_sha256: String,
    pub summary: ReceiptSummary,
    pub redaction: RedactionReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlatformInfo {
    pub os: String,
    pub architecture: String,
    pub family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandRecord {
    pub executable_display: String,
    pub executable_sha256: String,
    pub argument_displays: Vec<String>,
    pub argument_sha256: Vec<Option<String>>,
    pub command_sha256: String,
    pub environment_captured: bool,
    pub outcome: CommandOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandOutcome {
    pub state: CommandState,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub success: bool,
    pub spawn_error_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    Exited,
    Signaled,
    TimedOut,
    Interrupted,
    SpawnFailed,
    ObserverFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub backend: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub duration_ms: u64,
    pub working_directory_handle: String,
    pub working_directory_display: String,
    pub coverage: CoverageLevel,
    pub known_blind_spots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    Full,
    Partial,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub name: String,
    pub level: CoverageLevel,
    pub backend: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitsRecord {
    pub max_entries_per_snapshot: u64,
    pub max_events: u64,
    pub max_file_hash_bytes: u64,
    pub max_total_hash_bytes_per_snapshot: u64,
    pub command_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootRecord {
    pub root_id: String,
    pub path_handle: String,
    pub display_name: String,
    pub before: SnapshotStats,
    pub after: SnapshotStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStats {
    pub retained_entries: u64,
    pub scanned_entries: u64,
    pub hashed_files: u64,
    pub hashed_bytes: u64,
    pub skipped_hashes: u64,
    pub traversal_errors: u64,
    pub error_classes: BTreeMap<String, u64>,
    pub truncated: bool,
    pub omitted_count_known: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub previous_event_sha256: Option<String>,
    pub event: EventData,
    pub event_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EventData {
    CommandRequested(CommandRequested),
    CommandFinished(CommandOutcome),
    FileEffect(Box<FileEffect>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandRequested {
    pub executable_sha256: String,
    pub command_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEffect {
    pub root_id: String,
    pub path_handle: String,
    pub display_path: String,
    pub effect: FileEffectKind,
    pub before: Option<EntryState>,
    pub after: Option<EntryState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FileEffectKind {
    Created,
    Modified,
    Deleted,
    TypeChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryState {
    pub kind: EntryKind,
    pub size_bytes: Option<String>,
    pub modified_at_unix_ns: Option<String>,
    pub readonly: bool,
    pub unix_mode: Option<u32>,
    pub content_sha256: Option<String>,
    pub content_hash_state: ContentHashState,
    pub symlink_target_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentHashState {
    Hashed,
    NotRegularFile,
    SkippedSensitivePath,
    SkippedFileTooLarge,
    SkippedTotalBudget,
    ReadError,
    ChangedDuringRead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSummary {
    pub command_state: CommandState,
    pub command_success: bool,
    pub file_effect_counts: BTreeMap<String, u64>,
    pub retained_file_effects: u64,
    pub dropped_file_effects: u64,
    pub snapshot_truncated: bool,
    pub traversal_errors: u64,
    pub observation_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedactionReport {
    pub mode: String,
    pub environment_values_captured: bool,
    pub custom_secret_values_loaded: u64,
    pub redacted_arguments: u64,
    pub redacted_path_components: u64,
    pub sensitive_file_hashes_skipped: u64,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationReport {
    pub schema_version: String,
    pub tool_version: String,
    pub receipt_id: Option<String>,
    pub integrity_valid: bool,
    pub receipt_digest_valid: bool,
    pub receipt_id_valid: bool,
    pub events_digest_valid: bool,
    pub event_chain_valid: bool,
    pub schema_supported: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordResult {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub command_state: CommandState,
    pub command_success: bool,
    pub file_effect_counts: BTreeMap<String, u64>,
    pub dropped_file_effects: u64,
    pub observation_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShowResult {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub receipt_id: String,
    pub integrity_valid: bool,
    pub command: CommandRecord,
    pub observation: Observation,
    pub capabilities: Vec<Capability>,
    pub summary: ReceiptSummary,
    pub roots: Vec<RootRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub before_receipt_id: String,
    pub after_receipt_id: String,
    pub added_effects: Vec<EffectKey>,
    pub removed_effects: Vec<EffectKey>,
    pub changed_effects: Vec<ChangedEffect>,
    pub command_outcome_changed: bool,
    pub capability_declaration_changed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectKey {
    pub root_id: String,
    pub path_handle: String,
    pub display_path: String,
    pub effect: FileEffectKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangedEffect {
    pub key: EffectKey,
    pub before: FileEffect,
    pub after: FileEffect,
}
