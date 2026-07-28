use crate::capability::portable_capabilities;
use crate::error::AppError;
use crate::integrity::{append_event, finalize_receipt, sha256_bytes};
use crate::model::{
    CommandOutcome, CommandRecord, CommandRequested, CommandState, CoverageLevel, EventData,
    LimitsRecord, Observation, PlatformInfo, Receipt, ReceiptSummary, RecordResult,
    RedactionReport,
};
use crate::receipt::write_new_receipt;
use crate::redact::{os_bytes, Redactor};
use crate::snapshot::{compare, prepare_roots, root_records, SnapshotConfig};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct RecordOptions {
    pub output: PathBuf,
    pub working_directory: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub max_entries: u64,
    pub max_events: u64,
    pub max_file_hash_bytes: u64,
    pub max_total_hash_bytes: u64,
    pub timeout_ms: Option<u64>,
    pub redact_environment_names: Vec<String>,
    pub command: Vec<OsString>,
}

/// Runs a direct command and persists its bounded observation receipt.
///
/// # Errors
///
/// Returns an error when setup, snapshot configuration, interruption handling, integrity
/// sealing, or receipt storage fails. A child spawn failure is represented in a valid receipt.
#[allow(clippy::too_many_lines)]
pub fn record(options: &RecordOptions) -> Result<RecordResult, AppError> {
    validate_options(options)?;
    let redactor = Redactor::from_environment_names(&options.redact_environment_names)
        .map_err(|message| AppError::usage("invalid_redaction_environment", message))?;
    let working_directory = options
        .working_directory
        .as_deref()
        .map_or_else(std::env::current_dir, fs::canonicalize)
        .and_then(fs::canonicalize)
        .map_err(|_| {
            AppError::usage(
                "working_directory_unavailable",
                "the working directory does not exist or cannot be resolved",
            )
        })?;
    let roots = prepare_roots(&working_directory, &options.roots, &redactor)?;
    let snapshot_config = SnapshotConfig {
        max_entries: options.max_entries,
        max_file_hash_bytes: options.max_file_hash_bytes,
        max_total_hash_bytes: options.max_total_hash_bytes,
    };

    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || interrupt_flag.store(true, Ordering::SeqCst)).map_err(|_| {
        AppError::execution(
            "interrupt_handler_unavailable",
            "could not install the cross-platform interruption handler",
        )
    })?;
    let started_at = unix_ms();
    let before =
        crate::snapshot::capture_cancellable(&roots, &snapshot_config, &redactor, &interrupted);
    let command_started_at = unix_ms();
    let redacted_command = redactor.command(&options.command);

    let (outcome, mut dynamic_blind_spots) = run_command(
        &options.command,
        &working_directory,
        options.timeout_ms,
        &interrupted,
    );
    let command_finished_at = unix_ms();
    let after =
        crate::snapshot::capture_cancellable(&roots, &snapshot_config, &redactor, &interrupted);
    let finished_at = unix_ms();
    let effects = compare(&before, &after);

    let mut file_effect_counts = BTreeMap::new();
    for effect in &effects {
        let name = serde_json::to_value(&effect.effect)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        *file_effect_counts.entry(name).or_insert(0_u64) += 1;
    }
    let file_slots = options.max_events.saturating_sub(2);
    let retained_effect_count = u64::try_from(effects.len())
        .unwrap_or(u64::MAX)
        .min(file_slots);
    let dropped_file_effects = u64::try_from(effects.len())
        .unwrap_or(u64::MAX)
        .saturating_sub(retained_effect_count);

    let command_record = CommandRecord {
        executable_display: redacted_command.executable_display,
        executable_sha256: redacted_command.executable_sha256.clone(),
        argument_displays: redacted_command.argument_displays,
        argument_sha256: redacted_command.argument_sha256,
        command_sha256: redacted_command.command_sha256.clone(),
        environment_captured: false,
        outcome: outcome.clone(),
    };
    let mut events = Vec::new();
    append_event(
        &mut events,
        command_started_at,
        EventData::CommandRequested(CommandRequested {
            executable_sha256: redacted_command.executable_sha256,
            command_sha256: redacted_command.command_sha256,
        }),
    )?;
    append_event(
        &mut events,
        command_finished_at,
        EventData::CommandFinished(outcome.clone()),
    )?;
    for effect in effects
        .into_iter()
        .take(usize::try_from(file_slots).unwrap_or(usize::MAX))
    {
        append_event(
            &mut events,
            finished_at,
            EventData::FileEffect(Box::new(effect)),
        )?;
    }

    let root_records = root_records(&roots, &before, &after);
    let snapshot_truncated = root_records
        .iter()
        .any(|root| root.before.truncated || root.after.truncated);
    let traversal_errors = root_records.iter().fold(0_u64, |total, root| {
        total
            .saturating_add(root.before.traversal_errors)
            .saturating_add(root.after.traversal_errors)
    });
    if snapshot_truncated {
        dynamic_blind_spots.push(
            "at least one snapshot hit the entry limit; omitted path count is unknown".to_owned(),
        );
    }
    if traversal_errors > 0 {
        dynamic_blind_spots.push(
            "at least one path could not be traversed or read; see per-root error classes"
                .to_owned(),
        );
    }
    if dropped_file_effects > 0 {
        dynamic_blind_spots.push(
            "file effects exceeded the event limit; summary counts include dropped events"
                .to_owned(),
        );
    }
    let mut blind_spots = vec![
        "pre/post snapshots cannot observe transient create-write-delete effects".to_owned(),
        "filesystem deltas are not attributed to a specific process".to_owned(),
        "detached descendants may continue after the direct child exits".to_owned(),
        "network, listening-port, resource, stdout, stderr, and environment effects are not observed"
            .to_owned(),
        "content digests can miss files skipped by sensitivity, size, budget, races, or read errors"
            .to_owned(),
        "redaction is pattern-based and cannot guarantee removal of arbitrary positional secrets"
            .to_owned(),
    ];
    blind_spots.extend(dynamic_blind_spots);

    let working_directory_display_source = working_directory
        .file_name()
        .map_or(working_directory.as_path(), Path::new);
    let (working_directory_display, _) = redactor.path_display(working_directory_display_source);
    let working_directory_digest = sha256_bytes(&os_bytes(working_directory.as_os_str()));
    let summary = ReceiptSummary {
        command_state: outcome.state.clone(),
        command_success: outcome.success,
        file_effect_counts: file_effect_counts.clone(),
        retained_file_effects: retained_effect_count,
        dropped_file_effects,
        snapshot_truncated,
        traversal_errors,
        observation_complete: false,
    };
    let redaction = RedactionReport {
        mode: "relative_paths_with_sensitive_components_redacted".to_owned(),
        environment_values_captured: false,
        custom_secret_values_loaded: redactor.custom_value_count(),
        redacted_arguments: redacted_command.redacted_arguments,
        redacted_path_components: before
            .redacted_path_components
            .saturating_add(after.redacted_path_components),
        sensitive_file_hashes_skipped: before
            .sensitive_file_hashes_skipped
            .saturating_add(after.sensitive_file_hashes_skipped),
        limitations: vec![
            "opaque path and executable SHA-256 handles may still be susceptible to dictionary attacks"
                .to_owned(),
            "unknown secret forms require --redact-env and may otherwise appear in argument displays"
                .to_owned(),
            "redacted argument digests are omitted and command_sha256 binds only the redacted command representation"
                .to_owned(),
        ],
    };
    let mut receipt = Receipt {
        schema_version: crate::RECEIPT_SCHEMA.to_owned(),
        tool_version: crate::VERSION.to_owned(),
        receipt_id: String::new(),
        receipt_sha256: String::new(),
        platform: PlatformInfo {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            family: std::env::consts::FAMILY.to_owned(),
        },
        command: command_record,
        observation: Observation {
            backend: "portable_pre_post_snapshot".to_owned(),
            started_at_unix_ms: started_at,
            finished_at_unix_ms: finished_at,
            duration_ms: finished_at.saturating_sub(started_at),
            working_directory_handle: format!("path_{working_directory_digest}"),
            working_directory_display,
            coverage: CoverageLevel::Partial,
            known_blind_spots: blind_spots,
        },
        capabilities: portable_capabilities(),
        limits: LimitsRecord {
            max_entries_per_snapshot: options.max_entries,
            max_events: options.max_events,
            max_file_hash_bytes: options.max_file_hash_bytes,
            max_total_hash_bytes_per_snapshot: options.max_total_hash_bytes,
            command_timeout_ms: options.timeout_ms,
        },
        roots: root_records,
        events,
        events_sha256: String::new(),
        event_chain_head_sha256: String::new(),
        summary,
        redaction,
    };
    finalize_receipt(&mut receipt)?;
    write_new_receipt(&options.output, &receipt)?;

    Ok(RecordResult {
        schema_version: "cmdtrail.record-result.v1",
        tool_version: crate::VERSION,
        receipt_id: receipt.receipt_id,
        receipt_sha256: receipt.receipt_sha256,
        command_state: receipt.summary.command_state,
        command_success: receipt.summary.command_success,
        file_effect_counts,
        dropped_file_effects,
        observation_complete: false,
    })
}

fn validate_options(options: &RecordOptions) -> Result<(), AppError> {
    if options.command.is_empty() {
        return Err(AppError::usage(
            "missing_command",
            "a direct command is required after the mandatory -- separator",
        ));
    }
    if options.max_entries == 0 || options.max_entries > 1_000_000 {
        return Err(AppError::usage(
            "invalid_max_entries",
            "max entries must be between 1 and 1,000,000",
        ));
    }
    if !(2..=1_000_000).contains(&options.max_events) {
        return Err(AppError::usage(
            "invalid_max_events",
            "max events must be between 2 and 1,000,000",
        ));
    }
    if options.max_file_hash_bytes > 1024 * 1024 * 1024 {
        return Err(AppError::usage(
            "invalid_file_hash_limit",
            "the per-file hash limit cannot exceed 1 GiB",
        ));
    }
    if options.max_total_hash_bytes > 16 * 1024 * 1024 * 1024 {
        return Err(AppError::usage(
            "invalid_total_hash_limit",
            "the total hash limit cannot exceed 16 GiB per snapshot",
        ));
    }
    if options
        .timeout_ms
        .is_some_and(|timeout| timeout == 0 || timeout > 86_400_000)
    {
        return Err(AppError::usage(
            "invalid_timeout",
            "the command timeout must be between 1 ms and 24 hours",
        ));
    }
    match fs::symlink_metadata(&options.output) {
        Ok(_) => Err(AppError::io(
            "output_already_exists",
            "the receipt output path already exists; CmdTrail never overwrites receipts",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AppError::io(
            "output_preflight_failed",
            "the receipt output path could not be checked safely",
        )),
    }
}

fn run_command(
    command: &[OsString],
    working_directory: &std::path::Path,
    timeout_ms: Option<u64>,
    interrupted: &AtomicBool,
) -> (CommandOutcome, Vec<String>) {
    if interrupted.load(Ordering::SeqCst) {
        return interrupted_before_spawn();
    }
    let mut process = Command::new(&command[0]);
    process
        .args(&command[1..])
        .current_dir(working_directory)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => {
            return (
                CommandOutcome {
                    state: CommandState::SpawnFailed,
                    exit_code: None,
                    signal: None,
                    success: false,
                    spawn_error_kind: Some(format!("{:?}", error.kind()).to_ascii_lowercase()),
                },
                Vec::new(),
            );
        }
    };
    let mut forwarders = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        forwarders.push(forward_stdout(stdout));
    }
    if let Some(stderr) = child.stderr.take() {
        forwarders.push(forward_stderr(stderr));
    }

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return finish_run(outcome_from_status(status), Vec::new(), forwarders);
            }
            Ok(None) => {}
            Err(_) => {
                let kill_confirmed = child.kill().and_then(|()| child.wait()).is_ok();
                let blind_spots = (!kill_confirmed)
                    .then(|| {
                        vec![
                            "direct child termination could not be confirmed after a wait failure"
                                .to_owned(),
                        ]
                    })
                    .unwrap_or_default();
                return finish_run(
                    CommandOutcome {
                        state: CommandState::ObserverFailed,
                        exit_code: None,
                        signal: None,
                        success: false,
                        spawn_error_kind: Some("wait_failed".to_owned()),
                    },
                    blind_spots,
                    forwarders,
                );
            }
        }
        let timed_out =
            timeout_ms.is_some_and(|limit| started.elapsed() >= Duration::from_millis(limit));
        let was_interrupted = interrupted.load(Ordering::SeqCst);
        if timed_out || was_interrupted {
            let kill_confirmed = child.kill().and_then(|()| child.wait()).is_ok();
            let blind_spots = (!kill_confirmed)
                .then(|| {
                    vec![
                        "direct child termination could not be confirmed; the process may still be running"
                            .to_owned(),
                    ]
                })
                .unwrap_or_default();
            return finish_run(
                CommandOutcome {
                    state: if was_interrupted {
                        CommandState::Interrupted
                    } else {
                        CommandState::TimedOut
                    },
                    exit_code: None,
                    signal: None,
                    success: false,
                    spawn_error_kind: (!kill_confirmed)
                        .then(|| "termination_not_confirmed".to_owned()),
                },
                blind_spots,
                forwarders,
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn interrupted_before_spawn() -> (CommandOutcome, Vec<String>) {
    (
        CommandOutcome {
            state: CommandState::Interrupted,
            exit_code: None,
            signal: None,
            success: false,
            spawn_error_kind: None,
        },
        vec!["observation was interrupted before direct-command spawn".to_owned()],
    )
}

fn forward_stdout(mut output: ChildStdout) -> JoinHandle<io::Result<u64>> {
    std::thread::spawn(move || io::copy(&mut output, &mut io::stderr()))
}

fn forward_stderr(mut output: ChildStderr) -> JoinHandle<io::Result<u64>> {
    std::thread::spawn(move || io::copy(&mut output, &mut io::stderr()))
}

fn finish_run(
    outcome: CommandOutcome,
    mut blind_spots: Vec<String>,
    forwarders: Vec<JoinHandle<io::Result<u64>>>,
) -> (CommandOutcome, Vec<String>) {
    let forwarding_failed = forwarders.into_iter().fold(false, |failed, forwarder| {
        !matches!(forwarder.join(), Ok(Ok(_))) || failed
    });
    if forwarding_failed {
        blind_spots.push(
            "at least one observed-command output stream could not be fully passed through to stderr"
                .to_owned(),
        );
    }
    (outcome, blind_spots)
}

fn outcome_from_status(status: ExitStatus) -> CommandOutcome {
    let exit_code = status.code();
    let signal = exit_signal(status);
    CommandOutcome {
        state: if exit_code.is_some() {
            CommandState::Exited
        } else {
            CommandState::Signaled
        },
        exit_code,
        signal,
        success: status.success(),
        spawn_error_kind: None,
    }
}

#[cfg(unix)]
fn exit_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
