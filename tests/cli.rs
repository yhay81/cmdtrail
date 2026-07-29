use cmdtrail::integrity::verify_receipt;
use cmdtrail::receipt::read_receipt;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("cmdtrail-cli-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("test directory should be created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn fixture_child() {
    let Ok(mode) = std::env::var("CMDTRAIL_FIXTURE_MODE") else {
        return;
    };
    match mode.as_str() {
        "effects" => {
            fs::write("created.txt", b"created").expect("fixture should create");
            fs::write("modified.txt", b"after!").expect("fixture should modify");
            fs::remove_file("deleted.txt").expect("fixture should delete");
            fs::write(".env.production", b"PRIVATE_VALUE=do-not-record")
                .expect("fixture should create sensitive file");
            println!("fixture standard output");
            eprintln!("fixture standard error");
        }
        "many" => {
            for index in 0..5 {
                fs::write(format!("many-{index}.txt"), index.to_string())
                    .expect("fixture should create many files");
            }
        }
        "second" => {
            fs::write("second.txt", b"second").expect("fixture should create");
        }
        "occupy_receipt" => {
            fs::write("side-effect.txt", b"command-ran")
                .expect("fixture should create side effect");
            fs::write("receipt.json", b"occupied-by-command")
                .expect("fixture should occupy receipt path");
        }
        "sleep" => {
            fs::write("child-ready", b"ready").expect("fixture should signal readiness");
            std::thread::sleep(Duration::from_secs(5));
        }
        "fail" => std::process::exit(17),
        "noop" => {}
        other => panic!("unknown fixture mode: {other}"),
    }
}

#[test]
fn records_verifies_and_summarizes_portable_effects() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    fs::write(root.join("modified.txt"), b"before").expect("fixture should write");
    fs::write(root.join("deleted.txt"), b"delete").expect("fixture should write");
    let receipt = directory.path.join("effect.receipt.json");

    let output = run_record(&root, &receipt, "effects", &[]);
    assert!(
        output.status.success(),
        "record failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON document");
    assert_eq!(result["schema_version"], "cmdtrail.record-result.v1");
    assert_eq!(result["command_state"], "exited");
    assert_eq!(result["command_success"], true);
    assert_eq!(result["file_effect_counts"]["created"], 2);
    assert_eq!(result["file_effect_counts"]["modified"], 1);
    assert_eq!(result["file_effect_counts"]["deleted"], 1);
    let passthrough = String::from_utf8_lossy(&output.stderr);
    assert!(passthrough.contains("fixture standard output"));
    assert!(passthrough.contains("fixture standard error"));

    let parsed = read_json(&receipt);
    assert_eq!(parsed["observation"]["coverage"], "partial");
    assert_eq!(parsed["summary"]["observation_complete"], false);
    assert_eq!(parsed["redaction"]["environment_values_captured"], false);
    let serialized = serde_json::to_string(&parsed).expect("receipt should serialize");
    assert!(!serialized.contains("do-not-record"));
    assert!(!serialized.contains(".env.production"));
    assert!(!serialized.contains("literal-secret"));
    assert!(serialized.contains("[redacted_"));

    let verification = Command::new(cmdtrail())
        .args(["verify", "--format", "json"])
        .arg(&receipt)
        .output()
        .expect("verify should run");
    assert!(verification.status.success());
    let verification_json: Value =
        serde_json::from_slice(&verification.stdout).expect("verify should return JSON");
    assert_eq!(verification_json["integrity_valid"], true);

    let show = Command::new(cmdtrail())
        .args(["show", "--summary", "--format", "json"])
        .arg(&receipt)
        .output()
        .expect("show should run");
    assert!(show.status.success());
    let show_json: Value = serde_json::from_slice(&show.stdout).expect("show should return JSON");
    assert_eq!(show_json["schema_version"], "cmdtrail.show.v1");
    assert_eq!(show_json["integrity_valid"], true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&receipt)
                .expect("receipt metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn child_failure_is_a_successfully_recorded_fact() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("failure.receipt.json");
    let output = run_record(&root, &receipt, "fail", &[]);
    assert!(
        output.status.success(),
        "receipt creation, not child success, controls the wrapper exit"
    );
    let result: Value = serde_json::from_slice(&output.stdout).expect("record should return JSON");
    assert_eq!(result["command_state"], "exited");
    assert_eq!(result["command_success"], false);
    let parsed = read_json(&receipt);
    assert_eq!(parsed["command"]["outcome"]["exit_code"], 17);
}

#[test]
fn timeout_is_bounded_and_receipted() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("timeout.receipt.json");
    let started = std::time::Instant::now();
    let output = run_record(&root, &receipt, "sleep", &["--timeout", "100ms"]);
    assert!(
        output.status.success(),
        "timed record failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let parsed = read_json(&receipt);
    assert_eq!(parsed["command"]["outcome"]["state"], "timed_out");
    assert_eq!(parsed["command"]["outcome"]["success"], false);
}

#[cfg(unix)]
#[test]
fn interruption_is_receipted_and_marks_snapshot_incomplete() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("interrupt.receipt.json");
    let mut command = record_command(&root, &receipt, "sleep", &[]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().expect("cmdtrail should spawn");
    let ready = root.join("child-ready");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture child did not signal readiness"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let signal = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .expect("kill should run");
    assert!(signal.success());
    let output = child.wait_with_output().expect("cmdtrail should finish");
    assert!(
        output.status.success(),
        "interrupted record failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = read_json(&receipt);
    assert_eq!(parsed["command"]["outcome"]["state"], "interrupted");
    assert_eq!(parsed["summary"]["snapshot_truncated"], true);
    assert_eq!(parsed["summary"]["observation_complete"], false);
}

#[test]
fn limits_are_declared_and_dropped_events_are_counted() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("limited.receipt.json");
    let output = run_record(&root, &receipt, "many", &["--max-events", "3"]);
    assert!(output.status.success());
    let parsed = read_json(&receipt);
    assert_eq!(parsed["events"].as_array().map(Vec::len), Some(3));
    assert_eq!(parsed["summary"]["retained_file_effects"], 1);
    assert_eq!(parsed["summary"]["dropped_file_effects"], 4);
    assert_eq!(parsed["summary"]["observation_complete"], false);

    let truncated_receipt = directory.path.join("truncated.receipt.json");
    let truncated = run_record(&root, &truncated_receipt, "noop", &["--max-entries", "1"]);
    assert!(truncated.status.success());
    let truncated_json = read_json(&truncated_receipt);
    assert_eq!(truncated_json["summary"]["snapshot_truncated"], true);
    assert_eq!(
        truncated_json["roots"][0]["before"]["omitted_count_known"],
        false
    );
}

#[test]
fn tampering_unknown_fields_and_overwrites_fail_closed() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("original.receipt.json");
    assert!(run_record(&root, &receipt, "noop", &[]).status.success());

    let overwrite = run_record(&root, &receipt, "noop", &[]);
    assert_eq!(overwrite.status.code(), Some(1));
    let overwrite_error: Value =
        serde_json::from_slice(&overwrite.stderr).expect("runtime error should be JSON");
    assert_eq!(overwrite_error["code"], "output_already_exists");

    let mut tampered = read_json(&receipt);
    tampered["summary"]["command_success"] = Value::Bool(false);
    let tampered_path = directory.path.join("tampered.receipt.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec(&tampered).expect("JSON should encode"),
    )
    .expect("tampered receipt should write");
    let verify_tampered = Command::new(cmdtrail())
        .arg("verify")
        .arg(&tampered_path)
        .output()
        .expect("verify should run");
    assert_eq!(verify_tampered.status.code(), Some(3));
    let tamper_report: Value =
        serde_json::from_slice(&verify_tampered.stdout).expect("report should be JSON");
    assert_eq!(tamper_report["integrity_valid"], false);
    assert_eq!(tamper_report["receipt_digest_valid"], false);

    let mut unknown = read_json(&receipt);
    unknown["unexpected"] = Value::Bool(true);
    let unknown_path = directory.path.join("unknown.receipt.json");
    fs::write(
        &unknown_path,
        serde_json::to_vec(&unknown).expect("JSON should encode"),
    )
    .expect("unknown-field receipt should write");
    let verify_unknown = Command::new(cmdtrail())
        .arg("verify")
        .arg(&unknown_path)
        .output()
        .expect("verify should run");
    assert_eq!(verify_unknown.status.code(), Some(1));
    let unknown_error: Value =
        serde_json::from_slice(&verify_unknown.stderr).expect("error should be JSON");
    assert_eq!(unknown_error["code"], "receipt_parse_failed");

    let mut nested_unknown = read_json(&receipt);
    nested_unknown["events"][0]["details"]["unexpected"] = Value::Bool(true);
    let nested_unknown_path = directory.path.join("nested-unknown.receipt.json");
    fs::write(
        &nested_unknown_path,
        serde_json::to_vec(&nested_unknown).expect("JSON should encode"),
    )
    .expect("nested unknown-field receipt should write");
    let verify_nested_unknown = Command::new(cmdtrail())
        .arg("verify")
        .arg(&nested_unknown_path)
        .output()
        .expect("verify should run");
    assert_eq!(verify_nested_unknown.status.code(), Some(1));
    let nested_error: Value =
        serde_json::from_slice(&verify_nested_unknown.stderr).expect("error should be JSON");
    assert_eq!(nested_error["code"], "receipt_parse_failed");
}

#[test]
fn unavailable_receipt_parent_is_rejected_before_command_execution() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = directory.path.join("missing").join("receipt.json");

    let output = run_record(&root, &receipt, "second", &[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        !root.join("second.txt").exists(),
        "preflight failure must prevent command side effects"
    );
    assert!(!receipt.exists());
    let error: Value = String::from_utf8_lossy(&output.stderr)
        .lines()
        .last()
        .map(serde_json::from_str)
        .expect("runtime error line")
        .expect("runtime error should be JSON");
    assert_eq!(error["code"], "output_parent_unavailable");
    assert!(error.get("recovery").is_none());
}

#[test]
fn relative_receipt_filename_uses_the_process_working_directory() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let relative_receipt = Path::new("relative.receipt.json");
    let mut command = record_command(&root, relative_receipt, "noop", &[]);
    command.current_dir(&directory.path);

    let output = command.output().expect("cmdtrail record should run");

    assert!(
        output.status.success(),
        "record failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = directory.path.join(relative_receipt);
    let recovered = read_receipt(&receipt).expect("strict relative receipt");
    assert!(verify_receipt(&recovered).integrity_valid);
}

#[test]
fn post_command_receipt_race_persists_recovery_and_forbids_retry() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let receipt = root.join("receipt.json");

    let output = run_record(&root, &receipt, "occupy_receipt", &[]);

    assert_eq!(output.status.code(), Some(6));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read(&receipt).expect("occupied path should remain"),
        b"occupied-by-command"
    );
    assert!(root.join("side-effect.txt").is_file());
    let error: Value = String::from_utf8_lossy(&output.stderr)
        .lines()
        .last()
        .map(serde_json::from_str)
        .expect("runtime error line")
        .expect("runtime error should be JSON");
    assert_eq!(error["code"], "receipt_recovery_required");
    assert_eq!(error["exit_code"], 6);
    assert_eq!(error["recovery"]["action"], "do_not_retry_record");
    assert_eq!(error["recovery"]["command_state"], "exited");
    assert_eq!(
        error["recovery"]["primary_error_code"],
        "output_already_exists"
    );
    assert_eq!(error["recovery"]["recovery_receipt_persisted"], true);
    assert_eq!(
        error["recovery"]["receipt_sha256"].as_str().map(str::len),
        Some(64)
    );
    let recovery_path = PathBuf::from(
        error["recovery"]["recovery_receipt"]
            .as_str()
            .expect("recovery receipt path"),
    );
    let recovered = read_receipt(&recovery_path).expect("strict recovery receipt");
    assert!(verify_receipt(&recovered).integrity_valid);
    assert_eq!(
        error["recovery"]["receipt_id"],
        recovered.receipt_id.as_str()
    );
    assert_eq!(
        error["recovery"]["receipt_sha256"],
        recovered.receipt_sha256.as_str()
    );
}

#[test]
fn diff_compares_only_verified_receipts() {
    let directory = TestDirectory::new();
    let root = directory.path.join("root");
    fs::create_dir(&root).expect("root should be created");
    let before = directory.path.join("before.receipt.json");
    let after = directory.path.join("after.receipt.json");
    assert!(run_record(&root, &before, "many", &[]).status.success());
    assert!(run_record(&root, &after, "second", &[]).status.success());

    let diff = Command::new(cmdtrail())
        .arg("diff")
        .arg(&before)
        .arg(&after)
        .args(["--format", "json"])
        .output()
        .expect("diff should run");
    assert!(diff.status.success());
    let report: Value = serde_json::from_slice(&diff.stdout).expect("diff should return JSON");
    assert_eq!(report["schema_version"], "cmdtrail.diff.v1");
    assert!(report["added_effects"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(report["removed_effects"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
fn diff_keys_are_portable_across_equivalent_root_positions() {
    let directory = TestDirectory::new();
    let first_root = directory.path.join("first-root");
    let second_root = directory.path.join("second-root");
    fs::create_dir(&first_root).expect("first root should be created");
    fs::create_dir(&second_root).expect("second root should be created");
    let first_receipt = directory.path.join("first.receipt.json");
    let second_receipt = directory.path.join("second.receipt.json");
    assert!(run_record(&first_root, &first_receipt, "many", &[])
        .status
        .success());
    assert!(run_record(&second_root, &second_receipt, "many", &[])
        .status
        .success());

    let diff = Command::new(cmdtrail())
        .arg("diff")
        .arg(&first_receipt)
        .arg(&second_receipt)
        .output()
        .expect("diff should run");
    assert!(diff.status.success());
    let report: Value = serde_json::from_slice(&diff.stdout).expect("diff should return JSON");
    assert_eq!(report["added_effects"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["removed_effects"].as_array().map(Vec::len), Some(0));
    assert!(report["changed_effects"].as_array().is_some());
}

fn run_record(root: &Path, receipt: &Path, mode: &str, extra: &[&str]) -> Output {
    record_command(root, receipt, mode, extra)
        .output()
        .expect("cmdtrail record should run")
}

fn record_command(root: &Path, receipt: &Path, mode: &str, extra: &[&str]) -> Command {
    let mut command = Command::new(cmdtrail());
    command
        .arg("record")
        .arg("--out")
        .arg(receipt)
        .arg("--cwd")
        .arg(root)
        .arg("--root")
        .arg(".")
        .args(extra)
        .arg("--redact-env")
        .arg("TEST_REDACT_VALUE")
        .arg("--")
        .arg(std::env::current_exe().expect("test executable should resolve"))
        .args(["--exact", "fixture_child", "--nocapture"])
        .env("CMDTRAIL_FIXTURE_MODE", mode)
        .env("TEST_REDACT_VALUE", "literal-secret");
    command
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("JSON file should read"))
        .expect("JSON file should parse")
}

fn cmdtrail() -> &'static str {
    env!("CARGO_BIN_EXE_cmdtrail")
}
