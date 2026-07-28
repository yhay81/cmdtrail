use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use cmdtrail::capability::{capabilities_document, contract_document, schema_document};
use cmdtrail::diff::diff_receipts;
use cmdtrail::error::{AppError, ErrorDocument, ExitClass};
use cmdtrail::integrity::verify_receipt;
use cmdtrail::model::ShowResult;
use cmdtrail::receipt::read_receipt;
use cmdtrail::record::{record, RecordOptions};
use serde::Serialize;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "cmdtrail",
    version,
    about = "Bounded, capability-declared receipts for observable command side effects",
    long_about = "CmdTrail runs a direct command and records an integrity-protected receipt of the command outcome and persistent filesystem deltas visible to its declared portable snapshot backend. It never claims process-tree or network coverage that it does not provide."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a direct command and create a new, non-overwriting receipt
    Record(RecordArgs),
    /// Read a verified receipt
    Show(ShowArgs),
    /// Compare the effects in two verified receipts
    Diff(DiffArgs),
    /// Verify receipt, event-array, and event-chain integrity
    Verify(VerifyArgs),
    /// Print the stable receipt and event schema contract
    Schema(SchemaArgs),
    /// Report current backend coverage and blind spots
    Capabilities(FormatArgs),
    /// Print the machine-facing CLI contract
    Contract(FormatArgs),
    /// Generate a shell completion script
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Args)]
struct RecordArgs {
    /// New receipt path. Existing paths are never overwritten.
    #[arg(long, value_name = "NEW_FILE")]
    out: PathBuf,

    /// Working directory for the direct child and relative observation roots.
    #[arg(long, value_name = "DIRECTORY")]
    cwd: Option<PathBuf>,

    /// Directory to snapshot before and after the command. Repeatable; defaults to the working directory.
    #[arg(long, value_name = "DIRECTORY")]
    root: Vec<PathBuf>,

    /// Maximum retained entries across each pre/post snapshot.
    #[arg(long, default_value_t = 100_000)]
    max_entries: u64,

    /// Maximum retained events, including two direct-command lifecycle events.
    #[arg(long, default_value_t = 20_000)]
    max_events: u64,

    /// Maximum regular-file bytes hashed for one file.
    #[arg(long, default_value_t = 1_048_576)]
    max_file_hash_bytes: u64,

    /// Maximum regular-file bytes hashed across one snapshot.
    #[arg(long, default_value_t = 67_108_864)]
    max_total_hash_bytes: u64,

    /// Direct-child timeout with an explicit unit, for example 500ms, 30s, 5m, or 1h.
    #[arg(long, value_parser = parse_duration_ms)]
    timeout: Option<u64>,

    /// Load one exact secret value from this environment variable for display redaction. Repeatable.
    #[arg(long, value_name = "ENV_NAME")]
    redact_env: Vec<String>,

    /// Direct executable and arguments. A literal -- separator is mandatory; no shell is implied.
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct ShowArgs {
    #[arg(value_name = "RECEIPT")]
    receipt: PathBuf,
    /// Return the compact verified summary instead of the complete receipt.
    #[arg(long)]
    summary: bool,
    #[command(flatten)]
    format: FormatArgs,
}

#[derive(Debug, Args)]
struct DiffArgs {
    #[arg(value_name = "BEFORE_RECEIPT")]
    before: PathBuf,
    #[arg(value_name = "AFTER_RECEIPT")]
    after: PathBuf,
    #[command(flatten)]
    format: FormatArgs,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(value_name = "RECEIPT")]
    receipt: PathBuf,
    #[command(flatten)]
    format: FormatArgs,
}

#[derive(Debug, Args)]
struct SchemaArgs {
    /// Omit the top-level field descriptions.
    #[arg(long)]
    brief: bool,
    #[command(flatten)]
    format: FormatArgs,
}

#[derive(Debug, Clone, Copy, Args)]
struct FormatArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let document = ErrorDocument::from(&error);
            let _ = write_json(io::stderr(), &document);
            ExitCode::from(error.class as u8)
        }
    }
}

fn execute(cli: Cli) -> Result<u8, AppError> {
    match cli.command {
        Commands::Record(args) => {
            let options = RecordOptions {
                output: args.out,
                working_directory: args.cwd,
                roots: args.root,
                max_entries: args.max_entries,
                max_events: args.max_events,
                max_file_hash_bytes: args.max_file_hash_bytes,
                max_total_hash_bytes: args.max_total_hash_bytes,
                timeout_ms: args.timeout,
                redact_environment_names: args.redact_env,
                command: args.command,
            };
            let result = record(&options)?;
            print_json(&result)?;
            Ok(0)
        }
        Commands::Show(args) => {
            ensure_json(args.format);
            let receipt = read_receipt(&args.receipt)?;
            let verification = verify_receipt(&receipt);
            if !verification.integrity_valid {
                print_json(&verification)?;
                return Ok(ExitClass::Integrity as u8);
            }
            if args.summary {
                print_json(&ShowResult {
                    schema_version: "cmdtrail.show.v1",
                    tool_version: cmdtrail::VERSION,
                    receipt_id: receipt.receipt_id,
                    integrity_valid: true,
                    command: receipt.command,
                    observation: receipt.observation,
                    capabilities: receipt.capabilities,
                    summary: receipt.summary,
                    roots: receipt.roots,
                })?;
            } else {
                print_json(&receipt)?;
            }
            Ok(0)
        }
        Commands::Diff(args) => {
            ensure_json(args.format);
            let before = read_receipt(&args.before)?;
            let after = read_receipt(&args.after)?;
            print_json(&diff_receipts(&before, &after)?)?;
            Ok(0)
        }
        Commands::Verify(args) => {
            ensure_json(args.format);
            let receipt = read_receipt(&args.receipt)?;
            let report = verify_receipt(&receipt);
            let code = if report.integrity_valid {
                0
            } else {
                ExitClass::Integrity as u8
            };
            print_json(&report)?;
            Ok(code)
        }
        Commands::Schema(args) => {
            ensure_json(args.format);
            print_json(&schema_document(args.brief))?;
            Ok(0)
        }
        Commands::Capabilities(format) => {
            ensure_json(format);
            print_json(&capabilities_document())?;
            Ok(0)
        }
        Commands::Contract(format) => {
            ensure_json(format);
            print_json(&contract_document())?;
            Ok(0)
        }
        Commands::Completions { shell } => {
            let mut command = Cli::command();
            generate(shell, &mut command, "cmdtrail", &mut io::stdout());
            Ok(0)
        }
    }
}

fn ensure_json(format: FormatArgs) {
    match format.format {
        OutputFormat::Json => {}
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), AppError> {
    write_json(io::stdout(), value).map_err(|_| {
        AppError::io(
            "stdout_write_failed",
            "could not write the JSON result to standard output",
        )
    })
}

fn write_json<T: Serialize, W: Write>(mut output: W, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")
}

fn parse_duration_ms(value: &str) -> Result<u64, String> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        return Err("duration requires one of the units ms, s, m, or h".to_owned());
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| "duration must use a positive integer".to_owned())?;
    amount
        .checked_mul(multiplier)
        .filter(|milliseconds| *milliseconds > 0 && *milliseconds <= 86_400_000)
        .ok_or_else(|| "duration must be between 1 ms and 24 hours".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_is_bounded_and_requires_units() {
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        assert_eq!(parse_duration_ms("2m"), Ok(120_000));
        assert!(parse_duration_ms("30").is_err());
        assert!(parse_duration_ms("25h").is_err());
        assert!(parse_duration_ms("0s").is_err());
    }

    #[test]
    fn record_requires_separator() {
        assert!(Cli::try_parse_from([
            "cmdtrail",
            "record",
            "--out",
            "receipt.json",
            "echo",
            "hello"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "cmdtrail",
            "record",
            "--out",
            "receipt.json",
            "--",
            "echo",
            "hello"
        ])
        .is_ok());
    }
}
