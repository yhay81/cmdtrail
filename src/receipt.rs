use crate::error::AppError;
use crate::model::Receipt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Parses one bounded receipt document without performing file I/O.
///
/// # Errors
///
/// Returns an error when the input exceeds the receipt limit or is not valid
/// strict `CmdTrail` JSON.
pub fn parse_receipt_document(bytes: &[u8]) -> Result<Receipt, AppError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > crate::MAX_RECEIPT_BYTES {
        return Err(AppError::limit(
            "receipt_too_large",
            "the receipt exceeds the 64 MiB input limit",
        ));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        AppError::io(
            "receipt_parse_failed",
            "the receipt is not valid strict CmdTrail JSON",
        )
    })
}

/// Reads one strict receipt without following data beyond the configured size bound.
///
/// # Errors
///
/// Returns an error for inaccessible, oversized, non-regular, or invalid receipt input.
pub fn read_receipt(path: &Path) -> Result<Receipt, AppError> {
    let metadata = fs::metadata(path)
        .map_err(|_| AppError::io("receipt_open_failed", "could not open the receipt"))?;
    if !metadata.is_file() {
        return Err(AppError::io(
            "receipt_not_regular_file",
            "the receipt path is not a regular file",
        ));
    }
    if metadata.len() > crate::MAX_RECEIPT_BYTES {
        return Err(AppError::limit(
            "receipt_too_large",
            "the receipt exceeds the 64 MiB input limit",
        ));
    }

    let file = File::open(path)
        .map_err(|_| AppError::io("receipt_open_failed", "could not open the receipt"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(crate::MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::io("receipt_read_failed", "could not read the receipt"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > crate::MAX_RECEIPT_BYTES {
        return Err(AppError::limit(
            "receipt_too_large",
            "the receipt exceeds the 64 MiB input limit",
        ));
    }
    parse_receipt_document(&bytes)
}

/// Writes a receipt to a newly created private file and never overwrites a path.
///
/// # Errors
///
/// Returns an error when the parent or target is unsafe, serialization fails, or durable
/// writing fails.
pub fn write_new_receipt(path: &Path, receipt: &Receipt) -> Result<(), AppError> {
    if path.file_name().is_none() {
        return Err(AppError::usage(
            "invalid_output_path",
            "the output path must include a file name",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::metadata(parent).map_err(|_| {
        AppError::io(
            "output_parent_unavailable",
            "the receipt output directory does not exist or is inaccessible",
        )
    })?;
    if !parent_metadata.is_dir() {
        return Err(AppError::io(
            "output_parent_not_directory",
            "the receipt output parent is not a directory",
        ));
    }

    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|_| {
        AppError::io(
            "receipt_serialization_failed",
            "could not serialize the receipt",
        )
    })?;
    bytes.push(b'\n');

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::io(
                "output_already_exists",
                "the receipt output path already exists; CmdTrail never overwrites receipts",
            )
        } else {
            AppError::io(
                "output_create_failed",
                "could not create the receipt output",
            )
        }
    })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| AppError::io("output_write_failed", "could not durably write the receipt"))
}
