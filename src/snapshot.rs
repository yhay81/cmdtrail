use crate::error::AppError;
use crate::integrity::{hex_lower, sha256_bytes};
use crate::model::{
    ContentHashState, EntryKind, EntryState, FileEffect, FileEffectKind, RootRecord, SnapshotStats,
};
use crate::redact::{append_length_delimited, os_bytes, Redactor};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    pub max_entries: u64,
    pub max_file_hash_bytes: u64,
    pub max_total_hash_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedRoot {
    pub root_id: String,
    pub path_handle: String,
    pub display_name: String,
    pub canonical_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub root_id: String,
    pub path_handle: String,
    pub display_path: String,
    pub state: EntryState,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub entries: BTreeMap<String, SnapshotEntry>,
    pub stats: BTreeMap<String, SnapshotStats>,
    pub redacted_path_components: u64,
    pub sensitive_file_hashes_skipped: u64,
}

/// Resolves, validates, de-duplicates, and privacy-labels observation roots.
///
/// # Errors
///
/// Returns an error when a root is missing, inaccessible, not a directory, or overlaps another
/// requested root.
pub fn prepare_roots(
    working_directory: &Path,
    requested_roots: &[PathBuf],
    redactor: &Redactor,
) -> Result<Vec<PreparedRoot>, AppError> {
    let candidates = if requested_roots.is_empty() {
        vec![working_directory.to_path_buf()]
    } else {
        requested_roots
            .iter()
            .map(|root| {
                if root.is_absolute() {
                    root.clone()
                } else {
                    working_directory.join(root)
                }
            })
            .collect()
    };

    let mut canonical = Vec::new();
    for candidate in candidates {
        let path = fs::canonicalize(&candidate).map_err(|_| {
            AppError::usage(
                "observation_root_unavailable",
                "an observation root does not exist or cannot be resolved",
            )
        })?;
        let metadata = fs::metadata(&path).map_err(|_| {
            AppError::usage(
                "observation_root_unavailable",
                "an observation root cannot be inspected",
            )
        })?;
        if !metadata.is_dir() {
            return Err(AppError::usage(
                "observation_root_not_directory",
                "every observation root must be a directory",
            ));
        }
        canonical.push(path);
    }
    for (index, first) in canonical.iter().enumerate() {
        for second in canonical.iter().skip(index + 1) {
            if second == first {
                return Err(AppError::usage(
                    "duplicate_observation_roots",
                    "observation roots must be unique",
                ));
            }
            if second.starts_with(first) || first.starts_with(second) {
                return Err(AppError::usage(
                    "overlapping_observation_roots",
                    "observation roots must not overlap",
                ));
            }
        }
    }

    let roots = canonical
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            let path_bytes = os_bytes(path.as_os_str());
            let digest = sha256_bytes(&path_bytes);
            let display_source = path.file_name().unwrap_or_else(|| path.as_os_str());
            let (display_name, _) = redactor.path_display(Path::new(display_source));
            PreparedRoot {
                root_id: format!("root_{index:04}"),
                path_handle: format!("path_{digest}"),
                display_name,
                canonical_path: path,
            }
        })
        .collect::<Vec<_>>();
    Ok(roots)
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn capture(roots: &[PreparedRoot], config: &SnapshotConfig, redactor: &Redactor) -> Snapshot {
    capture_internal(roots, config, redactor, None)
}

pub(crate) fn capture_cancellable(
    roots: &[PreparedRoot],
    config: &SnapshotConfig,
    redactor: &Redactor,
    interrupted: &AtomicBool,
) -> Snapshot {
    capture_internal(roots, config, redactor, Some(interrupted))
}

#[allow(clippy::too_many_lines)]
fn capture_internal(
    roots: &[PreparedRoot],
    config: &SnapshotConfig,
    redactor: &Redactor,
    interrupted: Option<&AtomicBool>,
) -> Snapshot {
    let mut entries = BTreeMap::new();
    let mut stats = roots
        .iter()
        .map(|root| (root.root_id.clone(), SnapshotStats::default()))
        .collect::<BTreeMap<_, _>>();
    let mut retained_total = 0_u64;
    let mut hashed_bytes_total = 0_u64;
    let mut redacted_path_components = 0_u64;
    let mut sensitive_file_hashes_skipped = 0_u64;
    let mut global_truncated = false;

    for root in roots {
        if global_truncated || interrupted.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            if let Some(root_stats) = stats.get_mut(&root.root_id) {
                root_stats.truncated = true;
                root_stats.omitted_count_known = false;
            }
            continue;
        }

        for result in WalkDir::new(&root.canonical_path)
            .follow_links(false)
            .min_depth(1)
            .max_open(16)
            .sort_by_file_name()
        {
            let Some(root_stats) = stats.get_mut(&root.root_id) else {
                continue;
            };
            if interrupted.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
                root_stats.truncated = true;
                root_stats.omitted_count_known = false;
                global_truncated = true;
                break;
            }
            root_stats.scanned_entries = root_stats.scanned_entries.saturating_add(1);
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    record_walk_error(root_stats, &error);
                    continue;
                }
            };

            if retained_total >= config.max_entries {
                root_stats.truncated = true;
                root_stats.omitted_count_known = false;
                global_truncated = true;
                break;
            }

            let Ok(relative) = entry.path().strip_prefix(&root.canonical_path) else {
                root_stats.traversal_errors = root_stats.traversal_errors.saturating_add(1);
                *root_stats
                    .error_classes
                    .entry("path_escape".to_owned())
                    .or_default() += 1;
                continue;
            };
            let relative_bytes = os_bytes(relative.as_os_str());
            let mut path_material = Vec::new();
            append_length_delimited(&mut path_material, root.root_id.as_bytes());
            append_length_delimited(&mut path_material, &relative_bytes);
            let path_digest = sha256_bytes(&path_material);
            let path_handle = format!("path_{path_digest}");
            let (display_path, redacted_count) = redactor.path_display(relative);
            redacted_path_components = redacted_path_components.saturating_add(redacted_count);
            let sensitive_path = redactor.path_is_sensitive(relative);

            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    record_io_error(root_stats, &error);
                    continue;
                }
            };
            let captured_state = entry_state(
                entry.path(),
                &metadata,
                sensitive_path,
                config,
                &mut hashed_bytes_total,
            );
            if captured_state.content_hash_state == ContentHashState::SkippedSensitivePath {
                sensitive_file_hashes_skipped = sensitive_file_hashes_skipped.saturating_add(1);
            }
            if captured_state.content_hash_state == ContentHashState::Hashed {
                root_stats.hashed_files = root_stats.hashed_files.saturating_add(1);
                root_stats.hashed_bytes = root_stats.hashed_bytes.saturating_add(metadata.len());
            } else if captured_state.kind == EntryKind::File {
                root_stats.skipped_hashes = root_stats.skipped_hashes.saturating_add(1);
            }

            entries.insert(
                path_handle.clone(),
                SnapshotEntry {
                    root_id: root.root_id.clone(),
                    path_handle,
                    display_path,
                    state: captured_state,
                },
            );
            retained_total = retained_total.saturating_add(1);
            root_stats.retained_entries = root_stats.retained_entries.saturating_add(1);
        }
    }

    Snapshot {
        entries,
        stats,
        redacted_path_components,
        sensitive_file_hashes_skipped,
    }
}

#[must_use]
pub fn compare(before: &Snapshot, after: &Snapshot) -> Vec<FileEffect> {
    let keys = before
        .entries
        .keys()
        .chain(after.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut effects = Vec::new();
    for key in keys {
        let before_entry = before.entries.get(&key);
        let after_entry = after.entries.get(&key);
        let (effect, root_id, display_path) = match (before_entry, after_entry) {
            (None, Some(after_entry)) => (
                FileEffectKind::Created,
                after_entry.root_id.clone(),
                after_entry.display_path.clone(),
            ),
            (Some(before_entry), None) => (
                FileEffectKind::Deleted,
                before_entry.root_id.clone(),
                before_entry.display_path.clone(),
            ),
            (Some(before_entry), Some(after_entry))
                if before_entry.state.kind != after_entry.state.kind =>
            {
                (
                    FileEffectKind::TypeChanged,
                    after_entry.root_id.clone(),
                    after_entry.display_path.clone(),
                )
            }
            (Some(before_entry), Some(after_entry)) if before_entry.state != after_entry.state => (
                FileEffectKind::Modified,
                after_entry.root_id.clone(),
                after_entry.display_path.clone(),
            ),
            _ => continue,
        };
        effects.push(FileEffect {
            root_id,
            path_handle: key,
            display_path,
            effect,
            before: before_entry.map(|entry| entry.state.clone()),
            after: after_entry.map(|entry| entry.state.clone()),
        });
    }
    effects
}

#[must_use]
pub fn root_records(
    roots: &[PreparedRoot],
    before: &Snapshot,
    after: &Snapshot,
) -> Vec<RootRecord> {
    roots
        .iter()
        .map(|root| RootRecord {
            root_id: root.root_id.clone(),
            path_handle: root.path_handle.clone(),
            display_name: root.display_name.clone(),
            before: before.stats.get(&root.root_id).cloned().unwrap_or_default(),
            after: after.stats.get(&root.root_id).cloned().unwrap_or_default(),
        })
        .collect()
}

fn entry_state(
    path: &Path,
    metadata: &Metadata,
    sensitive_path: bool,
    config: &SnapshotConfig,
    hashed_bytes_total: &mut u64,
) -> EntryState {
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::Other
    };
    let size_bytes = (kind == EntryKind::File).then(|| metadata.len().to_string());
    let modified_at_unix_ns = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos().to_string());
    #[cfg(unix)]
    let unix_mode = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.mode())
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    let symlink_target_sha256 = if kind == EntryKind::Symlink {
        fs::read_link(path)
            .ok()
            .map(|target| sha256_bytes(&os_bytes(target.as_os_str())))
    } else {
        None
    };

    let (content_sha256, content_hash_state) = if kind != EntryKind::File {
        (None, ContentHashState::NotRegularFile)
    } else if sensitive_path {
        (None, ContentHashState::SkippedSensitivePath)
    } else if config.max_file_hash_bytes == 0 || metadata.len() > config.max_file_hash_bytes {
        (None, ContentHashState::SkippedFileTooLarge)
    } else if config.max_total_hash_bytes == 0
        || hashed_bytes_total.saturating_add(metadata.len()) > config.max_total_hash_bytes
    {
        (None, ContentHashState::SkippedTotalBudget)
    } else {
        match hash_regular_file(path, metadata.len(), config.max_file_hash_bytes) {
            Ok((digest, bytes)) if bytes == metadata.len() => {
                *hashed_bytes_total = hashed_bytes_total.saturating_add(bytes);
                (Some(digest), ContentHashState::Hashed)
            }
            Ok(_) => (None, ContentHashState::ChangedDuringRead),
            Err(_) => (None, ContentHashState::ReadError),
        }
    };

    EntryState {
        kind,
        size_bytes,
        modified_at_unix_ns,
        readonly: metadata.permissions().readonly(),
        unix_mode,
        content_sha256,
        content_hash_state,
        symlink_target_sha256,
    }
}

fn hash_regular_file(
    path: &Path,
    expected_size: u64,
    maximum: u64,
) -> std::io::Result<(String, u64)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file).take(maximum.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
    let mut read_total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_total = read_total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if read_total > maximum {
            return Ok((String::new(), read_total));
        }
        hasher.update(&buffer[..read]);
    }
    if read_total != expected_size {
        return Ok((String::new(), read_total));
    }
    let digest = hasher.finalize();
    Ok((hex_lower(&digest[..]), read_total))
}

fn record_walk_error(stats: &mut SnapshotStats, error: &walkdir::Error) {
    stats.traversal_errors = stats.traversal_errors.saturating_add(1);
    let class = if error.loop_ancestor().is_some() {
        "symlink_loop".to_owned()
    } else if let Some(io_error) = error.io_error() {
        format!("io_{:?}", io_error.kind()).to_ascii_lowercase()
    } else {
        "walk_error".to_owned()
    };
    *stats.error_classes.entry(class).or_default() += 1;
}

fn record_io_error(stats: &mut SnapshotStats, error: &std::io::Error) {
    stats.traversal_errors = stats.traversal_errors.saturating_add(1);
    let class = format!("io_{:?}", error.kind()).to_ascii_lowercase();
    *stats.error_classes.entry(class).or_default() += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "cmdtrail-snapshot-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("test directory should be created");
        directory
    }

    #[test]
    fn detects_create_modify_and_delete() {
        let directory = test_directory("effects");
        let deleted = directory.join("deleted.txt");
        let modified = directory.join("modified.txt");
        fs::write(&deleted, b"delete").expect("fixture should write");
        fs::write(&modified, b"before").expect("fixture should write");
        let redactor = Redactor::from_environment_names(&[]).expect("empty config is valid");
        let roots = prepare_roots(&directory, &[], &redactor).expect("root should prepare");
        let config = SnapshotConfig {
            max_entries: 100,
            max_file_hash_bytes: 1024,
            max_total_hash_bytes: 4096,
        };
        let before = capture(&roots, &config, &redactor);
        fs::remove_file(deleted).expect("fixture should delete");
        fs::write(&modified, b"after!").expect("fixture should update");
        fs::write(directory.join("created.txt"), b"create").expect("fixture should create");
        let after = capture(&roots, &config, &redactor);
        let effects = compare(&before, &after);
        assert_eq!(effects.len(), 3);
        let kinds = effects
            .iter()
            .map(|effect| effect.effect.clone())
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&FileEffectKind::Created));
        assert!(kinds.contains(&FileEffectKind::Modified));
        assert!(kinds.contains(&FileEffectKind::Deleted));
        fs::remove_dir_all(directory).expect("fixture should clean up");
    }

    #[test]
    fn skips_hashing_sensitive_files() {
        let directory = test_directory("redaction");
        fs::write(directory.join(".env"), b"SECRET=value").expect("fixture should write");
        let redactor = Redactor::from_environment_names(&[]).expect("empty config is valid");
        let roots = prepare_roots(&directory, &[], &redactor).expect("root should prepare");
        let snapshot = capture(
            &roots,
            &SnapshotConfig {
                max_entries: 10,
                max_file_hash_bytes: 1024,
                max_total_hash_bytes: 1024,
            },
            &redactor,
        );
        let entry = snapshot
            .entries
            .values()
            .next()
            .expect("entry should exist");
        assert_eq!(
            entry.state.content_hash_state,
            ContentHashState::SkippedSensitivePath
        );
        assert!(!entry.display_path.contains(".env"));
        fs::remove_dir_all(directory).expect("fixture should clean up");
    }

    #[test]
    fn zero_hash_limits_are_metadata_only_even_for_empty_files() {
        let directory = test_directory("metadata-only");
        fs::write(directory.join("empty.txt"), b"").expect("fixture should write");
        let redactor = Redactor::from_environment_names(&[]).expect("empty config is valid");
        let roots = prepare_roots(&directory, &[], &redactor).expect("root should prepare");
        let snapshot = capture(
            &roots,
            &SnapshotConfig {
                max_entries: 10,
                max_file_hash_bytes: 0,
                max_total_hash_bytes: 0,
            },
            &redactor,
        );
        let entry = snapshot
            .entries
            .values()
            .next()
            .expect("entry should exist");
        assert_eq!(
            entry.state.content_hash_state,
            ContentHashState::SkippedFileTooLarge
        );
        assert_eq!(entry.state.content_sha256, None);
        fs::remove_dir_all(directory).expect("fixture should clean up");
    }
}
