pub mod capability;
pub mod diff;
pub mod error;
pub mod integrity;
pub mod model;
pub mod receipt;
pub mod record;
pub mod redact;
pub mod snapshot;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RECEIPT_SCHEMA: &str = "cmdtrail.receipt.v1";
pub const MAX_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
