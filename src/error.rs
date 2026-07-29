use crate::model::CommandState;
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Io = 1,
    Usage = 2,
    Integrity = 3,
    Limit = 4,
    Execution = 5,
    PostExecutionReceipt = 6,
}

#[derive(Debug)]
pub struct AppError {
    pub class: ExitClass,
    pub code: &'static str,
    pub message: String,
    pub recovery: Option<Box<ReceiptRecovery>>,
}

impl AppError {
    pub fn new(class: ExitClass, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            code,
            message: message.into(),
            recovery: None,
        }
    }

    pub fn io(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Io, code, message)
    }

    pub fn usage(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Usage, code, message)
    }

    pub fn limit(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Limit, code, message)
    }

    pub fn execution(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(ExitClass::Execution, code, message)
    }

    pub fn post_execution_receipt(
        code: &'static str,
        message: impl Into<String>,
        recovery: ReceiptRecovery,
    ) -> Self {
        let mut error = Self::new(ExitClass::PostExecutionReceipt, code, message);
        error.recovery = Some(Box::new(recovery));
        error
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for AppError {}

#[derive(Debug, Serialize)]
pub struct ErrorDocument<'a> {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub code: &'a str,
    pub message: &'a str,
    pub exit_code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<&'a ReceiptRecovery>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    DoNotRetryRecord,
}

#[derive(Debug, Serialize)]
pub struct ReceiptRecovery {
    pub action: RecoveryAction,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub command_state: CommandState,
    pub requested_receipt: String,
    pub recovery_receipt: String,
    pub recovery_receipt_persisted: bool,
    pub primary_error_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_error_code: Option<&'static str>,
}

impl<'a> From<&'a AppError> for ErrorDocument<'a> {
    fn from(error: &'a AppError) -> Self {
        Self {
            schema_version: "cmdtrail.error.v1",
            tool_version: crate::VERSION,
            code: error.code,
            message: &error.message,
            exit_code: error.class as u8,
            recovery: error.recovery.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_execution_receipt_errors_are_machine_actionable() {
        let error = AppError::post_execution_receipt(
            "receipt_recovery_required",
            "the command was attempted; do not retry record",
            ReceiptRecovery {
                action: RecoveryAction::DoNotRetryRecord,
                receipt_id: "ct_0123456789abcdef01234567".to_owned(),
                receipt_sha256: "a".repeat(64),
                command_state: CommandState::Exited,
                requested_receipt: "receipt.json".to_owned(),
                recovery_receipt: ".cmdtrail-recovery-ct_test.json".to_owned(),
                recovery_receipt_persisted: true,
                primary_error_code: "output_already_exists",
                recovery_error_code: None,
            },
        );

        let document =
            serde_json::to_value(ErrorDocument::from(&error)).expect("serialize error document");
        assert_eq!(document["exit_code"], 6);
        assert_eq!(document["code"], "receipt_recovery_required");
        assert_eq!(
            document["recovery"]["action"],
            serde_json::json!("do_not_retry_record")
        );
        assert_eq!(document["recovery"]["command_state"], "exited");
        assert_eq!(document["recovery"]["recovery_receipt_persisted"], true);
    }
}
