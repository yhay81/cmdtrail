use crate::integrity::sha256_bytes;
use std::ffi::{OsStr, OsString};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Redactor {
    custom_values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RedactedCommand {
    pub executable_display: String,
    pub executable_sha256: String,
    pub argument_displays: Vec<String>,
    pub argument_sha256: Vec<Option<String>>,
    pub command_sha256: String,
    pub redacted_arguments: u64,
}

impl Redactor {
    /// Loads exact display-redaction values from named environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when a name is empty, missing, non-Unicode, or resolves to an empty value.
    pub fn from_environment_names(names: &[String]) -> Result<Self, String> {
        let mut custom_values = Vec::new();
        for name in names {
            if name.is_empty() {
                return Err("a redaction environment variable name cannot be empty".to_owned());
            }
            let value = std::env::var(name).map_err(|_| {
                "a requested redaction environment variable is unavailable".to_owned()
            })?;
            if value.is_empty() {
                return Err("a requested redaction value is empty".to_owned());
            }
            custom_values.push(value);
        }
        custom_values.sort();
        custom_values.dedup();
        Ok(Self { custom_values })
    }

    #[must_use]
    pub fn custom_value_count(&self) -> u64 {
        u64::try_from(self.custom_values.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn command(&self, command: &[OsString]) -> RedactedCommand {
        let executable = command.first().map_or_else(OsString::new, Clone::clone);
        let executable_bytes = os_bytes(&executable);
        let executable_sha256 = sha256_bytes(&executable_bytes);
        let executable_display = Path::new(&executable).file_name().map_or_else(
            || "[non-utf8-executable]".to_owned(),
            |name| self.text(name).0,
        );

        let mut argument_displays = Vec::new();
        let mut argument_sha256 = Vec::new();
        let mut redacted_arguments = 0_u64;
        let mut redact_next = false;
        for argument in command.iter().skip(1) {
            let bytes = os_bytes(argument);
            if redact_next {
                argument_displays.push("[redacted]".to_owned());
                argument_sha256.push(None);
                redacted_arguments = redacted_arguments.saturating_add(1);
                redact_next = false;
                continue;
            }

            let (mut display, mut redacted) = self.text(argument);
            let lower = display.to_ascii_lowercase();
            if let Some((key, _)) = display.split_once('=') {
                if sensitive_key(key) {
                    display = format!("{key}=[redacted]");
                    redacted = true;
                }
            } else if sensitive_key(&lower) && lower.starts_with('-') {
                redact_next = true;
            }
            if display.contains("://") {
                let masked = redact_url(&display);
                redacted |= masked != display;
                display = masked;
            }
            if redacted {
                redacted_arguments = redacted_arguments.saturating_add(1);
            }
            argument_displays.push(display);
            argument_sha256.push((!redacted).then(|| sha256_bytes(&bytes)));
        }

        let mut command_material = Vec::new();
        append_length_delimited(&mut command_material, executable_sha256.as_bytes());
        for display in &argument_displays {
            append_length_delimited(&mut command_material, display.as_bytes());
        }
        RedactedCommand {
            executable_display,
            executable_sha256,
            argument_displays,
            argument_sha256,
            command_sha256: sha256_bytes(&command_material),
            redacted_arguments,
        }
    }

    #[must_use]
    pub fn path_display(&self, path: &Path) -> (String, u64) {
        let display = path.to_string_lossy();
        let mut redacted_components = 0_u64;
        let rendered = display
            .split(['/', '\\'])
            .map(|component| {
                if sensitive_path_component(component) {
                    redacted_components = redacted_components.saturating_add(1);
                    format!("[redacted_{}]", &sha256_bytes(component.as_bytes())[..8])
                } else {
                    let (replaced, changed) = self.replace_custom_values(component);
                    if changed {
                        redacted_components = redacted_components.saturating_add(1);
                    }
                    replaced
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        (rendered, redacted_components)
    }

    #[must_use]
    pub fn path_is_sensitive(&self, path: &Path) -> bool {
        path.components().any(|component| {
            let text = component.as_os_str().to_string_lossy();
            sensitive_path_component(&text)
                || self
                    .custom_values
                    .iter()
                    .any(|value| !value.is_empty() && text.contains(value))
        })
    }

    fn text(&self, value: &OsStr) -> (String, bool) {
        let Some(text) = value.to_str() else {
            let digest = sha256_bytes(&os_bytes(value));
            return (format!("[non_utf8_{}]", &digest[..12]), true);
        };
        let (custom_redacted, mut changed) = self.replace_custom_values(text);
        let path_redacted = if custom_redacted.contains('/') || custom_redacted.contains('\\') {
            let (path, count) = self.path_display(Path::new(&custom_redacted));
            changed |= count > 0;
            path
        } else {
            custom_redacted
        };
        (path_redacted, changed)
    }

    fn replace_custom_values(&self, text: &str) -> (String, bool) {
        let mut output = text.to_owned();
        let mut changed = false;
        for value in &self.custom_values {
            if output.contains(value) {
                output = output.replace(value, "[redacted]");
                changed = true;
            }
        }
        (output, changed)
    }
}

#[must_use]
pub fn os_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

pub fn append_length_delimited(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    target.extend_from_slice(bytes);
}

#[must_use]
pub fn sensitive_path_component(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    let sensitive_extension = Path::new(&lower).extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("pem")
            || extension.eq_ignore_ascii_case("p12")
            || extension.eq_ignore_ascii_case("pfx")
    });
    lower == ".env"
        || lower.starts_with(".env.")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("credential")
        || lower.contains("private_key")
        || lower.contains("private-key")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("secret")
        || sensitive_extension
}

fn sensitive_key(key: &str) -> bool {
    let normalized = key
        .trim_start_matches('-')
        .replace(['_', '.'], "-")
        .to_ascii_lowercase();
    normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.contains("api-key")
        || normalized.contains("private-key")
        || normalized.contains("authorization")
        || normalized.contains("cookie")
}

fn redact_url(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_owned();
    };
    let boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..boundary];
    let suffix = &rest[boundary..];
    let masked_authority = authority.rsplit_once('@').map_or_else(
        || authority.to_owned(),
        |(_, host)| format!("[redacted]@{host}"),
    );
    let mut rendered_suffix = suffix.to_owned();
    if let Some(query_index) = rendered_suffix.find('?') {
        rendered_suffix.truncate(query_index);
        rendered_suffix.push_str("?[redacted-query]");
    }
    if let Some(fragment_index) = rendered_suffix.find('#') {
        rendered_suffix.truncate(fragment_index);
        rendered_suffix.push_str("#[redacted-fragment]");
    }
    format!("{scheme}://{masked_authority}{rendered_suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_arguments_and_urls() {
        let redactor = Redactor {
            custom_values: vec!["literal-secret".to_owned()],
        };
        let command = vec![
            OsString::from("curl"),
            OsString::from("--token"),
            OsString::from("abc"),
            OsString::from("https://user:pass@example.test/path?q=secret"),
            OsString::from("literal-secret"),
        ];
        let output = redactor.command(&command);
        assert_eq!(output.argument_displays[1], "[redacted]");
        assert_eq!(output.argument_sha256[1], None);
        assert_eq!(output.argument_sha256[3], None);
        assert!(!output.argument_displays.join(" ").contains("user:pass"));
        assert!(!output.argument_displays.join(" ").contains("q=secret"));
        assert!(!output
            .argument_displays
            .join(" ")
            .contains("literal-secret"));
    }

    #[test]
    fn redacts_sensitive_path_components() {
        let redactor = Redactor {
            custom_values: Vec::new(),
        };
        let (display, count) = redactor.path_display(Path::new("config/.env.production/key"));
        assert_eq!(count, 1);
        assert!(!display.contains(".env.production"));
    }

    #[test]
    fn redacts_query_without_a_path() {
        let redacted = redact_url("https://user:pass@example.test?token=secret");
        assert_eq!(redacted, "https://[redacted]@example.test?[redacted-query]");
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("user:pass"));
    }
}
