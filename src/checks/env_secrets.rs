use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for secrets passed via environment variables
pub struct EnvSecretsCheck;

impl EnvSecretsCheck {
    pub fn new() -> Self {
        EnvSecretsCheck
    }
}

impl Default for EnvSecretsCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Patterns that indicate a secret value
const SECRET_PATTERNS: &[&str] = &["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"];

/// Check if an environment variable key contains a secret pattern
fn is_secret_key(key: &str) -> bool {
    let key_upper = key.to_uppercase();

    for pattern in SECRET_PATTERNS {
        if key_upper.contains(pattern) {
            let key_bytes = key_upper.as_bytes();
            let pattern_bytes = pattern.as_bytes();

            for i in 0..=key_bytes.len() - pattern_bytes.len() {
                if key_bytes[i..i + pattern_bytes.len()] == *pattern_bytes {
                    // For before: valid if at start OR preceded by non-alphanumeric (including underscore)
                    let valid_before = i == 0 || !key_bytes[i - 1].is_ascii_alphanumeric();

                    // For after: valid if at end OR followed by non-alphanumeric (including underscore)
                    let end_idx = i + pattern_bytes.len();
                    let valid_after =
                        end_idx == key_bytes.len() || !key_bytes[end_idx].is_ascii_alphanumeric();

                    if valid_before && valid_after {
                        return true;
                    }
                }
            }
        }
    }
    false
}

impl Check for EnvSecretsCheck {
    fn name(&self) -> &str {
        "EnvSecretsCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for env_var in &container.env {
            // Extract just the key (before the =)
            let key = env_var.split('=').next().unwrap_or(env_var);

            if is_secret_key(key) {
                findings.push(Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::High,
                    format!(
                        "Container '{}' has potential secret in environment variable: {}",
                        container.name, key
                    ),
                    Some("Use Docker secrets or a vault instead of environment variables for sensitive data".to_string()),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(env: Vec<String>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            env,
            ..Default::default()
        }
    }

    #[test]
    fn test_db_password_triggers() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["DB_PASSWORD=foo".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("DB_PASSWORD"));
        // Should NOT contain the value
        assert!(!findings[0].message.contains("foo"));
    }

    #[test]
    fn test_api_key_triggers() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["API_KEY=bar".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_path_passes() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["PATH=/usr/bin".to_string()]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_mytoken_count_passes() {
        let check = EnvSecretsCheck::new();
        // MYTOKEN_COUNT contains TOKEN but not as a separate word
        let container = make_container(vec!["MYTOKEN_COUNT=xyz".to_string()]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_secret_key_case_insensitive() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["db_password=secret".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_multiple_secrets() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec![
            "DB_PASSWORD=foo".to_string(),
            "API_KEY=bar".to_string(),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_token_as_suffix_triggers() {
        let check = EnvSecretsCheck::new();
        // MY_TOKEN contains underscore before TOKEN - underscore is valid boundary
        let container = make_container(vec!["MY_TOKEN=value".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_token_as_prefix_triggers() {
        let check = EnvSecretsCheck::new();
        // TOKEN_MY - TOKEN followed by underscore, underscore is valid boundary
        let container = make_container(vec!["TOKEN_MY=value".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_private_key_triggers() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["PRIVATE_KEY=keydata".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_env_passes() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_only_key_no_value() {
        let check = EnvSecretsCheck::new();
        let container = make_container(vec!["SECRET=".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        // Should contain key but not value
        assert!(findings[0].message.contains("SECRET"));
    }
}
