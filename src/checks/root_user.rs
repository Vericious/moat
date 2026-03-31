use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers running as root user
pub struct RootUserCheck;

impl RootUserCheck {
    pub fn new() -> Self {
        RootUserCheck
    }
}

impl Default for RootUserCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a user string represents root or uid 0
fn is_root_user(user: &Option<String>) -> bool {
    match user {
        None => true,
        Some(u) => {
            let u_trimmed = u.trim();
            u_trimmed.is_empty() || u_trimmed == "0" || u_trimmed == "root"
        }
    }
}

impl Check for RootUserCheck {
    fn name(&self) -> &str {
        "RootUserCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if is_root_user(&container.user) {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::High,
                format!(
                    "Container '{}' is running as root user",
                    container.name
                ),
                Some("Set USER directive in Dockerfile or use --user flag to run as non-root".to_string()),
            )]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(user: Option<String>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            user,
            ..Default::default()
        }
    }

    #[test]
    fn test_user_none_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("root"));
    }

    #[test]
    fn test_user_root_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("root".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_user_zero_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("0".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_user_uid_zero_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("0".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_user_non_root_uid_produces_no_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("1000".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_user_appuser_produces_no_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("appuser".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_empty_user_string_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_whitespace_only_user_produces_finding() {
        let check = RootUserCheck::new();
        let container = make_container(Some("   ".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }
}
