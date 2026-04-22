use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check that verifies containers are not running as the root user.
/// Running as root increases the risk of privilege escalation attacks.
pub struct NonRootUserCheck;

impl NonRootUserCheck {
    pub fn new() -> Self {
        NonRootUserCheck
    }
}

impl Default for NonRootUserCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the user string represents root (UID 0 or username "root")
fn is_root(user: &Option<String>) -> bool {
    match user {
        None => true, // None means root (default container user)
        Some(u) => {
            let t = u.trim();
            t.is_empty() || t == "0" || t == "root" || t.starts_with("0:")
        }
    }
}

impl Check for NonRootUserCheck {
    fn name(&self) -> &str {
        "NonRootUserCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if is_root(&container.user) {
            let user_info = container
                .user
                .as_ref()
                .map(|u| format!(" (user: {})", u))
                .unwrap_or_default();

            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::High,
                format!(
                    "Container '{}' is running as root user{}",
                    container.name, user_info
                ),
                Some(
                    "Use the USER directive in Dockerfile or --user flag to run as a \
                     non-root user (e.g., USER appuser or USER 1000:1000)"
                        .to_string(),
                ),
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
    fn test_no_user_specified_is_root() {
        let check = NonRootUserCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("root"));
    }

    #[test]
    fn test_user_root_triggers_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("root".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("root"));
    }

    #[test]
    fn test_user_uid_0_triggers_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("0".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_user_0_with_group_triggers_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("0:0".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_user_1000_no_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("1000".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_user_appuser_no_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("appuser".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_user_1000_1000_no_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("1000:1000".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_empty_user_string_triggers_finding() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("".to_string()));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_finding_includes_user_info_in_message() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("root".to_string()));
        let findings = check.run(&container);

        assert!(findings[0].message.contains("(user: root)"));
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = NonRootUserCheck::new();
        let container = make_container(Some("root".to_string()));
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("USER"));
    }
}