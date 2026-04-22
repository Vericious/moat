use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers running without a seccomp profile.
/// Seccomp (Secure Computing Mode) restricts the syscalls a container can make.
pub struct SeccompCheck;

impl SeccompCheck {
    pub fn new() -> Self {
        SeccompCheck
    }
}

impl Default for SeccompCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SeccompCheck {
    fn name(&self) -> &str {
        "SeccompCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        // None = no seccomp profile (unconfined)
        // Some(_) = profile is set
        if container.seccomp_profile.is_none() {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::High,
                format!(
                    "Container '{}' is running without a seccomp profile",
                    container.name
                ),
                Some(
                    "Apply a seccomp profile to restrict available syscalls, \
                     e.g. --security-opt seccomp=<profile-file>"
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

    fn make_container(seccomp: Option<String>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            seccomp_profile: seccomp,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_seccomp_produces_high_finding() {
        let check = SeccompCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("without a seccomp profile"));
    }

    #[test]
    fn test_with_seccomp_profile_produces_no_findings() {
        let check = SeccompCheck::new();
        let container = make_container(Some("docker/default".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_unconfined_seccomp_produces_no_findings() {
        // If seccomp_profile is Some("unconfined"), profile is set (to unconfined)
        let check = SeccompCheck::new();
        let container = make_container(Some("unconfined".to_string()));
        let findings = check.run(&container);

        // "unconfined" is a profile (even if it's disable), so no finding
        assert!(findings.is_empty());
    }

    #[test]
    fn test_named_profile_produces_no_findings() {
        let check = SeccompCheck::new();
        let container = make_container(Some("seccomp=profiles/custom.json".to_string()));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = SeccompCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("seccomp"));
    }
}