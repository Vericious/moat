use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers with a writable root filesystem.
/// A readonly root filesystem prevents modification of system files
/// and limits the impact of container compromise.
pub struct ReadonlyRootfsCheck;

impl ReadonlyRootfsCheck {
    pub fn new() -> Self {
        ReadonlyRootfsCheck
    }
}

impl Default for ReadonlyRootfsCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ReadonlyRootfsCheck {
    fn name(&self) -> &str {
        "ReadonlyRootfsCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if !container.readonly_rootfs {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' has a writable root filesystem",
                    container.name
                ),
                Some(
                    "Mount the root filesystem as read-only using \
                     --read-only or --security-opt seccomp=... to restrict filesystem writes"
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

    fn make_container(readonly: bool) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            readonly_rootfs: readonly,
            ..Default::default()
        }
    }

    #[test]
    fn test_writable_rootfs_triggers_medium_finding() {
        let check = ReadonlyRootfsCheck::new();
        let container = make_container(false);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("writable"));
    }

    #[test]
    fn test_readonly_rootfs_produces_no_finding() {
        let check = ReadonlyRootfsCheck::new();
        let container = make_container(true);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = ReadonlyRootfsCheck::new();
        let container = make_container(false);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
    }
}