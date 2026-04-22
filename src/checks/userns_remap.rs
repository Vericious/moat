use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers not using user namespace remapping.
/// User namespace remapping maps container UIDs/GIDs to unprivileged host UIDs/GIDs,
/// providing an additional layer of isolation between containers.
pub struct UsernsRemapCheck;

impl UsernsRemapCheck {
    pub fn new() -> Self {
        UsernsRemapCheck
    }
}

impl Default for UsernsRemapCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for UsernsRemapCheck {
    fn name(&self) -> &str {
        "UsernsRemapCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        // None or "host" means user namespace remapping is NOT enabled
        let remapped = container
            .userns_mode
            .as_ref()
            .map(|m| m != "host")
            .unwrap_or(false);

        if !remapped {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' is not using user namespace remapping",
                    container.name
                ),
                Some(
                    "Enable user namespace remapping with --userns=remap. \
                     This maps container UIDs/GIDs to unprivileged host UIDs, \
                     adding a layer of isolation between containers."
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

    fn make_container(userns_mode: Option<&str>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            userns_mode: userns_mode.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_no_userns_triggers_medium_finding() {
        let check = UsernsRemapCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("not using user namespace remapping"));
    }

    #[test]
    fn test_host_userns_triggers_finding() {
        let check = UsernsRemapCheck::new();
        let container = make_container(Some("host"));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_remap_userns_produces_no_finding() {
        let check = UsernsRemapCheck::new();
        let container = make_container(Some("remap"));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_named_userns_produces_no_finding() {
        let check = UsernsRemapCheck::new();
        let container = make_container(Some("default"));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = UsernsRemapCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("userns"));
    }
}