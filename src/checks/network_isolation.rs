use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check that containers use network isolation (not host network mode).
/// Host network mode bypasses all Docker networking and gives the container
/// full access to the host's network stack.
pub struct NetworkIsolationCheck;

impl NetworkIsolationCheck {
    pub fn new() -> Self {
        NetworkIsolationCheck
    }
}

impl Default for NetworkIsolationCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for NetworkIsolationCheck {
    fn name(&self) -> &str {
        "NetworkIsolationCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if container.network_mode.as_deref() == Some("host") {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::High,
                format!(
                    "Container '{}' is using host network mode (bypasses network isolation)",
                    container.name
                ),
                Some(
                    "Use bridge or a custom Docker network instead of --network=host. \
                     This provides better network isolation between containers."
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

    fn make_container(network_mode: Option<&str>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            network_mode: network_mode.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_host_network_triggers_high_finding() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(Some("host"));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("host network"));
    }

    #[test]
    fn test_bridge_network_produces_no_finding() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(Some("bridge"));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_none_network_produces_no_finding() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(Some("none"));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_network_mode_produces_no_finding() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_custom_network_produces_no_finding() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(Some("my-custom-network"));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = NetworkIsolationCheck::new();
        let container = make_container(Some("host"));
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("bridge"));
    }
}