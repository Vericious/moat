use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check whether a container is using host network mode
pub struct HostNetworkCheck;

impl HostNetworkCheck {
    pub fn new() -> Self {
        HostNetworkCheck
    }
}

impl Default for HostNetworkCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for HostNetworkCheck {
    fn name(&self) -> &str {
        "HostNetworkCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        match container.network_mode.as_deref() {
            Some("host") => {
                vec![Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::High,
                    format!(
                        "Container '{}' is using host network mode (bypasses network isolation)",
                        container.name
                    ),
                    Some("Use bridge or a custom network instead of host network mode".to_string()),
                )]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(network_mode: Option<&str>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            network_mode: network_mode.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_host_network_produces_finding() {
        let check = HostNetworkCheck::new();
        let findings = check.run(&make_container(Some("host")));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("host network"));
    }

    #[test]
    fn test_bridge_network_produces_no_finding() {
        let check = HostNetworkCheck::new();
        let findings = check.run(&make_container(Some("bridge")));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_network_mode_produces_no_finding() {
        let check = HostNetworkCheck::new();
        let findings = check.run(&make_container(None));
        assert!(findings.is_empty());
    }
}
