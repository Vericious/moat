use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check that flags dangerous Linux capabilities regardless of privileged mode.
/// Separated from PrivilegedCheck so capability auditing can run independently.
pub struct CapabilitiesCheck;

impl CapabilitiesCheck {
    pub fn new() -> Self {
        CapabilitiesCheck
    }
}

impl Default for CapabilitiesCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Capabilities considered dangerous enough to warrant a critical finding
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
];

impl Check for CapabilitiesCheck {
    fn name(&self) -> &str {
        "CapabilitiesCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cap in &container.capabilities {
            let cap_upper = cap.to_uppercase();
            if DANGEROUS_CAPABILITIES.iter().any(|&d| d == cap_upper) {
                findings.push(Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::Critical,
                    format!(
                        "Container '{}' has dangerous capability: {}",
                        container.name, cap
                    ),
                    Some(format!(
                        "Remove the {} capability if not strictly required",
                        cap
                    )),
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

    fn make_container(caps: Vec<String>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            capabilities: caps,
            ..Default::default()
        }
    }

    #[test]
    fn test_sys_admin_produces_critical_finding() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec!["SYS_ADMIN".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("SYS_ADMIN"));
    }

    #[test]
    fn test_net_admin_produces_critical_finding() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec!["NET_ADMIN".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_dac_override_produces_critical_finding() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec!["DAC_OVERRIDE".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_safe_capabilities_produce_no_findings() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec![
            "CHOWN".to_string(),
            "NET_BIND_SERVICE".to_string(),
            "SETGID".to_string(),
            "SETUID".to_string(),
        ]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_dangerous_caps_produce_multiple_findings() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec![
            "SYS_ADMIN".to_string(),
            "DAC_OVERRIDE".to_string(),
            "SYS_PTRACE".to_string(),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_case_insensitive_cap_matching() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec!["sys_admin".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_empty_capabilities_produces_no_findings() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_findings_have_remediation() {
        let check = CapabilitiesCheck::new();
        let container = make_container(vec!["SYS_ADMIN".to_string()]);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("SYS_ADMIN"));
    }
}