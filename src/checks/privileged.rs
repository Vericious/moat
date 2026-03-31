use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for privileged container execution and dangerous capabilities
pub struct PrivilegedCheck;

impl PrivilegedCheck {
    pub fn new() -> Self {
        PrivilegedCheck
    }
}

impl Default for PrivilegedCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Dangerous capabilities that warrant a High severity finding
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
];

impl Check for PrivilegedCheck {
    fn name(&self) -> &str {
        "PrivilegedCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for privileged mode
        if container.privileged {
            findings.push(Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Critical,
                format!(
                    "Container '{}' is running in privileged mode",
                    container.name
                ),
                Some("Remove privileged mode from the container security configuration".to_string()),
            ));
        }

        // Check for dangerous capabilities
        for cap in &container.capabilities {
            let cap_upper = cap.to_uppercase();
            if DANGEROUS_CAPABILITIES.iter().any(|&d| d == cap_upper) {
                findings.push(Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::High,
                    format!(
                        "Container '{}' has dangerous capability: {}",
                        container.name, cap
                    ),
                    Some(format!(
                        "Consider removing the {} capability if not required",
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

    fn make_container(privileged: bool, caps: Vec<String>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            privileged,
            capabilities: caps,
            ..Default::default()
        }
    }

    #[test]
    fn test_privileged_true_produces_critical_finding() {
        let check = PrivilegedCheck::new();
        let container = make_container(true, vec![]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("privileged"));
    }

    #[test]
    fn test_sys_admin_cap_produces_high_finding() {
        let check = PrivilegedCheck::new();
        let container = make_container(false, vec!["SYS_ADMIN".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("SYS_ADMIN"));
    }

    #[test]
    fn test_clean_container_produces_no_findings() {
        let check = PrivilegedCheck::new();
        let container = make_container(false, vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_caps_produce_multiple_findings() {
        let check = PrivilegedCheck::new();
        let container = make_container(
            false,
            vec!["SYS_ADMIN".to_string(), "NET_ADMIN".to_string()],
        );
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_case_insensitive_cap_matching() {
        let check = PrivilegedCheck::new();
        let container = make_container(false, vec!["sys_admin".to_string()]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_safe_capabilities_produce_no_findings() {
        let check = PrivilegedCheck::new();
        let container = make_container(
            false,
            vec!["CHOWN".to_string(), "NET_BIND_SERVICE".to_string()],
        );
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_privileged_and_caps_produce_both_findings() {
        let check = PrivilegedCheck::new();
        let container = make_container(
            true,
            vec!["SYS_ADMIN".to_string()],
        );
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }
}
