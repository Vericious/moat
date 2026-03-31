use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for missing resource limits on containers
pub struct ResourceLimitsCheck;

impl ResourceLimitsCheck {
    pub fn new() -> Self {
        ResourceLimitsCheck
    }
}

impl Default for ResourceLimitsCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ResourceLimitsCheck {
    fn name(&self) -> &str {
        "ResourceLimitsCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check memory limit
        if container.memory_limit.is_none() || container.memory_limit == Some(0) {
            findings.push(Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' has no memory limit set (unlimited)",
                    container.name
                ),
                Some("Set memory limit with --memory flag".to_string()),
            ));
        }

        // Check CPU limit
        if container.cpu_limit.is_none() || container.cpu_limit == Some(0.0) {
            findings.push(Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' has no CPU limit set (unlimited)",
                    container.name
                ),
                Some("Set CPU limit with --cpus flag".to_string()),
            ));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(memory_limit: Option<u64>, cpu_limit: Option<f64>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            memory_limit,
            cpu_limit,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_limits_triggers_two_findings() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(None, None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_only_memory_set_triggers_one_finding() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(Some(512 * 1024 * 1024), None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("CPU"));
    }

    #[test]
    fn test_only_cpu_set_triggers_one_finding() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(None, Some(1.0));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("memory"));
    }

    #[test]
    fn test_both_set_triggers_zero_findings() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(Some(512 * 1024 * 1024), Some(1.0));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_zero_memory_limit_triggers_finding() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(Some(0), Some(1.0));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("memory"));
    }

    #[test]
    fn test_zero_cpu_limit_triggers_finding() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(Some(512 * 1024 * 1024), Some(0.0));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("CPU"));
    }

    #[test]
    fn test_large_memory_limit_still_has_limit() {
        let check = ResourceLimitsCheck::new();
        let container = make_container(Some(u64::MAX), Some(1.0));
        let findings = check.run(&container);

        // u64::MAX is still a limit (even if very large)
        assert!(findings.is_empty());
    }
}
