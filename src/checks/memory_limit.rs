use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers missing memory limits.
/// Without memory limits, a container can consume unlimited memory,
/// potentially causing OOM kills that affect the entire host.
pub struct MemoryLimitCheck;

impl MemoryLimitCheck {
    pub fn new() -> Self {
        MemoryLimitCheck
    }
}

impl Default for MemoryLimitCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for MemoryLimitCheck {
    fn name(&self) -> &str {
        "MemoryLimitCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        // memory_limit is None when no limit is set
        let has_limit = container.memory_limit.map(|m| m > 0).unwrap_or(false);
        if !has_limit {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' has no memory limit configured",
                    container.name
                ),
                Some(
                    "Set a memory limit using --memory in docker run, \
                     or resources.limits.memory in Kubernetes"
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

    fn make_container(memory_limit: Option<u64>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            memory_limit,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_memory_limit_triggers_medium_finding() {
        let check = MemoryLimitCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("no memory limit"));
    }

    #[test]
    fn test_with_memory_limit_produces_no_finding() {
        let check = MemoryLimitCheck::new();
        let container = make_container(Some(512_000_000));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_with_zero_memory_limit_triggers_finding() {
        let check = MemoryLimitCheck::new();
        let container = make_container(Some(0));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_small_memory_limit_still_has_limit() {
        let check = MemoryLimitCheck::new();
        // Even 1 byte limit counts as having a limit
        let container = make_container(Some(1));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = MemoryLimitCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("memory"));
    }
}