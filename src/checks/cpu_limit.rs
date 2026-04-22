use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for containers missing CPU limits.
/// Without CPU limits, a container can consume unlimited CPU time,
/// potentially starving other containers or the host system.
pub struct CpuLimitCheck;

impl CpuLimitCheck {
    pub fn new() -> Self {
        CpuLimitCheck
    }
}

impl Default for CpuLimitCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for CpuLimitCheck {
    fn name(&self) -> &str {
        "CpuLimitCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        // cpu_limit is None when no CPU limit is set.
        // Some(0.0) also represents unlimited (same as unset in Docker).
        let has_limit = container.cpu_limit.map(|c| c > 0.0).unwrap_or(false);
        if !has_limit {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!(
                    "Container '{}' has no CPU limit configured",
                    container.name
                ),
                Some(
                    "Set a CPU limit using --cpus or --cpuset-cpus in docker run, \
                     or CPUQuota/CPUPeriod in Kubernetes"
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

    fn make_container(cpu_limit: Option<f64>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            cpu_limit,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_cpu_limit_triggers_medium_finding() {
        let check = CpuLimitCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("no CPU limit"));
    }

    #[test]
    fn test_with_cpu_limit_produces_no_finding() {
        let check = CpuLimitCheck::new();
        let container = make_container(Some(1.0));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_with_half_cpu_limit_produces_no_finding() {
        let check = CpuLimitCheck::new();
        let container = make_container(Some(0.5));
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_with_zero_cpu_limit_triggers_finding() {
        let check = CpuLimitCheck::new();
        let container = make_container(Some(0.0));
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_finding_has_remediation() {
        let check = CpuLimitCheck::new();
        let container = make_container(None);
        let findings = check.run(&container);

        assert!(findings[0].remediation.is_some());
        assert!(findings[0].remediation.as_ref().unwrap().contains("CPU"));
    }
}