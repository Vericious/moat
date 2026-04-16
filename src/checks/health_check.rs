use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check whether a container has a health check defined
pub struct HealthCheckCheck;

impl HealthCheckCheck {
    pub fn new() -> Self {
        HealthCheckCheck
    }
}

impl Default for HealthCheckCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for HealthCheckCheck {
    fn name(&self) -> &str {
        "HealthCheckCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        if container.health_check {
            // Container has a health check — no finding
            Vec::new()
        } else {
            vec![Finding::new(
                self.name().to_string(),
                container.name.clone(),
                Severity::Medium,
                format!("Container '{}' has no health check defined", container.name),
                Some(
                    "Add a HEALTHCHECK instruction in Dockerfile or --health-cmd flag at runtime"
                        .to_string(),
                ),
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerInfo;

    fn make_container(has_health_check: bool) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            health_check: has_health_check,
            ..Default::default()
        }
    }

    #[test]
    fn test_no_health_check_produces_finding() {
        let check = HealthCheckCheck::new();
        let findings = check.run(&make_container(false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("no health check"));
    }

    #[test]
    fn test_has_health_check_produces_no_finding() {
        let check = HealthCheckCheck::new();
        let findings = check.run(&make_container(true));
        assert!(findings.is_empty());
    }
}
