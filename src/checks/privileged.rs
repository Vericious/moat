use bollard::models::ContainerInspectResponse;

use crate::models::{Finding, Severity};

/// Check if a container is running in privileged mode or with dangerous capabilities.
pub fn check(container_name: &str, info: &ContainerInspectResponse) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(host_config) = &info.host_config {
        // Check --privileged flag
        if host_config.privileged == Some(true) {
            findings.push(Finding {
                container: container_name.to_string(),
                check_id: "privileged-mode".to_string(),
                severity: Severity::Critical,
                title: "Container running in privileged mode".to_string(),
                message: format!(
                    "Container '{container_name}' is running with --privileged flag. \
                     This gives the container full access to the host system, \
                     effectively making it root on your machine."
                ),
                fix: "Remove the 'privileged: true' flag from your docker-compose.yml \
                      or --privileged from your docker run command. If the container \
                      needs specific capabilities, use cap_add to grant only what's needed."
                    .to_string(),
            });
        }

        // Check dangerous capabilities
        let dangerous_caps = [
            "SYS_ADMIN",
            "NET_ADMIN",
            "SYS_PTRACE",
            "SYS_RAWIO",
            "DAC_OVERRIDE",
        ];

        if let Some(cap_add) = &host_config.cap_add {
            for cap in cap_add {
                if dangerous_caps.contains(&cap.as_str()) {
                    findings.push(Finding {
                        container: container_name.to_string(),
                        check_id: format!("dangerous-capability-{}", cap.to_lowercase()),
                        severity: Severity::High,
                        title: format!("Container has dangerous capability: {cap}"),
                        message: format!(
                            "Container '{container_name}' has been granted the {cap} capability. \
                             This gives elevated privileges that could be used to escape the container."
                        ),
                        fix: format!(
                            "Remove '{cap}' from cap_add in your docker-compose.yml unless \
                             the container absolutely requires it. Check the container's \
                             documentation for the minimum required capabilities."
                        ),
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerInspectResponse, HostConfig};

    fn make_container(privileged: Option<bool>, caps: Option<Vec<String>>) -> ContainerInspectResponse {
        ContainerInspectResponse {
            host_config: Some(HostConfig {
                privileged,
                cap_add: caps,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn detects_privileged() {
        let info = make_container(Some(true), None);
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "privileged-mode");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn no_finding_when_not_privileged() {
        let info = make_container(Some(false), None);
        let findings = check("test", &info);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_dangerous_capability() {
        let info = make_container(None, Some(vec!["SYS_ADMIN".to_string()]));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "dangerous-capability-sys_admin");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn ignores_safe_capability() {
        let info = make_container(None, Some(vec!["CHOWN".to_string()]));
        let findings = check("test", &info);
        assert!(findings.is_empty());
    }
}
