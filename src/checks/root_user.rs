use bollard::models::ContainerInspectResponse;

use crate::models::{Finding, Severity};

/// Check if a container is running as root (UID 0).
pub fn check(container_name: &str, info: &ContainerInspectResponse) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(config) = &info.config {
        let user = config.user.as_deref().unwrap_or("");

        // Empty user means root (Docker default), "0" means explicit root,
        // "root" means explicit root
        let is_root = user.is_empty() || user == "0" || user == "root" || user.starts_with("0:");

        if is_root {
            findings.push(Finding {
                container: container_name.to_string(),
                check_id: "root-user".to_string(),
                severity: Severity::Medium,
                title: "Container running as root".to_string(),
                message: format!(
                    "Container '{container_name}' is running as root (UID 0). \
                     If an attacker escapes the container, they'll have root access \
                     to your host system."
                ),
                fix: "Add 'user: \"1000:1000\"' to your docker-compose.yml or \
                      use '--user 1000:1000' with docker run. Check the container's \
                      docs for the recommended non-root user."
                    .to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerConfig, ContainerInspectResponse};

    fn make_container(user: Option<&str>) -> ContainerInspectResponse {
        ContainerInspectResponse {
            config: Some(ContainerConfig {
                user: user.map(|u| u.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn detects_empty_user_as_root() {
        let info = make_container(Some(""));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "root-user");
    }

    #[test]
    fn detects_explicit_root() {
        let info = make_container(Some("root"));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_uid_zero() {
        let info = make_container(Some("0"));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_finding_for_nonroot_user() {
        let info = make_container(Some("1000:1000"));
        let findings = check("test", &info);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_finding_for_named_user() {
        let info = make_container(Some("appuser"));
        let findings = check("test", &info);
        assert!(findings.is_empty());
    }
}
