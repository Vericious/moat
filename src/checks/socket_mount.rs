use bollard::models::ContainerInspectResponse;

use crate::models::{Finding, Severity};

/// Check if a container has the Docker socket mounted.
pub fn check(container_name: &str, info: &ContainerInspectResponse) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(mounts) = &info.mounts {
        for mount in mounts {
            let source = mount.source.as_deref().unwrap_or("");
            let destination = mount.destination.as_deref().unwrap_or("");

            if source.contains("docker.sock") || destination.contains("docker.sock") {
                let is_readonly = mount.rw == Some(false);

                findings.push(Finding {
                    container: container_name.to_string(),
                    check_id: "docker-socket-mount".to_string(),
                    severity: if is_readonly {
                        Severity::High
                    } else {
                        Severity::Critical
                    },
                    title: "Docker socket mounted in container".to_string(),
                    message: format!(
                        "Container '{container_name}' has the Docker socket mounted{}. \
                         This gives the container the ability to control Docker on your host — \
                         it can create, stop, or modify any container, effectively giving it \
                         root access to your system.",
                        if is_readonly { " (read-only)" } else { " (read-write)" }
                    ),
                    fix: if is_readonly {
                        "The socket is mounted read-only, which limits the risk. \
                         Consider whether this container truly needs Docker socket access. \
                         If it only needs container stats, consider using a Docker proxy \
                         like tecnativa/docker-socket-proxy instead."
                            .to_string()
                    } else {
                        "Mount the socket as read-only if possible: \
                         '/var/run/docker.sock:/var/run/docker.sock:ro'. \
                         Better yet, use tecnativa/docker-socket-proxy to expose \
                         only the specific Docker API endpoints the container needs."
                            .to_string()
                    },
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerInspectResponse, MountPoint};

    fn make_container(source: &str, dest: &str, rw: Option<bool>) -> ContainerInspectResponse {
        ContainerInspectResponse {
            mounts: Some(vec![MountPoint {
                source: Some(source.to_string()),
                destination: Some(dest.to_string()),
                rw,
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn detects_rw_socket_mount() {
        let info = make_container("/var/run/docker.sock", "/var/run/docker.sock", Some(true));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_ro_socket_mount() {
        let info = make_container("/var/run/docker.sock", "/var/run/docker.sock", Some(false));
        let findings = check("test", &info);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn no_finding_for_normal_mount() {
        let info = make_container("/data", "/app/data", Some(true));
        let findings = check("test", &info);
        assert!(findings.is_empty());
    }
}
