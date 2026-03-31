use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for Docker socket mounts in containers
pub struct SocketMountCheck;

impl SocketMountCheck {
    pub fn new() -> Self {
        SocketMountCheck
    }
}

impl Default for SocketMountCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a path contains the Docker socket
fn is_docker_socket_path(path: &str) -> bool {
    path.contains("docker.sock")
}

impl Check for SocketMountCheck {
    fn name(&self) -> &str {
        "SocketMountCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mount in &container.mounts {
            if is_docker_socket_path(&mount.source) || is_docker_socket_path(&mount.destination) {
                findings.push(Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::Critical,
                    format!(
                        "Container '{}' has Docker socket mounted at '{}'",
                        container.name, mount.source
                    ),
                    Some("Remove Docker socket mount — this gives the container full control over the Docker daemon".to_string()),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerInfo, MountInfo};

    fn make_container_with_mounts(mounts: Vec<MountInfo>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            mounts,
            ..Default::default()
        }
    }

    fn make_docker_sock_mount(source: &str) -> MountInfo {
        MountInfo {
            source: source.to_string(),
            destination: "/var/run/docker.sock".to_string(),
            mode: "rw".to_string(),
            mount_type: "bind".to_string(),
        }
    }

    fn make_normal_mount() -> MountInfo {
        MountInfo {
            source: "/host/data".to_string(),
            destination: "/container/data".to_string(),
            mode: "rw".to_string(),
            mount_type: "bind".to_string(),
        }
    }

    #[test]
    fn test_var_run_docker_sock_triggers_critical() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![make_docker_sock_mount("/var/run/docker.sock")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("docker.sock"));
    }

    #[test]
    fn test_run_docker_sock_triggers() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![make_docker_sock_mount("/run/docker.sock")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_normal_volume_mount_passes() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![make_normal_mount()]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_mounts_one_socket() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![
            make_normal_mount(),
            make_docker_sock_mount("/var/run/docker.sock"),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_multiple_sockets_multiple_findings() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![
            make_docker_sock_mount("/var/run/docker.sock"),
            make_docker_sock_mount("/run/docker.sock"),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn test_no_mounts_passes() {
        let check = SocketMountCheck::new();
        let container = make_container_with_mounts(vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_socket_in_destination() {
        let check = SocketMountCheck::new();
        let mount = MountInfo {
            source: "/host/socket".to_string(),
            destination: "/var/run/docker.sock".to_string(),
            mode: "rw".to_string(),
            mount_type: "bind".to_string(),
        };
        let container = make_container_with_mounts(vec![mount]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
