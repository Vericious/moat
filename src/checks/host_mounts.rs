use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for sensitive host path mounts in containers
pub struct HostMountsCheck;

impl HostMountsCheck {
    pub fn new() -> Self {
        HostMountsCheck
    }
}

impl Default for HostMountsCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Sensitive host paths that should not be bind mounted
const SENSITIVE_PATHS: &[&str] = &["/", "/etc", "/root", "/home", "/var/run", "/proc", "/sys"];

/// Check if a mount source is from a sensitive host path
fn is_sensitive_mount(source: &str) -> bool {
    // Skip docker.sock - handled by SocketMountCheck
    if source.contains("docker.sock") {
        return false;
    }

    for sensitive in SENSITIVE_PATHS {
        if source == *sensitive || source.starts_with(&format!("{}/", sensitive)) {
            return true;
        }
    }
    false
}

impl Check for HostMountsCheck {
    fn name(&self) -> &str {
        "HostMountsCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mount in &container.mounts {
            if is_sensitive_mount(&mount.source) {
                findings.push(Finding::new(
                    self.name().to_string(),
                    container.name.clone(),
                    Severity::High,
                    format!(
                        "Container '{}' has sensitive host path '{}' mounted",
                        container.name, mount.source
                    ),
                    Some(
                        "Use named volumes instead of bind mounts to sensitive host paths"
                            .to_string(),
                    ),
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

    fn make_mount(source: &str) -> MountInfo {
        MountInfo {
            source: source.to_string(),
            destination: "/container/path".to_string(),
            mode: "rw".to_string(),
            mount_type: "bind".to_string(),
        }
    }

    fn make_container_with_mounts(mounts: Vec<MountInfo>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            mounts,
            ..Default::default()
        }
    }

    #[test]
    fn test_etc_mount_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/etc")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("/etc"));
    }

    #[test]
    fn test_data_mount_passes() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/data")]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_root_mount_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_docker_sock_is_skipped() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/var/run/docker.sock")]);
        let findings = check.run(&container);

        // Should be skipped - handled by SocketMountCheck
        assert!(findings.is_empty());
    }

    #[test]
    fn test_nested_etc_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/etc/nginx")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_nested_home_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/home/user/data")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_proc_mount_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/proc")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_sys_mount_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/sys/fs/cgroup")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_var_run_mount_triggers() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/var/run")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_multiple_sensitive_mounts() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![make_mount("/etc"), make_mount("/root")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_mixed_sensitive_and_safe() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![
            make_mount("/data"),
            make_mount("/etc"),
            make_mount("/var/log"),
        ]);
        // /data and /var/log are not sensitive, only /etc
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_mounts_passes() {
        let check = HostMountsCheck::new();
        let container = make_container_with_mounts(vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }
}
