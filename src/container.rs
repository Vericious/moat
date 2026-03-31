use serde::Serialize;
use std::default::Default;

/// Information about a mounted volume
#[derive(Debug, Clone, Default, Serialize)]
pub struct MountInfo {
    /// Source path on the host
    pub source: String,
    /// Destination path in the container
    pub destination: String,
    /// Mount mode (e.g., "rw", "ro")
    pub mode: String,
    /// Mount type (e.g., "bind", "volume")
    pub mount_type: String,
}

/// Information about an exposed port
#[derive(Debug, Clone, Default, Serialize)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Protocol (e.g., "tcp", "udp")
    pub protocol: String,
    /// Whether the port is exposed to the host
    pub exposed: bool,
    /// Host IP address the port is bound to (empty if not bound to host)
    pub host_ip: String,
}

/// Container information for security scanning
#[derive(Debug, Clone, Default, Serialize)]
pub struct ContainerInfo {
    /// Container name
    pub name: String,
    /// Container image name
    pub image: String,
    /// Whether container is running in privileged mode
    pub privileged: bool,
    /// User the container is running as (None if root or not specified)
    pub user: Option<String>,
    /// List of mounted volumes
    pub mounts: Vec<MountInfo>,
    /// List of exposed ports
    pub ports: Vec<PortInfo>,
    /// Environment variables (keys only, values stripped for security)
    pub env: Vec<String>,
    /// Linux capabilities granted to the container
    pub capabilities: Vec<String>,
    /// Memory limit in bytes (None if no limit set)
    pub memory_limit: Option<u64>,
    /// CPU limit (None if no limit set)
    pub cpu_limit: Option<f64>,
    /// Whether the container has a health check defined
    pub health_check: bool,
    /// Network mode (e.g., "host", "bridge", "none")
    pub network_mode: Option<String>,
}

impl ContainerInfo {
    /// Extract the container name from a full container name string (which may have leading '/')
    pub fn extract_name(full_name: &str) -> String {
        full_name.trim_start_matches('/').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_container_info() {
        let info = ContainerInfo::default();

        assert!(info.name.is_empty());
        assert!(info.image.is_empty());
        assert!(!info.privileged);
        assert!(info.user.is_none());
        assert!(info.mounts.is_empty());
        assert!(info.ports.is_empty());
        assert!(info.env.is_empty());
        assert!(info.capabilities.is_empty());
        assert!(info.memory_limit.is_none());
        assert!(info.cpu_limit.is_none());
        assert!(!info.health_check);
        assert!(info.network_mode.is_none());
    }

    #[test]
    fn test_default_mount_info() {
        let mount = MountInfo::default();

        assert!(mount.source.is_empty());
        assert!(mount.destination.is_empty());
        assert!(mount.mode.is_empty());
        assert!(mount.mount_type.is_empty());
    }

    #[test]
    fn test_default_port_info() {
        let port = PortInfo::default();

        assert_eq!(port.port, 0);
        assert!(port.protocol.is_empty());
        assert!(!port.exposed);
        assert!(port.host_ip.is_empty());
    }

    #[test]
    fn test_name_extraction_strips_leading_slash() {
        assert_eq!(ContainerInfo::extract_name("/container1"), "container1");
        assert_eq!(ContainerInfo::extract_name("/redis"), "redis");
    }

    #[test]
    fn test_name_extraction_no_leading_slash() {
        assert_eq!(ContainerInfo::extract_name("container1"), "container1");
        assert_eq!(ContainerInfo::extract_name("nginx"), "nginx");
    }

    #[test]
    fn test_name_extraction_empty() {
        assert_eq!(ContainerInfo::extract_name(""), "");
    }

    #[test]
    fn test_name_extraction_multiple_leading_slashes() {
        // trim_start_matches removes ALL leading matching chars
        assert_eq!(ContainerInfo::extract_name("///container"), "container");
        assert_eq!(ContainerInfo::extract_name("//container"), "container");
    }

    #[test]
    fn test_container_info_with_values() {
        let mut info = ContainerInfo::default();
        info.name = "test-container".to_string();
        info.image = "nginx:latest".to_string();
        info.privileged = true;
        info.user = Some("root".to_string());
        info.health_check = true;
        info.network_mode = Some("bridge".to_string());

        assert_eq!(info.name, "test-container");
        assert_eq!(info.image, "nginx:latest");
        assert!(info.privileged);
        assert_eq!(info.user, Some("root".to_string()));
        assert!(info.health_check);
        assert_eq!(info.network_mode, Some("bridge".to_string()));
    }

    #[test]
    fn test_mount_info_fields() {
        let mount = MountInfo {
            source: "/host/data".to_string(),
            destination: "/container/data".to_string(),
            mode: "rw".to_string(),
            mount_type: "bind".to_string(),
        };

        assert_eq!(mount.source, "/host/data");
        assert_eq!(mount.destination, "/container/data");
        assert_eq!(mount.mode, "rw");
        assert_eq!(mount.mount_type, "bind");
    }

    #[test]
    fn test_port_info_fields() {
        let port = PortInfo {
            port: 8080,
            protocol: "tcp".to_string(),
            exposed: true,
            host_ip: "0.0.0.0".to_string(),
        };

        assert_eq!(port.port, 8080);
        assert_eq!(port.protocol, "tcp");
        assert!(port.exposed);
        assert_eq!(port.host_ip, "0.0.0.0");
    }
}
