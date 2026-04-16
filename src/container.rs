use bollard::models::{ContainerInspectResponse, MountPoint, NetworkSettings, PortBinding};
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

impl From<ContainerInspectResponse> for ContainerInfo {
    /// Convert a bollard ContainerInspectResponse into our ContainerInfo
    fn from(response: ContainerInspectResponse) -> Self {
        let config = response.config.as_ref();
        let host_config = response.host_config.as_ref();
        let network_settings = response.network_settings.as_ref();

        // Extract name (strip leading '/')
        let name = response
            .name
            .as_ref()
            .map(|n| ContainerInfo::extract_name(n))
            .unwrap_or_default();

        // Extract image
        let image = config.and_then(|c| c.image.clone()).unwrap_or_default();

        // Privileged mode
        let privileged = host_config.and_then(|hc| hc.privileged).unwrap_or(false);

        // User
        let user = config.and_then(|c| c.user.clone());

        // Mounts
        let mounts = response
            .mounts
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(mount_point_to_mount_info)
            .collect();

        // Ports from network settings
        let ports = extract_ports(network_settings);

        // Environment variables (keys only)
        let env = config
            .and_then(|c| c.env.clone())
            .unwrap_or_default()
            .iter()
            .filter_map(|e| e.split('=').next().map(|k| k.to_string()))
            .collect();

        // Capabilities
        let capabilities = host_config
            .and_then(|hc| hc.cap_add.clone())
            .unwrap_or_default();

        // Memory limit (i64 bytes -> u64)
        let memory_limit = host_config.and_then(|hc| hc.memory).map(|m| m as u64);

        // CPU limit: NanoCpus is in nanoseconds, convert to cores (fraction)
        let cpu_limit = host_config
            .and_then(|hc| hc.nano_cpus)
            .map(|nc| nc as f64 / 1_000_000_000.0);

        // Health check
        let health_check = config.and_then(|c| c.healthcheck.as_ref()).is_some();

        // Network mode
        let network_mode = host_config.and_then(|hc| hc.network_mode.clone());

        ContainerInfo {
            name,
            image,
            privileged,
            user,
            mounts,
            ports,
            env,
            capabilities,
            memory_limit,
            cpu_limit,
            health_check,
            network_mode,
        }
    }
}

/// Convert a bollard MountPoint to our MountInfo
fn mount_point_to_mount_info(m: &MountPoint) -> MountInfo {
    MountInfo {
        source: m.source.as_ref().unwrap_or(&String::new()).clone(),
        destination: m.destination.as_ref().unwrap_or(&String::new()).clone(),
        mode: m.mode.as_ref().unwrap_or(&String::new()).clone(),
        mount_type: m
            .typ
            .as_ref()
            .map(|t| format!("{:?}", t))
            .unwrap_or_default(),
    }
}

/// Extract port information from NetworkSettings
fn extract_ports(network_settings: Option<&NetworkSettings>) -> Vec<PortInfo> {
    let mut ports = Vec::new();

    if let Some(settings) = network_settings {
        if let Some(ports_map) = &settings.ports {
            for (port_key, bindings_opt) in ports_map {
                let parts: Vec<&str> = port_key.split('/').collect();
                let port: u16 = parts
                    .first()
                    .and_then(|p_str| p_str.parse().ok())
                    .unwrap_or(0);
                let protocol = parts.get(1).unwrap_or(&"tcp").to_string();

                let bindings: Vec<PortBinding> = bindings_opt.clone().unwrap_or_default();
                let exposed = !bindings.is_empty();
                let host_ip = bindings
                    .first()
                    .and_then(|b| b.host_ip.as_ref())
                    .cloned()
                    .unwrap_or_default();

                ports.push(PortInfo {
                    port,
                    protocol,
                    exposed,
                    host_ip,
                });
            }
        }
    }

    ports
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

    // ─── From<ContainerInspectResponse> tests ─────────────────────────────────

    fn make_full_inspect_response() -> ContainerInspectResponse {
        use bollard::models::{ContainerConfig, HealthConfig, HostConfig, MountPoint, PortBinding};
        use std::collections::HashMap;

        let mut network_ports: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
        network_ports.insert(
            "80/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some("8080".to_string()),
            }]),
        );

        ContainerInspectResponse {
            id: Some("abc123".to_string()),
            name: Some("/nginx".to_string()),
            config: Some(ContainerConfig {
                image: Some("nginx:latest".to_string()),
                env: Some(vec![
                    "PATH=/usr/local/sbin:/usr/local/bin".to_string(),
                    "NGINX_VERSION=1.25.0".to_string(),
                    "SECRET_TOKEN=xyz".to_string(),
                ]),
                user: Some("nginx".to_string()),
                healthcheck: Some(HealthConfig::default()),
                ..Default::default()
            }),
            host_config: Some(HostConfig {
                privileged: Some(true),
                memory: Some(256_000_000i64),
                nano_cpus: Some(1_000_000_000i64), // 1 core
                cap_add: Some(vec!["NET_ADMIN".to_string(), "SYS_ADMIN".to_string()]),
                network_mode: Some("host".to_string()),
                ..Default::default()
            }),
            network_settings: Some(NetworkSettings {
                ports: Some(network_ports),
                ..Default::default()
            }),
            mounts: Some(vec![MountPoint {
                source: Some("/host/data".to_string()),
                destination: Some("/container/data".to_string()),
                mode: Some("rw".to_string()),
                typ: Some(bollard::models::MountPointTypeEnum::BIND),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn test_from_inspect_response_full_data() {
        let response = make_full_inspect_response();
        let info = ContainerInfo::from(response);

        assert_eq!(info.name, "nginx");
        assert_eq!(info.image, "nginx:latest");
        assert!(info.privileged);
        assert_eq!(info.user, Some("nginx".to_string()));
        assert!(info.health_check);
        assert_eq!(info.network_mode, Some("host".to_string()));
        assert_eq!(info.memory_limit, Some(256_000_000));
        assert_eq!(info.cpu_limit, Some(1.0)); // 1_000_000_000 nanos = 1 core
        assert_eq!(info.capabilities, vec!["NET_ADMIN", "SYS_ADMIN"]);

        // Mounts
        assert_eq!(info.mounts.len(), 1);
        assert_eq!(info.mounts[0].source, "/host/data");
        assert_eq!(info.mounts[0].destination, "/container/data");
        assert_eq!(info.mounts[0].mode, "rw");

        // Ports
        assert_eq!(info.ports.len(), 1);
        assert_eq!(info.ports[0].port, 80);
        assert_eq!(info.ports[0].protocol, "tcp");
        assert!(info.ports[0].exposed);
        assert_eq!(info.ports[0].host_ip, "0.0.0.0");

        // Env keys only
        assert_eq!(info.env.len(), 3);
        assert!(info.env.contains(&"PATH".to_string()));
        assert!(info.env.contains(&"NGINX_VERSION".to_string()));
        assert!(info.env.contains(&"SECRET_TOKEN".to_string()));
        assert!(!info.env.contains(&"PATH=/usr/local/sbin".to_string())); // no values
    }

    #[test]
    fn test_from_inspect_response_minimal_data() {
        // All None — verify all fields get sensible defaults
        let response = ContainerInspectResponse::default();
        let info = ContainerInfo::from(response);

        assert!(info.name.is_empty());
        assert!(info.image.is_empty());
        assert!(!info.privileged);
        assert!(info.user.is_none());
        assert!(!info.health_check);
        assert!(info.network_mode.is_none());
        assert!(info.memory_limit.is_none());
        assert!(info.cpu_limit.is_none());
        assert!(info.mounts.is_empty());
        assert!(info.ports.is_empty());
        assert!(info.env.is_empty());
        assert!(info.capabilities.is_empty());
    }

    #[test]
    fn test_from_inspect_response_capability_extraction() {
        use bollard::models::{ContainerConfig, HostConfig};

        // Caps only (no other fields)
        let response = ContainerInspectResponse {
            config: Some(ContainerConfig::default()),
            host_config: Some(HostConfig {
                cap_add: Some(vec![
                    "CHOWN".to_string(),
                    "NET_BIND_SERVICE".to_string(),
                    "SYS_ADMIN".to_string(),
                    "DAC_OVERRIDE".to_string(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let info = ContainerInfo::from(response);

        assert_eq!(info.capabilities.len(), 4);
        assert!(info.capabilities.contains(&"CHOWN".to_string()));
        assert!(info.capabilities.contains(&"SYS_ADMIN".to_string()));
        assert!(info.capabilities.contains(&"DAC_OVERRIDE".to_string()));
    }

    #[test]
    fn test_from_inspect_response_cpu_limit_nanoseconds() {
        use bollard::models::{ContainerConfig, HostConfig};

        // 2 cores = 2_000_000_000 nanoseconds
        let response = ContainerInspectResponse {
            config: Some(ContainerConfig::default()),
            host_config: Some(HostConfig {
                nano_cpus: Some(2_000_000_000i64),
                ..Default::default()
            }),
            ..Default::default()
        };

        let info = ContainerInfo::from(response);
        assert_eq!(info.cpu_limit, Some(2.0));
    }
}
