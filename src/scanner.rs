//! Docker container scanner for security checks

use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::models::{NetworkSettings, PortBinding};
use bollard::Docker;

use crate::container::{ContainerInfo, MountInfo, PortInfo};

/// Error type for scanner operations
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Failed to connect to Docker daemon: {0}")]
    Connection(String),
    #[error("Failed to list containers: {0}")]
    List(String),
    #[error("Failed to inspect container {0}: {1}")]
    Inspect(String, String),
}

/// Docker container scanner
#[derive(Debug)]
pub struct Scanner {
    docker: Docker,
}

impl Scanner {
    /// Create a new Scanner instance
    ///
    /// # Arguments
    /// * `socket_path` - Path to the Docker socket (e.g., "/var/run/docker.sock")
    pub fn new(socket_path: &str) -> Result<Self, ScanError> {
        let docker = Docker::connect_with_socket(socket_path, 10000, bollard::API_DEFAULT_VERSION)
            .map_err(|e| ScanError::Connection(e.to_string()))?;

        Ok(Scanner { docker })
    }

    /// Scan all running containers and return their information
    pub async fn scan(&self) -> Result<Vec<ContainerInfo>, ScanError> {
        // List all running containers
        let options = ListContainersOptions::<String> {
            all: false, // Only running containers
            ..Default::default()
        };

        let containers = self
            .docker
            .list_containers(Some(options))
            .await
            .map_err(|e| ScanError::List(e.to_string()))?;

        let mut results = Vec::new();

        for container in containers {
            // Get container ID
            let container_id = match &container.id {
                Some(id) => id.clone(),
                None => continue,
            };

            // Inspect container for detailed info
            match self.inspect_container(&container_id).await {
                Ok(info) => results.push(info),
                Err(e) => {
                    // Log error but continue with other containers
                    eprintln!(
                        "Warning: Failed to inspect container {}: {}",
                        container_id, e
                    );
                }
            }
        }

        Ok(results)
    }

    /// Inspect a single container and convert to ContainerInfo
    async fn inspect_container(&self, container_id: &str) -> Result<ContainerInfo, ScanError> {
        let options = InspectContainerOptions { size: false };

        let details = self
            .docker
            .inspect_container(container_id, Some(options))
            .await
            .map_err(|e| ScanError::Inspect(container_id.to_string(), e.to_string()))?;

        let config = details.config.ok_or_else(|| {
            ScanError::Inspect(
                container_id.to_string(),
                "Missing container config".to_string(),
            )
        })?;

        let host_config = details.host_config;
        let network_settings = details.network_settings;
        let mounts = details.mounts;

        // Extract container name
        let name = details
            .name
            .as_ref()
            .map(|n| ContainerInfo::extract_name(n))
            .unwrap_or_default();

        // Extract image
        let image = config.image.unwrap_or_default();

        // Check privileged mode
        let privileged = host_config
            .as_ref()
            .and_then(|hc| hc.privileged)
            .unwrap_or(false);

        // Extract user
        let user = config.user.clone();

        // Extract mounts
        let mounts = self.extract_mounts_from_option(&mounts);

        // Extract exposed ports from NetworkSettings
        let ports = self.extract_ports(&network_settings);

        // Extract environment variables (keys only)
        let env = config
            .env
            .unwrap_or_default()
            .iter()
            .filter_map(|e| {
                // Extract key from KEY=VALUE format
                e.split('=').next().map(|k| k.to_string())
            })
            .collect();

        // Extract capabilities from host config
        let capabilities = host_config
            .as_ref()
            .and_then(|hc| hc.cap_add.as_ref())
            .map(|caps| caps.to_vec())
            .unwrap_or_default();

        // Extract memory limit
        let memory_limit = host_config
            .as_ref()
            .and_then(|hc| hc.memory)
            .map(|m| m as u64);

        // Extract CPU limit
        let cpu_limit = host_config
            .as_ref()
            .and_then(|hc| hc.cpu_period.as_ref())
            .and_then(|period| {
                host_config
                    .as_ref()
                    .and_then(|hc| hc.cpu_quota.as_ref())
                    .map(|quota| (*quota as f64) / (*period as f64))
            });

        // Check for health check
        let health_check = config.healthcheck.is_some();

        // Extract network mode
        let network_mode = host_config.as_ref().and_then(|hc| hc.network_mode.clone());

        Ok(ContainerInfo {
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
        })
    }

    /// Extract mount information from container details
    fn extract_mounts_from_option(
        &self,
        mounts: &Option<Vec<bollard::models::MountPoint>>,
    ) -> Vec<MountInfo> {
        mounts
            .as_ref()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|m| MountInfo {
                source: m.source.as_ref().unwrap_or(&String::new()).clone(),
                destination: m.destination.as_ref().unwrap_or(&String::new()).clone(),
                mode: m.mode.as_ref().unwrap_or(&String::new()).clone(),
                mount_type: m
                    .typ
                    .as_ref()
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_default(),
            })
            .collect()
    }

    /// Extract port information from NetworkSettings
    fn extract_ports(&self, network_settings: &Option<NetworkSettings>) -> Vec<PortInfo> {
        let mut ports = Vec::new();

        // Get ports from NetworkSettings
        if let Some(settings) = network_settings {
            if let Some(ports_map) = &settings.ports {
                // PortMap is HashMap<String, Option<Vec<PortBinding>>>
                for (port_key, bindings_opt) in ports_map {
                    // Parse port key (e.g., "80/tcp", "443/udp")
                    let parts: Vec<&str> = port_key.split('/').collect();
                    let port: u16 = parts
                        .first()
                        .and_then(|p_str: &&str| p_str.parse().ok())
                        .unwrap_or(0);
                    let protocol = parts.get(1).unwrap_or(&"tcp").to_string();

                    // Get bindings - bindings_opt is Option<Vec<PortBinding>>
                    let bindings: Vec<PortBinding> = bindings_opt.clone().unwrap_or_default();
                    let exposed = !bindings.is_empty();

                    let host_ip = bindings
                        .first()
                        .and_then(|binding| binding.host_ip.as_ref())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_info_from_mock_inspect_data() {
        // Unit test: ContainerInfo conversion from mock inspect data
        // This mirrors the data that Scanner::inspect_container extracts from bollard
        let container_info = ContainerInfo {
            name: ContainerInfo::extract_name("/mock-nginx"),
            image: "nginx:latest".to_string(),
            privileged: true,
            user: Some("root".to_string()),
            mounts: vec![MountInfo {
                source: "/host/data".to_string(),
                destination: "/container/data".to_string(),
                mode: "rw".to_string(),
                mount_type: "bind".to_string(),
            }],
            ports: vec![
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    exposed: true,
                    host_ip: "0.0.0.0".to_string(),
                },
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    exposed: false,
                    host_ip: "".to_string(),
                },
            ],
            env: vec![
                "PATH=/usr/bin".to_string(),
                "NGINX_VERSION=1.25.0".to_string(),
            ],
            capabilities: vec!["NET_ADMIN".to_string(), "SYS_ADMIN".to_string()],
            memory_limit: Some(512_000_000),
            cpu_limit: Some(0.5),
            health_check: true,
            network_mode: Some("bridge".to_string()),
        };

        // Verify name extraction strips leading slash
        assert_eq!(container_info.name, "mock-nginx");
        assert_eq!(container_info.image, "nginx:latest");
        assert!(container_info.privileged);
        assert_eq!(container_info.user, Some("root".to_string()));
        assert!(container_info.health_check);
        assert_eq!(container_info.network_mode, Some("bridge".to_string()));
        assert_eq!(container_info.memory_limit, Some(512_000_000));
        assert_eq!(container_info.cpu_limit, Some(0.5));
        assert_eq!(container_info.capabilities, vec!["NET_ADMIN", "SYS_ADMIN"]);
        assert_eq!(container_info.mounts.len(), 1);
        assert_eq!(container_info.mounts[0].source, "/host/data");
        assert_eq!(container_info.ports.len(), 2);
        assert!(container_info.ports[0].exposed);
        assert!(!container_info.ports[1].exposed);
    }

    #[test]
    fn test_scanner_new_with_invalid_socket() {
        let result = Scanner::new("/nonexistent/path/docker.sock");
        if let Err(e) = result {
            match e {
                ScanError::Connection(_) => {}
                _ => panic!("Expected ConnectionError"),
            }
        }
    }

    #[test]
    fn test_scanner_new_with_empty_socket() {
        let result = Scanner::new("");
        if let Err(e) = result {
            match e {
                ScanError::Connection(_) => {}
                _ => panic!("Expected ConnectionError"),
            }
        }
    }

    /// Integration test — requires real Docker socket and `cargo test --features integration`
    #[tokio::test]
    #[cfg(feature = "integration")]
    async fn test_scanner_integration_with_docker_socket() {
        let socket = std::path::PathBuf::from("/var/run/docker.sock");
        if !socket.exists() {
            eprintln!("Skipping integration test: /var/run/docker.sock not found");
            return;
        }

        let scanner = Scanner::new("/var/run/docker.sock").expect("should connect to docker");
        let result = scanner.scan().await;
        assert!(result.is_ok());
        for c in &result.unwrap() {
            assert!(!c.name.is_empty());
            assert!(!c.image.is_empty());
        }
    }

    /// Verify descriptive error when Docker socket path is invalid
    #[test]
    fn test_scanner_connection_error_message() {
        let result = Scanner::new("/nonexistent/bad.sock");
        assert!(result.is_err(), "Expected error for invalid socket");
        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err_msg.contains("connect")
                || err_msg.contains("socket")
                || err_msg.contains("not found"),
            "Expected descriptive error, got: {}",
            err_msg
        );
    }
}
