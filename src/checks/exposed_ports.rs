use crate::checks::Check;
use crate::container::ContainerInfo;
use crate::finding::{Finding, Severity};

/// Check for dangerously exposed ports in containers
pub struct ExposedPortsCheck;

impl ExposedPortsCheck {
    pub fn new() -> Self {
        ExposedPortsCheck
    }
}

impl Default for ExposedPortsCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ExposedPortsCheck {
    fn name(&self) -> &str {
        "ExposedPortsCheck"
    }

    fn run(&self, container: &ContainerInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for port in &container.ports {
            if !port.exposed {
                continue;
            }

            let severity = match port.host_ip.as_str() {
                "0.0.0.0" | "" => Severity::Medium, // Bound to all interfaces
                "127.0.0.1" => Severity::Low,       // Bound to localhost only
                _ => Severity::Low,                 // Bound to specific IP
            };

            let bind_desc = if port.host_ip.is_empty() || port.host_ip == "0.0.0.0" {
                format!("{}:{}", "0.0.0.0", port.port)
            } else {
                format!("{}:{}", port.host_ip, port.port)
            };

            findings.push(Finding::new(
                self.name().to_string(),
                container.name.clone(),
                severity,
                format!(
                    "Container '{}' has port {} exposed on {}",
                    container.name, port.port, bind_desc
                ),
                Some("Bind to 127.0.0.1 or use a reverse proxy to restrict access".to_string()),
            ));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ContainerInfo, PortInfo};

    fn make_port(port: u16, exposed: bool, host_ip: &str) -> PortInfo {
        PortInfo {
            port,
            protocol: "tcp".to_string(),
            exposed,
            host_ip: host_ip.to_string(),
        }
    }

    fn make_container_with_ports(ports: Vec<PortInfo>) -> ContainerInfo {
        ContainerInfo {
            name: "test-container".to_string(),
            image: "nginx:latest".to_string(),
            ports,
            ..Default::default()
        }
    }

    #[test]
    fn test_0_0_0_0_8080_triggers_medium() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![make_port(8080, true, "0.0.0.0")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("0.0.0.0"));
        assert!(findings[0].message.contains("8080"));
    }

    #[test]
    fn test_127_0_0_1_8080_triggers_low() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![make_port(8080, true, "127.0.0.1")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_no_ports_produces_no_findings() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_unexposed_port_produces_no_findings() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![make_port(8080, false, "0.0.0.0")]);
        let findings = check.run(&container);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_empty_host_ip_triggers_medium() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![make_port(8080, true, "")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_specific_ip_triggers_low() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![make_port(8080, true, "192.168.1.100")]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_multiple_exposed_ports() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![
            make_port(80, true, "0.0.0.0"),
            make_port(443, true, "0.0.0.0"),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_mixed_exposed_and_unexposed() {
        let check = ExposedPortsCheck::new();
        let container = make_container_with_ports(vec![
            make_port(80, true, "0.0.0.0"),
            make_port(443, false, "0.0.0.0"),
        ]);
        let findings = check.run(&container);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
