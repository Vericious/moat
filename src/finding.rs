use serde::Serialize;
use std::fmt;

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

/// A security finding from a container check
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Name of the check that produced this finding
    pub check_name: String,
    /// Name of the affected container
    pub container_name: String,
    /// Severity level of the finding
    pub severity: Severity,
    /// Human-readable description of the finding
    pub message: String,
    /// Suggested remediation steps, if available
    pub remediation: Option<String>,
}

impl Finding {
    /// Create a new Finding
    pub fn new(
        check_name: String,
        container_name: String,
        severity: Severity,
        message: String,
        remediation: Option<String>,
    ) -> Self {
        Finding {
            check_name,
            container_name,
            severity,
            message,
            remediation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_critical_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_severity_all_variants_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Info.to_string(), "Info");
    }

    #[test]
    fn test_finding_creation_with_all_fields() {
        let finding = Finding::new(
            "PrivilegedCheck".to_string(),
            "web-server".to_string(),
            Severity::Critical,
            "Container is running in privileged mode".to_string(),
            Some("Remove privileged mode from container configuration".to_string()),
        );

        assert_eq!(finding.check_name, "PrivilegedCheck");
        assert_eq!(finding.container_name, "web-server");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.message, "Container is running in privileged mode");
        assert_eq!(
            finding.remediation,
            Some("Remove privileged mode from container configuration".to_string())
        );
    }

    #[test]
    fn test_finding_creation_without_remediation() {
        let finding = Finding::new(
            "ExposedPortsCheck".to_string(),
            "db-server".to_string(),
            Severity::Medium,
            "Port 5432 is exposed to the host".to_string(),
            None,
        );

        assert_eq!(finding.check_name, "ExposedPortsCheck");
        assert!(finding.remediation.is_none());
    }

    #[test]
    fn test_finding_serialization_to_json() {
        let finding = Finding::new(
            "RootUserCheck".to_string(),
            "app-container".to_string(),
            Severity::High,
            "Container is running as root user".to_string(),
            Some("Use a non-root user in the container".to_string()),
        );

        let json = serde_json::to_string(&finding).expect("Failed to serialize Finding");
        assert!(json.contains("\"check_name\":\"RootUserCheck\""));
        assert!(json.contains("\"container_name\":\"app-container\""));
        assert!(json.contains("\"severity\":\"High\""));
        assert!(json.contains("\"message\":\"Container is running as root user\""));
        assert!(json.contains("\"remediation\""));
    }

    #[test]
    fn test_finding_debug_impl() {
        let finding = Finding::new(
            "SocketMountCheck".to_string(),
            "test-container".to_string(),
            Severity::Low,
            "Docker socket is mounted".to_string(),
            None,
        );

        let debug_str = format!("{:?}", finding);
        assert!(debug_str.contains("SocketMountCheck"));
        assert!(debug_str.contains("test-container"));
    }

    #[test]
    fn test_finding_clone() {
        let finding = Finding::new(
            "HostMountsCheck".to_string(),
            "cache".to_string(),
            Severity::Info,
            "Host directory mounted".to_string(),
            None,
        );

        let cloned = finding.clone();
        assert_eq!(finding.check_name, cloned.check_name);
        assert_eq!(finding.container_name, cloned.container_name);
        assert_eq!(finding.severity, cloned.severity);
    }
}
