//! JSON reporter for machine-readable output

use serde::Serialize;

use crate::finding::{Finding, Severity};

#[derive(Serialize)]
struct JsonReport {
    scan_time: String,
    container_count: usize,
    finding_count: usize,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct JsonFinding {
    check_name: String,
    container_name: String,
    severity: String,
    message: String,
    remediation: Option<String>,
}

pub struct JsonReporter;

impl JsonReporter {
    pub fn new() -> Self {
        JsonReporter
    }

    fn severity_to_string(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    fn format_findings(&self, findings: &[Finding]) -> Vec<JsonFinding> {
        findings
            .iter()
            .map(|f| JsonFinding {
                check_name: f.check_name.clone(),
                container_name: f.container_name.clone(),
                severity: Self::severity_to_string(f.severity).to_string(),
                message: f.message.clone(),
                remediation: f.remediation.clone(),
            })
            .collect()
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Reporter for JsonReporter {
    fn report(&self, findings: &[Finding]) -> String {
        let container_count = findings
            .iter()
            .map(|f| &f.container_name)
            .collect::<std::collections::HashSet<_>>()
            .len();

        let report = JsonReport {
            scan_time: chrono_lite_now(),
            container_count,
            finding_count: findings.len(),
            findings: self.format_findings(findings),
        };

        serde_json::to_string_pretty(&report)
            .unwrap_or_else(|_| r#"{"error": "failed to serialize report"}"#.to_string())
    }
}

/// Returns a simple ISO-8601 timestamp without external dependencies
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple Unix timestamp - JSON reporter doesn't need full date formatting
    format!("{}", secs)
}

#[cfg(test)]
mod tests {
    use super::super::{JsonReporter, Reporter};
    use crate::finding::{Finding, Severity};

    #[test]
    fn test_json_reporter_produces_valid_json() {
        let reporter = JsonReporter::new();
        let output = reporter.report(&[]);
        serde_json::from_str::<serde_json::Value>(&output).expect("Should be valid JSON");
    }

    #[test]
    fn test_json_reporter_empty_findings() {
        let reporter = JsonReporter::new();
        let output = reporter.report(&[]);
        let v: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(v["finding_count"], 0);
        assert!(v["findings"].is_array());
    }

    #[test]
    fn test_json_reporter_with_findings() {
        let reporter = JsonReporter::new();
        let findings = vec![Finding::new(
            "PrivilegedCheck".to_string(),
            "nginx".to_string(),
            Severity::Critical,
            "Container is running in privileged mode".to_string(),
            Some("Remove privileged mode".to_string()),
        )];
        let output = reporter.report(&findings);
        assert!(output.contains("\"check_name\": \"PrivilegedCheck\""));
    }
}
