//! Reporter — formats and displays security findings

pub mod json;
pub mod markdown;

use crate::finding::{Finding, Severity};
use crate::report::json::JsonReporter;
use crate::report::markdown::MarkdownReporter;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReporterError {
    #[error("Unknown output format: {0}")]
    UnknownFormat(String),
}

/// Reporter trait for formatting and displaying security findings
pub trait Reporter: Send + Sync {
    /// Format findings and return the report as a string
    fn report(&self, findings: &[Finding]) -> String;
}

/// Reporter that formats findings for terminal output with ANSI colors
pub struct TerminalReporter;

impl TerminalReporter {
    pub fn new() -> Self {
        TerminalReporter
    }

    fn format_summary(&self, findings: &[Finding]) -> String {
        let total = findings.len();
        let by_container: std::collections::HashMap<_, _> = findings
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                *acc.entry(&f.container_name).or_insert(0) += 1;
                acc
            });

        let mut output = String::from("─── Summary ───────────────────────────────────────────\n");
        output.push_str(&format!("  Total findings: {}\n", total));
        for (container, count) in by_container {
            output.push_str(&format!("  • {}: {} finding(s)\n", container, count));
        }
        output
    }
}

impl Default for TerminalReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for TerminalReporter {
    fn report(&self, findings: &[Finding]) -> String {
        if findings.is_empty() {
            return "✅ No security issues found.".to_string();
        }

        // Group by severity
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        let high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
        let medium: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Medium).collect();
        let low: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Low).collect();
        let info: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Info).collect();

        let mut output = String::new();

        if !critical.is_empty() {
            output.push_str(&format!(
                "\n{}",
                "\u{001B}[41;37;1m━━━ CRITICAL ━━━\u{001B}[0m"
            ));
            for finding in &critical {
                output.push_str(&format!("\n  [{}] {} ({})\n", finding.container_name, finding.message, finding.check_name));
                if let Some(ref rem) = finding.remediation {
                    output.push_str(&format!("    → {}\n", rem));
                }
            }
            output.push('\n');
        }
        if !high.is_empty() {
            output.push_str("\n\u{001B}[43;30m━━━ HIGH ━━━\u{001B}[0m\n");
            for finding in &high {
                output.push_str(&format!("  [{}] {} ({})\n", finding.container_name, finding.message, finding.check_name));
                if let Some(ref rem) = finding.remediation {
                    output.push_str(&format!("    → {}\n", rem));
                }
            }
            output.push('\n');
        }
        if !medium.is_empty() {
            output.push_str("\n\u{001B}[43;30m━━━ MEDIUM ━━━\u{001B}[0m\n");
            for finding in &medium {
                output.push_str(&format!("  [{}] {} ({})\n", finding.container_name, finding.message, finding.check_name));
                if let Some(ref rem) = finding.remediation {
                    output.push_str(&format!("    → {}\n", rem));
                }
            }
            output.push('\n');
        }
        if !low.is_empty() {
            output.push_str("\n\u{001B}[46;30m━━━ LOW ━━━\u{001B}[0m\n");
            for finding in &low {
                output.push_str(&format!("  [{}] {} ({})\n", finding.container_name, finding.message, finding.check_name));
                if let Some(ref rem) = finding.remediation {
                    output.push_str(&format!("    → {}\n", rem));
                }
            }
            output.push('\n');
        }
        if !info.is_empty() {
            output.push_str("\n\u{001B}[36m━━━ INFO ━━━\u{001B}[0m\n");
            for finding in &info {
                output.push_str(&format!("  [{}] {} ({})\n", finding.container_name, finding.message, finding.check_name));
                if let Some(ref rem) = finding.remediation {
                    output.push_str(&format!("    → {}\n", rem));
                }
            }
            output.push('\n');
        }

        output.push_str(&self.format_summary(findings));
        output
    }
}

/// Get a reporter for the given format name
///
/// # Errors
///
/// Returns an error if the format is unknown
pub fn get_reporter(format: &str) -> Result<Box<dyn Reporter>, ReporterError> {
    match format {
        "terminal" => Ok(Box::new(TerminalReporter::new())),
        "json" => Ok(Box::new(JsonReporter::new())),
        "markdown" => Ok(Box::new(MarkdownReporter::new())),
        _ => Err(ReporterError::UnknownFormat(format.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_reporter_json() {
        let reporter = get_reporter("json");
        assert!(reporter.is_ok());
        let r = reporter.unwrap();
        // Verify it produces JSON output
        let findings = vec![Finding::new(
            "PrivilegedCheck".to_string(),
            "nginx".to_string(),
            Severity::Critical,
            "Container is running in privileged mode".to_string(),
            Some("Remove privileged mode".to_string()),
        )];
        let output = r.report(&findings);
        assert!(output.contains("\"check_name\": \"PrivilegedCheck\""));
    }

    #[test]
    fn test_get_reporter_terminal() {
        let reporter = get_reporter("terminal");
        assert!(reporter.is_ok());
        let r = reporter.unwrap();
        let findings = vec![Finding::new(
            "RootUserCheck".to_string(),
            "web".to_string(),
            Severity::High,
            "running as root".to_string(),
            None,
        )];
        let output = r.report(&findings);
        eprintln!("TERMINAL OUTPUT: {}", output);
        assert!(output.contains("RootUserCheck"));
    }

    #[test]
    fn test_get_reporter_unknown_returns_error() {
        match get_reporter("xml") {
            Err(e) => assert!(e.to_string().contains("Unknown output format: xml")),
            Ok(_) => panic!("Expected error for unknown format 'xml'"),
        }
    }

    #[test]
    fn test_reporter_trait_is_object_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn Reporter>>();
    }

    #[test]
    fn test_terminal_reporter_with_no_findings() {
        let reporter = TerminalReporter::new();
        let output = reporter.report(&[]);
        assert!(output.contains("No security issues found"));
    }

    #[test]
    fn test_json_reporter_with_no_findings() {
        let reporter = JsonReporter::new();
        let output = reporter.report(&[]);
        // New format is { scan_time, container_count, finding_count, findings: [] }
        assert!(output.contains("\"finding_count\": 0"));
        assert!(output.contains("\"findings\": []"));
    }

    #[test]
    fn test_markdown_reporter_with_no_findings() {
        let reporter = MarkdownReporter::new();
        let output = reporter.report(&[]);
        assert!(output.contains("No security issues found"));
    }
}
