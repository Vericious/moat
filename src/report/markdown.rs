//! Markdown reporter for human-readable output

use crate::finding::{Finding, Severity};

pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn new() -> Self {
        MarkdownReporter
    }
}

impl Default for MarkdownReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Reporter for MarkdownReporter {
    fn report(&self, findings: &[Finding]) -> String {
        if findings.is_empty() {
            return "✅ No security issues found.".to_string();
        }

        let mut output = String::from("# Security Scan Report\n\n");

        // Group by severity
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        let high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
        let medium: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Medium).collect();
        let low: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Low).collect();
        let info: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Info).collect();

        if !critical.is_empty() {
            output.push_str("## 🔴 Critical\n\n");
            for f in &critical {
                output.push_str(&format!("- **[{}]** [{}] {}  \n", f.container_name, f.check_name, f.message));
                if let Some(ref rem) = f.remediation {
                    output.push_str(&format!("  - Remediation: {}\n", rem));
                }
            }
            output.push('\n');
        }

        if !high.is_empty() {
            output.push_str("## 🟠 High\n\n");
            for f in &high {
                output.push_str(&format!("- **[{}]** [{}] {}  \n", f.container_name, f.check_name, f.message));
                if let Some(ref rem) = f.remediation {
                    output.push_str(&format!("  - Remediation: {}\n", rem));
                }
            }
            output.push('\n');
        }

        if !medium.is_empty() {
            output.push_str("## 🟡 Medium\n\n");
            for f in &medium {
                output.push_str(&format!("- **[{}]** [{}] {}  \n", f.container_name, f.check_name, f.message));
                if let Some(ref rem) = f.remediation {
                    output.push_str(&format!("  - Remediation: {}\n", rem));
                }
            }
            output.push('\n');
        }

        if !low.is_empty() {
            output.push_str("## 🔵 Low\n\n");
            for f in &low {
                output.push_str(&format!("- **[{}]** [{}] {}  \n", f.container_name, f.check_name, f.message));
                if let Some(ref rem) = f.remediation {
                    output.push_str(&format!("  - Remediation: {}\n", rem));
                }
            }
            output.push('\n');
        }

        if !info.is_empty() {
            output.push_str("## ℹ️ Info\n\n");
            for f in &info {
                output.push_str(&format!("- **[{}]** [{}] {}  \n", f.container_name, f.check_name, f.message));
                if let Some(ref rem) = f.remediation {
                    output.push_str(&format!("  - Remediation: {}\n", rem));
                }
            }
            output.push('\n');
        }

        // Summary
        output.push_str("## Summary\n\n");
        let total = findings.len();
        let by_container: std::collections::HashMap<_, _> = findings
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                *acc.entry(&f.container_name).or_insert(0) += 1;
                acc
            });

        output.push_str(&format!("- **Total findings:** {}  \n", total));
        for (container, count) in by_container {
            output.push_str(&format!("- **{}:** {} finding(s)  \n", container, count));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use crate::report::Reporter;
    use crate::finding::{Finding, Severity};
    // MarkdownReporter is defined in the parent module
    use super::MarkdownReporter;

    #[test]
    fn test_markdown_reporter_empty_findings() {
        let reporter = MarkdownReporter::new();
        let output = reporter.report(&[]);
        assert!(output.contains("No security issues found"));
    }

    #[test]
    fn test_markdown_reporter_with_finding() {
        let reporter = MarkdownReporter::new();
        let findings = vec![Finding::new(
            "PrivilegedCheck".to_string(),
            "nginx".to_string(),
            Severity::Critical,
            "Container is running in privileged mode".to_string(),
            Some("Remove privileged mode".to_string()),
        )];
        let output = reporter.report(&findings);
        assert!(output.contains("PrivilegedCheck"));
        assert!(output.contains("nginx"));
    }

    #[test]
    fn test_markdown_reporter_includes_summary() {
        let reporter = MarkdownReporter::new();
        let findings = vec![Finding::new(
            "RootUserCheck".to_string(),
            "web".to_string(),
            Severity::High,
            "running as root".to_string(),
            None,
        )];
        let output = reporter.report(&findings);
        assert!(output.contains("Summary"));
        assert!(output.contains("Total findings"));
    }
}
