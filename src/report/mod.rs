//! Reporter — formats and displays security findings

use crate::finding::{Finding, Severity};
use owo_colors::OwoColorize;

/// Reporter that formats findings for terminal output
pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Reporter
    }

    /// Report all findings to stdout
    pub fn report(&self, findings: &[Finding]) {
        if findings.is_empty() {
            println!("✅ No security issues found.");
            return;
        }

        // Group by severity
        let critical: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Critical).collect();
        let high: Vec<_> = findings.iter().filter(|f| f.severity == Severity::High).collect();
        let medium: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Medium).collect();
        let low: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Low).collect();
        let info: Vec<_> = findings.iter().filter(|f| f.severity == Severity::Info).collect();

        println!();

        if !critical.is_empty() {
            self.print_group_critical("CRITICAL", &critical);
        }
        if !high.is_empty() {
            self.print_group_high("HIGH", &high);
        }
        if !medium.is_empty() {
            self.print_group_medium("MEDIUM", &medium);
        }
        if !low.is_empty() {
            self.print_group_low("LOW", &low);
        }
        if !info.is_empty() {
            self.print_group_info("INFO", &info);
        }

        println!();
        self.print_summary(findings);
    }

    fn print_group_critical(&self, label: &str, findings: &[&Finding]) {
        println!("{}", format!("━━━ {} ━━━", label).on_red().white().bold());
        for finding in findings {
            println!("  [{}] {}", finding.container_name.red().bold(), finding.message);
            if let Some(ref rem) = finding.remediation {
                println!("    → {}", rem);
            }
        }
        println!();
    }

    fn print_group_high(&self, label: &str, findings: &[&Finding]) {
        println!("{}", format!("━━━ {} ━━━", label).on_yellow().black());
        for finding in findings {
            println!("  [{}] {}", finding.container_name.on_yellow().black(), finding.message);
            if let Some(ref rem) = finding.remediation {
                println!("    → {}", rem);
            }
        }
        println!();
    }

    fn print_group_medium(&self, label: &str, findings: &[&Finding]) {
        println!("{}", format!("━━━ {} ━━━", label).on_yellow().black());
        for finding in findings {
            println!("  [{}] {}", finding.container_name.on_yellow().black(), finding.message);
            if let Some(ref rem) = finding.remediation {
                println!("    → {}", rem);
            }
        }
        println!();
    }

    fn print_group_low(&self, label: &str, findings: &[&Finding]) {
        println!("{}", format!("━━━ {} ━━━", label).on_cyan().black());
        for finding in findings {
            println!("  [{}] {}", finding.container_name.on_cyan().black(), finding.message);
            if let Some(ref rem) = finding.remediation {
                println!("    → {}", rem);
            }
        }
        println!();
    }

    fn print_group_info(&self, label: &str, findings: &[&Finding]) {
        println!("{}", format!("━━━ {} ━━━", label).cyan());
        for finding in findings {
            println!("  [{}] {}", finding.container_name.cyan(), finding.message);
            if let Some(ref rem) = finding.remediation {
                println!("    → {}", rem);
            }
        }
        println!();
    }

    fn print_summary(&self, findings: &[Finding]) {
        let total = findings.len();
        let by_container: std::collections::HashMap<_, _> = findings
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, f| {
                *acc.entry(&f.container_name).or_insert(0) += 1;
                acc
            });

        println!("─── Summary ───────────────────────────────────────────");
        println!("  Total findings: {}", total);
        for (container, count) in by_container {
            println!("  • {}: {} finding(s)", container, count);
        }
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn test_report_with_no_findings() {
        let reporter = Reporter::new();
        reporter.report(&[]);
    }

    #[test]
    fn test_report_with_single_finding() {
        let reporter = Reporter::new();
        let findings = vec![Finding::new(
            "PrivilegedCheck".to_string(),
            "nginx".to_string(),
            Severity::Critical,
            "Container is running in privileged mode".to_string(),
            Some("Remove privileged mode".to_string()),
        )];
        reporter.report(&findings);
    }

    #[test]
    fn test_report_with_multiple_findings() {
        let reporter = Reporter::new();
        let findings = vec![
            Finding::new("PrivilegedCheck".to_string(), "web".to_string(), Severity::Critical, "privileged".to_string(), None),
            Finding::new("RootUserCheck".to_string(), "web".to_string(), Severity::High, "running as root".to_string(), None),
            Finding::new("ExposedPortsCheck".to_string(), "db".to_string(), Severity::Medium, "port 5432 exposed".to_string(), None),
        ];
        reporter.report(&findings);
    }
}
