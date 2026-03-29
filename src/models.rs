use serde::Serialize;

use crate::SeverityFilter;

/// Severity level of a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// A single security finding from a check.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Container name or ID this finding relates to.
    pub container: String,
    /// Unique check identifier (e.g. "privileged-mode").
    pub check_id: String,
    /// Severity level.
    pub severity: Severity,
    /// Short title (e.g. "Container running in privileged mode").
    pub title: String,
    /// Plain-English explanation of the issue.
    pub message: String,
    /// Suggested fix command or action.
    pub fix: String,
}

/// Filter findings by minimum severity threshold.
pub fn filter_by_severity(findings: &[Finding], min: &SeverityFilter) -> Vec<Finding> {
    let threshold = match min {
        SeverityFilter::Info => Severity::Info,
        SeverityFilter::Medium => Severity::Medium,
        SeverityFilter::High => Severity::High,
        SeverityFilter::Critical => Severity::Critical,
    };
    findings
        .iter()
        .filter(|f| f.severity >= threshold)
        .cloned()
        .collect()
}

/// Return exit code based on worst finding severity.
/// 0 = clean, 1 = high, 2 = critical, 3 = error (handled elsewhere).
pub fn worst_severity(findings: &[Finding]) -> u8 {
    let worst = findings.iter().map(|f| &f.severity).max();
    match worst {
        Some(Severity::Critical) => 2,
        Some(Severity::High) => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Info);
    }

    #[test]
    fn worst_severity_empty() {
        assert_eq!(worst_severity(&[]), 0);
    }

    #[test]
    fn worst_severity_critical() {
        let findings = vec![Finding {
            container: "test".into(),
            check_id: "test".into(),
            severity: Severity::Critical,
            title: "test".into(),
            message: "test".into(),
            fix: "test".into(),
        }];
        assert_eq!(worst_severity(&findings), 2);
    }

    #[test]
    fn filter_by_high() {
        let findings = vec![
            Finding {
                container: "a".into(),
                check_id: "t".into(),
                severity: Severity::Info,
                title: "t".into(),
                message: "t".into(),
                fix: "t".into(),
            },
            Finding {
                container: "b".into(),
                check_id: "t".into(),
                severity: Severity::High,
                title: "t".into(),
                message: "t".into(),
                fix: "t".into(),
            },
        ];
        let filtered = filter_by_severity(&findings, &SeverityFilter::High);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].container, "b");
    }
}
