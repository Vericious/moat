use colored::Colorize;

use crate::models::{Finding, Severity};

/// Render findings as colored terminal output.
pub fn render_terminal(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return format!("{}\n", "✅ No security issues found.".green().bold());
    }

    let mut out = String::new();

    // Group by container
    let mut containers: std::collections::BTreeMap<&str, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        containers.entry(&f.container).or_default().push(f);
    }

    for (container, container_findings) in &containers {
        out.push_str(&format!("\n{}\n", format!("── {container} ──").bold()));

        for f in container_findings {
            let severity_badge = match f.severity {
                Severity::Critical => "🔴 CRITICAL".red().bold().to_string(),
                Severity::High => "🟠 HIGH".yellow().bold().to_string(),
                Severity::Medium => "🟡 MEDIUM".yellow().to_string(),
                Severity::Info => "🟢 INFO".green().to_string(),
            };

            out.push_str(&format!("  {severity_badge} {}\n", f.title));
            out.push_str(&format!("    {}\n", f.message));
            out.push_str(&format!("    {} {}\n\n", "Fix:".bold(), f.fix));
        }
    }

    // Summary
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

    out.push_str(&format!(
        "\nScanned {} container(s): {} critical, {} high, {} medium, {} info finding(s)\n",
        containers.len(),
        critical,
        high,
        medium,
        info,
    ));

    out
}

/// Render findings as JSON.
pub fn render_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

/// Render findings as Markdown.
pub fn render_markdown(findings: &[Finding]) -> String {
    let mut out = String::from("# Moat Security Report\n\n");

    if findings.is_empty() {
        out.push_str("✅ No security issues found.\n");
        return out;
    }

    // Group by container
    let mut containers: std::collections::BTreeMap<&str, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        containers.entry(&f.container).or_default().push(f);
    }

    for (container, container_findings) in &containers {
        out.push_str(&format!("## {container}\n\n"));

        for f in container_findings {
            let emoji = match f.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Info => "🟢",
            };

            out.push_str(&format!(
                "### {emoji} {} ({})\n\n{}\n\n**Fix:** {}\n\n",
                f.title, f.severity, f.message, f.fix
            ));
        }
    }

    // Summary
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

    out.push_str(&format!(
        "---\n\n**Summary:** {} critical, {} high, {} medium, {} info finding(s) across {} container(s)\n",
        critical, high, medium, info, containers.len()
    ));

    out
}
