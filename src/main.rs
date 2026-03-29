mod checks;
mod models;
mod output;
mod scanner;

use clap::{Parser, ValueEnum};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "moat")]
#[command(about = "Homelab security posture scanner — know what's exposed before someone else does")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Scan running Docker containers for security issues
    Scan {
        /// Only scan a specific container by name or ID
        #[arg(long)]
        container: Option<String>,

        /// Minimum severity to report
        #[arg(long, default_value = "info")]
        severity: SeverityFilter,

        /// Output format
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,

        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
enum SeverityFilter {
    Info,
    Medium,
    High,
    Critical,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Markdown,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            container,
            severity,
            format,
            output,
        } => match scanner::run_scan(container.as_deref()).await {
            Ok(findings) => {
                let filtered = models::filter_by_severity(&findings, &severity);
                let rendered = match format {
                    OutputFormat::Terminal => output::render_terminal(&filtered),
                    OutputFormat::Json => output::render_json(&filtered),
                    OutputFormat::Markdown => output::render_markdown(&filtered),
                };

                if let Some(path) = output {
                    if let Err(e) = std::fs::write(&path, &rendered) {
                        eprintln!("Error writing to {path}: {e}");
                        return ExitCode::from(3);
                    }
                } else {
                    print!("{rendered}");
                }

                let exit = models::worst_severity(&filtered);
                ExitCode::from(exit)
            }
            Err(e) => {
                eprintln!("Scan error: {e}");
                ExitCode::from(3)
            }
        },
    }
}
