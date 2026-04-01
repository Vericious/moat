use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod container;
mod finding;
mod scanner;

/// Homelab Docker security scanner
#[derive(Parser)]
#[command(
    name = "moat",
    about = "Homelab Docker security scanner",
    version,
    infer_subcommands = true
)]
struct Cli {
    /// Output format
    #[arg(short, long, default_value = "terminal")]
    format: OutputFormat,

    /// Path to Docker socket
    #[arg(short, long, default_value = "/var/run/docker.sock")]
    socket: PathBuf,

    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan running containers for security issues
    Scan {
        /// Path to Docker socket (overrides global --socket)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },
    /// Show version information
    Version,
}

#[derive(Clone, Debug, PartialEq, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Markdown,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Terminal => write!(f, "terminal"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Markdown => write!(f, "markdown"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub format: OutputFormat,
    pub socket: PathBuf,
    pub verbose: bool,
}

impl From<&Cli> for Config {
    fn from(cli: &Cli) -> Self {
        Config {
            format: cli.format.clone(),
            socket: cli.socket.clone(),
            verbose: cli.verbose,
        }
    }
}

impl From<(OutputFormat, PathBuf, bool)> for Config {
    fn from((format, socket, verbose): (OutputFormat, PathBuf, bool)) -> Self {
        Config {
            format,
            socket,
            verbose,
        }
    }
}

fn run_version() {
    println!("moat v{}", env!("CARGO_PKG_VERSION"));
}

fn run_scan(config: &Config) -> anyhow::Result<()> {
    if config.verbose {
        eprintln!("Scanning containers via socket: {:?}", config.socket);
    }
    println!("Scan complete (no containers checked yet)");
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let config = match &cli.command {
        Some(Commands::Scan { socket }) => {
            let socket = socket.clone().unwrap_or(cli.socket);
            Config::from((cli.format, socket, cli.verbose))
        }
        Some(Commands::Version) => {
            run_version();
            return;
        }
        None => Config::from(&cli),
    };

    if config.verbose {
        eprintln!("Format: {}", config.format);
        eprintln!("Socket: {:?}", config.socket);
    }

    if let Err(e) = run_scan(&config) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path() {
        let cli = Cli::parse_from(["moat"]);
        assert_eq!(cli.socket, PathBuf::from("/var/run/docker.sock"));
    }

    #[test]
    fn test_format_parsing() {
        let cli = Cli::parse_from(["moat", "--format", "json"]);
        assert_eq!(cli.format, OutputFormat::Json);
    }

    #[test]
    fn test_format_parsing_markdown() {
        let cli = Cli::parse_from(["moat", "--format", "markdown"]);
        assert_eq!(cli.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_format_parsing_terminal() {
        let cli = Cli::parse_from(["moat", "--format", "terminal"]);
        assert_eq!(cli.format, OutputFormat::Terminal);
    }

    #[test]
    fn test_unknown_format_returns_error() {
        let result = Cli::try_parse_from(["moat", "--format", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verbose_flag() {
        let cli = Cli::parse_from(["moat", "--verbose"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_verbose_flag_short() {
        let cli = Cli::parse_from(["moat", "-v"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_config_from_cli() {
        let cli = Cli::parse_from(["moat", "--format", "json", "--socket", "/custom.sock", "-v"]);
        let config = Config::from(&cli);
        assert_eq!(config.format, OutputFormat::Json);
        assert_eq!(config.socket, PathBuf::from("/custom.sock"));
        assert!(config.verbose);
    }

    #[test]
    fn test_scan_subcommand_socket_override() {
        let cli = Cli::parse_from(["moat", "scan", "--socket", "/override.sock"]);
        match cli.command {
            Some(Commands::Scan { socket }) => {
                assert_eq!(socket, Some(PathBuf::from("/override.sock")));
            }
            _ => panic!("Expected Scan subcommand"),
        }
    }

    #[test]
    fn test_version_subcommand() {
        let cli = Cli::parse_from(["moat", "version"]);
        match cli.command {
            Some(Commands::Version) => {}
            _ => panic!("Expected Version subcommand"),
        }
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Terminal.to_string(), "terminal");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Markdown.to_string(), "markdown");
    }
}
