//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use shorwatch_core::Severity;

#[derive(Debug, Parser)]
#[command(
    name = "shorwatch",
    version,
    about = "Find quantum-vulnerable cryptography in source code and configuration.",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files or directories (respects .gitignore).
    #[command(after_help = EXIT_CODES)]
    Scan(ScanArgs),
    /// List the rules that would be applied.
    Rules(RulesArgs),
}

const EXIT_CODES: &str = "\
Exit codes:
  0  no findings that fail the scan (see --fail-on)
  1  findings that fail the scan
  2  error (bad arguments, invalid rules, unreadable paths)";

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Write the report to a file instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub rules: RuleSource,

    /// Only report findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub min_severity: SeverityArg,

    /// When to exit with code 1.
    #[arg(long, value_enum, default_value_t = FailOn::Vulnerable)]
    pub fail_on: FailOn,

    /// Skip test code: Maven/Gradle test source sets (`src/test`,
    /// `src/integrationTest`...), test directories and `*Test`/`*IT` classes.
    /// Without it, findings in test code are reported and labelled.
    #[arg(long)]
    pub exclude_tests: bool,

    /// One line per finding (text format only).
    #[arg(long)]
    pub compact: bool,

    /// Do not print the banner.
    #[arg(long)]
    pub no_banner: bool,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(flatten)]
    pub rules: RuleSource,
}

#[derive(Debug, Args)]
pub struct RuleSource {
    /// Extra rules directory, on top of the built-in rules (repeatable).
    #[arg(long = "rules", value_name = "DIR")]
    pub dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable, coloured on terminals.
    Text,
    /// SARIF 2.1.0 (GitHub code scanning, GitLab, IDEs).
    Sarif,
    /// CycloneDX 1.6 CBOM: an inventory of the cryptography found.
    Cbom,
    /// JSON, for scripts and other tools.
    Json,
    /// Markdown summary (CI job summaries, PR comments).
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Any finding still vulnerable (not in transition).
    Vulnerable,
    /// Any finding at all.
    Any,
    /// Never fail; always exit 0 unless there is an error.
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}
