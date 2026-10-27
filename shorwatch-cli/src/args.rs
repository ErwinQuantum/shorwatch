//! Command-line interface definition.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use shorwatch_core::Severity;

/// Without a subcommand, `shorwatch [PATHS] [OPTIONS]` scans like
/// `shorwatch scan`.
#[derive(Debug, Parser)]
#[command(
    name = "shorwatch",
    version,
    about = "Find quantum-vulnerable cryptography in source code and configuration.",
    long_about = None,
    args_conflicts_with_subcommands = true,
    after_help = USAGE,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub scan: ScanArgs,
}

const USAGE: &str = "\
Without a command, scans like `shorwatch scan`:
  shorwatch                 count what the current project holds, link the HTML report
  shorwatch --details       every finding, in the terminal
  shorwatch --watch         scan again whenever a file changes
  shorwatch report          scan and open the HTML report in the browser
  shorwatch ci              scan in a CI pipeline (SARIF + HTML, linked from the log)
  shorwatch baseline        record today's findings: later scans report only new ones";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files or directories (respects .gitignore).
    #[command(after_help = EXIT_CODES)]
    Scan(ScanArgs),
    /// Scan and open the HTML report in the browser (`scan --open`).
    #[command(after_help = EXIT_CODES)]
    Report(ScanArgs),
    /// Scan in a CI pipeline: SARIF and HTML reports, linked from the log.
    ///
    /// Writes `report.sarif` and `report.html` to one folder to publish as
    /// the job's artifact, and prints the summary with a link to the report
    /// where the CI system serves it (GitHub Actions, GitLab CI, Jenkins and
    /// Azure Pipelines are recognised; elsewhere, see --report-url). On
    /// GitHub Actions the summary also goes to the job summary.
    #[command(after_help = EXIT_CODES)]
    Ci(CiArgs),
    /// Record today's findings in a baseline: later scans report only new
    /// ones.
    ///
    /// Writes `shorwatch-baseline.json`; commit it, and scans run from the
    /// same folder read it (see --baseline, --no-baseline). Findings are
    /// recognised by rule, file and the code on their line, so edits
    /// elsewhere in a file keep them known.
    Baseline(BaselineArgs),
    /// Open the last HTML report in the browser, without scanning again.
    Open(OpenArgs),
    /// List the rules that would be applied.
    Rules(RulesArgs),
}

const EXIT_CODES: &str = "\
Exit codes:
  0  no findings that fail the scan (see --fail-on, --fail-severity)
  1  findings that fail the scan
  2  error (bad arguments, invalid rules, unreadable paths)";

/// What to scan and with which rules: shared by every scanning command.
#[derive(Debug, Args)]
pub struct Analysis {
    /// Files or directories to scan.
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    #[command(flatten)]
    pub rules: RuleSource,

    /// Only report findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub min_severity: SeverityArg,

    /// Skip test code: Maven/Gradle test source sets (`src/test`,
    /// `src/integrationTest`...), test directories and `*Test`/`*IT` classes.
    /// Without it, findings in test code are reported and labelled.
    #[arg(long)]
    pub exclude_tests: bool,

    /// Compiled dependencies to read types from: directories (class files,
    /// jars, jmods), jars or jmods, separated like CLASSPATH (`:`, or `;` on
    /// Windows), or `@file` listing them. Lets data flow follow calls into
    /// libraries, e.g. `jsch.getSession(...)` returning a `Session`.
    /// Signatures only: no code from the classpath is run or analyzed.
    #[arg(long, value_name = "PATHS")]
    pub classpath: Vec<OsString>,

    /// Leave out the findings recorded in this baseline (default:
    /// `shorwatch-baseline.json` in the working directory, when present).
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Report every finding, even those in the baseline.
    #[arg(long, conflicts_with = "baseline")]
    pub no_baseline: bool,
}

/// When a scan fails (exit code 1).
#[derive(Debug, Args)]
pub struct Gate {
    /// When to exit with code 1 (`never` keeps CI green and only reports).
    #[arg(long, value_enum, default_value_t = FailOn::Vulnerable)]
    pub fail_on: FailOn,

    /// Only findings at or above this severity fail the scan; the rest are
    /// still reported.
    #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
    pub fail_severity: SeverityArg,

    /// The link shown for the HTML report instead of its local path: where CI
    /// publishes it (an artifact, a Pages site...).
    #[arg(long, value_name = "URL", env = "SHORWATCH_REPORT_URL")]
    pub report_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub analysis: Analysis,

    #[command(flatten)]
    pub gate: Gate,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Write the report to a file instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Also write the HTML report to this file, whatever the --format. On an
    /// interactive terminal the text report writes one to a per-user folder
    /// anyway (the temporary folder on Windows, the cache folder elsewhere)
    /// and links it (see --no-html).
    #[arg(long, value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Do not write the HTML report to the per-user report folder.
    #[arg(long, conflicts_with = "html")]
    pub no_html: bool,

    /// Open the HTML report in the browser when the scan ends (written to
    /// the per-user report folder unless --html or --format html says
    /// where).
    #[arg(long, conflicts_with = "no_html")]
    pub open: bool,

    /// Scan again whenever a scanned file changes (text format, until
    /// Ctrl+C).
    #[arg(long, conflicts_with = "output")]
    pub watch: bool,

    /// Every finding, explained (text format only). By default the text
    /// report only counts them and links the HTML report.
    #[arg(long, conflicts_with_all = ["compact", "overview"])]
    pub details: bool,

    /// The files with findings and the most urgent ones explained (text
    /// format only).
    #[arg(long, conflicts_with = "compact")]
    pub overview: bool,

    /// One line per finding (text format only).
    #[arg(long)]
    pub compact: bool,

    /// Do not print the banner.
    #[arg(long)]
    pub no_banner: bool,
}

#[derive(Debug, Args)]
pub struct CiArgs {
    #[command(flatten)]
    pub analysis: Analysis,

    #[command(flatten)]
    pub gate: Gate,

    /// Where to write `report.sarif` and `report.html` (publish this folder
    /// as the job's artifact).
    #[arg(long, value_name = "DIR", default_value = "shorwatch-report")]
    pub out_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct BaselineArgs {
    #[command(flatten)]
    pub analysis: Analysis,

    /// Where to write the baseline.
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "shorwatch-baseline.json"
    )]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    /// The report to open instead of the last one written.
    pub report: Option<PathBuf>,
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
    /// A self-contained HTML audit report: a cover, chapters, every finding
    /// with its code and data-flow path (offline, no network access).
    Html,
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
