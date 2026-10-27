//! `shorwatch`: finds quantum-vulnerable cryptography in source code and
//! configuration.

mod args;
mod browser;
mod classpath;
mod discover;
mod layout;
mod output;
mod pipeline;
mod projects;
mod rules;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use shorwatch_core::{CodeRole, Severity, Status};

use args::{Cli, Command, FailOn, ScanArgs};

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(&args),
        Command::Open(args) => {
            browser::open_last(args.report.as_deref()).map(|()| ExitCode::SUCCESS)
        }
        Command::Rules(args) => rules::load(&args.rules).map(|rules| {
            print!("{}", rules::listing(&rules));
            ExitCode::SUCCESS
        }),
    };
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::from(2)
    })
}

fn scan(args: &ScanArgs) -> Result<ExitCode> {
    if output::wants_banner(args) {
        output::banner(VERSION)?;
    }
    let rules = rules::load(&args.rules)?;
    let mut files = discover::files(&args.paths)?;
    if args.exclude_tests {
        files.retain(|(_, role)| *role == CodeRole::Production);
    }
    let options = pipeline::Options {
        min_severity: args.min_severity.into(),
        tool_version: VERSION.to_owned(),
    };
    let library = classpath::load(&args.classpath)?;
    if !args.classpath.is_empty() {
        eprintln!(
            "classpath: {} types, {} methods returning types",
            library.types.len(),
            library.methods.len()
        );
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let paths: Vec<_> = files.iter().map(|(path, _)| path.clone()).collect();
    let projects = projects::detect(&args.paths, &paths, &cwd);
    let scan = pipeline::scan(&files, projects, &library, &rules, &options);
    let report = output::html_report(&scan, args)?;
    output::write(&scan, args, &report)?;
    if let Some(path) = &report.path {
        browser::remember(path);
        if args.open {
            browser::open(path)?;
        }
    }

    let threshold = Severity::from(args.fail_severity);
    let failing = scan
        .findings
        .iter()
        .filter(|f| f.severity >= threshold)
        .filter(|f| match args.fail_on {
            FailOn::Vulnerable => f.status == Status::Vulnerable,
            FailOn::Any => true,
            FailOn::Never => false,
        })
        .count();
    if failing == 0 {
        return Ok(ExitCode::SUCCESS);
    }
    output::verdict(failing, args, report.link.as_deref())?;
    Ok(ExitCode::from(1))
}
