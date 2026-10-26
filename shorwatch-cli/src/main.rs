//! `shorwatch`: finds quantum-vulnerable cryptography in source code and
//! configuration.

mod args;
mod discover;
mod layout;
mod output;
mod pipeline;
mod rules;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use shorwatch_core::{CodeRole, Status};

use args::{Cli, Command, FailOn, ScanArgs};

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(&args),
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
    let scan = pipeline::scan(&files, &rules, &options);
    output::write(&scan, args)?;

    let fails = match args.fail_on {
        FailOn::Vulnerable => scan.findings.iter().any(|f| f.status == Status::Vulnerable),
        FailOn::Any => !scan.findings.is_empty(),
        FailOn::Never => false,
    };
    Ok(if fails {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
