//! `shorwatch`: finds quantum-vulnerable cryptography in source code and
//! configuration.

mod args;
mod browser;
mod ci;
mod classpath;
mod discover;
mod gate;
mod layout;
mod output;
mod pipeline;
mod projects;
mod rules;
mod watch;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use shorwatch_report::Scan;

use args::{Cli, Command, ScanArgs};

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        None => scan(&cli.scan),
        Some(Command::Scan(args)) => scan(&args),
        Some(Command::Report(mut args)) => {
            args.open = true;
            scan(&args)
        }
        Some(Command::Ci(args)) => ci::run(&args, VERSION),
        Some(Command::Open(args)) => {
            browser::open_last(args.report.as_deref()).map(|()| ExitCode::SUCCESS)
        }
        Some(Command::Rules(args)) => rules::load(&args.rules).map(|rules| {
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
    if args.watch {
        return watch::run(args, VERSION);
    }
    if output::wants_banner(args) {
        output::banner(VERSION)?;
    }
    let mut scan = pipeline::run(&args.analysis, VERSION)?;
    output::add_links(&mut scan, args);
    let failing = report(&scan, args, args.open)?;
    Ok(gate::exit_code(failing))
}

/// Writes a scan's reports, opens the HTML one if asked to, and says why
/// the scan fails. Returns the number of failing findings.
fn report(scan: &Scan, args: &ScanArgs, open: bool) -> Result<usize> {
    let report = output::html_report(scan, args)?;
    output::write(scan, args, &report)?;
    if let Some(path) = &report.path {
        browser::remember(path);
        if open {
            browser::open(path)?;
        }
    }
    let failing = gate::failing(scan, &args.gate);
    if failing > 0 {
        output::verdict(failing, args, report.link.as_deref())?;
    }
    Ok(failing)
}
