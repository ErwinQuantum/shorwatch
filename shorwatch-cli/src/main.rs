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
mod printable;
mod projects;
mod rules;
mod suppress;
mod watch;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use shorwatch_report::Scan;

use args::{BaselineArgs, Cli, Command, ScanArgs};

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stack of every thread that scans. The passes over a file's tree recurse
/// with its nesting (a 2,000-operand concatenation in generated code), and a
/// thread's default stack (1 MB on Windows main, 2 MB in rayon) is too small
/// for that; the memory is only reserved, not used. `depth::MAX_DEPTH` in
/// shorwatch-langs bounds the nesting this has to cover.
const STACK_BYTES: usize = 256 * 1024 * 1024;

fn main() -> ExitCode {
    let build = rayon::ThreadPoolBuilder::new()
        .stack_size(STACK_BYTES)
        .build_global();
    if let Err(error) = build {
        eprintln!("error: {error}");
        return ExitCode::from(2);
    }
    std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(run)
        .ok()
        .and_then(|thread| thread.join().ok())
        .unwrap_or(ExitCode::from(2))
}

fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        None => scan(&cli.scan),
        Some(Command::Scan(args)) => scan(&args),
        Some(Command::Report(mut args)) => {
            args.open = true;
            scan(&args)
        }
        Some(Command::Ci(args)) => ci::run(&args, VERSION),
        Some(Command::Baseline(args)) => baseline(&args),
        Some(Command::Open(args)) => {
            browser::open_last(args.report.as_deref()).map(|()| ExitCode::SUCCESS)
        }
        Some(Command::Rules(args)) => rules::load(&args.rules).map(|rules| {
            print!("{}", rules::listing(&rules));
            ExitCode::SUCCESS
        }),
    };
    result.unwrap_or_else(|error| {
        eprintln!("{}", printable::text(&format!("error: {error:#}")));
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

fn baseline(args: &BaselineArgs) -> Result<ExitCode> {
    let scan = pipeline::run_for_baseline(&args.analysis, VERSION)?;
    let baseline = suppress::Baseline::of(&scan);
    std::fs::write(&args.output, baseline.to_json())
        .with_context(|| format!("writing `{}`", args.output.display()))?;
    println!(
        "Recorded {} in `{}`: scans from this folder now report only new findings. Commit it.",
        match baseline.len() {
            1 => "1 finding".to_owned(),
            n => format!("{n} findings"),
        },
        args.output.display()
    );
    Ok(ExitCode::SUCCESS)
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
