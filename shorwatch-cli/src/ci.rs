//! `shorwatch ci`: a scan for pipelines. SARIF and HTML reports in one
//! folder to publish as the job's artifact, the summary in the log, and a
//! link to the HTML report where the CI system serves it.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use shorwatch_report::{Scan, html, markdown, sarif, terminal};

use crate::args::CiArgs;
use crate::{gate, output, pipeline};

pub fn run(args: &CiArgs, version: &str) -> Result<ExitCode> {
    let scan = pipeline::run(&args.analysis, version)?;
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating `{}`", args.out_dir.display()))?;
    let html_path = args.out_dir.join("report.html");
    write(&args.out_dir.join("report.sarif"), &sarif::render(&scan))?;
    write(&html_path, &html::render(&scan))?;

    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let published = slashes(&html_path);
    let link = args
        .gate
        .report_url
        .clone()
        .or_else(|| report_url(env, &published))
        .unwrap_or_else(|| output::file_url(&html_path));

    let summary = terminal::render(
        &scan,
        &terminal::Options {
            report: Some(link.clone()),
            ci: true,
            ..terminal::Options::default()
        },
    );
    // Everything on stdout: CI systems read stdout and stderr separately and
    // may interleave them out of order.
    let mut stdout = anstream::stdout();
    stdout.write_all(summary.as_bytes())?;
    if let Some(path) = env("GITHUB_STEP_SUMMARY") {
        job_summary(Path::new(&path), &scan, &link)?;
    }

    let failing = gate::failing(&scan, &args.gate);
    if failing > 0 {
        write!(stdout, "{}", terminal::verdict(failing, Some(&link)))?;
        if env("GITHUB_ACTIONS").is_some() {
            // An annotation: the failure and its link on the run's page.
            writeln!(
                stdout,
                "::error title=Shorwatch::{failing} findings fail the scan. Report: {link}"
            )?;
        }
    }
    stdout.flush()?;
    Ok(gate::exit_code(failing))
}

fn write(path: &Path, report: &str) -> Result<()> {
    fs::write(path, report).with_context(|| format!("writing `{}`", path.display()))
}

/// GitHub Actions' job summary: the Markdown report, appended (other steps
/// write there too).
fn job_summary(path: &Path, scan: &Scan, link: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening `{}`", path.display()))?;
    writeln!(
        file,
        "{}\n[Open the HTML report]({link}) (the `shorwatch-report` artifact of this run).\n",
        markdown::render(scan)
    )?;
    Ok(())
}

/// Where the CI system serves the published report folder, from the
/// variables it sets: `html` is the report's path in the workspace.
fn report_url(env: impl Fn(&str) -> Option<String>, html: &str) -> Option<String> {
    if env("GITHUB_ACTIONS").is_some() {
        // Artifacts are listed on the run's page.
        return Some(format!(
            "{}/{}/actions/runs/{}",
            env("GITHUB_SERVER_URL")?,
            env("GITHUB_REPOSITORY")?,
            env("GITHUB_RUN_ID")?
        ));
    }
    if env("GITLAB_CI").is_some() {
        return Some(format!("{}/artifacts/file/{html}", env("CI_JOB_URL")?));
    }
    if env("JENKINS_URL").is_some() {
        return Some(format!("{}artifact/{html}", env("BUILD_URL")?));
    }
    if env("TF_BUILD").is_some() {
        return Some(format!(
            "{}{}/_build/results?buildId={}&view=artifacts",
            env("SYSTEM_COLLECTIONURI")?,
            env("SYSTEM_TEAMPROJECT")?.replace(' ', "%20"),
            env("BUILD_BUILDID")?
        ));
    }
    None
}

/// A workspace path as CI systems write it in URLs.
fn slashes(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    text.strip_prefix("./").unwrap_or(&text).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(vars: &[(&str, &str)]) -> Option<String> {
        let env = |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        };
        report_url(env, "shorwatch-report/report.html")
    }

    #[test]
    fn each_ci_system_links_its_artifacts() {
        assert_eq!(
            url(&[
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_SERVER_URL", "https://github.com"),
                ("GITHUB_REPOSITORY", "acme/payments"),
                ("GITHUB_RUN_ID", "42"),
            ])
            .as_deref(),
            Some("https://github.com/acme/payments/actions/runs/42")
        );
        assert_eq!(
            url(&[
                ("GITLAB_CI", "true"),
                ("CI_JOB_URL", "https://gitlab.com/acme/payments/-/jobs/7"),
            ])
            .as_deref(),
            Some(
                "https://gitlab.com/acme/payments/-/jobs/7/artifacts/file/shorwatch-report/report.html"
            )
        );
        assert_eq!(
            url(&[
                ("JENKINS_URL", "https://ci.acme.dev/"),
                ("BUILD_URL", "https://ci.acme.dev/job/payments/12/"),
            ])
            .as_deref(),
            Some("https://ci.acme.dev/job/payments/12/artifact/shorwatch-report/report.html")
        );
        assert_eq!(
            url(&[
                ("TF_BUILD", "True"),
                ("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/"),
                ("SYSTEM_TEAMPROJECT", "Payments Team"),
                ("BUILD_BUILDID", "99"),
            ])
            .as_deref(),
            Some(
                "https://dev.azure.com/acme/Payments%20Team/_build/results?buildId=99&view=artifacts"
            )
        );
    }

    #[test]
    fn unknown_or_incomplete_ci_gives_no_link() {
        assert_eq!(url(&[]), None);
        assert_eq!(url(&[("GITLAB_CI", "true")]), None);
    }

    #[test]
    fn report_paths_use_forward_slashes() {
        assert_eq!(
            slashes(
                Path::new("./shorwatch-report")
                    .join("report.html")
                    .as_path()
            ),
            "shorwatch-report/report.html"
        );
    }
}
