//! The projects of a scan, so reports can split findings by project: each
//! scanned path is one, unless it is a folder of projects (a directory of
//! microservices or of repositories), whose top-most build roots are then
//! the projects.

use std::fs;
use std::path::{Path, PathBuf};

use shorwatch_report::{Project, project_of};

use crate::discover::display_path;

/// Files or directories that make a directory a project root.
const MARKERS: &[&str] = &[
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pyproject.toml",
    ".git",
    "Directory.Build.props",
    "Directory.Packages.props",
    "global.json",
];

/// Extensions of files that make a directory a project root: a .NET solution
/// is named after the project. A `.csproj` is not one: a solution holds many,
/// and `link` must see them together.
const MARKER_EXTENSIONS: &[&str] = &["sln", "slnx"];

/// How deep below a scanned folder to look for project roots: services sit
/// at `services/billing`, repositories at `org/repo`.
const MAX_DEPTH: usize = 2;

const SKIPPED: &[&str] = &["target", "build", "node_modules", "src", "out", "dist"];

/// The projects `files` belong to, each with the number of its files.
pub fn detect(paths: &[PathBuf], files: &[PathBuf], cwd: &Path) -> Vec<Project> {
    // A path is a project of its own when it is a project root or a folder
    // of several; plain paths (`src/ config/`) make one project together.
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() && is_project(path) {
            roots.push(path.clone());
            continue;
        }
        let nested = if path.is_dir() {
            nested_projects(path, 0)
        } else {
            Vec::new()
        };
        if nested.len() > 1 {
            roots.extend(nested);
        } else if paths.len() == 1 {
            roots.push(path.clone());
        }
    }
    if roots.is_empty() {
        let root = cwd.to_owned();
        return vec![Project {
            name: name(&root, cwd),
            root: String::new(),
            files_scanned: files.len(),
        }];
    }

    let mut projects: Vec<Project> = roots
        .iter()
        .map(|root| Project {
            name: name(root, cwd),
            root: display_path(root, cwd),
            files_scanned: 0,
        })
        .collect();
    // Files no project contains (a folder's loose files) go together.
    let mut loose = 0;
    for file in files {
        match project_of(&projects, &display_path(file, cwd)) {
            Some(index) => projects[index].files_scanned += 1,
            None => loose += 1,
        }
    }
    if loose > 0 {
        projects.push(Project {
            name: "other files".into(),
            root: String::new(),
            files_scanned: loose,
        });
    }
    dedupe_names(&mut projects);
    projects
}

fn is_project(dir: &Path) -> bool {
    MARKERS.iter().any(|marker| dir.join(marker).exists())
        || fs::read_dir(dir).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| MARKER_EXTENSIONS.iter().any(|m| e.eq_ignore_ascii_case(m)))
            })
        })
}

/// The top-most project roots below `dir`.
fn nested_projects(dir: &Path, depth: usize) -> Vec<PathBuf> {
    if depth >= MAX_DEPTH {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut children: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.starts_with('.') && !SKIPPED.contains(&n))
        })
        .collect();
    children.sort();
    let mut roots = Vec::new();
    for child in children {
        if is_project(&child) {
            roots.push(child);
        } else {
            roots.extend(nested_projects(&child, depth + 1));
        }
    }
    roots
}

fn name(root: &Path, cwd: &Path) -> String {
    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        cwd.join(root)
    };
    // `.` and `..` name nothing: take the directory's real name.
    let absolute = absolute.canonicalize().unwrap_or(absolute);
    absolute.file_name().map_or_else(
        || display_path(root, cwd),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Two `api` services in different folders become `team-a/api` and `team-b/api`.
fn dedupe_names(projects: &mut [Project]) {
    let names: Vec<String> = projects.iter().map(|p| p.name.clone()).collect();
    for project in projects.iter_mut() {
        if names.iter().filter(|n| **n == project.name).count() > 1 && !project.root.is_empty() {
            project.name.clone_from(&project.root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "shorwatch-projects-{}-{}",
            std::process::id(),
            files.len()
        ));
        let _ = fs::remove_dir_all(&root);
        for file in files {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "").unwrap();
        }
        root
    }

    fn summary(projects: &[Project]) -> Vec<(String, usize)> {
        projects
            .iter()
            .map(|p| (p.name.clone(), p.files_scanned))
            .collect()
    }

    #[test]
    fn a_folder_of_services_is_one_project_per_service() {
        let root = tree(&[
            "billing/pom.xml",
            "billing/src/main/java/A.java",
            "billing/src/main/java/B.java",
            "gateway/build.gradle.kts",
            "gateway/src/main/kotlin/C.kt",
            "tools/legacy/pom.xml",
            "tools/legacy/D.java",
            "notes/E.java",
        ]);
        let files: Vec<PathBuf> = [
            "billing/src/main/java/A.java",
            "billing/src/main/java/B.java",
            "gateway/src/main/kotlin/C.kt",
            "tools/legacy/D.java",
            "notes/E.java",
        ]
        .iter()
        .map(|f| root.join(f))
        .collect();
        let projects = detect(std::slice::from_ref(&root), &files, &root);
        assert_eq!(
            summary(&projects),
            [
                ("billing".to_owned(), 2),
                ("gateway".to_owned(), 1),
                ("legacy".to_owned(), 1),
                ("other files".to_owned(), 1),
            ]
        );
        assert_eq!(projects[2].root, "tools/legacy");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_dotnet_solution_is_a_project_but_its_csproj_files_are_not() {
        let root = tree(&[
            "billing/Billing.sln",
            "billing/src/Api/Api.csproj",
            "billing/src/Core/Core.csproj",
            "gateway/Directory.Build.props",
            "gateway/Gateway.csproj",
            "gateway/G.cs",
        ]);
        let files = vec![root.join("billing/src/Api/A.cs"), root.join("gateway/G.cs")];
        let projects = detect(std::slice::from_ref(&root), &files, &root);
        let names: Vec<_> = projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["billing", "gateway"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_project_with_modules_stays_one_project() {
        let root = tree(&[
            "pom.xml",
            "core/pom.xml",
            "core/A.java",
            "web/pom.xml",
            "web/B.java",
        ]);
        let files = vec![root.join("core/A.java"), root.join("web/B.java")];
        let projects = detect(std::slice::from_ref(&root), &files, &root);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].files_scanned, 2);
        assert_eq!(projects[0].root, "");
        fs::remove_dir_all(root).unwrap();
    }
}
