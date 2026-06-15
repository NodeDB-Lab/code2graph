// SPDX-License-Identifier: Apache-2.0

//! Manifest-file parsers for package enrichment. Gated by the `manifest` cargo
//! feature; compiled only when that feature is enabled.
//!
//! Entry point: [`from_manifest`].

use std::path::Path;

use crate::symbol::Package;

// ── Cargo.toml / pyproject.toml serde helpers ────────────────────────────────

#[derive(serde::Deserialize)]
struct CargoManifest {
    package: Option<CargoPackage>,
}

#[derive(serde::Deserialize)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
}

#[derive(serde::Deserialize)]
struct PyprojectManifest {
    project: Option<PyprojectProject>,
}

#[derive(serde::Deserialize)]
struct PyprojectProject {
    name: Option<String>,
    version: Option<String>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Detect a package from a manifest file.
///
/// `filename` is the path as given by the caller (only the basename is used for
/// dispatch). `content` is the full text of the file.
///
/// Returns `None` for unrecognised filenames. Missing `name`/`version` fields
/// produce empty strings (never panics).
///
/// Supported files:
/// - `Cargo.toml` → manager `"cargo"`
/// - `package.json` → manager `"npm"`
/// - `pyproject.toml` → manager `"pypi"`
/// - `go.mod` → manager `"go"` (version is always `""`)
pub fn from_manifest(filename: &str, content: &str) -> Option<Package> {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename);

    match basename {
        "Cargo.toml" => parse_cargo(content),
        "package.json" => parse_npm(content),
        "pyproject.toml" => parse_pyproject(content),
        "go.mod" => Some(parse_go_mod(content)),
        _ => None,
    }
}

// ── Per-format parsers ────────────────────────────────────────────────────────

fn parse_cargo(content: &str) -> Option<Package> {
    let manifest: CargoManifest = toml::from_str(content).ok()?;
    let pkg = manifest.package?;
    Some(Package {
        manager: "cargo".into(),
        name: pkg.name.unwrap_or_default(),
        version: pkg.version.unwrap_or_default(),
    })
}

fn parse_npm(content: &str) -> Option<Package> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    Some(Package {
        manager: "npm".into(),
        name: v
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_owned(),
        version: v
            .get("version")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_owned(),
    })
}

fn parse_pyproject(content: &str) -> Option<Package> {
    let manifest: PyprojectManifest = toml::from_str(content).ok()?;
    let project = manifest.project?;
    Some(Package {
        manager: "pypi".into(),
        name: project.name.unwrap_or_default(),
        version: project.version.unwrap_or_default(),
    })
}

/// Parse a `go.mod` file via line scan (no extra dep).
/// The module name is the path after the `module` keyword on the first such line.
/// Version is always empty (go.mod doesn't carry a package version).
fn parse_go_mod(content: &str) -> Package {
    let name = content
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("module")
                .map(|rest| rest.trim().to_owned())
        })
        .unwrap_or_default();
    Package {
        manager: "go".into(),
        name,
        version: String::new(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_toml_parsed() {
        let content = r#"
[package]
name = "x"
version = "1.0"
edition = "2021"
"#;
        let pkg = from_manifest("Cargo.toml", content).expect("should parse");
        assert_eq!(pkg.manager, "cargo");
        assert_eq!(pkg.name, "x");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn package_json_parsed() {
        let content = r#"{"name":"my-pkg","version":"2.3.1","private":true}"#;
        let pkg = from_manifest("path/to/package.json", content).expect("should parse");
        assert_eq!(pkg.manager, "npm");
        assert_eq!(pkg.name, "my-pkg");
        assert_eq!(pkg.version, "2.3.1");
    }

    #[test]
    fn go_mod_parsed() {
        let content = "module github.com/org/repo\n\ngo 1.21\n";
        let pkg = from_manifest("go.mod", content).expect("should parse");
        assert_eq!(pkg.manager, "go");
        assert_eq!(pkg.name, "github.com/org/repo");
        assert_eq!(pkg.version, "");
    }

    #[test]
    fn pyproject_toml_parsed() {
        let content = r#"
[project]
name = "myapp"
version = "0.1.0"
"#;
        let pkg = from_manifest("pyproject.toml", content).expect("should parse");
        assert_eq!(pkg.manager, "pypi");
        assert_eq!(pkg.name, "myapp");
        assert_eq!(pkg.version, "0.1.0");
    }

    #[test]
    fn unknown_filename_returns_none() {
        assert!(from_manifest("setup.py", "").is_none());
        assert!(from_manifest("build.gradle", "").is_none());
    }
}
