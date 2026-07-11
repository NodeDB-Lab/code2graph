// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

const EXACT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "CMakeLists.txt",
    "Makefile",
    "meson.build",
    "configure.ac",
    "configure.in",
    "Gemfile",
    "Rakefile",
    "composer.json",
    "Package.swift",
    "pubspec.yaml",
    "pubspec.yml",
    "foundry.toml",
    "truffle-config.js",
    "truffle.js",
    "selene.toml",
    "terraform.tf",
    "main.tf",
];

const GLOB_MARKERS: &[&str] = &[
    "requirements*.txt",
    "*.sln",
    "*.csproj",
    "*.fsproj",
    "*.vbproj",
    "hardhat.config.*",
    "*.rockspec",
    "*.lpi",
    "*.lpr",
    "*.dproj",
    "*.lpk",
];

/// Whether a directory contains a recognized build or language manifest.
///
/// Marker presence is deliberately sufficient: selection never parses manifests.
pub(crate) fn has_marker(directory: &Path) -> bool {
    let Ok(entries) = fs::read_dir(directory) else {
        return false;
    };
    entries.flatten().any(|entry| {
        // Compare entry names rather than probing a joined path: filesystems with
        // case-insensitive lookup must not make marker recognition case-insensitive.
        let Ok(file_type) = entry.file_type() else {
            return false;
        };
        if !file_type.is_file() {
            return false;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        EXACT_MARKERS.contains(&name) || GLOB_MARKERS.iter().any(|pattern| matches(pattern, name))
    })
}

fn matches(pattern: &str, name: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == name;
    };
    name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::has_marker;

    #[test]
    fn recognizes_exact_and_glob_marker_families() {
        for marker in [
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "go.mod",
            "pom.xml",
            "CMakeLists.txt",
            "Gemfile",
            "composer.json",
            "Package.swift",
            "pubspec.yaml",
            "foundry.toml",
            "selene.toml",
            "terraform.tf",
            "project.csproj",
            "requirements-dev.txt",
            "project.rockspec",
            "project.lpi",
        ] {
            let directory = tempdir().expect("temporary directory");
            fs::write(directory.path().join(marker), "").expect("marker file");
            assert!(has_marker(directory.path()), "{marker}");
        }
    }

    #[test]
    fn matches_marker_names_case_sensitively_and_only_for_files() {
        let directory = tempdir().expect("temporary directory");
        fs::write(directory.path().join("cargo.toml"), "").expect("non-marker");
        fs::create_dir(directory.path().join("project.csproj")).expect("marker-shaped directory");
        assert!(!has_marker(directory.path()));

        fs::write(directory.path().join("hardhat.config.ts"), "").expect("glob marker");
        assert!(has_marker(directory.path()));
    }
}
