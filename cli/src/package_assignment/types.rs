// SPDX-License-Identifier: Apache-2.0

//! Package-assignment data contracts and canonical fingerprint records.

use code2graph::Package;

use crate::inventory::StableIoErrorKind;
use crate::project::ProjectPath;

/// Core manifest parser selected from an exact manifest basename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManifestParserKind {
    Cargo,
    Npm,
    Go,
    Pyproject,
}

impl ManifestParserKind {
    pub(crate) fn for_name(name: &str) -> Option<Self> {
        match name {
            "Cargo.toml" => Some(Self::Cargo),
            "package.json" => Some(Self::Npm),
            "go.mod" => Some(Self::Go),
            "pyproject.toml" => Some(Self::Pyproject),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Go => "go",
            Self::Pyproject => "pypi",
        }
    }
}

/// A stable reason why a candidate manifest could not yield a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageDiagnosticKind {
    Symlink,
    NotRegularFile,
    TooLarge { limit: usize },
    InvalidUtf8,
    ChangedDuringRead,
    ReadError { kind: StableIoErrorKind },
    Unparseable,
}

impl PackageDiagnosticKind {
    /// Stable diagnostic tag suitable for display and grouping.
    pub fn tag(&self) -> String {
        match self {
            Self::Symlink => "symlink".into(),
            Self::NotRegularFile => "not-regular-file".into(),
            Self::TooLarge { .. } => "file-too-large".into(),
            Self::InvalidUtf8 => "invalid-utf8".into(),
            Self::ChangedDuringRead => "changed-during-read".into(),
            Self::ReadError { kind } => format!("read-error:{}", kind.as_str()),
            Self::Unparseable => "unparseable".into(),
        }
    }

    fn fingerprint_fields(&self) -> Vec<String> {
        match self {
            Self::Symlink => vec!["symlink".into()],
            Self::NotRegularFile => vec!["not-regular-file".into()],
            Self::TooLarge { limit } => vec!["file-too-large".into(), limit.to_string()],
            Self::InvalidUtf8 => vec!["invalid-utf8".into()],
            Self::ChangedDuringRead => vec!["changed-during-read".into()],
            Self::ReadError { kind } => vec!["read-error".into(), kind.as_str().into()],
            Self::Unparseable => vec!["unparseable".into()],
        }
    }
}

/// Parse result retained as a compatibility input even when it is a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestOutcome {
    Parsed(Package),
    Failed(PackageDiagnosticKind),
}

/// One relevant core-supported manifest, with no manifest source content exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInput {
    pub path: String,
    pub content_hash: Option<String>,
    pub parser: ManifestParserKind,
    pub outcome: ManifestOutcome,
}

/// A package-assignment diagnostic associated with a manifest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDiagnostic {
    pub path: String,
    pub kind: PackageDiagnosticKind,
}

/// The package selected for one admitted source. `None` is a first-class outcome.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourcePackageAssignment {
    pub source_path: ProjectPath,
    pub manifest_path: Option<String>,
    pub package: Option<Package>,
}

/// Canonical discovery output. All vectors are sorted by their path keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAssignmentSet {
    pub manifests: Vec<ManifestInput>,
    pub assignments: Vec<SourcePackageAssignment>,
    pub diagnostics: Vec<PackageDiagnostic>,
}

impl PackageAssignmentSet {
    /// Canonical, content-free records for [`crate::cache::PackageFingerprint`].
    pub fn manifest_fingerprint_records(&self) -> Vec<String> {
        self.manifests
            .iter()
            .map(ManifestInput::fingerprint_record)
            .collect()
    }

    /// Canonical per-source selection records for [`crate::cache::PackageFingerprint`].
    pub fn assignment_fingerprint_records(&self) -> Vec<String> {
        self.assignments
            .iter()
            .map(SourcePackageAssignment::fingerprint_record)
            .collect()
    }
}

impl ManifestInput {
    fn fingerprint_record(&self) -> String {
        let mut fields = vec![
            "manifest".to_owned(),
            self.path.clone(),
            self.content_hash.clone().unwrap_or_default(),
            self.parser.as_str().to_owned(),
        ];
        match &self.outcome {
            ManifestOutcome::Parsed(package) => fields.extend([
                "parsed".to_owned(),
                package.manager.clone(),
                package.name.clone(),
                package.version.clone(),
            ]),
            ManifestOutcome::Failed(kind) => {
                fields.push("failed".to_owned());
                fields.extend(kind.fingerprint_fields());
            }
        }
        canonical_record(&fields)
    }
}

impl SourcePackageAssignment {
    fn fingerprint_record(&self) -> String {
        let mut fields = vec!["assignment".to_owned(), self.source_path.to_string()];
        match (&self.manifest_path, &self.package) {
            (Some(path), Some(package)) => fields.extend([
                "selected".to_owned(),
                path.clone(),
                package.manager.clone(),
                package.name.clone(),
                package.version.clone(),
            ]),
            (None, None) => fields.push("none".to_owned()),
            // This is not emitted by discovery, but a public struct can contain
            // either malformed combination; retain it as a distinct input.
            (manifest_path, package) => {
                fields.push("incomplete".to_owned());
                fields.push(manifest_path.clone().unwrap_or_default());
                fields.push(
                    package
                        .as_ref()
                        .map_or_else(String::new, |value| value.manager.clone()),
                );
                fields.push(
                    package
                        .as_ref()
                        .map_or_else(String::new, |value| value.name.clone()),
                );
                fields.push(
                    package
                        .as_ref()
                        .map_or_else(String::new, |value| value.version.clone()),
                );
            }
        }
        canonical_record(&fields)
    }
}

/// Unambiguously encodes arbitrary UTF-8 fields without exposing source bodies.
fn canonical_record(fields: &[String]) -> String {
    let mut output = String::new();
    for field in fields {
        output.push_str(&field.len().to_string());
        output.push(':');
        output.push_str(field);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_records_include_outcome_parameters_and_do_not_delimit_collide() {
        let base = ManifestInput {
            path: "Cargo.toml".into(),
            content_hash: None,
            parser: ManifestParserKind::Cargo,
            outcome: ManifestOutcome::Failed(PackageDiagnosticKind::TooLarge { limit: 10 }),
        };
        let mut changed = base.clone();
        changed.outcome = ManifestOutcome::Failed(PackageDiagnosticKind::TooLarge { limit: 11 });
        assert_ne!(base.fingerprint_record(), changed.fingerprint_record());

        let first = SourcePackageAssignment {
            source_path: ProjectPath::new(std::path::Path::new("a\u{1f}b")).expect("path"),
            manifest_path: None,
            package: None,
        };
        let second = SourcePackageAssignment {
            source_path: ProjectPath::new(std::path::Path::new("a")).expect("path"),
            manifest_path: Some("b".into()),
            package: None,
        };
        assert_ne!(first.fingerprint_record(), second.fingerprint_record());
    }
}
