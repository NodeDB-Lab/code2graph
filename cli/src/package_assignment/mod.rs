// SPDX-License-Identifier: Apache-2.0

//! Deterministic package-manifest discovery, assignment, and per-file application.

mod apply;
mod discover;
mod types;

pub use discover::{PackageSourcePath, assign_packages, assign_packages_checked};
pub use types::{
    ManifestInput, ManifestOutcome, ManifestParserKind, PackageAssignmentSet, PackageDiagnostic,
    PackageDiagnosticKind, SourcePackageAssignment,
};
