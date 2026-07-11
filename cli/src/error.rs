// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::exit::ExitCode;
use crate::result::OutputStatus;
use crate::worker::WorkerFailure;

/// CLI-library result type.
pub type Result<T> = std::result::Result<T, CliError>;

/// Typed failure categories with stable process mapping.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("no matching result")]
    NoMatch,
    #[error("selector is ambiguous")]
    Ambiguous,
    #[error("cache failure: {0}")]
    Cache(String),
    #[error("index failure: {0}")]
    Index(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("project path {path}: {reason}")]
    ProjectPath { path: PathBuf, reason: String },
    #[error("project path {path} is a symlink")]
    ProjectSymlink { path: PathBuf },
    #[error("project-relative path {path}: {reason}")]
    ProjectRelativePath { path: PathBuf, reason: String },
    #[error("source path {path} is outside project root {root}")]
    ProjectPathOutsideRoot { root: PathBuf, path: PathBuf },
    #[error("operation timed out")]
    Timeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("worker failure: {0}")]
    Worker(WorkerFailure),
    #[error("{command} execution is not implemented in this contract-only CLI shell")]
    Unavailable { command: String },
    #[error("fatal CLI failure: {0}")]
    Fatal(String),
}

impl CliError {
    /// Exhaustive mapping required by the public process contract.
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::NoMatch => ExitCode::NoMatch,
            Self::Usage(_) => ExitCode::Usage,
            Self::Ambiguous => ExitCode::Ambiguous,
            Self::Cache(_)
            | Self::Index(_)
            | Self::Unsupported(_)
            | Self::ProjectPath { .. }
            | Self::ProjectSymlink { .. }
            | Self::ProjectRelativePath { .. }
            | Self::ProjectPathOutsideRoot { .. }
            | Self::Timeout
            | Self::Cancelled
            | Self::Worker(_)
            | Self::Unavailable { .. }
            | Self::Fatal(_) => ExitCode::Operational,
        }
    }
}

impl From<&CliError> for OutputStatus {
    fn from(error: &CliError) -> Self {
        match error {
            CliError::NoMatch => Self::NoMatch,
            CliError::Ambiguous => Self::Ambiguous,
            CliError::Unsupported(_) | CliError::Unavailable { .. } => Self::Unsupported,
            CliError::Timeout => Self::Timeout,
            CliError::Cancelled => Self::Error,
            CliError::Usage(_)
            | CliError::Cache(_)
            | CliError::Index(_)
            | CliError::ProjectPath { .. }
            | CliError::ProjectSymlink { .. }
            | CliError::ProjectRelativePath { .. }
            | CliError::ProjectPathOutsideRoot { .. }
            | CliError::Worker(_)
            | CliError::Fatal(_) => Self::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_the_planned_exit_code() {
        assert_eq!(CliError::NoMatch.exit_code(), ExitCode::NoMatch);
        assert_eq!(CliError::Usage("x".into()).exit_code(), ExitCode::Usage);
        assert_eq!(CliError::Ambiguous.exit_code(), ExitCode::Ambiguous);
        for error in [
            CliError::Cache("x".into()),
            CliError::Index("x".into()),
            CliError::Unsupported("x".into()),
            CliError::ProjectPath {
                path: "project".into(),
                reason: "missing".into(),
            },
            CliError::ProjectSymlink {
                path: "project".into(),
            },
            CliError::ProjectRelativePath {
                path: "source".into(),
                reason: "invalid".into(),
            },
            CliError::ProjectPathOutsideRoot {
                root: "project".into(),
                path: "source".into(),
            },
            CliError::Timeout,
            CliError::Cancelled,
            CliError::Worker(WorkerFailure::Spawn),
            CliError::Unavailable {
                command: "status".into(),
            },
            CliError::Fatal("x".into()),
        ] {
            assert_eq!(error.exit_code(), ExitCode::Operational);
        }
    }

    #[test]
    fn every_error_has_a_machine_status() {
        let cases = [
            (CliError::NoMatch, OutputStatus::NoMatch),
            (CliError::Usage("x".into()), OutputStatus::Error),
            (CliError::Ambiguous, OutputStatus::Ambiguous),
            (CliError::Cache("x".into()), OutputStatus::Error),
            (CliError::Index("x".into()), OutputStatus::Error),
            (CliError::Unsupported("x".into()), OutputStatus::Unsupported),
            (
                CliError::ProjectPath {
                    path: "project".into(),
                    reason: "missing".into(),
                },
                OutputStatus::Error,
            ),
            (
                CliError::ProjectSymlink {
                    path: "project".into(),
                },
                OutputStatus::Error,
            ),
            (
                CliError::ProjectRelativePath {
                    path: "source".into(),
                    reason: "invalid".into(),
                },
                OutputStatus::Error,
            ),
            (
                CliError::ProjectPathOutsideRoot {
                    root: "project".into(),
                    path: "source".into(),
                },
                OutputStatus::Error,
            ),
            (CliError::Timeout, OutputStatus::Timeout),
            (CliError::Cancelled, OutputStatus::Error),
            (CliError::Worker(WorkerFailure::Spawn), OutputStatus::Error),
            (
                CliError::Unavailable {
                    command: "status".into(),
                },
                OutputStatus::Unsupported,
            ),
            (CliError::Fatal("x".into()), OutputStatus::Error),
        ];
        for (error, expected) in cases {
            assert_eq!(OutputStatus::from(&error), expected);
        }
    }
}
