// SPDX-License-Identifier: Apache-2.0

use code2graph::Language;

use crate::project::ProjectPath;

/// The inventory classification for a discovered ordinary file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileClassification {
    Enabled(Language),
    FeatureDisabled(Language),
    UnrecognizedExtension,
}

/// A stable, platform-neutral classification of a filesystem read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StableIoErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidInput,
    InvalidData,
    TimedOut,
    Interrupted,
    UnexpectedEof,
    WouldBlock,
    WriteZero,
    Other,
}

impl StableIoErrorKind {
    /// Stable kebab-case tag for external reporting.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::PermissionDenied => "permission-denied",
            Self::AlreadyExists => "already-exists",
            Self::InvalidInput => "invalid-input",
            Self::InvalidData => "invalid-data",
            Self::TimedOut => "timed-out",
            Self::Interrupted => "interrupted",
            Self::UnexpectedEof => "unexpected-eof",
            Self::WouldBlock => "would-block",
            Self::WriteZero => "write-zero",
            Self::Other => "other",
        }
    }
}

impl From<std::io::ErrorKind> for StableIoErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            std::io::ErrorKind::InvalidInput => Self::InvalidInput,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::TimedOut => Self::TimedOut,
            std::io::ErrorKind::Interrupted => Self::Interrupted,
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            std::io::ErrorKind::WouldBlock => Self::WouldBlock,
            std::io::ErrorKind::WriteZero => Self::WriteZero,
            _ => Self::Other,
        }
    }
}

/// Why a discovered path was not admitted to an inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmissionReason {
    UnrecognizedExtension,
    FeatureDisabled { language: Language },
    SymlinkFile,
    SymlinkDirectory,
    NotRegularFile,
    FileTooLarge { limit: usize },
    TotalBytesLimit { limit: usize },
    FileCountLimit { limit: usize },
    InvalidUtf8,
    ChangedDuringRead,
    ReadError { kind: StableIoErrorKind },
}

impl OmissionReason {
    /// Stable kebab-case tag for external reporting and reason counts.
    pub fn tag(&self) -> String {
        match self {
            Self::UnrecognizedExtension => "unrecognized-extension".into(),
            Self::FeatureDisabled { language } => format!("feature-disabled:{}", language.as_str()),
            Self::SymlinkFile => "symlink-file".into(),
            Self::SymlinkDirectory => "symlink-directory".into(),
            Self::NotRegularFile => "not-regular-file".into(),
            Self::FileTooLarge { .. } => "file-too-large".into(),
            Self::TotalBytesLimit { .. } => "total-bytes-limit".into(),
            Self::FileCountLimit { .. } => "file-count-limit".into(),
            Self::InvalidUtf8 => "invalid-utf8".into(),
            Self::ChangedDuringRead => "changed-during-read".into(),
            Self::ReadError { kind } => format!("read-error:{}", kind.as_str()),
        }
    }
}

/// A portable modification-time hint retained with admitted source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MtimeHint {
    pub seconds_since_unix_epoch: i64,
    pub nanoseconds: u32,
}

/// One admitted, UTF-8 source file. `bytes` are the exact hashed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryFile {
    pub path: ProjectPath,
    pub language: Language,
    pub bytes: Vec<u8>,
    pub text: String,
    pub blake3: String,
    pub mtime: Option<MtimeHint>,
}

/// One discovered path excluded from the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmittedFile {
    pub path: ProjectPath,
    pub reason: OmissionReason,
}

/// Stable aggregate counts for the scanning result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySummary {
    pub admitted_files: usize,
    pub admitted_bytes: usize,
    pub omitted_files: usize,
    pub omission_reasons: Vec<(OmissionReason, usize)>,
}

/// Whether every discovered candidate was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryCompleteness {
    Complete,
    Partial,
}

/// Exact source inputs admitted by a deterministic bounded scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInventory {
    pub files: Vec<InventoryFile>,
    pub omitted: Vec<OmittedFile>,
    pub completeness: InventoryCompleteness,
    pub summary: InventorySummary,
}
