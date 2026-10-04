// SPDX-License-Identifier: Apache-2.0

use super::{CacheError, CandidateId};

#[derive(Debug)]
pub(crate) enum CachePublicationFailure {
    Cache(CacheError),
    Conflict(PublicationConflict),
}

#[derive(Debug)]
pub(crate) struct PublicationConflict {
    pub candidate_id: CandidateId,
    pub field: PublicationField,
    pub file: Option<String>,
    pub tier: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationField {
    LanguageFingerprint,
    PackageFingerprint,
    CompatibilityId,
    InputDigest,
    Completeness,
    InventoryFileCount,
    InventoryTotalBytes,
    FileCount,
    Omissions,
    FilePresence,
    Language,
    ContentHash,
    SizeBytes,
    PackageAssignment,
    FileFacts,
    FileSubgraph,
    GraphSymbols,
    GraphEdges,
    GraphConfidence,
}

impl PublicationField {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LanguageFingerprint => "language_fingerprint",
            Self::PackageFingerprint => "package_fingerprint",
            Self::CompatibilityId => "compatibility_id",
            Self::InputDigest => "input_digest",
            Self::Completeness => "completeness",
            Self::InventoryFileCount => "inventory_file_count",
            Self::InventoryTotalBytes => "inventory_total_bytes",
            Self::FileCount => "file_count",
            Self::Omissions => "omissions",
            Self::FilePresence => "file_presence",
            Self::Language => "language",
            Self::ContentHash => "content_hash",
            Self::SizeBytes => "size_bytes",
            Self::PackageAssignment => "package_assignment",
            Self::FileFacts => "file_facts",
            Self::FileSubgraph => "file_subgraph",
            Self::GraphSymbols => "graph_symbols",
            Self::GraphEdges => "graph_edges",
            Self::GraphConfidence => "graph_confidence",
        }
    }
}

impl CachePublicationFailure {
    pub(super) fn conflict(
        candidate_id: [u8; 32],
        field: PublicationField,
        file: Option<&str>,
        tier: Option<&'static str>,
    ) -> Self {
        Self::Conflict(PublicationConflict {
            candidate_id: CandidateId::from_bytes(candidate_id),
            field,
            file: file.map(escaped_publication_identifier),
            tier,
        })
    }
}

impl From<CacheError> for CachePublicationFailure {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<CachePublicationFailure> for CacheError {
    fn from(error: CachePublicationFailure) -> Self {
        match error {
            CachePublicationFailure::Cache(error) => error,
            CachePublicationFailure::Conflict(_) => Self::CandidateConflict,
        }
    }
}

const IDENTIFIER_MAX_BYTES: usize = 256;

pub(crate) fn escaped_publication_identifier(value: &str) -> String {
    const MARKER: &str = "...";
    let mut output = String::with_capacity(IDENTIFIER_MAX_BYTES);
    output.push('"');
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        let escaped = character.escape_debug();
        let width = escaped.clone().map(char::len_utf8).sum::<usize>();
        let reserve = 1 + if chars.peek().is_some() {
            MARKER.len()
        } else {
            0
        };
        if output.len() + width + reserve > IDENTIFIER_MAX_BYTES {
            output.push_str(MARKER);
            break;
        }
        output.extend(escaped);
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_file_allocation_remains_bounded_after_escape_expansion() {
        let CachePublicationFailure::Conflict(conflict) = CachePublicationFailure::conflict(
            [1; 32],
            PublicationField::FilePresence,
            Some(&"\u{1b}".repeat(10_000)),
            None,
        ) else {
            panic!("expected conflict");
        };
        let file = conflict.file.expect("file identifier");
        assert!(file.len() <= IDENTIFIER_MAX_BYTES);
        assert!(file.ends_with("...\""));
        assert!(!file.chars().any(char::is_control));
    }
}
