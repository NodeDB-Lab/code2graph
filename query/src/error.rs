// SPDX-License-Identifier: Apache-2.0

//! Typed failures from query indexes and snapshot-delta application.

use std::fmt;

use code2graph::{EdgeKey, ScopeSnapshotToken, SymbolId};

/// A result returned by query operations.
pub type Result<T> = std::result::Result<T, QueryError>;

/// Failures that preserve the structural identity involved in a query-index
/// operation or snapshot-delta application.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// An index cannot contain two definitions with one structural identity.
    #[error("duplicate symbol id: {0}")]
    DuplicateSymbolId(SymbolId),

    /// An index cannot contain two edges with one lossless edge identity.
    #[error("duplicate edge key: {0:?}")]
    DuplicateEdgeKey(EdgeKey),

    /// Applying a scope delta requires an index that tracks its snapshot token.
    #[error("scope delta requires a tracked index")]
    ScopeDeltaRequiresTrackedIndex,

    /// A delta was based on a snapshot other than the index's current snapshot.
    #[error(
        "snapshot mismatch: expected {expected_token}, actual {actual_token}",
        expected_token = TokenHex(expected),
        actual_token = TokenHex(actual)
    )]
    SnapshotMismatch {
        /// The snapshot currently held by the index.
        expected: ScopeSnapshotToken,
        /// The snapshot the delta declares as its base.
        actual: ScopeSnapshotToken,
    },

    /// A removal named a symbol that is not present in the index.
    #[error("missing removed symbol: {0}")]
    MissingRemovedSymbol(SymbolId),

    /// A removal named an edge that is not present in the index.
    #[error("missing removed edge: {0:?}")]
    MissingRemovedEdge(EdgeKey),

    /// A scope delta declared the index's current token as its result.
    ///
    /// Retained as the typed public rejection for repeated transitions.
    #[error("scope delta snapshot does not advance")]
    ScopeDeltaSnapshotDoesNotAdvance,

    /// A delta lists a symbol identity for removal more than once.
    #[error("duplicate removed symbol in delta: {0}")]
    DuplicateRemovedSymbol(SymbolId),

    /// A delta lists a symbol identity for upsert more than once.
    #[error("duplicate upserted symbol in delta: {0}")]
    DuplicateUpsertedSymbol(SymbolId),

    /// A delta lists an edge identity for removal more than once.
    #[error("duplicate removed edge in delta: {0:?}")]
    DuplicateRemovedEdge(EdgeKey),

    /// A delta lists an edge identity for upsert more than once.
    #[error("duplicate upserted edge in delta: {0:?}")]
    DuplicateUpsertedEdge(EdgeKey),
}

/// A bounded, non-debug representation of an opaque snapshot token.
struct TokenHex<'a>(&'a ScopeSnapshotToken);

impl fmt::Display for TokenHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0.as_bytes()[..8] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_token_display_is_bounded_to_its_prefix() {
        let token = ScopeSnapshotToken::new([0xab; 32]);

        assert_eq!(TokenHex(&token).to_string(), "abababababababab…");
    }
}
