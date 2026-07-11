// SPDX-License-Identifier: Apache-2.0

//! Public value contracts for scope-tier graph snapshot transitions.

use crate::graph::{Edge, EdgeKey, FileFacts, Symbol};
use crate::symbol::SymbolId;

/// An opaque consumer-provided identity for one complete scope-graph snapshot.
///
/// The core compares this token but does not derive it, choose its hash
/// algorithm, or perform any persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeSnapshotToken([u8; 32]);

impl ScopeSnapshotToken {
    /// Create a snapshot token from its opaque 32-byte representation.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the opaque bytes comprising this snapshot token.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One file-level change in a scope-graph snapshot transition.
#[derive(Debug)]
pub enum FileChange<'a> {
    /// Insert or replace the facts for a file.
    Upsert(&'a FileFacts),
    /// Remove the facts for a file path.
    Remove(&'a str),
}

/// The complete, lossless change from one scope-graph snapshot to another.
///
/// Symbols and edge keys use structural identity; SCIP display strings are not
/// used as delta identity.
#[derive(Debug)]
pub struct ScopeGraphDelta {
    /// Snapshot represented by the graph before this delta is applied.
    pub base_snapshot: ScopeSnapshotToken,
    /// Snapshot represented by the graph after this delta is applied.
    pub snapshot: ScopeSnapshotToken,
    /// Definitions absent from the result snapshot.
    pub removed_symbols: Vec<SymbolId>,
    /// Definitions present in the result snapshot.
    pub upserted_symbols: Vec<Symbol>,
    /// Derived edge identities absent from the result snapshot.
    pub removed_edges: Vec<EdgeKey>,
    /// Derived edges present in the result snapshot.
    pub upserted_edges: Vec<Edge>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_token_exposes_its_exact_bytes_and_compares_by_value() {
        let bytes = [42; 32];
        let token = ScopeSnapshotToken::new(bytes);

        assert_eq!(token.as_bytes(), &bytes);
        assert_eq!(token, ScopeSnapshotToken::new(bytes));
        assert_ne!(token, ScopeSnapshotToken::new([43; 32]));
    }

    #[test]
    fn public_delta_values_construct_without_mutation_state() {
        let facts = FileFacts {
            file: "src/lib.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };
        let change = FileChange::Upsert(&facts);
        let removed = FileChange::Remove("src/old.rs");
        let base_snapshot = ScopeSnapshotToken::new([1; 32]);
        let snapshot = ScopeSnapshotToken::new([2; 32]);
        let delta = ScopeGraphDelta {
            base_snapshot,
            snapshot,
            removed_symbols: Vec::new(),
            upserted_symbols: Vec::new(),
            removed_edges: Vec::new(),
            upserted_edges: Vec::new(),
        };

        assert!(matches!(change, FileChange::Upsert(file) if file.file == "src/lib.rs"));
        assert!(matches!(removed, FileChange::Remove("src/old.rs")));
        assert_eq!(delta.base_snapshot, base_snapshot);
        assert_eq!(delta.snapshot, snapshot);
        assert!(delta.removed_symbols.is_empty());
        assert!(delta.upserted_symbols.is_empty());
        assert!(delta.removed_edges.is_empty());
        assert!(delta.upserted_edges.is_empty());
    }
}
