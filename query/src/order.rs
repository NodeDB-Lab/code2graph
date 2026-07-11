// SPDX-License-Identifier: Apache-2.0

//! Stable structural ordering for query-index storage.

use std::cmp::Ordering;

use code2graph::{EdgeKey, SymbolId};

/// Compare symbol identities in every ordered secondary index.
pub(crate) fn cmp_symbol_ids(left: &SymbolId, right: &SymbolId) -> Ordering {
    left.cmp(right)
}

/// Compare edge identities in every ordered adjacency index.
pub(crate) fn cmp_edge_keys(left: &EdgeKey, right: &EdgeKey) -> Ordering {
    left.cmp(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use code2graph::{Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, SymbolId};

    #[test]
    fn symbol_ordering_retains_coordinates_omitted_by_scip() {
        let descriptors = vec![
            Descriptor::Namespace("pkg".into()),
            Descriptor::Term("run".into()),
        ];
        let rust = SymbolId::global("rust", descriptors.clone());
        let python = SymbolId::global("python", descriptors);
        let local_a = SymbolId::local("src/a.rs", "value");
        let local_b = SymbolId::local("src/b.rs", "value");

        assert_eq!(rust.to_scip_string(), python.to_scip_string());
        assert_ne!(cmp_symbol_ids(&rust, &python), Ordering::Equal);
        assert_eq!(local_a.to_scip_string(), local_b.to_scip_string());
        assert_ne!(cmp_symbol_ids(&local_a, &local_b), Ordering::Equal);
    }

    #[test]
    fn edge_ordering_uses_edge_key_not_confidence() {
        let from = SymbolId::local("src/main.rs", "caller");
        let to = SymbolId::local("src/lib.rs", "callee");
        let first = Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Call,
            confidence: Confidence::NameOnly,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/main.rs".into(),
                line: 2,
                col: 4,
                byte: 16,
            },
        };
        let second = Edge {
            confidence: Confidence::Exact,
            ..first.clone()
        };

        assert_eq!(cmp_edge_keys(&first.key(), &second.key()), Ordering::Equal);
    }
}
