// SPDX-License-Identifier: Apache-2.0

//! Stable structural ordering for query-index storage.

use std::cmp::Ordering;

use code2graph::{Edge, EntryPoint, Symbol, SymbolKind, Visibility};

/// Compare complete symbol facts in a stable structural order.
pub(crate) fn cmp_symbols(left: &Symbol, right: &Symbol) -> Ordering {
    left.id
        .cmp(&right.id)
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| symbol_kind_rank(left.kind).cmp(&symbol_kind_rank(right.kind)))
        .then_with(|| visibility_rank(left.visibility).cmp(&visibility_rank(right.visibility)))
        .then_with(|| cmp_entry_points(&left.entry_points, &right.entry_points))
        .then_with(|| left.file.cmp(&right.file))
        .then_with(|| left.line.cmp(&right.line))
        .then_with(|| left.span.start.cmp(&right.span.start))
        .then_with(|| left.span.end.cmp(&right.span.end))
        .then_with(|| left.signature.cmp(&right.signature))
}

/// Compare complete edge facts in a stable structural order.
pub(crate) fn cmp_edges(left: &Edge, right: &Edge) -> Ordering {
    left.from
        .cmp(&right.from)
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| left.role.cmp(&right.role))
        .then_with(|| left.confidence.cmp(&right.confidence))
        .then_with(|| left.provenance.cmp(&right.provenance))
        .then_with(|| left.occ.file.cmp(&right.occ.file))
        .then_with(|| left.occ.line.cmp(&right.occ.line))
        .then_with(|| left.occ.col.cmp(&right.occ.col))
        .then_with(|| left.occ.byte.cmp(&right.occ.byte))
}

fn symbol_kind_rank(kind: SymbolKind) -> u8 {
    match kind {
        SymbolKind::Function => 0,
        SymbolKind::Method => 1,
        SymbolKind::Struct => 2,
        SymbolKind::Enum => 3,
        SymbolKind::Trait => 4,
        SymbolKind::Interface => 5,
        SymbolKind::Class => 6,
        SymbolKind::TypeAlias => 7,
        SymbolKind::Const => 8,
        SymbolKind::Static => 9,
        SymbolKind::Module => 10,
        SymbolKind::Impl => 11,
        SymbolKind::Table => 12,
        SymbolKind::View => 13,
        SymbolKind::Column => 14,
        SymbolKind::Resource => 15,
        SymbolKind::Other => 16,
    }
}

fn visibility_rank(visibility: Visibility) -> u8 {
    match visibility {
        Visibility::Public => 0,
        Visibility::Internal => 1,
        Visibility::Protected => 2,
        Visibility::Private => 3,
        Visibility::Unknown => 4,
    }
}

fn cmp_entry_points(left: &[EntryPoint], right: &[EntryPoint]) -> Ordering {
    left.iter()
        .map(entry_point_key)
        .cmp(right.iter().map(entry_point_key))
}

fn entry_point_key(entry_point: &EntryPoint) -> (u8, &str) {
    match entry_point {
        EntryPoint::Main => (0, ""),
        EntryPoint::HttpRoute(marker) => (1, marker),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use code2graph::{ByteSpan, Confidence, Descriptor, Occurrence, Provenance, RefRole, SymbolId};

    fn symbol(id: SymbolId) -> Symbol {
        Symbol {
            id,
            name: "run".into(),
            kind: SymbolKind::Function,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: "src/lib.rs".into(),
            line: 1,
            span: ByteSpan { start: 0, end: 12 },
            signature: "fn run()".into(),
        }
    }

    #[test]
    fn symbols_distinguish_same_display_globals_and_locals() {
        let descriptors = vec![
            Descriptor::Namespace("pkg".into()),
            Descriptor::Term("run".into()),
        ];
        let rust = symbol(SymbolId::global("rust", descriptors.clone()));
        let python = symbol(SymbolId::global("python", descriptors));
        let local_a = symbol(SymbolId::local("src/a.rs", "value"));
        let local_b = symbol(SymbolId::local("src/b.rs", "value"));

        assert_eq!(rust.id.to_string(), python.id.to_string());
        assert_ne!(cmp_symbols(&rust, &python), Ordering::Equal);
        assert_eq!(local_a.id.to_string(), local_b.id.to_string());
        assert_ne!(cmp_symbols(&local_a, &local_b), Ordering::Equal);
    }

    #[test]
    fn edge_ordering_is_deterministic_over_identity_and_payload() {
        let from = SymbolId::local("src/main.rs", "caller");
        let to = SymbolId::local("src/lib.rs", "callee");
        let first = Edge {
            from: from.clone(),
            to: to.clone(),
            role: RefRole::Call,
            confidence: Confidence::Scoped,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/main.rs".into(),
                line: 2,
                col: 4,
                byte: 16,
            },
        };
        let second = Edge {
            from,
            to,
            role: RefRole::Call,
            confidence: Confidence::Exact,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/main.rs".into(),
                line: 2,
                col: 4,
                byte: 16,
            },
        };
        let mut edges = [second.clone(), first.clone()];

        edges.sort_by(cmp_edges);

        assert_eq!(cmp_edges(&first, &second), Ordering::Less);
        assert_eq!(cmp_edges(&edges[0], &first), Ordering::Equal);
        assert_eq!(cmp_edges(&edges[1], &second), Ordering::Equal);
    }
}
