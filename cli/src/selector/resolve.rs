// SPDX-License-Identifier: Apache-2.0

//! Deterministic structural selector resolution.

use code2graph::{Symbol, SymbolId};
use code2graph_query::GraphIndex;

use crate::{CliError, LoadedGraph, Result};

use super::position::resolve_position;
use super::types::{
    SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, SelectorResolution,
    SelectorSummary,
};

/// Builds the query index used by selectors from a loaded graph.
///
/// Duplicate structural graph identities are invalid cached graph state and are
/// deliberately reported as an index failure rather than a selector miss.
pub fn build_graph_index(loaded: &LoadedGraph) -> Result<GraphIndex> {
    GraphIndex::from_graph(loaded.graph.clone()).map_err(|error| CliError::Index(error.to_string()))
}

/// Resolves one selector without applying any rendering/result limit.
pub fn resolve_selector(
    context: &SelectorContext<'_>,
    request: &SelectorRequest<'_>,
) -> Result<SelectorResolution> {
    context.deadline.check(context.cancellation)?;
    let (ids, symbols) = match request.selector {
        crate::Selector::Name(name) => {
            definition_matches(context.index.symbols_named(name), request.options)
        }
        // SCIP is a plural display key. Definition-only selection and
        // definition filters must narrow the structural IDs as well as records;
        // endpoint-only IDs remain eligible only for unfiltered graph-ID use.
        crate::Selector::Scip(scip) => {
            let (definition_ids, symbols) =
                definition_matches(context.index.symbols_with_scip(scip), request.options);
            let ids = if request.purpose == SelectorPurpose::AnyGraphId
                && request.options.file.is_none()
                && request.options.kind.is_none()
            {
                context
                    .index
                    .ids_with_scip(scip)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                definition_ids
            };
            (ids, symbols)
        }
        crate::Selector::Id(id) => exact_id(context.index, id, request.purpose, request.options),
        crate::Selector::Position(position) => position_match(context, position, request.options)?,
    };
    context.deadline.check(context.cancellation)?;
    let summary = SelectorSummary {
        matched_count: ids.len(),
        ambiguous: ids.len() > 1,
    };
    if summary.matched_count == 0 {
        return Err(CliError::NoMatch);
    }
    if request.options.require_unique && summary.matched_count != 1 {
        return Err(CliError::Ambiguous);
    }
    Ok(SelectorResolution {
        ids,
        symbols: (!symbols.is_empty()).then_some(symbols),
        summary,
    })
}

fn definition_matches(
    definitions: Vec<&Symbol>,
    options: &SelectorOptions,
) -> (Vec<SymbolId>, Vec<Symbol>) {
    let symbols = definitions
        .into_iter()
        .filter(|symbol| definition_matches_options(symbol, options))
        .cloned()
        .collect::<Vec<_>>();
    let ids = symbols.iter().map(|symbol| symbol.id.clone()).collect();
    (ids, symbols)
}

fn definition_matches_options(symbol: &Symbol, options: &SelectorOptions) -> bool {
    options
        .file
        .as_ref()
        .is_none_or(|file| symbol.file == file.as_str())
        && options.kind.is_none_or(|kind| symbol.kind == kind)
}

fn exact_id(
    index: &GraphIndex,
    id: &SymbolId,
    purpose: SelectorPurpose,
    options: &SelectorOptions,
) -> (Vec<SymbolId>, Vec<Symbol>) {
    if let Some(symbol) = index.symbol(id) {
        return if definition_matches_options(symbol, options) {
            (vec![id.clone()], vec![symbol.clone()])
        } else {
            (Vec::new(), Vec::new())
        };
    }
    if purpose == SelectorPurpose::AnyGraphId
        && options.file.is_none()
        && options.kind.is_none()
        && index.contains_id(id)
    {
        (vec![id.clone()], Vec::new())
    } else {
        (Vec::new(), Vec::new())
    }
}

fn position_match(
    context: &SelectorContext<'_>,
    position: &crate::SourcePosition,
    options: &SelectorOptions,
) -> Result<(Vec<SymbolId>, Vec<Symbol>)> {
    let id = resolve_position(context, position)?;
    let symbol =
        context.index.symbol(&id).cloned().ok_or_else(|| {
            CliError::Index("position resolved to a non-definition identity".into())
        })?;
    if definition_matches_options(&symbol, options) {
        Ok((vec![id], vec![symbol]))
    } else {
        Ok((Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol,
        SymbolId, SymbolKind, Visibility,
    };
    use code2graph_query::GraphIndex;

    use super::{
        SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, resolve_selector,
    };
    use crate::cache::{
        CacheCompleteness, CandidateId, CompatibilityFingerprint, CompatibilityRecord,
        LanguageFeatureFingerprint, LoadedSnapshot, PackageFingerprint, ProjectInputDigest,
    };
    use crate::{
        Deadline, NeverCancelled, ProjectPath, ProjectSelection, SelectionProvenance, Selector,
    };

    fn id(language: &str, name: &str) -> SymbolId {
        SymbolId::global(language, vec![Descriptor::Term(name.into())])
    }

    fn symbol(id: SymbolId, name: &str, file: &str, kind: SymbolKind) -> Symbol {
        Symbol {
            id,
            name: name.into(),
            kind,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: file.into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: name.into(),
        }
    }

    fn graph() -> (CodeGraph, SymbolId, SymbolId, SymbolId, SymbolId) {
        let rust = id("rust", "same");
        let python = id("python", "same");
        let endpoint_a = SymbolId::local("vendor/a", "remote");
        let endpoint_b = SymbolId::local("vendor/b", "remote");
        let edge = |from: SymbolId, to: SymbolId, byte| Edge {
            from,
            to,
            role: RefRole::Call,
            confidence: Confidence::Exact,
            provenance: Provenance::ScopeGraph,
            occ: Occurrence {
                file: "src/a.rs".into(),
                line: 1,
                col: 0,
                byte,
            },
        };
        (
            CodeGraph {
                symbols: vec![
                    symbol(rust.clone(), "same", "src/a.rs", SymbolKind::Function),
                    symbol(python.clone(), "same", "src/b.py", SymbolKind::Class),
                ],
                edges: vec![
                    edge(rust.clone(), endpoint_a.clone(), 0),
                    edge(python.clone(), endpoint_b.clone(), 1),
                ],
            },
            rust,
            python,
            endpoint_a,
            endpoint_b,
        )
    }

    fn snapshot() -> LoadedSnapshot {
        let language = LanguageFeatureFingerprint::current();
        let package = PackageFingerprint::from_normalized(["selector-test"]);
        let compatibility = CompatibilityFingerprint::new(language, package);
        let input = ProjectInputDigest::from_inputs([] as [(&str, &str, [u8; 32]); 0]);
        LoadedSnapshot {
            candidate_id: CandidateId::new(compatibility, input, CacheCompleteness::Complete, &[]),
            compatibility: CompatibilityRecord {
                id: compatibility,
                language_fingerprint: language,
                package_fingerprint: package,
                created_at_ns: 0,
            },
            input_digest: input,
            completeness: CacheCompleteness::Complete,
            omissions: Vec::new(),
            created_at_ns: 0,
            inventory_file_count: 0,
            inventory_total_bytes: 0,
            files: Vec::new(),
            tier_graphs: Vec::new(),
        }
    }

    fn resolve(
        index: &GraphIndex,
        snapshot: &LoadedSnapshot,
        selector: &Selector,
        purpose: SelectorPurpose,
        options: &SelectorOptions,
    ) -> crate::Result<super::SelectorResolution> {
        let selection = ProjectSelection {
            canonical_root: std::env::temp_dir(),
            canonical_source: None,
            provenance: SelectionProvenance::CurrentDirectory,
        };
        let deadline = Deadline::new(None);
        resolve_selector(
            &SelectorContext {
                index,
                selection: &selection,
                snapshot,
                max_file_bytes: 1024,
                deadline: &deadline,
                cancellation: &NeverCancelled,
            },
            &SelectorRequest {
                selector,
                purpose,
                options,
            },
        )
    }

    #[test]
    fn name_and_scip_keep_cross_language_collisions_and_filter_structural_results() {
        let (graph, rust, python, ..) = graph();
        assert_eq!(rust.to_scip_string(), python.to_scip_string());
        let index = GraphIndex::from_graph(graph).unwrap();
        let snapshot = snapshot();
        let all = resolve(
            &index,
            &snapshot,
            &Selector::Name("same".into()),
            SelectorPurpose::DefinitionOnly,
            &SelectorOptions::default(),
        )
        .unwrap();
        assert_eq!(all.ids, vec![python.clone(), rust.clone()]);
        assert_eq!(all.summary.matched_count, 2);
        assert!(all.summary.ambiguous);

        let filtered = resolve(
            &index,
            &snapshot,
            &Selector::Scip(rust.to_scip_string()),
            SelectorPurpose::AnyGraphId,
            &SelectorOptions {
                file: Some(ProjectPath::new(Path::new("src/a.rs")).unwrap()),
                kind: Some(SymbolKind::Function),
                require_unique: true,
            },
        )
        .unwrap();
        assert_eq!(filtered.ids, vec![rust]);
        assert_eq!(filtered.symbols.unwrap().len(), 1);
    }

    #[test]
    fn endpoint_only_scip_and_exact_id_obey_purpose_and_definition_filters() {
        let (graph, rust, _, endpoint_a, endpoint_b) = graph();
        assert_eq!(endpoint_a.to_scip_string(), endpoint_b.to_scip_string());
        let index = GraphIndex::from_graph(graph).unwrap();
        let snapshot = snapshot();

        let endpoint_scip = Selector::Scip(endpoint_a.to_scip_string());
        assert!(matches!(
            resolve(
                &index,
                &snapshot,
                &endpoint_scip,
                SelectorPurpose::DefinitionOnly,
                &SelectorOptions::default(),
            ),
            Err(crate::CliError::NoMatch)
        ));
        let endpoints = resolve(
            &index,
            &snapshot,
            &endpoint_scip,
            SelectorPurpose::AnyGraphId,
            &SelectorOptions::default(),
        )
        .unwrap();
        assert_eq!(endpoints.ids, vec![endpoint_a.clone(), endpoint_b]);
        assert_eq!(endpoints.summary.matched_count, 2);
        assert!(endpoints.symbols.is_none());
        assert!(matches!(
            resolve(
                &index,
                &snapshot,
                &endpoint_scip,
                SelectorPurpose::AnyGraphId,
                &SelectorOptions {
                    kind: Some(SymbolKind::Function),
                    ..SelectorOptions::default()
                },
            ),
            Err(crate::CliError::NoMatch)
        ));

        assert!(matches!(
            resolve(
                &index,
                &snapshot,
                &Selector::Id(endpoint_a.clone()),
                SelectorPurpose::DefinitionOnly,
                &SelectorOptions::default(),
            ),
            Err(crate::CliError::NoMatch)
        ));
        assert!(
            resolve(
                &index,
                &snapshot,
                &Selector::Id(endpoint_a.clone()),
                SelectorPurpose::AnyGraphId,
                &SelectorOptions {
                    file: Some(ProjectPath::new(Path::new("vendor/a")).unwrap()),
                    ..SelectorOptions::default()
                },
            )
            .is_err()
        );
        let endpoint = resolve(
            &index,
            &snapshot,
            &Selector::Id(endpoint_a.clone()),
            SelectorPurpose::AnyGraphId,
            &SelectorOptions::default(),
        )
        .unwrap();
        assert_eq!(endpoint.ids, vec![endpoint_a]);
        assert!(endpoint.symbols.is_none());

        assert!(
            resolve(
                &index,
                &snapshot,
                &Selector::Id(rust),
                SelectorPurpose::DefinitionOnly,
                &SelectorOptions {
                    kind: Some(SymbolKind::Class),
                    ..SelectorOptions::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn uniqueness_and_order_use_complete_structural_matches_after_shuffling() {
        let (first_graph, rust, python, ..) = graph();
        let mut second_graph = first_graph.clone();
        second_graph.symbols.reverse();
        second_graph.edges.reverse();
        let first = GraphIndex::from_graph(first_graph).unwrap();
        let second = GraphIndex::from_graph(second_graph).unwrap();
        let snapshot = snapshot();
        let selector = Selector::Name("same".into());
        let options = SelectorOptions::default();
        let left = resolve(
            &first,
            &snapshot,
            &selector,
            SelectorPurpose::DefinitionOnly,
            &options,
        )
        .unwrap();
        let right = resolve(
            &second,
            &snapshot,
            &selector,
            SelectorPurpose::DefinitionOnly,
            &options,
        )
        .unwrap();
        assert_eq!(left.ids, vec![python, rust]);
        assert_eq!(left.ids, right.ids);

        assert!(matches!(
            resolve(
                &first,
                &snapshot,
                &selector,
                SelectorPurpose::DefinitionOnly,
                &SelectorOptions {
                    require_unique: true,
                    ..SelectorOptions::default()
                },
            ),
            Err(crate::CliError::Ambiguous)
        ));
    }
}
