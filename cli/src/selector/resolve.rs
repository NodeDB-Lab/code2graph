// SPDX-License-Identifier: Apache-2.0

//! Deterministic structural selector resolution.

use code2graph::{Symbol, SymbolId};
use code2graph_query::{GraphIndex, GraphRead};

use crate::{CliError, LoadedGraph, Result};

use super::position::resolve_position;
use super::types::{
    SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, SelectorResolution,
    SelectorSummary,
};

const SELECTOR_PAGE_SIZE: usize = 256;

/// Builds the legacy in-memory index used by lifecycle routes that have not yet
/// moved to the CLI-owned paged cache reader.
pub fn build_graph_index(loaded: &LoadedGraph) -> Result<GraphIndex> {
    GraphIndex::from_graph(loaded.graph.clone()).map_err(|error| CliError::Index(error.to_string()))
}

/// Resolves one selector without applying any rendering/result limit.
pub fn resolve_selector<G>(
    context: &SelectorContext<'_, G>,
    request: &SelectorRequest<'_>,
) -> Result<SelectorResolution>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    context.deadline.check(context.cancellation)?;
    let (ids, symbols) = match request.selector {
        crate::Selector::Name(name) => {
            definition_matches(read_symbols_named(context.graph, name)?, request.options)
        }
        // SCIP is a plural display key. Definition-only selection and definition
        // filters narrow structural IDs as well as records; endpoint-only IDs
        // remain eligible only for unfiltered graph-ID use.
        crate::Selector::Scip(scip) => {
            let (definition_ids, symbols) = definition_matches(
                read_symbols_with_scip(context.graph, scip)?,
                request.options,
            );
            let ids = if request.purpose == SelectorPurpose::AnyGraphId
                && request.options.file.is_none()
                && request.options.kind.is_none()
            {
                read_ids_with_scip(context.graph, scip)?
            } else {
                definition_ids
            };
            (ids, symbols)
        }
        crate::Selector::Id(id) => exact_id(context.graph, id, request.purpose, request.options)?,
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

fn graph_error<E: Into<CliError>>(error: E) -> CliError {
    error.into()
}

fn read_symbols_named<G>(graph: &G, name: &str) -> Result<Vec<Symbol>>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    let mut after = None;
    let mut symbols = Vec::new();
    loop {
        let page = graph
            .symbols_named(name, after.as_ref(), SELECTOR_PAGE_SIZE)
            .map_err(graph_error)?;
        symbols.extend(page.items);
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok(symbols)
}

fn read_symbols_with_scip<G>(graph: &G, scip: &str) -> Result<Vec<Symbol>>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    let mut after = None;
    let mut symbols = Vec::new();
    loop {
        let page = graph
            .symbols_with_scip(scip, after.as_ref(), SELECTOR_PAGE_SIZE)
            .map_err(graph_error)?;
        symbols.extend(page.items);
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok(symbols)
}

fn read_ids_with_scip<G>(graph: &G, scip: &str) -> Result<Vec<SymbolId>>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    let mut after = None;
    let mut ids = Vec::new();
    loop {
        let page = graph
            .ids_with_scip(scip, after.as_ref(), SELECTOR_PAGE_SIZE)
            .map_err(graph_error)?;
        ids.extend(page.items);
        let Some(next) = page.next else { break };
        after = Some(next);
    }
    Ok(ids)
}

fn definition_matches(
    definitions: Vec<Symbol>,
    options: &SelectorOptions,
) -> (Vec<SymbolId>, Vec<Symbol>) {
    let symbols = definitions
        .into_iter()
        .filter(|symbol| definition_matches_options(symbol, options))
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

fn exact_id<G>(
    graph: &G,
    id: &SymbolId,
    purpose: SelectorPurpose,
    options: &SelectorOptions,
) -> Result<(Vec<SymbolId>, Vec<Symbol>)>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    if let Some(symbol) = graph.symbol(id).map_err(graph_error)? {
        return Ok(if definition_matches_options(&symbol, options) {
            (vec![id.clone()], vec![symbol])
        } else {
            (Vec::new(), Vec::new())
        });
    }
    if purpose == SelectorPurpose::AnyGraphId
        && options.file.is_none()
        && options.kind.is_none()
        && graph.contains_id(id).map_err(graph_error)?
    {
        Ok((vec![id.clone()], Vec::new()))
    } else {
        Ok((Vec::new(), Vec::new()))
    }
}

fn position_match<G>(
    context: &SelectorContext<'_, G>,
    position: &crate::SourcePosition,
    options: &SelectorOptions,
) -> Result<(Vec<SymbolId>, Vec<Symbol>)>
where
    G: GraphRead + ?Sized,
    G::Error: Into<CliError>,
{
    let id = resolve_position(context, position)?;
    let symbol = context
        .graph
        .symbol(&id)
        .map_err(graph_error)?
        .ok_or_else(|| CliError::Index("position resolved to a non-definition identity".into()))?;
    if definition_matches_options(&symbol, options) {
        Ok((vec![id], vec![symbol]))
    } else {
        Ok((Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use code2graph::{
        ByteSpan, CodeGraph, Confidence, Descriptor, Edge, Occurrence, Provenance, RefRole, Symbol,
        SymbolId, SymbolKind, Visibility,
    };
    use code2graph_query::GraphIndex;

    use super::{
        SelectorContext, SelectorOptions, SelectorPurpose, SelectorRequest, resolve_selector,
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

    fn resolve(
        graph: &GraphIndex,
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
        let candidate_hashes = HashMap::new();
        resolve_selector(
            &SelectorContext {
                graph,
                selection: &selection,
                candidate_hashes: &candidate_hashes,
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
        let options = SelectorOptions::default();
        let name = resolve(
            &index,
            &Selector::Name("same".into()),
            SelectorPurpose::DefinitionOnly,
            &options,
        )
        .unwrap();
        assert_eq!(name.ids, vec![python.clone(), rust.clone()]);
        let scip = resolve(
            &index,
            &Selector::Scip(rust.to_scip_string()),
            SelectorPurpose::DefinitionOnly,
            &options,
        )
        .unwrap();
        assert_eq!(scip.ids, vec![python, rust]);
        let file = SelectorOptions {
            file: Some(ProjectPath::new(std::path::Path::new("src/a.rs")).unwrap()),
            ..Default::default()
        };
        let narrowed = resolve(
            &index,
            &Selector::Scip("codegraph . . . same.".into()),
            SelectorPurpose::DefinitionOnly,
            &file,
        )
        .unwrap();
        assert_eq!(narrowed.ids.len(), 1);
    }

    #[test]
    fn endpoint_only_ids_require_any_graph_id() {
        let (graph, _, _, endpoint, _) = graph();
        let index = GraphIndex::from_graph(graph).unwrap();
        let options = SelectorOptions::default();
        assert!(matches!(
            resolve(
                &index,
                &Selector::Id(endpoint.clone()),
                SelectorPurpose::DefinitionOnly,
                &options
            ),
            Err(crate::CliError::NoMatch)
        ));
        let selected = resolve(
            &index,
            &Selector::Id(endpoint.clone()),
            SelectorPurpose::AnyGraphId,
            &options,
        )
        .unwrap();
        assert_eq!(selected.ids, vec![endpoint]);
    }
}
