// SPDX-License-Identifier: Apache-2.0

//! Definition substring search command.

use std::path::Path;

use crate::commands::shared::{limit, query_envelope, symbol_output};
use crate::commands::{QueryCommandContext, SymbolsCommandRequest};
use crate::result::{OutputEnvelope, SymbolOutput};
use crate::{CliError, ProjectPath, Result};

/// Executes the definition-only `symbols` substring query.
pub(crate) fn execute_symbols(
    context: &QueryCommandContext<'_>,
    request: SymbolsCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<SymbolOutput>>> {
    context.deadline.check(context.cancellation)?;
    let file = request
        .file
        .map(|value| ProjectPath::new(Path::new(value)))
        .transpose()?;
    let needle = (!request.case_sensitive).then(|| request.text.to_lowercase());
    let mut results = context
        .index
        .symbols()
        .filter(|symbol| {
            substring_matches(symbol, request.text, needle.as_deref())
                && file
                    .as_ref()
                    .is_none_or(|file| normalized_file(symbol) == file.as_str())
                && request.kind.is_none_or(|kind| symbol.kind == kind)
        })
        .map(symbol_output)
        .collect::<Vec<_>>();
    // Structural IDs are the ordering contract, independent of graph input order.
    results.sort_by(|left, right| left.id.cmp(&right.id));
    context.deadline.check(context.cancellation)?;
    if results.is_empty() {
        return Err(CliError::NoMatch);
    }
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

fn substring_matches(symbol: &code2graph::Symbol, text: &str, folded_needle: Option<&str>) -> bool {
    if let Some(needle) = folded_needle {
        symbol.name.to_lowercase().contains(needle)
            || symbol.id.to_scip_string().to_lowercase().contains(needle)
            || symbol.signature.to_lowercase().contains(needle)
            || normalized_file(symbol).to_lowercase().contains(needle)
    } else {
        symbol.name.contains(text)
            || symbol.id.to_scip_string().contains(text)
            || symbol.signature.contains(text)
            || normalized_file(symbol).contains(text)
    }
}

fn normalized_file(symbol: &code2graph::Symbol) -> String {
    ProjectPath::new(Path::new(&symbol.file))
        .map_or_else(|_| symbol.file.clone(), |path| path.to_string())
}

#[cfg(test)]
mod tests {
    use code2graph::{ByteSpan, Descriptor, Symbol, SymbolId, SymbolKind, Visibility};

    use super::{normalized_file, substring_matches};

    fn symbol(id: SymbolId, name: &str, file: &str, signature: &str, kind: SymbolKind) -> Symbol {
        Symbol {
            id,
            name: name.into(),
            kind,
            visibility: Visibility::Public,
            entry_points: Vec::new(),
            file: file.into(),
            line: 1,
            span: ByteSpan { start: 0, end: 1 },
            signature: signature.into(),
        }
    }

    #[test]
    fn normalized_file_preserves_invalid_cached_paths_without_panicking() {
        let invalid = symbol(
            SymbolId::local("invalid", "value"),
            "value",
            "../invalid.rs",
            "fn value()",
            SymbolKind::Function,
        );
        let valid = symbol(
            SymbolId::local("valid", "value"),
            "value",
            "src//valid.rs",
            "fn value()",
            SymbolKind::Function,
        );
        assert_eq!(normalized_file(&invalid), "../invalid.rs");
        assert_eq!(normalized_file(&valid), "src/valid.rs");
    }

    #[test]
    fn substring_fields_keep_display_distinct_from_lossless_identity() {
        let display = SymbolId::global("rust", vec![Descriptor::Term("display_target".into())]);
        let definition = symbol(
            display,
            "unrelated_name",
            "src/Needle.rs",
            "fn unrelated_name() -> SignatureNeedle",
            SymbolKind::Function,
        );
        for needle in [
            "unrelated_name",
            "display_target",
            "SignatureNeedle",
            "Needle.rs",
        ] {
            assert!(substring_matches(&definition, needle, None), "{needle}");
        }
        for needle in [
            "UNRELATED_NAME",
            "DISPLAY_TARGET",
            "SIGNATURENEEDLE",
            "NEEDLE.RS",
        ] {
            assert!(
                substring_matches(&definition, needle, Some(&needle.to_lowercase())),
                "{needle}"
            );
            assert!(!substring_matches(&definition, needle, None), "{needle}");
        }
    }
}
