// SPDX-License-Identifier: Apache-2.0

//! Structural validation for untrusted [`FileFacts`](super::FileFacts).

use super::{BindingTarget, ByteSpan, FileFacts};
use crate::error::{CodegraphError, Result};
use crate::lang::Language;
use crate::symbol::SymbolId;

/// Trusted coordinates for a single source file's facts.
///
/// This lets a deserialization boundary verify that hostile facts actually
/// belong to the file and language it requested, without retaining source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFactsValidationContext<'a> {
    /// The requested project-relative source path.
    pub expected_file: &'a str,
    /// The requested source language.
    pub expected_language: Language,
    /// Length of the requested source in bytes.
    pub source_len: usize,
}

/// Reject malformed lexical-scope facts before scope-aware resolution.
/// Extractors produce valid facts; bindings call this at their deserialization
/// boundary so hostile cycles and invalid indices cannot enter traversal.
///
/// This preserves the original structural-only validation contract. Call
/// [`validate_file_facts_with_context`] at a boundary which also knows the
/// requested file, language, and source length.
pub fn validate_file_facts(facts: &[FileFacts]) -> Result<()> {
    for file in facts {
        validate_structure(file)?;
    }
    Ok(())
}

/// Validate one file's facts against trusted source coordinates.
///
/// In addition to [`validate_file_facts`]'s index and cycle checks, this checks
/// ownership, identity coordinates, and byte ranges. It deliberately cannot
/// validate columns, line-to-byte correspondence, UTF-8 boundaries, or whether
/// a span covers the claimed syntax: those require the source body, which facts
/// intentionally do not retain.
pub fn validate_file_facts_with_context(
    facts: &FileFacts,
    context: FileFactsValidationContext<'_>,
) -> Result<()> {
    validate_structure(facts)?;
    let malformed = |reason: String| CodegraphError::MalformedFacts {
        file: facts.file.clone(),
        reason,
    };

    if facts.file != context.expected_file {
        return Err(malformed(format!(
            "facts file `{}` does not match expected file `{}`",
            facts.file, context.expected_file
        )));
    }
    if facts.lang != context.expected_language.as_str() {
        return Err(malformed(format!(
            "facts language `{}` does not match expected language `{}`",
            facts.lang,
            context.expected_language.as_str()
        )));
    }

    for (index, symbol) in facts.symbols.iter().enumerate() {
        if symbol.file != context.expected_file {
            return Err(malformed(format!(
                "symbol {index} has foreign file `{}`",
                symbol.file
            )));
        }
        validate_span(
            symbol.span,
            context.source_len,
            &format!("symbol {index}"),
            &malformed,
        )?;
        if symbol.line == 0 {
            return Err(malformed(format!("symbol {index} has zero line")));
        }
        validate_identity(&symbol.id, context, &format!("symbol {index}"), &malformed)?;
    }
    for (index, reference) in facts.references.iter().enumerate() {
        validate_occurrence(
            &reference.occ.file,
            reference.occ.line,
            reference.occ.byte,
            context,
            &format!("reference {index}"),
            &malformed,
        )?;
        if reference.source_module.is_some() && reference.role != super::RefRole::Import {
            return Err(malformed(format!(
                "reference {index} has source_module outside import role"
            )));
        }
        if reference.from_path.is_some() && reference.role != super::RefRole::Import {
            return Err(malformed(format!(
                "reference {index} has from_path outside import role"
            )));
        }
        if reference.qualifier.is_some()
            && !matches!(
                reference.role,
                super::RefRole::Call | super::RefRole::TypeRef
            )
        {
            return Err(malformed(format!(
                "reference {index} has qualifier outside call or type-ref role"
            )));
        }
        if let Some(scope) = reference.scope {
            if !facts.scopes[scope].span.contains(reference.occ.byte) {
                return Err(malformed(format!(
                    "reference {index} is outside scope {scope}"
                )));
            }
        }
        if reference.type_ref_ctx.is_some() && reference.role != super::RefRole::TypeRef {
            return Err(malformed(format!(
                "reference {index} has type_ref_ctx outside type-ref role"
            )));
        }
    }
    for (index, scope) in facts.scopes.iter().enumerate() {
        validate_span(
            scope.span,
            context.source_len,
            &format!("scope {index}"),
            &malformed,
        )?;
        if let Some(parent) = scope.parent {
            let parent_span = facts.scopes[parent].span;
            if !contains_span(parent_span, scope.span) {
                return Err(malformed(format!(
                    "scope {index} is outside parent scope {parent}"
                )));
            }
        }
    }
    for (index, binding) in facts.bindings.iter().enumerate() {
        let scope = &facts.scopes[binding.scope];
        if !scope.span.contains(binding.intro) {
            return Err(malformed(format!(
                "binding {index} intro is outside scope {}",
                binding.scope
            )));
        }
        if !binding_target_matches_kind(binding) {
            return Err(malformed(format!(
                "binding {index} has target incompatible with its kind"
            )));
        }
        if let BindingTarget::Def(id) = &binding.target {
            validate_identity(id, context, &format!("binding {index}"), &malformed)?;
            if !facts.symbols.iter().any(|symbol| &symbol.id == id) {
                return Err(malformed(format!(
                    "binding {index} targets a non-owned definition"
                )));
            }
        }
    }
    for (index, export) in facts.ffi_exports.iter().enumerate() {
        validate_identity(
            &export.symbol,
            context,
            &format!("ffi export {index}"),
            &malformed,
        )?;
        if !facts
            .symbols
            .iter()
            .any(|symbol| symbol.id == export.symbol)
        {
            return Err(malformed(format!(
                "ffi export {index} targets a non-owned definition"
            )));
        }
    }
    Ok(())
}

fn validate_structure(file: &FileFacts) -> Result<()> {
    let malformed = |reason: String| CodegraphError::MalformedFacts {
        file: file.file.clone(),
        reason,
    };
    for (index, scope) in file.scopes.iter().enumerate() {
        if let Some(parent) = scope.parent {
            if parent >= file.scopes.len() {
                return Err(malformed(format!(
                    "scope {index} has invalid parent {parent}"
                )));
            }
        }
    }
    for start in 0..file.scopes.len() {
        let mut current = start;
        for _ in 0..file.scopes.len() {
            match file.scopes[current].parent {
                Some(parent) => current = parent,
                None => break,
            }
        }
        if file.scopes[current].parent.is_some() {
            return Err(malformed(format!("scope {start} has a parent cycle")));
        }
    }
    for reference in &file.references {
        if let Some(scope) = reference.scope {
            if scope >= file.scopes.len() {
                return Err(malformed(format!(
                    "reference {} has invalid scope {scope}",
                    reference.name
                )));
            }
        }
    }
    for binding in &file.bindings {
        if binding.scope >= file.scopes.len() {
            return Err(malformed(format!(
                "binding {} has invalid scope {}",
                binding.name, binding.scope
            )));
        }
    }
    Ok(())
}

fn validate_span(
    span: ByteSpan,
    source_len: usize,
    owner: &str,
    malformed: &impl Fn(String) -> CodegraphError,
) -> Result<()> {
    if span.start > span.end {
        return Err(malformed(format!("{owner} has reversed span")));
    }
    if span.end > source_len {
        return Err(malformed(format!("{owner} span is outside source")));
    }
    Ok(())
}

fn contains_span(parent: ByteSpan, child: ByteSpan) -> bool {
    parent.start <= child.start && child.end <= parent.end
}

fn binding_target_matches_kind(binding: &super::Binding) -> bool {
    matches!(
        (&binding.kind, &binding.target),
        (
            super::BindingKind::Local | super::BindingKind::Param,
            BindingTarget::Local
        ) | (super::BindingKind::Import, BindingTarget::Import(_))
            | (super::BindingKind::Definition, BindingTarget::Def(_))
    )
}

fn validate_occurrence(
    file: &str,
    line: u32,
    byte: usize,
    context: FileFactsValidationContext<'_>,
    owner: &str,
    malformed: &impl Fn(String) -> CodegraphError,
) -> Result<()> {
    if file != context.expected_file {
        return Err(malformed(format!(
            "{owner} has foreign occurrence file `{file}`"
        )));
    }
    if line == 0 {
        return Err(malformed(format!("{owner} has zero line")));
    }
    if byte > context.source_len {
        return Err(malformed(format!(
            "{owner} occurrence byte is outside source"
        )));
    }
    Ok(())
}

fn validate_identity(
    id: &SymbolId,
    context: FileFactsValidationContext<'_>,
    owner: &str,
    malformed: &impl Fn(String) -> CodegraphError,
) -> Result<()> {
    match (id.language(), id.local_file()) {
        (Some(language), None) if language == context.expected_language.as_str() => Ok(()),
        (Some(language), None) => Err(malformed(format!(
            "{owner} has global identity language `{language}` instead of `{}`",
            context.expected_language.as_str()
        ))),
        (None, Some(file)) if file == context.expected_file => Ok(()),
        (None, Some(file)) => Err(malformed(format!(
            "{owner} has local identity file `{file}` instead of `{}`",
            context.expected_file
        ))),
        _ => Err(malformed(format!(
            "{owner} has invalid identity coordinates"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{
        Binding, BindingKind, FfiAbi, FfiExport, Occurrence, RefRole, Reference, Scope, ScopeKind,
        Symbol, SymbolKind, TypeRefContext, Visibility,
    };
    use crate::symbol::{Descriptor, SymbolId};

    fn id() -> SymbolId {
        SymbolId::global("rust", vec![Descriptor::Term("run".into())])
    }

    fn facts() -> FileFacts {
        FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: vec![Symbol {
                id: id(),
                name: "run".into(),
                kind: SymbolKind::Function,
                visibility: Visibility::Private,
                entry_points: vec![],
                file: "src/a.rs".into(),
                line: 1,
                span: ByteSpan { start: 0, end: 4 },
                signature: "fn run".into(),
            }],
            references: vec![Reference {
                name: "run".into(),
                occ: Occurrence {
                    file: "src/a.rs".into(),
                    line: 1,
                    col: 0,
                    byte: 3,
                },
                role: RefRole::Call,
                source_module: None,
                from_path: None,
                qualifier: None,
                scope: Some(0),
                type_ref_ctx: None,
            }],
            scopes: vec![Scope {
                parent: None,
                span: ByteSpan { start: 0, end: 4 },
                kind: ScopeKind::Module,
            }],
            bindings: vec![Binding {
                scope: 0,
                name: "run".into(),
                intro: 0,
                kind: BindingKind::Definition,
                target: BindingTarget::Def(id()),
            }],
            ffi_exports: vec![],
        }
    }

    fn context() -> FileFactsValidationContext<'static> {
        FileFactsValidationContext {
            expected_file: "src/a.rs",
            expected_language: Language::Rust,
            source_len: 4,
        }
    }

    fn assert_malformed(result: crate::error::Result<()>, expected_reason: &str) {
        match result {
            Err(crate::error::CodegraphError::MalformedFacts { file, reason }) => {
                assert_eq!(file, "src/a.rs");
                assert_eq!(reason, expected_reason);
            }
            Err(other) => panic!("expected malformed facts error, got {other:?}"),
            Ok(()) => panic!("expected malformed facts error"),
        }
    }

    #[test]
    fn context_accepts_empty_and_source_boundary_facts() {
        let empty = FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: vec![],
            references: vec![],
            scopes: vec![],
            bindings: vec![],
            ffi_exports: vec![],
        };
        assert!(
            validate_file_facts_with_context(
                &empty,
                FileFactsValidationContext {
                    source_len: 0,
                    ..context()
                }
            )
            .is_ok()
        );
        // `facts` has a symbol span ending at byte 4 and a reference within it.
        assert!(validate_file_facts_with_context(&facts(), context()).is_ok());
    }

    #[test]
    fn context_rejects_foreign_owner_and_language() {
        let mut value = facts();
        value.file = "src/b.rs".into();
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.lang = "python".into();
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.symbols[0].file = "src/b.rs".into();
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.symbols[0].id = SymbolId::global("python", vec![Descriptor::Term("run".into())]);
        assert!(validate_file_facts_with_context(&value, context()).is_err());
    }

    #[test]
    fn context_enforces_half_open_scope_relationships() {
        let mut value = facts();
        value.references[0].occ.byte = 4;
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "reference 0 is outside scope 0",
        );

        let mut value = facts();
        value.bindings[0].intro = 4;
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "binding 0 intro is outside scope 0",
        );

        // An EOF occurrence can be retained by facts without scope information;
        // validation does not invent a source-text extent for an occurrence.
        let mut value = facts();
        value.references[0].occ.byte = 4;
        value.references[0].scope = None;
        assert!(validate_file_facts_with_context(&value, context()).is_ok());
    }

    #[test]
    fn context_rejects_bad_spans_and_occurrences() {
        let mut value = facts();
        value.symbols[0].span = ByteSpan { start: 3, end: 2 };
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.scopes[0].span.end = 5;
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.symbols[0].line = 0;
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.references[0].occ.file = "src/b.rs".into();
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.references[0].occ.byte = 5;
        assert!(validate_file_facts_with_context(&value, context()).is_err());
    }

    #[test]
    fn context_rejects_role_specific_metadata_on_other_roles() {
        let mut value = facts();
        value.references[0].source_module = Some("module".into());
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "reference 0 has source_module outside import role",
        );

        let mut value = facts();
        value.references[0].role = RefRole::Read;
        value.references[0].qualifier = Some("module".into());
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "reference 0 has qualifier outside call or type-ref role",
        );

        let mut value = facts();
        value.references[0].type_ref_ctx = Some(TypeRefContext::Other);
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "reference 0 has type_ref_ctx outside type-ref role",
        );
    }

    #[test]
    fn context_validates_ffi_export_identity_and_ownership() {
        let mut value = facts();
        value.ffi_exports.push(FfiExport {
            symbol: id(),
            abi: FfiAbi::C,
            export_name: "run".into(),
        });
        assert!(validate_file_facts_with_context(&value, context()).is_ok());

        value.ffi_exports[0].symbol =
            SymbolId::global("rust", vec![Descriptor::Term("external".into())]);
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "ffi export 0 targets a non-owned definition",
        );
    }

    #[cfg(feature = "rust")]
    #[test]
    fn preserves_existing_extractor_scope_cycle_validation() {
        use crate::extract::{Extractor, RustExtractor};

        let mut value = RustExtractor.extract("fn run() {}", "src/a.rs").unwrap();
        value.scopes = vec![Scope {
            parent: Some(0),
            span: ByteSpan { start: 0, end: 1 },
            kind: ScopeKind::Module,
        }];
        assert!(validate_file_facts(&[value]).is_err());
    }

    #[test]
    fn context_accepts_local_and_external_facts_without_source_claims() {
        let mut value = facts();
        let local_id = SymbolId::local("src/a.rs", "local-definition");
        value.symbols[0].id = local_id.clone();
        value.bindings[0].target = BindingTarget::Def(local_id);
        value.references[0].role = RefRole::Import;
        value.references[0].from_path = Some("third-party/package".into());
        value.bindings.push(Binding {
            scope: 0,
            name: "dependency".into(),
            intro: 1,
            kind: BindingKind::Import,
            target: BindingTarget::Import("third-party/package".into()),
        });
        assert!(validate_file_facts_with_context(&value, context()).is_ok());
    }

    #[test]
    fn context_rejects_incompatible_binding_targets_with_stable_error() {
        let mut value = facts();
        value.bindings[0].kind = BindingKind::Param;
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "binding 0 has target incompatible with its kind",
        );

        let mut value = facts();
        value.bindings[0].kind = BindingKind::Import;
        value.bindings[0].target = BindingTarget::Import(String::new());
        assert!(validate_file_facts_with_context(&value, context()).is_ok());
    }

    #[test]
    fn context_accepts_qualified_type_references() {
        let mut value = facts();
        value.references[0].role = RefRole::TypeRef;
        value.references[0].qualifier = Some("resource".into());
        assert!(validate_file_facts_with_context(&value, context()).is_ok());
    }

    #[test]
    fn invalid_indices_return_malformed_facts_without_panicking() {
        let mut value = facts();
        value.scopes[0].parent = Some(1);
        assert_malformed(
            validate_file_facts_with_context(&value, context()),
            "scope 0 has invalid parent 1",
        );
    }

    #[cfg(feature = "svelte")]
    #[test]
    fn context_accepts_svelte_script_symbols_as_svelte_identities() {
        use crate::extract::{Extractor, SvelteExtractor};

        let source = "<script>export function run() {}</script>";
        let extracted = SvelteExtractor.extract(source, "src/App.svelte").unwrap();
        assert!(
            validate_file_facts_with_context(
                &extracted,
                FileFactsValidationContext {
                    expected_file: "src/App.svelte",
                    expected_language: Language::Svelte,
                    source_len: source.len(),
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_scope_cycles_indices_and_invalid_binding_relationships() {
        let mut value = facts();
        value.scopes[0].parent = Some(0);
        assert!(validate_file_facts(&[value]).is_err());
        let mut value = facts();
        value.references[0].scope = Some(1);
        assert!(validate_file_facts(&[value]).is_err());
        let mut value = facts();
        value.bindings[0].intro = 5;
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.scopes.push(Scope {
            parent: Some(0),
            span: ByteSpan { start: 3, end: 4 },
            kind: ScopeKind::Block,
        });
        value.scopes[0].span.end = 2;
        assert!(validate_file_facts_with_context(&value, context()).is_err());
        let mut value = facts();
        value.bindings[0].target = BindingTarget::Def(SymbolId::local("src/b.rs", "x"));
        assert!(validate_file_facts_with_context(&value, context()).is_err());
    }
}
