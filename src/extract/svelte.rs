// SPDX-License-Identifier: Apache-2.0

//! Svelte single-file component extractor.
//!
//! Parses the `.svelte` file with tree-sitter-svelte-ng, locates every
//! `<script>` block, delegates the inner source to the existing TypeScript /
//! JavaScript extraction core (`extract_ecmascript`), then remaps all byte
//! offsets back into the full `.svelte` file.  Two script blocks may be
//! present: the normal instance block and `<script context="module">`;
//! symbols and references from both are merged into a single [`FileFacts`].
//!
//! The merger pushes one document-spanning root [`ScopeKind::Module`] scope at
//! index 0, then re-parents each `<script>` block's own root scope under it so
//! the merged file has exactly one root (`parent == None`) — mirroring every
//! other language's one-module-per-file shape.  `ScopeId` indices from each
//! block are shifted by `scope_base` before the block's scopes are appended.
//!
//! Per-block [`SymbolKind::Module`] symbols are filtered out during the merge;
//! a single Module symbol spanning the whole document is synthesized once,
//! after the loop, giving the component a stable SCIP identity regardless of
//! how many `<script>` blocks it contains.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{ByteSpan, FileFacts, ScopeId, ScopeKind, SymbolKind};
use crate::lang::Language;

use super::Extractor;
use super::module_symbol;
use super::push_scope;
use super::shift_offsets;
use super::typescript::{extract_ecmascript, module_namespaces};

/// Extracts facts from a Svelte single-file component.
pub struct SvelteExtractor;

impl Extractor for SvelteExtractor {
    fn lang(&self) -> Language {
        Language::Svelte
    }

    fn extract(&self, source: &str, file: &str) -> Result<FileFacts> {
        let ts_lang = crate::grammar::svelte();
        let mut parser = Parser::new();
        parser
            .set_language(&ts_lang)
            .map_err(|_| CodegraphError::Parse {
                path: file.to_owned(),
            })?;

        let tree = parser
            .parse(source.as_bytes(), None)
            .ok_or_else(|| CodegraphError::Parse {
                path: file.to_owned(),
            })?;

        let root = tree.root_node();
        let bytes = source.as_bytes();

        // Collect all script_element nodes anywhere in the document.
        let mut script_nodes = Vec::new();
        collect_script_elements(&root, &mut script_nodes);

        // Start with an empty merged result.
        let mut merged = FileFacts {
            file: file.to_owned(),
            lang: "svelte".to_owned(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        };

        // A single document-spanning root scope. Each `<script>` block's former
        // root scope is re-parented under this so the merged file has exactly one
        // root (`parent == None`) — mirroring every other language's one-module-
        // per-file shape.
        let doc_root: ScopeId = push_scope(
            &mut merged.scopes,
            None,
            ByteSpan {
                start: 0,
                end: source.len(),
            },
            ScopeKind::Module,
        );

        for script_el in script_nodes {
            // Find the raw_text child — skip empty script blocks.
            let raw_text = match find_raw_text(&script_el) {
                Some(n) => n,
                None => continue,
            };

            let delta = raw_text.start_byte();
            let inner_source =
                std::str::from_utf8(&bytes[raw_text.byte_range()]).unwrap_or_default();

            // The embedded parser is TypeScript's JavaScript-superset grammar,
            // but these definitions belong to the enclosing Svelte document.
            // Keeping the output language Svelte makes every global identity
            // agree with the containing FileFacts coordinates.
            let mut block_facts = extract_ecmascript(inner_source, file, Language::Svelte, None)?;
            shift_offsets(&mut block_facts, delta, file, "svelte", bytes);

            // Merge: fix up ScopeId indices before extending. `scope_base` is >= 1
            // for every block (the doc root occupies index 0), so the shifts apply
            // uniformly.
            let scope_base: ScopeId = merged.scopes.len();
            // Shift scope field on bindings from this block.
            for b in &mut block_facts.bindings {
                b.scope += scope_base;
            }
            // Shift scope field on references from this block.
            for r in &mut block_facts.references {
                if let Some(s) = r.scope.as_mut() {
                    *s += scope_base;
                }
            }
            // Shift parent ScopeId on scopes from this block.
            for sc in &mut block_facts.scopes {
                if let Some(p) = sc.parent.as_mut() {
                    *p += scope_base;
                }
            }
            // Re-parent the block's former root scope (local index 0, parent None,
            // untouched by the Some(p) shift above) under the document root.
            if let Some(first) = block_facts.scopes.first_mut() {
                first.parent = Some(doc_root);
            }

            // Drop the per-block module symbols — they share one SCIP id and would
            // be duplicate identities. The single document module symbol is
            // synthesized once, after the loop.
            merged.symbols.extend(
                block_facts
                    .symbols
                    .into_iter()
                    .filter(|s| s.kind != SymbolKind::Module),
            );
            merged.references.extend(block_facts.references);
            merged.scopes.extend(block_facts.scopes);
            merged.bindings.extend(block_facts.bindings);
            // ffi_exports: Svelte scripts don't emit FFI exports.
        }

        // Exactly one module symbol spanning the whole document — its SCIP id is
        // identical to a single-script `.svelte` (the rendered id ignores `lang`).
        let namespaces = module_namespaces(file);
        merged.symbols.push(module_symbol(
            Language::Svelte,
            &namespaces,
            file,
            source.len(),
        ));

        Ok(merged)
    }
}

/// Walk the tree recursively and collect every `script_element` node.
fn collect_script_elements<'a>(node: &Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "script_element" {
        out.push(*node);
        return; // script_element children are its own internals, not nested scripts
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_script_elements(&child, out);
    }
}

/// Return the `raw_text` child of a `script_element`, if one exists.
fn find_raw_text<'a>(script_el: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = script_el.walk();
    script_el
        .children(&mut cursor)
        .find(|n| n.kind() == "raw_text")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::SymbolKind;

    fn svelte_source_with_ts_script() -> &'static str {
        r#"<script lang="ts">
import { foo } from './util';
export function run(x: number) { foo(x); }
let count = 0;
</script>
<main>Hello</main>"#
    }

    #[test]
    fn extracts_run_symbol_and_reference_with_svelte_identity() {
        let source = svelte_source_with_ts_script();
        let facts = SvelteExtractor
            .extract(source, "src/App.svelte")
            .expect("extraction should succeed");

        assert_eq!(facts.lang, "svelte");
        assert_eq!(facts.file, "src/App.svelte");

        let run_sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "run" && s.kind == SymbolKind::Function);
        let run_sym = run_sym.expect("expected `run` function symbol");
        assert_eq!(run_sym.id.language(), Some("svelte"));

        // Must have at least a call/import reference (foo, or import {foo}).
        assert!(
            !facts.references.is_empty(),
            "expected at least one reference"
        );
    }

    #[test]
    fn offset_remap_is_correct() {
        let source = svelte_source_with_ts_script();
        let facts = SvelteExtractor
            .extract(source, "src/App.svelte")
            .expect("extraction should succeed");

        let run_sym = facts
            .symbols
            .iter()
            .find(|s| s.name == "run" && s.kind == SymbolKind::Function)
            .expect("`run` symbol must be present");

        // The span.start of `run` must point at the declaration in the FULL
        // .svelte source — not at its offset in the inner script. The TS
        // extractor spans an exported function from the `export` keyword, so the
        // span must align with `export function run` in the embedding document.
        let expected_start = source
            .find("export function run")
            .expect("`export function run` must appear in source");
        assert_eq!(
            run_sym.span.start, expected_start,
            "span.start should be the byte offset of the `run` declaration in the full .svelte source"
        );
        // And the span must slice back to real source containing the name.
        assert!(
            source[run_sym.span.start..run_sym.span.end].contains("run"),
            "remapped span must slice the run declaration out of the .svelte source"
        );
    }

    #[test]
    fn extracts_js_script_no_lang_attr() {
        let source = r#"<script>
export function greet(name) { return name; }
</script>
<p>Hi</p>"#;
        let facts = SvelteExtractor
            .extract(source, "src/Comp.svelte")
            .expect("extraction should succeed");

        assert_eq!(facts.lang, "svelte", "lang should always be 'svelte'");
        let greet = facts.symbols.iter().find(|s| s.name == "greet");
        assert!(
            greet.is_some(),
            "expected `greet` symbol; got: {:?}",
            facts.symbols
        );
    }

    #[test]
    fn two_script_blocks_both_extracted_and_scope_indices_valid() {
        let source = r#"<script context="module">
export function preload() {}
</script>
<script>
export function setup() {}
</script>
<div>content</div>"#;
        let facts = SvelteExtractor
            .extract(source, "src/Page.svelte")
            .expect("extraction should succeed");

        let has_preload = facts.symbols.iter().any(|s| s.name == "preload");
        let has_setup = facts.symbols.iter().any(|s| s.name == "setup");
        assert!(has_preload, "expected `preload` from module script block");
        assert!(has_setup, "expected `setup` from instance script block");

        // Exactly ONE module symbol, spanning the whole document — both script
        // blocks no longer emit duplicate module symbols.
        let module_syms: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Module)
            .collect();
        assert_eq!(
            module_syms.len(),
            1,
            "expected exactly one Module symbol, got {module_syms:?}"
        );
        assert_eq!(module_syms[0].span.start, 0, "module span must start at 0");
        assert_eq!(
            module_syms[0].span.end,
            source.len(),
            "module span must cover the whole document"
        );

        // Exactly one root scope (`parent == None`), spanning the whole document.
        let root_scopes: Vec<_> = facts.scopes.iter().filter(|s| s.parent.is_none()).collect();
        assert_eq!(
            root_scopes.len(),
            1,
            "expected exactly one root scope, got {root_scopes:?}"
        );
        assert_eq!(root_scopes[0].span.start, 0, "root scope must start at 0");
        assert_eq!(
            root_scopes[0].span.end,
            source.len(),
            "root scope must cover the whole document"
        );

        // Each block's former root scope is now re-parented under the doc root
        // (index 0). The doc root is the only scope with parent None; every other
        // module-kind scope must point at it.
        let block_roots: Vec<_> = facts
            .scopes
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != 0 && s.kind == ScopeKind::Module)
            .collect();
        assert!(
            !block_roots.is_empty(),
            "expected at least one re-parented block root scope"
        );
        for (i, sc) in &block_roots {
            assert_eq!(
                sc.parent,
                Some(0),
                "block root scope at index {i} must be re-parented under the doc root"
            );
        }

        // All binding scope indices must be valid (in-bounds for the merged scopes vec).
        for b in &facts.bindings {
            assert!(
                b.scope < facts.scopes.len() || facts.scopes.is_empty(),
                "binding scope {} out of range (scopes.len={})",
                b.scope,
                facts.scopes.len()
            );
        }
        // All reference scope indices must be valid.
        for r in &facts.references {
            if let Some(s) = r.scope {
                assert!(
                    s < facts.scopes.len(),
                    "reference scope {} out of range (scopes.len={})",
                    s,
                    facts.scopes.len()
                );
            }
        }
    }

    #[test]
    fn no_script_block_emits_single_module_symbol_and_root_scope() {
        let source = r#"<main><p>Hello world</p></main>"#;
        let facts = SvelteExtractor
            .extract(source, "src/NoScript.svelte")
            .expect("extraction should succeed even with no script");

        assert_eq!(facts.lang, "svelte");
        assert_eq!(facts.file, "src/NoScript.svelte");

        // A script-less component still emits exactly one Module symbol spanning
        // the whole document (consistent with every other language) and no refs.
        assert_eq!(facts.symbols.len(), 1, "expected exactly one symbol");
        assert_eq!(facts.symbols[0].kind, SymbolKind::Module);
        assert_eq!(facts.symbols[0].span.start, 0);
        assert_eq!(facts.symbols[0].span.end, source.len());
        assert!(facts.references.is_empty(), "expected no references");

        // Exactly one root scope spanning the whole document.
        assert_eq!(facts.scopes.len(), 1, "expected exactly one (root) scope");
        assert_eq!(facts.scopes[0].parent, None);
        assert_eq!(facts.scopes[0].span.start, 0);
        assert_eq!(facts.scopes[0].span.end, source.len());
    }

    #[test]
    fn single_script_emits_one_module_symbol_spanning_document() {
        let source = svelte_source_with_ts_script();
        let facts = SvelteExtractor
            .extract(source, "src/App.svelte")
            .expect("extraction should succeed");

        let module_syms: Vec<_> = facts
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Module)
            .collect();
        assert_eq!(
            module_syms.len(),
            1,
            "single-script .svelte must yield exactly one Module symbol, got {module_syms:?}"
        );
        assert_eq!(module_syms[0].span.start, 0, "module span must start at 0");
        assert_eq!(
            module_syms[0].span.end,
            source.len(),
            "module span must cover the whole document"
        );
        // The SCIP id ignores `lang`, so it matches the file's module path.
        assert_eq!(
            module_syms[0].id.to_scip_string(),
            "codegraph . . . src/App/"
        );
    }
}
