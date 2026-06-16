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
//! The merger must fix up [`ScopeId`] indices because scope Vecs from each
//! block are local Vec indices — appending a second block's scopes shifts its
//! base, so bindings and references that reference scope indices are adjusted
//! by the scope-base offset before extending the merged Vec.

use tree_sitter::{Node, Parser};

use crate::error::{CodegraphError, Result};
use crate::graph::types::{FileFacts, ScopeId};
use crate::lang::Language;

use super::Extractor;
use super::shift_offsets;
use super::typescript::extract_ecmascript;

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

        for script_el in script_nodes {
            // Find the raw_text child — skip empty script blocks.
            let raw_text = match find_raw_text(&script_el) {
                Some(n) => n,
                None => continue,
            };

            let delta = raw_text.start_byte();
            let inner_source =
                std::str::from_utf8(&bytes[raw_text.byte_range()]).unwrap_or_default();

            // Detect lang="ts"/"typescript" inside the start_tag.
            let inner_lang = detect_script_lang(&script_el, bytes);

            let mut block_facts = extract_ecmascript(inner_source, file, inner_lang)?;
            shift_offsets(&mut block_facts, delta, file, "svelte", bytes);

            // Merge: fix up ScopeId indices before extending.
            let scope_base: ScopeId = merged.scopes.len();
            if scope_base > 0 {
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
            }

            merged.symbols.extend(block_facts.symbols);
            merged.references.extend(block_facts.references);
            merged.scopes.extend(block_facts.scopes);
            merged.bindings.extend(block_facts.bindings);
            // ffi_exports: Svelte scripts don't emit FFI exports.
        }

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

/// Detect whether `<script lang="ts">` or `<script lang="typescript">` is
/// present on the script element.  Falls back to [`Language::JavaScript`].
fn detect_script_lang(script_el: &Node<'_>, bytes: &[u8]) -> Language {
    let mut cursor = script_el.walk();
    for child in script_el.children(&mut cursor) {
        if child.kind() == "start_tag" {
            let mut tag_cursor = child.walk();
            for attr in child.children(&mut tag_cursor) {
                if attr.kind() != "attribute" {
                    continue;
                }
                // Check attribute_name == "lang"
                let mut attr_cursor = attr.walk();
                let attr_children: Vec<_> = attr.children(&mut attr_cursor).collect();
                let name_matches = attr_children
                    .iter()
                    .any(|n| n.kind() == "attribute_name" && &bytes[n.byte_range()] == b"lang");
                if !name_matches {
                    continue;
                }
                // Look for quoted_attribute_value → attribute_value
                for child2 in &attr_children {
                    if child2.kind() == "quoted_attribute_value" {
                        let mut qav_cursor = child2.walk();
                        for av in child2.children(&mut qav_cursor) {
                            if av.kind() == "attribute_value" {
                                let val = &bytes[av.byte_range()];
                                if val == b"ts" || val == b"typescript" {
                                    return Language::TypeScript;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Language::JavaScript
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
    fn extracts_run_symbol_and_reference_lang_ts() {
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
        assert!(
            run_sym.is_some(),
            "expected `run` function symbol; got: {:?}",
            facts.symbols
        );

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
    fn no_script_block_returns_empty_facts_no_panic() {
        let source = r#"<main><p>Hello world</p></main>"#;
        let facts = SvelteExtractor
            .extract(source, "src/NoScript.svelte")
            .expect("extraction should succeed even with no script");

        assert_eq!(facts.lang, "svelte");
        assert_eq!(facts.file, "src/NoScript.svelte");
        assert!(facts.symbols.is_empty(), "expected no symbols");
        assert!(facts.references.is_empty(), "expected no references");
    }
}
