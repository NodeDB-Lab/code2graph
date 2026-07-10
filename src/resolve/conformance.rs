// SPDX-License-Identifier: Apache-2.0

//! Conformance resolver: inherited-member recall over the type hierarchy.
//!
//! This is an **additive** resolver. When a member is referenced on a type that
//! does not define it directly but **inherits or implements** it from a
//! supertype / trait / interface, this resolver links the reference to the
//! inherited definition. The link is a deterministic *structural* derivation —
//! it walks the [`RefRole::IsImplementation`] edges already produced by the
//! extractors up the type hierarchy. It is **not** type inference: no receiver
//! type is inferred, no return type is computed, no overload is resolved by
//! signature. Every edge is tagged [`Confidence::Scoped`] (structurally
//! narrowed, but not type-checked) and [`Provenance::Conformance`].
//!
//! # What it covers (the honest v1 boundary)
//!
//! Only references where the call site **textually qualifies the owning type**
//! are considered — i.e. the extractor populated
//! [`Reference::qualifier`](crate::graph::types::Reference::qualifier) with
//! the written type name (`Foo::bar()`, `Type.method()`). For such a reference,
//! if `Foo` does not define `bar` directly but a supertype of `Foo` does, an
//! edge is drawn to the inherited definition (first match wins, walking the
//! hierarchy depth-first).
//!
//! # What it deliberately defers (the type-inference ceiling)
//!
//! - `self.method()` / `this.method()` — the qualifier is absent; resolving it
//!   needs the *receiver's* type, which is type inference.
//! - chained `inner().method()` — needs the return type of `inner()`.
//! - field-access chains (`a.b.method()`) — needs the field's type.
//!
//! These are out of scope: code2graph stays build-free and does not infer types.
//! When the qualifier is missing, this resolver simply emits nothing for that
//! reference (recall is only ever *added*, never faked).

use std::collections::{HashMap, HashSet};

use crate::graph::types::{
    CodeGraph, Confidence, Edge, FileFacts, Provenance, RefRole, Symbol, SymbolKind,
};
use crate::symbol::SymbolId;

use super::Resolver;
use super::{dedup_files_last_wins, enclosing_symbol_index};

/// Inherited-member recall resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConformanceResolver;

/// Whether a symbol is a *member of a type* — i.e. its descriptor chain has at
/// least two names (an owning container plus the member leaf) and its own kind
/// is a member kind (`Method`/`Const`/`Static`). For such a symbol the
/// penultimate descriptor name is the owning type and the leaf is the member.
///
/// `SymbolId` exposes descriptor *names* but not descriptor *kinds*, so the
/// symbol's own [`SymbolKind`] is the cleanest available signal that the
/// penultimate descriptor is a type (a member always renders under `Type#`).
fn member_of_type(sym: &Symbol) -> Option<(String /* type */, String /* member */)> {
    if !matches!(
        sym.kind,
        SymbolKind::Method | SymbolKind::Const | SymbolKind::Static
    ) {
        return None;
    }
    // Collect only the last two descriptor names without allocating a Vec.
    let mut second_last: Option<&str> = None;
    let mut last: Option<&str> = None;
    for name in sym.id.descriptor_names_iter() {
        second_last = last;
        last = Some(name);
    }
    match (second_last, last) {
        (Some(type_name), Some(member)) => Some((type_name.to_owned(), member.to_owned())),
        _ => None,
    }
}

impl Resolver for ConformanceResolver {
    fn resolve(&self, files: &[FileFacts]) -> crate::Result<CodeGraph> {
        crate::validate_file_facts(files)?;
        let files = dedup_files_last_wins(files);
        // ── 1. Flatten all symbols + a per-file index for caller attribution ──
        let symbols: Vec<Symbol> = files
            .iter()
            .flat_map(|f| f.symbols.iter().cloned())
            .collect();

        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_file.entry(s.file.as_str()).or_default().push(i);
        }

        // ── 2. type name → { member leaf → inherited member SymbolId } ────────
        let mut members: HashMap<String, HashMap<String, SymbolId>> = HashMap::new();
        for s in &symbols {
            if let Some((type_name, member)) = member_of_type(s) {
                members
                    .entry(type_name)
                    .or_default()
                    .entry(member)
                    .or_insert_with(|| s.id.clone());
            }
        }

        // ── 3. type name → [supertype bare names] (insertion order preserved) ─
        let mut supertypes: HashMap<String, Vec<String>> = HashMap::new();
        for f in files.iter().copied() {
            let file_syms = by_file.get(f.file.as_str());
            for r in &f.references {
                if r.role != RefRole::IsImplementation {
                    continue;
                }
                // The implementing type is the symbol enclosing this ref.
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue;
                };
                let Some(impl_type) = symbols[from_idx].id.leaf_name().map(|s| s.to_owned()) else {
                    continue;
                };
                supertypes
                    .entry(impl_type)
                    .or_default()
                    .push(r.name.clone());
            }
        }

        // ── 4. emit conformance edges for type-qualified member uses ──────────
        let mut edges: Vec<Edge> = Vec::new();
        for f in files.iter().copied() {
            let file_syms = by_file.get(f.file.as_str());
            for r in &f.references {
                // Only the honest, type-qualified cases (no receiver inference).
                if !matches!(r.role, RefRole::Call | RefRole::TypeRef) {
                    continue;
                }
                let Some(qualifier) = r.qualifier.as_deref() else {
                    continue; // unqualified → would need receiver-type inference
                };
                // The written type name is the last segment of the qualifier
                // (`a::b::Foo` → `Foo`, `Foo` → `Foo`). Iterate directly to
                // avoid an intermediate Vec allocation on every reference.
                let Some(type_name) = qualifier.split(['.', '/', ':']).rfind(|s| {
                    !s.is_empty() && !matches!(*s, "." | ".." | "crate" | "self" | "super")
                }) else {
                    continue;
                };
                let member = r.name.as_str();

                // Direct members are handled by the base resolvers — skip.
                if members
                    .get(type_name)
                    .is_some_and(|m| m.contains_key(member))
                {
                    continue;
                }

                // Walk supertypes depth-first; first ancestor defining `member`
                // wins. The visited set keeps the walk cycle-safe and stable.
                let Some(inherited) = find_inherited(type_name, member, &members, &supertypes)
                else {
                    continue;
                };

                // Attribute the edge's source to the enclosing caller symbol.
                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue;
                };

                edges.push(Edge {
                    from: symbols[from_idx].id.clone(),
                    to: inherited,
                    role: r.role,
                    confidence: Confidence::Scoped,
                    provenance: Provenance::Conformance,
                    occ: r.occ.clone(),
                });
            }
        }

        Ok(CodeGraph { symbols, edges })
    }
}

/// Depth-first walk up `supertypes[type_name]`, returning the inherited member's
/// [`SymbolId`] at the first ancestor type that defines `member`. Cycle-safe via
/// a visited-name set; order-stable because the supertype vectors preserve
/// insertion order and the recursion is left-to-right.
fn find_inherited(
    type_name: &str,
    member: &str,
    members: &HashMap<String, HashMap<String, SymbolId>>,
    supertypes: &HashMap<String, Vec<String>>,
) -> Option<SymbolId> {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(type_name.to_owned());
    let mut stack: Vec<String> = supertypes
        .get(type_name)
        .map(|v| v.iter().rev().cloned().collect())
        .unwrap_or_default();

    while let Some(ancestor) = stack.pop() {
        if !visited.insert(ancestor.clone()) {
            continue;
        }
        if let Some(id) = members.get(&ancestor).and_then(|m| m.get(member)) {
            return Some(id.clone());
        }
        if let Some(parents) = supertypes.get(&ancestor) {
            // Push in reverse so the first-declared parent is explored first.
            for p in parents.iter().rev() {
                if !visited.contains(p) {
                    stack.push(p.clone());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{Extractor, JavaExtractor, RustExtractor};
    use crate::graph::types::{Occurrence, Reference};

    /// Build a synthetic, type-qualified member-call reference. No extractor
    /// emits a call `qualifier` yet (only Rust captures path qualifiers, and the
    /// receiver of a `Type.method()` call is not captured anywhere), so the
    /// honest v1 *input shape* — a qualified member use — is injected here, the
    /// same way the symbol-table tests inject `Import` references. The symbols
    /// and the supertype edges under test are still produced by the real
    /// extractor.
    fn qualified_call(name: &str, qualifier: &str, file: &str, byte: usize) -> Reference {
        Reference {
            name: name.to_owned(),
            occ: Occurrence {
                file: file.to_owned(),
                line: 1,
                col: 0,
                byte,
            },
            role: RefRole::Call,
            source_module: None,
            from_path: None,
            qualifier: Some(qualifier.to_owned()),
            scope: None,
            type_ref_ctx: None,
        }
    }

    /// `class Base { void process(){} }`, `class Sub extends Base {}`, and a
    /// caller that qualifies `Sub.process()`. The only definition of `process`
    /// lives on `Base`, so conformance must link the call to `Base#process()`.
    #[test]
    fn java_inherited_method_resolves_via_conformance() {
        let base = JavaExtractor
            .extract(
                "package p; public class Base { public void process() {} }",
                "src/p/Base.java",
            )
            .unwrap();
        let sub = JavaExtractor
            .extract(
                "package p; public class Sub extends Base {}",
                "src/p/Sub.java",
            )
            .unwrap();

        // Caller: a class whose method body holds the qualified `Sub.process()`.
        // We extract a real caller class to get a containing symbol, then inject
        // the qualified reference at a byte inside that symbol's span.
        let mut caller = JavaExtractor
            .extract(
                "package p; public class Caller { public void run() {} }",
                "src/p/Caller.java",
            )
            .unwrap();
        // Find a byte inside the `run` method symbol so the edge's `from`
        // attributes to it.
        let run = caller
            .symbols
            .iter()
            .find(|s| s.name == "run")
            .expect("run method symbol");
        let byte = run.span.start;
        caller
            .references
            .push(qualified_call("process", "Sub", "src/p/Caller.java", byte));

        let graph = ConformanceResolver.resolve(&[base, sub, caller]).unwrap();

        let conf_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::Conformance)
            .collect();
        assert_eq!(
            conf_edges.len(),
            1,
            "expected exactly one conformance edge, got {:?}",
            conf_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
        let e = conf_edges[0];
        assert_eq!(e.role, RefRole::Call);
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::Conformance);
        assert!(
            e.to.to_scip_string().ends_with("Base#process()."),
            "edge `to` should be the inherited Base#process(), got: {}",
            e.to.to_scip_string()
        );
        assert!(
            e.from.to_scip_string().ends_with("Caller#run()."),
            "edge `from` should be the enclosing caller method, got: {}",
            e.from.to_scip_string()
        );
    }

    /// Multi-level: `Sub extends Base`, `Base extends Root`, member only on
    /// `Root`. The depth-first walk must climb two levels to find it.
    #[test]
    fn java_multi_level_inheritance_walks_chain() {
        let root = JavaExtractor
            .extract(
                "package p; public class Root { public void process() {} }",
                "src/p/Root.java",
            )
            .unwrap();
        let base = JavaExtractor
            .extract(
                "package p; public class Base extends Root {}",
                "src/p/Base.java",
            )
            .unwrap();
        let sub = JavaExtractor
            .extract(
                "package p; public class Sub extends Base {}",
                "src/p/Sub.java",
            )
            .unwrap();
        let mut caller = JavaExtractor
            .extract(
                "package p; public class Caller { public void run() {} }",
                "src/p/Caller.java",
            )
            .unwrap();
        let byte = caller
            .symbols
            .iter()
            .find(|s| s.name == "run")
            .expect("run symbol")
            .span
            .start;
        caller
            .references
            .push(qualified_call("process", "Sub", "src/p/Caller.java", byte));

        let graph = ConformanceResolver
            .resolve(&[root, base, sub, caller])
            .unwrap();
        let conf_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::Conformance)
            .collect();
        assert_eq!(conf_edges.len(), 1, "expected one conformance edge");
        assert!(
            conf_edges[0]
                .to
                .to_scip_string()
                .ends_with("Root#process()."),
            "should climb two levels to Root#process(), got: {}",
            conf_edges[0].to.to_scip_string()
        );
    }

    /// A direct member called qualified on its OWN type emits no conformance
    /// edge (the base resolvers already handle direct members; we must not
    /// duplicate at `Scoped`).
    #[test]
    fn direct_member_does_not_emit_conformance_edge() {
        let base = JavaExtractor
            .extract(
                "package p; public class Base { public void process() {} }",
                "src/p/Base.java",
            )
            .unwrap();
        let mut caller = JavaExtractor
            .extract(
                "package p; public class Caller { public void run() {} }",
                "src/p/Caller.java",
            )
            .unwrap();
        let byte = caller
            .symbols
            .iter()
            .find(|s| s.name == "run")
            .expect("run symbol")
            .span
            .start;
        // Qualify `Base.process()` directly on Base, which DEFINES process.
        caller
            .references
            .push(qualified_call("process", "Base", "src/p/Caller.java", byte));

        let graph = ConformanceResolver.resolve(&[base, caller]).unwrap();
        let conf_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::Conformance)
            .collect();
        assert!(
            conf_edges.is_empty(),
            "direct member must not yield a conformance edge, got {:?}",
            conf_edges
                .iter()
                .map(|e| e.to.to_scip_string())
                .collect::<Vec<_>>()
        );
    }

    /// End-to-end proof: conformance fires on REAL Rust extraction with no injected
    /// references.  `Person::hello(p)` in main.rs uses a path-qualified call
    /// (`scoped_identifier` in tree-sitter-rust) so the extractor sets
    /// `qualifier = Some("Person")` and `name = "hello"`.  `Person` has an
    /// `IsImplementation` edge to `Greet` (from `impl Greet for Person`) so
    /// conformance walks up to `Greet` and finds `Greet#hello().` — now a real
    /// symbol thanks to the trait-member extraction added to `collect_symbols`.
    ///
    /// Static-reasoning check:
    /// - `src/greet.rs`  → symbols: `Greet` (Trait) + `Greet#hello().` (Method)
    /// - `src/person.rs` → symbols: `Person` (Struct) + `Person` (Impl); references:
    ///   `IsImplementation("Greet")` inside the impl span.
    ///   `enclosing_symbol_index` picks the smallest span containing the `Greet`
    ///   node byte; the impl block (`Person` Impl) is smaller than the file root,
    ///   so `impl_type` = `"Person"` → `supertypes["Person"] = ["Greet"]`.
    /// - `src/main.rs`   → Call ref `name="hello"`, `qualifier=Some("Person")`
    ///   `type_name = "Person"`, no direct `hello` member, ancestor `"Greet"` has
    ///   `hello` → conformance emits `Call` edge to `Greet#hello().`,
    ///   `Confidence::Scoped`, `Provenance::Conformance`.
    #[test]
    fn conformance_resolves_rust_inherited_trait_method_end_to_end() {
        let greet = RustExtractor
            .extract("pub trait Greet { fn hello(&self); }", "src/greet.rs")
            .unwrap();
        let person = RustExtractor
            .extract(
                "pub struct Person; impl crate::greet::Greet for Person { fn hello(&self) {} }",
                "src/person.rs",
            )
            .unwrap();
        let main = RustExtractor
            .extract(
                "pub fn run(p: &Person) { Person::hello(p); }",
                "src/main.rs",
            )
            .unwrap();

        let graph = ConformanceResolver.resolve(&[greet, person, main]).unwrap();

        let conf_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::Conformance)
            .collect();

        // There must be at least one conformance edge whose `to` ends with
        // `Greet#hello().` — the inherited method definition on the trait.
        let to_hello: Vec<_> = conf_edges
            .iter()
            .filter(|e| e.to.to_scip_string().ends_with("Greet#hello()."))
            .collect();
        assert!(
            !to_hello.is_empty(),
            "expected a conformance edge to Greet#hello()., got conformance edges: {:?}",
            conf_edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );

        let e = to_hello[0];
        assert_eq!(
            e.role,
            RefRole::Call,
            "edge role should be Call, got {:?}",
            e.role
        );
        assert_eq!(
            e.confidence,
            Confidence::Scoped,
            "edge confidence should be Scoped, got {:?}",
            e.confidence
        );
        assert_eq!(
            e.provenance,
            Provenance::Conformance,
            "edge provenance should be Conformance, got {:?}",
            e.provenance
        );
        // The `from` must be the enclosing `run` function in main.rs.
        assert!(
            e.from.to_scip_string().ends_with("run()."),
            "edge `from` should end with 'run().', got: {}",
            e.from.to_scip_string()
        );
    }

    /// An unqualified reference (no receiver type written) is deferred entirely:
    /// resolving it would need receiver-type inference, which v1 does not do.
    #[test]
    fn unqualified_reference_is_deferred() {
        let base = JavaExtractor
            .extract(
                "package p; public class Base { public void process() {} }",
                "src/p/Base.java",
            )
            .unwrap();
        let sub = JavaExtractor
            .extract(
                "package p; public class Sub extends Base {}",
                "src/p/Sub.java",
            )
            .unwrap();
        let mut caller = JavaExtractor
            .extract(
                "package p; public class Caller { public void run() {} }",
                "src/p/Caller.java",
            )
            .unwrap();
        let byte = caller
            .symbols
            .iter()
            .find(|s| s.name == "run")
            .expect("run symbol")
            .span
            .start;
        // No qualifier → must be skipped.
        let mut unq = qualified_call("process", "Sub", "src/p/Caller.java", byte);
        unq.qualifier = None;
        caller.references.push(unq);

        let graph = ConformanceResolver.resolve(&[base, sub, caller]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::Conformance),
            "unqualified ref must not produce a conformance edge"
        );
    }
}
