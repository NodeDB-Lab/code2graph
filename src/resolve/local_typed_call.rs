// SPDX-License-Identifier: Apache-2.0

//! Local-typed-call resolver: `x.foo()` where `x` is a local variable or
//! parameter whose declared/constructed type is known **syntactically**.
//!
//! This is an **additive**, build-free resolver — no flow analysis, no type
//! inference. It reuses two existing facts:
//!
//! - [`Reference::qualifier`](crate::graph::types::Reference::qualifier) set to
//!   the bare receiver identifier for a member call (`x.foo()`), populated by the
//!   extractors that capture a receiver (most do — some via their main call
//!   query, others via a dedicated receiver-capture pass).
//! - [`Binding::type_name`](crate::graph::types::Binding::type_name) — the
//!   local/param binding's declared or constructed type, as written text.
//!
//! For a `Call` reference with a receiver qualifier, the receiver name is
//! resolved outward through scopes (the same `scope_walk` primitive Tier-B
//! uses) to its winning [`Binding`]. If that binding is a `Local`/`Param` with
//! a known `type_name`, the type's member table (built the same way
//! [`ConformanceResolver`](super::ConformanceResolver) builds it, walking
//! supertypes on a miss) is checked for the called member name. A match emits
//! a [`Confidence::Scoped`] / [`Provenance::LocalType`] edge.
//!
//! # Fails closed
//!
//! No edge is emitted when: the receiver isn't a plain identifier, scope
//! resolution finds no binding (or a non-local/param one), the binding has no
//! `type_name`, or the type has no member of that name (directly or
//! inherited). This resolver never guesses a receiver's type — it only reads
//! the syntactic fact the extractor already recorded.
//!
//! # What it deliberately defers
//!
//! Reassignment can make the recorded `type_name` stale for a later use of the
//! same binding — this resolver does not track reassignment or flow, so a
//! `LocalType` edge is a defeasible (not type-checked) fact, unlike
//! [`Provenance::Conformance`] which reads the owning type off the *enclosing*
//! symbol rather than a mutable binding. Method chains (`a().foo()`) and
//! nested field access (`a.b.foo()`) are never captured as a qualifier in the
//! first place (the extractor only captures a bare identifier receiver), so
//! they are out of scope here too.

use std::collections::HashMap;

use crate::graph::types::{
    Binding, BindingKind, CodeGraph, Confidence, Edge, FileFacts, Provenance, RefRole, ScopeId,
    Symbol,
};
use crate::symbol::SymbolId;

use super::conformance::{find_inherited, member_of_type};
use super::incremental::scope_walk;
use super::{Resolver, dedup_files_last_wins, enclosing_symbol_index};

/// Local/param receiver-type member-call resolver. See module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalTypedCallResolver;

impl Resolver for LocalTypedCallResolver {
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

        // ── 2. type name → { member leaf → member SymbolId } ──────────────────
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
        // Mirrors ConformanceResolver's supertype map exactly, so a local's type
        // inherits members the same way a type-qualified call does.
        let mut supertypes: HashMap<String, Vec<String>> = HashMap::new();
        for f in files.iter().copied() {
            for r in &f.references {
                if r.role != RefRole::IsImplementation {
                    continue;
                }
                let impl_type = if let Some(subject) = r.qualifier.as_deref() {
                    subject.to_owned()
                } else {
                    let file_syms = by_file.get(f.file.as_str());
                    let Some(from_idx) = file_syms
                        .and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                    else {
                        continue;
                    };
                    let Some(subject) = symbols[from_idx].id.leaf_name() else {
                        continue;
                    };
                    subject.to_owned()
                };
                supertypes
                    .entry(impl_type)
                    .or_default()
                    .push(r.name.clone());
            }
        }

        // ── 4. emit edges for calls on a scope-resolved local/param receiver ──
        let mut edges: Vec<Edge> = Vec::new();
        for f in files.iter().copied() {
            let file_syms = by_file.get(f.file.as_str());

            let mut bindings_by_scope: HashMap<ScopeId, Vec<&Binding>> = HashMap::new();
            for b in &f.bindings {
                bindings_by_scope.entry(b.scope).or_default().push(b);
            }

            for r in &f.references {
                if r.role != RefRole::Call {
                    continue;
                }
                let Some(receiver) = r.qualifier.as_deref() else {
                    continue; // no captured receiver → nothing to resolve
                };
                let Some(start_scope) = r.scope else {
                    continue;
                };

                let Some(binding) = scope_walk(
                    receiver,
                    r.occ.byte,
                    start_scope,
                    &f.scopes,
                    &bindings_by_scope,
                ) else {
                    continue; // unresolved receiver name → fail closed
                };
                if !matches!(binding.kind, BindingKind::Local | BindingKind::Param) {
                    continue; // e.g. an import or definition shadowing the name
                }
                let Some(type_name) = binding.type_name.as_deref() else {
                    continue; // unknown/unannotated type → never guess
                };

                let member = r.name.as_str();
                let target = members
                    .get(type_name)
                    .and_then(|m| m.get(member))
                    .cloned()
                    .or_else(|| find_inherited(type_name, member, &members, &supertypes));
                let Some(target) = target else {
                    continue;
                };

                let Some(from_idx) =
                    file_syms.and_then(|idxs| enclosing_symbol_index(&symbols, idxs, r.occ.byte))
                else {
                    continue;
                };

                edges.push(Edge {
                    from: symbols[from_idx].id.clone(),
                    to: target,
                    role: r.role,
                    confidence: Confidence::Scoped,
                    provenance: Provenance::LocalType,
                    occ: r.occ.clone(),
                });
            }
        }

        Ok(CodeGraph { symbols, edges })
    }
}

#[cfg(all(test, feature = "rust"))]
mod tests {
    use super::*;
    use crate::extract::{Extractor, RustExtractor};

    /// `struct Repo; impl Repo { fn save(&self) {} } fn f() { let r: Repo = Repo; r.save(); }`
    /// → exactly one edge, from the enclosing `f` to `Repo#save().`, Scoped/LocalType.
    #[test]
    fn resolves_annotated_local_method_call_end_to_end() {
        let facts = RustExtractor
            .extract(
                "struct Repo; impl Repo { fn save(&self) {} } fn f() { let r: Repo = Repo; r.save(); }",
                "src/lib.rs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("f()."));
    }

    /// `Vec<Repo>` has no `save` member — no edge, even though `Repo` does.
    #[test]
    fn wrong_member_type_yields_no_edge() {
        let facts = RustExtractor
            .extract(
                "struct Repo; impl Repo { fn save(&self) {} } fn f() { let v: Vec<Repo> = Vec::new(); v.save(); }",
                "src/lib.rs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Vec has no save() member — must not emit a LocalType edge"
        );
    }

    /// `let r = Repo; r.save();` — no type annotation and a bare-value
    /// constructor the extractor does not recognize → the binding carries
    /// `type_name = None`, so the resolver must fail closed.
    #[test]
    fn unknown_binding_type_yields_no_edge() {
        let facts = RustExtractor
            .extract(
                "struct Repo; impl Repo { fn save(&self) {} } fn f() { let r = Repo; r.save(); }",
                "src/lib.rs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "unannotated bare-value local must not emit a LocalType edge"
        );
    }

    /// Inherited member: `Repo`'s `save` comes from a trait `Store`, reached
    /// only via `find_inherited` walking `supertypes`.
    #[test]
    fn resolves_inherited_member_via_supertype_walk() {
        let store = RustExtractor
            .extract("pub trait Store { fn save(&self); }", "src/store.rs")
            .unwrap();
        let repo = RustExtractor
            .extract(
                "pub struct Repo; impl crate::store::Store for Repo { fn save(&self) {} } pub fn f() { let r: Repo = Repo; r.save(); }",
                "src/repo.rs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[store, repo]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();
        assert_eq!(edges.len(), 1, "expected one inherited LocalType edge");
        assert!(edges[0].to.to_scip_string().ends_with("Store#save()."));
        assert_eq!(edges[0].confidence, Confidence::Scoped);
    }
}

#[cfg(all(test, feature = "csharp"))]
mod csharp_tests {
    use super::*;
    use crate::extract::{CSharpExtractor, Extractor};

    /// `class Repo { public void Save(){} } class C { void Run(){ Repo repo = new Repo(); repo.Save(); } }`
    /// → exactly one edge, from the enclosing `Run` to `...Repo#Save().`, Scoped/LocalType.
    ///
    /// Uses a 4-char receiver name because the C# extractor's binding
    /// collector applies `MIN_REF_LEN` (3) to local-variable names.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let facts = CSharpExtractor
            .extract(
                "class Repo { public void Save(){} } class C { void Run(){ Repo repo = new Repo(); repo.Save(); } }",
                "src/C.cs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#Save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("Run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let facts = CSharpExtractor
            .extract(
                "class Repo { public void Save(){} } class C { void Run(){ Repo repo = new Repo(); repo.Missing(); } }",
                "src/C.cs",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no Missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "typescript"))]
mod ts_tests {
    use super::*;
    use crate::extract::{Extractor, TypeScriptExtractor};

    /// `class Repo { save() {} }` + `class C { run() { const r: Repo = new Repo(); r.save(); } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let facts = TypeScriptExtractor
            .extract(
                "class Repo { save() {} } class C { run() { const r: Repo = new Repo(); r.save(); } }",
                "src/c.ts",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// JavaScript is dynamically typed (no type annotations), so local-typed
    /// resolution there depends entirely on `new Foo()` constructor inference.
    /// `class Repo { save() {} }` + `class C { run() { const r = new Repo(); r.save(); } }`
    /// via the JS extractor → the same one-edge result as the TS test above.
    #[test]
    fn js_constructor_inference_resolves_typed_local_method_call() {
        use crate::extract::JavaScriptExtractor;

        let facts = JavaScriptExtractor
            .extract(
                "class Repo { save() {} } class C { run() { const r = new Repo(); r.save(); } }",
                "src/c.js",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let facts = TypeScriptExtractor
            .extract(
                "class Repo { save() {} } class C { run() { const r: Repo = new Repo(); r.missing(); } }",
                "src/c.ts",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "kotlin"))]
mod kotlin_tests {
    use super::*;
    use crate::extract::{Extractor, KotlinExtractor};

    /// `class Repo { fun save() {} }` + `class C { fun run() { val repo: Repo = Repo(); repo.save() } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let src = r#"
class Repo {
    fun save() {}
}
class C {
    fun run() {
        val repo: Repo = Repo()
        repo.save()
    }
}
"#;
        let facts = KotlinExtractor.extract(src, "src/C.kt").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = r#"
class Repo {
    fun save() {}
}
class C {
    fun run() {
        val repo: Repo = Repo()
        repo.missing()
    }
}
"#;
        let facts = KotlinExtractor.extract(src, "src/C.kt").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "dart"))]
mod dart_tests {
    use super::*;
    use crate::extract::{DartExtractor, Extractor};

    /// `class Repo { void save() {} }` + `class C { void run() { Repo repo = Repo(); repo.save(); } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    ///
    /// Dart has no `new`-keyword marker for constructor calls, so this relies
    /// on the explicit local type annotation (`Repo repo = …`), not
    /// constructor-call inference (which the Dart extractor deliberately
    /// does not attempt — see `dart.rs`'s binding collection).
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let src = "class Repo { void save() {} } class C { void run() { Repo repo = Repo(); repo.save(); } }";
        let facts = DartExtractor.extract(src, "lib/c.dart").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = "class Repo { void save() {} } class C { void run() { Repo repo = Repo(); repo.missing(); } }";
        let facts = DartExtractor.extract(src, "lib/c.dart").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "java"))]
mod java_tests {
    use super::*;
    use crate::extract::{Extractor, JavaExtractor};

    /// `class Repo { public void save(){} } class C { void run(){ Repo repo = new Repo(); repo.save(); } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let facts = JavaExtractor
            .extract(
                "class Repo { public void save(){} } class C { void run(){ Repo repo = new Repo(); repo.save(); } }",
                "src/C.java",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let facts = JavaExtractor
            .extract(
                "class Repo { public void save(){} } class C { void run(){ Repo repo = new Repo(); repo.missing(); } }",
                "src/C.java",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "swift"))]
mod swift_tests {
    use super::*;
    use crate::extract::{Extractor, SwiftExtractor};

    /// `class Repo { func save() {} }` + `class C { func run() { let repo: Repo = Repo(); repo.save() } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    ///
    /// Swift constructor calls (`Repo()`) are indistinguishable from function
    /// calls syntactically, so this relies on the explicit `let repo: Repo`
    /// type annotation, not constructor inference.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let src = "class Repo {\n    func save() {}\n}\nclass C {\n    func run() {\n        let repo: Repo = Repo()\n        repo.save()\n    }\n}\n";
        let facts = SwiftExtractor.extract(src, "Sources/C.swift").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = "class Repo {\n    func save() {}\n}\nclass C {\n    func run() {\n        let repo: Repo = Repo()\n        repo.missing()\n    }\n}\n";
        let facts = SwiftExtractor.extract(src, "Sources/C.swift").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "cpp"))]
mod cpp_tests {
    use super::*;
    use crate::extract::{CppExtractor, Extractor};

    /// `struct Repo { void save(){} }; void run(){ Repo repo; repo.save(); }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    ///
    /// Uses the `.` receiver form; the arrow form (`repo->save()`) is covered by
    /// the extractor's `receiver_qualifier_arrow_call_sets_qualifier` unit test.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let facts = CppExtractor
            .extract(
                "struct Repo { void save(){} };\nvoid run(){ Repo repo; repo.save(); }\n",
                "src/c.cpp",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let facts = CppExtractor
            .extract(
                "struct Repo { void save(){} };\nvoid run(){ Repo repo; repo.missing(); }\n",
                "src/c.cpp",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "go"))]
mod go_tests {
    use super::*;
    use crate::extract::{Extractor, GoExtractor};

    /// `type Repo struct{}; func (r *Repo) Save(){}` + `func run(){ var repo Repo; repo.Save() }`
    /// → exactly one edge, from `run` to `...Repo#Save().`, Scoped/LocalType. Passes only now
    /// that Go methods nest under their receiver type (`Repo#Save`).
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        let facts = GoExtractor
            .extract(
                "package p\n\ntype Repo struct{}\n\nfunc (r *Repo) Save() {}\n\nfunc run() {\n\tvar repo Repo\n\trepo.Save()\n}\n",
                "src/p.go",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#Save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let facts = GoExtractor
            .extract(
                "package p\n\ntype Repo struct{}\n\nfunc (r *Repo) Save() {}\n\nfunc run() {\n\tvar repo Repo\n\trepo.Missing()\n}\n",
                "src/p.go",
            )
            .unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no Missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "scala"))]
mod scala_tests {
    use super::*;
    use crate::extract::{Extractor, ScalaExtractor};

    /// `class Repo { def save(): Unit = {} }` + `class C { def run(): Unit = { val repo: Repo = new Repo(); repo.save() } }`
    /// → exactly one edge, from the enclosing `run` to `...Repo#save().`, Scoped/LocalType.
    #[test]
    fn resolves_typed_local_method_call_end_to_end() {
        // Multi-line: tree-sitter-scala mis-parses two class defs on one line.
        let src = "class Repo {\n  def save(): Unit = {}\n}\nclass C {\n  def run(): Unit = {\n    val repo: Repo = new Repo()\n    repo.save()\n  }\n}\n";
        let facts = ScalaExtractor.extract(src, "src/C.scala").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = "class Repo { def save(): Unit = {} } class C { def run(): Unit = { val repo: Repo = new Repo(); repo.missing() } }";
        let facts = ScalaExtractor.extract(src, "src/C.scala").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "python"))]
mod python_tests {
    use super::*;
    use crate::extract::{Extractor, PythonExtractor};

    /// A method + a top-level function taking a type-hinted param of that class
    /// calling the method → exactly one edge to `Repo#save().`, Scoped/LocalType.
    ///
    /// Python is dynamic, so this relies on the param type hint (`r: Repo`), not
    /// constructor inference.
    #[test]
    fn resolves_annotated_param_method_call_end_to_end() {
        let src =
            "class Repo:\n    def save(self):\n        pass\n\ndef run(r: Repo):\n    r.save()\n";
        let facts = PythonExtractor.extract(src, "src/c.py").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = "class Repo:\n    def save(self):\n        pass\n\ndef run(r: Repo):\n    r.missing()\n";
        let facts = PythonExtractor.extract(src, "src/c.py").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}

#[cfg(all(test, feature = "php"))]
mod php_tests {
    use super::*;
    use crate::extract::{Extractor, PhpExtractor};

    /// A method + a function taking a typed param of that class calling the
    /// method → exactly one edge to `Repo#save().`, Scoped/LocalType.
    ///
    /// Relies on the PHP parameter type (`Repo $r`); the receiver qualifier is
    /// normalized to the bare variable name (`r`, no `$`) so it matches the
    /// param binding's name.
    #[test]
    fn resolves_typed_param_method_call_end_to_end() {
        let src = "<?php class Repo { function save(){} } function run(Repo $r){ $r->save(); }";
        let facts = PhpExtractor.extract(src, "src/c.php").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        let edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| e.provenance == Provenance::LocalType)
            .collect();

        assert_eq!(
            edges.len(),
            1,
            "expected exactly one LocalType edge, got {:?}",
            edges
                .iter()
                .map(|e| format!("{} -> {}", e.from.to_scip_string(), e.to.to_scip_string()))
                .collect::<Vec<_>>()
        );
        let e = edges[0];
        assert!(e.to.to_scip_string().ends_with("Repo#save()."));
        assert_eq!(e.confidence, Confidence::Scoped);
        assert_eq!(e.provenance, Provenance::LocalType);
        assert!(e.from.to_scip_string().ends_with("run()."));
    }

    /// The receiver's type has no such member — no edge.
    #[test]
    fn wrong_member_yields_no_edge() {
        let src = "<?php class Repo { function save(){} } function run(Repo $r){ $r->missing(); }";
        let facts = PhpExtractor.extract(src, "src/c.php").unwrap();

        let graph = LocalTypedCallResolver.resolve(&[facts]).unwrap();
        assert!(
            graph
                .edges
                .iter()
                .all(|e| e.provenance != Provenance::LocalType),
            "Repo has no missing() member — must not emit a LocalType edge"
        );
    }
}
