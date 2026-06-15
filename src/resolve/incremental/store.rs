// SPDX-License-Identifier: Apache-2.0

//! Stateful incremental Tier-B resolution store.
//!
//! [`IncrementalGraph`] caches one isolated [`FileSubgraph`] per file plus a
//! [`GlobalIndex`] of all current definitions. Re-extracting a single changed
//! file rebuilds ONLY that file's subgraph (via [`build_subgraph`], which never
//! looks at any file but the one passed) and patches the index — the rest of
//! the graph is untouched. [`graph`] then [`stitch`]es the current cross-file
//! edges on demand.
//!
//! The store wraps the SAME pieces (`build_subgraph` + `stitch`) the batch
//! [`ScopeGraphResolver`] uses, so its output is identical (up to ordering) to
//! running that resolver over the same file set — the two paths never drift.
//!
//! [`ScopeGraphResolver`]: super::super::ScopeGraphResolver
//! [`graph`]: IncrementalGraph::graph

use std::collections::HashMap;

use crate::graph::types::{CodeGraph, FileFacts};

use super::stitch::{GlobalIndex, stitch};
use super::subgraph::{FileSubgraph, build_subgraph};

/// Incremental Tier-B resolution store. Holds one isolated subgraph per file
/// plus a global definition index, so re-extracting a single changed file
/// rebuilds only that file's subgraph — never the whole graph — while
/// `graph()` stitches the current cross-file edges on demand.
///
/// Output is identical (up to ordering) to running `ScopeGraphResolver` over
/// the same file set: both share `build_subgraph` + `stitch`.
pub struct IncrementalGraph {
    files: HashMap<String, FileSubgraph>,
    index: GlobalIndex,
}

impl IncrementalGraph {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            index: GlobalIndex::new(),
        }
    }

    /// Build a store from a file set by [`upsert`]ing each in turn. Ergonomic
    /// constructor equivalent to `new()` followed by an upsert per file.
    ///
    /// [`upsert`]: IncrementalGraph::upsert
    pub fn from_files(files: &[FileFacts]) -> Self {
        let mut store = Self::new();
        for f in files {
            store.upsert(f);
        }
        store
    }

    /// Insert or replace the subgraph for `facts.file`.
    ///
    /// Re-extracting a file rebuilds ONLY that file's subgraph — structurally
    /// guaranteed, because [`build_subgraph`] reads no file but the one passed.
    /// If a subgraph already existed for this key, its definitions are removed
    /// from the global index first, so the index reflects only the current set.
    pub fn upsert(&mut self, facts: &FileFacts) {
        let key = facts.file.clone();
        if let Some(old) = self.files.get(&key) {
            self.index.remove_symbols(&old.symbols);
        }
        let sub = build_subgraph(facts);
        self.index.insert_symbols(&sub.symbols);
        self.files.insert(key, sub);
    }

    /// Drop the file `file` from the store, removing its definitions from the
    /// global index. A no-op if the file is not present.
    pub fn remove(&mut self, file: &str) {
        if let Some(old) = self.files.remove(file) {
            self.index.remove_symbols(&old.symbols);
        }
    }

    /// Stitch the current cross-file edges and return the full [`CodeGraph`].
    ///
    /// Deterministic: file keys are processed in sorted order, so symbols,
    /// intra-file edges, and pending refs always accumulate in the same order
    /// regardless of upsert history. Cross-file edges are stitched last against
    /// the current global index.
    pub fn graph(&self) -> CodeGraph {
        // Process files in sorted-key order for deterministic output. Iterate the
        // entries directly (no key-then-lookup) so there is no fallible indexing.
        let mut entries: Vec<(&String, &FileSubgraph)> = self.files.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        let mut symbols = Vec::new();
        let mut edges = Vec::new();
        let mut pending = Vec::new();

        for (_, sub) in entries {
            symbols.extend(sub.symbols.iter().cloned());
            edges.extend(sub.intra_edges.iter().cloned());
            pending.extend(sub.pending.iter().cloned());
        }
        edges.extend(stitch(&pending, &self.index));

        CodeGraph { symbols, edges }
    }

    /// Number of files currently held.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the store holds no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

impl Default for IncrementalGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{Extractor, PythonExtractor, RustExtractor};
    use crate::graph::types::{CodeGraph, Edge};
    use crate::resolve::{Resolver, ScopeGraphResolver};

    /// Stable per-edge key: source/target SCIP ids, role, confidence, and the
    /// occurrence byte. Captures everything that distinguishes one edge fact.
    fn edge_key(e: &Edge) -> (String, String, String, String, usize) {
        (
            e.from.to_scip_string(),
            e.to.to_scip_string(),
            format!("{:?}", e.role),
            format!("{:?}", e.confidence),
            e.occ.byte,
        )
    }

    /// Assert two graphs are equal as MULTISETS (order-independent): batch
    /// concatenates in input order, the store in sorted-key order, so positional
    /// comparison would be wrong. Symbols compare by SCIP id, edges by `edge_key`.
    fn assert_multiset_eq(a: &CodeGraph, b: &CodeGraph) {
        let mut a_syms: Vec<String> = a.symbols.iter().map(|s| s.id.to_scip_string()).collect();
        let mut b_syms: Vec<String> = b.symbols.iter().map(|s| s.id.to_scip_string()).collect();
        a_syms.sort();
        b_syms.sort();
        assert_eq!(a_syms, b_syms, "symbol multisets differ");

        let mut a_edges: Vec<_> = a.edges.iter().map(edge_key).collect();
        let mut b_edges: Vec<_> = b.edges.iter().map(edge_key).collect();
        a_edges.sort();
        b_edges.sort();
        assert_eq!(a_edges, b_edges, "edge multisets differ");
    }

    /// A small, realistic Rust file set exercising cross-file import, a same-file
    /// definition call, and a local binding.
    fn rust_set() -> Vec<FileFacts> {
        let conf = RustExtractor
            .extract("pub struct Config {}", "src/conf.rs")
            .unwrap();
        let app = RustExtractor
            .extract("use conf::Config;\npub fn run() {}", "src/app.rs")
            .unwrap();
        let util = RustExtractor
            .extract(
                "pub fn helper() {} pub fn run2() { let h = make(); h() }",
                "src/util.rs",
            )
            .unwrap();
        vec![conf, app, util]
    }

    #[test]
    fn incremental_matches_batch_same_set() {
        let files = rust_set();
        let store = IncrementalGraph::from_files(&files);
        let batch = ScopeGraphResolver.resolve(&files);
        assert_multiset_eq(&store.graph(), &batch);
    }

    #[test]
    fn reupsert_changed_file_matches_batch_of_new_set() {
        // Two distinct definitions of `process`; B's import path selects which one
        // its call/import resolves to. Re-upserting B with a different import path
        // must re-route resolution exactly as a fresh batch over the new set would.
        let a = PythonExtractor
            .extract("def process():\n    pass\n", "alpha.py")
            .unwrap();
        let b = PythonExtractor
            .extract(
                "from alpha import process\n\ndef run():\n    process()\n",
                "main.py",
            )
            .unwrap();
        let c = PythonExtractor
            .extract("def process():\n    pass\n", "beta.py")
            .unwrap();

        let mut store = IncrementalGraph::from_files(&[a.clone(), b, c.clone()]);

        // B now imports from beta instead of alpha.
        let b_new = PythonExtractor
            .extract(
                "from beta import process\n\ndef run():\n    process()\n",
                "main.py",
            )
            .unwrap();
        store.upsert(&b_new);

        let batch = ScopeGraphResolver.resolve(&[a, b_new, c]);
        assert_multiset_eq(&store.graph(), &batch);
    }

    #[test]
    fn remove_drops_only_that_file() {
        let files = rust_set();
        let mut store = IncrementalGraph::from_files(&files);
        store.remove("src/app.rs");

        let conf = files[0].clone();
        let util = files[2].clone();
        let batch = ScopeGraphResolver.resolve(&[conf, util]);
        assert_multiset_eq(&store.graph(), &batch);

        // Nothing from src/app.rs survives in symbols or edges.
        let g = store.graph();
        assert!(
            g.symbols.iter().all(|s| s.file != "src/app.rs"),
            "removed file's symbols must be gone"
        );
        assert!(
            g.edges.iter().all(|e| e.occ.file != "src/app.rs"),
            "removed file's edges must be gone"
        );
    }

    #[test]
    fn upsert_is_idempotent() {
        let files = rust_set();
        let mut once = IncrementalGraph::new();
        for f in &files {
            once.upsert(f);
        }
        let once_graph = once.graph();

        let mut twice = IncrementalGraph::new();
        for f in &files {
            twice.upsert(f);
        }
        // Upsert every file a second time — must not duplicate anything.
        for f in &files {
            twice.upsert(f);
        }
        assert_multiset_eq(&twice.graph(), &once_graph);
    }
}
