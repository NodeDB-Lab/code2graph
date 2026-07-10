// SPDX-License-Identifier: Apache-2.0

//! Stateful incremental Tier-B resolution store.
//!
//! [`IncrementalGraph`] caches one isolated per-file subgraph plus a global
//! index of all current definitions. Re-extracting a single changed file
//! rebuilds ONLY that file's subgraph (the per-file build never looks at any
//! file but the one passed) and patches the index — the rest of the graph is
//! untouched. [`graph`] then stitches the current cross-file edges on demand.
//!
//! The store wraps the SAME per-file build and stitch passes the batch
//! [`ScopeGraphResolver`] uses, so its output is identical (up to ordering) to
//! running that resolver over the same file set — the two paths never drift.
//!
//! [`ScopeGraphResolver`]: super::super::ScopeGraphResolver
//! [`graph`]: IncrementalGraph::graph

use std::collections::HashMap;

use crate::error::{CodegraphError, Result};
use crate::graph::types::{CodeGraph, FileFacts};

use super::stitch::{GlobalIndex, stitch};
use super::subgraph::{FileSubgraph, build_subgraph};

/// Incremental Tier-B resolution store. Holds one isolated subgraph per file
/// plus a global definition index, so re-extracting a single changed file
/// rebuilds only that file's subgraph — never the whole graph — while
/// [`graph`](IncrementalGraph::graph) stitches the current cross-file edges on
/// demand.
///
/// Output is identical (up to ordering) to running [`ScopeGraphResolver`] over
/// the same file set: both share the same per-file build and stitch passes.
///
/// ```
/// use code2graph::{extract_path, resolve::IncrementalGraph};
///
/// // `app` imports `Config` from `conf`.
/// let conf = extract_path("src/conf.rs", "pub struct Config {}").unwrap();
/// let app = extract_path("src/app.rs", "use conf::Config;\npub fn run() {}").unwrap();
///
/// // Keep a resolved graph current as files change: each file is resolved in
/// // isolation and cross-file edges are stitched on demand.
/// let mut graph = IncrementalGraph::from_files(&[conf, app]);
/// let resolves_import = |g: code2graph::graph::CodeGraph| {
///     g.edges.iter().any(|e| e.to.to_scip_string().ends_with("conf/Config#"))
/// };
/// assert!(resolves_import(graph.graph()));
///
/// // Re-extract only the changed file; `conf` is never reprocessed.
/// let app = extract_path("src/app.rs", "use conf::Config;\npub fn helper() {}").unwrap();
/// graph.upsert(&app);
/// assert!(resolves_import(graph.graph()));
/// ```
///
/// [`ScopeGraphResolver`]: super::super::ScopeGraphResolver
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
    /// guaranteed, because the per-file build reads no file but the one passed.
    /// If a subgraph already existed for this key, its definitions are removed
    /// from the global index first, so the index reflects only the current set.
    pub fn upsert(&mut self, facts: &FileFacts) {
        self.upsert_subgraph(facts.file.clone(), build_subgraph(facts));
    }

    /// Return the stored [`FileSubgraph`] for a file key, or `None` if the file
    /// is not present in the store.
    ///
    /// This is the **persistence read path**: a consumer serializes the returned
    /// subgraph (e.g. with `serde_json::to_string`) and writes it to a cache
    /// store keyed by file path. On the next startup, the consumer deserializes
    /// each cached blob and restores it via [`upsert_subgraph`] — bypassing
    /// `build_subgraph` entirely for files that have not changed.
    ///
    /// [`upsert_subgraph`]: IncrementalGraph::upsert_subgraph
    pub fn subgraph(&self, file: &str) -> Option<&FileSubgraph> {
        self.files.get(file)
    }

    /// Insert or replace a PRE-BUILT (e.g. deserialized) [`FileSubgraph`] for
    /// `file`, updating the global definition index to reflect the new contents.
    ///
    /// This is the **persistence write path** (the restore leg): after deserializing
    /// a cached subgraph on startup, call this method to re-populate the store
    /// without re-running `build_subgraph`. The global index is rebuilt from the
    /// restored symbols, so **the index is never itself persisted** — the
    /// subgraphs are the single source of truth, and the index is always derived
    /// from them.
    ///
    /// If a subgraph already exists for `file` (e.g. a hot-reload of a changed
    /// file), its symbols are removed from the index first, exactly as `upsert`
    /// does, so the index never accumulates stale entries.
    ///
    /// All of `upsert`'s index-bookkeeping lives here; `upsert` itself delegates
    /// to this method (after calling `build_subgraph`) so the two paths can never
    /// drift.
    pub fn upsert_subgraph(&mut self, file: String, sub: FileSubgraph) {
        // Compatibility wrapper; callers needing malformed-cache diagnostics use
        // `try_upsert_subgraph`.
        let _ = self.try_upsert_subgraph(file, sub);
    }

    /// Atomically restore a persisted subgraph after validating its schema and
    /// ownership. On error neither the file store nor global index changes.
    pub fn try_upsert_subgraph(&mut self, file: String, sub: FileSubgraph) -> Result<()> {
        let invalid = |reason: String| CodegraphError::MalformedFacts {
            file: file.clone(),
            reason,
        };
        if sub.schema_version != 1 {
            return Err(invalid(format!(
                "unsupported subgraph schema {}",
                sub.schema_version
            )));
        }
        if sub.owner_file != file {
            return Err(invalid("subgraph owner does not match restore key".into()));
        }
        if sub.symbols.iter().any(|symbol| symbol.file != file)
            || sub.intra_edges.iter().any(|edge| edge.occ.file != file)
            || sub.pending.iter().any(|pending| pending.occ.file != file)
        {
            return Err(invalid(
                "subgraph contains facts owned by another file".into(),
            ));
        }
        if let Some(old) = self.files.get(&file) {
            self.index.remove_symbols(&old.symbols);
        }
        self.index.insert_symbols(&sub.symbols);
        self.files.insert(file, sub);
        Ok(())
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
    use crate::resolve::{Resolver, ScopeGraphResolver, SymbolTableResolver};

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
        let batch = ScopeGraphResolver.resolve(&files).unwrap();
        assert_multiset_eq(&store.graph(), &batch);
    }

    /// Duplicate `file` keys are a single source with competing versions. The
    /// store keys by path (last upsert wins); the batch resolvers must agree —
    /// deduping to the LAST version — so the two paths never diverge, and no two
    /// symbols ever share a SymbolId.
    #[test]
    fn duplicate_file_key_last_wins_matches_batch() {
        // v1 and v2 share the path `src/app.rs` but define different functions.
        let v1 = RustExtractor
            .extract("pub fn first() {}", "src/app.rs")
            .unwrap();
        let v2 = RustExtractor
            .extract("pub fn second() {}", "src/app.rs")
            .unwrap();

        // The store keys by path, so upserting v1 then v2 keeps only v2.
        let store = IncrementalGraph::from_files(&[v1.clone(), v2.clone()]);
        let batch = ScopeGraphResolver
            .resolve(&[v1.clone(), v2.clone()])
            .unwrap();
        assert_multiset_eq(&store.graph(), &batch);

        // The surviving graph reflects v2 (`second`), not v1 (`first`).
        let g = store.graph();
        assert!(
            g.symbols
                .iter()
                .any(|s| s.id.to_scip_string().ends_with("second().")),
            "last-wins must keep v2 (`second`), got: {:?}",
            g.symbols
                .iter()
                .map(|s| s.id.to_scip_string())
                .collect::<Vec<_>>()
        );
        assert!(
            !g.symbols
                .iter()
                .any(|s| s.id.to_scip_string().ends_with("first().")),
            "v1 (`first`) must not survive last-wins dedup"
        );

        // Tier-A over the duplicate set must not emit two symbols with the SAME
        // SymbolId (a duplicate identity, since the id derives from file + descriptors).
        let tier_a = SymbolTableResolver.resolve(&[v1, v2]).unwrap();
        let mut ids: Vec<String> = tier_a
            .symbols
            .iter()
            .map(|s| s.id.to_scip_string())
            .collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            total,
            "duplicate file keys must not yield duplicate SymbolIds"
        );
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

        let batch = ScopeGraphResolver.resolve(&[a, b_new, c]).unwrap();
        assert_multiset_eq(&store.graph(), &batch);
    }

    #[test]
    fn remove_drops_only_that_file() {
        let files = rust_set();
        let mut store = IncrementalGraph::from_files(&files);
        store.remove("src/app.rs");

        let conf = files[0].clone();
        let util = files[2].clone();
        let batch = ScopeGraphResolver.resolve(&[conf, util]).unwrap();
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

    /// Prove the full persistence seam end-to-end: serialize each file's
    /// [`FileSubgraph`] to JSON, deserialize it back, restore it into a fresh
    /// store via [`IncrementalGraph::upsert_subgraph`], and confirm that the
    /// reloaded store produces a graph identical (as a multiset) to the original.
    ///
    /// This test is the contract that makes persistence safe: if it passes, a
    /// consumer can cache subgraphs to disk and reload them without loss or drift.
    #[cfg(feature = "serde")]
    #[test]
    fn reload_from_serialized_subgraphs_matches_original() {
        use crate::resolve::FileSubgraph;

        let files = rust_set();
        let store = IncrementalGraph::from_files(&files);

        // For each file key, serialize the subgraph to JSON and deserialize it
        // back, then restore it into a fresh store via upsert_subgraph.
        let file_keys = ["src/conf.rs", "src/app.rs", "src/util.rs"];
        let mut restored = IncrementalGraph::new();
        for key in file_keys {
            let sub = store
                .subgraph(key)
                .unwrap_or_else(|| panic!("subgraph missing for {key}"));
            let json =
                serde_json::to_string(sub).unwrap_or_else(|e| panic!("serialize {key}: {e}"));
            let deserialized: FileSubgraph =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize {key}: {e}"));
            restored.upsert_subgraph(key.to_string(), deserialized);
        }

        // The reloaded store must yield an identical graph (order-independent).
        assert_multiset_eq(&restored.graph(), &store.graph());
    }

    #[test]
    fn restoring_a_subgraph_under_a_different_key_leaves_existing_state_unchanged() {
        let original = RustExtractor
            .extract("pub fn original() {}", "src/original.rs")
            .unwrap();
        let replacement = RustExtractor
            .extract("pub fn replacement() {}", "src/replacement.rs")
            .unwrap();

        let mut store = IncrementalGraph::from_files(&[original]);
        let before = store.graph();
        store.upsert_subgraph("src/other.rs".to_string(), build_subgraph(&replacement));

        assert_multiset_eq(&store.graph(), &before);
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
