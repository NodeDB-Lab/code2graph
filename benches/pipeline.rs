// SPDX-License-Identifier: Apache-2.0

//! Performance benchmarks for the code→graph pipeline.
//!
//! Three hot paths that matter for a "reusable primitive many tools build on":
//! - **extract**: the per-file tree-sitter walk (`extract_path`) — throughput.
//! - **resolve**: linking references to definitions across a multi-file graph,
//!   measured per resolution tier (Tier-A name, Tier-B scope, Layered dense).
//! - **end_to_end**: extract a small project then resolve it.
//!
//! Bench bodies are feature-gated on the languages they exercise. Run with e.g.
//! `cargo bench --features rust,typescript,python`.

use fluxbench::prelude::*;
// Import the attribute macro explicitly so `#[bench]` is unambiguous (the std
// prelude also defines an unstable `bench` attribute).
use fluxbench::bench;
use std::hint::black_box;

// ── Fixtures ─────────────────────────────────────────────────────────────────
// Real repo source for Rust (representative size + structure); compact but
// realistic snippets for the other languages (this is a Rust-only repo, so
// there are no in-tree TS/Python files to `include_str!`).

#[cfg(feature = "rust")]
const RUST_FILES: &[(&str, &str)] = &[
    ("src/graph/types.rs", include_str!("../src/graph/types.rs")),
    (
        "src/extract/support.rs",
        include_str!("../src/extract/support.rs"),
    ),
    (
        "src/resolve/conformance.rs",
        include_str!("../src/resolve/conformance.rs"),
    ),
    (
        "src/resolve/local_typed_call.rs",
        include_str!("../src/resolve/local_typed_call.rs"),
    ),
];

#[cfg(feature = "typescript")]
const TS_SOURCE: &str = r#"
export class Repository<T> {
    private items: Map<string, T> = new Map();
    add(key: string, value: T): void { this.items.set(key, value); }
    get(key: string): T | undefined { return this.items.get(key); }
    all(): T[] { return Array.from(this.items.values()); }
}
export class UserService extends Repository<User> {
    constructor(private log: Logger) { super(); }
    activate(id: string): void {
        const u = this.get(id);
        if (u) { u.active = true; this.log.info("activated"); }
    }
}
interface User { id: string; active: boolean; }
interface Logger { info(msg: string): void; }
"#;

#[cfg(feature = "python")]
const PY_SOURCE: &str = r#"
class Repository:
    def __init__(self):
        self._items = {}
    def add(self, key, value):
        self._items[key] = value
    def get(self, key):
        return self._items.get(key)

class UserService(Repository):
    def __init__(self, log):
        super().__init__()
        self.log = log
    def activate(self, user_id: str):
        u = self.get(user_id)
        if u is not None:
            u.active = True
            self.log.info("activated")
"#;

// ── Extraction throughput ────────────────────────────────────────────────────

#[cfg(feature = "rust")]
#[bench(group = "extract", severity = "warning")]
fn extract_rust(b: &mut Bencher) {
    let (path, src) = RUST_FILES[0];
    b.iter(|| code2graph::extract_path(black_box(path), black_box(src)).unwrap());
}

#[cfg(feature = "typescript")]
#[bench(group = "extract")]
fn extract_typescript(b: &mut Bencher) {
    b.iter(|| code2graph::extract_path(black_box("src/service.ts"), black_box(TS_SOURCE)).unwrap());
}

#[cfg(feature = "python")]
#[bench(group = "extract")]
fn extract_python(b: &mut Bencher) {
    b.iter(|| code2graph::extract_path(black_box("src/service.py"), black_box(PY_SOURCE)).unwrap());
}

// ── Resolution cost, per tier (Rust multi-file graph) ────────────────────────

#[cfg(feature = "rust")]
fn rust_graph() -> Vec<code2graph::FileFacts> {
    RUST_FILES
        .iter()
        .map(|(path, src)| code2graph::extract_path(path, src).unwrap())
        .collect()
}

#[cfg(feature = "rust")]
#[bench(group = "resolve", severity = "warning")]
fn resolve_tier_a_name(b: &mut Bencher) {
    use code2graph::{Resolver, SymbolTableResolver};
    let files = rust_graph();
    b.iter(|| SymbolTableResolver.resolve(black_box(&files)).unwrap());
}

#[cfg(feature = "rust")]
#[bench(group = "resolve")]
fn resolve_tier_b_scope(b: &mut Bencher) {
    use code2graph::{Resolver, ScopeGraphResolver};
    let files = rust_graph();
    b.iter(|| ScopeGraphResolver.resolve(black_box(&files)).unwrap());
}

#[cfg(feature = "rust")]
#[bench(group = "resolve")]
fn resolve_layered_dense(b: &mut Bencher) {
    use code2graph::{LayeredResolver, Resolver};
    let files = rust_graph();
    let resolver = LayeredResolver::default_dense();
    b.iter(|| resolver.resolve(black_box(&files)).unwrap());
}

// ── End-to-end: extract a project then resolve it ────────────────────────────

#[cfg(feature = "rust")]
#[bench(group = "end_to_end", severity = "warning")]
fn extract_and_resolve_rust(b: &mut Bencher) {
    use code2graph::{LayeredResolver, Resolver};
    let resolver = LayeredResolver::default_dense();
    b.iter(|| {
        let files: Vec<_> = RUST_FILES
            .iter()
            .map(|(path, src)| code2graph::extract_path(path, src).unwrap())
            .collect();
        resolver.resolve(black_box(&files)).unwrap()
    });
}

fn main() {
    if let Err(e) = fluxbench::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
