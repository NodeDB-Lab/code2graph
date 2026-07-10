// SPDX-License-Identifier: Apache-2.0

use code2graph::extract::Extractor;
use code2graph::{
    FileFacts,
    extract::RustExtractor,
    resolve::{
        ConformanceResolver, ExternalResolver, FfiBridgeResolver, LayeredResolver,
        NormalizedNameResolver, Resolver, ScopeGraphResolver, SymbolTableResolver,
    },
};

fn competing_versions() -> Vec<FileFacts> {
    let first = RustExtractor
        .extract("pub fn retired() {}", "src/service.rs")
        .expect("extract first version");
    let caller = RustExtractor
        .extract("pub fn run() {}", "src/caller.rs")
        .expect("extract caller");
    let last = RustExtractor
        .extract("pub fn current() {}", "src/service.rs")
        .expect("extract final version");
    vec![first, caller, last]
}

fn assert_last_input_wins(resolver: impl Resolver) {
    let graph = resolver.resolve(&competing_versions()).unwrap();
    let names: Vec<_> = graph
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect();

    assert!(
        names.contains(&"current"),
        "the final FileFacts version must contribute its definitions: {names:?}"
    );
    assert!(
        !names.contains(&"retired"),
        "a replaced FileFacts version must not remain in the resolved graph: {names:?}"
    );
}

macro_rules! resolver_uses_last_input_version {
    ($test_name:ident, $resolver:expr) => {
        #[test]
        fn $test_name() {
            assert_last_input_wins($resolver);
        }
    };
}

resolver_uses_last_input_version!(symbol_table_uses_last_input_version, SymbolTableResolver);
resolver_uses_last_input_version!(scope_graph_uses_last_input_version, ScopeGraphResolver);
resolver_uses_last_input_version!(
    normalized_name_uses_last_input_version,
    NormalizedNameResolver
);
resolver_uses_last_input_version!(conformance_uses_last_input_version, ConformanceResolver);
resolver_uses_last_input_version!(external_uses_last_input_version, ExternalResolver);
resolver_uses_last_input_version!(ffi_bridge_uses_last_input_version, FfiBridgeResolver);
resolver_uses_last_input_version!(
    layered_uses_last_input_version,
    LayeredResolver::default_dense()
);
