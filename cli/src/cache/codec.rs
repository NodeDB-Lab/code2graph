// SPDX-License-Identifier: Apache-2.0

//! Versioned bounded JSON codecs for cache blobs.

use std::io::{self, Write};

use code2graph::{
    CODE_GRAPH_SCHEMA_VERSION, CodeGraph, FILE_FACTS_SCHEMA_VERSION, FILE_SUBGRAPH_SCHEMA_VERSION,
    FileFacts, FileFactsValidationContext, FileSubgraph, IncrementalGraph, validate_file_facts,
    validate_file_facts_with_context,
};
use serde::{Deserialize, Serialize};

/// Maximum accepted encoded cache blob size.
pub const CACHE_BLOB_MAX_BYTES: usize = 16 * 1024 * 1024;
const CACHE_COLLECTION_MAX: usize = 1_000_000;
const CACHE_STRING_MAX: usize = 1_048_576;
const CACHE_OWNER_MAX_BYTES: usize = 4096;

/// Typed cache failures; callers may map these to their public CLI error.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache blob exceeds the size limit")]
    Oversize,
    #[error("cache blob is malformed")]
    Malformed,
    #[error("cache blob has an unsupported format or schema")]
    Incompatible,
    #[error("cache blob violates structural limits")]
    Limits,
    #[error("cache facts failed validation")]
    InvalidFacts,
    #[error("cache subgraph could not be restored")]
    InvalidSubgraph,
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    format: String,
    schema: u32,
    payload: T,
}

pub fn encode_file_facts(facts: &FileFacts) -> Result<Vec<u8>, CacheError> {
    encode("file-facts", FILE_FACTS_SCHEMA_VERSION, facts)
}
pub fn decode_file_facts(
    blob: &[u8],
    context: Option<FileFactsValidationContext<'_>>,
) -> Result<FileFacts, CacheError> {
    let facts = decode("file-facts", FILE_FACTS_SCHEMA_VERSION, blob)?;
    match context {
        Some(context) => validate_file_facts_with_context(&facts, context),
        None => validate_file_facts(std::slice::from_ref(&facts)),
    }
    .map_err(|_| CacheError::InvalidFacts)?;
    Ok(facts)
}
pub fn encode_subgraph(subgraph: &FileSubgraph) -> Result<Vec<u8>, CacheError> {
    encode("file-subgraph", FILE_SUBGRAPH_SCHEMA_VERSION, subgraph)
}
/// Decode only through the incremental store's checked restore boundary.
pub fn restore_subgraph(
    blob: &[u8],
    owner: String,
    graph: &mut IncrementalGraph,
) -> Result<(), CacheError> {
    if owner.len() > CACHE_OWNER_MAX_BYTES {
        return Err(CacheError::Limits);
    }
    let subgraph = decode("file-subgraph", FILE_SUBGRAPH_SCHEMA_VERSION, blob)?;
    graph
        .try_upsert_subgraph(owner, subgraph)
        .map_err(|_| CacheError::InvalidSubgraph)
}
pub fn encode_graph(graph: &CodeGraph) -> Result<Vec<u8>, CacheError> {
    encode("code-graph", CODE_GRAPH_SCHEMA_VERSION, graph)
}
pub fn decode_graph(blob: &[u8]) -> Result<CodeGraph, CacheError> {
    let graph: CodeGraph = decode("code-graph", CODE_GRAPH_SCHEMA_VERSION, blob)?;
    if graph.symbols.len() > CACHE_COLLECTION_MAX || graph.edges.len() > CACHE_COLLECTION_MAX {
        return Err(CacheError::Limits);
    }
    Ok(graph)
}

fn encode<T: Serialize>(format: &str, schema: u32, payload: &T) -> Result<Vec<u8>, CacheError> {
    let mut writer = BoundedWriter::new(CACHE_BLOB_MAX_BYTES);
    let result = serde_json::to_writer(
        &mut writer,
        &Envelope {
            format: format.to_owned(),
            schema,
            payload,
        },
    );
    match result {
        Ok(()) => Ok(writer.bytes),
        Err(_) if writer.overflowed => Err(CacheError::Oversize),
        Err(_) => Err(CacheError::Malformed),
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.bytes.extend_from_slice(&input[..remaining]);
            self.overflowed = true;
            return Err(io::Error::other("cache blob limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn decode<T: for<'de> Deserialize<'de>>(
    format: &str,
    schema: u32,
    blob: &[u8],
) -> Result<T, CacheError> {
    if blob.len() > CACHE_BLOB_MAX_BYTES {
        return Err(CacheError::Oversize);
    }
    let value: serde_json::Value =
        serde_json::from_slice(blob).map_err(|_| CacheError::Malformed)?;
    validate_json_limits(&value)?;
    let envelope: Envelope<T> = serde_json::from_value(value).map_err(|_| CacheError::Malformed)?;
    if envelope.format != format || envelope.schema != schema {
        return Err(CacheError::Incompatible);
    }
    Ok(envelope.payload)
}
fn validate_json_limits(value: &serde_json::Value) -> Result<(), CacheError> {
    match value {
        serde_json::Value::String(text) if text.len() > CACHE_STRING_MAX => Err(CacheError::Limits),
        serde_json::Value::Array(values) => {
            if values.len() > CACHE_COLLECTION_MAX {
                return Err(CacheError::Limits);
            }
            for value in values {
                validate_json_limits(value)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            if values.len() > CACHE_COLLECTION_MAX {
                return Err(CacheError::Limits);
            }
            for (key, value) in values {
                if key.len() > CACHE_STRING_MAX {
                    return Err(CacheError::Limits);
                }
                validate_json_limits(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> FileFacts {
        FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        }
    }

    #[test]
    fn facts_and_graph_round_trip_with_deterministic_bytes() {
        use code2graph::{ByteSpan, Descriptor, Symbol, SymbolId, SymbolKind, Visibility};

        let facts = facts();
        let first = encode_file_facts(&facts).expect("encode");
        let second = encode_file_facts(&facts).expect("encode");
        assert_eq!(first, second);
        assert!(!String::from_utf8_lossy(&first).contains("\"source\""));
        let restored = decode_file_facts(&first, None).expect("decode");
        assert_eq!(encode_file_facts(&restored).expect("encode"), first);

        let ids = [
            SymbolId::global("rust", vec![Descriptor::Term("run".into())]),
            SymbolId::local("src/a.rs", "scope:0:x"),
        ];
        let graph = CodeGraph {
            symbols: ids
                .iter()
                .enumerate()
                .map(|(index, id)| Symbol {
                    id: id.clone(),
                    name: format!("symbol-{index}"),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    entry_points: Vec::new(),
                    file: "src/a.rs".into(),
                    line: 7,
                    span: ByteSpan { start: 2, end: 9 },
                    signature: "fn run()".into(),
                })
                .collect(),
            edges: Vec::new(),
        };
        let encoded = encode_graph(&graph).expect("encode graph");
        let restored = decode_graph(&encoded).expect("decode graph");
        assert_eq!(
            restored
                .symbols
                .iter()
                .map(|symbol| symbol.id.clone())
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(encode_graph(&restored).expect("re-encode graph"), encoded);
    }

    #[test]
    fn rejects_oversize_malformed_and_wrong_subgraph_owner() {
        assert!(matches!(
            decode_graph(&vec![b'x'; CACHE_BLOB_MAX_BYTES + 1]),
            Err(CacheError::Oversize)
        ));
        assert!(matches!(
            decode_graph(b"not-json"),
            Err(CacheError::Malformed)
        ));
        let mut oversized = facts();
        oversized.file = "x".repeat(CACHE_BLOB_MAX_BYTES);
        assert!(matches!(
            encode_file_facts(&oversized),
            Err(CacheError::Oversize)
        ));

        let facts = facts();
        let mut source = IncrementalGraph::new();
        source.upsert(&facts);
        let blob = encode_subgraph(source.subgraph("src/a.rs").expect("subgraph")).expect("encode");
        let mut destination = IncrementalGraph::new();
        assert!(matches!(
            restore_subgraph(&blob, "src/b.rs".into(), &mut destination),
            Err(CacheError::InvalidSubgraph)
        ));
        assert!(destination.is_empty());
        assert!(matches!(
            restore_subgraph(
                &blob,
                "x".repeat(CACHE_OWNER_MAX_BYTES + 1),
                &mut destination
            ),
            Err(CacheError::Limits)
        ));
    }

    #[test]
    fn rejects_schema_string_and_collection_limit_attacks() {
        let wrong_schema =
            br#"{"format":"code-graph","schema":4294967295,"payload":{"symbols":[],"edges":[]}}"#;
        assert!(matches!(
            decode_graph(wrong_schema),
            Err(CacheError::Incompatible)
        ));

        let long_string = "x".repeat(CACHE_STRING_MAX + 1);
        let blob = serde_json::to_vec(&serde_json::json!({
            "format": "code-graph",
            "schema": CODE_GRAPH_SCHEMA_VERSION,
            "payload": { "symbols": [], "edges": [], "extra": long_string }
        }))
        .expect("JSON");
        assert!(matches!(decode_graph(&blob), Err(CacheError::Limits)));

        let mut many = String::from("{\"format\":\"code-graph\",\"schema\":1,\"payload\":{");
        many.push_str("\"symbols\":[");
        for index in 0..=CACHE_COLLECTION_MAX {
            if index != 0 {
                many.push(',');
            }
            many.push_str("null");
        }
        many.push_str("],\"edges\":[]}}");
        assert!(many.len() < CACHE_BLOB_MAX_BYTES);
        assert!(matches!(
            decode_graph(many.as_bytes()),
            Err(CacheError::Limits)
        ));
    }
}
