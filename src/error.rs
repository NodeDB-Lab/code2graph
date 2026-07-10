// SPDX-License-Identifier: Apache-2.0

//! `CodegraphError` — errors surfaced by extraction and resolution.
//!
//! Deliberately small and storage-free. Consumers map these into their own
//! error domains at their boundary.

/// Errors that can arise while turning source into structural facts.
#[derive(Debug, thiserror::Error)]
pub enum CodegraphError {
    /// The language for an extension/path is not supported by code2graph.
    #[error("unsupported language for `{0}`")]
    UnsupportedLanguage(String),

    /// tree-sitter failed to construct a parser or parse the source.
    #[error("parse error in `{path}`")]
    Parse {
        /// Source path (relative) that failed to parse.
        path: String,
    },

    /// A tree-sitter query failed to compile (internal/library bug).
    #[error("invalid tree-sitter query for `{lang}`: {msg}")]
    Query {
        /// Language whose query failed.
        lang: String,
        /// Underlying message.
        msg: String,
    },

    /// Resolver input violated the structural `FileFacts` contract.
    #[error("malformed file facts for `{file}`: {reason}")]
    MalformedFacts { file: String, reason: String },
}

/// Convenience alias for code2graph fallible operations.
pub type Result<T> = std::result::Result<T, CodegraphError>;
