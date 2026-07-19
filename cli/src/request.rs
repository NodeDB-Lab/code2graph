// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use code2graph::{RefRole, SymbolId, SymbolKind};

use crate::config::GlobalOptions;

/// A complete, owned CLI invocation suitable for host-side tests or embedding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliRequest {
    pub global: GlobalOptions,
    pub command: CommandRequest,
}

/// The selected CLI operation. These are requests only: no variant performs I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRequest {
    Index {
        path: Option<PathBuf>,
        force: bool,
        trust_mtime: bool,
    },
    Status,
    Symbols {
        text: String,
        file: Option<String>,
        kind: Option<SymbolKind>,
        case_sensitive: bool,
    },
    Def {
        selector: Selector,
        file: Option<String>,
        kind: Option<SymbolKind>,
        require_unique: bool,
    },
    Callers {
        selector: Selector,
        file: Option<String>,
        kind: Option<SymbolKind>,
        require_unique: bool,
        role: Option<RefRole>,
    },
    Callees {
        selector: Selector,
        file: Option<String>,
        kind: Option<SymbolKind>,
        require_unique: bool,
        role: Option<RefRole>,
    },
    Impact {
        selector: Selector,
        file: Option<String>,
        kind: Option<SymbolKind>,
        require_unique: bool,
        role: Option<RefRole>,
        depth: u32,
    },
    Usages {
        selector: Selector,
        file: Option<String>,
        kind: Option<SymbolKind>,
        require_unique: bool,
        role: Option<RefRole>,
    },
    DiffImpact {
        base: Option<String>,
        role: Option<RefRole>,
        depth: u32,
    },
    Imports {
        file: String,
    },
    ModuleDeps,
    References {
        file: String,
        name: Option<String>,
        role: Option<RefRole>,
    },
    Cache {
        op: CacheOp,
    },
}

/// A cache-management operation. These are requests only: no variant performs I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOp {
    /// Report this project's cache directory and database path.
    Path,
    /// Report cache footprint and per-snapshot breakdown.
    Status,
    /// Delete this project's cache, or every project's cache with `all`.
    Clear { all: bool },
}

impl CommandRequest {
    /// Stable command spelling for diagnostics and host capability errors.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Index { .. } => "index",
            Self::Status => "status",
            Self::Symbols { .. } => "symbols",
            Self::Def { .. } => "def",
            Self::Callers { .. } => "callers",
            Self::Callees { .. } => "callees",
            Self::Impact { .. } => "impact",
            Self::DiffImpact { .. } => "diff-impact",
            Self::Usages { .. } => "usages",
            Self::Imports { .. } => "imports",
            Self::ModuleDeps => "module-deps",
            Self::References { .. } => "references",
            Self::Cache { .. } => "cache",
        }
    }

    /// Effective resolved-edge role filter. Call traversal defaults to calls;
    /// `usages` deliberately keeps `None` to mean every role.
    pub fn effective_relation_role(&self) -> Option<RefRole> {
        match self {
            Self::Callers { role, .. } | Self::Callees { role, .. } | Self::Impact { role, .. } => {
                Some(role.unwrap_or(RefRole::Call))
            }
            Self::Usages { role, .. } => *role,
            _ => None,
        }
    }
}

/// Exactly one non-guessing symbol selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Name(String),
    /// Exact lossless structural identity decoded through `SymbolId` serde.
    Id(SymbolId),
    /// A plural SCIP display lookup, never an exact structural identity.
    Scip(String),
    Position(SourcePosition),
}

/// Human source position. Both coordinates are 1-based; omitted column is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePosition {
    pub file: String,
    pub line: u32,
    pub column: u32,
}
