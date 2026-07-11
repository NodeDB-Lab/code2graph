// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default maximum number of files considered by one invocation.
pub const DEFAULT_MAX_FILES: usize = 1_000;
/// Default maximum bytes read from any one source file.
pub const DEFAULT_MAX_FILE_BYTES: usize = 1_024 * 1_024;
/// Default maximum aggregate source bytes read by one invocation.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 25 * 1_024 * 1_024;
/// Default directory and traversal depth cap.
pub const DEFAULT_MAX_DEPTH: u32 = 32;
/// Default number of rows rendered by a command.
pub const DEFAULT_LIMIT: usize = 50;
/// Default reverse-reachability depth for `impact`.
pub const DEFAULT_IMPACT_DEPTH: u32 = 2;

/// Resolver implementation selected for an invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverTier {
    Name,
    #[default]
    Scope,
    Dense,
}

impl From<ResolverTier> for crate::cache::ResolverCacheTier {
    fn from(value: ResolverTier) -> Self {
        match value {
            ResolverTier::Name => Self::Name,
            ResolverTier::Scope => Self::Scope,
            ResolverTier::Dense => Self::Dense,
        }
    }
}

impl From<crate::cache::ResolverCacheTier> for ResolverTier {
    fn from(value: crate::cache::ResolverCacheTier) -> Self {
        match value {
            crate::cache::ResolverCacheTier::Name => Self::Name,
            crate::cache::ResolverCacheTier::Scope => Self::Scope,
            crate::cache::ResolverCacheTier::Dense => Self::Dense,
        }
    }
}

impl ResolverTier {
    /// Planned effective minimum when `--min-confidence` is not supplied.
    pub const fn default_min_confidence(self) -> code2graph::Confidence {
        match self {
            Self::Name => code2graph::Confidence::NameOnly,
            Self::Scope => code2graph::Confidence::Scoped,
            Self::Dense => code2graph::Confidence::Heuristic,
        }
    }
}

/// Bounded resources applied before project scanning and traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_depth: u32,
    pub result_limit: usize,
    pub timeout: Option<Duration>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            result_limit: DEFAULT_LIMIT,
            timeout: None,
        }
    }
}

/// Options shared by every command. Command execution owns their filesystem and
/// cache effects; parsing these options is pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalOptions {
    pub root: Option<PathBuf>,
    pub tier: ResolverTier,
    /// `None` lets execution choose the tier-specific confidence default.
    pub min_confidence: Option<code2graph::Confidence>,
    pub json: bool,
    pub limits: ResourceLimits,
    pub include_hidden: bool,
    pub frozen: bool,
    pub allow_stale: bool,
    pub allow_partial: bool,
    pub no_cache: bool,
}

impl GlobalOptions {
    /// Explicit override or the resolver tier's documented default.
    pub fn effective_min_confidence(&self) -> code2graph::Confidence {
        self.min_confidence
            .unwrap_or_else(|| self.tier.default_min_confidence())
    }
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            root: None,
            tier: ResolverTier::Scope,
            min_confidence: None,
            json: false,
            limits: ResourceLimits::default(),
            include_hidden: false,
            frozen: false,
            allow_stale: false,
            allow_partial: false,
            no_cache: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use code2graph::Confidence;

    #[test]
    fn tier_confidence_defaults_are_the_planned_values() {
        assert_eq!(
            ResolverTier::Name.default_min_confidence(),
            Confidence::NameOnly
        );
        assert_eq!(
            ResolverTier::Scope.default_min_confidence(),
            Confidence::Scoped
        );
        assert_eq!(
            ResolverTier::Dense.default_min_confidence(),
            Confidence::Heuristic
        );

        let options = GlobalOptions {
            min_confidence: Some(Confidence::Exact),
            ..GlobalOptions::default()
        };
        assert_eq!(options.effective_min_confidence(), Confidence::Exact);
    }

    #[test]
    fn resolver_tier_cache_conversions_are_lossless() {
        for tier in [ResolverTier::Name, ResolverTier::Scope, ResolverTier::Dense] {
            assert_eq!(
                ResolverTier::from(crate::cache::ResolverCacheTier::from(tier)),
                tier
            );
        }
    }
}
