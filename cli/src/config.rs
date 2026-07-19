// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use code2graph::{Language, QueryBindingRule};

use crate::error::{CliError, Result};

/// Filename of the project-local configuration file, read from the project root.
const CONFIG_FILE_NAME: &str = "code2graph.toml";

/// Deserialized shape of `code2graph.toml`.
///
/// ```toml
/// [[query_binding]]
/// lang = "rust"
/// construct = "mydb::sql"
/// sql_arg = 0
/// ```
#[derive(Debug, Deserialize)]
struct Code2graphToml {
    #[serde(default)]
    query_binding: Vec<RawQueryBindingRule>,
}

/// One `[[query_binding]]` table before its `lang` string is resolved to a
/// `code2graph::Language` and validated.
#[derive(Debug, Deserialize)]
struct RawQueryBindingRule {
    lang: String,
    construct: String,
    sql_arg: usize,
}

/// Loads project-supplied custom query-binding rules from `code2graph.toml`
/// at `project_root`, merged by the caller with `BindingRules::with_defaults()`.
///
/// A missing file is normal (not every project customizes query binding) and
/// yields an empty list; the built-in defaults still apply. A present but
/// unparsable file, or a rule naming an unknown language or an empty
/// `construct`, is a load-time configuration error reported to the user.
pub(crate) fn load_query_binding_rules(project_root: &Path) -> Result<Vec<QueryBindingRule>> {
    let path = project_root.join(CONFIG_FILE_NAME);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(CliError::Fatal(format!(
                "failed to read {}: {error}",
                path.display()
            )));
        }
    };
    let parsed: Code2graphToml = toml::from_str(&content)
        .map_err(|error| CliError::Fatal(format!("failed to parse {}: {error}", path.display())))?;
    parsed
        .query_binding
        .into_iter()
        .map(|raw| convert_rule(raw, &path))
        .collect()
}

fn convert_rule(raw: RawQueryBindingRule, path: &Path) -> Result<QueryBindingRule> {
    let lang = Language::from_tag(&raw.lang).ok_or_else(|| {
        CliError::Fatal(format!(
            "{}: unknown query-binding language {:?}",
            path.display(),
            raw.lang
        ))
    })?;
    if raw.construct.is_empty() {
        return Err(CliError::Fatal(format!(
            "{}: query-binding rule for {:?} has an empty construct",
            path.display(),
            raw.lang
        )));
    }
    Ok(QueryBindingRule {
        lang,
        construct: raw.construct,
        sql_arg: raw.sql_arg,
    })
}

/// Default maximum number of files considered by one invocation.
pub const DEFAULT_MAX_FILES: usize = 10_000;
/// Default maximum bytes read from any one source file.
pub const DEFAULT_MAX_FILE_BYTES: usize = 1_024 * 1_024;
/// Default maximum aggregate source bytes read by one invocation.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1_024 * 1_024;
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
    /// Stable kebab-case spelling, matching the serialized representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Scope => "scope",
            Self::Dense => "dense",
        }
    }

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

    #[test]
    fn absent_config_file_yields_no_custom_rules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rules = load_query_binding_rules(temp.path()).expect("absent file is not an error");
        assert!(rules.is_empty());
    }

    #[test]
    fn valid_config_file_yields_its_rules() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join(CONFIG_FILE_NAME),
            r#"
[[query_binding]]
lang = "rust"
construct = "mydb::sql"
sql_arg = 0

[[query_binding]]
lang = "python"
construct = "app.raw"
sql_arg = 1
"#,
        )
        .expect("write config");
        let rules = load_query_binding_rules(temp.path()).expect("valid config parses");
        assert_eq!(
            rules,
            vec![
                QueryBindingRule {
                    lang: Language::Rust,
                    construct: "mydb::sql".into(),
                    sql_arg: 0,
                },
                QueryBindingRule {
                    lang: Language::Python,
                    construct: "app.raw".into(),
                    sql_arg: 1,
                },
            ]
        );
    }

    #[test]
    fn unknown_language_is_rejected_with_a_clear_message() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join(CONFIG_FILE_NAME),
            r#"
[[query_binding]]
lang = "klingon"
construct = "mydb::sql"
sql_arg = 0
"#,
        )
        .expect("write config");
        let error = load_query_binding_rules(temp.path()).expect_err("unknown lang is rejected");
        assert!(error.to_string().contains("klingon"));
    }

    #[test]
    fn malformed_toml_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join(CONFIG_FILE_NAME), "not = [valid").expect("write config");
        assert!(load_query_binding_rules(temp.path()).is_err());
    }
}
