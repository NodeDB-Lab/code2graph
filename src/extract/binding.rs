// SPDX-License-Identifier: Apache-2.0

//! Query-binding rules: which language constructs carry embedded SQL.
//!
//! A query-binding rule declares that a particular language construct — a
//! macro, function, or method that accepts a SQL string — carries embedded
//! SQL in one of its arguments. An extractor uses these rules to locate
//! embedded SQL, pull out the tables it references, and emit cross-artifact
//! references linking code to the data it touches.
//!
//! The registry is matching-agnostic: it only stores rules and hands back the
//! ones registered for a language. How a rule's `construct` string is matched
//! against an actual call site (exact name, path suffix, receiver type, …) is
//! the extractor's responsibility, not this module's. Rules are pure data;
//! the registry performs no I/O and does no parsing.

use crate::lang::Language;

/// A rule declaring that `construct` — a macro, function, or method the
/// extractor recognizes for `lang` — carries an embedded SQL string in one
/// of its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryBindingRule {
    /// The language this construct appears in.
    pub lang: Language,
    /// The call target the extractor matches (e.g. `"sqlx::query"`).
    /// Matching semantics (exact match, path suffix, receiver-typed method,
    /// …) are defined by the extractor that consumes this rule, not here.
    pub construct: String,
    /// 0-based index of the argument holding the SQL string.
    pub sql_arg: usize,
}

/// A registry of query-binding rules, queryable per language.
///
/// Storage is a plain `Vec`, not a map keyed by language: rule counts are
/// small, insertion order is preserved (deterministic iteration), and a
/// linear filter over a handful of entries costs nothing.
#[derive(Debug, Clone)]
pub struct BindingRules {
    rules: Vec<QueryBindingRule>,
}

impl BindingRules {
    /// An empty registry with no rules.
    pub fn empty() -> Self {
        BindingRules { rules: Vec::new() }
    }

    /// The built-in default rule set covering common database-API
    /// conventions. Consumers extend this via [`BindingRules::register`].
    pub fn with_defaults() -> Self {
        let mut rules = BindingRules::empty();
        for (lang, construct, sql_arg) in DEFAULT_RULES {
            rules.register(QueryBindingRule {
                lang: *lang,
                construct: (*construct).to_string(),
                sql_arg: *sql_arg,
            });
        }
        rules
    }

    /// Registers a custom rule, appending it after any existing rules for
    /// the same language.
    pub fn register(&mut self, rule: QueryBindingRule) {
        self.rules.push(rule);
    }

    /// The rules registered for `lang`, in insertion order.
    pub fn for_language(&self, lang: Language) -> impl Iterator<Item = &QueryBindingRule> {
        self.rules.iter().filter(move |r| r.lang == lang)
    }

    /// Whether the registry holds no rules at all.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The total number of registered rules, across all languages.
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Built-in defaults: common database-API constructs that take a SQL string
/// argument. This set is deliberately modest — real-world coverage, not a
/// speculative superset. Consumers add project-specific constructs via
/// [`BindingRules::register`].
const DEFAULT_RULES: &[(Language, &str, usize)] = &[
    (Language::Rust, "sqlx::query", 0),
    (Language::Rust, "sqlx::query_as", 0),
    (Language::Rust, "sqlx::query_scalar", 0),
    (Language::Rust, "diesel::sql_query", 0),
    (Language::TypeScript, "knex.raw", 0),
    (Language::JavaScript, "knex.raw", 0),
    // `execute`/`text` are bare method/function names, not qualified paths:
    // several DB-API libraries (e.g. Python's DB-API cursors, SQLAlchemy's
    // `text()`) share these names, so matches here are inherently
    // name-scoped — extractors should treat resulting cross-artifact
    // references as `Confidence::NameOnly`.
    (Language::Python, "execute", 0),
    (Language::Python, "text", 0),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_defaults_has_rust_sqlx_query_rule() {
        let rules = BindingRules::with_defaults();
        let found = rules
            .for_language(Language::Rust)
            .find(|r| r.construct == "sqlx::query");
        let rule = found.expect("sqlx::query rule must be present");
        assert_eq!(rule.sql_arg, 0);
    }

    #[test]
    fn with_defaults_has_python_execute_rule() {
        let rules = BindingRules::with_defaults();
        let found = rules
            .for_language(Language::Python)
            .find(|r| r.construct == "execute");
        assert!(found.is_some());
    }

    #[test]
    fn for_language_rust_yields_only_rust_rules() {
        let rules = BindingRules::with_defaults();
        let rust_rules: Vec<_> = rules.for_language(Language::Rust).collect();
        assert!(rust_rules.iter().all(|r| r.lang == Language::Rust));

        let constructs: Vec<&str> = rust_rules.iter().map(|r| r.construct.as_str()).collect();
        for expected in [
            "sqlx::query",
            "sqlx::query_as",
            "sqlx::query_scalar",
            "diesel::sql_query",
        ] {
            assert!(
                constructs.contains(&expected),
                "missing default rust rule: {expected}"
            );
        }
    }

    #[test]
    fn for_language_with_no_rules_is_empty() {
        let rules = BindingRules::with_defaults();
        assert_eq!(rules.for_language(Language::Go).count(), 0);
    }

    #[test]
    fn register_on_empty_registry_surfaces_new_rule() {
        let mut rules = BindingRules::empty();
        rules.register(QueryBindingRule {
            lang: Language::Ruby,
            construct: "ActiveRecord::Base.connection.execute".to_string(),
            sql_arg: 0,
        });

        let found: Vec<_> = rules.for_language(Language::Ruby).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].construct, "ActiveRecord::Base.connection.execute");
    }

    #[test]
    fn empty_registry_yields_nothing_for_any_language() {
        let rules = BindingRules::empty();
        assert!(rules.is_empty());
        assert_eq!(rules.len(), 0);
        assert_eq!(rules.for_language(Language::Rust).count(), 0);
    }
}
