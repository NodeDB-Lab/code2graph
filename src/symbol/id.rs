// SPDX-License-Identifier: Apache-2.0

//! `SymbolId` — SCIP-aligned symbol identity.
//!
//! A global symbol is `<scheme> <package> (<descriptor>)+`; its rendered string
//! is a stable, human-readable, fully-qualified name, so two references resolve
//! to the same symbol iff their strings are equal — no separate join pass.
//!
//! codegraph is build-free, so it often does **not** know the package
//! (manager/name/version) at parse time. We still emit descriptors (the FQN
//! within a package); a consumer that knows the manifest can fill `package`
//! later. Within a single repo, descriptors + lang carry identity already.

use std::fmt;

use super::descriptor::Descriptor;

/// Package coordinates (SCIP `<manager> <package-name> <version>`). Any field
/// may be empty when unknown — codegraph leaves these to the consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Package {
    pub manager: String,
    pub name: String,
    pub version: String,
}

/// Return `s` trimmed, or `"."` if empty — SCIP requires `.` for unknown fields.
fn scip_field(s: &str) -> &str {
    let t = s.trim();
    if t.is_empty() { "." } else { t }
}

impl Package {
    /// An entirely-unknown package (all fields empty).
    pub fn unknown() -> Self {
        Self::default()
    }

    fn render(&self, out: &mut String) {
        // SCIP space-joins the three fields; empty fields render as `.` per spec.
        out.push_str(scip_field(&self.manager));
        out.push(' ');
        out.push_str(scip_field(&self.name));
        out.push(' ');
        out.push_str(scip_field(&self.version));
    }
}

/// Default scheme tag for codegraph-produced symbols.
pub const SCHEME: &str = "codegraph";

/// A symbol's identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolId {
    /// Cross-file / cross-repo identity: a fully-qualified descriptor path.
    Global {
        scheme: String,
        package: Package,
        /// Language tag (see [`crate::lang::Language::as_str`]).
        lang: String,
        descriptors: Vec<Descriptor>,
    },
    /// A document-local entity (locals, parameters): only meaningful within `file`.
    Local { file: String, id: String },
}

impl SymbolId {
    /// Build a global symbol with the default scheme and an unknown package.
    pub fn global(lang: impl Into<String>, descriptors: Vec<Descriptor>) -> Self {
        SymbolId::Global {
            scheme: SCHEME.to_owned(),
            package: Package::unknown(),
            lang: lang.into(),
            descriptors,
        }
    }

    /// A file-local symbol.
    pub fn local(file: impl Into<String>, id: impl Into<String>) -> Self {
        SymbolId::Local {
            file: file.into(),
            id: id.into(),
        }
    }

    /// The bare name of the final descriptor — the key for name-only matching.
    pub fn leaf_name(&self) -> Option<&str> {
        match self {
            SymbolId::Global { descriptors, .. } => descriptors.last().map(|d| d.name()),
            SymbolId::Local { id, .. } => Some(id),
        }
    }

    /// The SCIP-format symbol string. Equality of this string is symbol identity.
    pub fn to_scip_string(&self) -> String {
        let mut s = String::new();
        match self {
            SymbolId::Global {
                scheme,
                package,
                descriptors,
                ..
            } => {
                s.push_str(scheme);
                s.push(' ');
                package.render(&mut s);
                s.push(' ');
                for d in descriptors {
                    d.render(&mut s);
                }
            }
            SymbolId::Local { id, .. } => {
                s.push_str("local ");
                s.push_str(id);
            }
        }
        s
    }
}

impl fmt::Display for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_scip_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_renders_scip_string() {
        let id = SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("auth".into()),
                Descriptor::Method {
                    name: "validate_token".into(),
                    disambiguator: String::new(),
                },
            ],
        );
        // scheme ' ' manager ' ' name ' ' version ' ' descriptors (empty fields → '.')
        assert_eq!(
            id.to_scip_string(),
            "codegraph . . . auth/validate_token()."
        );
        assert_eq!(id.leaf_name(), Some("validate_token"));
    }

    #[test]
    fn local_renders_local_form() {
        let id = SymbolId::local("src/main.rs", "x0");
        assert_eq!(id.to_scip_string(), "local x0");
    }

    // ── SCIP-compliance golden tests ──────────────────────────────────────────

    #[test]
    fn golden_namespace_only() {
        // global, all-empty package, single Namespace → "codegraph . . . auth/"
        let id = SymbolId::global("rust", vec![Descriptor::Namespace("auth".into())]);
        assert_eq!(id.to_scip_string(), "codegraph . . . auth/");
    }

    // golden_namespace_and_method is covered by global_renders_scip_string above.

    #[test]
    fn golden_two_namespaces_and_type() {
        // global, all-empty package, two Namespaces + Type
        let id = SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("auth".into()),
                Descriptor::Namespace("session".into()),
                Descriptor::Type("Session".into()),
            ],
        );
        assert_eq!(id.to_scip_string(), "codegraph . . . auth/session/Session#");
    }

    #[test]
    fn golden_namespace_and_term() {
        // global, all-empty package, Namespace + Term (const/static)
        let id = SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("config".into()),
                Descriptor::Term("MAX_CONN".into()),
            ],
        );
        assert_eq!(id.to_scip_string(), "codegraph . . . config/MAX_CONN.");
    }

    #[test]
    fn golden_partial_package_manager_only() {
        // partially-populated package: manager = "npm", name/version empty
        let id = SymbolId::Global {
            scheme: SCHEME.to_owned(),
            package: Package {
                manager: "npm".into(),
                name: String::new(),
                version: String::new(),
            },
            lang: "typescript".into(),
            descriptors: vec![Descriptor::Namespace("src".into())],
        };
        assert_eq!(id.to_scip_string(), "codegraph npm . . src/");
    }
}
