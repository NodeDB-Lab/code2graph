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

impl Package {
    /// An entirely-unknown package (all fields empty).
    pub fn unknown() -> Self {
        Self::default()
    }

    fn render(&self, out: &mut String) {
        // SCIP space-joins the three fields; empty fields render as a bare space.
        out.push_str(self.manager.trim());
        out.push(' ');
        out.push_str(self.name.trim());
        out.push(' ');
        out.push_str(self.version.trim());
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
        // scheme ' ' <empty manager> ' ' <empty name> ' ' <empty version> ' ' descriptors
        assert_eq!(id.to_scip_string(), "codegraph    auth/validate_token().");
        assert_eq!(id.leaf_name(), Some("validate_token"));
    }

    #[test]
    fn local_renders_local_form() {
        let id = SymbolId::local("src/main.rs", "x0");
        assert_eq!(id.to_scip_string(), "local x0");
    }
}
