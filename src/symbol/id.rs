// SPDX-License-Identifier: Apache-2.0

//! `SymbolId` — SCIP-aligned symbol identity.
//!
//! A global symbol is `<scheme> <package> (<descriptor>)+`; its rendered SCIP
//! string is a stable, human-readable interoperability/display form. Structural
//! [`SymbolId`] equality is identity: global language and local-file coordinates
//! are intentionally retained even though SCIP does not render them.
//!
//! code2graph is build-free, so it often does **not** know the package
//! (manager/name/version) at parse time. We still emit descriptors (the FQN
//! within a package); a consumer that knows the manifest can fill `package`
//! later. Within a single repo, descriptors + lang carry identity already.

use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use super::descriptor::{Descriptor, parse_descriptor};

/// Package coordinates (SCIP `<manager> <package-name> <version>`). Any field
/// may be empty when unknown — code2graph leaves these to the consumer.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    fn render<W: fmt::Write>(&self, out: &mut W) -> fmt::Result {
        // SCIP space-joins the three fields; empty fields render as `.` per spec.
        out.write_str(scip_field(&self.manager))?;
        out.write_char(' ')?;
        out.write_str(scip_field(&self.name))?;
        out.write_char(' ')?;
        out.write_str(scip_field(&self.version))
    }
}

/// Default scheme tag for code2graph-produced symbols.
pub const SCHEME: &str = "codegraph";

/// Private representation behind [`SymbolId`]'s `Arc`. Both variants share
/// a single allocation path so cloning `SymbolId` is always O(1) — one
/// atomic refcount bump — regardless of which variant is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SymbolRepr {
    /// Cross-file / cross-repo identity: a fully-qualified descriptor path.
    Global {
        scheme: String,
        package: Package,
        lang: String,
        descriptors: Vec<Descriptor>,
    },
    /// A document-local entity (locals, parameters): only meaningful within `file`.
    Local { file: String, id: String },
}

/// Errors from parsing a SCIP symbol string (the inverse of
/// [`SymbolId::to_scip_string`]). Surfaced via [`std::str::FromStr`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SymbolParseError {
    /// The input was empty.
    #[error("empty symbol string")]
    Empty,

    /// The header had too few space-separated tokens (a global symbol needs
    /// scheme + 3 package fields + descriptors; `local` needs an id).
    #[error("malformed symbol header: not enough tokens")]
    MalformedHeader,

    /// A backtick-quoted identifier was never closed.
    #[error("unterminated backtick-quoted identifier")]
    UnterminatedQuote,

    /// An identifier was expected but none was found.
    #[error("expected an identifier")]
    ExpectedIdent,

    /// A descriptor had an unknown or missing suffix.
    #[error("unknown or missing descriptor suffix")]
    UnknownDescriptor,

    /// A method disambiguator was not a SCIP simple identifier.
    #[error("invalid method disambiguator")]
    InvalidDisambiguator,

    /// A global symbol carried zero descriptors.
    #[error("global symbol has no descriptors")]
    NoDescriptors,
}

/// A symbol's identity.
///
/// Internally an `Arc` over a private representation, so cloning is O(1)
/// (one atomic refcount bump) for both the global and local variants. The
/// representation is fully private; use the public constructors and accessor
/// methods to create and inspect values.
///
/// [`Ord`] is a structural total order, not an order of the SCIP display string:
/// global identities sort before local identities, then all stored coordinates
/// sort in declaration order. This makes it consistent with [`Eq`] even where
/// SCIP omits a language or local-file coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolId(Arc<SymbolRepr>);

/// Stable, versioned transport representation of a [`SymbolId`].
///
/// SCIP text omits code2graph's structural language/local-file coordinate, so
/// transporting only [`SymbolId::to_scip_string`] is lossy. This value preserves
/// that coordinate without exposing the private descriptor representation.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolIdWire {
    pub version: u32,
    pub scip: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub lang: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub file: Option<String>,
}

/// Errors converting a [`SymbolIdWire`] into a [`SymbolId`].
#[derive(Debug, thiserror::Error)]
pub enum SymbolIdWireError {
    #[error("unsupported SymbolId wire version {0}")]
    Version(u32),
    #[error("invalid SCIP symbol: {0}")]
    Parse(#[from] SymbolParseError),
    #[error("global SymbolId wire requires lang and forbids file")]
    GlobalContext,
    #[error("local SymbolId wire requires file and forbids lang")]
    LocalContext,
}

impl Ord for SymbolId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&*self.0, &*other.0) {
            (
                SymbolRepr::Global {
                    scheme: a_scheme,
                    package: a_package,
                    lang: a_lang,
                    descriptors: a_descriptors,
                },
                SymbolRepr::Global {
                    scheme: b_scheme,
                    package: b_package,
                    lang: b_lang,
                    descriptors: b_descriptors,
                },
            ) => (a_scheme, a_package, a_lang, a_descriptors).cmp(&(
                b_scheme,
                b_package,
                b_lang,
                b_descriptors,
            )),
            (
                SymbolRepr::Local {
                    file: a_file,
                    id: a_id,
                },
                SymbolRepr::Local {
                    file: b_file,
                    id: b_id,
                },
            ) => (a_file, a_id).cmp(&(b_file, b_id)),
            (SymbolRepr::Global { .. }, SymbolRepr::Local { .. }) => Ordering::Less,
            (SymbolRepr::Local { .. }, SymbolRepr::Global { .. }) => Ordering::Greater,
        }
    }
}

impl PartialOrd for SymbolId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl SymbolId {
    /// Build a global symbol with the default scheme and an unknown package.
    pub fn global(lang: impl Into<String>, descriptors: Vec<Descriptor>) -> Self {
        SymbolId(Arc::new(SymbolRepr::Global {
            scheme: SCHEME.to_owned(),
            package: Package::unknown(),
            lang: lang.into(),
            descriptors,
        }))
    }

    /// A file-local symbol.
    pub fn local(file: impl Into<String>, id: impl Into<String>) -> Self {
        SymbolId(Arc::new(SymbolRepr::Local {
            file: file.into(),
            id: id.into(),
        }))
    }

    /// The language coordinate of a global symbol, or `None` for a local symbol.
    /// This coordinate is structural identity and is not rendered by SCIP.
    pub fn language(&self) -> Option<&str> {
        match &*self.0 {
            SymbolRepr::Global { lang, .. } => Some(lang),
            SymbolRepr::Local { .. } => None,
        }
    }

    /// The owning file coordinate of a local symbol, or `None` for a global symbol.
    /// This coordinate is structural identity and is not rendered by SCIP.
    pub fn local_file(&self) -> Option<&str> {
        match &*self.0 {
            SymbolRepr::Global { .. } => None,
            SymbolRepr::Local { file, .. } => Some(file),
        }
    }

    /// Convert to the stable transport representation.
    pub fn to_wire(&self) -> SymbolIdWire {
        SymbolIdWire {
            version: 1,
            scip: self.to_scip_string(),
            lang: self.language().map(str::to_owned),
            file: self.local_file().map(str::to_owned),
        }
    }

    /// Reconstruct a symbol from its stable transport representation.
    pub fn try_from_wire(wire: SymbolIdWire) -> Result<Self, SymbolIdWireError> {
        if wire.version != 1 {
            return Err(SymbolIdWireError::Version(wire.version));
        }
        let parsed = Self::from_scip_string(&wire.scip)?;
        match &*parsed.0 {
            SymbolRepr::Global {
                scheme,
                package,
                descriptors,
                ..
            } => {
                let lang = wire.lang.ok_or(SymbolIdWireError::GlobalContext)?;
                if wire.file.is_some() {
                    return Err(SymbolIdWireError::GlobalContext);
                }
                Ok(Self(Arc::new(SymbolRepr::Global {
                    scheme: scheme.clone(),
                    package: package.clone(),
                    lang,
                    descriptors: descriptors.clone(),
                })))
            }
            SymbolRepr::Local { id, .. } => {
                let file = wire.file.ok_or(SymbolIdWireError::LocalContext)?;
                if wire.lang.is_some() {
                    return Err(SymbolIdWireError::LocalContext);
                }
                Ok(Self::local(file, id.clone()))
            }
        }
    }

    /// Return a new `SymbolId` with `package` stamped in. `Global` variants get
    /// the new package (scheme/lang/descriptors unchanged); `Local` variants are
    /// returned unchanged (locals have no package coordinate).
    pub fn with_package(&self, package: Package) -> SymbolId {
        match &*self.0 {
            SymbolRepr::Global {
                scheme,
                lang,
                descriptors,
                ..
            } => SymbolId(Arc::new(SymbolRepr::Global {
                scheme: scheme.clone(),
                package,
                lang: lang.clone(),
                descriptors: descriptors.clone(),
            })),
            SymbolRepr::Local { .. } => self.clone(),
        }
    }

    /// The ordered names of all `Namespace` descriptors in this symbol's path,
    /// in declaration order (outermost first). Non-namespace descriptors (Type,
    /// Term, Method, …) are excluded. Returns an empty vec for `Local` symbols.
    ///
    /// Used by the Tier-A resolver to match an import's `from_path` suffix
    /// against a candidate's module namespace chain without per-language rules.
    pub fn namespaces(&self) -> Vec<&str> {
        match &*self.0 {
            SymbolRepr::Global { descriptors, .. } => descriptors
                .iter()
                .filter_map(|d| {
                    if let Descriptor::Namespace(n) = d {
                        Some(n.as_str())
                    } else {
                        None
                    }
                })
                .collect(),
            SymbolRepr::Local { .. } => Vec::new(),
        }
    }

    /// Zero-allocation iterator over the names of all `Namespace` descriptors in
    /// this symbol's path, in declaration order (outermost first). Non-namespace
    /// descriptors are excluded. Yields nothing for `Local` symbols.
    ///
    /// Prefer this over [`SymbolId::namespaces`] in hot paths to avoid a heap allocation.
    pub fn namespaces_iter(&self) -> impl Iterator<Item = &str> {
        let descs: &[Descriptor] = match &*self.0 {
            SymbolRepr::Global { descriptors, .. } => descriptors.as_slice(),
            SymbolRepr::Local { .. } => &[],
        };
        descs.iter().filter_map(|d| {
            if let Descriptor::Namespace(n) = d {
                Some(n.as_str())
            } else {
                None
            }
        })
    }

    /// Zero-allocation iterator over the names of ALL descriptors in this
    /// symbol's path, in declaration order (outermost first) — every kind
    /// included (namespaces, types, methods, terms…), unlike
    /// [`namespaces_iter`](SymbolId::namespaces_iter) which yields only
    /// namespaces. Used to match an explicit call qualifier that may name an
    /// enclosing *type* (a Ruby/Kotlin module, a class) rather than a namespace.
    /// Yields nothing for `Local` symbols.
    pub fn descriptor_names_iter(&self) -> impl Iterator<Item = &str> {
        let descs: &[Descriptor] = match &*self.0 {
            SymbolRepr::Global { descriptors, .. } => descriptors.as_slice(),
            SymbolRepr::Local { .. } => &[],
        };
        descs.iter().map(|d| d.name())
    }

    /// The bare name of the final descriptor — the key for name-only matching.
    pub fn leaf_name(&self) -> Option<&str> {
        match &*self.0 {
            SymbolRepr::Global { descriptors, .. } => descriptors.last().map(|d| d.name()),
            SymbolRepr::Local { id, .. } => Some(id),
        }
    }

    /// Core rendering logic shared by [`to_scip_string`] and [`Display`].
    fn write_scip<W: fmt::Write>(&self, w: &mut W) -> fmt::Result {
        match &*self.0 {
            SymbolRepr::Global {
                scheme,
                package,
                descriptors,
                ..
            } => {
                w.write_str(scheme)?;
                w.write_char(' ')?;
                package.render(w)?;
                w.write_char(' ')?;
                for d in descriptors {
                    d.render(w)?;
                }
                Ok(())
            }
            SymbolRepr::Local { id, .. } => {
                w.write_str("local ")?;
                w.write_str(id)
            }
        }
    }

    /// The SCIP-format symbol display/interoperability string. It is not a
    /// lossless identity key because it omits global language and local-file
    /// coordinates; use structural [`SymbolId`] equality for identity.
    pub fn to_scip_string(&self) -> String {
        self.to_string()
    }

    /// Parse a SCIP symbol string — the inverse of [`SymbolId::to_scip_string`].
    ///
    /// Note `lang` (Global) and `file` (Local) are not encoded in the string,
    /// so they are parsed back as empty; only the string round-trips exactly.
    pub fn from_scip_string(s: &str) -> Result<Self, SymbolParseError> {
        if s.is_empty() {
            return Err(SymbolParseError::Empty);
        }

        // `local <id>` — the id is the whole remainder after the single space.
        if let Some(id) = s.strip_prefix("local ") {
            if id.is_empty() {
                return Err(SymbolParseError::ExpectedIdent);
            }
            return Ok(SymbolId(Arc::new(SymbolRepr::Local {
                file: String::new(),
                id: id.to_owned(),
            })));
        }
        if !s.contains(' ') {
            // No space at all: cannot be a valid header.
            return Err(SymbolParseError::MalformedHeader);
        }

        // Global: scheme manager name version descriptors (exactly 5 tokens).
        let mut parts = s.splitn(5, ' ');
        let scheme = parts.next().ok_or(SymbolParseError::MalformedHeader)?;
        let manager = parts.next().ok_or(SymbolParseError::MalformedHeader)?;
        let name = parts.next().ok_or(SymbolParseError::MalformedHeader)?;
        let version = parts.next().ok_or(SymbolParseError::MalformedHeader)?;
        let descriptors_str = parts.next().ok_or(SymbolParseError::MalformedHeader)?;
        if scheme.is_empty()
            || manager.is_empty()
            || name.is_empty()
            || version.is_empty()
            || descriptors_str.is_empty()
        {
            return Err(SymbolParseError::MalformedHeader);
        }

        let unfield = |t: &str| {
            if t == "." {
                String::new()
            } else {
                t.to_owned()
            }
        };
        let package = Package {
            manager: unfield(manager),
            name: unfield(name),
            version: unfield(version),
        };

        let mut descriptors = Vec::new();
        let mut cursor = descriptors_str;
        while !cursor.is_empty() {
            let (desc, rest) = parse_descriptor(cursor)?;
            descriptors.push(desc);
            cursor = rest;
        }
        if descriptors.is_empty() {
            return Err(SymbolParseError::NoDescriptors);
        }

        Ok(SymbolId(Arc::new(SymbolRepr::Global {
            scheme: scheme.to_owned(),
            package,
            lang: String::new(),
            descriptors,
        })))
    }
}

impl std::str::FromStr for SymbolId {
    type Err = SymbolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_scip_string(s)
    }
}

impl fmt::Display for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_scip(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbol::MethodDisambiguator;

    #[test]
    fn namespaces_returns_namespace_segments_only() {
        // Java-style: two Namespace descriptors + a Type leaf.
        let id = SymbolId::global(
            "java",
            vec![
                Descriptor::Namespace("com".into()),
                Descriptor::Namespace("example".into()),
                Descriptor::Type("Config".into()),
            ],
        );
        assert_eq!(id.namespaces(), vec!["com", "example"]);
    }

    #[test]
    fn namespaces_empty_for_local() {
        let id = SymbolId::local("src/main.rs", "x0");
        assert!(id.namespaces().is_empty());
    }

    #[test]
    fn namespaces_empty_for_no_namespace_descriptors() {
        // A Type-only symbol (no Namespace wrappers).
        let id = SymbolId::global("java", vec![Descriptor::Type("Foo".into())]);
        assert!(id.namespaces().is_empty());
    }

    #[test]
    fn global_renders_scip_string() {
        let id = SymbolId::global(
            "rust",
            vec![
                Descriptor::Namespace("auth".into()),
                Descriptor::Method {
                    name: "validate_token".into(),
                    disambiguator: MethodDisambiguator::empty(),
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
    fn global_identity_round_trips_with_its_language() {
        let rust = SymbolId::global("rust", vec![Descriptor::Term("helper".into())]);
        let python = SymbolId::global("python", vec![Descriptor::Term("helper".into())]);

        // SCIP deliberately has no language field. The lossless serde wire
        // representation carries it without changing the standard SCIP scheme.
        assert_eq!(rust.to_scip_string(), python.to_scip_string());
        assert_ne!(rust, python, "language is structural identity");
        assert_eq!(rust.language(), Some("rust"));
        assert_eq!(python.language(), Some("python"));
        assert_eq!(rust.local_file(), None);
        #[cfg(feature = "serde")]
        {
            assert_ne!(
                serde_json::to_string(&rust).unwrap(),
                serde_json::to_string(&python).unwrap(),
                "lossless wire identity must retain language"
            );
        }
    }

    #[test]
    fn local_renders_local_form() {
        let id = SymbolId::local("src/main.rs", "x0");
        assert_eq!(id.to_scip_string(), "local x0");
        assert_eq!(id.language(), None);
        assert_eq!(id.local_file(), Some("src/main.rs"));
    }

    #[test]
    fn same_display_local_symbols_in_different_files_are_distinct() {
        let a = SymbolId::local("src/a.rs", "x0");
        let b = SymbolId::local("src/b.rs", "x0");

        assert_eq!(a.to_scip_string(), b.to_scip_string());
        assert_ne!(a, b, "local file is structural identity");
    }

    #[test]
    fn structural_order_covers_every_symbol_id_coordinate() {
        fn global(
            scheme: &str,
            package: Package,
            lang: &str,
            descriptors: Vec<Descriptor>,
        ) -> SymbolId {
            SymbolId(Arc::new(SymbolRepr::Global {
                scheme: scheme.into(),
                package,
                lang: lang.into(),
                descriptors,
            }))
        }

        let descriptors = vec![
            Descriptor::Namespace("pkg".into()),
            Descriptor::Method {
                name: "helper".into(),
                disambiguator: MethodDisambiguator::new("1").unwrap(),
            },
        ];
        let package = Package {
            manager: "cargo".into(),
            name: "pkg".into(),
            version: "1.0.0".into(),
        };
        let base = global("codegraph", package.clone(), "rust", descriptors.clone());
        let ids = [
            base.clone(),
            global("other", package.clone(), "rust", descriptors.clone()),
            global(
                "codegraph",
                Package {
                    manager: "npm".into(),
                    ..package.clone()
                },
                "rust",
                descriptors.clone(),
            ),
            global(
                "codegraph",
                Package {
                    name: "other".into(),
                    ..package.clone()
                },
                "rust",
                descriptors.clone(),
            ),
            global(
                "codegraph",
                Package {
                    version: "2.0.0".into(),
                    ..package.clone()
                },
                "rust",
                descriptors.clone(),
            ),
            global("codegraph", package.clone(), "python", descriptors.clone()),
            global(
                "codegraph",
                package.clone(),
                "rust",
                vec![Descriptor::Term("helper".into())],
            ),
            SymbolId::local("src/a.rs", "x0"),
            SymbolId::local("src/b.rs", "x0"),
            SymbolId::local("src/a.rs", "x1"),
        ];

        assert_eq!(base.cmp(&base.clone()), Ordering::Equal);
        for (index, id) in ids.iter().enumerate() {
            let same = id.clone();
            assert_eq!(id.cmp(&same), Ordering::Equal);
            assert_eq!(id, &same);
            for different in &ids[index + 1..] {
                assert_ne!(id, different);
                assert_ne!(id.cmp(different), Ordering::Equal);
                assert_eq!(id.cmp(different), different.cmp(id).reverse());
            }
        }

        let ordered: std::collections::BTreeSet<_> = ids.iter().cloned().collect();
        assert_eq!(ordered.len(), ids.len());
    }

    #[test]
    fn ordering_uses_global_language_not_scip_display() {
        let rust = SymbolId::global("rust", vec![Descriptor::Term("helper".into())]);
        let python = SymbolId::global("python", vec![Descriptor::Term("helper".into())]);

        assert_eq!(rust.to_scip_string(), python.to_scip_string());
        assert!(
            python < rust,
            "ordering compares the stored language coordinate"
        );
    }

    #[test]
    fn ordering_uses_local_file_not_scip_display() {
        let a = SymbolId::local("src/a.rs", "x0");
        let b = SymbolId::local("src/b.rs", "x0");

        assert_eq!(a.to_scip_string(), b.to_scip_string());
        assert!(a < b, "ordering compares the stored local-file coordinate");
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
        // partially-populated package: manager = "npm", name/version empty.
        // Built via the private repr directly: this is a rendering golden test,
        // and no public constructor sets a package yet (that arrives with the
        // package-enrichment pass).
        let id = SymbolId(Arc::new(SymbolRepr::Global {
            scheme: SCHEME.to_owned(),
            package: Package {
                manager: "npm".into(),
                name: String::new(),
                version: String::new(),
            },
            lang: "typescript".to_owned(),
            descriptors: vec![Descriptor::Namespace("src".into())],
        }));
        assert_eq!(id.to_scip_string(), "codegraph npm . . src/");
    }

    // ── Parser round-trip tests ───────────────────────────────────────────────

    /// Assert that parsing then re-rendering reproduces the input string exactly.
    /// (`lang`/`file` are not encoded, so only the string can round-trip.)
    fn assert_roundtrip(s: &str) {
        let parsed = SymbolId::from_scip_string(s).expect("should parse");
        assert_eq!(parsed.to_scip_string(), s);
    }

    #[test]
    fn roundtrip_namespace() {
        assert_roundtrip("codegraph . . . auth/");
    }

    #[test]
    fn roundtrip_nested_type() {
        assert_roundtrip("codegraph . . . auth/session/Session#");
    }

    #[test]
    fn roundtrip_term() {
        assert_roundtrip("codegraph . . . config/MAX_CONN.");
    }

    #[test]
    fn roundtrip_method_empty_disambiguator() {
        assert_roundtrip("codegraph . . . auth/validate_token().");
    }

    #[test]
    fn roundtrip_method_with_namespace_and_type() {
        assert_roundtrip("codegraph . . . pkg/MyClass#method().");
    }

    #[test]
    fn roundtrip_macro() {
        assert_roundtrip("codegraph . . . MY_MACRO!");
    }

    #[test]
    fn roundtrip_meta() {
        assert_roundtrip("codegraph . . . attrs:");
    }

    #[test]
    fn roundtrip_type_parameter() {
        assert_roundtrip("codegraph . . . [T]");
    }

    #[test]
    fn roundtrip_parameter() {
        assert_roundtrip("codegraph . . . (param)");
    }

    #[test]
    fn roundtrip_partial_package() {
        assert_roundtrip("codegraph npm . . src/");
    }

    #[test]
    fn roundtrip_full_package() {
        assert_roundtrip("codegraph cargo serde 1.0.0 de/Deserialize#");
    }

    #[test]
    fn roundtrip_quoted_ident_with_space() {
        // Derive the exact rendered form from the renderer, then round-trip it.
        let id = SymbolId::global("rust", vec![Descriptor::Type("Foo Bar".into())]);
        let s = id.to_scip_string();
        assert_roundtrip(&s);
        // Sanity: the parsed descriptor recovers the original name.
        let parsed = SymbolId::from_scip_string(&s).unwrap();
        assert_eq!(
            parsed.leaf_name(),
            Some("Foo Bar"),
            "leaf_name should recover the original name"
        );
    }

    #[test]
    fn roundtrip_quoted_ident_with_backtick() {
        // Embedded backtick → doubled by the renderer; derive, don't hand-write.
        let id = SymbolId::global("rust", vec![Descriptor::Type("Foo`Bar".into())]);
        let s = id.to_scip_string();
        assert_roundtrip(&s);
        let parsed = SymbolId::from_scip_string(&s).unwrap();
        assert_eq!(
            parsed.leaf_name(),
            Some("Foo`Bar"),
            "leaf_name should recover the original name"
        );
    }

    #[test]
    fn roundtrip_quoted_empty_ident() {
        // Empty name is non-simple → renders as two backticks; must round-trip.
        let id = SymbolId::global("rust", vec![Descriptor::Type(String::new())]);
        let s = id.to_scip_string();
        assert_eq!(s, "codegraph . . . ``#");
        assert_roundtrip(&s);
    }

    #[test]
    fn roundtrip_local_x0() {
        let parsed = SymbolId::from_scip_string("local x0").unwrap();
        assert_eq!(parsed.to_scip_string(), "local x0");
        assert_eq!(parsed.leaf_name(), Some("x0"));
    }

    #[test]
    fn roundtrip_local_numeric() {
        let parsed = SymbolId::from_scip_string("local 42").unwrap();
        assert_eq!(parsed.leaf_name(), Some("42"));
        assert_eq!(parsed.to_scip_string(), "local 42");
    }

    // ── Negative tests ────────────────────────────────────────────────────────

    #[test]
    fn err_empty_string() {
        assert_eq!(SymbolId::from_scip_string(""), Err(SymbolParseError::Empty));
    }

    #[test]
    fn err_too_few_header_tokens() {
        // Only scheme + two package fields, no descriptors token.
        assert_eq!(
            SymbolId::from_scip_string("codegraph . ."),
            Err(SymbolParseError::MalformedHeader)
        );
    }

    #[test]
    fn err_no_space_or_empty_header_coordinates() {
        assert_eq!(
            SymbolId::from_scip_string("codegraph"),
            Err(SymbolParseError::MalformedHeader)
        );
        for value in [
            "local ",
            " codegraph . . run.",
            "codegraph  . . run.",
            "codegraph .  . run.",
            "codegraph . .  run.",
            "codegraph . . . ",
        ] {
            assert!(SymbolId::from_scip_string(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn invalid_method_disambiguator_is_rejected_by_the_parser() {
        assert!(
            SymbolId::from_scip_string("codegraph . . . helper(not valid).").is_err(),
            "a method disambiguator is a SCIP simple identifier, never arbitrary text"
        );
    }

    #[test]
    fn err_unknown_suffix() {
        assert_eq!(
            SymbolId::from_scip_string("codegraph . . . foo?"),
            Err(SymbolParseError::UnknownDescriptor)
        );
    }

    #[test]
    fn err_trailing_garbage() {
        // `auth/` parses, then `?` cannot begin a descriptor identifier.
        assert_eq!(
            SymbolId::from_scip_string("codegraph . . . auth/?"),
            Err(SymbolParseError::ExpectedIdent)
        );
    }

    #[test]
    fn err_unterminated_quote() {
        assert_eq!(
            SymbolId::from_scip_string("codegraph . . . `unclosed"),
            Err(SymbolParseError::UnterminatedQuote)
        );
    }

    #[test]
    fn fromstr_parses() {
        let id: SymbolId = "codegraph . . . auth/".parse().unwrap();
        assert_eq!(id.to_scip_string(), "codegraph . . . auth/");
    }

    #[test]
    fn stable_wire_round_trips_structural_display_collisions_and_rejects_mismatched_context() {
        let ids = [
            SymbolId::global("rust", vec![Descriptor::Term("run".into())]),
            SymbolId::global("python", vec![Descriptor::Term("run".into())]),
            SymbolId::local("src/main.rs", "x0"),
            SymbolId::local("src/lib.rs", "x0"),
        ];
        assert_eq!(ids[0].to_scip_string(), ids[1].to_scip_string());
        assert_eq!(ids[2].to_scip_string(), ids[3].to_scip_string());
        for id in ids {
            assert_eq!(SymbolId::try_from_wire(id.to_wire()).unwrap(), id);
        }
        assert!(matches!(
            SymbolId::try_from_wire(SymbolIdWire {
                version: 1,
                scip: "local x0".into(),
                lang: Some("rust".into()),
                file: None
            }),
            Err(SymbolIdWireError::LocalContext)
        ));
        assert!(matches!(
            SymbolId::try_from_wire(SymbolIdWire {
                version: 2,
                scip: "local x0".into(),
                lang: None,
                file: Some("src/main.rs".into())
            }),
            Err(SymbolIdWireError::Version(2))
        ));
    }

    #[test]
    fn clone_is_o1_both_variants() {
        // Cloning increments the Arc refcount; both variants share the same path.
        let g = SymbolId::global("rust", vec![Descriptor::Namespace("foo".into())]);
        let g2 = g.clone();
        assert_eq!(g, g2);

        let l = SymbolId::local("src/lib.rs", "x0");
        let l2 = l.clone();
        assert_eq!(l, l2);
    }
}
