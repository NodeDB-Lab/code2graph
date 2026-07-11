// SPDX-License-Identifier: Apache-2.0

//! SCIP-aligned symbol descriptors.
//!
//! A symbol's identity is a sequence of descriptors that together form a fully
//! qualified name, following Sourcegraph's SCIP grammar. Each descriptor kind
//! renders with a distinct suffix so the joined string is unambiguous; the
//! rendered SCIP string is for display/interoperability, while structural
//! identity lives in `SymbolId`'s language/local-file coordinates.
//!
//! Grammar (subset we emit), from `scip.proto`:
//! ```text
//! namespace       ident '/'
//! type            ident '#'
//! term            ident '.'
//! method          ident '(' disambiguator ')' '.'
//! type-parameter  '[' ident ']'
//! parameter       '(' ident ')'
//! meta            ident ':'
//! macro           ident '!'
//! ```

/// A SCIP method overload disambiguator.
///
/// SCIP permits only a simple identifier (or an empty value) and provides no
/// escaping for this coordinate. The inner value is private so a public
/// [`Descriptor::Method`] can never be constructed with an unrenderable value.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct MethodDisambiguator(String);

impl MethodDisambiguator {
    /// The common, non-overloaded method coordinate.
    pub fn empty() -> Self {
        Self(String::new())
    }

    /// Construct a SCIP-valid overload coordinate.
    pub fn new(value: impl Into<String>) -> Result<Self, super::id::SymbolParseError> {
        let value = value.into();
        if value.chars().all(is_simple_ident_char) {
            Ok(Self(value))
        } else {
            Err(super::id::SymbolParseError::InvalidDisambiguator)
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MethodDisambiguator {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// One element of a fully-qualified symbol path.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Descriptor {
    /// A namespace / module / package segment (`ident/`).
    Namespace(String),
    /// A type: struct, class, enum, trait, interface (`ident#`).
    Type(String),
    /// A term: const, static, variable, value (`ident.`).
    Term(String),
    /// A method or free function (`ident(disambiguator).`). The `disambiguator`
    /// distinguishes overloads and **must** be a SCIP *simple-identifier* (chars
    /// per `is_simple_ident_char`) or empty: SCIP's grammar is
    /// `method-disambiguator ::= simple-identifier?` with **no escaped form**, so
    /// a non-simple disambiguator cannot be rendered to a parseable SCIP string.
    /// Empty disambiguator is the common case.
    Method {
        name: String,
        disambiguator: MethodDisambiguator,
    },
    /// A generic type parameter (`[ident]`).
    TypeParameter(String),
    /// A value parameter (`(ident)`).
    Parameter(String),
    /// Meta (e.g. a module's attribute namespace) (`ident:`).
    Meta(String),
    /// A macro (`ident!`).
    Macro(String),
}

impl Descriptor {
    /// The bare identifier this descriptor names (used for name-only matching).
    pub fn name(&self) -> &str {
        match self {
            Descriptor::Namespace(n)
            | Descriptor::Type(n)
            | Descriptor::Term(n)
            | Descriptor::TypeParameter(n)
            | Descriptor::Parameter(n)
            | Descriptor::Meta(n)
            | Descriptor::Macro(n) => n,
            Descriptor::Method { name, .. } => name,
        }
    }

    /// Append this descriptor's SCIP rendering to `out`.
    pub fn render<W: core::fmt::Write>(&self, out: &mut W) -> core::fmt::Result {
        match self {
            Descriptor::Namespace(n) => {
                push_ident(out, n)?;
                out.write_char('/')
            }
            Descriptor::Type(n) => {
                push_ident(out, n)?;
                out.write_char('#')
            }
            Descriptor::Term(n) => {
                push_ident(out, n)?;
                out.write_char('.')
            }
            Descriptor::Method {
                name,
                disambiguator,
            } => {
                push_ident(out, name)?;
                out.write_char('(')?;
                out.write_str(disambiguator.as_str())?;
                out.write_str(").")
            }
            Descriptor::TypeParameter(n) => {
                out.write_char('[')?;
                push_ident(out, n)?;
                out.write_char(']')
            }
            Descriptor::Parameter(n) => {
                out.write_char('(')?;
                push_ident(out, n)?;
                out.write_char(')')
            }
            Descriptor::Meta(n) => {
                push_ident(out, n)?;
                out.write_char(':')
            }
            Descriptor::Macro(n) => {
                push_ident(out, n)?;
                out.write_char('!')
            }
        }
    }
}

/// Render an identifier per SCIP rules: bare if it is a simple identifier,
/// otherwise backtick-escaped (backticks inside doubled).
fn push_ident<W: core::fmt::Write>(out: &mut W, ident: &str) -> core::fmt::Result {
    let simple = !ident.is_empty() && ident.chars().all(is_simple_ident_char);
    if simple {
        out.write_str(ident)
    } else {
        out.write_char('`')?;
        for c in ident.chars() {
            if c == '`' {
                out.write_char('`')?;
            }
            out.write_char(c)?;
        }
        out.write_char('`')
    }
}

/// A character is part of a *simple* (bare) identifier per SCIP rules.
fn is_simple_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '+' || c == '-' || c == '$'
}

/// Parse one identifier from the front of `s`, inverting [`push_ident`].
///
/// Handles both the bare form (a maximal run of simple chars) and the
/// backtick-quoted form (doubled `` `` `` decodes to a literal `` ` ``).
/// Returns the decoded name and the remaining slice.
pub(crate) fn parse_ident(s: &str) -> Result<(String, &str), super::id::SymbolParseError> {
    use super::id::SymbolParseError;
    if let Some(quoted) = s.strip_prefix('`') {
        // Quoted: scan char-by-char over a moving slice; a `` ` `` followed by
        // another `` ` `` is a literal backtick, a lone `` ` `` closes the ident.
        let mut name = String::new();
        let mut rest = quoted;
        loop {
            let mut chars = rest.char_indices();
            match chars.next() {
                None => return Err(SymbolParseError::UnterminatedQuote),
                Some((_, '`')) => {
                    // `chars.as_str()` is everything after this backtick.
                    let after = chars.as_str();
                    if let Some(next) = after.strip_prefix('`') {
                        // Doubled backtick → literal backtick; keep scanning.
                        name.push('`');
                        rest = next;
                    } else {
                        // Closing backtick.
                        return Ok((name, after));
                    }
                }
                Some((_, c)) => {
                    name.push(c);
                    rest = chars.as_str();
                }
            }
        }
    } else {
        // Bare: maximal run of simple chars.
        let end = s
            .char_indices()
            .find(|&(_, c)| !is_simple_ident_char(c))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        if end == 0 {
            return Err(SymbolParseError::ExpectedIdent);
        }
        let (name, rest) = s.split_at(end);
        Ok((name.to_owned(), rest))
    }
}

/// Parse one descriptor from the front of `s`, inverting [`Descriptor::render`].
///
/// Returns the descriptor and the remaining slice. Each successful call
/// consumes at least one character, so a parse loop always terminates.
pub(crate) fn parse_descriptor(s: &str) -> Result<(Descriptor, &str), super::id::SymbolParseError> {
    use super::id::SymbolParseError;
    // Structured forms first: their leading delimiter is unambiguous.
    if let Some(rest) = s.strip_prefix('[') {
        let (name, rest) = parse_ident(rest)?;
        let rest = rest
            .strip_prefix(']')
            .ok_or(SymbolParseError::UnknownDescriptor)?;
        return Ok((Descriptor::TypeParameter(name), rest));
    }
    if let Some(rest) = s.strip_prefix('(') {
        let (name, rest) = parse_ident(rest)?;
        let rest = rest
            .strip_prefix(')')
            .ok_or(SymbolParseError::UnknownDescriptor)?;
        return Ok((Descriptor::Parameter(name), rest));
    }

    // Remaining forms lead with an identifier, then a suffix char decides.
    let (name, rest) = parse_ident(s)?;
    let mut chars = rest.chars();
    match chars.next() {
        Some('(') => {
            // Method: read raw disambiguator until ')', then '.'.
            let (disambiguator, after_close) = chars
                .as_str()
                .split_once(')')
                .ok_or(SymbolParseError::UnknownDescriptor)?;
            if !disambiguator.chars().all(is_simple_ident_char) {
                return Err(SymbolParseError::InvalidDisambiguator);
            }
            let disambiguator = MethodDisambiguator::new(disambiguator.to_owned())?;
            let rest = after_close
                .strip_prefix('.')
                .ok_or(SymbolParseError::UnknownDescriptor)?;
            Ok((
                Descriptor::Method {
                    name,
                    disambiguator,
                },
                rest,
            ))
        }
        Some('/') => Ok((Descriptor::Namespace(name), chars.as_str())),
        Some('#') => Ok((Descriptor::Type(name), chars.as_str())),
        Some('.') => Ok((Descriptor::Term(name), chars.as_str())),
        Some(':') => Ok((Descriptor::Meta(name), chars.as_str())),
        Some('!') => Ok((Descriptor::Macro(name), chars.as_str())),
        _ => Err(SymbolParseError::UnknownDescriptor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scip_suffixes() {
        let mut s = String::new();
        Descriptor::Namespace("auth".into()).render(&mut s).unwrap();
        Descriptor::Method {
            name: "validate_token".into(),
            disambiguator: MethodDisambiguator::empty(),
        }
        .render(&mut s)
        .unwrap();
        assert_eq!(s, "auth/validate_token().");
    }

    #[test]
    fn escapes_non_simple_idents() {
        let mut s = String::new();
        Descriptor::Type("Foo Bar".into()).render(&mut s).unwrap();
        assert_eq!(s, "`Foo Bar`#");
    }

    #[test]
    fn method_with_nonempty_disambiguator_round_trips() {
        // A SCIP-valid (simple-identifier) overload disambiguator must survive
        // render → parse → identical descriptor. "1" is the canonical overload
        // index; this locks the disambiguator path that all extractors leave
        // empty today, so a future overload-aware extractor can't silently break
        // identity.
        let desc = Descriptor::Method {
            name: "to_string".into(),
            disambiguator: MethodDisambiguator::new("1").unwrap(),
        };
        let mut s = String::new();
        desc.render(&mut s).unwrap();
        assert_eq!(s, "to_string(1).");
        let (parsed, rest) = parse_descriptor(&s).unwrap();
        assert_eq!(parsed, desc);
        assert!(rest.is_empty(), "no trailing input, got {rest:?}");
    }
}
