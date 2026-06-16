// SPDX-License-Identifier: Apache-2.0

//! SCIP-aligned symbol descriptors.
//!
//! A symbol's identity is a sequence of descriptors that together form a fully
//! qualified name, following Sourcegraph's SCIP grammar. Each descriptor kind
//! renders with a distinct suffix so the joined string is unambiguous and
//! cross-file matching is string equality (no separate resolution join).
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
    /// A method or free function (`ident(disambiguator).`). Empty disambiguator is common.
    Method { name: String, disambiguator: String },
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
                out.write_str(disambiguator)?;
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
            let disambiguator = disambiguator.to_owned();
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
            disambiguator: String::new(),
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
}
