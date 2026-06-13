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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Descriptor {
    /// A namespace / module / package segment (`ident/`).
    Namespace(String),
    /// A type: struct, class, enum, trait, interface (`ident#`).
    Type(String),
    /// A term: const, static, variable, value (`ident.`).
    Term(String),
    /// A method or free function (`ident(disambiguator).`). Empty disambiguator is common.
    Method {
        name: String,
        disambiguator: String,
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
    pub fn render(&self, out: &mut String) {
        match self {
            Descriptor::Namespace(n) => {
                push_ident(out, n);
                out.push('/');
            }
            Descriptor::Type(n) => {
                push_ident(out, n);
                out.push('#');
            }
            Descriptor::Term(n) => {
                push_ident(out, n);
                out.push('.');
            }
            Descriptor::Method {
                name,
                disambiguator,
            } => {
                push_ident(out, name);
                out.push('(');
                out.push_str(disambiguator);
                out.push_str(").");
            }
            Descriptor::TypeParameter(n) => {
                out.push('[');
                push_ident(out, n);
                out.push(']');
            }
            Descriptor::Parameter(n) => {
                out.push('(');
                push_ident(out, n);
                out.push(')');
            }
            Descriptor::Meta(n) => {
                push_ident(out, n);
                out.push(':');
            }
            Descriptor::Macro(n) => {
                push_ident(out, n);
                out.push('!');
            }
        }
    }
}

/// Render an identifier per SCIP rules: bare if it is a simple identifier,
/// otherwise backtick-escaped (backticks inside doubled).
fn push_ident(out: &mut String, ident: &str) {
    let simple = !ident.is_empty()
        && ident
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '+' || c == '-' || c == '$');
    if simple {
        out.push_str(ident);
    } else {
        out.push('`');
        for c in ident.chars() {
            if c == '`' {
                out.push('`');
            }
            out.push(c);
        }
        out.push('`');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scip_suffixes() {
        let mut s = String::new();
        Descriptor::Namespace("auth".into()).render(&mut s);
        Descriptor::Method {
            name: "validate_token".into(),
            disambiguator: String::new(),
        }
        .render(&mut s);
        assert_eq!(s, "auth/validate_token().");
    }

    #[test]
    fn escapes_non_simple_idents() {
        let mut s = String::new();
        Descriptor::Type("Foo Bar".into()).render(&mut s);
        assert_eq!(s, "`Foo Bar`#");
    }
}
