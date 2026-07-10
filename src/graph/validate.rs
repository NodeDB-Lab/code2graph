// SPDX-License-Identifier: Apache-2.0

//! Structural validation for untrusted [`FileFacts`](super::FileFacts).

use super::FileFacts;
use crate::error::{CodegraphError, Result};

/// Reject malformed lexical-scope facts before scope-aware resolution.
/// Extractors produce valid facts; bindings call this at their deserialization
/// boundary so hostile cycles and invalid indices cannot enter traversal.
pub fn validate_file_facts(facts: &[FileFacts]) -> Result<()> {
    for file in facts {
        let malformed = |reason: String| CodegraphError::MalformedFacts {
            file: file.file.clone(),
            reason,
        };
        for (index, scope) in file.scopes.iter().enumerate() {
            if let Some(parent) = scope.parent {
                if parent >= file.scopes.len() {
                    return Err(malformed(format!(
                        "scope {index} has invalid parent {parent}"
                    )));
                }
            }
        }
        for start in 0..file.scopes.len() {
            let mut current = start;
            for _ in 0..file.scopes.len() {
                match file.scopes[current].parent {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            if file.scopes[current].parent.is_some() {
                return Err(malformed(format!("scope {start} has a parent cycle")));
            }
        }
        for reference in &file.references {
            if let Some(scope) = reference.scope {
                if scope >= file.scopes.len() {
                    return Err(malformed(format!(
                        "reference {} has invalid scope {scope}",
                        reference.name
                    )));
                }
            }
        }
        for binding in &file.bindings {
            if binding.scope >= file.scopes.len() {
                return Err(malformed(format!(
                    "binding {} has invalid scope {}",
                    binding.name, binding.scope
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{Extractor, RustExtractor};

    #[test]
    fn rejects_scope_cycles_and_invalid_indices() {
        let mut facts = RustExtractor.extract("fn run() {}", "src/a.rs").unwrap();
        facts.scopes = vec![crate::Scope {
            parent: Some(0),
            span: crate::ByteSpan { start: 0, end: 1 },
            kind: crate::ScopeKind::Module,
        }];
        assert!(validate_file_facts(&[facts]).is_err());
    }
}
