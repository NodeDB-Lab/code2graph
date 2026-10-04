// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::CliError;
use crate::cache::{CachePublicationFailure, PublicationConflict, escaped_publication_identifier};

pub(super) fn publication_error(error: CachePublicationFailure, root: &Path) -> CliError {
    match error {
        CachePublicationFailure::Cache(error) => error.into(),
        CachePublicationFailure::Conflict(conflict) => {
            CliError::Cache(render_conflict(&conflict, root))
        }
    }
}

fn render_conflict(conflict: &PublicationConflict, root: &Path) -> String {
    let mut message = format!(
        "cache candidate {} conflicts in {}",
        conflict.candidate_id,
        conflict.field.as_str(),
    );
    if let Some(file) = &conflict.file {
        message.push_str(" for file ");
        message.push_str(file);
    }
    if let Some(tier) = conflict.tier {
        message.push_str(" for tier ");
        message.push_str(tier);
    }
    message.push_str(". Selected project root: ");
    message.push_str(&escaped_publication_identifier(&root.to_string_lossy()));
    message.push_str(
        ". Run `c2g cache clear --root <selected-project-root>` with that root, then retry.",
    );
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    const IDENTIFIER_MAX_BYTES: usize = 256;

    #[test]
    fn identifiers_escape_terminal_controls_quotes_and_backslashes() {
        let rendered = escaped_publication_identifier("file\n\r\t\u{1b}\"\\");
        assert_eq!(rendered, "\"file\\n\\r\\t\\u{1b}\\\"\\\\\"");
        assert!(!rendered.chars().any(char::is_control));
    }

    #[test]
    fn escaped_expansion_and_unicode_remain_bounded() {
        for value in [
            "\u{1b}".repeat(10_000),
            "界".repeat(10_000),
            "x".repeat(256),
        ] {
            let rendered = escaped_publication_identifier(&value);
            assert!(rendered.len() <= IDENTIFIER_MAX_BYTES);
            assert!(rendered.ends_with("...\""));
            assert!(!rendered.chars().any(char::is_control));
        }
        assert_eq!(escaped_publication_identifier("short"), "\"short\"");
    }

    #[test]
    fn ordinary_errors_retain_cli_text_and_exit_code() {
        for error in [
            crate::cache::CacheError::Access,
            crate::cache::CacheError::Timeout,
            crate::cache::CacheError::ReadOnly,
        ] {
            let expected_text = error.to_string();
            let actual =
                publication_error(CachePublicationFailure::Cache(error), Path::new("/root"));
            assert_eq!(
                actual.to_string(),
                CliError::Cache(expected_text).to_string()
            );
            assert_eq!(actual.exit_code(), crate::ExitCode::Operational);
        }
    }
}
