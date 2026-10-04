// SPDX-License-Identifier: Apache-2.0

use super::*;

struct CorruptPublishedFacts {
    database: std::path::PathBuf,
}

impl PublicationHook for CorruptPublishedFacts {
    fn before_publish(&self) -> Result<()> {
        let connection = rusqlite::Connection::open(&self.database)
            .map_err(|error| CliError::Index(error.to_string()))?;
        connection
            .execute(
                "UPDATE candidate_files SET file_facts = X'736563726574'",
                [],
            )
            .map_err(|error| CliError::Index(error.to_string()))?;
        Ok(())
    }
}

#[test]
fn publication_conflict_reaches_refresh_with_selected_root_and_recovery_command() {
    let (temp, selection) = project("fn secret_source() {}\n");
    let limits = ResourceLimits::default();
    let deadline = Deadline::new(None);
    let store = store(&temp, &selection);
    let first = prepare_and_publish_with(
        &Extractor,
        &store,
        inputs(&selection, &limits, &deadline),
        false,
    )
    .expect("initial publication");
    let location = CacheLocation::for_project(Some(temp.path()), &selection.canonical_root)
        .expect("cache location");
    let result = prepare_and_publish_with_hook(
        &Extractor,
        &store,
        inputs(&selection, &limits, &deadline),
        false,
        &CorruptPublishedFacts {
            database: location.database_path,
        },
    );
    let Err(CliError::Cache(message)) = result else {
        panic!("expected refresh publication conflict");
    };
    assert!(message.contains(&first.loaded.candidate_id.to_string()));
    assert!(message.contains("file_facts for file \"a.rs\""));
    assert!(
        message.contains(&crate::cache::escaped_publication_identifier(
            &selection.canonical_root.to_string_lossy(),
        ))
    );
    assert!(message.contains("c2g cache clear --root <selected-project-root>"));
    assert!(!message.contains("secret"));
    assert!(!message.contains("UPDATE"));
    assert!(!message.contains("--all"));
}
