// SPDX-License-Identifier: Apache-2.0

use rusqlite::{OptionalExtension, params};

use super::{
    CacheError, CachePublicationFailure, CacheStore, CandidateId, Deadline, PreparedCandidate,
    PublicationField, ensure_time, map_sqlite_error,
};

#[derive(Debug)]
struct CandidateFileRow {
    language: String,
    content_hash: Vec<u8>,
    size_bytes: i64,
    mtime_seconds: Option<i64>,
    mtime_nanoseconds: Option<i64>,
    package_assignment: String,
    file_facts: Vec<u8>,
    file_subgraph: Option<Vec<u8>>,
}

impl CacheStore {
    pub(super) fn verify_existing_candidate(
        &self,
        candidate: &PreparedCandidate,
        deadline: &Deadline,
    ) -> Result<(), CachePublicationFailure> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT count(*) FROM candidate_files WHERE candidate_id = ?1",
                [candidate.candidate_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| map_sqlite_error(error, deadline))?;
        if count
            != i64::try_from(candidate.files.len()).map_err(|_| CacheError::InvalidCandidate)?
        {
            return Err(CachePublicationFailure::conflict(
                candidate.candidate_id,
                PublicationField::FileCount,
                None,
                None,
            ));
        }
        let omissions =
            self.load_omissions(CandidateId::from_bytes(candidate.candidate_id), deadline)?;
        if omissions != candidate.omissions {
            return Err(CachePublicationFailure::conflict(
                candidate.candidate_id,
                PublicationField::Omissions,
                None,
                None,
            ));
        }
        let mut update_mtime = self.connection.prepare(
            "UPDATE candidate_files SET mtime_seconds = ?1, mtime_nanoseconds = ?2 WHERE candidate_id = ?3 AND path = ?4",
        ).map_err(|error| map_sqlite_error(error, deadline))?;
        for file in &candidate.files {
            ensure_time(deadline)?;
            let found: Option<CandidateFileRow> = self
                .connection
                .query_row(
                    "SELECT language, content_hash, size_bytes, mtime_seconds, mtime_nanoseconds, package_assignment, file_facts, file_subgraph FROM candidate_files WHERE candidate_id = ?1 AND path = ?2",
                    params![candidate.candidate_id.as_slice(), file.path],
                    |row| {
                        Ok(CandidateFileRow {
                            language: row.get(0)?,
                            content_hash: row.get(1)?,
                            size_bytes: row.get(2)?,
                            mtime_seconds: row.get(3)?,
                            mtime_nanoseconds: row.get(4)?,
                            package_assignment: row.get(5)?,
                            file_facts: row.get(6)?,
                            file_subgraph: row.get(7)?,
                        })
                    },
                )
                .optional()
                .map_err(|error| map_sqlite_error(error, deadline))?;
            let Some(found) = found else {
                return Err(CachePublicationFailure::conflict(
                    candidate.candidate_id,
                    PublicationField::FilePresence,
                    Some(&file.path),
                    None,
                ));
            };
            for (differs, field) in [
                (found.language != file.language, PublicationField::Language),
                (
                    found.content_hash != file.content_hash,
                    PublicationField::ContentHash,
                ),
                (
                    found.size_bytes != file.size_bytes,
                    PublicationField::SizeBytes,
                ),
                (
                    found.package_assignment != file.package_assignment,
                    PublicationField::PackageAssignment,
                ),
                (found.file_facts != file.facts, PublicationField::FileFacts),
            ] {
                if differs {
                    return Err(CachePublicationFailure::conflict(
                        candidate.candidate_id,
                        field,
                        Some(&file.path),
                        None,
                    ));
                }
            }
            match (found.file_subgraph, &file.subgraph) {
                (None, Some(subgraph)) => {
                    self.connection.execute(
                        "UPDATE candidate_files SET file_subgraph = ?1 WHERE candidate_id = ?2 AND path = ?3 AND file_subgraph IS NULL",
                        params![subgraph, candidate.candidate_id.as_slice(), file.path],
                    ).map_err(|error| map_sqlite_error(error, deadline))?;
                }
                (Some(stored), Some(incoming)) if stored != *incoming => {
                    return Err(CachePublicationFailure::conflict(
                        candidate.candidate_id,
                        PublicationField::FileSubgraph,
                        Some(&file.path),
                        None,
                    ));
                }
                _ => {}
            }
            if found.mtime_seconds != file.mtime_seconds
                || found.mtime_nanoseconds != file.mtime_nanoseconds
            {
                update_mtime
                    .execute(params![
                        file.mtime_seconds,
                        file.mtime_nanoseconds,
                        candidate.candidate_id.as_slice(),
                        file.path,
                    ])
                    .map_err(|error| map_sqlite_error(error, deadline))?;
            }
        }
        Ok(())
    }
}
