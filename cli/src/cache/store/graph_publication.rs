// SPDX-License-Identifier: Apache-2.0

use super::{
    CacheError, CachePublicationFailure, CacheStore, Deadline, PreparedGraph, PublicationField,
    map_sqlite_error,
};

impl CacheStore {
    pub(super) fn verify_existing_graph(
        &self,
        candidate_id: [u8; 32],
        snapshot_id: i64,
        graph: &PreparedGraph,
        deadline: &Deadline,
    ) -> Result<(), CachePublicationFailure> {
        let stored_symbols =
            self.load_graph_payloads(snapshot_id, "graph_symbols", "symbol", deadline)?;
        // Edges have no serialized copy to compare, so compare the identity the
        // columns carry: `edge_key` is the lossless edge identity and
        // `confidence` is the one attribute it deliberately excludes.
        let stored_edges =
            self.load_graph_payloads(snapshot_id, "graph_edges", "edge_key", deadline)?;
        let stored_confidence =
            self.load_graph_text(snapshot_id, "graph_edges", "confidence", deadline)?;
        for (differs, field) in [
            (
                stored_symbols.len() != graph.symbols.len()
                    || stored_symbols
                        .iter()
                        .zip(&graph.symbols)
                        .any(|(stored, row)| *stored != row.payload),
                PublicationField::GraphSymbols,
            ),
            (
                stored_edges.len() != graph.edges.len()
                    || stored_edges
                        .iter()
                        .zip(&graph.edges)
                        .any(|(stored, row)| *stored != row.edge_key),
                PublicationField::GraphEdges,
            ),
            (
                stored_confidence.len() != graph.edges.len()
                    || stored_confidence
                        .iter()
                        .zip(&graph.edges)
                        .any(|(stored, row)| *stored != row.confidence),
                PublicationField::GraphConfidence,
            ),
        ] {
            if differs {
                return Err(CachePublicationFailure::conflict(
                    candidate_id,
                    field,
                    None,
                    Some(graph.tier),
                ));
            }
        }
        Ok(())
    }

    fn load_graph_payloads(
        &self,
        snapshot_id: i64,
        table: &str,
        column: &str,
        deadline: &Deadline,
    ) -> Result<Vec<Vec<u8>>, CacheError> {
        let sql =
            format!("SELECT {column} FROM {table} WHERE snapshot_id = ?1 ORDER BY ordinal ASC");
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| map_sqlite_error(error, deadline))?;
        statement
            .query_map([snapshot_id], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| map_sqlite_error(error, deadline))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_sqlite_error(error, deadline))
    }

    fn load_graph_text(
        &self,
        snapshot_id: i64,
        table: &str,
        column: &str,
        deadline: &Deadline,
    ) -> Result<Vec<String>, CacheError> {
        let sql =
            format!("SELECT {column} FROM {table} WHERE snapshot_id = ?1 ORDER BY ordinal ASC");
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| map_sqlite_error(error, deadline))?;
        statement
            .query_map([snapshot_id], |row| row.get::<_, String>(0))
            .map_err(|error| map_sqlite_error(error, deadline))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_sqlite_error(error, deadline))
    }
}
