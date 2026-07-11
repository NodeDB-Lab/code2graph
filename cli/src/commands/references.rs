// SPDX-License-Identifier: Apache-2.0

//! Raw extracted-reference queries, including references with no resolved edge.

use std::path::Path;

use code2graph::{RefRole, Reference};

use crate::commands::QueryCommandContext;
use crate::commands::shared::{limit, normalized_project_path, query_envelope};
use crate::result::{OccurrenceOutput, OutputEnvelope, ReferenceOutput};
use crate::{CliError, ProjectPath, Result};

pub(crate) struct ReferencesCommandRequest<'a> {
    pub file: &'a str,
    pub name: Option<&'a str>,
    pub role: Option<RefRole>,
    pub result_limit: usize,
}

/// Lists extracted facts directly; it deliberately does not consult resolution.
pub(crate) fn execute_references(
    context: &QueryCommandContext<'_>,
    request: ReferencesCommandRequest<'_>,
) -> Result<OutputEnvelope<Vec<ReferenceOutput>>> {
    context.deadline.check(context.cancellation)?;
    let file = ProjectPath::new(Path::new(request.file))?;
    let record = context
        .loaded
        .snapshot
        .files
        .iter()
        .find(|entry| normalized_project_path(&entry.path) == file.as_str())
        .ok_or(CliError::NoMatch)?;
    let mut results = record
        .facts
        .references
        .iter()
        .filter(|reference| {
            request.name.is_none_or(|name| reference.name == name)
                && request.role.is_none_or(|role| reference.role == role)
        })
        .map(reference_output)
        .collect::<Vec<_>>();
    results.sort_by(|left, right| {
        (
            left.occurrence.byte,
            left.role,
            &left.name,
            left.qualifier.as_deref().unwrap_or(""),
        )
            .cmp(&(
                right.occurrence.byte,
                right.role,
                &right.name,
                right.qualifier.as_deref().unwrap_or(""),
            ))
    });
    context.deadline.check(context.cancellation)?;
    if results.is_empty() {
        return Err(CliError::NoMatch);
    }
    let (total, truncated) = limit(&mut results, request.result_limit);
    let mut envelope = query_envelope(context.loaded, results);
    envelope.total = total;
    envelope.returned = envelope.results.len();
    envelope.truncated = truncated;
    Ok(envelope)
}

fn reference_output(reference: &Reference) -> ReferenceOutput {
    ReferenceOutput {
        name: reference.name.clone(),
        role: reference.role.into(),
        occurrence: OccurrenceOutput {
            file: normalized_project_path(&reference.occ.file),
            line: reference.occ.line,
            column: reference.occ.col,
            byte: reference.occ.byte,
        },
        source_module: reference.source_module.clone(),
        from_path: reference.from_path.clone(),
        qualifier: reference.qualifier.clone(),
        type_ref_context: reference.type_ref_ctx.map(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use code2graph::{Occurrence, TypeRefContext};

    use super::*;

    #[test]
    fn raw_reference_output_preserves_written_metadata_and_coordinates() {
        let reference = Reference {
            name: "Type".into(),
            occ: Occurrence {
                file: "src/a.rs".into(),
                line: 3,
                col: 0,
                byte: 17,
            },
            role: RefRole::TypeRef,
            source_module: Some("local module".into()),
            from_path: Some("crate::model".into()),
            qualifier: Some("outer::inner".into()),
            scope: None,
            type_ref_ctx: Some(TypeRefContext::GenericArg),
        };
        let output = reference_output(&reference);
        assert_eq!(output.name, "Type");
        assert_eq!(output.role, crate::RefRoleOutput::TypeRef);
        assert_eq!(output.occurrence.file, "src/a.rs");
        assert_eq!(output.occurrence.line, 3);
        assert_eq!(output.occurrence.column, 0);
        assert_eq!(output.occurrence.byte, 17);
        assert_eq!(output.source_module.as_deref(), Some("local module"));
        assert_eq!(output.qualifier.as_deref(), Some("outer::inner"));
        assert_eq!(output.from_path.as_deref(), Some("crate::model"));
        assert_eq!(
            output.type_ref_context,
            Some(crate::TypeRefContextOutput::GenericArg)
        );
        let json = serde_json::to_value(output).unwrap();
        assert!(json.get("confidence").is_none());
        assert_eq!(json["qualifier"], "outer::inner");
    }

    #[test]
    fn unresolved_reference_omits_only_absent_optional_metadata() {
        let output = reference_output(&Reference {
            name: "missing".into(),
            occ: Occurrence {
                file: "src//a.rs".into(),
                line: 1,
                col: 2,
                byte: 2,
            },
            role: RefRole::Call,
            source_module: None,
            from_path: None,
            qualifier: None,
            scope: None,
            type_ref_ctx: None,
        });
        let json = serde_json::to_value(output).unwrap();
        assert_eq!(json["occurrence"]["file"], "src/a.rs");
        for field in [
            "sourceModule",
            "fromPath",
            "qualifier",
            "typeRefContext",
            "confidence",
        ] {
            assert!(json.get(field).is_none(), "unexpected field {field}");
        }
    }
}
