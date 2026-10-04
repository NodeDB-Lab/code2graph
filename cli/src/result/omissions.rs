// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cache::CacheOmission;
use crate::config::DEFAULT_MAX_OMISSIONS;

use super::CacheOmissionOutput;

/// One persisted omission-reason count, ordered by its verbatim cache reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheReasonCountOutput {
    pub reason: String,
    pub count: usize,
}

/// Counts every cached omission before callers cap diagnostic entries.
pub(crate) fn cache_omission_reasons(omissions: &[CacheOmission]) -> Vec<CacheReasonCountOutput> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for omission in omissions {
        *counts.entry(&omission.reason).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| CacheReasonCountOutput {
            reason: reason.to_owned(),
            count,
        })
        .collect()
}

/// Deterministically ordered, capped view of an omission list.
///
/// Returns the reported entries (at most [`DEFAULT_MAX_OMISSIONS`]) and whether
/// entries were held back. Callers keep the full total in their own count field,
/// so capping the entry list never hides how many files were omitted.
pub fn capped_omissions(omissions: &[CacheOmission]) -> (Vec<CacheOmissionOutput>, bool) {
    let mut sorted = omissions.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        (&left.path, &left.reason, &left.detail).cmp(&(&right.path, &right.reason, &right.detail))
    });
    let truncated = sorted.len() > DEFAULT_MAX_OMISSIONS;
    sorted.truncate(DEFAULT_MAX_OMISSIONS);
    (sorted.into_iter().map(Into::into).collect(), truncated)
}
