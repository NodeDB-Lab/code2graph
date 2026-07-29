// SPDX-License-Identifier: Apache-2.0

//! Metadata admission budgets for discovered source candidates.

use crate::config::ResourceLimits;
use crate::inventory::{OmissionReason, OmittedFile, SourceDiscovery};

pub(crate) fn apply_metadata_budgets(discovery: &mut SourceDiscovery, limits: &ResourceLimits) {
    let mut retained = Vec::new();
    let mut total = 0usize;
    for candidate in discovery.candidates.drain(..) {
        let reason = if candidate.language.is_none() {
            None
        } else if candidate.size_bytes > limits.max_file_bytes as u64 {
            Some(OmissionReason::FileTooLarge {
                limit: limits.max_file_bytes,
            })
        } else if retained.len() >= limits.max_files {
            Some(OmissionReason::FileCountLimit {
                limit: limits.max_files,
            })
        } else if usize::try_from(candidate.size_bytes)
            .ok()
            .and_then(|size| total.checked_add(size))
            .filter(|next| *next <= limits.max_total_bytes)
            .is_none()
        {
            Some(OmissionReason::TotalBytesLimit {
                limit: limits.max_total_bytes,
            })
        } else {
            total += usize::try_from(candidate.size_bytes)
                .expect("file size was checked against the platform-sized limit");
            None
        };
        if let Some(reason) = reason {
            discovery
                .omitted
                .push(OmittedFile::new(candidate.path, reason));
        } else {
            retained.push(candidate);
        }
    }
    discovery.candidates = retained;
    discovery.omitted.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.tag().cmp(&b.reason.tag()))
    });
}
