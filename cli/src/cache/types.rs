// SPDX-License-Identifier: Apache-2.0

//! Cache identity input types.

/// Whether an indexed candidate represents every discovered input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateCompleteness {
    Complete,
    Partial,
}

/// A canonical omission included in a partial candidate identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheOmission {
    pub path: String,
    pub reason: String,
}
