// SPDX-License-Identifier: Apache-2.0

//! Domain-separated, unambiguous cache compatibility identities.

use std::fmt;
use std::str::FromStr;

use code2graph::{
    CODE_GRAPH_SCHEMA_VERSION, FILE_FACTS_SCHEMA_VERSION, Language, LanguageAvailability,
};

use super::types::{CacheOmission, CandidateCompleteness};

/// Manual cache compatibility epoch for unreleased (`0.0.0`) workspace builds.
/// Bump this when cache-affecting behavior changes without a crate version change.
pub const CACHE_IMPLEMENTATION_EPOCH: u32 = 2;

macro_rules! fingerprint {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);
        impl $name {
            /// Raw fixed-width cache key bytes for SQLite storage.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Restores a fingerprint read from a schema-checked 32-byte key.
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            fn digest(parts: impl IntoIterator<Item = Vec<u8>>) -> Self {
                let mut hasher = blake3::Hasher::new();
                hasher.update(concat!("code2graph.cache.", stringify!($name), ".v1\0").as_bytes());
                for part in parts {
                    put(&mut hasher, &part);
                }
                Self(*hasher.finalize().as_bytes())
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
        impl FromStr for $name {
            type Err = &'static str;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 64 {
                    return Err("fingerprint must be 64 lowercase hexadecimal characters");
                }
                let mut bytes = [0; 32];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    let offset = index * 2;
                    let pair = &value[offset..offset + 2];
                    if pair
                        .bytes()
                        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
                    {
                        return Err("fingerprint must be lowercase hexadecimal");
                    }
                    *slot = u8::from_str_radix(pair, 16)
                        .map_err(|_| "invalid hexadecimal fingerprint")?;
                }
                Ok(Self(bytes))
            }
        }
    };
}

fingerprint!(LanguageFeatureFingerprint);
fingerprint!(PackageFingerprint);
fingerprint!(CompatibilityFingerprint);
fingerprint!(ProjectInputDigest);
fingerprint!(CandidateId);

impl LanguageFeatureFingerprint {
    /// Hash the complete enabled language set and explicit extractor epoch tags.
    pub fn current() -> Self {
        Self::from_languages(
            Language::ALL
                .iter()
                .copied()
                .filter(|language| language.availability() == LanguageAvailability::Enabled),
        )
    }

    fn from_languages(languages: impl IntoIterator<Item = Language>) -> Self {
        let mut tags: Vec<Vec<u8>> = languages
            .into_iter()
            .map(|language| format!("{}:extractor-epoch-1", language.as_str()).into_bytes())
            .collect();
        tags.sort();
        Self::digest(tags)
    }
}

impl PackageFingerprint {
    /// Hash caller-supplied normalized package inputs.
    ///
    /// Each item must be a complete canonical record. Prefer [`Self::from_selection`]
    /// when manifest inputs and per-source assignments are available separately.
    pub fn from_normalized<I, S>(inputs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut values: Vec<Vec<u8>> = inputs
            .into_iter()
            .map(|value| value.as_ref().as_bytes().to_vec())
            .collect();
        values.sort();
        Self::digest(values)
    }

    /// Hash normalized manifest inputs and per-source package assignments as distinct domains.
    ///
    /// Inputs are independently sorted; each domain tag and every field are
    /// length-prefixed before hashing, so manifest failures and `none`
    /// assignments are compatibility-significant without exposing source text.
    pub fn from_selection<MI, MS, PI, PS>(manifest_inputs: MI, selected_assignments: PI) -> Self
    where
        MI: IntoIterator<Item = MS>,
        MS: AsRef<str>,
        PI: IntoIterator<Item = PS>,
        PS: AsRef<str>,
    {
        let mut values = Vec::new();
        for input in manifest_inputs {
            let mut row = b"manifest-input".to_vec();
            append(&mut row, input.as_ref().as_bytes());
            values.push(row);
        }
        for assignment in selected_assignments {
            let mut row = b"source-assignment".to_vec();
            append(&mut row, assignment.as_ref().as_bytes());
            values.push(row);
        }
        values.sort();
        Self::digest(values)
    }
}

impl CompatibilityFingerprint {
    /// Compatibility identity for code and caller-selected package context.
    pub fn new(language: LanguageFeatureFingerprint, package: PackageFingerprint) -> Self {
        Self::digest(vec![
            env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
            CACHE_IMPLEMENTATION_EPOCH.to_le_bytes().to_vec(),
            FILE_FACTS_SCHEMA_VERSION.to_le_bytes().to_vec(),
            code2graph::FILE_SUBGRAPH_SCHEMA_VERSION
                .to_le_bytes()
                .to_vec(),
            CODE_GRAPH_SCHEMA_VERSION.to_le_bytes().to_vec(),
            language.0.to_vec(),
            package.0.to_vec(),
        ])
    }
}

impl ProjectInputDigest {
    /// Hash sorted `(path, language, content-hash)` tuples, preserving same-size changes.
    pub fn from_inputs<I, P, L, H>(inputs: I) -> Self
    where
        I: IntoIterator<Item = (P, L, H)>,
        P: AsRef<str>,
        L: AsRef<str>,
        H: AsRef<[u8]>,
    {
        let mut rows: Vec<Vec<u8>> = inputs
            .into_iter()
            .map(|(path, language, content)| {
                let mut row = Vec::new();
                append(&mut row, path.as_ref().as_bytes());
                append(&mut row, language.as_ref().as_bytes());
                append(&mut row, content.as_ref());
                row
            })
            .collect();
        rows.sort();
        Self::digest(rows)
    }
}

impl CandidateId {
    /// Include completeness and all canonical partial omissions in the identity.
    pub fn new(
        compatibility: CompatibilityFingerprint,
        input: ProjectInputDigest,
        completeness: CandidateCompleteness,
        omissions: &[CacheOmission],
    ) -> Self {
        let mut rows: Vec<Vec<u8>> = omissions
            .iter()
            .map(|omission| {
                let mut row = Vec::new();
                append(&mut row, omission.path.as_bytes());
                append(&mut row, omission.reason.as_bytes());
                append(&mut row, omission.detail.as_bytes());
                row
            })
            .collect();
        rows.sort();
        let state = match completeness {
            CandidateCompleteness::Complete => b"complete".to_vec(),
            CandidateCompleteness::Partial => b"partial".to_vec(),
        };
        let mut parts = vec![compatibility.0.to_vec(), input.0.to_vec(), state];
        parts.extend(rows);
        Self::digest(parts)
    }
}

fn put(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}
fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_order_independent_and_length_prefixed() {
        let left = ProjectInputDigest::from_inputs([("a", "bc", [1_u8]), ("ab", "c", [2])]);
        let right = ProjectInputDigest::from_inputs([("ab", "c", [2_u8]), ("a", "bc", [1])]);
        let ambiguous = ProjectInputDigest::from_inputs([("ab", "c", [1_u8]), ("a", "bc", [2])]);
        assert_eq!(left, right);
        assert_ne!(left, ambiguous);
    }

    #[test]
    fn same_size_content_and_compatibility_inputs_change_identities() {
        let old = ProjectInputDigest::from_inputs([("src/a.rs", "rust", b"one".as_slice())]);
        let new = ProjectInputDigest::from_inputs([("src/a.rs", "rust", b"two".as_slice())]);
        assert_ne!(old, new);
        let package_a = PackageFingerprint::from_normalized(["Cargo.toml:one"]);
        let package_b = PackageFingerprint::from_normalized(["Cargo.toml:two"]);
        assert_ne!(
            CompatibilityFingerprint::new(LanguageFeatureFingerprint::current(), package_a),
            CompatibilityFingerprint::new(LanguageFeatureFingerprint::current(), package_b)
        );
    }

    #[test]
    fn package_selection_is_sorted_and_domain_separated() {
        let first = PackageFingerprint::from_selection(
            ["Cargo.lock:abc", "Cargo.toml:def"],
            ["workspace:a", "workspace:b"],
        );
        let reordered = PackageFingerprint::from_selection(
            ["Cargo.toml:def", "Cargo.lock:abc"],
            ["workspace:b", "workspace:a"],
        );
        let category_swapped = PackageFingerprint::from_selection(
            ["workspace:a", "workspace:b"],
            ["Cargo.lock:abc", "Cargo.toml:def"],
        );
        assert_eq!(first, reordered);
        assert_ne!(first, category_swapped);
    }

    #[test]
    fn package_fingerprint_changes_for_each_canonical_input_domain() {
        let baseline =
            PackageFingerprint::from_selection(["Cargo.toml:hash-a"], ["src/a.rs:Cargo.toml"]);
        let manifest_changed =
            PackageFingerprint::from_selection(["Cargo.toml:hash-b"], ["src/a.rs:Cargo.toml"]);
        let assignment_changed =
            PackageFingerprint::from_selection(["Cargo.toml:hash-a"], ["src/a.rs:none"]);
        assert_ne!(baseline, manifest_changed);
        assert_ne!(baseline, assignment_changed);
    }

    #[test]
    fn current_language_fingerprint_contains_exactly_all_enabled_tags() {
        let enabled = Language::ALL
            .iter()
            .copied()
            .filter(|language| language.availability() == LanguageAvailability::Enabled);
        assert_eq!(
            LanguageFeatureFingerprint::current(),
            LanguageFeatureFingerprint::from_languages(enabled)
        );
    }

    #[test]
    fn candidates_distinguish_complete_partial_and_omissions() {
        let input = ProjectInputDigest::from_inputs([("a", "rust", [1_u8])]);
        let compatibility = CompatibilityFingerprint::new(
            LanguageFeatureFingerprint::current(),
            PackageFingerprint::from_normalized(["test"]),
        );
        let complete = CandidateId::new(compatibility, input, CandidateCompleteness::Complete, &[]);
        let partial = CandidateId::new(compatibility, input, CandidateCompleteness::Partial, &[]);
        let omitted = CandidateId::new(
            compatibility,
            input,
            CandidateCompleteness::Partial,
            &[CacheOmission {
                path: "a".into(),
                reason: "too-large".into(),
                detail: "limit=1".into(),
            }],
        );
        assert_ne!(complete, partial);
        assert_ne!(partial, omitted);

        let first = CandidateId::new(
            compatibility,
            input,
            CandidateCompleteness::Partial,
            &[
                CacheOmission {
                    path: "a".into(),
                    reason: "bc".into(),
                    detail: "detail".into(),
                },
                CacheOmission {
                    path: "ab".into(),
                    reason: "c".into(),
                    detail: "detail".into(),
                },
            ],
        );
        let reordered = CandidateId::new(
            compatibility,
            input,
            CandidateCompleteness::Partial,
            &[
                CacheOmission {
                    path: "ab".into(),
                    reason: "c".into(),
                    detail: "detail".into(),
                },
                CacheOmission {
                    path: "a".into(),
                    reason: "bc".into(),
                    detail: "detail".into(),
                },
            ],
        );
        let ambiguous_without_prefixes = CandidateId::new(
            compatibility,
            input,
            CandidateCompleteness::Partial,
            &[CacheOmission {
                path: "abc".into(),
                reason: "".into(),
                detail: "detail".into(),
            }],
        );
        assert_eq!(first, reordered);
        assert_ne!(first, ambiguous_without_prefixes);

        let other_compatibility = CompatibilityFingerprint::new(
            LanguageFeatureFingerprint::current(),
            PackageFingerprint::from_normalized(["other"]),
        );
        assert_ne!(
            complete,
            CandidateId::new(
                other_compatibility,
                input,
                CandidateCompleteness::Complete,
                &[],
            )
        );
    }

    #[test]
    fn fingerprint_display_round_trips_lowercase_and_feature_sets_change() {
        let value = LanguageFeatureFingerprint::current();
        assert_eq!(
            value
                .to_string()
                .parse::<LanguageFeatureFingerprint>()
                .expect("parse"),
            value
        );
        assert_ne!(
            LanguageFeatureFingerprint::from_languages([Language::Rust]),
            LanguageFeatureFingerprint::from_languages([Language::Rust, Language::Python])
        );
    }
}
