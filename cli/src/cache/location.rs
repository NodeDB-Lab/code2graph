// SPDX-License-Identifier: Apache-2.0

//! Cache paths isolated from project trees.

use std::fmt;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Stable, opaque identity for a canonical project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectKey([u8; 32]);

impl ProjectKey {
    /// The opaque bytes persisted with the cache partition identity.
    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Hash a canonical native path without converting it to lossy text.
    pub fn from_canonical_root(root: &Path) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"code2graph.cache.project-key.v1\0");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            hasher.update(b"unix\0");
            write_part(&mut hasher, root.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            hasher.update(b"windows-utf16le\0");
            let mut bytes = Vec::new();
            for unit in root.as_os_str().encode_wide() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            write_part(&mut hasher, &bytes);
        }
        #[cfg(not(any(unix, windows)))]
        {
            hasher.update(b"rust-osstr-encoded-bytes\0");
            write_part(&mut hasher, root.as_os_str().as_encoded_bytes());
        }
        Self(*hasher.finalize().as_bytes())
    }
}

impl fmt::Display for ProjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The external on-disk location assigned to one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheLocation {
    pub project_key: ProjectKey,
    pub directory: PathBuf,
    pub database_path: PathBuf,
}

impl CacheLocation {
    /// The parent directory holding every project's cache, independent of any
    /// specific project. Resolves to `<base>/projects` where `<base>` is the
    /// injected base or the OS cache directory.
    pub fn projects_root(cache_base: Option<&Path>) -> Option<PathBuf> {
        let base = match cache_base {
            Some(base) => base.to_path_buf(),
            None => ProjectDirs::from("org", "code2graph", "code2graph")?
                .cache_dir()
                .to_path_buf(),
        };
        Some(base.join("projects"))
    }

    /// Select an injected base or the OS cache directory; this never places data in `root`.
    pub fn for_project(cache_base: Option<&Path>, canonical_root: &Path) -> Option<Self> {
        let key = ProjectKey::from_canonical_root(canonical_root);
        let directory = Self::projects_root(cache_base)?.join(key.to_string());
        let database_path = directory.join("cache.sqlite3");
        Some(Self {
            project_key: key,
            directory,
            database_path,
        })
    }
}

fn write_part(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_base_is_outside_the_project_and_stable() {
        let root = Path::new("/canonical/project");
        let base = Path::new("/external/cache");
        let first = CacheLocation::for_project(Some(base), root).expect("injected base");
        let second = CacheLocation::for_project(Some(base), root).expect("injected base");
        assert_eq!(first, second);
        assert!(first.database_path.starts_with(base));
        assert!(!first.database_path.starts_with(root));
        assert!(
            first
                .project_key
                .to_string()
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn distinct_roots_have_distinct_keys() {
        assert_ne!(
            ProjectKey::from_canonical_root(Path::new("/canonical/a")),
            ProjectKey::from_canonical_root(Path::new("/canonical/b"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_key_preserves_non_utf8_native_path_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let non_utf8 = Path::new(OsStr::from_bytes(b"/canonical/\xff"));
        let replacement = Path::new("/canonical/\u{fffd}");
        assert_ne!(
            ProjectKey::from_canonical_root(non_utf8),
            ProjectKey::from_canonical_root(replacement)
        );
    }
}
