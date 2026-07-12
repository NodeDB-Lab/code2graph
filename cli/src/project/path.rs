// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::path::{Component, Path};

use crate::error::{CliError, Result};

/// A normalized, UTF-8 project-relative source path using `/` separators.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectPath(String);

impl ProjectPath {
    /// Validates and normalizes a project-relative path.
    pub fn new(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() || path.is_absolute() {
            return Err(CliError::ProjectRelativePath {
                path: path.to_path_buf(),
                reason: "path must be nonempty and relative".into(),
            });
        }

        if contains_dot_component(path) {
            return Err(CliError::ProjectRelativePath {
                path: path.to_path_buf(),
                reason: "path may not contain '.' or '..' components".into(),
            });
        }

        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let text = part.to_str().ok_or_else(|| CliError::ProjectRelativePath {
                        path: path.to_path_buf(),
                        reason: "path must be UTF-8".into(),
                    })?;
                    parts.push(text);
                }
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return Err(CliError::ProjectRelativePath {
                        path: path.to_path_buf(),
                        reason: "path may not contain root, prefix, '.' or '..' components".into(),
                    });
                }
            }
        }
        if parts.is_empty() {
            return Err(CliError::ProjectRelativePath {
                path: path.to_path_buf(),
                reason: "path must be nonempty".into(),
            });
        }
        Ok(Self(parts.join("/")))
    }

    /// Converts canonical, contained source and project-root paths to a normalized path.
    pub fn from_canonical_source(root: &Path, source: &Path) -> Result<Self> {
        if !root.is_absolute() || !source.is_absolute() {
            return Err(CliError::ProjectRelativePath {
                path: source.to_path_buf(),
                reason: "root and source must be canonical absolute paths".into(),
            });
        }
        let relative = source
            .strip_prefix(root)
            .map_err(|_| CliError::ProjectPathOutsideRoot {
                root: root.to_path_buf(),
                path: source.to_path_buf(),
            })?;
        Self::new(relative)
    }

    /// The stable slash-separated representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(unix)]
fn contains_dot_component(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..")
}

#[cfg(windows)]
fn contains_dot_component(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;

    let mut component = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        if unit == u16::from(b'/') || unit == u16::from(b'\\') {
            if component == [u16::from(b'.')] || component == [u16::from(b'.'), u16::from(b'.')] {
                return true;
            }
            component.clear();
        } else {
            component.push(unit);
        }
    }
    component == [u16::from(b'.')] || component == [u16::from(b'.'), u16::from(b'.')]
}

#[cfg(not(any(unix, windows)))]
fn contains_dot_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

impl AsRef<str> for ProjectPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProjectPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::ProjectPath;
    use crate::error::CliError;

    #[test]
    fn normalizes_relative_paths() {
        assert_eq!(
            ProjectPath::new(Path::new("src//lib.rs")).unwrap().as_str(),
            "src/lib.rs"
        );
    }

    #[test]
    fn rejects_absolute_and_traversal_paths() {
        for path in [
            "",
            ".",
            "..",
            "src/./lib.rs",
            "src/../lib.rs",
            "/src/lib.rs",
        ] {
            assert!(matches!(
                ProjectPath::new(Path::new(path)),
                Err(CliError::ProjectRelativePath { .. })
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_prefixes_and_cross_volume_sources() {
        for path in [r"C:src\lib.rs", r"C:\src\lib.rs", r"\src\lib.rs"] {
            assert!(matches!(
                ProjectPath::new(Path::new(path)),
                Err(CliError::ProjectRelativePath { .. })
            ));
        }
        assert!(matches!(
            ProjectPath::from_canonical_source(
                Path::new(r"C:\project"),
                Path::new(r"D:\src\lib.rs"),
            ),
            Err(CliError::ProjectPathOutsideRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"src/\xff.rs".to_vec()));
        assert!(matches!(
            ProjectPath::new(&path),
            Err(CliError::ProjectRelativePath { .. })
        ));
    }

    #[test]
    fn requires_canonical_containment() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("project");
        let source = root.join("src/lib.rs");
        let outside = directory.path().join("other/lib.rs");
        assert_eq!(
            ProjectPath::from_canonical_source(&root, &source)
                .unwrap()
                .as_str(),
            "src/lib.rs"
        );
        assert!(matches!(
            ProjectPath::from_canonical_source(&root, &outside),
            Err(CliError::ProjectPathOutsideRoot { .. })
        ));
    }
}
