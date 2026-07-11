// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{CliError, Result};
use crate::request::{CliRequest, CommandRequest};

use super::manifest::has_marker;

/// Why a project root was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionProvenance {
    RootArgument,
    IndexDirectory,
    IndexFileManifest,
    IndexFileParent,
    CurrentDirectory,
}

/// An owned canonical project root and the optional canonical index source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSelection {
    pub canonical_root: PathBuf,
    pub canonical_source: Option<PathBuf>,
    pub provenance: SelectionProvenance,
}

/// Selects a project without consulting the process working directory.
///
/// `cwd` must be an existing absolute directory. Relative `--root` and index
/// paths are resolved against it, so callers retain full control over I/O context.
/// An explicit index file may be outside `cwd`; marker discovery climbs from its
/// parent through the filesystem root.
pub fn select_project(request: &CliRequest, cwd: &Path) -> Result<ProjectSelection> {
    let cwd = validated_cwd(cwd)?;

    if let Some(root) = &request.global.root {
        return select_directory(root, &cwd, SelectionProvenance::RootArgument);
    }

    if let CommandRequest::Index {
        path: Some(path), ..
    } = &request.command
    {
        let path = absolute_path(path, &cwd.canonical);
        validate_no_symlinks(&path, &cwd.lexical)?;
        let metadata = fs::metadata(&path).map_err(|error| CliError::ProjectPath {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        if metadata.is_dir() {
            return selection(
                path,
                None,
                SelectionProvenance::IndexDirectory,
                &cwd.lexical,
            );
        }
        if metadata.is_file() {
            let source = canonicalize(&path)?;
            let parent = source.parent().ok_or_else(|| CliError::ProjectPath {
                path: source.clone(),
                reason: "file has no parent directory".into(),
            })?;
            let (root, provenance) = nearest_marker(parent)
                .unwrap_or((parent.to_path_buf(), SelectionProvenance::IndexFileParent));
            return selection(root, Some(source), provenance, &cwd.lexical);
        }
        return Err(CliError::ProjectPath {
            path,
            reason: "index path must be a regular file or directory".into(),
        });
    }

    select_directory(&cwd.canonical, &cwd, SelectionProvenance::CurrentDirectory)
}

struct ValidatedCwd {
    /// The caller-provided spelling establishes which strict ancestors are trusted aliases.
    lexical: PathBuf,
    canonical: PathBuf,
}

fn select_directory(
    path: &Path,
    cwd: &ValidatedCwd,
    provenance: SelectionProvenance,
) -> Result<ProjectSelection> {
    let path = absolute_path(path, &cwd.canonical);
    validate_no_symlinks(&path, &cwd.lexical)?;
    let metadata = fs::metadata(&path).map_err(|error| CliError::ProjectPath {
        path: path.clone(),
        reason: error.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(CliError::ProjectPath {
            path,
            reason: "project root must be an existing directory".into(),
        });
    }
    selection(path, None, provenance, &cwd.lexical)
}

fn validated_cwd(cwd: &Path) -> Result<ValidatedCwd> {
    if !cwd.is_absolute() {
        return Err(CliError::ProjectPath {
            path: cwd.to_path_buf(),
            reason: "cwd must be absolute".into(),
        });
    }
    let metadata = fs::metadata(cwd).map_err(|error| CliError::ProjectPath {
        path: cwd.to_path_buf(),
        reason: error.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(CliError::ProjectPath {
            path: cwd.to_path_buf(),
            reason: "cwd must be an existing directory".into(),
        });
    }
    validate_no_symlinks(cwd, cwd)?;
    Ok(ValidatedCwd {
        lexical: cwd.to_path_buf(),
        canonical: canonicalize(cwd)?,
    })
}

fn absolute_path(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn selection(
    root: PathBuf,
    canonical_source: Option<PathBuf>,
    provenance: SelectionProvenance,
    trusted_cwd: &Path,
) -> Result<ProjectSelection> {
    validate_no_symlinks(&root, trusted_cwd)?;
    let canonical_root = canonicalize(&root)?;
    if let Some(source) = &canonical_source
        && !source.starts_with(&canonical_root)
    {
        return Err(CliError::ProjectPath {
            path: source.clone(),
            reason: "canonical index source is outside the selected project root".into(),
        });
    }
    Ok(ProjectSelection {
        canonical_root,
        canonical_source,
        provenance,
    })
}

fn nearest_marker(start: &Path) -> Option<(PathBuf, SelectionProvenance)> {
    let mut candidate = Some(start);
    while let Some(directory) = candidate {
        if has_marker(directory) {
            return Some((
                directory.to_path_buf(),
                SelectionProvenance::IndexFileManifest,
            ));
        }
        candidate = directory.parent();
    }
    None
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|error| CliError::ProjectPath {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn validate_no_symlinks(path: &Path, trusted_cwd: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(CliError::ProjectPath {
            path: path.to_path_buf(),
            reason: "path must be absolute before symlink validation".into(),
        });
    }
    let mut component_path = PathBuf::new();
    for component in path.components() {
        component_path.push(component.as_os_str());
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }
        let metadata =
            fs::symlink_metadata(&component_path).map_err(|error| CliError::ProjectPath {
                path: component_path.clone(),
                reason: error.to_string(),
            })?;
        if metadata.file_type().is_symlink()
            && (component_path == path || !is_trusted_cwd_ancestor(&component_path, trusted_cwd))
        {
            return Err(CliError::ProjectSymlink {
                path: component_path,
            });
        }
    }
    Ok(())
}

/// macOS exposes `/var` as a platform-owned alias for `/private/var`.
/// It is trusted only when it is a strict lexical ancestor of the caller's cwd;
/// every user-controlled alias, the cwd itself, and selected descendants remain
/// subject to the no-symlink policy.
fn is_trusted_cwd_ancestor(component_path: &Path, trusted_cwd: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        component_path == Path::new("/var")
            && component_path != trusted_cwd
            && trusted_cwd.starts_with(component_path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (component_path, trusted_cwd);
        false
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    #[cfg(target_os = "macos")]
    use super::is_trusted_cwd_ancestor;
    use super::{SelectionProvenance, select_project};
    use crate::config::GlobalOptions;
    use crate::error::CliError;
    use crate::request::{CliRequest, CommandRequest};

    fn request(root: Option<&Path>, path: Option<&Path>) -> CliRequest {
        CliRequest {
            global: GlobalOptions {
                root: root.map(Path::to_path_buf),
                ..GlobalOptions::default()
            },
            command: CommandRequest::Index {
                path: path.map(Path::to_path_buf),
                force: false,
                trust_mtime: false,
            },
        }
    }

    #[test]
    fn root_has_precedence_and_never_climbs() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("explicit");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("directories");
        fs::write(root.join("Cargo.toml"), "").expect("manifest");
        let source = nested.join("main.rs");
        fs::write(&source, "").expect("source");
        let selection =
            select_project(&request(Some(&nested), Some(&source)), directory.path()).unwrap();
        assert_eq!(selection.canonical_root, fs::canonicalize(&nested).unwrap());
        assert_eq!(selection.provenance, SelectionProvenance::RootArgument);
    }

    #[test]
    fn file_selects_nearest_marker_or_its_parent() {
        let directory = tempdir().expect("temporary directory");
        let project = directory.path().join("project");
        let nested = project.join("src/deep");
        fs::create_dir_all(&nested).expect("directories");
        fs::write(project.join("package.json"), "{}").expect("manifest");
        let source = nested.join("main.ts");
        fs::write(&source, "").expect("source");
        let selection = select_project(&request(None, Some(&source)), directory.path()).unwrap();
        assert_eq!(
            selection.canonical_root,
            fs::canonicalize(&project).unwrap()
        );
        assert_eq!(selection.provenance, SelectionProvenance::IndexFileManifest);
        assert_eq!(
            selection.canonical_source,
            Some(fs::canonicalize(&source).unwrap())
        );

        let manifest_selection = select_project(
            &request(None, Some(&project.join("package.json"))),
            directory.path(),
        )
        .unwrap();
        assert_eq!(
            manifest_selection.canonical_root,
            fs::canonicalize(&project).unwrap()
        );
        assert_eq!(
            manifest_selection.provenance,
            SelectionProvenance::IndexFileManifest
        );

        let isolated = directory.path().join("isolated/file.rs");
        fs::create_dir_all(isolated.parent().unwrap()).expect("directory");
        fs::write(&isolated, "").expect("source");
        let selection = select_project(&request(None, Some(&isolated)), directory.path()).unwrap();
        assert_eq!(
            selection.canonical_root,
            fs::canonicalize(isolated.parent().unwrap()).unwrap()
        );
        assert_eq!(selection.provenance, SelectionProvenance::IndexFileParent);
    }

    #[test]
    fn explicit_external_file_discovers_nearest_manifest_or_falls_back_to_parent() {
        let directory = tempdir().expect("temporary directory");
        let cwd = directory.path().join("cwd");
        fs::create_dir(&cwd).expect("cwd");

        let project = directory.path().join("external/project");
        let nested = project.join("src/deep");
        fs::create_dir_all(&nested).expect("directories");
        fs::write(project.join("Cargo.toml"), "").expect("manifest");
        let source = nested.join("main.rs");
        fs::write(&source, "").expect("source");
        let selection = select_project(&request(None, Some(&source)), &cwd).unwrap();
        assert_eq!(
            selection.canonical_root,
            fs::canonicalize(&project).unwrap()
        );
        assert_eq!(selection.provenance, SelectionProvenance::IndexFileManifest);

        let isolated = directory.path().join("isolated/main.rs");
        fs::create_dir(isolated.parent().unwrap()).expect("isolated directory");
        fs::write(&isolated, "").expect("isolated source");
        let selection = select_project(&request(None, Some(&isolated)), &cwd).unwrap();
        assert_eq!(
            selection.canonical_root,
            fs::canonicalize(isolated.parent().unwrap()).unwrap()
        );
        assert_eq!(selection.provenance, SelectionProvenance::IndexFileParent);
    }

    #[test]
    fn cwd_and_index_directory_do_not_climb() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("project");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("directories");
        fs::write(root.join("go.mod"), "module example").expect("manifest");
        let directory_selection =
            select_project(&request(None, Some(&nested)), directory.path()).unwrap();
        assert_eq!(
            directory_selection.canonical_root,
            fs::canonicalize(&nested).unwrap()
        );
        let cwd_selection = select_project(&request(None, None), &nested).unwrap();
        assert_eq!(
            cwd_selection.canonical_root,
            fs::canonicalize(&nested).unwrap()
        );
        assert_eq!(
            cwd_selection.provenance,
            SelectionProvenance::CurrentDirectory
        );
    }

    #[test]
    fn rejects_invalid_cwd_before_other_selection_inputs() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("root");
        fs::create_dir(&root).expect("root");
        let non_directory_cwd = directory.path().join("cwd-file");
        fs::write(&non_directory_cwd, "").expect("cwd file");
        assert!(matches!(
            select_project(&request(Some(&root), None), &non_directory_cwd),
            Err(CliError::ProjectPath { .. })
        ));

        let missing_cwd = directory.path().join("missing-cwd");
        let invalid_root = directory.path().join("missing-root");
        match select_project(&request(Some(&invalid_root), None), &missing_cwd) {
            Err(CliError::ProjectPath { path, .. }) => assert_eq!(path, missing_cwd),
            result => panic!("invalid cwd must take precedence, got {result:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn trusts_only_var_as_a_strict_cwd_ancestor() {
        let cwd = Path::new("/var/folders/example/project");
        assert!(is_trusted_cwd_ancestor(Path::new("/var"), cwd));
        assert!(!is_trusted_cwd_ancestor(Path::new("/var/folders"), cwd));
        assert!(!is_trusted_cwd_ancestor(cwd, cwd));
        assert!(!is_trusted_cwd_ancestor(
            Path::new("/var/folders/example/project/child-link"),
            cwd
        ));
        assert!(!is_trusted_cwd_ancestor(Path::new("/outside"), cwd));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_user_ancestor_aliases_and_selected_symlink_escapes() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let physical = directory.path().join("physical/cwd");
        fs::create_dir_all(&physical).expect("physical cwd");
        let alias = directory.path().join("alias");
        symlink(directory.path().join("physical"), &alias).expect("user alias");
        let alias_cwd = alias.join("cwd");
        let source = physical.join("source.rs");
        fs::write(&source, "").expect("source");
        assert!(matches!(
            select_project(&request(None, Some(&source)), &alias_cwd),
            Err(CliError::ProjectSymlink { .. })
        ));

        let outside = directory.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        let escaped_source = outside.join("escaped.rs");
        fs::write(&escaped_source, "").expect("escaped source");
        let source_link = physical.join("source-link.rs");
        symlink(&escaped_source, &source_link).expect("source link");
        assert!(matches!(
            select_project(&request(None, Some(&source_link)), &physical),
            Err(CliError::ProjectSymlink { .. })
        ));

        let root_link = physical.join("root-link");
        symlink(&outside, &root_link).expect("root link");
        assert!(matches!(
            select_project(&request(Some(&root_link), None), &physical),
            Err(CliError::ProjectSymlink { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_roots_and_sources() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        fs::create_dir(&target).expect("target");
        let root_link = directory.path().join("root-link");
        symlink(&target, &root_link).expect("root link");
        assert!(matches!(
            select_project(&request(Some(&root_link), None), directory.path()),
            Err(CliError::ProjectSymlink { .. })
        ));

        let source = target.join("source.rs");
        fs::write(&source, "").expect("source");
        let source_link = directory.path().join("source-link.rs");
        symlink(&source, &source_link).expect("source link");
        assert!(matches!(
            select_project(&request(None, Some(&source_link)), directory.path()),
            Err(CliError::ProjectSymlink { .. })
        ));

        let directory_link = directory.path().join("target-link");
        symlink(&target, &directory_link).expect("directory link");
        assert!(matches!(
            select_project(
                &request(None, Some(&directory_link.join("source.rs"))),
                directory.path()
            ),
            Err(CliError::ProjectSymlink { .. })
        ));
    }
}
