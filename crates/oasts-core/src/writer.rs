//! Deterministic generated-file writing and ownership tracking.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::diag::Diagnostic;
use crate::emit::GeneratedFile;

const MANIFEST_NAME: &str = ".oasts-manifest.json";
const CODE_MANIFEST: &str = "OASTS1011";
const CODE_PATH: &str = "OASTS1012";
const CODE_WRITE_IO: &str = "OASTS1013";
const CODE_DUPLICATE: &str = "OASTS1014";
const PARALLEL_IO_MIN_FILES: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    manifest_version: u32,
    files: Vec<String>,
}

/// One on-disk difference found by [`check_drift`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftEntry {
    pub relative_path: String,
    pub state: DriftState,
}

/// The comparison state of one generated path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DriftState {
    Clean,
    Edited,
    Missing,
    Stale,
}

impl fmt::Display for DriftState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Clean => "clean",
            Self::Edited => "edited",
            Self::Missing => "missing",
            Self::Stale => "stale",
        })
    }
}

/// Deterministic drift results plus configuration/IO failures.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DriftReport {
    pub entries: Vec<DriftEntry>,
    pub diagnostics: Vec<Diagnostic>,
}

impl DriftReport {
    /// Returns whether every generated file and the ownership manifest match.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
            && self
                .entries
                .iter()
                .all(|entry| entry.state == DriftState::Clean)
    }
}

/// Counts from one successful writer run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteReport {
    pub files_written: usize,
    pub files_deleted: usize,
}

#[derive(Clone, Debug)]
struct PreparedFile {
    relative_path: String,
    content: Vec<u8>,
}

trait Renamer {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
}

struct FileRenamer;

impl Renamer for FileRenamer {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
}

enum ChangeKind {
    Generated(String),
    Manifest,
    Obsolete(String),
}

struct StagedChange {
    kind: ChangeKind,
    staged: Option<PathBuf>,
    backup: PathBuf,
}

struct AppliedChange {
    target: PathBuf,
    backup: Option<PathBuf>,
    installed: bool,
}

#[derive(Default)]
struct StagingDirectories {
    // Staging beside each target keeps every commit rename on the target's filesystem, including
    // when one generated subtree is a separate mount.
    directories: BTreeMap<PathBuf, tempfile::TempDir>,
    next_file: usize,
}

impl StagingDirectories {
    fn paths(&mut self, parent: &Path) -> Result<(PathBuf, PathBuf), Vec<Diagnostic>> {
        let index = self.next_file;
        self.next_file += 1;
        let directory = match self.directories.entry(parent.to_path_buf()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let directory = tempfile::Builder::new()
                    .prefix(".oasts-stage-")
                    .tempdir_in(parent)
                    .map_err(|error| {
                        vec![io_diagnostic(
                            format!("failed to create staging directory: {error}"),
                            Some(parent),
                        )]
                    })?;
                entry.insert(directory)
            }
        };
        Ok((
            directory.path().join(format!("new-{index}")),
            directory.path().join(format!("old-{index}")),
        ))
    }

    fn close(self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        for (_, directory) in self.directories {
            let path = directory.path().to_path_buf();
            if let Err(error) = directory.close() {
                diagnostics.push(io_diagnostic(
                    format!("failed to remove staging directory: {error}"),
                    Some(&path),
                ));
            }
        }
        diagnostics
    }
}

/// Resolves generated paths against the output directory, memoising parent resolution.
///
/// The memo is only sound where nothing acts on the filesystem afterwards, so it is confined to
/// the preflight sweep: preflight validates every path the run will touch and performs no I/O of
/// its own, and a cache hit there at worst lets a hostile path pass a check that the fresh
/// resolution in front of the actual operation then rejects. Every site that goes on to read,
/// write or unlink a target resolves through [`validate_target`] instead, which builds a throwaway
/// validator so the parent's metadata and containment are re-checked immediately before the
/// operation — the property the uncached code had, and the one a cross-family review flagged this
/// cache for weakening.
struct TargetValidator<'a> {
    output_dir: &'a Path,
    resolved_parents: BTreeMap<PathBuf, PathBuf>,
}

impl<'a> TargetValidator<'a> {
    fn new(output_dir: &'a Path) -> Self {
        Self {
            output_dir,
            resolved_parents: BTreeMap::new(),
        }
    }

    fn validate(&mut self, relative_path: &str) -> Result<PathBuf, Vec<Diagnostic>> {
        validate_relative_path(relative_path)?;
        let mut components = relative_path.split('/').peekable();
        let mut unresolved_parent = self.output_dir.to_path_buf();
        let mut resolved_parent = self.output_dir.to_path_buf();
        // `validate_relative_path` rejects empty paths and trailing separators.
        let file_name = components
            .next_back()
            .expect("validated relative paths contain a file name");
        for component in components {
            unresolved_parent.push(component);
            if let Some(cached) = self.resolved_parents.get(&unresolved_parent) {
                resolved_parent.clone_from(cached);
                continue;
            }

            let candidate = resolved_parent.join(component);
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if !metadata.is_dir() && !metadata.file_type().is_symlink() {
                        return Err(vec![path_diagnostic(
                            relative_path,
                            "a parent component is not a directory",
                        )]);
                    }
                    let canonical = fs::canonicalize(&candidate).map_err(|error| {
                        vec![io_diagnostic(
                            format!(
                                "failed to canonicalize parent of generated path '{relative_path}': {error}"
                            ),
                            Some(&candidate),
                        )]
                    })?;
                    if !canonical.is_dir() || !is_strictly_within(self.output_dir, &canonical) {
                        return Err(vec![path_diagnostic(
                            relative_path,
                            "symlink-canonicalized parent escapes the output directory",
                        )]);
                    }
                    resolved_parent = canonical;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    resolved_parent.push(component);
                }
                Err(error) => {
                    return Err(vec![io_diagnostic(
                        format!("failed to inspect generated path '{relative_path}': {error}"),
                        Some(&candidate),
                    )]);
                }
            }
            self.resolved_parents
                .insert(unresolved_parent.clone(), resolved_parent.clone());
        }
        let target = resolved_parent.join(file_name);
        validate_target_metadata(relative_path, &target, fs::symlink_metadata(&target))
    }
}

/// Removes directories left empty by deleting stale files, walking up to but never touching the
/// output root itself.
///
/// Renaming a schema only ever moves a file within its directory, so before artifact directories
/// were configurable nothing could empty one. Relocating an artifact empties its whole old tree,
/// and a committed `generated/` would otherwise keep those husks forever — `--check` sees only
/// files and would call the tree clean.
///
/// `remove_dir` refuses a non-empty directory, so a directory holding anything the user put there
/// survives untouched and every error is simply the signal to stop climbing.
fn prune_emptied_directories(output_root: &Path, emptied: Vec<PathBuf>) {
    let mut candidates = emptied;
    candidates.sort_unstable();
    candidates.dedup();
    // Deepest first, so a directory whose only content was another pruned directory is itself
    // empty by the time it is reached.
    for mut directory in candidates.into_iter().rev() {
        // Every candidate is the parent of a validated target, so climbing can only ever reach the
        // output root, which ends the walk.
        while directory != output_root && fs::remove_dir(&directory).is_ok() {
            directory.pop();
        }
    }
}

/// Writes generated files and updates the output-root ownership manifest.
pub fn write(output_dir: &Path, files: Vec<GeneratedFile>) -> Result<WriteReport, Vec<Diagnostic>> {
    write_with_renamer(output_dir, files, &FileRenamer)
}

fn write_with_renamer(
    output_dir: &Path,
    files: Vec<GeneratedFile>,
    renamer: &dyn Renamer,
) -> Result<WriteReport, Vec<Diagnostic>> {
    let mut created_directories = Vec::new();
    let result = (|| {
        let prepared = prepare_files(files)?;
        validate_output_path(output_dir)?;

        let output_existed = output_dir.exists();
        let canonical_output = if output_existed {
            canonical_output_dir(output_dir)?
        } else {
            output_dir.to_path_buf()
        };
        let previous_read = if output_existed {
            validate_target(&canonical_output, MANIFEST_NAME)?;
            read_manifest_bytes(&canonical_output)?
        } else {
            None
        };
        let previous = previous_read.as_ref().map(|(manifest, _)| manifest);
        validate_manifest_paths(previous)?;

        if !output_existed {
            create_directories(output_dir, &mut created_directories)?;
        }
        write_transaction(
            output_dir,
            &prepared,
            previous_read.as_ref(),
            &mut created_directories,
            renamer,
        )
    })();
    finish_created_directories(result, created_directories)
}

fn write_transaction(
    output_dir: &Path,
    prepared: &[PreparedFile],
    previous_read: Option<&(Manifest, Vec<u8>)>,
    created_directories: &mut Vec<PathBuf>,
    renamer: &dyn Renamer,
) -> Result<WriteReport, Vec<Diagnostic>> {
    let canonical_output = canonical_output_dir(output_dir)?;
    let previous = previous_read.map(|(manifest, _)| manifest);
    let mut targets = TargetValidator::new(&canonical_output);
    preflight_targets(&mut targets, prepared, previous)?;

    let new_paths = prepared
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let mut stale_paths = previous
        .into_iter()
        .flat_map(|manifest| manifest.files.iter())
        .filter(|path| !new_paths.contains(*path))
        .cloned()
        .collect::<Vec<_>>();
    stale_paths.sort_unstable();

    let unchanged = if rayon::current_num_threads() == 1 || prepared.len() < PARALLEL_IO_MIN_FILES {
        let mut existing_content = Vec::new();
        prepared
            .iter()
            .map(|file| existing_content_matches(&canonical_output, file, &mut existing_content))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        prepared
            .par_iter()
            .map_init(Vec::new, |existing_content, file| {
                existing_content_matches(&canonical_output, file, existing_content)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
    };

    let manifest = Manifest {
        manifest_version: 1,
        files: new_paths.into_iter().collect(),
    };
    let manifest_bytes = manifest_bytes(&manifest);
    let manifest_is_current = previous_read
        .is_some_and(|(_, previous_bytes)| previous_bytes.as_slice() == manifest_bytes.as_slice());
    let pending_manifest = if manifest_is_current {
        None
    } else {
        Some(manifest_bytes)
    };

    let mut staging = StagingDirectories::default();
    let staged = stage_changes(
        &canonical_output,
        prepared,
        unchanged,
        stale_paths,
        pending_manifest,
        created_directories,
        &mut staging,
    );
    let changes = match staged {
        Ok(changes) => changes,
        Err(mut diagnostics) => {
            diagnostics.extend(staging.close());
            return Err(diagnostics);
        }
    };

    let mut applied = Vec::with_capacity(changes.len());
    let committed = finish_changes(
        commit_changes(&canonical_output, &changes, renamer, &mut applied),
        renamer,
        applied,
    );
    let (report, emptied) = match committed {
        Ok(committed) => committed,
        Err(mut diagnostics) => {
            diagnostics.extend(staging.close());
            return Err(diagnostics);
        }
    };
    require_clean_staging(staging.close())?;
    prune_emptied_directories(&canonical_output, emptied);
    Ok(report)
}

fn stage_changes(
    output_dir: &Path,
    prepared: &[PreparedFile],
    unchanged: Vec<bool>,
    stale_paths: Vec<String>,
    manifest_bytes: Option<Vec<u8>>,
    created_directories: &mut Vec<PathBuf>,
    staging: &mut StagingDirectories,
) -> Result<Vec<StagedChange>, Vec<Diagnostic>> {
    let mut changes = Vec::new();
    for relative_path in stale_paths {
        let target = validate_target(output_dir, &relative_path)?;
        let kind = ChangeKind::Obsolete(relative_path);
        if target_metadata(&kind, &target, fs::symlink_metadata(&target))?.is_some() {
            let parent = target
                .parent()
                .expect("a validated target inside an absolute output directory has a parent");
            let (_, backup) = staging.paths(parent)?;
            changes.push(StagedChange {
                kind,
                staged: None,
                backup,
            });
        }
    }

    for (file, is_unchanged) in prepared.iter().zip(unchanged) {
        if !is_unchanged {
            let target = validate_target(output_dir, &file.relative_path)?;
            let parent = target
                .parent()
                .expect("a validated target inside an absolute output directory has a parent");
            create_directories(parent, created_directories)?;
            changes.push(stage_write(
                output_dir,
                ChangeKind::Generated(file.relative_path.clone()),
                &file.content,
                staging,
            )?);
        }
    }

    if let Some(manifest_bytes) = manifest_bytes {
        changes.push(stage_write(
            output_dir,
            ChangeKind::Manifest,
            &manifest_bytes,
            staging,
        )?);
    }
    Ok(changes)
}

fn stage_write(
    output_dir: &Path,
    kind: ChangeKind,
    content: &[u8],
    staging: &mut StagingDirectories,
) -> Result<StagedChange, Vec<Diagnostic>> {
    let relative_path = match &kind {
        ChangeKind::Generated(relative_path) | ChangeKind::Obsolete(relative_path) => relative_path,
        ChangeKind::Manifest => MANIFEST_NAME,
    };
    let target = validate_target(output_dir, relative_path)?;
    let permissions = writable_target_permissions(&kind, &target)?;
    let parent = target
        .parent()
        .expect("a validated target inside an absolute output directory has a parent");
    let (staged, backup) = staging.paths(parent)?;
    fs::write(&staged, content).map_err(change_error(&kind, &target))?;
    if let Some(permissions) = permissions {
        fs::set_permissions(&staged, permissions).map_err(change_error(&kind, &target))?;
    }
    Ok(StagedChange {
        kind,
        staged: Some(staged),
        backup,
    })
}

fn writable_target_permissions(
    kind: &ChangeKind,
    target: &Path,
) -> Result<Option<fs::Permissions>, Vec<Diagnostic>> {
    let Some(metadata) = target_metadata(kind, target, fs::symlink_metadata(target))? else {
        return Ok(None);
    };
    fs::OpenOptions::new()
        .write(true)
        .open(target)
        .map_err(change_error(kind, target))?;
    Ok(Some(metadata.permissions()))
}

fn target_metadata(
    kind: &ChangeKind,
    target: &Path,
    metadata: io::Result<fs::Metadata>,
) -> Result<Option<fs::Metadata>, Vec<Diagnostic>> {
    match metadata {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(change_error(kind, target)(error)),
    }
}

fn commit_changes(
    output_dir: &Path,
    changes: &[StagedChange],
    renamer: &dyn Renamer,
    applied: &mut Vec<AppliedChange>,
) -> Result<(WriteReport, Vec<PathBuf>), Vec<Diagnostic>> {
    let mut report = WriteReport::default();
    let mut emptied = Vec::new();
    for change in changes {
        let relative_path = match &change.kind {
            ChangeKind::Generated(relative_path) | ChangeKind::Obsolete(relative_path) => {
                relative_path
            }
            ChangeKind::Manifest => MANIFEST_NAME,
        };
        let target = validate_target(output_dir, relative_path)?;
        let backup = if target_metadata(&change.kind, &target, fs::symlink_metadata(&target))?
            .is_some()
        {
            fs::hard_link(&target, &change.backup).map_err(change_error(&change.kind, &target))?;
            Some(change.backup.clone())
        } else {
            None
        };
        applied.push(AppliedChange {
            target: target.clone(),
            backup,
            installed: false,
        });

        if let Some(staged) = &change.staged {
            let target = validate_target(output_dir, relative_path)?;
            renamer
                .rename(staged, &target)
                .map_err(change_error(&change.kind, &target))?;
            applied
                .last_mut()
                .expect("the current change was recorded before installation")
                .installed = true;
            if matches!(change.kind, ChangeKind::Generated(_)) {
                report.files_written += 1;
            }
        } else if applied
            .last()
            .expect("the current change was recorded before deletion")
            .backup
            .is_some()
        {
            fs::remove_file(&target).map_err(change_error(&change.kind, &target))?;
            applied
                .last_mut()
                .expect("the current change was recorded before deletion")
                .installed = true;
            report.files_deleted += 1;
            emptied.push(
                target
                    .parent()
                    .expect("a validated target inside an absolute output directory has a parent")
                    .to_path_buf(),
            );
        }
    }
    Ok((report, emptied))
}

fn finish_changes(
    committed: Result<(WriteReport, Vec<PathBuf>), Vec<Diagnostic>>,
    renamer: &dyn Renamer,
    applied: Vec<AppliedChange>,
) -> Result<(WriteReport, Vec<PathBuf>), Vec<Diagnostic>> {
    let Err(mut diagnostics) = committed else {
        return committed;
    };
    for change in applied.into_iter().rev() {
        if change.installed {
            if let Some(backup) = change.backup {
                if let Err(error) = renamer.rename(&backup, &change.target) {
                    diagnostics.push(io_diagnostic(
                        format!("failed to restore a generated file during rollback: {error}"),
                        Some(&change.target),
                    ));
                }
            } else {
                match fs::remove_file(&change.target) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => diagnostics.push(io_diagnostic(
                        format!("failed to remove a committed file during rollback: {error}"),
                        Some(&change.target),
                    )),
                }
            }
        }
    }
    Err(diagnostics)
}

fn create_directories(
    directory: &Path,
    created_directories: &mut Vec<PathBuf>,
) -> Result<(), Vec<Diagnostic>> {
    let mut missing = Vec::new();
    let mut current = directory;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    vec![io_diagnostic(
                        "failed to find an existing parent directory".to_owned(),
                        Some(directory),
                    )]
                })?;
            }
            Err(error) => {
                return Err(vec![io_diagnostic(
                    format!("failed to inspect output directory: {error}"),
                    Some(current),
                )]);
            }
        }
    }
    created_directories.extend(missing);
    fs::create_dir_all(directory).map_err(|error| {
        vec![io_diagnostic(
            format!("failed to create output directory: {error}"),
            Some(directory),
        )]
    })
}

fn finish_created_directories(
    result: Result<WriteReport, Vec<Diagnostic>>,
    created_directories: Vec<PathBuf>,
) -> Result<WriteReport, Vec<Diagnostic>> {
    let Err(mut diagnostics) = result else {
        return result;
    };
    let mut created_directories = created_directories;
    created_directories
        .sort_unstable_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    created_directories.dedup();
    for directory in created_directories {
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => diagnostics.push(io_diagnostic(
                format!("failed to remove a directory created during staging: {error}"),
                Some(&directory),
            )),
        }
    }
    Err(diagnostics)
}

fn require_clean_staging(diagnostics: Vec<Diagnostic>) -> Result<(), Vec<Diagnostic>> {
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics)
    }
}

fn change_error<'a>(
    kind: &'a ChangeKind,
    target: &'a Path,
) -> impl FnOnce(io::Error) -> Vec<Diagnostic> + 'a {
    move |error| {
        let message = match kind {
            ChangeKind::Generated(relative_path) => {
                format!("failed to write generated file '{relative_path}': {error}")
            }
            ChangeKind::Manifest => format!("failed to write ownership manifest: {error}"),
            ChangeKind::Obsolete(relative_path) => {
                format!("failed to delete obsolete generated file '{relative_path}': {error}")
            }
        };
        vec![io_diagnostic(message, Some(target))]
    }
}

fn existing_content_matches(
    output_dir: &Path,
    file: &PreparedFile,
    existing_content: &mut Vec<u8>,
) -> Result<bool, Vec<Diagnostic>> {
    let target = validate_target(output_dir, &file.relative_path)?;
    Ok(fs::File::open(&target).is_ok_and(|mut existing_file| {
        existing_content.clear();
        existing_file.read_to_end(existing_content).is_ok()
            && existing_content.as_slice() == file.content.as_slice()
    }))
}

/// Compares generated bytes and ownership metadata without changing the output tree.
#[must_use]
pub fn check_drift(output_dir: &Path, files: Vec<GeneratedFile>) -> DriftReport {
    match check_drift_inner(output_dir, files) {
        Ok(report) => report,
        Err(diagnostics) => DriftReport {
            entries: Vec::new(),
            diagnostics,
        },
    }
}

fn check_drift_inner(
    output_dir: &Path,
    files: Vec<GeneratedFile>,
) -> Result<DriftReport, Vec<Diagnostic>> {
    let prepared = prepare_files(files)?;
    validate_output_path(output_dir)?;
    if !output_dir.exists() {
        let mut entries = prepared
            .into_iter()
            .map(|file| DriftEntry {
                relative_path: file.relative_path,
                state: DriftState::Stale,
            })
            .collect::<Vec<_>>();
        entries.push(DriftEntry {
            relative_path: MANIFEST_NAME.to_owned(),
            state: DriftState::Stale,
        });
        entries.sort_unstable_by(|left, right| {
            left.relative_path
                .as_bytes()
                .cmp(right.relative_path.as_bytes())
        });
        return Ok(DriftReport {
            entries,
            diagnostics: Vec::new(),
        });
    }

    let canonical_output = canonical_output_dir(output_dir)?;
    validate_target(&canonical_output, MANIFEST_NAME)?;
    let manifest_read = read_manifest_bytes(&canonical_output)?;
    let manifest = manifest_read.as_ref().map(|(manifest, _)| manifest);
    validate_manifest_paths(manifest)?;
    let mut targets = TargetValidator::new(&canonical_output);
    preflight_targets(&mut targets, &prepared, manifest)?;

    let expected_manifest = Manifest {
        manifest_version: 1,
        files: prepared
            .iter()
            .map(|file| file.relative_path.clone())
            .collect(),
    };
    let expected_manifest_bytes = manifest_bytes(&expected_manifest);
    let manifest_is_current = manifest_read
        .as_ref()
        .is_some_and(|(_, bytes)| *bytes == expected_manifest_bytes);
    let recorded = manifest
        .into_iter()
        .flat_map(|manifest| manifest.files.iter().cloned())
        .collect::<BTreeSet<_>>();
    let generated = prepared
        .iter()
        .map(|file| (file.relative_path.clone(), file))
        .collect::<BTreeMap<_, _>>();

    let mut entries =
        if rayon::current_num_threads() == 1 || generated.len() < PARALLEL_IO_MIN_FILES {
            generated
                .iter()
                .map(|(relative_path, file)| {
                    compare_drift_file(&canonical_output, &recorded, relative_path, file)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            generated
                .iter()
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|(relative_path, file)| {
                    compare_drift_file(&canonical_output, &recorded, relative_path, file)
                })
                .collect::<Vec<_>>()
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
        };
    entries.reserve(recorded.len() + 1);
    for relative_path in recorded
        .iter()
        .filter(|path| !generated.contains_key(path.as_str()))
    {
        entries.push(DriftEntry {
            relative_path: relative_path.clone(),
            state: DriftState::Stale,
        });
    }
    entries.push(DriftEntry {
        relative_path: MANIFEST_NAME.to_owned(),
        state: if manifest_is_current {
            DriftState::Clean
        } else {
            DriftState::Stale
        },
    });
    entries.sort_unstable_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });

    Ok(DriftReport {
        entries,
        diagnostics: Vec::new(),
    })
}

fn compare_drift_file(
    output_dir: &Path,
    recorded: &BTreeSet<String>,
    relative_path: &str,
    file: &PreparedFile,
) -> Result<DriftEntry, Vec<Diagnostic>> {
    let state = if !recorded.contains(relative_path) {
        DriftState::Stale
    } else {
        let target = validate_target(output_dir, relative_path)?;
        match fs::read(&target) {
            Ok(bytes) if bytes == file.content => DriftState::Clean,
            Ok(_) => DriftState::Edited,
            Err(error) if error.kind() == ErrorKind::NotFound => DriftState::Missing,
            Err(error) => {
                return Err(vec![io_diagnostic(
                    format!("failed to read generated file '{relative_path}': {error}"),
                    Some(&target),
                )]);
            }
        }
    };
    Ok(DriftEntry {
        relative_path: relative_path.to_owned(),
        state,
    })
}

fn prepare_files(files: Vec<GeneratedFile>) -> Result<Vec<PreparedFile>, Vec<Diagnostic>> {
    let mut prepared = Vec::with_capacity(files.len());
    let mut paths = BTreeSet::new();
    for file in files {
        validate_relative_path(&file.relative_path)?;
        if file.relative_path == MANIFEST_NAME {
            return Err(vec![path_diagnostic(
                &file.relative_path,
                "generated files cannot replace the ownership manifest",
            )]);
        }
        if !paths.insert(file.relative_path.clone()) {
            return Err(vec![Diagnostic::config(
                CODE_DUPLICATE,
                format!("duplicate generated path '{}'", file.relative_path),
            )]);
        }
        prepared.push(PreparedFile {
            relative_path: file.relative_path,
            content: normalize_lf(file.content).into_bytes(),
        });
    }
    prepared.sort_unstable_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    Ok(prepared)
}

fn normalize_lf(content: String) -> String {
    if !content.contains('\r') {
        return content;
    }
    content.replace("\r\n", "\n").replace('\r', "\n")
}

fn validate_output_path(output_dir: &Path) -> Result<(), Vec<Diagnostic>> {
    if !output_dir.is_absolute() {
        return Err(vec![Diagnostic::config(
            CODE_PATH,
            format!(
                "output directory '{}' must be absolute",
                output_dir.display()
            ),
        )]);
    }
    Ok(())
}

fn canonical_output_dir(output_dir: &Path) -> Result<PathBuf, Vec<Diagnostic>> {
    let canonical = fs::canonicalize(output_dir).map_err(|error| {
        vec![io_diagnostic(
            format!("failed to canonicalize output directory: {error}"),
            Some(output_dir),
        )]
    })?;
    if !canonical.is_dir() {
        return Err(vec![io_diagnostic(
            "output path is not a directory".to_owned(),
            Some(&canonical),
        )]);
    }
    Ok(canonical)
}

fn read_manifest_bytes(output_dir: &Path) -> Result<Option<(Manifest, Vec<u8>)>, Vec<Diagnostic>> {
    let path = output_dir.join(MANIFEST_NAME);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(vec![io_diagnostic(
                format!("failed to read ownership manifest: {error}"),
                Some(&path),
            )]);
        }
    };
    let manifest = serde_json::from_slice::<Manifest>(&bytes).map_err(|error| {
        vec![Diagnostic::config(
            CODE_MANIFEST,
            format!("invalid ownership manifest '{}': {error}", path.display()),
        )]
    })?;
    if manifest.manifest_version != 1 {
        return Err(vec![Diagnostic::config(
            CODE_MANIFEST,
            format!(
                "unsupported ownership manifest version {} in '{}'",
                manifest.manifest_version,
                path.display()
            ),
        )]);
    }
    let unique = manifest.files.iter().collect::<BTreeSet<_>>();
    if unique.len() != manifest.files.len() {
        return Err(vec![Diagnostic::config(
            CODE_MANIFEST,
            format!(
                "ownership manifest '{}' contains duplicate paths",
                path.display()
            ),
        )]);
    }
    Ok(Some((manifest, bytes)))
}

fn validate_manifest_paths(manifest: Option<&Manifest>) -> Result<(), Vec<Diagnostic>> {
    if let Some(manifest) = manifest {
        for relative_path in &manifest.files {
            validate_relative_path(relative_path)?;
            if relative_path == MANIFEST_NAME {
                return Err(vec![path_diagnostic(
                    relative_path,
                    "ownership manifest cannot own itself",
                )]);
            }
        }
    }
    Ok(())
}

fn validate_relative_path(relative_path: &str) -> Result<(), Vec<Diagnostic>> {
    let bytes = relative_path.as_bytes();
    let invalid = relative_path.is_empty()
        || relative_path.starts_with(['/', '\\'])
        || relative_path.contains('\\')
        || bytes.get(1) == Some(&b':')
        || relative_path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."));
    if invalid {
        return Err(vec![path_diagnostic(
            relative_path,
            "path must be relative and contain no absolute, empty, '.', or '..' components",
        )]);
    }
    Ok(())
}

fn preflight_targets(
    targets: &mut TargetValidator<'_>,
    files: &[PreparedFile],
    previous: Option<&Manifest>,
) -> Result<(), Vec<Diagnostic>> {
    targets.validate(MANIFEST_NAME)?;
    for file in files {
        targets.validate(&file.relative_path)?;
    }
    if let Some(previous) = previous {
        for relative_path in &previous.files {
            targets.validate(relative_path)?;
        }
    }
    Ok(())
}

fn validate_target(output_dir: &Path, relative_path: &str) -> Result<PathBuf, Vec<Diagnostic>> {
    TargetValidator::new(output_dir).validate(relative_path)
}

fn validate_target_metadata(
    relative_path: &str,
    target: &Path,
    metadata: std::io::Result<fs::Metadata>,
) -> Result<PathBuf, Vec<Diagnostic>> {
    match metadata {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(vec![path_diagnostic(
            relative_path,
            "generated file target must not be a symlink",
        )]),
        Ok(metadata) if metadata.is_dir() => Err(vec![path_diagnostic(
            relative_path,
            "generated file target is a directory",
        )]),
        Ok(_) => Ok(target.to_path_buf()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(target.to_path_buf()),
        Err(error) => Err(vec![io_diagnostic(
            format!("failed to inspect generated path '{relative_path}': {error}"),
            Some(target),
        )]),
    }
}

fn is_strictly_within(output_dir: &Path, target: &Path) -> bool {
    target != output_dir && target.starts_with(output_dir)
}

fn manifest_bytes(manifest: &Manifest) -> Vec<u8> {
    // `Manifest` contains only an integer version and owned UTF-8 path strings.
    let mut bytes = serde_json::to_vec(manifest)
        .expect("the ownership manifest contains only JSON-serializable fields");
    bytes.push(b'\n');
    bytes
}

fn path_diagnostic(relative_path: &str, reason: &str) -> Diagnostic {
    Diagnostic::config(
        CODE_PATH,
        format!("unsafe generated path '{relative_path}': {reason}"),
    )
}

fn io_diagnostic(message: String, path: Option<&Path>) -> Diagnostic {
    let diagnostic = Diagnostic::config(CODE_WRITE_IO, message);
    if let Some(path) = path {
        diagnostic.with_source(path.to_string_lossy())
    } else {
        diagnostic
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct FailOnceRenamer {
        calls: Cell<usize>,
        fail_at: usize,
    }

    impl Renamer for FailOnceRenamer {
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.fail_at {
                Err(io::Error::other("forced mid-commit failure"))
            } else {
                fs::rename(from, to)
            }
        }
    }

    struct InterruptBeforeInstallRenamer {
        observed_old_target: Cell<Option<bool>>,
    }

    impl Renamer for InterruptBeforeInstallRenamer {
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            if from
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("new-"))
            {
                self.observed_old_target
                    .set(Some(fs::read(to).is_ok_and(|content| content == b"old")));
                Err(io::Error::new(
                    ErrorKind::Interrupted,
                    "forced interruption before installation",
                ))
            } else {
                fs::rename(from, to)
            }
        }
    }

    fn generated(path: &str, content: &str) -> GeneratedFile {
        GeneratedFile {
            relative_path: path.to_owned(),
            content: content.to_owned(),
        }
    }

    fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            for entry in fs::read_dir(directory).expect("read directory") {
                let entry = entry.expect("directory entry");
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("path below root")
                    .to_path_buf();
                if entry.file_type().expect("file type").is_dir() {
                    snapshot.insert(relative, None);
                    visit(root, &path, snapshot);
                } else {
                    snapshot.insert(relative, Some(fs::read(path).expect("file contents")));
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[test]
    fn writes_sorted_manifest_and_normalizes_line_endings() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let report = write(
            &output,
            vec![generated("z.ts", "z\r\n"), generated("a/a.ts", "a\r")],
        )
        .expect("write");

        assert_eq!(report.files_written, 2);
        assert_eq!(fs::read(output.join("z.ts")).expect("z"), b"z\n");
        assert_eq!(fs::read(output.join("a/a.ts")).expect("a"), b"a\n");
        assert_eq!(
            fs::read(output.join(MANIFEST_NAME)).expect("manifest"),
            b"{\"manifestVersion\":1,\"files\":[\"a/a.ts\",\"z.ts\"]}\n"
        );
    }

    #[test]
    fn skips_unchanged_files_and_counts_only_rewrites() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let files = vec![generated("a.ts", "a\n"), generated("b.ts", "b\n")];

        let first = write(&output, files.clone()).expect("first write");
        assert_eq!(first.files_written, 2);

        let unchanged = write(&output, files).expect("unchanged write");
        assert_eq!(unchanged, WriteReport::default());

        let changed = write(
            &output,
            vec![generated("a.ts", "changed\n"), generated("b.ts", "b\n")],
        )
        .expect("changed write");
        assert_eq!(changed.files_written, 1);
        assert_eq!(fs::read(output.join("a.ts")).expect("a"), b"changed\n");
    }

    #[test]
    fn parallel_comparisons_preserve_drift_and_write_results() {
        let files = (0..64)
            .map(|index| {
                generated(
                    &format!("group-{}/file-{index:02}.ts", index % 4),
                    &format!("value {index}\n"),
                )
            })
            .collect::<Vec<_>>();
        let mut expected_drift = None;

        for thread_count in [1, 2, 18] {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = temp.path().join("generated");
            let mut initial = files.clone();
            initial.push(generated("old.ts", "old\n"));
            write(&output, initial).expect("initial write");
            fs::write(output.join("group-0/file-00.ts"), "edited\n").expect("edit");
            fs::remove_file(output.join("group-1/file-01.ts")).expect("remove");

            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .expect("rayon pool");
            let drift = pool.install(|| check_drift(&output, files.clone()));
            if let Some(expected) = &expected_drift {
                assert_eq!(&drift, expected, "thread count {thread_count}");
            } else {
                expected_drift = Some(drift.clone());
            }

            let report = pool
                .install(|| write(&output, files.clone()))
                .expect("repair output");
            assert_eq!(
                report,
                WriteReport {
                    files_written: 2,
                    files_deleted: 1,
                },
                "thread count {thread_count}"
            );
            assert!(
                pool.install(|| check_drift(&output, files.clone()))
                    .is_clean()
            );
        }
    }

    #[test]
    fn regeneration_deletes_only_obsolete_owned_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        write(
            &output,
            vec![generated("keep.ts", "keep\n"), generated("old.ts", "old\n")],
        )
        .expect("first write");
        fs::write(output.join("user.ts"), "user\n").expect("user file");

        let report = write(&output, vec![generated("keep.ts", "keep\n")]).expect("second write");

        assert_eq!(report.files_deleted, 1);
        assert!(!output.join("old.ts").exists());
        assert!(output.join("user.ts").exists());
    }

    #[test]
    fn hostile_manifest_paths_abort_before_mutation() {
        for hostile in ["../victim.ts", "/absolute/victim.ts"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let output = temp.path().join("generated");
            fs::create_dir(&output).expect("output");
            let victim = temp.path().join("victim.ts");
            fs::write(&victim, "safe\n").expect("victim");
            let manifest = format!(
                "{{\"manifestVersion\":1,\"files\":[{}]}}\n",
                serde_json::to_string(hostile).expect("path JSON")
            );
            fs::write(output.join(MANIFEST_NAME), manifest).expect("manifest");

            let diagnostics = write(&output, vec![generated("new.ts", "new\n")])
                .expect_err("hostile manifest must fail");

            assert_eq!(diagnostics[0].category, crate::diag::Category::Config);
            assert_eq!(fs::read_to_string(&victim).expect("victim"), "safe\n");
            assert!(!output.join("new.ts").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_parent_escape_aborts_before_write_or_delete() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let outside = temp.path().join("outside");
        fs::create_dir(&output).expect("output");
        fs::create_dir(&outside).expect("outside");
        let victim = outside.join("victim.ts");
        fs::write(&victim, "safe\n").expect("victim");
        symlink(&outside, output.join("escape")).expect("escape symlink");
        let manifest = Manifest {
            manifest_version: 1,
            files: vec!["escape/victim.ts".to_owned()],
        };
        fs::write(output.join(MANIFEST_NAME), manifest_bytes(&manifest)).expect("manifest");

        let diagnostics = write(&output, vec![generated("new.ts", "new\n")])
            .expect_err("symlink escape must fail");

        assert_eq!(diagnostics[0].category, crate::diag::Category::Config);
        assert_eq!(fs::read_to_string(victim).expect("victim"), "safe\n");
        assert!(!output.join("new.ts").exists());
    }

    #[cfg(unix)]
    #[test]
    fn parent_memo_never_reaches_a_filesystem_action() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let output = fs::canonicalize(temp.path()).expect("canonical output");
        fs::create_dir(output.join("parent")).expect("parent");
        let outside_dir = tempfile::tempdir().expect("outside tempdir");
        let outside = output.join("outside.ts");
        fs::write(&outside, "outside").expect("outside");

        // Inside the preflight sweep a memo hit still re-checks the target itself, so a target
        // that became a symlink after its parent was resolved is rejected.
        let mut targets = TargetValidator::new(&output);
        targets
            .validate("parent/target.ts")
            .expect("missing target");
        assert_eq!(targets.resolved_parents.len(), 1);
        symlink(&outside, output.join("parent/target.ts")).expect("target symlink");
        assert_eq!(
            targets
                .validate("parent/target.ts")
                .expect_err("a memoised parent must not memoise target metadata")[0]
                .code,
            CODE_PATH
        );

        // Every site that reads, writes or unlinks goes through `validate_target`, which carries
        // no memo: a parent swapped for an escaping symlink after preflight is still caught.
        fs::remove_file(output.join("parent/target.ts")).expect("drop target symlink");
        fs::remove_dir(output.join("parent")).expect("drop parent");
        symlink(outside_dir.path(), output.join("parent")).expect("parent symlink");
        assert_eq!(
            validate_target(&output, "parent/target.ts")
                .expect_err("an action must not trust a stale parent resolution")[0]
                .code,
            CODE_PATH
        );
    }

    #[test]
    fn drift_distinguishes_edited_missing_and_stale() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let files = vec![generated("a.ts", "a\n"), generated("b.ts", "b\n")];
        write(&output, files.clone()).expect("write");
        assert!(check_drift(&output, files.clone()).is_clean());

        fs::write(output.join("a.ts"), "edited\n").expect("edit");
        fs::remove_file(output.join("b.ts")).expect("remove");
        let manifest = Manifest {
            manifest_version: 1,
            files: vec!["a.ts".to_owned(), "b.ts".to_owned(), "old.ts".to_owned()],
        };
        fs::write(output.join(MANIFEST_NAME), manifest_bytes(&manifest)).expect("manifest");

        let report = check_drift(&output, files);
        assert_eq!(
            report.entries,
            vec![
                DriftEntry {
                    relative_path: MANIFEST_NAME.to_owned(),
                    state: DriftState::Stale,
                },
                DriftEntry {
                    relative_path: "a.ts".to_owned(),
                    state: DriftState::Edited,
                },
                DriftEntry {
                    relative_path: "b.ts".to_owned(),
                    state: DriftState::Missing,
                },
                DriftEntry {
                    relative_path: "old.ts".to_owned(),
                    state: DriftState::Stale,
                },
            ]
        );
    }

    #[test]
    fn state_display_alias_and_missing_output_drift_are_covered() {
        for (state, label) in [
            (DriftState::Clean, "clean"),
            (DriftState::Edited, "edited"),
            (DriftState::Missing, "missing"),
            (DriftState::Stale, "stale"),
        ] {
            assert_eq!(state.to_string(), label);
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("missing");
        let report = check_drift(&output, vec![generated("a.ts", "a\n")]);
        assert!(!report.is_clean());
        assert_eq!(report.entries.len(), 2);
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.state == DriftState::Stale)
        );

        let written = write(&output, vec![generated("a.ts", "a\n")]).expect("write");
        assert_eq!(written.files_written, 1);
    }

    #[test]
    fn generated_and_manifest_paths_reject_unsafe_or_duplicate_entries() {
        for path in [
            "",
            "/absolute",
            "\\absolute",
            "a\\b",
            "C:drive",
            "a//b",
            "a/./b",
            "a/../b",
        ] {
            assert_eq!(
                prepare_files(vec![generated(path, "")]).expect_err("unsafe")[0].code,
                CODE_PATH
            );
        }
        assert_eq!(
            prepare_files(vec![generated(MANIFEST_NAME, "")]).expect_err("manifest replacement")[0]
                .code,
            CODE_PATH
        );
        assert_eq!(
            prepare_files(vec![generated("a.ts", "1"), generated("a.ts", "2")])
                .expect_err("duplicate")[0]
                .code,
            CODE_DUPLICATE
        );
        assert_eq!(
            validate_output_path(Path::new("relative")).expect_err("relative")[0].code,
            CODE_PATH
        );

        let self_owned = Manifest {
            manifest_version: 1,
            files: vec![MANIFEST_NAME.to_owned()],
        };
        assert_eq!(
            validate_manifest_paths(Some(&self_owned)).expect_err("self owned")[0].code,
            CODE_PATH
        );
        let unsafe_manifest = Manifest {
            manifest_version: 1,
            files: vec!["../bad.ts".to_owned()],
        };
        assert_eq!(
            validate_manifest_paths(Some(&unsafe_manifest)).expect_err("unsafe")[0].code,
            CODE_PATH
        );
        validate_manifest_paths(None).expect("absent manifest");
        assert!(!is_strictly_within(
            Path::new("/tmp/out"),
            Path::new("/tmp/out")
        ));
    }

    #[test]
    fn manifest_reader_reports_syntax_version_and_duplicate_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path();
        assert_eq!(read_manifest_bytes(output).expect("missing manifest"), None);
        for (contents, code) in [
            ("{", CODE_MANIFEST),
            (r#"{"manifestVersion":2,"files":[]}"#, CODE_MANIFEST),
            (
                r#"{"manifestVersion":1,"files":["a.ts","a.ts"]}"#,
                CODE_MANIFEST,
            ),
            (
                r#"{"manifestVersion":1,"files":[],"extra":true}"#,
                CODE_MANIFEST,
            ),
        ] {
            fs::write(output.join(MANIFEST_NAME), contents).expect("manifest");
            assert_eq!(
                read_manifest_bytes(output).expect_err("invalid manifest")[0].code,
                code
            );
        }
        fs::write(
            output.join(MANIFEST_NAME),
            r#"{"manifestVersion":1,"files":[]}"#,
        )
        .expect("manifest");
        assert!(
            read_manifest_bytes(output)
                .expect("valid manifest")
                .is_some()
        );
    }

    #[test]
    fn canonical_output_and_drift_errors_are_diagnostics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing");
        assert_eq!(
            canonical_output_dir(&missing).expect_err("missing")[0].code,
            CODE_WRITE_IO
        );
        let file = temp.path().join("file");
        fs::write(&file, "x").expect("file");
        assert_eq!(
            canonical_output_dir(&file).expect_err("file output")[0].code,
            CODE_WRITE_IO
        );

        let report = check_drift(temp.path(), vec![generated("../bad.ts", "")]);
        assert_eq!(report.diagnostics[0].code, CODE_PATH);
        assert!(report.entries.is_empty());

        let output = temp.path().join("generated");
        fs::create_dir(&output).expect("output");
        let report = check_drift(&output, vec![generated("new.ts", "new\n")]);
        assert!(
            report.entries.iter().any(|entry| {
                entry.relative_path == "new.ts" && entry.state == DriftState::Stale
            })
        );
    }

    #[test]
    fn stale_manifest_entry_missing_on_disk_is_ignored_during_delete() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        fs::create_dir(&output).expect("output");
        let manifest = Manifest {
            manifest_version: 1,
            files: vec!["missing.ts".to_owned()],
        };
        fs::write(output.join(MANIFEST_NAME), manifest_bytes(&manifest)).expect("manifest");
        let report = write(&output, Vec::new()).expect("missing stale file is harmless");
        assert_eq!(report.files_deleted, 0);
    }

    #[test]
    fn relocating_an_artifact_leaves_no_husk_of_its_old_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        write(
            &output,
            vec![
                generated("types/components/pet.ts", "old"),
                generated("types/operations/listpets.ts", "old"),
            ],
        )
        .expect("initial layout");

        // The same artifact, relocated two segments deep. Its whole old tree goes stale at once,
        // which nothing but a directory change can do.
        let report = write(
            &output,
            vec![generated("shared/model/components/pet.ts", "new")],
        )
        .expect("relocated layout");

        assert_eq!(report.files_deleted, 2);
        assert!(!output.join("types").exists(), "old tree survived");
        assert!(output.join("shared/model/components/pet.ts").exists());
    }

    #[test]
    fn a_directory_the_user_owns_survives_its_generated_files_going_stale() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        write(&output, vec![generated("types/components/pet.ts", "old")]).expect("initial layout");
        fs::write(output.join("types/components/notes.md"), "mine").expect("user file");

        write(&output, vec![generated("shared/pet.ts", "new")]).expect("relocated layout");

        assert!(output.join("types/components/notes.md").exists());
    }

    #[test]
    fn a_mid_write_failure_leaves_the_output_tree_unchanged() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let original = vec![
            generated("a.ts", "old a"),
            generated("locked/z.ts", "old z"),
        ];
        write(&output, original).expect("initial write");
        let before = tree_snapshot(&output);
        let renamer = FailOnceRenamer {
            calls: Cell::new(0),
            fail_at: 2,
        };

        let diagnostics = write_with_renamer(
            &output,
            vec![
                generated("a.ts", "new a"),
                generated("locked/z.ts", "new z"),
            ],
            &renamer,
        )
        .expect_err("second file must reject the write");

        assert_eq!(diagnostics[0].code, CODE_WRITE_IO);
        assert_eq!(tree_snapshot(&output), before);
        assert_eq!(
            renamer.calls.get(),
            3,
            "rollback must restore the changed file"
        );
    }

    #[test]
    fn the_old_target_remains_visible_until_its_replacement_is_installed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        write(&output, vec![generated("a.ts", "old")]).expect("initial write");
        let renamer = InterruptBeforeInstallRenamer {
            observed_old_target: Cell::new(None),
        };

        let diagnostics = write_with_renamer(&output, vec![generated("a.ts", "new")], &renamer)
            .expect_err("installation interruption");

        assert_eq!(diagnostics[0].code, CODE_WRITE_IO);
        assert_eq!(renamer.observed_old_target.get(), Some(true));
        assert_eq!(fs::read(output.join("a.ts")).expect("old target"), b"old");
    }

    #[test]
    fn a_failed_first_write_removes_the_new_output_tree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let renamer = FailOnceRenamer {
            calls: Cell::new(0),
            fail_at: 2,
        };

        let diagnostics = write_with_renamer(
            &output,
            vec![generated("a.ts", "a"), generated("nested/z.ts", "z")],
            &renamer,
        )
        .expect_err("second commit must fail");

        assert_eq!(diagnostics[0].code, CODE_WRITE_IO);
        assert!(!output.exists());
    }

    #[test]
    fn transaction_error_helpers_report_rollback_and_cleanup_failures() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.ts");
        let metadata_error = target_metadata(
            &ChangeKind::Obsolete("target.ts".to_owned()),
            &target,
            Err(io::Error::other("metadata failure")),
        )
        .expect_err("metadata error");
        assert_eq!(metadata_error[0].code, CODE_WRITE_IO);

        let missing_rollback = finish_changes(
            Err(Vec::new()),
            &FileRenamer,
            vec![AppliedChange {
                target: target.clone(),
                backup: None,
                installed: true,
            }],
        )
        .expect_err("rollback result");
        assert!(missing_rollback.is_empty());

        fs::create_dir(&target).expect("target directory");
        let remove_error = finish_changes(
            Err(Vec::new()),
            &FileRenamer,
            vec![AppliedChange {
                target: target.clone(),
                backup: None,
                installed: true,
            }],
        )
        .expect_err("rollback remove error");
        assert_eq!(remove_error[0].code, CODE_WRITE_IO);
        fs::remove_dir(&target).expect("target directory cleanup");

        let backup = temp.path().join("backup.ts");
        fs::write(&backup, "old").expect("backup");
        let failing_renamer = FailOnceRenamer {
            calls: Cell::new(0),
            fail_at: 1,
        };
        let restore_error = finish_changes(
            Err(Vec::new()),
            &failing_renamer,
            vec![AppliedChange {
                target,
                backup: Some(backup.clone()),
                installed: true,
            }],
        )
        .expect_err("rollback restore error");
        assert_eq!(restore_error[0].code, CODE_WRITE_IO);
        fs::remove_file(backup).expect("backup cleanup");

        require_clean_staging(Vec::new()).expect("empty cleanup result");
        let cleanup_error =
            require_clean_staging(vec![io_diagnostic("cleanup".to_owned(), Some(temp.path()))])
                .expect_err("cleanup diagnostic");
        assert_eq!(cleanup_error[0].code, CODE_WRITE_IO);
    }

    #[cfg(unix)]
    #[test]
    fn directory_and_staging_cleanup_failures_are_diagnostics() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let locked = temp.path().join("locked");
        fs::create_dir(&locked).expect("locked directory");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("lock directory");
        let create_error = create_directories(&locked.join("child"), &mut Vec::new())
            .expect_err("locked parent inspection");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlock directory");
        assert_eq!(create_error[0].code, CODE_WRITE_IO);

        let no_parent =
            create_directories(Path::new(""), &mut Vec::new()).expect_err("path without parent");
        assert_eq!(no_parent[0].code, CODE_WRITE_IO);

        let empty = temp.path().join("empty");
        fs::create_dir(&empty).expect("empty directory");
        assert!(
            finish_created_directories(Err(Vec::new()), vec![empty])
                .expect_err("empty cleanup result")
                .is_empty()
        );
        assert!(
            finish_created_directories(Err(Vec::new()), vec![temp.path().join("missing")])
                .expect_err("missing cleanup result")
                .is_empty()
        );
        let nonempty = temp.path().join("nonempty");
        fs::create_dir(&nonempty).expect("nonempty directory");
        fs::write(nonempty.join("file"), "x").expect("nonempty file");
        assert!(
            finish_created_directories(Err(Vec::new()), vec![nonempty.clone()])
                .expect_err("nonempty cleanup result")
                .is_empty()
        );
        fs::remove_dir_all(nonempty).expect("nonempty cleanup");
        let file = temp.path().join("file");
        fs::write(&file, "x").expect("file");
        assert_eq!(
            finish_created_directories(Err(Vec::new()), vec![file.clone()])
                .expect_err("file cleanup error")
                .len(),
            1
        );
        fs::remove_file(file).expect("file cleanup");

        let mut staging = StagingDirectories::default();
        let (nested, _) = staging.paths(temp.path()).expect("staging paths");
        fs::create_dir(&nested).expect("nested staging directory");
        fs::write(nested.join("file"), "x").expect("nested staging file");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000))
            .expect("lock staging directory");
        let staging_root = nested.parent().expect("staging root").to_path_buf();
        let cleanup_error = staging.close();
        assert_eq!(cleanup_error.len(), 1);
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .expect("unlock staging directory");
        fs::remove_dir_all(staging_root).expect("staging cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn writer_reports_create_delete_parent_file_and_manifest_io_failures() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path, value: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(value)).expect("permissions");
        }

        let create_temp = tempfile::tempdir().expect("tempdir");
        mode(create_temp.path(), 0o555);
        let create_error = write(&create_temp.path().join("new"), Vec::new()).expect_err("create");
        mode(create_temp.path(), 0o755);
        assert_eq!(create_error[0].code, CODE_WRITE_IO);

        let delete_temp = tempfile::tempdir().expect("tempdir");
        let delete_output = delete_temp.path().join("generated");
        write(&delete_output, vec![generated("old.ts", "old")]).expect("initial write");
        mode(&delete_output, 0o555);
        let delete_error = write(&delete_output, Vec::new()).expect_err("delete");
        mode(&delete_output, 0o755);
        assert_eq!(delete_error[0].code, CODE_WRITE_IO);

        let parent_temp = tempfile::tempdir().expect("tempdir");
        let parent_output = parent_temp.path().join("generated");
        fs::create_dir(&parent_output).expect("output");
        mode(&parent_output, 0o555);
        let parent_error =
            write(&parent_output, vec![generated("nested/a.ts", "a")]).expect_err("parent create");
        mode(&parent_output, 0o755);
        assert_eq!(parent_error[0].code, CODE_WRITE_IO);

        let file_temp = tempfile::tempdir().expect("tempdir");
        let file_output = file_temp.path().join("generated");
        write(&file_output, vec![generated("a.ts", "a")]).expect("initial write");
        mode(&file_output.join("a.ts"), 0o400);
        let file_error = write(&file_output, vec![generated("a.ts", "b")]).expect_err("file write");
        mode(&file_output.join("a.ts"), 0o600);
        assert_eq!(file_error[0].code, CODE_WRITE_IO);

        let manifest_path = file_output.join(MANIFEST_NAME);
        fs::write(
            &manifest_path,
            b"{\"manifestVersion\":1,\"files\":[\"a.ts\"]}",
        )
        .expect("noncanonical manifest");
        mode(&manifest_path, 0o400);
        let manifest_error =
            write(&file_output, vec![generated("a.ts", "a")]).expect_err("manifest write");
        mode(&manifest_path, 0o600);
        assert_eq!(manifest_error[0].code, CODE_WRITE_IO);
    }

    #[cfg(unix)]
    #[test]
    fn drift_and_manifest_permission_failures_are_reported() {
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &Path, value: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(value)).expect("permissions");
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let output = temp.path().join("generated");
        let files = vec![generated("a.ts", "a")];
        write(&output, files.clone()).expect("initial write");
        mode(&output.join("a.ts"), 0o000);
        let report = check_drift(&output, files.clone());
        mode(&output.join("a.ts"), 0o600);
        assert_eq!(report.diagnostics[0].code, CODE_WRITE_IO);

        mode(&output.join(MANIFEST_NAME), 0o000);
        let report = check_drift(&output, files);
        mode(&output.join(MANIFEST_NAME), 0o600);
        assert_eq!(report.diagnostics[0].code, CODE_WRITE_IO);
    }

    #[cfg(unix)]
    #[test]
    fn target_validation_rejects_parent_and_target_filesystem_hazards() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().expect("tempdir");
        let output = fs::canonicalize(temp.path()).expect("canonical output");

        fs::write(output.join("parent-file"), "x").expect("parent file");
        assert_eq!(
            validate_target(&output, "parent-file/a.ts").expect_err("parent file")[0].code,
            CODE_PATH
        );

        symlink(output.join("missing"), output.join("dangling")).expect("dangling symlink");
        assert_eq!(
            validate_target(&output, "dangling/a.ts").expect_err("dangling")[0].code,
            CODE_WRITE_IO
        );

        symlink(output.join("parent-file"), output.join("file-link")).expect("file symlink");
        assert_eq!(
            validate_target(&output, "file-link/a.ts").expect_err("file symlink")[0].code,
            CODE_PATH
        );

        symlink(output.join("parent-file"), output.join("target-link")).expect("target symlink");
        assert_eq!(
            validate_target(&output, "target-link").expect_err("target symlink")[0].code,
            CODE_PATH
        );
        fs::create_dir(output.join("target-dir")).expect("target dir");
        assert_eq!(
            validate_target(&output, "target-dir").expect_err("target dir")[0].code,
            CODE_PATH
        );

        let locked = output.join("locked");
        fs::create_dir(&locked).expect("locked dir");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("lock");
        let error = validate_target(&output, "locked/inside/a.ts").expect_err("locked target");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlock");
        assert_eq!(error[0].code, CODE_WRITE_IO);
    }

    #[test]
    fn diagnostic_helpers_cover_optional_path() {
        let diagnostic = io_diagnostic("io".to_owned(), None);
        assert_eq!(diagnostic.code, CODE_WRITE_IO);
        assert!(diagnostic.source_id.is_none());
        assert_eq!(path_diagnostic("bad", "reason").code, CODE_PATH);

        let error = validate_target_metadata(
            "blocked.ts",
            Path::new("blocked.ts"),
            Err(std::io::Error::from(ErrorKind::PermissionDenied)),
        )
        .expect_err("metadata failure");
        assert_eq!(error[0].code, CODE_WRITE_IO);
    }
}
