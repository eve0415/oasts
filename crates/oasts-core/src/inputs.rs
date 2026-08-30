//! The filesystem paths one compile depended on.
//!
//! A compile reads more than the document graph: the configuration file, the consumer's tsconfig
//! and everything its `extends` chain reaches, and the peer manifests the artifact warnings are
//! judged against. Nothing in an ordinary run needs to know that set, so recording is opt-in — a
//! host that never asks pays no allocation for it, which keeps the pinned allocation counters in
//! `bench/allocs.yaml` answering for the same work they always did. That only holds if a caller
//! asks [`InputRecorder::is_recording`] before *building* whatever it would record: handing
//! `record` a path it goes on to discard has already paid for the path.
//!
//! Recorded paths are *candidates*, not survivors: a path that was probed for and found missing is
//! recorded too, because its appearance would change the next run's answer. Config discovery and
//! the `tsconfig.json` ancestor walk both turn on exactly that.

use std::path::{Path, PathBuf};

use crate::config::WatchConfig;

/// Whether a recorded input names a directory or a file.
///
/// A watching host registers a directory as itself and a file through the directory containing it,
/// and it may not decide which by asking the filesystem: a path is a directory because the
/// configuration means it as one, and whatever happens to exist at that name when a watcher looks
/// must not change what the run depended on. A trust root that is not there yet is exactly the
/// case, and it is the case the recording exists for.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum InputKind {
    /// A directory the run depended on: the workspace root, or a `local.allowPaths` entry.
    ///
    /// Ordered before [`InputKind::File`] so that a path recorded both ways deduplicates to the
    /// directory, which is the wider registration and cannot be wrong.
    Directory,
    /// A document, manifest, or configuration file.
    #[default]
    File,
}

/// One path a run depended on, and how a host should watch it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WatchInput {
    pub path: PathBuf,
    pub kind: InputKind,
}

/// Accumulates the paths a run depended on, or discards them when no host asked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InputRecorder {
    recording: bool,
    inputs: Vec<WatchInput>,
}

impl InputRecorder {
    /// A recorder that discards everything, for a run nobody is watching.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            recording: false,
            inputs: Vec::new(),
        }
    }

    /// A recorder that keeps every path it is given.
    #[must_use]
    pub const fn on() -> Self {
        Self {
            recording: true,
            inputs: Vec::new(),
        }
    }

    /// Whether anything is being kept, so a caller can skip work only a recording run needs.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recording
    }

    /// Notes one file the run read, or probed for and did not find.
    pub fn record(&mut self, path: &Path) {
        self.push(path, InputKind::File);
    }

    /// Notes several files at once.
    pub fn record_all<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        for path in paths {
            self.record(path);
        }
    }

    /// Notes one directory the run depended on, whether or not it exists.
    pub fn record_directory(&mut self, path: &Path) {
        self.push(path, InputKind::Directory);
    }

    /// Notes several directories at once.
    pub fn record_all_directories<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        for path in paths {
            self.record_directory(path);
        }
    }

    fn push(&mut self, path: &Path, kind: InputKind) {
        if self.recording {
            self.inputs.push(WatchInput {
                path: path.to_path_buf(),
                kind,
            });
        }
    }

    /// The recorded inputs, sorted and deduplicated so two runs over the same tree agree.
    #[must_use]
    pub fn into_inputs(mut self) -> Vec<WatchInput> {
        self.inputs.sort();
        // By path alone: a path recorded as both keeps the directory, which sorts first.
        self.inputs.dedup_by(|left, right| left.path == right.path);
        self.inputs
    }
}

/// What one spec of a run depended on, and where it writes.
///
/// One of these per spec rather than one merged set for the run: two specs read different
/// documents into different output roots, and a host that could not tell them apart would have to
/// treat every spec's output tree as every other spec's, which is how a run's own writes start
/// looking like a change worth recompiling for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecWatchPlan {
    /// The `specs` key this plan answers for; `None` for a configuration with one spec at the
    /// root, which is the shape every single-spec run keeps.
    pub name: Option<String>,
    /// Every path this spec read or probed for, sorted and deduplicated. A path that does not
    /// exist is still listed whenever its appearance would change the result.
    pub inputs: Vec<WatchInput>,
    /// The tree this spec writes into.
    ///
    /// Never an input. A watcher is told about it so it can tell its own writes apart from a
    /// change worth recompiling for.
    pub output_root: PathBuf,
}

/// Everything a watching host needs in order to keep going after one compile.
///
/// Reported by the compile rather than assembled by the host: the paths are only knowable from
/// inside the run that read them, and the settings come from the same load, so a host that read
/// the configuration separately could be watching for a compile that never happened.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchPlan {
    /// The paths the configuration file itself decides, whichever spec is being built: every name
    /// discovery would accept, and the file it found. Held once beside the specs rather than
    /// copied into each, because the workspace shape is a property of the whole file.
    pub inputs: Vec<WatchInput>,
    /// One plan per spec the run attempted, in the order the workspace declares them. A run that
    /// never reached a spec reports none, and a single-spec run reports exactly one.
    pub specs: Vec<SpecWatchPlan>,
    /// The `watch` block the run resolved, or its defaults when no configuration was read.
    pub settings: WatchConfig,
}

impl WatchPlan {
    /// Every path any part of the run depended on, sorted and deduplicated.
    ///
    /// Two specs sharing a document legitimately report it twice, and a host watches one path for
    /// it. Deduplication keeps the wider registration for the same reason a recorder does: a path
    /// one spec named as a directory is watched as a directory.
    #[must_use]
    pub fn watched_inputs(&self) -> Vec<WatchInput> {
        let mut inputs = self
            .inputs
            .iter()
            .chain(self.specs.iter().flat_map(|spec| spec.inputs.iter()))
            .cloned()
            .collect::<Vec<_>>();
        inputs.sort();
        inputs.dedup_by(|left, right| left.path == right.path);
        inputs
    }

    /// The output trees this run writes into, sorted and deduplicated.
    #[must_use]
    pub fn output_roots(&self) -> Vec<PathBuf> {
        let mut roots = self
            .specs
            .iter()
            .map(|spec| spec.output_root.clone())
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();
        roots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> WatchInput {
        WatchInput {
            path: PathBuf::from(path),
            kind: InputKind::File,
        }
    }

    fn directory(path: &str) -> WatchInput {
        WatchInput {
            path: PathBuf::from(path),
            kind: InputKind::Directory,
        }
    }

    #[test]
    fn a_recorder_that_is_off_keeps_nothing() {
        let mut recorder = InputRecorder::off();
        assert!(!recorder.is_recording());
        recorder.record(Path::new("/a"));
        recorder.record_all([Path::new("/b"), Path::new("/c")]);
        recorder.record_directory(Path::new("/d"));
        recorder.record_all_directories([Path::new("/e")]);
        assert!(recorder.into_inputs().is_empty());
    }

    #[test]
    fn a_recording_recorder_sorts_and_deduplicates() {
        let mut recorder = InputRecorder::on();
        assert!(recorder.is_recording());
        recorder.record(Path::new("/b"));
        recorder.record_all([Path::new("/a"), Path::new("/b")]);
        recorder.record_directory(Path::new("/c"));
        recorder.record_all_directories([Path::new("/c")]);
        assert_eq!(
            recorder.into_inputs(),
            vec![file("/a"), file("/b"), directory("/c")]
        );
    }

    #[test]
    fn a_path_recorded_as_both_keeps_the_directory() {
        let mut recorder = InputRecorder::on();
        // Whichever order they arrive in: the wider registration is the one that cannot be wrong.
        recorder.record(Path::new("/root"));
        recorder.record_directory(Path::new("/root"));
        assert_eq!(recorder.into_inputs(), vec![directory("/root")]);

        let mut recorder = InputRecorder::on();
        recorder.record_directory(Path::new("/root"));
        recorder.record(Path::new("/root"));
        assert_eq!(recorder.into_inputs(), vec![directory("/root")]);
    }

    #[test]
    fn a_watch_plan_defaults_to_watching_nothing() {
        assert_eq!(
            WatchPlan::default(),
            WatchPlan {
                inputs: Vec::new(),
                specs: Vec::new(),
                settings: WatchConfig::default(),
            }
        );
        assert!(WatchPlan::default().watched_inputs().is_empty());
        assert!(WatchPlan::default().output_roots().is_empty());
    }

    #[test]
    fn a_plan_unions_its_specs_and_keeps_the_wider_registration() {
        let plan = WatchPlan {
            inputs: vec![file("/oasts.yaml")],
            specs: vec![
                SpecWatchPlan {
                    name: Some("billing".to_owned()),
                    inputs: vec![file("/shared.yaml"), directory("/root")],
                    output_root: PathBuf::from("/out/billing"),
                },
                SpecWatchPlan {
                    name: Some("users".to_owned()),
                    // The same document, and the same root by the narrower name.
                    inputs: vec![file("/root"), file("/shared.yaml")],
                    output_root: PathBuf::from("/out/users"),
                },
            ],
            settings: WatchConfig::default(),
        };

        assert_eq!(
            plan.watched_inputs(),
            vec![
                file("/oasts.yaml"),
                directory("/root"),
                file("/shared.yaml")
            ]
        );
        assert_eq!(
            plan.output_roots(),
            vec![PathBuf::from("/out/billing"), PathBuf::from("/out/users")]
        );
    }
}
