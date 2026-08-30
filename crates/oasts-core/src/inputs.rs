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

/// Accumulates the paths a run depended on, or discards them when no host asked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InputRecorder {
    recording: bool,
    paths: Vec<PathBuf>,
}

impl InputRecorder {
    /// A recorder that discards everything, for a run nobody is watching.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            recording: false,
            paths: Vec::new(),
        }
    }

    /// A recorder that keeps every path it is given.
    #[must_use]
    pub const fn on() -> Self {
        Self {
            recording: true,
            paths: Vec::new(),
        }
    }

    /// Whether anything is being kept, so a caller can skip work only a recording run needs.
    #[must_use]
    pub const fn is_recording(&self) -> bool {
        self.recording
    }

    /// Notes one path the run read, or probed for and did not find.
    pub fn record(&mut self, path: &Path) {
        if self.recording {
            self.paths.push(path.to_path_buf());
        }
    }

    /// Notes several paths at once.
    pub fn record_all<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        for path in paths {
            self.record(path);
        }
    }

    /// The recorded paths, sorted and deduplicated so two runs over the same tree agree.
    #[must_use]
    pub fn into_paths(mut self) -> Vec<PathBuf> {
        self.paths.sort();
        self.paths.dedup();
        self.paths
    }
}

/// Everything a watching host needs in order to keep going after one compile.
///
/// Reported by the compile rather than assembled by the host: the paths are only knowable from
/// inside the run that read them, and the settings come from the same load, so a host that read
/// the configuration separately could be watching for a compile that never happened.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchPlan {
    /// Every path the run read or probed for, sorted and deduplicated. A path that does not exist
    /// is still listed whenever its appearance would change the result.
    pub inputs: Vec<PathBuf>,
    /// The tree the run writes into, when the configuration resolved far enough to name one.
    ///
    /// Never an input. A watcher is told about it so it can tell its own writes apart from a
    /// change worth recompiling for.
    pub output_root: Option<PathBuf>,
    /// The `watch` block the run resolved, or its defaults when no configuration was read.
    pub settings: WatchConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorder_that_is_off_keeps_nothing() {
        let mut recorder = InputRecorder::off();
        assert!(!recorder.is_recording());
        recorder.record(Path::new("/a"));
        recorder.record_all([Path::new("/b"), Path::new("/c")]);
        assert!(recorder.into_paths().is_empty());
    }

    #[test]
    fn a_recording_recorder_sorts_and_deduplicates() {
        let mut recorder = InputRecorder::on();
        assert!(recorder.is_recording());
        recorder.record(Path::new("/b"));
        recorder.record_all([Path::new("/a"), Path::new("/b")]);
        assert_eq!(
            recorder.into_paths(),
            vec![PathBuf::from("/a"), PathBuf::from("/b")]
        );
    }

    #[test]
    fn a_watch_plan_defaults_to_watching_nothing() {
        assert_eq!(
            WatchPlan::default(),
            WatchPlan {
                inputs: Vec::new(),
                output_root: None,
                settings: WatchConfig::default(),
            }
        );
    }
}
