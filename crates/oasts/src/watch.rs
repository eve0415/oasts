//! The `watch` command: compile once, then compile again whenever an input changes.
//!
//! A session never exits on its own. Diagnostics are reported and the loop keeps going, because a
//! typo in a document is the ordinary case a watch exists for — ending the session there would
//! make the command useless exactly when it is wanted. The only exits are the interrupt that
//! stops the process and a failure to register the watch at all, which is the one condition under
//! which no promise about freshness can be kept.
//!
//! What gets watched is the *directory* holding each input rather than the input itself. Editors
//! save through a temporary file and rename over the target, which replaces the inode a per-file
//! watch is bound to and silently kills it; a directory watch survives that. Watching directories
//! also answers the question config discovery asks — whether a second `oasts.*` name has appeared
//! — and it costs nothing extra, because events are filtered against the paths the compile
//! actually depended on before any of them counts as a change.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use oasts_core::diag::Diagnostic;
use oasts_core::driver::{self, Command, ConfigSource, Outcome, Tracking, Unsupported};
use oasts_core::inputs::WatchPlan;

/// Failure to register a filesystem watch, which is the only way a session ends unasked.
const CODE_WATCH_IO: &str = "OASTS1031";

/// What a change source reported.
#[derive(Debug)]
pub(crate) enum Wake {
    /// One path the filesystem reported an event for.
    Changed(PathBuf),
    /// Events were lost and the watcher cannot say which. Everything it was watching is suspect.
    Desynchronized,
    /// Nothing arrived. Asked with a deadline this means the tree went quiet; asked without one it
    /// only means the source has nothing yet and should be asked again.
    Quiet,
    /// The source will report nothing further, so the session cannot answer for freshness and
    /// must end saying so.
    Stopped,
}

/// Where a session's change notifications come from.
///
/// The loop is written against this rather than against a watcher directly, so its coalescing and
/// filtering can be driven through the exact event sequences a real filesystem only produces by
/// luck — an event during a compile, an event for a file nobody read, a burst from one save.
pub(crate) trait Changes {
    /// Replaces the watched set with `directories`.
    fn watch(&mut self, directories: &[PathBuf]) -> Result<(), String>;

    /// Waits for the next event, up to `quiet` when a deadline is given.
    fn wake(&mut self, quiet: Option<Duration>) -> Wake;
}

/// Whether an event says a file changed, rather than that somebody looked at one.
///
/// Reads are reported too, and every compile reads its own inputs: without this a session would
/// recompile forever, each run's reads waking the next one. Nothing is lost by ignoring them,
/// because a write that follows a read is reported on its own.
const fn changes_content(kind: EventKind) -> bool {
    !matches!(kind, EventKind::Access(_))
}

/// What one raw watcher event means to a session.
///
/// The two failure shapes both mean the same thing here. A kernel queue that overflowed arrives as
/// an event flagged for rescan and carrying no paths at all, and a watcher that could not read its
/// own queue arrives as an error; either way some change happened and nobody can say which file it
/// was. Dropping those would be the one outcome a watch may not have — silently serving output
/// that is out of date — so both recompile blind.
fn signals(event: notify::Result<notify::Event>) -> Vec<Signal> {
    let Ok(event) = event else {
        return vec![Signal::Desynchronized];
    };
    if event.need_rescan() {
        return vec![Signal::Desynchronized];
    }
    if !changes_content(event.kind) {
        return Vec::new();
    }
    event.paths.into_iter().map(Signal::Changed).collect()
}

/// One thing the watcher told the session.
#[derive(Debug)]
enum Signal {
    Changed(PathBuf),
    Desynchronized,
}

/// The real filesystem, through one recursive-off watcher per session.
pub(crate) struct FsChanges {
    /// Kept as the result it came back as, rather than reported at construction: a watcher that
    /// could not be created and a directory that cannot be watched are the same failure to the
    /// session, and answering both from [`Changes::watch`] leaves it one way to fail.
    watcher: notify::Result<RecommendedWatcher>,
    events: Receiver<Signal>,
    watched: BTreeSet<PathBuf>,
}

impl FsChanges {
    /// Gives up every registration, so the next `watch` reopens the whole set.
    fn forget_all(&mut self) {
        if let Ok(watcher) = &mut self.watcher {
            for directory in &self.watched {
                // A directory that has since been removed cannot be unwatched and does not need
                // to be; what matters is that this one stops counting as registered.
                let _ = watcher.unwatch(directory);
            }
        }
        self.watched.clear();
    }

    fn new() -> Self {
        let (sender, events) = mpsc::channel();
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            for signal in signals(event) {
                // A dropped receiver means the session is over; there is nothing to report it to.
                let _ = sender.send(signal);
            }
        });
        Self {
            watcher,
            events,
            watched: BTreeSet::new(),
        }
    }
}

impl Changes for FsChanges {
    fn watch(&mut self, directories: &[PathBuf]) -> Result<(), String> {
        let watcher = match &mut self.watcher {
            Ok(watcher) => watcher,
            Err(error) => return Err(error.to_string()),
        };
        let wanted = directories.iter().cloned().collect::<BTreeSet<_>>();
        for stale in self.watched.difference(&wanted) {
            // A directory that has since been removed cannot be unwatched and does not need to be.
            let _ = watcher.unwatch(stale);
        }
        for fresh in wanted.difference(&self.watched) {
            watcher
                .watch(fresh, RecursiveMode::NonRecursive)
                .map_err(|error| format!("{}: {error}", fresh.display()))?;
        }
        self.watched = wanted;
        Ok(())
    }

    fn wake(&mut self, quiet: Option<Duration>) -> Wake {
        let received = match quiet {
            Some(quiet) => self.events.recv_timeout(quiet),
            None => self
                .events
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            // An event naming a watched directory itself, rather than something in it, may be that
            // directory being replaced — and a watch is bound to the directory that existed when it
            // was registered, so it goes deaf the moment a new one takes the name. Forgetting the
            // registration here is what makes the next one reopen it, and nothing can be said about
            // what the old watch missed in between.
            Ok(Signal::Changed(path)) if self.watched.remove(&path) => Wake::Desynchronized,
            Ok(Signal::Changed(path)) => Wake::Changed(path),
            // A watcher that lost events or failed outright cannot say which registration it lost
            // with it, so every one is given up and the next pass reopens them all. Keeping them
            // would leave a directory silently unwatched for the rest of the session.
            Ok(Signal::Desynchronized) => {
                self.forget_all();
                Wake::Desynchronized
            }
            Err(RecvTimeoutError::Timeout) => Wake::Quiet,
            Err(RecvTimeoutError::Disconnected) => Wake::Stopped,
        }
    }
}

/// What one compile left behind for the next wait.
#[derive(Default)]
struct Watched {
    inputs: BTreeSet<PathBuf>,
    output_root: Option<PathBuf>,
    /// Whether the last compile succeeded. A failed one widens what counts as a change, because
    /// the file that would fix it may be one the failed run never got far enough to read.
    settled: bool,
}

impl Watched {
    fn absorb(&mut self, plan: &WatchPlan, settled: bool) {
        if settled {
            self.inputs = plan.inputs.iter().cloned().collect();
        } else {
            // Never narrow on failure: a run that stopped at a broken document read less than the
            // one before it, and dropping the rest would strand the session.
            self.inputs.extend(plan.inputs.iter().cloned());
        }
        if plan.output_root.is_some() {
            self.output_root.clone_from(&plan.output_root);
        }
        self.settled = settled;
    }

    /// The directories to watch: one per input, or the nearest existing ancestor when the input's
    /// own directory is not there yet.
    ///
    /// Nothing is dropped. An input whose whole chain is missing yields the last directory the
    /// walk reached, and registering that either works or fails loudly — which is the point, since
    /// a path quietly left out of the watch set is a path the session has stopped answering for.
    fn directories(&self) -> Vec<PathBuf> {
        self.inputs
            .iter()
            .filter_map(|input| input.parent())
            .map(nearest_existing_directory)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Whether an event on `path` is worth a recompile.
    fn triggers(&self, path: &Path) -> bool {
        if self
            .output_root
            .as_ref()
            .is_some_and(|root| path.starts_with(root))
        {
            // Our own writes land here every successful cycle, so nothing under the output tree
            // counts unless the compile itself read it — which one path does, the `tsconfig.json`
            // the ancestor walk looks for beside the emitted files.
            return self.inputs.contains(path);
        }
        // Anything else while the last compile is broken: the fix may well be a file that run
        // never reached, and one wasted compile is cheaper than a session that cannot recover.
        self.inputs.contains(path) || !self.settled
    }
}

fn nearest_existing_directory(from: &Path) -> PathBuf {
    let mut candidate = from;
    loop {
        match candidate.parent() {
            Some(parent) if !candidate.is_dir() => candidate = parent,
            _ => return candidate.to_path_buf(),
        }
    }
}

/// How long a settling burst may hold a compile back before it runs anyway.
///
/// Coalescing waits for quiet, and a directory somebody else is writing into never goes quiet — a
/// bundler or test runner emitting into the output tree would otherwise hold a recompile off for
/// as long as it kept going. Churn may delay a compile; it may not cancel one.
const MAX_SETTLE: Duration = Duration::from_secs(1);

/// Waits until something worth recompiling for has changed and the tree has gone quiet again.
///
/// Coalescing is what makes one save one compile: a single editor write is several events, and an
/// edit landing while a compile runs queues behind it rather than starting a second one. Only
/// events that would themselves have started a compile keep the wait open — an event the filter
/// already rejected cannot postpone the compile it is not part of.
fn wait(watched: &Watched, changes: &mut dyn Changes, quiet: Duration, cap: Duration) -> bool {
    loop {
        let triggered = match changes.wake(None) {
            Wake::Stopped => return false,
            Wake::Quiet => false,
            Wake::Desynchronized => true,
            Wake::Changed(path) => watched.triggers(&path),
        };
        if !triggered {
            continue;
        }
        let capped = Instant::now() + cap;
        let mut settled = Instant::now() + quiet;
        loop {
            let remaining = settled
                .min(capped)
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            match changes.wake(Some(remaining)) {
                Wake::Quiet => return true,
                Wake::Stopped => return false,
                // Only an event that would itself have started a compile keeps the wait open. One
                // the filter has already rejected cannot postpone the compile it is not part of.
                Wake::Desynchronized => settled = Instant::now() + quiet,
                Wake::Changed(path) => {
                    if watched.triggers(&path) {
                        settled = Instant::now() + quiet;
                    }
                }
            }
        }
    }
}

fn watch_failed(reason: &str) -> Outcome {
    Outcome {
        exit_code: 2,
        stdout_summary: None,
        diagnostics: vec![Diagnostic::config(
            CODE_WATCH_IO,
            format!("failed to watch for changes: {reason}"),
        )],
        drift_lines: Vec::new(),
        watch_plan: None,
    }
}

/// Runs one watch session, compiling through `compile` and rendering through `report`.
pub(crate) fn session(
    changes: &mut dyn Changes,
    compile: &mut dyn FnMut() -> Outcome,
    report: &mut dyn FnMut(Outcome) -> u8,
) -> u8 {
    let mut watched = Watched::default();
    loop {
        let mut outcome = compile();
        let settled = outcome.exit_code == 0;
        // Only a tracked run reports a plan, and `run` always tracks — so the default here stands
        // for a caller that asked for no plan at all.
        let plan = outcome.watch_plan.take().unwrap_or_default();
        let quiet = Duration::from_millis(u64::from(plan.settings.debounce_ms));
        watched.absorb(&plan, settled);
        report(outcome);

        let directories = watched.directories();
        // Nothing to watch is not a session: no event could ever arrive, so waiting would be a
        // process that looks alive and answers for nothing.
        if directories.is_empty() {
            return report(watch_failed("the compile reported no inputs to watch"));
        }
        if let Err(reason) = changes.watch(&directories) {
            return report(watch_failed(&reason));
        }
        if !wait(&watched, changes, quiet, MAX_SETTLE) {
            // Not a clean end: nothing in the product asks a session to stop, so a source that has
            // stopped reporting is a watcher that died under it. Exiting 0 there would say the run
            // was fine and leave whoever asked for a watch with no watch and no reason.
            return report(watch_failed(
                "the filesystem watcher stopped reporting changes",
            ));
        }
    }
}

/// Runs `oasts watch` for one working directory.
pub(crate) fn run(
    config_path: Option<&Path>,
    specs: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    // Refused before any watcher exists, matching where the other commands answer it.
    if !specs.is_empty() {
        return crate::cli::report(driver::refuse(Unsupported::SpecSelection), stdout, stderr);
    }
    let mut changes = FsChanges::new();
    session(
        &mut changes,
        &mut || {
            driver::run(
                Command::Generate { check: false },
                ConfigSource::Path {
                    explicit: config_path,
                    cwd,
                },
                Tracking::Watch,
            )
        },
        &mut |outcome| crate::cli::report(outcome, stdout, stderr),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Receiver as TestReceiver;

    use oasts_core::config::WatchConfig;

    use super::*;

    /// A change source that replays exactly the sequence a test wants to see.
    #[derive(Default)]
    struct Scripted {
        wakes: VecDeque<Wake>,
        registered: Vec<Vec<PathBuf>>,
        refuse: Option<String>,
        /// Returned once the script runs out, for a test that needs a source with no end.
        repeat: Option<PathBuf>,
    }

    impl Changes for Scripted {
        fn watch(&mut self, directories: &[PathBuf]) -> Result<(), String> {
            self.registered.push(directories.to_vec());
            match &self.refuse {
                Some(reason) => Err(reason.clone()),
                None => Ok(()),
            }
        }

        fn wake(&mut self, _quiet: Option<Duration>) -> Wake {
            match self.wakes.pop_front() {
                Some(wake) => wake,
                None => match &self.repeat {
                    Some(path) => Wake::Changed(path.clone()),
                    None => Wake::Stopped,
                },
            }
        }
    }

    fn plan(inputs: &[&str], output_root: Option<&str>, debounce_ms: u32) -> WatchPlan {
        WatchPlan {
            inputs: inputs.iter().map(PathBuf::from).collect(),
            output_root: output_root.map(PathBuf::from),
            settings: WatchConfig { debounce_ms },
        }
    }

    fn outcome(exit_code: u8, plan: Option<WatchPlan>) -> Outcome {
        Outcome {
            exit_code,
            stdout_summary: None,
            diagnostics: Vec::new(),
            drift_lines: Vec::new(),
            watch_plan: plan,
        }
    }

    #[test]
    fn a_watch_set_replaces_on_success_and_only_widens_on_failure() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/a.yaml"], Some("/w/out"), 5), true);
        assert_eq!(watched.inputs.len(), 1);

        // A failed run read less; the set it read must not be all that stays watched.
        watched.absorb(&plan(&["/w/oasts.yaml"], None, 5), false);
        assert!(watched.inputs.contains(Path::new("/w/a.yaml")));
        assert!(watched.inputs.contains(Path::new("/w/oasts.yaml")));
        assert_eq!(watched.output_root, Some(PathBuf::from("/w/out")));

        // The next success is authoritative again, so a dropped reference stops being watched.
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), true);
        assert!(!watched.inputs.contains(Path::new("/w/a.yaml")));
    }

    #[test]
    fn only_inputs_trigger_once_a_compile_has_settled() {
        let mut watched = Watched::default();
        watched.absorb(
            &plan(
                &["/w/oasts.yaml", "/w/out/tsconfig.json"],
                Some("/w/out"),
                5,
            ),
            true,
        );
        assert!(watched.triggers(Path::new("/w/oasts.yaml")));
        // The one input inside the output tree still counts.
        assert!(watched.triggers(Path::new("/w/out/tsconfig.json")));
        // What the run itself wrote does not.
        assert!(!watched.triggers(Path::new("/w/out/types/index.ts")));
        assert!(!watched.triggers(Path::new("/w/unrelated.txt")));

        // While the last compile is broken, anything outside the output tree is worth retrying.
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), false);
        assert!(watched.triggers(Path::new("/w/unrelated.txt")));
        assert!(!watched.triggers(Path::new("/w/out/types/index.ts")));
    }

    #[test]
    fn watched_directories_fall_back_to_the_nearest_one_that_exists() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        fs::create_dir_all(root.join("spec")).expect("spec directory");
        let mut watched = Watched::default();
        watched.absorb(
            &plan(
                &[
                    root.join("spec/openapi.yaml").to_str().expect("utf-8"),
                    root.join("missing/deeper/api.yaml")
                        .to_str()
                        .expect("utf-8"),
                ],
                None,
                5,
            ),
            true,
        );
        assert_eq!(watched.directories(), vec![root.clone(), root.join("spec")]);
    }

    #[test]
    fn an_input_whose_whole_chain_is_missing_still_names_a_directory() {
        // Nothing is dropped: the walk runs out and hands back what it reached, which registers
        // or fails out loud rather than leaving the input silently unwatched.
        assert_eq!(
            nearest_existing_directory(Path::new("/oasts-nowhere-at-all")),
            PathBuf::from("/")
        );
        assert_eq!(
            nearest_existing_directory(Path::new("nowhere-at-all")),
            PathBuf::from("")
        );
    }

    #[test]
    fn waiting_coalesces_a_burst_and_ignores_paths_nothing_read() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), true);
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![
                // A source with nothing yet, asked without a deadline.
                Wake::Quiet,
                // A file the compile never read.
                Wake::Changed(PathBuf::from("/w/unrelated.txt")),
                // The real change, then the rest of one editor save.
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                Wake::Quiet,
            ]),
            ..Scripted::default()
        };
        assert!(wait(
            &watched,
            &mut changes,
            Duration::from_millis(5),
            MAX_SETTLE
        ));
        assert!(changes.wakes.is_empty());
    }

    #[test]
    fn churn_the_filter_rejects_does_not_hold_a_compile_back() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), true);
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                // Everything after this is the output tree being written by somebody else. None of
                // it would start a compile, so none of it may postpone one.
                Wake::Changed(PathBuf::from("/w/out/types/a.ts")),
                Wake::Changed(PathBuf::from("/w/out/types/b.ts")),
                Wake::Quiet,
            ]),
            ..Scripted::default()
        };
        assert!(wait(
            &watched,
            &mut changes,
            Duration::from_millis(5),
            MAX_SETTLE
        ));
        assert!(changes.wakes.is_empty());
    }

    #[test]
    fn unending_churn_delays_a_compile_but_never_cancels_it() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), true);
        // A source that never runs out: every wake is a real change, so the settling window is
        // refreshed forever and only the cap can end the wait.
        let mut changes = Scripted {
            repeat: Some(PathBuf::from("/w/oasts.yaml")),
            ..Scripted::default()
        };
        assert!(wait(
            &watched,
            &mut changes,
            Duration::from_millis(50),
            Duration::from_millis(20)
        ));
    }

    #[test]
    fn a_source_that_stops_mid_burst_ends_the_wait() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/oasts.yaml"], None, 5), true);
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                Wake::Stopped,
            ]),
            ..Scripted::default()
        };
        assert!(!wait(
            &watched,
            &mut changes,
            Duration::from_millis(5),
            MAX_SETTLE
        ));
    }

    #[test]
    fn a_session_recompiles_per_change_and_exits_zero_when_the_source_stops() {
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                Wake::Quiet,
                Wake::Changed(PathBuf::from("/w/oasts.yaml")),
                Wake::Quiet,
            ]),
            ..Scripted::default()
        };
        let mut compiles = 0_u32;
        let mut reported = Vec::new();
        let code = session(
            &mut changes,
            &mut || {
                compiles += 1;
                // The second run fails; the session must survive it.
                outcome(
                    u8::from(compiles == 2),
                    Some(plan(&["/w/oasts.yaml"], Some("/w/out"), 1)),
                )
            },
            &mut |outcome| {
                reported.push(outcome.exit_code);
                outcome.exit_code
            },
        );
        assert_eq!(code, 2, "a watcher that stopped is not a clean exit");
        assert_eq!(compiles, 3);
        assert_eq!(reported, vec![0, 1, 0, 2]);
        assert_eq!(changes.registered.len(), 3);
    }

    #[test]
    fn a_session_that_cannot_register_a_watch_reports_it_and_exits_two() {
        let mut changes = Scripted {
            refuse: Some("/w: permission denied".to_owned()),
            ..Scripted::default()
        };
        let mut reported = Vec::new();
        let code = session(
            &mut changes,
            &mut || outcome(0, Some(plan(&["/w/oasts.yaml"], None, 1))),
            &mut |outcome| {
                reported.extend(outcome.diagnostics.iter().map(|entry| entry.code));
                outcome.exit_code
            },
        );
        assert_eq!(code, 2);
        assert_eq!(reported, vec![CODE_WATCH_IO]);
    }

    #[test]
    fn a_first_cycle_with_nothing_to_watch_says_so_rather_than_waiting() {
        let mut changes = Scripted::default();
        let mut reported = Vec::new();
        let code = session(&mut changes, &mut || outcome(0, None), &mut |outcome| {
            reported.extend(outcome.diagnostics.iter().map(|entry| entry.code));
            outcome.exit_code
        });
        assert_eq!(code, 2);
        assert_eq!(reported, vec![CODE_WATCH_IO]);
        assert!(changes.registered.is_empty());
    }

    #[test]
    fn a_run_that_reported_no_plan_keeps_the_previous_watch_set() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let config = root.join("oasts.yaml");
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![Wake::Changed(config.clone()), Wake::Quiet]),
            ..Scripted::default()
        };
        let mut compiles = 0_u32;
        let code = session(
            &mut changes,
            &mut || {
                compiles += 1;
                if compiles == 1 {
                    outcome(
                        0,
                        Some(plan(&[config.to_str().expect("utf-8")], Some("/w/out"), 1)),
                    )
                } else {
                    outcome(2, None)
                }
            },
            &mut |outcome| outcome.exit_code,
        );
        assert_eq!(code, 2);
        assert_eq!(changes.registered[1], vec![root]);
    }

    #[test]
    fn reads_do_not_count_as_changes() {
        assert!(!changes_content(EventKind::Access(
            notify::event::AccessKind::Open(notify::event::AccessMode::Any)
        )));
        assert!(changes_content(EventKind::Modify(
            notify::event::ModifyKind::Data(notify::event::DataChange::Any)
        )));
    }

    #[test]
    fn lost_events_and_watcher_errors_both_mean_recompile_blind() {
        let modified = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path(PathBuf::from("/w/oasts.yaml"));
        assert!(matches!(
            signals(Ok(modified)).as_slice(),
            [Signal::Changed(path)] if path == Path::new("/w/oasts.yaml")
        ));

        let read = notify::Event::new(EventKind::Access(notify::event::AccessKind::Any))
            .add_path(PathBuf::from("/w/oasts.yaml"));
        assert!(signals(Ok(read)).is_empty());

        // What the kernel sends when its queue overflowed: no paths, and a flag saying so.
        let overflowed = notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        assert!(matches!(
            signals(Ok(overflowed)).as_slice(),
            [Signal::Desynchronized]
        ));

        assert!(matches!(
            signals(Err(notify::Error::generic("queue read failed"))).as_slice(),
            [Signal::Desynchronized]
        ));
    }

    #[test]
    fn a_desynchronized_watcher_recompiles_without_a_path_to_blame() {
        let mut watched = Watched::default();
        watched.absorb(&plan(&["/w/oasts.yaml"], Some("/w/out"), 5), true);
        let mut changes = Scripted {
            wakes: VecDeque::from(vec![
                Wake::Desynchronized,
                Wake::Desynchronized,
                Wake::Quiet,
            ]),
            ..Scripted::default()
        };
        assert!(wait(
            &watched,
            &mut changes,
            Duration::from_millis(5),
            MAX_SETTLE
        ));
        assert!(changes.wakes.is_empty());
    }

    #[test]
    fn the_real_watcher_refuses_a_directory_that_is_not_there() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut changes = FsChanges::new();
        let missing = temp.path().join("missing");
        let reason = changes
            .watch(std::slice::from_ref(&missing))
            .expect_err("a missing directory cannot be watched");
        assert!(
            reason.starts_with(&missing.display().to_string()),
            "{reason}"
        );
    }

    #[test]
    fn the_real_watcher_drops_directories_it_no_longer_needs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir_all(&first).expect("first");
        fs::create_dir_all(&second).expect("second");
        let mut changes = FsChanges::new();
        changes
            .watch(std::slice::from_ref(&first))
            .expect("first watch");
        changes
            .watch(std::slice::from_ref(&second))
            .expect("second watch");
        assert_eq!(changes.watched, BTreeSet::from([second]));
    }

    #[test]
    fn a_disconnected_source_stops_the_session() {
        let (sender, events) = mpsc::channel::<Signal>();
        drop(sender);
        let mut changes = FsChanges {
            // Waking never touches the watcher, and a real one here would be an event handler no
            // passing run ever calls.
            watcher: Err(notify::Error::generic("unused")),
            events,
            watched: BTreeSet::new(),
        };
        assert!(matches!(changes.wake(None), Wake::Stopped));
        assert!(matches!(changes.wake(Some(Duration::ZERO)), Wake::Stopped));
    }

    #[test]
    fn a_watcher_that_could_not_be_created_is_reported_as_a_watch_failure() {
        let (_sender, events) = mpsc::channel::<Signal>();
        let mut changes = FsChanges {
            watcher: Err(notify::Error::generic("no watchers left")),
            events,
            watched: BTreeSet::new(),
        };
        let reason = changes
            .watch(&[PathBuf::from("/")])
            .expect_err("no watcher, no watch");
        assert!(reason.contains("no watchers left"), "{reason}");
    }

    #[test]
    fn a_watched_directory_that_is_replaced_is_registered_again() {
        let temp = tempfile::tempdir().expect("tempdir");
        let watched = temp.path().join("spec");
        fs::create_dir_all(&watched).expect("spec directory");
        let mut changes = FsChanges::new();
        changes
            .watch(std::slice::from_ref(&watched))
            .expect("first watch");

        // What the kernel reports when the directory a watch is bound to goes away.
        fs::remove_dir_all(&watched).expect("replace the directory");
        fs::create_dir_all(&watched).expect("recreate the directory");
        let mut woke = Vec::new();
        while let wake @ (Wake::Changed(_) | Wake::Desynchronized) =
            changes.wake(Some(Duration::from_millis(200)))
        {
            woke.push(matches!(wake, Wake::Desynchronized));
        }
        assert!(woke.contains(&true), "{woke:?}");

        // The registration is gone, so the next one reopens the directory that is there now.
        changes
            .watch(std::slice::from_ref(&watched))
            .expect("rewatch");
        fs::write(watched.join("api.yaml"), "openapi: 3.1.0\n").expect("write into it");
        assert!(matches!(
            changes.wake(Some(Duration::from_secs(5))),
            Wake::Changed(_)
        ));
    }

    #[test]
    fn a_lost_event_reaches_the_session_through_the_real_source() {
        let (sender, events) = mpsc::channel::<Signal>();
        sender.send(Signal::Desynchronized).expect("queued signal");
        let mut changes = FsChanges {
            watcher: Err(notify::Error::generic("unused")),
            events,
            watched: BTreeSet::from([PathBuf::from("/w")]),
        };
        assert!(matches!(changes.wake(None), Wake::Desynchronized));
        // Waking on a lost event is what gives the registrations up.
        assert!(changes.watched.is_empty());
    }

    #[test]
    fn a_watcher_that_lost_events_gives_up_every_registration() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir_all(&first).expect("first");
        fs::create_dir_all(&second).expect("second");
        let mut changes = FsChanges::new();
        changes
            .watch(&[first.clone(), second.clone()])
            .expect("watch both");

        // Nothing in a pathless failure says which registration went with it, so none may be
        // assumed to have survived.
        changes.forget_all();
        assert!(changes.watched.is_empty());

        // The next pass reopens them, and the reopened watch reports again.
        changes
            .watch(&[first.clone(), second])
            .expect("rewatch after giving up");
        fs::write(first.join("api.yaml"), "openapi: 3.1.0\n").expect("write");
        assert!(matches!(
            changes.wake(Some(Duration::from_secs(5))),
            Wake::Changed(_)
        ));
    }

    #[test]
    fn an_idle_real_watcher_reports_quiet() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut changes = FsChanges::new();
        changes
            .watch(std::slice::from_ref(&temp.path().to_path_buf()))
            .expect("watch the temp directory");
        assert!(matches!(
            changes.wake(Some(Duration::from_millis(20))),
            Wake::Quiet
        ));
    }

    /// Ends the session however the test body leaves — a failed assertion included, which would
    /// otherwise leave `thread::scope` waiting on a session nothing had told to stop.
    struct StopOnDrop<'a>(&'a AtomicBool);

    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// The real watcher, ended once the test has seen everything it asked for.
    ///
    /// Wrapping rather than signalling through the watcher keeps the production source free of a
    /// shutdown path nothing in the product uses; every line under test here is the real one.
    struct UntilDone<'a> {
        inner: FsChanges,
        done: &'a AtomicBool,
        /// Announces that the watch is registered. Editing before that would race the session and
        /// lose the event, which is a test artefact rather than anything a person would hit.
        armed: mpsc::Sender<()>,
    }

    impl Changes for UntilDone<'_> {
        fn watch(&mut self, directories: &[PathBuf]) -> Result<(), String> {
            let registered = self.inner.watch(directories);
            let _ = self.armed.send(());
            registered
        }

        fn wake(&mut self, quiet: Option<Duration>) -> Wake {
            if self.done.load(Ordering::SeqCst) {
                return Wake::Stopped;
            }
            // A blocking wait becomes a short poll, so the stop flag is seen without an event.
            self.inner
                .wake(Some(quiet.unwrap_or(Duration::from_millis(20))))
        }
    }

    fn watch_fixture(root: &Path) {
        fs::create_dir_all(root.join("spec")).expect("spec directory");
        fs::create_dir_all(root.join("shared")).expect("shared directory");
        fs::create_dir_all(root.join("tsconfigs")).expect("tsconfig directory");
        // The referenced document lives in a directory of its own, and nothing else in the tree
        // does: a fixture whose only document is the entry cannot tell whether the set of
        // `$ref`-reached files is watched at all.
        fs::write(root.join("shared/components.yaml"), component(&["id"]))
            .expect("referenced document");
        fs::write(
            root.join("spec/openapi.yaml"),
            document(&["listThings"]).as_str(),
        )
        .expect("entry document");
        fs::write(
            root.join("tsconfigs/base.json"),
            r#"{ "compilerOptions": { "lib": ["ES2022"] } }"#,
        )
        .expect("extends base");
        fs::write(
            root.join("tsconfig.json"),
            r#"{ "extends": "./tsconfigs/base.json" }"#,
        )
        .expect("consumer tsconfig");
        fs::write(root.join("oasts.yaml"), config(&[])).expect("config");
    }

    /// Every operation answers with the same `$ref`, so the referenced file is reached from the
    /// entry rather than sitting beside it unread.
    fn document(operations: &[&str]) -> String {
        document_referencing("../shared/components.yaml", operations)
    }

    fn document_referencing(reference: &str, operations: &[&str]) -> String {
        let mut text =
            String::from("openapi: 3.1.0\ninfo: {title: watch, version: 1.0.0}\npaths:\n");
        for operation in operations {
            text.push_str(&format!(
                "  /{operation}:\n    get:\n      operationId: {operation}\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema: {{$ref: '{reference}#/Thing'}}\n"
            ));
        }
        text
    }

    fn component(properties: &[&str]) -> String {
        let mut text = String::from("Thing:\n  type: object\n  properties:\n");
        for property in properties {
            text.push_str(&format!("    {property}: {{type: string}}\n"));
        }
        text
    }

    fn config(extra: &[&str]) -> String {
        let mut text = String::from(
            "schemaVersion: 1\ninput:\n  path: ./spec/openapi.yaml\noutput: ./generated\nartifacts:\n  types: true\nwatch:\n  debounceMs: 10\n",
        );
        for line in extra {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// Waits for one full cycle: the compile is reported, then its watch is registered.
    fn await_cycle(ticks: &TestReceiver<u8>, armed: &TestReceiver<()>, what: &str) -> u8 {
        // Asserted rather than unwrapped with a closure: a closure that only runs when the test
        // fails is a function the 100% coverage floor counts and no passing run ever executes.
        let compiled = ticks.recv_timeout(Duration::from_secs(30));
        assert!(compiled.is_ok(), "no recompile after {what}: {compiled:?}");
        let registered = armed.recv_timeout(Duration::from_secs(30));
        assert!(
            registered.is_ok(),
            "no watch registered after {what}: {registered:?}"
        );
        compiled.expect("the compile was just asserted to have arrived")
    }

    #[test]
    fn a_real_session_recompiles_after_a_document_a_config_and_an_extends_change() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        watch_fixture(&root);

        let done = AtomicBool::new(false);
        let (ticks, tick_reader) = mpsc::channel();
        let (armed, armed_reader) = mpsc::channel();
        let compiles = std::sync::atomic::AtomicU32::new(0);

        std::thread::scope(|scope| {
            let _stop = StopOnDrop(&done);
            let session_root = root.clone();
            let ticks = ticks.clone();
            let done = &done;
            let compiles = &compiles;
            scope.spawn(move || {
                let mut changes = UntilDone {
                    inner: FsChanges::new(),
                    done,
                    armed,
                };
                session(
                    &mut changes,
                    &mut || {
                        compiles.fetch_add(1, Ordering::SeqCst);
                        driver::run(
                            Command::Generate { check: false },
                            ConfigSource::Path {
                                explicit: None,
                                cwd: &session_root,
                            },
                            Tracking::Watch,
                        )
                    },
                    &mut |outcome| {
                        let code = outcome.exit_code;
                        let _ = ticks.send(code);
                        code
                    },
                );
            });

            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "the first compile"),
                0
            );
            let emitted = root.join("generated/types/operations/listthings.ts");
            assert!(emitted.is_file(), "the first compile wrote nothing");

            // 1. The entry document, in its own directory.
            fs::write(
                root.join("spec/openapi.yaml"),
                document(&["listThings", "listOthers"]).as_str(),
            )
            .expect("edited document");
            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "a document change"),
                0
            );
            assert!(
                root.join("generated/types/operations/listothers.ts")
                    .is_file(),
                "the recompile did not emit the new operation"
            );

            // 2. The configuration file itself, reloaded rather than restarted.
            fs::write(root.join("oasts.yaml"), config(&["namespace: Watched"]))
                .expect("edited config");
            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "a config change"),
                0
            );

            // 3. A file the tsconfig `extends` chain reaches, two directories from the config.
            fs::write(
                root.join("tsconfigs/base.json"),
                r#"{ "compilerOptions": { "lib": ["ESNext"] } }"#,
            )
            .expect("edited extends base");
            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "an extends-chain change"),
                0
            );
        });

        assert_eq!(compiles.load(Ordering::SeqCst), 4);
    }

    /// The ordinary authoring order for a reference that does not resolve yet.
    ///
    /// Retarget a `$ref` at a directory nobody has created, make the directory, then write the
    /// file. A session that only reported the documents a *successful* load returned would have
    /// dropped every `$ref`-reached path the moment the load failed, leaving the directory holding
    /// them unwatched and the session unable to see either step.
    #[test]
    fn a_real_session_sees_a_ref_target_appear_after_the_load_that_wanted_it_failed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        watch_fixture(&root);

        let done = AtomicBool::new(false);
        let (ticks, tick_reader) = mpsc::channel();
        let (armed, armed_reader) = mpsc::channel();

        std::thread::scope(|scope| {
            let _stop = StopOnDrop(&done);
            let session_root = root.clone();
            let ticks = ticks.clone();
            let done = &done;
            scope.spawn(move || {
                let mut changes = UntilDone {
                    inner: FsChanges::new(),
                    done,
                    armed,
                };
                session(
                    &mut changes,
                    &mut || {
                        driver::run(
                            Command::Generate { check: false },
                            ConfigSource::Path {
                                explicit: None,
                                cwd: &session_root,
                            },
                            Tracking::Watch,
                        )
                    },
                    &mut |outcome| {
                        let code = outcome.exit_code;
                        let _ = ticks.send(code);
                        code
                    },
                );
            });

            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "the first compile"),
                0
            );

            // 1. Point the reference at a directory that is not there.
            fs::write(
                root.join("spec/openapi.yaml"),
                document_referencing("../later/components.yaml", &["listThings"]).as_str(),
            )
            .expect("retargeted document");
            assert_ne!(
                await_cycle(&tick_reader, &armed_reader, "an unresolvable reference"),
                0,
                "an unresolvable reference should report, not pass"
            );

            // 2. Create the directory. The compile still fails, and the session must be watching
            //    the new directory afterwards rather than only the one it used to read.
            fs::create_dir_all(root.join("later")).expect("later directory");
            assert_ne!(
                await_cycle(
                    &tick_reader,
                    &armed_reader,
                    "the missing directory appearing"
                ),
                0,
                "the directory alone does not resolve the reference"
            );

            // 3. Write the file the reference names.
            fs::write(root.join("later/components.yaml"), component(&["id"]))
                .expect("referenced document");
            assert_eq!(
                await_cycle(
                    &tick_reader,
                    &armed_reader,
                    "the referenced document appearing"
                ),
                0,
                "the session did not see the file that fixes the reference"
            );
        });
    }

    #[test]
    fn a_real_session_survives_a_broken_document_and_recovers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        watch_fixture(&root);

        let done = AtomicBool::new(false);
        let (ticks, tick_reader) = mpsc::channel();
        let (armed, armed_reader) = mpsc::channel();

        std::thread::scope(|scope| {
            let _stop = StopOnDrop(&done);
            let session_root = root.clone();
            let ticks = ticks.clone();
            let done = &done;
            scope.spawn(move || {
                let mut changes = UntilDone {
                    inner: FsChanges::new(),
                    done,
                    armed,
                };
                session(
                    &mut changes,
                    &mut || {
                        driver::run(
                            Command::Generate { check: false },
                            ConfigSource::Path {
                                explicit: None,
                                cwd: &session_root,
                            },
                            Tracking::Watch,
                        )
                    },
                    &mut |outcome| {
                        let code = outcome.exit_code;
                        let _ = ticks.send(code);
                        code
                    },
                );
            });

            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "the first compile"),
                0
            );
            fs::write(
                root.join("spec/openapi.yaml"),
                "openapi: 3.1.0\npaths: []\n",
            )
            .expect("broken document");
            assert_ne!(
                await_cycle(&tick_reader, &armed_reader, "a broken document"),
                0,
                "a broken document should report, not pass"
            );
            fs::write(
                root.join("spec/openapi.yaml"),
                document(&["listThings"]).as_str(),
            )
            .expect("repaired document");
            assert_eq!(
                await_cycle(&tick_reader, &armed_reader, "a repaired document"),
                0
            );
        });
    }

    /// Drives `run` end to end, through the real watcher and the real compiler.
    ///
    /// It terminates because the session cannot register a watch on the unreadable directory the
    /// entry document lives in — the one failure the loop is allowed to end on, reached here the
    /// way a person would reach it. The thread and deadline only turn a session that refuses to
    /// end into a failure rather than a hang.
    #[test]
    fn run_compiles_reports_and_ends_on_a_directory_it_cannot_watch() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        watch_fixture(&root);
        let spec = root.join("spec");
        fs::set_permissions(&spec, fs::Permissions::from_mode(0o000)).expect("seal the directory");

        let (finished, outcome_reader) = mpsc::channel();
        let session_root = root.clone();
        std::thread::spawn(move || {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run(None, &[], &session_root, &mut stdout, &mut stderr);
            let _ = finished.send((code, String::from_utf8(stderr).expect("UTF-8 stderr")));
        });
        let (code, stderr) = outcome_reader
            .recv_timeout(Duration::from_secs(30))
            .expect("the session ends on a directory it cannot watch");
        fs::set_permissions(&spec, fs::Permissions::from_mode(0o755)).expect("unseal");

        assert_eq!(code, 2, "{stderr}");
        assert!(stderr.contains("error[OASTS1031]"), "{stderr}");
    }

    #[test]
    fn run_refuses_a_spec_selection_before_it_watches_anything() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            None,
            &["petstore".to_owned()],
            temp.path(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 2);
        assert!(String::from_utf8_lossy(&stderr).contains("OASTS9002"));
    }
}
