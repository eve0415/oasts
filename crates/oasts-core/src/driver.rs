//! One orchestration for every host.
//!
//! The Rust CLI and the Node bindings both need the same sequence — load the
//! config, compile every selected spec, then either report drift or write — and
//! both need the same 0/1/2 exit codes out of it. Keeping that sequence here
//! means a host only decides how to render the [`Outcome`], never what the
//! outcome is.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::{
    self, CODE_SPEC_SELECTION, CODE_SPEC_UNKNOWN, ResolvedSpec, ResolvedWorkspace, WatchConfig,
};
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::emit::GeneratedFile;
use crate::inputs::{InputRecorder, SpecWatchPlan, WatchPlan};
use crate::source::FetcherHandle;
use crate::writer::{DriftState, check_drift, write};
use crate::{msw_peer, pipeline, zod_peer};

/// What the host asked the compiler to do.
#[derive(Clone, Copy, Debug)]
pub enum Command {
    /// Emit artifacts, or compare them against the working tree when `check`.
    Generate {
        /// Compare committed output byte for byte instead of writing it.
        check: bool,
    },
    /// Validate configuration and input without emitting artifacts.
    Check,
}

/// What a run reports besides its result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Tracking {
    /// Report the outcome only.
    #[default]
    Off,
    /// Also report what a watching host needs to wait for the next change.
    Watch,
}

/// Where the configuration comes from.
#[derive(Clone, Copy, Debug)]
pub enum ConfigSource<'a> {
    /// A data config the core reads and parses itself.
    Path {
        /// An explicit `--config` path, or `None` to discover one.
        explicit: Option<&'a Path>,
        /// Working directory discovery resolves against.
        cwd: &'a Path,
    },
    /// A script config the host already evaluated and serialized.
    Json {
        /// Path the evaluated config came from, for diagnostics.
        config_path: &'a Path,
        /// The evaluated default export, serialized as JSON.
        json: &'a [u8],
    },
}

/// Everything a host needs to render one run.
#[derive(Debug)]
pub struct Outcome {
    /// Process exit code per the 0/1/2 contract.
    pub exit_code: u8,
    /// Success summary for stdout, when the run succeeded.
    pub stdout_summary: Option<String>,
    /// Sorted diagnostics for stderr.
    pub diagnostics: Vec<Diagnostic>,
    /// `state: path` drift lines for stderr, when `--check` found drift.
    pub drift_lines: Vec<String>,
    /// What to keep watching, when the host asked for [`Tracking::Watch`].
    ///
    /// Carried on the outcome rather than fetched separately: a second pass would re-read a tree
    /// that has already moved on, and would answer for a compile nobody ran.
    pub watch_plan: Option<WatchPlan>,
}

impl Outcome {
    fn failed(sink: DiagnosticSink) -> Self {
        Self {
            exit_code: sink.worst_exit_code(),
            stdout_summary: None,
            diagnostics: sink.into_sorted_vec(),
            drift_lines: Vec::new(),
            watch_plan: None,
        }
    }

    fn succeeded(summary: &str, mut diagnostics: Vec<Diagnostic>) -> Self {
        diagnostics.sort();
        Self {
            exit_code: 0,
            stdout_summary: Some(summary.to_owned()),
            diagnostics,
            drift_lines: Vec::new(),
            watch_plan: None,
        }
    }

    fn with_watch_plan(mut self, tracked: Tracked) -> Self {
        if tracked.is_recording() {
            self.watch_plan = Some(WatchPlan {
                inputs: tracked.workspace.into_inputs(),
                specs: tracked.specs,
                settings: tracked.settings,
            });
        }
        self
    }
}

fn load(source: ConfigSource<'_>) -> Result<ResolvedWorkspace, Vec<Diagnostic>> {
    match source {
        ConfigSource::Path { explicit, cwd } => config::load_config(explicit, cwd),
        ConfigSource::Json { config_path, json } => {
            config::load_config_from_json(config_path, json)
        }
    }
}

/// One spec's compilation, held until every spec has compiled.
struct Compiled {
    spec: ResolvedSpec,
    files: Option<Vec<GeneratedFile>>,
    /// What this spec read, still open because the peer manifests are probed on the write path.
    inputs: InputRecorder,
}

/// What a tracked run accumulates for a watching host.
///
/// Carried alongside the compile rather than returned by it, because a run that failed still has
/// to say what it read: a session handed nothing to watch cannot see the edit that would fix it.
struct Tracked {
    /// The paths the configuration file itself decides, whichever spec is being built.
    workspace: InputRecorder,
    /// One plan per spec the run attempted, in workspace order.
    specs: Vec<SpecWatchPlan>,
    settings: WatchConfig,
}

impl Tracked {
    fn new(tracking: Tracking) -> Self {
        Self {
            workspace: match tracking {
                Tracking::Off => InputRecorder::off(),
                Tracking::Watch => InputRecorder::on(),
            },
            specs: Vec::new(),
            settings: WatchConfig::default(),
        }
    }

    const fn is_recording(&self) -> bool {
        self.workspace.is_recording()
    }

    /// A recorder for one spec, keeping exactly as much as the run as a whole was asked to keep.
    fn spec_recorder(&self) -> InputRecorder {
        if self.is_recording() {
            InputRecorder::on()
        } else {
            InputRecorder::off()
        }
    }

    /// Files one spec's finished plan.
    fn absorb(&mut self, spec: &ResolvedSpec, inputs: InputRecorder) {
        if !self.is_recording() {
            return;
        }
        self.specs.push(SpecWatchPlan {
            name: spec.name.clone(),
            inputs: inputs.into_inputs(),
            output_root: spec.config.output.clone(),
        });
    }

    /// Files every plan at once, for a run that ends before it reaches the write path.
    fn absorb_all(&mut self, compiled: Vec<Compiled>) {
        for entry in compiled {
            self.absorb(&entry.spec, entry.inputs);
        }
    }
}

/// Loads, compiles, and either reports drift or writes the generated files.
///
/// `selection` is the `--spec` names; empty selects every spec the configuration declares.
pub fn run(
    command: Command,
    source: ConfigSource<'_>,
    selection: &[String],
    fetcher: FetcherHandle,
    tracking: Tracking,
) -> Outcome {
    let mut tracked = Tracked::new(tracking);
    let outcome = compile(command, source, selection, fetcher, &mut tracked);
    outcome.with_watch_plan(tracked)
}

fn compile(
    command: Command,
    source: ConfigSource<'_>,
    selection: &[String],
    fetcher: FetcherHandle,
    tracked: &mut Tracked,
) -> Outcome {
    // Seeded before the load, so a run that never reaches a config still says which paths decide
    // whether the next one will. A watcher that gave up here could not see the config appear.
    record_config_candidates(source, &mut tracked.workspace);
    let mut sink = DiagnosticSink::new();
    let mut workspace = match load(source) {
        Ok(workspace) => workspace,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return Outcome::failed(sink);
        }
    };
    tracked.workspace.record(&workspace.config_path);
    // `watch` is a root-only key, so every spec resolved the same block and the first one answers
    // for the file. A file that declared no spec at all keeps the defaults seeded above.
    if let Some(spec) = workspace.specs.first() {
        tracked.settings = spec.config.watch;
    }
    sink.extend(std::mem::take(&mut workspace.diagnostics));

    let chosen = match select(&workspace, selection) {
        Ok(chosen) => chosen,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return Outcome::failed(sink);
        }
    };

    // Every selected spec compiles before anything is written, so a run that cannot produce one
    // spec's output leaves the whole workspace as it found it rather than half updated.
    let should_emit = matches!(command, Command::Generate { .. });
    let is_workspace = workspace.is_workspace();
    let workspace_root = workspace.workspace_root.clone();
    let mut compiled = Vec::new();
    for mut spec in workspace
        .specs
        .into_iter()
        .enumerate()
        .filter(|(index, _)| chosen.contains(index))
        .map(|(_, spec)| spec)
    {
        let mut inputs = tracked.spec_recorder();
        // The entry document as the config names it. The graph reports canonical paths for every
        // document it opened, which is the same file by another name — but only once it opens.
        //
        // `input.url` leaves the literal URI text here, and a URI is not a path anything can
        // watch: recorded, it would reach the watcher as a directory that cannot exist.
        // `is_rooted` is the same question the loader asks before it decides to open a file
        // rather than retrieve one.
        if crate::source::is_rooted(&spec.config.input) {
            inputs.record(&spec.config.input);
        }
        let mut spec_sink = DiagnosticSink::new();
        spec_sink.extend(std::mem::take(&mut spec.config.diagnostics));
        let files = pipeline::compile(
            &spec.config,
            fetcher.clone(),
            should_emit,
            &mut inputs,
            &mut spec_sink,
        );
        let mut diagnostics = spec_sink.into_vec();
        if let Some(name) = spec.name.as_deref() {
            for diagnostic in &mut diagnostics {
                diagnostic.spec = Some(Box::from(name));
            }
        }
        sink.extend(diagnostics);
        compiled.push(Compiled {
            spec,
            files,
            inputs,
        });
    }
    if sink.has_errors() {
        tracked.absorb_all(compiled);
        return Outcome::failed(sink);
    }
    let warnings = sink.into_sorted_vec();

    let Command::Generate { check } = command else {
        tracked.absorb_all(compiled);
        return Outcome::succeeded("check ok", warnings);
    };

    if check {
        return drift(compiled, &workspace_root, is_workspace, warnings, tracked);
    }
    emit(compiled, warnings, tracked)
}

fn record_config_candidates(source: ConfigSource<'_>, inputs: &mut InputRecorder) {
    // Asked before the candidates are built, not after: discovery mints eight owned paths, and a
    // run nobody is watching must not pay for them. `InputRecorder::record` discarding them is not
    // the same as never allocating them.
    if !inputs.is_recording() {
        return;
    }
    match source {
        ConfigSource::Path { explicit, cwd } => {
            inputs.record_all(
                config::discovery_candidates(cwd, explicit)
                    .iter()
                    .map(PathBuf::as_path),
            );
        }
        // A host that evaluated the config itself already knows where it came from, and the bytes
        // at that path were never read here — but it is still the file the run depends on.
        ConfigSource::Json { config_path, .. } => inputs.record(config_path),
    }
}

/// Resolves `--spec` names into the indices of the specs to build.
fn select(
    workspace: &ResolvedWorkspace,
    selection: &[String],
) -> Result<BTreeSet<usize>, Vec<Diagnostic>> {
    if selection.is_empty() {
        return Ok((0..workspace.specs.len()).collect());
    }
    let config_path = workspace.config_path.to_string_lossy();
    if !workspace.is_workspace() {
        return Err(vec![
            Diagnostic::config(
                CODE_SPEC_SELECTION,
                "--spec names one spec of a workspace, and this configuration declares a single \
                 spec at the root",
            )
            .with_source(config_path),
        ]);
    }
    let known = workspace
        .specs
        .iter()
        .filter_map(|spec| spec.name.as_deref())
        .collect::<BTreeSet<_>>();
    let requested = selection
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unknown = requested.difference(&known).collect::<Vec<_>>();
    if !unknown.is_empty() {
        let declared = known.iter().copied().collect::<Vec<_>>().join(", ");
        return Err(unknown
            .into_iter()
            .map(|name| {
                Diagnostic::config(
                    CODE_SPEC_UNKNOWN,
                    format!("no spec named '{name}'; this workspace declares {declared}"),
                )
                .with_source(config_path.clone())
            })
            .collect());
    }
    Ok(workspace
        .specs
        .iter()
        .enumerate()
        .filter(|(_, spec)| {
            spec.name
                .as_deref()
                .is_some_and(|name| requested.contains(name))
        })
        .map(|(index, _)| index)
        .collect())
}

/// The path prefix a drift line carries, so two specs' identically named files stay apart.
///
/// A single-spec run has one output root and keeps naming files relative to it. A workspace names
/// each file from the workspace root instead, which is a path the reader can open.
fn drift_prefix(spec: &ResolvedSpec, workspace_root: &Path, is_workspace: bool) -> String {
    if !is_workspace {
        return String::new();
    }
    let output = spec.config.output.as_path();
    let relative = output.strip_prefix(workspace_root).unwrap_or(output);
    format!("{}/", relative.to_string_lossy().replace('\\', "/"))
}

fn drift(
    compiled: Vec<Compiled>,
    workspace_root: &Path,
    is_workspace: bool,
    warnings: Vec<Diagnostic>,
    tracked: &mut Tracked,
) -> Outcome {
    let mut diagnostics = Vec::new();
    let mut drift_lines = Vec::new();
    for entry in compiled {
        tracked.absorb(&entry.spec, entry.inputs);
        // A successful emitting compile returns `Some`; `None` either means check-only or an
        // error, and both cases returned above.
        let files = entry
            .files
            .expect("successful emitting compilation returns generated files");
        let prefix = drift_prefix(&entry.spec, workspace_root, is_workspace);
        let mut report = check_drift(&entry.spec.config.output, files);
        if let Some(name) = entry.spec.name.as_deref() {
            for diagnostic in &mut report.diagnostics {
                diagnostic.spec = Some(Box::from(name));
            }
        }
        diagnostics.append(&mut report.diagnostics);
        drift_lines.extend(
            report
                .entries
                .iter()
                .filter(|entry| entry.state != DriftState::Clean)
                .map(|entry| format!("{}: {prefix}{}", entry.state, entry.relative_path)),
        );
    }
    if !diagnostics.is_empty() {
        let mut sink = DiagnosticSink::new();
        sink.extend(warnings);
        sink.extend(diagnostics);
        return Outcome::failed(sink);
    }
    if drift_lines.is_empty() {
        return Outcome::succeeded("check ok", warnings);
    }
    Outcome {
        exit_code: 1,
        stdout_summary: None,
        diagnostics: warnings,
        watch_plan: None,
        drift_lines,
    }
}

fn emit(compiled: Vec<Compiled>, mut warnings: Vec<Diagnostic>, tracked: &mut Tracked) -> Outcome {
    let mut summary = Vec::new();
    let mut failure = None;
    for entry in compiled {
        let config = &entry.spec.config;
        let mut inputs = entry.inputs;
        // Past a failed write nothing more is written, and the peer manifests answer for a tree
        // this run is no longer going to touch. The plan is still filed for every spec that
        // compiled: a session that stopped watching them could not see the edit that fixes this.
        if failure.is_none() {
            // Only on the write path: `--check` compares bytes for CI, where the consumer's
            // node_modules is neither inspected nor relevant.
            let mut peers = Vec::new();
            if config.artifacts.zod.enabled
                && let Some(diagnostic) = zod_peer::diagnose(&config.output, &mut inputs)
            {
                peers.push(diagnostic);
            }
            if config.artifacts.msw.enabled
                && let Some(diagnostic) = msw_peer::diagnose(&config.output, &mut inputs)
            {
                peers.push(diagnostic);
            }
            if let Some(name) = entry.spec.name.as_deref() {
                for diagnostic in &mut peers {
                    diagnostic.spec = Some(Box::from(name));
                }
            }
            warnings.append(&mut peers);
        }
        tracked.absorb(&entry.spec, inputs);
        if failure.is_some() {
            continue;
        }

        // A successful emitting compile returns `Some`; `None` either means check-only or an
        // error, and both cases returned above.
        let files = entry
            .files
            .expect("successful emitting compilation returns generated files");
        let generated_count = files.len();
        match write(&config.output, files) {
            Ok(_) => summary.push(match entry.spec.name.as_deref() {
                Some(name) => format!("{name}: generated {generated_count} files"),
                None => format!("generated {generated_count} files"),
            }),
            // Specs already written stay written; the summary of what did land is reported
            // beside the failure so the run says exactly how far it got.
            Err(diagnostics) => failure = Some(diagnostics),
        }
    }
    let Some(diagnostics) = failure else {
        return Outcome::succeeded(&summary.join("\n"), warnings);
    };
    let mut sink = DiagnosticSink::new();
    sink.extend(warnings);
    sink.extend(diagnostics);
    let mut outcome = Outcome::failed(sink);
    outcome.stdout_summary = (!summary.is_empty()).then(|| summary.join("\n"));
    outcome
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::diag::render_to_string;
    use crate::inputs::{InputKind, WatchInput};

    use super::*;

    #[test]
    fn run_preserves_config_warnings_once_in_deterministic_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            r#"openapi: 3.1.0
info: {title: test, version: 1.0.0}
paths:
  /things:
    get:
      operationId: listThings
      parameters:
        - {name: Cookie, in: header, schema: {type: string}}
      responses:
        '200':
          description: ok
          content:
            application/json: {}
"#,
        )
        .expect("OpenAPI document");
        fs::write(
            temp.path().join("oasts.yaml"),
            r#"schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  client: true
client:
  authEnforcement: types
validation:
  engine: off
"#,
        )
        .expect("config");
        let run_check = || {
            run(
                Command::Check,
                ConfigSource::Path {
                    explicit: None,
                    cwd: temp.path(),
                },
                &[],
                FetcherHandle::None,
                Tracking::Off,
            )
        };

        let first = run_check();
        let second = run_check();

        assert_eq!(first.exit_code, 0, "{:#?}", first.diagnostics);
        assert_eq!(
            first
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>(),
            ["OASTS0172", "OASTS5001"]
        );
        assert_eq!(
            first
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS0172")
                .count(),
            1
        );
        assert_eq!(
            render_to_string(first.diagnostics),
            render_to_string(second.diagnostics)
        );
    }
    /// One tree exercising every family of input a compile can depend on.
    fn tracked_workspace() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join("generated")).expect("output directory");
        fs::create_dir_all(root.join("node_modules/zod")).expect("peer directory");
        fs::write(
            root.join("node_modules/zod/package.json"),
            r#"{"version": "1.0.0"}"#,
        )
        .expect("peer manifest");
        fs::write(
            root.join("components.yaml"),
            r#"Thing: {type: object, properties: {id: {type: string}}}
"#,
        )
        .expect("referenced document");
        fs::write(
            root.join("openapi.yaml"),
            r#"openapi: 3.1.0
info: {title: test, version: 1.0.0}
paths:
  /things:
    get:
      operationId: listThings
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {$ref: './components.yaml#/Thing'}
"#,
        )
        .expect("entry document");
        fs::write(
            root.join("base.json"),
            r#"{ "compilerOptions": { "lib": ["ESNext"] } }"#,
        )
        .expect("extends base");
        fs::write(
            root.join("tsconfig.json"),
            r#"{ "extends": "./base.json" }"#,
        )
        .expect("consumer tsconfig");
        fs::write(
            root.join("oasts.yaml"),
            r#"schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  client: true
  zod: true
client:
  authEnforcement: types
validation:
  engine: zod
  request: true
  response: true
  unchecked: allow
"#,
        )
        .expect("config");
        temp
    }

    #[test]
    fn a_tracked_run_reports_every_family_of_input_it_depended_on() {
        let temp = tracked_workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let outcome = run(
            Command::Generate { check: false },
            ConfigSource::Path {
                explicit: None,
                cwd: &root,
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert_eq!(plan.output_roots(), vec![root.join("generated")]);

        let has = |path: PathBuf| watched(&plan, &path);
        let inputs = plan.watched_inputs();
        // Every discovery candidate, not only the one that exists: a second name appearing is what
        // turns a working run into a discovery failure.
        assert!(has(root.join("oasts.yaml")));
        assert!(has(root.join("oasts.json")));
        assert!(has(root.join("oasts.config.ts")));
        // The document graph, entry and reference alike.
        assert!(has(root.join("openapi.yaml")));
        assert!(has(root.join("components.yaml")));
        // The consumer tsconfig, its `extends` target, and the ancestor probe that found nothing.
        assert!(has(root.join("tsconfig.json")));
        assert!(has(root.join("base.json")));
        assert!(has(root.join("generated/tsconfig.json")));
        // The peer manifest the version warning was judged against.
        assert!(has(root.join("node_modules/zod/package.json")));
        // Nothing the run wrote is an input. The output root holds exactly one watched path — the
        // `tsconfig.json` the ancestor walk looked for there and did not find.
        assert_eq!(
            inputs
                .iter()
                .map(|input| input.path.as_path())
                .filter(|path| path.starts_with(root.join("generated")))
                .collect::<Vec<_>>(),
            vec![root.join("generated/tsconfig.json").as_path()]
        );
        assert!(inputs.is_sorted());
        // The trust root is a directory, and saying so is what stops a host watching the directory
        // that contains it. Everything else here is a file.
        assert_eq!(
            inputs
                .iter()
                .filter(|input| input.kind == InputKind::Directory)
                .map(|input| input.path.as_path())
                .collect::<Vec<_>>(),
            vec![root.as_path()]
        );
    }

    /// Whether the plan reports `path` for the workspace or for any spec, whatever kind it was
    /// recorded as.
    fn watched(plan: &WatchPlan, path: &Path) -> bool {
        plan.watched_inputs().iter().any(|input| input.path == path)
    }

    #[test]
    fn a_retrieved_entry_is_never_offered_to_a_watcher_as_a_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(
            root.join("oasts.yaml"),
            r#"schemaVersion: 1
input:
  url: https://example.test/openapi.yaml
output: ./generated
artifacts:
  types: true
remote:
  allowHosts: [example.test]
"#,
        )
        .expect("config");

        let outcome = run(
            Command::Check,
            ConfigSource::Path {
                explicit: None,
                cwd: &root,
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );

        // Retrieval fails with no fetcher, and the plan still has to be usable: a watcher handed
        // the URI text would resolve it to a directory that cannot exist and end the session.
        assert_eq!(outcome.exit_code, 1, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        let inputs = plan.watched_inputs();
        assert!(
            inputs.iter().all(|input| input.path.has_root()),
            "{inputs:#?}"
        );
        assert!(has_no_uri(&inputs), "{inputs:#?}");
    }

    fn has_no_uri(inputs: &[WatchInput]) -> bool {
        !inputs
            .iter()
            .any(|input| input.path.to_string_lossy().contains("://"))
    }

    #[test]
    fn a_project_with_no_tsconfig_anywhere_watches_nothing_above_its_workspace() {
        let temp = tracked_workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        fs::remove_file(root.join("tsconfig.json")).expect("drop the consumer tsconfig");
        let outcome = run(
            Command::Check,
            ConfigSource::Path {
                explicit: None,
                cwd: &root,
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        // The walk reaches the filesystem root looking for a config that is not there, and only
        // the probes inside the workspace are reported.
        //
        // This answers for the reported set, not for what a host registers from it: the workspace
        // root is itself in this set and trivially starts with itself, so the reach above the
        // workspace lives one step later, where an input becomes a directory to watch. The guard
        // for that is `watch::tests::a_session_registers_the_workspace_root_itself`.
        assert!(watched(&plan, &root.join("tsconfig.json")));
        assert!(watched(&plan, &root.join("generated/tsconfig.json")));
        let inputs = plan.watched_inputs();
        assert!(
            inputs.iter().all(|input| input.path.starts_with(&root)),
            "{inputs:#?}"
        );
    }

    #[test]
    fn an_untracked_run_reports_no_inputs() {
        let temp = tracked_workspace();
        let outcome = run(
            Command::Check,
            ConfigSource::Path {
                explicit: None,
                cwd: temp.path(),
            },
            &[],
            FetcherHandle::None,
            Tracking::Off,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        assert!(outcome.watch_plan.is_none());
    }

    #[test]
    fn a_run_that_never_found_a_config_still_reports_what_to_watch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let outcome = run(
            Command::Check,
            ConfigSource::Path {
                explicit: None,
                cwd: temp.path(),
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 2);
        let plan = outcome
            .watch_plan
            .expect("inputs survive a failed discovery");
        assert!(plan.output_roots().is_empty());
        assert!(plan.specs.is_empty());
        assert_eq!(plan.inputs.len(), 8);
    }

    #[test]
    fn an_explicit_config_path_is_the_only_candidate_watched() {
        let temp = tracked_workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let outcome = run(
            Command::Check,
            ConfigSource::Path {
                explicit: Some(Path::new("oasts.yaml")),
                cwd: &root,
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert!(watched(&plan, &root.join("oasts.yaml")));
        assert!(!watched(&plan, &root.join("oasts.json")));
    }

    #[test]
    fn an_evaluated_config_is_tracked_at_the_path_it_came_from() {
        let temp = tracked_workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let config_path = root.join("oasts.config.ts");
        let outcome = run(
            Command::Check,
            ConfigSource::Json {
                config_path: &config_path,
                json: br#"{"schemaVersion": 1, "input": {"path": "./openapi.yaml"},
                    "output": "./generated", "artifacts": {"types": true}}"#,
            },
            &[],
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert!(watched(&plan, &config_path));
    }

    const DOCUMENT: &str = r#"openapi: 3.1.0
info: {title: test, version: 1.0.0}
paths:
  /things:
    get:
      operationId: listThings
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: string}
"#;

    fn workspace(config: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("a.yaml"), DOCUMENT).expect("document a");
        fs::write(temp.path().join("b.yaml"), DOCUMENT).expect("document b");
        fs::write(temp.path().join("oasts.yaml"), config).expect("config");
        temp
    }

    const TWO_SPECS: &str = r#"schemaVersion: 1
specs:
  users:
    input: {path: ./b.yaml}
    output: ./generated/users
  billing:
    input: {path: ./a.yaml}
    output: ./generated/billing
"#;

    fn invoke(temp: &tempfile::TempDir, command: Command, specs: &[&str]) -> Outcome {
        run(
            command,
            ConfigSource::Path {
                explicit: None,
                cwd: temp.path(),
            },
            &specs
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
            FetcherHandle::None,
            Tracking::Off,
        )
    }

    #[test]
    fn a_workspace_writes_every_spec_and_summarizes_each() {
        let temp = workspace(TWO_SPECS);

        let outcome = invoke(&temp, Command::Generate { check: false }, &[]);

        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let summary = outcome.stdout_summary.expect("summary");
        let lines = summary.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("billing: generated "), "{summary}");
        assert!(lines[1].starts_with("users: generated "), "{summary}");
        assert!(temp.path().join("generated/billing").is_dir());
        assert!(temp.path().join("generated/users").is_dir());
    }

    #[test]
    fn spec_selection_builds_only_the_named_spec() {
        let temp = workspace(TWO_SPECS);

        let outcome = invoke(
            &temp,
            Command::Generate { check: false },
            &["users", "users"],
        );

        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        assert!(
            outcome
                .stdout_summary
                .expect("summary")
                .starts_with("users: generated ")
        );
        assert!(!temp.path().join("generated/billing").exists());
        assert!(temp.path().join("generated/users").is_dir());
    }

    #[test]
    fn an_unknown_spec_names_every_spec_the_workspace_declares() {
        let temp = workspace(TWO_SPECS);

        let outcome = invoke(&temp, Command::Check, &["nope", "also-nope"]);

        assert_eq!(outcome.exit_code, 2);
        assert_eq!(
            outcome
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>(),
            [
                "no spec named 'also-nope'; this workspace declares billing, users",
                "no spec named 'nope'; this workspace declares billing, users",
            ]
        );
    }

    #[test]
    fn spec_selection_needs_a_workspace_to_select_from() {
        let temp = workspace("schemaVersion: 1\ninput: {path: ./a.yaml}\noutput: ./generated\n");

        let outcome = invoke(&temp, Command::Check, &["billing"]);

        assert_eq!(outcome.exit_code, 2);
        assert_eq!(outcome.diagnostics.len(), 1);
        assert_eq!(outcome.diagnostics[0].code, "OASTS0295");
    }

    #[test]
    fn one_failing_spec_leaves_the_whole_workspace_untouched() {
        let temp = workspace(TWO_SPECS);
        fs::write(
            temp.path().join("b.yaml"),
            "openapi: '2.0'\ninfo: {title: bad, version: 1.0.0}\npaths: {}\n",
        )
        .expect("broken document");

        let outcome = invoke(&temp, Command::Generate { check: false }, &[]);

        assert_eq!(outcome.exit_code, 1);
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.spec.as_deref() == Some("users"))
        );
        assert!(!temp.path().join("generated").exists());
    }

    #[test]
    fn workspace_drift_lines_are_named_from_the_workspace_root() {
        let temp = workspace(TWO_SPECS);
        assert_eq!(
            invoke(&temp, Command::Generate { check: false }, &[]).exit_code,
            0
        );
        let edited = temp
            .path()
            .join("generated/users/types/operations/listthings.ts");
        fs::write(&edited, "// edited\n").expect("edit an owned file");

        let outcome = invoke(&temp, Command::Generate { check: true }, &[]);

        assert_eq!(outcome.exit_code, 1);
        assert_eq!(
            outcome.drift_lines,
            ["edited: generated/users/types/operations/listthings.ts"]
        );
    }

    #[test]
    fn a_clean_workspace_reports_no_drift() {
        let temp = workspace(TWO_SPECS);
        assert_eq!(
            invoke(&temp, Command::Generate { check: false }, &[]).exit_code,
            0
        );

        let outcome = invoke(&temp, Command::Generate { check: true }, &[]);

        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout_summary.as_deref(), Some("check ok"));
    }

    #[test]
    fn a_write_failure_reports_the_specs_that_did_land() {
        let temp = workspace(TWO_SPECS);
        fs::create_dir_all(temp.path().join("generated")).expect("output parent");
        fs::write(temp.path().join("generated/users"), "not a directory").expect("blocking file");

        let outcome = invoke(&temp, Command::Generate { check: false }, &[]);

        assert_eq!(outcome.exit_code, 2, "{:#?}", outcome.diagnostics);
        assert!(
            outcome
                .stdout_summary
                .expect("the specs that were written are reported")
                .starts_with("billing: generated ")
        );
        assert!(temp.path().join("generated/billing").is_dir());
    }
}
