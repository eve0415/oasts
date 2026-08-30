//! One orchestration for every host.
//!
//! The Rust CLI and the Node bindings both need the same sequence — load the
//! config, compile, then either report drift or write — and both need the same
//! 0/1/2 exit codes out of it. Keeping that sequence here means a host only
//! decides how to render the [`Outcome`], never what the outcome is.

use std::path::{Path, PathBuf};

use crate::config::WatchConfig;
use crate::config::{self, CODE_WORKSPACE_UNSUPPORTED, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::emit::GeneratedFile;
use crate::inputs::{InputRecorder, WatchPlan};
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

/// A surface this build declares but does not implement.
#[derive(Clone, Copy, Debug)]
pub enum Unsupported {
    /// `--spec`, which selects one spec out of a workspace config.
    SpecSelection,
}

/// The refusal for an unimplemented surface, shaped like any other outcome.
///
/// Hosts ask for this instead of writing an `OASTS` code themselves, so every
/// code in the product is declared exactly once, here in the core.
#[must_use]
pub fn refuse(surface: Unsupported) -> Outcome {
    let diagnostic = match surface {
        Unsupported::SpecSelection => Diagnostic::config(
            CODE_WORKSPACE_UNSUPPORTED,
            "--spec selects a workspace spec, and workspace configuration is not supported in this build",
        ),
    };
    let mut sink = DiagnosticSink::new();
    sink.push(diagnostic);
    Outcome::failed(sink)
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

    fn with_watch_plan(
        mut self,
        recorder: InputRecorder,
        output_root: Option<PathBuf>,
        settings: WatchConfig,
    ) -> Self {
        if recorder.is_recording() {
            self.watch_plan = Some(WatchPlan {
                inputs: recorder.into_inputs(),
                output_root,
                settings,
            });
        }
        self
    }
}

fn load(source: ConfigSource<'_>) -> Result<ResolvedConfig, Vec<Diagnostic>> {
    match source {
        ConfigSource::Path { explicit, cwd } => config::load_config(explicit, cwd),
        ConfigSource::Json { config_path, json } => {
            config::load_config_from_json(config_path, json)
        }
    }
}

/// Loads, compiles, and either reports drift or writes the generated files.
pub fn run(
    command: Command,
    source: ConfigSource<'_>,
    fetcher: FetcherHandle,
    tracking: Tracking,
) -> Outcome {
    let mut inputs = match tracking {
        Tracking::Off => InputRecorder::off(),
        Tracking::Watch => InputRecorder::on(),
    };
    let mut output_root = None;
    let mut settings = WatchConfig::default();
    let outcome = compile(
        command,
        source,
        fetcher,
        &mut inputs,
        &mut output_root,
        &mut settings,
    );
    outcome.with_watch_plan(inputs, output_root, settings)
}

fn compile(
    command: Command,
    source: ConfigSource<'_>,
    fetcher: FetcherHandle,
    inputs: &mut InputRecorder,
    output_root: &mut Option<PathBuf>,
    settings: &mut WatchConfig,
) -> Outcome {
    // Seeded before the load, so a run that never reaches a config still says which paths decide
    // whether the next one will. A watcher that gave up here could not see the config appear.
    record_config_candidates(source, inputs);
    let mut sink = DiagnosticSink::new();
    let mut config = match load(source) {
        Ok(config) => config,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return Outcome::failed(sink);
        }
    };
    inputs.record(&config.config_path);
    // The entry document as the config names it. The graph reports canonical paths for every
    // document it opened, which is the same file by another name — but only once it opens.
    //
    // `input.url` leaves the literal URI text here, and a URI is not a path anything can watch:
    // recorded, it would reach the watcher as a directory that cannot exist. `is_rooted` is the
    // same question the loader asks before it decides to open a file rather than retrieve one.
    if crate::source::is_rooted(&config.input) {
        inputs.record(&config.input);
    }
    if inputs.is_recording() {
        *output_root = Some(config.output.clone());
    }
    *settings = config.watch;
    sink.extend(std::mem::take(&mut config.diagnostics));

    let should_emit = matches!(command, Command::Generate { .. });
    let files = pipeline::compile(&config, fetcher, should_emit, inputs, &mut sink);
    if sink.has_errors() {
        return Outcome::failed(sink);
    }
    let warnings = sink.into_sorted_vec();

    let Command::Generate { check } = command else {
        return Outcome::succeeded("check ok", warnings);
    };
    // A successful emitting compile returns `Some`; `None` either means check-only or an error,
    // and both cases returned above.
    let files = files.expect("successful emitting compilation returns generated files");

    if check {
        return drift(&config, files, warnings);
    }
    emit(&config, files, inputs, warnings)
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

fn drift(config: &ResolvedConfig, files: Vec<GeneratedFile>, warnings: Vec<Diagnostic>) -> Outcome {
    let report = check_drift(&config.output, files);
    if !report.diagnostics.is_empty() {
        let mut sink = DiagnosticSink::new();
        sink.extend(warnings);
        sink.extend(report.diagnostics);
        return Outcome::failed(sink);
    }
    if report.is_clean() {
        return Outcome::succeeded("check ok", warnings);
    }
    Outcome {
        exit_code: 1,
        stdout_summary: None,
        diagnostics: warnings,
        watch_plan: None,
        drift_lines: report
            .entries
            .iter()
            .filter(|entry| entry.state != DriftState::Clean)
            .map(|entry| format!("{}: {}", entry.state, entry.relative_path))
            .collect(),
    }
}

fn emit(
    config: &ResolvedConfig,
    files: Vec<GeneratedFile>,
    inputs: &mut InputRecorder,
    mut warnings: Vec<Diagnostic>,
) -> Outcome {
    // Only on the write path: `--check` compares bytes for CI, where the consumer's node_modules
    // is neither inspected nor relevant.
    if config.artifacts.zod.enabled
        && let Some(diagnostic) = zod_peer::diagnose(&config.output, inputs)
    {
        warnings.push(diagnostic);
    }
    if config.artifacts.msw.enabled
        && let Some(diagnostic) = msw_peer::diagnose(&config.output, inputs)
    {
        warnings.push(diagnostic);
    }

    let generated_count = files.len();
    match write(&config.output, files) {
        Ok(_) => Outcome::succeeded(&format!("generated {generated_count} files"), warnings),
        Err(diagnostics) => {
            let mut sink = DiagnosticSink::new();
            sink.extend(warnings);
            sink.extend(diagnostics);
            Outcome::failed(sink)
        }
    }
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
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert_eq!(plan.output_root, Some(root.join("generated")));

        let has = |path: PathBuf| watched(&plan, &path);
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
            plan.inputs
                .iter()
                .map(|input| input.path.as_path())
                .filter(|path| path.starts_with(root.join("generated")))
                .collect::<Vec<_>>(),
            vec![root.join("generated/tsconfig.json").as_path()]
        );
        assert!(plan.inputs.is_sorted());
        // The trust root is a directory, and saying so is what stops a host watching the directory
        // that contains it. Everything else here is a file.
        assert_eq!(
            plan.inputs
                .iter()
                .filter(|input| input.kind == InputKind::Directory)
                .map(|input| input.path.as_path())
                .collect::<Vec<_>>(),
            vec![root.as_path()]
        );
    }

    /// Whether the plan reports `path`, whatever kind it was recorded as.
    fn watched(plan: &WatchPlan, path: &Path) -> bool {
        plan.inputs.iter().any(|input| input.path == path)
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
            FetcherHandle::None,
            Tracking::Watch,
        );

        // Retrieval fails with no fetcher, and the plan still has to be usable: a watcher handed
        // the URI text would resolve it to a directory that cannot exist and end the session.
        assert_eq!(outcome.exit_code, 1, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert!(
            plan.inputs.iter().all(|input| input.path.has_root()),
            "{:#?}",
            plan.inputs
        );
        assert!(has_no_uri(&plan.inputs), "{:#?}", plan.inputs);
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
        assert!(
            plan.inputs
                .iter()
                .all(|input| input.path.starts_with(&root)),
            "{:#?}",
            plan.inputs
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
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 2);
        let plan = outcome
            .watch_plan
            .expect("inputs survive a failed discovery");
        assert_eq!(plan.output_root, None);
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
            FetcherHandle::None,
            Tracking::Watch,
        );
        assert_eq!(outcome.exit_code, 0, "{:#?}", outcome.diagnostics);
        let plan = outcome
            .watch_plan
            .expect("a tracked run reports its inputs");
        assert!(watched(&plan, &config_path));
    }
}
