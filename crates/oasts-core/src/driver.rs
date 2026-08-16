//! One orchestration for every host.
//!
//! The Rust CLI and the Node bindings both need the same sequence — load the
//! config, compile, then either report drift or write — and both need the same
//! 0/1/2 exit codes out of it. Keeping that sequence here means a host only
//! decides how to render the [`Outcome`], never what the outcome is.

use std::path::Path;

use crate::config::{self, CODE_COMMAND_UNSUPPORTED, CODE_WORKSPACE_UNSUPPORTED, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::emit::GeneratedFile;
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
pub enum Unsupported<'a> {
    /// A command the CLI advertises without implementing it.
    Command(&'a str),
    /// `--spec`, which selects one spec out of a workspace config.
    SpecSelection,
}

/// The refusal for an unimplemented surface, shaped like any other outcome.
///
/// Hosts ask for this instead of writing an `OASTS` code themselves, so every
/// code in the product is declared exactly once, here in the core.
#[must_use]
pub fn refuse(surface: Unsupported<'_>) -> Outcome {
    let diagnostic = match surface {
        Unsupported::Command(command) => Diagnostic::config(
            CODE_COMMAND_UNSUPPORTED,
            format!("the {command} command is not supported in this build"),
        ),
        Unsupported::SpecSelection => Diagnostic::config(
            CODE_WORKSPACE_UNSUPPORTED,
            "--spec selects a workspace spec, and workspace configuration is not supported in this build",
        ),
    };
    let mut sink = DiagnosticSink::new();
    sink.push(diagnostic);
    Outcome::failed(sink)
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
}

impl Outcome {
    fn failed(sink: DiagnosticSink) -> Self {
        Self {
            exit_code: sink.worst_exit_code(),
            stdout_summary: None,
            diagnostics: sink.into_sorted_vec(),
            drift_lines: Vec::new(),
        }
    }

    fn succeeded(summary: &str, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            exit_code: 0,
            stdout_summary: Some(summary.to_owned()),
            diagnostics,
            drift_lines: Vec::new(),
        }
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
pub fn run(command: Command, source: ConfigSource<'_>) -> Outcome {
    let mut sink = DiagnosticSink::new();
    let config = match load(source) {
        Ok(config) => config,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return Outcome::failed(sink);
        }
    };

    let should_emit = matches!(command, Command::Generate { .. });
    let files = pipeline::compile(&config, should_emit, &mut sink);
    if sink.has_errors() {
        return Outcome::failed(sink);
    }
    let warnings = sink.into_sorted_vec();

    let Command::Generate { check } = command else {
        return Outcome::succeeded("check ok", warnings);
    };
    let files = files.expect("successful emitting compilation returns generated files");

    if check {
        return drift(&config, files, warnings);
    }
    emit(&config, files, warnings)
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
    mut warnings: Vec<Diagnostic>,
) -> Outcome {
    // Only on the write path: `--check` compares bytes for CI, where the consumer's node_modules
    // is neither inspected nor relevant.
    if config.artifacts.zod.enabled
        && let Some(diagnostic) = zod_peer::diagnose(&config.output)
    {
        warnings.push(diagnostic);
    }
    if config.artifacts.msw.enabled
        && let Some(diagnostic) = msw_peer::diagnose(&config.output)
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
