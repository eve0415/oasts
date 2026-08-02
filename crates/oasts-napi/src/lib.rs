//! Node bindings for the Oasts compiler.
//!
//! The Node CLI drives discovery and compilation through this crate so the
//! Rust core stays the single source of truth for config validation,
//! diagnostics, and emission. Failures cross the boundary as JSON-encoded
//! error reasons carrying the structured diagnostics and the process exit
//! code; successful runs return a [`RunResult`] the CLI prints verbatim.

use std::path::{Path, PathBuf};

use napi_derive::napi;
use oasts_core::config::{self, ResolvedConfig};
use oasts_core::diag::{Diagnostic, DiagnosticSink, Severity};
use oasts_core::msw_peer;
use oasts_core::pipeline;
use oasts_core::writer::{DriftState, check_drift, write};
use oasts_core::zod_peer;

/// A config discovery result exposed to the Node CLI.
#[napi(object)]
#[derive(Debug)]
pub struct DiscoveredConfigJs {
    /// Absolute or cwd-relative path of the single discovered config file.
    pub path: String,
    /// Whether the Node CLI must evaluate the file as a script config.
    pub is_script: bool,
}

/// One diagnostic in the stable cross-boundary shape.
#[napi(object)]
#[derive(Clone)]
pub struct DiagnosticJs {
    /// Stable `OASTSnnnn` diagnostic code.
    pub code: String,
    /// `error` or `warning`.
    pub severity: String,
    /// Human-readable message.
    pub message: String,
    /// Source file the diagnostic points at, when known.
    pub source_id: Option<String>,
    /// 1-based line, when known.
    pub line: Option<u32>,
    /// 1-based column, when known.
    pub col: Option<u32>,
    /// JSON pointer into the offending document, when known.
    pub json_pointer: Option<String>,
}

/// Options for one compiler invocation.
#[napi(object)]
pub struct RunOptions {
    /// Working directory of the invocation.
    pub cwd: String,
    /// Path of the discovered or explicit config file.
    pub config_path: String,
    /// Evaluated script config serialized to JSON; `None` for data configs.
    pub config_json: Option<String>,
    /// `generate` or `check`.
    pub command: String,
    /// Whether `generate` runs in `--check` drift mode.
    pub check: bool,
    /// `--spec` selections; non-empty selections are unsupported locally.
    pub specs: Vec<String>,
    /// `--locked`; a no-op in the local wedge (remote-only semantics).
    pub locked: bool,
}

/// Outcome of one compiler invocation.
#[napi(object)]
pub struct RunResult {
    /// Process exit code per the CLI's 0/1/2 exit-code contract.
    pub exit_code: u32,
    /// Success summary for stdout, when the run succeeded.
    pub stdout_summary: Option<String>,
    /// Rendered diagnostics and drift lines for stderr.
    pub rendered_stderr: String,
    /// Structured diagnostics mirroring `rendered_stderr`.
    pub diagnostics: Vec<DiagnosticJs>,
}

const CODE_WORKSPACE_UNSUPPORTED: &str = "OASTS0062";

fn to_diagnostic_js(diagnostic: &Diagnostic) -> DiagnosticJs {
    DiagnosticJs {
        code: diagnostic.code.to_owned(),
        severity: match diagnostic.severity {
            Severity::Error => "error".to_owned(),
            Severity::Warning => "warning".to_owned(),
        },
        message: diagnostic.message.clone(),
        source_id: diagnostic.source_id.clone(),
        line: diagnostic.line,
        col: diagnostic.col,
        json_pointer: diagnostic.json_pointer.clone(),
    }
}

fn failure_reason(exit_code: u8, diagnostics: &[Diagnostic]) -> String {
    let rendered = oasts_core::diag::render_to_string(diagnostics.to_vec());
    let structured = diagnostics
        .iter()
        .map(|diagnostic| {
            serde_json::json!({
                "code": diagnostic.code,
                "severity": match diagnostic.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "message": diagnostic.message,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "exitCode": exit_code,
        "renderedStderr": rendered,
        "diagnostics": structured,
    })
    .to_string()
}

/// Runs config discovery without script rejection.
///
/// Errors carry a JSON reason of shape
/// `{ exitCode, renderedStderr, diagnostics }`.
#[napi]
pub fn discover_config(
    cwd: String,
    explicit_path: Option<String>,
) -> napi::Result<DiscoveredConfigJs> {
    let explicit = explicit_path.map(PathBuf::from);
    match config::discover_candidate(Path::new(&cwd), explicit.as_deref()) {
        Ok(candidate) => Ok(DiscoveredConfigJs {
            path: candidate.path.to_string_lossy().into_owned(),
            is_script: candidate.is_script,
        }),
        Err(diagnostic) => Err(napi::Error::from_reason(failure_reason(2, &[diagnostic]))),
    }
}

fn load(options: &RunOptions) -> Result<ResolvedConfig, Vec<Diagnostic>> {
    let config_path = Path::new(&options.config_path);
    match options.config_json.as_deref() {
        Some(json) => config::load_config_from_json(config_path, json.as_bytes()),
        None => config::load_config(Some(config_path), Path::new(&options.cwd)),
    }
}

fn failure(sink: DiagnosticSink) -> RunResult {
    let exit_code = u32::from(sink.worst_exit_code());
    let diagnostics = sink.into_sorted_vec();
    RunResult {
        exit_code,
        stdout_summary: None,
        rendered_stderr: oasts_core::diag::render_to_string(diagnostics.clone()),
        diagnostics: diagnostics.iter().map(to_diagnostic_js).collect(),
    }
}

/// Runs `generate` or `check` for one already-discovered config.
///
/// The `locked` flag is accepted and ignored: `--locked` has remote-only
/// semantics and the local wedge treats it as a no-op success.
#[napi]
pub fn run(options: RunOptions) -> RunResult {
    let mut sink = DiagnosticSink::new();
    let config = match load(&options) {
        Ok(config) => config,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return failure(sink);
        }
    };
    if !options.specs.is_empty() {
        sink.push(Diagnostic::config(
            CODE_WORKSPACE_UNSUPPORTED,
            "--spec selects a workspace spec, and workspace configuration is not supported in this build",
        ));
        return failure(sink);
    }

    let should_emit = options.command == "generate";
    let files = pipeline::compile(&config, should_emit, &mut sink);
    if sink.has_errors() {
        return failure(sink);
    }
    let warnings = sink.into_sorted_vec();
    let mut rendered_warnings = oasts_core::diag::render_to_string(warnings.clone());
    let mut diagnostics_js = warnings.iter().map(to_diagnostic_js).collect::<Vec<_>>();

    if !should_emit {
        return RunResult {
            exit_code: 0,
            stdout_summary: Some("check ok".to_owned()),
            rendered_stderr: rendered_warnings,
            diagnostics: diagnostics_js,
        };
    }

    let files = files.expect("successful emitting compilation returns generated files");
    if options.check {
        let report = check_drift(&config.output, files);
        if !report.diagnostics.is_empty() {
            let mut drift_sink = DiagnosticSink::new();
            drift_sink.extend(warnings);
            drift_sink.extend(report.diagnostics);
            return failure(drift_sink);
        }
        if report.is_clean() {
            return RunResult {
                exit_code: 0,
                stdout_summary: Some("check ok".to_owned()),
                rendered_stderr: rendered_warnings,
                diagnostics: diagnostics_js,
            };
        }
        let mut drift_lines = rendered_warnings;
        for entry in report
            .entries
            .iter()
            .filter(|entry| entry.state != DriftState::Clean)
        {
            drift_lines.push_str(&format!("{}: {}\n", entry.state, entry.relative_path));
        }
        return RunResult {
            exit_code: 1,
            stdout_summary: None,
            rendered_stderr: drift_lines,
            diagnostics: diagnostics_js,
        };
    }

    // Only on the write path: `--check` compares bytes for CI, where the consumer's node_modules
    // is neither inspected nor relevant.
    if config.artifacts.zod.enabled
        && let Some(diagnostic) = zod_peer::diagnose(&config.output)
    {
        rendered_warnings.push_str(&oasts_core::diag::render_to_string(vec![
            diagnostic.clone(),
        ]));
        diagnostics_js.push(to_diagnostic_js(&diagnostic));
    }
    if config.artifacts.msw.enabled
        && let Some(diagnostic) = msw_peer::diagnose(&config.output)
    {
        rendered_warnings.push_str(&oasts_core::diag::render_to_string(vec![
            diagnostic.clone(),
        ]));
        diagnostics_js.push(to_diagnostic_js(&diagnostic));
    }

    let generated_count = files.len();
    match write(&config.output, files) {
        Ok(_) => RunResult {
            exit_code: 0,
            stdout_summary: Some(format!("generated {generated_count} files")),
            rendered_stderr: rendered_warnings,
            diagnostics: diagnostics_js,
        },
        Err(diagnostics) => {
            let mut write_sink = DiagnosticSink::new();
            write_sink.extend(warnings);
            write_sink.extend(diagnostics);
            failure(write_sink)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn copy_fixture(name: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        for file_name in ["openapi.yaml", "oasts.yaml"] {
            fs::copy(source.join(file_name), temp.path().join(file_name)).expect("copy fixture");
        }
        temp
    }

    fn options(temp: &tempfile::TempDir, command: &str, check: bool) -> RunOptions {
        RunOptions {
            cwd: temp.path().to_string_lossy().into_owned(),
            config_path: temp
                .path()
                .join("oasts.yaml")
                .to_string_lossy()
                .into_owned(),
            config_json: None,
            command: command.to_owned(),
            check,
            specs: Vec::new(),
            locked: false,
        }
    }

    #[test]
    fn discover_config_reports_candidates_and_structured_failures() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("oasts.config.ts"), "export default {};").expect("config");
        let discovered = discover_config(temp.path().to_string_lossy().into_owned(), None)
            .expect("script candidate");
        assert!(discovered.is_script);
        assert!(discovered.path.ends_with("oasts.config.ts"));

        let explicit = discover_config(
            temp.path().to_string_lossy().into_owned(),
            Some("oasts.config.ts".to_owned()),
        )
        .expect("explicit candidate");
        assert!(explicit.is_script);

        let empty = tempfile::tempdir().expect("tempdir");
        let error = discover_config(empty.path().to_string_lossy().into_owned(), None)
            .expect_err("zero candidates");
        let payload: serde_json::Value =
            serde_json::from_str(error.reason.as_ref()).expect("JSON reason");
        assert_eq!(payload["exitCode"], 2);
        assert_eq!(payload["diagnostics"][0]["code"], "OASTS0011");
        assert!(
            payload["renderedStderr"]
                .as_str()
                .expect("rendered stderr")
                .contains("error[OASTS0011]")
        );
    }

    #[test]
    fn run_generates_checks_and_reports_drift() {
        let temp = copy_fixture("petstore-3.0");

        let generated = run(options(&temp, "generate", false));
        assert_eq!(generated.exit_code, 0, "{}", generated.rendered_stderr);
        assert!(
            generated
                .stdout_summary
                .expect("summary")
                .starts_with("generated ")
        );

        let clean = run(options(&temp, "generate", true));
        assert_eq!(clean.exit_code, 0, "{}", clean.rendered_stderr);
        assert_eq!(clean.stdout_summary.as_deref(), Some("check ok"));

        let checked = run(options(&temp, "check", false));
        assert_eq!(checked.exit_code, 0, "{}", checked.rendered_stderr);
        assert_eq!(checked.stdout_summary.as_deref(), Some("check ok"));

        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(temp.path().join("generated/.oasts-manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        let edited = manifest["files"][0].as_str().expect("generated path");
        fs::write(temp.path().join("generated").join(edited), "edited\n").expect("edit output");
        let drifted = run(options(&temp, "generate", true));
        assert_eq!(drifted.exit_code, 1);
        assert!(drifted.stdout_summary.is_none());
        assert!(drifted.rendered_stderr.contains("edited:"));

        fs::write(
            temp.path().join("generated/.oasts-manifest.json"),
            "not JSON\n",
        )
        .expect("invalid manifest");
        let invalid_manifest = run(options(&temp, "generate", true));
        assert_eq!(invalid_manifest.exit_code, 2);
        assert!(invalid_manifest.rendered_stderr.contains("OASTS0231"));
    }

    #[test]
    fn run_accepts_json_config_bytes_and_reports_warnings() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Choice":{"oneOf":[{"type":"string"},{"type":"integer"}],"discriminator":{"propertyName":"kind"}}}}}"#,
        )
        .expect("OpenAPI JSON");
        let mut options = options(&temp, "generate", false);
        options.config_path = temp
            .path()
            .join("oasts.config.ts")
            .to_string_lossy()
            .into_owned();
        options.config_json = Some(
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated"}"#
                .to_owned(),
        );
        options.locked = true;

        let result = run(options);
        assert_eq!(result.exit_code, 0, "{}", result.rendered_stderr);
        assert!(result.rendered_stderr.contains("warning[OASTS1304]"));
        assert_eq!(result.diagnostics[0].severity, "warning");
        assert!(temp.path().join("generated").is_dir());
    }

    #[test]
    fn run_reports_load_spec_and_write_failures() {
        let missing = tempfile::tempdir().expect("tempdir");
        let load_failure = run(options(&missing, "generate", false));
        assert_eq!(load_failure.exit_code, 2);
        assert_eq!(load_failure.diagnostics[0].code, "OASTS0011");

        let temp = copy_fixture("petstore-3.0");
        let mut with_spec = options(&temp, "generate", false);
        with_spec.specs = vec!["petstore".to_owned()];
        let spec_failure = run(with_spec);
        assert_eq!(spec_failure.exit_code, 2);
        assert_eq!(spec_failure.diagnostics[0].code, "OASTS0062");

        let compile_failure = copy_fixture("petstore-3.0");
        fs::write(
            compile_failure.path().join("openapi.yaml"),
            "openapi: '2.0'\ninfo: { title: Invalid, version: 1.0.0 }\npaths: {}\n",
        )
        .expect("invalid input");
        let input_failure = run(options(&compile_failure, "generate", false));
        assert_eq!(input_failure.exit_code, 1);
        assert!(input_failure.rendered_stderr.contains("OASTS1101"));

        let hostile = copy_fixture("petstore-3.0");
        assert_eq!(run(options(&hostile, "generate", false)).exit_code, 0);
        let output = hostile.path().join("generated");
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join(".oasts-manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        let generated = manifest["files"][0].as_str().expect("generated path");
        fs::remove_file(output.join(generated)).expect("remove generated file");
        fs::write(
            output.join(".oasts-manifest.json"),
            r#"{"manifestVersion":1,"files":["../victim.ts"]}"#,
        )
        .expect("hostile manifest");
        let write_failure = run(options(&hostile, "generate", false));
        assert_eq!(write_failure.exit_code, 2);
        assert!(write_failure.rendered_stderr.contains("error["));
    }

    #[test]
    fn failure_reason_renders_warning_severity() {
        let mut warning = Diagnostic::config("OASTS0999", "warning");
        warning.severity = Severity::Warning;
        let payload: serde_json::Value =
            serde_json::from_str(&failure_reason(0, &[warning])).expect("JSON reason");
        assert_eq!(payload["diagnostics"][0]["severity"], "warning");
    }

    #[test]
    fn diagnostic_conversion_preserves_location_fields() {
        let diagnostic = Diagnostic::config("OASTS0001", "message")
            .with_source("config.yaml")
            .with_location(3, 7)
            .with_json_pointer("/input");
        let converted = to_diagnostic_js(&diagnostic);
        assert_eq!(converted.code, "OASTS0001");
        assert_eq!(converted.severity, "error");
        assert_eq!(converted.source_id.as_deref(), Some("config.yaml"));
        assert_eq!((converted.line, converted.col), (Some(3), Some(7)));
        assert_eq!(converted.json_pointer.as_deref(), Some("/input"));
    }

    /// A zod-artifact project with an out-of-range `zod` installed beside it.
    fn project_with_outdated_zod() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            "openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    Thing:\n      type: string\n",
        )
        .expect("OpenAPI YAML");
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\noutput: ./generated\nartifacts:\n  types: true\n  zod: true\n",
        )
        .expect("config YAML");
        let package = temp.path().join("node_modules").join("zod");
        fs::create_dir_all(&package).expect("package directory");
        fs::write(
            package.join("package.json"),
            r#"{"name":"zod","version":"4.1.0"}"#,
        )
        .expect("package manifest");
        temp
    }

    #[test]
    fn run_surfaces_the_zod_peer_warning_on_the_write_path() {
        let temp = project_with_outdated_zod();
        let generated = run(options(&temp, "generate", false));
        assert_eq!(generated.exit_code, 0, "{}", generated.rendered_stderr);
        assert!(
            generated
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS0241"),
            "{}",
            generated.rendered_stderr
        );
        assert!(generated.rendered_stderr.contains("^4.4.0"));
    }

    #[test]
    fn run_omits_the_zod_peer_warning_in_check_mode() {
        let temp = project_with_outdated_zod();
        assert_eq!(run(options(&temp, "generate", false)).exit_code, 0);

        let checked = run(options(&temp, "generate", true));
        assert_eq!(checked.exit_code, 0, "{}", checked.rendered_stderr);
        assert!(
            !checked
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS0241"),
            "{}",
            checked.rendered_stderr
        );
    }
}
