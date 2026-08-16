//! Node bindings for the Oasts compiler.
//!
//! The Node CLI drives discovery and compilation through this crate so the
//! Rust core stays the single source of truth for config validation,
//! diagnostics, and emission. Failures cross the boundary as JSON-encoded
//! error reasons carrying the structured diagnostics and the process exit
//! code; successful runs return a [`RunResult`] the CLI prints verbatim.

use std::path::{Path, PathBuf};

use napi_derive::napi;
use oasts_core::config;
use oasts_core::diag::{Diagnostic, Severity};
use oasts_core::driver::{self, Command, ConfigSource, Outcome, Unsupported};

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
    /// The command name the host parsed.
    pub command: String,
    /// Whether `generate` runs in `--check` drift mode.
    pub check: bool,
    /// `--spec` selections; non-empty selections are unsupported locally.
    pub specs: Vec<String>,
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

fn render(outcome: Outcome) -> RunResult {
    let mut rendered_stderr = oasts_core::diag::render_to_string(outcome.diagnostics.clone());
    for line in &outcome.drift_lines {
        rendered_stderr.push_str(line);
        rendered_stderr.push('\n');
    }
    RunResult {
        exit_code: u32::from(outcome.exit_code),
        stdout_summary: outcome.stdout_summary,
        rendered_stderr,
        diagnostics: outcome.diagnostics.iter().map(to_diagnostic_js).collect(),
    }
}

fn parse_command(name: &str, check: bool) -> Result<Command, Outcome> {
    match name {
        "generate" => Ok(Command::Generate { check }),
        "check" => Ok(Command::Check),
        other => Err(driver::refuse(Unsupported::Command(other))),
    }
}

/// Refusal for a declared command this build does not implement, else `None`.
///
/// The Node CLI asks before discovering a config, so an unimplemented command
/// never fails on a missing config file first. Answering here keeps every
/// `OASTS` code in the core.
#[napi]
pub fn command_refusal(command: String) -> Option<RunResult> {
    parse_command(&command, false).err().map(render)
}

/// Runs `generate` or `check` for one already-discovered config.
#[napi]
pub fn run(options: RunOptions) -> RunResult {
    if !options.specs.is_empty() {
        return render(driver::refuse(Unsupported::SpecSelection));
    }

    let command = match parse_command(&options.command, options.check) {
        Ok(command) => command,
        Err(refusal) => return render(refusal),
    };
    let config_path = Path::new(&options.config_path);
    let source = match options.config_json.as_deref() {
        Some(json) => ConfigSource::Json {
            config_path,
            json: json.as_bytes(),
        },
        None => ConfigSource::Path {
            explicit: Some(config_path),
            cwd: Path::new(&options.cwd),
        },
    };
    render(driver::run(command, source))
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
            // A schema-only document: every component is unreachable, so pruning is opted out of.
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated","filters":{"orphans":true}}"#
                .to_owned(),
        );
        let result = run(options);
        assert_eq!(result.exit_code, 0, "{}", result.rendered_stderr);
        assert!(result.rendered_stderr.contains("warning[OASTS4202]"));
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
        assert_eq!(spec_failure.diagnostics[0].code, "OASTS9002");

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
    fn command_refusal_names_only_unimplemented_commands() {
        assert!(command_refusal("generate".to_owned()).is_none());
        assert!(command_refusal("check".to_owned()).is_none());

        let refusal = command_refusal("watch".to_owned()).expect("watch is unimplemented");
        assert_eq!(refusal.exit_code, 2);
        assert_eq!(refusal.diagnostics[0].code, "OASTS9003");
        assert!(
            refusal
                .rendered_stderr
                .contains("the watch command is not supported in this build"),
            "{}",
            refusal.rendered_stderr
        );
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
    fn run_keeps_the_zod_peer_warning_when_the_write_fails() {
        let temp = project_with_outdated_zod();
        assert_eq!(run(options(&temp, "generate", false)).exit_code, 0);
        fs::write(
            temp.path().join("generated/.oasts-manifest.json"),
            r#"{"manifestVersion":2,"files":[]}"#,
        )
        .expect("unsupported manifest");

        let failed = run(options(&temp, "generate", false));

        assert_eq!(failed.exit_code, 2, "{}", failed.rendered_stderr);
        for code in ["OASTS0231", "OASTS0241"] {
            assert!(
                failed
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "{code} missing from {}",
                failed.rendered_stderr
            );
        }
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
