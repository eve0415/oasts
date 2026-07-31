//! Command-line orchestration for the Oasts compiler pipeline.
//!
//! Exit status precedence is `2` for configuration/IO/internal failures over
//! `1` for input/semantic failures when a sink contains both categories.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use oasts_core::config::{ResolvedConfig, load_config};
use oasts_core::diag::{self, Diagnostic, DiagnosticSink};
use oasts_core::emit::GeneratedFile;
use oasts_core::pipeline;
use oasts_core::writer::{DriftState, check_drift, write};

const CODE_CURRENT_DIR: &str = "OASTS0001";

#[derive(Debug, Parser)]
#[command(name = "oasts", disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate configured artifacts.
    Generate {
        /// Check committed output without writing.
        #[arg(long)]
        check: bool,
        /// Use an explicit configuration file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Validate configuration and input without emitting artifacts.
    Check {
        /// Use an explicit configuration file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },
}

/// Runs the CLI with explicit arguments and working directory.
pub fn run(args: Vec<String>, cwd: &Path) -> u8 {
    run_with_io(
        args,
        cwd,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

/// Reads process state and returns an [`ExitCode`] for the binary entry point.
pub fn run_from_env() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    run_from_state(
        args,
        std::env::current_dir(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

fn run_from_state(
    args: Vec<OsString>,
    cwd: io::Result<PathBuf>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match cwd {
        Ok(cwd) => ExitCode::from(run_os_with_io(args, &cwd, stdout, stderr)),
        Err(error) => {
            let diagnostic = Diagnostic::config(
                CODE_CURRENT_DIR,
                format!("failed to determine current directory: {error}"),
            );
            let _ = render_diagnostics(vec![diagnostic], stderr);
            ExitCode::from(2)
        }
    }
}

fn run_with_io(
    mut args: Vec<String>,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    if args.first().is_none_or(|argument| {
        matches!(argument.as_str(), "generate" | "check") || argument.starts_with('-')
    }) {
        args.insert(0, "oasts".to_owned());
    }
    run_os_with_io(
        args.into_iter().map(OsString::from).collect(),
        cwd,
        stdout,
        stderr,
    )
}

fn run_os_with_io(
    args: Vec<OsString>,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = write!(stderr, "{error}");
            return 2;
        }
    };
    match cli.command {
        Command::Generate { check, config } => {
            generate(config.as_deref(), check, cwd, stdout, stderr)
        }
        Command::Check { config } => check_input(config.as_deref(), cwd, stdout, stderr),
    }
}

fn generate(
    config_path: Option<&Path>,
    check: bool,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let (config, files, sink) = compile(config_path, cwd, true);
    if let Err(exit_code) = drain_warnings(sink, stderr) {
        return exit_code;
    }
    let config = config.expect("successful compilation retains its configuration");
    let files = files.expect("successful emitting compilation returns generated files");

    if check {
        let report = check_drift(&config.output, files);
        if !report.diagnostics.is_empty() {
            return report_diagnostics(report.diagnostics, stderr);
        }
        if report.is_clean() {
            let _ = writeln!(stdout, "check ok");
            return 0;
        }
        for entry in report
            .entries
            .iter()
            .filter(|entry| entry.state != DriftState::Clean)
        {
            let _ = writeln!(stderr, "{}: {}", entry.state, entry.relative_path);
        }
        return 1;
    }

    let generated_count = files.len();
    match write(&config.output, files) {
        Ok(_) => {
            let _ = writeln!(stdout, "generated {generated_count} files");
            0
        }
        Err(diagnostics) => report_diagnostics(diagnostics, stderr),
    }
}

fn check_input(
    config_path: Option<&Path>,
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let (_, _, sink) = compile(config_path, cwd, false);
    if let Err(exit_code) = drain_warnings(sink, stderr) {
        return exit_code;
    }
    let _ = writeln!(stdout, "check ok");
    0
}

fn drain_warnings(sink: DiagnosticSink, stderr: &mut dyn Write) -> Result<(), u8> {
    if sink.has_errors() {
        return Err(report_sink(sink, stderr));
    }
    let _ = render_diagnostics(sink.into_sorted_vec(), stderr);
    Ok(())
}

fn compile(
    config_path: Option<&Path>,
    cwd: &Path,
    should_emit: bool,
) -> (
    Option<ResolvedConfig>,
    Option<Vec<GeneratedFile>>,
    DiagnosticSink,
) {
    let mut sink = DiagnosticSink::new();
    let config = match load_config(config_path, cwd) {
        Ok(config) => config,
        Err(diagnostics) => {
            sink.extend(diagnostics);
            return (None, None, sink);
        }
    };
    let files = pipeline::compile(&config, should_emit, &mut sink);
    (Some(config), files, sink)
}

fn report_sink(sink: DiagnosticSink, stderr: &mut dyn Write) -> u8 {
    let exit_code = sink.worst_exit_code();
    let _ = render_diagnostics(sink.into_sorted_vec(), stderr);
    exit_code
}

fn report_diagnostics(diagnostics: Vec<Diagnostic>, stderr: &mut dyn Write) -> u8 {
    let mut sink = DiagnosticSink::new();
    sink.extend(diagnostics);
    report_sink(sink, stderr)
}

fn render_diagnostics(diagnostics: Vec<Diagnostic>, stderr: &mut dyn Write) -> io::Result<()> {
    diag::render(diagnostics, stderr)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn invoke(args: &[&str], cwd: &Path) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with_io(
            args.iter().map(|value| (*value).to_owned()).collect(),
            cwd,
            &mut stdout,
            &mut stderr,
        );
        (
            code,
            String::from_utf8(stdout).expect("UTF-8 stdout"),
            String::from_utf8(stderr).expect("UTF-8 stderr"),
        )
    }

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

    fn raw_json_project(document: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("openapi.json"), document).expect("OpenAPI JSON");
        fs::write(
            temp.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated"}"#,
        )
        .expect("config JSON");
        temp
    }

    fn tree_digest(root: &Path) -> [u8; 32] {
        let mut files = BTreeMap::new();
        collect_files(root, root, &mut files);
        let mut hasher = Sha256::new();
        for (path, bytes) in files {
            hasher.update(
                u64::try_from(path.len())
                    .expect("path length")
                    .to_be_bytes(),
            );
            hasher.update(path.as_bytes());
            hasher.update(
                u64::try_from(bytes.len())
                    .expect("file length")
                    .to_be_bytes(),
            );
            hasher.update(bytes);
        }
        hasher.finalize().into()
    }

    fn collect_files(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .expect("read tree")
            .map(|entry| entry.expect("entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                collect_files(root, &path, files);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.insert(relative, fs::read(path).expect("file bytes"));
            }
        }
    }

    fn manifest_paths(output: &Path) -> Vec<String> {
        let manifest: Value = serde_json::from_slice(
            &fs::read(output.join(".oasts-manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        manifest["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|path| path.as_str().expect("path").to_owned())
            .collect()
    }

    #[test]
    fn fixtures_generate_deterministically_and_report_all_drift_states() {
        for fixture in ["petstore-3.0", "tictactoe-3.1"] {
            let temp = copy_fixture(fixture);
            let output = temp.path().join("generated");
            let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());
            assert_eq!(code, 0, "{fixture}: {stderr}");
            assert!(stdout.starts_with("generated "));
            assert!(output.join(".oasts-manifest.json").is_file());
            let paths = manifest_paths(&output);
            assert!(!paths.is_empty());
            for path in &paths {
                assert!(output.join(path).is_file(), "{fixture}: {path}");
            }

            let first_digest = tree_digest(&output);
            let (code, _, stderr) = invoke(&["oasts", "generate"], temp.path());
            assert_eq!(code, 0, "{fixture}: {stderr}");
            assert_eq!(tree_digest(&output), first_digest);

            fs::write(output.join(&paths[0]), "edited\n").expect("edit output");
            let (code, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
            assert_eq!(code, 1);
            assert!(stderr.contains("edited:"), "{stderr}");

            assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
            fs::remove_file(output.join(&paths[0])).expect("remove output");
            let (code, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
            assert_eq!(code, 1);
            assert!(stderr.contains("missing:"), "{stderr}");

            assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
            let manifest_path = output.join(".oasts-manifest.json");
            let mut manifest: Value =
                serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
                    .expect("manifest JSON");
            manifest["files"]
                .as_array_mut()
                .expect("files")
                .push(json!("stale.ts"));
            let mut bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
            bytes.push(b'\n');
            fs::write(&manifest_path, bytes).expect("stale manifest");
            let (code, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
            assert_eq!(code, 1);
            assert!(stderr.contains("stale:"), "{stderr}");

            assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
            let (code, stdout, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
            assert_eq!(code, 0, "{fixture}: {stderr}");
            assert_eq!(stdout, "check ok\n");
        }
    }

    #[test]
    fn hostile_manifest_aborts_generate_with_exit_two() {
        for absolute in [false, true] {
            let temp = copy_fixture("petstore-3.0");
            assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
            let output = temp.path().join("generated");
            let generated = manifest_paths(&output)
                .into_iter()
                .next()
                .expect("generated path");
            fs::remove_file(output.join(&generated)).expect("remove generated file");
            let victim = temp.path().join("victim.ts");
            fs::write(&victim, "safe\n").expect("victim");
            let hostile = if absolute {
                victim.to_string_lossy().into_owned()
            } else {
                "../victim.ts".to_owned()
            };
            let manifest = json!({"manifestVersion": 1, "files": [hostile]});
            let mut bytes = serde_json::to_vec(&manifest).expect("manifest bytes");
            bytes.push(b'\n');
            fs::write(output.join(".oasts-manifest.json"), bytes).expect("manifest");

            let (code, _, stderr) = invoke(&["oasts", "generate"], temp.path());

            assert_eq!(code, 2, "{stderr}");
            assert_eq!(fs::read_to_string(&victim).expect("victim"), "safe\n");
            assert!(!output.join(&generated).exists());
        }
    }

    #[test]
    fn check_validates_without_touching_output() {
        let temp = copy_fixture("petstore-3.0");
        let (code, stdout, stderr) = invoke(&["oasts", "check"], temp.path());
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "check ok\n");
        assert!(!temp.path().join("generated").exists());
    }

    #[test]
    fn check_reports_composition_warnings_and_emission_errors_without_writing_output() {
        let temp = raw_json_project(
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Impossible":{"allOf":[{"type":"string"},{"type":"integer"}]}}}}"#,
        );

        let (code, stdout, stderr) =
            invoke(&["oasts", "check", "--config", "oasts.json"], temp.path());

        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "check ok\n");
        assert!(stderr.contains("warning[OASTS1303]"), "{stderr}");
        assert!(stderr.contains("disjoint primitive type sets"), "{stderr}");
        assert!(!temp.path().join("generated").exists());

        let reserved = raw_json_project(
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"CON":{"type":"string"}}}}"#,
        );
        let (code, _, stderr) = invoke(
            &["oasts", "check", "--config", "oasts.json"],
            reserved.path(),
        );
        assert_eq!(code, 1, "{stderr}");
        assert!(stderr.contains("error[OASTS1301]"), "{stderr}");
        assert!(stderr.contains("Windows reserved device"), "{stderr}");
        assert!(!reserved.path().join("generated").exists());
    }

    #[test]
    fn json_enum_and_const_outside_binary64_are_input_diagnostics() {
        for document in [
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Value":{"type":"number","enum":[1e999]}}}}"#,
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Value":{"type":"number","const":1e999}}}}"#,
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Value":{"enum":[{"nested":[1e999]}]}}}}"#,
        ] {
            let temp = raw_json_project(document);
            let (code, stdout, stderr) = invoke(
                &["oasts", "generate", "--config", "oasts.json"],
                temp.path(),
            );
            assert_eq!(code, 1, "{stderr}");
            assert!(stdout.is_empty(), "{stdout}");
            assert!(stderr.contains("error[OASTS1214]"), "{stderr}");
            assert!(stderr.contains("outside the binary64 domain"), "{stderr}");

            fs::write(
                temp.path().join("oasts.json"),
                r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated","types":{"enum":"const"}}"#,
            )
            .expect("const config JSON");
            let (code, _, stderr) = invoke(
                &["oasts", "generate", "--config", "oasts.json"],
                temp.path(),
            );
            assert_eq!(code, 1, "{stderr}");
            assert!(stderr.contains("outside the binary64 domain"), "{stderr}");
        }
    }

    #[test]
    fn invalid_multiple_of_is_an_input_diagnostic() {
        let temp = raw_json_project(
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Value":{"type":"number","multipleOf":"invalid"}}}}"#,
        );
        let (code, stdout, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );

        assert_eq!(code, 1, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("error[OASTS1112]"), "{stderr}");
    }

    #[test]
    fn json_defaults_and_examples_outside_binary64_render_annotated_in_tsdoc() {
        let temp = raw_json_project(
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Top":{"type":"number","default":1e999,"examples":[1e999]},"Container":{"type":"object","properties":{"value":{"type":"string","default":{"nested":[1e999]}}}}}}}"#,
        );

        let (code, stdout, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );

        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "generated 2 files\n");
        assert!(stderr.contains("OASTS1216"), "{stderr}");
        let top = fs::read_to_string(temp.path().join("generated/types/components/top.ts"))
            .expect("Top output");
        assert!(
            top.contains("Default value: 1e+999 (outside the binary64 range)"),
            "{top}"
        );
        assert!(
            top.contains("Outside the binary64 range.\n * \n * ```json\n * 1e+999\n * ```"),
            "{top}"
        );
        let container =
            fs::read_to_string(temp.path().join("generated/types/components/container.ts"))
                .expect("Container output");
        assert!(
            container.contains(
                "@defaultValue {\"nested\":[1e+999]\\} (contains a value outside the binary64 range)"
            ),
            "{container}"
        );
    }

    #[test]
    fn successful_generate_prints_structural_discriminator_warning() {
        let temp = raw_json_project(
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Choice":{"oneOf":[{"type":"string"},{"type":"integer"}],"discriminator":{"propertyName":"kind"}}}}}"#,
        );

        let (code, stdout, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );

        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "generated 1 files\n");
        assert!(stderr.contains("warning[OASTS1304]"), "{stderr}");
        assert!(
            stderr.contains("emitting a structural union because"),
            "{stderr}"
        );
    }

    #[test]
    fn yaml_config_with_every_supported_option_generates_successfully() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(&json!({
                "openapi": "3.1.0",
                "info": { "title": "complete config", "version": "1" },
                "paths": {},
                "components": { "schemas": { "Value": { "type": "string" } } }
            }))
            .expect("OpenAPI JSON"),
        )
        .expect("OpenAPI file");
        fs::write(
            temp.path().join("oasts.yaml"),
            concat!(
                "$schema: https://example.test/oasts.schema.json\n",
                "schemaVersion: 1\n",
                "workspaceRoot: .\n",
                "input:\n  path: ./openapi.json\n",
                "output: ./generated\n",
                "namespace: Complete\n",
                "artifacts:\n  types: true\n",
                "types:\n  enum: literal\n  enumExtensions: accept\n  dateTime: string\n  date: string\n  readonly: true\n",
                "naming:\n  fileCase: kebab\n  typeCase: pascal\n  propertyCase: preserve\n  operationCase: camel\n  enumMemberCase: pascal\n  typePrefix: ''\n  typeSuffix: ''\n",
                "documentation:\n  enabled: true\n  summary: true\n  description: true\n  deprecated: true\n  examples: true\n  constraints: true\n",
                "emit:\n  runtimeDirectory: runtime\n  importExtension: none\n  banner: [Complete]\n  format: deterministic\n",
                "local:\n  allowPaths: [.]\n",
                "limits:\n  maxDocumentBytes: 1024\n  maxTotalBytes: 2048\n  maxDocuments: 2\n  maxRefDepth: 2\n",
            ),
        )
        .expect("config file");

        let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());

        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "generated 1 files\n");

        fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&json!({
                "$schema": "https://example.test/oasts.schema.json",
                "schemaVersion": 1,
                "workspaceRoot": ".",
                "input": { "path": "./openapi.json" },
                "output": "./generated-json",
                "namespace": "Complete",
                "artifacts": {
                    "types": { "enabled": true, "directory": "types" },
                    "client": { "enabled": false },
                    "zod": false,
                    "validators": false,
                    "tanstack": false,
                    "msw": false
                },
                "types": {
                    "enum": "literal",
                    "enumExtensions": "accept",
                    "dateTime": "string",
                    "date": "string",
                    "readonly": true
                },
                "naming": {
                    "fileCase": "kebab",
                    "typeCase": "pascal",
                    "propertyCase": "preserve",
                    "operationCase": "camel",
                    "enumMemberCase": "pascal",
                    "typePrefix": "",
                    "typeSuffix": ""
                },
                "documentation": {
                    "enabled": true,
                    "summary": true,
                    "description": true,
                    "deprecated": true,
                    "examples": true,
                    "constraints": true
                },
                "emit": {
                    "runtimeDirectory": "runtime",
                    "importExtension": "none",
                    "banner": ["Complete"],
                    "format": "deterministic"
                },
                "local": { "allowPaths": [] },
                "limits": {
                    "maxDocumentBytes": 1024,
                    "maxTotalBytes": 2048,
                    "maxDocuments": 2,
                    "maxRefDepth": 2
                }
            }))
            .expect("config JSON"),
        )
        .expect("JSON config file");
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );
        assert_eq!(code, 0, "{stderr}");

        let relative_temp = tempfile::tempdir_in("../../target").expect("relative tempdir");
        fs::write(
            relative_temp.path().join("openapi.json"),
            fs::read(temp.path().join("openapi.json")).expect("OpenAPI bytes"),
        )
        .expect("relative OpenAPI file");
        fs::write(
            relative_temp.path().join("oasts.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated"
            }))
            .expect("relative config JSON"),
        )
        .expect("relative config file");
        let relative_cwd = PathBuf::from("../../target").join(
            relative_temp
                .path()
                .file_name()
                .expect("relative tempdir name"),
        );
        assert_eq!(invoke(&["oasts", "check"], &relative_cwd).0, 0);
    }

    #[test]
    fn invalid_input_config_and_cli_syntax_use_expected_exit_codes() {
        let invalid_input = copy_fixture("petstore-3.0");
        fs::write(
            invalid_input.path().join("openapi.yaml"),
            "openapi: '2.0'\ninfo: { title: Invalid, version: 1.0.0 }\npaths: {}\n",
        )
        .expect("invalid input");
        let (code, _, stderr) = invoke(&["oasts", "check"], invalid_input.path());
        assert_eq!(code, 1);
        assert!(stderr.contains("error[OASTS1101]"), "{stderr}");

        let invalid_config = copy_fixture("petstore-3.0");
        fs::write(
            invalid_config.path().join("oasts.yaml"),
            "schemaVersion: 1\ninput: { path: ./openapi.yaml }\noutput: ./generated\nclient: {}\n",
        )
        .expect("invalid config");
        assert_eq!(invoke(&["oasts", "check"], invalid_config.path()).0, 2);

        let missing_config = tempfile::tempdir().expect("tempdir");
        assert_eq!(invoke(&["oasts", "check"], missing_config.path()).0, 2);
        assert_eq!(
            invoke(&["oasts", "generate", "--unknown"], missing_config.path()).0,
            2
        );
        assert_eq!(invoke(&["oasts", "unknown"], missing_config.path()).0, 2);
        assert_eq!(invoke(&["check"], missing_config.path()).0, 2);

        let invalid_yaml = copy_fixture("petstore-3.0");
        fs::write(invalid_yaml.path().join("oasts.yaml"), "schemaVersion: [\n")
            .expect("invalid YAML");
        assert_eq!(invoke(&["oasts", "check"], invalid_yaml.path()).0, 2);

        let invalid_json = tempfile::tempdir().expect("tempdir");
        fs::write(invalid_json.path().join("oasts.json"), "{\n").expect("invalid JSON config");
        assert_eq!(invoke(&["oasts", "check"], invalid_json.path()).0, 2);

        let unsupported_json = tempfile::tempdir().expect("tempdir");
        fs::write(
            unsupported_json.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"url":"https://example.test/openapi.json"},"output":"./generated","remote":{}}"#,
        )
        .expect("unsupported JSON config");
        assert_eq!(invoke(&["oasts", "check"], unsupported_json.path()).0, 2);

        let missing_input = copy_fixture("petstore-3.0");
        fs::remove_file(missing_input.path().join("openapi.yaml")).expect("remove input");
        assert_eq!(invoke(&["oasts", "check"], missing_input.path()).0, 2);
    }

    #[test]
    fn invalid_manifest_is_a_config_failure_without_output_mutation() {
        let temp = copy_fixture("petstore-3.0");
        assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
        let output = temp.path().join("generated");
        let generated = manifest_paths(&output)
            .into_iter()
            .next()
            .expect("generated path");
        fs::remove_file(output.join(&generated)).expect("remove generated file");
        fs::write(output.join(".oasts-manifest.json"), "not JSON\n").expect("invalid manifest");

        let (code, _, stderr) = invoke(&["oasts", "generate"], temp.path());

        assert_eq!(code, 2, "{stderr}");
        assert!(stderr.contains("error[OASTS0231]"), "{stderr}");
        assert!(!output.join(generated).exists());
    }

    #[test]
    fn diagnostic_exit_precedence_and_rendering_are_deterministic() {
        let diagnostics = vec![
            Diagnostic::input("OASTS1000", "input")
                .with_source("workspace/api.yaml")
                .with_location(4, 2)
                .with_json_pointer("/paths"),
            Diagnostic::config("OASTS0031", "config"),
        ];
        let mut stderr = Vec::new();

        let code = report_diagnostics(diagnostics, &mut stderr);

        assert_eq!(code, 2);
        assert_eq!(
            String::from_utf8(stderr).expect("stderr"),
            "error[OASTS0031]: config\nerror[OASTS1000]: input\n  --> workspace/api.yaml:4:2 /paths\n"
        );
    }

    #[test]
    fn public_entrypoints_and_current_directory_failure_are_covered() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert_eq!(run(vec!["unknown".to_owned()], temp.path()), 2);
        let _exit = run_from_env();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _exit = run_from_state(
            vec![OsString::from("oasts"), OsString::from("check")],
            Err(io::Error::other("cwd unavailable")),
            &mut stdout,
            &mut stderr,
        );
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("stderr")
                .contains("cwd unavailable")
        );
    }

    #[test]
    fn rendering_propagates_writer_failures() {
        let mut writer = FailingWriter;
        std::io::Write::flush(&mut writer).expect("flush");
        let error = render_diagnostics(
            vec![Diagnostic::config("OASTS0000", "failure")],
            &mut writer,
        )
        .expect_err("writer failure");

        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn invalid_manifest_is_reported_in_generate_check_mode() {
        let temp = copy_fixture("petstore-3.0");
        assert_eq!(invoke(&["oasts", "generate"], temp.path()).0, 0);
        fs::write(
            temp.path().join("generated/.oasts-manifest.json"),
            "not JSON\n",
        )
        .expect("invalid manifest");
        let (code, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
        assert_eq!(code, 2);
        assert!(stderr.contains("OASTS0231"));
    }

    #[test]
    fn generate_reports_compilation_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (code, _, stderr) = invoke(&["oasts", "generate"], temp.path());
        assert_eq!(code, 2);
        assert!(stderr.contains("OASTS0011"));
    }
}
