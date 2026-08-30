//! Command-line orchestration for the Oasts compiler pipeline.
//!
//! Exit status precedence is `2` for configuration/IO/internal failures over
//! `1` for input/semantic failures when a sink contains both categories.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use oasts_core::diag::{self, Diagnostic};
use oasts_core::driver::{self, Command as DriverCommand, ConfigSource, Outcome, Tracking};

const CODE_CURRENT_DIR: &str = "OASTS1021";

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
        /// Build only the named workspace spec; repeatable.
        #[arg(long, value_name = "NAME")]
        spec: Vec<String>,
    },
    /// Validate configuration and input without emitting artifacts.
    Check {
        /// Use an explicit configuration file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Build only the named workspace spec; repeatable.
        #[arg(long, value_name = "NAME")]
        spec: Vec<String>,
    },
    /// Watch inputs and regenerate until interrupted.
    Watch {
        /// Use an explicit configuration file.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Build only the named workspace spec; repeatable.
        #[arg(long, value_name = "NAME")]
        spec: Vec<String>,
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
        matches!(argument.as_str(), "generate" | "check" | "watch") || argument.starts_with('-')
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
        Command::Watch { config, spec } => {
            crate::watch::run(config.as_deref(), &spec, cwd, stdout, stderr)
        }
        Command::Generate {
            check,
            config,
            spec,
        } => dispatch(
            DriverCommand::Generate { check },
            config.as_deref(),
            &spec,
            cwd,
            stdout,
            stderr,
        ),
        Command::Check { config, spec } => dispatch(
            DriverCommand::Check,
            config.as_deref(),
            &spec,
            cwd,
            stdout,
            stderr,
        ),
    }
}

fn dispatch(
    command: DriverCommand,
    config_path: Option<&Path>,
    specs: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let outcome = driver::run(
        command,
        ConfigSource::Path {
            explicit: config_path,
            cwd,
        },
        specs,
        oasts_fetch::handle(),
        Tracking::Off,
    );
    report(outcome, stdout, stderr)
}

pub(crate) fn report(outcome: Outcome, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let _ = render_diagnostics(outcome.diagnostics, stderr);
    for line in &outcome.drift_lines {
        let _ = writeln!(stderr, "{line}");
    }
    if let Some(summary) = outcome.stdout_summary {
        let _ = writeln!(stdout, "{summary}");
    }
    outcome.exit_code
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

    /// A project around a schema-only document.
    ///
    /// These documents declare no operations, so every component is unreachable and the default
    /// pruning would emit nothing. `orphans: true` is the escape hatch for exactly that shape.
    fn raw_json_project(document: &str) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("openapi.json"), document).expect("OpenAPI JSON");
        fs::write(
            temp.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated","filters":{"orphans":true}}"#,
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
        assert!(stderr.contains("warning[OASTS4201]"), "{stderr}");
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
        assert!(stderr.contains("error[OASTS4001]"), "{stderr}");
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
            assert!(stderr.contains("error[OASTS3101]"), "{stderr}");
            assert!(stderr.contains("outside the binary64 domain"), "{stderr}");

            fs::write(
                temp.path().join("oasts.json"),
                r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated","filters":{"orphans":true},"types":{"enum":"const"}}"#,
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
    fn numeric_member_with_oversized_exponent_is_an_input_diagnostic() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            r#"{
  "openapi": "3.1.0",
  "paths": {
    "/value": {
      "get": {
        "operationId": "getValue",
        "responses": {
          "200": {
            "description": "ok",
            "content": {
              "application/json": {
                "schema": {
                  "type": "number",
                  "enum": [1e-99999999999999999999]
                }
              }
            }
          }
        }
      }
    }
  }
}"#,
        )
        .expect("OpenAPI JSON");
        fs::write(
            temp.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated"}"#,
        )
        .expect("config JSON");

        let (code, stdout, stderr) =
            invoke(&["oasts", "check", "--config", "oasts.json"], temp.path());

        assert_eq!(code, 1, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("error[OASTS3104]"), "{stderr}");
        assert!(
            stderr.contains("exponent outside the supported decimal domain"),
            "{stderr}"
        );
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
        assert!(stderr.contains("error[OASTS2204]"), "{stderr}");
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
        assert!(stderr.contains("OASTS3103"), "{stderr}");
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
        assert!(stderr.contains("warning[OASTS4202]"), "{stderr}");
        assert!(
            stderr.contains("emitting a structural union because"),
            "{stderr}"
        );
    }

    /// The one emission decision a consumer's own file reaches: a committed tsconfig whose `lib`
    /// already declares `Temporal` means generated code does not repeat the reference directive.
    /// End to end through the CLI, because that is the path a consumer actually takes.
    #[test]
    fn a_consumer_lib_that_declares_temporal_drops_the_reference_directive() {
        let document = serde_json::to_vec(&json!({
            "openapi": "3.1.0",
            "info": { "title": "temporal", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "required": ["at"],
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }
            }
        }))
        .expect("OpenAPI JSON");
        let config = concat!(
            "schemaVersion: 1\n",
            "workspaceRoot: .\n",
            "input:\n  path: ./openapi.json\n",
            "output: ./generated\n",
            "artifacts:\n  types: true\n  client: true\n",
            "client:\n  authEnforcement: types\n  baseUrl:\n    source: runtime\n",
            "types:\n  dateTime: temporal\n",
            "validation:\n  engine: 'off'\n  unchecked: allow\n",
        );
        let directive = "/// <reference lib=\"esnext.temporal\" preserve=\"true\" />";

        let carries_directive = |tsconfig: Option<&str>, extra_config: &str| -> usize {
            let temp = tempfile::tempdir().expect("tempdir");
            fs::write(temp.path().join("openapi.json"), &document).expect("document");
            fs::write(
                temp.path().join("oasts.yaml"),
                format!("{config}{extra_config}"),
            )
            .expect("config");
            if let Some(tsconfig) = tsconfig {
                fs::write(temp.path().join("tsconfig.json"), tsconfig).expect("tsconfig");
            }
            let (code, _stdout, stderr) = invoke(&["oasts", "generate"], temp.path());
            assert_eq!(code, 0, "{stderr}");
            let mut count = 0;
            let mut stack = vec![temp.path().join("generated")];
            while let Some(directory) = stack.pop() {
                for entry in fs::read_dir(&directory).expect("read generated") {
                    let path = entry.expect("entry").path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if fs::read_to_string(&path).is_ok_and(|body| body.contains(directive)) {
                        count += 1;
                    }
                }
            }
            count
        };

        // No tsconfig, and one whose lib cannot supply Temporal: the directive is carried.
        assert!(carries_directive(None, "") > 0);
        assert!(carries_directive(Some(r#"{ "compilerOptions": { "lib": ["ES2023"] } }"#), "") > 0);
        // A lib that does supply it: nothing repeats the declaration.
        assert_eq!(
            carries_directive(
                Some(r#"{ "compilerOptions": { "lib": ["ES2023", "ESNext.Temporal"] } }"#),
                ""
            ),
            0
        );
        assert_eq!(
            carries_directive(Some(r#"{ "compilerOptions": { "target": "ESNext" } }"#), ""),
            0
        );
        // And opting out of reading it puts the directive back, which is what makes output that
        // depends on version, config and input alone still reachable.
        assert!(
            carries_directive(
                Some(r#"{ "compilerOptions": { "lib": ["ESNext"] } }"#),
                "typescript:\n  tsconfig: 'off'\n",
            ) > 0
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
                "filters:\n  orphans: true\n  deprecated: true\n",
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
                "filters": { "orphans": true, "deprecated": true },
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
    fn selecting_a_spec_from_a_single_spec_config_refuses() {
        let configured = copy_fixture("petstore-3.0");
        for args in [
            vec!["oasts", "generate", "--spec", "petstore"],
            vec!["oasts", "check", "--spec", "petstore"],
            vec!["oasts", "generate", "--spec", "petstore", "--spec", "other"],
        ] {
            let (code, stdout, stderr) = invoke(&args, configured.path());
            assert_eq!(code, 2, "{args:?}: {stderr}");
            assert!(stdout.is_empty(), "{args:?}: {stdout}");
            assert!(stderr.contains("error[OASTS0296]"), "{args:?}: {stderr}");
        }
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
        assert!(stderr.contains("error[OASTS2101]"), "{stderr}");

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
            r#"{"schemaVersion":1,"input":{"path":"./openapi.yaml"},"output":"./generated","watch":{}}"#,
        )
        .expect("unsupported JSON config");
        assert_eq!(invoke(&["oasts", "check"], unsupported_json.path()).0, 2);

        // A retrievable input the configuration never authorized is a fact about the input, not
        // about the configuration's shape, so it exits 1 like any other document failure — and it
        // does so without the seated retriever ever being asked for anything.
        let unauthorized = tempfile::tempdir().expect("tempdir");
        fs::write(
            unauthorized.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"url":"https://example.invalid/openapi.json"},"output":"./generated"}"#,
        )
        .expect("unauthorized JSON config");
        let (code, _, stderr) = invoke(&["oasts", "check"], unauthorized.path());
        assert_eq!(code, 1);
        assert!(stderr.contains("OASTS2021"), "{stderr}");

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
        assert!(stderr.contains("error[OASTS1011]"), "{stderr}");
        assert!(!output.join(generated).exists());
    }

    #[test]
    fn outcome_rendering_is_deterministic() {
        let outcome = Outcome {
            exit_code: 2,
            watch_plan: None,
            stdout_summary: Some("check ok".to_owned()),
            diagnostics: vec![
                Diagnostic::input("OASTS9903", "input")
                    .with_source("workspace/api.yaml")
                    .with_location(4, 2)
                    .with_json_pointer("/paths"),
                Diagnostic::config("OASTS0031", "config"),
            ],
            drift_lines: vec!["modified: generated/api.ts".to_owned()],
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = report(outcome, &mut stdout, &mut stderr);

        assert_eq!(code, 2);
        assert_eq!(String::from_utf8(stdout).expect("stdout"), "check ok\n");
        assert_eq!(
            String::from_utf8(stderr).expect("stderr"),
            "error[OASTS0031]: config\nerror[OASTS9903]: input\n  --> workspace/api.yaml:4:2 /paths\nmodified: generated/api.ts\n"
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
            vec![Diagnostic::config("OASTS9901", "failure")],
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
        assert!(stderr.contains("OASTS1011"));
    }

    #[test]
    fn generate_reports_compilation_errors() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (code, _, stderr) = invoke(&["oasts", "generate"], temp.path());
        assert_eq!(code, 2);
        assert!(stderr.contains("OASTS0011"));
    }

    fn project_with_installed_package(
        artifacts: &str,
        package_name: &str,
        version: &str,
    ) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Thing":{"type":"string"}}}}"#,
        )
        .expect("OpenAPI JSON");
        fs::write(
            temp.path().join("oasts.json"),
            format!(
                // A schema-only document: every component is unreachable, so pruning is opted out of.
                r#"{{"schemaVersion":1,"input":{{"path":"./openapi.json"}},"output":"./generated","filters":{{"orphans":true}},"artifacts":{artifacts}}}"#
            ),
        )
        .expect("config JSON");
        let package = temp.path().join("node_modules").join(package_name);
        fs::create_dir_all(&package).expect("package directory");
        fs::write(
            package.join("package.json"),
            format!("{{\"name\":\"{package_name}\",\"version\":\"{version}\"}}"),
        )
        .expect("package manifest");
        temp
    }

    #[test]
    fn generate_warns_when_the_installed_zod_is_out_of_range() {
        let temp = project_with_installed_package(r#"{"types":true,"zod":true}"#, "zod", "4.1.0");
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );
        assert_eq!(code, 0);
        assert!(stderr.contains("OASTS0241"), "{stderr}");
        assert!(stderr.contains("^4.4.0"), "{stderr}");
    }

    #[test]
    fn generate_stays_quiet_when_the_installed_zod_is_supported() {
        let temp = project_with_installed_package(r#"{"types":true,"zod":true}"#, "zod", "4.4.0");
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );
        assert_eq!(code, 0);
        assert!(!stderr.contains("OASTS0241"), "{stderr}");
    }

    #[test]
    fn check_mode_does_not_inspect_the_installed_zod() {
        let temp = project_with_installed_package(r#"{"types":true,"zod":true}"#, "zod", "4.1.0");
        assert_eq!(
            invoke(
                &["oasts", "generate", "--config", "oasts.json"],
                temp.path()
            )
            .0,
            0
        );
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json", "--check"],
            temp.path(),
        );
        assert_eq!(code, 0);
        assert!(!stderr.contains("OASTS0241"), "{stderr}");
    }

    #[test]
    fn a_run_without_the_zod_artifact_ignores_the_installed_zod() {
        let temp = project_with_installed_package(r#"{"types":true}"#, "zod", "4.1.0");
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );
        assert_eq!(code, 0);
        assert!(!stderr.contains("OASTS0241"), "{stderr}");
    }

    #[test]
    fn generate_warns_when_pruning_leaves_nothing_to_emit() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"Pet":{"type":"object"}}}}"#,
        )
        .expect("OpenAPI JSON");
        fs::write(
            temp.path().join("oasts.json"),
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated"}"#,
        )
        .expect("config JSON");

        let (code, stdout, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );

        assert_eq!(code, 0, "{stderr}");
        assert_eq!(stdout, "generated 0 files\n");
        assert!(stderr.contains("warning[OASTS2107]"), "{stderr}");
        assert!(stderr.contains("filters.orphans"), "{stderr}");
    }

    #[test]
    fn generate_warns_when_the_installed_msw_is_out_of_range() {
        let temp = project_with_installed_package(r#"{"types":true,"msw":true}"#, "msw", "3.0.0");
        let (code, _, stderr) = invoke(
            &["oasts", "generate", "--config", "oasts.json"],
            temp.path(),
        );

        assert_eq!(code, 0, "{stderr}");
        assert!(stderr.contains("OASTS0242"), "{stderr}");
        assert!(stderr.contains("^2.8.0"), "{stderr}");
    }

    fn workspace_fixture() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/petstore-3.0/openapi.yaml");
        for name in ["billing.yaml", "users.yaml"] {
            fs::copy(&source, temp.path().join(name)).expect("copy document");
        }
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\nshared:\n  artifacts: {types: true}\nspecs:\n  \
             users:\n    input: {path: ./users.yaml}\n    output: ./generated/users\n  \
             billing:\n    input: {path: ./billing.yaml}\n    output: ./generated/billing\n",
        )
        .expect("workspace config");
        temp
    }

    #[test]
    fn a_workspace_builds_every_spec_and_selects_one() {
        let temp = workspace_fixture();

        let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());
        assert_eq!(code, 0, "{stderr}");
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "{stdout}");
        assert!(lines[0].starts_with("billing: generated "), "{stdout}");
        assert!(lines[1].starts_with("users: generated "), "{stdout}");

        let (clean, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
        assert_eq!(clean, 0, "{stderr}");

        fs::write(
            temp.path().join("generated/users/types/headers.ts"),
            "// edited\n",
        )
        .expect("edit an owned file");
        let (drifted, _, stderr) = invoke(&["oasts", "generate", "--check"], temp.path());
        assert_eq!(drifted, 1);
        assert!(
            stderr.contains("edited: generated/users/types/headers.ts"),
            "{stderr}"
        );

        let (selected, stdout, stderr) =
            invoke(&["oasts", "generate", "--spec", "users"], temp.path());
        assert_eq!(selected, 0, "{stderr}");
        assert!(stdout.starts_with("users: generated "), "{stdout}");

        let (unknown, _, stderr) = invoke(&["oasts", "check", "--spec", "nope"], temp.path());
        assert_eq!(unknown, 2);
        assert!(
            stderr.contains(
                "error[OASTS0295]: no spec named 'nope'; this workspace declares billing, users"
            ),
            "{stderr}"
        );
    }

    #[test]
    fn a_workspace_that_cannot_compile_one_spec_writes_nothing() {
        let temp = workspace_fixture();
        fs::write(
            temp.path().join("users.yaml"),
            "openapi: '2.0'\ninfo: {title: Invalid, version: 1.0.0}\npaths: {}\n",
        )
        .expect("broken document");

        let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());

        assert_eq!(code, 1, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("spec 'users':"), "{stderr}");
        assert!(!temp.path().join("generated").exists());
    }

    #[test]
    fn a_root_that_cannot_be_written_is_refused_before_any_root_is_written() {
        let temp = workspace_fixture();
        fs::create_dir_all(temp.path().join("generated")).expect("output parent");
        fs::write(temp.path().join("generated/users"), "not a directory").expect("blocking file");

        let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());

        assert_eq!(code, 2, "{stderr}");
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("spec 'users':"), "{stderr}");
        assert!(!temp.path().join("generated/billing").exists());
    }

    #[test]
    fn two_specs_writing_into_one_tree_are_refused_before_any_write() {
        let temp = workspace_fixture();
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\nspecs:\n  \
             users:\n    input: {path: ./users.yaml}\n    output: ./generated\n  \
             billing:\n    input: {path: ./billing.yaml}\n    output: ./generated/billing\n",
        )
        .expect("colliding config");

        let (code, stdout, stderr) = invoke(&["oasts", "generate"], temp.path());

        assert_eq!(code, 2);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains("error[OASTS0082]"), "{stderr}");
        assert!(!temp.path().join("generated").exists());
    }
}
