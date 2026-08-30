//! Compilation pipeline shared by every CLI host.
//!
//! Orchestrates loading, parsing, semantic analysis, and emission for one
//! resolved configuration so the standalone binary and the Node binding run
//! the identical sequence.

use std::path::Path;
use std::sync::Arc;

use crate::client_model::build_client_model;
use crate::config::{ResolvedConfig, TsconfigSource};
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::emit::{GeneratedFile, emit_artifacts};
use crate::inputs::InputRecorder;
use crate::loader::load_graph_with_host;
use crate::parse::parse;
use crate::semantic::analyze;
use crate::source::{FetcherHandle, MemorySource, SourceHandle};

/// The synthetic root an in-memory compile is seated at.
///
/// Nothing on any host is named by it. `authorize_path` writes the literal prefix `workspace` into
/// every source id whatever the root is called, so this choice never reaches emitted bytes.
const MEMORY_ROOT: &str = "/workspace";
const MEMORY_CONFIG_PATH: &str = "/workspace/oasts.json";

/// Compiles one resolved configuration into generated files, reading from the filesystem.
///
/// Returns `Some(files)` only when the pipeline reached emission and
/// `should_emit` is true; diagnostics accumulate in `sink` either way.
pub fn compile(
    config: &ResolvedConfig,
    fetcher: FetcherHandle,
    should_emit: bool,
    inputs: &mut InputRecorder,
    sink: &mut DiagnosticSink,
) -> Option<Vec<GeneratedFile>> {
    compile_from(config, SourceHandle::Fs, fetcher, should_emit, inputs, sink)
}

/// Compiles one resolved configuration, reading documents from `source` and `fetcher`.
pub fn compile_from(
    config: &ResolvedConfig,
    source: SourceHandle,
    fetcher: FetcherHandle,
    should_emit: bool,
    inputs: &mut InputRecorder,
    sink: &mut DiagnosticSink,
) -> Option<Vec<GeneratedFile>> {
    // The loader records each document as it opens it, so a load that fails part way still reports
    // what it had reached and the path it choked on.
    let graph = load_graph_with_host(config, source, fetcher, inputs, sink)?;
    let ir = parse(&graph, sink)?;
    // Filtering and pruning run before analysis so name allocation, collision detection and path
    // registration see only survivors, and a filter diagnostic short-circuits here rather than
    // cascading into downstream naming errors.
    let ir = crate::filter::apply(ir, config.filters.as_ref(), &config.config_path, sink);
    if sink.has_errors() {
        return None;
    }
    // Parsing owns every downstream value in the IR. Keep only the source digest inputs so the
    // JSON document tree is released before analysis or emitted-file buffers can overlap with it.
    let source_tuples = graph.source_tuples();
    drop(graph);
    let analyzed = analyze(ir, config, sink);
    let client_model = config
        .artifacts
        .client
        .enabled
        .then(|| build_client_model(&analyzed, config, sink));
    if sink.has_errors() {
        return None;
    }
    let files = emit_artifacts(
        &analyzed,
        config,
        &source_tuples,
        client_model.as_ref(),
        inputs,
        sink,
    );
    if sink.has_errors() {
        return None;
    }
    should_emit.then_some(files)
}

/// One in-memory compilation: the files, and every diagnostic the run produced.
///
/// Warnings survive a successful compile, because a host that shows generated code has to be able
/// to show what the compiler said about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryCompilation {
    pub files: Vec<GeneratedFile>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Compiles one OpenAPI document and one JSON config with no filesystem at all.
///
/// The document is seated at whatever path the config's `input.path` resolves to below a synthetic
/// root, so a config naming any input is answered by the supplied document rather than by a missing
/// file. `output` is left as the config wrote it: it resolves lexically below the same root, and
/// every `GeneratedFile.relative_path` is output-root-relative regardless.
pub fn compile_in_memory(
    spec: &[u8],
    config_json: &[u8],
) -> Result<InMemoryCompilation, Vec<Diagnostic>> {
    let config_path = Path::new(MEMORY_CONFIG_PATH);
    let raw = crate::config::parse_config_json(config_path, config_json)
        .map_err(|diagnostic| vec![diagnostic])?;
    let tsconfig_default = crate::config::require_tsconfig_off(&raw, config_path)
        .map_err(|diagnostic| vec![diagnostic])?;
    crate::config::require_no_local_allow_paths(&raw, config_path)
        .map_err(|diagnostic| vec![diagnostic])?;
    crate::config::require_no_remote(&raw, config_path).map_err(|diagnostic| vec![diagnostic])?;
    crate::config::require_single_spec(&raw, config_path).map_err(|diagnostic| vec![diagnostic])?;

    let mut source = MemorySource::new(MEMORY_ROOT);
    let workspace = crate::config::resolve_config(config_path.to_path_buf(), raw, &source)?;
    // `require_single_spec` refused every workspace shape above, so exactly one target survives.
    let mut config = workspace
        .into_single()
        .expect("a config without specs resolves to exactly one target");
    // Stated rather than inherited: `require_tsconfig_off` has already refused every config that
    // asked for anything else, so this only closes the gap left by an absent key.
    config.tsconfig = TsconfigSource::Off;
    source.insert(&config.input, spec.to_vec());

    let mut sink = DiagnosticSink::new();
    sink.extend(std::mem::take(&mut config.diagnostics));
    sink.extend(tsconfig_default);
    let files = compile_from(
        &config,
        SourceHandle::Shared(Arc::new(source)),
        // A host with no filesystem also has no way to reach the network from inside the module,
        // so an `input.url` or a retrievable `$ref` is refused rather than silently resolved.
        FetcherHandle::None,
        true,
        &mut InputRecorder::off(),
        &mut sink,
    );
    let diagnostics = sink.into_sorted_vec();
    match files {
        Some(files) => Ok(InMemoryCompilation { files, diagnostics }),
        None => Err(diagnostics),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use serde_json::{Value, json};

    use crate::config::{load_single, load_single_from_json};

    /// Builds a document wide enough to cross `PARALLEL_PARSE_MIN_ITEMS`, which no fixture in the
    /// repository does, so parse takes its rayon branch rather than the sequential fallback.
    fn wide_document(schema_count: usize, path_count: usize) -> String {
        let mut spec = String::from("openapi: 3.1.1\ninfo: {title: t, version: 1.0.0}\npaths:\n");
        for index in 0..path_count {
            let schema = index % schema_count;
            spec.push_str(&format!(
                "  /items{index}:\n    get:\n      operationId: getItem{index}\n      parameters:\n        - {{name: q, in: query, schema: {{type: string}}}}\n      responses:\n        \"200\":\n          description: ok\n          content:\n            application/json:\n              schema: {{$ref: \"#/components/schemas/Schema{schema}\"}}\n"
            ));
        }
        spec.push_str("components:\n  schemas:\n");
        for index in 0..schema_count {
            spec.push_str(&format!(
                "    Schema{index}: {{type: object, required: [name], properties: {{name: {{type: string}}, index: {{type: integer}}}}}}\n"
            ));
        }
        spec
    }

    /// The one config both halves of the identity test run, so nothing but the read path differs.
    /// `tsconfig` is `off` on purpose: left to `auto`, the native half probes ancestors of its
    /// temporary output directory for a `tsconfig.json` and the in-memory half cannot.
    fn shared_config() -> Value {
        json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "typescript": { "tsconfig": "off" },
            "artifacts": {
                "types": true,
                "client": true,
                "validators": true,
                "zod": true,
                "tanstack": true,
                "msw": true
            },
            "validation": { "engine": "generated", "request": true, "response": true }
        })
    }

    #[test]
    fn a_workspace_config_needs_a_host_with_a_filesystem() {
        for block in ["specs", "shared"] {
            let config = json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.yaml" },
                "output": "./generated",
                "typescript": { "tsconfig": "off" },
                block: json!({}),
            });
            let diagnostics = compile_in_memory(b"", &serde_json::to_vec(&config).expect("config"))
                .expect_err("a workspace needs several documents and several output roots");
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>(),
                ["OASTS0297"]
            );
        }
    }

    #[test]
    fn compiling_in_memory_emits_the_bytes_the_filesystem_path_emits() {
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let documents = [
            fs::read(fixtures.join("petstore-3.0/openapi.yaml")).expect("petstore document"),
            fs::read(fixtures.join("client-showcase-3.1/openapi.yaml")).expect("showcase document"),
            wide_document(80, 80).into_bytes(),
        ];
        let config_json = serde_json::to_vec(&shared_config()).expect("config JSON");

        for spec in documents {
            let temp = tempfile::tempdir().expect("tempdir");
            fs::write(temp.path().join("openapi.yaml"), &spec).expect("OpenAPI document");
            let config = load_single_from_json(&temp.path().join("oasts.json"), &config_json)
                .expect("config");

            let mut sink = DiagnosticSink::new();
            let from_disk = compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink,
            )
            .expect("emitted files");
            assert!(!sink.has_errors(), "{:#?}", sink.as_slice());

            let in_memory = compile_in_memory(&spec, &config_json).expect("emitted files");

            assert_eq!(from_disk, in_memory.files);
        }
    }

    #[test]
    fn an_ambient_tsconfig_is_refused_rather_than_silently_overridden() {
        let mut raw = shared_config();
        for requested in ["auto", "./tsconfig.json"] {
            raw["typescript"] = json!({ "tsconfig": requested });
            let config_json = serde_json::to_vec(&raw).expect("config JSON");

            let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", &config_json)
                .expect_err("a tsconfig this host cannot read is refused");

            assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
            assert_eq!(diagnostics[0].code, "OASTS0251");
        }
    }

    #[test]
    fn an_omitted_tsconfig_key_compiles_and_says_what_it_assumed() {
        let mut raw = shared_config();
        raw.as_object_mut()
            .expect("config object")
            .remove("typescript");
        let config_json = serde_json::to_vec(&raw).expect("config JSON");
        let spec = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/petstore-3.0/openapi.yaml"),
        )
        .expect("petstore document");

        let compiled = compile_in_memory(&spec, &config_json).expect("emitted files");

        assert!(!compiled.files.is_empty());
        // An absent key means `auto` to the CLI, which probes; this host cannot, and the
        // difference reaches emitted bytes, so it is reported rather than assumed silently.
        let defaulted = compiled
            .diagnostics
            .iter()
            .find(|entry| entry.code == "OASTS0251")
            .expect("the defaulted tsconfig is reported");
        assert_eq!(defaulted.severity, crate::diag::Severity::Warning);
    }

    #[test]
    fn an_explicit_tsconfig_off_assumes_nothing_and_says_nothing() {
        let config_json = serde_json::to_vec(&shared_config()).expect("config JSON");
        // A document that does warn, so the search runs over something.
        let spec = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/client-showcase-3.1/openapi.yaml"),
        )
        .expect("showcase document");

        let compiled = compile_in_memory(&spec, &config_json).expect("emitted files");

        // Bound first: an argument evaluated only on failure is a region no passing run reaches.
        let diagnostics = compiled.diagnostics;
        assert!(!diagnostics.is_empty());
        assert!(
            !diagnostics.iter().any(|entry| entry.code == "OASTS0251"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn local_allow_paths_are_refused_rather_than_read_as_missing_documents() {
        let mut raw = shared_config();
        raw["local"] = json!({ "allowPaths": ["../shared"] });
        let config_json = serde_json::to_vec(&raw).expect("config JSON");

        let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", &config_json)
            .expect_err("a trust boundary with nothing behind it is refused");

        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "OASTS0221");
    }

    /// A retriever that answers one URI, so a compile can be driven without a network.
    #[derive(Debug)]
    struct OneDocument {
        uri: String,
        document: Vec<u8>,
    }

    impl crate::source::RemoteFetcher for OneDocument {
        fn fetch_once(
            &self,
            url: &str,
            _policy: &crate::source::FetchPolicy,
        ) -> Result<crate::source::FetchStep, String> {
            assert_eq!(url, self.uri, "only the configured URI is ever requested");
            Ok(crate::source::FetchStep::Body(self.document.clone()))
        }
    }

    #[test]
    fn compiling_a_retrieved_document_twice_emits_the_same_bytes() {
        const URI: &str = "https://specs.example.test/openapi.yaml";
        let document = wide_document(2, 2);
        let digest =
            crate::emit::lower_hex(&<sha2::Sha256 as sha2::Digest>::digest(document.as_bytes()));

        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("oasts.yaml"),
            format!(
                "schemaVersion: 1\ninput: {{ url: \"{URI}\" }}\noutput: generated\ntypescript: {{ tsconfig: \"off\" }}\nremote:\n  allowHosts: [specs.example.test]\n  integrity:\n    \"{URI}\": \"{}{digest}\"\n",
                crate::config::INTEGRITY_PREFIX
            ),
        )
        .expect("config");
        let config = load_single(Some(&temp.path().join("oasts.yaml")), temp.path())
            .expect("a pinned retrieval config resolves");

        let compile_once = || {
            let fetcher = FetcherHandle::from(Arc::new(OneDocument {
                uri: URI.to_owned(),
                document: document.as_bytes().to_vec(),
            })
                as Arc<dyn crate::source::RemoteFetcher>);
            let mut sink = DiagnosticSink::new();
            let files = compile_from(
                &config,
                SourceHandle::Fs,
                fetcher,
                true,
                &mut InputRecorder::off(),
                &mut sink,
            )
            .expect("a retrieved document compiles");
            assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
            files
        };

        let first = compile_once();
        let second = compile_once();

        assert_eq!(first, second);
        // The URI is the document's identity all the way through emission, so a reader of the
        // generated code can see which document a declaration came from.
        // The label is built before the assert: a call evaluated only on failure is a region the
        // coverage gate counts and no passing run reaches.
        let paths = first
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect::<Vec<_>>();
        assert!(
            first
                .iter()
                .any(|file| file.content.contains(&format!("// Source: {URI}#"))),
            "{paths:?}"
        );
    }

    #[test]
    fn a_remote_block_is_refused_by_a_host_that_cannot_reach_the_network() {
        let mut raw = shared_config();
        raw["remote"] = json!({ "allowHosts": ["specs.example.test"] });
        let config_json = serde_json::to_vec(&raw).expect("config JSON");

        let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", &config_json)
            .expect_err("retrieval this host cannot perform is refused");

        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "OASTS0271");
    }

    #[test]
    fn a_retrievable_entry_is_refused_by_a_host_that_cannot_reach_the_network() {
        let mut raw = shared_config();
        raw["input"] = json!({ "url": "https://specs.example.test/openapi.yaml" });
        let config_json = serde_json::to_vec(&raw).expect("config JSON");

        let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", &config_json)
            .expect_err("a retrievable entry is refused");

        // Nothing authorizes the host, so the refusal is about authorization rather than about
        // the capability: the more specific answer wins wherever both are true.
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "OASTS2021");
    }

    #[test]
    fn config_bytes_that_are_not_json_come_back_as_one_diagnostic() {
        let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", b"{not json")
            .expect_err("config bytes that are not JSON fail");

        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "OASTS0031");
    }

    #[test]
    fn a_config_that_does_not_resolve_comes_back_as_diagnostics() {
        let mut raw = shared_config();
        raw.as_object_mut().expect("config object").remove("output");
        let config_json = serde_json::to_vec(&raw).expect("config JSON");

        let diagnostics = compile_in_memory(b"openapi: 3.1.1\n", &config_json)
            .expect_err("a config missing output fails");

        assert!(
            diagnostics.iter().any(|entry| entry.code == "OASTS0061"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn a_reference_to_a_document_nobody_supplied_is_a_missing_document() {
        let config_json = serde_json::to_vec(&shared_config()).expect("config JSON");
        let spec = r##"openapi: 3.1.1
info: {title: t, version: 1.0.0}
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "./components.yaml#/Pet"}
"##;

        let diagnostics = compile_in_memory(spec.as_bytes(), &config_json)
            .expect_err("a second document was never supplied");

        assert!(
            diagnostics.iter().any(|entry| entry.code == "OASTS1003"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn compile_emits_identical_bytes_regardless_of_thread_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("openapi.yaml"), wide_document(80, 80))
            .expect("OpenAPI document");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": {
                "types": true,
                "client": true,
                "validators": true,
                "zod": true,
                "tanstack": true,
                "msw": true
            },
            "validation": { "engine": "generated", "request": true, "response": true }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let compile_with = |threads: usize| {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("rayon pool");
            pool.install(|| {
                let mut sink = DiagnosticSink::new();
                let files = compile(
                    &config,
                    FetcherHandle::None,
                    true,
                    &mut InputRecorder::off(),
                    &mut sink,
                )
                .expect("emitted files");
                assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
                files
            })
        };

        let single = compile_with(1);
        let parallel = compile_with(8);

        assert!(single.len() > 1, "{}", single.len());
        assert_eq!(single, parallel);
    }

    #[test]
    fn compile_emits_files_only_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/petstore-3.0");
        for file_name in ["openapi.yaml", "oasts.yaml"] {
            fs::copy(source.join(file_name), temp.path().join(file_name)).expect("copy fixture");
        }
        let config = load_single(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("emitted files");
        assert!(!files.is_empty());
        assert!(!sink.has_errors());

        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &config,
                FetcherHandle::None,
                false,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_none()
        );
        assert!(!sink.has_errors());
    }

    #[test]
    fn validators_only_can_reuse_the_disabled_types_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            r##"openapi: 3.1.1
info: {title: t, version: 1.0.0}
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Pet"}
components:
  schemas:
    Pet: {type: object, properties: {name: {type: string}}}
"##,
        )
        .expect("OpenAPI document");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": {
                "types": false,
                "validators": { "directory": "types" }
            }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("emitted files");

        assert!(!files.is_empty());
        assert!(
            files
                .iter()
                .all(|file| file.relative_path.starts_with("types/")),
            "{files:#?}"
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn zod_only_can_reuse_the_disabled_types_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            r##"openapi: 3.1.1
info: {title: t, version: 1.0.0}
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Pet"}
components:
  schemas:
    Pet: {type: object, properties: {name: {type: string}}}
"##,
        )
        .expect("OpenAPI document");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": {
                "types": false,
                "zod": { "directory": "types" }
            }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("emitted files");

        assert!(!files.is_empty());
        assert!(
            files
                .iter()
                .all(|file| file.relative_path.starts_with("types/")),
            "{files:#?}"
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn standalone_artifacts_preserve_shared_model_diagnostics_without_types() {
        for artifact in ["validators", "zod"] {
            let temp = tempfile::tempdir().expect("tempdir");
            fs::write(
                temp.path().join("openapi.yaml"),
                r##"openapi: 3.1.1
info: {title: t, version: 1.0.0}
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Pet"}
components:
  schemas:
    Cat:
      type: object
      required: [kind]
      properties:
        kind: {type: string, const: cat}
    Pet:
      oneOf:
        - {$ref: "#/components/schemas/Cat"}
        - {type: string}
      discriminator: {propertyName: kind}
"##,
            )
            .expect("OpenAPI document");
            let mut artifacts = json!({ "types": false });
            artifacts[artifact] = json!(true);
            let raw = json!({
                "schemaVersion": 1,
                "input": { "path": "openapi.yaml" },
                "output": "generated",
                "artifacts": artifacts
            });
            let config = load_single_from_json(
                &temp.path().join("oasts.json"),
                &serde_json::to_vec(&raw).expect("config JSON"),
            )
            .expect("resolved config");

            let mut sink = DiagnosticSink::new();
            let files = compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink,
            )
            .expect("emitted files");
            let diagnostics = format!("{:#?}", sink.as_slice());

            assert!(!files.is_empty(), "{artifact}");
            assert_eq!(
                sink.as_slice()
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "OASTS4202")
                    .count(),
                1,
                "{artifact}: {diagnostics}"
            );
            assert!(!sink.has_errors(), "{artifact}: {diagnostics}");
        }
    }

    #[test]
    fn compile_stops_on_load_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\ninput: { path: ./missing.yaml }\noutput: ./generated\n",
        )
        .expect("config");
        let config = load_single(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_none()
        );
        assert!(sink.has_errors());
    }

    #[test]
    fn config_pointer_diagnostics_render_the_absolute_config_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            "openapi: 3.1.1\ninfo: {title: t, version: 1.0.0}\npaths: {}\n",
        )
        .expect("OpenAPI document");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "naming": { "overrides": { "schemas": { "Missing": "Missing" } } }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_none()
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS0202")
            .expect("unmatched override diagnostic");
        let expected_source = config.config_path.to_string_lossy();
        assert_eq!(
            diagnostic.source_id.as_deref(),
            Some(expected_source.as_ref())
        );
        let rendered = crate::diag::render_to_string(sink.into_sorted_vec());
        assert!(rendered.contains(&format!(
            "  --> {}:1:1 /naming/overrides/schemas/Missing\n",
            config.config_path.display()
        )));
        assert!(!rendered.contains("<config>"));
    }

    #[test]
    fn client_enabled_petstore_emits_client_runtime_and_identical_types() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/petstore-3.0");
        fs::copy(
            source.join("openapi.yaml"),
            temp.path().join("openapi.yaml"),
        )
        .expect("copy fixture");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": { "authEnforcement": "types" },
            "validation": { "engine": "off", "unchecked": "allow" }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("emitted files");

        assert_eq!(
            files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "client/operations/createpets.ts",
                "client/operations/listpets.ts",
                "client/operations/showpetbyid.ts",
                "runtime/result.ts",
                "runtime/serialize.ts",
                "runtime/standard-schema.ts",
                "runtime/transport.ts",
                "types/components/error.ts",
                "types/components/pet.ts",
                "types/components/pets.ts",
                "types/headers.ts",
                "types/operations/createpets.ts",
                "types/operations/listpets.ts",
                "types/operations/showpetbyid.ts",
            ])
        );
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "client/api.ts")
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());

        let types_only = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated-types"
        });
        let types_only = load_single_from_json(
            &temp.path().join("oasts-types.json"),
            &serde_json::to_vec(&types_only).expect("types config JSON"),
        )
        .expect("types resolved config");
        let mut types_sink = DiagnosticSink::new();
        let types_files = compile(
            &types_only,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut types_sink,
        )
        .expect("types-only emitted files");
        let client_types = files
            .iter()
            .filter(|file| file.relative_path.starts_with("types/"))
            .map(|file| (file.relative_path.as_str(), file.content.as_str()))
            .collect::<BTreeMap<_, _>>();
        let types_only = types_files
            .iter()
            .map(|file| (file.relative_path.as_str(), file.content.as_str()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(client_types, types_only);
        assert!(!types_sink.has_errors(), "{:#?}", types_sink.as_slice());
    }

    #[test]
    fn forbidden_fetch_header_stays_in_types_and_is_dropped_only_from_the_client() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            r#"openapi: 3.0.4
info: {title: t, version: 1.0.0}
paths:
  /things:
    get:
      operationId: listThings
      parameters:
        - {name: Cookie, in: header, required: true, schema: {type: string}}
        - {name: X-Trace, in: header, required: true, schema: {type: string}}
      responses: {'200': {description: ok}}
"#,
        )
        .expect("OpenAPI document");
        let config = |name: &str, client: bool| {
            let mut raw = json!({
                "schemaVersion": 1,
                "input": { "path": "openapi.yaml" },
                "output": format!("generated-{name}")
            });
            if client {
                raw["artifacts"] = json!({ "types": true, "client": true });
                raw["client"] = json!({ "authEnforcement": "types" });
                raw["validation"] = json!({ "engine": "off", "unchecked": "allow" });
            }
            load_single_from_json(
                &temp.path().join(format!("oasts-{name}.json")),
                &serde_json::to_vec(&raw).expect("config JSON"),
            )
            .expect("resolved config")
        };

        let mut types_sink = DiagnosticSink::new();
        let types = compile(
            &config("types", false),
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut types_sink,
        )
        .expect("types-only build emits");
        let request_types = types
            .iter()
            .find(|file| file.relative_path == "types/operations/listthings.ts")
            .expect("operation types");
        assert!(request_types.content.contains("Cookie: string;"));
        assert!(request_types.content.contains("\"X-Trace\": string;"));
        assert!(types_sink.as_slice().is_empty());

        let mut client_sink = DiagnosticSink::new();
        let client = compile(
            &config("client", true),
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut client_sink,
        )
        .expect("client build emits");
        let request_types = client
            .iter()
            .find(|file| file.relative_path == "types/operations/listthings.ts")
            .expect("client build operation types");
        assert!(request_types.content.contains("Cookie: string;"));
        let operation = client
            .iter()
            .find(|file| file.relative_path == "client/operations/listthings.ts")
            .expect("client operation");
        assert!(!operation.content.contains("\"Cookie\""));
        assert!(operation.content.contains("\"X-Trace\""));
        let diagnostics = client_sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS5001")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].severity, crate::diag::Severity::Warning);
    }

    #[test]
    fn client_enabled_tictactoe_plans_operation_auth() {
        use crate::client_model::{AuthKind, AuthSchemeUse};

        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tictactoe-3.1");
        fs::copy(
            source.join("openapi.yaml"),
            temp.path().join("openapi.yaml"),
        )
        .expect("copy fixture");
        let raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": { "authEnforcement": "types" },
            "validation": { "engine": "off", "unchecked": "allow" }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        // The auth seam is gone: the same compile now succeeds with no diagnostics.
        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_some()
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());

        // Re-run the stages to inspect the planned auth for get-board, whose security is
        // `[{ defaultApiKey: [] }, { app2AppOauth: [board:read] }]` in the fixture.
        let mut sink = DiagnosticSink::new();
        let graph = crate::loader::load_graph(&config, &mut InputRecorder::off(), &mut sink)
            .expect("graph");
        let ir = parse(&graph, &mut sink).expect("IR");
        let analyzed = analyze(ir, &config, &mut sink);
        let model = build_client_model(&analyzed, &config, &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());

        let index = analyzed
            .ir
            .operations
            .iter()
            .position(|operation| operation.operation_id.as_deref() == Some("get-board"))
            .expect("get-board operation");
        let board = model
            .operations
            .iter()
            .find(|plan| plan.operation_index == index)
            .expect("get-board plan");
        assert_eq!(
            board.auth_plan,
            vec![
                vec![AuthSchemeUse {
                    name: "defaultApiKey".to_owned(),
                    kind: AuthKind::ApiKeyHeader {
                        name: "api-key".to_owned(),
                    },
                    scopes: Vec::new(),
                }],
                vec![AuthSchemeUse {
                    name: "app2AppOauth".to_owned(),
                    kind: AuthKind::OAuth2,
                    scopes: vec!["board:read".to_owned()],
                }],
            ]
        );
    }

    fn compile_multifile(
        files: &[(&str, &str)],
        should_emit: bool,
    ) -> (DiagnosticSink, Option<Vec<GeneratedFile>>) {
        compile_multifile_with_naming(files, None, should_emit)
    }

    fn compile_multifile_with_filters(
        files: &[(&str, &str)],
        filters: Value,
        should_emit: bool,
    ) -> (DiagnosticSink, Option<Vec<GeneratedFile>>) {
        compile_multifile_with_overrides(files, None, Some(filters), should_emit)
    }

    fn compile_multifile_with_naming(
        files: &[(&str, &str)],
        naming: Option<Value>,
        should_emit: bool,
    ) -> (DiagnosticSink, Option<Vec<GeneratedFile>>) {
        compile_multifile_with_overrides(files, naming, None, should_emit)
    }

    fn compile_multifile_with_overrides(
        files: &[(&str, &str)],
        naming: Option<Value>,
        filters: Option<Value>,
        should_emit: bool,
    ) -> (DiagnosticSink, Option<Vec<GeneratedFile>>) {
        let temp = tempfile::tempdir().expect("tempdir");
        for (relative, contents) in files {
            let path = temp.path().join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&path, contents).expect("write spec file");
        }
        let mut raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated"
        });
        if let Some(naming) = naming {
            raw["naming"] = naming;
        }
        if let Some(filters) = filters {
            raw["filters"] = filters;
        }
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            should_emit,
            &mut InputRecorder::off(),
            &mut sink,
        );
        (sink, files)
    }

    const CROSS_FILE_OPENAPI: &str = r##"openapi: "3.1.0"
info: { title: cross, version: "1" }
paths:
  /cross:
    get:
      operationId: get-cross
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/part-a.yaml#/CrossFileRoot"
"##;

    const CROSS_FILE_PART_A: &str = r##"CrossFileRoot:
  type: object
  properties:
    toB:
      $ref: "./part-b.yaml#/FromB"
    cycleStart:
      $ref: "#/CrossFileA"
CrossFileA:
  type: object
  properties:
    label: { type: string }
    toB:
      $ref: "./part-b.yaml#/CrossFileB"
"##;

    const CROSS_FILE_PART_B: &str = r##"FromB:
  type: object
  properties:
    note: { type: string }
    backToA:
      $ref: "./part-a.yaml#/CrossFileA"
CrossFileB:
  type: object
  properties:
    count: { type: integer }
    backToA:
      $ref: "./part-a.yaml#/CrossFileA"
"##;

    #[test]
    fn external_file_schemas_allocate_component_types_across_a_cycle() {
        let (sink, files) = compile_multifile(
            &[
                ("openapi.yaml", CROSS_FILE_OPENAPI),
                ("schemas/part-a.yaml", CROSS_FILE_PART_A),
                ("schemas/part-b.yaml", CROSS_FILE_PART_B),
            ],
            true,
        );
        let files = files.expect("expected emitted files");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // Both-direction and self-referential external schemas each get a type file.
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "types/components/crossfileroot.ts",
            "types/components/crossfilea.ts",
            "types/components/fromb.ts",
            "types/components/crossfileb.ts",
        ] {
            assert!(paths.contains(expected), "missing {expected}: {paths:#?}");
        }
    }

    #[test]
    fn external_schema_name_collides_with_root_component_exactly() {
        // An external schema and a root component both named `Shared` produce the
        // byte-identical identifier `Shared`. A genuine exact collision stays fatal:
        // refusing to guess which shape wins is the whole point of the check.
        // The operation references both, because an unreferenced component is pruned
        // before name allocation and a pruned schema cannot collide.
        let openapi = r##"openapi: "3.1.0"
info: { title: collide, version: "1" }
paths:
  /collide:
    get:
      operationId: get-collide
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/Shared"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/part.yaml#/Shared"
components:
  schemas:
    Shared:
      type: string
"##;
        let part = "Shared:\n  type: object\n  properties:\n    value: { type: string }\n";
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(files.is_none(), "collision must be fatal");
        let collided = sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == "OASTS3002" && diagnostic.message.contains("collision")
        });
        assert!(collided, "expected exact identifier collision diagnostic");
    }

    #[test]
    fn external_schema_name_differing_only_by_case_allocates_both() {
        // `custom-hostname` -> `CustomHostname` and `customhostname` -> `Customhostname`
        // differ only by the case of one letter, so they are two distinct TypeScript types.
        // The external name and the root component no longer collide, and both files emit
        // (their kebab file bases `custom-hostname` / `customhostname` also differ).
        let openapi = r##"openapi: "3.1.0"
info: { title: casefold, version: "1" }
paths:
  /hostname:
    get:
      operationId: get-hostname
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/custom-hostname"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/part.yaml#/customhostname"
components:
  schemas:
    custom-hostname:
      type: object
      properties:
        value: { type: string }
"##;
        let part = "customhostname:\n  type: object\n  properties:\n    value: { type: string }\n";
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let files = files.expect("emission succeeds");
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "types/components/custom-hostname.ts",
            "types/components/customhostname.ts",
        ] {
            assert!(paths.contains(expected), "missing {expected}: {paths:#?}");
        }
    }

    #[test]
    fn case_fold_only_names_sharing_a_generated_path_collide() {
        // `custom-hostname` -> `CustomHostname` and `custom-hostName` -> `CustomHostName`
        // are distinct identifiers, so the identifier layer allocates both (no OASTS3002).
        // Their kebab file bases both fold to `custom-hostname.ts`, so filesystem safety is
        // still enforced — at the path layer, via OASTS4002.
        let openapi = r##"openapi: "3.1.0"
info: { title: pathcollide, version: "1" }
paths:
  /a:
    get:
      operationId: get-a
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/custom-hostname"
  /b:
    get:
      operationId: get-b
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/custom-hostName"
components:
  schemas:
    custom-hostname:
      type: object
      properties:
        value: { type: string }
    custom-hostName:
      type: object
      properties:
        value: { type: string }
"##;
        let (sink, files) = compile_multifile(&[("openapi.yaml", openapi)], true);
        assert!(files.is_none(), "path collision must be fatal");
        let has_code = |code: &str| sink.as_slice().iter().any(|d| d.code == code);
        assert!(!has_code("OASTS3002"), "case-only diff must not be fatal");
        assert!(has_code("OASTS4002"), "path layer must still collide");
    }

    #[test]
    fn pasted_collision_suggestions_generate_without_a_path_collision() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.yaml"),
            r##"openapi: 3.1.0
info: { title: collision, version: "1" }
paths:
  /lower:
    get:
      operationId: get-lower
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: { $ref: "#/components/schemas/createdAt" }
  /upper:
    get:
      operationId: get-upper
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: { $ref: "#/components/schemas/CreatedAt" }
components:
  schemas:
    createdAt: { type: string }
    CreatedAt: { type: string }
webhooks:
  petCreated:
    get:
      responses:
        "200": { description: ok }
  pet-created:
    get:
      responses:
        "200": { description: ok }
"##,
        )
        .expect("OpenAPI");
        let base = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated"
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&base).expect("config JSON"),
        )
        .expect("config");
        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &config,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_none()
        );
        let rendered = crate::diag::render_to_string(sink.into_sorted_vec());
        assert!(rendered.contains("      'CreatedAt': 'CreatedAt_1'\n"));
        assert!(rendered.contains("      'createdAt': 'CreatedAt_2'\n"));
        assert!(rendered.contains("      'pet-created': 'PetCreated_1'\n"));
        assert!(rendered.contains("      'petCreated': 'PetCreated_2'\n"));

        let resolved = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "naming": {
                "overrides": {
                    "schemas": {
                        "CreatedAt": "CreatedAt_1",
                        "createdAt": "CreatedAt_2"
                    },
                    "webhooks": {
                        "pet-created": "PetCreated_1",
                        "petCreated": "PetCreated_2"
                    },
                    "operations": {
                        "get-lower": "fetchLower"
                    }
                }
            }
        });
        let config = load_single_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&resolved).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("suggestions resolve the collision");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("types/components/createdat-1.ts"));
        assert!(paths.contains("types/components/createdat-2.ts"));
        assert!(paths.contains("types/operations/fetchlower.ts"));
        assert!(paths.contains("types/webhooks/petcreated-1get.ts"));
        assert!(paths.contains("types/webhooks/petcreated-2get.ts"));
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn external_ref_inside_additional_properties_is_materialized() {
        let openapi = r##"openapi: "3.1.0"
info:
  title: additional
  version: "1"
paths:
  /bag:
    get:
      operationId: get-bag
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/part.yaml#/Bag"
"##;
        let part = r##"Bag:
  type: object
  additionalProperties:
    $ref: "#/Item"
Item:
  type: string
"##;
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(!sink.has_errors(), "diagnostics: {:?}", sink.as_slice());
        let names: Vec<&str> = files
            .as_deref()
            .expect("emission succeeds")
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert!(names.iter().any(|path| path.contains("item")), "{names:?}");
    }

    #[test]
    fn external_ref_in_a_request_encoding_header_schema_is_materialized() {
        let openapi = r##"openapi: "3.1.0"
info:
  title: encoding
  version: "1"
paths:
  /upload:
    post:
      operationId: post-upload
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file: { type: string }
            encoding:
              file:
                headers:
                  X-Meta:
                    schema:
                      $ref: "./schemas/part.yaml#/HeaderMeta"
      responses:
        "200":
          description: ok
"##;
        let part = "HeaderMeta:\n  type: object\n  properties:\n    trace: { type: string }\n";
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(!sink.has_errors(), "diagnostics: {:?}", sink.as_slice());
        let names: Vec<&str> = files
            .as_deref()
            .expect("emission succeeds")
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert!(
            names.contains(&"types/components/headermeta.ts"),
            "encoding header schema must materialize a type file: {names:?}"
        );
    }

    #[test]
    fn all_of_self_reference_terminates_and_renders_the_named_type() {
        // A component whose property `allOf`s a `$ref` back to itself must render the bare
        // named type rather than inlining forever. Reaching this test's assertions at all
        // proves no stack overflow. A `$ref` branch no longer enters the merge, so there is
        // no inlining to cut off and the walk-side cycle guard it used to need is gone.
        let openapi = r##"openapi: "3.1.0"
info:
  title: loop
  version: "1"
paths:
  /loop:
    get:
      operationId: get-loop
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Loop"
components:
  schemas:
    Loop:
      type: object
      properties:
        child:
          allOf:
            - $ref: "#/components/schemas/Loop"
"##;
        let (sink, files) = compile_multifile(&[("openapi.yaml", openapi)], true);
        assert!(!sink.has_errors(), "diagnostics: {:?}", sink.as_slice());
        let files = files.expect("emission succeeds");
        let loop_file = files
            .iter()
            .find(|file| file.relative_path == "types/components/loop.ts")
            .expect("Loop component type file");
        // The declaration names the type once; the recursive child branch references it again.
        assert!(loop_file.content.contains("child"), "{}", loop_file.content);
        assert!(
            loop_file.content.matches("Loop").count() >= 2,
            "recursive branch should render as the named type Loop: {}",
            loop_file.content
        );
    }

    #[test]
    fn multifile_materialization_walks_every_schema_shape() {
        // Single-document specs skip materialization entirely, so the reference-collection walk is
        // exercised only through multi-file specs. This one carries every schema shape the walk
        // branches on — array, tuple, allOf/anyOf/oneOf, a closed object, an operation parameter,
        // and entry-internal refs (which the worklist skips) — plus one external ref that makes the
        // graph multi-document so materialization actually runs.
        let openapi = r##"openapi: "3.1.0"
info:
  title: shapes
  version: "1"
paths:
  /shapes:
    get:
      operationId: get-shapes
      parameters:
        - name: kind
          in: query
          schema: { type: string }
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Root"
components:
  schemas:
    Root:
      type: object
      additionalProperties: false
      properties:
        arr: { $ref: "#/components/schemas/WithArray" }
        tup: { $ref: "#/components/schemas/WithTuple" }
        all: { $ref: "#/components/schemas/WithAllOf" }
        any: { $ref: "#/components/schemas/WithAnyOf" }
        one: { $ref: "#/components/schemas/WithOneOf" }
        ext: { $ref: "./schemas/part.yaml#/External" }
    WithArray:
      type: array
      items: { $ref: "#/components/schemas/Leaf" }
    WithTuple:
      type: array
      prefixItems:
        - { type: string }
      items: { type: number }
    WithAllOf:
      allOf:
        - $ref: "#/components/schemas/Leaf"
    WithAnyOf:
      anyOf:
        - { type: string }
        - { type: number }
    WithOneOf:
      oneOf:
        - { type: string }
        - { type: integer }
    Leaf:
      type: string
"##;
        let part = "External:\n  type: object\n  properties:\n    name: { type: string }\n";
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(!sink.has_errors(), "diagnostics: {:?}", sink.as_slice());
        let names: Vec<&str> = files
            .as_deref()
            .expect("emission succeeds")
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect();
        assert!(
            names.contains(&"types/components/external.ts"),
            "external schema must materialize: {names:?}"
        );
    }

    #[test]
    fn external_ref_to_missing_pointer_is_a_reference_diagnostic() {
        let openapi = r##"openapi: "3.1.0"
info:
  title: dangling
  version: "1"
paths:
  /gone:
    get:
      operationId: get-gone
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/part.yaml#/Missing"
"##;
        let part = "Present:\n  type: string\n";
        let (sink, files) = compile_multifile(
            &[("openapi.yaml", openapi), ("schemas/part.yaml", part)],
            true,
        );
        assert!(sink.has_errors(), "dangling external ref must not emit");
        assert!(files.is_none(), "no files for a dangling external ref");
    }

    #[test]
    fn fragmentless_external_schema_document_is_materialized_in_both_oas_versions() {
        for version in ["3.0.4", "3.1.1"] {
            let openapi = format!(
                r##"openapi: "{version}"
info:
  title: nofrag
  version: "1"
paths:
  /x:
    get:
      operationId: get-x
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/Pet.yaml"
"##
            );
            let pet = r##"type: object
required: [id]
properties:
  id: { type: string }
"##;
            let (sink, files) = compile_multifile(
                &[("openapi.yaml", &openapi), ("schemas/Pet.yaml", pet)],
                true,
            );
            assert!(!sink.has_errors(), "{version}: {:#?}", sink.as_slice());
            let files = files.expect("fragmentless schema reference emits");
            let pet = files
                .iter()
                .find(|file| file.relative_path == "types/components/pet.ts")
                .expect("Pet component");
            assert!(pet.content.contains("export interface Pet"));
            assert!(pet.content.contains("id: string"));
        }
    }

    #[test]
    fn fragmentless_document_roots_with_the_same_stem_collide() {
        let openapi = r##"openapi: "3.1.0"
info: { title: collide, version: "1" }
paths:
  /a:
    get:
      operationId: get-a
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./a/Pet.yaml"
  /b:
    get:
      operationId: get-b
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./b/Pet.yaml"
"##;
        let (sink, files) = compile_multifile(
            &[
                ("openapi.yaml", openapi),
                ("a/Pet.yaml", "type: string\n"),
                ("b/Pet.yaml", "type: integer\n"),
            ],
            true,
        );
        assert!(files.is_none(), "same-stem roots must not emit");
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == "OASTS3002"
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'Pet'")
        }));
    }

    #[test]
    fn fragmentless_document_stems_normalize_and_can_be_overridden() {
        let openapi = r##"openapi: "3.1.0"
info: { title: names, version: "1" }
paths:
  /value:
    get:
      operationId: get-value
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./schemas/my-schema.v2.yaml"
"##;
        let (sink, files) = compile_multifile(
            &[
                ("openapi.yaml", openapi),
                ("schemas/my-schema.v2.yaml", "type: string\n"),
            ],
            true,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let files = files.expect("normalized stem emits");
        assert!(files.iter().any(|file| {
            file.relative_path == "types/components/my-schema-v2.ts"
                && file.content.contains("export type MySchemaV2")
        }));

        let numeric_openapi = openapi.replace("my-schema.v2.yaml", "123.yaml");
        let numeric_files = [
            ("openapi.yaml", numeric_openapi.as_str()),
            ("schemas/123.yaml", "type: string\n"),
        ];
        let (sink, files) = compile_multifile(&numeric_files, true);
        assert!(files.is_none(), "a leading-digit stem must not emit");
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == "OASTS3002"
                && diagnostic
                    .message
                    .contains("invalid schema identifier '123'")
        }));

        let naming = json!({
            "overrides": {
                "schemas": {
                    "123": "Pet123"
                }
            }
        });
        let (sink, files) = compile_multifile_with_naming(&numeric_files, Some(naming), true);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // The file name follows the override, not the raw stem: an override exists to resolve a
        // name collision, and deriving the path from the name it replaced would just move the
        // collision to the file layer.
        assert!(files.expect("override emits").iter().any(|file| {
            file.relative_path == "types/components/pet123.ts"
                && file.content.contains("export type Pet123")
        }));
    }

    #[test]
    fn fragmentless_schema_self_reference_to_the_entry_document_terminates() {
        let openapi = r##"openapi: "3.1.0"
info: { title: self, version: "1" }
paths:
  /self:
    get:
      operationId: get-self
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "./openapi.yaml"
"##;
        let (sink, files) = compile_multifile(&[("openapi.yaml", openapi)], true);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(files.expect("self-reference emits").iter().any(|file| {
            file.relative_path == "types/components/openapi.ts"
                && file.content.contains("export type Openapi")
        }));
    }

    #[test]
    fn fragmentless_non_schema_references_use_the_object_resolution_path() {
        let openapi = r##"openapi: "3.1.0"
info: { title: objects, version: "1" }
paths:
  /pets:
    $ref: "./paths/Pets.yaml"
  /limited:
    get:
      operationId: get-limited
      parameters:
        - $ref: "#/components/parameters/Limit"
      responses:
        "200":
          $ref: "#/components/responses/Ok"
components:
  parameters:
    Limit:
      $ref: "./parameters/Limit.yaml"
  responses:
    Ok:
      $ref: "./responses/Ok.yaml"
"##;
        let path_item = r##"get:
  operationId: list-pets
  responses:
    "200":
      $ref: "../responses/Ok.yaml"
"##;
        let parameter = r##"name: limit
in: query
schema: { type: integer }
"##;
        let response = r##"description: ok
content:
  application/json:
    schema: { type: string }
"##;
        let (sink, files) = compile_multifile(
            &[
                ("openapi.yaml", openapi),
                ("paths/Pets.yaml", path_item),
                ("parameters/Limit.yaml", parameter),
                ("responses/Ok.yaml", response),
            ],
            true,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = files
            .expect("non-schema references emit")
            .into_iter()
            .map(|file| file.relative_path)
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("types/operations/list-pets.ts"));
        assert!(paths.contains("types/operations/get-limited.ts"));
    }

    #[test]
    fn client_showcase_fixture_compiles_with_aggregate() {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/client-showcase-3.1");
        let config = load_single(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved showcase config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("showcase emitted files");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(
            files
                .iter()
                .any(|file| file.relative_path == "client/api.ts")
        );
    }

    #[test]
    fn client_and_msw_reject_the_same_structural_xml_response() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/msw-response-media-parity-3.1");
        let diagnostics = |config_name: &str| {
            let config = load_single(Some(&fixture.join(config_name)), &fixture)
                .expect("resolved response media config");
            let mut sink = DiagnosticSink::new();
            assert!(
                compile(
                    &config,
                    FetcherHandle::None,
                    false,
                    &mut InputRecorder::off(),
                    &mut sink
                )
                .is_none()
            );
            sink.into_sorted_vec()
                .into_iter()
                .map(|diagnostic| {
                    (
                        diagnostic.code,
                        diagnostic.message,
                        diagnostic.json_pointer,
                        diagnostic.severity,
                    )
                })
                .collect::<Vec<_>>()
        };

        let client = diagnostics("oasts-client.yaml");
        let msw = diagnostics("oasts-msw.yaml");
        assert_eq!(client, msw);
        assert_eq!(client.len(), 1);
        assert_eq!(client[0].0, "OASTS5201");
        assert_eq!(
            client[0].1,
            "response media 'text/xml' is XML, which Oasts does not support"
        );
    }

    #[test]
    fn uninhabitable_allof_fixture_emits_every_artifact() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/uninhabitable-allof-3.0");
        let config = load_single(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("warnings do not block emission");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == crate::composition::CODE_COMPOSITION
                && diagnostic.severity == crate::diag::Severity::Warning
                && diagnostic.message.contains("closed object")
        }));
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| diagnostic.code == crate::composition::CODE_COMPOSITION)
        );
        let content = |path: &str| {
            files
                .iter()
                .find(|file| file.relative_path == path)
                .map(|file| file.content.as_str())
                .expect("fixture artifact")
        };
        assert!(content("types/components/dog.ts").contains("export type Dog = never;"));
        assert!(content("types/components/choice.ts").contains("export type Choice = Dog | Cat;"));
        assert!(content("types/operations/exchangenever.ts").contains("body: never;\n"));
        assert!(
            content("types/operations/exchangenever.ts")
                .contains("export type ExchangeNeverResponse200 = never;")
        );
        let client = content("client/operations/exchangenever.ts");
        assert!(client.contains("body: ExchangeNeverRequest[\"body\"];"));
        assert!(client.contains("validateExchangeNeverRequestBody(input.body"));
        assert!(client.contains("validateExchangeNeverResponse200(result.data"));
        assert!(
            content("validators/components/dog.ts")
                .contains("issues.push(issue(path, \"value not allowed\"));")
        );
    }

    fn filters_showcase(config: &str) -> (DiagnosticSink, Option<Vec<crate::emit::GeneratedFile>>) {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/filters-showcase-3.1");
        let config = load_single(Some(&fixture.join(config)), &fixture)
            .expect("resolved showcase fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        );
        (sink, files)
    }

    fn emitted_paths(files: &[crate::emit::GeneratedFile]) -> BTreeSet<&str> {
        files
            .iter()
            .map(|file| file.relative_path.as_str())
            .collect()
    }

    const LINKED_OPENAPI: &str = r##"openapi: "3.1.0"
info: { title: linked, version: "1" }
paths:
  /source:
    get:
      operationId: source
      tags: [keep]
      responses:
        "200":
          description: ok
          links:
            byId:
              operationId: target
            byRef:
              operationRef: "#/paths/~1target/get"
  /target:
    get:
      operationId: target
      tags: [drop]
      responses:
        "204": { description: ok }
"##;

    #[test]
    fn a_link_whose_target_the_filter_removed_is_dropped_rather_than_reported() {
        // The document is correct; the config removed the target. Blaming the document for that
        // would make selecting one tag a build failure pointing at a line the user cannot fix.
        let (sink, files) = compile_multifile_with_filters(
            &[("openapi.yaml", LINKED_OPENAPI)],
            json!({ "tags": { "include": ["keep"] } }),
            true,
        );

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let files = files.expect("filtering a link target still generates");
        let paths = emitted_paths(&files);
        assert!(paths.contains("types/operations/source.ts"), "{paths:#?}");
        assert!(!paths.contains("types/operations/target.ts"), "{paths:#?}");
    }

    #[test]
    fn a_link_target_missing_from_the_document_is_still_reported() {
        let (sink, files) = compile_multifile(
            &[(
                "openapi.yaml",
                r##"openapi: "3.1.0"
info: { title: linked, version: "1" }
paths:
  /source:
    get:
      operationId: source
      responses:
        "200":
          description: ok
          links:
            byId:
              operationId: nosuchtarget
"##,
            )],
            true,
        );

        assert!(files.is_none());
        let codes: Vec<&str> = sink.as_slice().iter().map(|d| d.code).collect();
        assert!(codes.contains(&"OASTS3201"), "{codes:?}");
    }

    #[test]
    fn a_parse_error_keeps_its_exit_code_when_filters_are_configured() {
        // The operation is rejected by the parser, so a pattern naming it matches nothing. That
        // is the document's defect, not the config's, and a config diagnostic here would raise
        // the run's exit code from 1 to 2 and point at the wrong file.
        let (sink, files) = compile_multifile_with_filters(
            &[(
                "openapi.yaml",
                r##"openapi: "3.1.0"
info: { title: broken, version: "1" }
paths:
  /bad:
    get:
      $ref: "#/paths/~1target"
      operationId: broken
      responses: { '204': { description: ok } }
  /target:
    post:
      operationId: target
      responses: { '204': { description: ok } }
"##,
            )],
            json!({ "operations": { "include": ["broken"] } }),
            true,
        );

        assert!(files.is_none());
        let codes: Vec<&str> = sink.as_slice().iter().map(|d| d.code).collect();
        assert!(codes.contains(&"OASTS2104"), "{codes:?}");
        assert!(
            !codes.contains(&"OASTS0262"),
            "the config is not at fault: {codes:?}"
        );
        assert_eq!(sink.worst_exit_code(), 1);
    }

    #[test]
    fn filters_showcase_unfiltered_collides_and_emits_nothing() {
        // `PetSummary` and `petSummary` allocate the same identifier. Both are reachable with no
        // filters, so the document cannot generate.
        let (sink, files) = filters_showcase("oasts-unfiltered.yaml");

        assert!(files.is_none(), "an exact collision must suppress output");
        let diagnostics = sink.as_slice();
        let collided = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "OASTS3002");
        assert!(collided, "{diagnostics:#?}");
    }

    #[test]
    fn a_filter_rescues_the_name_collision() {
        // Excluding `/admin/` drops the only operation reaching `petSummary`; pruning then drops
        // the schema, and the collision goes with it. This is a consequence of filtering running
        // on the IR before name allocation, and nothing else pins it.
        let (sink, files) = filters_showcase("oasts.yaml");
        let files = files.expect("filtering resolves the collision");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = emitted_paths(&files);
        assert!(paths.contains("types/components/petsummary.ts"));
        assert!(
            !paths.contains("types/operations/adminlistpets.ts"),
            "the excluded operation is gone: {paths:#?}"
        );
        assert!(
            !paths.contains("types/components/orphan.ts"),
            "the unreachable component is pruned: {paths:#?}"
        );
        assert!(
            paths.contains("types/components/webhookonly.ts")
                && paths.contains("types/components/callbackonly.ts"),
            "webhooks and callbacks are reachability roots: {paths:#?}"
        );
    }

    #[test]
    fn keeping_orphans_emits_the_unreachable_component() {
        let (sink, files) = filters_showcase("oasts-orphans-kept.yaml");
        let files = files.expect("orphans kept");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = emitted_paths(&files);
        assert!(paths.contains("types/components/orphan.ts"));
        assert!(
            paths.contains("types/components/petsummarylegacy.ts"),
            "keeping orphans keeps the filtered-out schema too, renamed by an override: {paths:#?}"
        );
    }

    #[test]
    fn dropping_deprecated_operations_removes_only_that_operation() {
        let (sink, files) = filters_showcase("oasts-deprecated.yaml");
        let files = files.expect("deprecated dropped");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = emitted_paths(&files);
        assert!(
            !paths.contains("types/operations/deletepet.ts"),
            "{paths:#?}"
        );
        assert!(paths.contains("types/operations/listpets.ts"));
    }

    #[test]
    fn a_tag_filter_removes_the_webhook_it_empties() {
        let (sink, files) = filters_showcase("oasts-tags.yaml");
        let files = files.expect("tag filtering");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = emitted_paths(&files);
        assert!(
            !paths.iter().any(|path| path.starts_with("types/webhooks/")),
            "the webhook's only operation is tagged `events`: {paths:#?}"
        );
        assert!(
            !paths.contains("types/components/webhookonly.ts"),
            "the component only that webhook reached is pruned with it: {paths:#?}"
        );
    }

    fn filters_rejection(config: &str) -> Vec<crate::diag::Diagnostic> {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/filters-rejection-3.1");
        match load_single(Some(&fixture.join(config)), &fixture) {
            // A malformed pattern fails before any document is loaded.
            Err(diagnostics) => diagnostics,
            Ok(resolved) => {
                let mut sink = DiagnosticSink::new();
                assert!(
                    compile(
                        &resolved,
                        FetcherHandle::None,
                        true,
                        &mut InputRecorder::off(),
                        &mut sink
                    )
                    .is_none()
                );
                sink.as_slice().to_vec()
            }
        }
    }

    #[test]
    fn filter_rejection_fixtures_report_their_code_and_exit_two() {
        for (config, code) in [
            ("oasts-bad-pattern.yaml", "OASTS0261"),
            ("oasts-unmatched.yaml", "OASTS0262"),
            ("oasts-empty.yaml", "OASTS0263"),
        ] {
            let diagnostics = filters_rejection(config);
            let reported = diagnostics.iter().any(|diagnostic| diagnostic.code == code);
            assert!(reported, "{config} should report {code}: {diagnostics:#?}");
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .expect("just asserted present");
            assert_eq!(diagnostic.category, crate::diag::Category::Config);
            assert_eq!(diagnostic.category.exit_code(), 2);
            assert!(diagnostic.json_pointer.is_some(), "{diagnostic:#?}");
        }
    }

    #[test]
    fn dialect_sibling_fixture_keeps_types_and_still_refuses_validators() {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/dialect-siblings-3.0");

        // The types artifact drops only the unrepresentable conjunct, so it warns and generates.
        let types = load_single(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved dialect-siblings types config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &types,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        )
        .expect("types artifact generates");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = emitted_paths(&files);
        assert!(paths.contains("types/components/apikey.ts"), "{paths:#?}");
        // `widened` carries a `type` array beside a `const`. Both are named, and the array — the
        // one that actually widened the node — is not left out because the other was found first.
        let mut warned = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| {
                diagnostic.json_pointer.as_deref().is_some_and(|pointer| {
                    pointer.starts_with("/components/schemas/ApiKey/properties/widened/")
                })
            })
            .map(|diagnostic| {
                (
                    diagnostic.code,
                    diagnostic.json_pointer.as_deref().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        warned.sort_unstable();
        assert_eq!(
            warned,
            vec![
                (
                    "OASTS2201",
                    "/components/schemas/ApiKey/properties/widened/const"
                ),
                (
                    "OASTS2201",
                    "/components/schemas/ApiKey/properties/widened/type"
                ),
            ]
        );

        // The validators artifact refuses each dropped keyword by name at the node that carried
        // it, so a preserved node never ships a check that ignores the constraint it dropped.
        let validators = load_single(Some(&fixture.join("oasts-validators.yaml")), &fixture)
            .expect("resolved dialect-siblings validators config");
        let mut sink = DiagnosticSink::new();
        assert!(
            compile(
                &validators,
                FetcherHandle::None,
                true,
                &mut InputRecorder::off(),
                &mut sink
            )
            .is_none()
        );
        assert_eq!(sink.worst_exit_code(), 1);
        let mut refused = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.severity == crate::diag::Severity::Error)
            .map(|diagnostic| {
                (
                    diagnostic.code,
                    diagnostic.message.as_str(),
                    diagnostic.json_pointer.as_deref().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        refused.sort_unstable();
        assert_eq!(
            refused,
            vec![
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'const'",
                    "/components/schemas/ApiKey/properties/opaque"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'const'",
                    "/components/schemas/ApiKey/properties/widened"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'const'",
                    "/components/schemas/Conjoined"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'const'",
                    "/components/schemas/JitAccess/oneOf/1/properties/state"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'contains'",
                    "/components/schemas/ApiKey/properties/auditLog"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'dependentRequired'",
                    "/components/schemas/ApiKey/properties/limits"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'minContains'",
                    "/components/schemas/ApiKey/properties/auditLog"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'patternProperties'",
                    "/components/schemas/ApiKey/properties/extensions"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'prefixItems'",
                    "/components/schemas/ApiKey/properties/tags"
                ),
                (
                    "OASTS6002",
                    "validators cannot emit a check for unsupported validation keyword 'propertyNames'",
                    "/components/schemas/ApiKey/properties/jwtTemplate"
                ),
            ]
        );
    }

    #[test]
    fn operation_ref_rejection_fixture_emits_only_the_cause_and_no_files() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/operation-ref-rejection-3.0");
        let config = load_single(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved rejection fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(
            &config,
            FetcherHandle::None,
            true,
            &mut InputRecorder::off(),
            &mut sink,
        );

        assert!(files.is_none());
        assert_eq!(sink.worst_exit_code(), 1);
        let diagnostics = sink.as_slice();
        assert_eq!(diagnostics.len(), 2, "{diagnostics:#?}");
        assert!(diagnostics.iter().all(|diagnostic| {
            diagnostic.code == "OASTS2104"
                && diagnostic.message
                    == "OpenAPI defines '$ref' on a Path Item Object but not on an Operation Object; bundle the document before compiling, or place '$ref' on the whole path item when its target is a Path Item Object"
        }));
    }
}
