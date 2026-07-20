//! Compilation pipeline shared by every CLI host.
//!
//! Orchestrates loading, parsing, semantic analysis, and emission for one
//! resolved configuration so the standalone binary and the Node binding run
//! the identical sequence.

use crate::client_model::build_client_model;
use crate::config::ResolvedConfig;
use crate::diag::DiagnosticSink;
use crate::emit::{GeneratedFile, emit_artifacts};
use crate::loader::load_graph;
use crate::parse::parse;
use crate::semantic::analyze;

/// Compiles one resolved configuration into generated files.
///
/// Returns `Some(files)` only when the pipeline reached emission and
/// `should_emit` is true; diagnostics accumulate in `sink` either way.
pub fn compile(
    config: &ResolvedConfig,
    should_emit: bool,
    sink: &mut DiagnosticSink,
) -> Option<Vec<GeneratedFile>> {
    let graph = load_graph(config, sink)?;
    let ir = parse(&graph, sink)?;
    let analyzed = analyze(ir, config, sink);
    let client_model = config
        .artifacts
        .client
        .enabled
        .then(|| build_client_model(&analyzed, config, sink));
    if sink.has_errors() {
        return None;
    }
    let source_tuples = graph.source_tuples();
    let files = emit_artifacts(
        &analyzed,
        config,
        &source_tuples,
        client_model.as_ref(),
        sink,
    );
    if sink.has_errors() {
        return None;
    }
    should_emit.then_some(files)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use serde_json::json;

    use crate::config::{load_config, load_config_from_json};

    #[test]
    fn compile_emits_files_only_when_requested() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/petstore-3.0");
        for file_name in ["openapi.yaml", "oasts.yaml"] {
            fs::copy(source.join(file_name), temp.path().join(file_name)).expect("copy fixture");
        }
        let config = load_config(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("emitted files");
        assert!(!files.is_empty());
        assert!(!sink.has_errors());

        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, false, &mut sink).is_none());
        assert!(!sink.has_errors());
    }

    #[test]
    fn compile_stops_on_load_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("oasts.yaml"),
            "schemaVersion: 1\ninput: { path: ./missing.yaml }\noutput: ./generated\n",
        )
        .expect("config");
        let config = load_config(None, temp.path()).expect("resolved config");

        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, true, &mut sink).is_none());
        assert!(sink.has_errors());
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("emitted files");

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
        let types_only = load_config_from_json(
            &temp.path().join("oasts-types.json"),
            &serde_json::to_vec(&types_only).expect("types config JSON"),
        )
        .expect("types resolved config");
        let mut types_sink = DiagnosticSink::new();
        let types_files =
            compile(&types_only, true, &mut types_sink).expect("types-only emitted files");
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
    fn client_enabled_tictactoe_fails_at_m1_auth_seam_with_operation_names() {
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, true, &mut sink).is_none());
        let auth_seams = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1430")
            .collect::<Vec<_>>();

        assert_eq!(auth_seams.len(), 3);
        for operation in ["get-board", "get-square", "put-square"] {
            assert!(
                auth_seams
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(operation)),
                "missing {operation}: {auth_seams:#?}"
            );
        }
    }

    #[test]
    fn client_showcase_fixture_compiles_with_aggregate() {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/client-showcase-3.1");
        let config = load_config(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved showcase config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("showcase emitted files");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(
            files
                .iter()
                .any(|file| file.relative_path == "client/api.ts")
        );
    }
}
