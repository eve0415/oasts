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
    use serde_json::{Value, json};

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
            load_config_from_json(
                &temp.path().join(format!("oasts-{name}.json")),
                &serde_json::to_vec(&raw).expect("config JSON"),
            )
            .expect("resolved config")
        };

        let mut types_sink = DiagnosticSink::new();
        let types = compile(&config("types", false), true, &mut types_sink)
            .expect("types-only build emits");
        let request_types = types
            .iter()
            .find(|file| file.relative_path == "types/operations/listthings.ts")
            .expect("operation types");
        assert!(request_types.content.contains("Cookie: string;"));
        assert!(request_types.content.contains("\"X-Trace\": string;"));
        assert!(types_sink.as_slice().is_empty());

        let mut client_sink = DiagnosticSink::new();
        let client =
            compile(&config("client", true), true, &mut client_sink).expect("client build emits");
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
            .filter(|diagnostic| diagnostic.code == "OASTS1411")
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");

        // The auth seam is gone: the same compile now succeeds with no diagnostics.
        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, true, &mut sink).is_some());
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());

        // Re-run the stages to inspect the planned auth for get-board, whose security is
        // `[{ defaultApiKey: [] }, { app2AppOauth: [board:read] }]` in the fixture.
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("graph");
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&raw).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, should_emit, &mut sink);
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
            diagnostic.code == "OASTS1202" && diagnostic.message.contains("collision")
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
        // are distinct identifiers, so the identifier layer allocates both (no OASTS1202).
        // Their kebab file bases both fold to `custom-hostname.ts`, so filesystem safety is
        // still enforced — at the path layer, via OASTS1302.
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
        assert!(!has_code("OASTS1202"), "case-only diff must not be fatal");
        assert!(has_code("OASTS1302"), "path layer must still collide");
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&base).expect("config JSON"),
        )
        .expect("config");
        let mut sink = DiagnosticSink::new();
        assert!(compile(&config, true, &mut sink).is_none());
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
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&resolved).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("suggestions resolve the collision");
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
        // A component whose property `allOf`s a `$ref` back to itself would inline forever
        // without the walk-side cycle guard; the recursive branch must render as the bare
        // named type instead. Reaching this test's assertions at all proves no stack overflow.
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
            diagnostic.code == "OASTS1202"
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
            diagnostic.code == "OASTS1202"
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

    #[test]
    fn client_and_msw_reject_the_same_structural_xml_response() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/msw-response-media-parity-3.1");
        let diagnostics = |config_name: &str| {
            let config = load_config(Some(&fixture.join(config_name)), &fixture)
                .expect("resolved response media config");
            let mut sink = DiagnosticSink::new();
            assert!(compile(&config, false, &mut sink).is_none());
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
        assert_eq!(client[0].0, "OASTS1403");
        assert_eq!(
            client[0].1,
            "response media 'text/xml' is XML, which Oasts does not support"
        );
    }

    #[test]
    fn uninhabitable_allof_fixture_emits_every_artifact() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/uninhabitable-allof-3.0");
        let config = load_config(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink).expect("warnings do not block emission");

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
        let config = load_config(Some(&fixture.join(config)), &fixture)
            .expect("resolved showcase fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink);
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
        assert!(codes.contains(&"OASTS1231"), "{codes:?}");
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
        assert!(codes.contains(&"OASTS1116"), "{codes:?}");
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
            .any(|diagnostic| diagnostic.code == "OASTS1202");
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
        match load_config(Some(&fixture.join(config)), &fixture) {
            // A malformed pattern fails before any document is loaded.
            Err(diagnostics) => diagnostics,
            Ok(resolved) => {
                let mut sink = DiagnosticSink::new();
                assert!(compile(&resolved, true, &mut sink).is_none());
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
    fn operation_ref_rejection_fixture_emits_only_the_cause_and_no_files() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/operation-ref-rejection-3.0");
        let config = load_config(Some(&fixture.join("oasts.yaml")), &fixture)
            .expect("resolved rejection fixture config");
        let mut sink = DiagnosticSink::new();
        let files = compile(&config, true, &mut sink);

        assert!(files.is_none());
        assert_eq!(sink.worst_exit_code(), 1);
        let diagnostics = sink.as_slice();
        assert_eq!(diagnostics.len(), 2, "{diagnostics:#?}");
        assert!(diagnostics.iter().all(|diagnostic| {
            diagnostic.code == "OASTS1116"
                && diagnostic.message
                    == "OpenAPI defines '$ref' on a Path Item Object but not on an Operation Object; bundle the document before compiling, or place '$ref' on the whole path item when its target is a Path Item Object"
        }));
    }
}
