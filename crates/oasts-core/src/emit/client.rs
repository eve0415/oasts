//! Fetch client artifact emission from the client planning IR.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::client_model::{
    AuthAlternative, AuthKind, AuthSchemeUse, BaseUrlPlan, BodyPlan, ClientModel, DecoderClass,
    FieldSerializationPlan, FormFieldPlan, HelperId, MultipartResponsePayload,
    MultipartResponsePlan, MultipartResponseShape, OperationPlan, ParameterPlan, PartMediaPlan,
    PayloadDisposition, PayloadKind, ResponseMatchKind, ResponseMediaPlan, ResponsePlan,
};
use crate::config::{
    AuthEnforcement, CacheMode, CredentialsMode, DocumentationConfig, FetchDefaults, RedirectMode,
    ReferrerPolicyValue, RequestModeValue, ValidationEngine,
};
use crate::ir::{
    Operation, Param, ParamLocation, ParamStyle, PrimitiveType, SchemaNode, SecKind, SegmentPart,
    ServerVariable,
};
use crate::media::media_essence;
use crate::response_media::StreamKind;
use crate::transform::TransformKind;
use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};

use super::model::EmissionModel;
use super::paths::{TRANSFORM_SUBDIR, relative_import};
use super::runtime_assets::{RuntimeSelection, emit_runtime_files};
use super::validators::operation_parameter_validator_names;
use super::{
    ClientDocKind, Emitter as TypesEmitter, GeneratedFile, RequestBodyAccess, TypeAxis,
    TypePosition, assign_import_aliases, encode_comment_text, import_clause, import_extension,
    push_indent, render_property_key, render_ts_string, request_body_validator_positions,
    response_media_names, uppercase_first, write_client_operation_tsdoc, write_source_metadata,
};

pub(crate) fn emit_client_from_model(
    model: &mut EmissionModel<'_, '_>,
    client: &ClientModel,
) -> Vec<GeneratedFile> {
    let mut files = Vec::new();
    let mut helper_ids = BTreeSet::new();
    let mut aggregate_entries = Vec::new();

    for plan in &client.operations {
        let Some(allocated) = model
            .analyzed
            .operation_names
            .iter()
            .find(|allocated| allocated.operation_index == plan.operation_index)
            .cloned()
        else {
            continue;
        };
        let Some(file_base) = model.operation_files[plan.operation_index].clone() else {
            continue;
        };
        let operation = model.analyzed.ir.operations[plan.operation_index].clone();
        helper_ids.extend(
            plan.param_plans
                .iter()
                .map(|parameter| helper_region_id(parameter.resolved.helper).to_owned()),
        );
        // The response decoder is a helper region like any serializer, so a document that declares
        // no multipart response never carries it — and the operation modules that do declare one are
        // the only ones importing it, which is what keeps it out of an unrelated operation's bundle.
        if plan.response_table.iter().any(response_decodes_multipart) {
            helper_ids.insert(MULTIPART_RESPONSE_REGION.to_owned());
        }
        if plan_decodes_sse(plan) {
            helper_ids.insert(SSE_DECODE_REGION.to_owned());
            helper_ids.insert(RAW_STREAM_REGION.to_owned());
        } else if plan_reads_raw_stream(plan) {
            helper_ids.insert(RAW_STREAM_REGION.to_owned());
        }
        if plan.body_plan.as_ref().is_some_and(body_sends_event_stream) {
            helper_ids.insert(SSE_ENCODE_REGION.to_owned());
        }
        let relative_path = format!("{}/operations/{file_base}.ts", model.dirs.client);
        model.register_path(&relative_path, &operation.source);
        let content = emit_operation(
            model,
            &operation,
            plan,
            &allocated.name,
            &file_base,
            &relative_path,
        );
        files.push(GeneratedFile {
            relative_path,
            content,
        });
        aggregate_entries.push((allocated.name, file_base));
    }

    let source = client
        .operations
        .first()
        .map(|plan| {
            model.analyzed.ir.operations[plan.operation_index]
                .source
                .clone()
        })
        .unwrap_or_default();
    if model
        .config
        .client
        .as_ref()
        .is_some_and(|client| client.aggregate)
    {
        let namespace = model.config.namespace.clone();
        let relative_path = format!("{}/{namespace}.ts", model.dirs.client);
        model.register_path(&relative_path, &source);
        files.push(GeneratedFile {
            relative_path,
            content: emit_aggregate(model, &namespace, &aggregate_entries),
        });
    }
    if let Some(auth_file) = emit_document_auth(model, client) {
        model.register_path(&auth_file.relative_path, &source);
        files.push(auth_file);
    }
    // This emitter receives a client model only after resolved config enabled the client artifact.
    let base_url = model
        .config
        .client
        .as_ref()
        .expect("client emission requires resolved client config")
        .base_url
        .clone();
    // Every server the client model exposes, across all operations (an operation-level `servers`
    // override plans its own list rather than inheriting the root): the `serverVariables` transport
    // config type must admit whatever any of them could require at the selected index.
    let mut server_variables: Vec<(String, ServerVariable)> = Vec::new();
    // Operations that resolve to the same server list (the common case: every operation inheriting
    // the root servers) re-present identical server entries; collecting each distinct URL once folds
    // those exact repeats out while leaving the first-seen variable union unchanged.
    let mut seen_servers: HashSet<&str> = HashSet::new();
    for plan in &client.operations {
        if let BaseUrlPlan::Server { servers, .. } = &plan.base_url {
            for server in servers {
                if seen_servers.insert(server.url.as_str()) {
                    server_variables.extend(server.variables.iter().cloned());
                }
            }
        }
    }
    files.extend(emit_runtime_files(RuntimeSelection {
        model,
        helper_ids: &helper_ids,
        base_url: &base_url,
        relative_server_url: client.base_url_required,
        source: &source,
        server_variables: &server_variables,
    }));
    files.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
    files
}

fn emit_aggregate(
    model: &EmissionModel<'_, '_>,
    namespace: &str,
    entries: &[(String, String)],
) -> String {
    let extension = import_extension(model);
    let mut output = model.header();
    for (name, file_base) in entries {
        output.push_str("import { ");
        output.push_str(name);
        output.push_str(", ");
        output.push_str(name);
        output.push_str("OrThrow } from ");
        output.push_str(&render_ts_string(&format!(
            "./operations/{file_base}{extension}"
        )));
        output.push_str(";\n");
    }
    if !entries.is_empty() {
        output.push('\n');
    }
    output.push_str("export const ");
    output.push_str(namespace);
    output.push_str(" = { ");
    output.push_str(
        &entries
            .iter()
            .flat_map(|(name, _)| [name.clone(), format!("{name}OrThrow")])
            .collect::<Vec<_>>()
            .join(", "),
    );
    output.push_str(" } as const;\n");
    output
}

/// The generated per-document `client/auth.ts`: a `DocumentAuthProviders` interface with one
/// property per client-usable security scheme, in the document's scheme-declaration order. An
/// oauth2 scheme's declared scopes and scopes required by operations become a string-literal union
/// so a provider implementation typed against the property narrows `AuthContext.scopes` (empty
/// combined set → plain `AuthProvider`); every other kind stays a plain `AuthProvider`, and an http
/// scheme's `bearerFormat` is surfaced as a per-property `@remarks` — which is why this is a
/// per-property interface, not a mapped type.
///
/// Type-only surface, no runtime constructor, by two independent reasons: the module is only
/// typechecked (the conformance/e2e harness loads `runtime/transport.ts` and `client/api.ts`, never
/// this file), and a scope-narrowed `AuthProvider<Scope>` is not assignable to the plain
/// `AuthProvider` slot the shared `createTransport` exposes — so a generated delegator forwarding a
/// scope-narrowed provider map to `createTransport` cannot typecheck without an escape hatch.
/// Consumers apply this interface when authoring providers instead.
///
/// Returns `None` when the document has no client-usable scheme (nothing to type), so no empty
/// module is emitted. Client-usability reuses `build_client_model`'s planning: a scheme is usable
/// exactly when it survives into some operation's `auth_plan`, which already drops every scheme the
/// fetch client cannot serialize.
fn emit_document_auth(
    model: &EmissionModel<'_, '_>,
    client: &ClientModel,
) -> Option<GeneratedFile> {
    let mut usable: HashSet<&str> = HashSet::new();
    for plan in &client.operations {
        for alternative in &plan.auth_plan {
            for scheme in alternative {
                usable.insert(scheme.name.as_str());
            }
        }
    }
    if usable.is_empty() {
        return None;
    }

    let mut body = String::new();
    for scheme in &model.analyzed.ir.security_schemes {
        if !usable.contains(scheme.name.as_str()) {
            continue;
        }
        if let SecKind::Http {
            bearer_format: Some(format),
            ..
        } = &scheme.kind
        {
            body.push_str("  /**\n   * @remarks\n   * Bearer token format: ");
            body.push_str(&encode_comment_text(format));
            body.push_str("\n   */\n");
        }
        body.push_str("  ");
        body.push_str(&render_property_key(&scheme.name));
        body.push_str(": ");
        body.push_str(&document_auth_provider_type(
            &scheme.name,
            &scheme.kind,
            client,
        ));
        body.push_str(";\n");
    }

    let extension = import_extension(model);
    let relative_path = format!("{}/auth.ts", model.dirs.client);
    let mut output = model.header();
    output.push_str("import type { AuthProvider } from ");
    output.push_str(&render_ts_string(&relative_import(
        &relative_path,
        &[model.dirs.runtime, "transport"],
        &extension,
    )));
    output.push_str(";\n\nexport interface DocumentAuthProviders {\n");
    output.push_str(&body);
    output.push_str("}\n");
    Some(GeneratedFile {
        relative_path,
        content: output,
    })
}

/// The `AuthProvider` type for one scheme property. Oauth2 carries its declared and required scopes
/// as a first-seen string-literal union; every other kind (including openIdConnect, whose scopes
/// are IdP-defined and invisible to the document) is a plain `AuthProvider`.
fn document_auth_provider_type(name: &str, kind: &SecKind, client: &ClientModel) -> String {
    match kind {
        SecKind::OAuth2 { flows } => {
            let mut scopes = flows.declared_scopes();
            for plan in &client.operations {
                for alternative in &plan.auth_plan {
                    for scheme in alternative {
                        if scheme.name == name {
                            for scope in &scheme.scopes {
                                if !scopes.contains(&scope.as_str()) {
                                    scopes.push(scope);
                                }
                            }
                        }
                    }
                }
            }
            if scopes.is_empty() {
                "AuthProvider".to_owned()
            } else {
                let union = scopes
                    .iter()
                    .map(|scope| render_ts_string(scope))
                    .collect::<Vec<_>>()
                    .join(" | ");
                format!("AuthProvider<{union}>")
            }
        }
        _ => "AuthProvider".to_owned(),
    }
}

fn emit_operation(
    model: &mut EmissionModel<'_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    allocated_name: &str,
    file_base: &str,
    // Where this module will be written. Every import it emits is relative to it.
    self_path: &str,
) -> String {
    let stem = uppercase_first(allocated_name);
    let transforming = model.transform_facts().enabled();
    let conversions = response_conversions(model, plan, &stem);
    let response_transforms = response_transform_bindings(model, plan, &stem, &conversions);
    let request_transforms = request_transform_binding(model, plan);
    // The object the request actually dispatches, named once: the validators read it and `execute`
    // receives it, and two spellings of the same choice would disagree as an undeclared binding in
    // the emitted module rather than as a failure here.
    let dispatch_root = if request_transforms { "wire" } else { "input" };
    let mut operation_type_names = operation_type_imports(plan, &stem, &conversions);
    let uses_typed_headers = plan
        .response_table
        .iter()
        .any(|response| response.has_headers);
    // The client names `SseEvent` from the runtime rather than the types artifact: it already
    // imports the rest of the result vocabulary from there, and the runtime is emitted for every
    // client, while the types artifact's own copy exists for the case where no client is.
    // Only the branches this module renders inline actually write the word: an alias-path branch
    // names its payload through the types artifact, which imports its own copy. Importing it
    // regardless would leave an unused binding in most streaming modules, which is a hard failure
    // under a consumer's `noUnusedLocals`.
    let uses_sse_event = plan.response_table.iter().any(|response| {
        matches!(response.payload, PayloadDisposition::Payload)
            && renders_payload_inline(response)
            && response
                .media
                .iter()
                .any(|entry| entry.decoder == DecoderClass::StreamingSse)
    });
    let mut component_imports = BTreeMap::<String, BTreeSet<String>>::new();
    let documentation = model.config.documentation.clone();
    // Everything that renders a component type lives in this one borrow scope, because the scope
    // has to end before `model.header()` can reborrow the model mutably.
    let (
        input,
        input_wire,
        request_twin,
        entry_pairs,
        result_type,
        envelope_type,
        component_aliases,
        alias_diagnostics,
    ) = {
        let renderer = TypesEmitter::new(model);
        for parameter in &plan.param_plans {
            renderer.collect_operation_imports(
                &parameter.schema,
                TypePosition::Request,
                TypeAxis::Application,
                &mut component_imports,
            );
            if request_transforms && parameter_transforms(model, parameter) {
                renderer.collect_operation_imports(
                    &parameter.schema,
                    TypePosition::Request,
                    TypeAxis::Wire,
                    &mut component_imports,
                );
            }
        }
        if let Some(body) = &plan.body_plan {
            collect_body_imports(
                &renderer,
                body,
                TypeAxis::Application,
                &mut component_imports,
            );
            if request_transforms {
                collect_body_imports(&renderer, body, TypeAxis::Wire, &mut component_imports);
            }
        }
        // A content-type-discriminated branch renders each media entry's own schema inline instead
        // of the status-wide alias, so those entries' component references import from here.
        for (index, response) in plan.response_table.iter().enumerate() {
            if renders_payload_inline(response)
                && matches!(response.payload, PayloadDisposition::Payload)
            {
                for (entry_index, entry) in response.media.iter().enumerate() {
                    collect_response_entry_imports(
                        &renderer,
                        entry,
                        TypeAxis::Application,
                        &mut component_imports,
                    );
                    // A converting entry's wire twin names the wire form of every component its
                    // payload reaches, the same rule the request twin follows.
                    if entry_payload_alias(conversions.get(index), entry_index).is_some() {
                        collect_response_entry_imports(
                            &renderer,
                            entry,
                            TypeAxis::Wire,
                            &mut component_imports,
                        );
                    }
                }
            }
            // An event pair is declared here whether or not the branch renders its arms inline —
            // a stream is one payload on both surfaces, so a branch can name its status-wide alias
            // and still declare the event pair its codec converts between.
            for entry_index in 0..response.media.len() {
                if event_pair_alias(conversions.get(index), entry_index).is_some() {
                    for axis in [TypeAxis::Application, TypeAxis::Wire] {
                        renderer.collect_operation_imports(
                            &response.media[entry_index].schema,
                            TypePosition::Response,
                            axis,
                            &mut component_imports,
                        );
                    }
                }
            }
        }
        // No component import means nothing can be shadowed, so the declaration set is not built.
        let (aliases, diagnostics) = if component_imports.is_empty() {
            (HashMap::new(), Vec::new())
        } else {
            // The interned set is extended only when a representation renders a global, so the
            // `string` default still borrows it and owns nothing per module.
            let globals = super::representation_globals(&model.config.types);
            let extended;
            let reserved = if globals.is_empty() {
                client_module_bindings()
            } else {
                extended = client_module_bindings()
                    .iter()
                    .copied()
                    .chain(globals)
                    .collect::<BTreeSet<&str>>();
                &extended
            };
            assign_import_aliases(
                &client_declarations(&stem, &operation_type_names, transforming, &conversions),
                reserved,
                &component_imports,
                &operation.source,
            )
        };
        renderer.set_import_aliases(aliases.clone());
        let arms = response_result_arms(&renderer, plan, &stem, &conversions, false);
        // Each converting media entry's payload pair, declared above the unions that name it.
        let entry_pairs = render_entry_payload_pairs(&renderer, plan, &conversions);
        let mut result_type = render_result_type(&arms, plan, &stem, "");
        // The pre-conversion union is declared next to the converted one so a reader sees both
        // surfaces in the module that converts between them, and so `execute`'s type argument names
        // a declaration rather than an inline union.
        if !response_transforms.is_empty() {
            let wire_arms = response_result_arms(&renderer, plan, &stem, &conversions, true);
            result_type.push('\n');
            result_type.push_str(&render_result_type(&wire_arms, plan, &stem, "Wire"));
        }
        // Whether the types artifact declared the request's wire twin. `render_input` names it on
        // the wire axis, so the same answer decides both the rendering and the import below.
        let request_twin = renderer.request_transforms(operation);
        let input_wire = request_transforms.then(|| {
            render_input(
                &renderer,
                operation,
                plan,
                &stem,
                &documentation,
                TypeAxis::Wire,
                request_twin,
            )
        });
        (
            render_input(
                &renderer,
                operation,
                plan,
                &stem,
                &documentation,
                TypeAxis::Application,
                request_twin,
            ),
            input_wire,
            request_twin,
            entry_pairs,
            result_type,
            successful_envelope_union(&arms),
            aliases,
            diagnostics,
        )
    };
    for diagnostic in alias_diagnostics {
        model.sink.push(diagnostic);
    }
    // The wire input names the request's wire twin for its JSON body member, so that declaration
    // has to come across with the rest of the operation's types.
    if input_wire.is_some()
        && request_twin
        && plan.body_plan.as_ref().is_some_and(body_uses_json_alias)
    {
        operation_type_names.insert(format!("{stem}RequestWire"));
    }
    let mut function_docs_operation = operation.clone();
    for parameter in &mut function_docs_operation.parameters {
        parameter.description = None;
    }

    let extension = import_extension(model);
    // Operation client emission is reachable only from the enabled client artifact pipeline.
    let auth_enforcement = model
        .config
        .client
        .as_ref()
        .expect("client emission requires client config")
        .auth_enforcement;
    let (imports_basic_credential, imports_cookie_credential, imports_client_certificate) =
        call_args_credentials(plan, auth_enforcement);
    let unchecked_response = model
        .config
        .validation
        .as_ref()
        .is_some_and(|validation| !validation.response);
    let streaming_response = plan.response_table.iter().any(|response| {
        matches!(response.payload, PayloadDisposition::Payload)
            && !matches!(
                response_body_side(response.kind, &response.match_key),
                ResponseBody::Error
            )
            && response.media.iter().any(|entry| {
                matches!(
                    entry.decoder,
                    DecoderClass::StreamingSse | DecoderClass::StreamingRaw
                )
            })
    });
    let decoding_notes = multipart_decoding_notes(plan);
    let (validate_request, validate_response) = validation_flags(model);
    let request_checks = request_validation_checks(
        model,
        operation,
        plan,
        &stem,
        validate_request,
        dispatch_root,
    );
    let response_checks = response_validation_checks(plan, &stem, validate_response);
    let event_checks = event_pipelines(plan, &stem, validate_response, &conversions);
    // Only the checks that name a validator: a per-event pipeline that converts without validating
    // names no validator module, and changes nothing about the functions this module declares —
    // its codec runs inside the runtime, so `orThrow` still delegates straight to the kernel.
    let validation_binding = !request_checks.is_empty()
        || !response_checks.is_empty()
        || event_checks.iter().any(|check| check.validator.is_some());
    let mut output = model.header();
    write_component_imports(
        &mut output,
        component_imports,
        &component_aliases,
        &extension,
        self_path,
        model.dirs.types,
    );
    if !operation_type_names.is_empty() {
        output.push_str("import type { ");
        output.push_str(
            &operation_type_names
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&relative_import(
            self_path,
            &[model.dirs.types, "operations", file_base],
            &extension,
        )));
        output.push_str(";\n");
    }
    if uses_typed_headers {
        output.push_str("import type { TypedHeaders } from ");
        output.push_str(&render_ts_string(&relative_import(
            self_path,
            &[model.dirs.types, "headers"],
            &extension,
        )));
        output.push_str(";\n");
    }
    output.push_str(if uses_sse_event {
        "import type { RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, SseEvent, UnknownHttpError } from "
    } else {
        "import type { RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError } from "
    });
    output.push_str(&render_ts_string(&relative_import(
        self_path,
        &[model.dirs.runtime, "result"],
        &extension,
    )));
    output.push_str(";\n");
    // `unwrap` reuses the result module's failed-branch throw so the orThrow variant delegates to
    // the bound base function instead of the runtime's unbound executeOrThrow. `TransformError` is
    // the class a conversion's catch narrows on, and comes from the same module.
    let binds_transform = request_transforms || !response_transforms.is_empty();
    let result_values = match (binds_transform, validation_binding || binds_transform) {
        (true, _) => "TransformError, unwrap",
        (false, true) => "unwrap",
        (false, false) => "",
    };
    if !result_values.is_empty() {
        output.push_str("import { ");
        output.push_str(result_values);
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&relative_import(
            self_path,
            &[model.dirs.runtime, "result"],
            &extension,
        )));
        output.push_str(";\n");
    }
    let mut helper_names = plan
        .param_plans
        .iter()
        .map(|parameter| helper_export_name(parameter.resolved.helper))
        .collect::<BTreeSet<_>>();
    if plan.response_table.iter().any(response_decodes_multipart) {
        helper_names.insert(MULTIPART_RESPONSE_DECODER);
    }
    if plan_decodes_sse(plan) {
        helper_names.insert(SSE_DECODER);
    }
    if plan_reads_raw_stream(plan) {
        helper_names.insert(RAW_STREAM_READER);
    }
    if !helper_names.is_empty() {
        output.push_str("import { ");
        output.push_str(&helper_names.into_iter().collect::<Vec<_>>().join(", "));
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&relative_import(
            self_path,
            &[model.dirs.runtime, "serialize"],
            &extension,
        )));
        output.push_str(";\n");
    }
    // The kernel entry points plus whichever body encoders this operation's descriptor names,
    // written in the table's order so adding an encoder cannot reorder the clause run to run.
    let mut transport_values = [false; TRANSPORT_VALUE_IMPORTS.len()];
    transport_values[transport_import_index("execute")] = true;
    // `executeOrThrow` only appears when nothing is bound. A validated or converting operation's
    // orThrow variant delegates to `unwrap` over its own base function instead, so importing the
    // runtime entry point unconditionally leaves it unread — which is an error in a consumer
    // project compiling generated code under `noUnusedLocals`.
    if !(validation_binding || binds_transform) {
        transport_values[transport_import_index("executeOrThrow")] = true;
    }
    if !plan.auth_plan.is_empty() {
        transport_values[transport_import_index("authAlternatives")] = true;
        for alternative in &plan.auth_plan {
            for scheme in alternative {
                transport_values[transport_import_index(credential_applier_name(&scheme.kind))] =
                    true;
            }
        }
    }
    if let Some(body) = &plan.body_plan {
        mark_body_encoders(body, &mut transport_values);
    }
    output.push_str("import {");
    for (index, name) in TRANSPORT_VALUE_IMPORTS.iter().enumerate() {
        if transport_values[index] {
            output.push(' ');
            output.push_str(name);
            output.push(',');
        }
    }
    output.pop();
    if imports_client_certificate {
        output.push_str(", type AmbientClientCertificate");
    }
    if imports_cookie_credential {
        output.push_str(", type AmbientCookieCredential");
    }
    if imports_basic_credential {
        output.push_str(", type BasicCredential");
    }
    output.push_str(", type CallOptions, type OperationDescriptor, type Transport } from ");
    output.push_str(&render_ts_string(&relative_import(
        self_path,
        &[model.dirs.runtime, "transport"],
        &extension,
    )));
    output.push_str(";\n");
    if validation_binding {
        write_validator_imports(
            &mut output,
            &request_checks,
            &response_checks,
            &event_checks,
            &ValidatorModule {
                from_file: self_path,
                artifact: validation_artifact_dir(model),
                file_base,
                extension: &extension,
            },
        );
    }
    // The operation's own codec module, one import for both directions: the encoder the request
    // conversion calls, every decoder its converting response branches call, and the per-event
    // decoder each converting event stream hands the runtime.
    // One decoder per declared response and per converting event stream, plus at most one encoder,
    // so the names are distinct by construction; sorting is the only thing the emitted order needs.
    let mut codec_names = response_transforms
        .iter()
        .map(|transform| transform.decoder.clone())
        .chain(
            response_transforms
                .iter()
                .filter_map(|transform| transform.reviver.clone()),
        )
        .chain(
            event_checks
                .iter()
                .filter_map(|check| check.pair.as_ref())
                .map(|pair| format!("decode{pair}")),
        )
        .collect::<Vec<_>>();
    if request_transforms {
        codec_names.push(format!("encode{stem}Input"));
    }
    codec_names.sort_unstable();
    if !codec_names.is_empty() {
        output.push_str(&format!("import {{ {} }} from ", codec_names.join(", ")));
        output.push_str(&render_ts_string(&relative_import(
            self_path,
            &[model.dirs.client, TRANSFORM_SUBDIR, "operations", file_base],
            &extension,
        )));
        output.push_str(";\n");
    }
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        operation,
        &model.config.documentation,
        ClientDocKind::Declaration,
        unchecked_response,
        streaming_response,
        &decoding_notes,
    );
    output.push_str("export type ");
    output.push_str(&stem);
    output.push_str("Input = ");
    output.push_str(&input);
    output.push_str(";\n\n");

    if let Some(input_wire) = &input_wire {
        write_source_metadata(&mut output, &operation.source, 0);
        output.push_str("export type ");
        output.push_str(&stem);
        output.push_str("InputWire = ");
        output.push_str(input_wire);
        output.push_str(";\n\n");
    }

    output.push_str(&entry_pairs);
    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        operation,
        &model.config.documentation,
        ClientDocKind::Declaration,
        unchecked_response,
        streaming_response,
        &decoding_notes,
    );
    output.push_str(&result_type);
    output.push('\n');

    output.push_str(&render_call_args(&plan.auth_plan, auth_enforcement, &stem));
    output.push('\n');

    for check in &event_checks {
        write_event_check(&mut output, check);
        output.push('\n');
    }

    write_source_metadata(&mut output, &operation.source, 0);
    write_descriptor(
        &mut output,
        model,
        operation,
        plan,
        allocated_name,
        &event_checks,
        &response_transforms,
    );
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        &function_docs_operation,
        &model.config.documentation,
        ClientDocKind::ResultFunction,
        unchecked_response,
        streaming_response,
        &decoding_notes,
    );
    output.push_str("export async function ");
    output.push_str(allocated_name);
    output.push_str("<S extends string = never>(transport: Transport<S>, input: ");
    output.push_str(&stem);
    output.push_str("Input, ...args: ");
    output.push_str(&stem);
    output.push_str("CallArgs<S>): Promise<");
    output.push_str(&stem);
    output.push_str("Result> {\n");
    output.push_str(&result_function_body(
        &stem,
        &request_checks,
        &response_checks,
        request_transforms,
        dispatch_root,
        &response_transforms,
    ));
    output.push_str("}\n\n");

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        &function_docs_operation,
        &model.config.documentation,
        ClientDocKind::ThrowFunction,
        unchecked_response,
        streaming_response,
        &decoding_notes,
    );
    output.push_str("export async function ");
    output.push_str(allocated_name);
    output.push_str("OrThrow<S extends string = never>(transport: Transport<S>, input: ");
    output.push_str(&stem);
    output.push_str("Input, ...args: ");
    output.push_str(&stem);
    output.push_str("CallArgs<S>): Promise<");
    output.push_str(&envelope_type);
    output.push_str("> {\n");
    // A conversion binds the same way a validator does: the orThrow variant delegates to the base
    // function so the throw happens after the conversion, not around it.
    output.push_str(&throw_function_body(
        allocated_name,
        &stem,
        validation_binding || binds_transform,
    ));
    output.push_str("}\n");
    output
}

// --- generated validation binding --------------------------------------------------------------

/// One request-position value the operation checks before dispatch: its `input` accessor, the
/// per-operation validator to call, and the wire-rooted base path issues carry.
struct RequestCheck {
    access: String,
    validator: String,
    base_path: String,
    /// Skip the call when the value is `undefined`, mirroring the transport's serialization
    /// presence test (`input[name] === undefined` is never serialized, so it is never validated).
    guarded: bool,
    /// For a content-type-discriminated body arm: the `contentType` accessor and the media value
    /// that selects this check. The test doubles as the presence guard, so such a check is never
    /// additionally `guarded`.
    content_type: Option<(String, String)>,
}

/// One JSON body validator call inside a documented branch: which `contentType` selects it (absent
/// when the branch is not content-type-discriminated, so the call is unguarded), the validator to
/// call, and which side of the branch carries the body.
struct BodyCheck {
    content_type: Option<String>,
    validator: String,
    body: ResponseBody,
}

/// Which side of a documented `response` branch carries the decoded JSON body to validate.
#[derive(Clone, Copy)]
pub(super) enum ResponseBody {
    /// A 2xx branch: the body lives in `result.data`.
    Data,
    /// A documented non-2xx branch: the body lives in `result.error`.
    Error,
    /// A `default` branch spans both, so `result.ok` selects the field at runtime.
    Both,
}

/// One documented response branch the operation checks after dispatch: an optional JSON body
/// validator call and/or an optional header validator call, both feeding the same
/// `responseIssues` buffer inside the branch's `if (result.match === ...)` arm. At least one of
/// the two is always present — a branch with neither never reaches the emitted checks.
struct ResponseCheck {
    /// The rendered `outcome` literal this branch is keyed on — the same value the result union's
    /// arm carries, so the emitted guard and the emitted arm can never disagree.
    outcome: String,
    body: Vec<BodyCheck>,
    /// The `<...>Headers` validator, called as `validator(result.meta.headers, [], responseIssues)`
    /// after the body check — present exactly when the response declares a header.
    headers_validator: Option<String>,
}

/// `(validate_request, validate_response)` — both false unless a non-off engine is resolved, which
/// keeps the emitted client bytes identical to today for `engine: off`.
/// One documented response branch whose payload the transform layer converts after dispatch.
struct ResponseTransform {
    /// The rendered `outcome` literal, the same value the result union's arm carries.
    outcome: String,
    /// The `contentType` discriminant this codec is selected by, present exactly when the branch
    /// converts entry by entry. Absent means one codec covers the whole branch.
    content_type: Option<String>,
    /// The emitted codec this branch calls, from the operation's own transform module.
    decoder: String,
    /// The path-scoped exact-integer revival this JSON entry hands to the transport.
    reviver: Option<String>,
    /// Which field carries the payload — `default` spans both, so `result.ok` picks at runtime.
    body: ResponseBody,
}

/// What the transform layer converts in one declared response.
pub(super) enum ResponseConversion {
    /// Nothing converts: the branch declares the same payload type on both surfaces.
    None,
    /// One codec converts the status-wide payload, keyed on the alias the types artifact declared
    /// for the whole branch. A branch reaches this only when it declares exactly one media entry —
    /// two would make it content-type discriminated — so the payload the alias names is that
    /// entry's, and the index says which.
    Whole(usize),
    /// One codec per converting media entry, named in the client's own operation module.
    PerEntry(Vec<EntryConversion>),
}

/// One media entry's codec: where it sits in the response's media list, the name its payload types
/// are declared under in the client's own operation module, and which value it converts.
pub(super) struct EntryConversion {
    pub(super) index: usize,
    pub(super) name: String,
    /// Set for an event stream, whose codec converts one event rather than the branch's payload.
    /// The payload is `AsyncIterable<SseEvent<…>>`, which no schema-keyed codec converts, so the
    /// pair this names is the event's — and the runtime calls the codec through the descriptor's
    /// per-event hook instead of the client converting a returned body.
    pub(super) per_event: bool,
}

/// What the transform layer converts in each declared response, in `response_table` order.
///
/// A content-type-discriminated branch renders one payload type per media entry rather than the
/// status-wide alias, so a single status-wide codec could neither accept the narrowed arm's input
/// nor return its output. Those branches convert entry by entry instead: the discriminant the arm
/// already carries selects the codec, and each entry names its own payload pair.
///
/// A multipart-decoded payload is not reachable here. It renders as the object its parts decode to,
/// which is not the shape any schema-keyed codec converts, so
/// `unconvertible_transform_diagnostics` refuses one that would have converted rather than leaving
/// it a wire string under a type that says `Date`.
pub(super) fn response_conversions(
    model: &EmissionModel<'_, '_>,
    plan: &OperationPlan,
    stem: &str,
) -> Vec<ResponseConversion> {
    if !model.transform_facts().enabled() {
        return Vec::new();
    }
    plan.response_table
        .iter()
        .map(|response| {
            if !matches!(response.payload, PayloadDisposition::Payload) {
                return ResponseConversion::None;
            }
            // JSON only, matching the types artifact's own twin rule: a `text/plain` payload stays a
            // string on both surfaces, declares no wire twin, and gets no codec, so binding one here
            // would name two symbols that were never emitted.
            // Keyed on the decoder, so a streaming-marked `+json` entry — `+json` by essence, a byte
            // stream by payload — is excluded here exactly as it is in the types artifact's twin
            // rule. Binding a codec to one would convert a `ReadableStream`, and would name a wire
            // twin the types artifact never declared.
            let converts = |entry: &ResponseMediaPlan| {
                entry.multipart.is_none()
                    && entry.decoder == DecoderClass::Json
                    && model.transform_facts().reaches(&entry.schema)
            };
            // An event stream's codec converts one event, and the status-wide alias names the
            // stream rather than the event — so a converting event entry is named per entry even on
            // a branch that carries no `contentType` discriminant, where `Whole` would otherwise
            // apply. Streaming-marked entries of the JSON family are excluded by the decoder for
            // the same reason they are above: their payload is bytes, not events.
            let converts_events = |entry: &ResponseMediaPlan| {
                entry.decoder == DecoderClass::StreamingSse
                    && model.transform_facts().reaches(&entry.schema)
            };
            if !response.content_type_discriminated && !response.media.iter().any(&converts_events)
            {
                let entry = response.media.iter().position(&converts);
                return match entry {
                    Some(entry) if !renders_payload_inline(response) => {
                        ResponseConversion::Whole(entry)
                    }
                    _ => ResponseConversion::None,
                };
            }
            // Named over every declared entry rather than only the converting ones, because the
            // names live in the arm space: one arm per media entry, converting or not. The
            // validators artifact tags the JSON subset instead, so a response mixing JSON with
            // another media type can tag the same entry differently in the two artifacts — each is
            // internally consistent, which is what the emitted code needs.
            let media = response
                .media
                .iter()
                .map(|entry| entry.media.as_str())
                .collect::<Vec<_>>();
            let names = response_media_names(&response_type_name(stem, response), &media);
            let entries = response
                .media
                .iter()
                .zip(names)
                .enumerate()
                .filter_map(|(index, (entry, name))| {
                    // `Event` distinguishes the pair from the entry's own payload, which an event
                    // entry still declares wherever the branch renders its arms inline.
                    if converts_events(entry) {
                        Some(EntryConversion {
                            index,
                            name: format!("{}Event", name.name),
                            per_event: true,
                        })
                    } else if converts(entry) {
                        Some(EntryConversion {
                            index,
                            name: name.name,
                            per_event: false,
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if entries.is_empty() {
                ResponseConversion::None
            } else {
                ResponseConversion::PerEntry(entries)
            }
        })
        .collect()
}

/// The conversion one media entry declares, whatever it converts.
fn entry_conversion(
    conversion: Option<&ResponseConversion>,
    index: usize,
) -> Option<&EntryConversion> {
    match conversion {
        Some(ResponseConversion::PerEntry(entries)) => {
            entries.iter().find(|entry| entry.index == index)
        }
        _ => None,
    }
}

/// The name one media entry's payload pair is declared under, or `None` when that entry does not
/// convert and keeps the type it renders inline on both surfaces.
///
/// An event entry answers `None` too: its payload is the stream, which is the same declaration on
/// both surfaces because the runtime converts each event before yielding it. What it declares a
/// pair for is the event, which `event_pair_alias` names.
fn entry_payload_alias(conversion: Option<&ResponseConversion>, index: usize) -> Option<&str> {
    entry_conversion(conversion, index)
        .filter(|entry| !entry.per_event)
        .map(|entry| entry.name.as_str())
}

/// The name one media entry's *event* pair is declared under, for an entry whose codec the runtime
/// calls once per yielded event.
fn event_pair_alias(conversion: Option<&ResponseConversion>, index: usize) -> Option<&str> {
    entry_conversion(conversion, index)
        .filter(|entry| entry.per_event)
        .map(|entry| entry.name.as_str())
}

/// Whether the request surface carries a value the transform layer converts, and so binds an
/// encode call before dispatch.
///
/// A caller-serialized parameter is excluded: its input is the caller's own pre-serialized string,
/// so there is no application value to convert. Every body shape this cannot carry is refused by
/// `unconvertible_transform_diagnostics` rather than left to convert silently.
///
/// The transform emitter reads this rather than restating it: it decides on the same condition
/// whether to export the encoder this module imports, and two independently written answers would
/// disagree as a compile error in the emitted code rather than as a failing test here.
pub(super) fn request_transform_binding(
    model: &EmissionModel<'_, '_>,
    plan: &OperationPlan,
) -> bool {
    if !model.transform_facts().enabled() {
        return false;
    }
    plan.param_plans
        .iter()
        .any(|parameter| parameter_transforms(model, parameter))
        || request_body_transforms(model, plan.body_plan.as_ref())
}

pub(super) fn reaches_non_integer_transform(
    model: &EmissionModel<'_, '_>,
    schema: &SchemaNode,
) -> bool {
    [
        TransformKind::DateTimeDate,
        TransformKind::DateTimeInstant,
        TransformKind::DatePlainDate,
    ]
    .into_iter()
    .any(|kind| model.transform_facts().reaches_kind(schema, kind))
}

pub(super) fn parameter_transforms(
    model: &EmissionModel<'_, '_>,
    parameter: &ParameterPlan,
) -> bool {
    if parameter.caller_serialized {
        return false;
    }
    if parameter_encodes_int64(parameter) {
        model.transform_facts().reaches(&parameter.schema)
    } else {
        reaches_non_integer_transform(model, &parameter.schema)
    }
}

pub(super) fn parameter_encodes_int64(parameter: &ParameterPlan) -> bool {
    parameter.resolved.helper.is_content_json()
}

/// Whether a request body carries an application value the operation encoder converts.
pub(super) fn request_body_transforms(
    model: &EmissionModel<'_, '_>,
    plan: Option<&BodyPlan>,
) -> bool {
    match plan {
        Some(BodyPlan::Json {
            schema: Some(schema),
            ..
        }) => model.transform_facts().reaches(schema),
        Some(BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. }) => {
            fields
                .iter()
                .any(|field| form_field_transforms(model, field))
        }
        Some(BodyPlan::ContentTypeDiscriminated { arms, .. }) => arms
            .iter()
            .any(|arm| request_body_transforms(model, Some(&arm.plan))),
        _ => false,
    }
}

/// Whether one rendered form field carries its schema value rather than a binary upload handle.
pub(super) fn form_field_transforms(model: &EmissionModel<'_, '_>, field: &FormFieldPlan) -> bool {
    if field.is_binary_upload() {
        return false;
    }
    if form_field_encodes_int64(field) {
        model.transform_facts().reaches(&field.schema)
    } else {
        reaches_non_integer_transform(model, &field.schema)
    }
}

pub(super) fn form_field_encodes_int64(field: &FormFieldPlan) -> bool {
    field.serialization.content_media().is_some_and(|media| {
        media
            .payloads
            .iter()
            .all(|payload| *payload == PayloadKind::Json)
    })
}

fn response_transform_bindings(
    model: &EmissionModel<'_, '_>,
    plan: &OperationPlan,
    stem: &str,
    conversions: &[ResponseConversion],
) -> Vec<ResponseTransform> {
    let mut bindings = Vec::new();
    for (response, conversion) in plan.response_table.iter().zip(conversions) {
        let outcome = outcome_literal(response);
        let body = response_body_side(response.kind, &response.match_key);
        match conversion {
            ResponseConversion::None => {}
            ResponseConversion::Whole(index) => bindings.push(ResponseTransform {
                outcome,
                content_type: None,
                decoder: format!("decode{}", response_type_name(stem, response)),
                reviver: model
                    .transform_facts()
                    .reaches_kind(&response.media[*index].schema, TransformKind::IntegerBigInt)
                    .then(|| format!("revive{}", response_type_name(stem, response))),
                body,
            }),
            ResponseConversion::PerEntry(entries) => {
                // An event entry binds no post-execute call: its codec runs inside the runtime, once
                // per yielded event, so by the time the result is in hand it has already converted.
                for entry in entries.iter().filter(|entry| !entry.per_event) {
                    bindings.push(ResponseTransform {
                        outcome: outcome.clone(),
                        content_type: Some(response.media[entry.index].media.clone()),
                        decoder: format!("decode{}", entry.name),
                        reviver: model
                            .transform_facts()
                            .reaches_kind(
                                &response.media[entry.index].schema,
                                TransformKind::IntegerBigInt,
                            )
                            .then(|| format!("revive{}", entry.name)),
                        body,
                    });
                }
            }
        }
    }
    bindings
}

fn validation_flags(model: &EmissionModel<'_, '_>) -> (bool, bool) {
    match model.config.validation.as_ref() {
        Some(validation)
            if matches!(
                validation.engine,
                ValidationEngine::Generated | ValidationEngine::Zod
            ) =>
        {
            (validation.request, validation.response)
        }
        _ => (false, false),
    }
}

/// The artifact directory the bound engine's checks are imported from.
///
/// Both engines expose the same `validate{Name}(value, path, issues)` entry points and the same
/// `Issue` type, so the engine selects a directory and changes nothing else about the emitted body —
/// and because the client forwards the value it already decoded rather than the validator's return,
/// which engine is bound is invisible in `data`.
fn validation_artifact_dir<'model>(model: &'model EmissionModel<'_, '_>) -> &'model str {
    match model.config.validation.as_ref() {
        Some(validation) if validation.engine == ValidationEngine::Zod => model.dirs.zod,
        _ => model.dirs.validators,
    }
}

/// The request-side checks: every parameter in declared order, then the JSON request body. Empty
/// unless request validation is enabled.
fn request_validation_checks(
    model: &EmissionModel<'_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    stem: &str,
    enabled: bool,
    root: &str,
) -> Vec<RequestCheck> {
    if !enabled {
        return Vec::new();
    }
    let mut checks = Vec::new();
    let names = operation_parameter_validator_names(operation, stem);
    for (index, parameter, _) in planned_parameters(operation, plan) {
        let type_name = &names[index];
        checks.push(RequestCheck {
            access: input_member(
                InputMember::Parameter {
                    location: parameter.location,
                    name: &parameter.name,
                },
                root,
            ),
            validator: format!("validate{type_name}"),
            base_path: format!(
                "[{}, {}]",
                render_ts_string(super::parameter_group_name(parameter.location)),
                render_ts_string(&parameter.name)
            ),
            guarded: true,
            content_type: None,
        });
    }
    // A required body is always sent, so it is validated unconditionally; an optional body — or any
    // member reached through one — is skipped when absent, matching the parameter presence rule.
    // Which positions exist, and what each is called, is decided in one place for all three
    // emitters; a position with no sound access path is declared but never called.
    if let Some(body) = &operation.request_body {
        for position in request_body_validator_positions(body, plan.body_plan.as_ref(), stem) {
            let access = position.access;
            let (repeated_wrapper, optional_repeated_wrapper) =
                match (&access, plan.body_plan.as_ref()) {
                    (
                        RequestBodyAccess::Field { key, wrapped: true },
                        Some(
                            BodyPlan::FormUrlencoded { fields, .. }
                            | BodyPlan::Multipart { fields, .. },
                        ),
                    ) => fields
                        .iter()
                        .find(|field| field.name == key.as_str())
                        .map_or((false, false), |field| {
                            let repeated = form_field_render_schema(model, field).repeated;
                            (repeated, repeated && !field.required)
                        }),
                    _ => (false, false),
                };
            let content_type = match &access {
                RequestBodyAccess::Arm { media } => {
                    let chain = if body.required { "." } else { "?." };
                    let discriminant = format!(
                        "{}{chain}contentType",
                        input_member(InputMember::Body, root)
                    );
                    Some((discriminant, media.clone()))
                }
                RequestBodyAccess::Whole | RequestBodyAccess::Field { .. } => None,
            };
            checks.push(RequestCheck {
                access: body_member_access(
                    &access,
                    root,
                    body.required,
                    repeated_wrapper,
                    optional_repeated_wrapper,
                ),
                base_path: body_member_path(&access, repeated_wrapper),
                validator: format!("validate{}", position.name),
                guarded: position.guarded,
                content_type,
            });
        }
    }
    checks
}

/// The accessor for one request-body validator position, rooted at the dispatched object.
///
/// Every hop that can be absent is optional-chained: the body itself when it is not required, and a
/// wrapper object when its field is optional. A guarded check then tests the whole expression, so an
/// absent hop short-circuits to `undefined` and the call is skipped rather than throwing.
fn body_member_access(
    access: &RequestBodyAccess,
    root: &str,
    body_required: bool,
    repeated_wrapper: bool,
    optional_repeated_wrapper: bool,
) -> String {
    let base = input_member(InputMember::Body, root);
    let chain = if body_required { "." } else { "?." };
    match access {
        RequestBodyAccess::Whole => base,
        RequestBodyAccess::Field { key, wrapped } => {
            let property = render_property_key(key);
            // A non-identifier key is bracket-accessed, and a bracket follows the object directly:
            // `x.["k"]` is not TypeScript, while the optional form `x?.["k"]` is.
            let mut access = if property == *key {
                format!("{base}{chain}{key}")
            } else if body_required {
                format!("{base}[{property}]")
            } else {
                format!("{base}?.[{property}]")
            };
            if *wrapped && repeated_wrapper {
                access.push_str(if optional_repeated_wrapper {
                    "?.map((item) => item.body)"
                } else {
                    ".map((item) => item.body)"
                });
            } else if *wrapped {
                access.push_str("?.body");
            }
            access
        }
        RequestBodyAccess::Arm { .. } => format!("{base}{chain}body"),
    }
}

/// The issue path for one request-body validator position, mirroring the accessor hop for hop.
fn body_member_path(access: &RequestBodyAccess, repeated_wrapper: bool) -> String {
    match access {
        RequestBodyAccess::Whole => "[\"body\"]".to_owned(),
        RequestBodyAccess::Field { key, wrapped } => {
            let key = render_ts_string(key);
            if *wrapped && !repeated_wrapper {
                format!("[\"body\", {key}, \"body\"]")
            } else {
                format!("[\"body\", {key}]")
            }
        }
        RequestBodyAccess::Arm { .. } => "[\"body\", \"body\"]".to_owned(),
    }
}

/// The response-side checks: each documented branch whose decoded body is JSON and carries an
/// emitted validator, plus — independently — every branch that declares a header. Empty unless
/// response validation is enabled.
fn response_validation_checks(
    plan: &OperationPlan,
    stem: &str,
    enabled: bool,
) -> Vec<ResponseCheck> {
    if !enabled {
        return Vec::new();
    }
    plan.response_table
        .iter()
        .filter_map(|response| {
            let body = body_validation_checks(response, stem);
            let headers_validator = response
                .has_headers
                .then(|| format!("validate{}Headers", response_type_name(stem, response)));
            if body.is_empty() && headers_validator.is_none() {
                return None;
            }
            Some(ResponseCheck {
                outcome: outcome_literal(response),
                body,
                headers_validator,
            })
        })
        .collect()
}

/// The JSON body validator calls for one response branch. Empty when the branch carries no JSON
/// payload at all. A branch that is not content-type-discriminated yields one unguarded call; a
/// discriminated branch yields one call per JSON media entry, each gated on that entry's
/// `contentType`, so the schema that runs is the one the selected entry declared.
///
/// Every entry of this response the validators artifact emitted a validator for, paired with the
/// name it declared that validator under and with the entry's index in the response.
///
/// The list is the naming input, so it has to be the *same* list the validators emitter filters —
/// `media_has_validatable_schema`, which admits a whole JSON value and an event stream's per-event
/// schema and refuses a raw stream. Filtering a subset here and naming from it would tag the same
/// entry differently in the two artifacts, and this module would import a name that was never
/// emitted. The two naming cases mirror that emitter as well: one entry keeps the plain
/// `validate{Stem}Response{Suffix}` name, and two or more are tagged by media.
fn response_validator_names<'plan>(
    response: &'plan ResponsePlan,
    stem: &str,
) -> Vec<(usize, &'plan ResponseMediaPlan, String)> {
    if !matches!(response.payload, PayloadDisposition::Payload) {
        return Vec::new();
    }
    let validated = response
        .media
        .iter()
        .enumerate()
        .filter(|(_, media)| {
            matches!(
                media.decoder,
                DecoderClass::Json | DecoderClass::StreamingSse
            )
        })
        .collect::<Vec<_>>();
    if validated.is_empty() {
        return Vec::new();
    }
    let media_names = validated
        .iter()
        .map(|(_, media)| media.media.as_str())
        .collect::<Vec<_>>();
    let base = response_type_name(stem, response);
    let names = response_media_names(&format!("validate{base}"), &media_names);
    validated
        .into_iter()
        .zip(names)
        .map(|((index, media), name)| (index, media, name.name))
        .collect()
}

/// The post-execute checks: the buffered entries only. An event stream is checked once per event
/// inside the runtime instead, because its schema describes an event and not the body.
fn body_validation_checks(response: &ResponsePlan, stem: &str) -> Vec<BodyCheck> {
    let json = response_validator_names(response, stem)
        .into_iter()
        .filter(|(_, media, _)| media.decoder == DecoderClass::Json)
        .collect::<Vec<_>>();
    if json.is_empty() {
        return Vec::new();
    }
    let body = response_body_side(response.kind, &response.match_key);
    if !response.content_type_discriminated {
        // The planner sets this flag false only for a single concrete media entry; the non-empty
        // JSON subset checked above is therefore exactly one entry.
        return vec![BodyCheck {
            content_type: None,
            validator: json.into_iter().next().expect("one JSON media entry").2,
            body,
        }];
    }
    json.into_iter()
        .map(|(_, media, validator)| BodyCheck {
            content_type: Some(media.media.clone()),
            validator,
            body,
        })
        .collect()
}

/// One event stream's per-event pipeline: which media entry it belongs to, the validator it calls
/// and the codec it applies — either may be absent — and the name of the function the operation
/// module declares to wrap them.
pub(super) struct EventCheck {
    pub(super) response_index: usize,
    pub(super) media_index: usize,
    pub(super) validator: Option<String>,
    /// The event pair this converts between, absent when the representation converts nothing this
    /// schema reaches. `decode{pair}` is the codec and `{pair}Wire` the value it accepts.
    pub(super) pair: Option<String>,
    pub(super) function: String,
}

/// The per-event pipelines this operation declares: one per event stream that validates its events,
/// converts them, or both.
///
/// The two halves are independent — response validation is a config switch and a conversion follows
/// from the representation the schema reaches — so this is keyed on their union rather than on
/// either one. The runtime calls the wrapper once per yielded event, before the event reaches the
/// consumer and before the progress counter moves, which is the position the contract puts per-item
/// checking at.
fn event_pipelines(
    plan: &OperationPlan,
    stem: &str,
    validate: bool,
    conversions: &[ResponseConversion],
) -> Vec<EventCheck> {
    plan.response_table
        .iter()
        .enumerate()
        .flat_map(|(response_index, response)| {
            let validators = if validate {
                response_validator_names(response, stem)
            } else {
                Vec::new()
            };
            response
                .media
                .iter()
                .enumerate()
                .filter(|(_, media)| media.decoder == DecoderClass::StreamingSse)
                .filter_map(move |(media_index, _)| {
                    let validator = validators
                        .iter()
                        .find(|(index, _, _)| *index == media_index)
                        .map(|(_, _, name)| name.clone());
                    let pair = event_pair_alias(conversions.get(response_index), media_index)
                        .map(str::to_owned);
                    // The wrapper is named after whichever half is present, and the two agree
                    // wherever both are: each is `response_media_names` over the same status, and
                    // an event entry is in both name spaces.
                    let base = match (&validator, &pair) {
                        (Some(validator), _) => validator.trim_start_matches("validate").to_owned(),
                        (None, Some(pair)) => pair.strip_suffix("Event").unwrap_or(pair).to_owned(),
                        (None, None) => return None,
                    };
                    Some(EventCheck {
                        response_index,
                        media_index,
                        function: format!("check{base}Event"),
                        validator,
                        pair,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

enum InputMember<'a> {
    Parameter {
        location: ParamLocation,
        name: &'a str,
    },
    Body,
}

/// The accessor for one nested input member, reused by both the presence guard and validator call.
///
/// `root` is the object the request actually dispatches: the caller's own input, or — where the
/// request converts — the encoded one, so a validator observes wire values and never an application
/// `Date`.
fn input_member(member: InputMember<'_>, root: &str) -> String {
    match member {
        InputMember::Parameter { location, name } => {
            // `location` is always one of the four fixed identifiers (path/query/header/cookie), so
            // it is always dot-accessed; only a non-identifier parameter name needs a bracket key.
            let location = super::parameter_group_name(location);
            let key = render_property_key(name);
            if key == name {
                format!("{root}.{location}?.{name}")
            } else {
                format!("{root}.{location}?.[{key}]")
            }
        }
        InputMember::Body => format!("{root}.body"),
    }
}

/// Where one operation's validator imports resolve from and to: the module doing the importing, and
/// the bound engine's artifact directory, file and extension it imports out of. Grouped because the
/// four travel together and mean nothing apart.
struct ValidatorModule<'a> {
    from_file: &'a str,
    artifact: &'a str,
    file_base: &'a str,
    extension: &'a str,
}

/// The `Issue` type import plus the per-operation checks pulled from the bound engine's artifact.
fn write_validator_imports(
    output: &mut String,
    request: &[RequestCheck],
    response: &[ResponseCheck],
    events: &[EventCheck],
    module: &ValidatorModule<'_>,
) {
    let ValidatorModule {
        from_file,
        artifact,
        file_base,
        extension,
    } = *module;
    output.push_str("import type { Issue } from ");
    output.push_str(&render_ts_string(&relative_import(
        from_file,
        &[artifact, "runtime"],
        extension,
    )));
    output.push_str(";\n");
    let validators = request
        .iter()
        .map(|check| check.validator.as_str())
        .chain(
            response
                .iter()
                .flat_map(|check| check.body.iter().map(|body| body.validator.as_str())),
        )
        .chain(
            response
                .iter()
                .filter_map(|check| check.headers_validator.as_deref()),
        )
        .chain(events.iter().filter_map(|check| check.validator.as_deref()))
        .collect::<BTreeSet<_>>();
    output.push_str("import { ");
    output.push_str(&validators.into_iter().collect::<Vec<_>>().join(", "));
    output.push_str(" } from ");
    output.push_str(&render_ts_string(&relative_import(
        from_file,
        &[artifact, "operations", file_base],
        extension,
    )));
    output.push_str(";\n");
}

/// The result-returning function body: today's single `execute` call when nothing is bound, else a
/// pre-dispatch request check and a post-dispatch response check around it.
fn result_function_body(
    stem: &str,
    request: &[RequestCheck],
    response: &[ResponseCheck],
    encodes_request: bool,
    dispatched: &str,
    transforms: &[ResponseTransform],
) -> String {
    if request.is_empty() && response.is_empty() && transforms.is_empty() && !encodes_request {
        return format!("  return execute<{stem}Result>(transport, descriptor, input, args[0]);\n");
    }
    // With a response conversion bound, `execute` hands back the pre-conversion surface and each
    // converting branch is narrowed and converted before it is returned; the branches that convert
    // nothing are the same declaration on both surfaces and fall through untouched.
    let executed = if transforms.is_empty() {
        format!("{stem}Result")
    } else {
        format!("{stem}ResultWire")
    };
    let mut body = String::new();
    if encodes_request {
        body.push_str(&format!("  let wire: {stem}InputWire;\n"));
        body.push_str("  try {\n");
        body.push_str(&format!("    wire = encode{stem}Input(input);\n"));
        body.push_str("  } catch (error) {\n");
        body.push_str("    if (error instanceof TransformError) {\n");
        body.push_str("      return { outcome: \"request-transform\", ok: false, error };\n");
        body.push_str("    }\n");
        body.push_str("    throw error;\n");
        body.push_str("  }\n");
    }
    if !request.is_empty() {
        body.push_str("  const requestIssues: Issue[] = [];\n");
        for check in request {
            let condition = match (&check.content_type, check.guarded) {
                (Some((discriminant, media)), _) => {
                    Some(format!("{discriminant} === {}", render_ts_string(media)))
                }
                (None, true) => Some(format!("{} !== undefined", check.access)),
                (None, false) => None,
            };
            if let Some(condition) = condition {
                body.push_str(&format!("  if ({condition}) {{\n"));
                body.push_str(&format!(
                    "    {}({}, {}, requestIssues);\n",
                    check.validator, check.access, check.base_path
                ));
                body.push_str("  }\n");
            } else {
                body.push_str(&format!(
                    "  {}({}, {}, requestIssues);\n",
                    check.validator, check.access, check.base_path
                ));
            }
        }
        body.push_str("  if (requestIssues.length > 0) {\n");
        body.push_str(
            "    return { outcome: \"request-validation\", ok: false, issues: requestIssues };\n",
        );
        body.push_str("  }\n");
    }
    if response.is_empty() && transforms.is_empty() {
        body.push_str(&format!(
            "  return execute<{executed}>(transport, descriptor, {dispatched}, args[0]);\n"
        ));
        return body;
    }
    body.push_str(&format!(
        "  const result = await execute<{executed}>(transport, descriptor, {dispatched}, args[0]);\n"
    ));
    if !response.is_empty() {
        write_response_validation(&mut body, response);
    }
    // Conversion runs after validation, on every branch that declares one, so a validator only ever
    // observes wire values and a decode that rejects is reported as its own arm rather than folded
    // into a validation failure.
    for transform in transforms {
        write_response_transform(&mut body, transform);
    }
    body.push_str("  return result;\n");
    body
}

/// One converting response branch: narrowed, converted, and returned — or reported as a
/// `response-transform` failure. The narrowing holds inside `catch` because `result` is `const` and
/// nothing in `try` assigns it, which is what lets the failure arm read `status` and `meta`.
fn write_response_transform(body: &mut String, transform: &ResponseTransform) {
    let ResponseTransform {
        outcome,
        content_type,
        decoder,
        ..
    } = transform;
    // The discriminant narrows `result` to the one arm this codec was built for, so both the value
    // it reads and the value it returns are that entry's own payload type rather than the branch's
    // union of them.
    let narrowed = match content_type {
        Some(media) => format!(
            "result.outcome === {outcome} && result.contentType === {}",
            render_ts_string(media)
        ),
        None => format!("result.outcome === {outcome}"),
    };
    body.push_str(&format!("  if ({narrowed}) {{\n"));
    body.push_str("    try {\n");
    match transform.body {
        ResponseBody::Data => {
            body.push_str(&format!(
                "      return {{ ...result, data: {decoder}(result.data) }};\n"
            ));
        }
        ResponseBody::Error => {
            body.push_str(&format!(
                "      return {{ ...result, error: {decoder}(result.error) }};\n"
            ));
        }
        ResponseBody::Both => {
            body.push_str("      return result.ok\n");
            body.push_str(&format!(
                "        ? {{ ...result, data: {decoder}(result.data) }}\n"
            ));
            body.push_str(&format!(
                "        : {{ ...result, error: {decoder}(result.error) }};\n"
            ));
        }
    }
    body.push_str("    } catch (error) {\n");
    body.push_str("      if (error instanceof TransformError) {\n");
    body.push_str("        return { outcome: \"response-transform\", ok: false, match: result.outcome, status: result.status, error, meta: result.meta };\n");
    body.push_str("      }\n");
    body.push_str("      throw error;\n");
    body.push_str("    }\n");
    body.push_str("  }\n");
}

fn write_response_validation(body: &mut String, response: &[ResponseCheck]) {
    // The outer guard admits exactly the branches that carry a check, which is what narrows
    // `result` to the arms with a `status` and a `meta` for the failure return below. A single
    // checked branch needs no inner test — the guard already established it.
    body.push_str("  if (");
    body.push_str(
        &response
            .iter()
            .map(|check| format!("result.outcome === {}", check.outcome))
            .collect::<Vec<_>>()
            .join(" || "),
    );
    body.push_str(") {\n");
    body.push_str("    const responseIssues: Issue[] = [];\n");
    let branched = response.len() > 1;
    let indent = if branched { "      " } else { "    " };
    for (index, check) in response.iter().enumerate() {
        if branched {
            let keyword = if index == 0 {
                "    if"
            } else {
                "    } else if"
            };
            body.push_str(&format!(
                "{keyword} (result.outcome === {}) {{\n",
                check.outcome
            ));
        }
        for (media_index, media_check) in check.body.iter().enumerate() {
            // A content-type-discriminated branch gates each call on the entry that was actually
            // selected, so the schema that runs is the one that entry declared.
            let indent = match &media_check.content_type {
                Some(content_type) => {
                    let keyword = if media_index == 0 { "if" } else { "} else if" };
                    body.push_str(&format!(
                        "{indent}{keyword} (result.contentType === {}) {{\n",
                        render_ts_string(content_type)
                    ));
                    &format!("{indent}  ")
                }
                None => indent,
            };
            write_body_validator_call(body, indent, media_check);
        }
        if check
            .body
            .last()
            .is_some_and(|media_check| media_check.content_type.is_some())
        {
            body.push_str(&format!("{indent}}}\n"));
        }
        if let Some(headers_validator) = &check.headers_validator {
            body.push_str(&format!(
                "{indent}{headers_validator}(result.meta.headers, [], responseIssues);\n"
            ));
        }
    }
    if branched {
        body.push_str("    }\n");
    }
    body.push_str("    if (responseIssues.length > 0) {\n");
    body.push_str("      return { outcome: \"response-validation\", ok: false, match: result.outcome, status: result.status, issues: responseIssues, meta: result.meta };\n");
    body.push_str("    }\n");
    body.push_str("  }\n");
}

/// One validator call, selecting `result.data` or `result.error` by the branch's side — or both,
/// chosen at runtime on `result.ok`, for a `default` branch that spans them.
/// The per-event pipeline the runtime calls once per yielded event: validate, then convert.
///
/// A failure throws rather than returning one, because by the time an event is decoded the result
/// has already resolved and there is no arm left to report into — the runtime catches the throw and
/// surfaces it as the stream's `StreamFailure`, with the issue list as its cause.
///
/// The order is contractual and this is where it is fixed: a validator describes the wire value, so
/// it runs before the codec replaces that value with its application form. Where nothing converts,
/// the value is returned unchanged — validation is assert-only, so the event the consumer receives
/// is the one that was checked.
///
/// The parameter names the event's wire type wherever this converts, because that is what the codec
/// accepts; the runtime's own `unknown` meets it at the descriptor's hook slot, which is declared
/// for exactly that.
fn write_event_check(output: &mut String, check: &EventCheck) {
    let EventCheck {
        validator,
        pair,
        function,
        ..
    } = check;
    let parameter = match pair {
        Some(pair) => format!("{pair}Wire"),
        None => "unknown".to_owned(),
    };
    output.push_str(&format!(
        "function {function}(data: {parameter}): unknown {{\n"
    ));
    if let Some(validator) = validator {
        output.push_str("  const eventIssues: Issue[] = [];\n");
        output.push_str(&format!("  {validator}(data, [], eventIssues);\n"));
        output.push_str("  if (eventIssues.length > 0) {\n");
        output.push_str("    throw eventIssues;\n");
        output.push_str("  }\n");
    }
    match pair {
        Some(pair) => output.push_str(&format!("  return decode{pair}(data);\n")),
        None => output.push_str("  return data;\n"),
    }
    output.push_str("}\n");
}

fn write_body_validator_call(body: &mut String, indent: &str, check: &BodyCheck) {
    let validator = &check.validator;
    match check.body {
        ResponseBody::Data => {
            body.push_str(&format!(
                "{indent}{validator}(result.data, [], responseIssues);\n"
            ));
        }
        ResponseBody::Error => {
            body.push_str(&format!(
                "{indent}{validator}(result.error, [], responseIssues);\n"
            ));
        }
        ResponseBody::Both => {
            body.push_str(&format!("{indent}if (result.ok) {{\n"));
            body.push_str(&format!(
                "{indent}  {validator}(result.data, [], responseIssues);\n"
            ));
            body.push_str(&format!("{indent}}} else {{\n"));
            body.push_str(&format!(
                "{indent}  {validator}(result.error, [], responseIssues);\n"
            ));
            body.push_str(&format!("{indent}}}\n"));
        }
    }
}

/// The orThrow function body: today's direct `executeOrThrow` when nothing is bound, else `unwrap`
/// over the validated base function so request and response checks apply before the throw.
fn throw_function_body(name: &str, stem: &str, binding: bool) -> String {
    if binding {
        format!("  return unwrap(await {name}(transport, input, ...args));\n")
    } else {
        format!("  return executeOrThrow<{stem}Result>(transport, descriptor, input, args[0]);\n")
    }
}

/// Names a client operation module binds without getting them from the types artifact: the runtime
/// kernel identifiers it imports, and the TypeScript globals its own signatures name in type
/// position. A component import carrying one of these collides with the binding — a duplicate
/// identifier for the kernel names, and for a global the built-in silently stops resolving, so
/// `Promise<Result>` against a document that declares a component named `Promise` is `TS2315: Type
/// 'Promise' is not generic`.
///
/// Reserved unconditionally, for the same reason `Req` and `Missing` are: which kernel imports a
/// module ends up writing depends on its resolved auth, parameter and validation shape, none of
/// which is settled when the import block is built. Reserving the union costs an alias only when a
/// component actually carries one of these names.
///
/// Only the globals emitted client code *names* belong here. `Readonly`, `Set`, `Omit` and the rest
/// appear solely in the embedded runtime assets under `runtime/`, which never hold a user schema
/// and so cannot be shadowed; `no_builtin_generics_in_schema_bearing_modules` is what keeps that
/// true as the emitters change.
const CLIENT_MODULE_BINDINGS: &[&str] = &[
    // runtime/result
    "RequestPhaseFailure",
    "ResponseMeta",
    "ResponsePhaseFailure",
    "UnknownHttpError",
    "unwrap",
    // runtime/transport
    "AmbientClientCertificate",
    "AmbientCookieCredential",
    "BasicCredential",
    "CallOptions",
    "OperationDescriptor",
    "Transport",
    "authAlternatives",
    "basicCredential",
    "bearerCredential",
    "binaryBody",
    "cookieKeyCredential",
    "discriminatedBody",
    "execute",
    "executeOrThrow",
    "headerKeyCredential",
    "httpSchemeCredential",
    "jsonBody",
    "multipartBody",
    "mutualTlsCredential",
    "queryKeyCredential",
    "textBody",
    "urlencodedBody",
    // runtime/serialize
    "decodeMultipartResponse",
    // validators/runtime
    "Issue",
    // types/headers
    "TypedHeaders",
    // TypeScript globals named by the emitted operation signatures.
    "Promise",
];

/// Every name a client operation module declares or imports from the types artifact. A component
/// import carrying one of these would be shadowed by the local declaration or duplicate the
/// operation-type import, so `assign_import_aliases` renames it. `Req` and `Missing` are reserved
/// unconditionally: they are the call-args helpers, and which of them this operation declares
/// depends on its resolved auth shape, which is not settled when imports are written.
fn client_declarations(
    stem: &str,
    operation_type_names: &BTreeSet<String>,
    transforming: bool,
    conversions: &[ResponseConversion],
) -> BTreeSet<String> {
    let mut declared = BTreeSet::from([
        format!("{stem}Input"),
        format!("{stem}Result"),
        format!("{stem}CallArgs"),
        "descriptor".to_owned(),
        "Req".to_owned(),
        "Missing".to_owned(),
    ]);
    // The pre-conversion surfaces are reserved for the whole compile rather than per operation:
    // which operations declare one is not settled when the declaration set is built, but a
    // representation that converts nothing can produce none of them, and reserving three names
    // per operation there would cost three allocations for nothing.
    if transforming {
        declared.extend([
            format!("{stem}ResultWire"),
            format!("{stem}InputWire"),
            format!("{stem}RequestWire"),
        ]);
    }
    // The per-entry payload pairs are declarations of this module too, so a component whose type
    // name equals one of them has to be aliased rather than shadow it.
    for conversion in conversions {
        if let ResponseConversion::PerEntry(entries) = conversion {
            for entry in entries {
                declared.insert(format!("{}Wire", entry.name));
                declared.insert(entry.name.clone());
            }
        }
    }
    declared.extend(operation_type_names.iter().cloned());
    declared
}

/// `CLIENT_MODULE_BINDINGS` plus every parameter-serializer helper name, interned once for the
/// process. Borrowed by `assign_import_aliases` rather than folded into the per-module declaration
/// set: it is the same 36 constant names for every emitted operation module, and owning them there
/// would allocate once per module for nothing.
fn client_module_bindings() -> &'static BTreeSet<&'static str> {
    static BINDINGS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    BINDINGS.get_or_init(|| {
        CLIENT_MODULE_BINDINGS
            .iter()
            .copied()
            .chain(HelperId::ALL.into_iter().map(helper_export_name))
            .collect()
    })
}

fn write_component_imports(
    output: &mut String,
    imports: BTreeMap<String, BTreeSet<String>>,
    aliases: &HashMap<String, String>,
    extension: &str,
    from_file: &str,
    types_dir: &str,
) {
    for (file, names) in imports {
        output.push_str("import type { ");
        output.push_str(
            &names
                .into_iter()
                .map(|name| import_clause(name, aliases))
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&relative_import(
            from_file,
            &[types_dir, "components", &file],
            extension,
        )));
        output.push_str(";\n");
    }
}

fn operation_type_imports(
    plan: &OperationPlan,
    stem: &str,
    conversions: &[ResponseConversion],
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if plan.body_plan.as_ref().is_some_and(body_uses_json_alias) {
        names.insert(format!("{stem}Request"));
    }
    for (index, response) in plan.response_table.iter().enumerate() {
        // A branch that renders its payload inline has no reader for the status-wide alias, so
        // importing it would be an unused import.
        if matches!(response.payload, PayloadDisposition::Payload)
            && !renders_payload_inline(response)
        {
            names.insert(response_type_name(stem, response));
            // Only a status-wide conversion reads the status-wide twin; a per-entry one declares
            // its own pairs in this module and imports neither.
            if matches!(conversions.get(index), Some(ResponseConversion::Whole(_))) {
                names.insert(format!("{}Wire", response_type_name(stem, response)));
            }
        }
        if response.has_headers {
            names.insert(format!("{}Headers", response_type_name(stem, response)));
        }
    }
    names
}

fn body_uses_json_alias(plan: &BodyPlan) -> bool {
    match plan {
        BodyPlan::Json { .. } => true,
        BodyPlan::ContentTypeDiscriminated { .. } => json_body_count(plan) == 1,
        BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::TopLevelStream { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => false,
    }
}

fn collect_body_imports(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    axis: TypeAxis,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
) {
    match plan {
        BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
            for field in fields {
                if let Some(schema) = form_field_render_schema(renderer.model, field).schema {
                    renderer.collect_operation_imports(
                        schema,
                        TypePosition::Request,
                        axis,
                        imports,
                    );
                }
            }
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            let inline_json = json_body_count(plan) > 1;
            for arm in arms {
                collect_discriminated_body_imports(renderer, &arm.plan, axis, inline_json, imports);
            }
        }
        BodyPlan::Json { .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::TopLevelStream { .. } => {}
    }
}

fn collect_discriminated_body_imports(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    axis: TypeAxis,
    inline_json: bool,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
) {
    if let BodyPlan::Json {
        schema: Some(schema),
        ..
    } = plan
        && inline_json
    {
        renderer.collect_operation_imports(schema, TypePosition::Request, axis, imports);
        return;
    }
    collect_body_imports(renderer, plan, axis, imports);
}

fn json_body_count(plan: &BodyPlan) -> usize {
    match plan {
        BodyPlan::Json { .. } => 1,
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            arms.iter().map(|arm| json_body_count(&arm.plan)).sum()
        }
        BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::TopLevelStream { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => 0,
    }
}

/// The caller-facing input object, on either surface. The wire surface is what the request
/// conversion produces and what `execute` then serializes; a position reaching no transform renders
/// the same declaration on both, which is why only converting operations declare the second one.
fn render_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    stem: &str,
    documentation: &DocumentationConfig,
    axis: TypeAxis,
    request_twin: bool,
) -> String {
    if plan.param_plans.is_empty() && plan.body_plan.is_none() {
        return "{}".to_owned();
    }
    let parameters = planned_parameters(operation, plan);
    let mut output = String::from("{\n");
    for location in [
        ParamLocation::Path,
        ParamLocation::Query,
        ParamLocation::Header,
        ParamLocation::Cookie,
    ] {
        let group = parameters
            .iter()
            .filter(|(_, parameter, _)| parameter.location == location)
            .collect::<Vec<_>>();
        if group.is_empty() {
            continue;
        }
        output.push_str("  ");
        // Shared with the types artifact's `Request`, with the descriptor's `location` literal,
        // and with the input-member access, because all four name the same property.
        output.push_str(super::parameter_group_name(location));
        if !group.iter().any(|(_, parameter, _)| parameter.required) {
            output.push('?');
        }
        output.push_str(": {\n");
        for (_, parameter, parameter_plan) in group {
            if let Some(description) = &parameter.description {
                write_parameter_property_tsdoc(&mut output, description, documentation, 4);
            }
            output.push_str("    ");
            output.push_str(&render_property_key(&parameter_plan.name));
            if !parameter.required {
                output.push('?');
            }
            output.push_str(": ");
            if parameter_plan.caller_serialized {
                // The client cannot serialize this media type, so the input is the caller's
                // pre-serialized wire string rather than the declared schema (OASTS5006).
                output.push_str("string");
            } else {
                let parameter_axis = if axis == TypeAxis::Wire
                    && !parameter_transforms(renderer.model, parameter_plan)
                {
                    TypeAxis::Application
                } else {
                    axis
                };
                output.push_str(&renderer.render_type(
                    &parameter_plan.schema,
                    TypePosition::Request,
                    parameter_axis,
                    4,
                ));
            }
            output.push_str(";\n");
        }
        output.push_str("  };\n");
    }
    if let Some(body_plan) = &plan.body_plan {
        output.push_str("  body");
        if !operation
            .request_body
            .as_ref()
            .is_some_and(|body| body.required)
        {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(&render_body_input(
            renderer,
            body_plan,
            stem,
            2,
            axis,
            request_twin,
        ));
        output.push_str(";\n");
    }
    output.push('}');
    output
}

fn planned_parameters<'operation>(
    operation: &'operation Operation,
    plan: &'operation OperationPlan,
) -> Vec<(usize, &'operation Param, &'operation ParameterPlan)> {
    plan.param_plans
        .iter()
        .map(|parameter_plan| {
            // Parameter plans are constructed by iterating this operation's parameter list and
            // preserve each source identity unchanged.
            operation
                .parameters
                .iter()
                .enumerate()
                .find(|(_, parameter)| parameter.source == parameter_plan.source)
                .map(|(index, parameter)| (index, parameter, parameter_plan))
                .expect("a client parameter plan originates from its operation")
        })
        .collect()
}

fn write_parameter_property_tsdoc(
    output: &mut String,
    description: &str,
    documentation: &DocumentationConfig,
    indent: usize,
) {
    if !documentation.enabled || !documentation.description {
        return;
    }
    push_indent(output, indent);
    output.push_str("/**\n");
    if !documentation.summary {
        push_indent(output, indent);
        output.push_str(" * @remarks\n");
    }
    for line in encode_comment_text(description).split('\n') {
        push_indent(output, indent);
        output.push_str(" * ");
        output.push_str(line);
        output.push('\n');
    }
    push_indent(output, indent);
    output.push_str(" */\n");
}

/// `body_twin` says the types artifact declared a wire twin of the request alias, which it does
/// only where the request converts — so a wire-axis render for a request that converts nothing
/// still names the application alias, the only one that exists.
fn render_body_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    stem: &str,
    indent: usize,
    axis: TypeAxis,
    body_twin: bool,
) -> String {
    match plan {
        BodyPlan::Json { .. } => {
            if axis == TypeAxis::Wire && body_twin {
                format!("{stem}RequestWire[\"body\"]")
            } else {
                format!("{stem}Request[\"body\"]")
            }
        }
        BodyPlan::TopLevelText { .. } => "string".to_owned(),
        BodyPlan::TopLevelBinary { .. } => "Uint8Array".to_owned(),
        BodyPlan::TopLevelStream { .. } => "ReadableStream<Uint8Array>".to_owned(),
        BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
            render_form_input(renderer, fields, indent, axis)
        }
        BodyPlan::ContentTypeDiscriminated { arms, all_concrete } => {
            let inline_json = json_body_count(plan) > 1;
            arms.iter()
                .map(|arm| {
                    let content_type = if *all_concrete {
                        render_ts_string(&arm.media)
                    } else {
                        "string".to_owned()
                    };
                    format!(
                        "{{ contentType: {content_type}; body: {} }}",
                        render_discriminated_body_input(
                            renderer,
                            &arm.plan,
                            stem,
                            indent,
                            axis,
                            body_twin,
                            inline_json,
                        )
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ")
        }
    }
}

fn render_discriminated_body_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    stem: &str,
    indent: usize,
    axis: TypeAxis,
    body_twin: bool,
    inline_json: bool,
) -> String {
    if let BodyPlan::Json { schema, .. } = plan
        && inline_json
    {
        return schema.as_ref().map_or_else(
            || "unknown".to_owned(),
            |schema| renderer.render_type(schema, TypePosition::Request, axis, indent),
        );
    }
    render_body_input(renderer, plan, stem, indent, axis, body_twin)
}

fn render_form_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    fields: &[FormFieldPlan],
    indent: usize,
    axis: TypeAxis,
) -> String {
    let mut output = String::from("{\n");
    for field in fields {
        push_indent(&mut output, indent + 2);
        output.push_str(&render_property_key(&field.name));
        if !field.required {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(&render_form_field_input(renderer, field, indent + 2, axis));
        output.push_str(";\n");
    }
    push_indent(&mut output, indent);
    output.push('}');
    output
}

#[derive(Clone, Copy)]
pub(super) struct FormFieldRenderSchema<'a> {
    pub schema: Option<&'a SchemaNode>,
    pub repeated: bool,
}

/// The schema a form field's input declaration renders, plus whether the runtime iterates it.
///
/// A wrapper belongs to each repeated item, so its `body` renders from the array item rather than
/// the array itself. Binary uploads render an opaque handle and therefore select no schema.
pub(super) fn form_field_render_schema<'a>(
    model: &'a EmissionModel<'_, '_>,
    field: &'a FormFieldPlan,
) -> FormFieldRenderSchema<'a> {
    let array_items = schema_array_items(model, &field.schema, &mut HashSet::new());
    let schema = if field.is_binary_upload() {
        None
    } else if field.wrapper.wrapped {
        Some(array_items.unwrap_or(&field.schema))
    } else {
        Some(&field.schema)
    };
    FormFieldRenderSchema {
        schema,
        repeated: array_items.is_some(),
    }
}

fn render_form_field_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    field: &FormFieldPlan,
    indent: usize,
    axis: TypeAxis,
) -> String {
    let field_axis = if axis == TypeAxis::Wire && !form_field_transforms(renderer.model, field) {
        TypeAxis::Application
    } else {
        axis
    };
    let rendered = form_field_render_schema(renderer.model, field);
    // The runtime iterates a repeated field before it applies the wrapper, so a wrapped field's
    // body is one array element. An unwrapped non-binary field still renders its array schema
    // directly because its serializer receives each element after the runtime performs the split.
    let body = match rendered.schema {
        Some(schema) => renderer.render_type(schema, TypePosition::Request, field_axis, indent),
        None => "Blob | File".to_owned(),
    };
    let repeat = |body: String| {
        if rendered.repeated && (rendered.schema.is_none() || field.wrapper.wrapped) {
            format!("({body})[]")
        } else {
            body
        }
    };
    if !field.wrapper.wrapped {
        return repeat(body);
    }
    let mut output = format!("{{ body: {body}; contentType: ");
    if field.wrapper.content_type_literal {
        // Planning enables a wrapped literal content type only for content-based serialization.
        let media = field
            .serialization
            .content_media()
            .expect("a wrapped field uses content-based serialization");
        output.push_str(
            &media
                .values
                .iter()
                .map(|value| render_ts_string(value))
                .collect::<Vec<_>>()
                .join(" | "),
        );
    } else {
        output.push_str("string");
    }
    if field.wrapper.filename {
        output.push_str("; filename?: string");
    }
    output.push_str(" }");
    repeat(output)
}

/// One emitted HTTP arm of a per-operation result union. The result type, the `orThrow` envelope
/// type, and the validation binding are all built from this one list, so the three can never
/// disagree about which arms exist or what each carries.
struct ResultArm {
    /// The rendered `outcome` literal: a bare number for an exact declared status, a quoted string
    /// for a range or `default`. Number literals and string literals never overlap, which is what
    /// keeps the declared-key space disjoint from the failure-tag space by construction.
    outcome: String,
    ok: bool,
    /// The rendered `status` type: a numeric literal for an exact key, `number` for a range or
    /// `default`, whose wire status is only known at runtime.
    status: String,
    payload: String,
    content_type: Option<String>,
    headers_interface: Option<String>,
}

/// The payload pair each converting media entry declares: the type its arm carries, and the wire
/// twin the pre-conversion arm carries.
///
/// Declared here rather than in the types artifact because a discriminated entry's payload is only
/// ever named by this module's own arms and by the codec that converts between them — the same
/// reason the request surface's `{Stem}Input` pair lives here.
fn render_entry_payload_pairs(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &OperationPlan,
    conversions: &[ResponseConversion],
) -> String {
    let mut output = String::new();
    for (response, conversion) in plan.response_table.iter().zip(conversions) {
        let ResponseConversion::PerEntry(entries) = conversion else {
            continue;
        };
        for conversion in entries {
            let entry = &response.media[conversion.index];
            for (declared, axis) in [
                (conversion.name.clone(), TypeAxis::Application),
                (format!("{}Wire", conversion.name), TypeAxis::Wire),
            ] {
                write_source_metadata(&mut output, &entry.source, 0);
                output.push_str("export type ");
                output.push_str(&declared);
                output.push_str(" = ");
                // An event pair names the event, not the payload: the schema describes what one
                // event carries, and the payload it is reached through is the stream around it.
                output.push_str(&if conversion.per_event {
                    renderer.render_type(&entry.schema, TypePosition::Response, axis, 0)
                } else {
                    response_entry_payload_type(renderer, entry, axis, 0)
                });
                output.push_str(";\n\n");
            }
        }
    }
    output
}

/// The result union's arms on one surface. `wire` asks for the pre-conversion surface `execute`
/// hands back, where every payload the conversions name declares its wire twin instead; a payload no
/// conversion names is the same declaration on both surfaces and renders identically either way.
fn response_result_arms(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &OperationPlan,
    stem: &str,
    conversions: &[ResponseConversion],
    wire: bool,
) -> Vec<ResultArm> {
    let mut arms = Vec::new();
    for (index, response) in plan.response_table.iter().enumerate() {
        push_response_result_arms(
            &mut arms,
            renderer,
            response,
            stem,
            conversions.get(index),
            wire,
        );
    }
    arms
}

fn push_response_result_arms(
    arms: &mut Vec<ResultArm>,
    renderer: &TypesEmitter<'_, '_, '_>,
    response: &ResponsePlan,
    stem: &str,
    conversion: Option<&ResponseConversion>,
    wire: bool,
) {
    let status = match response.kind {
        ResponseMatchKind::Exact => response.match_key.clone(),
        ResponseMatchKind::Range | ResponseMatchKind::Default => "number".to_owned(),
    };
    let outcome = outcome_literal(response);
    let axis = if wire {
        TypeAxis::Wire
    } else {
        TypeAxis::Application
    };
    // Only computed when the response declares a header, keeping a header-less response's arms
    // free of any new allocation on this path.
    let headers_interface = response
        .has_headers
        .then(|| format!("{}Headers", response_type_name(stem, response)));
    // A content-type-discriminated payload is one arm per declared media entry, each typed to that
    // entry's own schema through the renderer the types artifact uses — so the two artifacts can
    // never render the same entry differently. Everything else keeps the status-wide alias.
    let media: Vec<(Option<String>, String)> =
        if matches!(response.payload, PayloadDisposition::Payload)
            && renders_payload_inline(response)
        {
            response
                .media
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    (
                        // A non-discriminated branch has exactly one concrete entry and carries no
                        // `contentType` discriminant, so only the discriminated form names it.
                        response
                            .content_type_discriminated
                            .then(|| entry.media.clone()),
                        // A converting entry names the pair this module declares for it, so the arm
                        // and the codec that produces it read one declaration rather than two
                        // renderings of the same schema.
                        match entry_payload_alias(conversion, index) {
                            Some(alias) if wire => format!("{alias}Wire"),
                            Some(alias) => alias.to_owned(),
                            None => response_entry_payload_type(renderer, entry, axis, 2),
                        },
                    )
                })
                .collect()
        } else {
            vec![(
                None,
                response_payload_type(
                    response,
                    stem,
                    wire && matches!(conversion, Some(ResponseConversion::Whole(_))),
                ),
            )]
        };
    // `default` is the one key that spans both outcomes, so each of its media entries yields a
    // success arm and a failure arm; every other key resolves to exactly one.
    let outcomes: &[bool] = match response_body_side(response.kind, &response.match_key) {
        ResponseBody::Both => &[true, false],
        ResponseBody::Data => &[true],
        ResponseBody::Error => &[false],
    };
    for (content_type, payload) in media {
        for &ok in outcomes {
            arms.push(ResultArm {
                outcome: outcome.clone(),
                ok,
                status: status.clone(),
                payload: payload.clone(),
                content_type: content_type.clone(),
                headers_interface: headers_interface.clone(),
            });
        }
    }
}

/// The TSDoc note each multipart response branch carries.
///
/// Every clause here is a decision the OpenAPI specification does not make — it scopes the Encoding
/// Object to request bodies and says nothing about decoding a response — so the rule the generated
/// client actually follows is written at the call site rather than left for a caller to discover
/// from behaviour.
fn multipart_decoding_notes(plan: &OperationPlan) -> Vec<String> {
    let mut notes = Vec::new();
    for response in &plan.response_table {
        if !response_decodes_multipart(response) {
            continue;
        }
        for entry in &response.media {
            let Some(multipart) = &entry.multipart else {
                continue;
            };
            notes.push(format!(
                "- response {} {}: each part maps to the property named by its Content-Disposition name. A part naming no declared property is kept{}; a declared property with no part is absent; a repeated name is collected into an array property and rejected for any other property; a binary part decodes to Uint8Array. Part filenames and per-part headers are not surfaced.",
                response.match_key,
                entry.media,
                if multipart.open {
                    ""
                } else {
                    " even though the schema forbids it"
                }
            ));
        }
    }
    notes
}

/// The payload type one declared media entry renders to. A multipart entry is the decoded object;
/// everything else goes through the types artifact's own rule, so the two artifacts cannot render
/// the same non-multipart entry differently.
/// The type one inline-rendered media entry's payload declares on the given surface.
///
/// The axis is the caller's, not a constant: an entry the transform layer converts declares its wire
/// twin on the pre-conversion surface `execute` hands back, and its application form on the surface
/// the caller sees. Rendering both from one axis would have the conversion read an already-decoded
/// value.
fn response_entry_payload_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    entry: &ResponseMediaPlan,
    axis: TypeAxis,
    indent: usize,
) -> String {
    match &entry.multipart {
        Some(multipart) => render_multipart_response_type(renderer, multipart, axis, indent),
        None => renderer.media_payload_type(
            media_essence(&entry.media),
            &entry.schema,
            match entry.decoder {
                DecoderClass::StreamingSse => Some(StreamKind::Sse),
                DecoderClass::StreamingRaw => Some(StreamKind::Raw),
                _ => None,
            },
            TypePosition::Response,
            axis,
            indent,
        ),
    }
}

/// The component types the inline-rendered payload of one entry actually names. A binary part
/// renders as `Uint8Array` and never reaches its schema, so walking the whole entry schema would
/// import a component nothing reads.
fn collect_response_entry_imports(
    renderer: &TypesEmitter<'_, '_, '_>,
    entry: &ResponseMediaPlan,
    axis: TypeAxis,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let Some(multipart) = &entry.multipart else {
        renderer.collect_operation_imports(&entry.schema, TypePosition::Response, axis, imports);
        return;
    };
    let shapes = multipart
        .parts
        .iter()
        .map(|part| &part.shape)
        .chain(multipart.open.then_some(&multipart.additional));
    for shape in shapes {
        if shape.payload != MultipartResponsePayload::Binary {
            renderer.collect_operation_imports(
                &shape.schema,
                TypePosition::Response,
                TypeAxis::Application,
                imports,
            );
        }
    }
}

/// The object type a decoded `multipart/form-data` body inhabits: one property per declared schema
/// property, plus an index signature when the schema admits undeclared ones.
///
/// The index signature's type unions in every declared property type. TypeScript requires each
/// declared property to be assignable to the index type, and a part-by-part classification routinely
/// produces a mix (`Uint8Array` next to `string`) that no single member covers.
fn render_multipart_response_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &MultipartResponsePlan,
    axis: TypeAxis,
    indent: usize,
) -> String {
    let parts = plan
        .parts
        .iter()
        .map(|part| {
            (
                part,
                render_multipart_part_type(renderer, &part.shape, axis, indent + 2),
            )
        })
        .collect::<Vec<_>>();
    if parts.is_empty() && !plan.open {
        return "{}".to_owned();
    }
    let mut output = String::from("{\n");
    for (part, rendered) in &parts {
        push_indent(&mut output, indent + 2);
        output.push_str(&render_property_key(&part.name));
        if !part.required {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(rendered);
        output.push_str(";\n");
    }
    if plan.open {
        let fallback = render_multipart_part_type(renderer, &plan.additional, axis, indent + 2);
        // `unknown` absorbs every other member, so the widening union is only built when the
        // fallback is something a declared property could fail to satisfy.
        let mut members = vec![fallback.clone()];
        if fallback != "unknown" {
            for (_, rendered) in &parts {
                if !members.contains(rendered) {
                    members.push(rendered.clone());
                }
            }
        }
        push_indent(&mut output, indent + 2);
        output.push_str("[key: string]: ");
        output.push_str(&members.join(" | "));
        output.push_str(";\n");
    }
    push_indent(&mut output, indent);
    output.push('}');
    output
}

/// One decoded part's type. Binary is the only kind whose runtime value leaves the JSON data model,
/// so it is the only kind that overrides the schema's own rendering — matching the request side,
/// where a binary upload field renders as `Blob | File` instead of its `type: string` schema.
fn render_multipart_part_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    shape: &MultipartResponseShape,
    axis: TypeAxis,
    indent: usize,
) -> String {
    if shape.payload == MultipartResponsePayload::Binary {
        return if shape.repeated {
            "Uint8Array[]".to_owned()
        } else {
            "Uint8Array".to_owned()
        };
    }
    renderer.render_type(&shape.schema, TypePosition::Response, axis, indent)
}

fn render_result_type(
    arms: &[ResultArm],
    plan: &OperationPlan,
    stem: &str,
    suffix: &str,
) -> String {
    let mut output = String::new();
    output.push_str("export type ");
    output.push_str(stem);
    output.push_str("Result");
    output.push_str(suffix);
    output.push_str(" =\n");
    for arm in arms {
        write_response_result_arm(&mut output, arm);
    }
    output
        .push_str("  | { outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }\n");
    output.push_str("  | ResponsePhaseFailure<");
    output.push_str(&outcome_space(plan));
    output.push_str(">\n");
    output.push_str("  | RequestPhaseFailure;\n");
    output
}

/// The operation's declared-key literal union, as `ResponsePhaseFailure`'s `Match` argument.
/// `never` when the operation documents no response at all, which leaves those arms' `match` as
/// `null` — the only branch identity there is.
fn outcome_space(plan: &OperationPlan) -> String {
    if plan.response_table.is_empty() {
        return "never".to_owned();
    }
    plan.response_table
        .iter()
        .map(outcome_literal)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The `outcome` value one declared response is keyed on: an exact status is the number literal a
/// caller writes as `case 200:`, a range or `default` key its own string literal.
fn outcome_literal(response: &ResponsePlan) -> String {
    match response.kind {
        // Exact keys are three ASCII digits with a 1-5 lead, so they are always valid — and
        // leading-zero-free — TypeScript number literals.
        ResponseMatchKind::Exact => response.match_key.clone(),
        ResponseMatchKind::Range | ResponseMatchKind::Default => {
            render_ts_string(&response.match_key)
        }
    }
}

fn write_response_result_arm(output: &mut String, arm: &ResultArm) {
    output.push_str("  | { outcome: ");
    output.push_str(&arm.outcome);
    output.push_str("; ok: ");
    output.push_str(if arm.ok { "true" } else { "false" });
    output.push_str("; status: ");
    output.push_str(&arm.status);
    output.push_str(if arm.ok { "; data: " } else { "; error: " });
    output.push_str(&arm.payload);
    if let Some(content_type) = &arm.content_type {
        output.push_str("; contentType: ");
        output.push_str(&render_ts_string(content_type));
    }
    output.push_str("; meta: ");
    output.push_str(&meta_type(arm.headers_interface.as_deref()));
    output.push_str(" }\n");
}

/// The `meta` type one arm carries: plain `ResponseMeta`, or the narrowing intersection when that
/// arm's response declares headers. Shared with the `orThrow` envelope so the typed headers
/// reachable through the result form's `meta.headers` are equally reachable through the thrown
/// form's resolved `.meta.headers`.
fn meta_type(headers_interface: Option<&str>) -> String {
    match headers_interface {
        Some(interface_name) => format!(
            "ResponseMeta & {{ readonly headers: TypedHeaders<keyof {interface_name} & string> }}"
        ),
        None => "ResponseMeta".to_owned(),
    }
}

fn response_payload_type(response: &ResponsePlan, stem: &str, wire: bool) -> String {
    match response.payload {
        PayloadDisposition::NoPayload | PayloadDisposition::StaticBodyless => {
            "undefined".to_owned()
        }
        PayloadDisposition::Payload => {
            let name = response_type_name(stem, response);
            if wire { format!("{name}Wire") } else { name }
        }
    }
}

pub(super) fn response_type_name(stem: &str, response: &ResponsePlan) -> String {
    let suffix = match response.kind {
        ResponseMatchKind::Exact | ResponseMatchKind::Range => {
            response.match_key.to_ascii_uppercase()
        }
        ResponseMatchKind::Default => "Default".to_owned(),
    };
    format!("{stem}Response{suffix}")
}

/// Which side of the `ok` split a declared response key resolves to: a 2xx exact status or a
/// `2XX`-style range carries the success payload, any other declared status the error payload, and
/// `default` spans both because one `default` branch can cover 2xx and non-2xx statuses alike.
/// One classification for both readers — the arm writer, which turns it into how many arms the key
/// emits, and the validation binding, which turns it into which field it checks.
pub(super) fn response_body_side(kind: ResponseMatchKind, match_key: &str) -> ResponseBody {
    let successful = match kind {
        ResponseMatchKind::Default => return ResponseBody::Both,
        ResponseMatchKind::Exact => match_key
            .parse::<u16>()
            .is_ok_and(|status| (200..=299).contains(&status)),
        ResponseMatchKind::Range => match_key.starts_with('2'),
    };
    if successful {
        ResponseBody::Data
    } else {
        ResponseBody::Error
    }
}

/// The `orThrow` resolved type: one `{ data, meta }` envelope per distinct success arm, deduped on
/// the whole envelope so two arms differing only in `contentType` collapse. `never` when the
/// operation documents no successful response — the form can then only throw.
fn successful_envelope_union(arms: &[ResultArm]) -> String {
    let mut envelopes = Vec::new();
    for arm in arms {
        if !arm.ok {
            continue;
        }
        let envelope = format!(
            "{{ data: {}; meta: {} }}",
            arm.payload,
            meta_type(arm.headers_interface.as_deref())
        );
        if !envelopes.contains(&envelope) {
            envelopes.push(envelope);
        }
    }
    if envelopes.is_empty() {
        "never".to_owned()
    } else {
        envelopes.join(" | ")
    }
}

fn write_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    allocated_name: &str,
    event_checks: &[EventCheck],
    response_transforms: &[ResponseTransform],
) {
    output.push_str("const descriptor: OperationDescriptor = {\n  operationId: ");
    output.push_str(&render_ts_string(
        operation.operation_id.as_deref().unwrap_or(allocated_name),
    ));
    output.push_str(",\n  method: ");
    output.push_str(&render_ts_string(&operation.method.to_ascii_uppercase()));
    output.push_str(",\n  path: [\n");
    for segment in &operation.path_template {
        output.push_str("    [{ kind: \"literal\", text: \"/\" }");
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(text) => {
                    output.push_str(", { kind: \"literal\", text: ");
                    output.push_str(&render_ts_string(text));
                    output.push_str(" }");
                }
                SegmentPart::Param(name) => {
                    output.push_str(", { kind: \"param\", name: ");
                    output.push_str(&render_ts_string(name));
                    output.push_str(" }");
                }
            }
        }
        output.push_str("],\n");
    }
    output.push_str("  ],\n  params: ");
    let parameters = planned_parameters(operation, plan);
    if parameters.is_empty() {
        output.push_str("[]");
    } else {
        output.push_str("[\n");
        for (_, parameter, parameter_plan) in parameters {
            output.push_str("    { name: ");
            output.push_str(&render_ts_string(&parameter_plan.name));
            output.push_str(", location: ");
            output.push_str(&render_ts_string(super::parameter_group_name(
                parameter_plan.resolved.location,
            )));
            output.push_str(", required: ");
            output.push_str(if parameter.required { "true" } else { "false" });
            output.push_str(", serialize: ");
            output.push_str(helper_export_name(parameter_plan.resolved.helper));
            output.push_str(", allowReserved: ");
            output.push_str(if parameter_plan.resolved.allow_reserved {
                "true"
            } else {
                "false"
            });
            // Content JSON serializers take the raw typed value, so the transport skips its
            // `ParamValue` guard and forwards it unchecked; the flag is absent otherwise.
            if parameter_plan.resolved.helper.is_content_json() {
                output.push_str(", content: true");
            }
            output.push_str(" },\n");
        }
        output.push_str("  ]");
    }
    output.push_str(",\n  body: ");
    if let Some(body) = &plan.body_plan {
        write_body_descriptor(output, model, body, 2);
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  accept: ");
    output.push_str(
        &plan
            .accept
            .as_ref()
            .map_or_else(|| "null".to_owned(), |value| render_ts_string(value)),
    );
    output.push_str(",\n  credentialHeaders: [");
    output.push_str(
        &plan
            .credential_headers
            .iter()
            .map(|header| render_ts_string(header))
            .collect::<Vec<_>>()
            .join(", "),
    );
    output.push_str("],\n  security: ");
    output.push_str(&security_field(&plan.auth_plan));
    output.push_str(",\n  responses: [\n");
    for (response_index, response) in plan.response_table.iter().enumerate() {
        output.push_str("    { match: ");
        output.push_str(&render_ts_string(&response.match_key));
        output.push_str(", kind: ");
        output.push_str(&render_ts_string(match response.kind {
            ResponseMatchKind::Exact => "exact",
            ResponseMatchKind::Range => "range",
            ResponseMatchKind::Default => "default",
        }));
        output.push_str(", status: ");
        if response.kind == ResponseMatchKind::Exact {
            output.push_str(&response.match_key);
        } else {
            output.push_str("null");
        }
        output.push_str(", bodyless: ");
        output.push_str(
            if matches!(response.payload, PayloadDisposition::StaticBodyless) {
                "true"
            } else {
                "false"
            },
        );
        output.push_str(", media: [");
        // A statically bodyless branch drops its streaming entries: the contract is that such a
        // branch never forms a streaming branch or creates a handle, so naming a reader for one
        // would be a promise the runtime cannot keep — and it would drag the event parser into a
        // client that never reads a stream. Buffered entries stay exactly where they were, so no
        // non-streaming descriptor moves a byte.
        let bodyless = matches!(response.payload, PayloadDisposition::StaticBodyless);
        output.push_str(
            &response
                .media
                .iter()
                .enumerate()
                .filter(|(_, media)| !(bodyless && media.decoder.is_streaming()))
                .map(|(media_index, media)| {
                    let on_event = event_checks
                        .iter()
                        .find(|check| {
                            check.response_index == response_index
                                && check.media_index == media_index
                        })
                        .map(|check| check.function.as_str());
                    let lossless_int64 = !bodyless
                        && media.decoder == DecoderClass::Json
                        && model
                            .transform_facts()
                            .reaches_kind(&media.schema, TransformKind::IntegerBigInt);
                    let outcome = outcome_literal(response);
                    let reviver = lossless_int64.then(|| {
                        // The transform planner creates a reviver on this response/media entry
                        // whenever `lossless_int64` is true.
                        response_transforms
                            .iter()
                            .find(|transform| {
                                transform.outcome == outcome
                                    && transform
                                        .content_type
                                        .as_deref()
                                        .is_none_or(|content_type| content_type == media.media)
                            })
                            .and_then(|transform| transform.reviver.as_deref())
                            .expect("an int64 JSON response has a path-scoped reviver")
                    });
                    format!(
                        "[{}, {}]",
                        render_ts_string(&media.media),
                        render_response_decoder(media, on_event, reviver)
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        output.push_str("], hasContentTypeDiscriminant: ");
        output.push_str(if response.content_type_discriminated {
            "true"
        } else {
            "false"
        });
        output.push_str(" },\n");
    }
    output.push_str("  ],\n  baseUrl: ");
    write_base_url(output, &plan.base_url);
    output.push_str(",\n  fetchDefaults: ");
    // Operation client emission is reachable only from the enabled client artifact pipeline.
    write_fetch_defaults(
        output,
        &model
            .config
            .client
            .as_ref()
            .expect("client emission requires client config")
            .fetch_options,
    );
    output.push_str(",\n};\n");
}

/// Whether the alias is the unconditional `[options?: CallOptions]` form: `runtime` mode, an
/// unsecured operation, or an anonymous alternative present. The complement drives both the
/// conditional alias emission and the extra runtime-type imports.
fn call_args_is_unconditional(auth_plan: &[AuthAlternative], enforcement: AuthEnforcement) -> bool {
    enforcement != AuthEnforcement::Types
        || auth_plan.is_empty()
        || auth_plan.iter().any(|alternative| alternative.is_empty())
}

/// The `<Op>CallArgs<S>` alias plus any helper type it needs, terminated by a newline. In `types`
/// mode a secured operation with no anonymous alternative narrows the trailing options element by
/// whether `S` proves an alternative satisfied; every other case — `runtime` mode, unsecured, or an
/// anonymous alternative present — leaves the options element optional.
///
/// The satisfied fall-throughs and the widened branch resolve to a NAMED tuple, never an inlined
/// one: TypeScript will not accept a call argument against the deferred conditional under an
/// unconstrained `S` unless those outcomes share a named alias. A pure function of the plan for
/// byte-identical reruns.
fn render_call_args(
    auth_plan: &[AuthAlternative],
    enforcement: AuthEnforcement,
    stem: &str,
) -> String {
    if call_args_is_unconditional(auth_plan, enforcement) {
        // The parameter is kept so every operation's alias has the same arity and an explicit
        // instantiation still resolves, and `_`-prefixed so `noUnusedParameters` in a consumer's
        // project does not report the one alias body that never mentions it.
        return format!(
            "export type {stem}CallArgs<_S extends string> = [options?: CallOptions];\n"
        );
    }
    let widened_tuple = auth_options_tuple(auth_plan, full_rec);
    let mut out = String::new();
    let widened_branch;
    let required_terminal;
    if auth_plan.iter().all(|alternative| alternative.len() == 1) {
        // Single-member alternatives make the missing record identical to the full record, so one
        // S-independent `Req` tuple serves both the widened branch and every satisfied fall-through.
        out.push_str(&format!("type Req = {widened_tuple};\n"));
        widened_branch = "Req".to_owned();
        required_terminal = "Req".to_owned();
    } else {
        // A multi-member alternative makes the missing record depend on `S`, so it is factored into
        // a parameterized `Missing<S>`; the widened branch stays the concrete full record.
        let missing = auth_record_union(auth_plan, missing_rec);
        out.push_str(&format!("type Missing<S extends string> = {missing};\n"));
        widened_branch = widened_tuple;
        required_terminal = "[options: CallOptions & { auth: Missing<S> }]".to_owned();
    }
    let chain = call_args_chain(auth_plan, 0, &required_terminal);
    out.push_str(&format!(
        "export type {stem}CallArgs<S extends string> = [string] extends [S] ? {widened_branch} : {chain};\n"
    ));
    out
}

/// `[options: CallOptions & { auth: <render(A1)> | <render(A2)> | ... }]` over the alternatives.
fn auth_options_tuple(
    auth_plan: &[AuthAlternative],
    render: fn(&[AuthSchemeUse]) -> String,
) -> String {
    format!(
        "[options: CallOptions & {{ auth: {} }}]",
        auth_record_union(auth_plan, render)
    )
}

/// `<render(A1)> | <render(A2)> | ...` — the per-alternative auth record union.
fn auth_record_union(
    auth_plan: &[AuthAlternative],
    render: fn(&[AuthSchemeUse]) -> String,
) -> String {
    auth_plan
        .iter()
        .map(|alternative| render(alternative))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Every member required: `{ readonly <m1>: <Cred1>; readonly <m2>: <Cred2>; ... }`.
fn full_rec(alternative: &[AuthSchemeUse]) -> String {
    let properties = alternative
        .iter()
        .map(|scheme| {
            format!(
                "readonly {}: {}",
                render_property_key(&scheme.name),
                member_credential(&scheme.kind)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("{{ {properties} }}")
}

/// The minimal record `S` has not yet proven. A single member stays concrete (`full_rec`) — a
/// nested conditional there breaks assignability under an unconstrained `S`. Multiple members
/// intersect a per-member conditional so each name already in `S` becomes optional.
fn missing_rec(alternative: &[AuthSchemeUse]) -> String {
    if alternative.len() == 1 {
        return full_rec(alternative);
    }
    alternative
        .iter()
        .map(|scheme| {
            let credential = member_credential(&scheme.kind);
            format!(
                "([{literal} & S] extends [never] ? {{ readonly {key}: {credential} }} : {{ readonly {key}?: {credential} }})",
                literal = render_ts_string(&scheme.name),
                key = render_property_key(&scheme.name),
            )
        })
        .collect::<Vec<_>>()
        .join(" & ")
}

/// The credential type a caller supplies for one scheme in the per-call `auth` record.
fn member_credential(kind: &AuthKind) -> &'static str {
    match kind {
        AuthKind::Basic => "BasicCredential",
        AuthKind::HttpScheme { .. } => "{ credentials: string }",
        AuthKind::MutualTls => "typeof AmbientClientCertificate",
        AuthKind::ApiKeyCookie { .. } => "typeof AmbientCookieCredential",
        AuthKind::Bearer
        | AuthKind::ApiKeyHeader { .. }
        | AuthKind::ApiKeyQuery { .. }
        | AuthKind::OAuth2
        | AuthKind::OpenIdConnect => "string",
    }
}

/// Fold the alternatives first-to-last: each unproven member of `A[index]` falls through to the
/// check of `A[index + 1]`, an all-proven alternative yields optional options, and the final
/// fall-through past the last alternative is `required`.
fn call_args_chain(auth_plan: &[AuthAlternative], index: usize, required: &str) -> String {
    if index == auth_plan.len() {
        return required.to_owned();
    }
    let next = call_args_chain(auth_plan, index + 1, required);
    let next_is_conditional = index + 1 < auth_plan.len();
    call_args_member_chain(&auth_plan[index], 0, &next, next_is_conditional)
}

fn call_args_member_chain(
    members: &[AuthSchemeUse],
    index: usize,
    next: &str,
    next_is_conditional: bool,
) -> String {
    if index == members.len() {
        return "[options?: CallOptions]".to_owned();
    }
    let rest = call_args_member_chain(members, index + 1, next, next_is_conditional);
    let rendered_next = if next_is_conditional {
        format!("({next})")
    } else {
        next.to_owned()
    };
    format!(
        "[{} & S] extends [never] ? {rendered_next} : {rest}",
        render_ts_string(&members[index].name),
    )
}

/// Whether this module's `CallArgs` alias references the runtime credential types, deciding which
/// runtime imports the module needs.
fn call_args_credentials(plan: &OperationPlan, enforcement: AuthEnforcement) -> (bool, bool, bool) {
    if call_args_is_unconditional(&plan.auth_plan, enforcement) {
        return (false, false, false);
    }
    let mut basic = false;
    let mut cookie = false;
    let mut client_certificate = false;
    for alternative in &plan.auth_plan {
        for scheme in alternative {
            if matches!(scheme.kind, AuthKind::Basic) {
                basic = true;
            }
            if matches!(scheme.kind, AuthKind::ApiKeyCookie { .. }) {
                cookie = true;
            }
            if matches!(scheme.kind, AuthKind::MutualTls) {
                client_certificate = true;
            }
        }
    }
    (basic, cookie, client_certificate)
}

/// The descriptor `security` value: `[]` when unsecured, else a multi-line array whose entries are
/// the alternatives — `[]` for the anonymous option, else the ordered member objects.
/// An operation's security requirement, emitted as the resolver that satisfies it. Shipping the
/// resolver rather than the alternatives table is what keeps provider selection, RFC 6750 token
/// validation and RFC 7617 basic encoding out of an operation that declares no security at all —
/// `AuthResolver` in transport.ts carries the reasoning. An empty plan emits `null`, and nothing in
/// the auth pipeline is then reachable from the module.
fn security_field(auth_plan: &[AuthAlternative]) -> String {
    if auth_plan.is_empty() {
        return "null".to_owned();
    }
    let mut output = String::from("authAlternatives([\n");
    for alternative in auth_plan {
        output.push_str("    [");
        let members = alternative
            .iter()
            .map(render_security_member)
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&members);
        output.push_str("],\n");
    }
    output.push_str("  ])");
    output
}

fn render_security_member(scheme: &AuthSchemeUse) -> String {
    let mut member = String::from("{ name: ");
    member.push_str(&render_ts_string(&scheme.name));
    member.push_str(", apply: ");
    member.push_str(credential_applier_name(&scheme.kind));
    if let AuthKind::HttpScheme { scheme } = &scheme.kind {
        member.push_str(", scheme: ");
        member.push_str(&render_ts_string(scheme));
    }
    if let Some(param) = auth_kind_param(&scheme.kind) {
        member.push_str(", param: ");
        member.push_str(&render_ts_string(param));
    }
    member.push_str(", scopes: [");
    member.push_str(
        &scheme
            .scopes
            .iter()
            .map(|scope| render_ts_string(scope))
            .collect::<Vec<_>>()
            .join(", "),
    );
    member.push_str("] }");
    member
}

/// The runtime credential serializer each security scheme kind is emitted as. Carrying the applier
/// on the descriptor member rather than a `kind` tag is what keeps a bearer-only client from linking
/// RFC 7617 basic encoding and the rest; `SecurityUse` in transport.ts carries the reasoning. Bearer,
/// OAuth 2.0 and OpenID Connect serialize identically, so they share one applier.
fn credential_applier_name(kind: &AuthKind) -> &'static str {
    match kind {
        AuthKind::Basic => "basicCredential",
        AuthKind::Bearer | AuthKind::OAuth2 | AuthKind::OpenIdConnect => "bearerCredential",
        AuthKind::HttpScheme { .. } => "httpSchemeCredential",
        AuthKind::ApiKeyHeader { .. } => "headerKeyCredential",
        AuthKind::ApiKeyQuery { .. } => "queryKeyCredential",
        AuthKind::ApiKeyCookie { .. } => "cookieKeyCredential",
        AuthKind::MutualTls => "mutualTlsCredential",
    }
}

fn auth_kind_param(kind: &AuthKind) -> Option<&str> {
    match kind {
        AuthKind::ApiKeyHeader { name }
        | AuthKind::ApiKeyQuery { name }
        | AuthKind::ApiKeyCookie { name } => Some(name),
        AuthKind::Basic
        | AuthKind::Bearer
        | AuthKind::HttpScheme { .. }
        | AuthKind::MutualTls
        | AuthKind::OAuth2
        | AuthKind::OpenIdConnect => None,
    }
}

/// Every value an operation module can import from `runtime/transport`, in sorted order. The kernel
/// entry points sit inline among the body encoders because the whole list is written as one import
/// clause; keeping it a fixed sorted table rather than a collected set is what makes the clause
/// byte-stable across runs without allocating a set per module. `transport_value_imports_are_sorted`
/// pins the ordering.
const TRANSPORT_VALUE_IMPORTS: [&str; 17] = [
    "authAlternatives",
    "basicCredential",
    "bearerCredential",
    "binaryBody",
    "cookieKeyCredential",
    "discriminatedBody",
    "execute",
    "executeOrThrow",
    "headerKeyCredential",
    "httpSchemeCredential",
    "jsonBody",
    "multipartBody",
    "mutualTlsCredential",
    "queryKeyCredential",
    "streamBody",
    "textBody",
    "urlencodedBody",
];

/// The name's slot in `TRANSPORT_VALUE_IMPORTS`. Looked up rather than hand-numbered so adding an
/// import cannot silently renumber the others.
fn transport_import_index(name: &str) -> usize {
    // Callers pass either a literal from this table or `body_encoder_name`, whose match arms are
    // entries in the same table.
    TRANSPORT_VALUE_IMPORTS
        .iter()
        .position(|candidate| *candidate == name)
        .expect("every transport value import is listed in TRANSPORT_VALUE_IMPORTS")
}

/// The runtime encoder each body kind is emitted as. Shipping the encoder through the descriptor —
/// rather than a `kind` tag the transport would have to branch on — is what keeps an operation from
/// linking the body kinds it does not declare; `BodyEncoder` in transport.ts carries the reasoning.
fn body_encoder_name(plan: &BodyPlan) -> &'static str {
    match plan {
        BodyPlan::Json { .. } => "jsonBody",
        BodyPlan::TopLevelText { .. } => "textBody",
        BodyPlan::TopLevelBinary { .. } => "binaryBody",
        BodyPlan::TopLevelStream { .. } => "streamBody",
        BodyPlan::FormUrlencoded { .. } => "urlencodedBody",
        BodyPlan::Multipart { .. } => "multipartBody",
        BodyPlan::ContentTypeDiscriminated { .. } => "discriminatedBody",
    }
}

/// Marks every encoder an operation's body descriptor names, including the arm encoders a
/// content-discriminated body reaches.
fn mark_body_encoders(plan: &BodyPlan, wanted: &mut [bool; TRANSPORT_VALUE_IMPORTS.len()]) {
    wanted[transport_import_index(body_encoder_name(plan))] = true;
    if let BodyPlan::ContentTypeDiscriminated { arms, .. } = plan {
        for arm in arms {
            mark_body_encoders(&arm.plan, wanted);
        }
    }
}

fn write_body_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
    indent: usize,
) {
    match plan {
        BodyPlan::Json { media, .. }
        | BodyPlan::TopLevelText { media, .. }
        | BodyPlan::TopLevelBinary { media, .. }
        | BodyPlan::TopLevelStream { media, .. } => {
            write_simple_body(output, body_encoder_name(plan), media);
        }
        BodyPlan::FormUrlencoded { media, fields, .. } => {
            output.push_str("urlencodedBody(");
            output.push_str(&render_ts_string(media));
            output.push_str(", [\n");
            for field in fields {
                push_indent(output, indent + 2);
                output.push_str("{ name: ");
                output.push_str(&render_ts_string(&field.name));
                output.push_str(", required: ");
                output.push_str(if field.required { "true" } else { "false" });
                match &field.serialization {
                    FieldSerializationPlan::Style {
                        style,
                        explode,
                        allow_reserved,
                        ..
                    } => {
                        output.push_str(", style: ");
                        output.push_str(&render_ts_string(style_name(*style)));
                        output.push_str(", explode: ");
                        output.push_str(if *explode { "true" } else { "false" });
                        output.push_str(", allowReserved: ");
                        output.push_str(if *allow_reserved { "true" } else { "false" });
                    }
                    FieldSerializationPlan::Content {
                        media: part_media, ..
                    } => {
                        // A wrapped field carries the caller-selected media set; every content field
                        // carries per-media payload kinds so the descriptor is self-describing and
                        // never silently falls back to style serialization. The inner binding is the
                        // field's `PartMediaPlan`, distinct from the outer body-level `media` string.
                        if field.wrapper.wrapped {
                            output.push_str(", contentType: ");
                            write_selected_content_type(output, part_media);
                        }
                        output.push_str(", ");
                        write_payloads_array(output, part_media);
                    }
                }
                output.push_str(" },\n");
            }
            push_indent(output, indent);
            output.push_str("])");
        }
        BodyPlan::Multipart { fields, .. } => {
            output.push_str("multipartBody([\n");
            for field in fields {
                write_multipart_field(output, model, field, indent + 2);
            }
            push_indent(output, indent);
            output.push_str("])");
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            output.push_str("discriminatedBody([\n");
            for arm in arms {
                push_indent(output, indent + 2);
                output.push('[');
                output.push_str(&render_ts_string(&arm.media));
                output.push_str(", ");
                write_body_descriptor(output, model, &arm.plan, indent + 2);
                output.push_str("],\n");
            }
            push_indent(output, indent);
            output.push_str("])");
        }
    }
}

/// Renders `payloads: [...]` — the wire payload kind of each admitted media type, index-for-index
/// with the `admitted` list. The runtime picks `payloads[selected.index]` so the part Content-Type
/// and the body serialization agree on a non-first selection. The urlencoded body descriptor's
/// Content arm and the multipart field descriptor's wrapped arm both need this exact rendering.
fn write_payloads_array(output: &mut String, media: &PartMediaPlan) {
    output.push_str("payloads: [");
    output.push_str(
        &media
            .payloads
            .iter()
            .map(|payload| render_ts_string(payload.as_str()))
            .collect::<Vec<_>>()
            .join(", "),
    );
    output.push(']');
}

/// Renders `{ kind: "selected", admitted: [...] }` — the descriptor for a wrapped field whose
/// caller may pick any of `media`'s content types at call time. The urlencoded body descriptor's
/// Content arm and the multipart field descriptor's wrapped arm both need this exact rendering.
fn write_selected_content_type(output: &mut String, media: &PartMediaPlan) {
    output.push_str("{ kind: \"selected\", admitted: [");
    output.push_str(
        &media
            .values
            .iter()
            .map(|value| render_ts_string(value))
            .collect::<Vec<_>>()
            .join(", "),
    );
    output.push_str("] }");
}

fn write_simple_body(output: &mut String, encoder: &str, media: &str) {
    output.push_str(encoder);
    output.push('(');
    output.push_str(&render_ts_string(media));
    output.push(')');
}

fn write_multipart_field(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    field: &FormFieldPlan,
    indent: usize,
) {
    push_indent(output, indent);
    output.push_str("{ name: ");
    output.push_str(&render_ts_string(&field.name));
    output.push_str(", required: ");
    output.push_str(if field.required { "true" } else { "false" });
    output.push_str(", repeated: ");
    output.push_str(if form_field_render_schema(model, field).repeated {
        "true"
    } else {
        "false"
    });
    output.push_str(", wrapper: ");
    output.push_str(if field.wrapper.wrapped {
        "true"
    } else {
        "false"
    });
    output.push_str(", payload: ");
    output.push_str(&render_ts_string(field_payload(field)));
    output.push_str(", contentType: ");
    match &field.serialization {
        FieldSerializationPlan::Style { .. } => output.push_str("{ kind: \"none\" }"),
        FieldSerializationPlan::Content { media, .. } if field.wrapper.wrapped => {
            // A wrapped part admits caller media selection, so ship the index-aligned payload kinds:
            // the runtime picks payloads[selected.index], keeping the part Content-Type and the body
            // serialization from disagreeing on a non-first selection. The single `payload` above
            // stays for the style and non-wrapped fixed cases, which have exactly one payload kind.
            write_selected_content_type(output, media);
            output.push_str(", ");
            write_payloads_array(output, media);
        }
        FieldSerializationPlan::Content { media, .. } => {
            output.push_str("{ kind: \"fixed\", value: ");
            // Content planning rejects an empty media selection before emission.
            output.push_str(&render_ts_string(
                media
                    .values
                    .first()
                    .expect("content-based fields have a media value"),
            ));
            output.push_str(" }");
        }
    }
    output.push_str(", filename: ");
    output.push_str(if field.wrapper.filename {
        "true"
    } else {
        "false"
    });
    output.push_str(" },\n");
}

fn schema_array_items<'a>(
    model: &'a EmissionModel<'_, '_>,
    schema: &'a SchemaNode,
    visited: &mut HashSet<(String, String)>,
) -> Option<&'a SchemaNode> {
    match schema {
        SchemaNode::Array { items, .. } => Some(items),
        SchemaNode::Ref { target, .. } => {
            let key = (target.source_id.clone(), target.json_pointer.clone());
            if !visited.insert(key) {
                return None;
            }
            model
                .schema_target(&target.source_id, &target.json_pointer)
                .and_then(|target| model.analyzed.ir.schemas.get(target.index))
                .and_then(|target| schema_array_items(model, &target.schema, visited))
        }
        SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Object { .. }
        | SchemaNode::Tuple { .. }
        | SchemaNode::AllOf { .. }
        | SchemaNode::OneOf { .. }
        | SchemaNode::AnyOf { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => None,
    }
}

fn field_payload(field: &FormFieldPlan) -> &'static str {
    match &field.serialization {
        FieldSerializationPlan::Content { media, .. } => media_payload(media),
        FieldSerializationPlan::Style { .. } => match &field.schema {
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                format: Some(format),
                ..
            } if format == "binary" => "binary",
            SchemaNode::Object { .. } | SchemaNode::Tuple { .. } => "json",
            SchemaNode::Ref { .. }
            | SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Array { .. }
            | SchemaNode::AllOf { .. }
            | SchemaNode::OneOf { .. }
            | SchemaNode::AnyOf { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => "text",
        },
    }
}

fn media_payload(media: &PartMediaPlan) -> &'static str {
    match media.payloads.first() {
        Some(PayloadKind::Json) => "json",
        Some(PayloadKind::Text) => "text",
        Some(PayloadKind::Binary) | None => "binary",
    }
}

fn write_base_url(output: &mut String, plan: &BaseUrlPlan) {
    match plan {
        BaseUrlPlan::Runtime => output.push_str("{ kind: \"runtime\" }"),
        BaseUrlPlan::Literal { value } => {
            output.push_str("{ kind: \"literal\", value: ");
            output.push_str(&render_ts_string(value));
            output.push_str(" }");
        }
        BaseUrlPlan::Server { index, servers } => {
            output.push_str("{ kind: \"server\", index: ");
            output.push_str(&index.to_string());
            output.push_str(", servers: [");
            output.push_str(
                &servers
                    .iter()
                    .map(|server| {
                        format!(
                            "{{ url: {}, variables: [{}] }}",
                            render_ts_string(&server.url),
                            server
                                .variables
                                .iter()
                                .map(|(name, variable)| format!(
                                    "[{}, {}]",
                                    render_ts_string(name),
                                    render_ts_string(&variable.default)
                                ))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            output.push_str("] }");
        }
    }
}

fn write_fetch_defaults(output: &mut String, defaults: &FetchDefaults) {
    let mut fields = Vec::new();
    if let Some(value) = defaults.credentials {
        fields.push(format!(
            "credentials: {}",
            render_ts_string(match value {
                CredentialsMode::Omit => "omit",
                CredentialsMode::SameOrigin => "same-origin",
                CredentialsMode::Include => "include",
            })
        ));
    }
    if let Some(value) = defaults.cache {
        fields.push(format!(
            "cache: {}",
            render_ts_string(match value {
                CacheMode::Default => "default",
                CacheMode::NoStore => "no-store",
                CacheMode::Reload => "reload",
                CacheMode::NoCache => "no-cache",
                CacheMode::ForceCache => "force-cache",
                CacheMode::OnlyIfCached => "only-if-cached",
            })
        ));
    }
    if let Some(value) = defaults.redirect {
        fields.push(format!(
            "redirect: {}",
            render_ts_string(match value {
                RedirectMode::Follow => "follow",
                RedirectMode::Error => "error",
                RedirectMode::Manual => "manual",
            })
        ));
    }
    if let Some(value) = defaults.referrer_policy {
        fields.push(format!(
            "referrerPolicy: {}",
            render_ts_string(match value {
                ReferrerPolicyValue::NoReferrer => "no-referrer",
                ReferrerPolicyValue::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
                ReferrerPolicyValue::SameOrigin => "same-origin",
                ReferrerPolicyValue::Origin => "origin",
                ReferrerPolicyValue::StrictOrigin => "strict-origin",
                ReferrerPolicyValue::OriginWhenCrossOrigin => "origin-when-cross-origin",
                ReferrerPolicyValue::StrictOriginWhenCrossOrigin => {
                    "strict-origin-when-cross-origin"
                }
                ReferrerPolicyValue::UnsafeUrl => "unsafe-url",
            })
        ));
    }
    if let Some(value) = defaults.mode {
        fields.push(format!(
            "mode: {}",
            render_ts_string(match value {
                RequestModeValue::Cors => "cors",
                RequestModeValue::NoCors => "no-cors",
                RequestModeValue::SameOrigin => "same-origin",
            })
        ));
    }
    if let Some(value) = defaults.keepalive {
        fields.push(format!("keepalive: {value}"));
    }
    if fields.is_empty() {
        output.push_str("{}");
    } else {
        output.push_str("{ ");
        output.push_str(&fields.join(", "));
        output.push_str(" }");
    }
}

fn style_name(style: ParamStyle) -> &'static str {
    match style {
        ParamStyle::Form => "form",
        ParamStyle::Simple => "simple",
        ParamStyle::Label => "label",
        ParamStyle::Matrix => "matrix",
        ParamStyle::SpaceDelimited => "spaceDelimited",
        ParamStyle::PipeDelimited => "pipeDelimited",
        ParamStyle::DeepObject => "deepObject",
    }
}

/// The descriptor's decoder slot for one media entry: a tag string for the three built-in decoders,
/// and for multipart the decoder function itself alongside its plan. Shipping the function through
/// the descriptor rather than tagging it is what keeps the parser out of every other client — the
/// transport never names it, so nothing but a multipart operation module pulls it in.
fn render_response_decoder(
    media: &ResponseMediaPlan,
    on_event: Option<&str>,
    int64_reviver: Option<&str>,
) -> String {
    // A streaming entry ships its reader the same way, and for the same reason: the transport never
    // names the SSE parser, so only an operation that declares one links it. `onEvent` is the
    // per-event validate-and-convert pipeline; it is null until a later step binds one, and the
    // runtime skips per-event checking when it is.
    match media.decoder {
        DecoderClass::StreamingSse => {
            return format!(
                "{{ sse: {SSE_DECODER}, onEvent: {} }}",
                on_event.unwrap_or("null")
            );
        }
        DecoderClass::StreamingRaw => return format!("{{ raw: {RAW_STREAM_READER} }}"),
        _ => {}
    }
    if let Some(reviver) = int64_reviver {
        return format!("{{ json: \"int64\", revive: {reviver} }}");
    }
    let Some(plan) = &media.multipart else {
        return render_ts_string(decoder_name(media.decoder));
    };
    let parts = plan
        .parts
        .iter()
        .map(|part| {
            format!(
                "{{ name: {}, {} }}",
                render_ts_string(&part.name),
                render_multipart_shape(&part.shape)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ decode: {MULTIPART_RESPONSE_DECODER}, plan: {{ parts: [{parts}], additional: {{ {} }} }} }}",
        render_multipart_shape(&plan.additional)
    )
}

fn render_multipart_shape(shape: &MultipartResponseShape) -> String {
    format!(
        "payload: {}, repeated: {}",
        render_ts_string(shape.payload.as_str()),
        if shape.repeated { "true" } else { "false" }
    )
}

fn decoder_name(decoder: DecoderClass) -> &'static str {
    match decoder {
        DecoderClass::Json => "json",
        DecoderClass::Text => "text",
        DecoderClass::Binary => "binary",
        DecoderClass::StreamingSse
        | DecoderClass::StreamingRaw
        | DecoderClass::Xml
        | DecoderClass::Multipart
        | DecoderClass::MultipartUnnamed => {
            unreachable!(
                "multipart entries carry a plan, and undecodable media are diagnosed before emission"
            )
        }
    }
}

fn helper_region_id(helper: HelperId) -> &'static str {
    match helper {
        HelperId::PathSimple => "path-simple",
        HelperId::PathSimpleExplode => "path-simple-explode",
        HelperId::PathLabel => "path-label",
        HelperId::PathLabelExplode => "path-label-explode",
        HelperId::PathMatrix => "path-matrix",
        HelperId::PathMatrixExplode => "path-matrix-explode",
        HelperId::QueryForm => "query-form",
        HelperId::QueryFormExplode => "query-form-explode",
        HelperId::QuerySpaceDelimited => "query-space-delimited",
        HelperId::QuerySpaceDelimitedObject => "query-space-delimited-object",
        HelperId::QueryPipeDelimited => "query-pipe-delimited",
        HelperId::QueryPipeDelimitedObject => "query-pipe-delimited-object",
        HelperId::QueryDeepObject => "query-deep-object",
        HelperId::QueryDeepObjectExtended => "query-deep-object-extended",
        HelperId::HeaderSimple => "header-simple",
        HelperId::HeaderSimpleExplode => "header-simple-explode",
        HelperId::ContentJsonPath => "content-json-path",
        HelperId::ContentJsonQuery => "content-json-query",
        HelperId::ContentJsonHeader => "content-json-header",
    }
}

/// The `serialize.ts` region holding the multipart response decoder, and the name it exports.
const MULTIPART_RESPONSE_REGION: &str = "multipart-response";
const MULTIPART_RESPONSE_DECODER: &str = "decodeMultipartResponse";

/// The two streaming regions and their exports. `sse-decode` builds on `stream-raw`'s saturating
/// progress counter, so selecting the first always selects the second; a raw-only client selects
/// `stream-raw` alone and never carries the event parser.
const SSE_DECODE_REGION: &str = "sse-decode";
const SSE_DECODER: &str = "decodeSseStream";
/// The frame encoder is the caller's half of a streaming request body: the input is a byte stream,
/// and this is what turns typed events into one. It is emitted for the operations that document
/// that pairing and for no others — the generated module never imports it, the caller does.
const SSE_ENCODE_REGION: &str = "sse-encode";
const RAW_STREAM_REGION: &str = "stream-raw";
const RAW_STREAM_READER: &str = "readRawStream";

fn response_decodes_multipart(response: &ResponsePlan) -> bool {
    matches!(response.payload, PayloadDisposition::Payload)
        && response.media.iter().any(|media| media.multipart.is_some())
}

/// Whether a branch actually creates a stream handle. A statically bodyless branch never does,
/// however its media is declared — the type says `undefined` because that is what the runtime
/// delivers — so it must not drag the streaming regions in either.
fn response_streams(response: &ResponsePlan, kind: DecoderClass) -> bool {
    matches!(response.payload, PayloadDisposition::Payload)
        && response.media.iter().any(|media| media.decoder == kind)
}

/// Whether any arm of this body sends `text/event-stream`. Checked arm by arm, because a caller
/// picking that arm out of several needs the encoder just as much as one with no choice.
fn body_sends_event_stream(plan: &BodyPlan) -> bool {
    match plan {
        BodyPlan::TopLevelStream { media, .. } => media_essence(media) == "text/event-stream",
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            arms.iter().any(|arm| body_sends_event_stream(&arm.plan))
        }
        BodyPlan::Json { .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => false,
    }
}

fn plan_decodes_sse(plan: &OperationPlan) -> bool {
    plan.response_table
        .iter()
        .any(|response| response_streams(response, DecoderClass::StreamingSse))
}

fn plan_reads_raw_stream(plan: &OperationPlan) -> bool {
    plan.response_table
        .iter()
        .any(|response| response_streams(response, DecoderClass::StreamingRaw))
}

/// Whether a response branch renders its payload type in the operation module instead of reading
/// the types artifact's status-wide alias. Content-type-discriminated branches always do (one arm
/// per media entry); a multipart branch does because the decoded object type is a client-side
/// notion the types artifact does not render — the same split multipart *request* bodies already
/// take, where the types artifact says `unknown` and `render_form_input` owns the real shape.
pub(super) fn renders_payload_inline(response: &ResponsePlan) -> bool {
    response.content_type_discriminated || response_decodes_multipart(response)
}

fn helper_export_name(helper: HelperId) -> &'static str {
    match helper {
        HelperId::PathSimple => "serializePathSimple",
        HelperId::PathSimpleExplode => "serializePathSimpleExplode",
        HelperId::PathLabel => "serializePathLabel",
        HelperId::PathLabelExplode => "serializePathLabelExplode",
        HelperId::PathMatrix => "serializePathMatrix",
        HelperId::PathMatrixExplode => "serializePathMatrixExplode",
        HelperId::QueryForm => "serializeQueryForm",
        HelperId::QueryFormExplode => "serializeQueryFormExplode",
        HelperId::QuerySpaceDelimited => "serializeQuerySpaceDelimited",
        HelperId::QuerySpaceDelimitedObject => "serializeQuerySpaceDelimitedObject",
        HelperId::QueryPipeDelimited => "serializeQueryPipeDelimited",
        HelperId::QueryPipeDelimitedObject => "serializeQueryPipeDelimitedObject",
        HelperId::QueryDeepObject => "serializeQueryDeepObject",
        HelperId::QueryDeepObjectExtended => "serializeQueryDeepObjectExtended",
        HelperId::HeaderSimple => "serializeHeaderSimple",
        HelperId::HeaderSimpleExplode => "serializeHeaderSimpleExplode",
        HelperId::ContentJsonPath => "serializeContentJsonPath",
        HelperId::ContentJsonQuery => "serializeContentJsonQuery",
        HelperId::ContentJsonHeader => "serializeContentJsonHeader",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::client_model::{
        FieldWrapperPlan, PayloadKind, ResponseMediaPlan, build_client_model,
    };
    use crate::config::{ResolvedConfig, load_config_from_json};
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::emit::emit_artifacts;
    use crate::ir::{
        AdditionalProperties, SchemaMeta, SchemaRef, ServerEntry, ServerVariable, SourceRef,
    };
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::{Analyzed, analyze};

    fn analyzed(document: &Value) -> (TempDir, Analyzed, ResolvedConfig, Vec<(String, [u8; 32])>) {
        analyzed_with_aggregate(document, false)
    }

    fn analyzed_with_aggregate(
        document: &Value,
        aggregate: bool,
    ) -> (TempDir, Analyzed, ResolvedConfig, Vec<(String, [u8; 32])>) {
        analyzed_with_options(document, aggregate, false)
    }

    fn analyzed_with_options(
        document: &Value,
        aggregate: bool,
        documentation_enabled: bool,
    ) -> (TempDir, Analyzed, ResolvedConfig, Vec<(String, [u8; 32])>) {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec_pretty(document).expect("document JSON"),
        )
        .expect("document");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": {
                "authEnforcement": "types",
                "aggregate": aggregate,
                "baseUrl": { "source": "literal", "value": "https://api.example.test/v1" }
            },
            "validation": { "engine": "off", "unchecked": "allow" },
            "documentation": { "enabled": documentation_enabled }
        });
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("graph");
        let source_tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("IR");
        let analyzed = analyze(ir, &config, &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        (temp, analyzed, config, source_tuples)
    }

    fn emit_operation(document: Value, suffix: &str) -> (String, Vec<Diagnostic>) {
        emit_operation_with_documentation(document, suffix, false)
    }

    fn emit_operation_with_documentation(
        document: Value,
        suffix: &str,
        documentation_enabled: bool,
    ) -> (String, Vec<Diagnostic>) {
        let (_temp, analyzed, config, _source_tuples) =
            analyzed_with_options(&document, false, documentation_enabled);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        let content = files
            .iter()
            .find(|file| file.relative_path == format!("client/operations/{suffix}.ts"))
            .expect("operation file")
            .content
            .clone();
        (content, sink.into_sorted_vec())
    }

    /// The same emission under a configured `dateTime: date` representation, which is the only way
    /// to make any position reach the transform layer.
    fn emit_transforming_operation(document: Value, suffix: &str) -> (String, Vec<Diagnostic>) {
        let (files, diagnostics) = emit_transforming_files(document, false);
        let content = files
            .into_iter()
            .find(|file| file.relative_path == format!("client/operations/{suffix}.ts"))
            .expect("operation file")
            .content;
        (content, diagnostics)
    }

    /// Every client file the transforming emission writes, with response validation on or off. The
    /// two per-event halves are independent switches, so a test that means to observe one wrapper
    /// carrying both has to turn the other on.
    fn emit_transforming_files(
        document: Value,
        validate: bool,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        emit_files_with_types(document, validate, json!({ "dateTime": "date" }))
    }

    fn emit_files_with_types(
        document: Value,
        validate: bool,
        types: Value,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec_pretty(&document).expect("document JSON"),
        )
        .expect("document");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated",
            "artifacts": { "types": true, "client": true, "validators": validate },
            "client": {
                "authEnforcement": "types",
                "baseUrl": { "source": "literal", "value": "https://api.example.test/v1" }
            },
            "types": types,
            "validation": if validate {
                json!({ "engine": "generated", "request": true, "response": true, "unchecked": "allow" })
            } else {
                json!({ "engine": "off", "unchecked": "allow" })
            }
        });
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("graph");
        let ir = parse(&graph, &mut sink).expect("IR");
        let analyzed = analyze(ir, &config, &mut sink);
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        (files, sink.into_sorted_vec())
    }

    /// One operation returning a component whose only property converts.
    fn transforming_response_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "T", "version": "1.0.0" },
            "paths": {
                "/events": {
                    "get": {
                        "operationId": "readEvent",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Event" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "required": ["at"],
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }
            }
        })
    }

    fn transforming_int64_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "T", "version": "1.0.0" },
            "paths": {
                "/counters": {
                    "get": {
                        "operationId": "readCounter",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["id"],
                                            "properties": {
                                                "id": { "type": "integer", "format": "int64" }
                                            }
                                        }
                                    },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn only_an_int64_bigint_response_marks_its_json_decoder_lossless() {
        let (files, diagnostics) = emit_files_with_types(
            transforming_int64_document(),
            false,
            json!({ "integer": "bigint" }),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let bigint = operation_file(&files, "readcounter");
        assert!(
            bigint.contains("media: [[\"application/json\", { json: \"int64\", revive: reviveReadCounterResponse200ApplicationJson }], [\"text/plain\", \"text\"]], hasContentTypeDiscriminant: true"),
            "{bigint}"
        );

        let (date, diagnostics) =
            emit_transforming_operation(transforming_response_document(), "readevent");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            date.contains("media: [[\"application/json\", \"json\"]]"),
            "{date}"
        );
    }

    #[test]
    fn a_bodyless_int64_json_response_does_not_bind_a_reviver() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "T", "version": "1.0.0" },
            "paths": {
                "/counters": {
                    "get": {
                        "operationId": "readCounter",
                        "responses": {
                            "204": {
                                "description": "empty",
                                "content": {
                                    "application/json": {
                                        "schema": { "type": "integer", "format": "int64" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) =
            emit_files_with_types(document, false, json!({ "integer": "bigint" }));
        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>(),
            ["OASTS5204"]
        );
        let operation = operation_file(&files, "readcounter");
        assert!(
            operation.contains(
                "bodyless: true, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false"
            ),
            "{operation}"
        );
    }

    #[test]
    fn a_converting_response_decodes_after_execute() {
        let (content, _) =
            emit_transforming_operation(transforming_response_document(), "readevent");

        assert!(
            content.contains(
                "import { decodeReadEventResponse200 } from \"../transform/operations/readevent.js\";\n"
            ),
            "the operation module should import its response decoder: {content}"
        );
        assert!(
            content.contains(
                "  const result = await execute<ReadEventResultWire>(transport, descriptor, input, args[0]);\n"
            ),
            "execute should be typed on the pre-conversion surface: {content}"
        );
        assert!(
            content.contains(
                "      return { ...result, data: decodeReadEventResponse200(result.data) };\n"
            ),
            "the success arm should convert its payload: {content}"
        );
        assert!(
            content.contains(
                "        return { outcome: \"response-transform\", ok: false, match: result.outcome, status: result.status, error, meta: result.meta };\n"
            ),
            "a rejected decode should surface as a response-transform arm: {content}"
        );
    }

    #[test]
    fn a_converting_request_encodes_before_execute() {
        let mut document = transforming_response_document();
        document["paths"]["/events"]["get"]["parameters"] = json!([{
            "name": "since",
            "in": "query",
            "required": true,
            "schema": { "type": "string", "format": "date-time" }
        }]);
        let (content, _) = emit_transforming_operation(document, "readevent");

        assert!(
            content.contains(
                "import { decodeReadEventResponse200, encodeReadEventInput } from \"../transform/operations/readevent.js\";\n"
            ),
            "the operation module should import its input encoder: {content}"
        );
        assert!(
            content.contains("export type ReadEventInputWire = {"),
            "the pre-serialization input surface should be declared: {content}"
        );
        let encode = content
            .find("encodeReadEventInput(input)")
            .expect("the input encoder should be called");
        let execute = content
            .find("await execute<ReadEventResultWire>")
            .expect("execute should still be called");
        assert!(
            encode < execute,
            "the input must be encoded before execute serializes it: {content}"
        );
        assert!(
            content
                .contains("      return { outcome: \"request-transform\", ok: false, error };\n"),
            "a rejected encode should surface as a request-transform arm: {content}"
        );
        assert!(
            content.contains(
                "  const result = await execute<ReadEventResultWire>(transport, descriptor, wire, args[0]);\n"
            ),
            "execute should receive the encoded input, not the caller's: {content}"
        );
    }

    #[test]
    fn a_non_json_response_binds_no_codec() {
        // `text/plain` stays a string on both surfaces, so the types artifact declares no wire twin
        // and the transform artifact emits no decoder — binding one here would import two symbols
        // that were never emitted.
        let (content, _) = emit_transforming_operation(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "T", "version": "1.0.0" },
                "paths": {
                    "/events": {
                        "post": {
                            "operationId": "readEvent",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "text/plain": {
                                            "schema": { "type": "string", "format": "date-time" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
            "readevent",
        );

        assert!(!content.contains("../transform/operations/"), "{content}");
        assert!(!content.contains("ResultWire"), "{content}");
    }

    /// The showcase document's shape, with the response table swapped in per test.
    fn transforming_document(responses: Value) -> Value {
        let operation = json!({ "operationId": "readEvent", "responses": responses });
        json!({
            "openapi": "3.1.0",
            "info": { "title": "T", "version": "1.0.0" },
            "paths": { "/events": { "post": operation } },
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "required": ["at"],
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }
            }
        })
    }

    fn json_event_response(description: &str) -> Value {
        json!({
            "description": description,
            "content": {
                "application/json": { "schema": { "$ref": "#/components/schemas/Event" } }
            }
        })
    }

    #[test]
    fn a_converting_error_branch_decodes_the_error_field() {
        let (content, _) = emit_transforming_operation(
            transforming_document(json!({ "404": json_event_response("gone") })),
            "readevent",
        );

        assert!(
            content.contains(
                "      return { ...result, error: decodeReadEventResponse404(result.error) };\n"
            ),
            "an error branch converts the error field, not data: {content}"
        );
    }

    #[test]
    fn a_converting_default_branch_decodes_whichever_field_carries_the_body() {
        let (content, _) = emit_transforming_operation(
            transforming_document(json!({ "default": json_event_response("any") })),
            "readevent",
        );

        // `default` spans both outcomes, so the field is chosen at runtime rather than at emit time.
        assert!(
            content.contains("      return result.ok\n")
                && content.contains(
                    "        ? { ...result, data: decodeReadEventResponseDefault(result.data) }\n"
                )
                && content.contains(
                    "        : { ...result, error: decodeReadEventResponseDefault(result.error) };\n"
                ),
            "{content}"
        );
    }

    fn tsdoc_blocks(source: &str) -> String {
        let mut blocks = Vec::new();
        let mut rest = source;
        while let Some((_, after_start)) = rest.split_once("/**\n") {
            let (body, after_end) = after_start.split_once(" */\n").expect("closed TSDoc");
            blocks.push(format!("/**\n{body} */\n"));
            rest = after_end;
        }
        blocks.join("\n")
    }

    // Assembled from the same version the emitter reads, so a release bump is one edit in
    // Cargo.toml rather than a sweep through every snapshot in this file.
    const HEADER: &str = concat!(
        "// Generated by Oasts ",
        env!("CARGO_PKG_VERSION"),
        ". Do not edit.\n// Config schema version: 1\n// Source digest: digest\n\n"
    );

    #[test]
    fn dropped_cookie_header_never_appears_in_optional_or_required_call_inputs() {
        for required in [false, true] {
            let document = json!({
                "openapi": "3.1.0",
                "info": { "title": "test", "version": "1" },
                "paths": {
                    "/cookie-header": {
                        "get": {
                            "operationId": "cookieHeader",
                            "parameters": [{
                                "name": "Cookie",
                                "in": "header",
                                "required": required,
                                "schema": { "type": "string" }
                            }],
                            "responses": { "204": { "description": "empty" } }
                        }
                    }
                }
            });
            let (content, diagnostics) = emit_operation(document, "cookieheader");

            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| {
                        diagnostic.code == "OASTS5001"
                            && diagnostic.severity == crate::diag::Severity::Warning
                    })
                    .count(),
                1,
                "{diagnostics:#?}"
            );
            assert!(content.contains("export type CookieHeaderInput = {};"));
            assert!(content.contains("params: [],"));
            assert!(content.contains(
                "export async function cookieHeader<S extends string = never>(transport: Transport<S>, input: CookieHeaderInput,"
            ));
            assert!(!content.contains("Cookie:"));
            assert!(!content.contains("name: \"Cookie\""));
        }
    }

    #[test]
    fn content_parameters_emit_typed_and_caller_serialized_inputs() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/search": {
                    "get": {
                        "operationId": "search",
                        "parameters": [
                            {
                                "name": "filter",
                                "in": "query",
                                "content": { "application/json": { "schema": {
                                    "type": "object",
                                    "properties": { "tag": { "type": "string" } }
                                } } }
                            },
                            {
                                "name": "doc",
                                "in": "query",
                                "content": { "application/xml": { "schema": { "type": "object" } } }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "search");
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error),
            "{diagnostics:#?}"
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS5006")
                .count(),
            1,
        );
        // The JSON content serializer is imported and its descriptor entry flags `content: true`.
        assert!(content.contains("serializeContentJsonQuery"), "{content}");
        assert!(
            content.contains(
                "{ name: \"filter\", location: \"query\", required: false, serialize: serializeContentJsonQuery, allowReserved: false, content: true },"
            ),
            "{content}"
        );
        // The caller-serialized XML parameter forwards through the location default helper unflagged.
        assert!(
            content.contains(
                "{ name: \"doc\", location: \"query\", required: false, serialize: serializeQueryForm, allowReserved: false },"
            ),
            "{content}"
        );
        // Input types: the JSON parameter stays typed; the XML parameter becomes a bare string.
        assert!(content.contains("filter?: {"), "{content}");
        assert!(content.contains("tag?: string;"), "{content}");
        assert!(content.contains("doc?: string;"), "{content}");
    }

    #[test]
    fn delimited_object_parameters_import_object_serializers() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/colors": {
                    "get": {
                        "operationId": "getColors",
                        "parameters": [
                            {
                                "name": "space",
                                "in": "query",
                                "style": "spaceDelimited",
                                "explode": false,
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": { "type": "string" }
                                }
                            },
                            {
                                "name": "pipe",
                                "in": "query",
                                "style": "pipeDelimited",
                                "explode": false,
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": { "type": "string" }
                                }
                            }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });

        let (actual, diagnostics) = emit_operation(document, "getcolors");
        assert!(
            actual.contains(
                "import { serializeQueryPipeDelimitedObject, serializeQuerySpaceDelimitedObject } from \"../../runtime/serialize.js\";"
            ),
            "{actual}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn json_get_operation_module_snapshot() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPet",
                        "parameters": [
                            { "name": "petId", "in": "path", "required": true, "description": "The pet identifier.", "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "description": "The result limit.", "schema": { "type": "integer" } }
                        ],
                        "responses": {
                            "200": {
                                "description": "found",
                                "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } }
                            },
                            "default": {
                                "description": "fallback",
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Pet": {
                        "type": "object",
                        "required": ["id"],
                        "properties": { "id": { "type": "string" } }
                    }
                }
            }
        });
        let expected = format!(
            "{HEADER}import type {{ GetPetResponse200, GetPetResponseDefault }} from \"../../types/operations/getpet.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ serializePathSimple, serializeQueryFormExplode }} from \"../../runtime/serialize.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetInput = {{\n  /**\n   * The pet identifier.\n   */\n  petId: string;\n  /**\n   * The result limit.\n   */\n  limit?: number;\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetResult =\n  | {{ outcome: 200; ok: true; status: 200; data: GetPetResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"default\"; ok: true; status: number; data: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ outcome: \"default\"; ok: false; status: number; error: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200 | \"default\">\n  | RequestPhaseFailure;\n\nexport type GetPetCallArgs<_S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\nconst descriptor: OperationDescriptor = {{\n  operationId: \"getPet\",\n  method: \"GET\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"pets\" }}],\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"param\", name: \"petId\" }}],\n  ],\n  params: [\n    {{ name: \"petId\", location: \"path\", required: true, serialize: serializePathSimple, allowReserved: false }},\n    {{ name: \"limit\", location: \"query\", required: false, serialize: serializeQueryFormExplode, allowReserved: false }},\n  ],\n  body: null,\n  accept: \"application/json\",\n  credentialHeaders: [\"authorization\"],\n  security: null,\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n    {{ match: \"default\", kind: \"default\", status: null, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function getPet<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<GetPetResult> {{\n  return execute<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function getPetOrThrow<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<{{ data: GetPetResponse200; meta: ResponseMeta }} | {{ data: GetPetResponseDefault; meta: ResponseMeta }}> {{\n  return executeOrThrow<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let expected = expected.replace(
            "export type GetPetInput = {\n  /**\n   * The pet identifier.\n   */\n  petId: string;\n  /**\n   * The result limit.\n   */\n  limit?: number;\n};",
            "export type GetPetInput = {\n  path: {\n    /**\n     * The pet identifier.\n     */\n    petId: string;\n  };\n  query?: {\n    /**\n     * The result limit.\n     */\n    limit?: number;\n  };\n};",
        );
        let (actual, diagnostics) = emit_operation_with_documentation(document, "getpet", true);
        assert_eq!(actual, expected);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn multipart_operation_module_snapshot() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/uploads": {
                    "post": {
                        "operationId": "uploadAsset",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["meta", "title", "file"],
                                        "properties": {
                                            "meta": { "type": "object", "properties": { "tag": { "type": "string" } } },
                                            "title": { "type": "string" },
                                            "file": { "type": "string", "format": "binary" }
                                        }
                                    },
                                    "encoding": {
                                        "meta": { "contentType": "application/json, application/cbor" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "stored" } }
                    }
                }
            }
        });
        let expected = format!(
            "{HEADER}import type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, multipartBody, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetInput = {{\n  body: {{\n    meta: {{ body: {{\n      tag?: string;\n    }}; contentType: \"application/json\" | \"application/cbor\" }};\n    title: string;\n    file: Blob | File;\n  }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetResult =\n  | {{ outcome: 204; ok: true; status: 204; data: undefined; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<204>\n  | RequestPhaseFailure;\n\nexport type UploadAssetCallArgs<_S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"uploadAsset\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"uploads\" }}],\n  ],\n  params: [],\n  body: multipartBody([\n    {{ name: \"meta\", required: true, repeated: false, wrapper: true, payload: \"json\", contentType: {{ kind: \"selected\", admitted: [\"application/json\", \"application/cbor\"] }}, payloads: [\"json\", \"json\"], filename: false }},\n    {{ name: \"title\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: {{ kind: \"fixed\", value: \"text/plain\" }}, filename: false }},\n    {{ name: \"file\", required: true, repeated: false, wrapper: false, payload: \"binary\", contentType: {{ kind: \"fixed\", value: \"application/octet-stream\" }}, filename: true }},\n  ]),\n  accept: null,\n  credentialHeaders: [\"authorization\"],\n  security: null,\n  responses: [\n    {{ match: \"204\", kind: \"exact\", status: 204, bodyless: false, media: [], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function uploadAsset<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<UploadAssetResult> {{\n  return execute<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function uploadAssetOrThrow<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<{{ data: undefined; meta: ResponseMeta }}> {{\n  return executeOrThrow<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "uploadasset");
        assert_eq!(actual, expected);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn repeated_wrapped_multipart_field_takes_an_array_of_wrappers() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/uploads": {
                    "post": {
                        "operationId": "uploadFields",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["metas", "tags", "meta", "files", "cover"],
                                        "properties": {
                                            "metas": {
                                                "type": "array",
                                                "items": { "type": "object", "properties": { "tag": { "type": "string" } } }
                                            },
                                            "tags": { "type": "array", "items": { "type": "string" } },
                                            "meta": { "type": "object", "properties": { "tag": { "type": "string" } } },
                                            "files": {
                                                "type": "array",
                                                "items": { "type": "string", "format": "binary" }
                                            },
                                            "cover": { "type": "string", "format": "binary" }
                                        }
                                    },
                                    "encoding": {
                                        "metas": { "contentType": "application/json, application/cbor" },
                                        "meta": { "contentType": "application/json, application/cbor" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "uploadfields");

        assert!(
            actual.contains(
                "metas: ({ body: {\n      tag?: string;\n    }; contentType: \"application/json\" | \"application/cbor\" })[];"
            ),
            "{actual}"
        );
        assert!(actual.contains("tags: string[];"), "{actual}");
        assert!(
            actual.contains(
                "meta: { body: {\n      tag?: string;\n    }; contentType: \"application/json\" | \"application/cbor\" };"
            ),
            "{actual}"
        );
        assert!(actual.contains("files: (Blob | File)[];"), "{actual}");
        assert!(actual.contains("cover: Blob | File;"), "{actual}");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn repeated_wrapped_multipart_field_imports_its_rendered_item() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/upload": {
                    "post": {
                        "operationId": "upload",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["metas"],
                                        "properties": {
                                            "metas": { "$ref": "#/components/schemas/Metas" }
                                        }
                                    },
                                    "encoding": {
                                        "metas": {
                                            "contentType": "application/json, application/cbor"
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Meta": {
                        "type": "object",
                        "properties": { "tag": { "type": "string" } }
                    },
                    "Metas": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/Meta" }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "upload");

        assert!(
            actual.contains("import type { Meta } from \"../../types/components/meta.js\";"),
            "rendered item import mismatch:\n{actual}"
        );
        assert!(
            !actual.contains("import type { Metas }"),
            "outer array import should be absent:\n{actual}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn multipart_content_encoding_operation_module_snapshot() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/notes": {
                    "post": {
                        "operationId": "uploadNote",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["note"],
                                        "properties": {
                                            "note": { "type": "string", "contentEncoding": "binary" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "stored" } }
                    }
                }
            }
        });
        let expected = format!(
            "{HEADER}import type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, multipartBody, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nexport type UploadNoteInput = {{\n  body: {{\n    note: string;\n  }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nexport type UploadNoteResult =\n  | {{ outcome: 204; ok: true; status: 204; data: undefined; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<204>\n  | RequestPhaseFailure;\n\nexport type UploadNoteCallArgs<_S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"uploadNote\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"notes\" }}],\n  ],\n  params: [],\n  body: multipartBody([\n    {{ name: \"note\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: {{ kind: \"fixed\", value: \"application/octet-stream\" }}, filename: false }},\n  ]),\n  accept: null,\n  credentialHeaders: [\"authorization\"],\n  security: null,\n  responses: [\n    {{ match: \"204\", kind: \"exact\", status: 204, bodyless: false, media: [], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1notes/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function uploadNote<S extends string = never>(transport: Transport<S>, input: UploadNoteInput, ...args: UploadNoteCallArgs<S>): Promise<UploadNoteResult> {{\n  return execute<UploadNoteResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1notes/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function uploadNoteOrThrow<S extends string = never>(transport: Transport<S>, input: UploadNoteInput, ...args: UploadNoteCallArgs<S>): Promise<{{ data: undefined; meta: ResponseMeta }}> {{\n  return executeOrThrow<UploadNoteResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "uploadnote");
        assert_eq!(actual, expected);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    /// A schemaless 3.1 multipart field with `contentEncoding` (no `type`) carries the already-
    /// encoded string on the wire, so its descriptor mirrors the typed `{ type: string,
    /// contentEncoding }` case: `payload: "text"`, no CTE header, and no `filename` (not a binary
    /// upload). Without the honoring in `default_part_media`, a schemaless field would emit
    /// `payload: "binary"` and a `Blob | File` input instead.
    #[test]
    fn schemaless_content_encoding_multipart_field_emits_text_payload() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/notes": {
                    "post": {
                        "operationId": "uploadNote",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["note"],
                                        "properties": {
                                            "note": { "contentEncoding": "binary" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "uploadnote");

        assert!(actual.contains(
            "{ name: \"note\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: { kind: \"fixed\", value: \"application/octet-stream\" }, filename: false }"
        ));
        // The schemaless field's input type is its schema shape (`unknown`), not the `Blob | File`
        // a binary upload would demand.
        assert!(actual.contains("note: unknown;"));
        assert!(!actual.contains("Blob | File"));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    /// A repeated binary upload is an array in the descriptor and in the runtime, which rejects a
    /// lone Blob with `repeated multipart field files must be an array`. The input type used to
    /// promise exactly that lone Blob, so following it produced a call that never left the process.
    #[test]
    fn a_repeated_binary_upload_takes_an_array() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/uploads": {
                    "post": {
                        "operationId": "uploadFiles",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["files", "cover"],
                                        "properties": {
                                            "files": {
                                                "type": "array",
                                                "items": { "type": "string", "format": "binary" }
                                            },
                                            "cover": { "type": "string", "format": "binary" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "uploadfiles");

        assert!(actual.contains("files: (Blob | File)[];"), "{actual}");
        assert!(
            actual.contains("\"files\", required: true, repeated: true"),
            "{actual}"
        );
        // The singular field is the control: it keeps the bare union and its `repeated: false`.
        assert!(actual.contains("cover: Blob | File;"), "{actual}");
        assert!(
            actual.contains("\"cover\", required: true, repeated: false"),
            "{actual}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn content_discriminated_request_body_module_snapshot() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/messages": {
                    "post": {
                        "operationId": "sendMessage",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": { "schema": { "type": "object", "required": ["text"], "properties": { "text": { "type": "string" } } } },
                                "text/plain": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": {
                            "200": { "description": "sent", "content": { "text/plain": { "schema": { "type": "string" } } } }
                        }
                    }
                }
            }
        });
        let expected = format!(
            "{HEADER}import type {{ SendMessageRequest, SendMessageResponse200 }} from \"../../types/operations/sendmessage.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ discriminatedBody, execute, executeOrThrow, jsonBody, textBody, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageInput = {{\n  body: {{ contentType: \"application/json\"; body: SendMessageRequest[\"body\"] }} | {{ contentType: \"text/plain\"; body: string }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageResult =\n  | {{ outcome: 200; ok: true; status: 200; data: SendMessageResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n\nexport type SendMessageCallArgs<_S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"sendMessage\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"messages\" }}],\n  ],\n  params: [],\n  body: discriminatedBody([\n    [\"application/json\", jsonBody(\"application/json\")],\n    [\"text/plain\", textBody(\"text/plain\")],\n  ]),\n  accept: \"text/plain\",\n  credentialHeaders: [\"authorization\"],\n  security: null,\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"text/plain\", \"text\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function sendMessage<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<SendMessageResult> {{\n  return execute<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function sendMessageOrThrow<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<{{ data: SendMessageResponse200; meta: ResponseMeta }}> {{\n  return executeOrThrow<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "sendmessage");
        assert_eq!(actual, expected);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn body_named_parameter_and_request_body_render_in_distinct_groups() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/collision": {
                    "post": {
                        "operationId": "collideBody",
                        "parameters": [
                            { "name": "body", "in": "query", "schema": { "type": "string" } }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "collidebody");

        assert!(actual.contains(
            "export type CollideBodyInput = {\n  query?: {\n    body?: string;\n  };\n  body?: CollideBodyRequest[\"body\"];\n};"
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn cookie_parameter_emits_form_serializer_and_cookie_group() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/session": {
                    "get": {
                        "operationId": "readSession",
                        "parameters": [
                            { "name": "sid", "in": "cookie", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "readsession");

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            actual.contains("import { serializeQueryForm } from \"../../runtime/serialize.js\";"),
            "cookie serializer import missing:\n{actual}"
        );
        assert!(
            actual.contains("  cookie?: {\n    sid?: string;\n  };"),
            "cookie input group missing:\n{actual}"
        );
        assert!(
            actual.contains(
                "{ name: \"sid\", location: \"cookie\", required: false, serialize: serializeQueryForm, allowReserved: false }"
            ),
            "cookie descriptor param missing:\n{actual}"
        );
    }

    #[test]
    fn same_wire_name_parameters_render_in_distinct_location_groups() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items/{id}": {
                    "get": {
                        "operationId": "collideParameters",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "id", "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "collideparameters");

        assert!(actual.contains(
            "export type CollideParametersInput = {\n  path: {\n    id: string;\n  };\n  query?: {\n    id?: string;\n  };\n};"
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn input_groups_render_in_fixed_location_order() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items/{item-id}": {
                    "get": {
                        "operationId": "getItem",
                        "parameters": [
                            { "name": "X-Trace", "in": "header", "required": true, "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "schema": { "type": "integer" } },
                            { "name": "item-id", "in": "path", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "getitem");

        assert!(actual.contains(
            "export type GetItemInput = {\n  path: {\n    \"item-id\": string;\n  };\n  query?: {\n    limit?: number;\n  };\n  header: {\n    \"X-Trace\": string;\n  };\n};"
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    /// A multipart field with an explicit `style` on an object-shaped schema has no OAS-defined
    /// per-part serialization: OASTS5112 (`crates/oasts-core/src/client_model.rs`) rejects it
    /// instead of the retired pinned behavior this test replaces, where `field_payload` silently
    /// classified it the same as a JSON content field with no content-type header — a wire format
    /// the spec never sanctions.
    ///
    /// The client-model plan is still produced (`FieldSerializationPlan::Style` on the object
    /// schema, unchanged) so downstream planning has something to consult, but real generation
    /// never reaches emission for it: `pipeline::compile` returns `None` as soon as
    /// `sink.has_errors()`, before `emit_client_from_model` runs. This test stops at
    /// `build_client_model` accordingly, rather than asserting on TS text that
    /// `write_multipart_field` — deliberately unchanged — would still render verbatim.
    #[test]
    fn styled_object_multipart_field_is_rejected() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/styled-object": {
                    "post": {
                        "operationId": "styledObjectField",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["meta"],
                                        "properties": {
                                            "meta": {
                                                "type": "object",
                                                "properties": { "tag": { "type": "string" } }
                                            }
                                        }
                                    },
                                    "encoding": {
                                        "meta": { "style": "form" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);

        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS5112")
            .expect("OASTS5112 diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some(
                "/paths/~1styled-object/post/requestBody/content/multipart~1form-data/encoding/meta"
            )
        );
        assert_eq!(
            diagnostic.message,
            "multipart field 'meta' has no defined per-part serialization for Form/explode=true with this schema shape; use encoding.contentType instead"
        );

        let fields = client.operations[0]
            .body_plan
            .as_ref()
            .expect("body plan")
            .multipart_fields()
            .expect("multipart fields");
        assert!(matches!(
            &fields[0].serialization,
            FieldSerializationPlan::Style {
                style: ParamStyle::Form,
                ..
            }
        ));
    }

    /// A styled primitive field has a defined per-part serialization for any style/explode
    /// combination (OASTS5112's SUPPORTED case): it keeps the exact `text` payload emission this
    /// pins, unchanged from before the admission matrix landed.
    #[test]
    fn styled_primitive_multipart_field_emits_text_payload() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/styled-primitive": {
                    "post": {
                        "operationId": "styledPrimitiveField",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["note"],
                                        "properties": {
                                            "note": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "note": { "style": "form", "explode": false }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "styledprimitivefield");

        assert!(actual.contains(
            "{ name: \"note\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: { kind: \"none\" }, filename: false }"
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    /// An exploded `form`-style array of primitives has a defined per-part serialization (OASTS5112's
    /// SUPPORTED array case): it keeps the `repeated` descriptor, unchanged from before the
    /// admission matrix landed.
    #[test]
    fn styled_primitive_array_multipart_field_repeats_parts() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/styled-tags": {
                    "post": {
                        "operationId": "styledTagsArray",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["tags"],
                                        "properties": {
                                            "tags": { "type": "array", "items": { "type": "string" } }
                                        }
                                    },
                                    "encoding": {
                                        "tags": { "style": "form", "explode": true }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "styledtagsarray");

        assert!(actual.contains(
            "{ name: \"tags\", required: true, repeated: true, wrapper: false, payload: \"text\", contentType: { kind: \"none\" }, filename: false }"
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn distinct_parameter_properties_render() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items/{id}": {
                    "get": {
                        "operationId": "distinctParameters",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "filter", "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "distinctparameters");

        assert!(actual.contains("id: string;"));
        assert!(actual.contains("filter?: string;"));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn client_tsdoc_mapping_snapshot() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "readPet",
                        "summary": "Read a pet.",
                        "description": "Loads one pet.",
                        "deprecated": true,
                        "externalDocs": {
                            "url": "https://docs.example.test/pets",
                            "description": "Pet guide"
                        },
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "description": "The pet identifier.",
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "description": "The result limit.",
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": {
                            "200": { "description": "Found." },
                            "404": { "description": "Missing." }
                        }
                    }
                }
            }
        });
        let (module, diagnostics) = emit_operation_with_documentation(document, "readpet", true);
        let declaration = "/**\n * Read a pet.\n * \n * @remarks\n * Loads one pet.\n * \n * Responses\n * \n * - 200: Found.\n * - 404: Missing.\n * \n * @deprecated This operation is deprecated.\n * \n * @see {@link https://docs.example.test/pets | Pet guide}\n */\n";
        let pet_id_property = "/**\n     * The pet identifier.\n     */\n";
        let limit_property = "/**\n     * The result limit.\n     */\n";
        let result_function = "/**\n * Read a pet.\n * \n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Loads one pet.\n * \n * Responses\n * \n * - 200: Found.\n * - 404: Missing.\n * \n * @deprecated This operation is deprecated.\n * \n * @returns A typed result covering every documented response and failure.\n * \n * @see {@link https://docs.example.test/pets | Pet guide}\n */\n";
        let throw_function = result_function.replace(
            "@returns A typed result covering every documented response and failure.",
            "@returns The successful response data and its response metadata.",
        );
        assert_eq!(
            tsdoc_blocks(&module),
            [
                declaration,
                pet_id_property,
                limit_property,
                declaration,
                result_function,
                &throw_function,
            ]
            .join("\n")
        );
        assert_eq!(module.matches("@returns").count(), 2);
        assert!(!module.contains("@param"));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn input_parameter_docs_use_safe_property_tsdoc_and_skip_undocumented_properties() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/trace": {
                    "get": {
                        "operationId": "traceCall",
                        "parameters": [
                            {
                                "name": "X-Trace",
                                "in": "header",
                                "description": "Line one.\n@deprecated fake\n*/",
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "undocumented",
                                "in": "query",
                                "schema": { "type": "boolean" }
                            }
                        ],
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (_temp, analyzed, mut config, _source_tuples) =
            analyzed_with_options(&document, false, true);
        config.documentation.summary = false;
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        let operation = files
            .iter()
            .find(|file| file.relative_path == "client/operations/tracecall.ts")
            .expect("operation");

        assert!(operation.content.contains(
            "  query?: {\n    undocumented?: boolean;\n  };\n  header?: {\n    /**\n     * @remarks\n     * Line one.\n     * \\@deprecated fake\n     * *\\/\n     */\n    \"X-Trace\"?: string;\n  };"
        ));
        assert!(!operation.content.contains("@param"));
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());

        let mut disabled_property_docs = String::new();
        let mut disabled_documentation = config.documentation.clone();
        disabled_documentation.enabled = false;
        write_parameter_property_tsdoc(
            &mut disabled_property_docs,
            "Hidden.",
            &disabled_documentation,
            2,
        );
        assert!(disabled_property_docs.is_empty());

        // The shared renderer also serves real flat-signature parameters; cover that
        // branch independently from this request-object caller.
        let mut flat_parameter_docs = String::new();
        write_client_operation_tsdoc(
            &mut flat_parameter_docs,
            &analyzed.ir.operations[0],
            &config.documentation,
            ClientDocKind::ResultFunction,
            false,
            false,
            &[],
        );
        assert!(flat_parameter_docs.contains("@param X-Trace - Line one."));
    }

    #[test]
    fn aggregate_client_module_snapshot_and_disabled_absence() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/first": {
                    "get": {
                        "operationId": "firstCall",
                        "responses": { "204": { "description": "done" } }
                    }
                },
                "/second": {
                    "post": {
                        "operationId": "secondCall",
                        "responses": { "204": { "description": "done" } }
                    }
                }
            }
        });
        let (_temp, aggregate_analyzed, config, _source_tuples) =
            analyzed_with_aggregate(&document, true);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&aggregate_analyzed, &config, &mut sink);
        let mut model =
            EmissionModel::new(&aggregate_analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        let aggregate = files
            .iter()
            .find(|file| file.relative_path == "client/api.ts")
            .expect("aggregate module");
        let expected = format!(
            "{HEADER}import {{ firstCall, firstCallOrThrow }} from \"./operations/firstcall.js\";\nimport {{ secondCall, secondCallOrThrow }} from \"./operations/secondcall.js\";\n\nexport const api = {{ firstCall, firstCallOrThrow, secondCall, secondCallOrThrow }} as const;\n"
        );
        assert_eq!(aggregate.content, expected);
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());

        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "client/api.ts")
        );
    }

    // --- multipart response decoding ------------------------------------------------------------

    /// Emits every client file for `document`, so a test can read both an operation module and the
    /// helper-subset `serialize.ts` that operation's descriptor pulled in.
    fn emit_all_client_files(document: &Value) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let (_temp, analyzed, config, _source_tuples) = analyzed(document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        (files, sink.into_sorted_vec())
    }

    fn runtime_file(files: &[GeneratedFile], name: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("runtime/{name}"))
            .expect("runtime file")
            .content
            .clone()
    }

    fn multipart_response_document(schema: Value) -> Value {
        json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/bundle": {
                    "get": {
                        "operationId": "getbundle",
                        "responses": {
                            "200": { "description": "ok", "content": { "multipart/form-data": { "schema": schema } } }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn multipart_response_emits_a_part_plan_and_the_decoded_object_type() {
        let document = multipart_response_document(json!({
            "type": "object",
            "required": ["manifest", "archive"],
            "additionalProperties": false,
            "properties": {
                "manifest": { "type": "object", "properties": { "name": { "type": "string" } } },
                "readme": { "type": "string" },
                "archive": { "type": "string", "format": "binary" },
                "thumbnails": { "type": "array", "items": { "type": "string", "format": "binary" } },
                "labels": { "type": "array", "items": { "type": "string" } },
                "encoded": { "type": "string", "format": "byte" },
                "extra": {}
            }
        }));
        let (files, diagnostics) = emit_all_client_files(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let actual = operation_file(&files, "getbundle");

        // Each declared property carries its own classification, and only binary overrides the
        // schema's own type.
        assert!(
            actual.contains(
                "data: {\n    manifest: {\n      name?: string;\n    };\n    readme?: string;\n    archive: Uint8Array;\n    thumbnails?: Uint8Array[];\n    labels?: string[];\n    encoded?: string;\n    extra?: unknown;\n  }; meta: ResponseMeta"
            ),
            "{actual}"
        );
        // `additionalProperties: false` leaves the object closed, so no index signature.
        assert!(!actual.contains("[key: string]"), "{actual}");
        assert!(actual.contains(
            "media: [[\"multipart/form-data\", { decode: decodeMultipartResponse, plan: { parts: [{ name: \"manifest\", payload: \"json\", repeated: false }, { name: \"readme\", payload: \"text\", repeated: false }, { name: \"archive\", payload: \"binary\", repeated: false }, { name: \"thumbnails\", payload: \"binary\", repeated: true }, { name: \"labels\", payload: \"text\", repeated: true }, { name: \"encoded\", payload: \"text\", repeated: false }, { name: \"extra\", payload: \"wire\", repeated: false }], additional: { payload: \"wire\", repeated: false } } }]]"
        ), "{actual}");
        assert!(
            actual.contains(
                "import { decodeMultipartResponse } from \"../../runtime/serialize.js\";"
            ),
            "{actual}"
        );
        // The status-wide alias renders as `unknown` in the types artifact, so the operation module
        // must not import it.
        assert!(!actual.contains("GetbundleResponse200"), "{actual}");
        assert!(
            runtime_file(&files, "serialize.ts")
                .contains("export function decodeMultipartResponse"),
        );
    }

    #[test]
    fn multipart_response_widens_the_index_signature_over_declared_properties() {
        let document = multipart_response_document(json!({
            "type": "object",
            "additionalProperties": { "type": "string" },
            "properties": { "archive": { "type": "string", "format": "binary" } }
        }));
        let (files, diagnostics) = emit_all_client_files(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let actual = operation_file(&files, "getbundle");

        // A declared property must be assignable to the index type, and `Uint8Array` is not a
        // `string`, so the index signature unions both.
        assert!(
            actual.contains("archive?: Uint8Array;\n    [key: string]: string | Uint8Array;\n  }"),
            "{actual}"
        );
        assert!(
            actual.contains("additional: { payload: \"text\", repeated: false } } }"),
            "{actual}"
        );
    }

    #[test]
    fn multipart_response_without_an_object_schema_is_a_bare_index_signature() {
        let (files, diagnostics) = emit_all_client_files(&multipart_response_document(json!({})));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let actual = operation_file(&files, "getbundle");

        assert!(
            actual.contains("data: {\n    [key: string]: unknown;\n  }"),
            "{actual}"
        );
        assert!(
            actual.contains(
                "plan: { parts: [], additional: { payload: \"wire\", repeated: false } }"
            ),
            "{actual}"
        );

        // A closed object with no declared property admits nothing at all.
        let (empty, diagnostics) = emit_all_client_files(&multipart_response_document(
            json!({ "type": "object", "additionalProperties": false }),
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let empty = operation_file(&empty, "getbundle");
        assert!(empty.contains("status: 200; data: {}; meta:"), "{empty}");
    }

    #[test]
    fn multipart_response_documents_the_undefined_part_mapping_it_chose() {
        let closed = multipart_response_document(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "readme": { "type": "string" } }
        }));
        let (closed, _) = emit_operation_with_documentation(closed, "getbundle", true);
        assert!(
            closed.contains(
                "- response 200 multipart/form-data: each part maps to the property named by its Content-Disposition name. A part naming no declared property is kept even though the schema forbids it;"
            ),
            "{closed}"
        );
        assert!(
            closed.contains("a repeated name is collected into an array property and rejected for any other property; a binary part decodes to Uint8Array. Part filenames and per-part headers are not surfaced."),
            "{closed}"
        );

        let open = multipart_response_document(json!({ "type": "object" }));
        let (open, _) = emit_operation_with_documentation(open, "getbundle", true);
        assert!(
            open.contains("A part naming no declared property is kept; a declared property"),
            "{open}"
        );
    }

    #[test]
    fn multipart_response_shares_a_status_with_a_json_entry_and_narrows_on_content_type() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "components": { "schemas": { "Manifest": { "type": "object", "properties": { "name": { "type": "string" } } } } },
            "paths": {
                "/mixed": {
                    "get": {
                        "operationId": "getmixed",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "$ref": "#/components/schemas/Manifest" },
                                    "multipart/form-data": {
                                        "schema": {
                                            "type": "object",
                                            "additionalProperties": false,
                                            "properties": {
                                                "manifest": { "$ref": "#/components/schemas/Manifest" },
                                                "archive": { "type": "string", "format": "binary" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "getmixed");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");

        assert!(
            actual.contains("contentType: \"multipart/form-data\""),
            "{actual}"
        );
        assert!(
            actual.contains("manifest?: Manifest;\n    archive?: Uint8Array;\n  }"),
            "{actual}"
        );
        // The binary part never names its schema, so only the JSON-rendered part imports a
        // component type.
        assert!(
            actual
                .contains("import type { Manifest } from \"../../types/components/manifest.js\";"),
            "{actual}"
        );
    }

    #[test]
    fn a_client_without_a_multipart_response_carries_no_decoder() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (files, diagnostics) = emit_all_client_files(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");

        assert!(!operation_file(&files, "ping").contains("decodeMultipartResponse"));
        // The plan types stay in the always-emitted core region (transport.ts type-imports them),
        // but the decoder itself — the only part with a runtime cost — is gone.
        let serialize = runtime_file(&files, "serialize.ts");
        assert!(!serialize.contains("export function decodeMultipartResponse"));
        assert!(!serialize.contains("Content-Disposition has no name parameter"));
        assert!(serialize.contains("export type MultipartResponsePlan"));
    }

    fn string_schema(format: Option<&str>) -> SchemaNode {
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: format.map(str::to_owned),
            enum_values: None,
            const_value: None,
            meta: SchemaMeta::default(),
        }
    }

    fn object_schema() -> SchemaNode {
        SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(None),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: SchemaMeta::default(),
        }
    }

    fn content_field(
        name: &str,
        schema: SchemaNode,
        media: PartMediaPlan,
        wrapper: FieldWrapperPlan,
    ) -> FormFieldPlan {
        FormFieldPlan {
            name: name.to_owned(),
            required: true,
            schema,
            serialization: FieldSerializationPlan::Content {
                media,
                encoding_source: None,
            },
            wrapper,
            source: SourceRef::default(),
        }
    }

    fn style_field(name: &str, schema: SchemaNode) -> FormFieldPlan {
        FormFieldPlan {
            name: name.to_owned(),
            required: false,
            schema,
            serialization: FieldSerializationPlan::Style {
                style: ParamStyle::DeepObject,
                explode: false,
                allow_reserved: true,
                encoding_source: SourceRef::default(),
            },
            wrapper: FieldWrapperPlan {
                wrapped: false,
                content_type_literal: true,
                filename: false,
            },
            source: SourceRef::default(),
        }
    }

    fn response_plan(
        match_key: &str,
        kind: ResponseMatchKind,
        payload: PayloadDisposition,
        media: Vec<ResponseMediaPlan>,
        content_type_discriminated: bool,
    ) -> ResponsePlan {
        ResponsePlan {
            match_key: match_key.to_owned(),
            kind,
            media,
            payload,
            content_type_discriminated,
            has_headers: false,
            source: SourceRef::default(),
        }
    }

    fn response_media(media: &str, decoder: DecoderClass) -> ResponseMediaPlan {
        ResponseMediaPlan {
            media: media.to_owned(),
            decoder,
            multipart: None,
            schema: string_schema(None),
            streaming_marked: false,
            source: SourceRef::default(),
        }
    }

    #[test]
    fn scalar_descriptor_renderers_cover_every_mapping() {
        let helpers = [
            HelperId::PathSimple,
            HelperId::PathSimpleExplode,
            HelperId::PathLabel,
            HelperId::PathLabelExplode,
            HelperId::PathMatrix,
            HelperId::PathMatrixExplode,
            HelperId::QueryForm,
            HelperId::QueryFormExplode,
            HelperId::QuerySpaceDelimited,
            HelperId::QuerySpaceDelimitedObject,
            HelperId::QueryPipeDelimited,
            HelperId::QueryPipeDelimitedObject,
            HelperId::QueryDeepObject,
            HelperId::QueryDeepObjectExtended,
            HelperId::HeaderSimple,
            HelperId::HeaderSimpleExplode,
            HelperId::ContentJsonPath,
            HelperId::ContentJsonQuery,
            HelperId::ContentJsonHeader,
        ];
        for helper in helpers {
            assert!(!helper_region_id(helper).is_empty());
            assert!(helper_export_name(helper).starts_with("serialize"));
            assert_eq!(
                helper.is_content_json(),
                helper_export_name(helper).starts_with("serializeContentJson"),
            );
        }
        for (location, expected) in [
            (ParamLocation::Path, "path"),
            (ParamLocation::Query, "query"),
            (ParamLocation::Header, "header"),
            (ParamLocation::Cookie, "cookie"),
        ] {
            assert_eq!(crate::emit::parameter_group_name(location), expected);
        }
        for (style, expected) in [
            (ParamStyle::Form, "form"),
            (ParamStyle::Simple, "simple"),
            (ParamStyle::Label, "label"),
            (ParamStyle::Matrix, "matrix"),
            (ParamStyle::SpaceDelimited, "spaceDelimited"),
            (ParamStyle::PipeDelimited, "pipeDelimited"),
            (ParamStyle::DeepObject, "deepObject"),
        ] {
            assert_eq!(style_name(style), expected);
        }
        assert_eq!(decoder_name(DecoderClass::Json), "json");
        assert_eq!(decoder_name(DecoderClass::Text), "text");
        assert_eq!(decoder_name(DecoderClass::Binary), "binary");
        assert_eq!(
            media_payload(&PartMediaPlan {
                values: vec!["application/cbor".to_owned()],
                payloads: vec![PayloadKind::Binary],
                all_concrete: true,
                binary_upload: false,
                declared: true,
            }),
            "binary"
        );
        // A parameterized media essence classifies by its base type: `application/json;
        // charset=utf-8` is JSON, not the schema-shape fallback. A multipart content field carries
        // this straight into the descriptor's `payload`.
        let json_charset = PartMediaPlan {
            values: vec!["application/json; charset=utf-8".to_owned()],
            payloads: vec![PayloadKind::Json],
            all_concrete: true,
            binary_upload: false,
            declared: true,
        };
        assert_eq!(media_payload(&json_charset), "json");
        assert_eq!(
            field_payload(&content_field(
                "meta",
                object_schema(),
                json_charset,
                FieldWrapperPlan {
                    wrapped: false,
                    content_type_literal: true,
                    filename: false,
                },
            )),
            "json"
        );
        // A binary payload remains binary independently of its media type metadata.
        assert_eq!(
            media_payload(&PartMediaPlan {
                values: vec!["application/octet-stream".to_owned()],
                payloads: vec![PayloadKind::Binary],
                all_concrete: true,
                binary_upload: true,
                declared: false,
            }),
            "binary"
        );
        for decoder in [
            DecoderClass::StreamingSse,
            DecoderClass::StreamingRaw,
            DecoderClass::Xml,
            DecoderClass::Multipart,
            DecoderClass::MultipartUnnamed,
        ] {
            assert!(std::panic::catch_unwind(|| decoder_name(decoder)).is_err());
        }

        let mut rendered = String::new();
        write_base_url(&mut rendered, &BaseUrlPlan::Runtime);
        write_base_url(
            &mut rendered,
            &BaseUrlPlan::Literal {
                value: "https://literal.example".to_owned(),
            },
        );
        write_base_url(
            &mut rendered,
            &BaseUrlPlan::Server {
                index: 1,
                servers: vec![ServerEntry {
                    url: "https://{region}.example".to_owned(),
                    variables: vec![(
                        "region".to_owned(),
                        ServerVariable {
                            default: "eu".to_owned(),
                            enum_values: vec!["eu".to_owned()],
                        },
                    )],
                    source: SourceRef::default(),
                }],
            },
        );
        assert!(rendered.contains("server"));
        assert!(rendered.contains("region"));
    }

    #[test]
    fn relative_server_url_is_written_verbatim() {
        let mut rendered = String::new();
        write_base_url(
            &mut rendered,
            &BaseUrlPlan::Server {
                index: 0,
                servers: vec![ServerEntry {
                    url: "/api/{version}/".to_owned(),
                    variables: vec![(
                        "version".to_owned(),
                        ServerVariable {
                            default: "v2".to_owned(),
                            enum_values: Vec::new(),
                        },
                    )],
                    source: SourceRef::default(),
                }],
            },
        );

        assert_eq!(
            rendered,
            "{ kind: \"server\", index: 0, servers: [{ url: \"/api/{version}/\", variables: [[\"version\", \"v2\"]] }] }"
        );
    }

    #[test]
    fn input_member_uses_nested_parameter_access() {
        for (location, expected) in [
            (ParamLocation::Path, "input.path?.petId"),
            (ParamLocation::Query, "input.query?.petId"),
            (ParamLocation::Header, "input.header?.petId"),
            (ParamLocation::Cookie, "input.cookie?.petId"),
        ] {
            assert_eq!(
                input_member(
                    InputMember::Parameter {
                        location,
                        name: "petId",
                    },
                    "input"
                ),
                expected
            );
        }
        assert_eq!(
            input_member(
                InputMember::Parameter {
                    location: ParamLocation::Path,
                    name: "pet-id",
                },
                "input"
            ),
            "input.path?.[\"pet-id\"]"
        );
        assert_eq!(input_member(InputMember::Body, "input"), "input.body");
        assert_eq!(input_member(InputMember::Body, "wire"), "wire.body");
    }

    #[test]
    fn fetch_default_renderer_covers_every_wire_value() {
        let credentials = [
            CredentialsMode::Omit,
            CredentialsMode::SameOrigin,
            CredentialsMode::Include,
        ];
        let caches = [
            CacheMode::Default,
            CacheMode::NoStore,
            CacheMode::Reload,
            CacheMode::NoCache,
            CacheMode::ForceCache,
            CacheMode::OnlyIfCached,
        ];
        let redirects = [
            RedirectMode::Follow,
            RedirectMode::Error,
            RedirectMode::Manual,
        ];
        let referrers = [
            ReferrerPolicyValue::NoReferrer,
            ReferrerPolicyValue::NoReferrerWhenDowngrade,
            ReferrerPolicyValue::SameOrigin,
            ReferrerPolicyValue::Origin,
            ReferrerPolicyValue::StrictOrigin,
            ReferrerPolicyValue::OriginWhenCrossOrigin,
            ReferrerPolicyValue::StrictOriginWhenCrossOrigin,
            ReferrerPolicyValue::UnsafeUrl,
        ];
        let modes = [
            RequestModeValue::Cors,
            RequestModeValue::NoCors,
            RequestModeValue::SameOrigin,
        ];
        for value in credentials {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    credentials: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains("credentials"));
        }
        for value in caches {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    cache: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains("cache"));
        }
        for value in redirects {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    redirect: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains("redirect"));
        }
        for value in referrers {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    referrer_policy: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains("referrerPolicy"));
        }
        for value in modes {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    mode: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains("mode"));
        }
        for value in [false, true] {
            let mut output = String::new();
            write_fetch_defaults(
                &mut output,
                &FetchDefaults {
                    keepalive: Some(value),
                    ..FetchDefaults::default()
                },
            );
            assert!(output.contains(&value.to_string()));
        }
    }

    /// Every string tag the shared phase-failure unions occupy, plus the `unmatched` arm's own tag.
    /// A declared response key that rendered to one of these would silently merge two unrelated arms,
    /// so the disjointness is pinned by test rather than left to the shape of the key grammar.
    const RESERVED_OUTCOMES: [&str; 16] = [
        "unmatched",
        "auth",
        "aborted",
        "timeout",
        "network",
        "request-encode",
        "request-validation",
        "request-transform",
        "request-middleware",
        "cookie-params-unsendable",
        "response-aborted",
        "response-timeout",
        "response-decode",
        "response-validation",
        "response-transform",
        "response-middleware",
    ];

    /// A renderer over an empty document: enough for the result-type tests, whose payload types
    /// come from inline schemas rather than from named components.
    fn probe_analyzed() -> (TempDir, Analyzed, ResolvedConfig) {
        let (temporary, analyzed, config, _) = analyzed(&json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {}
        }));
        (temporary, analyzed, config)
    }

    #[test]
    fn the_declared_outcome_space_is_disjoint_from_every_reserved_tag() {
        // Two guards. First: the reserved list is the one the runtime actually declares — parsed
        // out of the embedded result.ts rather than restated, so a new failure tag cannot land
        // there without landing here. Second: no response key the parser admits can render to a
        // reserved tag, over the whole admitted key grammar (every exact status and every range).
        let runtime = include_str!("../../runtime/result.ts");
        let declared = runtime
            .match_indices("outcome: '")
            .map(|(index, marker)| {
                let rest = &runtime[index + marker.len()..];
                &rest[..rest.find('\'').expect("unterminated outcome literal")]
            })
            .collect::<BTreeSet<_>>();
        let reserved = RESERVED_OUTCOMES.into_iter().collect::<BTreeSet<_>>();
        // `unmatched` is emitted by the client, not declared in result.ts, so it is the one
        // reserved tag the runtime scan cannot see.
        assert_eq!(
            declared,
            reserved
                .iter()
                .copied()
                .filter(|tag| *tag != "unmatched")
                .collect::<BTreeSet<_>>()
        );

        let mut keys = vec!["default".to_owned()];
        for lead in '1'..='5' {
            keys.push(format!("{lead}XX"));
            for status in 0..100 {
                keys.push(format!("{lead}{status:02}"));
            }
        }
        for key in keys {
            let kind = if key == "default" {
                ResponseMatchKind::Default
            } else if key.ends_with("XX") {
                ResponseMatchKind::Range
            } else {
                ResponseMatchKind::Exact
            };
            let plan = response_plan(&key, kind, PayloadDisposition::NoPayload, Vec::new(), false);
            let rendered = outcome_literal(&plan);
            for tag in RESERVED_OUTCOMES {
                assert_ne!(rendered, render_ts_string(tag), "{key} collides with {tag}");
            }
            // An exact key renders as a bare number literal, everything else as a quoted string —
            // the two families cannot overlap even before the tag comparison above.
            assert_eq!(rendered.starts_with('"'), kind != ResponseMatchKind::Exact);
        }
    }

    #[test]
    fn result_renderer_covers_range_default_and_discriminated_media() {
        let responses = vec![
            response_plan(
                "100",
                ResponseMatchKind::Exact,
                PayloadDisposition::NoPayload,
                Vec::new(),
                false,
            ),
            response_plan(
                "404",
                ResponseMatchKind::Exact,
                PayloadDisposition::Payload,
                vec![response_media("application/json", DecoderClass::Json)],
                false,
            ),
            response_plan(
                "2XX",
                ResponseMatchKind::Range,
                PayloadDisposition::StaticBodyless,
                Vec::new(),
                false,
            ),
            response_plan(
                "4XX",
                ResponseMatchKind::Range,
                PayloadDisposition::NoPayload,
                Vec::new(),
                false,
            ),
            response_plan(
                "default",
                ResponseMatchKind::Default,
                PayloadDisposition::Payload,
                vec![
                    response_media("text/plain", DecoderClass::Text),
                    response_media("application/octet-stream", DecoderClass::Binary),
                ],
                true,
            ),
        ];
        let plan = OperationPlan {
            operation_index: 0,
            param_plans: Vec::new(),
            body_plan: None,
            response_table: responses,
            accept: None,
            base_url: BaseUrlPlan::Runtime,
            auth_plan: Vec::new(),
            credential_headers: Vec::new(),
        };
        let (_temporary, analyzed, config) = probe_analyzed();
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let renderer = TypesEmitter::new(&model);
        let arms = response_result_arms(&renderer, &plan, "Probe", &[], false);
        let output = render_result_type(&arms, &plan, "Probe", "");
        assert!(output.contains(
            "outcome: 100; ok: false; status: 100; error: undefined; meta: ResponseMeta"
        ));
        assert!(output.contains("outcome: \"2XX\"; ok: true; status: number; data: undefined"));
        assert!(output.contains("contentType: \"text/plain\""));
        assert!(output.contains("outcome: \"default\"; ok: false"));
        // The declared-key space is what ResponsePhaseFailure is instantiated over: exact keys as
        // number literals, range and default keys as strings, so the two families stay disjoint.
        assert!(output.contains(
            "| ResponsePhaseFailure<100 | 404 | \"2XX\" | \"4XX\" | \"default\">\n  | RequestPhaseFailure;\n"
        ));
        // The discriminated `default` branch contributes one envelope per media entry, each typed
        // to that entry's own schema (text/plain → string, application/octet-stream → unknown),
        // not one status-wide alias repeated.
        assert_eq!(
            successful_envelope_union(&arms),
            "{ data: undefined; meta: ResponseMeta } | { data: string; meta: ResponseMeta } | { data: unknown; meta: ResponseMeta }"
        );

        let empty = OperationPlan {
            response_table: Vec::new(),
            ..plan
        };
        let empty_arms = response_result_arms(&renderer, &empty, "Empty", &[], false);
        let output = render_result_type(&empty_arms, &empty, "Empty", "");
        assert!(output.contains("| ResponsePhaseFailure<never>\n  | RequestPhaseFailure;\n"));
        assert_eq!(successful_envelope_union(&empty_arms), "never");
    }

    #[test]
    fn a_component_shadowing_a_client_declaration_imports_under_an_alias() {
        // The client module declares `ReadpetInput`; a component of that name reaches it through a
        // content-discriminated arm, which renders the component directly instead of the
        // status-wide alias. Unaliased, the import and the declaration collide.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pet": {
                    "get": {
                        "operationId": "readpet",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/ReadpetInput" } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "ReadpetInput": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "readpet");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains(
                "import type { ReadpetInput as ReadpetInputBody } from \"../../types/components/readpetinput.js\";"
            ),
            "{content}"
        );
        assert!(
            content.contains("data: ReadpetInputBody; contentType: \"application/json\""),
            "{content}"
        );
        assert!(
            content.contains("export type ReadpetInput = {"),
            "{content}"
        );
    }

    #[test]
    fn a_client_alias_that_is_itself_imported_is_a_fatal_collision() {
        // `ReadpetInput` is shadowed by the module's own declaration, and the replacement name
        // `ReadpetInputBody` is a component this module already imports — no local rename is left.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pet": {
                    "get": {
                        "operationId": "readpet",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/ReadpetInput" } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            },
                            "400": {
                                "description": "bad",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/ReadpetInputBody" } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "ReadpetInput": { "type": "object", "properties": { "id": { "type": "string" } } },
                    "ReadpetInputBody": { "type": "object", "properties": { "detail": { "type": "string" } } }
                }
            }
        });
        let (_, diagnostics) = emit_operation(document, "readpet");
        let flagged = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS4102")
            .expect("alias collision diagnostic");
        assert_eq!(flagged.severity, Severity::Error);
        assert!(flagged.message.contains("ReadpetInputBody"));
    }

    #[test]
    fn each_declared_media_entry_carries_its_own_payload_type() {
        // A 200 declaring an object JSON body beside a text body emits two arms with *different*
        // data types — the bug this replaces handed both arms the same status-wide union.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pet": {
                    "get": {
                        "operationId": "readpet",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Pet": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "readpet");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains(
                "export type ReadpetResult =\n  | { outcome: 200; ok: true; status: 200; data: Pet; contentType: \"application/json\"; meta: ResponseMeta }\n  | { outcome: 200; ok: true; status: 200; data: string; contentType: \"text/plain\"; meta: ResponseMeta }\n"
            ),
            "{content}"
        );
        // The per-entry schema reference imports from the component module; the status-wide alias
        // has no reader left, so it is not imported at all.
        assert!(content.contains("import type { Pet } from \"../../types/components/pet.js\";"));
        assert!(!content.contains("ReadpetResponse200"), "{content}");
        // The orThrow envelope follows the same split.
        assert!(
            content.contains(
                "Promise<{ data: Pet; meta: ResponseMeta } | { data: string; meta: ResponseMeta }>"
            ),
            "{content}"
        );
    }

    #[test]
    fn a_result_arm_indents_its_inline_payload_to_the_arm_column() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "getThing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["id"],
                                            "properties": {
                                                "id": { "type": "string" },
                                                "nested": {
                                                    "type": "object",
                                                    "properties": {
                                                        "deep": { "type": "string" }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "getthing");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let start = content
            .find("export type GetThingResult =")
            .expect("result declaration");
        let end = content[start..]
            .find("\n\nexport type GetThingCallArgs")
            .expect("call args declaration");
        assert_eq!(
            &content[start..start + end],
            concat!(
                "export type GetThingResult =\n",
                "  | { outcome: 200; ok: true; status: 200; data: {\n",
                "    id: string;\n",
                "    nested?: {\n",
                "      deep?: string;\n",
                "    };\n",
                "  }; contentType: \"application/json\"; meta: ResponseMeta }\n",
                "  | { outcome: 200; ok: true; status: 200; data: string; contentType: \"text/plain\"; meta: ResponseMeta }\n",
                "  | { outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }\n",
                "  | ResponsePhaseFailure<200>\n",
                "  | RequestPhaseFailure;",
            )
        );
    }

    #[test]
    fn a_discriminated_default_branch_emits_four_arms() {
        // `default` spans both outcomes and this one declares two media entries, so it is 2 x 2 —
        // not the two arms a status-keyed branch would produce.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "default": {
                                "description": "any",
                                "content": {
                                    "application/json": { "schema": { "type": "object", "properties": { "code": { "type": "integer" } } } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "readthing");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains(
                "export type ReadthingResult =\n  | { outcome: \"default\"; ok: true; status: number; data: {\n    code?: number;\n  }; contentType: \"application/json\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: false; status: number; error: {\n    code?: number;\n  }; contentType: \"application/json\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: true; status: number; data: string; contentType: \"text/plain\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: false; status: number; error: string; contentType: \"text/plain\"; meta: ResponseMeta }\n"
            ),
            "{content}"
        );
    }

    #[test]
    fn a_sole_media_range_is_discriminated_and_typed_by_its_essence() {
        // One declared key that is a range is content-type-discriminated even though there is only
        // one entry, and `text/*` types as string.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/note": {
                    "get": {
                        "operationId": "readnote",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "text/*": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "readnote");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains(
                "export type ReadnoteResult =\n  | { outcome: 200; ok: true; status: 200; data: string; contentType: \"text/*\"; meta: ResponseMeta }\n"
            ),
            "{content}"
        );
    }

    #[test]
    fn bodyless_multi_media_response_snapshot() {
        let plan = OperationPlan {
            operation_index: 0,
            param_plans: Vec::new(),
            body_plan: None,
            response_table: vec![response_plan(
                "200",
                ResponseMatchKind::Exact,
                PayloadDisposition::StaticBodyless,
                vec![
                    response_media("application/json", DecoderClass::Json),
                    response_media("text/plain", DecoderClass::Text),
                ],
                true,
            )],
            accept: None,
            base_url: BaseUrlPlan::Runtime,
            auth_plan: Vec::new(),
            credential_headers: Vec::new(),
        };
        let (_temporary, analyzed, config) = probe_analyzed();
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let renderer = TypesEmitter::new(&model);
        let actual = render_result_type(
            &response_result_arms(&renderer, &plan, "HeadHealth", &[], false),
            &plan,
            "HeadHealth",
            "",
        );
        let expected = "export type HeadHealthResult =\n  | { outcome: 200; ok: true; status: 200; data: undefined; meta: ResponseMeta }\n  | { outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n";
        assert_eq!(actual, expected);
    }

    /// The import clause is written by walking `TRANSPORT_VALUE_IMPORTS` in place, so the table's
    /// own order IS the emitted order — an out-of-order entry would silently produce an unsorted
    /// import line. The two kernel entry points are named literally at the call site, so their
    /// lookups have to keep resolving.
    #[test]
    fn transport_value_imports_are_sorted() {
        let mut sorted = TRANSPORT_VALUE_IMPORTS;
        sorted.sort_unstable();
        assert_eq!(sorted, TRANSPORT_VALUE_IMPORTS);
        for name in ["execute", "executeOrThrow"] {
            assert_eq!(TRANSPORT_VALUE_IMPORTS[transport_import_index(name)], name);
        }
    }

    #[test]
    fn form_and_body_renderers_cover_wrappers_headers_and_descriptor_shapes() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Items": { "type": "array", "items": { "type": "string" } }
                }
            }
        });
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let source_id = analyzed.ir.schemas[0].source.source_id.clone();
        let items_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id,
                json_pointer: "/components/schemas/Items".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let selected = content_field(
            "selected",
            items_ref.clone(),
            PartMediaPlan {
                values: vec!["application/json".to_owned(), "application/cbor".to_owned()],
                payloads: vec![PayloadKind::Json, PayloadKind::Text],
                all_concrete: true,
                binary_upload: false,
                declared: true,
            },
            FieldWrapperPlan {
                wrapped: true,
                content_type_literal: true,
                filename: false,
            },
        );
        let wildcard = content_field(
            "wildcard",
            string_schema(None),
            PartMediaPlan {
                values: vec!["text/*".to_owned()],
                payloads: vec![PayloadKind::Text],
                all_concrete: false,
                binary_upload: false,
                declared: true,
            },
            FieldWrapperPlan {
                wrapped: true,
                content_type_literal: false,
                filename: true,
            },
        );
        let binary = content_field(
            "binary",
            string_schema(Some("binary")),
            PartMediaPlan {
                values: vec!["application/octet-stream".to_owned()],
                payloads: vec![PayloadKind::Binary],
                all_concrete: true,
                binary_upload: true,
                declared: false,
            },
            FieldWrapperPlan {
                wrapped: false,
                content_type_literal: true,
                filename: false,
            },
        );
        let encoded = content_field(
            "encoded",
            string_schema(None),
            PartMediaPlan {
                values: vec!["application/octet-stream".to_owned()],
                payloads: vec![PayloadKind::Text],
                all_concrete: true,
                binary_upload: false,
                declared: false,
            },
            FieldWrapperPlan {
                wrapped: false,
                content_type_literal: true,
                filename: false,
            },
        );
        let styled_object = style_field("styled", object_schema());
        let styled_binary = style_field("styledBinary", string_schema(Some("binary")));
        let styled_text = style_field("styledText", string_schema(None));
        let fields = vec![
            selected.clone(),
            wildcard.clone(),
            binary,
            encoded,
            styled_object,
            styled_binary,
            styled_text,
        ];

        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        assert!(matches!(
            schema_array_items(&model, &items_ref, &mut HashSet::new()),
            Some(SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            })
        ));
        let mut visited: HashSet<_> = [(
            items_ref.meta().source.source_id.clone(),
            items_ref.meta().source.json_pointer.clone(),
        )]
        .into_iter()
        .collect();
        if let SchemaNode::Ref { target, .. } = &items_ref {
            visited.clear();
            visited.insert((target.source_id.clone(), target.json_pointer.clone()));
        }
        assert!(schema_array_items(&model, &items_ref, &mut visited).is_none());
        assert!(
            schema_array_items(
                &model,
                &SchemaNode::Array {
                    items: Box::new(string_schema(None)),
                    finite: None,
                    meta: SchemaMeta::default(),
                },
                &mut HashSet::new()
            )
            .is_some()
        );
        assert!(schema_array_items(&model, &string_schema(None), &mut HashSet::new()).is_none());

        let arm = |media: String, plan| crate::client_model::BodyPlanArm {
            media,
            plan,
            source: SourceRef::default(),
        };
        let body = BodyPlan::ContentTypeDiscriminated {
            arms: vec![
                arm(
                    "multipart/form-data".to_owned(),
                    BodyPlan::Multipart {
                        media: "multipart/form-data".to_owned(),
                        fields: fields.clone(),
                        source: SourceRef::default(),
                    },
                ),
                arm(
                    "application/x-www-form-urlencoded".to_owned(),
                    BodyPlan::FormUrlencoded {
                        media: "application/x-www-form-urlencoded".to_owned(),
                        fields: vec![
                            content_field(
                                "profile",
                                object_schema(),
                                PartMediaPlan {
                                    values: vec!["application/json".to_owned()],
                                    payloads: vec![PayloadKind::Json],
                                    all_concrete: true,
                                    binary_upload: false,
                                    declared: false,
                                },
                                FieldWrapperPlan {
                                    wrapped: false,
                                    content_type_literal: true,
                                    filename: false,
                                },
                            ),
                            content_field(
                                "icon",
                                string_schema(None),
                                PartMediaPlan {
                                    values: vec!["image/png".to_owned(), "image/jpeg".to_owned()],
                                    payloads: vec![PayloadKind::Text, PayloadKind::Text],
                                    all_concrete: true,
                                    binary_upload: false,
                                    declared: true,
                                },
                                FieldWrapperPlan {
                                    wrapped: true,
                                    content_type_literal: true,
                                    filename: false,
                                },
                            ),
                            content_field(
                                "raw",
                                string_schema(Some("binary")),
                                PartMediaPlan {
                                    values: vec!["application/octet-stream".to_owned()],
                                    payloads: vec![PayloadKind::Binary],
                                    all_concrete: true,
                                    binary_upload: true,
                                    declared: false,
                                },
                                FieldWrapperPlan {
                                    wrapped: false,
                                    content_type_literal: true,
                                    filename: false,
                                },
                            ),
                            style_field("form", string_schema(None)),
                        ],
                        source: SourceRef::default(),
                    },
                ),
                arm(
                    "application/json".to_owned(),
                    BodyPlan::Json {
                        media: "application/json".to_owned(),
                        schema: Some(object_schema()),
                        source: SourceRef::default(),
                    },
                ),
                arm(
                    "text/plain".to_owned(),
                    BodyPlan::TopLevelText {
                        media: "text/plain".to_owned(),
                        schema: Some(string_schema(None)),
                        source: SourceRef::default(),
                    },
                ),
                arm(
                    "application/octet-stream".to_owned(),
                    BodyPlan::TopLevelBinary {
                        media: "application/octet-stream".to_owned(),
                        schema: Some(string_schema(Some("binary"))),
                        source: SourceRef::default(),
                    },
                ),
            ],
            all_concrete: false,
        };
        assert!(body_uses_json_alias(&body));
        assert!(!body_uses_json_alias(&BodyPlan::Multipart {
            media: "multipart/form-data".to_owned(),
            fields: Vec::new(),
            source: SourceRef::default(),
        }));

        {
            let renderer = TypesEmitter::new(&model);
            let input =
                render_body_input(&renderer, &body, "Probe", 2, TypeAxis::Application, false);
            assert!(input.contains("contentType: string"));
            assert!(input.contains("filename?: string"));
            assert!(input.contains("Blob | File"));
            assert!(input.contains("encoded: string"));
            assert!(!input.contains("Items"));
            let mut imports = BTreeMap::new();
            collect_body_imports(&renderer, &body, TypeAxis::Application, &mut imports);
            let mut import_text = String::new();
            write_component_imports(
                &mut import_text,
                imports,
                &HashMap::new(),
                ".js",
                "client/operations/getpet.ts",
                "types",
            );
            assert!(import_text.is_empty(), "{import_text}");
        }
        let mut descriptor = String::new();
        write_body_descriptor(&mut descriptor, &model, &body, 2);
        assert!(descriptor.contains("discriminatedBody("));
        assert!(descriptor.contains("urlencodedBody(\"application/x-www-form-urlencoded\", ["));
        // The runtime multipart field plan carries no Content-Transfer-Encoding, so the descriptor
        // must emit neither the `cte:` key nor a header literal for it.
        assert!(!descriptor.contains("cte:"));
        assert!(!descriptor.contains("Content-Transfer-Encoding"));
        assert!(descriptor.contains("payload: \"json\""));
        assert!(descriptor.contains("payload: \"binary\""));
        assert!(descriptor.contains("payload: \"text\""));
        assert!(descriptor.contains(
            "{ name: \"encoded\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: { kind: \"fixed\", value: \"application/octet-stream\" }, filename: false }"
        ));
        // Urlencoded content fields: unwrapped fixed-json emits payloads only; a wrapped selected
        // field emits the admitted media list and per-media payload kinds; the Style arm is intact.
        assert!(descriptor.contains("{ name: \"profile\", required: true, payloads: [\"json\"] }"));
        assert!(descriptor.contains(
            "contentType: { kind: \"selected\", admitted: [\"image/png\", \"image/jpeg\"]"
        ));
        assert!(descriptor.contains("payloads: [\"text\", \"text\"]"));
        // The wrapped multipart `selected` field admits two media with heterogeneous payload kinds,
        // so its descriptor carries the index-aligned payloads array alongside the single `payload`.
        assert!(descriptor.contains(
            "contentType: { kind: \"selected\", admitted: [\"application/json\", \"application/cbor\"] }, payloads: [\"json\", \"text\"]"
        ));
        // An urlencoded field whose default media classifies as a binary upload (`PayloadKind::
        // Binary`) still renders through the same `payloads` array as the other content kinds.
        assert!(descriptor.contains("{ name: \"raw\", required: true, payloads: [\"binary\"] }"));
        assert!(descriptor.contains("style: \"deepObject\""));
    }

    #[test]
    fn client_emission_covers_optional_body_extension_and_missing_allocations() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/optional": {
                    "post": {
                        "operationId": "optionalBody",
                        "requestBody": {
                            "content": {
                                "text/plain": { "schema": { "type": "string" } }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, analyzed, mut config, _source_tuples) =
            analyzed_with_options(&document, false, true);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        config.emit.import_extension = "none".to_owned();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        let operation = files
            .iter()
            .find(|file| file.relative_path.starts_with("client/operations/"))
            .expect("operation");
        assert!(operation.content.contains("body?: string"));
        assert!(operation.content.contains("from \"../../runtime/result\""));

        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        model.operation_files[0] = None;
        let files = emit_client_from_model(&mut model, &client);
        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("client/operations/"))
        );

        let mut without_names = analyzed.clone();
        without_names.operation_names.clear();
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&without_names, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("client/operations/"))
        );

        let empty_document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {}
        });
        let (_temp, empty_analyzed, aggregate_config, _source_tuples) =
            analyzed_with_aggregate(&empty_document, true);
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(
            &empty_analyzed,
            &aggregate_config,
            "digest".to_owned(),
            &mut sink,
        );
        let files = emit_client_from_model(
            &mut model,
            &ClientModel {
                operations: Vec::new(),
                base_url_required: false,
            },
        );
        assert!(
            files
                .iter()
                .any(|file| file.relative_path == "client/api.ts")
        );
    }

    #[test]
    fn descriptor_covers_parameter_and_response_flags() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "descriptorProbe",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "query",
                                "required": true,
                                "allowReserved": true,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut plan = client.operations[0].clone();
        plan.base_url = BaseUrlPlan::Runtime;
        plan.response_table = vec![
            response_plan(
                "2XX",
                ResponseMatchKind::Range,
                PayloadDisposition::StaticBodyless,
                vec![response_media(
                    "application/octet-stream",
                    DecoderClass::Binary,
                )],
                true,
            ),
            response_plan(
                "default",
                ResponseMatchKind::Default,
                PayloadDisposition::NoPayload,
                vec![response_media("text/plain", DecoderClass::Text)],
                false,
            ),
        ];
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let mut output = String::new();
        write_descriptor(
            &mut output,
            &model,
            &analyzed.ir.operations[0],
            &plan,
            "descriptorProbe",
            &[],
            &[],
        );
        assert!(output.contains("allowReserved: true"));
        assert!(output.contains("bodyless: true"));
        assert!(output.contains("hasContentTypeDiscriminant: true"));
    }

    fn auth_scheme(name: &str, kind: AuthKind, scopes: &[&str]) -> AuthSchemeUse {
        AuthSchemeUse {
            name: name.to_owned(),
            kind,
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        }
    }

    #[test]
    fn security_field_renders_representative_plans() {
        assert_eq!(security_field(&[]), "null");

        let or_with_scopes: Vec<AuthAlternative> = vec![
            vec![auth_scheme(
                "headerKey",
                AuthKind::ApiKeyHeader {
                    name: "X-Api-Key".to_owned(),
                },
                &[],
            )],
            vec![auth_scheme("oauthFlow", AuthKind::OAuth2, &["scope.a"])],
        ];
        assert_eq!(
            security_field(&or_with_scopes),
            "authAlternatives([\n    [{ name: \"headerKey\", apply: headerKeyCredential, param: \"X-Api-Key\", scopes: [] }],\n    [{ name: \"oauthFlow\", apply: bearerCredential, scopes: [\"scope.a\"] }],\n  ])"
        );

        let and_plan: Vec<AuthAlternative> = vec![vec![
            auth_scheme("basicAuth", AuthKind::Basic, &[]),
            auth_scheme(
                "headerKey",
                AuthKind::ApiKeyHeader {
                    name: "X-Api-Key".to_owned(),
                },
                &[],
            ),
        ]];
        assert_eq!(
            security_field(&and_plan),
            "authAlternatives([\n    [{ name: \"basicAuth\", apply: basicCredential, scopes: [] }, { name: \"headerKey\", apply: headerKeyCredential, param: \"X-Api-Key\", scopes: [] }],\n  ])"
        );

        let anonymous_included: Vec<AuthAlternative> = vec![
            vec![auth_scheme("bearerAuth", AuthKind::Bearer, &[])],
            vec![],
        ];
        assert_eq!(
            security_field(&anonymous_included),
            "authAlternatives([\n    [{ name: \"bearerAuth\", apply: bearerCredential, scopes: [] }],\n    [],\n  ])"
        );
    }

    #[test]
    fn generic_http_scheme_renders_credential_type_and_descriptor() {
        let plan = vec![vec![auth_scheme(
            "digestAuth",
            AuthKind::HttpScheme {
                scheme: "Digest".to_owned(),
            },
            &[],
        )]];
        assert_eq!(
            render_call_args(&plan, AuthEnforcement::Types, "Digest"),
            "type Req = [options: CallOptions & { auth: { readonly digestAuth: { credentials: string } } }];\nexport type DigestCallArgs<S extends string> = [string] extends [S] ? Req : [\"digestAuth\" & S] extends [never] ? Req : [options?: CallOptions];\n"
        );
        assert_eq!(
            security_field(&plan),
            "authAlternatives([\n    [{ name: \"digestAuth\", apply: httpSchemeCredential, scheme: \"Digest\", scopes: [] }],\n  ])"
        );
    }

    #[test]
    fn mutual_tls_renders_ambient_credential_descriptor_and_import() {
        let plan = vec![vec![auth_scheme("mtls", AuthKind::MutualTls, &[])]];
        assert_eq!(
            render_call_args(&plan, AuthEnforcement::Types, "MutualTls"),
            "type Req = [options: CallOptions & { auth: { readonly mtls: typeof AmbientClientCertificate } }];\nexport type MutualTlsCallArgs<S extends string> = [string] extends [S] ? Req : [\"mtls\" & S] extends [never] ? Req : [options?: CallOptions];\n"
        );
        assert_eq!(
            security_field(&plan),
            "authAlternatives([\n    [{ name: \"mtls\", apply: mutualTlsCredential, scopes: [] }],\n  ])"
        );

        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": { "mtls": { "type": "mutualTLS" } }
            },
            "paths": {
                "/ping": {
                    "get": {
                        "operationId": "ping",
                        "security": [{ "mtls": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "ping");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(actual.contains(
            "import { authAlternatives, execute, executeOrThrow, mutualTlsCredential, type AmbientClientCertificate, type CallOptions, type OperationDescriptor, type Transport } from"
        ));
    }

    #[test]
    fn call_args_alias_types_mode() {
        // Single-member single-alternative: one named, S-independent `Req` tuple.
        let single_member: Vec<AuthAlternative> =
            vec![vec![auth_scheme("bearerAuth", AuthKind::Bearer, &[])]];
        assert_eq!(
            render_call_args(&single_member, AuthEnforcement::Types, "InheritedRootOnly"),
            "type Req = [options: CallOptions & { auth: { readonly bearerAuth: string } }];\nexport type InheritedRootOnlyCallArgs<S extends string> = [string] extends [S] ? Req : [\"bearerAuth\" & S] extends [never] ? Req : [options?: CallOptions];\n"
        );

        // Multi-alternative single-member each: `Req` is the union of both records; the chain nests
        // the second alternative's check in parentheses.
        let or_plan: Vec<AuthAlternative> = vec![
            vec![auth_scheme(
                "headerKey",
                AuthKind::ApiKeyHeader {
                    name: "X-Api-Key".to_owned(),
                },
                &[],
            )],
            vec![auth_scheme("oauthFlow", AuthKind::OAuth2, &["scope.a"])],
        ];
        assert_eq!(
            render_call_args(&or_plan, AuthEnforcement::Types, "OrHeaderOauth"),
            "type Req = [options: CallOptions & { auth: { readonly headerKey: string } | { readonly oauthFlow: string } }];\nexport type OrHeaderOauthCallArgs<S extends string> = [string] extends [S] ? Req : [\"headerKey\" & S] extends [never] ? ([\"oauthFlow\" & S] extends [never] ? Req : [options?: CallOptions]) : [options?: CallOptions];\n"
        );

        // AND (multi-member): the missing record depends on S, factored into `Missing<S>`.
        let and_plan: Vec<AuthAlternative> = vec![vec![
            auth_scheme("basicAuth", AuthKind::Basic, &[]),
            auth_scheme(
                "headerKey",
                AuthKind::ApiKeyHeader {
                    name: "X-Api-Key".to_owned(),
                },
                &[],
            ),
        ]];
        assert_eq!(
            render_call_args(&and_plan, AuthEnforcement::Types, "AndBasicHeader"),
            "type Missing<S extends string> = ([\"basicAuth\" & S] extends [never] ? { readonly basicAuth: BasicCredential } : { readonly basicAuth?: BasicCredential }) & ([\"headerKey\" & S] extends [never] ? { readonly headerKey: string } : { readonly headerKey?: string });\nexport type AndBasicHeaderCallArgs<S extends string> = [string] extends [S] ? [options: CallOptions & { auth: { readonly basicAuth: BasicCredential; readonly headerKey: string } }] : [\"basicAuth\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [\"headerKey\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [options?: CallOptions];\n"
        );

        // Anonymous alternative present: options always optional.
        let anonymous_included: Vec<AuthAlternative> = vec![
            vec![auth_scheme("bearerAuth", AuthKind::Bearer, &[])],
            vec![],
        ];
        assert_eq!(
            render_call_args(
                &anonymous_included,
                AuthEnforcement::Types,
                "AnonymousIncluded"
            ),
            "export type AnonymousIncludedCallArgs<_S extends string> = [options?: CallOptions];\n"
        );
    }

    #[test]
    fn call_args_mixes_single_and_multi_member_alternatives() {
        // A single-member alternative alongside an AND alternative: the single member's missing
        // record stays the concrete full record inside the `Missing<S>` union, and the chain
        // parenthesizes the second alternative's member checks.
        let mixed: Vec<AuthAlternative> = vec![
            vec![auth_scheme(
                "cookieKey",
                AuthKind::ApiKeyCookie {
                    name: "session".to_owned(),
                },
                &[],
            )],
            vec![
                auth_scheme("basicAuth", AuthKind::Basic, &[]),
                auth_scheme(
                    "queryKey",
                    AuthKind::ApiKeyQuery {
                        name: "api_key".to_owned(),
                    },
                    &[],
                ),
            ],
        ];
        assert_eq!(
            render_call_args(&mixed, AuthEnforcement::Types, "Mixed"),
            "type Missing<S extends string> = { readonly cookieKey: typeof AmbientCookieCredential } | ([\"basicAuth\" & S] extends [never] ? { readonly basicAuth: BasicCredential } : { readonly basicAuth?: BasicCredential }) & ([\"queryKey\" & S] extends [never] ? { readonly queryKey: string } : { readonly queryKey?: string });\nexport type MixedCallArgs<S extends string> = [string] extends [S] ? [options: CallOptions & { auth: { readonly cookieKey: typeof AmbientCookieCredential } | { readonly basicAuth: BasicCredential; readonly queryKey: string } }] : [\"cookieKey\" & S] extends [never] ? ([\"basicAuth\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [\"queryKey\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [options?: CallOptions]) : [options?: CallOptions];\n"
        );
    }

    #[test]
    fn security_field_covers_every_scheme_kind() {
        let plan: Vec<AuthAlternative> = vec![
            vec![
                auth_scheme("basicAuth", AuthKind::Basic, &[]),
                auth_scheme("bearerAuth", AuthKind::Bearer, &[]),
            ],
            vec![
                auth_scheme(
                    "headerKey",
                    AuthKind::ApiKeyHeader {
                        name: "X-Api-Key".to_owned(),
                    },
                    &[],
                ),
                auth_scheme(
                    "queryKey",
                    AuthKind::ApiKeyQuery {
                        name: "api_key".to_owned(),
                    },
                    &[],
                ),
                auth_scheme(
                    "cookieKey",
                    AuthKind::ApiKeyCookie {
                        name: "session".to_owned(),
                    },
                    &[],
                ),
            ],
            vec![auth_scheme("oauthFlow", AuthKind::OAuth2, &["scope.a"])],
            vec![auth_scheme("oidc", AuthKind::OpenIdConnect, &[])],
            vec![],
        ];
        assert_eq!(
            security_field(&plan),
            "authAlternatives([\n    [{ name: \"basicAuth\", apply: basicCredential, scopes: [] }, { name: \"bearerAuth\", apply: bearerCredential, scopes: [] }],\n    [{ name: \"headerKey\", apply: headerKeyCredential, param: \"X-Api-Key\", scopes: [] }, { name: \"queryKey\", apply: queryKeyCredential, param: \"api_key\", scopes: [] }, { name: \"cookieKey\", apply: cookieKeyCredential, param: \"session\", scopes: [] }],\n    [{ name: \"oauthFlow\", apply: bearerCredential, scopes: [\"scope.a\"] }],\n    [{ name: \"oidc\", apply: bearerCredential, scopes: [] }],\n    [],\n  ])"
        );
    }

    #[test]
    fn basic_and_cookie_schemes_extend_the_runtime_import() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "basicAuth": { "type": "http", "scheme": "basic" },
                    "cookieKey": { "type": "apiKey", "in": "cookie", "name": "session" }
                }
            },
            "paths": {
                "/ping": {
                    "get": {
                        "operationId": "ping",
                        "security": [{ "basicAuth": [], "cookieKey": [] }],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object" } } }
                            }
                        }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "ping");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(actual.contains(
            "import { authAlternatives, basicCredential, cookieKeyCredential, execute, executeOrThrow, type AmbientCookieCredential, type BasicCredential, type CallOptions, type OperationDescriptor, type Transport } from"
        ));
    }

    fn emit_auth_module(document: Value) -> (Option<String>, Vec<Diagnostic>) {
        let (_temp, analyzed, config, _source_tuples) =
            analyzed_with_options(&document, false, false);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
        let content = files
            .iter()
            .find(|file| file.relative_path == "client/auth.ts")
            .map(|file| file.content.clone());
        (content, sink.into_sorted_vec())
    }

    #[test]
    fn document_auth_providers_renders_scoped_oauth2_and_plain_others() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "oauthScheme": { "type": "oauth2", "flows": { "authorizationCode": {
                        "authorizationUrl": "https://auth.example.test/authorize",
                        "tokenUrl": "https://auth.example.test/token",
                        "scopes": { "scope.a": "A", "scope.b": "B" }
                    } } },
                    "bearerScheme": { "type": "http", "scheme": "bearer" },
                    "keyScheme": { "type": "apiKey", "in": "header", "name": "X-Api-Key" },
                    "oidcScheme": { "type": "openIdConnect", "openIdConnectUrl": "https://idp.example.test/.well-known/openid-configuration" }
                }
            },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "security": [
                    { "oauthScheme": ["scope.a"] },
                    { "bearerScheme": [] },
                    { "keyScheme": [] },
                    { "oidcScheme": [] }
                ],
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            actual.expect("auth module"),
            format!(
                "{HEADER}import type {{ AuthProvider }} from \"../runtime/transport.js\";\n\nexport interface DocumentAuthProviders {{\n  oauthScheme: AuthProvider<\"scope.a\" | \"scope.b\">;\n  bearerScheme: AuthProvider;\n  keyScheme: AuthProvider;\n  oidcScheme: AuthProvider;\n}}\n"
            )
        );
    }

    #[test]
    fn document_auth_provider_includes_undeclared_required_oauth_scope() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "oauthScheme": { "type": "oauth2", "flows": { "authorizationCode": {
                        "authorizationUrl": "https://auth.example.test/authorize",
                        "tokenUrl": "https://auth.example.test/token",
                        "scopes": { "scope.a": "A" }
                    } } }
                }
            },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "security": [{ "oauthScheme": ["scope.missing"] }],
                "responses": { "200": { "description": "ok" } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "OASTS5408");
        assert_eq!(diagnostics[0].severity, Severity::Warning);
        assert_eq!(
            actual.expect("auth module"),
            format!(
                "{HEADER}import type {{ AuthProvider }} from \"../runtime/transport.js\";\n\nexport interface DocumentAuthProviders {{\n  oauthScheme: AuthProvider<\"scope.a\" | \"scope.missing\">;\n}}\n"
            )
        );
    }

    #[test]
    fn bearer_format_renders_as_remarks_tsdoc() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" }
                }
            },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "security": [{ "bearerAuth": [] }],
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            actual.expect("auth module"),
            format!(
                "{HEADER}import type {{ AuthProvider }} from \"../runtime/transport.js\";\n\nexport interface DocumentAuthProviders {{\n  /**\n   * @remarks\n   * Bearer token format: JWT\n   */\n  bearerAuth: AuthProvider;\n}}\n"
            )
        );
    }

    #[test]
    fn empty_declared_scopes_renders_plain_provider() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "oauthScheme": { "type": "oauth2", "flows": { "authorizationCode": {
                        "authorizationUrl": "https://auth.example.test/authorize",
                        "tokenUrl": "https://auth.example.test/token",
                        "scopes": {}
                    } } }
                }
            },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "security": [{ "oauthScheme": [] }],
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            actual.expect("auth module"),
            format!(
                "{HEADER}import type {{ AuthProvider }} from \"../runtime/transport.js\";\n\nexport interface DocumentAuthProviders {{\n  oauthScheme: AuthProvider;\n}}\n"
            )
        );
    }

    #[test]
    fn schemeless_document_emits_no_auth_module() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            actual.is_none(),
            "expected no client/auth.ts, got {actual:?}"
        );
    }

    #[test]
    fn auth_module_deterministic_order() {
        // Declared in components as zulu, alpha, mike; referenced by the operation in a different
        // order (mike, zulu, alpha). The module must follow scheme-declaration order, not
        // reference order and not alphabetical order.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "securitySchemes": {
                    "zulu": { "type": "http", "scheme": "bearer" },
                    "alpha": { "type": "apiKey", "in": "header", "name": "X-Alpha" },
                    "mike": { "type": "apiKey", "in": "header", "name": "X-Mike" }
                }
            },
            "paths": { "/ping": { "get": {
                "operationId": "ping",
                "security": [{ "mike": [] }, { "zulu": [] }, { "alpha": [] }],
                "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
            } } }
        });
        let (actual, diagnostics) = emit_auth_module(document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            actual.expect("auth module"),
            format!(
                "{HEADER}import type {{ AuthProvider }} from \"../runtime/transport.js\";\n\nexport interface DocumentAuthProviders {{\n  zulu: AuthProvider;\n  alpha: AuthProvider;\n  mike: AuthProvider;\n}}\n"
            )
        );
    }

    #[test]
    fn call_args_quotes_non_identifier_scheme_names() {
        // Security scheme names are arbitrary component-map keys: a kebab-case name must emit a
        // quoted property key and a correctly escaped string-literal type, in both the concrete
        // and the per-member conditional record shapes.
        let kebab: Vec<AuthAlternative> = vec![vec![auth_scheme("api-key", AuthKind::Bearer, &[])]];
        assert_eq!(
            render_call_args(&kebab, AuthEnforcement::Types, "Kebab"),
            "type Req = [options: CallOptions & { auth: { readonly \"api-key\": string } }];\nexport type KebabCallArgs<S extends string> = [string] extends [S] ? Req : [\"api-key\" & S] extends [never] ? Req : [options?: CallOptions];\n"
        );

        let mixed_and: Vec<AuthAlternative> = vec![vec![
            auth_scheme("api-key", AuthKind::Bearer, &[]),
            auth_scheme("plain", AuthKind::Basic, &[]),
        ]];
        assert_eq!(
            render_call_args(&mixed_and, AuthEnforcement::Types, "KebabAnd"),
            "type Missing<S extends string> = ([\"api-key\" & S] extends [never] ? { readonly \"api-key\": string } : { readonly \"api-key\"?: string }) & ([\"plain\" & S] extends [never] ? { readonly plain: BasicCredential } : { readonly plain?: BasicCredential });\nexport type KebabAndCallArgs<S extends string> = [string] extends [S] ? [options: CallOptions & { auth: { readonly \"api-key\": string; readonly plain: BasicCredential } }] : [\"api-key\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [\"plain\" & S] extends [never] ? [options: CallOptions & { auth: Missing<S> }] : [options?: CallOptions];\n"
        );
    }

    #[test]
    fn call_args_alias_runtime_mode_is_unconditional() {
        let secured: Vec<AuthAlternative> =
            vec![vec![auth_scheme("bearerAuth", AuthKind::Bearer, &[])]];
        assert_eq!(
            render_call_args(&secured, AuthEnforcement::Runtime, "InheritedRootOnly"),
            "export type InheritedRootOnlyCallArgs<_S extends string> = [options?: CallOptions];\n"
        );
    }

    #[test]
    fn generic_wrapper_signature_threads_transport_and_call_args() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/ping": {
                    "get": {
                        "operationId": "ping",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object" } } }
                            }
                        }
                    }
                }
            }
        });
        let (actual, diagnostics) = emit_operation(document, "ping");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(actual.contains(
            "export async function ping<S extends string = never>(transport: Transport<S>, input: PingInput, ...args: PingCallArgs<S>): Promise<PingResult> {\n  return execute<PingResult>(transport, descriptor, input, args[0]);\n}"
        ));
        assert!(actual.contains(
            "export async function pingOrThrow<S extends string = never>(transport: Transport<S>, input: PingInput, ...args: PingCallArgs<S>): Promise<"
        ));
        assert!(
            actual
                .contains("export type PingCallArgs<_S extends string> = [options?: CallOptions];")
        );
    }

    /// Two bindings an operation module emitted unconditionally and did not always read. Both are
    /// errors in a consumer compiling generated code with `noUnusedLocals`/`noUnusedParameters`,
    /// which is a bar this repo's own `--strict` gate does not reach.
    #[test]
    fn unread_kernel_import_and_scheme_parameter_are_not_emitted() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "security": [{ "bearerAuth": [] }],
            "paths": {
                "/open": {
                    "get": {
                        "operationId": "readOpen",
                        "security": [],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object" } } }
                            }
                        }
                    }
                },
                "/secured": {
                    "get": {
                        "operationId": "readSecured",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object" } } }
                            }
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": { "bearerAuth": { "type": "http", "scheme": "bearer" } }
            }
        });

        // Nothing bound: the orThrow variant really does call the runtime entry point.
        let (unbound, diagnostics) = emit_operation(document.clone(), "readopen");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(unbound.contains("executeOrThrow"));
        // No auth-conditional tuple, so the scheme parameter is declared and never read.
        assert!(
            unbound.contains(
                "export type ReadOpenCallArgs<_S extends string> = [options?: CallOptions];"
            ),
            "{unbound}"
        );

        // Response validation bound: orThrow goes through `unwrap` over the base function instead,
        // so the runtime entry point is never named and must not be imported.
        let bound = emit_validated_operation(document.clone(), "readopen", false, true);
        assert!(!bound.contains("executeOrThrow"), "{bound}");
        assert!(bound.contains("import { unwrap } from"), "{bound}");

        // The secured operation is the contrast: its tuple reads the parameter, so it keeps the
        // plain name and every reference to it still resolves.
        let (secured, diagnostics) = emit_operation(document, "readsecured");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            secured.contains(
                "export type ReadSecuredCallArgs<S extends string> = [string] extends [S] ?"
            ),
            "{secured}"
        );
        assert!(!secured.contains("ReadSecuredCallArgs<_S"), "{secured}");
    }

    // --- generated validation binding ----------------------------------------------------------

    /// Emits every client file with the validators artifact enabled and the generated engine bound
    /// to the given request/response directions, returning the files and sorted diagnostics. Errors
    /// are not asserted away, so callers can cover diagnosed-but-still-emitted shapes.
    fn emit_validated_files(
        document: &Value,
        request: bool,
        response: bool,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        emit_validation_files(document, request, response, "generated")
    }

    fn emit_validation_files(
        document: &Value,
        request: bool,
        response: bool,
        engine: &str,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec_pretty(document).expect("document JSON"),
        )
        .expect("document");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated",
            "artifacts": {
                "types": true,
                "client": true,
                "validators": engine == "generated",
                "zod": engine == "zod"
            },
            "client": {
                "authEnforcement": "types",
                "baseUrl": { "source": "literal", "value": "https://api.example.test/v1" }
            },
            "validation": {
                "engine": engine,
                "request": request,
                "response": response,
                "unchecked": "allow"
            }
        });
        let config = load_config_from_json(
            &temp.path().join("oasts.json"),
            &serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("graph");
        let source_tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("IR");
        let analyzed = analyze(ir, &config, &mut sink);
        let client = build_client_model(&analyzed, &config, &mut sink);
        let files = emit_artifacts(&analyzed, &config, &source_tuples, Some(&client), &mut sink);
        (files, sink.into_sorted_vec())
    }

    /// Emits one client operation file with generated validation bound, asserting a clean compile.
    fn emit_validated_operation(
        document: Value,
        suffix: &str,
        request: bool,
        response: bool,
    ) -> String {
        let (files, diagnostics) = emit_validated_files(&document, request, response);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        operation_file(&files, suffix)
    }

    fn operation_file(files: &[GeneratedFile], suffix: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("client/operations/{suffix}.ts"))
            .expect("operation file")
            .content
            .clone()
    }

    fn generated_file(files: &[GeneratedFile], relative_path: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == relative_path)
            .expect("generated file")
            .content
            .clone()
    }

    fn parameter_operation_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things/{id}": {
                    "get": {
                        "operationId": "readthing",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1 } },
                            { "name": "X-Tag", "in": "header", "required": false, "schema": { "type": "string" } }
                        ],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object", "properties": { "value": { "type": "string" } } } } }
                            }
                        }
                    }
                }
            }
        })
    }

    fn body_and_branches_document(body_required: bool) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/make": {
                    "post": {
                        "operationId": "makething",
                        "requestBody": {
                            "required": body_required,
                            "content": { "application/json": { "schema": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string" } } } } }
                        },
                        "responses": {
                            "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } } } } } },
                            "4XX": { "description": "client error", "content": { "application/json": { "schema": { "type": "object", "properties": { "code": { "type": "integer" } } } } } },
                            "default": { "description": "unexpected", "content": { "application/json": { "schema": { "type": "object", "properties": { "code": { "type": "integer" } } } } } }
                        }
                    }
                }
            }
        })
    }

    fn optional_body_bodyless_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/save": {
                    "put": {
                        "operationId": "savething",
                        "requestBody": {
                            "required": false,
                            "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" } } } } }
                        },
                        "responses": { "204": { "description": "saved" } }
                    }
                }
            }
        })
    }

    #[test]
    fn engine_off_leaves_the_operation_bytes_unwrapped() {
        // With the engine off the client is byte-identical to today: no validator imports, no issue
        // buffers, and both functions delegate straight to the runtime.
        let (content, diagnostics) = emit_operation(parameter_operation_document(), "readthing");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(content.contains(
            "export async function readthing<S extends string = never>(transport: Transport<S>, input: ReadthingInput, ...args: ReadthingCallArgs<S>): Promise<ReadthingResult> {\n  return execute<ReadthingResult>(transport, descriptor, input, args[0]);\n}"
        ));
        assert!(content.contains(
            "export async function readthingOrThrow<S extends string = never>(transport: Transport<S>, input: ReadthingInput, ...args: ReadthingCallArgs<S>): Promise<{ data: ReadthingResponse200; meta: ResponseMeta }> {\n  return executeOrThrow<ReadthingResult>(transport, descriptor, input, args[0]);\n}"
        ));
        assert!(!content.contains("Issue"));
        assert!(!content.contains("validators/"));
        assert!(!content.contains("requestIssues"));
        assert!(!content.contains("unwrap"));
    }

    #[test]
    fn request_validation_guards_parameters_across_locations_and_omits_the_response_block() {
        let content =
            emit_validated_operation(parameter_operation_document(), "readthing", true, false);
        assert!(content.contains(
            r#"export async function readthing<S extends string = never>(transport: Transport<S>, input: ReadthingInput, ...args: ReadthingCallArgs<S>): Promise<ReadthingResult> {
  const requestIssues: Issue[] = [];
  if (input.path?.id !== undefined) {
    validateReadthingPathId(input.path?.id, ["path", "id"], requestIssues);
  }
  if (input.query?.limit !== undefined) {
    validateReadthingQueryLimit(input.query?.limit, ["query", "limit"], requestIssues);
  }
  if (input.header?.["X-Tag"] !== undefined) {
    validateReadthingHeaderXTag(input.header?.["X-Tag"], ["header", "X-Tag"], requestIssues);
  }
  if (requestIssues.length > 0) {
    return { outcome: "request-validation", ok: false, issues: requestIssues };
  }
  return execute<ReadthingResult>(transport, descriptor, input, args[0]);
}"#
        ), "base function mismatch:\n{content}");
        // Response validation is off: no post-dispatch block, and the response validator stays unimported.
        assert!(!content.contains("const result = await execute"));
        assert!(!content.contains("validateReadthingResponse200"));
        assert!(content.contains("import type { Issue } from \"../../validators/runtime.js\";"));
        assert!(content.contains("import { unwrap } from \"../../runtime/result.js\";"));
        assert!(content.contains(
            "import { validateReadthingHeaderXTag, validateReadthingPathId, validateReadthingQueryLimit } from \"../../validators/operations/readthing.js\";"
        ));
        assert!(content.contains(
            "export async function readthingOrThrow<S extends string = never>(transport: Transport<S>, input: ReadthingInput, ...args: ReadthingCallArgs<S>): Promise<{ data: ReadthingResponse200; meta: ResponseMeta }> {\n  return unwrap(await readthing(transport, input, ...args));\n}"
        ));
    }

    #[test]
    fn response_validation_wraps_the_documented_branch_and_omits_the_request_block() {
        let content =
            emit_validated_operation(parameter_operation_document(), "readthing", false, true);
        assert!(content.contains(
            r#"export async function readthing<S extends string = never>(transport: Transport<S>, input: ReadthingInput, ...args: ReadthingCallArgs<S>): Promise<ReadthingResult> {
  const result = await execute<ReadthingResult>(transport, descriptor, input, args[0]);
  if (result.outcome === 200) {
    const responseIssues: Issue[] = [];
    validateReadthingResponse200(result.data, [], responseIssues);
    if (responseIssues.length > 0) {
      return { outcome: "response-validation", ok: false, match: result.outcome, status: result.status, issues: responseIssues, meta: result.meta };
    }
  }
  return result;
}"#
        ), "base function mismatch:\n{content}");
        // Request validation is off: no pre-dispatch block, and no parameter validators are imported.
        assert!(!content.contains("requestIssues"));
        assert!(!content.contains("validateReadthingPathId"));
        assert!(content.contains(
            "import { validateReadthingResponse200 } from \"../../validators/operations/readthing.js\";"
        ));
    }

    #[test]
    fn request_and_response_validation_wrap_parameters_and_the_response_together() {
        let content =
            emit_validated_operation(parameter_operation_document(), "readthing", true, true);
        assert!(
            content.contains(
                r#"  const requestIssues: Issue[] = [];
  if (input.path?.id !== undefined) {
    validateReadthingPathId(input.path?.id, ["path", "id"], requestIssues);
  }"#
            ),
            "request block mismatch:\n{content}"
        );
        assert!(content.contains(
            r#"  const result = await execute<ReadthingResult>(transport, descriptor, input, args[0]);
  if (result.outcome === 200) {
    const responseIssues: Issue[] = [];
    validateReadthingResponse200(result.data, [], responseIssues);"#
        ), "response block mismatch:\n{content}");
        assert!(content.contains(
            "import { validateReadthingHeaderXTag, validateReadthingPathId, validateReadthingQueryLimit, validateReadthingResponse200 } from \"../../validators/operations/readthing.js\";"
        ));
    }

    #[test]
    fn request_and_response_validation_wrap_a_required_body_and_a_default_branch() {
        let content =
            emit_validated_operation(body_and_branches_document(true), "makething", true, true);
        // A required body is validated unconditionally; the default branch selects data vs error on ok.
        assert!(content.contains(
            r#"export async function makething<S extends string = never>(transport: Transport<S>, input: MakethingInput, ...args: MakethingCallArgs<S>): Promise<MakethingResult> {
  const requestIssues: Issue[] = [];
  validateMakethingRequestBody(input.body, ["body"], requestIssues);
  if (requestIssues.length > 0) {
    return { outcome: "request-validation", ok: false, issues: requestIssues };
  }
  const result = await execute<MakethingResult>(transport, descriptor, input, args[0]);
  if (result.outcome === 200 || result.outcome === "4XX" || result.outcome === "default") {
    const responseIssues: Issue[] = [];
    if (result.outcome === 200) {
      validateMakethingResponse200(result.data, [], responseIssues);
    } else if (result.outcome === "4XX") {
      validateMakethingResponse4XX(result.error, [], responseIssues);
    } else if (result.outcome === "default") {
      if (result.ok) {
        validateMakethingResponseDefault(result.data, [], responseIssues);
      } else {
        validateMakethingResponseDefault(result.error, [], responseIssues);
      }
    }
    if (responseIssues.length > 0) {
      return { outcome: "response-validation", ok: false, match: result.outcome, status: result.status, issues: responseIssues, meta: result.meta };
    }
  }
  return result;
}"#
        ), "base function mismatch:\n{content}");
        assert!(content.contains(
            "export async function makethingOrThrow<S extends string = never>(transport: Transport<S>, input: MakethingInput, ...args: MakethingCallArgs<S>): Promise<{ data: MakethingResponse200; meta: ResponseMeta } | { data: MakethingResponseDefault; meta: ResponseMeta }> {\n  return unwrap(await makething(transport, input, ...args));\n}"
        ));
    }

    #[test]
    fn an_optional_body_is_presence_guarded_and_a_bodyless_response_is_skipped() {
        let content =
            emit_validated_operation(optional_body_bodyless_document(), "savething", true, true);
        // Optional body → presence guard; the 204 branch carries no JSON body, so response validation
        // adds nothing and the function returns the raw execute result.
        assert!(content.contains(
            r#"export async function savething<S extends string = never>(transport: Transport<S>, input: SavethingInput, ...args: SavethingCallArgs<S>): Promise<SavethingResult> {
  const requestIssues: Issue[] = [];
  if (input.body !== undefined) {
    validateSavethingRequestBody(input.body, ["body"], requestIssues);
  }
  if (requestIssues.length > 0) {
    return { outcome: "request-validation", ok: false, issues: requestIssues };
  }
  return execute<SavethingResult>(transport, descriptor, input, args[0]);
}"#
        ), "base function mismatch:\n{content}");
        assert!(!content.contains("const result = await execute"));
        assert!(content.contains(
            "import { validateSavethingRequestBody } from \"../../validators/operations/savething.js\";"
        ));
    }

    // --- non-JSON request bodies ---------------------------------------------------------------

    /// A form-urlencoded body with a required and an optional field, a multipart body mixing a
    /// value field, a binary upload and a wrapped field, and a content-type-discriminated body with
    /// one JSON arm and one text arm. One document so the cross-artifact check covers every shape.
    fn non_json_bodies_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/form": {
                    "post": {
                        "operationId": "sendform",
                        "requestBody": {
                            "required": true,
                            "content": { "application/x-www-form-urlencoded": { "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": { "type": "string", "minLength": 1 },
                                    "tag list": { "type": "array", "items": { "type": "string" } },
                                    "tag-list": { "type": "array", "items": { "type": "string" } },
                                    "***": { "type": "string" }
                                }
                            } } }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/upload": {
                    "post": {
                        "operationId": "sendupload",
                        "requestBody": {
                            "required": false,
                            "content": { "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["meta"],
                                    "properties": {
                                        "meta": { "type": "object", "properties": { "label": { "type": "string" } } },
                                        "file": { "type": "string", "format": "binary" },
                                        "note": { "type": "object", "properties": { "text": { "type": "string" } } },
                                        "extra note": { "type": "string" }
                                    }
                                },
                                "encoding": {
                                    "meta": { "contentType": "application/json" },
                                    "note": { "contentType": "application/json, application/xml" }
                                }
                            } }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/either": {
                    "post": {
                        "operationId": "sendeither",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": { "schema": { "type": "object", "properties": { "a": { "type": "string" } } } },
                                "text/plain": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/blob": {
                    "post": {
                        "operationId": "sendblob",
                        "requestBody": {
                            "required": true,
                            "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } } }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/empty": {
                    "post": {
                        "operationId": "sendempty",
                        "requestBody": { "required": true, "content": {} },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        })
    }

    #[test]
    fn a_body_with_no_schema_value_carries_no_validator() {
        // A binary body is a `Blob`, and an empty content map plans nothing at all; neither carries
        // a schema a validator could check, so neither emits a check or a declaration.
        let (files, diagnostics) = emit_validated_files(&non_json_bodies_document(), true, false);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        for operation in ["sendblob", "sendempty"] {
            let content = operation_file(&files, operation);
            assert!(
                !content.contains("requestIssues"),
                "{operation}:\n{content}"
            );
        }
    }

    #[test]
    fn form_fields_are_validated_individually_and_guarded_by_requiredness() {
        let content = emit_validated_operation(non_json_bodies_document(), "sendform", true, false);
        // One validator per field, reached through the body rather than applied to it. The required
        // field is always sent, so it is unguarded; the optional one is presence-guarded, and its
        // non-identifier key is bracket-accessed exactly as a parameter's would be.
        assert!(
            content.contains(
                r#"  const requestIssues: Issue[] = [];
  validateSendformRequestBodyName(input.body.name, ["body", "name"], requestIssues);
  if (input.body["tag list"] !== undefined) {
    validateSendformRequestBodyTagList(input.body["tag list"], ["body", "tag list"], requestIssues);
  }
"#
            ),
            "form field checks mismatch:\n{content}"
        );
        // The body itself carries no validator: a form body has no schema of its own to check.
        assert!(
            !content.contains("validateSendformRequestBody("),
            "{content}"
        );
        // `tag list` and `tag-list` collapse onto one identifier under Pascal normalization, so the
        // later field takes a bumped suffix and each name still describes its own field. A key with
        // no identifier content at all falls back to its position instead.
        assert!(
            content.contains(
                r#"  if (input.body["tag-list"] !== undefined) {
    validateSendformRequestBodyTagList2(input.body["tag-list"], ["body", "tag-list"], requestIssues);
  }
  if (input.body["***"] !== undefined) {
    validateSendformRequestBodyField3(input.body["***"], ["body", "***"], requestIssues);
  }"#
            ),
            "collision and fallback naming mismatch:\n{content}"
        );
    }

    #[test]
    fn a_multipart_binary_upload_carries_no_validator_and_an_optional_body_chains() {
        let (files, diagnostics) = emit_validated_files(&non_json_bodies_document(), true, false);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let content = operation_file(&files, "sendupload");
        // The body is optional, so every field access optional-chains through it — which is why the
        // required `meta` field is still guarded. A wrapped field renders `{ body, contentType }`,
        // so its validator applies to the payload and its issue path names that hop.
        assert!(
            content.contains(
                r#"  const requestIssues: Issue[] = [];
  if (input.body?.meta !== undefined) {
    validateSenduploadRequestBodyMeta(input.body?.meta, ["body", "meta"], requestIssues);
  }
  if (input.body?.note?.body !== undefined) {
    validateSenduploadRequestBodyNote(input.body?.note?.body, ["body", "note", "body"], requestIssues);
  }
"#
            ),
            "multipart checks mismatch:\n{content}"
        );
        // `file` renders `Blob | File`, which carries no schema value — neither called nor declared.
        assert!(!content.contains("RequestBodyFile"), "{content}");
        let validators = generated_file(&files, "validators/operations/sendupload.ts");
        assert!(!validators.contains("RequestBodyFile"), "{validators}");
        // The wrapper object is never itself validated, only its payload.
        assert!(
            !content.contains("validateSenduploadRequestBodyNote(input.body?.note,"),
            "{content}"
        );
        // A non-identifier key under an optional body takes the optional element access: `x.["k"]`
        // is not TypeScript, `x?.["k"]` is.
        assert!(
            content.contains(
                r#"  if (input.body?.["extra note"] !== undefined) {
    validateSenduploadRequestBodyExtraNote(input.body?.["extra note"], ["body", "extra note"], requestIssues);
  }"#
            ),
            "optional bracket access mismatch:\n{content}"
        );
    }

    #[test]
    fn a_repeated_wrapped_multipart_field_validates_the_wrapper_bodies() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/upload": {
                    "post": {
                        "operationId": "upload",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["metas"],
                                        "properties": {
                                            "metas": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": { "tag": { "type": "string" } }
                                                }
                                            }
                                        }
                                    },
                                    "encoding": {
                                        "metas": {
                                            "contentType": "application/json, application/cbor"
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let content = emit_validated_operation(document, "upload", true, false);

        assert!(
            content.contains(
                "validateUploadRequestBodyMetas(input.body.metas.map((item) => item.body), [\"body\", \"metas\"], requestIssues);"
            ),
            "repeated wrapper validation mismatch:\n{content}"
        );
    }

    #[test]
    fn an_optional_repeated_wrapped_form_field_validates_when_present() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/submit": {
                    "post": {
                        "operationId": "submit",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "dates": {
                                                "type": "array",
                                                "items": {
                                                    "type": "string",
                                                    "format": "date-time"
                                                }
                                            }
                                        }
                                    },
                                    "encoding": {
                                        "dates": {
                                            "contentType": "application/json, application/cbor"
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let content = emit_validated_operation(document, "submit", true, false);

        assert!(
            content.contains(
                "input.body.dates?.map((item) => item.body), [\"body\", \"dates\"], requestIssues);"
            ),
            "optional repeated wrapper validation mismatch:\n{content}"
        );
    }

    #[test]
    fn a_discriminated_body_validates_its_json_arm_under_the_content_type() {
        let content =
            emit_validated_operation(non_json_bodies_document(), "sendeither", true, false);
        // The arm is selected by `contentType`, not by presence — the test already implies the body
        // is there — and the payload sits under `.body`, mirroring the response side.
        assert!(
            content.contains(
                r#"  const requestIssues: Issue[] = [];
  if (input.body.contentType === "application/json") {
    validateSendeitherRequestBody(input.body.body, ["body", "body"], requestIssues);
  }
"#
            ),
            "discriminated checks mismatch:\n{content}"
        );
        // A lone JSON arm keeps the bare name, and the `text/plain` arm carries no validator at all.
        assert!(!content.contains("TextPlain"), "{content}");
    }

    #[test]
    fn every_request_body_validator_the_client_calls_is_declared() {
        // The invariant the shared position function exists to hold: the client emits the calls and
        // the validators artifact emits the declarations, from one derivation. A drift between them
        // emits TypeScript that imports a function nobody exported.
        let (files, diagnostics) = emit_validated_files(&non_json_bodies_document(), true, false);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        /// Every `RequestBody` validator name following `marker` in `content`.
        fn names(content: &str, marker: &str) -> BTreeSet<String> {
            content
                .match_indices(marker)
                .map(|(index, _)| {
                    let rest = &content[index + marker.len()..];
                    let end = rest
                        .find(|byte: char| !byte.is_ascii_alphanumeric())
                        .unwrap_or(rest.len());
                    rest[..end].to_owned()
                })
                .filter(|name| name.contains("RequestBody"))
                .collect()
        }
        let mut called = BTreeSet::new();
        let mut declared = BTreeSet::new();
        for file in &files {
            if file.relative_path.starts_with("client/operations/") {
                called.extend(names(&file.content, "validate"));
            } else if file.relative_path.starts_with("validators/operations/") {
                declared.extend(names(&file.content, "export function validate"));
            }
        }
        // Pinned by count, not just non-emptiness: a subset check passes vacuously if a change ever
        // drops every body position, which is the regression this test exists to catch. Four form
        // fields, three multipart fields, one discriminated JSON arm.
        assert_eq!(called.len(), 8, "{called:?}");
        // Computed eagerly rather than inside the message: an argument only evaluated on failure is
        // never executed by a passing run, and would read as a permanently uncovered line.
        let undeclared = called.difference(&declared).collect::<Vec<_>>();
        assert!(
            undeclared.is_empty(),
            "client calls validators nobody declared: {undeclared:?}"
        );
    }

    /// `text/json` is an ordinary `text/*` media, so it must emit exactly what `text/plain` emits.
    ///
    /// It used to emit something else: the compiler's JSON test accepted `text/json` while
    /// `build_body_plan` did not, so the body rendered `string` while a validator was still
    /// exported for the declared schema — an export nothing could call, because validating a
    /// string against that schema would check the wrong value. Asserting equality against
    /// `text/plain` rather than asserting the absence of that export is deliberate: it pins the
    /// two paths together, so a future rule that special-cases `text/json` again fails here
    /// whichever direction it drifts.
    #[test]
    fn a_text_json_body_emits_exactly_what_a_text_plain_body_emits() {
        let document = |media: &str| {
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": { "/json": { "post": {
                    "operationId": "sendtext",
                    "requestBody": {
                        "required": true,
                        "content": { media: { "schema": { "type": "string" } } }
                    },
                    "responses": { "204": { "description": "ok" } }
                } } }
            })
        };

        let (json_files, json_diagnostics) =
            emit_validated_files(&document("text/json"), true, false);
        let (plain_files, plain_diagnostics) =
            emit_validated_files(&document("text/plain"), true, false);

        assert!(json_diagnostics.is_empty(), "{json_diagnostics:#?}");
        assert!(plain_diagnostics.is_empty(), "{plain_diagnostics:#?}");
        assert_eq!(
            json_files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            plain_files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>()
        );
        // The provenance header carries a digest of the document's own bytes, which differ by the
        // media string under test and nothing else.
        let without_digest = |content: String| {
            content
                .lines()
                .filter(|line| !line.starts_with("// Source digest:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            without_digest(
                operation_file(&json_files, "sendtext").replace("text/json", "text/plain")
            ),
            without_digest(operation_file(&plain_files, "sendtext"))
        );
    }

    #[test]
    fn request_validation_binds_a_cookie_parameter() {
        // A cookie parameter is a first-class fetch-client parameter: its request binding validates
        // it in declared order under the `cookie` input group, after the query parameter.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "listthing",
                        "parameters": [
                            { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1 } },
                            { "name": "session", "in": "cookie", "required": false, "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_validated_files(&document, true, false);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let content = operation_file(&files, "listthing");
        assert!(
            content.contains(
                r#"  const requestIssues: Issue[] = [];
  if (input.query?.limit !== undefined) {
    validateListthingQueryLimit(input.query?.limit, ["query", "limit"], requestIssues);
  }
  if (input.cookie?.session !== undefined) {
    validateListthingCookieSession(input.cookie?.session, ["cookie", "session"], requestIssues);
  }
  if (requestIssues.length > 0) {
    return { outcome: "request-validation", ok: false, issues: requestIssues };
  }
  return execute<ListthingResult>(transport, descriptor, input, args[0]);"#
            ),
            "request block mismatch:\n{content}"
        );
        assert!(content.contains("validateListthingCookieSession"));
    }

    #[test]
    fn a_response_with_no_json_media_binds_no_body_validator() {
        // A payload branch whose declared media is text only: there is no JSON schema to check, so
        // the branch contributes no body validator — but its header validator still binds, which is
        // what keeps the branch in the emitted check list at all.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/note": {
                    "get": {
                        "operationId": "readnote",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "headers": { "X-Trace": { "schema": { "type": "string" } } },
                                "content": { "text/plain": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            }
        });
        let content = emit_validated_operation(document, "readnote", false, true);
        assert!(
            content.contains(
                r#"  if (result.outcome === 200) {
    const responseIssues: Issue[] = [];
    validateReadnoteResponse200Headers(result.meta.headers, [], responseIssues);"#
            ),
            "response block mismatch:\n{content}"
        );
        assert!(
            !content.contains("validateReadnoteResponse200("),
            "{content}"
        );
    }

    #[test]
    fn a_discriminated_branch_validates_against_the_matched_media_entry() {
        // One JSON entry beside a text entry: the validator name and schema are unchanged, and the
        // call is gated on the entry that was actually selected rather than skipped entirely.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } } } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_validated_files(&document, false, true);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let content = operation_file(&files, "readthing");
        assert!(
            content.contains(
                r#"  if (result.outcome === 200) {
    const responseIssues: Issue[] = [];
    if (result.contentType === "application/json") {
      validateReadthingResponse200(result.data, [], responseIssues);
    }"#
            ),
            "response block mismatch:\n{content}"
        );
        let validators = generated_file(&files, "validators/operations/readthing.ts");
        assert!(
            validators.contains("export function validateReadthingResponse200("),
            "{validators}"
        );
        assert!(
            !validators.contains("validateReadthingResponse200ApplicationJson"),
            "{validators}"
        );
    }

    #[test]
    fn two_json_entries_each_validate_under_their_own_content_type() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "default": {
                                "description": "any",
                                "content": {
                                    "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } } } },
                                    "application/vnd.api+json": { "schema": { "type": "object", "properties": { "code": { "type": "integer" } } } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let content = emit_validated_operation(document, "readthing", false, true);
        // A `default` branch spans both sides, so each media arm still selects on `ok`.
        assert!(
            content.contains(
                r#"    if (result.contentType === "application/json") {
      if (result.ok) {
        validateReadthingResponseDefaultApplicationJson(result.data, [], responseIssues);
      } else {
        validateReadthingResponseDefaultApplicationJson(result.error, [], responseIssues);
      }
    } else if (result.contentType === "application/vnd.api+json") {
      if (result.ok) {
        validateReadthingResponseDefaultApplicationVndApiJson(result.data, [], responseIssues);
      } else {
        validateReadthingResponseDefaultApplicationVndApiJson(result.error, [], responseIssues);
      }
    }"#
            ),
            "response block mismatch:\n{content}"
        );
        assert!(
            content.contains(
                "import { validateReadthingResponseDefaultApplicationJson, validateReadthingResponseDefaultApplicationVndApiJson } from \"../../validators/operations/readthing.js\";"
            ),
            "{content}"
        );
    }

    fn colliding_response_media_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json;a-b=1": { "schema": { "type": "string" } },
                                    "application/json;a.b=1": { "schema": { "type": "boolean" } }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn colliding_media_calls_match_generated_validator_declarations() {
        let (files, diagnostics) =
            emit_validated_files(&colliding_response_media_document(), false, true);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:#?}"
        );
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS6001")
            .expect("media alias warning");
        assert_eq!(collision.severity, Severity::Warning);
        assert!(collision.message.contains("application/json;a-b=1"));
        assert!(collision.message.contains("application/json;a.b=1"));
        assert!(
            collision
                .message
                .contains("ReadthingResponse200ApplicationJsonAB12")
        );

        let client = operation_file(&files, "readthing");
        let validators = generated_file(&files, "validators/operations/readthing.ts");
        for name in [
            "validateReadthingResponse200ApplicationJsonAB1",
            "validateReadthingResponse200ApplicationJsonAB12",
        ] {
            assert!(client.contains(&format!("{name}(result.data")), "{client}");
            assert!(
                validators.contains(&format!("export function {name}(")),
                "{validators}"
            );
        }
    }

    #[test]
    fn colliding_media_calls_match_zod_declarations() {
        let (files, diagnostics) =
            emit_validation_files(&colliding_response_media_document(), false, true, "zod");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:#?}"
        );
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS6001")
            .expect("media alias warning");
        assert_eq!(collision.severity, Severity::Warning);
        assert!(
            collision
                .message
                .contains("ReadthingResponse200ApplicationJsonAB12")
        );

        let client = operation_file(&files, "readthing");
        let zod = generated_file(&files, "zod/operations/readthing.ts");
        for name in [
            "validateReadthingResponse200ApplicationJsonAB1",
            "validateReadthingResponse200ApplicationJsonAB12",
        ] {
            assert!(client.contains(&format!("{name}(result.data")), "{client}");
            assert!(zod.contains(&format!("export function {name}(")), "{zod}");
        }
    }

    #[test]
    fn three_colliding_media_calls_increment_without_reusing_an_alias() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json;a-b=1": { "schema": { "type": "string" } },
                                    "application/json;a.b=1": { "schema": { "type": "boolean" } },
                                    "application/json;a+b=1": { "schema": { "type": "integer" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_validated_files(&document, false, true);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:#?}"
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS6001")
                .count(),
            2,
            "{diagnostics:#?}"
        );
        let client = operation_file(&files, "readthing");
        let validators = generated_file(&files, "validators/operations/readthing.ts");
        for name in [
            "validateReadthingResponse200ApplicationJsonAB1",
            "validateReadthingResponse200ApplicationJsonAB12",
            "validateReadthingResponse200ApplicationJsonAB13",
        ] {
            assert!(client.contains(&format!("{name}(result.data")), "{client}");
            assert!(
                validators.contains(&format!("export function {name}(")),
                "{validators}"
            );
        }
    }

    #[test]
    fn empty_media_tags_get_client_call_aliases() {
        let media = ["---", "..."];
        let names = response_media_names("validateReadthingResponse200", &media);
        assert_eq!(names[0].name, "validateReadthingResponse200Media");
        assert_eq!(names[1].name, "validateReadthingResponse200Media2");
        assert_eq!(names[1].collision, Some(media[0]));
    }

    #[test]
    fn response_validation_covers_a_two_xx_range_and_an_exact_error_branch() {
        // A 2XX range branch is a success, so it validates result.data; an exact non-2xx branch is a
        // documented error, so it validates result.error.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/poll": {
                    "get": {
                        "operationId": "pollthing",
                        "responses": {
                            "2XX": { "description": "range success", "content": { "application/json": { "schema": { "type": "object", "properties": { "value": { "type": "string" } } } } } },
                            "500": { "description": "server error", "content": { "application/json": { "schema": { "type": "object", "properties": { "code": { "type": "integer" } } } } } }
                        }
                    }
                }
            }
        });
        let content = emit_validated_operation(document, "pollthing", false, true);
        assert!(
            content.contains(
                r#"    if (result.outcome === 500) {
      validatePollthingResponse500(result.error, [], responseIssues);
    } else if (result.outcome === "2XX") {
      validatePollthingResponse2XX(result.data, [], responseIssues);
    }"#
            ),
            "response block mismatch:\n{content}"
        );
    }

    // --- typed response headers ------------------------------------------------------------

    fn headered_operation_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "fetchThing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "headers": {
                                    "X-Token": { "required": true, "schema": { "type": "string" } }
                                },
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            },
                            "404": {
                                "description": "missing",
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn headered_response_arm_narrows_meta_headers() {
        let (content, diagnostics) = emit_operation(headered_operation_document(), "fetchthing");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains(
                "import type { FetchThingResponse200, FetchThingResponse200Headers, FetchThingResponse404 } from \"../../types/operations/fetchthing.js\";"
            ),
            "operation type import must carry the headers interface name:\n{content}"
        );
        assert!(
            content.contains("import type { TypedHeaders } from \"../../types/headers.js\";"),
            "TypedHeaders must be imported when a response declares headers:\n{content}"
        );
        assert!(
            content.contains(
                "| { outcome: 200; ok: true; status: 200; data: FetchThingResponse200; meta: ResponseMeta & { readonly headers: TypedHeaders<keyof FetchThingResponse200Headers & string> } }"
            ),
            "the headered arm must narrow meta to the intersection type:\n{content}"
        );
        assert!(
            content.contains(
                "| { outcome: 404; ok: false; status: 404; error: FetchThingResponse404; meta: ResponseMeta }"
            ),
            "a sibling header-less arm must keep the plain meta type:\n{content}"
        );
    }

    #[test]
    fn headerless_client_output_unchanged() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            }
        });
        let expected = format!(
            "{HEADER}import type {{ ListItemsResponse200 }} from \"../../types/operations/listitems.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1items/get\nexport type ListItemsInput = {{}};\n\n// Source: workspace/openapi.json#/paths/~1items/get\nexport type ListItemsResult =\n  | {{ outcome: 200; ok: true; status: 200; data: ListItemsResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n\nexport type ListItemsCallArgs<_S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1items/get\nconst descriptor: OperationDescriptor = {{\n  operationId: \"listItems\",\n  method: \"GET\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"items\" }}],\n  ],\n  params: [],\n  body: null,\n  accept: \"application/json\",\n  credentialHeaders: [\"authorization\"],\n  security: null,\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function listItems<S extends string = never>(transport: Transport<S>, input: ListItemsInput, ...args: ListItemsCallArgs<S>): Promise<ListItemsResult> {{\n  return execute<ListItemsResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function listItemsOrThrow<S extends string = never>(transport: Transport<S>, input: ListItemsInput, ...args: ListItemsCallArgs<S>): Promise<{{ data: ListItemsResponse200; meta: ResponseMeta }}> {{\n  return executeOrThrow<ListItemsResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "listitems");
        assert_eq!(
            actual, expected,
            "a header-less document's client output must stay byte-identical to before response-header narrowing existed"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn response_validation_binds_header_validator() {
        // 200 carries both a validated JSON body and a header; 204 carries only a header, with no
        // payload to validate at all — the header check must still bind on its own.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "fetchThing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "headers": {
                                    "X-Token": { "required": true, "schema": { "type": "string" } }
                                },
                                "content": {
                                    "application/json": {
                                        "schema": { "type": "object", "properties": { "id": { "type": "string" } } }
                                    }
                                }
                            },
                            "204": {
                                "description": "no content",
                                "headers": {
                                    "X-Trace": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let enabled = emit_validated_operation(document.clone(), "fetchthing", false, true);
        assert!(
            enabled.contains(
                r#"    if (result.outcome === 200) {
      validateFetchThingResponse200(result.data, [], responseIssues);
      validateFetchThingResponse200Headers(result.meta.headers, [], responseIssues);
    } else if (result.outcome === 204) {
      validateFetchThingResponse204Headers(result.meta.headers, [], responseIssues);
    }"#
            ),
            "response block mismatch:\n{enabled}"
        );
        assert!(
            enabled.contains(
                "import { validateFetchThingResponse200, validateFetchThingResponse200Headers, validateFetchThingResponse204Headers } from \"../../validators/operations/fetchthing.js\";"
            ),
            "{enabled}"
        );

        // The resolved config rejects a generated engine with both directions off, so request
        // validation stays on here — only the response direction (and with it, header binding)
        // is what this assertion cares about.
        let disabled = emit_validated_operation(document, "fetchthing", true, false);
        // The meta narrowing itself is unconditional (a types concern), but with response
        // validation off there is no responseIssues buffer and no validator call at all.
        assert!(
            disabled.contains(
                "meta: ResponseMeta & { readonly headers: TypedHeaders<keyof FetchThingResponse200Headers & string> } }"
            ),
            "{disabled}"
        );
        assert!(
            !disabled.contains("validateFetchThingResponse200Headers("),
            "response validation disabled must not call the header validator:\n{disabled}"
        );
        assert!(
            !disabled.contains("validateFetchThingResponse204Headers("),
            "{disabled}"
        );
        assert!(!disabled.contains("responseIssues"), "{disabled}");
    }

    // --- streaming responses and request bodies --------------------------------------------------

    /// One `GET` whose 200 declares exactly `media`, so the plan carries a single streaming entry.
    fn single_media_stream_document(operation_id: &str, path: &str, media: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": {
                path: {
                    "get": {
                        "operationId": operation_id,
                        "responses": {
                            "200": { "description": "streamed", "content": media }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn only_a_client_that_sends_events_carries_the_frame_encoder() {
        // The encoder is the caller's half of a streaming request body: the input is a byte stream,
        // and this is what turns typed events into one. A client that only *reads* streams has
        // nothing to frame, so it must not carry it.
        let sending = json!({
            "openapi": "3.1.0",
            "paths": {
                "/publish": {
                    "post": {
                        "operationId": "publishTicks",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": { "schema": { "type": "object" } },
                                "text/event-stream": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": { "204": { "description": "accepted" } }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_all_client_files(&sending);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let serialize = runtime_file(&files, "serialize.ts");
        assert!(
            serialize.contains("export function encodeSseEvents<TData>("),
            "an operation that can send events carries the encoder: {serialize}"
        );

        let (reading, reading_diagnostics) = emit_all_client_files(&single_media_stream_document(
            "watchTicks",
            "/ticks",
            json!({ "text/event-stream": { "schema": { "type": "string" } } }),
        ));
        assert!(reading_diagnostics.is_empty(), "{reading_diagnostics:#?}");
        assert!(
            !runtime_file(&reading, "serialize.ts").contains("encodeSseEvents"),
            "a read-only streaming client frames nothing and carries no encoder"
        );
    }

    #[test]
    fn an_sse_operation_drags_in_the_raw_region_it_is_built_on_without_naming_its_reader() {
        let (sse_files, diagnostics) = emit_all_client_files(&single_media_stream_document(
            "watchTicks",
            "/ticks",
            json!({ "text/event-stream": { "schema": { "type": "string" } } }),
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        // `sse-decode` is written against helpers that live in `stream-raw`, so selecting the event
        // decoder has to select the raw region too or the emitted runtime does not compile.
        let serialize = runtime_file(&sse_files, "serialize.ts");
        assert!(
            serialize.contains("export function decodeSseStream("),
            "{serialize}"
        );
        assert!(
            serialize.contains("export function readRawStream("),
            "{serialize}"
        );
        // The module itself names only the decoder it calls: the raw reader is a region dependency,
        // not an import, and importing it would leave an unused binding.
        let operation = &sse_files
            .iter()
            .find(|file| file.relative_path == "client/operations/watchticks.ts")
            .expect("operation module")
            .content;
        assert!(
            operation.contains("import { decodeSseStream } from \"../../runtime/serialize.js\";"),
            "{operation}"
        );

        let (raw_files, diagnostics) = emit_all_client_files(&single_media_stream_document(
            "downloadBlob",
            "/blob",
            json!({ "application/octet-stream": { "x-oasts-streaming": true } }),
        ));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        // A raw-only operation must not link the event parser it never runs.
        let serialize = runtime_file(&raw_files, "serialize.ts");
        assert!(
            serialize.contains("export function readRawStream("),
            "{serialize}"
        );
        assert!(
            !serialize.contains("export function decodeSseStream("),
            "{serialize}"
        );
        let operation = &raw_files
            .iter()
            .find(|file| file.relative_path == "client/operations/downloadblob.ts")
            .expect("operation module")
            .content;
        assert!(
            operation.contains("import { readRawStream } from \"../../runtime/serialize.js\";"),
            "{operation}"
        );
    }

    #[test]
    fn only_a_branch_rendering_its_payload_inline_imports_sseevent_and_ships_a_stream_decoder() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/report": {
                    "get": {
                        "operationId": "readReport",
                        "responses": {
                            "200": {
                                "description": "either family",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } },
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            }
                        }
                    }
                },
                "/ticks": {
                    "get": {
                        "operationId": "watchTicks",
                        "responses": {
                            "200": {
                                "description": "one entry, so the status-wide alias carries it",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_all_client_files(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");

        let discriminated = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/readreport.ts")
            .expect("operation module")
            .content;
        // Two entries on one status discriminate on content type, so this module renders each arm's
        // payload itself — and only then does it write the word `SseEvent`.
        assert!(
            discriminated.contains(
                "import type { RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, SseEvent, UnknownHttpError } from \"../../runtime/result.js\";"
            ),
            "{discriminated}"
        );
        assert!(
            discriminated.contains(
                "data: AsyncIterable<SseEvent<string>>; contentType: \"text/event-stream\""
            ),
            "{discriminated}"
        );
        assert!(
            discriminated.contains(
                "data: ReadableStream<Uint8Array>; contentType: \"application/octet-stream\""
            ),
            "{discriminated}"
        );
        // Each family ships its own reader through the descriptor, so the transport never names
        // either one and an operation links only what it declares.
        assert!(
            discriminated.contains(
                "media: [[\"text/event-stream\", { sse: decodeSseStream, onEvent: null }], [\"application/octet-stream\", { raw: readRawStream }]]"
            ),
            "{discriminated}"
        );

        let alias_path = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/watchticks.ts")
            .expect("operation module")
            .content;
        // The alias-path branch names its payload through the types artifact, which imports its own
        // copy of `SseEvent`. Importing it here too would be an unused binding, which is a hard
        // failure under a consumer's `noUnusedLocals`.
        assert!(!alias_path.contains("SseEvent"), "{alias_path}");
    }

    /// One SSE-only branch whose events convert, one whose schema reaches no representation, and one
    /// status pairing a converting buffered entry with a converting event stream.
    fn converting_event_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "T", "version": "1.0.0" },
            "paths": {
                "/ticks": {
                    "get": {
                        "operationId": "watchTicks",
                        "responses": {
                            "200": {
                                "description": "one entry, so no contentType discriminant",
                                "content": {
                                    "text/event-stream": { "schema": { "$ref": "#/components/schemas/Event" } }
                                }
                            }
                        }
                    }
                },
                "/plain": {
                    "get": {
                        "operationId": "watchPlain",
                        "responses": {
                            "200": {
                                "description": "nothing here reaches a representation",
                                "content": { "text/event-stream": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                },
                "/report": {
                    "get": {
                        "operationId": "readReport",
                        "responses": {
                            "200": {
                                "description": "a buffered entry beside an event stream",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/Event" } },
                                    "text/event-stream": { "schema": { "$ref": "#/components/schemas/Event" } }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "required": ["at"],
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }
            }
        })
    }

    fn operation_module(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("client/operations/{base}.ts"))
            .expect("operation module")
            .content
            .clone()
    }

    #[test]
    fn a_converting_event_stream_binds_its_codec_to_the_descriptor_hook() {
        let (files, diagnostics) = emit_transforming_files(converting_event_document(), false);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");

        let alias_path = operation_module(&files, "watchticks");
        // The pair is the event's, not the payload's: the payload is the stream around it, which is
        // the same declaration on both surfaces because the runtime converts before it yields.
        assert!(
            alias_path.contains("export type WatchTicksResponse200Event = Event;"),
            "{alias_path}"
        );
        assert!(
            alias_path.contains("export type WatchTicksResponse200EventWire = EventWire;"),
            "{alias_path}"
        );
        assert!(
            alias_path.contains(
                "function checkWatchTicksResponse200Event(data: WatchTicksResponse200EventWire): unknown {\n  return decodeWatchTicksResponse200Event(data);\n}\n"
            ),
            "{alias_path}"
        );
        assert!(
            alias_path
                .contains("{ sse: decodeSseStream, onEvent: checkWatchTicksResponse200Event }"),
            "{alias_path}"
        );
        // Nothing converts after the call, so no pre-conversion result surface is declared and the
        // function still hands the kernel its own result type.
        assert!(!alias_path.contains("WatchTicksResultWire"), "{alias_path}");
        assert!(
            alias_path.contains(
                "  return execute<WatchTicksResult>(transport, descriptor, input, args[0]);\n"
            ),
            "{alias_path}"
        );

        // A schema no representation reaches declares no pair and binds no hook.
        let plain = operation_module(&files, "watchplain");
        assert!(plain.contains("onEvent: null }"), "{plain}");
        assert!(!plain.contains("WatchPlainResponse200Event"), "{plain}");

        // On a discriminated status the two entries convert through different mechanisms: the
        // buffered arm after the call, the event arm inside the runtime.
        let inline = operation_module(&files, "readreport");
        assert!(
            inline.contains(
                "data: AsyncIterable<SseEvent<Event>>; contentType: \"text/event-stream\""
            ),
            "{inline}"
        );
        assert!(
            inline.contains(
                "      return { ...result, data: decodeReadReportResponse200ApplicationJson(result.data) };\n"
            ),
            "{inline}"
        );
        assert!(
            inline.contains(
                "onEvent: checkReadReportResponse200TextEventStreamEvent }]], hasContentTypeDiscriminant: true }"
            ),
            "{inline}"
        );
        // The event arm is the one payload the two result surfaces agree on.
        assert!(
            inline.contains(
                "data: ReadReportResponse200ApplicationJsonWire; contentType: \"application/json\""
            ),
            "{inline}"
        );
    }

    #[test]
    fn a_per_event_pipeline_validates_before_it_converts() {
        // The two halves are independent switches, and the order they compose in is contractual: a
        // validator describes the wire value, so it runs before the codec replaces it.
        let (files, _) = emit_transforming_files(converting_event_document(), true);
        let content = operation_module(&files, "watchticks");
        assert!(
            content.contains(
                "function checkWatchTicksResponse200Event(data: WatchTicksResponse200EventWire): unknown {\n  const eventIssues: Issue[] = [];\n  validateWatchTicksResponse200(data, [], eventIssues);\n  if (eventIssues.length > 0) {\n    throw eventIssues;\n  }\n  return decodeWatchTicksResponse200Event(data);\n}\n"
            ),
            "{content}"
        );
        // Validation alone still returns the checked value unchanged.
        let plain = operation_module(&files, "watchplain");
        assert!(
            plain.contains(
                "function checkWatchPlainResponse200Event(data: unknown): unknown {\n  const eventIssues: Issue[] = [];\n  validateWatchPlainResponse200(data, [], eventIssues);\n  if (eventIssues.length > 0) {\n    throw eventIssues;\n  }\n  return data;\n}\n"
            ),
            "{plain}"
        );
    }

    #[test]
    fn a_streaming_success_branch_documents_that_ok_true_precedes_any_body_byte() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/ticks": {
                    "get": {
                        "operationId": "watchTicks",
                        "responses": {
                            "200": {
                                "description": "streamed",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                },
                "/count": {
                    "get": {
                        "operationId": "countTicks",
                        "responses": {
                            "200": {
                                "description": "buffered",
                                "content": {
                                    "application/json": { "schema": { "type": "integer" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_all_client_files(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        const REMARK: &str = "A streaming branch resolves when the response headers arrive, so `ok: true` attests only the matched status";

        let streaming = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/watchticks.ts")
            .expect("operation module")
            .content;
        // Both call variants carry it: the weaker proof is a property of the result, not of which
        // entry point produced it.
        assert_eq!(streaming.matches(REMARK).count(), 2, "{streaming}");

        let buffered = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/countticks.ts")
            .expect("operation module")
            .content;
        assert!(!buffered.contains(REMARK), "{buffered}");
    }

    #[test]
    fn a_streaming_request_body_is_bytes_on_the_input_and_ships_the_stream_encoder() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/upload": {
                    "post": {
                        "operationId": "uploadBlob",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/octet-stream": { "x-oasts-streaming": true }
                            }
                        },
                        "responses": { "204": { "description": "accepted" } }
                    }
                }
            }
        });
        let (content, diagnostics) = emit_operation(document, "uploadblob");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            content.contains("  body: ReadableStream<Uint8Array>;"),
            "{content}"
        );
        // The encoder travels in the descriptor rather than as a `kind` tag, so a client that sends
        // no stream never links `streamBody`.
        assert!(
            content.contains("body: streamBody(\"application/octet-stream\"),"),
            "{content}"
        );
        assert!(content.contains("streamBody,"), "{content}");
    }

    #[test]
    fn a_statically_bodyless_branch_drops_its_streaming_media_and_keeps_its_buffered_entries() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/probe": {
                    "head": {
                        "operationId": "probeTicks",
                        "responses": {
                            "200": {
                                "description": "HEAD fixes the body to null",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                },
                "/drain": {
                    "get": {
                        "operationId": "drainTicks",
                        "responses": {
                            "204": {
                                "description": "an exact bodyless status cannot carry a stream",
                                "content": {
                                    "application/json": { "schema": { "type": "integer" } },
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = emit_all_client_files(&document);
        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<&str>>(),
            ["OASTS5204", "OASTS5204", "OASTS5204"],
            "{diagnostics:#?}"
        );

        // A `HEAD` branch never creates a handle, so naming a reader for one would be a promise the
        // runtime cannot keep.
        let head = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/probeticks.ts")
            .expect("operation module")
            .content;
        assert!(
            head.contains("bodyless: true, media: [], hasContentTypeDiscriminant:"),
            "{head}"
        );

        // The buffered entry beside it is untouched: no non-streaming descriptor moves a byte.
        let drain = &files
            .iter()
            .find(|file| file.relative_path == "client/operations/drainticks.ts")
            .expect("operation module")
            .content;
        assert!(
            drain.contains("bodyless: true, media: [[\"application/json\", \"json\"]],"),
            "{drain}"
        );

        // Neither branch streams, so neither drags the stream regions into the runtime.
        let serialize = runtime_file(&files, "serialize.ts");
        assert!(
            !serialize.contains("export function decodeSseStream("),
            "{serialize}"
        );
        assert!(
            !serialize.contains("export function readRawStream("),
            "{serialize}"
        );
    }
}
