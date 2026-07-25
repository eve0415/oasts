//! Fetch client artifact emission from the client planning IR.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::client_model::{
    AuthAlternative, AuthKind, AuthSchemeUse, BaseUrlPlan, BodyPlan, ClientModel, DecoderClass,
    FieldSerializationPlan, FormFieldPlan, HelperId, OperationPlan, PartMediaPlan,
    PayloadDisposition, PayloadKind, ResponseMatchKind, ResponsePlan,
};
use crate::config::{
    AuthEnforcement, CacheMode, CredentialsMode, DocumentationConfig, FetchDefaults, RedirectMode,
    ReferrerPolicyValue, RequestModeValue, ValidationEngine,
};
use crate::ir::{
    Operation, ParamLocation, ParamStyle, PrimitiveType, SchemaNode, SecKind, SegmentPart,
    ServerVariable,
};
use crate::media::{is_json, media_essence};

use super::media_tag;

use super::model::EmissionModel;
use super::runtime_assets::{RuntimeSelection, emit_runtime_files};
use super::validators::operation_parameter_validator_names;
use super::{
    ClientDocKind, Emitter as TypesEmitter, GeneratedFile, TypePosition, encode_comment_text,
    import_extension, push_indent, render_property_key, render_ts_string, uppercase_first,
    write_client_operation_tsdoc, write_source_metadata,
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
        let relative_path = format!("client/operations/{file_base}.ts");
        model.register_path(&relative_path, &operation.source);
        files.push(GeneratedFile {
            relative_path,
            content: emit_operation(model, &operation, plan, &allocated.name, &file_base),
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
        let relative_path = format!("client/{namespace}.ts");
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
/// oauth2 scheme's declared scopes become a string-literal union so a provider implementation typed
/// against the property narrows `AuthContext.scopes` (empty declared set → plain `AuthProvider`);
/// every other kind stays a plain `AuthProvider`, and an http scheme's `bearerFormat` is surfaced
/// as a per-property `@remarks` — which is why this is a per-property interface, not a mapped type.
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
        body.push_str(&document_auth_provider_type(&scheme.kind));
        body.push_str(";\n");
    }

    let extension = import_extension(model);
    let mut output = model.header();
    output.push_str("import type { AuthProvider } from ");
    output.push_str(&render_ts_string(&format!(
        "../runtime/transport{extension}"
    )));
    output.push_str(";\n\nexport interface DocumentAuthProviders {\n");
    output.push_str(&body);
    output.push_str("}\n");
    Some(GeneratedFile {
        relative_path: "client/auth.ts".to_owned(),
        content: output,
    })
}

/// The `AuthProvider` type for one scheme property. Oauth2 carries its declared scopes as a
/// first-seen string-literal union; every other kind (including openIdConnect, whose scopes are
/// IdP-defined and invisible to the document) is a plain `AuthProvider`.
fn document_auth_provider_type(kind: &SecKind) -> String {
    match kind {
        SecKind::OAuth2 { flows } => {
            let scopes = flows.declared_scopes();
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
) -> String {
    let stem = uppercase_first(allocated_name);
    let operation_type_names = operation_type_imports(plan, &stem);
    let uses_typed_headers = plan
        .response_table
        .iter()
        .any(|response| response.has_headers);
    let mut component_imports = BTreeMap::<String, BTreeSet<String>>::new();
    let documentation = model.config.documentation.clone();
    // Everything that renders a component type lives in this one borrow scope, because the scope
    // has to end before `model.header()` can reborrow the model mutably.
    let (input, result_type, envelope_type) = {
        let renderer = TypesEmitter::new(model);
        for parameter in &plan.param_plans {
            renderer.collect_operation_imports(
                &parameter.schema,
                TypePosition::Request,
                &mut component_imports,
            );
        }
        if let Some(body) = &plan.body_plan {
            collect_body_imports(&renderer, body, &mut component_imports);
        }
        // A content-type-discriminated branch renders each media entry's own schema inline instead
        // of the status-wide alias, so those entries' component references import from here.
        for response in &plan.response_table {
            if response.content_type_discriminated
                && matches!(response.payload, PayloadDisposition::Payload)
            {
                for entry in &response.media {
                    renderer.collect_operation_imports(
                        &entry.schema,
                        TypePosition::Response,
                        &mut component_imports,
                    );
                }
            }
        }
        let arms = response_result_arms(&renderer, plan, &stem);
        (
            render_input(&renderer, operation, plan, &stem, &documentation),
            render_result_type(&arms, plan, &stem),
            successful_envelope_union(&arms),
        )
    };
    let mut function_docs_operation = operation.clone();
    for parameter in &mut function_docs_operation.parameters {
        parameter.description = None;
    }

    let extension = import_extension(model);
    let auth_enforcement = model
        .config
        .client
        .as_ref()
        .expect("client emission requires client config")
        .auth_enforcement;
    let (imports_basic_credential, imports_cookie_credential, imports_client_certificate) =
        call_args_credentials(plan, auth_enforcement);
    let runtime_directory = &model.config.emit.runtime_directory;
    let unchecked_response = model
        .config
        .validation
        .as_ref()
        .is_some_and(|validation| !validation.response);
    let (validate_request, validate_response) = validation_flags(model);
    let request_checks = request_validation_checks(operation, plan, &stem, validate_request);
    let response_checks = response_validation_checks(plan, &stem, validate_response);
    let validation_binding = !request_checks.is_empty() || !response_checks.is_empty();
    let mut output = model.header();
    write_component_imports(&mut output, component_imports, &extension);
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
        output.push_str(&render_ts_string(&format!(
            "../../types/operations/{file_base}{extension}"
        )));
        output.push_str(";\n");
    }
    if uses_typed_headers {
        output.push_str("import type { TypedHeaders } from ");
        output.push_str(&render_ts_string(&format!(
            "../../types/headers{extension}"
        )));
        output.push_str(";\n");
    }
    output.push_str(
        "import type { RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError } from ",
    );
    output.push_str(&render_ts_string(&format!(
        "../../{runtime_directory}/result{extension}"
    )));
    output.push_str(";\n");
    if validation_binding {
        // `unwrap` reuses the result module's failed-branch throw so the orThrow variant delegates
        // to the validated base function instead of the runtime's unvalidated executeOrThrow.
        output.push_str("import { unwrap } from ");
        output.push_str(&render_ts_string(&format!(
            "../../{runtime_directory}/result{extension}"
        )));
        output.push_str(";\n");
    }
    let helper_names = plan
        .param_plans
        .iter()
        .map(|parameter| helper_export_name(parameter.resolved.helper))
        .collect::<BTreeSet<_>>();
    if !helper_names.is_empty() {
        output.push_str("import { ");
        output.push_str(&helper_names.into_iter().collect::<Vec<_>>().join(", "));
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&format!(
            "../../{runtime_directory}/serialize{extension}"
        )));
        output.push_str(";\n");
    }
    output.push_str("import { execute, executeOrThrow");
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
    output.push_str(&render_ts_string(&format!(
        "../../{runtime_directory}/transport{extension}"
    )));
    output.push_str(";\n");
    if validation_binding {
        write_validator_imports(
            &mut output,
            &request_checks,
            &response_checks,
            file_base,
            &extension,
        );
    }
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        operation,
        &model.config.documentation,
        ClientDocKind::Declaration,
        unchecked_response,
    );
    output.push_str("export type ");
    output.push_str(&stem);
    output.push_str("Input = ");
    output.push_str(&input);
    output.push_str(";\n\n");

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        operation,
        &model.config.documentation,
        ClientDocKind::Declaration,
        unchecked_response,
    );
    output.push_str(&result_type);
    output.push('\n');

    output.push_str(&render_call_args(&plan.auth_plan, auth_enforcement, &stem));
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    write_descriptor(&mut output, model, operation, plan, allocated_name);
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        &function_docs_operation,
        &model.config.documentation,
        ClientDocKind::ResultFunction,
        unchecked_response,
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
    ));
    output.push_str("}\n\n");

    write_source_metadata(&mut output, &operation.source, 0);
    write_client_operation_tsdoc(
        &mut output,
        &function_docs_operation,
        &model.config.documentation,
        ClientDocKind::ThrowFunction,
        unchecked_response,
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
    output.push_str(&throw_function_body(
        allocated_name,
        &stem,
        validation_binding,
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
enum ResponseBody {
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

/// `(validate_request, validate_response)` — both false unless the resolved engine is `generated`,
/// which keeps the emitted client bytes identical to today for `engine: off`.
fn validation_flags(model: &EmissionModel<'_, '_>) -> (bool, bool) {
    match model.config.validation.as_ref() {
        Some(validation) if validation.engine == ValidationEngine::Generated => {
            (validation.request, validation.response)
        }
        _ => (false, false),
    }
}

/// The request-side checks: every parameter in declared order, then the JSON request body. Empty
/// unless request validation is enabled.
fn request_validation_checks(
    operation: &Operation,
    plan: &OperationPlan,
    stem: &str,
    enabled: bool,
) -> Vec<RequestCheck> {
    if !enabled {
        return Vec::new();
    }
    let mut checks = Vec::new();
    let names = operation_parameter_validator_names(operation, stem);
    for (parameter, type_name) in operation.parameters.iter().zip(&names) {
        checks.push(RequestCheck {
            access: input_member(InputMember::Parameter {
                location: parameter.location,
                name: &parameter.name,
            }),
            validator: format!("validate{type_name}"),
            base_path: format!(
                "[{}, {}]",
                render_ts_string(location_name(parameter.location)),
                render_ts_string(&parameter.name)
            ),
            guarded: true,
        });
    }
    if let Some(BodyPlan::Json { .. }) = &plan.body_plan {
        // A required body is always sent, so it is validated unconditionally; an optional body is
        // skipped when absent, matching the parameter presence rule.
        let required = operation
            .request_body
            .as_ref()
            .is_some_and(|body| body.required);
        checks.push(RequestCheck {
            access: input_member(InputMember::Body),
            validator: format!("validate{stem}RequestBody"),
            base_path: "[\"body\"]".to_owned(),
            guarded: !required,
        });
    }
    checks
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
/// The two naming cases mirror the validators emitter: one JSON entry keeps the plain
/// `validate{Stem}Response{Suffix}` name, and two or more are tagged by media.
fn body_validation_checks(response: &ResponsePlan, stem: &str) -> Vec<BodyCheck> {
    if !matches!(response.payload, PayloadDisposition::Payload) {
        return Vec::new();
    }
    let json = response
        .media
        .iter()
        .filter(|media| is_json(&media.media))
        .collect::<Vec<_>>();
    if json.is_empty() {
        return Vec::new();
    }
    let body = response_body_side(response.kind, &response.match_key);
    let base = response_type_name(stem, response);
    if !response.content_type_discriminated {
        return vec![BodyCheck {
            content_type: None,
            validator: format!("validate{base}"),
            body,
        }];
    }
    let tagged = json.len() > 1;
    json.into_iter()
        .map(|media| BodyCheck {
            content_type: Some(media.media.clone()),
            validator: if tagged {
                format!("validate{base}{}", media_tag(&media.media))
            } else {
                format!("validate{base}")
            },
            body,
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
fn input_member(member: InputMember<'_>) -> String {
    match member {
        InputMember::Parameter { location, name } => {
            // `location` is always one of the four fixed identifiers (path/query/header/cookie), so
            // it is always dot-accessed; only a non-identifier parameter name needs a bracket key.
            let location = location_name(location);
            let key = render_property_key(name);
            if key == name {
                format!("input.{location}?.{name}")
            } else {
                format!("input.{location}?.[{key}]")
            }
        }
        InputMember::Body => "input.body".to_owned(),
    }
}

/// The `Issue` type import plus the per-operation validators pulled from the validators artifact.
fn write_validator_imports(
    output: &mut String,
    request: &[RequestCheck],
    response: &[ResponseCheck],
    file_base: &str,
    extension: &str,
) {
    output.push_str("import type { Issue } from ");
    output.push_str(&render_ts_string(&format!(
        "../../validators/runtime{extension}"
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
        .collect::<BTreeSet<_>>();
    output.push_str("import { ");
    output.push_str(&validators.into_iter().collect::<Vec<_>>().join(", "));
    output.push_str(" } from ");
    output.push_str(&render_ts_string(&format!(
        "../../validators/operations/{file_base}{extension}"
    )));
    output.push_str(";\n");
}

/// The result-returning function body: today's single `execute` call when nothing is bound, else a
/// pre-dispatch request check and a post-dispatch response check around it.
fn result_function_body(
    stem: &str,
    request: &[RequestCheck],
    response: &[ResponseCheck],
) -> String {
    if request.is_empty() && response.is_empty() {
        return format!("  return execute<{stem}Result>(transport, descriptor, input, args[0]);\n");
    }
    let mut body = String::new();
    if !request.is_empty() {
        body.push_str("  const requestIssues: Issue[] = [];\n");
        for check in request {
            if check.guarded {
                body.push_str(&format!("  if ({} !== undefined) {{\n", check.access));
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
    if response.is_empty() {
        body.push_str(&format!(
            "  return execute<{stem}Result>(transport, descriptor, input, args[0]);\n"
        ));
        return body;
    }
    body.push_str(&format!(
        "  const result = await execute<{stem}Result>(transport, descriptor, input, args[0]);\n"
    ));
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
            write_body_validator_call(&mut body, indent, media_check);
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
    body.push_str("  return result;\n");
    body
}

/// One validator call, selecting `result.data` or `result.error` by the branch's side — or both,
/// chosen at runtime on `result.ok`, for a `default` branch that spans them.
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

fn write_component_imports(
    output: &mut String,
    imports: BTreeMap<String, BTreeSet<String>>,
    extension: &str,
) {
    for (file, names) in imports {
        output.push_str("import type { ");
        output.push_str(&names.into_iter().collect::<Vec<_>>().join(", "));
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&format!(
            "../../types/components/{file}{extension}"
        )));
        output.push_str(";\n");
    }
}

fn operation_type_imports(plan: &OperationPlan, stem: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if plan.body_plan.as_ref().is_some_and(body_uses_json_alias) {
        names.insert(format!("{stem}Request"));
    }
    for response in &plan.response_table {
        // A content-type-discriminated branch renders each entry's own schema inline, so the
        // status-wide alias has no reader and importing it would be an unused import.
        if matches!(response.payload, PayloadDisposition::Payload)
            && !response.content_type_discriminated
        {
            names.insert(response_type_name(stem, response));
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
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            arms.iter().any(|(_, arm)| body_uses_json_alias(arm))
        }
        BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => false,
    }
}

fn collect_body_imports(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
) {
    match plan {
        BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
            for field in fields {
                renderer.collect_operation_imports(&field.schema, TypePosition::Request, imports);
            }
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            for (_, arm) in arms {
                collect_body_imports(renderer, arm, imports);
            }
        }
        BodyPlan::Json { .. } | BodyPlan::TopLevelText { .. } | BodyPlan::TopLevelBinary { .. } => {
        }
    }
}

fn render_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    stem: &str,
    documentation: &DocumentationConfig,
) -> String {
    if plan.param_plans.is_empty() && plan.body_plan.is_none() {
        return "{}".to_owned();
    }
    let parameters = operation.parameters.iter().collect::<Vec<_>>();
    assert_eq!(parameters.len(), plan.param_plans.len());
    let mut output = String::from("{\n");
    for location in [
        ParamLocation::Path,
        ParamLocation::Query,
        ParamLocation::Header,
        ParamLocation::Cookie,
    ] {
        let group = parameters
            .iter()
            .copied()
            .zip(&plan.param_plans)
            .filter(|(parameter, _)| parameter.location == location)
            .collect::<Vec<_>>();
        if group.is_empty() {
            continue;
        }
        output.push_str("  ");
        output.push_str(location_name(location));
        if !group.iter().any(|(parameter, _)| parameter.required) {
            output.push('?');
        }
        output.push_str(": {\n");
        for (parameter, parameter_plan) in group {
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
                // pre-serialized wire string rather than the declared schema (OASTS1443).
                output.push_str("string");
            } else {
                output.push_str(&renderer.render_type(
                    &parameter_plan.schema,
                    TypePosition::Request,
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
        output.push_str(&render_body_input(renderer, body_plan, stem, 2));
        output.push_str(";\n");
    }
    output.push('}');
    output
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

fn render_body_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    stem: &str,
    indent: usize,
) -> String {
    match plan {
        BodyPlan::Json { .. } => format!("{stem}Request[\"body\"]"),
        BodyPlan::TopLevelText { .. } => "string".to_owned(),
        BodyPlan::TopLevelBinary { .. } => "Uint8Array".to_owned(),
        BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
            render_form_input(renderer, fields, indent)
        }
        BodyPlan::ContentTypeDiscriminated { arms, all_concrete } => arms
            .iter()
            .map(|(media, arm)| {
                let content_type = if *all_concrete {
                    render_ts_string(media)
                } else {
                    "string".to_owned()
                };
                format!(
                    "{{ contentType: {content_type}; body: {} }}",
                    render_body_input(renderer, arm, stem, indent)
                )
            })
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

fn render_form_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    fields: &[FormFieldPlan],
    indent: usize,
) -> String {
    let mut output = String::from("{\n");
    for field in fields {
        push_indent(&mut output, indent + 2);
        output.push_str(&render_property_key(&field.name));
        if !field.required {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(&render_form_field_input(renderer, field, indent + 2));
        output.push_str(";\n");
    }
    push_indent(&mut output, indent);
    output.push('}');
    output
}

fn render_form_field_input(
    renderer: &TypesEmitter<'_, '_, '_>,
    field: &FormFieldPlan,
    indent: usize,
) -> String {
    let body = match &field.serialization {
        FieldSerializationPlan::Content { media, .. } if media.binary_upload => {
            "Blob | File".to_owned()
        }
        FieldSerializationPlan::Style { .. } | FieldSerializationPlan::Content { .. } => {
            renderer.render_type(&field.schema, TypePosition::Request, indent)
        }
    };
    if !field.wrapper.wrapped {
        return body;
    }
    let mut output = format!("{{ body: {body}; contentType: ");
    if field.wrapper.content_type_literal {
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
    output
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

fn response_result_arms(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &OperationPlan,
    stem: &str,
) -> Vec<ResultArm> {
    let mut arms = Vec::new();
    for response in &plan.response_table {
        push_response_result_arms(&mut arms, renderer, response, stem);
    }
    arms
}

fn push_response_result_arms(
    arms: &mut Vec<ResultArm>,
    renderer: &TypesEmitter<'_, '_, '_>,
    response: &ResponsePlan,
    stem: &str,
) {
    let status = match response.kind {
        ResponseMatchKind::Exact => response.match_key.clone(),
        ResponseMatchKind::Range | ResponseMatchKind::Default => "number".to_owned(),
    };
    let outcome = outcome_literal(response);
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
            && response.content_type_discriminated
        {
            response
                .media
                .iter()
                .map(|entry| {
                    (
                        Some(entry.media.clone()),
                        renderer.media_payload_type(
                            media_essence(&entry.media),
                            &entry.schema,
                            TypePosition::Response,
                        ),
                    )
                })
                .collect()
        } else {
            vec![(None, response_payload_type(response, stem))]
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

fn render_result_type(arms: &[ResultArm], plan: &OperationPlan, stem: &str) -> String {
    let mut output = String::new();
    output.push_str("export type ");
    output.push_str(stem);
    output.push_str("Result =\n");
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

fn response_payload_type(response: &ResponsePlan, stem: &str) -> String {
    match response.payload {
        PayloadDisposition::NoPayload | PayloadDisposition::StaticBodyless => {
            "undefined".to_owned()
        }
        PayloadDisposition::Payload => response_type_name(stem, response),
    }
}

fn response_type_name(stem: &str, response: &ResponsePlan) -> String {
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
fn response_body_side(kind: ResponseMatchKind, match_key: &str) -> ResponseBody {
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
    let parameters = operation.parameters.iter().collect::<Vec<_>>();
    assert_eq!(parameters.len(), plan.param_plans.len());
    if parameters.is_empty() {
        output.push_str("[]");
    } else {
        output.push_str("[\n");
        for (parameter, parameter_plan) in parameters.into_iter().zip(&plan.param_plans) {
            output.push_str("    { name: ");
            output.push_str(&render_ts_string(&parameter_plan.name));
            output.push_str(", location: ");
            output.push_str(&render_ts_string(location_name(
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
    for response in &plan.response_table {
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
        output.push_str(
            &response
                .media
                .iter()
                .map(|media| {
                    format!(
                        "[{}, {}]",
                        render_ts_string(&media.media),
                        render_ts_string(decoder_name(media.decoder))
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
        return format!(
            "export type {stem}CallArgs<S extends string> = [options?: CallOptions];\n"
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
fn security_field(auth_plan: &[AuthAlternative]) -> String {
    if auth_plan.is_empty() {
        return "[]".to_owned();
    }
    let mut output = String::from("[\n");
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
    output.push_str("  ]");
    output
}

fn render_security_member(scheme: &AuthSchemeUse) -> String {
    let mut member = String::from("{ name: ");
    member.push_str(&render_ts_string(&scheme.name));
    member.push_str(", kind: ");
    member.push_str(&render_ts_string(auth_kind_tag(&scheme.kind)));
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

fn auth_kind_tag(kind: &AuthKind) -> &'static str {
    match kind {
        AuthKind::Basic => "basic",
        AuthKind::Bearer => "bearer",
        AuthKind::HttpScheme { .. } => "httpScheme",
        AuthKind::MutualTls => "mutualTls",
        AuthKind::ApiKeyHeader { .. } => "apiKeyHeader",
        AuthKind::ApiKeyQuery { .. } => "apiKeyQuery",
        AuthKind::ApiKeyCookie { .. } => "apiKeyCookie",
        AuthKind::OAuth2 => "oauth2",
        AuthKind::OpenIdConnect => "openIdConnect",
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

fn write_body_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
    indent: usize,
) {
    match plan {
        BodyPlan::Json { media, .. } => write_simple_body(output, "json", media),
        BodyPlan::TopLevelText { media, .. } => write_simple_body(output, "text", media),
        BodyPlan::TopLevelBinary { media, .. } => write_simple_body(output, "binary", media),
        BodyPlan::FormUrlencoded { media, fields, .. } => {
            output.push_str("{ kind: \"form-urlencoded\", contentType: ");
            output.push_str(&render_ts_string(media));
            output.push_str(", fields: [\n");
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
            output.push_str("] }");
        }
        BodyPlan::Multipart { fields, .. } => {
            output.push_str("{ kind: \"multipart\", fields: [\n");
            for field in fields {
                write_multipart_field(output, model, field, indent + 2);
            }
            push_indent(output, indent);
            output.push_str("] }");
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            output.push_str("{ kind: \"content-discriminated\", arms: [\n");
            for (media, arm) in arms {
                push_indent(output, indent + 2);
                output.push('[');
                output.push_str(&render_ts_string(media));
                output.push_str(", ");
                write_body_descriptor(output, model, arm, indent + 2);
                output.push_str("],\n");
            }
            push_indent(output, indent);
            output.push_str("] }");
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

fn write_simple_body(output: &mut String, kind: &str, media: &str) {
    output.push_str("{ kind: ");
    output.push_str(&render_ts_string(kind));
    output.push_str(", contentType: ");
    output.push_str(&render_ts_string(media));
    output.push_str(" }");
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
    output.push_str(
        if schema_is_array(model, &field.schema, &mut HashSet::new()) {
            "true"
        } else {
            "false"
        },
    );
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

fn schema_is_array(
    model: &EmissionModel<'_, '_>,
    schema: &SchemaNode,
    visited: &mut HashSet<(String, String)>,
) -> bool {
    match schema {
        SchemaNode::Array { .. } => true,
        SchemaNode::Ref { target, .. } => {
            let key = (target.source_id.clone(), target.json_pointer.clone());
            if !visited.insert(key) {
                return false;
            }
            model
                .schema_target(&target.source_id, &target.json_pointer)
                .and_then(|target| model.analyzed.ir.schemas.get(target.index))
                .is_some_and(|target| schema_is_array(model, &target.schema, visited))
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
        | SchemaNode::Unknown { .. } => false,
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

fn location_name(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "path",
        ParamLocation::Query => "query",
        ParamLocation::Header => "header",
        ParamLocation::Cookie => "cookie",
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

fn decoder_name(decoder: DecoderClass) -> &'static str {
    match decoder {
        DecoderClass::Json => "json",
        DecoderClass::Text => "text",
        DecoderClass::Binary => "binary",
        DecoderClass::Streaming | DecoderClass::Xml | DecoderClass::Multipart => {
            unreachable!("unsupported response decoders are diagnosed before emission")
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
        HelperId::HeaderSimple => "header-simple",
        HelperId::HeaderSimpleExplode => "header-simple-explode",
        HelperId::ContentJsonPath => "content-json-path",
        HelperId::ContentJsonQuery => "content-json-query",
        HelperId::ContentJsonHeader => "content-json-header",
    }
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

    const HEADER: &str = "// Generated by Oasts 0.0.0. Do not edit.\n// Config schema version: 1\n// Source digest: digest\n\n";

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
                .filter(|diagnostic| diagnostic.code == "OASTS1443")
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
            "{HEADER}import type {{ GetPetResponse200, GetPetResponseDefault }} from \"../../types/operations/getpet.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ serializePathSimple, serializeQueryFormExplode }} from \"../../runtime/serialize.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetInput = {{\n  /**\n   * The pet identifier.\n   */\n  petId: string;\n  /**\n   * The result limit.\n   */\n  limit?: number;\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetResult =\n  | {{ outcome: 200; ok: true; status: 200; data: GetPetResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"default\"; ok: true; status: number; data: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ outcome: \"default\"; ok: false; status: number; error: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200 | \"default\">\n  | RequestPhaseFailure;\n\nexport type GetPetCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\nconst descriptor: OperationDescriptor = {{\n  operationId: \"getPet\",\n  method: \"GET\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"pets\" }}],\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"param\", name: \"petId\" }}],\n  ],\n  params: [\n    {{ name: \"petId\", location: \"path\", required: true, serialize: serializePathSimple, allowReserved: false }},\n    {{ name: \"limit\", location: \"query\", required: false, serialize: serializeQueryFormExplode, allowReserved: false }},\n  ],\n  body: null,\n  accept: \"application/json\",\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n    {{ match: \"default\", kind: \"default\", status: null, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function getPet<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<GetPetResult> {{\n  return execute<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function getPetOrThrow<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<{{ data: GetPetResponse200; meta: ResponseMeta }} | {{ data: GetPetResponseDefault; meta: ResponseMeta }}> {{\n  return executeOrThrow<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n"
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
            "{HEADER}import type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetInput = {{\n  body: {{\n    meta: {{ body: {{\n      tag?: string;\n    }}; contentType: \"application/json\" | \"application/cbor\" }};\n    title: string;\n    file: Blob | File;\n  }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetResult =\n  | {{ outcome: 204; ok: true; status: 204; data: undefined; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<204>\n  | RequestPhaseFailure;\n\nexport type UploadAssetCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"uploadAsset\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"uploads\" }}],\n  ],\n  params: [],\n  body: {{ kind: \"multipart\", fields: [\n    {{ name: \"meta\", required: true, repeated: false, wrapper: true, payload: \"json\", contentType: {{ kind: \"selected\", admitted: [\"application/json\", \"application/cbor\"] }}, payloads: [\"json\", \"json\"], filename: false }},\n    {{ name: \"title\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: {{ kind: \"fixed\", value: \"text/plain\" }}, filename: false }},\n    {{ name: \"file\", required: true, repeated: false, wrapper: false, payload: \"binary\", contentType: {{ kind: \"fixed\", value: \"application/octet-stream\" }}, filename: true }},\n  ] }},\n  accept: null,\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"204\", kind: \"exact\", status: 204, bodyless: false, media: [], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function uploadAsset<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<UploadAssetResult> {{\n  return execute<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function uploadAssetOrThrow<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<{{ data: undefined; meta: ResponseMeta }}> {{\n  return executeOrThrow<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "uploadasset");
        assert_eq!(actual, expected);
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
            "{HEADER}import type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nexport type UploadNoteInput = {{\n  body: {{\n    note: string;\n  }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nexport type UploadNoteResult =\n  | {{ outcome: 204; ok: true; status: 204; data: undefined; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<204>\n  | RequestPhaseFailure;\n\nexport type UploadNoteCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1notes/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"uploadNote\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"notes\" }}],\n  ],\n  params: [],\n  body: {{ kind: \"multipart\", fields: [\n    {{ name: \"note\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: {{ kind: \"fixed\", value: \"application/octet-stream\" }}, filename: false }},\n  ] }},\n  accept: null,\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"204\", kind: \"exact\", status: 204, bodyless: false, media: [], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1notes/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function uploadNote<S extends string = never>(transport: Transport<S>, input: UploadNoteInput, ...args: UploadNoteCallArgs<S>): Promise<UploadNoteResult> {{\n  return execute<UploadNoteResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1notes/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function uploadNoteOrThrow<S extends string = never>(transport: Transport<S>, input: UploadNoteInput, ...args: UploadNoteCallArgs<S>): Promise<{{ data: undefined; meta: ResponseMeta }}> {{\n  return executeOrThrow<UploadNoteResult>(transport, descriptor, input, args[0]);\n}}\n"
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
            "{HEADER}import type {{ SendMessageRequest, SendMessageResponse200 }} from \"../../types/operations/sendmessage.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageInput = {{\n  body: {{ contentType: \"application/json\"; body: SendMessageRequest[\"body\"] }} | {{ contentType: \"text/plain\"; body: string }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageResult =\n  | {{ outcome: 200; ok: true; status: 200; data: SendMessageResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n\nexport type SendMessageCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"sendMessage\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"messages\" }}],\n  ],\n  params: [],\n  body: {{ kind: \"content-discriminated\", arms: [\n    [\"application/json\", {{ kind: \"json\", contentType: \"application/json\" }}],\n    [\"text/plain\", {{ kind: \"text\", contentType: \"text/plain\" }}],\n  ] }},\n  accept: \"text/plain\",\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"text/plain\", \"text\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function sendMessage<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<SendMessageResult> {{\n  return execute<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function sendMessageOrThrow<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<{{ data: SendMessageResponse200; meta: ResponseMeta }}> {{\n  return executeOrThrow<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n"
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
    /// per-part serialization: OASTS1427 (`crates/oasts-core/src/client_model.rs`) rejects it
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
            .find(|diagnostic| diagnostic.code == "OASTS1427")
            .expect("OASTS1427 diagnostic");
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
    /// combination (OASTS1427's SUPPORTED case): it keeps the exact `text` payload emission this
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

    /// An exploded `form`-style array of primitives has a defined per-part serialization (OASTS1427's
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
            assert_eq!(location_name(location), expected);
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
            DecoderClass::Streaming,
            DecoderClass::Xml,
            DecoderClass::Multipart,
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
                input_member(InputMember::Parameter {
                    location,
                    name: "petId",
                }),
                expected
            );
        }
        assert_eq!(
            input_member(InputMember::Parameter {
                location: ParamLocation::Path,
                name: "pet-id",
            }),
            "input.path?.[\"pet-id\"]"
        );
        assert_eq!(input_member(InputMember::Body), "input.body");
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
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let renderer = TypesEmitter::new(&mut model);
        let arms = response_result_arms(&renderer, &plan, "Probe");
        let output = render_result_type(&arms, &plan, "Probe");
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
        let empty_arms = response_result_arms(&renderer, &empty, "Empty");
        let output = render_result_type(&empty_arms, &empty, "Empty");
        assert!(output.contains("| ResponsePhaseFailure<never>\n  | RequestPhaseFailure;\n"));
        assert_eq!(successful_envelope_union(&empty_arms), "never");
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
                "export type ReadthingResult =\n  | { outcome: \"default\"; ok: true; status: number; data: {\n  code?: number;\n}; contentType: \"application/json\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: false; status: number; error: {\n  code?: number;\n}; contentType: \"application/json\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: true; status: number; data: string; contentType: \"text/plain\"; meta: ResponseMeta }\n  | { outcome: \"default\"; ok: false; status: number; error: string; contentType: \"text/plain\"; meta: ResponseMeta }\n"
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
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let renderer = TypesEmitter::new(&mut model);
        let actual = render_result_type(
            &response_result_arms(&renderer, &plan, "HeadHealth"),
            &plan,
            "HeadHealth",
        );
        let expected = "export type HeadHealthResult =\n  | { outcome: 200; ok: true; status: 200; data: undefined; meta: ResponseMeta }\n  | { outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n";
        assert_eq!(actual, expected);
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
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        assert!(schema_is_array(&model, &items_ref, &mut HashSet::new()));
        let mut visited = HashSet::from([(
            items_ref.meta().source.source_id.clone(),
            items_ref.meta().source.json_pointer.clone(),
        )]);
        if let SchemaNode::Ref { target, .. } = &items_ref {
            visited.clear();
            visited.insert((target.source_id.clone(), target.json_pointer.clone()));
        }
        assert!(!schema_is_array(&model, &items_ref, &mut visited));
        assert!(schema_is_array(
            &model,
            &SchemaNode::Array {
                items: Box::new(string_schema(None)),
                finite: None,
                meta: SchemaMeta::default(),
            },
            &mut HashSet::new()
        ));
        assert!(!schema_is_array(
            &model,
            &string_schema(None),
            &mut HashSet::new()
        ));

        let body = BodyPlan::ContentTypeDiscriminated {
            arms: vec![
                (
                    "multipart/form-data".to_owned(),
                    BodyPlan::Multipart {
                        media: "multipart/form-data".to_owned(),
                        fields: fields.clone(),
                        source: SourceRef::default(),
                    },
                ),
                (
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
                (
                    "application/json".to_owned(),
                    BodyPlan::Json {
                        media: "application/json".to_owned(),
                        schema: Some(object_schema()),
                        source: SourceRef::default(),
                    },
                ),
                (
                    "text/plain".to_owned(),
                    BodyPlan::TopLevelText {
                        media: "text/plain".to_owned(),
                        schema: Some(string_schema(None)),
                        source: SourceRef::default(),
                    },
                ),
                (
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
            let renderer = TypesEmitter::new(&mut model);
            let input = render_body_input(&renderer, &body, "Probe", 2);
            assert!(input.contains("contentType: string"));
            assert!(input.contains("filename?: string"));
            assert!(input.contains("Blob | File"));
            assert!(input.contains("encoded: string"));
            let mut imports = BTreeMap::new();
            collect_body_imports(&renderer, &body, &mut imports);
            let mut import_text = String::new();
            write_component_imports(&mut import_text, imports, ".js");
            assert!(import_text.contains("types/components"));
        }
        let mut descriptor = String::new();
        write_body_descriptor(&mut descriptor, &model, &body, 2);
        assert!(descriptor.contains("content-discriminated"));
        assert!(descriptor.contains("kind: \"form-urlencoded\""));
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
        assert_eq!(security_field(&[]), "[]");

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
            "[\n    [{ name: \"headerKey\", kind: \"apiKeyHeader\", param: \"X-Api-Key\", scopes: [] }],\n    [{ name: \"oauthFlow\", kind: \"oauth2\", scopes: [\"scope.a\"] }],\n  ]"
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
            "[\n    [{ name: \"basicAuth\", kind: \"basic\", scopes: [] }, { name: \"headerKey\", kind: \"apiKeyHeader\", param: \"X-Api-Key\", scopes: [] }],\n  ]"
        );

        let anonymous_included: Vec<AuthAlternative> = vec![
            vec![auth_scheme("bearerAuth", AuthKind::Bearer, &[])],
            vec![],
        ];
        assert_eq!(
            security_field(&anonymous_included),
            "[\n    [{ name: \"bearerAuth\", kind: \"bearer\", scopes: [] }],\n    [],\n  ]"
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
            "[\n    [{ name: \"digestAuth\", kind: \"httpScheme\", scheme: \"Digest\", scopes: [] }],\n  ]"
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
            "[\n    [{ name: \"mtls\", kind: \"mutualTls\", scopes: [] }],\n  ]"
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
            "import { execute, executeOrThrow, type AmbientClientCertificate, type CallOptions, type OperationDescriptor, type Transport } from"
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
            "export type AnonymousIncludedCallArgs<S extends string> = [options?: CallOptions];\n"
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
            "[\n    [{ name: \"basicAuth\", kind: \"basic\", scopes: [] }, { name: \"bearerAuth\", kind: \"bearer\", scopes: [] }],\n    [{ name: \"headerKey\", kind: \"apiKeyHeader\", param: \"X-Api-Key\", scopes: [] }, { name: \"queryKey\", kind: \"apiKeyQuery\", param: \"api_key\", scopes: [] }, { name: \"cookieKey\", kind: \"apiKeyCookie\", param: \"session\", scopes: [] }],\n    [{ name: \"oauthFlow\", kind: \"oauth2\", scopes: [\"scope.a\"] }],\n    [{ name: \"oidc\", kind: \"openIdConnect\", scopes: [] }],\n    [],\n  ]"
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
            "import { execute, executeOrThrow, type AmbientCookieCredential, type BasicCredential, type CallOptions, type OperationDescriptor, type Transport } from"
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
            "export type InheritedRootOnlyCallArgs<S extends string> = [options?: CallOptions];\n"
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
                .contains("export type PingCallArgs<S extends string> = [options?: CallOptions];")
        );
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
            "artifacts": { "types": true, "client": true, "validators": true },
            "client": {
                "authEnforcement": "types",
                "baseUrl": { "source": "literal", "value": "https://api.example.test/v1" }
            },
            "validation": {
                "engine": "generated",
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
        let ir = parse(&graph, &mut sink).expect("IR");
        let analyzed = analyze(ir, &config, &mut sink);
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);
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
        let content = emit_validated_operation(document, "readthing", false, true);
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
            "{HEADER}import type {{ ListItemsResponse200 }} from \"../../types/operations/listitems.js\";\nimport type {{ RequestPhaseFailure, ResponseMeta, ResponsePhaseFailure, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1items/get\nexport type ListItemsInput = {{}};\n\n// Source: workspace/openapi.json#/paths/~1items/get\nexport type ListItemsResult =\n  | {{ outcome: 200; ok: true; status: 200; data: ListItemsResponse200; meta: ResponseMeta }}\n  | {{ outcome: \"unmatched\"; ok: false; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | ResponsePhaseFailure<200>\n  | RequestPhaseFailure;\n\nexport type ListItemsCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1items/get\nconst descriptor: OperationDescriptor = {{\n  operationId: \"listItems\",\n  method: \"GET\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"items\" }}],\n  ],\n  params: [],\n  body: null,\n  accept: \"application/json\",\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A typed result covering every documented response and failure.\n */\nexport async function listItems<S extends string = never>(transport: Transport<S>, input: ListItemsInput, ...args: ListItemsCallArgs<S>): Promise<ListItemsResult> {{\n  return execute<ListItemsResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data and its response metadata.\n */\nexport async function listItemsOrThrow<S extends string = never>(transport: Transport<S>, input: ListItemsInput, ...args: ListItemsCallArgs<S>): Promise<{{ data: ListItemsResponse200; meta: ResponseMeta }}> {{\n  return executeOrThrow<ListItemsResult>(transport, descriptor, input, args[0]);\n}}\n"
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
}
