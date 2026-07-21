//! Fetch client artifact emission from the client planning IR.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::client_model::{
    AuthAlternative, AuthKind, AuthSchemeUse, BaseUrlPlan, BodyPlan, ClientModel, DecoderClass,
    FieldSerializationPlan, FormFieldPlan, HeaderInputRequirement, HelperId, OperationPlan,
    PartMediaPlan, PayloadDisposition, ResponseMatchKind, ResponsePlan,
};
use crate::config::{
    AuthEnforcement, CacheMode, CredentialsMode, DocumentationConfig, FetchDefaults, RedirectMode,
    ReferrerPolicyValue, RequestModeValue,
};
use crate::ir::{
    Operation, Param, ParamLocation, ParamStyle, PrimitiveType, SchemaNode, SegmentPart,
};

use super::model::EmissionModel;
use super::runtime_assets::{RuntimeSelection, emit_runtime_files};
use super::{
    ClientDocKind, Emitter as TypesEmitter, GeneratedFile, TypePosition, encode_comment_text,
    render_property_key, render_ts_string, source_diagnostic, uppercase_first,
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
        let parameters = operation
            .parameters
            .iter()
            .filter(|parameter| parameter.location != ParamLocation::Cookie)
            .collect::<Vec<_>>();
        assert_eq!(parameters.len(), plan.param_plans.len());
        let mut input_properties: BTreeMap<&str, &Param> = BTreeMap::new();
        let mut has_parameter_collision = false;
        for (parameter, parameter_plan) in parameters.iter().zip(&plan.param_plans) {
            if let Some(first_parameter) = input_properties.get(parameter_plan.name.as_str()) {
                model.sink.push(source_diagnostic(
                    "OASTS1422",
                    format!(
                        "parameter '{}' in {} ({}) and parameter '{}' in {} ({}) collide at generated input property '{}'",
                        first_parameter.name,
                        location_name(first_parameter.location),
                        first_parameter.source.display(),
                        parameter.name,
                        location_name(parameter.location),
                        parameter.source.display(),
                        parameter_plan.name,
                    ),
                    &parameter.source,
                ));
                has_parameter_collision = true;
                break;
            }
            input_properties.insert(parameter_plan.name.as_str(), *parameter);
        }
        let mut has_body_collision = false;
        if plan.body_plan.is_some()
            && let Some(parameter) = parameters.iter().find(|parameter| parameter.name == "body")
        {
            model.sink.push(source_diagnostic(
                "OASTS1421",
                "parameter 'body' collides with the request body at generated input property 'body'",
                &parameter.source,
            ));
            has_body_collision = true;
        }
        if has_parameter_collision || has_body_collision {
            continue;
        }
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
    let base_url = model
        .config
        .client
        .as_ref()
        .expect("client emission requires resolved client config")
        .base_url
        .clone();
    files.extend(emit_runtime_files(RuntimeSelection {
        model,
        helper_ids: &helper_ids,
        serialize_needed: true,
        base_url: &base_url,
        source: &source,
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

fn emit_operation(
    model: &mut EmissionModel<'_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    allocated_name: &str,
    file_base: &str,
) -> String {
    let stem = uppercase_first(allocated_name);
    let operation_type_names = operation_type_imports(plan, &stem);
    let mut component_imports = BTreeMap::<String, BTreeSet<String>>::new();
    let documentation = model.config.documentation.clone();
    let input = {
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
        render_input(&renderer, operation, plan, &stem, &documentation)
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
    let (imports_basic_credential, imports_cookie_credential) =
        call_args_credentials(plan, auth_enforcement);
    let runtime_directory = &model.config.emit.runtime_directory;
    let unchecked_response = model
        .config
        .validation
        .as_ref()
        .is_some_and(|validation| !validation.response);
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
    output.push_str(
        "import type { RequestFailure, ResponseFailure, ResponseMeta, UnknownHttpError } from ",
    );
    output.push_str(&render_ts_string(&format!(
        "../../{runtime_directory}/result{extension}"
    )));
    output.push_str(";\n");
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
    output.push_str(";\n\n");

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
    write_result_type(&mut output, plan, &stem);
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
    output.push_str("Result> {\n  return execute<");
    output.push_str(&stem);
    output.push_str("Result>(transport, descriptor, input, args[0]);\n}\n\n");

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
    output.push_str(&successful_payload_union(plan, &stem));
    output.push_str("> {\n  return executeOrThrow<");
    output.push_str(&stem);
    output.push_str("Result>(transport, descriptor, input, args[0]);\n}\n");
    output
}

fn import_extension(model: &EmissionModel<'_, '_>) -> String {
    if model.config.emit.import_extension == "none" {
        String::new()
    } else {
        model.config.emit.import_extension.clone()
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
        if matches!(response.payload, PayloadDisposition::Payload { .. }) {
            names.insert(response_type_name(stem, response));
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
                if let FieldSerializationPlan::Content { caller_headers, .. } = &field.serialization
                {
                    for header in caller_headers {
                        renderer.collect_operation_imports(
                            &header.schema,
                            TypePosition::Request,
                            imports,
                        );
                    }
                }
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
    let parameters = operation
        .parameters
        .iter()
        .filter(|parameter| parameter.location != ParamLocation::Cookie)
        .collect::<Vec<_>>();
    assert_eq!(parameters.len(), plan.param_plans.len());
    let mut output = String::from("{\n");
    for (parameter, parameter_plan) in parameters.into_iter().zip(&plan.param_plans) {
        if let Some(description) = &parameter.description {
            write_parameter_property_tsdoc(&mut output, description, documentation, 2);
        }
        output.push_str("  ");
        output.push_str(&render_property_key(&parameter_plan.name));
        if !parameter.required {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(&renderer.render_type(&parameter_plan.schema, TypePosition::Request, 2));
        output.push_str(";\n");
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
    let prefix = " ".repeat(indent);
    output.push_str(&prefix);
    output.push_str("/**\n");
    if !documentation.summary {
        output.push_str(&prefix);
        output.push_str(" * @remarks\n");
    }
    for line in encode_comment_text(description).split('\n') {
        output.push_str(&prefix);
        output.push_str(" * ");
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&prefix);
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
        output.push_str(&" ".repeat(indent + 2));
        output.push_str(&render_property_key(&field.name));
        if !field.required {
            output.push('?');
        }
        output.push_str(": ");
        output.push_str(&render_form_field_input(renderer, field, indent + 2));
        output.push_str(";\n");
    }
    output.push_str(&" ".repeat(indent));
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
    if let FieldSerializationPlan::Content { caller_headers, .. } = &field.serialization
        && field.wrapper.headers != HeaderInputRequirement::None
    {
        output.push_str("; headers");
        if field.wrapper.headers == HeaderInputRequirement::Optional {
            output.push('?');
        }
        output.push_str(": {");
        if !caller_headers.is_empty() {
            output.push('\n');
            for header in caller_headers {
                output.push_str(&" ".repeat(indent + 2));
                output.push_str(&render_property_key(&header.name));
                if !header.required {
                    output.push('?');
                }
                output.push_str(": ");
                output.push_str(&renderer.render_type(
                    &header.schema,
                    TypePosition::Request,
                    indent + 2,
                ));
                output.push_str(";\n");
            }
            output.push_str(&" ".repeat(indent));
        }
        output.push('}');
    }
    if field.wrapper.filename {
        output.push_str("; filename?: string");
    }
    output.push_str(" }");
    output
}

fn write_result_type(output: &mut String, plan: &OperationPlan, stem: &str) {
    output.push_str("export type ");
    output.push_str(stem);
    output.push_str("Result =\n");
    for response in &plan.response_table {
        write_response_result_arms(output, response, stem);
    }
    output.push_str("  | { kind: \"unmatched-response\"; ok: false; match: null; status: number; error: UnknownHttpError; meta: ResponseMeta }\n");
    output.push_str("  | { kind: \"response-failure\"; ok: false; match: ");
    if plan.response_table.is_empty() {
        output.push_str("null");
    } else {
        output.push_str(
            &plan
                .response_table
                .iter()
                .map(|response| render_ts_string(&response.match_key))
                .chain(std::iter::once("null".to_owned()))
                .collect::<Vec<_>>()
                .join(" | "),
        );
    }
    output.push_str("; status: number; error: ResponseFailure; meta: ResponseMeta }\n");
    output.push_str("  | { kind: \"request-failure\"; ok: false; match: null; status: null; error: RequestFailure };\n");
}

fn write_response_result_arms(output: &mut String, response: &ResponsePlan, stem: &str) {
    let statuses = match response.kind {
        ResponseMatchKind::Exact => response.match_key.clone(),
        ResponseMatchKind::Range | ResponseMatchKind::Default => "number".to_owned(),
    };
    let payload = response_payload_type(response, stem);
    let media = if matches!(response.payload, PayloadDisposition::Payload { .. })
        && response.content_type_discriminated
    {
        response
            .media
            .iter()
            .map(|media| Some(media.media.as_str()))
            .collect::<Vec<_>>()
    } else {
        vec![None]
    };
    match response.kind {
        ResponseMatchKind::Default => {
            for content_type in &media {
                write_response_result_arm(
                    output,
                    response,
                    &statuses,
                    &payload,
                    true,
                    *content_type,
                );
                write_response_result_arm(
                    output,
                    response,
                    &statuses,
                    &payload,
                    false,
                    *content_type,
                );
            }
        }
        ResponseMatchKind::Exact | ResponseMatchKind::Range => {
            let ok = if response.kind == ResponseMatchKind::Exact {
                response
                    .match_key
                    .parse::<u16>()
                    .is_ok_and(|status| (200..=299).contains(&status))
            } else {
                response.match_key.starts_with('2')
            };
            for content_type in media {
                write_response_result_arm(output, response, &statuses, &payload, ok, content_type);
            }
        }
    }
}

fn write_response_result_arm(
    output: &mut String,
    response: &ResponsePlan,
    status: &str,
    payload: &str,
    ok: bool,
    content_type: Option<&str>,
) {
    output.push_str("  | { kind: \"response\"; ok: ");
    output.push_str(if ok { "true" } else { "false" });
    output.push_str("; match: ");
    output.push_str(&render_ts_string(&response.match_key));
    output.push_str("; status: ");
    output.push_str(status);
    output.push_str(if ok { "; data: " } else { "; error: " });
    output.push_str(payload);
    if let Some(content_type) = content_type {
        output.push_str("; contentType: ");
        output.push_str(&render_ts_string(content_type));
    }
    output.push_str("; meta: ResponseMeta }\n");
}

fn response_payload_type(response: &ResponsePlan, stem: &str) -> String {
    match response.payload {
        PayloadDisposition::NoPayload | PayloadDisposition::StaticBodyless => {
            "undefined".to_owned()
        }
        PayloadDisposition::Payload { .. } => response_type_name(stem, response),
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

fn successful_payload_union(plan: &OperationPlan, stem: &str) -> String {
    let mut payloads = Vec::new();
    for response in &plan.response_table {
        let successful = match response.kind {
            ResponseMatchKind::Exact => response
                .match_key
                .parse::<u16>()
                .is_ok_and(|status| (200..=299).contains(&status)),
            ResponseMatchKind::Range => response.match_key.starts_with('2'),
            ResponseMatchKind::Default => true,
        };
        if successful {
            let payload = response_payload_type(response, stem);
            if !payloads.contains(&payload) {
                payloads.push(payload);
            }
        }
    }
    if payloads.is_empty() {
        "never".to_owned()
    } else {
        payloads.join(" | ")
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
    let parameters = operation
        .parameters
        .iter()
        .filter(|parameter| parameter.location != ParamLocation::Cookie)
        .collect::<Vec<_>>();
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

/// Whether this module's `CallArgs` alias references the `BasicCredential` and/or
/// `AmbientCookieCredential` runtime types, deciding which runtime imports the module needs.
fn call_args_credentials(plan: &OperationPlan, enforcement: AuthEnforcement) -> (bool, bool) {
    if call_args_is_unconditional(&plan.auth_plan, enforcement) {
        return (false, false);
    }
    let mut basic = false;
    let mut cookie = false;
    for alternative in &plan.auth_plan {
        for scheme in alternative {
            if matches!(scheme.kind, AuthKind::Basic) {
                basic = true;
            }
            if matches!(scheme.kind, AuthKind::ApiKeyCookie { .. }) {
                cookie = true;
            }
        }
    }
    (basic, cookie)
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
        AuthKind::Basic | AuthKind::Bearer | AuthKind::OAuth2 | AuthKind::OpenIdConnect => None,
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
                output.push_str(&" ".repeat(indent + 2));
                output.push_str("{ name: ");
                output.push_str(&render_ts_string(&field.name));
                output.push_str(", required: ");
                output.push_str(if field.required { "true" } else { "false" });
                if let FieldSerializationPlan::Style {
                    style,
                    explode,
                    allow_reserved,
                    ..
                } = &field.serialization
                {
                    output.push_str(", style: ");
                    output.push_str(&render_ts_string(style_name(*style)));
                    output.push_str(", explode: ");
                    output.push_str(if *explode { "true" } else { "false" });
                    output.push_str(", allowReserved: ");
                    output.push_str(if *allow_reserved { "true" } else { "false" });
                }
                output.push_str(" },\n");
            }
            output.push_str(&" ".repeat(indent));
            output.push_str("] }");
        }
        BodyPlan::Multipart { fields, .. } => {
            output.push_str("{ kind: \"multipart\", fields: [\n");
            for field in fields {
                write_multipart_field(output, model, field, indent + 2);
            }
            output.push_str(&" ".repeat(indent));
            output.push_str("] }");
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            output.push_str("{ kind: \"content-discriminated\", arms: [\n");
            for (media, arm) in arms {
                output.push_str(&" ".repeat(indent + 2));
                output.push('[');
                output.push_str(&render_ts_string(media));
                output.push_str(", ");
                write_body_descriptor(output, model, arm, indent + 2);
                output.push_str("],\n");
            }
            output.push_str(&" ".repeat(indent));
            output.push_str("] }");
        }
    }
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
    output.push_str(&" ".repeat(indent));
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
    if let FieldSerializationPlan::Content {
        content_transfer_encoding: Some(value),
        ..
    } = &field.serialization
    {
        output.push_str(", cte: ");
        output.push_str(&render_ts_string(value));
    }
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
    if media.binary_upload {
        return "binary";
    }
    let value = media.values.first().map_or("", String::as_str);
    if value == "application/json" || value.ends_with("+json") {
        "json"
    } else if value.starts_with("text/") {
        "text"
    } else {
        "binary"
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
        ParamLocation::Cookie => "header",
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
        HelperId::QueryPipeDelimited => "query-pipe-delimited",
        HelperId::QueryDeepObject => "query-deep-object",
        HelperId::HeaderSimple => "header-simple",
        HelperId::HeaderSimpleExplode => "header-simple-explode",
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
        HelperId::QueryPipeDelimited => "serializeQueryPipeDelimited",
        HelperId::QueryDeepObject => "serializeQueryDeepObject",
        HelperId::HeaderSimple => "serializeHeaderSimple",
        HelperId::HeaderSimpleExplode => "serializeHeaderSimpleExplode",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::client_model::{
        CallerHeaderPlan, FieldWrapperPlan, ResponseMediaPlan, build_client_model,
    };
    use crate::config::{ResolvedConfig, load_config_from_json};
    use crate::diag::{Diagnostic, DiagnosticSink};
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
            "{HEADER}import type {{ GetPetResponse200, GetPetResponseDefault }} from \"../../types/operations/getpet.js\";\nimport type {{ RequestFailure, ResponseFailure, ResponseMeta, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ serializePathSimple, serializeQueryFormExplode }} from \"../../runtime/serialize.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetInput = {{\n  /**\n   * The pet identifier.\n   */\n  petId: string;\n  /**\n   * The result limit.\n   */\n  limit?: number;\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Responses\n * \n * - 200: found\n * - default: fallback\n */\nexport type GetPetResult =\n  | {{ kind: \"response\"; ok: true; match: \"200\"; status: 200; data: GetPetResponse200; meta: ResponseMeta }}\n  | {{ kind: \"response\"; ok: true; match: \"default\"; status: number; data: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ kind: \"response\"; ok: false; match: \"default\"; status: number; error: GetPetResponseDefault; meta: ResponseMeta }}\n  | {{ kind: \"unmatched-response\"; ok: false; match: null; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | {{ kind: \"response-failure\"; ok: false; match: \"200\" | \"default\" | null; status: number; error: ResponseFailure; meta: ResponseMeta }}\n  | {{ kind: \"request-failure\"; ok: false; match: null; status: null; error: RequestFailure }};\n\nexport type GetPetCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\nconst descriptor: OperationDescriptor = {{\n  operationId: \"getPet\",\n  method: \"GET\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"pets\" }}],\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"param\", name: \"petId\" }}],\n  ],\n  params: [\n    {{ name: \"petId\", location: \"path\", required: true, serialize: serializePathSimple, allowReserved: false }},\n    {{ name: \"limit\", location: \"query\", required: false, serialize: serializeQueryFormExplode, allowReserved: false }},\n  ],\n  body: null,\n  accept: \"application/json\",\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n    {{ match: \"default\", kind: \"default\", status: null, bodyless: false, media: [[\"application/json\", \"json\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns A result discriminated by HTTP status.\n */\nexport async function getPet<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<GetPetResult> {{\n  return execute<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1pets~1{{petId}}/get\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Responses\n * \n * - 200: found\n * - default: fallback\n * \n * @returns The successful response data.\n */\nexport async function getPetOrThrow<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>): Promise<GetPetResponse200 | GetPetResponseDefault> {{\n  return executeOrThrow<GetPetResult>(transport, descriptor, input, args[0]);\n}}\n"
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
            "{HEADER}import type {{ RequestFailure, ResponseFailure, ResponseMeta, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetInput = {{\n  body: {{\n    meta: {{ body: {{\n      tag?: string;\n    }}; contentType: \"application/json\" | \"application/cbor\" }};\n    title: string;\n    file: Blob | File;\n  }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nexport type UploadAssetResult =\n  | {{ kind: \"response\"; ok: true; match: \"204\"; status: 204; data: undefined; meta: ResponseMeta }}\n  | {{ kind: \"unmatched-response\"; ok: false; match: null; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | {{ kind: \"response-failure\"; ok: false; match: \"204\" | null; status: number; error: ResponseFailure; meta: ResponseMeta }}\n  | {{ kind: \"request-failure\"; ok: false; match: null; status: null; error: RequestFailure }};\n\nexport type UploadAssetCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"uploadAsset\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"uploads\" }}],\n  ],\n  params: [],\n  body: {{ kind: \"multipart\", fields: [\n    {{ name: \"meta\", required: true, repeated: false, wrapper: true, payload: \"json\", contentType: {{ kind: \"selected\", admitted: [\"application/json\", \"application/cbor\"] }}, filename: false }},\n    {{ name: \"title\", required: true, repeated: false, wrapper: false, payload: \"text\", contentType: {{ kind: \"fixed\", value: \"text/plain\" }}, filename: false }},\n    {{ name: \"file\", required: true, repeated: false, wrapper: false, payload: \"binary\", contentType: {{ kind: \"fixed\", value: \"application/octet-stream\" }}, filename: true }},\n  ] }},\n  accept: null,\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"204\", kind: \"exact\", status: 204, bodyless: false, media: [], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A result discriminated by HTTP status.\n */\nexport async function uploadAsset<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<UploadAssetResult> {{\n  return execute<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1uploads/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data.\n */\nexport async function uploadAssetOrThrow<S extends string = never>(transport: Transport<S>, input: UploadAssetInput, ...args: UploadAssetCallArgs<S>): Promise<undefined> {{\n  return executeOrThrow<UploadAssetResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "uploadasset");
        assert_eq!(actual, expected);
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
            "{HEADER}import type {{ SendMessageRequest, SendMessageResponse200 }} from \"../../types/operations/sendmessage.js\";\nimport type {{ RequestFailure, ResponseFailure, ResponseMeta, UnknownHttpError }} from \"../../runtime/result.js\";\nimport {{ execute, executeOrThrow, type CallOptions, type OperationDescriptor, type Transport }} from \"../../runtime/transport.js\";\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageInput = {{\n  body: {{ contentType: \"application/json\"; body: SendMessageRequest[\"body\"] }} | {{ contentType: \"text/plain\"; body: string }};\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nexport type SendMessageResult =\n  | {{ kind: \"response\"; ok: true; match: \"200\"; status: 200; data: SendMessageResponse200; meta: ResponseMeta }}\n  | {{ kind: \"unmatched-response\"; ok: false; match: null; status: number; error: UnknownHttpError; meta: ResponseMeta }}\n  | {{ kind: \"response-failure\"; ok: false; match: \"200\" | null; status: number; error: ResponseFailure; meta: ResponseMeta }}\n  | {{ kind: \"request-failure\"; ok: false; match: null; status: null; error: RequestFailure }};\n\nexport type SendMessageCallArgs<S extends string> = [options?: CallOptions];\n\n// Source: workspace/openapi.json#/paths/~1messages/post\nconst descriptor: OperationDescriptor = {{\n  operationId: \"sendMessage\",\n  method: \"POST\",\n  path: [\n    [{{ kind: \"literal\", text: \"/\" }}, {{ kind: \"literal\", text: \"messages\" }}],\n  ],\n  params: [],\n  body: {{ kind: \"content-discriminated\", arms: [\n    [\"application/json\", {{ kind: \"json\", contentType: \"application/json\" }}],\n    [\"text/plain\", {{ kind: \"text\", contentType: \"text/plain\" }}],\n  ] }},\n  accept: \"text/plain\",\n  credentialHeaders: [\"authorization\"],\n  security: [],\n  responses: [\n    {{ match: \"200\", kind: \"exact\", status: 200, bodyless: false, media: [[\"text/plain\", \"text\"]], hasContentTypeDiscriminant: false }},\n  ],\n  baseUrl: {{ kind: \"literal\", value: \"https://api.example.test/v1\" }},\n  fetchDefaults: {{}},\n}};\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns A result discriminated by HTTP status.\n */\nexport async function sendMessage<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<SendMessageResult> {{\n  return execute<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n\n// Source: workspace/openapi.json#/paths/~1messages/post\n/**\n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * @returns The successful response data.\n */\nexport async function sendMessageOrThrow<S extends string = never>(transport: Transport<S>, input: SendMessageInput, ...args: SendMessageCallArgs<S>): Promise<SendMessageResponse200> {{\n  return executeOrThrow<SendMessageResult>(transport, descriptor, input, args[0]);\n}}\n"
        );
        let (actual, diagnostics) = emit_operation(document, "sendmessage");
        assert_eq!(actual, expected);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn body_parameter_collision_is_oxs1421_and_skips_the_operation() {
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
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);

        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("client/operations/"))
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS1421")
            .expect("collision diagnostic");
        assert!(diagnostic.message.contains("parameter 'body'"));
        assert!(diagnostic.message.contains("request body"));
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| diagnostic.code != "OASTS1422")
        );
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1collision/post/parameters/0")
        );
    }

    #[test]
    fn cookie_body_parameter_is_oxs1410_without_collision_diagnostics() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/collision": {
                    "post": {
                        "operationId": "cookieBody",
                        "parameters": [
                            { "name": "body", "in": "cookie", "schema": { "type": "string" } }
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
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);

        assert!(
            files
                .iter()
                .any(|file| file.relative_path == "client/operations/cookiebody.ts")
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1410")
        );
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| { diagnostic.code != "OASTS1421" && diagnostic.code != "OASTS1422" })
        );
    }

    #[test]
    fn parameter_property_collision_is_oxs1422_and_skips_the_operation() {
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
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let mut sink = DiagnosticSink::new();
        let client = build_client_model(&analyzed, &config, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = emit_client_from_model(&mut model, &client);
        drop(model);

        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("client/operations/"))
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS1422")
            .expect("collision diagnostic");
        assert!(diagnostic.message.contains("parameter 'id' in path"));
        assert!(diagnostic.message.contains("parameter 'id' in query"));
        assert!(diagnostic.message.contains("generated input property 'id'"));
        assert!(diagnostic.message.contains("/parameters/0"));
        assert!(diagnostic.message.contains("/parameters/1"));
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1items~1{id}/get/parameters/1")
        );
    }

    #[test]
    fn distinct_parameter_properties_do_not_emit_oxs1422() {
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
        let pet_id_property = "/**\n   * The pet identifier.\n   */\n";
        let limit_property = "/**\n   * The result limit.\n   */\n";
        let result_function = "/**\n * Read a pet.\n * \n * @remarks\n * Successful response data is decoded but unchecked against the OpenAPI schema.\n * \n * Loads one pet.\n * \n * Responses\n * \n * - 200: Found.\n * - 404: Missing.\n * \n * @deprecated This operation is deprecated.\n * \n * @returns A result discriminated by HTTP status.\n * \n * @see {@link https://docs.example.test/pets | Pet guide}\n */\n";
        let throw_function = result_function.replace(
            "@returns A result discriminated by HTTP status.",
            "@returns The successful response data.",
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
            "  /**\n   * @remarks\n   * Line one.\n   * \\@deprecated fake\n   * *\\/\n   */\n  \"X-Trace\"?: string;\n  undocumented?: boolean;"
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
            meta: SchemaMeta::default(),
        }
    }

    fn content_field(
        name: &str,
        schema: SchemaNode,
        media: PartMediaPlan,
        caller_headers: Vec<CallerHeaderPlan>,
        wrapper: FieldWrapperPlan,
        content_transfer_encoding: Option<&str>,
    ) -> FormFieldPlan {
        FormFieldPlan {
            name: name.to_owned(),
            required: true,
            schema,
            serialization: FieldSerializationPlan::Content {
                media,
                caller_headers,
                content_transfer_encoding: content_transfer_encoding.map(str::to_owned),
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
                headers: HeaderInputRequirement::None,
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
            source: SourceRef::default(),
        }
    }

    fn response_media(media: &str, decoder: DecoderClass) -> ResponseMediaPlan {
        ResponseMediaPlan {
            media: media.to_owned(),
            decoder,
            runtime_classified: false,
            schema: Some(string_schema(None)),
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
            HelperId::QueryPipeDelimited,
            HelperId::QueryDeepObject,
            HelperId::HeaderSimple,
            HelperId::HeaderSimpleExplode,
        ];
        for helper in helpers {
            assert!(!helper_region_id(helper).is_empty());
            assert!(helper_export_name(helper).starts_with("serialize"));
        }
        for (location, expected) in [
            (ParamLocation::Path, "path"),
            (ParamLocation::Query, "query"),
            (ParamLocation::Header, "header"),
            (ParamLocation::Cookie, "header"),
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
                all_concrete: true,
                binary_upload: false,
                declared: true,
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

    #[test]
    fn result_renderer_covers_range_default_and_discriminated_media() {
        let responses = vec![
            response_plan(
                "404",
                ResponseMatchKind::Exact,
                PayloadDisposition::Payload {
                    schemas: vec![Some(string_schema(None))],
                },
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
                PayloadDisposition::Payload {
                    schemas: vec![Some(string_schema(None)), Some(string_schema(None))],
                },
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
        let mut output = String::new();
        write_result_type(&mut output, &plan, "Probe");
        assert!(output.contains("match: \"2XX\"; status: number; data: undefined"));
        assert!(output.contains("contentType: \"text/plain\""));
        assert!(output.contains("ok: false; match: \"default\""));
        assert_eq!(
            successful_payload_union(&plan, "Probe"),
            "undefined | ProbeResponseDefault"
        );

        let empty = OperationPlan {
            response_table: Vec::new(),
            ..plan
        };
        let mut output = String::new();
        write_result_type(&mut output, &empty, "Empty");
        assert!(output.contains("response-failure\"; ok: false; match: null"));
        assert_eq!(successful_payload_union(&empty, "Empty"), "never");
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
        let mut actual = String::new();
        write_result_type(&mut actual, &plan, "HeadHealth");
        let expected = "export type HeadHealthResult =\n  | { kind: \"response\"; ok: true; match: \"200\"; status: 200; data: undefined; meta: ResponseMeta }\n  | { kind: \"unmatched-response\"; ok: false; match: null; status: number; error: UnknownHttpError; meta: ResponseMeta }\n  | { kind: \"response-failure\"; ok: false; match: \"200\" | null; status: number; error: ResponseFailure; meta: ResponseMeta }\n  | { kind: \"request-failure\"; ok: false; match: null; status: null; error: RequestFailure };\n";
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
                    "Items": { "type": "array", "items": { "type": "string" } },
                    "HeaderValue": { "type": "string" }
                }
            }
        });
        let (_temp, analyzed, config, _source_tuples) = analyzed(&document);
        let source_id = analyzed.ir.schemas[0].source.source_id.clone();
        let items_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: source_id.clone(),
                json_pointer: "/components/schemas/Items".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let header_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id,
                json_pointer: "/components/schemas/HeaderValue".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let caller_header = CallerHeaderPlan {
            name: "X-Part".to_owned(),
            required: false,
            schema: header_ref,
            source: SourceRef::default(),
        };
        let selected = content_field(
            "selected",
            items_ref.clone(),
            PartMediaPlan {
                values: vec!["application/json".to_owned(), "application/cbor".to_owned()],
                all_concrete: true,
                binary_upload: false,
                declared: true,
            },
            vec![caller_header.clone()],
            FieldWrapperPlan {
                wrapped: true,
                content_type_literal: true,
                headers: HeaderInputRequirement::Optional,
                filename: false,
            },
            Some("base64"),
        );
        let wildcard = content_field(
            "wildcard",
            string_schema(None),
            PartMediaPlan {
                values: vec!["text/*".to_owned()],
                all_concrete: false,
                binary_upload: false,
                declared: true,
            },
            vec![CallerHeaderPlan {
                required: true,
                ..caller_header
            }],
            FieldWrapperPlan {
                wrapped: true,
                content_type_literal: false,
                headers: HeaderInputRequirement::Required,
                filename: true,
            },
            None,
        );
        let binary = content_field(
            "binary",
            string_schema(Some("binary")),
            PartMediaPlan {
                values: vec!["application/octet-stream".to_owned()],
                all_concrete: true,
                binary_upload: true,
                declared: false,
            },
            Vec::new(),
            FieldWrapperPlan {
                wrapped: false,
                content_type_literal: true,
                headers: HeaderInputRequirement::None,
                filename: false,
            },
            None,
        );
        let empty_headers = content_field(
            "emptyHeaders",
            string_schema(None),
            PartMediaPlan {
                values: vec!["text/plain".to_owned()],
                all_concrete: true,
                binary_upload: false,
                declared: true,
            },
            Vec::new(),
            FieldWrapperPlan {
                wrapped: true,
                content_type_literal: true,
                headers: HeaderInputRequirement::Required,
                filename: false,
            },
            None,
        );
        let styled_object = style_field("styled", object_schema());
        let styled_binary = style_field("styledBinary", string_schema(Some("binary")));
        let styled_text = style_field("styledText", string_schema(None));
        let fields = vec![
            selected.clone(),
            wildcard.clone(),
            binary,
            empty_headers,
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
                        fields: vec![style_field("form", string_schema(None))],
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
            assert!(input.contains("headers?:"));
            assert!(input.contains("filename?: string"));
            assert!(input.contains("Blob | File"));
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
        assert!(descriptor.contains("cte: \"base64\""));
        assert!(descriptor.contains("payload: \"json\""));
        assert!(descriptor.contains("payload: \"binary\""));
        assert!(descriptor.contains("payload: \"text\""));
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
                        },
                        "responses": {}
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
                "/items/{id}": {
                    "get": {
                        "operationId": "descriptorProbe",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
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
}
