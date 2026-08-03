//! MSW handler artifact.
//!
//! Handlers mock the server side, so this emitter imports the types artifact and its own local
//! kernel and nothing else — never the client transport, the result model, or a validation engine.
//! That is also why it must not call [`EmissionModel::reserve_names`]: the types artifact has
//! already been emitted by the time this runs, so renaming a component here would leave the two
//! artifacts naming the same schema differently. Identifier clashes go through the same file-local
//! import aliasing the client uses instead.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    EmissionModel, Emitter as TypesEmitter, GeneratedFile, TypeAxis, TypePosition,
    assign_import_aliases, import_clause, import_extension, render_property_key, render_ts_string,
    render_ts_value, runtime_assets::rewrite_relative_ts_imports, source_diagnostic,
    uppercase_first, write_source_metadata,
};
use crate::client_model::{
    BodyPlan, FieldSerializationPlan, FormFieldPlan, HelperId, ParameterPlan, PartMediaPlan,
    PayloadKind, PrimitiveDomainProjector, body_plan_for_media, build_body_plan, parameter_plan,
};
use crate::composition::{finite_values, json_equal};
use crate::diag::Diagnostic;
use crate::ir::{
    AdditionalProperties, Operation, Param, ParamLocation, ParamStyle, PrimitiveType,
    ResponseStatus, SchemaNode, Segment, SegmentPart, ServerEntry, SourceRef,
};
use crate::response_media::{
    ResponseMediaKind, classify_response_media, diagnose_operation_response_media,
};

const MSW_RUNTIME_TS: &str = include_str!("../../runtime/msw-runtime.ts");
const MSW_PROJECT_TS: &str = include_str!("../../runtime/msw-project.ts");

/// A path literal carries a character the MSW matcher cannot be made to match.
const CODE_UNMATCHABLE_PATH: &str = "OASTS1506";

/// An operation uses an HTTP method for which MSW exposes no handler factory.
const CODE_UNMATCHABLE_METHOD: &str = "OASTS1507";

/// A parameter's declared wire form cannot be inverted into its generated TypeScript type.
const CODE_PARAMETER_PROJECTION: &str = "OASTS1508";

/// A request body's wire form cannot be inverted into its generated TypeScript type.
const CODE_BODY_PROJECTION: &str = "OASTS1509";

/// A parameter serialization loses boundaries before the handler can project its value.
const CODE_NONINVERTIBLE_PARAMETER: &str = "OASTS1510";

const MAX_PARAMETER_SHAPE_DEPTH: usize = 10;

/// How many shape nodes one parameter's projection descriptor may contain.
///
/// The depth limit alone does not bound the descriptor. A `$ref` target is inlined at every
/// position that names it, and the cycle guard is a path-scoped stack — it is popped on the way
/// out, so a schema shared between siblings is re-expanded once per sibling rather than reused.
/// Depth therefore bounds the *height* of the tree while its breadth multiplies freely: a document
/// of a few kilobytes whose refs branch eight ways at each of ten levels expands to billions of
/// nodes, and the compiler dies long before it reaches the depth limit. Measured before this
/// existed: 2.5 kB in, 51 MB of emitted handler out, growing eightfold per level.
///
/// The budget is per parameter and counts every node the descriptor emits, so it bounds the
/// product rather than either factor.
const MAX_PARAMETER_SHAPE_NODES: usize = 20_000;

/// The state one parameter's shape rendering carries: the reference path being walked, for cycle
/// detection, and the node budget above.
struct ProjectionLimits {
    visiting: BTreeSet<(String, String)>,
    remaining_nodes: usize,
}

impl ProjectionLimits {
    fn new() -> Self {
        Self {
            visiting: BTreeSet::new(),
            remaining_nodes: MAX_PARAMETER_SHAPE_NODES,
        }
    }

    /// Charges one node, failing when the descriptor has outgrown what is reasonable to emit.
    fn charge(&mut self) -> Result<(), String> {
        self.remaining_nodes = self.remaining_nodes.checked_sub(1).ok_or_else(|| {
            format!(
                "the parameter schema expands to more than {MAX_PARAMETER_SHAPE_NODES} projection nodes"
            )
        })?;
        Ok(())
    }
}

struct ProjectedParameter {
    index: usize,
    plan: ParameterPlan,
    shape: String,
}

struct ProjectedBody {
    plan: BodyPlan,
    required: bool,
    descriptor: String,
}

/// Characters that path-to-regexp treats as syntax and that a backslash escapes back into a
/// literal. Measured against the matcher rather than inferred: an unescaped `+` or `(` makes
/// handler registration *throw*, and an unescaped `?` or `:` matches the wrong requests.
const ESCAPABLE_PATH_SYNTAX: [char; 6] = ['\\', '+', '(', ')', '?', ':'];

/// `*` is the one character no escape reaches. MSW rewrites every `*` into a capture group before
/// path-to-regexp ever sees the pattern, so `\*` is rewritten too and then throws. A path literal
/// containing one has no representable matcher, which is a generation diagnostic rather than a
/// handler that quietly matches the wrong requests — or none at all.
const UNESCAPABLE_PATH_SYNTAX: char = '*';

/// Renders one operation's path template as an MSW path pattern.
///
/// Parameter names are re-spelled when the wire name is not a path-to-regexp identifier
/// (`[A-Za-z0-9_]+`): a hyphenated OpenAPI name such as `{pet-id}` simply never matches, and MSW
/// reports that as an unhandled request far from the cause. Re-spelling is safe because the
/// generated handler decodes parameter values from the request URL itself — MSW's own `params` is
/// never handed to the resolver — so the token only has to be unique, not meaningful.
fn path_pattern(path_template: &[Segment], source: &SourceRef) -> Result<String, Diagnostic> {
    let mut pattern = String::new();
    let mut param_index = 0usize;
    for segment in path_template {
        pattern.push('/');
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(literal) => {
                    if let Some(offending) = literal.chars().find(|c| *c == UNESCAPABLE_PATH_SYNTAX)
                    {
                        return Err(source_diagnostic(
                            CODE_UNMATCHABLE_PATH,
                            format!(
                                "path literal '{literal}' contains '{offending}', which the MSW request matcher always reads as a wildcard; no escape makes it match literally"
                            ),
                            source,
                        ));
                    }
                    for character in literal.chars() {
                        if ESCAPABLE_PATH_SYNTAX.contains(&character) {
                            pattern.push('\\');
                        }
                        pattern.push(character);
                    }
                }
                SegmentPart::Param(name) => {
                    pattern.push(':');
                    if is_path_to_regexp_identifier(name) {
                        pattern.push_str(name);
                    } else {
                        // The index keeps generated tokens unique even when two wire names
                        // normalize alike.
                        pattern.push_str(&format!("oastsParam{param_index}"));
                    }
                    // Exploded path collections serialize empty without a framing character. The
                    // projector accepts that wire value, so the request matcher must admit the
                    // same empty segment.
                    pattern.push_str("([^/]{0,})");
                    param_index += 1;
                }
            }
        }
    }
    if pattern.is_empty() {
        // The root path. A pattern that ends in a slash does not match a request without one,
        // while a bare pattern matches both, so the slash is dropped rather than emitted.
        pattern.push('/');
    }
    Ok(pattern)
}

fn is_path_to_regexp_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(crate) fn emit_msw_from_model(model: &mut EmissionModel<'_, '_>) -> Vec<GeneratedFile> {
    if !model.config.artifacts.client.enabled {
        let projector = PrimitiveDomainProjector::new(&model.analyzed.ir);
        for operation in &model.analyzed.ir.operations {
            diagnose_operation_response_media(operation, &projector, model.sink);
        }
        if model.sink.has_errors() {
            return Vec::new();
        }
    }
    let mut files = embedded_assets(model);
    for allocated in model.analyzed.operation_names.clone() {
        let Some(file_base) = model.operation_files[allocated.operation_index].clone() else {
            continue;
        };
        let operation = model.analyzed.ir.operations[allocated.operation_index].clone();
        if let Some(file) = emit_operation(model, &operation, &allocated.name, &file_base) {
            files.push(file);
        }
    }
    files.push(emit_paths(model));
    files
}

fn emit_paths(model: &mut EmissionModel<'_, '_>) -> GeneratedFile {
    let operations = model.analyzed.ir.operations.clone();
    let source = operations
        .first()
        .map(|operation| operation.source.clone())
        .or_else(|| {
            model
                .analyzed
                .ir
                .schemas
                .first()
                .map(|schema| schema.source.clone())
        })
        .unwrap_or_default();
    let mut component_imports = BTreeMap::<String, BTreeSet<String>>::new();
    {
        let renderer = TypesEmitter::new(model);
        let projector = PrimitiveDomainProjector::new(&model.analyzed.ir);
        for operation in &operations {
            for parameter in operation.parameters.iter().filter(|parameter| {
                matches!(
                    parameter.location,
                    ParamLocation::Path | ParamLocation::Query
                )
            }) {
                renderer.collect_operation_imports(
                    &parameter.schema,
                    TypePosition::Request,
                    TypeAxis::Application,
                    &mut component_imports,
                );
            }
            if let Some(body) = &operation.request_body {
                for media in &body.media_types {
                    let plan = body_plan_for_media(media, &projector);
                    collect_request_body_imports(&renderer, &plan, &mut component_imports);
                }
            }
            for response in &operation.responses {
                for media in &response.media_types {
                    if response_body_uses_schema(media, &projector) {
                        renderer.collect_operation_imports(
                            &media.schema,
                            TypePosition::Response,
                            TypeAxis::Application,
                            &mut component_imports,
                        );
                    }
                }
            }
        }
    }

    let declared = BTreeSet::from(["paths".to_owned()]);
    let mut reserved = BTreeSet::from(["Uint8Array"]);
    reserved.extend(super::representation_globals(&model.config.types));
    let (aliases, diagnostics) =
        assign_import_aliases(&declared, &reserved, &component_imports, &source);
    model.sink.extend(diagnostics);

    let extension = import_extension(model);
    let mut output = model.header();
    let has_component_imports = !component_imports.is_empty();
    write_component_imports(
        &mut output,
        component_imports,
        &aliases,
        &extension,
        "../types/components/",
    );
    if has_component_imports {
        output.push('\n');
    }
    output.push_str("export type paths = {\n");

    let mut paths = Vec::<(String, Vec<&Operation>)>::new();
    for operation in &operations {
        let path = raw_path_template(&operation.path_template);
        if let Some((_, methods)) = paths.iter_mut().find(|(key, _)| key == &path) {
            methods.push(operation);
        } else {
            paths.push((path, vec![operation]));
        }
    }

    let projector = PrimitiveDomainProjector::new(&model.analyzed.ir);
    let renderer = TypesEmitter::new(model);
    renderer.set_import_aliases(aliases);
    for (path, methods) in paths {
        output.push_str("  ");
        output.push_str(&render_ts_string(&path));
        output.push_str(": {\n");
        for operation in methods {
            write_paths_operation(&mut output, &renderer, model, operation, &projector);
        }
        output.push_str("  };\n");
    }
    output.push_str("};\n");

    let relative_path = "msw/paths.ts".to_owned();
    model.register_path(&relative_path, &source);
    GeneratedFile {
        relative_path,
        content: output,
    }
}

fn write_paths_operation(
    output: &mut String,
    renderer: &TypesEmitter<'_, '_, '_>,
    model: &EmissionModel<'_, '_>,
    operation: &Operation,
    projector: &PrimitiveDomainProjector<'_>,
) {
    output.push_str("    ");
    output.push_str(&operation.method.to_ascii_lowercase());
    output.push_str(": {\n      parameters: {");
    let mut wrote_parameter_group = false;
    for (location, name) in [
        (ParamLocation::Path, "path"),
        (ParamLocation::Query, "query"),
    ] {
        let parameters = operation
            .parameters
            .iter()
            .filter(|parameter| parameter.location == location)
            .collect::<Vec<_>>();
        if parameters.is_empty() {
            continue;
        }
        if !wrote_parameter_group {
            output.push('\n');
        }
        output.push_str("        ");
        output.push_str(name);
        output.push_str(": ");
        output.push_str(&renderer.render_parameter_group(&parameters, TypeAxis::Application, 8));
        output.push_str(";\n");
        wrote_parameter_group = true;
    }
    if wrote_parameter_group {
        output.push_str("      ");
    }
    output.push_str("};\n");

    if let Some(body) = &operation.request_body {
        output.push_str("      requestBody");
        if !body.required {
            output.push('?');
        }
        output.push_str(": {\n        content: {\n");
        for media in &body.media_types {
            let plan = body_plan_for_media(media, projector);
            output.push_str("          ");
            output.push_str(&render_ts_string(&media.full));
            output.push_str(": ");
            output.push_str(&render_request_body_type(renderer, model, &plan, 10));
            output.push_str(";\n");
        }
        output.push_str("        };\n      };\n");
    }

    output.push_str("      responses: {\n");
    for response in &operation.responses {
        output.push_str("        ");
        output.push_str(&render_ts_string(response_status_key(&response.status)));
        output.push_str(": {\n          content: ");
        if response.media_types.is_empty() {
            output.push_str("never;\n");
        } else {
            output.push_str("{\n");
            for media in &response.media_types {
                output.push_str("            ");
                output.push_str(&render_ts_string(&media.full));
                output.push_str(": ");
                output.push_str(&response_body_type(renderer, media, projector));
                output.push_str(";\n");
            }
            output.push_str("          };\n");
        }
        output.push_str("        };\n");
    }
    output.push_str("      };\n    };\n");
}

fn raw_path_template(template: &[Segment]) -> String {
    if template.is_empty() {
        return "/".to_owned();
    }
    let mut path = String::new();
    for segment in template {
        path.push('/');
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(value) => path.push_str(value),
                SegmentPart::Param(value) => {
                    path.push('{');
                    path.push_str(value);
                    path.push('}');
                }
            }
        }
    }
    path
}

fn response_status_key(status: &ResponseStatus) -> &str {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value,
        ResponseStatus::Default => "default",
    }
}

fn emit_operation(
    model: &mut EmissionModel<'_, '_>,
    operation: &Operation,
    allocated_name: &str,
    file_base: &str,
) -> Option<GeneratedFile> {
    let Some(method) = msw_method(&operation.method) else {
        model.sink.push(source_diagnostic(
            CODE_UNMATCHABLE_METHOD,
            format!(
                "HTTP method '{}' has no MSW http handler factory",
                operation.method.to_ascii_uppercase()
            ),
            &operation.source,
        ));
        return None;
    };
    let pattern = match path_pattern(&operation.path_template, &operation.source) {
        Ok(pattern) => pattern,
        Err(diagnostic) => {
            model.sink.push(diagnostic);
            return None;
        }
    };
    let projected_parameters = match plan_projected_parameters(model, operation) {
        Ok(parameters) => parameters,
        Err(diagnostics) => {
            model.sink.extend(diagnostics);
            return None;
        }
    };
    let projected_body = match plan_projected_body(model, operation) {
        Ok(body) => body,
        Err(diagnostics) => {
            model.sink.extend(diagnostics);
            return None;
        }
    };
    let response_projector = PrimitiveDomainProjector::new(&model.analyzed.ir);

    let stem = uppercase_first(allocated_name);
    let response_name = format!("{stem}Response");
    let resolver_input_name = format!("{stem}ResolverInput");
    let handler_name = format!("{allocated_name}Handler");
    let mut component_imports = BTreeMap::<String, BTreeSet<String>>::new();
    let (response_type, aliases, alias_diagnostics, response_body_name, response_body_union) = {
        let renderer = TypesEmitter::new(model);
        for response in &operation.responses {
            for media in &response.media_types {
                renderer.collect_operation_imports(
                    &media.schema,
                    TypePosition::Response,
                    TypeAxis::Application,
                    &mut component_imports,
                );
            }
        }
        for parameter in &operation.parameters {
            renderer.collect_operation_imports(
                &parameter.schema,
                TypePosition::Request,
                TypeAxis::Application,
                &mut component_imports,
            );
        }
        if let Some(body) = &projected_body {
            collect_request_body_imports(&renderer, &body.plan, &mut component_imports);
        }
        let declared = BTreeSet::from([
            response_name.clone(),
            resolver_input_name.clone(),
            handler_name.clone(),
        ]);
        let reserved = BTreeSet::from([
            "AsyncResponseResolverReturnType",
            "HttpHandler",
            "HttpResponse",
            "NoPayloadGuard",
            "ProjectionContext",
            "Record",
            "RequestBodyDescriptor",
            "SendableBody",
            "StrictRequest",
            "http",
            "projectParameter",
            "projectRequestBody",
            "requestBody",
            "respondWith",
        ]);
        let mut reserved = reserved;
        reserved.extend(super::representation_globals(&model.config.types));
        let (aliases, diagnostics) =
            assign_import_aliases(&declared, &reserved, &component_imports, &operation.source);
        renderer.set_import_aliases(aliases.clone());

        // This private marker usually takes the compact name shown below. If a component import or
        // one of its aliases already binds that name, only the private marker moves; public names
        // and component exports remain stable.
        let mut response_body_name = format!("{stem}ResponseBody");
        while declared.contains(&response_body_name)
            || component_imports
                .values()
                .flatten()
                .any(|name| aliases.get(name).map_or(name, |alias| alias) == &response_body_name)
        {
            response_body_name.push_str("Value");
        }
        (
            render_response_type(&renderer, operation, &response_name, &response_projector),
            aliases,
            diagnostics,
            response_body_name,
            response_body_union(&renderer, operation, &response_projector),
        )
    };
    model.sink.extend(alias_diagnostics);
    let has_projected_parameters = !projected_parameters.is_empty();
    let has_projected_cookies = projected_parameters
        .iter()
        .any(|projected| operation.parameters[projected.index].location == ParamLocation::Cookie);
    let has_response_body = response_body_union.is_some();
    let parameter_groups = {
        let renderer = TypesEmitter::new(model);
        renderer.set_import_aliases(aliases.clone());
        render_parameter_groups(&renderer, operation)
    };

    let extension = import_extension(model);
    let mut output = model.header();
    output.push_str("import { http } from \"msw\";\n");
    output.push_str(
        "import type { AsyncResponseResolverReturnType, HttpHandler, HttpResponse, StrictRequest } from \"msw\";\n\n",
    );
    output.push_str("import { respondWith, type NoPayloadGuard } from ");
    output.push_str(&render_ts_string(&format!("../runtime{extension}")));
    output.push_str(";\n");
    let mut project_imports = Vec::new();
    if has_projected_parameters {
        project_imports.push("projectParameter");
    }
    if projected_body.is_some() {
        project_imports.push("projectRequestBody");
    }
    if has_projected_parameters {
        project_imports.extend(["type Projected", "type ProjectionContext"]);
    }
    if projected_body.is_some() {
        project_imports.push("type RequestBodyDescriptor");
    }
    if has_response_body {
        project_imports.push("type SendableBody");
    }
    if !project_imports.is_empty() {
        output.push_str("import { ");
        output.push_str(&project_imports.join(", "));
        output.push_str(" } from ");
        output.push_str(&render_ts_string(&format!("../project{extension}")));
        output.push_str(";\n");
    }
    write_component_imports(
        &mut output,
        component_imports,
        &aliases,
        &extension,
        "../../types/components/",
    );
    output.push('\n');

    write_source_metadata(&mut output, &operation.source, 0);
    output.push_str(&response_type);
    output.push_str("\ntype ");
    output.push_str(&response_body_name);
    output.push_str(" = ");
    if let Some(response_body_union) = &response_body_union {
        output.push_str("SendableBody<");
        output.push_str(response_body_union);
        output.push('>');
    } else {
        output.push_str("null");
    }
    output.push_str(";\n\n");

    output.push_str("export type ");
    output.push_str(&resolver_input_name);
    output.push_str(" = {\n");
    output.push_str("  request: StrictRequest<never>;\n");
    for (name, group) in parameter_groups {
        // Wrapped rather than rendered differently: the group type comes from the shared renderer,
        // and projection stores `undefined` for a parameter the request omitted. Under
        // exactOptionalPropertyTypes an optional member and a present-and-undefined one are
        // different types, so the wrapper widens exactly the optional members and leaves the
        // required ones alone.
        output.push_str("  ");
        output.push_str(name);
        output.push_str(": Projected<");
        output.push_str(&group);
        output.push_str(">;\n");
    }
    if let Some(body) = &projected_body {
        let renderer = TypesEmitter::new(model);
        renderer.set_import_aliases(aliases.clone());
        output.push_str("  body: ");
        output.push_str(&render_request_body_type(&renderer, model, &body.plan, 2));
        if !body.required {
            output.push_str(" | undefined");
        }
        output.push_str(";\n");
    }
    if has_projected_cookies {
        output.push_str("  rawCookies: Record<string, string>;\n");
    } else {
        output.push_str("  cookies: Record<string, string>;\n");
    }
    output.push_str("  respond: <T extends ");
    output.push_str(&response_name);
    output.push_str(">(\n    response: T & NoPayloadGuard<T, ");
    output.push_str(&no_payload_match_union(operation));
    output.push_str(">,\n  ) => HttpResponse<");
    output.push_str(&response_body_name);
    output.push_str(">;\n};\n\n");

    let default_base_url = default_base_url(operation, &model.analyzed.ir.root_servers);
    output.push_str("export function ");
    output.push_str(&handler_name);
    output.push_str("(\n  resolver: (input: ");
    output.push_str(&resolver_input_name);
    output.push_str(") => AsyncResponseResolverReturnType<");
    output.push_str(&response_body_name);
    output.push_str(">,\n  options");
    if default_base_url.is_some() {
        output.push('?');
    }
    output.push_str(": { baseUrl");
    if default_base_url.is_some() {
        output.push('?');
    }
    output.push_str(": string },\n): HttpHandler {\n  const resolvedBaseUrl = options");
    if let Some(default_base_url) = default_base_url {
        output.push_str("?.baseUrl ?? ");
        output.push_str(&render_ts_string(&default_base_url));
    } else {
        output.push_str(".baseUrl");
    }
    output.push_str(";\n  const responsePayloads = ");
    output.push_str(&response_payload_map(operation, &response_projector));
    output.push_str(" as const;\n  const pathPattern = ");
    output.push_str(&render_ts_string(&pattern));
    output.push_str(";\n");
    if has_projected_parameters {
        output.push_str("  const pathTemplate: ProjectionContext[\"pathTemplate\"] = ");
        output.push_str(&render_path_template(&operation.path_template));
        output.push_str(";\n");
    }
    if let Some(body) = &projected_body {
        output.push_str("  const requestBody: RequestBodyDescriptor & { readonly required: ");
        output.push_str(if body.required { "true" } else { "false" });
        output.push_str(" } = ");
        output.push_str(&body.descriptor);
        output.push_str(";\n");
    }
    output.push_str("  return http.");
    output.push_str(method);
    output.push_str("<never, never, ");
    output.push_str(&response_body_name);
    output.push_str(">(`${resolvedBaseUrl}${pathPattern}`, ");
    if projected_body.is_some() {
        output.push_str("async ");
    }
    output.push_str("({ request, cookies: rawCookies }) => {\n");
    if has_projected_parameters {
        output.push_str("    const projectionContext: ProjectionContext = {\n      request,\n      baseUrl: resolvedBaseUrl,\n      pathTemplate,\n      cookies: rawCookies,\n    };\n");
    }
    if let Some(body) = &projected_body {
        let renderer = TypesEmitter::new(model);
        renderer.set_import_aliases(aliases.clone());
        output.push_str("    const body = await projectRequestBody<");
        output.push_str(&render_request_body_type(&renderer, model, &body.plan, 4));
        output.push_str(">(request, requestBody);\n");
    }
    output.push_str("    return resolver({\n      request,\n");
    write_projected_groups(&mut output, operation, &projected_parameters);
    if projected_body.is_some() {
        output.push_str("      body,\n");
    }
    output.push_str(if has_projected_cookies {
        "      rawCookies,\n"
    } else {
        "      cookies: rawCookies,\n"
    });
    output.push_str("      respond: (response) => {\n        const ownsContentType = Object.hasOwn(response, \"contentType\");\n        const ownsBody = Object.hasOwn(response, \"body\");\n        const contentType =\n          ownsContentType &&\n          \"contentType\" in response &&\n          typeof response.contentType === \"string\"\n            ? response.contentType\n            : null;\n        const body =\n          contentType === null && (ownsContentType || ownsBody)\n            ? response\n            : ownsBody && \"body\" in response\n              ? response.body\n              : null;\n        return respondWith(response.status, contentType, body, responsePayloads);\n      },\n    });\n  });\n}\n");

    let relative_path = format!("msw/handlers/{file_base}.ts");
    model.register_path(&relative_path, &operation.source);
    Some(GeneratedFile {
        relative_path,
        content: output,
    })
}

fn plan_projected_body(
    model: &EmissionModel<'_, '_>,
    operation: &Operation,
) -> Result<Option<ProjectedBody>, Vec<Diagnostic>> {
    let Some(body) = &operation.request_body else {
        return Ok(None);
    };
    let projector = PrimitiveDomainProjector::new(&model.analyzed.ir);
    let Some(plan) = build_body_plan(&body.media_types, &projector) else {
        return Err(vec![body_projection_diagnostic(
            &body.source,
            "the request body declares no usable media type",
        )]);
    };
    let mut diagnostics = Vec::new();
    for media in &body.media_types {
        if matches!(
            media.essence.as_str(),
            "application/x-www-form-urlencoded" | "multipart/form-data"
        ) && !matches!(
            projector.resolve_schema(&media.schema),
            Some(SchemaNode::Object { .. })
        ) {
            diagnostics.push(body_projection_diagnostic(
                &media.source,
                &format!(
                    "request media '{}' requires an object schema to correlate encoded fields with declared properties",
                    media.essence
                ),
            ));
        }
    }
    inspect_body_projection(model, &plan, &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let descriptor = match render_request_body_descriptor(model, &plan, body.required, &body.source)
    {
        Ok(descriptor) => descriptor,
        Err((source, reason)) => {
            return Err(vec![body_projection_diagnostic(&source, &reason)]);
        }
    };
    Ok(Some(ProjectedBody {
        plan,
        required: body.required,
        descriptor,
    }))
}

fn inspect_body_projection(
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match plan {
        BodyPlan::Json {
            schema: Some(schema),
            source,
            ..
        } => {
            if model.transform_facts().reaches(schema) {
                diagnostics.push(body_projection_diagnostic(
                    source,
                    "the application type applies a date/time transform that the standalone MSW artifact cannot reproduce",
                ));
            }
        }
        BodyPlan::FormUrlencoded { fields, .. } => {
            for field in fields {
                if model.transform_facts().reaches(&field.schema) {
                    diagnostics.push(body_projection_diagnostic(
                        &field.source,
                        &format!(
                            "form field '{}' applies a date/time transform that the standalone MSW artifact cannot reproduce",
                            field.name
                        ),
                    ));
                }
                match &field.serialization {
                    FieldSerializationPlan::Style {
                        style,
                        allow_reserved,
                        ..
                    } => {
                        if *allow_reserved {
                            diagnostics.push(body_projection_diagnostic(
                                &field.source,
                                &format!(
                                    "form field '{}' permits reserved delimiters, so its wire value is not invertible",
                                    field.name
                                ),
                            ));
                        }
                        if !matches!(
                            style,
                            ParamStyle::Form
                                | ParamStyle::SpaceDelimited
                                | ParamStyle::PipeDelimited
                                | ParamStyle::DeepObject
                        ) {
                            diagnostics.push(body_projection_diagnostic(
                                &field.source,
                                &format!(
                                    "form field '{}' uses a serialization style that has no form-body inverse",
                                    field.name
                                ),
                            ));
                        }
                    }
                    FieldSerializationPlan::Content { media, .. } => {
                        if field.wrapper.wrapped {
                            diagnostics.push(body_projection_diagnostic(
                                &field.source,
                                &format!(
                                    "form field '{}' selects among media types that are not represented on the wire",
                                    field.name
                                ),
                            ));
                        }
                        if media.payloads.first() == Some(&PayloadKind::Binary) {
                            diagnostics.push(body_projection_diagnostic(
                                &field.source,
                                &format!(
                                    "form field '{}' has a binary payload that form-urlencoded cannot carry",
                                    field.name
                                ),
                            ));
                        }
                    }
                }
            }
        }
        BodyPlan::Multipart { fields, .. } => {
            for field in fields {
                if multipart_field_payload(field) != PayloadKind::Binary
                    && model.transform_facts().reaches(&field.schema)
                {
                    diagnostics.push(body_projection_diagnostic(
                        &field.source,
                        &format!(
                            "multipart field '{}' applies a date/time transform that the standalone MSW artifact cannot reproduce",
                            field.name
                        ),
                    ));
                }
            }
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            for (_, arm) in arms {
                inspect_body_projection(model, arm, diagnostics);
            }
        }
        BodyPlan::Json { schema: None, .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. } => {}
    }
}

fn body_projection_diagnostic(source: &SourceRef, reason: &str) -> Diagnostic {
    source_diagnostic(
        CODE_BODY_PROJECTION,
        format!("request body cannot be projected into its declared type: {reason}"),
        source,
    )
}

fn render_request_body_descriptor(
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
    required: bool,
    source: &SourceRef,
) -> Result<String, (SourceRef, String)> {
    let mut output = String::from("{ required: ");
    output.push_str(if required { "true" } else { "false" });
    output.push_str(", discriminated: ");
    output.push_str(
        if matches!(plan, BodyPlan::ContentTypeDiscriminated { .. }) {
            "true"
        } else {
            "false"
        },
    );
    output.push_str(", sourcePointer: ");
    write_source_pointer_literal(&mut output, source);
    output.push_str(", media: [\n");
    match plan {
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            for (_, arm) in arms {
                output.push_str("    ");
                write_request_body_media_descriptor(&mut output, model, arm)?;
                output.push_str(",\n");
            }
        }
        BodyPlan::Json { .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => {
            output.push_str("    ");
            write_request_body_media_descriptor(&mut output, model, plan)?;
            output.push_str(",\n");
        }
    }
    output.push_str("  ] }");
    Ok(output)
}

fn write_request_body_media_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
) -> Result<(), (SourceRef, String)> {
    let (media, kind, source) = match plan {
        BodyPlan::Json { media, source, .. } => (media, "json", source),
        BodyPlan::TopLevelText { media, source, .. } => (media, "text", source),
        BodyPlan::TopLevelBinary { media, source, .. } => (media, "binary", source),
        BodyPlan::FormUrlencoded { media, source, .. } => (media, "urlencoded", source),
        BodyPlan::Multipart { media, source, .. } => (media, "multipart", source),
        BodyPlan::ContentTypeDiscriminated { .. } => {
            return Err((
                SourceRef::default(),
                "a nested content-type discriminator has no wire representation".to_owned(),
            ));
        }
    };
    output.push_str("{ media: ");
    output.push_str(&render_ts_string(media));
    output.push_str(", kind: ");
    output.push_str(&render_ts_string(kind));
    output.push_str(", sourcePointer: ");
    write_source_pointer_literal(output, source);
    if let BodyPlan::FormUrlencoded { fields, .. } = plan {
        output.push_str(", fields: [\n");
        for field in fields {
            output.push_str("      ");
            write_urlencoded_field_descriptor(output, model, field)?;
            output.push_str(",\n");
        }
        output.push_str("    ]");
    } else if let BodyPlan::Multipart { fields, .. } = plan {
        output.push_str(", fields: [\n");
        for field in fields {
            output.push_str("      ");
            write_multipart_field_descriptor(output, model, field)?;
            output.push_str(",\n");
        }
        output.push_str("    ]");
    }
    output.push_str(" }");
    Ok(())
}

fn write_urlencoded_field_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    field: &FormFieldPlan,
) -> Result<(), (SourceRef, String)> {
    output.push_str("{ name: ");
    output.push_str(&render_ts_string(&field.name));
    output.push_str(", required: ");
    output.push_str(if field.required { "true" } else { "false" });
    output.push_str(", sourcePointer: ");
    write_source_pointer_literal(output, &field.source);
    match &field.serialization {
        FieldSerializationPlan::Style { style, explode, .. } => {
            let helper = match style {
                ParamStyle::Form if *explode => "query-form-explode",
                ParamStyle::Form => "query-form",
                ParamStyle::SpaceDelimited => "query-space-delimited",
                ParamStyle::PipeDelimited => "query-pipe-delimited",
                ParamStyle::DeepObject => "query-deep-object-extended",
                ParamStyle::Simple | ParamStyle::Label | ParamStyle::Matrix => {
                    return Err((
                        field.source.clone(),
                        format!(
                            "form field '{}' uses a serialization style that has no form-body inverse",
                            field.name
                        ),
                    ));
                }
            };
            output.push_str(", decoder: \"style\", helper: ");
            output.push_str(&render_ts_string(helper));
            output.push_str(", shape: ");
            output.push_str(&render_body_field_shape(model, field, false)?);
        }
        FieldSerializationPlan::Content { media, .. } => match media.payloads.first() {
            Some(PayloadKind::Json) => output.push_str(", decoder: \"json\""),
            Some(PayloadKind::Text) => {
                output.push_str(", decoder: \"text\", shape: ");
                output.push_str(&render_body_field_shape(model, field, false)?);
            }
            Some(PayloadKind::Binary) | None => {
                return Err((
                    field.source.clone(),
                    format!(
                        "form field '{}' has no form-urlencoded payload decoder",
                        field.name
                    ),
                ));
            }
        },
    }
    output.push_str(" }");
    Ok(())
}

fn render_body_field_shape(
    model: &EmissionModel<'_, '_>,
    field: &FormFieldPlan,
    content_json: bool,
) -> Result<String, (SourceRef, String)> {
    render_projection_shape(
        model,
        &field.schema,
        content_json,
        false,
        0,
        &mut ProjectionLimits::new(),
    )
    .map_err(|reason| {
        (
            field.source.clone(),
            format!(
                "form field '{}' cannot be decoded from its serialized value: {reason}",
                field.name
            ),
        )
    })
}

fn write_multipart_field_descriptor(
    output: &mut String,
    model: &EmissionModel<'_, '_>,
    field: &FormFieldPlan,
) -> Result<(), (SourceRef, String)> {
    output.push_str("{ name: ");
    output.push_str(&render_ts_string(&field.name));
    output.push_str(", required: ");
    output.push_str(if field.required { "true" } else { "false" });
    output.push_str(", sourcePointer: ");
    write_source_pointer_literal(output, &field.source);
    output.push_str(", repeated: ");
    output.push_str(
        if schema_is_array(model, &field.schema, &mut BTreeSet::new()) {
            "true"
        } else {
            "false"
        },
    );
    output.push_str(", payload: ");
    output.push_str(&render_ts_string(multipart_field_payload(field).as_str()));
    output.push_str(", contentType: ");
    match &field.serialization {
        FieldSerializationPlan::Style { .. } => output.push_str("{ kind: \"none\" }"),
        FieldSerializationPlan::Content { media, .. } if field.wrapper.wrapped => {
            output.push_str("{ kind: \"selected\", admitted: [");
            output.push_str(&rendered_media_values(media));
            output.push_str("] }, payloads: [");
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
        FieldSerializationPlan::Content { media, .. } => {
            let Some(value) = media.values.first() else {
                return Err((
                    field.source.clone(),
                    format!(
                        "multipart field '{}' has no declared part media type",
                        field.name
                    ),
                ));
            };
            output.push_str("{ kind: \"fixed\", value: ");
            output.push_str(&render_ts_string(value));
            output.push_str(" }");
        }
    }
    output.push_str(", filename: ");
    output.push_str(if field.wrapper.filename {
        "true"
    } else {
        "false"
    });
    output.push_str(" }");
    Ok(())
}

fn rendered_media_values(media: &PartMediaPlan) -> String {
    media
        .values
        .iter()
        .map(|value| render_ts_string(value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_source_pointer_literal(output: &mut String, source: &SourceRef) {
    output.push_str("{ logicalSourceId: ");
    output.push_str(&render_ts_string(&source.source_id));
    output.push_str(", jsonPointer: ");
    output.push_str(&render_ts_string(&source.json_pointer));
    output.push_str(" }");
}

fn multipart_field_payload(field: &FormFieldPlan) -> PayloadKind {
    match &field.serialization {
        FieldSerializationPlan::Content { media, .. } => media
            .payloads
            .first()
            .copied()
            .unwrap_or(PayloadKind::Binary),
        FieldSerializationPlan::Style { .. } => match &field.schema {
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                format: Some(format),
                ..
            } if format == "binary" => PayloadKind::Binary,
            SchemaNode::Object { .. } | SchemaNode::Tuple { .. } => PayloadKind::Json,
            SchemaNode::Ref { .. }
            | SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Array { .. }
            | SchemaNode::AllOf { .. }
            | SchemaNode::OneOf { .. }
            | SchemaNode::AnyOf { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => PayloadKind::Text,
        },
    }
}

fn schema_is_array(
    model: &EmissionModel<'_, '_>,
    schema: &SchemaNode,
    visited: &mut BTreeSet<(String, String)>,
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

fn render_request_body_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    model: &EmissionModel<'_, '_>,
    plan: &BodyPlan,
    indent: usize,
) -> String {
    match plan {
        BodyPlan::Json { schema, .. } => schema.as_ref().map_or_else(
            || "unknown".to_owned(),
            |schema| {
                renderer.render_type(schema, TypePosition::Request, TypeAxis::Application, indent)
            },
        ),
        BodyPlan::TopLevelText { .. } => "string".to_owned(),
        BodyPlan::TopLevelBinary { .. } => "Uint8Array".to_owned(),
        BodyPlan::FormUrlencoded { fields, .. } => {
            render_projected_form_type(renderer, model, fields, false, indent)
        }
        BodyPlan::Multipart { fields, .. } => {
            render_projected_form_type(renderer, model, fields, true, indent)
        }
        BodyPlan::ContentTypeDiscriminated { arms, all_concrete } => arms
            .iter()
            .map(|(media, arm)| {
                let discriminant = if *all_concrete {
                    render_ts_string(media)
                } else {
                    "string".to_owned()
                };
                format!(
                    "{{ contentType: {discriminant}; body: {} }}",
                    render_request_body_type(renderer, model, arm, indent)
                )
            })
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

fn render_projected_form_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    model: &EmissionModel<'_, '_>,
    fields: &[FormFieldPlan],
    multipart: bool,
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
        if multipart && multipart_field_payload(field) == PayloadKind::Binary {
            output.push_str("Uint8Array");
            if schema_is_array(model, &field.schema, &mut BTreeSet::new()) {
                output.push_str("[]");
            }
        } else {
            output.push_str(&renderer.render_type(
                &field.schema,
                TypePosition::Request,
                TypeAxis::Application,
                indent + 2,
            ));
        }
        output.push_str(";\n");
    }
    output.push_str(&" ".repeat(indent));
    output.push('}');
    output
}

fn collect_request_body_imports(
    renderer: &TypesEmitter<'_, '_, '_>,
    plan: &BodyPlan,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
) {
    match plan {
        BodyPlan::Json {
            schema: Some(schema),
            ..
        } => renderer.collect_operation_imports(
            schema,
            TypePosition::Request,
            TypeAxis::Application,
            imports,
        ),
        BodyPlan::FormUrlencoded { fields, .. } => {
            for field in fields {
                renderer.collect_operation_imports(
                    &field.schema,
                    TypePosition::Request,
                    TypeAxis::Application,
                    imports,
                );
            }
        }
        BodyPlan::Multipart { fields, .. } => {
            for field in fields {
                if multipart_field_payload(field) != PayloadKind::Binary {
                    renderer.collect_operation_imports(
                        &field.schema,
                        TypePosition::Request,
                        TypeAxis::Application,
                        imports,
                    );
                }
            }
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            for (_, arm) in arms {
                collect_request_body_imports(renderer, arm, imports);
            }
        }
        BodyPlan::Json { schema: None, .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. } => {}
    }
}

fn plan_projected_parameters(
    model: &EmissionModel<'_, '_>,
    operation: &Operation,
) -> Result<Vec<ProjectedParameter>, Vec<Diagnostic>> {
    let projector = PrimitiveDomainProjector::new(&model.analyzed.ir);
    let mut projected = Vec::new();
    let mut diagnostics = Vec::new();
    for (index, parameter) in operation.parameters.iter().enumerate() {
        let plan = parameter_plan(
            parameter,
            &projector,
            model.config.compat.deep_object_encoding,
        );
        let style = parameter_style_name(plan.resolved.style);
        let reason = if plan.caller_serialized {
            Some(format!(
                "content media type '{}' is caller-serialized and defines no typed inverse",
                parameter.content_media_type.as_deref().unwrap_or("unknown")
            ))
        } else if model.transform_facts().reaches(&parameter.schema) {
            Some("the application type applies a date/time transform that the standalone MSW artifact cannot reproduce".to_owned())
        } else if plan.resolved.style == ParamStyle::Label
            && plan.resolved.explode
            && projector.admits_collection(&parameter.schema)
        {
            diagnostics.push(noninvertible_parameter_diagnostic(
                parameter,
                style,
                "explode=true uses '.' both inside values and between collection members",
            ));
            continue;
        } else if plan.resolved.allow_reserved {
            diagnostics.push(noninvertible_parameter_diagnostic(
                parameter,
                style,
                "allowReserved=true permits reserved delimiters inside the wire value",
            ));
            continue;
        } else {
            None
        };
        if let Some(reason) = reason {
            diagnostics.push(parameter_projection_diagnostic(parameter, style, &reason));
            continue;
        }
        let mut limits = ProjectionLimits::new();
        match render_projection_shape(
            model,
            &parameter.schema,
            plan.resolved.helper.is_content_json(),
            false,
            0,
            &mut limits,
        ) {
            Ok(shape) => projected.push(ProjectedParameter { index, plan, shape }),
            Err(reason) => {
                diagnostics.push(parameter_projection_diagnostic(parameter, style, &reason));
            }
        }
    }
    if diagnostics.is_empty() {
        Ok(projected)
    } else {
        Err(diagnostics)
    }
}

fn noninvertible_parameter_diagnostic(parameter: &Param, style: &str, reason: &str) -> Diagnostic {
    source_diagnostic(
        CODE_NONINVERTIBLE_PARAMETER,
        format!(
            "parameter '{}' with {style} serialization is not invertible: {reason}",
            parameter.name
        ),
        &parameter.source,
    )
}

fn parameter_projection_diagnostic(parameter: &Param, style: &str, reason: &str) -> Diagnostic {
    source_diagnostic(
        CODE_PARAMETER_PROJECTION,
        format!(
            "parameter '{}' with {style} serialization cannot be projected into its declared type: {reason}",
            parameter.name
        ),
        &parameter.source,
    )
}

fn parameter_style_name(style: ParamStyle) -> &'static str {
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

fn render_projection_shape(
    model: &EmissionModel<'_, '_>,
    schema: &SchemaNode,
    content_json: bool,
    nested_style_value: bool,
    depth: usize,
    limits: &mut ProjectionLimits,
) -> Result<String, String> {
    let depth = depth + usize::from(schema.is_nullable());
    if depth > MAX_PARAMETER_SHAPE_DEPTH {
        return Err("the parameter schema exceeds the supported projection depth".to_owned());
    }
    limits.charge()?;
    let rendered = match schema {
        SchemaNode::Ref { target, meta } => {
            let key = (target.source_id.clone(), target.json_pointer.clone());
            if !limits.visiting.insert(key.clone()) {
                return Err("the parameter schema is recursive".to_owned());
            }
            let Some(target) = model.schema_target(&target.source_id, &target.json_pointer) else {
                return Err("the parameter schema reference has no generated target".to_owned());
            };
            let resolved = &model.analyzed.ir.schemas[target.index].schema;
            let result = render_projection_shape(
                model,
                resolved,
                content_json,
                nested_style_value,
                depth,
                limits,
            );
            limits.visiting.remove(&key);
            nullable_shape(result?, meta.nullable)
        }
        SchemaNode::Primitive {
            ty,
            enum_values,
            const_value,
            ..
        } => {
            let values = finite_values(enum_values.as_deref(), const_value.as_ref());
            render_scalar_shape(*ty, values.as_deref(), schema.is_nullable())?
        }
        SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => finite_values(enum_values.as_deref(), const_value.as_ref()).map_or_else(
            || {
                if content_json {
                    Ok(nullable_shape(
                        "{ kind: \"unknown\" }".to_owned(),
                        schema.is_nullable(),
                    ))
                } else {
                    Err("an unconstrained schema has no unique scalar coercion".to_owned())
                }
            },
            |values| {
                Ok(nullable_shape(
                    render_literal_shape(&values),
                    schema.is_nullable(),
                ))
            },
        )?,
        SchemaNode::Object {
            properties,
            additional_properties,
            meta,
            ..
        } => {
            if nested_style_value && !content_json {
                return Err(
                    "a nested object is not representable by this parameter style".to_owned(),
                );
            }
            if !meta.validation_applicators().pattern_properties.is_empty() {
                return Err(
                    "patternProperties cannot be represented by a finite projection descriptor"
                        .to_owned(),
                );
            }
            let mut rendered = String::from("{ kind: \"object\", properties: {");
            for (name, property, property_meta) in properties
                .iter()
                .filter(|(_, _, meta)| super::property_in_position(meta, TypePosition::Request))
            {
                rendered.push('[');
                rendered.push_str(&render_ts_string(name));
                rendered.push(']');
                rendered.push_str(": { required: ");
                rendered.push_str(if property_meta.required {
                    "true"
                } else {
                    "false"
                });
                rendered.push_str(", shape: ");
                rendered.push_str(&render_projection_shape(
                    model,
                    property,
                    content_json,
                    true,
                    depth + 1,
                    limits,
                )?);
                rendered.push_str(" },");
            }
            rendered.push_str(" }, additional: ");
            match additional_properties {
                AdditionalProperties::Allowed(None) => rendered.push_str("true"),
                AdditionalProperties::Forbidden => rendered.push_str("false"),
                AdditionalProperties::Allowed(Some(additional))
                | AdditionalProperties::Schema(additional) => {
                    rendered.push_str(&render_projection_shape(
                        model,
                        additional,
                        content_json,
                        true,
                        depth + 1,
                        limits,
                    )?)
                }
            }
            rendered.push_str(" }");
            nullable_shape(rendered, schema.is_nullable())
        }
        SchemaNode::Array { items, .. } => {
            if nested_style_value && !content_json {
                return Err(
                    "a nested array is not representable by this parameter style".to_owned(),
                );
            }
            let items =
                render_projection_shape(model, items, content_json, true, depth + 1, limits)?;
            nullable_shape(
                format!("{{ kind: \"array\", items: {items} }}"),
                schema.is_nullable(),
            )
        }
        SchemaNode::Tuple { .. } => {
            return Err("tuple parameters have no projection descriptor that preserves their exact TypeScript tuple type".to_owned());
        }
        SchemaNode::AllOf { branches, .. } => {
            if branches.is_empty() {
                nullable_shape("{ kind: \"unknown\" }".to_owned(), schema.is_nullable())
            } else if let Some((scalar, values)) = projection_scalar_enum(branches) {
                let nullable = scalar.nullable || schema.is_nullable();
                render_scalar_shape(scalar.ty, Some(&values), nullable)?
            } else {
                let variants = render_projection_variants(
                    model,
                    branches,
                    content_json,
                    nested_style_value,
                    depth + 1,
                    limits,
                )?;
                nullable_shape(
                    format!("{{ kind: \"intersection\", variants: [{variants}] }}"),
                    schema.is_nullable(),
                )
            }
        }
        SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
            if branches.is_empty() {
                nullable_shape("{ kind: \"never\" }".to_owned(), schema.is_nullable())
            } else {
                let variants = render_projection_variants(
                    model,
                    branches,
                    content_json,
                    nested_style_value,
                    depth + 1,
                    limits,
                )?;
                nullable_shape(
                    format!("{{ kind: \"union\", variants: [{variants}] }}"),
                    schema.is_nullable(),
                )
            }
        }
        SchemaNode::Any { .. } | SchemaNode::Unknown { .. } => {
            if !content_json {
                return Err("an unconstrained schema has no unique wire-shape inverse".to_owned());
            }
            nullable_shape("{ kind: \"unknown\" }".to_owned(), schema.is_nullable())
        }
        SchemaNode::Never { .. } => {
            nullable_shape("{ kind: \"never\" }".to_owned(), schema.is_nullable())
        }
    };
    Ok(rendered)
}

fn render_projection_variants(
    model: &EmissionModel<'_, '_>,
    branches: &[SchemaNode],
    content_json: bool,
    nested_style_value: bool,
    depth: usize,
    limits: &mut ProjectionLimits,
) -> Result<String, String> {
    branches
        .iter()
        .map(|branch| {
            render_projection_shape(
                model,
                branch,
                content_json,
                nested_style_value,
                depth,
                limits,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|variants| variants.join(", "))
}

#[derive(Clone, Copy)]
struct ProjectionScalar {
    ty: PrimitiveType,
    nullable: bool,
}

fn projection_scalar_enum(
    branches: &[SchemaNode],
) -> Option<(ProjectionScalar, Vec<serde_json::Value>)> {
    let [first, second] = branches else {
        return None;
    };
    let (scalar, finite) = match (first, second) {
        (SchemaNode::Primitive { ty, meta, .. }, finite)
        | (finite, SchemaNode::Primitive { ty, meta, .. }) => (
            ProjectionScalar {
                ty: *ty,
                nullable: meta.nullable,
            },
            finite,
        ),
        _ => return None,
    };
    let values = projection_finite_union(finite)?;
    Some((scalar, values))
}

fn projection_finite_union(schema: &SchemaNode) -> Option<Vec<serde_json::Value>> {
    match schema {
        SchemaNode::Primitive {
            enum_values,
            const_value,
            ..
        }
        | SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => finite_values(enum_values.as_deref(), const_value.as_ref()),
        SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
            let mut combined = Vec::new();
            for branch in branches {
                let branch_values = projection_finite_union(branch)?;
                for value in branch_values {
                    if !combined.iter().any(|other| json_equal(other, &value)) {
                        combined.push(value);
                    }
                }
            }
            Some(combined)
        }
        SchemaNode::Ref { .. }
        | SchemaNode::Object { .. }
        | SchemaNode::Array { .. }
        | SchemaNode::Tuple { .. }
        | SchemaNode::AllOf { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => None,
    }
}

fn render_scalar_shape(
    ty: PrimitiveType,
    values: Option<&[serde_json::Value]>,
    nullable: bool,
) -> Result<String, String> {
    let kind = match ty {
        PrimitiveType::String => "string",
        PrimitiveType::Number => "number",
        PrimitiveType::Integer => "integer",
        PrimitiveType::Boolean => "boolean",
        PrimitiveType::Null => "null",
    };
    let Some(values) = values else {
        return Ok(nullable_shape(format!("{{ kind: \"{kind}\" }}"), nullable));
    };
    for value in values {
        let represented = match (ty, value) {
            (_, serde_json::Value::Null) => nullable || ty == PrimitiveType::Null,
            (PrimitiveType::String, serde_json::Value::String(_))
            | (PrimitiveType::Number | PrimitiveType::Integer, serde_json::Value::Number(_))
            | (PrimitiveType::Boolean, serde_json::Value::Bool(_)) => true,
            _ => false,
        };
        if !represented {
            return Err(format!(
                "enum member {} cannot be represented by the declared {kind} parameter",
                render_ts_value(value)
            ));
        }
    }
    let rendered = values
        .iter()
        .filter(|value| ty == PrimitiveType::Null || !value.is_null())
        .map(render_ts_value)
        .collect::<Vec<_>>()
        .join(", ");
    let shape = format!("{{ kind: \"{kind}\", enum: [{rendered}] }}");
    Ok(
        if ty != PrimitiveType::Null && values.iter().any(serde_json::Value::is_null) {
            nullable_shape(shape, true)
        } else {
            shape
        },
    )
}

fn render_literal_shape(values: &[serde_json::Value]) -> String {
    let values = values
        .iter()
        .map(render_ts_value)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ kind: \"literal\", values: [{values}] }}")
}

fn nullable_shape(shape: String, nullable: bool) -> String {
    if nullable {
        format!("{{ kind: \"nullable\", value: {shape} }}")
    } else {
        shape
    }
}

fn render_parameter_groups(
    renderer: &TypesEmitter<'_, '_, '_>,
    operation: &Operation,
) -> Vec<(&'static str, String)> {
    [
        (ParamLocation::Path, "params"),
        (ParamLocation::Query, "query"),
        (ParamLocation::Header, "headers"),
        (ParamLocation::Cookie, "cookies"),
    ]
    .into_iter()
    .filter_map(|(location, name)| {
        let parameters = operation
            .parameters
            .iter()
            .filter(|parameter| parameter.location == location)
            .collect::<Vec<_>>();
        (!parameters.is_empty()).then(|| {
            (
                name,
                renderer.render_parameter_group(&parameters, TypeAxis::Application, 2),
            )
        })
    })
    .collect()
}

fn render_path_template(template: &[Segment]) -> String {
    let segments = template
        .iter()
        .map(|segment| {
            let parts = segment
                .parts
                .iter()
                .map(|part| match part {
                    SegmentPart::Literal(value) => {
                        format!("{{ literal: {} }}", render_ts_string(value))
                    }
                    SegmentPart::Param(value) => {
                        format!("{{ parameter: {} }}", render_ts_string(value))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{parts}]")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{segments}]")
}

fn write_projected_groups(
    output: &mut String,
    operation: &Operation,
    projected: &[ProjectedParameter],
) {
    let query_parameter_names = operation
        .parameters
        .iter()
        .filter(|parameter| parameter.location == ParamLocation::Query)
        .map(|parameter| render_ts_string(&parameter.name))
        .collect::<Vec<_>>()
        .join(", ");
    for (location, group_name) in [
        (ParamLocation::Path, "params"),
        (ParamLocation::Query, "query"),
        (ParamLocation::Header, "headers"),
        (ParamLocation::Cookie, "cookies"),
    ] {
        let group = projected
            .iter()
            .filter(|projected| operation.parameters[projected.index].location == location)
            .collect::<Vec<_>>();
        if group.is_empty() {
            continue;
        }
        output.push_str("      ");
        output.push_str(group_name);
        output.push_str(": {\n");
        for projected in group {
            let parameter = &operation.parameters[projected.index];
            output.push_str("        ");
            output.push('[');
            output.push_str(&render_ts_string(&parameter.name));
            output.push(']');
            output.push_str(": projectParameter(projectionContext, {\n");
            output.push_str("          location: ");
            output.push_str(&render_ts_string(parameter_location_name(
                parameter.location,
            )));
            output.push_str(",\n          name: ");
            output.push_str(&render_ts_string(&parameter.name));
            output.push_str(",\n          helper: ");
            output.push_str(&render_ts_string(parameter_helper_name(
                projected.plan.resolved.helper,
            )));
            output.push_str(",\n          required: ");
            output.push_str(if parameter.required { "true" } else { "false" });
            // Query parameters that permit reserved delimiters are rejected before a handler is
            // emitted, and the serialization resolver forces this off in every other location.
            output.push_str(",\n          allowReserved: false");
            output.push_str(",\n          shape: ");
            output.push_str(&projected.shape);
            output.push_str(",\n          sourcePointer: { logicalSourceId: ");
            output.push_str(&render_ts_string(&parameter.source.source_id));
            output.push_str(", jsonPointer: ");
            output.push_str(&render_ts_string(&parameter.source.json_pointer));
            output.push_str(" },\n          applicationPath: [");
            output.push_str(&render_ts_string(&parameter.name));
            output.push_str("],\n          queryParameterNames: [");
            output.push_str(&query_parameter_names);
            output.push_str("],\n        }),\n");
        }
        output.push_str("      },\n");
    }
}

fn parameter_location_name(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "path",
        ParamLocation::Query => "query",
        ParamLocation::Header => "header",
        ParamLocation::Cookie => "cookie",
    }
}

fn parameter_helper_name(helper: HelperId) -> &'static str {
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

fn render_response_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    operation: &Operation,
    response_name: &str,
    projector: &PrimitiveDomainProjector<'_>,
) -> String {
    let mut arms = Vec::new();
    for response in &operation.responses {
        let match_key = response_match_literal(&response.status);
        let status = response_status_literal(&response.status);
        if response.media_types.is_empty() {
            arms.push(format!("{{ match: {match_key}; status: {status} }}"));
            continue;
        }
        for media in &response.media_types {
            let body = response_body_type(renderer, media, projector);
            arms.push(format!(
                "{{ match: {match_key}; status: {status}; contentType: {}; body: {body} }}",
                render_ts_string(&media.full)
            ));
        }
    }

    if arms.is_empty() {
        return format!("export type {response_name} = never;\n");
    }
    let mut output = format!("export type {response_name} =\n");
    let last = arms.len() - 1;
    for (index, arm) in arms.into_iter().enumerate() {
        output.push_str("  | ");
        output.push_str(&arm);
        if index == last {
            output.push_str(";\n");
        } else {
            output.push('\n');
        }
    }
    output
}

/// The TypeScript type a resolver must supply for one declared media entry.
///
/// JSON and supported text entries take the schema's rendered type. Byte-oriented media take the
/// bytes directly, while unsupported media are rejected before this emitter runs.
fn response_body_type(
    renderer: &TypesEmitter<'_, '_, '_>,
    media: &crate::ir::MediaType,
    projector: &PrimitiveDomainProjector<'_>,
) -> String {
    if response_body_uses_schema(media, projector) {
        renderer.render_type(
            &media.schema,
            TypePosition::Response,
            TypeAxis::Application,
            4,
        )
    } else {
        "Uint8Array".to_owned()
    }
}

fn response_body_uses_schema(
    media: &crate::ir::MediaType,
    projector: &PrimitiveDomainProjector<'_>,
) -> bool {
    !matches!(response_payload_kind(media, projector), "binary")
}

/// How a declared response media is written to the wire.
///
/// The emitter is the only place this is decided. The handler kernel used to re-derive it from the
/// content type at run time, and the two rules disagreed on `text/json` — which this compiler
/// counts as JSON, being the de-facto alias — so a body typed as its declared schema was written
/// out with `String(...)` and reached the wire as `[object Object]`. One source of truth removes
/// the whole class: the kernel is told, never asked.
fn response_payload_kind(
    media: &crate::ir::MediaType,
    projector: &PrimitiveDomainProjector<'_>,
) -> &'static str {
    match classify_response_media(media, projector) {
        ResponseMediaKind::Json => "json",
        ResponseMediaKind::Text => "text",
        ResponseMediaKind::Streaming
        | ResponseMediaKind::Xml
        | ResponseMediaKind::Multipart
        | ResponseMediaKind::MultipartUnnamed
        | ResponseMediaKind::Binary => "binary",
    }
}

/// The declared media-to-payload map an operation's handler passes to the kernel, so the kernel
/// never has to classify a content type itself.
fn response_payload_map(operation: &Operation, projector: &PrimitiveDomainProjector<'_>) -> String {
    let mut seen = BTreeMap::new();
    for response in &operation.responses {
        for media in &response.media_types {
            seen.insert(media.full.clone(), response_payload_kind(media, projector));
        }
    }
    let entries = seen
        .into_iter()
        // A computed key, like the other emitted object literals. A bare `__proto__` key in a
        // value position sets the prototype instead of creating an own property; a media type can
        // never spell that today (the parser requires a `/`), so this is consistency rather than a
        // live hole — and consistency is what stops it becoming one.
        .map(|(media, kind)| format!("[{}]: \"{kind}\"", render_ts_string(&media)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {entries} }}")
}

/// The union MSW is told the handler can respond with, which is what turns on its own
/// response-body checking. Deduplicated and ordered by first appearance so the emitted bytes are a
/// function of the document rather than of a hash iteration order.
///
/// An operation whose every declared response is bodyless has no body type at all; that is `null`,
/// the body such a response actually carries, and never `never` — `never` reads as "no response is
/// possible" and sends MSW's own resolver-return inference down its GraphQL branch.
fn response_body_union(
    renderer: &TypesEmitter<'_, '_, '_>,
    operation: &Operation,
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<String> {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for response in &operation.responses {
        for media in &response.media_types {
            let rendered = response_body_type(renderer, media, projector);
            if seen.insert(rendered.clone()) {
                ordered.push(rendered);
            }
        }
    }
    if ordered.is_empty() {
        return None;
    }
    Some(ordered.join(" | "))
}

fn response_match_literal(status: &ResponseStatus) -> String {
    match status {
        ResponseStatus::Exact(value) => value.clone(),
        ResponseStatus::Range(value) => render_ts_string(value),
        ResponseStatus::Default => render_ts_string("default"),
    }
}

fn response_status_literal(status: &ResponseStatus) -> String {
    match status {
        ResponseStatus::Exact(value) => value.clone(),
        ResponseStatus::Range(_) | ResponseStatus::Default => "number".to_owned(),
    }
}

fn no_payload_match_union(operation: &Operation) -> String {
    let matches = operation
        .responses
        .iter()
        .filter(|response| response.media_types.is_empty())
        .map(|response| response_match_literal(&response.status))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        "never".to_owned()
    } else {
        matches.join(" | ")
    }
}

fn write_component_imports(
    output: &mut String,
    imports: BTreeMap<String, BTreeSet<String>>,
    aliases: &foldhash::HashMap<String, String>,
    extension: &str,
    prefix: &str,
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
        output.push_str(&render_ts_string(&format!("{prefix}{file}{extension}")));
        output.push_str(";\n");
    }
}

fn default_base_url(operation: &Operation, root_servers: &[ServerEntry]) -> Option<String> {
    let effective_servers = if operation.servers.is_empty() {
        root_servers
    } else {
        &operation.servers
    };
    let server = effective_servers.first()?;
    let mut resolved = server.url.clone();
    for (name, variable) in &server.variables {
        resolved = resolved.replace(&format!("{{{name}}}"), &variable.default);
    }
    if resolved.contains(['{', '}']) {
        return None;
    }
    url::Url::parse(&resolved)
        .is_ok_and(|url| !url.cannot_be_a_base())
        .then_some(resolved)
}

fn msw_method(method: &str) -> Option<&'static str> {
    match method.to_ascii_lowercase().as_str() {
        "delete" => Some("delete"),
        "get" => Some("get"),
        "head" => Some("head"),
        "options" => Some("options"),
        "patch" => Some("patch"),
        "post" => Some("post"),
        "put" => Some("put"),
        _ => None,
    }
}

fn embedded_assets(model: &mut EmissionModel<'_, '_>) -> Vec<GeneratedFile> {
    let source = model
        .analyzed
        .ir
        .schemas
        .first()
        .map(|schema| schema.source.clone())
        .unwrap_or_default();
    [
        ("msw/project.ts", MSW_PROJECT_TS),
        ("msw/runtime.ts", MSW_RUNTIME_TS),
    ]
    .into_iter()
    .map(|(relative_path, source_text)| {
        let source_text = if relative_path == "msw/project.ts" {
            source_text.replace("./msw-runtime.ts", "./runtime.ts")
        } else {
            source_text.to_owned()
        };
        let content =
            rewrite_relative_ts_imports(&source_text, &model.config.emit.import_extension);
        model.register_path(relative_path, &source);
        GeneratedFile {
            relative_path: relative_path.to_owned(),
            content,
        }
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DateTimeRepresentation, ResolvedConfig, load_config};
    use crate::diag::DiagnosticSink;
    use crate::emit::emit_artifacts;
    use crate::ir::{PropMeta, SchemaMeta, SchemaRef};
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn generate_with_diagnostics(
        document: &str,
        config: &str,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), document).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), config).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_config(None, temp.path()).expect("config loads");
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let source_tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        assert!(!sink.has_errors(), "unexpected diagnostics");
        let files = emit_artifacts(&analyzed, &resolved, &source_tuples, None, &mut sink);
        (files, sink.into_sorted_vec())
    }

    fn generate(document: &str, config: &str) -> Vec<GeneratedFile> {
        let (files, diagnostics) = generate_with_diagnostics(document, config);
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:#?}"
        );
        files
    }

    fn generate_with_config(
        document: &str,
        configure: impl FnOnce(&mut ResolvedConfig),
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), document).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), MSW_CONFIG).expect("write config");
        let mut sink = DiagnosticSink::new();
        let mut resolved = load_config(None, temp.path()).expect("config loads");
        configure(&mut resolved);
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let source_tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        assert!(!sink.has_errors(), "unexpected diagnostics");
        let files = emit_artifacts(&analyzed, &resolved, &source_tuples, None, &mut sink);
        (files, sink.into_sorted_vec())
    }

    fn generated<'files>(files: &'files [GeneratedFile], path: &str) -> &'files str {
        &files
            .iter()
            .find(|file| file.relative_path == path)
            .expect("missing generated file")
            .content
    }

    const MINIMAL: &str = r#"
openapi: 3.1.0
info:
  title: Minimal
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "204":
          description: No pets.
"#;

    const MSW_CONFIG: &str = r#"
schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  msw: true
"#;

    const TYPES_ONLY_CONFIG: &str = r#"
schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
"#;

    const CLIENT_AND_MSW_CONFIG: &str = r#"
schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  client: true
  msw: true
client:
  authEnforcement: types
validation:
  engine: off
  unchecked: allow
"#;

    const SHOWCASE: &str = include_str!("../../../../fixtures/msw-showcase-3.1/openapi.yaml");
    const ENUM_PARAMETERS: &str =
        include_str!("../../../../fixtures/msw-enum-parameters-3.1/openapi.yaml");

    #[test]
    fn msw_artifact_emits_its_local_kernel() {
        let files = generate(MINIMAL, MSW_CONFIG);
        let runtime = files
            .iter()
            .find(|file| file.relative_path == "msw/runtime.ts")
            .expect("the msw kernel is emitted");
        assert!(runtime.content.contains("export class OastsHandlerError"));
        let project = generated(&files, "msw/project.ts");
        assert!(project.contains("export function projectParameter"));
        assert!(project.contains("export type SendableBody<T>"));
        assert!(project.contains("from \"./runtime.js\""));
        let paths = generated(&files, "msw/paths.ts");
        assert!(paths.contains("export type paths = {"));
        assert!(paths.contains("\"/pets\": {\n    get: {\n      parameters: {};"));
        assert!(paths.contains("\"204\": {\n          content: never;"));
    }

    #[test]
    fn the_kernel_is_absent_without_the_artifact() {
        let files = generate(MINIMAL, TYPES_ONLY_CONFIG);
        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("msw/"))
        );
    }

    #[test]
    fn msw_does_not_repeat_response_diagnostics_when_client_is_enabled() {
        let files = generate(MINIMAL, CLIENT_AND_MSW_CONFIG);
        generated(&files, "msw/runtime.ts");
        assert!(
            files
                .iter()
                .any(|file| file.relative_path.starts_with("msw/handlers/"))
        );
    }

    #[test]
    fn showcase_parameters_are_typed_and_projected_by_declared_location() {
        let files = generate(SHOWCASE, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getpetmock.ts");
        // Each group is wrapped so an optional member admits the `undefined` projection stores
        // for a parameter the request omitted; required members are untouched by the wrapper.
        assert!(handler.contains("params: Projected<{\n    petId: number;\n  }>;"));
        assert!(handler.contains("query: Projected<{\n    tags?: string[];"));
        assert!(handler.contains("headers: Projected<{\n    \"X-Request-Id\"?: string;\n  }>;"));
        assert!(handler.contains("helper: \"path-simple\""));
        assert!(handler.contains("helper: \"query-form-explode\""));
        assert!(handler.contains("helper: \"query-deep-object\""));
        assert!(handler.contains("helper: \"header-simple\""));
        assert!(handler.contains("shape: { kind: \"integer\" }"));
        assert!(handler.contains("applicationPath: [\"petId\"]"));
        assert!(handler.contains("queryParameterNames: [\"tags\", \"filter\"]"));

        let report = generated(&files, "msw/handlers/getreportmock.ts");
        assert!(report.contains("helper: \"path-label\""));
        assert!(report.contains("helper: \"query-pipe-delimited\""));
        assert!(report.contains("cookies: Projected<{\n    session?: string;\n  }>;"));
        assert!(report.contains("rawCookies: Record<string, string>;"));
        assert!(report.contains("location: \"cookie\""));
        assert!(report.contains("helper: \"query-form\""));
        assert!(!report.contains("headers: {"));

        let bodyless = generated(&files, "msw/handlers/headhealthmock.ts");
        assert!(!bodyless.contains("params: {"));
        assert!(!bodyless.contains("query: {"));
        assert!(!bodyless.contains("headers: {"));
        assert!(bodyless.contains("cookies: Record<string, string>;"));
        assert!(!bodyless.contains("projectParameter"));
        assert!(!bodyless.contains("Projected"));
        assert!(!bodyless.contains("ProjectionContext"));
        assert!(!bodyless.contains("projectionContext"));
        assert!(!bodyless.contains("pathTemplate"));
    }

    #[test]
    fn cookie_parameters_project_into_a_typed_group_and_keep_raw_cookies() {
        let document = r#"
openapi: 3.1.0
info: { title: Cookies, version: 1.0.0 }
paths:
  /profile:
    get:
      operationId: getProfile
      parameters:
        - name: identity
          in: cookie
          required: true
          schema:
            type: object
            required: [uid]
            properties:
              uid: { type: string }
      responses: { "204": { description: ok } }
"#;
        let files = generate(document, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getprofile.ts");
        assert!(handler.contains("cookies: Projected<{\n    identity: {\n      uid: string;"));
        assert!(handler.contains("rawCookies: Record<string, string>;"));
        assert!(handler.contains("location: \"cookie\""));
        assert!(handler.contains("helper: \"query-form\""));
        assert!(handler.contains("cookies: rawCookies"));
        assert!(handler.contains("      cookies: {"));
        assert!(handler.contains("      rawCookies,"));
    }

    #[test]
    fn paths_preserve_openapi_keys_and_share_projected_application_types() {
        let document = r#"
openapi: 3.1.0
info: { title: Paths, version: 1.0.0 }
paths:
  /:
    get:
      responses:
        default:
          description: fallback
          content:
            application/octet-stream:
              schema: { $ref: '#/components/schemas/UnusedBinaryShape' }
  /pets/{petId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema: { type: integer }
    get:
      parameters:
        - name: tags
          in: query
          schema: { type: array, items: { type: string } }
        - name: X-Trace
          in: header
          schema: { $ref: '#/components/schemas/Trace' }
      responses:
        "200":
          description: pet
          content:
            'Application/JSON; Version=2; profile="full"':
              schema: { $ref: '#/components/schemas/Pet' }
        "204": { description: empty }
        "4XX":
          description: problem
          content:
            text/plain:
              schema: { type: string }
    post:
      requestBody:
        required: false
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Pet' }
          multipart/form-data:
            schema:
              type: object
              required: [pet, photo]
              properties:
                pet: { $ref: '#/components/schemas/Pet' }
                photo: { type: string, format: binary }
      responses:
        "201":
          description: created
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Pet' }
components:
  schemas:
    Pet:
      type: object
      required: [id, name]
      properties:
        id: { type: integer }
        name: { type: string }
    Trace: { type: string }
    UnusedBinaryShape:
      type: object
      properties:
        bytes: { type: string }
"#;
        let files = generate(document, MSW_CONFIG);
        let paths = generated(&files, "msw/paths.ts");
        assert!(paths.contains("import type { Pet } from \"../types/components/pet.js\";"));
        assert!(!paths.contains("Trace"));
        assert!(!paths.contains("UnusedBinaryShape"));
        assert!(paths.contains(
            "\"/\": {\n    get: {\n      parameters: {};\n      responses: {\n        \"default\": {\n          content: {\n            \"application/octet-stream\": Uint8Array;"
        ));
        assert!(paths.contains(
            "\"/pets/{petId}\": {\n    get: {\n      parameters: {\n        path: {\n          petId: number;\n        };\n        query: {\n          tags?: string[];\n        };\n      };"
        ));
        assert!(paths.contains(
            "\"200\": {\n          content: {\n            \"application/json;profile=full;version=2\": Pet;"
        ));
        assert!(paths.contains("\"204\": {\n          content: never;"));
        assert!(paths.contains("\"4XX\": {"));
        assert!(paths.contains(
            "post: {\n      parameters: {\n        path: {\n          petId: number;\n        };\n      };\n      requestBody?: {\n        content: {\n          \"application/json\": Pet;\n          \"multipart/form-data\": {\n            pet: Pet;\n            photo: Uint8Array;"
        ));
        assert!(paths.contains("\"201\": {"));
    }

    #[test]
    fn enum_parameter_shapes_preserve_scalar_members_through_aliases_and_arrays() {
        let files = generate(ENUM_PARAMETERS, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/searchmessages.ts");
        assert!(
            handler.contains("shape: { kind: \"string\", enum: [\"relevance\", \"timestamp\"] }")
        );
        assert!(
            handler.contains("items: { kind: \"string\", enum: [\"user\", \"bot\", \"webhook\"] }")
        );
        assert!(
            handler.contains("items: { kind: \"string\", enum: [\"link\", \"embed\", \"file\"] }")
        );
        assert!(handler.contains("shape: { kind: \"integer\", enum: [10, 25] }"));
        assert!(handler.contains(
            "shape: { kind: \"nullable\", value: { kind: \"string\", enum: [\"active\"] } }"
        ));
        assert!(handler.contains("shape: { kind: \"number\", enum: [0.5, 1] }"));
        assert!(handler.contains("shape: { kind: \"boolean\", enum: [true] }"));
        assert!(handler.contains("shape: { kind: \"null\", enum: [null] }"));
    }

    #[test]
    fn showcase_request_bodies_are_typed_from_their_encoding_plans() {
        let files = generate(SHOWCASE, MSW_CONFIG);

        let json = generated(&files, "msw/handlers/createpetmock.ts");
        assert!(json.contains("body: NewPet;"), "{json}");
        assert!(json.contains("media: \"application/json\", kind: \"json\""));
        assert!(json.contains("const body = await projectRequestBody<NewPet>"));

        let binary = generated(&files, "msw/handlers/uploadphotomock.ts");
        assert!(binary.contains("body: Uint8Array;"), "{binary}");
        assert!(binary.contains("kind: \"binary\""));

        let form = generated(&files, "msw/handlers/submitformmock.ts");
        assert!(
            form.contains("name: string;\n    tags?: string[];"),
            "{form}"
        );
        assert!(form.contains("kind: \"urlencoded\""));
        assert!(form.contains("decoder: \"text\", shape: { kind: \"array\""));

        let multipart = generated(&files, "msw/handlers/uploadmultipartmock.ts");
        assert!(
            multipart.contains("meta: NewPet;\n    file: Uint8Array;"),
            "{multipart}"
        );
        assert!(multipart.contains("payload: \"json\", contentType: { kind: \"fixed\""));
        assert!(multipart.contains("payload: \"binary\""));
        assert!(multipart.contains("filename: true"));

        let bodyless = generated(&files, "msw/handlers/headhealthmock.ts");
        assert!(!bodyless.contains("projectRequestBody"));
        assert!(!bodyless.contains("  body:"));
    }

    #[test]
    fn text_ranges_and_multiple_request_media_keep_the_sent_media_arm() {
        let document = r#"
openapi: 3.1.0
info: { title: Body media, version: 1.0.0 }
paths:
  /text:
    post:
      operationId: sendText
      requestBody:
        required: false
        content:
          text/xml: { schema: { type: string } }
      responses: { "204": { description: ok } }
  /mixed:
    post:
      operationId: sendMixed
      requestBody:
        required: true
        content:
          multipart/mixed: { schema: { type: object } }
      responses: { "204": { description: ok } }
  /multiple:
    post:
      operationId: sendMultiple
      requestBody:
        content:
          application/json: { schema: { $ref: '#/components/schemas/Value' } }
          text/plain: { schema: { type: string } }
      responses: { "204": { description: ok } }
  /range:
    post:
      operationId: sendRange
      requestBody:
        content:
          'application/*': { schema: { type: string } }
      responses: { "204": { description: ok } }
  /unknown:
    post:
      operationId: sendUnknown
      requestBody:
        content:
          application/json: {}
      responses: { "204": { description: ok } }
components:
  schemas:
    Value: { type: object, properties: { name: { type: string } } }
"#;
        let files = generate(document, MSW_CONFIG);

        let text = generated(&files, "msw/handlers/sendtext.ts");
        assert!(text.contains("body: string | undefined;"), "{text}");
        assert!(text.contains("required: false"));
        assert!(text.contains("kind: \"text\""));

        let mixed = generated(&files, "msw/handlers/sendmixed.ts");
        assert!(mixed.contains("body: Uint8Array;"), "{mixed}");
        assert!(mixed.contains("kind: \"binary\""));

        let multiple = generated(&files, "msw/handlers/sendmultiple.ts");
        assert!(multiple.contains(
            "body: { contentType: \"application/json\"; body: Value } | { contentType: \"text/plain\"; body: string } | undefined;"
        ), "{multiple}");
        assert!(multiple.contains("discriminated: true"));

        let range = generated(&files, "msw/handlers/sendrange.ts");
        assert!(
            range.contains("body: { contentType: string; body: Uint8Array }"),
            "{range}"
        );

        let unknown = generated(&files, "msw/handlers/sendunknown.ts");
        assert!(unknown.contains("body: unknown | undefined;"), "{unknown}");
    }

    #[test]
    fn structured_body_descriptors_preserve_field_styles_and_part_policies() {
        let document = r#"
openapi: 3.1.0
info: { title: Structured bodies, version: 1.0.0 }
paths:
  /form:
    post:
      operationId: sendForm
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              required: [exploded, joined, spaced, piped, deep, json, text]
              properties:
                exploded: { type: string }
                joined: { type: array, items: { type: string } }
                spaced: { type: array, items: { type: string } }
                piped: { type: array, items: { type: string } }
                deep: { type: object, properties: { name: { type: string } } }
                json: { type: object, properties: { active: { type: boolean } } }
                text: { type: string }
            encoding:
              exploded: { style: form, explode: true }
              joined: { style: form, explode: false }
              spaced: { style: spaceDelimited, explode: false }
              piped: { style: pipeDelimited, explode: false }
              deep: { style: deepObject, explode: true }
              json: { contentType: application/json }
              text: { contentType: text/plain }
      responses: { "204": { description: ok } }
  /multipart:
    post:
      operationId: sendMultipart
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              required: [styledText, styledJson, styledBinary, selected, files, referencedFiles]
              properties:
                styledText: { type: string }
                styledJson: { type: object, properties: { active: { type: boolean } } }
                styledBinary: { type: string, format: binary }
                selected: { type: string }
                files: { type: array, items: { type: string, format: binary } }
                referencedFiles: { $ref: '#/components/schemas/BinaryFiles' }
            encoding:
              styledText: { style: form }
              styledJson: { style: form }
              styledBinary: { style: form }
              selected: { contentType: 'application/json, text/plain' }
      responses: { "204": { description: ok } }
components:
  schemas:
    BinaryFiles:
      type: array
      items: { type: string, format: binary }
"#;
        let files = generate(document, MSW_CONFIG);

        let form = generated(&files, "msw/handlers/sendform.ts");
        for helper in [
            "query-form-explode",
            "query-form",
            "query-space-delimited",
            "query-pipe-delimited",
            "query-deep-object-extended",
        ] {
            assert!(form.contains(&format!("helper: \"{helper}\"")), "{form}");
        }
        assert!(form.contains("name: \"json\""));
        assert!(form.contains("decoder: \"json\""));
        assert!(form.contains("name: \"text\""));
        assert!(form.contains("decoder: \"text\""));

        let multipart = generated(&files, "msw/handlers/sendmultipart.ts");
        assert!(multipart.contains("styledText: string;"), "{multipart}");
        assert!(multipart.contains("styledBinary: Uint8Array;"));
        assert!(multipart.contains("files: Uint8Array[];"));
        assert!(multipart.contains("referencedFiles: Uint8Array[];"));
        assert!(multipart.contains("contentType: { kind: \"none\" }"));
        assert!(multipart.contains(
            "contentType: { kind: \"selected\", admitted: [\"application/json\", \"text/plain\"] }, payloads: [\"json\", \"text\"]"
        ), "{multipart}");
        assert!(multipart.contains("repeated: true"));
    }

    #[test]
    fn noninvertible_form_bodies_report_diagnostics_without_handlers() {
        let document = r#"
openapi: 3.1.0
info: { title: Noninvertible forms, version: 1.0.0 }
paths:
  /reserved:
    post:
      operationId: sendReserved
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties: { value: { type: string } }
            encoding:
              value: { style: form, allowReserved: true }
      responses: { "204": { description: ok } }
  /selected:
    post:
      operationId: sendSelected
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties: { value: { type: string } }
            encoding:
              value: { contentType: 'text/plain, text/csv' }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_BODY_PROJECTION)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 2, "{projection:#?}");
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("reserved delimiters"))
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("not represented on the wire"))
        );
        assert!(files.iter().all(|file| {
            file.relative_path != "msw/handlers/sendreserved.ts"
                && file.relative_path != "msw/handlers/sendselected.ts"
        }));
    }

    #[test]
    fn missing_and_unprojectable_body_shapes_report_diagnostics() {
        let document = r#"
openapi: 3.1.0
info: { title: Invalid body shapes, version: 1.0.0 }
paths:
  /empty:
    post:
      operationId: sendEmpty
      requestBody: { content: {} }
      responses: { "204": { description: ok } }
  /shape:
    post:
      operationId: sendShape
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties: { value: {} }
            encoding:
              value: { contentType: text/plain }
      responses: { "204": { description: ok } }
  /scalar-form:
    post:
      operationId: sendScalarForm
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema: { type: string }
      responses: { "204": { description: ok } }
  /scalar-multipart:
    post:
      operationId: sendScalarMultipart
      requestBody:
        content:
          multipart/form-data:
            schema: { type: string }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_BODY_PROJECTION)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 4, "{projection:#?}");
        assert!(
            projection
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("declares no usable media type") })
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("cannot be decoded") }),
            "{projection:#?}"
        );
        assert_eq!(
            projection
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("requires an object schema"))
                .count(),
            2,
            "{projection:#?}"
        );
        assert!(files.iter().all(|file| {
            file.relative_path != "msw/handlers/sendempty.ts"
                && file.relative_path != "msw/handlers/sendshape.ts"
                && file.relative_path != "msw/handlers/sendscalarform.ts"
                && file.relative_path != "msw/handlers/sendscalarmultipart.ts"
        }));
    }

    #[test]
    fn transformed_request_bodies_report_diagnostics_without_placeholder_types() {
        let document = r#"
openapi: 3.1.0
info: { title: Transformed bodies, version: 1.0.0 }
paths:
  /json:
    post:
      operationId: sendJsonDate
      requestBody:
        content:
          application/json: { schema: { type: string, format: date-time } }
      responses: { "204": { description: ok } }
  /form:
    post:
      operationId: sendFormDate
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties: { at: { type: string, format: date-time } }
      responses: { "204": { description: ok } }
  /multipart:
    post:
      operationId: sendMultipartDate
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties: { at: { type: string, format: date-time } }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_config(document, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
        });
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_BODY_PROJECTION)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 3, "{projection:#?}");
        assert!(
            projection
                .iter()
                .all(|diagnostic| diagnostic.message.contains("date/time transform"))
        );
        assert!(
            files
                .iter()
                .all(|file| { !file.relative_path.starts_with("msw/handlers/send") })
        );
    }

    #[test]
    fn invalid_internal_body_plans_fail_with_diagnostics() {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), MINIMAL).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), MSW_CONFIG).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_config(None, temp.path()).expect("config loads");
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut sink);
        let source = SourceRef::default();
        let string_schema = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: None,
            meta: SchemaMeta::default(),
        };
        let wrapper = crate::client_model::FieldWrapperPlan {
            wrapped: false,
            content_type_literal: true,
            filename: false,
        };
        let style_field = FormFieldPlan {
            name: "value".to_owned(),
            required: true,
            schema: string_schema.clone(),
            serialization: FieldSerializationPlan::Style {
                style: ParamStyle::Simple,
                explode: false,
                allow_reserved: false,
                encoding_source: source.clone(),
            },
            wrapper,
            source: source.clone(),
        };
        let binary_field = FormFieldPlan {
            name: "binary".to_owned(),
            required: true,
            schema: string_schema.clone(),
            serialization: FieldSerializationPlan::Content {
                media: PartMediaPlan {
                    values: vec!["application/octet-stream".to_owned()],
                    payloads: vec![PayloadKind::Binary],
                    all_concrete: true,
                    binary_upload: true,
                    declared: true,
                },
                encoding_source: None,
            },
            wrapper,
            source: source.clone(),
        };
        let empty_field = FormFieldPlan {
            name: "empty".to_owned(),
            required: false,
            schema: string_schema,
            serialization: FieldSerializationPlan::Content {
                media: PartMediaPlan {
                    values: Vec::new(),
                    payloads: Vec::new(),
                    all_concrete: true,
                    binary_upload: false,
                    declared: true,
                },
                encoding_source: None,
            },
            wrapper,
            source: source.clone(),
        };

        let unsupported = BodyPlan::FormUrlencoded {
            media: "application/x-www-form-urlencoded".to_owned(),
            fields: vec![style_field.clone(), binary_field.clone()],
            source: source.clone(),
        };
        let mut diagnostics = Vec::new();
        inspect_body_projection(&model, &unsupported, &mut diagnostics);
        assert_eq!(diagnostics.len(), 2);

        let mut output = String::new();
        assert!(write_urlencoded_field_descriptor(&mut output, &model, &style_field).is_err());
        output.clear();
        assert!(write_urlencoded_field_descriptor(&mut output, &model, &binary_field).is_err());
        output.clear();
        assert!(write_urlencoded_field_descriptor(&mut output, &model, &empty_field).is_err());
        output.clear();
        assert!(write_multipart_field_descriptor(&mut output, &model, &empty_field).is_err());

        let nested = BodyPlan::ContentTypeDiscriminated {
            arms: vec![(
                "application/*".to_owned(),
                BodyPlan::ContentTypeDiscriminated {
                    arms: Vec::new(),
                    all_concrete: false,
                },
            )],
            all_concrete: false,
        };
        assert!(render_request_body_descriptor(&model, &nested, true, &source).is_err());

        let cycle_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "cycle".to_owned(),
                json_pointer: "/Cycle".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let mut visited = BTreeSet::from([("cycle".to_owned(), "/Cycle".to_owned())]);
        assert!(!schema_is_array(&model, &cycle_ref, &mut visited));
    }

    #[test]
    fn every_serialization_helper_has_a_projection_name() {
        let names = HelperId::ALL.map(parameter_helper_name);
        assert_eq!(names.len(), 19);
        assert_eq!(names.into_iter().collect::<BTreeSet<_>>().len(), 19);
        assert_eq!(parameter_location_name(ParamLocation::Cookie), "cookie");
        for (style, expected) in [
            (ParamStyle::Form, "form"),
            (ParamStyle::Simple, "simple"),
            (ParamStyle::Label, "label"),
            (ParamStyle::Matrix, "matrix"),
            (ParamStyle::SpaceDelimited, "spaceDelimited"),
            (ParamStyle::PipeDelimited, "pipeDelimited"),
            (ParamStyle::DeepObject, "deepObject"),
        ] {
            assert_eq!(parameter_style_name(style), expected);
        }
    }

    #[test]
    fn projection_shape_renderer_covers_every_schema_node_and_container_edge() {
        let temp = TempDir::new().expect("temp dir");
        let document = format!(
            "{MINIMAL}\ncomponents:\n  schemas:\n    Value:\n      type: string\n    Values:\n      type: array\n      items:\n        type: string\n"
        );
        fs::write(temp.path().join("openapi.yaml"), document).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), MSW_CONFIG).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_config(None, temp.path()).expect("config loads");
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        assert_eq!(default_base_url(&analyzed.ir.operations[0], &[]), None);
        let value_source = analyzed.ir.schemas[0].source.clone();
        let values_source = analyzed.ir.schemas[1].source.clone();
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut sink);

        let primitive = |ty, nullable| SchemaNode::Primitive {
            ty,
            format: None,
            enum_values: None,
            const_value: None,
            meta: SchemaMeta {
                nullable,
                ..SchemaMeta::default()
            },
        };
        let render = |schema: &SchemaNode, content_json, nested_style_value| {
            render_projection_shape(
                &model,
                schema,
                content_json,
                nested_style_value,
                0,
                &mut ProjectionLimits::new(),
            )
        };

        for (ty, expected) in [
            (PrimitiveType::String, "string"),
            (PrimitiveType::Number, "number"),
            (PrimitiveType::Integer, "integer"),
            (PrimitiveType::Boolean, "boolean"),
            (PrimitiveType::Null, "null"),
        ] {
            assert!(
                render(&primitive(ty, false), false, false)
                    .unwrap()
                    .contains(expected)
            );
        }
        assert!(
            render(&primitive(PrimitiveType::String, true), false, false)
                .unwrap()
                .contains("nullable")
        );

        let finite_primitive = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: Some(vec![json!("a"), json!("b")]),
            const_value: None,
            meta: SchemaMeta::default(),
        };
        assert!(
            render(&finite_primitive, false, false)
                .unwrap()
                .contains("kind: \"string\", enum: [\"a\", \"b\"]")
        );
        assert_eq!(
            projection_finite_union(&finite_primitive),
            Some(vec![json!("a"), json!("b")])
        );
        assert!(render_scalar_shape(PrimitiveType::String, Some(&[json!(1)]), false).is_err());
        let finite = SchemaNode::Finite {
            enum_values: Some(vec![json!(1), json!(true)]),
            const_value: None,
            meta: SchemaMeta {
                nullable: true,
                ..SchemaMeta::default()
            },
        };
        assert!(render(&finite, true, false).unwrap().contains("nullable"));
        let unconstrained_finite = SchemaNode::Finite {
            enum_values: None,
            const_value: None,
            meta: SchemaMeta::default(),
        };
        assert!(
            render(&unconstrained_finite, true, false)
                .unwrap()
                .contains("unknown")
        );
        assert!(render(&unconstrained_finite, false, false).is_err());

        let properties = vec![
            (
                "required".to_owned(),
                primitive(PrimitiveType::String, false),
                PropMeta {
                    required: true,
                    read_only: false,
                    write_only: false,
                },
            ),
            (
                "optional".to_owned(),
                primitive(PrimitiveType::Boolean, false),
                PropMeta {
                    required: false,
                    read_only: false,
                    write_only: false,
                },
            ),
            (
                "readOnly".to_owned(),
                primitive(PrimitiveType::String, false),
                PropMeta {
                    required: false,
                    read_only: true,
                    write_only: false,
                },
            ),
        ];
        for additional in [
            AdditionalProperties::Allowed(None),
            AdditionalProperties::Forbidden,
            AdditionalProperties::Allowed(Some(Box::new(primitive(PrimitiveType::Number, false)))),
            AdditionalProperties::Schema(Box::new(primitive(PrimitiveType::Integer, false))),
        ] {
            let object = SchemaNode::Object {
                properties: properties.clone(),
                additional_properties: additional,
                dependent_required: Vec::new(),
                finite: None,
                extra_required: Vec::new(),
                meta: SchemaMeta::default(),
            };
            let rendered = render(&object, true, false).unwrap();
            assert!(rendered.contains("required: true"));
            assert!(rendered.contains("required: false"));
            assert!(!rendered.contains("readOnly"));
        }

        let failing_additional = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Schema(Box::new(SchemaNode::Array {
                items: Box::new(primitive(PrimitiveType::String, false)),
                finite: None,
                meta: SchemaMeta::default(),
            })),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: SchemaMeta::default(),
        };
        assert!(render(&failing_additional, false, false).is_err());

        let array = SchemaNode::Array {
            items: Box::new(primitive(PrimitiveType::String, false)),
            finite: None,
            meta: SchemaMeta::default(),
        };
        assert!(render(&array, true, false).unwrap().contains("array"));
        assert!(render(&array, false, true).is_err());

        let all_empty = SchemaNode::AllOf {
            branches: Vec::new(),
            meta: SchemaMeta::default(),
        };
        assert!(render(&all_empty, true, false).unwrap().contains("unknown"));
        let all = SchemaNode::AllOf {
            branches: vec![
                primitive(PrimitiveType::String, false),
                primitive(PrimitiveType::String, false),
            ],
            meta: SchemaMeta::default(),
        };
        assert!(render(&all, true, false).unwrap().contains("intersection"));
        let one = SchemaNode::OneOf {
            branches: vec![
                primitive(PrimitiveType::String, false),
                primitive(PrimitiveType::Number, false),
            ],
            discriminator: None,
            meta: SchemaMeta::default(),
        };
        assert!(render(&one, true, false).unwrap().contains("union"));
        let any_empty = SchemaNode::AnyOf {
            branches: Vec::new(),
            discriminator: None,
            meta: SchemaMeta {
                nullable: true,
                ..SchemaMeta::default()
            },
        };
        let rendered = render(&any_empty, true, false).unwrap();
        assert!(rendered.contains("never"));
        assert!(rendered.contains("nullable"));
        assert!(
            render(
                &SchemaNode::Any {
                    meta: SchemaMeta::default()
                },
                true,
                false
            )
            .unwrap()
            .contains("unknown")
        );
        let unknown = SchemaNode::Unknown {
            reason: "test".to_owned(),
            meta: SchemaMeta::default(),
        };
        assert!(render(&unknown, true, false).unwrap().contains("unknown"));
        assert_eq!(projection_finite_union(&unknown), None);
        assert!(projection_scalar_enum(&[unknown.clone(), unknown.clone()]).is_none());
        assert!(
            render(
                &SchemaNode::Never {
                    meta: SchemaMeta {
                        nullable: true,
                        ..SchemaMeta::default()
                    }
                },
                true,
                false
            )
            .unwrap()
            .contains("nullable")
        );
        let missing_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "missing".to_owned(),
                json_pointer: "/components/schemas/Missing".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        assert!(render(&missing_ref, true, false).is_err());
        let nullable_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: value_source.source_id,
                json_pointer: value_source.json_pointer,
            },
            meta: SchemaMeta {
                nullable: true,
                ..SchemaMeta::default()
            },
        };
        assert!(
            render(&nullable_ref, true, false)
                .unwrap()
                .contains("nullable")
        );
        let failing_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: values_source.source_id,
                json_pointer: values_source.json_pointer,
            },
            meta: SchemaMeta::default(),
        };
        assert!(render(&failing_ref, false, true).is_err());
        let failing_union = SchemaNode::OneOf {
            branches: vec![array.clone()],
            discriminator: None,
            meta: SchemaMeta::default(),
        };
        assert!(render(&failing_union, false, true).is_err());
        let failing_intersection = SchemaNode::AllOf {
            branches: vec![array],
            meta: SchemaMeta::default(),
        };
        assert!(render(&failing_intersection, false, true).is_err());

        let mut deep = primitive(PrimitiveType::String, false);
        for _ in 0..=MAX_PARAMETER_SHAPE_DEPTH {
            deep = SchemaNode::Array {
                items: Box::new(deep),
                finite: None,
                meta: SchemaMeta::default(),
            };
        }
        assert!(render(&deep, true, false).is_err());
    }

    #[test]
    fn caller_serialized_content_reports_oasts1508_and_omits_the_handler() {
        let document = r#"
openapi: 3.1.0
info: { title: Opaque parameter, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
      parameters:
        - name: X-Value
          in: header
          content:
            application/xml:
              schema: { type: object }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_PARAMETER_PROJECTION)
            .expect("opaque content is not invertible");
        assert!(diagnostic.message.contains("X-Value"));
        assert!(diagnostic.message.contains("simple"));
        assert!(diagnostic.message.contains("application/xml"));
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/getvalue.ts")
        );
    }

    #[test]
    fn unsupported_parameter_shapes_report_oasts1508_without_a_placeholder_handler() {
        let document = r#"
openapi: 3.1.0
info: { title: Unsupported projections, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
      parameters:
        - name: tuple
          in: query
          schema:
            type: array
            prefixItems: [{ type: string }]
            items: false
        - name: nested
          in: query
          style: form
          explode: false
          schema:
            type: object
            properties:
              child: { type: object }
        - name: unconstrained
          in: header
          schema: true
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_PARAMETER_PROJECTION)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 3, "{projection:#?}");
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("tuple"))
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("nested"))
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("unconstrained"))
        );
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/getvalue.ts")
        );
    }

    #[test]
    fn exploded_label_collections_report_oasts1510_without_a_handler() {
        let document = r#"
openapi: 3.1.0
info: { title: Label boundaries, version: 1.0.0 }
paths:
  /values/{items}/{fields}:
    get:
      operationId: getValues
      parameters:
        - name: items
          in: path
          required: true
          style: label
          explode: true
          schema: { type: array, items: { type: string } }
        - name: fields
          in: path
          required: true
          style: label
          explode: true
          schema:
            type: object
            additionalProperties: { type: string }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_NONINVERTIBLE_PARAMETER)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 2, "{projection:#?}");
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("items"))
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("fields"))
        );
        assert!(
            projection
                .iter()
                .all(|diagnostic| diagnostic.message.contains("label"))
        );
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/getvalues.ts")
        );
    }

    #[test]
    fn reserved_query_values_report_oasts1510_without_a_handler() {
        let document = r#"
openapi: 3.1.0
info: { title: Query boundaries, version: 1.0.0 }
paths:
  /values:
    get:
      operationId: getValues
      parameters:
        - name: items
          in: query
          style: form
          explode: false
          allowReserved: true
          schema: { type: array, items: { type: string } }
        - name: filter
          in: query
          style: form
          allowReserved: true
          schema: { type: string }
      responses: { "204": { description: ok } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        let projection = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_NONINVERTIBLE_PARAMETER)
            .collect::<Vec<_>>();
        assert_eq!(projection.len(), 2, "{projection:#?}");
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("items"))
        );
        assert!(
            projection
                .iter()
                .any(|diagnostic| diagnostic.message.contains("filter"))
        );
        assert!(projection.iter().all(|diagnostic| {
            diagnostic.message.contains("form") && diagnostic.message.contains("allowReserved")
        }));
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/getvalues.ts")
        );
    }

    #[test]
    fn transformed_recursive_and_patterned_parameters_are_generation_diagnostics() {
        let date_document = r#"
openapi: 3.1.0
info: { title: Date, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
      parameters:
        - name: at
          in: query
          schema: { type: string, format: date-time }
      responses: { "204": { description: ok } }
"#;
        let (_, diagnostics) = generate_with_config(date_document, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
        });
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_PARAMETER_PROJECTION
                && diagnostic.message.contains("date/time transform")
        }));

        let structural = r#"
openapi: 3.1.0
info: { title: Structural, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
      parameters:
        - name: recursive
          in: header
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Node' }
        - name: patterned
          in: header
          content:
            application/json:
              schema:
                type: object
                patternProperties:
                  '^x': { type: string }
      responses: { "204": { description: ok } }
components:
  schemas:
    Node:
      type: object
      properties:
        next: { $ref: '#/components/schemas/Node' }
"#;
        let (_, diagnostics) = generate_with_diagnostics(structural, MSW_CONFIG);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_PARAMETER_PROJECTION && diagnostic.message.contains("recursive")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_PARAMETER_PROJECTION
                && diagnostic.message.contains("patternProperties")
        }));
    }

    #[test]
    fn the_response_body_union_names_every_declared_media_type() {
        // This union is what MSW is told the handler may respond with, and supplying it is the only
        // thing that turns on MSW's own response-body checking. A placeholder here would typecheck
        // and silently check nothing.
        let files = generate(SHOWCASE, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getpetmock.ts");
        assert!(
            handler.contains("type GetPetMockResponseBody = SendableBody<Pet | string | Problem>;"),
            "{handler}"
        );
    }

    #[test]
    fn the_payload_map_names_every_declared_media_and_its_wire_form() {
        // The kernel is told how each declared media is written rather than classifying it, so the
        // compiler and the runtime cannot disagree. text/json is the case that proves it: this
        // compiler counts it as JSON, and a runtime rule keyed on "application/json or +json"
        // silently wrote it out with String(...).
        let files = generate(UNCONSTRAINED, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/gettextjson.ts");
        assert!(
            handler.contains(r#"const responsePayloads = { ["text/json"]: "json" } as const;"#),
            "{handler}"
        );
        assert!(
            handler.contains("respondWith(response.status, contentType, body, responsePayloads)"),
            "{handler}"
        );

        let showcase = generate(SHOWCASE, MSW_CONFIG);
        let report = generated(&showcase, "msw/handlers/getreportmock.ts");
        assert!(
            report.contains(r#"{ ["application/octet-stream"]: "binary" }"#),
            "{report}"
        );
        let pet = generated(&showcase, "msw/handlers/getpetmock.ts");
        assert!(
            pet.contains(r#"{ ["application/json"]: "json", ["text/plain"]: "text" }"#),
            "{pet}"
        );
    }

    #[test]
    fn a_schema_that_expands_past_the_node_budget_is_refused() {
        // Depth alone does not bound the descriptor: a `$ref` is inlined wherever it is named, and
        // the cycle guard is popped on the way out, so a schema shared between siblings expands
        // once per sibling. Eight-way branching over ten levels used to emit tens of megabytes from
        // a few kilobytes of input, and hang the compiler before the depth limit ever tripped.
        let mut document = String::from(
            "openapi: 3.1.0\ninfo:\n  title: fanout\n  version: 1.0.0\nservers:\n  - url: https://api.test\npaths:\n  /a:\n    get:\n      operationId: getA\n      parameters:\n        - name: p\n          in: query\n          required: false\n          schema:\n            $ref: \"#/components/schemas/S0\"\n      responses:\n        \"204\":\n          description: ok\ncomponents:\n  schemas:\n",
        );
        const LEVELS: usize = 8;
        for level in 0..LEVELS {
            document.push_str(&format!("    S{level}:\n      oneOf:\n"));
            for _ in 0..8 {
                document.push_str(&format!(
                    "        - $ref: \"#/components/schemas/S{}\"\n",
                    level + 1
                ));
            }
        }
        document.push_str(&format!("    S{LEVELS}:\n      type: string\n"));

        let (files, diagnostics) = generate_with_diagnostics(&document, MSW_CONFIG);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_PARAMETER_PROJECTION
                    && diagnostic.message.contains("projection nodes")),
            "{diagnostics:?}"
        );
        // The operation is refused, not emitted at whatever size it reached.
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/geta.ts"),
            "a handler was emitted for a schema that blew the budget"
        );
    }

    #[test]
    fn a_bodyless_operation_declares_a_null_response_body() {
        // Not `never`: `never` reads as "no response is possible" and sends MSW's own
        // resolver-return inference down its GraphQL branch. `null` is the body such a response
        // actually carries.
        let files = generate(SHOWCASE, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/headhealthmock.ts");
        assert!(
            handler.contains("type HeadHealthMockResponseBody = null;"),
            "{handler}"
        );
        assert!(!handler.contains("SendableBody"), "{handler}");
    }

    const UNCONSTRAINED: &str =
        include_str!("../../../../fixtures/msw-unconstrained-body-3.1/openapi.yaml");

    #[test]
    fn every_body_union_is_clamped_in_the_type_system() {
        let files = generate(UNCONSTRAINED, MSW_CONFIG);
        for base in ["getunconstrained", "getbooleantrue"] {
            let handler = generated(&files, &format!("msw/handlers/{base}.ts"));
            assert!(
                handler.contains("ResponseBody = SendableBody<unknown>;"),
                "{base}: {handler}"
            );
            assert!(
                handler.contains("type SendableBody"),
                "{base} must import the type it names: {handler}"
            );
            assert!(!handler.contains("DefaultBodyType"), "{base}: {handler}");
        }
    }

    #[test]
    fn a_component_alias_of_unknown_is_clamped_without_inspecting_its_name() {
        let files = generate(UNCONSTRAINED, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getaliased.ts");
        assert!(
            handler.contains("type GetAliasedResponseBody = SendableBody<OpenBody>;"),
            "{handler}"
        );
        assert!(
            handler.contains("contentType: \"application/json\"; body: OpenBody"),
            "{handler}"
        );
    }

    #[test]
    fn an_open_entry_remains_visible_inside_a_mixed_body_union() {
        let files = generate(UNCONSTRAINED, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getmixed.ts");
        assert!(
            handler.contains("type GetMixedResponseBody = SendableBody<Thing | unknown>;"),
            "{handler}"
        );
    }

    #[test]
    fn a_binary_response_body_is_bytes_rather_than_its_structural_type() {
        // `type: string, format: binary` renders as `string` in the documentation types, but a
        // handler writes the wire body, and the wire body is bytes. The split follows the client's
        // own response-media classification so the two artifacts agree about one document.
        let files = generate(SHOWCASE, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getreportmock.ts");
        assert!(
            handler.contains(
                "{ match: 200; status: 200; contentType: \"application/octet-stream\"; body: Uint8Array }"
            ),
            "{handler}"
        );
        assert!(
            handler.contains("type GetReportMockResponseBody = SendableBody<Uint8Array>;"),
            "{handler}"
        );
    }

    #[test]
    fn operation_handlers_correlate_status_media_and_each_entry_schema() {
        let files = generate(SHOWCASE, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getpetmock.ts");
        assert!(handler.contains(
            "export type GetPetMockResponse =\n  | { match: 200; status: 200; contentType: \"application/json\"; body: Pet }\n  | { match: 200; status: 200; contentType: \"text/plain\"; body: string }\n  | { match: 204; status: 204 }\n  | { match: \"4XX\"; status: number; contentType: \"application/json\"; body: Problem }\n  | { match: \"default\"; status: number; contentType: \"application/json\"; body: Problem };"
        ));
        assert!(handler.contains("response: T & NoPayloadGuard<T, 204>"));
        assert!(handler.contains("const pathPattern = \"/pets/:petId([^/]{0,})\";"));
        assert!(handler.contains("const ownsBody = Object.hasOwn(response, \"body\");"));
        assert!(handler.contains("contentType === null && (ownsContentType || ownsBody)"));

        let binary = generated(&files, "msw/handlers/getreportmock.ts");
        assert!(binary.contains("contentType: \"application/octet-stream\"; body: Uint8Array"));
        assert_eq!(
            files
                .iter()
                .filter(|file| file.relative_path.starts_with("msw/handlers/"))
                .count(),
            7
        );
    }

    #[test]
    fn canonical_full_media_types_keep_distinct_schema_arms() {
        let document = r#"
openapi: 3.1.0
info: { title: Media, version: 1.0.0 }
paths:
  /media:
    get:
      operationId: readMedia
      responses:
        "200":
          description: variants
          content:
            'application/json; version=2; profile="full"':
              schema: { type: integer }
            text/plain:
              schema: { type: string }
        "204":
          description: absent content map
        "205":
          description: empty content map
          content: {}
"#;
        let files = generate(document, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/readmedia.ts");
        assert!(
            handler
                .contains("contentType: \"application/json;profile=full;version=2\"; body: number")
        );
        assert!(handler.contains("contentType: \"text/plain\"; body: string"));
        assert!(handler.contains("{ match: 204; status: 204 }"));
        assert!(handler.contains("{ match: 205; status: 205 }"));
    }

    #[test]
    fn component_imports_are_deduplicated_and_aliased_away_from_runtime_bindings() {
        let document = r#"
openapi: 3.1.0
info: { title: Aliases, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
      responses:
        "200":
          description: first
          content:
            application/json:
              schema: { $ref: '#/components/schemas/HttpResponse' }
            application/problem+json:
              schema: { $ref: '#/components/schemas/HttpResponse' }
            text/json:
              schema: { $ref: '#/components/schemas/GetValueResponseBody' }
components:
  schemas:
    HttpResponse:
      type: object
      required: [ok]
      properties:
        ok: { type: boolean }
    GetValueResponseBody:
      type: object
      required: [value]
      properties:
        value: { type: string }
"#;
        let files = generate(document, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getvalue.ts");
        assert_eq!(
            handler
                .matches("import type { HttpResponse as HttpResponseBody }")
                .count(),
            1
        );
        assert_eq!(handler.matches("body: HttpResponseBody").count(), 2);
        assert!(handler.contains("body: GetValueResponseBody"));
        // The private marker moved aside because an imported component already binds the compact
        // name. It still holds the real union, deduplicated: the two JSON-decoding arms share one
        // body type and collapse to a single member.
        assert!(
            handler.contains(
                "type GetValueResponseBodyValue = SendableBody<HttpResponseBody | GetValueResponseBody>;"
            ),
            "{handler}"
        );
    }

    #[test]
    fn effective_server_precedence_and_default_substitution_control_option_requiredness() {
        let document = r#"
openapi: 3.1.0
info: { title: Servers, version: 1.0.0 }
servers:
  - url: https://root.test/{version}
    variables:
      version: { default: v1 }
paths:
  /path:
    servers:
      - url: https://path.test/{stage}
        variables:
          stage: { default: beta }
    get:
      operationId: fromPath
      responses: { "204": { description: ok } }
    post:
      operationId: fromOperation
      servers:
        - url: /relative/{version}
          variables:
            version: { default: v2 }
      responses: { "204": { description: ok } }
  /root:
    get:
      operationId: fromRoot
      responses: { "204": { description: ok } }
  /unresolved:
    get:
      operationId: unresolvedServer
      servers:
        - url: https://{host}/{missing}
          variables:
            host: { default: api.test }
      responses: { "204": { description: ok } }
"#;
        let files = generate(document, MSW_CONFIG);
        let from_path = generated(&files, "msw/handlers/frompath.ts");
        assert!(from_path.contains("options?: { baseUrl?: string }"));
        assert!(from_path.contains("options?.baseUrl ?? \"https://path.test/beta\""));
        let from_operation = generated(&files, "msw/handlers/fromoperation.ts");
        assert!(from_operation.contains("options: { baseUrl: string }"));
        assert!(from_operation.contains("const resolvedBaseUrl = options.baseUrl;"));
        let from_root = generated(&files, "msw/handlers/fromroot.ts");
        assert!(from_root.contains("options?.baseUrl ?? \"https://root.test/v1\""));
        let unresolved = generated(&files, "msw/handlers/unresolvedserver.ts");
        assert!(unresolved.contains("options: { baseUrl: string }"));
    }

    #[test]
    fn a_document_without_an_effective_server_requires_base_url() {
        let document = r#"
openapi: 3.1.0
info: { title: No server, version: 1.0.0 }
servers: []
paths:
  /value:
    get:
      operationId: getValue
      responses: { "204": { description: ok } }
"#;
        let files = generate(document, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getvalue.ts");
        assert!(handler.contains("options: { baseUrl: string }"));
    }

    #[test]
    fn an_operation_without_responses_still_emits_a_callable_factory() {
        let document = r#"
openapi: 3.1.0
info: { title: No responses, version: 1.0.0 }
paths:
  /value:
    get:
      operationId: getValue
"#;
        let files = generate(document, MSW_CONFIG);
        let handler = generated(&files, "msw/handlers/getvalue.ts");
        assert!(handler.contains("export type GetValueResponse = never;"));
    }

    #[test]
    fn an_operation_without_an_allocated_file_is_skipped() {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), MINIMAL).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), MSW_CONFIG).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_config(None, temp.path()).expect("config loads");
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        let mut model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut sink);
        model.operation_files[0] = None;
        let files = emit_msw_from_model(&mut model);
        assert!(
            files
                .iter()
                .all(|file| !file.relative_path.starts_with("msw/handlers/"))
        );
    }

    #[test]
    fn every_msw_http_method_maps_to_its_lowercase_factory() {
        let document = r#"
openapi: 3.1.0
info: { title: Methods, version: 1.0.0 }
paths:
  /methods:
    delete: { operationId: deleteCall, responses: { "204": { description: ok } } }
    get: { operationId: getCall, responses: { "204": { description: ok } } }
    head: { operationId: headCall, responses: { "204": { description: ok } } }
    options: { operationId: optionsCall, responses: { "204": { description: ok } } }
    patch: { operationId: patchCall, responses: { "204": { description: ok } } }
    post: { operationId: postCall, responses: { "204": { description: ok } } }
    put: { operationId: putCall, responses: { "204": { description: ok } } }
"#;
        let files = generate(document, MSW_CONFIG);
        for method in ["delete", "get", "head", "options", "patch", "post", "put"] {
            let handler = generated(&files, &format!("msw/handlers/{method}call.ts"));
            assert!(handler.contains(&format!("return http.{method}<")));
        }
    }

    #[test]
    fn an_unmappable_method_reports_oasts1507_and_does_not_stop_other_handlers() {
        let document = r#"
openapi: 3.1.0
info: { title: Trace, version: 1.0.0 }
paths:
  /calls:
    trace: { operationId: traceCall, responses: { "204": { description: ok } } }
    get: { operationId: getCall, responses: { "204": { description: ok } } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_UNMATCHABLE_METHOD)
        );
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/tracecall.ts")
        );
        generated(&files, "msw/handlers/getcall.ts");
    }

    #[test]
    fn an_unmatchable_path_reports_oasts1506_and_does_not_stop_other_handlers() {
        let document = r#"
openapi: 3.1.0
info: { title: Paths, version: 1.0.0 }
paths:
  /bad*path:
    get: { operationId: badPath, responses: { "204": { description: ok } } }
  /good:
    get: { operationId: goodPath, responses: { "204": { description: ok } } }
"#;
        let (files, diagnostics) = generate_with_diagnostics(document, MSW_CONFIG);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_UNMATCHABLE_PATH)
        );
        assert!(
            files
                .iter()
                .all(|file| file.relative_path != "msw/handlers/badpath.ts")
        );
        generated(&files, "msw/handlers/goodpath.ts");
    }

    fn literal(text: &str) -> Segment {
        Segment {
            parts: vec![SegmentPart::Literal(text.to_owned())],
        }
    }

    fn param(name: &str) -> Segment {
        Segment {
            parts: vec![SegmentPart::Param(name.to_owned())],
        }
    }

    fn pattern_of(segments: &[Segment]) -> String {
        path_pattern(segments, &SourceRef::default()).expect("pattern is representable")
    }

    #[test]
    fn a_plain_template_becomes_a_colon_pattern() {
        assert_eq!(
            pattern_of(&[literal("pets"), param("petId")]),
            "/pets/:petId([^/]{0,})"
        );
    }

    #[test]
    fn the_root_path_keeps_a_single_slash() {
        assert_eq!(pattern_of(&[]), "/");
    }

    #[test]
    fn a_mixed_segment_concatenates_its_parts() {
        // A segment is not always one whole part: `/v{version}.json` is literal, param, literal.
        let segment = Segment {
            parts: vec![
                SegmentPart::Literal("v".to_owned()),
                SegmentPart::Param("version".to_owned()),
                SegmentPart::Literal(".json".to_owned()),
            ],
        };
        assert_eq!(pattern_of(&[segment]), "/v:version([^/]{0,}).json");
    }

    #[test]
    fn path_to_regexp_syntax_in_a_literal_is_escaped() {
        // Unescaped, `+` and `(` make handler registration throw and `?`/`:` capture the wrong
        // requests. Each one is legal in an OpenAPI path.
        assert_eq!(pattern_of(&[literal("a+b")]), "/a\\+b");
        assert_eq!(pattern_of(&[literal("a(b)c")]), "/a\\(b\\)c");
        assert_eq!(pattern_of(&[literal("a?b")]), "/a\\?b");
        assert_eq!(pattern_of(&[literal("pet:search")]), "/pet\\:search");
        assert_eq!(pattern_of(&[literal("a\\b")]), "/a\\\\b");
    }

    #[test]
    fn an_unescapable_wildcard_in_a_literal_is_a_diagnostic() {
        let diagnostic = path_pattern(&[literal("a*b")], &SourceRef::default())
            .expect_err("a literal asterisk has no representable matcher");
        assert_eq!(diagnostic.code, CODE_UNMATCHABLE_PATH);
        assert!(diagnostic.message.contains("a*b"));
    }

    #[test]
    fn a_parameter_name_that_is_not_an_identifier_is_respelled() {
        // `:pet-id` is accepted by path-to-regexp's parser and then never matches anything, which
        // surfaces as an unhandled request rather than an error. The generated token matches.
        assert_eq!(
            pattern_of(&[literal("pets"), param("pet-id")]),
            "/pets/:oastsParam0([^/]{0,})"
        );
        assert_eq!(
            pattern_of(&[literal("pets"), param("pet.id"), param("ok_1")]),
            "/pets/:oastsParam0([^/]{0,})/:ok_1([^/]{0,})"
        );
    }

    #[test]
    fn respelt_parameter_tokens_stay_unique_within_one_path() {
        // Two wire names that would normalize alike must not collide into one token.
        let rendered = pattern_of(&[param("a-b"), param("a.b")]);
        assert_eq!(rendered, "/:oastsParam0([^/]{0,})/:oastsParam1([^/]{0,})");
    }

    #[test]
    fn a_digit_leading_parameter_name_is_left_alone() {
        // Measured against the matcher: path-to-regexp accepts a leading digit, so re-spelling it
        // would churn the pattern for no reason.
        assert_eq!(pattern_of(&[param("1id")]), "/:1id([^/]{0,})");
    }

    #[test]
    fn no_trailing_slash_is_ever_emitted() {
        // A pattern ending in a slash does not match a request without one; a bare pattern matches
        // both spellings.
        for rendered in [
            pattern_of(&[literal("pets")]),
            pattern_of(&[literal("pets"), param("petId")]),
        ] {
            assert!(!rendered.ends_with('/'), "{rendered} ends with a slash");
        }
    }

    #[test]
    fn the_kernel_never_imports_the_client_runtime() {
        let files = generate(MINIMAL, MSW_CONFIG);
        let runtime = files
            .iter()
            .find(|file| file.relative_path == "msw/runtime.ts")
            .expect("the msw kernel is emitted");
        // The whole point of the local kernel: a consumer may enable msw without the client, so an
        // import reaching outside the msw directory would emit a module that does not exist.
        for line in runtime.content.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("import ") || trimmed.starts_with("export ") {
                assert!(
                    !trimmed.contains("../"),
                    "the msw kernel reached outside its own directory: {line}"
                );
            }
        }
    }
}
