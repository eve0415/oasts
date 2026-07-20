//! Client artifact planning over the normalized OpenAPI IR.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

use crate::config::{ResolvedBaseUrl, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    EncodingHeader, EncodingObject, Ir, MediaType, NamedSecurityScheme, OasVersion, Operation,
    ParamLocation, ParamStyle, PrimitiveType, ResponseStatus, SchemaNode, SecKind,
    SecurityRequirement, ServerEntry, SourceRef,
};
use crate::semantic::Analyzed;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientModel {
    pub operations: Vec<OperationPlan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlan {
    pub operation_index: usize,
    pub param_plans: Vec<ParameterPlan>,
    pub body_plan: Option<BodyPlan>,
    pub response_table: Vec<ResponsePlan>,
    pub accept: Option<String>,
    pub base_url: BaseUrlPlan,
    pub effective_security: Vec<SecurityRequirement>,
    pub credential_headers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterPlan {
    pub name: String,
    pub schema: SchemaNode,
    pub resolved: ResolvedParameterSerialization,
    pub source: SourceRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedParameterSerialization {
    pub location: ParamLocation,
    pub style: ParamStyle,
    pub explode: bool,
    pub allow_reserved: bool,
    pub helper: HelperId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperId {
    PathSimple,
    PathSimpleExplode,
    PathLabel,
    PathLabelExplode,
    PathMatrix,
    PathMatrixExplode,
    QueryForm,
    QueryFormExplode,
    QuerySpaceDelimited,
    QueryPipeDelimited,
    QueryDeepObject,
    HeaderSimple,
    HeaderSimpleExplode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyPlan {
    Json {
        media: String,
        schema: Option<SchemaNode>,
        source: SourceRef,
    },
    TopLevelText {
        media: String,
        schema: Option<SchemaNode>,
        source: SourceRef,
    },
    TopLevelBinary {
        media: String,
        schema: Option<SchemaNode>,
        source: SourceRef,
    },
    FormUrlencoded {
        media: String,
        fields: Vec<FormFieldPlan>,
        source: SourceRef,
    },
    Multipart {
        media: String,
        fields: Vec<FormFieldPlan>,
        source: SourceRef,
    },
    ContentTypeDiscriminated {
        arms: Vec<(String, BodyPlan)>,
        all_concrete: bool,
    },
}

impl BodyPlan {
    #[must_use]
    pub fn multipart_fields(&self) -> Option<&[FormFieldPlan]> {
        if let Self::Multipart { fields, .. } = self {
            Some(fields)
        } else {
            None
        }
    }

    #[must_use]
    pub fn discriminated_arms(&self) -> Option<(&[(String, Self)], bool)> {
        if let Self::ContentTypeDiscriminated { arms, all_concrete } = self {
            Some((arms, *all_concrete))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormFieldPlan {
    pub name: String,
    pub required: bool,
    pub schema: SchemaNode,
    pub serialization: FieldSerializationPlan,
    pub wrapper: FieldWrapperPlan,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldSerializationPlan {
    Style {
        style: ParamStyle,
        explode: bool,
        allow_reserved: bool,
        encoding_source: SourceRef,
    },
    Content {
        media: PartMediaPlan,
        caller_headers: Vec<CallerHeaderPlan>,
        content_transfer_encoding: Option<String>,
        encoding_source: Option<SourceRef>,
    },
}

impl FieldSerializationPlan {
    #[must_use]
    pub fn content_media(&self) -> Option<&PartMediaPlan> {
        if let Self::Content { media, .. } = self {
            Some(media)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartMediaPlan {
    pub values: Vec<String>,
    pub all_concrete: bool,
    pub binary_upload: bool,
    pub declared: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerHeaderPlan {
    pub name: String,
    pub required: bool,
    pub schema: SchemaNode,
    pub source: SourceRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderInputRequirement {
    None,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldWrapperPlan {
    pub wrapped: bool,
    pub content_type_literal: bool,
    pub headers: HeaderInputRequirement,
    pub filename: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponsePlan {
    pub match_key: String,
    pub kind: ResponseMatchKind,
    pub media: Vec<ResponseMediaPlan>,
    pub payload: PayloadDisposition,
    pub content_type_discriminated: bool,
    pub source: SourceRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseMatchKind {
    Exact,
    Range,
    Default,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMediaPlan {
    pub media: String,
    pub decoder: DecoderClass,
    /// Wildcard keys classify the actual concrete response media at runtime.
    pub runtime_classified: bool,
    pub schema: Option<SchemaNode>,
    pub streaming_marked: bool,
    pub source: SourceRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoderClass {
    Streaming,
    Json,
    Xml,
    Multipart,
    Text,
    Binary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadDisposition {
    NoPayload,
    StaticBodyless,
    Payload { schemas: Vec<Option<SchemaNode>> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseUrlPlan {
    Runtime,
    Literal {
        value: String,
    },
    Server {
        index: u32,
        servers: Vec<ServerEntry>,
    },
}

/// Builds one client operation plan per normalized IR operation.
#[must_use]
pub fn build_client_model(
    analyzed: &Analyzed,
    config: &ResolvedConfig,
    sink: &mut DiagnosticSink,
) -> ClientModel {
    let client = config
        .client
        .as_ref()
        .expect("the client model runs only when the client artifact is enabled");
    let projector = PrimitiveDomainProjector::new(&analyzed.ir);
    let operations = analyzed
        .ir
        .operations
        .iter()
        .enumerate()
        .map(|(operation_index, operation)| {
            let effective_security = operation
                .security
                .as_ref()
                .unwrap_or(&analyzed.ir.root_security)
                .clone();
            let effective_servers = if operation.servers.is_empty() {
                analyzed.ir.root_servers.clone()
            } else {
                operation.servers.clone()
            };
            let base_url = match &client.base_url {
                ResolvedBaseUrl::Runtime => BaseUrlPlan::Runtime,
                ResolvedBaseUrl::Literal { value } => BaseUrlPlan::Literal {
                    value: value.clone(),
                },
                ResolvedBaseUrl::Server { index } => BaseUrlPlan::Server {
                    index: *index,
                    servers: effective_servers,
                },
            };
            diagnose_parameters(operation, &projector, sink);
            diagnose_security(operation, &effective_security, &analyzed.ir, sink);
            diagnose_base_url(operation, &base_url, sink);
            if let Some(body) = &operation.request_body {
                diagnose_request_media(&body.media_types, &projector, sink);
                for media in &body.media_types {
                    diagnose_form_media(media, &projector, sink);
                }
            }
            let param_plans = operation
                .parameters
                .iter()
                .filter(|parameter| parameter.location != ParamLocation::Cookie)
                .map(parameter_plan)
                .collect();
            let body_plan = operation
                .request_body
                .as_ref()
                .and_then(|body| build_body_plan(&body.media_types, &projector));
            let response_table = response_table(operation, &projector, sink);
            let accept =
                build_accept(operation.responses.iter().flat_map(|response| {
                    response.media_types.iter().map(|media| media.name.as_str())
                }));
            OperationPlan {
                operation_index,
                param_plans,
                body_plan,
                response_table,
                accept,
                base_url,
                credential_headers: credential_headers(&effective_security, &analyzed.ir),
                effective_security,
            }
        })
        .collect();
    ClientModel { operations }
}

fn parameter_plan(parameter: &crate::ir::Param) -> ParameterPlan {
    let style = parameter.style.unwrap_or(match parameter.location {
        ParamLocation::Query => ParamStyle::Form,
        ParamLocation::Path | ParamLocation::Header | ParamLocation::Cookie => ParamStyle::Simple,
    });
    let explode = parameter.explode.unwrap_or(style == ParamStyle::Form);
    let helper = helper_id(parameter.location, style, explode);
    ParameterPlan {
        name: parameter.name.clone(),
        schema: parameter.schema.clone(),
        resolved: ResolvedParameterSerialization {
            location: parameter.location,
            style,
            explode,
            allow_reserved: parameter.allow_reserved,
            helper,
        },
        source: parameter.source.clone(),
    }
}

fn helper_id(location: ParamLocation, style: ParamStyle, explode: bool) -> HelperId {
    match (location, style, explode) {
        (ParamLocation::Path, ParamStyle::Simple, false) => HelperId::PathSimple,
        (ParamLocation::Path, ParamStyle::Simple, true) => HelperId::PathSimpleExplode,
        (ParamLocation::Path, ParamStyle::Label, false) => HelperId::PathLabel,
        (ParamLocation::Path, ParamStyle::Label, true) => HelperId::PathLabelExplode,
        (ParamLocation::Path, ParamStyle::Matrix, false) => HelperId::PathMatrix,
        (ParamLocation::Path, ParamStyle::Matrix, true) => HelperId::PathMatrixExplode,
        (ParamLocation::Query, ParamStyle::Form, false) => HelperId::QueryForm,
        (ParamLocation::Query, ParamStyle::Form, true) => HelperId::QueryFormExplode,
        (ParamLocation::Query, ParamStyle::SpaceDelimited, _) => HelperId::QuerySpaceDelimited,
        (ParamLocation::Query, ParamStyle::PipeDelimited, _) => HelperId::QueryPipeDelimited,
        (ParamLocation::Query, ParamStyle::DeepObject, _) => HelperId::QueryDeepObject,
        (ParamLocation::Header, ParamStyle::Simple, false) => HelperId::HeaderSimple,
        (ParamLocation::Header, ParamStyle::Simple, true) => HelperId::HeaderSimpleExplode,
        _ => match location {
            ParamLocation::Path => HelperId::PathSimple,
            ParamLocation::Query => HelperId::QueryForm,
            ParamLocation::Header => HelperId::HeaderSimple,
            ParamLocation::Cookie => HelperId::HeaderSimple,
        },
    }
}

fn build_body_plan(
    media_types: &[MediaType],
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<BodyPlan> {
    if media_types.is_empty() {
        return None;
    }
    let discriminated = media_types.len() > 1 || !is_concrete_media(&media_types[0].name);
    if discriminated {
        return Some(BodyPlan::ContentTypeDiscriminated {
            arms: media_types
                .iter()
                .map(|media| (media.name.clone(), body_plan_for_media(media, projector)))
                .collect(),
            all_concrete: media_types
                .iter()
                .all(|media| is_concrete_media(&media.name)),
        });
    }
    Some(body_plan_for_media(&media_types[0], projector))
}

fn body_plan_for_media(media: &MediaType, projector: &PrimitiveDomainProjector<'_>) -> BodyPlan {
    let schema = media.schema_present.then(|| media.schema.clone());
    if is_json(&media.name) {
        BodyPlan::Json {
            media: media.name.clone(),
            schema,
            source: media.source.clone(),
        }
    } else if media.name == "application/x-www-form-urlencoded" {
        BodyPlan::FormUrlencoded {
            media: media.name.clone(),
            fields: form_fields(media, false, projector),
            source: media.source.clone(),
        }
    } else if media.name.starts_with("multipart/") {
        BodyPlan::Multipart {
            media: media.name.clone(),
            fields: form_fields(media, true, projector),
            source: media.source.clone(),
        }
    } else if media.name.starts_with("text/") && !is_xml(&media.name) {
        BodyPlan::TopLevelText {
            media: media.name.clone(),
            schema,
            source: media.source.clone(),
        }
    } else {
        BodyPlan::TopLevelBinary {
            media: media.name.clone(),
            schema,
            source: media.source.clone(),
        }
    }
}

fn form_fields(
    media: &MediaType,
    multipart: bool,
    projector: &PrimitiveDomainProjector<'_>,
) -> Vec<FormFieldPlan> {
    let Some(SchemaNode::Object { properties, .. }) = projector.resolve_schema(&media.schema)
    else {
        return Vec::new();
    };
    properties
        .iter()
        .map(|(name, schema, meta)| {
            let encoding = media
                .encodings
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, encoding)| encoding);
            field_plan(
                name,
                schema,
                meta.required,
                encoding,
                media,
                multipart,
                projector,
            )
        })
        .collect()
}

fn field_plan(
    name: &str,
    schema: &SchemaNode,
    required: bool,
    encoding: Option<&EncodingObject>,
    media: &MediaType,
    multipart: bool,
    projector: &PrimitiveDomainProjector<'_>,
) -> FormFieldPlan {
    let style_applicable = encoding.is_some_and(|encoding| {
        (!multipart || media.oas_version == OasVersion::V3_1)
            && (encoding.style.is_some()
                || encoding.explode.is_some()
                || encoding.allow_reserved_explicit)
    });
    let (serialization, wrapper) = if style_applicable {
        let encoding = encoding.expect("style applicability requires an Encoding Object");
        let style = encoding.style.unwrap_or(ParamStyle::Form);
        (
            FieldSerializationPlan::Style {
                style,
                explode: encoding.explode.unwrap_or(style == ParamStyle::Form),
                allow_reserved: encoding.allow_reserved,
                encoding_source: encoding.source.clone(),
            },
            FieldWrapperPlan {
                wrapped: false,
                content_type_literal: true,
                headers: HeaderInputRequirement::None,
                filename: false,
            },
        )
    } else {
        let (part_media, caller_headers, implicit_cte, encoding_source) =
            content_field_parts(schema, encoding, media.oas_version, projector);
        let headers = if caller_headers.iter().any(|header| header.required) {
            HeaderInputRequirement::Required
        } else if caller_headers.is_empty() {
            HeaderInputRequirement::None
        } else {
            HeaderInputRequirement::Optional
        };
        let wrapped = part_media.values.len() > 1
            || !part_media.all_concrete
            || headers != HeaderInputRequirement::None;
        let filename = part_media.binary_upload;
        (
            FieldSerializationPlan::Content {
                media: part_media.clone(),
                caller_headers,
                content_transfer_encoding: implicit_cte,
                encoding_source,
            },
            FieldWrapperPlan {
                wrapped,
                content_type_literal: part_media.all_concrete,
                headers,
                filename,
            },
        )
    };
    FormFieldPlan {
        name: name.to_owned(),
        required,
        schema: schema.clone(),
        serialization,
        wrapper,
        source: meta_source(schema).clone(),
    }
}

fn content_field_parts(
    schema: &SchemaNode,
    encoding: Option<&EncodingObject>,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> (
    PartMediaPlan,
    Vec<CallerHeaderPlan>,
    Option<String>,
    Option<SourceRef>,
) {
    let (values, binary_upload, declared) = encoding
        .and_then(|encoding| encoding.content_type.as_ref())
        .map_or_else(
            || {
                let (media, binary) = default_part_media(schema, version, projector);
                (vec![media], binary, false)
            },
            |values| {
                (
                    values
                        .iter()
                        .map(|value| {
                            parse_declared_media(value)
                                .map_or_else(|()| value.clone(), |parsed| parsed.canonical)
                        })
                        .collect(),
                    false,
                    true,
                )
            },
        );
    let implicit_cte = (version == OasVersion::V3_1)
        .then(|| schema.meta().content_encoding.clone())
        .flatten();
    let caller_headers = encoding
        .map(|encoding| {
            encoding
                .headers
                .iter()
                .filter(|(name, _)| {
                    let lower = name.to_ascii_lowercase();
                    lower == "content-transfer-encoding" && implicit_cte.is_none()
                })
                .map(|(name, header)| caller_header(name, header))
                .collect()
        })
        .unwrap_or_default();
    let all_concrete = values
        .iter()
        .all(|value| parse_declared_media(value).is_ok_and(|parsed| parsed.concrete));
    (
        PartMediaPlan {
            values,
            all_concrete,
            binary_upload,
            declared,
        },
        caller_headers,
        implicit_cte,
        encoding.map(|encoding| encoding.source.clone()),
    )
}

fn caller_header(name: &str, header: &EncodingHeader) -> CallerHeaderPlan {
    CallerHeaderPlan {
        name: name.to_owned(),
        required: header.required,
        schema: header.schema.clone(),
        source: header.source.clone(),
    }
}

fn default_part_media(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> (String, bool) {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    match resolved {
        SchemaNode::Ref { .. } => ("application/octet-stream".to_owned(), false),
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            meta,
            ..
        } if version == OasVersion::V3_1 && meta.content_encoding.is_some() => {
            ("application/octet-stream".to_owned(), false)
        }
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            ..
        } if version == OasVersion::V3_0 && format.as_deref() == Some("binary") => {
            ("application/octet-stream".to_owned(), true)
        }
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            ..
        } if version == OasVersion::V3_0 && format.as_deref() == Some("byte") => {
            ("application/octet-stream".to_owned(), false)
        }
        SchemaNode::Object { .. } | SchemaNode::Tuple { .. } => {
            ("application/json".to_owned(), false)
        }
        SchemaNode::Array { items, .. } => default_part_media(items, version, projector),
        SchemaNode::Any { .. } | SchemaNode::Finite { .. } if version == OasVersion::V3_1 => {
            ("application/octet-stream".to_owned(), true)
        }
        _ if projector.project(resolved) == Projection::Known(Domain::OBJECT) => {
            ("application/json".to_owned(), false)
        }
        _ => ("text/plain".to_owned(), false),
    }
}

fn response_table(
    operation: &crate::ir::Operation,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) -> Vec<ResponsePlan> {
    let mut responses = operation.responses.iter().collect::<Vec<_>>();
    responses.sort_by(|left, right| {
        response_sort_key(&left.status).cmp(&response_sort_key(&right.status))
    });
    responses
        .into_iter()
        .map(|response| {
            let (match_key, kind) = match &response.status {
                ResponseStatus::Exact(value) => (value.clone(), ResponseMatchKind::Exact),
                ResponseStatus::Range(value) => (value.clone(), ResponseMatchKind::Range),
                ResponseStatus::Default => ("default".to_owned(), ResponseMatchKind::Default),
            };
            let media = response
                .media_types
                .iter()
                .map(|media| ResponseMediaPlan {
                    media: media.name.clone(),
                    decoder: classify_response_media(media),
                    runtime_classified: !is_concrete_media(&media.name),
                    schema: media.schema_present.then(|| media.schema.clone()),
                    streaming_marked: media.streaming_marked,
                    source: media.source.clone(),
                })
                .collect::<Vec<_>>();
            let static_bodyless = operation.method.eq_ignore_ascii_case("head")
                || matches!(
                    &response.status,
                    ResponseStatus::Exact(value) if matches!(value.as_str(), "204" | "205" | "304")
                );
            diagnose_response(response, static_bodyless, projector, sink);
            let payload = if media.is_empty() {
                PayloadDisposition::NoPayload
            } else if static_bodyless {
                PayloadDisposition::StaticBodyless
            } else {
                PayloadDisposition::Payload {
                    schemas: media.iter().map(|entry| entry.schema.clone()).collect(),
                }
            };
            let content_type_discriminated = media.len() > 1
                || media
                    .first()
                    .is_some_and(|entry| !is_concrete_media(&entry.media));
            ResponsePlan {
                match_key,
                kind,
                media,
                payload,
                content_type_discriminated,
                source: response.source.clone(),
            }
        })
        .collect()
}

fn diagnose_parameters(
    operation: &Operation,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    for parameter in &operation.parameters {
        if parameter.location == ParamLocation::Cookie {
            sink.push(source_diagnostic(
                "OASTS1410",
                format!(
                    "cookie parameter '{}' cannot be generated for a Fetch client",
                    parameter.name
                ),
                &parameter.source,
                Severity::Error,
            ));
            continue;
        }
        if parameter.location == ParamLocation::Header && forbidden_header_name(&parameter.name) {
            sink.push(source_diagnostic(
                "OASTS1411",
                format!(
                    "header parameter '{}' is unconditionally forbidden by Fetch",
                    parameter.name
                ),
                &parameter.source,
                Severity::Error,
            ));
        }
        let resolved = parameter_plan(parameter).resolved;
        if invalid_style_combination(
            resolved.location,
            resolved.style,
            resolved.explode,
            projector.project(&parameter.schema),
        ) {
            sink.push(source_diagnostic(
                "OASTS1419",
                format!(
                    "parameter '{}' has an unsupported {:?} serialization combination",
                    parameter.name, resolved.style
                ),
                &parameter.source,
                Severity::Error,
            ));
        }
    }
}

fn invalid_style_combination(
    location: ParamLocation,
    style: ParamStyle,
    explode: bool,
    projection: Projection,
) -> bool {
    let legal = match location {
        ParamLocation::Path => matches!(
            style,
            ParamStyle::Matrix | ParamStyle::Label | ParamStyle::Simple
        ),
        ParamLocation::Query => matches!(
            style,
            ParamStyle::Form
                | ParamStyle::SpaceDelimited
                | ParamStyle::PipeDelimited
                | ParamStyle::DeepObject
        ),
        ParamLocation::Header => style == ParamStyle::Simple,
        ParamLocation::Cookie => false,
    };
    if !legal {
        return true;
    }
    match (style, projection) {
        (ParamStyle::SpaceDelimited | ParamStyle::PipeDelimited, Projection::Known(domain)) => {
            explode || domain != Domain::ARRAY
        }
        (ParamStyle::DeepObject, Projection::Known(domain)) => !explode || domain != Domain::OBJECT,
        (
            ParamStyle::SpaceDelimited | ParamStyle::PipeDelimited | ParamStyle::DeepObject,
            Projection::Unsupported,
        ) => false,
        _ => false,
    }
}

fn diagnose_security(
    operation: &Operation,
    security: &[SecurityRequirement],
    ir: &Ir,
    sink: &mut DiagnosticSink,
) {
    let reachable = reachable_schemes(security, ir);
    for scheme in &reachable {
        if let SecKind::ApiKey {
            location: ParamLocation::Header,
            name,
        } = &scheme.kind
        {
            if forbidden_header_name(name) {
                sink.push(source_diagnostic(
                    "OASTS1411",
                    format!(
                        "header API key '{}' uses Fetch-forbidden header '{}'",
                        scheme.name, name
                    ),
                    &scheme.source,
                    Severity::Error,
                ));
            }
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "accept" | "content-type"
            ) {
                sink.push(source_diagnostic(
                    "OASTS1412",
                    format!(
                        "header API key '{}' collides with operation-owned header '{}'",
                        scheme.name, name
                    ),
                    &scheme.source,
                    Severity::Error,
                ));
            }
        }
        if let Some((location, key)) = security_wire_key(scheme) {
            for parameter in operation
                .parameters
                .iter()
                .filter(|parameter| parameter.location != ParamLocation::Cookie)
            {
                if parameter.location == location
                    && wire_names_equal(location, &parameter.name, &key)
                {
                    sink.push(source_diagnostic(
                        "OASTS1413",
                        format!(
                            "security scheme '{}' collides with parameter '{}' at the same wire key",
                            scheme.name, parameter.name
                        ),
                        &scheme.source,
                        Severity::Error,
                    ));
                }
            }
        }
    }
    for alternative in security {
        let schemes = alternative
            .iter()
            .filter_map(|(name, _)| {
                ir.security_schemes
                    .iter()
                    .find(|scheme| &scheme.name == name)
            })
            .collect::<Vec<_>>();
        for (index, left) in schemes.iter().enumerate() {
            let Some((left_location, left_key)) = security_wire_key(left) else {
                continue;
            };
            for right in &schemes[index + 1..] {
                let Some((right_location, right_key)) = security_wire_key(right) else {
                    continue;
                };
                if left_location == right_location
                    && wire_names_equal(left_location, &left_key, &right_key)
                {
                    sink.push(source_diagnostic(
                        "OASTS1413",
                        format!(
                            "AND security alternative maps incompatible schemes '{}' and '{}' to one wire key",
                            left.name, right.name
                        ),
                        &right.source,
                        Severity::Error,
                    ));
                }
            }
        }
    }
    if security.iter().any(|alternative| !alternative.is_empty()) {
        let name = operation.operation_id.as_deref().map_or_else(
            || {
                format!(
                    "{} {}",
                    operation.method.to_ascii_uppercase(),
                    operation.source.display()
                )
            },
            str::to_owned,
        );
        sink.push(source_diagnostic(
            "OASTS1430",
            format!(
                "operation '{name}' requires authentication, which is not yet supported in this build"
            ),
            &operation.source,
            Severity::Error,
        ));
    }
}

fn reachable_schemes<'ir>(
    security: &[SecurityRequirement],
    ir: &'ir Ir,
) -> Vec<&'ir NamedSecurityScheme> {
    let names = security
        .iter()
        .flatten()
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    names
        .into_iter()
        .filter_map(|name| {
            ir.security_schemes
                .iter()
                .find(|scheme| &scheme.name == name)
        })
        .collect()
}

fn security_wire_key(scheme: &NamedSecurityScheme) -> Option<(ParamLocation, String)> {
    match &scheme.kind {
        SecKind::ApiKey { location, name } => Some((*location, name.clone())),
        SecKind::Http { .. } | SecKind::OAuth2 | SecKind::OpenIdConnect => {
            Some((ParamLocation::Header, "authorization".to_owned()))
        }
        SecKind::MutualTls | SecKind::Other => None,
    }
}

fn wire_names_equal(location: ParamLocation, left: &str, right: &str) -> bool {
    if location == ParamLocation::Header {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn forbidden_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("proxy-")
        || lower.starts_with("sec-")
        || matches!(
            lower.as_str(),
            "accept-charset"
                | "accept-encoding"
                | "access-control-request-headers"
                | "access-control-request-method"
                | "connection"
                | "content-length"
                | "cookie"
                | "cookie2"
                | "date"
                | "dnt"
                | "expect"
                | "host"
                | "keep-alive"
                | "origin"
                | "referer"
                | "set-cookie"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "via"
        )
}

fn diagnose_base_url(operation: &Operation, base_url: &BaseUrlPlan, sink: &mut DiagnosticSink) {
    let BaseUrlPlan::Server { index, servers } = base_url else {
        return;
    };
    let index = *index as usize;
    let Some(server) = servers.get(index) else {
        sink.push(source_diagnostic(
            "OASTS1420",
            format!("operation has no effective server at index {index}"),
            &operation.source,
            Severity::Error,
        ));
        return;
    };
    let mut substituted = server.url.clone();
    for (name, variable) in &server.variables {
        substituted = substituted.replace(&format!("{{{name}}}"), &variable.default);
    }
    if !url::Url::parse(&substituted).is_ok_and(|url| !url.cannot_be_a_base()) {
        sink.push(source_diagnostic(
            "OASTS1420",
            format!(
                "server URL '{}' is not absolute after substituting declared defaults",
                server.url
            ),
            &server.source,
            Severity::Error,
        ));
    }
}

fn diagnose_form_media(
    media: &MediaType,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    let multipart = media.name.starts_with("multipart/");
    if !multipart && media.name != "application/x-www-form-urlencoded" {
        return;
    }
    let Some(SchemaNode::Object { properties, .. }) = projector.resolve_schema(&media.schema)
    else {
        return;
    };
    for (name, schema, property) in properties {
        if multipart && contains_control(name) {
            sink.push(source_diagnostic(
                "OASTS1414",
                format!(
                    "multipart field name {name:?} contains a control byte and cannot be represented"
                ),
                &property.source,
                Severity::Error,
            ));
        }
        let encoding = media
            .encodings
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, encoding)| encoding);
        let style_applicable = encoding.is_some_and(|encoding| {
            (!multipart || media.oas_version == OasVersion::V3_1)
                && (encoding.style.is_some()
                    || encoding.explode.is_some()
                    || encoding.allow_reserved_explicit)
        });
        if style_applicable {
            let encoding = encoding.expect("style applicability requires an Encoding Object");
            let style = encoding.style.unwrap_or(ParamStyle::Form);
            let explode = encoding.explode.unwrap_or(style == ParamStyle::Form);
            if invalid_style_combination(
                ParamLocation::Query,
                style,
                explode,
                projector.project(schema),
            ) {
                sink.push(source_diagnostic(
                    "OASTS1419",
                    format!(
                        "encoding for field '{name}' has an unsupported {style:?} serialization combination"
                    ),
                    &encoding.source,
                    Severity::Error,
                ));
            }
        } else if let Some(encoding) = encoding
            && let Some(values) = &encoding.content_type
        {
            for value in values {
                if parse_declared_media(value).is_err() {
                    sink.push(source_diagnostic(
                        "OASTS1418",
                        format!(
                            "encoding contentType value {value:?} is malformed or has a control/non-ASCII parameter value"
                        ),
                        &encoding.source,
                        Severity::Error,
                    ));
                }
            }
        }
        if multipart {
            diagnose_multipart_headers(name, schema, encoding, media.oas_version, projector, sink);
        }
    }
}

fn contains_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
}

fn diagnose_multipart_headers(
    field_name: &str,
    schema: &SchemaNode,
    encoding: Option<&EncodingObject>,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    let implicit = (version == OasVersion::V3_1)
        .then(|| schema.meta().content_encoding.as_deref())
        .flatten();
    let implicit_admitted = implicit.is_none_or(admitted_cte);
    if let Some(value) = implicit
        && !implicit_admitted
    {
        sink.push(source_diagnostic(
            "OASTS1415",
            format!(
                "multipart field '{field_name}' declares non-admitted contentEncoding '{value}'"
            ),
            &schema.meta().source,
            Severity::Error,
        ));
    }
    let Some(encoding) = encoding else {
        return;
    };
    for (header_name, header) in &encoding.headers {
        let lower = header_name.to_ascii_lowercase();
        match lower.as_str() {
            "content-type" => {}
            "content-disposition" => {
                let canonical = canonical_content_disposition(field_name);
                if schema_admits_string(&header.schema, &canonical, projector) != Some(true) {
                    sink.push(source_diagnostic(
                        "OASTS1416",
                        format!(
                            "declared Content-Disposition for field '{field_name}' does not admit the encoder-owned value"
                        ),
                        &header.source,
                        Severity::Error,
                    ));
                }
            }
            "content-transfer-encoding" => {
                if let Some(value) = implicit {
                    if implicit_admitted
                        && schema_admits_string(&header.schema, value, projector) != Some(true)
                    {
                        sink.push(source_diagnostic(
                            "OASTS1415",
                            format!(
                                "declared Content-Transfer-Encoding for field '{field_name}' does not admit implicit value '{value}'"
                            ),
                            &header.source,
                            Severity::Error,
                        ));
                    }
                } else if !finite_string_values(&header.schema, projector).is_some_and(|values| {
                    !values.is_empty() && values.iter().all(|value| admitted_cte(value))
                }) {
                    sink.push(source_diagnostic(
                        "OASTS1415",
                        format!(
                            "declared Content-Transfer-Encoding for field '{field_name}' is not restricted to admitted values"
                        ),
                        &header.source,
                        Severity::Error,
                    ));
                }
            }
            _ => sink.push(source_diagnostic(
                "OASTS1417",
                format!(
                    "multipart field '{field_name}' declares non-RFC-7578 header '{header_name}'"
                ),
                &header.source,
                Severity::Error,
            )),
        }
    }
}

fn admitted_cte(value: &str) -> bool {
    matches!(value, "7bit" | "8bit" | "binary")
}

fn canonical_content_disposition(field_name: &str) -> String {
    let escaped = field_name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("form-data; name=\"{escaped}\"")
}

fn schema_admits_string(
    schema: &SchemaNode,
    value: &str,
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<bool> {
    let schema = projector.resolve_schema(schema)?;
    match schema {
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            enum_values,
            const_value,
            ..
        } => Some(string_constraints_admit(
            enum_values.as_deref(),
            const_value.as_ref(),
            value,
        )),
        SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => Some(string_constraints_admit(
            enum_values.as_deref(),
            const_value.as_ref(),
            value,
        )),
        SchemaNode::Any { .. } => Some(true),
        SchemaNode::Never { .. }
        | SchemaNode::Primitive { .. }
        | SchemaNode::Object { .. }
        | SchemaNode::Array { .. }
        | SchemaNode::Tuple { .. } => Some(false),
        SchemaNode::AnyOf { branches, .. } | SchemaNode::OneOf { branches, .. } => branches
            .iter()
            .map(|branch| schema_admits_string(branch, value, projector))
            .try_fold(false, |admitted, branch| {
                branch.map(|branch| admitted || branch)
            }),
        SchemaNode::AllOf { branches, .. } => branches
            .iter()
            .map(|branch| schema_admits_string(branch, value, projector))
            .try_fold(true, |admitted, branch| {
                branch.map(|branch| admitted && branch)
            }),
        SchemaNode::Ref { .. } | SchemaNode::Unknown { .. } => None,
    }
}

fn string_constraints_admit(
    enum_values: Option<&[Value]>,
    const_value: Option<&Value>,
    target: &str,
) -> bool {
    const_value.is_none_or(|value| value.as_str() == Some(target))
        && enum_values
            .is_none_or(|values| values.iter().any(|value| value.as_str() == Some(target)))
}

fn finite_string_values(
    schema: &SchemaNode,
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<Vec<String>> {
    let schema = projector.resolve_schema(schema)?;
    let (enum_values, const_value) = match schema {
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            enum_values,
            const_value,
            ..
        }
        | SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => (enum_values.as_deref(), const_value.as_ref()),
        _ => return None,
    };
    if enum_values.is_none() && const_value.is_none() {
        return None;
    }
    let mut values = enum_values
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if let Some(value) = const_value {
        let Some(value) = value.as_str() else {
            return Some(Vec::new());
        };
        if enum_values.is_some() {
            values.retain(|candidate| candidate == value);
        } else {
            values.insert(value.to_owned());
        }
    }
    Some(values.into_iter().collect())
}

fn diagnose_request_media(
    media_types: &[MediaType],
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    for media in media_types {
        if media.streaming_marked || media.name == "text/event-stream" {
            sink.push(source_diagnostic(
                "OASTS1402",
                format!(
                    "request body media '{}' requires streaming support, which is not yet available",
                    media.name
                ),
                &media.source,
                Severity::Error,
            ));
        } else if is_xml(&media.name) {
            sink.push(source_diagnostic(
                "OASTS1403",
                format!(
                    "request body media '{}' is XML, which Oasts does not support",
                    media.name
                ),
                &media.source,
                Severity::Error,
            ));
        } else if media.name.starts_with("text/")
            && media.schema_present
            && projection_excludes_string(projector.project(&media.schema))
        {
            sink.push(source_diagnostic(
                "OASTS1405",
                format!(
                    "top-level text request media '{}' requires a schema whose primitive projection contains string",
                    media.name
                ),
                &media.source,
                Severity::Error,
            ));
        }
    }
}

fn diagnose_response(
    response: &crate::ir::ResponseEntry,
    static_bodyless: bool,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    if matches!(
        &response.status,
        ResponseStatus::Exact(value) if value.starts_with('1')
    ) || matches!(&response.status, ResponseStatus::Range(value) if value == "1XX")
    {
        sink.push(source_diagnostic(
            "OASTS1401",
            format!(
                "response key '{}' is informational and cannot be observed through Fetch",
                response_status_name(&response.status)
            ),
            &response.source,
            Severity::Error,
        ));
    }
    for media in &response.media_types {
        if static_bodyless {
            sink.push(source_diagnostic(
                "OASTS1406",
                format!(
                    "response key '{}' is statically bodyless but declares media '{}'",
                    response_status_name(&response.status),
                    media.name
                ),
                &media.source,
                Severity::Warning,
            ));
            continue;
        }
        match classify_response_media(media) {
            DecoderClass::Streaming => sink.push(source_diagnostic(
                "OASTS1402",
                format!(
                    "response media '{}' requires streaming support, which is not yet available",
                    media.name
                ),
                &media.source,
                Severity::Error,
            )),
            DecoderClass::Xml => sink.push(source_diagnostic(
                "OASTS1403",
                format!(
                    "response media '{}' is XML, which Oasts does not support",
                    media.name
                ),
                &media.source,
                Severity::Error,
            )),
            DecoderClass::Multipart => sink.push(source_diagnostic(
                "OASTS1404",
                format!(
                    "multipart response media '{}' is not supported",
                    media.name
                ),
                &media.source,
                Severity::Error,
            )),
            DecoderClass::Text
                if media.schema_present
                    && projection_excludes_string(projector.project(&media.schema)) =>
            {
                sink.push(source_diagnostic(
                    "OASTS1405",
                    format!(
                        "text response media '{}' requires a schema whose primitive projection contains string",
                        media.name
                    ),
                    &media.source,
                    Severity::Error,
                ));
            }
            DecoderClass::Json | DecoderClass::Text | DecoderClass::Binary => {}
        }
    }
}

fn response_status_name(status: &ResponseStatus) -> &str {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value,
        ResponseStatus::Default => "default",
    }
}

fn projection_excludes_string(projection: Projection) -> bool {
    matches!(projection, Projection::Known(domain) if !domain.contains(Domain::STRING))
}

fn source_diagnostic(
    code: &'static str,
    message: impl Into<String>,
    source: &SourceRef,
    severity: Severity,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::input(code, message)
        .with_source(&source.source_id)
        .with_json_pointer(&source.json_pointer);
    diagnostic.severity = severity;
    if let (Some(line), Some(col)) = (source.line, source.col) {
        diagnostic = diagnostic.with_location(line, col);
    }
    diagnostic
}

fn response_sort_key(status: &ResponseStatus) -> (u8, u16) {
    match status {
        ResponseStatus::Exact(value) => (0, value.parse().unwrap_or(u16::MAX)),
        ResponseStatus::Range(value) => (
            1,
            value
                .as_bytes()
                .first()
                .map_or(u16::MAX, |digit| u16::from(*digit)),
        ),
        ResponseStatus::Default => (2, 0),
    }
}

fn classify_response_media(media: &MediaType) -> DecoderClass {
    if media.streaming_marked || media.name == "text/event-stream" {
        DecoderClass::Streaming
    } else if is_json(&media.name) {
        DecoderClass::Json
    } else if is_xml(&media.name) {
        DecoderClass::Xml
    } else if media.name.starts_with("multipart/") {
        DecoderClass::Multipart
    } else if media.name == "application/x-www-form-urlencoded" || media.name.starts_with("text/") {
        DecoderClass::Text
    } else {
        DecoderClass::Binary
    }
}

struct ParsedDeclaredMedia {
    canonical: String,
    concrete: bool,
}

fn parse_declared_media(input: &str) -> Result<ParsedDeclaredMedia, ()> {
    let segments = split_quoted(input, ';')?;
    let essence = segments.first().copied().ok_or(())?.trim();
    let (media_type, subtype) = essence.split_once('/').ok_or(())?;
    if media_type.is_empty()
        || subtype.is_empty()
        || !media_type.bytes().all(is_tchar)
        || !subtype.bytes().all(is_tchar)
        || media_type == "*" && subtype != "*"
    {
        return Err(());
    }
    let concrete = media_type != "*" && subtype != "*";
    let mut parameters = std::collections::BTreeMap::new();
    for segment in &segments[1..] {
        let segment = segment.trim_matches([' ', '\t']);
        if segment.is_empty() {
            return Err(());
        }
        let (name, raw_value) = segment.split_once('=').ok_or(())?;
        if name != name.trim_matches([' ', '\t'])
            || raw_value != raw_value.trim_matches([' ', '\t'])
            || name.is_empty()
            || !name.bytes().all(is_tchar)
        {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if parameters.contains_key(&name) {
            return Err(());
        }
        let mut value = parse_parameter_value(raw_value)?;
        if name == "charset" {
            value.make_ascii_lowercase();
        }
        parameters.insert(name, value);
    }
    let mut canonical = format!(
        "{}/{}",
        media_type.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    );
    for (name, value) in parameters {
        canonical.push_str("; ");
        canonical.push_str(&name);
        canonical.push('=');
        if !value.is_empty() && value.bytes().all(is_tchar) {
            canonical.push_str(&value);
        } else {
            canonical.push('"');
            for character in value.chars() {
                if matches!(character, '"' | '\\') {
                    canonical.push('\\');
                }
                canonical.push(character);
            }
            canonical.push('"');
        }
    }
    Ok(ParsedDeclaredMedia {
        canonical,
        concrete,
    })
}

fn split_quoted(input: &str, separator: char) -> Result<Vec<&str>, ()> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == separator {
            parts.push(&input[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(());
    }
    parts.push(&input[start..]);
    Ok(parts)
}

fn parse_parameter_value(value: &str) -> Result<String, ()> {
    if !value.is_ascii() {
        return Err(());
    }
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut decoded = String::new();
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                if character.is_ascii_control() {
                    return Err(());
                }
                decoded.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_ascii_control() {
                return Err(());
            } else {
                decoded.push(character);
            }
        }
        if escaped {
            return Err(());
        }
        Ok(decoded)
    } else if !value.is_empty() && value.bytes().all(is_tchar) {
        Ok(value.to_owned())
    } else {
        Err(())
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_json(media: &str) -> bool {
    media == "application/json"
        || media
            .rsplit_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+json"))
}

fn is_xml(media: &str) -> bool {
    matches!(media, "application/xml" | "text/xml")
        || media
            .rsplit_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+xml"))
}

fn is_concrete_media(media: &str) -> bool {
    !media.contains('*')
}

fn build_accept<'a>(declared: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut concrete = BTreeSet::new();
    let mut typed_ranges = BTreeSet::new();
    let mut any = false;
    for media in declared {
        if media == "*/*" {
            any = true;
        } else if media.ends_with("/*") {
            typed_ranges.insert(media);
        } else {
            concrete.insert(media);
        }
    }
    let values = concrete
        .into_iter()
        .chain(typed_ranges)
        .chain(any.then_some("*/*"))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(", "))
}

fn credential_headers(security: &[SecurityRequirement], ir: &Ir) -> Vec<String> {
    let mut headers = BTreeSet::from(["authorization".to_owned()]);
    for (scheme_name, _) in security.iter().flatten() {
        if let Some(scheme) = ir
            .security_schemes
            .iter()
            .find(|scheme| &scheme.name == scheme_name)
            && let SecKind::ApiKey {
                location: ParamLocation::Header,
                name,
            } = &scheme.kind
        {
            headers.insert(name.to_ascii_lowercase());
        }
    }
    headers.into_iter().collect()
}

fn meta_source(schema: &SchemaNode) -> &SourceRef {
    &schema.meta().source
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Domain(u8);

impl Domain {
    const STRING: Self = Self(1 << 0);
    const NUMBER: Self = Self(1 << 1);
    const BOOLEAN: Self = Self(1 << 2);
    const NULL: Self = Self(1 << 3);
    const ARRAY: Self = Self(1 << 4);
    const OBJECT: Self = Self(1 << 5);
    const EMPTY: Self = Self(0);
    const FULL: Self = Self((1 << 6) - 1);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Projection {
    Known(Domain),
    Unsupported,
}

struct PrimitiveDomainProjector<'ir> {
    schemas: HashMap<(String, String), &'ir SchemaNode>,
    domains: HashMap<(String, String), Projection>,
}

impl<'ir> PrimitiveDomainProjector<'ir> {
    fn new(ir: &'ir Ir) -> Self {
        let schemas = ir
            .schemas
            .iter()
            .map(|schema| {
                (
                    (
                        schema.source.source_id.clone(),
                        schema.source.json_pointer.clone(),
                    ),
                    &schema.schema,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut domains = schemas
            .keys()
            .cloned()
            .map(|key| (key, Projection::Known(Domain::FULL)))
            .collect::<HashMap<_, _>>();
        loop {
            let next = schemas
                .iter()
                .map(|(key, schema)| (key.clone(), project_schema(schema, &domains)))
                .collect::<HashMap<_, _>>();
            if next == domains {
                break;
            }
            domains = next;
        }
        Self { schemas, domains }
    }

    fn project(&self, schema: &SchemaNode) -> Projection {
        project_schema(schema, &self.domains)
    }

    fn resolve_schema<'schema>(
        &'schema self,
        schema: &'schema SchemaNode,
    ) -> Option<&'schema SchemaNode>
    where
        'ir: 'schema,
    {
        let mut current = schema;
        let mut seen = BTreeSet::new();
        while let SchemaNode::Ref { target, .. } = current {
            let key = (target.source_id.clone(), target.json_pointer.clone());
            if !seen.insert(key.clone()) {
                return None;
            }
            current = self.schemas.get(&key).copied()?;
        }
        Some(current)
    }
}

fn project_schema(schema: &SchemaNode, refs: &HashMap<(String, String), Projection>) -> Projection {
    let (base, apply_nullable) = match schema {
        SchemaNode::Ref { target, .. } => (
            refs.get(&(target.source_id.clone(), target.json_pointer.clone()))
                .copied()
                .unwrap_or(Projection::Unsupported),
            true,
        ),
        SchemaNode::Primitive {
            ty,
            enum_values,
            const_value,
            ..
        } => {
            let mut declared = match ty {
                PrimitiveType::String => Domain::STRING,
                PrimitiveType::Number | PrimitiveType::Integer => Domain::NUMBER,
                PrimitiveType::Boolean => Domain::BOOLEAN,
                PrimitiveType::Null => Domain::NULL,
            };
            if schema.meta().nullable {
                declared = declared.union(Domain::NULL);
            }
            (
                finite_projection(enum_values.as_deref(), const_value.as_ref())
                    .map_or(Projection::Known(declared), |finite| {
                        intersect_projection(Projection::Known(declared), finite)
                    }),
                false,
            )
        }
        SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => (
            finite_projection(enum_values.as_deref(), const_value.as_ref())
                .unwrap_or(Projection::Known(Domain::FULL)),
            false,
        ),
        SchemaNode::Object { .. } => (Projection::Known(Domain::OBJECT), true),
        SchemaNode::Array { .. } | SchemaNode::Tuple { .. } => {
            (Projection::Known(Domain::ARRAY), true)
        }
        SchemaNode::AllOf { branches, .. } => (
            branches
                .iter()
                .map(|branch| project_schema(branch, refs))
                .reduce(intersect_projection)
                .unwrap_or(Projection::Known(Domain::FULL)),
            true,
        ),
        SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => (
            branches
                .iter()
                .map(|branch| project_schema(branch, refs))
                .reduce(union_projection)
                .unwrap_or(Projection::Known(Domain::EMPTY)),
            true,
        ),
        SchemaNode::Any { .. } => (Projection::Known(Domain::FULL), false),
        SchemaNode::Never { .. } => (Projection::Known(Domain::EMPTY), false),
        SchemaNode::Unknown { .. } => (Projection::Unsupported, false),
    };
    match base {
        Projection::Known(domain) if apply_nullable && schema.meta().nullable => {
            Projection::Known(domain.union(Domain::NULL))
        }
        other => other,
    }
}

fn values_projection(values: &[Value]) -> Projection {
    let mut domain = Domain::EMPTY;
    for value in values {
        domain = domain.union(match value {
            Value::Null => Domain::NULL,
            Value::Bool(_) => Domain::BOOLEAN,
            Value::Number(_) => Domain::NUMBER,
            Value::String(_) => Domain::STRING,
            Value::Array(_) => Domain::ARRAY,
            Value::Object(_) => Domain::OBJECT,
        });
    }
    Projection::Known(domain)
}

fn finite_projection(
    enum_values: Option<&[Value]>,
    const_value: Option<&Value>,
) -> Option<Projection> {
    match (enum_values, const_value) {
        (Some(values), Some(value)) => Some(intersect_projection(
            values_projection(values),
            values_projection(std::slice::from_ref(value)),
        )),
        (Some(values), None) => Some(values_projection(values)),
        (None, Some(value)) => Some(values_projection(std::slice::from_ref(value))),
        (None, None) => None,
    }
}

fn union_projection(left: Projection, right: Projection) -> Projection {
    match (left, right) {
        (Projection::Known(left), Projection::Known(right)) => Projection::Known(left.union(right)),
        _ => Projection::Unsupported,
    }
}

fn intersect_projection(left: Projection, right: Projection) -> Projection {
    match (left, right) {
        (Projection::Known(left), Projection::Known(right)) => {
            Projection::Known(left.intersect(right))
        }
        _ => Projection::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedConfig, load_config_from_json};
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::ir::{
        Ir, MediaType, NamedSchema, NamedSecurityScheme, OasVersion, Operation, ParamLocation,
        ParamStyle, PrimitiveType, ResponseStatus, SchemaMeta, SchemaNode, SchemaRef, SecKind,
        SourceRef,
    };
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::{Analyzed, analyze};

    fn analyzed(document: &Value, client: Value) -> (TempDir, Analyzed, ResolvedConfig) {
        let (temp, analyzed, config, sink) = analyzed_with_diagnostics(document, client);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        (temp, analyzed, config)
    }

    fn analyzed_with_diagnostics(
        document: &Value,
        client: Value,
    ) -> (TempDir, Analyzed, ResolvedConfig, DiagnosticSink) {
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
            "client": client,
            "validation": { "engine": "off", "unchecked": "allow" }
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
        (temp, analyzed, config, sink)
    }

    fn client_diagnostics(document: &Value) -> Vec<Diagnostic> {
        client_diagnostics_with(
            document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        )
    }

    fn client_diagnostics_with(document: &Value, client: Value) -> Vec<Diagnostic> {
        let (_temp, analyzed, config) = analyzed(document, client);
        let mut sink = DiagnosticSink::new();
        let _ = build_client_model(&analyzed, &config, &mut sink);
        sink.into_sorted_vec()
    }

    fn classifier_media(name: &str, streaming_marked: bool) -> MediaType {
        MediaType {
            name: name.to_owned(),
            raw_name: name.to_owned(),
            schema: SchemaNode::Any {
                meta: SchemaMeta::default(),
            },
            schema_present: false,
            examples: Vec::new(),
            encodings: Vec::new(),
            streaming_marked,
            oas_version: OasVersion::V3_1,
            source: SourceRef::new("openapi.json", "/media"),
        }
    }

    fn test_meta(pointer: &str) -> SchemaMeta {
        SchemaMeta {
            source: SourceRef::new("openapi.json", pointer),
            ..SchemaMeta::default()
        }
    }

    fn test_primitive(ty: PrimitiveType, pointer: &str) -> SchemaNode {
        SchemaNode::Primitive {
            ty,
            format: None,
            enum_values: None,
            const_value: None,
            meta: test_meta(pointer),
        }
    }

    #[test]
    fn accept_builder_matches_frozen_vectors() {
        for (declared, expected) in [
            (
                vec!["application/xml", "application/json", "text/plain"],
                Some("application/json, application/xml, text/plain"),
            ),
            (
                vec!["*/*", "text/*", "application/json", "image/*"],
                Some("application/json, image/*, text/*, */*"),
            ),
            (
                vec![
                    "application/json",
                    "application/json",
                    "text/plain",
                    "*/*",
                    "*/*",
                ],
                Some("application/json, text/plain, */*"),
            ),
            (Vec::new(), None),
        ] {
            assert_eq!(
                build_accept(declared.into_iter()),
                expected.map(str::to_owned)
            );
        }
    }

    #[test]
    fn builds_operation_plans_in_ir_order_with_resolved_defaults_and_tables() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{
                "url": "https://{host}/v1",
                "variables": { "host": { "default": "api.example.test" } }
            }],
            "security": [{}],
            "paths": {
                "/first/{id}": {
                    "post": {
                        "operationId": "first",
                        "parameters": [
                            {
                                "name": "id", "in": "path", "required": true,
                                "style": "label", "explode": true,
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "search", "in": "query",
                                "schema": { "type": "array", "items": { "type": "string" } }
                            },
                            {
                                "name": "X-Trace", "in": "header",
                                "schema": { "type": "string" }
                            }
                        ],
                        "requestBody": {
                            "content": {
                                "text/plain": { "schema": { "type": "string" } },
                                "application/json": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "default": {
                                "description": "fallback",
                                "content": { "*/*": { "schema": { "type": "string" } } }
                            },
                            "404": {
                                "description": "missing",
                                "content": { "text/plain": { "schema": { "type": "string" } } }
                            },
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "object" } } }
                            },
                            "2XX": { "description": "range" }
                        }
                    }
                },
                "/second": {
                    "get": { "operationId": "second", "responses": { "204": { "description": "empty" } } }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "server", "index": 0 }
            }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);

        assert_eq!(model.operations.len(), 2);
        let first = &model.operations[0];
        assert_eq!(first.operation_index, 0);
        assert_eq!(first.param_plans.len(), 3);
        assert_eq!(
            first.param_plans[0].resolved,
            ResolvedParameterSerialization {
                location: ParamLocation::Path,
                style: ParamStyle::Label,
                explode: true,
                allow_reserved: false,
                helper: HelperId::PathLabelExplode,
            }
        );
        assert_eq!(
            first.param_plans[1].resolved.helper,
            HelperId::QueryFormExplode
        );
        assert_eq!(first.param_plans[2].resolved.helper, HelperId::HeaderSimple);
        let body = first.body_plan.as_ref().expect("body plan");
        let (arms, all_concrete) = body.discriminated_arms().expect("discriminated body");
        assert!(body.multipart_fields().is_none());
        assert_eq!(
            arms.iter()
                .map(|(media, _)| media.as_str())
                .collect::<Vec<_>>(),
            ["text/plain", "application/json"]
        );
        assert!(all_concrete);
        assert_eq!(
            first
                .response_table
                .iter()
                .map(|entry| (&entry.match_key, entry.kind))
                .collect::<Vec<_>>(),
            [
                (&"200".to_owned(), ResponseMatchKind::Exact),
                (&"404".to_owned(), ResponseMatchKind::Exact),
                (&"2XX".to_owned(), ResponseMatchKind::Range),
                (&"default".to_owned(), ResponseMatchKind::Default),
            ]
        );
        assert_eq!(
            first.accept.as_deref(),
            Some("application/json, text/plain, */*")
        );
        assert!(matches!(
            first.response_table[2].payload,
            PayloadDisposition::NoPayload
        ));
        assert!(first.response_table[3].content_type_discriminated);
        assert!(first.response_table[3].media[0].runtime_classified);
        assert!(
            first.response_table[0]
                .media
                .iter()
                .all(|media| !media.runtime_classified)
        );
        assert!(matches!(
            &first.base_url,
            BaseUrlPlan::Server { index: 0, servers } if servers[0].url == "https://{host}/v1"
        ));
        assert_eq!(first.effective_security, vec![Vec::new()]);
        assert_eq!(first.credential_headers, ["authorization"]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn builds_multipart_field_plans_from_property_order_and_version_defaults() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["meta"],
                                        "properties": {
                                            "meta": { "type": "object" },
                                            "file": { "type": "string", "contentEncoding": "binary" }
                                        }
                                    },
                                    "encoding": {
                                        "meta": { "contentType": "application/json, application/*" },
                                        "file": { "style": "form", "explode": false }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let body = model.operations[0].body_plan.as_ref().expect("body plan");
        let fields = body.multipart_fields().expect("multipart body");
        assert!(body.discriminated_arms().is_none());

        assert_eq!(
            fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["meta", "file"]
        );
        assert!(fields[0].required);
        assert!(fields[0].wrapper.wrapped);
        assert!(!fields[0].wrapper.content_type_literal);
        assert!(matches!(
            fields[0].serialization,
            FieldSerializationPlan::Content { .. }
        ));
        assert!(matches!(
            fields[1].serialization,
            FieldSerializationPlan::Style {
                style: ParamStyle::Form,
                explode: false,
                ..
            }
        ));
        assert!(fields[1].serialization.content_media().is_none());
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn multipart_wrapper_headers_follow_admitted_caller_header_requiredness() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "ignored": { "type": "string" },
                                            "optional": { "type": "string" },
                                            "required": { "type": "string" },
                                            "implicit": { "type": "string", "contentEncoding": "binary" }
                                        }
                                    },
                                    "encoding": {
                                        "ignored": {
                                            "headers": {
                                                "Content-Type": { "schema": { "type": "string" } },
                                                "Content-Disposition": { "schema": { "type": "string" } }
                                            }
                                        },
                                        "optional": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit", "8bit"] } }
                                            }
                                        },
                                        "required": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "required": true, "schema": { "const": "binary" } }
                                            }
                                        },
                                        "implicit": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": {} }
                                            }
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
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let fields = model.operations[0]
            .body_plan
            .as_ref()
            .expect("body plan")
            .multipart_fields()
            .expect("multipart body");

        assert_eq!(fields[0].wrapper.headers, HeaderInputRequirement::None);
        assert!(!fields[0].wrapper.wrapped);
        assert_eq!(fields[1].wrapper.headers, HeaderInputRequirement::Optional);
        assert!(fields[1].wrapper.wrapped);
        assert_eq!(fields[2].wrapper.headers, HeaderInputRequirement::Required);
        assert!(fields[2].wrapper.wrapped);
        assert_eq!(fields[3].wrapper.headers, HeaderInputRequirement::None);
        assert!(!fields[3].wrapper.wrapped);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn part_media_defaults_match_oas30_and_oas31_tables() {
        let document31 = json!({
            "openapi": "3.1.0",
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "typeless": {},
                                            "finiteTypeless": { "enum": ["value"] },
                                            "encoded": { "type": "string", "contentEncoding": "binary" },
                                            "object": { "type": "object" },
                                            "objects": { "type": "array", "items": { "type": "object" } },
                                            "primitive": { "type": "boolean" }
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
        let (_temp, analyzed31, config) = analyzed(
            &document31,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed31, &config, &mut sink);
        let fields = model.operations[0]
            .body_plan
            .as_ref()
            .expect("body plan")
            .multipart_fields()
            .expect("multipart body");
        let media31 = fields
            .iter()
            .map(|field| {
                let media = field.serialization.content_media().expect("content branch");
                (media.values[0].as_str(), media.binary_upload)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            media31,
            [
                ("application/octet-stream", true),
                ("application/octet-stream", true),
                ("application/octet-stream", false),
                ("application/json", false),
                ("application/json", false),
                ("text/plain", false),
            ]
        );

        let document30 = json!({
            "openapi": "3.0.3",
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "binary": { "type": "string", "format": "binary" },
                                            "byte": { "type": "string", "format": "byte" },
                                            "object": { "type": "object" },
                                            "objects": { "type": "array", "items": { "type": "object" } },
                                            "primitive": { "type": "integer" }
                                        }
                                    },
                                    "encoding": {
                                        "binary": { "style": "deepObject" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document30,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let fields = model.operations[0]
            .body_plan
            .as_ref()
            .expect("body plan")
            .multipart_fields()
            .expect("multipart body");
        let media30 = fields
            .iter()
            .map(|field| {
                let media = field
                    .serialization
                    .content_media()
                    .expect("OAS 3.0 multipart ignores style");
                (media.values[0].as_str(), media.binary_upload)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            media30,
            [
                ("application/octet-stream", true),
                ("application/octet-stream", false),
                ("application/json", false),
                ("application/json", false),
                ("text/plain", false),
            ]
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn credential_headers_follow_effective_reachable_security() {
        let document = json!({
            "openapi": "3.1.0",
            "security": [{ "root": [] }],
            "components": {
                "securitySchemes": {
                    "root": { "type": "apiKey", "in": "header", "name": "X-Root" },
                    "first": { "type": "apiKey", "in": "header", "name": "X-Key" },
                    "second": { "type": "apiKey", "in": "header", "name": "x-key" },
                    "query": { "type": "apiKey", "in": "query", "name": "key" }
                }
            },
            "paths": {
                "/security": {
                    "get": {
                        "security": [{ "first": [] }, { "second": [] }, { "query": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);

        assert_eq!(
            model.operations[0].credential_headers,
            ["authorization", "x-key"]
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1430")
        );
    }

    #[test]
    fn client_model_helper_edges_are_total() {
        for (location, style, explode, expected) in [
            (
                ParamLocation::Path,
                ParamStyle::Simple,
                false,
                HelperId::PathSimple,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Simple,
                true,
                HelperId::PathSimpleExplode,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Label,
                false,
                HelperId::PathLabel,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Matrix,
                false,
                HelperId::PathMatrix,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Matrix,
                true,
                HelperId::PathMatrixExplode,
            ),
            (
                ParamLocation::Query,
                ParamStyle::Form,
                false,
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Header,
                ParamStyle::Simple,
                true,
                HelperId::HeaderSimpleExplode,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Form,
                false,
                HelperId::PathSimple,
            ),
            (
                ParamLocation::Query,
                ParamStyle::Simple,
                false,
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Header,
                ParamStyle::Form,
                false,
                HelperId::HeaderSimple,
            ),
            (
                ParamLocation::Cookie,
                ParamStyle::Form,
                false,
                HelperId::HeaderSimple,
            ),
        ] {
            assert_eq!(helper_id(location, style, explode), expected);
        }

        let empty_ir = Ir::default();
        let projector = PrimitiveDomainProjector::new(&empty_ir);
        assert!(build_body_plan(&[], &projector).is_none());
        let any_media = classifier_media("multipart/form-data", false);
        assert!(form_fields(&any_media, true, &projector).is_empty());
        let mut diagnostic_sink = DiagnosticSink::new();
        diagnose_form_media(&any_media, &projector, &mut diagnostic_sink);
        assert!(diagnostic_sink.as_slice().is_empty());
        assert!(invalid_style_combination(
            ParamLocation::Cookie,
            ParamStyle::Form,
            false,
            Projection::Known(Domain::STRING)
        ));
        assert!(!invalid_style_combination(
            ParamLocation::Query,
            ParamStyle::DeepObject,
            true,
            Projection::Unsupported
        ));

        let unresolved = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "missing.json".to_owned(),
                json_pointer: "/Missing".to_owned(),
            },
            meta: test_meta("/unresolved"),
        };
        assert_eq!(
            default_part_media(&unresolved, OasVersion::V3_1, &projector),
            ("application/octet-stream".to_owned(), false)
        );
        let object_composition = SchemaNode::AllOf {
            branches: vec![
                SchemaNode::Any {
                    meta: test_meta("/any"),
                },
                SchemaNode::Object {
                    properties: Vec::new(),
                    additional_properties: crate::ir::AdditionalProperties::Allowed(None),
                    meta: test_meta("/object"),
                },
            ],
            meta: test_meta("/composition"),
        };
        assert_eq!(
            default_part_media(&object_composition, OasVersion::V3_1, &projector),
            ("application/json".to_owned(), false)
        );

        assert_eq!(response_status_name(&ResponseStatus::Default), "default");
        assert_eq!(
            response_sort_key(&ResponseStatus::Exact("bad".to_owned())),
            (0, u16::MAX)
        );
        assert_eq!(
            response_sort_key(&ResponseStatus::Range(String::new())),
            (1, u16::MAX)
        );
        let located = SourceRef {
            source_id: "openapi.json".to_owned(),
            json_pointer: "/located".to_owned(),
            line: Some(7),
            col: Some(9),
        };
        let diagnostic = source_diagnostic("OASTS1410", "located", &located, Severity::Error);
        assert_eq!((diagnostic.line, diagnostic.col), (Some(7), Some(9)));

        for invalid in [
            "",
            "*/json",
            "text/plain;",
            "text/plain; =value",
            "text/plain; name",
            "text/plain; name=\"unterminated",
            "text/plain; name=\"trailing\\\"",
            "text/plain; name=\"bad\\\u{0001}\"",
            "text/plain; name=",
        ] {
            assert!(parse_declared_media(invalid).is_err(), "{invalid:?}");
        }
        assert!(split_quoted("text/plain; note=\"unterminated", ';').is_err());
        assert!(parse_parameter_value(r#""trailing\""#).is_err());

        let string = test_primitive(PrimitiveType::String, "/string");
        let tuple = SchemaNode::Tuple {
            prefix_items: Vec::new(),
            rest: crate::ir::TupleRest::Allowed,
            meta: test_meta("/tuple"),
        };
        assert_eq!(schema_admits_string(&tuple, "x", &projector), Some(false));
        assert_eq!(finite_string_values(&tuple, &projector), None);
        assert_eq!(finite_string_values(&string, &projector), None);
        let finite = SchemaNode::Finite {
            enum_values: Some(vec![json!("x"), json!("y")]),
            const_value: Some(json!("x")),
            meta: test_meta("/finite"),
        };
        assert_eq!(
            finite_string_values(&finite, &projector),
            Some(vec!["x".to_owned()])
        );
        assert_eq!(
            projector.project(&finite),
            Projection::Known(Domain::STRING)
        );
        let bad_const = SchemaNode::Finite {
            enum_values: None,
            const_value: Some(json!(1)),
            meta: test_meta("/bad-const"),
        };
        assert_eq!(
            finite_string_values(&bad_const, &projector),
            Some(Vec::new())
        );
        let any_of = SchemaNode::AnyOf {
            branches: vec![
                test_primitive(PrimitiveType::Integer, "/integer"),
                string.clone(),
            ],
            meta: test_meta("/any-of"),
        };
        let all_of = SchemaNode::AllOf {
            branches: vec![
                SchemaNode::Any {
                    meta: test_meta("/open"),
                },
                string,
            ],
            meta: test_meta("/all-of"),
        };
        assert_eq!(schema_admits_string(&any_of, "x", &projector), Some(true));
        assert_eq!(schema_admits_string(&all_of, "x", &projector), Some(true));

        let all_json_types = SchemaNode::Finite {
            enum_values: Some(vec![
                Value::Null,
                json!(true),
                json!(1),
                json!("x"),
                json!([]),
                json!({}),
            ]),
            const_value: None,
            meta: test_meta("/all-json-types"),
        };
        assert_eq!(
            projector.project(&all_json_types),
            Projection::Known(Domain::FULL)
        );
        let contradictory_primitive = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: Some(json!(1)),
            meta: test_meta("/contradictory-primitive"),
        };
        assert_eq!(
            projector.project(&contradictory_primitive),
            Projection::Known(Domain::EMPTY)
        );
        let nullable_constant = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: Some(json!("value")),
            meta: SchemaMeta {
                nullable: true,
                ..test_meta("/nullable-constant")
            },
        };
        assert_eq!(
            projector.project(&nullable_constant),
            Projection::Known(Domain::STRING)
        );
        let nullable_object = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: crate::ir::AdditionalProperties::Allowed(None),
            meta: SchemaMeta {
                nullable: true,
                ..test_meta("/nullable-object")
            },
        };
        assert_eq!(
            projector.project(&nullable_object),
            Projection::Known(Domain::OBJECT.union(Domain::NULL))
        );
        assert_eq!(
            projector.project(&test_primitive(PrimitiveType::Null, "/null")),
            Projection::Known(Domain::NULL)
        );
        let nullable_string = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: None,
            meta: SchemaMeta {
                nullable: true,
                ..test_meta("/nullable-string")
            },
        };
        assert_eq!(
            projector.project(&nullable_string),
            Projection::Known(Domain::STRING.union(Domain::NULL))
        );
        assert_eq!(
            union_projection(Projection::Unsupported, Projection::Known(Domain::STRING)),
            Projection::Unsupported
        );
        assert_eq!(
            intersect_projection(Projection::Unsupported, Projection::Known(Domain::STRING)),
            Projection::Unsupported
        );

        let cycle_ir = Ir {
            schemas: vec![
                NamedSchema {
                    name: "A".to_owned(),
                    schema: SchemaNode::Ref {
                        target: SchemaRef {
                            source_id: "openapi.json".to_owned(),
                            json_pointer: "/B".to_owned(),
                        },
                        meta: test_meta("/A"),
                    },
                    source: SourceRef::new("openapi.json", "/A"),
                },
                NamedSchema {
                    name: "B".to_owned(),
                    schema: SchemaNode::Ref {
                        target: SchemaRef {
                            source_id: "openapi.json".to_owned(),
                            json_pointer: "/A".to_owned(),
                        },
                        meta: test_meta("/B"),
                    },
                    source: SourceRef::new("openapi.json", "/B"),
                },
            ],
            ..Ir::default()
        };
        let cycle_projector = PrimitiveDomainProjector::new(&cycle_ir);
        assert!(
            cycle_projector
                .resolve_schema(&cycle_ir.schemas[0].schema)
                .is_none()
        );

        let schemes = vec![
            NamedSecurityScheme {
                name: "http".to_owned(),
                kind: SecKind::Http {
                    scheme: "bearer".to_owned(),
                },
                source: SourceRef::new("openapi.json", "/http"),
            },
            NamedSecurityScheme {
                name: "mutual".to_owned(),
                kind: SecKind::MutualTls,
                source: SourceRef::new("openapi.json", "/mutual"),
            },
            NamedSecurityScheme {
                name: "other".to_owned(),
                kind: SecKind::Other,
                source: SourceRef::new("openapi.json", "/other"),
            },
        ];
        assert!(security_wire_key(&schemes[1]).is_none());
        let ir = Ir {
            security_schemes: schemes,
            ..Ir::default()
        };
        let operation = Operation {
            method: "get".to_owned(),
            path_template: Vec::new(),
            operation_id: None,
            summary: None,
            description: None,
            deprecated: false,
            external_docs: None,
            parameters: Vec::new(),
            request_body: None,
            responses: Vec::new(),
            servers: Vec::new(),
            security: None,
            source: SourceRef::new("openapi.json", "/operation"),
        };
        let security = vec![
            vec![
                ("mutual".to_owned(), Vec::new()),
                ("other".to_owned(), Vec::new()),
            ],
            vec![
                ("http".to_owned(), Vec::new()),
                ("mutual".to_owned(), Vec::new()),
            ],
        ];
        let mut sink = DiagnosticSink::new();
        diagnose_security(&operation, &security, &ir, &mut sink);
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1430")
        );
    }

    #[test]
    fn literal_base_url_and_body_plan_variant_accessors_are_modeled() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/body": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/octet-stream": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "literal", "value": "https://literal.example.test" }
            }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);

        assert_eq!(
            model.operations[0].base_url,
            BaseUrlPlan::Literal {
                value: "https://literal.example.test".to_owned()
            }
        );
        assert!(matches!(
            model.operations[0].body_plan,
            Some(BodyPlan::TopLevelBinary { .. })
        ));
    }

    #[test]
    fn primitive_projection_resolves_two_schema_cycle_as_greatest_fixed_point() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "A": { "$ref": "#/components/schemas/B" },
                    "B": {
                        "allOf": [
                            { "$ref": "#/components/schemas/A" },
                            { "type": "string" }
                        ]
                    }
                }
            },
            "paths": {
                "/cycle": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "cycle",
                                "content": {
                                    "text/plain": { "schema": { "$ref": "#/components/schemas/A" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, analyzed, _config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let response_schema = &analyzed.ir.operations[0].responses[0].media_types[0].schema;
        assert!(matches!(response_schema, SchemaNode::Ref { .. }));
        let projector = PrimitiveDomainProjector::new(&analyzed.ir);

        assert_eq!(
            projector.project(response_schema),
            Projection::Known(Domain::STRING)
        );
    }

    #[test]
    fn oxs1401_rejects_client_informational_responses_only() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/status": {
                    "get": {
                        "responses": {
                            "100": { "description": "continue" },
                            "1XX": { "description": "informational" },
                            "200": { "description": "accepted sibling" }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1401")
                .count(),
            2
        );
        assert!(diagnostics.iter().all(|diagnostic| {
            diagnostic.code != "OASTS1401"
                || diagnostic.json_pointer.as_deref().is_some_and(|pointer| {
                    pointer.ends_with("/responses/100") || pointer.ends_with("/responses/1XX")
                })
        }));
    }

    #[test]
    fn response_classifier_matches_every_frozen_classifier_class() {
        for (media, marked, expected) in [
            ("text/event-stream", false, DecoderClass::Streaming),
            ("application/stream+json", true, DecoderClass::Streaming),
            ("application/json", false, DecoderClass::Json),
            ("application/vnd.api+json", false, DecoderClass::Json),
            ("application/xml", false, DecoderClass::Xml),
            ("text/xml", false, DecoderClass::Xml),
            ("application/atom+xml", false, DecoderClass::Xml),
            ("multipart/mixed", false, DecoderClass::Multipart),
            (
                "application/x-www-form-urlencoded",
                false,
                DecoderClass::Text,
            ),
            ("text/plain", false, DecoderClass::Text),
            ("text/html", false, DecoderClass::Text),
            ("application/octet-stream", false, DecoderClass::Binary),
            ("image/png", false, DecoderClass::Binary),
            ("application/pdf", false, DecoderClass::Binary),
        ] {
            assert_eq!(
                classify_response_media(&classifier_media(media, marked)),
                expected,
                "{media}"
            );
        }
    }

    #[test]
    fn oxs1402_streaming_precedes_other_response_classifiers() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/stream": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "text/event-stream": { "schema": { "type": "string" } },
                                "application/json": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "marked json",
                                "content": {
                                    "application/stream+json": {
                                        "x-oasts-streaming": true,
                                        "schema": { "type": "object" }
                                    }
                                }
                            },
                            "201": {
                                "description": "marked xml",
                                "content": {
                                    "application/stream+xml": {
                                        "x-oasts-streaming": true,
                                        "schema": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1402")
                .count(),
            3
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1403")
        );
    }

    #[test]
    fn oxs1403_rejects_xml_requests_and_responses() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/xml": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/xml": { "schema": { "type": "string" } },
                                "application/json": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "xml",
                                "content": {
                                    "application/atom+xml": { "schema": { "type": "string" } }
                                }
                            },
                            "201": {
                                "description": "json sibling",
                                "content": {
                                    "application/json": { "schema": { "type": "object" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1403")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1404_rejects_only_multipart_responses() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/multipart": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "unsupported response",
                                "content": {
                                    "multipart/mixed": { "schema": { "type": "object" } }
                                }
                            },
                            "201": {
                                "description": "binary sibling",
                                "content": {
                                    "application/octet-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1404")
                .count(),
            1
        );
    }

    #[test]
    fn oxs1405_requires_string_projection_for_text_branches() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/projection": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "text/plain": { "schema": { "type": "integer" } },
                                "application/json": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": { "description": "absent schema", "content": { "text/plain": {} } },
                            "201": { "description": "string", "content": { "text/plain": { "schema": { "type": "string" } } } },
                            "202": { "description": "true", "content": { "text/plain": { "schema": true } } },
                            "203": { "description": "false", "content": { "text/plain": { "schema": false } } },
                            "206": { "description": "typeless", "content": { "text/plain": { "schema": {} } } },
                            "207": { "description": "number const", "content": { "text/plain": { "schema": { "const": 1 } } } },
                            "208": { "description": "string enum", "content": { "application/x-www-form-urlencoded": { "schema": { "enum": ["ok"] } } } },
                            "209": { "description": "anyOf", "content": { "text/plain": { "schema": { "anyOf": [{ "type": "integer" }, { "type": "string" }] } } } },
                            "210": { "description": "oneOf", "content": { "text/plain": { "schema": { "oneOf": [{ "type": "boolean" }, { "type": "string" }] } } } },
                            "211": { "description": "allOf", "content": { "text/plain": { "schema": { "allOf": [{ "type": "string" }, { "type": "integer" }] } } } },
                            "212": { "description": "object", "content": { "text/plain": { "schema": { "type": "object" } } } }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1405")
                .count(),
            5
        );
    }

    #[test]
    fn oxs1405_defers_to_existing_unsupported_keyword_diagnostic() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/unsupported": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "unsupported schema",
                                "content": {
                                    "text/plain": { "schema": { "not": { "type": "integer" } } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, analyzed, config, mut sink) = analyzed_with_diagnostics(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let _ = build_client_model(&analyzed, &config, &mut sink);
        let diagnostics = sink.into_sorted_vec();

        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1103")
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1405")
        );
    }

    #[test]
    fn oxs1406_warns_and_suppresses_classification_for_static_bodyless_media() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/head": {
                    "head": {
                        "responses": {
                            "200": {
                                "description": "head body",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                },
                "/statuses": {
                    "get": {
                        "responses": {
                            "204": { "description": "xml", "content": { "application/xml": { "schema": { "type": "string" } } } },
                            "205": { "description": "multipart", "content": { "multipart/mixed": { "schema": { "type": "object" } } } },
                            "304": { "description": "marked", "content": { "application/custom": { "x-oasts-streaming": true, "schema": { "type": "string" } } } },
                            "2XX": { "description": "dynamic sibling", "content": { "application/json": { "schema": { "type": "object" } } } }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);
        let bodyless = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1406")
            .collect::<Vec<_>>();

        assert_eq!(bodyless.len(), 4);
        assert!(
            bodyless
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| { matches!(diagnostic.code, "OASTS1402" | "OASTS1403" | "OASTS1404") })
        );
    }

    #[test]
    fn oxs1410_rejects_cookie_parameters_and_keeps_siblings() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cookie": {
                    "get": {
                        "parameters": [
                            { "name": "session", "in": "cookie", "schema": { "type": "string" } },
                            { "name": "safe", "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1410")
                .count(),
            1
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS1410" && diagnostic.message.contains("session")
        }));
    }

    #[test]
    fn oxs1411_rejects_unconditionally_forbidden_operation_headers() {
        let document = json!({
            "openapi": "3.1.0",
            "security": [{ "proxyKey": [] }],
            "components": {
                "securitySchemes": {
                    "proxyKey": { "type": "apiKey", "in": "header", "name": "Proxy-Secret" },
                    "inactive": { "type": "apiKey", "in": "header", "name": "Host" }
                }
            },
            "paths": {
                "/headers": {
                    "get": {
                        "parameters": [
                            { "name": "Content-Length", "in": "header", "schema": { "type": "string" } },
                            { "name": "X-HTTP-Method", "in": "header", "schema": { "type": "string" } },
                            { "name": "X-Safe", "in": "header", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1411")
                .count(),
            2
        );
        assert!(!diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS1411"
                && (diagnostic.message.contains("X-HTTP-Method")
                    || diagnostic.message.contains("inactive"))
        }));
    }

    #[test]
    fn oxs1412_rejects_active_api_key_owned_header_collisions() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "acceptKey": { "type": "apiKey", "in": "header", "name": "Accept" },
                    "contentKey": { "type": "apiKey", "in": "header", "name": "content-TYPE" },
                    "safeKey": { "type": "apiKey", "in": "header", "name": "X-Key" }
                }
            },
            "paths": {
                "/collision": {
                    "get": {
                        "security": [{ "acceptKey": [] }, { "contentKey": [] }, { "safeKey": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1412")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1413_rejects_parameter_and_and_alternative_wire_key_collisions() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "queryKey": { "type": "apiKey", "in": "query", "name": "token" },
                    "headerA": { "type": "apiKey", "in": "header", "name": "X-Credential" },
                    "headerB": { "type": "apiKey", "in": "header", "name": "x-credential" },
                    "safe": { "type": "apiKey", "in": "query", "name": "other" }
                }
            },
            "paths": {
                "/security": {
                    "get": {
                        "parameters": [
                            { "name": "token", "in": "query", "schema": { "type": "string" } },
                            { "name": "X-Input", "in": "header", "schema": { "type": "string" } }
                        ],
                        "security": [
                            { "queryKey": [] },
                            { "headerA": [], "headerB": [] },
                            { "safe": [] }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1413")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1414_rejects_only_control_bytes_in_multipart_field_names() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/fields": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "safe\"slash\\é": { "type": "string" },
                                            "bad\nname": { "type": "string" },
                                            "bad\u{0001}name": { "type": "string" }
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
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1414")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1415_rejects_invalid_cte_values_and_composition() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cte": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "badEncoding": { "type": "string", "contentEncoding": "base64url" },
                                            "badHeader": { "type": "string" },
                                            "nonStringHeader": { "type": "string" },
                                            "nonStringConst": { "type": "string" },
                                            "badComposition": { "type": "string", "contentEncoding": "7bit" },
                                            "matching": { "type": "string", "contentEncoding": "binary" },
                                            "unconstrained": { "type": "string", "contentEncoding": "8bit" },
                                            "broadCaller": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "badHeader": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["base64", "quoted-printable"] } }
                                            }
                                        },
                                        "nonStringHeader": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": [1] } }
                                            }
                                        },
                                        "nonStringConst": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "const": 1 } }
                                            }
                                        },
                                        "badComposition": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "const": "8bit" } }
                                            }
                                        },
                                        "matching": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit", "binary"] } }
                                            }
                                        },
                                        "unconstrained": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": {} }
                                            }
                                        },
                                        "broadCaller": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit", "base64"] } }
                                            }
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
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1415")
                .count(),
            6
        );
    }

    #[test]
    fn oxs1415_requires_caller_cte_schemas_to_prove_only_admitted_values() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cte": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "unconstrained": { "type": "string" },
                                            "mixed": { "type": "string" },
                                            "admitted": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "unconstrained": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "type": "string" } }
                                            }
                                        },
                                        "mixed": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit", "base64"] } }
                                            }
                                        },
                                        "admitted": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit", "8bit"] } }
                                            }
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
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1415")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1415_rejects_unevaluable_cte_composition_after_oxs1103() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cte": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "field": { "type": "string", "contentEncoding": "7bit" }
                                        }
                                    },
                                    "encoding": {
                                        "field": {
                                            "headers": {
                                                "Content-Transfer-Encoding": {
                                                    "schema": { "not": { "const": "8bit" } }
                                                }
                                            }
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
        let (_temp, analyzed, config, mut sink) = analyzed_with_diagnostics(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let _ = build_client_model(&analyzed, &config, &mut sink);
        let diagnostics = sink.into_sorted_vec();

        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1103")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1415")
        );
    }

    #[test]
    fn oxs1416_rejects_incompatible_content_disposition_schema() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/disposition": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "wrong": { "type": "string" },
                                            "right": { "type": "string" },
                                            "open": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "wrong": {
                                            "headers": {
                                                "Content-Disposition": { "schema": { "const": "attachment" } }
                                            }
                                        },
                                        "right": {
                                            "headers": {
                                                "Content-Disposition": { "schema": { "const": "form-data; name=\"right\"" } }
                                            }
                                        },
                                        "open": {
                                            "headers": {
                                                "Content-Disposition": { "schema": { "type": "string" } }
                                            }
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
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1416")
                .count(),
            1
        );
    }

    #[test]
    fn oxs1417_rejects_headers_outside_rfc7578_set() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/headers": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": { "field": { "type": "string" } }
                                    },
                                    "encoding": {
                                        "field": {
                                            "headers": {
                                                "X-Custom": { "schema": { "type": "string" } },
                                                "Content-Type": { "schema": { "type": "string" } },
                                                "Content-Disposition": { "schema": { "type": "string" } },
                                                "Content-Transfer-Encoding": { "schema": { "enum": ["7bit"] } }
                                            }
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
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1417")
                .count(),
            1
        );
    }

    #[test]
    fn oxs1418_validates_declared_encoding_content_types_as_rfc9110() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/media": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "valid": { "type": "string" },
                                            "badWhitespace": { "type": "string" },
                                            "badControl": { "type": "string" },
                                            "badNonAscii": { "type": "string" },
                                            "badDuplicate": { "type": "string" },
                                            "badSyntax": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "valid": { "contentType": "Application/JSON; Charset=\"UTF-8\", image/*" },
                                        "badWhitespace": { "contentType": "text/plain; charset = utf-8" },
                                        "badControl": { "contentType": "text/plain; note=\"bad\u{0001}value\"" },
                                        "badNonAscii": { "contentType": "text/plain; note=\"café\"" },
                                        "badDuplicate": { "contentType": "application/json; charset=utf-8; Charset=utf-16" },
                                        "badSyntax": { "contentType": "missing-slash" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1418")
                .count(),
            5
        );
    }

    #[test]
    fn encoding_media_parser_matches_canonical_media_vectors() {
        for (input, expected) in [
            (
                "Application/XML; charset=UTF-8",
                "application/xml; charset=utf-8",
            ),
            (
                "application/vnd.custom; charset=UTF-8; boundary=AbC123",
                "application/vnd.custom; boundary=AbC123; charset=utf-8",
            ),
            (
                "application/vnd.custom2; note=\"a\\\"b\\\\c\"",
                "application/vnd.custom2; note=\"a\\\"b\\\\c\"",
            ),
        ] {
            assert_eq!(
                parse_declared_media(input).expect("valid media").canonical,
                expected
            );
        }
        for input in [
            "application/json; charset=utf-8; Charset=utf-16",
            "application/xml; charset = utf-8",
            "text/plain; name=\"bad\u{0001}value\"",
            "text/plain; name=\"café\"",
        ] {
            assert!(parse_declared_media(input).is_err(), "{input}");
        }
    }

    #[test]
    fn oxs1419_rejects_illegal_or_shape_ambiguous_parameter_styles() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/styles/{pathForm}/{pathOk}": {
                    "get": {
                        "parameters": [
                            { "name": "pathForm", "in": "path", "required": true, "style": "form", "schema": { "type": "string" } },
                            { "name": "pathOk", "in": "path", "required": true, "style": "simple", "schema": { "type": "string" } },
                            { "name": "querySimple", "in": "query", "style": "simple", "schema": { "type": "string" } },
                            { "name": "headerForm", "in": "header", "style": "form", "schema": { "type": "string" } },
                            { "name": "spaceExploded", "in": "query", "style": "spaceDelimited", "explode": true, "schema": { "type": "array", "items": { "type": "string" } } },
                            { "name": "spaceObject", "in": "query", "style": "spaceDelimited", "explode": false, "schema": { "type": "object" } },
                            { "name": "pipeOk", "in": "query", "style": "pipeDelimited", "explode": false, "schema": { "type": "array", "items": { "type": "string" } } },
                            { "name": "deepFalse", "in": "query", "style": "deepObject", "explode": false, "schema": { "type": "object" } },
                            { "name": "deepArray", "in": "query", "style": "deepObject", "explode": true, "schema": { "type": "array", "items": { "type": "string" } } },
                            { "name": "deepOk", "in": "query", "style": "deepObject", "explode": true, "schema": { "type": "object" } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1419")
                .count(),
            7
        );
    }

    #[test]
    fn oxs1419_applies_restricted_styles_to_encoding_objects() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/encoding-styles": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "bad": { "type": "object" },
                                            "good": { "type": "array", "items": { "type": "string" } },
                                            "ignoredMedia": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "bad": { "style": "spaceDelimited", "explode": false },
                                        "good": { "style": "pipeDelimited", "explode": false },
                                        "ignoredMedia": { "style": "form", "contentType": "malformed" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1419")
                .count(),
            1
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1418")
        );
    }

    #[test]
    fn oxs1420_validates_server_index_and_default_substituted_absolute_url() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://root.example.test" }],
            "paths": {
                "/missing": {
                    "get": { "responses": { "200": { "description": "missing index" } } }
                },
                "/relative": {
                    "get": {
                        "servers": [
                            { "url": "https://zero.example.test" },
                            { "url": "/{version}", "variables": { "version": { "default": "v1" } } }
                        ],
                        "responses": { "200": { "description": "relative" } }
                    }
                },
                "/valid": {
                    "get": {
                        "servers": [
                            { "url": "https://zero.example.test" },
                            { "url": "https://{host}/v1", "variables": { "host": { "default": "api.example.test" } } }
                        ],
                        "responses": { "200": { "description": "valid" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics_with(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "server", "index": 1 }
            }),
        );

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1420")
                .count(),
            2
        );
    }

    #[test]
    fn oxs1430_rejects_only_operations_with_non_anonymous_security() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "key": { "type": "apiKey", "in": "query", "name": "key" }
                }
            },
            "paths": {
                "/secured": {
                    "get": {
                        "operationId": "securedOperation",
                        "security": [{ "key": [] }, {}],
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "/anonymous": {
                    "get": {
                        "operationId": "anonymousOperation",
                        "security": [{}],
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "/empty": {
                    "get": {
                        "operationId": "emptyOperation",
                        "security": [],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);
        let seam = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1430")
            .collect::<Vec<_>>();

        assert_eq!(seam.len(), 1);
        assert!(seam[0].message.contains("securedOperation"));
        assert!(!seam[0].message.contains("anonymousOperation"));
        assert!(!seam[0].message.contains("emptyOperation"));
    }
}
