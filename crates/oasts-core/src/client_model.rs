//! Client artifact planning over the normalized OpenAPI IR.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use serde_json::Value;

use crate::config::{ResolvedBaseUrl, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    EncodingObject, Ir, MediaType, NamedSecurityScheme, OAuthFlow, OasVersion, Operation,
    ParamLocation, ParamStyle, PrimitiveType, ResponseStatus, SchemaNode, SecKind,
    SecurityRequirement, ServerEntry, SourceRef,
};
use crate::loader::append_pointer;
use crate::media::{MediaRangeKind, is_json, is_xml, media_essence};
use crate::semantic::Analyzed;

const CODE_OAUTH2_EMPTY_FLOWS: &str = "OASTS1435";
const CODE_OAUTH2_FLOW_REQUIRED_URL: &str = "OASTS1436";
const CODE_OAUTH2_FLOW_URL: &str = "OASTS1437";
const CODE_OPENID_CONNECT_URL: &str = "OASTS1439";
const CODE_HTTP_SCHEME_TOKEN: &str = "OASTS1444";
const CODE_OAUTH2_REQUIREMENT_SCOPE: &str = "OASTS1440";
const CODE_NON_OAUTH_REQUIREMENT_SCOPES: &str = "OASTS1441";
const CODE_URLENCODED_CONTENT_TYPE_IGNORED: &str = "OASTS1425";
const CODE_MULTIPART_30_STYLE_IGNORED: &str = "OASTS1426";
const CODE_MULTIPART_STYLE_UNDEFINED: &str = "OASTS1427";
const JSON_PART_MEDIA: &str = "application/json";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientModel {
    pub operations: Vec<OperationPlan>,
    pub base_url_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPlan {
    pub operation_index: usize,
    pub param_plans: Vec<ParameterPlan>,
    pub body_plan: Option<BodyPlan>,
    pub response_table: Vec<ResponsePlan>,
    pub accept: Option<String>,
    pub base_url: BaseUrlPlan,
    /// Effective security as an ordered list of OR alternatives; an empty inner
    /// alternative is the anonymous `{}` option and is preserved in place.
    pub auth_plan: Vec<AuthAlternative>,
    pub credential_headers: Vec<String>,
}

/// One security OR alternative: the AND-set of scheme uses a caller satisfies together.
/// Empty represents the anonymous `{}` alternative.
pub type AuthAlternative = Vec<AuthSchemeUse>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSchemeUse {
    pub name: String,
    pub kind: AuthKind,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthKind {
    Basic,
    Bearer,
    HttpScheme {
        scheme: String,
    },
    MutualTls,
    ApiKeyHeader {
        name: String,
    },
    ApiKeyQuery {
        name: String,
    },
    ApiKeyCookie {
        name: String,
    },
    /// OAuth2 and OpenIdConnect both serialize as a bearer token at runtime but keep
    /// distinct kinds so the emitted descriptor preserves provider context.
    OAuth2,
    OpenIdConnect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterPlan {
    pub name: String,
    pub schema: SchemaNode,
    pub resolved: ResolvedParameterSerialization,
    /// The caller supplies a pre-serialized `string`, so the client input type ignores `schema`.
    /// Set for content-sourced parameters whose media type is neither JSON-family nor a
    /// text/plain-over-string passthrough (the OASTS1443 case); every typed case keeps this false.
    pub caller_serialized: bool,
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
    QuerySpaceDelimitedObject,
    QueryPipeDelimited,
    QueryPipeDelimitedObject,
    QueryDeepObject,
    HeaderSimple,
    HeaderSimpleExplode,
    /// Content-sourced JSON-family parameters: `JSON.stringify` then location-appropriate encoding.
    /// One per wire framing (path segment vs `name=value` query/cookie pair vs raw simple-header
    /// value); style/explode/allowReserved never apply. Cookies reuse the query serializer.
    ContentJsonPath,
    ContentJsonQuery,
    ContentJsonHeader,
}

impl HelperId {
    /// Whether this helper is a content-sourced JSON serializer, which the runtime feeds the raw
    /// typed value (not a pre-validated `ParamValue`) so its descriptor entry carries `content: true`.
    #[must_use]
    pub(crate) fn is_content_json(self) -> bool {
        matches!(
            self,
            Self::ContentJsonPath | Self::ContentJsonQuery | Self::ContentJsonHeader
        )
    }
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
    /// Wire payload kind per admitted media type, index-aligned with `values`. Both the urlencoded
    /// and multipart body descriptors consume it: the runtime picks the caller-selected admitted
    /// media and indexes `payloads[selected.index]`, so one classification keeps the emitted part
    /// Content-Type and the body serialization in agreement for that exact media.
    pub payloads: Vec<PayloadKind>,
    pub all_concrete: bool,
    pub binary_upload: bool,
    pub declared: bool,
}

/// How a content-based form field is serialized onto the wire for one admitted media type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadKind {
    Json,
    Text,
    Binary,
}

impl PayloadKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }
}

/// Records a step into an array's `items` for the media classifiers, guarding the cross-hop ref
/// cycle that `resolve_schema`'s per-call seen-set cannot span. A schema-position cycle such as
/// `Tree: {type: array, items: $ref Tree}` resolves one hop at a time, so without a set that
/// outlives the recursion the classifiers descend until the stack overflows and aborts the host
/// process (an uncatchable SIGABRT through napi). Returns `false` on a revisited ref target,
/// routing the caller to its terminal fallback arm; a non-ref item never cycles and always
/// proceeds. Mirrors the ref-target set threaded through `schema_is_array`.
fn enter_array_items(items: &SchemaNode, visited: &mut HashSet<(String, String)>) -> bool {
    match items {
        SchemaNode::Ref { target, .. } => {
            visited.insert((target.source_id.clone(), target.json_pointer.clone()))
        }
        _ => true,
    }
}

/// Classifies the wire payload kind for one admitted media type of a content-based form field.
///
/// Follows the OAS 3.1.1 Encoding Object default `contentType` table: `object` → application/json,
/// `string` + `contentEncoding` (and other binary defaults) → octet-stream, other primitives →
/// text/plain. An explicitly declared media type overrides the default and is classified here by
/// its essence: `application/json` and `+json` suffixes are JSON, `text/*` is text, and every other
/// concrete or wildcard media falls back to the schema shape (object/tuple → JSON, arrays by their
/// ref-resolved items — mirroring `default_part_media` — else text). The caller seeds `visited`; a
/// ref-cyclic array bottoms out at the text fallback.
fn content_payload_kind(
    resolved: &SchemaNode,
    media_value: &str,
    projector: &PrimitiveDomainProjector<'_>,
    visited: &mut HashSet<(String, String)>,
) -> PayloadKind {
    let essence = media_essence(media_value);
    if essence == "application/json" || essence.ends_with("+json") {
        return PayloadKind::Json;
    }
    if essence.starts_with("text/") {
        return PayloadKind::Text;
    }
    match resolved {
        SchemaNode::Object { .. } | SchemaNode::Tuple { .. } => PayloadKind::Json,
        SchemaNode::Array { items, .. } if enter_array_items(items, visited) => {
            let items = projector.resolve_schema(items).unwrap_or(items);
            content_payload_kind(items, media_value, projector, visited)
        }
        _ => PayloadKind::Text,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldWrapperPlan {
    pub wrapped: bool,
    pub content_type_literal: bool,
    pub filename: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponsePlan {
    pub match_key: String,
    pub kind: ResponseMatchKind,
    pub media: Vec<ResponseMediaPlan>,
    pub payload: PayloadDisposition,
    pub content_type_discriminated: bool,
    /// Whether the response declares at least one header — independent of `payload`, since a
    /// header applies to the response regardless of whether it carries a body. Drives the client
    /// emitter's `meta.headers` narrowing and, when response validation is bound, its header
    /// validator call.
    pub has_headers: bool,
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
    /// Canonical full media type or range (sorted parameters included). Both the emitted
    /// `contentType` discriminant literal and the runtime's most-specific selection key on it, so
    /// parameter-differing keys stay distinct arms.
    pub media: String,
    pub decoder: DecoderClass,
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
    let oas_version = analyzed.ir.version;
    diagnose_security_schemes(&analyzed.ir, sink);
    let security_schemes = index_security_schemes(&analyzed.ir);
    let operations: Vec<_> = analyzed
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
            let auth_plan = plan_auth(
                operation,
                &effective_security,
                &security_schemes,
                oas_version,
                sink,
            );
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
                .map(|parameter| parameter_plan(parameter, &projector))
                .collect();
            let body_plan = operation
                .request_body
                .as_ref()
                .and_then(|body| build_body_plan(&body.media_types, &projector));
            let response_table = response_table(operation, &projector, sink);
            let accept = build_accept(operation.responses.iter().flat_map(|response| {
                response
                    .media_types
                    .iter()
                    .map(|media| (media.full.as_str(), media.range_kind))
            }));
            OperationPlan {
                operation_index,
                param_plans,
                body_plan,
                response_table,
                accept,
                base_url,
                credential_headers: credential_headers(&effective_security, &analyzed.ir),
                auth_plan,
            }
        })
        .collect();
    let base_url_required = operations
        .iter()
        .any(|operation| has_relative_server_url(&operation.base_url));
    ClientModel {
        operations,
        base_url_required,
    }
}

fn diagnose_security_schemes(ir: &Ir, sink: &mut DiagnosticSink) {
    for scheme in &ir.security_schemes {
        match &scheme.kind {
            SecKind::OAuth2 { flows } => {
                if flows.is_empty() {
                    sink.push(source_diagnostic(
                        CODE_OAUTH2_EMPTY_FLOWS,
                        "oauth2 scheme declares no flows",
                        &scheme.source,
                        Severity::Error,
                    ));
                }
                diagnose_oauth_flow(
                    scheme,
                    "implicit",
                    flows.implicit.as_ref(),
                    &["authorizationUrl"],
                    sink,
                );
                diagnose_oauth_flow(
                    scheme,
                    "password",
                    flows.password.as_ref(),
                    &["tokenUrl"],
                    sink,
                );
                diagnose_oauth_flow(
                    scheme,
                    "clientCredentials",
                    flows.client_credentials.as_ref(),
                    &["tokenUrl"],
                    sink,
                );
                diagnose_oauth_flow(
                    scheme,
                    "authorizationCode",
                    flows.authorization_code.as_ref(),
                    &["authorizationUrl", "tokenUrl"],
                    sink,
                );
            }
            SecKind::OpenIdConnect { url } => {
                if url.is_empty() {
                    sink.push(source_diagnostic(
                        CODE_OPENID_CONNECT_URL,
                        "openIdConnect scheme requires openIdConnectUrl",
                        &scheme.source,
                        Severity::Error,
                    ));
                } else if !is_absolute_url(url) {
                    sink.push(source_diagnostic(
                        CODE_OPENID_CONNECT_URL,
                        format!("openIdConnectUrl '{url}' is not an absolute URL"),
                        &scheme.source,
                        Severity::Error,
                    ));
                }
            }
            SecKind::Http { scheme: token, .. } => {
                // The scheme is emitted verbatim into `Authorization: <scheme> <credentials>`. An
                // absent/empty scheme (unwrap_or_default at parse) produces `Authorization:
                // <credentials>` and a non-token scheme (spaces, commas) lets the header re-parse
                // split fields, so fail loudly rather than emit a malformed request.
                if token.is_empty() {
                    sink.push(source_diagnostic(
                        CODE_HTTP_SCHEME_TOKEN,
                        format!(
                            "http security scheme '{}' must declare a scheme token",
                            scheme.name
                        ),
                        &scheme.source,
                        Severity::Error,
                    ));
                } else if !token.bytes().all(crate::media::is_tchar) {
                    sink.push(source_diagnostic(
                        CODE_HTTP_SCHEME_TOKEN,
                        format!(
                            "http security scheme '{}' scheme '{token}' is not an RFC 9110 token",
                            scheme.name
                        ),
                        &scheme.source,
                        Severity::Error,
                    ));
                }
            }
            _ => {}
        }
    }
}

fn diagnose_oauth_flow(
    scheme: &NamedSecurityScheme,
    key: &str,
    flow: Option<&OAuthFlow>,
    required_fields: &[&str],
    sink: &mut DiagnosticSink,
) {
    let Some(flow) = flow else {
        return;
    };
    let source = oauth_flow_source(scheme, key);
    // `refreshUrl` is never a required flow URL, so it carries a literal `false`; the other two ask
    // the caller's list. Both the missing-required and non-absolute checks run per field — a field is
    // never both (a missing URL cannot fail the absolute check) so a single pass over one table emits
    // the same diagnostics the two separate passes did.
    for (field, required, value) in [
        (
            "authorizationUrl",
            required_fields.contains(&"authorizationUrl"),
            flow.authorization_url.as_deref(),
        ),
        (
            "tokenUrl",
            required_fields.contains(&"tokenUrl"),
            flow.token_url.as_deref(),
        ),
        ("refreshUrl", false, flow.refresh_url.as_deref()),
    ] {
        if required && value.is_none() {
            sink.push(source_diagnostic(
                CODE_OAUTH2_FLOW_REQUIRED_URL,
                format!("{key} flow requires {field}"),
                &source,
                Severity::Error,
            ));
        }
        if let Some(value) = value.filter(|value| !is_absolute_url(value)) {
            sink.push(source_diagnostic(
                CODE_OAUTH2_FLOW_URL,
                format!("{key} {field} '{value}' is not an absolute URL"),
                &source,
                Severity::Error,
            ));
        }
    }
}

fn oauth_flow_source(scheme: &NamedSecurityScheme, key: &str) -> SourceRef {
    let flows_pointer = append_pointer(&scheme.source.json_pointer, "flows");
    SourceRef {
        json_pointer: append_pointer(&flows_pointer, key),
        ..scheme.source.clone()
    }
}

fn is_absolute_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| !url.cannot_be_a_base())
}

/// How a parameter reaches the wire, decided by its content media type (OAS Parameter Object
/// `content`). Non-content parameters and content parameters that serialize identically to a
/// schema+style string both resolve to `SchemaStyle`; the class only distinguishes what the
/// serializer and input type must do differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParamContentClass {
    /// Schema+style serialization, or a content text/plain-over-string passthrough that is
    /// byte-for-byte identical to it: the input stays typed from the schema.
    SchemaStyle,
    /// Content JSON family: `JSON.stringify` then location encoding; the input stays typed.
    ContentJson,
    /// Content media the client cannot serialize (any non-JSON that is not a text/plain-over-string
    /// passthrough): the caller pre-serializes to a `string`, and OASTS1443 records it.
    CallerSerialized,
}

fn classify_param_content(
    parameter: &crate::ir::Param,
    projector: &PrimitiveDomainProjector<'_>,
) -> ParamContentClass {
    let Some(media) = parameter.content_media_type.as_deref() else {
        return ParamContentClass::SchemaStyle;
    };
    if is_json(media) {
        return ParamContentClass::ContentJson;
    }
    // text/plain over a string-shaped schema (nullability aside) is a bare passthrough — the value
    // is used as-is with location encoding, exactly like a schema+style string. Every other media,
    // and text/plain over a non-string schema, needs a caller-serialized string.
    if media_essence(media) == "text/plain"
        && matches!(
            projector.project(&parameter.schema),
            Projection::Known(domain) if domain_is_required_with_optional_null(domain, Domain::STRING)
        )
    {
        return ParamContentClass::SchemaStyle;
    }
    ParamContentClass::CallerSerialized
}

/// The location-default serializer used when style and explode are irrelevant — the terminal arm of
/// `helper_id`, reused for content parameters whose value is always a single string. A cookie
/// parameter reuses the query-form serializer: its value is always `allowReserved: false` (enforced
/// in `parameter_plan`), for which `serializeQueryForm` produces byte-identical output, and the
/// runtime routes it into the Cookie header by the descriptor's `location`, not the helper identity.
fn location_default_helper(location: ParamLocation) -> HelperId {
    match location {
        ParamLocation::Path => HelperId::PathSimple,
        ParamLocation::Query | ParamLocation::Cookie => HelperId::QueryForm,
        ParamLocation::Header => HelperId::HeaderSimple,
    }
}

fn content_json_helper(location: ParamLocation) -> HelperId {
    match location {
        ParamLocation::Path => HelperId::ContentJsonPath,
        // A cookie JSON value serializes identically to a query one; location drives Cookie framing.
        ParamLocation::Query | ParamLocation::Cookie => HelperId::ContentJsonQuery,
        ParamLocation::Header => HelperId::ContentJsonHeader,
    }
}

fn parameter_plan(
    parameter: &crate::ir::Param,
    projector: &PrimitiveDomainProjector<'_>,
) -> ParameterPlan {
    // OAS 3.1 §4.8.12.2.2: the default style for `in: cookie` is `form`, matching `in: query`.
    // Content parameters carry no style/explode (parse zeroes them), so these resolve to the
    // location defaults and only feed the vestigial `resolved` fields; the helper is overridden
    // below and serialization ignores style/explode/allowReserved.
    let style = parameter.style.unwrap_or(match parameter.location {
        ParamLocation::Query | ParamLocation::Cookie => ParamStyle::Form,
        ParamLocation::Path | ParamLocation::Header => ParamStyle::Simple,
    });
    let explode = parameter
        .explode
        .unwrap_or(matches!(style, ParamStyle::Form | ParamStyle::DeepObject));
    let (helper, caller_serialized) = match classify_param_content(parameter, projector) {
        ParamContentClass::SchemaStyle => (
            helper_id(
                parameter.location,
                style,
                explode,
                projector.project(&parameter.schema),
            ),
            false,
        ),
        ParamContentClass::ContentJson => (content_json_helper(parameter.location), false),
        ParamContentClass::CallerSerialized => (location_default_helper(parameter.location), true),
    };
    ParameterPlan {
        name: parameter.name.clone(),
        schema: parameter.schema.clone(),
        resolved: ResolvedParameterSerialization {
            location: parameter.location,
            style,
            explode,
            // OAS 3.1 §4.8.12: allowReserved applies to `in: query` only. A parser that forwards it
            // for any location would let a non-query serializer emit raw reserved characters — on the
            // cookie path a raw ';'/'=' smuggles extra pairs into the joined Cookie header.
            allow_reserved: parameter.location == ParamLocation::Query && parameter.allow_reserved,
            helper,
        },
        caller_serialized,
        source: parameter.source.clone(),
    }
}

fn helper_id(
    location: ParamLocation,
    style: ParamStyle,
    explode: bool,
    projection: Projection,
) -> HelperId {
    match (location, style, explode) {
        (ParamLocation::Path, ParamStyle::Simple, false) => HelperId::PathSimple,
        (ParamLocation::Path, ParamStyle::Simple, true) => HelperId::PathSimpleExplode,
        (ParamLocation::Path, ParamStyle::Label, false) => HelperId::PathLabel,
        (ParamLocation::Path, ParamStyle::Label, true) => HelperId::PathLabelExplode,
        (ParamLocation::Path, ParamStyle::Matrix, false) => HelperId::PathMatrix,
        (ParamLocation::Path, ParamStyle::Matrix, true) => HelperId::PathMatrixExplode,
        (ParamLocation::Query, ParamStyle::Form, false) => HelperId::QueryForm,
        (ParamLocation::Query, ParamStyle::Form, true) => HelperId::QueryFormExplode,
        (ParamLocation::Query, ParamStyle::SpaceDelimited, _) if matches!(projection, Projection::Known(domain) if domain_is_required_with_optional_null(domain, Domain::OBJECT)) => {
            HelperId::QuerySpaceDelimitedObject
        }
        (ParamLocation::Query, ParamStyle::SpaceDelimited, _) => HelperId::QuerySpaceDelimited,
        (ParamLocation::Query, ParamStyle::PipeDelimited, _) if matches!(projection, Projection::Known(domain) if domain_is_required_with_optional_null(domain, Domain::OBJECT)) => {
            HelperId::QueryPipeDelimitedObject
        }
        (ParamLocation::Query, ParamStyle::PipeDelimited, _) => HelperId::QueryPipeDelimited,
        (ParamLocation::Query, ParamStyle::DeepObject, _) => HelperId::QueryDeepObject,
        (ParamLocation::Header, ParamStyle::Simple, false) => HelperId::HeaderSimple,
        (ParamLocation::Header, ParamStyle::Simple, true) => HelperId::HeaderSimpleExplode,
        _ => location_default_helper(location),
    }
}

fn build_body_plan(
    media_types: &[MediaType],
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<BodyPlan> {
    if media_types.is_empty() {
        return None;
    }
    let discriminated =
        media_types.len() > 1 || media_types[0].range_kind != MediaRangeKind::Concrete;
    if discriminated {
        // Arms discriminate on the canonical full media type, so two parameter-differing keys
        // (e.g. two parameterized JSON media types) stay distinct arms. Ordering is BTreeMap-stable
        // by canonical-full-type byte order, independent of source declaration order.
        let mut arms = media_types
            .iter()
            .map(|media| (media.full.clone(), body_plan_for_media(media, projector)))
            .collect::<Vec<_>>();
        arms.sort_by(|(left, _), (right, _)| left.cmp(right));
        return Some(BodyPlan::ContentTypeDiscriminated {
            arms,
            all_concrete: media_types
                .iter()
                .all(|media| media.range_kind == MediaRangeKind::Concrete),
        });
    }
    Some(body_plan_for_media(&media_types[0], projector))
}

/// Classifies a request body media type by its essence (`media.essence`) — the wire serialization
/// (JSON, urlencoded, multipart, text, binary) is an essence-level decision, so a parameterized JSON
/// key still serializes as JSON — while the emitted `contentType` string is the canonical full media
/// type (`media.full`), preserving any parameters onto the wire.
fn body_plan_for_media(media: &MediaType, projector: &PrimitiveDomainProjector<'_>) -> BodyPlan {
    let schema = media.schema_present.then(|| media.schema.clone());
    if is_json(&media.essence) {
        BodyPlan::Json {
            media: media.full.clone(),
            schema,
            source: media.source.clone(),
        }
    } else if media.essence == "application/x-www-form-urlencoded" {
        BodyPlan::FormUrlencoded {
            media: media.full.clone(),
            fields: form_fields(media, false, projector),
            source: media.source.clone(),
        }
    } else if media.essence.starts_with("multipart/") {
        BodyPlan::Multipart {
            media: media.full.clone(),
            fields: form_fields(media, true, projector),
            source: media.source.clone(),
        }
    } else if media.essence.starts_with("text/") && !is_xml(&media.essence) {
        BodyPlan::TopLevelText {
            media: media.full.clone(),
            schema,
            source: media.source.clone(),
        }
    } else {
        BodyPlan::TopLevelBinary {
            media: media.full.clone(),
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
                filename: false,
            },
        )
    } else {
        let (part_media, encoding_source) =
            content_field_parts(schema, encoding, media.oas_version, projector);
        let wrapped = part_media.values.len() > 1 || !part_media.all_concrete;
        let filename = part_media.binary_upload;
        let all_concrete = part_media.all_concrete;
        (
            FieldSerializationPlan::Content {
                media: part_media,
                encoding_source,
            },
            FieldWrapperPlan {
                wrapped,
                content_type_literal: all_concrete,
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
) -> (PartMediaPlan, Option<SourceRef>) {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    // Parse each declared media once, taking both facets from that single parse: the canonical
    // string and whether it is a concrete media (not a range). The default-media branch is always a
    // concrete literal, so it needs no parse.
    let (values, all_concrete, binary_upload, declared) =
        match encoding.and_then(|encoding| encoding.content_type.as_ref()) {
            None => {
                let (media, binary) =
                    default_part_media(schema, version, projector, &mut HashSet::new());
                (vec![media.to_owned()], true, binary, false)
            }
            Some(values) => {
                let mut canonicals = Vec::with_capacity(values.len());
                let mut all_concrete = true;
                for value in values {
                    match crate::media::canonical_encoding_content_type(value) {
                        Ok(parsed) => {
                            all_concrete &= parsed.range_kind == MediaRangeKind::Concrete;
                            canonicals.push(parsed.full);
                        }
                        Err(()) => {
                            all_concrete = false;
                            canonicals.push(value.clone());
                        }
                    }
                }
                (canonicals, all_concrete, false, true)
            }
        };
    // A binary upload is binary for every admitted media, independent of the media string, so it
    // short-circuits the per-value classification (which is only ever reached with `binary_upload`
    // false). Each value gets a fresh cycle-guard set — a cycle is per-traversal.
    let payloads = if binary_upload {
        vec![PayloadKind::Binary; values.len()]
    } else {
        values
            .iter()
            .map(|value| content_payload_kind(resolved, value, projector, &mut HashSet::new()))
            .collect()
    };
    (
        PartMediaPlan {
            values,
            payloads,
            all_concrete,
            binary_upload,
            declared,
        },
        encoding.map(|encoding| encoding.source.clone()),
    )
}

/// The `contentEncoding` in effect for a part schema, resolved through `$ref` chains and the
/// branches of a lowered conjunction. `SchemaMeta::split_for_conjunction` moves the annotation onto
/// the synthetic typed branch, so a `{$ref, contentEncoding}` part carries it on a sibling of the
/// shape branch; this reunites them the way the classifier folds a conjunction's shape.
fn resolved_content_encoding<'a>(
    schema: &'a SchemaNode,
    projector: &'a PrimitiveDomainProjector<'_>,
) -> Option<&'a str> {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    if let Some(encoding) = resolved.meta().content_encoding.as_deref() {
        return Some(encoding);
    }
    match resolved {
        SchemaNode::AllOf { branches, .. } => branches
            .iter()
            .find_map(|branch| resolved_content_encoding(branch, projector)),
        _ => None,
    }
}

// The media component is always a static literal, so it is returned borrowed: `diagnose_form_media`
// reads only the binary-upload bool (no allocation on that path), while `content_field_parts`
// `.to_owned()`s the media exactly where it stores it. The caller seeds `visited`; a ref-cyclic
// array bottoms out at the text/plain fallback rather than overflowing the stack.
fn default_part_media(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
    visited: &mut HashSet<(String, String)>,
) -> (&'static str, bool) {
    let encoding = resolved_content_encoding(schema, projector);
    default_part_media_impl(schema, version, encoding, projector, visited)
}

// `encoding` is the part's effective `contentEncoding`, resolved once through `$ref`/conjunction
// branches so it reaches the shape branch even when `split_for_conjunction` moved it to a sibling.
fn default_part_media_impl(
    schema: &SchemaNode,
    version: OasVersion,
    encoding: Option<&str>,
    projector: &PrimitiveDomainProjector<'_>,
    visited: &mut HashSet<(String, String)>,
) -> (&'static str, bool) {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    match resolved {
        SchemaNode::Ref { .. } => ("application/octet-stream", false),
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            ..
        } if version == OasVersion::V3_1 && encoding.is_some() => {
            ("application/octet-stream", false)
        }
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            ..
        } if version == OasVersion::V3_0 && format.as_deref() == Some("binary") => {
            ("application/octet-stream", true)
        }
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            ..
        } if version == OasVersion::V3_0 && format.as_deref() == Some("byte") => {
            ("application/octet-stream", false)
        }
        SchemaNode::Object { .. } | SchemaNode::Tuple { .. } => ("application/json", false),
        SchemaNode::Array { items, .. } if enter_array_items(items, visited) => {
            // An array's items carry their own encoding, not the array-level one.
            let items_encoding = resolved_content_encoding(items, projector);
            default_part_media_impl(items, version, items_encoding, projector, visited)
        }
        SchemaNode::Array { .. } => ("text/plain", false),
        SchemaNode::Any { .. } | SchemaNode::Finite { .. } if version == OasVersion::V3_1 => {
            // Mirror the `Primitive{String}` arm above: a schemaless 3.1 field carrying
            // `contentEncoding` transmits the already-encoded string on the wire (OAS 3.1.1), so it
            // is not a binary upload. Without the annotation the schemaless default stays binary.
            ("application/octet-stream", encoding.is_none())
        }
        SchemaNode::AllOf { branches, .. } if version == OasVersion::V3_1 && encoding.is_some() => {
            // A lowered conjunction (`SchemaMeta::split_for_conjunction`) scatters the original
            // schema's shape and its `contentEncoding` across sibling branches. Classify through
            // them with the reunited `encoding` so a `{$ref, contentEncoding}` part matches the
            // un-lowered `{type, contentEncoding}` spelling; a branch's text/plain is the "no
            // opinion" fallback, so the first branch with a concrete media wins.
            branches
                .iter()
                .map(|branch| {
                    default_part_media_impl(branch, version, encoding, projector, visited)
                })
                .find(|(media, _)| *media != "text/plain")
                .unwrap_or(("text/plain", false))
        }
        _ if projector.project(resolved) == Projection::Known(Domain::OBJECT) => {
            ("application/json", false)
        }
        _ => ("text/plain", false),
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
                    // The runtime discriminates response arms on the canonical full media type, so a
                    // parameter-differing key (e.g. `application/json;stream=watch`) produces a
                    // distinct arm. Decoding stays essence-keyed via `classify_response_media`.
                    media: media.full.clone(),
                    decoder: classify_response_media(media),
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
                || response
                    .media_types
                    .first()
                    .is_some_and(|entry| entry.range_kind != MediaRangeKind::Concrete);
            ResponsePlan {
                match_key,
                kind,
                media,
                payload,
                content_type_discriminated,
                has_headers: !response.headers.is_empty(),
                source: response.source.clone(),
            }
        })
        .collect()
}

const CODE_DEEP_OBJECT_FALSE_EXPLODE: &str = "OASTS1442";
const CODE_CONTENT_CALLER_SERIALIZED: &str = "OASTS1443";

fn diagnose_parameters(
    operation: &Operation,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    for parameter in &operation.parameters {
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
        // A content media the client cannot serialize is carried as the caller's pre-serialized
        // string; the media type is present on this class by construction.
        if let Some(media) = &parameter.content_media_type
            && classify_param_content(parameter, projector) == ParamContentClass::CallerSerialized
        {
            sink.push(source_diagnostic(
                CODE_CONTENT_CALLER_SERIALIZED,
                format!(
                    "parameter '{}' media type '{media}' is caller-serialized; input is the pre-serialized string",
                    parameter.name
                ),
                &parameter.source,
                Severity::Warning,
            ));
        }
        let resolved = parameter_plan(parameter, projector).resolved;
        if resolved.style == ParamStyle::DeepObject && parameter.explode == Some(false) {
            sink.push(source_diagnostic(
                CODE_DEEP_OBJECT_FALSE_EXPLODE,
                "explode: false with deepObject is undefined in OAS; treating as deepObject",
                &parameter.source,
                Severity::Warning,
            ));
        }
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
        // OAS 3.1 §4.8.12: `form` is the only style defined for `in: cookie`.
        ParamLocation::Cookie => style == ParamStyle::Form,
    };
    if !legal {
        return true;
    }
    match (style, projection) {
        (ParamStyle::SpaceDelimited | ParamStyle::PipeDelimited, Projection::Known(domain)) => {
            explode
                || !(domain_is_required_with_optional_null(domain, Domain::ARRAY)
                    || domain_is_required_with_optional_null(domain, Domain::OBJECT))
        }
        (ParamStyle::DeepObject, Projection::Known(domain)) => {
            !domain_is_required_with_optional_null(domain, Domain::OBJECT)
        }
        (
            ParamStyle::SpaceDelimited | ParamStyle::PipeDelimited | ParamStyle::DeepObject,
            Projection::Unsupported,
        ) => false,
        _ => false,
    }
}

fn domain_is_required_with_optional_null(domain: Domain, required: Domain) -> bool {
    domain.contains(required) && domain.intersect(required.union(Domain::NULL)) == domain
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
            for parameter in &operation.parameters {
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
}

/// Operation label for auth diagnostics: `operationId`, else `METHOD source`.
fn operation_label(operation: &Operation) -> String {
    operation.operation_id.as_deref().map_or_else(
        || {
            format!(
                "{} {}",
                operation.method.to_ascii_uppercase(),
                operation.source.display()
            )
        },
        str::to_owned,
    )
}

/// A security scheme resolved by name, with its oauth2 declared scopes precomputed. Non-oauth2
/// schemes carry an empty `declared_scopes`, which their planning never reads.
struct SchemeLookup<'ir> {
    scheme: &'ir NamedSecurityScheme,
    declared_scopes: Vec<&'ir str>,
}

/// Indexes the document's security schemes by name once, so per-operation auth planning resolves a
/// scheme in O(1) and never recomputes its declared scopes. Keeps the first scheme for a duplicated
/// name, matching the earlier `Iterator::find` (first match).
fn index_security_schemes(ir: &Ir) -> HashMap<&str, SchemeLookup<'_>> {
    let mut index = HashMap::new();
    for scheme in &ir.security_schemes {
        index
            .entry(scheme.name.as_str())
            .or_insert_with(|| SchemeLookup {
                scheme,
                declared_scopes: match &scheme.kind {
                    SecKind::OAuth2 { flows } => flows.declared_scopes(),
                    _ => Vec::new(),
                },
            });
    }
    index
}

/// Resolves effective security into ordered OR alternatives. Every spec-legal security scheme
/// kind is representable; spec-illegal kinds remain fatal through OASTS1433 so the client never
/// silently drops a documented auth member.
fn plan_auth(
    operation: &Operation,
    security: &[SecurityRequirement],
    schemes: &HashMap<&str, SchemeLookup<'_>>,
    oas_version: OasVersion,
    sink: &mut DiagnosticSink,
) -> Vec<AuthAlternative> {
    security
        .iter()
        .map(|alternative| {
            alternative
                .iter()
                .filter_map(|(name, scopes)| {
                    auth_scheme_use(operation, name, scopes, schemes, oas_version, sink)
                })
                .collect()
        })
        .collect()
}

fn auth_scheme_use(
    operation: &Operation,
    name: &str,
    scopes: &[String],
    schemes: &HashMap<&str, SchemeLookup<'_>>,
    oas_version: OasVersion,
    sink: &mut DiagnosticSink,
) -> Option<AuthSchemeUse> {
    let Some(lookup) = schemes.get(name) else {
        sink.push(source_diagnostic(
            "OASTS1434",
            format!(
                "operation '{}' security requirement references security scheme '{name}', which is not declared in components.securitySchemes",
                operation_label(operation)
            ),
            &operation.source,
            Severity::Error,
        ));
        return None;
    };
    let scheme = lookup.scheme;
    match &scheme.kind {
        SecKind::OAuth2 { .. } => {
            for scope in scopes {
                if !lookup.declared_scopes.contains(&scope.as_str()) {
                    sink.push(source_diagnostic(
                        CODE_OAUTH2_REQUIREMENT_SCOPE,
                        format!(
                            "security requirement scope '{scope}' is not declared by oauth2 scheme '{}'",
                            scheme.name
                        ),
                        &operation.source,
                        Severity::Error,
                    ));
                }
            }
        }
        SecKind::OpenIdConnect { .. } => {
            // OpenID Connect scopes are IdP-defined and invisible to the document.
        }
        _ if oas_version == OasVersion::V3_0 && !scopes.is_empty() => {
            sink.push(source_diagnostic(
                CODE_NON_OAUTH_REQUIREMENT_SCOPES,
                format!(
                    "security requirement for '{}' must not list scopes in OpenAPI 3.0",
                    scheme.name
                ),
                &operation.source,
                Severity::Error,
            ));
        }
        _ => {}
    }
    let kind = match &scheme.kind {
        SecKind::Http { scheme: raw, .. } => match raw.to_ascii_lowercase().as_str() {
            "basic" => Some(AuthKind::Basic),
            "bearer" => Some(AuthKind::Bearer),
            _ => Some(AuthKind::HttpScheme {
                scheme: raw.clone(),
            }),
        },
        SecKind::ApiKey {
            location: ParamLocation::Header,
            name,
        } => Some(AuthKind::ApiKeyHeader { name: name.clone() }),
        SecKind::ApiKey {
            location: ParamLocation::Query,
            name,
        } => Some(AuthKind::ApiKeyQuery { name: name.clone() }),
        SecKind::ApiKey {
            location: ParamLocation::Cookie,
            name,
        } => Some(AuthKind::ApiKeyCookie { name: name.clone() }),
        SecKind::OAuth2 { .. } => Some(AuthKind::OAuth2),
        SecKind::OpenIdConnect { .. } => Some(AuthKind::OpenIdConnect),
        SecKind::MutualTls => Some(AuthKind::MutualTls),
        SecKind::ApiKey {
            location: ParamLocation::Path,
            ..
        }
        | SecKind::Other => {
            sink.push(source_diagnostic(
                "OASTS1433",
                format!(
                    "operation '{}' security scheme '{}' uses an unrecognized security scheme kind, which the fetch client cannot serialize",
                    operation_label(operation),
                    scheme.name
                ),
                &scheme.source,
                Severity::Error,
            ));
            None
        }
    };
    kind.map(|kind| AuthSchemeUse {
        name: scheme.name.clone(),
        kind,
        scopes: scopes.to_vec(),
    })
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
        SecKind::Http { .. } | SecKind::OAuth2 { .. } | SecKind::OpenIdConnect { .. } => {
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
    if servers.get(index).is_none() {
        sink.push(source_diagnostic(
            "OASTS1420",
            format!("operation has no effective server at index {index}"),
            &operation.source,
            Severity::Error,
        ));
    }
}

fn has_relative_server_url(base_url: &BaseUrlPlan) -> bool {
    let BaseUrlPlan::Server { servers, .. } = base_url else {
        return false;
    };
    servers.iter().any(|server| {
        let mut substituted = server.url.clone();
        for (name, variable) in &server.variables {
            substituted = substituted.replace(&format!("{{{name}}}"), &variable.default);
        }
        !is_absolute_url(&substituted)
    })
}

/// Multipart-only admission matrix for an explicit encoding `style`/`explode` keyword (OASTS1427).
///
/// The OAS 3.1.1 Encoding Object defines per-part serialization for a narrow set of shapes: a
/// primitive — text or binary alike, any style/explode — always maps to its existing scalar
/// payload, and an array of primitives maps to `form`+`explode:true` repeated parts (the spec
/// default, whether explicit or defaulted). Every other combination — `form`+`explode:false`, the
/// delimited/deep styles at any explode, or any shape that resolves to a JSON part (an object, or
/// an array whose items do) — has no defined per-part wire mapping, so it is rejected here rather
/// than letting the emitter reuse the JSON-with-no-content-type shortcut it takes for unstyled
/// object fields.
///
/// "Resolves to a JSON part" reuses `default_part_media` — the same classifier `content_field_parts`
/// (field-payload planning) already applies to this field — rather than a raw domain-bit test, for
/// two reasons that both matter here:
///   - An allOf-of-objects schema lowers to a synthetic `AllOf` node, never a `SchemaNode::Object`;
///     `default_part_media`'s catch-all (`projector.project(resolved) == Known(OBJECT)`) already
///     handles it, so this stays caught as object-shaped instead of falling through as unclassified.
///   - A schemaless 3.1 field (`SchemaNode::Any`/`Finite`) is the *only* way to express a binary
///     upload in 3.1 (`default_part_media`'s dedicated arm), but projects to `Domain::FULL` — which
///     includes the `OBJECT` bit. A domain-bit test would misclassify it as object-shaped and
///     reject the binary-passthrough case the admission matrix must support; `default_part_media`
///     resolves it to `application/octet-stream`, not JSON, so it correctly passes through here.
fn multipart_style_admission_rejected(
    style: ParamStyle,
    explode: bool,
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> bool {
    let is_array = matches!(
        projector.project(schema),
        Projection::Known(domain) if domain.contains(Domain::ARRAY)
    );
    if is_array {
        let items_are_object =
            array_item_media(schema, version, projector) == Some(JSON_PART_MEDIA);
        items_are_object || style != ParamStyle::Form || !explode
    } else {
        default_part_media(schema, version, projector, &mut HashSet::new()).0 == JSON_PART_MEDIA
    }
}

/// The default part media of a resolved `Array` node's item schema, via the same
/// `default_part_media` classifier. Anything else — a `Tuple`, or a shape the projector cannot
/// resolve down to a concrete `Array` node — reports `None` so
/// `multipart_style_admission_rejected` falls back to the array-of-primitives branch rather than
/// guessing at item shape.
fn array_item_media(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> Option<&'static str> {
    match projector.resolve_schema(schema) {
        Some(SchemaNode::Array { items, .. }) => {
            Some(default_part_media(items, version, projector, &mut HashSet::new()).0)
        }
        _ => None,
    }
}

fn diagnose_form_media(
    media: &MediaType,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
    let multipart = media.essence.starts_with("multipart/");
    if !multipart && media.essence != "application/x-www-form-urlencoded" {
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
        if multipart
            && media.oas_version == OasVersion::V3_0
            && encoding.is_some_and(|encoding| {
                encoding.style.is_some()
                    || encoding.explode.is_some()
                    || encoding.allow_reserved_explicit
            })
        {
            let encoding = encoding.expect("multipart style keywords require an Encoding Object");
            sink.push(source_diagnostic(
                CODE_MULTIPART_30_STYLE_IGNORED,
                "multipart encoding style keywords apply only to urlencoded bodies in OpenAPI 3.0 and are ignored",
                &encoding.source,
                Severity::Warning,
            ));
        }
        let style_applicable = encoding.is_some_and(|encoding| {
            (!multipart || media.oas_version == OasVersion::V3_1)
                && (encoding.style.is_some()
                    || encoding.explode.is_some()
                    || encoding.allow_reserved_explicit)
        });
        if style_applicable {
            let encoding = encoding.expect("style applicability requires an Encoding Object");
            if encoding.content_type.is_some() {
                sink.push(source_diagnostic(
                    CODE_URLENCODED_CONTENT_TYPE_IGNORED,
                    format!(
                        "urlencoded field '{name}' declares explicit serialization so encoding.contentType is ignored"
                    ),
                    &encoding.source,
                    Severity::Warning,
                ));
            }
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
            // Multipart-only: 3.0 multipart style keywords never reach this branch (`style_applicable`
            // requires `multipart => V3_1`), so `multipart` alone is the correct 3.1 gate. Independent
            // of the query-legality check above — both can fire on the same field, since they test
            // different things (is this a legal style/explode combination at all, vs. does multipart
            // define any per-part wire mapping for it).
            if multipart
                && multipart_style_admission_rejected(
                    style,
                    explode,
                    schema,
                    media.oas_version,
                    projector,
                )
            {
                sink.push(source_diagnostic(
                    CODE_MULTIPART_STYLE_UNDEFINED,
                    format!(
                        "multipart field '{name}' has no defined per-part serialization for {style:?}/explode={explode} with this schema shape; use encoding.contentType instead"
                    ),
                    &encoding.source,
                    Severity::Error,
                ));
            }
        } else {
            if let Some(encoding) = encoding
                && let Some(values) = &encoding.content_type
            {
                for value in values {
                    if crate::media::canonical_encoding_content_type(value).is_err() {
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
            // A urlencoded body is a text format (OAS 3.1.1), so a field whose default part media is
            // binary has no representation; require multipart or base64url instead of silently
            // corrupting the wire. Independent of the content-type check above: an explicit
            // `encoding.contentType` overrides the *declared* media but cannot make a binary schema
            // representable in a text format, so the shape check runs on both content paths.
            if !multipart
                && default_part_media(schema, media.oas_version, projector, &mut HashSet::new()).1
            {
                sink.push(source_diagnostic(
                    "OASTS1423",
                    format!(
                        "form field '{name}' has a binary payload that application/x-www-form-urlencoded cannot represent; use multipart/form-data for binary uploads or base64-encode the value (type: string, contentEncoding: base64url)"
                    ),
                    &property.source,
                    Severity::Error,
                ));
            }
            // A structured urlencoded field (object, or an array bottoming out at objects) under a
            // text media type has no wire representation: the form-explode serializer drops an
            // object's field name (`meta: {a:1}` → `a=1`) and throws on an array of objects — both
            // silent corruption on a type-correct call. `default_part_media == application/json`
            // (itself ref-cycle guarded) identifies the structured shapes, whose default media is
            // already JSON, so only an explicitly declared text media can misroute them. For such a
            // schema `content_payload_kind` returns Text exactly when the media essence is `text/*`,
            // so match the essence case-insensitively (media types are case-insensitive) without
            // re-parsing the value or re-walking the schema. Scope: urlencoded only — the multipart
            // analog is pre-existing.
            if !multipart
                && default_part_media(schema, media.oas_version, projector, &mut HashSet::new()).0
                    == "application/json"
                && let Some(values) = encoding.and_then(|encoding| encoding.content_type.as_ref())
            {
                let declares_text = values.iter().any(|value| {
                    media_essence(value)
                        .to_ascii_lowercase()
                        .starts_with("text/")
                });
                if declares_text {
                    sink.push(source_diagnostic(
                        "OASTS1424",
                        format!(
                            "form field '{name}' declares a text media type but its schema is an object; use application/json (or a *+json media type) for structured urlencoded values"
                        ),
                        &property.source,
                        Severity::Error,
                    ));
                }
            }
        }
        if multipart {
            diagnose_multipart_headers(name, encoding, projector, sink);
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
    encoding: Option<&EncodingObject>,
    projector: &PrimitiveDomainProjector<'_>,
    sink: &mut DiagnosticSink,
) {
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
                if finite_string_values(&header.schema, projector).is_some_and(|values| {
                    values.is_empty() || values.iter().any(|value| !admitted_cte(value))
                }) {
                    sink.push(source_diagnostic(
                        "OASTS1415",
                        format!(
                            "declared Content-Transfer-Encoding for field '{field_name}' includes a value other than 7bit, 8bit, or binary and is never emitted"
                        ),
                        &header.source,
                        Severity::Warning,
                    ));
                }
            }
            _ => sink.push(source_diagnostic(
                "OASTS1417",
                format!(
                    "multipart field '{field_name}' declares header '{header_name}', but it is never emitted because multipart/form-data forbids senders including it"
                ),
                &header.source,
                Severity::Warning,
            )),
        }
    }
}

fn admitted_cte(value: &str) -> bool {
    ["7bit", "8bit", "binary"]
        .iter()
        .any(|admitted| value.eq_ignore_ascii_case(admitted))
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
        if media.streaming_marked || media.essence == "text/event-stream" {
            sink.push(source_diagnostic(
                "OASTS1402",
                format!(
                    "request body media '{}' requires streaming support, which is not yet available",
                    media.essence
                ),
                &media.source,
                Severity::Error,
            ));
        } else if is_xml(&media.essence) {
            sink.push(source_diagnostic(
                "OASTS1403",
                format!(
                    "request body media '{}' is XML, which Oasts does not support",
                    media.essence
                ),
                &media.source,
                Severity::Error,
            ));
        } else if media.essence.starts_with("text/")
            && media.schema_present
            && projection_excludes_string(projector.project(&media.schema))
        {
            sink.push(source_diagnostic(
                "OASTS1405",
                format!(
                    "top-level text request media '{}' requires a schema whose primitive projection contains string",
                    media.essence
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
    for media in &response.media_types {
        if static_bodyless {
            sink.push(source_diagnostic(
                "OASTS1406",
                format!(
                    "response key '{}' is statically bodyless but declares media '{}'",
                    response_status_name(&response.status),
                    media.essence
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
                    media.essence
                ),
                &media.source,
                Severity::Error,
            )),
            DecoderClass::Xml => sink.push(source_diagnostic(
                "OASTS1403",
                format!(
                    "response media '{}' is XML, which Oasts does not support",
                    media.essence
                ),
                &media.source,
                Severity::Error,
            )),
            DecoderClass::Multipart => sink.push(source_diagnostic(
                "OASTS1404",
                format!(
                    "multipart response media '{}' is not supported",
                    media.essence
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
                        media.essence
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
    if media.streaming_marked || media.essence == "text/event-stream" {
        DecoderClass::Streaming
    } else if is_json(&media.essence) {
        DecoderClass::Json
    } else if is_xml(&media.essence) {
        DecoderClass::Xml
    } else if media.essence.starts_with("multipart/") {
        DecoderClass::Multipart
    } else if media.essence == "application/x-www-form-urlencoded"
        || media.essence.starts_with("text/")
    {
        DecoderClass::Text
    } else {
        DecoderClass::Binary
    }
}

/// Whether a response header's declared value is an opaque wire string rather than its typed schema.
/// A content-sourced header whose media type is not JSON-family (RFC 8259, plus the `+json`
/// structured suffix) transmits a caller-parsed string on the wire, so both the emitted header type
/// and its validator treat it as a bare `string`; JSON-family and schema+style headers keep their
/// schema.
pub(crate) fn response_header_is_opaque_string(header: &crate::ir::ResponseHeader) -> bool {
    header
        .content_media_type
        .as_deref()
        .is_some_and(|media| !is_json(media))
}

fn build_accept<'a>(
    declared: impl IntoIterator<Item = (&'a str, MediaRangeKind)>,
) -> Option<String> {
    let mut concrete = BTreeSet::new();
    let mut typed_ranges = BTreeSet::new();
    let mut any = false;
    // Classify by the parsed range kind, never by probing the full string: a parameterized range
    // (`text/*; q=0.5`) carries the `*` mid-string, so `ends_with("/*")` would miss it and stamp it
    // into the concrete set.
    for (media, kind) in declared {
        match kind {
            MediaRangeKind::Any => any = true,
            MediaRangeKind::TypeRange => {
                typed_ranges.insert(media);
            }
            MediaRangeKind::Concrete => {
                concrete.insert(media);
            }
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
    schemas: &'ir [crate::ir::NamedSchema],
    indices: HashMap<(&'ir str, &'ir str), usize>,
    domains: Vec<Projection>,
}

impl<'ir> PrimitiveDomainProjector<'ir> {
    fn new(ir: &'ir Ir) -> Self {
        let schemas = ir.schemas.as_slice();
        if schemas.is_empty() {
            return Self {
                schemas,
                indices: HashMap::new(),
                domains: Vec::new(),
            };
        }
        let mut indices = HashMap::with_capacity(schemas.len());
        for (index, schema) in schemas.iter().enumerate() {
            indices.insert(
                (
                    schema.source.source_id.as_str(),
                    schema.source.json_pointer.as_str(),
                ),
                index,
            );
        }

        let mut reverse_offsets = vec![0; schemas.len() + 1];
        let mut dependencies = Vec::new();
        for schema in schemas {
            dependencies.clear();
            collect_projection_dependencies(&schema.schema, &indices, &mut dependencies);
            dependencies.sort_unstable();
            dependencies.dedup();
            for &dependency in &dependencies {
                reverse_offsets[dependency + 1] += 1;
            }
        }
        for index in 1..reverse_offsets.len() {
            reverse_offsets[index] += reverse_offsets[index - 1];
        }
        let mut reverse_dependencies = vec![0; reverse_offsets[schemas.len()]];
        let mut cursors = reverse_offsets[..schemas.len()].to_vec();
        for (source, schema) in schemas.iter().enumerate() {
            dependencies.clear();
            collect_projection_dependencies(&schema.schema, &indices, &mut dependencies);
            dependencies.sort_unstable();
            dependencies.dedup();
            for &dependency in &dependencies {
                reverse_dependencies[cursors[dependency]] = source;
                cursors[dependency] += 1;
            }
        }
        drop(cursors);
        drop(dependencies);

        // Starting every component at FULL and only propagating changes preserves the previous
        // greatest-fixed-point behavior for recursive schemas. A pure ref cycle stays FULL, while
        // changes introduced by a dependency propagate to every affected schema.
        let mut domains = vec![Projection::Known(Domain::FULL); schemas.len()];
        let mut queue = (0..schemas.len()).collect::<VecDeque<_>>();
        let mut queued = vec![true; schemas.len()];
        while let Some(index) = queue.pop_front() {
            queued[index] = false;
            let next = project_schema(&schemas[index].schema, &indices, &domains);
            if next == domains[index] {
                continue;
            }
            domains[index] = next;
            for &dependent in
                &reverse_dependencies[reverse_offsets[index]..reverse_offsets[index + 1]]
            {
                if !queued[dependent] {
                    queue.push_back(dependent);
                    queued[dependent] = true;
                }
            }
        }

        Self {
            schemas,
            indices,
            domains,
        }
    }

    fn project(&self, schema: &SchemaNode) -> Projection {
        project_schema(schema, &self.indices, &self.domains)
    }

    fn resolve_schema<'schema>(
        &'schema self,
        schema: &'schema SchemaNode,
    ) -> Option<&'schema SchemaNode>
    where
        'ir: 'schema,
    {
        let mut current = schema;
        let mut seen = HashSet::new();
        while let SchemaNode::Ref { target, .. } = current {
            let index = schema_index(&self.indices, &target.source_id, &target.json_pointer)?;
            if !seen.insert(index) {
                return None;
            }
            current = &self.schemas.get(index)?.schema;
        }
        Some(current)
    }
}

fn schema_index(
    indices: &HashMap<(&str, &str), usize>,
    source_id: &str,
    json_pointer: &str,
) -> Option<usize> {
    indices.get(&(source_id, json_pointer)).copied()
}

fn collect_projection_dependencies(
    schema: &SchemaNode,
    indices: &HashMap<(&str, &str), usize>,
    dependencies: &mut Vec<usize>,
) {
    match schema {
        SchemaNode::Ref { target, .. } => {
            if let Some(index) = schema_index(indices, &target.source_id, &target.json_pointer) {
                dependencies.push(index);
            }
        }
        SchemaNode::AllOf { branches, .. }
        | SchemaNode::OneOf { branches, .. }
        | SchemaNode::AnyOf { branches, .. } => {
            for branch in branches {
                collect_projection_dependencies(branch, indices, dependencies);
            }
        }
        SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Object { .. }
        | SchemaNode::Array { .. }
        | SchemaNode::Tuple { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => {}
    }
}

fn project_schema(
    schema: &SchemaNode,
    indices: &HashMap<(&str, &str), usize>,
    domains: &[Projection],
) -> Projection {
    let (base, apply_nullable) = match schema {
        SchemaNode::Ref { target, .. } => (
            schema_index(indices, &target.source_id, &target.json_pointer)
                .and_then(|index| domains.get(index).copied())
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
                .map(|branch| project_schema(branch, indices, domains))
                .reduce(intersect_projection)
                .unwrap_or(Projection::Known(Domain::FULL)),
            true,
        ),
        SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => (
            branches
                .iter()
                .map(|branch| project_schema(branch, indices, domains))
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
            essence: name.to_owned(),
            full: name.to_owned(),
            // Every classifier fixture is a concrete media; range_kind is inert for decoder tests.
            range_kind: MediaRangeKind::Concrete,
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

    fn projection_chain(length: usize, missing_terminal: bool) -> Ir {
        assert!(length > 0);
        let mut schemas = Vec::with_capacity(length);
        for index in 0..length {
            let name = format!("S{index}");
            let pointer = format!("/components/schemas/{name}");
            let schema = if index + 1 < length {
                SchemaNode::Ref {
                    target: SchemaRef {
                        source_id: "openapi.json".to_owned(),
                        json_pointer: format!("/components/schemas/S{}", index + 1),
                    },
                    meta: test_meta(&pointer),
                }
            } else if missing_terminal {
                SchemaNode::Ref {
                    target: SchemaRef {
                        source_id: "openapi.json".to_owned(),
                        json_pointer: "/components/schemas/Missing".to_owned(),
                    },
                    meta: test_meta(&pointer),
                }
            } else {
                test_primitive(PrimitiveType::String, &pointer)
            };
            schemas.push(NamedSchema {
                name,
                schema,
                source: SourceRef::new("openapi.json", pointer),
            });
        }
        Ir {
            schemas,
            ..Ir::default()
        }
    }

    #[test]
    fn accept_builder_orders_concrete_then_typed_ranges_then_any() {
        use MediaRangeKind::{Any, Concrete, TypeRange};
        for (declared, expected) in [
            (
                vec![
                    ("application/xml", Concrete),
                    ("application/json", Concrete),
                    ("text/plain", Concrete),
                ],
                Some("application/json, application/xml, text/plain"),
            ),
            (
                vec![
                    ("*/*", Any),
                    ("text/*", TypeRange),
                    ("application/json", Concrete),
                    ("image/*", TypeRange),
                ],
                Some("application/json, image/*, text/*, */*"),
            ),
            (
                vec![
                    ("application/json", Concrete),
                    ("application/json", Concrete),
                    ("text/plain", Concrete),
                    ("*/*", Any),
                    ("*/*", Any),
                ],
                Some("application/json, text/plain, */*"),
            ),
            // A parameterized type range is bucketed by its parsed kind, never by a full-string
            // probe: its canonical carries `*` mid-string, yet it stays out of the concrete set.
            (
                vec![("text/*;q=0.5", TypeRange), ("application/json", Concrete)],
                Some("application/json, text/*;q=0.5"),
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
        // Discriminated arms are ordered by canonical-full-type byte order, not source order (the
        // request body declares `text/plain` before `application/json`).
        assert_eq!(
            arms.iter()
                .map(|(media, _)| media.as_str())
                .collect::<Vec<_>>(),
            ["application/json", "text/plain"]
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
        assert!(matches!(
            &first.base_url,
            BaseUrlPlan::Server { index: 0, servers } if servers[0].url == "https://{host}/v1"
        ));
        assert_eq!(first.auth_plan, vec![Vec::new()]);
        assert_eq!(first.credential_headers, ["authorization"]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn response_media_plans_key_on_canonical_full_type() {
        // A parameter-differing key is a distinct response arm keyed on its canonical full type,
        // while decoding stays essence-keyed: `application/json;stream=watch` decodes as JSON.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/watch": {
                    "get": {
                        "operationId": "watch",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "type": "object" } },
                                    "application/json; stream=watch": { "schema": { "type": "object" } }
                                }
                            }
                        }
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
        let response = &model.operations[0].response_table[0];
        assert!(response.content_type_discriminated);
        assert_eq!(
            response
                .media
                .iter()
                .map(|media| media.media.as_str())
                .collect::<Vec<_>>(),
            ["application/json", "application/json;stream=watch"]
        );
        assert!(
            response
                .media
                .iter()
                .all(|media| media.decoder == DecoderClass::Json)
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn request_body_arms_discriminate_on_canonical_full_media_types() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/submit": {
                    "post": {
                        "operationId": "submit",
                        "requestBody": {
                            "content": {
                                "application/json; v=2": { "schema": { "type": "object" } },
                                "application/json; v=1": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json; profile=full": { "schema": { "type": "object" } },
                                    "application/json": { "schema": { "type": "object" } }
                                }
                            }
                        }
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
        let operation = &model.operations[0];
        let (arms, all_concrete) = operation
            .body_plan
            .as_ref()
            .expect("body plan")
            .discriminated_arms()
            .expect("discriminated body");
        // Two parameter-differing JSON keys are two distinct arms, ordered by canonical byte order
        // regardless of source order.
        assert_eq!(
            arms.iter()
                .map(|(media, _)| media.as_str())
                .collect::<Vec<_>>(),
            ["application/json;v=1", "application/json;v=2"]
        );
        assert!(all_concrete);
        // Essence-based classification: a parameterized JSON key still serializes as JSON.
        assert!(
            arms.iter()
                .all(|(_, plan)| matches!(plan, BodyPlan::Json { .. }))
        );
        // Accept lists canonical full response forms in deterministic order.
        assert_eq!(
            operation.accept.as_deref(),
            Some("application/json, application/json;profile=full")
        );
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
        assert!(urlencoded_fields(body).is_none());

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
        // `application/json, application/*`: the object schema classifies the wildcard tier via the
        // object fallback, so both admitted media types resolve to JSON payloads.
        assert_eq!(
            fields[0]
                .serialization
                .content_media()
                .expect("content branch")
                .payloads,
            [PayloadKind::Json, PayloadKind::Json]
        );
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
    fn multipart_content_encoding_preserves_only_string_shaped_payloads() {
        // A `contentEncoding` annotation means a string instance is already encoded. An object part
        // keeps its JSON payload, while a string part passes its UTF-8 bytes through as text.
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
                                            "structured": { "type": "object", "contentEncoding": "binary" },
                                            "raw": { "type": "string", "contentEncoding": "binary" }
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
        let field = |name: &str| {
            fields
                .iter()
                .find(|field| field.name == name)
                .expect("field")
        };
        // Object part: JSON payload and object input preserved.
        let structured = field("structured");
        assert!(matches!(structured.schema, SchemaNode::Object { .. }));
        assert_eq!(
            structured
                .serialization
                .content_media()
                .expect("content")
                .values,
            ["application/json"]
        );
        assert_eq!(field_payloads(structured), [PayloadKind::Json]);
        // The encoded instance string remains a text payload; no CTE header is planned.
        assert_eq!(field_payloads(field("raw")), [PayloadKind::Text]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn multipart_content_encoding_classifies_through_conjunction_branches() {
        // A 3.1 part schema carrying `contentEncoding` beside a `$ref` lowers to a synthetic AllOf
        // whose typed branch holds the annotation (SchemaMeta::split_for_conjunction). The part-media
        // classifier must resolve the encoding through that branch exactly as it resolves the shape,
        // so both spellings of a base64 string part classify identically as application/octet-stream
        // — not text/plain for the lowered one.
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": { "Base": { "type": "string" } }
            },
            "paths": {
                "/upload": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "direct": { "type": "string", "contentEncoding": "binary" },
                                            "viaRef": {
                                                "$ref": "#/components/schemas/Base",
                                                "contentEncoding": "binary"
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
        let field = |name: &str| {
            fields
                .iter()
                .find(|field| field.name == name)
                .expect("field")
        };
        let media = |name: &str| {
            field(name)
                .serialization
                .content_media()
                .expect("content")
                .values
                .clone()
        };
        assert_eq!(media("direct"), ["application/octet-stream"]);
        assert_eq!(media("viaRef"), media("direct"));
        // Both spellings preserve the already-encoded instance string as a text payload.
        for name in ["direct", "viaRef"] {
            assert_eq!(field_payloads(field(name)), [PayloadKind::Text]);
        }
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn multipart_wrapper_ignores_all_declared_part_headers() {
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

        for field in fields {
            assert!(!field.wrapper.wrapped);
            assert!(field.serialization.content_media().is_some());
        }
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
                                            "encodedTypeless": { "contentEncoding": "binary" },
                                            "encoded": { "type": "string", "contentEncoding": "binary" },
                                            "object": { "type": "object" },
                                            "objects": { "type": "array", "items": { "type": "object" } },
                                            "primitive": { "type": "boolean" },
                                            "styled": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "styled": { "style": "form" }
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
        // `styled` is an OAS 3.1 multipart field with an explicit `style`, so it resolves to the
        // `Style` variant rather than `Content` and is skipped here; the other properties stay
        // Content-based and are asserted below.
        let media31 = fields
            .iter()
            .filter_map(|field| {
                let media = field.serialization.content_media()?;
                Some((
                    media.values[0].as_str(),
                    media.binary_upload,
                    media.payloads[0],
                ))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            media31,
            [
                ("application/octet-stream", true, PayloadKind::Binary),
                ("application/octet-stream", true, PayloadKind::Binary),
                // Schemaless 3.1 field with `contentEncoding`: the instance is the already-encoded
                // string, so it is a text payload without a CTE header, matching the typed row.
                ("application/octet-stream", false, PayloadKind::Text),
                ("application/octet-stream", false, PayloadKind::Text),
                ("application/json", false, PayloadKind::Json),
                ("application/json", false, PayloadKind::Json),
                ("text/plain", false, PayloadKind::Text),
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

    // Mirrors `BodyPlan::multipart_fields`: returns `None` for a non-urlencoded body so the `else`
    // arm is covered by a plain `is_none` assertion rather than a pipeline-running should_panic
    // test. Call sites `.expect` the Some.
    fn urlencoded_fields(body: &BodyPlan) -> Option<&[FormFieldPlan]> {
        if let BodyPlan::FormUrlencoded { fields, .. } = body {
            Some(fields)
        } else {
            None
        }
    }

    fn field_payloads(field: &FormFieldPlan) -> &[PayloadKind] {
        &field
            .serialization
            .content_media()
            .expect("content-based field")
            .payloads
    }

    #[test]
    fn urlencoded_content_fields_plan_payloads_and_ignore_headers() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "profile": {
                                                "type": "object",
                                                "properties": {
                                                    "nickname": { "type": "string" },
                                                    "age": { "type": "integer" }
                                                }
                                            },
                                            "icon": { "type": "string", "contentEncoding": "base64url" },
                                            "apiField": { "type": "object" },
                                            "leaky": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "icon": { "contentType": "image/png, image/jpeg" },
                                        "apiField": { "contentType": "application/vnd.api+json" },
                                        "leaky": {
                                            "contentType": "text/plain",
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "type": "string" } }
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
        let body = model.operations[0].body_plan.as_ref().expect("body plan");
        let fields = urlencoded_fields(body).expect("form-urlencoded body");
        let by_name = |name: &str| {
            fields
                .iter()
                .find(|field| field.name == name)
                .expect("field present")
        };

        // Object default → application/json → one JSON payload, unwrapped.
        let profile = by_name("profile");
        assert_eq!(field_payloads(profile), [PayloadKind::Json]);
        assert!(!profile.wrapper.wrapped);

        // OAS icon shape: two admitted media types → two text payloads, wrapped. Its base64url
        // `contentEncoding` does not add a CTE to a urlencoded body.
        let icon = by_name("icon");
        assert_eq!(field_payloads(icon), [PayloadKind::Text, PayloadKind::Text]);
        assert!(icon.wrapper.wrapped);

        // `+json` suffix classifies as JSON.
        assert_eq!(field_payloads(by_name("apiField")), [PayloadKind::Json]);

        // Encoding Object `headers` SHALL be ignored for non-multipart bodies, so the caller
        // Content-Transfer-Encoding header must not wrap the field.
        let leaky = by_name("leaky");
        assert_eq!(field_payloads(leaky), [PayloadKind::Text]);
        assert!(!leaky.wrapper.wrapped);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn urlencoded_array_fields_classify_payload_by_items() {
        // A urlencoded array field under a non-JSON, non-text explicit media falls back to the
        // schema shape, which for an array is decided by its (ref-resolved) items — mirroring
        // `default_part_media`. Misclassifying an array-of-objects as `text` would emit
        // `payloads: ["text"]` and blow up in `isParamValue` at runtime on every call.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "objs": { "type": "array", "items": { "type": "object", "properties": { "tag": { "type": "string" } } } },
                                            "strs": { "type": "array", "items": { "type": "string" } },
                                            "refs": { "type": "array", "items": { "$ref": "#/components/schemas/Thing" } },
                                            "nested": { "type": "array", "items": { "type": "array", "items": { "type": "object" } } }
                                        }
                                    },
                                    "encoding": {
                                        "objs": { "contentType": "application/octet-stream" },
                                        "strs": { "contentType": "application/octet-stream" },
                                        "refs": { "contentType": "application/octet-stream" },
                                        "nested": { "contentType": "application/octet-stream" }
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
                    "Thing": { "type": "object", "properties": { "id": { "type": "string" } } }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let fields = urlencoded_fields(model.operations[0].body_plan.as_ref().expect("body plan"))
            .expect("form-urlencoded body");
        let payloads = |name: &str| -> Vec<PayloadKind> {
            field_payloads(
                fields
                    .iter()
                    .find(|field| field.name == name)
                    .expect("field"),
            )
            .to_vec()
        };
        assert_eq!(payloads("objs"), [PayloadKind::Json]);
        assert_eq!(payloads("strs"), [PayloadKind::Text]);
        assert_eq!(payloads("refs"), [PayloadKind::Json]);
        assert_eq!(payloads("nested"), [PayloadKind::Json]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn urlencoded_json_id_field_is_json_payload() {
        // A string field with `contentType: application/json` is JSON-serialized (quotes kept on the
        // wire), so the JSON media branch wins over the string schema shape.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "id": { "contentType": "application/json" }
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
        let fields = urlencoded_fields(model.operations[0].body_plan.as_ref().expect("body plan"))
            .expect("form-urlencoded body");
        assert_eq!(field_payloads(&fields[0]), [PayloadKind::Json]);
        assert!(!fields[0].wrapper.wrapped);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn urlencoded_content_flows_for_3_0() {
        // The content path is version-agnostic: a 3.0 object field defaults to application/json.
        let document = json!({
            "openapi": "3.0.3",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "profile": {
                                                "type": "object",
                                                "properties": {
                                                    "nickname": { "type": "string" }
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
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let fields = urlencoded_fields(model.operations[0].body_plan.as_ref().expect("body plan"))
            .expect("form-urlencoded body");
        assert_eq!(field_payloads(&fields[0]), [PayloadKind::Json]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn urlencoded_media_classifies_by_essence_not_full_value() {
        // A parameterized `application/json; charset=utf-8` is JSON on the wire; keying on the full
        // canonical value would fall through to the string schema fallback and ship the field
        // unquoted (silent wire corruption). Essence classification routes it to JSON.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "jsonish": { "type": "string" },
                                            "textish": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "jsonish": { "contentType": "application/json; charset=utf-8" },
                                        "textish": { "contentType": "text/plain; charset=utf-8" }
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
        let fields = urlencoded_fields(model.operations[0].body_plan.as_ref().expect("body plan"))
            .expect("form-urlencoded body");
        let payloads = |name: &str| -> &[PayloadKind] {
            field_payloads(
                fields
                    .iter()
                    .find(|field| field.name == name)
                    .expect("field"),
            )
        };
        assert_eq!(payloads("jsonish"), [PayloadKind::Json]);
        assert_eq!(payloads("textish"), [PayloadKind::Text]);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn form_media_classifiers_survive_ref_cyclic_array_schemas() {
        // A schema-position ref cycle through array items is accepted by the loader; the media
        // classifiers must not recurse it until the stack overflows and aborts the host process
        // (SIGABRT). Both a self-cycle (`Tree`) and a two-hop cycle (`A`↔`B`) are placed in a
        // urlencoded and a multipart body — every classifier path is exercised. A revisit resolves
        // to the terminal fallback, so classification stays deterministic.
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "Tree": { "type": "array", "items": { "$ref": "#/components/schemas/Tree" } },
                    "A": { "type": "array", "items": { "$ref": "#/components/schemas/B" } },
                    "B": { "type": "array", "items": { "$ref": "#/components/schemas/A" } }
                }
            },
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "tree": { "$ref": "#/components/schemas/Tree" },
                                            "pair": { "$ref": "#/components/schemas/A" }
                                        }
                                    }
                                },
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "tree": { "$ref": "#/components/schemas/Tree" },
                                            "pair": { "$ref": "#/components/schemas/A" }
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
        let (_temp, analyzed, config, _sink) = analyzed_with_diagnostics(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        // Reaching this line without a stack overflow is the assertion; the arms classify
        // deterministically via the terminal fallback.
        let model = build_client_model(&analyzed, &config, &mut sink);
        assert!(model.operations[0].body_plan.is_some());
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
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn delimited_query_helpers_follow_the_projected_domain() {
        for (style, projection, expected) in [
            (
                ParamStyle::SpaceDelimited,
                Projection::Known(Domain::OBJECT),
                HelperId::QuerySpaceDelimitedObject,
            ),
            (
                ParamStyle::SpaceDelimited,
                Projection::Known(Domain::ARRAY),
                HelperId::QuerySpaceDelimited,
            ),
            (
                ParamStyle::SpaceDelimited,
                Projection::Unsupported,
                HelperId::QuerySpaceDelimited,
            ),
            (
                ParamStyle::PipeDelimited,
                Projection::Known(Domain::OBJECT),
                HelperId::QueryPipeDelimitedObject,
            ),
            (
                ParamStyle::PipeDelimited,
                Projection::Known(Domain::ARRAY),
                HelperId::QueryPipeDelimited,
            ),
            (
                ParamStyle::PipeDelimited,
                Projection::Unsupported,
                HelperId::QueryPipeDelimited,
            ),
        ] {
            assert_eq!(
                helper_id(ParamLocation::Query, style, false, projection),
                expected
            );
        }
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
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Cookie,
                ParamStyle::Simple,
                false,
                HelperId::QueryForm,
            ),
        ] {
            assert_eq!(
                helper_id(location, style, explode, Projection::Unsupported),
                expected
            );
        }

        let empty_ir = Ir::default();
        let projector = PrimitiveDomainProjector::new(&empty_ir);
        assert!(build_body_plan(&[], &projector).is_none());
        let any_media = classifier_media("multipart/form-data", false);
        assert!(form_fields(&any_media, true, &projector).is_empty());
        let mut diagnostic_sink = DiagnosticSink::new();
        diagnose_form_media(&any_media, &projector, &mut diagnostic_sink);
        assert!(diagnostic_sink.as_slice().is_empty());
        assert!(!invalid_style_combination(
            ParamLocation::Cookie,
            ParamStyle::Form,
            false,
            Projection::Known(Domain::STRING)
        ));
        assert!(invalid_style_combination(
            ParamLocation::Cookie,
            ParamStyle::Simple,
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
            default_part_media(
                &unresolved,
                OasVersion::V3_1,
                &projector,
                &mut HashSet::new()
            ),
            ("application/octet-stream", false)
        );
        let object_composition = SchemaNode::AllOf {
            branches: vec![
                SchemaNode::Any {
                    meta: test_meta("/any"),
                },
                SchemaNode::Object {
                    properties: Vec::new(),
                    additional_properties: crate::ir::AdditionalProperties::Allowed(None),
                    dependent_required: Vec::new(),
                    finite: None,
                    extra_required: Vec::new(),
                    meta: test_meta("/object"),
                },
            ],
            meta: test_meta("/composition"),
        };
        assert_eq!(
            default_part_media(
                &object_composition,
                OasVersion::V3_1,
                &projector,
                &mut HashSet::new()
            ),
            ("application/json", false)
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
        let diagnostic = source_diagnostic("OASTS1419", "located", &located, Severity::Error);
        assert_eq!((diagnostic.line, diagnostic.col), (Some(7), Some(9)));

        let string = test_primitive(PrimitiveType::String, "/string");
        let tuple = SchemaNode::Tuple {
            prefix_items: Vec::new(),
            rest: crate::ir::TupleRest::Allowed,
            finite: None,
            meta: test_meta("/tuple"),
        };
        assert_eq!(schema_admits_string(&tuple, "x", &projector), Some(false));
        assert!(string_constraints_admit(None, None, "x"));
        assert!(string_constraints_admit(
            Some(&[json!("y"), json!("x")]),
            None,
            "x"
        ));
        assert!(!string_constraints_admit(Some(&[json!("y")]), None, "x"));
        assert!(!string_constraints_admit(
            Some(&[json!("x")]),
            Some(&json!("y")),
            "x"
        ));
        assert_eq!(
            schema_admits_string(
                &SchemaNode::Unknown {
                    reason: "test".to_owned(),
                    meta: test_meta("/unknown"),
                },
                "x",
                &projector,
            ),
            None
        );
        assert_eq!(finite_string_values(&tuple, &projector), None);
        assert_eq!(finite_string_values(&string, &projector), None);
        assert_eq!(
            finite_string_values(
                &SchemaNode::Ref {
                    target: SchemaRef {
                        source_id: "missing.json".to_owned(),
                        json_pointer: "/missing".to_owned(),
                    },
                    meta: test_meta("/missing-ref"),
                },
                &projector,
            ),
            None
        );
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
            discriminator: None,
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
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
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
        assert_eq!(
            cycle_projector.project(&cycle_ir.schemas[0].schema),
            Projection::Known(Domain::FULL)
        );
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
                    bearer_format: None,
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
            callbacks: Vec::new(),
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
        let schemes = index_security_schemes(&ir);
        let plan = plan_auth(&operation, &security, &schemes, OasVersion::V3_1, &mut sink);
        assert_eq!(
            plan,
            vec![
                vec![AuthSchemeUse {
                    name: "mutual".to_owned(),
                    kind: AuthKind::MutualTls,
                    scopes: Vec::new(),
                }],
                vec![
                    AuthSchemeUse {
                        name: "http".to_owned(),
                        kind: AuthKind::Bearer,
                        scopes: Vec::new(),
                    },
                    AuthSchemeUse {
                        name: "mutual".to_owned(),
                        kind: AuthKind::MutualTls,
                        scopes: Vec::new(),
                    },
                ],
            ]
        );
        assert_eq!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1433")
                .count(),
            1
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
    fn delimited_style_domains_allow_one_nullable_collection_kind() {
        for (domain, space_invalid, pipe_invalid, deep_invalid) in [
            (Domain::ARRAY, false, false, true),
            (Domain::ARRAY.union(Domain::NULL), false, false, true),
            (Domain::OBJECT, false, false, false),
            (Domain::OBJECT.union(Domain::NULL), false, false, false),
            (Domain::ARRAY.union(Domain::OBJECT), true, true, true),
            (Domain::STRING, true, true, true),
        ] {
            for (style, explode, expected) in [
                (ParamStyle::SpaceDelimited, false, space_invalid),
                (ParamStyle::PipeDelimited, false, pipe_invalid),
                (ParamStyle::DeepObject, true, deep_invalid),
            ] {
                assert_eq!(
                    invalid_style_combination(
                        ParamLocation::Query,
                        style,
                        explode,
                        Projection::Known(domain),
                    ),
                    expected,
                    "unexpected result for {domain:?} with {style:?}",
                );
            }
        }
    }

    #[test]
    fn primitive_projection_worklist_propagates_long_chains_in_either_source_order() {
        const LENGTH: usize = 4096;
        for reversed in [false, true] {
            let mut ir = projection_chain(LENGTH, false);
            if reversed {
                ir.schemas.reverse();
            }
            let projector = PrimitiveDomainProjector::new(&ir);

            assert_eq!(projector.domains.len(), LENGTH);
            assert!(
                projector
                    .domains
                    .iter()
                    .all(|projection| *projection == Projection::Known(Domain::STRING))
            );
        }
    }

    #[test]
    fn primitive_projection_worklist_propagates_unsupported_targets() {
        const LENGTH: usize = 4096;
        let ir = projection_chain(LENGTH, true);
        let projector = PrimitiveDomainProjector::new(&ir);

        assert!(
            projector
                .domains
                .iter()
                .all(|projection| *projection == Projection::Unsupported)
        );
    }

    #[test]
    fn primitive_projection_worklist_propagates_constraints_through_cycles() {
        let reference = |name: &str, pointer: &str| SchemaNode::Ref {
            target: SchemaRef {
                source_id: "openapi.json".to_owned(),
                json_pointer: format!("/components/schemas/{name}"),
            },
            meta: test_meta(pointer),
        };
        let ir = Ir {
            schemas: vec![
                NamedSchema {
                    name: "A".to_owned(),
                    schema: SchemaNode::AllOf {
                        branches: vec![
                            reference("B", "/components/schemas/A/allOf/0"),
                            test_primitive(PrimitiveType::String, "/components/schemas/A/allOf/1"),
                        ],
                        meta: test_meta("/components/schemas/A"),
                    },
                    source: SourceRef::new("openapi.json", "/components/schemas/A"),
                },
                NamedSchema {
                    name: "B".to_owned(),
                    schema: reference("A", "/components/schemas/B"),
                    source: SourceRef::new("openapi.json", "/components/schemas/B"),
                },
            ],
            ..Ir::default()
        };
        let projector = PrimitiveDomainProjector::new(&ir);

        assert!(
            projector
                .domains
                .iter()
                .all(|projection| *projection == Projection::Known(Domain::STRING))
        );
    }

    #[test]
    fn primitive_projection_worklist_tracks_composition_nullable_and_unknown_dependencies() {
        let reference = |name: &str, pointer: &str, nullable: bool| {
            let mut meta = test_meta(pointer);
            meta.nullable = nullable;
            SchemaNode::Ref {
                target: SchemaRef {
                    source_id: "openapi.json".to_owned(),
                    json_pointer: format!("/components/schemas/{name}"),
                },
                meta,
            }
        };
        let named = |name: &str, schema| NamedSchema {
            name: name.to_owned(),
            schema,
            source: SourceRef::new("openapi.json", format!("/components/schemas/{name}")),
        };
        let ir = Ir {
            schemas: vec![
                named(
                    "Any",
                    SchemaNode::AnyOf {
                        branches: vec![
                            reference("String", "/components/schemas/Any/anyOf/0", false),
                            test_primitive(
                                PrimitiveType::Number,
                                "/components/schemas/Any/anyOf/1",
                            ),
                        ],
                        discriminator: None,
                        meta: test_meta("/components/schemas/Any"),
                    },
                ),
                named(
                    "One",
                    SchemaNode::OneOf {
                        branches: vec![
                            reference("String", "/components/schemas/One/oneOf/0", false),
                            test_primitive(
                                PrimitiveType::Boolean,
                                "/components/schemas/One/oneOf/1",
                            ),
                        ],
                        discriminator: None,
                        meta: test_meta("/components/schemas/One"),
                    },
                ),
                named(
                    "Nullable",
                    reference("String", "/components/schemas/Nullable", true),
                ),
                named(
                    "UnknownRef",
                    reference("Unknown", "/components/schemas/UnknownRef", false),
                ),
                named(
                    "String",
                    test_primitive(PrimitiveType::String, "/components/schemas/String"),
                ),
                named(
                    "Unknown",
                    SchemaNode::Unknown {
                        reason: "test".to_owned(),
                        meta: test_meta("/components/schemas/Unknown"),
                    },
                ),
            ],
            ..Ir::default()
        };
        let projector = PrimitiveDomainProjector::new(&ir);

        assert_eq!(
            projector.domains,
            [
                Projection::Known(Domain::STRING.union(Domain::NUMBER)),
                Projection::Known(Domain::STRING.union(Domain::BOOLEAN)),
                Projection::Known(Domain::STRING.union(Domain::NULL)),
                Projection::Unsupported,
                Projection::Known(Domain::STRING),
                Projection::Unsupported,
            ]
        );
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
    fn informational_responses_produce_no_client_diagnostics() {
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

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
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
    fn oasts1402_streaming_precedes_other_response_classifiers() {
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
    fn oasts1403_rejects_xml_requests_and_responses() {
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
    fn oasts1404_rejects_only_multipart_responses() {
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
    fn oasts1405_requires_string_projection_for_text_branches() {
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
    fn oasts1405_defers_to_existing_unsupported_keyword_diagnostic() {
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
    fn oasts1406_warns_and_suppresses_classification_for_static_bodyless_media() {
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
    fn cookie_parameters_plan_as_form_without_diagnostics() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cookie": {
                    "get": {
                        "operationId": "cookieOp",
                        "parameters": [
                            { "name": "session", "in": "cookie", "schema": { "type": "string" } },
                            { "name": "safe", "in": "query", "schema": { "type": "string" } }
                        ],
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
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());

        let cookie = model.operations[0]
            .param_plans
            .iter()
            .find(|plan| plan.name == "session")
            .expect("cookie param plan");
        assert_eq!(
            cookie.resolved,
            ResolvedParameterSerialization {
                location: ParamLocation::Cookie,
                style: ParamStyle::Form,
                explode: true,
                allow_reserved: false,
                // A cookie parameter reuses the query-form serializer; location drives Cookie framing.
                helper: HelperId::QueryForm,
            }
        );
    }

    #[test]
    fn allow_reserved_is_forced_off_on_non_query_locations() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/cookie": {
                    "get": {
                        "operationId": "cookieOp",
                        "parameters": [
                            {
                                "name": "session",
                                "in": "cookie",
                                "allowReserved": true,
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "reserved",
                                "in": "query",
                                "allowReserved": true,
                                "schema": { "type": "string" }
                            }
                        ],
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

        let plans = &model.operations[0].param_plans;
        let cookie = plans
            .iter()
            .find(|plan| plan.name == "session")
            .expect("cookie param plan");
        assert!(
            !cookie.resolved.allow_reserved,
            "allowReserved must be forced off for a cookie parameter"
        );
        // The query parameter keeps allowReserved, proving the guard is scoped to non-query.
        let query = plans
            .iter()
            .find(|plan| plan.name == "reserved")
            .expect("query param plan");
        assert!(
            query.resolved.allow_reserved,
            "allowReserved stays honored for a query parameter"
        );
    }

    fn content_param_model(
        location: &str,
        media: &str,
        schema: Value,
    ) -> (ClientModel, Vec<Diagnostic>) {
        let required = location == "path";
        let path = if location == "path" {
            "/items/{p}"
        } else {
            "/items"
        };
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                path: {
                    "get": {
                        "operationId": "contentOp",
                        "parameters": [
                            {
                                "name": "p",
                                "in": location,
                                "required": required,
                                "content": { media: { "schema": schema } }
                            }
                        ],
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
        (model, sink.into_sorted_vec())
    }

    fn only_param(model: &ClientModel) -> &ParameterPlan {
        &model.operations[0].param_plans[0]
    }

    #[test]
    fn json_content_parameter_stays_typed_and_selects_the_content_json_helper() {
        let (model, diagnostics) = content_param_model(
            "query",
            "application/json",
            json!({ "type": "object", "properties": { "n": { "type": "integer" } } }),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let plan = only_param(&model);
        assert_eq!(plan.resolved.helper, HelperId::ContentJsonQuery);
        assert!(plan.resolved.helper.is_content_json());
        // The input stays typed from the content schema, so the object schema is preserved verbatim.
        assert!(!plan.caller_serialized);
        assert!(matches!(&plan.schema, SchemaNode::Object { .. }));
    }

    #[test]
    fn text_plain_string_content_parameter_is_a_typed_passthrough() {
        let (model, diagnostics) =
            content_param_model("query", "text/plain", json!({ "type": "string" }));
        // A string-shaped text/plain content parameter serializes exactly like a schema+style string
        // — the location default helper, a typed input, and no OASTS1443.
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let plan = only_param(&model);
        assert_eq!(plan.resolved.helper, HelperId::QueryFormExplode);
        assert!(!plan.caller_serialized);
    }

    #[test]
    fn unserializable_content_parameter_is_caller_serialized_with_one_warning() {
        let (model, diagnostics) =
            content_param_model("query", "application/xml", json!({ "type": "object" }));
        let plan = only_param(&model);
        // The client cannot serialize XML, so the caller supplies the pre-serialized string and the
        // location default helper forwards it.
        assert!(plan.caller_serialized);
        assert_eq!(plan.resolved.helper, HelperId::QueryForm);
        let warnings: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1443")
            .collect();
        assert_eq!(warnings.len(), 1, "{diagnostics:#?}");
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert!(warnings[0].message.contains("application/xml"));
        assert!(warnings[0].message.contains("caller-serialized"));
    }

    #[test]
    fn text_plain_non_string_content_parameter_is_caller_serialized() {
        // The passthrough is string-only; text/plain over a non-string schema falls to OASTS1443.
        let (model, diagnostics) =
            content_param_model("query", "text/plain", json!({ "type": "object" }));
        assert!(only_param(&model).caller_serialized);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1443")
                .count(),
            1,
        );
    }

    #[test]
    fn json_content_helper_is_selected_per_location() {
        for (location, expected) in [
            ("path", HelperId::ContentJsonPath),
            ("query", HelperId::ContentJsonQuery),
            ("header", HelperId::ContentJsonHeader),
            // A cookie JSON parameter reuses the query serializer.
            ("cookie", HelperId::ContentJsonQuery),
        ] {
            let (model, diagnostics) =
                content_param_model(location, "application/json", json!({ "type": "object" }));
            assert!(diagnostics.is_empty(), "{location}: {diagnostics:#?}");
            assert_eq!(only_param(&model).resolved.helper, expected, "{location}");
        }
    }

    #[test]
    fn caller_serialized_content_uses_the_location_default_helper() {
        for (location, expected) in [
            ("path", HelperId::PathSimple),
            ("query", HelperId::QueryForm),
            ("header", HelperId::HeaderSimple),
            // A cookie parameter reuses the query-form serializer.
            ("cookie", HelperId::QueryForm),
        ] {
            let (model, diagnostics) =
                content_param_model(location, "application/xml", json!({ "type": "object" }));
            let plan = only_param(&model);
            assert!(plan.caller_serialized, "{location}");
            assert_eq!(plan.resolved.helper, expected, "{location}");
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "OASTS1443")
                    .count(),
                1,
                "{location}"
            );
        }
    }

    #[test]
    fn oasts1411_rejects_unconditionally_forbidden_operation_headers() {
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
    fn oasts1412_rejects_active_api_key_owned_header_collisions() {
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
    fn oasts1413_rejects_parameter_and_and_alternative_wire_key_collisions() {
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
    fn oasts1414_rejects_only_control_bytes_in_multipart_field_names() {
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
    fn multipart_ignores_forbidden_headers_and_passes_content_encoding_through() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/parts": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "custom": { "type": "string" },
                                            "encoded": { "type": "string", "contentEncoding": "base64" },
                                            "quoted": { "type": "string" },
                                            "binary": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "custom": {
                                            "headers": {
                                                "X-Custom": { "schema": { "type": "string" } }
                                            }
                                        },
                                        "quoted": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "const": "quoted-printable" } }
                                            }
                                        },
                                        "binary": {
                                            "headers": {
                                                "Content-Transfer-Encoding": { "schema": { "const": "BiNaRy" } }
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
        let diagnostics = sink.into_sorted_vec();
        let fields = model.operations[0]
            .body_plan
            .as_ref()
            .expect("body plan")
            .multipart_fields()
            .expect("multipart body");
        let field = |name: &str| {
            fields
                .iter()
                .find(|field| field.name == name)
                .expect("field")
        };

        assert_eq!(diagnostics.len(), 2);
        for code in ["OASTS1415", "OASTS1417"] {
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == code)
                .expect("diagnostic");
            assert_eq!(diagnostic.severity, Severity::Warning);
        }
        assert_eq!(field_payloads(field("encoded")), [PayloadKind::Text]);
        for name in ["custom", "quoted", "binary"] {
            assert!(!field(name).wrapper.wrapped);
        }
    }

    #[test]
    fn oasts1415_warns_only_for_declared_unsupported_cte_values() {
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

        let diagnostics = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1415")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 4);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
    }

    #[test]
    fn oasts1415_allows_unconstrained_and_admitted_cte_schemas() {
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

        let diagnostics = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1415")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Severity::Warning);
    }

    #[test]
    fn oasts1415_skips_unevaluable_cte_composition_after_oasts1103() {
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
                .all(|diagnostic| diagnostic.code != "OASTS1415")
        );
    }

    #[test]
    fn oasts1416_rejects_incompatible_content_disposition_schema() {
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
    fn oasts1417_warns_for_headers_outside_rfc7578_set() {
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

        let diagnostics = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1417")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Severity::Warning);
    }

    #[test]
    fn oasts1418_validates_declared_encoding_content_types_as_rfc9110() {
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
                                            "badSyntax": { "type": "string" },
                                            "badUnterminated": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "valid": { "contentType": "Application/JSON; note=\"a,b\", image/*" },
                                        "badWhitespace": { "contentType": "text/plain; charset = utf-8" },
                                        "badControl": { "contentType": "text/plain; note=\"bad\u{0001}value\"" },
                                        "badNonAscii": { "contentType": "text/plain; note=\"café\"" },
                                        "badDuplicate": { "contentType": "application/json; charset=utf-8; Charset=utf-16" },
                                        "badSyntax": { "contentType": "missing-slash" },
                                        "badUnterminated": { "contentType": "application/json; note=\"a,b" }
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
            6
        );
    }

    #[test]
    fn oasts1423_rejects_binary_urlencoded_field() {
        // A urlencoded body is text-only, so a field whose default part media is binary (3.0
        // format:binary, 3.1 schemaless) cannot be represented; a base64url string can and must not
        // fire. An explicit `encoding.contentType` does not make a binary schema representable in a
        // text format, so the check fires on both content paths — the `*Explicit` fields below carry
        // one and must still be flagged.
        let document30 = json!({
            "openapi": "3.0.3",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "raw": { "type": "string", "format": "binary" },
                                            "rawExplicit": { "type": "string", "format": "binary" }
                                        }
                                    },
                                    "encoding": {
                                        "rawExplicit": { "contentType": "application/octet-stream" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let document31 = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "anything": {},
                                            "encoded": { "type": "string", "contentEncoding": "base64url" },
                                            "anythingExplicit": {},
                                            "iconExplicit": { "type": "string", "contentEncoding": "base64url" },
                                            "encodedExplicit": { "contentEncoding": "base64url" }
                                        }
                                    },
                                    "encoding": {
                                        "anythingExplicit": { "contentType": "application/octet-stream" },
                                        "iconExplicit": { "contentType": "image/png" },
                                        "encodedExplicit": { "contentType": "image/png" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });

        let flagged = |document: &Value| -> Vec<Diagnostic> {
            client_diagnostics(document)
                .into_iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1423")
                .collect()
        };
        let names = |diagnostics: &[Diagnostic]| -> Vec<String> {
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.clone())
                .collect()
        };
        // 3.0 `raw` + `rawExplicit`, 3.1 `anything` + `anythingExplicit`. The base64url string
        // fields (`encoded`, `iconExplicit`) and the schemaless-with-contentEncoding field
        // (`encodedExplicit`, admitted via Fix 1) are representable and must not fire. Asserting the
        // per-document counts and the exact flagged field names — not just the total — pins that the
        // check fires on the right fields, not merely the right number.
        let doc30 = flagged(&document30);
        let doc31 = flagged(&document31);
        assert_eq!(doc30.len(), 2);
        assert_eq!(doc31.len(), 2);
        assert!(
            doc30
                .iter()
                .chain(&doc31)
                .all(|diagnostic| diagnostic.severity == Severity::Error)
        );
        for (name, messages) in [
            ("'raw'", names(&doc30)),
            ("'rawExplicit'", names(&doc30)),
            ("'anything'", names(&doc31)),
            ("'anythingExplicit'", names(&doc31)),
        ] {
            assert!(
                messages.iter().any(|message| message.contains(name)),
                "missing {name}"
            );
        }
    }

    #[test]
    fn oasts1424_rejects_text_media_on_structured_urlencoded_field() {
        // A urlencoded object (or array of objects) under a text media type has no wire
        // representation: the form-explode serializer drops an object's field name and throws on an
        // array of objects. Only structured shapes fire; a string under text/plain and an object
        // under a media that classifies JSON are both representable and must not.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/forms": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "obj": { "type": "object" },
                                            "arr": { "type": "array", "items": { "type": "object" } },
                                            "objOctet": { "type": "object" },
                                            "str": { "type": "string" }
                                        }
                                    },
                                    "encoding": {
                                        "obj": { "contentType": "text/plain" },
                                        "arr": { "contentType": "text/plain" },
                                        "objOctet": { "contentType": "application/octet-stream" },
                                        "str": { "contentType": "text/plain" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let flagged = client_diagnostics(&document)
            .into_iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1424")
            .collect::<Vec<_>>();
        // Only `obj` and `arr` are structured-under-text; `objOctet` classifies JSON and `str` is
        // text-representable.
        assert_eq!(flagged.len(), 2);
        assert!(
            flagged
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Error)
        );
        assert!(
            flagged
                .iter()
                .any(|diagnostic| diagnostic.message.contains("'obj'"))
        );
        assert!(
            flagged
                .iter()
                .any(|diagnostic| diagnostic.message.contains("'arr'"))
        );
    }

    #[test]
    fn oasts1419_rejects_illegal_or_shape_ambiguous_parameter_styles() {
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
            5
        );
    }

    #[test]
    fn deep_object_explode_defaults_true_and_explicit_false_warns() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            { "name": "omitted", "in": "query", "style": "deepObject", "schema": { "type": "object" } },
                            { "name": "disabled", "in": "query", "style": "deepObject", "explode": false, "schema": { "type": "object" } },
                            { "name": "enabled", "in": "query", "style": "deepObject", "explode": true, "schema": { "type": "object" } }
                        ],
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
            model.operations[0]
                .param_plans
                .iter()
                .map(|plan| (plan.resolved.explode, plan.resolved.helper))
                .collect::<Vec<_>>(),
            [
                (true, HelperId::QueryDeepObject),
                (false, HelperId::QueryDeepObject),
                (true, HelperId::QueryDeepObject),
            ]
        );
        assert_eq!(sink.as_slice().len(), 1, "{:#?}", sink.as_slice());
        let diagnostic = &sink.as_slice()[0];
        assert_eq!(diagnostic.code, "OASTS1442");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.message,
            "explode: false with deepObject is undefined in OAS; treating as deepObject"
        );
    }

    #[test]
    fn urlencoded_style_with_contenttype_warns_1425() {
        for version in ["3.0.3", "3.1.0"] {
            let document = json!({
                "openapi": version,
                "paths": { "/forms": { "post": {
                    "requestBody": { "content": {
                        "application/x-www-form-urlencoded": {
                            "schema": { "type": "object", "properties": { "field": { "type": "string" } } },
                            "encoding": { "field": { "style": "form", "contentType": "text/plain" } }
                        }
                    }},
                    "responses": { "204": { "description": "ok" } }
                }}}
            });
            let diagnostics = client_diagnostics(&document);
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_URLENCODED_CONTENT_TYPE_IGNORED)
                .expect("OASTS1425 diagnostic");
            assert_eq!(diagnostic.severity, Severity::Warning);
            assert_eq!(
                diagnostic.json_pointer.as_deref(),
                Some(
                    "/paths/~1forms/post/requestBody/content/application~1x-www-form-urlencoded/encoding/field"
                )
            );
            assert_eq!(
                diagnostic.message,
                "urlencoded field 'field' declares explicit serialization so encoding.contentType is ignored"
            );
        }
    }

    #[test]
    fn urlencoded_style_without_contenttype_no_warning() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": { "type": "object", "properties": { "field": { "type": "string" } } },
                        "encoding": { "field": { "style": "form" } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn urlencoded_contenttype_without_style_no_warning() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "application/x-www-form-urlencoded": {
                        "schema": { "type": "object", "properties": { "field": { "type": "string" } } },
                        "encoding": { "field": { "contentType": "text/plain" } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn multipart_30_style_keywords_warn_1426() {
        let document = json!({
            "openapi": "3.0.3",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": {
                            "styled": { "type": "string" },
                            "exploded": { "type": "string" },
                            "reserved": { "type": "string" }
                        }},
                        "encoding": {
                            "styled": { "style": "form" },
                            "exploded": { "explode": true },
                            "reserved": { "allowReserved": true }
                        }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPART_30_STYLE_IGNORED)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 3);
        for field in ["styled", "exploded", "reserved"] {
            let diagnostic = warnings
                .iter()
                .find(|diagnostic| {
                    diagnostic
                        .json_pointer
                        .as_deref()
                        .is_some_and(|pointer| pointer.ends_with(&format!("/encoding/{field}")))
                })
                .expect("field warning");
            assert_eq!(diagnostic.severity, Severity::Warning);
            assert_eq!(
                diagnostic.message,
                "multipart encoding style keywords apply only to urlencoded bodies in OpenAPI 3.0 and are ignored"
            );
        }
    }

    #[test]
    fn multipart_31_style_keywords_no_1426() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": { "field": { "type": "string" } } },
                        "encoding": { "field": { "style": "form", "explode": true, "allowReserved": true } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn oasts1427_rejects_undefined_multipart_style_combinations() {
        // Four ways a 3.1 multipart field can have no defined per-part serialization: an array
        // explicitly opting out of the repeated-parts default (`explode: false`), an array under a
        // delimited/deep style (which multipart never defines, unlike urlencoded), an array whose
        // items are objects even under the otherwise-supported form+explode:true pair, and an
        // object with any explicit style keyword at all.
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": {
                            "arrForm": { "type": "array", "items": { "type": "string" } },
                            "arrDeep": { "type": "array", "items": { "type": "string" } },
                            "arrObjItems": { "type": "array", "items": { "type": "object" } },
                            "objStyled": { "type": "object" }
                        }},
                        "encoding": {
                            "arrForm": { "style": "form", "explode": false },
                            "arrDeep": { "style": "deepObject" },
                            "arrObjItems": { "style": "form", "explode": true },
                            "objStyled": { "style": "form" }
                        }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let flagged = client_diagnostics(&document)
            .into_iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPART_STYLE_UNDEFINED)
            .collect::<Vec<_>>();
        for field in ["arrForm", "arrDeep", "arrObjItems", "objStyled"] {
            assert_eq!(
                flagged
                    .iter()
                    .filter(|diagnostic| diagnostic
                        .json_pointer
                        .as_deref()
                        .is_some_and(|pointer| pointer.ends_with(&format!("/encoding/{field}"))))
                    .count(),
                1,
                "expected exactly one OASTS1427 for '{field}'"
            );
        }
        for (field, rendering) in [
            ("arrForm", "Form/explode=false"),
            ("arrDeep", "DeepObject/explode=false"),
            ("arrObjItems", "Form/explode=true"),
            ("objStyled", "Form/explode=true"),
        ] {
            let diagnostic = flagged
                .iter()
                .find(|diagnostic| {
                    diagnostic
                        .json_pointer
                        .as_deref()
                        .is_some_and(|pointer| pointer.ends_with(&format!("/encoding/{field}")))
                })
                .expect("field diagnostic");
            assert!(
                diagnostic.message.contains(rendering),
                "'{field}' message missing {rendering:?}: {}",
                diagnostic.message
            );
            assert!(
                diagnostic
                    .message
                    .contains("use encoding.contentType instead")
            );
        }
    }

    /// The conjunction lowering (allOf/$ref/applicator coexistence) resolves an allOf-of-objects
    /// schema to a `Domain::OBJECT` projection without ever producing a `SchemaNode::Object` node.
    /// The admission matrix classifies via `default_part_media`'s own domain-projection catch-all,
    /// so this still reports OASTS1427 instead of silently falling through as unclassified.
    #[test]
    fn allof_object_conjunction_with_style_is_rejected() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": {
                            "meta": {
                                "allOf": [
                                    { "type": "object", "properties": { "a": { "type": "string" } } },
                                    { "type": "object", "properties": { "b": { "type": "string" } } }
                                ]
                            }
                        }},
                        "encoding": { "meta": { "style": "form" } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let flagged = client_diagnostics(&document)
            .into_iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPART_STYLE_UNDEFINED)
            .collect::<Vec<_>>();
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(flagged[0].message.contains("'meta'"));
    }

    /// A schemaless 3.1 field is the only way to express a binary upload in that version
    /// (`default_part_media`'s dedicated arm), and it projects to `Domain::FULL` — which includes
    /// the `OBJECT` bit. The admission matrix must classify it by `default_part_media`'s actual
    /// media (`application/octet-stream`, not JSON), not by domain-bit containment, or this
    /// passthrough case would be misclassified as object-shaped and rejected.
    #[test]
    fn binary_primitive_multipart_field_with_style_no_oasts1427() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": { "/uploads": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": {
                            "file": {}
                        }},
                        "encoding": { "file": { "style": "form" } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        // Schemaless + styled produces no diagnostic of any kind: it is fully admitted.
        assert!(client_diagnostics(&document).is_empty());
    }

    /// OASTS1427 is 3.1-only: 3.0 multipart style keywords are already warn-ignored by OASTS1426, so
    /// the same object+style shape in a 3.0 document must not additionally report OASTS1427.
    #[test]
    fn oasts1427_does_not_fire_on_30_documents() {
        let document = json!({
            "openapi": "3.0.3",
            "paths": { "/forms": { "post": {
                "requestBody": { "content": {
                    "multipart/form-data": {
                        "schema": { "type": "object", "properties": {
                            "meta": { "type": "object" }
                        }},
                        "encoding": { "meta": { "style": "form" } }
                    }
                }},
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        // OASTS1426 (the 3.0 multipart style warning) is expected on this exact shape, so the
        // diagnostics list here is never empty — the `.filter()` below always has a non-empty
        // source to iterate.
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_MULTIPART_30_STYLE_IGNORED)
            .expect("OASTS1426 diagnostic");
        let oasts1427 = diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPART_STYLE_UNDEFINED)
            .collect::<Vec<_>>();
        assert!(oasts1427.is_empty(), "{oasts1427:#?}");
    }

    #[test]
    fn oasts1419_applies_restricted_styles_to_encoding_objects() {
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
                                            "bad": {
                                                "anyOf": [
                                                    { "type": "array", "items": { "type": "string" } },
                                                    { "type": "object" }
                                                ]
                                            },
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
    fn oasts1420_only_rejects_an_out_of_range_server_index() {
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
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "server", "index": 1 }
            }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let diagnostics = sink.into_sorted_vec();

        assert!(model.base_url_required);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1420")
                .count(),
            1
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS1420"
                && diagnostic
                    .message
                    .contains("operation has no effective server at index 1")
        }));
    }

    #[test]
    fn absolute_server_urls_do_not_require_a_transport_base_url() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://{host}/v1", "variables": {
                "host": { "default": "api.example.test" }
            }}],
            "paths": {
                "/status": {
                    "get": { "responses": { "204": { "description": "ok" } } }
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

        assert!(!model.base_url_required);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn any_relative_effective_server_requires_a_transport_base_url() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [
                { "url": "https://api.example.test/v1" },
                { "url": "/api/{version}", "variables": {
                    "version": { "default": "v2" }
                }}
            ],
            "paths": {
                "/status": {
                    "get": { "responses": { "204": { "description": "ok" } } }
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

        assert!(model.base_url_required);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn oauth2_empty_flows_errors_1435() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2" }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OAUTH2_EMPTY_FLOWS)
            .expect("empty OAuth2 flows diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth")
        );
        assert_eq!(diagnostic.message, "oauth2 scheme declares no flows");
    }

    #[test]
    fn http_scheme_token_errors_1444() {
        // An empty scheme and a non-token scheme are each fatal; a registered generalized token like
        // digest stays clean. One document exercises all three so the flagged set is never empty.
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "blank": { "type": "http", "scheme": "" },
                "spaced": { "type": "http", "scheme": "my scheme" },
                "digest": { "type": "http", "scheme": "digest" }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let hits: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_HTTP_SCHEME_TOKEN)
            .collect();
        assert_eq!(hits.len(), 2, "{diagnostics:#?}");
        for (pointer, message) in [
            (
                "/components/securitySchemes/blank",
                "http security scheme 'blank' must declare a scheme token",
            ),
            (
                "/components/securitySchemes/spaced",
                "http security scheme 'spaced' scheme 'my scheme' is not an RFC 9110 token",
            ),
        ] {
            let hit = hits
                .iter()
                .find(|diagnostic| diagnostic.json_pointer.as_deref() == Some(pointer))
                .expect("flagged scheme");
            assert_eq!(hit.severity, Severity::Error);
            assert_eq!(hit.message, message);
        }
        // digest is a valid RFC 9110 token, so it is never among the flagged pointers.
        assert!(
            hits.iter()
                .all(|diagnostic| diagnostic.json_pointer.as_deref()
                    != Some("/components/securitySchemes/digest"))
        );
    }

    #[test]
    fn flow_missing_required_url_errors_1436() {
        for (key, fields) in [
            ("implicit", vec!["authorizationUrl"]),
            ("password", vec!["tokenUrl"]),
            ("clientCredentials", vec!["tokenUrl"]),
            ("authorizationCode", vec!["authorizationUrl", "tokenUrl"]),
        ] {
            let mut document = json!({
                "openapi": "3.1.0",
                "components": { "securitySchemes": {
                    "oauth": { "type": "oauth2", "flows": {} }
                }}
            });
            let mut flows = serde_json::Map::new();
            flows.insert(key.to_owned(), json!({ "scopes": {} }));
            document["components"]["securitySchemes"]["oauth"]["flows"] = Value::Object(flows);
            let diagnostics = client_diagnostics(&document);
            let hits = diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_OAUTH2_FLOW_REQUIRED_URL)
                .collect::<Vec<_>>();
            assert_eq!(hits.len(), fields.len(), "{key}: {diagnostics:#?}");
            let pointer = format!("/components/securitySchemes/oauth/flows/{key}");
            for (diagnostic, field) in hits.iter().zip(fields) {
                assert_eq!(diagnostic.severity, Severity::Error);
                assert_eq!(diagnostic.json_pointer.as_deref(), Some(pointer.as_str()));
                assert_eq!(diagnostic.message, format!("{key} flow requires {field}"));
            }
        }
    }

    #[test]
    fn flow_url_not_absolute_errors_1437() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": { "authorizationCode": {
                        "authorizationUrl": "relative",
                        "tokenUrl": "urn:example",
                        "refreshUrl": "https://example.test/refresh",
                        "scopes": {}
                    }}
                }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let hits = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_OAUTH2_FLOW_URL)
            .collect::<Vec<_>>();
        assert_eq!(hits.len(), 2);
        for diagnostic in &hits {
            assert_eq!(diagnostic.severity, Severity::Error);
            assert_eq!(
                diagnostic.json_pointer.as_deref(),
                Some("/components/securitySchemes/oauth/flows/authorizationCode")
            );
        }
        assert!(hits.iter().any(|diagnostic| {
            diagnostic.message
                == "authorizationCode authorizationUrl 'relative' is not an absolute URL"
        }));
        assert!(hits.iter().any(|diagnostic| {
            diagnostic.message == "authorizationCode tokenUrl 'urn:example' is not an absolute URL"
        }));
    }

    #[test]
    fn openidconnect_url_missing_or_invalid_errors_1439() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "missing": { "type": "openIdConnect" },
                "invalid": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "urn:example"
                }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let missing = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.message == "openIdConnect scheme requires openIdConnectUrl"
            })
            .expect("missing OpenID Connect URL diagnostic");
        assert_eq!(missing.code, CODE_OPENID_CONNECT_URL);
        assert_eq!(missing.severity, Severity::Error);
        assert_eq!(
            missing.json_pointer.as_deref(),
            Some("/components/securitySchemes/missing")
        );
        let invalid = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.message == "openIdConnectUrl 'urn:example' is not an absolute URL"
            })
            .expect("invalid OpenID Connect URL diagnostic");
        assert_eq!(invalid.code, CODE_OPENID_CONNECT_URL);
        assert_eq!(invalid.severity, Severity::Error);
        assert_eq!(
            invalid.json_pointer.as_deref(),
            Some("/components/securitySchemes/invalid")
        );
    }

    #[test]
    fn valid_flows_produce_no_diagnostics() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": "https://example.test/authorize",
                            "refreshUrl": "https://example.test/refresh",
                            "scopes": {}
                        },
                        "password": {
                            "tokenUrl": "https://example.test/token",
                            "scopes": {}
                        },
                        "clientCredentials": {
                            "tokenUrl": "https://example.test/token",
                            "scopes": {}
                        },
                        "authorizationCode": {
                            "authorizationUrl": "https://example.test/authorize",
                            "tokenUrl": "https://example.test/token",
                            "scopes": {}
                        }
                    }
                },
                "oidc": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "https://example.test/.well-known/openid-configuration"
                }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn auth_plan_distinguishes_secured_anonymous_and_empty_security() {
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
        let (analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let plan_for = |id: &str| {
            let index = analyzed
                .ir
                .operations
                .iter()
                .position(|operation| operation.operation_id.as_deref() == Some(id))
                .expect("operation");
            model
                .operations
                .iter()
                .find(|plan| plan.operation_index == index)
                .expect("plan")
                .auth_plan
                .clone()
        };
        assert_eq!(
            plan_for("securedOperation"),
            vec![
                vec![AuthSchemeUse {
                    name: "key".to_owned(),
                    kind: AuthKind::ApiKeyQuery {
                        name: "key".to_owned(),
                    },
                    scopes: Vec::new(),
                }],
                Vec::new(),
            ]
        );
        assert_eq!(plan_for("anonymousOperation"), vec![Vec::new()]);
        assert!(plan_for("emptyOperation").is_empty());
    }

    fn runtime_plan(document: &Value) -> (Analyzed, ClientModel, DiagnosticSink) {
        let (_temp, analyzed, config) = analyzed(
            document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        (analyzed, model, sink)
    }

    #[test]
    fn auth_plan_preserves_alternative_member_and_scope_order() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "defaultApiKey": { "type": "apiKey", "in": "header", "name": "api-key" },
                    "app2AppOauth": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://example.test/token",
                                "scopes": { "board:read": "Read the board" }
                            }
                        }
                    }
                }
            },
            "paths": {
                "/board": {
                    "get": {
                        "operationId": "get-board",
                        "security": [
                            { "defaultApiKey": [] },
                            { "app2AppOauth": ["board:read"] }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            model.operations[0].auth_plan,
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

    #[test]
    fn http_scheme_token_matching_is_case_insensitive() {
        for (token, expected) in [
            ("Basic", AuthKind::Basic),
            ("BASIC", AuthKind::Basic),
            ("basic", AuthKind::Basic),
            ("Bearer", AuthKind::Bearer),
            ("bearer", AuthKind::Bearer),
            (
                "Digest",
                AuthKind::HttpScheme {
                    scheme: "Digest".to_owned(),
                },
            ),
            (
                "Negotiate",
                AuthKind::HttpScheme {
                    scheme: "Negotiate".to_owned(),
                },
            ),
        ] {
            let document = json!({
                "openapi": "3.1.0",
                "components": {
                    "securitySchemes": { "h": { "type": "http", "scheme": token } }
                },
                "paths": {
                    "/p": {
                        "get": {
                            "operationId": "op",
                            "security": [{ "h": [] }],
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            });
            let (_analyzed, model, sink) = runtime_plan(&document);
            assert!(!sink.has_errors(), "token {token}: {:#?}", sink.as_slice());
            assert_eq!(
                model.operations[0].auth_plan,
                vec![vec![AuthSchemeUse {
                    name: "h".to_owned(),
                    kind: expected.clone(),
                    scopes: Vec::new(),
                }]],
                "token {token}"
            );
        }
    }

    #[test]
    fn auth_plan_maps_cookie_and_oauth_scheme_kinds() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "cookieKey": { "type": "apiKey", "in": "cookie", "name": "session" },
                    "oidc": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://auth.example/.well-known/openid-configuration"
                    },
                    "oauthFlow": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://auth.example/token",
                                "scopes": { "scope.a": "a" }
                            }
                        }
                    }
                }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [{ "cookieKey": [] }, { "oauthFlow": ["scope.a"] }, { "oidc": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            model.operations[0].auth_plan,
            vec![
                vec![AuthSchemeUse {
                    name: "cookieKey".to_owned(),
                    kind: AuthKind::ApiKeyCookie {
                        name: "session".to_owned(),
                    },
                    scopes: Vec::new(),
                }],
                vec![AuthSchemeUse {
                    name: "oauthFlow".to_owned(),
                    kind: AuthKind::OAuth2,
                    scopes: vec!["scope.a".to_owned()],
                }],
                vec![AuthSchemeUse {
                    name: "oidc".to_owned(),
                    kind: AuthKind::OpenIdConnect,
                    scopes: Vec::new(),
                }],
            ]
        );
    }

    #[test]
    fn wire_key_pairing_skips_a_keyless_member() {
        // An AND alternative pairing a keyed scheme with mutualTLS: the wire-key collision scan
        // skips the keyless member instead of colliding.
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": {
                    "bearerAuth": { "type": "http", "scheme": "bearer" },
                    "mtls": { "type": "mutualTLS" }
                }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [{ "bearerAuth": [], "mtls": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, _model, sink) = runtime_plan(&document);
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn mutual_tls_scheme_produces_a_clean_auth_plan() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": { "mtls": { "type": "mutualTLS" } }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [{ "mtls": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            model.operations[0].auth_plan,
            vec![vec![AuthSchemeUse {
                name: "mtls".to_owned(),
                kind: AuthKind::MutualTls,
                scopes: Vec::new(),
            }]]
        );
    }

    #[test]
    fn unknown_scheme_kind_reports_oasts1433() {
        for scheme in [
            json!({ "type": "quantum" }),
            json!({ "type": "apiKey", "in": "path", "name": "bad" }),
        ] {
            let document = json!({
                "openapi": "3.1.0",
                "components": {
                    "securitySchemes": { "weird": scheme }
                },
                "paths": {
                    "/p": {
                        "get": {
                            "operationId": "op",
                            "security": [{ "weird": [] }],
                            "responses": { "200": { "description": "ok" } }
                        }
                    }
                }
            });
            let (_analyzed, _model, sink) = runtime_plan(&document);
            let hits = sink
                .as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1433")
                .collect::<Vec<_>>();
            assert_eq!(hits.len(), 1);
            assert!(hits[0].message.contains("weird"));
        }
    }

    #[test]
    fn undeclared_scheme_name_reports_oasts1434() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": { "known": { "type": "apiKey", "in": "header", "name": "X-Key" } }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [{ "ghost": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, _model, sink) = runtime_plan(&document);
        let hits = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1434")
            .collect::<Vec<_>>();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("ghost"));
        assert!(hits[0].message.contains("op"));
    }

    #[test]
    fn auth_plan_preserves_anonymous_alternative_in_place() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "securitySchemes": { "k": { "type": "apiKey", "in": "query", "name": "key" } }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [{ "k": [] }, {}],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            model.operations[0].auth_plan,
            vec![
                vec![AuthSchemeUse {
                    name: "k".to_owned(),
                    kind: AuthKind::ApiKeyQuery {
                        name: "key".to_owned(),
                    },
                    scopes: Vec::new(),
                }],
                Vec::new(),
            ]
        );
    }

    #[test]
    fn explicit_empty_security_overrides_root_to_empty_plan() {
        let document = json!({
            "openapi": "3.1.0",
            "security": [{ "k": [] }],
            "components": {
                "securitySchemes": { "k": { "type": "apiKey", "in": "header", "name": "X-Key" } }
            },
            "paths": {
                "/p": {
                    "get": {
                        "operationId": "op",
                        "security": [],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(model.operations[0].auth_plan.is_empty());
    }

    #[test]
    fn operation_security_overrides_root_default() {
        let document = json!({
            "openapi": "3.1.0",
            "security": [{ "rootKey": [] }],
            "components": {
                "securitySchemes": {
                    "rootKey": { "type": "apiKey", "in": "header", "name": "X-Root" },
                    "opKey": { "type": "apiKey", "in": "query", "name": "op-key" }
                }
            },
            "paths": {
                "/overridden": {
                    "get": {
                        "operationId": "overridden",
                        "security": [{ "opKey": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "/inherits": {
                    "get": {
                        "operationId": "inherits",
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        let (analyzed, model, sink) = runtime_plan(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let plan_for = |id: &str| {
            let index = analyzed
                .ir
                .operations
                .iter()
                .position(|operation| operation.operation_id.as_deref() == Some(id))
                .expect("operation");
            model
                .operations
                .iter()
                .find(|plan| plan.operation_index == index)
                .expect("plan")
                .auth_plan
                .clone()
        };
        assert_eq!(
            plan_for("overridden"),
            vec![vec![AuthSchemeUse {
                name: "opKey".to_owned(),
                kind: AuthKind::ApiKeyQuery {
                    name: "op-key".to_owned(),
                },
                scopes: Vec::new(),
            }]]
        );
        assert_eq!(
            plan_for("inherits"),
            vec![vec![AuthSchemeUse {
                name: "rootKey".to_owned(),
                kind: AuthKind::ApiKeyHeader {
                    name: "X-Root".to_owned(),
                },
                scopes: Vec::new(),
            }]]
        );
    }

    #[test]
    fn oauth2_requirement_scope_outside_union_errors_1440() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": "https://example.test/authorize",
                            "scopes": { "scope.a": "A" }
                        },
                        "clientCredentials": {
                            "tokenUrl": "https://example.test/token",
                            "scopes": { "scope.b": "B" }
                        }
                    }
                }
            }},
            "paths": { "/p": { "get": {
                "operationId": "op",
                "security": [{ "oauth": ["scope.a", "scope.b", "scope.missing"] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let (_analyzed, _model, sink) = runtime_plan(&document);
        let hits = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_OAUTH2_REQUIREMENT_SCOPE)
            .collect::<Vec<_>>();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Error);
        assert_eq!(hits[0].source_id.as_deref(), Some("workspace/openapi.json"));
        assert_eq!(hits[0].json_pointer.as_deref(), Some("/paths/~1p/get"));
        assert_eq!(
            hits[0].message,
            "security requirement scope 'scope.missing' is not declared by oauth2 scheme 'oauth'"
        );
    }

    #[test]
    fn oauth2_requirement_all_scopes_declared_is_clean() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": "https://example.test/authorize",
                            "scopes": { "scope.a": "A" }
                        },
                        "clientCredentials": {
                            "tokenUrl": "https://example.test/token",
                            "scopes": { "scope.b": "B" }
                        }
                    }
                }
            }},
            "paths": { "/p": { "get": {
                "operationId": "op",
                "security": [{ "oauth": ["scope.a", "scope.b"] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn oauth2_scheme_use_survives_scope_error() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": { "clientCredentials": {
                        "tokenUrl": "https://example.test/token",
                        "scopes": { "scope.a": "A" }
                    }}
                }
            }},
            "paths": { "/p": { "get": {
                "operationId": "op",
                "security": [{ "oauth": ["scope.missing"] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let (_analyzed, model, sink) = runtime_plan(&document);
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_OAUTH2_REQUIREMENT_SCOPE)
        );
        assert_eq!(
            model.operations[0].auth_plan,
            vec![vec![AuthSchemeUse {
                name: "oauth".to_owned(),
                kind: AuthKind::OAuth2,
                scopes: vec!["scope.missing".to_owned()],
            }]]
        );
    }

    #[test]
    fn oidc_requirement_scopes_unchecked() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oidc": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "https://example.test/.well-known/openid-configuration"
                }
            }},
            "paths": { "/p": { "get": {
                "operationId": "op",
                "security": [{ "oidc": ["provider-defined", "arbitrary"] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let diagnostics = client_diagnostics(&document);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn non_oauth_scopes_error_in_30_clean_in_31() {
        for (version, expected_code) in [
            ("3.0.3", Some(CODE_NON_OAUTH_REQUIREMENT_SCOPES)),
            ("3.1.0", None),
        ] {
            let document = json!({
                "openapi": version,
                "components": { "securitySchemes": {
                    "apiKey": { "type": "apiKey", "in": "header", "name": "X-Key" }
                }},
                "paths": { "/p": { "get": {
                    "operationId": "op",
                    "security": [{ "apiKey": ["role:reader"] }],
                    "responses": { "200": {
                        "description": "ok",
                        "content": { "application/json": { "schema": { "type": "object" } } }
                    } }
                }}}
            });
            let diagnostics = client_diagnostics(&document);
            let hits = diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_NON_OAUTH_REQUIREMENT_SCOPES)
                .collect::<Vec<_>>();
            match expected_code {
                Some(code) => {
                    assert_eq!(hits.len(), 1);
                    assert_eq!(hits[0].code, code);
                    assert_eq!(hits[0].severity, Severity::Error);
                    assert_eq!(hits[0].source_id.as_deref(), Some("workspace/openapi.json"));
                    assert_eq!(hits[0].json_pointer.as_deref(), Some("/paths/~1p/get"));
                    assert_eq!(
                        hits[0].message,
                        "security requirement for 'apiKey' must not list scopes in OpenAPI 3.0"
                    );
                }
                None => assert!(hits.is_empty(), "{diagnostics:#?}"),
            }
        }
    }

    #[test]
    fn media_less_30_document_still_gates_version_dependent_rules() {
        // A 3.0 document with no media anywhere (204-only response, no request/response content) has
        // no media type to infer the OAS version from. The version now rides the IR from the parser,
        // so the 3.0-only non-oauth-scopes gate (OASTS1441) still fires; the same document as 3.1 is
        // clean. (Regression: media inference defaulted a media-less document to 3.1 and silently
        // skipped the gate.)
        for (version, expected) in [("3.0.3", 1usize), ("3.1.0", 0usize)] {
            let document = json!({
                "openapi": version,
                "components": { "securitySchemes": {
                    "apiKeyAuth": { "type": "apiKey", "in": "header", "name": "X-Key" }
                }},
                "paths": { "/p": { "get": {
                    "operationId": "op",
                    "security": [{ "apiKeyAuth": ["scopeA"] }],
                    "responses": { "204": { "description": "no content" } }
                }}}
            });
            let diagnostics = client_diagnostics(&document);
            let hits = diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_NON_OAUTH_REQUIREMENT_SCOPES)
                .count();
            assert_eq!(hits, expected, "version {version}: {diagnostics:#?}");
        }
    }
}
