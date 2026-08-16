//! Client artifact planning over the normalized OpenAPI IR.

use std::borrow::Cow;
use std::collections::{BTreeSet, VecDeque};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use serde_json::Value;

use crate::config::{DeepObjectEncoding, ResolvedBaseUrl, ResolvedConfig, UncheckedPolicy};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::headers::forbidden_request_header_name;
use crate::ir::{
    AdditionalProperties, EncodingObject, Ir, MediaType, NamedSecurityScheme, OAuthFlow,
    OasVersion, Operation, ParamLocation, ParamStyle, PrimitiveType, ResponseStatus, SchemaMeta,
    SchemaNode, SecKind, SecurityRequirement, ServerEntry, SourceRef,
};
use crate::loader::append_pointer;
use crate::media::{MediaRangeKind, is_json, media_essence};
pub use crate::param_serialization::{HelperId, ResolvedParameterSerialization};
use crate::param_serialization::{
    parameter_requires_caller_serialization, resolve_parameter_serialization,
};
pub use crate::response_media::ResponseMediaKind as DecoderClass;
#[cfg(test)]
use crate::response_media::response_status_name;
use crate::response_media::{
    ResponseMediaProjector, ResponseSchemaProjection, classify_response_media,
    diagnose_operation_response_media, diagnose_unchecked_raw_streams,
    xml_requires_structural_mapping,
};
use crate::semantic::Analyzed;

const CODE_OAUTH2_EMPTY_FLOWS: &str = "OASTS5403";
const CODE_OAUTH2_FLOW_REQUIRED_URL: &str = "OASTS5404";
const CODE_OAUTH2_FLOW_URL: &str = "OASTS5405";
const CODE_OPENID_CONNECT_URL: &str = "OASTS5407";
const CODE_HTTP_SCHEME_TOKEN: &str = "OASTS5411";
const CODE_OAUTH2_REQUIREMENT_SCOPE: &str = "OASTS5408";
const CODE_NON_OAUTH_REQUIREMENT_SCOPES: &str = "OASTS5409";
const CODE_URLENCODED_CONTENT_TYPE_IGNORED: &str = "OASTS5109";
const CODE_MULTIPART_30_STYLE_IGNORED: &str = "OASTS5111";
const CODE_MULTIPART_STYLE_UNDEFINED: &str = "OASTS5112";
const CODE_FORM_SCHEMA_PROPERTIES: &str = "OASTS5106";
const CODE_FORM_SCHEMA_UNCONSTRAINED: &str = "OASTS5113";
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
    /// text/plain-over-string passthrough (the OASTS5006 case); every typed case keeps this false.
    pub caller_serialized: bool,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyPlanArm {
    pub media: String,
    pub plan: BodyPlan,
    pub source: SourceRef,
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
    /// A streaming request body: the caller's byte stream reaches fetch untouched. It carries no
    /// schema on purpose — the bytes are never validated and never transformed, because both are
    /// whole-value operations over a value that does not exist yet at dispatch time, so a schema
    /// here would only invite a check that has no failure branch to report into.
    TopLevelStream { media: String, source: SourceRef },
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
        arms: Vec<BodyPlanArm>,
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
    pub fn discriminated_arms(&self) -> Option<(&[BodyPlanArm], bool)> {
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

impl FormFieldPlan {
    /// Whether this field is sent as an upload handle rather than as its declared schema value.
    /// Such a field renders `Blob | File`, so it carries nothing a codec could convert and nothing
    /// a projector could invert. The type renderer keeps its own `match` arm instead of calling
    /// this, because there it must stay exhaustive over `FieldSerializationPlan`.
    #[must_use]
    pub fn is_binary_upload(&self) -> bool {
        matches!(
            &self.serialization,
            FieldSerializationPlan::Content { media, .. } if media.binary_upload
        )
    }
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
    /// The entry's declared schema, always the IR node — an absent `schema` keyword leaves the IR's
    /// unconstrained default here rather than erasing it, so the client renders the same payload
    /// type the types artifact does for that entry.
    pub schema: SchemaNode,
    /// Per-part decoding plan, present exactly when `decoder` is `Multipart`. Both the emitted
    /// descriptor and the emitted payload type read it, so the bytes the runtime produces and the
    /// type the caller sees are derived from one classification.
    pub multipart: Option<MultipartResponsePlan>,
    pub streaming_marked: bool,
    pub source: SourceRef,
}

/// How one property of a decoded `multipart/form-data` response object is produced from its part.
///
/// The kind is fixed at generation time from the declared schema rather than sniffed from the wire,
/// because the decoded value has to inhabit the TypeScript type that same schema renders. The
/// classification mirrors the request encoder's (`default_part_media` + `content_payload_kind`) so
/// a round trip through both directions agrees on what a part carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipartResponsePayload {
    Json,
    Text,
    Binary,
    /// The schema constrains nothing, so the property's type is `unknown` and there is no shape to
    /// classify from. The part's own `Content-Type` decides at runtime, defaulting to `text/plain`
    /// (RFC 7578 §4.4). This is the one place the wire, not the description, picks the decoding.
    Wire,
}

impl MultipartResponsePayload {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Wire => "wire",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipartResponseShape {
    pub payload: MultipartResponsePayload,
    /// The declared schema is an array, so every part carrying this name contributes one element in
    /// wire order and a single occurrence still decodes to a one-element array. One level deep,
    /// exactly like the request encoder's `repeated`.
    pub repeated: bool,
    /// The schema the property's TypeScript type renders from — the array itself when `repeated`,
    /// since the array type is already what the caller receives.
    pub schema: SchemaNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipartResponsePartPlan {
    pub name: String,
    pub required: bool,
    pub shape: MultipartResponseShape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipartResponsePlan {
    /// Declared properties in schema order; a part's `Content-Disposition` name selects one.
    pub parts: Vec<MultipartResponsePartPlan>,
    /// The shape a part naming no declared property decodes under. Present whatever the schema says
    /// about `additionalProperties`, because an unexpected part is kept and decoded either way —
    /// the same thing a JSON body does with an undeclared member.
    pub additional: MultipartResponseShape,
    /// Whether the declared schema admits undeclared properties, i.e. whether the emitted object
    /// type carries an index signature. Distinct from `additional`, which is the decoding rule.
    pub open: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadDisposition {
    NoPayload,
    StaticBodyless,
    /// The branch carries a body. The per-entry schemas live on `ResponsePlan.media`, which is the
    /// single source of truth for them.
    Payload,
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
    let deep_object = config.compat.deep_object_encoding;
    let oas_version = analyzed.ir.version;
    diagnose_security_schemes(&analyzed.ir, sink);
    // The config layer already answered the pure-config half of the unchecked-data policy, before
    // any document was read. This is the half only the document can answer.
    let unchecked = config
        .validation
        .as_ref()
        .map_or(UncheckedPolicy::Warn, |validation| validation.unchecked);
    for operation in &analyzed.ir.operations {
        diagnose_operation_response_media(operation, &projector, sink);
        if unchecked != UncheckedPolicy::Allow {
            diagnose_unchecked_raw_streams(
                operation,
                &projector,
                unchecked == UncheckedPolicy::Error,
                sink,
            );
        }
    }
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
            let param_plans = plan_parameters(operation, &projector, deep_object, sink);
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
                    diagnose_form_media(media, &projector, deep_object, sink);
                }
            }
            let body_plan = operation
                .request_body
                .as_ref()
                .and_then(|body| build_body_plan(&body.media_types, &projector));
            let response_table = response_table(operation, oas_version, &projector);
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
                        if flows.declared {
                            "oauth2 scheme declares no flows"
                        } else {
                            "oauth2 scheme requires flows"
                        },
                        &scheme.source,
                        if flows.declared {
                            Severity::Warning
                        } else {
                            Severity::Error
                        },
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
                } else if !is_uri_reference(url) {
                    sink.push(source_diagnostic(
                        CODE_OPENID_CONNECT_URL,
                        format!("openIdConnectUrl '{url}' is not an RFC 3986 URI-reference"),
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
    // the caller's list. Both the missing-required and malformed-reference checks run per field — a
    // field is never both (a missing URL cannot be malformed) so a single pass over one table emits
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
        if let Some(value) = value.filter(|value| !is_uri_reference(value)) {
            sink.push(source_diagnostic(
                CODE_OAUTH2_FLOW_URL,
                format!("{key} {field} '{value}' is not an RFC 3986 URI-reference"),
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

fn is_uri_reference(value: &str) -> bool {
    // OAS 3.0.4 §4.6 and 3.1.1 §4.7 permit every URL field to be an RFC 3986
    // relative reference unless that field says otherwise; OAuth flow URLs and
    // `openIdConnectUrl` do not. Do not restore an absolute-URI check based on an
    // OAS 3.1 JSON Schema revision's `format: uri`: that schema is non-normative,
    // and the specification makes its prose authoritative when they differ.
    fluent_uri::UriRef::parse(value).is_ok()
}

fn is_absolute_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| !url.cannot_be_a_base())
}

pub(crate) fn parameter_plan(
    parameter: &crate::ir::Param,
    projector: &PrimitiveDomainProjector<'_>,
    deep_object: DeepObjectEncoding,
) -> ParameterPlan {
    let projection = projector.project(&parameter.schema);
    let schema_is_object_only = matches!(
        projection,
        Projection::Known(domain)
            if domain_is_required_with_optional_null(domain, Domain::OBJECT)
    );
    let schema_is_string_only = matches!(
        projection,
        Projection::Known(domain)
            if domain_is_required_with_optional_null(domain, Domain::STRING)
    );
    ParameterPlan {
        name: parameter.name.clone(),
        schema: parameter.schema.clone(),
        resolved: resolve_parameter_serialization(
            parameter,
            schema_is_object_only,
            schema_is_string_only,
            deep_object,
        ),
        caller_serialized: parameter_requires_caller_serialization(
            parameter,
            schema_is_string_only,
        ),
        source: parameter.source.clone(),
    }
}

pub(crate) fn build_body_plan(
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
            .map(|media| BodyPlanArm {
                media: media.full.clone(),
                plan: body_plan_for_media(media, projector),
                source: media.source.clone(),
            })
            .collect::<Vec<_>>();
        arms.sort_by(|left, right| left.media.cmp(&right.media));
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
pub(crate) fn body_plan_for_media(
    media: &MediaType,
    projector: &PrimitiveDomainProjector<'_>,
) -> BodyPlan {
    let schema = media.schema_present.then(|| media.schema.clone());
    // Streaming is decided before every other essence rule, exactly as it is on the response side:
    // a marked `+json` or `text/*` body must never be silently buffered by the rule that would
    // otherwise claim it. A media class the compiler already refuses never reaches here — the
    // request diagnostics run that refusal first.
    if media.streaming_marked || media.essence == "text/event-stream" {
        BodyPlan::TopLevelStream {
            media: media.full.clone(),
            source: media.source.clone(),
        }
    } else if is_json(&media.essence) {
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
    } else if media.essence == "multipart/form-data" {
        BodyPlan::Multipart {
            media: media.full.clone(),
            fields: form_fields(media, true, projector),
            source: media.source.clone(),
        }
    } else if media.essence.starts_with("text/") {
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
    let Ok(properties) = collect_form_properties(&media.schema, projector) else {
        return Vec::new();
    };
    properties
        .into_iter()
        .map(|property| {
            let encoding = media
                .encodings
                .iter()
                .find(|(field, _)| field == property.name)
                .map(|(_, encoding)| encoding);
            field_plan(
                property.name,
                property.schema.as_ref(),
                property.required,
                encoding,
                media,
                multipart,
                projector,
            )
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FormProperty<'schema> {
    pub(crate) name: &'schema str,
    pub(crate) schema: Cow<'schema, SchemaNode>,
    pub(crate) required: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FormProperties<'schema> {
    Object(&'schema [(String, SchemaNode, crate::ir::PropMeta)]),
    Collected(Vec<FormProperty<'schema>>),
}

pub(crate) enum FormPropertiesIter<'schema> {
    Object(std::slice::Iter<'schema, (String, SchemaNode, crate::ir::PropMeta)>),
    Collected(std::vec::IntoIter<FormProperty<'schema>>),
}

impl<'schema> Iterator for FormPropertiesIter<'schema> {
    type Item = FormProperty<'schema>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Object(properties) => {
                properties.next().map(|(name, schema, meta)| FormProperty {
                    name,
                    schema: Cow::Borrowed(schema),
                    required: meta.required,
                })
            }
            Self::Collected(properties) => properties.next(),
        }
    }
}

impl<'schema> IntoIterator for FormProperties<'schema> {
    type Item = FormProperty<'schema>;
    type IntoIter = FormPropertiesIter<'schema>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Object(properties) => FormPropertiesIter::Object(properties.iter()),
            Self::Collected(properties) => FormPropertiesIter::Collected(properties.into_iter()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FormPropertiesError {
    /// The schema constrains nothing — absent, `{}`, or an unsupported construct. The document is
    /// valid; it just says nothing this encoding can correlate.
    Unconstrained,
    /// The schema positively excludes an object, so the document contradicts the encoding.
    NotObject,
}

/// Collects the named fields a flat form encoding can correlate with wire names.
///
/// `allOf` is a conjunction, so a property required by any branch is required by the result.
/// `oneOf` and `anyOf` are alternatives, so a property is required only when every branch declares
/// it as required. First occurrence order is preserved across both branch and property traversal;
/// the hash map is lookup-only and never contributes iteration order.
pub(crate) fn collect_form_properties<'schema, 'ir>(
    schema: &'schema SchemaNode,
    projector: &'schema PrimitiveDomainProjector<'ir>,
) -> Result<FormProperties<'schema>, FormPropertiesError>
where
    'ir: 'schema,
{
    // An absent schema, `{}`, and an unsupported construct all reach here projecting to the full
    // domain: the document is valid and simply says nothing, which is a different fact from a
    // schema that says "string" where the encoding needs named properties. Only the latter can be
    // called a contradiction, so only the latter refuses.
    match projector.project(schema) {
        Projection::Known(domain)
            if domain_is_required_with_optional_null(domain, Domain::OBJECT) => {}
        Projection::Known(Domain::FULL) | Projection::Unsupported => {
            return Err(FormPropertiesError::Unconstrained);
        }
        Projection::Known(_) => return Err(FormPropertiesError::NotObject),
    }
    collect_form_properties_inner(schema, projector, &mut HashSet::new())
}

fn collect_form_properties_inner<'schema, 'ir>(
    schema: &'schema SchemaNode,
    projector: &'schema PrimitiveDomainProjector<'ir>,
    visiting: &mut HashSet<usize>,
) -> Result<FormProperties<'schema>, FormPropertiesError>
where
    'ir: 'schema,
{
    match schema {
        SchemaNode::Ref { target, .. } => {
            let Some(index) =
                schema_index(&projector.indices, &target.source_id, &target.json_pointer)
            else {
                return Ok(FormProperties::Collected(Vec::new()));
            };
            if !visiting.insert(index) {
                return Ok(FormProperties::Collected(Vec::new()));
            }
            let properties = projector.schemas.get(index).map_or_else(
                || Ok(FormProperties::Collected(Vec::new())),
                |resolved| collect_form_properties_inner(&resolved.schema, projector, visiting),
            );
            visiting.remove(&index);
            properties
        }
        SchemaNode::Object { properties, .. } => Ok(FormProperties::Object(properties)),
        SchemaNode::AllOf { branches, .. } => {
            merge_form_property_branches(branches, projector, visiting, FormPropertyMerge::AllOf)
        }
        SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
            merge_form_property_branches(branches, projector, visiting, FormPropertyMerge::AnyOf)
        }
        SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Array { .. }
        | SchemaNode::Tuple { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => Ok(FormProperties::Collected(Vec::new())),
    }
}

#[derive(Clone, Copy)]
enum FormPropertyMerge {
    AllOf,
    AnyOf,
}

fn merge_form_property_branches<'schema, 'ir>(
    branches: &'schema [SchemaNode],
    projector: &'schema PrimitiveDomainProjector<'ir>,
    visiting: &mut HashSet<usize>,
    merge: FormPropertyMerge,
) -> Result<FormProperties<'schema>, FormPropertiesError>
where
    'ir: 'schema,
{
    let mut merged = Vec::<FormProperty<'schema>>::new();
    let mut slot_by_name = HashMap::<&'schema str, usize>::new();
    let mut required_counts = Vec::<usize>::new();
    let mut present_counts = Vec::<usize>::new();
    for branch in branches {
        let properties = collect_form_properties_inner(branch, projector, visiting)?;
        for property in properties.into_iter() {
            if let Some(&slot) = slot_by_name.get(property.name) {
                if !schemas_structurally_equal(
                    merged[slot].schema.as_ref(),
                    property.schema.as_ref(),
                ) {
                    merge_form_property_schema(&mut merged[slot].schema, property.schema, merge);
                }
                present_counts[slot] += 1;
                required_counts[slot] += usize::from(property.required);
                if matches!(merge, FormPropertyMerge::AllOf) {
                    merged[slot].required |= property.required;
                }
            } else {
                let slot = merged.len();
                slot_by_name.insert(property.name, slot);
                required_counts.push(usize::from(property.required));
                present_counts.push(1);
                merged.push(property);
            }
        }
    }
    if matches!(merge, FormPropertyMerge::AnyOf) {
        for (slot, property) in merged.iter_mut().enumerate() {
            property.required =
                present_counts[slot] == branches.len() && required_counts[slot] == branches.len();
        }
    }
    Ok(FormProperties::Collected(merged))
}

fn merge_form_property_schema<'schema>(
    existing: &mut Cow<'schema, SchemaNode>,
    incoming: Cow<'schema, SchemaNode>,
    merge: FormPropertyMerge,
) {
    match (merge, &mut *existing) {
        (FormPropertyMerge::AllOf, Cow::Owned(SchemaNode::AllOf { branches, .. }))
        | (FormPropertyMerge::AnyOf, Cow::Owned(SchemaNode::AnyOf { branches, .. })) => {
            branches.push(incoming.into_owned());
            return;
        }
        _ => {}
    }
    let previous = std::mem::replace(
        existing,
        Cow::Owned(SchemaNode::Any {
            meta: SchemaMeta::default(),
        }),
    )
    .into_owned();
    *existing = Cow::Owned(match merge {
        FormPropertyMerge::AllOf => SchemaNode::AllOf {
            branches: vec![previous, incoming.into_owned()],
            meta: SchemaMeta::default(),
        },
        FormPropertyMerge::AnyOf => SchemaNode::AnyOf {
            branches: vec![previous, incoming.into_owned()],
            discriminator: None,
            meta: SchemaMeta::default(),
        },
    });
}

/// Whether two branches' declarations of one property name describe the same thing.
///
/// Provenance and prose are cleared first. Two branches documenting the same field with different
/// wording describe the same field, and refusing over a `description` would reject documents whose
/// only sin is being written twice. What survives the clearing — type, constraints, applicators —
/// is what decides the encoding and the emitted type, so a difference there is a real conflict.
fn schemas_structurally_equal(left: &SchemaNode, right: &SchemaNode) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    clear_schema_provenance(&mut left);
    clear_schema_provenance(&mut right);
    left == right
}

fn clear_schema_provenance(schema: &mut SchemaNode) {
    let meta = match schema {
        SchemaNode::Ref { meta, .. }
        | SchemaNode::Primitive { meta, .. }
        | SchemaNode::Finite { meta, .. }
        | SchemaNode::Object { meta, .. }
        | SchemaNode::Array { meta, .. }
        | SchemaNode::Tuple { meta, .. }
        | SchemaNode::AllOf { meta, .. }
        | SchemaNode::OneOf { meta, .. }
        | SchemaNode::AnyOf { meta, .. }
        | SchemaNode::Any { meta }
        | SchemaNode::Never { meta }
        | SchemaNode::Unknown { meta, .. } => meta,
    };
    meta.source = SourceRef::default();
    meta.docs = crate::ir::SchemaDocs::default();
    if let Some(applicators) = meta.validation_applicators.as_deref_mut() {
        for nested in applicators
            .not
            .iter_mut()
            .chain(applicators.property_names.iter_mut())
            .chain(applicators.unevaluated_properties.iter_mut())
            .chain(applicators.unevaluated_items.iter_mut())
        {
            clear_schema_provenance(nested);
        }
        for pattern in &mut applicators.pattern_properties {
            clear_schema_provenance(&mut pattern.schema);
        }
        if let Some(contains) = applicators.contains.as_deref_mut() {
            clear_schema_provenance(&mut contains.schema);
        }
        for (_, dependent) in &mut applicators.dependent_schemas {
            clear_schema_provenance(dependent);
        }
        if let Some(conditional) = applicators.conditional.as_deref_mut() {
            clear_schema_provenance(&mut conditional.condition);
            if let Some(then_schema) = conditional.then_schema.as_deref_mut() {
                clear_schema_provenance(then_schema);
            }
            if let Some(else_schema) = conditional.else_schema.as_deref_mut() {
                clear_schema_provenance(else_schema);
            }
        }
    }
    match schema {
        SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } => {
            for (_, property, _) in properties {
                clear_schema_provenance(property);
            }
            if let AdditionalProperties::Allowed(Some(additional))
            | AdditionalProperties::Schema(additional) = additional_properties
            {
                clear_schema_provenance(additional);
            }
        }
        SchemaNode::Array { items, .. } => clear_schema_provenance(items),
        SchemaNode::Tuple {
            prefix_items, rest, ..
        } => {
            for item in prefix_items {
                clear_schema_provenance(item);
            }
            if let crate::ir::TupleRest::Schema(rest) = rest {
                clear_schema_provenance(rest);
            }
        }
        SchemaNode::AllOf { branches, .. } => {
            for branch in branches {
                clear_schema_provenance(branch);
            }
        }
        SchemaNode::OneOf {
            branches,
            discriminator,
            ..
        }
        | SchemaNode::AnyOf {
            branches,
            discriminator,
            ..
        } => {
            for branch in branches {
                clear_schema_provenance(branch);
            }
            if let Some(discriminator) = discriminator.as_deref_mut() {
                discriminator.source = SourceRef::default();
            }
        }
        SchemaNode::Ref { .. }
        | SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => {}
    }
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
                let binary_upload = explicit_binary_upload(schema, projector, &mut HashSet::new());
                (canonicals, all_concrete, binary_upload, true)
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

fn explicit_binary_upload(
    schema: &SchemaNode,
    projector: &PrimitiveDomainProjector<'_>,
    visited: &mut HashSet<(String, String)>,
) -> bool {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    match resolved {
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: Some(format),
            ..
        } => format == "binary",
        SchemaNode::Array { items, .. } if enter_array_items(items, visited) => {
            explicit_binary_upload(items, projector, visited)
        }
        SchemaNode::AllOf { branches, .. } => branches
            .iter()
            .any(|branch| explicit_binary_upload(branch, projector, visited)),
        SchemaNode::Ref { .. }
        | SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Object { .. }
        | SchemaNode::Array { .. }
        | SchemaNode::Tuple { .. }
        | SchemaNode::OneOf { .. }
        | SchemaNode::AnyOf { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => false,
    }
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
            format,
            ..
        } if format.as_deref() == Some("binary") => ("application/octet-stream", true),
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

/// Plans how each property of a `multipart/form-data` response object decodes.
///
/// The declared object's `properties` become the named parts and its `additionalProperties` becomes
/// the rule for a part naming none of them. A schema that is not object-shaped at all (an absent
/// `schema` keyword, `type: string`, a broken `$ref`) declares no property to map onto, so every
/// part falls to the open fallback and the emitted type is a bare index signature.
fn multipart_response_plan(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> MultipartResponsePlan {
    // Nothing constrains the part, so the property renders as `unknown` and the wire classifies it.
    // The node is synthesized rather than borrowed from the object: the object's own schema would
    // render as the whole decoded type, which is not what an undeclared part carries.
    let open_fallback = |schema: &SchemaNode| MultipartResponseShape {
        payload: MultipartResponsePayload::Wire,
        repeated: false,
        schema: SchemaNode::Any {
            meta: SchemaNode::meta(schema).clone(),
        },
    };
    let Some(SchemaNode::Object {
        properties,
        additional_properties,
        ..
    }) = projector.resolve_schema(schema)
    else {
        return MultipartResponsePlan {
            parts: Vec::new(),
            additional: open_fallback(schema),
            open: true,
        };
    };
    let parts = properties
        .iter()
        .map(|(name, property, meta)| MultipartResponsePartPlan {
            name: name.clone(),
            required: meta.required,
            shape: multipart_response_shape(property, version, projector),
        })
        .collect();
    let (additional, open) = match additional_properties {
        AdditionalProperties::Schema(additional)
        | AdditionalProperties::Allowed(Some(additional)) => (
            multipart_response_shape(additional, version, projector),
            true,
        ),
        AdditionalProperties::Allowed(None) => (open_fallback(schema), true),
        // A closed schema still decodes an unexpected part rather than dropping it — the same thing
        // `JSON.parse` does with an undeclared member — so the fallback shape survives; only the
        // emitted index signature goes away.
        AdditionalProperties::Forbidden => (open_fallback(schema), false),
    };
    MultipartResponsePlan {
        parts,
        additional,
        open,
    }
}

fn multipart_response_shape(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
) -> MultipartResponseShape {
    let mut visited = HashSet::new();
    let repeated = matches!(
        projector.resolve_schema(schema).unwrap_or(schema),
        SchemaNode::Array { .. }
    );
    MultipartResponseShape {
        payload: multipart_response_payload(schema, version, projector, &mut visited),
        repeated,
        schema: schema.clone(),
    }
}

/// Classifies one part's payload, descending through `$ref` and array `items` exactly as the
/// request encoder's classifier does — a part carries one element of a repeated property, so the
/// item schema, not the array, is what decides.
///
/// The two arms that diverge from `default_part_media` are deliberate, because that function answers
/// "what may a caller hand in", and this one answers "what does the decoder produce":
///   - an unconstrained schema is `Wire` rather than a binary upload, since its rendered type is
///     `unknown` and a `Uint8Array` claim would be unfounded;
///   - a bare `enum`/`const` without a declared type stays a value, never bytes.
fn multipart_response_payload(
    schema: &SchemaNode,
    version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
    visited: &mut HashSet<(String, String)>,
) -> MultipartResponsePayload {
    let resolved = projector.resolve_schema(schema).unwrap_or(schema);
    match resolved {
        SchemaNode::Any { .. } | SchemaNode::Unknown { .. } => MultipartResponsePayload::Wire,
        SchemaNode::Array { items, .. } if enter_array_items(items, visited) => {
            multipart_response_payload(items, version, projector, visited)
        }
        // OAS 3.0's only binary spelling. OAS 3.1 replaced it with `contentEncoding`, which says the
        // string arrives already encoded and therefore stays text — the same reading the request
        // encoder takes (`default_part_media`), where `contentEncoding` clears `binary_upload`.
        SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format,
            ..
        } if version == OasVersion::V3_0 && format.as_deref() == Some("binary") => {
            MultipartResponsePayload::Binary
        }
        _ => {
            let (media, _) = default_part_media(resolved, version, projector, visited);
            match content_payload_kind(resolved, media, projector, visited) {
                PayloadKind::Json => MultipartResponsePayload::Json,
                PayloadKind::Text | PayloadKind::Binary => MultipartResponsePayload::Text,
            }
        }
    }
}

fn response_table(
    operation: &crate::ir::Operation,
    oas_version: OasVersion,
    projector: &PrimitiveDomainProjector<'_>,
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
                .map(|media| {
                    // The runtime discriminates response arms on the canonical full media type, so a
                    // parameter-differing key (e.g. `application/json;stream=watch`) produces a
                    // distinct arm. Decoding uses the essence plus the schema projection for the
                    // XML-family opaque-vs-structural distinction.
                    let decoder = classify_response_media(media, projector);
                    ResponseMediaPlan {
                        media: media.full.clone(),
                        decoder,
                        multipart: (decoder == DecoderClass::Multipart).then(|| {
                            multipart_response_plan(&media.schema, oas_version, projector)
                        }),
                        schema: media.schema.clone(),
                        streaming_marked: media.streaming_marked,
                        source: media.source.clone(),
                    }
                })
                .collect::<Vec<_>>();
            let static_bodyless = operation.method.eq_ignore_ascii_case("head")
                || matches!(
                    &response.status,
                    ResponseStatus::Exact(value) if matches!(value.as_str(), "204" | "205" | "304")
                );
            let payload = if media.is_empty() {
                PayloadDisposition::NoPayload
            } else if static_bodyless {
                PayloadDisposition::StaticBodyless
            } else {
                PayloadDisposition::Payload
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

const CODE_DEEP_OBJECT_FALSE_EXPLODE: &str = "OASTS5005";
const CODE_CONTENT_CALLER_SERIALIZED: &str = "OASTS5006";

fn plan_parameters(
    operation: &Operation,
    projector: &PrimitiveDomainProjector<'_>,
    deep_object: DeepObjectEncoding,
    sink: &mut DiagnosticSink,
) -> Vec<ParameterPlan> {
    operation
        .parameters
        .iter()
        .filter_map(|parameter| {
            if parameter.location == ParamLocation::Header
                && forbidden_request_header_name(&parameter.name)
            {
                sink.push(source_diagnostic(
                    "OASTS5001",
                    format!(
                        "header parameter '{}' is dropped from the generated client because Fetch forbids setting that request header",
                        parameter.name
                    ),
                    &parameter.source,
                    Severity::Warning,
                ));
                return None;
            }
            let plan = parameter_plan(parameter, projector, deep_object);
            // A content media the client cannot serialize is carried as the caller's pre-serialized
            // string; the media type is present on this class by construction.
            if let Some(media) = &parameter.content_media_type
                && plan.caller_serialized
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
            if plan.resolved.style == ParamStyle::DeepObject && parameter.explode == Some(false) {
                sink.push(source_diagnostic(
                    CODE_DEEP_OBJECT_FALSE_EXPLODE,
                    "explode: false with deepObject is undefined in OAS; treating as deepObject",
                    &parameter.source,
                    Severity::Warning,
                ));
            }
            let projection = projector.project(&parameter.schema);
            if invalid_style_combination(
                plan.resolved.location,
                plan.resolved.style,
                plan.resolved.explode,
                projection,
                deep_object,
            ) {
                sink.push(source_diagnostic(
                    "OASTS5004",
                    format!(
                        "parameter '{}' has an unsupported {:?} serialization combination{}",
                        parameter.name,
                        plan.resolved.style,
                        extended_remedy(
                            plan.resolved.location,
                            plan.resolved.style,
                            plan.resolved.explode,
                            projection,
                            deep_object,
                        )
                    ),
                    &parameter.source,
                    Severity::Error,
                ));
            }
            Some(plan)
        })
        .collect()
}

fn invalid_style_combination(
    location: ParamLocation,
    style: ParamStyle,
    explode: bool,
    projection: Projection,
    deep_object: DeepObjectEncoding,
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
        // OpenAPI defines `deepObject` for `object` only, so strict admits nothing else. Bracket-path
        // encoding is total over shapes — an array brackets by index, a scalar is the same rule at
        // depth zero — so extended admits every projection and the schema's type stops deciding.
        // The axes that still reject are unchanged: an illegal location/style pair above, and
        // `explode: false`, which is a different question from the schema's type.
        (ParamStyle::DeepObject, Projection::Known(domain)) => {
            deep_object == DeepObjectEncoding::Strict
                && !domain_is_required_with_optional_null(domain, Domain::OBJECT)
        }
        (
            ParamStyle::SpaceDelimited | ParamStyle::PipeDelimited | ParamStyle::DeepObject,
            Projection::Unsupported,
        ) => false,
        _ => false,
    }
}

/// The remedy clause appended to `OASTS5004` when the only thing rejecting this combination is the
/// strict `deepObject` reading — the one axis a user can move without editing a document they may
/// not own. Every other rejection (an illegal location/style pair, `explode: false`, a delimited
/// style over a scalar) is unaffected by the compat setting, so naming it there would send the
/// reader after a switch that cannot help.
fn extended_remedy(
    location: ParamLocation,
    style: ParamStyle,
    explode: bool,
    projection: Projection,
    deep_object: DeepObjectEncoding,
) -> &'static str {
    if deep_object == DeepObjectEncoding::Strict
        && !invalid_style_combination(
            location,
            style,
            explode,
            projection,
            DeepObjectEncoding::Extended,
        )
    {
        "; OpenAPI leaves deepObject undefined for arrays and scalars, so it is rejected by default — set compat.deepObjectEncoding: extended to encode it as a bracket path"
    } else {
        ""
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
            if forbidden_request_header_name(name) {
                sink.push(source_diagnostic(
                    "OASTS5001",
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
                    "OASTS5002",
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
                        "OASTS5003",
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
                        "OASTS5003",
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
/// kind is representable; spec-illegal kinds remain fatal through OASTS5401 so the client never
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
            "OASTS5402",
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
                        Severity::Warning,
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
                "OASTS5401",
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

fn diagnose_base_url(operation: &Operation, base_url: &BaseUrlPlan, sink: &mut DiagnosticSink) {
    let BaseUrlPlan::Server { index, servers } = base_url else {
        return;
    };
    let index = *index as usize;
    if servers.get(index).is_none() {
        sink.push(source_diagnostic(
            "OASTS5301",
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

/// Multipart-only admission matrix for an explicit encoding `style`/`explode` keyword (OASTS5112).
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
    deep_object: DeepObjectEncoding,
    sink: &mut DiagnosticSink,
) {
    let multipart = media.essence.starts_with("multipart/");
    if !multipart && media.essence != "application/x-www-form-urlencoded" {
        return;
    }
    let properties = match collect_form_properties(&media.schema, projector) {
        Ok(properties) => properties,
        Err(error) => {
            sink.push(form_properties_diagnostic(media, error));
            return;
        }
    };
    for property in properties.into_iter() {
        let name = property.name;
        let schema = property.schema.as_ref();
        if multipart && contains_control(name) {
            sink.push(source_diagnostic(
                "OASTS5101",
                format!(
                    "multipart field name {name:?} contains a control byte and cannot be represented"
                ),
                &schema.meta().source,
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
            let projection = projector.project(schema);
            if invalid_style_combination(
                ParamLocation::Query,
                style,
                explode,
                projection,
                deep_object,
            ) {
                let remedy = extended_remedy(
                    ParamLocation::Query,
                    style,
                    explode,
                    projection,
                    deep_object,
                );
                sink.push(source_diagnostic(
                    "OASTS5004",
                    format!(
                        "encoding for field '{name}' has an unsupported {style:?} serialization combination{remedy}"
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
                            "OASTS5105",
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
                    "OASTS5107",
                    format!(
                        "form field '{name}' has a binary payload that application/x-www-form-urlencoded cannot represent; use multipart/form-data for binary uploads or base64-encode the value (type: string, contentEncoding: base64url)"
                    ),
                    &schema.meta().source,
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
                        "OASTS5108",
                        format!(
                            "form field '{name}' declares a text media type but its schema is an object; use application/json (or a *+json media type) for structured urlencoded values"
                        ),
                        &schema.meta().source,
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

fn form_properties_diagnostic(media: &MediaType, error: FormPropertiesError) -> Diagnostic {
    match error {
        // A warning, not an error: the document is valid OpenAPI — `schema` is an optional field of
        // the Media Type Object — so refusing would reject a document that is merely underspecified.
        // It still has to be said, because the encoder that comes out of it carries no fields and
        // therefore sends an empty body.
        FormPropertiesError::Unconstrained => source_diagnostic(
            CODE_FORM_SCHEMA_UNCONSTRAINED,
            format!(
                "request media '{}' declares no schema properties, so its encoder carries no fields and sends an empty body",
                media.essence
            ),
            &media.source,
            Severity::Warning,
        ),
        FormPropertiesError::NotObject => source_diagnostic(
            CODE_FORM_SCHEMA_PROPERTIES,
            format!(
                "request media '{}' schema declares no object properties to correlate with encoded field names",
                media.essence
            ),
            &media.source,
            Severity::Error,
        ),
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
                        "OASTS5103",
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
                        "OASTS5102",
                        format!(
                            "declared Content-Transfer-Encoding for field '{field_name}' includes a value other than 7bit, 8bit, or binary and is never emitted"
                        ),
                        &header.source,
                        Severity::Warning,
                    ));
                }
            }
            _ => sink.push(source_diagnostic(
                "OASTS5104",
                format!(
                    "multipart field '{field_name}' declares header '{header_name}', but it is never emitted because RFC 7578 §4.8 permits only Content-Disposition, Content-Type, and Content-Transfer-Encoding part headers"
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
        // XML needing structural mapping is refused before the streaming mark is read, so the
        // vendor extension cannot launder a media class this compiler already rejects into an
        // opaque byte stream. The response classifier applies the same precedence.
        if xml_requires_structural_mapping(media, projector) {
            sink.push(source_diagnostic(
                "OASTS5201",
                format!(
                    "request body media '{}' is XML, which Oasts does not support",
                    media.essence
                ),
                &media.source,
                Severity::Error,
            ));
        } else if media.streaming_marked || media.essence == "text/event-stream" {
            // A streaming request body is carried, not classified further: the string-projection
            // rule below is about converting a typed value to text, and a stream has no value to
            // convert. Reaching that rule would refuse a perfectly sendable byte stream over the
            // shape of a schema nothing ever reads.
        } else if media.essence.starts_with("text/")
            && !is_json(&media.essence)
            && media.schema_present
            && projection_excludes_string(projector.project(&media.schema))
        {
            sink.push(source_diagnostic(
                "OASTS5203",
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

/// Whether a response header's declared value is an opaque wire string rather than its typed schema.
/// A content-sourced header whose media type is not JSON-family (`application/json`, `text/json`,
/// or a `+json` structured suffix) transmits a caller-parsed string on the wire, so both the emitted
/// header type and its validator treat it as a bare `string`; JSON-family and schema+style headers
/// keep their schema.
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

pub(crate) struct PrimitiveDomainProjector<'ir> {
    schemas: &'ir [crate::ir::NamedSchema],
    indices: HashMap<(&'ir str, &'ir str), usize>,
    domains: Vec<Projection>,
}

impl ResponseMediaProjector for PrimitiveDomainProjector<'_> {
    fn response_schema_projection(&self, schema: &SchemaNode) -> ResponseSchemaProjection {
        match self.project(schema) {
            Projection::Known(domain)
                if domain_is_required_with_optional_null(domain, Domain::STRING) =>
            {
                ResponseSchemaProjection::StringWithOptionalNull
            }
            Projection::Known(domain) if domain.contains(Domain::STRING) => {
                ResponseSchemaProjection::IncludesString
            }
            Projection::Known(_) => ResponseSchemaProjection::ExcludesString,
            Projection::Unsupported => ResponseSchemaProjection::Unsupported,
        }
    }
}

impl<'ir> PrimitiveDomainProjector<'ir> {
    pub(crate) fn new(ir: &'ir Ir) -> Self {
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

    pub(crate) fn admits_collection(&self, schema: &SchemaNode) -> bool {
        matches!(
            self.project(schema),
            Projection::Known(domain)
                if domain.contains(Domain::ARRAY) || domain.contains(Domain::OBJECT)
        )
    }

    pub(crate) fn resolve_schema<'schema>(
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
        AdditionalProperties, ConditionalApplicator, ContainsApplicator, Discriminator, Ir,
        MediaType, NamedSchema, NamedSecurityScheme, OasVersion, Operation, ParamLocation,
        ParamStyle, PatternProperty, PrimitiveType, PropMeta, ResponseStatus, SchemaMeta,
        SchemaNode, SchemaRef, SecKind, SourceRef, TupleRest, ValidationApplicators,
    };
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::{Analyzed, analyze};

    fn analyzed(document: &Value, client: Value) -> (TempDir, Analyzed, ResolvedConfig) {
        let (temp, analyzed, config, sink) = analyzed_with_diagnostics(document, client);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        (temp, analyzed, config)
    }

    /// Same as `analyzed`, with the validation block spelled out. Only the tests that turn
    /// validation on need it; everything else keeps the engine off.
    fn analyzed_with_validation(
        document: &Value,
        client: Value,
        validation: Value,
    ) -> (TempDir, Analyzed, ResolvedConfig) {
        let (temp, analyzed, config, sink) =
            analyzed_with_options(document, client, Some(validation));
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        (temp, analyzed, config)
    }

    fn analyzed_with_diagnostics(
        document: &Value,
        client: Value,
    ) -> (TempDir, Analyzed, ResolvedConfig, DiagnosticSink) {
        analyzed_with_options(document, client, None)
    }

    fn analyzed_with_options(
        document: &Value,
        client: Value,
        validation: Option<Value>,
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
            "artifacts": {
                "types": true,
                "client": true,
                // The generated engine requires this artifact, and the tests that turn validation
                // on are exactly the ones that name that engine.
                "validators": validation.is_some()
            },
            "client": client,
            "validation": validation
                .unwrap_or_else(|| json!({ "engine": "off", "unchecked": "allow" }))
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

    /// The single response media plan a one-operation document produces.
    fn response_media_plan(document: &Value) -> ResponseMediaPlan {
        let (_temp, analyzed, config) = analyzed(
            document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        model.operations[0].response_table[0].media[0].clone()
    }

    fn multipart_document(version: &str, schema: Value) -> Value {
        json!({
            "openapi": version,
            "info": { "title": "t", "version": "1" },
            "paths": { "/bundle": { "get": {
                "operationId": "getbundle",
                "responses": { "200": { "description": "ok", "content": { "multipart/form-data": { "schema": schema } } } }
            } } }
        })
    }

    /// The payload kind one declared property is planned with.
    fn part_payload(version: &str, property: Value) -> MultipartResponsePayload {
        let plan = response_media_plan(&multipart_document(
            version,
            json!({ "type": "object", "properties": { "field": property } }),
        ))
        .multipart
        .expect("multipart plan");
        plan.parts[0].shape.payload
    }

    #[test]
    fn multipart_response_parts_classify_by_shape_not_by_the_wire() {
        // OAS 3.0's binary spelling is the only one that leaves the JSON data model.
        assert_eq!(
            part_payload("3.0.3", json!({ "type": "string", "format": "binary" })),
            MultipartResponsePayload::Binary
        );
        // `format: byte` is base64 *text* on the wire, exactly as the request encoder reads it.
        assert_eq!(
            part_payload("3.0.3", json!({ "type": "string", "format": "byte" })),
            MultipartResponsePayload::Text
        );
        // OAS 3.1 `contentEncoding` says the string arrives already encoded, so it stays text —
        // 3.1 has no binary part spelling this classifier can see.
        assert_eq!(
            part_payload(
                "3.1.0",
                json!({ "type": "string", "contentEncoding": "base64" })
            ),
            MultipartResponsePayload::Text
        );
        assert_eq!(
            part_payload("3.1.0", json!({ "type": "object" })),
            MultipartResponsePayload::Json
        );
        assert_eq!(
            part_payload("3.1.0", json!({ "type": "integer" })),
            MultipartResponsePayload::Text
        );
        // A bare enum without a declared type is a value, never bytes — the arm where this
        // classifier deliberately parts company with `default_part_media`.
        assert_eq!(
            part_payload("3.1.0", json!({ "enum": ["a", "b"] })),
            MultipartResponsePayload::Text
        );
        // An unconstrained property renders as `unknown`, so the part's own Content-Type decides.
        assert_eq!(
            part_payload("3.1.0", json!({})),
            MultipartResponsePayload::Wire
        );
        // An array classifies by its items and repeats; nothing deeper changes the repeat flag.
        let arrays = response_media_plan(&multipart_document(
            "3.0.3",
            json!({
                "type": "object",
                "properties": {
                    "files": { "type": "array", "items": { "type": "string", "format": "binary" } },
                    "labels": { "type": "array", "items": { "type": "string" } }
                }
            }),
        ))
        .multipart
        .expect("multipart plan");
        assert_eq!(
            arrays.parts[0].shape.payload,
            MultipartResponsePayload::Binary
        );
        assert!(arrays.parts[0].shape.repeated);
        assert_eq!(
            arrays.parts[1].shape.payload,
            MultipartResponsePayload::Text
        );
        assert!(arrays.parts[1].shape.repeated);
    }

    #[test]
    fn multipart_response_parts_follow_refs_and_survive_a_ref_cycle() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "components": { "schemas": {
                "File": { "type": "string", "format": "binary" },
                "Tree": { "type": "array", "items": { "$ref": "#/components/schemas/Tree" } }
            } },
            "paths": { "/bundle": { "get": {
                "operationId": "getbundle",
                "responses": { "200": { "description": "ok", "content": { "multipart/form-data": { "schema": {
                    "type": "object",
                    "properties": {
                        "file": { "$ref": "#/components/schemas/File" },
                        "tree": { "$ref": "#/components/schemas/Tree" }
                    }
                } } } } }
            } } }
        });
        let plan = response_media_plan(&document)
            .multipart
            .expect("multipart plan");

        assert_eq!(
            plan.parts[0].shape.payload,
            MultipartResponsePayload::Binary
        );
        assert!(!plan.parts[0].shape.repeated);
        // A ref cycle through `items` bottoms out at the text fallback instead of recursing.
        assert_eq!(plan.parts[1].shape.payload, MultipartResponsePayload::Text);
        assert!(plan.parts[1].shape.repeated);
    }

    #[test]
    fn multipart_response_additional_properties_decide_the_open_fallback() {
        // The published open-ended shape: no declared property, every part admitted.
        let cloudflare = response_media_plan(&multipart_document(
            "3.0.3",
            json!({
                "type": "object",
                "additionalProperties": { "type": "array", "items": { "type": "string", "format": "binary" } }
            }),
        ))
        .multipart
        .expect("multipart plan");
        assert!(cloudflare.parts.is_empty());
        assert!(cloudflare.open);
        assert_eq!(
            cloudflare.additional.payload,
            MultipartResponsePayload::Binary
        );
        assert!(cloudflare.additional.repeated);

        // A closed schema keeps a decoding rule for an unexpected part; only the type closes.
        let closed = response_media_plan(&multipart_document(
            "3.0.3",
            json!({ "type": "object", "additionalProperties": false }),
        ))
        .multipart
        .expect("multipart plan");
        assert!(!closed.open);
        assert_eq!(closed.additional.payload, MultipartResponsePayload::Wire);

        // `additionalProperties: true` and an omitted keyword both leave an unconstrained fallback.
        for additional in [json!(true), json!(null)] {
            let mut schema = json!({ "type": "object" });
            if !additional.is_null() {
                schema["additionalProperties"] = additional;
            }
            let plan = response_media_plan(&multipart_document("3.0.3", schema))
                .multipart
                .expect("multipart plan");
            assert!(plan.open);
            assert_eq!(plan.additional.payload, MultipartResponsePayload::Wire);
        }

        // A response schema that is not object-shaped declares no property to map onto.
        let opaque = response_media_plan(&multipart_document("3.0.3", json!({ "type": "string" })))
            .multipart
            .expect("multipart plan");
        assert!(opaque.parts.is_empty());
        assert!(opaque.open);
        assert_eq!(opaque.additional.payload, MultipartResponsePayload::Wire);
    }

    #[test]
    fn payload_kind_names_are_the_emitted_descriptor_values() {
        for (payload, name) in [
            (MultipartResponsePayload::Json, "json"),
            (MultipartResponsePayload::Text, "text"),
            (MultipartResponsePayload::Binary, "binary"),
            (MultipartResponsePayload::Wire, "wire"),
        ] {
            assert_eq!(payload.as_str(), name);
        }
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

    fn form_document(media: &str, schema: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": { "/forms": { "post": {
                "operationId": "sendForm",
                "requestBody": {
                    "required": true,
                    "content": { media: { "schema": schema } }
                },
                "responses": { "204": { "description": "ok" } }
            }}}
        })
    }

    fn planned_form_fields(media: &str, schema: Value) -> (Vec<FormFieldPlan>, Vec<Diagnostic>) {
        let document = form_document(media, schema);
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let fields = match model.operations[0].body_plan.as_ref().expect("body plan") {
            BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
                fields.clone()
            }
            plan => panic!("expected form body plan, got {plan:#?}"),
        };
        (fields, sink.into_sorted_vec())
    }

    #[test]
    fn allof_form_body_merges_properties_in_declaration_order() {
        let (fields, diagnostics) = planned_form_fields(
            "application/x-www-form-urlencoded",
            json!({
                "allOf": [
                    {
                        "type": "object",
                        "required": ["left", "shared"],
                        "properties": {
                            "left": { "type": "string" },
                            "shared": { "type": "string" }
                        }
                    },
                    {
                        "type": "object",
                        "required": ["right"],
                        "properties": {
                            "shared": { "type": "string" },
                            "right": { "type": "boolean" }
                        }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.required))
                .collect::<Vec<_>>(),
            [("left", true), ("shared", true), ("right", true)]
        );
    }

    #[test]
    fn oneof_form_body_unions_properties_and_requires_only_common_required_names() {
        let (fields, diagnostics) = planned_form_fields(
            "application/x-www-form-urlencoded",
            json!({
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" },
                            "forum": { "type": "boolean" }
                        }
                    },
                    {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" },
                            "text": { "type": "integer" }
                        }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.required))
                .collect::<Vec<_>>(),
            [("name", true), ("forum", false), ("text", false)]
        );
    }

    /// The rule that decides whether valid callers work at runtime. An instance of a `oneOf` may
    /// match one branch only, so a name the other branch requires is a name this instance will not
    /// carry — and `serializeUrlencoded` throws on a missing required field. Required has to mean
    /// "required whichever branch you sent", which is required in every branch.
    #[test]
    fn a_name_required_by_one_alternative_is_optional_on_the_merged_list() {
        let (fields, diagnostics) = planned_form_fields(
            "application/x-www-form-urlencoded",
            json!({
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["shared", "only_left"],
                        "properties": {
                            "shared": { "type": "string" },
                            "only_left": { "type": "string" }
                        }
                    },
                    {
                        "type": "object",
                        "required": ["shared"],
                        "properties": {
                            "shared": { "type": "string" },
                            "only_left": { "type": "string" }
                        }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.required))
                .collect::<Vec<_>>(),
            [("shared", true), ("only_left", false)]
        );
    }

    #[test]
    fn anyof_multipart_body_unions_properties() {
        let (fields, diagnostics) = planned_form_fields(
            "multipart/form-data",
            json!({
                "anyOf": [
                    {
                        "type": "object",
                        "required": ["shared", "first"],
                        "properties": {
                            "shared": { "type": "string" },
                            "first": { "type": "string" }
                        }
                    },
                    {
                        "type": "object",
                        "required": ["shared", "second"],
                        "properties": {
                            "shared": { "type": "string" },
                            "second": { "type": "boolean" }
                        }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.required))
                .collect::<Vec<_>>(),
            [("shared", true), ("first", false), ("second", false)]
        );
    }

    #[test]
    fn nested_allof_inside_oneof_merges_recursively() {
        let (fields, diagnostics) = planned_form_fields(
            "application/x-www-form-urlencoded",
            json!({
                "oneOf": [
                    {
                        "allOf": [
                            {
                                "type": "object",
                                "required": ["common"],
                                "properties": { "common": { "type": "string" } }
                            },
                            {
                                "type": "object",
                                "properties": { "left": { "type": "boolean" } }
                            }
                        ]
                    },
                    {
                        "type": "object",
                        "required": ["common"],
                        "properties": {
                            "common": { "type": "string" },
                            "right": { "type": "integer" }
                        }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.required))
                .collect::<Vec<_>>(),
            [("common", true), ("left", false), ("right", false)]
        );
    }

    #[test]
    fn alternative_property_required_in_only_one_branch_is_optional() {
        let (fields, diagnostics) = planned_form_fields(
            "application/x-www-form-urlencoded",
            json!({
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["shared"],
                        "properties": { "shared": { "type": "string" } }
                    },
                    {
                        "type": "object",
                        "properties": { "shared": { "type": "string" } }
                    }
                ]
            }),
        );

        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert_eq!(fields.len(), 1);
        assert!(!fields[0].required);
    }

    #[test]
    fn scalar_form_body_reports_oasts1421_at_the_media_entry() {
        let document = form_document(
            "application/x-www-form-urlencoded",
            json!({ "type": "string" }),
        );
        let diagnostics = client_diagnostics(&document);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_FORM_SCHEMA_PROPERTIES)
            .expect("OASTS5106 diagnostic");

        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(
            diagnostic
                .message
                .contains("application/x-www-form-urlencoded")
        );
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1forms/post/requestBody/content/application~1x-www-form-urlencoded")
        );
    }

    #[test]
    fn anyof_form_property_with_different_enums_merges_as_anyof() {
        let document = form_document(
            "application/x-www-form-urlencoded",
            json!({
                "anyOf": [
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [4] } }
                    },
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [5] } }
                    }
                ]
            }),
        );
        let (_temp, analyzed, _config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let media = &analyzed.ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0];
        let projector = PrimitiveDomainProjector::new(&analyzed.ir);
        let properties = collect_form_properties(&media.schema, &projector)
            .expect("composed form properties")
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(properties.len(), 1);
        let schema = properties[0].schema.as_ref();
        assert!(matches!(
            schema,
            SchemaNode::AnyOf {
                branches,
                discriminator,
                meta,
            } if branches.len() == 2
                && discriminator.is_none()
                && meta == &SchemaMeta::default()
                && matches!(
                branches.as_slice(),
                [
                    SchemaNode::Primitive {
                        enum_values: Some(first),
                        ..
                    },
                    SchemaNode::Primitive {
                        enum_values: Some(second),
                        ..
                    }
                ] if first == &[json!(4)] && second == &[json!(5)]
            )
        ));
    }

    #[test]
    fn allof_form_property_with_different_constraints_merges_as_allof() {
        let document = form_document(
            "application/x-www-form-urlencoded",
            json!({
                "allOf": [
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "minimum": 1 } }
                    },
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "minimum": 2 } }
                    }
                ]
            }),
        );
        let (_temp, analyzed, _config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let media = &analyzed.ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0];
        let projector = PrimitiveDomainProjector::new(&analyzed.ir);
        let mut properties = collect_form_properties(&media.schema, &projector)
            .expect("composed form properties")
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(properties.len(), 1);
        let schema = properties[0].schema.as_ref();
        assert!(matches!(
            schema,
            SchemaNode::AllOf { branches, meta }
                if branches.len() == 2 && meta == &SchemaMeta::default()
        ));

        merge_form_property_schema(
            &mut properties[0].schema,
            Cow::Owned(SchemaNode::Primitive {
                ty: PrimitiveType::Boolean,
                format: None,
                enum_values: None,
                const_value: None,
                meta: SchemaMeta::default(),
            }),
            FormPropertyMerge::AllOf,
        );
        assert!(matches!(
            properties[0].schema.as_ref(),
            SchemaNode::AllOf { branches, .. } if branches.len() == 3
        ));
    }

    #[test]
    fn three_disagreeing_form_property_alternatives_make_one_flat_anyof() {
        let document = form_document(
            "application/x-www-form-urlencoded",
            json!({
                "anyOf": [
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [1] } }
                    },
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [2] } }
                    },
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [3] } }
                    }
                ]
            }),
        );
        let (_temp, analyzed, _config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let media = &analyzed.ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0];
        let projector = PrimitiveDomainProjector::new(&analyzed.ir);
        let properties = collect_form_properties(&media.schema, &projector)
            .expect("composed form properties")
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(properties.len(), 1);
        assert!(matches!(
            properties[0].schema.as_ref(),
            SchemaNode::AnyOf { branches, .. } if branches.len() == 3
        ));
    }

    #[test]
    fn structurally_equal_form_property_duplicates_stay_borrowed_and_unwrapped() {
        let document = form_document(
            "application/x-www-form-urlencoded",
            json!({
                "anyOf": [
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [4] } }
                    },
                    {
                        "type": "object",
                        "properties": { "value": { "type": "integer", "enum": [4] } }
                    }
                ]
            }),
        );
        let (_temp, analyzed, _config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let media = &analyzed.ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0];
        let projector = PrimitiveDomainProjector::new(&analyzed.ir);
        let properties = collect_form_properties(&media.schema, &projector)
            .expect("composed form properties")
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(properties.len(), 1);
        assert!(matches!(properties[0].schema, Cow::Borrowed(_)));
        assert!(matches!(
            properties[0].schema.as_ref(),
            SchemaNode::Primitive { .. }
        ));
    }

    #[test]
    fn structural_form_property_equality_ignores_every_nested_source() {
        let string_schema = |pointer: &str| SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: None,
            meta: SchemaMeta {
                source: SourceRef::new("schema.yaml", pointer),
                ..SchemaMeta::default()
            },
        };
        let applicators = ValidationApplicators {
            not: Some(Box::new(string_schema("/not"))),
            property_names: Some(Box::new(string_schema("/propertyNames"))),
            pattern_properties: vec![PatternProperty {
                pattern: "^x".to_owned(),
                schema: string_schema("/patternProperties"),
                type_key: None,
            }],
            contains: Some(Box::new(ContainsApplicator {
                schema: Box::new(string_schema("/contains")),
                min_contains: Some(1),
                max_contains: Some(2),
            })),
            dependent_schemas: vec![("flag".to_owned(), string_schema("/dependentSchemas/flag"))],
            conditional: Some(Box::new(ConditionalApplicator {
                condition: Box::new(string_schema("/if")),
                then_schema: Some(Box::new(string_schema("/then"))),
                else_schema: Some(Box::new(string_schema("/else"))),
            })),
            unevaluated_properties: Some(Box::new(string_schema("/unevaluatedProperties"))),
            unevaluated_items: Some(Box::new(string_schema("/unevaluatedItems"))),
        };
        let mut left = SchemaNode::AllOf {
            branches: vec![
                SchemaNode::Ref {
                    target: SchemaRef {
                        source_id: "schema.yaml".to_owned(),
                        json_pointer: "/component".to_owned(),
                    },
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/ref"),
                        ..SchemaMeta::default()
                    },
                },
                string_schema("/primitive"),
                SchemaNode::Finite {
                    enum_values: Some(vec![json!("value")]),
                    const_value: None,
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/finite"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Object {
                    properties: vec![(
                        "field".to_owned(),
                        string_schema("/object/properties/field"),
                        PropMeta {
                            required: true,
                            read_only: false,
                            write_only: false,
                        },
                    )],
                    additional_properties: AdditionalProperties::Schema(Box::new(string_schema(
                        "/object/additionalProperties",
                    ))),
                    dependent_required: Vec::new(),
                    finite: None,
                    extra_required: Vec::new(),
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/object"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Object {
                    properties: Vec::new(),
                    additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                        string_schema("/openObject/additionalProperties"),
                    ))),
                    dependent_required: Vec::new(),
                    finite: None,
                    extra_required: Vec::new(),
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/openObject"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Array {
                    items: Box::new(string_schema("/array/items")),
                    finite: None,
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/array"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Tuple {
                    prefix_items: vec![string_schema("/tuple/prefixItems/0")],
                    rest: TupleRest::Schema(Box::new(string_schema("/tuple/items"))),
                    finite: None,
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/tuple"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::AllOf {
                    branches: vec![string_schema("/allOf/0")],
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/allOf"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::OneOf {
                    branches: vec![string_schema("/oneOf/0")],
                    discriminator: Some(Box::new(Discriminator {
                        property_name: "kind".to_owned(),
                        mapping: Vec::new(),
                        source: SourceRef::new("schema.yaml", "/oneOf/discriminator"),
                    })),
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/oneOf"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::AnyOf {
                    branches: vec![string_schema("/anyOf/0")],
                    discriminator: Some(Box::new(Discriminator {
                        property_name: "kind".to_owned(),
                        mapping: Vec::new(),
                        source: SourceRef::new("schema.yaml", "/anyOf/discriminator"),
                    })),
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/anyOf"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Any {
                    meta: SchemaMeta {
                        validation_applicators: Some(Box::default()),
                        source: SourceRef::new("schema.yaml", "/any"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Never {
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/never"),
                        ..SchemaMeta::default()
                    },
                },
                SchemaNode::Unknown {
                    reason: "test".to_owned(),
                    meta: SchemaMeta {
                        source: SourceRef::new("schema.yaml", "/unknown"),
                        ..SchemaMeta::default()
                    },
                },
            ],
            meta: SchemaMeta {
                validation_applicators: Some(Box::new(applicators)),
                source: SourceRef::new("schema.yaml", "/root"),
                ..SchemaMeta::default()
            },
        };
        let mut right = left.clone();
        clear_schema_provenance(&mut right);

        assert!(schemas_structurally_equal(&left, &right));
        clear_schema_provenance(&mut left);
        assert_eq!(left, right);
    }

    #[test]
    fn form_property_ref_collection_cycle_and_missing_edges_are_total() {
        let missing = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "missing.yaml".to_owned(),
                json_pointer: "/schema".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let empty_ir = Ir::default();
        let empty_projector = PrimitiveDomainProjector::new(&empty_ir);
        assert!(
            collect_form_properties_inner(&missing, &empty_projector, &mut HashSet::new())
                .expect("missing refs are total")
                .into_iter()
                .next()
                .is_none()
        );

        let mut invalid_indices = HashMap::new();
        invalid_indices.insert(("missing.yaml", "/schema"), 0);
        let invalid_projector = PrimitiveDomainProjector {
            schemas: &[],
            indices: invalid_indices,
            domains: Vec::new(),
        };
        assert!(
            collect_form_properties_inner(&missing, &invalid_projector, &mut HashSet::new())
                .expect("an absent indexed schema is total")
                .into_iter()
                .next()
                .is_none()
        );

        let source = SourceRef::new("cycle.yaml", "/components/schemas/Cycle");
        let cycle_ir = Ir {
            schemas: vec![NamedSchema {
                name: "Cycle".to_owned(),
                schema: SchemaNode::Ref {
                    target: SchemaRef {
                        source_id: source.source_id.clone(),
                        json_pointer: source.json_pointer.clone(),
                    },
                    meta: SchemaMeta::default(),
                },
                source,
            }],
            ..Ir::default()
        };
        let cycle_projector = PrimitiveDomainProjector::new(&cycle_ir);
        let mut visiting = HashSet::new();
        visiting.insert(0);
        assert!(
            collect_form_properties_inner(
                &cycle_ir.schemas[0].schema,
                &cycle_projector,
                &mut visiting,
            )
            .expect("cycles are total")
            .into_iter()
            .next()
            .is_none()
        );

        let unknown = SchemaNode::Unknown {
            reason: "test".to_owned(),
            meta: SchemaMeta::default(),
        };
        assert!(
            collect_form_properties_inner(&unknown, &empty_projector, &mut HashSet::new())
                .expect("unknown schemas are total")
                .into_iter()
                .next()
                .is_none()
        );
    }

    #[test]
    #[should_panic(expected = "expected form body plan")]
    fn planned_form_fields_rejects_a_non_form_plan() {
        let _ = planned_form_fields("application/json", json!({ "type": "object" }));
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
                .map(|arm| arm.media.as_str())
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

    /// `emit::response_media_names` aliases colliding media tags positionally, and validators and
    /// zod feed it `ResponseEntry::media_types` while the client feeds it `ResponsePlan::media`.
    /// The two must stay in the same order or a collision would name the declaration after one
    /// schema and the call after another. Request arms are sorted by media type; responses must
    /// not be.
    #[test]
    fn response_media_plans_preserve_the_declared_media_order() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/report": {
                    "get": {
                        "operationId": "report",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/vnd.zeta+json": { "schema": { "type": "object" } },
                                    "application/vnd.alpha+json": { "schema": { "type": "string" } }
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
        let declared = analyzed.ir.operations[0].responses[0]
            .media_types
            .iter()
            .map(|media| media.full.as_str())
            .collect::<Vec<_>>();
        let planned = model.operations[0].response_table[0]
            .media
            .iter()
            .map(|media| media.media.as_str())
            .collect::<Vec<_>>();
        assert_eq!(declared, planned);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn schemaless_response_media_plan_carries_the_ir_node() {
        // A `content` entry with no `schema` keyword still carries the IR's unconstrained node, so
        // the client renders the same payload type the types artifact renders for that entry. An
        // `Option` here would erase the node and let the two artifacts disagree.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/report": {
                    "get": {
                        "operationId": "report",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "text/csv": {} }
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
        let ir_media = &analyzed.ir.operations[0].responses[0].media_types[0];
        assert!(!ir_media.schema_present);
        assert_eq!(response.media[0].schema, ir_media.schema);
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
                .map(|arm| arm.media.as_str())
                .collect::<Vec<_>>(),
            ["application/json;v=1", "application/json;v=2"]
        );
        assert!(all_concrete);
        // Essence-based classification: a parameterized JSON key still serializes as JSON.
        assert!(
            arms.iter()
                .all(|arm| matches!(arm.plan, BodyPlan::Json { .. }))
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
                                            "styled": { "type": "string" },
                                            "binary": { "type": "string", "format": "binary" },
                                            "binaryAllOf": { "allOf": [{ "type": "string", "format": "binary" }] }
                                        }
                                    },
                                    "encoding": {
                                        "styled": { "style": "form" },
                                        "binary": { "contentType": "application/octet-stream" },
                                        "binaryAllOf": { "contentType": "application/octet-stream" }
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
                ("application/octet-stream", true, PayloadKind::Binary),
                ("application/octet-stream", true, PayloadKind::Binary),
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
    fn client_model_helper_edges_are_total() {
        let empty_ir = Ir::default();
        let projector = PrimitiveDomainProjector::new(&empty_ir);
        assert!(build_body_plan(&[], &projector).is_none());
        let any_media = classifier_media("multipart/form-data", false);
        assert!(form_fields(&any_media, true, &projector).is_empty());
        let mut diagnostic_sink = DiagnosticSink::new();
        diagnose_form_media(
            &any_media,
            &projector,
            DeepObjectEncoding::Strict,
            &mut diagnostic_sink,
        );
        assert_eq!(diagnostic_sink.as_slice().len(), 1);
        // `classifier_media` carries no schema, which is a valid Media Type Object — so this is the
        // unconstrained warning, not the refusal a schema contradicting the encoding would earn.
        assert_eq!(
            diagnostic_sink.as_slice()[0].code,
            CODE_FORM_SCHEMA_UNCONSTRAINED
        );
        assert_eq!(diagnostic_sink.as_slice()[0].severity, Severity::Warning);
        assert!(!invalid_style_combination(
            ParamLocation::Cookie,
            ParamStyle::Form,
            false,
            Projection::Known(Domain::STRING),
            DeepObjectEncoding::Strict,
        ));
        assert!(invalid_style_combination(
            ParamLocation::Cookie,
            ParamStyle::Simple,
            false,
            Projection::Known(Domain::STRING),
            DeepObjectEncoding::Strict,
        ));
        assert!(!invalid_style_combination(
            ParamLocation::Query,
            ParamStyle::DeepObject,
            true,
            Projection::Unsupported,
            DeepObjectEncoding::Strict,
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
        let diagnostic = source_diagnostic("OASTS5004", "located", &located, Severity::Error);
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
            tags: Vec::new(),
            path: None,
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
                .filter(|diagnostic| diagnostic.code == "OASTS5401")
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
                        DeepObjectEncoding::Strict,
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
        let ir = Ir::default();
        let projector = PrimitiveDomainProjector::new(&ir);
        for (media, marked, expected) in [
            ("text/event-stream", false, DecoderClass::StreamingSse),
            ("text/event-stream", true, DecoderClass::StreamingSse),
            ("application/stream+json", true, DecoderClass::StreamingRaw),
            // The mark makes an eligible media type an opaque byte stream, whatever the buffered
            // classifier would have made of it.
            ("text/plain", true, DecoderClass::StreamingRaw),
            ("application/octet-stream", true, DecoderClass::StreamingRaw),
            ("application/json", true, DecoderClass::StreamingRaw),
            // A media class the buffered classifier refuses keeps its own refusal: the mark is not
            // a way to launder an undecodable entry into a byte stream that generates cleanly.
            ("multipart/mixed", true, DecoderClass::MultipartUnnamed),
            ("application/json", false, DecoderClass::Json),
            // Unregistered, so it decodes as the `text/*` it says it is rather than as the JSON it
            // probably means.
            ("text/json", false, DecoderClass::Text),
            ("application/vnd.api+json", false, DecoderClass::Json),
            ("application/xml", false, DecoderClass::Binary),
            ("text/xml", false, DecoderClass::Binary),
            ("application/atom+xml", false, DecoderClass::Binary),
            ("multipart/form-data", false, DecoderClass::Multipart),
            ("multipart/mixed", false, DecoderClass::MultipartUnnamed),
            ("multipart/*", false, DecoderClass::MultipartUnnamed),
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
                classify_response_media(&classifier_media(media, marked), &projector),
                expected,
                "{media}"
            );
        }

        let mut unsupported_xml = classifier_media("text/xml", false);
        unsupported_xml.schema_present = true;
        unsupported_xml.schema = SchemaNode::Unknown {
            reason: "test".to_owned(),
            meta: test_meta("/unsupported-xml"),
        };
        assert_eq!(
            classify_response_media(&unsupported_xml, &projector),
            DecoderClass::Binary
        );

        // Structural XML is refused, and the mark does not change that.
        let mut structural_xml = classifier_media("application/xml", true);
        structural_xml.schema_present = true;
        structural_xml.schema = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(None),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: test_meta("/structural-xml"),
        };
        assert_eq!(
            classify_response_media(&structural_xml, &projector),
            DecoderClass::Xml
        );
    }

    #[test]
    fn a_streaming_request_body_is_carried_as_a_stream_with_no_diagnostic() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://stream.example.test" }],
            "paths": {
                "/publish": {
                    "post": {
                        "operationId": "publish",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "text/event-stream": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": { "204": { "description": "accepted" } }
                    }
                },
                "/upload": {
                    "post": {
                        "operationId": "upload",
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
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "server", "index": 0 }
            }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);

        assert!(sink.into_sorted_vec().is_empty());
        for operation in &model.operations {
            assert!(
                matches!(operation.body_plan, Some(BodyPlan::TopLevelStream { .. })),
                "{:?}",
                operation.body_plan
            );
        }
    }

    #[test]
    fn a_raw_stream_is_unchecked_data_whatever_the_validation_setting() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://stream.example.test" }],
            "paths": {
                "/blob": {
                    "get": {
                        "operationId": "downloadBlob",
                        "responses": {
                            "200": {
                                "description": "raw bytes",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            },
                            "503": {
                                "description": "an error branch streams too, and is not data",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            }
                        }
                    }
                },
                "/events": {
                    "get": {
                        "operationId": "watchEvents",
                        "responses": {
                            "200": {
                                "description": "checked per event, so never unchecked data",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "object" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        // Response validation is ON in every case: this half of the policy is the one the config
        // layer cannot answer, so being on must not silence it.
        // The SSE branch contributes nothing here: its events are validated one at a time when
        // response validation is on, so it is not unchecked data under any policy.
        for (policy, expected) in [
            ("error", vec!["OASTS5205"]),
            ("warn", vec!["OASTS5206"]),
            ("allow", Vec::new()),
        ] {
            let (_temp, analyzed, config) = analyzed_with_validation(
                &document,
                json!({
                    "authEnforcement": "types",
                    "baseUrl": { "source": "server", "index": 0 }
                }),
                json!({
                    "engine": "generated",
                    "request": true,
                    "response": true,
                    "unchecked": policy
                }),
            );
            let mut sink = DiagnosticSink::new();
            let _ = build_client_model(&analyzed, &config, &mut sink);
            let codes = sink
                .into_sorted_vec()
                .into_iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>();
            assert_eq!(codes, expected, "unchecked: {policy}");
        }
    }

    #[test]
    fn a_range_or_default_key_can_be_selected_on_a_2xx_so_its_raw_stream_is_unchecked_data() {
        // The policy only speaks about data the caller receives on success. A `2XX` key and a
        // `default` key can both be the branch a 2xx response selects, so a raw stream under either
        // is unchecked success data; a `4XX` key never can, so its stream is an error payload the
        // policy has nothing to say about.
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://stream.example.test" }],
            "paths": {
                "/ranged": {
                    "get": {
                        "operationId": "watchRanged",
                        "responses": {
                            "2XX": {
                                "description": "any success streams",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            },
                            "4XX": {
                                "description": "a client error streams too, and is not data",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            },
                            "default": {
                                "description": "anything else streams too",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed_with_validation(
            &document,
            json!({
                "authEnforcement": "types",
                "baseUrl": { "source": "server", "index": 0 }
            }),
            json!({
                "engine": "generated",
                "request": true,
                "response": true,
                "unchecked": "warn"
            }),
        );
        let mut sink = DiagnosticSink::new();
        let _ = build_client_model(&analyzed, &config, &mut sink);
        let reported = sink
            .into_sorted_vec()
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>();

        assert_eq!(
            reported
                .iter()
                .map(|(code, _)| *code)
                .collect::<Vec<&str>>(),
            ["OASTS5206", "OASTS5206"],
            "{reported:?}"
        );
        assert!(
            reported
                .iter()
                .any(|(_, message)| message.contains("response key '2XX'")),
            "{reported:?}"
        );
        assert!(
            reported
                .iter()
                .any(|(_, message)| message.contains("response key 'default'")),
            "{reported:?}"
        );
    }

    #[test]
    fn a_streaming_mark_reaches_every_media_class_the_classifier_does_not_refuse() {
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
        let codes = client_diagnostics(&document)
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>();

        // Nothing is refused: the marked `+json` response streams, and the marked `+xml` one has a
        // schema needing no structural mapping, so it is opaque bytes the mark can legitimately
        // claim rather than a class the XML rule owns.
        assert!(codes.is_empty(), "{codes:?}");
    }

    #[test]
    fn text_xml_requests_are_text_while_xml_responses_stay_binary() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/opaque": {
                    "post": {
                        "operationId": "opaqueXml",
                        "requestBody": {
                            "content": {
                                "application/xml": {},
                                "text/xml": {},
                                "image/svg+xml": {}
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "opaque",
                                "content": {
                                    "application/xml": {},
                                    "text/xml": {},
                                    "image/svg+xml": {}
                                }
                            }
                        }
                    }
                },
                "/string": {
                    "post": {
                        "operationId": "stringXml",
                        "requestBody": {
                            "content": {
                                "text/xml": { "schema": { "type": ["string", "null"] } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "opaque string",
                                "content": {
                                    "text/xml": { "schema": { "type": "string", "format": "binary" } }
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

        assert!(sink.as_slice().is_empty());
        let opaque = model
            .operations
            .iter()
            .find(|plan| {
                analyzed
                    .ir
                    .operations
                    .get(plan.operation_index)
                    .and_then(|operation| operation.operation_id.as_deref())
                    == Some("opaqueXml")
            })
            .expect("opaque operation");
        let (arms, _) = opaque
            .body_plan
            .as_ref()
            .and_then(BodyPlan::discriminated_arms)
            .expect("discriminated opaque body");
        assert!(arms.iter().any(|arm| {
            arm.media == "text/xml" && matches!(arm.plan, BodyPlan::TopLevelText { .. })
        }));
        assert!(arms.iter().all(|arm| {
            arm.media == "text/xml" || matches!(arm.plan, BodyPlan::TopLevelBinary { .. })
        }));
        assert!(
            opaque.response_table[0]
                .media
                .iter()
                .all(|media| media.decoder == DecoderClass::Binary)
        );

        let string = model
            .operations
            .iter()
            .find(|plan| {
                analyzed
                    .ir
                    .operations
                    .get(plan.operation_index)
                    .and_then(|operation| operation.operation_id.as_deref())
                    == Some("stringXml")
            })
            .expect("string operation");
        let expected_text_variant = BodyPlan::TopLevelText {
            media: String::new(),
            schema: None,
            source: test_meta("/expected-binary").source,
        };
        assert_eq!(
            std::mem::discriminant(string.body_plan.as_ref().expect("string request body")),
            std::mem::discriminant(&expected_text_variant)
        );
        assert_eq!(
            string.response_table[0].media[0].decoder,
            DecoderClass::Binary
        );
    }

    #[test]
    fn oasts1403_rejects_structural_xml_requests_and_responses() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/xml": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "text/xml": { "schema": { "type": "object" } },
                                "application/json": { "schema": { "type": "object" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "xml",
                                "content": {
                                    "application/atom+xml": { "schema": { "type": "object" } }
                                }
                            },
                            "201": {
                                "description": "json sibling",
                                "content": {
                                    "application/json": { "schema": { "type": "object" } }
                                }
                            },
                            "202": {
                                "description": "text xml",
                                "content": {
                                    "text/xml": { "schema": { "type": "object" } }
                                }
                            },
                            "203": {
                                "description": "mixed xml",
                                "content": {
                                    "text/xml": { "schema": { "anyOf": [{ "type": "string" }, { "type": "object" }] } }
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
                .filter(|diagnostic| diagnostic.code == "OASTS5201")
                .count(),
            4
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
                            },
                            "202": {
                                "description": "decodable form-data sibling",
                                "content": {
                                    "multipart/form-data": { "schema": { "type": "object" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let diagnostics = client_diagnostics(&document);

        // Only the subtype with no part-naming convention is rejected: `multipart/form-data` names
        // its parts, so it decodes, and the multipart *request* body was never in question.
        let rejected = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS5202")
            .collect::<Vec<_>>();
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].message.contains("multipart/mixed"));
    }

    /// `text/json` is text in both directions. It used to be text on the way out and JSON on the
    /// way back, which made one media type in one document mean two things; unregistering it here
    /// is what closed that. A document that carries JSON says `application/json`.
    #[test]
    fn text_json_is_text_in_both_directions() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/json": {
                    "post": {
                        "operationId": "textJson",
                        "requestBody": {
                            "content": {
                                "text/json": {
                                    "schema": { "type": "string" }
                                }
                            }
                        },
                        "responses": {
                            "202": {
                                "description": "accepted",
                                "content": {
                                    "text/json": { "schema": { "type": "string" } }
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

        assert!(sink.as_slice().is_empty());
        let operation = &model.operations[0];
        assert!(matches!(
            operation.body_plan,
            Some(BodyPlan::TopLevelText { ref media, .. }) if media == "text/json"
        ));
        assert_eq!(operation.accept.as_deref(), Some("text/json"));
        assert_eq!(operation.response_table[0].media[0].media, "text/json");
        assert_eq!(
            operation.response_table[0].media[0].decoder,
            DecoderClass::Text
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
                                "text/plain": { "schema": { "type": "object" } },
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
                .filter(|diagnostic| diagnostic.code == "OASTS5203")
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
                                    "text/plain": { "schema": { "if": { "type": "integer" } } }
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
                .any(|diagnostic| diagnostic.code == "OASTS5203")
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
            .filter(|diagnostic| diagnostic.code == "OASTS5204")
            .collect::<Vec<_>>();

        assert_eq!(bodyless.len(), 4);
        assert!(
            bodyless
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
        assert!(!diagnostics.iter().any(|diagnostic| {
            matches!(diagnostic.code, "OASTS1402" | "OASTS5201" | "OASTS5202")
        }));
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
        // — the location default helper, a typed input, and no OASTS5006.
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
            .filter(|diagnostic| diagnostic.code == "OASTS5006")
            .collect();
        assert_eq!(warnings.len(), 1, "{diagnostics:#?}");
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert!(warnings[0].message.contains("application/xml"));
        assert!(warnings[0].message.contains("caller-serialized"));
    }

    #[test]
    fn text_plain_non_string_content_parameter_is_caller_serialized() {
        // The passthrough is string-only; text/plain over a non-string schema falls to OASTS5006.
        let (model, diagnostics) =
            content_param_model("query", "text/plain", json!({ "type": "object" }));
        assert!(only_param(&model).caller_serialized);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS5006")
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
                    .filter(|diagnostic| diagnostic.code == "OASTS5006")
                    .count(),
                1,
                "{location}"
            );
        }
    }

    #[test]
    fn oasts1411_drops_forbidden_parameters_and_rejects_active_header_api_keys() {
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
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let diagnostics = sink.as_slice();

        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS5001")
                .count(),
            2
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS5001"
                && diagnostic.severity == Severity::Warning
                && diagnostic.message.contains("Content-Length")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS5001"
                && diagnostic.severity == Severity::Error
                && diagnostic.message.contains("proxyKey")
        }));
        assert!(!diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS5001"
                && (diagnostic.message.contains("X-HTTP-Method")
                    || diagnostic.message.contains("inactive"))
        }));
        assert_eq!(
            model.operations[0]
                .param_plans
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<Vec<_>>(),
            ["X-HTTP-Method", "X-Safe"]
        );
    }

    #[test]
    fn fetch_header_filter_does_not_apply_to_webhooks_or_callbacks() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/subscribe": {
                    "post": {
                        "operationId": "subscribe",
                        "callbacks": {
                            "delivery": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "operationId": "deliver",
                                        "parameters": [
                                            { "name": "Cookie", "in": "header", "required": true, "schema": { "type": "string" } }
                                        ],
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "webhooks": {
                "ping": {
                    "post": {
                        "operationId": "ping",
                        "parameters": [
                            { "name": "Host", "in": "header", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        assert_eq!(
            analyzed.ir.webhooks[0].operations[0].parameters[0].name,
            "Host"
        );
        assert_eq!(
            analyzed.ir.operations[0].callbacks[0].expressions[0].operations[0].parameters[0].name,
            "Cookie"
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        assert_eq!(model.operations.len(), 1);
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
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
                .filter(|diagnostic| diagnostic.code == "OASTS5002")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5003")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5101")
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
        for code in ["OASTS5102", "OASTS5104"] {
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
            .filter(|diagnostic| diagnostic.code == "OASTS5102")
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
            .filter(|diagnostic| diagnostic.code == "OASTS5102")
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
                                                    "schema": { "if": { "const": "8bit" } }
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
                .all(|diagnostic| diagnostic.code != "OASTS5102")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5103")
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
            .filter(|diagnostic| diagnostic.code == "OASTS5104")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Severity::Warning);
        assert_eq!(
            diagnostics[0].message,
            "multipart field 'field' declares header 'X-Custom', but it is never emitted because RFC 7578 §4.8 permits only Content-Disposition, Content-Type, and Content-Transfer-Encoding part headers"
        );
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
                .filter(|diagnostic| diagnostic.code == "OASTS5105")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5107")
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
            .filter(|diagnostic| diagnostic.code == "OASTS5108")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5004")
                .count(),
            5
        );
    }

    /// The three deepObject schema shapes real documents use, in one operation.
    fn deep_object_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            { "name": "filter", "in": "query", "style": "deepObject", "schema": { "type": "object" } },
                            { "name": "tags", "in": "query", "style": "deepObject", "schema": { "type": "array", "items": { "type": "string" } } },
                            { "name": "raw", "in": "query", "style": "deepObject", "schema": {} },
                            { "name": "label", "in": "query", "style": "deepObject", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        })
    }

    fn deep_object_plan(
        document: &Value,
        deep_object: DeepObjectEncoding,
    ) -> (Vec<(String, HelperId)>, Vec<Diagnostic>) {
        let (_temp, analyzed, mut config) = analyzed(
            document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        config.compat.deep_object_encoding = deep_object;
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let helpers = model.operations[0]
            .param_plans
            .iter()
            .map(|plan| (plan.name.clone(), plan.resolved.helper))
            .collect();
        (helpers, sink.into_sorted_vec())
    }

    #[test]
    fn strict_deep_object_admits_only_object_schemas() {
        let (helpers, diagnostics) =
            deep_object_plan(&deep_object_document(), DeepObjectEncoding::Strict);
        let rejected = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS5004")
            .count();
        assert_eq!(rejected, 3, "{diagnostics:#?}");
        // Only the object-typed parameter survives the strict gate.
        assert!(
            helpers
                .iter()
                .all(|(_, helper)| *helper == HelperId::QueryDeepObject),
            "{helpers:?}"
        );
    }

    /// The strict rejection is the one a user can lift without editing the document, so it is the
    /// one that has to say so. Every other rejection must stay silent about compat — pointing a
    /// reader at a switch that would not have helped is worse than saying nothing.
    #[test]
    fn strict_deep_object_rejection_names_the_compat_setting() {
        let (_, diagnostics) =
            deep_object_plan(&deep_object_document(), DeepObjectEncoding::Strict);
        let deep_object: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS5004")
            .collect();
        assert!(
            deep_object.iter().all(|diagnostic| diagnostic
                .message
                .contains("compat.deepObjectEncoding: extended")),
            "{deep_object:#?}"
        );

        let unrelated = client_diagnostics(&json!({
            "openapi": "3.1.0",
            "paths": {
                "/styles": {
                    "get": {
                        "parameters": [
                            { "name": "querySimple", "in": "query", "style": "simple", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }));
        let illegal_style = unrelated
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS5004")
            .expect("an illegal query style is still rejected");
        assert!(
            !illegal_style.message.contains("compat"),
            "{illegal_style:#?}"
        );
    }

    #[test]
    fn extended_deep_object_admits_every_schema_shape() {
        let (helpers, diagnostics) =
            deep_object_plan(&deep_object_document(), DeepObjectEncoding::Extended);
        // Bracket-path encoding is total over shapes, so the schema's type stops rejecting anything
        // and the operation plans clean.
        assert!(diagnostics.is_empty());
        assert_eq!(
            helpers,
            vec![
                ("filter".to_owned(), HelperId::QueryDeepObject),
                ("tags".to_owned(), HelperId::QueryDeepObjectExtended),
                ("raw".to_owned(), HelperId::QueryDeepObjectExtended),
                ("label".to_owned(), HelperId::QueryDeepObjectExtended),
            ]
        );
    }

    #[test]
    fn extended_deep_object_leaves_explode_handling_alone() {
        // `explode: false` with deepObject is undefined in OpenAPI and is a different question from
        // the schema's type, so `compat` must not touch it.
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            { "name": "tags", "in": "query", "style": "deepObject", "explode": false, "schema": { "type": "array", "items": { "type": "string" } } }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        for encoding in [DeepObjectEncoding::Strict, DeepObjectEncoding::Extended] {
            let (_, diagnostics) = deep_object_plan(&document, encoding);
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == CODE_DEEP_OBJECT_FALSE_EXPLODE),
                "{encoding:?}: {diagnostics:#?}"
            );
        }
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
        assert_eq!(diagnostic.code, "OASTS5005");
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
                .expect("OASTS5109 diagnostic");
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
                "expected exactly one OASTS5112 for '{field}'"
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
    /// so this still reports OASTS5112 instead of silently falling through as unclassified.
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

    /// OASTS5112 is 3.1-only: 3.0 multipart style keywords are already warn-ignored by OASTS5111, so
    /// the same object+style shape in a 3.0 document must not additionally report OASTS5112.
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
        // OASTS5111 (the 3.0 multipart style warning) is expected on this exact shape, so the
        // diagnostics list here is never empty — the `.filter()` below always has a non-empty
        // source to iterate.
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_MULTIPART_30_STYLE_IGNORED)
            .expect("OASTS5111 diagnostic");
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
                .filter(|diagnostic| diagnostic.code == "OASTS5004")
                .count(),
            1
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS5105")
        );
    }

    #[test]
    fn oasts1420_only_rejects_an_out_of_range_server_index() {
        let document = json!({
            "openapi": "3.1.0",
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
                .filter(|diagnostic| diagnostic.code == "OASTS5301")
                .count(),
            1
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "OASTS5301"
                && diagnostic
                    .message
                    .contains("operation has no effective server at index 1")
        }));
    }

    #[test]
    fn operation_empty_servers_inherits_the_synthesized_root_server() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/status": {
                    "get": {
                        "servers": [],
                        "responses": { "204": { "description": "ok" } }
                    }
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

        assert_eq!(analyzed.ir.root_servers.len(), 1);
        assert_eq!(analyzed.ir.root_servers[0].url, "/");
        assert!(analyzed.ir.operations[0].servers.is_empty());

        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);

        assert!(matches!(
            &model.operations[0].base_url,
            BaseUrlPlan::Server { index: 0, servers }
                if servers.len() == 1
                    && servers[0].url == "/"
                    && servers[0].variables.is_empty()
        ));
        assert!(model.base_url_required);
        assert!(sink.as_slice().is_empty());
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
    fn oauth2_empty_flows_warn_and_remain_a_token_auth_alternative() {
        let document = json!({
            "openapi": "3.1.1",
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2", "flows": {} }
            }},
            "security": [{ "oauth": [] }],
            "paths": {
                "/secured": {
                    "get": { "responses": { "204": { "description": "ok" } } }
                }
            }
        });
        let (_temp, analyzed, config) = analyzed(
            &document,
            json!({ "authEnforcement": "types", "baseUrl": { "source": "runtime" } }),
        );
        let mut sink = DiagnosticSink::new();
        let model = build_client_model(&analyzed, &config, &mut sink);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OAUTH2_EMPTY_FLOWS)
            .expect("empty OAuth2 flows diagnostic");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth")
        );
        assert_eq!(diagnostic.message, "oauth2 scheme declares no flows");
        assert!(!sink.has_errors());
        assert!(matches!(
            model.operations[0].auth_plan.as_slice(),
            [alternative]
                if matches!(
                    alternative.as_slice(),
                    [AuthSchemeUse { name, kind: AuthKind::OAuth2, scopes }]
                        if name == "oauth" && scopes.is_empty()
                )
        ));
        assert_eq!(model.operations[0].credential_headers, ["authorization"]);
    }

    #[test]
    fn oauth2_missing_flows_still_errors_1435() {
        let document = json!({
            "openapi": "3.1.1",
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2" }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OAUTH2_EMPTY_FLOWS)
            .expect("missing OAuth2 flows diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth")
        );
        assert_eq!(diagnostic.message, "oauth2 scheme requires flows");
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
    fn relative_oauth_flow_urls_are_valid_uri_references() {
        for version in ["3.0.4", "3.1.1"] {
            let document = json!({
                "openapi": version,
                "components": { "securitySchemes": {
                    "oauth": {
                        "type": "oauth2",
                        "flows": { "authorizationCode": {
                            "authorizationUrl": "/oauth/authorize",
                            "tokenUrl": "oauth/token?next=%2F",
                            "refreshUrl": "urn:example:refresh",
                            "scopes": {}
                        }}
                    }
                }}
            });
            let diagnostics = client_diagnostics(&document);
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn malformed_oauth_flow_url_errors_1437() {
        let document = json!({
            "openapi": "3.1.1",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": { "authorizationCode": {
                        "authorizationUrl": "%",
                        "tokenUrl": "/oauth/token",
                        "scopes": {}
                    }}
                }
            }}
        });
        let diagnostics = client_diagnostics(&document);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OAUTH2_FLOW_URL)
            .expect("malformed OAuth2 flow URL diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth/flows/authorizationCode")
        );
        assert_eq!(
            diagnostic.message,
            "authorizationCode authorizationUrl '%' is not an RFC 3986 URI-reference"
        );
    }

    #[test]
    fn relative_openidconnect_url_is_a_valid_uri_reference() {
        for version in ["3.0.4", "3.1.1"] {
            let document = json!({
                "openapi": version,
                "components": { "securitySchemes": {
                    "oidc": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "/.well-known/openid-configuration"
                    }
                }}
            });
            let diagnostics = client_diagnostics(&document);
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn openidconnect_url_missing_or_malformed_errors_1439() {
        let document = json!({
            "openapi": "3.1.1",
            "components": { "securitySchemes": {
                "missing": { "type": "openIdConnect" },
                "malformed": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "%"
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
        let malformed = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.message == "openIdConnectUrl '%' is not an RFC 3986 URI-reference"
            })
            .expect("malformed OpenID Connect URL diagnostic");
        assert_eq!(malformed.code, CODE_OPENID_CONNECT_URL);
        assert_eq!(malformed.severity, Severity::Error);
        assert_eq!(
            malformed.json_pointer.as_deref(),
            Some("/components/securitySchemes/malformed")
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
                .filter(|diagnostic| diagnostic.code == "OASTS5401")
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
            .filter(|diagnostic| diagnostic.code == "OASTS5402")
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
    fn oauth2_requirement_scope_outside_declared_map_warns_1440() {
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
        assert_eq!(hits[0].severity, Severity::Warning);
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
    fn oauth2_scheme_use_preserves_undeclared_scope() {
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
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OAUTH2_REQUIREMENT_SCOPE)
            .expect("undeclared scope warning");
        assert_eq!(diagnostic.severity, Severity::Warning);
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
        // so the 3.0-only non-oauth-scopes gate (OASTS5409) still fires; the same document as 3.1 is
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
