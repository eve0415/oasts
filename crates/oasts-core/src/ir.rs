//! Version-neutral intermediate representation for OpenAPI input.

use serde_json::{Number, Value};

/// Stable source identity attached to parsed nodes.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SourceRef {
    pub source_id: String,
    pub json_pointer: String,
    pub line: Option<u32>,
    pub col: Option<u32>,
}

impl SourceRef {
    #[must_use]
    pub fn new(source_id: impl Into<String>, json_pointer: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            json_pointer: json_pointer.into(),
            line: None,
            col: None,
        }
    }

    #[must_use]
    pub fn display(&self) -> String {
        format!("{}#{}", self.source_id, self.json_pointer)
    }
}

/// A complete, version-neutral OpenAPI model for the types-only wedge.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ir {
    pub operations: Vec<Operation>,
    /// Entry-document `components.schemas`, in source insertion order.
    pub schemas: Vec<NamedSchema>,
    /// Entry-document server defaults, in source insertion order.
    pub root_servers: Vec<ServerEntry>,
    /// Entry-document security alternatives; an empty requirement is anonymous access.
    pub root_security: Vec<SecurityRequirement>,
    /// Entry-document named security schemes, in source insertion order.
    pub security_schemes: Vec<NamedSecurityScheme>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OasVersion {
    V3_0,
    V3_1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSchema {
    pub name: String,
    pub schema: SchemaNode,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    pub method: String,
    pub path_template: Vec<Segment>,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub deprecated: bool,
    pub external_docs: Option<(String, Option<String>)>,
    pub parameters: Vec<Param>,
    pub request_body: Option<Body>,
    pub responses: Vec<ResponseEntry>,
    /// Operation-then-path-item effective servers; an empty array defers root fallback.
    pub servers: Vec<ServerEntry>,
    /// Operation-level security override; `None` preserves the document default.
    pub security: Option<Vec<SecurityRequirement>>,
    pub source: SourceRef,
}

/// One slash-delimited path segment, retaining mixed literal/parameter order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Segment {
    pub parts: Vec<SegmentPart>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentPart {
    Literal(String),
    Param(String),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
    Cookie,
}

/// Raw OpenAPI parameter serialization style.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamStyle {
    Form,
    Simple,
    Label,
    Matrix,
    SpaceDelimited,
    PipeDelimited,
    DeepObject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Param {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub deprecated: bool,
    pub description: Option<String>,
    pub schema: SchemaNode,
    /// Explicit serialization style; location-dependent defaults remain unresolved.
    pub style: Option<ParamStyle>,
    /// Explicit explode value; style-dependent defaults remain unresolved.
    pub explode: Option<bool>,
    /// Explicit `allowReserved`, defaulting to false when absent.
    pub allow_reserved: bool,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Body {
    pub required: bool,
    pub description: Option<String>,
    pub media_types: Vec<MediaType>,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaType {
    /// Canonical parameter-free media type or range.
    pub name: String,
    /// Content-map key exactly as written in the source document.
    pub raw_name: String,
    pub schema: SchemaNode,
    /// Whether the Media Type Object declared a schema rather than leaving it unconstrained.
    pub schema_present: bool,
    /// Media-type examples paired with a stable source label.
    pub examples: Vec<(String, Value)>,
    /// Applicable request-body Encoding Objects, in source insertion order.
    pub encodings: Vec<(String, EncodingObject)>,
    /// Whether the Media Type Object explicitly opts into streaming semantics.
    pub streaming_marked: bool,
    /// Source document line, retained for version-indexed Encoding Object rules.
    pub oas_version: OasVersion,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingObject {
    /// Comma-separated `contentType` alternatives, or `None` when absent.
    pub content_type: Option<Vec<String>>,
    /// Named per-part headers, in source insertion order.
    pub headers: Vec<(String, EncodingHeader)>,
    /// Explicit serialization style; media/version defaults remain unresolved.
    pub style: Option<ParamStyle>,
    /// Explicit explode value; style-dependent defaults remain unresolved.
    pub explode: Option<bool>,
    /// Explicit `allowReserved`, defaulting to false when absent.
    pub allow_reserved: bool,
    /// Whether a boolean `allowReserved` was explicitly declared, including `false`.
    pub allow_reserved_explicit: bool,
    /// Source identity of this Encoding Object.
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingHeader {
    /// Whether callers must supply this header.
    pub required: bool,
    /// Header value schema.
    pub schema: SchemaNode,
    /// Source identity of this Header Object.
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerEntry {
    /// Server URL template exactly as declared.
    pub url: String,
    /// Server template variables, in source insertion order.
    pub variables: Vec<(String, ServerVariable)>,
    /// Source identity of this Server Object.
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerVariable {
    /// Required default substitution value.
    pub default: String,
    /// Optional allowed substitutions, in source insertion order.
    pub enum_values: Vec<String>,
}

/// One security alternative, preserving scheme and scope insertion order.
pub type SecurityRequirement = Vec<(String, Vec<String>)>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSecurityScheme {
    /// Component-map key exactly as declared.
    pub name: String,
    /// Supported security scheme classification.
    pub kind: SecKind,
    /// Source identity of this Security Scheme Object.
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecKind {
    /// HTTP authentication using the declared scheme token.
    Http { scheme: String },
    /// API key serialized at the declared parameter location and name.
    ApiKey {
        location: ParamLocation,
        name: String,
    },
    /// OAuth 2.0 flows; detailed flow parsing is deferred.
    OAuth2,
    /// OpenID Connect discovery; URL parsing is deferred.
    OpenIdConnect,
    /// Mutual TLS authentication.
    MutualTls,
    /// Unknown or unsupported security scheme shape.
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseEntry {
    pub status: ResponseStatus,
    pub description: String,
    pub media_types: Vec<MediaType>,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseStatus {
    Exact(String),
    Range(String),
    Default,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimitiveType {
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaDocs {
    pub title: Option<String>,
    pub description: Option<String>,
    pub deprecated: bool,
    pub default: Option<Value>,
    pub examples: Vec<Value>,
    pub comment: Option<String>,
    pub constraints: Vec<String>,
}

/// Raw recognized enum extensions. Semantic analysis owns their validation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnumExtensionData {
    pub enum_varnames: Option<Value>,
    pub enum_names: Option<Value>,
    pub enum_descriptions: Option<Value>,
    pub enum_descriptions_camel: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExclusiveBound {
    Boolean(bool),
    Number(Number),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NumericConstraints {
    pub minimum: Option<Number>,
    pub maximum: Option<Number>,
    pub exclusive_minimum: Option<ExclusiveBound>,
    pub exclusive_maximum: Option<ExclusiveBound>,
    pub multiple_of: Option<Number>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StringConstraints {
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub pattern: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArrayConstraints {
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    pub unique_items: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectConstraints {
    pub min_properties: Option<u64>,
    pub max_properties: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaMeta {
    pub nullable: bool,
    /// OpenAPI 3.1 `contentEncoding`, retained for multipart composition.
    pub content_encoding: Option<String>,
    pub docs: SchemaDocs,
    pub enum_extensions: EnumExtensionData,
    pub numeric_constraints: NumericConstraints,
    pub string_constraints: StringConstraints,
    pub array_constraints: ArrayConstraints,
    pub object_constraints: ObjectConstraints,
    pub rejected_validation_keywords: Vec<String>,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropMeta {
    pub required: bool,
    pub read_only: bool,
    pub write_only: bool,
    pub deprecated: bool,
    pub description: Option<String>,
    pub default: Option<Value>,
    pub examples: Vec<Value>,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdditionalProperties {
    /// `additionalProperties: true`, including the omitted default.
    Allowed(Option<Box<SchemaNode>>),
    Forbidden,
    Schema(Box<SchemaNode>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TupleRest {
    Allowed,
    Forbidden,
    Schema(Box<SchemaNode>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Discriminator {
    pub property_name: String,
    pub mapping: Vec<(String, String)>,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SchemaRef {
    pub source_id: String,
    pub json_pointer: String,
}

/// Version-neutral schema shapes. Common annotations, nullability, and source
/// identity live in each variant's `meta` field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaNode {
    Ref {
        target: SchemaRef,
        meta: SchemaMeta,
    },
    Primitive {
        ty: PrimitiveType,
        format: Option<String>,
        enum_values: Option<Vec<Value>>,
        const_value: Option<Value>,
        meta: SchemaMeta,
    },
    /// A finite `enum`/`const` constraint without a declared primitive type.
    Finite {
        enum_values: Option<Vec<Value>>,
        const_value: Option<Value>,
        meta: SchemaMeta,
    },
    Object {
        properties: Vec<(String, SchemaNode, PropMeta)>,
        additional_properties: AdditionalProperties,
        dependent_required: Vec<(String, Vec<String>)>,
        meta: SchemaMeta,
    },
    Array {
        items: Box<SchemaNode>,
        meta: SchemaMeta,
    },
    Tuple {
        prefix_items: Vec<SchemaNode>,
        rest: TupleRest,
        meta: SchemaMeta,
    },
    AllOf {
        branches: Vec<SchemaNode>,
        meta: SchemaMeta,
    },
    OneOf {
        branches: Vec<SchemaNode>,
        discriminator: Option<Discriminator>,
        meta: SchemaMeta,
    },
    AnyOf {
        branches: Vec<SchemaNode>,
        meta: SchemaMeta,
    },
    /// The JSON Schema boolean schema `true`.
    Any {
        meta: SchemaMeta,
    },
    /// The JSON Schema boolean schema `false`.
    Never {
        meta: SchemaMeta,
    },
    Unknown {
        reason: String,
        meta: SchemaMeta,
    },
}

impl SchemaNode {
    #[must_use]
    pub const fn meta(&self) -> &SchemaMeta {
        match self {
            Self::Ref { meta, .. }
            | Self::Primitive { meta, .. }
            | Self::Finite { meta, .. }
            | Self::Object { meta, .. }
            | Self::Array { meta, .. }
            | Self::Tuple { meta, .. }
            | Self::AllOf { meta, .. }
            | Self::OneOf { meta, .. }
            | Self::AnyOf { meta, .. }
            | Self::Any { meta }
            | Self::Never { meta }
            | Self::Unknown { meta, .. } => meta,
        }
    }

    #[must_use]
    pub const fn is_nullable(&self) -> bool {
        self.meta().nullable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_of_exposes_its_metadata() {
        for schema in [
            SchemaNode::AnyOf {
                branches: Vec::new(),
                meta: SchemaMeta {
                    nullable: true,
                    ..SchemaMeta::default()
                },
            },
            SchemaNode::Any {
                meta: SchemaMeta::default(),
            },
            SchemaNode::Never {
                meta: SchemaMeta::default(),
            },
        ] {
            assert_eq!(schema.is_nullable(), schema.meta().nullable);
        }
    }
}
