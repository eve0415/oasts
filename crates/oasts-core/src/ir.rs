//! Version-neutral intermediate representation for OpenAPI input.

use serde_json::{Number, Value};

/// Whether a JSON Pointer addresses a `components/schemas` entry itself, rather than something
/// nested inside one.
///
/// A prefix test alone is not enough: `/components/schemas/Foo/properties/bar` shares the prefix
/// but is an inline schema, which has a name of its own to derive and a declaration of its own to
/// emit. Callers use this to tell the two apart — a declared component is already named by its map
/// key, everything else is addressed by pointer.
#[must_use]
pub fn is_root_component_pointer(json_pointer: &str) -> bool {
    json_pointer
        .strip_prefix("/components/schemas/")
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
}

/// Resolves a relative file reference against a logical source id (e.g. `workspace/openapi.json`),
/// normalizing `.` and `..` segments, so a `file#/...` discriminator mapping value can be resolved
/// to the source it names.
#[must_use]
pub fn join_relative_source(base: &str, relative: &str) -> String {
    let mut segments: Vec<&str> = base.split('/').collect();
    segments.pop();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    segments.join("/")
}

/// Resolves one discriminator `mapping` value to the schema identity it names, using the same
/// rules emission applies: a bare name is a root component of the declaring document, a leading
/// `#` is a pointer into it, and a `file#pointer` is relative to the declaring document.
#[must_use]
pub fn mapping_schema_ref(source: &SourceRef, target: &str) -> SchemaRef {
    let base = source.source_id.as_str();
    match target.split_once('#') {
        None => SchemaRef {
            source_id: base.to_owned(),
            json_pointer: format!("/components/schemas/{target}"),
        },
        Some(("", fragment)) => SchemaRef {
            source_id: base.to_owned(),
            json_pointer: fragment.to_owned(),
        },
        Some((file, fragment)) => SchemaRef {
            source_id: join_relative_source(base, file),
            json_pointer: fragment.to_owned(),
        },
    }
}

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
    /// Entry-document webhooks, in source insertion order.
    pub webhooks: Vec<Webhook>,
    /// Entry-document `components.schemas`, in source insertion order.
    pub schemas: Vec<NamedSchema>,
    /// Entry-document server defaults, in source insertion order.
    pub root_servers: Vec<ServerEntry>,
    /// Entry-document security alternatives; an empty requirement is anonymous access.
    pub root_security: Vec<SecurityRequirement>,
    /// Entry-document named security schemes, in source insertion order.
    pub security_schemes: Vec<NamedSecurityScheme>,
    /// Declarations that filtering and pruning removed.
    ///
    /// Naming overrides are judged against the document as written, so an override naming one of
    /// these is not reported as a typo — default-on pruning must never turn a config that was
    /// valid into an error.
    pub removed: RemovedDeclarations,
    /// The entry document's declared OpenAPI version, carried from the parser so version-dependent
    /// rules read the document's own version rather than inferring it from the first media type —
    /// media-less documents (204-only, header-only) have no media to infer from.
    pub version: OasVersion,
}

/// The names of declarations that filtering and pruning removed, in source order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemovedDeclarations {
    pub schemas: Vec<String>,
    /// Operation ids; an operation without one contributes nothing, because an override cannot
    /// have named it either.
    pub operations: Vec<String>,
    /// JSON pointers of removed operations, for link targets written as an `operationRef`.
    pub operation_pointers: Vec<String>,
    pub webhooks: Vec<String>,
    pub callbacks: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OasVersion {
    V3_0,
    V3_1,
}

impl Default for OasVersion {
    /// The constructor default for synthetic IRs built with `..Ir::default()`; real documents
    /// always overwrite it with the parser's declared version.
    fn default() -> Self {
        Self::V3_1
    }
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
    /// Operation tags in source order; empty when the operation declares none.
    ///
    /// Tags are advisory metadata, so a non-array `tags` value and non-string entries inside
    /// one are skipped silently rather than diagnosed — a malformed tag must not fail an
    /// otherwise valid document.
    pub tags: Vec<String>,
    /// The raw path template as written, e.g. `/pets/{petId}`. `None` for webhook and callback
    /// operations, which have no path — filters keyed on paths abstain on those rather than
    /// rejecting them. `path_template` cannot serve here: it is empty both for `/` and for a
    /// webhook.
    pub path: Option<String>,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub deprecated: bool,
    pub external_docs: Option<(String, Option<String>)>,
    pub parameters: Vec<Param>,
    pub request_body: Option<Body>,
    pub responses: Vec<ResponseEntry>,
    /// Named callbacks, in source insertion order.
    pub callbacks: Vec<Callback>,
    /// Operation-then-path-item effective servers; an empty array defers root fallback.
    pub servers: Vec<ServerEntry>,
    /// Operation-level security override; `None` preserves the document default.
    pub security: Option<Vec<SecurityRequirement>>,
    pub source: SourceRef,
}

/// A named top-level webhook and its path-item operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Webhook {
    pub name: String,
    pub operations: Vec<Operation>,
    pub source: SourceRef,
}

/// A named operation callback and its runtime expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Callback {
    pub name: String,
    pub expressions: Vec<CallbackExpression>,
    pub source: SourceRef,
}

/// A callback runtime expression and its path-item operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackExpression {
    pub expression: String,
    pub operations: Vec<Operation>,
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
    /// Canonical full media type when the parameter is sourced from `content`.
    pub content_media_type: Option<String>,
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
    pub essence: String,
    /// Canonical full media type or range, including sorted parameters.
    pub full: String,
    /// How wide the essence matches, decided by the RFC 9110 type/subtype wildcards. Carried from
    /// parse so downstream consumers (body/response discrimination, Accept assembly) never re-derive
    /// range-ness from a raw `*` substring on the parameterized full string. `pub(crate)` because its
    /// type lives in the crate-private `media` module.
    pub(crate) range_kind: crate::media::MediaRangeKind,
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
    /// Canonical full media type when the header is sourced from `content`.
    pub content_media_type: Option<String>,
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
#[expect(
    clippy::large_enum_variant,
    reason = "security schemes are few and their payloads intentionally remain inline"
)]
pub enum SecKind {
    /// HTTP authentication using the declared scheme token.
    Http {
        scheme: String,
        bearer_format: Option<String>,
    },
    /// API key serialized at the declared parameter location and name.
    ApiKey {
        location: ParamLocation,
        name: String,
    },
    /// OAuth 2.0 authentication with its declared flows.
    OAuth2 { flows: OAuthFlows },
    /// OpenID Connect discovery using the declared URL.
    OpenIdConnect { url: String },
    /// Mutual TLS authentication.
    MutualTls,
    /// Unknown or unsupported security scheme shape.
    Other,
}

/// The four OAuth 2.0 flow kinds declared by OpenAPI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthFlows {
    /// Whether the required `flows` field was present on the Security Scheme Object.
    pub declared: bool,
    pub implicit: Option<OAuthFlow>,
    pub password: Option<OAuthFlow>,
    pub client_credentials: Option<OAuthFlow>,
    pub authorization_code: Option<OAuthFlow>,
}

impl OAuthFlows {
    /// Returns whether no OAuth 2.0 flow is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.implicit.is_none()
            && self.password.is_none()
            && self.client_credentials.is_none()
            && self.authorization_code.is_none()
    }

    /// Returns declared scope names in first-seen order without duplicates.
    #[must_use]
    pub fn declared_scopes(&self) -> Vec<&str> {
        let mut declared = Vec::new();
        for flow in [
            self.implicit.as_ref(),
            self.password.as_ref(),
            self.client_credentials.as_ref(),
            self.authorization_code.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for (name, _) in &flow.scopes {
                if !declared.contains(&name.as_str()) {
                    declared.push(name.as_str());
                }
            }
        }
        declared
    }
}

/// One OAuth 2.0 flow with source-ordered scope declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthFlow {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub refresh_url: Option<String>,
    pub scopes: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseEntry {
    pub status: ResponseStatus,
    pub description: String,
    pub media_types: Vec<MediaType>,
    /// Named response headers, in source insertion order.
    pub headers: Vec<(String, ResponseHeader)>,
    /// Named response links, in source insertion order.
    pub links: Vec<Link>,
    pub source: SourceRef,
}

/// A response Header Object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    /// Whether callers must receive this header.
    pub required: bool,
    /// Whether use of this header is discouraged.
    pub deprecated: bool,
    /// Human-readable header description.
    pub description: Option<String>,
    /// Header value schema.
    pub schema: SchemaNode,
    /// Canonical full media type when the header is sourced from `content`.
    pub content_media_type: Option<String>,
    /// Source identity of this Header Object.
    pub source: SourceRef,
}

/// A response Link Object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// Link-map key exactly as declared.
    pub name: String,
    /// Target operation selector.
    pub target: LinkTarget,
    /// Operation parameters, in source insertion order.
    pub parameters: Vec<(String, String)>,
    /// Human-readable link description.
    pub description: Option<String>,
    /// Source identity of this Link Object.
    pub source: SourceRef,
}

/// The operation selector declared by a response Link Object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkTarget {
    /// An operation selected by its identifier.
    OperationId(String),
    /// An operation selected by a reference.
    OperationRef(String),
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
    /// Required names retained for a typeless schema such as `{required: ["id"]}`. Typed object
    /// nodes keep their position-aware required data on properties/`extra_required`; validators
    /// consult this copy only for `SchemaNode::Any`.
    pub required: Vec<String>,
}

/// JSON Schema applicators retained solely for exact generated validation. The TypeScript type
/// surface intentionally ignores the applicators without a faithful structural representation.
/// `patternProperties` is the exception: the types emitter consumes it as structural index
/// signatures while the validators emitter also applies each regex-keyed schema exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainsApplicator {
    pub schema: Box<SchemaNode>,
    pub min_contains: Option<u64>,
    pub max_contains: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatternPropertyKey {
    All,
    Prefix(String),
    Contains(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternProperty {
    pub pattern: String,
    pub schema: SchemaNode,
    pub type_key: Option<PatternPropertyKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalApplicator {
    pub condition: Box<SchemaNode>,
    pub then_schema: Option<Box<SchemaNode>>,
    pub else_schema: Option<Box<SchemaNode>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidationApplicators {
    pub not: Option<Box<SchemaNode>>,
    pub property_names: Option<Box<SchemaNode>>,
    pub pattern_properties: Vec<PatternProperty>,
    pub contains: Option<Box<ContainsApplicator>>,
    pub dependent_schemas: Vec<(String, SchemaNode)>,
    pub conditional: Option<Box<ConditionalApplicator>>,
    pub unevaluated_properties: Option<Box<SchemaNode>>,
    pub unevaluated_items: Option<Box<SchemaNode>>,
}

/// A finite `enum`/`const` value restriction shared by structural container schemas.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FiniteConstraint {
    pub enum_values: Option<Vec<Value>>,
    pub const_value: Option<Value>,
}

/// Splits a boxed [`FiniteConstraint`] into its parts, handing back `None`/`None` uniformly when
/// the box is absent so callers don't special-case presence.
#[must_use]
pub fn finite_parts(finite: &Option<Box<FiniteConstraint>>) -> (Option<&[Value]>, Option<&Value>) {
    finite.as_deref().map_or((None, None), |f| {
        (f.enum_values.as_deref(), f.const_value.as_ref())
    })
}

/// Per-node metadata carried by every [`SchemaNode`] variant.
///
/// The six constraint/extension groups below are boxed because real specs populate them on well
/// under 1% of nodes (measured on github/stripe/kubernetes corpora), yet each is large inline
/// (`EnumExtensionData` 288 B, `NumericConstraints` 120 B, `StringConstraints` 56 B,
/// `ArrayConstraints` 40 B, `ObjectConstraints` 56 B). Storing them as `Option<Box<…>>` keeps an
/// unpopulated group at 8 bytes, so the common node stays small and the whole IR's peak heap drops
/// — without adding an allocation to the overwhelmingly common empty case. Read them through the
/// accessors ([`SchemaMeta::numeric_constraints`] etc.), which hand back a shared empty default
/// when the box is absent; the raw fields stay public for construction. `docs` stays inline: it is
/// populated on a large minority of nodes, so boxing it would add allocations without a matching
/// resident-size win.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaMeta {
    pub nullable: bool,
    /// Distinguishes an omitted `additionalProperties` from an explicit `true`/schema. Both
    /// accept the same values, but only the explicit keyword produces evaluated-property
    /// annotations for `unevaluatedProperties`.
    pub additional_properties_present: bool,
    /// Distinguishes an omitted `items` from an explicit `true`/schema for evaluated-item
    /// annotation collection.
    pub items_present: bool,
    /// OpenAPI `readOnly` on this schema node: the value is server-emitted only, never accepted
    /// from the client.
    pub read_only: bool,
    /// OpenAPI `writeOnly` on this schema node: the value is client-supplied only, never emitted
    /// by the server.
    pub write_only: bool,
    /// OpenAPI 3.1 `contentEncoding`, retained for multipart composition.
    pub content_encoding: Option<String>,
    pub docs: SchemaDocs,
    pub enum_extensions: Option<Box<EnumExtensionData>>,
    pub numeric_constraints: Option<Box<NumericConstraints>>,
    pub string_constraints: Option<Box<StringConstraints>>,
    pub array_constraints: Option<Box<ArrayConstraints>>,
    pub object_constraints: Option<Box<ObjectConstraints>>,
    pub validation_applicators: Option<Box<ValidationApplicators>>,
    pub rejected_validation_keywords: Vec<String>,
    pub source: SourceRef,
}

static EMPTY_ENUM_EXTENSIONS: EnumExtensionData = EnumExtensionData {
    enum_varnames: None,
    enum_names: None,
    enum_descriptions: None,
    enum_descriptions_camel: None,
};
static EMPTY_NUMERIC_CONSTRAINTS: NumericConstraints = NumericConstraints {
    minimum: None,
    maximum: None,
    exclusive_minimum: None,
    exclusive_maximum: None,
    multiple_of: None,
};
static EMPTY_STRING_CONSTRAINTS: StringConstraints = StringConstraints {
    min_length: None,
    max_length: None,
    pattern: None,
};
static EMPTY_ARRAY_CONSTRAINTS: ArrayConstraints = ArrayConstraints {
    min_items: None,
    max_items: None,
    unique_items: false,
};
static EMPTY_OBJECT_CONSTRAINTS: ObjectConstraints = ObjectConstraints {
    min_properties: None,
    max_properties: None,
    required: Vec::new(),
};
static EMPTY_VALIDATION_APPLICATORS: ValidationApplicators = ValidationApplicators {
    not: None,
    property_names: None,
    pattern_properties: Vec::new(),
    contains: None,
    dependent_schemas: Vec::new(),
    conditional: None,
    unevaluated_properties: None,
    unevaluated_items: None,
};
impl SchemaMeta {
    #[must_use]
    pub fn enum_extensions(&self) -> &EnumExtensionData {
        self.enum_extensions
            .as_deref()
            .unwrap_or(&EMPTY_ENUM_EXTENSIONS)
    }

    #[must_use]
    pub fn numeric_constraints(&self) -> &NumericConstraints {
        self.numeric_constraints
            .as_deref()
            .unwrap_or(&EMPTY_NUMERIC_CONSTRAINTS)
    }

    #[must_use]
    pub fn string_constraints(&self) -> &StringConstraints {
        self.string_constraints
            .as_deref()
            .unwrap_or(&EMPTY_STRING_CONSTRAINTS)
    }

    #[must_use]
    pub fn array_constraints(&self) -> &ArrayConstraints {
        self.array_constraints
            .as_deref()
            .unwrap_or(&EMPTY_ARRAY_CONSTRAINTS)
    }

    #[must_use]
    pub fn object_constraints(&self) -> &ObjectConstraints {
        self.object_constraints
            .as_deref()
            .unwrap_or(&EMPTY_OBJECT_CONSTRAINTS)
    }

    #[must_use]
    pub fn validation_applicators(&self) -> &ValidationApplicators {
        self.validation_applicators
            .as_deref()
            .unwrap_or(&EMPTY_VALIDATION_APPLICATORS)
    }

    /// Splits this meta for conjunction lowering, where an object that carries applicators
    /// (`allOf`/`$ref`/`oneOf`/`anyOf`) alongside typed/constraint content is rewritten to a
    /// synthetic `AllOf` wrapping a typed branch. The wrapper node keeps everything read once at
    /// the conjunction — documentation, nullability, and read/write-only visibility — while the
    /// typed branch takes the structured validation constraints it alone must enforce.
    /// `unevaluatedProperties`/`unevaluatedItems` remain on the wrapper so they run after every
    /// synthetic branch and see annotations produced by sibling `$ref`/composition pieces; the
    /// other validation applicators stay with the typed branch. The split prevents
    /// double-application: TSDoc reads the wrapper's docs, validators walk each constraint group
    /// once, and both nodes point at the same source. Returns `(wrapper, typed_branch)`.
    #[must_use]
    pub fn split_for_conjunction(self) -> (SchemaMeta, SchemaMeta) {
        let (wrapper_validation_applicators, typed_validation_applicators) = self
            .validation_applicators
            .map_or((None, None), |applicators| {
                let ValidationApplicators {
                    not,
                    property_names,
                    pattern_properties,
                    contains,
                    dependent_schemas,
                    conditional,
                    unevaluated_properties,
                    unevaluated_items,
                } = *applicators;
                (
                    box_if_populated(ValidationApplicators {
                        unevaluated_properties,
                        unevaluated_items,
                        ..ValidationApplicators::default()
                    }),
                    box_if_populated(ValidationApplicators {
                        not,
                        property_names,
                        pattern_properties,
                        contains,
                        dependent_schemas,
                        conditional,
                        ..ValidationApplicators::default()
                    }),
                )
            });
        let typed = SchemaMeta {
            content_encoding: self.content_encoding,
            additional_properties_present: self.additional_properties_present,
            items_present: self.items_present,
            enum_extensions: self.enum_extensions,
            numeric_constraints: self.numeric_constraints,
            string_constraints: self.string_constraints,
            array_constraints: self.array_constraints,
            object_constraints: self.object_constraints,
            validation_applicators: typed_validation_applicators,
            rejected_validation_keywords: self.rejected_validation_keywords,
            source: self.source.clone(),
            ..SchemaMeta::default()
        };
        let wrapper = SchemaMeta {
            nullable: self.nullable,
            read_only: self.read_only,
            write_only: self.write_only,
            docs: self.docs,
            validation_applicators: wrapper_validation_applicators,
            source: self.source,
            ..SchemaMeta::default()
        };
        (wrapper, typed)
    }
}

/// Boxes `value` only when it differs from its default, so an unpopulated constraint/extension
/// group costs 8 bytes (a null `Option<Box<…>>`) and no allocation, while a populated one moves off
/// the inline `SchemaMeta` footprint. Used at IR construction; reads go through the accessors.
///
/// This is the sanctioned constructor for the boxed groups: the invariant `Some(boxed)` ⟺
/// non-default is load-bearing, because `SchemaMeta`'s derived `PartialEq` feeds allOf merge
/// equality in the emitter — a hand-built `Some(Box::new(T::default()))` would compare unequal
/// to the canonical `None` and silently flip merge decisions.
#[must_use]
pub fn box_if_populated<T: Default + PartialEq>(value: T) -> Option<Box<T>> {
    (value != T::default()).then(|| Box::new(value))
}

/// Metadata belonging to the object-property edge. Schema annotations stay on the child node's
/// [`SchemaMeta`] so each property does not duplicate owned documentation values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropMeta {
    pub required: bool,
    pub read_only: bool,
    pub write_only: bool,
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
        /// Finite `enum`/`const` value restriction checked by validators; types stay structural.
        finite: Option<Box<FiniteConstraint>>,
        /// Required names asserted by the schema's `required` array but not declared in `properties`; enforced by validators only, invisible to the type surface.
        extra_required: Vec<String>,
        meta: SchemaMeta,
    },
    Array {
        items: Box<SchemaNode>,
        /// Finite `enum`/`const` value restriction checked by validators; types stay structural.
        finite: Option<Box<FiniteConstraint>>,
        meta: SchemaMeta,
    },
    Tuple {
        prefix_items: Vec<SchemaNode>,
        rest: TupleRest,
        /// Finite `enum`/`const` value restriction checked by validators; types stay structural.
        finite: Option<Box<FiniteConstraint>>,
        meta: SchemaMeta,
    },
    AllOf {
        branches: Vec<SchemaNode>,
        meta: SchemaMeta,
    },
    OneOf {
        branches: Vec<SchemaNode>,
        /// Boxed: a discriminator is present on a small fraction of `oneOf` nodes, so the 112-byte
        /// `Discriminator` is kept off the common `SchemaNode` footprint.
        discriminator: Option<Box<Discriminator>>,
        meta: SchemaMeta,
    },
    AnyOf {
        branches: Vec<SchemaNode>,
        /// Boxed: mirrors `OneOf`'s discriminator representation; present on a small fraction of
        /// `anyOf` nodes, parsing deferred.
        discriminator: Option<Box<Discriminator>>,
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

    /// Consumes the node for its metadata. Used where a lowering replaces a node with a different
    /// one at the same source location and must carry that location, its docs, and its annotations
    /// across rather than rebuild them.
    #[must_use]
    pub fn into_meta(self) -> SchemaMeta {
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
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    /// `into_meta` is the owned counterpart of `meta()`, and its arms are what a lowering relies on
    /// to carry a node's source location and annotations onto the node that replaces it. Every
    /// variant is listed here because a variant that silently stopped yielding its meta would drop
    /// the `// Source:` provenance of whatever replaced it, with nothing else to notice.
    #[test]
    fn into_meta_yields_the_meta_of_every_variant() {
        let tagged = |nullable: bool| SchemaMeta {
            nullable,
            ..SchemaMeta::default()
        };
        let reference = SchemaRef {
            source_id: "doc".to_owned(),
            json_pointer: "/components/schemas/Thing".to_owned(),
        };
        let nodes = [
            SchemaNode::Ref {
                target: reference,
                meta: tagged(true),
            },
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                format: None,
                enum_values: None,
                const_value: None,
                meta: tagged(true),
            },
            SchemaNode::Finite {
                enum_values: None,
                const_value: None,
                meta: tagged(true),
            },
            SchemaNode::Object {
                properties: Vec::new(),
                additional_properties: AdditionalProperties::Allowed(None),
                dependent_required: Vec::new(),
                finite: None,
                extra_required: Vec::new(),
                meta: tagged(true),
            },
            SchemaNode::Array {
                items: Box::new(SchemaNode::Any {
                    meta: SchemaMeta::default(),
                }),
                finite: None,
                meta: tagged(true),
            },
            SchemaNode::Tuple {
                prefix_items: Vec::new(),
                rest: TupleRest::Allowed,
                finite: None,
                meta: tagged(true),
            },
            SchemaNode::AllOf {
                branches: Vec::new(),
                meta: tagged(true),
            },
            SchemaNode::OneOf {
                branches: Vec::new(),
                discriminator: None,
                meta: tagged(true),
            },
            SchemaNode::AnyOf {
                branches: Vec::new(),
                discriminator: None,
                meta: tagged(true),
            },
            SchemaNode::Any { meta: tagged(true) },
            SchemaNode::Never { meta: tagged(true) },
            SchemaNode::Unknown {
                reason: "probe".to_owned(),
                meta: tagged(true),
            },
        ];
        for node in nodes {
            let borrowed = node.meta().nullable;
            assert!(borrowed);
            assert!(node.into_meta().nullable);
        }
    }

    #[test]
    fn schema_node_and_meta_stay_small() {
        // Guards the T3.9 layout win: boxing the six sparse constraint/extension groups (and
        // `OneOf`'s discriminator) keeps `SchemaNode` far below its former 992 bytes. A regression
        // here means a large field was added inline again, re-inflating every stored node.
        assert_eq!(size_of::<SchemaNode>(), 496);
        assert_eq!(size_of::<SchemaMeta>(), 368);
        assert_eq!(size_of::<PropMeta>(), 3);

        // The boxed groups must each be an 8-byte null-optimized pointer inline.
        assert_eq!(size_of::<Option<Box<EnumExtensionData>>>(), 8);
        assert_eq!(size_of::<Option<Box<NumericConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<StringConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<ArrayConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<ObjectConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<ValidationApplicators>>>(), 8);
        assert_eq!(size_of::<Option<Box<Discriminator>>>(), 8);

        // The unboxed component sizes the design reasons about; a change here should be a
        // deliberate re-measure, not a silent drift.
        assert_eq!(size_of::<SchemaDocs>(), 200);
        assert_eq!(size_of::<EnumExtensionData>(), 288);
        assert_eq!(size_of::<NumericConstraints>(), 120);
        assert_eq!(size_of::<Discriminator>(), 112);
        assert_eq!(size_of::<SourceRef>(), 64);
    }

    #[test]
    fn box_if_populated_boxes_only_non_default_values() {
        assert!(box_if_populated(NumericConstraints::default()).is_none());
        let populated = NumericConstraints {
            minimum: Some(Number::from(1)),
            ..NumericConstraints::default()
        };
        assert_eq!(
            box_if_populated(populated.clone()).as_deref(),
            Some(&populated)
        );
    }

    #[test]
    fn conjunction_split_keeps_unevaluated_applicators_on_the_wrapper() {
        let schema = || {
            Box::new(SchemaNode::Any {
                meta: SchemaMeta::default(),
            })
        };
        let (wrapper, typed) = SchemaMeta {
            validation_applicators: Some(Box::new(ValidationApplicators {
                not: Some(schema()),
                conditional: Some(Box::new(ConditionalApplicator {
                    condition: schema(),
                    then_schema: None,
                    else_schema: None,
                })),
                unevaluated_properties: Some(schema()),
                unevaluated_items: Some(schema()),
                ..ValidationApplicators::default()
            })),
            ..SchemaMeta::default()
        }
        .split_for_conjunction();

        let wrapper_applicators = wrapper.validation_applicators();
        assert!(wrapper_applicators.unevaluated_properties.is_some());
        assert!(wrapper_applicators.unevaluated_items.is_some());
        assert!(wrapper_applicators.not.is_none());
        assert!(wrapper_applicators.conditional.is_none());
        let typed_applicators = typed.validation_applicators();
        assert!(typed_applicators.not.is_some());
        assert!(typed_applicators.conditional.is_some());
        assert!(typed_applicators.unevaluated_properties.is_none());
        assert!(typed_applicators.unevaluated_items.is_none());
    }

    #[test]
    fn constraint_accessors_return_the_shared_empty_default_when_absent() {
        let meta = SchemaMeta::default();
        assert_eq!(meta.enum_extensions(), &EnumExtensionData::default());
        assert_eq!(meta.numeric_constraints(), &NumericConstraints::default());
        assert_eq!(meta.string_constraints(), &StringConstraints::default());
        assert_eq!(meta.array_constraints(), &ArrayConstraints::default());
        assert_eq!(meta.object_constraints(), &ObjectConstraints::default());
        assert_eq!(
            meta.validation_applicators(),
            &ValidationApplicators::default()
        );
        let populated = SchemaMeta {
            numeric_constraints: box_if_populated(NumericConstraints {
                minimum: Some(Number::from(2)),
                ..NumericConstraints::default()
            }),
            ..SchemaMeta::default()
        };
        assert_eq!(
            populated.numeric_constraints().minimum,
            Some(Number::from(2))
        );
    }

    #[test]
    fn any_of_exposes_its_metadata() {
        for schema in [
            SchemaNode::AnyOf {
                branches: Vec::new(),
                discriminator: None,
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

    #[test]
    fn finite_parts_splits_present_and_absent_boxes() {
        assert_eq!(finite_parts(&None), (None, None));
        let finite = Some(Box::new(FiniteConstraint {
            enum_values: Some(vec![Value::from(1)]),
            const_value: Some(Value::from(2)),
        }));
        let (enum_values, const_value) = finite_parts(&finite);
        assert_eq!(enum_values, Some(&[Value::from(1)][..]));
        assert_eq!(const_value, Some(&Value::from(2)));
    }
}
