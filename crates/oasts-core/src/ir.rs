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

/// Per-node metadata carried by every [`SchemaNode`] variant.
///
/// The five constraint/extension groups below are boxed because real specs populate them on well
/// under 1% of nodes (measured on github/stripe/kubernetes corpora), yet each is large inline
/// (`EnumExtensionData` 288 B, `NumericConstraints` 120 B, `StringConstraints` 56 B,
/// `ArrayConstraints` 40 B, `ObjectConstraints` 32 B). Storing them as `Option<Box<…>>` keeps an
/// unpopulated group at 8 bytes, so the common node stays small and the whole IR's peak heap drops
/// — without adding an allocation to the overwhelmingly common empty case. Read them through the
/// accessors ([`SchemaMeta::numeric_constraints`] etc.), which hand back a shared empty default
/// when the box is absent; the raw fields stay public for construction. `docs` stays inline: it is
/// populated on a large minority of nodes, so boxing it would add allocations without a matching
/// resident-size win.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaMeta {
    pub nullable: bool,
    /// OpenAPI 3.1 `contentEncoding`, retained for multipart composition.
    pub content_encoding: Option<String>,
    pub docs: SchemaDocs,
    pub enum_extensions: Option<Box<EnumExtensionData>>,
    pub numeric_constraints: Option<Box<NumericConstraints>>,
    pub string_constraints: Option<Box<StringConstraints>>,
    pub array_constraints: Option<Box<ArrayConstraints>>,
    pub object_constraints: Option<Box<ObjectConstraints>>,
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
        /// Boxed: a discriminator is present on a small fraction of `oneOf` nodes, so the 112-byte
        /// `Discriminator` is kept off the common `SchemaNode` footprint.
        discriminator: Option<Box<Discriminator>>,
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
    use std::mem::size_of;

    use super::*;

    #[test]
    fn schema_node_and_meta_stay_small() {
        // Guards the T3.9 layout win: boxing the five sparse constraint/extension groups (and
        // `OneOf`'s discriminator) keeps `SchemaNode` far below its former 992 bytes. A regression
        // here means a large field was added inline again, re-inflating every stored node.
        assert_eq!(size_of::<SchemaNode>(), 488);
        assert_eq!(size_of::<SchemaMeta>(), 360);

        // The boxed groups must each be an 8-byte null-optimized pointer inline.
        assert_eq!(size_of::<Option<Box<EnumExtensionData>>>(), 8);
        assert_eq!(size_of::<Option<Box<NumericConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<StringConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<ArrayConstraints>>>(), 8);
        assert_eq!(size_of::<Option<Box<ObjectConstraints>>>(), 8);
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
    fn constraint_accessors_return_the_shared_empty_default_when_absent() {
        let meta = SchemaMeta::default();
        assert_eq!(meta.enum_extensions(), &EnumExtensionData::default());
        assert_eq!(meta.numeric_constraints(), &NumericConstraints::default());
        assert_eq!(meta.string_constraints(), &StringConstraints::default());
        assert_eq!(meta.array_constraints(), &ArrayConstraints::default());
        assert_eq!(meta.object_constraints(), &ObjectConstraints::default());

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
