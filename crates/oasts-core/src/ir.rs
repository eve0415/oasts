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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Param {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub deprecated: bool,
    pub description: Option<String>,
    pub schema: SchemaNode,
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
    pub name: String,
    pub schema: SchemaNode,
    /// Media-type examples paired with a stable source label.
    pub examples: Vec<(String, Value)>,
    pub source: SourceRef,
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaMeta {
    pub nullable: bool,
    pub docs: SchemaDocs,
    pub enum_extensions: EnumExtensionData,
    pub numeric_constraints: NumericConstraints,
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
