//! Semantic analysis, identifier normalization, and stable name allocation.

use std::collections::HashMap;
use std::fmt;

use serde_json::{Number, Value};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::config::{
    EnumExtensions, EnumMemberCase, EnumRepresentation, NamingConfig, OperationCase,
    ResolvedConfig, TypesConfig,
};
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::ir::{
    AdditionalProperties, Ir, Operation, PrimitiveType, SchemaMeta, SchemaNode, SegmentPart,
    SourceRef, TupleRest,
};
use crate::num::render_number;

const CODE_OPERATION_NAME: &str = "OASTS1201";
const CODE_TYPE_NAME: &str = "OASTS1202";
const CODE_ENUM_RULE_14: &str = "OASTS1214";
// Config-category (exit code 2): an override key that names no declaration in the document.
const CODE_OVERRIDE_UNMATCHED: &str = "OASTS0202";

const RESERVED_WORDS: [&str; 46] = [
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
    "await",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetCase {
    Pascal,
    Camel,
    ScreamingSnake,
    Preserve,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizeError {
    NonAscii(char),
    Empty,
    LeadingDigit,
    ReservedWord(String),
    InvalidIdentifierCharacter(char),
    NumericDomain,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonAscii(character) => {
                write!(
                    formatter,
                    "non-ASCII character U+{:04X} remains",
                    *character as u32
                )
            }
            Self::Empty => formatter.write_str("normalization produced an empty identifier"),
            Self::LeadingDigit => formatter.write_str("identifier begins with a digit"),
            Self::ReservedWord(word) => {
                write!(formatter, "'{word}' is a TypeScript reserved word")
            }
            Self::InvalidIdentifierCharacter(character) => write!(
                formatter,
                "identifier contains invalid character '{}'",
                character.escape_default()
            ),
            Self::NumericDomain => {
                formatter.write_str("numeric value is outside the binary64 domain")
            }
        }
    }
}

impl std::error::Error for NormalizeError {}

/// Applies the exact Unicode, tokenization, casing, and validation order.
pub fn normalize_identifier(input: &str, case: TargetCase) -> Result<String, NormalizeError> {
    let tokens = identifier_tokens(input)?;
    if tokens.is_empty() {
        return Err(NormalizeError::Empty);
    }
    let normalized = transform_tokens(&tokens, case);
    validate_normalized_identifier(&normalized)?;
    Ok(normalized)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedOperationName {
    pub operation_index: usize,
    pub name: String,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedSchemaName {
    pub schema_index: usize,
    pub wire_name: String,
    pub name: String,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumMember {
    pub name: String,
    pub value: Value,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumMemberTable {
    pub source: SourceRef,
    pub members: Vec<EnumMember>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Analyzed {
    pub ir: Ir,
    pub operation_names: Vec<AllocatedOperationName>,
    pub schema_names: Vec<AllocatedSchemaName>,
    pub enum_members: Vec<EnumMemberTable>,
}

/// Runs name allocation and rule-14 enum analysis using resolved config.
pub fn analyze(ir: Ir, config: &ResolvedConfig, sink: &mut DiagnosticSink) -> Analyzed {
    analyze_with_options(ir, &config.naming, &config.types, sink)
}

/// Runs semantic analysis with the two option groups that affect Phase 3.
pub fn analyze_with_options(
    ir: Ir,
    naming: &NamingConfig,
    types: &TypesConfig,
    sink: &mut DiagnosticSink,
) -> Analyzed {
    let operation_names = allocate_operation_names(&ir, naming, sink);
    let schema_names = allocate_schema_names(&ir, naming, sink);
    report_unmatched_overrides(&ir, naming, sink);
    let mut enum_members = Vec::new();
    let mut enum_analysis = EnumAnalysis {
        naming,
        types,
        sink,
        tables: &mut enum_members,
    };
    for schema in &ir.schemas {
        analyze_schema_enums(&schema.schema, &mut enum_analysis);
    }
    for operation in &ir.operations {
        for parameter in &operation.parameters {
            analyze_schema_enums(&parameter.schema, &mut enum_analysis);
        }
        if let Some(body) = &operation.request_body {
            for media_type in &body.media_types {
                analyze_schema_enums(&media_type.schema, &mut enum_analysis);
            }
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                analyze_schema_enums(&media_type.schema, &mut enum_analysis);
            }
        }
    }
    Analyzed {
        ir,
        operation_names,
        schema_names,
        enum_members,
    }
}

/// Allocates one operation name from an explicit ID or its method/path fallback.
pub fn derive_operation_name(
    operation: &Operation,
    case: TargetCase,
) -> Result<String, NormalizeError> {
    if let Some(operation_id) = &operation.operation_id {
        return normalize_identifier(operation_id, case);
    }
    let mut candidate = operation.method.to_ascii_lowercase();
    for segment in &operation.path_template {
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(literal) => {
                    let tokens = identifier_tokens(literal)?;
                    candidate.push_str(&transform_tokens(&tokens, TargetCase::Pascal));
                }
                SegmentPart::Param(name) => {
                    candidate.push_str("By");
                    candidate.push_str(&normalize_identifier(name, TargetCase::Pascal)?);
                }
            }
        }
    }
    normalize_identifier(&candidate, case)
}

fn allocate_operation_names(
    ir: &Ir,
    naming: &NamingConfig,
    sink: &mut DiagnosticSink,
) -> Vec<AllocatedOperationName> {
    let case = match naming.operation_case {
        OperationCase::Camel => TargetCase::Camel,
        OperationCase::Preserve => TargetCase::Preserve,
    };
    let mut names = Vec::new();
    let mut seen: HashMap<String, (String, SourceRef)> = HashMap::new();
    for (operation_index, operation) in ir.operations.iter().enumerate() {
        // An override keyed on operationId supplies the final name verbatim: the case transform
        // does not run on it and it must still validate and collide like any derived name.
        let override_name = operation
            .operation_id
            .as_deref()
            .and_then(|id| naming.overrides.operations.get(id));
        let allocation = match override_name {
            Some(name) => validate_final_identifier(name)
                .map(|()| name.clone())
                .map_err(|error| (name.clone(), error)),
            None => derive_operation_name(operation, case).map_err(|error| {
                (
                    operation
                        .operation_id
                        .as_deref()
                        .unwrap_or("derived name")
                        .to_owned(),
                    error,
                )
            }),
        };
        match allocation {
            Ok(name) => {
                report_collision(
                    "operation",
                    CODE_OPERATION_NAME,
                    &name,
                    &operation.source,
                    &mut seen,
                    sink,
                );
                names.push(AllocatedOperationName {
                    operation_index,
                    name,
                    source: operation.source.clone(),
                });
            }
            Err((input, error)) => push_name_error(
                CODE_OPERATION_NAME,
                "operation",
                &input,
                error,
                &operation.source,
                sink,
            ),
        }
    }
    names
}

fn allocate_schema_names(
    ir: &Ir,
    naming: &NamingConfig,
    sink: &mut DiagnosticSink,
) -> Vec<AllocatedSchemaName> {
    let mut names = Vec::new();
    let mut seen: HashMap<String, (String, SourceRef)> = HashMap::new();
    for (schema_index, schema) in ir.schemas.iter().enumerate() {
        // An override supplies the complete identifier: typePrefix/typeSuffix are not applied on
        // top, but the value must still validate and collide like any generated name.
        let allocation = match naming.overrides.schemas.get(&schema.name) {
            Some(name) => validate_final_identifier(name)
                .map(|()| name.clone())
                .map_err(|error| (name.clone(), error)),
            None => normalize_identifier(&schema.name, TargetCase::Pascal)
                .and_then(|base| {
                    let candidate = format!("{}{}{}", naming.type_prefix, base, naming.type_suffix);
                    validate_final_identifier(&candidate)?;
                    Ok(candidate)
                })
                .map_err(|error| (schema.name.clone(), error)),
        };
        match allocation {
            Ok(name) => {
                report_collision(
                    "schema",
                    CODE_TYPE_NAME,
                    &name,
                    &schema.source,
                    &mut seen,
                    sink,
                );
                names.push(AllocatedSchemaName {
                    schema_index,
                    wire_name: schema.name.clone(),
                    name,
                    source: schema.source.clone(),
                });
            }
            Err((input, error)) => push_name_error(
                CODE_TYPE_NAME,
                "schema",
                &input,
                error,
                &schema.source,
                sink,
            ),
        }
    }
    names
}

/// Reports every override key that names no declaration in the document.
///
/// This is a config error (exit code 2): a typo that silently did nothing would leave the
/// collision the override was meant to resolve still unexplained, sending the user hunting.
/// The check needs the document, so it runs here rather than at config load. Keys are visited
/// in the map's sorted order, so the diagnostics are deterministic.
fn report_unmatched_overrides(ir: &Ir, naming: &NamingConfig, sink: &mut DiagnosticSink) {
    for key in naming.overrides.schemas.keys() {
        if !ir.schemas.iter().any(|schema| &schema.name == key) {
            sink.push(unmatched_override_diagnostic("schema", "schemas", key));
        }
    }
    for key in naming.overrides.operations.keys() {
        if !ir
            .operations
            .iter()
            .any(|operation| operation.operation_id.as_deref() == Some(key.as_str()))
        {
            sink.push(unmatched_override_diagnostic(
                "operation",
                "operations",
                key,
            ));
        }
    }
}

fn unmatched_override_diagnostic(kind: &str, namespace: &str, key: &str) -> Diagnostic {
    Diagnostic::config(
        CODE_OVERRIDE_UNMATCHED,
        format!("naming override key '{key}' matches no {kind} in the document"),
    )
    .with_json_pointer(format!(
        "/naming/overrides/{namespace}/{}",
        escape_json_pointer_token(key)
    ))
}

/// Escapes a single JSON Pointer reference token per RFC 6901 (`~` -> `~0`, `/` -> `~1`).
fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn report_collision(
    kind: &str,
    code: &'static str,
    name: &str,
    source: &SourceRef,
    seen: &mut HashMap<String, (String, SourceRef)>,
    sink: &mut DiagnosticSink,
) {
    // Exact match over case-folded match at the identifier layer, because TypeScript
    // identifiers are case-sensitive: two names differing only in case are two distinct,
    // legal types. Filesystem safety on case-insensitive volumes is enforced separately
    // by the path-collision check (`register_path` / OASTS1302 in `emit/model.rs`), so this
    // layer must not also reject case-only differences.
    if let Some((_, previous_source)) = seen.get(name) {
        let message = format!(
            "{kind} name collision: '{name}' allocated at {} and {}",
            previous_source.display(),
            source.display()
        );
        sink.push(source_diagnostic(code, message, source));
    } else {
        seen.insert(name.to_owned(), (name.to_owned(), source.clone()));
    }
}

fn casefold_collision<T>(
    name: &str,
    seen: &HashMap<String, T>,
    message: impl FnOnce(&T) -> String,
) -> (String, Option<String>) {
    let folded = name.to_ascii_lowercase();
    let collision = seen.get(&folded).map(message);
    (folded, collision)
}

fn push_name_error(
    code: &'static str,
    kind: &str,
    input: &str,
    error: NormalizeError,
    source: &SourceRef,
    sink: &mut DiagnosticSink,
) {
    sink.push(source_diagnostic(
        code,
        format!("invalid {kind} identifier '{input}': {error}"),
        source,
    ));
}

struct EnumAnalysis<'options, 'output> {
    naming: &'options NamingConfig,
    types: &'options TypesConfig,
    sink: &'output mut DiagnosticSink,
    tables: &'output mut Vec<EnumMemberTable>,
}

fn analyze_schema_enums(schema: &SchemaNode, analysis: &mut EnumAnalysis<'_, '_>) {
    match schema {
        SchemaNode::Primitive {
            ty,
            enum_values,
            const_value,
            meta,
            ..
        } => analyze_finite_values(
            Some(*ty),
            enum_values.as_deref(),
            const_value.as_ref(),
            meta,
            analysis,
        ),
        SchemaNode::Finite {
            enum_values,
            const_value,
            meta,
        } => analyze_finite_values(
            None,
            enum_values.as_deref(),
            const_value.as_ref(),
            meta,
            analysis,
        ),
        SchemaNode::Object {
            properties,
            additional_properties,
            meta,
            ..
        } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
            for (_, property, _) in properties {
                analyze_schema_enums(property, analysis);
            }
            match additional_properties {
                AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) => {
                    analyze_schema_enums(schema, analysis);
                }
                AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => {}
            }
        }
        SchemaNode::Array { items, meta } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
            analyze_schema_enums(items, analysis);
        }
        SchemaNode::Tuple {
            prefix_items,
            rest,
            meta,
        } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
            for item in prefix_items {
                analyze_schema_enums(item, analysis);
            }
            if let TupleRest::Schema(schema) = rest {
                analyze_schema_enums(schema, analysis);
            }
        }
        SchemaNode::AllOf { branches, meta }
        | SchemaNode::AnyOf { branches, meta }
        | SchemaNode::OneOf { branches, meta, .. } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
            for branch in branches {
                analyze_schema_enums(branch, analysis);
            }
        }
        SchemaNode::Ref { meta, .. }
        | SchemaNode::Any { meta }
        | SchemaNode::Never { meta }
        | SchemaNode::Unknown { meta, .. } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
        }
    }
}

fn analyze_finite_values(
    ty: Option<PrimitiveType>,
    enum_values: Option<&[Value]>,
    const_value: Option<&Value>,
    meta: &SchemaMeta,
    analysis: &mut EnumAnalysis<'_, '_>,
) {
    let extension_values =
        validate_enum_extensions(enum_values, meta, analysis.types, analysis.sink);
    if let Some(values) = enum_values {
        if values.is_empty() {
            enum_error(meta, "enum must contain at least one member", analysis.sink);
        }
        if let Some(ty) = ty {
            validate_value_domain(values, ty, meta, "enum", analysis.sink);
        }
        validate_numeric_members(values, meta, true, analysis.sink);
    }
    if let Some(value) = const_value {
        if let Some(ty) = ty {
            validate_value_domain(
                std::slice::from_ref(value),
                ty,
                meta,
                "const",
                analysis.sink,
            );
        }
        validate_numeric_members(std::slice::from_ref(value), meta, false, analysis.sink);
    }

    let selected = finite_intersection(enum_values, const_value);
    let Some(selected) = selected else {
        if enum_values.is_some() && const_value.is_some() {
            enum_error(
                meta,
                "enum and const have an empty intersection",
                analysis.sink,
            );
        }
        return;
    };
    if selected.is_empty() {
        return;
    }
    if analysis.types.enum_representation != EnumRepresentation::Const {
        return;
    }

    let mut members = Vec::new();
    let mut seen = HashMap::new();
    for value in selected {
        let enum_index = enum_values.and_then(|values| {
            values
                .iter()
                .position(|candidate| values_equal(candidate, value))
        });
        let explicit_name = match (&extension_values.names, enum_index) {
            (Some(names), Some(index)) => names.get(index),
            _ => None,
        };
        let name_result = match explicit_name {
            Some(name) => validate_explicit_enum_name(name.clone()),
            None => derive_enum_member_name(value, analysis.naming.enum_member_case),
        };
        let name = match name_result {
            Ok(name) => name,
            Err(error) => {
                enum_error(
                    meta,
                    format!("invalid enum member name: {error}"),
                    analysis.sink,
                );
                continue;
            }
        };
        let (folded, collision) = casefold_collision(&name, &seen, |previous| {
            format!("enum member names '{previous}' and '{name}' collide after case folding")
        });
        seen.insert(folded, name.clone());
        if let Some(message) = collision {
            enum_error(meta, message, analysis.sink);
        }
        let description = extension_values
            .descriptions
            .as_ref()
            .and_then(|descriptions| {
                enum_index
                    .and_then(|index| descriptions.get(index))
                    .cloned()
            });
        members.push(EnumMember {
            name,
            value: value.clone(),
            description,
        });
    }
    analysis.tables.push(EnumMemberTable {
        source: meta.source.clone(),
        members,
    });
}

#[derive(Default)]
struct ValidatedExtensions {
    names: Option<Vec<String>>,
    descriptions: Option<Vec<String>>,
}

fn validate_enum_extensions(
    enum_values: Option<&[Value]>,
    meta: &SchemaMeta,
    types: &TypesConfig,
    sink: &mut DiagnosticSink,
) -> ValidatedExtensions {
    let enum_ext = meta.enum_extensions();
    let extensions = [
        ("x-enum-varnames", enum_ext.enum_varnames.as_ref()),
        ("x-enumNames", enum_ext.enum_names.as_ref()),
        ("x-enum-descriptions", enum_ext.enum_descriptions.as_ref()),
        (
            "x-enumDescriptions",
            enum_ext.enum_descriptions_camel.as_ref(),
        ),
    ];
    if types.enum_extensions == EnumExtensions::Reject {
        for (name, value) in extensions {
            if value.is_some() {
                enum_error(
                    meta,
                    format!("enum extension '{name}' is rejected by config"),
                    sink,
                );
            }
        }
        return ValidatedExtensions::default();
    }

    let expected_len = enum_values.map_or(0, <[Value]>::len);
    let first_names = validate_extension_array(
        "x-enum-varnames",
        enum_ext.enum_varnames.as_ref(),
        expected_len,
        meta,
        sink,
    );
    let second_names = validate_extension_array(
        "x-enumNames",
        enum_ext.enum_names.as_ref(),
        expected_len,
        meta,
        sink,
    );
    let first_descriptions = validate_extension_array(
        "x-enum-descriptions",
        enum_ext.enum_descriptions.as_ref(),
        expected_len,
        meta,
        sink,
    );
    let second_descriptions = validate_extension_array(
        "x-enumDescriptions",
        enum_ext.enum_descriptions_camel.as_ref(),
        expected_len,
        meta,
        sink,
    );
    if let (Some(left), Some(right)) = (&first_names, &second_names)
        && left != right
    {
        enum_error(meta, "x-enum-varnames and x-enumNames disagree", sink);
    }
    if let (Some(left), Some(right)) = (&first_descriptions, &second_descriptions)
        && left != right
    {
        enum_error(
            meta,
            "x-enum-descriptions and x-enumDescriptions disagree",
            sink,
        );
    }
    let names = first_names.or(second_names);
    if let Some(names) = &names {
        validate_explicit_name_set(names, meta, sink);
    }
    ValidatedExtensions {
        names,
        descriptions: first_descriptions.or(second_descriptions),
    }
}

fn validate_extension_array(
    name: &str,
    value: Option<&Value>,
    expected_len: usize,
    meta: &SchemaMeta,
    sink: &mut DiagnosticSink,
) -> Option<Vec<String>> {
    let value = value?;
    let Some(array) = value.as_array() else {
        enum_error(
            meta,
            format!("enum extension '{name}' must be an array"),
            sink,
        );
        return None;
    };
    if array.len() != expected_len {
        enum_error(
            meta,
            format!(
                "enum extension '{name}' has length {}, expected {expected_len}",
                array.len()
            ),
            sink,
        );
        return None;
    }
    let Some(strings) = array.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
        enum_error(
            meta,
            format!("enum extension '{name}' must contain only strings"),
            sink,
        );
        return None;
    };
    Some(strings.into_iter().map(str::to_owned).collect())
}

fn validate_explicit_name_set(names: &[String], meta: &SchemaMeta, sink: &mut DiagnosticSink) {
    let mut seen = HashMap::new();
    for name in names {
        if let Err(error) = validate_explicit_enum_name(name.clone()) {
            enum_error(
                meta,
                format!("invalid explicit enum member name '{name}': {error}"),
                sink,
            );
        }
        let (folded, collision) = casefold_collision(name, &seen, |_| {
            format!("explicit enum member name '{name}' collides after case folding")
        });
        seen.insert(folded, ());
        if let Some(message) = collision {
            enum_error(meta, message, sink);
        }
    }
}

fn validate_explicit_enum_name(name: String) -> Result<String, NormalizeError> {
    if let Some(character) = name.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    validate_final_identifier(&name)?;
    Ok(name)
}

fn validate_value_domain(
    values: &[Value],
    ty: PrimitiveType,
    meta: &SchemaMeta,
    keyword: &str,
    sink: &mut DiagnosticSink,
) {
    for value in values {
        if !value_in_domain(value, ty, meta.nullable) {
            let mut message = format!(
                "{keyword} member {} contradicts declared type {ty:?}",
                compact_json(value)
            );
            if value.is_boolean() && ty == PrimitiveType::String {
                message.push_str(
                    "; likely a YAML 1.1 boolean coercion (bare off/on/yes/no), quote the value as a string",
                );
            }
            enum_error(meta, message, sink);
        }
    }
}

fn value_in_domain(value: &Value, ty: PrimitiveType, nullable: bool) -> bool {
    if value.is_null() {
        return ty == PrimitiveType::Null || nullable;
    }
    match ty {
        PrimitiveType::String => value.is_string(),
        PrimitiveType::Number => value.is_number(),
        PrimitiveType::Integer => value.as_number().is_some_and(number_is_integer),
        PrimitiveType::Boolean => value.is_boolean(),
        PrimitiveType::Null => false,
    }
}

fn number_is_integer(number: &Number) -> bool {
    number.is_i64()
        || number.is_u64()
        || number
            .as_f64()
            .is_some_and(|value| value.is_finite() && value.fract() == 0.0)
}

fn validate_numeric_members(
    values: &[Value],
    meta: &SchemaMeta,
    detect_collisions: bool,
    sink: &mut DiagnosticSink,
) {
    let mut seen = HashMap::new();
    for value in values {
        validate_numeric_value(value, meta, detect_collisions, &mut seen, sink);
    }
}

fn validate_numeric_value(
    value: &Value,
    meta: &SchemaMeta,
    detect_collision: bool,
    seen: &mut HashMap<u64, String>,
    sink: &mut DiagnosticSink,
) {
    match value {
        Value::Number(number) => {
            let raw = number.to_string();
            let Some(binary64) = number.as_f64().filter(|value| value.is_finite()) else {
                enum_error(
                    meta,
                    format!("numeric member {raw} is outside the binary64 domain"),
                    sink,
                );
                return;
            };
            let original =
                Decimal::parse(&raw).expect("serde_json number rendering is valid decimal");
            if original.negative_zero {
                enum_error(meta, "numeric enum member -0 is not representable", sink);
                return;
            }
            let rendered = render_number(binary64);
            if Decimal::parse(&rendered).as_ref() != Some(&original) {
                enum_error(
                    meta,
                    format!(
                        "numeric member {raw} does not round-trip through binary64 (renders as {rendered})"
                    ),
                    sink,
                );
            }
            if detect_collision {
                let bits = binary64.to_bits();
                if let Some(previous) = seen.insert(bits, raw.clone()) {
                    enum_error(
                        meta,
                        format!(
                            "numeric members {previous} and {raw} collide after binary64 conversion"
                        ),
                        sink,
                    );
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_numeric_value(value, meta, false, seen, sink);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_numeric_value(value, meta, false, seen, sink);
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn finite_intersection<'a>(
    enum_values: Option<&'a [Value]>,
    const_value: Option<&'a Value>,
) -> Option<Vec<&'a Value>> {
    match (enum_values, const_value) {
        (None, None) => Some(Vec::new()),
        (Some(values), None) => Some(values.iter().collect()),
        (None, Some(value)) => Some(vec![value]),
        (Some(values), Some(value)) => values
            .iter()
            .any(|candidate| values_equal(candidate, value))
            .then(|| vec![value]),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            Decimal::parse(&left.to_string()) == Decimal::parse(&right.to_string())
        }
        _ => left == right,
    }
}

fn derive_enum_member_name(
    value: &Value,
    enum_case: EnumMemberCase,
) -> Result<String, NormalizeError> {
    let tokens = match value {
        Value::String(value) => {
            let mut tokens = identifier_tokens(value)?;
            if value.is_empty() {
                tokens.push("Empty".to_owned());
            } else if tokens.is_empty() {
                return Err(NormalizeError::Empty);
            }
            if tokens
                .first()
                .and_then(|token| token.bytes().next())
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                tokens.insert(0, "Value".to_owned());
            }
            tokens
        }
        Value::Number(number) => numeric_name_tokens(number)?,
        Value::Bool(true) => vec!["True".to_owned()],
        Value::Bool(false) => vec!["False".to_owned()],
        Value::Null => vec!["Null".to_owned()],
        Value::Array(_) | Value::Object(_) => return Err(NormalizeError::Empty),
    };
    let case = match enum_case {
        EnumMemberCase::Pascal => TargetCase::Pascal,
        EnumMemberCase::Camel => TargetCase::Camel,
        EnumMemberCase::ScreamingSnake => TargetCase::ScreamingSnake,
        EnumMemberCase::Preserve => TargetCase::Preserve,
    };
    let name = transform_tokens(&tokens, case);
    validate_normalized_identifier(&name)?;
    Ok(name)
}

fn numeric_name_tokens(number: &Number) -> Result<Vec<String>, NormalizeError> {
    let value = number
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or(NormalizeError::NumericDomain)?;
    let rendered = render_number(value);
    let mut tokens = vec!["Value".to_owned()];
    let mut chars = rendered.chars().peekable();
    if chars.peek() == Some(&'-') {
        chars.next();
        tokens.push("Negative".to_owned());
    }
    let mut digits = String::new();
    while let Some(character) = chars.next() {
        match character {
            '.' => {
                push_digits(&mut tokens, &mut digits);
                tokens.push("Point".to_owned());
            }
            'e' => {
                push_digits(&mut tokens, &mut digits);
                tokens.push("Exponent".to_owned());
                if chars
                    .next()
                    .expect("rendered exponents include an explicit sign")
                    == '-'
                {
                    tokens.push("Negative".to_owned());
                } else {
                    tokens.push("Positive".to_owned());
                }
            }
            digit => digits.push(digit),
        }
    }
    push_digits(&mut tokens, &mut digits);
    Ok(tokens)
}

fn push_digits(tokens: &mut Vec<String>, digits: &mut String) {
    if !digits.is_empty() {
        tokens.push(std::mem::take(digits));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Decimal {
    negative: bool,
    digits: String,
    exponent: i64,
    negative_zero: bool,
}

impl Decimal {
    fn parse(input: &str) -> Option<Self> {
        let (negative, unsigned) = input
            .strip_prefix('-')
            .map_or((false, input), |unsigned| (true, unsigned));
        let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().ok()?),
            None => (unsigned, 0),
        };
        let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let mut digits = format!("{integer}{fraction}");
        let first_nonzero = digits
            .bytes()
            .position(|digit| digit != b'0')
            .unwrap_or(digits.len());
        digits.drain(..first_nonzero);
        if digits.is_empty() {
            return Some(Self {
                negative: false,
                digits: "0".to_owned(),
                exponent: 0,
                negative_zero: negative,
            });
        }
        let mut adjusted_exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
        while digits.ends_with('0') {
            digits.pop();
            adjusted_exponent = adjusted_exponent.checked_add(1)?;
        }
        Some(Self {
            negative,
            digits,
            exponent: adjusted_exponent,
            negative_zero: false,
        })
    }
}

fn identifier_tokens(input: &str) -> Result<Vec<String>, NormalizeError> {
    let decomposed = input
        .nfkd()
        .filter(|character| get_general_category(*character) != GeneralCategory::NonspacingMark)
        .collect::<String>();
    if let Some(character) = decomposed.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    Ok(decomposed
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
        .map(str::to_owned)
        .collect())
}

fn transform_tokens(tokens: &[String], case: TargetCase) -> String {
    match case {
        TargetCase::Pascal => tokens.iter().map(|token| capitalize_token(token)).collect(),
        TargetCase::Camel => tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                if index == 0 {
                    lowercase_token(token)
                } else {
                    capitalize_token(token)
                }
            })
            .collect(),
        TargetCase::ScreamingSnake => tokens
            .iter()
            .map(|token| token.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join("_"),
        TargetCase::Preserve => tokens.concat(),
    }
}

fn capitalize_token(token: &str) -> String {
    change_first_alphabetic(token, u8::to_ascii_uppercase)
}

fn lowercase_token(token: &str) -> String {
    change_first_alphabetic(token, u8::to_ascii_lowercase)
}

fn change_first_alphabetic(token: &str, transform: fn(&u8) -> u8) -> String {
    let mut bytes = token.as_bytes().to_vec();
    if let Some(character) = bytes.iter_mut().find(|byte| byte.is_ascii_alphabetic()) {
        *character = transform(character);
    }
    String::from_utf8(bytes).expect("ASCII case conversion preserves UTF-8")
}

fn validate_normalized_identifier(identifier: &str) -> Result<(), NormalizeError> {
    if identifier.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if identifier
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return Err(NormalizeError::LeadingDigit);
    }
    if RESERVED_WORDS.contains(&identifier) {
        return Err(NormalizeError::ReservedWord(identifier.to_owned()));
    }
    Ok(())
}

fn validate_final_identifier(identifier: &str) -> Result<(), NormalizeError> {
    if let Some(character) = identifier.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    if let Some(character) = identifier
        .chars()
        .find(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$'))
    {
        return Err(NormalizeError::InvalidIdentifierCharacter(character));
    }
    validate_normalized_identifier(identifier)
}

fn enum_error(meta: &SchemaMeta, message: impl Into<String>, sink: &mut DiagnosticSink) {
    sink.push(source_diagnostic(CODE_ENUM_RULE_14, message, &meta.source));
}

fn source_diagnostic(
    code: &'static str,
    message: impl Into<String>,
    source: &SourceRef,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::input(code, message)
        .with_source(&source.source_id)
        .with_json_pointer(&source.json_pointer);
    if let (Some(line), Some(col)) = (source.line, source.col) {
        diagnostic = diagnostic.with_location(line, col);
    }
    diagnostic
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serializing a JSON value cannot fail")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{EnumExtensions, EnumRepresentation, NameOverrides};
    use crate::diag::Category;
    use crate::ir::{NamedSchema, SchemaDocs, SchemaRef, Segment};

    fn named_schema(name: &str) -> NamedSchema {
        let pointer = format!("/components/schemas/{name}");
        NamedSchema {
            name: name.to_owned(),
            schema: any_schema(&pointer),
            source: source(&pointer),
        }
    }

    fn schema_overrides(entries: &[(&str, &str)]) -> NamingConfig {
        NamingConfig {
            overrides: NameOverrides {
                schemas: entries
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        }
    }

    fn schema_names(analyzed: &Analyzed) -> Vec<&str> {
        analyzed
            .schema_names
            .iter()
            .map(|allocated| allocated.name.as_str())
            .collect()
    }

    fn source(pointer: &str) -> SourceRef {
        SourceRef::new("openapi.yaml", pointer)
    }

    fn any_schema(pointer: &str) -> SchemaNode {
        SchemaNode::Any {
            meta: SchemaMeta {
                source: source(pointer),
                ..SchemaMeta::default()
            },
        }
    }

    fn operation(path: Vec<Segment>) -> Operation {
        Operation {
            method: "get".to_owned(),
            path_template: path,
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
            source: source("/paths/~1test/get"),
        }
    }

    fn segment(parts: Vec<SegmentPart>) -> Segment {
        Segment { parts }
    }

    #[test]
    fn normalizes_identifier_vectors_in_contract_order() {
        assert_eq!(
            normalize_identifier("Café", TargetCase::Pascal),
            Ok("Cafe".to_owned())
        );
        for rejected in ["λ", "漢字", "pet🐶", "petλ", "\u{0301}", "---"] {
            assert!(normalize_identifier(rejected, TargetCase::Pascal).is_err());
        }
        assert_eq!(
            normalize_identifier("2fast", TargetCase::Pascal),
            Err(NormalizeError::LeadingDigit)
        );
        assert!(matches!(
            normalize_identifier("class", TargetCase::Camel),
            Err(NormalizeError::ReservedWord(_))
        ));
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::Pascal),
            Ok("PetStatus".to_owned())
        );
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::Camel),
            Ok("petStatus".to_owned())
        );
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::ScreamingSnake),
            Ok("PET_STATUS".to_owned())
        );
    }

    #[test]
    fn derives_operation_names_from_mixed_path_parts() {
        let cases = [
            (
                vec![
                    segment(vec![SegmentPart::Literal("pets".to_owned())]),
                    segment(vec![SegmentPart::Param("petId".to_owned())]),
                ],
                "getPetsByPetId",
            ),
            (
                vec![
                    segment(vec![SegmentPart::Literal("reports".to_owned())]),
                    segment(vec![
                        SegmentPart::Param("id".to_owned()),
                        SegmentPart::Literal(".json".to_owned()),
                    ]),
                ],
                "getReportsByIdJson",
            ),
            (Vec::new(), "get"),
            (
                vec![
                    segment(vec![SegmentPart::Literal("files".to_owned())]),
                    segment(vec![
                        SegmentPart::Param("name".to_owned()),
                        SegmentPart::Literal(".tar.gz".to_owned()),
                    ]),
                ],
                "getFilesByNameTarGz",
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(
                derive_operation_name(&operation(path), TargetCase::Camel),
                Ok(expected.to_owned())
            );
        }
    }

    #[test]
    fn allocation_reports_both_collision_locations() {
        let mut first = operation(Vec::new());
        first.operation_id = Some("get-pets".to_owned());
        first.source = source("/paths/~1a/get");
        let mut second = operation(Vec::new());
        second.operation_id = Some("get_pets".to_owned());
        second.source = source("/paths/~1b/get");
        let ir = Ir {
            operations: vec![first, second],
            schemas: vec![
                NamedSchema {
                    name: "Pet".to_owned(),
                    schema: any_schema("/components/schemas/Pet"),
                    source: source("/components/schemas/Pet"),
                },
                NamedSchema {
                    name: "pet".to_owned(),
                    schema: any_schema("/components/schemas/pet"),
                    source: source("/components/schemas/pet"),
                },
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        let messages = sink
            .as_slice()
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|message| {
            message.contains("/paths/~1a/get") && message.contains("/paths/~1b/get")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("/components/schemas/Pet")
                && message.contains("/components/schemas/pet")
        }));
    }

    #[test]
    fn case_fold_only_identifiers_allocate_both_types() {
        // `custom-hostname` -> `CustomHostname` and `customhostname` -> `Customhostname`
        // differ only by the case of one letter, so they are two distinct, legal TypeScript
        // types and both must allocate. Filesystem safety is the path layer's job, not this one.
        let ir = Ir {
            schemas: vec![
                NamedSchema {
                    name: "custom-hostname".to_owned(),
                    schema: any_schema("/components/schemas/custom-hostname"),
                    source: source("/components/schemas/custom-hostname"),
                },
                NamedSchema {
                    name: "customhostname".to_owned(),
                    schema: any_schema("/components/schemas/customhostname"),
                    source: source("/components/schemas/customhostname"),
                },
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let names = analyzed
            .schema_names
            .iter()
            .map(|allocated| allocated.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["CustomHostname", "Customhostname"]);
    }

    #[test]
    fn schema_override_resolves_a_real_collision_into_distinct_names() {
        // `stream_liveInput` and `stream_live_input` both normalize to `StreamLiveInput`; the
        // override on the first disambiguates so both declarations allocate.
        let ir = Ir {
            schemas: vec![
                named_schema("stream_liveInput"),
                named_schema("stream_live_input"),
            ],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("stream_liveInput", "StreamLiveInputId")]);
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            schema_names(&analyzed),
            ["StreamLiveInputId", "StreamLiveInput"]
        );
    }

    #[test]
    fn schema_override_value_is_validated_like_any_generated_name() {
        let ir = Ir {
            schemas: vec![named_schema("widget")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("widget", "2Bad")]);
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(analyzed.schema_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
            .expect("override value rejection");
        assert!(diagnostic.message.contains("2Bad"));
        assert!(diagnostic.message.contains("begins with a digit"));
    }

    #[test]
    fn two_overrides_colliding_with_each_other_still_report_a_collision() {
        let ir = Ir {
            schemas: vec![named_schema("alpha"), named_schema("beta")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("alpha", "Same"), ("beta", "Same")]);
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_TYPE_NAME
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'Same'")
        }));
    }

    #[test]
    fn override_colliding_with_an_untouched_generated_name_still_collides() {
        // `widget` generates `Widget`; the override forces `other` onto the same identifier.
        let ir = Ir {
            schemas: vec![named_schema("widget"), named_schema("other")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("other", "Widget")]);
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_TYPE_NAME
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'Widget'")
        }));
    }

    #[test]
    fn override_suppresses_type_prefix_and_suffix() {
        let ir = Ir {
            schemas: vec![named_schema("widget"), named_schema("gadget")],
            ..Ir::default()
        };
        let naming = NamingConfig {
            type_prefix: "Api".to_owned(),
            type_suffix: "Dto".to_owned(),
            overrides: NameOverrides {
                schemas: BTreeMap::from([("widget".to_owned(), "Widget".to_owned())]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // The override is the complete identifier; the non-overridden schema still gets affixes.
        assert_eq!(schema_names(&analyzed), ["Widget", "ApiGadgetDto"]);
    }

    #[test]
    fn unmatched_override_keys_are_config_errors_naming_the_key() {
        let ir = Ir {
            schemas: vec![named_schema("widget")],
            ..Ir::default()
        };
        let naming = NamingConfig {
            overrides: NameOverrides {
                schemas: BTreeMap::from([("ghost".to_owned(), "Ghost".to_owned())]),
                operations: BTreeMap::from([("phantomOp".to_owned(), "PhantomOp".to_owned())]),
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);

        let schema_diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == CODE_OVERRIDE_UNMATCHED && diagnostic.message.contains("ghost")
            })
            .expect("unmatched schema override");
        assert_eq!(schema_diagnostic.category, Category::Config);
        assert_eq!(schema_diagnostic.category.exit_code(), 2);
        assert!(schema_diagnostic.message.contains("schema"));
        assert_eq!(
            schema_diagnostic.json_pointer.as_deref(),
            Some("/naming/overrides/schemas/ghost")
        );

        let operation_diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == CODE_OVERRIDE_UNMATCHED
                    && diagnostic.message.contains("phantomOp")
            })
            .expect("unmatched operation override");
        assert_eq!(operation_diagnostic.category, Category::Config);
        assert!(operation_diagnostic.message.contains("operation"));
        assert_eq!(
            operation_diagnostic.json_pointer.as_deref(),
            Some("/naming/overrides/operations/phantomOp")
        );
    }

    #[test]
    fn operation_override_replaces_the_derived_name_verbatim() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("deleteWebhook".to_owned());
        op.source = source("/paths/~1webhooks/delete");
        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: BTreeMap::from([(
                    "deleteWebhook".to_owned(),
                    "DeleteRealtimeKitWebhook".to_owned(),
                )]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(analyzed.operation_names[0].name, "DeleteRealtimeKitWebhook");
    }

    #[test]
    fn operation_override_value_is_validated_like_any_generated_name() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("deleteWebhook".to_owned());
        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: BTreeMap::from([("deleteWebhook".to_owned(), "class".to_owned())]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.operation_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
            .expect("override value rejection");
        assert!(diagnostic.message.contains("class"));
        assert!(diagnostic.message.contains("reserved word"));
    }

    fn enum_schema(
        values: Vec<Value>,
        ty: PrimitiveType,
        extension: Option<Value>,
        pointer: &str,
    ) -> NamedSchema {
        NamedSchema {
            name: pointer.trim_start_matches('/').to_owned(),
            schema: SchemaNode::Primitive {
                ty,
                format: None,
                enum_values: Some(values),
                const_value: None,
                meta: SchemaMeta {
                    docs: SchemaDocs::default(),
                    enum_extensions: crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                        enum_varnames: extension,
                        ..crate::ir::EnumExtensionData::default()
                    }),
                    source: source(pointer),
                    ..SchemaMeta::default()
                },
            },
            source: source(pointer),
        }
    }

    fn const_types() -> TypesConfig {
        TypesConfig {
            enum_representation: EnumRepresentation::Const,
            enum_extensions: EnumExtensions::Accept,
            ..TypesConfig::default()
        }
    }

    #[test]
    fn validates_enum_extensions_and_uses_explicit_names_verbatim() {
        let schemas = vec![
            enum_schema(
                vec![json!("a"), json!("b")],
                PrimitiveType::String,
                Some(json!(["OnlyOne"])),
                "/length",
            ),
            enum_schema(
                vec![json!("a")],
                PrimitiveType::String,
                Some(json!(["λ"])),
                "/nonascii",
            ),
            enum_schema(
                vec![json!("available"), json!("sold")],
                PrimitiveType::String,
                Some(json!(["AvailableWire", "SoldWire"])),
                "/valid",
            ),
        ];
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("length 1, expected 2"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("non-ASCII"))
        );
        assert!(analyzed.enum_members.iter().any(|table| {
            table
                .members
                .iter()
                .map(|member| member.name.as_str())
                .eq(["AvailableWire", "SoldWire"])
        }));
    }

    #[test]
    fn rejects_competing_enum_name_extensions_that_disagree() {
        let mut schema = enum_schema(
            vec![json!("a"), json!("b")],
            PrimitiveType::String,
            Some(json!(["A", "B"])),
            "/competing",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut schema.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["A", "B"])),
                enum_names: Some(json!(["First", "Second"])),
                ..Default::default()
            });
        }
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![schema],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("disagree"))
        );
    }

    #[test]
    fn rejects_numeric_aliases_and_negative_zero() {
        let large = "9007199254740993".parse::<Number>().expect("number");
        let negative_zero = Number::from_f64(-0.0).expect("number");
        let schemas = vec![
            enum_schema(
                vec![Value::Number(large)],
                PrimitiveType::Integer,
                None,
                "/large",
            ),
            enum_schema(
                vec![Value::Number(negative_zero)],
                PrimitiveType::Integer,
                None,
                "/negative-zero",
            ),
        ];
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("does not round-trip"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("-0"))
        );
    }

    #[test]
    fn intersects_enum_const_and_nullable_domains() {
        let mut mismatch = enum_schema(vec![json!("a")], PrimitiveType::String, None, "/mismatch");
        if let SchemaNode::Primitive { const_value, .. } = &mut mismatch.schema {
            *const_value = Some(json!("b"));
        }
        let mut nullable = enum_schema(vec![json!("a")], PrimitiveType::String, None, "/nullable");
        if let SchemaNode::Primitive { meta, .. } = &mut nullable.schema {
            meta.nullable = true;
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![mismatch, nullable],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("empty intersection"))
        );
        let nullable_table = analyzed
            .enum_members
            .iter()
            .find(|table| table.source.json_pointer == "/nullable")
            .expect("nullable enum table");
        assert_eq!(nullable_table.members.len(), 1);
        assert_eq!(nullable_table.members[0].value, json!("a"));
    }

    #[test]
    fn derives_specialized_const_member_names() {
        let cases = [
            (json!(""), PrimitiveType::String, "Empty"),
            (json!("2x"), PrimitiveType::String, "Value2X"),
            (json!(1.5), PrimitiveType::Number, "Value1Point5"),
            (json!(-2), PrimitiveType::Integer, "ValueNegative2"),
            (
                json!(1e21),
                PrimitiveType::Number,
                "Value1ExponentPositive21",
            ),
        ];
        for (index, (value, ty, expected)) in cases.into_iter().enumerate() {
            let schema = enum_schema(vec![value], ty, None, &format!("/case-{index}"));
            let mut sink = DiagnosticSink::new();
            let analyzed = analyze_with_options(
                Ir {
                    operations: Vec::new(),
                    schemas: vec![schema],
                    ..Ir::default()
                },
                &NamingConfig::default(),
                &const_types(),
                &mut sink,
            );
            assert!(!sink.has_errors(), "{:?}", sink.as_slice());
            assert_eq!(analyzed.enum_members[0].members[0].name, expected);
        }
    }

    #[test]
    fn normalization_errors_and_remaining_case_modes_are_explicit() {
        let errors = [
            NormalizeError::NonAscii('λ'),
            NormalizeError::Empty,
            NormalizeError::LeadingDigit,
            NormalizeError::ReservedWord("class".to_owned()),
            NormalizeError::InvalidIdentifierCharacter('-'),
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(
            normalize_identifier("---", TargetCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            normalize_identifier("pet status", TargetCase::Preserve),
            Ok("petstatus".to_owned())
        );
        assert_eq!(
            validate_final_identifier("bad-name"),
            Err(NormalizeError::InvalidIdentifierCharacter('-'))
        );
        assert!(matches!(
            validate_final_identifier("λ"),
            Err(NormalizeError::NonAscii('λ'))
        ));
        assert_eq!(capitalize_token("123"), "123");
    }

    #[test]
    fn allocation_rejects_invalid_operation_and_schema_names() {
        let mut invalid_operation = operation(Vec::new());
        invalid_operation.operation_id = Some("---".to_owned());
        let ir = Ir {
            operations: vec![invalid_operation],
            schemas: vec![NamedSchema {
                name: "---".to_owned(),
                schema: any_schema("/invalid"),
                source: source("/invalid"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.operation_names.is_empty());
        assert!(analyzed.schema_names.is_empty());
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
        );
    }

    #[test]
    fn preserve_operation_names_and_empty_member_tokens_are_covered() {
        let mut named = operation(Vec::new());
        named.operation_id = Some("Pet_Name".to_owned());
        let naming = NamingConfig {
            operation_case: OperationCase::Preserve,
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![named],
                schemas: Vec::new(),
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.operation_names[0].name, "PetName");
        assert_eq!(
            derive_enum_member_name(&json!("---"), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            validate_normalized_identifier(""),
            Err(NormalizeError::Empty)
        );
    }

    #[test]
    fn enum_analysis_walks_every_schema_container() {
        let leaf = any_schema("/leaf");
        let meta = SchemaMeta {
            source: source("/container"),
            ..SchemaMeta::default()
        };
        let schemas = vec![
            SchemaNode::Object {
                properties: Vec::new(),
                additional_properties: AdditionalProperties::Allowed(Some(Box::new(leaf.clone()))),
                dependent_required: Vec::new(),
                meta: meta.clone(),
            },
            SchemaNode::Tuple {
                prefix_items: vec![leaf.clone()],
                rest: TupleRest::Schema(Box::new(leaf.clone())),
                meta: meta.clone(),
            },
            SchemaNode::AllOf {
                branches: vec![leaf.clone()],
                meta: meta.clone(),
            },
            SchemaNode::AnyOf {
                branches: vec![leaf.clone()],
                meta: meta.clone(),
            },
            SchemaNode::OneOf {
                branches: vec![leaf.clone()],
                discriminator: None,
                meta: meta.clone(),
            },
            SchemaNode::Ref {
                target: SchemaRef {
                    source_id: "openapi.yaml".to_owned(),
                    json_pointer: "/target".to_owned(),
                },
                meta: meta.clone(),
            },
            SchemaNode::Never { meta: meta.clone() },
            SchemaNode::Unknown {
                reason: "test".to_owned(),
                meta,
            },
        ];
        let named = schemas
            .into_iter()
            .enumerate()
            .map(|(index, schema)| NamedSchema {
                name: format!("Schema{index}"),
                schema,
                source: source(&format!("/schema/{index}")),
            })
            .collect();
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: named,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names.len(), 8);
        assert!(!sink.has_errors());
    }

    #[test]
    fn enum_extension_validation_covers_rejection_shapes_and_collisions() {
        let mut meta = SchemaMeta {
            source: source("/enum"),
            ..SchemaMeta::default()
        };
        let set_ext = |meta: &mut SchemaMeta, ext: crate::ir::EnumExtensionData| {
            meta.enum_extensions = crate::ir::box_if_populated(ext);
        };
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["One"])),
                ..Default::default()
            },
        );
        let mut rejected_types = const_types();
        rejected_types.enum_extensions = EnumExtensions::Reject;
        let mut sink = DiagnosticSink::new();
        let rejected =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &rejected_types, &mut sink);
        assert!(rejected.names.is_none());

        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!("not-an-array")),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!([7])),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["Same", "same"])),
                enum_names: Some(json!(["Same", "same"])),
                enum_descriptions: Some(json!(["first", "second"])),
                enum_descriptions_camel: Some(json!(["one", "two"])),
            },
        );
        let validated = validate_enum_extensions(
            Some(&[json!(1), json!(2)]),
            &meta,
            &const_types(),
            &mut sink,
        );
        assert_eq!(validated.names.expect("names").len(), 2);

        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["bad-name"])),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        assert!(sink.as_slice().len() >= 6);
    }

    #[test]
    fn finite_value_validation_covers_empty_domains_names_and_descriptions() {
        let mut empty = enum_schema(Vec::new(), PrimitiveType::String, None, "/empty");
        let mut collision = enum_schema(
            vec![json!("a-b"), json!("a_b")],
            PrimitiveType::String,
            None,
            "/collision",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut collision.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_descriptions: Some(json!(["first", "second"])),
                ..Default::default()
            });
        }
        let mut contradiction = enum_schema(
            vec![json!(1), Value::Null],
            PrimitiveType::String,
            None,
            "/contradiction",
        );
        if let SchemaNode::Primitive { const_value, .. } = &mut contradiction.schema {
            *const_value = Some(json!(1));
        }
        if let SchemaNode::Primitive { const_value, .. } = &mut empty.schema {
            *const_value = Some(json!("only"));
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![empty, collision, contradiction],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(!analyzed.enum_members.is_empty());
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("at least one"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("collide"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("contradicts"))
        );
    }

    #[test]
    fn domain_violation_names_the_yaml_cause_only_for_booleans_under_string() {
        let meta = SchemaMeta {
            source: source("/yaml-bug"),
            ..SchemaMeta::default()
        };
        let mut sink = DiagnosticSink::new();
        validate_value_domain(
            &[json!(false), json!("redaction")],
            PrimitiveType::String,
            &meta,
            "enum",
            &mut sink,
        );
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.message.contains("contradicts declared type")
                && diagnostic.message.contains("YAML 1.1")
                && diagnostic.message.contains("quote the value as a string")
        }));

        let meta = SchemaMeta {
            source: source("/non-boolean"),
            ..SchemaMeta::default()
        };
        let mut sink = DiagnosticSink::new();
        validate_value_domain(&[json!(1)], PrimitiveType::String, &meta, "enum", &mut sink);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.message.contains("contradicts declared type")
                && !diagnostic.message.contains("YAML")
        }));
    }

    #[test]
    fn value_numeric_and_intersection_helpers_cover_boundaries() {
        assert!(value_in_domain(&Value::Null, PrimitiveType::Null, false));
        assert!(value_in_domain(&Value::Null, PrimitiveType::String, true));
        assert!(!value_in_domain(&json!("x"), PrimitiveType::Null, false));
        assert!(value_in_domain(&json!("x"), PrimitiveType::String, false));
        assert!(value_in_domain(&json!(1.5), PrimitiveType::Number, false));
        assert!(value_in_domain(&json!(1.0), PrimitiveType::Integer, false));
        assert!(!value_in_domain(&json!(1.5), PrimitiveType::Integer, false));
        assert!(value_in_domain(&json!(true), PrimitiveType::Boolean, false));

        assert_eq!(finite_intersection(None, None), Some(Vec::new()));
        let one = json!(1);
        let two = json!(2);
        assert_eq!(finite_intersection(None, Some(&one)), Some(vec![&one]));
        assert_eq!(
            finite_intersection(Some(std::slice::from_ref(&one)), None),
            Some(vec![&one])
        );
        assert_eq!(
            finite_intersection(Some(std::slice::from_ref(&one)), Some(&two)),
            None
        );
        assert!(values_equal(&json!(1), &json!(1.0)));
        assert!(!values_equal(&json!(1), &json!(2)));

        let mut sink = DiagnosticSink::new();
        let collision_values = [
            json!(9_007_199_254_740_992_u64),
            json!(9_007_199_254_740_993_u64),
        ];
        validate_numeric_members(
            &collision_values,
            &SchemaMeta {
                source: source("/numbers"),
                ..SchemaMeta::default()
            },
            true,
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("collide"))
        );

        let outside_binary64 = "1e999"
            .parse::<Number>()
            .expect("arbitrary-precision JSON number");
        let mut domain_sink = DiagnosticSink::new();
        validate_numeric_members(
            &[Value::Number(outside_binary64.clone())],
            &SchemaMeta {
                source: source("/outside-binary64"),
                ..SchemaMeta::default()
            },
            true,
            &mut domain_sink,
        );
        assert!(domain_sink.as_slice().iter().any(|diagnostic| {
            diagnostic.message == "numeric member 1e+999 is outside the binary64 domain"
        }));
        let error = numeric_name_tokens(&outside_binary64).expect_err("outside binary64 domain");
        assert_eq!(error, NormalizeError::NumericDomain);
        assert_eq!(
            error.to_string(),
            "numeric value is outside the binary64 domain"
        );
    }

    #[test]
    fn member_name_decimal_and_source_helpers_cover_edge_cases() {
        for (value, expected) in [
            (json!(true), "True"),
            (json!(false), "False"),
            (Value::Null, "Null"),
        ] {
            assert_eq!(
                derive_enum_member_name(&value, EnumMemberCase::Pascal),
                Ok(expected.to_owned())
            );
        }
        assert_eq!(
            derive_enum_member_name(&json!([]), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            derive_enum_member_name(&json!({}), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert!(derive_enum_member_name(&json!("λ"), EnumMemberCase::Pascal).is_err());
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::Camel),
            Ok("twoWords".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::ScreamingSnake),
            Ok("TWO_WORDS".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::Preserve),
            Ok("twowords".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!(1e-7), EnumMemberCase::Pascal),
            Ok("Value1ExponentNegative7".to_owned())
        );

        assert_eq!(Decimal::parse("bad"), None);
        assert_eq!(Decimal::parse("1eBAD"), None);
        assert_eq!(Decimal::parse("1200").expect("decimal").exponent, 2);
        assert!(Decimal::parse("-0").expect("negative zero").negative_zero);

        let located = SourceRef {
            source_id: "openapi.yaml".to_owned(),
            json_pointer: "/value".to_owned(),
            line: Some(3),
            col: Some(5),
        };
        let diagnostic = source_diagnostic("TEST", "message", &located);
        assert_eq!((diagnostic.line, diagnostic.col), (Some(3), Some(5)));
        assert_eq!(compact_json(&json!({ "x": 1 })), "{\"x\":1}");
    }
}
