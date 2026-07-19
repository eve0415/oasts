//! Deterministic TypeScript types artifact emission.
//!
//! A named, direct object becomes an `interface`; every other named schema is
//! a `type`. This deliberately small rule keeps declaration form independent
//! of formatting details. OpenAPI's omitted/`true` `additionalProperties`
//! remains open without an index signature: `[key: string]: unknown` would
//! force every declared property to be assignable to `unknown` today and to a
//! narrower value if that signature ever changed, so it does not faithfully
//! describe the declared members.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::config::{DocumentationConfig, EnumRepresentation, FileCase, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, ExclusiveBound, MediaType, NumericConstraints, Operation, Param,
    ParamLocation, PrimitiveType, PropMeta, ResponseEntry, ResponseStatus, SchemaDocs, SchemaNode,
    SourceRef, TupleRest,
};
use crate::num::render_number;
use crate::semantic::{AllocatedSchemaName, Analyzed, EnumMember};

const CODE_FILE_NAME: &str = "OASTS1301";
const CODE_PATH_COLLISION: &str = "OASTS1302";
const CODE_COMPOSITION: &str = "OASTS1303";
const CODE_DISCRIMINATOR: &str = "OASTS1304";
const CODE_REFERENCE: &str = "OASTS1305";

type OwnedProperties = Vec<(String, SchemaNode, PropMeta)>;

/// One deterministic, not-yet-written generated artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFile {
    /// Output-root-relative path using `/` separators.
    pub relative_path: String,
    pub content: String,
}

/// Computes the per-spec source digest.
#[must_use]
pub fn source_digest(source_tuples: &[(String, [u8; 32])]) -> String {
    let mut tuples = source_tuples.to_vec();
    tuples.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut hasher = Sha256::new();
    hasher.update(b"oasts-src-v1\0");
    hasher.update(
        u64::try_from(tuples.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (source_id, document_digest) in tuples {
        hasher.update(
            u64::try_from(source_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(source_id.as_bytes());
        hasher.update(document_digest);
    }
    lower_hex(&hasher.finalize())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// File-name validation failure for a declaration name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileNameError {
    Empty,
    UnsafePath,
    ReservedDevice,
    UnsafeCharacter(char),
}

impl fmt::Display for FileNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("file name is empty"),
            Self::UnsafePath => formatter.write_str("file name is absolute or contains traversal"),
            Self::ReservedDevice => formatter.write_str("file name is a Windows reserved device"),
            Self::UnsafeCharacter(character) => write!(
                formatter,
                "file name contains unsafe character '{}'",
                character.escape_default()
            ),
        }
    }
}

impl std::error::Error for FileNameError {}

/// Derives a safe base name from an already-approved declaration identifier.
pub fn file_base_name(name: &str, case: FileCase) -> Result<String, FileNameError> {
    if has_unsafe_path(name) {
        return Err(FileNameError::UnsafePath);
    }
    if is_reserved_device(name) {
        return Err(FileNameError::ReservedDevice);
    }
    let tokens = source_name_tokens(name)?;
    if tokens.is_empty() {
        return Err(FileNameError::Empty);
    }
    let candidate = match case {
        FileCase::Kebab => tokens
            .iter()
            .map(|token| token.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("-"),
        FileCase::Snake => tokens
            .iter()
            .map(|token| token.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("_"),
        FileCase::Camel => tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                if index == 0 {
                    lowercase_first(token)
                } else {
                    uppercase_first(token)
                }
            })
            .collect(),
        FileCase::Pascal => tokens.iter().map(|token| uppercase_first(token)).collect(),
        FileCase::Preserve => tokens.join("-"),
    };
    validate_file_base(&candidate)?;
    Ok(candidate)
}

fn source_name_tokens(name: &str) -> Result<Vec<String>, FileNameError> {
    let decomposed = name
        .nfkd()
        .filter(|character| get_general_category(*character) != GeneralCategory::NonspacingMark)
        .collect::<String>();
    if let Some(character) = decomposed.chars().find(|character| !character.is_ascii()) {
        return Err(FileNameError::UnsafeCharacter(character));
    }
    Ok(decomposed
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
        .map(str::to_owned)
        .collect())
}

fn lowercase_first(token: &str) -> String {
    change_first_ascii_letter(token, u8::to_ascii_lowercase)
}

fn uppercase_first(token: &str) -> String {
    change_first_ascii_letter(token, u8::to_ascii_uppercase)
}

fn change_first_ascii_letter(token: &str, transform: fn(&u8) -> u8) -> String {
    let mut bytes = token.as_bytes().to_vec();
    if let Some(byte) = bytes.iter_mut().find(|byte| byte.is_ascii_alphabetic()) {
        *byte = transform(byte);
    }
    String::from_utf8(bytes).expect("transforming ASCII letters preserves UTF-8")
}

fn validate_file_base(candidate: &str) -> Result<(), FileNameError> {
    if candidate.is_empty() {
        return Err(FileNameError::Empty);
    }
    if has_unsafe_path(candidate) {
        return Err(FileNameError::UnsafePath);
    }
    if is_reserved_device(candidate) {
        return Err(FileNameError::ReservedDevice);
    }
    if let Some(character) = candidate
        .chars()
        .find(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-'))
    {
        return Err(FileNameError::UnsafeCharacter(character));
    }
    Ok(())
}

fn has_unsafe_path(value: &str) -> bool {
    matches!(value, "." | "..")
        || value.starts_with(['/', '\\'])
        || value.contains(['/', '\\'])
        || value.as_bytes().get(1) == Some(&b':')
}

fn is_reserved_device(value: &str) -> bool {
    let device = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(device.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || reserved_numbered_device(&device, "COM")
        || reserved_numbered_device(&device, "LPT")
}

fn reserved_numbered_device(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

/// Emits all component and operation type files in deterministic path order.
pub fn emit_types(
    analyzed: &Analyzed,
    config: &ResolvedConfig,
    source_tuples: &[(String, [u8; 32])],
    sink: &mut DiagnosticSink,
) -> Vec<GeneratedFile> {
    Emitter::new(analyzed, config, source_digest(source_tuples), sink).emit()
}

/// Short alias used by artifact pipelines that already selected `types`.
pub fn emit(
    analyzed: &Analyzed,
    config: &ResolvedConfig,
    source_tuples: &[(String, [u8; 32])],
    sink: &mut DiagnosticSink,
) -> Vec<GeneratedFile> {
    emit_types(analyzed, config, source_tuples, sink)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TypePosition {
    Neutral,
    Request,
    Response,
}

#[derive(Clone, Copy)]
enum SchemaChildMode {
    Validation,
    References(TypePosition),
}

#[derive(Clone, Debug)]
struct SchemaTarget {
    index: usize,
    name: String,
    file_base: String,
    request_differs: bool,
    response_differs: bool,
}

struct Emitter<'model, 'sink> {
    analyzed: &'model Analyzed,
    config: &'model ResolvedConfig,
    digest: String,
    schema_targets: HashMap<String, HashMap<String, SchemaTarget>>,
    enum_member_indices: BTreeMap<(String, String), usize>,
    component_files: Vec<Option<String>>,
    operation_files: Vec<Option<String>>,
    sink: &'sink mut DiagnosticSink,
}

impl<'model, 'sink> Emitter<'model, 'sink> {
    fn new(
        analyzed: &'model Analyzed,
        config: &'model ResolvedConfig,
        digest: String,
        sink: &'sink mut DiagnosticSink,
    ) -> Self {
        let mut enum_member_indices = BTreeMap::new();
        for (index, table) in analyzed.enum_members.iter().enumerate() {
            enum_member_indices
                .entry((
                    table.source.source_id.clone(),
                    table.source.json_pointer.clone(),
                ))
                .or_insert(index);
        }
        let mut emitter = Self {
            analyzed,
            config,
            digest,
            schema_targets: HashMap::new(),
            enum_member_indices,
            component_files: vec![None; analyzed.ir.schemas.len()],
            operation_files: vec![None; analyzed.ir.operations.len()],
            sink,
        };
        emitter.allocate_paths();
        emitter
    }

    fn allocate_paths(&mut self) {
        let mut seen = HashMap::<String, (String, SourceRef)>::new();
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            let Some(file_base) = self.allocate_file_base(&allocated.wire_name, &schema.source)
            else {
                continue;
            };
            let relative = format!("types/components/{file_base}.ts");
            self.report_path_collision(&relative, &schema.source, &mut seen);
            self.component_files[allocated.schema_index] = Some(file_base.clone());
            let (request_differs, response_differs) = shape_variants(&schema.schema);
            self.schema_targets
                .entry(schema.source.source_id.clone())
                .or_default()
                .insert(
                    schema.source.json_pointer.clone(),
                    SchemaTarget {
                        index: allocated.schema_index,
                        name: allocated.name.clone(),
                        file_base,
                        request_differs,
                        response_differs,
                    },
                );
        }
        for allocated in &self.analyzed.operation_names {
            let operation = &self.analyzed.ir.operations[allocated.operation_index];
            let source_name = operation.operation_id.as_deref().unwrap_or(&allocated.name);
            let Some(file_base) = self.allocate_file_base(source_name, &operation.source) else {
                continue;
            };
            let relative = format!("types/operations/{file_base}.ts");
            self.report_path_collision(&relative, &operation.source, &mut seen);
            self.operation_files[allocated.operation_index] = Some(file_base);
        }
    }

    fn allocate_file_base(&mut self, name: &str, source: &SourceRef) -> Option<String> {
        match file_base_name(name, self.config.naming.file_case) {
            Ok(file_base) => Some(file_base),
            Err(error) => {
                self.sink.push(source_diagnostic(
                    CODE_FILE_NAME,
                    format!("invalid generated file name for '{name}': {error}"),
                    source,
                ));
                None
            }
        }
    }

    fn report_path_collision(
        &mut self,
        path: &str,
        source: &SourceRef,
        seen: &mut HashMap<String, (String, SourceRef)>,
    ) {
        let folded = path.to_ascii_lowercase();
        if let Some((previous, previous_source)) = seen.get(&folded) {
            self.sink.push(source_diagnostic(
                CODE_PATH_COLLISION,
                format!(
                    "generated path collision after case folding: '{previous}' at {} and '{path}' at {}",
                    previous_source.display(),
                    source.display()
                ),
                source,
            ));
        } else {
            seen.insert(folded, (path.to_owned(), source.clone()));
        }
    }

    fn schema_target(&self, source_id: &str, json_pointer: &str) -> Option<&SchemaTarget> {
        self.schema_targets.get(source_id)?.get(json_pointer)
    }

    fn emit(mut self) -> Vec<GeneratedFile> {
        self.validate_model();
        let mut files = Vec::new();
        for allocated in &self.analyzed.schema_names {
            if self.component_files[allocated.schema_index].is_none() {
                continue;
            }
            files.push(self.emit_component(allocated));
        }
        for allocated in &self.analyzed.operation_names {
            if self.operation_files[allocated.operation_index].is_none() {
                continue;
            }
            files.push(self.emit_operation(allocated.operation_index, &allocated.name));
        }
        files.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
        files
    }

    fn header(&self) -> String {
        let mut output = format!(
            "// Generated by Oasts {}. Do not edit.\n// Config schema version: 1\n// Source digest: {}\n",
            crate::version(),
            self.digest
        );
        for line in &self.config.emit.banner {
            output.push_str("// ");
            output.push_str(line);
            output.push('\n');
        }
        output.push('\n');
        output
    }

    fn validate_model(&mut self) {
        let mut diagnostics = Vec::new();
        for schema in &self.analyzed.ir.schemas {
            self.validate_schema(&schema.schema, &mut diagnostics);
        }
        for operation in &self.analyzed.ir.operations {
            for parameter in &operation.parameters {
                self.validate_schema(&parameter.schema, &mut diagnostics);
            }
            if let Some(body) = &operation.request_body {
                for media_type in &body.media_types {
                    self.validate_schema(&media_type.schema, &mut diagnostics);
                }
            }
            for response in &operation.responses {
                for media_type in &response.media_types {
                    self.validate_schema(&media_type.schema, &mut diagnostics);
                }
            }
        }
        self.sink.extend(diagnostics);
    }

    fn validate_schema(&self, schema: &SchemaNode, diagnostics: &mut Vec<Diagnostic>) {
        match schema {
            SchemaNode::Ref { target, meta } => {
                if self
                    .schema_target(&target.source_id, &target.json_pointer)
                    .is_none()
                {
                    diagnostics.push(source_diagnostic(
                        CODE_REFERENCE,
                        format!(
                            "schema reference {}#{} has no allocated component type",
                            target.source_id, target.json_pointer
                        ),
                        &meta.source,
                    ));
                }
            }
            SchemaNode::AllOf { branches, meta } => {
                self.validate_all_of(branches, meta, diagnostics);
            }
            SchemaNode::OneOf {
                branches,
                discriminator: Some(discriminator),
                ..
            } => {
                let mut literals = BTreeSet::new();
                let mut reason = None;
                for branch in branches {
                    match self.discriminator_literal(branch, &discriminator.property_name) {
                        Some(literal) if literals.insert(literal.clone()) => {}
                        Some(literal) => {
                            reason = Some(format!(
                                "discriminator property '{}' repeats literal {literal}",
                                discriminator.property_name
                            ));
                            break;
                        }
                        None => {
                            reason = Some(format!(
                                "a branch does not prove one literal for discriminator property '{}'",
                                discriminator.property_name
                            ));
                            break;
                        }
                    }
                }
                if let Some(reason) = reason {
                    diagnostics.push(warning_diagnostic(
                        CODE_DISCRIMINATOR,
                        format!("emitting a structural union because {reason}"),
                        &discriminator.source,
                    ));
                }
            }
            _ => {}
        }
        self.for_each_schema_child(schema, SchemaChildMode::Validation, &mut |child| {
            self.validate_schema(child, diagnostics);
        });
    }

    fn validate_all_of(
        &self,
        branches: &[SchemaNode],
        meta: &crate::ir::SchemaMeta,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        let domains = branches
            .iter()
            .filter_map(|branch| self.primitive_domain(branch, &mut HashSet::new()))
            .collect::<Vec<_>>();
        if domains.len() >= 2 {
            let mut intersection = domains[0].clone();
            for domain in &domains[1..] {
                intersection.retain(|atom| domain.contains(atom));
            }
            if intersection.is_empty() {
                diagnostics.push(source_diagnostic(
                    CODE_COMPOSITION,
                    "allOf has disjoint primitive type sets",
                    &meta.source,
                ));
            }
        }

        let finite_sets = branches
            .iter()
            .filter_map(|branch| self.finite_constraint(branch, &mut HashSet::new()))
            .collect::<Vec<_>>();
        if finite_sets.len() >= 2 {
            let mut intersection = finite_sets[0].clone();
            for values in &finite_sets[1..] {
                intersection.retain(|value| values.iter().any(|other| json_equal(value, other)));
            }
            if intersection.is_empty() {
                diagnostics.push(source_diagnostic(
                    CODE_COMPOSITION,
                    "allOf has incompatible const or finite-enum constraints",
                    &meta.source,
                ));
            }
        }

        let bounds = branches
            .iter()
            .filter_map(|branch| self.numeric_bounds(branch, &mut HashSet::new()))
            .collect::<Vec<_>>();
        if let Some(combined) = bounds.into_iter().reduce(NumericBounds::intersect)
            && combined.is_empty()
        {
            diagnostics.push(source_diagnostic(
                CODE_COMPOSITION,
                "allOf has an empty numeric interval",
                &meta.source,
            ));
        }

        let objects = branches
            .iter()
            .filter_map(|branch| self.object_shape(branch, &mut HashSet::new()))
            .collect::<Vec<_>>();
        let required = objects
            .iter()
            .flat_map(|object| {
                object
                    .properties
                    .iter()
                    .filter(|(_, _, meta)| meta.required)
                    .map(|(name, _, _)| name.clone())
            })
            .collect::<BTreeSet<_>>();
        for object in &objects {
            if object.additional_properties != &AdditionalProperties::Forbidden {
                continue;
            }
            let declared = object
                .properties
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<HashSet<_>>();
            for name in &required {
                if !declared.contains(name.as_str()) {
                    diagnostics.push(source_diagnostic(
                        CODE_COMPOSITION,
                        format!(
                            "allOf requires property '{}' that a closed object branch forbids",
                            name
                        ),
                        &meta.source,
                    ));
                }
            }
        }
    }

    fn resolve_ref<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<&'a SchemaNode> {
        let SchemaNode::Ref { target, .. } = schema else {
            return Some(schema);
        };
        let key = (target.source_id.clone(), target.json_pointer.clone());
        if visited.contains(&key) {
            return None;
        }
        visited.insert(key);
        let target = self.schema_target(&target.source_id, &target.json_pointer)?;
        let resolved = &self.analyzed.ir.schemas.get(target.index)?.schema;
        self.resolve_ref(resolved, visited)
    }

    fn primitive_domain(
        &self,
        schema: &SchemaNode,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<BTreeSet<PrimitiveAtom>> {
        let schema = self.resolve_ref(schema, visited)?;
        match schema {
            SchemaNode::Primitive { ty, meta, .. } => {
                let mut domain = BTreeSet::new();
                match ty {
                    PrimitiveType::String => {
                        domain.insert(PrimitiveAtom::String);
                    }
                    PrimitiveType::Number => {
                        domain.insert(PrimitiveAtom::Number);
                        domain.insert(PrimitiveAtom::Integer);
                    }
                    PrimitiveType::Integer => {
                        domain.insert(PrimitiveAtom::Integer);
                    }
                    PrimitiveType::Boolean => {
                        domain.insert(PrimitiveAtom::Boolean);
                    }
                    PrimitiveType::Null => {
                        domain.insert(PrimitiveAtom::Null);
                    }
                }
                if meta.nullable {
                    domain.insert(PrimitiveAtom::Null);
                }
                Some(domain)
            }
            SchemaNode::AnyOf { branches, .. } | SchemaNode::OneOf { branches, .. } => {
                let mut domain = BTreeSet::new();
                for branch in branches {
                    domain.extend(self.primitive_domain(branch, visited)?);
                }
                Some(domain)
            }
            _ => None,
        }
    }

    fn finite_constraint(
        &self,
        schema: &SchemaNode,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<Vec<Value>> {
        let schema = self.resolve_ref(schema, visited)?;
        let (enum_values, const_value) = match schema {
            SchemaNode::Primitive {
                enum_values,
                const_value,
                ..
            }
            | SchemaNode::Finite {
                enum_values,
                const_value,
                ..
            } => (enum_values, const_value),
            _ => return None,
        };
        finite_values(enum_values.as_deref(), const_value.as_ref())
    }

    fn numeric_bounds(
        &self,
        schema: &SchemaNode,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<NumericBounds> {
        let schema = self.resolve_ref(schema, visited)?;
        let SchemaNode::Primitive { ty, meta, .. } = schema else {
            return None;
        };
        if !matches!(ty, PrimitiveType::Number | PrimitiveType::Integer) {
            return None;
        }
        NumericBounds::from_constraints(&meta.numeric_constraints)
    }

    fn object_shape<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<ObjectShape<'a>> {
        let schema = self.resolve_ref(schema, visited)?;
        let SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } = schema
        else {
            return None;
        };
        Some(ObjectShape {
            properties,
            additional_properties,
        })
    }

    fn discriminator_literal(&self, schema: &SchemaNode, property_name: &str) -> Option<String> {
        let object = self.object_shape(schema, &mut HashSet::new())?;
        let (_, property, _) = object
            .properties
            .iter()
            .find(|(name, _, _)| name == property_name)?;
        let values = self.finite_constraint(property, &mut HashSet::new())?;
        (values.len() == 1).then(|| render_json_compact(&values[0]))
    }

    fn emit_component(&self, allocated: &AllocatedSchemaName) -> GeneratedFile {
        let schema = &self.analyzed.ir.schemas[allocated.schema_index];
        let file_base = self.component_files[allocated.schema_index]
            .as_deref()
            .unwrap_or_default();
        let mut content = self.header();
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        self.collect_component_imports(
            &schema.schema,
            TypePosition::Neutral,
            allocated.schema_index,
            &mut imports,
        );
        let target = self
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .expect("an allocated component file has a schema target");
        let request_differs = target.request_differs;
        let response_differs = target.response_differs;
        if request_differs {
            self.collect_component_imports(
                &schema.schema,
                TypePosition::Request,
                allocated.schema_index,
                &mut imports,
            );
        }
        if response_differs {
            self.collect_component_imports(
                &schema.schema,
                TypePosition::Response,
                allocated.schema_index,
                &mut imports,
            );
        }
        self.write_imports(&mut content, imports, "./");
        self.write_schema_declaration(
            &mut content,
            &allocated.name,
            &schema.schema,
            TypePosition::Neutral,
            &schema.source,
        );
        if request_differs {
            self.write_schema_declaration(
                &mut content,
                &format!("{}Request", allocated.name),
                &schema.schema,
                TypePosition::Request,
                &schema.source,
            );
        }
        if response_differs {
            self.write_schema_declaration(
                &mut content,
                &format!("{}Response", allocated.name),
                &schema.schema,
                TypePosition::Response,
                &schema.source,
            );
        }
        GeneratedFile {
            relative_path: format!("types/components/{file_base}.ts"),
            content,
        }
    }

    fn write_schema_declaration(
        &self,
        output: &mut String,
        name: &str,
        schema: &SchemaNode,
        position: TypePosition,
        source: &SourceRef,
    ) {
        if let Some(values) = schema_finite_values(schema)
            && self.config.types.enum_representation == EnumRepresentation::Const
        {
            let fallback_members;
            let members = if let Some(members) = self.enum_members(schema) {
                members
            } else {
                fallback_members = values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| EnumMember {
                        name: format!("Value{}", index + 1),
                        value: value.clone(),
                        description: None,
                    })
                    .collect::<Vec<_>>();
                &fallback_members
            };
            write_source_metadata(output, source, 0);
            write_schema_tsdoc(
                output,
                &schema.meta().docs,
                DocKind::Schema,
                &self.config.documentation,
                0,
                false,
            );
            output.push_str("export const ");
            output.push_str(name);
            output.push_str(" = {\n");
            for member in members {
                if let Some(description) = &member.description {
                    let docs = SchemaDocs {
                        description: Some(description.clone()),
                        ..SchemaDocs::default()
                    };
                    write_schema_tsdoc(
                        output,
                        &docs,
                        DocKind::Property,
                        &self.config.documentation,
                        2,
                        false,
                    );
                }
                output.push_str("  ");
                output.push_str(&member.name);
                output.push_str(": ");
                output.push_str(&render_ts_value(&member.value));
                output.push_str(",\n");
            }
            output.push_str("} as const;\n\n");
            write_source_metadata(output, source, 0);
            write_schema_tsdoc(
                output,
                &schema.meta().docs,
                DocKind::Schema,
                &self.config.documentation,
                0,
                false,
            );
            output.push_str("export type ");
            output.push_str(name);
            output.push_str(" = (typeof ");
            output.push_str(name);
            output.push_str(")[keyof typeof ");
            output.push_str(name);
            output.push_str("];\n");
            return;
        }

        write_source_metadata(output, source, 0);
        write_schema_tsdoc(
            output,
            &schema.meta().docs,
            DocKind::Schema,
            &self.config.documentation,
            0,
            false,
        );
        if let SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } = schema
            && !matches!(
                additional_properties,
                AdditionalProperties::Schema(_) | AdditionalProperties::Allowed(Some(_))
            )
            && !schema.is_nullable()
        {
            output.push_str("export interface ");
            output.push_str(name);
            output.push(' ');
            output.push_str(&self.render_interface_body(properties, position, 0));
            output.push('\n');
        } else {
            output.push_str("export type ");
            output.push_str(name);
            output.push_str(" = ");
            output.push_str(&self.render_type(schema, position, 0));
            output.push_str(";\n");
        }
    }

    fn enum_members(&self, schema: &SchemaNode) -> Option<&[EnumMember]> {
        let source = &schema.meta().source;
        let index = self
            .enum_member_indices
            .get(&(source.source_id.clone(), source.json_pointer.clone()))?;
        self.analyzed
            .enum_members
            .get(*index)
            .map(|table| table.members.as_slice())
    }

    fn render_interface_body(
        &self,
        properties: &[(String, SchemaNode, PropMeta)],
        position: TypePosition,
        indent: usize,
    ) -> String {
        self.render_object_parts(
            properties,
            &AdditionalProperties::Forbidden,
            position,
            indent,
            true,
        )
    }

    fn render_type(&self, schema: &SchemaNode, position: TypePosition, indent: usize) -> String {
        let rendered = match schema {
            SchemaNode::Ref { target, .. } => self
                .schema_target(&target.source_id, &target.json_pointer)
                .map_or_else(
                    || "unknown".to_owned(),
                    |target| target.variant_name(position),
                ),
            SchemaNode::Primitive {
                ty,
                enum_values,
                const_value,
                ..
            } => finite_values(enum_values.as_deref(), const_value.as_ref()).map_or_else(
                || match ty {
                    PrimitiveType::String => "string".to_owned(),
                    PrimitiveType::Number | PrimitiveType::Integer => "number".to_owned(),
                    PrimitiveType::Boolean => "boolean".to_owned(),
                    PrimitiveType::Null => "null".to_owned(),
                },
                |values| render_literal_union(&values),
            ),
            SchemaNode::Finite {
                enum_values,
                const_value,
                ..
            } => finite_values(enum_values.as_deref(), const_value.as_ref()).map_or_else(
                || "unknown".to_owned(),
                |values| render_literal_union(&values),
            ),
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                self.render_object_parts(properties, additional_properties, position, indent, false)
            }
            SchemaNode::Array { items, .. } => {
                let item = self.render_type(items, position, indent);
                format!("{}[]", parenthesize_array_item(item, items))
            }
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                let mut items = prefix_items
                    .iter()
                    .map(|item| self.render_type(item, position, indent))
                    .collect::<Vec<_>>();
                match rest {
                    TupleRest::Allowed => items.push("...unknown[]".to_owned()),
                    TupleRest::Forbidden => {}
                    TupleRest::Schema(schema) => {
                        let rest = self.render_type(schema, position, indent);
                        items.push(format!("...{}[]", parenthesize_array_item(rest, schema)));
                    }
                }
                format!("[{}]", items.join(", "))
            }
            SchemaNode::AllOf { branches, .. } => {
                if let Some((properties, additional_properties)) = self.merge_all_of(branches) {
                    self.render_object_parts(
                        &properties,
                        &additional_properties,
                        position,
                        indent,
                        false,
                    )
                } else if branches.is_empty() {
                    "unknown".to_owned()
                } else {
                    branches
                        .iter()
                        .map(|branch| self.render_type(branch, position, indent))
                        .collect::<Vec<_>>()
                        .join(" & ")
                }
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                if branches.is_empty() {
                    "never".to_owned()
                } else {
                    branches
                        .iter()
                        .map(|branch| self.render_type(branch, position, indent))
                        .collect::<Vec<_>>()
                        .join(" | ")
                }
            }
            SchemaNode::Any { .. } | SchemaNode::Unknown { .. } => "unknown".to_owned(),
            SchemaNode::Never { .. } => "never".to_owned(),
        };
        if matches!(
            schema,
            SchemaNode::Primitive {
                enum_values: Some(_),
                ..
            } | SchemaNode::Primitive {
                const_value: Some(_),
                ..
            }
        ) {
            rendered
        } else {
            add_nullable(rendered, schema)
        }
    }

    fn render_object_parts(
        &self,
        properties: &[(String, SchemaNode, PropMeta)],
        additional_properties: &AdditionalProperties,
        position: TypePosition,
        indent: usize,
        interface_members: bool,
    ) -> String {
        let included = properties
            .iter()
            .filter(|(_, _, meta)| property_in_position(meta, position))
            .collect::<Vec<_>>();
        let has_included_properties = !included.is_empty();
        let literal = if included.is_empty() {
            "{}".to_owned()
        } else {
            let mut output = String::from("{\n");
            for (name, schema, meta) in included {
                let member_indent = indent + 2;
                let docs = property_docs(schema, meta);
                write_schema_tsdoc(
                    &mut output,
                    &docs,
                    DocKind::Property,
                    &self.config.documentation,
                    member_indent,
                    interface_members,
                );
                output.push_str(&" ".repeat(member_indent));
                if self.config.types.readonly {
                    output.push_str("readonly ");
                }
                output.push_str(&render_property_key(name));
                if !meta.required {
                    output.push('?');
                }
                output.push_str(": ");
                output.push_str(&self.render_type(schema, position, member_indent));
                output.push_str(";\n");
            }
            output.push_str(&" ".repeat(indent));
            output.push('}');
            output
        };
        match additional_properties {
            AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => literal,
            AdditionalProperties::Allowed(Some(schema)) | AdditionalProperties::Schema(schema) => {
                let value = self.render_type(schema, position, indent);
                if !has_included_properties {
                    format!("{{ [key: string]: {value} }}")
                } else {
                    format!("{literal} & Record<string, {value}>")
                }
            }
        }
    }

    fn merge_all_of(
        &self,
        branches: &[SchemaNode],
    ) -> Option<(OwnedProperties, AdditionalProperties)> {
        let shapes = branches
            .iter()
            .map(|branch| self.object_shape(branch, &mut HashSet::new()))
            .collect::<Option<Vec<_>>>()?;
        let first = shapes.first()?;
        let merged_additional_properties = first.additional_properties.clone();
        if shapes
            .iter()
            .any(|shape| shape.additional_properties != first.additional_properties)
        {
            return None;
        }
        let all_property_names = shapes
            .iter()
            .flat_map(|shape| shape.properties.iter().map(|(name, _, _)| name.as_str()))
            .collect::<BTreeSet<_>>();
        if shapes.iter().any(|shape| {
            shape.additional_properties == &AdditionalProperties::Forbidden
                && all_property_names.iter().any(|name| {
                    !shape
                        .properties
                        .iter()
                        .any(|(declared, _, _)| declared == name)
                })
        }) {
            return None;
        }
        let mut merged = Vec::<(String, SchemaNode, PropMeta)>::new();
        for shape in shapes {
            for (name, schema, meta) in shape.properties {
                if let Some((_, previous_schema, previous_meta)) =
                    merged.iter().find(|(previous, _, _)| previous == name)
                {
                    if previous_meta.required != meta.required || previous_schema != schema {
                        return None;
                    }
                } else {
                    merged.push((name.clone(), schema.clone(), meta.clone()));
                }
            }
        }
        Some((merged, merged_additional_properties))
    }

    fn collect_component_imports(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        current_schema: usize,
        imports: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        self.walk_refs(schema, position, &mut |target| {
            if target.index != current_schema {
                imports
                    .entry(target.file_base.clone())
                    .or_default()
                    .insert(target.variant_name(position));
            }
        });
    }

    fn walk_refs(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        visit: &mut dyn FnMut(&SchemaTarget),
    ) {
        if let SchemaNode::Ref { target, .. } = schema
            && let Some(target) = self.schema_target(&target.source_id, &target.json_pointer)
        {
            visit(target);
        }
        self.for_each_schema_child(
            schema,
            SchemaChildMode::References(position),
            &mut |child| {
                self.walk_refs(child, position, visit);
            },
        );
    }

    fn for_each_schema_child(
        &self,
        schema: &SchemaNode,
        mode: SchemaChildMode,
        visit: &mut dyn FnMut(&SchemaNode),
    ) {
        match schema {
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                for (_, property, meta) in properties {
                    if matches!(mode, SchemaChildMode::Validation)
                        || matches!(mode, SchemaChildMode::References(position) if property_in_position(meta, position))
                    {
                        visit(property);
                    }
                }
                if let AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) = additional_properties
                {
                    visit(schema);
                }
            }
            SchemaNode::Array { items, .. } => visit(items),
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for item in prefix_items {
                    visit(item);
                }
                if let TupleRest::Schema(schema) = rest {
                    visit(schema);
                }
            }
            SchemaNode::AllOf { branches, .. } => {
                if let SchemaChildMode::References(position) = mode
                    && let Some((properties, additional_properties)) = self.merge_all_of(branches)
                {
                    for (_, property, meta) in &properties {
                        if property_in_position(meta, position) {
                            visit(property);
                        }
                    }
                    if let AdditionalProperties::Allowed(Some(schema))
                    | AdditionalProperties::Schema(schema) = &additional_properties
                    {
                        visit(schema);
                    }
                } else {
                    for branch in branches {
                        visit(branch);
                    }
                }
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                for branch in branches {
                    visit(branch);
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

    fn write_imports(
        &self,
        output: &mut String,
        imports: BTreeMap<String, BTreeSet<String>>,
        prefix: &str,
    ) {
        if imports.is_empty() {
            return;
        }
        let extension = if self.config.emit.import_extension == "none" {
            ""
        } else {
            self.config.emit.import_extension.as_str()
        };
        for (file, names) in imports {
            output.push_str("import type { ");
            output.push_str(&names.into_iter().collect::<Vec<_>>().join(", "));
            output.push_str(" } from ");
            output.push_str(&render_ts_string(&format!("{prefix}{file}{extension}")));
            output.push_str(";\n");
        }
        output.push('\n');
    }
}

impl SchemaTarget {
    fn variant_name(&self, position: TypePosition) -> String {
        match position {
            TypePosition::Request if self.request_differs => format!("{}Request", self.name),
            TypePosition::Response if self.response_differs => format!("{}Response", self.name),
            TypePosition::Neutral | TypePosition::Request | TypePosition::Response => {
                self.name.clone()
            }
        }
    }
}

impl Emitter<'_, '_> {
    fn emit_operation(&self, operation_index: usize, allocated_name: &str) -> GeneratedFile {
        let operation = &self.analyzed.ir.operations[operation_index];
        let stem = uppercase_first(allocated_name);
        let file_base = self.operation_files[operation_index]
            .as_deref()
            .unwrap_or_default();
        let mut content = self.header();
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        for parameter in &operation.parameters {
            self.collect_operation_imports(&parameter.schema, TypePosition::Request, &mut imports);
        }
        if let Some(body) = &operation.request_body
            && let Some(media_type) = select_request_media(&body.media_types)
            && media_is_json(&media_type.name)
        {
            self.collect_operation_imports(&media_type.schema, TypePosition::Request, &mut imports);
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                if media_is_json(&media_type.name) {
                    self.collect_operation_imports(
                        &media_type.schema,
                        TypePosition::Response,
                        &mut imports,
                    );
                }
            }
        }
        self.write_imports(&mut content, imports, "../components/");

        write_source_metadata(&mut content, &operation.source, 0);
        write_operation_tsdoc(&mut content, operation, &self.config.documentation, 0);
        content.push_str("export type ");
        content.push_str(&stem);
        content.push_str("Request = ");
        content.push_str(&self.render_request(operation, 0));
        content.push_str(";\n\n");

        let mut response_declarations = operation
            .responses
            .iter()
            .map(|response| {
                (
                    format!(
                        "{}Response{}",
                        stem,
                        response_status_type_suffix(&response.status)
                    ),
                    response,
                )
            })
            .collect::<Vec<_>>();
        response_declarations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut response_names = Vec::new();
        for (response_name, response) in response_declarations {
            response_names.push(response_name.clone());
            write_source_metadata(&mut content, &response.source, 0);
            content.push_str("export type ");
            content.push_str(&response_name);
            content.push_str(" = ");
            content.push_str(&self.render_response_entry(response));
            content.push_str(";\n\n");
        }
        write_source_metadata(&mut content, &operation.source, 0);
        write_operation_tsdoc(&mut content, operation, &self.config.documentation, 0);
        content.push_str("export type ");
        content.push_str(&stem);
        content.push_str("Response = ");
        if response_names.is_empty() {
            content.push_str("never");
        } else {
            content.push_str(&response_names.join(" | "));
        }
        content.push_str(";\n");

        GeneratedFile {
            relative_path: format!("types/operations/{file_base}.ts"),
            content,
        }
    }

    fn render_request(&self, operation: &Operation, indent: usize) -> String {
        let groups = [
            (ParamLocation::Path, "path"),
            (ParamLocation::Query, "query"),
            (ParamLocation::Header, "headers"),
            (ParamLocation::Cookie, "cookies"),
        ];
        let mut output = String::from("{\n");
        let mut has_members = false;
        for (location, group_name) in groups {
            let parameters = operation
                .parameters
                .iter()
                .filter(|parameter| parameter.location == location)
                .collect::<Vec<_>>();
            if parameters.is_empty() {
                continue;
            }
            has_members = true;
            let group_required = parameters.iter().any(|parameter| parameter.required);
            let group = self.render_parameter_group(&parameters, indent + 2);
            output.push_str(&" ".repeat(indent + 2));
            if self.config.types.readonly {
                output.push_str("readonly ");
            }
            output.push_str(group_name);
            if !group_required {
                output.push('?');
            }
            output.push_str(": ");
            output.push_str(&group);
            output.push_str(";\n");
        }
        if let Some(body) = &operation.request_body
            && let Some(media_type) = select_request_media(&body.media_types)
        {
            has_members = true;
            let body_type = self.render_media_type(media_type, TypePosition::Request);
            if let Some(description) = &body.description {
                let docs = SchemaDocs {
                    description: Some(description.clone()),
                    ..SchemaDocs::default()
                };
                write_schema_tsdoc(
                    &mut output,
                    &docs,
                    DocKind::Property,
                    &self.config.documentation,
                    indent + 2,
                    false,
                );
            }
            output.push_str(&" ".repeat(indent + 2));
            if self.config.types.readonly {
                output.push_str("readonly ");
            }
            output.push_str("body");
            if !body.required {
                output.push('?');
            }
            output.push_str(": ");
            output.push_str(&body_type);
            output.push_str(";\n");
        }
        if !has_members {
            return "{}".to_owned();
        }
        output.push_str(&" ".repeat(indent));
        output.push('}');
        output
    }

    fn render_parameter_group(&self, parameters: &[&Param], indent: usize) -> String {
        let mut output = String::from("{\n");
        for parameter in parameters {
            let docs = SchemaDocs {
                title: None,
                description: parameter.description.clone(),
                deprecated: parameter.deprecated,
                default: None,
                examples: parameter.schema.meta().docs.examples.clone(),
                comment: parameter.schema.meta().docs.comment.clone(),
                constraints: parameter.schema.meta().docs.constraints.clone(),
            };
            write_schema_tsdoc(
                &mut output,
                &docs,
                DocKind::Parameter,
                &self.config.documentation,
                indent + 2,
                false,
            );
            output.push_str(&" ".repeat(indent + 2));
            if self.config.types.readonly {
                output.push_str("readonly ");
            }
            output.push_str(&render_property_key(&parameter.name));
            if !parameter.required {
                output.push('?');
            }
            output.push_str(": ");
            output.push_str(&self.render_type(
                &parameter.schema,
                TypePosition::Request,
                indent + 2,
            ));
            output.push_str(";\n");
        }
        output.push_str(&" ".repeat(indent));
        output.push('}');
        output
    }

    fn render_response_entry(&self, response: &ResponseEntry) -> String {
        if response.media_types.is_empty() {
            return "null".to_owned();
        }
        let mut types = Vec::new();
        for media_type in &response.media_types {
            let rendered = self.render_media_type(media_type, TypePosition::Response);
            if !types.contains(&rendered) {
                types.push(rendered);
            }
        }
        types.join(" | ")
    }

    fn render_media_type(
        &self,
        media_type: &crate::ir::MediaType,
        position: TypePosition,
    ) -> String {
        if media_is_json(&media_type.name) {
            self.render_type(&media_type.schema, position, 0)
        } else if media_type.name.starts_with("text/") {
            "string".to_owned()
        } else {
            // Binary and custom media stay unknown in the types-only artifact;
            // Phase 5's client runtime will own byte-container choices.
            "unknown".to_owned()
        }
    }

    fn collect_operation_imports(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        imports: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        self.walk_refs(schema, position, &mut |target| {
            imports
                .entry(target.file_base.clone())
                .or_default()
                .insert(target.variant_name(position));
        });
    }
}

fn select_request_media(media_types: &[crate::ir::MediaType]) -> Option<&crate::ir::MediaType> {
    media_types
        .iter()
        .find(|media_type| media_is_json(&media_type.name))
        .or_else(|| media_types.first())
}

fn media_is_json(name: &str) -> bool {
    name == "application/json" || name.ends_with("+json")
}

fn media_is_unknown(name: &str) -> bool {
    !media_is_json(name) && !name.starts_with("text/")
}

fn response_status_type_suffix(status: &ResponseStatus) -> String {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value.to_ascii_uppercase(),
        ResponseStatus::Default => "Default".to_owned(),
    }
}

fn property_in_position(meta: &PropMeta, position: TypePosition) -> bool {
    match position {
        TypePosition::Neutral => true,
        TypePosition::Request => !meta.read_only,
        TypePosition::Response => !meta.write_only,
    }
}

fn property_docs(schema: &SchemaNode, meta: &PropMeta) -> SchemaDocs {
    SchemaDocs {
        title: schema.meta().docs.title.clone(),
        description: meta.description.clone(),
        deprecated: meta.deprecated,
        default: meta.default.clone(),
        examples: meta.examples.clone(),
        comment: schema.meta().docs.comment.clone(),
        constraints: schema.meta().docs.constraints.clone(),
    }
}

fn schema_finite_values(schema: &SchemaNode) -> Option<Vec<Value>> {
    let (enum_values, const_value) = match schema {
        SchemaNode::Primitive {
            enum_values,
            const_value,
            ..
        }
        | SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => (enum_values, const_value),
        _ => return None,
    };
    finite_values(enum_values.as_deref(), const_value.as_ref())
}

fn finite_values(enum_values: Option<&[Value]>, const_value: Option<&Value>) -> Option<Vec<Value>> {
    match (enum_values, const_value) {
        (None, None) => None,
        (Some(values), None) => Some(values.to_vec()),
        (None, Some(value)) => Some(vec![value.clone()]),
        (Some(values), Some(value)) => Some(
            if values.iter().any(|candidate| json_equal(candidate, value)) {
                vec![value.clone()]
            } else {
                Vec::new()
            },
        ),
    }
}

fn json_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .is_some_and(|(left, right)| left == right),
        _ => left == right,
    }
}

fn render_literal_union(values: &[Value]) -> String {
    if values.is_empty() {
        "never".to_owned()
    } else {
        values
            .iter()
            .map(render_ts_value)
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

fn render_ts_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map_or_else(|| value.to_string(), render_number),
        Value::String(value) => render_ts_string(value),
        Value::Array(_) | Value::Object(_) => render_json_compact(value),
    }
}

/// Encodes an untrusted value for a TypeScript double-quoted string literal.
#[must_use]
pub fn render_ts_string(value: &str) -> String {
    let mut encoded = serde_json::to_string(value).expect("serializing a string cannot fail");
    encoded = encoded.replace('\u{2028}', "\\u2028");
    encoded.replace('\u{2029}', "\\u2029")
}

/// Emits a wire property key verbatim, quoting anything outside ASCII identifier syntax.
#[must_use]
pub fn render_property_key(value: &str) -> String {
    let mut characters = value.chars();
    let valid_start = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || matches!(character, '_' | '$'));
    if valid_start
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
    {
        value.to_owned()
    } else {
        render_ts_string(value)
    }
}

fn add_nullable(rendered: String, schema: &SchemaNode) -> String {
    if !schema.is_nullable()
        || rendered.split(" | ").any(|member| member == "null")
        || matches!(
            schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Null,
                ..
            }
        )
    {
        rendered
    } else {
        format!("{rendered} | null")
    }
}

fn parenthesize_array_item(rendered: String, schema: &SchemaNode) -> String {
    if schema.is_nullable()
        || matches!(
            schema,
            SchemaNode::AllOf { .. } | SchemaNode::OneOf { .. } | SchemaNode::AnyOf { .. }
        )
    {
        format!("({rendered})")
    } else {
        rendered
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DocKind {
    Schema,
    Property,
    Parameter,
}

#[derive(Default)]
struct TsDoc {
    summary: Option<String>,
    remarks: Vec<String>,
    deprecated: Option<&'static str>,
    default_value: Option<String>,
    examples: Vec<DocExample>,
    private_remarks: Option<String>,
    see: Vec<(String, Option<String>)>,
}

struct DocExample {
    label: Option<String>,
    value: Value,
}

fn write_schema_tsdoc(
    output: &mut String,
    docs: &SchemaDocs,
    kind: DocKind,
    config: &DocumentationConfig,
    indent: usize,
    interface_member: bool,
) {
    if !config.enabled {
        return;
    }
    let mut tsdoc = TsDoc::default();
    match kind {
        DocKind::Schema | DocKind::Property => {
            map_summary_description(
                &mut tsdoc,
                docs.title.as_deref(),
                docs.description.as_deref(),
                config,
            );
        }
        DocKind::Parameter => {
            if let Some(description) = docs.description.as_ref() {
                if config.summary {
                    tsdoc.summary = Some(description.clone());
                } else if config.description {
                    tsdoc.remarks.push(description.clone());
                }
            }
        }
    }
    if config.deprecated && docs.deprecated {
        tsdoc.deprecated = Some(match kind {
            DocKind::Schema => "This schema is deprecated.",
            DocKind::Property => "This property is deprecated.",
            DocKind::Parameter => "This parameter is deprecated.",
        });
    }
    if let Some(default) = docs.default.as_ref() {
        let rendered = render_json_compact(default);
        if kind == DocKind::Property && interface_member {
            tsdoc.default_value = Some(rendered);
        } else if kind == DocKind::Schema {
            tsdoc.remarks.push(format!("Default value: {rendered}"));
        }
    }
    if config.constraints && !docs.constraints.is_empty() {
        tsdoc.remarks.push(format!(
            "Constraints\n\n{}",
            docs.constraints
                .iter()
                .map(|constraint| format!("- {constraint}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if config.examples {
        tsdoc.examples = docs
            .examples
            .iter()
            .cloned()
            .map(|value| DocExample { label: None, value })
            .collect();
    }
    tsdoc.private_remarks = docs.comment.clone();
    write_tsdoc(output, &tsdoc, indent);
}

fn map_summary_description(
    tsdoc: &mut TsDoc,
    title: Option<&str>,
    description: Option<&str>,
    config: &DocumentationConfig,
) {
    if config.summary {
        if let Some(title) = title {
            tsdoc.summary = Some(title.to_owned());
        } else if config.description
            && let Some(description) = description
        {
            tsdoc.summary = Some(description.to_owned());
            return;
        }
    }
    if config.description
        && let Some(description) = description
    {
        tsdoc.remarks.push(description.to_owned());
    }
}

fn write_operation_tsdoc(
    output: &mut String,
    operation: &Operation,
    config: &DocumentationConfig,
    indent: usize,
) {
    if !config.enabled {
        return;
    }
    let mut tsdoc = TsDoc::default();
    map_summary_description(
        &mut tsdoc,
        operation.summary.as_deref(),
        operation.description.as_deref(),
        config,
    );
    if config.description && !operation.responses.is_empty() {
        tsdoc.remarks.push(format!(
            "Responses\n\n{}",
            operation
                .responses
                .iter()
                .map(|response| format!(
                    "- {}: {}",
                    response_status_label(&response.status),
                    response.description
                ))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    if config.constraints {
        let mut media_notes = Vec::new();
        if let Some(body) = &operation.request_body
            && let Some(media_type) = select_request_media(&body.media_types)
            && media_is_unknown(&media_type.name)
        {
            media_notes.push(format!(
                "- request body {}: represented as unknown in the types artifact.",
                media_type.name
            ));
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                if media_is_unknown(&media_type.name) {
                    media_notes.push(format!(
                        "- response {} {}: represented as unknown in the types artifact.",
                        response_status_label(&response.status),
                        media_type.name
                    ));
                }
            }
        }
        if !media_notes.is_empty() {
            tsdoc.remarks.push(format!(
                "Media type constraints\n\n{}",
                media_notes.join("\n")
            ));
        }
    }
    if config.deprecated && operation.deprecated {
        tsdoc.deprecated = Some("This operation is deprecated.");
    }
    if let Some((url, description)) = &operation.external_docs {
        tsdoc.see.push((url.clone(), description.clone()));
    }
    if config.examples {
        for media_type in operation
            .request_body
            .iter()
            .flat_map(|body| &body.media_types)
        {
            push_media_examples(&mut tsdoc.examples, media_type, "request body");
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                let source = format!("response {}", response_status_label(&response.status));
                push_media_examples(&mut tsdoc.examples, media_type, &source);
            }
        }
    }
    write_tsdoc(output, &tsdoc, indent);
}

fn push_media_examples(examples: &mut Vec<DocExample>, media_type: &MediaType, source: &str) {
    for (label, value) in &media_type.examples {
        examples.push(DocExample {
            label: Some(format!("Source: {source} {label} ({})", media_type.name)),
            value: value.clone(),
        });
    }
    for value in &media_type.schema.meta().docs.examples {
        examples.push(DocExample {
            label: Some(format!("Source: {source} ({})", media_type.name)),
            value: value.clone(),
        });
    }
}

fn write_tsdoc(output: &mut String, docs: &TsDoc, indent: usize) {
    if docs.summary.is_none()
        && docs.remarks.is_empty()
        && docs.deprecated.is_none()
        && docs.default_value.is_none()
        && docs.examples.is_empty()
        && docs.private_remarks.is_none()
        && docs.see.is_empty()
    {
        return;
    }
    let prefix = " ".repeat(indent);
    output.push_str(&prefix);
    output.push_str("/**\n");
    let mut sections = Vec::<Vec<String>>::new();
    if let Some(summary) = &docs.summary {
        sections.push(encode_comment_lines(summary));
    }
    if !docs.remarks.is_empty() {
        let mut lines = vec!["@remarks".to_owned()];
        lines.extend(encode_comment_lines(&docs.remarks.join("\n\n")));
        sections.push(lines);
    }
    if let Some(deprecated) = docs.deprecated {
        sections.push(vec![format!("@deprecated {deprecated}")]);
    }
    if let Some(default) = &docs.default_value {
        sections.push(vec![format!(
            "@defaultValue {}",
            encode_comment_fragment(default)
        )]);
    }
    for example in &docs.examples {
        let mut lines = vec!["@example".to_owned()];
        if let Some(label) = &example.label {
            lines.extend(encode_comment_lines(label));
            lines.push(String::new());
        }
        lines.push("```json".to_owned());
        lines.extend(
            render_json_pretty(&example.value)
                .lines()
                .map(neutralize_comment_close),
        );
        lines.push("```".to_owned());
        sections.push(lines);
    }
    if let Some(private_remarks) = &docs.private_remarks {
        let mut lines = vec!["@privateRemarks".to_owned()];
        lines.extend(encode_comment_lines(private_remarks));
        sections.push(lines);
    }
    for (url, label) in &docs.see {
        let encoded_url = encode_link_part(url);
        let link = label.as_ref().map_or_else(
            || format!("@see {{@link {encoded_url}}}"),
            |label| format!("@see {{@link {encoded_url} | {}}}", encode_link_part(label)),
        );
        sections.push(vec![link]);
    }
    for (section_index, section) in sections.iter().enumerate() {
        if section_index != 0 {
            output.push_str(&prefix);
            output.push_str(" * \n");
        }
        for line in section {
            output.push_str(&prefix);
            output.push_str(" * ");
            output.push_str(line);
            output.push('\n');
        }
    }
    output.push_str(&prefix);
    output.push_str(" */\n");
}

/// Encodes untrusted CommonMark while preserving code spans and fenced blocks.
#[must_use]
pub fn encode_comment_text(value: &str) -> String {
    encode_comment_lines(value).join("\n")
}

fn encode_comment_lines(value: &str) -> Vec<String> {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut fenced = false;
    normalized
        .split('\n')
        .map(|line| {
            let trimmed = line.trim_start();
            let fence_line = trimmed.starts_with("```") || trimmed.starts_with("~~~");
            let encoded = if fenced || fence_line {
                neutralize_comment_close(line)
            } else {
                encode_comment_line(line)
            };
            if fence_line {
                fenced = !fenced;
            }
            encoded
        })
        .collect()
}

fn encode_comment_fragment(value: &str) -> String {
    encode_comment_lines(value).join(" ")
}

fn encode_comment_line(line: &str) -> String {
    let neutralized =
        neutralize_comment_close(line).replace("sourceMappingURL=", "sourceMappingURL\\=");
    let leading = neutralized.len() - neutralized.trim_start().len();
    let mut output = neutralized[..leading].to_owned();
    let rest = &neutralized[leading..];
    output.push_str(&encode_comment_inline(rest));
    output
}

fn encode_comment_inline(value: &str) -> String {
    let mut output = String::new();
    let mut characters = value.char_indices().peekable();
    let mut code = false;
    let mut html = false;
    while let Some((index, character)) = characters.next() {
        if character == '`' {
            code = !code;
            output.push(character);
            continue;
        }
        if code {
            output.push(character);
            continue;
        }
        let next = characters.peek().map(|(_, character)| *character);
        match character {
            '@' if next.is_some_and(|next| next.is_ascii_alphabetic())
                && (index == 0
                    || value[..index]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)) =>
            {
                output.push_str("\\@");
            }
            '{' if next == Some('@') => output.push_str("\\{"),
            '}' => output.push_str("\\}"),
            '<' if next.is_some_and(|next| {
                next.is_ascii_alphabetic() || matches!(next, '/' | '!' | '?')
            }) =>
            {
                html = true;
                output.push_str("\\<");
            }
            '>' if html => {
                html = false;
                output.push_str("\\>");
            }
            _ => output.push(character),
        }
    }
    output
}

fn neutralize_comment_close(value: &str) -> String {
    value
        .replace("*/", "*\\/")
        .replace("sourceMappingURL=", "sourceMappingURL\\=")
}

fn encode_link_part(value: &str) -> String {
    let encoded = neutralize_comment_close(value)
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('<', "\\<")
        .replace('>', "\\>")
        .replace('|', "\\|");
    encoded.replace(['\n', '\r'], " ")
}

fn write_source_metadata(output: &mut String, source: &SourceRef, indent: usize) {
    output.push_str(&" ".repeat(indent));
    output.push_str("// Source: ");
    output.push_str(&encode_line_comment(&source.display()));
    output.push('\n');
}

fn encode_line_comment(value: &str) -> String {
    value
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .replace("sourceMappingURL=", "sourceMappingURL\\=")
}

fn render_json_compact(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => number
            .as_f64()
            .filter(|value| value.is_finite())
            .map_or_else(|| number.to_string(), render_number),
        Value::String(value) => render_ts_string(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(render_json_compact)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    render_ts_string(key),
                    render_json_compact(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn render_json_pretty(value: &Value) -> String {
    render_json_pretty_at(value, 0)
}

fn render_json_pretty_at(value: &Value, indent: usize) -> String {
    match value {
        Value::Array(values) if !values.is_empty() => {
            let child_indent = indent + 2;
            format!(
                "[\n{}\n{}]",
                values
                    .iter()
                    .map(|value| format!(
                        "{}{}",
                        " ".repeat(child_indent),
                        render_json_pretty_at(value, child_indent)
                    ))
                    .collect::<Vec<_>>()
                    .join(",\n"),
                " ".repeat(indent)
            )
        }
        Value::Object(values) if !values.is_empty() => {
            let child_indent = indent + 2;
            format!(
                "{{\n{}\n{}}}",
                values
                    .iter()
                    .map(|(key, value)| format!(
                        "{}{}: {}",
                        " ".repeat(child_indent),
                        render_ts_string(key),
                        render_json_pretty_at(value, child_indent)
                    ))
                    .collect::<Vec<_>>()
                    .join(",\n"),
                " ".repeat(indent)
            )
        }
        _ => render_json_compact(value),
    }
}

fn response_status_label(status: &ResponseStatus) -> &str {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value,
        ResponseStatus::Default => "default",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::config::load_config;
    use crate::ir::{Body, Discriminator, Ir, MediaType, NamedSchema, SchemaMeta, SchemaRef};
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::{AllocatedOperationName, EnumMemberTable, analyze};

    fn compile(document: Value, config_patch: Value) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec_pretty(&document).expect("OpenAPI JSON"),
        )
        .expect("write OpenAPI");
        let mut config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated"
        });
        if let (Some(config), Some(patch)) = (config.as_object_mut(), config_patch.as_object()) {
            config.extend(patch.clone());
        }
        fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved = load_config(Some(&config_path), temp.path()).expect("valid config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("loaded graph");
        let ir = parse(&graph, &mut sink).expect("supported OpenAPI");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_types(&analyzed, &resolved, &graph.source_tuples(), &mut sink);
        (files, sink.into_sorted_vec())
    }

    fn openapi(schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    fn generated_body(file: &GeneratedFile) -> &str {
        file.content
            .split_once("\n\n")
            .map_or(file.content.as_str(), |(_, body)| body)
    }

    fn source(pointer: &str) -> SourceRef {
        SourceRef {
            source_id: "workspace/openapi.json".to_owned(),
            json_pointer: pointer.to_owned(),
            line: Some(3),
            col: Some(5),
        }
    }

    fn meta(pointer: &str) -> SchemaMeta {
        SchemaMeta {
            source: source(pointer),
            ..SchemaMeta::default()
        }
    }

    fn primitive(ty: PrimitiveType, pointer: &str) -> SchemaNode {
        SchemaNode::Primitive {
            ty,
            format: None,
            enum_values: None,
            const_value: None,
            meta: meta(pointer),
        }
    }

    fn schema_ref(pointer: &str, target_pointer: &str) -> SchemaNode {
        SchemaNode::Ref {
            target: SchemaRef {
                source_id: "workspace/openapi.json".to_owned(),
                json_pointer: target_pointer.to_owned(),
            },
            meta: meta(pointer),
        }
    }

    fn prop_meta(pointer: &str) -> PropMeta {
        PropMeta {
            required: false,
            read_only: false,
            write_only: false,
            deprecated: false,
            description: None,
            default: None,
            examples: Vec::new(),
            source: source(pointer),
        }
    }

    fn resolved_config(config_patch: Value) -> (TempDir, ResolvedConfig) {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec(&openapi(json!({}))).expect("OpenAPI JSON"),
        )
        .expect("write OpenAPI");
        let mut config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated"
        });
        if let (Some(config), Some(patch)) = (config.as_object_mut(), config_patch.as_object()) {
            config.extend(patch.clone());
        }
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved = load_config(Some(&config_path), temp.path()).expect("valid config");
        (temp, resolved)
    }

    #[test]
    fn source_digest_pins_the_framing_preimage() {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"oasts-src-v1\0");
        preimage.extend_from_slice(&1_u64.to_be_bytes());
        preimage.extend_from_slice(&16_u64.to_be_bytes());
        preimage.extend_from_slice(b"workspace/a.yaml");
        preimage.extend_from_slice(&[0; 32]);
        assert_eq!(
            lower_hex(&preimage),
            concat!(
                "6f78736368656d612d7372632d763100",
                "0000000000000001",
                "0000000000000010",
                "776f726b73706163652f612e79616d6c",
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        let expected = lower_hex(&Sha256::digest(&preimage));
        assert_eq!(
            source_digest(&[("workspace/a.yaml".to_owned(), [0; 32])]),
            expected
        );
        let first = ("workspace/a.yaml".to_owned(), [1; 32]);
        let second = ("workspace/b.yaml".to_owned(), [2; 32]);
        assert_eq!(
            source_digest(&[first.clone(), second.clone()]),
            source_digest(&[second, first])
        );
    }

    #[test]
    fn file_case_modes_and_unsafe_names_are_frozen() {
        assert_eq!(
            file_base_name("PetHTTPStatus", FileCase::Kebab),
            Ok("pethttpstatus".to_owned())
        );
        assert_eq!(
            file_base_name("PetHTTPStatus", FileCase::Snake),
            Ok("pethttpstatus".to_owned())
        );
        assert_eq!(
            file_base_name("PetHTTPStatus", FileCase::Camel),
            Ok("petHTTPStatus".to_owned())
        );
        assert_eq!(
            file_base_name("PetHTTPStatus", FileCase::Pascal),
            Ok("PetHTTPStatus".to_owned())
        );
        assert_eq!(
            file_base_name("PetHTTPStatus", FileCase::Preserve),
            Ok("PetHTTPStatus".to_owned())
        );
        for (case, configured, expected) in [
            (FileCase::Kebab, "kebab", "peturl"),
            (FileCase::Snake, "snake", "peturl"),
            (FileCase::Camel, "camel", "petURL"),
            (FileCase::Pascal, "pascal", "PetURL"),
            (FileCase::Preserve, "preserve", "petURL"),
        ] {
            assert_eq!(file_base_name("petURL", case), Ok(expected.to_owned()));
            let (files, diagnostics) = compile(
                openapi(json!({ "petURL": { "type": "string" } })),
                json!({ "naming": { "fileCase": configured } }),
            );
            assert!(diagnostics.is_empty(), "{case:?}: {diagnostics:?}");
            assert_eq!(
                files[0].relative_path,
                format!("types/components/{expected}.ts")
            );
        }
        assert_eq!(
            file_base_name("pet_URL", FileCase::Camel),
            Ok("petURL".to_owned())
        );
        assert_eq!(
            file_base_name("λ", FileCase::Kebab),
            Err(FileNameError::UnsafeCharacter('λ'))
        );
        assert_eq!(
            file_base_name("CON", FileCase::Kebab),
            Err(FileNameError::ReservedDevice)
        );
        assert_eq!(
            file_base_name("lpt9.txt", FileCase::Preserve),
            Err(FileNameError::ReservedDevice)
        );
        assert_eq!(
            file_base_name("../pet", FileCase::Preserve),
            Err(FileNameError::UnsafePath)
        );

        let (_, diagnostics) = compile(
            openapi(json!({
                "Foo": { "type": "string" },
                "foo": { "type": "number" }
            })),
            json!({}),
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_PATH_COLLISION)
        );
    }

    #[test]
    fn encoder_filename_numeric_and_diagnostic_edges_are_explicit() {
        for (error, message) in [
            (FileNameError::Empty, "file name is empty"),
            (
                FileNameError::UnsafePath,
                "file name is absolute or contains traversal",
            ),
            (
                FileNameError::ReservedDevice,
                "file name is a Windows reserved device",
            ),
            (
                FileNameError::UnsafeCharacter('.'),
                "file name contains unsafe character '.'",
            ),
        ] {
            assert_eq!(error.to_string(), message);
        }
        assert_eq!(
            file_base_name("---", FileCase::Kebab),
            Err(FileNameError::Empty)
        );
        assert_eq!(validate_file_base(""), Err(FileNameError::Empty));
        assert_eq!(validate_file_base("/a"), Err(FileNameError::UnsafePath));
        assert_eq!(
            validate_file_base("COM1"),
            Err(FileNameError::ReservedDevice)
        );
        assert_eq!(
            validate_file_base("a.b"),
            Err(FileNameError::UnsafeCharacter('.'))
        );

        let one = json!(1);
        assert_eq!(
            finite_values(Some(std::slice::from_ref(&one)), Some(&one)),
            Some(vec![one.clone()])
        );
        assert_eq!(
            finite_values(Some(&[json!(2)]), Some(&one)),
            Some(Vec::new())
        );
        assert!(json_equal(&json!(1), &json!(1.0)));
        assert_eq!(render_literal_union(&[]), "never");
        assert_eq!(render_ts_value(&json!(true)), "true");
        assert_eq!(render_ts_value(&json!(1.25)), "1.25");
        let outside_binary64 = "1e999"
            .parse::<serde_json::Number>()
            .expect("arbitrary-precision JSON number");
        assert_eq!(render_ts_value(&Value::Number(outside_binary64)), "1e+999");
        assert_eq!(render_ts_value(&json!([null, false])), "[null,false]");
        assert_eq!(render_ts_value(&json!({"a": 1})), "{\"a\":1}");
        assert_eq!(
            render_json_pretty(&json!([1, {"a": true}])),
            "[\n  1,\n  {\n    \"a\": true\n  }\n]"
        );
        assert_eq!(
            encode_comment_text("@tag\r\n```\n*/\n```"),
            "\\@tag\n```\n*\\/\n```"
        );

        let mut nullable = primitive(PrimitiveType::String, "/nullable");
        if let SchemaNode::Primitive { meta, .. } = &mut nullable {
            meta.nullable = true;
        }
        assert_eq!(
            parenthesize_array_item("string | null".to_owned(), &nullable),
            "(string | null)"
        );

        let bounds = NumericBounds::from_constraints(&NumericConstraints {
            exclusive_minimum: Some(ExclusiveBound::Number(serde_json::Number::from(1))),
            exclusive_maximum: Some(ExclusiveBound::Number(serde_json::Number::from(3))),
            ..NumericConstraints::default()
        })
        .expect("numeric bounds");
        assert_eq!(
            bounds.lower,
            Some(Bound {
                value: 1.0,
                exclusive: true
            })
        );
        assert!(!NumericBounds::default().is_empty());
        let low = Bound {
            value: 1.0,
            exclusive: false,
        };
        let high = Bound {
            value: 2.0,
            exclusive: false,
        };
        assert_eq!(stricter_lower(Some(high), Some(low)), Some(high));
        assert_eq!(stricter_lower(Some(low), Some(high)), Some(high));
        assert_eq!(
            stricter_lower(
                Some(low),
                Some(Bound {
                    exclusive: true,
                    ..low
                })
            ),
            Some(Bound {
                exclusive: true,
                ..low
            })
        );
        assert_eq!(stricter_upper(Some(low), Some(high)), Some(low));
        assert_eq!(stricter_upper(Some(high), Some(low)), Some(low));
        assert_eq!(
            stricter_upper(
                Some(low),
                Some(Bound {
                    exclusive: true,
                    ..low
                })
            ),
            Some(Bound {
                exclusive: true,
                ..low
            })
        );

        let diagnostic = source_diagnostic("TEST", "located", &source("/located"));
        assert_eq!((diagnostic.line, diagnostic.col), (Some(3), Some(5)));
    }

    #[test]
    fn emitter_validates_nested_refs_discriminators_and_primitive_domains() {
        fn tagged(pointer: &str, value: &str) -> SchemaNode {
            SchemaNode::Object {
                properties: vec![(
                    "kind".to_owned(),
                    SchemaNode::Primitive {
                        ty: PrimitiveType::String,
                        format: None,
                        enum_values: None,
                        const_value: Some(json!(value)),
                        meta: meta(&format!("{pointer}/kind")),
                    },
                    prop_meta(&format!("{pointer}/kind")),
                )],
                additional_properties: AdditionalProperties::Allowed(None),
                meta: meta(pointer),
            }
        }

        let analyzed = Analyzed {
            ir: Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({}));
        let mut sink = DiagnosticSink::new();
        let emitter = Emitter::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let missing = schema_ref("/missing", "/components/schemas/Missing");
        let nested = SchemaNode::AnyOf {
            branches: vec![
                SchemaNode::Object {
                    properties: Vec::new(),
                    additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                        missing.clone(),
                    ))),
                    meta: meta("/object"),
                },
                SchemaNode::Tuple {
                    prefix_items: Vec::new(),
                    rest: TupleRest::Schema(Box::new(missing.clone())),
                    meta: meta("/tuple"),
                },
                SchemaNode::OneOf {
                    branches: vec![tagged("/cat", "pet"), tagged("/dog", "pet")],
                    discriminator: Some(Discriminator {
                        property_name: "kind".to_owned(),
                        mapping: Vec::new(),
                        source: source("/discriminator"),
                    }),
                    meta: meta("/union"),
                },
            ],
            meta: meta("/nested"),
        };
        let mut diagnostics = Vec::new();
        emitter.validate_schema(&nested, &mut diagnostics);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_REFERENCE)
                .count(),
            2
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR)
        );

        let unique = SchemaNode::OneOf {
            branches: vec![tagged("/one", "one"), tagged("/two", "two")],
            discriminator: Some(Discriminator {
                property_name: "kind".to_owned(),
                mapping: Vec::new(),
                source: source("/unique-discriminator"),
            }),
            meta: meta("/unique"),
        };
        let before = diagnostics.len();
        emitter.validate_schema(&unique, &mut diagnostics);
        assert_eq!(diagnostics.len(), before);
        emitter.validate_schema(
            &SchemaNode::OneOf {
                branches: Vec::new(),
                discriminator: None,
                meta: meta("/no-discriminator"),
            },
            &mut diagnostics,
        );

        for schema in [
            primitive(PrimitiveType::Boolean, "/boolean"),
            primitive(PrimitiveType::Null, "/null"),
            SchemaNode::AnyOf {
                branches: vec![
                    primitive(PrimitiveType::String, "/string"),
                    primitive(PrimitiveType::Integer, "/integer"),
                ],
                meta: meta("/any-of"),
            },
        ] {
            assert!(
                emitter
                    .primitive_domain(&schema, &mut HashSet::new())
                    .is_some()
            );
        }
        let mut nullable = primitive(PrimitiveType::String, "/nullable-domain");
        if let SchemaNode::Primitive { meta, .. } = &mut nullable {
            meta.nullable = true;
        }
        assert!(
            emitter
                .primitive_domain(&nullable, &mut HashSet::new())
                .expect("nullable domain")
                .contains(&PrimitiveAtom::Null)
        );
    }

    #[test]
    fn emitter_resolves_cycles_and_renders_rare_schema_shapes() {
        let self_ref = schema_ref("/components/schemas/Loop", "/components/schemas/Loop");
        let analyzed = Analyzed {
            ir: Ir {
                operations: Vec::new(),
                schemas: vec![NamedSchema {
                    name: "Loop".to_owned(),
                    schema: self_ref.clone(),
                    source: source("/components/schemas/Loop"),
                }],
            },
            operation_names: Vec::new(),
            schema_names: vec![AllocatedSchemaName {
                schema_index: 0,
                wire_name: "Loop".to_owned(),
                name: "Loop".to_owned(),
                source: source("/components/schemas/Loop"),
            }],
            enum_members: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "enum": "const" }
        }));
        let mut sink = DiagnosticSink::new();
        let emitter = Emitter::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        assert!(
            emitter
                .primitive_domain(&self_ref, &mut HashSet::new())
                .is_none()
        );

        assert_eq!(
            emitter.render_type(
                &schema_ref("/unknown-ref", "/components/schemas/Unknown"),
                TypePosition::Neutral,
                0,
            ),
            "unknown"
        );
        assert_eq!(
            emitter.render_type(
                &primitive(PrimitiveType::Null, "/null"),
                TypePosition::Neutral,
                0
            ),
            "null"
        );
        for (schema, expected) in [
            (
                SchemaNode::Tuple {
                    prefix_items: Vec::new(),
                    rest: TupleRest::Allowed,
                    meta: meta("/open-tuple"),
                },
                "[...unknown[]]",
            ),
            (
                SchemaNode::Tuple {
                    prefix_items: Vec::new(),
                    rest: TupleRest::Schema(Box::new(SchemaNode::AnyOf {
                        branches: vec![
                            primitive(PrimitiveType::String, "/tuple-string"),
                            primitive(PrimitiveType::Number, "/tuple-number"),
                        ],
                        meta: meta("/tuple-union"),
                    })),
                    meta: meta("/schema-tuple"),
                },
                "[...(string | number)[]]",
            ),
            (
                SchemaNode::AllOf {
                    branches: Vec::new(),
                    meta: meta("/empty-all-of"),
                },
                "unknown",
            ),
            (
                SchemaNode::AnyOf {
                    branches: Vec::new(),
                    meta: meta("/empty-any-of"),
                },
                "never",
            ),
            (
                SchemaNode::Never {
                    meta: meta("/never"),
                },
                "never",
            ),
        ] {
            assert_eq!(
                emitter.render_type(&schema, TypePosition::Neutral, 0),
                expected
            );
        }

        assert!(
            emitter
                .enum_members(&primitive(PrimitiveType::String, "/enum"))
                .is_none()
        );
        let enum_schema = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: Some(vec![json!("fallback")]),
            const_value: None,
            meta: meta("/fallback-enum"),
        };
        let mut declaration = String::new();
        emitter.write_schema_declaration(
            &mut declaration,
            "Fallback",
            &enum_schema,
            TypePosition::Neutral,
            &source("/fallback-enum"),
        );
        assert!(declaration.contains("Value1: \"fallback\""));
    }

    #[test]
    fn emitter_merging_ref_walks_const_docs_and_extensionless_imports_are_covered() {
        fn object(
            pointer: &str,
            properties: Vec<(String, SchemaNode, PropMeta)>,
            additional_properties: AdditionalProperties,
        ) -> SchemaNode {
            SchemaNode::Object {
                properties,
                additional_properties,
                meta: meta(pointer),
            }
        }

        let target_source = source("/components/schemas/Target");
        let analyzed = Analyzed {
            ir: Ir {
                operations: Vec::new(),
                schemas: vec![NamedSchema {
                    name: "Target".to_owned(),
                    schema: primitive(PrimitiveType::String, "/components/schemas/Target"),
                    source: target_source.clone(),
                }],
            },
            operation_names: Vec::new(),
            schema_names: vec![AllocatedSchemaName {
                schema_index: 0,
                wire_name: "Target".to_owned(),
                name: "Target".to_owned(),
                source: target_source.clone(),
            }],
            enum_members: vec![EnumMemberTable {
                source: source("/described-enum"),
                members: vec![EnumMember {
                    name: "Ready".to_owned(),
                    value: json!("ready"),
                    description: Some("Ready to run.".to_owned()),
                }],
            }],
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "enum": "const" },
            "emit": { "importExtension": "none" }
        }));
        let mut sink = DiagnosticSink::new();
        let emitter = Emitter::new(&analyzed, &config, "digest".to_owned(), &mut sink);

        let first = object(
            "/closed-one",
            vec![(
                "one".to_owned(),
                primitive(PrimitiveType::String, "/closed-one/one"),
                prop_meta("/closed-one/one"),
            )],
            AdditionalProperties::Forbidden,
        );
        let second = object(
            "/closed-two",
            vec![(
                "two".to_owned(),
                primitive(PrimitiveType::String, "/closed-two/two"),
                prop_meta("/closed-two/two"),
            )],
            AdditionalProperties::Forbidden,
        );
        assert!(emitter.merge_all_of(&[first, second]).is_none());

        let equal_property = (
            "same".to_owned(),
            primitive(PrimitiveType::String, "/equal/same"),
            prop_meta("/equal/same"),
        );
        assert!(
            emitter
                .merge_all_of(&[
                    object(
                        "/equal-one",
                        vec![equal_property.clone()],
                        AdditionalProperties::Allowed(None),
                    ),
                    object(
                        "/equal-two",
                        vec![equal_property],
                        AdditionalProperties::Allowed(None),
                    ),
                ])
                .is_some()
        );

        let first = object(
            "/conflict-one",
            vec![(
                "same".to_owned(),
                primitive(PrimitiveType::String, "/conflict-one/same"),
                prop_meta("/conflict-one/same"),
            )],
            AdditionalProperties::Allowed(None),
        );
        let mut required = prop_meta("/conflict-two/same");
        required.required = true;
        let second = object(
            "/conflict-two",
            vec![(
                "same".to_owned(),
                primitive(PrimitiveType::String, "/conflict-two/same"),
                required,
            )],
            AdditionalProperties::Allowed(None),
        );
        assert!(emitter.merge_all_of(&[first, second]).is_none());

        let target_ref = schema_ref("/target-ref", "/components/schemas/Target");
        let walk_schema = SchemaNode::AnyOf {
            branches: vec![
                object(
                    "/additional-ref",
                    Vec::new(),
                    AdditionalProperties::Allowed(Some(Box::new(target_ref.clone()))),
                ),
                SchemaNode::Tuple {
                    prefix_items: Vec::new(),
                    rest: TupleRest::Schema(Box::new(target_ref.clone())),
                    meta: meta("/rest-ref"),
                },
                SchemaNode::AllOf {
                    branches: vec![
                        object(
                            "/merge-ref-one",
                            Vec::new(),
                            AdditionalProperties::Allowed(Some(Box::new(target_ref.clone()))),
                        ),
                        object(
                            "/merge-ref-two",
                            Vec::new(),
                            AdditionalProperties::Allowed(Some(Box::new(target_ref))),
                        ),
                    ],
                    meta: meta("/merge-ref"),
                },
            ],
            meta: meta("/walk"),
        };
        let mut visits = 0;
        emitter.walk_refs(&walk_schema, TypePosition::Neutral, &mut |_| visits += 1);
        assert_eq!(visits, 3);

        let mut imports =
            BTreeMap::from([("target".to_owned(), BTreeSet::from(["Target".to_owned()]))]);
        let mut output = String::new();
        emitter.write_imports(&mut output, std::mem::take(&mut imports), "./");
        assert_eq!(output, "import type { Target } from \"./target\";\n\n");

        let described = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: Some(vec![json!("ready")]),
            const_value: None,
            meta: meta("/described-enum"),
        };
        let mut output = String::new();
        emitter.write_schema_declaration(
            &mut output,
            "Status",
            &described,
            TypePosition::Neutral,
            &source("/described-enum"),
        );
        assert!(output.contains("Ready to run."));
        assert_eq!(
            emitter.render_type(
                &SchemaNode::Finite {
                    enum_values: None,
                    const_value: None,
                    meta: meta("/empty-finite"),
                },
                TypePosition::Neutral,
                0,
            ),
            "unknown"
        );
    }

    #[test]
    fn unsafe_allocated_file_names_are_diagnosed_and_skipped() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/unsafe": {
                    "get": {
                        "operationId": "CON",
                        "responses": { "204": { "description": "none" } }
                    }
                }
            },
            "components": {
                "schemas": {
                    "CON": { "type": "string" },
                    "Safe": { "type": "string" }
                }
            }
        });
        let (files, diagnostics) = compile(
            document,
            json!({ "emit": { "banner": ["Generated safely."] } }),
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_FILE_NAME)
                .count(),
            2
        );
        assert_eq!(files.len(), 1);
        assert!(files[0].content.contains("// Generated safely.\n"));
    }

    #[test]
    fn operation_readonly_optional_unknown_media_and_example_docs_are_covered() {
        let mut request_schema = primitive(PrimitiveType::String, "/request/schema");
        if let SchemaNode::Primitive { meta, .. } = &mut request_schema {
            meta.docs.examples.push(json!({ "request": true }));
        }
        let mut response_schema = primitive(PrimitiveType::String, "/response/schema");
        if let SchemaNode::Primitive { meta, .. } = &mut response_schema {
            meta.docs.examples.push(json!(["response"]));
        }
        let rich = Operation {
            method: "post".to_owned(),
            path_template: Vec::new(),
            operation_id: Some("rich".to_owned()),
            summary: None,
            description: Some("Rich operation.".to_owned()),
            deprecated: false,
            external_docs: None,
            parameters: vec![Param {
                name: "filter".to_owned(),
                location: ParamLocation::Query,
                required: false,
                deprecated: false,
                description: Some("Optional filter.".to_owned()),
                schema: primitive(PrimitiveType::Boolean, "/parameter/filter"),
                source: source("/parameter/filter"),
            }],
            request_body: Some(Body {
                required: false,
                description: Some("Opaque body.".to_owned()),
                media_types: vec![MediaType {
                    name: "application/octet-stream".to_owned(),
                    schema: request_schema,
                    examples: vec![("sample".to_owned(), json!({ "bytes": 2 }))],
                    source: source("/request/media"),
                }],
                source: source("/request"),
            }),
            responses: vec![
                ResponseEntry {
                    status: ResponseStatus::Exact("200".to_owned()),
                    description: "Opaque response.".to_owned(),
                    media_types: vec![MediaType {
                        name: "application/octet-stream".to_owned(),
                        schema: response_schema,
                        examples: vec![("sample".to_owned(), json!({ "bytes": 3 }))],
                        source: source("/response/media"),
                    }],
                    source: source("/response"),
                },
                ResponseEntry {
                    status: ResponseStatus::Exact("204".to_owned()),
                    description: "Empty response.".to_owned(),
                    media_types: Vec::new(),
                    source: source("/response/empty"),
                },
            ],
            source: source("/operation/rich"),
        };
        let empty = Operation {
            method: "get".to_owned(),
            path_template: Vec::new(),
            operation_id: Some("empty".to_owned()),
            summary: None,
            description: None,
            deprecated: false,
            external_docs: None,
            parameters: Vec::new(),
            request_body: None,
            responses: Vec::new(),
            source: source("/operation/empty"),
        };
        let analyzed = Analyzed {
            ir: Ir {
                operations: vec![rich, empty],
                schemas: Vec::new(),
            },
            operation_names: vec![
                AllocatedOperationName {
                    operation_index: 0,
                    name: "rich".to_owned(),
                    source: source("/operation/rich"),
                },
                AllocatedOperationName {
                    operation_index: 1,
                    name: "empty".to_owned(),
                    source: source("/operation/empty"),
                },
            ],
            schema_names: Vec::new(),
            enum_members: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "readonly": true },
            "documentation": { "summary": false, "description": true }
        }));
        let mut sink = DiagnosticSink::new();
        let files = Emitter::new(&analyzed, &config, "digest".to_owned(), &mut sink).emit();
        assert!(sink.as_slice().is_empty());
        let rich = files
            .iter()
            .find(|file| file.relative_path.ends_with("rich.ts"))
            .expect("rich operation");
        for expected in [
            "readonly query?:",
            "Optional filter.",
            "Opaque body.",
            "readonly body?: unknown",
            "request body application/octet-stream",
            "Source: request body sample (application/octet-stream)",
            "Source: request body (application/octet-stream)",
            "Source: response 200 sample (application/octet-stream)",
            "Source: response 200 (application/octet-stream)",
            "export type RichResponse204 = null",
        ] {
            assert!(rich.content.contains(expected));
        }
        let empty = files
            .iter()
            .find(|file| file.relative_path.ends_with("empty.ts"))
            .expect("empty operation");
        assert!(empty.content.contains("export type EmptyResponse = never;"));

        let mut output = String::new();
        write_operation_tsdoc(
            &mut output,
            &analyzed.ir.operations[0],
            &DocumentationConfig {
                enabled: false,
                ..DocumentationConfig::default()
            },
            0,
        );
        assert!(output.is_empty());

        write_operation_tsdoc(
            &mut output,
            &analyzed.ir.operations[0],
            &DocumentationConfig {
                constraints: false,
                examples: false,
                ..DocumentationConfig::default()
            },
            0,
        );
        assert!(!output.is_empty());
    }

    #[test]
    fn string_property_and_additional_property_encoders_snapshot() {
        assert_eq!(
            render_ts_string("\"\\\n\u{2028}\u{2029}"),
            "\"\\\"\\\\\\n\\u2028\\u2029\""
        );
        assert_eq!(render_property_key("ok_$1"), "ok_$1");
        assert_eq!(render_property_key("not-ok"), "\"not-ok\"");

        let document = openapi(json!({
            "Open": { "type": "object", "properties": { "name": { "type": "string" } } },
            "Map": { "type": "object", "additionalProperties": { "type": "number" } },
            "Mixed": { "type": "object", "properties": { "name": { "type": "string" } }, "additionalProperties": { "type": "number" } },
            "Closed": { "type": "object", "additionalProperties": false, "properties": { "name": { "type": "string" } } }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let bodies = files
            .iter()
            .map(|file| (file.relative_path.as_str(), generated_body(file)))
            .collect::<BTreeMap<_, _>>();
        assert!(
            bodies["types/components/open.ts"]
                .contains("export interface Open {\n  name?: string;\n}")
        );
        assert!(!bodies["types/components/open.ts"].contains("[key: string]"));
        assert!(
            bodies["types/components/map.ts"]
                .contains("export type Map = { [key: string]: number };")
        );
        assert!(bodies["types/components/mixed.ts"].contains("} & Record<string, number>;"));
        assert!(bodies["types/components/closed.ts"].contains("export interface Closed"));
    }

    #[test]
    fn object_tuple_recursion_readonly_and_variants_snapshot() {
        let document = openapi(json!({
            "Pet": {
                "title": "Pet",
                "description": "A pet.",
                "type": "object",
                "required": ["id", "display-name", "children"],
                "properties": {
                    "id": { "type": ["integer", "null"] },
                    "display-name": { "type": "string", "default": "cat" },
                    "nickname": { "type": "string" },
                    "children": { "type": "array", "items": { "$ref": "#/components/schemas/Pet" } },
                    "serverId": { "type": "string", "readOnly": true },
                    "secret": { "type": "string", "writeOnly": true }
                }
            },
            "Pair": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "number" }],
                "items": false
            }
        }));
        let (files, diagnostics) = compile(document, json!({ "types": { "readonly": true } }));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert_eq!(
            generated_body(pet),
            concat!(
                "// Source: workspace/openapi.json#/components/schemas/Pet\n",
                "/**\n",
                " * Pet\n",
                " * \n",
                " * @remarks\n",
                " * A pet.\n",
                " */\n",
                "export interface Pet {\n",
                "  readonly id: number | null;\n",
                "  /**\n",
                "   * @defaultValue \"cat\"\n",
                "   */\n",
                "  readonly \"display-name\": string;\n",
                "  readonly nickname?: string;\n",
                "  readonly children: Pet[];\n",
                "  readonly serverId?: string;\n",
                "  readonly secret?: string;\n",
                "}\n",
                "// Source: workspace/openapi.json#/components/schemas/Pet\n",
                "/**\n",
                " * Pet\n",
                " * \n",
                " * @remarks\n",
                " * A pet.\n",
                " */\n",
                "export interface PetRequest {\n",
                "  readonly id: number | null;\n",
                "  /**\n",
                "   * @defaultValue \"cat\"\n",
                "   */\n",
                "  readonly \"display-name\": string;\n",
                "  readonly nickname?: string;\n",
                "  readonly children: PetRequest[];\n",
                "  readonly secret?: string;\n",
                "}\n",
                "// Source: workspace/openapi.json#/components/schemas/Pet\n",
                "/**\n",
                " * Pet\n",
                " * \n",
                " * @remarks\n",
                " * A pet.\n",
                " */\n",
                "export interface PetResponse {\n",
                "  readonly id: number | null;\n",
                "  /**\n",
                "   * @defaultValue \"cat\"\n",
                "   */\n",
                "  readonly \"display-name\": string;\n",
                "  readonly nickname?: string;\n",
                "  readonly children: PetResponse[];\n",
                "  readonly serverId?: string;\n",
                "}\n"
            )
        );
        let pair = files
            .iter()
            .find(|file| file.relative_path.ends_with("pair.ts"))
            .expect("Pair file");
        assert!(generated_body(pair).ends_with("export type Pair = [string, number];\n"));
    }

    #[test]
    fn enum_literal_and_const_forms_snapshot() {
        let document = openapi(json!({
            "PetStatus": { "type": ["string", "null"], "enum": ["available", "sold", null] }
        }));
        let (literal, diagnostics) = compile(document.clone(), json!({}));
        assert!(diagnostics.is_empty());
        assert!(
            generated_body(&literal[0])
                .ends_with("export type PetStatus = \"available\" | \"sold\" | null;\n")
        );
        let (constant, diagnostics) = compile(document, json!({ "types": { "enum": "const" } }));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(generated_body(&constant[0]).ends_with(concat!(
            "export const PetStatus = {\n",
            "  Available: \"available\",\n",
            "  Sold: \"sold\",\n",
            "  Null: null,\n",
            "} as const;\n\n",
            "// Source: workspace/openapi.json#/components/schemas/PetStatus\n",
            "export type PetStatus = (typeof PetStatus)[keyof typeof PetStatus];\n"
        )));
    }

    #[test]
    fn type_array_filters_finite_values_into_each_branch() {
        let document = openapi(json!({
            "Value": {
                "type": ["string", "integer"],
                "enum": ["a", 1]
            },
            "Constant": {
                "type": ["string", "integer"],
                "const": 1
            },
            "StringOnly": {
                "type": ["string", "integer"],
                "enum": ["only"]
            },
            "NullableConstant": {
                "type": ["string", "null"],
                "const": "x"
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let value = files
            .iter()
            .find(|file| file.relative_path.ends_with("value.ts"))
            .expect("Value file");
        assert!(generated_body(value).ends_with("export type Value = \"a\" | 1;\n"));
        let constant = files
            .iter()
            .find(|file| file.relative_path.ends_with("constant.ts"))
            .expect("Constant file");
        assert!(generated_body(constant).ends_with("export type Constant = 1;\n"));
        let string_only = files
            .iter()
            .find(|file| file.relative_path.ends_with("stringonly.ts"))
            .expect("StringOnly file");
        assert!(generated_body(string_only).ends_with("export type StringOnly = \"only\";\n"));
        let nullable_constant = files
            .iter()
            .find(|file| file.relative_path.ends_with("nullableconstant.ts"))
            .expect("NullableConstant file");
        assert!(
            generated_body(nullable_constant).ends_with("export type NullableConstant = \"x\";\n")
        );
    }

    #[test]
    fn typeless_enum_and_const_emit_literal_types_without_an_invented_domain() {
        let document = openapi(json!({
            "Choice": {
                "enum": ["a", 1, true, null, [1], { "x": 1 }]
            },
            "Exact": {
                "const": { "x": 1 }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let choice = files
            .iter()
            .find(|file| file.relative_path.ends_with("choice.ts"))
            .expect("Choice file");
        assert!(
            generated_body(choice)
                .ends_with("export type Choice = \"a\" | 1 | true | null | [1] | {\"x\":1};\n")
        );
        let exact = files
            .iter()
            .find(|file| file.relative_path.ends_with("exact.ts"))
            .expect("Exact file");
        assert!(generated_body(exact).ends_with("export type Exact = {\"x\":1};\n"));
    }

    #[test]
    fn one_of_discriminator_and_all_of_rendering_snapshot() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Animal": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }], "discriminator": { "propertyName": "kind" } },
            "Broken": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "type": "string" }], "discriminator": { "propertyName": "kind" } },
            "Merged": { "allOf": [
                { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } },
                { "type": "object", "properties": { "name": { "type": "string" } } }
            ] },
            "Intersected": { "allOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }] }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR)
                .count(),
            1
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == Severity::Warning)
                .count(),
            1
        );
        let animal = files
            .iter()
            .find(|file| file.relative_path.ends_with("animal.ts"))
            .expect("Animal");
        assert!(generated_body(animal).contains("export type Animal = Cat | Dog;"));
        let merged = files
            .iter()
            .find(|file| file.relative_path.ends_with("merged.ts"))
            .expect("Merged");
        assert!(
            generated_body(merged)
                .contains("export type Merged = {\n  id: string;\n  name?: string;\n};")
        );
        let intersection = files
            .iter()
            .find(|file| file.relative_path.ends_with("intersected.ts"))
            .expect("Intersected");
        assert!(generated_body(intersection).contains("export type Intersected = Cat & Dog;"));
    }

    #[test]
    fn all_of_contradiction_proofs_have_positive_and_negative_vectors() {
        let cases = [
            (
                json!({ "allOf": [{ "type": "string" }, { "type": "number" }] }),
                json!({ "allOf": [{ "type": "number" }, { "type": "integer" }] }),
                "disjoint primitive",
            ),
            (
                json!({ "allOf": [{ "type": "string", "enum": ["a"] }, { "type": "string", "const": "b" }] }),
                json!({ "allOf": [{ "type": "string", "enum": ["a", "b"] }, { "type": "string", "const": "b" }] }),
                "finite-enum",
            ),
            (
                json!({ "allOf": [{ "enum": ["a"] }, { "const": "b" }] }),
                json!({ "allOf": [{ "enum": ["a", "b"] }, { "const": "b" }] }),
                "finite-enum",
            ),
            (
                json!({ "allOf": [{ "type": "number", "minimum": 2 }, { "type": "number", "exclusiveMaximum": 2 }] }),
                json!({ "allOf": [{ "type": "number", "minimum": 2 }, { "type": "number", "maximum": 2 }] }),
                "numeric interval",
            ),
            (
                json!({ "allOf": [{ "type": "number", "minimum": 5, "exclusiveMinimum": 2 }, { "type": "number", "maximum": 4 }] }),
                json!({ "allOf": [{ "type": "number", "minimum": 2, "exclusiveMinimum": 5 }, { "type": "number", "minimum": 4 }] }),
                "numeric interval",
            ),
            (
                json!({ "allOf": [
                    { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } },
                    { "type": "object", "additionalProperties": false, "properties": {} }
                ] }),
                json!({ "allOf": [
                    { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } },
                    { "type": "object", "additionalProperties": false, "properties": { "id": { "type": "string" } } }
                ] }),
                "closed object",
            ),
        ];
        for (positive, negative, message) in cases {
            let (_, diagnostics) = compile(openapi(json!({ "Proof": positive })), json!({}));
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == CODE_COMPOSITION
                        && diagnostic.message.contains(message)),
                "{message}: {diagnostics:?}"
            );
            let (_, diagnostics) = compile(openapi(json!({ "NoProof": negative })), json!({}));
            assert!(diagnostics.is_empty(), "{message}: {diagnostics:?}");
        }

        let mut v30 = openapi(json!({
            "Proof": { "allOf": [
                { "type": "number", "minimum": 2, "exclusiveMinimum": true },
                { "type": "number", "maximum": 2 }
            ] }
        }));
        v30["openapi"] = json!("3.0.3");
        let (_, diagnostics) = compile(v30, json!({}));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_COMPOSITION && diagnostic.message.contains("numeric interval")
        }));
    }

    #[test]
    fn tsdoc_mapping_comment_encoder_and_toggles_snapshot() {
        let document = openapi(json!({
            "Hostile": {
                "title": "Hostile */ schema",
                "description": "{@link evil}\n}\n<tag>\nstray >\n@deprecated fake\nback\\slash\n//# sourceMappingURL=evil\n`{@safe}`\n```txt\n  */ {@safe}\n```",
                "deprecated": true,
                "default": { "x": 1 },
                "examples": [{ "x": "*/" }],
                "$comment": "private */ note",
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "A name.", "deprecated": true, "default": "n", "minLength": 1 }
                }
            },
            "Promoted": { "description": "Promoted description.", "type": "string" },
            "Bare": { "type": "boolean" }
        }));
        let (files, diagnostics) = compile(document.clone(), json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let hostile = files
            .iter()
            .find(|file| file.relative_path.ends_with("hostile.ts"))
            .expect("Hostile");
        let body = generated_body(hostile);
        for expected in [
            "Hostile *\\/ schema",
            "\\{@link evil\\}",
            "\\}",
            "\\<tag\\>",
            "stray >",
            "\\@deprecated fake",
            "back\\slash",
            "sourceMappingURL\\=evil",
            "`{@safe}`",
            "  *\\/ {@safe}",
            "@deprecated This schema is deprecated.",
            "Default value: {\"x\":1\\}",
            "@example",
            "@privateRemarks",
            "@defaultValue \"n\"",
            "Constraints",
            "- minLength: 1",
            "@deprecated This property is deprecated.",
        ] {
            assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
        }
        let promoted = files
            .iter()
            .find(|file| file.relative_path.ends_with("promoted.ts"))
            .expect("Promoted");
        assert!(generated_body(promoted).contains(" * Promoted description.\n"));
        let bare = files
            .iter()
            .find(|file| file.relative_path.ends_with("bare.ts"))
            .expect("Bare");
        assert!(!generated_body(bare).contains("/**"));

        let (disabled, diagnostics) =
            compile(document, json!({ "documentation": { "enabled": false } }));
        assert!(diagnostics.is_empty());
        assert!(
            disabled
                .iter()
                .all(|file| !generated_body(file).contains("/**"))
        );
        assert!(
            disabled
                .iter()
                .all(|file| generated_body(file).contains("// Source: "))
        );

        let (flags_off, diagnostics) = compile(
            openapi(json!({
                "Documented": {
                    "title": "Title",
                    "description": "Description",
                    "deprecated": true,
                    "examples": [1],
                    "minLength": 1,
                    "type": "string"
                }
            })),
            json!({
                "documentation": {
                    "summary": false,
                    "description": false,
                    "deprecated": false,
                    "examples": false,
                    "constraints": false
                }
            }),
        );
        assert!(diagnostics.is_empty());
        assert!(!generated_body(&flags_off[0]).contains("/**"));
    }

    #[test]
    fn comment_encoder_escapes_tag_position_at_signs_anywhere_in_prose() {
        assert_eq!(
            encode_comment_text("Contact us at @support for help"),
            "Contact us at \\@support for help"
        );
        assert_eq!(encode_comment_text("x @remarks y"), "x \\@remarks y");
        assert_eq!(
            encode_comment_text("@leading user@example.com @1 `x @remarks y`"),
            "\\@leading user@example.com @1 `x @remarks y`"
        );
        assert_eq!(
            encode_comment_text("```txt\nx @remarks y */\n```"),
            "```txt\nx @remarks y *\\/\n```"
        );
    }

    #[test]
    fn operation_request_response_imports_and_docs_snapshot() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/pets/{pet-id}": {
                    "get": {
                        "operationId": "get-pet",
                        "summary": "Get a pet",
                        "description": "Loads one pet.",
                        "deprecated": true,
                        "externalDocs": { "url": "https://example.test/pets", "description": "Pet docs" },
                        "parameters": [
                            { "name": "pet-id", "in": "path", "required": true, "description": "Pet id.", "schema": { "type": "string" } },
                            { "name": "x-mode", "in": "header", "deprecated": true, "schema": { "type": "string" } }
                        ],
                        "responses": {
                            "200": { "description": "A pet.", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" }, "example": { "name": "Milo" } } } },
                            "4XX": { "description": "Client error.", "content": { "text/plain": { "schema": { "type": "string" } } } },
                            "default": { "description": "Unknown.", "content": { "application/octet-stream": { "schema": { "type": "string" } } } }
                        }
                    }
                }
            },
            "components": { "schemas": { "Pet": { "type": "object", "properties": { "name": { "type": "string" } } } } }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = files
            .iter()
            .find(|file| file.relative_path.contains("operations"))
            .expect("operation");
        let body = generated_body(operation);
        for expected in [
            "import type { Pet } from \"../components/pet.js\";",
            "@deprecated This operation is deprecated.",
            "Responses",
            "- 200: A pet.",
            "@see {@link https://example.test/pets | Pet docs}",
            "Source: response 200 example (application/json)",
            "export type GetPetRequest = {",
            "\"pet-id\": string;",
            "@deprecated This parameter is deprecated.",
            "export type GetPetResponse200 = Pet;",
            "export type GetPetResponse4XX = string;",
            "export type GetPetResponseDefault = unknown;",
            "export type GetPetResponse = GetPetResponse200 | GetPetResponse4XX | GetPetResponseDefault;",
        ] {
            assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
        }
        assert!(!body.contains("@returns"));
        assert!(!body.contains("@default "));
        assert!(!body.contains("@summary"));
        assert!(!body.contains("@description"));
    }

    #[test]
    fn operation_description_promotion_and_unlabelled_external_docs_are_frozen() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/promoted": {
                    "get": {
                        "description": "Promoted operation description.",
                        "externalDocs": { "url": "https://example.test/reference" },
                        "responses": { "204": { "description": "No content." } }
                    }
                },
                "/bare": {
                    "post": {
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let promoted = files
            .iter()
            .find(|file| file.relative_path.ends_with("getpromoted.ts"))
            .expect("promoted operation");
        assert!(generated_body(promoted).contains(" * Promoted operation description.\n"));
        assert!(generated_body(promoted).contains("@see {@link https://example.test/reference}"));
        let bare = files
            .iter()
            .find(|file| file.relative_path.ends_with("postbare.ts"))
            .expect("bare operation");
        assert!(generated_body(bare).contains(" * @remarks\n * Responses\n"));
        assert!(!generated_body(bare).contains("operation for"));
    }

    #[test]
    fn unsupported_construct_stays_unknown() {
        let document = openapi(json!({ "Conditional": { "if": { "type": "string" } } }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1103")
        );
        assert!(generated_body(&files[0]).ends_with("export type Conditional = unknown;\n"));
    }

    #[test]
    fn official_fixtures_emit_deterministically() {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        for name in ["petstore-3.0", "tictactoe-3.1"] {
            let directory = fixture_root.join(name);
            let config = load_config(Some(&directory.join("oasts.yaml")), &directory)
                .expect("fixture config");
            let mut sink = DiagnosticSink::new();
            let graph = load_graph(&config, &mut sink).expect("fixture graph");
            let ir = parse(&graph, &mut sink).expect("fixture IR");
            let analyzed = analyze(ir, &config, &mut sink);
            let first = emit_types(&analyzed, &config, &graph.source_tuples(), &mut sink);
            let second = emit_types(&analyzed, &config, &graph.source_tuples(), &mut sink);
            let aliased = emit(&analyzed, &config, &graph.source_tuples(), &mut sink);
            assert!(!first.is_empty());
            assert_eq!(first, second);
            assert_eq!(first, aliased);
            assert!(!sink.has_errors(), "{name}: {:?}", sink.as_slice());
            for file in first {
                let lines = file.content.lines().collect::<Vec<_>>();
                assert_eq!(lines[0], "// Generated by Oasts 0.0.0. Do not edit.");
                assert_eq!(lines[1], "// Config schema version: 1");
                let digest = lines[2]
                    .strip_prefix("// Source digest: ")
                    .expect("digest header");
                assert_eq!(digest.len(), 64);
                assert!(
                    digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                );
                assert!(!file.content.contains("export enum"));
                assert!(!file.content.contains("const enum"));
                assert!(!file.content.contains("namespace "));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PrimitiveAtom {
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

struct ObjectShape<'a> {
    properties: &'a [(String, SchemaNode, PropMeta)],
    additional_properties: &'a AdditionalProperties,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct NumericBounds {
    lower: Option<Bound>,
    upper: Option<Bound>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Bound {
    value: f64,
    exclusive: bool,
}

impl NumericBounds {
    fn from_constraints(constraints: &NumericConstraints) -> Option<Self> {
        let minimum = constraints.minimum.as_ref().and_then(number_bound);
        let maximum = constraints.maximum.as_ref().and_then(number_bound);
        let exclusive_minimum = exclusive_bound(constraints.exclusive_minimum.as_ref(), minimum);
        let exclusive_maximum = exclusive_bound(constraints.exclusive_maximum.as_ref(), maximum);
        let lower = stricter_lower(minimum, exclusive_minimum);
        let upper = stricter_upper(maximum, exclusive_maximum);
        (lower.is_some() || upper.is_some()).then_some(Self { lower, upper })
    }

    fn intersect(self, other: Self) -> Self {
        Self {
            lower: stricter_lower(self.lower, other.lower),
            upper: stricter_upper(self.upper, other.upper),
        }
    }

    fn is_empty(self) -> bool {
        let (Some(lower), Some(upper)) = (self.lower, self.upper) else {
            return false;
        };
        lower.value > upper.value
            || (lower.value == upper.value && (lower.exclusive || upper.exclusive))
    }
}

fn number_bound(number: &serde_json::Number) -> Option<Bound> {
    number
        .as_f64()
        .filter(|value| value.is_finite())
        .map(|value| Bound {
            value,
            exclusive: false,
        })
}

fn exclusive_bound(exclusive: Option<&ExclusiveBound>, inclusive: Option<Bound>) -> Option<Bound> {
    match exclusive {
        Some(ExclusiveBound::Boolean(true)) => inclusive.map(|bound| Bound {
            exclusive: true,
            ..bound
        }),
        Some(ExclusiveBound::Number(number)) => number_bound(number).map(|bound| Bound {
            exclusive: true,
            ..bound
        }),
        Some(ExclusiveBound::Boolean(false)) | None => None,
    }
}

fn stricter_lower(left: Option<Bound>, right: Option<Bound>) -> Option<Bound> {
    match (left, right) {
        (None, bound) | (bound, None) => bound,
        (Some(left), Some(right)) if left.value > right.value => Some(left),
        (Some(left), Some(right)) if right.value > left.value => Some(right),
        (Some(left), Some(right)) => Some(Bound {
            value: left.value,
            exclusive: left.exclusive || right.exclusive,
        }),
    }
}

fn stricter_upper(left: Option<Bound>, right: Option<Bound>) -> Option<Bound> {
    match (left, right) {
        (None, bound) | (bound, None) => bound,
        (Some(left), Some(right)) if left.value < right.value => Some(left),
        (Some(left), Some(right)) if right.value < left.value => Some(right),
        (Some(left), Some(right)) => Some(Bound {
            value: left.value,
            exclusive: left.exclusive || right.exclusive,
        }),
    }
}

fn shape_variants(schema: &SchemaNode) -> (bool, bool) {
    let SchemaNode::Object { properties, .. } = schema else {
        return (false, false);
    };
    (
        properties.iter().any(|(_, _, meta)| meta.read_only),
        properties.iter().any(|(_, _, meta)| meta.write_only),
    )
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

fn warning_diagnostic(
    code: &'static str,
    message: impl Into<String>,
    source: &SourceRef,
) -> Diagnostic {
    let mut diagnostic = source_diagnostic(code, message, source);
    diagnostic.severity = Severity::Warning;
    diagnostic
}
