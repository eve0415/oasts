//! Normalization for composition schemas whose domains are provably empty.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, ExclusiveBound, Ir, NumericConstraints, Operation, PrimitiveType,
    PropMeta, SchemaNode, SchemaRef, SourceRef, TupleRest,
};

pub(crate) const CODE_COMPOSITION: &str = "OASTS1303";

/// Replaces every `allOf` proven empty with `Never`, preserving its source metadata and reporting
/// each independent proof as a warning. The proof pass is immutable so references can resolve
/// against a stable component table; a second tree walk performs the replacements.
pub(crate) fn lower_uninhabitable_all_ofs(ir: &mut Ir, sink: &mut DiagnosticSink) {
    let analysis = CompositionAnalysis::new(ir);
    let mut lowerings = HashSet::new();
    let mut diagnostics = Vec::new();
    analysis.inspect_ir(&mut lowerings, &mut diagnostics);
    drop(analysis);
    lower_ir(ir, &lowerings);
    sink.extend(diagnostics);
}

struct CompositionAnalysis<'ir> {
    ir: &'ir Ir,
    schemas: HashMap<(&'ir str, &'ir str), usize>,
}

impl<'ir> CompositionAnalysis<'ir> {
    fn new(ir: &'ir Ir) -> Self {
        let schemas = ir
            .schemas
            .iter()
            .enumerate()
            .map(|(index, schema)| {
                (
                    (
                        schema.source.source_id.as_str(),
                        schema.source.json_pointer.as_str(),
                    ),
                    index,
                )
            })
            .collect();
        Self { ir, schemas }
    }

    fn inspect_ir(&self, lowerings: &mut HashSet<SchemaRef>, diagnostics: &mut Vec<Diagnostic>) {
        for schema in &self.ir.schemas {
            self.inspect_schema(&schema.schema, lowerings, diagnostics);
        }
        for operation in &self.ir.operations {
            self.inspect_operation(operation, lowerings, diagnostics);
        }
        for webhook in &self.ir.webhooks {
            for operation in &webhook.operations {
                self.inspect_operation(operation, lowerings, diagnostics);
            }
        }
    }

    fn inspect_operation(
        &self,
        operation: &Operation,
        lowerings: &mut HashSet<SchemaRef>,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        for parameter in &operation.parameters {
            self.inspect_schema(&parameter.schema, lowerings, diagnostics);
        }
        if let Some(body) = &operation.request_body {
            for media_type in &body.media_types {
                self.inspect_media_type(media_type, lowerings, diagnostics);
            }
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                self.inspect_media_type(media_type, lowerings, diagnostics);
            }
            for (_, header) in &response.headers {
                self.inspect_schema(&header.schema, lowerings, diagnostics);
            }
        }
        for callback in &operation.callbacks {
            for expression in &callback.expressions {
                for operation in &expression.operations {
                    self.inspect_operation(operation, lowerings, diagnostics);
                }
            }
        }
    }

    fn inspect_media_type(
        &self,
        media_type: &crate::ir::MediaType,
        lowerings: &mut HashSet<SchemaRef>,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        self.inspect_schema(&media_type.schema, lowerings, diagnostics);
        for (_, encoding) in &media_type.encodings {
            for (_, header) in &encoding.headers {
                self.inspect_schema(&header.schema, lowerings, diagnostics);
            }
        }
    }

    fn inspect_schema(
        &self,
        schema: &SchemaNode,
        lowerings: &mut HashSet<SchemaRef>,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        if let SchemaNode::AllOf { branches, meta } = schema {
            let messages = self.prove_empty(branches);
            if !messages.is_empty() {
                lowerings.insert(source_key(&meta.source));
            }
            diagnostics.extend(
                messages
                    .into_iter()
                    .map(|message| warning_diagnostic(message, &meta.source)),
            );
        }
        match schema {
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                for (_, property, _) in properties {
                    self.inspect_schema(property, lowerings, diagnostics);
                }
                if let AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) = additional_properties
                {
                    self.inspect_schema(schema, lowerings, diagnostics);
                }
            }
            SchemaNode::Array { items, .. } => {
                self.inspect_schema(items, lowerings, diagnostics);
            }
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for item in prefix_items {
                    self.inspect_schema(item, lowerings, diagnostics);
                }
                if let TupleRest::Schema(schema) = rest {
                    self.inspect_schema(schema, lowerings, diagnostics);
                }
            }
            SchemaNode::AllOf { branches, .. }
            | SchemaNode::OneOf { branches, .. }
            | SchemaNode::AnyOf { branches, .. } => {
                for branch in branches {
                    self.inspect_schema(branch, lowerings, diagnostics);
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

    fn prove_empty(&self, branches: &[SchemaNode]) -> Vec<String> {
        let mut messages = Vec::new();
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
                messages.push("allOf has disjoint primitive type sets".to_owned());
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
                messages.push("allOf has incompatible const or finite-enum constraints".to_owned());
            }
        }

        let bounds = branches
            .iter()
            .filter_map(|branch| self.numeric_bounds(branch, &mut HashSet::new()))
            .collect::<Vec<_>>();
        if let Some(combined) = bounds.into_iter().reduce(NumericBounds::intersect)
            && combined.is_empty()
        {
            messages.push("allOf has an empty numeric interval".to_owned());
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
                    messages.push(format!(
                        "allOf requires property '{}' that a closed object branch forbids",
                        name
                    ));
                }
            }
        }
        messages
    }

    fn resolve_ref<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<&'a SchemaNode> {
        let SchemaNode::Ref { target, .. } = schema else {
            return Some(schema);
        };
        let key = (target.source_id.as_str(), target.json_pointer.as_str());
        if !visited.insert(key) {
            return None;
        }
        let index = self.schemas.get(&key)?;
        let resolved = &self.ir.schemas.get(*index)?.schema;
        self.resolve_ref(resolved, visited)
    }

    fn primitive_domain<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
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

    fn finite_constraint<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
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

    fn numeric_bounds<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<NumericBounds> {
        let schema = self.resolve_ref(schema, visited)?;
        let SchemaNode::Primitive { ty, meta, .. } = schema else {
            return None;
        };
        if !matches!(ty, PrimitiveType::Number | PrimitiveType::Integer) {
            return None;
        }
        NumericBounds::from_constraints(meta.numeric_constraints())
    }

    fn object_shape<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
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
}

fn lower_ir(ir: &mut Ir, lowerings: &HashSet<SchemaRef>) {
    for schema in &mut ir.schemas {
        lower_schema(&mut schema.schema, lowerings);
    }
    for operation in &mut ir.operations {
        lower_operation(operation, lowerings);
    }
    for webhook in &mut ir.webhooks {
        for operation in &mut webhook.operations {
            lower_operation(operation, lowerings);
        }
    }
}

fn lower_operation(operation: &mut Operation, lowerings: &HashSet<SchemaRef>) {
    for parameter in &mut operation.parameters {
        lower_schema(&mut parameter.schema, lowerings);
    }
    if let Some(body) = &mut operation.request_body {
        for media_type in &mut body.media_types {
            lower_media_type(media_type, lowerings);
        }
    }
    for response in &mut operation.responses {
        for media_type in &mut response.media_types {
            lower_media_type(media_type, lowerings);
        }
        for (_, header) in &mut response.headers {
            lower_schema(&mut header.schema, lowerings);
        }
    }
    for callback in &mut operation.callbacks {
        for expression in &mut callback.expressions {
            for operation in &mut expression.operations {
                lower_operation(operation, lowerings);
            }
        }
    }
}

fn lower_media_type(media_type: &mut crate::ir::MediaType, lowerings: &HashSet<SchemaRef>) {
    lower_schema(&mut media_type.schema, lowerings);
    for (_, encoding) in &mut media_type.encodings {
        for (_, header) in &mut encoding.headers {
            lower_schema(&mut header.schema, lowerings);
        }
    }
}

fn lower_schema(schema: &mut SchemaNode, lowerings: &HashSet<SchemaRef>) {
    if matches!(schema, SchemaNode::AllOf { meta, .. } if lowerings.contains(&source_key(&meta.source)))
    {
        let mut meta = schema.meta().clone();
        meta.nullable = false;
        *schema = SchemaNode::Never { meta };
        return;
    }
    match schema {
        SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } => {
            for (_, property, _) in properties {
                lower_schema(property, lowerings);
            }
            if let AdditionalProperties::Allowed(Some(schema))
            | AdditionalProperties::Schema(schema) = additional_properties
            {
                lower_schema(schema, lowerings);
            }
        }
        SchemaNode::Array { items, .. } => lower_schema(items, lowerings),
        SchemaNode::Tuple {
            prefix_items, rest, ..
        } => {
            for item in prefix_items {
                lower_schema(item, lowerings);
            }
            if let TupleRest::Schema(schema) = rest {
                lower_schema(schema, lowerings);
            }
        }
        SchemaNode::AllOf { branches, .. }
        | SchemaNode::OneOf { branches, .. }
        | SchemaNode::AnyOf { branches, .. } => {
            for branch in branches {
                lower_schema(branch, lowerings);
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

fn source_key(source: &SourceRef) -> SchemaRef {
    SchemaRef {
        source_id: source.source_id.clone(),
        json_pointer: source.json_pointer.clone(),
    }
}

fn warning_diagnostic(message: impl Into<String>, source: &SourceRef) -> Diagnostic {
    let mut diagnostic = Diagnostic::input(CODE_COMPOSITION, message)
        .with_source(&source.source_id)
        .with_json_pointer(&source.json_pointer);
    diagnostic.severity = Severity::Warning;
    if let (Some(line), Some(col)) = (source.line, source.col) {
        diagnostic = diagnostic.with_location(line, col);
    }
    diagnostic
}

pub(crate) fn finite_values(
    enum_values: Option<&[Value]>,
    const_value: Option<&Value>,
) -> Option<Vec<Value>> {
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

pub(crate) fn json_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .is_some_and(|(left, right)| left == right),
        _ => left == right,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{NamedSchema, SchemaMeta};

    fn meta(pointer: &str) -> SchemaMeta {
        SchemaMeta {
            source: SourceRef {
                source_id: "workspace/openapi.json".to_owned(),
                json_pointer: pointer.to_owned(),
                line: Some(3),
                col: Some(5),
            },
            ..SchemaMeta::default()
        }
    }

    #[test]
    fn primitive_proof_handles_null_nullable_and_reference_cycles() {
        let self_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "workspace/openapi.json".to_owned(),
                json_pointer: "/components/schemas/Loop".to_owned(),
            },
            meta: meta("/components/schemas/Loop"),
        };
        let ir = Ir {
            schemas: vec![NamedSchema {
                name: "Loop".to_owned(),
                schema: self_ref.clone(),
                source: meta("/components/schemas/Loop").source,
            }],
            ..Ir::default()
        };
        let analysis = CompositionAnalysis::new(&ir);
        assert!(
            analysis
                .primitive_domain(&self_ref, &mut HashSet::new())
                .is_none()
        );

        let null = SchemaNode::Primitive {
            ty: PrimitiveType::Null,
            format: None,
            enum_values: None,
            const_value: None,
            meta: meta("/null"),
        };
        assert!(
            analysis
                .primitive_domain(&null, &mut HashSet::new())
                .expect("null domain")
                .contains(&PrimitiveAtom::Null)
        );
        let mut nullable = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: None,
            const_value: None,
            meta: meta("/nullable"),
        };
        if let SchemaNode::Primitive { meta, .. } = &mut nullable {
            meta.nullable = true;
        }
        assert!(
            analysis
                .primitive_domain(&nullable, &mut HashSet::new())
                .expect("nullable domain")
                .contains(&PrimitiveAtom::Null)
        );

        let diagnostic = warning_diagnostic("proof", &meta("/proof").source);
        assert_eq!((diagnostic.line, diagnostic.col), (Some(3), Some(5)));
    }
}
