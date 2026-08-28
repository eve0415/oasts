//! Deterministic standalone Zod artifact emission.
//!
//! Every generated module owns its structural types and imports only Zod, the embedded check
//! kernel, and sibling Zod modules. Component references stay named and deferred so recursive
//! graphs compile without widening their output types.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::composition::finite_values;
use crate::config::ZodFlavor;
use crate::diag::Diagnostic;
use crate::ir::{
    AdditionalProperties, ExclusiveBound, Operation, PrimitiveType, PropMeta, ResponseEntry,
    SchemaMeta, SchemaNode, SourceRef, TupleRest, finite_parts,
};
use crate::num::render_number_value;
use crate::response_media::media_has_validatable_schema;

use super::descriptor_index::{
    DescriptorTarget, Reject, SiblingImports, collect_operation_rejects, collect_rejects,
    embedded_asset, emit_callbacks_index, emit_webhooks_index, render_sibling_imports,
};
use super::model::{EmissionModel, Registrar};
use super::validators::{
    CODE_MEDIA_TAG_COLLISION, identical_component_delegate, operation_parameter_validator_names,
    validator_wire_type_name,
};
use super::{
    Emission, Emitter, EmitterFactory, GeneratedFile, ObjectKeyMode, OperationModule, TypeAxis,
    TypePosition, callback_operation, emit_in_parallel, import_extension, lowercase_first,
    merge_emission, property_in_position, render_json_compact, render_ts_string,
    request_body_validator_positions, response_media_names, response_status_type_suffix,
    source_diagnostic, uppercase_first, warning_diagnostic,
};
use crate::client_model::{PrimitiveDomainProjector, build_body_plan};
use crate::semantic::{AllocatedOperationName, AllocatedSchemaName};
use rayon::prelude::*;

const ZOD_RUNTIME_TS: &str = include_str!("../../runtime/zod-runtime.ts");
#[cfg(test)]
const VALIDATORS_RUNTIME_TS: &str = include_str!("../../runtime/validators-runtime.ts");

/// A schema carries a validation keyword the Zod artifact does not implement.
const CODE_REJECTED_KEYWORD: &str = "OASTS6101";
/// A schema degraded to an unknown leaf, so no faithful Zod schema can be emitted.
const CODE_UNKNOWN_LEAF: &str = "OASTS6102";

/// The diagnostic this artifact raises for one node the shared reject walk found no check for.
fn reject_diagnostic(reject: Reject<'_>, source: &SourceRef) -> Diagnostic {
    match reject {
        Reject::Keyword(keyword) => source_diagnostic(
            CODE_REJECTED_KEYWORD,
            format!("zod cannot emit a check for unsupported validation keyword '{keyword}'"),
            source,
        ),
        Reject::UnknownLeaf(reason) => source_diagnostic(
            CODE_UNKNOWN_LEAF,
            format!("zod cannot emit a check for an unsupported schema ({reason})"),
            source,
        ),
    }
}

const ZOD_RESERVED_NAMES: &[&str] = &[
    "z",
    "integer",
    "minLength",
    "maxLength",
    "pattern",
    "multipleOf",
    "stringFormat",
    "int32",
    "int64Wire",
    "enumValues",
    "constValue",
    "uniqueItems",
    "contains",
    "propertyCount",
    "dependentRequired",
    "dependentSchemas",
    "propertyNames",
    "patternProperties",
    "conditional",
    "not",
    "oneOf",
    "unevaluatedProperties",
    "unevaluatedItems",
    "isDateTime",
    "isDate",
    "isTime",
    "isUuid",
    // Injected by every module's `validate{Name}` entry point. A component named `Issue` would
    // otherwise shadow the imported type (TS2440) — GitHub declares exactly that one.
    "Issue",
    "collect",
    "headers",
];

pub(crate) fn emit_zod_from_model(
    model: &mut EmissionModel<'_>,
    registrar: &mut Registrar<'_>,
) -> Vec<GeneratedFile> {
    let analyzed = model.analyzed;
    // Built once per document, never per operation: this indexes every schema in the IR and
    // walks each one's projection dependencies, so constructing it inside the operation loop
    // would make request-body planning cost O(operations x schemas).
    let projector = PrimitiveDomainProjector::new(&analyzed.ir);
    let mut rejects = Vec::new();
    let target = DescriptorTarget {
        dir: model.dirs.zod,
        export_suffix: "Schema",
    };
    {
        let emitter = Emitter::new(model);
        for schema in &analyzed.ir.schemas {
            collect_rejects(&emitter, &schema.schema, reject_diagnostic, &mut rejects);
        }
        for operation in &analyzed.ir.operations {
            collect_operation_rejects(&emitter, operation, true, reject_diagnostic, &mut rejects);
        }
        for webhook in &analyzed.ir.webhooks {
            for operation in &webhook.operations {
                collect_operation_rejects(
                    &emitter,
                    operation,
                    false,
                    reject_diagnostic,
                    &mut rejects,
                );
            }
        }
        for allocated in &analyzed.callback_names {
            let operation = callback_operation(&analyzed.ir, &analyzed.callback_names, allocated);
            collect_operation_rejects(&emitter, operation, false, reject_diagnostic, &mut rejects);
        }
    }
    registrar.sink.extend(rejects);
    model.reserve_names(ZOD_RESERVED_NAMES);
    // Every rename this artifact performs is done. From here the allocation is frozen, so the model
    // is reborrowed shared for the whole emission — which is what lets one emitter factory span the
    // loops below while diagnostics and path registrations still flow through the registrar.
    let model = &*model;
    // One factory for the artifact, rather than the four `Emitter::new` rebuilds this emitter used
    // to pay — three per item plus one per int64 schema node. Each rebuild reindexed every enum
    // member; `worker()` still hands each item its own empty alias and diagnostic cells.
    let factory = Emitter::new(model).into_factory();

    let mut files = vec![embedded_asset(
        model,
        registrar,
        target,
        "runtime.ts",
        ZOD_RUNTIME_TS,
    )];
    // Each of the four loops below builds one module per item from the frozen model, then hands the
    // ordered result to a sequential merge. Nothing an item emits is read by the next one, so the
    // loop divides; replaying the collected emissions in input order is the sequence the
    // sequential branch produced, registration for registration and diagnostic for diagnostic.
    let component = |allocated: &AllocatedSchemaName| {
        let file_base = model.component_files[allocated.schema_index].as_deref()?;
        let schema = &analyzed.ir.schemas[allocated.schema_index];
        // A component file and its target are registered together during path allocation.
        let name = model
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .map(|target| target.name.clone())
            .expect("a component with an allocated file has a registered target");
        let mut emission = Emission::default();
        emit_component(
            model,
            &factory,
            &mut emission,
            allocated.schema_index,
            file_base,
            &name,
        );
        Some(emission)
    };
    let schema_names = &analyzed.schema_names;
    let emissions = if emit_in_parallel(schema_names.len()) {
        schema_names
            .par_iter()
            .filter_map(component)
            .collect::<Vec<_>>()
    } else {
        schema_names
            .iter()
            .filter_map(component)
            .collect::<Vec<_>>()
    };
    for emission in emissions {
        merge_emission(&mut files, registrar, emission);
    }
    let operation = |allocated: &AllocatedOperationName| {
        let mut emission = Emission::default();
        emit_operation(
            model,
            &factory,
            &mut emission,
            &projector,
            allocated.operation_index,
            &allocated.name,
        );
        emission
    };
    let operation_names = &analyzed.operation_names;
    let emissions = if emit_in_parallel(operation_names.len()) {
        operation_names
            .par_iter()
            .map(operation)
            .collect::<Vec<_>>()
    } else {
        operation_names.iter().map(operation).collect::<Vec<_>>()
    };
    for emission in emissions {
        merge_emission(&mut files, registrar, emission);
    }
    if !analyzed.ir.webhooks.is_empty() {
        let webhook = |index: usize| {
            let file_base = model.webhook_files[index].as_deref()?;
            let allocated = &analyzed.webhook_names[index];
            let operation = &analyzed.ir.webhooks[allocated.webhook_index].operations
                [allocated.operation_index];
            let mut emission = Emission::default();
            emit_operation_file(
                model,
                &factory,
                &mut emission,
                &projector,
                operation,
                OperationModule {
                    allocated_name: &allocated.stem,
                    directory: "webhooks",
                    file_base,
                    include_responses: false,
                },
            );
            Some(emission)
        };
        let webhook_count = analyzed.webhook_names.len();
        let emissions = if emit_in_parallel(webhook_count) {
            (0..webhook_count)
                .into_par_iter()
                .filter_map(webhook)
                .collect::<Vec<_>>()
        } else {
            (0..webhook_count).filter_map(webhook).collect::<Vec<_>>()
        };
        for emission in emissions {
            merge_emission(&mut files, registrar, emission);
        }
        files.push(emit_webhooks_index(model, target));
    }
    if !analyzed.callback_names.is_empty() {
        let callback = |index: usize| {
            let file_base = model.callback_files[index].as_deref()?;
            let allocated = &analyzed.callback_names[index];
            let operation = callback_operation(&analyzed.ir, &analyzed.callback_names, allocated);
            let mut emission = Emission::default();
            emit_operation_file(
                model,
                &factory,
                &mut emission,
                &projector,
                operation,
                OperationModule {
                    allocated_name: &allocated.stem,
                    directory: "callbacks",
                    file_base,
                    include_responses: false,
                },
            );
            Some(emission)
        };
        let callback_count = analyzed.callback_names.len();
        let emissions = if emit_in_parallel(callback_count) {
            (0..callback_count)
                .into_par_iter()
                .filter_map(callback)
                .collect::<Vec<_>>()
        } else {
            (0..callback_count).filter_map(callback).collect::<Vec<_>>()
        };
        for emission in emissions {
            merge_emission(&mut files, registrar, emission);
        }
        files.push(emit_callbacks_index(model, target));
    }
    files
}

struct SchemaRenderer<'a, 'input> {
    model: &'a EmissionModel<'input>,
    /// The artifact's one emitter factory. `render_bigint_int64` needs a types emitter per int64
    /// node to spell the wire type; a worker off this factory is that emitter without reindexing
    /// every enum member for each node.
    factory: &'a EmitterFactory<'a, 'input>,
    position: TypePosition,
    current_schema: Option<usize>,
    current_schema_name: &'a str,
    runtime_values: &'a mut BTreeSet<&'static str>,
    imports: &'a mut SiblingImports,
    /// Set when this component reaches itself across a `z.lazy` thunk.
    ///
    /// TypeScript resolves a cycle closed by property getters unaided, and refuses one closed by a
    /// thunk (TS7022) — so the thunk is the only edge that makes the explicit schema annotation
    /// load-bearing. Recorded here, at the site that *chose* getter or thunk, because that choice
    /// is not recoverable from the rendered text: a `z.lazy` for a sibling that never refers back
    /// is not on any cycle, and treating it as one puts the annotation back on the ordinary
    /// recursive component — reinstating the very `exactOptionalPropertyTypes` failure the absent
    /// annotation exists to avoid.
    lazy_closes_cycle: &'a mut bool,
}

impl<'a, 'input> SchemaRenderer<'a, 'input> {
    fn render(&mut self, schema: &SchemaNode) -> String {
        self.render_deferred(schema, false)
    }

    fn render_deferred(&mut self, schema: &SchemaNode, self_is_deferred: bool) -> String {
        let mut expression = match schema {
            SchemaNode::Ref { target, .. } => {
                let Some(target) = self
                    .model
                    .schema_target(&target.source_id, &target.json_pointer)
                else {
                    return "z.unknown()".to_owned();
                };
                let type_name = target.variant_name(self.position);
                let schema_name = schema_const_name(&type_name);
                if Some(target.index) == self.current_schema {
                    if self_is_deferred {
                        self.current_schema_name.to_owned()
                    } else {
                        // A self reference with nothing to defer it: the thunk is the cycle.
                        *self.lazy_closes_cycle = true;
                        format!("z.lazy(() => {})", self.current_schema_name)
                    }
                } else {
                    self.imports.record_export(
                        target.index,
                        &target.file_base,
                        schema_name.clone(),
                    );
                    if let Some(current) = self.current_schema
                        && reaches_component(
                            self.model,
                            &self.model.analyzed.ir.schemas[target.index].schema,
                            current,
                            &mut BTreeSet::new(),
                        )
                    {
                        // The sibling refers back, so this thunk sits on a cycle through us.
                        *self.lazy_closes_cycle = true;
                    }
                    format!("z.lazy(() => {schema_name})")
                }
            }
            SchemaNode::Primitive {
                ty,
                format,
                enum_values,
                const_value,
                meta,
            } => {
                if self.model.transform_facts().site(schema)
                    == Some(crate::transform::TransformKind::IntegerBigInt)
                {
                    self.render_bigint_int64(schema, meta)
                } else {
                    self.render_primitive(
                        *ty,
                        format.as_deref(),
                        enum_values.as_deref(),
                        const_value.as_ref(),
                        meta,
                        schema.is_nullable(),
                    )
                }
            }
            SchemaNode::Finite {
                enum_values,
                const_value,
                ..
            } => self.render_finite(enum_values.as_deref(), const_value.as_ref()),
            SchemaNode::Object {
                properties,
                additional_properties,
                dependent_required,
                finite,
                extra_required,
                meta,
            } => {
                let mut object = self.render_object(
                    properties,
                    additional_properties,
                    extra_required,
                    meta,
                    self_is_deferred,
                );
                if !dependent_required.is_empty() {
                    self.runtime_values.insert("dependentRequired");
                    object = check(
                        object,
                        &format!(
                            "dependentRequired([{}])",
                            dependent_required
                                .iter()
                                .map(|(trigger, required)| format!(
                                    "[{},[{}]]",
                                    render_ts_string(trigger),
                                    required
                                        .iter()
                                        .map(|name| render_ts_string(name))
                                        .collect::<Vec<_>>()
                                        .join(",")
                                ))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    );
                }
                let (enum_values, const_value) = finite_parts(finite);
                self.apply_finite_checks(object, enum_values, const_value)
            }
            SchemaNode::Array {
                items,
                finite,
                meta,
                ..
            } => {
                let item = self.render_deferred(items, self_is_deferred);
                let array = self.apply_array_constraints(format!("z.array({item})"), meta);
                let (enum_values, const_value) = finite_parts(finite);
                self.apply_finite_checks(array, enum_values, const_value)
            }
            SchemaNode::Tuple {
                prefix_items,
                rest,
                finite,
                meta,
            } => {
                let items = prefix_items
                    .iter()
                    .map(|item| optional(self.render_deferred(item, self_is_deferred)))
                    .collect::<Vec<_>>()
                    .join(",");
                let tuple = match rest {
                    TupleRest::Allowed => format!("z.tuple([{items}], z.unknown())"),
                    TupleRest::Forbidden => format!("z.tuple([{items}])"),
                    TupleRest::Schema(schema) => format!(
                        "z.tuple([{items}], {})",
                        self.render_deferred(schema, self_is_deferred)
                    ),
                };
                let tuple = self.apply_tuple_constraints(tuple, meta);
                let (enum_values, const_value) = finite_parts(finite);
                self.apply_finite_checks(tuple, enum_values, const_value)
            }
            SchemaNode::AllOf { branches, .. } => {
                let rendered = branches
                    .iter()
                    .map(|branch| self.render_deferred(branch, self_is_deferred))
                    .collect::<Vec<_>>();
                intersection(rendered)
            }
            SchemaNode::AnyOf { branches, .. } => {
                let rendered = branches
                    .iter()
                    .map(|branch| self.render_deferred(branch, self_is_deferred))
                    .collect::<Vec<_>>();
                union(rendered)
            }
            SchemaNode::OneOf { branches, .. } => {
                let rendered = branches
                    .iter()
                    .map(|branch| self.render_deferred(branch, self_is_deferred))
                    .collect::<Vec<_>>();
                let base = union(rendered.clone());
                self.runtime_values.insert("oneOf");
                check(base, &format!("oneOf([{}])", rendered.join(",")))
            }
            SchemaNode::Any { meta } => self.render_typeless(meta, self_is_deferred),
            SchemaNode::Never { .. } => "z.never()".to_owned(),
            SchemaNode::Unknown { .. } => "z.unknown()".to_owned(),
        };

        let (enum_values, const_value) = node_finite_values(schema);
        let has_finite = enum_values.is_some() || const_value.is_some();
        // A primitive already widened its own domain, and a `Finite` node's union *is* its
        // admissible set — for both, the finite values decide whether null is allowed, so a null
        // branch bolted on here would only re-admit what the enum excluded.
        let finite_owns_null = has_finite
            && matches!(
                schema,
                SchemaNode::Primitive { .. } | SchemaNode::Finite { .. }
            );
        if schema.is_nullable()
            && !finite_owns_null
            && !matches!(
                schema,
                SchemaNode::Primitive {
                    ty: PrimitiveType::Null,
                    ..
                }
            )
        {
            expression = format!("z.union([{expression},z.null()])");
            // A finite `enum`/`const` decides the admissible set on its own, so it has to see the
            // null the union just admitted — otherwise `nullable: true` alongside an enum that does
            // not list null would accept null, where the generated engine applies its enum check
            // unconditionally and rejects it. Re-applying outside the union costs no duplicate
            // issue: zod suppresses a node's checks when the base fails, so the outer check runs
            // only on a value the union already accepted.
            if has_finite {
                expression = self.apply_finite_checks(expression, enum_values, const_value);
            }
        }
        self.apply_applicators(expression, schema, self_is_deferred)
    }

    fn render_primitive(
        &mut self,
        ty: PrimitiveType,
        format: Option<&str>,
        enum_values: Option<&[Value]>,
        const_value: Option<&Value>,
        meta: &SchemaMeta,
        nullable: bool,
    ) -> String {
        let domain = match ty {
            PrimitiveType::String => {
                self.apply_string_constraints("z.string()".to_owned(), format, meta)
            }
            PrimitiveType::Number => self.apply_number_constraints("z.number()".to_owned(), meta),
            PrimitiveType::Integer => {
                self.runtime_values.insert("integer");
                let number = check("z.number()".to_owned(), "integer()");
                let number = self.apply_number_constraints(number, meta);
                if format == Some("int32") {
                    self.runtime_values.insert("int32");
                    check(number, "int32()")
                } else {
                    number
                }
            }
            PrimitiveType::Boolean => "z.boolean()".to_owned(),
            PrimitiveType::Null => "z.null()".to_owned(),
        };
        let Some(values) = finite_values(enum_values, const_value) else {
            return domain;
        };
        // A nullable node widens its own domain here rather than letting the caller union `z.null()`
        // around the finished expression. The finite set is what decides whether null is admissible,
        // and intersecting against it both rejects a null the enum does not list and keeps `null` out
        // of the inferred output type — which the caller's outer union could not do, because a
        // `.check()` narrows no types.
        let domain = if nullable {
            format!("z.union([{domain},z.null()])")
        } else {
            domain
        };
        let finite = self.render_json_value_union(&values);
        let constrained = if values.is_empty() {
            finite
        } else {
            format!("z.intersection({domain},{finite})")
        };
        self.apply_finite_checks(constrained, enum_values, const_value)
    }

    fn render_bigint_int64(&mut self, schema: &SchemaNode, meta: &SchemaMeta) -> String {
        self.runtime_values.insert("int64Wire");
        let type_expression =
            self.factory
                .worker()
                .render_type(schema, self.position, TypeAxis::Wire, 0);
        let expression = format!("z.custom<{type_expression}>()");
        let constraints = meta.numeric_constraints();
        let has_constraints = constraints.minimum.is_some()
            || constraints.maximum.is_some()
            || constraints.exclusive_minimum.is_some()
            || constraints.exclusive_maximum.is_some()
            || constraints.multiple_of.is_some();
        if has_constraints {
            let bigint = self.apply_bigint_constraints("z.custom<bigint>()".to_owned(), meta);
            check(expression, &format!("int64Wire({bigint})"))
        } else {
            check(expression, "int64Wire()")
        }
    }

    fn apply_string_constraints(
        &mut self,
        mut expression: String,
        format: Option<&str>,
        meta: &SchemaMeta,
    ) -> String {
        let constraints = meta.string_constraints();
        if let Some(minimum) = constraints.min_length {
            self.runtime_values.insert("minLength");
            expression = check(expression, &format!("minLength({minimum})"));
        }
        if let Some(maximum) = constraints.max_length {
            self.runtime_values.insert("maxLength");
            expression = check(expression, &format!("maxLength({maximum})"));
        }
        if let Some(pattern_value) = &constraints.pattern {
            self.runtime_values.insert("pattern");
            expression = check(
                expression,
                &format!("pattern(new RegExp({}))", render_ts_string(pattern_value)),
            );
        }
        if let Some((predicate, name)) = format.and_then(string_format) {
            self.runtime_values.insert("stringFormat");
            self.runtime_values.insert(predicate);
            expression = check(
                expression,
                &format!("stringFormat({predicate},{})", render_ts_string(name)),
            );
        }
        expression
    }

    fn apply_number_constraints(&mut self, mut expression: String, meta: &SchemaMeta) -> String {
        let constraints = meta.numeric_constraints();
        expression = apply_lower_bound(expression, constraints);
        expression = apply_upper_bound(expression, constraints);
        if let Some(divisor) = &constraints.multiple_of {
            self.runtime_values.insert("multipleOf");
            expression = check(
                expression,
                &format!("multipleOf({})", render_number_value(divisor)),
            );
        }
        expression
    }

    fn apply_bigint_constraints(&mut self, mut expression: String, meta: &SchemaMeta) -> String {
        let constraints = meta.numeric_constraints();
        expression = self.apply_bigint_bound(
            expression,
            constraints.exclusive_minimum.as_ref(),
            constraints.minimum.as_ref(),
            "bigintMinimum",
        );
        expression = self.apply_bigint_bound(
            expression,
            constraints.exclusive_maximum.as_ref(),
            constraints.maximum.as_ref(),
            "bigintMaximum",
        );
        if let Some(divisor) = &constraints.multiple_of {
            self.runtime_values.insert("bigintMultipleOf");
            expression = check(
                expression,
                &format!("bigintMultipleOf({})", render_number_value(divisor)),
            );
        }
        expression
    }

    fn apply_bigint_bound(
        &mut self,
        mut expression: String,
        exclusive: Option<&ExclusiveBound>,
        inclusive: Option<&serde_json::Number>,
        helper: &'static str,
    ) -> String {
        let mut bound = |expression: String, value: &serde_json::Number, exclusive: bool| {
            self.runtime_values.insert(helper);
            check(
                expression,
                &format!("{helper}({}, {exclusive})", render_number_value(value)),
            )
        };
        let inclusive_is_exclusive = match exclusive {
            Some(ExclusiveBound::Number(value)) => {
                expression = bound(expression, value, true);
                false
            }
            Some(ExclusiveBound::Boolean(true)) => true,
            Some(ExclusiveBound::Boolean(false)) | None => false,
        };
        if let Some(value) = inclusive {
            expression = bound(expression, value, inclusive_is_exclusive);
        }
        expression
    }

    fn apply_array_constraints(&mut self, expression: String, meta: &SchemaMeta) -> String {
        let constraints = meta.array_constraints();
        let mut expression = apply_item_count_bounds(expression, constraints);
        if constraints.unique_items {
            self.runtime_values.insert("uniqueItems");
            expression = check(expression, "uniqueItems()");
        }
        expression
    }

    fn apply_tuple_constraints(&mut self, expression: String, meta: &SchemaMeta) -> String {
        let constraints = meta.array_constraints();
        let mut expression = if constraints.min_items.is_some() || constraints.max_items.is_some() {
            let bound = apply_item_count_bounds("z.array(z.unknown())".to_owned(), constraints);
            format!("z.intersection({expression},{bound})")
        } else {
            expression
        };
        if constraints.unique_items {
            self.runtime_values.insert("uniqueItems");
            expression = check(expression, "uniqueItems()");
        }
        expression
    }

    fn render_object(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        additional: &AdditionalProperties,
        extra_required: &[String],
        meta: &SchemaMeta,
        self_is_deferred: bool,
    ) -> String {
        let mut members = Vec::new();
        for (name, schema, property_meta) in properties {
            if !property_in_position(property_meta, self.position) {
                continue;
            }
            let recursive = self.contains_self_ref(schema);
            let mut property = self.render_deferred(schema, self_is_deferred || recursive);
            if !property_meta.required {
                property = optional(property);
            }
            if recursive {
                members.push(format!(
                    "get {}() {{ return {property}; }}",
                    render_value_key(name)
                ));
            } else {
                members.push(format!("{}:{property}", render_value_key(name)));
            }
        }
        for name in extra_required {
            if !properties.iter().any(|(property, _, _)| property == name) {
                members.push(format!("{}:z.unknown()", render_value_key(name)));
            }
        }

        let pattern_properties = &meta.validation_applicators().pattern_properties;
        let expression = if pattern_properties.is_empty() {
            match additional {
                AdditionalProperties::Forbidden => {
                    format!("z.strictObject({{{}}})", members.join(","))
                }
                AdditionalProperties::Schema(schema)
                | AdditionalProperties::Allowed(Some(schema)) => catchall(
                    format!("z.looseObject({{{}}})", members.join(",")),
                    &self.render_deferred(schema, self_is_deferred),
                    self.model.config.zod.flavor,
                ),
                AdditionalProperties::Allowed(None) => {
                    format!("z.looseObject({{{}}})", members.join(","))
                }
            }
        } else {
            format!("z.looseObject({{{}}})", members.join(","))
        };

        self.apply_property_count(expression, meta)
    }

    /// Bounds an object's key count, shared by the typed and typeless object paths so the two
    /// cannot drift on what `minProperties`/`maxProperties` mean.
    fn apply_property_count(&mut self, expression: String, meta: &SchemaMeta) -> String {
        let constraints = meta.object_constraints();
        if constraints.min_properties.is_none() && constraints.max_properties.is_none() {
            return expression;
        }
        self.runtime_values.insert("propertyCount");
        check(
            expression,
            &format!(
                "propertyCount({},{})",
                optional_u64(constraints.min_properties),
                optional_u64(constraints.max_properties)
            ),
        )
    }

    fn render_typeless(&mut self, meta: &SchemaMeta, self_is_deferred: bool) -> String {
        if meta.numeric_constraints.is_none()
            && meta.string_constraints.is_none()
            && meta.array_constraints.is_none()
            && meta.object_constraints.is_none()
            && !has_object_applicators(meta)
            && !has_array_applicators(meta)
        {
            return "z.unknown()".to_owned();
        }

        let number = self.apply_number_constraints("z.number()".to_owned(), meta);
        let string = self.apply_string_constraints("z.string()".to_owned(), None, meta);
        let array = self.apply_array_constraints("z.array(z.unknown())".to_owned(), meta);
        let required = meta
            .object_constraints()
            .required
            .iter()
            .map(|name| format!("{}:z.unknown()", render_value_key(name)))
            .collect::<Vec<_>>()
            .join(",");
        let object = format!("z.looseObject({{{required}}})");
        let object = self.apply_property_count(object, meta);
        let object = self.apply_object_applicators(object, meta, None, self_is_deferred);
        let array = self.apply_array_applicators(array, meta, None, self_is_deferred);
        format!("z.union([{string},{number},z.boolean(),z.null(),{array},{object}])")
    }

    fn render_finite(
        &mut self,
        enum_values: Option<&[Value]>,
        const_value: Option<&Value>,
    ) -> String {
        let values = finite_values(enum_values, const_value).unwrap_or_default();
        let expression = self.render_json_value_union(&values);
        self.apply_finite_checks(expression, enum_values, const_value)
    }

    fn render_json_value_union(&mut self, values: &[Value]) -> String {
        union(
            values
                .iter()
                .map(|value| self.render_json_value_schema(value))
                .collect(),
        )
    }

    fn render_json_value_schema(&mut self, value: &Value) -> String {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => format!(
                "z.literal({})",
                render_json_compact(value, ObjectKeyMode::ProtoSafe)
            ),
            Value::Array(values) => format!(
                "z.tuple([{}])",
                values
                    .iter()
                    .map(|value| self.render_json_value_schema(value))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Value::Object(values) => format!(
                "z.strictObject({{{}}})",
                values
                    .iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        render_value_key(key),
                        self.render_json_value_schema(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    fn apply_finite_checks(
        &mut self,
        mut expression: String,
        enum_values: Option<&[Value]>,
        const_value: Option<&Value>,
    ) -> String {
        if let Some(values) = enum_values {
            self.runtime_values.insert("enumValues");
            expression = check(
                expression,
                &format!(
                    "enumValues([{}])",
                    values
                        .iter()
                        .map(|value| render_json_compact(value, ObjectKeyMode::ProtoSafe))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        }
        if let Some(value) = const_value {
            self.runtime_values.insert("constValue");
            expression = check(
                expression,
                &format!(
                    "constValue({})",
                    render_json_compact(value, ObjectKeyMode::ProtoSafe)
                ),
            );
        }
        expression
    }

    fn apply_applicators(
        &mut self,
        mut expression: String,
        schema: &SchemaNode,
        self_is_deferred: bool,
    ) -> String {
        let meta = schema.meta();
        if !matches!(schema, SchemaNode::Object { .. } | SchemaNode::Any { .. }) {
            let object_guard = self.render_object_applicator_guard(meta, schema, self_is_deferred);
            if let Some(guard) = object_guard {
                expression = format!("z.intersection({expression},{guard})");
            }
        } else if matches!(schema, SchemaNode::Object { .. }) {
            expression =
                self.apply_object_applicators(expression, meta, Some(schema), self_is_deferred);
        }
        if !matches!(
            schema,
            SchemaNode::Array { .. } | SchemaNode::Tuple { .. } | SchemaNode::Any { .. }
        ) {
            let array_guard = self.render_array_applicator_guard(meta, schema, self_is_deferred);
            if let Some(guard) = array_guard {
                expression = format!("z.intersection({expression},{guard})");
            }
        } else if matches!(schema, SchemaNode::Array { .. } | SchemaNode::Tuple { .. }) {
            expression =
                self.apply_array_applicators(expression, meta, Some(schema), self_is_deferred);
        }

        let applicators = meta.validation_applicators();
        if let Some(schema) = &applicators.not {
            self.runtime_values.insert("not");
            let nested = self.render_deferred(schema, self_is_deferred);
            expression = check(expression, &format!("not({nested})"));
        }
        if let Some(conditional) = &applicators.conditional {
            self.runtime_values.insert("conditional");
            expression = check(
                expression,
                &format!(
                    "conditional({},{},{})",
                    self.render_deferred(&conditional.condition, self_is_deferred),
                    render_optional_schema(
                        self,
                        conditional.then_schema.as_deref(),
                        self_is_deferred
                    ),
                    render_optional_schema(
                        self,
                        conditional.else_schema.as_deref(),
                        self_is_deferred
                    )
                ),
            );
        }
        expression
    }

    fn render_object_applicator_guard(
        &mut self,
        meta: &SchemaMeta,
        schema: &SchemaNode,
        self_is_deferred: bool,
    ) -> Option<String> {
        has_object_applicators(meta).then(|| {
            let object = self.apply_object_applicators(
                "z.looseObject({})".to_owned(),
                meta,
                Some(schema),
                self_is_deferred,
            );
            format!(
                "z.union([{object},z.string(),z.number(),z.boolean(),z.null(),z.array(z.unknown())])"
            )
        })
    }

    fn render_array_applicator_guard(
        &mut self,
        meta: &SchemaMeta,
        schema: &SchemaNode,
        self_is_deferred: bool,
    ) -> Option<String> {
        has_array_applicators(meta).then(|| {
            let array = self.apply_array_applicators(
                "z.array(z.unknown())".to_owned(),
                meta,
                Some(schema),
                self_is_deferred,
            );
            format!(
                "z.union([{array},z.string(),z.number(),z.boolean(),z.null(),z.looseObject({{}})])"
            )
        })
    }

    fn apply_object_applicators(
        &mut self,
        mut expression: String,
        meta: &SchemaMeta,
        context: Option<&SchemaNode>,
        self_is_deferred: bool,
    ) -> String {
        let applicators = meta.validation_applicators();
        if let Some(schema) = &applicators.property_names {
            self.runtime_values.insert("propertyNames");
            let nested = self.render_deferred(schema, self_is_deferred);
            expression = check(expression, &format!("propertyNames({nested})"));
        }
        if !applicators.pattern_properties.is_empty() {
            self.runtime_values.insert("patternProperties");
            let patterns = applicators
                .pattern_properties
                .iter()
                .map(|pattern| {
                    format!(
                        "[new RegExp({},\"u\"),{}]",
                        render_ts_string(&pattern.pattern),
                        self.render_deferred(&pattern.schema, self_is_deferred)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let declared = context.map_or_else(Vec::new, |schema| {
                if let SchemaNode::Object { properties, .. } = schema {
                    properties
                        .iter()
                        .filter(|(_, _, property_meta)| {
                            property_in_position(property_meta, self.position)
                        })
                        .map(|(name, _, _)| name.clone())
                        .collect()
                } else {
                    Vec::new()
                }
            });
            let additional = context.map_or_else(
                || "undefined".to_owned(),
                |schema| {
                    if let SchemaNode::Object {
                        additional_properties,
                        ..
                    } = schema
                    {
                        match additional_properties {
                            AdditionalProperties::Forbidden => "false".to_owned(),
                            AdditionalProperties::Schema(schema)
                            | AdditionalProperties::Allowed(Some(schema)) => {
                                self.render_deferred(schema, self_is_deferred)
                            }
                            AdditionalProperties::Allowed(None) => "undefined".to_owned(),
                        }
                    } else {
                        "undefined".to_owned()
                    }
                },
            );
            expression = check(
                expression,
                &format!(
                    "patternProperties([{patterns}],[{}],{additional})",
                    declared
                        .iter()
                        .map(|name| render_ts_string(name))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        }
        if !applicators.dependent_schemas.is_empty() {
            self.runtime_values.insert("dependentSchemas");
            expression = check(
                expression,
                &format!(
                    "dependentSchemas([{}])",
                    applicators
                        .dependent_schemas
                        .iter()
                        .map(|(trigger, schema)| format!(
                            "[{},{}]",
                            render_ts_string(trigger),
                            self.render_deferred(schema, self_is_deferred)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        }
        if let Some(allowed) = &applicators.unevaluated_properties {
            self.runtime_values.insert("unevaluatedProperties");
            let scope = context.map_or_else(
                || "{}".to_owned(),
                |schema| self.render_property_scope(schema, self_is_deferred, &mut Vec::new()),
            );
            let allowed = render_allowed_schema(self, allowed, self_is_deferred);
            expression = check(
                expression,
                &format!("unevaluatedProperties({scope},{allowed})"),
            );
        }
        expression
    }

    fn apply_array_applicators(
        &mut self,
        mut expression: String,
        meta: &SchemaMeta,
        context: Option<&SchemaNode>,
        self_is_deferred: bool,
    ) -> String {
        let applicators = meta.validation_applicators();
        if let Some(contains) = &applicators.contains {
            self.runtime_values.insert("contains");
            let nested = self.render_deferred(&contains.schema, self_is_deferred);
            expression = check(
                expression,
                &format!(
                    "contains({nested},{},{},{})",
                    contains
                        .min_contains
                        .map_or_else(|| "1".to_owned(), |value| value.to_string()),
                    optional_u64(contains.max_contains),
                    contains.min_contains.is_some()
                ),
            );
        }
        if let Some(allowed) = &applicators.unevaluated_items {
            self.runtime_values.insert("unevaluatedItems");
            let scope = self.render_item_scope(context, meta, self_is_deferred);
            let allowed = render_allowed_schema(self, allowed, self_is_deferred);
            expression = check(expression, &format!("unevaluatedItems({scope},{allowed})"));
        }
        expression
    }

    fn render_property_scope(
        &mut self,
        schema: &SchemaNode,
        self_is_deferred: bool,
        active_refs: &mut Vec<usize>,
    ) -> String {
        let mut fields = Vec::new();
        match schema {
            SchemaNode::Ref { target, .. } => {
                if let Some(target) = self
                    .model
                    .schema_target(&target.source_id, &target.json_pointer)
                    && !active_refs.contains(&target.index)
                {
                    active_refs.push(target.index);
                    let target_schema = &self.model.analyzed.ir.schemas[target.index].schema;
                    let rendered =
                        self.render_property_scope(target_schema, self_is_deferred, active_refs);
                    active_refs.pop();
                    return rendered;
                }
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                meta,
                ..
            } => {
                let declared = properties
                    .iter()
                    .filter(|(_, _, property_meta)| {
                        property_in_position(property_meta, self.position)
                    })
                    .map(|(name, _, _)| render_ts_string(name))
                    .collect::<Vec<_>>();
                if !declared.is_empty() {
                    fields.push(format!("declared:[{}]", declared.join(",")));
                }
                let patterns = meta
                    .validation_applicators()
                    .pattern_properties
                    .iter()
                    .map(|pattern| {
                        format!("new RegExp({},\"u\")", render_ts_string(&pattern.pattern))
                    })
                    .collect::<Vec<_>>();
                if !patterns.is_empty() {
                    fields.push(format!("patterns:[{}]", patterns.join(",")));
                }
                if meta.additional_properties_present
                    && matches!(
                        additional_properties,
                        AdditionalProperties::Allowed(_) | AdditionalProperties::Schema(_)
                    )
                {
                    fields.push("additional:true".to_owned());
                }
            }
            SchemaNode::AllOf { branches, .. } => {
                fields.push(format!(
                    "allOf:[{}]",
                    branches
                        .iter()
                        .map(|branch| self.render_property_scope(
                            branch,
                            self_is_deferred,
                            active_refs
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            SchemaNode::AnyOf { branches, .. } | SchemaNode::OneOf { branches, .. } => {
                fields.push(format!(
                    "branches:[{}]",
                    branches
                        .iter()
                        .map(|branch| format!(
                            "[{},{}]",
                            self.render_deferred(branch, self_is_deferred),
                            self.render_property_scope(branch, self_is_deferred, active_refs)
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Array { .. }
            | SchemaNode::Tuple { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => {}
        }
        if let Some(conditional) = &schema.meta().validation_applicators().conditional {
            let mut conditional_fields = vec![format!(
                "condition:{}",
                self.render_deferred(&conditional.condition, self_is_deferred)
            )];
            if let Some(then_schema) = &conditional.then_schema {
                conditional_fields.push(format!(
                    "whenTrue:{}",
                    self.render_property_scope(then_schema, self_is_deferred, active_refs)
                ));
            }
            if let Some(else_schema) = &conditional.else_schema {
                conditional_fields.push(format!(
                    "whenFalse:{}",
                    self.render_property_scope(else_schema, self_is_deferred, active_refs)
                ));
            }
            fields.push(format!("conditional:{{{}}}", conditional_fields.join(",")));
        }
        format!("{{{}}}", fields.join(","))
    }

    fn render_item_scope(
        &mut self,
        context: Option<&SchemaNode>,
        meta: &SchemaMeta,
        self_is_deferred: bool,
    ) -> String {
        let mut fields = Vec::new();
        match context {
            Some(SchemaNode::Array { .. }) => {
                if meta.items_present {
                    fields.push("itemsCovers:true".to_owned());
                }
            }
            Some(SchemaNode::Tuple { prefix_items, .. }) => {
                if !prefix_items.is_empty() {
                    fields.push(format!("prefixCount:{}", prefix_items.len()));
                }
                if meta.items_present {
                    fields.push("itemsCovers:true".to_owned());
                }
            }
            _ => {}
        }
        if let Some(contains) = &meta.validation_applicators().contains {
            fields.push(format!(
                "contains:[{}]",
                self.render_deferred(&contains.schema, self_is_deferred)
            ));
        }
        format!("{{{}}}", fields.join(","))
    }

    fn contains_self_ref(&self, schema: &SchemaNode) -> bool {
        let Some(current) = self.current_schema else {
            return false;
        };
        schema_contains_ref(self.model, schema, current)
    }
}

fn schema_contains_ref(
    model: &EmissionModel<'_>,
    schema: &SchemaNode,
    target_index: usize,
) -> bool {
    if let SchemaNode::Ref { target, .. } = schema
        && model
            .schema_target(&target.source_id, &target.json_pointer)
            .is_some_and(|target| target.index == target_index)
    {
        return true;
    }
    direct_children(schema)
        .into_iter()
        .any(|child| schema_contains_ref(model, child, target_index))
}

fn direct_children(schema: &SchemaNode) -> Vec<&SchemaNode> {
    let mut children = Vec::new();
    match schema {
        SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } => {
            children.extend(properties.iter().map(|(_, schema, _)| schema));
            if let AdditionalProperties::Allowed(Some(schema))
            | AdditionalProperties::Schema(schema) = additional_properties
            {
                children.push(schema);
            }
        }
        SchemaNode::Array { items, .. } => children.push(items),
        SchemaNode::Tuple {
            prefix_items, rest, ..
        } => {
            children.extend(prefix_items);
            if let TupleRest::Schema(schema) = rest {
                children.push(schema);
            }
        }
        SchemaNode::AllOf { branches, .. }
        | SchemaNode::OneOf { branches, .. }
        | SchemaNode::AnyOf { branches, .. } => children.extend(branches),
        _ => {}
    }
    let applicators = schema.meta().validation_applicators();
    children.extend(applicators.not.as_deref());
    children.extend(applicators.property_names.as_deref());
    children.extend(
        applicators
            .pattern_properties
            .iter()
            .map(|pattern| &pattern.schema),
    );
    if let Some(contains) = &applicators.contains {
        children.push(&contains.schema);
    }
    children.extend(
        applicators
            .dependent_schemas
            .iter()
            .map(|(_, schema)| schema),
    );
    if let Some(conditional) = &applicators.conditional {
        children.push(&conditional.condition);
        children.extend(conditional.then_schema.as_deref());
        children.extend(conditional.else_schema.as_deref());
    }
    children.extend(applicators.unevaluated_properties.as_deref());
    children.extend(applicators.unevaluated_items.as_deref());
    children
}

fn has_object_applicators(meta: &SchemaMeta) -> bool {
    let applicators = meta.validation_applicators();
    applicators.property_names.is_some()
        || !applicators.pattern_properties.is_empty()
        || !applicators.dependent_schemas.is_empty()
        || applicators.unevaluated_properties.is_some()
}

fn has_array_applicators(meta: &SchemaMeta) -> bool {
    let applicators = meta.validation_applicators();
    applicators.contains.is_some() || applicators.unevaluated_items.is_some()
}

fn render_optional_schema(
    renderer: &mut SchemaRenderer<'_, '_>,
    schema: Option<&SchemaNode>,
    self_is_deferred: bool,
) -> String {
    schema.map_or_else(
        || "undefined".to_owned(),
        |schema| renderer.render_deferred(schema, self_is_deferred),
    )
}

fn render_allowed_schema(
    renderer: &mut SchemaRenderer<'_, '_>,
    schema: &SchemaNode,
    self_is_deferred: bool,
) -> String {
    if matches!(schema, SchemaNode::Never { .. }) {
        "false".to_owned()
    } else {
        renderer.render_deferred(schema, self_is_deferred)
    }
}

/// Appends one runtime or native check to a schema expression.
///
/// Grows the expression in place rather than formatting a new one: a schema accumulates a check per
/// constraint keyword, and this is called once per keyword on every node in the document.
fn check(mut expression: String, check: &str) -> String {
    expression.push_str(".check(");
    expression.push_str(check);
    expression.push(')');
    expression
}

/// The module emitted schemas import from.
///
/// This and [`schema_type`] live here rather than on [`ZodFlavor`] because they are emitted
/// TypeScript, and emitted vocabulary belongs to the emitter — the config module names the choice,
/// this module spells it. `TransformKind::ts_type` is the same split for date representations.
const fn specifier(flavor: ZodFlavor) -> &'static str {
    match flavor {
        ZodFlavor::Classic => "zod",
        ZodFlavor::Mini => "zod/mini",
    }
}

/// The schema base type an explicitly annotated export is declared against.
const fn schema_type(flavor: ZodFlavor) -> &'static str {
    match flavor {
        ZodFlavor::Classic => "z.ZodType",
        ZodFlavor::Mini => "z.ZodMiniType",
    }
}

/// Binds a schema for the keys an object declares no property for.
///
/// The one applicator with no shared spelling: classic carries it as a method, mini only as a free
/// function. Both set the same `catchall` on the object def.
fn catchall(mut object: String, additional: &str, flavor: ZodFlavor) -> String {
    match flavor {
        ZodFlavor::Classic => {
            object.push_str(".catchall(");
            object.push_str(additional);
            object.push(')');
            object
        }
        ZodFlavor::Mini => {
            object.insert_str(0, "z.catchall(");
            object.push(',');
            object.push_str(additional);
            object.push(')');
            object
        }
    }
}

/// Wraps a schema so the position it occupies also admits `undefined`.
///
/// Spelled as the free function rather than the `.optional()` method because the free function is
/// the one form both zod and `zod/mini` accept; the method exists only on the classic wrapper.
fn optional(mut expression: String) -> String {
    expression.insert_str(0, "z.optional(");
    expression.push(')');
    expression
}

fn union(expressions: Vec<String>) -> String {
    match expressions.as_slice() {
        [] => "z.never()".to_owned(),
        [expression] => expression.clone(),
        _ => format!("z.union([{}])", expressions.join(",")),
    }
}

fn intersection(expressions: Vec<String>) -> String {
    let mut expressions = expressions.into_iter();
    let Some(mut result) = expressions.next() else {
        return "z.unknown()".to_owned();
    };
    for expression in expressions {
        result = format!("z.intersection({result},{expression})");
    }
    result
}

/// Bounds an array's element count.
///
/// Zod's `.min()`/`.max()` on an array are the method forms of the very same `minLength`/`maxLength`
/// checks, so routing through `.check()` keeps the verdicts identical while staying inside the
/// vocabulary `zod/mini` also exports. The runtime's own `minLength`/`maxLength` are the *string*
/// predicates, which count code points and are a different contract — these stay namespaced under
/// `z` so the two never get confused at a call site.
fn apply_item_count_bounds(
    mut expression: String,
    constraints: &crate::ir::ArrayConstraints,
) -> String {
    if let Some(minimum) = constraints.min_items {
        expression = check(expression, &format!("z.minLength({minimum})"));
    }
    if let Some(maximum) = constraints.max_items {
        expression = check(expression, &format!("z.maxLength({maximum})"));
    }
    expression
}

/// Applies one end of a numeric range.
///
/// Lower and upper are the same shape with the comparators swapped, so they share a body: whether
/// `exclusive` names its own value, merely marks `inclusive` as strict, or is absent decides which
/// comparator each recorded bound renders as. Keeping it in one place is what stops a spec-fidelity
/// fix from landing on one end and silently emitting an inclusive bound at the other.
fn apply_bound(
    mut expression: String,
    exclusive: Option<&ExclusiveBound>,
    inclusive: Option<&serde_json::Number>,
    strict: &str,
    loose: &str,
) -> String {
    let bound = |expression: String, comparator: &str, value: &serde_json::Number| {
        check(
            expression,
            &format!("z.{comparator}({})", render_number_value(value)),
        )
    };
    // `exclusive` decides only which comparator the recorded `inclusive` bound renders as — except
    // when it carries its own value, which is a second bound on top rather than a choice.
    let comparator = match exclusive {
        Some(ExclusiveBound::Number(value)) => {
            expression = bound(expression, strict, value);
            loose
        }
        Some(ExclusiveBound::Boolean(true)) => strict,
        Some(ExclusiveBound::Boolean(false)) | None => loose,
    };
    if let Some(value) = inclusive {
        expression = bound(expression, comparator, value);
    }
    expression
}

fn apply_lower_bound(expression: String, constraints: &crate::ir::NumericConstraints) -> String {
    apply_bound(
        expression,
        constraints.exclusive_minimum.as_ref(),
        constraints.minimum.as_ref(),
        "gt",
        "gte",
    )
}

fn apply_upper_bound(expression: String, constraints: &crate::ir::NumericConstraints) -> String {
    apply_bound(
        expression,
        constraints.exclusive_maximum.as_ref(),
        constraints.maximum.as_ref(),
        "lt",
        "lte",
    )
}

fn string_format(format: &str) -> Option<(&'static str, &'static str)> {
    match format {
        "date-time" => Some(("isDateTime", "date-time")),
        "date" => Some(("isDate", "date")),
        "time" => Some(("isTime", "time")),
        "uuid" => Some(("isUuid", "uuid")),
        _ => None,
    }
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "undefined".to_owned(), |value| value.to_string())
}

fn render_value_key(key: &str) -> String {
    if key == "__proto__" {
        format!("[{}]", render_ts_string(key))
    } else {
        render_ts_string(key)
    }
}

fn schema_const_name(export_type: &str) -> String {
    format!("{}Schema", lowercase_first(export_type))
}

struct Decl {
    type_declaration: String,
    schema: String,
}

/// The `enum`/`const` restriction a node carries, wherever the variant keeps it.
fn node_finite_values(schema: &SchemaNode) -> (Option<&[Value]>, Option<&Value>) {
    match schema {
        SchemaNode::Primitive {
            enum_values,
            const_value,
            ..
        }
        | SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => (enum_values.as_deref(), const_value.as_ref()),
        SchemaNode::Object { finite, .. }
        | SchemaNode::Array { finite, .. }
        | SchemaNode::Tuple { finite, .. } => finite_parts(finite),
        _ => (None, None),
    }
}

/// Builds one exported declaration pair. `annotated_type` is `Some` only for a schema in a
/// reference cycle, which is the sole case that needs the explicit annotation.
fn render_decl(
    export_name: &str,
    declared_type: &str,
    schema_name: &str,
    annotated_type: Option<(&str, &str)>,
    expression: &str,
) -> Decl {
    // An operation module also exports the `validate{Name}(value, path, issues)` entry point the
    // generated client calls, so a client's emitted call sites are identical whichever engine is
    // bound and only the import path differs. It discards the parsed value: the client forwards what
    // it already decoded, which keeps zod's object reconstruction invisible at that seam.
    let wrapper = format!(
        "\nexport function validate{export_name}(value: unknown, path: readonly (string | number)[], issues: Issue[]): void {{\n  collect({schema_name}, value, path, issues);\n}}\n"
    );
    match annotated_type {
        Some((type_expression, type_annotation)) => Decl {
            type_declaration: format!("export type {declared_type} = {type_expression};\n"),
            schema: format!(
                "export const {schema_name}: {type_annotation} = {expression};\n{wrapper}"
            ),
        },
        None => Decl {
            type_declaration: String::new(),
            schema: format!(
                "export const {schema_name} = {expression};\n\nexport type {declared_type} = z.infer<typeof {schema_name}>;\n{wrapper}"
            ),
        },
    }
}

/// Whether a component's schema can reach itself by following `$ref`s, directly or through other
/// components. Only such a schema needs the explicit schema-type annotation: without one
/// TypeScript reports a circular inference error, and with one the cycle is broken. Everything else
/// exports `z.infer` of its own schema, which is both what the artifact contract asks for and the
/// only honest answer — the structural types the types artifact emits are approximations in places
/// (a `prefixItems` tuple is declared with its leading elements required, though the schema permits
/// a shorter array), so annotating every schema against them asserts a type the schema does not
/// enforce and fails to compile.
fn participates_in_reference_cycle(model: &EmissionModel<'_>, schema_index: usize) -> bool {
    let mut visited = BTreeSet::new();
    reaches_component(
        model,
        &model.analyzed.ir.schemas[schema_index].schema,
        schema_index,
        &mut visited,
    )
}

fn reaches_component(
    model: &EmissionModel<'_>,
    schema: &SchemaNode,
    target_index: usize,
    visited: &mut BTreeSet<usize>,
) -> bool {
    if let SchemaNode::Ref { target, .. } = schema
        && let Some(resolved) = model.schema_target(&target.source_id, &target.json_pointer)
    {
        if resolved.index == target_index {
            return true;
        }
        if visited.insert(resolved.index)
            && reaches_component(
                model,
                &model.analyzed.ir.schemas[resolved.index].schema,
                target_index,
                visited,
            )
        {
            return true;
        }
    }
    direct_children(schema)
        .into_iter()
        .any(|child| reaches_component(model, child, target_index, visited))
}

fn emit_component(
    model: &EmissionModel<'_>,
    factory: &EmitterFactory<'_, '_>,
    emission: &mut Emission,
    schema_index: usize,
    file_base: &str,
    name: &str,
) {
    let analyzed = model.analyzed;
    let schema = &analyzed.ir.schemas[schema_index];
    let (request_variant, response_variant, neutral_wire, request_wire, response_wire) = {
        // Reaching this emitter with a file base proves path allocation registered the target too.
        let target = model
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .expect("a component with an allocated file has a registered target");
        (
            target.request_export(),
            target.response_export(),
            target.wire_export(TypePosition::Neutral),
            target.wire_export(TypePosition::Request),
            target.wire_export(TypePosition::Response),
        )
    };
    // The wire twin is carried as `None` when there is none rather than as a copy of the export
    // name: under the `string` default no position has one, and a copy per variant would be an
    // allocation the non-converting build pays for nothing.
    let mut variants = vec![(name.to_owned(), neutral_wire, TypePosition::Neutral)];
    if let Some(request) = request_variant {
        variants.push((request, request_wire, TypePosition::Request));
    }
    if let Some(response) = response_variant {
        variants.push((response, response_wire, TypePosition::Response));
    }

    let mut runtime_values = BTreeSet::new();
    runtime_values.insert("type Issue");
    runtime_values.insert("collect");
    let mut imports = SiblingImports {
        skip_self: Some(schema_index),
        ..SiblingImports::default()
    };
    let mut declarations = Vec::new();
    let cyclic = participates_in_reference_cycle(model, schema_index);
    for (export_name, wire_name, position) in variants {
        let declared_type = wire_name.as_deref().unwrap_or(&export_name);
        let schema_name = schema_const_name(&export_name);
        let mut lazy_closes_cycle = false;
        let expression = SchemaRenderer {
            model,
            factory,
            position,
            current_schema: Some(schema_index),
            current_schema_name: &schema_name,
            runtime_values: &mut runtime_values,
            imports: &mut imports,
            lazy_closes_cycle: &mut lazy_closes_cycle,
        }
        .render(&schema.schema);
        // A cycle only defeats TypeScript's inference when one of its back edges is a `z.lazy`
        // thunk; a cycle closed entirely by property getters resolves on its own. Annotating those
        // is not merely redundant, it is unsound: `ZodType<T>` wants an output whose optional
        // members exclude `undefined`, and no zod object infers that, so a consumer compiling with
        // `exactOptionalPropertyTypes` cannot assign the schema to its own annotation.
        //
        // `lazy_closes_cycle` is set by the renderer itself, at the one site that chose getter or
        // thunk. Over-approximating here is NOT free: a `z.lazy` for a sibling that never refers
        // back is on no cycle, and annotating because of it puts `ZodType<T>` back on the ordinary
        // recursive component — which is exactly the assignment `exactOptionalPropertyTypes`
        // rejects.
        //
        // The annotated type is rendered only once that is settled. Rendering it eagerly would
        // also collect its component imports, and an annotation that is then dropped leaves those
        // imports named nowhere — `noUnusedLocals` reports the unread type import in the consumer's
        // own compile, which is the same class of defect the drop exists to remove.
        let annotation = (cyclic && lazy_closes_cycle).then(|| {
            let emitter = factory.worker();
            imports.collect_types(&emitter, &schema.schema, position);
            (
                emitter.render_type(&schema.schema, position, TypeAxis::Wire, 0),
                format!("{}<{declared_type}>", schema_type(model.config.zod.flavor)),
            )
        });
        declarations.push(render_decl(
            &export_name,
            declared_type,
            &schema_name,
            annotation
                .as_ref()
                .map(|(expression, annotation)| (expression.as_str(), annotation.as_str())),
            &expression,
        ));
    }
    let content = assemble_file(
        model,
        "./",
        &imports,
        &BTreeMap::new(),
        &runtime_values,
        &declarations,
    );
    let relative_path = format!("{}/components/{file_base}.ts", model.dirs.zod);
    emission.register_path(&relative_path, &schema.source);
    emission.files.push(GeneratedFile {
        relative_path,
        content,
    });
}

fn emit_operation(
    model: &EmissionModel<'_>,
    factory: &EmitterFactory<'_, '_>,
    emission: &mut Emission,
    projector: &PrimitiveDomainProjector<'_>,
    operation_index: usize,
    allocated_name: &str,
) {
    let Some(file_base) = model.operation_files[operation_index].clone() else {
        return;
    };
    let operation = &model.analyzed.ir.operations[operation_index];
    emit_operation_file(
        model,
        factory,
        emission,
        projector,
        operation,
        OperationModule {
            allocated_name,
            directory: "operations",
            file_base: &file_base,
            include_responses: true,
        },
    );
}

fn emit_operation_file(
    model: &EmissionModel<'_>,
    factory: &EmitterFactory<'_, '_>,
    emission: &mut Emission,
    projector: &PrimitiveDomainProjector<'_>,
    operation: &Operation,
    module: OperationModule<'_>,
) {
    let OperationModule {
        allocated_name,
        directory,
        file_base,
        include_responses,
    } = module;
    let stem = uppercase_first(allocated_name);
    // Held across `positions` because a form field's schema is a projector-resolved clone owned by
    // the plan rather than a node the IR can lend.
    let body_plan = operation
        .request_body
        .as_ref()
        .and_then(|body| build_body_plan(&body.media_types, projector));
    let mut positions = Vec::new();
    for (export_type, parameter) in operation_parameter_validator_names(operation, &stem)
        .into_iter()
        .zip(&operation.parameters)
    {
        positions.push((export_type, &parameter.schema, TypePosition::Request));
    }
    if let Some(body) = &operation.request_body {
        for position in request_body_validator_positions(body, body_plan.as_ref(), &stem) {
            positions.push((position.name, position.schema, TypePosition::Request));
        }
    }
    if include_responses {
        let mut responses = Vec::new();
        for response in &operation.responses {
            let suffix = response_status_type_suffix(&response.status);
            responses.extend(response_body_schemas(
                response,
                &stem,
                &suffix,
                &mut emission.diagnostics,
            ));
        }
        responses.sort_by(|left, right| left.0.cmp(&right.0));
        for (export_type, schema) in responses {
            positions.push((export_type, schema, TypePosition::Response));
        }
    }
    let mut header_positions = if include_responses {
        operation
            .responses
            .iter()
            .filter(|response| !response.headers.is_empty())
            .map(|response| {
                let suffix = response_status_type_suffix(&response.status);
                (format!("{stem}Response{suffix}Headers"), response)
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    header_positions.sort_by(|left, right| left.0.cmp(&right.0));
    if positions.is_empty() && header_positions.is_empty() {
        return;
    }

    let mut runtime_values = BTreeSet::new();
    runtime_values.insert("type Issue");
    runtime_values.insert("collect");
    let mut imports = SiblingImports::default();
    let mut reexports: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut declarations = Vec::new();
    // Every name this module declares of its own, so a derived twin never lands on one.
    // Built only when a representation converts: nothing derives a twin otherwise, and an empty
    // set allocates nothing, so the `string` default pays for none of this.
    let siblings: BTreeSet<&str> = if model.transform_facts().enabled() {
        positions
            .iter()
            .map(|(export_type, _, _)| export_type.as_str())
            .chain(
                header_positions
                    .iter()
                    .map(|(export_type, _)| export_type.as_str()),
            )
            .collect()
    } else {
        BTreeSet::new()
    };
    let mut wire_diagnostics = Vec::new();
    // An operation schema is never itself the target of a `$ref`, so its inference can only cycle
    // through a component, and that component carries the annotation that breaks it.
    for (export_type, schema, position) in &positions {
        let (schema, position) = (*schema, *position);
        // A position that is a bare `$ref` to a component whose name it already shares must
        // re-export that component rather than declare its own: the two identifiers are the same,
        // so declaring one here both collides with the sibling import and makes the schema
        // reference itself. Airbyte's `AssistV1ProcessRequestBody` is a real case.
        let emitter = factory.worker();
        let declared_type = validator_wire_type_name(
            &emitter,
            export_type,
            schema,
            position,
            &siblings,
            &mut wire_diagnostics,
        );
        if let Some(file_base) =
            identical_component_delegate(&emitter, export_type, schema, position)
        {
            let entry = reexports.entry(file_base).or_default();
            entry.insert(format!("type {declared_type}"));
            entry.insert(schema_const_name(export_type));
            entry.insert(format!("validate{export_type}"));
            continue;
        }
        // The name borrows the export, not the emitter, so the read-only borrow of the model ends
        // here and the renderer below can take it mutably.
        drop(emitter);
        let schema_name = schema_const_name(export_type);
        let mut lazy_closes_cycle = false;
        let expression = SchemaRenderer {
            model,
            factory,
            position,
            current_schema: None,
            current_schema_name: &schema_name,
            runtime_values: &mut runtime_values,
            lazy_closes_cycle: &mut lazy_closes_cycle,
            imports: &mut imports,
        }
        .render(schema);
        declarations.push(render_decl(
            export_type,
            &declared_type,
            &schema_name,
            None,
            &expression,
        ));
    }
    for (export_type, response) in header_positions {
        let (_, expression) = render_headers(
            model,
            factory,
            response,
            &export_type,
            &mut imports,
            &mut runtime_values,
        );
        let schema_name = schema_const_name(&export_type);
        let transforms = response.headers.iter().any(|(_, header)| {
            !crate::client_model::response_header_is_opaque_string(header)
                && model.transform_facts().reaches(&header.schema)
        });
        // Borrowed when nothing transforms, which is every position under the `string` default.
        let declared_type = if transforms {
            Cow::Owned(format!("{export_type}Wire"))
        } else {
            Cow::Borrowed(export_type.as_str())
        };
        declarations.push(render_decl(
            &export_type,
            &declared_type,
            &schema_name,
            None,
            &expression,
        ));
    }
    emission.diagnostics.extend(wire_diagnostics);
    let content = assemble_file(
        model,
        "../components/",
        &imports,
        &reexports,
        &runtime_values,
        &declarations,
    );
    let relative_path = format!("{}/{directory}/{file_base}.ts", model.dirs.zod);
    emission.register_path(&relative_path, &operation.source);
    emission.files.push(GeneratedFile {
        relative_path,
        content,
    });
}

fn render_headers(
    model: &EmissionModel<'_>,
    factory: &EmitterFactory<'_, '_>,
    response: &ResponseEntry,
    schema_name: &str,
    imports: &mut SiblingImports,
    runtime_values: &mut BTreeSet<&'static str>,
) -> (String, String) {
    let mut type_members = Vec::new();
    let mut schema_members = Vec::new();
    for (name, header) in &response.headers {
        let opaque = crate::client_model::response_header_is_opaque_string(header);
        let type_expression = if opaque {
            "string".to_owned()
        } else {
            let emitter = factory.worker();
            imports.collect_types(&emitter, &header.schema, TypePosition::Response);
            emitter.render_type(&header.schema, TypePosition::Response, TypeAxis::Wire, 2)
        };
        type_members.push(format!(
            "  {}{}{}: {type_expression};",
            if model.config.types.readonly {
                "readonly "
            } else {
                ""
            },
            render_ts_string(name),
            if header.required { "" } else { "?" }
        ));
        // An opaque content header is typed `string` and its wire value always is one, so it carries
        // no schema — only, when required, the presence check. Everything else contributes its
        // schema, and a JSON-family content header is marked so the runtime parses before checking.
        let mut fields = vec![
            format!("name:{}", render_ts_string(name)),
            format!("required:{}", header.required),
        ];
        if !opaque {
            let mut lazy_closes_cycle = false;
            let expression = SchemaRenderer {
                model,
                factory,
                position: TypePosition::Response,
                current_schema: None,
                current_schema_name: schema_name,
                lazy_closes_cycle: &mut lazy_closes_cycle,
                runtime_values,
                imports,
            }
            .render(&header.schema);
            fields.push(format!("schema:{expression}"));
            if header.content_media_type.is_some() {
                fields.push("json:true".to_owned());
            }
        }
        schema_members.push(format!("{{{}}}", fields.join(",")));
    }
    runtime_values.insert("headers");
    let type_expression = format!("{{\n{}\n}}", type_members.join("\n"));
    (
        type_expression.clone(),
        // The value reaching this schema is the platform `Headers` object the client holds, not a
        // record, so it is read through `get(name)`. `z.custom` supplies the declared type without
        // imposing an object shape the `Headers` instance would fail, and passes the value through
        // by reference.
        format!(
            "z.custom<{type_expression}>().check(headers([{}]))",
            schema_members.join(",")
        ),
    )
}

fn response_body_schemas<'ir>(
    response: &'ir ResponseEntry,
    stem: &str,
    suffix: &str,
    sink: &mut crate::diag::DiagnosticSink,
) -> Vec<(String, &'ir SchemaNode)> {
    let json = response
        .media_types
        .iter()
        .filter(|media| media_has_validatable_schema(&media.essence, media.streaming_marked))
        .collect::<Vec<_>>();
    if json.is_empty() {
        return Vec::new();
    }
    let media = json
        .iter()
        .map(|media| media.full.as_str())
        .collect::<Vec<_>>();
    let names = response_media_names(&format!("{stem}Response{suffix}"), &media);
    let mut named = Vec::new();
    for (media, name) in json.into_iter().zip(names) {
        if let Some(previous) = name.collision {
            sink.push(warning_diagnostic(
                CODE_MEDIA_TAG_COLLISION,
                format!(
                    "response media type '{}' produces the same zod schema name as '{previous}'; emitting it as '{}'",
                    media.full, name.name
                ),
                &media.source,
            ));
        }
        named.push((name.name, &media.schema));
    }
    named
}

fn assemble_file(
    model: &EmissionModel<'_>,
    sibling_prefix: &str,
    imports: &SiblingImports,
    reexports: &BTreeMap<String, BTreeSet<String>>,
    runtime_values: &BTreeSet<&'static str>,
    declarations: &[Decl],
) -> String {
    let extension = import_extension(model);
    let mut output = model.header();
    // A namespace import, not `import { z } from "zod"`. Zod re-exports `z` as a runtime namespace
    // *object*, so importing that binding is an opaque value reference a bundler cannot look
    // through: every string format, every locale, and both JSON Schema converters link whether or
    // not a schema mentions them. A true namespace import lets the bundler resolve `z.string` and
    // friends statically and drop the rest — bundling the github artifact's
    // `pulls-update-review-comment` module with esbuild falls from 66.0 kB to 21.4 kB gzip. The
    // README's table reports the same measurement across a spread of operations.
    output.push_str("import * as z from \"");
    output.push_str(specifier(model.config.zod.flavor));
    output.push_str("\";\n");
    if !runtime_values.is_empty() {
        output.push_str(&format!(
            "import {{ {} }} from {};\n",
            runtime_values
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .join(", "),
            render_ts_string(&format!("../runtime{extension}"))
        ));
    }
    render_sibling_imports(&mut output, imports, sibling_prefix, &extension);
    for (file_base, specifiers) in reexports {
        output.push_str(&format!(
            "export {{ {} }} from {};\n",
            specifiers.iter().cloned().collect::<Vec<_>>().join(", "),
            render_ts_string(&format!("{sibling_prefix}{file_base}{extension}"))
        ));
    }
    output.push('\n');
    for (index, declaration) in declarations.iter().enumerate() {
        if !declaration.type_declaration.is_empty() {
            output.push_str(&declaration.type_declaration);
            output.push('\n');
        }
        output.push_str(&declaration.schema);
        if index + 1 < declarations.len() {
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::client_model::build_client_model;
    use crate::config::load_config;
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::emit::emit_artifacts;
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;

    fn compile(document: Value) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        compile_with_config(
            document,
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "zod": true }
            }),
        )
    }

    fn compile_with_config(
        document: Value,
        config: Value,
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write document");
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let source_tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("input parses");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let client = if resolved.artifacts.client.enabled {
            Some(build_client_model(&analyzed, &resolved, &mut sink))
        } else {
            None
        };
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &source_tuples,
            client.as_ref(),
            &mut sink,
        );
        (files, sink.into_sorted_vec())
    }

    fn doc(schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    fn component(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("zod/components/{base}.ts"))
            .expect("component zod file")
            .content
            .clone()
    }

    fn generated(files: &[GeneratedFile], relative_path: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == relative_path)
            .unwrap_or_else(|| panic!("missing generated file {relative_path}"))
            .content
            .clone()
    }

    fn assert_clean(diagnostics: &[Diagnostic]) {
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn every_emitted_file_imports_zod_as_a_namespace() {
        // `import { z }` binds zod's runtime namespace object, which a bundler cannot look through:
        // the whole library links into every consumer. Nothing else pins the import form, so a
        // well-meaning tidy-up back to the named import would silently quadruple emitted bundles.
        let (files, diagnostics) = compile(doc(json!({ "Thing": { "type": "string" } })));
        assert_clean(&diagnostics);
        let mut value_imports = 0;
        for file in &files {
            for line in file.content.lines() {
                if !line.ends_with("from \"zod\";") || line.starts_with("import type ") {
                    continue;
                }
                value_imports += 1;
                assert_eq!(
                    line, "import * as z from \"zod\";",
                    "{}",
                    file.relative_path
                );
            }
        }
        assert!(value_imports > 0);
    }

    #[test]
    fn the_mini_flavor_switches_the_specifier_the_annotation_and_catchall() {
        // These three are the whole classic/mini delta in emitted code. Everything else — the
        // factories, `.check()`, `z.optional`, `z.infer` — is spelled identically by both entry
        // points, which is why the flavor is a rendering detail rather than a second emitter.
        let document = doc(json!({
            "Bag": { "type": "object", "additionalProperties": { "type": "integer" } },
            "Node": { "$ref": "#/components/schemas/Node" }
        }));
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "types": true, "zod": true },
            "zod": { "flavor": "mini" }
        });
        let (files, diagnostics) = compile_with_config(document, config);
        assert_clean(&diagnostics);

        let bag = component(&files, "bag");
        assert!(bag.contains("import * as z from \"zod/mini\";"), "{bag}");
        assert!(bag.contains("z.catchall(z.looseObject({}),"), "{bag}");
        assert!(!bag.contains("}).catchall("), "{bag}");

        let node = component(&files, "node");
        assert!(
            node.contains("export const nodeSchema: z.ZodMiniType<Node> ="),
            "{node}"
        );
        assert!(!node.contains("z.ZodType<"), "{node}");
    }

    #[test]
    fn object_modes_and_runtime_checks_follow_the_zod_contract() {
        let (files, diagnostics) = compile(doc(json!({
            "Open": {
                "type": "object",
                "properties": { "emoji": { "type": "string", "maxLength": 1 } }
            },
            "Closed": { "type": "object", "additionalProperties": false },
            "Bag": { "type": "object", "additionalProperties": { "type": "integer" } }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "open").contains("z.looseObject"));
        assert!(component(&files, "open").contains(".check(maxLength(1))"));
        assert!(component(&files, "closed").contains("z.strictObject"));
        let bag = component(&files, "bag");
        assert!(bag.contains("z.looseObject({}).catchall("));
        assert!(bag.contains(".check(integer())"));
    }

    #[test]
    fn a_component_named_after_a_zod_runtime_identifier_gets_the_lowest_free_suffix() {
        let (files, diagnostics) = compile_with_config(
            doc(json!({
                "RuntimeCollision": { "type": "integer" },
                "TakenSuffix": { "type": "string" }
            })),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "zod": true },
                "naming": {
                    "overrides": {
                        "schemas": {
                            "RuntimeCollision": "integer",
                            "TakenSuffix": "integer2"
                        }
                    }
                }
            }),
        );
        assert_clean(&diagnostics);
        let collision = component(&files, "integer");
        assert!(
            collision.contains("import { collect, integer, type Issue } from \"../runtime.js\";")
        );
        assert!(collision.contains("export const integer3Schema ="));
        assert!(collision.contains("export type integer3 = z.infer<typeof integer3Schema>;"));
        assert!(!collision.contains("export type integer ="));
        assert!(component(&files, "integer2").contains("export type integer2 ="));
    }

    #[test]
    fn a_component_named_issue_does_not_shadow_the_imported_issue_type() {
        // Every module imports `Issue` for its validate entry point, so a component declaring that
        // exact name shadows it (TS2440). GitHub declares one, which is how this was found.
        let (files, diagnostics) = compile(doc(json!({
            "Issue": { "type": "object", "properties": { "title": { "type": "string" } } }
        })));
        assert_clean(&diagnostics);
        let renamed = component(&files, "issue");
        assert!(
            renamed.contains("import { collect, type Issue } from \"../runtime.js\";"),
            "{renamed}"
        );
        assert!(!renamed.contains("export type Issue ="), "{renamed}");
        assert!(renamed.contains("export type Issue2 ="), "{renamed}");
    }

    #[test]
    fn recursive_component_uses_a_getter_and_cross_file_refs_are_lazy() {
        let (files, diagnostics) = compile(doc(json!({
            "Tree": {
                "type": "object",
                "properties": {
                    "children": { "type": "array", "items": { "$ref": "#/components/schemas/Tree" } },
                    "other": { "$ref": "#/components/schemas/Other" }
                }
            },
            "Other": { "type": "string" }
        })));
        assert_clean(&diagnostics);
        let tree = component(&files, "tree");
        assert!(tree.contains("get \"children\"() { return z.optional(z.array(treeSchema)); }"));
        assert!(tree.contains("z.optional(z.lazy(() => otherSchema))"));
        // Value-only: with no annotation to render, the component's structural type is never
        // written, so importing the sibling's *type* would leave it unread in the consumer's
        // compile. The schema binding is still imported, because the thunk names it.
        assert!(
            tree.contains("import { otherSchema } from \"./other.js\";"),
            "{tree}"
        );
        assert!(!tree.contains("type Other,"), "{tree}");
    }

    #[test]
    fn every_schema_const_has_a_typed_annotation_without_escape_hatches() {
        let (files, diagnostics) = compile(doc(json!({
            "Thing": { "type": "object", "properties": { "id": { "type": "integer" } } }
        })));
        assert_clean(&diagnostics);
        for file in files
            .iter()
            .filter(|file| file.relative_path.starts_with("zod/components/"))
        {
            // An acyclic component takes its type from the schema rather than from a structural
            // declaration: the structural types are approximations in places (a `prefixItems`
            // tuple is declared with its leading elements required, though the schema accepts a
            // shorter array), so annotating against them would assert what the schema does not
            // enforce and fail to compile.
            assert!(
                file.content
                    .contains("export type Thing = z.infer<typeof thingSchema>;"),
                "acyclic component should export z.infer of its own schema: {}",
                file.content
            );
            assert!(!file.content.contains(": z.ZodType<"));
            assert!(!file.content.contains(": any"));
            assert!(!file.content.contains("!;"));
            // The zod namespace import spells `as` for a reason that has nothing to do with
            // casting, so it is exempted by exact text rather than by being an import: a future
            // aliased sibling import (`import { type Other as Other2, ... }`) is a real escape
            // hatch and must still fail here.
            for line in file
                .content
                .lines()
                .filter(|line| !line.starts_with("import * as z from "))
            {
                assert!(!line.contains(" as "), "{line}");
            }
        }
    }

    #[test]
    fn a_nullable_container_still_applies_its_finite_check() {
        // A container carries its finite restriction as a check rather than an intersection, so the
        // null branch is unioned around it — and the check has to be re-applied outside that union,
        // or a null the enum omits slips through the branch the union just added.
        let (files, diagnostics) = compile(json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Fixed": {
                        "type": "object",
                        "properties": {
                            "pair": {
                                "type": "array",
                                "nullable": true,
                                "items": { "type": "string" },
                                "enum": [["a", "b"]]
                            }
                        }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let content = component(&files, "fixed");
        assert!(content.contains("z.null()])"), "{content}");
        assert!(
            content.matches("enumValues([[\"a\",\"b\"]])").count() >= 2,
            "the finite check must also apply outside the null union: {content}"
        );
    }

    #[test]
    fn an_operation_position_that_merely_refs_a_component_re_exports_it() {
        // The derived request-body export and the component share one identifier, so declaring it
        // here would both collide with the sibling import and make the schema reference itself.
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/assist": {
                    "post": {
                        "operationId": "assist",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/AssistRequestBody" }
                                }
                            }
                        },
                        "responses": { "204": { "description": "done" } }
                    }
                }
            },
            "components": {
                "schemas": {
                    "AssistRequestBody": {
                        "type": "object",
                        "properties": { "prompt": { "type": "string" } }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let operation = files
            .iter()
            .find(|file| file.relative_path == "zod/operations/assist.ts")
            .expect("operation module");
        assert!(
            operation.content.contains(
                "export { assistRequestBodySchema, type AssistRequestBody, validateAssistRequestBody } from \"../components/assistrequestbody.js\";"
            ),
            "{}",
            operation.content
        );
        assert!(
            !operation
                .content
                .contains("export const assistRequestBodySchema ="),
            "the name must not also be declared locally: {}",
            operation.content
        );
    }

    /// A self-referential object reaches itself through a getter, and TypeScript resolves a getter
    /// cycle on its own. The annotation it used to carry was therefore never load-bearing — and it
    /// was actively wrong: `ZodType<T>` demands an output whose optional members exclude
    /// `undefined`, which is not what any zod object infers, so a consumer with
    /// `exactOptionalPropertyTypes` could not compile the module.
    #[test]
    fn a_getter_reachable_cycle_carries_no_annotation() {
        let (files, diagnostics) = compile(doc(json!({
            "TreeNode": {
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": { "type": "string" },
                    "children": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/TreeNode" }
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let tree = component(&files, "treenode");
        assert!(tree.contains("get \"children\"()"), "{tree}");
        assert!(!tree.contains("z.ZodType<"), "{tree}");
        assert!(
            tree.contains("export type TreeNode = z.infer<typeof treeNodeSchema>;"),
            "{tree}"
        );
    }

    /// The shape the `z.lazy(` text probe got wrong: a component whose own cycle is closed by a
    /// getter, but which also references a sibling that never refers back. The sibling's thunk is
    /// on no cycle, so the annotation is still not load-bearing — and emitting one would reinstate
    /// the `exactOptionalPropertyTypes` failure this whole path exists to remove.
    #[test]
    fn a_getter_cycle_beside_an_acyclic_sibling_ref_stays_unannotated() {
        let (files, diagnostics) = compile(doc(json!({
            "Meta": {
                "type": "object",
                "properties": { "label": { "type": "string" } }
            },
            "TreeNode": {
                "type": "object",
                "required": ["value"],
                "properties": {
                    "value": { "type": "string" },
                    "meta": { "$ref": "#/components/schemas/Meta" },
                    "children": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/TreeNode" }
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let tree = component(&files, "treenode");
        assert!(tree.contains("z.lazy(() => metaSchema)"), "{tree}");
        assert!(tree.contains("get \"children\"()"), "{tree}");
        assert!(!tree.contains("z.ZodType<"), "{tree}");
    }

    #[test]
    fn a_schema_in_a_reference_cycle_keeps_its_explicit_annotation() {
        // A cycle whose back edge is a `z.lazy` thunk still needs the annotation: TypeScript
        // reports TS7022 without one. Only getter-reachable cycles resolve on their own.
        let (files, diagnostics) = compile(doc(json!({
            "Ping": {
                "type": "object",
                "properties": { "pong": { "$ref": "#/components/schemas/Pong" } }
            },
            "Pong": {
                "type": "object",
                "properties": { "ping": { "$ref": "#/components/schemas/Ping" } }
            }
        })));
        assert_clean(&diagnostics);
        for (path, expected) in [
            (
                "zod/components/ping.ts",
                "export const pingSchema: z.ZodType<Ping> =",
            ),
            (
                "zod/components/pong.ts",
                "export const pongSchema: z.ZodType<Pong> =",
            ),
        ] {
            let content = generated(&files, path);
            assert!(
                content.contains(expected),
                "{path} should carry the cycle-breaking annotation: {}",
                content
            );
        }
    }

    #[test]
    fn transforming_date_time_schemas_declare_wire_types() {
        let (files, diagnostics) = compile_with_config(
            doc(json!({
                "Event": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Node": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "child": { "$ref": "#/components/schemas/Node" },
                        "event": { "$ref": "#/components/schemas/Event" }
                    }
                },
                "Ping": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "pong": { "$ref": "#/components/schemas/Pong" }
                    }
                },
                "Pong": {
                    "type": "object",
                    "properties": { "ping": { "$ref": "#/components/schemas/Ping" } }
                }
            })),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "zod": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "zod",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );
        assert_clean(&diagnostics);

        let event = component(&files, "event");
        assert!(event.contains("export const eventSchema ="), "{event}");
        assert!(
            event.contains("export type EventWire = z.infer<typeof eventSchema>;"),
            "{event}"
        );
        assert!(
            event.contains("export function validateEvent(value: unknown,"),
            "{event}"
        );
        assert!(
            event.contains("stringFormat(isDateTime,\"date-time\")"),
            "{event}"
        );

        let node = component(&files, "node");
        assert!(
            node.contains("import { eventSchema } from \"./event.js\";"),
            "{node}"
        );
        assert!(!node.contains("type EventWire,"), "{node}");
        // `Node` reaches itself only through a getter, and its `z.lazy` names a sibling that never
        // refers back — so no thunk sits on its cycle and the annotation is not load-bearing. It
        // used to carry one, and that annotation was unassignable under
        // `exactOptionalPropertyTypes`: `ZodType<T>` wants optional members without `undefined`,
        // which no zod object infers. The wire type comes from the schema instead, which is the
        // form the artifact contract asks for everywhere the cycle does not force otherwise.
        assert!(!node.contains("z.ZodType<"), "{node}");
        assert!(
            node.contains("export type NodeWire = z.infer<typeof nodeSchema>;"),
            "{node}"
        );
        assert!(
            node.contains("export function validateNode(value: unknown,"),
            "{node}"
        );

        // The mutual pair is the shape whose cycle really does run through a thunk, so it keeps its
        // annotation — and a transforming component that keeps one is the only path on which the
        // annotated type is rendered on the wire axis.
        let ping = component(&files, "ping");
        assert!(ping.contains("z.lazy(() => pongSchema)"), "{ping}");
        assert!(
            ping.contains("export const pingSchema: z.ZodType<PingWire> ="),
            "{ping}"
        );
        assert!(
            ping.contains("export type PingWire = {\n  at: string;"),
            "{ping}"
        );
    }

    #[test]
    fn transforming_operation_schemas_keep_their_public_names() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/events": {
                    "post": {
                        "operationId": "createEvent",
                        "parameters": [{
                            "name": "since",
                            "in": "query",
                            "schema": { "type": "string", "format": "date-time" }
                        }],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/CreateEventRequestBody" }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "created",
                                "headers": {
                                    "X-Created-At": {
                                        "required": true,
                                        "schema": { "type": "string", "format": "date-time" }
                                    }
                                },
                                "content": {
                                    "application/json": {
                                        "schema": { "type": "string", "format": "date-time" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "CreateEventRequestBody": {
                        "type": "object",
                        "required": ["at"],
                        "properties": {
                            "at": { "type": "string", "format": "date-time" }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile_with_config(
            document,
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "zod": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "zod",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );
        assert_clean(&diagnostics);
        let content = generated(&files, "zod/operations/createevent.ts");
        assert!(content.contains("export type CreateEventQuerySinceWire = z.infer<typeof createEventQuerySinceSchema>;"), "{content}");
        assert!(
            content.contains("export function validateCreateEventQuerySince(value: unknown,"),
            "{content}"
        );
        assert!(content.contains("export { createEventRequestBodySchema, type CreateEventRequestBodyWire, validateCreateEventRequestBody } from \"../components/createeventrequestbody.js\";"), "{content}");
        assert!(content.contains("export type CreateEventResponse200Wire = z.infer<typeof createEventResponse200Schema>;"), "{content}");
        assert!(content.contains("export type CreateEventResponse200HeadersWire = z.infer<typeof createEventResponse200HeadersSchema>;"), "{content}");
        assert!(content.contains("\"X-Created-At\": string;"), "{content}");
        assert!(
            content
                .contains("export function validateCreateEventResponse200Headers(value: unknown,"),
            "{content}"
        );
    }

    #[test]
    fn rejected_keywords_use_zod_diagnostics() {
        let (_, diagnostics) = compile(json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": { "Bad": { "$dynamicRef": true } } }
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_REJECTED_KEYWORD
                && diagnostic
                    .message
                    .contains("zod cannot emit a check for unsupported validation keyword")
        }));
    }

    #[test]
    fn generation_is_deterministic() {
        let document = doc(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "tags": { "type": "array", "items": { "type": "string" }, "uniqueItems": true }
                }
            }
        }));
        let (first, _) = compile(document.clone());
        let (second, _) = compile(document);
        assert_eq!(component(&first, "thing"), component(&second, "thing"));
    }

    #[test]
    fn primitive_constraints_formats_and_finite_values_render_exact_zod_checks() {
        let (files, diagnostics) = compile(doc(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 8,
                        "pattern": "^[a-z]+$"
                    },
                    "dateTime": { "type": "string", "format": "date-time" },
                    "date": { "type": "string", "format": "date" },
                    "time": { "type": "string", "format": "time" },
                    "uuid": { "type": "string", "format": "uuid" },
                    "annotationOnly": { "type": "string", "format": "email" },
                    "int64Annotation": { "type": "integer", "format": "int64" },
                    "count": {
                        "type": "integer",
                        "format": "int32",
                        "minimum": 0,
                        "maximum": 10,
                        "multipleOf": 2
                    },
                    "ratio": {
                        "type": "number",
                        "minimum": 0,
                        "exclusiveMinimum": 2,
                        "maximum": 10,
                        "exclusiveMaximum": 8,
                        "multipleOf": 0.1
                    },
                    "enabled": { "type": "boolean" },
                    "nothing": { "type": "null" },
                    "nullable": { "type": ["string", "null"] },
                    "finite": { "type": "string", "enum": ["a", "b"], "const": "a" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        for expected in [
            "z.string().check(minLength(1)).check(maxLength(8)).check(pattern(new RegExp(\"^[a-z]+$\")))",
            "stringFormat(isDateTime,\"date-time\")",
            "stringFormat(isDate,\"date\")",
            "stringFormat(isTime,\"time\")",
            "stringFormat(isUuid,\"uuid\")",
            "z.number().check(integer()).check(z.gte(0)).check(z.lte(10)).check(multipleOf(2)).check(int32())",
            "z.number().check(z.gt(2)).check(z.gte(0)).check(z.lt(8)).check(z.lte(10)).check(multipleOf(0.1))",
            "z.boolean()",
            "z.null()",
            "z.union([z.string(),z.null()])",
            "check(enumValues([\"a\",\"b\"]))",
            "check(constValue(\"a\"))",
        ] {
            assert!(content.contains(expected), "missing {expected}: {content}");
        }
        assert!(content.contains("\"annotationOnly\":z.optional(z.string())"));
        assert!(content.contains("\"int64Annotation\":z.optional(z.number().check(integer()))"));
        assert!(!content.contains("isEmail"));
        assert!(!content.contains("int64()"));
    }

    #[test]
    fn bigint_int64_uses_the_lossless_wire_check() {
        let (files, diagnostics) = compile_with_config(
            doc(json!({
                "Thing": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "integer", "format": "int64" },
                        "step": { "type": "integer", "format": "int64", "multipleOf": 2 },
                        "bounded": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "exclusiveMinimum": 1,
                            "maximum": 10,
                            "exclusiveMaximum": 9
                        }
                    }
                }
            })),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "zod": true },
                "types": { "integer": "bigint" },
                "validation": { "engine": "zod", "request": true, "unchecked": "allow" }
            }),
        );
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(
            content.contains(
                "z.custom<number | bigint | { readonly rawJSON: string }>().check(int64Wire())"
            ),
            "{content}"
        );
        assert!(
            content.contains(
                "z.custom<number | bigint | { readonly rawJSON: string }>().check(int64Wire(z.custom<bigint>().check(bigintMultipleOf(2))))"
            ),
            "{content}"
        );
        assert!(content.contains("int64Wire(z.custom<bigint>().check(bigintMinimum(1, true)).check(bigintMinimum(0, false)).check(bigintMaximum(9, true)).check(bigintMaximum(10, false)))"), "{content}");
        assert!(!content.contains(".check(int64())"), "{content}");
    }

    #[test]
    fn openapi_30_nullable_and_boolean_exclusive_bounds_keep_their_dialect_meaning() {
        let (files, diagnostics) = compile_with_config(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {},
                "components": {
                    "schemas": {
                        "Bounds": {
                            "type": "object",
                            "properties": {
                                "exclusive": {
                                    "type": "number",
                                    "minimum": 5,
                                    "exclusiveMinimum": true,
                                    "maximum": 10,
                                    "exclusiveMaximum": true
                                },
                                "inclusive": {
                                    "type": "number",
                                    "minimum": 1,
                                    "exclusiveMinimum": false,
                                    "maximum": 9,
                                    "exclusiveMaximum": false
                                },
                                "bigintExclusive": {
                                    "type": "integer",
                                    "format": "int64",
                                    "minimum": 5,
                                    "exclusiveMinimum": true
                                },
                                "nullable": { "type": "string", "nullable": true }
                            }
                        }
                    }
                }
            }),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "zod": true },
                "types": { "integer": "bigint" },
                "validation": { "engine": "zod", "request": true, "unchecked": "allow" }
            }),
        );
        assert_clean(&diagnostics);
        let content = component(&files, "bounds");
        assert!(
            content.contains("z.number().check(z.gt(5)).check(z.lt(10))"),
            "{content}"
        );
        assert!(
            content.contains("z.number().check(z.gte(1)).check(z.lte(9))"),
            "{content}"
        );
        assert!(
            content.contains("int64Wire(z.custom<bigint>().check(bigintMinimum(5, true)))"),
            "{content}"
        );
        assert!(
            content.contains("z.union([z.string(),z.null()])"),
            "{content}"
        );
    }

    #[test]
    fn a_nullable_enum_admits_null_only_when_the_enum_lists_it() {
        // The enum decides the admissible set, so `nullable: true` beside an enum that omits null
        // must not re-admit it — the generated engine applies its enum check unconditionally and
        // rejects null, and the type surface carries no null either. The null branch therefore
        // widens the domain *inside* the intersection, where the finite set can still exclude it,
        // rather than being unioned around the finished expression where a check cannot narrow it.
        let (files, diagnostics) = compile(json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Choice": {
                        "type": "object",
                        "properties": {
                            "without": {
                                "type": "string",
                                "enum": ["always", "never"],
                                "nullable": true
                            },
                            "with": {
                                "type": "string",
                                "enum": ["a", null],
                                "nullable": true
                            }
                        }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let content = component(&files, "choice");
        assert!(
            content.contains(
                r#"z.intersection(z.union([z.string(),z.null()]),z.union([z.literal("always"),z.literal("never")]))"#
            ),
            "{content}"
        );
        // A null the enum does list stays reachable, through the finite union rather than a
        // bolted-on branch.
        assert!(
            content.contains(r#"z.literal("a"),z.literal(null)"#),
            "{content}"
        );
        // Never the shape that would let null slip past the enum check.
        assert!(
            !content
                .contains(r#"z.literal("never")).check(enumValues(["always","never"])),z.null()"#),
            "{content}"
        );
    }

    #[test]
    fn arrays_and_each_tuple_rest_mode_preserve_bounds_uniqueness_and_finite_checks() {
        let (files, diagnostics) = compile(doc(json!({
            "List": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "maxItems": 3,
                "uniqueItems": true,
                "enum": [["a"]],
                "const": ["a"]
            },
            "AllowedTuple": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "items": true
            },
            "ClosedTuple": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                "items": false,
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": true
            },
            "RestTuple": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "items": { "type": "boolean" },
                "enum": [["a", true]],
                "const": ["a", true]
            }
        })));
        assert_clean(&diagnostics);

        let list = component(&files, "list");
        assert!(list.contains(
            "z.array(z.string()).check(z.minLength(1)).check(z.maxLength(3)).check(uniqueItems())"
        ));
        assert!(list.contains("enumValues([[\"a\"]])"));
        assert!(list.contains("constValue([\"a\"])"));

        let allowed = component(&files, "allowedtuple");
        assert!(allowed.contains("z.tuple([z.optional(z.string())], z.unknown())"));

        let closed = component(&files, "closedtuple");
        assert!(
            closed.contains(
                "z.tuple([z.optional(z.string()),z.optional(z.number().check(integer()))])"
            )
        );
        assert!(
            closed.contains("z.array(z.unknown()).check(z.minLength(1)).check(z.maxLength(2))")
        );
        assert!(closed.contains(".check(uniqueItems())"));

        let rest = component(&files, "resttuple");
        assert!(rest.contains("z.tuple([z.optional(z.string())], z.boolean())"));
        assert!(rest.contains("enumValues([[\"a\",true]])"));
        assert!(rest.contains("constValue([\"a\",true])"));
    }

    #[test]
    fn boolean_schemas_typeless_constraints_and_json_finite_values_keep_their_domains() {
        let (files, diagnostics) = compile(doc(json!({
            "Anything": true,
            "Nothing": false,
            "Constrained": {
                "minimum": 1,
                "minLength": 2,
                "minItems": 3,
                "required": ["present"],
                "minProperties": 1,
                "maxProperties": 4
            },
            "Finite": {
                "enum": [null, true, 1, "x", [1, "x"], { "__proto__": { "safe": true }, "x": 1 }]
            },
            "Constant": { "const": { "nested": [false] } }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "anything").contains("= z.unknown();"));
        assert!(component(&files, "nothing").contains("= z.never();"));

        let constrained = component(&files, "constrained");
        assert!(constrained.contains("z.union([z.string().check(minLength(2)),z.number().check(z.gte(1)),z.boolean(),z.null(),z.array(z.unknown()).check(z.minLength(3)),"));
        assert!(
            constrained
                .contains("z.looseObject({\"present\":z.unknown()}).check(propertyCount(1,4))")
        );

        let finite = component(&files, "finite");
        for expected in [
            "z.literal(null)",
            "z.literal(true)",
            "z.literal(1)",
            "z.literal(\"x\")",
            "z.tuple([z.literal(1),z.literal(\"x\")])",
            "z.strictObject({[\"__proto__\"]:z.strictObject({\"safe\":z.literal(true)}),\"x\":z.literal(1)})",
        ] {
            assert!(finite.contains(expected), "missing {expected}: {finite}");
        }
        assert!(
            component(&files, "constant")
                .contains("z.strictObject({\"nested\":z.tuple([z.literal(false)])}).check(constValue({\"nested\":[false]}))")
        );
    }

    #[test]
    fn compositions_render_their_zod_combinators_and_reference_flavors() {
        let (files, diagnostics) = compile(doc(json!({
            "Target": { "type": "string" },
            "Two": { "allOf": [{ "type": "string" }, { "minLength": 1 }] },
            "Three": {
                "allOf": [
                    { "type": "number" },
                    { "minimum": 0 },
                    { "maximum": 10 }
                ]
            },
            "Either": { "anyOf": [{ "type": "string" }, { "type": "boolean" }] },
            "ExactlyOne": { "oneOf": [{ "type": "string" }, { "const": "fixed" }] },
            "Reference": { "$ref": "#/components/schemas/Target" },
            "Dynamic": {
                "$id": "https://example.invalid/dynamic",
                "$dynamicAnchor": "node",
                "type": "object",
                "properties": { "next": { "$dynamicRef": "#node" } }
            },
            "Recursive": {
                "$id": "https://example.invalid/recursive",
                "$recursiveAnchor": true,
                "type": "object",
                "properties": { "next": { "$recursiveRef": "#" } }
            }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "two").contains("z.intersection(z.string(),z.union([z.string().check(minLength(1)),z.number(),z.boolean(),z.null(),z.array(z.unknown()),z.looseObject({})]))"));
        assert!(component(&files, "three").contains("z.intersection(z.intersection(z.number(),"));
        assert!(component(&files, "either").contains("z.union([z.string(),z.boolean()])"));
        let one = component(&files, "exactlyone");
        assert!(
            one.contains("z.union([z.string(),z.literal(\"fixed\").check(constValue(\"fixed\"))])")
        );
        assert!(
            one.contains("oneOf([z.string(),z.literal(\"fixed\").check(constValue(\"fixed\"))])")
        );
        assert!(component(&files, "reference").contains("z.lazy(() => targetSchema)"));
        assert!(
            component(&files, "dynamic")
                .contains("get \"next\"() { return z.optional(dynamicSchema); }")
        );
        assert!(
            component(&files, "recursive")
                .contains("get \"next\"() { return z.optional(recursiveSchema); }")
        );
    }

    #[test]
    fn object_applicators_render_declared_pattern_and_unevaluated_property_semantics() {
        let (files, diagnostics) = compile(doc(json!({
            "StrictPattern": {
                "type": "object",
                "properties": { "fixed": { "type": "string" } },
                "patternProperties": { "^x-": { "type": "integer" } },
                "additionalProperties": false,
                "propertyNames": { "type": "string", "minLength": 1 },
                "dependentSchemas": { "fixed": { "required": ["dependent"] } },
                "unevaluatedProperties": false
            },
            "CatchallPattern": {
                "type": "object",
                "patternProperties": { "^x-": { "type": "integer" } },
                "additionalProperties": { "type": "boolean" }
            },
            "OpenPattern": {
                "type": "object",
                "patternProperties": { "^x-": { "type": "integer" } }
            },
            "TypelessPattern": {
                "patternProperties": { "^x-": { "type": "integer" } },
                "unevaluatedProperties": { "type": "string" }
            },
            "GuardedString": {
                "type": "string",
                "patternProperties": { "^x-": { "type": "integer" } }
            }
        })));
        assert_clean(&diagnostics);

        let strict = component(&files, "strictpattern");
        assert!(strict.contains("propertyNames(z.string().check(minLength(1)))"));
        assert!(strict.contains("patternProperties([[new RegExp(\"^x-\",\"u\"),z.number().check(integer())]],[\"fixed\"],false)"));
        assert!(strict.contains("dependentSchemas([[\"fixed\",z.union([z.string(),z.number(),z.boolean(),z.null(),z.array(z.unknown()),z.looseObject({\"dependent\":z.unknown()})])]])"));
        assert!(strict.contains("unevaluatedProperties({declared:[\"fixed\"],patterns:[new RegExp(\"^x-\",\"u\")]},false)"));

        let catchall = component(&files, "catchallpattern");
        assert!(catchall.contains("patternProperties([[new RegExp(\"^x-\",\"u\"),z.number().check(integer())]],[],z.boolean())"));
        let open = component(&files, "openpattern");
        assert!(open.contains("patternProperties([[new RegExp(\"^x-\",\"u\"),z.number().check(integer())]],[],undefined)"));
        let typeless = component(&files, "typelesspattern");
        assert!(typeless.contains("patternProperties([[new RegExp(\"^x-\",\"u\"),z.number().check(integer())]],[],undefined)"));
        assert!(typeless.contains("unevaluatedProperties({},z.string())"));
        let guarded = component(&files, "guardedstring");
        assert!(guarded.contains(
            "z.intersection(z.string(),z.union([z.looseObject({}).check(patternProperties("
        ));
    }

    #[test]
    fn property_scopes_follow_refs_compositions_conditionals_and_position_variants() {
        let (files, diagnostics) = compile(doc(json!({
            "Base": {
                "type": "object",
                "properties": {
                    "requestOnly": { "type": "string", "writeOnly": true },
                    "responseOnly": { "type": "string", "readOnly": true },
                    "shared": { "type": "string" }
                },
                "additionalProperties": true
            },
            "RefScope": {
                "$ref": "#/components/schemas/Base",
                "unevaluatedProperties": false
            },
            "AllScope": {
                "allOf": [
                    { "$ref": "#/components/schemas/Base" },
                    { "type": "object", "properties": { "all": { "type": "string" } } }
                ],
                "unevaluatedProperties": false
            },
            "AnyScope": {
                "anyOf": [
                    { "type": "object", "properties": { "a": { "type": "string" } } },
                    { "type": "object", "properties": { "b": { "type": "string" } } }
                ],
                "unevaluatedProperties": false
            },
            "OneScope": {
                "oneOf": [
                    { "type": "object", "properties": { "a": { "type": "string" } } },
                    { "type": "object", "properties": { "b": { "type": "string" } } }
                ],
                "unevaluatedProperties": false
            },
            "ConditionalScope": {
                "type": "object",
                "if": { "required": ["kind"] },
                "then": { "properties": { "yes": { "type": "string" } } },
                "else": { "properties": { "no": { "type": "string" } } },
                "unevaluatedProperties": false
            },
            "PrimitiveScope": { "type": "string", "unevaluatedProperties": false }
            ,
            "CycleA": { "$ref": "#/components/schemas/CycleB" },
            "CycleB": { "$ref": "#/components/schemas/CycleA" },
            "CycleScope": {
                "$ref": "#/components/schemas/CycleA",
                "unevaluatedProperties": false
            }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "refscope").contains("unevaluatedProperties({declared:[\"requestOnly\",\"responseOnly\",\"shared\"],additional:true},false)"));
        assert!(component(&files, "allscope").contains("allOf:[{declared:[\"requestOnly\",\"responseOnly\",\"shared\"],additional:true},{declared:[\"all\"]}]"));
        assert!(component(&files, "anyscope").contains("branches:[[z.looseObject({\"a\":z.optional(z.string())}),{declared:[\"a\"]}],[z.looseObject({\"b\":z.optional(z.string())}),{declared:[\"b\"]}]]"));
        assert!(component(&files, "onescope").contains("branches:[[z.looseObject({\"a\":z.optional(z.string())}),{declared:[\"a\"]}],[z.looseObject({\"b\":z.optional(z.string())}),{declared:[\"b\"]}]]"));
        let conditional = component(&files, "conditionalscope");
        assert!(conditional.contains("conditional:{condition:"));
        assert!(conditional.contains("whenTrue:{declared:[\"yes\"]}"));
        assert!(conditional.contains("whenFalse:{declared:[\"no\"]}"));
        assert!(component(&files, "primitivescope").contains("unevaluatedProperties({},false)"));
        assert!(component(&files, "cyclescope").contains("unevaluatedProperties({},false)"));

        let base = component(&files, "base");
        assert!(base.contains("export const baseRequestSchema"));
        assert!(base.contains("export const baseResponseSchema"));
        assert!(base.contains("\"requestOnly\":z.optional(z.string())"));
        assert!(base.contains("\"responseOnly\":z.optional(z.string())"));
    }

    #[test]
    fn array_applicators_render_contains_bounds_and_evaluated_item_scopes() {
        let (files, diagnostics) = compile(doc(json!({
            "DefaultContains": {
                "type": "array",
                "contains": { "const": "hit" }
            },
            "BoundedContains": {
                "type": "array",
                "contains": { "type": "integer" },
                "minContains": 0,
                "maxContains": 2,
                "unevaluatedItems": false
            },
            "TupleScope": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "items": { "type": "boolean" },
                "contains": { "type": "integer" },
                "unevaluatedItems": { "type": "string" }
            },
            "NoItemsScope": {
                "type": "array",
                "unevaluatedItems": false
            },
            "ItemScope": {
                "type": "array",
                "items": { "type": "string" },
                "unevaluatedItems": false
            },
            "TypelessContains": {
                "contains": { "type": "string" },
                "unevaluatedItems": false
            },
            "GuardedNumber": {
                "type": "number",
                "contains": { "type": "string" }
            }
        })));
        assert_clean(&diagnostics);
        let default_contains = component(&files, "defaultcontains");
        assert!(
            default_contains.contains(
                "contains(z.literal(\"hit\").check(constValue(\"hit\")),1,undefined,false)"
            ),
            "{default_contains}"
        );
        let bounded = component(&files, "boundedcontains");
        assert!(bounded.contains("contains(z.number().check(integer()),0,2,true)"));
        assert!(
            bounded.contains("unevaluatedItems({contains:[z.number().check(integer())]},false)")
        );
        let tuple = component(&files, "tuplescope");
        assert!(tuple.contains("unevaluatedItems({prefixCount:1,itemsCovers:true,contains:[z.number().check(integer())]},z.string())"));
        assert!(component(&files, "noitemsscope").contains("unevaluatedItems({},false)"));
        assert!(
            component(&files, "itemscope").contains("unevaluatedItems({itemsCovers:true},false)")
        );
        assert!(
            component(&files, "typelesscontains")
                .contains("unevaluatedItems({contains:[z.string()]},false)")
        );
        assert!(component(&files, "guardednumber").contains("z.intersection(z.number(),z.union([z.array(z.unknown()).check(contains(z.string(),1,undefined,false))"));
    }

    #[test]
    fn not_and_every_conditional_branch_combination_render_explicit_runtime_operands() {
        let (files, diagnostics) = compile(doc(json!({
            "Negated": { "type": "string", "not": { "const": "blocked" } },
            "Both": {
                "if": { "required": ["kind"] },
                "then": { "required": ["yes"] },
                "else": { "required": ["no"] }
            },
            "ThenOnly": { "if": { "type": "string" }, "then": false },
            "ElseOnly": { "if": { "type": "string" }, "else": { "type": "number" } },
            "ConditionOnly": { "if": { "type": "boolean" } }
        })));
        assert_clean(&diagnostics);
        let negated = component(&files, "negated");
        assert!(
            negated.contains(
                "z.string().check(not(z.literal(\"blocked\").check(constValue(\"blocked\"))))"
            ),
            "{negated}"
        );
        let both = component(&files, "both");
        assert!(both.contains("conditional("));
        assert!(both.contains("z.looseObject({\"yes\":z.unknown()})"));
        assert!(both.contains("z.looseObject({\"no\":z.unknown()})"));
        assert!(
            component(&files, "thenonly").contains("conditional(z.string(),z.never(),undefined)")
        );
        assert!(
            component(&files, "elseonly").contains("conditional(z.string(),undefined,z.number())")
        );
        assert!(
            component(&files, "conditiononly")
                .contains("conditional(z.boolean(),undefined,undefined)")
        );
    }

    #[test]
    fn dependent_required_and_phantom_required_properties_render_own_key_checks() {
        let (files, diagnostics) = compile(doc(json!({
            "Account": {
                "type": "object",
                "properties": { "card": { "type": "string" } },
                "required": ["phantom"],
                "dependentRequired": {
                    "card": ["billing", "country"],
                    "other": ["detail"]
                },
                "minProperties": 1,
                "maxProperties": 5
            }
        })));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS2203")
        );
        assert_clean(&diagnostics);
        let content = component(&files, "account");
        assert!(content.contains("\"phantom\":z.unknown()"));
        assert!(content.contains("propertyCount(1,5)"));
        assert!(content.contains(
            "dependentRequired([[\"card\",[\"billing\",\"country\"]],[\"other\",[\"detail\"]]])"
        ));
    }

    #[test]
    fn operations_render_every_parameter_location_bodies_responses_and_headers() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things/{id}": {
                    "post": {
                        "operationId": "putThing",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "search", "in": "query", "schema": { "type": "string" } },
                            { "name": "X-Trace", "in": "header", "schema": { "type": "string" } },
                            { "name": "session", "in": "cookie", "schema": { "type": "string" } }
                        ],
                        "requestBody": {
                            "content": {
                                "text/plain": { "schema": { "type": "string" } },
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": { "value": { "type": "integer" } }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "204": { "description": "empty" },
                            "400": {
                                "description": "bad",
                                "headers": {
                                    "X-Reason": { "schema": { "type": "string" } }
                                },
                                "content": {
                                    "application/json": { "schema": { "type": "string" } }
                                }
                            },
                            "200": {
                                "description": "ok",
                                "headers": {
                                    "X-Required": {
                                        "required": true,
                                        "schema": { "$ref": "#/components/schemas/HeaderValue" }
                                    },
                                    "X-Optional": { "schema": { "type": "integer", "minimum": 1 } },
                                    "X-Opaque": {
                                        "required": true,
                                        "content": {
                                            "application/xml": { "schema": { "type": "string" } }
                                        }
                                    }
                                },
                                "content": {
                                    "application/json": { "schema": { "type": "object" } },
                                    "application/vnd.api+json": { "schema": { "type": "array", "items": { "type": "string" } } }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "HeaderValue": { "type": "string", "minLength": 2 }
                }
            }
        }));
        assert_clean(&diagnostics);
        let operation = generated(&files, "zod/operations/putthing.ts");
        for expected in [
            "putThingPathIdSchema",
            "putThingQuerySearchSchema",
            "putThingHeaderXTraceSchema",
            "putThingCookieSessionSchema",
            "putThingRequestBodySchema",
            "putThingResponse200ApplicationJsonSchema",
            "putThingResponse200ApplicationVndApiJsonSchema",
            "putThingResponse400Schema",
            "putThingResponse200HeadersSchema",
            "putThingResponse400HeadersSchema",
        ] {
            assert!(
                operation.contains(expected),
                "missing {expected}: {operation}"
            );
        }
        let headers_200 = operation
            .find("putThingResponse200HeadersSchema")
            .expect("200 headers declaration");
        let headers_400 = operation
            .find("putThingResponse400HeadersSchema")
            .expect("400 headers declaration");
        assert!(headers_200 < headers_400, "{operation}");
        assert!(operation.contains(
            "{name:\"X-Required\",required:true,schema:z.lazy(() => headerValueSchema)}"
        ));
        assert!(operation.contains(
            "{name:\"X-Optional\",required:false,schema:z.number().check(integer()).check(z.gte(1))}"
        ));
        // An opaque content header contributes no schema at all: its wire value is always a string.
        assert!(operation.contains("{name:\"X-Opaque\",required:"));
        assert!(!operation.contains("\"X-Opaque\",required:true,schema:"));
        assert!(operation.contains(
            "import { type HeaderValue, headerValueSchema } from \"../components/headervalue.js\";"
        ));
        assert!(!operation.contains("Response204Schema"));
    }

    #[test]
    fn webhook_and_callback_indexes_keep_empty_entries_and_group_multiple_parents() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/first": {
                    "post": {
                        "operationId": "first",
                        "responses": { "202": { "description": "accepted" } },
                        "callbacks": {
                            "updates": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "parameters": [
                                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                                            { "name": "q", "in": "query", "schema": { "type": "string" } },
                                            { "name": "X-Key", "in": "header", "schema": { "type": "string" } },
                                            { "name": "sid", "in": "cookie", "schema": { "type": "string" } }
                                        ],
                                        "requestBody": {
                                            "content": {
                                                "application/json": { "schema": { "type": "boolean" } }
                                            }
                                        },
                                        "responses": { "204": { "description": "ok" } }
                                    },
                                    "put": { "responses": { "204": { "description": "ok" } } }
                                },
                                "{$request.query.fallback}": {
                                    "get": { "responses": { "204": { "description": "ok" } } }
                                }
                            }
                        }
                    }
                },
                "/second": {
                    "post": {
                        "operationId": "second",
                        "responses": { "202": { "description": "accepted" } },
                        "callbacks": {
                            "done": {
                                "{$request.body#/done}": {
                                    "patch": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": { "schema": { "type": "string" } }
                                            }
                                        },
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "webhooks": {
                "events": {
                    "post": {
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "q", "in": "query", "schema": { "type": "string" } },
                            { "name": "X-Key", "in": "header", "schema": { "type": "string" } },
                            { "name": "sid", "in": "cookie", "schema": { "type": "string" } }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    },
                    "delete": {
                        "parameters": [
                            { "name": "only", "in": "query", "schema": { "type": "integer" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "responseOnly": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ignored response",
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                },
                "empty": {}
            }
        }));
        assert_clean(&diagnostics);
        let webhooks = generated(&files, "zod/webhooks/index.ts");
        for expected in [
            "path: {",
            "query: {",
            "header: {",
            "cookie: {",
            "requestBody: eventsPostRequestBodySchema",
            "\"only\": eventsDeleteQueryOnlySchema",
            "\"responseOnly\": {},",
            "\"empty\": {},",
        ] {
            assert!(
                webhooks.contains(expected),
                "missing {expected}: {webhooks}"
            );
        }
        let callbacks = generated(&files, "zod/callbacks/index.ts");
        assert!(callbacks.contains("export const firstCallbacks = {"));
        assert!(callbacks.contains("export const secondCallbacks = {"));
        assert!(callbacks.contains("\"{$request.body#/url}\": {"));
        assert!(callbacks.contains("requestBody: firstUpdates_1PostRequestBodySchema"));
        assert!(!callbacks.contains("$request.query.fallback"));
        assert!(callbacks.contains("requestBody: secondDonePatchRequestBodySchema"));
    }

    #[test]
    fn unfileable_component_operation_webhook_and_callback_names_are_skipped_with_diagnostics() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/operation": {
                    "get": {
                        "operationId": "AUX",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": { "application/json": { "schema": { "type": "string" } } }
                            }
                        }
                    }
                }
            },
            "webhooks": {
                "events": {
                    "post": {
                        "operationId": "CON",
                        "requestBody": {
                            "content": {
                                "application/json": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "204": { "description": "ok" } },
                        "callbacks": {
                            "ack": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "operationId": "PRN",
                                        "requestBody": {
                                            "content": {
                                                "application/json": { "schema": { "type": "boolean" } }
                                            }
                                        },
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": { "schemas": { "NUL": { "type": "string" } } }
        }));
        assert!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == crate::emit::CODE_FILE_NAME)
                .count()
                >= 4,
            "{diagnostics:#?}"
        );
        for forbidden in [
            "zod/components/nul.ts",
            "zod/operations/aux.ts",
            "zod/webhooks/con.ts",
            "zod/callbacks/prn.ts",
        ] {
            assert!(
                files.iter().all(|file| file.relative_path != forbidden),
                "{forbidden} must not be emitted"
            );
        }
        assert!(generated(&files, "zod/webhooks/index.ts").contains("\"events\": {},"));
    }

    #[test]
    fn unknown_leaf_and_response_header_rejections_keep_zod_diagnostic_identity() {
        let (_, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "thing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "headers": {
                                    "X-Bad": { "schema": { "type": "mystery" } }
                                }
                            }
                        }
                    }
                }
            },
            "components": { "schemas": { "Unknown": { "type": "mystery" } } }
        }));
        let unknown = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_UNKNOWN_LEAF)
            .collect::<Vec<_>>();
        assert_eq!(unknown.len(), 2, "{diagnostics:#?}");
        assert!(unknown.iter().all(|diagnostic| {
            diagnostic
                .message
                .contains("zod cannot emit a check for an unsupported schema")
        }));
        assert!(unknown.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/components/schemas/Unknown")
        }));
        assert!(unknown.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some("/paths/~1thing/get/responses/200/headers/X-Bad/schema")
        }));
    }

    #[test]
    fn colliding_json_response_media_tags_warn_and_emit_the_alias() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readThing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json;a-b=1": { "schema": { "type": "string" } },
                                    "application/json;a.b=1": { "schema": { "type": "boolean" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile_with_config(
            document,
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "zod": true },
                "client": {
                    "authEnforcement": "types",
                    "baseUrl": { "source": "literal", "value": "https://api.example.test" }
                },
                "validation": {
                    "engine": "zod",
                    "request": false,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );
        assert_clean(&diagnostics);
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_MEDIA_TAG_COLLISION)
            .expect("media tag collision diagnostic");
        assert_eq!(collision.severity, Severity::Warning);
        assert!(collision.message.contains("application/json;a-b=1"));
        assert!(collision.message.contains("application/json;a.b=1"));
        assert!(
            collision
                .message
                .contains("ReadThingResponse200ApplicationJsonAB12")
        );
        let operation = generated(&files, "zod/operations/readthing.ts");
        assert_eq!(
            operation
                .matches("readThingResponse200ApplicationJsonAB1Schema")
                .count(),
            3,
            "one declaration, its z.infer reference, and the validate wrapper remain: {operation}"
        );
        assert!(operation.contains("= z.string();"));
        assert_eq!(
            operation
                .matches("readThingResponse200ApplicationJsonAB12Schema")
                .count(),
            3,
            "the aliased declaration, its z.infer reference, and validate wrapper are emitted: {operation}"
        );
        assert!(operation.contains("= z.boolean();"));
        let client = generated(&files, "client/operations/readthing.ts");
        for name in [
            "validateReadThingResponse200ApplicationJsonAB1",
            "validateReadThingResponse200ApplicationJsonAB12",
        ] {
            assert!(
                operation.contains(&format!("export function {name}(")),
                "{operation}"
            );
            assert!(client.contains(&format!("{name}(result.data")), "{client}");
        }
    }

    #[test]
    fn three_colliding_response_media_tags_increment_zod_aliases() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readThing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json;a-b=1": { "schema": { "type": "string" } },
                                    "application/json;a.b=1": { "schema": { "type": "boolean" } },
                                    "application/json;a+b=1": { "schema": { "type": "integer" } }
                                }
                            }
                        }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let aliases = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_MEDIA_TAG_COLLISION)
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), 2, "{diagnostics:#?}");
        assert!(aliases.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("ReadThingResponse200ApplicationJsonAB12")
        }));
        assert!(aliases.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("ReadThingResponse200ApplicationJsonAB13")
        }));
        let operation = generated(&files, "zod/operations/readthing.ts");
        for name in [
            "validateReadThingResponse200ApplicationJsonAB1",
            "validateReadThingResponse200ApplicationJsonAB12",
            "validateReadThingResponse200ApplicationJsonAB13",
        ] {
            assert!(
                operation.contains(&format!("export function {name}(")),
                "{operation}"
            );
        }
    }

    #[test]
    fn empty_response_media_tags_get_zod_aliases() {
        let media = ["---", "..."];
        let names = response_media_names("ReadThingResponse200", &media);
        assert_eq!(names[0].name, "ReadThingResponse200Media");
        assert_eq!(names[1].name, "ReadThingResponse200Media2");
        assert_eq!(names[1].collision, Some(media[0]));
    }

    #[test]
    fn direct_renderer_defenses_preserve_safe_fallbacks_and_empty_combinator_meaning() {
        use crate::ir::{
            PatternProperty, ResponseHeader, ResponseStatus, SchemaMeta, SchemaRef, SourceRef,
            ValidationApplicators, box_if_populated,
        };
        use crate::semantic::Analyzed;

        let temp = TempDir::new().expect("temp directory");
        fs::write(temp.path().join("openapi.json"), "{}").expect("write input");
        fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "zod": true },
                "types": { "readonly": true }
            }))
            .expect("config JSON"),
        )
        .expect("write config");
        let resolved = load_config(Some(&temp.path().join("oasts.json")), temp.path())
            .expect("config resolves");
        let analyzed = Analyzed {
            ir: crate::ir::Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let mut sink = DiagnosticSink::new();
        let mut registrar = Registrar::new(&mut sink);
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut registrar);
        let mut runtime_values = BTreeSet::new();
        let mut imports = SiblingImports::default();
        let mut lazy_closes_cycle = false;
        let factory = Emitter::new(&model).into_factory();
        let mut renderer = SchemaRenderer {
            model: &model,
            factory: &factory,
            position: TypePosition::Neutral,
            current_schema: None,
            lazy_closes_cycle: &mut lazy_closes_cycle,
            current_schema_name: "missingSchema",
            runtime_values: &mut runtime_values,
            imports: &mut imports,
        };
        let missing = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "missing.json".to_owned(),
                json_pointer: "/Missing".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        assert_eq!(renderer.render(&missing), "z.unknown()");

        let empty_finite = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: Some(Vec::new()),
            const_value: None,
            meta: SchemaMeta::default(),
        };
        assert_eq!(
            renderer.render(&empty_finite),
            "z.never().check(enumValues([]))"
        );

        let allowed_pattern_object = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                SchemaNode::Primitive {
                    ty: PrimitiveType::Boolean,
                    format: None,
                    enum_values: None,
                    const_value: None,
                    meta: SchemaMeta::default(),
                },
            ))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: SchemaMeta {
                validation_applicators: box_if_populated(ValidationApplicators {
                    pattern_properties: vec![PatternProperty {
                        pattern: "^x-".to_owned(),
                        schema: SchemaNode::Primitive {
                            ty: PrimitiveType::String,
                            format: None,
                            enum_values: None,
                            const_value: None,
                            meta: SchemaMeta::default(),
                        },
                        type_key: None,
                    }],
                    ..ValidationApplicators::default()
                }),
                ..SchemaMeta::default()
            },
        };
        assert_eq!(direct_children(&allowed_pattern_object).len(), 2);
        assert!(renderer.render(&allowed_pattern_object).contains(
            "patternProperties([[new RegExp(\"^x-\",\"u\"),z.string()]],[],z.boolean())"
        ));

        let response = ResponseEntry {
            status: ResponseStatus::Exact("200".to_owned()),
            description: "ok".to_owned(),
            media_types: Vec::new(),
            headers: vec![
                (
                    "X-Test".to_owned(),
                    ResponseHeader {
                        required: false,
                        deprecated: false,
                        description: None,
                        schema: SchemaNode::Primitive {
                            ty: PrimitiveType::String,
                            format: None,
                            enum_values: None,
                            const_value: None,
                            meta: SchemaMeta::default(),
                        },
                        content_media_type: None,
                        source: SourceRef::default(),
                    },
                ),
                // A content header declaring a media type carries JSON text on the wire, so the
                // descriptor marks it and the runtime parses before the schema sees the value.
                (
                    "X-Json".to_owned(),
                    ResponseHeader {
                        required: true,
                        deprecated: false,
                        description: None,
                        schema: SchemaNode::Primitive {
                            ty: PrimitiveType::Number,
                            format: None,
                            enum_values: None,
                            const_value: None,
                            meta: SchemaMeta::default(),
                        },
                        content_media_type: Some("application/json".to_owned()),
                        source: SourceRef::default(),
                    },
                ),
            ],
            links: Vec::new(),
            source: SourceRef::default(),
        };
        let factory = Emitter::new(&model).into_factory();
        let (header_type, header_schema) = render_headers(
            &model,
            &factory,
            &response,
            "Headers",
            &mut imports,
            &mut runtime_values,
        );
        assert!(header_type.contains("readonly \"X-Test\"?: string;"));
        assert_eq!(
            header_schema,
            "z.custom<{\n  readonly \"X-Test\"?: string;\n  readonly \"X-Json\": number;\n}>().check(headers([{name:\"X-Test\",required:false,schema:z.string()},{name:\"X-Json\",required:true,schema:z.number(),json:true}]))"
        );

        assert_eq!(union(Vec::new()), "z.never()");
        assert_eq!(union(vec!["only".to_owned()]), "only");
        assert_eq!(intersection(Vec::new()), "z.unknown()");
        assert_eq!(
            intersection(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]),
            "z.intersection(z.intersection(a,b),c)"
        );
    }

    #[test]
    fn openapi_30_schema_valued_additional_properties_use_the_catchall_schema() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Bag": {
                        "type": "object",
                        "additionalProperties": { "type": "boolean" }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let bag = component(&files, "bag");
        assert!(bag.contains(".catchall(z.boolean())"), "{bag}");
    }

    #[test]
    fn a_direct_self_reference_is_lazy_when_the_schema_root_is_not_deferred() {
        let (files, diagnostics) = compile(doc(json!({
            "SelfAlias": { "$ref": "#/components/schemas/SelfAlias" }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "selfalias").contains(
            "export const selfAliasSchema: z.ZodType<SelfAlias> = z.lazy(() => selfAliasSchema);"
        ));
    }

    #[test]
    fn operations_webhooks_and_callbacks_emit_standalone_schema_modules() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "operationId": "subscribe",
                        "parameters": [{
                            "name": "token",
                            "in": "query",
                            "schema": { "type": "string" }
                        }],
                        "responses": {
                            "202": {
                                "description": "accepted",
                                "content": {
                                    "application/json": { "schema": { "type": "boolean" } }
                                }
                            }
                        },
                        "callbacks": {
                            "onData": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": { "type": "string", "minLength": 1 }
                                                }
                                            }
                                        },
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "webhooks": {
                "pet.created": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let operation = files
            .iter()
            .find(|file| file.relative_path == "zod/operations/subscribe.ts")
            .expect("operation zod file");
        assert!(operation.content.contains("subscribeQueryTokenSchema"));
        assert!(operation.content.contains("subscribeResponse202Schema"));
        let webhook = files
            .iter()
            .find(|file| file.relative_path == "zod/webhooks/petcreatedpost.ts")
            .expect("webhook zod file");
        assert!(webhook.content.contains("petCreatedPostRequestBodySchema"));
        assert!(!webhook.content.contains("Response204Schema"));
        let callback = files
            .iter()
            .find(|file| file.relative_path == "zod/callbacks/subscribeondatapost.ts")
            .expect("callback zod file");
        assert!(
            callback
                .content
                .contains("subscribeOnDataPostRequestBodySchema")
        );
        let webhooks_index = files
            .iter()
            .find(|file| file.relative_path == "zod/webhooks/index.ts")
            .expect("webhook index");
        assert!(
            webhooks_index
                .content
                .contains("requestBody: petCreatedPostRequestBodySchema")
        );
        let callbacks_index = files
            .iter()
            .find(|file| file.relative_path == "zod/callbacks/index.ts")
            .expect("callback index");
        assert!(
            callbacks_index
                .content
                .contains("requestBody: subscribeOnDataPostRequestBodySchema")
        );
    }

    fn extract_function<'a>(source: &'a str, name: &str) -> &'a str {
        let plain = format!("function {name}");
        let exported = format!("export function {name}");
        let start = source
            .find(&exported)
            .or_else(|| source.find(&plain))
            .unwrap_or_else(|| panic!("missing function {name}"));
        let signature_end = source[start..]
            .find('\n')
            .map(|offset| start + offset)
            .expect("function signature");
        let open = source[start..signature_end]
            .rfind('{')
            .map(|offset| start + offset)
            .expect("function body");
        let mut depth = 0usize;
        for (offset, byte) in source[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[start..=open + offset];
                    }
                }
                _ => {}
            }
        }
        panic!("unterminated function {name}");
    }

    fn extract_const<'a>(source: &'a str, name: &str) -> &'a str {
        let declaration = format!("const {name} =");
        let start = source
            .find(&declaration)
            .unwrap_or_else(|| panic!("missing const {name}"));
        let end = source[start..]
            .find(';')
            .map(|offset| start + offset)
            .expect("const terminator");
        &source[start..=end]
    }

    #[test]
    #[should_panic(expected = "unterminated function broken")]
    fn runtime_function_extraction_rejects_an_unterminated_body() {
        extract_function("function broken() {\n", "broken");
    }

    #[test]
    #[should_panic(expected = "missing generated file missing.ts")]
    fn generated_file_lookup_rejects_a_missing_path() {
        generated(&[], "missing.ts");
    }

    #[test]
    #[should_panic(expected = "missing function absent")]
    fn runtime_function_extraction_rejects_a_missing_declaration() {
        extract_function("export function present() {}\n", "absent");
    }

    #[test]
    #[should_panic(expected = "missing const ABSENT")]
    fn runtime_const_extraction_rejects_a_missing_declaration() {
        extract_const("const PRESENT = 1;", "ABSENT");
    }

    #[test]
    fn zod_and_validators_runtimes_share_their_predicates() {
        for name in [
            "deepEqual",
            "decompose",
            "isMultipleOf",
            "codePointLength",
            "isLeapYear",
            "isValidDate",
            "isValidTime",
            "isValidOffset",
            "isDateTime",
            "isDate",
            "isTime",
            "isUuid",
            "isInt32",
            "int64WireValue",
        ] {
            assert_eq!(
                extract_function(ZOD_RUNTIME_TS, name),
                extract_function(VALIDATORS_RUNTIME_TS, name),
                "predicate declaration '{name}' diverged"
            );
        }
        for name in [
            "DAYS_IN_MONTH",
            "DATE_PATTERN",
            "TIME_PATTERN",
            "DATE_TIME_PATTERN",
            "UUID_PATTERN",
            "INT64_WIRE_INTEGER",
        ] {
            assert_eq!(
                extract_const(ZOD_RUNTIME_TS, name),
                extract_const(VALIDATORS_RUNTIME_TS, name),
                "predicate declaration '{name}' diverged"
            );
        }
    }
}
