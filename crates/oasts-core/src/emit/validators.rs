//! Deterministic standalone validators artifact emission.
//!
//! Emits, under the output root when the validators artifact is enabled:
//!   - `validators/standard-schema.ts` and `validators/runtime.ts` (embedded assets, verbatim);
//!   - `validators/components/<base>.ts`, one per component;
//!   - `validators/operations/<base>.ts`, one per path operation;
//!   - `validators/webhooks/<base>.ts` and `validators/callbacks/<base>.ts`, for inbound requests.
//!
//! Standalone contract: emitted validator files import ONLY from `../standard-schema.ts`,
//! `../runtime.ts`, and each other — never from the types artifact. Each file re-exports its own
//! structural type through the shared `render_type` path, so the shape is byte-identical to the
//! types artifact's for the same wire variant, and every validator const is annotated
//! `SyncStandardSchemaV1<T>` (never the bare async `StandardSchemaV1<T>`) so the frozen
//! compile-asserts keep their sync guarantee and typed phantom.
//!
//! Reject handling: a schema reachable from an emitted validator that carries an unsupported
//! validation keyword, or that degraded to an unknown leaf, fails the run with a diagnostic naming
//! the keyword/construct and its source pointer. The writer never commits a failed run, so the
//! types/client artifacts stay byte-identical when validators is disabled.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use foldhash::{HashSet, HashSetExt};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

use crate::diag::Diagnostic;
use crate::ir::{
    AdditionalProperties, ConditionalApplicator, ContainsApplicator, ExclusiveBound,
    FiniteConstraint, Operation, ParamLocation, PatternProperty, PrimitiveType, PropMeta,
    ResponseEntry, SchemaMeta, SchemaNode, SourceRef, TupleRest, finite_parts,
};
use crate::num::render_number_value;
use crate::semantic::{TargetCase, normalize_identifier};

use super::descriptor_index::{
    DescriptorTarget, Reject, SiblingImports, collect_operation_rejects, collect_rejects,
    embedded_asset, emit_callbacks_index, emit_webhooks_index, render_sibling_imports,
};
use super::model::{EmissionModel, Registrar};
use super::reads_identifier;
use super::{
    CODE_WIRE_ALIAS, CODE_WIRE_COLLISION, Emission, Emitter, EmitterFactory, GeneratedFile,
    ObjectKeyMode, OperationModule, TypeAxis, TypePosition, callback_operation, import_extension,
    lowercase_first, merge_emission, property_in_position, render_json_compact, render_ts_string,
    request_body_validator_positions, response_media_names, response_status_type_suffix,
    source_diagnostic, uppercase_first, warning_diagnostic,
};
use crate::client_model::{PrimitiveDomainProjector, build_body_plan};
use crate::response_media::media_has_validatable_schema;

/// Emitted verbatim as `validators/runtime.ts`; the generated-validator call ABI is fixed to it.
const VALIDATORS_RUNTIME_TS: &str = include_str!("../../runtime/validators-runtime.ts");
/// Emitted verbatim as `validators/standard-schema.ts`; the vendored Standard Schema declaration.
const VALIDATORS_STANDARD_SCHEMA_TS: &str =
    include_str!("../../runtime/validators-standard-schema.ts");

/// A JSON response media entry was renamed because its validator-name fragment collided.
pub(super) const CODE_MEDIA_TAG_COLLISION: &str = "OASTS6001";
/// A schema carries a validation keyword the validators artifact does not implement.
const CODE_REJECTED_KEYWORD: &str = "OASTS6002";
/// A schema degraded to an unknown leaf, so no faithful validator can be emitted for it.
const CODE_UNKNOWN_LEAF: &str = "OASTS6003";
/// An applicator's subschema is not fully checkable, so emitting the outer check would be unsound.
const CODE_INCOMPLETE_APPLICATOR: &str = "OASTS6004";

/// The diagnostic this artifact raises for one node the shared reject walk found no check for.
fn reject_diagnostic(reject: Reject<'_>, source: &SourceRef) -> Diagnostic {
    match reject {
        Reject::Keyword(keyword) => source_diagnostic(
            CODE_REJECTED_KEYWORD,
            format!(
                "validators cannot emit a check for unsupported validation keyword '{keyword}'"
            ),
            source,
        ),
        Reject::UnknownLeaf(reason) => source_diagnostic(
            CODE_UNKNOWN_LEAF,
            format!("validators cannot emit a check for an unsupported schema ({reason})"),
            source,
        ),
    }
}

/// TypeScript aborts control-flow analysis at 2,000 recursive flow-node visits. The estimate below
/// counts the flow-producing bindings, conditions, merges, mutations, and effectful calls emitted
/// for a schema. Keep each generated body at no more than half that hard limit: a compound
/// condition can contribute both its narrowing edge and its branch merge, so two compiler flow
/// nodes per estimated unit is the conservative bound.
const VALIDATOR_CFA_BUDGET: usize = 1_000;

/// The response-body validators for one declared response: its JSON media entries paired with the
/// exported names the client will call.
///
/// A response with a single JSON entry keeps the plain `validate{Stem}Response{Suffix}` name — the
/// common case, where a second entry exists but is not JSON. Two or more JSON entries each get
/// their own validator, suffixed by the media tag, because they are separate schemas the client
/// selects between on `contentType`. The shared response-media allocator resolves tag collisions
/// positionally from the response's document order, so declaration and client-call names agree.
fn response_body_validators<'ir>(
    response: &'ir crate::ir::ResponseEntry,
    stem: &str,
    suffix: &str,
    sink: &mut crate::diag::DiagnosticSink,
) -> Vec<(String, &'ir SchemaNode)> {
    let json: Vec<&crate::ir::MediaType> = response
        .media_types
        .iter()
        .filter(|media| media_has_validatable_schema(&media.essence, media.streaming_marked))
        .collect();
    if json.is_empty() {
        return Vec::new();
    }
    let media = json
        .iter()
        .map(|media| media.full.as_str())
        .collect::<Vec<_>>();
    let names = response_media_names(&format!("{stem}Response{suffix}"), &media);
    let mut named: Vec<(String, &SchemaNode)> = Vec::new();
    for (media, name) in json.into_iter().zip(names) {
        if let Some(previous) = name.collision {
            sink.push(warning_diagnostic(
                CODE_MEDIA_TAG_COLLISION,
                format!(
                    "response media type '{}' produces the same validator name as '{previous}'; emitting it as '{}'",
                    media.full, name.name
                ),
                &media.source,
            ));
        }
        named.push((name.name, &media.schema));
    }
    named
}

/// Identifiers the validators emitter injects into every generated file: the runtime kernel imports
/// (`type Issue` is always imported; the rest are pulled in on demand), the Standard Schema types,
/// and the per-file local helpers. A component whose exported type name equals one of these would
/// shadow the imported identifier (TS2440), so these names are reserved in the validators
/// name-allocation scope and any colliding component type is renamed.
const VALIDATOR_RESERVED_NAMES: &[&str] = &[
    "Issue",
    "issue",
    "appendKey",
    "deepEqual",
    "isMultipleOf",
    "codePointLength",
    "isDateTime",
    "isDate",
    "isTime",
    "isUuid",
    "isEmail",
    "isHostname",
    "isIpv4",
    "isIpv6",
    "isUri",
    "isUriReference",
    "isDuration",
    "isInt32",
    "int64WireValue",
    "StandardSchemaV1",
    "SyncStandardSchemaV1",
    "isRecord",
    "isArray",
    "hasGet",
];

pub(crate) fn emit_validators_from_model(
    model: &mut EmissionModel<'_>,
    registrar: &mut Registrar<'_>,
) -> Vec<GeneratedFile> {
    let analyzed = model.analyzed;
    // Built once per document, never per operation: this indexes every schema in the IR and
    // walks each one's projection dependencies, so constructing it inside the operation loop
    // would make request-body planning cost O(operations x schemas).
    let projector = PrimitiveDomainProjector::new(&analyzed.ir);

    // Reject-handling walk: reachable schemas with unsupported keywords or unknown-leaf degradation
    // fail the run. Every component and every operation position is emitted, so walking the
    // component schemas and operation schemas (into their children, never through `$ref` — the
    // target is itself a walked component) covers exactly the reachable set once.
    let mut rejects = Vec::new();
    let target = DescriptorTarget {
        dir: model.dirs.validators,
        export_suffix: "Validator",
    };
    {
        // The reject walk reuses the types emitter's child-walk (`SchemaChildMode::Validation`
        // visits exactly the schemas a validator would descend into), so this borrows `model`
        // read-only through an emitter that is dropped before `reserve_names` needs it back.
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

    // Validators is the terminal emitter, so renaming component targets that collide with the
    // injected kernel identifiers here is safe — no later emitter reads the allocation.
    model.reserve_names(VALIDATOR_RESERVED_NAMES);
    // Every rename this artifact performs is done. From here the allocation is frozen, so the model
    // is reborrowed shared for the whole emission — which is what lets one emitter factory span the
    // loops below while diagnostics and path registrations still flow through the registrar.
    let model = &*model;
    // One factory for the artifact, rather than the three `Emitter::new` rebuilds this emitter used
    // to pay per item. Each rebuild reindexed every enum member; `worker()` still hands each item
    // its own empty alias and diagnostic cells, so a worker is exactly the emitter it replaces.
    let factory = Emitter::new(model).into_factory();

    let mut files = Vec::new();
    files.push(embedded_asset(
        model,
        registrar,
        target,
        "runtime.ts",
        VALIDATORS_RUNTIME_TS,
    ));
    files.push(embedded_asset(
        model,
        registrar,
        target,
        "standard-schema.ts",
        VALIDATORS_STANDARD_SCHEMA_TS,
    ));

    for allocated in &analyzed.schema_names {
        let Some(file_base) = model.component_files[allocated.schema_index].clone() else {
            continue;
        };
        // The export name is the (possibly reserved-renamed) target name, so it agrees with the
        // structural type, self/cross references, and sibling imports — all of which read the target.
        // An allocated file always has a registered target (allocate_paths sets both together).
        let schema = &analyzed.ir.schemas[allocated.schema_index];
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
            &file_base,
            &name,
        );
        merge_emission(&mut files, registrar, emission);
    }
    for allocated in &analyzed.operation_names {
        let Some(file_base) = model.operation_files[allocated.operation_index].clone() else {
            continue;
        };
        let operation = &analyzed.ir.operations[allocated.operation_index];
        let mut emission = Emission::default();
        emit_operation_file(
            model,
            &factory,
            &mut emission,
            &projector,
            operation,
            OperationModule {
                allocated_name: &allocated.name,
                directory: "operations",
                file_base: &file_base,
                include_responses: true,
            },
        );
        merge_emission(&mut files, registrar, emission);
    }
    if !analyzed.ir.webhooks.is_empty() {
        for index in 0..analyzed.webhook_names.len() {
            let Some(file_base) = model.webhook_files[index].clone() else {
                continue;
            };
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
                    file_base: &file_base,
                    include_responses: false,
                },
            );
            merge_emission(&mut files, registrar, emission);
        }
        files.push(emit_webhooks_index(model, target));
    }
    if !analyzed.callback_names.is_empty() {
        for index in 0..analyzed.callback_names.len() {
            let Some(file_base) = model.callback_files[index].clone() else {
                continue;
            };
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
                    file_base: &file_base,
                    include_responses: false,
                },
            );
            merge_emission(&mut files, registrar, emission);
        }
        files.push(emit_callbacks_index(model, target));
    }
    files
}

// --- per-file scope ----------------------------------------------------------------------------

/// File-scoped state accumulated while generating a file's validate bodies: the runtime value
/// imports actually used, whether the record/array narrowing guards are needed, and the lazily
/// cached regex patterns (slot = index).
#[derive(Clone, Debug, Eq, PartialEq)]
struct IncompleteApplicator {
    keyword: &'static str,
    source: SourceRef,
}

#[derive(Clone, Default)]
struct FileScope {
    runtime_values: BTreeSet<&'static str>,
    needs_is_record: bool,
    needs_is_array: bool,
    patterns: Vec<(String, bool)>,
    incomplete_applicators: Vec<IncompleteApplicator>,
}

impl FileScope {
    /// Returns the module-scope cache slot for a pattern string, deduplicating equal patterns.
    fn pattern_slot(&mut self, pattern: &str, unicode: bool) -> usize {
        if let Some(index) = self
            .patterns
            .iter()
            .position(|existing| existing.0 == pattern && existing.1 == unicode)
        {
            return index;
        }
        self.patterns.push((pattern.to_owned(), unicode));
        self.patterns.len() - 1
    }

    fn record_incomplete_applicator(&mut self, keyword: &'static str, source: &SourceRef) {
        let incomplete = IncompleteApplicator {
            keyword,
            source: source.clone(),
        };
        if !self.incomplete_applicators.contains(&incomplete) {
            self.incomplete_applicators.push(incomplete);
        }
    }
}

fn report_incomplete_applicators(sink: &mut crate::diag::DiagnosticSink, scope: &FileScope) {
    for incomplete in &scope.incomplete_applicators {
        sink.push(source_diagnostic(
            CODE_INCOMPLETE_APPLICATOR,
            format!(
                "validators cannot emit '{}' because a required subschema is not fully checkable",
                incomplete.keyword
            ),
            &incomplete.source,
        ));
    }
}

/// A saturated estimate of the maximum TypeScript control-flow depth contributed by an emitted
/// schema. It models the constructs the binder turns into flow nodes rather than source lines:
/// initialized locals, narrowing conditions and their merges, mutations, loop labels, and dotted
/// assertion calls. Saturation keeps the walk O(schema size) without allowing arithmetic overflow;
/// callers only need to know whether a subtree crosses the split budget.
fn validation_flow_cost(schema: &SchemaNode, position: TypePosition) -> usize {
    let cap = VALIDATOR_CFA_BUDGET + 1;
    let add = |left: usize, right: usize| left.saturating_add(right).min(cap);
    let checks = |count: usize| count.saturating_mul(3).min(cap);
    let meta = schema.meta();
    let typeless = || {
        let numeric = meta.numeric_constraints().minimum.is_some() as usize
            + meta.numeric_constraints().maximum.is_some() as usize
            + meta.numeric_constraints().exclusive_minimum.is_some() as usize
            + meta.numeric_constraints().exclusive_maximum.is_some() as usize
            + meta.numeric_constraints().multiple_of.is_some() as usize;
        let string = meta.string_constraints().min_length.is_some() as usize
            + meta.string_constraints().max_length.is_some() as usize
            + meta.string_constraints().pattern.is_some() as usize;
        let array = meta.array_constraints().min_items.is_some() as usize
            + meta.array_constraints().max_items.is_some() as usize
            + usize::from(meta.array_constraints().unique_items) * 4;
        let object = meta.object_constraints().min_properties.is_some() as usize
            + meta.object_constraints().max_properties.is_some() as usize
            + meta.object_constraints().required.len();
        checks(numeric + string + array + object)
    };
    let base = match schema {
        SchemaNode::Ref { .. } | SchemaNode::Unknown { .. } => 0,
        SchemaNode::Primitive {
            ty,
            format,
            enum_values,
            const_value,
            ..
        } => {
            let constraints = match ty {
                PrimitiveType::String => {
                    meta.string_constraints().min_length.is_some() as usize
                        + meta.string_constraints().max_length.is_some() as usize
                        + meta.string_constraints().pattern.is_some() as usize
                        + usize::from(
                            format
                                .as_deref()
                                .and_then(string_format_predicate)
                                .is_some(),
                        )
                }
                PrimitiveType::Number | PrimitiveType::Integer => {
                    meta.numeric_constraints().minimum.is_some() as usize
                        + meta.numeric_constraints().maximum.is_some() as usize
                        + meta.numeric_constraints().exclusive_minimum.is_some() as usize
                        + meta.numeric_constraints().exclusive_maximum.is_some() as usize
                        + meta.numeric_constraints().multiple_of.is_some() as usize
                        + usize::from(
                            matches!(ty, PrimitiveType::Integer)
                                && format.as_deref() == Some("int32"),
                        )
                }
                PrimitiveType::Boolean | PrimitiveType::Null => 0,
            };
            let finite = enum_values
                .as_ref()
                .map_or(0, |values| values.len().max(1).saturating_add(2))
                + usize::from(const_value.is_some()) * 3;
            add(3, add(checks(constraints), finite))
        }
        SchemaNode::Finite {
            enum_values,
            const_value,
            ..
        } => enum_values
            .as_ref()
            .map_or(0, |values| values.len().max(1).saturating_add(2))
            .saturating_add(usize::from(const_value.is_some()) * 3)
            .min(cap),
        SchemaNode::Object {
            properties,
            additional_properties,
            dependent_required,
            finite,
            extra_required,
            ..
        } => {
            let mut cost = 11;
            for (_, property, property_meta) in properties {
                if !property_in_position(property_meta, position) {
                    continue;
                }
                let property_cost = if is_noop_schema(property) {
                    usize::from(property_meta.required) * 3
                } else {
                    add(4, validation_flow_cost(property, position))
                };
                cost = add(cost, property_cost);
            }
            cost = add(cost, checks(extra_required.len()));
            for (_, dependents) in dependent_required {
                cost = add(cost, add(2, checks(dependents.len())));
            }
            cost = add(
                cost,
                match additional_properties {
                    AdditionalProperties::Forbidden => add(
                        add(5, properties.len()),
                        meta.validation_applicators().pattern_properties.len(),
                    ),
                    AdditionalProperties::Schema(sub) if !is_noop_schema(sub) => add(
                        add(
                            add(6, properties.len()),
                            meta.validation_applicators().pattern_properties.len(),
                        ),
                        validation_flow_cost(sub, position),
                    ),
                    AdditionalProperties::Schema(_) | AdditionalProperties::Allowed(_) => 0,
                },
            );
            cost = add(
                cost,
                checks(
                    meta.object_constraints().min_properties.is_some() as usize
                        + meta.object_constraints().max_properties.is_some() as usize,
                ),
            );
            let (enum_values, const_value) = finite_parts(finite);
            add(
                cost,
                enum_values.map_or(0, |values| values.len().max(1).saturating_add(2))
                    + usize::from(const_value.is_some()) * 3,
            )
        }
        SchemaNode::Array { items, finite, .. } => {
            let item_cost = if is_noop_schema(items) {
                0
            } else {
                add(4, validation_flow_cost(items, position))
            };
            let constraints = meta.array_constraints().min_items.is_some() as usize
                + meta.array_constraints().max_items.is_some() as usize
                + usize::from(meta.array_constraints().unique_items) * 4;
            let (enum_values, const_value) = finite_parts(finite);
            add(
                add(8, add(item_cost, checks(constraints))),
                enum_values.map_or(0, |values| values.len().max(1).saturating_add(2))
                    + usize::from(const_value.is_some()) * 3,
            )
        }
        SchemaNode::Tuple {
            prefix_items,
            rest,
            finite,
            ..
        } => {
            let mut cost = 13;
            for prefix in prefix_items {
                if !is_noop_schema(prefix) {
                    cost = add(cost, add(4, validation_flow_cost(prefix, position)));
                }
            }
            cost = add(
                cost,
                match rest {
                    TupleRest::Schema(sub) if !is_noop_schema(sub) => {
                        add(4, validation_flow_cost(sub, position))
                    }
                    TupleRest::Forbidden => 3,
                    TupleRest::Schema(_) | TupleRest::Allowed => 0,
                },
            );
            let constraints = meta.array_constraints().min_items.is_some() as usize
                + meta.array_constraints().max_items.is_some() as usize
                + usize::from(meta.array_constraints().unique_items) * 4;
            cost = add(cost, checks(constraints));
            let (enum_values, const_value) = finite_parts(finite);
            add(
                cost,
                enum_values.map_or(0, |values| values.len().max(1).saturating_add(2))
                    + usize::from(const_value.is_some()) * 3,
            )
        }
        SchemaNode::AllOf { branches, .. } => branches.iter().fold(0, |cost, branch| {
            add(cost, validation_flow_cost(branch, position))
        }),
        SchemaNode::AnyOf { branches, .. } | SchemaNode::OneOf { branches, .. } => {
            branches.iter().fold(4, |cost, branch| {
                add(cost, add(16, validation_flow_cost(branch, position)))
            })
        }
        SchemaNode::Never { .. } => 1,
        SchemaNode::Any { .. } => typeless(),
    };
    let applicators = meta.validation_applicators();
    let with_not = applicators
        .not
        .as_ref()
        .map_or(0, |schema| add(4, validation_flow_cost(schema, position)));
    let with_property_names = applicators
        .property_names
        .as_ref()
        .map_or(0, |schema| add(7, validation_flow_cost(schema, position)));
    let with_pattern_properties = applicators
        .pattern_properties
        .iter()
        .fold(0, |cost, pattern| {
            add(
                cost,
                add(7, validation_flow_cost(&pattern.schema, position)),
            )
        });
    let with_contains = applicators.contains.as_ref().map_or(0, |contains| {
        let bounds = usize::from(contains.min_contains.is_some())
            + usize::from(contains.max_contains.is_some());
        add(
            add(10, checks(bounds.max(1))),
            validation_flow_cost(&contains.schema, position),
        )
    });
    let with_dependent_schemas = applicators
        .dependent_schemas
        .iter()
        .fold(0, |cost, (_, schema)| {
            add(cost, add(4, validation_flow_cost(schema, position)))
        });
    let with_conditional = applicators.conditional.as_ref().map_or(0, |conditional| {
        let condition = add(12, validation_flow_cost(&conditional.condition, position));
        let then_schema = conditional
            .then_schema
            .as_ref()
            .map_or(0, |schema| validation_flow_cost(schema, position));
        let else_schema = conditional
            .else_schema
            .as_ref()
            .map_or(0, |schema| validation_flow_cost(schema, position));
        add(condition, add(then_schema, else_schema))
    });
    let with_unevaluated_properties = applicators
        .unevaluated_properties
        .as_ref()
        .map_or(0, |schema| add(12, validation_flow_cost(schema, position)));
    let with_unevaluated_items = applicators
        .unevaluated_items
        .as_ref()
        .map_or(0, |schema| add(12, validation_flow_cost(schema, position)));
    add(
        base,
        add(
            add(with_not, with_property_names),
            add(
                with_pattern_properties,
                add(
                    with_contains,
                    add(
                        with_dependent_schemas,
                        add(
                            with_conditional,
                            add(with_unevaluated_properties, with_unevaluated_items),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn schema_path_digest(path: &[String]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    for segment in path {
        hasher.update(
            u64::try_from(segment.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(segment.as_bytes());
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

// --- validate-body code generation -------------------------------------------------------------

/// One validate-function body under construction: indented output plus a monotonic counter that
/// names locals uniquely across the whole function so nested scopes never shadow. Borrows the
/// file-scoped runtime state and sibling imports (both accumulate across the file's declarations)
/// plus the immutable emission `model` (for `$ref` target resolution); `position` is the fixed wire
/// variant of the declaration being generated.
struct FnBody<'scope, 'model, 'input> {
    out: String,
    helpers: Vec<String>,
    indent: usize,
    counter: usize,
    helper_prefix: String,
    schema_path: Vec<String>,
    scope: &'scope mut FileScope,
    imports: &'scope mut SiblingImports,
    model: &'model EmissionModel<'input>,
    position: TypePosition,
    completeness: Vec<bool>,
    probing_refs: HashSet<(String, String)>,
}

#[derive(Clone, Default)]
struct EvaluationCallbacks {
    property: Option<String>,
    item: Option<String>,
}

struct BranchEvaluation {
    callbacks: EvaluationCallbacks,
    properties: Option<String>,
    items: Option<String>,
    /// Byte range of the two lines declaring the property recorder, and of the item pair. A branch
    /// only reports one evaluation kind unless the schema asks for both, so the other pair is
    /// dropped once the branch body has been emitted and shown not to reference it.
    property_declaration: Option<Range<usize>>,
    item_declaration: Option<Range<usize>>,
}

/// The two declared types the `value` parameter takes across emitted validator signatures.
const VALUE_UNKNOWN: &str = "unknown";
const VALUE_RECORD: &str = "{ [key: string]: unknown }";

/// The `value` parameter, `_`-prefixed when the body never reads it. An uninhabitable schema's
/// validator rejects every instance without inspecting one, and a branch helper past the
/// control-flow-analysis limit delegates without touching it.
fn value_parameter(body: &str, declared_type: &str) -> String {
    let prefix = if reads_identifier(body, "value") {
        ""
    } else {
        "_"
    };
    format!("{prefix}value: {declared_type}")
}

/// The evaluation-tracking parameter list, `_`-prefixed on whichever the body never reads. They
/// stay declared so every validator keeps one calling convention and every delegate call keeps its
/// arity; `noUnusedParameters` exempts the prefixed spelling and reports the plain one.
fn evaluation_parameters(body: &str) -> String {
    let property = if reads_identifier(body, "evaluatedProperty") {
        ""
    } else {
        "_"
    };
    let item = if reads_identifier(body, "evaluatedItem") {
        ""
    } else {
        "_"
    };
    format!(
        "{property}evaluatedProperty?: (key: string) => void, {item}evaluatedItem?: (index: number) => void"
    )
}

impl EvaluationCallbacks {
    fn root() -> Self {
        Self {
            property: Some("evaluatedProperty".to_owned()),
            item: Some("evaluatedItem".to_owned()),
        }
    }

    fn is_empty(&self) -> bool {
        self.property.is_none() && self.item.is_none()
    }

    fn argument(callback: &Option<String>) -> &str {
        callback.as_deref().unwrap_or("undefined")
    }
}

impl<'scope, 'model, 'input> FnBody<'scope, 'model, 'input> {
    fn new(
        scope: &'scope mut FileScope,
        imports: &'scope mut SiblingImports,
        model: &'model EmissionModel<'input>,
        position: TypePosition,
        helper_prefix: &str,
        root_path: String,
    ) -> Self {
        Self {
            out: String::new(),
            helpers: Vec::new(),
            indent: 1,
            counter: 0,
            helper_prefix: helper_prefix.to_owned(),
            schema_path: vec![root_path],
            scope,
            imports,
            model,
            position,
            completeness: Vec::new(),
            probing_refs: HashSet::new(),
        }
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn open(&mut self, text: &str) {
        self.line(text);
        self.indent += 1;
    }

    fn close(&mut self, text: &str) {
        self.indent -= 1;
        self.line(text);
    }

    fn fresh(&mut self) -> usize {
        let value = self.counter;
        self.counter += 1;
        value
    }

    fn finish(self) -> (String, String) {
        debug_assert!(self.completeness.is_empty());
        (self.helpers.concat(), self.out)
    }

    fn mark_incomplete(&mut self) {
        if let Some(complete) = self.completeness.last_mut() {
            *complete = false;
        }
    }

    fn finish_completeness(&mut self) -> bool {
        // Every schema generation entry pushes one completeness scope before it can finish.
        let complete = self
            .completeness
            .pop()
            .expect("schema emission starts a completeness scope");
        if !complete {
            self.mark_incomplete();
        }
        complete
    }

    fn branch_evaluation(
        &mut self,
        evaluation: &EvaluationCallbacks,
        suffix: &str,
    ) -> BranchEvaluation {
        let mut callbacks = EvaluationCallbacks::default();
        let mut property_declaration = None;
        let properties = evaluation.property.as_ref().map(|_| {
            let values = format!("branchProperties{suffix}");
            let callback = format!("recordBranchProperty{suffix}");
            let start = self.out.len();
            self.line(&format!("const {values}: string[] = [];"));
            self.line(&format!(
                "const {callback} = (key: string): void => {{ {values}.push(key); }};"
            ));
            property_declaration = Some(start..self.out.len());
            callbacks.property = Some(callback);
            values
        });
        let mut item_declaration = None;
        let items = evaluation.item.as_ref().map(|_| {
            let values = format!("branchItems{suffix}");
            let callback = format!("recordBranchItem{suffix}");
            let start = self.out.len();
            self.line(&format!("const {values}: number[] = [];"));
            self.line(&format!(
                "const {callback} = (index: number): void => {{ {values}.push(index); }};"
            ));
            item_declaration = Some(start..self.out.len());
            callbacks.item = Some(callback);
            values
        });
        BranchEvaluation {
            callbacks,
            properties,
            items,
            property_declaration,
            item_declaration,
        }
    }

    /// Drops whichever branch recorder the emitted branch never passed on. The enclosing schema
    /// declares both evaluation kinds whenever it tracks either, so a branch that only reports
    /// properties would otherwise carry an item recorder nothing reads — and a collection nothing
    /// ever fills, which the merge below would then walk for no reason.
    ///
    /// Called after the branch body is emitted; the incomplete-applicator paths truncate `self.out`
    /// and return before reaching it, so the recorded ranges are only ever read while still valid.
    fn prune_unused_branch_evaluation(&mut self, branch: &mut BranchEvaluation) {
        // Items first: dropping the earlier property pair would move this range.
        for (declaration, callback, values) in [
            (
                &mut branch.item_declaration,
                &mut branch.callbacks.item,
                &mut branch.items,
            ),
            (
                &mut branch.property_declaration,
                &mut branch.callbacks.property,
                &mut branch.properties,
            ),
        ] {
            // Zipped rather than unwrapped one at a time: `branch_evaluation` writes the
            // declaration and the callback name together or not at all, so a shape where only one
            // of them is present has no way to arise and no arm should claim to handle it.
            let Some((range, name)) = declaration.clone().zip(callback.clone()) else {
                continue;
            };
            if reads_identifier(&self.out[range.end..], &name) {
                continue;
            }
            self.out.replace_range(range, "");
            *declaration = None;
            *callback = None;
            *values = None;
        }
    }

    fn merge_branch_evaluation(
        &mut self,
        branch: &BranchEvaluation,
        evaluation: &EvaluationCallbacks,
    ) {
        if let (Some(values), Some(callback)) =
            (branch.properties.as_deref(), evaluation.property.as_deref())
        {
            self.open(&format!("for (const key of {values}) {{"));
            self.line(&format!("{callback}?.(key);"));
            self.close("}");
        }
        if let (Some(values), Some(callback)) =
            (branch.items.as_deref(), evaluation.item.as_deref())
        {
            self.open(&format!("for (const index of {values}) {{"));
            self.line(&format!("{callback}?.(index);"));
            self.close("}");
        }
    }

    /// Emits a single `if (condition) { issues.push(issue(path, message)); }` check.
    fn push_issue(&mut self, condition: &str, path: &str, iss: &str, message: &str) {
        self.scope.runtime_values.insert("issue");
        self.open(&format!("if ({condition}) {{"));
        self.line(&format!(
            "{iss}.push(issue({path}, {}));",
            render_ts_string(message)
        ));
        self.close("}");
    }

    /// Emits the `else`/`else if (value !== null)` type-mismatch arm shared by every primitive and
    /// container gate, then closes the block. Takes the base expected-type name and widens the
    /// mismatch message with `, null` exactly when the gate is nullable — the same flag that selects
    /// the `!== null` arm. (Tuples are never nullable — `nullable` is a 3.0-only keyword and 3.1
    /// tuples take the `prefixItems` path before any type-array `null` widening — so they always
    /// take the non-nullable arm.)
    fn close_type_gate(&mut self, nullable: bool, val: &str, path: &str, iss: &str, base: &str) {
        let type_list = if nullable {
            format!("{base}, null")
        } else {
            base.to_owned()
        };
        self.indent -= 1;
        if nullable {
            self.open(&format!("}} else if ({val} !== null) {{"));
        } else {
            self.open("} else {");
        }
        self.scope.runtime_values.insert("issue");
        self.line(&format!(
            "{iss}.push(issue({path}, {}));",
            render_ts_string(&format!("expected type {type_list}"))
        ));
        self.close("}");
    }

    fn helper_name(&self, role: &str, part: Option<usize>) -> String {
        let digest = schema_path_digest(&self.schema_path);
        let suffix = part.map_or_else(String::new, |index| format!("Part{index}"));
        format!("validate{}{}{}{}", self.helper_prefix, role, digest, suffix)
    }

    fn gen_root_schema(&mut self, schema: &SchemaNode, val: &str, path: &str, iss: &str) -> bool {
        self.gen_schema_inline(schema, val, path, iss, &EvaluationCallbacks::root())
    }

    fn gen_schema(
        &mut self,
        schema: &SchemaNode,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) -> bool {
        if validation_flow_cost(schema, self.position) > VALIDATOR_CFA_BUDGET {
            self.gen_schema_helper(schema, val, path, iss, evaluation)
        } else {
            self.gen_schema_inline(schema, val, path, iss, evaluation)
        }
    }

    fn gen_child_schema(
        &mut self,
        segment: String,
        schema: &SchemaNode,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) -> bool {
        self.schema_path.push(segment);
        let complete = self.gen_schema(schema, val, path, iss, evaluation);
        self.schema_path.pop();
        complete
    }

    fn gen_schema_helper(
        &mut self,
        schema: &SchemaNode,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) -> bool {
        let name = self.helper_name("At", None);
        let parent_out = std::mem::take(&mut self.out);
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        self.indent = 1;
        self.counter = 0;
        let complete = self.gen_schema_inline(
            schema,
            "value",
            "path",
            "issues",
            &EvaluationCallbacks::root(),
        );
        let helper_body = std::mem::replace(&mut self.out, parent_out);
        let evaluation_parameters = evaluation_parameters(&helper_body);
        let value_parameter = value_parameter(&helper_body, VALUE_UNKNOWN);
        self.indent = parent_indent;
        self.counter = parent_counter;
        self.helpers.push(format!(
            "function {name}({value_parameter}, path: readonly (string | number)[], issues: Issue[], {evaluation_parameters}): void {{\n{helper_body}}}\n\n"
        ));
        if evaluation.is_empty() {
            self.line(&format!("{name}({val}, {path}, {iss});"));
        } else {
            self.line(&format!(
                "{name}({val}, {path}, {iss}, {}, {});",
                EvaluationCallbacks::argument(&evaluation.property),
                EvaluationCallbacks::argument(&evaluation.item)
            ));
        }
        complete
    }

    fn gen_schema_inline(
        &mut self,
        schema: &SchemaNode,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) -> bool {
        self.completeness.push(true);
        if !schema.meta().rejected_validation_keywords.is_empty() {
            self.mark_incomplete();
        }
        let applicators = schema.meta().validation_applicators();
        let outer_evaluation = evaluation.clone();
        let mut active_evaluation = evaluation.clone();
        let local_properties = applicators.unevaluated_properties.as_ref().map(|_| {
            let index = self.fresh();
            let values = format!("evaluatedProperties{index}");
            let callback = format!("recordProperty{index}");
            self.line(&format!("const {values}: string[] = [];"));
            self.line(&format!(
                "const {callback} = (key: string): void => {{ {values}.push(key); }};"
            ));
            active_evaluation.property = Some(callback);
            values
        });
        let local_items = applicators.unevaluated_items.as_ref().map(|_| {
            let index = self.fresh();
            let values = format!("evaluatedItems{index}");
            let callback = format!("recordItem{index}");
            self.line(&format!("const {values}: number[] = [];"));
            self.line(&format!(
                "const {callback} = (index: number): void => {{ {values}.push(index); }};"
            ));
            active_evaluation.item = Some(callback);
            values
        });
        match schema {
            SchemaNode::Ref { target, .. } => {
                if let Some(resolved) = self
                    .model
                    .schema_target(&target.source_id, &target.json_pointer)
                {
                    // Delegate to the referent's position variant: a request-position body must call
                    // `validate{Name}Request`, which does not demand the `readOnly` properties the
                    // request shape drops. `variant_name(Neutral)` is the bare name, so neutral bodies
                    // are unaffected.
                    let validator = format!("validate{}", resolved.variant_name(self.position));
                    self.imports.record_export(
                        resolved.index,
                        &resolved.file_base,
                        validator.clone(),
                    );
                    if active_evaluation.is_empty() {
                        self.line(&format!("{validator}({val}, {path}, {iss});"));
                    } else {
                        self.line(&format!(
                            "{validator}({val}, {path}, {iss}, {}, {});",
                            EvaluationCallbacks::argument(&active_evaluation.property),
                            EvaluationCallbacks::argument(&active_evaluation.item)
                        ));
                    }
                    let key = (target.source_id.clone(), target.json_pointer.clone());
                    if self.probing_refs.insert(key.clone()) {
                        let referenced = &self.model.analyzed.ir.schemas[resolved.index].schema;
                        let complete = self.probe_schema(referenced);
                        self.probing_refs.remove(&key);
                        if !complete {
                            self.mark_incomplete();
                        }
                    }
                } else {
                    self.mark_incomplete();
                }
                // An unresolved reference is already reported as OASTS4203 by the types pass.
            }
            SchemaNode::Primitive {
                ty,
                format,
                enum_values,
                const_value,
                meta,
            } => {
                let bigint_int64 = self.model.transform_facts().site(schema)
                    == Some(crate::transform::TransformKind::IntegerBigInt);
                if bigint_int64 {
                    self.gen_bigint_int64(meta, val, path, iss);
                } else {
                    self.gen_primitive(*ty, format.as_deref(), meta, val, path, iss);
                }
                self.gen_finite(enum_values.as_deref(), const_value.as_ref(), val, path, iss);
            }
            SchemaNode::Finite {
                enum_values,
                const_value,
                ..
            } => {
                self.gen_finite(enum_values.as_deref(), const_value.as_ref(), val, path, iss);
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                dependent_required,
                finite,
                extra_required,
                meta,
            } => {
                let force_split =
                    validation_flow_cost(schema, self.position) > VALIDATOR_CFA_BUDGET;
                self.gen_object(
                    ObjectParts {
                        properties,
                        additional_properties,
                        additional_properties_present: meta.additional_properties_present,
                        dependent_required,
                        extra_required,
                        meta,
                    },
                    force_split,
                    val,
                    path,
                    iss,
                    &active_evaluation,
                );
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::Array {
                items,
                finite,
                meta,
                ..
            } => {
                self.gen_array(items, meta, val, path, iss, &active_evaluation);
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::Tuple {
                prefix_items,
                rest,
                finite,
                meta,
            } => {
                self.gen_tuple(
                    TupleParts { prefix_items, rest },
                    meta,
                    val,
                    path,
                    iss,
                    &active_evaluation,
                );
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::AllOf { branches, .. } => {
                self.gen_all_of(branches, val, path, iss, &active_evaluation);
            }
            SchemaNode::AnyOf { branches, .. } => {
                self.gen_composition(
                    branches,
                    val,
                    path,
                    iss,
                    Composition::AnyOf,
                    &active_evaluation,
                );
            }
            SchemaNode::OneOf { branches, .. } => {
                self.gen_composition(
                    branches,
                    val,
                    path,
                    iss,
                    Composition::OneOf,
                    &active_evaluation,
                );
            }
            SchemaNode::Never { .. } => {
                // A `false` schema admits nothing; an empty body would accept every input. Reject
                // unconditionally. `Any` accepts all (empty body is correct); `Unknown` is already
                // rejected at generation by the reject walk.
                self.scope.runtime_values.insert("issue");
                self.line(&format!(
                    "{iss}.push(issue({path}, {}));",
                    render_ts_string("value not allowed")
                ));
            }
            SchemaNode::Any { meta } => {
                // A typeless schema carrying assertions (`{minLength: 3}`) constrains only values of
                // the matching type and vacuously accepts every other type; a plain free-form `Any`
                // carries no constraint group and emits nothing. `Unknown` accepts all (the reject
                // walk already failed the run for it).
                self.gen_typeless_constraints(meta, val, path, iss);
            }
            SchemaNode::Unknown { .. } => self.mark_incomplete(),
        }
        self.gen_validation_applicators(ApplicatorParts {
            meta: schema.meta(),
            val,
            path,
            iss,
            evaluation: &active_evaluation,
            evaluated_properties: local_properties.as_deref(),
            evaluated_items: local_items.as_deref(),
        });
        if let (Some(values), Some(callback)) = (
            local_properties.as_deref(),
            outer_evaluation.property.as_deref(),
        ) {
            self.open(&format!("for (const key of {values}) {{"));
            self.line(&format!("{callback}?.(key);"));
            self.close("}");
        }
        if let (Some(values), Some(callback)) =
            (local_items.as_deref(), outer_evaluation.item.as_deref())
        {
            self.open(&format!("for (const index of {values}) {{"));
            self.line(&format!("{callback}?.(index);"));
            self.close("}");
        }
        self.finish_completeness()
    }

    /// Runs the real child emitter transactionally and discards every generated byte/import/helper.
    /// The returned completeness bit therefore comes from the same branches that produce code,
    /// including checks reached through `$ref`, without maintaining a parallel capability table.
    fn probe_schema(&mut self, schema: &SchemaNode) -> bool {
        let parent_out = std::mem::take(&mut self.out);
        let parent_helpers = std::mem::take(&mut self.helpers);
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        let complete = self.gen_schema(
            schema,
            "value",
            "path",
            "issues",
            &EvaluationCallbacks::default(),
        );

        self.out = parent_out;
        self.helpers = parent_helpers;
        self.indent = parent_indent;
        self.counter = parent_counter;
        *self.scope = parent_scope;
        *self.imports = parent_imports;
        complete
    }

    fn gen_validation_applicators(&mut self, parts: ApplicatorParts<'_>) {
        let ApplicatorParts {
            meta,
            val,
            path,
            iss,
            evaluation,
            evaluated_properties,
            evaluated_items,
        } = parts;
        let applicators = meta.validation_applicators();
        if let Some(schema) = &applicators.not {
            self.gen_not(schema, val, path, iss);
        }
        if let Some(schema) = &applicators.property_names {
            self.gen_property_names(schema, val, path, iss);
        }
        if !applicators.pattern_properties.is_empty() {
            self.gen_pattern_properties(
                &applicators.pattern_properties,
                val,
                path,
                iss,
                evaluation,
            );
        }
        if let Some(contains) = &applicators.contains {
            self.gen_contains(contains, val, path, iss, evaluation);
        }
        if !applicators.dependent_schemas.is_empty() {
            self.gen_dependent_schemas(&applicators.dependent_schemas, val, path, iss, evaluation);
        }
        if let Some(conditional) = &applicators.conditional {
            self.gen_conditional(conditional, val, path, iss, evaluation);
        }
        // Applicators are generated only from inside `gen_schema`, after it pushed this scope.
        let annotation_sources_complete = self
            .completeness
            .last()
            .copied()
            .expect("validation applicators run inside a completeness scope");
        if let (Some(schema), Some(evaluated)) = (
            applicators.unevaluated_properties.as_deref(),
            evaluated_properties,
        ) {
            if annotation_sources_complete {
                self.gen_unevaluated_properties(schema, evaluated, val, path, iss, evaluation);
            } else {
                self.scope
                    .record_incomplete_applicator("unevaluatedProperties", &schema.meta().source);
            }
        }
        if let (Some(schema), Some(evaluated)) =
            (applicators.unevaluated_items.as_deref(), evaluated_items)
        {
            if annotation_sources_complete {
                self.gen_unevaluated_items(schema, evaluated, val, path, iss, evaluation);
            } else {
                self.scope
                    .record_incomplete_applicator("unevaluatedItems", &schema.meta().source);
            }
        }
    }

    fn gen_not(&mut self, schema: &SchemaNode, val: &str, path: &str, iss: &str) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.runtime_values.insert("issue");
        let scratch = format!("issues{}", self.fresh());
        self.line(&format!("const {scratch}: Issue[] = [];"));
        let complete = self.gen_child_schema(
            "not".to_owned(),
            schema,
            val,
            path,
            &scratch,
            &EvaluationCallbacks::default(),
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("not", &schema.meta().source);
            return;
        }
        self.open(&format!("if ({scratch}.length === 0) {{"));
        self.line(&format!(
            "{iss}.push(issue({path}, \"value matches not schema\"));"
        ));
        self.close("}");
    }

    fn gen_property_names(&mut self, schema: &SchemaNode, val: &str, path: &str, iss: &str) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_record = true;
        self.scope.runtime_values.insert("appendKey");
        self.scope.runtime_values.insert("issue");
        self.open(&format!("if (isRecord({val})) {{"));
        self.open(&format!("for (const key of Object.keys({val})) {{"));
        let scratch = format!("issues{}", self.fresh());
        let child_path = format!("appendKey({path}, key)");
        self.line(&format!("const {scratch}: Issue[] = [];"));
        let complete = self.gen_child_schema(
            "propertyNames".to_owned(),
            schema,
            "key",
            &child_path,
            &scratch,
            &EvaluationCallbacks::default(),
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("propertyNames", &schema.meta().source);
            return;
        }
        self.open(&format!("if ({scratch}.length > 0) {{"));
        self.line(&format!(
            "{iss}.push(issue({child_path}, \"property name does not satisfy propertyNames schema\"));"
        ));
        self.close("}");
        self.close("}");
        self.close("}");
    }

    fn gen_pattern_properties(
        &mut self,
        pattern_properties: &[PatternProperty],
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let total = pattern_properties.iter().fold(0usize, |cost, pattern| {
            let child = validation_flow_cost(&pattern.schema, self.position);
            let entry = 7 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child;
            cost.saturating_add(entry).min(VALIDATOR_CFA_BUDGET + 1)
        });
        if total > VALIDATOR_CFA_BUDGET {
            self.gen_pattern_properties_bounded(pattern_properties, val, path, iss);
            self.gen_pattern_property_annotations(pattern_properties, val, evaluation);
            return;
        }

        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_record = true;
        self.scope.runtime_values.insert("appendKey");
        self.open(&format!("if (isRecord({val})) {{"));
        self.open(&format!("for (const key of Object.keys({val})) {{"));
        for pattern_property in pattern_properties {
            let pattern = &pattern_property.pattern;
            let schema = &pattern_property.schema;
            let slot = self.scope.pattern_slot(pattern, true);
            self.open(&format!("if (pattern{slot}Regex().test(key)) {{"));
            let index = self.fresh();
            let child = format!("value{index}");
            let child_path = format!("path{index}");
            self.line(&format!("const {child}: unknown = {val}[key];"));
            self.line(&format!("const {child_path} = appendKey({path}, key);"));
            let complete = self.gen_child_schema(
                format!("patternProperties/{pattern}"),
                schema,
                &child,
                &child_path,
                iss,
                &EvaluationCallbacks::default(),
            );
            if !complete {
                self.out.truncate(out_len);
                self.helpers.truncate(helpers_len);
                self.indent = parent_indent;
                self.counter = parent_counter;
                *self.scope = parent_scope;
                *self.imports = parent_imports;
                self.scope
                    .record_incomplete_applicator("patternProperties", &schema.meta().source);
                return;
            }
            self.close("}");
        }
        self.close("}");
        self.close("}");
        self.gen_pattern_property_annotations(pattern_properties, val, evaluation);
    }

    fn gen_pattern_properties_bounded(
        &mut self,
        pattern_properties: &[PatternProperty],
        val: &str,
        path: &str,
        iss: &str,
    ) {
        for pattern_property in pattern_properties {
            if !self.probe_schema(&pattern_property.schema) {
                self.scope.record_incomplete_applicator(
                    "patternProperties",
                    &pattern_property.schema.meta().source,
                );
                return;
            }
        }

        let mut chunks = Vec::new();
        let mut start = 0;
        let mut cost = 0usize;
        for (index, pattern_property) in pattern_properties.iter().enumerate() {
            let child = validation_flow_cost(&pattern_property.schema, self.position);
            let next = 7 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child;
            if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                chunks.push((start, index));
                start = index;
                cost = 0;
            }
            cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
        }
        chunks.push((start, pattern_properties.len()));

        self.scope.needs_is_record = true;
        self.scope.runtime_values.insert("appendKey");
        let mut calls = Vec::new();
        for (part, (start, end)) in chunks.into_iter().enumerate() {
            let name = self.helper_name("PatternProperties", Some(part));
            let parent_out = std::mem::take(&mut self.out);
            let parent_indent = self.indent;
            let parent_counter = self.counter;
            self.indent = 1;
            self.counter = 0;
            self.open("for (const key of keys) {");
            for pattern_property in &pattern_properties[start..end] {
                let pattern = &pattern_property.pattern;
                let slot = self.scope.pattern_slot(pattern, true);
                self.open(&format!("if (pattern{slot}Regex().test(key)) {{"));
                let index = self.fresh();
                let child = format!("value{index}");
                let child_path = format!("path{index}");
                self.line(&format!("const {child}: unknown = value[key];"));
                self.line(&format!("const {child_path} = appendKey(path, key);"));
                self.gen_child_schema(
                    format!("patternProperties/{pattern}"),
                    &pattern_property.schema,
                    &child,
                    &child_path,
                    "issues",
                    &EvaluationCallbacks::default(),
                );
                self.close("}");
            }
            self.close("}");
            let helper_body = std::mem::replace(&mut self.out, parent_out);
            let value_parameter = value_parameter(&helper_body, VALUE_RECORD);
            self.indent = parent_indent;
            self.counter = parent_counter;
            self.helpers.push(format!(
                "function {name}({value_parameter}, keys: readonly string[], path: readonly (string | number)[], issues: Issue[]): void {{\n{helper_body}}}\n\n"
            ));
            calls.push(name);
        }

        self.open(&format!("if (isRecord({val})) {{"));
        let keys = format!("keys{}", self.fresh());
        self.line(&format!("const {keys} = Object.keys({val});"));
        for name in calls {
            self.line(&format!("{name}({val}, {keys}, {path}, {iss});"));
        }
        self.close("}");
    }

    fn gen_pattern_property_annotations(
        &mut self,
        pattern_properties: &[PatternProperty],
        val: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let Some(callback) = &evaluation.property else {
            return;
        };
        let condition = pattern_properties
            .iter()
            .map(|pattern_property| {
                let slot = self.scope.pattern_slot(&pattern_property.pattern, true);
                format!("pattern{slot}Regex().test(key)")
            })
            .collect::<Vec<_>>()
            .join(" || ");
        self.scope.needs_is_record = true;
        self.open(&format!("if ({callback} !== undefined) {{"));
        self.open(&format!("if (isRecord({val})) {{"));
        self.open(&format!("for (const key of Object.keys({val})) {{"));
        self.open(&format!("if ({condition}) {{"));
        self.line(&format!("{callback}(key);"));
        self.close("}");
        self.close("}");
        self.close("}");
        self.close("}");
    }

    fn gen_contains(
        &mut self,
        contains: &ContainsApplicator,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_array = true;
        self.scope.runtime_values.insert("issue");
        self.open(&format!("if (isArray({val})) {{"));
        let count = format!("matches{}", self.fresh());
        self.line(&format!("let {count} = 0;"));
        self.open(&format!(
            "for (let index = 0; index < {val}.length; index += 1) {{"
        ));
        let scratch = format!("issues{}", self.fresh());
        let child_path = format!("[...{path}, index]");
        self.line(&format!("const {scratch}: Issue[] = [];"));
        let complete = self.gen_child_schema(
            "contains".to_owned(),
            &contains.schema,
            &format!("{val}[index]"),
            &child_path,
            &scratch,
            &EvaluationCallbacks::default(),
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("contains", &contains.schema.meta().source);
            return;
        }
        self.open(&format!("if ({scratch}.length === 0) {{"));
        self.line(&format!("{count} += 1;"));
        if let Some(callback) = &evaluation.item {
            self.line(&format!("{callback}?.(index);"));
        }
        self.close("}");
        self.close("}");

        let minimum = contains.min_contains.unwrap_or(1);
        if minimum > 0 {
            let message = if contains.min_contains.is_some() {
                format!("fewer matching items than minContains {minimum}")
            } else {
                "no array item matches contains schema".to_owned()
            };
            self.push_issue(&format!("{count} < {minimum}"), path, iss, &message);
        }
        if let Some(maximum) = contains.max_contains {
            self.push_issue(
                &format!("{count} > {maximum}"),
                path,
                iss,
                &format!("more matching items than maxContains {maximum}"),
            );
        }
        self.close("}");
    }

    fn gen_dependent_schemas(
        &mut self,
        dependent_schemas: &[(String, SchemaNode)],
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let total = dependent_schemas.iter().fold(0usize, |cost, (_, schema)| {
            let child = validation_flow_cost(schema, self.position);
            let entry = 4 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child;
            cost.saturating_add(entry).min(VALIDATOR_CFA_BUDGET + 1)
        });
        if total > VALIDATOR_CFA_BUDGET {
            self.gen_dependent_schemas_bounded(dependent_schemas, val, path, iss, evaluation);
            return;
        }

        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_record = true;
        self.open(&format!("if (isRecord({val})) {{"));
        for (trigger, schema) in dependent_schemas {
            self.open(&format!(
                "if (Object.hasOwn({val}, {})) {{",
                render_ts_string(trigger)
            ));
            let complete = self.gen_child_schema(
                format!("dependentSchemas/{trigger}"),
                schema,
                val,
                path,
                iss,
                evaluation,
            );
            if !complete {
                self.out.truncate(out_len);
                self.helpers.truncate(helpers_len);
                self.indent = parent_indent;
                self.counter = parent_counter;
                *self.scope = parent_scope;
                *self.imports = parent_imports;
                self.scope
                    .record_incomplete_applicator("dependentSchemas", &schema.meta().source);
                return;
            }
            self.close("}");
        }
        self.close("}");
    }

    fn gen_dependent_schemas_bounded(
        &mut self,
        dependent_schemas: &[(String, SchemaNode)],
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        for (_, schema) in dependent_schemas {
            if !self.probe_schema(schema) {
                self.scope
                    .record_incomplete_applicator("dependentSchemas", &schema.meta().source);
                return;
            }
        }

        let mut chunks = Vec::new();
        let mut start = 0;
        let mut cost = 0usize;
        for (index, (_, schema)) in dependent_schemas.iter().enumerate() {
            let child = validation_flow_cost(schema, self.position);
            let next = 4 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child;
            if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                chunks.push((start, index));
                start = index;
                cost = 0;
            }
            cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
        }
        chunks.push((start, dependent_schemas.len()));

        self.scope.needs_is_record = true;
        let mut calls = Vec::new();
        for (part, (start, end)) in chunks.into_iter().enumerate() {
            let name = self.helper_name("DependentSchemas", Some(part));
            let parent_out = std::mem::take(&mut self.out);
            let parent_indent = self.indent;
            let parent_counter = self.counter;
            self.indent = 1;
            self.counter = 0;
            for (trigger, schema) in &dependent_schemas[start..end] {
                self.open(&format!(
                    "if (Object.hasOwn(value, {})) {{",
                    render_ts_string(trigger)
                ));
                self.gen_child_schema(
                    format!("dependentSchemas/{trigger}"),
                    schema,
                    "value",
                    "path",
                    "issues",
                    &EvaluationCallbacks::root(),
                );
                self.close("}");
            }
            let helper_body = std::mem::replace(&mut self.out, parent_out);
            let evaluation_parameters = evaluation_parameters(&helper_body);
            let value_parameter = value_parameter(&helper_body, VALUE_RECORD);
            self.indent = parent_indent;
            self.counter = parent_counter;
            self.helpers.push(format!(
                "function {name}({value_parameter}, path: readonly (string | number)[], issues: Issue[], {evaluation_parameters}): void {{\n{helper_body}}}\n\n"
            ));
            calls.push(name);
        }

        self.open(&format!("if (isRecord({val})) {{"));
        for name in calls {
            self.line(&format!(
                "{name}({val}, {path}, {iss}, {}, {});",
                EvaluationCallbacks::argument(&evaluation.property),
                EvaluationCallbacks::argument(&evaluation.item)
            ));
        }
        self.close("}");
    }

    fn gen_conditional(
        &mut self,
        conditional: &ConditionalApplicator,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        let scratch = format!("issues{}", self.fresh());
        self.line(&format!("const {scratch}: Issue[] = [];"));
        let mut condition_evaluation = self.branch_evaluation(evaluation, &scratch);
        let complete = self.gen_child_schema(
            "if".to_owned(),
            &conditional.condition,
            val,
            path,
            &scratch,
            &condition_evaluation.callbacks,
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("if", &conditional.condition.meta().source);
            return;
        }

        self.prune_unused_branch_evaluation(&mut condition_evaluation);
        self.open(&format!("if ({scratch}.length === 0) {{"));
        self.merge_branch_evaluation(&condition_evaluation, evaluation);
        if let Some(schema) = &conditional.then_schema {
            let complete =
                self.gen_child_schema("then".to_owned(), schema, val, path, iss, evaluation);
            if !complete {
                self.out.truncate(out_len);
                self.helpers.truncate(helpers_len);
                self.indent = parent_indent;
                self.counter = parent_counter;
                *self.scope = parent_scope;
                *self.imports = parent_imports;
                self.scope
                    .record_incomplete_applicator("then", &schema.meta().source);
                return;
            }
        }
        if let Some(schema) = &conditional.else_schema {
            self.indent -= 1;
            self.open("} else {");
            let complete =
                self.gen_child_schema("else".to_owned(), schema, val, path, iss, evaluation);
            if !complete {
                self.out.truncate(out_len);
                self.helpers.truncate(helpers_len);
                self.indent = parent_indent;
                self.counter = parent_counter;
                *self.scope = parent_scope;
                *self.imports = parent_imports;
                self.scope
                    .record_incomplete_applicator("else", &schema.meta().source);
                return;
            }
        }
        self.close("}");
    }

    fn gen_unevaluated_properties(
        &mut self,
        schema: &SchemaNode,
        evaluated: &str,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_record = true;
        self.scope.runtime_values.insert("appendKey");
        self.open(&format!("if (isRecord({val})) {{"));
        self.open(&format!("for (const key of Object.keys({val})) {{"));
        self.open(&format!("if (!{evaluated}.includes(key)) {{"));
        let child_path = format!("appendKey({path}, key)");
        let complete = self.gen_child_schema(
            "unevaluatedProperties".to_owned(),
            schema,
            &format!("{val}[key]"),
            &child_path,
            iss,
            &EvaluationCallbacks::default(),
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("unevaluatedProperties", &schema.meta().source);
            return;
        }
        if let Some(callback) = &evaluation.property {
            self.line(&format!("{callback}?.(key);"));
        }
        self.close("}");
        self.close("}");
        self.close("}");
    }

    fn gen_unevaluated_items(
        &mut self,
        schema: &SchemaNode,
        evaluated: &str,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let out_len = self.out.len();
        let helpers_len = self.helpers.len();
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        let parent_scope = self.scope.clone();
        let parent_imports = self.imports.clone();

        self.scope.needs_is_array = true;
        self.open(&format!("if (isArray({val})) {{"));
        self.open(&format!(
            "for (let index = 0; index < {val}.length; index += 1) {{"
        ));
        self.open(&format!("if (!{evaluated}.includes(index)) {{"));
        let complete = self.gen_child_schema(
            "unevaluatedItems".to_owned(),
            schema,
            &format!("{val}[index]"),
            &format!("[...{path}, index]"),
            iss,
            &EvaluationCallbacks::default(),
        );
        if !complete {
            self.out.truncate(out_len);
            self.helpers.truncate(helpers_len);
            self.indent = parent_indent;
            self.counter = parent_counter;
            *self.scope = parent_scope;
            *self.imports = parent_imports;
            self.scope
                .record_incomplete_applicator("unevaluatedItems", &schema.meta().source);
            return;
        }
        if let Some(callback) = &evaluation.item {
            self.line(&format!("{callback}?.(index);"));
        }
        self.close("}");
        self.close("}");
        self.close("}");
    }

    fn gen_response_headers(&mut self, response: &ResponseEntry) {
        self.scope.runtime_values.insert("hasGet");
        self.open("if (hasGet(value)) {");
        for (name, header) in &response.headers {
            // An opaque content header is typed `string`; its wire value is always a string when
            // present, so an optional one needs no check at all and a required one needs only the
            // presence check below — never a schema check that would reject the raw string.
            let opaque = crate::client_model::response_header_is_opaque_string(header);
            if opaque && !header.required {
                continue;
            }
            let index = self.fresh();
            let val = format!("v{index}");
            let key = render_ts_string(name);
            self.line(&format!("const {val} = value.get({key});"));
            if header.required {
                self.push_issue(
                    &format!("{val} === null"),
                    "path",
                    "issues",
                    &format!("missing required header {name}"),
                );
            }
            if !opaque {
                let child_path = format!("path{index}");
                self.scope.runtime_values.insert("appendKey");
                self.line(&format!("const {child_path} = appendKey(path, {key});"));
                self.open(&format!("if ({val} !== null) {{"));
                if header.content_media_type.is_some() {
                    // A JSON-family content header (non-opaque with a media type) carries JSON text on
                    // the wire, so parse it before schema validation — an object/number/array schema
                    // can never match the raw string. A parse failure is a decode issue; the schema
                    // check stays inside the try because the generated validators never throw.
                    self.scope.runtime_values.insert("issue");
                    let decoded = format!("d{index}");
                    self.open("try {");
                    self.line(&format!("const {decoded}: unknown = JSON.parse({val});"));
                    self.gen_child_schema(
                        format!("headers/{name}"),
                        &header.schema,
                        &decoded,
                        &child_path,
                        "issues",
                        &EvaluationCallbacks::default(),
                    );
                    self.indent -= 1;
                    self.open("} catch {");
                    self.line(&format!(
                        "issues.push(issue({child_path}, {}));",
                        render_ts_string("value is not valid JSON")
                    ));
                    self.close("}");
                } else {
                    // Schema-style header values arrive as wire strings, so non-string schema domains
                    // over-report by design.
                    self.gen_child_schema(
                        format!("headers/{name}"),
                        &header.schema,
                        &val,
                        &child_path,
                        "issues",
                        &EvaluationCallbacks::default(),
                    );
                }
                self.close("}");
            }
        }
        self.indent -= 1;
        self.open("} else {");
        self.scope.runtime_values.insert("issue");
        self.line("issues.push(issue(path, \"value is not a Headers object\"));");
        self.close("}");
    }

    /// Emits the type-conditional checks for a typeless constrained schema (`Any` carrying constraint
    /// groups, e.g. `{minLength: 3}` or the constraint-only typed branch of a lowered conjunction).
    /// Per JSON Schema, a typeless assertion constrains values OF ITS MATCHING TYPE and vacuously
    /// accepts every other type — so each present group emits a standalone type-guard block with NO
    /// else arm (a non-matching type must push no issue). Fixed emission order — number, string,
    /// array, object — keeps output deterministic. `contentEncoding` is a serialization concern, not
    /// a JSON-validity assertion, so it is deliberately not checked here.
    fn gen_typeless_constraints(&mut self, meta: &SchemaMeta, val: &str, path: &str, iss: &str) {
        if meta.numeric_constraints.is_some() {
            self.open(&format!(
                "if (typeof {val} === \"number\" && Number.isFinite({val})) {{"
            ));
            self.gen_number_constraints_inner(meta, val, path, iss);
            self.close("}");
        }
        if meta.string_constraints.is_some() {
            self.open(&format!("if (typeof {val} === \"string\") {{"));
            self.gen_string_constraints(None, meta, val, path, iss);
            self.close("}");
        }
        if meta.array_constraints.is_some() {
            self.scope.needs_is_array = true;
            self.open(&format!("if (isArray({val})) {{"));
            self.gen_array_constraints(meta, val, path, iss);
            self.close("}");
        }
        if meta.object_constraints.is_some() {
            self.scope.needs_is_record = true;
            self.open(&format!("if (isRecord({val})) {{"));
            let constraints = meta.object_constraints();
            self.gen_extra_required(&constraints.required, val, path, iss);
            self.gen_property_count_bounds(
                constraints.min_properties,
                constraints.max_properties,
                &format!("Object.keys({val})"),
                path,
                iss,
            );
            self.close("}");
        }
    }

    fn gen_primitive(
        &mut self,
        ty: PrimitiveType,
        format: Option<&str>,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let (type_condition, type_name) = match ty {
            PrimitiveType::String => (format!("typeof {val} === \"string\""), "string"),
            PrimitiveType::Number => (
                format!("typeof {val} === \"number\" && Number.isFinite({val})"),
                "number",
            ),
            PrimitiveType::Integer => (
                format!("typeof {val} === \"number\" && Number.isInteger({val})"),
                "integer",
            ),
            PrimitiveType::Boolean => (format!("typeof {val} === \"boolean\""), "boolean"),
            PrimitiveType::Null => (format!("{val} === null"), "null"),
        };
        let widen_null = meta.nullable && !matches!(ty, PrimitiveType::Null);

        self.open(&format!("if ({type_condition}) {{"));
        match ty {
            PrimitiveType::String => self.gen_string_constraints(format, meta, val, path, iss),
            PrimitiveType::Number | PrimitiveType::Integer => {
                self.gen_number_constraints(ty, format, meta, val, path, iss);
            }
            PrimitiveType::Boolean | PrimitiveType::Null => {
                if format.is_some() {
                    self.mark_incomplete();
                }
            }
        }
        self.close_type_gate(widen_null, val, path, iss, type_name);
    }

    fn gen_bigint_int64(&mut self, meta: &SchemaMeta, val: &str, path: &str, iss: &str) {
        self.scope.runtime_values.insert("int64WireValue");
        let index = self.fresh();
        let integer = format!("integer{index}");
        self.line(&format!("const {integer} = int64WireValue({val});"));
        self.open(&format!("if ({integer} !== null) {{"));
        self.push_issue(
            &format!("{integer} < -9223372036854775808n || {integer} >= 9223372036854775808n"),
            path,
            iss,
            "out of int64 range",
        );
        let constraints = meta.numeric_constraints();
        if constraints.minimum.is_some()
            || constraints.maximum.is_some()
            || constraints.exclusive_minimum.is_some()
            || constraints.exclusive_maximum.is_some()
            || constraints.multiple_of.is_some()
        {
            self.gen_bound(
                constraints,
                BoundDirection::Lower,
                &integer,
                path,
                iss,
                true,
            );
            self.gen_bound(
                constraints,
                BoundDirection::Upper,
                &integer,
                path,
                iss,
                true,
            );
            if let Some(multiple) = &constraints.multiple_of {
                let literal = render_number_value(multiple);
                self.scope.runtime_values.insert("isBigIntMultipleOf");
                self.push_issue(
                    &format!("!isBigIntMultipleOf({integer}, {literal})"),
                    path,
                    iss,
                    &format!("not a multiple of {literal}"),
                );
            }
        }
        self.close_type_gate(meta.nullable, val, path, iss, "integer");
    }

    fn gen_string_constraints(
        &mut self,
        format: Option<&str>,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let constraints = meta.string_constraints();
        if constraints.min_length.is_some() || constraints.max_length.is_some() {
            self.scope.runtime_values.insert("codePointLength");
        }
        // When both bounds are present the code-point length is compared twice; compute it once
        // into a local so the O(n) scan runs a single time. A single bound stays inline.
        let length_expr = if constraints.min_length.is_some() && constraints.max_length.is_some() {
            let index = self.fresh();
            let name = format!("length{index}");
            self.line(&format!("const {name} = codePointLength({val});"));
            name
        } else {
            format!("codePointLength({val})")
        };
        if let Some(min) = constraints.min_length {
            self.push_issue(
                &format!("{length_expr} < {min}"),
                path,
                iss,
                &format!("shorter than minLength {min}"),
            );
        }
        if let Some(max) = constraints.max_length {
            self.push_issue(
                &format!("{length_expr} > {max}"),
                path,
                iss,
                &format!("longer than maxLength {max}"),
            );
        }
        if let Some(pattern) = &constraints.pattern {
            let slot = self.scope.pattern_slot(pattern, false);
            self.push_issue(
                &format!("!pattern{slot}Regex().test({val})"),
                path,
                iss,
                "does not match pattern",
            );
        }
        if let Some(format) = format {
            if let Some((predicate, message)) = string_format_predicate(format) {
                self.scope.runtime_values.insert(predicate);
                self.push_issue(&format!("!{predicate}({val})"), path, iss, message);
            } else {
                self.mark_incomplete();
            }
        }
    }

    fn gen_number_constraints(
        &mut self,
        ty: PrimitiveType,
        format: Option<&str>,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        self.gen_number_constraints_inner(meta, val, path, iss);
        // The int32 clause is type-specific (it needs a declared integer/int32), so it lives here
        // rather than in the shared inner body the typeless path reuses.
        if matches!(ty, PrimitiveType::Integer) && format == Some("int32") {
            self.scope.runtime_values.insert("isInt32");
            self.push_issue(&format!("!isInt32({val})"), path, iss, "out of int32 range");
        } else if format.is_some() {
            self.mark_incomplete();
        }
    }

    /// The type-agnostic numeric checks — bounds (min/max/exclusive) then multipleOf — shared by the
    /// declared-number primitive path and the typeless numeric guard. The caller supplies the number
    /// type gate; this body assumes `val` is already narrowed to a finite number.
    fn gen_number_constraints_inner(
        &mut self,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let constraints = meta.numeric_constraints();
        self.gen_bound(constraints, BoundDirection::Lower, val, path, iss, false);
        self.gen_bound(constraints, BoundDirection::Upper, val, path, iss, false);
        if let Some(multiple) = &constraints.multiple_of {
            let literal = render_number_value(multiple);
            self.scope.runtime_values.insert("isMultipleOf");
            self.push_issue(
                &format!("!isMultipleOf({val}, {literal})"),
                path,
                iss,
                &format!("not a multiple of {literal}"),
            );
        }
    }

    /// Emits the inclusive/exclusive comparison checks for one direction of a numeric range.
    /// Direction supplies the comparators and message vocabulary; the OpenAPI dialect split lives in
    /// `exclusive`: 3.1 carries the threshold as a `Number` (its own check plus any inclusive bound),
    /// while 3.0 carries a `Boolean` toggle that only strengthens the inclusive bound's comparator.
    fn gen_bound(
        &mut self,
        constraints: &crate::ir::NumericConstraints,
        direction: BoundDirection,
        val: &str,
        path: &str,
        iss: &str,
        exact_bigint: bool,
    ) {
        let bound = direction.resolve(constraints);
        match bound.exclusive {
            Some(ExclusiveBound::Number(value)) => {
                self.emit_threshold(
                    val,
                    bound.exclusive_comparator,
                    bound.exclusive_message,
                    value,
                    (path, iss),
                    exact_bigint,
                );
                if let Some(value) = bound.inclusive {
                    self.emit_threshold(
                        val,
                        bound.inclusive_comparator,
                        bound.inclusive_message,
                        value,
                        (path, iss),
                        exact_bigint,
                    );
                }
            }
            // A 3.0 `exclusiveMinimum/Maximum: true` only strengthens the inclusive bound's
            // comparator, so it reuses the inclusive threshold value with the exclusive vocabulary.
            Some(ExclusiveBound::Boolean(true)) => {
                if let Some(value) = bound.inclusive {
                    self.emit_threshold(
                        val,
                        bound.exclusive_comparator,
                        bound.exclusive_message,
                        value,
                        (path, iss),
                        exact_bigint,
                    );
                }
            }
            Some(ExclusiveBound::Boolean(false)) | None => {
                if let Some(value) = bound.inclusive {
                    self.emit_threshold(
                        val,
                        bound.inclusive_comparator,
                        bound.inclusive_message,
                        value,
                        (path, iss),
                        exact_bigint,
                    );
                }
            }
        }
    }

    /// Emits one `{val} {comparator} {literal}` range check whose message ends with the rendered
    /// threshold literal. The comparator/message vocabulary and the threshold vary per call; this is
    /// the single construction shared by both inclusive and exclusive bounds in either direction.
    fn emit_threshold(
        &mut self,
        val: &str,
        comparator: &str,
        message: &str,
        value: &Number,
        location: (&str, &str),
        exact_bigint: bool,
    ) {
        let (path, iss) = location;
        let literal = render_number_value(value);
        let condition = if exact_bigint {
            self.scope.runtime_values.insert("compareBigIntToNumber");
            format!("compareBigIntToNumber({val}, {literal}) {comparator} 0")
        } else {
            format!("{val} {comparator} {literal}")
        };
        self.push_issue(&condition, path, iss, &format!("{message} {literal}"));
    }

    /// Splits an object/array/tuple's `enum`/`const` box and generates its finite-value guard —
    /// the shared tail of those three schema arms.
    fn gen_finite_constraint(
        &mut self,
        finite: &Option<Box<FiniteConstraint>>,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let (enum_values, const_value) = finite_parts(finite);
        self.gen_finite(enum_values, const_value, val, path, iss);
    }

    fn gen_finite(
        &mut self,
        enum_values: Option<&[Value]>,
        const_value: Option<&Value>,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        if let Some(values) = enum_values {
            self.scope.runtime_values.insert("deepEqual");
            let condition = if values.is_empty() {
                "true".to_owned()
            } else if values.len() > VALIDATOR_CFA_BUDGET {
                let mut calls = Vec::new();
                for (part, chunk) in values.chunks(VALIDATOR_CFA_BUDGET).enumerate() {
                    let name = self.helper_name("Enum", Some(part));
                    let members = chunk
                        .iter()
                        .map(|value| {
                            format!(
                                "deepEqual(value, {})",
                                render_json_compact(value, ObjectKeyMode::ProtoSafe)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" || ");
                    self.helpers.push(format!(
                        "function {name}(value: unknown): boolean {{\n  return {members};\n}}\n\n"
                    ));
                    calls.push(format!("{name}({val})"));
                }
                format!("!({})", calls.join(" || "))
            } else {
                let members = values
                    .iter()
                    .map(|value| {
                        format!(
                            "deepEqual({val}, {})",
                            render_json_compact(value, ObjectKeyMode::ProtoSafe)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" || ");
                format!("!({members})")
            };
            self.push_issue(&condition, path, iss, "value not in enum");
        }
        if let Some(value) = const_value {
            self.scope.runtime_values.insert("deepEqual");
            self.push_issue(
                &format!(
                    "!deepEqual({val}, {})",
                    render_json_compact(value, ObjectKeyMode::ProtoSafe)
                ),
                path,
                iss,
                "value not equal to const",
            );
        }
    }

    fn gen_object(
        &mut self,
        parts: ObjectParts<'_>,
        force_split: bool,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let ObjectParts {
            properties,
            additional_properties,
            additional_properties_present,
            dependent_required,
            extra_required,
            meta,
        } = parts;
        self.scope.needs_is_record = true;
        self.open(&format!("if (isRecord({val})) {{"));

        self.gen_object_properties_bounded(properties, force_split, val, path, iss);
        self.gen_extra_required_bounded(extra_required, force_split, val, path, iss);
        self.gen_dependent_required_bounded(dependent_required, force_split, val, path, iss);

        // `Object.keys(value)` backs the additional-properties iteration and each of
        // minProperties/maxProperties. When at least two of those consume it, evaluate it once into
        // a local and reuse; a lone consumer keeps the inline call to avoid a needless binding.
        let keys_iteration = match additional_properties {
            AdditionalProperties::Forbidden => true,
            AdditionalProperties::Schema(sub) => !is_noop_schema(sub),
            AdditionalProperties::Allowed(_) => false,
        };
        let min = meta.object_constraints().min_properties;
        let max = meta.object_constraints().max_properties;
        let keys_uses = keys_iteration as usize + min.is_some() as usize + max.is_some() as usize;
        let keys_expr = if keys_uses >= 2 {
            let index = self.fresh();
            let name = format!("keys{index}");
            self.line(&format!("const {name} = Object.keys({val});"));
            name
        } else {
            format!("Object.keys({val})")
        };

        self.gen_additional_properties_bounded(
            AdditionalPropertiesParts {
                additional: additional_properties,
                properties,
                pattern_properties: &meta.validation_applicators().pattern_properties,
                force_split,
                keys_expr: &keys_expr,
            },
            val,
            path,
            iss,
        );
        if additional_properties_present && let Some(callback) = &evaluation.property {
            let condition = self.unknown_key_condition_inline(
                properties,
                &meta.validation_applicators().pattern_properties,
            );
            self.open(&format!("if ({callback} !== undefined) {{"));
            self.open(&format!("for (const key of Object.keys({val})) {{"));
            self.open(&format!("if ({condition}) {{"));
            self.line(&format!("{callback}(key);"));
            self.close("}");
            self.close("}");
            self.close("}");
        }

        self.gen_property_count_bounds(min, max, &keys_expr, path, iss);
        if let Some(callback) = &evaluation.property
            && !properties.is_empty()
        {
            let declared = properties
                .iter()
                .filter(|(_, _, meta)| property_in_position(meta, self.position))
                .map(|(name, _, _)| render_ts_string(name))
                .collect::<Vec<_>>()
                .join(", ");
            self.open(&format!("if ({callback} !== undefined) {{"));
            self.line(&format!(
                "const declaredProperties: readonly string[] = [{declared}];"
            ));
            self.open("for (const key of declaredProperties) {");
            self.open(&format!("if (Object.hasOwn({val}, key)) {{"));
            self.line(&format!("{callback}(key);"));
            self.close("}");
            self.close("}");
            self.close("}");
        }

        self.close_type_gate(meta.nullable, val, path, iss, "object");
    }

    fn gen_object_properties_bounded(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        force_split: bool,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let property_cost = |property: &SchemaNode, meta: &PropMeta| {
            if is_noop_schema(property) {
                usize::from(meta.required) * 3
            } else {
                let child = validation_flow_cost(property, self.position);
                // An oversized child is replaced by one plain helper call before this object body
                // reaches TypeScript, so only its property-presence scaffold contributes here.
                4 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child
            }
        };
        let total = properties
            .iter()
            .filter(|(_, _, meta)| property_in_position(meta, self.position))
            .fold(0usize, |cost, (_, property, meta)| {
                cost.saturating_add(property_cost(property, meta))
                    .min(VALIDATOR_CFA_BUDGET + 1)
            });
        if total == 0 {
            return;
        }
        if total <= VALIDATOR_CFA_BUDGET && !force_split {
            self.gen_object_properties(properties, val, path, iss);
            return;
        }

        let mut chunks = Vec::new();
        let mut start = 0;
        let mut cost = 0usize;
        for (index, (_, property, meta)) in properties.iter().enumerate() {
            if !property_in_position(meta, self.position) {
                continue;
            }
            let next = property_cost(property, meta);
            if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                chunks.push((start, index));
                start = index;
                cost = 0;
            }
            cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
        }
        chunks.push((start, properties.len()));

        for (part, (start, end)) in chunks.into_iter().enumerate() {
            let name = self.helper_name("Object", Some(part));
            let parent_out = std::mem::take(&mut self.out);
            let parent_indent = self.indent;
            let parent_counter = self.counter;
            self.indent = 1;
            self.counter = 0;
            self.gen_object_properties(&properties[start..end], "value", "path", "issues");
            let helper_body = std::mem::replace(&mut self.out, parent_out);
            self.indent = parent_indent;
            self.counter = parent_counter;
            self.helpers.push(format!(
                "function {name}(value: {{ [key: string]: unknown }}, path: readonly (string | number)[], issues: Issue[]): void {{\n{helper_body}}}\n\n"
            ));
            self.line(&format!("{name}({val}, {path}, {iss});"));
        }
    }

    fn gen_extra_required_bounded(
        &mut self,
        extra_required: &[String],
        force_split: bool,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        if extra_required.is_empty() {
            return;
        }
        if !force_split {
            self.gen_extra_required(extra_required, val, path, iss);
            return;
        }

        let name = self.helper_name("Required", None);
        let required = extra_required
            .iter()
            .map(|property| render_ts_string(property))
            .collect::<Vec<_>>()
            .join(", ");
        self.scope.runtime_values.insert("issue");
        self.helpers.push(format!(
            "function {name}(value: {{ [key: string]: unknown }}, path: readonly (string | number)[], issues: Issue[]): void {{\n  const required: readonly string[] = [{required}];\n  for (const key of required) {{\n    if (!Object.hasOwn(value, key)) {{\n      issues.push(issue(path, `missing required property ${{key}}`));\n    }}\n  }}\n}}\n\n"
        ));
        self.line(&format!("{name}({val}, {path}, {iss});"));
    }

    fn gen_extra_required(&mut self, extra_required: &[String], val: &str, path: &str, iss: &str) {
        for name in extra_required {
            let key = render_ts_string(name);
            self.scope.runtime_values.insert("issue");
            self.open(&format!("if (!Object.hasOwn({val}, {key})) {{"));
            self.line(&format!(
                "{iss}.push(issue({path}, {}));",
                render_ts_string(&format!("missing required property {name}"))
            ));
            self.close("}");
        }
    }

    fn gen_dependent_required_bounded(
        &mut self,
        dependent_required: &[(String, Vec<String>)],
        force_split: bool,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        if dependent_required.is_empty() {
            return;
        }
        if !force_split {
            self.gen_dependent_required(dependent_required, val, path, iss);
            return;
        }

        let name = self.helper_name("Dependent", None);
        let requirements = dependent_required
            .iter()
            .map(|(trigger, dependents)| {
                let dependents = dependents
                    .iter()
                    .map(|dependent| render_ts_string(dependent))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{}, [{dependents}]]", render_ts_string(trigger))
            })
            .collect::<Vec<_>>()
            .join(", ");
        self.scope.runtime_values.insert("issue");
        self.helpers.push(format!(
            "function {name}(value: {{ [key: string]: unknown }}, path: readonly (string | number)[], issues: Issue[]): void {{\n  const requirements: readonly (readonly [string, readonly string[]])[] = [{requirements}];\n  for (const [trigger, dependents] of requirements) {{\n    if (Object.hasOwn(value, trigger)) {{\n      for (const dependent of dependents) {{\n        if (!Object.hasOwn(value, dependent)) {{\n          issues.push(issue(path, `missing required property ${{dependent}}`));\n        }}\n      }}\n    }}\n  }}\n}}\n\n"
        ));
        self.line(&format!("{name}({val}, {path}, {iss});"));
    }

    fn gen_dependent_required(
        &mut self,
        dependent_required: &[(String, Vec<String>)],
        val: &str,
        path: &str,
        iss: &str,
    ) {
        for (trigger, dependents) in dependent_required {
            // Own-property presence (see the property-presence site): `in` would let an inherited
            // trigger/dependent name forge or defeat a dependentRequired constraint.
            self.open(&format!(
                "if (Object.hasOwn({val}, {})) {{",
                render_ts_string(trigger)
            ));
            for dependent in dependents {
                self.scope.runtime_values.insert("issue");
                self.open(&format!(
                    "if (!Object.hasOwn({val}, {})) {{",
                    render_ts_string(dependent)
                ));
                self.line(&format!(
                    "{iss}.push(issue({path}, {}));",
                    render_ts_string(&format!("missing required property {dependent}"))
                ));
                self.close("}");
            }
            self.close("}");
        }
    }

    fn gen_object_properties(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        val: &str,
        path: &str,
        iss: &str,
    ) {
        for (name, property, property_meta) in properties {
            if !property_in_position(property_meta, self.position) {
                continue;
            }
            let key = render_ts_string(name);
            // A no-op child (a free-form `{}`/`true` schema) validates nothing, so the whole
            // value-descent scaffold — the own-key read, the path append, the empty body — is dead.
            // A required such property still needs its presence enforced, which reduces to the bare
            // own-key test; a non-required one contributes no check at all.
            if is_noop_schema(property) {
                if property_meta.required {
                    self.scope.runtime_values.insert("issue");
                    self.open(&format!("if (!Object.hasOwn({val}, {key})) {{"));
                    self.line(&format!(
                        "{iss}.push(issue({path}, {}));",
                        render_ts_string(&format!("missing required property {name}"))
                    ));
                    self.close("}");
                }
                continue;
            }
            // Own-property presence, never `in`: `in` walks the prototype chain, so inherited names
            // like `toString`/`constructor` would spuriously appear present. JSON wire objects only
            // carry own keys, so this matches the frozen conformance behavior exactly.
            self.open(&format!("if (Object.hasOwn({val}, {key})) {{"));
            let index = self.fresh();
            let child = format!("value{index}");
            let child_path = format!("path{index}");
            self.line(&format!("const {child}: unknown = {val}[{key}];"));
            self.scope.runtime_values.insert("appendKey");
            self.line(&format!("const {child_path} = appendKey({path}, {key});"));
            self.gen_child_schema(
                format!("properties/{name}"),
                property,
                &child,
                &child_path,
                iss,
                &EvaluationCallbacks::default(),
            );
            if property_meta.required {
                self.indent -= 1;
                self.open("} else {");
                self.scope.runtime_values.insert("issue");
                self.line(&format!(
                    "{iss}.push(issue({path}, {}));",
                    render_ts_string(&format!("missing required property {name}"))
                ));
                self.close("}");
            } else {
                self.close("}");
            }
        }
    }

    /// Emits the minProperties/maxProperties count checks against a prepared `Object.keys(...)`
    /// expression (a hoisted local when the typed object gate also iterates keys, an inline call in
    /// the typeless guard). Shared so the message vocabulary stays in one place across both paths.
    fn gen_property_count_bounds(
        &mut self,
        min: Option<u64>,
        max: Option<u64>,
        keys_expr: &str,
        path: &str,
        iss: &str,
    ) {
        if let Some(min) = min {
            self.push_issue(
                &format!("{keys_expr}.length < {min}"),
                path,
                iss,
                &format!("fewer properties than minProperties {min}"),
            );
        }
        if let Some(max) = max {
            self.push_issue(
                &format!("{keys_expr}.length > {max}"),
                path,
                iss,
                &format!("more properties than maxProperties {max}"),
            );
        }
    }

    fn gen_additional_properties_bounded(
        &mut self,
        parts: AdditionalPropertiesParts<'_>,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let AdditionalPropertiesParts {
            additional,
            properties,
            pattern_properties,
            force_split,
            keys_expr,
        } = parts;
        let validates_keys = match additional {
            AdditionalProperties::Forbidden => true,
            AdditionalProperties::Schema(sub) => !is_noop_schema(sub),
            AdditionalProperties::Allowed(_) => false,
        };
        if !force_split || !validates_keys {
            self.gen_additional_properties(
                AdditionalPropertiesParts {
                    additional,
                    properties,
                    pattern_properties,
                    force_split,
                    keys_expr,
                },
                val,
                path,
                iss,
            );
            return;
        }

        let name = self.helper_name("Additional", None);
        // Position-filtered for the same reason the inline guard is: a property absent from the
        // shape being validated is not a known key there. Left unfiltered, an object over the
        // control-flow budget took this split path and kept exempting `readOnly`/`writeOnly` keys
        // that the inline form rejects — and where `unevaluatedProperties` also applied, its
        // now-filtered record condition and this list disagreed, so neither gate rejected the key.
        let known = properties
            .iter()
            .filter(|(_, _, meta)| property_in_position(meta, self.position))
            .map(|(property, _, _)| render_ts_string(property))
            .collect::<Vec<_>>()
            .join(", ");
        let pattern_condition = self.pattern_key_condition(pattern_properties, "key");
        let parent_out = std::mem::take(&mut self.out);
        let parent_indent = self.indent;
        let parent_counter = self.counter;
        self.indent = 1;
        self.counter = 0;
        self.line(&format!("const known: readonly string[] = [{known}];"));
        self.open("for (const key of keys) {");
        self.open(&format!("if (!known.includes(key){pattern_condition}) {{"));
        if let AdditionalProperties::Schema(sub) = additional {
            let index = self.fresh();
            let child = format!("value{index}");
            let child_path = format!("path{index}");
            self.line(&format!("const {child}: unknown = value[key];"));
            self.scope.runtime_values.insert("appendKey");
            self.line(&format!("const {child_path} = appendKey(path, key);"));
            self.gen_child_schema(
                "additionalProperties".to_owned(),
                sub,
                &child,
                &child_path,
                "issues",
                &EvaluationCallbacks::default(),
            );
        } else {
            self.scope.runtime_values.insert("issue");
            self.scope.runtime_values.insert("appendKey");
            self.line("issues.push(issue(appendKey(path, key), \"unexpected property\"));");
        }
        self.close("}");
        self.close("}");
        let helper_body = std::mem::replace(&mut self.out, parent_out);
        let value_parameter = value_parameter(&helper_body, VALUE_RECORD);
        self.indent = parent_indent;
        self.counter = parent_counter;
        self.helpers.push(format!(
            "function {name}({value_parameter}, keys: readonly string[], path: readonly (string | number)[], issues: Issue[]): void {{\n{helper_body}}}\n\n"
        ));
        self.line(&format!("{name}({val}, {keys_expr}, {path}, {iss});"));
    }

    fn gen_additional_properties(
        &mut self,
        parts: AdditionalPropertiesParts<'_>,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let AdditionalPropertiesParts {
            additional,
            properties,
            pattern_properties,
            force_split: _,
            keys_expr,
        } = parts;
        match additional {
            AdditionalProperties::Forbidden => {
                let condition = self.unknown_key_condition(properties, pattern_properties);
                self.open(&format!("for (const key of {keys_expr}) {{"));
                self.scope.runtime_values.insert("issue");
                self.scope.runtime_values.insert("appendKey");
                self.open(&format!("if ({condition}) {{"));
                self.line(&format!(
                    "{iss}.push(issue(appendKey({path}, key), \"unexpected property\"));"
                ));
                self.close("}");
                self.close("}");
            }
            // A no-op additional schema (`additionalProperties: {}`) validates every extra key
            // against nothing, so the whole iteration is dead — treat it like the permissive default.
            AdditionalProperties::Schema(sub) if !is_noop_schema(sub) => {
                let condition = self.unknown_key_condition(properties, pattern_properties);
                self.open(&format!("for (const key of {keys_expr}) {{"));
                self.open(&format!("if ({condition}) {{"));
                let index = self.fresh();
                let child = format!("value{index}");
                let child_path = format!("path{index}");
                self.line(&format!("const {child}: unknown = {val}[key];"));
                self.scope.runtime_values.insert("appendKey");
                self.line(&format!("const {child_path} = appendKey({path}, key);"));
                self.gen_child_schema(
                    "additionalProperties".to_owned(),
                    sub,
                    &child,
                    &child_path,
                    iss,
                    &EvaluationCallbacks::default(),
                );
                self.close("}");
                self.close("}");
            }
            AdditionalProperties::Schema(_) | AdditionalProperties::Allowed(_) => {}
        }
    }

    fn unknown_key_condition(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        pattern_properties: &[PatternProperty],
    ) -> String {
        let declared = unknown_key_condition(properties, self.position);
        let patterns = self.pattern_key_condition(pattern_properties, "key");
        format!("{declared}{patterns}")
    }

    fn unknown_key_condition_inline(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        pattern_properties: &[PatternProperty],
    ) -> String {
        let mut conditions = vec![unknown_key_condition(properties, self.position)];
        conditions.extend(pattern_properties.iter().map(|pattern_property| {
            let slot = self.scope.pattern_slot(&pattern_property.pattern, true);
            format!("!pattern{slot}Regex().test(key)")
        }));
        conditions.join(" && ")
    }

    fn pattern_key_condition(
        &mut self,
        pattern_properties: &[PatternProperty],
        key: &str,
    ) -> String {
        if pattern_properties.is_empty() {
            return String::new();
        }
        let matchers = pattern_properties
            .iter()
            .map(|pattern_property| {
                let slot = self.scope.pattern_slot(&pattern_property.pattern, true);
                format!("pattern{slot}Regex")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let name = self.helper_name("PatternKey", None);
        self.helpers.push(format!(
            "const {name}Matchers: readonly (() => RegExp)[] = [{matchers}];\n\nfunction {name}(key: string): boolean {{\n  return {name}Matchers.some((matcher) => matcher().test(key));\n}}\n\n"
        ));
        format!(" && !{name}({key})")
    }

    fn gen_array(
        &mut self,
        items: &SchemaNode,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        self.scope.needs_is_array = true;
        self.open(&format!("if (isArray({val})) {{"));
        // A no-op element schema (`items: {}`/`true`) validates every element against nothing, so
        // the per-element loop and its path scaffold are dead; the length/uniqueness constraints
        // and the array type gate still apply.
        if !is_noop_schema(items) {
            let index = self.fresh();
            let element = format!("value{index}");
            let element_path = format!("path{index}");
            self.open(&format!(
                "for (let index{index} = 0; index{index} < {val}.length; index{index} += 1) {{"
            ));
            self.line(&format!("const {element}: unknown = {val}[index{index}];"));
            self.scope.runtime_values.insert("appendKey");
            self.line(&format!(
                "const {element_path} = appendKey({path}, index{index});"
            ));
            self.gen_child_schema(
                "items".to_owned(),
                items,
                &element,
                &element_path,
                iss,
                &EvaluationCallbacks::default(),
            );
            self.close("}");
        }
        self.gen_array_constraints(meta, val, path, iss);
        if meta.items_present
            && let Some(callback) = &evaluation.item
        {
            self.open(&format!("if ({callback} !== undefined) {{"));
            self.open(&format!(
                "for (let index = 0; index < {val}.length; index += 1) {{"
            ));
            self.line(&format!("{callback}(index);"));
            self.close("}");
            self.close("}");
        }
        self.close_type_gate(meta.nullable, val, path, iss, "array");
    }

    fn gen_tuple(
        &mut self,
        parts: TupleParts<'_>,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let TupleParts { prefix_items, rest } = parts;
        self.scope.needs_is_array = true;
        self.open(&format!("if (isArray({val})) {{"));
        self.gen_tuple_prefixes_bounded(prefix_items, val, path, iss);
        let prefix_len = prefix_items.len();
        match rest {
            // A no-op rest schema validates trailing elements against nothing, so the rest loop is
            // dead; the length/uniqueness constraints below still apply.
            TupleRest::Schema(sub) if !is_noop_schema(sub) => {
                let index = self.fresh();
                let element = format!("value{index}");
                let element_path = format!("path{index}");
                self.open(&format!(
                    "for (let index{index} = {prefix_len}; index{index} < {val}.length; index{index} += 1) {{"
                ));
                self.line(&format!("const {element}: unknown = {val}[index{index}];"));
                self.scope.runtime_values.insert("appendKey");
                self.line(&format!(
                    "const {element_path} = appendKey({path}, index{index});"
                ));
                self.gen_child_schema(
                    "items".to_owned(),
                    sub,
                    &element,
                    &element_path,
                    iss,
                    &EvaluationCallbacks::default(),
                );
                self.close("}");
            }
            TupleRest::Schema(_) => {}
            TupleRest::Forbidden => {
                // The types artifact caps the tuple length; reject any element past the fixed
                // prefix, reusing the length-bound message vocabulary.
                self.push_issue(
                    &format!("{val}.length > {prefix_len}"),
                    path,
                    iss,
                    &format!("more items than maxItems {prefix_len}"),
                );
            }
            TupleRest::Allowed => {}
        }
        // minItems/maxItems/uniqueItems apply to tuples too (the parser populates
        // meta.array_constraints for tuple nodes); emit them after the element checks, matching
        // gen_array's relative order so issue order stays consistent between the two array shapes.
        self.gen_array_constraints(meta, val, path, iss);
        if let Some(callback) = &evaluation.item {
            self.open(&format!("if ({callback} !== undefined) {{"));
            self.open(&format!(
                "for (let index = 0; index < Math.min({val}.length, {}); index += 1) {{",
                prefix_items.len()
            ));
            self.line(&format!("{callback}(index);"));
            self.close("}");
            if meta.items_present {
                self.open(&format!(
                    "for (let index = {}; index < {val}.length; index += 1) {{",
                    prefix_items.len()
                ));
                self.line(&format!("{callback}(index);"));
                self.close("}");
            }
            self.close("}");
        }
        self.close_type_gate(meta.nullable, val, path, iss, "array");
    }

    fn gen_tuple_prefixes_bounded(
        &mut self,
        prefix_items: &[SchemaNode],
        val: &str,
        path: &str,
        iss: &str,
    ) {
        let prefix_cost = |prefix: &SchemaNode| {
            if is_noop_schema(prefix) {
                0
            } else {
                let child = validation_flow_cost(prefix, self.position);
                4 + usize::from(child <= VALIDATOR_CFA_BUDGET) * child
            }
        };
        let total = prefix_items.iter().fold(0usize, |cost, prefix| {
            cost.saturating_add(prefix_cost(prefix))
                .min(VALIDATOR_CFA_BUDGET + 1)
        });
        if total <= VALIDATOR_CFA_BUDGET {
            self.gen_tuple_prefixes(prefix_items, 0, val, path, iss);
            return;
        }

        let mut chunks = Vec::new();
        let mut start = 0;
        let mut cost = 0usize;
        for (index, prefix) in prefix_items.iter().enumerate() {
            let next = prefix_cost(prefix);
            if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                chunks.push((start, index));
                start = index;
                cost = 0;
            }
            cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
        }
        chunks.push((start, prefix_items.len()));

        for (part, (start, end)) in chunks.into_iter().enumerate() {
            let name = self.helper_name("Tuple", Some(part));
            let parent_out = std::mem::take(&mut self.out);
            let parent_indent = self.indent;
            let parent_counter = self.counter;
            self.indent = 1;
            self.counter = 0;
            self.gen_tuple_prefixes(&prefix_items[start..end], start, "value", "path", "issues");
            let helper_body = std::mem::replace(&mut self.out, parent_out);
            self.indent = parent_indent;
            self.counter = parent_counter;
            self.helpers.push(format!(
                "function {name}(value: readonly unknown[], path: readonly (string | number)[], issues: Issue[]): void {{\n{helper_body}}}\n\n"
            ));
            self.line(&format!("{name}({val}, {path}, {iss});"));
        }
    }

    fn gen_tuple_prefixes(
        &mut self,
        prefix_items: &[SchemaNode],
        offset: usize,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        for (index, prefix) in prefix_items.iter().enumerate() {
            let position_index = offset + index;
            // A no-op prefix schema validates its position against nothing, so both the
            // length-guard block and its value/path scaffold are dead — skip the whole position.
            if is_noop_schema(prefix) {
                continue;
            }
            self.open(&format!("if ({val}.length > {position_index}) {{"));
            let index = self.fresh();
            let element = format!("value{index}");
            let element_path = format!("path{index}");
            self.line(&format!(
                "const {element}: unknown = {val}[{position_index}];"
            ));
            self.scope.runtime_values.insert("appendKey");
            self.line(&format!(
                "const {element_path} = appendKey({path}, {position_index});"
            ));
            self.gen_child_schema(
                format!("prefixItems/{position_index}"),
                prefix,
                &element,
                &element_path,
                iss,
                &EvaluationCallbacks::default(),
            );
            self.close("}");
        }
    }

    fn gen_array_constraints(&mut self, meta: &SchemaMeta, val: &str, path: &str, iss: &str) {
        let constraints = meta.array_constraints();
        if let Some(min) = constraints.min_items {
            self.push_issue(
                &format!("{val}.length < {min}"),
                path,
                iss,
                &format!("fewer items than minItems {min}"),
            );
        }
        if let Some(max) = constraints.max_items {
            self.push_issue(
                &format!("{val}.length > {max}"),
                path,
                iss,
                &format!("more items than maxItems {max}"),
            );
        }
        if constraints.unique_items {
            self.scope.runtime_values.insert("deepEqual");
            self.scope.runtime_values.insert("issue");
            let index = self.fresh();
            let unique = format!("unique{index}");
            self.line(&format!("let {unique} = true;"));
            self.open(&format!(
                "for (let i{index} = 0; {unique} && i{index} < {val}.length; i{index} += 1) {{"
            ));
            self.open(&format!(
                "for (let j{index} = i{index} + 1; {unique} && j{index} < {val}.length; j{index} += 1) {{"
            ));
            self.open(&format!(
                "if (deepEqual({val}[i{index}], {val}[j{index}])) {{"
            ));
            self.line(&format!("{unique} = false;"));
            self.close("}");
            self.close("}");
            self.close("}");
            self.open(&format!("if (!{unique}) {{"));
            self.line(&format!("{iss}.push(issue({path}, \"items not unique\"));"));
            self.close("}");
        }
    }

    fn gen_all_of(
        &mut self,
        branches: &[SchemaNode],
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        let branch_cost = |branch: &SchemaNode| {
            let cost = validation_flow_cost(branch, self.position);
            usize::from(cost <= VALIDATOR_CFA_BUDGET) * cost
        };
        let total = branches.iter().fold(0usize, |cost, branch| {
            cost.saturating_add(branch_cost(branch))
                .min(VALIDATOR_CFA_BUDGET + 1)
        });
        if total <= VALIDATOR_CFA_BUDGET {
            self.gen_all_of_branches(branches, 0, val, path, iss, evaluation);
            return;
        }

        let mut chunks = Vec::new();
        let mut start = 0;
        let mut cost = 0usize;
        for (index, branch) in branches.iter().enumerate() {
            let next = branch_cost(branch);
            if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                chunks.push((start, index));
                start = index;
                cost = 0;
            }
            cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
        }
        chunks.push((start, branches.len()));

        for (part, (start, end)) in chunks.into_iter().enumerate() {
            let name = self.helper_name("AllOf", Some(part));
            let parent_out = std::mem::take(&mut self.out);
            let parent_indent = self.indent;
            let parent_counter = self.counter;
            self.indent = 1;
            self.counter = 0;
            self.gen_all_of_branches(
                &branches[start..end],
                start,
                "value",
                "path",
                "issues",
                &EvaluationCallbacks::root(),
            );
            let helper_body = std::mem::replace(&mut self.out, parent_out);
            let evaluation_parameters = evaluation_parameters(&helper_body);
            let value_parameter = value_parameter(&helper_body, VALUE_UNKNOWN);
            self.indent = parent_indent;
            self.counter = parent_counter;
            self.helpers.push(format!(
                "function {name}({value_parameter}, path: readonly (string | number)[], issues: Issue[], {evaluation_parameters}): void {{\n{helper_body}}}\n\n"
            ));
            self.line(&format!(
                "{name}({val}, {path}, {iss}, {}, {});",
                EvaluationCallbacks::argument(&evaluation.property),
                EvaluationCallbacks::argument(&evaluation.item)
            ));
        }
    }

    fn gen_all_of_branches(
        &mut self,
        branches: &[SchemaNode],
        offset: usize,
        val: &str,
        path: &str,
        iss: &str,
        evaluation: &EvaluationCallbacks,
    ) {
        for (index, branch) in branches.iter().enumerate() {
            self.gen_child_schema(
                format!("allOf/{}", offset + index),
                branch,
                val,
                path,
                iss,
                evaluation,
            );
        }
    }

    fn gen_composition(
        &mut self,
        branches: &[SchemaNode],
        val: &str,
        path: &str,
        iss: &str,
        kind: Composition,
        evaluation: &EvaluationCallbacks,
    ) {
        self.scope.runtime_values.insert("issue");
        let index = self.fresh();
        let counter = format!("matches{index}");
        self.line(&format!("let {counter} = 0;"));
        let limit = match kind {
            // Annotation collection must examine every successful anyOf branch. Without an
            // annotation consumer the first success still decides the assertion verdict.
            Composition::AnyOf if !evaluation.is_empty() => branches.len().saturating_add(1),
            Composition::AnyOf => 1,
            Composition::OneOf => 2,
        };
        let branch_cost = |branch: &SchemaNode| {
            let child = validation_flow_cost(branch, self.position);
            let annotations = usize::from(!evaluation.is_empty()) * 10;
            6 + annotations + usize::from(child <= VALIDATOR_CFA_BUDGET) * child
        };
        let total = branches.iter().fold(4usize, |cost, branch| {
            cost.saturating_add(branch_cost(branch))
                .min(VALIDATOR_CFA_BUDGET + 1)
        });
        if total <= VALIDATOR_CFA_BUDGET {
            self.gen_composition_branches(CompositionParts {
                branches,
                offset: 0,
                val,
                path,
                counter: &counter,
                limit: &limit.to_string(),
                kind,
                evaluation,
            });
        } else {
            let mut chunks = Vec::new();
            let mut start = 0;
            let mut cost = 0usize;
            for (branch_index, branch) in branches.iter().enumerate() {
                let next = branch_cost(branch);
                if cost > 0 && cost.saturating_add(next) > VALIDATOR_CFA_BUDGET {
                    chunks.push((start, branch_index));
                    start = branch_index;
                    cost = 0;
                }
                cost = cost.saturating_add(next).min(VALIDATOR_CFA_BUDGET + 1);
            }
            chunks.push((start, branches.len()));

            for (part, (start, end)) in chunks.into_iter().enumerate() {
                let name = self.helper_name(kind.helper_role(), Some(part));
                let parent_out = std::mem::take(&mut self.out);
                let parent_indent = self.indent;
                let parent_counter = self.counter;
                self.indent = 1;
                self.counter = 0;
                let helper_counter = format!("matches{}", self.fresh());
                self.line(&format!("let {helper_counter} = 0;"));
                self.gen_composition_branches(CompositionParts {
                    branches: &branches[start..end],
                    offset: start,
                    val: "value",
                    path: "path",
                    counter: &helper_counter,
                    limit: "limit",
                    kind,
                    evaluation: &EvaluationCallbacks::root(),
                });
                self.line(&format!("return {helper_counter};"));
                let helper_body = std::mem::replace(&mut self.out, parent_out);
                let evaluation_parameters = evaluation_parameters(&helper_body);
                let value_parameter = value_parameter(&helper_body, VALUE_UNKNOWN);
                self.indent = parent_indent;
                self.counter = parent_counter;
                self.helpers.push(format!(
                    "function {name}({value_parameter}, path: readonly (string | number)[], limit: number, {evaluation_parameters}): number {{\n{helper_body}}}\n\n"
                ));
                self.open(&format!("if ({counter} < {limit}) {{"));
                self.line(&format!(
                    "{counter} += {name}({val}, {path}, {limit} - {counter}, {}, {});",
                    EvaluationCallbacks::argument(&evaluation.property),
                    EvaluationCallbacks::argument(&evaluation.item)
                ));
                self.close("}");
            }
        }
        let (condition, message) = match kind {
            Composition::AnyOf => (format!("{counter} === 0"), "no anyOf branch matched"),
            Composition::OneOf => (
                format!("{counter} !== 1"),
                "expected exactly one oneOf branch to match",
            ),
        };
        self.open(&format!("if ({condition}) {{"));
        self.line(&format!(
            "{iss}.push(issue({path}, {}));",
            render_ts_string(message)
        ));
        self.close("}");
    }

    fn gen_composition_branches(&mut self, parts: CompositionParts<'_>) {
        let CompositionParts {
            branches,
            offset,
            val,
            path,
            counter,
            limit,
            kind,
            evaluation,
        } = parts;
        for (branch_index, branch) in branches.iter().enumerate() {
            self.open(&format!("if ({counter} < {limit}) {{"));
            let scratch_index = self.fresh();
            let scratch = format!("issues{scratch_index}");
            self.line(&format!("const {scratch}: Issue[] = [];"));
            let mut branch_evaluation = self.branch_evaluation(evaluation, &scratch);
            self.gen_child_schema(
                format!("{}/{}", kind.keyword(), offset + branch_index),
                branch,
                val,
                path,
                &scratch,
                &branch_evaluation.callbacks,
            );
            self.prune_unused_branch_evaluation(&mut branch_evaluation);
            self.open(&format!("if ({scratch}.length === 0) {{"));
            self.line(&format!("{counter} += 1;"));
            self.merge_branch_evaluation(&branch_evaluation, evaluation);
            self.close("}");
            self.close("}");
        }
    }
}

#[derive(Clone, Copy)]
enum Composition {
    AnyOf,
    OneOf,
}

impl Composition {
    fn keyword(self) -> &'static str {
        match self {
            Self::AnyOf => "anyOf",
            Self::OneOf => "oneOf",
        }
    }

    fn helper_role(self) -> &'static str {
        match self {
            Self::AnyOf => "AnyOf",
            Self::OneOf => "OneOf",
        }
    }
}

/// The borrowed pieces of a `SchemaNode::Object`, grouped so object generation takes one argument.
struct ObjectParts<'a> {
    properties: &'a [(String, SchemaNode, PropMeta)],
    additional_properties: &'a AdditionalProperties,
    additional_properties_present: bool,
    dependent_required: &'a [(String, Vec<String>)],
    extra_required: &'a [String],
    meta: &'a SchemaMeta,
}

struct TupleParts<'a> {
    prefix_items: &'a [SchemaNode],
    rest: &'a TupleRest,
}

struct ApplicatorParts<'a> {
    meta: &'a SchemaMeta,
    val: &'a str,
    path: &'a str,
    iss: &'a str,
    evaluation: &'a EvaluationCallbacks,
    evaluated_properties: Option<&'a str>,
    evaluated_items: Option<&'a str>,
}

struct AdditionalPropertiesParts<'a> {
    additional: &'a AdditionalProperties,
    properties: &'a [(String, SchemaNode, PropMeta)],
    pattern_properties: &'a [PatternProperty],
    force_split: bool,
    keys_expr: &'a str,
}

struct CompositionParts<'a> {
    branches: &'a [SchemaNode],
    offset: usize,
    val: &'a str,
    path: &'a str,
    counter: &'a str,
    limit: &'a str,
    kind: Composition,
    evaluation: &'a EvaluationCallbacks,
}

/// A schema whose validate body is empty, so descending into it emits only dead scaffold. A plain
/// free-form `{}`/`true` schema (`Any` with no constraint group) and an unknown leaf (`Unknown`,
/// which additionally fails the run via the reject walk, so it never reaches committed output) are
/// no-ops. A constrained typeless `Any` (`{minLength: 3}`) is NOT — it emits type-guarded checks, so
/// callers must give it the full value/path descent scaffold. Callers skip that scaffold only for
/// the no-op case.
fn is_noop_schema(schema: &SchemaNode) -> bool {
    match schema {
        SchemaNode::Any { meta } => {
            !has_typeless_constraints(meta) && meta.validation_applicators.is_none()
        }
        _ => false,
    }
}

/// Whether a schema's meta carries any typeless constraint group (numeric/string/array/object) —
/// the assertions a typeless `Any` node still enforces type-conditionally. `contentEncoding` is not
/// a validity constraint, so it does not count. The boxed groups follow the `Some` ⟺ non-default
/// invariant, so a populated box always means a real constraint.
fn has_typeless_constraints(meta: &SchemaMeta) -> bool {
    meta.numeric_constraints.is_some()
        || meta.string_constraints.is_some()
        || meta.array_constraints.is_some()
        || meta.object_constraints.is_some()
}

/// The guard that decides whether a key is undeclared, for the position being emitted.
///
/// Position-filtered for the same reason the `declaredProperties` list in the same emitted function
/// is: a `readOnly` property is not part of the request shape and a `writeOnly` one is not part of
/// the response shape, so exempting it from the unknown-key rejection admits a key the emitted type
/// does not declare. Under `additionalProperties: false` that made the validator wider than the
/// type it checks.
fn unknown_key_condition(
    properties: &[(String, SchemaNode, PropMeta)],
    position: TypePosition,
) -> String {
    let conditions = properties
        .iter()
        .filter(|(_, _, meta)| property_in_position(meta, position))
        .map(|(name, _, _)| format!("key !== {}", render_ts_string(name)))
        .collect::<Vec<_>>();
    if conditions.is_empty() {
        // Nothing is declared here, so every key is an undeclared one.
        return "true".to_owned();
    }
    conditions.join(" && ")
}

fn string_format_predicate(format: &str) -> Option<(&'static str, &'static str)> {
    match format {
        "date-time" => Some(("isDateTime", "invalid date-time format")),
        "date" => Some(("isDate", "invalid date format")),
        "time" => Some(("isTime", "invalid time format")),
        "uuid" => Some(("isUuid", "invalid uuid format")),
        "email" => Some(("isEmail", "invalid email format")),
        "hostname" => Some(("isHostname", "invalid hostname format")),
        "ipv4" => Some(("isIpv4", "invalid ipv4 format")),
        "ipv6" => Some(("isIpv6", "invalid ipv6 format")),
        "uri" => Some(("isUri", "invalid uri format")),
        "uri-reference" => Some(("isUriReference", "invalid uri-reference format")),
        "duration" => Some(("isDuration", "invalid duration format")),
        _ => None,
    }
}

/// One direction (lower or upper) of a numeric range. Carries the comparators and message
/// vocabulary that differ between the two directions while `gen_bound` owns the shared control flow.
#[derive(Clone, Copy)]
enum BoundDirection {
    Lower,
    Upper,
}

/// The direction-specific pieces `gen_bound` consumes: this direction's threshold fields on the
/// schema plus the comparator and message text used to render each check.
struct Bound<'a> {
    inclusive: &'a Option<Number>,
    exclusive: &'a Option<ExclusiveBound>,
    inclusive_comparator: &'static str,
    exclusive_comparator: &'static str,
    inclusive_message: &'static str,
    exclusive_message: &'static str,
}

impl BoundDirection {
    fn resolve(self, constraints: &crate::ir::NumericConstraints) -> Bound<'_> {
        match self {
            BoundDirection::Lower => Bound {
                inclusive: &constraints.minimum,
                exclusive: &constraints.exclusive_minimum,
                inclusive_comparator: "<",
                exclusive_comparator: "<=",
                inclusive_message: "less than minimum",
                exclusive_message: "not greater than exclusiveMinimum",
            },
            BoundDirection::Upper => Bound {
                inclusive: &constraints.maximum,
                exclusive: &constraints.exclusive_maximum,
                inclusive_comparator: ">",
                exclusive_comparator: ">=",
                inclusive_message: "greater than maximum",
                exclusive_message: "not less than exclusiveMaximum",
            },
        }
    }
}

// --- component and operation emission ----------------------------------------------------------

/// One emitted validator: its exported structural type declaration plus the validate/checked/const
/// trio built from an already-generated validate body.
struct Decl {
    type_declaration: String,
    helpers: String,
    validator: String,
}

struct NamedTypeDeclaration {
    name: String,
    content: String,
}

type SiblingBindings = BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>;

/// A direct component `$ref` whose positioned component name already is this operation export needs
/// no operation-local declaration: its structural type and validator are exactly the component's.
/// Returning the component file lets the caller preserve the operation module's public surface with
/// a direct re-export instead of emitting a self-referential alias and recursive wrapper.
pub(super) fn identical_component_delegate(
    emitter: &Emitter<'_, '_>,
    export_type: &str,
    schema: &SchemaNode,
    position: TypePosition,
) -> Option<String> {
    let SchemaNode::Ref { target, meta } = schema else {
        return None;
    };
    let resolved = emitter
        .model
        .schema_target(&target.source_id, &target.json_pointer)?;
    let applicators = meta.validation_applicators();
    (applicators.not.is_none()
        && applicators.property_names.is_none()
        && applicators.pattern_properties.is_empty()
        && applicators.contains.is_none()
        && applicators.dependent_schemas.is_empty()
        && applicators.conditional.is_none()
        && applicators.unevaluated_properties.is_none()
        && applicators.unevaluated_items.is_none()
        && emitter.model.transform_facts().site(schema).is_none()
        && emitter.render_type(schema, position, TypeAxis::Application, 0) == export_type)
        .then(|| resolved.file_base.clone())
}

/// The wire type an operation-local validator declares while its public export stem stays fixed.
/// A bare component delegate reuses that component's allocated twin name, including a collision
/// replacement; every other transforming position owns the ordinary `{Name}Wire` twin.
pub(super) fn validator_wire_type_name<'a>(
    emitter: &Emitter<'_, '_>,
    export_name: &'a str,
    schema: &SchemaNode,
    position: TypePosition,
    siblings: &BTreeSet<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Cow<'a, str> {
    // Borrowed on the non-converting path: under the `string` default every position takes it, and
    // owning a copy of the name it already has is an allocation that build pays for nothing.
    // `enabled` first because `reaches` is a fresh recursive scan that allocates as it collects a
    // node's outgoing refs, and no representation converting means no position has a twin.
    let facts = emitter.model.transform_facts();
    if !facts.enabled() || !facts.reaches(schema) {
        return Cow::Borrowed(export_name);
    }
    if let SchemaNode::Ref { target, .. } = schema
        && let Some(resolved) = emitter
            .model
            .schema_target(&target.source_id, &target.json_pointer)
        && resolved.variant_name(position) == export_name
    {
        // A component's twin was allocated against every declared component name already, so it
        // arrives resolved; only the operation-local names below are derived here.
        return Cow::Owned(resolved.wire_name(position));
    }
    let derived = format!("{export_name}Wire");
    if !siblings.contains(derived.as_str()) {
        return Cow::Owned(derived);
    }
    // The same yield the component twins take, module-locally: a position literally named
    // `<other>Wire` owns that name, and the derived one gives way rather than declaring it twice.
    let replacement = format!("{derived}Value");
    if siblings.contains(replacement.as_str()) {
        diagnostics.push(source_diagnostic(
            CODE_WIRE_COLLISION,
            format!(
                "generated wire type name '{derived}' for '{export_name}' collides with another declaration in the same module, and the replacement name '{replacement}' is already taken; rename one with naming.overrides"
            ),
            &schema.meta().source,
        ));
        return Cow::Owned(derived);
    }
    diagnostics.push(warning_diagnostic(
        CODE_WIRE_ALIAS,
        format!(
            "generated wire type name '{derived}' for '{export_name}' collides with another declaration in the same module; emitting it as '{replacement}'"
        ),
        &schema.meta().source,
    ));
    Cow::Owned(replacement)
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

    // A `readOnly`/`writeOnly` property somewhere in this component (or a component it references)
    // makes the request and/or response shape diverge from the neutral one, so this component gains
    // first-class Request/Response validator variants mirroring the type artifact. The divergence
    // was resolved across the whole reference graph at model construction; `Some` is exactly the
    // positions that diverge, and carries the name each one declares under.
    let (request_variant, response_variant, neutral_wire, request_wire, response_wire) = {
        // A component file and its target are registered together during path allocation.
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
    // Borrowed when the position has no wire twin, which is every position under the `string`
    // default: owning a copy of the name it already has is an allocation that build pays for
    // nothing, and the drift gate counts it.
    let neutral_type: Cow<'_, str> = neutral_wire
        .as_deref()
        .map_or(Cow::Borrowed(name), Cow::Borrowed);

    let mut scope = FileScope::default();
    let mut imports = SiblingImports {
        skip_self: Some(schema_index),
        ..SiblingImports::default()
    };

    let declarations = if request_variant.is_some() || response_variant.is_some() {
        // One full validator triplet per needed position. Fixed order — Neutral, then Request, then
        // Response — keeps the emitted file deterministic. The variant export names come from
        // `SchemaTarget`, the same producer the type artifact and every sibling import read, so
        // agreement is enforced here rather than restated.
        let mut variants: Vec<(String, Option<String>, TypePosition)> = Vec::with_capacity(3);
        variants.push((name.to_owned(), neutral_wire, TypePosition::Neutral));
        if let Some(export) = request_variant {
            variants.push((export, request_wire, TypePosition::Request));
        }
        if let Some(export) = response_variant {
            variants.push((export, response_wire, TypePosition::Response));
        }

        // Phase 1: render each variant's structural type and collect its sibling imports through the
        // shared emitter, position by position — the position selects which properties survive.
        let type_declarations: Vec<String> = {
            let emitter = factory.worker();
            variants
                .iter()
                .map(|(export_name, wire_name, position)| {
                    let declared_type = wire_name.as_deref().unwrap_or(export_name);
                    let mut declaration = String::new();
                    emitter.write_schema_declaration(
                        &mut declaration,
                        declared_type,
                        &schema.schema,
                        *position,
                        TypeAxis::Wire,
                        &schema.source,
                    );
                    imports.collect_types(&emitter, &schema.schema, *position);
                    declaration
                })
                .collect()
        };

        // Phase 2: generate each variant's validate body (needs schema_target lookups through a
        // dropped emitter); the position drives which properties the body checks.
        let mut declarations = Vec::with_capacity(variants.len());
        for ((export_name, wire_name, position), type_declaration) in
            variants.iter().zip(type_declarations)
        {
            let declared_type = wire_name.as_deref().unwrap_or(export_name);
            let mut body = FnBody::new(
                &mut scope,
                &mut imports,
                model,
                *position,
                export_name,
                schema.schema.meta().source.display(),
            );
            body.gen_root_schema(&schema.schema, "value", "path", "issues");
            let (helpers, body) = body.finish();
            declarations.push(Decl {
                type_declaration,
                helpers,
                validator: render_validator(export_name, declared_type, &body),
            });
        }
        declarations
    } else {
        // Neutral-only common case: a single declaration, allocation-identical to a marker-free
        // component before variants existed (the drift gate pins this shape).
        let type_declaration = {
            let emitter = factory.worker();
            let mut declaration = String::new();
            emitter.write_schema_declaration(
                &mut declaration,
                &neutral_type,
                &schema.schema,
                TypePosition::Neutral,
                TypeAxis::Wire,
                &schema.source,
            );
            imports.collect_types(&emitter, &schema.schema, TypePosition::Neutral);
            declaration
        };
        let mut body = FnBody::new(
            &mut scope,
            &mut imports,
            model,
            TypePosition::Neutral,
            name,
            schema.schema.meta().source.display(),
        );
        body.gen_root_schema(&schema.schema, "value", "path", "issues");
        let (helpers, body) = body.finish();
        vec![Decl {
            type_declaration,
            helpers,
            validator: render_validator(name, &neutral_type, &body),
        }]
    };

    let reexports = SiblingBindings::new();
    let content = assemble_file(model, "./", &imports, &reexports, &scope, &declarations);
    report_incomplete_applicators(&mut emission.diagnostics, &scope);
    let relative_path = format!("{}/components/{file_base}.ts", model.dirs.validators);
    emission.register_path(&relative_path, &schema.source);
    emission.files.push(GeneratedFile {
        relative_path,
        content,
    });
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

    // Deterministic list of (export type name, schema, wire position) to validate: every parameter,
    // every request-body position, and every JSON response branch (4XX/default included).
    let mut positions: Vec<(String, &SchemaNode, TypePosition)> = Vec::new();
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
        let mut responses: Vec<(String, &SchemaNode)> = Vec::new();
        for response in &operation.responses {
            let suffix = response_status_type_suffix(&response.status);
            responses.extend(response_body_validators(
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

    let mut scope = FileScope::default();
    let mut imports = SiblingImports::default();
    let mut reexports = SiblingBindings::new();

    // Phase 1: render each position's type alias and collect sibling imports. One emitter serves
    // both the value and header declarations — its merge/link caches carry across the two loops —
    // and the block scopes its borrow of `model` so phase 2 can reborrow `model` mutably.
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
    let (type_declarations, header_type_declarations): (
        Vec<Option<NamedTypeDeclaration>>,
        Vec<NamedTypeDeclaration>,
    ) = {
        let emitter = factory.worker();
        let type_declarations = positions
            .iter()
            .map(|(export_type, schema, position)| {
                let declared_type = validator_wire_type_name(
                    &emitter,
                    export_type,
                    schema,
                    *position,
                    &siblings,
                    &mut wire_diagnostics,
                );
                if let Some(file_base) =
                    identical_component_delegate(&emitter, export_type, schema, *position)
                {
                    let (types, values) = reexports.entry(file_base).or_default();
                    types.insert(declared_type.into_owned());
                    values.insert(format!("{}Validator", lowercase_first(export_type)));
                    values.insert(format!("validate{export_type}"));
                    return None;
                }
                imports.collect_types(&emitter, schema, *position);
                let declaration = format!(
                    "export type {declared_type} = {};\n",
                    emitter.render_type(schema, *position, TypeAxis::Wire, 0)
                );
                Some(NamedTypeDeclaration {
                    name: declared_type.into_owned(),
                    content: declaration,
                })
            })
            .collect();
        let header_type_declarations = header_positions
            .iter()
            .map(|(export_type, response)| {
                let transforms = response.headers.iter().any(|(_, header)| {
                    !crate::client_model::response_header_is_opaque_string(header)
                        && model.transform_facts().reaches(&header.schema)
                });
                let declared_type = if transforms {
                    format!("{export_type}Wire")
                } else {
                    export_type.clone()
                };
                for (_, header) in &response.headers {
                    imports.collect_types(&emitter, &header.schema, TypePosition::Response);
                }
                let mut declaration = String::new();
                emitter.write_response_headers_interface(
                    &mut declaration,
                    &declared_type,
                    response,
                    TypeAxis::Wire,
                );
                NamedTypeDeclaration {
                    name: declared_type,
                    content: declaration,
                }
            })
            .collect();
        (type_declarations, header_type_declarations)
    };

    // Phase 2: generate validate bodies.
    let mut declarations = Vec::with_capacity(positions.len() + header_positions.len());
    for ((export_type, schema, position), type_declaration) in
        positions.iter().zip(type_declarations)
    {
        let Some(type_declaration) = type_declaration else {
            continue;
        };
        let mut body = FnBody::new(
            &mut scope,
            &mut imports,
            model,
            *position,
            export_type,
            schema.meta().source.display(),
        );
        body.gen_root_schema(schema, "value", "path", "issues");
        let (helpers, body) = body.finish();
        declarations.push(Decl {
            type_declaration: type_declaration.content,
            helpers,
            validator: render_validator(export_type, &type_declaration.name, &body),
        });
    }
    for ((export_type, response), type_declaration) in
        header_positions.iter().zip(header_type_declarations)
    {
        let mut body = FnBody::new(
            &mut scope,
            &mut imports,
            model,
            TypePosition::Response,
            export_type,
            response.source.display(),
        );
        body.gen_response_headers(response);
        let (helpers, body) = body.finish();
        declarations.push(Decl {
            type_declaration: type_declaration.content,
            helpers,
            validator: render_validator(export_type, &type_declaration.name, &body),
        });
    }

    let content = assemble_file(
        model,
        "../components/",
        &imports,
        &reexports,
        &scope,
        &declarations,
    );
    emission.diagnostics.extend(wire_diagnostics);
    report_incomplete_applicators(&mut emission.diagnostics, &scope);
    let relative_path = format!("{}/{directory}/{file_base}.ts", model.dirs.validators);
    emission.register_path(&relative_path, &operation.source);
    emission.files.push(GeneratedFile {
        relative_path,
        content,
    });
}

/// The validator export-type name for each of `operation`'s parameters, aligned 1:1 with
/// `operation.parameters` (cookie parameters included — they carry a validator in the standalone
/// artifact even though the fetch client rejects them). The validators emitter and the client
/// request binding both derive their per-parameter check names here, so the imported call names
/// stay in lockstep with the exported ones.
pub(super) fn operation_parameter_validator_names(
    operation: &Operation,
    stem: &str,
) -> Vec<String> {
    let mut names = Vec::with_capacity(operation.parameters.len());
    let mut used: HashSet<String> = HashSet::new();
    for (index, parameter) in operation.parameters.iter().enumerate() {
        let location = location_title(parameter.location);
        let name_part = normalize_identifier(&parameter.name, TargetCase::Pascal)
            .unwrap_or_else(|_| format!("Param{index}"));
        let base = format!("{stem}{location}{name_part}");
        let mut export_type = base.clone();
        // The disambiguation suffix must vary per attempt: a fixed `{base}{index}` can itself
        // collide with another parameter's base name (case-only names collapse under Pascal
        // normalization), and re-inserting an already-taken name never terminates. Start at this
        // parameter's index — preserving the single-collision name — and bump until a name is free.
        let mut suffix = index;
        while !used.insert(export_type.clone()) {
            export_type = format!("{base}{suffix}");
            suffix += 1;
        }
        names.push(export_type);
    }
    names
}

fn location_title(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "Path",
        ParamLocation::Query => "Query",
        ParamLocation::Header => "Header",
        ParamLocation::Cookie => "Cookie",
    }
}

/// The `validate`/`checked`/const trio for one export, given its already-generated validate body.
fn render_validator(export_name: &str, declared_type: &str, body: &str) -> String {
    let const_name = format!("{}Validator", lowercase_first(export_name));
    let mut output = String::new();
    let evaluation_parameters = evaluation_parameters(body);
    let value_parameter = value_parameter(body, VALUE_UNKNOWN);
    output.push_str(&format!(
        "export function validate{export_name}({value_parameter}, path: readonly (string | number)[], issues: Issue[], {evaluation_parameters}): void {{\n"
    ));
    output.push_str(body);
    output.push_str("}\n\n");
    output.push_str(&format!(
        "function checked{export_name}(value: unknown, issues: Issue[]): value is {declared_type} {{\n  validate{export_name}(value, [], issues);\n  return issues.length === 0;\n}}\n\n"
    ));
    output.push_str(&format!(
        "export const {const_name}: SyncStandardSchemaV1<{declared_type}> = {{\n"
    ));
    output.push_str("  \"~standard\": {\n");
    output.push_str("    version: 1,\n");
    output.push_str("    vendor: \"oasts\",\n");
    output.push_str("    validate(value) {\n");
    output.push_str("      const issues: Issue[] = [];\n");
    output.push_str(&format!(
        "      return checked{export_name}(value, issues) ? {{ value }} : {{ issues }};\n"
    ));
    output.push_str("    },\n");
    output.push_str("    types: undefined,\n");
    output.push_str("  },\n");
    output.push_str("};\n");
    output
}

// --- file assembly -----------------------------------------------------------------------------

fn assemble_file(
    model: &EmissionModel<'_>,
    sibling_prefix: &str,
    imports: &SiblingImports,
    reexports: &SiblingBindings,
    scope: &FileScope,
    declarations: &[Decl],
) -> String {
    let extension = import_extension(model);
    let mut output = model.header();

    if !declarations.is_empty() {
        output.push_str(&format!(
            "import type {{ SyncStandardSchemaV1 }} from {};\n",
            render_ts_string(&format!("../standard-schema{extension}"))
        ));
        let runtime_values = std::iter::once("type Issue".to_owned())
            .chain(scope.runtime_values.iter().map(|value| (*value).to_owned()))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "import {{ {runtime_values} }} from {};\n",
            render_ts_string(&format!("../runtime{extension}"))
        ));
    }
    render_sibling_imports(&mut output, imports, sibling_prefix, &extension);
    for (file_base, (type_names, value_names)) in reexports {
        let specifiers = type_names
            .iter()
            .map(|name| format!("type {name}"))
            .chain(value_names.iter().cloned())
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "export {{ {specifiers} }} from {};\n",
            render_ts_string(&format!("{sibling_prefix}{file_base}{extension}"))
        ));
    }
    output.push('\n');

    if scope.needs_is_record {
        // Every index-signature type this emitter writes is spelled structurally rather than as
        // `Record<string, unknown>`: validator modules declare and import component types, so a
        // document with a component named `Record` puts a non-generic `Record` in this scope and
        // the built-in stops resolving (`TS2315: Type 'Record' is not generic`). Reserving the
        // name instead would rename the user's exported type; the structural form costs nothing
        // and cannot be shadowed. `no_builtin_generics_in_schema_bearing_modules` pins this.
        output.push_str(
            "function isRecord(value: unknown): value is { [key: string]: unknown } {\n  return typeof value === \"object\" && value !== null && !Array.isArray(value);\n}\n\n",
        );
    }
    if scope.needs_is_array {
        output.push_str(
            "function isArray(value: unknown): value is readonly unknown[] {\n  return Array.isArray(value);\n}\n\n",
        );
    }
    for (slot, (pattern, unicode)) in scope.patterns.iter().enumerate() {
        output.push_str(&format!("let pattern{slot}: RegExp | undefined;\n"));
        output.push_str(&format!("function pattern{slot}Regex(): RegExp {{\n"));
        let flags = if *unicode { ", \"u\"" } else { "" };
        output.push_str(&format!(
            "  return (pattern{slot} ??= new RegExp({}{flags}));\n",
            render_ts_string(pattern),
        ));
        output.push_str("}\n\n");
    }

    for (index, declaration) in declarations.iter().enumerate() {
        output.push_str(&declaration.type_declaration);
        output.push('\n');
        output.push_str(&declaration.helpers);
        output.push_str(&declaration.validator);
        if index + 1 < declarations.len() {
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::inputs::InputRecorder;
    use std::fs;

    use serde_json::{Map, Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::client_model::build_client_model;
    use crate::config::load_single;
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::emit::emit_artifacts;
    use crate::ir::SchemaRef;
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;

    /// Compiles an OpenAPI document with the validators artifact enabled, returning the emitted
    /// files and the sorted diagnostics. Mirrors the pipeline stages so the reject walk runs.
    fn compile(document: Value) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        compile_with_config(
            document,
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "validators": true }
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
        let resolved = load_single(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph =
            load_graph(&resolved, &mut InputRecorder::off(), &mut sink).expect("graph loads");
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
            &mut InputRecorder::off(),
            &mut sink,
        );
        (files, sink.into_sorted_vec())
    }

    fn doc_31(schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    #[test]
    fn validation_flow_cost_includes_every_validation_applicator() {
        let schema = SchemaNode::Any {
            meta: SchemaMeta {
                validation_applicators: Some(Box::new(crate::ir::ValidationApplicators {
                    not: Some(Box::new(SchemaNode::Any {
                        meta: SchemaMeta::default(),
                    })),
                    property_names: Some(Box::new(SchemaNode::Any {
                        meta: SchemaMeta::default(),
                    })),
                    conditional: Some(Box::new(ConditionalApplicator {
                        condition: Box::new(SchemaNode::Any {
                            meta: SchemaMeta::default(),
                        }),
                        then_schema: Some(Box::new(SchemaNode::Never {
                            meta: SchemaMeta::default(),
                        })),
                        else_schema: Some(Box::new(SchemaNode::Never {
                            meta: SchemaMeta::default(),
                        })),
                    })),
                    unevaluated_properties: Some(Box::new(SchemaNode::Any {
                        meta: SchemaMeta::default(),
                    })),
                    unevaluated_items: Some(Box::new(SchemaNode::Never {
                        meta: SchemaMeta::default(),
                    })),
                    ..crate::ir::ValidationApplicators::default()
                })),
                ..SchemaMeta::default()
            },
        };

        assert_eq!(validation_flow_cost(&schema, TypePosition::Neutral), 50);
    }

    fn doc_30(schemas: Value) -> Value {
        json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    fn component(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("validators/components/{base}.ts"))
            .expect("component validator file")
            .content
            .clone()
    }

    #[test]
    fn transforming_date_time_validator_declares_the_wire_type() {
        let (files, diagnostics) = compile_with_config(
            doc_31(json!({
                "Event": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Envelope": {
                    "type": "object",
                    "required": ["event"],
                    "properties": {
                        "event": { "$ref": "#/components/schemas/Event" }
                    }
                }
            })),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "validators": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "generated",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );
        assert_clean(&diagnostics);
        let content = component(&files, "event");
        assert!(
            content.contains("export interface EventWire {\n  at: string;\n}"),
            "{content}"
        );
        assert!(
            content.contains("export function validateEvent(value: unknown,"),
            "{content}"
        );
        assert!(
            content.contains(
                "function checkedEvent(value: unknown, issues: Issue[]): value is EventWire {"
            ),
            "{content}"
        );
        assert!(
            content.contains("export const eventValidator: SyncStandardSchemaV1<EventWire> = {"),
            "{content}"
        );
        assert!(
            content.contains("if (typeof value0 === \"string\") {"),
            "{content}"
        );
        let envelope = component(&files, "envelope");
        assert!(
            envelope.contains("import { type EventWire, validateEvent } from \"./event.js\";"),
            "{envelope}"
        );
        assert!(envelope.contains("event: EventWire;"), "{envelope}");
    }

    #[test]
    fn a_derived_wire_name_yields_to_a_position_that_owns_it() {
        // Query parameters `a` and `aWire`: the first converts, so it derives `ReadQueryAWire` —
        // which is the second's own name. Both were emitted as `export type ReadQueryAWire`.
        let (files, diagnostics) = compile_with_config(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": { "/r": { "get": {
                    "operationId": "read",
                    "parameters": [
                        { "name": "a", "in": "query", "required": true,
                          "schema": { "type": "string", "format": "date-time" } },
                        { "name": "aWire", "in": "query", "required": true,
                          "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "ok", "content": {
                        "application/json": { "schema": { "type": "object" } } } } }
                } } },
                "components": { "schemas": {} }
            }),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "validators": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "generated",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );

        let content = &files
            .iter()
            .find(|file| file.relative_path == "validators/operations/read.ts")
            .expect("the operation validator module")
            .content;
        assert!(
            content.contains("export type ReadQueryAWireValue = string;"),
            "{content}"
        );
        assert_eq!(
            content.matches("export type ReadQueryAWire =").count(),
            1,
            "{content}"
        );
        let mut warned = false;
        for diagnostic in &diagnostics {
            if diagnostic.code == "OASTS4104" {
                warned = true;
            }
        }
        assert!(warned, "{diagnostics:#?}");
    }

    #[test]
    fn a_wire_name_with_nowhere_left_to_yield_is_fatal() {
        // `ReadQueryAWire` and `ReadQueryAWireValue` are both owned by other positions, so the
        // derived twin has no free name and sharing one silently is the outcome to avoid.
        let (_files, diagnostics) = compile_with_config(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": { "/r": { "get": {
                    "operationId": "read",
                    "parameters": [
                        { "name": "a", "in": "query", "required": true,
                          "schema": { "type": "string", "format": "date-time" } },
                        { "name": "aWire", "in": "query", "required": true,
                          "schema": { "type": "string" } },
                        { "name": "aWireValue", "in": "query", "required": true,
                          "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "ok", "content": {
                        "application/json": { "schema": { "type": "object" } } } } }
                } } },
                "components": { "schemas": {} }
            }),
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "validators": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "generated",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );

        let mut fatal = Vec::new();
        for diagnostic in &diagnostics {
            if diagnostic.code == "OASTS4105" {
                fatal.push(diagnostic.message.as_str());
            }
        }
        assert_eq!(fatal.len(), 1, "{diagnostics:#?}");
        assert!(fatal[0].contains("ReadQueryAWireValue"), "{fatal:?}");
    }

    #[test]
    fn transforming_operation_validators_keep_their_public_names() {
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
                "artifacts": { "types": true, "client": true, "validators": true },
                "types": { "dateTime": "date" },
                "validation": {
                    "engine": "generated",
                    "request": true,
                    "response": true,
                    "unchecked": "allow"
                }
            }),
        );
        assert_clean(&diagnostics);
        let content = operation(&files, "createevent");
        assert!(
            content.contains("export type CreateEventQuerySinceWire = string;"),
            "{content}"
        );
        assert!(
            content.contains("export function validateCreateEventQuerySince(value: unknown,"),
            "{content}"
        );
        assert!(
            content.contains("SyncStandardSchemaV1<CreateEventQuerySinceWire>"),
            "{content}"
        );
        assert!(content.contains("export { type CreateEventRequestBodyWire, createEventRequestBodyValidator, validateCreateEventRequestBody } from \"../components/createeventrequestbody.js\";"), "{content}");
        assert!(
            content.contains("export type CreateEventResponse200Wire = string;"),
            "{content}"
        );
        assert!(
            content.contains("export interface CreateEventResponse200HeadersWire {"),
            "{content}"
        );
        assert!(content.contains("\"X-Created-At\": string;"), "{content}");
        assert!(
            content
                .contains("export function validateCreateEventResponse200Headers(value: unknown,"),
            "{content}"
        );
    }

    #[test]
    fn oversized_inline_object_is_split_by_its_own_stable_path() {
        let mut properties = Map::new();
        for index in 0..260 {
            properties.insert(
                format!("field{index:03}"),
                json!({ "type": "string", "readOnly": index == 0 }),
            );
        }
        let typed_properties = properties.clone();
        let evaluated_properties = properties.clone();
        let document = doc_31(json!({
            "Wide": {
                "type": "object",
                "properties": {
                    "nestedClosed": {
                        "type": "object",
                        "properties": Value::Object(properties),
                        "required": ["missing"],
                        "dependentRequired": { "field001": ["field002"] },
                        "additionalProperties": false
                    },
                    "nestedTyped": {
                        "type": "object",
                        "properties": Value::Object(typed_properties),
                        "additionalProperties": { "type": "string" }
                    }
                }
            },
            "EvaluatedWide": {
                "allOf": [{
                    "type": "object",
                    "properties": Value::Object(evaluated_properties)
                }],
                "unevaluatedProperties": false
            }
        }));
        let (first_files, first_diagnostics) = compile(document.clone());
        let (second_files, second_diagnostics) = compile(document);
        assert_eq!(first_diagnostics, second_diagnostics);
        assert_eq!(first_files, second_files);

        let content = component(&first_files, "wide");
        assert!(content.contains("function validateWideObject"));
        assert!(content.contains("function validateWideAt"));
        assert!(content.contains("function validateWideRequired"));
        assert!(content.contains("function validateWideDependent"));
        assert!(content.contains("function validateWideAdditional"));
        assert!(content.contains("export function validateWide(value: unknown,"));
        assert!(content.contains("function checkedWide(value: unknown,"));
        assert!(content.contains("export const wideValidator: SyncStandardSchemaV1<Wide> = {"));
        let evaluated = component(&first_files, "evaluatedwide");
        assert!(
            evaluated.contains("(value, path, issues, recordProperty0, evaluatedItem);"),
            "{evaluated}"
        );
        // `field000` is readOnly, so it is not part of the request shape and is not a known key
        // there. The split helper's `known` list is filtered by position for the same reason the
        // inline guard is — otherwise an object large enough to take this path keeps exempting a
        // key the small-object form rejects, and where `unevaluatedProperties` also applies the
        // two gates disagree and neither rejects it.
        let request_known = content
            .split("function validateWideRequestAdditional")
            .nth(1)
            .expect("a request-position additional-properties helper")
            .split("\n}\n")
            .next()
            .expect("the helper body");
        assert!(!request_known.contains("\"field000\""), "{request_known}");
        assert!(request_known.contains("\"field001\""), "{request_known}");
    }

    #[test]
    fn oversized_schema_sequences_use_bounded_helpers() {
        let strings = vec![json!({ "type": "string" }); 340];
        let tuple = vec![json!({ "type": "string" }); 150];
        let alternatives = vec![json!({ "type": "string" }); 120];
        let enum_values = (0..1_001)
            .map(|index| Value::String(format!("value{index}")))
            .collect::<Vec<_>>();
        let (files, diagnostics) = compile(doc_31(json!({
            "ManyAllOf": { "allOf": strings },
            "ManyTuple": {
                "type": "array",
                "prefixItems": tuple,
                "items": false
            },
            "ManyAnyOf": { "anyOf": alternatives },
            "ManyOneOf": { "oneOf": vec![json!({ "type": "string" }); 120] },
            "ManyEnum": { "type": "string", "enum": enum_values },
            "CostMatrix": {
                "type": "object",
                "properties": {
                    "closedObject": {
                        "type": "object",
                        "properties": { "free": {} },
                        "required": ["free"],
                        "dependentRequired": { "free": ["dependent"] },
                        "additionalProperties": false,
                        "minProperties": 1,
                        "maxProperties": 2,
                        "enum": [{}],
                        "const": {}
                    },
                    "schemaObject": {
                        "type": "object",
                        "additionalProperties": { "type": "string" }
                    },
                    "noopArray": {
                        "type": "array",
                        "items": {},
                        "minItems": 1,
                        "maxItems": 2,
                        "uniqueItems": true,
                        "enum": [[]],
                        "const": []
                    },
                    "schemaTuple": {
                        "type": "array",
                        "prefixItems": [{ "type": "string" }],
                        "items": { "type": "number" },
                        "minItems": 1,
                        "maxItems": 2,
                        "uniqueItems": true,
                        "enum": [[]],
                        "const": []
                    },
                    "forbiddenTuple": {
                        "type": "array",
                        "prefixItems": [{ "type": "string" }],
                        "items": false
                    },
                    "allowedTuple": {
                        "type": "array",
                        "prefixItems": [{}, { "type": "string" }],
                        "items": true
                    },
                    "all": { "allOf": [{ "type": "string" }] },
                    "any": { "anyOf": [{ "type": "string" }] },
                    "one": { "oneOf": [{ "type": "string" }] },
                    "finite": { "enum": ["value"] },
                    "never": false
                }
            }
        })));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(component(&files, "manyallof").contains("ManyAllOfAllOf"));
        assert!(component(&files, "manytuple").contains("ManyTupleTuple"));
        assert!(component(&files, "manyanyof").contains("ManyAnyOfAnyOf"));
        assert!(component(&files, "manyoneof").contains("ManyOneOfOneOf"));
        assert!(component(&files, "manyenum").contains("ManyEnumEnum"));
    }

    #[test]
    fn oversized_pattern_and_dependent_schema_applicators_use_bounded_helpers() {
        let mut patterns = Map::new();
        let mut dependencies = Map::new();
        for index in 0..160 {
            patterns.insert(
                format!("^p{index:03}-"),
                json!({ "type": "string", "minLength": 1 }),
            );
            dependencies.insert(
                format!("trigger{index:03}"),
                json!({ "required": [format!("dependent{index:03}")] }),
            );
        }
        let (files, diagnostics) = compile(doc_31(json!({
            "ManyApplicators": {
                "type": "object",
                "patternProperties": Value::Object(patterns),
                "dependentSchemas": Value::Object(dependencies),
                "additionalProperties": false
            }
        })));
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code == "OASTS2201" && diagnostic.severity == Severity::Warning
            }),
            "{diagnostics:?}"
        );
        let content = component(&files, "manyapplicators");
        assert!(content.contains("ManyApplicatorsPatternProperties"));
        assert!(content.contains("ManyApplicatorsDependentSchemas"));
        assert!(content.contains("ManyApplicatorsPatternKey"));
    }

    #[test]
    fn oversized_incomplete_applicators_fail_before_emitting_bounded_helpers() {
        let mut patterns = Map::new();
        let mut dependencies = Map::new();
        for index in 0..160 {
            let schema = if index == 0 {
                json!({ "type": "string", "format": "unknown-format" })
            } else {
                json!({ "type": "string", "minLength": 1 })
            };
            patterns.insert(format!("^p{index:03}-"), schema.clone());
            dependencies.insert(format!("trigger{index:03}"), schema);
        }
        let (files, diagnostics) = compile(doc_31(json!({
            "IncompletePatterns": {
                "patternProperties": Value::Object(patterns)
            },
            "IncompleteDependencies": {
                "dependentSchemas": Value::Object(dependencies)
            }
        })));
        for keyword in ["patternProperties", "dependentSchemas"] {
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                        && diagnostic.message.contains(keyword)
                }),
                "{keyword}: {diagnostics:?}"
            );
        }
        assert!(!component(&files, "incompletepatterns").contains("PatternPropertiesPart"));
        assert!(!component(&files, "incompletedependencies").contains("DependentSchemasPart"));
    }

    /// `reserve_names` renames `Issue` (a kernel identifier this artifact injects) to `Issue2`
    /// after the collision pass has already aliased its request variant to `IssueRequestBody`.
    /// Dropping that alias on the rename would re-derive `Issue2Request` — a name this document
    /// declares — and nothing re-checks a post-rename derivation, so two modules would export one
    /// identifier with no diagnostic and the artifact would not compile. The alias is kept instead:
    /// it stays globally unique because it was checked against every declared name when assigned.
    #[test]
    fn a_reserved_name_rename_keeps_the_variant_alias_it_was_given() {
        let (files, diagnostics) = compile(doc_30(json!({
            "Issue": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true }, "n": { "type": "string" } }
            },
            "IssueRequest": { "type": "object", "properties": { "label": { "type": "string" } } },
            "Issue2Request": { "type": "object", "properties": { "z": { "type": "string" } } },
            "Envelope": {
                "type": "object",
                "properties": {
                    "a": { "$ref": "#/components/schemas/Issue" },
                    "b": { "$ref": "#/components/schemas/Issue2Request" }
                }
            }
        })));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:?}"
        );
        // The renamed component keeps the alias rather than re-deriving `Issue2Request`.
        let issue = component(&files, "issue");
        assert!(
            issue.contains("export interface IssueRequestBody {"),
            "{issue}"
        );
        assert!(!issue.contains("Issue2Request"), "{issue}");
        // The importer therefore binds two distinct identifiers, one per source module.
        let envelope = component(&files, "envelope");
        assert!(
            envelope.contains(
                "import { type Issue2, type IssueRequestBody, validateIssue2, validateIssueRequestBody } from \"./issue.js\";"
            ),
            "{envelope}"
        );
        assert!(
            envelope.contains(
                "import { type Issue2Request, validateIssue2Request } from \"./issue2request.js\";"
            ),
            "{envelope}"
        );
    }

    fn type_component(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("types/components/{base}.ts"))
            .expect("component types file")
            .content
            .lines()
            .filter(|line| !line.starts_with("// Source digest:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_clean(diagnostics: &[Diagnostic]) {
        assert!(
            !diagnostics.iter().any(|d| d.severity == Severity::Error),
            "unexpected errors: {diagnostics:#?}"
        );
    }

    fn operation_validators(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("validators/operations/{base}.ts"))
            .expect("operation validator file")
            .content
            .clone()
    }

    fn generated(files: &[GeneratedFile], relative_path: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == relative_path)
            .expect("generated file")
            .content
            .clone()
    }

    fn two_json_response_document(second_media: &str) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] } },
                                    second_media: { "schema": { "type": "object", "properties": { "code": { "type": "integer" } }, "required": ["code"] } }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn a_single_json_entry_beside_a_non_json_one_keeps_the_plain_validator_name() {
        // The common discriminated case: two media entries, one of them JSON. Nothing about the
        // validator artifact changes — no new name, no per-entry split.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": { "schema": { "type": "object", "properties": { "id": { "type": "string" } } } },
                                    "text/plain": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation_validators(&files, "readthing");
        assert!(
            content.contains("export function validateReadthingResponse200("),
            "{content}"
        );
        assert!(
            !content.contains("validateReadthingResponse200Application"),
            "{content}"
        );
    }

    #[test]
    fn two_json_entries_emit_one_validator_each_tagged_by_media() {
        let (files, diagnostics) = compile(two_json_response_document("application/vnd.api+json"));
        assert_clean(&diagnostics);
        let content = operation_validators(&files, "readthing");
        assert!(
            content.contains("export function validateReadthingResponse200ApplicationJson("),
            "{content}"
        );
        assert!(
            content.contains("export function validateReadthingResponse200ApplicationVndApiJson("),
            "{content}"
        );
        // The untagged name is gone: with two schemas there is no single one it could mean.
        assert!(
            !content.contains("export function validateReadthingResponse200("),
            "{content}"
        );
    }

    #[test]
    fn parameter_differing_json_entries_tag_distinctly() {
        let (files, diagnostics) =
            compile(two_json_response_document("application/json;stream=watch"));
        assert_clean(&diagnostics);
        let content = operation_validators(&files, "readthing");
        assert!(
            content.contains("export function validateReadthingResponse200ApplicationJson("),
            "{content}"
        );
        assert!(
            content.contains(
                "export function validateReadthingResponse200ApplicationJsonStreamWatch("
            ),
            "{content}"
        );
    }

    #[test]
    fn oasts1400_warns_and_aliases_colliding_media_tags() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json;a-b=1": { "schema": { "type": "object" } },
                                    "application/json;a.b=1": { "schema": { "type": "string" } }
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
                "artifacts": { "types": true, "client": true, "validators": true },
                "client": {
                    "authEnforcement": "types",
                    "baseUrl": { "source": "literal", "value": "https://api.example.test" }
                },
                "validation": {
                    "engine": "generated",
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
            .expect("collision diagnostic");
        assert_eq!(collision.severity, Severity::Warning);
        assert!(collision.message.contains("application/json;a-b=1"));
        assert!(collision.message.contains("application/json;a.b=1"));
        assert!(
            collision
                .message
                .contains("ReadthingResponse200ApplicationJsonAB12"),
            "{}",
            collision.message
        );
        let content = operation_validators(&files, "readthing");
        assert!(
            content.contains("validateReadthingResponse200ApplicationJsonAB1("),
            "{content}"
        );
        assert!(
            content.contains("validateReadthingResponse200ApplicationJsonAB12("),
            "{content}"
        );
        let client = generated(&files, "client/operations/readthing.ts");
        for name in [
            "validateReadthingResponse200ApplicationJsonAB1",
            "validateReadthingResponse200ApplicationJsonAB12",
        ] {
            assert!(
                content.contains(&format!("export function {name}(")),
                "{content}"
            );
            assert!(client.contains(&format!("{name}(result.data")), "{client}");
        }
    }

    #[test]
    fn three_colliding_media_tags_increment_the_alias() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/thing": {
                    "get": {
                        "operationId": "readthing",
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
                .contains("ReadthingResponse200ApplicationJsonAB12")
        }));
        assert!(aliases.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("ReadthingResponse200ApplicationJsonAB13")
        }));
        let content = operation_validators(&files, "readthing");
        for name in [
            "validateReadthingResponse200ApplicationJsonAB1",
            "validateReadthingResponse200ApplicationJsonAB12",
            "validateReadthingResponse200ApplicationJsonAB13",
        ] {
            assert!(
                content.contains(&format!("export function {name}(")),
                "{content}"
            );
        }
    }

    #[test]
    fn response_media_names_use_media_tags_for_multiple_json_entries() {
        let media = ["application/json", "application/vnd.api+json"];
        let names = response_media_names("ReadthingResponse200", &media);
        assert_eq!(names[0].name, "ReadthingResponse200ApplicationJson");
        assert_eq!(names[1].name, "ReadthingResponse200ApplicationVndApiJson");
        let media = ["application/json;stream=watch", "text/*", "*/*"];
        let names = response_media_names("ReadthingResponse200", &media);
        assert_eq!(
            names[0].name,
            "ReadthingResponse200ApplicationJsonStreamWatch"
        );
        assert_eq!(names[1].name, "ReadthingResponse200TextWildcard");
        assert_eq!(names[2].name, "ReadthingResponse200WildcardWildcard");
        // A leading digit and a bare separator run both survive without producing empty tokens.
        let media = ["application/3d-model", "---"];
        let names = response_media_names("ReadthingResponse200", &media);
        assert_eq!(names[0].name, "ReadthingResponse200Application3dModel");
        assert_eq!(names[1].name, "ReadthingResponse200Media");
    }

    #[test]
    fn response_media_names_disambiguate_in_document_order() {
        let media = [
            "application/json;a-b=1",
            "application/json;a.b=1",
            "application/json;a+b=1",
        ];
        let names = response_media_names("ReadthingResponse200", &media);
        assert_eq!(names[0].name, "ReadthingResponse200ApplicationJsonAB1");
        assert_eq!(names[1].name, "ReadthingResponse200ApplicationJsonAB12");
        assert_eq!(names[2].name, "ReadthingResponse200ApplicationJsonAB13");
        assert_eq!(names[1].collision, Some(media[0]));
        assert_eq!(names[2].collision, Some(media[0]));

        // The literal `Tag2` owner makes the later `Tag` collision advance to `Tag3`.
        let media = ["a-a", "a-a2", "a.a"];
        let names = response_media_names("Response", &media);
        assert_eq!(names[0].name, "ResponseAA");
        assert_eq!(names[1].name, "ResponseAA2");
        assert_eq!(names[2].name, "ResponseAA3");
    }

    #[test]
    fn response_media_names_alias_empty_tags() {
        let media = ["---", "..."];
        let names = response_media_names("ReadthingResponse200", &media);
        assert_eq!(names[0].name, "ReadthingResponse200Media");
        assert_eq!(names[1].name, "ReadthingResponse200Media2");
        assert_eq!(names[1].collision, Some(media[0]));
    }

    #[test]
    fn runtime_and_standard_schema_assets_emit_verbatim_without_a_header() {
        let (files, diagnostics) = compile(doc_31(json!({ "Thing": { "type": "string" } })));
        assert_clean(&diagnostics);
        let runtime = files
            .iter()
            .find(|f| f.relative_path == "validators/runtime.ts")
            .expect("runtime.ts");
        // Verbatim kernel: exported ABI helpers present, and no generated header banner.
        assert!(runtime.content.contains("export function isMultipleOf"));
        assert!(runtime.content.contains("export function codePointLength"));
        assert!(!runtime.content.contains("Generated by Oasts"));
        let standard = files
            .iter()
            .find(|f| f.relative_path == "validators/standard-schema.ts")
            .expect("standard-schema.ts");
        assert!(
            standard
                .content
                .contains("export interface SyncStandardSchemaV1")
        );
        assert!(!standard.content.contains("Generated by Oasts"));
    }

    #[test]
    fn primitive_domains_render_each_type_condition_and_message() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Prims": {
                "type": "object",
                "properties": {
                    "s": { "type": "string" },
                    "n": { "type": "number" },
                    "i": { "type": "integer" },
                    "b": { "type": "boolean" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "prims");
        assert!(content.contains("if (typeof value0 === \"string\") {"));
        assert!(content.contains("issues.push(issue(path0, \"expected type string\"));"));
        assert!(content.contains("if (typeof value1 === \"number\" && Number.isFinite(value1)) {"));
        assert!(content.contains("issues.push(issue(path1, \"expected type number\"));"));
        assert!(
            content.contains("if (typeof value2 === \"number\" && Number.isInteger(value2)) {")
        );
        assert!(content.contains("issues.push(issue(path2, \"expected type integer\"));"));
        assert!(content.contains("if (typeof value3 === \"boolean\") {"));
        assert!(content.contains("issues.push(issue(path3, \"expected type boolean\"));"));
    }

    #[test]
    fn non_object_root_reports_object_mismatch_at_root_path() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": { "type": "object", "properties": { "a": { "type": "string" } } }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (isRecord(value)) {"));
        assert!(content.contains("issues.push(issue(path, \"expected type object\"));"));
    }

    #[test]
    fn type_array_null_widens_the_type_message() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "nickname": { "type": ["string", "null"] } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (typeof value0 === \"string\") {"));
        assert!(content.contains("} else if (value0 !== null) {"));
        assert!(content.contains("issues.push(issue(path0, \"expected type string, null\"));"));
    }

    #[test]
    fn oas30_nullable_widens_the_type_message() {
        let (files, diagnostics) = compile(doc_30(json!({
            "Thing": {
                "type": "object",
                "properties": { "nickname": { "type": "string", "nullable": true } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("} else if (value0 !== null) {"));
        assert!(content.contains("issues.push(issue(path0, \"expected type string, null\"));"));
    }

    #[test]
    fn oas30_boolean_exclusive_bounds_use_the_coupled_minimum_and_maximum() {
        let (files, diagnostics) = compile(doc_30(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "v": {
                        "type": "number",
                        "minimum": 5,
                        "exclusiveMinimum": true,
                        "maximum": 10,
                        "exclusiveMaximum": true
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (value0 <= 5) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not greater than exclusiveMinimum 5\"));")
        );
        assert!(content.contains("if (value0 >= 10) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not less than exclusiveMaximum 10\"));")
        );
        // The boolean modifier replaces the inclusive bound; the plain minimum/maximum must not fire.
        assert!(!content.contains("less than minimum"));
        assert!(!content.contains("greater than maximum"));
    }

    #[test]
    fn numeric_31_exclusive_bounds_and_multiple_of_render_the_schema_literal() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "r": { "type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1 },
                    "t": { "type": "number", "multipleOf": 0.1 }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (value0 <= 0) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not greater than exclusiveMinimum 0\"));")
        );
        assert!(content.contains("if (value0 >= 1) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not less than exclusiveMaximum 1\"));")
        );
        assert!(content.contains("if (!isMultipleOf(value1, 0.1)) {"));
        assert!(content.contains("issues.push(issue(path1, \"not a multiple of 0.1\"));"));
    }

    #[test]
    fn numeric_31_inclusive_and_numeric_exclusive_bounds_both_emit() {
        // In 3.1 `minimum`/`exclusiveMinimum` (and the maximum pair) are independent keywords, so a
        // schema carrying both emits the exclusive check alongside the inclusive one in each
        // direction — the exclusive-Number arm still emits the inclusive bound after its own.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "v": {
                        "type": "number",
                        "minimum": 0,
                        "exclusiveMinimum": 2,
                        "maximum": 10,
                        "exclusiveMaximum": 8
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (value0 <= 2) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not greater than exclusiveMinimum 2\"));")
        );
        assert!(content.contains("if (value0 < 0) {"));
        assert!(content.contains("issues.push(issue(path0, \"less than minimum 0\"));"));
        assert!(content.contains("if (value0 >= 8) {"));
        assert!(
            content.contains("issues.push(issue(path0, \"not less than exclusiveMaximum 8\"));")
        );
        assert!(content.contains("if (value0 > 10) {"));
        assert!(content.contains("issues.push(issue(path0, \"greater than maximum 10\"));"));
    }

    #[test]
    fn string_length_and_pattern_constraints_render() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "s": { "type": "string", "minLength": 1, "maxLength": 20, "pattern": "[0-9]" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        // Both length bounds present: the code-point length is scanned once into a local reused by
        // each comparison, never recomputed per bound.
        assert!(content.contains("const length1 = codePointLength(value0);"));
        assert!(content.contains("if (length1 < 1) {"));
        assert!(content.contains("issues.push(issue(path0, \"shorter than minLength 1\"));"));
        assert!(content.contains("if (length1 > 20) {"));
        assert!(content.contains("issues.push(issue(path0, \"longer than maxLength 20\"));"));
        assert_eq!(content.matches("codePointLength(value0)").count(), 1);
        assert!(content.contains("if (!pattern0Regex().test(value0)) {"));
        assert!(content.contains("issues.push(issue(path0, \"does not match pattern\"));"));
    }

    #[test]
    fn a_single_length_bound_stays_inline_without_a_hoisted_local() {
        // A lone bound is computed once already, so hoisting would only add a needless binding.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "s": { "type": "string", "minLength": 1 } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (codePointLength(value0) < 1) {"));
        assert!(!content.contains("const length"));
    }

    #[test]
    fn lazy_regex_cache_is_module_scoped_with_no_top_level_construction() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "s": { "type": "string", "pattern": "^[A-Za-z0-9-]+$" } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("let pattern0: RegExp | undefined;"));
        assert!(content.contains(
            "function pattern0Regex(): RegExp {\n  return (pattern0 ??= new RegExp(\"^[A-Za-z0-9-]+$\"));\n}"
        ));
        // The only `new RegExp` is inside the lazy getter — never at module top level.
        assert_eq!(content.matches("new RegExp").count(), 1);
    }

    #[test]
    fn asserted_formats_call_the_kernel_predicate() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "a": { "type": "string", "format": "date-time" },
                    "b": { "type": "string", "format": "date" },
                    "c": { "type": "string", "format": "time" },
                    "d": { "type": "string", "format": "uuid" },
                    "e": { "type": "string", "format": "email" },
                    "f": { "type": "string", "format": "hostname" },
                    "g": { "type": "string", "format": "ipv4" },
                    "h": { "type": "string", "format": "ipv6" },
                    "i": { "type": "string", "format": "uri" },
                    "j": { "type": "string", "format": "uri-reference" },
                    "k": { "type": "string", "format": "duration" },
                    "l": { "type": "integer", "format": "int32" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (!isDateTime(value0)) {"));
        assert!(content.contains("\"invalid date-time format\""));
        assert!(content.contains("if (!isDate(value1)) {"));
        assert!(content.contains("\"invalid date format\""));
        assert!(content.contains("if (!isTime(value2)) {"));
        assert!(content.contains("\"invalid time format\""));
        assert!(content.contains("if (!isUuid(value3)) {"));
        assert!(content.contains("\"invalid uuid format\""));
        assert!(content.contains("if (!isEmail(value4)) {"));
        assert!(content.contains("\"invalid email format\""));
        assert!(content.contains("if (!isHostname(value5)) {"));
        assert!(content.contains("\"invalid hostname format\""));
        assert!(content.contains("if (!isIpv4(value6)) {"));
        assert!(content.contains("\"invalid ipv4 format\""));
        assert!(content.contains("if (!isIpv6(value7)) {"));
        assert!(content.contains("\"invalid ipv6 format\""));
        assert!(content.contains("if (!isUri(value8)) {"));
        assert!(content.contains("\"invalid uri format\""));
        assert!(content.contains("if (!isUriReference(value9)) {"));
        assert!(content.contains("\"invalid uri-reference format\""));
        assert!(content.contains("if (!isDuration(value10)) {"));
        assert!(content.contains("\"invalid duration format\""));
        assert!(content.contains("if (!isInt32(value11)) {"));
        assert!(content.contains("\"out of int32 range\""));
    }

    #[test]
    fn bigint_int64_validates_each_lossless_wire_representation() {
        let (files, diagnostics) = compile_with_config(
            doc_31(json!({
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
                "artifacts": { "types": true, "client": true, "validators": true },
                "types": { "integer": "bigint" },
                "validation": { "engine": "generated", "request": true, "unchecked": "allow" }
            }),
        );
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(
            content.contains("const integer1 = int64WireValue(value0);"),
            "{content}"
        );
        assert!(
            content.contains(
                "if (integer1 < -9223372036854775808n || integer1 >= 9223372036854775808n) {"
            ),
            "{content}"
        );
        assert!(content.contains("\"out of int64 range\""), "{content}");
        assert!(
            content.contains("if (!isBigIntMultipleOf(integer3, 2)) {"),
            "{content}"
        );
        assert!(
            content.contains("compareBigIntToNumber(integer5, 1) <= 0"),
            "{content}"
        );
        assert!(
            content.contains("compareBigIntToNumber(integer5, 0) < 0"),
            "{content}"
        );
        assert!(
            content.contains("compareBigIntToNumber(integer5, 9) >= 0"),
            "{content}"
        );
        assert!(
            content.contains("compareBigIntToNumber(integer5, 10) > 0"),
            "{content}"
        );
        assert!(!content.contains(" = Number("), "{content}");
        assert!(!content.contains("isInt64(value0)"), "{content}");
    }

    #[test]
    fn annotation_only_formats_assert_nothing_beyond_type() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "e": { "type": "string", "format": "password" },
                    "id": { "type": "integer", "format": "int64" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(!content.contains("isEmail"));
        assert!(!content.contains("format"));
        // The string and the integer still type-check but carry no format assertion.
        assert_eq!(content.matches("=== \"string\"").count(), 1);
        assert!(content.contains("Number.isInteger(value1)"), "{content}");
    }

    #[test]
    fn enum_and_const_use_deep_equality() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["a", "b"] },
                    "species": { "type": "string", "const": "canis" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (!(deepEqual(value0, \"a\") || deepEqual(value0, \"b\"))) {"));
        assert!(content.contains("issues.push(issue(path0, \"value not in enum\"));"));
        assert!(content.contains("if (!deepEqual(value1, \"canis\")) {"));
        assert!(content.contains("issues.push(issue(path1, \"value not equal to const\"));"));
    }

    #[test]
    fn object_enum_emits_deepequal_check() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "kind": { "type": "string" } },
                "enum": [{ "kind": "a" }, { "kind": "b" }]
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        let structural = content
            .find("expected type object")
            .expect("object type check");
        let finite = content
            .find("value not in enum")
            .expect("object enum check");
        assert!(content.contains("deepEqual("));
        assert!(finite > structural);
    }

    #[test]
    fn array_const_emits_deepequal_check() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "array",
                "items": { "type": "integer" },
                "const": [1, 2]
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("deepEqual("));
        assert!(content.contains("value not equal to const"));
    }

    #[test]
    fn tuple_enum_types_unchanged() {
        let (plain_files, plain_diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                "items": false
            }
        })));
        let (finite_files, finite_diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                "items": false,
                "enum": [["a", 1], ["b", 2]]
            }
        })));
        assert_clean(&plain_diagnostics);
        assert_clean(&finite_diagnostics);
        assert_eq!(
            type_component(&plain_files, "thing"),
            type_component(&finite_files, "thing")
        );
        assert!(!component(&plain_files, "thing").contains("value not in enum"));
        assert!(component(&finite_files, "thing").contains("value not in enum"));
    }

    #[test]
    fn open_closed_and_schema_valued_objects_handle_additional_properties() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Open": {
                "type": "object",
                "properties": { "a": { "type": "string" } }
            },
            "Closed": {
                "type": "object",
                "additionalProperties": false,
                "required": ["label"],
                "properties": { "label": { "type": "string" } }
            },
            "Bag": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 3,
                "additionalProperties": { "type": "integer" },
                "properties": { "kind": { "type": "string" } }
            }
        })));
        assert_clean(&diagnostics);
        let open = component(&files, "open");
        assert!(!open.contains("unexpected property"));
        assert!(!open.contains("Object.keys(value)"));
        let closed = component(&files, "closed");
        assert!(closed.contains("for (const key of Object.keys(value)) {"));
        assert!(closed.contains("if (key !== \"label\") {"));
        assert!(
            closed.contains("issues.push(issue(appendKey(path, key), \"unexpected property\"));")
        );
        assert!(closed.contains("issues.push(issue(path, \"missing required property label\"));"));
        let bag = component(&files, "bag");
        // The validation iteration and both property-count bounds share one key list. A second,
        // callback-guarded iteration reports the explicit additionalProperties annotation.
        assert!(bag.contains("const keys1 = Object.keys(value);"));
        assert!(bag.contains("for (const key of keys1) {"));
        assert!(bag.contains("if (key !== \"kind\") {"));
        assert!(bag.contains("const value2: unknown = value[key];"));
        assert!(bag.contains("if (keys1.length < 1) {"));
        assert!(
            bag.contains("issues.push(issue(path, \"fewer properties than minProperties 1\"));")
        );
        assert!(bag.contains("if (keys1.length > 3) {"));
        assert_eq!(bag.matches("Object.keys(value)").count(), 2);
        assert!(bag.contains("if (evaluatedProperty !== undefined) {"));
        assert!(
            bag.contains("issues.push(issue(path, \"more properties than maxProperties 3\"));")
        );
    }

    /// A closed object's unknown-key guard has to name the properties THIS position declares. A
    /// `readOnly` property is absent from the request shape and a `writeOnly` one from the
    /// response shape, so exempting either from the rejection lets the validator accept a key the
    /// emitted type does not declare — the validator wider than the type it checks. The
    /// `declaredProperties` list in the same emitted function was already filtered; this is the
    /// sibling that was not.
    #[test]
    fn a_closed_object_rejects_keys_absent_from_its_own_position() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Widget": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {
                    "id": { "type": "string", "readOnly": true },
                    "secret": { "type": "string", "writeOnly": true },
                    "name": { "type": "string" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let widget = component(&files, "widget");
        // The neutral declaration keeps every declared property, so its guard names all three.
        assert!(
            widget.contains("if (key !== \"id\" && key !== \"secret\" && key !== \"name\") {"),
            "{widget}"
        );
        // The request shape has no `id`, so `id` is an unexpected key there — and the response
        // shape has no `secret`.
        assert!(
            widget.contains("if (key !== \"secret\" && key !== \"name\") {"),
            "{widget}"
        );
        assert!(
            widget.contains("if (key !== \"id\" && key !== \"name\") {"),
            "{widget}"
        );
    }

    #[test]
    fn dependent_required_fires_only_when_the_trigger_is_present() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Account": {
                "type": "object",
                "properties": {
                    "creditCard": { "type": "string" },
                    "billingAddress": { "type": "string" }
                },
                "dependentRequired": { "creditCard": ["billingAddress"] }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "account");
        assert!(content.contains("if (Object.hasOwn(value, \"creditCard\")) {"));
        assert!(content.contains("if (!Object.hasOwn(value, \"billingAddress\")) {"));
        assert!(
            content.contains(
                "issues.push(issue(path, \"missing required property billingAddress\"));"
            )
        );
    }

    #[test]
    fn arrays_validate_items_then_length_and_uniqueness() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "list": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1,
                        "maxItems": 3,
                        "uniqueItems": true
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (isArray(value0)) {"));
        assert!(content.contains("for (let index1 = 0; index1 < value0.length; index1 += 1) {"));
        assert!(content.contains("if (value0.length < 1) {"));
        assert!(content.contains("\"fewer items than minItems 1\""));
        assert!(content.contains("if (value0.length > 3) {"));
        assert!(content.contains("\"more items than maxItems 3\""));
        assert!(content.contains("if (deepEqual(value0[i2], value0[j2])) {"));
        assert!(content.contains("\"items not unique\""));
        assert!(content.contains("issues.push(issue(path0, \"expected type array\"));"));
    }

    #[test]
    fn tuples_validate_prefix_and_rest_schema() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Pair": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                "items": { "type": "boolean" }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "pair");
        assert!(content.contains("if (value.length > 0) {"));
        assert!(content.contains("const value0: unknown = value[0];"));
        assert!(content.contains("if (value.length > 1) {"));
        assert!(content.contains("const value1: unknown = value[1];"));
        assert!(content.contains("for (let index2 = 2; index2 < value.length; index2 += 1) {"));
    }

    #[test]
    fn forbidden_tuple_rest_caps_the_length() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Pair": {
                "type": "array",
                "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                "items": false
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "pair");
        assert!(content.contains("if (value.length > 2) {"));
        assert!(content.contains("issues.push(issue(path, \"more items than maxItems 2\"));"));
    }

    #[test]
    fn self_reference_recurses_without_an_import() {
        let (files, diagnostics) = compile(doc_31(json!({
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
        let content = component(&files, "treenode");
        assert!(content.contains("validateTreeNode(value2, path2, issues);"));
        // A self-reference imports neither its own type nor its own validate function.
        assert!(!content.contains("from \"./treenode"));
    }

    #[test]
    fn mutual_recursion_imports_each_sibling_type_and_validator() {
        let (files, diagnostics) = compile(doc_31(json!({
            "A": {
                "type": "object",
                "properties": { "b": { "$ref": "#/components/schemas/B" } }
            },
            "B": {
                "type": "object",
                "properties": { "a": { "$ref": "#/components/schemas/A" } }
            }
        })));
        assert_clean(&diagnostics);
        let a = component(&files, "a");
        assert!(a.contains("import { type B, validateB } from \"./b.js\";"));
        assert!(a.contains("validateB(value0, path0, issues);"));
        let b = component(&files, "b");
        assert!(b.contains("import { type A, validateA } from \"./a.js\";"));
        assert!(b.contains("validateA(value0, path0, issues);"));
    }

    #[test]
    fn all_of_wrapped_ref_names_the_component_in_both_the_type_and_the_validator_call() {
        // 3.0's quoting idiom: `allOf: [$ref]` beside a `description`, because 3.0 ignores a
        // sibling of `$ref`. The validators artifact always delegated to the component's own
        // validator; the types artifact used to inline the component's body instead, so the
        // two named different things for the same node. Both name `Target` now, which is why
        // the type import and the validator import are one line rather than two.
        let (files, diagnostics) = compile(doc_30(json!({
            "Target": {
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string" } }
            },
            "Wrapper": {
                "type": "object",
                "properties": {
                    "target": {
                        "allOf": [{ "$ref": "#/components/schemas/Target" }],
                        "description": "A described reference in OpenAPI 3.0."
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "wrapper");
        let imports = content
            .lines()
            .filter(|line| line.starts_with("import "))
            .collect::<Vec<_>>();
        assert_eq!(
            imports,
            [
                "import type { SyncStandardSchemaV1 } from \"../standard-schema.js\";",
                "import { type Issue, appendKey, issue } from \"../runtime.js\";",
                "import { type Target, validateTarget } from \"./target.js\";",
            ],
            "{content}"
        );
        assert!(
            content.contains("validateTarget(value0, path0, issues);"),
            "{content}"
        );
        assert!(content.contains("target?: Target;"), "{content}");
    }

    #[test]
    fn all_of_aggregates_each_branch_at_the_same_path() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Combined": {
                "allOf": [
                    { "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } },
                    { "type": "object", "required": ["b"], "properties": { "b": { "type": "integer" } } }
                ]
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "combined");
        assert!(content.contains("\"missing required property a\""));
        assert!(content.contains("\"missing required property b\""));
        let a = content
            .find("missing required property a")
            .expect("branch a");
        let b = content
            .find("missing required property b")
            .expect("branch b");
        assert!(a < b, "allOf branches aggregate in declaration order");
    }

    #[test]
    fn any_of_probes_branches_into_scratch_arrays() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Scalar": {
                "anyOf": [{ "type": "string" }, { "type": "integer" }]
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "scalar");
        assert!(content.contains("let matches0 = 0;"));
        // Annotation collection examines every successful branch, so the guard stays above the
        // maximum possible match count instead of stopping at the first success.
        assert_eq!(content.matches("if (matches0 < 3) {").count(), 2);
        assert!(content.contains("const issues1: Issue[] = [];"));
        assert!(content.contains("if (issues1.length === 0) {"));
        assert!(content.contains("if (matches0 === 0) {"));
        assert!(content.contains("issues.push(issue(path, \"no anyOf branch matched\"));"));
    }

    #[test]
    fn one_of_counts_matches_and_ignores_the_discriminator() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Shape": {
                "oneOf": [
                    { "$ref": "#/components/schemas/Circle" },
                    { "$ref": "#/components/schemas/Square" }
                ],
                "discriminator": { "propertyName": "kind" }
            },
            "Circle": {
                "type": "object",
                "required": ["kind"],
                "properties": { "kind": { "const": "circle" } }
            },
            "Square": {
                "type": "object",
                "required": ["kind"],
                "properties": { "kind": { "const": "square" } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "shape");
        assert!(content.contains("let matches0 = 0;"));
        // Each branch probe is guarded so oneOf stops once a second match makes the verdict fail
        // (matches0 >= 2); the count still ends at exactly 0, 1, or 2, so `!== 1` is unchanged.
        assert_eq!(content.matches("if (matches0 < 2) {").count(), 2);
        assert!(content.contains("if (matches0 !== 1) {"));
        assert!(
            content.contains(
                "issues.push(issue(path, \"expected exactly one oneOf branch to match\"));"
            )
        );
        // The discriminator is never consulted: no property-name routing appears in the validator.
        assert!(!content.contains("kind"));
        assert!(content.contains("validateCircle(value, path, issues1,"));
        assert!(content.contains("validateSquare(value, path, issues2,"));
    }

    #[test]
    fn every_validator_const_is_the_sync_specialization_with_no_escape_hatches() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "a": { "type": "string" },
                    "b": { "type": "array", "items": { "type": "integer" } }
                }
            }
        })));
        assert_clean(&diagnostics);
        for file in files
            .iter()
            .filter(|f| f.relative_path.starts_with("validators/components/"))
        {
            assert!(
                file.content.contains("SyncStandardSchemaV1<"),
                "{} annotates its const with the sync specialization",
                file.relative_path
            );
            // The async base type would erase the sync guarantee and the typed phantom.
            assert!(
                !file.content.contains(": StandardSchemaV1<"),
                "{} must not fall back to the bare StandardSchemaV1",
                file.relative_path
            );
            // No escape hatches in emitted code: no casts and no `any`.
            assert!(
                !file.content.contains(" as "),
                "{} has an `as` cast",
                file.relative_path
            );
            assert!(
                !file.content.contains("any"),
                "{} has an `any`",
                file.relative_path
            );
        }
    }

    #[test]
    fn validator_files_import_only_from_the_standalone_surface() {
        // Includes an operation whose response references a component, so an operation file carries
        // a `../components/` import alongside the component files' `./` sibling imports.
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/a": { "get": { "operationId": "getA", "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/A" } } } } } } }
            },
            "components": {
                "schemas": {
                    "A": { "type": "object", "properties": { "b": { "$ref": "#/components/schemas/B" } } },
                    "B": { "type": "string" }
                }
            }
        }));
        assert_clean(&diagnostics);
        for file in files.iter().filter(|f| {
            f.relative_path.starts_with("validators/components/")
                || f.relative_path.starts_with("validators/operations/")
        }) {
            for line in file.content.lines().filter(|line| line.contains(" from ")) {
                assert!(
                    line.contains("\"../standard-schema")
                        || line.contains("\"../runtime")
                        || line.contains("\"./")
                        || line.contains("\"../components/"),
                    "{} imports outside the standalone surface: {line}",
                    file.relative_path
                );
                assert!(
                    !line.contains("types/") && !line.contains("/runtime/"),
                    "{} imports from the types or client runtime: {line}",
                    file.relative_path
                );
            }
        }
    }

    #[test]
    fn generation_is_deterministic_across_runs() {
        let document = doc_31(json!({
            "Thing": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "tags": { "type": "array", "items": { "type": "string" }, "uniqueItems": true }
                }
            }
        }));
        let (first, _) = compile(document.clone());
        let (second, _) = compile(document);
        assert_eq!(
            component(&first, "thing"),
            component(&second, "thing"),
            "validator emission must be byte-identical across runs"
        );
    }

    #[test]
    fn property_checks_follow_declaration_order() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "id": { "type": "string" }, "name": { "type": "string" } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        let id = content.find("value[\"id\"]").expect("id property");
        let name = content.find("value[\"name\"]").expect("name property");
        assert!(id < name, "properties are checked in declaration order");
    }

    #[test]
    fn bare_required_emits_a_type_conditional_presence_check_but_keeps_unknown_type() {
        let (files, diagnostics) = compile(doc_31(json!({
            "RequiredOnly": { "required": ["value", "description"] }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "requiredonly");
        assert!(content.contains("export type RequiredOnly = unknown;"));
        assert!(content.contains("if (isRecord(value)) {"));
        assert!(content.contains("\"missing required property value\""));
        assert!(content.contains("\"missing required property description\""));
    }

    #[test]
    fn not_emits_only_for_complete_required_enum_and_object_subschemas() {
        let (files, diagnostics) = compile(doc_31(json!({
            "NotRequired": { "not": { "required": ["id"] } },
            "NotEnum": { "not": { "enum": [23456] } },
            "NotObject": {
                "not": {
                    "type": "object",
                    "required": ["type"],
                    "properties": {
                        "type": { "type": "string", "enum": ["blocked"] }
                    }
                }
            }
        })));
        assert_clean(&diagnostics);

        let required = component(&files, "notrequired");
        assert!(required.contains("if (isRecord(value)) {"));
        assert!(required.contains("\"missing required property id\""));
        assert!(required.contains("if (issues0.length === 0) {"));
        assert!(required.contains("\"value matches not schema\""));

        let finite = component(&files, "notenum");
        assert!(finite.contains("deepEqual(value, 23456)"));
        assert!(finite.contains("if (issues0.length === 0) {"));

        let object = component(&files, "notobject");
        assert!(object.contains("if (isRecord(value)) {"));
        assert!(object.contains("\"missing required property type\""));
        assert!(object.contains("if (issues0.length === 0) {"));
    }

    #[test]
    fn not_required_is_supported_in_both_openapi_dialects() {
        for document in [
            doc_30(json!({ "NotRequired": { "not": { "required": ["id"] } } })),
            doc_31(json!({ "NotRequired": { "not": { "required": ["id"] } } })),
        ] {
            let (files, diagnostics) = compile(document);
            assert_clean(&diagnostics);
            let content = component(&files, "notrequired");
            assert!(content.contains("\"missing required property id\""));
            assert!(content.contains("\"value matches not schema\""));
        }
    }

    /// A `not` of a schema that admits everything admits nothing, so the parser lowers it to the
    /// same `Never` node the boolean schema `false` produces, and the negation machinery never
    /// reaches this emitter. What the rejection is spelled as changed; that every value is rejected,
    /// and that the component stays complete, did not.
    #[test]
    fn not_of_an_empty_schema_is_complete_and_rejects_every_value() {
        let (files, diagnostics) = compile(doc_31(json!({
            "RejectAll": { "not": {} }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "rejectall");
        assert!(content.contains("issues.push(issue(path, \"value not allowed\"));"));
        // Unconditional: no branch guards the rejection, so no value reaches an accepting path.
        assert!(!content.contains("if ("));
    }

    #[test]
    fn incomplete_not_is_diagnosed_and_the_negation_is_not_emitted() {
        for inner in [
            json!({ "type": "string", "format": "idn-email" }),
            json!({ "type": "number", "format": "float" }),
            json!({ "type": "integer", "format": "int64" }),
            json!({ "type": "boolean", "format": "custom" }),
            json!({ "type": "string", "$dynamicRef": "#thing" }),
        ] {
            let (files, diagnostics) = compile(doc_31(json!({
                "Incomplete": { "not": inner }
            })));
            let incomplete = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_INCOMPLETE_APPLICATOR)
                .expect("incomplete not has a named diagnostic");
            assert!(incomplete.message.contains("'not'"));
            assert_eq!(
                incomplete.json_pointer.as_deref(),
                Some("/components/schemas/Incomplete/not")
            );
            let content = component(&files, "incomplete");
            assert!(!content.contains("value matches not schema"));
            assert!(!content.contains("const issues0"));
        }
    }

    #[test]
    fn incomplete_not_follows_refs_with_the_real_emitter() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Email": { "type": "string", "format": "idn-email" },
            "Incomplete": {
                "not": { "$ref": "#/components/schemas/Email" }
            }
        })));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_INCOMPLETE_APPLICATOR)
        );
        let content = component(&files, "incomplete");
        assert!(!content.contains("validateEmail"));
        assert!(!content.contains("value matches not schema"));
    }

    #[test]
    fn incomplete_nested_applicator_propagates_to_the_outer_not() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Incomplete": {
                "not": {
                    "propertyNames": { "type": "string", "format": "idn-email" }
                }
            }
        })));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_INCOMPLETE_APPLICATOR)
                .count(),
            1
        );
        assert_eq!(
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_INCOMPLETE_APPLICATOR)
                .and_then(|diagnostic| diagnostic.json_pointer.as_deref()),
            Some("/components/schemas/Incomplete/not")
        );
        let content = component(&files, "incomplete");
        assert!(!content.contains("value matches not schema"));
        assert!(!content.contains("property name does not satisfy"));
    }

    #[test]
    fn property_names_emits_only_for_a_complete_subschema_in_openapi_31() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Named": {
                "propertyNames": { "type": "string", "pattern": "^[a-z]+$" }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "named");
        assert!(content.contains("for (const key of Object.keys(value)) {"));
        assert!(content.contains("pattern0Regex().test(key)"));
        assert!(content.contains("property name does not satisfy propertyNames schema"));

        let (files, diagnostics) = compile(doc_31(json!({
            "Incomplete": {
                "propertyNames": { "type": "string", "format": "idn-email" }
            }
        })));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                    && diagnostic.message.contains("'propertyNames'"))
        );
        let content = component(&files, "incomplete");
        assert!(!content.contains("for (const key of Object.keys(value))"));
        assert!(!content.contains("property name does not satisfy"));
    }

    #[test]
    fn property_names_remains_rejected_in_openapi_30() {
        let (_files, diagnostics) = compile(doc_30(json!({
            "Rejected": { "propertyNames": { "type": "string" } }
        })));
        let rejected = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == CODE_REJECTED_KEYWORD
                    && diagnostic.message.contains("'propertyNames'")
            })
            .expect("OpenAPI 3.0 propertyNames stays rejected");
        assert_eq!(rejected.severity, Severity::Error);
    }

    #[test]
    fn pattern_properties_apply_every_matching_schema_and_exclude_matches_from_additional() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Patterned": {
                "type": "object",
                "properties": {
                    "fixed": { "type": "string" },
                    "x-count": { "type": "integer" }
                },
                "patternProperties": {
                    "^x-": { "type": "integer" },
                    "count$": { "minimum": 2 }
                },
                "additionalProperties": false
            },
            "NegatedPattern": {
                "not": {
                    "patternProperties": {
                        "^x-": { "type": "string" }
                    }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "patterned");
        assert!(content.contains("new RegExp(\"^x-\", \"u\")"));
        assert!(content.contains("new RegExp(\"count$\", \"u\")"));
        assert!(content.contains("const validatePatternedPatternKey"));
        assert!(
            content
                .contains("Matchers: readonly (() => RegExp)[] = [pattern0Regex, pattern1Regex];")
        );
        assert!(
            content.contains(
                "key !== \"fixed\" && key !== \"x-count\" && !validatePatternedPatternKey"
            )
        );
        assert!(content.contains("pattern0Regex().test(key)"));
        assert!(content.contains("pattern1Regex().test(key)"));
        assert!(component(&files, "negatedpattern").contains("value matches not schema"));
    }

    #[test]
    fn contains_counts_all_matches_and_honors_zero_minimum_and_maximum() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Bounded": {
                "type": "array",
                "contains": { "type": "integer" },
                "minContains": 2,
                "maxContains": 3
            },
            "Optional": {
                "type": "array",
                "contains": { "type": "string" },
                "minContains": 0,
                "maxContains": 1
            },
            "DefaultMinimum": {
                "type": "array",
                "contains": { "const": "hit" }
            },
            "BoundsWithoutContains": {
                "type": "array",
                "minContains": 2,
                "maxContains": 3
            }
        })));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "OASTS2201"),
            "{diagnostics:?}"
        );
        let bounded = component(&files, "bounded");
        assert!(bounded.contains("let matches0 = 0;"));
        assert!(bounded.contains("matches0 += 1;"));
        assert!(bounded.contains("if (matches0 < 2) {"));
        assert!(bounded.contains("if (matches0 > 3) {"));
        let optional = component(&files, "optional");
        assert!(!optional.contains("matches0 < 0"));
        assert!(optional.contains("if (matches0 > 1) {"));
        let default_minimum = component(&files, "defaultminimum");
        assert!(default_minimum.contains("if (matches0 < 1) {"));
        assert!(default_minimum.contains("no array item matches contains schema"));
        let standalone_bounds = component(&files, "boundswithoutcontains");
        assert!(!standalone_bounds.contains("matches"));
        assert!(!standalone_bounds.contains("minContains"));
        assert!(!standalone_bounds.contains("maxContains"));
    }

    #[test]
    fn dependent_schemas_validate_the_whole_object_only_when_the_trigger_is_present() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Account": {
                "type": "object",
                "properties": {
                    "creditCard": { "type": "string" },
                    "billingAddress": { "type": "string" }
                },
                "dependentSchemas": {
                    "creditCard": {
                        "required": ["billingAddress"]
                    }
                }
            }
        })));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "OASTS2201"),
            "{diagnostics:?}"
        );
        let content = component(&files, "account");
        assert!(content.contains("if (Object.hasOwn(value, \"creditCard\")) {"));
        assert!(content.contains("if (!Object.hasOwn(value, \"billingAddress\")) {"));
        assert!(
            content.contains(
                "issues.push(issue(path, \"missing required property billingAddress\"));"
            )
        );
    }

    #[test]
    fn conditional_emits_a_private_verdict_and_ignores_branches_without_if() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Conditional": {
                "if": { "required": ["kind"] },
                "then": { "required": ["selectedThen"] },
                "else": { "required": ["selectedElse"] }
            },
            "NoCondition": {
                "then": { "required": ["ignoredThen"] },
                "else": { "required": ["ignoredElse"] }
            },
            "ConditionOnly": {
                "if": { "required": ["probe"] }
            }
        })));
        assert_clean(&diagnostics);

        let conditional = component(&files, "conditional");
        assert!(conditional.contains("const issues0: Issue[] = [];"));
        assert!(conditional.contains("if (issues0.length === 0) {"));
        assert!(conditional.contains("\"missing required property selectedThen\""));
        assert!(conditional.contains("} else {"));
        assert!(conditional.contains("\"missing required property selectedElse\""));
        let no_condition = component(&files, "nocondition");
        assert!(!no_condition.contains("ignoredThen"));
        assert!(!no_condition.contains("ignoredElse"));
        let condition_only = component(&files, "conditiononly");
        assert!(condition_only.contains("const issues0: Issue[] = [];"));
        assert!(!condition_only.contains("issues.push("));
    }

    #[test]
    fn each_incomplete_conditional_subschema_has_its_own_diagnostic() {
        for (keyword, schema) in [
            (
                "if",
                json!({
                    "if": { "type": "string", "format": "idn-email" },
                    "then": false
                }),
            ),
            (
                "then",
                json!({
                    "if": true,
                    "then": { "type": "string", "format": "idn-email" }
                }),
            ),
            (
                "else",
                json!({
                    "if": false,
                    "else": { "type": "string", "format": "idn-email" }
                }),
            ),
        ] {
            let (files, diagnostics) = compile(doc_31(json!({ "Incomplete": schema })));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                        && diagnostic.message.contains(&format!("'{keyword}'"))
                }),
                "{keyword}: {diagnostics:?}"
            );
            let content = component(&files, "incomplete");
            assert!(!content.contains("const issues0"), "{keyword}: {content}");
        }
    }

    #[test]
    fn unevaluated_applicators_collect_sibling_and_nested_annotations() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Choice": {
                "type": "object",
                "anyOf": [
                    {
                        "required": ["alpha"],
                        "properties": { "alpha": { "type": "string" } }
                    },
                    {
                        "required": ["beta"],
                        "properties": { "beta": { "type": "integer" } }
                    }
                ],
                "unevaluatedProperties": false
            },
            "Sequence": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "contains": { "type": "integer" },
                "unevaluatedItems": false
            },
            "Referenced": {
                "$ref": "#/components/schemas/ReferencedProperties",
                "unevaluatedProperties": false
            },
            "ReferencedProperties": {
                "properties": { "fromRef": { "type": "string" } }
            }
        })));
        assert_clean(&diagnostics);

        let choice = component(&files, "choice");
        let collector = choice.find("const evaluatedProperties").expect("collector");
        let any_of = choice.find("let matches").expect("anyOf");
        let unevaluated = choice
            .rfind("evaluatedProperties0.includes(key)")
            .expect("unevaluatedProperties");
        assert!(collector < any_of && any_of < unevaluated, "{choice}");
        assert!(choice.contains("branchPropertiesissues"));
        assert!(choice.contains("recordProperty0?.(key);"));

        let sequence = component(&files, "sequence");
        assert!(sequence.contains("const evaluatedItems0: number[] = [];"));
        assert!(sequence.contains("recordItem0(index);"));
        assert!(sequence.contains("recordItem0?.(index);"));
        assert!(sequence.contains("!evaluatedItems0.includes(index)"));

        let referenced = component(&files, "referenced");
        assert!(referenced.contains(
            "validateReferencedProperties(value, path, issues, recordProperty0, evaluatedItem);"
        ));
        assert!(referenced.contains("!evaluatedProperties0.includes(key)"));
    }

    /// Two bindings a validator module emitted whether or not the schema reached them: the
    /// evaluation-tracking parameters on every validator, and a per-branch recorder for the
    /// evaluation kind the branch never reports. Both are errors in a consumer compiling generated
    /// code under `noUnusedParameters`/`noUnusedLocals`.
    #[test]
    fn unread_evaluation_bindings_are_not_emitted() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Plain": {
                "type": "object",
                "properties": { "a": { "type": "string" } }
            },
            "Scalar": { "type": "string", "minLength": 1 },
            "PropertyChoice": {
                "type": "object",
                "anyOf": [
                    { "required": ["alpha"], "properties": { "alpha": { "type": "string" } } },
                    { "required": ["beta"], "properties": { "beta": { "type": "integer" } } }
                ],
                "unevaluatedProperties": false
            },
            "ItemChoice": {
                "type": "array",
                "anyOf": [
                    { "prefixItems": [{ "type": "string" }] },
                    { "prefixItems": [{ "type": "integer" }, { "type": "integer" }] }
                ],
                "unevaluatedItems": false
            }
        })));
        assert_clean(&diagnostics);

        // A scalar can report neither kind, so both parameters are prefixed.
        let scalar = component(&files, "scalar");
        assert!(
            scalar.contains("_evaluatedProperty?: (key: string) => void"),
            "{scalar}"
        );
        assert!(
            scalar.contains("_evaluatedItem?: (index: number) => void"),
            "{scalar}"
        );

        // An object reports the properties it evaluated to whatever encloses it, so it reads the
        // property parameter and never the item one — the halves move independently.
        let plain = component(&files, "plain");
        assert!(
            plain.contains(", evaluatedProperty?: (key: string) => void"),
            "{plain}"
        );
        assert!(
            plain.contains("_evaluatedItem?: (index: number) => void"),
            "{plain}"
        );

        // An object choice records properties per branch and never items, so only the property
        // recorder is emitted — and the parameter it forwards keeps its plain name.
        let property_choice = component(&files, "propertychoice");
        assert!(
            property_choice.contains("const recordBranchProperty"),
            "{property_choice}"
        );
        assert!(
            !property_choice.contains("const recordBranchItem"),
            "{property_choice}"
        );
        assert!(
            property_choice.contains("evaluatedProperty?: (key: string) => void"),
            "{property_choice}"
        );

        // The array mirror: the item recorder is emitted and the property one is not.
        let item_choice = component(&files, "itemchoice");
        assert!(
            item_choice.contains("const recordBranchItem"),
            "{item_choice}"
        );
        assert!(
            !item_choice.contains("const recordBranchProperty"),
            "{item_choice}"
        );
    }

    #[test]
    fn incomplete_unevaluated_subschemas_are_diagnosed_without_emitting_checks() {
        for (keyword, value) in [
            (
                "unevaluatedProperties",
                json!({ "type": "string", "format": "idn-email" }),
            ),
            (
                "unevaluatedItems",
                json!({ "type": "string", "format": "idn-email" }),
            ),
        ] {
            let (files, diagnostics) = compile(doc_31(json!({
                "Incomplete": { (keyword): value }
            })));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                        && diagnostic.message.contains(keyword)
                }),
                "{keyword}: {diagnostics:?}"
            );
            let content = component(&files, "incomplete");
            assert!(!content.contains(".includes("), "{keyword}: {content}");
        }

        for (keyword, schema) in [
            (
                "unevaluatedProperties",
                json!({
                    "properties": {
                        "known": { "type": "string", "format": "idn-email" }
                    },
                    "unevaluatedProperties": false
                }),
            ),
            (
                "unevaluatedItems",
                json!({
                    "items": { "type": "string", "format": "idn-email" },
                    "unevaluatedItems": false
                }),
            ),
        ] {
            let (files, diagnostics) = compile(doc_31(json!({ "Incomplete": schema })));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                        && diagnostic.message.contains(keyword)
                }),
                "{keyword}: {diagnostics:?}"
            );
            assert!(
                !component(&files, "incomplete").contains(".includes("),
                "{keyword}"
            );
        }
    }

    #[test]
    fn additional_items_is_an_unknown_annotation_in_31_and_rejected_in_30() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Annotated": {
                "type": "string",
                "additionalItems": { "$ref": "#/components/schemas/Missing" }
            }
        })));
        assert_clean(&diagnostics);
        assert!(!component(&files, "annotated").contains("Missing"));

        let (files, diagnostics) = compile(doc_30(json!({
            "Rejected": {
                "type": "string",
                "additionalItems": {}
            }
        })));
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CODE_REJECTED_KEYWORD
                    && diagnostic.message.contains("'additionalItems'")
            }),
            "{diagnostics:?}"
        );
        assert!(type_component(&files, "rejected").contains("export type Rejected = string;"));
    }

    #[test]
    fn new_2020_12_keywords_remain_rejected_in_openapi_30() {
        for (keyword, value) in [
            ("patternProperties", json!({ "^x": {} })),
            ("contains", json!({})),
            ("minContains", json!(0)),
            ("maxContains", json!(1)),
            ("dependentSchemas", json!({ "x": {} })),
            ("propertyNames", json!({})),
            ("const", json!("x")),
            ("prefixItems", json!([{ "type": "string" }])),
            ("dependentRequired", json!({ "a": ["b"] })),
            ("additionalItems", json!(false)),
            ("if", json!({})),
            ("then", json!({})),
            ("else", json!({})),
            ("unevaluatedProperties", json!(false)),
            ("unevaluatedItems", json!(false)),
        ] {
            let (_files, diagnostics) = compile(doc_30(json!({
                "Rejected": { (keyword): value }
            })));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_REJECTED_KEYWORD && diagnostic.message.contains(keyword)
                }),
                "{keyword}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn new_applicator_subschemas_participate_in_not_completeness() {
        for (keyword, value) in [
            (
                "patternProperties",
                json!({ "^x": { "type": "string", "format": "idn-email" } }),
            ),
            (
                "contains",
                json!({ "type": "string", "format": "idn-email" }),
            ),
            (
                "dependentSchemas",
                json!({ "trigger": { "type": "string", "format": "idn-email" } }),
            ),
        ] {
            let (files, diagnostics) = compile(doc_31(json!({
                "Incomplete": {
                    "not": { (keyword): value }
                }
            })));
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CODE_INCOMPLETE_APPLICATOR
                        && diagnostic.message.contains("'not'")
                }),
                "{keyword}: {diagnostics:?}"
            );
            assert!(
                !component(&files, "incomplete").contains("value matches not schema"),
                "{keyword}"
            );
        }
    }

    #[test]
    fn every_rejected_validation_keyword_fails_the_run_naming_keyword_and_pointer() {
        // Under 3.0 the dialect is not JSON Schema, so a dynamic reference is unrepresentable and
        // rejected outright. Under 3.1 it is rejected only where the loader could not pin it —
        // covered by `path_dependent_dynamic_ref_is_rejected_by_validators`.
        for keyword in ["$dynamicRef", "$recursiveRef"] {
            let (_files, diagnostics) = compile(doc_30(json!({
                "Rejected": { (keyword): true }
            })));
            let rejected = diagnostics
                .iter()
                .find(|d| d.code == "OASTS6002" && d.message.contains(keyword))
                .expect("rejected keyword fails with OASTS6002");
            assert_eq!(rejected.severity, Severity::Error);
            assert_eq!(
                rejected.json_pointer.as_deref(),
                Some("/components/schemas/Rejected")
            );
            // Exactly one validators-side diagnostic per rejected keyword: the same parse also
            // degrades the node to an unknown leaf, but OASTS6003 must not double-report it. (The
            // parse-time unsupported-keyword warning is a separate category and still fires.)
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "OASTS6002" || d.code == "OASTS6003")
                    .count(),
                1,
                "rejected keyword '{keyword}' must raise exactly one validators diagnostic",
            );
        }
    }

    #[test]
    fn path_dependent_dynamic_references_warn_and_refuse_validators() {
        for (keyword, schemas, pointer) in [
            (
                "$dynamicRef",
                json!({
                    "First": {
                        "$id": "https://example.invalid/dynamic-first",
                        "$dynamicAnchor": "Node",
                        "type": "object",
                        "properties": {
                            "next": { "$dynamicRef": "#Node" }
                        }
                    },
                    "Second": {
                        "$id": "https://example.invalid/dynamic-second",
                        "$dynamicAnchor": "Node"
                    }
                }),
                "/components/schemas/First/properties/next/$dynamicRef",
            ),
            (
                "$recursiveRef",
                json!({
                    "First": {
                        "$id": "https://example.invalid/recursive-first",
                        "$recursiveAnchor": true,
                        "type": "object",
                        "properties": {
                            "next": { "$recursiveRef": "#" }
                        }
                    },
                    "Second": {
                        "$id": "https://example.invalid/recursive-second",
                        "$recursiveAnchor": true
                    }
                }),
                "/components/schemas/First/properties/next/$recursiveRef",
            ),
        ] {
            let (_files, diagnostics) = compile(doc_31(schemas));
            let warning = diagnostics
                .iter()
                .find(|diagnostic| {
                    diagnostic.code == "OASTS2216"
                        && diagnostic.json_pointer.as_deref() == Some(pointer)
                })
                .expect("path-dependent dynamic reference should warn");
            assert_eq!(warning.severity, Severity::Warning);
            assert!(warning.message.contains("2 schema resources"));

            let rejected = diagnostics
                .iter()
                .find(|diagnostic| {
                    diagnostic.code == CODE_REJECTED_KEYWORD && diagnostic.message.contains(keyword)
                })
                .expect("validators should reject path-dependent resolution");
            assert_eq!(rejected.severity, Severity::Error);
            assert_eq!(
                rejected.json_pointer.as_deref(),
                Some("/components/schemas/First/properties/next")
            );
        }
    }

    #[test]
    fn unknown_leaf_degradation_fails_the_run_naming_the_construct_and_pointer() {
        let (_files, diagnostics) = compile(doc_31(json!({
            "Degraded": { "type": "mystery" }
        })));
        let unknown = diagnostics
            .iter()
            .find(|d| d.code == "OASTS6003")
            .expect("unknown leaf fails with OASTS6003");
        assert_eq!(unknown.severity, Severity::Error);
        assert!(unknown.message.contains("unsupported type mystery"));
        assert_eq!(
            unknown.json_pointer.as_deref(),
            Some("/components/schemas/Degraded")
        );
    }

    #[test]
    fn disabling_validators_emits_no_validators_directory() {
        // The reject walk and validator files exist only when the artifact is enabled; a
        // types-only build of the very same rejected input still generates cleanly.
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        let document = doc_31(json!({ "Rejected": { "not": true } }));
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "types": true }
        });
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write");
        let resolved = load_single(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut InputRecorder::off(), &mut sink).expect("graph");
        let ir = parse(&graph, &mut sink).expect("ir");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            None,
            &mut InputRecorder::off(),
            &mut sink,
        );
        assert!(
            !files
                .iter()
                .any(|f| f.relative_path.starts_with("validators/"))
        );
        assert!(
            !sink.has_errors(),
            "types-only build of rejected input stays clean"
        );
    }

    fn operation(files: &[GeneratedFile], base: &str) -> String {
        files
            .iter()
            .find(|file| file.relative_path == format!("validators/operations/{base}.ts"))
            .expect("operation validator file")
            .content
            .clone()
    }

    fn response_headers_document(headers: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "fetchThing",
                        "responses": {
                            "201": {
                                "description": "created",
                                "headers": headers,
                                "content": {
                                    "application/json": {
                                        "schema": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn response_header_validator_emits_presence_and_schema_checks() {
        let (files, diagnostics) = compile(response_headers_document(json!({
            "X-Token": {
                "required": true,
                "schema": { "type": "string", "minLength": 2 }
            },
            "X-Trace": {
                "schema": { "type": "string", "pattern": "^[a-z]+$" }
            }
        })));
        assert_clean(&diagnostics);
        let content = operation(&files, "fetchthing");
        assert!(content.contains("if (hasGet(value)) {"), "{content}");
        assert!(
            content.contains("const v0 = value.get(\"X-Token\");"),
            "{content}"
        );
        assert!(content.contains("if (v0 === null) {"), "{content}");
        assert!(
            content.contains("missing required header X-Token"),
            "{content}"
        );
        assert!(content.contains("if (v0 !== null) {"), "{content}");
        assert!(
            content.contains("if (codePointLength(v0) < 2) {"),
            "{content}"
        );
        assert!(
            content.contains("const v1 = value.get(\"X-Trace\");"),
            "{content}"
        );
        assert!(content.contains("if (v1 !== null) {"), "{content}");
        assert!(
            content.contains("if (!pattern0Regex().test(v1)) {"),
            "{content}"
        );
        assert!(
            !content.contains("missing required header X-Trace"),
            "{content}"
        );
        assert!(
            content.contains("value is not a Headers object"),
            "{content}"
        );
    }

    #[test]
    fn opaque_content_response_headers_skip_schema_validation() {
        let (files, diagnostics) = compile(response_headers_document(json!({
            "X-Json": {
                "required": true,
                "content": { "application/json": { "schema": { "type": "string", "minLength": 3 } } }
            },
            "X-Opaque-Req": {
                "required": true,
                "content": { "application/xml": { "schema": { "type": "string" } } }
            },
            "X-Opaque-Opt": {
                "content": { "application/xml": { "schema": { "type": "string" } } }
            }
        })));
        assert_clean(&diagnostics);
        let content = operation(&files, "fetchthing");
        // A JSON-family content header parses the wire JSON before schema validation, then validates
        // the decoded value — never the raw wire string, which an object/number schema can't match.
        assert!(
            content.contains("const v0 = value.get(\"X-Json\");"),
            "{content}"
        );
        assert!(content.contains("appendKey(path, \"X-Json\")"), "{content}");
        assert!(
            content.contains("const d0: unknown = JSON.parse(v0);"),
            "{content}"
        );
        assert!(
            content.contains("if (codePointLength(d0) < 3) {"),
            "{content}"
        );
        assert!(
            content.contains("issues.push(issue(path0, \"value is not valid JSON\"));"),
            "{content}"
        );
        // An opaque required content header keeps only its presence check — no schema check that
        // would reject the raw wire string.
        assert!(
            content.contains("const v1 = value.get(\"X-Opaque-Req\");"),
            "{content}"
        );
        assert!(
            content.contains("missing required header X-Opaque-Req"),
            "{content}"
        );
        assert!(!content.contains("if (v1 !== null) {"), "{content}");
        assert!(
            !content.contains("appendKey(path, \"X-Opaque-Req\")"),
            "{content}"
        );
        // An opaque optional content header needs no check at all, so the validator body binds no
        // value for it (the header still appears as a `string` in the interface declaration).
        assert!(
            !content.contains("value.get(\"X-Opaque-Opt\")"),
            "{content}"
        );
    }

    #[test]
    fn response_header_validator_position_name_matches_types_interface() {
        let (files, diagnostics) = compile(response_headers_document(json!({
            "X-Token": { "schema": { "type": "string" } }
        })));
        assert_clean(&diagnostics);
        let validators = operation(&files, "fetchthing");
        let types = files
            .iter()
            .find(|file| file.relative_path == "types/operations/fetchthing.ts")
            .expect("operation types file")
            .content
            .as_str();
        let position = "FetchThingResponse201Headers";
        assert!(
            types.contains(&format!("export interface {position} {{")),
            "{types}"
        );
        assert!(
            validators.contains(&format!("export interface {position} {{")),
            "{validators}"
        );
        assert!(
            validators.contains("export const fetchThingResponse201HeadersValidator"),
            "{validators}"
        );
    }

    #[test]
    fn multiple_headered_responses_emit_sorted_positions() {
        let (files, diagnostics) = compile(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "fetchThing",
                        "responses": {
                            "404": {
                                "description": "missing",
                                "headers": {
                                    "X-Reason": { "schema": { "type": "string" } }
                                }
                            },
                            "201": {
                                "description": "created",
                                "headers": {
                                    "X-Token": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        }));
        assert_clean(&diagnostics);
        let validators = operation(&files, "fetchthing");
        let first = validators
            .find("fetchThingResponse201HeadersValidator")
            .expect("201 headers validator");
        let second = validators
            .find("fetchThingResponse404HeadersValidator")
            .expect("404 headers validator");
        assert!(first < second, "{validators}");
    }

    #[test]
    fn non_string_header_schema_still_emits_with_wire_string_semantics() {
        let (files, diagnostics) = compile(response_headers_document(json!({
            "X-Count": { "schema": { "type": "integer", "minimum": 1 } }
        })));
        assert_clean(&diagnostics);
        let content = operation(&files, "fetchthing");
        assert!(
            content.contains("const v0 = value.get(\"X-Count\");"),
            "{content}"
        );
        assert!(
            content.contains("if (typeof v0 === \"number\" && Number.isInteger(v0)) {"),
            "{content}"
        );
        assert!(content.contains("if (v0 < 1) {"), "{content}");
    }

    #[test]
    fn headerless_document_validators_unchanged() {
        let document = response_headers_document(json!({}));
        let (first_files, first_diagnostics) = compile(document.clone());
        let (second_files, second_diagnostics) = compile(document);
        assert_clean(&first_diagnostics);
        assert_clean(&second_diagnostics);
        let first = operation(&first_files, "fetchthing");
        let second = operation(&second_files, "fetchthing");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert!(!first.contains("hasGet"), "{first}");
        assert!(!first.contains("HeadersValidator"), "{first}");
    }

    /// When the operation-derived name already is the component's positioned export, the component
    /// triplet remains available from the operation module without a meaningless local wrapper.
    #[test]
    fn identical_operation_delegate_is_reexported() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/assist": {
                    "post": {
                        "operationId": "assistV1Process",
                        "parameters": [{
                            "name": "mode",
                            "in": "query",
                            "schema": {
                                "$ref": "#/components/schemas/AssistV1ProcessQueryMode"
                            }
                        }],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/AssistV1ProcessRequestBody"
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "processed",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/AssistV1ProcessResponse200"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "AssistV1ProcessQueryMode": {
                        "type": "string"
                    },
                    "AssistV1ProcessRequestBody": {
                        "type": "object",
                        "required": ["prompt"],
                        "properties": {
                            "prompt": { "type": "string" }
                        }
                    },
                    "AssistV1ProcessResponse200": {
                        "type": "object",
                        "required": ["accepted"],
                        "properties": {
                            "accepted": { "type": "boolean" }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation(&files, "assistv1process");
        assert!(content.contains(
            "export { type AssistV1ProcessQueryMode, assistV1ProcessQueryModeValidator, validateAssistV1ProcessQueryMode } from \"../components/assistv1processquerymode.js\";"
        ));
        assert!(content.contains(
            "export { type AssistV1ProcessRequestBody, assistV1ProcessRequestBodyValidator, validateAssistV1ProcessRequestBody } from \"../components/assistv1processrequestbody.js\";"
        ));
        assert!(content.contains(
            "export { type AssistV1ProcessResponse200, assistV1ProcessResponse200Validator, validateAssistV1ProcessResponse200 } from \"../components/assistv1processresponse200.js\";"
        ));
        assert!(
            !content
                .contains("export type AssistV1ProcessRequestBody = AssistV1ProcessRequestBody;"),
            "{content}"
        );
        assert!(
            !content.contains("export function validateAssistV1ProcessRequestBody("),
            "{content}"
        );
        assert!(!content.contains("../standard-schema.js"), "{content}");
        assert!(!content.contains("../runtime.js"), "{content}");
    }

    /// A `$ref` from a request body must delegate to the referent's Request-variant validator, not
    /// the Neutral one, which would demand a `readOnly` property the request type dropped.
    /// Symmetrically, a `$ref` from a response delegates to the Response variant.
    #[test]
    fn request_body_ref_calls_request_validator() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Pet" }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Pet" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Pet": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": { "type": "string", "readOnly": true },
                            "secret": { "type": "string", "writeOnly": true }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation(&files, "createpet");
        // Request body position delegates to the Request variant; response to the Response variant.
        assert!(
            content.contains(
                "validatePetRequest(value, path, issues, evaluatedProperty, evaluatedItem);"
            ),
            "{content}"
        );
        assert!(
            content.contains(
                "validatePetResponse(value, path, issues, evaluatedProperty, evaluatedItem);"
            ),
            "{content}"
        );
        assert!(
            content.contains("export type CreatePetRequestBody = PetRequest;"),
            "{content}"
        );
        assert!(
            content.contains("export function validateCreatePetRequestBody("),
            "{content}"
        );
        assert!(
            content.contains("export type CreatePetResponse200 = PetResponse;"),
            "{content}"
        );
        assert!(
            content.contains("export function validateCreatePetResponse200("),
            "{content}"
        );
        // The Neutral validator is never called from a positioned body.
        assert!(
            !content.contains("validatePet(value, path, issues);"),
            "{content}"
        );
    }

    /// The value import must name the same position variant the body calls: the request body calls
    /// `validatePetRequest`, so it must be imported. The type name was already position-aware. The
    /// component (writeOnly-free) has no Response variant, so nothing Response-shaped is imported —
    /// importing a name the component file does not export would be a TS2305 cross-file error.
    #[test]
    fn operation_imports_request_variant() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Pet" }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Pet" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Pet": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": { "type": "string", "readOnly": true },
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation(&files, "createpet");
        let import_line = content
            .lines()
            .find(|line| line.contains("components/pet"))
            .expect("Pet component import line");
        // Both the Neutral type (response position, which does not differ) and the Request variant.
        assert!(import_line.contains("type Pet,"), "{import_line}");
        assert!(import_line.contains("type PetRequest"), "{import_line}");
        // The value import names the Request variant the request body calls.
        assert!(import_line.contains("validatePetRequest"), "{import_line}");
        // No Response variant exists on this component, so none is imported.
        assert!(!import_line.contains("Response"), "{import_line}");
    }

    #[test]
    fn operations_emit_per_parameter_body_and_response_validators() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/things/{id}": {
                    "get": {
                        "operationId": "getThing",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                            { "name": "a-b", "in": "query", "schema": { "type": "string" } },
                            { "name": "a.b", "in": "query", "schema": { "type": "string" } },
                            { "name": "X-Trace", "in": "header", "schema": { "type": "string" } },
                            { "name": "sid", "in": "cookie", "schema": { "type": "string" } },
                            { "name": "---", "in": "query", "schema": { "type": "string" } }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "w": { "type": "string", "readOnly": true },
                                            "v": { "type": "integer" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object", "properties": { "ok": { "type": "boolean" } } } } } },
                            "4XX": { "description": "err", "content": { "application/json": { "schema": { "type": "string" } } } },
                            "default": { "description": "def", "content": { "application/json": { "schema": { "type": "integer" } } } }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation(&files, "getthing");
        // One validator per parameter, keyed by capitalized location + Pascal-cased name.
        assert!(content.contains(
            "export const getThingPathIdValidator: SyncStandardSchemaV1<GetThingPathId>"
        ));
        assert!(content.contains(
            "export const getThingHeaderXTraceValidator: SyncStandardSchemaV1<GetThingHeaderXTrace>"
        ));
        assert!(content.contains(
            "export const getThingCookieSidValidator: SyncStandardSchemaV1<GetThingCookieSid>"
        ));
        // Two query names that Pascal-collapse to the same identifier are disambiguated by index.
        assert!(content.contains("export type GetThingQueryAB = string;"));
        assert!(content.contains("export type GetThingQueryAB2 = string;"));
        // A parameter name that has no identifier form falls back to its positional index.
        assert!(content.contains("export type GetThingQueryParam5 = string;"));
        // Request body validator; the readOnly property is excluded in the request wire position.
        assert!(content.contains(
            "export const getThingRequestBodyValidator: SyncStandardSchemaV1<GetThingRequestBody>"
        ));
        assert!(!content.contains("Object.hasOwn(value, \"w\")"));
        assert!(content.contains("Object.hasOwn(value, \"v\")"));
        // Response branch validators, including the range and default branches.
        assert!(content.contains("export const getThingResponse200Validator"));
        assert!(content.contains("export const getThingResponse4XXValidator"));
        assert!(content.contains("export const getThingResponseDefaultValidator"));
        assert!(content.contains("from \"../standard-schema.js\""));
        assert!(content.contains("from \"../runtime.js\""));
    }

    #[test]
    fn webhook_request_validators_emit_body_and_parameter_checks() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "pet.created": {
                    "post": {
                        "parameters": [{
                            "name": "X-Signature",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string", "minLength": 8 }
                        }],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["id"],
                                        "properties": { "id": { "type": "string" } }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "subscriber response",
                                "content": {
                                    "application/json": { "schema": { "type": "boolean" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = files
            .iter()
            .find(|file| file.relative_path == "validators/webhooks/petcreatedpost.ts")
            .expect("webhook validator file")
            .content
            .as_str();
        assert!(content.contains("export const petCreatedPostHeaderXSignatureValidator"));
        assert!(content.contains("shorter than minLength 8"));
        assert!(content.contains("export const petCreatedPostRequestBodyValidator"));
        assert!(content.contains("missing required property id"));
        assert!(!content.contains("Response200Validator"), "{content}");
    }

    #[test]
    fn callback_request_validators_emit() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "operationId": "subscribe",
                        "responses": { "202": { "description": "accepted" } },
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
                                        "responses": { "204": { "description": "ok" } },
                                        "callbacks": {
                                            "onAck": {
                                                "{$request.body#/ackUrl}": {
                                                    "put": {
                                                        "parameters": [{
                                                            "name": "token",
                                                            "in": "query",
                                                            "schema": { "type": "string" }
                                                        }],
                                                        "responses": { "204": { "description": "ok" } }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        assert!(files.iter().any(|file| {
            file.relative_path == "validators/callbacks/subscribeondatapost.ts"
                && file
                    .content
                    .contains("subscribeOnDataPostRequestBodyValidator")
        }));
        assert!(files.iter().any(|file| {
            file.relative_path == "validators/callbacks/subscribeondatapostonackput.ts"
                && file
                    .content
                    .contains("subscribeOnDataPostOnAckPutQueryTokenValidator")
        }));
    }

    #[test]
    fn webhook_validators_descriptor_maps_names_to_consts() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "operationId": "subscribe",
                        "responses": { "202": { "description": "accepted" } },
                        "callbacks": {
                            "onData": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": { "schema": { "type": "string" } }
                                            }
                                        },
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                },
                                "{$request.query.fallback}": {
                                    "get": { "responses": { "204": { "description": "ok" } } }
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
                },
                "responseOnly": {
                    "get": { "responses": { "204": { "description": "ok" } } }
                },
                "emptyHook": {}
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let webhooks = files
            .iter()
            .find(|file| file.relative_path == "validators/webhooks/index.ts")
            .expect("webhooks descriptor")
            .content
            .as_str();
        assert!(webhooks.contains("\"pet.created\": {\n"), "{webhooks}");
        assert!(webhooks.contains("post: {\n"), "{webhooks}");
        assert!(
            webhooks.contains("requestBody: petCreatedPostRequestBodyValidator"),
            "{webhooks}"
        );
        assert!(webhooks.contains("\"responseOnly\": {},\n"), "{webhooks}");
        assert!(webhooks.contains("\"emptyHook\": {},\n"), "{webhooks}");
        let callbacks = files
            .iter()
            .find(|file| file.relative_path == "validators/callbacks/index.ts")
            .expect("callbacks descriptor")
            .content
            .as_str();
        assert!(
            callbacks.contains("\"{$request.body#/url}\": {\n"),
            "{callbacks}"
        );
        for line in callbacks.lines().filter(|line| line.contains("$request")) {
            assert!(line.trim_start().starts_with('"'), "{line}");
        }
        assert!(
            callbacks.contains("requestBody: subscribeOnData_1PostRequestBodyValidator"),
            "{callbacks}"
        );
    }

    #[test]
    fn webhook_and_callback_validators_skip_unfileable_names() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
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
                                        "operationId": "AUX",
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": { "type": "boolean" }
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
            }
        });
        let (files, diagnostics) = compile(document);
        assert!(!diagnostics.is_empty());
        assert!(!files.iter().any(|file| {
            file.relative_path == "validators/webhooks/con.ts"
                || file.relative_path == "validators/callbacks/aux.ts"
        }));
        let webhooks = files
            .iter()
            .find(|file| file.relative_path == "validators/webhooks/index.ts")
            .expect("webhooks descriptor")
            .content
            .as_str();
        assert!(webhooks.contains("\"events\": {},\n"), "{webhooks}");
    }

    #[test]
    fn webhookless_document_validator_files_unchanged() {
        let document = doc_31(json!({
            "Pet": { "type": "object", "properties": { "id": { "type": "string" } } }
        }));
        let (first, first_diagnostics) = compile(document.clone());
        let (second, second_diagnostics) = compile(document);
        assert_clean(&first_diagnostics);
        assert_clean(&second_diagnostics);
        let first = first
            .iter()
            .filter(|file| file.relative_path.starts_with("validators/"))
            .map(|file| (&file.relative_path, file.content.as_bytes()))
            .collect::<Vec<_>>();
        let second = second
            .iter()
            .filter(|file| file.relative_path.starts_with("validators/"))
            .map(|file| (&file.relative_path, file.content.as_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(first, second);
        assert!(!first.iter().any(|(path, _)| {
            path.starts_with("validators/webhooks/") || path.starts_with("validators/callbacks/")
        }));
    }

    #[test]
    fn operation_with_no_json_positions_emits_no_file() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/ping": {
                    "get": {
                        "operationId": "ping",
                        "responses": { "204": { "description": "no content" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        assert!(
            !files
                .iter()
                .any(|f| f.relative_path.starts_with("validators/operations/")),
            "an operation with nothing to validate emits no file"
        );
    }

    #[test]
    fn null_type_renders_the_null_domain() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "n": { "type": "null" } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (value0 === null) {"));
        assert!(content.contains("issues.push(issue(path0, \"expected type null\"));"));
    }

    #[test]
    fn empty_enum_membership_is_unconditional() {
        // The parser rejects empty enums, so this defensive branch is exercised directly: an empty
        // allowed set admits nothing, so the membership check must be unconditionally true.
        let temp = TempDir::new().expect("temp directory");
        fs::write(temp.path().join("openapi.json"), "{}").expect("write input");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "validators": true }
        });
        fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved =
            load_single(Some(&temp.path().join("oasts.json")), temp.path()).expect("config");
        let analyzed = crate::semantic::Analyzed {
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
        let mut scope = FileScope::default();
        let mut imports = SiblingImports::default();
        let mut body = FnBody::new(
            &mut scope,
            &mut imports,
            &model,
            TypePosition::Neutral,
            "Finite",
            "workspace/openapi.json#/finite".to_owned(),
        );
        body.gen_finite(Some(&[]), None, "value", "path", "issues");
        assert!(body.out.contains("if (true) {"));
        assert!(
            body.out
                .contains("issues.push(issue(path, \"value not in enum\"));")
        );
    }

    #[test]
    fn unresolved_ref_marks_the_emission_incomplete() {
        let temp = TempDir::new().expect("temp directory");
        fs::write(temp.path().join("openapi.json"), "{}").expect("write input");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "validators": true }
        });
        fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved =
            load_single(Some(&temp.path().join("oasts.json")), temp.path()).expect("config");
        let analyzed = crate::semantic::Analyzed {
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
        let mut scope = FileScope::default();
        let mut imports = SiblingImports::default();
        let mut body = FnBody::new(
            &mut scope,
            &mut imports,
            &model,
            TypePosition::Neutral,
            "Ref",
            "workspace/openapi.json#/ref".to_owned(),
        );
        let schema = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "missing.json".to_owned(),
                json_pointer: "/Missing".to_owned(),
            },
            meta: SchemaMeta::default(),
        };

        assert!(!body.gen_root_schema(&schema, "value", "path", "issues"));
        assert!(body.out.is_empty());
    }

    #[test]
    fn plain_bounds_render() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "age": { "type": "integer", "minimum": 0, "maximum": 200 }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (value0 < 0) {"));
        assert!(content.contains("issues.push(issue(path0, \"less than minimum 0\"));"));
        assert!(content.contains("if (value0 > 200) {"));
        assert!(content.contains("issues.push(issue(path0, \"greater than maximum 200\"));"));
    }

    #[test]
    fn nullable_object_and_array_widen_the_container_message() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Obj": { "type": ["object", "null"], "properties": { "a": { "type": "string" } } },
            "Arr": { "type": ["array", "null"], "items": { "type": "string" } }
        })));
        assert_clean(&diagnostics);
        assert!(component(&files, "obj").contains("} else if (value !== null) {"));
        assert!(component(&files, "obj").contains("\"expected type object, null\""));
        assert!(component(&files, "arr").contains("} else if (value !== null) {"));
        assert!(component(&files, "arr").contains("\"expected type array, null\""));
    }

    #[test]
    fn closed_empty_object_and_allowed_tuple_rest_render() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Empty": { "type": "object", "additionalProperties": false },
            "OpenTuple": { "type": "array", "prefixItems": [{ "type": "string" }], "items": true }
        })));
        assert_clean(&diagnostics);
        // A closed object with no declared properties rejects every key.
        let empty = component(&files, "empty");
        assert!(empty.contains("for (const key of Object.keys(value)) {"));
        assert!(empty.contains("if (true) {"));
        assert!(empty.contains("\"unexpected property\""));
        // A tuple whose rest is unconstrained validates only the prefix positions.
        let open = component(&files, "opentuple");
        assert!(open.contains("if (value.length > 0) {"));
        assert!(!open.contains("more items than maxItems"));
    }

    #[test]
    fn a_non_error_warning_does_not_fail_a_clean_validators_build() {
        // A discriminator with a branch that proves no per-branch literal (a bare primitive carries
        // no discriminator property) emits a structural-union warning, not an error, so a validators
        // build over the same input is still clean.
        let (files, diagnostics) = compile(doc_31(json!({
            "Shape": {
                "oneOf": [
                    { "$ref": "#/components/schemas/A" },
                    { "type": "string" }
                ],
                "discriminator": { "propertyName": "kind" }
            },
            "A": { "type": "object", "properties": { "kind": { "type": "string" } } }
        })));
        assert!(
            diagnostics.iter().any(|d| d.severity == Severity::Warning),
            "the ambiguous discriminator should warn: {diagnostics:#?}"
        );
        assert_clean(&diagnostics);
        assert!(!component(&files, "shape").is_empty());
    }

    #[test]
    fn a_repeated_pattern_shares_one_lazy_cache_slot() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "a": { "type": "string", "pattern": "[0-9]" },
                    "b": { "type": "string", "pattern": "[0-9]" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        // Equal patterns deduplicate to a single module-scope cache slot used by both checks.
        assert_eq!(content.matches("let pattern0: RegExp").count(), 1);
        assert!(!content.contains("pattern1"));
        assert_eq!(content.matches("pattern0Regex().test(").count(), 2);
    }

    #[test]
    fn components_and_operations_with_unfileable_names_are_skipped() {
        // A Windows reserved device name cannot become a safe file base, so the artifact skips the
        // component/operation (the invalid-file-name diagnostic still fails the run).
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/x": { "get": { "operationId": "aux", "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "string" } } } } } } }
            },
            "components": { "schemas": { "CON": { "type": "string" } } }
        });
        let (files, diagnostics) = compile(document);
        assert!(
            !files
                .iter()
                .any(|f| f.relative_path.starts_with("validators/components/con")),
            "a reserved component name allocates no validator file"
        );
        assert!(
            !files
                .iter()
                .any(|f| f.relative_path.starts_with("validators/operations/aux")),
            "a reserved operation name allocates no validator file"
        );
        // Skipping is not silent: the reserved component (`CON`) and operation (`aux`) each fail the
        // run with the invalid-file-name diagnostic, so the writer never commits partial output.
        let file_name_errors: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == crate::emit::CODE_FILE_NAME)
            .collect();
        assert_eq!(file_name_errors.len(), 2);
        assert!(
            file_name_errors
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Error)
        );
    }

    #[test]
    fn import_extension_none_drops_the_suffix() {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        let document = doc_31(json!({
            "A": { "type": "object", "properties": { "b": { "$ref": "#/components/schemas/B" } } },
            "B": { "type": "string" }
        }));
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "types": true, "validators": true },
            "emit": { "importExtension": "none" }
        });
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write");
        let resolved = load_single(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut InputRecorder::off(), &mut sink).expect("graph");
        let ir = parse(&graph, &mut sink).expect("ir");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            None,
            &mut InputRecorder::off(),
            &mut sink,
        );
        assert_clean(&sink.into_sorted_vec());
        let a = component(&files, "a");
        assert!(a.contains("from \"../standard-schema\";"));
        assert!(a.contains("from \"../runtime\";"));
        assert!(a.contains("from \"./b\";"));
    }

    #[test]
    fn property_presence_uses_own_property_not_prototype_walk() {
        // Fix A: `in` walks the prototype chain, so inherited names (`toString`, `constructor`)
        // read as present. All three presence sites — property presence, dependentRequired trigger,
        // dependentRequired dependent — must use Object.hasOwn instead.
        let (files, diagnostics) = compile(doc_31(json!({
            "Account": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" },
                    "creditCard": { "type": "string" },
                    "billingAddress": { "type": "string" }
                },
                "dependentRequired": { "creditCard": ["billingAddress"] }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "account");
        // (1) property-presence site
        assert!(content.contains("if (Object.hasOwn(value, \"id\")) {"));
        // (2) dependentRequired trigger site
        assert!(content.contains("if (Object.hasOwn(value, \"creditCard\")) {"));
        // (3) dependentRequired dependent site
        assert!(content.contains("if (!Object.hasOwn(value, \"billingAddress\")) {"));
        // No prototype-walking `in` anywhere.
        assert!(!content.contains(" in value"));
    }

    #[test]
    fn proto_object_const_uses_computed_key_not_a_prototype_setter() {
        // Fix B: a literal `__proto__` key in an object literal sets the prototype; the comparison
        // object must instead carry an own `__proto__` data property via computed-key syntax.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "p": { "const": { "__proto__": { "a": 1 }, "b": 2 } }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        // Executable position (deepEqual argument): the reserved key uses computed-key syntax so it
        // creates an own data property; the plain sibling key stays a normal key.
        assert!(content.contains("if (!deepEqual(value0, {[\"__proto__\"]:{\"a\":1},\"b\":2})) {"));
        // Type position stays byte-identical: a `__proto__` property type is not a prototype setter,
        // so the shared renderer's plain-key literal is left untouched.
        assert!(content.contains("p?: {\"__proto__\":{\"a\":1},\"b\":2};"));
    }

    #[test]
    fn nested_proto_key_uses_computed_key_at_every_depth() {
        // Fix B: the rewrite reaches every nesting level, including inside arrays.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "p": { "const": { "outer": [{ "__proto__": { "x": 1 } }] } }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        // Computed-key rewrite reaches a `__proto__` nested inside an array element (executable
        // position); the type position keeps the plain-key literal.
        assert!(
            content
                .contains("if (!deepEqual(value0, {\"outer\":[{[\"__proto__\"]:{\"x\":1}}]})) {")
        );
        assert!(content.contains("p?: {\"outer\":[{\"__proto__\":{\"x\":1}}]};"));
    }

    #[test]
    fn component_named_after_an_injected_identifier_is_renamed() {
        // Fix C: a component named `Issue` would emit `export interface Issue` alongside the
        // always-present `import { type Issue }` (TS2440). Its export is renamed to the lowest free
        // numeric suffix; the kernel import keeps its name. A sibling component literally named
        // `Issue2` is already taken, so the rename skips it and lands on `Issue3`. A component named
        // `deepEqual` (Pascal-cased to `DeepEqual`) does not collide case-sensitively with the value
        // import `deepEqual`, so it is left unchanged.
        let (files, diagnostics) = compile(doc_31(json!({
            "Issue": {
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string" } }
            },
            "Issue2": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            },
            "deepEqual": {
                "type": "string",
                "enum": ["x", "y"]
            }
        })));
        assert_clean(&diagnostics);
        let issue = component(&files, "issue");
        // The kernel type import is present and keeps its name.
        assert!(issue.contains("import { type Issue,"));
        // The bump loop skips the taken `Issue2`; export, self trio, and const use `Issue3`.
        assert!(issue.contains("export interface Issue3 {"));
        assert!(issue.contains("export function validateIssue3("));
        assert!(issue.contains("checkedIssue3("));
        assert!(issue.contains("export const issue3Validator:"));
        // No bare `Issue` export shadows the import, and it did not reuse the taken `Issue2`.
        assert!(!issue.contains("export interface Issue {"));
        assert!(!issue.contains("export interface Issue2 {"));
        // The unrelated `Issue2` component keeps its own name (not a reserved identifier).
        let issue2 = component(&files, "issue2");
        assert!(issue2.contains("export interface Issue2 {"));
        // The `deepEqual` component collides only in casing, so it is not renamed: import name
        // (`deepEqual`, value) and export name (`DeepEqual`, type) differ and coexist.
        let dq = component(&files, "deepequal");
        assert!(dq.contains("export type DeepEqual ="));
        assert!(!dq.contains("DeepEqual2"));
    }

    #[test]
    fn never_schema_rejects_every_value() {
        // Fix D: a `false` schema (SchemaNode::Never) previously emitted an empty body, accepting
        // everything. It must reject unconditionally.
        let (files, diagnostics) = compile(doc_31(json!({ "Nope": false })));
        assert_clean(&diagnostics);
        let content = component(&files, "nope");
        assert!(content.contains("issues.push(issue(path, \"value not allowed\"));"));
        // The empty-body acceptance must be gone: the push is unconditional (no `if (` guarding it).
        assert!(!content.contains("if (true) {"));
    }

    #[test]
    fn uninhabitable_all_of_rejects_every_value() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Nope": {
                "allOf": [
                    { "type": "string" },
                    { "type": "boolean" }
                ]
            }
        })));
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.code == crate::composition::CODE_COMPOSITION
                    && diagnostic.severity == Severity::Warning
            }),
            "{diagnostics:?}"
        );
        assert!(!diagnostics.iter().any(|diagnostic| {
            diagnostic.code == crate::composition::CODE_COMPOSITION
                && diagnostic.severity == Severity::Error
        }));
        let content = component(&files, "nope");
        assert!(content.contains("export type Nope = never;"));
        assert!(content.contains("issues.push(issue(path, \"value not allowed\"));"));
    }

    #[test]
    fn filtered_finite_values_drive_generated_validators() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Survivor": {
                "type": "string",
                "enum": ["on", false]
            },
            "Exhausted": {
                "type": "boolean",
                "enum": [1]
            },
            "ImpossibleConst": {
                "type": "string",
                "const": false
            },
            "ObjectChoice": {
                "type": "object",
                "enum": [{ "value": 1 }, false]
            },
            "ArrayChoice": {
                "type": "array",
                "items": { "type": "integer" },
                "enum": [[1], "wrong"]
            }
        })));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS3101")
                .count(),
            6
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );

        let survivor = component(&files, "survivor");
        assert!(survivor.contains("if (!(deepEqual(value, \"on\"))) {"));
        assert!(!survivor.contains("deepEqual(value, false)"));
        for base in ["exhausted", "impossibleconst"] {
            let content = component(&files, base);
            assert!(content.contains("issues.push(issue(path, \"value not allowed\"));"));
            assert!(!content.contains("deepEqual(value"));
        }
        let object = component(&files, "objectchoice");
        assert!(object.contains("deepEqual(value, {\"value\":1})"));
        assert!(!object.contains("deepEqual(value, false)"));
        let array = component(&files, "arraychoice");
        assert!(array.contains("deepEqual(value, [1])"));
        assert!(!array.contains("deepEqual(value, \"wrong\")"));
    }

    #[test]
    fn tuple_emits_array_constraints_like_a_plain_array() {
        // Fix F: gen_tuple dropped minItems/maxItems/uniqueItems even though the parser populates
        // them for tuple nodes. A plain tuple emits none.
        let (files, diagnostics) = compile(doc_31(json!({
            "Constrained": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "items": { "type": "integer" },
                "minItems": 1,
                "maxItems": 5,
                "uniqueItems": true
            },
            "Plain": {
                "type": "array",
                "prefixItems": [{ "type": "string" }],
                "items": { "type": "integer" }
            }
        })));
        assert_clean(&diagnostics);
        let constrained = component(&files, "constrained");
        assert!(constrained.contains("if (value.length < 1) {"));
        assert!(constrained.contains("\"fewer items than minItems 1\""));
        assert!(constrained.contains("if (value.length > 5) {"));
        assert!(constrained.contains("\"more items than maxItems 5\""));
        assert!(constrained.contains("\"items not unique\""));
        let plain = component(&files, "plain");
        assert!(!plain.contains("fewer items than minItems"));
        assert!(!plain.contains("more items than maxItems"));
        assert!(!plain.contains("items not unique"));
    }

    #[test]
    fn colliding_parameter_validator_names_terminate_with_distinct_deterministic_names() {
        // Three same-location parameters whose Pascal forms collide: `foo`/`Foo` both normalize to
        // `Foo`, and `Foo`'s fixed-suffix fallback (`Foo` + its index 2) equals `foo2`'s own base
        // name. The old invariant fallback re-inserted an already-taken name forever; the per-attempt
        // bump terminates. This test hangs against the pre-fix generator, so its completion is the
        // termination proof.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/x": {
                    "get": {
                        "operationId": "getThing",
                        "parameters": [
                            { "name": "foo", "in": "query", "schema": { "type": "string" } },
                            { "name": "foo2", "in": "query", "schema": { "type": "string" } },
                            { "name": "Foo", "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "no content" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document);
        assert_clean(&diagnostics);
        let content = operation(&files, "getthing");
        // Deterministic disambiguation: base, base+2 (already a real base), then base+3.
        assert!(content.contains("export type GetThingQueryFoo = string;"));
        assert!(content.contains("export type GetThingQueryFoo2 = string;"));
        assert!(content.contains("export type GetThingQueryFoo3 = string;"));
    }

    #[test]
    fn free_form_children_emit_no_dead_scaffold() {
        // A no-op child (`Any`, from a free-form `{}`/`true` schema) has an empty validate body, so
        // every value-descent binding and loop around it is dead and must be skipped.
        let (files, diagnostics) = compile(doc_31(json!({
            "Freeform": {
                "type": "object",
                "properties": { "anything": {} }
            },
            "AnyItems": {
                "type": "array",
                "items": {}
            },
            "OpenBag": {
                "type": "object",
                "additionalProperties": {}
            }
        })));
        assert_clean(&diagnostics);
        // A non-required free-form property contributes no check at all: no own-key read, path
        // append, or descent, and no allocated value/path index.
        let freeform = component(&files, "freeform");
        assert!(!freeform.contains("Object.hasOwn(value, \"anything\")"));
        assert!(!freeform.contains("value0"));
        assert!(!freeform.contains("appendKey"));
        // A free-form array element keeps the array type gate but emits no per-element loop.
        let any_items = component(&files, "anyitems");
        assert!(any_items.contains("if (isArray(value)) {"));
        assert!(any_items.contains("if (evaluatedItem !== undefined) {"));
        assert!(any_items.contains("for (let index"));
        assert!(!any_items.contains("value0"));
        // A free-form additionalProperties schema emits only its dormant annotation iteration.
        let open_bag = component(&files, "openbag");
        assert!(open_bag.contains("if (isRecord(value)) {"));
        assert!(open_bag.contains("if (evaluatedProperty !== undefined) {"));
        assert!(open_bag.contains("Object.keys(value)"));
        assert!(!open_bag.contains("const value"));
    }

    #[test]
    fn required_free_form_property_keeps_only_its_presence_check() {
        // Only the value-descent scaffold is skippable: a required no-op property still enforces
        // presence, which reduces to the bare own-key test with no value/path binding.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "required": ["meta"],
                "properties": { "meta": {} }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(content.contains("if (!Object.hasOwn(value, \"meta\")) {"));
        assert!(content.contains("issues.push(issue(path, \"missing required property meta\"));"));
        assert!(!content.contains("value[\"meta\"]"));
        assert!(!content.contains("const value0"));
    }

    #[test]
    fn phantom_required_emits_hasown_presence_check() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "required": ["phantom"],
                "properties": { "declared": { "type": "string" } }
            }
        })));
        assert_clean(&diagnostics);
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS2203")
            .expect("phantom required warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(
            warning.json_pointer.as_deref(),
            Some("/components/schemas/Thing/required")
        );
        let content = component(&files, "thing");
        assert!(content.contains("if (!Object.hasOwn(value, \"phantom\")) {"));
        assert!(
            content.contains("issues.push(issue(path, \"missing required property phantom\"));")
        );
    }

    #[test]
    fn free_form_tuple_positions_skip_their_dead_scaffold() {
        // A no-op prefix position and a no-op rest schema each validate against nothing, so both the
        // length-guard block and the rest loop are dead; the surviving position is still checked.
        let (files, diagnostics) = compile(doc_31(json!({
            "PrefixAny": {
                "type": "array",
                "prefixItems": [{}, { "type": "string" }],
                "items": {}
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "prefixany");
        // Position 0 (free-form) is skipped; position 1 (string) is validated at index 1.
        assert!(!content.contains("if (value.length > 0) {"));
        assert!(content.contains("if (value.length > 1) {"));
        assert!(content.contains("const value0: unknown = value[1];"));
        // The free-form rest schema emits no value-validation loop; the remaining loop only
        // reports prefix/items annotations when an enclosing unevaluatedItems asks for them.
        assert!(content.contains("if (evaluatedItem !== undefined) {"));
        assert_eq!(content.matches("const value").count(), 1);
    }

    /// A component whose request shape drops a `readOnly` property emits a full Request-variant
    /// validator triplet (type + validate + checked + const) alongside the Neutral one, and the
    /// Request body omits the dropped property's check. Without this, a `$ref` from a request body
    /// would call the Neutral validator, which demands a property the request type does not carry.
    #[test]
    fn component_emits_request_variant_validator() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Pet": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "readOnly": true },
                    "name": { "type": "string" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "pet");
        // The full Request-variant triplet.
        assert!(
            content.contains("export interface PetRequest {"),
            "{content}"
        );
        assert!(
            content.contains(
                "export function validatePetRequest(value: unknown, path: readonly (string | number)[], issues: Issue[], evaluatedProperty?:"
            ),
            "{content}"
        );
        assert!(
            content.contains(
                "function checkedPetRequest(value: unknown, issues: Issue[]): value is PetRequest {"
            ),
            "{content}"
        );
        assert!(
            content
                .contains("export const petRequestValidator: SyncStandardSchemaV1<PetRequest> = {"),
            "{content}"
        );
        // The Neutral validator is still emitted.
        assert!(
            content.contains("export function validatePet("),
            "{content}"
        );
        // No spurious Response variant — nothing is writeOnly.
        assert!(!content.contains("PetResponse"), "{content}");
        // The Neutral body checks `id`; the Request body drops it.
        let neutral_body = validate_body(&content, "validatePet");
        assert!(neutral_body.contains("\"id\""), "neutral: {neutral_body}");
        let request_body = validate_body(&content, "validatePetRequest");
        assert!(
            !request_body.contains("\"id\""),
            "request body must not check the dropped readOnly property: {request_body}"
        );
    }

    /// The Response variant is symmetric: a `writeOnly` property is dropped from the response shape,
    /// so the Response validator omits its check.
    #[test]
    fn component_emits_response_variant_validator() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "secret": { "type": "string", "writeOnly": true },
                    "name": { "type": "string" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "pet");
        assert!(
            content.contains("export interface PetResponse {"),
            "{content}"
        );
        assert!(
            content.contains(
                "export function validatePetResponse(value: unknown, path: readonly (string | number)[], issues: Issue[], evaluatedProperty?:"
            ),
            "{content}"
        );
        assert!(
            content.contains("function checkedPetResponse(value: unknown, issues: Issue[]): value is PetResponse {"),
            "{content}"
        );
        assert!(
            content.contains(
                "export const petResponseValidator: SyncStandardSchemaV1<PetResponse> = {"
            ),
            "{content}"
        );
        assert!(
            content.contains("export function validatePet("),
            "{content}"
        );
        assert!(!content.contains("PetRequest"), "{content}");
        let neutral_body = validate_body(&content, "validatePet");
        assert!(
            neutral_body.contains("\"secret\""),
            "neutral: {neutral_body}"
        );
        let response_body = validate_body(&content, "validatePetResponse");
        assert!(
            !response_body.contains("\"secret\""),
            "response body must not check the dropped writeOnly property: {response_body}"
        );
    }

    /// Returns the `validate{Name}` function body region of `content` — the slice between its
    /// `export function validate{Name}(` header and the following `function checked{Name}(` — so an
    /// assertion targets one variant's body without matching sibling validators in the same file.
    fn validate_body<'a>(content: &'a str, validate_name: &str) -> &'a str {
        let after = content
            .split_once(&format!("export function {validate_name}("))
            .expect("validate function present")
            .1;
        let checked_name = validate_name.replacen("validate", "checked", 1);
        after
            .split_once(&format!("function {checked_name}("))
            .expect("checked function present")
            .0
    }

    #[test]
    fn typeless_string_constraints_type_guarded() {
        // `{minLength: 3}` is typeless: it constrains only strings and vacuously accepts every other
        // type. The check must sit inside a `typeof value === "string"` guard with no else arm, so a
        // number value falls through and pushes nothing.
        let (files, diagnostics) = compile(doc_31(json!({ "Thing": { "minLength": 3 } })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        let body = validate_body(&content, "validateThing");
        assert!(
            body.contains("if (typeof value === \"string\") {"),
            "{body}"
        );
        assert!(body.contains("if (codePointLength(value) < 3) {"), "{body}");
        assert!(
            body.contains("issues.push(issue(path, \"shorter than minLength 3\"));"),
            "{body}"
        );
        // Typeless admits every type: no type-mismatch arm, so a non-string value produces no issue.
        assert!(!body.contains("} else"), "{body}");
        assert!(!body.contains("expected type"), "{body}");
        // The only push is the guarded minLength one — nothing unguarded.
        assert_eq!(body.matches("issues.push(").count(), 1, "{body}");
    }

    #[test]
    fn typeless_number_and_array_and_object_guards() {
        // A typeless schema carrying constraints for several types emits one standalone type-guard
        // block per present group, in the fixed order number, string, array, object (string absent
        // here). Each block's checks fire only for a value of its matching type.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": { "minimum": 5, "minItems": 2, "maxProperties": 4 }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        let body = validate_body(&content, "validateThing");
        let number = body
            .find("if (typeof value === \"number\" && Number.isFinite(value)) {")
            .expect("number guard");
        assert!(body[number..].contains("if (value < 5) {"), "{body}");
        assert!(
            body.contains("issues.push(issue(path, \"less than minimum 5\"));"),
            "{body}"
        );
        let array = body.find("if (isArray(value)) {").expect("array guard");
        assert!(
            body.contains("issues.push(issue(path, \"fewer items than minItems 2\"));"),
            "{body}"
        );
        let object = body.find("if (isRecord(value)) {").expect("object guard");
        assert!(
            body.contains("if (Object.keys(value).length > 4) {"),
            "{body}"
        );
        assert!(
            body.contains("issues.push(issue(path, \"more properties than maxProperties 4\"));"),
            "{body}"
        );
        // No string group was declared, so no string guard is emitted.
        assert!(!body.contains("=== \"string\""), "{body}");
        // Fixed emission order: number, then array, then object.
        assert!(number < array && array < object, "{body}");
    }

    #[test]
    fn constrained_any_is_not_noop_scaffold_emitted() {
        // A constrained typeless property (`{minimum: 0}`) is no longer a no-op: it must get the full
        // own-key descent scaffold (own-key read, path append, typed body), where before it was
        // skipped and its constraint silently dropped.
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": { "n": { "minimum": 0 } }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(
            content.contains("if (Object.hasOwn(value, \"n\")) {"),
            "{content}"
        );
        assert!(
            content.contains("const value0: unknown = value[\"n\"];"),
            "{content}"
        );
        assert!(
            content.contains("const path0 = appendKey(path, \"n\");"),
            "{content}"
        );
        assert!(
            content.contains("if (typeof value0 === \"number\" && Number.isFinite(value0)) {"),
            "{content}"
        );
        assert!(
            content.contains("issues.push(issue(path0, \"less than minimum 0\"));"),
            "{content}"
        );
    }

    #[test]
    fn contentencoding_typeless_emits_no_check() {
        // contentEncoding is a serialization concern, not a JSON-validity assertion, so a typeless
        // `{contentEncoding: "base64"}` stays a no-op — its validate body is byte-identical to a
        // plain free-form `{}`.
        let (files, diagnostics) = compile(doc_31(json!({
            "Encoded": { "contentEncoding": "base64" },
            "Plain": {}
        })));
        assert_clean(&diagnostics);
        let encoded = component(&files, "encoded");
        let plain = component(&files, "plain");
        let encoded_body = validate_body(&encoded, "validateEncoded");
        let plain_body = validate_body(&plain, "validatePlain");
        // Byte-identical to a plain free-form `{}`: same empty validate body, no emitted check.
        assert_eq!(encoded_body, plain_body, "encoded: {encoded}");
        assert!(!encoded_body.contains("issues.push("), "{encoded}");
        assert!(!encoded_body.contains("if ("), "{encoded}");
        assert!(!encoded.contains("base64"), "{encoded}");
    }

    #[test]
    fn allof_sibling_constraints_enforced() {
        // `{allOf: [...], minLength: 3}` lowers to a conjunction whose typed branch is a constraint-
        // only typeless `Any`. The generated validator must enforce that sibling minLength through the
        // typed branch's string guard, composing with the applicator branch's own checks.
        let (files, diagnostics) = compile(doc_31(json!({
            "Combined": {
                "allOf": [
                    { "type": "object", "properties": { "a": { "type": "string" } } }
                ],
                "minLength": 3
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "combined");
        let body = validate_body(&content, "validateCombined");
        // The applicator branch still checks the object shape.
        assert!(body.contains("if (isRecord(value)) {"), "{body}");
        // The sibling minLength is enforced by the typed branch's string guard.
        assert!(
            body.contains("if (typeof value === \"string\") {"),
            "{body}"
        );
        assert!(body.contains("if (codePointLength(value) < 3) {"), "{body}");
        assert!(
            body.contains("issues.push(issue(path, \"shorter than minLength 3\"));"),
            "{body}"
        );
    }
}
