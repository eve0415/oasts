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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{Number, Value};

use crate::diag::Diagnostic;
use crate::ir::{
    AdditionalProperties, ExclusiveBound, FiniteConstraint, Operation, ParamLocation,
    PrimitiveType, PropMeta, ResponseEntry, SchemaMeta, SchemaNode, TupleRest, finite_parts,
};
use crate::num::render_number_value;
use crate::semantic::{TargetCase, normalize_identifier};

use super::model::EmissionModel;
use super::runtime_assets::rewrite_relative_ts_imports;
use super::{
    Emitter, GeneratedFile, ObjectKeyMode, SchemaChildMode, TypePosition, callback_operation,
    callback_parent_operation, import_extension, lowercase_first, media_tag, property_in_position,
    push_indent, render_json_compact, render_ts_string, response_status_type_suffix,
    source_diagnostic, uppercase_first,
};
use crate::media::is_json;

/// Emitted verbatim as `validators/runtime.ts`; the generated-validator call ABI is fixed to it.
const VALIDATORS_RUNTIME_TS: &str = include_str!("../../runtime/validators-runtime.ts");
/// Emitted verbatim as `validators/standard-schema.ts`; the vendored Standard Schema declaration.
const VALIDATORS_STANDARD_SCHEMA_TS: &str =
    include_str!("../../runtime/validators-standard-schema.ts");

/// A schema carries a validation keyword the validators artifact does not implement.
const CODE_REJECTED_KEYWORD: &str = "OASTS1501";
/// A schema degraded to an unknown leaf, so no faithful validator can be emitted for it.
const CODE_UNKNOWN_LEAF: &str = "OASTS1502";
/// Two JSON media entries on one response mangle to the same validator-name fragment.
const CODE_MEDIA_TAG_COLLISION: &str = "OASTS1400";

/// The response-body validators for one declared response: its JSON media entries paired with the
/// exported names the client will call.
///
/// A response with a single JSON entry keeps the plain `validate{Stem}Response{Suffix}` name — the
/// common case, where a second entry exists but is not JSON. Two or more JSON entries each get
/// their own validator, suffixed by the media tag, because they are separate schemas the client
/// selects between on `contentType`. A tag collision is fatal rather than silently disambiguated:
/// the compiler never invents a suffix a caller cannot predict from the document.
fn response_body_validators<'ir>(
    response: &'ir crate::ir::ResponseEntry,
    stem: &str,
    suffix: &str,
    sink: &mut crate::diag::DiagnosticSink,
) -> Vec<(String, &'ir SchemaNode)> {
    let json: Vec<&crate::ir::MediaType> = response
        .media_types
        .iter()
        .filter(|media| is_json(&media.essence))
        .collect();
    let Some(first) = json.first() else {
        return Vec::new();
    };
    if json.len() == 1 {
        return vec![(format!("{stem}Response{suffix}"), &first.schema)];
    }
    let mut named: Vec<(String, &SchemaNode)> = Vec::new();
    let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
    for media in json {
        let name = format!("{stem}Response{suffix}{}", media_tag(&media.full));
        if let Some(previous) = claimed.insert(name.clone(), &media.full) {
            sink.push(source_diagnostic(
                CODE_MEDIA_TAG_COLLISION,
                format!(
                    "response media types '{previous}' and '{}' produce the same validator name '{name}'",
                    media.full
                ),
                &media.source,
            ));
            continue;
        }
        named.push((name, &media.schema));
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
    "isInt32",
    "StandardSchemaV1",
    "SyncStandardSchemaV1",
    "isRecord",
    "isArray",
    "hasGet",
];

pub(crate) fn emit_validators_from_model(model: &mut EmissionModel<'_, '_>) -> Vec<GeneratedFile> {
    let analyzed = model.analyzed;

    // Reject-handling walk: reachable schemas with unsupported keywords or unknown-leaf degradation
    // fail the run. Every component and every operation position is emitted, so walking the
    // component schemas and operation schemas (into their children, never through `$ref` — the
    // target is itself a walked component) covers exactly the reachable set once.
    let mut rejects = Vec::new();
    {
        // The reject walk reuses the types emitter's child-walk (`SchemaChildMode::Validation`
        // visits exactly the schemas a validator would descend into), so this borrows `model`
        // read-only through an emitter that is dropped before `reserve_names` needs it back.
        let emitter = Emitter::new(model);
        for schema in &analyzed.ir.schemas {
            collect_rejects(&emitter, &schema.schema, &mut rejects);
        }
        for operation in &analyzed.ir.operations {
            collect_operation_rejects(&emitter, operation, true, &mut rejects);
        }
        for webhook in &analyzed.ir.webhooks {
            for operation in &webhook.operations {
                collect_operation_rejects(&emitter, operation, false, &mut rejects);
            }
        }
        for allocated in &analyzed.callback_names {
            let operation = callback_operation(&analyzed.ir, &analyzed.callback_names, allocated);
            collect_operation_rejects(&emitter, operation, false, &mut rejects);
        }
    }
    model.sink.extend(rejects);

    // Validators is the terminal emitter, so renaming component targets that collide with the
    // injected kernel identifiers here is safe — no later emitter reads the allocation.
    model.reserve_names(VALIDATOR_RESERVED_NAMES);

    let mut files = Vec::new();
    files.push(embedded_asset(model, "runtime.ts", VALIDATORS_RUNTIME_TS));
    files.push(embedded_asset(
        model,
        "standard-schema.ts",
        VALIDATORS_STANDARD_SCHEMA_TS,
    ));

    for allocated in &analyzed.schema_names {
        if model.component_files[allocated.schema_index].is_none() {
            continue;
        }
        // The export name is the (possibly reserved-renamed) target name, so it agrees with the
        // structural type, self/cross references, and sibling imports — all of which read the target.
        // An allocated file always has a registered target (allocate_paths sets both together).
        let schema = &analyzed.ir.schemas[allocated.schema_index];
        let name = model
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .map(|target| target.name.clone())
            .expect("a component with an allocated file has a registered target");
        if let Some(file) = emit_component(model, allocated.schema_index, &name) {
            files.push(file);
        }
    }
    for allocated in &analyzed.operation_names {
        if model.operation_files[allocated.operation_index].is_none() {
            continue;
        }
        if let Some(file) = emit_operation(model, allocated.operation_index, &allocated.name) {
            files.push(file);
        }
    }
    if !analyzed.ir.webhooks.is_empty() {
        for index in 0..analyzed.webhook_names.len() {
            let Some(file_base) = model.webhook_files[index].clone() else {
                continue;
            };
            let allocated = &analyzed.webhook_names[index];
            let operation = &analyzed.ir.webhooks[allocated.webhook_index].operations
                [allocated.operation_index];
            if let Some(file) = emit_operation_file(
                model,
                operation,
                &allocated.stem,
                "webhooks",
                &file_base,
                false,
            ) {
                files.push(file);
            }
        }
        files.push(emit_webhooks_index(model));
    }
    if !analyzed.callback_names.is_empty() {
        for index in 0..analyzed.callback_names.len() {
            let Some(file_base) = model.callback_files[index].clone() else {
                continue;
            };
            let allocated = &analyzed.callback_names[index];
            let operation = callback_operation(&analyzed.ir, &analyzed.callback_names, allocated);
            if let Some(file) = emit_operation_file(
                model,
                operation,
                &allocated.stem,
                "callbacks",
                &file_base,
                false,
            ) {
                files.push(file);
            }
        }
        files.push(emit_callbacks_index(model));
    }
    files
}

/// Embeds a validators runtime asset verbatim (no generated header) with `.ts` import specifiers
/// rewritten to the configured extension, and registers its path in the collision namespace.
fn embedded_asset(
    model: &mut EmissionModel<'_, '_>,
    file_name: &str,
    source: &str,
) -> GeneratedFile {
    let content = rewrite_relative_ts_imports(source, &model.config.emit.import_extension);
    let relative_path = format!("validators/{file_name}");
    let asset_source = model
        .analyzed
        .ir
        .schemas
        .first()
        .map(|schema| schema.source.clone())
        .unwrap_or_default();
    model.register_path(&relative_path, &asset_source);
    GeneratedFile {
        relative_path,
        content,
    }
}

// --- reject-handling walk ----------------------------------------------------------------------

fn collect_rejects(emitter: &Emitter<'_, '_, '_>, schema: &SchemaNode, out: &mut Vec<Diagnostic>) {
    let meta = schema.meta();
    // One rejected keyword is one root cause: it drives OASTS1501, and the same parse degrades the
    // node to an unknown leaf. Surfacing OASTS1502 as well would double-report it against the frozen
    // matrix's single-diagnostic contract, so the unknown-leaf code fires only for nodes that
    // reached Unknown without carrying a rejected keyword (e.g. `$dynamicRef`, an unknown `type`).
    if meta.rejected_validation_keywords.is_empty() {
        if let SchemaNode::Unknown { reason, meta } = schema {
            out.push(source_diagnostic(
                CODE_UNKNOWN_LEAF,
                format!("validators cannot emit a check for an unsupported schema ({reason})"),
                &meta.source,
            ));
        }
    } else {
        for keyword in &meta.rejected_validation_keywords {
            out.push(source_diagnostic(
                CODE_REJECTED_KEYWORD,
                format!(
                    "validators cannot emit a check for unsupported validation keyword '{keyword}'"
                ),
                &meta.source,
            ));
        }
    }
    // Validation mode visits the same direct children (no `$ref` following) a validator descends,
    // so the reachable set the reject walk covers matches the emitted checks exactly.
    emitter.for_each_schema_child(schema, SchemaChildMode::Validation, &mut |child| {
        collect_rejects(emitter, child, out);
    });
}

fn collect_operation_rejects(
    emitter: &Emitter<'_, '_, '_>,
    operation: &Operation,
    include_responses: bool,
    out: &mut Vec<Diagnostic>,
) {
    for parameter in &operation.parameters {
        collect_rejects(emitter, &parameter.schema, out);
    }
    if let Some(body) = &operation.request_body {
        for media in &body.media_types {
            collect_rejects(emitter, &media.schema, out);
        }
    }
    if include_responses {
        for response in &operation.responses {
            for media in &response.media_types {
                collect_rejects(emitter, &media.schema, out);
            }
            for (_, header) in &response.headers {
                collect_rejects(emitter, &header.schema, out);
            }
        }
    }
}

// --- per-file scope ----------------------------------------------------------------------------

/// File-scoped state accumulated while generating a file's validate bodies: the runtime value
/// imports actually used, whether the record/array narrowing guards are needed, and the lazily
/// cached regex patterns (slot = index).
#[derive(Default)]
struct FileScope {
    runtime_values: BTreeSet<&'static str>,
    needs_is_record: bool,
    needs_is_array: bool,
    patterns: Vec<String>,
}

impl FileScope {
    /// Returns the module-scope cache slot for a pattern string, deduplicating equal patterns.
    fn pattern_slot(&mut self, pattern: &str) -> usize {
        if let Some(index) = self
            .patterns
            .iter()
            .position(|existing| existing == pattern)
        {
            return index;
        }
        self.patterns.push(pattern.to_owned());
        self.patterns.len() - 1
    }
}

// --- validate-body code generation -------------------------------------------------------------

/// One validate-function body under construction: indented output plus a monotonic counter that
/// names locals uniquely across the whole function so nested scopes never shadow. Borrows the
/// file-scoped `FileScope` (imports/guards/patterns accumulate across the file's declarations) and
/// the immutable emission `model` (for `$ref` target resolution); `position` is the fixed wire
/// variant of the declaration being generated.
struct FnBody<'scope, 'model, 'input, 'sink> {
    out: String,
    indent: usize,
    counter: usize,
    scope: &'scope mut FileScope,
    model: &'model EmissionModel<'input, 'sink>,
    position: TypePosition,
}

impl<'scope, 'model, 'input, 'sink> FnBody<'scope, 'model, 'input, 'sink> {
    fn new(
        scope: &'scope mut FileScope,
        model: &'model EmissionModel<'input, 'sink>,
        position: TypePosition,
    ) -> Self {
        Self {
            out: String::new(),
            indent: 1,
            counter: 0,
            scope,
            model,
            position,
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

    fn gen_schema(&mut self, schema: &SchemaNode, val: &str, path: &str, iss: &str) {
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
                    self.line(&format!(
                        "validate{}({val}, {path}, {iss});",
                        resolved.variant_name(self.position)
                    ));
                }
                // An unresolved reference is already reported as OASTS1305 by the types pass.
            }
            SchemaNode::Primitive {
                ty,
                format,
                enum_values,
                const_value,
                meta,
            } => {
                self.gen_primitive(*ty, format.as_deref(), meta, val, path, iss);
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
                self.gen_object(
                    ObjectParts {
                        properties,
                        additional_properties,
                        dependent_required,
                        extra_required,
                        meta,
                    },
                    val,
                    path,
                    iss,
                );
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::Array {
                items,
                finite,
                meta,
                ..
            } => {
                self.gen_array(items, meta, val, path, iss);
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::Tuple {
                prefix_items,
                rest,
                finite,
                meta,
            } => {
                self.gen_tuple(prefix_items, rest, meta, val, path, iss);
                self.gen_finite_constraint(finite, val, path, iss);
            }
            SchemaNode::AllOf { branches, .. } => {
                for branch in branches {
                    self.gen_schema(branch, val, path, iss);
                }
            }
            SchemaNode::AnyOf { branches, .. } => {
                self.gen_composition(branches, val, path, iss, Composition::AnyOf);
            }
            SchemaNode::OneOf { branches, .. } => {
                self.gen_composition(branches, val, path, iss, Composition::OneOf);
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
            SchemaNode::Unknown { .. } => {}
        }
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
                    self.gen_schema(&header.schema, &decoded, &child_path, "issues");
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
                    self.gen_schema(&header.schema, &val, &child_path, "issues");
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
            PrimitiveType::Boolean | PrimitiveType::Null => {}
        }
        self.close_type_gate(widen_null, val, path, iss, type_name);
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
            let slot = self.scope.pattern_slot(pattern);
            self.push_issue(
                &format!("!pattern{slot}Regex().test({val})"),
                path,
                iss,
                "does not match pattern",
            );
        }
        if let Some(format) = format
            && let Some((predicate, message)) = string_format_predicate(format)
        {
            self.scope.runtime_values.insert(predicate);
            self.push_issue(&format!("!{predicate}({val})"), path, iss, message);
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
        self.gen_bound(constraints, BoundDirection::Lower, val, path, iss);
        self.gen_bound(constraints, BoundDirection::Upper, val, path, iss);
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
    ) {
        let bound = direction.resolve(constraints);
        match bound.exclusive {
            Some(ExclusiveBound::Number(value)) => {
                self.emit_threshold(
                    val,
                    bound.exclusive_comparator,
                    bound.exclusive_message,
                    value,
                    path,
                    iss,
                );
                if let Some(value) = bound.inclusive {
                    self.emit_threshold(
                        val,
                        bound.inclusive_comparator,
                        bound.inclusive_message,
                        value,
                        path,
                        iss,
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
                        path,
                        iss,
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
                        path,
                        iss,
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
        path: &str,
        iss: &str,
    ) {
        let literal = render_number_value(value);
        self.push_issue(
            &format!("{val} {comparator} {literal}"),
            path,
            iss,
            &format!("{message} {literal}"),
        );
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

    fn gen_object(&mut self, parts: ObjectParts<'_>, val: &str, path: &str, iss: &str) {
        let ObjectParts {
            properties,
            additional_properties,
            dependent_required,
            extra_required,
            meta,
        } = parts;
        self.scope.needs_is_record = true;
        self.open(&format!("if (isRecord({val})) {{"));

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
            self.gen_schema(property, &child, &child_path, iss);
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

        self.gen_additional_properties(
            additional_properties,
            properties,
            val,
            path,
            iss,
            &keys_expr,
        );

        self.gen_property_count_bounds(min, max, &keys_expr, path, iss);

        self.close_type_gate(meta.nullable, val, path, iss, "object");
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

    fn gen_additional_properties(
        &mut self,
        additional: &AdditionalProperties,
        properties: &[(String, SchemaNode, PropMeta)],
        val: &str,
        path: &str,
        iss: &str,
        keys_expr: &str,
    ) {
        match additional {
            AdditionalProperties::Forbidden => {
                let condition = unknown_key_condition(properties);
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
                let condition = unknown_key_condition(properties);
                self.open(&format!("for (const key of {keys_expr}) {{"));
                self.open(&format!("if ({condition}) {{"));
                let index = self.fresh();
                let child = format!("value{index}");
                let child_path = format!("path{index}");
                self.line(&format!("const {child}: unknown = {val}[key];"));
                self.scope.runtime_values.insert("appendKey");
                self.line(&format!("const {child_path} = appendKey({path}, key);"));
                self.gen_schema(sub, &child, &child_path, iss);
                self.close("}");
                self.close("}");
            }
            AdditionalProperties::Schema(_) | AdditionalProperties::Allowed(_) => {}
        }
    }

    fn gen_array(
        &mut self,
        items: &SchemaNode,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
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
            self.gen_schema(items, &element, &element_path, iss);
            self.close("}");
        }
        self.gen_array_constraints(meta, val, path, iss);
        self.close_type_gate(meta.nullable, val, path, iss, "array");
    }

    fn gen_tuple(
        &mut self,
        prefix_items: &[SchemaNode],
        rest: &TupleRest,
        meta: &SchemaMeta,
        val: &str,
        path: &str,
        iss: &str,
    ) {
        self.scope.needs_is_array = true;
        self.open(&format!("if (isArray({val})) {{"));
        for (position_index, prefix) in prefix_items.iter().enumerate() {
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
            self.gen_schema(prefix, &element, &element_path, iss);
            self.close("}");
        }
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
                self.gen_schema(sub, &element, &element_path, iss);
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
        self.close_type_gate(meta.nullable, val, path, iss, "array");
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

    fn gen_composition(
        &mut self,
        branches: &[SchemaNode],
        val: &str,
        path: &str,
        iss: &str,
        kind: Composition,
    ) {
        self.scope.runtime_values.insert("issue");
        let index = self.fresh();
        let counter = format!("matches{index}");
        self.line(&format!("let {counter} = 0;"));
        // Once the verdict is decided, stop probing: anyOf passes at the first match, and oneOf
        // fails as soon as a second match appears. The guard limit is that decisive count. This is
        // semantics-neutral — branch issues go to discarded scratch arrays, and the surfaced verdict
        // and single composition issue depend only on whether `matches` is 0 / exactly 1 / >= 2,
        // which the early exit preserves.
        let limit = match kind {
            Composition::AnyOf => 1,
            Composition::OneOf => 2,
        };
        for branch in branches {
            self.open(&format!("if ({counter} < {limit}) {{"));
            let scratch_index = self.fresh();
            let scratch = format!("issues{scratch_index}");
            self.line(&format!("const {scratch}: Issue[] = [];"));
            self.gen_schema(branch, val, path, &scratch);
            self.open(&format!("if ({scratch}.length === 0) {{"));
            self.line(&format!("{counter} += 1;"));
            self.close("}");
            self.close("}");
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
}

#[derive(Clone, Copy)]
enum Composition {
    AnyOf,
    OneOf,
}

/// The borrowed pieces of a `SchemaNode::Object`, grouped so object generation takes one argument.
struct ObjectParts<'a> {
    properties: &'a [(String, SchemaNode, PropMeta)],
    additional_properties: &'a AdditionalProperties,
    dependent_required: &'a [(String, Vec<String>)],
    extra_required: &'a [String],
    meta: &'a SchemaMeta,
}

/// A schema whose validate body is empty, so descending into it emits only dead scaffold. A plain
/// free-form `{}`/`true` schema (`Any` with no constraint group) and an unknown leaf (`Unknown`,
/// which additionally fails the run via the reject walk, so it never reaches committed output) are
/// no-ops. A constrained typeless `Any` (`{minLength: 3}`) is NOT — it emits type-guarded checks, so
/// callers must give it the full value/path descent scaffold. Callers skip that scaffold only for
/// the no-op case.
fn is_noop_schema(schema: &SchemaNode) -> bool {
    match schema {
        SchemaNode::Any { meta } => !has_typeless_constraints(meta),
        other => matches!(other, SchemaNode::Unknown { .. }),
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

fn unknown_key_condition(properties: &[(String, SchemaNode, PropMeta)]) -> String {
    if properties.is_empty() {
        return "true".to_owned();
    }
    properties
        .iter()
        .map(|(name, _, _)| format!("key !== {}", render_ts_string(name)))
        .collect::<Vec<_>>()
        .join(" && ")
}

fn string_format_predicate(format: &str) -> Option<(&'static str, &'static str)> {
    match format {
        "date-time" => Some(("isDateTime", "invalid date-time format")),
        "date" => Some(("isDate", "invalid date format")),
        "time" => Some(("isTime", "invalid time format")),
        "uuid" => Some(("isUuid", "invalid uuid format")),
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
    validator: String,
}

fn emit_component(
    model: &mut EmissionModel<'_, '_>,
    schema_index: usize,
    name: &str,
) -> Option<GeneratedFile> {
    let analyzed = model.analyzed;
    let file_base = model.component_files[schema_index].clone()?;
    let schema = &analyzed.ir.schemas[schema_index];

    // A `readOnly`/`writeOnly` property somewhere in this component (or a component it references)
    // makes the request and/or response shape diverge from the neutral one, so this component gains
    // first-class Request/Response validator variants mirroring the type artifact. The divergence
    // was resolved across the whole reference graph at model construction; `Some` is exactly the
    // positions that diverge, and carries the name each one declares under.
    let (request_variant, response_variant) = {
        let target = model
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .expect("a component with an allocated file has a registered target");
        (target.request_export(), target.response_export())
    };

    let mut scope = FileScope::default();
    let mut imports = SiblingImports::default();

    let declarations = if request_variant.is_some() || response_variant.is_some() {
        // One full validator triplet per needed position. Fixed order — Neutral, then Request, then
        // Response — keeps the emitted file deterministic. The variant export names come from
        // `SchemaTarget`, the same producer the type artifact and every sibling import read, so
        // agreement is enforced here rather than restated.
        let mut variants: Vec<(String, TypePosition)> = Vec::with_capacity(3);
        variants.push((name.to_owned(), TypePosition::Neutral));
        if let Some(export) = request_variant {
            variants.push((export, TypePosition::Request));
        }
        if let Some(export) = response_variant {
            variants.push((export, TypePosition::Response));
        }

        // Phase 1: render each variant's structural type and collect its sibling imports through the
        // shared emitter, position by position — the position selects which properties survive.
        let type_declarations: Vec<String> = {
            let emitter = Emitter::new(model);
            variants
                .iter()
                .map(|(export, position)| {
                    let mut declaration = String::new();
                    emitter.write_schema_declaration(
                        &mut declaration,
                        export,
                        &schema.schema,
                        *position,
                        &schema.source,
                    );
                    imports.collect(&emitter, &schema.schema, *position, Some(schema_index));
                    declaration
                })
                .collect()
        };

        // Phase 2: generate each variant's validate body (needs schema_target lookups through a
        // dropped emitter); the position drives which properties the body checks.
        let mut declarations = Vec::with_capacity(variants.len());
        for ((export, position), type_declaration) in variants.iter().zip(type_declarations) {
            let mut body = FnBody::new(&mut scope, model, *position);
            body.gen_schema(&schema.schema, "value", "path", "issues");
            declarations.push(Decl {
                type_declaration,
                validator: render_validator(export, &body.out),
            });
        }
        declarations
    } else {
        // Neutral-only common case: a single declaration, allocation-identical to a marker-free
        // component before variants existed (the drift gate pins this shape).
        let type_declaration = {
            let emitter = Emitter::new(model);
            let mut declaration = String::new();
            emitter.write_schema_declaration(
                &mut declaration,
                name,
                &schema.schema,
                TypePosition::Neutral,
                &schema.source,
            );
            imports.collect(
                &emitter,
                &schema.schema,
                TypePosition::Neutral,
                Some(schema_index),
            );
            declaration
        };
        let mut body = FnBody::new(&mut scope, model, TypePosition::Neutral);
        body.gen_schema(&schema.schema, "value", "path", "issues");
        vec![Decl {
            type_declaration,
            validator: render_validator(name, &body.out),
        }]
    };

    let content = assemble_file(model, "./", &imports, &scope, &declarations);
    let relative_path = format!("validators/components/{file_base}.ts");
    model.register_path(&relative_path, &schema.source);
    Some(GeneratedFile {
        relative_path,
        content,
    })
}

fn emit_operation(
    model: &mut EmissionModel<'_, '_>,
    operation_index: usize,
    allocated_name: &str,
) -> Option<GeneratedFile> {
    let analyzed = model.analyzed;
    let file_base = model.operation_files[operation_index].clone()?;
    let operation = &analyzed.ir.operations[operation_index];
    emit_operation_file(
        model,
        operation,
        allocated_name,
        "operations",
        &file_base,
        true,
    )
}

fn emit_operation_file(
    model: &mut EmissionModel<'_, '_>,
    operation: &Operation,
    allocated_name: &str,
    directory: &str,
    file_base: &str,
    include_responses: bool,
) -> Option<GeneratedFile> {
    let stem = uppercase_first(allocated_name);

    // Deterministic list of (export type name, schema, wire position) to validate: every parameter,
    // the JSON request body, and every JSON response branch (4XX/default included).
    let mut positions: Vec<(String, &SchemaNode, TypePosition)> = Vec::new();
    for (export_type, parameter) in operation_parameter_validator_names(operation, &stem)
        .into_iter()
        .zip(&operation.parameters)
    {
        positions.push((export_type, &parameter.schema, TypePosition::Request));
    }
    if let Some(body) = &operation.request_body
        && let Some(media) = body
            .media_types
            .iter()
            .find(|media| is_json(&media.essence))
    {
        positions.push((
            format!("{stem}RequestBody"),
            &media.schema,
            TypePosition::Request,
        ));
    }
    if include_responses {
        let mut responses: Vec<(String, &SchemaNode)> = Vec::new();
        for response in &operation.responses {
            let suffix = response_status_type_suffix(&response.status);
            responses.extend(response_body_validators(
                response, &stem, &suffix, model.sink,
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
        return None;
    }

    let mut scope = FileScope::default();
    let mut imports = SiblingImports::default();

    // Phase 1: render each position's type alias and collect sibling imports. One emitter serves
    // both the value and header declarations — its merge/link caches carry across the two loops —
    // and the block scopes its borrow of `model` so phase 2 can reborrow `model` mutably.
    let (type_declarations, header_type_declarations): (Vec<String>, Vec<String>) = {
        let emitter = Emitter::new(model);
        let type_declarations = positions
            .iter()
            .map(|(export_type, schema, position)| {
                imports.collect(&emitter, schema, *position, None);
                format!(
                    "export type {export_type} = {};\n",
                    emitter.render_type(schema, *position, 0)
                )
            })
            .collect();
        let header_type_declarations = header_positions
            .iter()
            .map(|(export_type, response)| {
                for (_, header) in &response.headers {
                    imports.collect(&emitter, &header.schema, TypePosition::Response, None);
                }
                let mut declaration = String::new();
                emitter.write_response_headers_interface(&mut declaration, export_type, response);
                declaration
            })
            .collect();
        (type_declarations, header_type_declarations)
    };

    // Phase 2: generate validate bodies.
    let mut declarations = Vec::with_capacity(positions.len() + header_positions.len());
    for ((export_type, schema, position), type_declaration) in
        positions.iter().zip(type_declarations)
    {
        let mut body = FnBody::new(&mut scope, model, *position);
        body.gen_schema(schema, "value", "path", "issues");
        declarations.push(Decl {
            type_declaration,
            validator: render_validator(export_type, &body.out),
        });
    }
    for ((export_type, response), type_declaration) in
        header_positions.iter().zip(header_type_declarations)
    {
        let mut body = FnBody::new(&mut scope, model, TypePosition::Response);
        body.gen_response_headers(response);
        declarations.push(Decl {
            type_declaration,
            validator: render_validator(export_type, &body.out),
        });
    }

    let content = assemble_file(model, "../components/", &imports, &scope, &declarations);
    let relative_path = format!("validators/{directory}/{file_base}.ts");
    model.register_path(&relative_path, &operation.source);
    Some(GeneratedFile {
        relative_path,
        content,
    })
}

fn emit_webhooks_index(model: &EmissionModel<'_, '_>) -> GeneratedFile {
    let analyzed = model.analyzed;
    let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
    let mut body = String::from("export const webhooks = {\n");
    // webhook_names is grouped by ascending webhook_index (its allocation order), so each webhook's
    // entries are the contiguous run at the cursor — advance through them once instead of rescanning
    // the whole table per webhook.
    let mut cursor = 0;
    for (webhook_index, webhook) in analyzed.ir.webhooks.iter().enumerate() {
        body.push_str("  ");
        body.push_str(&render_ts_string(&webhook.name));
        body.push_str(": {");
        let mut wrote_method = false;
        while let Some(allocated) = analyzed
            .webhook_names
            .get(cursor)
            .filter(|allocated| allocated.webhook_index == webhook_index)
        {
            let file_base = model.webhook_files[cursor].as_deref();
            cursor += 1;
            let Some(file_base) = file_base else {
                continue;
            };
            let operation = &webhook.operations[allocated.operation_index];
            if !operation_has_request_validators(operation) {
                continue;
            }
            if !wrote_method {
                body.push('\n');
                wrote_method = true;
            }
            write_request_descriptor_method(
                &mut body,
                &mut imports,
                file_base,
                &allocated.stem,
                operation,
                4,
            );
        }
        if wrote_method {
            body.push_str("  },\n");
        } else {
            body.push_str("},\n");
        }
    }
    body.push_str("};\n");
    assemble_descriptor_index(model, "validators/webhooks/index.ts", imports, body)
}

fn emit_callbacks_index(model: &EmissionModel<'_, '_>) -> GeneratedFile {
    let analyzed = model.analyzed;
    let ir = &analyzed.ir;
    let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
    let mut body = String::new();
    let mut seen_parents = HashSet::new();
    // A parent's filed, validator-bearing callback entries interleave with its nested callbacks'
    // entries in callback_names (pre-order DFS), so group every qualifying entry by parent once
    // (callback_names order preserved) instead of rescanning the whole table per parent.
    let mut entries_by_parent: HashMap<_, Vec<usize>> = HashMap::new();
    for (index, entry) in analyzed.callback_names.iter().enumerate() {
        if model.callback_files[index].is_some()
            && operation_has_request_validators(callback_operation(
                ir,
                &analyzed.callback_names,
                entry,
            ))
        {
            entries_by_parent
                .entry(&entry.parent)
                .or_default()
                .push(index);
        }
    }
    for (index, entry) in analyzed.callback_names.iter().enumerate() {
        if model.callback_files[index].is_none()
            || !operation_has_request_validators(callback_operation(
                ir,
                &analyzed.callback_names,
                entry,
            ))
            || !seen_parents.insert(&entry.parent)
        {
            continue;
        }
        if !body.is_empty() {
            body.push('\n');
        }
        let parent = &entry.parent;
        let parent_op = callback_parent_operation(ir, &analyzed.callback_names, parent);
        body.push_str("export const ");
        body.push_str(&lowercase_first(&uppercase_first(&entry.parent_stem)));
        body.push_str("Callbacks = {\n");
        let entries = &entries_by_parent[parent];
        let mut cursor = 0;
        while cursor < entries.len() {
            let callback_index = analyzed.callback_names[entries[cursor]].callback_index;
            let callback = &parent_op.callbacks[callback_index];
            body.push_str("  ");
            body.push_str(&render_ts_string(&callback.name));
            body.push_str(": {\n");
            while cursor < entries.len()
                && analyzed.callback_names[entries[cursor]].callback_index == callback_index
            {
                let expression_index = analyzed.callback_names[entries[cursor]].expression_index;
                body.push_str("    ");
                body.push_str(&render_ts_string(
                    &callback.expressions[expression_index].expression,
                ));
                body.push_str(": {\n");
                while cursor < entries.len() && {
                    let current = &analyzed.callback_names[entries[cursor]];
                    current.callback_index == callback_index
                        && current.expression_index == expression_index
                } {
                    let i = entries[cursor];
                    let allocated = &analyzed.callback_names[i];
                    let file_base = model.callback_files[i].as_deref().unwrap_or_default();
                    let operation = callback_operation(ir, &analyzed.callback_names, allocated);
                    write_request_descriptor_method(
                        &mut body,
                        &mut imports,
                        file_base,
                        &allocated.stem,
                        operation,
                        6,
                    );
                    cursor += 1;
                }
                body.push_str("    },\n");
            }
            body.push_str("  },\n");
        }
        body.push_str("};\n");
    }
    assemble_descriptor_index(model, "validators/callbacks/index.ts", imports, body)
}

fn operation_has_request_validators(operation: &Operation) -> bool {
    !operation.parameters.is_empty()
        || operation
            .request_body
            .as_ref()
            .is_some_and(|body| body.media_types.iter().any(|media| is_json(&media.essence)))
}

fn write_request_descriptor_method(
    body: &mut String,
    imports: &mut BTreeMap<String, BTreeSet<String>>,
    file_base: &str,
    allocated_name: &str,
    operation: &Operation,
    indent: usize,
) {
    let stem = uppercase_first(allocated_name);
    let parameter_names = operation_parameter_validator_names(operation, &stem);
    let entry = imports.entry(file_base.to_owned()).or_default();
    push_indent(body, indent);
    body.push_str(&operation.method);
    body.push_str(": {\n");
    if !operation.parameters.is_empty() {
        push_indent(body, indent + 2);
        body.push_str("parameters: {\n");
        for location in [
            ParamLocation::Path,
            ParamLocation::Query,
            ParamLocation::Header,
            ParamLocation::Cookie,
        ] {
            let matching = operation
                .parameters
                .iter()
                .zip(&parameter_names)
                .filter(|(parameter, _)| parameter.location == location)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                continue;
            }
            push_indent(body, indent + 4);
            body.push_str(location_key(location));
            body.push_str(": {\n");
            for (parameter, export_type) in matching {
                let validator = format!("{}Validator", lowercase_first(export_type));
                entry.insert(validator.clone());
                push_indent(body, indent + 6);
                body.push_str(&render_ts_string(&parameter.name));
                body.push_str(": ");
                body.push_str(&validator);
                body.push_str(",\n");
            }
            push_indent(body, indent + 4);
            body.push_str("},\n");
        }
        push_indent(body, indent + 2);
        body.push_str("},\n");
    }
    if operation.request_body.as_ref().is_some_and(|request_body| {
        request_body
            .media_types
            .iter()
            .any(|media| is_json(&media.essence))
    }) {
        let validator = format!("{}RequestBodyValidator", lowercase_first(&stem));
        entry.insert(validator.clone());
        push_indent(body, indent + 2);
        body.push_str("requestBody: ");
        body.push_str(&validator);
        body.push_str(",\n");
    }
    push_indent(body, indent);
    body.push_str("},\n");
}

fn location_key(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "path",
        ParamLocation::Query => "query",
        ParamLocation::Header => "header",
        ParamLocation::Cookie => "cookie",
    }
}

fn assemble_descriptor_index(
    model: &EmissionModel<'_, '_>,
    relative_path: &str,
    imports: BTreeMap<String, BTreeSet<String>>,
    body: String,
) -> GeneratedFile {
    let extension = import_extension(model);
    let mut content = model.header();
    for (file_base, names) in imports {
        content.push_str("import { ");
        content.push_str(&names.into_iter().collect::<Vec<_>>().join(", "));
        content.push_str(" } from ");
        content.push_str(&render_ts_string(&format!("./{file_base}{extension}")));
        content.push_str(";\n");
    }
    if !content.ends_with("\n\n") {
        content.push('\n');
    }
    content.push_str(&body);
    GeneratedFile {
        relative_path: relative_path.to_owned(),
        content,
    }
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
fn render_validator(export_type: &str, body: &str) -> String {
    let const_name = format!("{}Validator", lowercase_first(export_type));
    let mut output = String::new();
    output.push_str(&format!(
        "export function validate{export_type}(value: unknown, path: readonly (string | number)[], issues: Issue[]): void {{\n"
    ));
    output.push_str(body);
    output.push_str("}\n\n");
    output.push_str(&format!(
        "function checked{export_type}(value: unknown, issues: Issue[]): value is {export_type} {{\n  validate{export_type}(value, [], issues);\n  return issues.length === 0;\n}}\n\n"
    ));
    output.push_str(&format!(
        "export const {const_name}: SyncStandardSchemaV1<{export_type}> = {{\n"
    ));
    output.push_str("  \"~standard\": {\n");
    output.push_str("    version: 1,\n");
    output.push_str("    vendor: \"oasts\",\n");
    output.push_str("    validate(value) {\n");
    output.push_str("      const issues: Issue[] = [];\n");
    output.push_str(&format!(
        "      return checked{export_type}(value, issues) ? {{ value }} : {{ issues }};\n"
    ));
    output.push_str("    },\n");
    output.push_str("    types: undefined,\n");
    output.push_str("  },\n");
    output.push_str("};\n");
    output
}

// --- sibling import collection -----------------------------------------------------------------

/// Per-file-base type names and validate-function names imported from sibling validator files.
#[derive(Default)]
struct SiblingImports {
    files: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
}

impl SiblingImports {
    /// Records the type + validate imports for every `$ref` reachable from `schema` in `position`.
    /// `skip_self` excludes a component's self-reference (its own type and validate live locally).
    fn collect(
        &mut self,
        emitter: &Emitter<'_, '_, '_>,
        schema: &SchemaNode,
        position: TypePosition,
        skip_self: Option<usize>,
    ) {
        emitter.walk_refs(schema, position, &mut |target| {
            if Some(target.index) == skip_self {
                return;
            }
            let entry = self.files.entry(target.file_base.clone()).or_default();
            // Both the type name and the validate name resolve through the position variant, so the
            // import matches the name the body calls and the export the component actually emits —
            // `variant_name(Neutral)` is the bare name, leaving neutral imports unchanged.
            entry.0.insert(target.variant_name(position));
            entry
                .1
                .insert(format!("validate{}", target.variant_name(position)));
        });
    }
}

// --- file assembly -----------------------------------------------------------------------------

fn assemble_file(
    model: &EmissionModel<'_, '_>,
    sibling_prefix: &str,
    imports: &SiblingImports,
    scope: &FileScope,
    declarations: &[Decl],
) -> String {
    let extension = import_extension(model);
    let mut output = model.header();

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
    for (file_base, (type_names, value_names)) in &imports.files {
        let specifiers = type_names
            .iter()
            .map(|name| format!("type {name}"))
            .chain(value_names.iter().cloned())
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "import {{ {specifiers} }} from {};\n",
            render_ts_string(&format!("{sibling_prefix}{file_base}{extension}"))
        ));
    }
    output.push('\n');

    if scope.needs_is_record {
        output.push_str(
            "function isRecord(value: unknown): value is Record<string, unknown> {\n  return typeof value === \"object\" && value !== null && !Array.isArray(value);\n}\n\n",
        );
    }
    if scope.needs_is_array {
        output.push_str(
            "function isArray(value: unknown): value is readonly unknown[] {\n  return Array.isArray(value);\n}\n\n",
        );
    }
    for (slot, pattern) in scope.patterns.iter().enumerate() {
        output.push_str(&format!("let pattern{slot}: RegExp | undefined;\n"));
        output.push_str(&format!("function pattern{slot}Regex(): RegExp {{\n"));
        output.push_str(&format!(
            "  return (pattern{slot} ??= new RegExp({}));\n",
            render_ts_string(pattern)
        ));
        output.push_str("}\n\n");
    }

    for (index, declaration) in declarations.iter().enumerate() {
        output.push_str(&declaration.type_declaration);
        output.push('\n');
        output.push_str(&declaration.validator);
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
    use crate::config::load_config;
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::emit::emit_artifacts;
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;

    /// Compiles an OpenAPI document with the validators artifact enabled, returning the emitted
    /// files and the sorted diagnostics. Mirrors the pipeline stages so the reject walk runs.
    fn compile(document: Value) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write document");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated",
            "artifacts": { "types": true, "validators": true }
        });
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("input parses");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            None,
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
    fn oasts1400_rejects_colliding_media_tags() {
        // `application/json;a-b=1` and `application/json;a.b=1` mangle identically. The compiler
        // reports it rather than inventing a disambiguating suffix.
        let (_files, diagnostics) = compile(json!({
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
        }));
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_MEDIA_TAG_COLLISION)
            .expect("collision diagnostic");
        assert_eq!(collision.severity, Severity::Error);
        assert!(
            collision
                .message
                .contains("validateReadthingResponse200ApplicationJsonAB")
                || collision
                    .message
                    .contains("ReadthingResponse200ApplicationJsonAB"),
            "{}",
            collision.message
        );
    }

    #[test]
    fn media_tag_is_total_over_every_byte_class() {
        assert_eq!(media_tag("application/json"), "ApplicationJson");
        assert_eq!(
            media_tag("application/vnd.api+json"),
            "ApplicationVndApiJson"
        );
        assert_eq!(
            media_tag("application/json;stream=watch"),
            "ApplicationJsonStreamWatch"
        );
        assert_eq!(media_tag("text/*"), "TextWildcard");
        assert_eq!(media_tag("*/*"), "WildcardWildcard");
        // A leading digit and a bare separator run both survive without producing empty tokens.
        assert_eq!(media_tag("application/3d-model"), "Application3dModel");
        assert_eq!(media_tag("---"), "");
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
                    "e": { "type": "integer", "format": "int32" }
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
        assert!(content.contains("if (!isInt32(value4)) {"));
        assert!(content.contains("\"out of int32 range\""));
    }

    #[test]
    fn annotation_only_formats_assert_nothing_beyond_type() {
        let (files, diagnostics) = compile(doc_31(json!({
            "Thing": {
                "type": "object",
                "properties": {
                    "e": { "type": "string", "format": "email" },
                    "u": { "type": "string", "format": "uri" }
                }
            }
        })));
        assert_clean(&diagnostics);
        let content = component(&files, "thing");
        assert!(!content.contains("isEmail"));
        assert!(!content.contains("format"));
        // Both string properties still type-check but carry no format assertion.
        assert_eq!(content.matches("=== \"string\"").count(), 2);
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
        // The additional-properties iteration and both property-count bounds share `Object.keys`, so
        // it is evaluated once into a local and reused; it never recurs inline.
        assert!(bag.contains("const keys1 = Object.keys(value);"));
        assert!(bag.contains("for (const key of keys1) {"));
        assert!(bag.contains("if (key !== \"kind\") {"));
        assert!(bag.contains("const value2: unknown = value[key];"));
        assert!(bag.contains("if (keys1.length < 1) {"));
        assert!(
            bag.contains("issues.push(issue(path, \"fewer properties than minProperties 1\"));")
        );
        assert!(bag.contains("if (keys1.length > 3) {"));
        assert_eq!(bag.matches("Object.keys(value)").count(), 1);
        assert!(
            bag.contains("issues.push(issue(path, \"more properties than maxProperties 3\"));")
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
        // Each branch probe is guarded so anyOf stops once a branch has matched (matches0 >= 1).
        assert_eq!(content.matches("if (matches0 < 1) {").count(), 2);
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
        assert!(content.contains("validateCircle(value, path, issues1);"));
        assert!(content.contains("validateSquare(value, path, issues2);"));
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
    fn every_rejected_validation_keyword_fails_the_run_naming_keyword_and_pointer() {
        for keyword in [
            "if",
            "then",
            "else",
            "not",
            "dependentSchemas",
            "unevaluatedProperties",
            "unevaluatedItems",
            "contains",
            "minContains",
            "maxContains",
            "patternProperties",
            "propertyNames",
        ] {
            let (_files, diagnostics) = compile(doc_31(json!({
                "Rejected": { (keyword): true }
            })));
            let rejected = diagnostics
                .iter()
                .find(|d| d.code == "OASTS1501" && d.message.contains(keyword))
                .expect("rejected keyword fails with OASTS1501");
            assert_eq!(rejected.severity, Severity::Error);
            assert_eq!(
                rejected.json_pointer.as_deref(),
                Some("/components/schemas/Rejected")
            );
            // Exactly one validators-side diagnostic per rejected keyword: the same parse also
            // degrades the node to an unknown leaf, but OASTS1502 must not double-report it. (The
            // parse-time unsupported-keyword warning is a separate category and still fires.)
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|d| d.code == "OASTS1501" || d.code == "OASTS1502")
                    .count(),
                1,
                "rejected keyword '{keyword}' must raise exactly one validators diagnostic",
            );
        }
    }

    #[test]
    fn unknown_leaf_degradation_fails_the_run_naming_the_construct_and_pointer() {
        let (_files, diagnostics) = compile(doc_31(json!({
            "Degraded": { "$dynamicRef": "#thing" }
        })));
        let unknown = diagnostics
            .iter()
            .find(|d| d.code == "OASTS1502")
            .expect("unknown leaf fails with OASTS1502");
        assert_eq!(unknown.severity, Severity::Error);
        assert!(unknown.message.contains("$dynamicRef"));
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
        let resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph");
        let ir = parse(&graph, &mut sink).expect("ir");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            None,
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

    /// The reported bug: a `$ref` from a request body must delegate to the referent's Request-variant
    /// validator, not the Neutral one, which would demand a `readOnly` property the request type
    /// dropped. Symmetrically, a `$ref` from a response delegates to the Response variant.
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
            content.contains("validatePetRequest(value, path, issues);"),
            "{content}"
        );
        assert!(
            content.contains("validatePetResponse(value, path, issues);"),
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
    fn validator_descriptor_parameter_locations_are_total() {
        assert_eq!(location_key(ParamLocation::Path), "path");
        assert_eq!(location_key(ParamLocation::Query), "query");
        assert_eq!(location_key(ParamLocation::Header), "header");
        assert_eq!(location_key(ParamLocation::Cookie), "cookie");
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
            load_config(Some(&temp.path().join("oasts.json")), temp.path()).expect("config");
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
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut sink);
        let mut scope = FileScope::default();
        let mut body = FnBody::new(&mut scope, &model, TypePosition::Neutral);
        body.gen_finite(Some(&[]), None, "value", "path", "issues");
        assert!(body.out.contains("if (true) {"));
        assert!(
            body.out
                .contains("issues.push(issue(path, \"value not in enum\"));")
        );
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
        let resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph");
        let ir = parse(&graph, &mut sink).expect("ir");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            None,
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
        assert!(!any_items.contains("for (let index"));
        assert!(!any_items.contains("value0"));
        // A free-form additionalProperties schema emits no key iteration.
        let open_bag = component(&files, "openbag");
        assert!(open_bag.contains("if (isRecord(value)) {"));
        assert!(!open_bag.contains("Object.keys(value)"));
        assert!(!open_bag.contains("for (const key"));
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
            .find(|diagnostic| diagnostic.code == "OASTS1111")
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
        // The free-form rest schema emits no trailing-element loop.
        assert!(!content.contains("for (let index"));
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
                "export function validatePetRequest(value: unknown, path: readonly (string | number)[], issues: Issue[]): void {"
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
                "export function validatePetResponse(value: unknown, path: readonly (string | number)[], issues: Issue[]): void {"
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
