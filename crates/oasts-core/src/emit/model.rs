use foldhash::{HashMap, HashMapExt, HashSet};

use crate::config::ResolvedConfig;
use crate::diag::DiagnosticSink;
use crate::ir::{AdditionalProperties, SchemaNode, SourceRef, TupleRest};
use crate::semantic::Analyzed;

use crate::transform::TransformFacts;

use super::{
    CODE_FILE_NAME, CODE_PATH_COLLISION, CODE_VARIANT_ALIAS, CODE_VARIANT_COLLISION,
    CODE_WIRE_ALIAS, CODE_WIRE_COLLISION, TypePosition, file_base_name, shape_variants,
    source_diagnostic, warning_diagnostic,
};

#[derive(Clone, Debug)]
pub(crate) struct SchemaTarget {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) file_base: String,
    pub(crate) request_differs: bool,
    pub(crate) response_differs: bool,
    /// The name this component's request-position variant exports under when the derived
    /// `{name}Request` is already a declared component's name. `None` — the overwhelmingly common
    /// case — means `variant_name` derives it, so a document without a collision allocates exactly
    /// as it did before this field existed.
    pub(crate) request_variant: Option<String>,
    pub(crate) response_variant: Option<String>,
    /// The name each position's wire twin exports under when the derived `{base}Wire` is already a
    /// declared component's name, indexed by [`TypePosition::index`]. `None` — the overwhelmingly
    /// common case — means `wire_name` derives it, so a document without a collision allocates
    /// exactly as it did before this field existed.
    pub(crate) wire_variants: [Option<String>; 3],
    /// Whether this component reaches a date/time transform, and so declares wire twins at all.
    pub(crate) transforms: bool,
}

/// Shared deterministic allocation product for all emitters.
pub(crate) struct EmissionModel<'input, 'sink> {
    pub(crate) analyzed: &'input Analyzed,
    pub(crate) config: &'input ResolvedConfig,
    digest: String,
    schema_targets: HashMap<String, HashMap<String, SchemaTarget>>,
    pub(crate) component_files: Vec<Option<String>>,
    pub(crate) operation_files: Vec<Option<String>>,
    /// Parallel to `analyzed.webhook_names`: the file base each webhook operation emits to under
    /// `types/webhooks/`, or `None` if its name failed file-base validation.
    pub(crate) webhook_files: Vec<Option<String>>,
    /// Parallel to `analyzed.callback_names`: the file base each callback operation emits to under
    /// `types/callbacks/`, or `None` if its name failed file-base validation.
    pub(crate) callback_files: Vec<Option<String>>,
    seen: HashMap<String, (String, SourceRef)>,
    /// Which schemas reach a date/time transform, computed once here so every emitter reads one
    /// answer rather than recomputing it or threading it through every render call.
    transform_facts: TransformFacts<'input>,
    pub(crate) sink: &'sink mut DiagnosticSink,
}

impl<'input, 'sink> EmissionModel<'input, 'sink> {
    pub(crate) fn new(
        analyzed: &'input Analyzed,
        config: &'input ResolvedConfig,
        digest: String,
        sink: &'sink mut DiagnosticSink,
    ) -> Self {
        let mut model = Self {
            analyzed,
            config,
            digest,
            schema_targets: HashMap::new(),
            component_files: vec![None; analyzed.ir.schemas.len()],
            operation_files: vec![None; analyzed.ir.operations.len()],
            webhook_files: vec![None; analyzed.webhook_names.len()],
            callback_files: vec![None; analyzed.callback_names.len()],
            seen: HashMap::new(),
            transform_facts: TransformFacts::compute(&analyzed.ir, config),
            sink,
        };
        model.allocate_paths();
        model.resolve_variant_shapes();
        // After variance, because a wire name composes onto `variant_name(position)` — including the
        // alias a variant collision assigned — and never onto the derived name.
        model.resolve_wire_names();
        model
    }

    /// The transform reachability this compile was configured for.
    pub(crate) fn transform_facts(&self) -> &TransformFacts<'input> {
        &self.transform_facts
    }

    /// Names each transforming component's wire twins, one per declaring position.
    ///
    /// The derived name is `{base}Wire` where `base` is `variant_name(position)`. That composition is
    /// injective: bases are globally unique after variance resolution, and `x -> x + "Wire"` preserves
    /// that, so two components can never derive the same twin name and no cross-component bookkeeping
    /// is needed here. A derived name can only ever collide with a *declared* component, which is the
    /// one thing this pass checks.
    ///
    /// It also cannot collide with another generated variant or alias: those end in `Request`,
    /// `Response`, or `Body`, and this ends in `Wire`.
    ///
    /// Fast-reject: with no representation transforming, nothing declares a twin and the pass returns
    /// before allocating, keeping a default-configured document allocation-identical.
    fn resolve_wire_names(&mut self) {
        if !self.transform_facts.enabled() {
            return;
        }
        let declared: HashSet<&str> = self
            .schema_targets
            .values()
            .flat_map(|by_pointer| by_pointer.values())
            .map(|target| target.name.as_str())
            .collect();
        let mut diagnostics = Vec::new();
        let mut assignments: Vec<(String, String, bool, [Option<String>; 3])> = Vec::new();
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            let Some(target) =
                self.schema_target(&schema.source.source_id, &schema.source.json_pointer)
            else {
                continue;
            };
            let transforms = self.transform_facts.component(allocated.schema_index);
            let mut wire_variants = [None, None, None];
            if transforms {
                for position in [
                    TypePosition::Neutral,
                    TypePosition::Request,
                    TypePosition::Response,
                ] {
                    if target.wire_export_base(position).is_none() {
                        continue;
                    }
                    let derived = format!("{}Wire", target.variant_name(position));
                    if !declared.contains(derived.as_str()) {
                        // Stored even when nothing collides, for the reason `reserve_names` gives
                        // about variant overrides: a later rename would otherwise re-derive this
                        // name from one that pass invented, and nothing re-checks that derivation
                        // against the declared components.
                        wire_variants[position.index()] = Some(derived);
                        continue;
                    }
                    let replacement = format!("{derived}Value");
                    if declared.contains(replacement.as_str()) {
                        diagnostics.push(source_diagnostic(
                            CODE_WIRE_COLLISION,
                            format!(
                                "generated wire type name '{derived}' for component '{owner}' collides with component '{derived}', and the replacement name '{replacement}' is already taken; rename one with naming.overrides",
                                owner = target.name,
                            ),
                            &schema.source,
                        ));
                        continue;
                    }
                    diagnostics.push(warning_diagnostic(
                        CODE_WIRE_ALIAS,
                        format!(
                            "generated wire type name '{derived}' for component '{owner}' collides with component '{derived}'; emitting it as '{replacement}'",
                            owner = target.name,
                        ),
                        &schema.source,
                    ));
                    wire_variants[position.index()] = Some(replacement);
                }
            }
            assignments.push((
                schema.source.source_id.clone(),
                schema.source.json_pointer.clone(),
                transforms,
                wire_variants,
            ));
        }
        drop(declared);
        for (source_id, json_pointer, transforms, wire_variants) in assignments {
            // Infallible: the key came from a successful `schema_target` lookup above, and nothing
            // between there and here removes an entry.
            let target = self
                .schema_targets
                .get_mut(&source_id)
                .and_then(|by_pointer| by_pointer.get_mut(&json_pointer))
                .expect("a wire-named component resolves through the key it was found under");
            target.transforms = transforms;
            target.wire_variants = wire_variants;
        }
        self.sink.extend(diagnostics);
    }

    /// Propagates request/response variance across the component reference graph to a fixpoint.
    ///
    /// `shape_variants` decides variance from each component's own inline structure but stops at a
    /// `$ref` — a graph edge, not crossed there. A component with no local read/write-only marker
    /// still needs a variant when it references one that does: in that position its rendering names
    /// the referent's variant type, so the neutral and variant renderings diverge. This pass closes
    /// that gap. It seeds each component's flags from `shape_variants`, then repeatedly ORs a
    /// referent's flags into every referrer until nothing changes. Monotone false->true, so the
    /// fixpoint is order-independent and deterministic regardless of graph shape or cycles.
    ///
    /// Fast-reject: with no marker set anywhere, no variance can propagate, so the pass returns
    /// before allocating any working buffer — the common marker-free input stays zero-heap, matching
    /// the pre-pass allocation profile the drift gate pins.
    fn resolve_variant_shapes(&mut self) {
        let any_variance = self.schema_targets.values().any(|by_pointer| {
            by_pointer
                .values()
                .any(|target| target.request_differs || target.response_differs)
        });
        if !any_variance {
            return;
        }

        let count = self.analyzed.ir.schemas.len();
        let mut request = vec![false; count];
        let mut response = vec![false; count];
        let mut edges: Vec<Vec<usize>> = vec![Vec::new(); count];
        for allocated in &self.analyzed.schema_names {
            let index = allocated.schema_index;
            let schema = &self.analyzed.ir.schemas[index];
            let Some(target) =
                self.schema_target(&schema.source.source_id, &schema.source.json_pointer)
            else {
                continue;
            };
            request[index] = target.request_differs;
            response[index] = target.response_differs;
            let mut referenced = Vec::new();
            self.collect_ref_edges(&schema.schema, &mut referenced);
            referenced.sort_unstable();
            referenced.dedup();
            edges[index] = referenced;
        }

        let mut changed = true;
        while changed {
            changed = false;
            for source in 0..count {
                for &referent in &edges[source] {
                    if request[referent] && !request[source] {
                        request[source] = true;
                        changed = true;
                    }
                    if response[referent] && !response[source] {
                        response[source] = true;
                        changed = true;
                    }
                }
            }
        }

        // `self.analyzed` is a Copy `&'input` reference, so writing back through it borrows the
        // schema names disjointly from `self.schema_targets` — no cached key vector is needed to
        // separate the read from the `get_mut`.
        let analyzed = self.analyzed;
        for allocated in &analyzed.schema_names {
            let index = allocated.schema_index;
            let source = &analyzed.ir.schemas[index].source;
            if let Some(target) = self
                .schema_targets
                .get_mut(&source.source_id)
                .and_then(|by_pointer| by_pointer.get_mut(&source.json_pointer))
            {
                target.request_differs = request[index];
                target.response_differs = response[index];
            }
        }

        self.resolve_variant_collisions();
    }

    /// Renames a generated `{Name}Request`/`{Name}Response` variant that collides with a
    /// component's own exported type name: both would export the same identifier from different
    /// files, and any module needing both would emit two conflicting imports — a load-time
    /// SyntaxError/TS2300 the semantic-stage exact-collision check (which runs before variance is
    /// resolved) structurally cannot see. The document's own component name is its public API and
    /// stays put; the derived name is the compiler's invention, so it is the one that yields, to
    /// `{Name}RequestBody`/`{Name}ResponseBody` — the same role-derived word `assign_import_aliases`
    /// uses for the analogous import-shadowing case. Renaming here rather than at the reference
    /// sites means one name globally: every reference, sibling import and validator declaration
    /// follows through `SchemaTarget::variant_name`, and the result is order-independent, so the
    /// same document always produces the same identifier. It warns rather than staying silent
    /// because, unlike the file-local import alias, an exported name changes.
    ///
    /// Reached only after the fast-reject above returns for variance-free input, so a document with
    /// no read/write-only marker never runs this and stays allocation-identical (the allocs gate
    /// pins committed fixtures, several of which carry variance). `schema_targets` is keyed by
    /// source_id/json_pointer, not name, so resolving a suffix-stripped prefix against it directly
    /// would mean a linear scan per suffixed component — O(suffixed components x all components).
    /// Instead this builds one `name -> target` index up front (deterministic first-wins insertion,
    /// walking `schema_names` in order so a duplicate-name input — already erroring elsewhere via
    /// the semantic-stage exact-collision check — still indexes deterministically) and resolves
    /// every suffix-strip against it in O(1), keeping the whole pass O(N). Two variant names can
    /// never collide with each other (that needs equal base names, which the exact-collision check
    /// already blocks), so a variant-vs-base scan against the index is complete.
    ///
    /// The replacement is one fixed candidate, never a search: a numeric fallback would be
    /// order-dependent and produce unstable public API. When it is itself taken — by a declared
    /// component or by a replacement handed out earlier in this pass — nothing compiler-invented
    /// remains, so that residual is fatal and points at `naming.overrides`.
    ///
    /// `schema_names` order fixes diagnostic order; one diagnostic per collision.
    fn resolve_variant_collisions(&mut self) {
        let mut by_name: HashMap<&str, &SchemaTarget> = HashMap::new();
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            if let Some(target) =
                self.schema_target(&schema.source.source_id, &schema.source.json_pointer)
            {
                by_name.entry(target.name.as_str()).or_insert(target);
            }
        }

        let mut diagnostics = Vec::new();
        // Both stay empty until a collision actually fires, so the common path allocates nothing.
        let mut assigned: Vec<String> = Vec::new();
        let mut renames: Vec<(String, String, bool, String)> = Vec::new();
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            let Some(shadowed) =
                self.schema_target(&schema.source.source_id, &schema.source.json_pointer)
            else {
                continue;
            };
            for (suffix, request) in [("Request", true), ("Response", false)] {
                let Some(prefix) = shadowed.name.strip_suffix(suffix) else {
                    continue;
                };
                let owner = by_name.get(prefix).copied().filter(|candidate| {
                    if request {
                        candidate.request_differs
                    } else {
                        candidate.response_differs
                    }
                });
                let Some(owner) = owner else {
                    continue;
                };
                let source = &self.analyzed.ir.schemas[owner.index].source;
                let alias = format!("{}Body", shadowed.name);
                if by_name.contains_key(alias.as_str()) || assigned.contains(&alias) {
                    diagnostics.push(source_diagnostic(
                        CODE_VARIANT_ALIAS,
                        format!(
                            "generated variant name '{shadowed}' for component '{owner}' collides with component '{shadowed}', and the replacement name '{alias}' is already taken; rename one with naming.overrides",
                            shadowed = shadowed.name,
                            owner = owner.name,
                        ),
                        source,
                    ));
                    continue;
                }
                diagnostics.push(warning_diagnostic(
                    CODE_VARIANT_COLLISION,
                    format!(
                        "generated variant name '{shadowed}' for component '{owner}' collides with component '{shadowed}'; emitting it as '{alias}'",
                        shadowed = shadowed.name,
                        owner = owner.name,
                    ),
                    source,
                ));
                renames.push((
                    source.source_id.clone(),
                    source.json_pointer.clone(),
                    request,
                    alias.clone(),
                ));
                assigned.push(alias);
            }
        }
        drop(by_name);
        for (source_id, json_pointer, request, alias) in renames {
            // Infallible: the key was produced by a successful `schema_target` lookup above, and
            // nothing between there and here removes an entry.
            let target = self
                .schema_targets
                .get_mut(&source_id)
                .and_then(|by_pointer| by_pointer.get_mut(&json_pointer))
                .expect("a renamed variant's owner resolves through the key it was found under");
            if request {
                target.request_variant = Some(alias);
            } else {
                target.response_variant = Some(alias);
            }
        }
        for diagnostic in diagnostics {
            self.sink.push(diagnostic);
        }
    }

    /// Records the target index of every component `$ref` reachable from `schema` through the same
    /// inline structure `shape_variants` walks. A `$ref` is terminal here — it records the edge and
    /// stops; the referent's own edges are collected when it is visited as a source. Stack-only.
    fn collect_ref_edges(&self, schema: &SchemaNode, edges: &mut Vec<usize>) {
        match schema {
            SchemaNode::Ref { target, .. } => {
                if let Some(target) = self.schema_target(&target.source_id, &target.json_pointer) {
                    edges.push(target.index);
                }
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                for (_, property, _) in properties {
                    self.collect_ref_edges(property, edges);
                }
                if let AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) = additional_properties
                {
                    self.collect_ref_edges(schema, edges);
                }
            }
            SchemaNode::Array { items, .. } => self.collect_ref_edges(items, edges),
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for item in prefix_items {
                    self.collect_ref_edges(item, edges);
                }
                if let TupleRest::Schema(schema) = rest {
                    self.collect_ref_edges(schema, edges);
                }
            }
            SchemaNode::AllOf { branches, .. }
            | SchemaNode::AnyOf { branches, .. }
            | SchemaNode::OneOf { branches, .. } => {
                for branch in branches {
                    self.collect_ref_edges(branch, edges);
                }
            }
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => {}
        }
        let applicators = schema.meta().validation_applicators();
        if let Some(schema) = &applicators.not {
            self.collect_ref_edges(schema, edges);
        }
        if let Some(schema) = &applicators.property_names {
            self.collect_ref_edges(schema, edges);
        }
        for pattern in &applicators.pattern_properties {
            self.collect_ref_edges(&pattern.schema, edges);
        }
        if let Some(contains) = &applicators.contains {
            self.collect_ref_edges(&contains.schema, edges);
        }
        for (_, schema) in &applicators.dependent_schemas {
            self.collect_ref_edges(schema, edges);
        }
        if let Some(conditional) = &applicators.conditional {
            self.collect_ref_edges(&conditional.condition, edges);
            if let Some(schema) = &conditional.then_schema {
                self.collect_ref_edges(schema, edges);
            }
            if let Some(schema) = &conditional.else_schema {
                self.collect_ref_edges(schema, edges);
            }
        }
        if let Some(schema) = &applicators.unevaluated_properties {
            self.collect_ref_edges(schema, edges);
        }
        if let Some(schema) = &applicators.unevaluated_items {
            self.collect_ref_edges(schema, edges);
        }
    }

    fn allocate_paths(&mut self) {
        for allocated in &self.analyzed.schema_names {
            let schema = &self.analyzed.ir.schemas[allocated.schema_index];
            let source_name = if self
                .config
                .naming
                .overrides
                .schemas
                .contains_key(&allocated.wire_name)
            {
                &allocated.name
            } else {
                &allocated.wire_name
            };
            let Some(file_base) = self.allocate_file_base(source_name, &schema.source) else {
                continue;
            };
            let relative = format!("types/components/{file_base}.ts");
            self.register_path(&relative, &schema.source);
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
                        request_variant: None,
                        response_variant: None,
                        wire_variants: [None, None, None],
                        transforms: false,
                    },
                );
        }
        for allocated in &self.analyzed.operation_names {
            let operation = &self.analyzed.ir.operations[allocated.operation_index];
            let source_name =
                operation
                    .operation_id
                    .as_deref()
                    .map_or(allocated.name.as_str(), |operation_id| {
                        if self
                            .config
                            .naming
                            .overrides
                            .operations
                            .contains_key(operation_id)
                        {
                            &allocated.name
                        } else {
                            operation_id
                        }
                    });
            let Some(file_base) = self.allocate_file_base(source_name, &operation.source) else {
                continue;
            };
            let relative = format!("types/operations/{file_base}.ts");
            self.register_path(&relative, &operation.source);
            self.operation_files[allocated.operation_index] = Some(file_base);
        }
        // Webhook and callback operations mirror the path-operation branch exactly (operationId if
        // present, else the allocated stem), but emit to their own `types/webhooks/` and
        // `types/callbacks/` directories, so their file bases never collide with operations across
        // directories — only within their own directory, which `register_path` still guards.
        for (index, allocated) in self.analyzed.webhook_names.iter().enumerate() {
            let operation = &self.analyzed.ir.webhooks[allocated.webhook_index].operations
                [allocated.operation_index];
            let source_name = operation.operation_id.as_deref().unwrap_or(&allocated.stem);
            let source = allocated.source.clone();
            let Some(file_base) = self.allocate_file_base(source_name, &source) else {
                continue;
            };
            let relative = format!("types/webhooks/{file_base}.ts");
            self.register_path(&relative, &source);
            self.webhook_files[index] = Some(file_base);
        }
        for (index, allocated) in self.analyzed.callback_names.iter().enumerate() {
            let operation = super::callback_operation(
                &self.analyzed.ir,
                &self.analyzed.callback_names,
                allocated,
            );
            let source_name = operation.operation_id.as_deref().unwrap_or(&allocated.stem);
            let source = allocated.source.clone();
            let Some(file_base) = self.allocate_file_base(source_name, &source) else {
                continue;
            };
            let relative = format!("types/callbacks/{file_base}.ts");
            self.register_path(&relative, &source);
            self.callback_files[index] = Some(file_base);
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

    /// Registers an artifact path in the shared case-folded collision namespace.
    pub(crate) fn register_path(&mut self, path: &str, source: &SourceRef) {
        let folded = path.to_ascii_lowercase();
        if let Some((previous, previous_source)) = self.seen.get(&folded) {
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
            self.seen.insert(folded, (path.to_owned(), source.clone()));
        }
    }

    pub(crate) fn schema_target(
        &self,
        source_id: &str,
        json_pointer: &str,
    ) -> Option<&SchemaTarget> {
        self.schema_targets.get(source_id)?.get(json_pointer)
    }

    /// Renames component target names that collide with identifiers a terminal emitter injects into
    /// every one of its files (e.g. the validators kernel imports and helpers), so an exported type
    /// never shadows an imported one (TS2440). All name usages — the component's own export, its
    /// self/cross references, sibling imports, and the rendered structural type — read the target
    /// name, so mutating it here keeps every site consistent. Only exact (case-sensitive) matches
    /// are renamed, since that is what actually conflicts in a TypeScript module scope; colliding
    /// names get the lowest free numeric suffix, deterministically across runs. Call this only from
    /// the last emitter to run: it mutates the shared allocation, and any emitter reading target
    /// names afterward would see the renamed set.
    pub(crate) fn reserve_names(&mut self, reserved: &[&str]) {
        let analyzed = self.analyzed;
        let mut taken: HashSet<String> = reserved.iter().map(|name| (*name).to_owned()).collect();
        for targets in self.schema_targets.values() {
            for target in targets.values() {
                taken.insert(target.name.clone());
            }
        }
        for allocated in &analyzed.schema_names {
            let schema = &analyzed.ir.schemas[allocated.schema_index];
            let Some(target) = self
                .schema_targets
                .get_mut(&schema.source.source_id)
                .and_then(|by_pointer| by_pointer.get_mut(&schema.source.json_pointer))
            else {
                continue;
            };
            if !reserved.contains(&target.name.as_str()) {
                continue;
            }
            let base = target.name.clone();
            let mut suffix = 2u32;
            let mut candidate = format!("{base}{suffix}");
            while taken.contains(&candidate) {
                suffix += 1;
                candidate = format!("{base}{suffix}");
            }
            taken.insert(candidate.clone());
            target.name = candidate;
            // A variant override survives the rename deliberately. Clearing it would re-derive
            // `{newName}Request` from a name this pass invented, and nothing re-checks that
            // derivation against the declared components — a document declaring both `Issue` and
            // `Issue2Request` would then export `Issue2Request` from two modules with no
            // diagnostic. The stored alias is still globally unique (it was checked against every
            // declared name when it was assigned, and `taken` here can never re-mint it), so
            // keeping it is the collision-free choice even though it no longer echoes the new name.
        }
    }

    pub(crate) fn header(&self) -> String {
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
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::config::load_config;
    use crate::emit::source_digest;
    use crate::ir::{SchemaMeta, SchemaRef};
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;

    /// Runs the pipeline through analysis (config load, graph load, parse, semantic analyze) for
    /// an inline `components.schemas` document, stopping short of `EmissionModel::new` so each
    /// caller can construct its own model against its own `DiagnosticSink` — the model-affecting
    /// diagnostics (e.g. OASTS1306 variant collisions) only exist after that call, so a shared sink
    /// here would either hide them from `variant_collisions` or leak unrelated pipeline warnings
    /// into it. Returns the owned outputs a caller needs for that call: the `TempDir` (kept alive
    /// so the config's relative `input.path` still resolves), the resolved config, the analyzed
    /// IR, and the source digest.
    fn build_model_inputs(schemas: Value) -> (TempDir, ResolvedConfig, Analyzed, String) {
        build_model_inputs_with(schemas, |_| {})
    }

    /// `build_model_inputs`, with `patch` applied to the resolved config before analysis. The config
    /// guard still refuses a non-`string` date representation at load time, so a test wanting one
    /// sets it here — which is what every later pass reads.
    pub(super) fn build_model_inputs_with(
        schemas: Value,
        patch: fn(&mut ResolvedConfig),
    ) -> (TempDir, ResolvedConfig, Analyzed, String) {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        });
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write document");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "./openapi.json" },
            "output": "./generated"
        });
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("write config");
        let mut resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        patch(&mut resolved);
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("input parses");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let digest = source_digest(&graph.source_tuples());
        (temp, resolved, analyzed, digest)
    }

    /// Looks up the `SchemaTarget` allocated for the component named `name`. `schema_targets` is
    /// keyed by source_id/json_pointer, not name, so every by-name lookup in this module's tests
    /// scans the same way.
    pub(super) fn find_target<'a>(
        model: &'a EmissionModel<'_, '_>,
        name: &str,
    ) -> &'a SchemaTarget {
        model
            .schema_targets
            .values()
            .flat_map(|by_pointer| by_pointer.values())
            .find(|target| target.name == name)
            .expect("component target present")
    }

    /// Runs the pipeline through model construction and returns the resolved
    /// `(request_differs, response_differs)` flags for the component whose allocated name is
    /// `component`. The flags are what every emitter reads to decide whether to emit variants.
    fn variant_flags(schemas: Value, component: &str) -> (bool, bool) {
        let (_temp, resolved, analyzed, digest) = build_model_inputs(schemas);
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);
        let target = find_target(&model, component);
        (target.request_differs, target.response_differs)
    }

    /// A component with no direct read/write-only marker still needs a Request variant when it
    /// references a component that does: its request-position rendering names the referent's
    /// variant, so the two positions diverge.
    #[test]
    fn ref_transitivity_request() {
        let schemas = json!({
            "Envelope": {
                "type": "object",
                "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
            },
            "Pet": {
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas.clone(), "Pet"), (true, false));
        assert_eq!(variant_flags(schemas, "Envelope"), (true, false));
    }

    /// Variance flows the full length of a `A -> B -> Pet` reference chain, not just one hop.
    #[test]
    fn ref_transitivity_two_hop() {
        let schemas = json!({
            "A": {
                "type": "object",
                "properties": { "b": { "$ref": "#/components/schemas/B" } }
            },
            "B": {
                "type": "object",
                "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
            },
            "Pet": {
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas.clone(), "A"), (true, false));
        assert_eq!(variant_flags(schemas.clone(), "B"), (true, false));
        assert_eq!(variant_flags(schemas, "Pet"), (true, false));
    }

    /// Response variance propagates independently of request variance: a `writeOnly` referent forces
    /// only the Response variant up the chain.
    #[test]
    fn ref_transitivity_response() {
        let schemas = json!({
            "Envelope": {
                "type": "object",
                "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
            },
            "Pet": {
                "type": "object",
                "properties": { "secret": { "type": "string", "writeOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas.clone(), "Pet"), (false, true));
        assert_eq!(variant_flags(schemas, "Envelope"), (false, true));
    }

    /// A reference graph with no read/write-only marker anywhere resolves to no variants — the
    /// fast-reject path that keeps the pass zero-heap for the common case.
    #[test]
    fn fixpoint_no_differs_skips() {
        let schemas = json!({
            "A": {
                "type": "object",
                "properties": { "b": { "$ref": "#/components/schemas/B" } }
            },
            "B": {
                "type": "object",
                "properties": { "name": { "type": "string" } }
            }
        });
        assert_eq!(variant_flags(schemas.clone(), "A"), (false, false));
        assert_eq!(variant_flags(schemas, "B"), (false, false));
    }

    /// A component whose generated file name is invalid (a Windows reserved device name) never
    /// gets a `SchemaTarget`, so the fixpoint's seeding loop skips it via `continue` rather than
    /// panicking on the missing lookup; every resolvable component's flags are unaffected.
    #[test]
    fn unresolvable_schema_target_skipped_in_fixpoint() {
        let schemas = json!({
            "CON": { "type": "string" },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas, "Pet"), (true, false));
    }

    /// Variance flows through a `$ref` reached via `additionalProperties` holding a schema (not a
    /// bare `true`/`false`), matching the renderer, which inlines the same map-value schema.
    #[test]
    fn ref_transitivity_through_additional_properties_schema() {
        let schemas = json!({
            "Registry": {
                "type": "object",
                "additionalProperties": { "$ref": "#/components/schemas/Pet" }
            },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas, "Registry"), (true, false));
    }

    /// Variance flows through a `$ref` reached via a tuple's rest-item schema (`items` alongside
    /// `prefixItems`), matching the renderer, which inlines the same schema for elements beyond
    /// the fixed prefix.
    #[test]
    fn ref_transitivity_through_tuple_rest() {
        let schemas = json!({
            "Coords": {
                "type": "array",
                "prefixItems": [{ "type": "number" }],
                "items": { "$ref": "#/components/schemas/Pet" }
            },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(variant_flags(schemas, "Coords"), (true, false));
    }

    /// Variance flows through a `$ref` reached via an `anyOf` or `oneOf` branch, matching the
    /// renderer, which inlines each branch.
    #[test]
    fn ref_transitivity_through_any_of_and_one_of() {
        let schemas = json!({
            "AnyOfComponent": {
                "anyOf": [
                    { "$ref": "#/components/schemas/Pet" },
                    { "type": "string" }
                ]
            },
            "OneOfComponent": {
                "oneOf": [
                    { "$ref": "#/components/schemas/Pet" },
                    { "type": "string" }
                ]
            },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(
            variant_flags(schemas.clone(), "AnyOfComponent"),
            (true, false)
        );
        assert_eq!(variant_flags(schemas, "OneOfComponent"), (true, false));
    }

    #[test]
    fn ref_transitivity_through_validation_applicators() {
        let schemas = json!({
            "NotComponent": {
                "not": { "$ref": "#/components/schemas/Pet" }
            },
            "PropertyNamesComponent": {
                "propertyNames": { "$ref": "#/components/schemas/Pet" }
            },
            "PatternPropertiesComponent": {
                "patternProperties": {
                    "^x": { "$ref": "#/components/schemas/Pet" }
                }
            },
            "ContainsComponent": {
                "contains": { "$ref": "#/components/schemas/Pet" }
            },
            "DependentSchemasComponent": {
                "dependentSchemas": {
                    "trigger": { "$ref": "#/components/schemas/Pet" }
                }
            },
            "ConditionalComponent": {
                "if": { "$ref": "#/components/schemas/Pet" },
                "then": { "$ref": "#/components/schemas/Pet" },
                "else": { "$ref": "#/components/schemas/Pet" }
            },
            "UnevaluatedPropertiesComponent": {
                "unevaluatedProperties": { "$ref": "#/components/schemas/Pet" }
            },
            "UnevaluatedItemsComponent": {
                "unevaluatedItems": { "$ref": "#/components/schemas/Pet" }
            },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        });
        assert_eq!(
            variant_flags(schemas.clone(), "NotComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "PropertyNamesComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "PatternPropertiesComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "ContainsComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "DependentSchemasComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "ConditionalComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas.clone(), "UnevaluatedPropertiesComponent"),
            (true, false)
        );
        assert_eq!(
            variant_flags(schemas, "UnevaluatedItemsComponent"),
            (true, false)
        );
    }

    /// `additionalProperties: <schema>` from real input always parses to `AdditionalProperties::
    /// Schema` (see `parse::mod`'s `additionalProperties` handling); `Allowed(Some(schema))` is a
    /// construction-only variant no parser path ever emits, but `collect_ref_edges` treats it
    /// identically via the shared match arm. A document-based test can never reach it through
    /// parsing, so it is exercised directly against a hand-built schema, the same way
    /// `semantic.rs`'s own enum-traversal test covers the same variant for its own consumer.
    #[test]
    fn collect_ref_edges_treats_allowed_some_like_schema() {
        let (_temp, resolved, analyzed, digest) = build_model_inputs(json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            }
        }));
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);

        let source_id = analyzed.ir.schemas[0].source.source_id.clone();
        let pet_ref = SchemaNode::Ref {
            target: SchemaRef {
                source_id,
                json_pointer: "/components/schemas/Pet".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let synthetic = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(pet_ref))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: SchemaMeta::default(),
        };
        let mut edges = Vec::new();
        model.collect_ref_edges(&synthetic, &mut edges);
        let pet_index = find_target(&model, "Pet").index;
        assert_eq!(edges, vec![pet_index]);
    }

    /// Builds the model for `schemas` and returns the diagnostics it produced under `code`.
    fn model_diagnostics(schemas: Value, code: &str) -> Vec<crate::diag::Diagnostic> {
        let (_temp, resolved, analyzed, digest) = build_model_inputs(schemas);
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);
        drop(model);
        sink.into_sorted_vec()
            .into_iter()
            .filter(|diagnostic| diagnostic.code == code)
            .collect()
    }

    /// The OASTS1306 rename warnings for `schemas`.
    fn variant_collisions(schemas: Value) -> Vec<crate::diag::Diagnostic> {
        model_diagnostics(schemas, "OASTS1306")
    }

    /// The OASTS1310 residual-collision errors for `schemas` — the replacement name was taken too.
    fn variant_alias_collisions(schemas: Value) -> Vec<crate::diag::Diagnostic> {
        model_diagnostics(schemas, "OASTS1310")
    }

    /// A component literally named `PetRequest` shadows the synthetic `PetRequest` that `Pet`'s
    /// readOnly property forces: both would export the same identifier from different files, a
    /// load-time error the semantic-stage exact-collision check cannot see (it runs before variance
    /// is resolved). The document's own component keeps its name and the derived variant — the
    /// compiler's own invention — takes the role-derived replacement.
    #[test]
    fn variant_collision_request_renames_the_derived_variant_and_warns() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "PetRequest": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_collisions(schemas);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].severity, crate::diag::Severity::Warning);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'PetRequest' for component 'Pet' collides with component 'PetRequest'; emitting it as 'PetRequestBody'"
        );
    }

    /// The replacement is a single fixed candidate, not a search: when `PetRequestBody` is itself a
    /// declared component the compiler has nothing left to invent, so the document is refused.
    #[test]
    fn a_variant_alias_that_is_itself_declared_is_a_fatal_collision() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "PetRequest": {
                "type": "object",
                "properties": { "name": { "type": "string" } }
            },
            "PetRequestBody": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_alias_collisions(schemas);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].severity, crate::diag::Severity::Error);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'PetRequest' for component 'Pet' collides with component 'PetRequest', and the replacement name 'PetRequestBody' is already taken; rename one with naming.overrides"
        );
    }

    /// Two owners whose derived variants both collide each get their own replacement, and the
    /// second sees the first's — the taken-set is declared names plus aliases already handed out.
    #[test]
    fn a_second_collision_sees_the_first_alias_as_taken() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "PetRequest": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "PetRequestRequest": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_collisions(schemas);
        assert_eq!(flagged.len(), 2);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'PetRequest' for component 'Pet' collides with component 'PetRequest'; emitting it as 'PetRequestBody'"
        );
        assert_eq!(
            flagged[1].message,
            "generated variant name 'PetRequestRequest' for component 'PetRequest' collides with component 'PetRequestRequest'; emitting it as 'PetRequestRequestBody'"
        );
    }

    /// The variant a component generates through transitive variance also collides: `Envelope`
    /// gains a Request variant only because it references the readOnly `Pet`, and a component named
    /// `EnvelopeRequest` shadows it.
    #[test]
    fn variant_collision_flags_transitive_variance() {
        let schemas = json!({
            "Envelope": {
                "type": "object",
                "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
            },
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "EnvelopeRequest": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_collisions(schemas);
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'EnvelopeRequest' for component 'Envelope' collides with component 'EnvelopeRequest'; emitting it as 'EnvelopeRequestBody'"
        );
    }

    /// A writeOnly-forced Response variant collides the same way, and a component ending in
    /// `Request` whose stripped prefix names no varying component (`StrayRequest`) does not — the
    /// suffix match must resolve to an actually-varying owner.
    #[test]
    fn variant_collision_flags_response_and_ignores_unmatched_suffix() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "secret": { "type": "string", "writeOnly": true } }
            },
            "PetResponse": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            },
            "StrayRequest": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_collisions(schemas);
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'PetResponse' for component 'Pet' collides with component 'PetResponse'; emitting it as 'PetResponseBody'"
        );
    }

    /// The response mirror of the residual-fatal case: a taken `{Name}ResponseBody` is refused the
    /// same way, so neither position can silently fall through to a colliding declaration.
    #[test]
    fn a_response_variant_alias_that_is_itself_declared_is_a_fatal_collision() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "secret": { "type": "string", "writeOnly": true } }
            },
            "PetResponse": {
                "type": "object",
                "properties": { "name": { "type": "string" } }
            },
            "PetResponseBody": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        let flagged = variant_alias_collisions(schemas);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].severity, crate::diag::Severity::Error);
        assert_eq!(
            flagged[0].message,
            "generated variant name 'PetResponse' for component 'Pet' collides with component 'PetResponse', and the replacement name 'PetResponseBody' is already taken; rename one with naming.overrides"
        );
    }

    /// A component whose name merely contains a variant suffix without ending in it
    /// (`PetResponsePlain`) does not collide with `Pet`'s Request variant.
    #[test]
    fn variant_collision_control_no_false_positive() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string", "readOnly": true } }
            },
            "PetResponsePlain": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        assert!(variant_collisions(schemas).is_empty());
    }

    /// With no variance anywhere the fixpoint fast-rejects before the collision check runs, so a
    /// document with both `Pet` and `PetRequest` (neither varying) is clean.
    #[test]
    fn variant_collision_skipped_without_variance() {
        let schemas = json!({
            "Pet": {
                "type": "object",
                "properties": { "id": { "type": "string" } }
            },
            "PetRequest": {
                "type": "object",
                "properties": { "note": { "type": "string" } }
            }
        });
        assert!(variant_collisions(schemas).is_empty());
    }
}

#[cfg(test)]
mod wire_variant_tests {
    use serde_json::{Value, json};

    use super::tests::{build_model_inputs_with, find_target};
    use super::*;
    use crate::config::DateTimeRepresentation;
    use crate::diag::Diagnostic;
    use crate::emit::TypePosition;

    /// A schema with one `date-time` property, so it reaches a transform.
    fn timed() -> Value {
        json!({
            "type": "object",
            "properties": { "at": { "type": "string", "format": "date-time" } }
        })
    }

    /// Builds a model under `types.dateTime: date` and returns the wire export names of `component`
    /// for each position, plus every diagnostic the construction produced.
    fn wire_exports(schemas: Value, component: &str) -> (Vec<Option<String>>, Vec<Diagnostic>) {
        exports_under(schemas, component, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
        })
    }

    fn exports_under(
        schemas: Value,
        component: &str,
        patch: fn(&mut ResolvedConfig),
    ) -> (Vec<Option<String>>, Vec<Diagnostic>) {
        let (_temp, resolved, analyzed, digest) = build_model_inputs_with(schemas, patch);
        let mut sink = DiagnosticSink::new();
        let model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);
        let target = find_target(&model, component);
        let exports = [
            TypePosition::Neutral,
            TypePosition::Request,
            TypePosition::Response,
        ]
        .into_iter()
        .map(|position| target.wire_export(position))
        .collect();
        (exports, sink.into_sorted_vec())
    }

    fn codes(diagnostics: &[Diagnostic], code: &str) -> Vec<String> {
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == code)
            .map(|diagnostic| diagnostic.message.clone())
            .collect()
    }

    #[test]
    fn the_suffix_goes_last() {
        let (exports, diagnostics) = wire_exports(json!({ "Pet": timed() }), "Pet");
        assert_eq!(exports[0].as_deref(), Some("PetWire"));
        assert_eq!(exports[1], None, "the request position does not diverge");
        assert_eq!(exports[2], None);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_position_split_component_names_a_twin_per_position() {
        let (exports, diagnostics) = wire_exports(
            json!({
                "Pet": {
                    "type": "object",
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "id": { "type": "string", "readOnly": true },
                        "secret": { "type": "string", "writeOnly": true }
                    }
                }
            }),
            "Pet",
        );
        assert_eq!(exports[0].as_deref(), Some("PetWire"));
        assert_eq!(exports[1].as_deref(), Some("PetRequestWire"));
        assert_eq!(exports[2].as_deref(), Some("PetResponseWire"));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_component_reaching_no_transform_names_no_twin() {
        let (exports, _diagnostics) = wire_exports(
            json!({
                "Plain": { "type": "object", "properties": { "id": { "type": "string" } } }
            }),
            "Plain",
        );
        assert_eq!(exports, vec![None, None, None]);
    }

    #[test]
    fn string_mode_names_no_twin_at_all() {
        let (exports, diagnostics) = exports_under(json!({ "Pet": timed() }), "Pet", |_| {});
        assert_eq!(exports, vec![None, None, None]);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_declared_component_keeps_its_name_and_the_twin_yields() {
        let (exports, diagnostics) = wire_exports(
            json!({
                "Pet": timed(),
                "PetWire": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
            "Pet",
        );
        assert_eq!(exports[0].as_deref(), Some("PetWireValue"));
        let warnings = codes(&diagnostics, "OASTS1311");
        assert_eq!(warnings.len(), 1, "{diagnostics:#?}");
        assert!(warnings[0].contains("'PetWire'"));
        assert!(warnings[0].contains("'PetWireValue'"));
        assert!(codes(&diagnostics, "OASTS1312").is_empty());
    }

    #[test]
    fn a_reserved_name_rename_does_not_re_derive_the_wire_twin() {
        // `Issue` is a name the validators runtime binds, so that emitter renames the component to
        // `Issue2` — after wire twins were allocated. Re-deriving the twin from the new name gave
        // `Issue2Wire`, which the document already declares, and a module importing both got two
        // bindings of one name with no diagnostic.
        let (exports, diagnostics) = wire_exports(
            json!({
                "Issue": timed(),
                "Issue2Wire": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
            "Issue",
        );
        assert_eq!(exports[0].as_deref(), Some("IssueWire"));
        assert!(
            codes(&diagnostics, "OASTS1311").is_empty(),
            "{diagnostics:#?}"
        );
        assert!(
            codes(&diagnostics, "OASTS1312").is_empty(),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn a_taken_replacement_is_fatal_rather_than_silently_shared() {
        let (_exports, diagnostics) = wire_exports(
            json!({
                "Pet": timed(),
                "PetWire": { "type": "object", "properties": { "n": { "type": "integer" } } },
                "PetWireValue": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
            "Pet",
        );
        let errors = codes(&diagnostics, "OASTS1312");
        assert_eq!(errors.len(), 1, "{diagnostics:#?}");
        assert!(errors[0].contains("'PetWire'"));
        assert!(errors[0].contains("'PetWireValue'"));
        assert!(errors[0].contains("naming.overrides"));
        assert!(codes(&diagnostics, "OASTS1311").is_empty());
    }

    #[test]
    fn the_suffix_composes_onto_the_aliased_request_variant() {
        // `Pet` needs a request variant, but `PetRequest` is declared, so OASTS1306 aliases the
        // variant to `PetRequestBody`. The wire suffix must compose onto that alias — composing onto
        // the derived name would have two modules exporting `PetRequestWire` with no diagnostic.
        let (exports, diagnostics) = wire_exports(
            json!({
                "Pet": {
                    "type": "object",
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "id": { "type": "string", "readOnly": true }
                    }
                },
                "PetRequest": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
            "Pet",
        );
        assert_eq!(exports[1].as_deref(), Some("PetRequestBodyWire"));
        assert_eq!(
            codes(&diagnostics, "OASTS1306").len(),
            1,
            "{diagnostics:#?}"
        );
        assert!(codes(&diagnostics, "OASTS1311").is_empty());
        assert!(codes(&diagnostics, "OASTS1312").is_empty());
    }

    /// A component whose generated file name is invalid (a Windows reserved device name) never gets
    /// a `SchemaTarget`, so the wire pass skips it rather than panicking on the missing lookup.
    #[test]
    fn an_unallocatable_component_is_skipped_rather_than_named() {
        let (exports, diagnostics) = wire_exports(
            json!({
                "CON": timed(),
                "Pet": timed()
            }),
            "Pet",
        );
        assert_eq!(exports[0].as_deref(), Some("PetWire"));
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "OASTS1311" && diagnostic.code != "OASTS1312"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn a_twin_of_a_twin_is_named_without_collision() {
        // `PetWire` is itself a component that transforms, so it needs its own twin. Deriving from a
        // unique base keeps the two apart with no alias needed.
        let (exports, _diagnostics) =
            wire_exports(json!({ "Pet": timed(), "PetWire": timed() }), "PetWire");
        assert_eq!(exports[0].as_deref(), Some("PetWireWire"));
    }
}

#[cfg(test)]
mod wire_declaration_tests {
    use serde_json::{Value, json};

    use super::tests::build_model_inputs_with;
    use super::*;
    use crate::config::{DateRepresentation, DateTimeRepresentation};
    use crate::emit::emit_types_from_model;

    /// The emitted `types/components/<base>.ts` for the single-component documents below.
    fn component_file(schemas: Value, base: &str, patch: fn(&mut ResolvedConfig)) -> String {
        let (_temp, resolved, analyzed, digest) = build_model_inputs_with(schemas, patch);
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);
        let files = emit_types_from_model(&mut model);
        files
            .into_iter()
            .find(|file| file.relative_path == format!("types/components/{base}.ts"))
            .expect("component file")
            .content
    }

    fn date_mode(config: &mut ResolvedConfig) {
        config.types.date_time = DateTimeRepresentation::Date;
    }

    fn temporal_mode(config: &mut ResolvedConfig) {
        config.types.date_time = DateTimeRepresentation::Temporal;
        config.types.date = DateRepresentation::Temporal;
    }

    fn pet() -> Value {
        json!({
            "Pet": {
                "type": "object",
                "required": ["bornAt"],
                "properties": {
                    "name": { "type": "string" },
                    "bornAt": { "type": "string", "format": "date-time" }
                }
            }
        })
    }

    #[test]
    fn a_transforming_component_declares_both_surfaces() {
        let content = component_file(pet(), "pet", date_mode);
        assert!(content.contains("export interface Pet {"), "{content}");
        assert!(content.contains("bornAt: Date;"), "{content}");
        assert!(content.contains("export interface PetWire {"), "{content}");
        assert!(content.contains("bornAt: string;"), "{content}");
        // The twin sits after its application type, not before it.
        assert!(
            content.find("interface Pet ").unwrap() < content.find("interface PetWire ").unwrap()
        );
    }

    #[test]
    fn string_mode_declares_one_surface() {
        let content = component_file(pet(), "pet", |_| {});
        assert!(content.contains("bornAt: string;"), "{content}");
        assert!(!content.contains("PetWire"), "{content}");
        assert!(!content.contains("Date"), "{content}");
    }

    #[test]
    fn a_component_reaching_no_transform_declares_one_surface() {
        let content = component_file(
            json!({ "Plain": { "type": "object", "properties": { "id": { "type": "string" } } } }),
            "plain",
            date_mode,
        );
        assert!(!content.contains("PlainWire"), "{content}");
    }

    #[test]
    fn temporal_modes_name_their_types_and_carry_the_lib_reference() {
        let content = component_file(
            json!({
                "Event": {
                    "type": "object",
                    "required": ["at", "on"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "on": { "type": "string", "format": "date" }
                    }
                }
            }),
            "event",
            temporal_mode,
        );
        assert!(content.contains("at: Temporal.Instant;"), "{content}");
        assert!(content.contains("on: Temporal.PlainDate;"), "{content}");
        assert!(content.contains("at: string;"), "{content}");
        assert!(
            content.contains("/// <reference lib=\"esnext.temporal\" preserve=\"true\" />"),
            "{content}"
        );
        // The header stays the first line; the directive follows it.
        assert!(content.starts_with("// Generated by Oasts"), "{content}");
    }

    #[test]
    fn the_date_mode_needs_no_lib_reference() {
        let content = component_file(pet(), "pet", date_mode);
        assert!(!content.contains("esnext.temporal"), "{content}");
    }

    #[test]
    fn a_reference_names_the_twin_on_the_wire_surface_only() {
        let content = component_file(
            json!({
                "Pet": {
                    "type": "object",
                    "required": ["bornAt"],
                    "properties": { "bornAt": { "type": "string", "format": "date-time" } }
                },
                "Owner": {
                    "type": "object",
                    "required": ["pet", "id"],
                    "properties": {
                        "pet": { "$ref": "#/components/schemas/Pet" },
                        "id": { "type": "string" }
                    }
                }
            }),
            "owner",
            date_mode,
        );
        assert!(
            content.contains("import type { Pet, PetWire } from \"./pet.js\";"),
            "{content}"
        );
        assert!(content.contains("pet: Pet;"), "{content}");
        assert!(content.contains("pet: PetWire;"), "{content}");
    }

    #[test]
    fn a_reference_to_a_non_transforming_component_keeps_one_name() {
        let content = component_file(
            json!({
                "Tag": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Pet": {
                    "type": "object",
                    "required": ["bornAt", "tag"],
                    "properties": {
                        "bornAt": { "type": "string", "format": "date-time" },
                        "tag": { "$ref": "#/components/schemas/Tag" }
                    }
                }
            }),
            "pet",
            date_mode,
        );
        assert!(
            content.contains("import type { Tag } from \"./tag.js\";"),
            "{content}"
        );
        assert!(!content.contains("TagWire"), "{content}");
        // Both surfaces name the same referenced type, because it is identity in both.
        assert_eq!(content.matches("tag: Tag;").count(), 2, "{content}");
    }

    #[test]
    fn a_position_split_component_declares_a_twin_per_position() {
        let content = component_file(
            json!({
                "Pet": {
                    "type": "object",
                    "required": ["bornAt", "id", "secret"],
                    "properties": {
                        "bornAt": { "type": "string", "format": "date-time" },
                        "id": { "type": "string", "readOnly": true },
                        "secret": { "type": "string", "writeOnly": true }
                    }
                }
            }),
            "pet",
            date_mode,
        );
        for name in [
            "Pet",
            "PetRequest",
            "PetResponse",
            "PetWire",
            "PetRequestWire",
            "PetResponseWire",
        ] {
            assert!(
                content.contains(&format!("export interface {name} ")),
                "{name}: {content}"
            );
        }
    }

    #[test]
    fn a_recursive_component_names_its_own_twin() {
        let content = component_file(
            json!({
                "Node": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "child": { "$ref": "#/components/schemas/Node" }
                    }
                }
            }),
            "node",
            date_mode,
        );
        assert!(content.contains("child?: Node;"), "{content}");
        assert!(content.contains("child?: NodeWire;"), "{content}");
    }

    #[test]
    fn an_array_of_dates_transforms_element_wise_on_the_application_surface() {
        let content = component_file(
            json!({
                "Log": {
                    "type": "object",
                    "required": ["stamps"],
                    "properties": {
                        "stamps": {
                            "type": "array",
                            "items": { "type": "string", "format": "date-time" }
                        }
                    }
                }
            }),
            "log",
            date_mode,
        );
        assert!(content.contains("stamps: Date[];"), "{content}");
        assert!(content.contains("stamps: string[];"), "{content}");
    }

    #[test]
    fn an_enum_of_date_strings_keeps_its_literal_union_on_both_surfaces() {
        let content = component_file(
            json!({
                "Milestone": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": {
                            "type": "string",
                            "format": "date-time",
                            "enum": ["2024-01-01T00:00:00Z"]
                        }
                    }
                }
            }),
            "milestone",
            date_mode,
        );
        assert!(
            content.contains("at: \"2024-01-01T00:00:00Z\";"),
            "{content}"
        );
        assert!(!content.contains("MilestoneWire"), "{content}");
        assert!(!content.contains("Date"), "{content}");
    }

    #[test]
    fn an_operation_payload_declares_a_twin_when_it_converts() {
        let (_temp, resolved, analyzed, digest) = build_model_inputs_with(json!({}), date_mode);
        drop((resolved, analyzed, digest));
        let content = operation_file(
            json!({
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "parameters": [
                            { "name": "since", "in": "query",
                              "schema": { "type": "string", "format": "date-time" } }
                        ],
                        "requestBody": {
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
                            },
                            "404": {
                                "description": "missing",
                                "content": {
                                    "application/json": {
                                        "schema": { "type": "object",
                                                    "properties": { "message": { "type": "string" } } }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
            json!({
                "Pet": {
                    "type": "object",
                    "required": ["bornAt"],
                    "properties": { "bornAt": { "type": "string", "format": "date-time" } }
                }
            }),
            "createpet",
            date_mode,
        );
        assert!(
            content.contains("export type CreatePetRequestWire = {"),
            "{content}"
        );
        assert!(content.contains("since?: Date;"), "{content}");
        assert!(content.contains("since?: string;"), "{content}");
        assert!(
            content.contains("export type CreatePetResponse200Wire = PetWire;"),
            "{content}"
        );
        assert!(
            !content.contains("CreatePetResponse404Wire"),
            "a response reaching no transform declares one type: {content}"
        );
        assert!(
            content.contains("import type { Pet, PetWire } from \"../components/pet.js\";"),
            "{content}"
        );
    }

    /// The emitted `types/operations/<base>.ts` for a document with paths.
    fn operation_file(
        paths: Value,
        schemas: Value,
        base: &str,
        patch: fn(&mut ResolvedConfig),
    ) -> String {
        use std::fs;
        use tempfile::TempDir;

        use crate::config::load_config;
        use crate::emit::source_digest;
        use crate::loader::load_graph;
        use crate::parse::parse;
        use crate::semantic::analyze;

        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec(&json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": paths,
                "components": { "schemas": schemas }
            }))
            .expect("document JSON"),
        )
        .expect("write document");
        fs::write(
            &config_path,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated"
            }))
            .expect("config JSON"),
        )
        .expect("write config");
        let mut resolved = load_config(Some(&config_path), temp.path()).expect("config resolves");
        patch(&mut resolved);
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("input parses");
        let analyzed = analyze(ir, &resolved, &mut sink);
        let digest = source_digest(&graph.source_tuples());
        let mut model = EmissionModel::new(&analyzed, &resolved, digest, &mut sink);
        emit_types_from_model(&mut model)
            .into_iter()
            .find(|file| file.relative_path == format!("types/operations/{base}.ts"))
            .expect("operation file")
            .content
    }

    #[test]
    fn a_nullable_date_stays_nullable_on_both_surfaces() {
        let content = component_file(
            json!({
                "Slot": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": {
                            "anyOf": [
                                { "type": "string", "format": "date-time" },
                                { "type": "null" }
                            ]
                        }
                    }
                }
            }),
            "slot",
            date_mode,
        );
        assert!(content.contains("at: Date | null;"), "{content}");
        assert!(content.contains("at: string | null;"), "{content}");
    }
}
