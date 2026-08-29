//! Emission shared by the zod and validators artifacts.
//!
//! Both emit one check per schema into per-file modules, pull sibling checks in by name, walk the
//! same reject surface, and publish the same webhook/callback request-descriptor indexes. Only
//! three things separate them: the output directory, the suffix on every exported binding
//! (`…Schema` vs `…Validator`), and how a rejected node is worded and coded. The first two are the
//! fields of [`DescriptorTarget`]; the third is a [`RejectDiagnostic`] the artifact supplies, so
//! each keeps its own codes while the walk that finds the rejects is written once.
//!
//! File assembly deliberately stays in each artifact: the two `assemble_file` functions differ in
//! their module preamble, their re-export shape, and their declaration record, not just in naming.
//! Only the sibling-import block they genuinely share lives here, as
//! [`render_sibling_imports`].

use std::collections::{BTreeMap, BTreeSet};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};

use crate::diag::Diagnostic;
use crate::ir::{Operation, ParamLocation, SchemaNode, SourceRef};
use crate::media::is_json;

use super::model::{EmissionModel, Registrar};
use super::runtime_assets::rewrite_relative_ts_imports;
use super::validators::operation_parameter_validator_names;
use super::{
    Emitter, GeneratedFile, SchemaChildMode, TypePosition, callback_operation,
    callback_parent_operation, import_extension, lowercase_first, push_indent, render_ts_string,
    uppercase_first,
};

/// Which artifact a shared emission is writing for.
#[derive(Clone, Copy)]
pub(super) struct DescriptorTarget<'config> {
    /// The artifact's output directory, relative to the output root.
    pub(super) dir: &'config str,
    /// Suffix on every exported per-schema binding: `petSchema` vs `petValidator`.
    pub(super) export_suffix: &'static str,
}

/// A node the walk below found no check can be emitted for. The artifact turns it into its own
/// diagnostic: the codes and the wording are per-artifact, the classification is not.
pub(super) enum Reject<'schema> {
    /// A validation keyword the parse rejected, named here.
    Keyword(&'schema str),
    /// A node that reached `Unknown` without carrying a rejected keyword, with the parse's reason.
    UnknownLeaf(&'schema str),
}

/// Builds an artifact's diagnostic for one rejected node.
type RejectDiagnostic = fn(Reject<'_>, &SourceRef) -> Diagnostic;

// --- reject-handling walk ----------------------------------------------------------------------

pub(super) fn collect_rejects(
    emitter: &Emitter<'_, '_>,
    schema: &SchemaNode,
    diagnostic: RejectDiagnostic,
    out: &mut Vec<Diagnostic>,
) {
    let meta = schema.meta();
    // One rejected keyword is one root cause, and naming the keyword says strictly more than
    // reporting the leaf it produced. A node can carry both — it reached Unknown *and* holds a
    // rejected keyword — and reporting each would double-report against the frozen matrix's
    // single-diagnostic contract, so the unknown-leaf reject fires only for nodes that reached
    // Unknown without carrying one (e.g. an unknown `type`). A node that kept its representable
    // siblings carries the keyword without being Unknown, and is reported by the same first arm.
    if meta.rejected_validation_keywords.is_empty() {
        if let SchemaNode::Unknown { reason, meta } = schema {
            out.push(diagnostic(Reject::UnknownLeaf(reason), &meta.source));
        }
    } else {
        for keyword in &meta.rejected_validation_keywords {
            out.push(diagnostic(Reject::Keyword(keyword), &meta.source));
        }
    }
    // Validation mode visits the same direct children (no `$ref` following) a check descends, so
    // the reachable set the reject walk covers matches the emitted checks exactly.
    emitter.for_each_schema_child(schema, SchemaChildMode::Validation, &mut |child| {
        collect_rejects(emitter, child, diagnostic, out);
    });
}

pub(super) fn collect_operation_rejects(
    emitter: &Emitter<'_, '_>,
    operation: &Operation,
    include_responses: bool,
    diagnostic: RejectDiagnostic,
    out: &mut Vec<Diagnostic>,
) {
    for parameter in &operation.parameters {
        collect_rejects(emitter, &parameter.schema, diagnostic, out);
    }
    if let Some(body) = &operation.request_body {
        for media in &body.media_types {
            collect_rejects(emitter, &media.schema, diagnostic, out);
        }
    }
    if include_responses {
        for response in &operation.responses {
            for media in &response.media_types {
                collect_rejects(emitter, &media.schema, diagnostic, out);
            }
            for (_, header) in &response.headers {
                collect_rejects(emitter, &header.schema, diagnostic, out);
            }
        }
    }
}

// --- sibling imports ---------------------------------------------------------------------------

/// Per-file-base type names and check names imported from sibling files of the same artifact.
#[derive(Clone, Default)]
pub(super) struct SiblingImports {
    pub(super) files: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    pub(super) skip_self: Option<usize>,
}

impl SiblingImports {
    /// Records the type imports for every `$ref` the structural type surface reaches in `position`.
    /// A component's self-reference is local and therefore excluded.
    pub(super) fn collect_types(
        &mut self,
        emitter: &Emitter<'_, '_>,
        schema: &SchemaNode,
        position: TypePosition,
    ) {
        emitter.walk_refs(schema, position, &mut |target| {
            if Some(target.index) == self.skip_self {
                return;
            }
            let entry = self.files.entry(target.file_base.clone()).or_default();
            let type_name = if target.transforms {
                target.wire_name(position)
            } else {
                target.variant_name(position)
            };
            entry.0.insert(type_name);
        });
    }

    /// Records the exact sibling identifier at the point the emitted body references it.
    pub(super) fn record_export(&mut self, target_index: usize, file_base: &str, name: String) {
        if Some(target_index) != self.skip_self {
            self.files
                .entry(file_base.to_owned())
                .or_default()
                .1
                .insert(name);
        }
    }
}

/// Writes one `import { … } from "…"` line per sibling file, types first.
pub(super) fn render_sibling_imports(
    output: &mut String,
    imports: &SiblingImports,
    sibling_prefix: &str,
    extension: &str,
) {
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
}

// --- embedded runtime assets -------------------------------------------------------------------

/// Embeds a runtime asset verbatim (no generated header) with `.ts` import specifiers rewritten to
/// the configured extension, and registers its path in the collision namespace.
pub(super) fn embedded_asset(
    model: &EmissionModel<'_>,
    registrar: &mut Registrar<'_>,
    target: DescriptorTarget<'_>,
    file_name: &str,
    source: &str,
) -> GeneratedFile {
    let content = rewrite_relative_ts_imports(source, &model.config.emit.import_extension);
    let relative_path = format!("{}/{file_name}", target.dir);
    let asset_source = model
        .analyzed
        .ir
        .schemas
        .first()
        .map(|schema| schema.source.clone())
        .unwrap_or_default();
    registrar.register_path(&relative_path, &asset_source);
    GeneratedFile {
        relative_path,
        content,
    }
}

// --- descriptor indexes ------------------------------------------------------------------------

pub(super) fn emit_webhooks_index(
    model: &EmissionModel<'_>,
    target: DescriptorTarget<'_>,
) -> GeneratedFile {
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
            if !operation_has_request_checks(operation) {
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
                target.export_suffix,
            );
        }
        if wrote_method {
            body.push_str("  },\n");
        } else {
            body.push_str("},\n");
        }
    }
    body.push_str("};\n");
    assemble_descriptor_index(
        model,
        &format!("{}/webhooks/index.ts", target.dir),
        imports,
        body,
    )
}

pub(super) fn emit_callbacks_index(
    model: &EmissionModel<'_>,
    target: DescriptorTarget<'_>,
) -> GeneratedFile {
    let analyzed = model.analyzed;
    let ir = &analyzed.ir;
    let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
    let mut body = String::new();
    let mut seen_parents = HashSet::new();
    // A parent's filed, check-bearing callback entries interleave with its nested callbacks'
    // entries in callback_names (pre-order DFS), so group every qualifying entry by parent once
    // (callback_names order preserved) instead of rescanning the whole table per parent.
    let mut entries_by_parent: HashMap<_, Vec<usize>> = HashMap::new();
    for (index, entry) in analyzed.callback_names.iter().enumerate() {
        if model.callback_files[index].is_some()
            && operation_has_request_checks(callback_operation(ir, &analyzed.callback_names, entry))
        {
            entries_by_parent
                .entry(&entry.parent)
                .or_default()
                .push(index);
        }
    }
    for (index, entry) in analyzed.callback_names.iter().enumerate() {
        if model.callback_files[index].is_none()
            || !operation_has_request_checks(callback_operation(
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
        let parent_operation = callback_parent_operation(ir, &analyzed.callback_names, parent);
        body.push_str("export const ");
        body.push_str(&lowercase_first(&uppercase_first(&entry.parent_stem)));
        body.push_str("Callbacks = {\n");
        let entries = &entries_by_parent[parent];
        let mut cursor = 0;
        while cursor < entries.len() {
            let callback_index = analyzed.callback_names[entries[cursor]].callback_index;
            let callback = &parent_operation.callbacks[callback_index];
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
                    let index = entries[cursor];
                    let allocated = &analyzed.callback_names[index];
                    let file_base = model.callback_files[index].as_deref().unwrap_or_default();
                    let operation = callback_operation(ir, &analyzed.callback_names, allocated);
                    write_request_descriptor_method(
                        &mut body,
                        &mut imports,
                        file_base,
                        &allocated.stem,
                        operation,
                        6,
                        target.export_suffix,
                    );
                    cursor += 1;
                }
                body.push_str("    },\n");
            }
            body.push_str("  },\n");
        }
        body.push_str("};\n");
    }
    assemble_descriptor_index(
        model,
        &format!("{}/callbacks/index.ts", target.dir),
        imports,
        body,
    )
}

/// Whether an operation carries anything the request descriptor can point at: any parameter, or a
/// JSON request body.
fn operation_has_request_checks(operation: &Operation) -> bool {
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
    export_suffix: &str,
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
                let export = format!("{}{export_suffix}", lowercase_first(export_type));
                entry.insert(export.clone());
                push_indent(body, indent + 6);
                body.push_str(&render_ts_string(&parameter.name));
                body.push_str(": ");
                body.push_str(&export);
                body.push_str(",\n");
            }
            push_indent(body, indent + 4);
            body.push_str("},\n");
        }
        push_indent(body, indent + 2);
        body.push_str("},\n");
    }
    if operation
        .request_body
        .as_ref()
        .is_some_and(|body| body.media_types.iter().any(|media| is_json(&media.essence)))
    {
        let export = format!("{}RequestBody{export_suffix}", lowercase_first(&stem));
        entry.insert(export.clone());
        push_indent(body, indent + 2);
        body.push_str("requestBody: ");
        body.push_str(&export);
        body.push_str(",\n");
    }
    push_indent(body, indent);
    body.push_str("},\n");
}

pub(super) fn location_key(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "path",
        ParamLocation::Query => "query",
        ParamLocation::Header => "header",
        ParamLocation::Cookie => "cookie",
    }
}

fn assemble_descriptor_index(
    model: &EmissionModel<'_>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_parameter_locations_are_total() {
        assert_eq!(location_key(ParamLocation::Path), "path");
        assert_eq!(location_key(ParamLocation::Query), "query");
        assert_eq!(location_key(ParamLocation::Header), "header");
        assert_eq!(location_key(ParamLocation::Cookie), "cookie");
    }
}
