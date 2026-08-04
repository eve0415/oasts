//! Date/time transform artifact emission.
//!
//! Emits, under the output root when the client artifact is enabled and any `types.dateTime` /
//! `types.date` representation is non-`string`:
//!   - `client/transform/runtime.ts` (embedded asset, verbatim);
//!   - `client/transform/result.ts` (a generated re-export of the shared result module);
//!   - component and operation codec modules for every payload reaching a transform.
//!
//! Nothing goes under the shared `runtime/` directory. Two specs may share one emitted runtime
//! whenever their `emit.importExtension` and `client.transport` agree, and the date options are
//! explicitly allowed to differ between them — so a runtime file whose bytes depended on a date
//! option would break that sharing. `validators/runtime.ts` is the precedent for a per-artifact
//! runtime file, and this module mirrors it.
//!
//! The re-export exists so the asset stays verbatim. Every embedded runtime asset imports only its
//! own siblings, which is what lets the emitter copy it and rewrite nothing but the import
//! extension; the codec kernel needs `TransformError` from the shared result module, which sits two
//! directories away under a configurable name. Rewriting that specifier inside the asset would make
//! the emitted codec bytes differ from the tested source bytes, so the config-dependent path lives
//! in a generated sibling instead — where config-dependent bytes belong. Re-exporting also keeps one
//! `TransformError` class per program, so the wrapper's `instanceof` still holds.

use std::collections::{BTreeMap, BTreeSet};

use foldhash::HashMap;

use crate::client_model::{
    BodyPlan, ClientModel, FormFieldPlan, MultipartResponsePayload, OperationPlan,
    PayloadDisposition, ResponseMediaPlan,
};
use crate::diag::Diagnostic;
use crate::ir::{
    AdditionalProperties, Discriminator, Operation, ParamLocation, PrimitiveType, PropMeta,
    ResponseEntry, SchemaMeta, SchemaNode, SourceRef, TupleRest,
};
use crate::media::{is_json, is_xml, media_essence};
use crate::transform::{JsonKinds, KindBranch, TransformFacts, TransformKind, UnionDispatch};

use super::model::EmissionModel;
use super::paths::{TRANSFORM_SUBDIR, relative_import};
use super::runtime_assets::rewrite_relative_ts_imports;
use super::{
    CODE_TRANSFORM_UNION, CODE_UNCONVERTIBLE_TRANSFORM, Emitter, GeneratedFile, SchemaChildMode,
    TypePosition, import_extension, operation_response_declarations, property_in_position,
    render_literal_key, render_property_key, render_ts_string, source_diagnostic, uppercase_first,
};

/// Emitted as `client/transform/runtime.ts`; the generated-transform call ABI is fixed to it.
const TRANSFORM_RUNTIME_TS: &str = include_str!("../../runtime/transform-runtime.ts");

/// How one union node selects the conversion to apply, once the declared discriminator has had its
/// turn. `crate::transform` settles every tier that needs only the schema shape; the discriminator
/// tier needs the emitter's allocation to resolve `mapping` values to components, so it is decided
/// here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedDispatch {
    Identity,
    Shared,
    Kind(Vec<KindBranch>),
    /// Dispatch on a declared discriminator property. `tags[i]` are the literals selecting branch
    /// `i`; a branch proving several literals selects on any of them.
    Discriminator {
        property: String,
        tags: Vec<Vec<String>>,
    },
}

/// Resolves how a union node converts, or the diagnostic refusing it.
///
/// `None` means the node is not a union. Otherwise the classification comes from
/// `crate::transform`, except that an indistinguishable one gets one more chance: a declared
/// discriminator that proves a distinct literal per branch dispatches on that property. The proof
/// comes from the emitter's own discriminator machinery, which is the sole producer of those
/// semantics — a mapping value that resolves to nothing leaves the union indistinguishable rather
/// than being trusted.
pub(crate) fn resolve_dispatch(
    emitter: &Emitter<'_, '_, '_>,
    facts: &TransformFacts<'_>,
    node: &SchemaNode,
) -> Option<Result<ResolvedDispatch, Diagnostic>> {
    let (branches, discriminator) = union_parts(node)?;
    let (left, right) = match facts.branch_dispatch(branches) {
        UnionDispatch::Identity => return Some(Ok(ResolvedDispatch::Identity)),
        UnionDispatch::Shared => return Some(Ok(ResolvedDispatch::Shared)),
        UnionDispatch::Kind(kinds) => return Some(Ok(ResolvedDispatch::Kind(kinds))),
        UnionDispatch::Indistinguishable { left, right } => (left, right),
    };
    if let Some(discriminator) = discriminator {
        let (mapping_targets, _dangling) = emitter.mapping_targets(discriminator);
        // The dangling-mapping warning belongs to the validation pass, which reports it once; here a
        // value that resolves to nothing simply contributes no tag.
        if let Ok(tags) =
            emitter.prove_discriminator_tags(branches, discriminator, &mapping_targets)
            && emitter.discriminator_branches_fix_a_literal(branches, &discriminator.property_name)
        {
            return Some(Ok(ResolvedDispatch::Discriminator {
                property: discriminator.property_name.clone(),
                tags,
            }));
        }
    }
    let message = if facts.branches_differ_only_in_optionality(branches) {
        format!(
            "branches {left} and {right} of this union convert the same date/time values but disagree on which of those properties they require, so which conversion is emitted would depend on the order the branches are declared in; make the branches agree on their required properties, or set the representation back to string"
        )
    } else {
        format!(
            "branches {left} and {right} of this union convert date/time values differently, and no JSON value kind or discriminator tells them apart; declare a discriminator whose mapping resolves both branches and whose property each branch requires and fixes to a literal, or set the representation back to string"
        )
    };
    Some(Err(source_diagnostic(
        CODE_TRANSFORM_UNION,
        message,
        &node.meta().source,
    )))
}

/// A union's branches and its declared discriminator, or `None` when the node is not a union.
fn union_parts(node: &SchemaNode) -> Option<(&[SchemaNode], Option<&Discriminator>)> {
    match node {
        SchemaNode::OneOf {
            branches,
            discriminator,
            ..
        }
        | SchemaNode::AnyOf {
            branches,
            discriminator,
            ..
        } => Some((branches, discriminator.as_deref())),
        _ => None,
    }
}

/// Every union in the transform surface that no tier can dispatch, as the diagnostics refusing it.
///
/// The surface is bodies and request parameters — the positions the generated client actually
/// converts. Response headers, webhook payloads, and callback payloads keep wire types, so a union
/// there never converts and is never refused.
fn collect_union_refusals(
    emitter: &Emitter<'_, '_, '_>,
    facts: &TransformFacts<'_>,
    node: &SchemaNode,
    out: &mut Vec<Diagnostic>,
) {
    // A subtree that reaches no conversion cannot hold a union that converts, so this is a
    // fast-reject over the overwhelmingly common case rather than a shortcut.
    if !facts.reaches(node) {
        return;
    }
    if let Some(Err(diagnostic)) = resolve_dispatch(emitter, facts, node) {
        out.push(diagnostic);
    }
    // A converting index signature is emitted as one pass over `Object.entries`, which cannot also
    // carry per-property conversions — so an object declaring both would convert its declared
    // properties and silently leave every undeclared key a wire string behind an index signature
    // that says otherwise.
    // `Schema` alone, not `Allowed(Some(_))`: the parser only ever pairs a schema with the latter
    // synthetically, never from a document — `parse::tests` says so where it covers that arm by
    // building the node directly.
    if let SchemaNode::Object {
        properties,
        additional_properties: AdditionalProperties::Schema(additional),
        meta,
        ..
    } = node
        && !properties.is_empty()
        && facts.reaches(additional)
    {
        out.push(source_diagnostic(
            CODE_UNCONVERTIBLE_TRANSFORM,
            "an index signature that applies a date/time transform cannot be converted alongside declared properties; drop the declared properties, drop the index signature, or set the representation back to string",
            &meta.source,
        ));
    }
    // A pattern property renders an index signature in the declared type but has no conversion: the
    // codecs walk declared properties and one index signature, and no emitted shape dispatches on a
    // key pattern. Converting nothing behind a type that says `Date` is the failure this refuses.
    if let SchemaNode::Object { meta, .. } = node {
        for pattern in &meta.validation_applicators().pattern_properties {
            if pattern.type_key.is_some() && facts.reaches(&pattern.schema) {
                out.push(source_diagnostic(
                    CODE_UNCONVERTIBLE_TRANSFORM,
                    format!(
                        "pattern property '{}' applies a date/time transform to an index signature no codec converts; drop the pattern property, or set the representation back to string",
                        pattern.pattern
                    ),
                    &meta.source,
                ));
            }
        }
    }
    // The types emitter's own child walk, so this never becomes a second answer to "what is nested
    // inside this schema". `Validation` mode visits every child regardless of read/writeOnly
    // position, which is what a refusal must consider: the union is refused wherever it appears.
    emitter.for_each_schema_child(node, SchemaChildMode::Validation, &mut |child| {
        collect_union_refusals(emitter, facts, child, out);
    });
}

/// Refuses every position that reaches a transform the client pipeline cannot carry.
///
/// The emitted codecs convert one payload per position, keyed on the type that position declares.
/// Inline-rendered response payloads and non-literal request discriminants declare shapes the
/// operation codecs cannot carry. They are refused here because emitting nothing for them would put
/// a wire string behind a type that promises a `Date`.
fn unconvertible_transform_diagnostics(
    model: &EmissionModel<'_, '_>,
    plan: &OperationPlan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    body_transform_refusals(model, plan.body_plan.as_ref(), diagnostics);
    for response in &plan.response_table {
        if !matches!(response.payload, PayloadDisposition::Payload)
            || !super::client::renders_payload_inline(response)
        {
            continue;
        }
        for entry in &response.media {
            if inline_response_entry_transforms(model, entry) {
                let mismatch = if response.content_type_discriminated {
                    "its inline payload is narrowed by contentType on the result while the response converter passes only data or error to the status-wide codec"
                } else {
                    "its decoded multipart object is rendered inline while the response converter accepts the status-wide media alias"
                };
                diagnostics.push(source_diagnostic(
                    CODE_UNCONVERTIBLE_TRANSFORM,
                    format!(
                        "response '{}' entry '{}' applies a date/time transform, but {mismatch}; set the representation back to string",
                        response.match_key, entry.media,
                    ),
                    &entry.source,
                ));
            }
        }
    }
}

/// Whether an inline-rendered response entry actually exposes a transformed application value.
/// Text and binary entries ignore their schemas when rendering, and multipart binary parts render
/// `Uint8Array`; none of those positions can put a wire string behind a `Date` type.
fn inline_response_entry_transforms(
    model: &EmissionModel<'_, '_>,
    entry: &ResponseMediaPlan,
) -> bool {
    let Some(multipart) = &entry.multipart else {
        return is_json(media_essence(&entry.media))
            && model.transform_facts().reaches(&entry.schema);
    };
    multipart
        .parts
        .iter()
        .map(|part| &part.shape)
        .chain(multipart.open.then_some(&multipart.additional))
        .any(|shape| {
            shape.payload != MultipartResponsePayload::Binary
                && model.transform_facts().reaches(&shape.schema)
        })
}

fn body_transform_refusals(
    model: &EmissionModel<'_, '_>,
    plan: Option<&BodyPlan>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(BodyPlan::ContentTypeDiscriminated { arms, all_concrete }) = plan {
        if !all_concrete
            && arms.len() > 1
            && let Some(arm) = arms
                .iter()
                .find(|arm| super::client::request_body_transforms(model, Some(&arm.plan)))
        {
            diagnostics.push(source_diagnostic(
                CODE_UNCONVERTIBLE_TRANSFORM,
                "a content-type-discriminated request body mixes media ranges with multiple arms, so its string contentType cannot select one date/time conversion; use concrete media types, or set the representation back to string",
                &arm.source,
            ));
        }
        for arm in arms {
            body_transform_refusals(model, Some(&arm.plan), diagnostics);
        }
    }
}

/// Emits the transform artifact's files, or nothing when no representation transforms.
pub(crate) fn emit_transform_from_model(
    model: &mut EmissionModel<'_, '_>,
    client: &ClientModel,
) -> Vec<GeneratedFile> {
    if !model.transform_facts().enabled() {
        return Vec::new();
    }
    let mut refusals = Vec::new();
    {
        // Borrows the model read-only through an emitter that is dropped before the sink is written,
        // the same shape the validators artifact uses for its reject walk.
        let emitter = Emitter::new(model);
        let facts = emitter.model.transform_facts();
        let ir = &emitter.model.analyzed.ir;
        for schema in &ir.schemas {
            collect_union_refusals(&emitter, facts, &schema.schema, &mut refusals);
        }
        for plan in &client.operations {
            unconvertible_transform_diagnostics(emitter.model, plan, &mut refusals);
        }
        for operation in &ir.operations {
            for parameter in &operation.parameters {
                collect_union_refusals(&emitter, facts, &parameter.schema, &mut refusals);
            }
            for media in operation
                .request_body
                .iter()
                .flat_map(|body| &body.media_types)
                .chain(
                    operation
                        .responses
                        .iter()
                        .flat_map(|response| &response.media_types),
                )
            {
                collect_union_refusals(&emitter, facts, &media.schema, &mut refusals);
            }
        }
    }
    let mut pairs = Vec::new();
    let mut operation_pairs = Vec::new();
    {
        let emitter = Emitter::new(model);
        for allocated in &emitter.model.analyzed.schema_names {
            if let Some(file) =
                emit_component_pairs(&emitter, allocated.schema_index, &allocated.name)
            {
                pairs.push((
                    file,
                    emitter.model.analyzed.ir.schemas[allocated.schema_index]
                        .source
                        .clone(),
                ));
            }
        }
        for plan in &client.operations {
            let operation_index = plan.operation_index;
            let Some(allocated) = emitter
                .model
                .analyzed
                .operation_names
                .iter()
                .find(|allocated| allocated.operation_index == operation_index)
            else {
                continue;
            };
            let Some(file_base) = emitter.model.operation_files[operation_index].as_deref() else {
                continue;
            };
            let operation = &emitter.model.analyzed.ir.operations[operation_index];
            if let Some(file) =
                emit_operation_pairs(&emitter, operation, plan, &allocated.name, file_base)
            {
                operation_pairs.push((file, operation.source.clone()));
            }
        }
        refusals.extend(emitter.deferred_diagnostics.take());
    }
    model.sink.extend(refusals);
    let extension = import_extension(model);
    let result_module = super::render_ts_string(&relative_import(
        &format!("{}/{TRANSFORM_SUBDIR}/result.ts", model.dirs.client),
        &[model.dirs.runtime, "result"],
        &extension,
    ));
    let header = model.header();
    let mut files = vec![
        transform_file(
            model,
            "runtime.ts",
            rewrite_relative_ts_imports(TRANSFORM_RUNTIME_TS, &model.config.emit.import_extension),
        ),
        transform_file(
            model,
            "result.ts",
            format!(
                "{header}export {{ TransformError }} from {result_module};\nexport type {{ ApplicationPath, SourcePointer }} from {result_module};\n"
            ),
        ),
    ];
    for (file, source) in pairs {
        model.register_path(&file.relative_path, &source);
        files.push(file);
    }
    for (file, source) in operation_pairs {
        model.register_path(&file.relative_path, &source);
        files.push(file);
    }
    files
}

fn transform_file(
    model: &mut EmissionModel<'_, '_>,
    file_name: &str,
    content: String,
) -> GeneratedFile {
    let relative_path = format!("{}/{TRANSFORM_SUBDIR}/{file_name}", model.dirs.client);
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

// --- pair modules ------------------------------------------------------------------------------

/// The name a kernel import is bound to in the module being rendered — its own, unless the module
/// declares that identifier and `assign_import_aliases` had to rename the import.
fn local_import_name(name: &str, aliases: &HashMap<String, String>) -> String {
    aliases
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_owned())
}

/// Every name a codec module imports from the compiler's own modules, as the shape
/// `assign_import_aliases` reads. Rendered against the module's declarations, so a document that
/// names a component `Instant` or `ApplicationPath` gets the *import* renamed rather than being
/// refused: the identifier is the compiler's, and the rename is file-local.
fn transform_module_imports() -> BTreeMap<String, BTreeSet<String>> {
    let mut imports = BTreeMap::new();
    imports.insert(
        "result".to_owned(),
        BTreeSet::from(["ApplicationPath".to_owned()]),
    );
    let mut kernel = BTreeSet::new();
    for direction in [Direction::Decode, Direction::Encode] {
        for kind in [
            TransformKind::DateTimeDate,
            TransformKind::DateTimeInstant,
            TransformKind::DatePlainDate,
        ] {
            kernel.insert(direction.codec(kind).to_owned());
        }
    }
    imports.insert("runtime".to_owned(), kernel);
    imports
}

/// The encode/decode pair module for one transforming component, or `None` when the component
/// declares no twin.
///
/// One module per component, mirroring `types/components/`, so a component and its conversion are
/// one file apart and deleting a component removes both. The pairs are exported rather than inlined
/// at the call site because they double as the revive helpers for a cache-hydration boundary, which
/// is why each takes `path` with a default: called directly on a value the caller owns, the root is
/// the empty path.
fn emit_component_pairs(
    emitter: &Emitter<'_, '_, '_>,
    index: usize,
    name: &str,
) -> Option<GeneratedFile> {
    let schema = &emitter.model.analyzed.ir.schemas[index];
    let file_base = emitter.model.component_files[index].clone()?;
    // Infallible: `allocate_paths` registers a component's file base and its target together, so a
    // component with a file base has a target.
    let target = emitter
        .model
        .schema_target(&schema.source.source_id, &schema.source.json_pointer)
        .expect("a component with an allocated file has a registered target");
    if !target.transforms {
        return None;
    }
    let mut type_imports: BTreeSet<String> = BTreeSet::new();
    let mut pair_imports: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut helpers: BTreeSet<&'static str> = BTreeSet::new();
    let mut pointers: Vec<SourceRef> = Vec::new();
    let mut bodies = String::new();
    // What this module binds, before anything is rendered: the conversion carries the codec name
    // into its expressions, so the import's local name has to be settled first.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for position in [
        TypePosition::Neutral,
        TypePosition::Request,
        TypePosition::Response,
    ] {
        let Some(wire) = target.wire_export(position) else {
            continue;
        };
        let application = target.variant_name(position);
        declared.insert(application.clone());
        declared.insert(wire);
        let stem = if position == TypePosition::Neutral {
            name
        } else {
            application.as_str()
        };
        for direction in [Direction::Decode, Direction::Encode] {
            declared.insert(format!("{}{stem}", direction.prefix()));
        }
    }
    // A sibling pair this module calls is bound here too, and its name is derived from a component
    // the document named — so `decodeInstant` can arrive from a sibling as readily as from the
    // kernel. Every component whose name a kernel codec ends in is enough to know that.
    let module_imports = transform_module_imports();
    for allocated in &emitter.model.analyzed.schema_names {
        for direction in [Direction::Decode, Direction::Encode] {
            let pair = format!("{}{}", direction.prefix(), allocated.name);
            if module_imports.values().any(|names| names.contains(&pair)) {
                declared.insert(pair);
            }
        }
    }
    let (aliases, alias_diagnostics) =
        super::assign_import_aliases(&declared, &BTreeSet::new(), &module_imports, &schema.source);
    emitter
        .deferred_diagnostics
        .borrow_mut()
        .extend(alias_diagnostics);
    let path_type = local_import_name("ApplicationPath", &aliases);
    for position in [
        TypePosition::Neutral,
        TypePosition::Request,
        TypePosition::Response,
    ] {
        let Some(wire) = target.wire_export(position) else {
            continue;
        };
        let application = target.variant_name(position);
        type_imports.insert(application.clone());
        type_imports.insert(wire.clone());
        for direction in [Direction::Decode, Direction::Encode] {
            let mut builder = PairBuilder::new(emitter, position, &aliases);
            builder.pointers = pointers;
            builder.helpers = helpers;
            builder.pair_imports = pair_imports;
            let expression = builder
                .convert(&schema.schema, direction, "value", "path", Frame::ROOT)
                .unwrap_or_else(|| "value".to_owned());
            pointers = builder.pointers;
            helpers = builder.helpers;
            pair_imports = builder.pair_imports;
            let (parameter, returns) = match direction {
                Direction::Decode => (wire.as_str(), application.as_str()),
                Direction::Encode => (application.as_str(), wire.as_str()),
            };
            bodies.push_str(&format!(
                "\nexport function {}{}(value: {parameter}, path: {path_type} = []): {returns} {{\n  return {expression};\n}}\n",
                direction.prefix(),
                if position == TypePosition::Neutral {
                    name.to_owned()
                } else {
                    application.clone()
                },
            ));
        }
    }
    let mut content = emitter.header();
    let header_len = content.len();
    let extension = import_extension(emitter.model);
    let relative_path = format!(
        "{}/{TRANSFORM_SUBDIR}/components/{file_base}.ts",
        emitter.model.dirs.client
    );
    content.push_str(&format!(
        "import type {{ {} }} from {};\n",
        type_imports.into_iter().collect::<Vec<_>>().join(", "),
        super::render_ts_string(&relative_import(
            &relative_path,
            &[emitter.model.dirs.types, "components", &file_base],
            &extension,
        ))
    ));
    content.push_str(&format!(
        "import type {{ {} }} from \"../result{extension}\";\n",
        super::import_clause("ApplicationPath".to_owned(), &aliases)
    ));
    if !helpers.is_empty() {
        content.push_str(&format!(
            "import {{ {} }} from \"../runtime{extension}\";\n",
            helpers
                .into_iter()
                .map(|helper| super::import_clause(helper.to_owned(), &aliases))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (file, names) in pair_imports {
        if file == file_base {
            continue;
        }
        content.push_str(&format!(
            "import {{ {} }} from \"./{file}{extension}\";\n",
            names.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    content.push('\n');
    write_pointer_constants(&mut content, &pointers);
    content.push_str(&bodies);
    Some(GeneratedFile {
        relative_path,
        content: super::insert_temporal_reference(content, header_len),
    })
}

/// The request encoder and response decoders for one operation, or `None` when every position is
/// identity. Names and ordering mirror the operation types module exactly.
fn emit_operation_pairs(
    emitter: &Emitter<'_, '_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
    allocated_name: &str,
    file_base: &str,
) -> Option<GeneratedFile> {
    let stem = uppercase_first(allocated_name);
    let request_transforms = super::client::request_transform_binding(emitter.model, plan);
    let responses = operation_response_declarations(operation, &stem)
        .into_iter()
        .filter(|(_, response)| emitter.response_transforms(response))
        .collect::<Vec<_>>();
    if !request_transforms && responses.is_empty() {
        return None;
    }

    let mut type_imports = BTreeSet::new();
    let mut pair_imports = BTreeMap::new();
    let mut helpers = BTreeSet::new();
    let mut pointers = Vec::new();
    let mut bodies = String::new();

    // Settled before anything renders, for the reason `emit_component_pairs` gives.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    if request_transforms {
        declared.insert(format!("{stem}Input"));
        declared.insert(format!("{stem}InputWire"));
        declared.insert(format!("encode{stem}Input"));
    }
    for (application, _) in &responses {
        declared.insert(application.clone());
        declared.insert(format!("{application}Wire"));
        declared.insert(format!("decode{application}"));
    }
    let module_imports = transform_module_imports();
    for allocated in &emitter.model.analyzed.schema_names {
        for direction in [Direction::Decode, Direction::Encode] {
            let pair = format!("{}{}", direction.prefix(), allocated.name);
            if module_imports.values().any(|names| names.contains(&pair)) {
                declared.insert(pair);
            }
        }
    }
    let (aliases, alias_diagnostics) = super::assign_import_aliases(
        &declared,
        &BTreeSet::new(),
        &module_imports,
        &operation.source,
    );
    emitter
        .deferred_diagnostics
        .borrow_mut()
        .extend(alias_diagnostics);
    let path_type = local_import_name("ApplicationPath", &aliases);

    if request_transforms {
        let application = format!("{stem}Input");
        let wire = format!("{application}Wire");
        let schema = operation_input_schema(emitter, operation, plan);
        let mut builder = PairBuilder::new(emitter, TypePosition::Request, &aliases);
        let converted = builder.convert(&schema, Direction::Encode, "value", "path", Frame::ROOT);
        pointers = builder.pointers;
        helpers = builder.helpers;
        pair_imports = builder.pair_imports;
        let body = guarded_body(
            converted,
            Direction::Encode,
            &mut pointers,
            &mut helpers,
            &operation.source,
        );
        bodies.push_str(&format!(
            "\nexport function encode{application}(value: {application}, path: {path_type} = []): {wire} {{\n  return {body};\n}}\n"
        ));
    }

    for (application, response) in responses {
        let wire = format!("{application}Wire");
        type_imports.insert(application.clone());
        type_imports.insert(wire.clone());
        let schema = operation_response_schema(response);
        let mut builder = PairBuilder::new(emitter, TypePosition::Response, &aliases);
        builder.pointers = pointers;
        builder.helpers = helpers;
        builder.pair_imports = pair_imports;
        let converted = builder.convert(&schema, Direction::Decode, "value", "path", Frame::ROOT);
        pointers = builder.pointers;
        helpers = builder.helpers;
        pair_imports = builder.pair_imports;
        let body = guarded_body(
            converted,
            Direction::Decode,
            &mut pointers,
            &mut helpers,
            &response.source,
        );
        bodies.push_str(&format!(
            "\nexport function decode{application}(value: {wire}, path: {path_type} = []): {application} {{\n  return {body};\n}}\n"
        ));
    }

    let mut content = emitter.header();
    let header_len = content.len();
    let extension = import_extension(emitter.model);
    let relative_path = format!(
        "{}/{TRANSFORM_SUBDIR}/operations/{file_base}.ts",
        emitter.model.dirs.client
    );
    if !type_imports.is_empty() {
        content.push_str(&format!(
            "import type {{ {} }} from {};\n",
            type_imports.into_iter().collect::<Vec<_>>().join(", "),
            super::render_ts_string(&relative_import(
                &relative_path,
                &[emitter.model.dirs.types, "operations", file_base],
                &extension,
            ))
        ));
    }
    if request_transforms {
        content.push_str(&format!(
            "import type {{ {stem}Input, {stem}InputWire }} from \"../../operations/{file_base}{extension}\";\n"
        ));
    }
    content.push_str(&format!(
        "import type {{ {} }} from \"../result{extension}\";\n",
        super::import_clause("ApplicationPath".to_owned(), &aliases)
    ));
    if !helpers.is_empty() {
        content.push_str(&format!(
            "import {{ {} }} from \"../runtime{extension}\";\n",
            helpers
                .into_iter()
                .map(|helper| super::import_clause(helper.to_owned(), &aliases))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (file, names) in pair_imports {
        content.push_str(&format!(
            "import {{ {} }} from \"../components/{file}{extension}\";\n",
            names.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    content.push('\n');
    write_pointer_constants(&mut content, &pointers);
    content.push_str(&bodies);
    Some(GeneratedFile {
        relative_path,
        content: super::insert_temporal_reference(content, header_len),
    })
}

/// The operation request surface represented as the object shape its client module emits.
fn operation_input_schema(
    emitter: &Emitter<'_, '_, '_>,
    operation: &Operation,
    plan: &OperationPlan,
) -> SchemaNode {
    let mut properties = Vec::new();
    for (location, group_name) in [
        (ParamLocation::Path, "path"),
        (ParamLocation::Query, "query"),
        (ParamLocation::Header, "header"),
        (ParamLocation::Cookie, "cookie"),
    ] {
        let parameters = plan
            .param_plans
            .iter()
            .filter(|parameter| parameter.resolved.location == location)
            .collect::<Vec<_>>();
        if parameters.is_empty() {
            continue;
        }
        // One lookup per parameter: the group's own optionality is derived from the same answers
        // rather than re-scanning the operation's parameter list a second time.
        let resolved = parameters
            .into_iter()
            .map(|parameter| {
                let required = operation
                    .parameters
                    .iter()
                    .find(|candidate| candidate.source == parameter.source)
                    .expect("a client parameter plan originates from its operation")
                    .required;
                (parameter, required)
            })
            .collect::<Vec<_>>();
        let required = resolved.iter().any(|(_, required)| *required);
        let group_properties = resolved
            .into_iter()
            .filter(|(parameter, _)| !parameter.caller_serialized)
            .map(|(parameter, required)| {
                (
                    parameter.name.clone(),
                    parameter.schema.clone(),
                    operation_property(required),
                )
            })
            .collect::<Vec<_>>();
        if group_properties.is_empty() {
            continue;
        }
        properties.push((
            group_name.to_owned(),
            object_schema(group_properties, operation.source.clone()),
            operation_property(required),
        ));
    }
    if let Some(body_plan) = &plan.body_plan
        && super::client::request_body_transforms(emitter.model, Some(body_plan))
    {
        properties.push((
            "body".to_owned(),
            request_body_schema(body_plan, operation.source.clone()),
            operation_property(
                operation
                    .request_body
                    .as_ref()
                    .is_some_and(|body| body.required),
            ),
        ));
    }
    object_schema(properties, operation.source.clone())
}

/// The request body's rendered client shape, restricted to body plans the encoder can bind.
fn request_body_schema(plan: &BodyPlan, source: SourceRef) -> SchemaNode {
    match plan {
        BodyPlan::Json {
            schema: Some(schema),
            ..
        } => schema.clone(),
        BodyPlan::FormUrlencoded {
            fields,
            source: body_source,
            ..
        }
        | BodyPlan::Multipart {
            fields,
            source: body_source,
            ..
        } => object_schema(
            fields
                .iter()
                .map(|field| {
                    (
                        field.name.clone(),
                        form_field_schema(field),
                        operation_property(field.required),
                    )
                })
                .collect(),
            body_source.clone(),
        ),
        BodyPlan::Json { .. } | BodyPlan::TopLevelText { .. } | BodyPlan::TopLevelBinary { .. } => {
            SchemaNode::Any {
                meta: operation_schema_meta(source),
            }
        }
        BodyPlan::ContentTypeDiscriminated { arms, all_concrete } => SchemaNode::AnyOf {
            branches: arms
                .iter()
                .map(|arm| {
                    let arm_source = arm.source.clone();
                    object_schema(
                        vec![
                            (
                                "contentType".to_owned(),
                                string_schema(
                                    arm_source.clone(),
                                    all_concrete
                                        .then(|| serde_json::Value::String(arm.media.clone())),
                                ),
                                operation_property(true),
                            ),
                            (
                                "body".to_owned(),
                                request_body_schema(&arm.plan, arm_source.clone()),
                                operation_property(true),
                            ),
                        ],
                        arm_source,
                    )
                })
                .collect(),
            discriminator: all_concrete.then(|| {
                Box::new(Discriminator {
                    property_name: "contentType".to_owned(),
                    mapping: Vec::new(),
                    source: source.clone(),
                })
            }),
            meta: operation_schema_meta(source),
        },
    }
}

/// One form field's actual input shape. Content-selected values wrap their schema payload under
/// `body`, while binary uploads render as `Blob | File` and carry no date/time value to convert.
fn form_field_schema(field: &FormFieldPlan) -> SchemaNode {
    if field.is_binary_upload() {
        return SchemaNode::Any {
            meta: operation_schema_meta(field.source.clone()),
        };
    }
    if !field.wrapper.wrapped {
        return field.schema.clone();
    }
    let properties = vec![
        (
            "body".to_owned(),
            field.schema.clone(),
            operation_property(true),
        ),
        (
            "contentType".to_owned(),
            string_schema(field.source.clone(), None),
            operation_property(true),
        ),
    ];
    object_schema(properties, field.source.clone())
}

fn string_schema(source: SourceRef, const_value: Option<serde_json::Value>) -> SchemaNode {
    SchemaNode::Primitive {
        ty: PrimitiveType::String,
        format: None,
        enum_values: None,
        const_value,
        meta: operation_schema_meta(source),
    }
}

/// The media union represented by one response declaration in the types module.
fn operation_response_schema(response: &ResponseEntry) -> SchemaNode {
    let mut branches = response
        .media_types
        .iter()
        .map(|media_type| {
            if is_json(&media_type.essence) {
                media_type.schema.clone()
            } else if media_type.essence.starts_with("text/") && !is_xml(&media_type.essence) {
                SchemaNode::Primitive {
                    ty: PrimitiveType::String,
                    format: None,
                    enum_values: None,
                    const_value: None,
                    meta: operation_schema_meta(media_type.schema.meta().source.clone()),
                }
            } else {
                SchemaNode::Any {
                    meta: operation_schema_meta(media_type.schema.meta().source.clone()),
                }
            }
        })
        .collect::<Vec<_>>();
    if branches.len() == 1 {
        return branches.pop().expect("one response media branch");
    }
    SchemaNode::AnyOf {
        branches,
        discriminator: None,
        meta: operation_schema_meta(response.source.clone()),
    }
}

fn object_schema(properties: Vec<(String, SchemaNode, PropMeta)>, source: SourceRef) -> SchemaNode {
    SchemaNode::Object {
        properties,
        additional_properties: AdditionalProperties::Allowed(None),
        dependent_required: Vec::new(),
        finite: None,
        extra_required: Vec::new(),
        meta: operation_schema_meta(source),
    }
}

fn operation_schema_meta(source: SourceRef) -> SchemaMeta {
    SchemaMeta {
        source,
        ..SchemaMeta::default()
    }
}

const fn operation_property(required: bool) -> PropMeta {
    PropMeta {
        required,
        read_only: false,
        write_only: false,
    }
}

/// One operation entry point's returned expression.
///
/// A position that converts nothing returns the value untouched — there is no conversion to fault,
/// so wrapping it would cost a closure and a guard per call for nothing. A converting one is wrapped
/// so a native fault from walking a wrong-shaped container becomes the same result arm a rejected
/// leaf produces; the wrap goes here, at the entry point, rather than at every node beneath it.
fn guarded_body(
    converted: Option<String>,
    direction: Direction,
    pointers: &mut Vec<SourceRef>,
    helpers: &mut BTreeSet<&'static str>,
    source: &SourceRef,
) -> String {
    let Some(expression) = converted else {
        return "value".to_owned();
    };
    helpers.insert("guarded");
    let pointer = pointer_constant(pointers, source);
    let label = match direction {
        Direction::Encode => "request",
        Direction::Decode => "response",
    };
    format!("guarded(() => ({expression}), \"{label}\", {pointer})")
}

/// Appends one source location and names the constant `write_pointer_constants` will emit for it.
///
/// Appended rather than deduplicated: the locations already in the list are the schema positions the
/// conversion reads, and an entry point's own location — an operation or a response declaration — is
/// never one of them, so a lookup would never hit.
fn pointer_constant(pointers: &mut Vec<SourceRef>, source: &SourceRef) -> String {
    pointers.push(source.clone());
    format!("P{}", pointers.len() - 1)
}

/// Hoists one `SourcePointer` per distinct schema location, in first-seen order.
///
/// Hoisted rather than inlined at each call: the same location is named by both directions of a
/// pair, so one constant halves the emitted bytes it would otherwise cost, and a stable order keeps
/// double generation byte-identical.
fn write_pointer_constants(content: &mut String, pointers: &[SourceRef]) {
    for (index, pointer) in pointers.iter().enumerate() {
        content.push_str(&format!(
            "const P{index} = {{ logicalSourceId: {}, jsonPointer: {} }};\n",
            render_ts_string(&pointer.source_id),
            render_ts_string(&pointer.json_pointer)
        ));
    }
}

// --- conversion expressions ------------------------------------------------------------------

/// Which way a conversion runs. Decode turns a wire value into an application value; encode is its
/// inverse. Both are pure and share untouched subtrees by reference — the walker only descends into
/// paths that reach a conversion, so an unconverted subtree is copied by the enclosing spread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Decode,
    Encode,
}

impl Direction {
    const fn codec(self, kind: TransformKind) -> &'static str {
        match (self, kind) {
            (Self::Decode, TransformKind::DateTimeDate) => "decodeDateTimeDate",
            (Self::Encode, TransformKind::DateTimeDate) => "encodeDateTimeDate",
            (Self::Decode, TransformKind::DateTimeInstant) => "decodeInstant",
            (Self::Encode, TransformKind::DateTimeInstant) => "encodeInstant",
            (Self::Decode, TransformKind::DatePlainDate) => "decodePlainDate",
            (Self::Encode, TransformKind::DatePlainDate) => "encodePlainDate",
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::Encode => "encode",
        }
    }
}

/// One object conversion under construction: the whole-value conversions to spread as its base, the
/// property assignments over them, and the keys the base must shed first.
#[derive(Default)]
struct ObjectParts {
    /// A conversion replacing the whole value, when the schema is an open map rather than a set of
    /// declared properties. Mutually exclusive with `parts` by construction.
    whole: Option<String>,
    bases: Vec<String>,
    parts: Vec<String>,
    omitted: Vec<String>,
    /// Property names that already contributed a part. Two `allOf` branches may constrain the same
    /// property, and the merged type declares it once — so the object literal has to assign it once
    /// too, or TypeScript refuses the duplicate key outright.
    assigned: BTreeSet<String>,
}

impl ObjectParts {
    /// The object literal these parts build over `value`, or `None` when nothing converts and the
    /// caller can keep the value by reference.
    fn render(self, value: &str, frame: Frame) -> Option<String> {
        if let Some(whole) = self.whole {
            return Some(whole);
        }
        if self.parts.is_empty() && self.bases.is_empty() {
            return None;
        }
        // Broken across lines rather than joined: a real schema converts several properties, and a
        // single-line object literal runs to hundreds of columns in generated output no formatter is
        // ever allowed to touch.
        let inner = " ".repeat(frame.indent + 2);
        let closing = " ".repeat(frame.indent);
        let mut base = value.to_owned();
        for name in &self.omitted {
            base = format!("omit({base}, {})", render_ts_string(name));
        }
        let mut spreads = vec![format!("...{base}")];
        spreads.extend(self.bases.iter().map(|base| format!("...{base}")));
        spreads.extend(self.parts);
        Some(format!(
            "{{\n{inner}{},\n{closing}}}",
            spreads.join(&format!(",\n{inner}"))
        ))
    }
}

/// Where one conversion sits: the callback-variable depth, so a nested `.map` callback never shadows
/// its parent's binding, and the indent its object literals break at.
#[derive(Clone, Copy)]
struct Frame {
    depth: usize,
    indent: usize,
}

impl Frame {
    const ROOT: Self = Self {
        depth: 0,
        indent: 2,
    };

    /// A frame for a value reached through a new callback binding.
    const fn nested(self) -> Self {
        Self {
            depth: self.depth + 1,
            indent: self.indent + 2,
        }
    }

    /// A frame for a value reached without a new binding — one level deeper in the literal only.
    const fn inner(self) -> Self {
        Self {
            depth: self.depth,
            indent: self.indent + 2,
        }
    }
}

/// Builds one module's conversion expressions, collecting the imports and hoisted pointer constants
/// they need as it goes.
struct PairBuilder<'a, 'model, 'input, 'sink> {
    emitter: &'a Emitter<'model, 'input, 'sink>,
    position: TypePosition,
    /// The local binding each kernel import took in this module. Empty in every module whose own
    /// declarations leave the kernel names free, which is all but a handful.
    aliases: &'a HashMap<String, String>,
    /// Hoisted `SourcePointer` constants in first-seen order, so the emitted bytes stay stable.
    pointers: Vec<SourceRef>,
    /// Sibling pair modules this file calls into, keyed by file base.
    pair_imports: BTreeMap<String, BTreeSet<String>>,
    /// The codec kernel exports actually called, so the runtime import names exactly those.
    helpers: BTreeSet<&'static str>,
}

impl<'a, 'model, 'input, 'sink> PairBuilder<'a, 'model, 'input, 'sink> {
    fn new(
        emitter: &'a Emitter<'model, 'input, 'sink>,
        position: TypePosition,
        aliases: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            emitter,
            position,
            aliases,
            pointers: Vec::new(),
            pair_imports: BTreeMap::new(),
            helpers: BTreeSet::new(),
        }
    }

    fn facts(&self) -> &TransformFacts<'input> {
        self.emitter.model.transform_facts()
    }

    /// The hoisted constant naming this schema's location, allocated on first use.
    fn pointer(&mut self, source: &SourceRef) -> String {
        // A plain loop, not `position(..).unwrap_or_else(..)`: the closure never runs on the first
        // call, where the list is still empty, and llvm-cov scores a never-instantiated closure as
        // an uncovered line under a 100%-lines gate.
        for (index, held) in self.pointers.iter().enumerate() {
            if held.source_id == source.source_id && held.json_pointer == source.json_pointer {
                return format!("P{index}");
            }
        }
        self.pointers.push(source.clone());
        format!("P{}", self.pointers.len() - 1)
    }

    /// The conversion `value` needs at `path`, or `None` when nothing under it converts and the
    /// caller can keep the value by reference.
    fn convert(
        &mut self,
        node: &SchemaNode,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        let inner = self.convert_inner(node, direction, value, path, frame)?;
        // A nullable node admits null in both surfaces, and no codec accepts it.
        if node.meta().nullable {
            return Some(format!("{value} === null ? null : {inner}"));
        }
        Some(inner)
    }

    fn convert_inner(
        &mut self,
        node: &SchemaNode,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        if let Some(kind) = self.facts().site(node) {
            let pointer = self.pointer(&node.meta().source);
            let codec = direction.codec(kind);
            self.helpers.insert(codec);
            let local = local_import_name(codec, self.aliases);
            return Some(format!("{local}({value}, {pointer}, {path})"));
        }
        match node {
            SchemaNode::Ref { target, .. } => {
                // A reference resolving to nothing and one resolving to a component that does not
                // convert are the same answer here: nothing to call, so the value rides the
                // enclosing spread untouched.
                let target = self
                    .emitter
                    .model
                    .schema_target(&target.source_id, &target.json_pointer)
                    .filter(|target| target.transforms)?;
                let name = format!(
                    "{}{}",
                    direction.prefix(),
                    target.variant_name(self.position)
                );
                self.pair_imports
                    .entry(target.file_base.clone())
                    .or_default()
                    .insert(name.clone());
                Some(format!("{name}({value}, {path})"))
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => self.convert_object(
                properties,
                additional_properties,
                direction,
                value,
                path,
                frame,
            ),
            SchemaNode::Array { items, .. } => {
                let item = format!("item{}", frame.depth);
                let index = format!("index{}", frame.depth);
                let element = self.convert(
                    items,
                    direction,
                    &item,
                    &format!("pushPath({path}, {index})"),
                    frame.nested(),
                )?;
                self.helpers.insert("pushPath");
                Some(format!("{value}.map(({item}, {index}) => {element})"))
            }
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => self.convert_tuple(prefix_items, rest, direction, value, path, frame),
            SchemaNode::AllOf { branches, .. } => {
                let mut object = ObjectParts::default();
                self.collect_parts(branches, direction, value, path, frame, &mut object);
                object.render(value, frame)
            }
            SchemaNode::OneOf { .. } | SchemaNode::AnyOf { .. } => {
                self.convert_union(node, direction, value, path, frame)
            }
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => None,
        }
    }

    fn convert_object(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        additional_properties: &AdditionalProperties,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        let mut object = ObjectParts::default();
        self.collect_object_parts(
            properties,
            additional_properties,
            direction,
            value,
            path,
            frame,
            &mut object,
        );
        object.render(value, frame)
    }

    /// Collects one `allOf` node's parts.
    ///
    /// The branches all describe the same value, so their conversions merge rather than chain:
    /// chaining would read each later branch's properties off an earlier branch's *result*,
    /// recomputing it once per property. A branch converting the whole value — a `$ref` to a
    /// component with its own pair — contributes that call as a base to spread; an object branch
    /// contributes its properties, each read off the original value.
    fn collect_parts(
        &mut self,
        branches: &[SchemaNode],
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
        object: &mut ObjectParts,
    ) {
        for branch in branches {
            match branch {
                SchemaNode::AllOf {
                    branches: nested, ..
                } => {
                    self.collect_parts(nested, direction, value, path, frame, object);
                }
                SchemaNode::Object {
                    properties,
                    additional_properties,
                    ..
                } => self.collect_object_parts(
                    properties,
                    additional_properties,
                    direction,
                    value,
                    path,
                    frame,
                    object,
                ),
                _ => {
                    if let Some(converted) = self.convert(branch, direction, value, path, frame) {
                        object.bases.push(converted);
                    }
                }
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one collector over the four things an object conversion reads, plus its output"
    )]
    fn collect_object_parts(
        &mut self,
        properties: &[(String, SchemaNode, PropMeta)],
        additional_properties: &AdditionalProperties,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
        object: &mut ObjectParts,
    ) {
        for (name, schema, meta) in properties {
            if !property_in_position(meta, self.position) {
                continue;
            }
            let access = format!("{value}{}", property_access(name));
            let Some(converted) = self.convert(
                schema,
                direction,
                &access,
                &format!("pushPath({path}, {})", render_ts_string(name)),
                frame.inner(),
            ) else {
                continue;
            };
            if !object.assigned.insert(name.clone()) {
                continue;
            }
            self.helpers.insert("pushPath");
            let key = render_literal_key(name);
            if meta.required {
                object.parts.push(format!("{key}: {converted}"));
            } else {
                // The base spread has to lose the key first — see `omit` in the codec kernel for why
                // the simpler conditional spread does not typecheck, and why assigning `undefined`
                // instead is worse. Emitted as a conditional spread so an absent optional stays
                // absent rather than becoming present-with-undefined.
                object.omitted.push(name.clone());
                self.helpers.insert("omit");
                object.parts.push(format!(
                    "...({access} === undefined ? {{}} : {{ {key}: {converted} }})"
                ));
            }
        }
        if let AdditionalProperties::Allowed(Some(schema)) | AdditionalProperties::Schema(schema) =
            additional_properties
            && properties.is_empty()
        {
            let entry = format!("entry{}", frame.depth);
            let key = format!("key{}", frame.depth);
            if let Some(converted) = self.convert(
                schema,
                direction,
                &entry,
                &format!("pushPath({path}, {key})"),
                frame.nested(),
            ) {
                self.helpers.insert("pushPath");
                object.whole = Some(format!(
                    "Object.fromEntries(Object.entries({value}).map(([{key}, {entry}]) => [{key}, {converted}]))"
                ));
            }
        }
    }

    fn convert_tuple(
        &mut self,
        prefix_items: &[SchemaNode],
        rest: &TupleRest,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        let mut parts = Vec::new();
        let mut converted = false;
        for (index, item) in prefix_items.iter().enumerate() {
            let access = format!("{value}[{index}]");
            match self.convert(
                item,
                direction,
                &access,
                &format!("pushPath({path}, {index})"),
                frame.inner(),
            ) {
                Some(expression) => {
                    self.helpers.insert("pushPath");
                    converted = true;
                    parts.push(expression);
                }
                None => parts.push(access),
            }
        }
        if let TupleRest::Schema(schema) = rest {
            let item = format!("item{}", frame.depth);
            let index = format!("index{}", frame.depth);
            if let Some(element) = self.convert(
                schema,
                direction,
                &item,
                &format!("pushPath({path}, {index} + {})", prefix_items.len()),
                frame.nested(),
            ) {
                self.helpers.insert("pushPath");
                converted = true;
                parts.push(format!(
                    "...{value}.slice({}).map(({item}, {index}) => {element})",
                    prefix_items.len()
                ));
            } else {
                parts.push(format!("...{value}.slice({})", prefix_items.len()));
            }
        }
        converted.then(|| format!("[{}]", parts.join(", ")))
    }

    fn convert_union(
        &mut self,
        node: &SchemaNode,
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        let (branches, _) =
            union_parts(node).expect("convert_union is called only for oneOf and anyOf nodes");
        // The refusal walk has already reported an indistinguishable union, so the run fails; there
        // is nothing honest to emit for it, and identity is what keeps the emitter total.
        match resolve_dispatch(self.emitter, self.facts(), node)
            .expect("a oneOf or anyOf node always resolves to a dispatch")
        {
            Ok(ResolvedDispatch::Identity) | Err(_) => None,
            Ok(ResolvedDispatch::Shared) => self.convert(
                branches
                    .first()
                    .expect("a shared union dispatch has at least one branch"),
                direction,
                value,
                path,
                frame,
            ),
            Ok(ResolvedDispatch::Kind(kinds)) => {
                let arms = kinds
                    .iter()
                    .filter(|branch| branch.converts)
                    .map(|branch| {
                        let test = self.branch_test(
                            branches.get(branch.index),
                            branch.kinds,
                            direction,
                            value,
                        );
                        (test, branch.index)
                    })
                    .collect::<Vec<_>>();
                self.dispatch_arms(arms, branches, direction, value, path, frame)
            }
            Ok(ResolvedDispatch::Discriminator { property, tags }) => {
                let access = format!("{value}{}", property_access(&property));
                let arms = tags
                    .iter()
                    .enumerate()
                    .filter_map(|(index, literals)| {
                        let test = literals
                            .iter()
                            .map(|tag| format!("{access} === {}", render_ts_string(tag)))
                            .collect::<Vec<_>>()
                            .join(" || ");
                        (!test.is_empty()).then_some((test, index))
                    })
                    .collect::<Vec<_>>();
                self.dispatch_arms(arms, branches, direction, value, path, frame)
            }
        }
    }

    /// The test selecting one union branch, in the surface the direction is reading.
    ///
    /// Decoding reads the wire, where every branch is a JSON value and its declared kinds decide.
    /// Encoding reads the application surface, where a converted branch holds a `Date` or a
    /// `Temporal` object rather than the string the kind set describes — so a branch that converts
    /// at its root is tested for that runtime object instead.
    fn branch_test(
        &mut self,
        branch: Option<&SchemaNode>,
        kinds: JsonKinds,
        direction: Direction,
        value: &str,
    ) -> String {
        if direction == Direction::Encode
            && let Some(branch) = branch
            && let Some(kind) = self.facts().site_through_refs(branch)
        {
            return match kind {
                TransformKind::DateTimeDate => format!("{value} instanceof Date"),
                TransformKind::DateTimeInstant => {
                    self.helpers.insert("isInstant");
                    format!("isInstant({value})")
                }
                TransformKind::DatePlainDate => {
                    self.helpers.insert("isPlainDate");
                    format!("isPlainDate({value})")
                }
            };
        }
        kind_test(kinds, value)
    }

    /// Chains one ternary per converting branch, falling through to the value itself. Emitted in
    /// declared branch order, so the bytes follow the document.
    fn dispatch_arms(
        &mut self,
        arms: Vec<(String, usize)>,
        branches: &[SchemaNode],
        direction: Direction,
        value: &str,
        path: &str,
        frame: Frame,
    ) -> Option<String> {
        let mut rendered = Vec::new();
        for (test, index) in arms {
            let branch = branches
                .get(index)
                .expect("a dispatch arm index originates from this union's branches");
            if let Some(expression) = self.convert(branch, direction, value, path, frame) {
                rendered.push(format!("{test} ? {expression}"));
            }
        }
        if rendered.is_empty() {
            return None;
        }
        Some(format!("{} : {value}", rendered.join(" : ")))
    }
}

/// A JavaScript test selecting exactly the JSON value kinds in `kinds`.
fn kind_test(kinds: JsonKinds, value: &str) -> String {
    let mut tests = Vec::new();
    if kinds.contains(JsonKinds::NULL) {
        tests.push(format!("{value} === null"));
    }
    for (kind, name) in [
        (JsonKinds::BOOLEAN, "boolean"),
        (JsonKinds::NUMBER, "number"),
        (JsonKinds::STRING, "string"),
    ] {
        if kinds.contains(kind) {
            tests.push(format!("typeof {value} === {name:?}"));
        }
    }
    if kinds.contains(JsonKinds::ARRAY) {
        tests.push(format!("Array.isArray({value})"));
    }
    if kinds.contains(JsonKinds::OBJECT) {
        // Ordered so the cheap rejections run first, and `Array.isArray` last: an array is also
        // `typeof "object"`, so without it an array would select the object branch.
        tests.push(format!(
            "(typeof {value} === \"object\" && {value} !== null && !Array.isArray({value}))"
        ));
    }
    tests.join(" || ")
}

/// Property access that stays valid for a key needing quoting. Reads the same key renderer the
/// declarations read, so an access and the property it reaches can never disagree about quoting.
fn property_access(name: &str) -> String {
    let key = render_property_key(name);
    if key == name {
        format!(".{name}")
    } else {
        format!("[{key}]")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::client_model::build_client_model;
    use crate::config::{DateRepresentation, DateTimeRepresentation, ResolvedConfig, load_config};
    use crate::diag::DiagnosticSink;
    use crate::emit::emit_artifacts;
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;

    /// The asset's only relative import, a sibling in the repo and a sibling once emitted — the
    /// generated re-export is what makes the emitted side true.
    const ASSET_RESULT_IMPORT: &str = "from \"./result.ts\"";

    /// Compiles `document` with the client enabled and `patch` applied to the resolved config,
    /// returning the emitted files and every diagnostic. Unlike `compile`, a failing run is expected.
    pub(super) fn compile_document(
        document: Value,
        patch: fn(&mut ResolvedConfig),
    ) -> (Vec<GeneratedFile>, Vec<Diagnostic>, bool) {
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
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true },
                "client": {},
                "validation": { "engine": "off", "unchecked": "allow" }
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
        let client = build_client_model(&analyzed, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            Some(&client),
            &mut sink,
        );
        let has_errors = sink.has_errors();
        (files, sink.into_sorted_vec(), has_errors)
    }

    /// A document whose one operation returns `Notice`, plus whatever schemas it is given.
    pub(super) fn notice_document(schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/notices": {
                    "get": {
                        "operationId": "listNotices",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Notice" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": { "schemas": schemas }
        })
    }

    fn refusals(diagnostics: &[Diagnostic]) -> Vec<&Diagnostic> {
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1313")
            .collect()
    }

    /// The branches of a kind dispatch, or `None` for any other resolution. Total rather than
    /// panicking, so no arm is left permanently uncovered; both answers are asserted below.
    fn kind_branches(
        dispatch: Option<&Result<ResolvedDispatch, Diagnostic>>,
    ) -> Option<&[KindBranch]> {
        match dispatch {
            Some(Ok(ResolvedDispatch::Kind(branches))) => Some(branches),
            _ => None,
        }
    }

    /// The dispatch a named component root resolves to, read the way Phase-4 rendering will read it.
    /// The refusal walk only ever keeps the `Err` arm, so this is the only way to observe the rest.
    fn resolved(
        document: Value,
        name: &str,
        patch: fn(&mut ResolvedConfig),
    ) -> Option<Result<ResolvedDispatch, Diagnostic>> {
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
        let facts = TransformFacts::compute(&analyzed.ir, &resolved);
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);
        let node = &analyzed
            .ir
            .schemas
            .iter()
            .find(|schema| schema.name == name)
            .expect("declared component")
            .schema;
        resolve_dispatch(&emitter, &facts, node)
    }

    #[test]
    fn a_non_union_node_resolves_to_no_dispatch() {
        assert!(
            resolved(
                notice_document(json!({
                    "Notice": {
                        "type": "object",
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                })),
                "Notice",
                |config| config.types.date_time = DateTimeRepresentation::Date,
            )
            .is_none()
        );
    }

    #[test]
    fn a_union_where_nothing_converts_resolves_to_identity() {
        // Also the negative side of `kind_branches`: an Identity resolution is not a kind dispatch.
        let dispatch = resolved(
            notice_document(json!({
                "Notice": { "oneOf": [{ "type": "string" }, { "type": "integer" }] }
            })),
            "Notice",
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        assert_eq!(dispatch, Some(Ok(ResolvedDispatch::Identity)));
        assert!(kind_branches(dispatch.as_ref()).is_none());
    }

    #[test]
    fn a_nullable_converting_branch_resolves_to_a_kind_dispatch() {
        let dispatch = resolved(
            notice_document(json!({
                "Timed": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Notice": {
                    "anyOf": [{ "$ref": "#/components/schemas/Timed" }, { "type": "null" }]
                }
            })),
            "Notice",
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        let branches = kind_branches(dispatch.as_ref()).expect("kind dispatch");
        assert!(branches[0].converts);
        assert!(!branches[1].converts);
    }

    #[test]
    fn branches_converting_identically_resolve_to_one_shared_conversion() {
        let dispatch = resolved(
            notice_document(json!({
                "Notice": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "at": { "type": "string", "format": "date-time" },
                                "left": { "type": "string" }
                            }
                        },
                        {
                            "type": "object",
                            "properties": {
                                "at": { "type": "string", "format": "date-time" },
                                "right": { "type": "integer" }
                            }
                        }
                    ]
                }
            })),
            "Notice",
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        assert_eq!(dispatch, Some(Ok(ResolvedDispatch::Shared)));
    }

    #[test]
    fn a_union_in_a_request_parameter_is_refused() {
        let mut document = notice_document(json!({
            "Notice": {
                "type": "object",
                "properties": { "at": { "type": "string", "format": "date-time" } }
            }
        }));
        document["paths"]["/notices"]["get"]["parameters"] = json!([{
            "name": "window",
            "in": "query",
            "schema": {
                "oneOf": [
                    {
                        "type": "object",
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    },
                    {
                        "type": "object",
                        "properties": { "on": { "type": "string", "format": "date-time" } }
                    }
                ]
            }
        }]);
        let (_files, diagnostics, _has_errors) = compile_document(document, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
        });
        let flagged = refusals(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:#?}");
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/paths/~1notices/get/parameters/0/schema")
        );
    }

    #[test]
    fn a_discriminator_dispatches_branches_no_kind_separates() {
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Reminder": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "const": "reminder" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Digest": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "const": "digest" },
                        "on": { "type": "string", "format": "date" }
                    }
                },
                "Notice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Reminder" },
                        { "$ref": "#/components/schemas/Digest" }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            })),
            |config| {
                config.types.date_time = DateTimeRepresentation::Temporal;
                config.types.date = DateRepresentation::Temporal;
            },
        );
        assert!(
            refusals(&diagnostics).is_empty(),
            "the discriminator resolves both branches: {diagnostics:#?}"
        );
    }

    #[test]
    fn a_union_differing_only_in_requiredness_names_that_as_the_difference() {
        // The generic message points at conversions that are in fact identical, which sends the
        // reader looking for a difference that is not there.
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "anyOf": [
                        {
                            "type": "object",
                            "required": ["at"],
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );

        let refused = refusals(&diagnostics);
        assert_eq!(refused.len(), 1, "{diagnostics:#?}");
        assert!(
            refused[0]
                .message
                .contains("disagree on which of those properties they require"),
            "{refused:#?}"
        );
    }

    #[test]
    fn a_base_requiring_the_tag_proves_it_for_the_subtype_that_fixes_it() {
        // The standard spelling: the base requires `kind` as a plain string, and each subtype fixes
        // its literal without repeating `required`. The two facts live in different constituents of
        // the same `allOf`, and demanding both from one of them refused the whole pattern.
        let (_files, diagnostics, has_errors) = compile_document(
            notice_document(json!({
                "Base": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": { "kind": { "type": "string" } }
                },
                "Reminder": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Base" },
                        {
                            "type": "object",
                            "properties": {
                                "kind": { "const": "reminder" },
                                "at": { "type": "string", "format": "date-time" }
                            }
                        }
                    ]
                },
                "Digest": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Base" },
                        {
                            "type": "object",
                            "properties": {
                                "kind": { "const": "digest" },
                                "on": { "type": "string", "format": "date-time" }
                            }
                        }
                    ]
                },
                "Notice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Reminder" },
                        { "$ref": "#/components/schemas/Digest" }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refusals(&diagnostics).is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_discriminator_whose_tag_is_optional_does_not_dispatch() {
        // Dispatched on it before this. `value.kind === "reminder"` does not narrow an optional
        // property, so both arms were type errors, and a payload omitting the tag fell through
        // every arm unconverted.
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Reminder": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "const": "reminder" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Digest": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "const": "digest" },
                        "on": { "type": "string", "format": "date" }
                    }
                },
                "Notice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Reminder" },
                        { "$ref": "#/components/schemas/Digest" }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            })),
            |config| {
                config.types.date_time = DateTimeRepresentation::Temporal;
                config.types.date = DateRepresentation::Temporal;
            },
        );

        let refused = refusals(&diagnostics);
        assert_eq!(refused.len(), 1, "{diagnostics:#?}");
        assert!(
            refused[0].message.contains("requires and fixes"),
            "{refused:#?}"
        );
    }

    #[test]
    fn branches_no_kind_and_no_discriminator_separate_are_refused() {
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        {
                            "type": "object",
                            "properties": { "on": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        let flagged = refusals(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:#?}");
        assert!(flagged[0].message.contains("branches 0 and 1"));
        assert!(flagged[0].message.contains("declare a discriminator"));
        assert!(
            flagged[0]
                .message
                .contains("set the representation back to string")
        );
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/components/schemas/Notice")
        );
    }

    #[test]
    fn a_discriminator_whose_branches_prove_no_literal_does_not_rescue_the_union() {
        // Inline object branches carry no reference identity and fix no tag value, so nothing proves
        // a literal — a declared discriminator is not taken on trust.
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string" },
                                "at": { "type": "string", "format": "date-time" }
                            }
                        },
                        {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string" },
                                "on": { "type": "string", "format": "date-time" }
                            }
                        }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        assert_eq!(refusals(&diagnostics).len(), 1, "{diagnostics:#?}");
    }

    #[test]
    fn an_inline_union_in_a_response_body_is_refused() {
        // Not reachable as a component root, so this is the response-media arm of the walk and
        // nothing else. A response body is the primary transform position.
        let (_files, diagnostics, _has_errors) = compile_document(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/notices": {
                        "get": {
                            "operationId": "listNotices",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "oneOf": [
                                                    {
                                                        "type": "object",
                                                        "properties": {
                                                            "at": {
                                                                "type": "string",
                                                                "format": "date-time"
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "type": "object",
                                                        "properties": {
                                                            "on": {
                                                                "type": "string",
                                                                "format": "date-time"
                                                            }
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        let flagged = refusals(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:#?}");
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/paths/~1notices/get/responses/200/content/application~1json/schema")
        );
    }

    #[test]
    fn a_discriminator_whose_branches_fix_no_literal_is_refused() {
        // The mapping resolves both branches, so the generator knows which codec each wire value
        // selects — but neither branch fixes `kind` to a literal, so the emitted union's own type
        // carries `kind: string` on both arms and the dispatch it would emit never narrows.
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Scheduled": {
                    "type": "object",
                    "required": ["kind", "at"],
                    "properties": {
                        "kind": { "type": "string" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Cancelled": {
                    "type": "object",
                    "required": ["kind", "on"],
                    "properties": {
                        "kind": { "type": "string" },
                        "on": { "type": "string", "format": "date-time" }
                    }
                },
                "Notice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Scheduled" },
                        { "$ref": "#/components/schemas/Cancelled" }
                    ],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {
                            "scheduled": "#/components/schemas/Scheduled",
                            "cancelled": "#/components/schemas/Cancelled"
                        }
                    }
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        assert_eq!(refusals(&diagnostics).len(), 1, "{diagnostics:#?}");
    }

    #[test]
    fn a_discriminator_whose_branches_fix_a_literal_dispatches() {
        let (files, diagnostics, has_errors) = compile_document(
            notice_document(json!({
                "Scheduled": {
                    "type": "object",
                    "required": ["kind", "at"],
                    "properties": {
                        "kind": { "const": "scheduled" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Cancelled": {
                    "type": "object",
                    "required": ["kind", "on"],
                    "properties": {
                        "kind": { "const": "cancelled" },
                        "on": { "type": "string", "format": "date-time" }
                    }
                },
                "Notice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Scheduled" },
                        { "$ref": "#/components/schemas/Cancelled" }
                    ],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {
                            "scheduled": "#/components/schemas/Scheduled",
                            "cancelled": "#/components/schemas/Cancelled"
                        }
                    }
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refusals(&diagnostics).is_empty(), "{diagnostics:#?}");
        let content = files
            .into_iter()
            .find(|file| file.relative_path == "client/transform/components/notice.ts")
            .expect("notice codec module")
            .content;
        assert!(
            content.contains("value.kind === \"scheduled\""),
            "{content}"
        );
    }

    #[test]
    fn a_refusable_union_is_not_refused_in_string_mode() {
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        {
                            "type": "object",
                            "properties": { "on": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            })),
            |_| {},
        );
        assert!(refusals(&diagnostics).is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_union_inside_a_request_body_is_refused_too() {
        let mut document = notice_document(json!({
            "Notice": {
                "oneOf": [
                    {
                        "type": "object",
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    },
                    {
                        "type": "object",
                        "properties": { "on": { "type": "string", "format": "date-time" } }
                    }
                ]
            }
        }));
        document["paths"]["/notices"]["post"] = json!({
            "operationId": "createNotice",
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": { "notice": { "$ref": "#/components/schemas/Notice" } }
                        }
                    }
                }
            },
            "responses": { "204": { "description": "done" } }
        });
        let (_files, diagnostics, _has_errors) = compile_document(document, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
        });
        // Once for the component root, once for nothing else: the body reaches the union through a
        // `$ref`, and a referenced component is walked as its own root exactly once.
        assert_eq!(refusals(&diagnostics).len(), 1, "{diagnostics:#?}");
    }

    /// Compiles a minimal client-enabled document, applying `patch` to the resolved config before
    /// emission. The config guard still refuses non-`string` representations at load time, so the
    /// representation is set on the resolved value — which is exactly what the emitter reads.
    fn compile(patch: fn(&mut ResolvedConfig)) -> Vec<GeneratedFile> {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        let document: Value = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
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
                        "properties": { "bornAt": { "type": "string", "format": "date-time" } }
                    }
                }
            }
        });
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write document");
        fs::write(
            &config_path,
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true },
                "client": {},
                "validation": { "engine": "off", "unchecked": "allow" }
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
        let client = build_client_model(&analyzed, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            Some(&client),
            &mut sink,
        );
        assert!(!sink.has_errors());
        files
    }

    fn find<'files>(files: &'files [GeneratedFile], name: &str) -> Option<&'files GeneratedFile> {
        let wanted = format!("client/transform/{name}");
        files.iter().find(|file| file.relative_path == wanted)
    }

    #[test]
    fn transform_files_are_absent_in_string_mode() {
        let files = compile(|_| {});
        assert!(find(&files, "runtime.ts").is_none());
        assert!(find(&files, "result.ts").is_none());
    }

    #[test]
    fn the_asset_is_byte_verbatim_apart_from_its_import_extension() {
        for patch in [
            |config: &mut ResolvedConfig| config.types.date_time = DateTimeRepresentation::Date,
            |config: &mut ResolvedConfig| config.types.date_time = DateTimeRepresentation::Temporal,
            |config: &mut ResolvedConfig| config.types.date = DateRepresentation::Temporal,
        ] {
            let files = compile(patch);
            let file = find(&files, "runtime.ts").expect("transform runtime asset");
            // The one difference the shared rewrite is allowed to make, and nothing else: strip the
            // extension from both sides and the emitted bytes are the source bytes exactly.
            assert_eq!(
                file.content.replace("from \"./result.js\"", ""),
                TRANSFORM_RUNTIME_TS.replace(ASSET_RESULT_IMPORT, "")
            );
            assert!(file.content.contains(
                "import { type ApplicationPath, type SourcePointer, TransformError } from \"./result.js\";"
            ));
            assert!(!file.content.contains("Generated by Oasts"));
        }
    }

    #[test]
    fn every_codec_the_kernel_exports_is_one_the_emitter_can_name() {
        // `transform_module_imports` lists the codec names a module may bind, and `Direction::codec`
        // is where they come from. A kernel export starting with `decode`/`encode` that the emitter
        // cannot name would be one no module ever aliases — a collision with no local remedy.
        let mut declared: Vec<&str> = Vec::new();
        for line in TRANSFORM_RUNTIME_TS.lines() {
            let Some(rest) = line.strip_prefix("export function ") else {
                continue;
            };
            let name = rest.split(['<', '(']).next().expect("a declared name");
            if name.starts_with("decode") || name.starts_with("encode") {
                declared.push(name);
            }
        }
        declared.sort_unstable();
        let mut aliasable: Vec<String> = transform_module_imports()
            .remove("runtime")
            .expect("the kernel import entry")
            .into_iter()
            .collect();
        aliasable.sort_unstable();
        assert_eq!(declared, aliasable);
    }

    #[test]
    fn the_asset_imports_only_siblings_so_nothing_but_the_extension_can_move() {
        let relative = TRANSFORM_RUNTIME_TS
            .lines()
            .filter(|line| line.contains("from \"./") || line.contains("from \"../"))
            .collect::<Vec<_>>();
        assert_eq!(relative.len(), 1, "{relative:?}");
        assert!(relative[0].contains(ASSET_RESULT_IMPORT));
        assert!(!relative[0].contains("from \"../"));
    }

    #[test]
    fn the_generated_reexport_carries_the_configured_runtime_directory_and_extension() {
        let files = compile(|config| {
            config.types.date_time = DateTimeRepresentation::Date;
            config.emit.runtime_directory = "shared".to_owned();
            config.emit.import_extension = ".ts".to_owned();
        });
        let file = find(&files, "result.ts").expect("transform result re-export");
        assert!(file.content.starts_with("// Generated by Oasts"));
        assert!(
            file.content
                .contains("export { TransformError } from \"../../shared/result.ts\";")
        );
        assert!(file.content.contains(
            "export type { ApplicationPath, SourcePointer } from \"../../shared/result.ts\";"
        ));
        // The asset never learns the runtime directory; only the re-export does.
        let asset = find(&files, "runtime.ts").expect("transform runtime asset");
        assert!(!asset.content.contains("shared"));
    }
}

#[cfg(test)]
mod pair_tests {
    use serde_json::{Value, json};

    use super::Diagnostic;
    use super::tests::{compile_document, notice_document};
    use crate::config::{DateRepresentation, DateTimeRepresentation, ResolvedConfig};

    fn date_mode(config: &mut ResolvedConfig) {
        config.types.date_time = DateTimeRepresentation::Date;
    }

    fn temporal_mode(config: &mut ResolvedConfig) {
        config.types.date_time = DateTimeRepresentation::Temporal;
        config.types.date = DateRepresentation::Temporal;
    }

    /// The emitted pair module for one component, or `None` when the component emits none.
    fn pairs(schemas: Value, base: &str, patch: fn(&mut ResolvedConfig)) -> Option<String> {
        let (files, diagnostics, has_errors) = compile_document(notice_document(schemas), patch);
        // Read off the sink rather than scanning the diagnostics: a closure over a vector that is
        // empty in every passing run is never instantiated, and llvm-cov scores a never-instantiated
        // closure as an uncovered line under the 100%-lines gate.
        assert!(!has_errors, "{diagnostics:#?}");
        files
            .into_iter()
            .find(|file| file.relative_path == format!("client/transform/components/{base}.ts"))
            .map(|file| file.content)
    }

    #[test]
    fn a_component_shadowing_the_representation_global_is_aliased_not_refused() {
        // `at: Date` meant the imported component before this — a `{ label: string }` object where
        // a `Date` was promised. It compiled, which is what made it dangerous. Refusing the document
        // would have been wrong too: the name is the document's, and the alias is file-local.
        let (files, diagnostics, has_errors) = compile_document(
            notice_document(json!({
                "Date": {
                    "type": "object",
                    "required": ["label"],
                    "properties": { "label": { "type": "string" } }
                },
                "Notice": {
                    "type": "object",
                    "required": ["at", "d"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "d": { "$ref": "#/components/schemas/Date" }
                    }
                }
            })),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        let notice = files
            .iter()
            .find(|file| file.relative_path == "types/components/notice.ts")
            .expect("the component module");
        assert!(
            notice.content.contains("import type { Date as "),
            "{}",
            notice.content
        );
        assert!(notice.content.contains("at: Date;"), "{}", notice.content);
    }

    #[test]
    fn a_component_named_for_a_result_import_aliases_the_import() {
        // Two `import type { ApplicationPath }` in one module before this. The document owns the
        // name; the compiler's own import is what gives way, and only inside this file.
        let content = pairs(
            json!({
                "ApplicationPath": {
                    "type": "object",
                    "required": ["at"],
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Notice": { "$ref": "#/components/schemas/ApplicationPath" }
            }),
            "applicationpath",
            date_mode,
        )
        .expect("a converting component emits a pair module");
        assert!(
            content.contains(
                "import type { ApplicationPath as ApplicationPathBody } from \"../result"
            ),
            "{content}"
        );
        assert!(
            content.contains("path: ApplicationPathBody = []"),
            "{content}"
        );
    }

    #[test]
    fn a_component_whose_codec_names_a_kernel_export_aliases_the_kernel() {
        // `decodeInstant` was both this module's own export and the kernel import it calls.
        let content = pairs(
            json!({
                "Instant": {
                    "type": "object",
                    "required": ["at"],
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Notice": { "$ref": "#/components/schemas/Instant" }
            }),
            "instant",
            temporal_mode,
        )
        .expect("a converting component emits a pair module");
        assert!(
            content.contains("decodeInstant as decodeInstantBody"),
            "{content}"
        );
        assert!(
            content.contains("export function decodeInstant("),
            "{content}"
        );
        assert!(content.contains("decodeInstantBody(value.at"), "{content}");
    }

    #[test]
    fn a_component_whose_codec_name_is_never_imported_keeps_the_plain_name() {
        // `Instant` converts only through a `$ref`, so its module calls a sibling pair and imports
        // no kernel codec — nothing to give way to, and the emitted call stays unaliased.
        let content = pairs(
            json!({
                "Stamp": {
                    "type": "object",
                    "required": ["at"],
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Instant": {
                    "type": "object",
                    "required": ["stamp"],
                    "properties": { "stamp": { "$ref": "#/components/schemas/Stamp" } }
                },
                "Notice": { "$ref": "#/components/schemas/Instant" }
            }),
            "instant",
            temporal_mode,
        )
        .expect("a converting component emits a pair module");
        assert!(!content.contains("as decodeInstantBody"), "{content}");
        assert!(content.contains("decodeStamp(value.stamp"), "{content}");
    }

    #[test]
    fn a_converting_property_named_proto_uses_a_computed_key() {
        // `__proto__: v` and `"__proto__": v` both invoke the prototype setter in a value literal,
        // so either spelling would emit an object without the own property its type declares.
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["__proto__"],
                    "properties": { "__proto__": { "type": "string", "format": "date-time" } }
                }
            }),
            "notice",
            |config| config.types.date_time = DateTimeRepresentation::Date,
        )
        .expect("a pair module");

        assert!(
            content.contains("[\"__proto__\"]: decodeDateTimeDate("),
            "{content}"
        );
        assert!(!content.contains("\n    __proto__:"), "{content}");
    }

    #[test]
    fn merged_allof_branches_assign_a_shared_property_once() {
        let content = pairs(
            json!({
                "Notice": {
                    "allOf": [
                        {
                            "type": "object",
                            "required": ["at"],
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        {
                            "type": "object",
                            "required": ["at"],
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            }),
            "notice",
            |config| config.types.date_time = DateTimeRepresentation::Date,
        )
        .expect("a pair module");

        // A duplicate key is not a style problem: TypeScript refuses the object literal outright.
        let decode = content
            .split("export function encodeNotice")
            .next()
            .expect("the decode half");
        assert_eq!(
            decode.matches("at: decodeDateTimeDate(").count(),
            1,
            "{content}"
        );
    }

    #[test]
    fn a_converting_index_signature_beside_declared_properties_is_refused() {
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "type": "object",
                    "required": ["at"],
                    "properties": { "at": { "type": "string", "format": "date-time" } },
                    "additionalProperties": { "type": "string", "format": "date-time" }
                }
            })),
            |config| config.types.date_time = DateTimeRepresentation::Date,
        );

        let messages = unconvertible_messages(&diagnostics);
        assert_eq!(messages.len(), 1, "{diagnostics:#?}");
        assert!(messages[0].contains("index signature"), "{messages:?}");
    }

    /// Every message the unconvertible-transform refusal emitted. A loop rather than an iterator
    /// chain, for the reason `shadow_messages` gives.
    fn unconvertible_messages(diagnostics: &[Diagnostic]) -> Vec<&str> {
        let mut messages = Vec::new();
        for diagnostic in diagnostics {
            if diagnostic.code == "OASTS1314" {
                messages.push(diagnostic.message.as_str());
            }
        }
        messages
    }

    #[test]
    fn a_converting_pattern_property_is_refused() {
        // Emitted `{ [key: `x-${string}`]: Date }` and no codec at all before this: the index
        // signature promised a converted value nothing ever converted.
        let (_files, diagnostics, _has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "type": "object",
                    "patternProperties": {
                        "^x-": { "type": "string", "format": "date-time" }
                    }
                }
            })),
            date_mode,
        );

        let refusals = unconvertible_messages(&diagnostics);
        assert_eq!(refusals.len(), 1, "{diagnostics:#?}");
        assert!(
            refusals[0].contains("pattern property '^x-'"),
            "{refusals:?}"
        );
    }

    #[test]
    fn a_pattern_property_that_declares_no_index_signature_is_left_alone() {
        // The types emitter renders a signature only for a pattern it can turn into a key type.
        // One it cannot declares nothing, so nothing promises a converted value and nothing is
        // refused — reachability and that rendering have to agree on which patterns count.
        let (_files, diagnostics, has_errors) = compile_document(
            notice_document(json!({
                "Notice": {
                    "type": "object",
                    "patternProperties": {
                        "^x-[0-9]+$": { "type": "string", "format": "date-time" }
                    }
                }
            })),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(
            unconvertible_messages(&diagnostics).is_empty(),
            "{diagnostics:#?}"
        );
    }

    /// The union-dispatch expression a `Notice` component compiles its decode to.
    fn notice_decode(notice: Value, patch: fn(&mut ResolvedConfig)) -> String {
        let content = pairs(notice, "notice", patch).expect("a pair module");
        let start = content
            .find("export function decodeNotice")
            .expect("decode");
        let end = content[start..].find("\n}").expect("close") + start;
        content[start..end].to_owned()
    }

    fn timed() -> Value {
        json!({
            "type": "object",
            "required": ["at"],
            "properties": { "at": { "type": "string", "format": "date-time" } }
        })
    }

    #[test]
    fn a_required_property_converts_in_place() {
        let content = pairs(json!({ "Notice": timed() }), "notice", date_mode).expect("pairs");
        assert!(
            content.contains("at: decodeDateTimeDate(value.at, P0, pushPath(path, \"at\"))"),
            "{content}"
        );
        assert!(
            content.contains("at: encodeDateTimeDate(value.at, P0, pushPath(path, \"at\"))"),
            "{content}"
        );
        assert!(content.contains("export function decodeNotice(value: NoticeWire, path: ApplicationPath = []): Notice {"), "{content}");
        assert!(content.contains("export function encodeNotice(value: Notice, path: ApplicationPath = []): NoticeWire {"), "{content}");
    }

    #[test]
    fn an_optional_property_loses_its_key_from_the_base_spread() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(content.contains("...omit(value, \"at\")"), "{content}");
        assert!(
            content.contains("...(value.at === undefined ? {} : { at: decodeDateTimeDate("),
            "{content}"
        );
    }

    #[test]
    fn a_nullable_property_guards_null_before_the_codec() {
        let content = pairs(
            json!({
                "Notice": {
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
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("typeof value.at === \"string\" ? decodeDateTimeDate("),
            "{content}"
        );
        assert!(
            content.contains("value.at instanceof Date ? encodeDateTimeDate("),
            "{content}"
        );
    }

    #[test]
    fn a_nested_object_converts_at_its_own_path() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["inner"],
                    "properties": {
                        "inner": {
                            "type": "object",
                            "required": ["at"],
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("pushPath(pushPath(path, \"inner\"), \"at\")"),
            "{content}"
        );
        assert!(content.contains("inner: {"), "{content}");
    }

    #[test]
    fn an_array_converts_element_wise_with_the_index_in_the_path() {
        let content = pairs(
            json!({
                "Notice": {
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
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("value.stamps.map((item0, index0) => decodeDateTimeDate(item0, P0, pushPath(pushPath(path, \"stamps\"), index0)))"),
            "{content}"
        );
    }

    #[test]
    fn a_tuple_converts_its_positions_and_its_rest() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["pair"],
                    "properties": {
                        "pair": {
                            "type": "array",
                            "prefixItems": [
                                { "type": "string" },
                                { "type": "string", "format": "date-time" }
                            ],
                            "items": { "type": "string", "format": "date-time" }
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(content.contains("value.pair[0]"), "{content}");
        assert!(
            content.contains("decodeDateTimeDate(value.pair[1],"),
            "{content}"
        );
        assert!(content.contains("...value.pair.slice(2).map("), "{content}");
    }

    #[test]
    fn an_open_map_converts_every_entry() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["byId"],
                    "properties": {
                        "byId": {
                            "type": "object",
                            "additionalProperties": { "type": "string", "format": "date-time" }
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("Object.fromEntries(Object.entries(value.byId).map(([key0, entry0]) => [key0, decodeDateTimeDate(entry0,"),
            "{content}"
        );
    }

    #[test]
    fn a_referenced_component_is_called_never_re_inlined() {
        let content = pairs(
            json!({
                "Inner": timed(),
                "Notice": {
                    "type": "object",
                    "required": ["inner"],
                    "properties": { "inner": { "$ref": "#/components/schemas/Inner" } }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("import { decodeInner, encodeInner } from \"./inner.js\";"),
            "{content}"
        );
        assert!(
            content.contains("inner: decodeInner(value.inner, pushPath(path, \"inner\"))"),
            "{content}"
        );
        assert!(!content.contains("decodeDateTimeDate"), "{content}");
    }

    #[test]
    fn a_recursive_component_calls_itself_and_imports_nothing() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["at"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "child": { "$ref": "#/components/schemas/Notice" }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("child: decodeNotice(value.child, pushPath(path, \"child\"))"),
            "{content}"
        );
        assert!(!content.contains("from \"./notice.js\""), "{content}");
    }

    #[test]
    fn pointer_constants_are_hoisted_in_first_seen_order_and_shared_by_both_directions() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["a", "b"],
                    "properties": {
                        "a": { "type": "string", "format": "date-time" },
                        "b": { "type": "string", "format": "date-time" }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(content.contains("const P0 = { logicalSourceId: \"workspace/openapi.json\", jsonPointer: \"/components/schemas/Notice/properties/a\" };"), "{content}");
        assert!(content.contains("const P1 = { logicalSourceId: \"workspace/openapi.json\", jsonPointer: \"/components/schemas/Notice/properties/b\" };"), "{content}");
        assert!(!content.contains("P2"), "{content}");
        assert_eq!(
            content.matches("P0, pushPath(path, \"a\")").count(),
            2,
            "{content}"
        );
    }

    #[test]
    fn a_kind_dispatched_union_tests_the_wire_kind_and_the_application_shape() {
        let decode = notice_decode(
            json!({
                "Inner": timed(),
                "Notice": {
                    "type": "object",
                    "required": ["slot"],
                    "properties": {
                        "slot": {
                            "oneOf": [
                                { "type": "string" },
                                { "$ref": "#/components/schemas/Inner" }
                            ]
                        }
                    }
                }
            }),
            date_mode,
        );
        assert!(
            decode.contains("(typeof value.slot === \"object\" && value.slot !== null && !Array.isArray(value.slot)) ? decodeInner("),
            "{decode}"
        );
    }

    #[test]
    fn a_shared_union_applies_one_conversion_with_no_dispatch() {
        let decode = notice_decode(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["slot"],
                    "properties": {
                        "slot": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "required": ["at"],
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" },
                                        "left": { "type": "string" }
                                    }
                                },
                                {
                                    "type": "object",
                                    "required": ["at"],
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" },
                                        "right": { "type": "integer" }
                                    }
                                }
                            ]
                        }
                    }
                }
            }),
            date_mode,
        );
        assert!(!decode.contains(" ? "), "no dispatch at all: {decode}");
        assert!(
            decode.contains("at: decodeDateTimeDate(value.slot.at,"),
            "{decode}"
        );
    }

    #[test]
    fn a_discriminated_union_dispatches_on_the_tag_property() {
        let decode = notice_decode(
            json!({
                "Reminder": {
                    "type": "object",
                    "required": ["kind", "at"],
                    "properties": {
                        "kind": { "type": "string", "const": "reminder" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "Digest": {
                    "type": "object",
                    "required": ["kind", "on"],
                    "properties": {
                        "kind": { "type": "string", "const": "digest" },
                        "on": { "type": "string", "format": "date" }
                    }
                },
                "Notice": {
                    "type": "object",
                    "required": ["slot"],
                    "properties": {
                        "slot": {
                            "oneOf": [
                                { "$ref": "#/components/schemas/Reminder" },
                                { "$ref": "#/components/schemas/Digest" }
                            ],
                            "discriminator": { "propertyName": "kind" }
                        }
                    }
                }
            }),
            temporal_mode,
        );
        assert!(
            decode.contains("value.slot.kind === \"reminder\" ? decodeReminder("),
            "{decode}"
        );
        assert!(
            decode.contains("value.slot.kind === \"digest\" ? decodeDigest("),
            "{decode}"
        );
    }

    #[test]
    fn temporal_modes_name_their_codecs_and_carry_the_lib_reference() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["at", "on"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "on": { "type": "string", "format": "date" }
                    }
                }
            }),
            "notice",
            temporal_mode,
        )
        .expect("pairs");
        assert!(content.contains("decodeInstant(value.at,"), "{content}");
        assert!(content.contains("decodePlainDate(value.on,"), "{content}");
        assert!(content.contains("encodeInstant(value.at,"), "{content}");
        assert!(content.contains("encodePlainDate(value.on,"), "{content}");
        // No Temporal type is named in a pair module, so it needs no lib reference of its own.
        assert!(!content.contains("esnext.temporal"), "{content}");
    }

    #[test]
    fn a_property_that_does_not_convert_is_left_to_the_base_spread() {
        let content = pairs(
            json!({
                "Plain": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Notice": {
                    "type": "object",
                    "required": ["at", "tags", "plain", "pair", "rest"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "tags": { "type": "array", "items": { "type": "string" } },
                        "plain": { "$ref": "#/components/schemas/Plain" },
                        "pair": {
                            "type": "array",
                            "prefixItems": [{ "type": "string" }, { "type": "integer" }],
                            "items": false
                        },
                        "rest": {
                            "type": "array",
                            "prefixItems": [{ "type": "string", "format": "date-time" }],
                            "items": { "type": "integer" }
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        for absent in ["tags:", "plain:", "pair:"] {
            assert!(
                !content.contains(absent),
                "{absent} should ride the spread: {content}"
            );
        }
        assert!(content.contains("...value.rest.slice(1)"), "{content}");
        assert!(
            !content.contains("...value.rest.slice(1).map("),
            "{content}"
        );
    }

    #[test]
    fn an_all_of_composes_its_branches_conversions() {
        let content = pairs(
            json!({
                "Base": {
                    "type": "object",
                    "required": ["at"],
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Notice": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Base" },
                        {
                            "type": "object",
                            "required": ["on"],
                            "properties": { "on": { "type": "string", "format": "date-time" } }
                        },
                        { "type": "object", "properties": { "id": { "type": "string" } } }
                    ]
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        // The ref's own pair runs first, then the inline branch converts its own property over the
        // result — each spreads what it does not touch, so both survive.
        assert!(content.contains("...decodeBase(value, path),"), "{content}");
        assert!(
            content.contains("on: decodeDateTimeDate(value.on,"),
            "{content}"
        );
    }

    #[test]
    fn branches_and_maps_that_do_not_convert_add_nothing() {
        let content = pairs(
            json!({
                "Plain": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Notice": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Plain" },
                        {
                            "type": "object",
                            "required": ["at", "labels"],
                            "properties": {
                                "at": { "type": "string", "format": "date-time" },
                                "labels": {
                                    "type": "object",
                                    "additionalProperties": { "type": "string" }
                                }
                            }
                        }
                    ]
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("at: decodeDateTimeDate(value.at,"),
            "{content}"
        );
        assert!(!content.contains("decodePlain"), "{content}");
        assert!(!content.contains("labels:"), "{content}");
        assert!(!content.contains("Object.fromEntries"), "{content}");
    }

    #[test]
    fn a_nested_all_of_flattens_into_one_object() {
        let content = pairs(
            json!({
                "Notice": {
                    "allOf": [
                        {
                            "allOf": [
                                {
                                    "type": "object",
                                    "required": ["at"],
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" }
                                    }
                                }
                            ]
                        },
                        {
                            "type": "object",
                            "required": ["on"],
                            "properties": { "on": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("at: decodeDateTimeDate(value.at,"),
            "{content}"
        );
        assert!(
            content.contains("on: decodeDateTimeDate(value.on,"),
            "{content}"
        );
        assert_eq!(
            content.matches("...value,").count(),
            2,
            "one spread each way: {content}"
        );
    }

    #[test]
    fn a_union_whose_converting_branches_all_drop_out_stays_identity() {
        // Both branches are objects whose only date is writeOnly, so the response position converts
        // nothing at all even though the component reaches a transform through the request position.
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["slot"],
                    "properties": {
                        "slot": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "required": ["at"],
                                    "properties": {
                                        "at": {
                                            "type": "string",
                                            "format": "date-time",
                                            "writeOnly": true
                                        }
                                    }
                                },
                                { "type": "integer" }
                            ]
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("export function decodeNoticeResponse(value: NoticeResponseWire, path: ApplicationPath = []): NoticeResponse {\n  return value;\n}"),
            "{content}"
        );
    }

    #[test]
    fn a_three_zero_nullable_site_guards_null_before_the_codec() {
        let (files, _diagnostics, _has_errors) = compile_document(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/notices": {
                        "get": {
                            "operationId": "listNotices",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": { "$ref": "#/components/schemas/Notice" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "components": {
                    "schemas": {
                        "Notice": {
                            "type": "object",
                            "required": ["at"],
                            "properties": {
                                "at": {
                                    "type": "string",
                                    "format": "date-time",
                                    "nullable": true
                                }
                            }
                        }
                    }
                }
            }),
            date_mode,
        );
        let content = files
            .into_iter()
            .find(|file| file.relative_path == "client/transform/components/notice.ts")
            .expect("pairs")
            .content;
        assert!(
            content.contains("at: value.at === null ? null : decodeDateTimeDate(value.at,"),
            "{content}"
        );
    }

    #[test]
    fn a_temporal_union_tests_the_runtime_object_when_encoding() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["at", "on"],
                    "properties": {
                        "at": {
                            "oneOf": [
                                { "type": "string", "format": "date-time" },
                                { "type": "integer" }
                            ]
                        },
                        "on": {
                            "oneOf": [
                                { "type": "string", "format": "date" },
                                { "type": "integer" }
                            ]
                        }
                    }
                }
            }),
            "notice",
            temporal_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("isInstant(value.at) ? encodeInstant("),
            "{content}"
        );
        assert!(
            content.contains("isPlainDate(value.on) ? encodePlainDate("),
            "{content}"
        );
        assert!(content.contains("import { decodeInstant, decodePlainDate, encodeInstant, encodePlainDate, isInstant, isPlainDate, pushPath }"), "{content}");
    }

    #[test]
    fn a_union_of_an_array_and_a_nullable_object_tests_both_kinds() {
        let content = pairs(
            json!({
                "Inner": timed(),
                "Notice": {
                    "type": "object",
                    "required": ["slot"],
                    "properties": {
                        "slot": {
                            "oneOf": [
                                {
                                    "type": "array",
                                    "items": { "$ref": "#/components/schemas/Inner" }
                                },
                                { "type": "integer" }
                            ]
                        }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("Array.isArray(value.slot) ? value.slot.map("),
            "{content}"
        );
    }

    #[test]
    fn a_nullable_converting_branch_tests_null_alongside_its_own_kind() {
        let (files, _diagnostics, _has_errors) = compile_document(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/notices": {
                        "get": {
                            "operationId": "listNotices",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": { "$ref": "#/components/schemas/Notice" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "components": {
                    "schemas": {
                        "Notice": {
                            "type": "object",
                            "required": ["slot"],
                            "properties": {
                                "slot": {
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "nullable": true,
                                            "required": ["at"],
                                            "properties": {
                                                "at": { "type": "string", "format": "date-time" }
                                            }
                                        },
                                        { "type": "integer" }
                                    ]
                                }
                            }
                        }
                    }
                }
            }),
            date_mode,
        );
        let content = files
            .into_iter()
            .find(|file| file.relative_path == "client/transform/components/notice.ts")
            .expect("pairs")
            .content;
        assert!(
            content.contains("value.slot === null || (typeof value.slot === \"object\""),
            "{content}"
        );
    }

    #[test]
    fn a_property_key_needing_quotes_is_accessed_by_index() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["born-at"],
                    "properties": { "born-at": { "type": "string", "format": "date-time" } }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        assert!(
            content.contains("\"born-at\": decodeDateTimeDate(value[\"born-at\"], P0, pushPath(path, \"born-at\"))"),
            "{content}"
        );
    }

    #[test]
    fn an_unallocatable_component_emits_no_pair_module() {
        // "CON" is a Windows reserved device name, so no file base is allocated for it and the run
        // already carries the OASTS1301 refusal — the pair emitter must skip it rather than panic.
        let (files, diagnostics, has_errors) = compile_document(
            notice_document(json!({ "CON": timed(), "Notice": timed() })),
            date_mode,
        );
        assert!(has_errors, "{diagnostics:#?}");
        assert!(
            diagnostics.iter().any(|d| d.code == "OASTS1301"),
            "{diagnostics:#?}"
        );
        assert!(!files.iter().any(|file| {
            file.relative_path
                .starts_with("client/transform/components/con")
        }));
    }

    #[test]
    fn a_component_reaching_no_transform_emits_no_pair_module() {
        assert!(
            pairs(
                json!({
                    "Notice": { "type": "object", "properties": { "id": { "type": "string" } } }
                }),
                "notice",
                date_mode,
            )
            .is_none()
        );
    }

    #[test]
    fn string_mode_emits_no_pair_module() {
        assert!(pairs(json!({ "Notice": timed() }), "notice", |_| {}).is_none());
    }

    #[test]
    fn a_position_split_component_emits_a_pair_per_position() {
        let content = pairs(
            json!({
                "Notice": {
                    "type": "object",
                    "required": ["at", "id", "secret"],
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "id": { "type": "string", "readOnly": true },
                        "secret": { "type": "string", "writeOnly": true }
                    }
                }
            }),
            "notice",
            date_mode,
        )
        .expect("pairs");
        for name in [
            "decodeNotice",
            "encodeNotice",
            "decodeNoticeRequest",
            "encodeNoticeRequest",
            "decodeNoticeResponse",
            "encodeNoticeResponse",
        ] {
            assert!(
                content.contains(&format!("export function {name}(")),
                "{name}: {content}"
            );
        }
    }
}

#[cfg(test)]
mod operation_pair_tests {
    use serde_json::{Value, json};

    use super::tests::compile_document;
    use crate::config::{DateTimeRepresentation, ResolvedConfig};
    use crate::emit::GeneratedFile;

    fn date_mode(config: &mut ResolvedConfig) {
        config.types.date_time = DateTimeRepresentation::Date;
    }

    fn operation_document(operation: Value, schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/events": { "post": operation } },
            "components": { "schemas": schemas }
        })
    }

    fn operation_module<'files>(files: &'files [GeneratedFile], base: &str) -> Option<&'files str> {
        files
            .iter()
            .find(|file| file.relative_path == format!("client/transform/operations/{base}.ts"))
            .map(|file| file.content.as_str())
    }

    fn operation_types<'files>(files: &'files [GeneratedFile], base: &str) -> &'files str {
        files
            .iter()
            .find(|file| file.relative_path == format!("types/operations/{base}.ts"))
            .map(|file| file.content.as_str())
            .expect("operation types")
    }

    fn client_operation<'files>(files: &'files [GeneratedFile], base: &str) -> &'files str {
        files
            .iter()
            .find(|file| file.relative_path == format!("client/operations/{base}.ts"))
            .map(|file| file.content.as_str())
            .expect("client operation")
    }

    /// The messages an emission refused for a position no single codec is keyed on.
    fn refused(diagnostics: &[crate::diag::Diagnostic]) -> Vec<&str> {
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1314")
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    fn event_schema() -> Value {
        json!({
            "Event": {
                "type": "object",
                "required": ["at"],
                "properties": { "at": { "type": "string", "format": "date-time" } }
            }
        })
    }

    #[test]
    fn a_converting_form_body_emits_a_field_encoder() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "submitEventForm",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "required": ["at"],
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" },
                                        "label": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "204": { "description": "ok" } }
                }),
                json!({}),
            ),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refused(&diagnostics).is_empty(), "{diagnostics:#?}");
        let content = operation_module(&files, "submiteventform").expect("operation codec");
        assert!(
            content.contains("at: encodeDateTimeDate(value.body.at"),
            "{content}"
        );
        assert!(!content.contains("value.body.label"), "{content}");
    }

    #[test]
    fn a_converting_multipart_body_emits_the_exact_field_key() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "uploadEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["happened-at"],
                                    "properties": {
                                        "happened-at": {
                                            "type": "string",
                                            "format": "date-time"
                                        },
                                        "label": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "204": { "description": "ok" } }
                }),
                json!({}),
            ),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refused(&diagnostics).is_empty(), "{diagnostics:#?}");
        let content = operation_module(&files, "uploadevent").expect("operation codec");
        assert!(
            content.contains("\"happened-at\": encodeDateTimeDate(value.body[\"happened-at\"]"),
            "{content}"
        );
        assert!(!content.contains("value.body.label"), "{content}");
    }

    #[test]
    fn a_discriminated_request_body_dispatches_only_to_the_converting_arm() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "submitEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/Event" }
                            },
                            "application/vnd.label+json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["label"],
                                    "properties": { "label": { "type": "string" } }
                                }
                            }
                        }
                    },
                    "responses": { "204": { "description": "ok" } }
                }),
                event_schema(),
            ),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refused(&diagnostics).is_empty(), "{diagnostics:#?}");
        let content = operation_module(&files, "submitevent").expect("operation codec");
        assert!(
            content.contains("value.body.contentType === \"application/json\""),
            "{content}"
        );
        assert!(
            content.contains("body: encodeEvent(value.body.body"),
            "{content}"
        );
        assert!(
            !content.contains("value.body.contentType === \"application/vnd.label+json\""),
            "{content}"
        );

        let client = client_operation(&files, "submitevent");
        assert!(
            client.contains("contentType: \"application/json\""),
            "{client}"
        );
        assert!(
            client.contains("contentType: \"application/vnd.label+json\""),
            "{client}"
        );
    }

    #[test]
    fn a_transforming_request_body_mixed_with_a_media_range_is_refused() {
        let (_files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "submitRangedEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/Event" }
                            },
                            "text/*": { "schema": { "type": "string" } }
                        }
                    },
                    "responses": { "204": { "description": "ok" } }
                }),
                event_schema(),
            ),
            date_mode,
        );

        assert!(has_errors, "{diagnostics:#?}");
        assert_eq!(
            refused(&diagnostics),
            [
                "a content-type-discriminated request body mixes media ranges with multiple arms, so its string contentType cannot select one date/time conversion; use concrete media types, or set the representation back to string"
            ],
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn concrete_request_body_arms_encode_their_rendered_input_shapes() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "submitFlexibleEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {},
                            "application/octet-stream": {},
                            "application/problem+json": {
                                "schema": { "$ref": "#/components/schemas/Problem" }
                            },
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "required": ["label"],
                                    "properties": { "label": { "type": "string" } }
                                }
                            },
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["archive", "occurredAt"],
                                    "properties": {
                                        "archive": {},
                                        "occurredAt": {
                                            "type": "string",
                                            "format": "date-time"
                                        }
                                    }
                                },
                                "encoding": {
                                    "occurredAt": { "contentType": "text/plain, text/*" }
                                }
                            },
                            "text/plain": { "schema": { "type": "string" } }
                        }
                    },
                    "responses": { "204": { "description": "ok" } }
                }),
                json!({
                    "Problem": {
                        "type": "object",
                        "properties": { "detail": { "type": "string" } }
                    }
                }),
            ),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refused(&diagnostics).is_empty(), "{diagnostics:#?}");
        let content = operation_module(&files, "submitflexibleevent").expect("operation codec");
        assert!(
            content.contains("value.body.contentType === \"multipart/form-data\""),
            "{content}"
        );
        assert!(
            content.contains("encodeDateTimeDate(value.body.body.occurredAt.body"),
            "{content}"
        );
        assert!(!content.contains("value.body.body.archive"), "{content}");

        let client = client_operation(&files, "submitflexibleevent");
        assert!(
            client.contains("contentType: \"application/json\"; body: unknown"),
            "{client}"
        );
        assert!(client.contains("body: Problem"), "{client}");
        assert!(client.contains("archive: Blob | File"), "{client}");
        assert!(
            client.contains("occurredAt: { body: Date; contentType: string }"),
            "{client}"
        );
    }

    #[test]
    fn a_converting_discriminated_response_entry_is_refused_before_an_unsafe_binding() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "readEvent",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Event" }
                                },
                                "application/vnd.api+json": {
                                    "schema": { "$ref": "#/components/schemas/Event" }
                                }
                            }
                        }
                    }
                }),
                event_schema(),
            ),
            date_mode,
        );

        let messages = refused(&diagnostics);
        assert_eq!(
            messages.len(),
            2,
            "one per declared media entry: {diagnostics:#?}"
        );
        assert!(has_errors, "{diagnostics:#?}");
        assert!(
            messages[0].contains("narrowed by contentType on the result"),
            "{messages:?}"
        );
        let client = client_operation(&files, "readevent");
        assert!(
            client.contains("contentType: \"application/json\""),
            "{client}"
        );
        assert!(!client.contains("ReadEventResultWire"), "{client}");
        assert!(!client.contains("decodeReadEventResponse200"), "{client}");
    }

    #[test]
    fn a_converting_multipart_response_part_is_refused_with_its_own_reason() {
        let (_files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "downloadEvent",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "properties": {
                                            "event": { "$ref": "#/components/schemas/Event" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }),
                event_schema(),
            ),
            date_mode,
        );

        assert!(has_errors, "{diagnostics:#?}");
        assert_eq!(
            refused(&diagnostics),
            [
                "response '200' entry 'multipart/form-data' applies a date/time transform, but its decoded multipart object is rendered inline while the response converter accepts the status-wide media alias; set the representation back to string"
            ],
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn a_multipart_binary_part_does_not_claim_a_transform() {
        let (_files, diagnostics, has_errors) = compile_document(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/events": {
                        "post": {
                            "operationId": "downloadArchive",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "multipart/form-data": {
                                            "schema": {
                                                "type": "object",
                                                "additionalProperties": false,
                                                "properties": {
                                                    "archive": {
                                                        "type": "string",
                                                        "format": "binary"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "components": { "schemas": event_schema() }
            }),
            date_mode,
        );

        assert!(!has_errors, "{diagnostics:#?}");
        assert!(refused(&diagnostics).is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_converting_open_multipart_fallback_is_refused() {
        let (_files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "downloadEventFields",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "additionalProperties": {
                                            "type": "string",
                                            "format": "date-time"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }),
                json!({}),
            ),
            date_mode,
        );

        assert!(has_errors, "{diagnostics:#?}");
        assert_eq!(
            refused(&diagnostics),
            [
                "response '200' entry 'multipart/form-data' applies a date/time transform, but its decoded multipart object is rendered inline while the response converter accepts the status-wide media alias; set the representation back to string"
            ],
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn operations_without_allocated_names_or_files_emit_no_transform_module() {
        let response = json!({
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "schema": { "type": "string", "format": "date-time" }
                    }
                }
            }
        });
        let (files, diagnostics, has_errors) = compile_document(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/invalid-name": {
                        "get": {
                            "operationId": "---",
                            "responses": response
                        }
                    },
                    "/invalid-file": {
                        "get": {
                            "operationId": "CON",
                            "responses": response
                        }
                    }
                }
            }),
            date_mode,
        );
        assert!(has_errors, "{diagnostics:#?}");
        for code in ["OASTS1201", "OASTS1301"] {
            assert!(
                diagnostics.iter().any(|diagnostic| diagnostic.code == code),
                "missing {code}: {diagnostics:#?}"
            );
        }
        assert!(files.iter().all(|file| {
            !file
                .relative_path
                .starts_with("client/transform/operations/")
        }));
    }

    #[test]
    fn an_inline_request_body_emits_an_operation_encoder() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "recordInlineEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["startedAt"],
                                    "properties": {
                                        "startedAt": {
                                            "type": "string",
                                            "format": "date-time"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "204": { "description": "done" } }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let content = operation_module(&files, "recordinlineevent").expect("operation codec");
        assert!(content.contains("import type { RecordInlineEventInput, RecordInlineEventInputWire } from \"../../operations/recordinlineevent.js\";"), "{content}");
        assert!(content.contains("export function encodeRecordInlineEventInput(value: RecordInlineEventInput, path: ApplicationPath = []): RecordInlineEventInputWire"), "{content}");
        assert!(
            content.contains("startedAt: encodeDateTimeDate(value.body.startedAt"),
            "{content}"
        );
    }

    #[test]
    fn an_inline_response_body_emits_an_operation_decoder() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "readInlineEvent",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["acceptedAt"],
                                        "properties": {
                                            "acceptedAt": {
                                                "type": "string",
                                                "format": "date-time"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let content = operation_module(&files, "readinlineevent").expect("operation codec");
        assert!(content.contains("export function decodeReadInlineEventResponse200(value: ReadInlineEventResponse200Wire, path: ApplicationPath = []): ReadInlineEventResponse200"), "{content}");
        assert!(
            content.contains("acceptedAt: decodeDateTimeDate(value.acceptedAt"),
            "{content}"
        );
    }

    #[test]
    fn response_media_shapes_cover_text_binary_and_media_unions() {
        let timed = json!({
            "type": "object",
            "required": ["acceptedAt"],
            "properties": {
                "acceptedAt": { "type": "string", "format": "date-time" }
            }
        });
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "readMediaEvent",
                    "responses": {
                        "200": {
                            "description": "json or text",
                            "content": {
                                "application/json": { "schema": timed },
                                "text/plain": { "schema": { "type": "string" } }
                            }
                        },
                        "201": {
                            "description": "json or binary",
                            "content": {
                                "application/json": { "schema": timed },
                                "application/octet-stream": {
                                    "schema": { "type": "string", "format": "binary" }
                                }
                            }
                        }
                    }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(has_errors, "{diagnostics:#?}");
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1314")
                .count(),
            2,
            "{diagnostics:#?}"
        );
        let content = operation_module(&files, "readmediaevent").expect("operation codec");
        assert!(
            content.contains("export function decodeReadMediaEventResponse200"),
            "{content}"
        );
        assert!(
            content.contains(
                "(typeof value === \"object\" && value !== null && !Array.isArray(value)) ? {"
            ),
            "{content}"
        );
        assert!(
            content.contains("export function decodeReadMediaEventResponse201"),
            "{content}"
        );
        assert!(
            content.contains("decodeReadMediaEventResponse201(value: ReadMediaEventResponse201Wire, path: ApplicationPath = []): ReadMediaEventResponse201 {\n  return value;"),
            "{content}"
        );
    }

    #[test]
    fn a_referenced_request_body_delegates_to_the_component_pair() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "recordEvent",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/EventDraft" }
                            }
                        }
                    },
                    "responses": { "204": { "description": "done" } }
                }),
                json!({
                    "EventDraft": {
                        "type": "object",
                        "required": ["occurredAt"],
                        "properties": {
                            "occurredAt": { "type": "string", "format": "date-time" }
                        }
                    }
                }),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let content = operation_module(&files, "recordevent").expect("operation codec");
        assert!(
            content.contains("import { encodeEventDraft } from \"../components/eventdraft.js\";"),
            "{content}"
        );
        assert!(content.contains("export function encodeRecordEventInput(value: RecordEventInput, path: ApplicationPath = []): RecordEventInputWire"), "{content}");
        assert!(
            content.contains("body: encodeEventDraft(value.body, pushPath(path, \"body\"))"),
            "{content}"
        );
        assert!(!content.contains("encodeDateTimeDate"), "{content}");
    }

    #[test]
    fn transforming_parameters_emit_a_wire_request_and_convert_arrays_element_wise() {
        let (files, diagnostics, has_errors) = compile_document(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": {
                    "/events/{occurredAt}": {
                        "get": {
                            "operationId": "readEvent",
                            "parameters": [
                                {
                                    "name": "occurredAt",
                                    "in": "path",
                                    "required": true,
                                    "schema": { "type": "string", "format": "date-time" }
                                },
                                {
                                    "name": "window",
                                    "in": "query",
                                    "schema": {
                                        "type": "array",
                                        "items": { "type": "string", "format": "date-time" }
                                    }
                                }
                            ],
                            "responses": { "204": { "description": "done" } }
                        }
                    }
                }
            }),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let types = operation_types(&files, "readevent");
        assert!(
            types.contains("export type ReadEventRequestWire ="),
            "{types}"
        );
        assert!(types.contains("occurredAt: string;"), "{types}");
        assert!(types.contains("window?: string[];"), "{types}");

        let content = operation_module(&files, "readevent").expect("operation codec");
        assert!(
            content.contains("encodeDateTimeDate(value.path.occurredAt"),
            "{content}"
        );
        assert!(
            content.contains("value.query.window.map((item0, index0) => encodeDateTimeDate(item0"),
            "{content}"
        );
        assert!(content.contains("export function encodeReadEventInput(value: ReadEventInput, path: ApplicationPath = []): ReadEventInputWire"), "{content}");
    }

    #[test]
    fn a_caller_serialized_transform_emits_no_input_encoder() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "readOpaqueEvent",
                    "parameters": [{
                        "name": "occurredAt",
                        "in": "query",
                        "content": {
                            "application/octet-stream": {
                                "schema": { "type": "string", "format": "date-time" }
                            }
                        }
                    }],
                    "responses": { "204": { "description": "done" } }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        assert!(operation_module(&files, "readopaqueevent").is_none());
    }

    #[test]
    fn a_caller_serialized_only_group_is_omitted_from_a_body_encoder() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "recordOpaqueEvent",
                    "parameters": [{
                        "name": "opaque",
                        "in": "query",
                        "content": {
                            "application/octet-stream": {
                                "schema": { "type": "string", "format": "date-time" }
                            }
                        }
                    }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["occurredAt"],
                                    "properties": {
                                        "occurredAt": {
                                            "type": "string",
                                            "format": "date-time"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "204": { "description": "done" } }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let content = operation_module(&files, "recordopaqueevent").expect("operation codec");
        assert!(
            content.contains("occurredAt: encodeDateTimeDate(value.body.occurredAt"),
            "{content}"
        );
        assert!(!content.contains("value.query"), "{content}");
    }

    #[test]
    fn input_parameter_groups_follow_client_names_and_optionality() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "filterEvents",
                    "parameters": [
                        {
                            "name": "opaque",
                            "in": "query",
                            "required": true,
                            "content": {
                                "application/octet-stream": {
                                    "schema": { "type": "string", "format": "date-time" }
                                }
                            }
                        },
                        {
                            "name": "since",
                            "in": "query",
                            "schema": { "type": "string", "format": "date-time" }
                        },
                        {
                            "name": "X-At",
                            "in": "header",
                            "schema": { "type": "string", "format": "date-time" }
                        },
                        {
                            "name": "session-at",
                            "in": "cookie",
                            "schema": { "type": "string", "format": "date-time" }
                        }
                    ],
                    "responses": { "204": { "description": "done" } }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        let content = operation_module(&files, "filterevents").expect("operation codec");
        assert!(!content.contains("value.query === undefined"), "{content}");
        assert!(
            content.contains("value.header === undefined ? {} : { header:"),
            "{content}"
        );
        assert!(
            content.contains("value.cookie === undefined ? {} : { cookie:"),
            "{content}"
        );
        assert!(
            content.contains("\"X-At\": encodeDateTimeDate(value.header[\"X-At\"]"),
            "{content}"
        );
        assert!(
            content.contains("\"session-at\": encodeDateTimeDate(value.cookie[\"session-at\"]"),
            "{content}"
        );
        assert!(!content.contains("opaque"), "{content}");
    }

    #[test]
    fn an_operation_reaching_no_transform_emits_no_operation_module() {
        let (files, diagnostics, has_errors) = compile_document(
            operation_document(
                json!({
                    "operationId": "readLabel",
                    "parameters": [
                        {
                            "name": "label",
                            "in": "query",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": { "label": { "type": "string" } }
                                    }
                                }
                            }
                        }
                    }
                }),
                json!({}),
            ),
            date_mode,
        );
        assert!(!has_errors, "{diagnostics:#?}");
        assert!(operation_module(&files, "readlabel").is_none());
    }
}
