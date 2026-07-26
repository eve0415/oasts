//! Deterministic TypeScript types artifact emission.
//!
//! A named, direct object becomes an `interface`; every other named schema is
//! a `type`. This deliberately small rule keeps declaration form independent
//! of formatting details. OpenAPI's omitted/`true` `additionalProperties`
//! remains open without an index signature: `[key: string]: unknown` would
//! force every declared property to be assignable to `unknown` today and to a
//! narrower value if that signature ever changed, so it does not faithfully
//! describe the declared members.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::client_model::ClientModel;
use crate::config::{DocumentationConfig, EnumRepresentation, FileCase, ResolvedConfig};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, Discriminator, ExclusiveBound, Ir, MediaType, NumericConstraints,
    Operation, Param, ParamLocation, PrimitiveType, PropMeta, ResponseEntry, ResponseHeader,
    ResponseStatus, SchemaDocs, SchemaNode, SchemaRef, SourceRef, TupleRest, finite_parts,
};
use crate::media::is_json;
use crate::num::{first_number_outside_binary64, render_number_value};
use crate::semantic::{
    AllocatedCallbackName, AllocatedSchemaName, Analyzed, CallbackParent, EnumMember, ResolvedLink,
};

mod client;
mod model;
pub(crate) mod runtime_assets;
mod validators;

use model::{EmissionModel, SchemaTarget};

const CODE_FILE_NAME: &str = "OASTS1301";
const CODE_PATH_COLLISION: &str = "OASTS1302";
const CODE_COMPOSITION: &str = "OASTS1303";
const CODE_DISCRIMINATOR: &str = "OASTS1304";
const CODE_REFERENCE: &str = "OASTS1305";
const CODE_VARIANT_COLLISION: &str = "OASTS1306";
/// A component import an operation module renames to escape shadowing one of its own declarations,
/// whose role-derived replacement is itself taken by another import or declaration in that module.
/// Nothing is left to rename it to, so the module is refused rather than emitted uncompilable.
const CODE_IMPORT_ALIAS: &str = "OASTS1307";
/// A discriminator `mapping` value that resolves to no allocated component schema — a dangling
/// mapping target the union can never dispatch to.
const CODE_MAPPING_TARGET: &str = "OASTS1308";
/// A discriminator whose `mapping`/`const` proof is internally incoherent — a mapping tag that
/// contradicts the branch's own fixed value, or an allOf idiom that fixes the tag property to an
/// empty (uninhabitable) value set. The render degrades to a plain structural union.
const CODE_DISCRIMINATOR_PROOF: &str = "OASTS1309";

const INDENT_CHUNK: &str = "                                ";

fn push_indent(output: &mut String, mut width: usize) {
    while width >= INDENT_CHUNK.len() {
        output.push_str(INDENT_CHUNK);
        width -= INDENT_CHUNK.len();
    }
    output.push_str(&INDENT_CHUNK[..width]);
}

/// A merged `allOf` property borrowed straight from the model IR: name, schema,
/// and metadata. Borrowed (not owned) so `merge_all_of` never deep-clones the
/// `SchemaNode` payload it already has behind `&'a self` / the branch slice.
type BorrowedProperty<'a> = (&'a str, &'a SchemaNode, &'a PropMeta);

/// A cached `allOf` merge result, keyed in the emitter by the branch slice's IR address.
/// `None` records a slice that does not merge into a single object shape (cached so the
/// negative answer is not recomputed once per position per pass either). The merged
/// properties are shared via `Rc` so a cache hit is a refcount bump, not a `Vec` clone,
/// and are borrowed at the model lifetime because the IR outlives the emitter.
type CachedAllOf<'a> = Option<(Rc<[BorrowedProperty<'a>]>, &'a AdditionalProperties)>;

/// Views an owned property slice as `BorrowedProperty` tuples. The direct-object
/// callers own their properties while the `allOf`-merge caller already holds
/// borrowed ones; funnelling both through this keeps `render_object_parts` a
/// single concrete instantiation for the coverage gate.
fn borrow_properties(properties: &[(String, SchemaNode, PropMeta)]) -> Vec<BorrowedProperty<'_>> {
    properties
        .iter()
        .map(|(name, schema, meta)| (name.as_str(), schema, meta))
        .collect()
}

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

/// Derives a safe base name from a source declaration name.
///
/// The raw name never reaches the file system: it is split into ASCII token
/// runs and only the joined candidate is validated, so a
/// path-shaped source name like `actions/add-labels` derives a safe flat name
/// instead of being rejected.
pub fn file_base_name(name: &str, case: FileCase) -> Result<String, FileNameError> {
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

pub(super) fn uppercase_first(token: &str) -> String {
    change_first_ascii_letter(token, u8::to_ascii_uppercase)
}

fn change_first_ascii_letter(token: &str, transform: fn(&u8) -> u8) -> String {
    let mut bytes = token.as_bytes().to_vec();
    if let Some(byte) = bytes.iter_mut().find(|byte| byte.is_ascii_alphabetic()) {
        *byte = transform(byte);
    }
    String::from_utf8(bytes).expect("transforming ASCII letters preserves UTF-8")
}

/// The import specifier suffix for generated cross-file imports: the configured extension, or the
/// empty string for the `"none"` policy that emits extensionless specifiers.
pub(super) fn import_extension(model: &EmissionModel<'_, '_>) -> String {
    if model.config.emit.import_extension == "none" {
        String::new()
    } else {
        model.config.emit.import_extension.clone()
    }
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
    let mut model = EmissionModel::new(analyzed, config, source_digest(source_tuples), sink);
    emit_types_from_model(&mut model)
}

pub(crate) fn emit_types_from_model(model: &mut EmissionModel<'_, '_>) -> Vec<GeneratedFile> {
    let _client_artifact_emitter = client::emit_client_from_model;
    let _runtime_asset_emitter = runtime_assets::emit_runtime_files;
    Emitter::new(model).emit()
}

/// Emits every enabled artifact (types, client, validators) for one compile.
///
/// Public so out-of-crate harnesses can run the emission stage exactly as
/// `pipeline::compile` does, including a client model when one was built.
pub fn emit_artifacts(
    analyzed: &Analyzed,
    config: &ResolvedConfig,
    source_tuples: &[(String, [u8; 32])],
    client_model: Option<&ClientModel>,
    sink: &mut DiagnosticSink,
) -> Vec<GeneratedFile> {
    let mut model = EmissionModel::new(analyzed, config, source_digest(source_tuples), sink);
    let mut files = emit_types_from_model(&mut model);
    if let Some(client_model) = client_model {
        files.extend(client::emit_client_from_model(&mut model, client_model));
    }
    if config.artifacts.validators.enabled {
        files.extend(validators::emit_validators_from_model(&mut model));
    }
    files.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
    files
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TypePosition {
    Neutral,
    Request,
    Response,
}

#[derive(Clone, Copy)]
enum SchemaChildMode {
    Validation,
    References(TypePosition),
}

pub(super) struct Emitter<'model, 'input, 'sink> {
    model: &'model mut EmissionModel<'input, 'sink>,
    enum_member_indices: BTreeMap<(String, String), usize>,
    /// Resolved link indices (into `model.analyzed.link_targets`), grouped by the response
    /// they were declared on and keyed the same way as `enum_member_indices`. Built only when
    /// the document has at least one link — the fast-reject keeps a link-free document's
    /// emission allocation-identical to before links existed. Each group stays in
    /// `link_targets` order (insertion order, one linear pass), matching the ticket's
    /// deterministic-order requirement without a separate sort.
    link_targets_by_response: BTreeMap<(String, String), Vec<usize>>,
    /// `operation_index -> Stem` for every allocated operation name, the same transform
    /// `emit_operation` applies to its own `stem`. Populated alongside
    /// `link_targets_by_response` (same fast-reject) so a resolved link's target response type
    /// name can be looked up in O(1) instead of scanning `operation_names` per link.
    operation_stems: HashMap<usize, String>,
    /// Refs whose targets `merge_all_of` is currently inlining, along the active
    /// render ancestry. A recursive schema whose `allOf` branch points
    /// back to an ancestor would otherwise inline forever; the branch renders as a
    /// bare named reference instead. Balanced push/pop keeps this empty between
    /// top-level declarations, so acyclic output is byte-identical.
    inlining_refs: RefCell<Vec<SchemaRef>>,
    /// Prewarmed `allOf` merges keyed by `(branch slice address, length)`. Populated
    /// once per distinct IR node by `prewarm_all_of`, then read on every render/import
    /// pass so the merge runs once instead of up to six times per node. Only IR-resident
    /// non-empty slices are keyed here (their address is stable for the emission);
    /// locally built branches miss and recompute, and no live non-empty IR slice can
    /// share a local's address. Empty slices all share the dangling-pointer sentinel, so
    /// `cache_merge_all_of` refuses to insert them.
    merge_cache: RefCell<HashMap<(usize, usize), CachedAllOf<'input>>>,
    /// Component imports the operation module being rendered binds under a different local name,
    /// keyed by the imported variant name. An operation module declares `<Stem>Request` and
    /// `<Stem>Response*` of its own; a component that already carries one of those names would be
    /// shadowed by the local declaration, silently retyping every reference site to the envelope.
    /// Filled for the duration of that one file and empty everywhere else, so a module with no
    /// such component renders byte-identically to before aliasing existed.
    import_aliases: RefCell<HashMap<String, String>>,
    /// Diagnostics raised while rendering, which runs behind `&self` and so cannot reach the
    /// sink. Flushed in emission order once rendering is done.
    deferred_diagnostics: RefCell<Vec<Diagnostic>>,
}

impl<'model, 'input, 'sink> Emitter<'model, 'input, 'sink> {
    pub(super) fn new(model: &'model mut EmissionModel<'input, 'sink>) -> Self {
        let mut enum_member_indices = BTreeMap::new();
        for (index, table) in model.analyzed.enum_members.iter().enumerate() {
            enum_member_indices
                .entry((
                    table.source.source_id.clone(),
                    table.source.json_pointer.clone(),
                ))
                .or_insert(index);
        }
        let mut link_targets_by_response: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        let mut operation_stems: HashMap<usize, String> = HashMap::new();
        if !model.analyzed.link_targets.is_empty() {
            for (index, resolved) in model.analyzed.link_targets.iter().enumerate() {
                let resolved: &ResolvedLink = resolved;
                link_targets_by_response
                    .entry((
                        resolved.response_source.source_id.clone(),
                        resolved.response_source.json_pointer.clone(),
                    ))
                    .or_default()
                    .push(index);
            }
            operation_stems = model
                .analyzed
                .operation_names
                .iter()
                .map(|allocated| (allocated.operation_index, uppercase_first(&allocated.name)))
                .collect();
        }
        Self {
            model,
            enum_member_indices,
            link_targets_by_response,
            operation_stems,
            inlining_refs: RefCell::new(Vec::new()),
            merge_cache: RefCell::new(HashMap::new()),
            import_aliases: RefCell::new(HashMap::new()),
            deferred_diagnostics: RefCell::new(Vec::new()),
        }
    }

    fn emit(mut self) -> Vec<GeneratedFile> {
        self.validate_model();
        // Compute every component's `allOf` merges once up front. Each component is
        // rendered for up to three positions and walked for imports for each, so a node's
        // position-independent merge would otherwise run up to six times; the cache turns
        // the later passes into refcount-cheap hits. All components are prewarmed before
        // any is emitted, so a merge that resolves a `$ref` into a sibling component hits
        // that sibling's prewarmed entry too.
        for allocated in &self.model.analyzed.schema_names {
            if self.model.component_files[allocated.schema_index].is_none() {
                continue;
            }
            self.prewarm_all_of(&self.model.analyzed.ir.schemas[allocated.schema_index].schema);
        }
        // Operations carry inline schemas too (parameters, bodies, response payloads,
        // response headers, encoding headers — the same set validate_model walks); an allOf
        // embedded there never resolves through a component, so without its own prewarm it
        // would fall back to the uncached recompute on every render pass.
        for allocated in &self.model.analyzed.operation_names {
            if self.model.operation_files[allocated.operation_index].is_none() {
                continue;
            }
            let operation = &self.model.analyzed.ir.operations[allocated.operation_index];
            for parameter in &operation.parameters {
                self.prewarm_all_of(&parameter.schema);
            }
            if let Some(body) = &operation.request_body {
                for media_type in &body.media_types {
                    self.prewarm_all_of(&media_type.schema);
                    for (_, encoding) in &media_type.encodings {
                        for (_, header) in &encoding.headers {
                            self.prewarm_all_of(&header.schema);
                        }
                    }
                }
            }
            for response in &operation.responses {
                for media_type in &response.media_types {
                    self.prewarm_all_of(&media_type.schema);
                }
                for (_, header) in &response.headers {
                    self.prewarm_all_of(&header.schema);
                }
            }
        }
        let mut files = Vec::new();
        for allocated in &self.model.analyzed.schema_names {
            if self.model.component_files[allocated.schema_index].is_none() {
                continue;
            }
            files.push(self.emit_component(allocated));
        }
        let mut any_response_headers = false;
        for allocated in &self.model.analyzed.operation_names {
            let Some(file_base) = self.model.operation_files[allocated.operation_index].as_deref()
            else {
                continue;
            };
            let operation = &self.model.analyzed.ir.operations[allocated.operation_index];
            self.push_operation_file(
                &mut files,
                &mut any_response_headers,
                operation,
                &allocated.name,
                "operations",
                file_base,
            );
        }
        // Webhook and callback operations reuse the operation renderer verbatim; their response
        // headers count toward the shared `types/headers.ts` helper just like a path operation's.
        for index in 0..self.model.analyzed.webhook_names.len() {
            let Some(file_base) = self.model.webhook_files[index].as_deref() else {
                continue;
            };
            let allocated = &self.model.analyzed.webhook_names[index];
            let operation = &self.model.analyzed.ir.webhooks[allocated.webhook_index].operations
                [allocated.operation_index];
            self.push_operation_file(
                &mut files,
                &mut any_response_headers,
                operation,
                &allocated.stem,
                "webhooks",
                file_base,
            );
        }
        // A document with any webhook gets the `Webhooks` descriptor, including a webhook whose
        // path item declares no operations (it appears in the map with an empty object type).
        if !self.model.analyzed.ir.webhooks.is_empty() {
            files.push(self.emit_webhooks_index());
        }
        for index in 0..self.model.analyzed.callback_names.len() {
            let Some(file_base) = self.model.callback_files[index].as_deref() else {
                continue;
            };
            let allocated = &self.model.analyzed.callback_names[index];
            let operation = callback_operation(
                &self.model.analyzed.ir,
                &self.model.analyzed.callback_names,
                allocated,
            );
            self.push_operation_file(
                &mut files,
                &mut any_response_headers,
                operation,
                &allocated.stem,
                "callbacks",
                file_base,
            );
        }
        if self.model.callback_files.iter().any(Option::is_some) {
            files.push(self.emit_callbacks_index());
        }
        if any_response_headers {
            files.push(self.emit_headers_helper_file());
        }
        for diagnostic in self.deferred_diagnostics.take() {
            self.model.sink.push(diagnostic);
        }
        files.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
        files
    }

    /// Emits `types/webhooks/index.ts`: the `Webhooks` descriptor mapping each webhook name (as
    /// written in the document, quoted when not a bare identifier) to its per-method
    /// request/response type pair. Method keys are the lowercase IR methods; the per-file
    /// `<Stem>Request`/`<Stem>Response` types are imported from the sibling operation files. A
    /// webhook with no emittable operation contributes an empty object type.
    fn emit_webhooks_index(&self) -> GeneratedFile {
        let analyzed = self.model.analyzed;
        let readonly = self.model.config.types.readonly;
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        let mut body = String::from("export type Webhooks = {\n");
        // webhook_names is grouped by ascending webhook_index (its allocation order), so each
        // webhook's entries are the contiguous run at the cursor — advance through them once rather
        // than rescanning the whole table per webhook.
        let mut cursor = 0;
        for (webhook_index, webhook) in analyzed.ir.webhooks.iter().enumerate() {
            body.push_str("  ");
            if readonly {
                body.push_str("readonly ");
            }
            body.push_str(&render_property_key(&webhook.name));
            body.push_str(": {");
            let mut wrote_method = false;
            while let Some(allocated) = analyzed
                .webhook_names
                .get(cursor)
                .filter(|allocated| allocated.webhook_index == webhook_index)
            {
                let file_base = self.model.webhook_files[cursor].as_deref();
                cursor += 1;
                let Some(file_base) = file_base else {
                    continue;
                };
                if !wrote_method {
                    body.push('\n');
                    wrote_method = true;
                }
                let operation =
                    &analyzed.ir.webhooks[webhook_index].operations[allocated.operation_index];
                self.write_descriptor_method(
                    &mut body,
                    &mut imports,
                    file_base,
                    &allocated.stem,
                    &operation.method,
                    4,
                );
            }
            if wrote_method {
                body.push_str("  };\n");
            } else {
                body.push_str("};\n");
            }
        }
        body.push_str("};\n");
        let mut content = self.header();
        self.write_imports(&mut content, imports, "./");
        content.push_str(&body);
        GeneratedFile {
            relative_path: "types/webhooks/index.ts".to_owned(),
            content,
        }
    }

    /// Emits `types/callbacks/index.ts`: one `<ParentStem>Callbacks` descriptor per operation that
    /// declares callbacks (path, webhook, or nested), in first-declared order. Each maps the
    /// callback name to the runtime expression (verbatim, always a quoted string key — it never
    /// appears in an identifier) to the per-method request/response pair, imported from the sibling
    /// callback operation files.
    fn emit_callbacks_index(&self) -> GeneratedFile {
        let analyzed = self.model.analyzed;
        let ir = &analyzed.ir;
        let readonly = self.model.config.types.readonly;
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        let mut body = String::new();
        let mut seen_parents: HashSet<&CallbackParent> = HashSet::new();
        // A parent's filed callback entries interleave with its nested callbacks' entries in
        // callback_names (pre-order DFS), so group every filed entry by parent once (callback_names
        // order preserved) rather than rescanning the whole table per parent.
        let mut entries_by_parent: HashMap<&CallbackParent, Vec<usize>> = HashMap::new();
        for (index, entry) in analyzed.callback_names.iter().enumerate() {
            if self.model.callback_files[index].is_some() {
                entries_by_parent
                    .entry(&entry.parent)
                    .or_default()
                    .push(index);
            }
        }
        for (index, entry) in analyzed.callback_names.iter().enumerate() {
            if self.model.callback_files[index].is_none() || !seen_parents.insert(&entry.parent) {
                continue;
            }
            if !body.is_empty() {
                body.push('\n');
            }
            let parent = &entry.parent;
            let parent_op = callback_parent_operation(ir, &analyzed.callback_names, parent);
            body.push_str("export type ");
            body.push_str(&uppercase_first(&entry.parent_stem));
            body.push_str("Callbacks = {\n");
            // Filed entries for this parent, already ordered by (callback, expression, operation).
            let entries = &entries_by_parent[parent];
            for callback_group in entries.chunk_by(|&left, &right| {
                analyzed.callback_names[left].callback_index
                    == analyzed.callback_names[right].callback_index
            }) {
                let callback_index = analyzed.callback_names[callback_group[0]].callback_index;
                let callback = &parent_op.callbacks[callback_index];
                body.push_str("  ");
                if readonly {
                    body.push_str("readonly ");
                }
                body.push_str(&render_property_key(&callback.name));
                body.push_str(": {\n");
                for expression_group in callback_group.chunk_by(|&left, &right| {
                    analyzed.callback_names[left].expression_index
                        == analyzed.callback_names[right].expression_index
                }) {
                    let expression_index =
                        analyzed.callback_names[expression_group[0]].expression_index;
                    body.push_str("    ");
                    if readonly {
                        body.push_str("readonly ");
                    }
                    body.push_str(&render_property_key(
                        &callback.expressions[expression_index].expression,
                    ));
                    body.push_str(": {\n");
                    for &i in expression_group {
                        let entry = &analyzed.callback_names[i];
                        let file_base = self.model.callback_files[i].as_deref().unwrap_or_default();
                        let operation = callback_operation(ir, &analyzed.callback_names, entry);
                        self.write_descriptor_method(
                            &mut body,
                            &mut imports,
                            file_base,
                            &entry.stem,
                            &operation.method,
                            6,
                        );
                    }
                    body.push_str("    };\n");
                }
                body.push_str("  };\n");
            }
            body.push_str("};\n");
        }
        let mut content = self.header();
        self.write_imports(&mut content, imports, "./");
        content.push_str(&body);
        GeneratedFile {
            relative_path: "types/callbacks/index.ts".to_owned(),
            content,
        }
    }

    /// Writes one `<method>: { request: <Stem>Request; response: <Stem>Response }` descriptor entry
    /// at the given indent and records the two per-file type imports. Shared by the webhook and
    /// callback descriptor maps, whose method-level shape is identical.
    fn write_descriptor_method(
        &self,
        body: &mut String,
        imports: &mut BTreeMap<String, BTreeSet<String>>,
        file_base: &str,
        stem: &str,
        method: &str,
        indent: usize,
    ) {
        let readonly = self.model.config.types.readonly;
        let stem = uppercase_first(stem);
        let request = format!("{stem}Request");
        let response = format!("{stem}Response");
        let entry = imports.entry(file_base.to_owned()).or_default();
        entry.insert(request.clone());
        entry.insert(response.clone());
        push_indent(body, indent);
        if readonly {
            body.push_str("readonly ");
        }
        body.push_str(method);
        body.push_str(": { ");
        if readonly {
            body.push_str("readonly ");
        }
        body.push_str("request: ");
        body.push_str(&request);
        body.push_str("; ");
        if readonly {
            body.push_str("readonly ");
        }
        body.push_str("response: ");
        body.push_str(&response);
        body.push_str(" };\n");
    }

    /// Emits the shared `TypedHeaders<K>` helper once, only when at least one emitted
    /// response declares a header — a document with none stays byte-identical to before this
    /// helper existed. Pure generated output (no source node backs it, so no
    /// `write_source_metadata` line); later client tickets are what actually construct a
    /// `TypedHeaders` value, so nothing in this ticket references it yet.
    fn emit_headers_helper_file(&self) -> GeneratedFile {
        let mut content = self.header();
        content.push_str("export interface TypedHeaders<K extends string> extends Headers {\n");
        content.push_str("  get(name: K): string | null;\n");
        content.push_str("  get(name: string): string | null;\n");
        content.push_str("}\n");
        GeneratedFile {
            relative_path: "types/headers.ts".to_owned(),
            content,
        }
    }

    fn header(&self) -> String {
        self.model.header()
    }

    fn validate_model(&mut self) {
        let mut diagnostics = Vec::new();
        for schema in &self.model.analyzed.ir.schemas {
            self.validate_schema(&schema.schema, &mut diagnostics);
        }
        for operation in &self.model.analyzed.ir.operations {
            for parameter in &operation.parameters {
                self.validate_schema(&parameter.schema, &mut diagnostics);
            }
            if let Some(body) = &operation.request_body {
                for media_type in &body.media_types {
                    self.validate_schema(&media_type.schema, &mut diagnostics);
                    for (_, encoding) in &media_type.encodings {
                        for (_, header) in &encoding.headers {
                            self.validate_schema(&header.schema, &mut diagnostics);
                        }
                    }
                }
            }
            for response in &operation.responses {
                for media_type in &response.media_types {
                    self.validate_schema(&media_type.schema, &mut diagnostics);
                }
                for (_, header) in &response.headers {
                    self.validate_schema(&header.schema, &mut diagnostics);
                }
            }
        }
        self.model.sink.extend(diagnostics);
    }

    fn validate_schema(&self, schema: &SchemaNode, diagnostics: &mut Vec<Diagnostic>) {
        match schema {
            SchemaNode::Ref { target, meta } => {
                if self
                    .model
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
            }
            | SchemaNode::AnyOf {
                branches,
                discriminator: Some(discriminator),
                ..
            } => {
                self.validate_discriminated(branches, discriminator, diagnostics);
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
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<&'a SchemaNode> {
        let SchemaNode::Ref { target, .. } = schema else {
            return Some(schema);
        };
        let key = (target.source_id.as_str(), target.json_pointer.as_str());
        if visited.contains(&key) {
            return None;
        }
        visited.insert(key);
        let target = self
            .model
            .schema_target(&target.source_id, &target.json_pointer)?;
        let resolved = &self.model.analyzed.ir.schemas.get(target.index)?.schema;
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

    /// Diagnoses a discriminated `oneOf`/`anyOf` (one shared path for both, since the discriminator
    /// contract is identical). Each branch must contribute a distinct tag value for the discriminator
    /// property; the tag is drawn — first non-empty wins — from the explicit `mapping`, the branch's
    /// own fixed `const`/`enum` seen through the `$ref`+allOf idiom, or the referenced component name.
    /// The render is always a plain structural union — proof drives diagnostics only, never the type
    /// shape — so an unprovable union degrades to that same union plus one warning saying why.
    fn validate_discriminated(
        &self,
        branches: &[SchemaNode],
        discriminator: &Discriminator,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        let prop = discriminator.property_name.as_str();

        // Resolve every mapping value once. An unresolvable value is a hard error and contributes no
        // tag; a resolvable one records (tag -> target component index) for branch matching below.
        let mut mapping_targets: Vec<(&str, usize)> = Vec::new();
        for (tag, target) in &discriminator.mapping {
            match self.resolve_mapping_target(discriminator, target) {
                Some(index) => mapping_targets.push((tag.as_str(), index)),
                None => diagnostics.push(source_diagnostic(
                    CODE_MAPPING_TARGET,
                    format!(
                        "discriminator mapping value '{target}' resolves to no component schema"
                    ),
                    &discriminator.source,
                )),
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut fallback: Option<(&'static str, String)> = None;
        'proof: for branch in branches {
            let branch_index = self.branch_target_index(branch);
            let mapping_tags: Vec<&str> = mapping_targets
                .iter()
                .filter(|(_, index)| branch_index == Some(*index))
                .map(|(tag, _)| *tag)
                .collect();
            let const_proof = self.merged_object_property_finite(branch, prop, &mut HashSet::new());

            // An allOf idiom that fixes the tag property to disjoint values proves an uninhabitable
            // branch: no wire value selects it, so the union cannot dispatch. Warn and fall back.
            if const_proof.as_deref().is_some_and(<[Value]>::is_empty) {
                fallback = Some((
                    CODE_DISCRIMINATOR_PROOF,
                    format!(
                        "discriminator branch fixes '{prop}' to no inhabitable value; emitting a structural union"
                    ),
                ));
                break 'proof;
            }

            let effective: Vec<String> = if !mapping_tags.is_empty() {
                // A mapping tag that disagrees with the branch's own single fixed value is
                // incoherent: the wire value the mapping routes here would fail the branch's const.
                if let Some([value]) = const_proof.as_deref()
                    && let Some(conflict) = mapping_tags.iter().find(|tag| **tag != tag_key(value))
                {
                    fallback = Some((
                        CODE_DISCRIMINATOR_PROOF,
                        format!(
                            "discriminator maps '{conflict}' to a branch whose '{prop}' is fixed to {}; emitting a structural union",
                            render_json_compact(value, ObjectKeyMode::Plain)
                        ),
                    ));
                    break 'proof;
                }
                mapping_tags.iter().map(|tag| (*tag).to_owned()).collect()
            } else if let Some(values) = const_proof.as_deref().filter(|values| !values.is_empty())
            {
                values.iter().map(tag_key).collect()
            } else {
                self.implicit_tag(branch).into_iter().collect()
            };

            if effective.is_empty() {
                fallback = Some((
                    CODE_DISCRIMINATOR,
                    format!(
                        "emitting a structural union because a branch does not prove one literal for discriminator property '{prop}'"
                    ),
                ));
                break 'proof;
            }
            for tag in effective {
                if !seen.insert(tag.clone()) {
                    fallback = Some((
                        CODE_DISCRIMINATOR,
                        format!(
                            "emitting a structural union because discriminator property '{prop}' repeats literal {tag}"
                        ),
                    ));
                    break 'proof;
                }
            }
        }

        if let Some((code, message)) = fallback {
            diagnostics.push(warning_diagnostic(code, message, &discriminator.source));
        }
    }

    /// The allocated component index a branch's `$ref` resolves to, or `None` for a non-`$ref`
    /// branch (inline objects carry no reference identity to match a mapping target against).
    fn branch_target_index(&self, branch: &SchemaNode) -> Option<usize> {
        let SchemaNode::Ref { target, .. } = branch else {
            return None;
        };
        self.model
            .schema_target(&target.source_id, &target.json_pointer)
            .map(|target| target.index)
    }

    /// Resolves a discriminator `mapping` value to an allocated component index. A bare name is a
    /// component in the discriminator's own document; a `#/...` fragment is a local pointer there;
    /// a `file#/...` value resolves the file relative to that document. `None` means the value
    /// designates no allocated schema (a dangling mapping target).
    fn resolve_mapping_target(&self, discriminator: &Discriminator, target: &str) -> Option<usize> {
        let base = discriminator.source.source_id.as_str();
        let (source_id, pointer) = match target.split_once('#') {
            None => (base.to_owned(), format!("/components/schemas/{target}")),
            Some(("", fragment)) => (base.to_owned(), fragment.to_owned()),
            Some((file, fragment)) => (join_relative_source(base, file), fragment.to_owned()),
        };
        self.model
            .schema_target(&source_id, &pointer)
            .map(|target| target.index)
    }

    /// The implicit discriminator tag for a `$ref` branch: the referenced component's name, taken as
    /// the reference's last path segment. `None` for a non-`$ref` branch.
    fn implicit_tag(&self, branch: &SchemaNode) -> Option<String> {
        let SchemaNode::Ref { target, .. } = branch else {
            return None;
        };
        target.json_pointer.rsplit('/').next().map(str::to_owned)
    }

    /// The finite value set a branch fixes its tag property to, seen through the `$ref`+allOf idiom:
    /// a `$ref` resolves and recurses; an object reads the property's own `const`/`enum`; an allOf
    /// intersects the finite sets its sub-branches prove (the merge that lets the common
    /// parent+allOf discriminated-union spelling prove). `None` means no finite proof; `Some(empty)`
    /// means the sub-branches fix the property to disjoint values — an uninhabitable branch. Cycles
    /// are guarded by a visited set keyed on the resolved `(source_id, json_pointer)`.
    fn merged_object_property_finite<'a>(
        &'a self,
        branch: &'a SchemaNode,
        prop: &str,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<Vec<Value>> {
        match branch {
            SchemaNode::Ref { target, .. } => {
                if !visited.insert((target.source_id.as_str(), target.json_pointer.as_str())) {
                    return None;
                }
                let index = self
                    .model
                    .schema_target(&target.source_id, &target.json_pointer)?
                    .index;
                let resolved = &self.model.analyzed.ir.schemas.get(index)?.schema;
                self.merged_object_property_finite(resolved, prop, visited)
            }
            SchemaNode::Object { properties, .. } => {
                let (_, schema, _) = properties.iter().find(|(name, _, _)| name == prop)?;
                // A primitive tag property fixes its value in `const`/`enum` (resolved through a
                // `$ref`); an object/array/tuple-typed one carries it in the `finite` box b9e3b24
                // added. Consult both so either spelling proves.
                self.finite_constraint(schema, &mut visited.clone())
                    .or_else(|| container_finite_values(schema))
            }
            SchemaNode::AllOf { branches, .. } => {
                let mut sets = branches.iter().filter_map(|branch| {
                    self.merged_object_property_finite(branch, prop, &mut visited.clone())
                });
                let mut intersection = sets.next()?;
                for set in sets {
                    intersection.retain(|value| set.iter().any(|other| json_equal(value, other)));
                }
                Some(intersection)
            }
            _ => None,
        }
    }

    fn emit_component(&self, allocated: &AllocatedSchemaName) -> GeneratedFile {
        let schema = &self.model.analyzed.ir.schemas[allocated.schema_index];
        let file_base = self.model.component_files[allocated.schema_index]
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
            .model
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

    pub(super) fn write_schema_declaration(
        &self,
        output: &mut String,
        name: &str,
        schema: &SchemaNode,
        position: TypePosition,
        source: &SourceRef,
    ) {
        if let Some(values) = schema_finite_values(schema)
            && self.model.config.types.enum_representation == EnumRepresentation::Const
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
                &self.model.config.documentation,
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
                        &self.model.config.documentation,
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
                &self.model.config.documentation,
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
            &self.model.config.documentation,
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
        self.model
            .analyzed
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
        let borrowed = borrow_properties(properties);
        self.render_object_parts(
            &borrowed,
            &AdditionalProperties::Forbidden,
            position,
            indent,
            true,
        )
    }

    pub(super) fn render_type(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        indent: usize,
    ) -> String {
        let rendered = match schema {
            SchemaNode::Ref { target, .. } => self
                .model
                .schema_target(&target.source_id, &target.json_pointer)
                .map_or_else(
                    || "unknown".to_owned(),
                    |target| self.local_import_name(target.variant_name(position)),
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
                let borrowed = borrow_properties(properties);
                self.render_object_parts(&borrowed, additional_properties, position, indent, false)
            }
            SchemaNode::Array { items, .. } => {
                let item = self.render_type(items, position, indent);
                let mut item = parenthesize_array_item(item, items);
                item.reserve(2);
                item.push_str("[]");
                item
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
                        let mut rest = parenthesize_array_item(rest, schema);
                        rest.reserve(5);
                        rest.insert_str(0, "...");
                        rest.push_str("[]");
                        items.push(rest);
                    }
                }
                format!("[{}]", items.join(", "))
            }
            SchemaNode::AllOf { branches, .. } => {
                // Inlining a branch that resolves back to an ancestor being inlined
                // would recurse forever on a recursive schema. The guard falls through
                // to intersection rendering, where the ref becomes a bare named
                // reference that terminates the cycle.
                if let Some(rendered) =
                    self.merge_all_of_guarded(branches, |properties, additional_properties| {
                        self.render_object_parts(
                            properties,
                            additional_properties,
                            position,
                            indent,
                            false,
                        )
                    })
                {
                    rendered
                } else if branches.is_empty() {
                    "unknown".to_owned()
                } else {
                    let rendered = branches
                        .iter()
                        .filter_map(|branch| {
                            let rendered = self.render_type(branch, position, indent);
                            if rendered == "unknown" {
                                None
                            } else {
                                Some(parenthesize_intersection_member(rendered, branch))
                            }
                        })
                        .collect::<Vec<_>>();
                    if rendered.is_empty() {
                        "unknown".to_owned()
                    } else {
                        rendered.join(" & ")
                    }
                }
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                if branches.is_empty() {
                    "never".to_owned()
                } else {
                    // Linear membership rather than a hash set: a union carries a handful of
                    // branches, and a set would clone every rendered branch to own its key.
                    let mut rendered_branches = Vec::with_capacity(branches.len());
                    for branch in branches {
                        let rendered = self.render_type(branch, position, indent);
                        if !rendered_branches.contains(&rendered) {
                            rendered_branches.push(rendered);
                        }
                    }
                    rendered_branches.join(" | ")
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

    // Concrete slice (not `impl Iterator`) on purpose: a generic property source
    // monomorphizes this per caller, and the 100%-line gate then measures each
    // rarely-exercised instantiation separately. One concrete instantiation stays
    // fully covered by the callers as a group, exactly as it was before borrowing.
    // Two passes (`any` then `filter`) instead of collecting an `included` Vec so
    // the borrowed callers add no allocation the owned form did not already pay.
    fn render_object_parts(
        &self,
        properties: &[BorrowedProperty<'_>],
        additional_properties: &AdditionalProperties,
        position: TypePosition,
        indent: usize,
        interface_members: bool,
    ) -> String {
        let has_included_properties = properties
            .iter()
            .any(|&(_, _, meta)| property_in_position(meta, position));
        let literal = if !has_included_properties {
            "{}".to_owned()
        } else {
            let mut output = String::from("{\n");
            for &(name, schema, meta) in properties
                .iter()
                .filter(|&&(_, _, meta)| property_in_position(meta, position))
            {
                let member_indent = indent + 2;
                let docs = property_docs(schema, meta);
                write_schema_tsdoc(
                    &mut output,
                    &docs,
                    DocKind::Property,
                    &self.model.config.documentation,
                    member_indent,
                    interface_members,
                );
                push_indent(&mut output, member_indent);
                if self.model.config.types.readonly {
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
            push_indent(&mut output, indent);
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

    /// Target keys of the `allOf` branches that are direct `$ref`s — the branches
    /// `merge_all_of` would inline by resolving. Used to detect a ref that points
    /// back to an ancestor already being inlined (the recursive-schema cycle).
    fn inlineable_ref_keys(&self, branches: &[SchemaNode]) -> Vec<SchemaRef> {
        branches
            .iter()
            .filter_map(|branch| match branch {
                SchemaNode::Ref { target, .. } => Some(target.clone()),
                _ => None,
            })
            .collect()
    }

    /// Runs `body` over the merged `allOf` shape while the branches' inlineable ref
    /// targets sit on the cycle-guard stack, then restores the stack. Returns `None`
    /// without running `body` when a branch resolves back to an ancestor already being
    /// inlined (the recursive-schema cycle) or when the branches do not merge into a
    /// single object shape. The stack borrow is released before `body` runs so the body
    /// can recurse and push its own guards.
    fn merge_all_of_guarded<'a, R>(
        &'a self,
        branches: &'a [SchemaNode],
        body: impl FnOnce(&[BorrowedProperty<'a>], &AdditionalProperties) -> R,
    ) -> Option<R> {
        let inline_keys = self.inlineable_ref_keys(branches);
        let would_cycle = {
            let stack = self.inlining_refs.borrow();
            inline_keys.iter().any(|key| stack.contains(key))
        };
        if would_cycle {
            return None;
        }
        // The merge is position-independent and depends only on the branch slice, so a
        // prewarmed entry (keyed by the slice's stable IR address) answers every render
        // and import pass for this node. `None` here means the slice was not prewarmed —
        // it is not IR-resident (a client plan or a test builds it), and its address is
        // not stable to key on, so recompute it uncached. `Some(None)` is a prewarmed
        // does-not-merge answer. Clone out of the cache in a tight scope: `body` re-enters
        // this method, so the cache borrow must be released before it runs.
        let key = (branches.as_ptr() as usize, branches.len());
        let cached = self.merge_cache.borrow().get(&key).cloned();
        let fresh;
        let (properties, additional_properties): (&[BorrowedProperty<'a>], &AdditionalProperties) =
            match &cached {
                Some(Some((properties, additional_properties))) => {
                    (&properties[..], *additional_properties)
                }
                Some(None) => return None,
                None => {
                    fresh = self.merge_all_of(branches)?;
                    (&fresh.0, fresh.1)
                }
            };
        let pushed = inline_keys.len();
        self.inlining_refs.borrow_mut().extend(inline_keys);
        let result = body(properties, additional_properties);
        let mut stack = self.inlining_refs.borrow_mut();
        let kept = stack.len() - pushed;
        stack.truncate(kept);
        Some(result)
    }

    fn merge_all_of<'a>(
        &'a self,
        branches: &'a [SchemaNode],
    ) -> Option<(Vec<BorrowedProperty<'a>>, &'a AdditionalProperties)> {
        // One scratch set reused across branches; clearing before each call keeps
        // today's per-call-fresh cycle-visited semantics without a fresh allocation
        // per branch.
        let mut visited = HashSet::new();
        let shapes = branches
            .iter()
            .map(|branch| {
                visited.clear();
                self.object_shape(branch, &mut visited)
            })
            .collect::<Option<Vec<_>>>()?;
        Self::merge_shapes(&shapes)
    }

    /// Model-lifetime `allOf` merge, used only to prewarm the cache. Identical result to
    /// `merge_all_of` for the same branches, but the borrows are tied to the immutable IR
    /// (`&'input`) rather than the `&self` borrow, so the properties outlive the emitter
    /// and can be stored. Branches must be IR-resident; `merge_all_of` stays the fallback
    /// for locally built schemas whose branch slices have no stable address to key on.
    fn merge_all_of_ir(
        &self,
        branches: &'input [SchemaNode],
    ) -> Option<(Vec<BorrowedProperty<'input>>, &'input AdditionalProperties)> {
        let mut visited = HashSet::new();
        let shapes = branches
            .iter()
            .map(|branch| {
                visited.clear();
                let resolved = self.resolve_ref_ir(branch, &mut visited)?;
                let SchemaNode::Object {
                    properties,
                    additional_properties,
                    ..
                } = resolved
                else {
                    return None;
                };
                Some(ObjectShape {
                    properties,
                    additional_properties,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Self::merge_shapes(&shapes)
    }

    /// The `allOf` object merge over already-resolved branch shapes. Shared by the
    /// `&'a self` fallback (`merge_all_of`) and the model-lifetime prewarm
    /// (`merge_all_of_ir`) so both emit a byte-identical merged property list.
    fn merge_shapes<'a>(
        shapes: &[ObjectShape<'a>],
    ) -> Option<(Vec<BorrowedProperty<'a>>, &'a AdditionalProperties)> {
        let first = shapes.first()?;
        let merged_additional_properties = first.additional_properties;
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
        // `slot_of` gives O(1) duplicate-name lookup so the merge stays O(branches ×
        // props) instead of O(branches × props²); `merged` still holds first-occurrence
        // order because a name is only ever pushed on its first sighting.
        let mut merged = Vec::<BorrowedProperty<'a>>::new();
        let mut slot_of = HashMap::<&str, usize>::new();
        for shape in shapes {
            for (name, schema, meta) in shape.properties {
                if let Some(&slot) = slot_of.get(name.as_str()) {
                    let (_, previous_schema, previous_meta) = merged[slot];
                    if previous_meta.required != meta.required || previous_schema != schema {
                        return None;
                    }
                } else {
                    slot_of.insert(name.as_str(), merged.len());
                    merged.push((name.as_str(), schema, meta));
                }
            }
        }
        Some((merged, merged_additional_properties))
    }

    /// Resolves a `$ref` chain to its target node at the model lifetime. Mirrors
    /// `resolve_ref`, but re-reads through `self.model.analyzed` (a `&'input` copy) so the
    /// result is tied to the IR, not the `&self` borrow — required to cache a merge that
    /// outlives the current call. Returns `None` on a ref cycle or unresolvable target,
    /// exactly as `resolve_ref`, so a prewarmed merge equals the fallback merge.
    fn resolve_ref_ir(
        &self,
        schema: &'input SchemaNode,
        visited: &mut HashSet<(&'input str, &'input str)>,
    ) -> Option<&'input SchemaNode> {
        let SchemaNode::Ref { target, .. } = schema else {
            return Some(schema);
        };
        let key = (target.source_id.as_str(), target.json_pointer.as_str());
        if visited.contains(&key) {
            return None;
        }
        visited.insert(key);
        let index = self
            .model
            .schema_target(&target.source_id, &target.json_pointer)?
            .index;
        let resolved = &self.model.analyzed.ir.schemas.get(index)?.schema;
        self.resolve_ref_ir(resolved, visited)
    }

    /// Populates the merge cache for every `allOf` node in one IR schema tree. Descends the
    /// raw structure — never through a `$ref`, which is a leaf here, so the walk always
    /// terminates — and computes each node's merge once, before the node is rendered and
    /// walked for imports up to six times.
    fn prewarm_all_of(&self, schema: &'input SchemaNode) {
        match schema {
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                for (_, property, _) in properties {
                    self.prewarm_all_of(property);
                }
                if let AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) = additional_properties
                {
                    self.prewarm_all_of(schema);
                }
            }
            SchemaNode::Array { items, .. } => self.prewarm_all_of(items),
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for item in prefix_items {
                    self.prewarm_all_of(item);
                }
                if let TupleRest::Schema(schema) = rest {
                    self.prewarm_all_of(schema);
                }
            }
            SchemaNode::AllOf { branches, .. } => {
                self.cache_merge_all_of(branches);
                for branch in branches {
                    self.prewarm_all_of(branch);
                }
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                for branch in branches {
                    self.prewarm_all_of(branch);
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

    /// Computes and stores one IR branch slice's merge, keyed by the slice's stable
    /// address and length. Caches the `None` (does-not-merge) answer too, since the
    /// fallback would otherwise recompute it once per position per pass just the same.
    /// The prewarm walk visits each distinct slice once, so this never overwrites.
    ///
    /// Empty slices are never inserted: every empty `Vec` shares Rust's dangling-pointer
    /// sentinel, so an empty IR slice's key would also match every other empty slice,
    /// IR-resident or not. Skipping them keeps the pointer key collision-free; the
    /// fallback recomputes an empty merge to the same `None` answer either way.
    fn cache_merge_all_of(&self, branches: &'input [SchemaNode]) {
        if branches.is_empty() {
            return;
        }
        let key = (branches.as_ptr() as usize, branches.len());
        // Compute the entry before touching the cache — `merge_all_of_ir` never reads it,
        // and this keeps the mutable borrow to the single `insert`.
        let entry = self
            .merge_all_of_ir(branches)
            .map(|(properties, additional_properties)| {
                (Rc::from(properties), additional_properties)
            });
        self.merge_cache.borrow_mut().insert(key, entry);
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

    pub(super) fn walk_refs(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        visit: &mut dyn FnMut(&SchemaTarget),
    ) {
        if let SchemaNode::Ref { target, .. } = schema
            && let Some(target) = self
                .model
                .schema_target(&target.source_id, &target.json_pointer)
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
                // Mirror render_type's cycle guard: a branch resolving back to an
                // ancestor being inlined must not inline again, or this walk recurses
                // forever on a recursive schema. Fall through to visiting the raw
                // branches, where a `$ref` branch records its import and terminates.
                let handled = if let SchemaChildMode::References(position) = mode {
                    self.merge_all_of_guarded(branches, |properties, additional_properties| {
                        for &(_, property, meta) in properties {
                            if property_in_position(meta, position) {
                                visit(property);
                            }
                        }
                        if let AdditionalProperties::Allowed(Some(schema))
                        | AdditionalProperties::Schema(schema) = additional_properties
                        {
                            visit(schema);
                        }
                    })
                } else {
                    None
                };
                if handled.is_none() {
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
        let aliases = self.import_aliases.borrow();
        let extension = import_extension(self.model);
        for (file, names) in imports {
            output.push_str("import type { ");
            output.push_str(
                &names
                    .into_iter()
                    .map(|name| import_clause(name, &aliases))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            output.push_str(" } from ");
            output.push_str(&render_ts_string(&format!("{prefix}{file}{extension}")));
            output.push_str(";\n");
        }
        output.push('\n');
    }
}

/// Picks the local binding for every component import a module would otherwise let its own
/// declarations shadow. A shadowed import is silently retyped to the local declaration, so the
/// emitted module is not merely uncompilable — where it does compile, it is wrong.
///
/// The colliding name is by construction one of the module's own declarations, so appending `Body`
/// names the reference site's role exactly (`<Stem>RequestBody`, `<Stem>Response200Body`,
/// `<Stem>InputBody`). The component and the declaration are two legitimate public types in two
/// different modules and the rename is file-local, so no exported name changes; refusing the
/// document instead would reject input that generates perfectly valid TypeScript.
///
/// The residual case — the role name is itself taken by another import or declaration here — is a
/// genuine two-way collision with no local remedy, so it is fatal and points at `naming.overrides`.
/// Returns the diagnostics rather than pushing them: the types emitter renders behind `&self` and
/// defers them, while the client emitter owns a sink at that point.
pub(super) fn assign_import_aliases(
    declared: &BTreeSet<String>,
    imports: &BTreeMap<String, BTreeSet<String>>,
    source: &SourceRef,
) -> (HashMap<String, String>, Vec<Diagnostic>) {
    let mut aliases = HashMap::new();
    let mut diagnostics = Vec::new();
    // Fast-reject: the overwhelming majority of modules import nothing carrying a declaration's
    // name, and this runs once per emitted module.
    let shadowed = imports
        .values()
        .flatten()
        .filter(|name| declared.contains(name.as_str()))
        .collect::<Vec<_>>();
    if shadowed.is_empty() {
        return (aliases, diagnostics);
    }
    let imported = imports.values().flatten().collect::<BTreeSet<_>>();
    for name in shadowed {
        let alias = format!("{name}Body");
        if declared.contains(&alias) || imported.contains(&alias) {
            diagnostics.push(source_diagnostic(
                CODE_IMPORT_ALIAS,
                format!(
                    "component '{name}' is shadowed by this operation module's own '{name}' declaration, and the replacement name '{alias}' is already taken here; rename one with naming.overrides"
                ),
                source,
            ));
            continue;
        }
        aliases.insert(name.clone(), alias);
    }
    (aliases, diagnostics)
}

/// Renders one import's clause, naming the alias when the module binds the component locally.
pub(super) fn import_clause(name: String, aliases: &HashMap<String, String>) -> String {
    match aliases.get(&name) {
        Some(alias) => format!("{name} as {alias}"),
        None => name,
    }
}

impl SchemaTarget {
    pub(super) fn variant_name(&self, position: TypePosition) -> String {
        match position {
            TypePosition::Request if self.request_differs => format!("{}Request", self.name),
            TypePosition::Response if self.response_differs => format!("{}Response", self.name),
            TypePosition::Neutral | TypePosition::Request | TypePosition::Response => {
                self.name.clone()
            }
        }
    }
}

impl Emitter<'_, '_, '_> {
    /// Renders one operation-shaped file and appends it, folding its response headers into the
    /// running `any_response_headers` flag first. Shared by the path-operation, webhook, and
    /// callback emission loops, which differ only in how they resolve `(operation, name, file_base)`
    /// and the `subdir` they target.
    fn push_operation_file(
        &self,
        files: &mut Vec<GeneratedFile>,
        any_response_headers: &mut bool,
        operation: &Operation,
        allocated_name: &str,
        subdir: &str,
        file_base: &str,
    ) {
        if !*any_response_headers {
            *any_response_headers = operation
                .responses
                .iter()
                .any(|response| !response.headers.is_empty());
        }
        files.push(self.emit_operation_file(operation, allocated_name, subdir, file_base));
    }

    /// Renders one operation-shaped type file — the `<Stem>Request`, per-status `<Stem>Response*`,
    /// their header interfaces, and the `<Stem>Response` union — to `types/<subdir>/<file_base>.ts`.
    /// Webhook and callback operations reuse this unchanged: they carry the same
    /// parameter/body/response/header/link surface as a path operation, and all three subdirectories
    /// sit at the same depth, so the `../components/` import prefix is shared.
    fn emit_operation_file(
        &self,
        operation: &Operation,
        allocated_name: &str,
        subdir: &str,
        file_base: &str,
    ) -> GeneratedFile {
        let stem = uppercase_first(allocated_name);
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

        let mut content = self.header();
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        for parameter in &operation.parameters {
            self.collect_operation_imports(&parameter.schema, TypePosition::Request, &mut imports);
        }
        if let Some(body) = &operation.request_body
            && let Some(media_type) = select_request_media(&body.media_types)
            && is_json(&media_type.essence)
        {
            self.collect_operation_imports(&media_type.schema, TypePosition::Request, &mut imports);
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                if is_json(&media_type.essence) {
                    self.collect_operation_imports(
                        &media_type.schema,
                        TypePosition::Response,
                        &mut imports,
                    );
                }
            }
            for (_, header) in &response.headers {
                self.collect_operation_imports(
                    &header.schema,
                    TypePosition::Response,
                    &mut imports,
                );
            }
        }
        // The declaration set exists only to be tested against imports, so an import-free module
        // never builds it. Most operation modules do import something, but the ones that do not
        // stay allocation-identical to before aliasing existed.
        let (aliases, alias_diagnostics) = if imports.is_empty() {
            (HashMap::new(), Vec::new())
        } else {
            let mut declared =
                BTreeSet::from([format!("{stem}Request"), format!("{stem}Response")]);
            for (response_name, response) in &response_declarations {
                declared.insert(response_name.clone());
                if !response.headers.is_empty() {
                    declared.insert(format!("{response_name}Headers"));
                }
            }
            assign_import_aliases(&declared, &imports, &operation.source)
        };
        self.set_import_aliases(aliases);
        self.deferred_diagnostics
            .borrow_mut()
            .extend(alias_diagnostics);
        self.write_imports(&mut content, imports, "../components/");

        write_source_metadata(&mut content, &operation.source, 0);
        write_operation_tsdoc(&mut content, operation, &self.model.config.documentation, 0);
        content.push_str("export type ");
        content.push_str(&stem);
        content.push_str("Request = ");
        content.push_str(&self.render_request(operation, 0));
        content.push_str(";\n\n");

        let mut response_names = Vec::new();
        for (response_name, response) in response_declarations {
            response_names.push(response_name.clone());
            write_source_metadata(&mut content, &response.source, 0);
            self.write_response_tsdoc(&mut content, response);
            content.push_str("export type ");
            content.push_str(&response_name);
            content.push_str(" = ");
            content.push_str(&self.render_response_entry(response));
            content.push_str(";\n\n");
            if !response.headers.is_empty() {
                self.write_response_headers_interface(
                    &mut content,
                    &format!("{response_name}Headers"),
                    response,
                );
            }
        }
        write_source_metadata(&mut content, &operation.source, 0);
        write_operation_tsdoc(&mut content, operation, &self.model.config.documentation, 0);
        content.push_str("export type ");
        content.push_str(&stem);
        content.push_str("Response = ");
        if response_names.is_empty() {
            content.push_str("never");
        } else {
            content.push_str(&response_names.join(" | "));
        }
        content.push_str(";\n");

        self.import_aliases.borrow_mut().clear();
        GeneratedFile {
            relative_path: format!("types/{subdir}/{file_base}.ts"),
            content,
        }
    }

    /// Binds the module being rendered to `aliases`, so every reference site resolves a component
    /// through `local_import_name`. Set for the duration of one file and cleared after it.
    pub(super) fn set_import_aliases(&self, aliases: HashMap<String, String>) {
        self.import_aliases.replace(aliases);
    }

    /// The name a component's exported identifier is bound to inside the module being rendered.
    /// Differs from the exported name only where `assign_import_aliases` had to rename it.
    fn local_import_name(&self, name: String) -> String {
        let aliases = self.import_aliases.borrow();
        if aliases.is_empty() {
            return name;
        }
        aliases.get(&name).cloned().unwrap_or(name)
    }

    /// Writes the response type's own TSDoc block: currently just `@see` entries, one per
    /// resolved link declared on this response, in `link_targets` order. A response with no
    /// resolved link produces an empty `TsDoc` that `write_tsdoc` turns into zero bytes, so a
    /// link-free document's response types stay byte-identical to before links were emitted.
    /// An unresolved link (`target_operation_index: None`) already fired its diagnostic in
    /// `semantic::resolve_links` and contributes nothing here; the same applies to a resolved
    /// target whose own name allocation failed (no entry in `operation_stems`) — there is no
    /// name left to link to.
    fn write_response_tsdoc(&self, output: &mut String, response: &ResponseEntry) {
        if !self.model.config.documentation.enabled {
            return;
        }
        let mut tsdoc = TsDoc::default();
        // Fast-reject: a link-free document (the common case) keeps `link_targets_by_response`
        // empty, so every response skips straight past the lookup instead of paying for two
        // `String` clones to build a key that could only ever miss.
        if !self.link_targets_by_response.is_empty()
            && let Some(indices) = self.link_targets_by_response.get(&(
                response.source.source_id.clone(),
                response.source.json_pointer.clone(),
            ))
        {
            for &index in indices {
                let resolved: &ResolvedLink = &self.model.analyzed.link_targets[index];
                let Some(target_index) = resolved.target_operation_index else {
                    continue;
                };
                let Some(target_stem) = self.operation_stems.get(&target_index) else {
                    continue;
                };
                tsdoc.see.push((
                    format!("{target_stem}Response"),
                    Some(resolved.link_name.clone()),
                ));
            }
        }
        write_tsdoc(output, &tsdoc, 0);
    }

    /// Emits the `{ResponseName}Headers` interface next to the response payload type it
    /// describes, one property per declared header keyed exactly as written (quoted through
    /// `render_property_key` when it is not a bare identifier). Only called when
    /// `response.headers` is non-empty, so a header-less response never reaches this and stays
    /// byte-identical to before headers were emitted.
    fn write_response_headers_interface(
        &self,
        output: &mut String,
        interface_name: &str,
        response: &ResponseEntry,
    ) {
        write_source_metadata(output, &response.source, 0);
        output.push_str("export interface ");
        output.push_str(interface_name);
        output.push_str(" {\n");
        for (name, header) in &response.headers {
            write_schema_tsdoc(
                output,
                &response_header_docs(header),
                DocKind::Header,
                &self.model.config.documentation,
                2,
                false,
            );
            output.push_str("  ");
            if self.model.config.types.readonly {
                output.push_str("readonly ");
            }
            output.push_str(&render_property_key(name));
            if !header.required {
                output.push('?');
            }
            output.push_str(": ");
            if crate::client_model::response_header_is_opaque_string(header) {
                // A content-sourced non-JSON header carries an opaque wire string; only JSON-family
                // and schema+style headers render their typed schema.
                output.push_str("string");
            } else {
                output.push_str(&self.render_type(&header.schema, TypePosition::Response, 2));
            }
            output.push_str(";\n");
        }
        output.push_str("}\n\n");
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
            push_indent(&mut output, indent + 2);
            if self.model.config.types.readonly {
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
            let body_type = self.media_payload_type(
                &media_type.essence,
                &media_type.schema,
                TypePosition::Request,
            );
            if let Some(description) = &body.description {
                let docs = SchemaDocs {
                    description: Some(description.clone()),
                    ..SchemaDocs::default()
                };
                write_schema_tsdoc(
                    &mut output,
                    &docs,
                    DocKind::Property,
                    &self.model.config.documentation,
                    indent + 2,
                    false,
                );
            }
            push_indent(&mut output, indent + 2);
            if self.model.config.types.readonly {
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
        push_indent(&mut output, indent);
        output.push('}');
        output
    }

    fn render_parameter_group(&self, parameters: &[&Param], indent: usize) -> String {
        let mut output = String::from("{\n");
        for parameter in parameters {
            let docs = schema_field_docs(
                parameter.description.as_deref(),
                parameter.deprecated,
                &parameter.schema,
            );
            write_schema_tsdoc(
                &mut output,
                &docs,
                DocKind::Parameter,
                &self.model.config.documentation,
                indent + 2,
                false,
            );
            push_indent(&mut output, indent + 2);
            if self.model.config.types.readonly {
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
        push_indent(&mut output, indent);
        output.push('}');
        output
    }

    fn render_response_entry(&self, response: &ResponseEntry) -> String {
        if response.media_types.is_empty() {
            return "null".to_owned();
        }
        let mut types = Vec::new();
        for media_type in &response.media_types {
            let rendered = self.media_payload_type(
                &media_type.essence,
                &media_type.schema,
                TypePosition::Response,
            );
            if !types.contains(&rendered) {
                types.push(rendered);
            }
        }
        types.join(" | ")
    }

    /// The TypeScript type one declared media entry's payload renders to. Keyed on the entry's
    /// essence and schema rather than on an `ir::MediaType`, so the client emitter — which holds a
    /// `ResponseMediaPlan`, not an IR node — renders each arm through this same rule instead of
    /// duplicating it and silently diverging from the types artifact.
    pub(super) fn media_payload_type(
        &self,
        essence: &str,
        schema: &SchemaNode,
        position: TypePosition,
    ) -> String {
        if is_json(essence) {
            self.render_type(schema, position, 0)
        } else if essence.starts_with("text/") {
            "string".to_owned()
        } else {
            // Binary and custom media stay unknown in the types-only artifact;
            // the client runtime owns byte-container choices.
            "unknown".to_owned()
        }
    }

    pub(super) fn collect_operation_imports(
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

/// Resolves the `&Operation` a callback allocation addresses. Walks from the declaring operation
/// — a path operation, a webhook operation, or (recursively) the enclosing callback operation —
/// then descends the callback/expression/operation indices to the leaf operation node.
pub(super) fn callback_operation<'ir>(
    ir: &'ir Ir,
    callback_names: &[AllocatedCallbackName],
    entry: &AllocatedCallbackName,
) -> &'ir Operation {
    let parent = match &entry.parent {
        CallbackParent::Operation { operation_index } => &ir.operations[*operation_index],
        CallbackParent::WebhookOperation {
            webhook_index,
            operation_index,
        } => &ir.webhooks[*webhook_index].operations[*operation_index],
        CallbackParent::Callback { index } => {
            callback_operation(ir, callback_names, &callback_names[*index])
        }
    };
    &parent.callbacks[entry.callback_index].expressions[entry.expression_index].operations
        [entry.operation_index_within_expression]
}

/// Resolves the operation that *declares* a callback — the one whose `callbacks` array the
/// descriptor reads its callback name and expression text from. For a nested callback this is the
/// enclosing callback operation; otherwise the path or webhook operation named by the parent.
pub(super) fn callback_parent_operation<'ir>(
    ir: &'ir Ir,
    callback_names: &[AllocatedCallbackName],
    parent: &CallbackParent,
) -> &'ir Operation {
    match parent {
        CallbackParent::Operation { operation_index } => &ir.operations[*operation_index],
        CallbackParent::WebhookOperation {
            webhook_index,
            operation_index,
        } => &ir.webhooks[*webhook_index].operations[*operation_index],
        CallbackParent::Callback { index } => {
            callback_operation(ir, callback_names, &callback_names[*index])
        }
    }
}

fn select_request_media(media_types: &[crate::ir::MediaType]) -> Option<&crate::ir::MediaType> {
    media_types
        .iter()
        .find(|media_type| is_json(&media_type.essence))
        .or_else(|| media_types.first())
}

fn media_is_unknown(name: &str) -> bool {
    !is_json(name) && !name.starts_with("text/")
}

pub(super) fn response_status_type_suffix(status: &ResponseStatus) -> String {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value.to_ascii_uppercase(),
        ResponseStatus::Default => "Default".to_owned(),
    }
}

pub(super) fn property_in_position(meta: &PropMeta, position: TypePosition) -> bool {
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

/// `SchemaDocs` for a Parameter or Header Object: its own `description`/`deprecated`, never a
/// `title` or `default` (those live only inside the schema), plus the nested schema's
/// `examples`/`comment`/`constraints`. Both objects carry the same description/deprecated/schema
/// shape, so `render_parameter_group` (Parameter) and `response_header_docs` (Header) share this.
fn schema_field_docs(
    description: Option<&str>,
    deprecated: bool,
    schema: &SchemaNode,
) -> SchemaDocs {
    SchemaDocs {
        title: None,
        description: description.map(str::to_owned),
        deprecated,
        default: None,
        examples: schema.meta().docs.examples.clone(),
        comment: schema.meta().docs.comment.clone(),
        constraints: schema.meta().docs.constraints.clone(),
    }
}

fn response_header_docs(header: &ResponseHeader) -> SchemaDocs {
    schema_field_docs(
        header.description.as_deref(),
        header.deprecated,
        &header.schema,
    )
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

/// The finite value set an object schema fixes itself to via the `finite` box b9e3b24 added (a
/// whole-object `const`/`enum`). Used for a discriminator tag property typed as an object, whose
/// fixed value lives in that box rather than a primitive `const`/`enum`; `None` for any other kind.
fn container_finite_values(schema: &SchemaNode) -> Option<Vec<Value>> {
    let SchemaNode::Object { finite, .. } = schema else {
        return None;
    };
    let (enum_values, const_value) = finite_parts(finite);
    finite_values(enum_values, const_value)
}

/// The canonical string form of a discriminator tag value, shared across the mapping/const/implicit
/// sources so their tags compare equal for collision detection. A JSON string uses its raw content
/// (a mapping key and an implicit component name are already raw strings); any other value renders
/// compactly, matching how it would appear on the wire.
fn tag_key(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => render_json_compact(value, ObjectKeyMode::Plain),
    }
}

/// Resolves a relative file reference against a logical source id (e.g. `workspace/openapi.json`),
/// normalizing `.` and `..` segments, so a `file#/...` discriminator mapping value can be looked up
/// in the schema target index. Returns the resolved logical source id.
fn join_relative_source(base: &str, relative: &str) -> String {
    let mut segments: Vec<&str> = base.split('/').collect();
    segments.pop();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    segments.join("/")
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

pub(super) fn render_ts_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => render_number_value(value),
        Value::String(value) => render_ts_string(value),
        Value::Array(_) | Value::Object(_) => render_json_compact(value, ObjectKeyMode::Plain),
    }
}

/// Encodes an untrusted value for a TypeScript double-quoted string literal.
#[must_use]
pub fn render_ts_string(value: &str) -> String {
    let mut encoded = serde_json::to_string(value).expect("serializing a string cannot fail");
    if encoded.contains('\u{2028}') {
        encoded = encoded.replace('\u{2028}', "\\u2028");
    }
    if encoded.contains('\u{2029}') {
        encoded = encoded.replace('\u{2029}', "\\u2029");
    }
    encoded
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

fn add_nullable(mut rendered: String, schema: &SchemaNode) -> String {
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
        rendered.reserve(7);
        rendered.push_str(" | null");
        rendered
    }
}

fn parenthesize_array_item(mut rendered: String, schema: &SchemaNode) -> String {
    if schema.is_nullable()
        || matches!(
            schema,
            SchemaNode::AllOf { .. } | SchemaNode::OneOf { .. } | SchemaNode::AnyOf { .. }
        )
    {
        rendered.reserve(2);
        rendered.insert(0, '(');
        rendered.push(')');
        rendered
    } else {
        rendered
    }
}

/// Parenthesizes one `allOf` branch's rendered type before the members are joined with ` & `.
/// TypeScript's `&` binds tighter than `|`, so an unparenthesized union member silently changes
/// the type — `A | B & C` parses as `A | (B & C)`. Mirrors [`parenthesize_array_item`], but adds
/// the rendered-text check: an `enum`/`const` primitive and a `Finite` node render a top-level
/// union without being a `OneOf`/`AnyOf` or nullable node, so the node-kind test alone misses them.
fn parenthesize_intersection_member(mut rendered: String, branch: &SchemaNode) -> String {
    if matches!(branch, SchemaNode::OneOf { .. } | SchemaNode::AnyOf { .. })
        || branch.is_nullable()
        || renders_top_level_union(&rendered)
    {
        rendered.reserve(2);
        rendered.insert(0, '(');
        rendered.push(')');
        rendered
    } else {
        rendered
    }
}

/// True when `rendered` is a union at bracket depth zero — a ` | ` outside every `()`/`[]`/`{}`
/// pair. A nested union such as `(string | number)[]` or `{ a: string | number }` binds tighter
/// than `&` and needs no parentheses; only a top-level ` | ` does. The scan anchors on the leading
/// space so a bare `|` inside a string literal (an `enum` value) is never mistaken for a union.
fn renders_top_level_union(rendered: &str) -> bool {
    let bytes = rendered.as_bytes();
    let mut depth = 0usize;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b' ' if depth == 0
                && bytes.get(index + 1) == Some(&b'|')
                && bytes.get(index + 2) == Some(&b' ') =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DocKind {
    Schema,
    Property,
    Parameter,
    Header,
}

#[derive(Default)]
struct TsDoc {
    summary: Option<String>,
    remarks: Vec<String>,
    deprecated: Option<&'static str>,
    params: Vec<(String, String)>,
    returns: Option<&'static str>,
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
        DocKind::Parameter | DocKind::Header => {
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
            DocKind::Header => "This header is deprecated.",
        });
    }
    if let Some(default) = docs.default.as_ref() {
        let mut rendered = render_json_compact(default, ObjectKeyMode::Plain);
        if first_number_outside_binary64(default).is_some() {
            let marker = if default.is_number() {
                "outside the binary64 range"
            } else {
                "contains a value outside the binary64 range"
            };
            rendered.push_str(&format!(" ({marker})"));
        }
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
            .map(|value| {
                let label = first_number_outside_binary64(&value).map(|_| {
                    if value.is_number() {
                        "Outside the binary64 range.".to_owned()
                    } else {
                        "Contains a value outside the binary64 range.".to_owned()
                    }
                });
                DocExample { label, value }
            })
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
            && media_is_unknown(&media_type.essence)
        {
            media_notes.push(format!(
                "- request body {}: represented as unknown in the types artifact.",
                media_type.essence
            ));
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                if media_is_unknown(&media_type.essence) {
                    media_notes.push(format!(
                        "- response {} {}: represented as unknown in the types artifact.",
                        response_status_label(&response.status),
                        media_type.essence
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

#[derive(Clone, Copy)]
pub(super) enum ClientDocKind {
    Declaration,
    ResultFunction,
    ThrowFunction,
}

pub(super) fn write_client_operation_tsdoc(
    output: &mut String,
    operation: &Operation,
    config: &DocumentationConfig,
    kind: ClientDocKind,
    unchecked_response: bool,
) {
    if !config.enabled && matches!(kind, ClientDocKind::Declaration) {
        return;
    }
    let mut tsdoc = TsDoc::default();
    if config.enabled {
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
        if config.deprecated && operation.deprecated {
            tsdoc.deprecated = Some("This operation is deprecated.");
        }
        if let Some((url, description)) = &operation.external_docs {
            tsdoc.see.push((url.clone(), description.clone()));
        }
    }
    match kind {
        ClientDocKind::Declaration => {}
        ClientDocKind::ResultFunction | ClientDocKind::ThrowFunction => {
            if unchecked_response {
                tsdoc.remarks.insert(
                    0,
                    "Successful response data is decoded but unchecked against the OpenAPI schema."
                        .to_owned(),
                );
            }
            if config.enabled && config.description {
                tsdoc.params = operation
                    .parameters
                    .iter()
                    .filter_map(|parameter| {
                        parameter
                            .description
                            .as_ref()
                            .map(|description| (parameter.name.clone(), description.clone()))
                    })
                    .collect();
            }
            tsdoc.returns = Some(if matches!(kind, ClientDocKind::ResultFunction) {
                "A typed result covering every documented response and failure."
            } else {
                "The successful response data and its response metadata."
            });
        }
    }
    write_tsdoc(output, &tsdoc, 0);
}

fn push_media_examples(examples: &mut Vec<DocExample>, media_type: &MediaType, source: &str) {
    for (label, value) in &media_type.examples {
        examples.push(DocExample {
            label: Some(format!("Source: {source} {label} ({})", media_type.essence)),
            value: value.clone(),
        });
    }
    for value in &media_type.schema.meta().docs.examples {
        examples.push(DocExample {
            label: Some(format!("Source: {source} ({})", media_type.essence)),
            value: value.clone(),
        });
    }
}

struct TsDocWriter<'output> {
    output: &'output mut String,
    indent: usize,
    has_section: bool,
}

impl TsDocWriter<'_> {
    fn begin_section(&mut self) {
        if self.has_section {
            push_indent(self.output, self.indent);
            self.output.push_str(" * \n");
        } else {
            self.has_section = true;
        }
    }

    fn start_line(&mut self) {
        push_indent(self.output, self.indent);
        self.output.push_str(" * ");
    }

    fn finish_line(&mut self) {
        self.output.push('\n');
    }

    fn plain_line(&mut self, value: &str) {
        self.start_line();
        self.output.push_str(value);
        self.finish_line();
    }

    fn encoded_lines(&mut self, value: &str) {
        visit_comment_lines(value, |line, literal| {
            self.start_line();
            if literal {
                write_neutralized(self.output, line);
            } else {
                write_comment_line(self.output, line);
            }
            self.finish_line();
        });
    }

    fn neutralized_line(&mut self, value: &str) {
        self.start_line();
        write_neutralized(self.output, value);
        self.finish_line();
    }
}

fn write_tsdoc(output: &mut String, docs: &TsDoc, indent: usize) {
    if docs.summary.is_none()
        && docs.remarks.is_empty()
        && docs.deprecated.is_none()
        && docs.params.is_empty()
        && docs.returns.is_none()
        && docs.default_value.is_none()
        && docs.examples.is_empty()
        && docs.private_remarks.is_none()
        && docs.see.is_empty()
    {
        return;
    }
    push_indent(output, indent);
    output.push_str("/**\n");
    let mut writer = TsDocWriter {
        output,
        indent,
        has_section: false,
    };
    if let Some(summary) = &docs.summary {
        writer.begin_section();
        writer.encoded_lines(summary);
    }
    if !docs.remarks.is_empty() {
        writer.begin_section();
        writer.plain_line("@remarks");
        writer.encoded_lines(&docs.remarks.join("\n\n"));
    }
    if let Some(deprecated) = docs.deprecated {
        writer.begin_section();
        writer.start_line();
        writer.output.push_str("@deprecated ");
        writer.output.push_str(deprecated);
        writer.finish_line();
    }
    if !docs.params.is_empty() {
        writer.begin_section();
        for (name, description) in &docs.params {
            writer.start_line();
            writer.output.push_str("@param ");
            write_comment_fragment(writer.output, name);
            writer.output.push_str(" - ");
            write_comment_fragment(writer.output, description);
            writer.finish_line();
        }
    }
    if let Some(returns) = docs.returns {
        writer.begin_section();
        writer.start_line();
        writer.output.push_str("@returns ");
        writer.output.push_str(returns);
        writer.finish_line();
    }
    if let Some(default) = &docs.default_value {
        writer.begin_section();
        writer.start_line();
        writer.output.push_str("@defaultValue ");
        write_comment_fragment(writer.output, default);
        writer.finish_line();
    }
    for example in &docs.examples {
        writer.begin_section();
        writer.plain_line("@example");
        if let Some(label) = &example.label {
            writer.encoded_lines(label);
            writer.plain_line("");
        }
        writer.plain_line("```json");
        for line in render_json_pretty(&example.value).lines() {
            writer.neutralized_line(line);
        }
        writer.plain_line("```");
    }
    if let Some(private_remarks) = &docs.private_remarks {
        writer.begin_section();
        writer.plain_line("@privateRemarks");
        writer.encoded_lines(private_remarks);
    }
    for (url, label) in &docs.see {
        writer.begin_section();
        writer.start_line();
        writer.output.push_str("@see {@link ");
        write_link_part(writer.output, url);
        if let Some(label) = label {
            writer.output.push_str(" | ");
            write_link_part(writer.output, label);
        }
        writer.output.push('}');
        writer.finish_line();
    }
    push_indent(writer.output, indent);
    writer.output.push_str(" */\n");
}

/// Encodes untrusted CommonMark while preserving code spans and fenced blocks.
#[must_use]
pub fn encode_comment_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut first = true;
    visit_comment_lines(value, |line, literal| {
        if first {
            first = false;
        } else {
            output.push('\n');
        }
        if literal {
            write_neutralized(&mut output, line);
        } else {
            write_comment_line(&mut output, line);
        }
    });
    output
}

fn normalize_comment_newlines(value: &str) -> Cow<'_, str> {
    if !value.contains('\r') {
        return Cow::Borrowed(value);
    }
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            output.push('\n');
        } else {
            output.push(character);
        }
    }
    Cow::Owned(output)
}

fn visit_comment_lines(value: &str, mut visit: impl FnMut(&str, bool)) {
    let normalized = normalize_comment_newlines(value);
    let mut fenced = false;
    for line in normalized.split('\n') {
        let trimmed = line.trim_start();
        let fence_line = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        visit(line, fenced || fence_line);
        if fence_line {
            fenced = !fenced;
        }
    }
}

fn write_comment_fragment(output: &mut String, value: &str) {
    let mut first = true;
    visit_comment_lines(value, |line, literal| {
        if first {
            first = false;
        } else {
            output.push(' ');
        }
        if literal {
            write_neutralized(output, line);
        } else {
            write_comment_line(output, line);
        }
    });
}

fn write_comment_line(output: &mut String, line: &str) {
    let leading = line.len() - line.trim_start().len();
    output.push_str(&line[..leading]);
    let rest = &line[leading..];
    if comment_line_requires_encoding(rest) {
        write_comment_inline(output, rest);
    } else {
        output.push_str(rest);
    }
}

fn comment_line_requires_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    for index in 0..bytes.len() {
        match bytes[index] {
            b'`' | b'@' | b'{' | b'}' | b'<' => return true,
            b'*' if bytes.get(index + 1) == Some(&b'/') => return true,
            b's' if value[index..].starts_with("sourceMappingURL=") => return true,
            _ => {}
        }
    }
    false
}

fn write_comment_inline(output: &mut String, value: &str) {
    let mut index = 0;
    let mut code = false;
    let mut html = false;
    let mut previous_whitespace = false;
    while index < value.len() {
        let rest = &value[index..];
        if rest.starts_with("*/") {
            output.push_str("*\\/");
            index += 2;
            previous_whitespace = false;
            continue;
        }
        if rest.starts_with("sourceMappingURL=") {
            output.push_str("sourceMappingURL\\=");
            index += "sourceMappingURL=".len();
            previous_whitespace = false;
            continue;
        }
        let character = rest.chars().next().expect("non-empty suffix");
        let character_len = character.len_utf8();
        let next = rest[character_len..].chars().next();
        if character == '`' {
            code = !code;
            output.push(character);
            index += character_len;
            previous_whitespace = false;
            continue;
        }
        if code {
            output.push(character);
            index += character_len;
            previous_whitespace = character.is_whitespace();
            continue;
        }
        match character {
            '@' if next.is_some_and(|next| next.is_ascii_alphabetic())
                && (index == 0 || previous_whitespace) =>
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
        index += character_len;
        previous_whitespace = character.is_whitespace();
    }
}

fn write_neutralized(output: &mut String, mut value: &str) {
    while !value.is_empty() {
        let comment_close = value.find("*/").map(|index| (index, 2, "*\\/"));
        let source_map = value
            .find("sourceMappingURL=")
            .map(|index| (index, "sourceMappingURL=".len(), "sourceMappingURL\\="));
        let next = match (comment_close, source_map) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (Some(found), None) | (None, Some(found)) => Some(found),
            (None, None) => None,
        };
        let Some((index, matched_len, replacement)) = next else {
            output.push_str(value);
            break;
        };
        output.push_str(&value[..index]);
        output.push_str(replacement);
        value = &value[index + matched_len..];
    }
}

fn write_link_part(output: &mut String, value: &str) {
    let mut index = 0;
    while index < value.len() {
        let rest = &value[index..];
        if rest.starts_with("*/") {
            output.push_str("*\\/");
            index += 2;
            continue;
        }
        if rest.starts_with("sourceMappingURL=") {
            output.push_str("sourceMappingURL\\=");
            index += "sourceMappingURL=".len();
            continue;
        }
        let character = rest.chars().next().expect("non-empty suffix");
        match character {
            '{' => output.push_str("\\{"),
            '}' => output.push_str("\\}"),
            '<' => output.push_str("\\<"),
            '>' => output.push_str("\\>"),
            '|' => output.push_str("\\|"),
            '\n' | '\r' => output.push(' '),
            _ => output.push(character),
        }
        index += character.len_utf8();
    }
}

pub(super) fn write_source_metadata(output: &mut String, source: &SourceRef, indent: usize) {
    push_indent(output, indent);
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

/// How `render_json_compact` renders object keys. `Plain` emits a bare string key, correct for type
/// positions. `ProtoSafe` emits a computed key (`["__proto__"]:`) for a key named `__proto__` — in
/// an executable object literal a bare `__proto__` key *sets the prototype* instead of creating an
/// own data property, so the built value would be wrong; a computed key always creates an own data
/// property. Every other key renders identically in both modes. Executable value positions
/// (validator `deepEqual` arguments) use `ProtoSafe`; type positions keep `Plain`, so the type
/// artifacts stay byte-identical.
#[derive(Clone, Copy)]
pub(super) enum ObjectKeyMode {
    Plain,
    ProtoSafe,
}

pub(super) fn render_json_compact(value: &Value, mode: ObjectKeyMode) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(number) => render_number_value(number),
        Value::String(value) => render_ts_string(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(|value| render_json_compact(value, mode))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    render_object_key(key, mode),
                    render_json_compact(value, mode)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn render_object_key(key: &str, mode: ObjectKeyMode) -> String {
    match mode {
        ObjectKeyMode::ProtoSafe if key == "__proto__" => format!("[{}]", render_ts_string(key)),
        _ => render_ts_string(key),
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
        _ => render_json_compact(value, ObjectKeyMode::Plain),
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
                "6f617374732d7372632d763100",
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
    fn path_shaped_source_names_derive_from_token_runs() {
        assert_eq!(
            file_base_name(
                "actions/add-custom-labels-to-self-hosted-runner-for-org",
                FileCase::Kebab
            ),
            Ok("actions-add-custom-labels-to-self-hosted-runner-for-org".to_owned())
        );
        assert_eq!(
            file_base_name("../../etc/passwd", FileCase::Kebab),
            Ok("etc-passwd".to_owned())
        );
        assert_eq!(
            file_base_name("lpt9.txt", FileCase::Preserve),
            Ok("lpt9-txt".to_owned())
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
            file_base_name("lpt9", FileCase::Preserve),
            Err(FileNameError::ReservedDevice)
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
        let indent_width = INDENT_CHUNK.len() + 3;
        let mut indentation = String::new();
        push_indent(&mut indentation, indent_width);
        assert_eq!(indentation, " ".repeat(indent_width));

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
                dependent_required: Vec::new(),
                finite: None,
                extra_required: Vec::new(),
                meta: meta(pointer),
            }
        }

        let analyzed = Analyzed {
            ir: Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({}));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);
        let missing = schema_ref("/missing", "/components/schemas/Missing");
        let nested = SchemaNode::AnyOf {
            branches: vec![
                SchemaNode::Object {
                    properties: Vec::new(),
                    additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                        missing.clone(),
                    ))),
                    dependent_required: Vec::new(),
                    finite: None,
                    extra_required: Vec::new(),
                    meta: meta("/object"),
                },
                SchemaNode::Tuple {
                    prefix_items: Vec::new(),
                    rest: TupleRest::Schema(Box::new(missing.clone())),
                    finite: None,
                    meta: meta("/tuple"),
                },
                SchemaNode::OneOf {
                    branches: vec![tagged("/cat", "pet"), tagged("/dog", "pet")],
                    discriminator: Some(Box::new(Discriminator {
                        property_name: "kind".to_owned(),
                        mapping: Vec::new(),
                        source: source("/discriminator"),
                    })),
                    meta: meta("/union"),
                },
            ],
            discriminator: None,
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
            discriminator: Some(Box::new(Discriminator {
                property_name: "kind".to_owned(),
                mapping: Vec::new(),
                source: source("/unique-discriminator"),
            })),
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
                discriminator: None,
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
                ..Ir::default()
            },
            operation_names: Vec::new(),
            schema_names: vec![AllocatedSchemaName {
                schema_index: 0,
                wire_name: "Loop".to_owned(),
                name: "Loop".to_owned(),
                source: source("/components/schemas/Loop"),
            }],
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "enum": "const" }
        }));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);
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
                    finite: None,
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
                        discriminator: None,
                        meta: meta("/tuple-union"),
                    })),
                    finite: None,
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
                    discriminator: None,
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
    fn render_type_reduces_unknown_in_unions_and_intersections() {
        let analyzed = Analyzed {
            ir: Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({}));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);

        let unknown = |reason: &str, pointer: &str| SchemaNode::Unknown {
            reason: reason.to_owned(),
            meta: meta(pointer),
        };
        let object = SchemaNode::Object {
            properties: vec![(
                "a".to_owned(),
                primitive(PrimitiveType::String, "/object/a"),
                prop_meta("/object/a"),
            )],
            additional_properties: AdditionalProperties::Forbidden,
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: meta("/object"),
        };
        let conjunction = SchemaNode::AllOf {
            branches: vec![
                SchemaNode::OneOf {
                    branches: vec![
                        unknown("first reason", "/one-of/first"),
                        unknown("second reason", "/one-of/second"),
                    ],
                    discriminator: None,
                    meta: meta("/one-of"),
                },
                object,
            ],
            meta: meta("/all-of"),
        };
        assert_eq!(
            emitter.render_type(&conjunction, TypePosition::Neutral, 0),
            "{\n  a?: string;\n}"
        );

        let duplicate_unknowns = SchemaNode::AnyOf {
            branches: vec![
                unknown("one reason", "/duplicates/first"),
                unknown("another reason", "/duplicates/second"),
            ],
            discriminator: None,
            meta: meta("/duplicates"),
        };
        assert_eq!(
            emitter.render_type(&duplicate_unknowns, TypePosition::Neutral, 0),
            "unknown"
        );

        let distinct = SchemaNode::OneOf {
            branches: vec![
                primitive(PrimitiveType::String, "/distinct/string"),
                primitive(PrimitiveType::Number, "/distinct/number"),
            ],
            discriminator: None,
            meta: meta("/distinct"),
        };
        assert_eq!(
            emitter.render_type(&distinct, TypePosition::Neutral, 0),
            "string | number"
        );

        let boolean_schemas = SchemaNode::AnyOf {
            branches: vec![
                SchemaNode::Any {
                    meta: meta("/boolean-schemas/true"),
                },
                SchemaNode::Never {
                    meta: meta("/boolean-schemas/false"),
                },
                primitive(PrimitiveType::String, "/boolean-schemas/string"),
            ],
            discriminator: None,
            meta: meta("/boolean-schemas"),
        };
        assert_eq!(
            emitter.render_type(&boolean_schemas, TypePosition::Neutral, 0),
            "unknown | never | string"
        );

        let only_unknown = SchemaNode::AllOf {
            branches: vec![SchemaNode::Any {
                meta: meta("/all-unknown/true"),
            }],
            meta: meta("/all-unknown"),
        };
        assert_eq!(
            emitter.render_type(&only_unknown, TypePosition::Neutral, 0),
            "unknown"
        );
    }

    #[test]
    fn intersection_parenthesizes_union_members() {
        // `&` binds tighter than `|` in TypeScript, so a union branch of an intersection must be
        // wrapped or the type changes meaning. Every wrapping trigger is exercised: a `OneOf` node,
        // a nullable branch, an `enum` primitive (a top-level union that is not a `OneOf`/`AnyOf`
        // node), and a bare primitive plus an array-of-union that must stay unwrapped.
        let analyzed = Analyzed {
            ir: Ir {
                schemas: Vec::new(),
                ..Ir::default()
            },
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({}));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);

        let mut nullable_string = primitive(PrimitiveType::String, "/nullable");
        if let SchemaNode::Primitive { meta, .. } = &mut nullable_string {
            meta.nullable = true;
        }
        let enum_string = SchemaNode::Primitive {
            ty: PrimitiveType::String,
            format: None,
            enum_values: Some(vec![json!("a"), json!("b")]),
            const_value: None,
            meta: meta("/enum"),
        };
        let one_of = |pointer: &str| SchemaNode::OneOf {
            branches: vec![
                primitive(PrimitiveType::String, "/one"),
                primitive(PrimitiveType::Number, "/two"),
            ],
            discriminator: None,
            meta: meta(pointer),
        };
        let conjunction = SchemaNode::AllOf {
            branches: vec![
                primitive(PrimitiveType::String, "/plain"),
                one_of("/union"),
                nullable_string,
                enum_string,
                SchemaNode::Array {
                    items: Box::new(one_of("/array-union")),
                    finite: None,
                    meta: meta("/array"),
                },
            ],
            meta: meta("/conjunction"),
        };

        assert_eq!(
            emitter.render_type(&conjunction, TypePosition::Neutral, 0),
            r#"string & (string | number) & (string | null) & ("a" | "b") & (string | number)[]"#,
        );
    }

    fn schema_file<'a>(files: &'a [GeneratedFile], base: &str) -> &'a GeneratedFile {
        let suffix = format!("/{base}.ts");
        files
            .iter()
            .find(|file| file.relative_path.ends_with(&suffix))
            .expect("generated schema file")
    }

    fn composition_diagnostic_count(diagnostics: &[Diagnostic]) -> usize {
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_COMPOSITION)
            .count()
    }

    #[test]
    fn oneof_anyof_coexist_lowers_to_allof() {
        // {oneOf, anyOf} on one object is the conjunction of the two unions. It lowers to
        // AllOf[OneOf, AnyOf] and renders `(A | B) & (C | D)` — the parenthesization from the S4 fix.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "Thing": {
                    "oneOf": [{ "type": "string" }, { "type": "number" }],
                    "anyOf": [{ "type": "boolean" }, { "type": "integer" }]
                }
            })),
            json!({}),
        );
        let thing = schema_file(&files, "thing");
        assert!(
            thing
                .content
                .contains("(string | number) & (boolean | number)"),
            "{}",
            thing.content
        );
    }

    #[test]
    fn lowered_conjunction_disjoint_type_reports_oasts1303() {
        // {type:"string", oneOf:[number, integer]} lowers to AllOf[OneOf(number|integer), string].
        // The primitive domains are disjoint, so the existing composition check now fires OASTS1303 on
        // a spec that used to be silently wrong.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Thing": {
                    "type": "string",
                    "oneOf": [{ "type": "number" }, { "type": "integer" }]
                }
            })),
            json!({}),
        );
        assert!(
            composition_diagnostic_count(&diagnostics) >= 1,
            "{diagnostics:?}"
        );
    }

    #[test]
    fn lowered_conjunction_compatible_no_diag() {
        // A compatible coexistence — string on both the allOf branch and the typed piece — intersects
        // to a non-empty domain, so no OASTS1303.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Thing": {
                    "type": "string",
                    "allOf": [{ "type": "string" }]
                }
            })),
            json!({}),
        );
        assert_eq!(
            composition_diagnostic_count(&diagnostics),
            0,
            "{diagnostics:?}"
        );
    }

    #[test]
    fn allof_sibling_constraint_documented_once() {
        // The sibling minLength documents the wrapper's TSDoc exactly once; the typed branch carries
        // empty docs and never repeats it (the meta split guarding against double-application).
        let (files, _diagnostics) = compile(
            openapi(json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "allOf": [{ "$ref": "#/components/schemas/Base" }],
                    "minLength": 3
                }
            })),
            json!({}),
        );
        let thing = schema_file(&files, "thing");
        assert_eq!(
            thing.content.matches("minLength: 3").count(),
            1,
            "{}",
            thing.content
        );
    }

    #[test]
    fn recursive_all_of_ref_terminates_as_named_reference() {
        // Regression: a schema whose member is `allOf: [{$ref: self}]` — the Kubernetes
        // JSONSchemaProps idiom — must not inline forever. merge_all_of inlines the ref
        // once, then the self-referential branch renders as the bare named type instead
        // of recursing. Before the render cycle guard this overflowed the stack (
        // cycles are legal when they form recursive schemas).
        let recursive = SchemaNode::Object {
            properties: vec![(
                "child".to_owned(),
                SchemaNode::AllOf {
                    branches: vec![schema_ref(
                        "/components/schemas/Loop/properties/child",
                        "/components/schemas/Loop",
                    )],
                    meta: meta("/components/schemas/Loop/properties/child"),
                },
                prop_meta("/components/schemas/Loop/properties/child"),
            )],
            additional_properties: AdditionalProperties::Forbidden,
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: meta("/components/schemas/Loop"),
        };
        let analyzed = Analyzed {
            ir: Ir {
                operations: Vec::new(),
                schemas: vec![NamedSchema {
                    name: "Loop".to_owned(),
                    schema: recursive.clone(),
                    source: source("/components/schemas/Loop"),
                }],
                ..Ir::default()
            },
            operation_names: Vec::new(),
            schema_names: vec![AllocatedSchemaName {
                schema_index: 0,
                wire_name: "Loop".to_owned(),
                name: "Loop".to_owned(),
                source: source("/components/schemas/Loop"),
            }],
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({}));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);

        // Terminates (no stack overflow) and the recursive branch is the bare named type.
        let rendered = emitter.render_type(&recursive, TypePosition::Neutral, 0);
        assert!(rendered.contains("child"));
        assert!(
            rendered.contains("Loop"),
            "recursive branch must render as the named type: {rendered}"
        );
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
                dependent_required: Vec::new(),
                finite: None,
                extra_required: Vec::new(),
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
                ..Ir::default()
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
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "enum": "const" },
            "emit": { "importExtension": "none" }
        }));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&mut model);

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
                    finite: None,
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
            discriminator: None,
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
    fn prewarm_covers_alias_cycle_and_schema_additional_properties() {
        // Direct IR construction, since the analyzer never emits these shapes. An `allOf`
        // whose ref branch chains through a ref-alias cycle (AliasA -> AliasB -> AliasA)
        // drives `resolve_ref_ir`'s cycle guard during prewarm, and an object with a
        // schema-valued `additionalProperties` drives the prewarm walk's recursion into
        // it. `emit()` prewarms both before rendering, so this also reads back the cached
        // does-not-merge answer.
        let alias_a = source("/components/schemas/AliasA");
        let alias_b = source("/components/schemas/AliasB");
        let uses = source("/components/schemas/UsesAlias");
        let dict = source("/components/schemas/Dict");
        let open_dict = source("/components/schemas/OpenDict");
        let analyzed = Analyzed {
            ir: Ir {
                operations: Vec::new(),
                schemas: vec![
                    NamedSchema {
                        name: "AliasA".to_owned(),
                        schema: schema_ref(
                            "/components/schemas/AliasA",
                            "/components/schemas/AliasB",
                        ),
                        source: alias_a.clone(),
                    },
                    NamedSchema {
                        name: "AliasB".to_owned(),
                        schema: schema_ref(
                            "/components/schemas/AliasB",
                            "/components/schemas/AliasA",
                        ),
                        source: alias_b.clone(),
                    },
                    NamedSchema {
                        name: "UsesAlias".to_owned(),
                        schema: SchemaNode::AllOf {
                            branches: vec![schema_ref(
                                "/components/schemas/UsesAlias/allOf/0",
                                "/components/schemas/AliasA",
                            )],
                            meta: meta("/components/schemas/UsesAlias"),
                        },
                        source: uses.clone(),
                    },
                    NamedSchema {
                        name: "Dict".to_owned(),
                        schema: SchemaNode::Object {
                            properties: Vec::new(),
                            additional_properties: AdditionalProperties::Schema(Box::new(
                                primitive(
                                    PrimitiveType::String,
                                    "/components/schemas/Dict/additionalProperties",
                                ),
                            )),
                            dependent_required: Vec::new(),
                            finite: None,
                            extra_required: Vec::new(),
                            meta: meta("/components/schemas/Dict"),
                        },
                        source: dict.clone(),
                    },
                    NamedSchema {
                        name: "OpenDict".to_owned(),
                        // `Allowed(Some(_))` is the other schema-valued form the prewarm
                        // walk descends into; `Schema(_)` above covers the sibling arm.
                        schema: SchemaNode::Object {
                            properties: Vec::new(),
                            additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                                primitive(
                                    PrimitiveType::Number,
                                    "/components/schemas/OpenDict/additionalProperties",
                                ),
                            ))),
                            dependent_required: Vec::new(),
                            finite: None,
                            extra_required: Vec::new(),
                            meta: meta("/components/schemas/OpenDict"),
                        },
                        source: open_dict.clone(),
                    },
                ],
                ..Ir::default()
            },
            operation_names: Vec::new(),
            schema_names: vec![
                AllocatedSchemaName {
                    schema_index: 0,
                    wire_name: "AliasA".to_owned(),
                    name: "AliasA".to_owned(),
                    source: alias_a,
                },
                AllocatedSchemaName {
                    schema_index: 1,
                    wire_name: "AliasB".to_owned(),
                    name: "AliasB".to_owned(),
                    source: alias_b,
                },
                AllocatedSchemaName {
                    schema_index: 2,
                    wire_name: "UsesAlias".to_owned(),
                    name: "UsesAlias".to_owned(),
                    source: uses,
                },
                AllocatedSchemaName {
                    schema_index: 3,
                    wire_name: "Dict".to_owned(),
                    name: "Dict".to_owned(),
                    source: dict,
                },
                AllocatedSchemaName {
                    schema_index: 4,
                    wire_name: "OpenDict".to_owned(),
                    name: "OpenDict".to_owned(),
                    source: open_dict,
                },
            ],
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({ "emit": { "importExtension": "none" } }));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = Emitter::new(&mut model).emit();
        // The cyclic `allOf` does not merge, so `UsesAlias` renders as its raw branch ref.
        assert!(
            files
                .iter()
                .any(|file| file.content.contains("export type UsesAlias = AliasA;"))
        );
        // The schema-valued `additionalProperties` keeps its index signature.
        assert!(
            files
                .iter()
                .any(|file| file.content.contains("[key: string]: string"))
        );
    }

    #[test]
    fn prewarmed_merges_match_the_fallback_path() {
        // Differential guard for the mirrored resolve_ref/resolve_ref_ir pair: for every
        // IR-resident allOf slice in the composition-stressor fixture, the model-lifetime
        // prewarm path and the &self fallback path must produce the identical merge. An
        // edit that desynchronizes the mirrors makes the cached answer win silently in
        // production, so this asserts equivalence over real analyzer output, not one
        // hand-picked shape.
        fn collect_all_of<'i>(schema: &'i SchemaNode, out: &mut Vec<&'i [SchemaNode]>) {
            match schema {
                SchemaNode::Object {
                    properties,
                    additional_properties,
                    ..
                } => {
                    for (_, property, _) in properties {
                        collect_all_of(property, out);
                    }
                    if let AdditionalProperties::Allowed(Some(schema))
                    | AdditionalProperties::Schema(schema) = additional_properties
                    {
                        collect_all_of(schema, out);
                    }
                }
                SchemaNode::Array { items, .. } => collect_all_of(items, out),
                SchemaNode::Tuple {
                    prefix_items, rest, ..
                } => {
                    for item in prefix_items {
                        collect_all_of(item, out);
                    }
                    if let TupleRest::Schema(schema) = rest {
                        collect_all_of(schema, out);
                    }
                }
                SchemaNode::AllOf { branches, .. } => {
                    out.push(branches);
                    for branch in branches {
                        collect_all_of(branch, out);
                    }
                }
                SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                    for branch in branches {
                        collect_all_of(branch, out);
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

        // pathological-3.1 stresses allOf composition; validators-showcase-3.1 carries
        // the tuple and schema-valued additionalProperties shapes the walk descends into.
        let mut compared = 0usize;
        for fixture_name in ["pathological-3.1", "validators-showcase-3.1"] {
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures")
                .join(fixture_name);
            let config = crate::config::load_config(Some(&fixture.join("oasts.yaml")), &fixture)
                .expect("fixture config loads");
            let mut sink = DiagnosticSink::new();
            let graph = crate::loader::load_graph(&config, &mut sink).expect("fixture graph loads");
            let ir = crate::parse::parse(&graph, &mut sink).expect("fixture parses");
            let analyzed = crate::semantic::analyze(ir, &config, &mut sink);
            assert!(!sink.has_errors(), "{fixture_name}: {:#?}", sink.as_slice());

            let mut sink = DiagnosticSink::new();
            let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
            let emitter = Emitter::new(&mut model);
            let mut slices = Vec::new();
            for schema in &analyzed.ir.schemas {
                collect_all_of(&schema.schema, &mut slices);
            }
            compared += slices.len();
            for branches in slices {
                let prewarm = emitter
                    .merge_all_of_ir(branches)
                    .map(|(properties, additional)| (properties, additional.clone()));
                let fallback = emitter
                    .merge_all_of(branches)
                    .map(|(properties, additional)| (properties, additional.clone()));
                assert_eq!(prewarm, fallback);
            }

            // The empty slice shares the dangling-pointer sentinel with every other empty
            // Vec, so cache_merge_all_of must refuse to key it.
            emitter.cache_merge_all_of(&[]);
            assert!(emitter.merge_cache.borrow().is_empty());
        }
        assert!(
            compared > 0,
            "the walked fixtures must contain allOf slices for this guard to bite"
        );

        // The corpus never emits `Allowed(Some(_))` — cover that walk arm with direct IR,
        // the same way the prewarm test covers it in production code.
        let open_dict = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                SchemaNode::AllOf {
                    branches: vec![primitive(PrimitiveType::String, "/open/allOf/0")],
                    meta: meta("/open"),
                },
            ))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: meta("/open"),
        };
        let mut extra = Vec::new();
        collect_all_of(&open_dict, &mut extra);
        assert_eq!(extra.len(), 1);
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
                content_media_type: None,
                style: None,
                explode: None,
                allow_reserved: false,
                source: source("/parameter/filter"),
            }],
            request_body: Some(Body {
                required: false,
                description: Some("Opaque body.".to_owned()),
                media_types: vec![MediaType {
                    essence: "application/octet-stream".to_owned(),
                    full: "application/octet-stream".to_owned(),
                    range_kind: crate::media::MediaRangeKind::Concrete,
                    raw_name: String::new(),
                    schema: request_schema,
                    schema_present: true,
                    examples: vec![("sample".to_owned(), json!({ "bytes": 2 }))],
                    encodings: Vec::new(),
                    streaming_marked: false,
                    oas_version: crate::ir::OasVersion::V3_1,
                    source: source("/request/media"),
                }],
                source: source("/request"),
            }),
            responses: vec![
                ResponseEntry {
                    status: ResponseStatus::Exact("200".to_owned()),
                    description: "Opaque response.".to_owned(),
                    media_types: vec![MediaType {
                        essence: "application/octet-stream".to_owned(),
                        full: "application/octet-stream".to_owned(),
                        range_kind: crate::media::MediaRangeKind::Concrete,
                        raw_name: String::new(),
                        schema: response_schema,
                        schema_present: true,
                        examples: vec![("sample".to_owned(), json!({ "bytes": 3 }))],
                        encodings: Vec::new(),
                        streaming_marked: false,
                        oas_version: crate::ir::OasVersion::V3_1,
                        source: source("/response/media"),
                    }],
                    headers: Vec::new(),
                    links: Vec::new(),
                    source: source("/response"),
                },
                ResponseEntry {
                    status: ResponseStatus::Exact("204".to_owned()),
                    description: "Empty response.".to_owned(),
                    media_types: Vec::new(),
                    headers: Vec::new(),
                    links: Vec::new(),
                    source: source("/response/empty"),
                },
            ],
            callbacks: Vec::new(),
            servers: Vec::new(),
            security: None,
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
            callbacks: Vec::new(),
            servers: Vec::new(),
            security: None,
            source: source("/operation/empty"),
        };
        let analyzed = Analyzed {
            ir: Ir {
                operations: vec![rich, empty],
                schemas: Vec::new(),
                ..Ir::default()
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
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let (_temp, config) = resolved_config(json!({
            "types": { "readonly": true },
            "documentation": { "summary": false, "description": true }
        }));
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let files = Emitter::new(&mut model).emit();
        drop(model);
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

    /// The variant-need decision reaches read/write-only markers buried in an inline nested object,
    /// so the top-level component splits into Request/Response variants that drop them per position.
    /// A sibling with no such markers stays single. Regression: a shallow decision that only inspects
    /// direct properties emits a Neutral-only type while the position-aware renderer drops the nested
    /// property — a mismatch that surfaces as a dangling import or a dead export downstream.
    #[test]
    fn shape_variants_recurses_nested_inline() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "meta": {
                        "type": "object",
                        "properties": {
                            "serverId": { "type": "string", "readOnly": true },
                            "secret": { "type": "string", "writeOnly": true }
                        }
                    }
                }
            },
            "Plain": {
                "type": "object",
                "properties": { "name": { "type": "string" } }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
        let plain = files
            .iter()
            .find(|file| file.relative_path.ends_with("plain.ts"))
            .expect("Plain file");
        assert!(!plain.content.contains("PlainRequest"), "{}", plain.content);
        assert!(
            !plain.content.contains("PlainResponse"),
            "{}",
            plain.content
        );
    }

    /// The decision recurses through the merged shape of an inline `allOf` branch, matching the
    /// renderer, which drops the read/write-only member from the intersection per position.
    #[test]
    fn shape_variants_recurses_allof_inline() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "combo": {
                        "allOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "serverId": { "type": "string", "readOnly": true },
                                    "secret": { "type": "string", "writeOnly": true }
                                }
                            }
                        ]
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// The decision descends into array items, matching the renderer, which drops the read/write-only
    /// member from each element type per position.
    #[test]
    fn shape_variants_recurses_array_items() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "serverId": { "type": "string", "readOnly": true },
                                "secret": { "type": "string", "writeOnly": true }
                            }
                        }
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// The decision descends into an inline `additionalProperties` value schema, matching the
    /// renderer, which drops the read/write-only member from the value type per position. Without
    /// this recursion a read/write-only marker reachable only through `additionalProperties` is
    /// missed and no variant is emitted (mutation gap: deleting the recursion survived the suite).
    #[test]
    fn shape_variants_recurses_additional_properties_inline() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "attrs": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "serverId": { "type": "string", "readOnly": true },
                                "secret": { "type": "string", "writeOnly": true }
                            }
                        }
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// The decision descends into an inline `oneOf` branch, matching the renderer, which drops the
    /// read/write-only member from each branch per position.
    #[test]
    fn shape_variants_recurses_oneof_inline() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "choice": {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "serverId": { "type": "string", "readOnly": true },
                                    "secret": { "type": "string", "writeOnly": true }
                                }
                            }
                        ]
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// The decision descends into a tuple's rest-item schema (`items` alongside `prefixItems`),
    /// matching the renderer, which drops the read/write-only member from elements beyond the
    /// fixed prefix per position.
    #[test]
    fn shape_variants_recurses_tuple_rest() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "coords": {
                        "type": "array",
                        "prefixItems": [{ "type": "number" }],
                        "items": {
                            "type": "object",
                            "properties": {
                                "serverId": { "type": "string", "readOnly": true },
                                "secret": { "type": "string", "writeOnly": true }
                            }
                        }
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// Once both variants are known needed while walking a tuple's fixed-position elements, the
    /// accumulator short-circuits without visiting the remaining prefix items or the rest-item
    /// schema; the observable result is still both variants emitted.
    #[test]
    fn shape_variants_tuple_prefix_items_short_circuit() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "coords": {
                        "type": "array",
                        "prefixItems": [
                            {
                                "type": "object",
                                "properties": {
                                    "serverId": { "type": "string", "readOnly": true },
                                    "secret": { "type": "string", "writeOnly": true }
                                }
                            },
                            { "type": "string" }
                        ],
                        "items": { "type": "string" }
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// Once both variants are known needed, the accumulator short-circuits without visiting the rest
    /// of the tree; the observable result is still both variants emitted.
    #[test]
    fn both_variants_short_circuit() {
        let document = openapi(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "serverId": { "type": "string", "readOnly": true },
                    "secret": { "type": "string", "writeOnly": true },
                    "deep": {
                        "type": "object",
                        "properties": {
                            "more": { "type": "string", "readOnly": true }
                        }
                    }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
    }

    /// A `readOnly` annotation on a component's own root (not on any of its properties) seeds that
    /// component's Request variant need directly, with no property-level marker involved. Referenced
    /// as a property elsewhere, the referent gets a `{Name}Request` alias, and the propagation pass
    /// carries that need to the referrer too, since the referrer's rendering of that property now
    /// names the referent's variant type.
    #[test]
    fn readonly_root_component_seeds_variant() {
        let document = openapi(json!({
            "Timestamps": {
                "type": "object",
                "readOnly": true,
                "properties": { "createdAt": { "type": "string" } }
            },
            "Pet": {
                "type": "object",
                "properties": { "timestamps": { "$ref": "#/components/schemas/Timestamps" } }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let timestamps = files
            .iter()
            .find(|file| file.relative_path.ends_with("timestamps.ts"))
            .expect("Timestamps file");
        assert!(
            timestamps
                .content
                .contains("export interface TimestampsRequest {"),
            "{}",
            timestamps.content
        );
        assert!(
            !timestamps.content.contains("Response"),
            "root readOnly alone must not seed a Response variant: {}",
            timestamps.content
        );
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(
            pet.content.contains("TimestampsRequest"),
            "PetRequest must reference Timestamps' own Request variant: {}",
            pet.content
        );
    }

    /// A `writeOnly` annotation on the root of a schema nested inside an `allOf` branch — not on a
    /// property, and not on the referenced component's own top-level node — still seeds that
    /// component's Response variant need: the recursion into each branch applies the same
    /// own-annotation check it applies at the top level. The fixpoint then carries the need to
    /// whatever else references the component.
    #[test]
    fn writeonly_in_allof_branch_propagates_via_fixpoint() {
        let document = openapi(json!({
            "Secret": {
                "allOf": [
                    {
                        "type": "object",
                        "writeOnly": true,
                        "properties": { "value": { "type": "string" } }
                    }
                ]
            },
            "Envelope": {
                "type": "object",
                "properties": { "secret": { "$ref": "#/components/schemas/Secret" } }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let secret = files
            .iter()
            .find(|file| file.relative_path.ends_with("secret.ts"))
            .expect("Secret file");
        assert!(
            secret.content.contains("export type SecretResponse ="),
            "{}",
            secret.content
        );
        assert!(
            !secret.content.contains("Request"),
            "an allOf-branch writeOnly alone must not seed a Request variant: {}",
            secret.content
        );
        let envelope = files
            .iter()
            .find(|file| file.relative_path.ends_with("envelope.ts"))
            .expect("Envelope file");
        assert!(
            envelope
                .content
                .contains("export interface EnvelopeResponse {"),
            "fixpoint must carry Secret's Response need to Envelope: {}",
            envelope.content
        );
    }

    /// A scalar-rooted component's `readOnly` still seeds its own Request variant (an alias sharing
    /// the neutral declaration's underlying type), but that root annotation does not retroactively
    /// mark the referring property's own metadata. Property omission in a rendered position is keyed
    /// off the referring site's own `readOnly`/`writeOnly` annotation, never off a property inherited
    /// from what the property's type points at, so a property typed as this component is never
    /// dropped from a request rendering on the strength of the referent's root alone — only the
    /// referenced type name changes to the referent's own variant. This is a deliberate, bounded
    /// limitation of the omission mechanism, not a defect.
    #[test]
    fn scalar_readonly_root_generates_alias_not_omission() {
        let document = openapi(json!({
            "Token": { "type": "string", "readOnly": true },
            "Session": {
                "type": "object",
                "properties": { "token": { "$ref": "#/components/schemas/Token" } }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let token = files
            .iter()
            .find(|file| file.relative_path.ends_with("token.ts"))
            .expect("Token file");
        assert!(token.content.contains("TokenRequest"), "{}", token.content);
        let session = files
            .iter()
            .find(|file| file.relative_path.ends_with("session.ts"))
            .expect("Session file");
        assert!(
            session
                .content
                .contains("export interface SessionRequest {"),
            "{}",
            session.content
        );
        // If the property were omitted the way a referring-site `readOnly` omits it, "TokenRequest"
        // would never appear anywhere in this file — Neutral rendering names the property's type
        // "Token", so "TokenRequest" only ever appears in a rendering where the property survived and
        // its type resolved to the referent's own Request variant.
        assert!(
            session.content.contains("TokenRequest"),
            "the token property must survive into SessionRequest, naming Token's Request variant: {}",
            session.content
        );
    }

    /// A `readOnly`-rooted component referenced two hops deep (through an intermediate component,
    /// itself referenced by a third) still resolves to the same variant alias name at every hop —
    /// the propagation fixpoint and naming are keyed off each component's own identity, not off the
    /// path used to reach it, so nesting depth cannot perturb the name.
    #[test]
    fn nested_component_variant_naming() {
        let document = openapi(json!({
            "Timestamps": {
                "type": "object",
                "readOnly": true,
                "properties": { "createdAt": { "type": "string" } }
            },
            "Pet": {
                "type": "object",
                "properties": { "timestamps": { "$ref": "#/components/schemas/Timestamps" } }
            },
            "Shelter": {
                "type": "object",
                "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet file");
        assert!(
            pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        assert!(pet.content.contains("TimestampsRequest"), "{}", pet.content);
        let shelter = files
            .iter()
            .find(|file| file.relative_path.ends_with("shelter.ts"))
            .expect("Shelter file");
        assert!(
            shelter
                .content
                .contains("export interface ShelterRequest {"),
            "{}",
            shelter.content
        );
        assert!(
            shelter.content.contains("PetRequest"),
            "Shelter's variant must name Pet's own Request variant, not a mangled compound name: {}",
            shelter.content
        );
        assert!(
            !shelter.content.contains("PetTimestampsRequest"),
            "{}",
            shelter.content
        );
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

    fn discriminator_diagnostics(diagnostics: &[Diagnostic]) -> Vec<&Diagnostic> {
        diagnostics
            .iter()
            .filter(|diagnostic| {
                matches!(
                    diagnostic.code,
                    CODE_DISCRIMINATOR | CODE_DISCRIMINATOR_PROOF | CODE_MAPPING_TARGET
                )
            })
            .collect()
    }

    #[test]
    fn anyof_discriminator_proves_literals() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "anyOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
        let pet = files
            .iter()
            .find(|file| file.relative_path.ends_with("pet.ts"))
            .expect("Pet");
        assert!(generated_body(pet).contains("export type Pet = Cat | Dog;"));
    }

    #[test]
    fn anyof_discriminator_structural_fallback_warns() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Pet": { "anyOf": [{ "$ref": "#/components/schemas/Cat" }, { "type": "string" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_DISCRIMINATOR);
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
    }

    #[test]
    fn oneof_and_anyof_discriminator_proof_runs_once() {
        // oneOf, anyOf, and a discriminator coexist, so the schema lowers to a conjunction. Only the
        // oneOf branch carries the discriminator, so the structural-fallback proof — and its single
        // OASTS1304 — fires once, not once per synthetic branch.
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Wrapped": {
                "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "type": "string" }],
                "anyOf": [{ "$ref": "#/components/schemas/Cat" }, { "type": "string" }],
                "discriminator": { "propertyName": "kind" }
            }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_DISCRIMINATOR);
    }

    #[test]
    fn discriminator_mapping_proves_branch_literal() {
        let document = openapi(json!({
            "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Dog": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind",
                       "mapping": { "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog" } } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn discriminator_allof_idiom_proves_through_merge() {
        let document = openapi(json!({
            "Pet": { "type": "object", "properties": { "name": { "type": "string" } } },
            "Cat": { "allOf": [
                { "$ref": "#/components/schemas/Pet" },
                { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } }
            ] },
            "Dog": { "allOf": [
                { "$ref": "#/components/schemas/Pet" },
                { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } }
            ] },
            "Animal": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn dangling_mapping_is_error_oasts1308() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind",
                       "mapping": { "cat": "other.json#/components/schemas/Cat" } } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        // The const-proved branches still prove; only the dangling mapping value is reported.
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_MAPPING_TARGET);
        assert_eq!(flagged[0].severity, Severity::Error);
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
    }

    #[test]
    fn mapping_const_conflict_warns_oasts1309() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": { "feline": "Cat" } } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        let warning = flagged[0];
        assert_eq!(warning.code, CODE_DISCRIMINATOR_PROOF);
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(
            warning.json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
        assert!(warning.message.contains("maps 'feline'"), "{warning:?}");
        assert!(warning.message.contains("fixed to \"cat\""), "{warning:?}");
    }

    #[test]
    fn implicit_mapping_uses_component_name() {
        let document = openapi(json!({
            "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Dog": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        // No mapping and no const: the component names Cat/Dog are the distinct tags, so the union
        // proves where the pre-implicit path would have warned.
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn allof_conflicting_consts_no_proof() {
        let document = openapi(json!({
            "Broken": { "allOf": [
                { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "a" } } },
                { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "b" } } }
            ] },
            "Other": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "c" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Broken" }, { "$ref": "#/components/schemas/Other" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        let warning = flagged[0];
        assert_eq!(warning.code, CODE_DISCRIMINATOR_PROOF);
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(
            warning.json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
        assert!(
            warning.message.contains("no inhabitable value"),
            "{warning:?}"
        );
    }

    #[test]
    fn discriminator_container_finite_tag_proves() {
        // Branch A's tag property is itself an object with a `const`, so its fixed value lives in the
        // object `finite` field b9e3b24 added rather than a primitive `const`; the proof must consult
        // it. Branch B's tag property is a non-finite array, which proves nothing and falls back to
        // the implicit component name — so the two branches still carry distinct tags.
        let document = openapi(json!({
            "A": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "object", "const": { "k": 1 } } } },
            "B": { "type": "object", "properties": { "kind": { "type": "array", "items": { "type": "string" } } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn discriminator_allof_cycle_terminates() {
        // A self-referential allOf branch must not recurse forever while proving its tag: the visited
        // set breaks the cycle, and the non-recursive sub-branch still fixes the literal.
        let document = openapi(json!({
            "Rec": { "allOf": [
                { "$ref": "#/components/schemas/Rec" },
                { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "rec" } } }
            ] },
            "Leaf": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "leaf" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Rec" }, { "$ref": "#/components/schemas/Leaf" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn discriminator_join_relative_source_normalizes_segments() {
        assert_eq!(
            join_relative_source("workspace/nested/openapi.json", "./sibling/../shared.json"),
            "workspace/nested/shared.json"
        );
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
    fn annotated_default_and_example_markers_render() {
        let document = serde_json::from_str::<Value>(
            r#"{"openapi":"3.1.0","info":{"title":"test","version":"1"},"paths":{},"components":{"schemas":{"Annotated":{"type":"number","default":1e999,"examples":[{"nested":[1e999]}]},"Contained":{"type":"object","default":{"nested":[1e999]},"examples":[1e999]}}}}"#,
        )
        .expect("OpenAPI document with arbitrary-precision annotations");
        let (files, diagnostics) = compile(document, json!({}));
        assert_eq!(diagnostics.len(), 4, "{diagnostics:?}");
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code == "OASTS1216" && diagnostic.severity == Severity::Warning
            }),
            "{diagnostics:?}"
        );
        let annotated = files
            .iter()
            .find(|file| file.relative_path.ends_with("annotated.ts"))
            .expect("Annotated");
        let body = generated_body(annotated);
        assert!(
            body.contains("Default value: 1e+999 (outside the binary64 range)"),
            "{body}"
        );
        assert!(
            body.contains("Contains a value outside the binary64 range.\n * \n * ```json"),
            "{body}"
        );
        let contained = files
            .iter()
            .find(|file| file.relative_path.ends_with("contained.ts"))
            .expect("Contained");
        let body = generated_body(contained);
        assert!(
            body.contains(
                "Default value: {\"nested\":[1e+999]\\} (contains a value outside the binary64 range)"
            ),
            "{body}"
        );
        assert!(
            body.contains("Outside the binary64 range.\n * \n * ```json"),
            "{body}"
        );
    }

    #[test]
    fn tsdoc_writer_preserves_section_and_escape_layout() {
        let docs = TsDoc {
            summary: Some("Summary @tag\r\nnext".to_owned()),
            remarks: vec!["First".to_owned(), "Second\nline".to_owned()],
            deprecated: Some("Deprecated."),
            params: vec![
                ("arg\r\nname".to_owned(), "Description\rline".to_owned()),
                // A fenced block inside a param description takes the literal path: its lines are
                // neutralized rather than comment-escaped, so a `*/` inside the fence cannot close
                // the comment while the fence's own markup survives.
                (
                    "fenced".to_owned(),
                    "before\n```txt\n*/ sourceMappingURL=\n```\nafter @tag".to_owned(),
                ),
            ],
            returns: Some("A value."),
            default_value: Some("value\n@tag".to_owned()),
            examples: vec![
                DocExample {
                    label: Some("Label @tag\r\nnext".to_owned()),
                    value: json!("*/ sourceMappingURL="),
                },
                DocExample {
                    label: None,
                    value: json!([1, true]),
                },
            ],
            private_remarks: Some("Private @tag\n```txt\n*/ sourceMappingURL=\n```".to_owned()),
            see: vec![(
                "u{v}|<x>\r\n*/sourceMappingURL=".to_owned(),
                Some("L{a}\r\nB".to_owned()),
            )],
        };
        let mut output = String::new();

        write_tsdoc(&mut output, &docs, 2);

        assert_eq!(
            output,
            concat!(
                "  /**\n",
                "   * Summary \\@tag\n",
                "   * next\n",
                "   * \n",
                "   * @remarks\n",
                "   * First\n",
                "   * \n",
                "   * Second\n",
                "   * line\n",
                "   * \n",
                "   * @deprecated Deprecated.\n",
                "   * \n",
                "   * @param arg name - Description line\n",
                // Fenced lines are neutralized (`*/` and `sourceMappingURL=` escaped) while the
                // fence markers survive; the surrounding prose still takes the @tag escape.
                "   * @param fenced - before ```txt *\\/ sourceMappingURL\\= ``` after \\@tag\n",
                "   * \n",
                "   * @returns A value.\n",
                "   * \n",
                "   * @defaultValue value \\@tag\n",
                "   * \n",
                "   * @example\n",
                "   * Label \\@tag\n",
                "   * next\n",
                "   * \n",
                "   * ```json\n",
                "   * \"*\\/ sourceMappingURL\\=\"\n",
                "   * ```\n",
                "   * \n",
                "   * @example\n",
                "   * ```json\n",
                "   * [\n",
                "   *   1,\n",
                "   *   true\n",
                "   * ]\n",
                "   * ```\n",
                "   * \n",
                "   * @privateRemarks\n",
                "   * Private \\@tag\n",
                "   * ```txt\n",
                "   * *\\/ sourceMappingURL\\=\n",
                "   * ```\n",
                "   * \n",
                "   * @see {@link u\\{v\\}\\|\\<x\\>  *\\/sourceMappingURL\\= | L\\{a\\}  B}\n",
                "   */\n",
            ),
        );
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

    /// A response entry with `n` declared headers ("X-Rate-Limit" optional/integer/deprecated,
    /// "X-Request-Id" required/string, in that order — only the first `n` are kept) plus a
    /// `200 application/json: string` payload, wired through a `get /items` operation whose
    /// generated stem is `ListItems`.
    fn headered_document(header_count: usize) -> Value {
        let mut headers = serde_json::Map::new();
        headers.insert(
            "X-Rate-Limit".to_owned(),
            json!({ "deprecated": true, "schema": { "type": "integer" } }),
        );
        headers.insert(
            "X-Request-Id".to_owned(),
            json!({ "required": true, "schema": { "type": "string" } }),
        );
        while headers.len() > header_count {
            let key = headers.keys().next_back().cloned();
            if let Some(key) = key {
                headers.shift_remove(&key);
            }
        }
        json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } },
                                "headers": Value::Object(headers)
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn response_header_interface_renders_required_and_optional() {
        let (files, diagnostics) = compile(
            headered_document(2),
            json!({ "types": { "readonly": true } }),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = files
            .iter()
            .find(|file| file.relative_path.ends_with("listitems.ts"))
            .expect("operation file");
        let body = generated_body(operation);
        let response_at = body
            .find("export type ListItemsResponse200 = string;")
            .expect("response type declared");
        let headers_at = body
            .find("export interface ListItemsResponse200Headers {")
            .expect("headers interface declared");
        assert!(
            response_at < headers_at,
            "headers interface must follow the response type it describes:\n{body}"
        );
        for expected in [
            "export interface ListItemsResponse200Headers {",
            "@deprecated This header is deprecated.",
            "readonly \"X-Rate-Limit\"?: number;",
            "readonly \"X-Request-Id\": string;",
        ] {
            assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
        }
    }

    #[test]
    fn content_response_headers_type_by_media_family() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } },
                                "headers": {
                                    "X-Json": {
                                        "required": true,
                                        "content": { "application/json": { "schema": {
                                            "type": "object",
                                            "properties": { "label": { "type": "string" } },
                                            "required": ["label"]
                                        } } }
                                    },
                                    "X-Xml": {
                                        "content": { "application/xml": { "schema": { "type": "object" } } }
                                    },
                                    "X-Plain": { "schema": { "type": "integer" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = files
            .iter()
            .find(|file| file.relative_path.ends_with("listitems.ts"))
            .expect("operation file");
        let body = generated_body(operation);
        // A JSON-family content header keeps its typed schema (the declared object shape).
        assert!(
            body.contains("\"X-Json\": {"),
            "X-Json must stay typed:\n{body}"
        );
        assert!(
            body.contains("label"),
            "X-Json object property missing:\n{body}"
        );
        // A non-JSON content header collapses to a bare wire string.
        assert!(
            body.contains("\"X-Xml\"?: string;"),
            "X-Xml must be a plain string:\n{body}"
        );
        // A schema+style header is unaffected and stays typed.
        assert!(
            body.contains("\"X-Plain\"?: number;"),
            "X-Plain must stay typed:\n{body}"
        );
    }

    #[test]
    fn typed_headers_file_emitted_only_when_headers_exist() {
        let (headered_files, diagnostics) = compile(headered_document(2), json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let helper = headered_files
            .iter()
            .find(|file| file.relative_path == "types/headers.ts")
            .expect("TypedHeaders helper emitted for a headered document");
        assert!(
            generated_body(helper).contains(
                "export interface TypedHeaders<K extends string> extends Headers {\n  get(name: K): string | null;\n  get(name: string): string | null;\n}\n"
            )
        );

        let (headerless_files, diagnostics) = compile(headered_document(0), json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(
            !headerless_files
                .iter()
                .any(|file| file.relative_path == "types/headers.ts")
        );
    }

    #[test]
    fn response_links_render_as_see_tags() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/square": {
                    "get": {
                        "operationId": "getSquare",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } },
                                "links": {
                                    "GetToPut": {
                                        "description": "Follow-up write.",
                                        "operationId": "putSquare",
                                        "parameters": {}
                                    }
                                }
                            }
                        }
                    },
                    "put": {
                        "operationId": "putSquare",
                        "responses": { "204": { "description": "Updated." } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = files
            .iter()
            .find(|file| file.relative_path.ends_with("getsquare.ts"))
            .expect("get-square operation file");
        let body = generated_body(operation);
        assert!(
            body.contains("@see {@link PutSquareResponse | GetToPut}"),
            "missing link see-tag in:\n{body}"
        );
        let see_at = body
            .find("@see {@link PutSquareResponse | GetToPut}")
            .expect("see tag present");
        let response_at = body
            .find("export type GetSquareResponse200 = string;")
            .expect("response type declared");
        assert!(
            see_at < response_at,
            "the see-tag belongs to GetSquareResponse200's own TSDoc block:\n{body}"
        );
    }

    /// Two links attached to the same response: one whose `operationId` resolves to no
    /// operation at all (`target_operation_index: None`, already diagnosed in the semantic
    /// stage), and one whose target operation exists but whose own name allocation was
    /// rejected by an invalid `naming.overrides.operations` value (so it never reaches
    /// `operation_stems`). Neither contributes a `@see` line.
    #[test]
    fn response_tsdoc_skips_unresolved_and_unnamed_link_targets() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/square": {
                    "get": {
                        "operationId": "getSquare",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } },
                                "links": {
                                    "Dangling": {
                                        "operationId": "missing",
                                        "parameters": {}
                                    },
                                    "Unnamed": {
                                        "operationId": "badTarget",
                                        "parameters": {}
                                    }
                                }
                            }
                        }
                    },
                    "put": {
                        "operationId": "badTarget",
                        "responses": { "204": { "description": "Updated." } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(
            document,
            json!({ "naming": { "overrides": { "operations": { "badTarget": "bad name" } } } }),
        );
        assert!(
            !diagnostics.is_empty(),
            "expected the dangling-link and bad-override errors"
        );
        let operation = files
            .iter()
            .find(|file| file.relative_path.ends_with("getsquare.ts"))
            .expect("get-square operation file");
        assert!(!generated_body(operation).contains("@see"));
    }

    /// `documentation.enabled = false` suppresses a response's `@see` link entries the same
    /// way it suppresses every other TSDoc this emitter writes.
    #[test]
    fn disabled_documentation_suppresses_response_tsdoc() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/square": {
                    "get": {
                        "operationId": "getSquare",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": { "application/json": { "schema": { "type": "string" } } },
                                "links": {
                                    "GetToPut": {
                                        "operationId": "putSquare",
                                        "parameters": {}
                                    }
                                }
                            }
                        }
                    },
                    "put": {
                        "operationId": "putSquare",
                        "responses": { "204": { "description": "Updated." } }
                    }
                }
            }
        });
        let (files, diagnostics) =
            compile(document, json!({ "documentation": { "enabled": false } }));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = files
            .iter()
            .find(|file| file.relative_path.ends_with("getsquare.ts"))
            .expect("get-square operation file");
        assert!(!generated_body(operation).contains("@see"));
    }

    /// A document with no response headers and no links must render byte-identically to the
    /// pre-ticket baseline captured against unmodified `main` (`f6773bd`/`5545d2a`, before this
    /// ticket's emission changes): same two files, same bytes, and no `types/headers.ts`.
    #[test]
    fn headerless_document_output_unchanged() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Item" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Item": {
                        "type": "object",
                        "required": ["id"],
                        "properties": { "id": { "type": "string" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(files.len(), 2);
        let component = files
            .iter()
            .find(|file| file.relative_path == "types/components/item.ts")
            .expect("component file");
        let operation = files
            .iter()
            .find(|file| file.relative_path == "types/operations/listitems.ts")
            .expect("operation file");
        assert_eq!(
            component.content,
            "// Generated by Oasts 0.0.0. Do not edit.\n// Config schema version: 1\n// Source digest: e265b1d269c4ed7fdb110ea9e7e2ba57706d2ed600c92c9832049ea0f4785ffc\n\n// Source: workspace/openapi.json#/components/schemas/Item\nexport interface Item {\n  id: string;\n}\n"
        );
        assert_eq!(
            operation.content,
            "// Generated by Oasts 0.0.0. Do not edit.\n// Config schema version: 1\n// Source digest: e265b1d269c4ed7fdb110ea9e7e2ba57706d2ed600c92c9832049ea0f4785ffc\n\nimport type { Item } from \"../components/item.js\";\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Responses\n * \n * - 200: OK\n */\nexport type ListItemsRequest = {};\n\n// Source: workspace/openapi.json#/paths/~1items/get/responses/200\nexport type ListItemsResponse200 = Item;\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Responses\n * \n * - 200: OK\n */\nexport type ListItemsResponse = ListItemsResponse200;\n"
        );
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path == "types/headers.ts")
        );
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
            let aliased =
                emit_artifacts(&analyzed, &config, &graph.source_tuples(), None, &mut sink);
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

    fn webhook_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "newPet": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "petEvents": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } }
                        },
                        "responses": { "200": { "description": "ok" } }
                    },
                    "delete": { "responses": { "204": { "description": "gone" } } }
                },
                "pet.created": {
                    "post": { "responses": { "200": { "description": "ok" } } }
                }
            },
            "components": {
                "schemas": {
                    "Pet": { "type": "object", "required": ["id"], "properties": { "id": { "type": "string" } } }
                }
            }
        })
    }

    fn find_file<'a>(files: &'a [GeneratedFile], path: &str) -> &'a GeneratedFile {
        files
            .iter()
            .find(|file| file.relative_path == path)
            .expect("expected generated file")
    }

    /// One operation whose synthesized declarations may collide with the components it imports.
    /// `body_ref` and `response_ref` name the component each site references, or `null` to inline.
    fn shadowing_document(schemas: Value, body_ref: &str, response_ref: &str) -> Value {
        let media = |reference: &str| {
            if reference.is_empty() {
                json!({ "application/json": { "schema": { "type": "string" } } })
            } else {
                json!({
                    "application/json": {
                        "schema": { "$ref": format!("#/components/schemas/{reference}") }
                    }
                })
            }
        };
        json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/uploads": {
                    "post": {
                        "operationId": "completeUpload",
                        "requestBody": { "required": true, "content": media(body_ref) },
                        "responses": {
                            "200": { "description": "ok", "content": media(response_ref) }
                        }
                    }
                }
            },
            "components": { "schemas": schemas }
        })
    }

    #[test]
    fn a_component_shadowing_the_request_type_imports_under_a_role_alias() {
        let (files, diagnostics) = compile(
            shadowing_document(
                json!({
                    "CompleteUploadRequest": {
                        "type": "object",
                        "properties": { "id": { "type": "string" } }
                    }
                }),
                "CompleteUploadRequest",
                "",
            ),
            json!({}),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let file = find_file(&files, "types/operations/completeupload.ts");
        assert!(
            file.content.contains(
                "import type { CompleteUploadRequest as CompleteUploadRequestBody } from \"../components/completeuploadrequest.js\";"
            ),
            "{}",
            file.content
        );
        // The declaration keeps its name and the member names the alias, so `body` resolves to the
        // component rather than back to the envelope being declared.
        assert!(
            file.content
                .contains("export type CompleteUploadRequest = {"),
            "{}",
            file.content
        );
        assert!(
            file.content.contains("body: CompleteUploadRequestBody;"),
            "{}",
            file.content
        );
    }

    #[test]
    fn a_component_shadowing_a_response_type_imports_under_a_role_alias() {
        let (files, diagnostics) = compile(
            shadowing_document(
                json!({
                    "CompleteUploadResponse200": {
                        "type": "object",
                        "properties": { "id": { "type": "string" } }
                    }
                }),
                "",
                "CompleteUploadResponse200",
            ),
            json!({}),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let file = find_file(&files, "types/operations/completeupload.ts");
        assert!(
            file.content.contains(
                "import type { CompleteUploadResponse200 as CompleteUploadResponse200Body } from \"../components/completeuploadresponse200.js\";"
            ),
            "{}",
            file.content
        );
        assert!(
            file.content
                .contains("export type CompleteUploadResponse200 = CompleteUploadResponse200Body;"),
            "{}",
            file.content
        );
    }

    #[test]
    fn an_alias_that_is_itself_imported_is_a_fatal_collision() {
        let (_, diagnostics) = compile(
            shadowing_document(
                json!({
                    "CompleteUploadRequest": {
                        "type": "object",
                        "properties": { "id": { "type": "string" } }
                    },
                    "CompleteUploadRequestBody": { "type": "string" }
                }),
                "CompleteUploadRequest",
                "CompleteUploadRequestBody",
            ),
            json!({}),
        );
        let flagged = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_IMPORT_ALIAS)
            .expect("alias collision diagnostic");
        assert_eq!(flagged.severity, Severity::Error);
        assert!(
            flagged.message.contains("CompleteUploadRequest")
                && flagged.message.contains("CompleteUploadRequestBody"),
            "{}",
            flagged.message
        );
    }

    #[test]
    fn webhook_type_files_render_request_response() {
        let (files, diagnostics) = compile(webhook_document(), json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        // Single-method webhook: one file, carrying the inherited body/response surface.
        let single = find_file(&files, "types/webhooks/newpetpost.ts");
        assert!(
            single
                .content
                .contains("import type { Pet } from \"../components/pet.js\";")
        );
        assert!(single.content.contains("export type NewPetPostRequest = {"));
        assert!(single.content.contains("body: Pet;"));
        assert!(single.content.contains("export type NewPetPostResponse ="));
        // Multi-method webhook: one file per method, never a merged file.
        let post = find_file(&files, "types/webhooks/peteventspost.ts");
        assert!(
            post.content
                .contains("export type PetEventsPostRequest = {")
        );
        let delete = find_file(&files, "types/webhooks/peteventsdelete.ts");
        assert!(
            delete
                .content
                .contains("export type PetEventsDeleteRequest =")
        );
        assert!(
            delete
                .content
                .contains("export type PetEventsDeleteResponse =")
        );
    }

    #[test]
    fn webhooks_descriptor_map_shape() {
        let (files, _) = compile(webhook_document(), json!({}));
        let index = find_file(&files, "types/webhooks/index.ts");
        assert!(index.content.contains("export type Webhooks = {"));
        // Names as written: a bare identifier stays bare, a dotted name is a quoted key.
        assert!(index.content.contains("  newPet: {\n"));
        assert!(index.content.contains("  \"pet.created\": {\n"));
        // Every method arm, keyed by the lowercase IR method.
        assert!(index.content.contains(
            "    post: { request: PetEventsPostRequest; response: PetEventsPostResponse };\n"
        ));
        assert!(index.content.contains(
            "    delete: { request: PetEventsDeleteRequest; response: PetEventsDeleteResponse };\n"
        ));
        // The per-file types are imported from the sibling operation files.
        assert!(index.content.contains(
            "import type { NewPetPostRequest, NewPetPostResponse } from \"./newpetpost.js\";"
        ));
    }

    fn callback_document() -> Value {
        json!({
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
                                        "responses": { "200": { "description": "ok" } },
                                        "callbacks": {
                                            "onAck": {
                                                "{$request.body#/ackUrl}": {
                                                    "post": { "responses": { "204": { "description": "acked" } } }
                                                }
                                            }
                                        }
                                    }
                                },
                                "{$request.query.fallback}": {
                                    "get": { "responses": { "200": { "description": "ok" } } }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn callback_descriptor_uses_quoted_expression_keys() {
        let (files, diagnostics) = compile(callback_document(), json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let index = find_file(&files, "types/callbacks/index.ts");
        // Descriptor named after the declaring operation's stem; both runtime expressions on the
        // multi-expression callback appear only as quoted string keys.
        assert!(index.content.contains("export type SubscribeCallbacks = {"));
        assert!(index.content.contains("  onData: {\n"));
        assert!(index.content.contains("    \"{$request.body#/url}\": {\n"));
        assert!(
            index
                .content
                .contains("    \"{$request.query.fallback}\": {\n")
        );
        // A callback nested inside a callback operation gets its own descriptor.
        assert!(
            index
                .content
                .contains("export type SubscribeOnData_1PostCallbacks = {")
        );
        assert!(index.content.contains("  onAck: {\n"));
        assert!(
            index
                .content
                .contains("    \"{$request.body#/ackUrl}\": {\n")
        );
        // The expression text never leaks into an identifier: every line mentioning `$request`
        // is a quoted property key, never an export/import token.
        for line in index.content.lines() {
            if line.contains("$request") {
                assert!(
                    line.trim_start().starts_with('"'),
                    "expression must only appear as a quoted key: {line}"
                );
            }
        }
    }

    #[test]
    fn webhookless_document_emits_no_webhook_files() {
        // A document with neither webhooks nor callbacks emits nothing under either directory, so
        // its file set stays byte-identical to before this ticket.
        let document = openapi(json!({
            "Pet": { "type": "object", "properties": { "id": { "type": "string" } } }
        }));
        let (files, _) = compile(document, json!({}));
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("types/webhooks/"))
        );
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("types/callbacks/"))
        );
    }

    #[test]
    fn empty_webhook_appears_in_map_without_files() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": { "quietHook": {} }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        // No per-method file exists — only the index carries the webhook.
        assert!(!files.iter().any(|file| {
            file.relative_path.starts_with("types/webhooks/")
                && file.relative_path != "types/webhooks/index.ts"
        }));
        let index = find_file(&files, "types/webhooks/index.ts");
        assert!(index.content.contains("quietHook: {};"));
    }

    #[test]
    fn webhook_side_callback_gets_its_own_descriptor() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "petCreated": {
                    "post": {
                        "responses": { "200": { "description": "ok" } },
                        "callbacks": {
                            "ack": {
                                "{$request.body#/ackUrl}": {
                                    "post": { "responses": { "204": { "description": "acked" } } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        let index = find_file(&files, "types/callbacks/index.ts");
        // A callback declared on a webhook operation is named after that webhook operation's stem.
        assert!(
            index
                .content
                .contains("export type PetCreatedPostCallbacks = {")
        );
        assert!(index.content.contains("  ack: {\n"));
        assert!(
            index
                .content
                .contains("    \"{$request.body#/ackUrl}\": {\n")
        );
    }

    #[test]
    fn descriptor_maps_honor_readonly_config() {
        let readonly = json!({ "types": { "readonly": true } });
        let (webhook_files, _) = compile(webhook_document(), readonly.clone());
        let webhooks = find_file(&webhook_files, "types/webhooks/index.ts");
        assert!(webhooks.content.contains("  readonly newPet: {\n"));
        assert!(webhooks.content.contains(
            "    readonly post: { readonly request: NewPetPostRequest; readonly response: NewPetPostResponse };\n"
        ));
        let (callback_files, _) = compile(callback_document(), readonly);
        let callbacks = find_file(&callback_files, "types/callbacks/index.ts");
        assert!(callbacks.content.contains("  readonly onData: {\n"));
        assert!(
            callbacks
                .content
                .contains("    readonly \"{$request.body#/url}\": {\n")
        );
    }

    #[test]
    fn webhook_and_callback_files_skipped_when_file_name_invalid() {
        // A webhook operation whose operationId file-bases to a Windows reserved device gets no
        // file, so it is dropped from the descriptor map (leaving the webhook an empty object) and
        // its callback is likewise fileless — exercising the file-base `None` skip on both paths.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "petCreated": {
                    "post": {
                        "operationId": "CON",
                        "responses": { "200": { "description": "ok" } },
                        "callbacks": {
                            "ack": {
                                "{$request.body#/ackUrl}": {
                                    "post": {
                                        "operationId": "AUX",
                                        "responses": { "204": { "description": "acked" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        // The invalid file names are reported (OASTS1301), not silently absorbed.
        assert!(diagnostics.iter().any(|d| d.code == CODE_FILE_NAME));
        // No per-operation webhook file, and the webhook is an empty object in the map.
        assert!(!files.iter().any(|file| {
            file.relative_path.starts_with("types/webhooks/")
                && file.relative_path != "types/webhooks/index.ts"
        }));
        let webhooks = find_file(&files, "types/webhooks/index.ts");
        assert!(webhooks.content.contains("petCreated: {};"));
        // The fileless callback produces no callbacks index at all.
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("types/callbacks/"))
        );
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

/// Whether a component needs a Request variant (some reachable node — including the schema's own
/// root — carries `readOnly`, dropped in request position) and/or a Response variant (same for
/// `writeOnly`, dropped in response position). The traversal mirrors the position-aware renderer
/// exactly: it descends every inline structure the renderer inlines — nested objects,
/// `additionalProperties`, array items, tuple members, and `allOf`/`anyOf`/`oneOf` branches — so the
/// decision agrees with what the renderer produces. A mismatch would emit a dead export or a
/// dangling import.
///
/// A `$ref` is a graph edge, not crossed here: the referenced component renders as its own named
/// (possibly variant) type, and variance flows across refs in a separate propagation pass. Stack-only
/// with no heap allocation, so a marker-free component returns `(false, false)` doing zero
/// allocation, exactly as the pre-recursion decision did.
fn shape_variants(schema: &SchemaNode) -> (bool, bool) {
    let mut acc = (false, false);
    accumulate_shape_variants(schema, &mut acc);
    acc
}

fn accumulate_shape_variants(schema: &SchemaNode, acc: &mut (bool, bool)) {
    if acc.0 && acc.1 {
        return;
    }
    acc.0 |= schema.meta().read_only;
    acc.1 |= schema.meta().write_only;
    match schema {
        SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } => {
            for (_, property, meta) in properties {
                acc.0 |= meta.read_only;
                acc.1 |= meta.write_only;
                accumulate_shape_variants(property, acc);
                if acc.0 && acc.1 {
                    return;
                }
            }
            if let AdditionalProperties::Allowed(Some(schema))
            | AdditionalProperties::Schema(schema) = additional_properties
            {
                accumulate_shape_variants(schema, acc);
            }
        }
        SchemaNode::Array { items, .. } => accumulate_shape_variants(items, acc),
        SchemaNode::Tuple {
            prefix_items, rest, ..
        } => {
            for item in prefix_items {
                accumulate_shape_variants(item, acc);
                if acc.0 && acc.1 {
                    return;
                }
            }
            if let TupleRest::Schema(schema) = rest {
                accumulate_shape_variants(schema, acc);
            }
        }
        SchemaNode::AllOf { branches, .. }
        | SchemaNode::AnyOf { branches, .. }
        | SchemaNode::OneOf { branches, .. } => {
            for branch in branches {
                accumulate_shape_variants(branch, acc);
                if acc.0 && acc.1 {
                    return;
                }
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

/// The exported-name fragment identifying one media entry, mangled from its canonical full media
/// string: `*` becomes `Wildcard`, every other non-alphanumeric ASCII byte is a token separator,
/// and each token is uppercase-first and concatenated (`application/vnd.api+json` →
/// `ApplicationVndApiJson`). Total by construction — it never invents a disambiguating suffix, so a
/// collision between two distinct media strings is a diagnostic rather than a silent rename.
pub(super) fn media_tag(media: &str) -> String {
    let mut tag = String::with_capacity(media.len());
    let mut fresh = true;
    for byte in media.chars() {
        if byte == '*' {
            tag.push_str("Wildcard");
            fresh = true;
        } else if byte.is_ascii_alphanumeric() {
            if fresh {
                tag.extend(byte.to_uppercase());
            } else {
                tag.push(byte);
            }
            fresh = false;
        } else {
            fresh = true;
        }
    }
    tag
}

pub(super) fn source_diagnostic(
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
