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
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use rayon::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::client_model::{BodyPlan, BodyPlanArm, ClientModel, FormFieldPlan};
#[cfg(test)]
use crate::composition::{CODE_COMPOSITION, CODE_CONFLICTING_PROPERTY};
use crate::composition::{finite_values, json_equal};
use crate::config::{
    DateRepresentation, DateTimeRepresentation, DiscriminatedUnions, DocumentationConfig,
    EnumRepresentation, FileCase, ResolvedConfig, TypesConfig,
};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, Body, Discriminator, Ir, MediaType, Operation, Param, ParamLocation,
    PatternProperty, PatternPropertyKey, PrimitiveType, PropMeta, ResponseEntry, ResponseHeader,
    ResponseStatus, SchemaDocs, SchemaNode, SourceRef, TupleRest, finite_parts, mapping_schema_ref,
};
use crate::media::{is_json, is_xml};
use crate::num::{first_number_outside_binary64, render_number_value};
use crate::response_media::{StreamKind, media_carries_json_value, media_stream_kind};
use crate::semantic::{
    AllocatedCallbackName, AllocatedSchemaName, Analyzed, CallbackParent, EnumMember, ResolvedLink,
    TargetCase, normalize_identifier,
};

mod client;
mod model;
mod msw;
mod paths;
pub(crate) mod runtime_assets;
mod tanstack;
mod transform;
mod validators;
mod zod;

use model::{EmissionModel, SchemaTarget};

const CODE_FILE_NAME: &str = "OASTS4001";
const CODE_PATH_COLLISION: &str = "OASTS4002";
const CODE_VARIANT_COLLISION: &str = "OASTS4101";
/// A component import an operation module renames to escape shadowing one of its own declarations,
/// whose role-derived replacement is itself taken by another import or declaration in that module.
/// Nothing is left to rename it to, so the module is refused rather than emitted uncompilable.
const CODE_IMPORT_ALIAS: &str = "OASTS4102";
/// A generated request/response variant whose colliding-name replacement is itself a declared
/// component or another variant's replacement. No local remedy exists, so the document is refused
/// rather than emitted with two declarations fighting over one identifier.
const CODE_VARIANT_ALIAS: &str = "OASTS4103";
/// A wire twin whose derived `{Name}Wire` is already a declared component's name. The document owns
/// its name; the compiler invented the other, so the twin yields to `{Name}WireValue` and generation
/// continues — the same rule OASTS4101 applies to a colliding request/response variant.
const CODE_WIRE_ALIAS: &str = "OASTS4104";
/// The residual: `{Name}WireValue` is itself declared. Nothing compiler-invented remains, so the
/// document is refused rather than emitted with two declarations fighting over one identifier.
const CODE_WIRE_COLLISION: &str = "OASTS4105";
const CODE_DISCRIMINATOR: &str = "OASTS4202";
const CODE_UNALLOCATED_REFERENCE: &str = "OASTS4203";
/// A discriminator `mapping` value that resolves to no allocated component schema. A mapping target
/// can only ever matter when it equals a branch's `$ref` target, and those are always materialized,
/// so a value that fails to resolve could never have matched a branch: it is a dead entry, not a
/// broken document. It drops out of tag resolution and proof falls back to the branch's own
/// `const`/`enum` or component name.
const CODE_MAPPING_TARGET: &str = "OASTS4204";
/// A discriminator whose `mapping`/`const` proof is internally incoherent — a mapping tag that
/// contradicts the branch's own fixed value, or an allOf idiom that fixes the tag property to an
/// empty (uninhabitable) value set. The render degrades to a plain structural union.
const CODE_DISCRIMINATOR_PROOF: &str = "OASTS4205";
/// A discriminator whose proof can select branches but whose emitted TypeScript union does not
/// carry required unit-literal tags on every branch, so consumers cannot narrow it exhaustively.
const CODE_DISCRIMINATOR_NARROWING: &str = "OASTS4207";
/// A union whose branches convert date/time values differently, where no JSON value kind and no
/// declared discriminator tells them apart. Applying either branch's conversion to the other's value
/// would corrupt it silently, and ordered try-each-branch decoding cannot detect the mistake — a
/// non-converting branch always succeeds by identity — so the document is refused instead.
const CODE_TRANSFORM_UNION: &str = "OASTS4301";
/// A position that reaches a transform the client pipeline cannot carry: a form or multipart field,
/// a content-type-discriminated request body, or a per-media-entry response payload. Each declares
/// a shape no single codec is keyed on, and emitting nothing for one would leave a wire string
/// behind a type promising an application value.
pub(super) const CODE_UNCONVERTIBLE_TRANSFORM: &str = "OASTS4302";

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
/// properties are shared via `Arc` so workers read one immutable prewarmed result,
/// and are borrowed at the model lifetime because the IR outlives the emitter.
type CachedAllOf<'a> = Option<(Arc<[BorrowedProperty<'a>]>, &'a AdditionalProperties)>;

struct ObjectShape<'a> {
    properties: &'a [(String, SchemaNode, PropMeta)],
    additional_properties: &'a AdditionalProperties,
}

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
    // The only mutation replaces one ASCII byte with another, preserving the input's UTF-8.
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

/// Whether `body` mentions `name` as a whole identifier in code rather than in a message.
///
/// Whole-identifier because `evaluatedItem` is a prefix of `evaluatedItems0` and
/// `recordBranchPropertyissues2` of `…issues20`. Quoted text is skipped because emitted validators
/// carry issue messages — `issue(path, "value not allowed")` names `value` without reading it.
/// Template literals are scanned through: their interpolations hold real reads, and the worst a
/// word in the literal text can do is keep a parameter's plain name, which the gate then reports.
///
/// A match preceded by `.` is a member access, not a read of the binding: emitted conversions write
/// `value.at`, so a schema property named after a hoisted constant would otherwise make that
/// constant look read and re-emit it unused.
///
/// Both mistakes fail loudly rather than silently: a missed read emits `_name` while the body says
/// `name` (TS2304), and a phantom read emits `name` unread (TS6133). The consumer flag matrix in
/// `scripts/verify-ts.sh` is what catches either.
pub(crate) fn reads_identifier(body: &str, name: &str) -> bool {
    let boundary = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$';
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' || byte == b'\'' {
            index += 1;
            while index < bytes.len() && bytes[index] != byte {
                index += if bytes[index] == b'\\' { 2 } else { 1 };
            }
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(name.as_bytes()) {
            let end = index + name.len();
            let preceding = index.checked_sub(1).map(|before| bytes[before]);
            let before_ok = preceding.is_none_or(|byte| !boundary(byte) && byte != b'.');
            let after_ok = end == bytes.len() || !boundary(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
        }
        index += 1;
    }
    false
}

pub(crate) fn is_reserved_device(value: &str) -> bool {
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
    validate_emission_model(&mut model);
    emit_types_from_model(&mut model)
}

pub(crate) fn emit_types_from_model(model: &mut EmissionModel<'_, '_>) -> Vec<GeneratedFile> {
    let _client_artifact_emitter = client::emit_client_from_model;
    let _runtime_asset_emitter = runtime_assets::emit_runtime_files;
    let (files, diagnostics) = Emitter::new(model).emit();
    model.sink.extend(diagnostics);
    files
}

fn validate_emission_model(model: &mut EmissionModel<'_, '_>) {
    let diagnostics = Emitter::new(model).validate_model();
    model.sink.extend(diagnostics);
}

/// Emits every enabled artifact (types, client, validators, zod, msw) for one compile.
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
    // The consumer's own compiler options, read once per run. This is the single point at which
    // anything outside version, config and input reaches emitted bytes, so it is resolved here
    // rather than deep in an emitter — and it fails safe: anything unreadable answers "not
    // provided", which keeps the reference directive.
    let (consumer_provides_temporal, tsconfig_diagnostics) =
        crate::tsconfig::consumer_provides_temporal(&config.output, &config.tsconfig);
    sink.extend(tsconfig_diagnostics);
    let mut model = EmissionModel::new(analyzed, config, source_digest(source_tuples), sink);
    model.consumer_provides_temporal = consumer_provides_temporal;
    validate_emission_model(&mut model);
    let mut files = if config.artifacts.types.enabled {
        emit_types_from_model(&mut model)
    } else {
        Vec::new()
    };
    if let Some(client_model) = client_model {
        files.extend(client::emit_client_from_model(&mut model, client_model));
        // The transform artifact lives under the client's tree and only ever runs at the client's
        // pipeline positions, so it is emitted with the client and never without it.
        files.extend(transform::emit_transform_from_model(
            &mut model,
            client_model,
        ));
        // Descriptors wrap the client's own `orThrow` surface and propagate its `CallArgs<S>`, so
        // the tanstack artifact is emitted with the client and never without it — the config layer
        // already refuses the combination, and this placement makes that structural.
        if config.artifacts.tanstack.enabled {
            files.extend(tanstack::emit_tanstack_from_model(&mut model, client_model));
        }
    }
    if config.artifacts.validators.enabled {
        files.extend(validators::emit_validators_from_model(&mut model));
    }
    if config.artifacts.zod.enabled {
        files.extend(zod::emit_zod_from_model(&mut model));
    }
    if config.artifacts.msw.enabled {
        files.extend(msw::emit_msw_from_model(&mut model));
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

/// Which of a schema's two type surfaces is being rendered.
///
/// They differ only where a date/time transform reaches: the application surface names `Date` or a
/// `Temporal` type there, the wire surface names `string`. Everywhere else — and everywhere at all
/// under the `string` default — the two are the same declaration and only one is emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TypeAxis {
    Application,
    Wire,
}

/// What a conjunction proves about a discriminator property: the literals it fixes the property to,
/// and whether any constituent requires it.
///
/// The two travel together because they come from one walk, but they merge differently — an `allOf`
/// *intersects* the values its constituents fix and *unions* the ones that require the property. The
/// base-plus-subtype spelling is exactly that split: the base requires the tag as a plain string and
/// the subtype fixes its literal without repeating `required`.
#[derive(Default)]
struct TagFacts {
    values: Option<Vec<Value>>,
    required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectedTagType {
    String,
    Number,
    Integer,
    Boolean,
    Null,
    Incompatible,
}

impl TypePosition {
    /// A stable slot for per-position state, so one array replaces one field per position.
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Neutral => 0,
            Self::Request => 1,
            Self::Response => 2,
        }
    }
}

#[derive(Clone, Copy)]
enum SchemaChildMode {
    Validation,
    References(TypePosition),
}

pub(super) struct Emitter<'model, 'input, 'sink> {
    model: &'model EmissionModel<'input, 'sink>,
    enum_member_indices: Arc<BTreeMap<(String, String), usize>>,
    /// Resolved link indices (into `model.analyzed.link_targets`), grouped by the response
    /// they were declared on and keyed the same way as `enum_member_indices`. Built only when
    /// the document has at least one link — the fast-reject keeps a link-free document's
    /// emission allocation-identical to before links existed. Each group stays in
    /// `link_targets` order (insertion order, one linear pass), matching the ticket's
    /// deterministic-order requirement without a separate sort.
    link_targets_by_response: Arc<BTreeMap<(String, String), Vec<usize>>>,
    /// `operation_index -> Stem` for every allocated operation name, the same transform
    /// `emit_operation` applies to its own `stem`. Populated alongside
    /// `link_targets_by_response` (same fast-reject) so a resolved link's target response type
    /// name can be looked up in O(1) instead of scanning `operation_names` per link.
    operation_stems: Arc<HashMap<usize, String>>,
    /// Prewarmed `allOf` merges keyed by `(branch slice address, length)`. Populated
    /// once per distinct IR node by `prewarm_all_of`, then read on every render/import
    /// pass so the merge runs once instead of up to six times per node. Only IR-resident
    /// non-empty slices are keyed here (their address is stable for the emission);
    /// locally built branches miss and recompute, and no live non-empty IR slice can
    /// share a local's address. Empty slices all share the dangling-pointer sentinel, so
    /// `cache_merge_all_of` refuses to insert them.
    merge_cache: Arc<HashMap<(usize, usize), CachedAllOf<'input>>>,
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

struct EmitterFactory<'model, 'input, 'sink> {
    model: &'model EmissionModel<'input, 'sink>,
    enum_member_indices: Arc<BTreeMap<(String, String), usize>>,
    link_targets_by_response: Arc<BTreeMap<(String, String), Vec<usize>>>,
    operation_stems: Arc<HashMap<usize, String>>,
    merge_cache: Arc<HashMap<(usize, usize), CachedAllOf<'input>>>,
}

struct EmittedOperation {
    file: GeneratedFile,
    diagnostics: Vec<Diagnostic>,
    has_response_headers: bool,
    names_sse_event: bool,
}

/// Whether this operation's rendered types name `SseEvent` — that is, whether any response declares
/// an SSE branch. The request side never does: a streaming request body renders as bytes.
fn operation_names_sse_event(operation: &Operation) -> bool {
    operation.responses.iter().any(|response| {
        response.media_types.iter().any(|media| {
            media_stream_kind(&media.essence, media.streaming_marked) == Some(StreamKind::Sse)
        })
    })
}

fn append_operation_emissions(
    files: &mut Vec<GeneratedFile>,
    diagnostics: &mut Vec<Diagnostic>,
    any_response_headers: &mut bool,
    any_sse_event: &mut bool,
    emissions: Vec<EmittedOperation>,
) {
    for emission in emissions {
        *any_response_headers |= emission.has_response_headers;
        *any_sse_event |= emission.names_sse_event;
        diagnostics.extend(emission.diagnostics);
        files.push(emission.file);
    }
}

impl<'model, 'input, 'sink> EmitterFactory<'model, 'input, 'sink> {
    fn worker(&self) -> Emitter<'model, 'input, 'sink> {
        Emitter {
            model: self.model,
            enum_member_indices: Arc::clone(&self.enum_member_indices),
            link_targets_by_response: Arc::clone(&self.link_targets_by_response),
            operation_stems: Arc::clone(&self.operation_stems),
            merge_cache: Arc::clone(&self.merge_cache),
            import_aliases: RefCell::new(HashMap::new()),
            deferred_diagnostics: RefCell::new(Vec::new()),
        }
    }
}

impl<'model, 'input, 'sink> Emitter<'model, 'input, 'sink> {
    pub(super) fn new(model: &'model EmissionModel<'input, 'sink>) -> Self {
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
            enum_member_indices: Arc::new(enum_member_indices),
            link_targets_by_response: Arc::new(link_targets_by_response),
            operation_stems: Arc::new(operation_stems),
            merge_cache: Arc::new(HashMap::new()),
            import_aliases: RefCell::new(HashMap::new()),
            deferred_diagnostics: RefCell::new(Vec::new()),
        }
    }

    fn emit(mut self) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let mut diagnostics = Vec::new();
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
        let factory = self.into_factory();
        let mut files = factory
            .model
            .analyzed
            .schema_names
            .par_iter()
            .filter(|allocated| factory.model.component_files[allocated.schema_index].is_some())
            .map_init(
                || factory.worker(),
                |worker, allocated| worker.emit_component(allocated),
            )
            .collect::<Vec<_>>();
        let mut any_response_headers = false;
        let mut any_sse_event = false;
        let operations = factory
            .model
            .analyzed
            .operation_names
            .par_iter()
            .map_init(
                || factory.worker(),
                |worker, allocated| {
                    let file_base =
                        factory.model.operation_files[allocated.operation_index].as_deref()?;
                    let operation =
                        &factory.model.analyzed.ir.operations[allocated.operation_index];
                    Some(worker.emit_operation(operation, &allocated.name, "operations", file_base))
                },
            )
            .filter_map(|emission| emission)
            .collect::<Vec<_>>();
        append_operation_emissions(
            &mut files,
            &mut diagnostics,
            &mut any_response_headers,
            &mut any_sse_event,
            operations,
        );
        // Webhook and callback operations reuse the operation renderer verbatim; their response
        // headers count toward the shared `types/headers.ts` helper just like a path operation's.
        let webhooks = (0..factory.model.analyzed.webhook_names.len())
            .into_par_iter()
            .map_init(
                || factory.worker(),
                |worker, index| {
                    let file_base = factory.model.webhook_files[index].as_deref()?;
                    let allocated = &factory.model.analyzed.webhook_names[index];
                    let operation = &factory.model.analyzed.ir.webhooks[allocated.webhook_index]
                        .operations[allocated.operation_index];
                    Some(worker.emit_operation(operation, &allocated.stem, "webhooks", file_base))
                },
            )
            .filter_map(|emission| emission)
            .collect::<Vec<_>>();
        append_operation_emissions(
            &mut files,
            &mut diagnostics,
            &mut any_response_headers,
            &mut any_sse_event,
            webhooks,
        );
        // A document with any webhook gets the `Webhooks` descriptor, including a webhook whose
        // path item declares no operations (it appears in the map with an empty object type).
        if !factory.model.analyzed.ir.webhooks.is_empty() {
            files.push(factory.worker().emit_webhooks_index());
        }
        let callbacks = (0..factory.model.analyzed.callback_names.len())
            .into_par_iter()
            .map_init(
                || factory.worker(),
                |worker, index| {
                    let file_base = factory.model.callback_files[index].as_deref()?;
                    let allocated = &factory.model.analyzed.callback_names[index];
                    let operation = callback_operation(
                        &factory.model.analyzed.ir,
                        &factory.model.analyzed.callback_names,
                        allocated,
                    );
                    Some(worker.emit_operation(operation, &allocated.stem, "callbacks", file_base))
                },
            )
            .filter_map(|emission| emission)
            .collect::<Vec<_>>();
        append_operation_emissions(
            &mut files,
            &mut diagnostics,
            &mut any_response_headers,
            &mut any_sse_event,
            callbacks,
        );
        if factory.model.callback_files.iter().any(Option::is_some) {
            files.push(factory.worker().emit_callbacks_index());
        }
        if any_response_headers {
            files.push(factory.worker().emit_headers_helper_file());
        }
        if any_sse_event {
            files.push(factory.worker().emit_stream_helper_file());
        }
        files.sort_unstable_by(|left, right| left.relative_path.cmp(&right.relative_path));
        (files, diagnostics)
    }

    fn into_factory(self) -> EmitterFactory<'model, 'input, 'sink> {
        EmitterFactory {
            model: self.model,
            enum_member_indices: self.enum_member_indices,
            link_targets_by_response: self.link_targets_by_response,
            operation_stems: self.operation_stems,
            merge_cache: self.merge_cache,
        }
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
            relative_path: format!("{}/webhooks/index.ts", self.model.dirs.types),
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
            relative_path: format!("{}/callbacks/index.ts", self.model.dirs.types),
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

    /// Emits `SseEvent<TData>` once, only when some emitted response declares an SSE branch, on
    /// the same rule the header helper follows. It is a second declaration of the shape the client
    /// runtime already exports: this artifact ships without the client, so it cannot import from a
    /// runtime that may not be emitted, and the two are structurally identical and unify wherever
    /// both are present.
    fn emit_stream_helper_file(&self) -> GeneratedFile {
        let mut content = self.header();
        content.push_str("export type SseEvent<TData> = {\n");
        content.push_str("  data: TData;\n");
        content.push_str("  event?: string;\n");
        content.push_str("  id?: string;\n");
        content.push_str("  retry?: number;\n");
        content.push_str("};\n");
        GeneratedFile {
            relative_path: format!("{}/stream.ts", self.model.dirs.types),
            content,
        }
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
            relative_path: format!("{}/headers.ts", self.model.dirs.types),
            content,
        }
    }

    fn header(&self) -> String {
        self.model.header()
    }

    fn validate_model(&self) -> Vec<Diagnostic> {
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
        diagnostics
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
                        CODE_UNALLOCATED_REFERENCE,
                        format!(
                            "schema reference {}#{} has no allocated component type",
                            target.source_id, target.json_pointer
                        ),
                        &meta.source,
                    ));
                }
            }
            SchemaNode::OneOf {
                branches,
                discriminator: Some(discriminator),
                ..
            } => {
                self.validate_discriminated(
                    branches,
                    discriminator,
                    self.model.config.types.discriminated_unions == DiscriminatedUnions::Tagged,
                    diagnostics,
                );
            }
            SchemaNode::AnyOf {
                branches,
                discriminator: Some(discriminator),
                ..
            } => {
                self.validate_discriminated(branches, discriminator, false, diagnostics);
            }
            _ => {}
        }
        self.for_each_schema_child(schema, SchemaChildMode::Validation, &mut |child| {
            self.validate_schema(child, diagnostics);
        });
    }

    fn resolve_ref<'a>(
        &self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<&'a SchemaNode>
    where
        'input: 'a,
    {
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
        self.resolve_ref(resolved, visited)
    }

    fn object_shape<'a>(
        &self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<ObjectShape<'a>>
    where
        'input: 'a,
    {
        let schema = self.resolve_ref(schema, visited)?;
        let SchemaNode::Object {
            properties,
            additional_properties,
            meta,
            ..
        } = schema
        else {
            return None;
        };
        meta.validation_applicators()
            .pattern_properties
            .is_empty()
            .then_some(ObjectShape {
                properties,
                additional_properties,
            })
    }

    fn finite_constraint<'a>(
        &self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<Vec<Value>>
    where
        'input: 'a,
    {
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

    /// Diagnoses a discriminated `oneOf`/`anyOf`. Each branch must contribute a distinct tag value
    /// for the discriminator property; the tag is drawn — first non-empty wins — from the explicit
    /// `mapping`, the branch's own fixed `const`/`enum` seen through the `$ref`+allOf idiom, or the
    /// referenced component name. An unprovable union keeps its structural shape and gains one
    /// warning; a proven tagged `oneOf` may also reuse the tags to project its branch types.
    fn validate_discriminated(
        &self,
        branches: &[SchemaNode],
        discriminator: &Discriminator,
        tagged_projection: bool,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        let (mapping_targets, dangling) = self.mapping_targets(discriminator);
        for target in dangling {
            diagnostics.push(warning_diagnostic(
                CODE_MAPPING_TARGET,
                format!(
                    "discriminator mapping value '{target}' resolves to no component schema; the entry contributes no tag"
                ),
                &discriminator.source,
            ));
        }
        match self.prove_discriminator_tags(branches, discriminator, &mapping_targets) {
            Err((code, message)) => {
                diagnostics.push(warning_diagnostic(code, message, &discriminator.source));
            }
            Ok(tags) => {
                if let Some(message) = self.discriminator_narrowing_warning(
                    branches,
                    discriminator,
                    &mapping_targets,
                    &tags,
                    tagged_projection,
                ) {
                    diagnostics.push(warning_diagnostic(
                        CODE_DISCRIMINATOR_NARROWING,
                        message,
                        &discriminator.source,
                    ));
                }
            }
        }
    }

    fn discriminator_narrowing_warning(
        &self,
        branches: &[SchemaNode],
        discriminator: &Discriminator,
        mapping_targets: &[(&str, usize)],
        tags: &[Vec<String>],
        tagged_projection: bool,
    ) -> Option<String> {
        let property = discriminator.property_name.as_str();
        let facts = branches
            .iter()
            .map(|branch| self.merged_object_property_finite(branch, property, &mut HashSet::new()))
            .collect::<Vec<_>>();

        if facts.iter().any(|facts| {
            facts
                .values
                .as_deref()
                .is_some_and(|values| values.iter().any(Value::is_object))
        }) {
            return Some(format!(
                "discriminator property '{property}' uses object const tags, which render as object types rather than unit types and cannot make the emitted union exhaustive"
            ));
        }

        if self.discriminator_branches_fix_a_literal(branches, property) {
            return None;
        }

        if tagged_projection {
            for position in [
                TypePosition::Neutral,
                TypePosition::Request,
                TypePosition::Response,
            ] {
                if let Err(literal) = self
                    .projected_discriminator_values_by_branch(branches, property, position, tags)
                {
                    return Some(format!(
                        "discriminator tags for property '{property}' collapse to TypeScript literal {literal} after scalar projection, so the tagged union would not discriminate its branches; emitting a structural union"
                    ));
                }
            }
        }

        if facts.iter().any(|facts| {
            !facts.required
                && facts
                    .values
                    .as_deref()
                    .is_some_and(|values| !values.is_empty())
        }) {
            return Some(format!(
                "discriminator property '{property}' is optional in at least one branch, so a payload that omits it falls through every equality arm and prevents exhaustive narrowing"
            ));
        }

        let projects_in = |position: TypePosition| {
            branches.iter().zip(tags).all(|(branch, tags)| {
                self.discriminator_branches_fix_a_literal_in_position(
                    std::slice::from_ref(branch),
                    property,
                    position,
                ) || self
                    .projected_discriminator_values(branch, property, position, tags)
                    .is_some()
            })
        };
        let neutral = projects_in(TypePosition::Neutral);

        if tagged_projection
            && neutral
            && [TypePosition::Request, TypePosition::Response]
                .into_iter()
                .all(&projects_in)
        {
            return None;
        }

        if tagged_projection
            && [
                TypePosition::Neutral,
                TypePosition::Request,
                TypePosition::Response,
            ]
            .into_iter()
            .any(|position| {
                branches.iter().zip(tags).any(|(branch, tags)| {
                    self.branch_accepts_discriminator_projection(branch, property, position)
                        && self
                            .projected_discriminator_values(branch, property, position, tags)
                            .is_none()
                })
            })
        {
            return Some(format!(
                "discriminator property '{property}' uses a tag whose JSON kind does not match the branch's declared scalar type, so that branch is emitted without tagged projection"
            ));
        }

        // A directional variant can fail to project for a reason the neutral declaration does not
        // share: a `readOnly` discriminator is absent from the request shape and a `writeOnly` one
        // from the response shape, so that variant has no property to carry the tag. The union
        // still narrows everywhere the property exists, which is why the messages below — which
        // say the union cannot narrow — would be false here.
        if tagged_projection && neutral {
            let directional = [
                (TypePosition::Request, "request"),
                (TypePosition::Response, "response"),
            ]
            .into_iter()
            .filter(|&(position, _)| !projects_in(position))
            .map(|(_, name)| name)
            .collect::<Vec<_>>()
            .join(" and ");
            return Some(format!(
                "discriminator property '{property}' is absent from the {directional} shape, so that variant is emitted without tagged projection while the neutral declaration still narrows"
            ));
        }

        let uses_mapping = branches.iter().any(|branch| {
            let branch_index = self.branch_target_index(branch);
            mapping_targets
                .iter()
                .any(|(_, index)| branch_index == Some(*index))
        });
        if uses_mapping {
            Some(format!(
                "discriminator property '{property}' uses mapping literals that the structural branch types do not declare, so the emitted union cannot narrow on those tags"
            ))
        } else {
            Some(format!(
                "discriminator property '{property}' uses implicit component-name tags that the document does not declare on the wire, so the emitted union cannot narrow on those tags"
            ))
        }
    }

    /// Resolves every `mapping` value once, splitting the resolvable `(tag, component index)` pairs
    /// from the values that designate no allocated schema. The mapping never shapes the emitted
    /// union, so a stale pointer degrades proof, not output — the caller decides whether to warn.
    fn mapping_targets<'a>(
        &self,
        discriminator: &'a Discriminator,
    ) -> (Vec<(&'a str, usize)>, Vec<&'a str>) {
        let mut resolved: Vec<(&'a str, usize)> = Vec::new();
        let mut dangling: Vec<&'a str> = Vec::new();
        for (tag, target) in &discriminator.mapping {
            match self.resolve_mapping_target(discriminator, target) {
                Some(index) => resolved.push((tag.as_str(), index)),
                None => dangling.push(target.as_str()),
            }
        }
        (resolved, dangling)
    }

    /// The literal tags each branch proves for the discriminator property, in branch order, or the
    /// `(code, message)` of the one proof failure that stops the union from dispatching.
    ///
    /// This is the sole producer of discriminator tag semantics. `validate_discriminated` reads it
    /// for its diagnostic; the transform emitter reads it to decide whether a union can dispatch a
    /// per-branch transform on the tag property (`emit::transform`). Neither re-derives it, so the
    /// two can never disagree about what a document's discriminator proves.
    fn prove_discriminator_tags(
        &self,
        branches: &[SchemaNode],
        discriminator: &Discriminator,
        mapping_targets: &[(&str, usize)],
    ) -> Result<Vec<Vec<String>>, (&'static str, String)> {
        let prop = discriminator.property_name.as_str();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut proven: Vec<Vec<String>> = Vec::with_capacity(branches.len());
        for branch in branches {
            if matches!(
                self.resolve_ref(branch, &mut HashSet::new()),
                Some(SchemaNode::Never { .. })
            ) {
                // An empty branch contributes no possible discriminator literal. Preserve its
                // position for transform dispatch, whose empty tag set naturally emits no arm.
                proven.push(Vec::new());
                continue;
            }
            let branch_index = self.branch_target_index(branch);
            let mapping_tags: Vec<&str> = mapping_targets
                .iter()
                .filter(|(_, index)| branch_index == Some(*index))
                .map(|(tag, _)| *tag)
                .collect();
            let const_proof = self
                .merged_object_property_finite(branch, prop, &mut HashSet::new())
                .values;

            // An allOf idiom that fixes the tag property to disjoint values proves an uninhabitable
            // branch: no wire value selects it, so the union cannot dispatch. Warn and fall back.
            if const_proof.as_deref().is_some_and(<[Value]>::is_empty) {
                return Err((
                    CODE_DISCRIMINATOR_PROOF,
                    format!(
                        "discriminator branch fixes '{prop}' to no inhabitable value; emitting a structural union"
                    ),
                ));
            }

            let effective: Vec<String> = if !mapping_tags.is_empty() {
                // A mapping tag that disagrees with the branch's own single fixed value is
                // incoherent: the wire value the mapping routes here would fail the branch's const.
                if let Some([value]) = const_proof.as_deref()
                    && let Some(conflict) = mapping_tags.iter().find(|tag| **tag != tag_key(value))
                {
                    return Err((
                        CODE_DISCRIMINATOR_PROOF,
                        format!(
                            "discriminator maps '{conflict}' to a branch whose '{prop}' is fixed to {}; emitting a structural union",
                            render_json_compact(value, ObjectKeyMode::Plain)
                        ),
                    ));
                }
                mapping_tags.iter().map(|tag| (*tag).to_owned()).collect()
            } else if let Some(values) = const_proof.as_deref().filter(|values| !values.is_empty())
            {
                values.iter().map(tag_key).collect()
            } else {
                self.implicit_tag(branch).into_iter().collect()
            };

            if effective.is_empty() {
                return Err((
                    CODE_DISCRIMINATOR,
                    format!(
                        "emitting a structural union because a branch does not prove one literal for discriminator property '{prop}'"
                    ),
                ));
            }
            for tag in &effective {
                if !seen.insert(tag.clone()) {
                    return Err((
                        CODE_DISCRIMINATOR,
                        format!(
                            "emitting a structural union because discriminator property '{prop}' repeats literal {tag}"
                        ),
                    ));
                }
            }
            proven.push(effective);
        }
        Ok(proven)
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
        // One resolution rule, shared with the reachability walk that decides whether a mapping
        // target survives pruning — the two must never disagree about what a mapping value names.
        let reference = mapping_schema_ref(&discriminator.source, target);
        self.model
            .schema_target(&reference.source_id, &reference.json_pointer)
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
    /// Whether every branch fixes the discriminator property to at least one literal in its **own**
    /// declared type.
    ///
    /// `prove_discriminator_tags` also accepts a branch whose only proof is a mapping entry. That is
    /// enough to *choose* a codec, because the mapping says which branch a wire value routes to. It
    /// is not enough to *emit* the choice: the emitted dispatch narrows with
    /// `value.<property> === "<tag>"`, and TypeScript narrows on that only where the branch's type
    /// declares the literal. Under a mapping-only proof every arm still declares `<property>` as
    /// `string`, and the emitted ternary compiles to a type error rather than a dispatch.
    /// A branch also has to *require* the property. TypeScript does narrow an optional literal on an
    /// equality check, but a payload that omits the tag falls through every arm, so the dispatch is
    /// not exhaustive and its fallback cannot be `never`.
    pub(super) fn discriminator_branches_fix_a_literal(
        &self,
        branches: &[SchemaNode],
        property: &str,
    ) -> bool {
        self.discriminator_branches_fix_a_literal_in_position(
            branches,
            property,
            TypePosition::Neutral,
        )
    }

    fn discriminator_branches_fix_a_literal_in_position(
        &self,
        branches: &[SchemaNode],
        property: &str,
        position: TypePosition,
    ) -> bool {
        branches.iter().all(|branch| {
            matches!(
                self.resolve_ref(branch, &mut HashSet::new()),
                Some(SchemaNode::Never { .. })
            ) || {
                let facts = self.merged_object_property_finite_in_position(
                    branch,
                    property,
                    position,
                    &mut HashSet::new(),
                );
                facts.required && facts.values.is_some_and(|values| !values.is_empty())
            }
        })
    }

    fn discriminator_projection_tags(
        &self,
        branches: &[SchemaNode],
        discriminator: &Discriminator,
    ) -> Option<Vec<Vec<String>>> {
        if self.model.config.types.discriminated_unions != DiscriminatedUnions::Tagged
            || self.discriminator_branches_fix_a_literal(branches, &discriminator.property_name)
        {
            return None;
        }
        let (mapping_targets, _dangling) = self.mapping_targets(discriminator);
        self.prove_discriminator_tags(branches, discriminator, &mapping_targets)
            .ok()
    }

    fn branch_accepts_discriminator_projection(
        &self,
        branch: &SchemaNode,
        property: &str,
        position: TypePosition,
    ) -> bool {
        let facts = self.merged_object_property_finite_in_position(
            branch,
            property,
            position,
            &mut HashSet::new(),
        );
        facts.required && facts.values.is_none()
    }

    fn projected_discriminator_values(
        &self,
        branch: &SchemaNode,
        property: &str,
        position: TypePosition,
        tags: &[String],
    ) -> Option<Vec<Value>> {
        if !self.branch_accepts_discriminator_projection(branch, property, position) {
            return None;
        }
        let tag_type =
            self.merged_object_property_tag_type(branch, property, position, &mut HashSet::new())?;
        tags.iter()
            .map(|tag| projected_tag_value(tag, tag_type))
            .collect()
    }

    fn projected_discriminator_values_by_branch(
        &self,
        branches: &[SchemaNode],
        property: &str,
        position: TypePosition,
        tags: &[Vec<String>],
    ) -> Result<Vec<Option<Vec<Value>>>, String> {
        debug_assert_eq!(branches.len(), tags.len());
        let mut owners = BTreeMap::<String, usize>::new();
        let mut projected = Vec::with_capacity(branches.len());
        for (index, (branch, tags)) in branches.iter().zip(tags).enumerate() {
            let fixed = self
                .merged_object_property_finite_in_position(
                    branch,
                    property,
                    position,
                    &mut HashSet::new(),
                )
                .values
                .filter(|values| !values.is_empty());
            let (values, emit_projection) = if let Some(values) = fixed {
                (values, false)
            } else {
                let Some(values) =
                    self.projected_discriminator_values(branch, property, position, tags)
                else {
                    projected.push(None);
                    continue;
                };
                (values, true)
            };
            let mut branch_literals = BTreeSet::new();
            let mut unique = Vec::with_capacity(values.len());
            for value in values {
                let literal = render_ts_value(&value);
                if !branch_literals.insert(literal.clone()) {
                    continue;
                }
                if owners.insert(literal.clone(), index).is_some() {
                    return Err(literal);
                }
                unique.push(value);
            }
            projected.push(emit_projection.then_some(unique));
        }
        Ok(projected)
    }

    fn merged_object_property_tag_type<'a>(
        &'a self,
        branch: &'a SchemaNode,
        property: &str,
        position: TypePosition,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<ProjectedTagType> {
        match branch {
            SchemaNode::Ref { target, .. } => {
                if !visited.insert((target.source_id.as_str(), target.json_pointer.as_str())) {
                    return None;
                }
                self.model
                    .schema_target(&target.source_id, &target.json_pointer)
                    .and_then(|target| self.model.analyzed.ir.schemas.get(target.index))
                    .and_then(|resolved| {
                        self.merged_object_property_tag_type(
                            &resolved.schema,
                            property,
                            position,
                            visited,
                        )
                    })
            }
            SchemaNode::Object { properties, .. } => properties
                .iter()
                .find(|(name, _, meta)| name == property && property_in_position(meta, position))
                .and_then(|(_, schema, _)| self.projected_tag_type(schema, &mut HashSet::new())),
            SchemaNode::AllOf { branches, .. } => branches
                .iter()
                .filter_map(|branch| {
                    self.merged_object_property_tag_type(
                        branch,
                        property,
                        position,
                        &mut visited.clone(),
                    )
                })
                .reduce(intersect_projected_tag_types),
            _ => None,
        }
    }

    fn projected_tag_type<'a>(
        &'a self,
        schema: &'a SchemaNode,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> Option<ProjectedTagType> {
        if schema.meta().nullable {
            return None;
        }
        match schema {
            SchemaNode::Ref { target, .. } => {
                if !visited.insert((target.source_id.as_str(), target.json_pointer.as_str())) {
                    return None;
                }
                self.model
                    .schema_target(&target.source_id, &target.json_pointer)
                    .and_then(|target| self.model.analyzed.ir.schemas.get(target.index))
                    .and_then(|resolved| self.projected_tag_type(&resolved.schema, visited))
            }
            SchemaNode::Primitive { ty, .. } => Some(match ty {
                PrimitiveType::String => ProjectedTagType::String,
                PrimitiveType::Number => ProjectedTagType::Number,
                PrimitiveType::Integer => ProjectedTagType::Integer,
                PrimitiveType::Boolean => ProjectedTagType::Boolean,
                PrimitiveType::Null => ProjectedTagType::Null,
            }),
            SchemaNode::AllOf { branches, .. } => branches
                .iter()
                .filter_map(|branch| self.projected_tag_type(branch, &mut visited.clone()))
                .reduce(intersect_projected_tag_types),
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                let mut types = branches
                    .iter()
                    .map(|branch| self.projected_tag_type(branch, &mut visited.clone()));
                let first = types.next()??;
                types
                    .all(|tag_type| tag_type == Some(first))
                    .then_some(first)
            }
            SchemaNode::Finite { .. }
            | SchemaNode::Object { .. }
            | SchemaNode::Array { .. }
            | SchemaNode::Tuple { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => None,
        }
    }

    fn merged_object_property_finite<'a>(
        &'a self,
        branch: &'a SchemaNode,
        prop: &str,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> TagFacts {
        self.merged_object_property_finite_in_position(branch, prop, TypePosition::Neutral, visited)
    }

    fn merged_object_property_finite_in_position<'a>(
        &'a self,
        branch: &'a SchemaNode,
        prop: &str,
        position: TypePosition,
        visited: &mut HashSet<(&'a str, &'a str)>,
    ) -> TagFacts {
        match branch {
            SchemaNode::Ref { target, .. } => {
                if !visited.insert((target.source_id.as_str(), target.json_pointer.as_str())) {
                    return TagFacts::default();
                }
                self.model
                    .schema_target(&target.source_id, &target.json_pointer)
                    .and_then(|target| self.model.analyzed.ir.schemas.get(target.index))
                    .map_or_else(TagFacts::default, |resolved| {
                        self.merged_object_property_finite_in_position(
                            &resolved.schema,
                            prop,
                            position,
                            visited,
                        )
                    })
            }
            // A primitive tag property fixes its value in `const`/`enum` (resolved through a
            // `$ref`); an object/array/tuple-typed one carries it in the `finite` box b9e3b24
            // added. Consult both so either spelling proves.
            SchemaNode::Object { properties, .. } => properties
                .iter()
                .find(|(name, _, meta)| name == prop && property_in_position(meta, position))
                .map_or_else(TagFacts::default, |(_, schema, meta)| TagFacts {
                    values: self
                        .finite_constraint(schema, &mut visited.clone())
                        .or_else(|| container_finite_values(schema)),
                    required: meta.required,
                }),
            SchemaNode::AllOf { branches, .. } => {
                let mut facts = TagFacts::default();
                for branch in branches {
                    let constituent = self.merged_object_property_finite_in_position(
                        branch,
                        prop,
                        position,
                        &mut visited.clone(),
                    );
                    facts.required |= constituent.required;
                    let Some(values) = constituent.values else {
                        continue;
                    };
                    match facts.values.as_mut() {
                        None => facts.values = Some(values),
                        Some(intersection) => intersection
                            .retain(|value| values.iter().any(|other| json_equal(value, other))),
                    }
                }
                facts
            }
            _ => TagFacts::default(),
        }
    }

    fn emit_component(&self, allocated: &AllocatedSchemaName) -> GeneratedFile {
        let schema = &self.model.analyzed.ir.schemas[allocated.schema_index];
        let file_base = self.model.component_files[allocated.schema_index]
            .as_deref()
            .unwrap_or_default();
        let mut content = self.header();
        let header_len = content.len();
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        self.collect_component_imports(
            &schema.schema,
            TypePosition::Neutral,
            TypeAxis::Application,
            allocated.schema_index,
            &mut imports,
        );
        // Path allocation registers the component file and its schema target in one pass.
        let target = self
            .model
            .schema_target(&schema.source.source_id, &schema.source.json_pointer)
            .expect("an allocated component file has a schema target");
        // The declarations read the same producer every reference site reads, so a variant this
        // component exports and a sibling's import of it can never spell the name differently.
        // `Some` is exactly "this position diverges", so it also gates the per-position imports.
        let request_variant = target.request_export();
        let response_variant = target.response_export();
        if request_variant.is_some() {
            self.collect_component_imports(
                &schema.schema,
                TypePosition::Request,
                TypeAxis::Application,
                allocated.schema_index,
                &mut imports,
            );
        }
        if response_variant.is_some() {
            self.collect_component_imports(
                &schema.schema,
                TypePosition::Response,
                TypeAxis::Application,
                allocated.schema_index,
                &mut imports,
            );
        }
        // A twin is emitted for exactly the positions that declare one, and each pulls the wire
        // names of the components it references.
        let wire_exports = [
            TypePosition::Neutral,
            TypePosition::Request,
            TypePosition::Response,
        ]
        .map(|position| target.wire_export(position));
        for (index, position) in [
            TypePosition::Neutral,
            TypePosition::Request,
            TypePosition::Response,
        ]
        .into_iter()
        .enumerate()
        {
            if wire_exports[index].is_some() {
                self.collect_component_imports(
                    &schema.schema,
                    position,
                    TypeAxis::Wire,
                    allocated.schema_index,
                    &mut imports,
                );
            }
        }
        let (aliases, alias_diagnostics) = assign_import_aliases(
            &BTreeSet::new(),
            &representation_globals(&self.model.config.types),
            &imports,
            &schema.source,
        );
        self.set_import_aliases(aliases);
        self.deferred_diagnostics
            .borrow_mut()
            .extend(alias_diagnostics);
        self.write_imports(&mut content, imports, "./");
        let neutral_variants = match (&request_variant, &response_variant) {
            (Some(request), Some(response)) => Some(NeutralSchemaVariants { request, response }),
            _ => None,
        };
        self.write_schema_declaration_with_docs(
            &mut content,
            &allocated.name,
            &schema.schema,
            TypePosition::Neutral,
            TypeAxis::Application,
            SchemaDeclarationContext {
                source: &schema.source,
                docs: SchemaDocView {
                    neutral_variants,
                    ..SchemaDocView::from(&schema.schema.meta().docs)
                },
            },
        );
        if let Some(export) = &request_variant {
            self.write_schema_declaration(
                &mut content,
                export,
                &schema.schema,
                TypePosition::Request,
                TypeAxis::Application,
                &schema.source,
            );
        }
        if let Some(export) = &response_variant {
            self.write_schema_declaration(
                &mut content,
                export,
                &schema.schema,
                TypePosition::Response,
                TypeAxis::Application,
                &schema.source,
            );
        }
        // Each twin sits directly after its application type: the declaration order stays
        // dependency-topological, and a reader sees the two surfaces of one schema together.
        for (index, position) in [
            TypePosition::Neutral,
            TypePosition::Request,
            TypePosition::Response,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(export) = &wire_exports[index] {
                self.write_schema_declaration(
                    &mut content,
                    export,
                    &schema.schema,
                    position,
                    TypeAxis::Wire,
                    &schema.source,
                );
            }
        }
        GeneratedFile {
            relative_path: format!("{}/components/{file_base}.ts", self.model.dirs.types),
            content: insert_temporal_reference(
                content,
                header_len,
                self.model.consumer_provides_temporal,
            ),
        }
    }

    pub(super) fn write_schema_declaration(
        &self,
        output: &mut String,
        name: &str,
        schema: &SchemaNode,
        position: TypePosition,
        axis: TypeAxis,
        source: &SourceRef,
    ) {
        self.write_schema_declaration_with_docs(
            output,
            name,
            schema,
            position,
            axis,
            SchemaDeclarationContext {
                source,
                docs: SchemaDocView::from(&schema.meta().docs),
            },
        );
    }

    fn write_schema_declaration_with_docs(
        &self,
        output: &mut String,
        name: &str,
        schema: &SchemaNode,
        position: TypePosition,
        axis: TypeAxis,
        context: SchemaDeclarationContext<'_>,
    ) {
        let SchemaDeclarationContext { source, docs } = context;
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
                docs,
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
                    write_schema_tsdoc(
                        output,
                        SchemaDocView {
                            description: Some(description),
                            ..SchemaDocView::default()
                        },
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
                docs,
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
            docs,
            DocKind::Schema,
            &self.model.config.documentation,
            0,
            false,
        );
        if let SchemaNode::Object {
            properties,
            additional_properties,
            meta,
            ..
        } = schema
            && !matches!(
                additional_properties,
                AdditionalProperties::Schema(_) | AdditionalProperties::Allowed(Some(_))
            )
            && properties
                .iter()
                .any(|(_, _, meta)| property_in_position(meta, position))
            && meta.validation_applicators().pattern_properties.is_empty()
            && !schema.is_nullable()
        {
            output.push_str("export interface ");
            output.push_str(name);
            output.push(' ');
            output.push_str(&self.render_interface_body(properties, position, axis, 0));
            output.push('\n');
        } else {
            output.push_str("export type ");
            output.push_str(name);
            output.push_str(" = ");
            output.push_str(&self.render_type(schema, position, axis, 0));
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
        axis: TypeAxis,
        indent: usize,
    ) -> String {
        let borrowed = borrow_properties(properties);
        self.render_object_parts(
            &borrowed,
            &AdditionalProperties::Forbidden,
            position,
            axis,
            indent,
            true,
        )
    }

    pub(super) fn render_type(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        axis: TypeAxis,
        indent: usize,
    ) -> String {
        // A transform site is the one place the two surfaces disagree: the application surface names
        // the runtime type, the wire surface keeps the `string` the JSON actually carries. The site
        // predicate already excludes a formatted string carrying an `enum`/`const`, so a literal
        // union stays the literal union it is.
        if let Some(kind) = self.model.transform_facts().site(schema) {
            if axis == TypeAxis::Application {
                return add_nullable(kind.ts_type().to_owned(), schema);
            }
            if kind == crate::transform::TransformKind::IntegerBigInt {
                return add_nullable(
                    "number | bigint | { readonly rawJSON: string }".to_owned(),
                    schema,
                );
            }
        }
        let rendered = match schema {
            SchemaNode::Ref { target, .. } => self
                .model
                .schema_target(&target.source_id, &target.json_pointer)
                .map_or_else(
                    || "unknown".to_owned(),
                    |target| {
                        let name = match axis {
                            // A referenced component that transforms has a twin of its own, and the
                            // wire surface names that twin; one that does not is identity in both
                            // surfaces and keeps its single name.
                            TypeAxis::Wire if target.transforms => target.wire_name(position),
                            TypeAxis::Application | TypeAxis::Wire => target.variant_name(position),
                        };
                        self.local_import_name(name)
                    },
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
                meta,
                ..
            } => {
                let borrowed = borrow_properties(properties);
                let literal = self.render_object_parts(
                    &borrowed,
                    additional_properties,
                    position,
                    axis,
                    indent,
                    false,
                );
                // An object with no property visible here renders as its own index signature,
                // which is the whole point of that spelling — but a pattern signature says the
                // same thing more precisely, so the base yields to it rather than intersecting.
                // Decided structurally, before rendering, so it does not depend on how an empty
                // object happens to be spelled.
                let literal_is_empty_object = !borrowed
                    .iter()
                    .any(|&(_, _, meta)| property_in_position(meta, position))
                    && matches!(
                        additional_properties,
                        AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden
                    );
                self.render_pattern_properties(
                    literal,
                    literal_is_empty_object,
                    &meta.validation_applicators().pattern_properties,
                    position,
                    axis,
                    indent,
                )
            }
            SchemaNode::Array { items, .. } => {
                let item = self.render_type(items, position, axis, indent);
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
                    .map(|item| self.render_type(item, position, axis, indent))
                    .collect::<Vec<_>>();
                match rest {
                    TupleRest::Allowed => items.push("...unknown[]".to_owned()),
                    TupleRest::Forbidden => {}
                    TupleRest::Schema(schema) => {
                        let rest = self.render_type(schema, position, axis, indent);
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
                // Identity first: a `$ref` branch renders as its own bare name, so it never
                // enters the merge. The anonymous branches merge among themselves into one
                // object literal that takes the position of the first of them, and the
                // members join with `&` in declaration order. Rendering a ref as a name is
                // also what terminates a recursive schema — the cycle that inlining used to
                // need a guard against cannot start.
                let has_named = branches.iter().any(is_named_branch);
                let merged =
                    self.merge_all_of_guarded(branches, |properties, additional_properties| {
                        let is_empty_object = !properties
                            .iter()
                            .any(|&(_, _, meta)| property_in_position(meta, position))
                            && matches!(
                                additional_properties,
                                AdditionalProperties::Allowed(None)
                                    | AdditionalProperties::Forbidden
                            );
                        (
                            self.render_object_parts(
                                properties,
                                additional_properties,
                                position,
                                axis,
                                indent,
                                false,
                            ),
                            is_empty_object,
                        )
                    });
                // An annotation- or validation-only sibling beside a `$ref` lowers to a branch
                // carrying just constraints, which renders `unknown` and disappears here — that
                // is what keeps `allOf: [$ref], minLength: 3` printing as the bare name. Only
                // `unknown` is dropped; an empty object beside a named branch is kept, and kept
                // as the bare `{}` an empty object used to render as everywhere.
                let anonymous_merged = merged.is_some();
                let mut pending_merge = merged;
                let mut members = Vec::with_capacity(branches.len());
                for branch in branches {
                    let from_merge = covered_by_merge(branch, anonymous_merged);
                    let (rendered, is_empty_object) = if from_merge {
                        // The merged blob stands in for the whole anonymous half, at the
                        // position of the first anonymous branch. Taking it is what emits it
                        // exactly once — every later anonymous branch is already inside it.
                        match pending_merge.take() {
                            Some(merged) => merged,
                            None => continue,
                        }
                    } else {
                        let is_empty_object =
                            if is_named_branch(branch) {
                                false
                            } else {
                                let mut visited = HashSet::new();
                                self.object_shape(branch, &mut visited)
                                    .is_some_and(|shape| {
                                        !shape.properties.iter().any(|(_, _, meta)| {
                                            property_in_position(meta, position)
                                        }) && matches!(
                                            shape.additional_properties,
                                            AdditionalProperties::Allowed(None)
                                                | AdditionalProperties::Forbidden
                                        )
                                    })
                            };
                        (
                            self.render_type(branch, position, axis, indent),
                            is_empty_object,
                        )
                    };
                    // Tested before parenthesizing, or a member needing parentheses would
                    // survive the drop as `(unknown)`.
                    if rendered == "unknown" {
                        continue;
                    }
                    // Beside a named branch an empty object keeps the bare `{}` it renders as
                    // nowhere else. `{}` is what narrows a nullable named branch — `(X | null) &
                    // {}` is `X` — and the named branch is what rejects the primitives a lone
                    // `{}` would admit, so the hole this commit closes cannot open here. The
                    // index signature would: the open one widens the named type, and the closed
                    // one makes its declared properties impossible. Decided structurally, before
                    // rendering, so it does not depend on how an empty object is spelled.
                    //
                    // The one case that reasoning does not cover is a conjunction every member of
                    // which admits null — a nullable empty object beside a nullable named branch.
                    // Null then satisfies the whole intersection, the validators and the zod
                    // schemas both accept it, and a bare `{}` is the only artifact claiming
                    // otherwise. Carrying the `| null` through lets TypeScript distribute to the
                    // same verdict: `(X | null) & ({} | null)` is `X | null`.
                    let substituted = has_named && is_empty_object;
                    let rendered = if substituted {
                        // Resolved rather than read off the branch node, because a `$ref` member
                        // carries its target's nullability, not its own. Computed here rather than
                        // per branch: an empty object beside a named branch is the rare shape.
                        let admits_null = branches.iter().all(|branch| {
                            let mut visited = HashSet::new();
                            self.resolve_ref(branch, &mut visited)
                                .is_some_and(SchemaNode::is_nullable)
                        });
                        // Parenthesized rather than left to precedence: with a third member in the
                        // intersection, a bare `A & B & {} | null` binds as `(A & B & {}) | null`
                        // and admits a null that A rejects.
                        if admits_null {
                            "({} | null)".to_owned()
                        } else {
                            "{}".to_owned()
                        }
                    } else {
                        rendered
                    };
                    // Neither substituted spelling needs the parenthesizer, and the merged blob
                    // never did.
                    let member = if from_merge || substituted {
                        rendered
                    } else {
                        parenthesize_intersection_member(rendered, branch)
                    };
                    // `A & A` is `A` spelled twice, and the merge used to fold a repeated
                    // branch away. Linear membership for the same reason the union arm below
                    // uses it: an intersection carries a handful of members, and a set would
                    // clone every rendered member to own its key.
                    if !members.contains(&member) {
                        members.push(member);
                    }
                }
                if members.is_empty() {
                    "unknown".to_owned()
                } else {
                    members.join(" & ")
                }
            }
            SchemaNode::OneOf {
                branches,
                discriminator,
                ..
            } => {
                if branches.is_empty() {
                    "never".to_owned()
                } else {
                    let projection_values = discriminator.as_deref().and_then(|discriminator| {
                        self.discriminator_projection_tags(branches, discriminator)
                            .and_then(|tags| {
                                self.projected_discriminator_values_by_branch(
                                    branches,
                                    &discriminator.property_name,
                                    position,
                                    &tags,
                                )
                                .ok()
                            })
                            .map(|values| (discriminator.property_name.as_str(), values))
                    });
                    // Linear membership rather than a hash set: a union carries a handful of
                    // branches, and a set would clone every rendered branch to own its key.
                    let mut rendered_branches = Vec::with_capacity(branches.len());
                    for (index, branch) in branches.iter().enumerate() {
                        let mut rendered = self.render_type(branch, position, axis, indent);
                        if let Some((property, values)) = &projection_values
                            && let Some(values) = values
                                .get(index)
                                .and_then(Option::as_deref)
                                .filter(|values| !values.is_empty())
                        {
                            let member = parenthesize_intersection_member(rendered, branch);
                            let literals = values
                                .iter()
                                .map(render_ts_value)
                                .collect::<Vec<_>>()
                                .join(" | ");
                            let readonly = if self.model.config.types.readonly {
                                "readonly "
                            } else {
                                ""
                            };
                            rendered = format!(
                                "({member} & {{ {readonly}{}: {literals} }})",
                                render_property_key(property)
                            );
                        }
                        if !rendered_branches.contains(&rendered) {
                            rendered_branches.push(rendered);
                        }
                    }
                    rendered_branches.join(" | ")
                }
            }
            SchemaNode::AnyOf { branches, .. } => {
                if branches.is_empty() {
                    "never".to_owned()
                } else {
                    // `anyOf` never gains discriminator intersections: at-least-one matching branch
                    // does not make the discriminator a total branch selector.
                    let mut rendered_branches = Vec::with_capacity(branches.len());
                    for branch in branches {
                        let rendered = self.render_type(branch, position, axis, indent);
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
        axis: TypeAxis,
        indent: usize,
        interface_members: bool,
    ) -> String {
        let has_included_properties = properties
            .iter()
            .any(|&(_, _, meta)| property_in_position(meta, position));
        let literal = if has_included_properties {
            let mut output = String::from("{\n");
            for &(name, schema, meta) in properties
                .iter()
                .filter(|&&(_, _, meta)| property_in_position(meta, position))
            {
                let member_indent = indent + 2;
                let docs = property_docs(schema);
                write_schema_tsdoc(
                    &mut output,
                    docs,
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
                output.push_str(&self.render_type(schema, position, axis, member_indent));
                output.push_str(";\n");
            }
            push_indent(&mut output, indent);
            output.push('}');
            output
        } else {
            // `{}` is not an object type in TypeScript — it admits every non-nullish value,
            // including primitives. An index signature is what the document actually declared:
            // open objects take any key, a closed object with no properties takes none.
            // Structural spelling, not `Record<...>`, for the reason at the typed arm below.
            match additional_properties {
                AdditionalProperties::Forbidden => "{ [key: string]: never }".to_owned(),
                _ => "{ [key: string]: unknown }".to_owned(),
            }
        };
        match additional_properties {
            AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => literal,
            AdditionalProperties::Allowed(Some(schema)) | AdditionalProperties::Schema(schema) => {
                let value = self.render_type(schema, position, axis, indent);
                // Both arms spell the index signature structurally rather than reaching for
                // `Record<string, V>`. A document may declare a component named `Record`, and the
                // emitted module that declares (or imports) it then resolves `Record` to that
                // non-generic type instead of the built-in — `TS2315: Type 'Record' is not
                // generic`. The structural form cannot be shadowed. See
                // `builtin_name_shadow_3_0` and `scripts/verify-ts.sh`.
                if !has_included_properties {
                    format!("{{ [key: string]: {value} }}")
                } else {
                    format!("{literal} & {{ [key: string]: {value} }}")
                }
            }
        }
    }

    fn render_pattern_properties(
        &self,
        literal: String,
        literal_is_empty_object: bool,
        pattern_properties: &[PatternProperty],
        position: TypePosition,
        axis: TypeAxis,
        indent: usize,
    ) -> String {
        pattern_properties
            .iter()
            .filter_map(|pattern| {
                let key = pattern.type_key.as_ref()?;
                let value = self.render_type(&pattern.schema, position, axis, indent);
                let signature = match key {
                    PatternPropertyKey::All => format!("{{ [key: string]: {value} }}"),
                    PatternPropertyKey::Prefix(prefix) => format!(
                        "{{ [key: `{}${{string}}`]: {value} }}",
                        render_ts_template_component(prefix)
                    ),
                    PatternPropertyKey::Contains(infix) => format!(
                        "{{ [key: `${{string}}{}${{string}}`]: {value} }}",
                        render_ts_template_component(infix)
                    ),
                };
                Some(signature)
            })
            .enumerate()
            .fold(literal, |rendered, (index, signature)| {
                // Only the first signature may replace the base — the rest intersect onto it, or
                // a second pattern would discard the first.
                if literal_is_empty_object && index == 0 {
                    signature
                } else {
                    format!("{rendered} & {signature}")
                }
            })
    }

    /// Runs `body` over the merged shape of the branches that have no name of their own.
    /// Returns `None` without running `body` when those branches do not merge into a single
    /// object shape, or when there are none — an `allOf` of nothing but `$ref`s has no
    /// anonymous half to describe.
    fn merge_all_of_guarded<'a, R>(
        &'a self,
        branches: &'a [SchemaNode],
        body: impl FnOnce(&[BorrowedProperty<'a>], &AdditionalProperties) -> R,
    ) -> Option<R> {
        // The merge is position-independent and depends only on the branch slice, so a
        // prewarmed entry (keyed by the slice's stable IR address) answers every render
        // and import pass for this node. `None` here means the slice was not prewarmed —
        // it is not IR-resident (a client plan or a test builds it), and its address is
        // not stable to key on, so recompute it uncached. `Some(None)` is a prewarmed
        // does-not-merge answer. Clone out of the cache in a tight scope: `body` re-enters
        // this method, so the cache borrow must be released before it runs.
        let key = (branches.as_ptr() as usize, branches.len());
        let cached = self.merge_cache.get(&key).cloned();
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
        Some(body(properties, additional_properties))
    }

    fn merge_all_of<'a>(
        &self,
        branches: &'a [SchemaNode],
    ) -> Option<(Vec<BorrowedProperty<'a>>, &'a AdditionalProperties)>
    where
        'input: 'a,
    {
        // Only the branches with no name of their own. A `$ref` branch renders as its own
        // bare name, so resolving it here would describe a shape nothing emits — and the
        // merge is an analysis input, not the emission strategy.
        //
        // One scratch set reused across branches; clearing before each call keeps
        // today's per-call-fresh cycle-visited semantics without a fresh allocation
        // per branch.
        let mut visited = HashSet::new();
        let shapes = branches
            .iter()
            .filter(|branch| !is_named_branch(branch))
            .map(|branch| {
                visited.clear();
                self.object_shape(branch, &mut visited)
            })
            .collect::<Option<Vec<_>>>()?;
        Self::merge_shapes(&shapes)
    }

    /// The `allOf` object merge over already-resolved branch shapes.
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

    /// Populates the merge cache for every `allOf` node in one IR schema tree. Descends the
    /// raw structure — never through a `$ref`, which is a leaf here, so the walk always
    /// terminates — and computes each node's merge once, before the node is rendered and
    /// walked for imports up to six times.
    fn prewarm_all_of(&mut self, schema: &'input SchemaNode) {
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
        let applicators = schema.meta().validation_applicators();
        if let Some(schema) = &applicators.not {
            self.prewarm_all_of(schema);
        }
        if let Some(schema) = &applicators.property_names {
            self.prewarm_all_of(schema);
        }
        for pattern in &applicators.pattern_properties {
            self.prewarm_all_of(&pattern.schema);
        }
        if let Some(contains) = &applicators.contains {
            self.prewarm_all_of(&contains.schema);
        }
        for (_, schema) in &applicators.dependent_schemas {
            self.prewarm_all_of(schema);
        }
        if let Some(conditional) = &applicators.conditional {
            self.prewarm_all_of(&conditional.condition);
            if let Some(schema) = &conditional.then_schema {
                self.prewarm_all_of(schema);
            }
            if let Some(schema) = &conditional.else_schema {
                self.prewarm_all_of(schema);
            }
        }
        if let Some(schema) = &applicators.unevaluated_properties {
            self.prewarm_all_of(schema);
        }
        if let Some(schema) = &applicators.unevaluated_items {
            self.prewarm_all_of(schema);
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
    fn cache_merge_all_of(&mut self, branches: &'input [SchemaNode]) {
        if branches.is_empty() {
            return;
        }
        let key = (branches.as_ptr() as usize, branches.len());
        // Compute the entry before touching the cache to keep the mutable borrow to the
        // single `insert`.
        let entry = self
            .merge_all_of(branches)
            .map(|(properties, additional_properties)| {
                (Arc::from(properties), additional_properties)
            });
        // Prewarming completes before the cache is shared with any rendering clone.
        Arc::get_mut(&mut self.merge_cache)
            .expect("the allOf cache is not shared until prewarming finishes")
            .insert(key, entry);
    }

    fn collect_component_imports(
        &self,
        schema: &SchemaNode,
        position: TypePosition,
        axis: TypeAxis,
        current_schema: usize,
        imports: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        self.walk_refs(schema, position, &mut |target| {
            if target.index != current_schema {
                // Reads the same producer the reference site reads, so the import and the type it
                // names can never spell the twin differently.
                let name = match axis {
                    TypeAxis::Wire if target.transforms => target.wire_name(position),
                    TypeAxis::Application | TypeAxis::Wire => target.variant_name(position),
                };
                imports
                    .entry(target.file_base.clone())
                    .or_default()
                    .insert(name);
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
                // Mirror render_type's partition exactly, or this walk records a different
                // set of imports than the renderer names — which is how a component reached
                // only through an `allOf` ended up emitted and imported by nothing. Each
                // `$ref` branch is visited directly, so it records its import and
                // terminates; the merged body describes only the anonymous half, and when
                // that half does not merge its branches are visited one by one.
                //
                // Validation mode is untouched: it visits every branch, refs included,
                // because a validator is emitted for the whole conjunction rather than for
                // the rendered type.
                if let SchemaChildMode::References(position) = mode {
                    let merged =
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
                        });
                    for branch in branches {
                        if !covered_by_merge(branch, merged.is_some()) {
                            visit(branch);
                        }
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
        if matches!(mode, SchemaChildMode::References(_)) {
            for pattern in &schema.meta().validation_applicators().pattern_properties {
                if pattern.type_key.is_some() {
                    visit(&pattern.schema);
                }
            }
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

/// The TypeScript globals a configured date/time representation renders as.
///
/// An imported component of the same name silently retypes every occurrence of the global in that
/// module — `at: Date` comes to mean the component rather than the built-in, which compiles and is
/// wrong. Every emitter that renders the application axis reserves these so `assign_import_aliases`
/// renames the import instead; the alias is file-local, so no exported name changes.
pub(super) fn representation_globals(types: &TypesConfig) -> BTreeSet<&'static str> {
    let mut globals = BTreeSet::new();
    if types.date_time == DateTimeRepresentation::Date {
        globals.insert("Date");
    }
    if types.date_time == DateTimeRepresentation::Temporal
        || types.date == DateRepresentation::Temporal
    {
        globals.insert("Temporal");
    }
    globals
}

/// Picks the local binding for every component import a module would otherwise let its own
/// declarations shadow. A shadowed import is silently retyped to the local declaration, so the
/// emitted module is not merely uncompilable — where it does compile, it is wrong.
///
/// Appending `Body` names the reference site's role exactly for the operation-derived declarations
/// that make up most collisions (`<Stem>RequestBody`, `<Stem>Response200Body`, `<Stem>InputBody`).
/// The client emitter also reserves its runtime-kernel imports and the TypeScript globals its
/// signatures name, where the suffix reads as a bare disambiguator rather than a role — one alias
/// rule is worth more than a second suffix, because the alias is file-local and never exported.
/// The component and the declaration are two legitimate public types in two different modules and
/// the rename is file-local, so no exported name changes; refusing the document instead would
/// reject input that generates perfectly valid TypeScript.
///
/// The residual case — the role name is itself taken by another import or declaration here — is a
/// genuine two-way collision with no local remedy, so it is fatal and points at `naming.overrides`.
/// Returns the diagnostics rather than pushing them: the types emitter renders behind `&self` and
/// defers them, while the client emitter owns a sink at that point.
pub(super) fn assign_import_aliases(
    declared: &BTreeSet<String>,
    reserved: &BTreeSet<&str>,
    imports: &BTreeMap<String, BTreeSet<String>>,
    source: &SourceRef,
) -> (HashMap<String, String>, Vec<Diagnostic>) {
    let mut aliases = HashMap::new();
    let mut diagnostics = Vec::new();
    // `reserved` is the caller's fixed set — the identifiers its emitter injects into every module
    // and the built-ins its signatures name. It is passed borrowed and separate from `declared`
    // rather than merged into it because merging would own ~35 constant strings per emitted
    // module, and the module-specific half is the only part that varies.
    let binds = |name: &str| declared.contains(name) || reserved.contains(name);
    // Fast-reject: the overwhelming majority of modules import nothing carrying a declaration's
    // name, and this runs once per emitted module.
    let shadowed = imports
        .values()
        .flatten()
        .filter(|name| binds(name.as_str()))
        .collect::<Vec<_>>();
    if shadowed.is_empty() {
        return (aliases, diagnostics);
    }
    let imported = imports.values().flatten().collect::<BTreeSet<_>>();
    for name in shadowed {
        let alias = format!("{name}Body");
        if binds(&alias) || imported.contains(&alias) {
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
            TypePosition::Request if self.request_differs => self
                .request_variant
                .clone()
                .unwrap_or_else(|| format!("{}Request", self.name)),
            TypePosition::Response if self.response_differs => self
                .response_variant
                .clone()
                .unwrap_or_else(|| format!("{}Response", self.name)),
            TypePosition::Neutral | TypePosition::Request | TypePosition::Response => {
                self.name.clone()
            }
        }
    }

    /// The name this component's request-position variant declares under, or `None` when the
    /// position declares nothing of its own — either because the shape does not diverge from the
    /// neutral one, or because no operation uses the component in request position at all.
    /// Every artifact that emits a component reads this rather than pairing the `differs` flag
    /// with its own `variant_name` call, so the flag and the name cannot drift apart.
    pub(super) fn request_export(&self) -> Option<String> {
        self.request_differs
            .then(|| self.variant_name(TypePosition::Request))
    }

    pub(super) fn response_export(&self) -> Option<String> {
        self.response_differs
            .then(|| self.variant_name(TypePosition::Response))
    }

    /// The name this position's wire twin exports under: the wire suffix composed onto
    /// `variant_name(position)`, or the replacement a collision assigned.
    ///
    /// The suffix goes last and composes onto the *variant* name, never the derived one: a component
    /// whose request variant was aliased to `PetRequestBody` yields `PetRequestBodyWire`. Composing
    /// onto the derived name instead would have two modules exporting `PetRequestWire` with no
    /// diagnostic at all.
    pub(super) fn wire_name(&self, position: TypePosition) -> String {
        // A position that declares nothing of its own reads the neutral declaration's twin, exactly
        // as `variant_name` reads its name. Deriving one here instead would rebuild it from a name
        // `reserve_names` may since have renamed, and nothing re-checks that against the declared
        // components — the trap that pass documents for variant overrides.
        self.wire_variants[position.index()]
            .clone()
            .or_else(|| self.wire_variants[TypePosition::Neutral.index()].clone())
            .unwrap_or_else(|| format!("{}Wire", self.variant_name(position)))
    }

    /// Whether this position declares anything of its own, ignoring transforms. Reads as the shape
    /// question it is, so the wire pass and the emitters agree on which positions exist.
    pub(super) fn wire_export_base(&self, position: TypePosition) -> Option<String> {
        match position {
            TypePosition::Neutral => Some(self.name.clone()),
            TypePosition::Request => self.request_export(),
            TypePosition::Response => self.response_export(),
        }
    }

    /// The name this position's wire twin declares under, or `None` when the component reaches no
    /// transform or the position declares nothing of its own. Every artifact emitting a twin reads
    /// this rather than pairing `transforms` with its own `wire_name` call, so the flag and the name
    /// cannot drift apart.
    pub(super) fn wire_export(&self, position: TypePosition) -> Option<String> {
        if !self.transforms {
            return None;
        }
        self.wire_export_base(position)
            .map(|_| self.wire_name(position))
    }
}

impl Emitter<'_, '_, '_> {
    /// Renders one operation-shaped file and returns its ordered diagnostics and header-helper bit.
    /// Shared by the path-operation, webhook, and callback parallel loops, whose ordered collects
    /// make these per-file accumulators deterministic before the caller appends them.
    fn emit_operation(
        &self,
        operation: &Operation,
        allocated_name: &str,
        subdir: &str,
        file_base: &str,
    ) -> EmittedOperation {
        let file = self.emit_operation_file(operation, allocated_name, subdir, file_base);
        EmittedOperation {
            file,
            diagnostics: self.deferred_diagnostics.take(),
            has_response_headers: operation
                .responses
                .iter()
                .any(|response| !response.headers.is_empty()),
            names_sse_event: operation_names_sse_event(operation),
        }
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
        let response_declarations = operation_response_declarations(operation, &stem);

        let mut content = self.header();
        let mut imports = BTreeMap::<String, BTreeSet<String>>::new();
        for parameter in &operation.parameters {
            self.collect_operation_imports(
                &parameter.schema,
                TypePosition::Request,
                TypeAxis::Application,
                &mut imports,
            );
        }
        if let Some(body) = &operation.request_body
            && let Some(media_type) = select_request_media(&body.media_types)
            && media_carries_json_value(&media_type.essence, media_type.streaming_marked)
        {
            self.collect_operation_imports(
                &media_type.schema,
                TypePosition::Request,
                TypeAxis::Application,
                &mut imports,
            );
        }
        // The request twin names the wire form of every component its payload reaches.
        if self.request_transforms(operation) {
            for parameter in &operation.parameters {
                self.collect_operation_imports(
                    &parameter.schema,
                    TypePosition::Request,
                    TypeAxis::Wire,
                    &mut imports,
                );
            }
            if let Some(body) = &operation.request_body
                && let Some(media_type) = select_request_media(&body.media_types)
            {
                self.collect_operation_imports(
                    &media_type.schema,
                    TypePosition::Request,
                    TypeAxis::Wire,
                    &mut imports,
                );
            }
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                // An SSE entry renders its schema too — as the event's decoded `data` — so it names
                // the same components a JSON entry would. A raw stream renders as bytes and names
                // nothing, which is why this asks for the family rather than for "is it streaming".
                let sse = media_stream_kind(&media_type.essence, media_type.streaming_marked)
                    == Some(StreamKind::Sse);
                if !sse
                    && !media_carries_json_value(&media_type.essence, media_type.streaming_marked)
                {
                    continue;
                }
                // An event is rendered on the application surface whatever the configured
                // representation, because the runtime converts one before yielding it — so it names
                // the application components and only those, on the branch's wire alias as well.
                // A buffered entry names the application form, and its twin as well when it
                // converts.
                if sse {
                    self.collect_operation_imports(
                        &media_type.schema,
                        TypePosition::Response,
                        TypeAxis::Application,
                        &mut imports,
                    );
                    continue;
                }
                self.collect_operation_imports(
                    &media_type.schema,
                    TypePosition::Response,
                    TypeAxis::Application,
                    &mut imports,
                );
                if self.response_transforms(response) {
                    self.collect_operation_imports(
                        &media_type.schema,
                        TypePosition::Response,
                        TypeAxis::Wire,
                        &mut imports,
                    );
                }
            }
            for (_, header) in &response.headers {
                self.collect_operation_imports(
                    &header.schema,
                    TypePosition::Response,
                    TypeAxis::Application,
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
            // The payload twins count as declarations too, on exactly the conditions that emit
            // them below. Listing only the application names left a module importing a component
            // called `{Stem}Response200` with one of the pair aliased and its `Wire` twin not: the
            // import then bound the local twin instead, which is TS2440 where the names collide and
            // a silently wrong type where they do not.
            if self.request_transforms(operation) {
                declared.insert(format!("{stem}RequestWire"));
            }
            for (response_name, response) in &response_declarations {
                declared.insert(response_name.clone());
                if self.response_transforms(response) {
                    declared.insert(format!("{response_name}Wire"));
                }
                if !response.headers.is_empty() {
                    declared.insert(format!("{response_name}Headers"));
                }
            }
            assign_import_aliases(
                &declared,
                &representation_globals(&self.model.config.types),
                &imports,
                &operation.source,
            )
        };
        self.set_import_aliases(aliases);
        self.deferred_diagnostics
            .borrow_mut()
            .extend(alias_diagnostics);
        self.write_imports(&mut content, imports, "../components/");
        if operation_names_sse_event(operation) {
            content.push_str("import type { SseEvent } from \"../stream");
            content.push_str(&import_extension(self.model));
            content.push_str("\";\n\n");
        }

        write_source_metadata(&mut content, &operation.source, 0);
        write_operation_tsdoc(&mut content, operation, &self.model.config.documentation, 0);
        content.push_str("export type ");
        content.push_str(&stem);
        content.push_str("Request = ");
        content.push_str(&self.render_request(operation, TypeAxis::Application, 0));
        content.push_str(";\n\n");
        // A payload twin is emitted for exactly the positions that convert, on the same rule the
        // component twins follow: a payload reaching no transform is identity in both surfaces and
        // declares one type.
        if self.request_transforms(operation) {
            write_source_metadata(&mut content, &operation.source, 0);
            content.push_str("export type ");
            content.push_str(&stem);
            content.push_str("RequestWire = ");
            content.push_str(&self.render_request(operation, TypeAxis::Wire, 0));
            content.push_str(";\n\n");
        }

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
            if self.response_transforms(response) {
                write_source_metadata(&mut content, &response.source, 0);
                content.push_str("export type ");
                content.push_str(&response_name);
                content.push_str("Wire = ");
                content.push_str(&self.render_response_entry_wire(response));
                content.push_str(";\n\n");
            }
            if !response.headers.is_empty() {
                self.write_response_headers_interface(
                    &mut content,
                    &format!("{response_name}Headers"),
                    response,
                    TypeAxis::Application,
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
            relative_path: format!("{}/{subdir}/{file_base}.ts", self.model.dirs.types),
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
                    Cow::Owned(format!("{target_stem}Response")),
                    Some(Cow::Borrowed(resolved.link_name.as_str())),
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
        axis: TypeAxis,
    ) {
        write_source_metadata(output, &response.source, 0);
        output.push_str("export interface ");
        output.push_str(interface_name);
        output.push_str(" {\n");
        for (name, header) in &response.headers {
            write_schema_tsdoc(
                output,
                response_header_docs(header),
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
                output.push_str(&self.render_type(&header.schema, TypePosition::Response, axis, 2));
            }
            output.push_str(";\n");
        }
        output.push_str("}\n\n");
    }

    fn render_request(&self, operation: &Operation, axis: TypeAxis, indent: usize) -> String {
        let groups = [
            ParamLocation::Path,
            ParamLocation::Query,
            ParamLocation::Header,
            ParamLocation::Cookie,
        ]
        .map(|location| (location, parameter_group_name(location)));
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
            let group = self.render_parameter_group(&parameters, axis, indent + 2);
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
                media_stream_kind(&media_type.essence, media_type.streaming_marked),
                TypePosition::Request,
                axis,
                indent + 2,
            );
            if let Some(description) = &body.description {
                write_schema_tsdoc(
                    &mut output,
                    SchemaDocView {
                        description: Some(description),
                        ..SchemaDocView::default()
                    },
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

    pub(super) fn render_parameter_group(
        &self,
        parameters: &[&Param],
        axis: TypeAxis,
        indent: usize,
    ) -> String {
        let mut output = String::from("{\n");
        for parameter in parameters {
            let docs = schema_field_docs(
                parameter.description.as_deref(),
                parameter.deprecated,
                &parameter.schema,
            );
            write_schema_tsdoc(
                &mut output,
                docs,
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
                axis,
                indent + 2,
            ));
            output.push_str(";\n");
        }
        push_indent(&mut output, indent);
        output.push('}');
        output
    }

    /// Whether any JSON media entry of this response converts, and so declares a payload twin.
    pub(super) fn response_transforms(&self, response: &ResponseEntry) -> bool {
        response.media_types.iter().any(|media_type| {
            media_carries_json_value(&media_type.essence, media_type.streaming_marked)
                && self.model.transform_facts().reaches(&media_type.schema)
        })
    }

    /// Whether any request parameter or the selected JSON request body converts.
    pub(super) fn request_transforms(&self, operation: &Operation) -> bool {
        operation
            .parameters
            .iter()
            .any(|parameter| self.model.transform_facts().reaches(&parameter.schema))
            || operation
                .request_body
                .as_ref()
                .and_then(|body| select_request_media(&body.media_types))
                .is_some_and(|media_type| {
                    media_carries_json_value(&media_type.essence, media_type.streaming_marked)
                        && self.model.transform_facts().reaches(&media_type.schema)
                })
    }

    /// The wire form of one response's payload union. Called only where `response_transforms`
    /// answered true, which already establishes that a JSON media entry is present.
    fn render_response_entry_wire(&self, response: &ResponseEntry) -> String {
        let mut types = Vec::new();
        for media_type in &response.media_types {
            let rendered = self.media_payload_type(
                &media_type.essence,
                &media_type.schema,
                media_stream_kind(&media_type.essence, media_type.streaming_marked),
                TypePosition::Response,
                TypeAxis::Wire,
                0,
            );
            if !types.contains(&rendered) {
                types.push(rendered);
            }
        }
        types.join(" | ")
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
                media_stream_kind(&media_type.essence, media_type.streaming_marked),
                TypePosition::Response,
                TypeAxis::Application,
                0,
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
        stream: Option<StreamKind>,
        position: TypePosition,
        axis: TypeAxis,
        indent: usize,
    ) -> String {
        // The two directions deliberately disagree, and this is the one place that says so. A
        // response stream is the thing the client hands back, so SSE arrives as typed events; a
        // request stream is bytes in both families, because framing typed events would put every
        // framing, transform and validation failure after the request was already dispatched,
        // where the result model has no arm to report it in. The frame encoder is a separate
        // export the caller composes instead.
        match (stream, position) {
            (Some(_), TypePosition::Request) => {
                return "ReadableStream<Uint8Array>".to_owned();
            }
            (Some(StreamKind::Sse), TypePosition::Response | TypePosition::Neutral) => {
                // Always the application surface, whichever axis was asked for. The runtime
                // converts each event before yielding it, so both surfaces see the application
                // form: there is no wire twin for a stream because there is no moment at which a
                // consumer holds an unconverted one. A branch that pairs an event stream with a
                // buffered entry depends on that — the buffered arm's wire twin is what `execute`
                // hands back, and an event arm that disagreed across the two would leave the
                // emitted module unable to compile against its own declared result.
                return format!(
                    "AsyncIterable<SseEvent<{}>>",
                    self.render_type(schema, position, TypeAxis::Application, indent)
                );
            }
            (Some(StreamKind::Raw), TypePosition::Response | TypePosition::Neutral) => {
                return "ReadableStream<Uint8Array>".to_owned();
            }
            (None, _) => {}
        }
        if is_json(essence) {
            self.render_type(schema, position, axis, indent)
        } else if essence.starts_with("text/") && !is_xml(essence) {
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
        axis: TypeAxis,
        imports: &mut BTreeMap<String, BTreeSet<String>>,
    ) {
        self.walk_refs(schema, position, &mut |target| {
            let name = match axis {
                TypeAxis::Wire if target.transforms => target.wire_name(position),
                TypeAxis::Application | TypeAxis::Wire => target.variant_name(position),
            };
            imports
                .entry(target.file_base.clone())
                .or_default()
                .insert(name);
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

/// The response type declarations for one operation, in their emitted order.
pub(super) fn operation_response_declarations<'operation>(
    operation: &'operation Operation,
    stem: &str,
) -> Vec<(String, &'operation ResponseEntry)> {
    let mut declarations = operation
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
    declarations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    declarations
}

pub(super) fn property_in_position(meta: &PropMeta, position: TypePosition) -> bool {
    match position {
        TypePosition::Neutral => true,
        TypePosition::Request => !meta.read_only,
        TypePosition::Response => !meta.write_only,
    }
}

fn property_docs(schema: &SchemaNode) -> SchemaDocView<'_> {
    SchemaDocView::from(&schema.meta().docs)
}

/// `SchemaDocs` for a Parameter or Header Object: its own `description`/`deprecated`, never a
/// `title` or `default` (those live only inside the schema), plus the nested schema's
/// `examples`/`comment`/`constraints`. Both objects carry the same description/deprecated/schema
/// shape, so `render_parameter_group` (Parameter) and `response_header_docs` (Header) share this.
fn schema_field_docs<'a>(
    description: Option<&'a str>,
    deprecated: bool,
    schema: &'a SchemaNode,
) -> SchemaDocView<'a> {
    SchemaDocView {
        title: None,
        description,
        deprecated,
        default: None,
        ..SchemaDocView::from(&schema.meta().docs)
    }
}

fn response_header_docs(header: &ResponseHeader) -> SchemaDocView<'_> {
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

fn intersect_projected_tag_types(
    left: ProjectedTagType,
    right: ProjectedTagType,
) -> ProjectedTagType {
    match (left, right) {
        (ProjectedTagType::Number, ProjectedTagType::Integer)
        | (ProjectedTagType::Integer, ProjectedTagType::Number) => ProjectedTagType::Integer,
        (left, right) if left == right => left,
        _ => ProjectedTagType::Incompatible,
    }
}

fn projected_tag_value(tag: &str, tag_type: ProjectedTagType) -> Option<Value> {
    match tag_type {
        ProjectedTagType::String => Some(Value::String(tag.to_owned())),
        ProjectedTagType::Number | ProjectedTagType::Integer => {
            let Value::Number(number) = serde_json::from_str::<Value>(tag).ok()? else {
                return None;
            };
            if tag_type == ProjectedTagType::Integer
                && !number.as_f64().is_some_and(|value| value.fract() == 0.0)
            {
                return None;
            }
            Some(Value::Number(number))
        }
        ProjectedTagType::Boolean => match tag {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        ProjectedTagType::Null => (tag == "null").then_some(Value::Null),
        ProjectedTagType::Incompatible => None,
    }
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
    // A Rust string is always a serializable JSON string scalar.
    let mut encoded = serde_json::to_string(value).expect("serializing a string cannot fail");
    if encoded.contains('\u{2028}') {
        encoded = encoded.replace('\u{2028}', "\\u2028");
    }
    if encoded.contains('\u{2029}') {
        encoded = encoded.replace('\u{2029}', "\\u2029");
    }
    encoded
}

fn render_ts_template_component(value: &str) -> String {
    let quoted = render_ts_string(value);
    quoted[1..quoted.len() - 1]
        .replace('`', "\\`")
        .replace("${", "\\${")
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

/// An object-literal key in **value** position.
///
/// `render_property_key` answers the type-declaration question, where `__proto__` is an ordinary
/// property name. In a value literal it is not: both `__proto__: v` and `"__proto__": v` invoke the
/// prototype setter rather than creating an own property, so the emitted object would lack a
/// property its declared type promises — and `JSON.stringify` and `Object.keys` would both drop it.
/// A computed key is the only spelling that creates one.
pub(super) fn render_literal_key(value: &str) -> String {
    if value == "__proto__" {
        return format!("[{}]", render_ts_string(value));
    }
    render_property_key(value)
}

/// A branch whose identity survives emission: a `$ref` renders as its own bare name, so it
/// never enters the anonymous merge. Read by the renderer and by the import walk, so the two
/// cannot drift — a renderer and an import walk that disagreed is what left a component
/// reachable only through `allOf` emitted but imported by nothing.
///
/// Only a direct `$ref` counts. A branch that is itself an `allOf` wrapping a ref is anonymous
/// here and recurses through the normal path.
fn is_named_branch(branch: &SchemaNode) -> bool {
    matches!(branch, SchemaNode::Ref { .. })
}

/// Whether the merged anonymous blob already accounts for this branch — true exactly for the
/// branches the renderer replaces with that blob and the import walk therefore must not visit
/// itself. Read by both, because a renderer and an import walk that computed this separately
/// is what emitted a component nothing imported; sharing only `is_named_branch` still left
/// the combination with the merge written out twice, in mutually inverted forms.
fn covered_by_merge(branch: &SchemaNode, merged: bool) -> bool {
    merged && !is_named_branch(branch)
}

/// The property name the emitted input gives one parameter location's group.
///
/// One producer for both the types artifact's `Request` and the client artifact's `Input`, because
/// the two describe the same operation input: a `Request` value has to be assignable to the
/// parameter an `Input` declares, and two independent spellings made that false wherever an
/// operation carried a header or a cookie. Singular throughout, matching the document's own `in:`
/// values.
///
/// The descriptor's own `location` string is this same name, and must stay so: the runtime reads a
/// parameter as `input[plan.location]`, so the literal a descriptor carries is the key it looks up
/// on the value the caller passed. The emitted input-member access and a validator's issue path
/// name that same property. One producer for all four, because they are one name — a second
/// spelling anywhere makes every parameter read `undefined` at request time, which throws for a
/// required parameter and silently drops an optional one.
///
/// The msw artifact deliberately keeps its own spelling: its resolver argument is a handler's
/// destructured context mirroring MSW's vocabulary, where `params` and `cookies` are MSW's own
/// property names. Nothing assigns a `Request` into it, and it could not align if it tried.
pub(crate) const fn parameter_group_name(location: ParamLocation) -> &'static str {
    match location {
        ParamLocation::Path => "path",
        ParamLocation::Query => "query",
        ParamLocation::Header => "header",
        ParamLocation::Cookie => "cookie",
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
    // The rendered-text check matters for the same reason it does in
    // `parenthesize_intersection_member`: an `enum`/`const` primitive and a `Finite` node render a
    // top-level union without being a `OneOf`/`AnyOf` or nullable node, and `[]` binds tighter than
    // `|`, so `"a" | "b"[]` is a union of `"a"` and `"b"[]` rather than an array of the union.
    if schema.is_nullable()
        || matches!(
            schema,
            SchemaNode::AllOf { .. } | SchemaNode::OneOf { .. } | SchemaNode::AnyOf { .. }
        )
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

#[derive(Clone, Copy, Default)]
struct SchemaDocView<'a> {
    title: Option<&'a str>,
    description: Option<&'a str>,
    deprecated: bool,
    default: Option<&'a Value>,
    examples: &'a [Value],
    comment: Option<&'a str>,
    constraints: &'a [String],
    neutral_variants: Option<NeutralSchemaVariants<'a>>,
}

struct SchemaDeclarationContext<'a> {
    source: &'a SourceRef,
    docs: SchemaDocView<'a>,
}

#[derive(Clone, Copy)]
struct NeutralSchemaVariants<'a> {
    request: &'a str,
    response: &'a str,
}

impl<'a> From<&'a SchemaDocs> for SchemaDocView<'a> {
    fn from(docs: &'a SchemaDocs) -> Self {
        Self {
            title: docs.title.as_deref(),
            description: docs.description.as_deref(),
            deprecated: docs.deprecated,
            default: docs.default.as_ref(),
            examples: &docs.examples,
            comment: docs.comment.as_deref(),
            constraints: &docs.constraints,
            neutral_variants: None,
        }
    }
}

#[derive(Default)]
struct TsDoc<'a> {
    summary: Option<Cow<'a, str>>,
    remarks: Vec<Cow<'a, str>>,
    deprecated: Option<&'static str>,
    params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    returns: Option<&'static str>,
    default_value: Option<Cow<'a, str>>,
    examples: Vec<DocExample<'a>>,
    private_remarks: Option<Cow<'a, str>>,
    see: Vec<(Cow<'a, str>, Option<Cow<'a, str>>)>,
    neutral_variants: Option<NeutralSchemaVariants<'a>>,
}

struct DocExample<'a> {
    label: Option<Cow<'a, str>>,
    value: Cow<'a, Value>,
}

fn write_schema_tsdoc(
    output: &mut String,
    docs: SchemaDocView<'_>,
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
            map_summary_description(&mut tsdoc, docs.title, docs.description, config);
        }
        DocKind::Parameter | DocKind::Header => {
            if let Some(description) = docs.description {
                if config.summary {
                    tsdoc.summary = Some(Cow::Borrowed(description));
                } else if config.description {
                    tsdoc.remarks.push(Cow::Borrowed(description));
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
    if let Some(default) = docs.default {
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
            tsdoc.default_value = Some(Cow::Owned(rendered));
        } else if kind == DocKind::Schema {
            tsdoc
                .remarks
                .push(Cow::Owned(format!("Default value: {rendered}")));
        }
    }
    if config.constraints && !docs.constraints.is_empty() {
        tsdoc.remarks.push(Cow::Owned(format!(
            "Constraints\n\n{}",
            docs.constraints
                .iter()
                .map(|constraint| format!("- {constraint}"))
                .collect::<Vec<_>>()
                .join("\n")
        )));
    }
    if config.examples {
        tsdoc.examples = docs
            .examples
            .iter()
            .map(|value| {
                let label = first_number_outside_binary64(value).map(|_| {
                    Cow::Owned(if value.is_number() {
                        "Outside the binary64 range.".to_owned()
                    } else {
                        "Contains a value outside the binary64 range.".to_owned()
                    })
                });
                DocExample {
                    label,
                    value: Cow::Borrowed(value),
                }
            })
            .collect();
    }
    tsdoc.private_remarks = docs.comment.map(Cow::Borrowed);
    tsdoc.neutral_variants = docs.neutral_variants;
    write_tsdoc(output, &tsdoc, indent);
}

fn map_summary_description<'a>(
    tsdoc: &mut TsDoc<'a>,
    title: Option<&'a str>,
    description: Option<&'a str>,
    config: &DocumentationConfig,
) {
    if config.summary {
        if let Some(title) = title {
            tsdoc.summary = Some(Cow::Borrowed(title));
        } else if config.description
            && let Some(description) = description
        {
            tsdoc.summary = Some(Cow::Borrowed(description));
            return;
        }
    }
    if config.description
        && let Some(description) = description
    {
        tsdoc.remarks.push(Cow::Borrowed(description));
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
        tsdoc.remarks.push(Cow::Owned(format!(
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
        )));
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
            tsdoc.remarks.push(Cow::Owned(format!(
                "Media type constraints\n\n{}",
                media_notes.join("\n")
            )));
        }
    }
    if config.deprecated && operation.deprecated {
        tsdoc.deprecated = Some("This operation is deprecated.");
    }
    if let Some((url, description)) = &operation.external_docs {
        tsdoc.see.push((
            Cow::Borrowed(url.as_str()),
            description.as_deref().map(Cow::Borrowed),
        ));
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
    // Whether any success branch resolves as a stream. Independent of `unchecked_response`: a
    // stream's proof is weaker whatever the validation setting, because the result resolves before
    // a single body byte has been read.
    streaming_response: bool,
    // Per-response notes the client emitter owns because they describe runtime decoding, not the
    // declared schema — the multipart part-mapping rules, whose behaviour the specification leaves
    // undefined and which therefore has to be readable at the call site.
    decoding_notes: &[String],
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
            tsdoc.remarks.push(Cow::Owned(format!(
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
            )));
        }
        if config.constraints && !decoding_notes.is_empty() {
            tsdoc.remarks.push(Cow::Owned(format!(
                "Response decoding\n\n{}",
                decoding_notes.join("\n")
            )));
        }
        if config.deprecated && operation.deprecated {
            tsdoc.deprecated = Some("This operation is deprecated.");
        }
        if let Some((url, description)) = &operation.external_docs {
            tsdoc.see.push((
                Cow::Borrowed(url.as_str()),
                description.as_deref().map(Cow::Borrowed),
            ));
        }
    }
    match kind {
        ClientDocKind::Declaration => {}
        ClientDocKind::ResultFunction | ClientDocKind::ThrowFunction => {
            if unchecked_response {
                tsdoc.remarks.insert(
                    0,
                    Cow::Borrowed(
                        "Successful response data is decoded but unchecked against the OpenAPI schema.",
                    ),
                );
            }
            if streaming_response {
                tsdoc.remarks.insert(
                    0,
                    Cow::Borrowed(
                        "A streaming branch resolves when the response headers arrive, so `ok: true` attests only the matched status, the selected media type, and that the stream handle was created. Each server-sent event proves its own framing and decoding as it is yielded, and carries the wire form of its schema; a raw byte stream is never checked against a schema at all.",
                    ),
                );
            }
            if config.enabled && config.description {
                tsdoc.params = operation
                    .parameters
                    .iter()
                    .filter_map(|parameter| {
                        parameter.description.as_ref().map(|description| {
                            (
                                Cow::Borrowed(parameter.name.as_str()),
                                Cow::Borrowed(description.as_str()),
                            )
                        })
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

fn push_media_examples<'a>(
    examples: &mut Vec<DocExample<'a>>,
    media_type: &'a MediaType,
    source: &str,
) {
    for (label, value) in &media_type.examples {
        examples.push(DocExample {
            label: Some(Cow::Owned(format!(
                "Source: {source} {label} ({})",
                media_type.essence
            ))),
            value: Cow::Borrowed(value),
        });
    }
    for value in &media_type.schema.meta().docs.examples {
        examples.push(DocExample {
            label: Some(Cow::Owned(format!(
                "Source: {source} ({})",
                media_type.essence
            ))),
            value: Cow::Borrowed(value),
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

fn write_tsdoc(output: &mut String, docs: &TsDoc<'_>, indent: usize) {
    if docs.summary.is_none()
        && docs.remarks.is_empty()
        && docs.deprecated.is_none()
        && docs.params.is_empty()
        && docs.returns.is_none()
        && docs.default_value.is_none()
        && docs.examples.is_empty()
        && docs.private_remarks.is_none()
        && docs.see.is_empty()
        && docs.neutral_variants.is_none()
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
    if !docs.remarks.is_empty() || docs.neutral_variants.is_some() {
        writer.begin_section();
        writer.plain_line("@remarks");
        if let Some((first, rest)) = docs.remarks.split_first() {
            writer.encoded_lines(first);
            for remark in rest {
                writer.plain_line("");
                writer.encoded_lines(remark);
            }
        }
        if let Some(variants) = docs.neutral_variants {
            if !docs.remarks.is_empty() {
                writer.plain_line("");
            }
            writer.start_line();
            writer.output.push_str(
                "This is the shape declared by the document, not a wire shape for any single message. Use {@link ",
            );
            write_link_part(writer.output, variants.request);
            writer
                .output
                .push_str("} for what a caller sends and {@link ");
            write_link_part(writer.output, variants.response);
            writer.output.push_str("} for what the server returns.");
            writer.finish_line();
        }
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
        for line in render_json_pretty(example.value.as_ref()).lines() {
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
        // The loop guard keeps `index` below `len`, and every update advances by a UTF-8 width.
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
        // The loop guard keeps `index` below `len`, and every update advances by a UTF-8 width.
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
    let applicators = schema.meta().validation_applicators();
    if let Some(schema) = &applicators.not {
        accumulate_shape_variants(schema, acc);
    }
    if let Some(schema) = &applicators.property_names {
        accumulate_shape_variants(schema, acc);
    }
    for pattern in &applicators.pattern_properties {
        accumulate_shape_variants(&pattern.schema, acc);
    }
    if let Some(contains) = &applicators.contains {
        accumulate_shape_variants(&contains.schema, acc);
    }
    for (_, schema) in &applicators.dependent_schemas {
        accumulate_shape_variants(schema, acc);
    }
    if let Some(conditional) = &applicators.conditional {
        accumulate_shape_variants(&conditional.condition, acc);
        if let Some(schema) = &conditional.then_schema {
            accumulate_shape_variants(schema, acc);
        }
        if let Some(schema) = &conditional.else_schema {
            accumulate_shape_variants(schema, acc);
        }
    }
    if let Some(schema) = &applicators.unevaluated_properties {
        accumulate_shape_variants(schema, acc);
    }
    if let Some(schema) = &applicators.unevaluated_items {
        accumulate_shape_variants(schema, acc);
    }
}

pub(super) struct ResponseMediaName<'media> {
    pub(super) name: String,
    pub(super) collision: Option<&'media str>,
}

/// Names every JSON body a response declares, given that response's **full** media list in declared
/// order. A sole JSON entry keeps `base`; two or more append their media tag, with an empty tag
/// composed as `Media`. The first entry claiming a name keeps it; a later collision appends `2`,
/// then increments until it finds an unclaimed name, so the suffix stays predictable from the
/// response's own media-entry order even when a literal tag already claimed a numbered candidate.
/// `collision` names the earlier entry whose plain name caused the alias.
///
/// Two obligations sit on the caller, because the validators, zod, and client emitters each emit
/// one side of the same symbol: the first two emit the declaration, the client emits the call. A
/// caller that passes a different subset, or a different order, emits a call to a function that was
/// never declared.
///
/// *Which* entries: exactly the response's JSON entries, and nothing else. All three callers spell
/// that `is_json`, but on different fields — validators and zod on `MediaType::essence`, the client
/// on the full `ResponseMediaPlan::media`. Those agree because `is_json` runs `media_essence` on
/// whatever it is handed, so a parameterized value classifies by its base type either way; it is
/// keyed on the essence by design, exactly as `is_xml` beside it documents.
///
/// *In what order*: the declared media order. Validators and zod filter `ResponseEntry::media_types`
/// directly; the client filters `ResponsePlan::media`, which is built as an order-preserving map
/// over that same slice. Request bodies are *not* like this — `build_body_plan` sorts its
/// discriminated arms by media type — so a future sort applied to response media would silently
/// swap which schema each alias names. `client_model` pins that with a test.
///
/// Selection stays with the callers rather than moving in here so this function remains total over
/// any media string, which is what its unit tests exercise; a JSON-only parameter would make the
/// empty-tag path above unreachable and untestable.
pub(super) fn response_media_names<'media>(
    base: &str,
    media: &[&'media str],
) -> Vec<ResponseMediaName<'media>> {
    // The overwhelmingly common response declares one JSON entry, which is never tagged and has
    // nothing to collide against. Answering it here keeps the claim map off that path entirely.
    if media.len() == 1 {
        return vec![ResponseMediaName {
            name: base.to_owned(),
            collision: None,
        }];
    }
    let mut claimed = BTreeMap::new();
    media
        .iter()
        .map(|media| {
            let tag = media_tag(media);
            let mut name = if tag.is_empty() {
                format!("{base}Media")
            } else {
                format!("{base}{tag}")
            };
            let collision = claimed.get(&name).copied();
            if collision.is_some() {
                let plain = name;
                let mut next = 2;
                loop {
                    name = format!("{plain}{next}");
                    if !claimed.contains_key(&name) {
                        break;
                    }
                    next += 1;
                }
            }
            claimed.insert(name.clone(), *media);
            ResponseMediaName { name, collision }
        })
        .collect()
}

/// The exported-name fragment identifying one media entry, mangled from its canonical full media
/// string: `*` becomes `Wildcard`, every other non-alphanumeric ASCII byte is a token separator,
/// and each token is uppercase-first and concatenated (`application/vnd.api+json` →
/// `ApplicationVndApiJson`).
fn media_tag(media: &str) -> String {
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

/// Where one request-body validator position reads its value, relative to the dispatch root.
pub(super) enum RequestBodyAccess {
    /// The body itself: `<root>.body`.
    Whole,
    /// One form field: `<root>.body.<key>`, or `<root>.body.<key>.body` when the field is wrapped,
    /// because a wrapped field renders `{ body, contentType }` and the schema describes the payload
    /// rather than the wrapper.
    Field { key: String, wrapped: bool },
    /// One content-type arm: `<root>.body.body`, selected by testing `<root>.body.contentType`
    /// against `media` rather than by a presence guard.
    Arm { media: String },
}

/// One request-body position: a validator the validators/zod artifacts declare, and — when the
/// value can be reached soundly — a call the client emits against it.
pub(super) struct RequestBodyPosition<'a> {
    /// Export-type name, without the `validate` prefix.
    pub name: String,
    pub schema: &'a SchemaNode,
    /// How the client reaches the value. Every position has one: the declaration-only case existed
    /// only while two predicates disagreed about `text/json`, and that disagreement is gone.
    pub access: RequestBodyAccess,
    /// Whether the client must test the value for presence before calling.
    pub guarded: bool,
}

/// Every request-body validator position for one operation, derived once for all three emitters.
///
/// The same obligation as `response_media_names` above: validators and zod emit the declarations,
/// the client emits the calls, and a caller that derives a different set emits a call to a function
/// that was never declared. `emit_validators_from_model` gets only the `EmissionModel`, so this
/// works from the IR `Body` plus the `BodyPlan` each caller already has — the client from
/// `OperationPlan::body_plan`, validators and zod from `build_body_plan` over the same
/// `Body::media_types` with a `PrimitiveDomainProjector`, which is how that plan was built.
///
/// *Naming*: the JSON body keeps the bare `{stem}RequestBody` it has always had. Form fields take
/// `{stem}RequestBody{Field}`, which cannot collide with a parameter's `{stem}{Location}{Name}`
/// because `Location` is one of the four fixed titles and none of them is `RequestBody`; the same
/// bump loop as `operation_parameter_validator_names` resolves fields that collapse onto one
/// identifier under Pascal normalization. Discriminated arms go through `response_media_names`, so
/// a lone JSON arm keeps the bare name and two or more are tagged by media.
///
/// *Order*: `build_body_plan` sorts discriminated arms by media type, so arm order is **not**
/// declaration order. Both emitters read that same sorted slice, so positional derivation agrees —
/// but note the contrast with the response side, which preserves declared media order; applying one
/// side's assumption to the other silently swaps which schema each name describes.
///
/// There used to be a fourth case here, for a body the validators counted as JSON while
/// `build_body_plan` counted as text — the two disagreed about `text/json` — which produced a
/// validator export nothing could call. One predicate answers both questions now, so that position
/// cannot arise and the arm that carried it is gone.
pub(super) fn request_body_validator_positions<'a>(
    body: &'a Body,
    plan: Option<&'a BodyPlan>,
    stem: &str,
) -> Vec<RequestBodyPosition<'a>> {
    let base = format!("{stem}RequestBody");
    let Some(plan) = plan else {
        return Vec::new();
    };
    match plan {
        BodyPlan::Json { media, .. } => body
            .media_types
            .iter()
            .find(|entry| &entry.full == media)
            .map(|entry| {
                vec![RequestBodyPosition {
                    name: base,
                    schema: &entry.schema,
                    access: RequestBodyAccess::Whole,
                    guarded: !body.required,
                }]
            })
            .unwrap_or_default(),
        // None of the three carries a schema value a validator or a transform could bind to: a text
        // body renders `string` whatever its schema says, binary bodies are opaque bytes, and a
        // streaming body has no whole value at all.
        BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::TopLevelStream { .. } => Vec::new(),
        BodyPlan::FormUrlencoded { fields, .. } | BodyPlan::Multipart { fields, .. } => {
            form_field_positions(fields, &base, body.required)
        }
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            discriminated_arm_positions(body, arms, &base)
        }
    }
}

/// One position per form field that carries a schema value. A binary upload renders `Blob | File`,
/// so it has no schema value to check and contributes nothing.
fn form_field_positions<'a>(
    fields: &'a [FormFieldPlan],
    base: &str,
    body_required: bool,
) -> Vec<RequestBodyPosition<'a>> {
    let mut used: HashSet<String> = HashSet::new();
    // Seeded so a field whose fragment is empty cannot land on the bare body name.
    used.insert(base.to_owned());
    let mut positions = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        if field.is_binary_upload() {
            continue;
        }
        let fragment = normalize_identifier(&field.name, TargetCase::Pascal)
            .unwrap_or_else(|_| format!("Field{index}"));
        let candidate = format!("{base}{fragment}");
        let mut name = candidate.clone();
        let mut suffix = index;
        while !used.insert(name.clone()) {
            name = format!("{candidate}{suffix}");
            suffix += 1;
        }
        positions.push(RequestBodyPosition {
            name,
            schema: &field.schema,
            access: RequestBodyAccess::Field {
                key: field.name.clone(),
                wrapped: field.wrapper.wrapped,
            },
            // An absent body makes every field access absent too, so a required field still needs
            // the guard when the body itself is optional.
            guarded: !field.required || !body_required,
        });
    }
    positions
}

/// One position per arm whose own plan is JSON. A text or binary arm carries nothing to check.
///
/// The schema comes from the arm's IR media entry rather than from `BodyPlan::Json::schema`, which
/// is `None` for a media object that declared no schema — taking it from the plan would delete the
/// export such a body already has.
fn discriminated_arm_positions<'a>(
    body: &'a Body,
    arms: &'a [BodyPlanArm],
    base: &str,
) -> Vec<RequestBodyPosition<'a>> {
    let json = arms
        .iter()
        .filter(|arm| matches!(arm.plan, BodyPlan::Json { .. }))
        .filter_map(|arm| {
            body.media_types
                .iter()
                .find(|entry| entry.full == arm.media)
                .map(|entry| (arm, &entry.schema))
        })
        .collect::<Vec<_>>();
    let medias = json
        .iter()
        .map(|(arm, _)| arm.media.as_str())
        .collect::<Vec<_>>();
    json.iter()
        .zip(response_media_names(base, &medias))
        .map(|((arm, schema), name)| RequestBodyPosition {
            name: name.name,
            schema,
            // The content-type test doubles as the presence guard: an absent body has no
            // `contentType` to match.
            access: RequestBodyAccess::Arm {
                media: arm.media.clone(),
            },
            guarded: false,
        })
        .collect()
}

/// Inserts the `esnext.temporal` lib reference into an assembled file that names a `Temporal` type.
///
/// Not a workaround for missing TypeScript support — the compiler ships `lib.esnext.temporal` — but
/// how a generated file opts a consumer whose own `lib` predates it into the declarations this
/// file's types need. Derived from the emitted text rather than from configuration, so a file that
/// happens to name no Temporal type never carries one, and the two can never disagree.
///
/// It goes after the generated header, which is the first line of every emitted file: a triple-slash
/// directive may be preceded by comments, and by nothing else.
pub(super) fn insert_temporal_reference(
    content: String,
    header_len: usize,
    consumer_provides_temporal: bool,
) -> String {
    if consumer_provides_temporal || !content[header_len..].contains("Temporal.") {
        return content;
    }
    let mut output = String::with_capacity(content.len() + TEMPORAL_REFERENCE.len());
    output.push_str(&content[..header_len]);
    output.push_str(TEMPORAL_REFERENCE);
    output.push_str(&content[header_len..]);
    output
}

const TEMPORAL_REFERENCE: &str = "/// <reference lib=\"esnext.temporal\" preserve=\"true\" />\n\n";

/// The same directive as an embedded asset writes it — one newline, not the blank line the inserter
/// adds — so an asset that ships with it can have it taken back out.
const TEMPORAL_REFERENCE_LINE: &str =
    "/// <reference lib=\"esnext.temporal\" preserve=\"true\" />\n";

/// Removes an embedded asset's own leading Temporal reference.
///
/// Assets that name `Temporal` carry the directive in their source rather than getting it from
/// `insert_temporal_reference`, so a consumer whose `lib` already declares Temporal needs it taken
/// off here too — otherwise one file keeps a directive every other file dropped.
pub(super) fn strip_temporal_reference(asset: &str, consumer_provides_temporal: bool) -> &str {
    if consumer_provides_temporal {
        asset.strip_prefix(TEMPORAL_REFERENCE_LINE).unwrap_or(asset)
    } else {
        asset
    }
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

pub(super) fn warning_diagnostic(
    code: &'static str,
    message: impl Into<String>,
    source: &SourceRef,
) -> Diagnostic {
    let mut diagnostic = source_diagnostic(code, message, source);
    diagnostic.severity = Severity::Warning;
    diagnostic
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

    /// Generic types TypeScript declares globally. Emitted code that names one of these inside a
    /// module that also declares or imports a component type gets the component instead of the
    /// built-in — `TS2315: Type 'X' is not generic` — because a local binding wins over a global.
    /// Qdrant declares a component named `Record`, and that is exactly what broke.
    ///
    /// The emitters stay clear of these two ways: an index signature is spelled structurally rather
    /// than as `Record<string, V>`, and the client aliases a component import that carries a name
    /// its own signatures use (`CLIENT_MODULE_BINDINGS`). Neither is self-enforcing, so this test
    /// is what keeps a newly written emitter from reintroducing the bug.
    const TS_GLOBAL_GENERICS: &[&str] = &[
        "Array",
        "AsyncGenerator",
        "AsyncIterable",
        "AsyncIterableIterator",
        "AsyncIterator",
        "Awaited",
        "Exclude",
        "Extract",
        "Generator",
        "InstanceType",
        "Iterable",
        "IterableIterator",
        "Iterator",
        "Map",
        "NoInfer",
        "NonNullable",
        "Omit",
        "OmitThisParameter",
        "Parameters",
        "Partial",
        "Pick",
        "Promise",
        "PromiseLike",
        "Readonly",
        "ReadonlyArray",
        "ReadonlyMap",
        "ReadonlySet",
        "Record",
        "Required",
        "ReturnType",
        "Set",
        "ThisParameterType",
        "ThisType",
        "Uint8Array",
        "WeakMap",
        "WeakRef",
        "WeakSet",
    ];

    /// Drops comments so a schema `description` echoed into TSDoc cannot read as emitted code.
    fn strip_ts_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let bytes = source.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index..].starts_with(b"//") {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            } else if bytes[index..].starts_with(b"/*") {
                index += 2;
                while index < bytes.len() && !bytes[index..].starts_with(b"*/") {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            } else {
                out.push(char::from(bytes[index]));
                index += 1;
            }
        }
        out
    }

    /// Every `Name<` in `code` whose `Name` is a global generic, ignoring occurrences that are the
    /// tail of a longer identifier (`SyncStandardSchemaV1<` must not read as a `Set<`).
    fn builtin_generic_references(code: &str) -> Vec<&'static str> {
        let bytes = code.as_bytes();
        let mut found = Vec::new();
        for name in TS_GLOBAL_GENERICS {
            let mut from = 0;
            while let Some(offset) = code[from..].find(&format!("{name}<")) {
                let start = from + offset;
                let preceded_by_identifier = start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric()
                        || bytes[start - 1] == b'_'
                        || bytes[start - 1] == b'$'
                        || bytes[start - 1] == b'.');
                if !preceded_by_identifier {
                    found.push(*name);
                    break;
                }
                from = start + name.len();
            }
        }
        found
    }

    /// Every identifier an emitted module binds in its own scope: the local name of each named
    /// import (an `A as B` clause binds `B`, not `A`) and each top-level declaration. Emitted code
    /// is machine-written and one declaration per line, so this reads it directly rather than
    /// pulling in a parser.
    fn module_bindings(code: &str) -> BTreeSet<&str> {
        let mut bound = BTreeSet::new();
        for line in code.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("import ") {
                // Named-import clauses only. The emitters write no default or namespace import, so
                // a line without braces contributes nothing; reading it as empty keeps that case
                // off a branch of its own.
                let names = rest
                    .split_once('{')
                    .and_then(|(_, tail)| tail.split_once('}'))
                    .map_or("", |(names, _)| names);
                for clause in names.split(',') {
                    let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
                    let name = clause.rsplit(" as ").next().unwrap_or(clause).trim();
                    if !name.is_empty() {
                        bound.insert(name);
                    }
                }
                continue;
            }
            let declaration = line.strip_prefix("export ").unwrap_or(line);
            let declaration = declaration
                .strip_prefix("declare ")
                .unwrap_or(declaration)
                .strip_prefix("async ")
                .unwrap_or(declaration);
            for keyword in [
                "interface ",
                "type ",
                "function ",
                "const ",
                "let ",
                "var ",
                "class ",
                "enum ",
            ] {
                let Some(rest) = declaration.strip_prefix(keyword) else {
                    continue;
                };
                let name = rest
                    .split(|character: char| {
                        !character.is_ascii_alphanumeric() && character != '_' && character != '$'
                    })
                    .next()
                    .unwrap_or_default();
                if !name.is_empty() {
                    bound.insert(name);
                }
                break;
            }
        }
        bound
    }

    /// A document whose components carry the names of TypeScript's global generics, reached through
    /// every position that puts a component type into a module: a `$ref` parameter, a request body,
    /// a response body, and a property of another component. The `properties` + `additionalProperties`
    /// pair is what reaches the intersection spelling, and the `date-time` property is what reaches
    /// the transform axis.
    fn builtin_named_document() -> Value {
        let mut schemas = serde_json::Map::new();
        let mut paths = serde_json::Map::new();
        for name in TS_GLOBAL_GENERICS {
            schemas.insert(
                (*name).to_owned(),
                json!({ "type": "string", "enum": ["a", "b"] }),
            );
            schemas.insert(
                format!("{name}Holder"),
                json!({
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": { "type": "string" },
                        "at": { "type": "string", "format": "date-time" },
                        "nested": { "$ref": format!("#/components/schemas/{name}") }
                    },
                    "additionalProperties": { "type": "number" }
                }),
            );
            paths.insert(
                format!("/probe/{}", name.to_lowercase()),
                json!({
                    "post": {
                        "operationId": format!("probe{name}"),
                        "parameters": [{
                            "name": "mode",
                            "in": "query",
                            "required": true,
                            "schema": { "$ref": format!("#/components/schemas/{name}") }
                        }],
                        "requestBody": {
                            "required": true,
                            "content": { "application/json": {
                                "schema": { "$ref": format!("#/components/schemas/{name}Holder") }
                            } }
                        },
                        "responses": { "200": {
                            "description": "ok",
                            "content": { "application/json": {
                                "schema": { "$ref": format!("#/components/schemas/{name}Holder") }
                            } }
                        } }
                    }
                }),
            );
        }
        json!({
            "openapi": "3.1.0",
            "info": { "title": "builtin names", "version": "1" },
            "servers": [{ "url": "https://api.example.test" }],
            "paths": Value::Object(paths),
            "components": { "schemas": Value::Object(schemas) }
        })
    }

    /// Compiles `document` with every artifact on, `patch` applied to the resolved config after it
    /// loads. The patch seam exists because the date/time transform is refused by config validation
    /// in this build, and its emitted modules still have to be held to the invariant.
    fn compile_all_artifacts(
        document: Value,
        patch: fn(&mut ResolvedConfig),
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
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true, "client": true, "validators": true },
                "client": { "baseUrl": { "source": "server", "index": 0 } },
                "validation": { "engine": "generated", "request": true, "response": true, "unchecked": "allow" }
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
        let client = crate::client_model::build_client_model(&analyzed, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &graph.source_tuples(),
            Some(&client),
            &mut sink,
        );
        (files, sink.into_sorted_vec())
    }

    /// No emitted module may both bind a name and use that name as a generic: the local binding
    /// wins over the global, and the built-in stops resolving (`TS2315`). Naming a built-in is
    /// fine on its own — `client/operations/*` writes `Promise<Result>` and stays correct because
    /// a colliding component import is aliased away — so the invariant is the co-occurrence, not
    /// the reference.
    ///
    /// Stated over emitted output rather than over the emitters, so it holds no matter which
    /// mechanism a given emitter uses to stay clear: the structural index signature in the types
    /// and validators artifacts, `CLIENT_MODULE_BINDINGS` in the client. Run against a document
    /// that names every global generic, so a regression fails here rather than on a user's corpus.
    #[test]
    fn no_builtin_generics_in_schema_bearing_modules() {
        let (files, diagnostics) = compile_all_artifacts(builtin_named_document(), |config| {
            config.types.date_time = crate::config::DateTimeRepresentation::Date;
        });
        // Asserted as "no diagnostics at all" rather than "no errors": a predicate over an empty
        // list never runs its closure, and the coverage gate reads that as a dead line.
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        // One report line per module that names a global generic at all, listing the ones it also
        // binds. Built for every such module rather than only for offenders, so the reporting path
        // runs on a passing run — a report assembled only on failure is dead code the coverage
        // gate rejects, and is also the shape most likely to be broken when it finally runs.
        let mut report = Vec::new();
        let mut shadowing = 0usize;
        for file in &files {
            let code = strip_ts_comments(&file.content);
            let referenced = builtin_generic_references(&code);
            if referenced.is_empty() {
                continue;
            }
            let bound = module_bindings(&code);
            let shadowed = referenced
                .iter()
                .filter(|name| bound.contains(*name))
                .copied()
                .collect::<Vec<_>>();
            shadowing += usize::from(!shadowed.is_empty());
            report.push(format!(
                "{}: uses {} / shadows {}",
                file.relative_path,
                referenced.join(", "),
                shadowed.join(", ")
            ));
        }
        let message = report.join("\n");
        assert!(
            !report.is_empty(),
            "no emitted module names a global generic at all, so this test proves nothing"
        );
        assert_eq!(
            shadowing, 0,
            "emitted modules bind a name they also use as a TypeScript global generic:\n{message}"
        );

        // Positive controls, so a broken reader cannot pass this test by finding nothing. The
        // document guarantees both files exist and both are exactly the shapes that used to break.
        let record = find_file(&files, "types/components/recordholder.ts");
        assert!(record.content.contains("} & { [key: string]: number };"));
        let client = find_file(&files, "client/operations/probepromise.ts");
        assert!(
            client
                .content
                .contains("import type { Promise as PromiseBody } from")
        );
        assert!(
            builtin_generic_references(&strip_ts_comments(&client.content)).contains(&"Promise")
        );
    }

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

    fn prop_meta() -> PropMeta {
        PropMeta {
            required: false,
            read_only: false,
            write_only: false,
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

        let diagnostic = source_diagnostic("TEST", "located", &source("/located"));
        assert_eq!((diagnostic.line, diagnostic.col), (Some(3), Some(5)));
    }

    #[test]
    fn emitter_validates_nested_refs_and_discriminators() {
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
                    prop_meta(),
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);
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
                .filter(|diagnostic| diagnostic.code == CODE_UNALLOCATED_REFERENCE)
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
        let added = &diagnostics[before..];
        assert_eq!(added.len(), 1, "{added:?}");
        assert_eq!(added[0].code, CODE_DISCRIMINATOR_NARROWING);
        assert_eq!(added[0].severity, Severity::Warning);
        assert!(added[0].message.contains("optional"), "{added:?}");
        assert!(added[0].message.contains("exhaustive"), "{added:?}");
        emitter.validate_schema(
            &SchemaNode::OneOf {
                branches: Vec::new(),
                discriminator: None,
                meta: meta("/no-discriminator"),
            },
            &mut diagnostics,
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);
        assert!(
            emitter
                .resolve_ref(&self_ref, &mut HashSet::new())
                .is_none()
        );
        assert_eq!(
            emitter.render_type(
                &schema_ref("/unknown-ref", "/components/schemas/Unknown"),
                TypePosition::Neutral,
                TypeAxis::Application,
                0,
            ),
            "unknown"
        );
        assert_eq!(
            emitter.render_type(
                &primitive(PrimitiveType::Null, "/null"),
                TypePosition::Neutral,
                TypeAxis::Application,
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
                SchemaNode::OneOf {
                    branches: Vec::new(),
                    discriminator: None,
                    meta: meta("/empty-one-of"),
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
                emitter.render_type(&schema, TypePosition::Neutral, TypeAxis::Application, 0),
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
            TypeAxis::Application,
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);

        let unknown = |reason: &str, pointer: &str| SchemaNode::Unknown {
            reason: reason.to_owned(),
            meta: meta(pointer),
        };
        let object = SchemaNode::Object {
            properties: vec![(
                "a".to_owned(),
                primitive(PrimitiveType::String, "/object/a"),
                prop_meta(),
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
            emitter.render_type(
                &conjunction,
                TypePosition::Neutral,
                TypeAxis::Application,
                0
            ),
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
            emitter.render_type(
                &duplicate_unknowns,
                TypePosition::Neutral,
                TypeAxis::Application,
                0
            ),
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
            emitter.render_type(&distinct, TypePosition::Neutral, TypeAxis::Application, 0),
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
            emitter.render_type(
                &boolean_schemas,
                TypePosition::Neutral,
                TypeAxis::Application,
                0
            ),
            "unknown | never | string"
        );

        let only_unknown = SchemaNode::AllOf {
            branches: vec![SchemaNode::Any {
                meta: meta("/all-unknown/true"),
            }],
            meta: meta("/all-unknown"),
        };
        assert_eq!(
            emitter.render_type(
                &only_unknown,
                TypePosition::Neutral,
                TypeAxis::Application,
                0
            ),
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);

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
            emitter.render_type(
                &conjunction,
                TypePosition::Neutral,
                TypeAxis::Application,
                0
            ),
            r#"string & (string | number) & (string | null) & ("a" | "b") & (string | number)[]"#,
        );

        // `[]` binds tighter than `|`, so an enum item has to be parenthesized: without it
        // `"a" | "b"[]` reads as a union of `"a"` and `"b"[]` rather than an array of the union.
        // An `enum` primitive is neither a composition node nor nullable, so the node-kind test
        // alone misses it — real specs (stripe's `available_payout_methods`) hit this.
        let enum_array = SchemaNode::Array {
            items: Box::new(SchemaNode::Primitive {
                ty: PrimitiveType::String,
                format: None,
                enum_values: Some(vec![json!("instant"), json!("standard")]),
                const_value: None,
                meta: meta("/enum-item"),
            }),
            finite: None,
            meta: meta("/enum-array"),
        };
        assert_eq!(
            emitter.render_type(&enum_array, TypePosition::Neutral, TypeAxis::Application, 0),
            r#"("instant" | "standard")[]"#,
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
        // The primitive domains are disjoint, so the existing composition check now fires OASTS4201 on
        // a spec that used to be silently wrong.
        let (files, diagnostics) = compile(
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
        assert!(
            diagnostics.iter().all(|diagnostic| {
                diagnostic.code != CODE_COMPOSITION
                    || diagnostic.severity == crate::diag::Severity::Warning
            }),
            "{diagnostics:?}"
        );
        assert!(
            schema_file(&files, "thing")
                .content
                .contains("export type Thing = never;")
        );
    }

    #[test]
    fn lowered_conjunction_compatible_no_diag() {
        // A compatible coexistence — string on both the allOf branch and the typed piece — intersects
        // to a non-empty domain, so no OASTS4201.
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
        // JSONSchemaProps idiom — must not inline forever. Cycles are legal when they form
        // recursive schemas, and this once overflowed the stack.
        //
        // The assertion is unchanged but the mechanism behind it is not. The merge used to
        // inline the ref one level and an explicit cycle-guard stack stopped the second
        // level; now the ref never enters the merge at all, so it renders as the bare named
        // type on the first pass and there is no cycle to guard.
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
                prop_meta(),
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);

        // Terminates (no stack overflow) and the recursive branch is the bare named type.
        let rendered =
            emitter.render_type(&recursive, TypePosition::Neutral, TypeAxis::Application, 0);
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let emitter = Emitter::new(&model);

        let first = object(
            "/closed-one",
            vec![(
                "one".to_owned(),
                primitive(PrimitiveType::String, "/closed-one/one"),
                prop_meta(),
            )],
            AdditionalProperties::Forbidden,
        );
        let second = object(
            "/closed-two",
            vec![(
                "two".to_owned(),
                primitive(PrimitiveType::String, "/closed-two/two"),
                prop_meta(),
            )],
            AdditionalProperties::Forbidden,
        );
        assert!(emitter.merge_all_of(&[first, second]).is_none());

        let equal_property = (
            "same".to_owned(),
            primitive(PrimitiveType::String, "/equal/same"),
            prop_meta(),
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
                prop_meta(),
            )],
            AdditionalProperties::Allowed(None),
        );
        let mut required = prop_meta();
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
            TypeAxis::Application,
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
                TypeAxis::Application,
                0,
            ),
            "unknown"
        );
    }

    #[test]
    fn prewarm_covers_alias_cycle_and_schema_additional_properties() {
        // Direct IR construction, since the analyzer never emits these shapes. An `allOf`
        // whose ref branch chains through a ref-alias cycle (AliasA -> AliasB -> AliasA)
        // drives `resolve_ref`'s cycle guard during prewarm, and an object with a
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let (files, diagnostics) = Emitter::new(&model).emit();
        assert!(diagnostics.is_empty());
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
        // Differential guard for the cached prewarm and uncached fallback paths: for every
        // IR-resident allOf slice in the composition-stressor fixture, both must retain the
        // identical merge. This would catch a future prewarm-specific resolver or merger
        // diverging from the fallback over real analyzer output, not one hand-picked shape.
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
            let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
            let mut emitter = Emitter::new(&model);
            let mut slices = Vec::new();
            for schema in &analyzed.ir.schemas {
                collect_all_of(&schema.schema, &mut slices);
            }
            compared += slices.len();
            for branches in slices {
                let fallback = emitter
                    .merge_all_of(branches)
                    .map(|(properties, additional)| (properties, additional.clone()));
                emitter.cache_merge_all_of(branches);
                let key = (branches.as_ptr().addr(), branches.len());
                let prewarm = emitter
                    .merge_cache
                    .get(&key)
                    .cloned()
                    .expect("non-empty allOf slice is cached")
                    .map(|(properties, additional)| (properties.to_vec(), additional.clone()));
                assert_eq!(prewarm, fallback);
            }

            // The empty slice shares the dangling-pointer sentinel with every other empty
            // Vec, so cache_merge_all_of must refuse to key it.
            let cached = emitter.merge_cache.len();
            emitter.cache_merge_all_of(&[]);
            assert_eq!(emitter.merge_cache.len(), cached);
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
            tags: Vec::new(),
            path: None,
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
            tags: Vec::new(),
            path: None,
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
        let model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let (files, diagnostics) = Emitter::new(&model).emit();
        model.sink.extend(diagnostics);
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
    fn an_object_with_no_properties_is_not_the_empty_type() {
        // `{}` in TypeScript means "anything except null/undefined", so a field typed `{}`
        // accepts 42 and "hello". An index signature says what the document actually said.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "Odd": { "type": "object", "properties": {
                    "openTrue": { "type": "object", "additionalProperties": true },
                    "openOmitted": { "type": "object", "properties": {} },
                    "closed": { "type": "object", "additionalProperties": false }
                } }
            })),
            json!({}),
        );
        let odd = generated_body(schema_file(&files, "odd"));
        assert!(
            odd.contains("openTrue?: { [key: string]: unknown };"),
            "{odd}"
        );
        assert!(
            odd.contains("openOmitted?: { [key: string]: unknown };"),
            "{odd}"
        );
        assert!(odd.contains("closed?: { [key: string]: never };"), "{odd}");
        assert!(
            !odd.contains(": {};"),
            "no bare empty type may survive: {odd}"
        );
    }

    #[test]
    fn a_top_level_empty_object_is_not_an_empty_interface() {
        // `interface X {}` has the identical hole `{}` has: 42 is assignable to it.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "Bag": { "type": "object", "additionalProperties": true }
            })),
            json!({}),
        );
        let bag = generated_body(schema_file(&files, "bag"));
        assert!(
            bag.contains("export type Bag = { [key: string]: unknown };"),
            "{bag}"
        );
        assert!(!bag.contains("export interface Bag {}"), "{bag}");
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
        // The index-signature half is written structurally, not as `Record<string, number>` —
        // see `render_object_literal`. A component named `Record` declares a non-generic type in
        // this same module, and the built-in would resolve to it (TS2315).
        assert!(bodies["types/components/mixed.ts"].contains("} & { [key: string]: number };"));
        assert!(bodies["types/components/closed.ts"].contains("export interface Closed"));
    }

    #[test]
    fn pattern_properties_emit_intersected_index_signatures_without_widening_declared_members() {
        let document = openapi(json!({
            "Patterned": {
                "type": "object",
                "properties": {
                    "fixed": { "type": "string" }
                },
                "patternProperties": {
                    "^x-": { "type": "number" },
                    "flag": { "type": "boolean" }
                }
            },
            "OnlyPattern": {
                "type": "object",
                "patternProperties": {
                    "^x-": { "type": "number" }
                }
            },
            "PatternedAllOf": {
                "allOf": [
                    {
                        "type": "object",
                        "patternProperties": {
                            "^x-": { "type": "number" }
                        }
                    },
                    {
                        "type": "object",
                        "properties": {
                            "fixed": { "type": "string" }
                        }
                    }
                ]
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let patterned = files
            .iter()
            .find(|file| file.relative_path.ends_with("patterned.ts"))
            .expect("Patterned file");
        let body = generated_body(patterned);
        assert!(body.contains("export type Patterned = {"));
        assert!(body.contains("fixed?: string;"));
        assert!(body.contains("& { [key: `x-${string}`]: number }"));
        assert!(body.contains("& { [key: `${string}flag${string}`]: boolean };"));
        assert!(!body.contains("fixed?: string |"));
        let only_pattern = files
            .iter()
            .find(|file| file.relative_path.ends_with("onlypattern.ts"))
            .expect("OnlyPattern file");
        // The pattern signature stands alone: it already says which keys exist and what they
        // hold. Intersecting the empty object's own index signature onto it would widen the
        // value type back to `unknown`, and anything reading the result through
        // `Object.entries` would see `unknown` instead of the pattern's type.
        let only_pattern_body = generated_body(only_pattern);
        assert!(
            only_pattern_body
                .contains("export type OnlyPattern = { [key: `x-${string}`]: number };"),
            "{only_pattern_body}"
        );
        assert!(
            !only_pattern_body.contains("[key: string]: unknown"),
            "{only_pattern_body}"
        );
        let patterned_all_of = files
            .iter()
            .find(|file| file.relative_path.ends_with("patternedallof.ts"))
            .expect("PatternedAllOf file");
        let all_of_body = generated_body(patterned_all_of);
        assert!(all_of_body.contains("{ [key: `x-${string}`]: number } & {"));
        assert!(all_of_body.contains("fixed?: string;"));
    }

    #[test]
    fn pattern_property_type_keys_cover_faithful_literal_regex_forms_and_skip_end_anchors() {
        let document = openapi(json!({
            "Forms": {
                "type": "object",
                "patternProperties": {
                    "": { "type": "string" },
                    "^exact$": { "type": "number" },
                    "mid": { "type": "boolean" },
                    "tail$": { "type": "null" },
                    "[a-z]": { "type": "integer" }
                }
            },
            "SchemaAdditional": {
                "type": "object",
                "patternProperties": {
                    "^x": { "type": "string" }
                },
                "additionalProperties": { "type": "number" }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS2201")
                .count(),
            4,
            "{diagnostics:?}"
        );
        let forms = files
            .iter()
            .find(|file| file.relative_path.ends_with("forms.ts"))
            .expect("Forms file");
        let body = generated_body(forms);
        assert!(body.contains("{ [key: string]: string }"));
        assert!(body.contains("{ [key: `${string}mid${string}`]: boolean }"));
        assert!(!body.contains("exact?: number"));
        assert!(!body.contains("${string}tail"));
        assert!(!body.contains("integer"));
        let schema_additional = files
            .iter()
            .find(|file| file.relative_path.ends_with("schemaadditional.ts"))
            .expect("SchemaAdditional file");
        let body = generated_body(schema_additional);
        assert!(body.contains("{ [key: string]: number }"));
        assert!(!body.contains("x-${string}"));
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
                " * \n",
                " * This is the shape declared by the document, not a wire shape for any single message. Use {@link PetRequest} for what a caller sends and {@link PetResponse} for what the server returns.\n",
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
    fn neutral_variant_tsdoc_names_both_wire_shapes_and_preserves_description() {
        let document = openapi(json!({
            "Widget": {
                "description": "A catalog widget.",
                "type": "object",
                "required": ["id", "name"],
                "properties": {
                    "id": { "type": "string", "readOnly": true },
                    "secret": { "type": "string", "writeOnly": true },
                    "name": { "type": "string" }
                }
            },
            "ReadOnlyWidget": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "readOnly": true },
                    "name": { "type": "string" }
                }
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let widget = generated_body(schema_file(&files, "widget"));
        let guidance = "This is the shape declared by the document, not a wire shape for any single message. Use {@link WidgetRequest} for what a caller sends and {@link WidgetResponse} for what the server returns.";
        assert_eq!(widget.matches(guidance).count(), 1, "{widget}");
        assert!(
            widget.contains(&format!(
                concat!(
                    "/**\n",
                    " * A catalog widget.\n",
                    " * \n",
                    " * @remarks\n",
                    " * {}\n",
                    " */\n",
                    "export interface Widget {{"
                ),
                guidance
            )),
            "{widget}"
        );

        let read_only = generated_body(schema_file(&files, "readonlywidget"));
        assert!(
            read_only.contains("export interface ReadOnlyWidgetRequest {")
                && !read_only.contains("ReadOnlyWidgetResponse")
                && !read_only.contains("shape declared by the document"),
            "{read_only}"
        );
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
    fn enum_members_outside_declared_types_are_warned_and_filtered() {
        let document = openapi(json!({
            "StringChoice": {
                "type": "string",
                "enum": ["on", "off", false]
            },
            "IntegerChoice": {
                "type": "integer",
                "enum": [1, "one"]
            },
            "BooleanChoice": {
                "type": "boolean",
                "enum": [true, 1]
            },
            "FilteredIntersection": {
                "type": "string",
                "enum": ["keep", false],
                "const": "keep"
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS3101")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 4);
        assert!(warnings.iter().all(|diagnostic| {
            diagnostic.severity == Severity::Warning
                && diagnostic.message.contains("can never validate")
                && diagnostic.message.contains("generated type and validator")
                && !diagnostic.message.contains("YAML")
        }));
        for (file_name, expected) in [
            (
                "stringchoice.ts",
                "export type StringChoice = \"on\" | \"off\";\n",
            ),
            ("integerchoice.ts", "export type IntegerChoice = 1;\n"),
            ("booleanchoice.ts", "export type BooleanChoice = true;\n"),
            (
                "filteredintersection.ts",
                "export type FilteredIntersection = \"keep\";\n",
            ),
        ] {
            let file = files
                .iter()
                .find(|file| file.relative_path.ends_with(file_name))
                .expect("generated type");
            assert!(generated_body(file).ends_with(expected), "{file_name}");
        }
    }

    #[test]
    fn nullable_enum_null_survives_without_a_warning() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "test", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "NullableChoice": {
                        "type": "string",
                        "nullable": true,
                        "enum": ["value", null]
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(
            generated_body(&files[0]).ends_with("export type NullableChoice = \"value\" | null;\n")
        );
    }

    #[test]
    fn exhausted_enum_and_out_of_domain_const_lower_to_never() {
        let document = openapi(json!({
            "Exhausted": {
                "type": "string",
                "enum": [false]
            },
            "ImpossibleConst": {
                "type": "integer",
                "const": "one"
            }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS3101")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 3);
        assert!(
            warnings
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
        assert!(
            warnings
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("admits no value"))
                .count()
                == 2
        );
        for file in files.iter().filter(|file| {
            file.relative_path.ends_with("exhausted.ts")
                || file.relative_path.ends_with("impossibleconst.ts")
        }) {
            assert!(generated_body(file).ends_with(" = never;\n"));
        }
    }

    #[test]
    fn literally_empty_enum_warns_and_emits_never_in_openapi_31() {
        let (files, diagnostics) = compile(
            openapi(json!({
                "Empty": {
                    "type": "string",
                    "enum": []
                }
            })),
            json!({}),
        );
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "OASTS3101")
            .expect("empty enum diagnostic");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert!(diagnostic.message.contains("OpenAPI 3.1 (SHOULD)"));
        assert!(generated_body(&files[0]).ends_with("export type Empty = never;\n"));
    }

    #[test]
    fn filtering_keeps_enum_extension_names_aligned_with_survivors() {
        let document = openapi(json!({
            "Mode": {
                "type": "string",
                "enum": ["on", false, "off"],
                "x-enum-varnames": ["Enabled", "Wrong", "Disabled"],
                "x-enumNames": ["Enabled", "Wrong", "Disabled"],
                "x-enum-descriptions": ["enabled", "wrong", "disabled"],
                "x-enumDescriptions": ["enabled", "wrong", "disabled"]
            }
        }));
        let (files, diagnostics) = compile(document, json!({ "types": { "enum": "const" } }));
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS3101")
                .count(),
            1
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("enum extension") })
        );
        let body = generated_body(&files[0]);
        assert!(body.contains("Enabled: \"on\""));
        assert!(body.contains("Disabled: \"off\""));
        assert!(!body.contains("Wrong"));
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
        // Two: the discriminator warning above, and OASTS4206 for `Intersected`. `Cat & Dog`
        // types `kind` as `"cat" & "dog"`, so that one property really is uninhabitable —
        // the intersection is still what gets emitted, and the warning is the only thing
        // that says the property inside it collapsed.
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == Severity::Warning)
                .count(),
            2
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
        let conflicting = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_CONFLICTING_PROPERTY)
            .collect::<Vec<_>>();
        assert_eq!(conflicting.len(), 1, "{diagnostics:?}");
        assert!(conflicting[0].message.contains("kind"), "{conflicting:?}");
    }

    #[test]
    fn all_of_preserves_ref_identity() {
        // The same probe pair in every composition shape that can carry a `$ref`. `allOf`
        // used to resolve its members and print the merged property bag, which is the one
        // place a `$ref` stopped being a name. Structure alone cannot tell the inlined
        // literal from the component it copied, so this asserts the emitted text — the
        // fixtures under fixtures/composition-identity-* carry the tsc-verified half.
        let document = openapi(json!({
            "WidgetMeta": { "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } },
            "OtherMeta": { "type": "object", "required": ["b"], "properties": { "b": { "type": "string" } } },
            "ViaRef": { "$ref": "#/components/schemas/WidgetMeta" },
            "ViaOneOf": { "oneOf": [{ "$ref": "#/components/schemas/WidgetMeta" }, { "$ref": "#/components/schemas/OtherMeta" }] },
            "ViaAnyOf": { "anyOf": [{ "$ref": "#/components/schemas/WidgetMeta" }, { "$ref": "#/components/schemas/OtherMeta" }] },
            "ViaAnyOfNull": { "anyOf": [{ "$ref": "#/components/schemas/WidgetMeta" }, { "type": "null" }] },
            "ViaAllOfOne": { "allOf": [{ "$ref": "#/components/schemas/WidgetMeta" }] },
            "ViaAllOfOneDescribed": { "description": "a quoted ref", "allOf": [{ "$ref": "#/components/schemas/WidgetMeta" }] },
            "ViaAllOfTwo": { "allOf": [{ "$ref": "#/components/schemas/WidgetMeta" }, { "$ref": "#/components/schemas/OtherMeta" }] },
            "ViaAllOfMixed": { "allOf": [
                { "$ref": "#/components/schemas/WidgetMeta" },
                { "type": "object", "properties": { "c": { "type": "string" } } }
            ] },
            "ViaAllOfInline": { "allOf": [
                { "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } },
                { "type": "object", "properties": { "b": { "type": "string" } } }
            ] }
        }));
        let (files, _diagnostics) = compile(document, json!({}));
        let rendered = |base: &str| generated_body(schema_file(&files, base)).to_owned();

        // The six shapes that already named their members. These must not move.
        assert!(rendered("viaref").contains("export type ViaRef = WidgetMeta;"));
        assert!(rendered("viaoneof").contains("export type ViaOneOf = WidgetMeta | OtherMeta;"));
        assert!(rendered("viaanyof").contains("export type ViaAnyOf = WidgetMeta | OtherMeta;"));
        assert!(rendered("viaanyofnull").contains("export type ViaAnyOfNull = WidgetMeta | null;"));
        // An `allOf` of two anonymous objects still folds to one object literal: identity-first
        // changes what happens to `$ref` branches, not to anonymous ones.
        let inline = rendered("viaallofinline");
        assert!(
            inline.contains("export type ViaAllOfInline = {\n  a: string;\n  b?: string;\n};"),
            "{inline}"
        );

        // A single `$ref`, with and without an annotation sibling: the quoting idiom, not
        // composition. A one-member join is the member.
        let one = rendered("viaallofone");
        assert!(
            one.contains("export type ViaAllOfOne = WidgetMeta;"),
            "{one}"
        );
        let described = rendered("viaallofonedescribed");
        assert!(
            described.contains("export type ViaAllOfOneDescribed = WidgetMeta;"),
            "{described}"
        );
        assert!(described.contains("a quoted ref"), "{described}");

        // More than one member: each keeps its identity and they join with `&`.
        let two = rendered("viaalloftwo");
        assert!(
            two.contains("export type ViaAllOfTwo = WidgetMeta & OtherMeta;"),
            "{two}"
        );
        let mixed = rendered("viaallofmixed");
        assert!(
            mixed.contains("export type ViaAllOfMixed = WidgetMeta & {")
                && mixed.contains("c?: string;"),
            "{mixed}"
        );
    }

    #[test]
    fn conflicting_property_is_seen_through_a_nested_all_of() {
        // The discriminator idiom composed twice: a component that is itself an `allOf` is
        // the shape most likely to reach TypeScript as `X & { … }`, so a conflict introduced
        // at the second level is exactly the one the warning has to see. Resolving a branch
        // one `$ref` deep and requiring a plain object misses it.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Base": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string" } } },
                "Cat": { "allOf": [
                    { "$ref": "#/components/schemas/Base" },
                    { "type": "object", "properties": { "kind": { "type": "string", "const": "cat" } } }
                ] },
                "Hybrid": { "allOf": [
                    { "$ref": "#/components/schemas/Cat" },
                    { "type": "object", "properties": { "kind": { "type": "string", "const": "dog" } } }
                ] }
            })),
            json!({}),
        );
        let flagged = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_CONFLICTING_PROPERTY)
            .collect::<Vec<_>>();
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        let message = &flagged[0].message;
        assert!(message.contains("kind"), "{message}");
    }

    #[test]
    fn a_single_self_contradictory_branch_is_not_a_property_conflict() {
        // One branch declaring `n` with minimum above maximum empties the whole node, which
        // is OASTS4201's job. Reporting it as branches disagreeing about `n` names a cause
        // that is not there — there is only one declaration of `n`.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Solo": { "allOf": [
                    { "type": "object", "properties": { "n": { "type": "number", "minimum": 5, "maximum": 4 } } },
                    { "type": "object", "properties": { "n": { "description": "no constraints of its own" } } }
                ] }
            })),
            json!({}),
        );
        // Asserted on the whole list rather than a filtered one: a closure that filters an
        // empty iterator never runs, and the coverage gate counts it as an unreached region.
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn a_node_lowered_to_never_reports_no_property_conflict() {
        // The node is replaced by `never`, so a warning about a property inside it describes
        // a type the output does not contain.
        let (files, diagnostics) = compile(
            openapi(json!({
                "Lowered": { "allOf": [
                    { "type": "object", "additionalProperties": false, "required": ["a"],
                      "properties": { "a": { "type": "string" } } },
                    { "type": "object", "required": ["b"],
                      "properties": { "a": { "type": "number" }, "b": { "type": "string" } } }
                ] }
            })),
            json!({}),
        );
        let lowered = &schema_file(&files, "lowered").content;
        assert!(
            lowered.contains("export type Lowered = never;"),
            "{lowered}"
        );
        let flagged = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_CONFLICTING_PROPERTY)
            .count();
        assert_eq!(flagged, 0, "{diagnostics:?}");
    }

    #[test]
    fn a_repeated_all_of_ref_renders_once() {
        // The merge used to fold a repeated branch into one shape. Joining members without
        // deduplicating turns that into `Base & Base`, which is the same type spelled twice —
        // the union arm has always deduplicated its branches for the same reason.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "Base": { "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } },
                "Twice": { "allOf": [
                    { "$ref": "#/components/schemas/Base" },
                    { "$ref": "#/components/schemas/Base" }
                ] }
            })),
            json!({}),
        );
        let twice = generated_body(schema_file(&files, "twice")).to_owned();
        assert!(twice.contains("export type Twice = Base;"), "{twice}");
    }

    #[test]
    fn an_empty_anonymous_all_of_branch_does_not_widen_a_named_one() {
        // An empty object renders as an index signature everywhere it stands as a type of its
        // own. Beside a named branch it must not: `WidgetMeta & { [key: string]: unknown }`
        // re-opens every key of a closed type, and the closed spelling would make `a` impossible.
        // It keeps the bare `{}`, which is what this member has always contributed.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "WidgetMeta": { "type": "object", "properties": { "a": { "type": "string" } } },
                "Wrapped": { "allOf": [
                    { "$ref": "#/components/schemas/WidgetMeta" },
                    { "type": "object", "properties": {} }
                ] }
            })),
            json!({}),
        );
        let wrapped = generated_body(schema_file(&files, "wrapped"));
        assert!(
            wrapped.contains("export type Wrapped = WidgetMeta & {};"),
            "{wrapped}"
        );
        assert!(!wrapped.contains("[key: string]"), "{wrapped}");
    }

    #[test]
    fn a_request_names_its_parameter_slots_the_way_the_client_input_does() {
        // The two artifacts describe the same operation input, so a value of one has to be
        // assignable to the other. Plural group names made that false for every operation with a
        // header or a cookie, and TypeScript only caught it where no other slot matched.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "readPet",
                        "parameters": [
                            { "name": "petId", "in": "path", "required": true,
                              "schema": { "type": "string" } },
                            { "name": "X-Trace", "in": "header",
                              "schema": { "type": "string" } },
                            { "name": "session", "in": "cookie",
                              "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = find_file(&files, "types/operations/readpet.ts");
        assert!(
            operation.content.contains("  header?: {\n"),
            "{}",
            operation.content
        );
        assert!(
            operation.content.contains("  cookie?: {\n"),
            "{}",
            operation.content
        );
        assert!(
            !operation.content.contains("headers?:"),
            "{}",
            operation.content
        );
        assert!(
            !operation.content.contains("cookies?:"),
            "{}",
            operation.content
        );
    }

    #[test]
    fn an_all_nullable_intersection_keeps_the_null_its_validators_accept() {
        // `{}` removes the null of a nullable named branch, which is the point of keeping it. It
        // may not remove a null that nothing else rejects: when the empty branch is ITSELF
        // nullable and so is the named one, null satisfies every member, and the validators and
        // zod schemas both accept it. `(X | null) & ({} | null)` distributes to `X | null`, so the
        // emitted type reaches the same verdict instead of contradicting them.
        let (files, _diagnostics) = compile(
            openapi(json!({
                "WidgetMaybe": {
                    "type": ["object", "null"],
                    "properties": { "a": { "type": "string" } }
                },
                "BothNullable": {
                    "type": ["object", "null"],
                    "allOf": [{ "$ref": "#/components/schemas/WidgetMaybe" }]
                },
                // The control: the named branch rejects null on its own, so the conjunction does
                // too and the bare `{}` stays.
                "WidgetMeta": {
                    "type": "object",
                    "required": ["a"],
                    "properties": { "a": { "type": "string" } }
                },
                "OneNullable": {
                    "type": ["object", "null"],
                    "allOf": [{ "$ref": "#/components/schemas/WidgetMeta" }]
                }
            })),
            json!({}),
        );
        let both = generated_body(schema_file(&files, "bothnullable"));
        assert!(
            both.contains("export type BothNullable = WidgetMaybe & ({} | null);"),
            "{both}"
        );
        let one = generated_body(schema_file(&files, "onenullable"));
        assert!(
            one.contains("export type OneNullable = WidgetMeta & {};"),
            "{one}"
        );
    }

    #[test]
    fn empty_object_branch_survives_beside_a_named_branch() {
        // `{}` is not a member that says nothing: in TypeScript it admits every value except
        // `null` and `undefined`, so intersecting it with a nullable named branch is what
        // removes the `null`. Dropping it as noise widens the type back.
        let document = openapi(json!({
            "MaybeObject": { "anyOf": [
                { "type": "object", "properties": { "a": { "type": "string" } } },
                { "type": "null" }
            ] },
            "Constrained": { "allOf": [
                { "$ref": "#/components/schemas/MaybeObject" },
                { "type": "object" }
            ] }
        }));
        let (files, _diagnostics) = compile(document, json!({}));
        let constrained = generated_body(schema_file(&files, "constrained")).to_owned();
        assert!(
            constrained.contains("export type Constrained = MaybeObject & {};"),
            "{constrained}"
        );
        assert!(!constrained.contains("[key: string]"), "{constrained}");
    }

    #[test]
    fn nullable_all_of_ref_wraps_the_whole_intersection() {
        // 3.0's `nullable` beside the `allOf` quoting idiom. `null` is appended to whatever
        // the node rendered to, outside the intersection — distributing it into the members
        // would give `(A | null) & (B | null)`, whose object half collapses to `never`.
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "test", "version": "1" },
            "paths": {},
            "components": { "schemas": {
                "WidgetMeta": { "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } },
                "OtherMeta": { "type": "object", "required": ["b"], "properties": { "b": { "type": "string" } } },
                "NullableOne": { "nullable": true, "allOf": [{ "$ref": "#/components/schemas/WidgetMeta" }] },
                "NullableTwo": { "nullable": true, "allOf": [
                    { "$ref": "#/components/schemas/WidgetMeta" },
                    { "$ref": "#/components/schemas/OtherMeta" }
                ] }
            } }
        });
        let (files, _diagnostics) = compile(document, json!({}));
        let one = generated_body(schema_file(&files, "nullableone")).to_owned();
        assert!(
            one.contains("export type NullableOne = WidgetMeta | null;"),
            "{one}"
        );
        // `&` binds tighter than `|`, so the unparenthesized tail is `(A & B) | null` — the
        // whole intersection is nullable, not its last member. The fixture's compile-assert
        // pins that reading at the type level.
        let two = generated_body(schema_file(&files, "nullabletwo")).to_owned();
        assert!(
            two.contains("export type NullableTwo = WidgetMeta & OtherMeta | null;"),
            "{two}"
        );
    }

    fn discriminator_diagnostics(diagnostics: &[Diagnostic]) -> Vec<&Diagnostic> {
        diagnostics
            .iter()
            .filter(|diagnostic| {
                matches!(
                    diagnostic.code,
                    CODE_DISCRIMINATOR
                        | CODE_DISCRIMINATOR_PROOF
                        | CODE_DISCRIMINATOR_NARROWING
                        | CODE_MAPPING_TARGET
                )
            })
            .collect()
    }

    #[test]
    fn proven_discriminator_that_cannot_narrow_warns() {
        let cases = [
            (
                openapi(json!({
                    "Cat": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
                    "Dog": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
                    "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                             "discriminator": { "propertyName": "petType", "mapping": {
                                 "feline": "#/components/schemas/Cat", "canine": "#/components/schemas/Dog"
                             } } }
                })),
                "mapping literals",
            ),
            (
                openapi(json!({
                    "Cat": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
                    "Dog": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
                    "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                             "discriminator": { "propertyName": "petType" } }
                })),
                "component-name tags",
            ),
            (
                openapi(json!({
                    "Cat": { "type": "object", "properties": { "petType": { "type": "string", "const": "cat" } } },
                    "Dog": { "type": "object", "properties": { "petType": { "type": "string", "const": "dog" } } },
                    "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                             "discriminator": { "propertyName": "petType" } }
                })),
                "optional",
            ),
            (
                openapi(json!({
                    "Cat": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "object", "const": { "k": 1 } } } },
                    "Dog": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "object", "const": { "k": 2 } } } },
                    "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                             "discriminator": { "propertyName": "petType" } }
                })),
                "object",
            ),
        ];

        for (document, reason) in cases {
            let (_files, diagnostics) = compile(document, json!({}));
            let warnings = diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS4207")
                .collect::<Vec<_>>();
            assert_eq!(warnings.len(), 1, "{reason}: {diagnostics:?}");
            assert_eq!(warnings[0].severity, Severity::Warning);
            assert!(
                warnings[0].message.contains("petType"),
                "{reason}: {warnings:?}"
            );
            assert!(
                warnings[0].message.contains(reason),
                "{reason}: {warnings:?}"
            );
        }

        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "petType" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn tagged_discriminator_projects_only_sound_oneof_tags() {
        let mapping_document = openapi(json!({
            "Cat": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
            "Dog": { "type": "object", "required": ["petType"], "properties": { "petType": { "type": "string" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "petType", "mapping": {
                         "feline": "#/components/schemas/Cat", "kitty": "#/components/schemas/Cat",
                         "canine": "#/components/schemas/Dog"
                     } } }
        }));
        let (tagged_files, tagged_diagnostics) = compile(
            mapping_document.clone(),
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let tagged = generated_body(schema_file(&tagged_files, "pet"));
        assert!(
            tagged.contains(
                "export type Pet = (Cat & { petType: \"feline\" | \"kitty\" }) | (Dog & { petType: \"canine\" });"
            ),
            "{tagged}"
        );
        assert!(tagged_diagnostics.is_empty(), "{tagged_diagnostics:?}");

        let (structural_files, structural_diagnostics) = compile(mapping_document, json!({}));
        let structural = generated_body(schema_file(&structural_files, "pet"));
        assert!(
            structural.contains("export type Pet = Cat | Dog;"),
            "{structural}"
        );
        assert_eq!(
            structural_diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .count(),
            1,
            "{structural_diagnostics:?}"
        );

        let const_document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind" } }
        }));
        let (files, diagnostics) = compile(
            const_document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(find_file(&files, "types/components/pet.ts"));
        assert!(pet.contains("export type Pet = Cat | Dog;"), "{pet}");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        let optional_document = openapi(json!({
            "Cat": { "type": "object", "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind" } }
        }));
        let (files, diagnostics) = compile(
            optional_document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(pet.contains("export type Pet = Cat | Dog;"), "{pet}");
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1, "{diagnostics:?}");
        assert!(warnings[0].message.contains("optional"));

        let anyof_document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string" } } },
            "Pet": { "anyOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog"
                     } } }
        }));
        for config in [
            json!({}),
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        ] {
            let (files, diagnostics) = compile(anyof_document.clone(), config);
            let pet = generated_body(schema_file(&files, "pet"));
            assert!(pet.contains("export type Pet = Cat | Dog;"), "{pet}");
            assert_eq!(
                diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                    .count(),
                1,
                "{diagnostics:?}"
            );
        }

        let wire_document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "servers": [{ "url": "https://api.example.test" }],
            "paths": {},
            "components": { "schemas": {
                "Cat": { "type": "object", "required": ["petType", "at"], "properties": {
                    "petType": { "type": "string" }, "at": { "type": "string", "format": "date-time" }
                } },
                "Dog": { "type": "object", "required": ["petType", "at"], "properties": {
                    "petType": { "type": "string" }, "at": { "type": "string", "format": "date-time" }
                } },
                "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                         "discriminator": { "propertyName": "petType", "mapping": {
                             "feline": "#/components/schemas/Cat", "canine": "#/components/schemas/Dog"
                         } } }
            } }
        });
        let (files, diagnostics) = compile_all_artifacts(wire_document, |config| {
            config.types.date_time = DateTimeRepresentation::Date;
            config.types.discriminated_unions = DiscriminatedUnions::Tagged;
        });
        let pet = generated_body(find_file(&files, "types/components/pet.ts"));
        assert!(
            pet.contains(
                "export type Pet = (Cat & { petType: \"feline\" }) | (Dog & { petType: \"canine\" });"
            ),
            "{pet}"
        );
        assert!(
            pet.contains(
                "export type PetWire = (CatWire & { petType: \"feline\" }) | (DogWire & { petType: \"canine\" });"
            ),
            "{pet}"
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != CODE_DISCRIMINATOR_NARROWING),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn tagged_discriminator_projects_mapping_tags_as_the_declared_scalar_type() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "integer" }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "integer" }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "1": "#/components/schemas/Cat", "2": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(
            pet.contains("export type Pet = (Cat & { kind: 1 }) | (Dog & { kind: 2 });"),
            "{pet}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn tagged_discriminator_falls_back_when_projected_tags_collide() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "number" }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "number" }
            } },
            "FixedCat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "number", "const": 1 }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "1": "#/components/schemas/Cat", "1.0": "#/components/schemas/Dog"
                     } } },
            "DeduplicatedPet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "1": "#/components/schemas/Cat", "1.0": "#/components/schemas/Cat",
                         "2": "#/components/schemas/Dog"
                     } } },
            "MixedPet": { "oneOf": [{ "$ref": "#/components/schemas/FixedCat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "1": "#/components/schemas/FixedCat", "1.0": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(pet.contains("export type Pet = Cat | Dog;"), "{pet}");
        let deduplicated = generated_body(schema_file(&files, "deduplicatedpet"));
        assert!(
            deduplicated.contains(
                "export type DeduplicatedPet = (Cat & { kind: 1 }) | (Dog & { kind: 2 });"
            ),
            "{deduplicated}"
        );
        let mixed = generated_body(schema_file(&files, "mixedpet"));
        assert!(
            mixed.contains("export type MixedPet = FixedCat | Dog;"),
            "{mixed}"
        );
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 2, "{diagnostics:#?}");
        assert!(warnings.iter().all(|warning| {
            warning.severity == Severity::Warning
                && warning.message.contains("TypeScript literal 1")
                && warning.message.contains("structural union")
        }));
    }

    #[test]
    fn tagged_discriminator_leaves_a_mismatched_mapping_tag_unprojected() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "integer" }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "integer" }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "2": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(
            pet.contains("export type Pet = Cat | (Dog & { kind: 2 });"),
            "{pet}"
        );
        let warnings = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1, "{diagnostics:#?}");
        assert!(warnings[0].message.contains("JSON kind"));
    }

    #[test]
    fn projected_tag_values_follow_scalar_json_kinds() {
        assert_eq!(
            projected_tag_value("tag", ProjectedTagType::String),
            Some(json!("tag"))
        );
        assert_eq!(
            projected_tag_value("1.5", ProjectedTagType::Number),
            Some(json!(1.5))
        );
        assert_eq!(projected_tag_value("1.5", ProjectedTagType::Integer), None);
        assert_eq!(
            projected_tag_value("true", ProjectedTagType::Boolean),
            Some(json!(true))
        );
        assert_eq!(
            projected_tag_value("false", ProjectedTagType::Boolean),
            Some(json!(false))
        );
        assert_eq!(
            projected_tag_value("other", ProjectedTagType::Boolean),
            None
        );
        assert_eq!(
            projected_tag_value("null", ProjectedTagType::Null),
            Some(Value::Null)
        );
        assert_eq!(projected_tag_value("other", ProjectedTagType::Null), None);
        assert_eq!(
            projected_tag_value("1", ProjectedTagType::Incompatible),
            None
        );
        assert_eq!(
            intersect_projected_tag_types(ProjectedTagType::Number, ProjectedTagType::Integer),
            ProjectedTagType::Integer
        );
        assert_eq!(
            intersect_projected_tag_types(ProjectedTagType::String, ProjectedTagType::String),
            ProjectedTagType::String
        );
        assert_eq!(
            intersect_projected_tag_types(ProjectedTagType::String, ProjectedTagType::Boolean),
            ProjectedTagType::Incompatible
        );
        assert_eq!(
            projected_tag_value("not-json", ProjectedTagType::Number),
            None
        );
        assert_eq!(projected_tag_value("true", ProjectedTagType::Number), None);
    }

    #[test]
    fn tagged_projection_resolves_refs_compositions_and_scalar_kinds() {
        let document = openapi(json!({
            "NumberTag": { "type": "number" },
            "TagA": { "$ref": "#/components/schemas/TagB" },
            "TagB": { "$ref": "#/components/schemas/TagA" },
            "NumberArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "$ref": "#/components/schemas/NumberTag" }
            } },
            "ComposedArm": { "allOf": [
                {},
                { "type": "object", "required": ["kind"], "properties": {
                    "kind": { "allOf": [{ "type": "number" }, { "type": "integer" }] }
                } }
            ] },
            "BooleanArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "oneOf": [{ "type": "boolean" }, { "type": "boolean" }] }
            } },
            "NullArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "null" }
            } },
            "NullableArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": ["integer", "null"] }
            } },
            "ArrayArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "array", "items": { "type": "string" } }
            } },
            "CyclicPropertyArm": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "$ref": "#/components/schemas/TagA" }
            } },
            "CyclicBranchArm": { "allOf": [
                { "$ref": "#/components/schemas/CyclicBranchArm" },
                { "type": "object", "required": ["kind"], "properties": {
                    "kind": { "type": "integer" }
                } }
            ] },
            "Pet": {
                "oneOf": [
                    { "$ref": "#/components/schemas/NumberArm" },
                    { "$ref": "#/components/schemas/ComposedArm" },
                    { "$ref": "#/components/schemas/BooleanArm" },
                    { "$ref": "#/components/schemas/NullArm" },
                    { "$ref": "#/components/schemas/NullableArm" },
                    { "$ref": "#/components/schemas/ArrayArm" },
                    { "$ref": "#/components/schemas/CyclicPropertyArm" },
                    { "$ref": "#/components/schemas/CyclicBranchArm" }
                ],
                "discriminator": { "propertyName": "kind", "mapping": {
                    "1.5": "#/components/schemas/NumberArm",
                    "2": "#/components/schemas/ComposedArm",
                    "true": "#/components/schemas/BooleanArm",
                    "null": "#/components/schemas/NullArm",
                    "4": "#/components/schemas/NullableArm",
                    "array": "#/components/schemas/ArrayArm",
                    "cycle": "#/components/schemas/CyclicPropertyArm",
                    "5": "#/components/schemas/CyclicBranchArm"
                } }
            }
        }));
        let (files, diagnostics) = compile(
            document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(pet.contains("NumberArm & { kind: 1.5 }"), "{pet}");
        assert!(pet.contains("ComposedArm & { kind: 2 }"), "{pet}");
        assert!(pet.contains("BooleanArm & { kind: true }"), "{pet}");
        assert!(pet.contains("NullArm & { kind: null }"), "{pet}");
        assert!(pet.contains("NullableArm"), "{pet}");
        assert!(pet.contains("ArrayArm"), "{pet}");
        assert!(pet.contains("CyclicPropertyArm"), "{pet}");
        assert!(pet.contains("CyclicBranchArm & { kind: 5 }"), "{pet}");
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .count(),
            1,
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn tagged_projection_does_not_require_optional_or_position_filtered_tags() {
        let optional_document = openapi(json!({
            "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Dog": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            optional_document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(pet.contains("export type Pet = Cat | Dog;"), "{pet}");
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .count(),
            1,
            "{diagnostics:?}"
        );

        let filtered_document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string", "readOnly": true }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string", "readOnly": true }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            filtered_document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(
            pet.contains("export type PetRequest = CatRequest | DogRequest;"),
            "{pet}"
        );
        assert!(
            pet.contains(
                "export type Pet = (Cat & { kind: \"cat\" }) | (Dog & { kind: \"dog\" });"
            ),
            "{pet}"
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .count(),
            1,
            "{diagnostics:?}"
        );
        // Names the shape that cannot carry the tag. The neutral declaration above demonstrably
        // narrows, so a message claiming the union cannot narrow would be false of this document.
        assert_eq!(
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .map(|diagnostic| diagnostic.message.as_str()),
            Some(
                "discriminator property 'kind' is absent from the request shape, so that variant is emitted without tagged projection while the neutral declaration still narrows"
            ),
            "{diagnostics:?}"
        );

        let filtered_response_document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string", "writeOnly": true }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string", "writeOnly": true }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            filtered_response_document,
            json!({ "types": { "discriminatedUnions": "tagged" } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(
            pet.contains("export type PetResponse = CatResponse | DogResponse;"),
            "{pet}"
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .count(),
            1,
            "{diagnostics:?}"
        );
        // The mirror image, and the reason one axis-blind sentence could not serve both.
        assert_eq!(
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_DISCRIMINATOR_NARROWING)
                .map(|diagnostic| diagnostic.message.as_str()),
            Some(
                "discriminator property 'kind' is absent from the response shape, so that variant is emitted without tagged projection while the neutral declaration still narrows"
            ),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn tagged_projection_honors_readonly_configuration() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string" }
            } },
            "Dog": { "type": "object", "required": ["kind"], "properties": {
                "kind": { "type": "string" }
            } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind", "mapping": {
                         "cat": "#/components/schemas/Cat", "dog": "#/components/schemas/Dog"
                     } } }
        }));
        let (files, diagnostics) = compile(
            document,
            json!({ "types": { "discriminatedUnions": "tagged", "readonly": true } }),
        );
        let pet = generated_body(schema_file(&files, "pet"));
        assert!(
            pet.contains(
                "export type Pet = (Cat & { readonly kind: \"cat\" }) | (Dog & { readonly kind: \"dog\" });"
            ),
            "{pet}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
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
        // OASTS4202 — fires once, not once per synthetic branch.
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
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_DISCRIMINATOR_NARROWING);
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert!(flagged[0].message.contains("mapping literals"));
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

    /// A mapping value the compiler cannot resolve is a dead entry, not a broken document: the
    /// mapping never shapes the emitted union, so the entry drops out of tag resolution and proof
    /// falls back to each branch's own `const`. Files are still emitted.
    #[test]
    fn dangling_mapping_warns_and_contributes_no_tag() {
        let document = openapi(json!({
            "Cat": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "cat" } } },
            "Dog": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string", "const": "dog" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind",
                       "mapping": { "cat": "other.json#/components/schemas/Cat" } } }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        // The const-proved branches still prove; only the dangling mapping value is reported.
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_MAPPING_TARGET);
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert_eq!(
            flagged[0].message,
            "discriminator mapping value 'other.json#/components/schemas/Cat' resolves to no component schema; the entry contributes no tag"
        );
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
        // The dropped entry must not also make the union unprovable.
        assert!(
            flagged
                .iter()
                .all(|diagnostic| diagnostic.code != CODE_DISCRIMINATOR),
            "{diagnostics:?}"
        );
        let pet = find_file(&files, "types/components/pet.ts");
        assert!(
            pet.content.contains("export type Pet = Cat | Dog;"),
            "{}",
            pet.content
        );
    }

    /// Every mapping entry dangling still emits the same structural union, with one warning per dead
    /// entry and one narrowing warning after proof falls back to referenced component names.
    #[test]
    fn an_entirely_dangling_mapping_still_emits_the_union() {
        let document = openapi(json!({
            "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Dog": { "type": "object", "properties": { "kind": { "type": "string" } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/Cat" }, { "$ref": "#/components/schemas/Dog" }],
                     "discriminator": { "propertyName": "kind",
                       "mapping": { "cat": "other.json#/components/schemas/Cat",
                                    "dog": "other.json#/components/schemas/Dog" } } }
        }));
        let (files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 3, "{diagnostics:?}");
        assert!(
            flagged
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_MAPPING_TARGET)
                .count()
                == 2,
            "{diagnostics:?}"
        );
        assert!(
            flagged.iter().any(|diagnostic| {
                diagnostic.code == CODE_DISCRIMINATOR_NARROWING
                    && diagnostic.severity == Severity::Warning
            }),
            "{diagnostics:?}"
        );
        let pet = find_file(&files, "types/components/pet.ts");
        assert!(
            pet.content.contains("export type Pet = Cat | Dog;"),
            "{}",
            pet.content
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
        // The component names still prove distinct tags, but the document does not declare those
        // strings on the wire, so the structural output cannot narrow on them.
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_DISCRIMINATOR_NARROWING);
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert!(flagged[0].message.contains("component-name tags"));
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
        // Branch A's tag property is itself an object with a `const`, so proof finds its fixed value
        // in the object `finite` field. That still is not a unit type TypeScript can discriminate;
        // branch B's non-finite array falls back to its implicit component name.
        let document = openapi(json!({
            "A": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "object", "const": { "k": 1 } } } },
            "B": { "type": "object", "properties": { "kind": { "type": "array", "items": { "type": "string" } } } },
            "Pet": { "oneOf": [{ "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" }], "discriminator": { "propertyName": "kind" } }
        }));
        let (_files, diagnostics) = compile(document, json!({}));
        let flagged = discriminator_diagnostics(&diagnostics);
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].code, CODE_DISCRIMINATOR_NARROWING);
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert!(flagged[0].message.contains("object const tags"));
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
    fn discriminator_ignores_never_branch_literal_space() {
        let (files, diagnostics) = compile(
            openapi(json!({
                "Dead": {
                    "allOf": [
                        { "type": "string" },
                        { "type": "number" }
                    ]
                },
                "Live": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "const": "Dead" }
                    }
                },
                "Choice": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Dead" },
                        { "$ref": "#/components/schemas/Live" }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            })),
            json!({}),
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_COMPOSITION
                && diagnostic.severity == crate::diag::Severity::Warning
        }));
        assert!(
            discriminator_diagnostics(&diagnostics).is_empty(),
            "{diagnostics:?}"
        );
        assert!(
            schema_file(&files, "choice")
                .content
                .contains("export type Choice = Dead | Live;")
        );
    }

    #[test]
    fn discriminator_join_relative_source_normalizes_segments() {
        assert_eq!(
            crate::ir::join_relative_source(
                "workspace/nested/openapi.json",
                "./sibling/../shared.json"
            ),
            "workspace/nested/shared.json"
        );
    }

    #[test]
    fn conflicting_property_across_all_of_branches_warns_without_lowering() {
        // Identity-first sends every all-`$ref` `allOf` down the intersection path, so a
        // property two branches disagree about is no longer folded away by the merge — it
        // reaches TypeScript as `string & number`, which is silently `never` at exactly one
        // property. OASTS4206 is the only signal that says so.
        //
        // It fires on a provably empty intersection, not on any inequality. Narrowing a
        // property is what `allOf` is *for* — the discriminator idiom refines a base's
        // `kind: string` to `const: "cat"` — and warning on that would fire on most real
        // documents that use `allOf` at all.
        let (files, diagnostics) = compile(
            openapi(json!({
                "Conflict": { "allOf": [
                    { "type": "object", "properties": { "a": { "type": "string" } } },
                    { "type": "object", "properties": { "a": { "type": "number" } } }
                ] }
            })),
            json!({}),
        );
        let flagged = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_CONFLICTING_PROPERTY)
            .collect::<Vec<_>>();
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert!(flagged[0].message.contains('a'), "{:?}", flagged[0]);
        // A warning, not a proof of emptiness: the node keeps its intersection type.
        let conflict = schema_file(&files, "conflict");
        assert!(
            !conflict.content.contains("export type Conflict = never;"),
            "{}",
            conflict.content
        );

        // Identical declarations merge, so nothing to say.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Same": { "allOf": [
                    { "type": "object", "properties": { "a": { "type": "string" } } },
                    { "type": "object", "properties": { "a": { "type": "string" } } }
                ] }
            })),
            json!({}),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        // A numeric property whose bounds cannot both hold.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Bounds": { "allOf": [
                    { "type": "object", "properties": { "n": { "type": "number", "minimum": 5 } } },
                    { "type": "object", "properties": { "n": { "type": "number", "maximum": 4 } } }
                ] }
            })),
            json!({}),
        );
        let flagged = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_CONFLICTING_PROPERTY)
            .collect::<Vec<_>>();
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        let message = &flagged[0].message;
        assert!(message.contains("empty numeric interval"), "{message}");

        // Overlapping finite sets intersect to `"y"`. Unequal, inhabitable, silent.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Overlap": { "allOf": [
                    { "type": "object", "properties": { "a": { "type": "string", "enum": ["x", "y"] } } },
                    { "type": "object", "properties": { "a": { "type": "string", "const": "y" } } }
                ] }
            })),
            json!({}),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        // The discriminator idiom: a base's open `kind` refined to one literal. Unequal, and
        // entirely legitimate — the intersection is `"cat"`, not `never`.
        let (_files, diagnostics) = compile(
            openapi(json!({
                "Base": { "type": "object", "required": ["kind"], "properties": { "kind": { "type": "string" } } },
                "Cat": { "allOf": [
                    { "$ref": "#/components/schemas/Base" },
                    { "type": "object", "properties": { "kind": { "type": "string", "const": "cat" } } }
                ] }
            })),
            json!({}),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
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
            let (files, diagnostics) = compile(openapi(json!({ "Proof": positive })), json!({}));
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == CODE_COMPOSITION
                        && diagnostic.severity == crate::diag::Severity::Warning
                        && diagnostic.message.contains(message)),
                "{message}: {diagnostics:?}"
            );
            let proof = schema_file(&files, "proof");
            assert!(proof.content.contains("export type Proof = never;"));
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
                diagnostic.code == "OASTS3103" && diagnostic.severity == Severity::Warning
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
            summary: Some(Cow::Owned("Summary @tag\r\nnext".to_owned())),
            remarks: vec![
                Cow::Owned("First".to_owned()),
                Cow::Owned("Second\nline".to_owned()),
            ],
            deprecated: Some("Deprecated."),
            params: vec![
                (
                    Cow::Owned("arg\r\nname".to_owned()),
                    Cow::Owned("Description\rline".to_owned()),
                ),
                // A fenced block inside a param description takes the literal path: its lines are
                // neutralized rather than comment-escaped, so a `*/` inside the fence cannot close
                // the comment while the fence's own markup survives.
                (
                    Cow::Owned("fenced".to_owned()),
                    Cow::Owned("before\n```txt\n*/ sourceMappingURL=\n```\nafter @tag".to_owned()),
                ),
            ],
            returns: Some("A value."),
            default_value: Some(Cow::Owned("value\n@tag".to_owned())),
            examples: vec![
                DocExample {
                    label: Some(Cow::Owned("Label @tag\r\nnext".to_owned())),
                    value: Cow::Owned(json!("*/ sourceMappingURL=")),
                },
                DocExample {
                    label: None,
                    value: Cow::Owned(json!([1, true])),
                },
            ],
            private_remarks: Some(Cow::Owned(
                "Private @tag\n```txt\n*/ sourceMappingURL=\n```".to_owned(),
            )),
            see: vec![(
                Cow::Owned("u{v}|<x>\r\n*/sourceMappingURL=".to_owned()),
                Some(Cow::Owned("L{a}\r\nB".to_owned())),
            )],
            neutral_variants: None,
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
    fn inline_request_body_is_indented_to_its_member_column() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/labels": {
                    "post": {
                        "operationId": "submitLabels",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["labels", "metadata"],
                                        "properties": {
                                            "labels": {
                                                "description": "The labels to submit.",
                                                "type": "array",
                                                "items": { "type": "string" }
                                            },
                                            "metadata": {
                                                "type": "object",
                                                "required": ["source"],
                                                "properties": {
                                                    "source": { "type": "string" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "Accepted" } }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let operation = find_file(&files, "types/operations/submitlabels.ts");
        assert!(
            operation.content.contains(concat!(
                "export type SubmitLabelsRequest = {\n",
                "  body: {\n",
                "    /**\n",
                "     * The labels to submit.\n",
                "     */\n",
                "    labels: string[];\n",
                "    metadata: {\n",
                "      source: string;\n",
                "    };\n",
                "  };\n",
                "};\n",
            )),
            "{}",
            operation.content
        );
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
                .any(|diagnostic| diagnostic.code == "OASTS2201")
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
    fn an_event_payload_renders_its_application_form_on_both_surfaces() {
        // The runtime converts each event before yielding it, so an event names the application
        // component whichever surface asks — there is no moment at which a consumer holds an
        // unconverted one, and so no wire twin for a stream. The pre-conversion result the buffered
        // arm needs is where that matters: an event arm that disagreed across the two surfaces
        // would leave the emitted module unable to return its own declared result.
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": {
                "schemas": {
                    "Tick": {
                        "type": "object",
                        "required": ["at"],
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }
            },
            "paths": {
                "/report": {
                    "get": {
                        "operationId": "readReport",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": { "schema": { "$ref": "#/components/schemas/Tick" } },
                                    "text/event-stream": { "schema": { "$ref": "#/components/schemas/Tick" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        // The representation requires the client artifact, which is also the artifact whose result
        // type the mismatch would have made unsatisfiable.
        let (files, diagnostics) = compile(
            document,
            json!({
                "types": { "dateTime": "date" },
                "artifacts": { "types": true, "client": true },
                "client": { "authEnforcement": "types", "baseUrl": { "source": "runtime" } },
                "validation": { "engine": "off", "request": false, "response": false, "unchecked": "allow" }
            }),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let types = files
            .iter()
            .find(|file| file.relative_path == "types/operations/readreport.ts")
            .expect("types operation file");
        let types_body = types.content.clone();
        // Both surfaces of the status-wide alias: the buffered arm differs across them, the event
        // arm does not.
        assert!(
            types_body.contains("ReadReportResponse200 = Tick | AsyncIterable<SseEvent<Tick>>;"),
            "{types_body}"
        );
        assert!(
            types_body
                .contains("ReadReportResponse200Wire = TickWire | AsyncIterable<SseEvent<Tick>>;"),
            "{types_body}"
        );
        // The event names the application component and only that, so the wire alias imports both
        // forms and each arm reads the one it declares.
        assert!(
            types_body.contains("import type { Tick, TickWire } from \"../components/tick.js\";"),
            "{types_body}"
        );

        // No configured representation, nothing to convert, no difference to render.
        let (_, quiet) = compile(
            json!({
                "openapi": "3.1.0",
                "info": { "title": "test", "version": "1" },
                "paths": {
                    "/ticks": {
                        "get": {
                            "operationId": "watchTicks",
                            "responses": {
                                "200": {
                                    "description": "OK",
                                    "content": {
                                        "text/event-stream": { "schema": { "type": "string" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
            json!({}),
        );
        assert!(quiet.is_empty(), "{quiet:?}");
    }

    #[test]
    fn the_sse_event_helper_is_emitted_only_when_a_response_declares_an_event_stream() {
        let streaming = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/ticks": {
                    "get": {
                        "operationId": "watchTicks",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (streaming_files, diagnostics) = compile(streaming, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let helper = streaming_files
            .iter()
            .find(|file| file.relative_path == "types/stream.ts")
            .expect("SseEvent helper emitted for a document with an SSE response");
        let helper_body = generated_body(helper);
        assert!(
            helper_body.contains(
                "export type SseEvent<TData> = {\n  data: TData;\n  event?: string;\n  id?: string;\n  retry?: number;\n};\n"
            ),
            "{helper_body}"
        );
        // The operation module writes the word `SseEvent`, so it imports the helper it just caused
        // to exist rather than redeclaring the shape per module.
        let operation = streaming_files
            .iter()
            .find(|file| file.relative_path.ends_with("watchticks.ts"))
            .expect("operation file");
        assert!(
            operation
                .content
                .contains("import type { SseEvent } from \"../stream"),
            "{}",
            operation.content
        );

        // A document with no SSE branch stays exactly as it was before the helper existed.
        let buffered = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/ticks": {
                    "get": {
                        "operationId": "watchTicks",
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (buffered_files, diagnostics) = compile(buffered, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(
            !buffered_files
                .iter()
                .any(|file| file.relative_path == "types/stream.ts")
        );
        let operation = buffered_files
            .iter()
            .find(|file| file.relative_path.ends_with("watchticks.ts"))
            .expect("operation file");
        assert!(
            !operation.content.contains("SseEvent"),
            "{}",
            operation.content
        );
    }

    #[test]
    fn a_streaming_payload_is_events_only_in_a_response_and_bytes_in_every_request_position() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {
                "/publish": {
                    "post": {
                        "operationId": "publishTicks",
                        "requestBody": {
                            "required": true,
                            "content": { "text/event-stream": { "schema": { "type": "string" } } }
                        },
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "text/event-stream": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                },
                "/upload": {
                    "post": {
                        "operationId": "uploadBlob",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/octet-stream": { "x-oasts-streaming": true }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/octet-stream": { "x-oasts-streaming": true }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (files, diagnostics) = compile(document, json!({}));
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        let publish = files
            .iter()
            .find(|file| file.relative_path.ends_with("publishticks.ts"))
            .expect("operation file");
        // Both families send bytes: framing typed events for the caller would move every framing
        // and conversion failure past the point where the request was already dispatched.
        assert!(
            publish
                .content
                .contains("body: ReadableStream<Uint8Array>;"),
            "{}",
            publish.content
        );
        // SSE is the one streaming position that has a schema at all, and it describes each event's
        // decoded `data` — so the response is events, not the whole body.
        assert!(
            publish
                .content
                .contains("export type PublishTicksResponse200 = AsyncIterable<SseEvent<string>>;"),
            "{}",
            publish.content
        );

        let upload = files
            .iter()
            .find(|file| file.relative_path.ends_with("uploadblob.ts"))
            .expect("operation file");
        assert!(
            upload.content.contains("body: ReadableStream<Uint8Array>;"),
            "{}",
            upload.content
        );
        // A raw stream carries no schema position in either direction, so it stays bytes.
        assert!(
            upload
                .content
                .contains("export type UploadBlobResponse200 = ReadableStream<Uint8Array>;"),
            "{}",
            upload.content
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
            concat!(
                "// Generated by Oasts ",
                env!("CARGO_PKG_VERSION"),
                ". Do not edit.\n// Config schema version: 1\n// Source digest: e265b1d269c4ed7fdb110ea9e7e2ba57706d2ed600c92c9832049ea0f4785ffc\n\n// Source: workspace/openapi.json#/components/schemas/Item\nexport interface Item {\n  id: string;\n}\n"
            )
        );
        assert_eq!(
            operation.content,
            concat!(
                "// Generated by Oasts ",
                env!("CARGO_PKG_VERSION"),
                ". Do not edit.\n// Config schema version: 1\n// Source digest: e265b1d269c4ed7fdb110ea9e7e2ba57706d2ed600c92c9832049ea0f4785ffc\n\nimport type { Item } from \"../components/item.js\";\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Responses\n * \n * - 200: OK\n */\nexport type ListItemsRequest = {};\n\n// Source: workspace/openapi.json#/paths/~1items/get/responses/200\nexport type ListItemsResponse200 = Item;\n\n// Source: workspace/openapi.json#/paths/~1items/get\n/**\n * @remarks\n * Responses\n * \n * - 200: OK\n */\nexport type ListItemsResponse = ListItemsResponse200;\n"
            )
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
                assert_eq!(
                    lines[0],
                    concat!(
                        "// Generated by Oasts ",
                        env!("CARGO_PKG_VERSION"),
                        ". Do not edit."
                    )
                );
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
    fn a_component_shadowing_a_response_wire_twin_imports_under_a_role_alias() {
        let (files, diagnostics) = compile(
            shadowing_document(
                json!({
                    "CompleteUploadResponse200": {
                        "type": "object",
                        "properties": { "at": { "type": "string", "format": "date-time" } }
                    }
                }),
                "",
                "CompleteUploadResponse200",
            ),
            json!({
                "artifacts": { "types": true, "client": true },
                "client": {},
                "validation": { "engine": "off", "unchecked": "allow" },
                "types": { "dateTime": "date" }
            }),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let file = find_file(&files, "types/operations/completeupload.ts");
        // Both halves of the pair are declarations of this module, so both have to be aliased. With
        // only the application name in the declared set, `CompleteUploadResponse200Wire` bound the
        // local twin and the wire payload silently referred to itself.
        assert!(
            file.content.contains(
                "import type { CompleteUploadResponse200 as CompleteUploadResponse200Body, CompleteUploadResponse200Wire as CompleteUploadResponse200WireBody } from \"../components/completeuploadresponse200.js\";"
            ),
            "{}",
            file.content
        );
        assert!(
            file.content.contains(
                "export type CompleteUploadResponse200Wire = CompleteUploadResponse200WireBody;"
            ),
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
    fn parallel_operation_diagnostics_keep_source_order() {
        let media = |reference: &str| {
            json!({
                "application/json": {
                    "schema": { "$ref": format!("#/components/schemas/{reference}") }
                }
            })
        };
        let operation = |stem: &str| {
            let request = format!("{stem}Request");
            let alias = format!("{stem}RequestBody");
            json!({
                "operationId": stem.to_ascii_lowercase(),
                "requestBody": { "required": true, "content": media(&request) },
                "responses": {
                    "200": { "description": "ok", "content": media(&alias) }
                }
            })
        };
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "parallel diagnostics", "version": "1" },
            "paths": {
                "/alpha": { "post": operation("Alpha") },
                "/beta": { "post": operation("Beta") }
            },
            "components": {
                "schemas": {
                    "AlphaRequest": { "type": "string" },
                    "AlphaRequestBody": { "type": "string" },
                    "BetaRequest": { "type": "string" },
                    "BetaRequestBody": { "type": "string" }
                }
            }
        });
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        fs::write(
            &input,
            serde_json::to_vec(&document).expect("document JSON"),
        )
        .expect("write OpenAPI");
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
        let config = load_config(Some(&config_path), temp.path()).expect("valid config");
        let mut preparation_sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut preparation_sink).expect("loaded graph");
        let ir = parse(&graph, &mut preparation_sink).expect("supported OpenAPI");
        let analyzed = analyze(ir, &config, &mut preparation_sink);
        assert!(preparation_sink.as_slice().is_empty());
        let source_tuples = graph.source_tuples();
        let expected = ["AlphaRequest", "BetaRequest"];

        for thread_count in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .expect("rayon pool");
            for _ in 0..8 {
                let mut sink = DiagnosticSink::new();
                let files =
                    pool.install(|| emit_types(&analyzed, &config, &source_tuples, &mut sink));
                assert!(!files.is_empty());
                let ordered = sink
                    .as_slice()
                    .iter()
                    .filter(|diagnostic| diagnostic.code == CODE_IMPORT_ALIAS)
                    .map(|diagnostic| {
                        expected
                            .iter()
                            .find(|name| diagnostic.message.contains(*name))
                            .copied()
                            .expect("diagnostic names its shadowed import")
                    })
                    .collect::<Vec<_>>();
                assert_eq!(ordered, expected, "thread count {thread_count}");
            }
        }
    }

    /// The whole point of routing declarations through `variant_name`: the module that declares the
    /// renamed variant and the sibling that imports it read one producer, so a rename can never
    /// leave a dangling import. `Envelope` gains a Request variant only by referencing `Pet`, so its
    /// request rendering names `Pet`'s request variant — under the alias, not the derived name.
    #[test]
    fn a_renamed_variant_is_declared_and_imported_under_the_alias() {
        let (files, diagnostics) = compile(
            openapi(json!({
                "Pet": {
                    "type": "object",
                    "properties": { "id": { "type": "string", "readOnly": true } }
                },
                "PetRequest": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } }
                },
                "Envelope": {
                    "type": "object",
                    "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
                }
            })),
            json!({}),
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:?}"
        );
        let pet = find_file(&files, "types/components/pet.ts");
        assert!(
            pet.content
                .contains("export type PetRequestBody = { [key: string]: unknown };"),
            "{}",
            pet.content
        );
        assert!(
            !pet.content.contains("export interface PetRequest {"),
            "{}",
            pet.content
        );
        // The document's own component is untouched, in its own file under its own name.
        let declared = find_file(&files, "types/components/petrequest.ts");
        assert!(
            declared.content.contains("export interface PetRequest {"),
            "{}",
            declared.content
        );
        let envelope = find_file(&files, "types/components/envelope.ts");
        assert!(
            envelope
                .content
                .contains("import type { Pet, PetRequestBody } from \"./pet.js\";"),
            "{}",
            envelope.content
        );
        assert!(
            envelope.content.contains("pet?: PetRequestBody;"),
            "{}",
            envelope.content
        );
    }

    /// The response mirror: a `writeOnly` marker forces the Response variant, and a declared
    /// `PetResponse` pushes it to `PetResponseBody` at both the declaration and the reference.
    #[test]
    fn a_renamed_response_variant_is_declared_and_imported_under_the_alias() {
        let (files, diagnostics) = compile(
            openapi(json!({
                "Pet": {
                    "type": "object",
                    "properties": { "secret": { "type": "string", "writeOnly": true } }
                },
                "PetResponse": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } }
                },
                "Envelope": {
                    "type": "object",
                    "properties": { "pet": { "$ref": "#/components/schemas/Pet" } }
                }
            })),
            json!({}),
        );
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error),
            "{diagnostics:?}"
        );
        let pet = find_file(&files, "types/components/pet.ts");
        assert!(
            pet.content
                .contains("export type PetResponseBody = { [key: string]: unknown };"),
            "{}",
            pet.content
        );
        assert!(
            !pet.content.contains("export interface PetResponse {"),
            "{}",
            pet.content
        );
        let envelope = find_file(&files, "types/components/envelope.ts");
        assert!(
            envelope
                .content
                .contains("import type { Pet, PetResponseBody } from \"./pet.js\";"),
            "{}",
            envelope.content
        );
    }

    /// Both `Body` producers can land on one identifier: the operation module `completeUpload`
    /// declares `CompleteUploadRequest`, so its import of the component `CompleteUploadRequest`
    /// aliases to `CompleteUploadRequestBody` — the same name `CompleteUpload`'s renamed request
    /// variant already exports, which this module also imports. Two bindings, one identifier, no
    /// local remedy, so the existing fatal alias collision is the correct landing.
    #[test]
    fn a_variant_alias_colliding_with_an_import_alias_is_a_fatal_collision() {
        let (_, diagnostics) = compile(
            shadowing_document(
                json!({
                    "CompleteUpload": {
                        "type": "object",
                        "properties": { "id": { "type": "string", "readOnly": true } }
                    },
                    "CompleteUploadRequest": {
                        "type": "object",
                        "properties": { "name": { "type": "string" } }
                    }
                }),
                "CompleteUpload",
                "CompleteUploadRequest",
            ),
            json!({}),
        );
        let flagged: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_IMPORT_ALIAS)
            .collect();
        assert_eq!(flagged.len(), 1, "{diagnostics:?}");
        assert_eq!(flagged[0].severity, Severity::Error);
        let message = flagged[0].message.as_str();
        assert!(message.contains("CompleteUploadRequestBody"), "{message}");
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
        // The invalid file names are reported (OASTS4001), not silently absorbed.
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
