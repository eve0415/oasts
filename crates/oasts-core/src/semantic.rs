//! Semantic analysis, identifier normalization, and stable name allocation.

use std::collections::BTreeMap;
use std::fmt;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use serde_json::{Number, Value};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

use crate::composition::lower_uninhabitable_all_ofs;
use crate::config::{
    EnumExtensions, EnumMemberCase, EnumRepresentation, FileCase, NamingConfig, OperationCase,
    ResolvedConfig, TypesConfig,
};
use crate::diag::{
    Diagnostic, DiagnosticSink, NamingOverrideNamespace, NamingOverrideSuggestion, Severity,
};
use crate::ir::{
    AdditionalProperties, Callback, ExclusiveBound, Ir, LinkTarget, NamedSchema, OasVersion,
    Operation, ParamLocation, SchemaMeta, SchemaNode, SegmentPart, SourceRef, TupleRest, Webhook,
    finite_parts, is_root_component_pointer,
};
use crate::num::{finite_binary64, first_number_outside_binary64, render_number};

const CODE_OPERATION_NAME: &str = "OASTS1201";
const CODE_TYPE_NAME: &str = "OASTS1202";
const CODE_ENUM_RULE_14: &str = "OASTS1214";
const CODE_NUMERIC_BOUND_DOMAIN: &str = "OASTS1215";
const CODE_ANNOTATION_DOMAIN: &str = "OASTS1216";
const CODE_LINK_OPERATION_ID: &str = "OASTS1231";
const CODE_LINK_OPERATION_REF: &str = "OASTS1232";
const CODE_LINK_PARAMETER: &str = "OASTS1233";
// Webhook and callback name stems allocate in their own scopes (see `allocate_webhook_names`
// and `allocate_callback_names`) but share one collision/normalization-failure code: both are
// the same failure shape (a generated identifier collides or fails to normalize) just applied
// to a different declaration kind, and neither scope is user-configurable yet.
const CODE_WEBHOOK_NAME: &str = "OASTS1321";
// Config-category (exit code 2): an override key that names no declaration in the document.
const CODE_OVERRIDE_UNMATCHED: &str = "OASTS0202";

const RESERVED_WORDS: [&str; 46] = [
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
    "await",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetCase {
    Pascal,
    Camel,
    ScreamingSnake,
    Preserve,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizeError {
    NonAscii(char),
    Empty,
    LeadingDigit,
    ReservedWord(String),
    InvalidIdentifierCharacter(char),
    NumericDomain,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonAscii(character) => {
                write!(
                    formatter,
                    "non-ASCII character U+{:04X} remains",
                    *character as u32
                )
            }
            Self::Empty => formatter.write_str("normalization produced an empty identifier"),
            Self::LeadingDigit => formatter.write_str("identifier begins with a digit"),
            Self::ReservedWord(word) => {
                write!(formatter, "'{word}' is a TypeScript reserved word")
            }
            Self::InvalidIdentifierCharacter(character) => write!(
                formatter,
                "identifier contains invalid character '{}'",
                character.escape_default()
            ),
            Self::NumericDomain => {
                formatter.write_str("numeric value is outside the binary64 domain")
            }
        }
    }
}

impl std::error::Error for NormalizeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NameAllocation {
    name: String,
    escaped_reserved_word: Option<String>,
}

/// Applies the exact Unicode, tokenization, casing, and validation order.
pub fn normalize_identifier(input: &str, case: TargetCase) -> Result<String, NormalizeError> {
    normalize_identifier_allocation(input, case).map(|allocation| allocation.name)
}

fn normalize_identifier_allocation(
    input: &str,
    case: TargetCase,
) -> Result<NameAllocation, NormalizeError> {
    let tokens = identifier_tokens(input)?;
    if tokens.is_empty() {
        return Err(NormalizeError::Empty);
    }
    escape_reserved_word(transform_tokens(&tokens, case))
}

fn escape_reserved_word(identifier: String) -> Result<NameAllocation, NormalizeError> {
    match validate_normalized_identifier(&identifier) {
        Ok(()) => Ok(NameAllocation {
            name: identifier,
            escaped_reserved_word: None,
        }),
        Err(NormalizeError::ReservedWord(word)) => Ok(NameAllocation {
            name: format!("{identifier}_"),
            escaped_reserved_word: Some(word),
        }),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedOperationName {
    pub operation_index: usize,
    pub name: String,
    pub source: SourceRef,
}

/// One webhook operation's allocated name stem, indexed into `Ir.webhooks[webhook_index]
/// .operations[operation_index]`. Webhook files emit to their own output directory, so this
/// stem lives in a scope entirely separate from `AllocatedOperationName`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedWebhookName {
    pub webhook_index: usize,
    pub operation_index: usize,
    pub stem: String,
    pub source: SourceRef,
}

/// Locates the operation that declares a callback, so the emitter can both reach that operation's
/// `&Operation` (to descend into the callback) and name the `<ParentStem>Callbacks` descriptor.
/// A callback can hang off a path operation, a webhook operation, or another callback operation
/// (nesting), so the parent is one of those three — the `Callback` variant references the
/// enclosing callback's own `AllocatedCallbackName` by its index in `Analyzed.callback_names`,
/// which allocation always fills before the nested child (pre-order), so the index resolves.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CallbackParent {
    /// `Ir.operations[operation_index]`.
    Operation { operation_index: usize },
    /// `Ir.webhooks[webhook_index].operations[operation_index]`.
    WebhookOperation {
        webhook_index: usize,
        operation_index: usize,
    },
    /// The enclosing callback-expression operation, at `Analyzed.callback_names[index]`.
    Callback { index: usize },
}

/// One callback-expression operation's allocated name stem. `parent` plus the three descent
/// indices address the operation node at
/// `<parent operation>.callbacks[callback_index].expressions[expression_index]
/// .operations[operation_index_within_expression]`. Covers callbacks at every depth: on path
/// operations, on webhook operations, and nested inside another callback's operation.
///
/// `parent_stem` is the declaring operation's own stem (e.g. `PutSquare` for a path operation,
/// the webhook stem for a webhook operation, the enclosing callback's stem for a nested one) —
/// it is both this stem's naming base and the `<parent_stem>Callbacks` descriptor name, stored
/// here so the emitter groups and names descriptors without re-deriving parent stems.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedCallbackName {
    pub parent: CallbackParent,
    pub parent_stem: String,
    pub callback_index: usize,
    pub expression_index: usize,
    pub operation_index_within_expression: usize,
    pub stem: String,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatedSchemaName {
    pub schema_index: usize,
    pub wire_name: String,
    pub name: String,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumMember {
    pub name: String,
    pub value: Value,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumMemberTable {
    pub source: SourceRef,
    pub members: Vec<EnumMember>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedLink {
    pub response_source: SourceRef,
    pub link_name: String,
    pub target_operation_index: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Analyzed {
    pub ir: Ir,
    pub operation_names: Vec<AllocatedOperationName>,
    pub schema_names: Vec<AllocatedSchemaName>,
    pub enum_members: Vec<EnumMemberTable>,
    pub link_targets: Vec<ResolvedLink>,
    pub webhook_names: Vec<AllocatedWebhookName>,
    pub callback_names: Vec<AllocatedCallbackName>,
}

/// Runs name allocation and rule-14 enum analysis using resolved config.
pub fn analyze(ir: Ir, config: &ResolvedConfig, sink: &mut DiagnosticSink) -> Analyzed {
    analyze_with_options(ir, &config.naming, &config.types, sink)
}

/// Runs semantic analysis with the two option groups that affect Phase 3.
pub fn analyze_with_options(
    mut ir: Ir,
    naming: &NamingConfig,
    types: &TypesConfig,
    sink: &mut DiagnosticSink,
) -> Analyzed {
    lower_uninhabitable_all_ofs(&mut ir, sink);
    validate_unique_operation_ids(&ir, sink);
    let operation_names = allocate_operation_names(&ir, naming, sink);
    let webhook_names = allocate_webhook_names(&ir, sink);
    let callback_names = allocate_callback_names(&ir, &operation_names, &webhook_names, sink);
    let link_targets = resolve_links(&ir, sink);
    let schema_names = allocate_schema_names(&ir, naming, sink);
    report_unmatched_overrides(&ir, naming, sink);
    let mut enum_members = Vec::new();
    let mut enum_analysis = EnumAnalysis {
        naming,
        types,
        version: ir.version,
        sink,
        tables: &mut enum_members,
    };
    for schema in &ir.schemas {
        analyze_schema_enums(&schema.schema, &mut enum_analysis);
    }
    for operation in &ir.operations {
        for parameter in &operation.parameters {
            analyze_schema_enums(&parameter.schema, &mut enum_analysis);
        }
        if let Some(body) = &operation.request_body {
            for media_type in &body.media_types {
                analyze_schema_enums(&media_type.schema, &mut enum_analysis);
            }
        }
        for response in &operation.responses {
            for media_type in &response.media_types {
                analyze_schema_enums(&media_type.schema, &mut enum_analysis);
            }
        }
    }
    Analyzed {
        ir,
        operation_names,
        schema_names,
        enum_members,
        link_targets,
        webhook_names,
        callback_names,
    }
}

fn for_each_operation<'ir>(ir: &'ir Ir, visit: &mut impl FnMut(&'ir Operation)) {
    for operation in &ir.operations {
        visit_operation_tree(operation, visit);
    }
    for webhook in &ir.webhooks {
        for operation in &webhook.operations {
            visit_operation_tree(operation, visit);
        }
    }
}

fn visit_operation_tree<'ir>(operation: &'ir Operation, visit: &mut impl FnMut(&'ir Operation)) {
    visit(operation);
    for callback in &operation.callbacks {
        for expression in &callback.expressions {
            for operation in &expression.operations {
                visit_operation_tree(operation, visit);
            }
        }
    }
}

fn validate_unique_operation_ids(ir: &Ir, sink: &mut DiagnosticSink) {
    let mut seen: HashMap<&str, &SourceRef> = HashMap::new();
    for_each_operation(ir, &mut |operation| {
        let Some(operation_id) = operation.operation_id.as_deref() else {
            return;
        };
        if let Some(previous_source) = seen.get(operation_id) {
            sink.push(source_diagnostic(
                CODE_OPERATION_NAME,
                format!(
                    "duplicate operationId '{operation_id}' declared at {} and {}; OpenAPI requires operationId to be unique among all operations",
                    previous_source.display(),
                    operation.source.display()
                ),
                &operation.source,
            ));
        } else {
            seen.insert(operation_id, &operation.source);
        }
    });
}

fn resolve_links(ir: &Ir, sink: &mut DiagnosticSink) -> Vec<ResolvedLink> {
    // Resolve each link target in O(1). Both maps keep the first operation for a given key, so a
    // lookup lands on the same operation `Iterator::position` (first match) returned before.
    let mut by_operation_id: HashMap<&str, usize> = HashMap::new();
    let mut by_json_pointer: HashMap<&str, usize> = HashMap::new();
    for (index, operation) in ir.operations.iter().enumerate() {
        if let Some(operation_id) = operation.operation_id.as_deref() {
            by_operation_id.entry(operation_id).or_insert(index);
        }
        by_json_pointer
            .entry(operation.source.json_pointer.as_str())
            .or_insert(index);
    }
    let mut resolved_links = Vec::new();
    for operation in &ir.operations {
        for response in &operation.responses {
            for link in &response.links {
                let target_operation_index = match &link.target {
                    LinkTarget::OperationId(operation_id) => {
                        let target = by_operation_id.get(operation_id.as_str()).copied();
                        if target.is_none() {
                            sink.push(source_diagnostic(
                                CODE_LINK_OPERATION_ID,
                                format!(
                                    "link '{}' references unknown operationId '{}'",
                                    link.name, operation_id
                                ),
                                &link.source,
                            ));
                        }
                        target
                    }
                    LinkTarget::OperationRef(operation_ref) => {
                        let target = operation_ref
                            .strip_prefix('#')
                            .and_then(|fragment| by_json_pointer.get(fragment).copied());
                        if target.is_none() {
                            sink.push(source_diagnostic(
                                CODE_LINK_OPERATION_REF,
                                format!(
                                    "link '{}' operationRef '{}' does not resolve to an operation in this document",
                                    link.name, operation_ref
                                ),
                                &link.source,
                            ));
                        }
                        target
                    }
                };
                if let Some(target_operation_index) = target_operation_index {
                    for (parameter, _) in &link.parameters {
                        if !link_parameter_is_declared(
                            &ir.operations[target_operation_index],
                            parameter,
                        ) {
                            sink.push(source_diagnostic(
                                CODE_LINK_PARAMETER,
                                format!(
                                    "link '{}' parameter '{}' is not declared by the target operation",
                                    link.name, parameter
                                ),
                                &link.source,
                            ));
                        }
                    }
                }
                resolved_links.push(ResolvedLink {
                    response_source: response.source.clone(),
                    link_name: link.name.clone(),
                    target_operation_index,
                });
            }
        }
    }
    resolved_links
}

fn link_parameter_is_declared(operation: &Operation, key: &str) -> bool {
    let qualified = key.split_once('.').and_then(|(prefix, name)| {
        let location = match prefix {
            "path" => ParamLocation::Path,
            "query" => ParamLocation::Query,
            "header" => ParamLocation::Header,
            "cookie" => ParamLocation::Cookie,
            _ => return None,
        };
        Some((location, name))
    });
    let (location, name) = qualified.map_or((None, key), |(location, name)| (Some(location), name));
    operation.parameters.iter().any(|parameter| {
        parameter.name == name && location.is_none_or(|location| parameter.location == location)
    })
}

/// Allocates one operation name from an explicit ID or its method/path fallback.
pub fn derive_operation_name(
    operation: &Operation,
    case: TargetCase,
) -> Result<String, NormalizeError> {
    derive_operation_name_allocation(operation, case).map(|allocation| allocation.name)
}

fn derive_operation_name_allocation(
    operation: &Operation,
    case: TargetCase,
) -> Result<NameAllocation, NormalizeError> {
    if let Some(operation_id) = &operation.operation_id {
        return normalize_identifier_allocation(operation_id, case);
    }
    let mut candidate = operation.method.to_ascii_lowercase();
    for segment in &operation.path_template {
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(literal) => {
                    let tokens = identifier_tokens(literal)?;
                    candidate.push_str(&transform_tokens(&tokens, TargetCase::Pascal));
                }
                SegmentPart::Param(name) => {
                    candidate.push_str("By");
                    candidate.push_str(&normalize_identifier(name, TargetCase::Pascal)?);
                }
            }
        }
    }
    normalize_identifier_allocation(&candidate, case)
}

struct PendingOperationName {
    allocated: AllocatedOperationName,
    operation_id: Option<String>,
    overridden: bool,
}

fn allocate_operation_names(
    ir: &Ir,
    naming: &NamingConfig,
    sink: &mut DiagnosticSink,
) -> Vec<AllocatedOperationName> {
    let case = match naming.operation_case {
        OperationCase::Camel => TargetCase::Camel,
        OperationCase::Preserve => TargetCase::Preserve,
    };
    let mut pending = Vec::new();
    for (operation_index, operation) in ir.operations.iter().enumerate() {
        // An override keyed on operationId supplies the final name verbatim: the case transform
        // does not run on it and it must still validate and collide like any derived name.
        let override_name = operation
            .operation_id
            .as_deref()
            .and_then(|id| naming.overrides.operations.get(id));
        let allocation = match override_name {
            Some(name) => validate_final_identifier(name)
                .map(|()| NameAllocation {
                    name: name.clone(),
                    escaped_reserved_word: None,
                })
                .map_err(|error| (name.clone(), error)),
            None => derive_operation_name_allocation(operation, case).map_err(|error| {
                (
                    operation
                        .operation_id
                        .as_deref()
                        .unwrap_or("derived name")
                        .to_owned(),
                    error,
                )
            }),
        };
        match allocation {
            Ok(allocation) => {
                if let Some(word) = &allocation.escaped_reserved_word {
                    push_reserved_word_warning(
                        CODE_OPERATION_NAME,
                        "operation",
                        word,
                        &allocation.name,
                        &operation.source,
                        sink,
                    );
                }
                pending.push(PendingOperationName {
                    allocated: AllocatedOperationName {
                        operation_index,
                        name: allocation.name,
                        source: operation.source.clone(),
                    },
                    operation_id: operation.operation_id.clone(),
                    overridden: override_name.is_some(),
                });
            }
            Err((input, error)) => push_name_error(
                CODE_OPERATION_NAME,
                "operation",
                &input,
                error,
                &operation.source,
                sink,
            ),
        }
    }

    // Find collisions with borrowed keys. Keep the first index for each name so diagnostics retain
    // their original first-declaration source and encounter order.
    let mut first_indices = HashMap::<&str, usize>::with_capacity(pending.len());
    let mut collisions = Vec::new();
    for (index, operation) in pending.iter().enumerate() {
        let name = operation.allocated.name.as_str();
        if let Some(previous_index) = first_indices.get(name).copied() {
            collisions.push((index, previous_index));
        } else {
            first_indices.insert(name, index);
        }
    }
    drop(first_indices);

    let mut group_suggestions = HashMap::new();
    // Suggestions only reach a user through a collision diagnostic. Build the ordered grouping
    // and remedy indexes only on that uncommon path.
    if !collisions.is_empty() {
        let mut groups = BTreeMap::<&str, Vec<usize>>::new();
        for (index, operation) in pending.iter().enumerate() {
            groups
                .entry(operation.allocated.name.as_str())
                .or_default()
                .push(index);
        }
        let existing_file_names = pending.iter().filter_map(|operation| {
            let source_name = if operation.overridden {
                operation.allocated.name.as_str()
            } else {
                operation
                    .operation_id
                    .as_deref()
                    .unwrap_or(&operation.allocated.name)
            };
            crate::emit::file_base_name(source_name, naming.file_case).ok()
        });
        let mut suggester = OverrideSuggester::new(
            naming.file_case,
            pending
                .iter()
                .map(|operation| operation.allocated.name.as_str()),
            existing_file_names,
        );
        for (name, indices) in &groups {
            if indices.len() < 2 {
                continue;
            }
            let raw_names = indices
                .iter()
                .filter_map(|index| pending[*index].operation_id.as_deref())
                .collect::<Vec<_>>();
            let unique = raw_names.iter().copied().collect::<HashSet<_>>();
            if raw_names.len() == indices.len() && unique.len() == indices.len() {
                group_suggestions.insert(
                    (*name).to_owned(),
                    suggester.allocate(NamingOverrideNamespace::Operations, name, raw_names),
                );
            }
        }
    }

    for (index, previous_index) in collisions {
        let operation = &pending[index];
        let diagnostic = operation_collision_diagnostic(
            operation,
            &pending[previous_index],
            group_suggestions
                .get(&operation.allocated.name)
                .cloned()
                .unwrap_or_default(),
        );
        if let Some(diagnostic) = diagnostic {
            sink.push(diagnostic);
        }
    }
    pending
        .into_iter()
        .map(|operation| operation.allocated)
        .collect()
}

fn operation_collision_diagnostic(
    operation: &PendingOperationName,
    previous: &PendingOperationName,
    suggestions: Vec<NamingOverrideSuggestion>,
) -> Option<Diagnostic> {
    if matches!(
        (&previous.operation_id, &operation.operation_id),
        (Some(previous_id), Some(operation_id)) if previous_id == operation_id
    ) {
        return None;
    }
    Some(
        source_diagnostic(
            CODE_OPERATION_NAME,
            format!(
                "operation name collision: '{}' allocated at {} and {}",
                operation.allocated.name,
                previous.allocated.source.display(),
                operation.allocated.source.display()
            ),
            &operation.allocated.source,
        )
        .with_naming_override_suggestions(suggestions),
    )
}

/// Allocates one name stem per webhook operation, in a collision scope entirely separate from
/// `allocate_operation_names`.
///
/// Webhook files emit to their own output directory (a later, emission-side concern), so a
/// webhook stem colliding with, or being identical to, a path-operation name is not a collision
/// at all — the two never share a directory. Tracking both kinds in the same `seen` map would
/// make an unrelated webhook name perturb path-operation allocation (and vice versa), so this
/// pass keeps its own map and never touches the operation-name one.
fn allocate_webhook_names(ir: &Ir, sink: &mut DiagnosticSink) -> Vec<AllocatedWebhookName> {
    let mut names = Vec::new();
    let mut seen: HashMap<String, (String, SourceRef)> = HashMap::new();
    for (webhook_index, webhook) in ir.webhooks.iter().enumerate() {
        for (operation_index, operation) in webhook.operations.iter().enumerate() {
            match derive_webhook_stem(webhook, operation) {
                Ok(stem) => {
                    report_collision(
                        "webhook",
                        CODE_WEBHOOK_NAME,
                        &stem,
                        &operation.source,
                        &mut seen,
                        sink,
                    );
                    names.push(AllocatedWebhookName {
                        webhook_index,
                        operation_index,
                        stem,
                        source: operation.source.clone(),
                    });
                }
                Err((input, error)) => push_name_error(
                    CODE_WEBHOOK_NAME,
                    "webhook",
                    &input,
                    error,
                    &operation.source,
                    sink,
                ),
            }
        }
    }
    names
}

/// Derives one webhook operation's name stem: the operation's own `operationId` if present
/// (mirroring `derive_operation_name`, which never touches the method once an `operationId` is
/// available), else the webhook's name plus the Pascal-cased HTTP method — the same
/// Pascal-cased-token composition `derive_operation_name`'s fallback uses for path parts,
/// applied to a webhook's name instead of a path template (webhooks have no path).
///
/// The method is capitalized directly rather than run through `normalize_identifier`: it is one
/// of the parser's fixed `METHODS` literals (never document-supplied), so it can never fail to
/// normalize — exactly the trust `derive_operation_name`'s own fallback already places in it.
fn derive_webhook_stem(
    webhook: &Webhook,
    operation: &Operation,
) -> Result<String, (String, NormalizeError)> {
    if let Some(operation_id) = &operation.operation_id {
        return normalize_identifier(operation_id, TargetCase::Pascal)
            .map_err(|error| (operation_id.clone(), error));
    }
    let name_stem = normalize_identifier(&webhook.name, TargetCase::Pascal)
        .map_err(|error| (webhook.name.clone(), error))?;
    Ok(format!(
        "{name_stem}{}",
        capitalize_token(&operation.method)
    ))
}

/// Allocates one name stem per callback-expression operation at every depth, in a single
/// collision scope separate from both `allocate_operation_names` and `allocate_webhook_names`.
///
/// Every callback operation emits to the one shared `types/callbacks/` directory regardless of
/// where it was declared, so all callback stems — path-operation, webhook-operation, and nested
/// — share this pass's one `seen` map (a stem colliding across those declaration sites is a real
/// file collision), while webhooks and path operations keep their own separate scopes.
///
/// The walk is pre-order DFS: each callback operation's stem is allocated, then its own nested
/// callbacks are walked with that stem as their parent. A callback whose parent operation failed
/// to allocate a stem (a path/webhook operation absent from its name table, or a callback
/// operation whose own normalization failed) has no base to build on and is skipped, along with
/// anything nested beneath it.
fn allocate_callback_names(
    ir: &Ir,
    operation_names: &[AllocatedOperationName],
    webhook_names: &[AllocatedWebhookName],
    sink: &mut DiagnosticSink,
) -> Vec<AllocatedCallbackName> {
    let mut names = Vec::new();
    let mut seen: HashMap<String, (String, SourceRef)> = HashMap::new();
    for allocated in operation_names {
        let operation = &ir.operations[allocated.operation_index];
        // Fast-reject before the parent-stem allocation: the vast majority of operations declare
        // no callbacks, so deriving a stem for each would allocate a String that is never used.
        if operation.callbacks.is_empty() {
            continue;
        }
        let parent_stem = capitalize_token(&allocated.name);
        allocate_operation_callbacks(
            operation,
            &CallbackParent::Operation {
                operation_index: allocated.operation_index,
            },
            &parent_stem,
            &mut names,
            &mut seen,
            sink,
        );
    }
    for allocated in webhook_names {
        allocate_operation_callbacks(
            &ir.webhooks[allocated.webhook_index].operations[allocated.operation_index],
            &CallbackParent::WebhookOperation {
                webhook_index: allocated.webhook_index,
                operation_index: allocated.operation_index,
            },
            &allocated.stem,
            &mut names,
            &mut seen,
            sink,
        );
    }
    names
}

/// Allocates every callback declared directly on `operation`, then recurses into each allocated
/// callback operation's own callbacks. `parent` and `parent_stem` describe the declaring
/// operation (the recursion passes the just-allocated child as the parent of its nested
/// callbacks).
fn allocate_operation_callbacks(
    operation: &Operation,
    parent: &CallbackParent,
    parent_stem: &str,
    names: &mut Vec<AllocatedCallbackName>,
    seen: &mut HashMap<String, (String, SourceRef)>,
    sink: &mut DiagnosticSink,
) {
    for (callback_index, callback) in operation.callbacks.iter().enumerate() {
        // The expression disambiguator only exists to keep expressions apart within the
        // same callback; a single-expression callback needs none.
        let disambiguate = callback.expressions.len() > 1;
        for (expression_index, expression) in callback.expressions.iter().enumerate() {
            for (operation_index_within_expression, expression_operation) in
                expression.operations.iter().enumerate()
            {
                let allocation = derive_callback_stem(
                    parent_stem,
                    callback,
                    expression_index,
                    disambiguate,
                    expression_operation,
                );
                match allocation {
                    Ok(stem) => {
                        report_collision(
                            "callback",
                            CODE_WEBHOOK_NAME,
                            &stem,
                            &expression_operation.source,
                            seen,
                            sink,
                        );
                        let index = names.len();
                        names.push(AllocatedCallbackName {
                            parent: parent.clone(),
                            parent_stem: parent_stem.to_owned(),
                            callback_index,
                            expression_index,
                            operation_index_within_expression,
                            stem: stem.clone(),
                            source: expression_operation.source.clone(),
                        });
                        allocate_operation_callbacks(
                            expression_operation,
                            &CallbackParent::Callback { index },
                            &stem,
                            names,
                            seen,
                            sink,
                        );
                    }
                    Err((input, error)) => push_name_error(
                        CODE_WEBHOOK_NAME,
                        "callback",
                        &input,
                        error,
                        &expression_operation.source,
                        sink,
                    ),
                }
            }
        }
    }
}

/// Derives one callback-expression operation's name stem: the parent operation's own stem, the
/// callback's Pascal-cased name, an optional 1-based `_N` expression disambiguator, then the
/// Pascal-cased HTTP method. The runtime expression string (e.g. `{$request.body#/url}`) never
/// contributes to the identifier — it is preserved verbatim only for later use as a quoted
/// string key in descriptor emission.
///
/// As in `derive_webhook_stem`, the method is capitalized directly: it is always one of the
/// parser's fixed `METHODS` literals, never document-supplied, so it cannot fail to normalize.
fn derive_callback_stem(
    parent_stem: &str,
    callback: &Callback,
    expression_index: usize,
    disambiguate: bool,
    operation: &Operation,
) -> Result<String, (String, NormalizeError)> {
    let callback_name_stem = normalize_identifier(&callback.name, TargetCase::Pascal)
        .map_err(|error| (callback.name.clone(), error))?;
    let disambiguator = if disambiguate {
        format!("_{}", expression_index + 1)
    } else {
        String::new()
    };
    Ok(format!(
        "{parent_stem}{callback_name_stem}{disambiguator}{}",
        capitalize_token(&operation.method)
    ))
}

/// Whether a schema has a stable raw name that can key `naming.overrides.schemas`.
///
/// Declared components use their map key. A materialized document-root schema uses its file stem,
/// which is likewise stable and user-addressable. Other materialized schemas are named from their
/// pointer context, so they remain outside the override namespace. The root-component test keeps
/// `/components/schemas/Foo/properties/bar` — an inline schema that merely lives under a declared
/// one — out.
fn is_overrideable_schema(source: &SourceRef) -> bool {
    source.json_pointer.is_empty() || is_root_component_pointer(&source.json_pointer)
}

/// The override entry that renames `schema`, if its raw name is user-addressable.
fn schema_override<'naming>(
    naming: &'naming NamingConfig,
    schema: &NamedSchema,
) -> Option<&'naming String> {
    is_overrideable_schema(&schema.source)
        .then(|| naming.overrides.schemas.get(&schema.name))
        .flatten()
}

struct PendingSchemaName {
    allocated: AllocatedSchemaName,
    overridden: bool,
}

fn allocate_schema_names(
    ir: &Ir,
    naming: &NamingConfig,
    sink: &mut DiagnosticSink,
) -> Vec<AllocatedSchemaName> {
    let mut pending = Vec::new();
    for (schema_index, schema) in ir.schemas.iter().enumerate() {
        // An override supplies the complete identifier: typePrefix/typeSuffix are not applied on
        // top, but the value must still validate and collide like any generated name.
        let allocation = match schema_override(naming, schema) {
            Some(name) => validate_final_identifier(name)
                .map(|()| NameAllocation {
                    name: name.clone(),
                    escaped_reserved_word: None,
                })
                .map_err(|error| (name.clone(), error)),
            None => normalize_identifier(&schema.name, TargetCase::Pascal)
                .and_then(|base| {
                    let candidate = format!("{}{}{}", naming.type_prefix, base, naming.type_suffix);
                    validate_final_identifier(&candidate)?;
                    Ok(NameAllocation {
                        name: candidate,
                        escaped_reserved_word: None,
                    })
                })
                .map_err(|error| (schema.name.clone(), error)),
        };
        match allocation {
            Ok(allocation) => {
                pending.push(PendingSchemaName {
                    allocated: AllocatedSchemaName {
                        schema_index,
                        wire_name: schema.name.clone(),
                        name: allocation.name,
                        source: schema.source.clone(),
                    },
                    overridden: schema_override(naming, schema).is_some(),
                });
            }
            Err((input, error)) => push_name_error(
                CODE_TYPE_NAME,
                "schema",
                &input,
                error,
                &schema.source,
                sink,
            ),
        }
    }

    // Find collisions with borrowed keys. Keep the first index for each name so diagnostics retain
    // their original first-declaration source and encounter order.
    let mut first_indices = HashMap::<&str, usize>::with_capacity(pending.len());
    let mut collisions = Vec::new();
    for (index, schema) in pending.iter().enumerate() {
        let name = schema.allocated.name.as_str();
        if let Some(previous_index) = first_indices.get(name).copied() {
            collisions.push((index, previous_index));
        } else {
            first_indices.insert(name, index);
        }
    }
    drop(first_indices);

    let mut all_suggestions = Vec::new();
    // Suggestions only ever reach the user attached to an OASTS1202, so a document with no
    // identifier collision can never be shown one. Everything below — indexing every allocated
    // name, deriving a file base per schema, grouping those — is remedy machinery, and skipping
    // it outright is what keeps the overwhelmingly common clean run from paying for it.
    if !collisions.is_empty() {
        let mut groups = BTreeMap::<&str, Vec<usize>>::new();
        for (index, schema) in pending.iter().enumerate() {
            groups
                .entry(schema.allocated.name.as_str())
                .or_default()
                .push(index);
        }
        let mut suggested_sources = HashSet::new();
        let existing_file_names = pending.iter().filter_map(|schema| {
            let source_name = if schema.overridden {
                schema.allocated.name.as_str()
            } else {
                &schema.allocated.wire_name
            };
            crate::emit::file_base_name(source_name, naming.file_case).ok()
        });
        let mut suggester = OverrideSuggester::new(
            naming.file_case,
            pending.iter().map(|schema| schema.allocated.name.as_str()),
            existing_file_names,
        );
        collect_schema_override_suggestions(
            &pending,
            naming,
            &groups,
            &mut suggester,
            &mut suggested_sources,
            &mut all_suggestions,
        );
    }

    for (index, previous_index) in collisions {
        let schema = &pending[index];
        let previous = &pending[previous_index];
        let message = format!(
            "schema name collision: '{}' allocated at {} and {}",
            schema.allocated.name,
            previous.allocated.source.display(),
            schema.allocated.source.display()
        );
        sink.push(
            source_diagnostic(CODE_TYPE_NAME, message, &schema.allocated.source)
                .with_naming_override_suggestions(all_suggestions.clone()),
        );
    }
    pending.into_iter().map(|schema| schema.allocated).collect()
}

/// The paste-ready `naming.overrides.schemas` block for a run that collided, covering both the
/// identifier collisions themselves and the latent file-path collisions a pasted override would
/// otherwise uncover on the next run.
fn collect_schema_override_suggestions(
    pending: &[PendingSchemaName],
    naming: &NamingConfig,
    groups: &BTreeMap<&str, Vec<usize>>,
    suggester: &mut OverrideSuggester,
    suggested_sources: &mut HashSet<String>,
    all_suggestions: &mut Vec<NamingOverrideSuggestion>,
) {
    for (name, indices) in groups {
        if indices.len() < 2
            || !indices
                .iter()
                .all(|index| is_overrideable_schema(&pending[*index].allocated.source))
        {
            continue;
        }
        let raw_names = indices
            .iter()
            .map(|index| pending[*index].allocated.wire_name.as_str())
            .collect::<Vec<_>>();
        let unique = raw_names.iter().copied().collect::<HashSet<_>>();
        if unique.len() == indices.len() {
            let suggestions = suggester.allocate(NamingOverrideNamespace::Schemas, name, raw_names);
            suggested_sources.extend(
                suggestions
                    .iter()
                    .map(|suggestion| suggestion.source_name.clone()),
            );
            all_suggestions.extend(suggestions);
        }
    }

    // A pasted identifier override also becomes that declaration's file-base source. Include
    // latent raw-name path collisions in the same block so resolving OASTS1202 cannot merely
    // uncover OASTS1302 on the next run.
    let mut file_groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, schema) in pending.iter().enumerate() {
        if !is_overrideable_schema(&schema.allocated.source) {
            continue;
        }
        let source_name = if schema.overridden {
            schema.allocated.name.as_str()
        } else {
            &schema.allocated.wire_name
        };
        if let Ok(file_base) = crate::emit::file_base_name(source_name, naming.file_case) {
            file_groups
                .entry(file_base.to_ascii_lowercase())
                .or_default()
                .push(index);
        }
    }
    for indices in file_groups.values().filter(|indices| indices.len() > 1) {
        let raw_names = indices
            .iter()
            .map(|index| pending[*index].allocated.wire_name.as_str())
            .collect::<Vec<_>>();
        let unique = raw_names.iter().copied().collect::<HashSet<_>>();
        if unique.len() != indices.len()
            || raw_names
                .iter()
                .any(|source_name| suggested_sources.contains(*source_name))
        {
            continue;
        }
        let suggestions = suggester.allocate_with_bases(
            NamingOverrideNamespace::Schemas,
            indices
                .iter()
                .map(|index| {
                    (
                        pending[*index].allocated.wire_name.as_str(),
                        pending[*index].allocated.name.as_str(),
                    )
                })
                .collect(),
        );
        suggested_sources.extend(
            suggestions
                .iter()
                .map(|suggestion| suggestion.source_name.clone()),
        );
        all_suggestions.extend(suggestions);
    }
}

/// Reports every override key that names no declaration in the document.
///
/// This is a config error (exit code 2): a typo that silently did nothing would leave the
/// collision the override was meant to resolve still unexplained, sending the user hunting.
/// The check needs the document, so it runs here rather than at config load. Keys are visited
/// in the map's sorted order, so the diagnostics are deterministic.
fn report_unmatched_overrides(ir: &Ir, naming: &NamingConfig, sink: &mut DiagnosticSink) {
    for key in naming.overrides.schemas.keys() {
        if !ir
            .schemas
            .iter()
            .any(|schema| &schema.name == key && is_overrideable_schema(&schema.source))
        {
            sink.push(unmatched_override_diagnostic("schema", "schemas", key));
        }
    }
    for key in naming.overrides.operations.keys() {
        if !ir
            .operations
            .iter()
            .any(|operation| operation.operation_id.as_deref() == Some(key.as_str()))
        {
            sink.push(unmatched_override_diagnostic(
                "operation",
                "operations",
                key,
            ));
        }
    }
}

fn unmatched_override_diagnostic(kind: &str, namespace: &str, key: &str) -> Diagnostic {
    Diagnostic::config(
        CODE_OVERRIDE_UNMATCHED,
        format!("naming override key '{key}' matches no {kind} in the document"),
    )
    .with_json_pointer(format!(
        "/naming/overrides/{namespace}/{}",
        escape_json_pointer_token(key)
    ))
}

/// Escapes a single JSON Pointer reference token per RFC 6901 (`~` -> `~0`, `/` -> `~1`).
fn escape_json_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

struct OverrideSuggester {
    file_case: FileCase,
    taken_identifiers: HashSet<String>,
    taken_file_bases: HashSet<String>,
}

impl OverrideSuggester {
    fn new<'name>(
        file_case: FileCase,
        identifiers: impl IntoIterator<Item = &'name str>,
        file_bases: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            file_case,
            taken_identifiers: identifiers.into_iter().map(str::to_owned).collect(),
            taken_file_bases: file_bases
                .into_iter()
                .map(|file_base| file_base.to_ascii_lowercase())
                .collect(),
        }
    }

    fn allocate(
        &mut self,
        namespace: NamingOverrideNamespace,
        base: &str,
        source_names: Vec<&str>,
    ) -> Vec<NamingOverrideSuggestion> {
        self.allocate_with_bases(
            namespace,
            source_names
                .into_iter()
                .map(|source_name| (source_name, base))
                .collect(),
        )
    }

    fn allocate_with_bases(
        &mut self,
        namespace: NamingOverrideNamespace,
        mut entries: Vec<(&str, &str)>,
    ) -> Vec<NamingOverrideSuggestion> {
        entries.sort_unstable_by_key(|(source_name, _)| *source_name);
        entries
            .into_iter()
            .map(|(source_name, base)| {
                let mut suffix = 1_u64;
                loop {
                    let identifier = format!("{base}_{suffix}");
                    suffix += 1;
                    let file_base = crate::emit::file_base_name(&identifier, self.file_case)
                        .expect("a valid TypeScript identifier always produces a safe file base")
                        .to_ascii_lowercase();
                    if self.taken_identifiers.contains(&identifier)
                        || self.taken_file_bases.contains(&file_base)
                    {
                        continue;
                    }
                    self.taken_identifiers.insert(identifier.clone());
                    self.taken_file_bases.insert(file_base);
                    break NamingOverrideSuggestion {
                        namespace,
                        source_name: source_name.to_owned(),
                        identifier,
                    };
                }
            })
            .collect()
    }
}

fn report_collision(
    kind: &str,
    code: &'static str,
    name: &str,
    source: &SourceRef,
    seen: &mut HashMap<String, (String, SourceRef)>,
    sink: &mut DiagnosticSink,
) {
    // Exact match over case-folded match at the identifier layer, because TypeScript
    // identifiers are case-sensitive: two names differing only in case are two distinct,
    // legal types. Filesystem safety on case-insensitive volumes is enforced separately
    // by the path-collision check (`register_path` / OASTS1302 in `emit/model.rs`), so this
    // layer must not also reject case-only differences.
    if let Some((_, previous_source)) = seen.get(name) {
        let message = format!(
            "{kind} name collision: '{name}' allocated at {} and {}",
            previous_source.display(),
            source.display()
        );
        sink.push(source_diagnostic(code, message, source));
    } else {
        seen.insert(name.to_owned(), (name.to_owned(), source.clone()));
    }
}

fn casefold_collision<T>(
    name: &str,
    seen: &HashMap<String, T>,
    message: impl FnOnce(&T) -> String,
) -> (String, Option<String>) {
    let folded = name.to_ascii_lowercase();
    let collision = seen.get(&folded).map(message);
    (folded, collision)
}

fn push_name_error(
    code: &'static str,
    kind: &str,
    input: &str,
    error: NormalizeError,
    source: &SourceRef,
    sink: &mut DiagnosticSink,
) {
    sink.push(source_diagnostic(
        code,
        format!("invalid {kind} identifier '{input}': {error}"),
        source,
    ));
}

fn push_reserved_word_warning(
    code: &'static str,
    kind: &str,
    original: &str,
    emitted: &str,
    source: &SourceRef,
    sink: &mut DiagnosticSink,
) {
    let mut diagnostic = source_diagnostic(
        code,
        format!(
            "{kind} identifier '{original}' is a TypeScript reserved word; emitted as '{emitted}'"
        ),
        source,
    );
    diagnostic.severity = Severity::Warning;
    sink.push(diagnostic);
}

struct EnumAnalysis<'options, 'output> {
    naming: &'options NamingConfig,
    types: &'options TypesConfig,
    version: OasVersion,
    sink: &'output mut DiagnosticSink,
    tables: &'output mut Vec<EnumMemberTable>,
}

fn analyze_schema_enums(schema: &SchemaNode, analysis: &mut EnumAnalysis<'_, '_>) {
    validate_numeric_bound_domain(schema.meta(), analysis.sink);
    validate_annotation_domain(schema.meta(), analysis.sink);
    match schema {
        SchemaNode::Primitive {
            enum_values,
            const_value,
            meta,
            ..
        } => analyze_finite_values(enum_values.as_deref(), const_value.as_ref(), meta, analysis),
        SchemaNode::Finite {
            enum_values,
            const_value,
            meta,
        } => analyze_finite_values(enum_values.as_deref(), const_value.as_ref(), meta, analysis),
        SchemaNode::Object {
            properties,
            additional_properties,
            finite,
            meta,
            ..
        } => {
            let (enum_values, const_value) = finite_parts(finite);
            analyze_finite_values(enum_values, const_value, meta, analysis);
            for (_, property, _) in properties {
                analyze_schema_enums(property, analysis);
            }
            match additional_properties {
                AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) => {
                    analyze_schema_enums(schema, analysis);
                }
                AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => {}
            }
        }
        SchemaNode::Array {
            items,
            finite,
            meta,
            ..
        } => {
            let (enum_values, const_value) = finite_parts(finite);
            analyze_finite_values(enum_values, const_value, meta, analysis);
            analyze_schema_enums(items, analysis);
        }
        SchemaNode::Tuple {
            prefix_items,
            rest,
            finite,
            meta,
        } => {
            let (enum_values, const_value) = finite_parts(finite);
            analyze_finite_values(enum_values, const_value, meta, analysis);
            for item in prefix_items {
                analyze_schema_enums(item, analysis);
            }
            if let TupleRest::Schema(schema) = rest {
                analyze_schema_enums(schema, analysis);
            }
        }
        SchemaNode::AllOf { branches, meta }
        | SchemaNode::AnyOf { branches, meta, .. }
        | SchemaNode::OneOf { branches, meta, .. } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
            for branch in branches {
                analyze_schema_enums(branch, analysis);
            }
        }
        SchemaNode::Ref { meta, .. }
        | SchemaNode::Any { meta }
        | SchemaNode::Never { meta }
        | SchemaNode::Unknown { meta, .. } => {
            validate_enum_extensions(None, meta, analysis.types, analysis.sink);
        }
    }
    let Some(applicators) = schema.meta().validation_applicators.as_deref() else {
        return;
    };
    if let Some(schema) = &applicators.not {
        analyze_schema_enums(schema, analysis);
    }
    if let Some(schema) = &applicators.property_names {
        analyze_schema_enums(schema, analysis);
    }
    for pattern in &applicators.pattern_properties {
        analyze_schema_enums(&pattern.schema, analysis);
    }
    if let Some(contains) = &applicators.contains {
        analyze_schema_enums(&contains.schema, analysis);
    }
    for (_, schema) in &applicators.dependent_schemas {
        analyze_schema_enums(schema, analysis);
    }
    if let Some(conditional) = &applicators.conditional {
        analyze_schema_enums(&conditional.condition, analysis);
        if let Some(schema) = &conditional.then_schema {
            analyze_schema_enums(schema, analysis);
        }
        if let Some(schema) = &conditional.else_schema {
            analyze_schema_enums(schema, analysis);
        }
    }
    if let Some(schema) = &applicators.unevaluated_properties {
        analyze_schema_enums(schema, analysis);
    }
    if let Some(schema) = &applicators.unevaluated_items {
        analyze_schema_enums(schema, analysis);
    }
}

fn validate_numeric_bound_domain(meta: &SchemaMeta, sink: &mut DiagnosticSink) {
    let Some(constraints) = meta.numeric_constraints.as_deref() else {
        return;
    };
    let bounds = [
        ("minimum", constraints.minimum.as_ref()),
        ("maximum", constraints.maximum.as_ref()),
        (
            "exclusiveMinimum",
            match constraints.exclusive_minimum.as_ref() {
                Some(ExclusiveBound::Number(number)) => Some(number),
                Some(ExclusiveBound::Boolean(_)) | None => None,
            },
        ),
        (
            "exclusiveMaximum",
            match constraints.exclusive_maximum.as_ref() {
                Some(ExclusiveBound::Number(number)) => Some(number),
                Some(ExclusiveBound::Boolean(_)) | None => None,
            },
        ),
    ];
    for (keyword, number) in bounds {
        if let Some(number) = number
            && finite_binary64(number).is_none()
        {
            sink.push(source_diagnostic(
                CODE_NUMERIC_BOUND_DOMAIN,
                format!(
                    "numeric bound {keyword} '{}' is outside the binary64 domain",
                    number
                ),
                &meta.source,
            ));
        }
    }
}

fn validate_annotation_domain(meta: &SchemaMeta, sink: &mut DiagnosticSink) {
    if meta.docs.default.is_none() && meta.docs.examples.is_empty() {
        return;
    }
    for value in meta.docs.default.iter().chain(meta.docs.examples.iter()) {
        if let Some(number) = first_number_outside_binary64(value) {
            let mut diagnostic = source_diagnostic(
                CODE_ANNOTATION_DOMAIN,
                format!(
                    "default or example value '{}' is outside the binary64 domain and is shown only as documentation text",
                    number
                ),
                &meta.source,
            );
            diagnostic.severity = Severity::Warning;
            sink.push(diagnostic);
        }
    }
}

fn analyze_finite_values(
    enum_values: Option<&[Value]>,
    const_value: Option<&Value>,
    meta: &SchemaMeta,
    analysis: &mut EnumAnalysis<'_, '_>,
) {
    if enum_values.is_none() && const_value.is_none() && meta.enum_extensions.is_none() {
        return;
    }
    let extension_values =
        validate_enum_extensions(enum_values, meta, analysis.types, analysis.sink);
    if let Some(values) = enum_values {
        if values.is_empty() {
            match analysis.version {
                OasVersion::V3_0 => enum_error(
                    meta,
                    "enum must contain at least one member in OpenAPI 3.0 (MUST)",
                    analysis.sink,
                ),
                OasVersion::V3_1 => enum_warning(
                    meta,
                    "enum should contain at least one member in OpenAPI 3.1 (SHOULD); the schema admits no value and is lowered to never",
                    analysis.sink,
                ),
            }
        }
        validate_numeric_members(values, meta, true, analysis.sink);
    }
    if let Some(value) = const_value {
        validate_numeric_members(std::slice::from_ref(value), meta, false, analysis.sink);
    }

    let selected = finite_intersection(enum_values, const_value);
    let Some(selected) = selected else {
        if enum_values.is_some() && const_value.is_some() {
            enum_error(
                meta,
                "enum and const have an empty intersection",
                analysis.sink,
            );
        }
        return;
    };
    if selected.is_empty() {
        return;
    }
    if analysis.types.enum_representation != EnumRepresentation::Const {
        return;
    }

    let mut members = Vec::new();
    let mut seen = HashMap::new();
    for value in selected {
        let enum_index = enum_values.and_then(|values| {
            values
                .iter()
                .position(|candidate| values_equal(candidate, value))
        });
        let explicit_name = match (&extension_values.names, enum_index) {
            (Some(names), Some(index)) => names.get(index),
            _ => None,
        };
        let name_result = match explicit_name {
            Some(name) => validate_explicit_enum_name(name.clone()),
            None => derive_enum_member_name_allocation(value, analysis.naming.enum_member_case),
        };
        let allocation = match name_result {
            Ok(allocation) => allocation,
            Err(error) => {
                enum_error(
                    meta,
                    format!("invalid enum member name: {error}"),
                    analysis.sink,
                );
                continue;
            }
        };
        if let Some(word) = &allocation.escaped_reserved_word {
            push_reserved_word_warning(
                CODE_ENUM_RULE_14,
                "enum member",
                word,
                &allocation.name,
                &meta.source,
                analysis.sink,
            );
        }
        let name = allocation.name;
        let (folded, collision) = casefold_collision(&name, &seen, |previous| {
            format!("enum member names '{previous}' and '{name}' collide after case folding")
        });
        seen.insert(folded, name.clone());
        if let Some(message) = collision {
            enum_error(meta, message, analysis.sink);
        }
        let description = extension_values
            .descriptions
            .as_ref()
            .and_then(|descriptions| {
                enum_index
                    .and_then(|index| descriptions.get(index))
                    .cloned()
                    .flatten()
            });
        members.push(EnumMember {
            name,
            value: value.clone(),
            description,
        });
    }
    analysis.tables.push(EnumMemberTable {
        source: meta.source.clone(),
        members,
    });
}

#[derive(Default)]
struct ValidatedExtensions {
    names: Option<Vec<String>>,
    descriptions: Option<Vec<Option<String>>>,
}

fn validate_enum_extensions(
    enum_values: Option<&[Value]>,
    meta: &SchemaMeta,
    types: &TypesConfig,
    sink: &mut DiagnosticSink,
) -> ValidatedExtensions {
    let Some(enum_ext) = meta.enum_extensions.as_deref() else {
        return ValidatedExtensions::default();
    };
    let extensions = [
        ("x-enum-varnames", enum_ext.enum_varnames.as_ref()),
        ("x-enumNames", enum_ext.enum_names.as_ref()),
        ("x-enum-descriptions", enum_ext.enum_descriptions.as_ref()),
        (
            "x-enumDescriptions",
            enum_ext.enum_descriptions_camel.as_ref(),
        ),
    ];
    if types.enum_extensions == EnumExtensions::Reject {
        for (name, value) in extensions {
            if value.is_some() {
                enum_error(
                    meta,
                    format!("enum extension '{name}' is rejected by config"),
                    sink,
                );
            }
        }
        return ValidatedExtensions::default();
    }

    let expected_len = enum_values.map_or(0, <[Value]>::len);
    let first_names = validate_extension_array(
        "x-enum-varnames",
        enum_ext.enum_varnames.as_ref(),
        expected_len,
        meta,
        sink,
        str::to_owned,
    );
    let second_names = validate_extension_array(
        "x-enumNames",
        enum_ext.enum_names.as_ref(),
        expected_len,
        meta,
        sink,
        str::to_owned,
    );
    let first_descriptions = validate_extension_array(
        "x-enum-descriptions",
        enum_ext.enum_descriptions.as_ref(),
        expected_len,
        meta,
        sink,
        |description| Some(description.to_owned()),
    );
    let second_descriptions = validate_camel_enum_descriptions(
        enum_values,
        enum_ext.enum_descriptions_camel.as_ref(),
        meta,
        sink,
    );
    if let (Some(left), Some(right)) = (&first_names, &second_names)
        && left != right
    {
        enum_error(meta, "x-enum-varnames and x-enumNames disagree", sink);
    }
    if let (Some(left), Some(right)) = (&first_descriptions, &second_descriptions)
        && left != right
    {
        enum_error(
            meta,
            "x-enum-descriptions and x-enumDescriptions disagree",
            sink,
        );
    }
    let names = first_names.or(second_names);
    if let Some(names) = &names {
        validate_explicit_name_set(names, meta, sink);
    }
    ValidatedExtensions {
        names,
        descriptions: first_descriptions.or(second_descriptions),
    }
}

fn validate_camel_enum_descriptions(
    enum_values: Option<&[Value]>,
    value: Option<&Value>,
    meta: &SchemaMeta,
    sink: &mut DiagnosticSink,
) -> Option<Vec<Option<String>>> {
    let value = value?;
    let enum_values = enum_values.unwrap_or_default();
    match value {
        Value::Array(_) => validate_extension_array(
            "x-enumDescriptions",
            Some(value),
            enum_values.len(),
            meta,
            sink,
            |description| Some(description.to_owned()),
        ),
        Value::Object(entries) => {
            let Some(entries) = entries
                .iter()
                .map(|(name, description)| Some((name, description.as_str()?)))
                .collect::<Option<Vec<_>>>()
            else {
                enum_extension_warning(
                    meta,
                    "enum extension 'x-enumDescriptions' must map enum values to description strings; it is ignored",
                    sink,
                );
                return None;
            };
            let mut descriptions = vec![None; enum_values.len()];
            for (name, description) in entries {
                let Some(index) = enum_values
                    .iter()
                    .position(|value| value.as_str() == Some(name))
                else {
                    enum_extension_warning(
                        meta,
                        format!(
                            "enum extension 'x-enumDescriptions' key '{name}' does not name a string enum member; the entry is ignored"
                        ),
                        sink,
                    );
                    continue;
                };
                descriptions[index] = Some(description.to_owned());
            }
            Some(descriptions)
        }
        _ => {
            enum_extension_warning(
                meta,
                "enum extension 'x-enumDescriptions' must be an array or a map; it is ignored",
                sink,
            );
            None
        }
    }
}

fn validate_extension_array<T>(
    name: &str,
    value: Option<&Value>,
    expected_len: usize,
    meta: &SchemaMeta,
    sink: &mut DiagnosticSink,
    convert: impl FnMut(&str) -> T,
) -> Option<Vec<T>> {
    let value = value?;
    let Some(array) = value.as_array() else {
        enum_extension_warning(
            meta,
            format!("enum extension '{name}' must be an array; it is ignored"),
            sink,
        );
        return None;
    };
    if array.len() != expected_len {
        enum_extension_warning(
            meta,
            format!(
                "enum extension '{name}' has length {}, expected {expected_len}; it is ignored",
                array.len()
            ),
            sink,
        );
        return None;
    }
    let Some(strings) = array.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
        enum_extension_warning(
            meta,
            format!("enum extension '{name}' must contain only strings; it is ignored"),
            sink,
        );
        return None;
    };
    Some(strings.into_iter().map(convert).collect())
}

fn validate_explicit_name_set(names: &[String], meta: &SchemaMeta, sink: &mut DiagnosticSink) {
    let mut seen = HashMap::new();
    for name in names {
        if let Err(error) = validate_explicit_enum_name(name.clone()) {
            enum_error(
                meta,
                format!("invalid explicit enum member name '{name}': {error}"),
                sink,
            );
        }
        let (folded, collision) = casefold_collision(name, &seen, |_| {
            format!("explicit enum member name '{name}' collides after case folding")
        });
        seen.insert(folded, ());
        if let Some(message) = collision {
            enum_error(meta, message, sink);
        }
    }
}

fn validate_explicit_enum_name(name: String) -> Result<NameAllocation, NormalizeError> {
    if let Some(character) = name.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    validate_final_identifier_allocation(name)
}

fn validate_numeric_members(
    values: &[Value],
    meta: &SchemaMeta,
    detect_collisions: bool,
    sink: &mut DiagnosticSink,
) {
    let mut seen = HashMap::new();
    for value in values {
        validate_numeric_value(value, meta, detect_collisions, &mut seen, sink);
    }
}

fn validate_numeric_value(
    value: &Value,
    meta: &SchemaMeta,
    detect_collision: bool,
    seen: &mut HashMap<u64, String>,
    sink: &mut DiagnosticSink,
) {
    match value {
        Value::Number(number) => {
            let raw = number.to_string();
            let Some(binary64) = finite_binary64(number) else {
                enum_error(
                    meta,
                    format!("numeric member {raw} is outside the binary64 domain"),
                    sink,
                );
                return;
            };
            let original =
                Decimal::parse(&raw).expect("serde_json number rendering is valid decimal");
            if original.negative_zero {
                enum_error(meta, "numeric enum member -0 is not representable", sink);
                return;
            }
            let rendered = render_number(binary64);
            if Decimal::parse(&rendered).as_ref() != Some(&original) {
                enum_error(
                    meta,
                    format!(
                        "numeric member {raw} does not round-trip through binary64 (renders as {rendered})"
                    ),
                    sink,
                );
            }
            if detect_collision {
                let bits = binary64.to_bits();
                if let Some(previous) = seen.insert(bits, raw.clone()) {
                    enum_error(
                        meta,
                        format!(
                            "numeric members {previous} and {raw} collide after binary64 conversion"
                        ),
                        sink,
                    );
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_numeric_value(value, meta, false, seen, sink);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_numeric_value(value, meta, false, seen, sink);
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn finite_intersection<'a>(
    enum_values: Option<&'a [Value]>,
    const_value: Option<&'a Value>,
) -> Option<Vec<&'a Value>> {
    match (enum_values, const_value) {
        (None, None) => Some(Vec::new()),
        (Some(values), None) => Some(values.iter().collect()),
        (None, Some(value)) => Some(vec![value]),
        (Some(values), Some(value)) => values
            .iter()
            .any(|candidate| values_equal(candidate, value))
            .then(|| vec![value]),
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            Decimal::parse(&left.to_string()) == Decimal::parse(&right.to_string())
        }
        _ => left == right,
    }
}

#[cfg(test)]
fn derive_enum_member_name(
    value: &Value,
    enum_case: EnumMemberCase,
) -> Result<String, NormalizeError> {
    derive_enum_member_name_allocation(value, enum_case).map(|allocation| allocation.name)
}

fn derive_enum_member_name_allocation(
    value: &Value,
    enum_case: EnumMemberCase,
) -> Result<NameAllocation, NormalizeError> {
    let tokens = match value {
        Value::String(value) => {
            let mut tokens = identifier_tokens(value)?;
            if value.is_empty() {
                tokens.push("Empty".to_owned());
            } else if tokens.is_empty() {
                return Err(NormalizeError::Empty);
            }
            if tokens
                .first()
                .and_then(|token| token.bytes().next())
                .is_some_and(|byte| byte.is_ascii_digit())
            {
                tokens.insert(0, "Value".to_owned());
            }
            tokens
        }
        Value::Number(number) => numeric_name_tokens(number)?,
        Value::Bool(true) => vec!["True".to_owned()],
        Value::Bool(false) => vec!["False".to_owned()],
        Value::Null => vec!["Null".to_owned()],
        Value::Array(_) | Value::Object(_) => return Err(NormalizeError::Empty),
    };
    let case = match enum_case {
        EnumMemberCase::Pascal => TargetCase::Pascal,
        EnumMemberCase::Camel => TargetCase::Camel,
        EnumMemberCase::ScreamingSnake => TargetCase::ScreamingSnake,
        EnumMemberCase::Preserve => TargetCase::Preserve,
    };
    let name = transform_tokens(&tokens, case);
    escape_reserved_word(name)
}

fn numeric_name_tokens(number: &Number) -> Result<Vec<String>, NormalizeError> {
    let value = number
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or(NormalizeError::NumericDomain)?;
    let rendered = render_number(value);
    let mut tokens = vec!["Value".to_owned()];
    let mut chars = rendered.chars().peekable();
    if chars.peek() == Some(&'-') {
        chars.next();
        tokens.push("Negative".to_owned());
    }
    let mut digits = String::new();
    while let Some(character) = chars.next() {
        match character {
            '.' => {
                push_digits(&mut tokens, &mut digits);
                tokens.push("Point".to_owned());
            }
            'e' => {
                push_digits(&mut tokens, &mut digits);
                tokens.push("Exponent".to_owned());
                if chars
                    .next()
                    .expect("rendered exponents include an explicit sign")
                    == '-'
                {
                    tokens.push("Negative".to_owned());
                } else {
                    tokens.push("Positive".to_owned());
                }
            }
            digit => digits.push(digit),
        }
    }
    push_digits(&mut tokens, &mut digits);
    Ok(tokens)
}

fn push_digits(tokens: &mut Vec<String>, digits: &mut String) {
    if !digits.is_empty() {
        tokens.push(std::mem::take(digits));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Decimal {
    negative: bool,
    digits: String,
    exponent: i64,
    negative_zero: bool,
}

impl Decimal {
    fn parse(input: &str) -> Option<Self> {
        let (negative, unsigned) = input
            .strip_prefix('-')
            .map_or((false, input), |unsigned| (true, unsigned));
        let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().ok()?),
            None => (unsigned, 0),
        };
        let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let mut digits = format!("{integer}{fraction}");
        let first_nonzero = digits
            .bytes()
            .position(|digit| digit != b'0')
            .unwrap_or(digits.len());
        digits.drain(..first_nonzero);
        if digits.is_empty() {
            return Some(Self {
                negative: false,
                digits: "0".to_owned(),
                exponent: 0,
                negative_zero: negative,
            });
        }
        let mut adjusted_exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
        while digits.ends_with('0') {
            digits.pop();
            adjusted_exponent = adjusted_exponent.checked_add(1)?;
        }
        Some(Self {
            negative,
            digits,
            exponent: adjusted_exponent,
            negative_zero: false,
        })
    }
}

fn identifier_tokens(input: &str) -> Result<Vec<String>, NormalizeError> {
    let decomposed = input
        .nfkd()
        .filter(|character| get_general_category(*character) != GeneralCategory::NonspacingMark)
        .collect::<String>();
    if let Some(character) = decomposed.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    Ok(decomposed
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
        .map(str::to_owned)
        .collect())
}

fn transform_tokens(tokens: &[String], case: TargetCase) -> String {
    match case {
        TargetCase::Pascal => tokens.iter().map(|token| capitalize_token(token)).collect(),
        TargetCase::Camel => tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                if index == 0 {
                    lowercase_token(token)
                } else {
                    capitalize_token(token)
                }
            })
            .collect(),
        TargetCase::ScreamingSnake => tokens
            .iter()
            .map(|token| token.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join("_"),
        TargetCase::Preserve => tokens.concat(),
    }
}

fn capitalize_token(token: &str) -> String {
    change_first_alphabetic(token, u8::to_ascii_uppercase)
}

fn lowercase_token(token: &str) -> String {
    change_first_alphabetic(token, u8::to_ascii_lowercase)
}

fn change_first_alphabetic(token: &str, transform: fn(&u8) -> u8) -> String {
    let mut bytes = token.as_bytes().to_vec();
    if let Some(character) = bytes.iter_mut().find(|byte| byte.is_ascii_alphabetic()) {
        *character = transform(character);
    }
    String::from_utf8(bytes).expect("ASCII case conversion preserves UTF-8")
}

fn validate_normalized_identifier(identifier: &str) -> Result<(), NormalizeError> {
    if identifier.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if identifier
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return Err(NormalizeError::LeadingDigit);
    }
    if RESERVED_WORDS.contains(&identifier) {
        return Err(NormalizeError::ReservedWord(identifier.to_owned()));
    }
    Ok(())
}

fn validate_final_identifier(identifier: &str) -> Result<(), NormalizeError> {
    validate_final_identifier_characters(identifier)?;
    validate_normalized_identifier(identifier)
}

fn validate_final_identifier_allocation(
    identifier: String,
) -> Result<NameAllocation, NormalizeError> {
    validate_final_identifier_characters(&identifier)?;
    escape_reserved_word(identifier)
}

fn validate_final_identifier_characters(identifier: &str) -> Result<(), NormalizeError> {
    if let Some(character) = identifier.chars().find(|character| !character.is_ascii()) {
        return Err(NormalizeError::NonAscii(character));
    }
    if let Some(character) = identifier
        .chars()
        .find(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '$'))
    {
        return Err(NormalizeError::InvalidIdentifierCharacter(character));
    }
    Ok(())
}

fn enum_error(meta: &SchemaMeta, message: impl Into<String>, sink: &mut DiagnosticSink) {
    sink.push(source_diagnostic(CODE_ENUM_RULE_14, message, &meta.source));
}

fn enum_extension_warning(
    meta: &SchemaMeta,
    message: impl Into<String>,
    sink: &mut DiagnosticSink,
) {
    enum_warning(meta, message, sink);
}

fn enum_warning(meta: &SchemaMeta, message: impl Into<String>, sink: &mut DiagnosticSink) {
    let mut diagnostic = source_diagnostic(CODE_ENUM_RULE_14, message, &meta.source);
    diagnostic.severity = Severity::Warning;
    sink.push(diagnostic);
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

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;

    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{EnumExtensions, EnumRepresentation, NameOverrides};
    use crate::diag::{Category, Severity};
    use crate::ir::{
        CallbackExpression, FiniteConstraint, Link, NamedSchema, Param, ParamLocation,
        PrimitiveType, ResponseEntry, ResponseStatus, SchemaDocs, SchemaRef, Segment,
    };
    use crate::loader::load_graph;
    use crate::parse::parse;

    fn named_schema(name: &str) -> NamedSchema {
        let pointer = format!("/components/schemas/{name}");
        NamedSchema {
            name: name.to_owned(),
            schema: any_schema(&pointer),
            source: source(&pointer),
        }
    }

    /// A schema materialized at an inline pointer — the shape a `$ref` into a media type's
    /// `schema`, a `oneOf` branch, or a `$defs` entry produces. Its name is derived, not declared.
    fn materialized_schema(name: &str, pointer: &str) -> NamedSchema {
        NamedSchema {
            name: name.to_owned(),
            schema: any_schema(pointer),
            source: source(pointer),
        }
    }

    fn schema_overrides(entries: &[(&str, &str)]) -> NamingConfig {
        NamingConfig {
            overrides: NameOverrides {
                schemas: entries
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        }
    }

    fn schema_names(analyzed: &Analyzed) -> Vec<&str> {
        analyzed
            .schema_names
            .iter()
            .map(|allocated| allocated.name.as_str())
            .collect()
    }

    fn source(pointer: &str) -> SourceRef {
        SourceRef::new("openapi.yaml", pointer)
    }

    fn any_schema(pointer: &str) -> SchemaNode {
        SchemaNode::Any {
            meta: SchemaMeta {
                source: source(pointer),
                ..SchemaMeta::default()
            },
        }
    }

    fn diagnostics_for_schema(schema: &str) -> Vec<Diagnostic> {
        let temp = TempDir::new().expect("temp directory");
        let input = temp.path().join("openapi.json");
        let config_path = temp.path().join("oasts.json");
        let schema = serde_json::from_str::<Value>(schema).expect("schema JSON");
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "paths": {},
            "components": { "schemas": { "Value": schema } }
        });
        fs::write(&input, serde_json::to_vec(&document).expect("OpenAPI JSON"))
            .expect("OpenAPI document");
        fs::write(
            &config_path,
            r#"{"schemaVersion":1,"input":{"path":"./openapi.json"},"output":"./generated"}"#,
        )
        .expect("config JSON");
        let config =
            crate::config::load_config(Some(&config_path), temp.path()).expect("valid config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("loaded graph");
        let ir = parse(&graph, &mut sink).expect("supported OpenAPI");
        let _analyzed = analyze(ir, &config, &mut sink);
        sink.into_sorted_vec()
    }

    fn assert_bound_domain_diagnostic(schema: &str, keyword: &str) {
        let diagnostics = diagnostics_for_schema(schema);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_NUMERIC_BOUND_DOMAIN)
            .expect("numeric bound domain diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.message,
            format!("numeric bound {keyword} '1e+999' is outside the binary64 domain")
        );
        assert!(
            diagnostic
                .source_id
                .as_deref()
                .is_some_and(|source| source.ends_with("openapi.json"))
        );
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/schemas/Value")
        );
    }

    #[test]
    fn minimum_outside_binary64_errors() {
        assert_bound_domain_diagnostic(r#"{"type":"number","minimum":1e999}"#, "minimum");
    }

    #[test]
    fn maximum_outside_binary64_errors() {
        assert_bound_domain_diagnostic(r#"{"type":"number","maximum":1e999}"#, "maximum");
    }

    #[test]
    fn exclusive_minimum_number_outside_binary64_errors() {
        assert_bound_domain_diagnostic(
            r#"{"type":"number","exclusiveMinimum":1e999}"#,
            "exclusiveMinimum",
        );
    }

    #[test]
    fn exclusive_maximum_number_outside_binary64_errors() {
        assert_bound_domain_diagnostic(
            r#"{"type":"number","exclusiveMaximum":1e999}"#,
            "exclusiveMaximum",
        );
    }

    #[test]
    fn default_outside_binary64_warns_oasts1216() {
        let diagnostics = diagnostics_for_schema(r#"{"type":"number","default":1e999}"#);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_ANNOTATION_DOMAIN)
            .expect("annotation domain diagnostic");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.message,
            "default or example value '1e+999' is outside the binary64 domain and is shown only as documentation text"
        );
        assert!(
            diagnostic
                .source_id
                .as_deref()
                .is_some_and(|source| source.ends_with("openapi.json"))
        );
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/schemas/Value")
        );

        let control = diagnostics_for_schema(r#"{"type":"number","default":1.5}"#);
        assert!(control.is_empty(), "{control:?}");
    }

    fn operation(path: Vec<Segment>) -> Operation {
        Operation {
            method: "get".to_owned(),
            path_template: path,
            operation_id: None,
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
            source: source("/paths/~1test/get"),
        }
    }

    fn operation_with_response(
        pointer: &str,
        operation_id: Option<&str>,
        response_pointer: &str,
        links: Vec<Link>,
    ) -> Operation {
        let mut operation = operation(Vec::new());
        operation.operation_id = operation_id.map(str::to_owned);
        operation.source = source(pointer);
        operation.responses.push(ResponseEntry {
            status: ResponseStatus::Exact("200".to_owned()),
            description: "ok".to_owned(),
            media_types: Vec::new(),
            headers: Vec::new(),
            links,
            source: source(response_pointer),
        });
        operation
    }

    fn link(name: &str, target: LinkTarget, parameters: &[&str]) -> Link {
        Link {
            name: name.to_owned(),
            target,
            parameters: parameters
                .iter()
                .map(|parameter| ((*parameter).to_owned(), "runtime".to_owned()))
                .collect(),
            description: None,
            source: source(&format!("/paths/~1source/get/responses/200/links/{name}")),
        }
    }

    fn parameter(name: &str, location: ParamLocation) -> Param {
        Param {
            name: name.to_owned(),
            location,
            required: false,
            deprecated: false,
            description: None,
            schema: any_schema(&format!("/paths/~1target/get/parameters/{name}/schema")),
            content_media_type: None,
            style: None,
            explode: None,
            allow_reserved: false,
            source: source(&format!("/paths/~1target/get/parameters/{name}")),
        }
    }

    fn analyze_links(operations: Vec<Operation>) -> (Analyzed, DiagnosticSink) {
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        (analyzed, sink)
    }

    fn assert_link_diagnostic(diagnostic: &Diagnostic, code: &str, pointer: &str, message: &str) {
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(diagnostic.source_id.as_deref(), Some("openapi.yaml"));
        assert_eq!(diagnostic.json_pointer.as_deref(), Some(pointer));
        assert_eq!(diagnostic.message, message);
    }

    #[test]
    fn link_operation_id_resolves() {
        let source_pointer = "/paths/~1source/get/responses/200";
        let (analyzed, sink) = analyze_links(vec![
            operation_with_response(
                "/paths/~1source/get",
                Some("source"),
                source_pointer,
                vec![link(
                    "ById",
                    LinkTarget::OperationId("target".to_owned()),
                    &[],
                )],
            ),
            operation_with_response(
                "/paths/~1target/get",
                Some("target"),
                "/paths/~1target/get/responses/200",
                Vec::new(),
            ),
        ]);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            analyzed.link_targets,
            vec![ResolvedLink {
                response_source: source(source_pointer),
                link_name: "ById".to_owned(),
                target_operation_index: Some(1),
            }]
        );
    }

    #[test]
    fn link_dangling_operation_id_errors() {
        let (analyzed, sink) = analyze_links(vec![operation_with_response(
            "/paths/~1source/get",
            Some("source"),
            "/paths/~1source/get/responses/200",
            vec![link(
                "Missing",
                LinkTarget::OperationId("missing".to_owned()),
                &[],
            )],
        )]);
        let diagnostic = sink.as_slice().first().expect("link diagnostic");

        assert_link_diagnostic(
            diagnostic,
            CODE_LINK_OPERATION_ID,
            "/paths/~1source/get/responses/200/links/Missing",
            "link 'Missing' references unknown operationId 'missing'",
        );
        assert_eq!(analyzed.link_targets[0].target_operation_index, None);
    }

    #[test]
    fn link_operation_ref_resolves_locally() {
        let target_pointer = "/paths/~1pets~1{petId}/get";
        let (analyzed, sink) = analyze_links(vec![
            operation_with_response(
                "/paths/~1source/get",
                Some("source"),
                "/paths/~1source/get/responses/200",
                vec![link(
                    "ByRef",
                    LinkTarget::OperationRef("#/paths/~1pets~1{petId}/get".to_owned()),
                    &[],
                )],
            ),
            operation_with_response(
                target_pointer,
                Some("target"),
                "/paths/~1pets~1{petId}/get/responses/200",
                Vec::new(),
            ),
        ]);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(analyzed.link_targets[0].target_operation_index, Some(1));
    }

    #[test]
    fn link_operation_ref_external_or_unknown_errors() {
        let (analyzed, sink) = analyze_links(vec![operation_with_response(
            "/paths/~1source/get",
            Some("source"),
            "/paths/~1source/get/responses/200",
            vec![
                link(
                    "External",
                    LinkTarget::OperationRef("other.yaml#/paths/~1target/get".to_owned()),
                    &[],
                ),
                link(
                    "UnknownLocal",
                    LinkTarget::OperationRef("#/paths/~1missing/get".to_owned()),
                    &[],
                ),
            ],
        )]);
        let diagnostics = sink.as_slice();

        assert_eq!(diagnostics.len(), 2);
        assert_link_diagnostic(
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.message.contains("External"))
                .expect("external ref diagnostic"),
            CODE_LINK_OPERATION_REF,
            "/paths/~1source/get/responses/200/links/External",
            "link 'External' operationRef 'other.yaml#/paths/~1target/get' does not resolve to an operation in this document",
        );
        assert_link_diagnostic(
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic.message.contains("UnknownLocal"))
                .expect("unknown local ref diagnostic"),
            CODE_LINK_OPERATION_REF,
            "/paths/~1source/get/responses/200/links/UnknownLocal",
            "link 'UnknownLocal' operationRef '#/paths/~1missing/get' does not resolve to an operation in this document",
        );
        assert!(
            analyzed
                .link_targets
                .iter()
                .all(|link| link.target_operation_index.is_none())
        );
    }

    #[test]
    fn link_parameter_undeclared_errors() {
        let mut target = operation_with_response(
            "/paths/~1target/get",
            Some("target"),
            "/paths/~1target/get/responses/200",
            Vec::new(),
        );
        target.parameters = vec![
            parameter("petId", ParamLocation::Path),
            parameter("x", ParamLocation::Query),
            parameter("trace", ParamLocation::Header),
            parameter("session", ParamLocation::Cookie),
        ];
        let (analyzed, sink) = analyze_links(vec![
            operation_with_response(
                "/paths/~1source/get",
                Some("source"),
                "/paths/~1source/get/responses/200",
                vec![link(
                    "Lookup",
                    LinkTarget::OperationId("target".to_owned()),
                    &[
                        "petId",
                        "path.petId",
                        "query.x",
                        "header.trace",
                        "cookie.session",
                        "body.missing",
                    ],
                )],
            ),
            target,
        ]);
        let diagnostics = sink.as_slice();

        assert_eq!(diagnostics.len(), 1);
        assert_link_diagnostic(
            &diagnostics[0],
            CODE_LINK_PARAMETER,
            "/paths/~1source/get/responses/200/links/Lookup",
            "link 'Lookup' parameter 'body.missing' is not declared by the target operation",
        );
        assert_eq!(analyzed.link_targets[0].target_operation_index, Some(1));
    }

    #[test]
    fn link_unresolved_skips_parameter_check() {
        let (analyzed, sink) = analyze_links(vec![operation_with_response(
            "/paths/~1source/get",
            Some("source"),
            "/paths/~1source/get/responses/200",
            vec![link(
                "Missing",
                LinkTarget::OperationId("missing".to_owned()),
                &["body.missing"],
            )],
        )]);
        let diagnostics = sink.as_slice();

        assert_eq!(diagnostics.len(), 1);
        assert_link_diagnostic(
            &diagnostics[0],
            CODE_LINK_OPERATION_ID,
            "/paths/~1source/get/responses/200/links/Missing",
            "link 'Missing' references unknown operationId 'missing'",
        );
        assert_eq!(analyzed.link_targets[0].target_operation_index, None);
    }

    fn segment(parts: Vec<SegmentPart>) -> Segment {
        Segment { parts }
    }

    #[test]
    fn normalizes_identifier_vectors_in_contract_order() {
        assert_eq!(
            normalize_identifier("Café", TargetCase::Pascal),
            Ok("Cafe".to_owned())
        );
        for rejected in ["λ", "漢字", "pet🐶", "petλ", "\u{0301}", "---"] {
            assert!(normalize_identifier(rejected, TargetCase::Pascal).is_err());
        }
        assert_eq!(
            normalize_identifier("2fast", TargetCase::Pascal),
            Err(NormalizeError::LeadingDigit)
        );
        assert_eq!(
            normalize_identifier("class", TargetCase::Camel),
            Ok("class_".to_owned())
        );
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::Pascal),
            Ok("PetStatus".to_owned())
        );
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::Camel),
            Ok("petStatus".to_owned())
        );
        assert_eq!(
            normalize_identifier("pet_status", TargetCase::ScreamingSnake),
            Ok("PET_STATUS".to_owned())
        );
    }

    #[test]
    fn derives_operation_names_from_mixed_path_parts() {
        let cases = [
            (
                vec![
                    segment(vec![SegmentPart::Literal("pets".to_owned())]),
                    segment(vec![SegmentPart::Param("petId".to_owned())]),
                ],
                "getPetsByPetId",
            ),
            (
                vec![
                    segment(vec![SegmentPart::Literal("reports".to_owned())]),
                    segment(vec![
                        SegmentPart::Param("id".to_owned()),
                        SegmentPart::Literal(".json".to_owned()),
                    ]),
                ],
                "getReportsByIdJson",
            ),
            (Vec::new(), "get"),
            (
                vec![
                    segment(vec![SegmentPart::Literal("files".to_owned())]),
                    segment(vec![
                        SegmentPart::Param("name".to_owned()),
                        SegmentPart::Literal(".tar.gz".to_owned()),
                    ]),
                ],
                "getFilesByNameTarGz",
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(
                derive_operation_name(&operation(path), TargetCase::Camel),
                Ok(expected.to_owned())
            );
        }
    }

    #[test]
    fn allocation_reports_both_collision_locations() {
        let mut first = operation(Vec::new());
        first.operation_id = Some("get-pets".to_owned());
        first.source = source("/paths/~1a/get");
        let mut second = operation(Vec::new());
        second.operation_id = Some("get_pets".to_owned());
        second.source = source("/paths/~1b/get");
        let ir = Ir {
            operations: vec![first, second],
            schemas: vec![
                NamedSchema {
                    name: "Pet".to_owned(),
                    schema: any_schema("/components/schemas/Pet"),
                    source: source("/components/schemas/Pet"),
                },
                NamedSchema {
                    name: "pet".to_owned(),
                    schema: any_schema("/components/schemas/pet"),
                    source: source("/components/schemas/pet"),
                },
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        let messages = sink
            .as_slice()
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|message| {
            message.contains("/paths/~1a/get") && message.contains("/paths/~1b/get")
        }));
        assert!(messages.iter().any(|message| {
            message.contains("/components/schemas/Pet")
                && message.contains("/components/schemas/pet")
        }));
    }

    fn callback_leaf_operation(method: &str, pointer: &str) -> Operation {
        let mut leaf = operation(Vec::new());
        leaf.method = method.to_owned();
        leaf.source = source(pointer);
        leaf
    }

    #[test]
    fn webhook_stems_use_operation_id_else_pascal_name() {
        let mut with_id = operation(Vec::new());
        with_id.operation_id = Some("customName".to_owned());
        with_id.source = source("/webhooks/petSubscription/get");
        let mut without_id = operation(Vec::new());
        without_id.method = "post".to_owned();
        without_id.source = source("/webhooks/petSubscription/post");
        let ir = Ir {
            webhooks: vec![Webhook {
                name: "petSubscription".to_owned(),
                operations: vec![with_id, without_id],
                source: source("/webhooks/petSubscription"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let stems = analyzed
            .webhook_names
            .iter()
            .map(|allocated| allocated.stem.as_str())
            .collect::<Vec<_>>();
        assert_eq!(stems, ["CustomName", "PetSubscriptionPost"]);
    }

    #[test]
    fn operation_id_uniqueness_is_global_but_name_scopes_stay_separate() {
        let mut path_operation = operation(Vec::new());
        path_operation.operation_id = Some("PetsGet".to_owned());
        path_operation.source = source("/paths/~1pets/get");
        let mut webhook_operation = operation(Vec::new());
        webhook_operation.operation_id = Some("PetsGet".to_owned());
        webhook_operation.source = source("/webhooks/pets/get");
        let ir = Ir {
            operations: vec![path_operation],
            webhooks: vec![Webhook {
                name: "pets".to_owned(),
                operations: vec![webhook_operation],
                source: source("/webhooks/pets"),
            }],
            ..Ir::default()
        };
        let naming = NamingConfig {
            operation_case: OperationCase::Preserve,
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "{:#?}", sink.as_slice());
        assert!(diagnostics[0].message.contains("duplicate operationId"));
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| diagnostic.code != CODE_WEBHOOK_NAME)
        );
        assert_eq!(
            analyzed
                .operation_names
                .iter()
                .map(|allocated| allocated.name.as_str())
                .collect::<Vec<_>>(),
            ["PetsGet"]
        );
        assert_eq!(
            analyzed
                .webhook_names
                .iter()
                .map(|allocated| allocated.stem.as_str())
                .collect::<Vec<_>>(),
            ["PetsGet"]
        );
    }

    #[test]
    fn operation_id_uniqueness_descends_into_callbacks() {
        let mut path_operation = operation(Vec::new());
        path_operation.operation_id = Some("shared".to_owned());
        path_operation.source = source("/paths/~1a/get");

        let mut callback_operation =
            callback_leaf_operation("post", "/paths/~1subscribe/post/callbacks/delivery/0/post");
        callback_operation.operation_id = Some("shared".to_owned());
        let mut callback_parent = operation(Vec::new());
        callback_parent.operation_id = Some("subscribe".to_owned());
        callback_parent.source = source("/paths/~1subscribe/post");
        callback_parent.callbacks = vec![Callback {
            name: "delivery".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/callbackUrl}".to_owned(),
                operations: vec![callback_operation],
                source: source("/paths/~1subscribe/post/callbacks/delivery/0"),
            }],
            source: source("/paths/~1subscribe/post/callbacks/delivery"),
        }];

        let mut webhook_operation = operation(Vec::new());
        webhook_operation.operation_id = Some("shared".to_owned());
        webhook_operation.source = source("/webhooks/ping/post");
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: vec![path_operation, callback_parent],
                webhooks: vec![Webhook {
                    name: "ping".to_owned(),
                    operations: vec![webhook_operation],
                    source: source("/webhooks/ping"),
                }],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CODE_OPERATION_NAME
                    && diagnostic
                        .message
                        .contains("duplicate operationId 'shared'")
            })
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 2, "{:#?}", sink.as_slice());
        assert_eq!(
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.json_pointer.as_deref())
                .collect::<HashSet<_>>(),
            [
                "/webhooks/ping/post",
                "/paths/~1subscribe/post/callbacks/delivery/0/post",
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn webhook_stem_collision_reports_oasts1321() {
        let mut first = operation(Vec::new());
        first.source = source("/webhooks/petCreated/get");
        let mut second = operation(Vec::new());
        second.source = source("/webhooks/pet-created/get");
        let ir = Ir {
            webhooks: vec![
                Webhook {
                    name: "petCreated".to_owned(),
                    operations: vec![first],
                    source: source("/webhooks/petCreated"),
                },
                Webhook {
                    name: "pet-created".to_owned(),
                    operations: vec![second],
                    source: source("/webhooks/pet-created"),
                },
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_WEBHOOK_NAME)
            .expect("webhook collision diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.message.contains("webhook name collision"));
        assert!(diagnostic.message.contains("'PetCreatedGet'"));
        assert!(diagnostic.message.contains("/webhooks/petCreated/get"));
        assert!(diagnostic.message.contains("/webhooks/pet-created/get"));
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/webhooks/pet-created/get")
        );
    }

    #[test]
    fn webhook_name_without_identifier_chars_reports_oasts1321() {
        let mut invalid = operation(Vec::new());
        invalid.source = source("/webhooks/---/get");
        let ir = Ir {
            webhooks: vec![Webhook {
                name: "---".to_owned(),
                operations: vec![invalid],
                source: source("/webhooks/---"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.webhook_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_WEBHOOK_NAME)
            .expect("webhook normalization diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/webhooks/---/get")
        );
    }

    #[test]
    fn webhook_operation_id_without_identifier_chars_reports_oasts1321() {
        let mut invalid = operation(Vec::new());
        invalid.operation_id = Some("---".to_owned());
        invalid.source = source("/webhooks/petCreated/get");
        let ir = Ir {
            webhooks: vec![Webhook {
                name: "petCreated".to_owned(),
                operations: vec![invalid],
                source: source("/webhooks/petCreated"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.webhook_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_WEBHOOK_NAME)
            .expect("webhook operationId normalization diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.message.contains("'---'"));
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/webhooks/petCreated/get")
        );
    }

    #[test]
    fn callback_stems_compose_with_expression_disambiguator() {
        let mut multi = operation(Vec::new());
        multi.operation_id = Some("subscribe".to_owned());
        multi.source = source("/paths/~1subscribe/post");
        multi.callbacks = vec![Callback {
            name: "delivery.status".to_owned(),
            expressions: vec![
                CallbackExpression {
                    expression: "{$request.body#/callbackUrl}".to_owned(),
                    operations: vec![callback_leaf_operation(
                        "post",
                        "/paths/~1subscribe/post/callbacks/delivery.status/0/post",
                    )],
                    source: source("/paths/~1subscribe/post/callbacks/delivery.status/0"),
                },
                CallbackExpression {
                    expression: "{$request.query.fallback}".to_owned(),
                    operations: vec![callback_leaf_operation(
                        "get",
                        "/paths/~1subscribe/post/callbacks/delivery.status/1/get",
                    )],
                    source: source("/paths/~1subscribe/post/callbacks/delivery.status/1"),
                },
            ],
            source: source("/paths/~1subscribe/post/callbacks/delivery.status"),
        }];

        let mut single = operation(Vec::new());
        single.operation_id = Some("ping".to_owned());
        single.source = source("/paths/~1ping/post");
        single.callbacks = vec![Callback {
            name: "audit".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.header.X-Audit-Url}".to_owned(),
                operations: vec![callback_leaf_operation(
                    "put",
                    "/paths/~1ping/post/callbacks/audit/0/put",
                )],
                source: source("/paths/~1ping/post/callbacks/audit/0"),
            }],
            source: source("/paths/~1ping/post/callbacks/audit"),
        }];

        let ir = Ir {
            operations: vec![multi, single],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let stems = analyzed
            .callback_names
            .iter()
            .map(|allocated| allocated.stem.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            stems,
            [
                "SubscribeDeliveryStatus_1Post",
                "SubscribeDeliveryStatus_2Get",
                "PingAuditPut",
            ]
        );
    }

    #[test]
    fn callback_expression_text_never_in_identifier() {
        let mut parent = operation(Vec::new());
        parent.operation_id = Some("subscribe".to_owned());
        parent.source = source("/paths/~1subscribe/post");
        parent.callbacks = vec![Callback {
            name: "delivery".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/url}".to_owned(),
                operations: vec![callback_leaf_operation(
                    "post",
                    "/paths/~1subscribe/post/callbacks/delivery/0/post",
                )],
                source: source("/paths/~1subscribe/post/callbacks/delivery/0"),
            }],
            source: source("/paths/~1subscribe/post/callbacks/delivery"),
        }];
        let ir = Ir {
            operations: vec![parent],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(analyzed.callback_names.len(), 1);
        let stem = analyzed.callback_names[0].stem.as_str();
        assert!(!stem.contains('{') && !stem.contains('$') && !stem.contains('#'));
        assert_eq!(stem, "SubscribeDeliveryPost");
    }

    #[test]
    fn callback_name_without_identifier_chars_reports_oasts1321() {
        let mut parent = operation(Vec::new());
        parent.operation_id = Some("subscribe".to_owned());
        parent.source = source("/paths/~1subscribe/post");
        parent.callbacks = vec![Callback {
            name: "---".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/url}".to_owned(),
                operations: vec![callback_leaf_operation(
                    "post",
                    "/paths/~1subscribe/post/callbacks/---/0/post",
                )],
                source: source("/paths/~1subscribe/post/callbacks/---/0"),
            }],
            source: source("/paths/~1subscribe/post/callbacks/---"),
        }];
        let ir = Ir {
            operations: vec![parent],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.callback_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_WEBHOOK_NAME)
            .expect("callback normalization diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1subscribe/post/callbacks/---/0/post")
        );
    }

    #[test]
    fn callbacks_allocate_on_webhook_operations() {
        let mut webhook_operation = operation(Vec::new());
        webhook_operation.method = "post".to_owned();
        webhook_operation.source = source("/webhooks/petCreated/post");
        webhook_operation.callbacks = vec![Callback {
            name: "ack".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/ackUrl}".to_owned(),
                operations: vec![callback_leaf_operation(
                    "post",
                    "/webhooks/petCreated/post/callbacks/ack/0/post",
                )],
                source: source("/webhooks/petCreated/post/callbacks/ack/0"),
            }],
            source: source("/webhooks/petCreated/post/callbacks/ack"),
        }];
        let ir = Ir {
            webhooks: vec![Webhook {
                name: "petCreated".to_owned(),
                operations: vec![webhook_operation],
                source: source("/webhooks/petCreated"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(analyzed.callback_names.len(), 1);
        let allocated = &analyzed.callback_names[0];
        // The parent stem is the webhook operation's own stem, not a path-operation stem.
        assert_eq!(allocated.parent_stem, "PetCreatedPost");
        assert_eq!(allocated.stem, "PetCreatedPostAckPost");
        assert_eq!(
            allocated.parent,
            CallbackParent::WebhookOperation {
                webhook_index: 0,
                operation_index: 0,
            }
        );
    }

    #[test]
    fn callbacks_allocate_nested_inside_callback_operations() {
        let mut nested_leaf = callback_leaf_operation(
            "get",
            "/paths/~1subscribe/post/callbacks/delivery/0/post/callbacks/retry/0/get",
        );
        nested_leaf.callbacks = Vec::new();
        let mut outer_leaf =
            callback_leaf_operation("post", "/paths/~1subscribe/post/callbacks/delivery/0/post");
        outer_leaf.callbacks = vec![Callback {
            name: "retry".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/retryUrl}".to_owned(),
                operations: vec![nested_leaf],
                source: source(
                    "/paths/~1subscribe/post/callbacks/delivery/0/post/callbacks/retry/0",
                ),
            }],
            source: source("/paths/~1subscribe/post/callbacks/delivery/0/post/callbacks/retry"),
        }];
        let mut parent = operation(Vec::new());
        parent.operation_id = Some("subscribe".to_owned());
        parent.source = source("/paths/~1subscribe/post");
        parent.callbacks = vec![Callback {
            name: "delivery".to_owned(),
            expressions: vec![CallbackExpression {
                expression: "{$request.body#/url}".to_owned(),
                operations: vec![outer_leaf],
                source: source("/paths/~1subscribe/post/callbacks/delivery/0"),
            }],
            source: source("/paths/~1subscribe/post/callbacks/delivery"),
        }];
        let ir = Ir {
            operations: vec![parent],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // Pre-order: the outer callback operation is allocated before its nested child.
        let stems = analyzed
            .callback_names
            .iter()
            .map(|allocated| allocated.stem.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            stems,
            ["SubscribeDeliveryPost", "SubscribeDeliveryPostRetryGet"]
        );
        // The nested child's parent is the outer callback operation's own allocation, and its
        // parent stem is that operation's stem.
        assert_eq!(
            analyzed.callback_names[1].parent,
            CallbackParent::Callback { index: 0 }
        );
        assert_eq!(
            analyzed.callback_names[1].parent_stem,
            "SubscribeDeliveryPost"
        );
    }

    #[test]
    fn case_fold_only_identifiers_allocate_both_types() {
        // `custom-hostname` -> `CustomHostname` and `customhostname` -> `Customhostname`
        // differ only by the case of one letter, so they are two distinct, legal TypeScript
        // types and both must allocate. Filesystem safety is the path layer's job, not this one.
        let ir = Ir {
            schemas: vec![
                NamedSchema {
                    name: "custom-hostname".to_owned(),
                    schema: any_schema("/components/schemas/custom-hostname"),
                    source: source("/components/schemas/custom-hostname"),
                },
                NamedSchema {
                    name: "customhostname".to_owned(),
                    schema: any_schema("/components/schemas/customhostname"),
                    source: source("/components/schemas/customhostname"),
                },
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let names = analyzed
            .schema_names
            .iter()
            .map(|allocated| allocated.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["CustomHostname", "Customhostname"]);
    }

    #[test]
    fn schema_override_resolves_a_real_collision_into_distinct_names() {
        // `stream_liveInput` and `stream_live_input` both normalize to `StreamLiveInput`; the
        // override on the first disambiguates so both declarations allocate.
        let ir = Ir {
            schemas: vec![
                named_schema("stream_liveInput"),
                named_schema("stream_live_input"),
            ],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("stream_liveInput", "StreamLiveInputId")]);
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            schema_names(&analyzed),
            ["StreamLiveInputId", "StreamLiveInput"]
        );
    }

    #[test]
    fn schema_override_value_is_validated_like_any_generated_name() {
        let ir = Ir {
            schemas: vec![named_schema("widget")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("widget", "2Bad")]);
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(analyzed.schema_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
            .expect("override value rejection");
        assert!(diagnostic.message.contains("2Bad"));
        assert!(diagnostic.message.contains("begins with a digit"));
    }

    #[test]
    fn two_overrides_colliding_with_each_other_still_report_a_collision() {
        let ir = Ir {
            schemas: vec![named_schema("alpha"), named_schema("beta")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("alpha", "Same"), ("beta", "Same")]);
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_TYPE_NAME
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'Same'")
        }));
    }

    #[test]
    fn normalized_schema_names_still_report_an_exact_match_collision() {
        let ir = Ir {
            schemas: vec![named_schema("Foo Bar"), named_schema("FooBar")],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_TYPE_NAME
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'FooBar'")
        }));
    }

    #[test]
    fn schema_collision_suggestions_are_stable_distinct_and_path_safe() {
        let ir = Ir {
            schemas: vec![
                named_schema("Foo Bar"),
                named_schema("FooBar"),
                named_schema("FooBar_1"),
                named_schema("userID"),
                named_schema("userId"),
            ],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
            .expect("schema collision");
        assert_eq!(
            diagnostic.naming_override_suggestions.as_deref(),
            Some(&vec![
                NamingOverrideSuggestion {
                    namespace: NamingOverrideNamespace::Schemas,
                    source_name: "Foo Bar".to_owned(),
                    identifier: "FooBar_2".to_owned(),
                },
                NamingOverrideSuggestion {
                    namespace: NamingOverrideNamespace::Schemas,
                    source_name: "FooBar".to_owned(),
                    identifier: "FooBar_3".to_owned(),
                },
                NamingOverrideSuggestion {
                    namespace: NamingOverrideNamespace::Schemas,
                    source_name: "userID".to_owned(),
                    identifier: "UserID_1".to_owned(),
                },
                NamingOverrideSuggestion {
                    namespace: NamingOverrideNamespace::Schemas,
                    source_name: "userId".to_owned(),
                    identifier: "UserId_2".to_owned(),
                },
            ])
        );
        let rendered = crate::diag::render_to_string(sink.into_sorted_vec());
        assert!(rendered.contains("    schemas:\n"));
        assert!(rendered.contains("      'Foo Bar': 'FooBar_2'\n"));
        assert!(rendered.contains("      'FooBar': 'FooBar_3'\n"));
        assert!(rendered.contains("      'userID': 'UserID_1'\n"));
        assert!(rendered.contains("      'userId': 'UserId_2'\n"));
    }

    #[test]
    fn duplicate_raw_schema_name_has_no_unusable_map_suggestion() {
        let ir = Ir {
            schemas: vec![named_schema("duplicate"), named_schema("duplicate")],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        let collision = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
            .expect("schema collision");
        assert!(collision.naming_override_suggestions.is_none());
    }

    #[test]
    fn a_schema_override_renames_a_declared_component() {
        let ir = Ir {
            schemas: vec![named_schema("widget")],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &schema_overrides(&[("widget", "Gadget")]),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names[0].name, "Gadget");
        assert!(sink.as_slice().is_empty());
    }

    #[test]
    fn a_schema_override_renames_a_materialized_document_root() {
        let ir = Ir {
            schemas: vec![materialized_schema("123", "")],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &schema_overrides(&[("123", "Pet123")]),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names[0].name, "Pet123");
        assert!(sink.as_slice().is_empty());
    }

    #[test]
    fn a_schema_override_keyed_on_a_materialized_name_is_a_config_error() {
        // `Conflict Schema` is derived from the pointer, not written in the document, so the key
        // names no component and must be reported instead of silently renaming the inline schema.
        let ir = Ir {
            schemas: vec![materialized_schema(
                "Conflict Schema",
                "/components/responses/Conflict/content/application~1json/schema",
            )],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &schema_overrides(&[("Conflict Schema", "Renamed")]),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names[0].name, "ConflictSchema");
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_OVERRIDE_UNMATCHED
                && diagnostic.message.contains("'Conflict Schema'")
        }));
    }

    #[test]
    fn an_inline_schema_under_a_declared_component_is_not_overridable() {
        // `/components/schemas/Foo/properties/bar` shares the declared component's prefix but is
        // itself inline, so the trailing-segment test must keep it out of the override namespace.
        let ir = Ir {
            schemas: vec![materialized_schema(
                "Foo bar",
                "/components/schemas/Foo/properties/bar",
            )],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &schema_overrides(&[("Foo bar", "Renamed")]),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names[0].name, "FooBar");
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_OVERRIDE_UNMATCHED)
        );
    }

    #[test]
    fn override_colliding_with_an_untouched_generated_name_still_collides() {
        // `widget` generates `Widget`; the override forces `other` onto the same identifier.
        let ir = Ir {
            schemas: vec![named_schema("widget"), named_schema("other")],
            ..Ir::default()
        };
        let naming = schema_overrides(&[("other", "Widget")]);
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_TYPE_NAME
                && diagnostic.message.contains("collision")
                && diagnostic.message.contains("'Widget'")
        }));
    }

    #[test]
    fn override_suppresses_type_prefix_and_suffix() {
        let ir = Ir {
            schemas: vec![named_schema("widget"), named_schema("gadget")],
            ..Ir::default()
        };
        let naming = NamingConfig {
            type_prefix: "Api".to_owned(),
            type_suffix: "Dto".to_owned(),
            overrides: NameOverrides {
                schemas: BTreeMap::from([("widget".to_owned(), "Widget".to_owned())]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // The override is the complete identifier; the non-overridden schema still gets affixes.
        assert_eq!(schema_names(&analyzed), ["Widget", "ApiGadgetDto"]);
    }

    #[test]
    fn unmatched_override_keys_are_config_errors_naming_the_key() {
        let ir = Ir {
            schemas: vec![named_schema("widget")],
            ..Ir::default()
        };
        let naming = NamingConfig {
            overrides: NameOverrides {
                schemas: BTreeMap::from([("ghost".to_owned(), "Ghost".to_owned())]),
                operations: BTreeMap::from([("phantomOp".to_owned(), "PhantomOp".to_owned())]),
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(ir, &naming, &TypesConfig::default(), &mut sink);

        let schema_diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == CODE_OVERRIDE_UNMATCHED && diagnostic.message.contains("ghost")
            })
            .expect("unmatched schema override");
        assert_eq!(schema_diagnostic.category, Category::Config);
        assert_eq!(schema_diagnostic.category.exit_code(), 2);
        assert!(schema_diagnostic.message.contains("schema"));
        assert_eq!(
            schema_diagnostic.json_pointer.as_deref(),
            Some("/naming/overrides/schemas/ghost")
        );

        let operation_diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| {
                diagnostic.code == CODE_OVERRIDE_UNMATCHED
                    && diagnostic.message.contains("phantomOp")
            })
            .expect("unmatched operation override");
        assert_eq!(operation_diagnostic.category, Category::Config);
        assert!(operation_diagnostic.message.contains("operation"));
        assert_eq!(
            operation_diagnostic.json_pointer.as_deref(),
            Some("/naming/overrides/operations/phantomOp")
        );
    }

    #[test]
    fn operation_override_replaces_the_derived_name_verbatim() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("deleteWebhook".to_owned());
        op.source = source("/paths/~1webhooks/delete");
        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: BTreeMap::from([(
                    "deleteWebhook".to_owned(),
                    "DeleteRealtimeKitWebhook".to_owned(),
                )]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(analyzed.operation_names[0].name, "DeleteRealtimeKitWebhook");
    }

    #[test]
    fn reserved_operation_id_is_escaped_with_a_warning() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("delete".to_owned());
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        assert_eq!(analyzed.operation_names[0].name, "delete_");
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
            .expect("reserved-word warning");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.message,
            "operation identifier 'delete' is a TypeScript reserved word; emitted as 'delete_'"
        );
    }

    #[test]
    fn reserved_operation_escape_participates_in_collision_detection() {
        let mut reserved = operation(Vec::new());
        reserved.operation_id = Some("delete".to_owned());
        reserved.source = source("/paths/~1reserved/delete");
        let mut supplied = operation(Vec::new());
        supplied.operation_id = Some("delete_".to_owned());
        supplied.source = source("/paths/~1supplied/delete");
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![reserved, supplied],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        assert_eq!(
            analyzed
                .operation_names
                .iter()
                .map(|operation| operation.name.as_str())
                .collect::<Vec<_>>(),
            ["delete_", "delete_"]
        );
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error
                && diagnostic.message
                    == "operation name collision: 'delete_' allocated at openapi.yaml#/paths/~1reserved/delete and openapi.yaml#/paths/~1supplied/delete"
        }));
    }

    #[test]
    fn reserved_operation_override_wins_without_escape_or_warning() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("delete".to_owned());
        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: BTreeMap::from([("delete".to_owned(), "remove".to_owned())]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );

        assert_eq!(analyzed.operation_names[0].name, "remove");
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn duplicate_literal_operation_ids_name_the_document_violation() {
        let mut first = operation(Vec::new());
        first.operation_id = Some("update".to_owned());
        first.source = source("/paths/~1first/put");
        let mut second = operation(Vec::new());
        second.operation_id = Some("update".to_owned());
        second.source = source("/paths/~1second/patch");
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: vec![first, second],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error)
            .expect("duplicate operationId error");
        assert_eq!(
            diagnostic.message,
            "duplicate operationId 'update' declared at openapi.yaml#/paths/~1first/put and openapi.yaml#/paths/~1second/patch; OpenAPI requires operationId to be unique among all operations"
        );
        assert!(diagnostic.naming_override_suggestions.is_none());
    }

    /// The suggestion pass only runs once something collides, and it then walks *every* operation
    /// to index the names already in use — including the ones that did not collide and the ones
    /// the user already renamed. This pins that walk.
    #[test]
    fn the_operation_suggestion_pass_indexes_uncollided_and_overridden_names() {
        let mut first = operation(Vec::new());
        first.operation_id = Some("get-pet".to_owned());
        first.source = source("/paths/~1first/get");
        let mut second = operation(Vec::new());
        second.operation_id = Some("get_pet".to_owned());
        second.source = source("/paths/~1second/get");
        let mut untouched = operation(Vec::new());
        untouched.operation_id = Some("listPets".to_owned());
        untouched.source = source("/paths/~1third/get");
        let mut renamed = operation(Vec::new());
        renamed.operation_id = Some("deletePet".to_owned());
        renamed.source = source("/paths/~1fourth/delete");

        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: [("deletePet".to_owned(), "removePet".to_owned())]
                    .into_iter()
                    .collect(),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![first, second, untouched, renamed],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );

        let names = analyzed
            .operation_names
            .iter()
            .map(|allocated| allocated.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"listPets"));
        assert!(names.contains(&"removePet"));
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error)
            .expect("the normalization collision still errors");
        assert!(diagnostic.naming_override_suggestions.is_some());
    }

    #[test]
    fn distinct_operation_ids_that_normalize_together_keep_collision_wording() {
        let mut first = operation(Vec::new());
        first.operation_id = Some("get-pet".to_owned());
        first.source = source("/paths/~1first/get");
        let mut second = operation(Vec::new());
        second.operation_id = Some("get_pet".to_owned());
        second.source = source("/paths/~1second/get");
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: vec![first, second],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );

        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error)
            .expect("normalization collision");
        assert_eq!(
            diagnostic.message,
            "operation name collision: 'getPet' allocated at openapi.yaml#/paths/~1first/get and openapi.yaml#/paths/~1second/get"
        );
        assert_eq!(
            diagnostic
                .naming_override_suggestions
                .as_deref()
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn operation_override_value_is_validated_like_any_generated_name() {
        let mut op = operation(Vec::new());
        op.operation_id = Some("deleteWebhook".to_owned());
        let naming = NamingConfig {
            overrides: NameOverrides {
                operations: BTreeMap::from([("deleteWebhook".to_owned(), "class".to_owned())]),
                ..NameOverrides::default()
            },
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![op],
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.operation_names.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
            .expect("override value rejection");
        assert!(diagnostic.message.contains("class"));
        assert!(diagnostic.message.contains("reserved word"));
    }

    #[test]
    fn reserved_enum_members_are_escaped_and_collide_with_supplied_underscore() {
        let schema = enum_schema(
            vec![json!("delete"), json!("delete_")],
            PrimitiveType::String,
            Some(json!(["delete", "delete_"])),
            "/reserved-enum",
        );
        let naming = NamingConfig {
            enum_member_case: EnumMemberCase::Camel,
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                schemas: vec![schema],
                ..Ir::default()
            },
            &naming,
            &const_types(),
            &mut sink,
        );

        assert_eq!(
            analyzed.enum_members[0]
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["delete_", "delete_"]
        );
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.severity == Severity::Warning
                && diagnostic
                    .message
                    .contains("enum member identifier 'delete'")
        }));
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error
                && diagnostic.message.contains("collide after case folding")
        }));
    }

    fn enum_schema(
        values: Vec<Value>,
        ty: PrimitiveType,
        extension: Option<Value>,
        pointer: &str,
    ) -> NamedSchema {
        NamedSchema {
            name: pointer.trim_start_matches('/').to_owned(),
            schema: SchemaNode::Primitive {
                ty,
                format: None,
                enum_values: Some(values),
                const_value: None,
                meta: SchemaMeta {
                    docs: SchemaDocs::default(),
                    enum_extensions: crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                        enum_varnames: extension,
                        ..crate::ir::EnumExtensionData::default()
                    }),
                    source: source(pointer),
                    ..SchemaMeta::default()
                },
            },
            source: source(pointer),
        }
    }

    fn const_types() -> TypesConfig {
        TypesConfig {
            enum_representation: EnumRepresentation::Const,
            enum_extensions: EnumExtensions::Accept,
            ..TypesConfig::default()
        }
    }

    #[test]
    fn validates_enum_extensions_and_uses_explicit_names_verbatim() {
        let schemas = vec![
            enum_schema(
                vec![json!("a"), json!("b")],
                PrimitiveType::String,
                Some(json!(["OnlyOne"])),
                "/length",
            ),
            enum_schema(
                vec![json!("a")],
                PrimitiveType::String,
                Some(json!(["λ"])),
                "/nonascii",
            ),
            enum_schema(
                vec![json!("available"), json!("sold")],
                PrimitiveType::String,
                Some(json!(["AvailableWire", "SoldWire"])),
                "/valid",
            ),
        ];
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("length 1, expected 2"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("non-ASCII"))
        );
        assert!(analyzed.enum_members.iter().any(|table| {
            table
                .members
                .iter()
                .map(|member| member.name.as_str())
                .eq(["AvailableWire", "SoldWire"])
        }));
    }

    #[test]
    fn enum_description_extensions_accept_documented_map_and_existing_array_forms() {
        let mut mapped = enum_schema(
            vec![json!("ACTIVE"), json!("INACTIVE")],
            PrimitiveType::String,
            None,
            "/mapped",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut mapped.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_descriptions_camel: Some(json!({
                    "INACTIVE": "disabled",
                    "ACTIVE": "enabled",
                    "MISSING": "ignored"
                })),
                ..Default::default()
            });
        }
        let mut array = enum_schema(
            vec![json!("ACTIVE"), json!("INACTIVE")],
            PrimitiveType::String,
            None,
            "/array",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut array.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_descriptions: Some(json!(["enabled", "disabled"])),
                ..Default::default()
            });
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                schemas: vec![mapped, array],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let warning = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.message.contains("key 'MISSING'"))
            .expect("unknown map key warning");
        assert_eq!(warning.severity, Severity::Warning);
        assert!(warning.message.ends_with("the entry is ignored"));
        for table in &analyzed.enum_members {
            assert_eq!(
                table
                    .members
                    .iter()
                    .map(|member| member.description.as_deref())
                    .collect::<Vec<_>>(),
                vec![Some("enabled"), Some("disabled")]
            );
        }
    }

    #[test]
    fn malformed_enum_extensions_warn_and_are_ignored_unless_config_rejects_them() {
        for value in [
            json!("not-an-array-or-map"),
            json!(7),
            json!({ "ACTIVE": 7 }),
        ] {
            let meta = SchemaMeta {
                enum_extensions: crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                    enum_descriptions_camel: Some(value),
                    ..Default::default()
                }),
                source: source("/enum"),
                ..SchemaMeta::default()
            };
            let mut sink = DiagnosticSink::new();
            let validated = validate_enum_extensions(
                Some(&[json!("ACTIVE")]),
                &meta,
                &const_types(),
                &mut sink,
            );
            assert!(validated.descriptions.is_none());
            assert_eq!(sink.as_slice().len(), 1);
            assert_eq!(sink.as_slice()[0].severity, Severity::Warning);
            assert!(sink.as_slice()[0].message.contains("it is ignored"));

            let mut rejected_types = const_types();
            rejected_types.enum_extensions = EnumExtensions::Reject;
            let mut rejected_sink = DiagnosticSink::new();
            let rejected = validate_enum_extensions(
                Some(&[json!("ACTIVE")]),
                &meta,
                &rejected_types,
                &mut rejected_sink,
            );
            assert!(rejected.descriptions.is_none());
            assert_eq!(rejected_sink.as_slice().len(), 1);
            assert_eq!(rejected_sink.as_slice()[0].severity, Severity::Error);
            assert!(
                rejected_sink.as_slice()[0]
                    .message
                    .contains("is rejected by config")
            );
        }
    }

    #[test]
    fn competing_enum_description_spellings_keep_kebab_precedence() {
        let mut schema = enum_schema(
            vec![json!("ACTIVE")],
            PrimitiveType::String,
            None,
            "/competing-descriptions",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut schema.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_descriptions: Some(json!(["kebab"])),
                enum_descriptions_camel: Some(json!({ "ACTIVE": "camel" })),
                ..Default::default()
            });
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                schemas: vec![schema],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| {
                diagnostic.message == "x-enum-descriptions and x-enumDescriptions disagree"
            })
            .expect("competing description diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            analyzed.enum_members[0].members[0].description.as_deref(),
            Some("kebab")
        );
    }

    #[test]
    fn rejects_competing_enum_name_extensions_that_disagree() {
        let mut schema = enum_schema(
            vec![json!("a"), json!("b")],
            PrimitiveType::String,
            Some(json!(["A", "B"])),
            "/competing",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut schema.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["A", "B"])),
                enum_names: Some(json!(["First", "Second"])),
                ..Default::default()
            });
        }
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![schema],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("disagree"))
        );
    }

    #[test]
    fn rejects_numeric_aliases_and_negative_zero() {
        let large = "9007199254740993".parse::<Number>().expect("number");
        let negative_zero = Number::from_f64(-0.0).expect("number");
        let schemas = vec![
            enum_schema(
                vec![Value::Number(large)],
                PrimitiveType::Integer,
                None,
                "/large",
            ),
            enum_schema(
                vec![Value::Number(negative_zero)],
                PrimitiveType::Integer,
                None,
                "/negative-zero",
            ),
        ];
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("does not round-trip"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("-0"))
        );
    }

    #[test]
    fn intersects_enum_const_and_nullable_domains() {
        let mut mismatch = enum_schema(vec![json!("a")], PrimitiveType::String, None, "/mismatch");
        if let SchemaNode::Primitive { const_value, .. } = &mut mismatch.schema {
            *const_value = Some(json!("b"));
        }
        let mut nullable = enum_schema(vec![json!("a")], PrimitiveType::String, None, "/nullable");
        if let SchemaNode::Primitive { meta, .. } = &mut nullable.schema {
            meta.nullable = true;
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![mismatch, nullable],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("empty intersection"))
        );
        let nullable_table = analyzed
            .enum_members
            .iter()
            .find(|table| table.source.json_pointer == "/nullable")
            .expect("nullable enum table");
        assert_eq!(nullable_table.members.len(), 1);
        assert_eq!(nullable_table.members[0].value, json!("a"));
    }

    #[test]
    fn derives_specialized_const_member_names() {
        let cases = [
            (json!(""), PrimitiveType::String, "Empty"),
            (json!("2x"), PrimitiveType::String, "Value2X"),
            (json!(1.5), PrimitiveType::Number, "Value1Point5"),
            (json!(-2), PrimitiveType::Integer, "ValueNegative2"),
            (
                json!(1e21),
                PrimitiveType::Number,
                "Value1ExponentPositive21",
            ),
        ];
        for (index, (value, ty, expected)) in cases.into_iter().enumerate() {
            let schema = enum_schema(vec![value], ty, None, &format!("/case-{index}"));
            let mut sink = DiagnosticSink::new();
            let analyzed = analyze_with_options(
                Ir {
                    operations: Vec::new(),
                    schemas: vec![schema],
                    ..Ir::default()
                },
                &NamingConfig::default(),
                &const_types(),
                &mut sink,
            );
            assert!(!sink.has_errors(), "{:?}", sink.as_slice());
            assert_eq!(analyzed.enum_members[0].members[0].name, expected);
        }
    }

    #[test]
    fn normalization_errors_and_remaining_case_modes_are_explicit() {
        let errors = [
            NormalizeError::NonAscii('λ'),
            NormalizeError::Empty,
            NormalizeError::LeadingDigit,
            NormalizeError::ReservedWord("class".to_owned()),
            NormalizeError::InvalidIdentifierCharacter('-'),
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(
            normalize_identifier("---", TargetCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            normalize_identifier("pet status", TargetCase::Preserve),
            Ok("petstatus".to_owned())
        );
        assert_eq!(
            validate_final_identifier("bad-name"),
            Err(NormalizeError::InvalidIdentifierCharacter('-'))
        );
        assert!(matches!(
            validate_final_identifier("λ"),
            Err(NormalizeError::NonAscii('λ'))
        ));
        assert_eq!(capitalize_token("123"), "123");
    }

    #[test]
    fn allocation_rejects_invalid_operation_and_schema_names() {
        let mut invalid_operation = operation(Vec::new());
        invalid_operation.operation_id = Some("---".to_owned());
        let ir = Ir {
            operations: vec![invalid_operation],
            schemas: vec![NamedSchema {
                name: "---".to_owned(),
                schema: any_schema("/invalid"),
                source: source("/invalid"),
            }],
            ..Ir::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            ir,
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert!(analyzed.operation_names.is_empty());
        assert!(analyzed.schema_names.is_empty());
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_OPERATION_NAME)
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_TYPE_NAME)
        );
    }

    #[test]
    fn preserve_operation_names_and_empty_member_tokens_are_covered() {
        let mut named = operation(Vec::new());
        named.operation_id = Some("Pet_Name".to_owned());
        let naming = NamingConfig {
            operation_case: OperationCase::Preserve,
            ..NamingConfig::default()
        };
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: vec![named],
                schemas: Vec::new(),
                ..Ir::default()
            },
            &naming,
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.operation_names[0].name, "PetName");
        assert_eq!(
            derive_enum_member_name(&json!("---"), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            validate_normalized_identifier(""),
            Err(NormalizeError::Empty)
        );
    }

    #[test]
    fn enum_analysis_walks_every_schema_container() {
        let leaf = any_schema("/leaf");
        let meta = SchemaMeta {
            source: source("/container"),
            ..SchemaMeta::default()
        };
        let schemas = vec![
            SchemaNode::Object {
                properties: Vec::new(),
                additional_properties: AdditionalProperties::Allowed(Some(Box::new(leaf.clone()))),
                dependent_required: Vec::new(),
                finite: None,
                extra_required: Vec::new(),
                meta: meta.clone(),
            },
            SchemaNode::Tuple {
                prefix_items: vec![leaf.clone()],
                rest: TupleRest::Schema(Box::new(leaf.clone())),
                finite: None,
                meta: meta.clone(),
            },
            SchemaNode::AllOf {
                branches: vec![leaf.clone()],
                meta: meta.clone(),
            },
            SchemaNode::AnyOf {
                branches: vec![leaf.clone()],
                discriminator: None,
                meta: meta.clone(),
            },
            SchemaNode::OneOf {
                branches: vec![leaf.clone()],
                discriminator: None,
                meta: meta.clone(),
            },
            SchemaNode::Ref {
                target: SchemaRef {
                    source_id: "openapi.yaml".to_owned(),
                    json_pointer: "/target".to_owned(),
                },
                meta: meta.clone(),
            },
            SchemaNode::Never { meta: meta.clone() },
            SchemaNode::Unknown {
                reason: "test".to_owned(),
                meta,
            },
        ];
        let named = schemas
            .into_iter()
            .enumerate()
            .map(|(index, schema)| NamedSchema {
                name: format!("Schema{index}"),
                schema,
                source: source(&format!("/schema/{index}")),
            })
            .collect();
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: named,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        assert_eq!(analyzed.schema_names.len(), 8);
        assert!(!sink.has_errors());
    }

    #[test]
    fn container_numeric_enum_member_binary64_checked() {
        let outside_binary64 = "1e999"
            .parse::<Number>()
            .expect("arbitrary-precision JSON number");
        let schema = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(None),
            dependent_required: Vec::new(),
            finite: Some(Box::new(FiniteConstraint {
                enum_values: Some(vec![json!({ "value": outside_binary64 })]),
                const_value: None,
            })),
            extra_required: Vec::new(),
            meta: SchemaMeta {
                source: source("/components/schemas/Container"),
                ..SchemaMeta::default()
            },
        };
        let mut sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                schemas: vec![NamedSchema {
                    name: "Container".to_owned(),
                    schema,
                    source: source("/components/schemas/Container"),
                }],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &TypesConfig::default(),
            &mut sink,
        );
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.message.contains("outside the binary64 domain"))
            .expect("binary64 domain diagnostic");
        assert_eq!(diagnostic.code, CODE_ENUM_RULE_14);
        assert_eq!(diagnostic.severity, Severity::Error);
    }

    #[test]
    fn enum_extension_validation_covers_rejection_shapes_and_collisions() {
        let mut meta = SchemaMeta {
            source: source("/enum"),
            ..SchemaMeta::default()
        };
        let set_ext = |meta: &mut SchemaMeta, ext: crate::ir::EnumExtensionData| {
            meta.enum_extensions = crate::ir::box_if_populated(ext);
        };
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["One"])),
                ..Default::default()
            },
        );
        let mut rejected_types = const_types();
        rejected_types.enum_extensions = EnumExtensions::Reject;
        let mut sink = DiagnosticSink::new();
        let rejected =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &rejected_types, &mut sink);
        assert!(rejected.names.is_none());

        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!("not-an-array")),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!([7])),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["Same", "same"])),
                enum_names: Some(json!(["Same", "same"])),
                enum_descriptions: Some(json!(["first", "second"])),
                enum_descriptions_camel: Some(json!(["one", "two"])),
            },
        );
        let validated = validate_enum_extensions(
            Some(&[json!(1), json!(2)]),
            &meta,
            &const_types(),
            &mut sink,
        );
        assert_eq!(validated.names.expect("names").len(), 2);

        set_ext(
            &mut meta,
            crate::ir::EnumExtensionData {
                enum_varnames: Some(json!(["bad-name"])),
                ..Default::default()
            },
        );
        let _invalid =
            validate_enum_extensions(Some(&[json!(1)]), &meta, &const_types(), &mut sink);
        assert!(sink.as_slice().len() >= 6);
    }

    #[test]
    fn finite_value_validation_covers_empty_names_and_descriptions() {
        let mut empty = enum_schema(Vec::new(), PrimitiveType::String, None, "/empty");
        let mut collision = enum_schema(
            vec![json!("a-b"), json!("a_b")],
            PrimitiveType::String,
            None,
            "/collision",
        );
        if let SchemaNode::Primitive { meta, .. } = &mut collision.schema {
            meta.enum_extensions = crate::ir::box_if_populated(crate::ir::EnumExtensionData {
                enum_descriptions: Some(json!(["first", "second"])),
                ..Default::default()
            });
        }
        let mut contradiction = enum_schema(
            vec![json!(1), Value::Null],
            PrimitiveType::String,
            None,
            "/contradiction",
        );
        if let SchemaNode::Primitive { const_value, .. } = &mut contradiction.schema {
            *const_value = Some(json!(1));
        }
        if let SchemaNode::Primitive { const_value, .. } = &mut empty.schema {
            *const_value = Some(json!("only"));
        }
        let mut sink = DiagnosticSink::new();
        let analyzed = analyze_with_options(
            Ir {
                operations: Vec::new(),
                schemas: vec![empty, collision, contradiction],
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut sink,
        );
        assert!(!analyzed.enum_members.is_empty());
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("at least one"))
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("collide"))
        );

        let mut v30_sink = DiagnosticSink::new();
        let _analyzed = analyze_with_options(
            Ir {
                schemas: vec![enum_schema(
                    Vec::new(),
                    PrimitiveType::String,
                    None,
                    "/empty-3.0",
                )],
                version: OasVersion::V3_0,
                ..Ir::default()
            },
            &NamingConfig::default(),
            &const_types(),
            &mut v30_sink,
        );
        let diagnostic = v30_sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.message.contains("at least one"))
            .expect("OpenAPI 3.0 empty enum diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.message.contains("OpenAPI 3.0 (MUST)"));
    }

    #[test]
    fn value_numeric_and_intersection_helpers_cover_boundaries() {
        assert_eq!(finite_intersection(None, None), Some(Vec::new()));
        let one = json!(1);
        let two = json!(2);
        assert_eq!(finite_intersection(None, Some(&one)), Some(vec![&one]));
        assert_eq!(
            finite_intersection(Some(std::slice::from_ref(&one)), None),
            Some(vec![&one])
        );
        assert_eq!(
            finite_intersection(Some(std::slice::from_ref(&one)), Some(&two)),
            None
        );
        assert!(values_equal(&json!(1), &json!(1.0)));
        assert!(!values_equal(&json!(1), &json!(2)));

        let mut sink = DiagnosticSink::new();
        let collision_values = [
            json!(9_007_199_254_740_992_u64),
            json!(9_007_199_254_740_993_u64),
        ];
        validate_numeric_members(
            &collision_values,
            &SchemaMeta {
                source: source("/numbers"),
                ..SchemaMeta::default()
            },
            true,
            &mut sink,
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.message.contains("collide"))
        );

        let outside_binary64 = "1e999"
            .parse::<Number>()
            .expect("arbitrary-precision JSON number");
        let mut domain_sink = DiagnosticSink::new();
        validate_numeric_members(
            &[Value::Number(outside_binary64.clone())],
            &SchemaMeta {
                source: source("/outside-binary64"),
                ..SchemaMeta::default()
            },
            true,
            &mut domain_sink,
        );
        assert!(domain_sink.as_slice().iter().any(|diagnostic| {
            diagnostic.message == "numeric member 1e+999 is outside the binary64 domain"
        }));
        let error = numeric_name_tokens(&outside_binary64).expect_err("outside binary64 domain");
        assert_eq!(error, NormalizeError::NumericDomain);
        assert_eq!(
            error.to_string(),
            "numeric value is outside the binary64 domain"
        );
    }

    #[test]
    fn member_name_decimal_and_source_helpers_cover_edge_cases() {
        for (value, expected) in [
            (json!(true), "True"),
            (json!(false), "False"),
            (Value::Null, "Null"),
        ] {
            assert_eq!(
                derive_enum_member_name(&value, EnumMemberCase::Pascal),
                Ok(expected.to_owned())
            );
        }
        assert_eq!(
            derive_enum_member_name(&json!([]), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert_eq!(
            derive_enum_member_name(&json!({}), EnumMemberCase::Pascal),
            Err(NormalizeError::Empty)
        );
        assert!(derive_enum_member_name(&json!("λ"), EnumMemberCase::Pascal).is_err());
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::Camel),
            Ok("twoWords".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::ScreamingSnake),
            Ok("TWO_WORDS".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!("two words"), EnumMemberCase::Preserve),
            Ok("twowords".to_owned())
        );
        assert_eq!(
            derive_enum_member_name(&json!(1e-7), EnumMemberCase::Pascal),
            Ok("Value1ExponentNegative7".to_owned())
        );

        assert_eq!(Decimal::parse("bad"), None);
        assert_eq!(Decimal::parse("1eBAD"), None);
        assert_eq!(Decimal::parse("1200").expect("decimal").exponent, 2);
        assert!(Decimal::parse("-0").expect("negative zero").negative_zero);

        let located = SourceRef {
            source_id: "openapi.yaml".to_owned(),
            json_pointer: "/value".to_owned(),
            line: Some(3),
            col: Some(5),
        };
        let diagnostic = source_diagnostic("TEST", "message", &located);
        assert_eq!((diagnostic.line, diagnostic.col), (Some(3), Some(5)));
    }
}
