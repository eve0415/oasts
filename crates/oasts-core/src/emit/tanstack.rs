//! TanStack Query descriptor artifact.
//!
//! Descriptors compose into whatever adapter the application already uses, so this emitter imports
//! the generated client's `orThrow` surface, the types artifact, and its own local runtime — and
//! **no TanStack package**. Nothing generated here has a peer dependency, which is why there is no
//! version range for a gate to keep honest.
//!
//! Like the msw emitter, this one must not call [`EmissionModel::reserve_names`]: the types and
//! client artifacts have already been emitted by the time it runs, so renaming a component here
//! would leave the artifacts naming the same schema differently. Identifier clashes go through the
//! same file-local import aliasing the client uses.

use std::collections::{BTreeMap, BTreeSet};

use super::client::{ResponseBody, request_transform_binding, response_body_side};
use super::import_extension;
use super::model::{EmissionModel, Registrar};
use super::paths::{TRANSFORM_SUBDIR, relative_import};
use super::runtime_assets::rewrite_relative_ts_imports;
use super::{
    Emission, GeneratedFile, merge_emission, render_literal_key, render_property_key,
    render_ts_string, source_diagnostic, uppercase_first, warning_diagnostic,
    write_source_metadata,
};
use crate::client_model::{BodyPlan, ClientModel, DecoderClass, OperationPlan, PayloadDisposition};
use crate::ir::{Operation, ParamLocation, Segment, SegmentPart, SourceRef};
use crate::semantic::{TargetCase, normalize_identifier, normalize_interior_identifier};

/// A read operation carries no payload on at least one success branch, so it emits no query
/// descriptor: a query function may not resolve `undefined`.
const CODE_INELIGIBLE_QUERY: &str = "OASTS6301";

/// Names the emitted modules import unconditionally: `ParamValue` in `keys.ts`, the rest in every
/// operation module. A key binding taking one of these would shadow the import, so they seed the
/// set the flat binding names are allocated against.
const MODULE_IMPORTS: &[&str] = &[
    "ApiError",
    "KeyValue",
    "ParamValue",
    "Transport",
    "withInput",
    "withRequestSignal",
];

/// The composed key object `keys.ts` exports beside the flat bindings.
const COMPOSED_KEYS_EXPORT: &str = "keys";

/// The member the composed key object gives a node's own key. A path segment deriving this member
/// would emit a duplicate object key, so it seeds every parent's member allocation.
const COMPOSED_SELF_MEMBER: &str = "all";

const TANSTACK_RUNTIME_TS: &str = include_str!("../../runtime/tanstack-runtime.ts");

/// Two path nodes normalize to the same key-factory name.
pub(crate) const CODE_SEGMENT_COLLISION: &str = "OASTS6302";

/// A `naming.overrides.pathSegments` entry matched no path segment in the document.
pub(crate) const CODE_UNMATCHED_SEGMENT_OVERRIDE: &str = "OASTS6303";

/// A name the key factory derived was already taken, so it was emitted with a numeric suffix.
///
/// Every name this reports is one the compiler composed — a flat binding, a member of the composed
/// object, a key function's argument — never one the document declares, which is why it yields
/// rather than refusing. It is a warning for the same reason OASTS4104 is: nothing about the
/// author's intent is ambiguous, but a derived name that moved is invisible at the call site unless
/// something says so.
pub(crate) const CODE_RENAMED_KEY_NAME: &str = "OASTS6304";

/// What one URL path segment contributes to a query key.
///
/// The three cases are exactly the three the key contract distinguishes, and they are distinguished
/// so that a literal segment and a parameter whose value happens to be that same text can never
/// produce the same key at any prefix depth.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SegmentKind {
    /// Every run is literal. Contributes the joined text as a bare string.
    Literal(String),
    /// One whole template expression. Contributes a single-key object, never the bare value.
    Param(String),
    /// Ordered literal runs and template expressions. Contributes a nested array of its runs, so
    /// `/reports/{id}.json` and `/reports/{id}.xml` stay distinct at every prefix depth.
    Mixed(Vec<SegmentPart>),
}

impl SegmentKind {
    /// Classifies one path segment. The IR carries no separator parts, so an empty one is a
    /// trailing slash: it contributes nothing nameable and therefore no key element.
    fn classify(segment: &Segment) -> Option<Self> {
        let runs = segment.parts.clone();
        if runs.is_empty() {
            return None;
        }
        let parameters = runs
            .iter()
            .filter(|part| matches!(part, SegmentPart::Param(_)))
            .count();
        if parameters == 0 {
            let mut text = String::new();
            for run in &runs {
                if let SegmentPart::Literal(literal) = run {
                    text.push_str(literal);
                }
            }
            return Some(Self::Literal(text));
        }
        if let [SegmentPart::Param(name)] = runs.as_slice() {
            return Some(Self::Param(name.clone()));
        }
        Some(Self::Mixed(runs))
    }

    /// The segment as it appears in the path template — the key a `pathSegments` override uses.
    fn raw_text(&self) -> String {
        match self {
            Self::Literal(text) => text.clone(),
            Self::Param(name) => format!("{{{name}}}"),
            Self::Mixed(runs) => {
                let mut text = String::new();
                for run in runs {
                    match run {
                        SegmentPart::Literal(literal) => text.push_str(literal),
                        SegmentPart::Param(name) => {
                            text.push('{');
                            text.push_str(name);
                            text.push('}');
                        }
                    }
                }
                text
            }
        }
    }

    /// Whether a binding for a node ending in this segment takes the `All` suffix.
    ///
    /// A purely literal segment names a collection, so its own key is the prefix every key beneath
    /// it extends — `All` says so. A segment carrying a parameter already reads as an entity
    /// (`byPetId`), and suffixing it would say the opposite of what it means.
    fn takes_all_suffix(&self) -> bool {
        matches!(self, Self::Literal(_))
    }

    /// The parameters this segment introduces, each allocated to the identifier the generated key
    /// function takes it as. Fallible independently of the member name: an override can replace a
    /// segment whose own text is unnameable, but a parameter still has to become an identifier
    /// because the function takes it positionally.
    fn parameter_bindings(&self) -> Result<Vec<KeyParameter>, String> {
        match self {
            Self::Literal(_) => Ok(Vec::new()),
            Self::Param(name) => Ok(vec![KeyParameter::allocate(name)?]),
            Self::Mixed(runs) => runs
                .iter()
                .filter_map(|run| match run {
                    SegmentPart::Param(name) => Some(KeyParameter::allocate(name)),
                    SegmentPart::Literal(_) => None,
                })
                .collect(),
        }
    }

    /// The member name this segment contributes, before any override is applied.
    ///
    /// A parameter's member is spelled from the identifier [`KeyParameter::allocate`] derives
    /// rather than from the wire name again, so the two agree on how the name is normalized. They
    /// are still separate allocations and can end up spelled differently: `/tenants/{user_id}/
    /// sites/{userId}` gives the second segment the member `byUserId` while its argument, which
    /// competes with the first segment's, becomes `userId2`.
    fn derived_member(&self) -> Result<String, String> {
        match self {
            Self::Literal(text) => normalize_interior_identifier(text, TargetCase::Camel)
                .map_err(|error| format!("path segment '{text}' is not a usable name: {error}")),
            Self::Param(name) => Ok(format!(
                "by{}",
                uppercase_first(&KeyParameter::allocate(name)?.identifier)
            )),
            Self::Mixed(runs) => {
                // The runs are joined with a separator the identifier tokenizer splits on, then
                // normalized once. Normalizing each run on its own would reject a segment whose
                // literal run is punctuation-only — `{owner}-{repo}` has a run of exactly `-`,
                // which is a legal path template and carries no name of its own.
                let joined = runs
                    .iter()
                    .map(|run| match run {
                        SegmentPart::Literal(literal) => literal.as_str(),
                        SegmentPart::Param(name) => name.as_str(),
                    })
                    .collect::<Vec<_>>()
                    .join("-");
                let pascal = normalize_interior_identifier(&joined, TargetCase::Pascal).map_err(
                    |error| {
                        format!(
                            "path segment '{}' is not a usable name: {error}",
                            self.raw_text()
                        )
                    },
                )?;
                Ok(format!("by{pascal}"))
            }
        }
    }
}

/// One path parameter as a key factory sees it: the wire name it keys under, and the identifier
/// the generated function takes it as.
#[derive(Clone, Debug)]
pub(crate) struct KeyParameter {
    wire: String,
    identifier: String,
}

impl KeyParameter {
    fn allocate(name: &str) -> Result<Self, String> {
        let identifier = normalize_identifier(name, TargetCase::Camel)
            .map_err(|error| format!("path parameter '{name}' is not a usable name: {error}"))?;
        Ok(Self {
            wire: name.to_owned(),
            identifier,
        })
    }
}

/// One node in the tree of URL path prefixes the document declares.
///
/// Every node gets a binding, including nodes no operation terminates at: an invalidation list for
/// `DELETE /pets/{petId}/toys/{toyId}` needs the key for `/pets/{petId}/toys` whether or not that
/// path is itself declared.
#[derive(Debug)]
struct PathNode {
    /// The root's segment is the empty literal: it contributes the namespace element rather than a
    /// path segment, and like any literal it takes the `All` suffix. Making it a real value rather
    /// than `None` keeps every child's kind non-optional, which is what they always are.
    kind: SegmentKind,
    /// Ordered by raw segment text, so emission order is a property of the document rather than of
    /// the order operations happened to be visited in.
    children: BTreeMap<String, PathNode>,
    source: SourceRef,
}

impl PathNode {
    fn root(source: SourceRef) -> Self {
        Self {
            kind: SegmentKind::Literal(String::new()),
            children: BTreeMap::new(),
            source,
        }
    }
}

/// The resolved facts about one path node, in the order the flat bindings are emitted.
#[derive(Clone, Debug)]
pub(crate) struct KeyBinding {
    /// The flat exported binding name, e.g. `apiPetsByPetIdToysAll`.
    pub(crate) name: String,
    /// The member names from the root's child down to this node.
    members: Vec<String>,
    /// Every path parameter in scope at this node, in template order: the binding's parameters.
    parameters: Vec<KeyParameter>,
    /// Whether this node names a collection rather than an entity — the same fact that decides the
    /// `All` suffix. Recorded here so an invalidation list reads it off the binding instead of
    /// re-classifying the path's last segment, which a trailing slash would answer wrongly.
    collection: bool,
    /// The key elements this node contributes, root's namespace element first.
    elements: Vec<KeyElement>,
    source: SourceRef,
}

impl KeyBinding {
    /// Whether the binding is a function rather than a constant.
    pub(crate) fn is_function(&self) -> bool {
        !self.parameters.is_empty()
    }
}

/// One element of an emitted query key.
#[derive(Clone, Debug)]
enum KeyElement {
    /// A literal string element: the namespace root, or a literal path segment.
    Literal(String),
    /// A single-key object holding one path parameter's wire value.
    Param(KeyParameter),
    /// A nested array of a mixed segment's ordered runs.
    Mixed(Vec<KeyElement>),
}

/// Every path node's binding, keyed by the joined raw segment texts that address it.
pub(crate) struct KeyFactory {
    /// Ordered by node address, so both `keys.ts` and every operation module see one order.
    pub(crate) bindings: BTreeMap<Vec<String>, KeyBinding>,
    root: PathNode,
}

/// Builds the key factory for a document, reporting every naming collision it finds.
pub(crate) fn build_key_factory(
    model: &EmissionModel<'_>,
    registrar: &mut Registrar<'_>,
) -> KeyFactory {
    let namespace = model.config.namespace.clone();
    let overrides = model.config.naming.overrides.path_segments.clone();
    let fallback_source = model
        .analyzed
        .ir
        .operations
        .first()
        .map(|operation| operation.source.clone())
        .or_else(|| {
            model
                .analyzed
                .ir
                .schemas
                .first()
                .map(|schema| schema.source.clone())
        })
        .unwrap_or_default();

    // Two declared paths that reduce to the same key address would give two distinct endpoints one
    // cache entry, so fetching either would serve the other's data. `/pets` and `/pets/` are the
    // case that reaches this: they are distinct OpenAPI paths and the client builds distinct URLs
    // for them, but a segment carrying only the separator contributes nothing nameable to a key.
    let mut addresses: BTreeMap<Vec<String>, String> = BTreeMap::new();
    let mut root = PathNode::root(fallback_source.clone());
    for operation in &model.analyzed.ir.operations {
        let template = path_template_text(&operation.path_template);
        match addresses.entry(address_of(&operation.path_template)) {
            std::collections::btree_map::Entry::Occupied(existing) => {
                if *existing.get() != template {
                    registrar.sink.push(source_diagnostic(
                        CODE_SEGMENT_COLLISION,
                        format!(
                            "paths '{}' and '{template}' produce the same query key, so their operations would share one cache entry",
                            existing.get()
                        ),
                        &operation.source,
                    ));
                    continue;
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(template);
            }
        }
        let mut cursor = &mut root;
        for kind in operation
            .path_template
            .iter()
            .filter_map(SegmentKind::classify)
        {
            cursor = cursor
                .children
                .entry(kind.raw_text())
                .or_insert_with(|| PathNode {
                    kind,
                    children: BTreeMap::new(),
                    source: operation.source.clone(),
                });
        }
    }

    let mut matched_overrides = Vec::new();
    let mut planned = Vec::new();
    collect_bindings(
        &root,
        &namespace,
        &overrides,
        &mut matched_overrides,
        &BindingWalk {
            address: &[],
            members: &[],
            parameters: &[],
            elements: &[KeyElement::Literal(namespace.clone())],
            configured: None,
        },
        &mut planned,
        registrar,
    );
    let bindings = allocate_flat_names(&planned, reserved_binding_names(model), registrar);

    for key in overrides.keys() {
        if !matched_overrides.contains(key) {
            registrar.sink.push(warning_diagnostic(
                CODE_UNMATCHED_SEGMENT_OVERRIDE,
                format!(
                    "naming.overrides.pathSegments key '{key}' matched no path segment in this document"
                ),
                &fallback_source,
            ));
        }
    }

    KeyFactory { bindings, root }
}

/// The accumulators one recursive step of the walk carries down: where the node sits, what it is
/// named, what parameters are in scope, what key elements precede it, and whether the segment that
/// named it was named by configuration rather than derived.
struct BindingWalk<'walk> {
    address: &'walk [String],
    members: &'walk [String],
    parameters: &'walk [KeyParameter],
    elements: &'walk [KeyElement],
    configured: Option<&'walk str>,
}

/// The lowest free name in `taken`: `base`, then `base2`, `base3`, and so on, the same allocation
/// [`EmissionModel::reserve_names`] performs for a component name a terminal emitter's own
/// identifier has taken. The chosen name is inserted, so a caller allocating in a loop threads one
/// set through every candidate.
fn allocate_unique(base: &str, taken: &mut BTreeSet<String>) -> String {
    let mut candidate = base.to_owned();
    let mut suffix = 2_u32;
    while !taken.insert(candidate.clone()) {
        candidate = format!("{base}{suffix}");
        suffix += 1;
    }
    candidate
}

/// Every identifier `keys.ts` and the operation modules bind themselves, so a flat binding name is
/// allocated around them rather than shadowing one.
///
/// The operation half is derived from every allocated operation name, including operations that end
/// up with no descriptor: reserving a superset costs nothing but a name nobody wanted, while
/// reserving a subset would let a binding shadow an import in the one module that names it.
fn reserved_binding_names(model: &EmissionModel<'_>) -> BTreeSet<String> {
    let mut reserved: BTreeSet<String> = MODULE_IMPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .chain([COMPOSED_KEYS_EXPORT.to_owned()])
        .collect();
    for allocated in &model.analyzed.operation_names {
        let name = &allocated.name;
        let stem = uppercase_first(name);
        reserved.extend([
            format!("{name}OrThrow"),
            format!("{name}Query"),
            format!("{name}Mutation"),
            format!("{name}MutationAffects"),
            format!("encode{stem}Input"),
            format!("{stem}CallArgs"),
            format!("{stem}Input"),
            format!("{stem}Result"),
            format!("{stem}QueryKey"),
            format!("{stem}QueryData"),
            format!("{stem}QueryError"),
            format!("{stem}MutationKey"),
            format!("{stem}MutationData"),
            format!("{stem}MutationError"),
        ]);
    }
    reserved
}

/// One path node after the walk has named it, before flat binding names are allocated.
///
/// Allocation is deferred because a name a `pathSegments` entry chose must never move, and whether
/// it would move depends on nodes the walk reaches later — a node's own flat name is composed from
/// every member above it, so it cannot be known before its ancestors are named. Collecting the
/// whole walk first is what lets the configured nodes claim their names before any derived one
/// allocates.
struct PlannedNode {
    address: Vec<String>,
    /// The flat name composed from the namespace and this node's members.
    base: String,
    /// The `pathSegments` key that named this node's own member, when one did.
    configured: Option<String>,
    collection: bool,
    members: Vec<String>,
    parameters: Vec<KeyParameter>,
    elements: Vec<KeyElement>,
    source: SourceRef,
}

/// Who already holds a flat name a later node wanted.
enum NameHolder {
    /// An identifier `keys.ts` declares or every operation module imports, whatever the document
    /// says. Nothing about it is negotiable, so a name that lands on one always yields.
    Artifact,
    /// Another path node, with where the document declares it — what a reader needs to see to know
    /// which of the two paths kept the bare name.
    Node {
        address: Vec<String>,
        source: SourceRef,
    },
}

/// The `pathSegments` entry that resolves a collision between two path nodes: the first segment
/// where the two addresses actually diverge, not the colliding node's own.
///
/// For `/foo-bar/{id}` against `/foo_bar/{id}` the colliding node is `{id}`, but `{id}` is the same
/// text in both — naming it would rename both and resolve nothing. The divergence is one level up,
/// and that is the entry the reader has to write. Two addresses where one is a prefix of the other
/// never diverge, and then there is no entry to suggest.
fn divergence_remedy(address: &[String], other: &[String]) -> String {
    match address
        .iter()
        .zip(other.iter())
        .find(|(current, held)| current != held)
    {
        Some((raw, _)) => format!(
            " — pin it with `naming.overrides.pathSegments: {{ \"{raw}\": \"<distinctName>\" }}`"
        ),
        None => String::new(),
    }
}

/// Allocates one flat binding name per planned node, configured nodes first.
///
/// A name a `pathSegments` entry produced is claimed before any derived name is allocated, so it is
/// never the one that moves: `naming.overrides` is the remedy every collision diagnostic points at,
/// and a remedy that can itself be renamed pins nothing. When such a name cannot be honored at all
/// the run refuses and names the entry, rather than quietly emitting something else.
///
/// Both passes read `planned` in walk order — pre-order over path nodes, siblings by raw segment
/// text — so which derived competitor keeps the bare name is a property of the document rather than
/// of the order operations were visited in.
fn allocate_flat_names(
    planned: &[PlannedNode],
    reserved: BTreeSet<String>,
    registrar: &mut Registrar<'_>,
) -> BTreeMap<Vec<String>, KeyBinding> {
    let mut holders: BTreeMap<String, NameHolder> = reserved
        .into_iter()
        .map(|name| (name, NameHolder::Artifact))
        .collect();
    let mut bindings = BTreeMap::new();
    let mut claimed: BTreeMap<String, (&PlannedNode, &String)> = BTreeMap::new();

    for (node, key) in planned
        .iter()
        .filter_map(|node| node.configured.as_ref().map(|key| (node, key)))
    {
        if holders.contains_key(&node.base) {
            registrar.sink.push(source_diagnostic(
                CODE_SEGMENT_COLLISION,
                format!(
                    "naming.overrides.pathSegments key '{key}' names path '/{}' '{}', which the generated modules already bind — choose another name",
                    node.address.join("/"),
                    node.base,
                ),
                &node.source,
            ));
            continue;
        }
        if let Some((other, other_key)) = claimed.get(&node.base) {
            // One entry reaching both branches is not two names fighting: `pathSegments` is keyed
            // by raw segment text globally, so a single `x` entry renames every `x` in the document
            // and cannot separate two of them. Telling the reader to rename one of the two would be
            // an instruction nothing can carry out — the segment that can separate the paths is the
            // one above, where their addresses diverge.
            let message = if other_key == &key {
                format!(
                    "naming.overrides.pathSegments key '{key}' names the segment in both '/{}' and '/{}', and both compose the binding '{}' — one entry renames every segment with that text, so the two paths have to be told apart above it{}",
                    other.address.join("/"),
                    node.address.join("/"),
                    node.base,
                    divergence_remedy(&node.address, &other.address),
                )
            } else {
                format!(
                    "naming.overrides.pathSegments keys '{other_key}' and '{key}' both bind '{}', for paths '/{}' and '/{}' — one of them has to name something else",
                    node.base,
                    other.address.join("/"),
                    node.address.join("/"),
                )
            };
            registrar.sink.push(source_diagnostic(
                CODE_SEGMENT_COLLISION,
                message,
                &node.source,
            ));
            continue;
        }
        claimed.insert(node.base.clone(), (node, key));
        bindings.insert(node.address.clone(), node.binding(node.base.clone()));
    }

    for (name, (node, _)) in claimed {
        holders.insert(
            name,
            NameHolder::Node {
                address: node.address.clone(),
                source: node.source.clone(),
            },
        );
    }

    for node in planned.iter().filter(|node| node.configured.is_none()) {
        let mut candidate = node.base.clone();
        let mut suffix = 2_u32;
        while holders.contains_key(&candidate) {
            candidate = format!("{}{suffix}", node.base);
            suffix += 1;
        }
        if candidate != node.base {
            let message = match holders.get(&node.base) {
                Some(NameHolder::Node {
                    address: held,
                    source,
                }) => format!(
                    "key binding '{}' for path '/{}' is already bound by path '/{}' (declared at {}); emitting it as '{candidate}'{}",
                    node.base,
                    node.address.join("/"),
                    held.join("/"),
                    source.display(),
                    divergence_remedy(&node.address, held),
                ),
                Some(NameHolder::Artifact) | None => format!(
                    "key binding '{}' for path '/{}' is an identifier the generated modules already bind; emitting it as '{candidate}' — pin it with `naming.overrides.pathSegments`",
                    node.base,
                    node.address.join("/"),
                ),
            };
            registrar.sink.push(warning_diagnostic(
                CODE_RENAMED_KEY_NAME,
                message,
                &node.source,
            ));
        }
        holders.insert(
            candidate.clone(),
            NameHolder::Node {
                address: node.address.clone(),
                source: node.source.clone(),
            },
        );
        bindings.insert(node.address.clone(), node.binding(candidate));
    }

    bindings
}

impl PlannedNode {
    fn binding(&self, name: String) -> KeyBinding {
        KeyBinding {
            name,
            collection: self.collection,
            members: self.members.clone(),
            parameters: self.parameters.clone(),
            elements: self.elements.clone(),
            source: self.source.clone(),
        }
    }
}

/// One child of a path node, after the walk has decided what member names it.
struct ResolvedChild<'tree> {
    raw: &'tree String,
    node: &'tree PathNode,
    member: String,
    /// Whether `member` came from a `pathSegments` entry rather than from the segment text.
    configured: bool,
    parameters: Vec<KeyParameter>,
}

fn collect_bindings(
    node: &PathNode,
    namespace: &str,
    overrides: &BTreeMap<String, String>,
    matched_overrides: &mut Vec<String>,
    walk: &BindingWalk<'_>,
    planned: &mut Vec<PlannedNode>,
    registrar: &mut Registrar<'_>,
) {
    let BindingWalk {
        address,
        members,
        parameters,
        elements,
        configured,
    } = *walk;
    let takes_all = node.kind.takes_all_suffix();
    let mut base = namespace.to_owned();
    for member in members {
        base.push_str(&uppercase_first(member));
    }
    if takes_all {
        base.push_str("All");
    }
    planned.push(PlannedNode {
        address: address.to_vec(),
        base,
        configured: configured.map(str::to_owned),
        collection: takes_all,
        members: members.to_vec(),
        parameters: parameters.to_vec(),
        elements: elements.to_vec(),
        source: node.source.clone(),
    });

    let mut resolved = Vec::new();
    for (raw, child) in &node.children {
        let kind = &child.kind;
        // The override is consulted before derivation, not after: a segment whose text cannot
        // become an identifier is exactly the case the override exists for, so deriving first and
        // bailing on failure would make the entry the diagnostic names dead on arrival.
        let override_member = overrides.get(raw).inspect(|_| {
            if !matched_overrides.contains(raw) {
                matched_overrides.push(raw.clone());
            }
        });
        let naming = kind.parameter_bindings().and_then(|parameters| {
            let member = match override_member {
                Some(member) => member.clone(),
                None => kind.derived_member()?,
            };
            Ok((member, parameters))
        });
        match naming {
            Ok((member, parameters)) => resolved.push(ResolvedChild {
                raw,
                node: child,
                member,
                configured: override_member.is_some(),
                parameters,
            }),
            Err(message) => registrar.sink.push(source_diagnostic(
                CODE_SEGMENT_COLLISION,
                format!(
                    "{message} — name it with `naming.overrides.pathSegments: {{ \"{raw}\": \"<name>\" }}`"
                ),
                &child.source,
            )),
        }
    }

    // A configured member claims its name before `all` and before any derived sibling, and is
    // refused rather than renamed when it cannot have it — the same order the flat names follow,
    // and for the same reason.
    let mut taken_members: BTreeSet<String> = BTreeSet::new();
    let mut configured_members: BTreeMap<String, &String> = BTreeMap::new();
    let mut refused: BTreeSet<&String> = BTreeSet::new();
    for child in resolved.iter().filter(|child| child.configured) {
        let raw = child.raw;
        if child.member == COMPOSED_SELF_MEMBER {
            registrar.sink.push(source_diagnostic(
                CODE_SEGMENT_COLLISION,
                format!(
                    "naming.overrides.pathSegments key '{raw}' names the member '{COMPOSED_SELF_MEMBER}', which every node of the composed key object already gives its own key — choose another name"
                ),
                &child.node.source,
            ));
            refused.insert(raw);
            continue;
        }
        if let Some(other) = configured_members.get(&child.member) {
            registrar.sink.push(source_diagnostic(
                CODE_SEGMENT_COLLISION,
                format!(
                    "naming.overrides.pathSegments keys '{other}' and '{raw}' both bind the member '{}' under the same parent — one of them has to name something else",
                    child.member
                ),
                &child.node.source,
            ));
            refused.insert(raw);
            continue;
        }
        configured_members.insert(child.member.clone(), raw);
        taken_members.insert(child.member.clone());
    }
    // Reserved after the configured members and before the derived ones: a segment deriving `all`
    // is allocated around it instead of emitting a duplicate object key — TS1117, or silently the
    // wrong key if it compiled.
    taken_members.insert(COMPOSED_SELF_MEMBER.to_owned());
    for child in resolved.iter_mut().filter(|child| !child.configured) {
        let allocated = allocate_unique(&child.member, &mut taken_members);
        if allocated != child.member {
            registrar.sink.push(warning_diagnostic(
                CODE_RENAMED_KEY_NAME,
                format!(
                    "path segment '{raw}' derives the member '{member}', which is already taken under this parent; emitting it as '{allocated}' — choose the name yourself with `naming.overrides.pathSegments: {{ \"{raw}\": \"<name>\" }}`",
                    raw = child.raw,
                    member = child.member,
                ),
                &child.node.source,
            ));
            child.member = allocated;
        }
    }

    for child in resolved.iter().filter(|child| !refused.contains(child.raw)) {
        let mut child_address = address.to_vec();
        child_address.push(child.raw.clone());
        let mut child_members = members.to_vec();
        child_members.push(child.member.clone());
        let mut child_parameters = parameters.to_vec();
        let mut child_elements = elements.to_vec();

        let mut taken_identifiers: BTreeSet<String> = child_parameters
            .iter()
            .map(|existing| existing.identifier.clone())
            .collect();
        for parameter in child.parameters.iter().cloned() {
            // A path template naming one parameter twice gets one function argument, not two: the
            // client substitutes a single declared value into every occurrence, so a key taking two
            // could name a request the client cannot make. Both elements read the one allocation
            // back by wire name.
            if child_parameters
                .iter()
                .any(|existing: &KeyParameter| existing.wire == parameter.wire)
            {
                continue;
            }
            // Two *different* wire names can still normalize to one identifier — `{user_id}` beside
            // `{userId}` — and those are two parameters, so they take two arguments.
            let identifier = allocate_unique(&parameter.identifier, &mut taken_identifiers);
            if identifier != parameter.identifier {
                registrar.sink.push(warning_diagnostic(
                    CODE_RENAMED_KEY_NAME,
                    format!(
                        "path parameter '{wire}' derives the argument name '{derived}', which another parameter on this path already takes; emitting it as '{identifier}'",
                        wire = parameter.wire,
                        derived = parameter.identifier,
                    ),
                    &child.node.source,
                ));
            }
            child_parameters.push(KeyParameter {
                wire: parameter.wire,
                identifier,
            });
        }
        child_elements.push(key_element(&child.node.kind, &child_parameters));

        collect_bindings(
            child.node,
            namespace,
            overrides,
            matched_overrides,
            &BindingWalk {
                address: &child_address,
                members: &child_members,
                parameters: &child_parameters,
                elements: &child_elements,
                configured: child.configured.then_some(child.raw.as_str()),
            },
            planned,
            registrar,
        );
    }
}

/// `scope` is every parameter in scope at this node, so a run's identifier is read back from the
/// one already allocated for it rather than re-derived.
fn key_element(kind: &SegmentKind, scope: &[KeyParameter]) -> KeyElement {
    let allocated = |wire: &str| {
        // `collect_bindings` appended every parameter from this segment before calling here.
        scope
            .iter()
            .rev()
            .find(|parameter| parameter.wire == wire)
            .cloned()
            .expect("every parameter this segment introduces was just pushed onto the scope")
    };
    match kind {
        SegmentKind::Literal(text) => KeyElement::Literal(text.clone()),
        SegmentKind::Param(name) => KeyElement::Param(allocated(name)),
        SegmentKind::Mixed(runs) => KeyElement::Mixed(
            runs.iter()
                .map(|run| match run {
                    SegmentPart::Literal(literal) => KeyElement::Literal(literal.clone()),
                    SegmentPart::Param(name) => KeyElement::Param(allocated(name)),
                })
                .collect(),
        ),
    }
}

fn render_key_element(element: &KeyElement) -> String {
    match element {
        KeyElement::Literal(text) => render_ts_string(text),
        KeyElement::Param(parameter) => {
            // A *value*-position object literal, so `__proto__` has to be a computed key: written
            // bare it would set the object's prototype instead of creating an own property, and the
            // parameter's value would vanish from the key entirely.
            let key = render_literal_key(&parameter.wire);
            // Property shorthand whenever the wire name is already the parameter identifier, which
            // is the common case and the shape the key contract shows.
            let present = if key == parameter.identifier {
                format!("{{ {} }}", parameter.identifier)
            } else {
                format!("{{ {key}: {} }}", parameter.identifier)
            };
            // TanStack's stable hash drops undefined-valued object properties. An empty array is
            // therefore the missing-value representation: it is serializable and structurally
            // distinct from the object every present path value contributes.
            format!("{} === undefined ? [] : {present}", parameter.identifier)
        }
        KeyElement::Mixed(runs) => {
            let rendered: Vec<String> = runs.iter().map(render_key_element).collect();
            format!("[{}]", rendered.join(", "))
        }
    }
}

impl KeyFactory {
    /// The binding addressed by a path template, if the factory allocated one.
    fn binding(&self, path_template: &[Segment]) -> Option<&KeyBinding> {
        self.bindings.get(&address_of(path_template))
    }

    /// The binding for the immediate parent of a path template — the collection an entity sits in.
    fn parent_binding(&self, path_template: &[Segment]) -> Option<&KeyBinding> {
        let mut address = address_of(path_template);
        address.pop()?;
        self.bindings.get(&address)
    }

    /// Renders `tanstack/keys.ts`.
    pub(crate) fn render(&self, model: &EmissionModel<'_>) -> String {
        let mut output = model.header();
        output.push_str(
            "// One binding per path node. An operation module imports the single leaf binding it needs,\n\
             // never the composed `keys` object below: a bundler cannot drop unused properties of an\n\
             // object that is referenced at all, so importing the object would retain every path's key\n\
             // data. Import `keys` when you want prefix invalidation and are willing to pay for the tree.\n\n",
        );
        let extension = import_extension(model);
        output.push_str("import type { ParamValue } from ");
        output.push_str(&render_ts_string(&relative_import(
            &format!("{}/keys.ts", model.dirs.tanstack),
            &[model.dirs.runtime, "serialize"],
            &extension,
        )));
        output.push_str(
            ";\n\n// What a path parameter contributes to a key. Wider than `ParamValue` because a\n             // `content`-typed parameter carries arbitrary JSON, and one signature has to serve\n             // every operation on the path — the client is what checks the value against its own\n             // schema; a key only has to be able to hold it. A factory also accepts `undefined`\n             // for an optional path parameter and encodes it as a distinct array segment.\n             export type KeyValue = ParamValue | { readonly [key: string]: KeyValue } | readonly KeyValue[];\n\n",
        );

        for binding in self.bindings.values() {
            write_source_metadata(&mut output, &binding.source, 0);
            let elements: Vec<String> = binding.elements.iter().map(render_key_element).collect();
            let body = format!("[{}] as const", elements.join(", "));
            if binding.is_function() {
                let signature: Vec<String> = binding
                    .parameters
                    .iter()
                    .map(|parameter| format!("{}: KeyValue | undefined", parameter.identifier))
                    .collect();
                output.push_str(&format!(
                    "export const {} = ({}) => {body};\n\n",
                    binding.name,
                    signature.join(", ")
                ));
            } else {
                output.push_str(&format!("export const {} = {body};\n\n", binding.name));
            }
        }

        output.push_str(
            "// Every node is an object carrying its own key at `all` plus its children, uniformly. The\n\
             // shape therefore does not change when a document later declares a path beneath an existing\n\
             // one — `keys.pets.byPetId.all` keeps meaning \"everything under this pet\" either way.\n",
        );
        output.push_str("export const keys = ");
        output.push_str(&self.render_nested(&self.root, &Vec::new(), 0));
        output.push_str(";\n");
        output
    }

    fn render_nested(&self, node: &PathNode, address: &[String], depth: usize) -> String {
        let indent = "  ".repeat(depth + 1);
        let closing = "  ".repeat(depth);
        let mut output = String::from("{\n");
        if let Some(binding) = self.bindings.get(address) {
            output.push_str(&format!(
                "{indent}{COMPOSED_SELF_MEMBER}: {},\n",
                binding.name
            ));
        }
        for (raw, child) in &node.children {
            let mut child_address = address.to_vec();
            child_address.push(raw.clone());
            let Some(binding) = self.bindings.get(&child_address) else {
                continue;
            };
            // A child binding is created only after its derived member is appended.
            let member = binding
                .members
                .last()
                .expect("a child node's binding always carries at least one member");
            output.push_str(&format!(
                "{indent}{}: {},\n",
                render_literal_key(member),
                self.render_nested(child, &child_address, depth + 1)
            ));
        }
        output.push_str(&closing);
        output.push('}');
        output
    }
}

/// The path template as written, for a diagnostic that has to name two paths a reader can find.
fn path_template_text(path_template: &[Segment]) -> String {
    let mut text = String::new();
    for segment in path_template {
        // The IR carries no separator parts — the leading `/` is the client emitter's addition — so
        // an empty segment is a trailing slash and renders as exactly that.
        text.push('/');
        for part in &segment.parts {
            match part {
                SegmentPart::Literal(literal) => text.push_str(literal),
                SegmentPart::Param(name) => {
                    text.push('{');
                    text.push_str(name);
                    text.push('}');
                }
            }
        }
    }
    text
}

fn address_of(path_template: &[Segment]) -> Vec<String> {
    path_template
        .iter()
        .filter_map(|segment| SegmentKind::classify(segment).map(|kind| kind.raw_text()))
        .collect()
}

/// Whether an operation is a read, i.e. whether it is a candidate for a query descriptor.
fn is_read(operation: &Operation) -> bool {
    matches!(
        operation.method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD"
    )
}

/// Whether any arm of this body can be a stream. A discriminated body is checked arm by arm: the
/// caller picks the wire type at the call site, so an operation offering one streaming media among
/// several buffered ones can still be handed a stream, and a retry would resend an exhausted one.
fn body_can_stream(plan: &BodyPlan) -> bool {
    match plan {
        BodyPlan::TopLevelStream { .. } => true,
        BodyPlan::ContentTypeDiscriminated { arms, .. } => {
            arms.iter().any(|arm| body_can_stream(&arm.plan))
        }
        BodyPlan::Json { .. }
        | BodyPlan::TopLevelText { .. }
        | BodyPlan::TopLevelBinary { .. }
        | BodyPlan::FormUrlencoded { .. }
        | BodyPlan::Multipart { .. } => false,
    }
}

/// The reason a streaming operation gets no descriptor at all, or `None` when it streams nothing.
/// A request-side stream counts too: it is single-consumption in the same way, so a retried
/// mutation would send an exhausted body.
fn streaming_ineligibility(plan: &OperationPlan) -> Option<&'static str> {
    if plan.body_plan.as_ref().is_some_and(body_can_stream) {
        return Some(
            "its request body can be a stream, which cannot be consumed twice and so cannot be retried",
        );
    }
    let streams = plan.response_table.iter().any(|response| {
        matches!(response.payload, PayloadDisposition::Payload)
            && response.media.iter().any(|media| {
                matches!(
                    media.decoder,
                    DecoderClass::StreamingSse | DecoderClass::StreamingRaw
                )
            })
    });
    streams.then_some(
        "it responds with a stream, which is consumable once and cannot be handed to two cache readers",
    )
}

/// Whether `orThrow` can resolve a client envelope rather than always throwing.
///
/// An operation whose every documented response is an error has no success arm, so the client types
/// its throwing wrapper `Promise<never>`. Reads never reach here — `is_query_eligible` refuses them
/// first — but writes are emitted regardless, and `never` carries no `.data` to unwrap.
fn has_successful_response(plan: &OperationPlan) -> bool {
    plan.response_table.iter().any(|response| {
        !matches!(
            response_body_side(response.kind, &response.match_key),
            ResponseBody::Error
        )
    })
}

/// Whether a read operation may emit a query descriptor.
///
/// A query function resolving `undefined` is rejected, and a descriptor resolves the operation's
/// payload — so **every** success branch must carry one. A read with a body-carrying 200 beside a
/// bodyless 204 fails this: its payload union admits `undefined` whenever the server picks the 204.
/// `HEAD` always falls out here rather than by special case, because Fetch fixes its body to null
/// and every one of its branches is therefore bodyless.
fn is_query_eligible(plan: &OperationPlan) -> Result<(), &'static str> {
    let mut success_branches = 0_usize;
    for response in &plan.response_table {
        if matches!(
            response_body_side(response.kind, &response.match_key),
            ResponseBody::Error
        ) {
            continue;
        }
        success_branches += 1;
        if !matches!(response.payload, PayloadDisposition::Payload) {
            return Err(
                "at least one successful response is bodyless, and a query function may not resolve undefined",
            );
        }
    }
    if success_branches == 0 {
        return Err(
            "it documents no successful response, so a query function has nothing to resolve",
        );
    }
    Ok(())
}

/// The non-path input sections an operation declares, in canonical order.
///
/// A request body is included when one is declared. Only reads reach this, and Fetch forbids a body
/// on `GET` or `HEAD` — so such a call always fails at request construction and the body can never
/// actually vary a response. It is keyed anyway: leaving it out would make two descriptor calls
/// that differ only in their body produce the same key, which is a claim about cache identity that
/// is wrong on its own terms, whatever the transport later does with the request.
fn input_sections(operation: &Operation) -> Vec<&'static str> {
    let mut sections = Vec::new();
    for (location, name) in [
        (ParamLocation::Query, "query"),
        (ParamLocation::Header, "header"),
        (ParamLocation::Cookie, "cookie"),
    ] {
        if operation
            .parameters
            .iter()
            .any(|parameter| parameter.location == location)
        {
            sections.push(name);
        }
    }
    if operation.request_body.is_some() {
        sections.push("body");
    }
    sections
}

/// A member access on `base`, bracketed when the wire name is not a bare identifier.
///
/// Delegates to `render_property_key` so the definition of "bare identifier" cannot drift from the
/// rest of the emit module, which is the same reason the transform emitter's property access does.
fn member_access(base: &str, name: &str) -> String {
    let key = render_property_key(name);
    if key == name {
        format!("{base}.{name}")
    } else {
        format!("{base}[{key}]")
    }
}

/// The call that produces one binding's key from an input expression.
fn binding_call(binding: &KeyBinding, operation: &Operation, input: &str) -> String {
    if binding.is_function() {
        let arguments: Vec<String> = binding
            .parameters
            .iter()
            .map(|parameter| {
                let required = operation.parameters.iter().any(|candidate| {
                    candidate.location == ParamLocation::Path
                        && candidate.name == parameter.wire
                        && candidate.required
                });
                let path = if required {
                    format!("{input}.path")
                } else {
                    format!("{input}.path?")
                };
                member_access(&path, &parameter.wire)
            })
            .collect();
        format!("{}({})", binding.name, arguments.join(", "))
    } else {
        binding.name.clone()
    }
}

/// One emitted tanstack operation module, before its imports are rendered.
struct ModuleBody {
    content: String,
    /// Key bindings the body references, so `keys.ts` is imported by leaf name only.
    bindings: BTreeSet<String>,
    /// Names the body imports from the artifact's local runtime.
    runtime_imports: BTreeSet<String>,
    /// Whether the body calls the operation's request encoder.
    uses_encoder: bool,
}

/// Emits the tanstack artifact: the key factory, the local runtime, and one module per operation.
pub(crate) fn emit_tanstack_from_model(
    model: &EmissionModel<'_>,
    registrar: &mut Registrar<'_>,
    client: &ClientModel,
) -> Vec<GeneratedFile> {
    let factory = build_key_factory(model, registrar);
    let mut files = Vec::new();

    let keys_source = factory
        .bindings
        .values()
        .next()
        .map_or_else(SourceRef::default, |binding| binding.source.clone());
    let keys = factory.render(model);
    let keys_path = format!("{}/keys.ts", model.dirs.tanstack);
    registrar.register_path(&keys_path, &keys_source);
    files.push(GeneratedFile {
        relative_path: keys_path,
        content: keys,
    });

    // The embedded source sits beside transport.ts; emitted, it sits one directory below the
    // runtime tree. The repoint happens AFTER the extension rewrite, not before: that rewrite only
    // recognizes `./`-prefixed specifiers, so repointing first would leave the `.ts` suffix in
    // emitted output.
    let runtime_path = format!("{}/runtime.ts", model.dirs.tanstack);
    let runtime =
        rewrite_relative_ts_imports(TANSTACK_RUNTIME_TS, &model.config.emit.import_extension)
            .replace(
                &format!("\"./transport{}\"", import_extension(model)),
                &format!(
                    "\"{}\"",
                    relative_import(
                        &runtime_path,
                        &[model.dirs.runtime, "transport"],
                        &import_extension(model),
                    )
                ),
            );
    registrar.register_path(&runtime_path, &keys_source);
    files.push(GeneratedFile {
        relative_path: runtime_path,
        content: runtime,
    });

    for plan in &client.operations {
        let Some(allocated) = model
            .analyzed
            .operation_names
            .iter()
            .find(|allocated| allocated.operation_index == plan.operation_index)
            .cloned()
        else {
            continue;
        };
        let Some(file_base) = model.operation_files[plan.operation_index].clone() else {
            continue;
        };
        let operation = model.analyzed.ir.operations[plan.operation_index].clone();
        let mut emission = Emission::default();
        emit_operation(
            model,
            &mut emission,
            &factory,
            &operation,
            plan,
            &allocated.name,
            &file_base,
        );
        merge_emission(&mut files, registrar, emission);
    }

    files
}

fn emit_operation(
    model: &EmissionModel<'_>,
    emission: &mut Emission,
    factory: &KeyFactory,
    operation: &Operation,
    plan: &OperationPlan,
    allocated_name: &str,
    file_base: &str,
) {
    let stem = uppercase_first(allocated_name);
    let encodes = request_transform_binding(model, plan);

    // A streaming operation is excluded on both sides, not just the query side: a stream handle is
    // consumable exactly once, so caching one under a query key hands every later cache reader an
    // already-drained iterable, and a mutation descriptor would resolve one into the same trap.
    if let Some(reason) = streaming_ineligibility(plan) {
        emission.diagnostics.push(warning_diagnostic(
            CODE_INELIGIBLE_QUERY,
            format!("operation '{allocated_name}' emits no descriptor: {reason}"),
            &operation.source,
        ));
        return;
    }
    let body = if is_read(operation) {
        if let Err(reason) = is_query_eligible(plan) {
            emission.diagnostics.push(warning_diagnostic(
                CODE_INELIGIBLE_QUERY,
                format!("operation '{allocated_name}' emits no query descriptor: {reason}"),
                &operation.source,
            ));
            return;
        }
        let Some(body) = query_body(factory, operation, allocated_name, &stem, encodes) else {
            return;
        };
        body
    } else {
        let Some(body) = mutation_body(
            factory,
            operation,
            model.config.namespace.as_str(),
            allocated_name,
            &stem,
            encodes,
            has_successful_response(plan),
        ) else {
            return;
        };
        body
    };

    let extension = import_extension(model);
    let relative_path = format!("{}/operations/{file_base}.ts", model.dirs.tanstack);
    let mut output = model.header();
    // Every descriptor names at least its own path node's binding, so this import is unconditional.
    output.push_str(&format!(
        "import {{ {} }} from {};\n",
        body.bindings.iter().cloned().collect::<Vec<_>>().join(", "),
        render_ts_string(&format!("../keys{extension}"))
    ));
    if !body.runtime_imports.is_empty() {
        output.push_str(&format!(
            "import {{ {} }} from {};\n",
            body.runtime_imports
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            render_ts_string(&format!("../runtime{extension}"))
        ));
    }
    output.push_str(&format!(
        "import {{ {allocated_name}OrThrow, type {stem}CallArgs, type {stem}Input, type {stem}Result }} from {};\n",
        render_ts_string(&relative_import(
            &relative_path,
            &[model.dirs.client, "operations", file_base],
            &extension,
        ))
    ));
    if body.uses_encoder {
        output.push_str(&format!(
            "import {{ encode{stem}Input }} from {};\n",
            render_ts_string(&relative_import(
                &relative_path,
                &[model.dirs.client, TRANSFORM_SUBDIR, "operations", file_base],
                &extension,
            ))
        ));
    }
    output.push_str(&format!(
        "import type {{ ApiError }} from {};\n",
        render_ts_string(&relative_import(
            &relative_path,
            &[model.dirs.runtime, "result"],
            &extension,
        ))
    ));
    output.push_str(&format!(
        "import type {{ Transport }} from {};\n\n",
        render_ts_string(&relative_import(
            &relative_path,
            &[model.dirs.runtime, "transport"],
            &extension,
        ))
    ));
    output.push_str(&body.content);

    emission.register_path(&relative_path, &operation.source);
    emission.files.push(GeneratedFile {
        relative_path,
        content: output,
    });
}

fn query_body(
    factory: &KeyFactory,
    operation: &Operation,
    allocated_name: &str,
    stem: &str,
    encodes: bool,
) -> Option<ModuleBody> {
    let binding = factory.binding(&operation.path_template)?;
    let mut bindings = BTreeSet::new();
    bindings.insert(binding.name.clone());

    // The key must hold wire values, so a transform-reachable input is encoded before it is keyed.
    // `orThrow` still receives the application-typed input — the client runs its own encode
    // internally — so this encode exists only to build the key.
    let key_input = if encodes { "wire" } else { "input" };
    let sections = input_sections(operation);
    let key = if sections.is_empty() {
        binding_call(binding, operation, key_input)
    } else {
        // Whether the caller supplied any of the declared sections is a runtime fact, so the
        // append is a runtime decision. See `withInput` for why appending unconditionally breaks
        // exact-match invalidation.
        let fields: Vec<String> = sections
            .iter()
            .map(|section| format!("{section}: {key_input}.{section}"))
            .collect();
        format!(
            "withInput({}, {{ {} }})",
            binding_call(binding, operation, key_input),
            fields.join(", ")
        )
    };

    let mut runtime_imports = BTreeSet::from(["withRequestSignal".to_owned()]);
    if !sections.is_empty() {
        runtime_imports.insert("withInput".to_owned());
    }

    let mut content = String::new();
    write_source_metadata(&mut content, &operation.source, 0);
    content.push_str(&format!(
        "export function {allocated_name}Query<S extends string = never>(transport: Transport<S>, input: {stem}Input, ...args: {stem}CallArgs<S>) {{\n"
    ));
    if encodes {
        content.push_str(&format!("  const wire = encode{stem}Input(input);\n"));
    }
    content.push_str("  return {\n");
    content.push_str(&format!("    queryKey: {key},\n"));
    content.push_str(&format!(
        "    queryFn: async ({{ signal }}: {{ signal: AbortSignal }}) => (await {allocated_name}OrThrow(withRequestSignal(transport, signal), input, ...args)).data,\n"
    ));
    content.push_str("  };\n}\n\n");
    content.push_str(&format!(
        "export type {stem}QueryKey = ReturnType<typeof {allocated_name}Query>[\"queryKey\"];\n"
    ));
    content.push_str(&format!(
        "export type {stem}QueryData = Awaited<ReturnType<ReturnType<typeof {allocated_name}Query>[\"queryFn\"]>>;\n"
    ));
    content.push_str(&format!(
        "export type {stem}QueryError = ApiError<Extract<{stem}Result, {{ ok: false }}>>;\n"
    ));

    Some(ModuleBody {
        content,
        bindings,
        runtime_imports,
        uses_encoder: encodes,
    })
}

fn mutation_body(
    factory: &KeyFactory,
    operation: &Operation,
    namespace: &str,
    allocated_name: &str,
    stem: &str,
    encodes: bool,
    unwraps_payload: bool,
) -> Option<ModuleBody> {
    let binding = factory.binding(&operation.path_template)?;
    let mut bindings = BTreeSet::new();

    // Broadest first: the immediate parent collection, then the entity. `invalidateQueries`
    // prefix-matches, so entry [0] already covers everything beneath it, and entry [1] gives a
    // caller who wants `exact: true` something to name. A mutation on a collection path has no
    // entity below it, so it yields the collection alone.
    let key_input = if encodes { "wire" } else { "input" };
    let mut affects = Vec::new();
    if !binding.collection
        && let Some(parent) = factory.parent_binding(&operation.path_template)
    {
        bindings.insert(parent.name.clone());
        affects.push(binding_call(parent, operation, key_input));
    }
    bindings.insert(binding.name.clone());
    affects.push(binding_call(binding, operation, key_input));

    // A collection-level mutation on an unparameterized path reads nothing from its input, and a
    // consumer compiling the generated tree with `noUnusedParameters` would be told so. The
    // underscore keeps the signature identical — parameter names do not affect assignability — and
    // is the convention that flag itself defines.
    let affects_parameter = if encodes || binding.is_function() {
        "input"
    } else {
        "_input"
    };

    let mut content = String::new();
    write_source_metadata(&mut content, &operation.source, 0);
    content.push_str(&format!(
        "export function {allocated_name}Mutation<S extends string = never>(transport: Transport<S>, ...args: {stem}CallArgs<S>) {{\n"
    ));
    content.push_str("  return {\n");
    content.push_str(&format!(
        "    mutationKey: [{}, {}] as const,\n",
        render_ts_string(namespace),
        render_ts_string(allocated_name)
    ));
    // TanStack supplies no signal to a mutation function, so `args` passes through untouched and
    // the transport is never wrapped. `.data` unwraps the client envelope to the payload; an
    // operation with no success arm has no envelope to unwrap, and keeps the awaited `never`.
    let data_access = if unwraps_payload { ".data" } else { "" };
    content.push_str(&format!(
        "    mutationFn: async (input: {stem}Input) => (await {allocated_name}OrThrow(transport, input, ...args)){data_access},\n"
    ));
    content.push_str("  };\n}\n\n");

    write_source_metadata(&mut content, &operation.source, 0);
    content.push_str(&format!(
        "export function {allocated_name}MutationAffects({affects_parameter}: {stem}Input) {{\n"
    ));
    if encodes {
        content.push_str(&format!("  const wire = encode{stem}Input(input);\n"));
    }
    content.push_str(&format!(
        "  return [{}] as const;\n}}\n\n",
        affects.join(", ")
    ));

    content.push_str(&format!(
        "export type {stem}MutationKey = ReturnType<typeof {allocated_name}Mutation>[\"mutationKey\"];\n"
    ));
    content.push_str(&format!(
        "export type {stem}MutationData = Awaited<ReturnType<ReturnType<typeof {allocated_name}Mutation>[\"mutationFn\"]>>;\n"
    ));
    content.push_str(&format!(
        "export type {stem}MutationError = ApiError<Extract<{stem}Result, {{ ok: false }}>>;\n"
    ));

    Some(ModuleBody {
        content,
        bindings,
        runtime_imports: BTreeSet::new(),
        uses_encoder: encodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_model::build_client_model;
    use crate::config::load_single;
    use crate::diag::{Diagnostic, DiagnosticSink, Severity};
    use crate::emit::emit_artifacts;
    use crate::inputs::InputRecorder;
    use crate::loader::load_graph;
    use crate::parse::parse;
    use crate::semantic::analyze;
    use std::fs;
    use tempfile::TempDir;

    const TANSTACK_CONFIG: &str = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: api\noutput: ./generated\nartifacts:\n  types: true\n  client: true\n  tanstack: true\nclient:\n  authEnforcement: types\n  baseUrl:\n    source: runtime\nvalidation:\n  engine: 'off'\n  unchecked: allow\n";

    /// Runs the whole emission stage, which is the only way the descriptor emitter is reachable:
    /// it needs a client model, and the client model is built beside it.
    fn emit(document: &str, config: &str) -> (Vec<GeneratedFile>, Vec<Diagnostic>) {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), document).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), config).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_single(None, temp.path()).expect("config loads");
        let graph =
            load_graph(&resolved, &mut InputRecorder::off(), &mut sink).expect("graph loads");
        let tuples = graph.source_tuples();
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        let client = build_client_model(&analyzed, &resolved, &mut sink);
        let files = emit_artifacts(
            &analyzed,
            &resolved,
            &tuples,
            Some(&client),
            &mut InputRecorder::off(),
            &mut sink,
        );
        (files, sink.into_sorted_vec())
    }

    fn emitted<'files>(files: &'files [GeneratedFile], path: &str) -> &'files str {
        &files
            .iter()
            .find(|file| file.relative_path == path)
            .expect("the emitter produced this module")
            .content
    }

    #[test]
    fn tanstack_files_start_their_first_declaration_after_one_blank_line() {
        let (files, diagnostics) = emit(DOCUMENT, TANSTACK_CONFIG);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity != Severity::Error)
        );

        for (path, first_declaration) in [
            (
                "tanstack/keys.ts",
                "// One binding per path node. An operation module imports the single leaf binding it needs,",
            ),
            ("tanstack/operations/listpets.ts", "import { "),
        ] {
            let content = emitted(&files, path);
            let (_, after_digest) = content
                .split_once("// Source digest: ")
                .expect("source digest header");
            let (_, after_header) = after_digest.split_once('\n').expect("digest line ending");
            assert!(
                after_header.starts_with(&format!("\n{first_declaration}")),
                "unexpected first bytes for {path}: {content:?}"
            );
        }
    }

    fn literal(text: &str) -> SegmentPart {
        SegmentPart::Literal(text.to_owned())
    }

    fn param(name: &str) -> SegmentPart {
        SegmentPart::Param(name.to_owned())
    }

    fn segment(parts: Vec<SegmentPart>) -> Segment {
        Segment { parts }
    }

    fn parameter_names(kind: &SegmentKind) -> Vec<String> {
        kind.parameter_bindings()
            .expect("nameable")
            .into_iter()
            .map(|parameter| parameter.wire)
            .collect()
    }

    fn member_of(kind: &SegmentKind) -> Result<String, String> {
        kind.derived_member()
    }

    #[test]
    fn a_purely_literal_segment_classifies_as_literal() {
        let kind = SegmentKind::classify(&segment(vec![literal("pets")]));
        assert_eq!(kind, Some(SegmentKind::Literal("pets".to_owned())));
        let kind = kind.expect("classified");
        assert_eq!(kind.raw_text(), "pets");
        assert_eq!(member_of(&kind), Ok("pets".to_owned()));
        assert!(parameter_names(&kind).is_empty());
        assert!(kind.takes_all_suffix());
    }

    #[test]
    fn a_whole_template_segment_classifies_as_a_parameter() {
        let kind = SegmentKind::classify(&segment(vec![param("petId")])).expect("classified");
        assert_eq!(kind, SegmentKind::Param("petId".to_owned()));
        assert_eq!(kind.raw_text(), "{petId}");
        assert_eq!(member_of(&kind), Ok("byPetId".to_owned()));
        assert_eq!(parameter_names(&kind), vec!["petId".to_owned()]);
        assert!(!kind.takes_all_suffix());
    }

    #[test]
    fn a_mixed_segment_with_a_trailing_literal_keeps_its_runs_ordered() {
        let kind = SegmentKind::classify(&segment(vec![param("id"), literal(".json")]))
            .expect("classified");
        assert_eq!(kind.raw_text(), "{id}.json");
        assert_eq!(member_of(&kind), Ok("byIdJson".to_owned()));
        assert_eq!(parameter_names(&kind), vec!["id".to_owned()]);
        assert!(!kind.takes_all_suffix());
    }

    #[test]
    fn a_mixed_segment_with_a_leading_literal_keeps_its_runs_ordered() {
        let kind = SegmentKind::classify(&segment(vec![literal("v"), param("major")]))
            .expect("classified");
        assert_eq!(kind.raw_text(), "v{major}");
        assert_eq!(member_of(&kind), Ok("byVMajor".to_owned()));
    }

    #[test]
    fn a_mixed_segment_with_several_runs_names_every_run() {
        let kind = SegmentKind::classify(&segment(vec![
            param("owner"),
            literal("-"),
            param("repo"),
            literal(".git"),
        ]))
        .expect("classified");
        assert_eq!(kind.raw_text(), "{owner}-{repo}.git");
        assert_eq!(member_of(&kind), Ok("byOwnerRepoGit".to_owned()));
        assert_eq!(
            parameter_names(&kind),
            vec!["owner".to_owned(), "repo".to_owned()]
        );
    }

    #[test]
    fn an_empty_segment_is_a_trailing_slash_and_classifies_as_nothing() {
        // The IR carries no separator parts, so an empty segment is exactly a trailing slash. It
        // contributes no key element, which is why two paths differing only by one need the
        // same-key check rather than distinct bindings.
        assert_eq!(SegmentKind::classify(&segment(Vec::new())), None);
    }

    const CONFIG: &str = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: api\noutput: ./generated\nartifacts:\n  types: true\n";

    fn keys_for(document: &str, config: &str) -> (String, Vec<crate::diag::Diagnostic>) {
        let temp = TempDir::new().expect("temp dir");
        fs::write(temp.path().join("openapi.yaml"), document).expect("write document");
        fs::write(temp.path().join("oasts.yaml"), config).expect("write config");
        let mut sink = DiagnosticSink::new();
        let resolved = load_single(None, temp.path()).expect("config loads");
        let graph =
            load_graph(&resolved, &mut InputRecorder::off(), &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("document parses");
        drop(graph);
        let analyzed = analyze(ir, &resolved, &mut sink);
        let mut registrar = Registrar::new(&mut sink);
        let model = EmissionModel::new(&analyzed, &resolved, "digest".to_owned(), &mut registrar);
        let factory = build_key_factory(&model, &mut registrar);
        let rendered = factory.render(&model);
        (rendered, sink.into_sorted_vec())
    }

    const SHOWCASE: &str = r#"
openapi: 3.1.0
info:
  title: Keys
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
  /pets/mine:
    get:
      operationId: getMyPet
      responses:
        '200':
          description: ok
  /pets/{petId}:
    get:
      operationId: getPet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: ok
  /pets/{petId}/toys/{toyId}:
    get:
      operationId: getToy
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
        - name: toyId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: ok
  /reports/{id}.json:
    get:
      operationId: getReportJson
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: ok
  /reports/{id}.xml:
    get:
      operationId: getReportXml
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: ok
"#;

    /// Asserts the run refused nothing, and returns the rename warnings it did raise.
    fn renames(diagnostics: &[crate::diag::Diagnostic]) -> Vec<&str> {
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error),
            "{diagnostics:#?}"
        );
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_RENAMED_KEY_NAME)
            .map(|diagnostic| diagnostic.message.as_str())
            .collect()
    }

    #[test]
    fn every_path_node_gets_a_flat_binding_including_undeclared_intermediates() {
        let (keys, diagnostics) = keys_for(SHOWCASE, CONFIG);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");

        // A node with no parameterized ancestor is a constant.
        assert!(
            keys.contains("export const apiAll = [\"api\"] as const;"),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiPetsAll = [\"api\", \"pets\"] as const;"),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiPetsMineAll = [\"api\", \"pets\", \"mine\"] as const;"),
            "{keys}"
        );

        // A whole-template segment contributes a single-key object, never the bare value, so
        // `/pets/mine` and `/pets/{petId}` with petId = "mine" cannot collide at any prefix depth.
        assert!(
            keys.contains(
                "export const apiPetsByPetId = (petId: KeyValue | undefined) => [\"api\", \"pets\", petId === undefined ? [] : { petId }] as const;"
            ),
            "{keys}"
        );

        // `/pets/{petId}/toys` is declared by no operation, yet an invalidation list for the toy
        // entity needs its key, so it still gets a binding.
        assert!(
            keys.contains(
                "export const apiPetsByPetIdToysAll = (petId: KeyValue | undefined) => [\"api\", \"pets\", petId === undefined ? [] : { petId }, \"toys\"] as const;"
            ),
            "{keys}"
        );
        assert!(
            keys.contains(
                "export const apiPetsByPetIdToysByToyId = (petId: KeyValue | undefined, toyId: KeyValue | undefined) => [\"api\", \"pets\", petId === undefined ? [] : { petId }, \"toys\", toyId === undefined ? [] : { toyId }] as const;"
            ),
            "{keys}"
        );

        // A mixed segment contributes one nested array of its ordered runs, keeping the two report
        // extensions distinct at every prefix depth.
        assert!(
            keys.contains(
                "export const apiReportsByIdJson = (id: KeyValue | undefined) => [\"api\", \"reports\", [id === undefined ? [] : { id }, \".json\"]] as const;"
            ),
            "{keys}"
        );
        assert!(
            keys.contains(
                "export const apiReportsByIdXml = (id: KeyValue | undefined) => [\"api\", \"reports\", [id === undefined ? [] : { id }, \".xml\"]] as const;"
            ),
            "{keys}"
        );
    }

    #[test]
    fn the_composed_object_carries_every_node_uniformly() {
        let (keys, _) = keys_for(SHOWCASE, CONFIG);
        let nested = keys
            .split_once("export const keys = ")
            .expect("composed object")
            .1;
        assert!(nested.contains("all: apiAll,"), "{nested}");
        assert!(nested.contains("all: apiPetsAll,"), "{nested}");
        assert!(nested.contains("byPetId: {"), "{nested}");
        assert!(nested.contains("all: apiPetsByPetId,"), "{nested}");
        assert!(nested.contains("byIdJson: {"), "{nested}");
    }

    #[test]
    fn an_operation_module_never_needs_the_composed_object() {
        let (keys, _) = keys_for(SHOWCASE, CONFIG);
        // Every binding is exported on its own, so a module importing one leaf retains one arrow
        // function rather than the whole spec's key data.
        for name in [
            "apiAll",
            "apiPetsAll",
            "apiPetsMineAll",
            "apiPetsByPetId",
            "apiPetsByPetIdToysAll",
            "apiPetsByPetIdToysByToyId",
            "apiReportsAll",
            "apiReportsByIdJson",
            "apiReportsByIdXml",
        ] {
            assert!(
                keys.contains(&format!("export const {name} =")),
                "missing flat binding {name}"
            );
        }
    }

    const COLLIDING: &str = r#"
openapi: 3.1.0
info:
  title: Collision
  version: 1.0.0
paths:
  /foo-bar:
    get:
      operationId: readHyphenated
      responses:
        '200':
          description: ok
  /foo_bar:
    get:
      operationId: readUnderscored
      responses:
        '200':
          description: ok
"#;

    #[test]
    fn two_segments_normalizing_to_one_member_take_the_lowest_free_suffix() {
        let (keys, diagnostics) = keys_for(COLLIDING, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains("path segment 'foo_bar' derives the member 'fooBar'")
                && warnings[0].contains("emitting it as 'fooBar2'"),
            "{warnings:#?}"
        );
        // Children are walked in raw-segment order, so `foo-bar` sorts first and keeps the bare
        // member; `foo_bar` takes the suffix. Both keys still carry their own raw text, so the two
        // paths never share a cache entry however they are named.
        assert!(keys.contains("export const apiFooBarAll = [\"api\", \"foo-bar\"] as const;\n"));
        assert!(
            keys.contains("export const apiFooBar2All = [\"api\", \"foo_bar\"] as const;\n"),
            "{keys}"
        );
        assert!(keys.contains("  fooBar: {\n"), "{keys}");
        assert!(keys.contains("  fooBar2: {\n"), "{keys}");
    }

    #[test]
    fn two_nodes_at_different_depths_binding_one_name_are_disambiguated() {
        // `/foo/bar` and `/foo-bar` sit under different parents, so the per-parent member
        // allocation cannot see them; their flat binding names collide all the same, and the flat
        // allocation is what separates them.
        const CROSS_DEPTH: &str = r#"
openapi: 3.1.0
info:
  title: Cross depth
  version: 1.0.0
paths:
  /foo/bar:
    get:
      operationId: readNested
      responses:
        '200':
          description: ok
  /foo-bar:
    get:
      operationId: readFlat
      responses:
        '200':
          description: ok
"#;
        let (keys, diagnostics) = keys_for(CROSS_DEPTH, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        // The warning names both competitors, where the winner is declared, and the entry that
        // pins the loser — the segment where the two addresses diverge, which is the only one a
        // reader can act on.
        assert!(
            warnings[0].contains(
                "key binding 'apiFooBarAll' for path '/foo-bar' is already bound by path '/foo/bar' (declared at "
            ),
            "{warnings:#?}"
        );
        assert!(
            warnings[0].contains(
                "emitting it as 'apiFooBarAll2' — pin it with `naming.overrides.pathSegments: { \"foo-bar\": \"<distinctName>\" }`"
            ),
            "{warnings:#?}"
        );
        // The walk is pre-order over children sorted by raw segment text, so `foo` and the node
        // beneath it are reached before `foo-bar`: the deeper node keeps the bare name.
        assert!(
            keys.contains("export const apiFooBarAll = [\"api\", \"foo\", \"bar\"] as const;\n")
        );
        assert!(
            keys.contains("export const apiFooBarAll2 = [\"api\", \"foo-bar\"] as const;\n"),
            "{keys}"
        );
    }

    #[test]
    fn a_path_segment_override_resolves_the_collision() {
        let config = format!(
            "{CONFIG}naming:\n  overrides:\n    pathSegments:\n      foo_bar: fooBarUnderscore\n"
        );
        let (keys, diagnostics) = keys_for(COLLIDING, &config);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(keys.contains("export const apiFooBarAll ="), "{keys}");
        assert!(
            keys.contains("export const apiFooBarUnderscoreAll ="),
            "{keys}"
        );
        assert!(keys.contains("fooBarUnderscore: {"), "{keys}");
    }

    #[test]
    fn an_override_matching_no_segment_warns() {
        let config = format!(
            "{CONFIG}naming:\n  overrides:\n    pathSegments:\n      not-a-segment: neverUsed\n"
        );
        let (_, diagnostics) = keys_for(SHOWCASE, &config);
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_UNMATCHED_SEGMENT_OVERRIDE)
            .expect("unmatched override reported");
        assert_eq!(warning.severity, Severity::Warning);
        assert!(warning.message.contains("not-a-segment"), "{warning:?}");
    }

    const DOCUMENT: &str = r#"
openapi: 3.1.0
info:
  title: Descriptors
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
    post:
      operationId: createPet
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        '201':
          description: made
          content:
            application/json:
              schema:
                type: object
  /pets/{petId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: getPet
      parameters:
        - name: fields
          in: query
          schema:
            type: string
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
        '404':
          description: gone
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: deletePet
      responses:
        '204':
          description: gone
    head:
      operationId: headPet
      responses:
        '200':
          description: ok
  /pets/{petId}/toys/{toyId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema:
          type: string
      - name: toyId
        in: path
        required: true
        schema:
          type: string
    delete:
      operationId: deleteToy
      responses:
        '204':
          description: gone
  /search:
    get:
      operationId: search
      parameters:
        - name: q
          in: query
          schema:
            type: string
        - name: X-Trace-Id
          in: header
          schema:
            type: string
        - name: session
          in: cookie
          schema:
            type: string
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
  /mixed/{id}.json:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: getMixed
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
  /partial/{petId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: getPartial
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
        '204':
          description: nothing
"#;

    #[test]
    fn a_query_descriptor_wraps_the_orthrow_call_and_resolves_its_payload() {
        let (files, diagnostics) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/getpet.ts");

        assert!(
            module.contains("import { apiPetsByPetId } from \"../keys.js\";"),
            "{module}"
        );
        assert!(
            module.contains("import { withInput, withRequestSignal } from \"../runtime.js\";"),
            "{module}"
        );
        // The descriptor imports a single leaf binding, never the composed object.
        assert!(!module.contains("keys.pets"), "{module}");
        assert!(
            module.contains("export function getPetQuery<S extends string = never>(transport: Transport<S>, input: GetPetInput, ...args: GetPetCallArgs<S>)"),
            "{module}"
        );
        // `.data` unwraps the client envelope to the payload, which is what makes the bodyless
        // eligibility rule reachable at all.
        assert!(
            module.contains(
                "(await getPetOrThrow(withRequestSignal(transport, signal), input, ...args)).data,"
            ),
            "{module}"
        );
        assert!(
            module.contains(
                "export type GetPetQueryKey = ReturnType<typeof getPetQuery>[\"queryKey\"];"
            ),
            "{module}"
        );
        assert!(module.contains("export type GetPetQueryData = Awaited<ReturnType<ReturnType<typeof getPetQuery>[\"queryFn\"]>>;"), "{module}");
        assert!(
            module.contains(
                "export type GetPetQueryError = ApiError<Extract<GetPetResult, { ok: false }>>;"
            ),
            "{module}"
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn a_proto_named_parameter_keys_as_an_own_property() {
        const PROTO: &str = r#"
openapi: 3.1.0
info:
  title: Proto
  version: 1.0.0
paths:
  /things/{__proto__}:
    parameters:
      - name: __proto__
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readThing
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        let (files, _) = emit(PROTO, TANSTACK_CONFIG);
        let keys = emitted(&files, "tanstack/keys.ts");
        // A bare `__proto__` key in a value-position object literal sets the prototype instead of
        // creating an own property, so every distinct parameter value would serialize to `{}` and
        // collapse onto one cache entry. The computed form creates a real property.
        assert!(keys.contains("[\"__proto__\"]: proto"), "{keys}");
        assert!(!keys.contains("{ __proto__:"), "{keys}");
    }

    #[test]
    fn a_segment_binding_the_composed_objects_own_member_takes_a_suffix() {
        const ALL: &str = r#"
openapi: 3.1.0
info:
  title: All
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
  /pets/all:
    get:
      operationId: listAll
      responses:
        '200':
          description: ok
"#;
        // `all` is the composed object's member for a node's own key, so a child taking it would
        // emit a duplicate object key: TS1117, or — were it to compile — `keys.pets.all` silently
        // resolving to the child object instead of the collection key. The reserved member is
        // seeded into the allocation, so the segment gets the next free name and the key it
        // produces still carries the raw text `all`.
        let (keys, diagnostics) = keys_for(ALL, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains("emitting it as 'all2'"),
            "{warnings:#?}"
        );
        assert!(
            keys.contains("export const apiPetsAll2All = [\"api\", \"pets\", \"all\"] as const;\n"),
            "{keys}"
        );
        assert!(keys.contains("    all: apiPetsAll,\n"), "{keys}");
        assert!(keys.contains("    all2: {\n"), "{keys}");
    }

    #[test]
    fn an_override_naming_the_composed_objects_own_member_is_refused_too() {
        // An override value is arbitrary text, so it reaches the reserved member by a route the
        // derived grammar cannot. A configured name is never renamed, and `all` is the one member
        // every node already spends on its own key, so there is nothing to do but refuse.
        let config = format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      pets: all\n");
        let (keys, diagnostics) = keys_for(SHOWCASE, &config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("reserved member reported");
        assert!(refusal.message.contains("'pets'"), "{refusal:?}");
        assert!(!keys.contains("  all2: {\n"), "{keys}");
    }

    #[test]
    fn an_override_resolves_a_segment_whose_own_text_cannot_be_named() {
        // The refusal names a `pathSegments` entry, so that entry has to actually work: the
        // override is consulted before derivation, not after a derivation failure has already
        // bailed out.
        const DASH: &str = r#"
openapi: 3.1.0
info:
  title: Dash
  version: 1.0.0
paths:
  /-/pets:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
"#;
        let config =
            format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      \"-\": dash\n");
        let (keys, diagnostics) = keys_for(DASH, &config);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(keys.contains("export const apiDashPetsAll ="), "{keys}");
    }

    #[test]
    fn an_override_cannot_rescue_an_unnameable_parameter() {
        // An override replaces a segment's *member name*. A parameter still has to become an
        // identifier regardless, because the generated key function takes it positionally — so this
        // stays refused, and the diagnostic names the parameter rather than the segment.
        const UNNAMEABLE_PARAM: &str = r#"
openapi: 3.1.0
info:
  title: Unnameable parameter
  version: 1.0.0
paths:
  /a/{日本}:
    parameters:
      - name: 日本
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readOne
      responses:
        '200':
          description: ok
"#;
        let config = format!(
            "{CONFIG}naming:\n  overrides:\n    pathSegments:\n      \"{{日本}}\": thing\n"
        );
        let (_, diagnostics) = keys_for(UNNAMEABLE_PARAM, &config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("unnameable parameter still refused");
        assert!(refusal.message.contains("path parameter"), "{refusal:?}");
        // The override matched, so it was consulted and deliberately not honoured — not simply
        // missed. Without this the test would pass identically with no override at all.
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_UNMATCHED_SEGMENT_OVERRIDE),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn an_override_rescues_a_mixed_segment_whose_parameter_is_fine() {
        // The segment's own text cannot be named, but its parameter can — so the override supplies
        // the member and the parameter still allocates normally. Refusing this would have made the
        // escape hatch useless for exactly the segments most likely to need it.
        const MIXED: &str = r#"
openapi: 3.1.0
info:
  title: Mixed override
  version: 1.0.0
paths:
  /a/{id}日本:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readOne
      responses:
        '200':
          description: ok
"#;
        let config = format!(
            "{CONFIG}naming:\n  overrides:\n    pathSegments:\n      \"{{id}}日本\": byIdJp\n"
        );
        let (keys, diagnostics) = keys_for(MIXED, &config);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            keys.contains("export const apiAByIdJp = (id: KeyValue | undefined) =>"),
            "{keys}"
        );
    }

    #[test]
    fn a_read_documenting_no_successful_response_says_so() {
        const NO_SUCCESS: &str = r#"
openapi: 3.1.0
info:
  title: No success
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        '404':
          description: gone
          content:
            application/json:
              schema:
                type: object
"#;
        let (files, diagnostics) = emit(NO_SUCCESS, TANSTACK_CONFIG);
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path == "tanstack/operations/listpets.ts")
        );
        let warning = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_INELIGIBLE_QUERY)
            .expect("ineligibility reported");
        // The reason has to be the true one: claiming its responses are bodyless would send a
        // reader looking for a 204 that is not there.
        assert!(
            warning.message.contains("documents no successful response"),
            "{warning:?}"
        );
    }

    /// The read above is refused outright, but a write with the same responses is still emitted —
    /// so it is the mutation side that has to stop unwrapping. `orThrow` is typed `Promise<never>`
    /// there, and `never` has no `.data` (TS2339 in a consumer's build).
    #[test]
    fn a_write_documenting_no_successful_response_keeps_the_awaited_never() {
        const NO_SUCCESS_WRITE: &str = r#"
openapi: 3.1.0
info:
  title: No success
  version: 1.0.0
paths:
  /pets:
    post:
      operationId: createPet
      responses:
        '404':
          description: gone
          content:
            application/json:
              schema:
                type: object
"#;
        let (files, _) = emit(NO_SUCCESS_WRITE, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/createpet.ts");
        assert!(
            module.contains(
                "mutationFn: async (input: CreatePetInput) => (await createPetOrThrow(transport, input, ...args)),"
            ),
            "{module}"
        );
    }

    #[test]
    fn a_binding_shadowing_the_key_factorys_own_import_is_refused() {
        // `keys.ts` type-imports `ParamValue`; a binding of that name would shadow it in the same
        // file (TS2395, then TS1361 when the signature reaches for the type). Only an override can
        // reach one of these names, and an override is never renamed, so the run refuses instead.
        const ROOT_PARAM: &str = r#"
openapi: 3.1.0
info:
  title: Shadow ParamValue
  version: 1.0.0
paths:
  /{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readOne
      responses:
        '200':
          description: ok
"#;
        let config = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: Param\noutput: ./generated\nartifacts:\n  types: true\nnaming:\n  overrides:\n    pathSegments:\n      \"{id}\": Value\n";
        let (keys, diagnostics) = keys_for(ROOT_PARAM, config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("ParamValue shadowing reported");
        assert_eq!(refusal.severity, Severity::Error);
        assert!(refusal.message.contains("'ParamValue'"), "{refusal:?}");
        assert!(!keys.contains("export const ParamValue"), "{keys}");
    }

    #[test]
    fn a_binding_shadowing_an_operations_own_import_is_refused() {
        const TWO_PARAMS: &str = r#"
openapi: 3.1.0
info:
  title: Shadow operation
  version: 1.0.0
paths:
  /{a}/{b}:
    parameters:
      - name: a
        in: path
        required: true
        schema:
          type: string
      - name: b
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readThing
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        // Would bind `readThingOrThrow`, which is exactly what the module imports from the client.
        // Those names are reserved before the walk, and the entry that reached one is named back
        // rather than renamed: a configured name never moves.
        let config = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: read\noutput: ./generated\nartifacts:\n  types: true\n  client: true\n  tanstack: true\nclient:\n  authEnforcement: types\n  baseUrl:\n    source: runtime\nnaming:\n  overrides:\n    pathSegments:\n      \"{a}\": thing\n      \"{b}\": orThrow\nvalidation:\n  engine: 'off'\n  unchecked: allow\n";
        let (files, diagnostics) = emit(TWO_PARAMS, config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("operation-import shadowing reported");
        assert!(refusal.message.contains("'{b}'"), "{refusal:?}");
        assert!(refusal.message.contains("readThingOrThrow"), "{refusal:?}");
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("tanstack/operations/"))
        );
    }

    #[test]
    fn a_binding_shadowing_a_module_import_is_refused() {
        const ROOT_PARAM: &str = r#"
openapi: 3.1.0
info:
  title: Shadow
  version: 1.0.0
paths:
  /{thing}:
    parameters:
      - name: thing
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readThing
      responses:
        '200':
          description: ok
"#;
        let config = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: with\noutput: ./generated\nartifacts:\n  types: true\nnaming:\n  overrides:\n    pathSegments:\n      \"{thing}\": input\n";
        let (keys, diagnostics) = keys_for(ROOT_PARAM, config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("import shadowing reported");
        assert!(refusal.message.contains("'withInput'"), "{refusal:?}");
        assert!(!keys.contains("export const withInput"), "{keys}");
    }

    #[test]
    fn two_paths_reducing_to_one_key_are_refused() {
        const TRAILING_SLASH: &str = r#"
openapi: 3.1.0
info:
  title: Slash
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
  /pets/:
    get:
      operationId: listPetsSlash
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        // `/pets` and `/pets/` are distinct OpenAPI paths and the client builds distinct URLs, but
        // a trailing separator contributes nothing nameable to a key — so without this the two
        // operations would silently share one cache entry and either would serve the other's data.
        let (_, diagnostics) = keys_for(TRAILING_SLASH, CONFIG);
        let collision = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("same-key paths reported");
        assert_eq!(collision.severity, Severity::Error);
        assert!(
            collision.message.contains("'/pets' and '/pets/'"),
            "{collision:?}"
        );
    }

    #[test]
    fn a_read_declaring_a_request_body_keys_it() {
        // Fetch forbids a body on GET, so this operation can never succeed — but two calls that
        // differ only in their body must still not claim to be the same cache entry.
        const GET_WITH_BODY: &str = r#"
openapi: 3.1.0
info:
  title: Read with body
  version: 1.0.0
paths:
  /search:
    get:
      operationId: searchWithBody
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        let (files, _) = emit(GET_WITH_BODY, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/searchwithbody.ts");
        assert!(
            module.contains("queryKey: withInput(apiSearchAll, { body: input.body }),"),
            "{module}"
        );
    }

    #[test]
    fn the_canonical_object_carries_every_declared_non_path_section() {
        let (files, _) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/search.ts");
        assert!(
            module.contains("queryKey: withInput(apiSearchAll, { query: input.query, header: input.header, cookie: input.cookie }),"),
            "{module}"
        );
    }

    #[test]
    fn a_path_only_read_ends_its_key_at_the_path_elements() {
        let (files, _) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/listpets.ts");
        assert!(module.contains("queryKey: apiPetsAll,"), "{module}");
        let mixed = emitted(&files, "tanstack/operations/getmixed.ts");
        assert!(
            mixed.contains("queryKey: apiMixedByIdJson(input.path.id),"),
            "{mixed}"
        );
    }

    #[test]
    fn an_optional_path_parameter_is_guarded_in_query_and_invalidation_keys() {
        const OPTIONAL_PATH: &str = r#"
openapi: 3.1.0
info:
  title: Optional path
  version: 1.0.0
paths:
  /hooks/{id}:
    parameters:
      - name: id
        in: path
        schema:
          type: string
    get:
      operationId: getHook
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: deleteHook
      responses:
        '204':
          description: gone
  /events/{occurredAt}:
    parameters:
      - name: occurredAt
        in: path
        schema:
          type: string
          format: date-time
    get:
      operationId: readEvent
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    put:
      operationId: updateEvent
      responses:
        '204':
          description: updated
"#;
        let config =
            TANSTACK_CONFIG.replace("validation:", "types:\n  dateTime: date\nvalidation:");
        let (files, diagnostics) = emit(OPTIONAL_PATH, &config);

        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(
            keys.contains("export const apiHooksById = (id: KeyValue | undefined) => [\"api\", \"hooks\", id === undefined ? [] : { id }] as const;"),
            "{keys}"
        );

        let query = emitted(&files, "tanstack/operations/gethook.ts");
        assert!(
            query.contains("queryKey: apiHooksById(input.path?.id),"),
            "{query}"
        );
        let mutation = emitted(&files, "tanstack/operations/deletehook.ts");
        assert!(
            mutation.contains("return [apiHooksAll, apiHooksById(input.path?.id)] as const;"),
            "{mutation}"
        );

        let wire_query = emitted(&files, "tanstack/operations/readevent.ts");
        assert!(
            wire_query.contains("queryKey: apiEventsByOccurredAt(wire.path?.occurredAt),"),
            "{wire_query}"
        );
        let wire_mutation = emitted(&files, "tanstack/operations/updateevent.ts");
        assert!(
            wire_mutation.contains(
                "return [apiEventsAll, apiEventsByOccurredAt(wire.path?.occurredAt)] as const;"
            ),
            "{wire_mutation}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn any_bodyless_success_suppresses_its_descriptor_and_warns() {
        let (files, diagnostics) = emit(DOCUMENT, TANSTACK_CONFIG);
        for file in [
            "tanstack/operations/headpet.ts",
            "tanstack/operations/getpartial.ts",
        ] {
            assert!(
                !files.iter().any(|emitted| emitted.relative_path == file),
                "{file} should not be emitted"
            );
        }
        let warnings: Vec<&Diagnostic> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_INELIGIBLE_QUERY)
            .collect();
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(
            warnings
                .iter()
                .all(|warning| warning.severity == Severity::Warning)
        );
        // A bodyless method and a payload union that merely admits undefined are both refused: the
        // second is the case a "at least one branch carries a body" rule would wrongly let through.
        assert!(
            warnings
                .iter()
                .any(|warning| warning.message.contains("headPet")),
            "{warnings:#?}"
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.message.contains("getPartial")),
            "{warnings:#?}"
        );
        let mixed_response_warning = warnings
            .iter()
            .find(|warning| warning.message.contains("getPartial"))
            .expect("mixed response warning");
        assert_eq!(
            mixed_response_warning.message,
            "operation 'getPartial' emits no query descriptor: at least one successful response is bodyless, and a query function may not resolve undefined"
        );
    }

    #[test]
    fn a_collection_mutation_affects_the_collection_alone() {
        let (files, _) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/createpet.ts");
        assert!(
            module.contains("export function createPetMutation<S extends string = never>(transport: Transport<S>, ...args: CreatePetCallArgs<S>)"),
            "{module}"
        );
        assert!(
            module.contains("mutationKey: [\"api\", \"createPet\"] as const,"),
            "{module}"
        );
        // No signal is merged: TanStack supplies none to a mutation function, so the transport is
        // passed through untouched and `withRequestSignal` is never imported.
        assert!(
            module.contains("mutationFn: async (input: CreatePetInput) => (await createPetOrThrow(transport, input, ...args)).data,"),
            "{module}"
        );
        assert!(!module.contains("withRequestSignal"), "{module}");
        assert!(module.contains("return [apiPetsAll] as const;"), "{module}");
        assert!(
            module.contains("export type CreatePetMutationKey ="),
            "{module}"
        );
        assert!(
            module.contains("export type CreatePetMutationData ="),
            "{module}"
        );
        assert!(
            module.contains("export type CreatePetMutationError ="),
            "{module}"
        );
    }

    #[test]
    fn an_entity_mutation_affects_its_collection_then_itself() {
        let (files, _) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/deletepet.ts");
        assert!(
            module.contains("return [apiPetsAll, apiPetsByPetId(input.path.petId)] as const;"),
            "{module}"
        );
    }

    #[test]
    fn two_siblings_binding_one_member_are_disambiguated() {
        // Their flat binding names differ — only the literal segment takes the `All` suffix — so
        // the binding-name allocation cannot see this. The composed object gives them one parent
        // and therefore one object literal, where a duplicate key is TS1117.
        const SIBLINGS: &str = r#"
openapi: 3.1.0
info:
  title: Siblings
  version: 1.0.0
paths:
  /pets/by-id:
    get:
      operationId: listLiteral
      responses:
        '200':
          description: ok
  /pets/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readById
      responses:
        '200':
          description: ok
"#;
        let (keys, diagnostics) = keys_for(SIBLINGS, CONFIG);
        assert!(!renames(&diagnostics).is_empty(), "{diagnostics:#?}");
        assert_eq!(keys.matches("byId: {").count(), 1, "{keys}");
        assert_eq!(keys.matches("byId2: {").count(), 1, "{keys}");
        // The literal sorts before the template, so it is the one that keeps the bare member.
        assert!(
            keys.contains(
                "export const apiPetsByIdAll = [\"api\", \"pets\", \"by-id\"] as const;\n"
            ),
            "{keys}"
        );
    }

    #[test]
    fn a_binding_colliding_with_the_modules_own_factory_is_refused() {
        const ROOT_PARAM: &str = r#"
openapi: 3.1.0
info:
  title: Factory clash
  version: 1.0.0
paths:
  /{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: foo
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        // The module declares `fooQuery` and would import a key binding of the same name.
        let config = "schemaVersion: 1\ninput:\n  path: ./openapi.yaml\nnamespace: foo\noutput: ./generated\nartifacts:\n  types: true\n  client: true\n  tanstack: true\nclient:\n  authEnforcement: types\n  baseUrl:\n    source: runtime\nnaming:\n  overrides:\n    pathSegments:\n      \"{id}\": Query\nvalidation:\n  engine: 'off'\n  unchecked: allow\n";
        let (files, diagnostics) = emit(ROOT_PARAM, config);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("fooQuery")),
            "{diagnostics:#?}"
        );
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("tanstack/operations/"))
        );
    }

    #[test]
    fn a_content_typed_path_parameter_is_admitted_by_the_key_signature() {
        // A `content`-typed parameter carries arbitrary JSON, which the wire-value domain does not
        // admit — the binding signature has to be wider or the descriptor call does not compile.
        const CONTENT: &str = r#"
openapi: 3.1.0
info:
  title: Content parameter
  version: 1.0.0
paths:
  /filters/{filter}:
    parameters:
      - name: filter
        in: path
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                nested:
                  type: object
                  properties:
                    deep:
                      type: string
    get:
      operationId: readFiltered
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        let (keys, diagnostics) = keys_for(CONTENT, CONFIG);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            keys.contains("export type KeyValue = ParamValue |"),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiFiltersByFilter = (filter: KeyValue | undefined) =>"),
            "{keys}"
        );
    }

    #[test]
    fn a_trailing_slash_entity_mutation_still_names_its_collection() {
        // The trailing segment classifies to nothing, so deriving entity-ness from the path's last
        // segment would call this a collection and drop the parent key from the invalidation list.
        const TRAILING: &str = r#"
openapi: 3.1.0
info:
  title: Trailing
  version: 1.0.0
paths:
  /pets/{petId}/:
    parameters:
      - name: petId
        in: path
        required: true
        schema:
          type: string
    delete:
      operationId: deletePet
      responses:
        '204':
          description: gone
"#;
        let (files, _) = emit(TRAILING, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/deletepet.ts");
        assert!(
            module.contains("return [apiPetsAll, apiPetsByPetId(input.path.petId)] as const;"),
            "{module}"
        );
    }

    #[test]
    fn a_nested_entity_mutation_threads_every_ancestor_parameter() {
        let (files, _) = emit(DOCUMENT, TANSTACK_CONFIG);
        let module = emitted(&files, "tanstack/operations/deletetoy.ts");
        assert!(
            module.contains("return [apiPetsByPetIdToysAll(input.path.petId), apiPetsByPetIdToysByToyId(input.path.petId, input.path.toyId)] as const;"),
            "{module}"
        );
    }

    #[test]
    fn the_local_runtime_is_repointed_at_the_configured_runtime_directory() {
        let config = TANSTACK_CONFIG.replace(
            "validation:",
            "emit:\n  runtimeDirectory: kernel\nvalidation:",
        );
        let (files, _) = emit(DOCUMENT, &config);
        let runtime = emitted(&files, "tanstack/runtime.ts");
        assert!(
            runtime.contains("from \"../kernel/transport.js\""),
            "{runtime}"
        );
        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(keys.contains("from \"../kernel/serialize.js\""), "{keys}");
        let module = emitted(&files, "tanstack/operations/getpet.ts");
        assert!(
            module.contains("from \"../../kernel/result.js\""),
            "{module}"
        );
        assert!(
            module.contains("from \"../../kernel/transport.js\""),
            "{module}"
        );
    }

    #[test]
    fn an_extensionless_import_style_reaches_the_local_runtime_too() {
        let config =
            TANSTACK_CONFIG.replace("validation:", "emit:\n  importExtension: none\nvalidation:");
        let (files, _) = emit(DOCUMENT, &config);
        let runtime = emitted(&files, "tanstack/runtime.ts");
        // The repoint runs after the extension rewrite, so a `.ts` suffix must not survive into
        // emitted output under any import style.
        assert!(
            runtime.contains("from \"../runtime/transport\""),
            "{runtime}"
        );
        assert!(!runtime.contains("transport.ts"), "{runtime}");
        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(keys.contains("from \"../runtime/serialize\""), "{keys}");
    }

    #[test]
    fn a_transform_reachable_input_is_encoded_before_it_is_keyed() {
        const DATED: &str = r#"
openapi: 3.1.0
info:
  title: Dated
  version: 1.0.0
paths:
  /events/{occurredAt}:
    parameters:
      - name: occurredAt
        in: path
        required: true
        schema:
          type: string
          format: date-time
    get:
      operationId: readEvent
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    put:
      operationId: updateEvent
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        let config =
            TANSTACK_CONFIG.replace("validation:", "types:\n  dateTime: date\nvalidation:");
        let (files, _) = emit(DATED, &config);

        let query = emitted(&files, "tanstack/operations/readevent.ts");
        assert!(query.contains("import { encodeReadEventInput } from \"../../client/transform/operations/readevent.js\";"), "{query}");
        assert!(
            query.contains("const wire = encodeReadEventInput(input);"),
            "{query}"
        );
        assert!(
            query.contains("queryKey: apiEventsByOccurredAt(wire.path.occurredAt),"),
            "{query}"
        );
        // `orThrow` still takes the application-typed input; the client encodes internally. The
        // descriptor's encode exists only to build the key.
        assert!(
            query
                .contains("readEventOrThrow(withRequestSignal(transport, signal), input, ...args)"),
            "{query}"
        );

        // The invalidation list must encode too, or it would name an entity key holding an
        // application value that no query ever stored.
        let mutation = emitted(&files, "tanstack/operations/updateevent.ts");
        assert!(
            mutation.contains("const wire = encodeUpdateEventInput(input);"),
            "{mutation}"
        );
        assert!(
            mutation.contains(
                "return [apiEventsAll, apiEventsByOccurredAt(wire.path.occurredAt)] as const;"
            ),
            "{mutation}"
        );
    }

    #[test]
    fn a_wire_name_that_is_not_an_identifier_is_bracketed() {
        const ODD: &str = r#"
openapi: 3.1.0
info:
  title: Odd
  version: 1.0.0
paths:
  /things/{thing-id}:
    parameters:
      - name: thing-id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: getThing
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;
        let (files, _) = emit(ODD, TANSTACK_CONFIG);
        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(
            keys.contains(
                "(thingId: KeyValue | undefined) => [\"api\", \"things\", thingId === undefined ? [] : { \"thing-id\": thingId }] as const"
            ),
            "{keys}"
        );
        let module = emitted(&files, "tanstack/operations/getthing.ts");
        assert!(
            module.contains("apiThingsByThingId(input.path[\"thing-id\"])"),
            "{module}"
        );
    }
    #[test]
    fn a_document_with_no_operations_still_emits_a_key_factory() {
        const SCHEMAS_ONLY: &str = "openapi: 3.1.0\ninfo:\n  title: Empty\n  version: 1.0.0\npaths: {}\ncomponents:\n  schemas:\n    Pet:\n      type: object\n";
        let (keys, diagnostics) = keys_for(SCHEMAS_ONLY, CONFIG);
        assert!(
            keys.contains("export const apiAll = [\"api\"] as const;"),
            "{keys}"
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn the_root_path_contributes_no_segment_of_its_own() {
        const ROOT: &str = r#"
openapi: 3.1.0
info:
  title: Root
  version: 1.0.0
paths:
  /:
    get:
      operationId: getRoot
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: deleteRoot
      responses:
        '204':
          description: gone
"#;
        let (files, diagnostics) = emit(ROOT, TANSTACK_CONFIG);
        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(
            keys.contains("export const apiAll = [\"api\"] as const;"),
            "{keys}"
        );
        let query = emitted(&files, "tanstack/operations/getroot.ts");
        assert!(query.contains("queryKey: apiAll,"), "{query}");
        // A mutation at the root has no parent collection above it, so its list is the root alone.
        let mutation = emitted(&files, "tanstack/operations/deleteroot.ts");
        assert!(mutation.contains("return [apiAll] as const;"), "{mutation}");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_segment_that_cannot_be_named_is_refused_and_names_the_override() {
        // Latin accents survive normalization (NFKD strips the mark), so the refusals need text
        // that does not: a script with no ASCII form, and a segment with no alphanumerics at all.
        const NON_ASCII: &str = r#"
openapi: 3.1.0
info:
  title: Unnameable
  version: 1.0.0
paths:
  /日本:
    get:
      operationId: readOne
      responses:
        '200':
          description: ok
  /---:
    get:
      operationId: readTwo
      responses:
        '200':
          description: ok
"#;
        let (_, diagnostics) = keys_for(NON_ASCII, CONFIG);
        let refusals: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .collect();
        assert_eq!(refusals.len(), 2, "{refusals:#?}");
        assert!(
            refusals
                .iter()
                .any(|refusal| refusal.message.contains("non-ASCII"))
        );
        assert!(
            refusals
                .iter()
                .any(|refusal| refusal.message.contains("empty identifier"))
        );
        assert!(
            refusals
                .iter()
                .all(|refusal| refusal.message.contains("naming.overrides.pathSegments")),
            "{refusals:#?}"
        );
    }

    #[test]
    fn an_unnameable_parameter_and_mixed_segment_are_refused_too() {
        const NON_ASCII: &str = r#"
openapi: 3.1.0
info:
  title: Unnameable parameters
  version: 1.0.0
paths:
  /a/{日本}:
    parameters:
      - name: 日本
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readOne
      responses:
        '200':
          description: ok
  /b/{id}日本:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readTwo
      responses:
        '200':
          description: ok
"#;
        let (_, diagnostics) = keys_for(NON_ASCII, CONFIG);
        let refusals: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .collect();
        assert_eq!(refusals.len(), 2, "{refusals:#?}");
        assert!(
            refusals
                .iter()
                .all(|refusal| refusal.message.contains("not a usable name"))
        );
    }

    #[test]
    fn one_path_declaring_the_same_parameter_twice_takes_it_once() {
        const REPEATED: &str = r#"
openapi: 3.1.0
info:
  title: Repeated
  version: 1.0.0
paths:
  /a/{id}/b/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readRepeated
      responses:
        '200':
          description: ok
"#;
        // The client substitutes the one declared `id` into both occurrences, so a key factory
        // taking two arguments could name a request the client cannot make. One argument, read
        // back by wire name at both elements, is what matches.
        let (keys, diagnostics) = keys_for(REPEATED, CONFIG);
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
        assert!(
            keys.contains(
                "export const apiAByIdBById = (id: KeyValue | undefined) => [\"api\", \"a\", id === undefined ? [] : { id }, \"b\", id === undefined ? [] : { id }] as const;\n"
            ),
            "{keys}"
        );
    }

    #[test]
    fn two_configured_members_under_one_parent_are_refused() {
        // Neither is compiler-invented, so neither yields — this is a collision between two things
        // the configuration declares, and the diagnostic names both entries.
        const SIBLINGS: &str = r#"
openapi: 3.1.0
info:
  title: Two entries
  version: 1.0.0
paths:
  /alpha:
    get:
      operationId: readAlpha
      responses:
        '200':
          description: ok
  /beta:
    get:
      operationId: readBeta
      responses:
        '200':
          description: ok
"#;
        let config = format!(
            "{CONFIG}naming:\n  overrides:\n    pathSegments:\n      alpha: same\n      beta: same\n"
        );
        let (keys, diagnostics) = keys_for(SIBLINGS, &config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("two entries binding one member reported");
        assert_eq!(refusal.severity, Severity::Error);
        assert!(
            refusal.message.contains("'alpha' and 'beta'") && refusal.message.contains("'same'"),
            "{refusal:?}"
        );
        // The first entry keeps what it asked for; the second names nothing at all.
        assert_eq!(keys.matches("same: {").count(), 1, "{keys}");
    }

    #[test]
    fn two_configured_nodes_composing_one_binding_name_are_refused() {
        // The members differ and sit under different parents, so the member layer cannot see this.
        // `/p/q` composes `apiPRAll` from two members and `/pq` composes it from one.
        const CROSS_DEPTH: &str = r#"
openapi: 3.1.0
info:
  title: Two entries, one binding
  version: 1.0.0
paths:
  /p/q:
    get:
      operationId: readNested
      responses:
        '200':
          description: ok
  /pq:
    get:
      operationId: readFlat
      responses:
        '200':
          description: ok
"#;
        let config =
            format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      q: r\n      pq: pR\n");
        let (keys, diagnostics) = keys_for(CROSS_DEPTH, &config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("two entries binding one name reported");
        assert!(
            refusal.message.contains("'q' and 'pq'") && refusal.message.contains("'apiPRAll'"),
            "{refusal:?}"
        );
        assert_eq!(keys.matches("export const apiPRAll").count(), 1, "{keys}");
    }

    #[test]
    fn one_entry_reaching_two_branches_names_the_segment_that_separates_them() {
        // `pathSegments` is keyed by raw segment text globally, so the single `x` entry names the
        // last segment of both paths and cannot rename one of them. The refusal has to point at
        // the segment where the two addresses diverge, which is the only one that tells them apart.
        const SHARED: &str = r#"
openapi: 3.1.0
info:
  title: One entry, two branches
  version: 1.0.0
paths:
  /foo/bar/x:
    get:
      operationId: readNested
      responses:
        '200':
          description: ok
  /foo-bar/x:
    get:
      operationId: readFlat
      responses:
        '200':
          description: ok
"#;
        let config = format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      x: common\n");
        let (keys, diagnostics) = keys_for(SHARED, &config);
        let refusal = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION)
            .expect("one entry reaching two branches reported");
        assert_eq!(refusal.severity, Severity::Error);
        assert!(
            refusal.message.contains(
                "naming.overrides.pathSegments key 'x' names the segment in both '/foo/bar/x' and '/foo-bar/x'"
            ),
            "{refusal:?}"
        );
        // The entry that cannot separate them must not be the one the message asks the reader to
        // change; the divergent segment is.
        assert!(
            refusal
                .message
                .contains("`naming.overrides.pathSegments: { \"foo-bar\": \"<distinctName>\" }`"),
            "{refusal:?}"
        );
        assert!(!refusal.message.contains("keys 'x' and 'x'"), "{refusal:?}");
        // The first branch keeps the name it asked for; the second binds nothing.
        assert_eq!(
            keys.matches("export const apiFooBarCommonAll").count(),
            1,
            "{keys}"
        );
    }

    #[test]
    fn a_derived_binding_landing_on_an_operations_own_import_yields() {
        // No override is involved: `/foo/{query}` composes `apiFooByQuery`, and an operation whose
        // allocated name is `apiFooBy` makes its module declare that exact identifier. The derived
        // binding is compiler-invented on both sides of the race, so it moves and warns.
        const RESERVED: &str = r#"
openapi: 3.1.0
info:
  title: Derived onto a module name
  version: 1.0.0
paths:
  /foo/{query}:
    parameters:
      - name: query
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readFoo
      responses:
        '200':
          description: ok
  /other:
    get:
      operationId: apiFooBy
      responses:
        '200':
          description: ok
"#;
        let (keys, diagnostics) = keys_for(RESERVED, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains(
                "key binding 'apiFooByQuery' for path '/foo/{query}' is an identifier the generated modules already bind"
            ),
            "{warnings:#?}"
        );
        assert!(
            keys.contains("export const apiFooByQuery2 = (query: KeyValue | undefined)"),
            "{keys}"
        );
    }

    #[test]
    fn a_configured_member_never_yields_to_a_derived_sibling() {
        // `/foo-bar` derives `fooBar`, and the override asks for `fooBar` on `/foo_bar`. The
        // document owns the name it chose, so the derived sibling is the one that moves.
        let config =
            format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      foo_bar: fooBar\n");
        let (keys, diagnostics) = keys_for(COLLIDING, &config);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains("path segment 'foo-bar'"),
            "{warnings:#?}"
        );
        assert!(
            keys.contains("export const apiFooBarAll = [\"api\", \"foo_bar\"] as const;\n"),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiFooBar2All = [\"api\", \"foo-bar\"] as const;\n"),
            "{keys}"
        );
    }

    #[test]
    fn a_digit_led_member_that_erases_its_own_boundary_still_gets_a_name() {
        // `uppercase_first` uppercases the first ASCII letter anywhere in the member, so a member
        // that begins with digits leaves no boundary in the concatenation: `/v2/foo` and `/v/2foo`
        // both compose `apiV2FooAll`. Reachable only because a digit-led member is nameable at all,
        // and answered by the same allocation as any other flat-name race.
        const ERASED: &str = r#"
openapi: 3.1.0
info:
  title: Erased boundary
  version: 1.0.0
paths:
  /v2/foo:
    get:
      operationId: readVersioned
      responses:
        '200':
          description: ok
  /v/2foo:
    get:
      operationId: readSplit
      responses:
        '200':
          description: ok
"#;
        let (keys, diagnostics) = keys_for(ERASED, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            keys.contains("export const apiV2FooAll = [\"api\", \"v\", \"2foo\"] as const;\n"),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiV2FooAll2 = [\"api\", \"v2\", \"foo\"] as const;\n"),
            "{keys}"
        );
    }

    #[test]
    fn two_parameters_normalizing_to_one_argument_name_stay_two_arguments() {
        // `{user_id}` and `{userId}` are two declared parameters that derive one identifier. Unlike
        // a repeated parameter they cannot share an argument, so the second takes a suffix — and
        // each element still keys under its own wire name.
        const TWO_WIRES: &str = r#"
openapi: 3.1.0
info:
  title: Two wires
  version: 1.0.0
paths:
  /tenants/{user_id}/sites/{userId}:
    parameters:
      - name: user_id
        in: path
        required: true
        schema:
          type: string
      - name: userId
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readSite
      responses:
        '200':
          description: ok
"#;
        let (keys, diagnostics) = keys_for(TWO_WIRES, CONFIG);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains("path parameter 'userId' derives the argument name 'userId'")
                && warnings[0].contains("emitting it as 'userId2'"),
            "{warnings:#?}"
        );
        assert!(
            keys.contains(
                "export const apiTenantsByUserIdSitesByUserId = (userId: KeyValue | undefined, userId2: KeyValue | undefined) => [\"api\", \"tenants\", userId === undefined ? [] : { user_id: userId }, \"sites\", userId2 === undefined ? [] : { userId: userId2 }] as const;\n"
            ),
            "{keys}"
        );
    }

    #[test]
    fn an_override_can_make_a_child_take_its_own_ancestors_name() {
        // `/foo` binds `apiFooAll`. `/foo/{x}` normally binds `apiFooByX`, but an override naming
        // the parameter segment `all` makes it bind `apiFooAll` too. The configured descendant
        // claims the name and the derived ancestor is what moves. Neither address diverges from the
        // other — one is a prefix of it — so there is no entry to suggest, and the message must not
        // invent one.
        const NESTED: &str = r#"
openapi: 3.1.0
info:
  title: Ancestor
  version: 1.0.0
paths:
  /foo:
    get:
      operationId: readFoo
      responses:
        '200':
          description: ok
  /foo/{x}:
    parameters:
      - name: x
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readFooX
      responses:
        '200':
          description: ok
"#;
        let config =
            format!("{CONFIG}naming:\n  overrides:\n    pathSegments:\n      \"{{x}}\": All\n");
        let (keys, diagnostics) = keys_for(NESTED, &config);
        let warnings = renames(&diagnostics);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(
            warnings[0].contains(
                "key binding 'apiFooAll' for path '/foo' is already bound by path '/foo/{x}'"
            ),
            "{warnings:#?}"
        );
        assert!(
            !warnings[0].contains("naming.overrides.pathSegments:"),
            "{warnings:#?}"
        );
        assert!(
            keys.contains(
                "export const apiFooAll = (x: KeyValue | undefined) => [\"api\", \"foo\", x === undefined ? [] : { x }] as const;\n"
            ),
            "{keys}"
        );
        assert!(
            keys.contains("export const apiFooAll2 = [\"api\", \"foo\"] as const;\n"),
            "{keys}"
        );
    }

    #[test]
    fn an_operation_whose_key_binding_was_dropped_emits_no_module() {
        // A segment with no usable name is the residue nothing can allocate around, so its subtree
        // gets no binding at all — and an operation there has no key to name.
        const COLLIDING_OPS: &str = r#"
openapi: 3.1.0
info:
  title: Unnameable subtree
  version: 1.0.0
paths:
  /foo-bar/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readHyphenated
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: deleteHyphenated
      responses:
        '204':
          description: gone
  /日本/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: readUnderscored
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: deleteUnderscored
      responses:
        '204':
          description: gone
"#;
        let (files, diagnostics) = emit(COLLIDING_OPS, TANSTACK_CONFIG);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_SEGMENT_COLLISION),
            "{diagnostics:#?}"
        );
        // The nameable path keeps its bindings; the other has none, so neither its query nor its
        // mutation can name a key and neither module is emitted.
        assert!(
            files
                .iter()
                .any(|file| file.relative_path == "tanstack/operations/readhyphenated.ts")
        );
        for dropped in [
            "tanstack/operations/readunderscored.ts",
            "tanstack/operations/deleteunderscored.ts",
        ] {
            assert!(
                !files.iter().any(|file| file.relative_path == dropped),
                "{dropped} should not be emitted"
            );
        }
        // The composed object still renders, skipping the node whose binding was refused.
        let keys = emitted(&files, "tanstack/keys.ts");
        assert!(keys.contains("export const keys = "), "{keys}");
    }

    #[test]
    fn an_operation_whose_name_or_file_could_not_be_allocated_is_skipped() {
        const UNNAMEABLE: &str = r#"
openapi: 3.1.0
info:
  title: Unnameable
  version: 1.0.0
paths:
  /pets:
    get:
      operationId: 日本
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
    delete:
      operationId: con
      responses:
        '204':
          description: gone
"#;
        let (files, _) = emit(UNNAMEABLE, TANSTACK_CONFIG);
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("tanstack/operations/")),
            "neither operation can be named, so neither emits a descriptor"
        );
    }

    #[test]
    fn a_streaming_operation_gets_no_descriptor_on_either_the_read_or_the_write_path() {
        const STREAMING: &str = r#"
openapi: 3.1.0
info:
  title: Streaming
  version: 1.0.0
paths:
  /ticks:
    get:
      operationId: watchTicks
      responses:
        '200':
          description: a stream of ticks
          content:
            text/event-stream:
              schema:
                type: string
  /upload:
    post:
      operationId: uploadBlob
      requestBody:
        required: true
        content:
          application/octet-stream:
            x-oasts-streaming: true
      responses:
        '204':
          description: accepted
  /either:
    post:
      operationId: publishEither
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
          text/event-stream:
            schema:
              type: object
      responses:
        '204':
          description: accepted
"#;
        let (files, diagnostics) = emit(STREAMING, TANSTACK_CONFIG);
        assert!(
            !files
                .iter()
                .any(|file| file.relative_path.starts_with("tanstack/operations/")),
            "neither side may emit a descriptor"
        );

        let reasons = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_INELIGIBLE_QUERY)
            .map(|diagnostic| {
                // A refusal here must not discard the rest of the generated document, so the
                // severity is as much the contract as the message is.
                assert_eq!(diagnostic.severity, crate::diag::Severity::Warning);
                diagnostic.message.clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(reasons.len(), 3, "{reasons:?}");
        // The read side: a stream handle is drained by its first cache reader, so caching one hands
        // every later reader an exhausted iterable.
        assert!(
            reasons.iter().any(|reason| reason.contains("watchTicks")
                && reason.contains("it responds with a stream")),
            "{reasons:?}"
        );
        // The write side is refused for the mirror reason, which is why the check runs before the
        // query/mutation split: a retried mutation would resend an already-consumed body.
        assert!(
            reasons.iter().any(|reason| reason.contains("uploadBlob")
                && reason.contains("its request body can be a stream")),
            "{reasons:?}"
        );
        // A body offering one streaming media beside a buffered one is refused on the same ground:
        // the caller picks the arm at the call site, so the descriptor cannot know it got the
        // buffered one, and a retry of the streaming arm resends an exhausted body.
        assert!(
            reasons.iter().any(|reason| reason.contains("publishEither")
                && reason.contains("its request body can be a stream")),
            "{reasons:?}"
        );
    }
}
