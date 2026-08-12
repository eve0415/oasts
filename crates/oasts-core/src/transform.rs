//! Which schemas reach a date/time transform under the resolved configuration.
//!
//! A schema that reaches no transform site gets no wire twin, no encode/decode pair, and every
//! reference to it stays identity — exactly as it is today with `types.dateTime` and `types.date`
//! at their `string` defaults. Emitting a twin for every schema regardless would double the
//! declaration set and the transform-function count on documents with no date anywhere, spending
//! the typecheck and client-size budgets for nothing, so reachability is computed first and the
//! emitters ask it.

use foldhash::HashMap;
use serde_json::Value;

use crate::config::{
    DateRepresentation, DateTimeRepresentation, IntegerRepresentation, ResolvedConfig,
};
use crate::ir::{AdditionalProperties, Ir, PrimitiveType, SchemaNode, TupleRest};

/// The codec a transform site is compiled against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformKind {
    /// `format: date-time` under `types.dateTime: date` — a JavaScript `Date`.
    DateTimeDate,
    /// `format: date-time` under `types.dateTime: temporal` — a `Temporal.Instant`.
    DateTimeInstant,
    /// `format: date` under `types.date: temporal` — a `Temporal.PlainDate`.
    DatePlainDate,
    /// `format: int64` under `types.integer: bigint` — a JavaScript `bigint`.
    IntegerBigInt,
}

impl TransformKind {
    /// The TypeScript type the application surface names for this codec.
    #[must_use]
    pub const fn ts_type(self) -> &'static str {
        match self {
            Self::DateTimeDate => "Date",
            Self::DateTimeInstant => "Temporal.Instant",
            Self::DatePlainDate => "Temporal.PlainDate",
            Self::IntegerBigInt => "bigint",
        }
    }
}

/// One structural pass's findings for a node: whether the node itself contains a transform site
/// without following a `$ref`, and every component index it references.
#[derive(Default)]
struct Scan {
    direct: bool,
    deps: Vec<usize>,
}

/// The set of JSON value kinds a schema admits, as a bit set.
///
/// This is what tier-1 union dispatch tests: when a converting branch admits a kind no sibling
/// admits, the wire value's own kind selects the branch, with no declared discriminator needed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JsonKinds(u8);

impl JsonKinds {
    pub const EMPTY: Self = Self(0);
    pub const NULL: Self = Self(1);
    pub const BOOLEAN: Self = Self(2);
    pub const NUMBER: Self = Self(4);
    pub const STRING: Self = Self(8);
    pub const ARRAY: Self = Self(16);
    pub const OBJECT: Self = Self(32);
    /// Every kind: what a boolean `true` schema, a degraded leaf, or an unresolvable reference
    /// admits. Disjoint from nothing, so a union containing one can never dispatch on kind.
    pub const ANY: Self = Self(63);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[must_use]
    pub const fn is_disjoint(self, other: Self) -> bool {
        self.0 & other.0 == 0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }
}

/// One branch of a kind-dispatched union.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KindBranch {
    /// Position in the union's declared branch list.
    pub index: usize,
    /// The kinds selecting this branch. Disjoint from every differently-converting sibling's.
    pub kinds: JsonKinds,
    /// Whether reaching this branch runs a conversion at all; a `false` branch is passed through.
    pub converts: bool,
}

/// How a `oneOf`/`anyOf` selects the conversion to apply to a wire value.
///
/// Ordered try-each-branch decoding is deliberately not an option: a non-converting branch always
/// "succeeds" by identity, so declaration order would silently decide the result and a wrong-branch
/// decode would be undetectable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnionDispatch {
    /// No branch converts, so every reference to the union stays identity.
    Identity,
    /// The wire value's own JSON kind selects the branch.
    Kind(Vec<KindBranch>),
    /// Every branch converts identically, so one conversion applies with no dispatch at all.
    Shared,
    /// Two branches convert differently and no JSON kind separates them. The emit layer tries the
    /// declared discriminator next and, failing that, refuses the document — the two remedies are
    /// declaring a `discriminator` or setting the representation back to `string`.
    Indistinguishable { left: usize, right: usize },
}

/// One conversion a node performs, at a path within that node.
///
/// Compared, never rendered: two branches "convert identically" exactly when their conversion lists
/// are equal. A `$ref` is opaque — the referenced component is converted by its own emitted pair, so
/// two refs to different components are two different calls however alike the components look.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Conversion {
    Site(TransformKind),
    Component(usize),
    /// A nested union: its dispatch AND what each of its branches converts. The dispatch alone does
    /// not identify the conversions — two `anyOf: [X, null]` nodes over different components produce
    /// the same kind dispatch — so comparing dispatches only would call two outer branches identical
    /// and apply one branch's conversion to the other's value.
    Union(Box<UnionDispatch>, Vec<Conversions>),
}

/// One step from a node's root to a value it converts. Carries no rendering meaning; it exists so
/// two branches converting at different places compare unequal.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Step {
    /// Requiredness is part of the step, not decoration: two branches converting the same property
    /// emit different code when one of them permits it to be omitted, so a profile that ignored it
    /// would call them interchangeable and let branch order decide which one is emitted.
    Property {
        name: String,
        required: bool,
    },
    Items,
    Index(usize),
    AdditionalProperties,
    Branch(usize),
}

type Conversions = Vec<(Vec<Step>, Conversion)>;

/// Per-schema transform reachability for one compile.
///
/// Borrows the `Ir` it describes rather than taking it per call: resolving a `$ref` to its target
/// node is needed by more than one question here, and a borrow makes answering them about a
/// different document impossible.
pub struct TransformFacts<'ir> {
    ir: &'ir Ir,
    /// Parallel to `ir.schemas`: whether the component transitively reaches a transform site.
    components: Vec<bool>,
    /// `(source_id, json_pointer)` to component index. Mirrors the emitter's target allocation,
    /// which is likewise keyed by each component's own source, so a `$ref` this map misses is
    /// exactly a `$ref` the emitter would render as `unknown`.
    by_pointer: HashMap<(&'ir str, &'ir str), usize>,
    date_time: DateTimeRepresentation,
    date: DateRepresentation,
    integer: IntegerRepresentation,
}

impl<'ir> TransformFacts<'ir> {
    /// Computes reachability for every component, then leaves inline nodes to be asked directly.
    ///
    /// Component reachability is a worklist over the `$ref` graph rather than a recursive walk:
    /// recursive and mutually recursive schemas are ordinary in real documents, and following refs
    /// during the walk would not terminate on them. Each component is scanned once for its own
    /// sites and its outgoing refs; reachability then propagates along the reversed edges, so the
    /// whole fixed point costs one pass over the schemas plus one over the edges.
    #[must_use]
    pub fn compute(ir: &'ir Ir, config: &ResolvedConfig) -> Self {
        let mut facts = Self {
            ir,
            components: vec![false; ir.schemas.len()],
            by_pointer: ir
                .schemas
                .iter()
                .enumerate()
                .map(|(index, schema)| {
                    (
                        (
                            schema.source.source_id.as_str(),
                            schema.source.json_pointer.as_str(),
                        ),
                        index,
                    )
                })
                .collect(),
            date_time: config.types.date_time,
            date: config.types.date,
            integer: config.types.integer,
        };
        if !facts.enabled() {
            return facts;
        }
        let scans = ir
            .schemas
            .iter()
            .map(|schema| {
                let mut scan = Scan::default();
                facts.scan(&schema.schema, &mut scan);
                scan
            })
            .collect::<Vec<_>>();
        let mut referrers = vec![Vec::new(); ir.schemas.len()];
        for (index, scan) in scans.iter().enumerate() {
            for &dep in &scan.deps {
                referrers[dep].push(index);
            }
        }
        let mut queue = Vec::new();
        for (index, scan) in scans.iter().enumerate() {
            if scan.direct {
                facts.components[index] = true;
                queue.push(index);
            }
        }
        while let Some(index) = queue.pop() {
            for &referrer in &referrers[index] {
                if !facts.components[referrer] {
                    facts.components[referrer] = true;
                    queue.push(referrer);
                }
            }
        }
        facts
    }

    /// Whether any representation converts. False is the default and the byte-for-byte-unchanged
    /// path.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.date_time != DateTimeRepresentation::String
            || self.date != DateRepresentation::String
            || self.integer != IntegerRepresentation::Number
    }

    /// Whether any schema in the document reaches a transform.
    #[must_use]
    pub fn any(&self) -> bool {
        self.components.iter().any(|&transforms| transforms)
    }

    /// Whether the component at `index` transitively reaches a transform site.
    #[must_use]
    pub fn component(&self, index: usize) -> bool {
        self.components.get(index).copied().unwrap_or(false)
    }

    /// Whether this node — component root or inline — transitively reaches a transform site.
    #[must_use]
    pub fn reaches(&self, node: &SchemaNode) -> bool {
        if !self.enabled() {
            return false;
        }
        let mut scan = Scan::default();
        self.scan(node, &mut scan);
        scan.direct || scan.deps.iter().any(|&dep| self.components[dep])
    }

    /// Whether this node reaches at least one site of exactly `kind`, following component refs.
    #[must_use]
    pub fn reaches_kind(&self, node: &SchemaNode, kind: TransformKind) -> bool {
        self.enabled() && self.reaches_kind_inner(node, kind, &mut Vec::new())
    }

    fn reaches_kind_inner(
        &self,
        node: &SchemaNode,
        kind: TransformKind,
        visiting: &mut Vec<usize>,
    ) -> bool {
        if self.site(node) == Some(kind) {
            return true;
        }
        match node {
            SchemaNode::Ref { target, .. } => {
                let Some(&index) = self
                    .by_pointer
                    .get(&(target.source_id.as_str(), target.json_pointer.as_str()))
                else {
                    return false;
                };
                if visiting.contains(&index) {
                    return false;
                }
                visiting.push(index);
                let reaches =
                    self.reaches_kind_inner(&self.ir.schemas[index].schema, kind, visiting);
                visiting.pop();
                reaches
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                meta,
                ..
            } => {
                properties
                    .iter()
                    .any(|(_, property, _)| self.reaches_kind_inner(property, kind, visiting))
                    || match additional_properties {
                        AdditionalProperties::Allowed(Some(schema))
                        | AdditionalProperties::Schema(schema) => {
                            self.reaches_kind_inner(schema, kind, visiting)
                        }
                        AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => {
                            false
                        }
                    }
                    || meta
                        .validation_applicators()
                        .pattern_properties
                        .iter()
                        .any(|pattern| {
                            pattern.type_key.is_some()
                                && self.reaches_kind_inner(&pattern.schema, kind, visiting)
                        })
            }
            SchemaNode::Array { items, .. } => self.reaches_kind_inner(items, kind, visiting),
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                prefix_items
                    .iter()
                    .any(|item| self.reaches_kind_inner(item, kind, visiting))
                    || match rest {
                        TupleRest::Schema(schema) => {
                            self.reaches_kind_inner(schema, kind, visiting)
                        }
                        TupleRest::Allowed | TupleRest::Forbidden => false,
                    }
            }
            SchemaNode::AllOf { branches, .. }
            | SchemaNode::OneOf { branches, .. }
            | SchemaNode::AnyOf { branches, .. } => branches
                .iter()
                .any(|branch| self.reaches_kind_inner(branch, kind, visiting)),
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => false,
        }
    }

    /// The codec this node is a transform site for, or `None` when it is not one.
    ///
    /// A date site is a plain formatted string; an integer site is specifically `format: int64`.
    /// A `format: date-time` on `type: integer` is not one: the format annotates a value the type
    /// says is not a string. Nor is a primitive carrying an `enum` or `const` — that is a literal
    /// union, strictly more precise than the representation type, and collapsing it would lose
    /// information the caller already has. Note this is the `Primitive` arm, not `Finite`: a typed
    /// enum parses to `Primitive` carrying `enum_values`, and `Finite` is only ever the typeless
    /// enum/const node.
    #[must_use]
    pub fn site(&self, node: &SchemaNode) -> Option<TransformKind> {
        match node {
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                format: Some(format),
                enum_values: None,
                const_value: None,
                ..
            } => match format.as_str() {
                "date-time" => match self.date_time {
                    DateTimeRepresentation::String => None,
                    DateTimeRepresentation::Date => Some(TransformKind::DateTimeDate),
                    DateTimeRepresentation::Temporal => Some(TransformKind::DateTimeInstant),
                },
                // RFC 3339 full-time carries a mandatory offset that no Temporal.PlainTime or Date
                // can represent, so format: time is a wire and application string under every
                // setting.
                "date" => match self.date {
                    DateRepresentation::String => None,
                    DateRepresentation::Temporal => Some(TransformKind::DatePlainDate),
                },
                _ => None,
            },
            SchemaNode::Primitive {
                ty: PrimitiveType::Integer,
                format: Some(format),
                enum_values: None,
                const_value: None,
                ..
            } if format == "int64" && self.integer == IntegerRepresentation::Bigint => {
                Some(TransformKind::IntegerBigInt)
            }
            _ => None,
        }
    }

    /// How this `oneOf`/`anyOf` selects the conversion to apply, or `None` when the node is not one.
    ///
    /// `allOf` needs no dispatch: its branches merge into one value, so the conversion is the union
    /// of the branches' conversions rather than a choice between them.
    #[must_use]
    pub fn union_dispatch(&self, node: &SchemaNode) -> Option<UnionDispatch> {
        let branches = match node {
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => branches,
            _ => return None,
        };
        Some(self.branch_dispatch(branches))
    }

    /// How a union over exactly these branches selects its conversion. Callers holding the branches
    /// already — the emit layer, which needs the declared discriminator beside them — read this
    /// rather than re-matching the node.
    #[must_use]
    pub fn branch_dispatch(&self, branches: &[SchemaNode]) -> UnionDispatch {
        if !self.enabled() {
            return UnionDispatch::Identity;
        }
        self.classify_branches(branches).0
    }

    /// The dispatch plus each branch's conversions, so a caller comparing two unions can compare both
    /// without recomputing either.
    fn classify_branches(&self, branches: &[SchemaNode]) -> (UnionDispatch, Vec<Conversions>) {
        let profiles = branches
            .iter()
            .map(|branch| {
                (
                    self.kinds(branch, &mut Vec::new()),
                    self.conversions(branch),
                )
            })
            .collect::<Vec<_>>();
        let per_branch = || {
            profiles
                .iter()
                .map(|(_, conversions)| conversions.clone())
                .collect::<Vec<_>>()
        };
        if profiles
            .iter()
            .all(|(_, conversions)| conversions.is_empty())
        {
            return (UnionDispatch::Identity, per_branch());
        }

        // Every branch converting identically needs no dispatch at all — whichever branch the value
        // came from, the same conversion applies. Checked before the kind test because those
        // branches typically share a kind, which would otherwise produce a `Kind` dispatch whose
        // branches are indistinguishable by kind and so decide nothing.
        if profiles
            .iter()
            .all(|(_, conversions)| *conversions == profiles[0].1)
        {
            return (UnionDispatch::Shared, per_branch());
        }

        // Tier 1: the wire value's kind selects the branch, provided no two branches that convert
        // differently share a kind. Branches converting identically may overlap freely — whichever
        // the value came from, the same conversion applies.
        let mut collision = None;
        'pairs: for (left, (left_kinds, left_conversions)) in profiles.iter().enumerate() {
            for (right, (right_kinds, right_conversions)) in
                profiles.iter().enumerate().skip(left + 1)
            {
                if left_conversions != right_conversions && !left_kinds.is_disjoint(*right_kinds) {
                    collision = Some((left, right));
                    break 'pairs;
                }
            }
        }
        let Some((left, right)) = collision else {
            let branches = profiles
                .iter()
                .enumerate()
                .map(|(index, (kinds, conversions))| KindBranch {
                    index,
                    kinds: *kinds,
                    converts: !conversions.is_empty(),
                })
                .collect();
            return (UnionDispatch::Kind(branches), per_branch());
        };

        (
            UnionDispatch::Indistinguishable { left, right },
            per_branch(),
        )
    }

    /// The JSON value kinds this node admits.
    ///
    /// `meta.nullable` is read at every node, not just at `type: null` branches: the OpenAPI 3.0
    /// keyword makes a branch admit `null` without a `null` type anywhere in the union, so a kind set
    /// read off the declared type alone would call two overlapping branches disjoint.
    fn kinds(&self, node: &SchemaNode, visiting: &mut Vec<usize>) -> JsonKinds {
        let nullable = if node.meta().nullable {
            JsonKinds::NULL
        } else {
            JsonKinds::EMPTY
        };
        let declared = match node {
            SchemaNode::Ref { target, .. } => {
                let resolved = self
                    .by_pointer
                    .get(&(target.source_id.as_str(), target.json_pointer.as_str()));
                // A cycle and an unresolvable reference are both uncharacterized, and the safe answer
                // for a disjointness test is "admits everything" — never the empty set, which would
                // read as vacuously disjoint and pick a dispatch that does not discriminate.
                match resolved {
                    Some(&index) if !visiting.contains(&index) => {
                        visiting.push(index);
                        let kinds = self.kinds(&self.ir.schemas[index].schema, visiting);
                        visiting.pop();
                        kinds
                    }
                    _ => JsonKinds::ANY,
                }
            }
            SchemaNode::Primitive { ty, .. } => match ty {
                PrimitiveType::String => JsonKinds::STRING,
                PrimitiveType::Number | PrimitiveType::Integer => JsonKinds::NUMBER,
                PrimitiveType::Boolean => JsonKinds::BOOLEAN,
                PrimitiveType::Null => JsonKinds::NULL,
            },
            SchemaNode::Finite {
                enum_values,
                const_value,
                ..
            } => finite_kinds(enum_values.as_deref(), const_value.as_ref()),
            SchemaNode::Object { .. } => JsonKinds::OBJECT,
            SchemaNode::Array { .. } | SchemaNode::Tuple { .. } => JsonKinds::ARRAY,
            // allOf branches all apply to the same value, so only kinds every branch admits survive.
            SchemaNode::AllOf { branches, .. } => {
                branches.iter().fold(JsonKinds::ANY, |kinds, branch| {
                    kinds.intersect(self.kinds(branch, visiting))
                })
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                branches.iter().fold(JsonKinds::EMPTY, |kinds, branch| {
                    kinds.union(self.kinds(branch, visiting))
                })
            }
            SchemaNode::Any { .. } | SchemaNode::Unknown { .. } => JsonKinds::ANY,
            SchemaNode::Never { .. } => JsonKinds::EMPTY,
        };
        declared.union(nullable)
    }

    /// Whether every branch converts the same values at the same places and the branches disagree
    /// only about which of those properties they require.
    ///
    /// Read by the refusal that reports an indistinguishable union, so it can name the difference
    /// the user can actually act on instead of pointing at conversions that are in fact identical.
    #[must_use]
    pub fn branches_differ_only_in_optionality(&self, branches: &[SchemaNode]) -> bool {
        let erased = |branch| {
            let mut conversions = self.conversions(branch);
            for (path, _) in &mut conversions {
                for step in path {
                    if let Step::Property { required, .. } = step {
                        *required = true;
                    }
                }
            }
            conversions
        };
        // Consecutive pairs rather than each against the first: equality is transitive, so the two
        // say the same thing, and this one needs no case for a branch list that cannot be empty.
        branches
            .windows(2)
            .all(|pair| erased(&pair[0]) == erased(&pair[1]))
    }

    /// The conversions this node performs, each with the path it performs them at, in a deterministic
    /// order. Used only for equality: two branches convert identically when these lists match.
    fn conversions(&self, node: &SchemaNode) -> Conversions {
        let mut out = Vec::new();
        self.collect_conversions(node, &mut Vec::new(), &mut out);
        out
    }

    fn collect_conversions(&self, node: &SchemaNode, path: &mut Vec<Step>, out: &mut Conversions) {
        if let Some(kind) = self.site(node) {
            out.push((path.clone(), Conversion::Site(kind)));
            return;
        }
        match node {
            SchemaNode::Ref { target, .. } => {
                if let Some(&index) = self
                    .by_pointer
                    .get(&(target.source_id.as_str(), target.json_pointer.as_str()))
                    && self.components[index]
                {
                    out.push((path.clone(), Conversion::Component(index)));
                }
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                ..
            } => {
                for (name, property, meta) in properties {
                    path.push(Step::Property {
                        name: name.clone(),
                        required: meta.required,
                    });
                    self.collect_conversions(property, path, out);
                    path.pop();
                }
                if let AdditionalProperties::Allowed(Some(schema))
                | AdditionalProperties::Schema(schema) = additional_properties
                {
                    path.push(Step::AdditionalProperties);
                    self.collect_conversions(schema, path, out);
                    path.pop();
                }
            }
            SchemaNode::Array { items, .. } => {
                path.push(Step::Items);
                self.collect_conversions(items, path, out);
                path.pop();
            }
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for (index, item) in prefix_items.iter().enumerate() {
                    path.push(Step::Index(index));
                    self.collect_conversions(item, path, out);
                    path.pop();
                }
                if let TupleRest::Schema(schema) = rest {
                    path.push(Step::Items);
                    self.collect_conversions(schema, path, out);
                    path.pop();
                }
            }
            SchemaNode::AllOf { branches, .. } => {
                for (index, branch) in branches.iter().enumerate() {
                    path.push(Step::Branch(index));
                    self.collect_conversions(branch, path, out);
                    path.pop();
                }
            }
            SchemaNode::OneOf { branches, .. } | SchemaNode::AnyOf { branches, .. } => {
                // A nested union converts by its own dispatch, so it enters the list as one step
                // carrying that dispatch: two outer branches match only if their inner ones do too.
                let (dispatch, per_branch) = self.classify_branches(branches);
                if dispatch != UnionDispatch::Identity {
                    out.push((
                        path.clone(),
                        Conversion::Union(Box::new(dispatch), per_branch),
                    ));
                }
            }
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => {}
        }
    }

    /// The codec this node converts with, following `$ref` edges to their targets.
    ///
    /// Union dispatch reads this rather than [`Self::site`]: a branch that is a reference to a
    /// component whose whole body is a formatted string converts exactly as the inline form does,
    /// and the encode direction has to test for the runtime object either way. Cycles terminate
    /// because a component root that is a `$ref` chain is finite and revisits are refused.
    #[must_use]
    pub fn site_through_refs(&self, node: &SchemaNode) -> Option<TransformKind> {
        let mut current = node;
        let mut visited = Vec::new();
        loop {
            if let Some(kind) = self.site(current) {
                return Some(kind);
            }
            let SchemaNode::Ref { target, .. } = current else {
                return None;
            };
            let &index = self
                .by_pointer
                .get(&(target.source_id.as_str(), target.json_pointer.as_str()))?;
            if visited.contains(&index) {
                return None;
            }
            visited.push(index);
            current = &self.ir.schemas[index].schema;
        }
    }

    /// One structural pass: records this node's own sites and its outgoing component refs, never
    /// following a ref. Both the component fixed point and [`Self::reaches`] read the same pass, so
    /// the two can never disagree about what a node contains.
    fn scan(&self, node: &SchemaNode, out: &mut Scan) {
        if self.site(node).is_some() {
            out.direct = true;
            return;
        }
        match node {
            SchemaNode::Ref { target, .. } => {
                if let Some(&index) = self
                    .by_pointer
                    .get(&(target.source_id.as_str(), target.json_pointer.as_str()))
                {
                    out.deps.push(index);
                }
            }
            SchemaNode::Object {
                properties,
                additional_properties,
                meta,
                ..
            } => {
                for (_, property, _) in properties {
                    self.scan(property, out);
                }
                match additional_properties {
                    AdditionalProperties::Allowed(Some(schema))
                    | AdditionalProperties::Schema(schema) => self.scan(schema, out),
                    AdditionalProperties::Allowed(None) | AdditionalProperties::Forbidden => {}
                }
                // Only a pattern the types emitter turns into an index signature: one without a key
                // it can render contributes no declared type, so nothing there can promise a
                // converted value. Reachability and that rendering have to agree.
                for pattern in &meta.validation_applicators().pattern_properties {
                    if pattern.type_key.is_some() {
                        self.scan(&pattern.schema, out);
                    }
                }
            }
            SchemaNode::Array { items, .. } => self.scan(items, out),
            SchemaNode::Tuple {
                prefix_items, rest, ..
            } => {
                for item in prefix_items {
                    self.scan(item, out);
                }
                match rest {
                    TupleRest::Schema(schema) => self.scan(schema, out),
                    TupleRest::Allowed | TupleRest::Forbidden => {}
                }
            }
            SchemaNode::AllOf { branches, .. }
            | SchemaNode::OneOf { branches, .. }
            | SchemaNode::AnyOf { branches, .. } => {
                for branch in branches {
                    self.scan(branch, out);
                }
            }
            SchemaNode::Primitive { .. }
            | SchemaNode::Finite { .. }
            | SchemaNode::Any { .. }
            | SchemaNode::Never { .. }
            | SchemaNode::Unknown { .. } => {}
        }
    }
}

/// The kinds a typeless `enum`/`const` admits, read off its declared values. No values means nothing
/// constrains the shape, which admits everything.
fn finite_kinds(enum_values: Option<&[Value]>, const_value: Option<&Value>) -> JsonKinds {
    let mut kinds = JsonKinds::EMPTY;
    for value in enum_values.unwrap_or_default().iter().chain(const_value) {
        kinds = kinds.union(match value {
            Value::Null => JsonKinds::NULL,
            Value::Bool(_) => JsonKinds::BOOLEAN,
            Value::Number(_) => JsonKinds::NUMBER,
            Value::String(_) => JsonKinds::STRING,
            Value::Array(_) => JsonKinds::ARRAY,
            Value::Object(_) => JsonKinds::OBJECT,
        });
    }
    if kinds == JsonKinds::EMPTY {
        JsonKinds::ANY
    } else {
        kinds
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::config::{
        DateRepresentation, DateTimeRepresentation, IntegerRepresentation, ResolvedConfig,
        TypesConfig, load_config,
    };
    use crate::diag::DiagnosticSink;
    use crate::ir::Ir;
    use crate::loader::load_graph;
    use crate::parse::parse;

    /// A parsed document plus the config the facts are computed under. `TransformFacts` borrows the
    /// `Ir`, so the two are owned together rather than returned as a pair.
    pub(super) struct Fixture {
        pub(super) ir: Ir,
        config: ResolvedConfig,
        _temp: TempDir,
    }

    impl Fixture {
        pub(super) fn facts(&self) -> TransformFacts<'_> {
            TransformFacts::compute(&self.ir, &self.config)
        }

        pub(super) fn root(&self, name: &str) -> &SchemaNode {
            &self.ir.schemas[index_of(&self.ir, name)].schema
        }
    }

    /// Parses a document under `types`. The config guard still refuses a non-`string` representation
    /// at load time, so the representation is set on the resolved value — which is what the analysis
    /// reads.
    pub(super) fn fixture(document: Value, types: TypesConfig) -> Fixture {
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
        let mut config: ResolvedConfig =
            load_config(Some(&config_path), temp.path()).expect("config resolves");
        config.types = types;
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("graph loads");
        let ir = parse(&graph, &mut sink).expect("input parses");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        Fixture {
            ir,
            config,
            _temp: temp,
        }
    }

    pub(super) fn date_mode() -> TypesConfig {
        TypesConfig {
            date_time: DateTimeRepresentation::Date,
            ..TypesConfig::default()
        }
    }

    pub(super) fn bigint_mode() -> TypesConfig {
        TypesConfig {
            integer: IntegerRepresentation::Bigint,
            ..TypesConfig::default()
        }
    }

    /// The default: no representation transforms.
    pub(super) fn string_mode() -> TypesConfig {
        TypesConfig::default()
    }

    pub(super) fn temporal_mode() -> TypesConfig {
        TypesConfig {
            date_time: DateTimeRepresentation::Temporal,
            date: DateRepresentation::Temporal,
            ..TypesConfig::default()
        }
    }

    pub(super) fn doc(schemas: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    /// The component index of `name`, by the order the parser recorded components.
    pub(super) fn index_of(ir: &Ir, name: &str) -> usize {
        ir.schemas
            .iter()
            .position(|schema| schema.name == name)
            .expect("declared component")
    }

    fn transforms(ir: &Ir, computed: &TransformFacts, name: &str) -> bool {
        computed.component(index_of(ir, name))
    }

    #[test]
    fn a_flat_date_time_property_transforms() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": { "bornAt": { "type": "string", "format": "date-time" } }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Pet"));
        assert!(computed.any());
    }

    #[test]
    fn a_schema_without_a_dated_format_does_not_transform() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "age": { "type": "integer" },
                        "tag": { "type": "string", "format": "uuid" }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Pet"));
        assert!(!computed.any());
    }

    #[test]
    fn integer_bigint_selects_only_integer_int64_sites() {
        let document = doc(json!({
            "Id": { "type": "integer", "format": "int64" },
            "Small": { "type": "integer", "format": "int32" },
            "WrongType": { "type": "string", "format": "int64" }
        }));
        let fx = fixture(document.clone(), bigint_mode());
        let computed = fx.facts();
        assert_eq!(
            computed.site(fx.root("Id")).map(TransformKind::ts_type),
            Some("bigint")
        );
        assert!(transforms(&fx.ir, &computed, "Id"));
        assert_eq!(computed.site(fx.root("Small")), None);
        assert_eq!(computed.site(fx.root("WrongType")), None);

        let fx = fixture(document, string_mode());
        let computed = fx.facts();
        assert_eq!(computed.site(fx.root("Id")), None);
        assert!(!computed.any());
    }

    #[test]
    fn string_mode_transforms_nothing_at_all() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": {
                        "bornAt": { "type": "string", "format": "date-time" },
                        "bornOn": { "type": "string", "format": "date" }
                    }
                }
            })),
            TypesConfig::default(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Pet"));
        assert!(!computed.any());
    }

    #[test]
    fn each_representation_selects_only_its_own_format() {
        let document = doc(json!({
            "Pet": {
                "type": "object",
                "properties": { "bornAt": { "type": "string", "format": "date-time" } }
            },
            "Day": {
                "type": "object",
                "properties": { "on": { "type": "string", "format": "date" } }
            }
        }));
        let fx = fixture(document.clone(), date_mode());
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Pet"));
        assert!(
            !transforms(&fx.ir, &computed, "Day"),
            "types.date is still string, so format: date is not a site"
        );

        let fx = fixture(
            document.clone(),
            TypesConfig {
                date: DateRepresentation::Temporal,
                ..TypesConfig::default()
            },
        );
        let computed = fx.facts();
        assert!(
            !transforms(&fx.ir, &computed, "Pet"),
            "types.dateTime is still string, so format: date-time is not a site"
        );
        assert!(transforms(&fx.ir, &computed, "Day"));

        let fx = fixture(document, temporal_mode());
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Pet"));
        assert!(transforms(&fx.ir, &computed, "Day"));
    }

    #[test]
    fn the_kind_names_the_codec_the_representation_selects() {
        let document = doc(json!({
            "Pet": {
                "type": "object",
                "properties": {
                    "bornAt": { "type": "string", "format": "date-time" },
                    "bornOn": { "type": "string", "format": "date" }
                }
            }
        }));
        let dated = json!({ "type": "string", "format": "date-time" });
        let plain = json!({ "type": "string", "format": "date" });
        for (types, expect_date_time, expect_date) in [
            (date_mode(), Some(TransformKind::DateTimeDate), None),
            (
                temporal_mode(),
                Some(TransformKind::DateTimeInstant),
                Some(TransformKind::DatePlainDate),
            ),
            (TypesConfig::default(), None, None),
        ] {
            let fx = fixture(document.clone(), types);
            let computed = fx.facts();
            let pet = &fx.ir.schemas[index_of(&fx.ir, "Pet")].schema;
            let born_at = property(pet, "bornAt");
            let born_on = property(pet, "bornOn");
            assert_eq!(computed.site(born_at), expect_date_time, "{dated}");
            assert_eq!(computed.site(born_on), expect_date, "{plain}");
        }
    }

    /// The named property of an object schema, or `None` when the node is not an object or declares
    /// no such property. Total rather than panicking: an "impossible" arm is a permanently uncovered
    /// line under a 100%-lines gate, so both answers are real and both are tested.
    fn property_of<'schema>(
        schema: &'schema SchemaNode,
        name: &str,
    ) -> Option<&'schema SchemaNode> {
        match schema {
            SchemaNode::Object { properties, .. } => properties
                .iter()
                .find(|(key, _, _)| key == name)
                .map(|(_, node, _)| node),
            _ => None,
        }
    }

    fn property<'schema>(schema: &'schema SchemaNode, name: &str) -> &'schema SchemaNode {
        property_of(schema, name).expect("declared property")
    }

    #[test]
    fn the_property_lookup_helper_is_total() {
        let empty = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Forbidden,
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: crate::ir::SchemaMeta::default(),
        };
        assert!(property_of(&empty, "missing").is_none());
        assert!(
            property_of(
                &SchemaNode::Any {
                    meta: crate::ir::SchemaMeta::default()
                },
                "any"
            )
            .is_none()
        );
    }

    #[test]
    fn a_ref_chain_reaches_a_transform_two_hops_away() {
        let fx = fixture(
            doc(json!({
                "Outer": {
                    "type": "object",
                    "properties": { "middle": { "$ref": "#/components/schemas/Middle" } }
                },
                "Middle": {
                    "type": "object",
                    "properties": { "inner": { "$ref": "#/components/schemas/Inner" } }
                },
                "Inner": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Inner"));
        assert!(transforms(&fx.ir, &computed, "Middle"));
        assert!(transforms(&fx.ir, &computed, "Outer"));
    }

    #[test]
    fn a_ref_chain_that_reaches_no_transform_stays_untransformed() {
        let fx = fixture(
            doc(json!({
                "Outer": {
                    "type": "object",
                    "properties": { "middle": { "$ref": "#/components/schemas/Middle" } }
                },
                "Middle": { "type": "object", "properties": { "n": { "type": "integer" } } }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Outer"));
        assert!(!transforms(&fx.ir, &computed, "Middle"));
    }

    #[test]
    fn direct_self_recursion_terminates() {
        let fx = fixture(
            doc(json!({
                "Node": {
                    "type": "object",
                    "properties": {
                        "at": { "type": "string", "format": "date-time" },
                        "child": { "$ref": "#/components/schemas/Node" }
                    }
                },
                "Plain": {
                    "type": "object",
                    "properties": { "child": { "$ref": "#/components/schemas/Plain" } }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Node"));
        assert!(!transforms(&fx.ir, &computed, "Plain"));
    }

    #[test]
    fn mutual_recursion_terminates_and_propagates_both_ways() {
        let fx = fixture(
            doc(json!({
                "A": {
                    "type": "object",
                    "properties": { "b": { "$ref": "#/components/schemas/B" } }
                },
                "B": {
                    "type": "object",
                    "properties": {
                        "a": { "$ref": "#/components/schemas/A" },
                        "at": { "type": "string", "format": "date-time" }
                    }
                },
                "C": {
                    "type": "object",
                    "properties": { "d": { "$ref": "#/components/schemas/D" } }
                },
                "D": {
                    "type": "object",
                    "properties": { "c": { "$ref": "#/components/schemas/C" } }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(
            transforms(&fx.ir, &computed, "A"),
            "reaches the date through B"
        );
        assert!(transforms(&fx.ir, &computed, "B"));
        assert!(!transforms(&fx.ir, &computed, "C"));
        assert!(!transforms(&fx.ir, &computed, "D"));
    }

    #[test]
    fn a_typed_enum_of_date_strings_keeps_its_literal_union() {
        // `type: string` with an `enum` parses to Primitive carrying enum_values — NOT to Finite,
        // which is the typeless enum/const node. A predicate that only excluded Finite would
        // transform this and destroy a literal union that is strictly more precise than a Date.
        let fx = fixture(
            doc(json!({
                "Milestone": {
                    "type": "object",
                    "properties": {
                        "at": {
                            "type": "string",
                            "format": "date-time",
                            "enum": ["2024-01-01T00:00:00Z", "2025-01-01T00:00:00Z"]
                        }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let milestone = &fx.ir.schemas[index_of(&fx.ir, "Milestone")].schema;
        assert!(matches!(
            property(milestone, "at"),
            SchemaNode::Primitive {
                enum_values: Some(_),
                ..
            }
        ));
        assert_eq!(computed.site(property(milestone, "at")), None);
        assert!(!transforms(&fx.ir, &computed, "Milestone"));
    }

    #[test]
    fn a_typed_const_date_string_keeps_its_literal() {
        let fx = fixture(
            doc(json!({
                "Epoch": {
                    "type": "object",
                    "properties": {
                        "at": {
                            "type": "string",
                            "format": "date-time",
                            "const": "1970-01-01T00:00:00Z"
                        }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert_eq!(
            computed.site(property(
                &fx.ir.schemas[index_of(&fx.ir, "Epoch")].schema,
                "at"
            )),
            None
        );
        assert!(!transforms(&fx.ir, &computed, "Epoch"));
    }

    #[test]
    fn a_typeless_finite_node_never_transforms() {
        let fx = fixture(
            doc(json!({
                "Loose": {
                    "type": "object",
                    "properties": {
                        "at": { "enum": ["2024-01-01T00:00:00Z"], "format": "date-time" }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let loose = &fx.ir.schemas[index_of(&fx.ir, "Loose")].schema;
        assert!(matches!(property(loose, "at"), SchemaNode::Finite { .. }));
        assert!(!transforms(&fx.ir, &computed, "Loose"));
    }

    #[test]
    fn a_dated_format_on_a_non_string_type_does_not_transform() {
        let fx = fixture(
            doc(json!({
                "Stamp": {
                    "type": "object",
                    "properties": {
                        "at": { "type": "integer", "format": "date-time" },
                        "on": { "type": "number", "format": "date" }
                    }
                }
            })),
            temporal_mode(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Stamp"));
    }

    #[test]
    fn a_string_without_a_format_does_not_transform() {
        let fx = fixture(
            doc(json!({
                "Plain": { "type": "object", "properties": { "at": { "type": "string" } } }
            })),
            temporal_mode(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Plain"));
    }

    #[test]
    fn time_is_always_a_string() {
        let fx = fixture(
            doc(json!({
                "Clock": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "time" } }
                }
            })),
            temporal_mode(),
        );
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Clock"));
    }

    #[test]
    fn arrays_tuples_and_additional_properties_carry_reachability() {
        let fx = fixture(
            doc(json!({
                "Dates": { "type": "array", "items": { "type": "string", "format": "date-time" } },
                "Pairs": {
                    "type": "array",
                    "prefixItems": [
                        { "type": "string" },
                        { "type": "string", "format": "date-time" }
                    ],
                    "items": false
                },
                "TupleRest": {
                    "type": "array",
                    "prefixItems": [{ "type": "string" }],
                    "items": { "type": "string", "format": "date-time" }
                },
                "Map": {
                    "type": "object",
                    "additionalProperties": { "type": "string", "format": "date-time" }
                },
                "OpenMap": { "type": "object", "additionalProperties": true },
                "Nested": {
                    "type": "object",
                    "properties": {
                        "deep": {
                            "type": "object",
                            "properties": {
                                "list": {
                                    "type": "array",
                                    "items": { "type": "string", "format": "date-time" }
                                }
                            }
                        }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        for name in ["Dates", "Pairs", "TupleRest", "Map", "Nested"] {
            assert!(transforms(&fx.ir, &computed, name), "{name}");
        }
        assert!(!transforms(&fx.ir, &computed, "OpenMap"));
    }

    #[test]
    fn all_of_merges_reachability_from_every_branch() {
        let fx = fixture(
            doc(json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Timed": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Merged": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Base" },
                        { "$ref": "#/components/schemas/Timed" }
                    ]
                },
                "MergedInline": {
                    "allOf": [
                        { "type": "object", "properties": { "id": { "type": "string" } } },
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        }
                    ]
                },
                "MergedPlain": {
                    "allOf": [
                        { "$ref": "#/components/schemas/Base" },
                        { "type": "object", "properties": { "n": { "type": "integer" } } }
                    ]
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "Merged"));
        assert!(transforms(&fx.ir, &computed, "MergedInline"));
        assert!(!transforms(&fx.ir, &computed, "MergedPlain"));
        assert!(!transforms(&fx.ir, &computed, "Base"));
    }

    #[test]
    fn uninhabitable_all_of_discards_unreachable_transforms() {
        let mut fx = fixture(
            doc(json!({
                "Impossible": {
                    "allOf": [
                        { "type": "string", "format": "date-time" },
                        { "type": "number" }
                    ]
                }
            })),
            date_mode(),
        );
        let mut sink = DiagnosticSink::new();
        crate::composition::lower_uninhabitable_all_ofs(&mut fx.ir, &mut sink);
        assert!(matches!(fx.root("Impossible"), SchemaNode::Never { .. }));
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == crate::composition::CODE_COMPOSITION
                && diagnostic.severity == crate::diag::Severity::Warning
        }));
        let computed = fx.facts();
        assert!(!transforms(&fx.ir, &computed, "Impossible"));
    }

    #[test]
    fn an_inline_node_is_asked_directly_rather_than_through_a_component() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "bornAt": { "type": "string", "format": "date-time" }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let pet = &fx.ir.schemas[index_of(&fx.ir, "Pet")].schema;
        assert!(computed.reaches(pet));
        assert!(computed.reaches(property(pet, "bornAt")));
        assert!(!computed.reaches(property(pet, "name")));
    }

    #[test]
    fn reaches_answers_no_to_everything_in_string_mode() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                }
            })),
            TypesConfig::default(),
        );
        let computed = fx.facts();
        let pet = &fx.ir.schemas[index_of(&fx.ir, "Pet")].schema;
        assert!(!computed.reaches(pet));
        assert!(!computed.reaches(property(pet, "at")));
    }

    #[test]
    fn an_inline_node_reaches_a_transform_through_a_component_ref() {
        let fx = fixture(
            doc(json!({
                "Timed": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "Plain": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Holder": {
                    "type": "object",
                    "properties": {
                        "timed": { "$ref": "#/components/schemas/Timed" },
                        "plain": { "$ref": "#/components/schemas/Plain" }
                    }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let holder = &fx.ir.schemas[index_of(&fx.ir, "Holder")].schema;
        // The ref itself carries no site, so only the component table can answer.
        assert!(computed.reaches(property(holder, "timed")));
        assert!(!computed.reaches(property(holder, "plain")));
    }

    #[test]
    fn union_branches_carry_reachability() {
        let fx = fixture(
            doc(json!({
                "Timed": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                },
                "OneOfDated": {
                    "oneOf": [
                        { "type": "string" },
                        { "$ref": "#/components/schemas/Timed" }
                    ]
                },
                "AnyOfDated": {
                    "anyOf": [
                        { "type": "string", "format": "date-time" },
                        { "type": "null" }
                    ]
                },
                "OneOfPlain": {
                    "oneOf": [{ "type": "string" }, { "type": "integer" }]
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert!(transforms(&fx.ir, &computed, "OneOfDated"));
        assert!(transforms(&fx.ir, &computed, "AnyOfDated"));
        assert!(!transforms(&fx.ir, &computed, "OneOfPlain"));
    }

    #[test]
    fn an_open_additional_properties_carrying_a_schema_is_walked() {
        // The parser never builds `Allowed(Some(_))` — the shape only appears in post-parse merge
        // results (parse/mod.rs says so where it covers the same arm), so it is built directly.
        let fx = fixture(
            doc(json!({
                "Pet": { "type": "object", "properties": { "id": { "type": "string" } } }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let dated = SchemaNode::Primitive {
            ty: crate::ir::PrimitiveType::String,
            format: Some("date-time".to_owned()),
            enum_values: None,
            const_value: None,
            meta: crate::ir::SchemaMeta::default(),
        };
        let open_with_schema = |schema: SchemaNode| SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(schema))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: crate::ir::SchemaMeta::default(),
        };
        let dated_map = open_with_schema(dated);
        assert!(computed.reaches(&dated_map));
        assert!(computed.reaches_kind(&dated_map, TransformKind::DateTimeDate));
        assert!(!computed.reaches(&open_with_schema(SchemaNode::Any {
            meta: crate::ir::SchemaMeta::default(),
        })));
    }

    #[test]
    fn an_unresolvable_ref_reaches_nothing() {
        let fx = fixture(
            doc(json!({
                "Pet": {
                    "type": "object",
                    "properties": { "at": { "type": "string", "format": "date-time" } }
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let dangling = SchemaNode::Ref {
            target: crate::ir::SchemaRef {
                source_id: "workspace/openapi.json".to_owned(),
                json_pointer: "/components/schemas/Missing".to_owned(),
            },
            meta: crate::ir::SchemaMeta::default(),
        };
        assert!(!computed.reaches(&dangling));
        assert!(!computed.reaches_kind(&dangling, TransformKind::DateTimeDate));
        assert!(transforms(&fx.ir, &computed, "Pet"));
    }

    #[test]
    fn a_nullable_dated_property_is_still_a_site() {
        let fx = fixture(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {},
                "components": {
                    "schemas": {
                        "Pet": {
                            "type": "object",
                            "properties": {
                                "bornAt": {
                                    "type": "string",
                                    "format": "date-time",
                                    "nullable": true
                                }
                            }
                        }
                    }
                }
            }),
            date_mode(),
        );
        let computed = fx.facts();
        let born_at = property(&fx.ir.schemas[index_of(&fx.ir, "Pet")].schema, "bornAt");
        assert!(
            born_at.meta().nullable,
            "the 3.0 nullable keyword is carried"
        );
        assert_eq!(computed.site(born_at), Some(TransformKind::DateTimeDate));
        assert!(transforms(&fx.ir, &computed, "Pet"));
    }
}

#[cfg(test)]
mod union_tests {
    use serde_json::json;

    use super::tests::{date_mode, doc, fixture, string_mode};
    use super::*;
    use crate::config::{DateRepresentation, DateTimeRepresentation, TypesConfig};

    /// The dispatch classification of a named component whose root is a union.
    fn dispatch(document: Value, name: &str, types: TypesConfig) -> UnionDispatch {
        let fx = fixture(document, types);
        fx.facts()
            .union_dispatch(fx.root(name))
            .expect("the component root is a union")
    }

    /// The branches of a kind dispatch, or `None` for any other classification. Total rather than
    /// panicking, so no arm is left permanently uncovered; both answers are asserted below.
    fn kind_branches(dispatch: &UnionDispatch) -> Option<&[KindBranch]> {
        match dispatch {
            UnionDispatch::Kind(branches) => Some(branches),
            _ => None,
        }
    }

    /// Two object branches, both converting `at`, differing only in a plain field.
    const SHARED: &str = "Shared";

    fn timed() -> Value {
        json!({
            "type": "object",
            "properties": { "at": { "type": "string", "format": "date-time" } }
        })
    }

    #[test]
    fn a_nullable_object_branch_dispatches_on_the_null_kind() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Slot": {
                    "anyOf": [{ "$ref": "#/components/schemas/Timed" }, { "type": "null" }]
                }
            })),
            "Slot",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches.len(), 2);
        assert!(branches[0].converts);
        assert_eq!(branches[0].kinds, JsonKinds::OBJECT);
        assert!(!branches[1].converts);
        assert_eq!(branches[1].kinds, JsonKinds::NULL);
    }

    #[test]
    fn a_string_branch_beside_an_object_branch_dispatches_on_kind() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Either": {
                    "oneOf": [{ "type": "string" }, { "$ref": "#/components/schemas/Timed" }]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::STRING);
        assert!(!branches[0].converts);
        assert_eq!(branches[1].kinds, JsonKinds::OBJECT);
        assert!(branches[1].converts);
    }

    #[test]
    fn an_array_branch_beside_an_object_branch_dispatches_on_kind() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "OneOrMany": {
                    "oneOf": [
                        { "type": "array", "items": { "$ref": "#/components/schemas/Timed" } },
                        { "$ref": "#/components/schemas/Timed" }
                    ]
                }
            })),
            "OneOrMany",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::ARRAY);
        assert_eq!(branches[1].kinds, JsonKinds::OBJECT);
        assert!(branches.iter().all(|branch| branch.converts));
    }

    #[test]
    fn a_nullable_branch_that_overlaps_a_null_branch_is_not_disjoint() {
        // The 3.0 `nullable` keyword makes a branch admit null without a null type in the union, so
        // a kind set read off the declared type alone would call these two disjoint.
        let d = dispatch(
            json!({
                "openapi": "3.0.3",
                "info": { "title": "t", "version": "1" },
                "paths": {},
                "components": {
                    "schemas": {
                        "Slot": {
                            "anyOf": [
                                {
                                    "type": "object",
                                    "nullable": true,
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" }
                                    }
                                },
                                { "type": "object", "properties": { "n": { "type": "integer" } } }
                            ]
                        }
                    }
                }
            }),
            "Slot",
            date_mode(),
        );
        assert!(
            matches!(d, UnionDispatch::Indistinguishable { .. }),
            "got {d:?}"
        );
    }

    #[test]
    fn a_branch_admitting_everything_is_disjoint_from_nothing() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Loose": {
                    "oneOf": [{ "$ref": "#/components/schemas/Timed" }, true]
                }
            })),
            "Loose",
            date_mode(),
        );
        assert!(
            matches!(d, UnionDispatch::Indistinguishable { .. }),
            "an Any branch admits every kind, so no kind selects the other branch; got {d:?}"
        );
    }

    #[test]
    fn branches_that_convert_identically_share_one_conversion() {
        let d = dispatch(
            doc(json!({
                SHARED: {
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
            SHARED,
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Shared);
    }

    #[test]
    fn branches_disagreeing_on_requiredness_do_not_share_a_conversion() {
        // Shared before this, which emitted the first branch's conversion: declared required-first
        // it converted `at` unconditionally and threw on the valid payload `{}`; declared the other
        // way round it emitted the guarded form. Same document, two behaviours.
        let required = json!({
            "type": "object",
            "required": ["at"],
            "properties": { "at": { "type": "string", "format": "date-time" } }
        });
        let optional = json!({
            "type": "object",
            "properties": { "at": { "type": "string", "format": "date-time" } }
        });
        for order in [json!([required, optional]), json!([optional, required])] {
            let d = dispatch(
                doc(json!({ SHARED: { "anyOf": order } })),
                SHARED,
                date_mode(),
            );
            assert!(
                matches!(d, UnionDispatch::Indistinguishable { .. }),
                "branch order must not decide the conversion; got {d:?}"
            );
        }
    }

    #[test]
    fn branches_converting_at_different_paths_are_indistinguishable() {
        let d = dispatch(
            doc(json!({
                "Split": {
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
            "Split",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Indistinguishable { left: 0, right: 1 });
    }

    #[test]
    fn branches_converting_to_different_codecs_are_indistinguishable() {
        let d = dispatch(
            doc(json!({
                "Split": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date" } }
                        }
                    ]
                }
            })),
            "Split",
            TypesConfig {
                date_time: DateTimeRepresentation::Temporal,
                date: DateRepresentation::Temporal,
                ..TypesConfig::default()
            },
        );
        assert_eq!(d, UnionDispatch::Indistinguishable { left: 0, right: 1 });
    }

    #[test]
    fn a_converting_branch_beside_a_plain_branch_of_the_same_kind_is_indistinguishable() {
        let d = dispatch(
            doc(json!({
                "Split": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        },
                        { "type": "object", "properties": { "n": { "type": "integer" } } }
                    ]
                }
            })),
            "Split",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Indistinguishable { left: 0, right: 1 });
    }

    #[test]
    fn two_refs_to_distinct_components_are_indistinguishable_even_when_alike() {
        // A component is converted by its own emitted pair, so two refs are two different calls
        // however alike the components look. Applying one branch's pair to the other's value is the
        // silent wrong-branch decode this classification exists to refuse.
        let d = dispatch(
            doc(json!({
                "Left": timed(),
                "Right": timed(),
                "Either": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Left" },
                        { "$ref": "#/components/schemas/Right" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Indistinguishable { left: 0, right: 1 });
    }

    #[test]
    fn two_refs_to_the_same_component_share_one_conversion() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Either": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Timed" },
                        { "$ref": "#/components/schemas/Timed" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Shared);
    }

    #[test]
    fn a_union_where_nothing_converts_is_identity() {
        let d = dispatch(
            doc(json!({
                "Either": { "oneOf": [{ "type": "string" }, { "type": "integer" }] }
            })),
            "Either",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Identity);
    }

    #[test]
    fn string_mode_leaves_every_union_identity() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Slot": {
                    "anyOf": [{ "$ref": "#/components/schemas/Timed" }, { "type": "null" }]
                }
            })),
            "Slot",
            string_mode(),
        );
        assert_eq!(d, UnionDispatch::Identity);
    }

    #[test]
    fn a_non_union_node_has_no_dispatch() {
        let fx = fixture(doc(json!({ "Timed": timed() })), date_mode());
        let computed = fx.facts();
        assert!(computed.union_dispatch(fx.root("Timed")).is_none());
    }

    #[test]
    fn all_of_needs_no_dispatch_because_its_branches_merge() {
        let fx = fixture(
            doc(json!({
                "Merged": {
                    "allOf": [
                        { "type": "object", "properties": { "id": { "type": "string" } } },
                        {
                            "type": "object",
                            "properties": { "at": { "type": "string", "format": "date-time" } }
                        }
                    ]
                }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        let merged = fx.root("Merged");
        assert!(computed.union_dispatch(merged).is_none());
        assert!(computed.reaches(merged));
    }

    #[test]
    fn a_boolean_branch_dispatches_on_its_own_kind() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Either": {
                    "oneOf": [{ "type": "boolean" }, { "$ref": "#/components/schemas/Timed" }]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::BOOLEAN);
        assert_eq!(branches[1].kinds, JsonKinds::OBJECT);
    }

    #[test]
    fn a_typeless_enum_branch_takes_its_kinds_from_its_values() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Either": {
                    "oneOf": [
                        { "enum": ["a", "b"] },
                        { "$ref": "#/components/schemas/Timed" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::STRING);
        assert!(!branches[0].converts);
    }

    #[test]
    fn finite_kinds_read_every_json_value_shape() {
        assert_eq!(
            finite_kinds(
                Some(&[
                    json!(null),
                    json!(true),
                    json!(1),
                    json!("s"),
                    json!([]),
                    json!({})
                ]),
                None
            ),
            JsonKinds::ANY
        );
        assert_eq!(finite_kinds(None, Some(&json!("s"))), JsonKinds::STRING);
        assert_eq!(
            finite_kinds(None, None),
            JsonKinds::ANY,
            "no declared value constrains nothing, which admits everything"
        );
    }

    #[test]
    fn an_all_of_branch_admits_only_kinds_every_sub_branch_admits() {
        let d = dispatch(
            doc(json!({
                "Either": {
                    "oneOf": [
                        {
                            "allOf": [
                                {
                                    "type": "object",
                                    "properties": {
                                        "at": { "type": "string", "format": "date-time" }
                                    }
                                },
                                { "type": "object", "properties": { "id": { "type": "string" } } }
                            ]
                        },
                        { "type": "string" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::OBJECT);
        assert!(branches[0].converts);
        assert_eq!(branches[1].kinds, JsonKinds::STRING);
    }

    #[test]
    fn a_tuple_branch_converts_at_its_positions_and_its_rest() {
        let d = dispatch(
            doc(json!({
                "Either": {
                    "oneOf": [
                        {
                            "type": "array",
                            "prefixItems": [{ "type": "string", "format": "date-time" }],
                            "items": { "type": "string", "format": "date-time" }
                        },
                        { "type": "string" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[0].kinds, JsonKinds::ARRAY);
        assert!(branches[0].converts);
    }

    #[test]
    fn a_branch_converting_through_additional_properties_is_seen() {
        let d = dispatch(
            doc(json!({
                "Either": {
                    "oneOf": [
                        {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string",
                                "format": "date-time"
                            }
                        },
                        { "type": "string" }
                    ]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert!(branches[0].converts);
    }

    #[test]
    fn a_nested_union_enters_the_outer_comparison_as_its_own_dispatch() {
        // Both outer branches hold a nullable date at the same path, so their nested dispatches match
        // and the outer union converts identically — which only holds if the nested classification is
        // part of what is compared.
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Outer": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "slot": {
                                    "anyOf": [
                                        { "$ref": "#/components/schemas/Timed" },
                                        { "type": "null" }
                                    ]
                                },
                                "left": { "type": "string" }
                            }
                        },
                        {
                            "type": "object",
                            "properties": {
                                "slot": {
                                    "anyOf": [
                                        { "$ref": "#/components/schemas/Timed" },
                                        { "type": "null" }
                                    ]
                                },
                                "right": { "type": "integer" }
                            }
                        }
                    ]
                }
            })),
            "Outer",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Shared);
    }

    #[test]
    fn a_nested_union_that_differs_makes_the_outer_branches_differ() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Other": timed(),
                "Outer": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "slot": {
                                    "anyOf": [
                                        { "$ref": "#/components/schemas/Timed" },
                                        { "type": "null" }
                                    ]
                                }
                            }
                        },
                        {
                            "type": "object",
                            "properties": {
                                "slot": {
                                    "anyOf": [
                                        { "$ref": "#/components/schemas/Other" },
                                        { "type": "null" }
                                    ]
                                }
                            }
                        }
                    ]
                }
            })),
            "Outer",
            date_mode(),
        );
        assert_eq!(d, UnionDispatch::Indistinguishable { left: 0, right: 1 });
    }

    #[test]
    fn a_reference_cycle_admits_every_kind_rather_than_none() {
        let d = dispatch(
            doc(json!({
                "Cycle": {
                    "anyOf": [
                        { "$ref": "#/components/schemas/Cycle" },
                        { "type": "string", "format": "date-time" }
                    ]
                }
            })),
            "Cycle",
            date_mode(),
        );
        assert!(
            matches!(d, UnionDispatch::Indistinguishable { .. }),
            "an uncharacterized cycle overlaps every sibling; got {d:?}"
        );
    }

    #[test]
    fn an_unresolvable_reference_branch_admits_every_kind() {
        let fx = fixture(doc(json!({ "Timed": timed() })), date_mode());
        let computed = fx.facts();
        let dangling = SchemaNode::Ref {
            target: crate::ir::SchemaRef {
                source_id: "workspace/openapi.json".to_owned(),
                json_pointer: "/components/schemas/Missing".to_owned(),
            },
            meta: crate::ir::SchemaMeta::default(),
        };
        let union = SchemaNode::OneOf {
            branches: vec![
                dangling,
                SchemaNode::Primitive {
                    ty: PrimitiveType::String,
                    format: Some("date-time".to_owned()),
                    enum_values: None,
                    const_value: None,
                    meta: crate::ir::SchemaMeta::default(),
                },
            ],
            discriminator: None,
            meta: crate::ir::SchemaMeta::default(),
        };
        let d = computed
            .union_dispatch(&union)
            .expect("the node is a union");
        assert!(
            matches!(d, UnionDispatch::Indistinguishable { .. }),
            "got {d:?}"
        );
        assert!(kind_branches(&d).is_none());
    }

    #[test]
    fn a_branch_whose_open_additional_properties_carry_a_schema_is_walked() {
        // The parser never builds `Allowed(Some(_))`; the shape only appears in post-parse merge
        // results, so the branch is built directly.
        let fx = fixture(doc(json!({ "Timed": timed() })), date_mode());
        let computed = fx.facts();
        let meta = crate::ir::SchemaMeta::default;
        let open = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(
                SchemaNode::Primitive {
                    ty: PrimitiveType::String,
                    format: Some("date-time".to_owned()),
                    enum_values: None,
                    const_value: None,
                    meta: meta(),
                },
            ))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: meta(),
        };
        let union = SchemaNode::OneOf {
            branches: vec![
                open,
                SchemaNode::Primitive {
                    ty: PrimitiveType::String,
                    format: None,
                    enum_values: None,
                    const_value: None,
                    meta: meta(),
                },
            ],
            discriminator: None,
            meta: meta(),
        };
        let d = computed
            .union_dispatch(&union)
            .expect("the node is a union");
        let branches = kind_branches(&d).expect("kind dispatch");
        assert!(branches[0].converts, "the open map converts its values");
        assert!(!branches[1].converts);
    }

    #[test]
    fn a_never_branch_admits_nothing_and_overlaps_nothing() {
        let d = dispatch(
            doc(json!({
                "Timed": timed(),
                "Either": {
                    "oneOf": [{ "$ref": "#/components/schemas/Timed" }, false]
                }
            })),
            "Either",
            date_mode(),
        );
        let branches = kind_branches(&d).expect("kind dispatch");
        assert_eq!(branches[1].kinds, JsonKinds::EMPTY);
    }

    #[test]
    fn a_reference_cycle_resolves_to_no_site_rather_than_looping() {
        let fx = fixture(
            doc(json!({
                "A": { "$ref": "#/components/schemas/B" },
                "B": { "$ref": "#/components/schemas/A" },
                "Timed": timed()
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert_eq!(computed.site_through_refs(fx.root("A")), None);
        assert_eq!(
            computed.site_through_refs(fx.root("Timed")),
            None,
            "an object is not itself a site"
        );
    }

    #[test]
    fn a_reference_to_a_bare_dated_string_resolves_to_its_codec() {
        let fx = fixture(
            doc(json!({
                "Stamp": { "type": "string", "format": "date-time" },
                "Alias": { "$ref": "#/components/schemas/Stamp" }
            })),
            date_mode(),
        );
        let computed = fx.facts();
        assert_eq!(
            computed.site_through_refs(fx.root("Alias")),
            Some(TransformKind::DateTimeDate)
        );
    }

    #[test]
    fn json_kinds_report_disjointness_and_membership() {
        assert!(JsonKinds::NULL.is_disjoint(JsonKinds::OBJECT));
        assert!(!JsonKinds::ANY.is_disjoint(JsonKinds::NULL));
        assert!(!JsonKinds::EMPTY.contains(JsonKinds::NULL));
        assert!(JsonKinds::ANY.contains(JsonKinds::ARRAY));
        assert!(
            JsonKinds::EMPTY.is_disjoint(JsonKinds::ANY),
            "a Never branch admits nothing, so it overlaps nothing"
        );
        assert_eq!(JsonKinds::NULL.union(JsonKinds::OBJECT).count(), 2);
    }
}
