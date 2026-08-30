//! Operation selection and component pruning, applied to the IR between parsing and
//! semantic analysis.
//!
//! Running here rather than at emission means name allocation, collision detection and path
//! registration all see only the operations and schemas that survive, so every artifact agrees
//! on what exists and no emitted import can dangle.

use std::path::Path;

use foldhash::{HashMap, HashMapExt};

use regex_lite::RegexBuilder;

use crate::config::{AxisFilter, FiltersConfig};
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{Ir, Operation, RemovedDeclarations, SchemaRef};
use crate::parse::{RefOrigin, collect_operation_refs, collect_schema_refs};

/// A malformed filter pattern: a regex literal whose body does not compile.
pub(crate) const CODE_FILTER_PATTERN: &str = "OASTS0261";

/// A filter pattern that matches no operation in the document.
pub(crate) const CODE_FILTER_UNMATCHED: &str = "OASTS0262";

/// Filters that select operations but leave none of them, and no webhooks either.
pub(crate) const CODE_FILTER_EMPTY: &str = "OASTS0263";

/// Pruning removed every component schema and there was nothing else to emit.
pub(crate) const CODE_PRUNED_EVERYTHING: &str = "OASTS2107";

/// What one compiled pattern matches with.
#[derive(Clone, Debug)]
pub enum PatternKind {
    /// Whole-string equality against the subject.
    Exact,
    /// A regex that must match the whole subject. `/get/` matches `get` and not `forgetPet`;
    /// substring and prefix matching are written explicitly with `.*`.
    ///
    /// Whole-subject matching is what keeps a misread pattern from silently over-selecting:
    /// `/pets/` is a legal OpenAPI path that also reads as a regex literal, and under substring
    /// semantics excluding it would quietly take `/pets` and `/pets/{petId}` too. Anchored, it
    /// matches nothing and the unmatched-pattern rule says so.
    Regex {
        /// The anchored form, used for every selection decision.
        anchored: regex_lite::Regex,
        /// The body as written, if it compiles on its own. Only consulted when a pattern
        /// matched nothing, to tell a user who wrote a prefix regex why. Best-effort by
        /// construction: losing the hint costs nothing, so it never fails compilation.
        loose: Option<regex_lite::Regex>,
    },
}

/// One filter pattern, compiled once during configuration resolution.
///
/// A pattern is either exact string equality or a slash-delimited regex. A string is read as a
/// regex only when it reads as a complete regex literal — `/body/` or `/body/i` — so path-shaped
/// values like `/pets`, `/pets/{petId}` and the root path `/` stay exact. `/pets/` is a regex
/// matching `pets`.
#[derive(Clone, Debug)]
pub struct Pattern {
    source: String,
    kind: PatternKind,
}

impl Pattern {
    /// Whether this pattern matches one subject.
    #[must_use]
    pub fn matches(&self, subject: &str) -> bool {
        match &self.kind {
            PatternKind::Exact => self.source == subject,
            PatternKind::Regex { anchored, .. } => anchored.is_match(subject),
        }
    }

    /// Whether this pattern matches one subject, comparing exact patterns without regard to
    /// ASCII case. Used for methods, where `DELETE` and `delete` name the same operation.
    #[must_use]
    pub fn matches_ignoring_ascii_case(&self, subject: &str) -> bool {
        match &self.kind {
            PatternKind::Exact => self.source.eq_ignore_ascii_case(subject),
            PatternKind::Regex { anchored, .. } => anchored.is_match(subject),
        }
    }

    /// Whether this pattern would have matched had it not been anchored.
    ///
    /// Never decides selection — it exists so a pattern that matched nothing can say whether the
    /// cause was the whole-subject rule, which is the one mistake anchoring makes easy.
    #[must_use]
    pub fn matches_loosely(&self, subject: &str) -> bool {
        match &self.kind {
            PatternKind::Exact => false,
            PatternKind::Regex { loose, .. } => {
                loose.as_ref().is_some_and(|loose| loose.is_match(subject))
            }
        }
    }

    /// The pattern as the configuration wrote it.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// What this pattern matches with.
    #[must_use]
    pub fn kind(&self) -> &PatternKind {
        &self.kind
    }
}

/// Two patterns are equal when they were written identically — identical source text compiles
/// to identical behaviour, and `regex_lite::Regex` is not itself comparable.
impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Pattern {}

/// The compiled include and exclude lists for one selection axis.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AxisPatterns {
    pub include: Vec<Pattern>,
    pub exclude: Vec<Pattern>,
}

impl AxisPatterns {
    fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

/// Resolved operation selection and component pruning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Filters {
    pub tags: Option<AxisPatterns>,
    pub operations: Option<AxisPatterns>,
    pub paths: Option<AxisPatterns>,
    pub methods: Option<AxisPatterns>,
    /// `false` drops operations marked `deprecated: true`. Never applies to component schemas —
    /// a schema a surviving operation references is kept regardless.
    pub deprecated: bool,
    /// `true` keeps component schemas no surviving operation reaches, for documents that are
    /// deliberately schema libraries. The default prunes them.
    pub orphans: bool,
}

impl Filters {
    /// Whether any axis actually selects operations.
    ///
    /// `filters: { orphans: true }` declares none, and neither does an axis present but empty,
    /// so neither can trip the leaves-nothing-to-generate diagnostic.
    #[must_use]
    pub fn declares_selection_axis(&self) -> bool {
        // `deprecated: false` is a selection too — it is applied as a conjunct in `survives` and
        // can reject every operation on its own, so a guard that ignored it would let the most
        // likely way to empty a document pass silently.
        !self.deprecated
            || [&self.tags, &self.operations, &self.paths, &self.methods]
                .into_iter()
                .flatten()
                .any(|axis| !axis.is_empty())
    }
}

/// Applies operation filtering and component pruning to a parsed IR.
///
/// Runs between parsing and semantic analysis so that name allocation, collision detection and
/// path registration see only survivors.
pub fn apply(
    mut ir: Ir,
    filters: Option<&Filters>,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Ir {
    if let Some(filters) = filters {
        // A document that already failed to parse has an unreliable operation set, so any claim
        // about what a pattern does or does not match would be unreliable too — and a config
        // diagnostic raised there would flip the exit code from the input failure's 1 to 2,
        // blaming the config for the document's defect.
        let document_is_sound = !sink.has_errors();
        // An unmatched pattern is the actionable cause, and it usually also empties the
        // result. Reporting both would bury the typo under its own consequence.
        let unmatched = document_is_sound && report_unmatched_patterns(&ir, filters, source, sink);
        let before = (ir.operations.len(), ir.webhooks.len());
        select_operations(&mut ir, filters);
        if document_is_sound && !unmatched {
            report_empty_selection(&ir, filters, before, source, sink);
        }
    }
    if filters.is_some_and(|filters| filters.orphans) {
        return ir;
    }
    let before = ir.schemas.len();
    prune_unreachable_schemas(&mut ir);
    report_pruned_everything(&ir, before, sink);
    ir
}

/// Warns when pruning left nothing at all to emit.
///
/// Exit status is unchanged — an existing config with no `filters` block keeps working, which is
/// the whole point of pruning being on by default. But the manifest removes files that stop
/// being generated, so an empty emit set deletes a previously committed tree, and that cannot
/// happen without saying so.
fn report_pruned_everything(ir: &Ir, before: usize, sink: &mut DiagnosticSink) {
    if before == 0 || !ir.schemas.is_empty() {
        return;
    }
    let mut emits_something = !ir.operations.is_empty();
    for webhook in &ir.webhooks {
        emits_something |= !webhook.operations.is_empty();
    }
    if emits_something {
        return;
    }
    let mut diagnostic = Diagnostic::input(
        CODE_PRUNED_EVERYTHING,
        format!(
            "no operation reaches any of the {before} component schemas, and no operation \
             survives either, so nothing is generated; set filters.orphans to keep components \
             a document declares for their own sake"
        ),
    );
    diagnostic.severity = Severity::Warning;
    sink.push(diagnostic);
}

/// Reports every pattern that matches no operation in the document.
///
/// A pattern naming nothing is a configuration typo, not a document defect — an upstream tag
/// rename that silently dropped forty endpoints from a generated client would otherwise be a
/// mystery rather than a build failure. Both `include` and `exclude` lists are checked, and
/// exact and regex patterns alike.
///
/// Every pattern is judged against the whole document, before any axis removes anything, so one
/// axis narrowing the survivors cannot make another axis's pattern look unmatched. A pattern
/// that matched an operation which `deprecated: false` then dropped still counts as matched:
/// it named a real operation, and `deprecated` is a separate conjunct.
fn report_unmatched_patterns(
    ir: &Ir,
    filters: &Filters,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> bool {
    let mut selectable = UnmatchedPatterns::new(filters);
    // Replayed with the unanchored matcher, so a pattern that matched nothing can say whether
    // the whole-subject rule was the cause — the one mistake anchoring makes easy.
    let mut loosely = UnmatchedPatterns::new(filters);
    for operation in ir
        .operations
        .iter()
        .chain(ir.webhooks.iter().flat_map(|webhook| &webhook.operations))
    {
        selectable.record_operation(filters, operation);
        loosely.record_operation_with(filters, operation, Pattern::matches_loosely);
    }

    // Callback operations are matched separately because they are never filtered independently
    // of the operation that declares them. A pattern that only reaches one is still a mistake,
    // but reporting it as naming nothing would send the user hunting for an operationId their
    // document plainly contains.
    let mut in_callbacks = UnmatchedPatterns::new(filters);
    for operation in ir
        .operations
        .iter()
        .chain(ir.webhooks.iter().flat_map(|webhook| &webhook.operations))
    {
        record_callback_operations(&mut in_callbacks, filters, operation);
    }

    selectable.report(filters, &in_callbacks, &loosely, source, sink)
}

/// Records every callback operation a parent declares, at any nesting depth.
fn record_callback_operations(
    into: &mut UnmatchedPatterns,
    filters: &Filters,
    operation: &Operation,
) {
    for callback in &operation.callbacks {
        for expression in &callback.expressions {
            for nested in &expression.operations {
                into.record_operation(filters, nested);
                record_callback_operations(into, filters, nested);
            }
        }
    }
}

/// Reports filters that select operations but leave nothing to generate.
///
/// Scoped to filters declaring at least one selection axis: `filters: { orphans: true }` alone
/// never trips it, and a document that legitimately declares no paths — legal in OpenAPI 3.1 —
/// is untouched when nothing is being selected.
fn report_empty_selection(
    ir: &Ir,
    filters: &Filters,
    before: (usize, usize),
    source: &Path,
    sink: &mut DiagnosticSink,
) {
    if !filters.declares_selection_axis() {
        return;
    }
    if !ir.operations.is_empty() || ir.webhooks.iter().any(|w| !w.operations.is_empty()) {
        return;
    }
    let (operations, webhooks) = before;
    sink.push(
        Diagnostic::config(
            CODE_FILTER_EMPTY,
            format!(
                "filters leave nothing to generate: 0 of {operations} operations and \
                 0 of {webhooks} webhooks survive"
            ),
        )
        .with_source(source.display().to_string())
        .with_json_pointer("/filters"),
    );
}

/// The four selection axes, named for diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Axis {
    Tags,
    Operations,
    Paths,
    Methods,
}

impl Axis {
    const ALL: [Self; 4] = [Self::Tags, Self::Operations, Self::Paths, Self::Methods];

    fn key(self) -> &'static str {
        match self {
            Self::Tags => "tags",
            Self::Operations => "operations",
            Self::Paths => "paths",
            Self::Methods => "methods",
        }
    }

    fn patterns(self, filters: &Filters) -> Option<&AxisPatterns> {
        match self {
            Self::Tags => filters.tags.as_ref(),
            Self::Operations => filters.operations.as_ref(),
            Self::Paths => filters.paths.as_ref(),
            Self::Methods => filters.methods.as_ref(),
        }
    }
}

/// Per-pattern match flags, parallel to each configured axis's include and exclude lists.
struct UnmatchedPatterns {
    matched: HashMap<(&'static str, &'static str), Vec<bool>>,
}

impl UnmatchedPatterns {
    fn new(filters: &Filters) -> Self {
        let mut matched = HashMap::new();
        for axis in Axis::ALL {
            let Some(patterns) = axis.patterns(filters) else {
                continue;
            };
            matched.insert((axis.key(), "include"), vec![false; patterns.include.len()]);
            matched.insert((axis.key(), "exclude"), vec![false; patterns.exclude.len()]);
        }
        Self { matched }
    }

    /// Records everything one operation matches, across all four axes.
    fn record_operation(&mut self, filters: &Filters, operation: &Operation) {
        self.record_operation_with(filters, operation, Pattern::matches);
    }

    /// As `record_operation`, with the matcher supplied.
    fn record_operation_with(
        &mut self,
        filters: &Filters,
        operation: &Operation,
        matches: fn(&Pattern, &str) -> bool,
    ) {
        self.record(
            filters.tags.as_ref(),
            Axis::Tags,
            Some(&operation.tags),
            matches,
        );
        self.record(
            filters.operations.as_ref(),
            Axis::Operations,
            operation.operation_id.as_ref().map(std::slice::from_ref),
            matches,
        );
        self.record(
            filters.paths.as_ref(),
            Axis::Paths,
            operation.path.as_ref().map(std::slice::from_ref),
            matches,
        );
        self.record(
            filters.methods.as_ref(),
            Axis::Methods,
            Some(std::slice::from_ref(&operation.method)),
            matches,
        );
    }

    fn record(
        &mut self,
        patterns: Option<&AxisPatterns>,
        axis: Axis,
        subjects: Option<&[String]>,
        matches: fn(&Pattern, &str) -> bool,
    ) {
        let (Some(patterns), Some(subjects)) = (patterns, subjects) else {
            return;
        };
        for (list, entries) in [
            ("include", &patterns.include),
            ("exclude", &patterns.exclude),
        ] {
            // Construction registers both lists for every configured axis before any matching run.
            let flags = self
                .matched
                .get_mut(&(axis.key(), list))
                .expect("every configured axis list is registered");
            for (position, pattern) in entries.iter().enumerate() {
                if subjects.iter().any(|subject| matches(pattern, subject)) {
                    flags[position] = true;
                }
            }
        }
    }

    /// Returns whether any pattern went unmatched.
    fn report(
        &self,
        filters: &Filters,
        in_callbacks: &Self,
        loosely: &Self,
        source: &Path,
        sink: &mut DiagnosticSink,
    ) -> bool {
        let mut reported = false;
        for axis in Axis::ALL {
            let Some(patterns) = axis.patterns(filters) else {
                continue;
            };
            for (list, entries) in [
                ("include", &patterns.include),
                ("exclude", &patterns.exclude),
            ] {
                let flags = &self.matched[&(axis.key(), list)];
                for (position, pattern) in entries.iter().enumerate() {
                    if flags[position] {
                        continue;
                    }
                    reported = true;
                    let reason = if in_callbacks.matched[&(axis.key(), list)][position] {
                        "matches only callback operations, which are never filtered \
                         independently of the operation that declares them"
                    } else if loosely.matched[&(axis.key(), list)][position] {
                        "matches no operation; a regex pattern must match the whole subject, \
                         so add `.*` to match a prefix or a substring"
                    } else {
                        "matches no operation"
                    };
                    sink.push(
                        Diagnostic::config(
                            CODE_FILTER_UNMATCHED,
                            format!(
                                "filters.{}.{list} pattern '{}' {reason}",
                                axis.key(),
                                pattern.source()
                            ),
                        )
                        .with_source(source.display().to_string())
                        .with_json_pointer(format!("/filters/{}/{list}/{position}", axis.key())),
                    );
                }
            }
        }
        reported
    }
}

/// Drops the operations and webhook operations the filters reject.
///
/// A webhook left with no operations is removed with them. Callback operations are never
/// filtered independently — they live and die with the parent operation that owns them.
fn select_operations(ir: &mut Ir, filters: &Filters) {
    let mut removed = std::mem::take(&mut ir.removed);
    ir.operations.retain(|operation| {
        let keep = survives(operation, filters);
        if !keep {
            // Only top-level operations are addressable by `naming.overrides.operations`, so
            // only their ids are recorded — mirroring what the override check itself scans.
            if let Some(id) = &operation.operation_id {
                removed.operations.push(id.clone());
            }
            removed
                .operation_pointers
                .push(operation.source.json_pointer.clone());
            record_removed_callbacks(operation, &mut removed);
        }
        keep
    });
    for webhook in &mut ir.webhooks {
        webhook.operations.retain(|operation| {
            let keep = survives(operation, filters);
            if !keep {
                record_removed_callbacks(operation, &mut removed);
            }
            keep
        });
    }
    ir.webhooks.retain(|webhook| {
        let keep = !webhook.operations.is_empty();
        if !keep {
            removed.webhooks.push(webhook.name.clone());
        }
        keep
    });
    ir.removed = removed;
}

/// Notes every callback name a dropped operation took with it, nested ones included — the
/// override check reaches callbacks at any depth, so the record has to as well.
fn record_removed_callbacks(operation: &Operation, removed: &mut RemovedDeclarations) {
    for callback in &operation.callbacks {
        removed.callbacks.push(callback.name.clone());
        for expression in &callback.expressions {
            for nested in &expression.operations {
                record_removed_callbacks(nested, removed);
            }
        }
    }
}

/// Whether every configured, applicable axis admits this operation.
fn survives(operation: &Operation, filters: &Filters) -> bool {
    if !filters.deprecated && operation.deprecated {
        return false;
    }
    axis_admits(
        filters.tags.as_ref(),
        Some(&operation.tags),
        Pattern::matches,
    ) && axis_admits(
        filters.operations.as_ref(),
        operation.operation_id.as_ref().map(std::slice::from_ref),
        Pattern::matches,
    ) && axis_admits(
        filters.paths.as_ref(),
        operation.path.as_ref().map(std::slice::from_ref),
        Pattern::matches,
    ) && axis_admits(
        filters.methods.as_ref(),
        Some(std::slice::from_ref(&operation.method)),
        Pattern::matches_ignoring_ascii_case,
    )
}

/// Whether one axis admits a subject.
///
/// `None` subjects mean the axis does not apply to this operation — a webhook has no path, an
/// operation without an operationId has no id — and an inapplicable axis abstains rather than
/// rejecting. Without abstention a `paths` filter would silently delete every webhook.
///
/// `Some(&[])` is the opposite case and must not be confused with it: an operation declaring no
/// tags *is* subject to the tags axis, and simply matches nothing.
fn axis_admits(
    axis: Option<&AxisPatterns>,
    subjects: Option<&[String]>,
    matches: fn(&Pattern, &str) -> bool,
) -> bool {
    let Some(axis) = axis else {
        return true;
    };
    let Some(subjects) = subjects else {
        return true;
    };
    let hits = |patterns: &[Pattern]| {
        patterns
            .iter()
            .any(|pattern| subjects.iter().any(|subject| matches(pattern, subject)))
    };
    if hits(&axis.exclude) {
        return false;
    }
    axis.include.is_empty() || hits(&axis.include)
}

/// Drops every component schema no surviving operation reaches.
///
/// Seeded from the operations that survive and closed transitively, never by subtracting the
/// references of operations that were dropped — a schema two operations share must survive when
/// either one does.
///
/// The walk is a worklist with a visited set rather than a recursion: `$ref` graphs are cyclic
/// and diamond-shaped in practice, so a recursive walk would either not terminate or blow up
/// exponentially.
fn prune_unreachable_schemas(ir: &mut Ir) {
    // A SchemaRef and a NamedSchema's SourceRef carry the same (source_id, json_pointer) pair,
    // and a schema materialized from an external document keeps the referring pointer verbatim,
    // so this index resolves every reference that names a schema. Keys borrow: the walk below is
    // the index's last reader, so it is dead before the rebuild needs `ir.schemas` mutably, and
    // this runs on every compile — owning the keys would allocate twice per declared schema for
    // nothing.
    let mut index: HashMap<(&str, &str), usize> = HashMap::with_capacity(ir.schemas.len());
    for (position, schema) in ir.schemas.iter().enumerate() {
        index.insert(
            (
                schema.source.source_id.as_str(),
                schema.source.json_pointer.as_str(),
            ),
            position,
        );
    }

    let mut queue: Vec<(SchemaRef, RefOrigin)> = Vec::new();
    for operation in &ir.operations {
        collect_operation_refs(operation, &mut queue);
    }
    for webhook in &ir.webhooks {
        for operation in &webhook.operations {
            collect_operation_refs(operation, &mut queue);
        }
    }

    let mut reached = vec![false; ir.schemas.len()];
    // A discriminator mapping target reaches a component the branches need not `$ref`, so it
    // counts as reachability here exactly like a `$ref` does; one that names nothing simply
    // misses the index below.
    while let Some((reference, _)) = queue.pop() {
        // A reference that names no schema — an inline subschema, or a pointer into a non-schema
        // component — has nothing to mark and nothing to walk.
        let Some(&position) = index.get(&(
            reference.source_id.as_str(),
            reference.json_pointer.as_str(),
        )) else {
            continue;
        };
        if reached[position] {
            continue;
        }
        reached[position] = true;
        collect_schema_refs(&ir.schemas[position].schema, &mut queue);
    }

    // Rebuilt rather than retained in place so a dropped schema's name can be moved into the
    // removal record instead of cloned; survivors keep document order, which emission depends on.
    drop(index);
    let mut removed = std::mem::take(&mut ir.removed);
    let mut survivors = Vec::with_capacity(reached.iter().filter(|kept| **kept).count());
    for (position, schema) in std::mem::take(&mut ir.schemas).into_iter().enumerate() {
        if reached[position] {
            survivors.push(schema);
        } else {
            removed.schema_sources.push(schema.source.display());
            removed.schemas.push(schema.name);
        }
    }
    ir.schemas = survivors;
    ir.removed = removed;
}

/// Compiles a raw `filters` block, reporting every malformed pattern.
///
/// Compilation happens during configuration resolution so a bad pattern fails before any
/// document is loaded.
pub(crate) fn resolve(
    raw: Option<&FiltersConfig>,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Option<Filters> {
    let raw = raw?;
    Some(Filters {
        tags: compile_axis(raw.tags.as_ref(), "tags", source, sink),
        operations: compile_axis(raw.operations.as_ref(), "operations", source, sink),
        paths: compile_axis(raw.paths.as_ref(), "paths", source, sink),
        methods: compile_axis(raw.methods.as_ref(), "methods", source, sink),
        deprecated: raw.deprecated,
        orphans: raw.orphans,
    })
}

fn compile_axis(
    raw: Option<&AxisFilter>,
    axis: &str,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Option<AxisPatterns> {
    let raw = raw?;
    Some(AxisPatterns {
        include: compile_list(raw.include.as_deref(), axis, "include", source, sink),
        exclude: compile_list(raw.exclude.as_deref(), axis, "exclude", source, sink),
    })
}

fn compile_list(
    patterns: Option<&[String]>,
    axis: &str,
    list: &str,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Vec<Pattern> {
    let Some(patterns) = patterns else {
        return Vec::new();
    };
    let mut compiled = Vec::with_capacity(patterns.len());
    for (position, pattern) in patterns.iter().enumerate() {
        match compile_pattern(pattern) {
            Ok(pattern) => compiled.push(pattern),
            Err(reason) => sink.push(
                Diagnostic::config(
                    CODE_FILTER_PATTERN,
                    format!("invalid filters.{axis}.{list} pattern '{pattern}': {reason}"),
                )
                .with_source(source.display().to_string())
                .with_json_pointer(format!("/filters/{axis}/{list}/{position}")),
            ),
        }
    }
    compiled
}

/// Compiles one pattern string.
///
/// A pattern is a regex only when it reads as a complete regex literal: a leading `/`, a
/// non-empty body, and a closing `/` optionally followed by `i` — the sole accepted flag.
/// Everything else is exact, which is what keeps the paths axis usable: its subjects all begin
/// with `/`, so `/pets`, `/pets/{petId}` and the root path `/` must stay writable verbatim.
///
/// A near-miss like `/^get` or `/^get/g` is therefore an exact pattern rather than an error.
/// It still cannot pass silently — matching no operation is itself a hard error once a document
/// is in hand. Only a body that is syntactically not a regex fails here, because closing the
/// slashes makes the intent unambiguous.
fn compile_pattern(pattern: &str) -> Result<Pattern, String> {
    let Some(rest) = pattern.strip_prefix('/') else {
        return Ok(exact(pattern));
    };
    let (body, case_insensitive) = if let Some(body) = rest.strip_suffix("/i") {
        (body, true)
    } else if let Some(body) = rest.strip_suffix('/') {
        (body, false)
    } else {
        return Ok(exact(pattern));
    };
    if body.is_empty() {
        return Ok(exact(pattern));
    }
    // `\A`/`\z` rather than `^`/`$`: they anchor to the whole haystack even if the body turns
    // on multi-line mode itself.
    let anchored = RegexBuilder::new(&format!("\\A(?:{body})\\z"))
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|error| error.to_string())?;
    let loose = RegexBuilder::new(body)
        .case_insensitive(case_insensitive)
        .build()
        .ok();
    Ok(Pattern {
        source: pattern.to_owned(),
        kind: PatternKind::Regex { anchored, loose },
    })
}

fn exact(pattern: &str) -> Pattern {
    Pattern {
        source: pattern.to_owned(),
        kind: PatternKind::Exact,
    }
}

#[cfg(test)]
mod tests {
    use crate::inputs::InputRecorder;
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::ir::{SchemaMeta, SchemaNode, SourceRef};

    /// Parses a document graph the way the pipeline does: entry document first, then any
    /// additional files it references by name.
    fn ir_from_documents(documents: &[(&str, Value)]) -> (TempDir, Ir) {
        let temp = TempDir::new().expect("temp directory");
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&json!({
                "schemaVersion": 1,
                "input": { "path": "openapi.json" },
                "output": "generated"
            }))
            .expect("config json"),
        )
        .expect("write config");
        for (name, document) in documents {
            std::fs::write(
                temp.path().join(name),
                serde_json::to_vec(document).expect("document json"),
            )
            .expect("write document");
        }
        let resolved =
            crate::config::load_config(Some(std::path::Path::new("oasts.json")), temp.path())
                .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let graph = crate::loader::load_graph(&resolved, &mut InputRecorder::off(), &mut sink)
            .expect("graph");
        let ir = crate::parse::parse(&graph, &mut sink).expect("supported version");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        (temp, ir)
    }

    fn ir_from(document: Value) -> (TempDir, Ir) {
        ir_from_documents(&[("openapi.json", document)])
    }

    fn schema_names(ir: &Ir) -> Vec<&str> {
        ir.schemas
            .iter()
            .map(|schema| schema.name.as_str())
            .collect()
    }

    fn filters_from(value: Value) -> Filters {
        let raw: FiltersConfig = serde_json::from_value(value).expect("filters config");
        let mut sink = DiagnosticSink::new();
        let filters =
            resolve(Some(&raw), std::path::Path::new("oasts.yaml"), &mut sink).expect("filters");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        filters
    }

    /// A document covering every axis: several tags, four methods, a nested path prefix, an
    /// untagged operation, an operation with no operationId, a deprecated operation, and a
    /// webhook.
    fn selection_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": { "operationId": "listPets", "tags": ["pets"], "responses": { "204": { "description": "ok" } } },
                    "post": {
                        "operationId": "createPet",
                        "tags": ["pets", "write"],
                        "responses": { "204": { "description": "ok" } },
                        "callbacks": {
                            "petStored": {
                                "{$request.body#/url}": {
                                    "patch": {
                                        "operationId": "onPetStored",
                                        "tags": ["hooks"],
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        }
                    }
                },
                "/pets/{petId}": {
                    "delete": {
                        "operationId": "deletePet",
                        "tags": ["pets"],
                        "deprecated": true,
                        "parameters": [{ "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "204": { "description": "ok" } }
                    },
                    "put": {
                        "tags": ["misc"],
                        "parameters": [{ "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } }],
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/admin/stats": {
                    "get": { "operationId": "adminStats", "tags": ["internal"], "responses": { "204": { "description": "ok" } } }
                },
                "/health": {
                    "get": { "operationId": "health", "responses": { "204": { "description": "ok" } } }
                }
            },
            "webhooks": {
                "petCreated": {
                    "post": { "operationId": "onPet", "tags": ["events"], "responses": { "204": { "description": "ok" } } }
                }
            }
        })
    }

    fn surviving(filters: &Filters) -> (Vec<String>, usize) {
        let (_temp, ir) = ir_from(selection_document());
        let mut sink = DiagnosticSink::new();
        let filtered = apply(
            ir,
            Some(filters),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        let names = filtered
            .operations
            .iter()
            .map(|operation| {
                operation.operation_id.clone().unwrap_or_else(|| {
                    format!(
                        "{}:{}",
                        operation.method,
                        operation.path.as_deref().unwrap_or("")
                    )
                })
            })
            .collect();
        (names, filtered.webhooks.len())
    }

    fn filters_keeping_orphans() -> Filters {
        Filters {
            tags: None,
            operations: None,
            paths: None,
            methods: None,
            deprecated: true,
            orphans: true,
        }
    }

    fn pet_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Pet" } } } } } } } },
            "components": { "schemas": {
                "Pet": { "type": "object", "properties": { "kind": { "$ref": "#/components/schemas/Kind" } } },
                "Kind": { "type": "string" },
                "Unused": { "type": "object" }
            } }
        })
    }

    #[test]
    fn an_unconfigured_axis_admits_everything() {
        let (names, webhooks) = surviving(&filters_from(json!({})));
        assert_eq!(
            names,
            [
                "listPets",
                "createPet",
                "put:/pets/{petId}",
                "deletePet",
                "adminStats",
                "health"
            ]
        );
        assert_eq!(webhooks, 1);
    }

    #[test]
    fn a_path_filter_abstains_on_webhooks() {
        let (names, webhooks) =
            surviving(&filters_from(json!({ "paths": { "include": ["/pets"] } })));
        assert_eq!(names, ["listPets", "createPet"]);
        assert_eq!(
            webhooks, 1,
            "a webhook has no path, so the paths axis abstains rather than rejecting"
        );
    }

    #[test]
    fn an_untagged_operation_is_dropped_by_a_tag_include() {
        let (names, _) = surviving(&filters_from(json!({ "tags": { "include": ["pets"] } })));
        assert!(
            !names.contains(&"health".to_owned()),
            "an operation declaring no tags is applicable to the tags axis and matches nothing"
        );
        assert_eq!(names, ["listPets", "createPet", "deletePet"]);
    }

    #[test]
    fn an_operation_without_an_operation_id_abstains_from_the_operations_axis() {
        let (names, _) = surviving(&filters_from(
            json!({ "operations": { "exclude": ["listPets"] } }),
        ));
        assert!(
            names.contains(&"put:/pets/{petId}".to_owned()),
            "no operationId means the operations axis cannot judge it: {names:?}"
        );
        assert!(!names.contains(&"listPets".to_owned()));
    }

    #[test]
    fn an_operation_without_an_operation_id_is_still_filterable_by_path() {
        let (names, _) = surviving(&filters_from(
            json!({ "paths": { "include": ["/pets/{petId}"] } }),
        ));
        assert_eq!(names, ["put:/pets/{petId}", "deletePet"]);
    }

    #[test]
    fn exclude_beats_include_on_the_same_axis() {
        let (names, _) = surviving(&filters_from(json!({
            "tags": { "include": ["pets"], "exclude": ["pets"] }
        })));
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    fn an_exclude_only_axis_admits_the_rest() {
        let (names, _) = surviving(&filters_from(
            json!({ "tags": { "exclude": ["internal"] } }),
        ));
        assert_eq!(
            names,
            [
                "listPets",
                "createPet",
                "put:/pets/{petId}",
                "deletePet",
                "health"
            ]
        );
    }

    #[test]
    fn an_operation_matches_on_any_of_its_tags() {
        let (names, _) = surviving(&filters_from(json!({ "tags": { "include": ["write"] } })));
        assert_eq!(names, ["createPet"], "the second tag matches");
    }

    #[test]
    fn each_axis_filters_on_its_own_subject() {
        let (by_operation, _) = surviving(&filters_from(
            json!({ "operations": { "include": ["adminStats"] } }),
        ));
        assert_eq!(
            by_operation,
            ["put:/pets/{petId}", "adminStats"],
            "the id-less operation abstains from this axis and is admitted"
        );

        let (by_path, _) = surviving(&filters_from(
            json!({ "paths": { "exclude": ["/\\/admin\\/.*/"] } }),
        ));
        assert!(!by_path.contains(&"adminStats".to_owned()), "{by_path:?}");

        let (by_method, _) =
            surviving(&filters_from(json!({ "methods": { "include": ["post"] } })));
        assert_eq!(by_method, ["createPet"]);
    }

    #[test]
    fn exact_method_patterns_are_case_insensitive() {
        let (names, _) = surviving(&filters_from(
            json!({ "methods": { "exclude": ["DELETE"] } }),
        ));
        assert!(!names.contains(&"deletePet".to_owned()), "{names:?}");
    }

    #[test]
    fn regex_method_patterns_match_the_lowercase_form() {
        let (lower, _) = surviving(&filters_from(
            json!({ "methods": { "include": ["/de.*/"] } }),
        ));
        assert_eq!(lower, ["deletePet"]);
        let (upper, _) = surviving(&filters_from(
            json!({ "methods": { "include": ["/DE.*/"] } }),
        ));
        assert!(
            upper.is_empty(),
            "an uppercase regex matches nothing: {upper:?}"
        );
        let (insensitive, _) = surviving(&filters_from(
            json!({ "methods": { "include": ["/DE.*/i"] } }),
        ));
        assert_eq!(insensitive, ["deletePet"]);
    }

    #[test]
    fn axes_combine_with_and() {
        let (names, _) = surviving(&filters_from(json!({
            "tags": { "include": ["pets"] },
            "methods": { "exclude": ["delete"] }
        })));
        assert_eq!(names, ["listPets", "createPet"]);
    }

    #[test]
    fn a_webhook_emptied_of_operations_is_removed() {
        let (_, webhooks) = surviving(&filters_from(json!({ "tags": { "include": ["pets"] } })));
        assert_eq!(webhooks, 0, "the webhook's only operation was filtered out");
    }

    #[test]
    fn pruning_runs_over_the_survivors() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/kept": { "get": { "operationId": "kept", "tags": ["keep"], "responses": {
                    "200": { "description": "ok", "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Kept" } } } } } } },
                "/dropped": { "get": { "operationId": "dropped", "tags": ["drop"], "responses": {
                    "200": { "description": "ok", "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Dropped" } } } } } } }
            },
            "components": { "schemas": {
                "Kept": { "type": "object" },
                "Dropped": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let filtered = apply(
            ir,
            Some(&filters_from(json!({ "tags": { "include": ["keep"] } }))),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        assert_eq!(schema_names(&filtered), vec!["Kept"]);
    }

    #[test]
    fn deprecated_operations_are_kept_by_default() {
        let (names, _) = surviving(&filters_from(json!({})));
        assert!(names.contains(&"deletePet".to_owned()), "{names:?}");
    }

    #[test]
    fn deprecated_false_drops_deprecated_operations() {
        let (names, _) = surviving(&filters_from(json!({ "deprecated": false })));
        assert!(!names.contains(&"deletePet".to_owned()), "{names:?}");
        assert!(names.contains(&"listPets".to_owned()), "{names:?}");
    }

    #[test]
    fn deprecated_false_drops_deprecated_webhook_operations() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": { "operationId": "listPets", "responses": { "204": { "description": "ok" } } } } },
            "webhooks": { "old": { "post": { "operationId": "onOld", "deprecated": true, "responses": { "204": { "description": "ok" } } } } }
        }));
        let mut sink = DiagnosticSink::new();
        let filtered = apply(
            ir,
            Some(&filters_from(json!({ "deprecated": false }))),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        assert_eq!(filtered.operations.len(), 1);
        assert!(
            filtered.webhooks.is_empty(),
            "the webhook's only operation was deprecated"
        );
    }

    #[test]
    fn deprecated_false_never_drops_a_referenced_component_schema() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/OldPet" } } } } } } } },
            "components": { "schemas": {
                "OldPet": { "type": "object", "deprecated": true }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let filtered = apply(
            ir,
            Some(&filters_from(json!({ "deprecated": false }))),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        assert_eq!(
            schema_names(&filtered),
            vec!["OldPet"],
            "a schema's fate is decided by reachability alone"
        );
    }

    fn diagnose(filters: &Filters, document: Value) -> Vec<crate::diag::Diagnostic> {
        let (_temp, ir) = ir_from(document);
        let mut sink = DiagnosticSink::new();
        let _ = apply(
            ir,
            Some(filters),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        sink.as_slice().to_vec()
    }

    fn codes(diagnostics: &[crate::diag::Diagnostic]) -> Vec<&str> {
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    #[test]
    fn an_exact_pattern_matching_no_operation_is_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "operations": { "include": ["listPets", "nosuchop"] } })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
        assert_eq!(diagnostics[0].category.exit_code(), 2);
        assert_eq!(
            diagnostics[0].json_pointer.as_deref(),
            Some("/filters/operations/include/1")
        );
        let message = &diagnostics[0].message;
        assert!(message.contains("nosuchop"), "{message}");
    }

    #[test]
    fn a_regex_matching_no_operation_is_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "tags": { "include": ["/^nope/"] } })),
            selection_document(),
        );
        assert_eq!(
            codes(&diagnostics),
            [CODE_FILTER_UNMATCHED],
            "the typo is reported, not the empty result it caused"
        );
    }

    #[test]
    fn an_exclude_pattern_matching_no_operation_is_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "methods": { "exclude": ["patch"] } })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
        assert_eq!(
            diagnostics[0].json_pointer.as_deref(),
            Some("/filters/methods/exclude/0")
        );
    }

    #[test]
    fn a_pattern_that_matches_produces_no_diagnostic() {
        let diagnostics = diagnose(
            &filters_from(json!({
                "tags": { "include": ["pets"], "exclude": ["internal"] },
                "paths": { "include": ["/pets", "/pets/{petId}"] }
            })),
            selection_document(),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn a_tag_that_exists_only_on_a_webhook_counts_as_matched() {
        let diagnostics = diagnose(
            &filters_from(json!({ "tags": { "exclude": ["events"] } })),
            selection_document(),
        );
        assert!(
            diagnostics.is_empty(),
            "webhook operations are matchable subjects: {diagnostics:#?}"
        );
    }

    #[test]
    fn a_pattern_matching_only_a_deprecated_dropped_operation_counts_as_matched() {
        let diagnostics = diagnose(
            &filters_from(json!({
                "operations": { "include": ["deletePet", "listPets"] },
                "deprecated": false
            })),
            selection_document(),
        );
        assert!(
            diagnostics.is_empty(),
            "the pattern named a real operation; deprecated is a separate conjunct: {diagnostics:#?}"
        );
    }

    #[test]
    fn a_pattern_naming_nothing_still_errors_when_deprecated_is_off() {
        let diagnostics = diagnose(
            &filters_from(json!({
                "operations": { "include": ["listPets", "nosuchop"] },
                "deprecated": false
            })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
    }

    #[test]
    fn a_pattern_is_judged_against_the_whole_document_not_what_another_axis_left() {
        // `methods.include: [delete]` leaves only deletePet, whose tag is `pets`. The `internal`
        // tag still exists in the document, so the tags pattern matched something.
        let diagnostics = diagnose(
            &filters_from(json!({
                "methods": { "include": ["delete"] },
                "tags": { "exclude": ["internal"] }
            })),
            selection_document(),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    fn empty_document() -> Value {
        json!({ "openapi": "3.1.0", "info": { "title": "t", "version": "1" } })
    }

    #[test]
    fn filters_leaving_nothing_to_generate_are_an_error() {
        // Both patterns match something on their own axis, but their AND is empty.
        let diagnostics = diagnose(
            &filters_from(json!({
                "tags": { "include": ["internal"] },
                "methods": { "include": ["post"] }
            })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_EMPTY]);
        assert_eq!(diagnostics[0].category.exit_code(), 2);
        assert_eq!(diagnostics[0].json_pointer.as_deref(), Some("/filters"));
        let message = &diagnostics[0].message;
        assert!(message.contains("0 of 6 operations"), "{message}");
        assert!(message.contains("0 of 1 webhooks"), "{message}");
    }

    #[test]
    fn a_selection_axis_filtering_every_operation_out_is_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "paths": { "exclude": ["/.*/"] } })),
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": { "/pets": { "get": { "operationId": "listPets", "responses": { "204": { "description": "ok" } } } } }
            }),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_EMPTY]);
    }

    #[test]
    fn a_path_exclude_cannot_empty_a_document_that_still_has_webhooks() {
        let diagnostics = diagnose(
            &filters_from(json!({ "paths": { "exclude": ["/.*/"] } })),
            selection_document(),
        );
        assert!(
            diagnostics.is_empty(),
            "the webhook abstains from the paths axis and survives: {diagnostics:#?}"
        );
    }

    #[test]
    fn zero_operations_with_a_surviving_webhook_is_not_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "tags": { "include": ["events"] } })),
            selection_document(),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn orphans_only_filters_never_trip_the_empty_result_rule() {
        let diagnostics = diagnose(&filters_from(json!({ "orphans": true })), empty_document());
        assert!(
            diagnostics.is_empty(),
            "no selection axis is declared: {diagnostics:#?}"
        );
    }

    #[test]
    fn a_document_with_no_operations_is_untouched_without_filters() {
        let (_temp, ir) = ir_from(empty_document());
        let mut sink = DiagnosticSink::new();
        let _ = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn an_unmatched_pattern_reports_as_a_typo_not_an_empty_result() {
        let diagnostics = diagnose(
            &filters_from(json!({ "operations": { "include": ["nosuchop"] } })),
            selection_document(),
        );
        assert_eq!(
            codes(&diagnostics),
            [CODE_FILTER_UNMATCHED],
            "a typo reports as a typo, not as an empty result"
        );
    }

    #[test]
    fn a_naming_override_naming_a_filtered_out_declaration_is_not_a_typo() {
        // Overrides are judged against the document as written, not against what survived.
        // Otherwise default-on pruning turns a previously valid config into an error, and the
        // message blames the override rather than the pruning that caused it.
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/kept": { "get": { "operationId": "kept", "tags": ["keep"], "responses": {
                    "200": { "description": "ok", "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Kept" } } } } } } },
                "/dropped": {
                    "get": {
                        "operationId": "dropped",
                        "tags": ["drop"],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Dropped" }
                                    }
                                }
                            }
                        },
                        "callbacks": {
                            "droppedCallback": {
                                "{$request.body#/url}": {
                                    "post": {
                                        "operationId": "onDropped",
                                        "responses": { "204": { "description": "ok" } },
                                        "callbacks": {
                                            "nestedCallback": {
                                                "{$request.body#/ack}": {
                                                    "post": {
                                                        "operationId": "onNested",
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
            },
            "webhooks": { "goneHook": { "post": { "operationId": "onGone", "tags": ["drop"], "responses": { "204": { "description": "ok" } } } } },
            "components": { "schemas": {
                "Kept": { "type": "object" },
                "Dropped": { "type": "object" },
                "NeverReached": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let filtered = apply(
            ir,
            Some(&filters_from(json!({ "tags": { "include": ["keep"] } }))),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );

        assert_eq!(schema_names(&filtered), vec!["Kept"]);
        assert_eq!(filtered.removed.schemas, ["Dropped", "NeverReached"]);
        assert_eq!(filtered.removed.operations, ["dropped"]);
        assert!(
            !filtered.removed.operations.contains(&"onGone".to_owned()),
            "a webhook operation id was never addressable by an operations override"
        );
        assert_eq!(filtered.removed.webhooks, ["goneHook"]);
        assert_eq!(
            filtered.removed.callbacks,
            ["droppedCallback", "nestedCallback"],
            "callbacks are addressable at any depth, so they are recorded at any depth"
        );
    }

    #[test]
    fn a_pattern_naming_only_a_callback_operation_says_so() {
        // Callback operations are never filtered independently of the operation that declares
        // them, so such a pattern is a real mistake — but reporting it as naming nothing would
        // send the user hunting for an operationId their document plainly contains.
        let diagnostics = diagnose(
            &filters_from(json!({ "operations": { "exclude": ["onPetStored"] } })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
        let message = &diagnostics[0].message;
        assert!(message.contains("onPetStored"), "{message}");
        assert!(message.contains("callback"), "{message}");
    }

    #[test]
    fn a_pattern_naming_nothing_at_all_still_says_that() {
        let diagnostics = diagnose(
            &filters_from(json!({ "operations": { "exclude": ["nosuchop"] } })),
            selection_document(),
        );
        let message = &diagnostics[0].message;
        assert!(message.contains("matches no operation"), "{message}");
        assert!(!message.contains("callback"), "{message}");
    }

    #[test]
    fn a_tag_used_only_by_a_callback_operation_reports_the_callback_reason() {
        let diagnostics = diagnose(
            &filters_from(json!({ "tags": { "exclude": ["hooks"] } })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
        let message = &diagnostics[0].message;
        assert!(message.contains("callback"), "{message}");
    }

    #[test]
    fn an_anchored_regex_that_misses_a_prefix_explains_itself() {
        let diagnostics = diagnose(
            &filters_from(json!({ "paths": { "exclude": ["/^\\/admin\\//"] } })),
            selection_document(),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_UNMATCHED]);
        let message = &diagnostics[0].message;
        assert!(message.contains("whole subject"), "{message}");
    }

    #[test]
    fn deprecated_false_counts_as_a_selection_axis() {
        let filters = filters_from(json!({ "deprecated": false }));
        assert!(
            filters.declares_selection_axis(),
            "deprecated: false removes operations, so it selects"
        );
        assert!(!filters_from(json!({ "orphans": true })).declares_selection_axis());
        assert!(!filters_from(json!({ "deprecated": true })).declares_selection_axis());
    }

    #[test]
    fn deprecated_false_emptying_the_document_is_an_error() {
        let diagnostics = diagnose(
            &filters_from(json!({ "deprecated": false })),
            json!({
                "openapi": "3.1.0",
                "info": { "title": "t", "version": "1" },
                "paths": { "/pets": { "get": {
                    "operationId": "listPets",
                    "deprecated": true,
                    "responses": { "204": { "description": "ok" } }
                } } }
            }),
        );
        assert_eq!(codes(&diagnostics), [CODE_FILTER_EMPTY]);
    }

    #[test]
    fn pruning_everything_away_is_reported_even_without_a_filters_block() {
        // A schema-library document with no filters at all: pruning empties the emit set, and
        // the manifest then deletes whatever was generated before. Exit stays 0 — existing
        // configs keep working — but it cannot be silent.
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": {
                "Pet": { "type": "object" },
                "Owner": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(pruned.schemas.is_empty());
        assert!(!sink.has_errors(), "a warning, not an error");
        let diagnostics = sink.as_slice();
        assert_eq!(codes(diagnostics), [CODE_PRUNED_EVERYTHING]);
        let message = &diagnostics[0].message;
        assert!(message.contains('2'), "{message}");
    }

    #[test]
    fn pruning_nothing_away_reports_nothing() {
        let (_temp, ir) = ir_from(pet_document());
        let mut sink = DiagnosticSink::new();
        let _ = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn a_discriminator_mapping_target_is_a_reachability_root() {
        // A mapping entry names a component the union's branches never `$ref`. Pruning it away
        // leaves the discriminator pointing at nothing and the union missing a tag.
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Pet" } } } } } } } },
            "components": { "schemas": {
                "Pet": {
                    "oneOf": [{ "$ref": "#/components/schemas/Dog" }],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": { "dog": "#/components/schemas/Dog", "cat": "#/components/schemas/Cat" }
                    }
                },
                "Dog": { "type": "object", "properties": { "kind": { "type": "string" } } },
                "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
                "Unused": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(schema_names(&pruned), vec!["Pet", "Dog", "Cat"]);
    }

    #[test]
    fn a_bare_mapping_name_resolves_like_a_component_reference() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Pet" } } } } } } } },
            "components": { "schemas": {
                "Pet": {
                    "oneOf": [{ "$ref": "#/components/schemas/Dog" }],
                    "discriminator": { "propertyName": "kind", "mapping": { "cat": "Cat" } }
                },
                "Dog": { "type": "object" },
                "Cat": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        let names = schema_names(&pruned);
        assert!(names.contains(&"Cat"), "{names:?}");
    }

    #[test]
    fn a_mapping_target_in_another_document_is_a_reachability_root() {
        let (_temp, ir) = ir_from_documents(&[
            (
                "openapi.json",
                json!({
                    "openapi": "3.1.0",
                    "info": { "title": "t", "version": "1" },
                    "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                        "200": { "description": "ok", "content": { "application/json": {
                            "schema": { "$ref": "#/components/schemas/Pet" } } } } } } } },
                    "components": { "schemas": {
                        "Pet": {
                            "oneOf": [{ "$ref": "external.json#/Dog" }],
                            "discriminator": {
                                "propertyName": "kind",
                                "mapping": { "cat": "external.json#/Cat" }
                            }
                        }
                    } }
                }),
            ),
            (
                "external.json",
                json!({ "Dog": { "type": "object" }, "Cat": { "type": "object" } }),
            ),
        ]);
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        let names = schema_names(&pruned);
        assert!(
            names.iter().any(|name| name.contains("Cat")),
            "a mapping target in another document survives: {names:?}"
        );
    }

    #[test]
    fn pruning_every_component_is_not_reported_while_an_operation_survives() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/ping": { "get": { "operationId": "ping", "responses": { "204": { "description": "ok" } } } } },
            "components": { "schemas": { "Unused": { "type": "object" } } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(pruned.schemas.is_empty());
        assert_eq!(pruned.operations.len(), 1);
        let diagnostics = sink.as_slice();
        assert!(
            diagnostics.is_empty(),
            "there is still output: {diagnostics:#?}"
        );
    }

    #[test]
    fn a_surviving_webhook_alone_keeps_the_pruned_everything_warning_quiet() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "webhooks": { "ping": { "post": { "operationId": "onPing", "responses": { "204": { "description": "ok" } } } } },
            "components": { "schemas": { "Unused": { "type": "object" } } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(pruned.schemas.is_empty(), "the component is unreachable");
        assert_eq!(pruned.webhooks.len(), 1);
        let diagnostics = sink.as_slice();
        assert!(
            diagnostics.is_empty(),
            "the webhook still generates: {diagnostics:#?}"
        );
    }

    #[test]
    fn unreachable_components_are_pruned() {
        let (_temp, ir) = ir_from(pet_document());
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            schema_names(&pruned),
            vec!["Pet", "Kind"],
            "Unused is dropped, Kind is reached transitively"
        );
    }

    #[test]
    fn orphans_true_keeps_unreachable_components() {
        let (_temp, ir) = ir_from(pet_document());
        let mut sink = DiagnosticSink::new();
        let kept = apply(
            ir,
            Some(&filters_keeping_orphans()),
            std::path::Path::new("oasts.yaml"),
            &mut sink,
        );
        assert_eq!(schema_names(&kept), vec!["Pet", "Kind", "Unused"]);
    }

    #[test]
    fn pruning_preserves_source_order() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/x": { "get": { "operationId": "readX", "responses": {
                "200": { "description": "ok", "content": { "application/json": { "schema": {
                    "type": "object",
                    "properties": {
                        "c": { "$ref": "#/components/schemas/C" },
                        "a": { "$ref": "#/components/schemas/A" }
                    } } } } } } } } },
            "components": { "schemas": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(
            schema_names(&pruned),
            vec!["A", "C"],
            "survivors keep document order regardless of discovery order"
        );
    }

    #[test]
    fn a_reference_cycle_terminates() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/n": { "get": { "operationId": "readNode", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Node" } } } } } } } },
            "components": { "schemas": {
                "Node": { "type": "object", "properties": {
                    "next": { "$ref": "#/components/schemas/Node" },
                    "peer": { "$ref": "#/components/schemas/Peer" } } },
                "Peer": { "type": "object", "properties": { "back": { "$ref": "#/components/schemas/Node" } } },
                "Detached": { "type": "string" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(schema_names(&pruned), vec!["Node", "Peer"]);
    }

    #[test]
    fn webhooks_are_reachability_roots() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "webhooks": { "petCreated": { "post": { "operationId": "onPet", "responses": {
                "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Event" } } } } } } } },
            "components": { "schemas": {
                "Event": { "type": "object" },
                "Unused": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(schema_names(&pruned), vec!["Event"]);
    }

    #[test]
    fn callbacks_of_surviving_operations_are_roots() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/subscribe": { "post": {
                "operationId": "subscribe",
                "responses": { "204": { "description": "ok" } },
                "callbacks": { "onEvent": { "{$request.body#/url}": { "post": {
                    "requestBody": { "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Callback" } } } },
                    "responses": { "204": { "description": "ok" } } } } } }
            } } },
            "components": { "schemas": {
                "Callback": { "type": "object" },
                "Unused": { "type": "object" }
            } }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(schema_names(&pruned), vec!["Callback"]);
    }

    #[test]
    fn a_reference_naming_no_schema_is_skipped_rather_than_panicking() {
        // Every reference the parser produces today resolves to a NamedSchema — external and
        // subtree targets are both materialized, and an unresolvable `$ref` fails at load. The
        // walk still must not assume it: a reference that names no schema has nothing to mark
        // and nothing to descend into, so it is skipped. Driven through a synthetic IR because
        // no document can currently reach it.
        let dangling = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "openapi.json".to_owned(),
                json_pointer: "/components/schemas/Absent".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let mut ir = Ir {
            operations: vec![Operation {
                method: "get".to_owned(),
                path_template: Vec::new(),
                tags: Vec::new(),
                path: Some("/pets".to_owned()),
                operation_id: Some("listPets".to_owned()),
                summary: None,
                description: None,
                deprecated: false,
                external_docs: None,
                parameters: vec![crate::ir::Param {
                    name: "filter".to_owned(),
                    location: crate::ir::ParamLocation::Query,
                    required: false,
                    deprecated: false,
                    description: None,
                    schema: dangling,
                    style: None,
                    explode: None,
                    allow_reserved: false,
                    content_media_type: None,
                    source: SourceRef::new("openapi.json", "/paths/~1pets/get/parameters/0"),
                }],
                request_body: None,
                responses: Vec::new(),
                callbacks: Vec::new(),
                servers: Vec::new(),
                security: None,
                source: SourceRef::new("openapi.json", "/paths/~1pets/get"),
            }],
            schemas: vec![crate::ir::NamedSchema {
                name: "Present".to_owned(),
                schema: SchemaNode::Any {
                    meta: SchemaMeta::default(),
                },
                source: SourceRef::new("openapi.json", "/components/schemas/Present"),
            }],
            ..Ir::default()
        };

        prune_unreachable_schemas(&mut ir);

        assert!(
            ir.schemas.is_empty(),
            "the dangling reference marks nothing reachable"
        );
    }

    #[test]
    fn a_ref_that_is_not_a_named_schema_is_skipped_rather_than_panicking() {
        let (_temp, ir) = ir_from(json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": {
                "operationId": "listPets",
                "parameters": [{ "$ref": "#/components/parameters/Limit" }],
                "responses": { "200": { "description": "ok", "content": { "application/json": {
                    "schema": { "$ref": "#/components/schemas/Pet" } } } } }
            } } },
            "components": {
                "parameters": { "Limit": { "name": "limit", "in": "query", "schema": { "$ref": "#/components/schemas/Count" } } },
                "schemas": {
                    "Pet": { "type": "object" },
                    "Count": { "type": "integer" },
                    "Unused": { "type": "object" }
                }
            }
        }));
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        assert_eq!(
            schema_names(&pruned),
            vec!["Pet", "Count"],
            "an inlined parameter still carries its schema reference"
        );
    }

    #[test]
    fn a_materialized_external_schema_is_kept_when_an_operation_needs_it() {
        let (_temp, ir) = ir_from_documents(&[
            (
                "openapi.json",
                json!({
                    "openapi": "3.1.0",
                    "info": { "title": "t", "version": "1" },
                    "paths": { "/pets": { "get": { "operationId": "listPets", "responses": {
                        "200": { "description": "ok", "content": { "application/json": {
                            "schema": { "$ref": "external.json#/Kept" } } } } } } } },
                    "components": { "schemas": { "Unused": { "type": "object" } } }
                }),
            ),
            (
                "external.json",
                json!({ "Kept": { "type": "object", "properties": { "id": { "type": "string" } } } }),
            ),
        ]);
        let mut sink = DiagnosticSink::new();
        let pruned = apply(ir, None, std::path::Path::new("oasts.yaml"), &mut sink);
        let names = schema_names(&pruned);
        assert!(
            names.iter().any(|name| name.contains("Kept")),
            "a materialized external schema an operation references must survive: {names:?}"
        );
        assert!(
            !names.contains(&"Unused"),
            "the unreferenced local component is still pruned: {names:?}"
        );
    }

    #[test]
    fn the_collectors_are_reachable_from_the_filter_module() {
        let reference = SchemaNode::Ref {
            target: SchemaRef {
                source_id: "openapi.json".to_owned(),
                json_pointer: "/components/schemas/Pet".to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let mut refs = Vec::new();
        collect_schema_refs(&reference, &mut refs);
        assert_eq!(refs.len(), 1);

        let operation = Operation {
            method: "get".to_owned(),
            path_template: Vec::new(),
            tags: Vec::new(),
            path: Some("/pets".to_owned()),
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
            source: SourceRef::new("openapi.json", "/paths/~1pets/get"),
        };
        let mut refs = Vec::new();
        collect_operation_refs(&operation, &mut refs);
        assert!(refs.is_empty());
    }

    fn compiled(pattern: &str) -> Pattern {
        compile_pattern(pattern).expect("pattern should compile")
    }

    #[test]
    fn an_exact_pattern_matches_the_whole_subject() {
        let pattern = compiled("listPets");
        assert!(matches!(pattern.kind(), PatternKind::Exact));
        assert_eq!(pattern.source(), "listPets");
        assert!(pattern.matches("listPets"));
        assert!(!pattern.matches("listPetsById"));
    }

    #[test]
    fn a_path_shaped_pattern_stays_exact() {
        for pattern in ["/pets", "/", "/pets/{petId}", "/^get"] {
            let compiled = compiled(pattern);
            assert!(
                matches!(compiled.kind(), PatternKind::Exact),
                "{pattern} should be exact"
            );
            assert!(compiled.matches(pattern));
        }
    }

    #[test]
    fn a_regex_pattern_matches_the_whole_subject() {
        let pattern = compiled("/get/");
        assert!(matches!(pattern.kind(), PatternKind::Regex { .. }));
        assert!(pattern.matches("get"));
        assert!(
            !pattern.matches("forgetPet"),
            "a regex matches the whole subject, so it cannot silently over-select"
        );
        assert!(compiled("/get.*Pets/").matches("getAllPets"));
        assert!(!compiled("/get.*Pets/").matches("forgetPets"));
        assert!(
            compiled("/.*get.*/").matches("forgetPet"),
            "substring needs .*"
        );
    }

    #[test]
    fn a_trailing_slash_path_pattern_cannot_over_select() {
        // `/pets/` is a legal OpenAPI path that also reads as a regex literal. Because matching
        // is whole-subject, the misread cannot silently take `/pets` and `/pets/{petId}` with it
        // — it matches nothing, which the unmatched-pattern rule then reports.
        let pattern = compiled("/pets/");
        assert!(matches!(pattern.kind(), PatternKind::Regex { .. }));
        assert!(!pattern.matches("/pets/{petId}"));
        assert!(!pattern.matches("/pets/"));
        assert!(!pattern.matches("/pets"));
        assert!(pattern.matches("pets"), "the body is still `pets`");
    }

    #[test]
    fn a_prefix_regex_reports_that_matching_is_whole_subject() {
        let pattern = compiled("/^\\/admin\\//");
        assert!(
            !pattern.matches("/admin/stats"),
            "anchored, so a prefix does not match"
        );
        assert!(
            pattern.matches_loosely("/admin/stats"),
            "the unanchored form would have matched, which the diagnostic reports"
        );
        assert!(compiled("/^\\/admin\\/.*/").matches("/admin/stats"));
    }

    #[test]
    fn the_i_flag_matches_case_insensitively() {
        let pattern = compiled("/GET.*/i");
        assert!(pattern.matches("getPets"));
        assert!(!compiled("/GET.*/").matches("getPets"));
    }

    #[test]
    fn a_near_miss_regex_literal_is_exact_rather_than_an_error() {
        for pattern in ["/^get", "/^pet/x", "/^get/gi", "//", "/i", "//i"] {
            assert!(
                matches!(compiled(pattern).kind(), PatternKind::Exact),
                "{pattern} does not read as a complete regex literal"
            );
        }
    }

    #[test]
    fn an_uncompilable_body_is_rejected() {
        let error = compile_pattern("/[unclosed/").expect_err("body should not compile");
        assert!(!error.is_empty());
    }

    #[test]
    fn exact_method_patterns_ignore_ascii_case() {
        assert!(compiled("DELETE").matches_ignoring_ascii_case("delete"));
        assert!(compiled("Delete").matches_ignoring_ascii_case("delete"));
        assert!(!compiled("DELETE").matches_ignoring_ascii_case("get"));
        assert!(
            compiled("/^delete$/").matches_ignoring_ascii_case("delete"),
            "regex patterns match the lowercase canonical form"
        );
        assert!(!compiled("/DELETE/").matches_ignoring_ascii_case("delete"));
    }

    #[test]
    fn patterns_compare_on_their_source_text() {
        assert_eq!(compiled("/^get/"), compiled("/^get/"));
        assert_ne!(compiled("/^get/"), compiled("/^get/i"));
        assert_eq!(compiled("listPets"), compiled("listPets"));
    }
}
