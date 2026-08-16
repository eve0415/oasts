//! Local OpenAPI document loading and reference resolution.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::ResolvedConfig;
use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::syntax::parse_yaml_document_value;

const CODE_DOCUMENT_IO: &str = "OASTS1003";
const CODE_REF_ESCAPE: &str = "OASTS2001";
const CODE_NON_UNICODE_PATH: &str = "OASTS2002";
const CODE_DOCUMENT_PARSE: &str = "OASTS2003";
const CODE_INVALID_REFERENCE: &str = "OASTS2004";
const CODE_POINTER: &str = "OASTS2005";
const CODE_NON_SCHEMA_CYCLE: &str = "OASTS2006";
const CODE_EXTENSION_FALLBACK: &str = "OASTS2007";
const CODE_MAX_DOCUMENT_BYTES: &str = "OASTS2011";
const CODE_MAX_TOTAL_BYTES: &str = "OASTS2012";
const CODE_MAX_DOCUMENTS: &str = "OASTS2013";
const CODE_MAX_REF_DEPTH: &str = "OASTS2014";
const CODE_REMOTE_UNSUPPORTED: &str = "OASTS9201";
const SERDE_JSON_NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// Stable index of a document within one graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DocId(usize);

impl DocId {
    /// Returns the graph-local numeric index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// One parsed local document and its source identity.
#[derive(Clone, Debug)]
pub struct Document {
    pub id: DocId,
    pub canonical_path: PathBuf,
    pub source_id: String,
    pub value: Value,
    /// Digest of the source bytes, taken at load; the bytes themselves are not
    /// retained — everything downstream needs only the parsed value and this hash.
    pub sha256: [u8; 32],
}

/// Location of a resolved node in the document graph.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeLocation {
    pub doc_id: DocId,
    pub json_pointer: String,
}

type AnchorRegistry = HashMap<(String, String), NodeLocation>;

/// Every identifier the schema resources in a graph declare.
///
/// The three dynamic maps are ordered, not hashed: the dynamic-reference analysis *iterates* them
/// to count how many resources declare one anchor name, and an iteration order that varies between
/// runs would make generated output vary with it. `anchors` stays a `HashMap` because it is only
/// ever point-queried.
#[derive(Clone, Debug, Default)]
struct IdentifierRegistry {
    /// Keyed `(resource base URI, anchor name)`, populated by both `$anchor` and `$dynamicAnchor`
    /// — a `$dynamicAnchor` also creates an ordinary plain-name fragment, so `$ref: "#name"` finds
    /// it. The reverse does not hold: a plain `$anchor` is never eligible for dynamic resolution.
    anchors: AnchorRegistry,
    /// Keyed `(anchor name, resource base URI)` — name first so all resources declaring one name
    /// form a contiguous range.
    dynamic_anchors: BTreeMap<(String, String), NodeLocation>,
    /// Resource base URI -> the schema object carrying `$recursiveAnchor: true`.
    recursive_anchors: BTreeMap<String, NodeLocation>,
    /// Resource base URI -> the schema resource root declared by `$id`.
    resources: BTreeMap<String, NodeLocation>,
}

/// What a `$dynamicRef` or `$recursiveRef` can be lowered to, decided at load time.
///
/// Dynamic resolution is only genuinely dynamic when two or more schema *resources* declare the
/// same anchor — a resource being something `$id` creates. Every other shape collapses to a single
/// target that no evaluation path can change, which is why the compiler can lower most of these
/// keywords to an ordinary reference instead of refusing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicResolution {
    /// Exactly one schema object is the target on every evaluation path.
    Pinned(NodeLocation),
    /// The bookending condition failed, so the keyword behaves exactly like `$ref`.
    Plain,
    /// Two or more schema resources declare the anchor, so the target depends on the path taken
    /// through the schema and no single schema can stand in for it.
    PathDependent { declaring_resources: usize },
    /// A `$recursiveRef` whose initial target is the document root of an OpenAPI document — the
    /// OpenAPI Object, which is not a schema.
    NonSchemaRoot,
}

/// Semantic position in which a reference appeared.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PositionKind {
    Schema,
    NonSchema,
}

/// A `$ref` edge retained without flattening either endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceEdge {
    pub from: NodeLocation,
    pub to: NodeLocation,
    pub reference: String,
    pub position: PositionKind,
}

/// Borrowed resolved node handle.
#[derive(Clone, Debug)]
pub struct Node<'a> {
    pub doc_id: DocId,
    pub json_pointer: String,
    pub value: &'a Value,
}

#[derive(Clone, Debug)]
struct AllowRoot {
    canonical_path: PathBuf,
}

/// Parsed local documents plus their retained reference edges.
#[derive(Clone, Debug)]
pub struct DocumentGraph {
    documents: Vec<Document>,
    path_to_id: HashMap<PathBuf, DocId>,
    identifiers: IdentifierRegistry,
    entry_id: DocId,
    edges: Vec<ReferenceEdge>,
    workspace_root: PathBuf,
    allow_roots: Vec<AllowRoot>,
    max_ref_depth: u64,
}

impl DocumentGraph {
    /// Returns the entry document.
    #[must_use]
    pub fn entry(&self) -> &Document {
        &self.documents[self.entry_id.0]
    }

    /// Returns a document by graph-local ID.
    #[must_use]
    pub fn document(&self, id: DocId) -> Option<&Document> {
        self.documents.get(id.0)
    }

    /// Returns all documents in graph insertion order.
    #[must_use]
    pub fn documents(&self) -> &[Document] {
        &self.documents
    }

    /// Returns the configured maximum number of reference hops.
    #[must_use]
    pub const fn max_ref_depth(&self) -> u64 {
        self.max_ref_depth
    }

    /// Returns the node at `json_pointer` inside `doc_id` without re-resolving
    /// a reference URI, for callers that already hold a resolved target.
    #[must_use]
    pub fn node_at(&self, doc_id: DocId, json_pointer: &str) -> Option<Node<'_>> {
        let document = self.document(doc_id)?;
        let value = evaluate_pointer(&document.value, json_pointer).ok()?;
        Some(Node {
            doc_id,
            json_pointer: json_pointer.to_owned(),
            value,
        })
    }

    /// Returns retained reference edges.
    #[must_use]
    pub fn edges(&self) -> &[ReferenceEdge] {
        &self.edges
    }

    /// Resolves a reference against one document's retrieval URI.
    pub fn resolve(&self, base_doc: DocId, reference: &str) -> Result<Node<'_>, Diagnostic> {
        self.resolve_from(base_doc, "", reference)
    }

    /// Resolves a reference written at `json_pointer` against the base URI in force *there*.
    ///
    /// The difference from [`Self::resolve`] is the `$id` chain. `$id` "identifies a schema
    /// resource with its canonical URI" and "the absolute-URI also serves as the base URI for
    /// relative URI-references in keywords within the schema resource" (2020-12 §8.2.1) — so a
    /// reference inside an `$id`-bearing subtree resolves against that `$id`, not against the file
    /// the subtree happens to live in.
    ///
    /// Identity is checked before retrieval: a URI naming a schema resource already in the graph is
    /// answered from the resource registry and never reaches the filesystem. That is what lets a
    /// bundled document carry an absolute `$id` without it being read as a request to fetch a
    /// remote document. The path-authorization boundary is untouched — it still guards every
    /// resolution that does reach the filesystem.
    pub fn resolve_from(
        &self,
        base_doc: DocId,
        json_pointer: &str,
        reference: &str,
    ) -> Result<Node<'_>, Diagnostic> {
        let Some(base_document) = self.document(base_doc) else {
            return Err(missing_document_error(base_doc));
        };
        let base = self.schema_base_at(base_doc, json_pointer)?;
        let target_url = resolve_identity_uri(
            &base,
            reference,
            Some(&base_document.source_id),
            Some(json_pointer),
        )?;
        if let Some(target) = registered_anchor_location(
            &target_url,
            &self.identifiers.anchors,
            Some(&base_document.source_id),
            None,
        )? {
            return self.node_from_location(target);
        }
        if let Some(root) = registered_resource(&self.identifiers, &target_url) {
            let within = pointer_from_url(&target_url, Some(&base_document.source_id), None)?;
            return self.node_from_location(NodeLocation {
                doc_id: root.doc_id,
                json_pointer: format!("{}{within}", root.json_pointer),
            });
        }
        let target_id = if reference.starts_with('#') {
            base_doc
        } else {
            let target_path =
                local_path_from_url(&target_url, Some(&base_document.source_id), None)?;
            let canonical = fs::canonicalize(&target_path).map_err(|error| {
                io_error(
                    CODE_DOCUMENT_IO,
                    format!("failed to canonicalize referenced document: {error}"),
                    Some(&base_document.source_id),
                    None,
                )
            })?;
            authorize_path(&canonical, &self.workspace_root, &self.allow_roots).map_err(
                |message| {
                    input_error(
                        CODE_REF_ESCAPE,
                        message,
                        Some(&base_document.source_id),
                        None,
                    )
                },
            )?;
            let Some(target_id) = self.path_to_id.get(&canonical).copied() else {
                return Err(io_error(
                    CODE_DOCUMENT_IO,
                    format!(
                        "referenced document '{}' is not part of the loaded graph",
                        canonical.display()
                    ),
                    Some(&base_document.source_id),
                    None,
                ));
            };
            target_id
        };
        let target = pointer_or_anchor(
            &target_url,
            target_id,
            &self.identifiers.anchors,
            Some(&base_document.source_id),
            None,
        )?;
        self.node_from_location(target)
    }

    /// Resolves a `$dynamicRef` written at `json_pointer` to what it can be lowered to.
    ///
    /// JSON Schema 2020-12 §8.2.3.2: the value is first resolved against the current base URI, and
    /// only *"if the initially resolved starting point URI includes a fragment that was created by
    /// the `$dynamicAnchor` keyword"* does the dynamic walk happen at all — *"otherwise, its
    /// behavior is identical to `$ref`"*. That condition is decidable at load time, and when it
    /// holds, the walk's answer is fixed unless two or more resources declare the same name.
    pub fn resolve_dynamic_ref(
        &self,
        base_doc: DocId,
        json_pointer: &str,
        reference: &str,
    ) -> Result<DynamicResolution, Diagnostic> {
        let base = self.schema_base_at(base_doc, json_pointer)?;
        let source_id = self
            .document(base_doc)
            .map(|document| document.source_id.as_str());
        let target_url = resolve_identity_uri(&base, reference, source_id, Some(json_pointer))?;
        let Some(fragment) = target_url.fragment() else {
            return Ok(DynamicResolution::Plain);
        };
        // A JSON Pointer fragment, or none at all, cannot have been created by `$dynamicAnchor`.
        if fragment.is_empty() || fragment.starts_with('/') {
            return Ok(DynamicResolution::Plain);
        }
        let name = percent_decode(fragment).map_err(|message| {
            input_error(
                CODE_INVALID_REFERENCE,
                message,
                source_id,
                Some(json_pointer),
            )
        })?;
        let resource = resource_base_uri(&target_url);
        let Some(pinned) = self
            .identifiers
            .dynamic_anchors
            .get(&(name.clone(), resource))
        else {
            // Bookending fails: the initial target is a plain `$anchor`, or nothing. Identical
            // to `$ref`, and the caller lowers it through the ordinary reference path.
            return Ok(DynamicResolution::Plain);
        };
        Ok(self.pin_or_defer(self.resources_declaring(&name), pinned))
    }

    /// Resolves a `$recursiveRef: "#"` written at `json_pointer`.
    ///
    /// JSON Schema 2019-09 §8.2.4.2.1 resolves `"#"` against the current base URI and then examines
    /// *that* schema for `$recursiveAnchor`. Because the keyword's value is restricted to `"#"`,
    /// the initial target is always a schema *resource root* — so an anchor sitting anywhere else
    /// can never arm the mechanism, and in an OpenAPI document with no `$id` the root reached this
    /// way is the OpenAPI Object rather than a schema at all.
    pub fn resolve_recursive_ref(
        &self,
        base_doc: DocId,
        json_pointer: &str,
    ) -> Result<DynamicResolution, Diagnostic> {
        let base = self.schema_base_at(base_doc, json_pointer)?;
        let resource = resource_base_uri(&base);
        let root = match self.identifiers.resources.get(&resource) {
            Some(root) => root.clone(),
            None => {
                // No `$id` governs this position, so the resource is the whole document. In an
                // OpenAPI document that root is the OpenAPI Object — a known non-schema, which
                // §9.4.2 leaves as undefined behaviour rather than a resolvable target.
                // `schema_base_at` above already indexed this document, so the ID is known good.
                let document = &self.documents[base_doc.0];
                if document.value.get("openapi").is_some() {
                    return Ok(DynamicResolution::NonSchemaRoot);
                }
                NodeLocation {
                    doc_id: base_doc,
                    json_pointer: String::new(),
                }
            }
        };
        let armed = self
            .node_at(root.doc_id, &root.json_pointer)
            .and_then(|node| node.value.get("$recursiveAnchor").and_then(Value::as_bool))
            .unwrap_or(false);
        if !armed {
            // "in the absence of $recursiveAnchor ... $recursiveRef's behavior is identical to
            // that of $ref."
            return Ok(DynamicResolution::Plain);
        }
        Ok(self.pin_or_defer(self.identifiers.recursive_anchors.len(), &root))
    }

    /// The base URI in force at a schema node.
    ///
    /// Walking the `$id` chain can only change the answer if some `$id` exists, and a document
    /// that declares none — which is nearly all of them — always answers with its own file URI.
    /// Checking the resource registry first keeps the common case free of the walk.
    fn schema_base_at(&self, doc_id: DocId, json_pointer: &str) -> Result<Url, Diagnostic> {
        if self.identifiers.resources.is_empty() {
            // Indexed directly, exactly as `base_at` below would: a graph-local ID always names a
            // loaded document, and a second fallible lookup would only add a branch nothing can
            // reach.
            let document = &self.documents[doc_id.0];
            return file_url(&document.canonical_path).map_err(|message| {
                input_error(
                    CODE_INVALID_REFERENCE,
                    message,
                    Some(&document.source_id),
                    Some(json_pointer),
                )
            });
        }
        base_at(&self.documents, doc_id, json_pointer, PositionKind::Schema)
    }

    /// Counts the schema resources declaring one `$dynamicAnchor` name.
    ///
    /// The map is keyed name-first precisely so this is a contiguous range scan.
    fn resources_declaring(&self, name: &str) -> usize {
        self.identifiers
            .dynamic_anchors
            .range((name.to_owned(), String::new())..)
            .take_while(|((anchor, _), _)| anchor == name)
            .count()
    }

    /// One declaring resource means the dynamic-scope walk has one candidate and therefore one
    /// answer, whatever path evaluation took to get here; more than one means the answer genuinely
    /// depends on that path.
    ///
    /// Deliberately conservative: it does not ask whether a second declaring resource can actually
    /// reach this keyword, so it defers some references that a reachability analysis would pin.
    /// Erring this way can only refuse work, never mis-resolve it.
    fn pin_or_defer(&self, declaring_resources: usize, pinned: &NodeLocation) -> DynamicResolution {
        if declaring_resources <= 1 {
            DynamicResolution::Pinned(pinned.clone())
        } else {
            DynamicResolution::PathDependent {
                declaring_resources,
            }
        }
    }

    fn node_from_location(&self, target: NodeLocation) -> Result<Node<'_>, Diagnostic> {
        let target_document = &self.documents[target.doc_id.0];
        let value =
            evaluate_pointer(&target_document.value, &target.json_pointer).map_err(|message| {
                input_error(
                    CODE_POINTER,
                    message,
                    Some(&target_document.source_id),
                    Some(&target.json_pointer),
                )
            })?;
        Ok(Node {
            doc_id: target.doc_id,
            json_pointer: target.json_pointer,
            value,
        })
    }

    /// Returns sorted logical source IDs and raw SHA-256 digests.
    #[must_use]
    pub fn source_tuples(&self) -> Vec<(String, [u8; 32])> {
        let mut tuples = self
            .documents
            .iter()
            .map(|document| (document.source_id.clone(), document.sha256))
            .collect::<Vec<_>>();
        tuples.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        tuples
    }
}

/// Loads the configured local document graph, reporting the first load failure.
pub fn load_graph(config: &ResolvedConfig, sink: &mut DiagnosticSink) -> Option<DocumentGraph> {
    match GraphBuilder::new(config).and_then(GraphBuilder::build) {
        Ok((graph, warnings)) => {
            sink.extend(warnings);
            Some(graph)
        }
        Err(diagnostic) => {
            sink.push(diagnostic);
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum WalkContext {
    Schema,
    NonSchema,
    SchemaMap,
    SchemaArray,
    Skip,
}

impl WalkContext {
    const fn position(self) -> PositionKind {
        match self {
            Self::Schema => PositionKind::Schema,
            Self::NonSchema | Self::SchemaMap | Self::SchemaArray | Self::Skip => {
                PositionKind::NonSchema
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct WalkLocation {
    doc_id: DocId,
    json_pointer: Rc<str>,
}

#[derive(Clone, Copy)]
struct WalkPointer<'pointer> {
    doc_id: DocId,
    json_pointer: &'pointer str,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VisitKey {
    location: WalkLocation,
    context: WalkContext,
    base: Rc<Url>,
}

#[derive(Clone, Debug)]
struct ActiveReference {
    target: NodeLocation,
    position: PositionKind,
}

#[derive(Default)]
struct TraversalState {
    stack: Vec<WalkLocation>,
    active_references: Vec<ActiveReference>,
}

struct ResolvedWalkNode<'value> {
    document: &'value Document,
    value: &'value Value,
    doc_id: DocId,
    context: WalkContext,
    base: Rc<Url>,
    ref_depth: u64,
}

struct GraphBuilder<'a> {
    config: &'a ResolvedConfig,
    documents: Vec<Rc<Document>>,
    path_to_id: HashMap<PathBuf, DocId>,
    identifiers: IdentifierRegistry,
    edges: Vec<ReferenceEdge>,
    workspace_root: PathBuf,
    allow_roots: Vec<AllowRoot>,
    total_bytes: u64,
    visited: HashSet<VisitKey>,
    warnings: Vec<Diagnostic>,
}

impl<'a> GraphBuilder<'a> {
    fn new(config: &'a ResolvedConfig) -> Result<Self, Diagnostic> {
        let workspace_root = fs::canonicalize(&config.workspace_root).map_err(|error| {
            io_error(
                CODE_DOCUMENT_IO,
                format!("failed to canonicalize workspaceRoot: {error}"),
                Some(&config.config_path.to_string_lossy()),
                Some("/workspaceRoot"),
            )
        })?;
        let mut allow_roots = Vec::with_capacity(config.local_allow_paths.len());
        for (config_index, path) in config.local_allow_paths.iter().enumerate() {
            let canonical_path = fs::canonicalize(path).map_err(|error| {
                io_error(
                    CODE_DOCUMENT_IO,
                    format!(
                        "failed to canonicalize local.allowPaths entry {config_index} '{}': {error}",
                        path.display()
                    ),
                    Some(&config.config_path.to_string_lossy()),
                    Some("/local/allowPaths"),
                )
            })?;
            allow_roots.push(AllowRoot { canonical_path });
        }
        Ok(Self {
            config,
            documents: Vec::new(),
            path_to_id: HashMap::new(),
            identifiers: IdentifierRegistry::default(),
            edges: Vec::new(),
            workspace_root,
            allow_roots,
            total_bytes: 0,
            visited: HashSet::new(),
            warnings: Vec::new(),
        })
    }

    fn build(mut self) -> Result<(DocumentGraph, Vec<Diagnostic>), Diagnostic> {
        let entry_path = configured_entry_path(&self.config.input)?;
        let entry_id = self.load_document(&entry_path)?;
        let entry_path = self.documents[entry_id.0].canonical_path.clone();
        // `load_document` stores a canonical absolute filesystem path, which `file_url` accepts.
        let entry_base = file_url(&entry_path)
            .expect("a canonical filesystem path is representable as a file URI");
        let mut state = TraversalState::default();
        self.walk_node(
            NodeLocation {
                doc_id: entry_id,
                json_pointer: String::new(),
            },
            WalkContext::NonSchema,
            Rc::new(entry_base),
            0,
            &mut state,
        )?;
        let documents = self
            .documents
            .into_iter()
            .map(|document| {
                // Traversal keeps document handles only in stack-local borrows and returns before
                // graph construction takes ownership here.
                Rc::try_unwrap(document).expect("document handles do not escape graph traversal")
            })
            .collect();
        Ok((
            DocumentGraph {
                documents,
                path_to_id: self.path_to_id,
                identifiers: self.identifiers,
                entry_id,
                edges: self.edges,
                workspace_root: self.workspace_root,
                allow_roots: self.allow_roots,
                max_ref_depth: self.config.limits.max_ref_depth,
            },
            self.warnings,
        ))
    }

    fn load_document(&mut self, requested_path: &Path) -> Result<DocId, Diagnostic> {
        // Resolved file URLs usually produce the same canonical absolute path already stored for
        // the document. Reuse that entry before asking the filesystem to canonicalize every `$ref`.
        if let Some(id) = self.path_to_id.get(requested_path) {
            return Ok(*id);
        }
        let canonical_path = fs::canonicalize(requested_path).map_err(|error| {
            io_error(
                CODE_DOCUMENT_IO,
                format!(
                    "failed to canonicalize document '{}': {error}",
                    requested_path.display()
                ),
                None,
                None,
            )
        })?;
        let source_id =
            logical_source_id(&canonical_path, &self.workspace_root, &self.allow_roots)?;

        if let Some(id) = self.path_to_id.get(&canonical_path) {
            return Ok(*id);
        }

        let next_count = u64::try_from(self.documents.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if next_count > self.config.limits.max_documents {
            return Err(limit_error(
                CODE_MAX_DOCUMENTS,
                "maxDocuments",
                self.config.limits.max_documents,
                &source_id,
            ));
        }

        // Size limits gate on metadata BEFORE reading, so an oversized target
        // is never buffered into memory just to be rejected.
        let byte_len = document_byte_len(&canonical_path, &source_id)?;
        if byte_len > self.config.limits.max_document_bytes {
            return Err(limit_error(
                CODE_MAX_DOCUMENT_BYTES,
                "maxDocumentBytes",
                self.config.limits.max_document_bytes,
                &source_id,
            ));
        }
        let next_total = self.total_bytes.saturating_add(byte_len);
        if next_total > self.config.limits.max_total_bytes {
            return Err(limit_error(
                CODE_MAX_TOTAL_BYTES,
                "maxTotalBytes",
                self.config.limits.max_total_bytes,
                &source_id,
            ));
        }

        let raw = fs::read(&canonical_path).map_err(|error| {
            io_error(
                CODE_DOCUMENT_IO,
                format!("failed to read document: {error}"),
                Some(&source_id),
                None,
            )
        })?;
        let contains_anchor = declares_identifier(&raw);
        let (value, warning) = parse_document(&canonical_path, &raw, &source_id)?;
        if let Some(warning) = warning {
            self.warnings.push(warning);
        }
        let sha256 = Sha256::digest(&raw).into();
        drop(raw);
        let id = DocId(self.documents.len());
        if contains_anchor {
            // `canonical_path` came from `fs::canonicalize`, so it is an absolute file path.
            let base = file_url(&canonical_path)
                .expect("a canonical filesystem path is representable as a file URI");
            collect_anchors(&value, id, base, &source_id, &mut self.identifiers)?;
        }
        self.documents.push(Rc::new(Document {
            id,
            canonical_path: canonical_path.clone(),
            source_id,
            value,
            sha256,
        }));
        self.path_to_id.insert(canonical_path, id);
        self.total_bytes = next_total;
        Ok(id)
    }

    fn walk_node(
        &mut self,
        location: NodeLocation,
        context: WalkContext,
        base: Rc<Url>,
        ref_depth: u64,
        state: &mut TraversalState,
    ) -> Result<(), Diagnostic> {
        if context == WalkContext::Skip {
            return Ok(());
        }

        let document = self.documents.get(location.doc_id.0).cloned();
        let value = document
            .as_ref()
            .and_then(|document| {
                evaluate_pointer_trusted(&document.value, &location.json_pointer).ok()
            })
            .ok_or_else(|| {
                input_error(
                    CODE_POINTER,
                    format!("JSON Pointer '{}' does not resolve", location.json_pointer),
                    self.source_id(location.doc_id),
                    Some(&location.json_pointer),
                )
            })?;
        let doc_id = location.doc_id;
        let mut json_pointer = location.json_pointer;
        // `value` could only have been produced through the same `document.as_ref()` above.
        self.walk_resolved_node(
            ResolvedWalkNode {
                document: document.as_ref().expect("resolved document exists"),
                value,
                doc_id,
                context,
                base,
                ref_depth,
            },
            state,
            &mut json_pointer,
        )
    }

    fn walk_resolved_node(
        &mut self,
        node: ResolvedWalkNode<'_>,
        state: &mut TraversalState,
        json_pointer: &mut String,
    ) -> Result<(), Diagnostic> {
        enum Container<'value> {
            Object(&'value serde_json::Map<String, Value>),
            Array(&'value [Value]),
        }

        let ResolvedWalkNode {
            document,
            value,
            doc_id,
            context,
            base,
            ref_depth,
        } = node;
        let container = match value {
            Value::Object(object) => Container::Object(object),
            Value::Array(values) => Container::Array(values),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => return Ok(()),
        };
        let location = WalkLocation {
            doc_id,
            json_pointer: Rc::from(json_pointer.as_str()),
        };
        let key = VisitKey {
            location: location.clone(),
            context,
            base: Rc::clone(&base),
        };
        if !self.visited.insert(key) {
            return Ok(());
        }

        state.stack.push(location.clone());
        let mut effective_base = base;
        if context == WalkContext::Schema
            && let Container::Object(object) = &container
            && let Some(id_value) = object.get("$id")
        {
            let Some(id) = id_value.as_str() else {
                return Err(input_error(
                    CODE_INVALID_REFERENCE,
                    "Schema Object $id must be a string URI reference",
                    self.source_id(doc_id),
                    Some(&append_pointer(json_pointer, "$id")),
                ));
            };
            effective_base = Rc::new(resolve_identity_uri(
                &effective_base,
                id,
                self.source_id(doc_id),
                Some(&append_pointer(json_pointer, "$id")),
            )?);
        }

        match container {
            Container::Object(object) => {
                if matches!(context, WalkContext::Schema | WalkContext::NonSchema)
                    && let Some(reference_value) = object.get("$ref")
                {
                    let Some(reference) = reference_value.as_str() else {
                        return Err(input_error(
                            CODE_INVALID_REFERENCE,
                            "$ref must be a string URI reference",
                            self.source_id(doc_id),
                            Some(&append_pointer(json_pointer, "$ref")),
                        ));
                    };
                    self.follow_reference(
                        WalkPointer {
                            doc_id,
                            json_pointer,
                        },
                        context.position(),
                        &effective_base,
                        reference,
                        ref_depth,
                        state,
                    )?;
                }

                for (name, child) in object {
                    if matches!(context, WalkContext::Schema | WalkContext::NonSchema)
                        && matches!(name.as_str(), "$ref" | "$id")
                    {
                        continue;
                    }
                    let child_context = child_context(context, json_pointer, name, child);
                    if child_context == WalkContext::Skip {
                        continue;
                    }
                    let restore_length = json_pointer.len();
                    push_pointer_token(json_pointer, name);
                    let result = self.walk_resolved_node(
                        ResolvedWalkNode {
                            document,
                            value: child,
                            doc_id,
                            context: child_context,
                            base: Rc::clone(&effective_base),
                            ref_depth,
                        },
                        state,
                        json_pointer,
                    );
                    json_pointer.truncate(restore_length);
                    result?;
                }
            }
            Container::Array(values) => {
                let child_context = array_child_context(context);
                if child_context != WalkContext::Skip {
                    for (index, child) in values.iter().enumerate() {
                        let restore_length = json_pointer.len();
                        push_pointer_index(json_pointer, index);
                        let result = self.walk_resolved_node(
                            ResolvedWalkNode {
                                document,
                                value: child,
                                doc_id,
                                context: child_context,
                                base: Rc::clone(&effective_base),
                                ref_depth,
                            },
                            state,
                            json_pointer,
                        );
                        json_pointer.truncate(restore_length);
                        result?;
                    }
                }
            }
        }

        state.stack.pop();
        Ok(())
    }

    fn follow_reference(
        &mut self,
        from: WalkPointer<'_>,
        position: PositionKind,
        base: &Url,
        reference: &str,
        ref_depth: u64,
        state: &mut TraversalState,
    ) -> Result<(), Diagnostic> {
        let reference_pointer = append_pointer(from.json_pointer, "$ref");
        let target_url = resolve_identity_uri(
            base,
            reference,
            self.source_id(from.doc_id),
            Some(&reference_pointer),
        )?;
        let target = if let Some(target) = registered_anchor_location(
            &target_url,
            &self.identifiers.anchors,
            self.source_id(from.doc_id),
            Some(&reference_pointer),
        )? {
            target
        } else if let Some(root) = registered_resource(&self.identifiers, &target_url) {
            // The URI names a schema resource already in the graph. Answer from the registry —
            // reaching for the filesystem here is what turns an `$id` into a fetch attempt.
            let within = pointer_from_url(
                &target_url,
                self.source_id(from.doc_id),
                Some(&reference_pointer),
            )?;
            NodeLocation {
                doc_id: root.doc_id,
                json_pointer: format!("{}{within}", root.json_pointer),
            }
        } else {
            let source_id = self.source_id(from.doc_id);
            let target_path =
                local_path_from_url(&target_url, source_id, Some(&reference_pointer))?;
            let target_id = self.load_document(&target_path).map_err(|mut diagnostic| {
                if diagnostic.source_id.is_none()
                    && let Some(source_id) = self.source_id(from.doc_id)
                {
                    diagnostic = diagnostic.with_source(source_id);
                }
                // load_document diagnostics identify the failing file, never a position inside the
                // referencing document — the $ref location is always ours to stamp.
                diagnostic.with_json_pointer(&reference_pointer)
            })?;
            pointer_or_anchor(
                &target_url,
                target_id,
                &self.identifiers.anchors,
                self.source_id(from.doc_id),
                Some(&reference_pointer),
            )?
        };
        let target_document = Rc::clone(&self.documents[target.doc_id.0]);
        let target_source = target_document.source_id.clone();
        let target_value =
            evaluate_pointer(&target_document.value, &target.json_pointer).map_err(|message| {
                input_error(
                    CODE_POINTER,
                    message,
                    Some(&target_source),
                    Some(&target.json_pointer),
                )
            })?;
        self.edges.push(ReferenceEdge {
            from: NodeLocation {
                doc_id: from.doc_id,
                json_pointer: from.json_pointer.to_owned(),
            },
            to: target.clone(),
            reference: reference.to_owned(),
            position,
        });

        let next_depth = ref_depth.saturating_add(1);
        if next_depth > self.config.limits.max_ref_depth {
            return Err(limit_error(
                CODE_MAX_REF_DEPTH,
                "maxRefDepth",
                self.config.limits.max_ref_depth,
                &target_source,
            ));
        }

        if state.stack.iter().any(|ancestor| {
            ancestor.doc_id == target.doc_id
                && ancestor.json_pointer.as_ref() == target.json_pointer
        }) {
            let start = state
                .active_references
                .iter()
                .position(|active| active.target == target)
                .unwrap_or(usize::MAX)
                .checked_add(1)
                .unwrap_or(0);
            let active_non_schema = state.active_references[start..]
                .iter()
                .any(|active| active.position == PositionKind::NonSchema);
            if active_non_schema || position == PositionKind::NonSchema {
                return Err(input_error(
                    CODE_NON_SCHEMA_CYCLE,
                    "reference cycle passes through a non-schema OpenAPI position",
                    Some(&target_source),
                    Some(&target.json_pointer),
                ));
            }
            return Ok(());
        }

        let target_base = Rc::new(self.base_at_target(&target, position)?);
        state.active_references.push(ActiveReference {
            target: target.clone(),
            position,
        });
        let target_doc_id = target.doc_id;
        let mut target_pointer = target.json_pointer;
        let target_context = match position {
            PositionKind::Schema => WalkContext::Schema,
            PositionKind::NonSchema => WalkContext::NonSchema,
        };
        let result = self.walk_resolved_node(
            ResolvedWalkNode {
                document: &target_document,
                value: target_value,
                doc_id: target_doc_id,
                context: target_context,
                base: target_base,
                ref_depth: next_depth,
            },
            state,
            &mut target_pointer,
        );
        state.active_references.pop();
        result
    }

    fn base_at_target(
        &self,
        target: &NodeLocation,
        expected_position: PositionKind,
    ) -> Result<Url, Diagnostic> {
        base_at_document(
            &self.documents[target.doc_id.0],
            &target.json_pointer,
            expected_position,
        )
    }

    fn source_id(&self, id: DocId) -> Option<&str> {
        self.documents
            .get(id.0)
            .map(|document| document.source_id.as_str())
    }
}

/// Computes the base URI in force at one node, walking the `$id` chain down to it.
///
/// Shared by the graph builder (which needs it while walking references) and the finished graph
/// (which needs it to resolve the dynamic-reference keywords), so it takes the document slice
/// rather than either owner.
fn base_at(
    documents: &[Document],
    doc_id: DocId,
    json_pointer: &str,
    expected_position: PositionKind,
) -> Result<Url, Diagnostic> {
    let document = &documents[doc_id.0];
    base_at_document(document, json_pointer, expected_position)
}

fn base_at_document(
    document: &Document,
    json_pointer: &str,
    expected_position: PositionKind,
) -> Result<Url, Diagnostic> {
    let mut base = file_url(&document.canonical_path).map_err(|message| {
        input_error(
            CODE_INVALID_REFERENCE,
            message,
            Some(&document.source_id),
            Some(json_pointer),
        )
    })?;
    if json_pointer.is_empty() {
        return Ok(base);
    }

    let mut value = &document.value;
    let mut pointer = String::new();
    let mut context = if document.value.get("openapi").is_some() {
        WalkContext::NonSchema
    } else {
        match expected_position {
            PositionKind::Schema => WalkContext::Schema,
            PositionKind::NonSchema => WalkContext::NonSchema,
        }
    };
    for encoded_token in json_pointer[1..].split('/') {
        if context == WalkContext::Schema
            && let Value::Object(object) = value
            && let Some(id_value) = object.get("$id")
        {
            let Some(id) = id_value.as_str() else {
                return Err(input_error(
                    CODE_INVALID_REFERENCE,
                    "Schema Object $id must be a string URI reference",
                    Some(&document.source_id),
                    Some(&append_pointer(&pointer, "$id")),
                ));
            };
            let id_pointer = append_pointer(&pointer, "$id");
            base = resolve_identity_uri(&base, id, Some(&document.source_id), Some(&id_pointer))?;
        }

        let token = unescape_pointer_token_borrowed(encoded_token).map_err(|message| {
            input_error(
                CODE_INVALID_REFERENCE,
                message,
                Some(&document.source_id),
                Some(json_pointer),
            )
        })?;
        let pointer_error = || {
            input_error(
                CODE_POINTER,
                format!("JSON Pointer '{json_pointer}' does not resolve"),
                Some(&document.source_id),
                Some(json_pointer),
            )
        };
        let (child, next_context) = match value {
            Value::Object(object) => {
                let child = object.get(token.as_ref()).ok_or_else(pointer_error)?;
                (
                    child,
                    child_context(context, &pointer, token.as_ref(), child),
                )
            }
            Value::Array(array) => {
                let child = token
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| array.get(index))
                    .ok_or_else(pointer_error)?;
                let next_context = array_child_context(context);
                (child, next_context)
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Err(pointer_error());
            }
        };
        context = next_context;
        pointer = append_pointer(&pointer, token.as_ref());
        value = child;
    }
    Ok(base)
}

/// The schema resource a URI names, if the graph holds one.
///
/// `resource_base_uri` copies the URI to strip its fragment, so the empty-registry check comes
/// first: a document declaring no `$id` can never match, and every reference resolution passes
/// through here.
fn registered_resource<'a>(
    identifiers: &'a IdentifierRegistry,
    url: &Url,
) -> Option<&'a NodeLocation> {
    if identifiers.resources.is_empty() {
        return None;
    }
    identifiers.resources.get(&resource_base_uri(url))
}

fn missing_document_error(id: DocId) -> Diagnostic {
    input_error(
        CODE_INVALID_REFERENCE,
        format!("document ID {} is not present in this graph", id.index()),
        None,
        None,
    )
}

/// Registers the two dynamic identifier keywords carried by one schema object.
///
/// `$dynamicAnchor` lands in two maps on purpose. §8.2.2 makes it create an ordinary plain-name
/// fragment, so `$ref: "#name"` must find it exactly as it would an `$anchor`; and it lands in the
/// dynamic map because the reverse does *not* hold — a plain `$anchor` is never eligible for
/// dynamic-scope resolution, an asymmetry the 2020-12 test suite pins explicitly.
fn collect_dynamic_identifiers(
    object: &serde_json::Map<String, Value>,
    doc_id: DocId,
    pointer: &str,
    base: &Url,
    source_id: &str,
    identifiers: &mut IdentifierRegistry,
) -> Result<(), Diagnostic> {
    let resource = resource_base_uri(base);
    if let Some(anchor_value) = object.get("$dynamicAnchor") {
        let anchor_pointer = append_pointer(pointer, "$dynamicAnchor");
        let Some(name) = anchor_value.as_str() else {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                "Schema Object $dynamicAnchor must be a valid plain name",
                Some(source_id),
                Some(&anchor_pointer),
            ));
        };
        if !valid_anchor_name(name) {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                format!("Schema Object $dynamicAnchor '{name}' is not a valid plain name"),
                Some(source_id),
                Some(&anchor_pointer),
            ));
        }
        let location = NodeLocation {
            doc_id,
            json_pointer: pointer.to_owned(),
        };
        let plain_key = (resource.clone(), name.to_owned());
        // §8.2.2: "The effect of specifying the same fragment name multiple times within the same
        // resource, using any combination of $anchor and/or $dynamicAnchor, is undefined.
        // Implementations MAY raise an error if such usage is detected." Raise it — the same call
        // the plain `$anchor` path already makes.
        if identifiers.anchors.contains_key(&plain_key) {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                format!("duplicate $dynamicAnchor '{name}' in the same schema resource"),
                Some(source_id),
                Some(&anchor_pointer),
            ));
        }
        identifiers.anchors.insert(plain_key, location.clone());
        identifiers
            .dynamic_anchors
            .insert((name.to_owned(), resource.clone()), location);
    }
    if let Some(anchor_value) = object.get("$recursiveAnchor") {
        let anchor_pointer = append_pointer(pointer, "$recursiveAnchor");
        let Some(enabled) = anchor_value.as_bool() else {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                "Schema Object $recursiveAnchor must be a boolean",
                Some(source_id),
                Some(&anchor_pointer),
            ));
        };
        // "Omitting this keyword has the same behavior as a value of false" — so a `false` records
        // nothing. The walk is pre-order, so the first hit in a resource is its outermost one.
        if enabled {
            identifiers
                .recursive_anchors
                .entry(resource)
                .or_insert(NodeLocation {
                    doc_id,
                    json_pointer: pointer.to_owned(),
                });
        }
    }
    Ok(())
}

fn collect_anchors(
    value: &Value,
    doc_id: DocId,
    base: Url,
    source_id: &str,
    identifiers: &mut IdentifierRegistry,
) -> Result<(), Diagnostic> {
    let context = if value.get("openapi").is_some() {
        WalkContext::NonSchema
    } else {
        WalkContext::Schema
    };
    collect_anchors_at(value, doc_id, "", context, base, source_id, identifiers)
}

fn collect_anchors_at(
    value: &Value,
    doc_id: DocId,
    pointer: &str,
    context: WalkContext,
    mut base: Url,
    source_id: &str,
    identifiers: &mut IdentifierRegistry,
) -> Result<(), Diagnostic> {
    if context == WalkContext::Skip {
        return Ok(());
    }

    if context == WalkContext::Schema
        && let Value::Object(object) = value
        && let Some(id_value) = object.get("$id")
    {
        let Some(id) = id_value.as_str() else {
            return Ok(());
        };
        let Ok(resolved) = resolve_identity_uri(
            &base,
            id,
            Some(source_id),
            Some(&append_pointer(pointer, "$id")),
        ) else {
            return Ok(());
        };
        base = resolved;
        // `$id` is what makes this subtree a schema *resource*, and resource identity is the unit
        // the dynamic-scope walk counts in. Record the root so a dynamic reference resolving to
        // this resource's URI can find the schema it names.
        identifiers
            .resources
            .entry(resource_base_uri(&base))
            .or_insert_with(|| NodeLocation {
                doc_id,
                json_pointer: pointer.to_owned(),
            });
    }

    if context == WalkContext::Schema
        && let Value::Object(object) = value
    {
        collect_dynamic_identifiers(object, doc_id, pointer, &base, source_id, identifiers)?;
    }

    if context == WalkContext::Schema
        && let Value::Object(object) = value
        && let Some(anchor_value) = object.get("$anchor")
    {
        let anchor_pointer = append_pointer(pointer, "$anchor");
        let Some(name) = anchor_value.as_str() else {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                "Schema Object $anchor must be a valid plain name",
                Some(source_id),
                Some(&anchor_pointer),
            ));
        };
        if !valid_anchor_name(name) {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                format!("Schema Object $anchor '{name}' is not a valid plain name"),
                Some(source_id),
                Some(&anchor_pointer),
            ));
        }
        let key = (resource_base_uri(&base), name.to_owned());
        if identifiers.anchors.contains_key(&key) {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                format!("duplicate $anchor '{name}' in the same schema resource"),
                Some(source_id),
                Some(&anchor_pointer),
            ));
        }
        identifiers.anchors.insert(
            key,
            NodeLocation {
                doc_id,
                json_pointer: pointer.to_owned(),
            },
        );
    }

    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let child_context = child_context(context, pointer, name, child);
                if child_context != WalkContext::Skip {
                    collect_anchors_at(
                        child,
                        doc_id,
                        &append_pointer(pointer, name),
                        child_context,
                        base.clone(),
                        source_id,
                        identifiers,
                    )?;
                }
            }
        }
        Value::Array(array) => {
            let child_context = array_child_context(context);
            if child_context != WalkContext::Skip {
                for (index, child) in array.iter().enumerate() {
                    collect_anchors_at(
                        child,
                        doc_id,
                        &append_pointer_index(pointer, index),
                        child_context,
                        base.clone(),
                        source_id,
                        identifiers,
                    )?;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn valid_anchor_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn resource_base_uri(url: &Url) -> String {
    let mut resource = url.clone();
    resource.set_fragment(None);
    resource.into()
}

fn document_byte_len(path: &Path, source_id: &str) -> Result<u64, Diagnostic> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| {
            io_error(
                CODE_DOCUMENT_IO,
                format!("failed to read document metadata: {error}"),
                Some(source_id),
                None,
            )
        })
}

type DocumentParser = fn(&[u8], &str) -> Result<Value, Diagnostic>;

fn parse_document(
    path: &Path,
    raw: &[u8],
    source_id: &str,
) -> Result<(Value, Option<Diagnostic>), Diagnostic> {
    match path.extension().and_then(OsStr::to_str) {
        // The extension names the primary parser; the other is the fallback. The warning reports the
        // format actually used, and `combined_parse_error` always receives the errors in canonical
        // (json, yaml) order with the primary parser's position.
        Some(ext @ ("json" | "yaml" | "yml")) => {
            let (primary, fallback, fell_back_to) = if ext == "json" {
                (
                    parse_json as DocumentParser,
                    parse_yaml as DocumentParser,
                    "YAML",
                )
            } else {
                (
                    parse_yaml as DocumentParser,
                    parse_json as DocumentParser,
                    "JSON",
                )
            };
            match parse_with_fallback(raw, source_id, primary, fallback) {
                Ok((value, false)) => Ok((value, None)),
                Ok((value, true)) => Ok((
                    value,
                    Some(extension_fallback_warning(
                        source_id,
                        &format!(".{ext}"),
                        fell_back_to,
                    )),
                )),
                Err(errors) => {
                    let (primary_error, fallback_error) = *errors;
                    let (line, col) = (primary_error.line, primary_error.col);
                    let (json_error, yaml_error) = if ext == "json" {
                        (primary_error, fallback_error)
                    } else {
                        (fallback_error, primary_error)
                    };
                    Err(combined_parse_error(
                        source_id, line, col, json_error, yaml_error,
                    ))
                }
            }
        }
        _ => match parse_with_fallback(raw, source_id, parse_json, parse_yaml) {
            Ok((value, _)) => Ok((value, None)),
            Err(errors) => {
                let (json_error, yaml_error) = *errors;
                Err(combined_parse_error(
                    source_id, None, None, json_error, yaml_error,
                ))
            }
        },
    }
}

fn parse_with_fallback(
    raw: &[u8],
    source_id: &str,
    primary: DocumentParser,
    fallback: DocumentParser,
) -> Result<(Value, bool), Box<(Diagnostic, Diagnostic)>> {
    match primary(raw, source_id) {
        Ok(value) => Ok((value, false)),
        Err(primary_error) => match fallback(raw, source_id) {
            Ok(value) => Ok((value, true)),
            Err(fallback_error) => Err(Box::new((primary_error, fallback_error))),
        },
    }
}

fn combined_parse_error(
    source_id: &str,
    line: Option<u32>,
    col: Option<u32>,
    json_error: Diagnostic,
    yaml_error: Diagnostic,
) -> Diagnostic {
    let mut diagnostic = input_error(
        CODE_DOCUMENT_PARSE,
        format!(
            "document is neither valid JSON nor YAML: {}; {}",
            json_error.message, yaml_error.message
        ),
        Some(source_id),
        None,
    );
    diagnostic.line = line;
    diagnostic.col = col;
    diagnostic
}

fn extension_fallback_warning(source_id: &str, extension: &str, format: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::input(
        CODE_EXTENSION_FALLBACK,
        format!("document '{source_id}' has extension '{extension}' but parsed as {format}"),
    )
    .with_source(source_id);
    diagnostic.severity = Severity::Warning;
    diagnostic
}

fn configured_entry_path(path: &Path) -> Result<PathBuf, Diagnostic> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let Some(value) = path.to_str() else {
        return Ok(path.to_path_buf());
    };
    let Ok(url) = Url::parse(value) else {
        return Ok(path.to_path_buf());
    };
    local_path_from_url(&url, None, None)
}

/// Fast-reject that gates the identifier tree walk over the *raw* file bytes. It must also
/// fire on spellings that escape the `$`: a document can write the key with the dollar as a
/// JSON or YAML unicode/hex character escape and still parse to the key `$anchor`. Missing
/// one skips registration silently — later refs fail to resolve and duplicate-anchor
/// validation never runs. Over-triggering is harmless (the walk just finds no identifier
/// keys); a false negative is not, so the pairs below need no false negatives, not exactness.
///
/// `$id` earns its place despite matching plenty of unrelated text: it is what creates a
/// schema resource, and resource registration must not depend on whether the document also
/// happens to declare an anchor — that would make `$id` mean different things in two
/// documents differing only in an unrelated keyword.
///
/// Every spelling starts with `$` or `\`, so one SIMD `memchr2` pass finds every candidate
/// position; the per-candidate work is then a handful of `starts_with` checks. Scanning the
/// three spellings independently with `windows()` walked the whole file three times over and
/// cost ~4.5 ns/byte — 50 ms of the 216 ms GitHub compile, for a document that declares no
/// identifier at all.
fn declares_identifier(raw: &[u8]) -> bool {
    // The dollar as the unicode escape U+0024 (JSON, and YAML double-quoted) — the literal
    // bytes `\`, `u`, `0`, `0`, `2`, `4`.
    const ESCAPED_UNICODE_DOLLAR: &[u8] = &[0x5C, 0x75, 0x30, 0x30, 0x32, 0x34];
    // The dollar as the YAML hex escape \x24.
    const ESCAPED_HEX_DOLLAR: &[u8] = br"\x24";
    const IDENTIFIER_SUFFIXES: [&[u8]; 4] =
        [b"anchor", b"dynamicAnchor", b"recursiveAnchor", b"id"];

    memchr::memchr2_iter(b'$', b'\\', raw).any(|index| {
        let candidate = &raw[index..];
        let suffix = if candidate[0] == b'$' {
            &candidate[1..]
        } else if candidate.starts_with(ESCAPED_UNICODE_DOLLAR) {
            &candidate[ESCAPED_UNICODE_DOLLAR.len()..]
        } else if candidate.starts_with(ESCAPED_HEX_DOLLAR) {
            &candidate[ESCAPED_HEX_DOLLAR.len()..]
        } else {
            return false;
        };
        IDENTIFIER_SUFFIXES
            .iter()
            .any(|identifier| suffix.starts_with(identifier))
    })
}

/// Parses a JSON document into an owned `Value`, rejecting duplicate object keys.
///
/// This is the single largest item left in `load_graph` — 18.2 ms of GitHub's 11.3 MB spec —
/// so "swap in a SIMD parser" comes up. It was benchmarked properly on the real corpora and the
/// answer is no. Tokenizing is not the cost: deserializing to `serde::de::IgnoredAny`, which
/// tokenizes and validates but builds nothing, is 5.6 ms — **30% of the work. The other 70% is
/// materializing the tree**: a `String` per key, a `String` per string value, an `IndexMap` per
/// object, across GitHub's 69,973 objects and 192,169 keys. A SIMD front end feeding the same
/// tree therefore buys nothing, and measurement agrees exactly: simd-json into
/// `serde_json::Value` is 18.2 ms, indistinguishable from this.
///
/// The parsers that are genuinely faster are faster because they build a *different* tree, and
/// each one breaks a contract this compiler depends on:
///
/// - sonic-rs into `serde_json::Value` is 14.0 ms (-23%) but rounds a large integer default to
///   `1.2345678901234568e+29`, and accepts duplicate object keys as last-wins.
/// - sonic-rs' own DOM is 4.2 ms — the ceiling, reachable only by changing what the loader, the
///   parser and the IR all consume — and still accepts duplicate keys.
/// - simd-json's own DOM loses key order on objects past ~40 keys, which `preserve_order` exists
///   to guarantee because emitted output depends on it.
///
/// Number exactness is not a nicety here: `default`, `enum`, `const`, `minimum`, `maximum` and
/// `multipleOf` all carry numbers that reach generated TypeScript. Only this path keeps all of
/// exact numbers, key order, duplicate-key rejection, and line/column error positions.
fn parse_json(raw: &[u8], source_id: &str) -> Result<Value, Diagnostic> {
    serde_json::from_slice::<DedupValue>(raw)
        .map(|value| value.0)
        .map_err(|error| {
            input_error(
                CODE_DOCUMENT_PARSE,
                format!("invalid JSON document: {error}"),
                Some(source_id),
                None,
            )
            .with_location(to_u32(error.line()), to_u32(error.column()))
        })
}

struct DedupValue(Value);

impl<'de> Deserialize<'de> for DedupValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DedupValueVisitor)
    }
}

struct DedupValueVisitor;

impl<'de> Visitor<'de> for DedupValueVisitor {
    type Value = DedupValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DedupValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DedupValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DedupValue(Value::Number(value.into())))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(DedupValue(Value::String(value.to_owned())))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DedupValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DedupValue>()? {
            values.push(value.0);
        }
        Ok(DedupValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        // Delegate to `build_map_value`, which is generic over the error type but NOT over the
        // `MapAccess` type. serde_json drives `visit_map` with two different concrete `MapAccess`
        // implementations that share one `Error` type: `SliceRead` for real JSON objects and
        // `NumberDeserializer` for the arbitrary-precision number token. Both collapse onto a
        // single `build_map_value::<serde_json::Error>` instantiation whose runtime coverage is
        // the union of the object and number paths — so no monomorphization leaves the
        // number-token branch (or the object branch) permanently unexecuted, which is what makes
        // the file's line coverage measurable at 100%.
        let mut driver = MapAccessDriver(mapping);
        build_map_value(&mut driver).map(DedupValue)
    }
}

/// Type-erased view of a serde `MapAccess` over the exact key/value shapes `build_map_value`
/// consumes: string keys, a raw string value for the number token, and recursive `DedupValue`
/// values. Erasing the `MapAccess` type (keeping only its `Error`) is what lets `build_map_value`
/// stay non-generic in the map access and thus be a single instantiation per error type.
trait DedupMapAccess<E> {
    fn next_key(&mut self) -> Result<Option<String>, E>;
    fn next_value_string(&mut self) -> Result<String, E>;
    fn next_value(&mut self) -> Result<Value, E>;
}

struct MapAccessDriver<A>(A);

impl<'de, A> DedupMapAccess<A::Error> for MapAccessDriver<A>
where
    A: MapAccess<'de>,
{
    fn next_key(&mut self) -> Result<Option<String>, A::Error> {
        self.0.next_key::<String>()
    }

    fn next_value_string(&mut self) -> Result<String, A::Error> {
        self.0.next_value::<String>()
    }

    fn next_value(&mut self) -> Result<Value, A::Error> {
        self.0.next_value::<DedupValue>().map(|value| value.0)
    }
}

/// Builds a `Value` from a JSON map, rejecting duplicate object keys and decoding the
/// arbitrary-precision number token. Generic over the error type only, so serde_json's
/// object-parsing and number-token map accesses reuse one instantiation.
#[inline(always)]
fn build_map_value<E>(access: &mut dyn DedupMapAccess<E>) -> Result<Value, E>
where
    E: serde::de::Error,
{
    let Some(first_key) = access.next_key()? else {
        return Ok(Value::Object(serde_json::Map::new()));
    };
    if first_key == SERDE_JSON_NUMBER_TOKEN {
        let raw_token = access.next_value_string()?;
        let number = serde_json::Number::from_str(&raw_token).map_err(E::custom)?;
        return Ok(Value::Number(number));
    }

    let mut values = serde_json::Map::new();
    let first_value = access.next_value()?;
    values.insert(first_key, first_value);
    while let Some(key) = access.next_key()? {
        match values.entry(key) {
            serde_json::map::Entry::Occupied(entry) => {
                return Err(E::custom(format!("duplicate object key '{}'", entry.key())));
            }
            serde_json::map::Entry::Vacant(entry) => {
                let value = access.next_value()?;
                entry.insert(value);
            }
        }
    }
    Ok(Value::Object(values))
}

fn parse_yaml(raw: &[u8], source_id: &str) -> Result<Value, Diagnostic> {
    let source = std::str::from_utf8(raw).map_err(|error| {
        input_error(
            CODE_DOCUMENT_PARSE,
            format!("YAML document is not UTF-8: {error}"),
            Some(source_id),
            None,
        )
    })?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    parse_yaml_document_value(source).map_err(|error| {
        input_error(
            CODE_DOCUMENT_PARSE,
            format!("invalid YAML document: {}", error.message),
            Some(source_id),
            None,
        )
        .with_location(error.line, error.col)
    })
}

fn logical_source_id(
    canonical_path: &Path,
    workspace_root: &Path,
    allow_roots: &[AllowRoot],
) -> Result<String, Diagnostic> {
    let (prefix, suffix) = authorize_path(canonical_path, workspace_root, allow_roots)
        .map_err(|message| input_error(CODE_REF_ESCAPE, message, None, None))?;
    let encoded = encode_relative_path(suffix)
        .map_err(|message| input_error(CODE_NON_UNICODE_PATH, message, None, None))?;
    Ok(format!("{prefix}/{encoded}"))
}

fn authorize_path<'a>(
    canonical_path: &'a Path,
    workspace_root: &'a Path,
    allow_roots: &'a [AllowRoot],
) -> Result<(String, &'a Path), String> {
    if let Ok(suffix) = canonical_path.strip_prefix(workspace_root) {
        return Ok(("workspace".to_owned(), suffix));
    }

    let mut selected: Option<(usize, &AllowRoot)> = None;
    let mut selected_length = 0;
    for (index, root) in allow_roots.iter().enumerate() {
        if canonical_path.starts_with(&root.canonical_path) {
            let length = root.canonical_path.components().count();
            if selected.is_none() || length > selected_length {
                selected = Some((index, root));
                selected_length = length;
            }
        }
    }
    if let Some((index, root)) = selected {
        // `selected` is assigned only by the `starts_with` branch above.
        let suffix = canonical_path
            .strip_prefix(&root.canonical_path)
            .expect("the selected allow root is a prefix of the canonical path");
        return Ok((format!("allow/{index}"), suffix));
    }

    Err(format!(
        "local reference '{}' escapes workspaceRoot and every local.allowPaths root",
        canonical_path.display()
    ))
}

fn encode_relative_path(path: &Path) -> Result<String, String> {
    let mut encoded_segments = Vec::new();
    for component in path.components() {
        let Component::Normal(segment) = component else {
            continue;
        };
        let segment = segment.to_str().ok_or_else(|| {
            format!(
                "canonical document path '{}' is not valid Unicode",
                path.display()
            )
        })?;
        let mut encoded = String::new();
        for byte in segment.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
                encoded.push(char::from(*byte));
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
        encoded_segments.push(encoded);
    }
    Ok(encoded_segments.join("/"))
}

/// Joins a reference onto a base URI without asking whether the result is retrievable.
///
/// `$id` names a schema resource; it is not a request to fetch one. A bundled document that
/// identifies its resources with `https://` URIs resolves entirely in memory, so the scheme check
/// belongs at the point something is actually read — `local_path_from_url`, which every path that
/// reaches the filesystem goes through, and which is where OASTS9201 now comes from.
fn resolve_identity_uri(
    base: &Url,
    reference: &str,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<Url, Diagnostic> {
    base.join(reference).map_err(|error| {
        input_error(
            CODE_INVALID_REFERENCE,
            format!("invalid URI reference '{reference}': {error}"),
            source_id,
            pointer,
        )
    })
}

fn file_url(path: &Path) -> Result<Url, String> {
    Url::from_file_path(path).map_err(|()| {
        format!(
            "local document path '{}' cannot be represented as a file URI",
            path.display()
        )
    })
}

fn local_path_from_url(
    url: &Url,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<PathBuf, Diagnostic> {
    if url.scheme() != "file" {
        return Err(input_error(
            CODE_REMOTE_UNSUPPORTED,
            format!(
                "remote loading is not supported in this build: '{}'",
                url.as_str()
            ),
            source_id,
            pointer,
        ));
    }
    url.to_file_path().map_err(|()| {
        input_error(
            CODE_INVALID_REFERENCE,
            format!("file URI '{}' is not a local filesystem path", url.as_str()),
            source_id,
            pointer,
        )
    })
}

fn pointer_from_url(
    url: &Url,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<String, Diagnostic> {
    let Some(fragment) = url.fragment() else {
        return Ok(String::new());
    };
    let decoded = percent_decode(fragment)
        .map_err(|message| input_error(CODE_INVALID_REFERENCE, message, source_id, pointer))?;
    if !decoded.is_empty() && !decoded.starts_with('/') {
        return Err(input_error(
            CODE_INVALID_REFERENCE,
            format!("URI fragment '#{decoded}' is not a JSON Pointer"),
            source_id,
            pointer,
        ));
    }
    validate_pointer(&decoded)
        .map_err(|message| input_error(CODE_INVALID_REFERENCE, message, source_id, pointer))?;
    Ok(decoded)
}

fn registered_anchor_location(
    url: &Url,
    anchors: &AnchorRegistry,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<Option<NodeLocation>, Diagnostic> {
    if anchors.is_empty() {
        return Ok(None);
    }
    let Some(fragment) = url.fragment() else {
        return Ok(None);
    };
    if fragment.is_empty() || fragment.starts_with('/') {
        return Ok(None);
    }
    let name = percent_decode(fragment)
        .map_err(|message| input_error(CODE_INVALID_REFERENCE, message, source_id, pointer))?;
    if name.is_empty() || name.starts_with('/') {
        return Ok(None);
    }
    Ok(anchors.get(&(resource_base_uri(url), name)).cloned())
}

fn pointer_or_anchor(
    url: &Url,
    doc_id: DocId,
    anchors: &AnchorRegistry,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<NodeLocation, Diagnostic> {
    let Some(fragment) = url.fragment() else {
        return Ok(NodeLocation {
            doc_id,
            json_pointer: String::new(),
        });
    };
    if fragment.is_empty() || fragment.starts_with('/') {
        return Ok(NodeLocation {
            doc_id,
            json_pointer: pointer_from_url(url, source_id, pointer)?,
        });
    }
    let name = percent_decode(fragment)
        .map_err(|message| input_error(CODE_INVALID_REFERENCE, message, source_id, pointer))?;
    if name.is_empty() || name.starts_with('/') {
        validate_pointer(&name)
            .map_err(|message| input_error(CODE_INVALID_REFERENCE, message, source_id, pointer))?;
        return Ok(NodeLocation {
            doc_id,
            json_pointer: name,
        });
    }
    anchors
        .get(&(resource_base_uri(url), name.clone()))
        .cloned()
        .ok_or_else(|| {
            input_error(
                CODE_INVALID_REFERENCE,
                format!("no $anchor '{name}' in the target resource"),
                source_id,
                pointer,
            )
        })
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index.saturating_add(2) >= bytes.len() {
                return Err(format!("invalid percent escape in URI fragment '#{value}'"));
            }
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(format!("invalid percent escape in URI fragment '#{value}'"));
            };
            decoded.push((high << 4) | low);
            index = index.saturating_add(3);
        } else {
            decoded.push(bytes[index]);
            index = index.saturating_add(1);
        }
    }
    String::from_utf8(decoded).map_err(|_| format!("URI fragment '#{value}' is not valid UTF-8"))
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn evaluate_pointer<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value, String> {
    validate_pointer(pointer)?;
    evaluate_pointer_trusted(value, pointer)
}

/// Resolves a pointer that is escaped-by-construction — built by `append_pointer`
/// during the walk, or already validated at the `$ref`/external boundary — so it
/// skips the standalone `validate_pointer` pass that the untrusted `evaluate_pointer`
/// entry point keeps. Callers passing an externally supplied pointer MUST go through
/// `evaluate_pointer`; this variant assumes a well-formed pointer and reports only
/// resolution failures, not escape/format ones.
fn evaluate_pointer_trusted<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value, String> {
    if pointer.is_empty() {
        return Ok(value);
    }
    let mut current = value;
    for encoded_token in pointer[1..].split('/') {
        let token = unescape_pointer_token_borrowed(encoded_token)?;
        current = match current {
            Value::Object(object) => object
                .get(token.as_ref())
                .ok_or_else(|| format!("JSON Pointer '{pointer}' does not resolve"))?,
            Value::Array(array) => {
                if token.is_empty()
                    || (token.len() > 1 && token.starts_with('0'))
                    || !token.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(format!("JSON Pointer '{pointer}' does not resolve"));
                }
                let index = token
                    .parse::<usize>()
                    .map_err(|_| format!("JSON Pointer '{pointer}' does not resolve"))?;
                array
                    .get(index)
                    .ok_or_else(|| format!("JSON Pointer '{pointer}' does not resolve"))?
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Err(format!("JSON Pointer '{pointer}' does not resolve"));
            }
        };
    }
    Ok(current)
}

fn validate_pointer(pointer: &str) -> Result<(), String> {
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(format!("'{pointer}' is not a JSON Pointer"));
    }
    for token in pointer[1..].split('/') {
        unescape_pointer_token(token)?;
    }
    Ok(())
}

fn unescape_pointer_token(token: &str) -> Result<String, String> {
    unescape_pointer_token_borrowed(token).map(Cow::into_owned)
}

/// Decodes a single JSON Pointer token, borrowing the input unchanged when it
/// holds no `~` escape so the walk pays no allocation for the common token; only
/// a genuinely escaped token allocates to expand `~0`/`~1`.
fn unescape_pointer_token_borrowed(token: &str) -> Result<Cow<'_, str>, String> {
    if !token.contains('~') {
        return Ok(Cow::Borrowed(token));
    }
    let mut result = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            result.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => result.push('~'),
            Some('1') => result.push('/'),
            _ => return Err(format!("invalid JSON Pointer escape in token '{token}'")),
        }
    }
    Ok(Cow::Owned(result))
}

pub(crate) fn append_pointer(pointer: &str, token: &str) -> String {
    let mut result = String::with_capacity(pointer.len() + 1 + token.len());
    result.push_str(pointer);
    push_pointer_token(&mut result, token);
    result
}

fn push_pointer_token(pointer: &mut String, token: &str) {
    pointer.push('/');
    for character in token.chars() {
        match character {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            _ => pointer.push(character),
        }
    }
}

fn push_pointer_index(pointer: &mut String, index: usize) {
    let mut buffer = itoa::Buffer::new();
    push_pointer_token(pointer, buffer.format(index));
}

pub(crate) fn append_pointer_index(pointer: &str, index: usize) -> String {
    let mut buffer = itoa::Buffer::new();
    append_pointer(pointer, buffer.format(index))
}

fn array_child_context(context: WalkContext) -> WalkContext {
    match context {
        WalkContext::Schema | WalkContext::SchemaArray => WalkContext::Schema,
        WalkContext::NonSchema => WalkContext::NonSchema,
        WalkContext::SchemaMap | WalkContext::Skip => WalkContext::Skip,
    }
}

fn child_context(context: WalkContext, pointer: &str, name: &str, value: &Value) -> WalkContext {
    match context {
        WalkContext::SchemaMap => WalkContext::Schema,
        WalkContext::SchemaArray => WalkContext::Schema,
        WalkContext::Skip => WalkContext::Skip,
        WalkContext::NonSchema => {
            if name == "schema" {
                WalkContext::Schema
            } else if name == "schemas" && pointer == "/components" {
                WalkContext::SchemaMap
            } else if matches!(name, "example" | "value") {
                WalkContext::Skip
            } else {
                WalkContext::NonSchema
            }
        }
        WalkContext::Schema => {
            if matches!(
                name,
                "properties" | "patternProperties" | "dependentSchemas" | "$defs" | "definitions"
            ) {
                WalkContext::SchemaMap
            } else if matches!(name, "allOf" | "anyOf" | "oneOf" | "prefixItems") {
                WalkContext::SchemaArray
            } else if matches!(
                name,
                "items"
                    | "contains"
                    | "not"
                    | "if"
                    | "then"
                    | "else"
                    | "propertyNames"
                    | "additionalProperties"
                    | "unevaluatedProperties"
                    | "unevaluatedItems"
                    | "contentSchema"
            ) && matches!(value, Value::Object(_) | Value::Bool(_) | Value::Array(_))
            {
                if matches!(value, Value::Array(_)) {
                    WalkContext::SchemaArray
                } else {
                    WalkContext::Schema
                }
            } else {
                WalkContext::Skip
            }
        }
    }
}

fn input_error(
    code: &'static str,
    message: impl Into<String>,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Diagnostic {
    attach_source_pointer(Diagnostic::input(code, message), source_id, pointer)
}

fn io_error(
    code: &'static str,
    message: impl Into<String>,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Diagnostic {
    attach_source_pointer(Diagnostic::config(code, message), source_id, pointer)
}

fn attach_source_pointer(
    mut diagnostic: Diagnostic,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Diagnostic {
    if let Some(source_id) = source_id {
        diagnostic = diagnostic.with_source(source_id);
    }
    if let Some(pointer) = pointer {
        diagnostic = diagnostic.with_json_pointer(pointer);
    }
    diagnostic
}

fn limit_error(code: &'static str, name: &str, value: u64, source_id: &str) -> Diagnostic {
    input_error(
        code,
        format!("limits.{name} ({value}) exceeded while loading '{source_id}'"),
        Some(source_id),
        None,
    )
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedConfig, load_config};
    use crate::diag::{Category, Severity};

    fn write(root: &Path, relative: &str, contents: &str) -> PathBuf {
        let path = root.join(relative);
        let parent = path
            .parent()
            .expect("joined fixture paths always have a parent");
        fs::create_dir_all(parent).expect("fixture parent should be created");
        fs::write(&path, contents).expect("fixture should be written");
        path
    }

    fn resolved_config(root: &Path, extra: &str) -> ResolvedConfig {
        fs::create_dir_all(root.join("workspace")).expect("workspace should be created");
        let config = format!(
            "schemaVersion: 1\nworkspaceRoot: workspace\ninput: {{ path: entry.yaml }}\noutput: generated\n{extra}"
        );
        let path = write(root, "oasts.yaml", &config);
        load_config(Some(&path), root).expect("fixture config should resolve")
    }

    fn resolved_json_config(root: &Path) -> ResolvedConfig {
        fs::create_dir_all(root.join("workspace")).expect("workspace should be created");
        let path = write(
            root,
            "oasts.yaml",
            "schemaVersion: 1\nworkspaceRoot: workspace\ninput: { path: entry.json }\noutput: generated\n",
        );
        load_config(Some(&path), root).expect("fixture config should resolve")
    }

    fn load_ok(config: &ResolvedConfig) -> DocumentGraph {
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(config, &mut sink).expect("graph should load");
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
        graph
    }

    fn assert_load_code(config: &ResolvedConfig, code: &str) -> Diagnostic {
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(config, &mut sink).is_none());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .expect("expected loader diagnostic code")
            .clone();
        assert_eq!(diagnostic.category, Category::Input);
        assert_eq!(diagnostic.category.exit_code(), 1);
        diagnostic
    }

    #[test]
    fn declares_identifier_matches_every_dollar_spelling() {
        // The dollar as the unicode escape (JSON, and YAML double-quoted) and as the YAML
        // hex escape, spelled here so the test cannot silently degrade to a literal dollar.
        const UNICODE_ESCAPE: &str = "\\u0024";
        const HEX_ESCAPE: &str = "\\x24";
        for spelling in ["$", UNICODE_ESCAPE, HEX_ESCAPE] {
            for identifier in ["anchor", "dynamicAnchor", "recursiveAnchor", "id"] {
                let raw = format!("{{\"{spelling}{identifier}\": \"a\"}}");
                assert!(declares_identifier(raw.as_bytes()), "{raw}");
            }
        }
    }

    #[test]
    fn declares_identifier_rejects_near_misses() {
        for raw in [
            // A dollar that starts an unrelated keyword.
            "{\"$ref\": \"#/x\"}",
            // A backslash escape whose code point is not the dollar.
            "{\"\\u0041nchor\": \"a\"}",
            // A dollar spelling with no room left for a suffix.
            "$",
            // The suffixes alone, unprefixed.
            "{\"id\": 1, \"anchor\": 2}",
            "",
        ] {
            assert!(!declares_identifier(raw.as_bytes()), "{raw}");
        }
    }

    #[test]
    fn authorize_path_prefers_the_most_specific_allow_root() {
        let file = Path::new("/allow/nested/doc.yaml");
        let workspace = Path::new("/elsewhere");
        for (roots, expected_index) in [
            (["/allow", "/allow/nested"], 1),
            (["/allow/nested", "/allow"], 0),
        ] {
            let roots = roots.map(|root| AllowRoot {
                canonical_path: PathBuf::from(root),
            });
            let (prefix, suffix) =
                authorize_path(file, workspace, &roots).expect("allow root should match");
            assert_eq!(prefix, format!("allow/{expected_index}"));
            assert_eq!(suffix, Path::new("doc.yaml"));
        }
    }

    #[test]
    fn dedup_value_deserializes_from_a_string_deserializer() {
        // serde monomorphizes this instantiation from the magic-number plumbing even though
        // from_slice never drives it; exercise it so the string path stays verified.
        use serde::de::IntoDeserializer;
        let deserializer: serde::de::value::StringDeserializer<serde_json::Error> =
            "text".to_owned().into_deserializer();
        let DedupValue(value) = DedupValue::deserialize(deserializer).expect("string input");
        assert_eq!(value, Value::String("text".to_owned()));
    }

    #[test]
    fn dedup_visitor_scalar_methods_build_values() {
        // With arbitrary_precision every number reaches the visitor as the private-token map, so
        // the plain scalar hooks are unreachable through from_slice — exercise them directly.
        type E = serde_json::Error;
        assert_eq!(
            DedupValueVisitor.visit_bool::<E>(true).expect("bool").0,
            Value::Bool(true)
        );
        assert_eq!(
            DedupValueVisitor.visit_i64::<E>(-5).expect("i64").0,
            Value::Number((-5i64).into())
        );
        assert_eq!(
            DedupValueVisitor.visit_u64::<E>(7).expect("u64").0,
            Value::Number(7u64.into())
        );
        assert_eq!(
            DedupValueVisitor.visit_str::<E>("s").expect("str").0,
            Value::String("s".to_owned())
        );
        assert_eq!(
            DedupValueVisitor.visit_unit::<E>().expect("unit").0,
            Value::Null
        );
    }

    #[test]
    fn dedup_visitor_expecting_names_a_json_value() {
        // serde only consults `expecting` on type-mismatch paths, and DedupValue accepts every
        // JSON shape, so the deserializer can never reach it — exercise it directly.
        struct Expecting;
        impl fmt::Display for Expecting {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                DedupValueVisitor.expecting(formatter)
            }
        }
        assert_eq!(Expecting.to_string(), "a JSON value");
    }

    #[test]
    fn json_duplicate_object_key_is_fatal() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.json",
            "{\n  \"a\": 1,\n  \"a\": 2\n}\n",
        );
        let config = resolved_json_config(directory.path());
        let mut sink = DiagnosticSink::new();

        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice().len(), 1);
        let diagnostic = &sink.as_slice()[0];
        assert_eq!(diagnostic.code, CODE_DOCUMENT_PARSE);
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(diagnostic.message.contains("invalid JSON document"));
        assert!(diagnostic.message.contains("duplicate object key 'a'"));
        assert!(diagnostic.line.is_some());
        assert!(diagnostic.col.is_some());
    }

    #[test]
    fn json_duplicate_key_in_nested_object_is_fatal() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.json",
            r#"{"outer":[{"nested":{"a":1,"a":2}}]}"#,
        );
        let config = resolved_json_config(directory.path());

        let diagnostic = assert_load_code(&config, CODE_DOCUMENT_PARSE);

        assert!(diagnostic.message.contains("invalid JSON document"));
        assert!(diagnostic.message.contains("duplicate object key 'a'"));
    }

    #[test]
    fn json_same_key_in_sibling_objects_is_fine() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.json",
            r#"[{"a":1,"nested":{"a":3}},{"a":2,"nested":{"a":4}}]"#,
        );
        let config = resolved_json_config(directory.path());

        let graph = load_ok(&config);

        assert_eq!(graph.entry().value[0]["a"], 1);
        assert_eq!(graph.entry().value[1]["nested"]["a"], 4);
    }

    #[test]
    fn json_arbitrary_precision_number_roundtrips() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.json",
            r#"{"hugeFloat":1e999,"hugeInteger":123456789012345678901234567890}"#,
        );
        let config = resolved_json_config(directory.path());

        let graph = load_ok(&config);
        let document = &graph.entry().value;

        assert_eq!(
            document["hugeFloat"].as_number().map(ToString::to_string),
            Some("1e+999".to_owned())
        );
        assert_eq!(
            document["hugeInteger"].as_number().map(ToString::to_string),
            Some("123456789012345678901234567890".to_owned())
        );
    }

    #[test]
    fn json_value_visitor_describes_expected_input() {
        let error = <serde::de::value::Error as serde::de::Error>::invalid_type(
            serde::de::Unexpected::Other("non-JSON input"),
            &DedupValueVisitor,
        );

        assert_eq!(
            error.to_string(),
            "invalid type: non-JSON input, expected a JSON value"
        );
    }

    #[test]
    fn loads_multifile_graph_and_resolves_nested_references() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: ./schemas/pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "workspace/schemas/pet.yaml",
            "Pet:\n  type: object\n  properties:\n    friend:\n      $ref: nested.yaml#/Friend\n",
        );
        write(
            directory.path(),
            "workspace/schemas/nested.yaml",
            "Friend:\n  type: object\n  properties:\n    name: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        assert_eq!(graph.documents().len(), 3);
        assert_eq!(graph.edges().len(), 2);
        let ids = graph
            .source_tuples()
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "workspace/entry.yaml",
                "workspace/schemas/nested.yaml",
                "workspace/schemas/pet.yaml",
            ]
        );
        let pet = graph
            .resolve(
                graph.entry().id,
                "./schemas/pet.yaml#/Pet/properties/friend",
            )
            .expect("cross-file node should resolve");
        assert_eq!(pet.value["$ref"], "nested.yaml#/Friend");
    }

    #[test]
    fn graph_resolve_reuses_the_loaded_document_for_fragment_only_references() {
        let directory = TempDir::new().expect("tempdir should be created");
        let entry = write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);
        fs::remove_file(entry).expect("loaded document should be removable");

        let pet = graph
            .resolve(graph.entry().id, "#/components/schemas/Pet")
            .expect("fragment-only reference should reuse the loaded document");

        assert_eq!(pet.value["type"], "string");
    }

    #[test]
    fn input_yaml_resolves_anchors_aliases_and_merge_keys() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            concat!(
                "openapi: 3.1.0\n",
                "components:\n",
                "  parameters:\n",
                "    Common: &common\n",
                "      name: id\n",
                "      in: query\n",
                "      schema: { type: string }\n",
                "paths:\n",
                "  /pets:\n",
                "    parameters:\n",
                "      - *common\n",
                "    get:\n",
                "      parameters:\n",
                "        - name: id\n",
                "          in: query\n",
                "          schema: { type: string }\n",
                "      responses: {}\n",
                "x-first: &first [*common]\n",
                "x-second: &second [*first]\n",
                "x-third: *second\n",
                "x-merge:\n",
                "  <<: *common\n",
            ),
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);
        let document = &graph.entry().value;

        assert_eq!(
            document["paths"]["/pets"]["parameters"][0],
            document["paths"]["/pets"]["get"]["parameters"][0]
        );
        assert_eq!(document["x-third"], document["x-second"]);
        assert_eq!(document["x-second"][0], document["x-first"]);
        assert_eq!(
            document["x-merge"],
            document["components"]["parameters"]["Common"]
        );
    }

    #[test]
    fn input_yaml_alias_expansion_has_a_named_node_budget() {
        let directory = TempDir::new().expect("tempdir should be created");
        let mut document = String::from("openapi: 3.1.0\npaths: {}\nx0: &a0 leaf\n");
        for level in 1..=13 {
            document.push_str(&format!(
                "x{level}: &a{level} [*a{}, *a{}, *a{}]\n",
                level - 1,
                level - 1,
                level - 1
            ));
        }
        write(directory.path(), "workspace/entry.yaml", &document);
        let config = resolved_config(directory.path(), "");

        let diagnostic = assert_load_code(&config, CODE_DOCUMENT_PARSE);

        assert!(diagnostic.message.contains("alias expansion"));
        assert!(diagnostic.message.contains("1000000"));
    }

    #[test]
    fn allow_paths_use_config_index_and_longest_containing_root() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: ../allowed/deep/pet.yaml#/Pet\n    Other:\n      $ref: ../allowed/other.yaml#/Other\n",
        );
        write(
            directory.path(),
            "allowed/deep/pet.yaml",
            "Pet: { type: string }\n",
        );
        write(
            directory.path(),
            "allowed/other.yaml",
            "Other: { type: number }\n",
        );
        let config = resolved_config(
            directory.path(),
            "local:\n  allowPaths: [allowed, allowed/deep]\n",
        );

        let graph = load_ok(&config);
        let ids = graph
            .source_tuples()
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        assert!(ids.contains(&"allow/0/other.yaml".to_owned()));
        assert!(ids.contains(&"allow/1/pet.yaml".to_owned()));
    }

    #[test]
    fn reference_outside_every_authorized_root_is_rejected() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: ../outside/pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "outside/pet.yaml",
            "Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");

        let diagnostic = assert_load_code(&config, CODE_REF_ESCAPE);
        assert!(diagnostic.message.contains("escapes workspaceRoot"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_workspace_pointing_outside_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: escape/pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "outside/pet.yaml",
            "Pet: { type: string }\n",
        );
        symlink(
            directory.path().join("outside"),
            directory.path().join("workspace/escape"),
        )
        .expect("fixture symlink should be created");
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_REF_ESCAPE);
    }

    #[test]
    fn remote_reference_is_rejected_without_fetching() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: https://example.invalid/pet.yaml#/Pet\n",
        );
        let config = resolved_config(directory.path(), "");

        let diagnostic = assert_load_code(&config, CODE_REMOTE_UNSUPPORTED);
        assert!(diagnostic.message.contains("not supported in this build"));
    }

    #[test]
    fn non_file_scheme_entry_is_rejected_as_remote_input() {
        let directory = TempDir::new().expect("tempdir should be created");
        let config_path = write(
            directory.path(),
            "oasts.yaml",
            "schemaVersion: 1\ninput: { url: https://example.invalid/openapi.yaml }\noutput: generated\n",
        );
        let config = load_config(Some(&config_path), directory.path())
            .expect("remote input should reach the loader");

        assert_load_code(&config, CODE_REMOTE_UNSUPPORTED);
    }

    #[test]
    fn logical_id_encoding_is_segment_based_and_does_not_normalize_unicode() {
        assert_eq!(
            encode_relative_path(Path::new("%2F")),
            Ok("%252F".to_owned())
        );
        assert_eq!(encode_relative_path(Path::new("a/b")), Ok("a/b".to_owned()));
        assert_eq!(encode_relative_path(Path::new("%")), Ok("%25".to_owned()));
        assert_eq!(
            encode_relative_path(Path::new("a b")),
            Ok("a%20b".to_owned())
        );
        assert_eq!(encode_relative_path(Path::new("#")), Ok("%23".to_owned()));
        let composed = encode_relative_path(Path::new("é")).expect("path should encode");
        let decomposed = encode_relative_path(Path::new("e\u{301}")).expect("path should encode");
        assert_eq!(composed, "%C3%A9");
        assert_eq!(decomposed, "e%CC%81");
        assert_ne!(composed, decomposed);
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_canonical_path_is_a_named_input_diagnostic() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let directory = TempDir::new().expect("tempdir should be created");
        write(directory.path(), "workspace/entry.yaml", "openapi: 3.1.0\n");
        let mut config = resolved_config(directory.path(), "");
        let invalid_name = OsString::from_vec(vec![b'n', b'o', b'n', 0xff]);
        let invalid_path = directory.path().join("workspace").join(invalid_name);
        fs::write(&invalid_path, "openapi: 3.1.0\n")
            .expect("non-Unicode fixture should be written");
        config.input = invalid_path;

        assert_load_code(&config, CODE_NON_UNICODE_PATH);
    }

    #[test]
    fn logical_ids_are_stable_across_checkout_relocation() {
        fn fixture(root: &Path) -> Vec<(String, [u8; 32])> {
            write(
                root,
                "workspace/entry.yaml",
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: schemas/pet.yaml#/Pet\n",
            );
            write(
                root,
                "workspace/schemas/pet.yaml",
                "Pet: { type: string }\n",
            );
            let config = resolved_config(root, "");
            load_ok(&config).source_tuples()
        }

        let first = TempDir::new().expect("first tempdir should be created");
        let second = TempDir::new().expect("second tempdir should be created");
        let first_tuples = fixture(first.path());
        let second_tuples = fixture(second.path());

        assert_eq!(first_tuples, second_tuples);
        for (id, _) in first_tuples {
            assert!(!id.contains(first.path().to_string_lossy().as_ref()));
            assert!(!id.contains(second.path().to_string_lossy().as_ref()));
        }
    }

    #[test]
    fn json_pointer_unescapes_tilde_and_slash_tokens() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    'a/b':\n      type: object\n      properties:\n        '~key': { type: string }\n    Holder:\n      $ref: '#/components/schemas/a~1b/properties/~0key'\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);

        let node = graph
            .resolve(
                graph.entry().id,
                "#/components/schemas/a~1b/properties/~0key",
            )
            .expect("escaped pointer should resolve");
        assert_eq!(node.value["type"], "string");
    }

    #[test]
    fn missing_json_pointer_target_is_an_input_diagnostic() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: '#/components/schemas/Missing'\n",
        );
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_POINTER);
    }

    #[test]
    fn max_ref_depth_names_limit_and_offending_document() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    A:\n      $ref: a.yaml#/A\n",
        );
        write(
            directory.path(),
            "workspace/a.yaml",
            "A:\n  $ref: b.yaml#/B\n",
        );
        write(
            directory.path(),
            "workspace/b.yaml",
            "B: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "limits:\n  maxRefDepth: 1\n");

        let diagnostic = assert_load_code(&config, CODE_MAX_REF_DEPTH);
        assert!(diagnostic.message.contains("maxRefDepth"));
        assert_eq!(diagnostic.source_id.as_deref(), Some("workspace/b.yaml"));
    }

    #[test]
    fn max_document_bytes_is_enforced() {
        let directory = TempDir::new().expect("tempdir should be created");
        let entry = format!("openapi: 3.1.0\n# {}\n", "x".repeat(1_100));
        write(directory.path(), "workspace/entry.yaml", &entry);
        let config = resolved_config(directory.path(), "limits:\n  maxDocumentBytes: 1024\n");

        assert_load_code(&config, CODE_MAX_DOCUMENT_BYTES);
    }

    #[test]
    fn max_documents_is_enforced() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "workspace/pet.yaml",
            "Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "limits:\n  maxDocuments: 1\n");

        assert_load_code(&config, CODE_MAX_DOCUMENTS);
    }

    #[test]
    fn max_total_bytes_is_enforced() {
        let directory = TempDir::new().expect("tempdir should be created");
        let entry = format!(
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: pet.yaml#/Pet\n# {}\n",
            "e".repeat(520)
        );
        let pet = format!("Pet: {{ type: string }}\n# {}\n", "p".repeat(520));
        write(directory.path(), "workspace/entry.yaml", &entry);
        write(directory.path(), "workspace/pet.yaml", &pet);
        let config = resolved_config(directory.path(), "limits:\n  maxTotalBytes: 1024\n");

        assert_load_code(&config, CODE_MAX_TOTAL_BYTES);
    }

    #[test]
    fn schema_position_cycle_is_legal_and_retained_as_an_edge() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      type: object\n      properties:\n        children:\n          type: array\n          items:\n            $ref: '#/components/schemas/Pet'\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].position, PositionKind::Schema);
    }

    #[test]
    fn cycle_through_non_schema_position_is_rejected() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  responses:\n    A:\n      $ref: '#/components/responses/B'\n    B:\n      $ref: '#/components/responses/A'\n",
        );
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_NON_SCHEMA_CYCLE);
    }

    #[test]
    fn schema_id_changes_the_base_for_nested_relative_refs() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Holder:\n      $id: ./sub/x.yaml\n      type: object\n      properties:\n        pet:\n          $ref: pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "workspace/sub/pet.yaml",
            "Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);
        assert!(
            graph
                .source_tuples()
                .iter()
                .any(|(id, _)| id == "workspace/sub/pet.yaml")
        );
    }

    #[test]
    fn same_file_forward_anchor_reference_resolves() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Forward:\n      $ref: '#Foo'\n    Target:\n      $anchor: Foo\n      type: string\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        assert_eq!(graph.edges().len(), 1);
        assert_eq!(
            graph.edges()[0].to.json_pointer,
            "/components/schemas/Target"
        );
        let target = graph
            .resolve(graph.entry().id, "#Foo")
            .expect("plain-name anchor should resolve");
        assert_eq!(target.value["type"], "string");
        assert_eq!(
            graph
                .resolve(graph.entry().id, "#%")
                .expect_err("invalid percent escape should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
    }

    #[test]
    fn unicode_escaped_dollar_anchor_key_still_registers() {
        // The raw file bytes spell the `$anchor` key with the dollar as the JSON `$` unicode
        // escape, so the fast-reject must fire on that spelling or the anchor never registers and
        // `#Foo` fails to resolve. Build the escape from bytes so this test source carries no
        // backslash that a JSON-escaping toolchain could collapse back into a literal `$`.
        let escaped_dollar_bytes = [0x5C, 0x75, 0x30, 0x30, 0x32, 0x34u8];
        let escaped_dollar = std::str::from_utf8(&escaped_dollar_bytes)
            .expect("ascii unicode escape is valid utf-8");
        let content = [
            r##"{"openapi":"3.1.0","components":{"schemas":{"Forward":{"$ref":"#Foo"},"Target":{""##,
            escaped_dollar,
            r##"anchor":"Foo","type":"string"}}}}"##,
        ]
        .concat();

        let directory = TempDir::new().expect("tempdir should be created");
        write(directory.path(), "workspace/entry.json", &content);
        let config = resolved_json_config(directory.path());

        let graph = load_ok(&config);
        let target = graph
            .resolve(graph.entry().id, "#Foo")
            .expect("escaped-dollar anchor should register and resolve");
        assert_eq!(target.value["type"], "string");
    }

    #[test]
    fn anchor_resolution_uses_the_innermost_schema_id_scope() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    RootTarget:\n      $anchor: Foo\n      type: string\n    Inner:\n      $id: ./inner.json\n      $defs:\n        InnerTarget:\n          $anchor: Foo\n          type: number\n        Reference:\n          $ref: '#Foo'\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        let edge = graph
            .edges()
            .iter()
            .find(|edge| edge.reference == "#Foo")
            .expect("inner reference edge");
        assert_eq!(
            edge.to.json_pointer,
            "/components/schemas/Inner/$defs/InnerTarget"
        );
        let root_target = graph
            .resolve(graph.entry().id, "#Foo")
            .expect("root anchor should resolve");
        assert_eq!(root_target.value["type"], "string");
        let inner_target = graph
            .resolve(graph.entry().id, "./inner.json#Foo")
            .expect("inner resource anchor should resolve");
        assert_eq!(inner_target.value["type"], "number");
    }

    #[test]
    fn cross_file_anchor_reference_resolves() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    External:\n      $ref: './b.yaml#Foo'\n",
        );
        write(
            directory.path(),
            "workspace/b.yaml",
            "$anchor: Foo\ntype: boolean\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to.doc_id, DocId(1));
        assert_eq!(graph.edges()[0].to.json_pointer, "");
        let target = graph
            .resolve(graph.entry().id, "./b.yaml#Foo")
            .expect("cross-file anchor should resolve");
        assert_eq!(target.value["type"], "boolean");
    }

    #[test]
    fn dynamic_reference_resolution_distinguishes_pinned_plain_and_path_dependent_targets() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Plain:\n      $anchor: Ordinary\n      type: string\n    Pinned:\n      $id: https://example.invalid/pinned\n      $dynamicAnchor: Only\n      $defs:\n        Reference:\n          $dynamicRef: '#Only'\n    First:\n      $id: https://example.invalid/first\n      $dynamicAnchor: Shared\n      $defs:\n        Reference:\n          $dynamicRef: '#Shared'\n    Second:\n      $id: https://example.invalid/second\n      $dynamicAnchor: Shared\n      type: number\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);
        let entry = graph.entry().id;

        assert_eq!(
            graph
                .resolve_dynamic_ref(entry, "/components/schemas/Plain", "#Ordinary")
                .expect("plain anchor should resolve like $ref"),
            DynamicResolution::Plain
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(
                    entry,
                    "/components/schemas/Plain",
                    "#/components/schemas/Pinned",
                )
                .expect("pointer fragment should resolve like $ref"),
            DynamicResolution::Plain
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(
                    entry,
                    "/components/schemas/Plain",
                    "https://example.invalid/pinned",
                )
                .expect("fragmentless reference should resolve like $ref"),
            DynamicResolution::Plain
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(entry, "/components/schemas/Pinned/$defs/Reference", "#Only",)
                .expect("one declaring resource pins the target"),
            DynamicResolution::Pinned(NodeLocation {
                doc_id: entry,
                json_pointer: "/components/schemas/Pinned".to_owned(),
            })
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(
                    entry,
                    "/components/schemas/First/$defs/Reference",
                    "#Shared",
                )
                .expect("two declaring resources defer the target"),
            DynamicResolution::PathDependent {
                declaring_resources: 2,
            }
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(entry, "/components/schemas/Pinned/$defs/Reference", "#%",)
                .expect_err("invalid percent escape should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
    }

    #[test]
    fn recursive_reference_resolution_distinguishes_all_resource_shapes() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    First:\n      $id: https://example.invalid/first\n      $recursiveAnchor: true\n      $defs:\n        Reference:\n          $recursiveRef: '#'\n    Second:\n      $id: https://example.invalid/second\n      $recursiveAnchor: true\n    Disabled:\n      $id: https://example.invalid/disabled\n      $recursiveAnchor: false\n      $defs:\n        Reference: {}\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);
        let entry = graph.entry().id;

        assert_eq!(
            graph
                .resolve_recursive_ref(entry, "/components/schemas/First/$defs/Reference")
                .expect("two recursive resources defer the target"),
            DynamicResolution::PathDependent {
                declaring_resources: 2,
            }
        );
        assert_eq!(
            graph
                .resolve_recursive_ref(entry, "/components/schemas/Disabled/$defs/Reference")
                .expect("false recursive anchor behaves like $ref"),
            DynamicResolution::Plain
        );
        assert_eq!(
            graph
                .resolve_recursive_ref(entry, "/components/schemas")
                .expect("OpenAPI root is not a schema resource"),
            DynamicResolution::NonSchemaRoot
        );

        let schema_directory = TempDir::new().expect("tempdir should be created");
        write(
            schema_directory.path(),
            "workspace/entry.yaml",
            "$recursiveAnchor: true\n$recursiveRef: '#'\n",
        );
        let schema_config = resolved_config(schema_directory.path(), "");
        let schema_graph = load_ok(&schema_config);
        assert_eq!(
            schema_graph
                .resolve_recursive_ref(schema_graph.entry().id, "")
                .expect("standalone schema root should pin"),
            DynamicResolution::Pinned(NodeLocation {
                doc_id: schema_graph.entry().id,
                json_pointer: String::new(),
            })
        );
    }

    #[test]
    fn dynamic_identifier_shapes_and_duplicates_are_rejected() {
        for schema in [
            "Invalid:\n      $dynamicAnchor: 9bad\n",
            "Invalid:\n      $dynamicAnchor: 7\n",
            "First:\n      $dynamicAnchor: Same\n    Second:\n      $dynamicAnchor: Same\n",
            "Invalid:\n      $recursiveAnchor: yes\n",
        ] {
            let directory = TempDir::new().expect("tempdir should be created");
            write(
                directory.path(),
                "workspace/entry.yaml",
                &format!("openapi: 3.1.0\ncomponents:\n  schemas:\n    {schema}"),
            );
            let config = resolved_config(directory.path(), "");

            assert_load_code(&config, CODE_INVALID_REFERENCE);
        }
    }

    #[test]
    fn absolute_id_resolves_to_registered_resource_without_fetching() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Target:\n      $id: https://example.invalid/target\n      type: string\n    Holder:\n      $ref: https://example.invalid/target\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        assert_eq!(graph.documents().len(), 1);
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(
            graph.edges()[0].to.json_pointer,
            "/components/schemas/Target"
        );
        let target = graph
            .resolve_from(
                graph.entry().id,
                "/components/schemas/Holder",
                "https://example.invalid/target",
            )
            .expect("registered absolute identity should resolve in-document");
        assert_eq!(target.value["type"], "string");
    }

    #[test]
    fn dynamic_resolution_propagates_invalid_base_pointer_and_uri_errors() {
        let directory = TempDir::new().expect("tempdir should be created");
        // The `$id` matters: it registers a schema resource, which is what makes the base-URI walk
        // run at all. A document declaring none takes the fast path that answers with the
        // document's own URI without walking, so there is no pointer there to be invalid.
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Plain: { $id: 'plain', type: string }\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);
        let entry = graph.entry().id;

        assert_eq!(
            graph
                .resolve_from(entry, "/components/schemas/Plain", "http://[")
                .expect_err("invalid URI should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
        assert_eq!(
            graph
                .resolve_dynamic_ref(entry, "/components/schemas/Missing", "#Node")
                .expect_err("invalid dynamic reference location should fail")
                .code,
            CODE_POINTER
        );
        assert_eq!(
            graph
                .resolve_recursive_ref(entry, "/components/schemas/Missing")
                .expect_err("invalid recursive reference location should fail")
                .code,
            CODE_POINTER
        );
    }

    #[test]
    fn registered_resource_rejects_an_invalid_pointer_fragment() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Target:\n      $id: https://example.invalid/target\n      type: string\n    Holder:\n      $ref: https://example.invalid/target#/%\n",
        );
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_INVALID_REFERENCE);
    }

    #[test]
    fn invalid_anchor_name_is_fatal() {
        for anchor in ["9bad", "7"] {
            let directory = TempDir::new().expect("tempdir should be created");
            write(
                directory.path(),
                "workspace/entry.yaml",
                &format!(
                    "openapi: 3.1.0\ncomponents:\n  schemas:\n    Invalid:\n      $anchor: {anchor}\n      type: string\n"
                ),
            );
            let config = resolved_config(directory.path(), "");

            assert_load_code(&config, CODE_INVALID_REFERENCE);
        }
    }

    #[test]
    fn duplicate_anchor_in_one_resource_is_fatal() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    First:\n      $anchor: Same\n      type: string\n    Second:\n      $anchor: Same\n      type: number\n",
        );
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_INVALID_REFERENCE);
    }

    #[test]
    fn unknown_anchor_name_is_fatal() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Missing:\n      $ref: '#Unknown'\n",
        );
        let config = resolved_config(directory.path(), "");

        let diagnostic = assert_load_code(&config, CODE_INVALID_REFERENCE);
        assert_eq!(
            diagnostic.message,
            "no $anchor 'Unknown' in the target resource"
        );
    }

    #[test]
    fn invalid_percent_escape_in_anchor_reference_is_fatal() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Target:\n      $anchor: Known\n      type: string\n    Invalid:\n      $ref: '#%'\n",
        );
        let config = resolved_config(directory.path(), "");

        assert_load_code(&config, CODE_INVALID_REFERENCE);
    }

    #[test]
    fn document_without_anchor_text_loads_successfully() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Plain: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);

        assert_eq!(graph.documents().len(), 1);
    }

    #[test]
    fn anchor_collection_skips_invalid_id_subtrees_and_walks_schema_arrays() {
        let directory = TempDir::new().expect("tempdir should be created");
        let base = file_url(&directory.path().join("entry.yaml")).expect("file URL");
        let value = json!({
            "$anchor": "_Root.good-name",
            "allOf": [
                { "$anchor": "ArrayTarget", "type": "string" },
                { "$id": 7, "$anchor": 5 },
                { "$id": "https://example.invalid/schema", "$anchor": "Remote" }
            ]
        });
        let mut identifiers = IdentifierRegistry::default();

        collect_anchors(
            &value,
            DocId(4),
            base.clone(),
            "entry.yaml",
            &mut identifiers,
        )
        .expect("invalid IDs should stop only their subtrees");

        assert_eq!(identifiers.anchors.len(), 3);
        // An absolute `$id` names a schema resource; it is not a request to fetch one. The anchor
        // beneath it registers against that resource URI rather than the enclosing document's.
        assert_eq!(
            identifiers
                .anchors
                .get(&(
                    "https://example.invalid/schema".to_owned(),
                    "Remote".to_owned()
                ))
                .expect("absolute-$id anchor"),
            &NodeLocation {
                doc_id: DocId(4),
                json_pointer: "/allOf/2".to_owned(),
            }
        );
        assert_eq!(
            identifiers
                .resources
                .get("https://example.invalid/schema")
                .expect("absolute-$id resource"),
            &NodeLocation {
                doc_id: DocId(4),
                json_pointer: "/allOf/2".to_owned(),
            }
        );
        assert_eq!(
            identifiers
                .anchors
                .get(&(resource_base_uri(&base), "ArrayTarget".to_owned()))
                .expect("array anchor"),
            &NodeLocation {
                doc_id: DocId(4),
                json_pointer: "/allOf/0".to_owned(),
            }
        );
        collect_anchors_at(
            &json!({ "$anchor": 5 }),
            DocId(4),
            "",
            WalkContext::Skip,
            base.clone(),
            "entry.yaml",
            &mut identifiers,
        )
        .expect("skipped contexts are ignored");
        collect_anchors_at(
            &json!([]),
            DocId(4),
            "",
            WalkContext::SchemaMap,
            base.clone(),
            "entry.yaml",
            &mut identifiers,
        )
        .expect("schema-map arrays are ignored");
        assert_eq!(
            collect_anchors_at(
                &json!({ "$anchor": 5 }),
                DocId(4),
                "",
                WalkContext::Schema,
                base,
                "entry.yaml",
                &mut identifiers,
            )
            .expect_err("non-string anchor should fail")
            .code,
            CODE_INVALID_REFERENCE
        );
        assert_eq!(
            collect_anchors(
                &json!({ "allOf": [{ "$anchor": "9bad" }] }),
                DocId(4),
                file_url(&directory.path().join("invalid.yaml")).expect("file URL"),
                "invalid.yaml",
                &mut identifiers,
            )
            .expect_err("array child errors should propagate")
            .code,
            CODE_INVALID_REFERENCE
        );

        let no_fragment = Url::parse("file:///entry.yaml").expect("URL");
        assert_eq!(
            registered_anchor_location(&no_fragment, &identifiers.anchors, None, None)
                .expect("lookup should succeed"),
            None
        );
        let pointer_fragment = Url::parse("file:///entry.yaml#/%").expect("URL");
        assert_eq!(
            registered_anchor_location(&pointer_fragment, &identifiers.anchors, None, None)
                .expect("lookup should succeed"),
            None
        );
        let encoded_pointer = Url::parse("file:///entry.yaml#%2Ftarget").expect("URL");
        assert_eq!(
            registered_anchor_location(&encoded_pointer, &identifiers.anchors, None, None)
                .expect("lookup should succeed"),
            None
        );
        assert_eq!(
            pointer_or_anchor(&encoded_pointer, DocId(4), &identifiers.anchors, None, None)
                .expect("encoded pointer should resolve"),
            NodeLocation {
                doc_id: DocId(4),
                json_pointer: "/target".to_owned(),
            }
        );
        let invalid_percent = Url::parse("file:///entry.yaml#%").expect("URL");
        assert_eq!(
            pointer_or_anchor(&invalid_percent, DocId(4), &identifiers.anchors, None, None)
                .expect_err("invalid percent escape should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
        let invalid_pointer = Url::parse("file:///entry.yaml#%2Fbad~2escape").expect("URL");
        assert_eq!(
            pointer_or_anchor(&invalid_pointer, DocId(4), &identifiers.anchors, None, None)
                .expect_err("invalid decoded pointer should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
    }

    #[test]
    fn ancestor_schema_id_applies_when_a_cross_file_ref_targets_a_fragment() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Child:\n      $ref: defs.yaml#/$defs/Child\n",
        );
        write(
            directory.path(),
            "workspace/defs.yaml",
            "$id: ./sub/root.yaml\n$defs:\n  Child:\n    type: object\n    properties:\n      pet:\n        $ref: pet.yaml#/Pet\n",
        );
        write(
            directory.path(),
            "workspace/sub/pet.yaml",
            "Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");

        let graph = load_ok(&config);
        assert!(
            graph
                .source_tuples()
                .iter()
                .any(|(id, _)| id == "workspace/sub/pet.yaml")
        );
    }

    #[test]
    fn graph_resolve_reports_invalid_ids_paths_and_pointers() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet: { type: string }\n",
        );
        let config = resolved_config(directory.path(), "");
        let graph = load_ok(&config);

        assert_eq!(DocId(7).index(), 7);
        assert_eq!(
            graph.resolve(DocId(99), "#").expect_err("unknown ID").code,
            CODE_INVALID_REFERENCE
        );
        assert_eq!(
            graph
                .resolve(graph.entry().id, "missing.yaml")
                .expect_err("missing file")
                .code,
            CODE_DOCUMENT_IO
        );

        write(directory.path(), "workspace/unloaded.yaml", "value: true\n");
        assert_eq!(
            graph
                .resolve(graph.entry().id, "unloaded.yaml")
                .expect_err("unloaded file")
                .code,
            CODE_DOCUMENT_IO
        );
        write(directory.path(), "outside.yaml", "value: true\n");
        assert_eq!(
            graph
                .resolve(graph.entry().id, "../outside.yaml")
                .expect_err("escaped file")
                .code,
            CODE_REF_ESCAPE
        );
        for (reference, code) in [
            (
                "https://example.invalid/schema.yaml",
                CODE_REMOTE_UNSUPPORTED,
            ),
            ("#/%", CODE_INVALID_REFERENCE),
            ("#not-a-pointer", CODE_INVALID_REFERENCE),
            ("#/missing", CODE_POINTER),
        ] {
            assert_eq!(
                graph
                    .resolve(graph.entry().id, reference)
                    .expect_err("invalid resolution")
                    .code,
                code
            );
        }
    }

    #[test]
    fn builder_reports_workspace_allow_root_entry_and_parse_io_errors() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(directory.path(), "workspace/entry.yaml", "openapi: 3.1.0\n");
        let mut config = resolved_config(directory.path(), "");

        config.workspace_root = directory.path().join("missing-workspace");
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice()[0].code, CODE_DOCUMENT_IO);

        config = resolved_config(directory.path(), "");
        config.local_allow_paths = vec![directory.path().join("missing-allow-root")];
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice()[0].code, CODE_DOCUMENT_IO);

        config = resolved_config(directory.path(), "");
        config.input = directory.path().join("workspace/missing.yaml");
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice()[0].code, CODE_DOCUMENT_IO);

        for (name, contents) in [
            ("bad.json", "{"),
            ("bad.yaml", "value: ["),
            ("bad.unknown", "{ nope: ["),
        ] {
            config = resolved_config(directory.path(), "");
            config.input = write(directory.path(), &format!("workspace/{name}"), contents);
            assert_load_code(&config, CODE_DOCUMENT_PARSE);
        }

        let error = document_byte_len(
            &directory.path().join("workspace/missing-metadata.yaml"),
            "workspace/missing-metadata.yaml",
        )
        .expect_err("missing metadata should be an I/O diagnostic");
        assert_eq!(error.code, CODE_DOCUMENT_IO);
        assert!(error.message.contains("failed to read document metadata"));
        assert_eq!(
            error.source_id.as_deref(),
            Some("workspace/missing-metadata.yaml")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_document_is_an_io_diagnostic() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().expect("tempdir should be created");
        let entry = write(directory.path(), "workspace/entry.yaml", "openapi: 3.1.0\n");
        let config = resolved_config(directory.path(), "");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o000))
            .expect("permissions should change");
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o600))
            .expect("permissions should be restored");
        assert_eq!(sink.as_slice()[0].code, CODE_DOCUMENT_IO);
    }

    #[test]
    fn invalid_ref_and_schema_id_types_are_diagnostics() {
        for (document, code) in [
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: 7\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $id: 7\n      type: string\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  responses:\n    Bad:\n      $ref: false\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: 'http://['\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: '#/%'\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $id: 'http://['\n      type: string\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: https://example.invalid/schema.json\n",
                CODE_REMOTE_UNSUPPORTED,
            ),
            // Invalid $id inside an allOf element: the diagnostic propagates back
            // through the array-child walk, not the object-child walk.
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      allOf:\n        - $id: 7\n          type: string\n",
                CODE_INVALID_REFERENCE,
            ),
        ] {
            let directory = TempDir::new().expect("tempdir should be created");
            write(directory.path(), "workspace/entry.yaml", document);
            let config = resolved_config(directory.path(), "");
            assert_load_code(&config, code);
        }
    }

    #[test]
    fn missing_reference_inherits_source_and_pointer_metadata() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $ref: missing.yaml#/Pet\n",
        );
        let config = resolved_config(directory.path(), "");
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        let diagnostic = &sink.as_slice()[0];
        assert_eq!(diagnostic.code, CODE_DOCUMENT_IO);
        assert_eq!(
            diagnostic.source_id.as_deref(),
            Some("workspace/entry.yaml")
        );
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/schemas/Pet/$ref")
        );
    }

    #[test]
    fn walker_covers_arrays_skips_and_repeated_locations() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ntags:\n  - name: one\ncomponents:\n  schemas:\n    Mixed:\n      allOf:\n        - type: object\n      prefixItems:\n        - type: string\n      items:\n        - type: number\n      example:\n        $ref: missing.yaml\n",
        );
        let config = resolved_config(directory.path(), "");
        let mut builder = GraphBuilder::new(&config).expect("builder");
        let entry_id = builder
            .load_document(&config.input)
            .expect("entry should load");
        let base =
            Rc::new(file_url(&builder.documents[entry_id.0].canonical_path).expect("file URL"));
        let location = NodeLocation {
            doc_id: entry_id,
            json_pointer: String::new(),
        };
        let mut state = TraversalState::default();
        builder
            .walk_node(
                location.clone(),
                WalkContext::NonSchema,
                Rc::clone(&base),
                0,
                &mut state,
            )
            .expect("document should walk");
        builder
            .walk_node(
                location,
                WalkContext::NonSchema,
                Rc::clone(&base),
                0,
                &mut state,
            )
            .expect("visited location should be skipped");
        builder
            .walk_node(
                NodeLocation {
                    doc_id: entry_id,
                    json_pointer: String::new(),
                },
                WalkContext::Skip,
                Rc::clone(&base),
                0,
                &mut state,
            )
            .expect("skip context should return");
        builder
            .walk_node(
                NodeLocation {
                    doc_id: entry_id,
                    json_pointer: "/components/schemas/Mixed/items".to_owned(),
                },
                WalkContext::SchemaMap,
                Rc::clone(&base),
                0,
                &mut state,
            )
            .expect("schema-map array should be skipped");
        let error = builder
            .walk_node(
                NodeLocation {
                    doc_id: DocId(999),
                    json_pointer: "/missing".to_owned(),
                },
                WalkContext::Schema,
                base,
                0,
                &mut state,
            )
            .expect_err("missing node should fail");
        assert_eq!(error.code, CODE_POINTER);
    }

    #[test]
    fn walker_does_not_retain_scalar_visit_keys() {
        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.yaml",
            "openapi: 3.1.0\ninfo:\n  title: Example\n  version: 1.0.0\n",
        );
        let config = resolved_config(directory.path(), "");
        let mut builder = GraphBuilder::new(&config).expect("builder");
        let entry_id = builder
            .load_document(&config.input)
            .expect("entry should load");
        let base =
            Rc::new(file_url(&builder.documents[entry_id.0].canonical_path).expect("file URL"));
        builder
            .walk_node(
                NodeLocation {
                    doc_id: entry_id,
                    json_pointer: String::new(),
                },
                WalkContext::NonSchema,
                base,
                0,
                &mut TraversalState::default(),
            )
            .expect("document should walk");

        let mut retained = builder
            .visited
            .iter()
            .map(|key| key.location.json_pointer.as_ref())
            .collect::<Vec<_>>();
        retained.sort_unstable();
        assert_eq!(retained, ["", "/info"]);
    }

    #[test]
    fn load_document_reuses_a_cached_canonical_path_without_filesystem_access() {
        let directory = TempDir::new().expect("tempdir should be created");
        let entry = write(directory.path(), "workspace/entry.yaml", "openapi: 3.1.0\n");
        let config = resolved_config(directory.path(), "");
        let mut builder = GraphBuilder::new(&config).expect("builder");
        let id = builder.load_document(&entry).expect("entry should load");
        let canonical_path = builder.documents[id.0].canonical_path.clone();
        fs::remove_file(&canonical_path).expect("cached document should be removable");

        assert_eq!(
            builder
                .load_document(&canonical_path)
                .expect("cached document should not touch the filesystem"),
            id
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_document_reuses_a_cached_document_through_a_symlink_alias() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir should be created");
        let entry = write(directory.path(), "workspace/entry.yaml", "openapi: 3.1.0\n");
        let alias = directory.path().join("workspace/alias.yaml");
        symlink(&entry, &alias).expect("fixture symlink should be created");
        let config = resolved_config(directory.path(), "");
        let mut builder = GraphBuilder::new(&config).expect("builder");
        let id = builder.load_document(&entry).expect("entry should load");

        assert_eq!(
            builder
                .load_document(&alias)
                .expect("alias should reuse the cached document"),
            id
        );
    }

    #[test]
    fn document_parsers_cover_extensions_utf8_and_fallbacks() {
        assert_eq!(
            parse_document(Path::new("value.json"), br#"{"ok":true}"#, "json")
                .expect("JSON document")
                .0,
            json!({ "ok": true })
        );
        assert_eq!(
            parse_document(Path::new("value.yaml"), b"ok: true\n", "yaml")
                .expect("YAML document")
                .0,
            json!({ "ok": true })
        );
        assert_eq!(
            parse_document(Path::new("value.data"), br#"[1,2]"#, "fallback-json")
                .expect("fallback JSON")
                .0,
            json!([1, 2])
        );
        assert_eq!(
            parse_document(Path::new("value.data"), b"ok: true\n", "fallback-yaml")
                .expect("fallback YAML")
                .0,
            json!({ "ok": true })
        );
        assert_eq!(
            parse_yaml(&[0xff], "bad-utf8").expect_err("UTF-8").code,
            CODE_DOCUMENT_PARSE
        );
        let yaml_error = parse_yaml(b"value: [", "bad-yaml").expect_err("syntax");
        assert!(yaml_error.line.is_some());
        let json_error = parse_json(b"{", "bad-json").expect_err("syntax");
        assert!(json_error.line.is_some());
    }

    #[test]
    fn yaml_document_skips_one_leading_bom_and_preserves_mid_content_bom() {
        let temp = TempDir::new().expect("tempdir");
        let config = resolved_config(temp.path(), "");
        write(
            &config.workspace_root,
            "entry.yaml",
            "\u{feff}openapi: 3.1.0\ninfo:\n  title: \"before\u{feff}after\"\n  version: 1.0.0\npaths: {}\n",
        );

        let graph = load_ok(&config);

        assert_eq!(graph.entry().value["openapi"], "3.1.0");
        assert_eq!(graph.entry().value["info"]["title"], "before\u{feff}after");
    }

    #[test]
    fn extension_fallback_loads_json_named_yaml_with_one_warning() {
        let temp = TempDir::new().expect("tempdir");
        let config = resolved_json_config(temp.path());
        write(
            &config.workspace_root,
            "entry.json",
            "openapi: 3.1.0\ninfo:\n  title: API\n  version: 1.0.0\npaths: {}\n",
        );
        let mut sink = DiagnosticSink::new();

        let graph = load_graph(&config, &mut sink).expect("YAML fallback should load");

        assert_eq!(graph.entry().value["openapi"], "3.1.0");
        assert_eq!(sink.as_slice().len(), 1);
        let warning = &sink.as_slice()[0];
        assert_eq!(warning.code, "OASTS2007");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.category, Category::Input);
        assert_eq!(warning.source_id.as_deref(), Some("workspace/entry.json"));
        assert_eq!(
            warning.message,
            "document 'workspace/entry.json' has extension '.json' but parsed as YAML"
        );
    }

    #[test]
    fn extension_fallback_loads_yaml_named_json_with_one_warning() {
        let temp = TempDir::new().expect("tempdir");
        let config = resolved_config(temp.path(), "");
        write(
            &config.workspace_root,
            "entry.yaml",
            r#"{"openapi":"3.1.0","info":{"title":"\uD834\uDD1E","version":"1.0.0"},"paths":{}}"#,
        );
        let mut sink = DiagnosticSink::new();

        let graph = load_graph(&config, &mut sink).expect("JSON fallback should load");

        assert_eq!(graph.entry().value["info"]["title"], "𝄞");
        assert_eq!(sink.as_slice().len(), 1);
        let warning = &sink.as_slice()[0];
        assert_eq!(warning.code, "OASTS2007");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.source_id.as_deref(), Some("workspace/entry.yaml"));
        assert_eq!(
            warning.message,
            "document 'workspace/entry.yaml' has extension '.yaml' but parsed as JSON"
        );
    }

    #[test]
    fn matching_document_extensions_emit_no_fallback_warning() {
        let yaml_temp = TempDir::new().expect("tempdir");
        let yaml_config = resolved_config(yaml_temp.path(), "");
        write(
            &yaml_config.workspace_root,
            "entry.yaml",
            "openapi: 3.1.0\ninfo: { title: API, version: 1.0.0 }\npaths: {}\n",
        );
        load_ok(&yaml_config);

        let json_temp = TempDir::new().expect("tempdir");
        let json_config = resolved_json_config(json_temp.path());
        write(
            &json_config.workspace_root,
            "entry.json",
            r#"{"openapi":"3.1.0","info":{"title":"API","version":"1.0.0"},"paths":{}}"#,
        );
        load_ok(&json_config);
    }

    #[test]
    fn extension_fallback_reports_combined_error_when_both_parsers_fail() {
        let temp = TempDir::new().expect("tempdir");
        let config = resolved_json_config(temp.path());
        write(&config.workspace_root, "entry.json", "value: [\n");

        let diagnostic = assert_load_code(&config, CODE_DOCUMENT_PARSE);

        assert!(
            diagnostic
                .message
                .starts_with("document is neither valid JSON nor YAML: invalid JSON document:")
        );
        assert!(diagnostic.message.contains("; invalid YAML document:"));
    }

    #[test]
    fn uri_and_pointer_helpers_cover_rejections_and_boundaries() {
        let base = Url::parse("file:///tmp/base.yaml").expect("base URL");
        assert_eq!(
            resolve_identity_uri(&base, "http://[", Some("source"), Some("/$ref"))
                .expect_err("invalid URI")
                .code,
            CODE_INVALID_REFERENCE
        );
        // Joining is identity work and says nothing about retrievability — a remote URI joins
        // cleanly here and is refused below, where something would actually be read.
        assert_eq!(
            resolve_identity_uri(
                &base,
                "https://example.invalid/x",
                Some("source"),
                Some("/$ref"),
            )
            .expect("remote URI joins")
            .as_str(),
            "https://example.invalid/x"
        );
        assert!(file_url(Path::new("relative/path")).is_err());
        let remote = Url::parse("https://example.invalid/x").expect("remote URL");
        assert_eq!(
            local_path_from_url(&remote, Some("source"), Some("/$ref"))
                .expect_err("remote URL")
                .code,
            CODE_REMOTE_UNSUPPORTED
        );
        let nonlocal = Url::parse("file://example.invalid/path").expect("file URL");
        assert_eq!(
            local_path_from_url(&nonlocal, Some("source"), Some("/$ref"))
                .expect_err("non-local file URL")
                .code,
            CODE_INVALID_REFERENCE
        );

        for (url, expected) in [
            ("file:///tmp/a", Ok("")),
            ("file:///tmp/a#/a%20b", Ok("/a b")),
            ("file:///tmp/a#name", Err(CODE_INVALID_REFERENCE)),
            ("file:///tmp/a#/%", Err(CODE_INVALID_REFERENCE)),
            ("file:///tmp/a#/%GG", Err(CODE_INVALID_REFERENCE)),
            ("file:///tmp/a#/%FF", Err(CODE_INVALID_REFERENCE)),
            ("file:///tmp/a#/~2", Err(CODE_INVALID_REFERENCE)),
        ] {
            let url = Url::parse(url).expect("test URL");
            match expected {
                Ok(pointer) => assert_eq!(
                    pointer_from_url(&url, Some("source"), Some("/$ref")).expect("valid pointer"),
                    pointer
                ),
                Err(code) => assert_eq!(
                    pointer_from_url(&url, Some("source"), Some("/$ref"))
                        .expect_err("invalid pointer")
                        .code,
                    code
                ),
            }
        }

        assert_eq!(percent_decode("%41%4a%4A"), Ok("AJJ".to_owned()));
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
    }

    #[test]
    fn json_pointer_helpers_cover_arrays_scalars_and_escaping() {
        let value = json!({ "array": ["zero"], "object": { "a/b~c": 7 }, "scalar": true });
        assert_eq!(evaluate_pointer(&value, "").expect("root"), &value);
        assert_eq!(
            evaluate_pointer(&value, "/object/a~1b~0c").expect("escaped key"),
            &json!(7)
        );
        assert_eq!(evaluate_pointer(&value, "/array/0").expect("array"), "zero");
        for pointer in [
            "not-a-pointer",
            "/missing",
            "/array/",
            "/array/00",
            "/array/nope",
            "/array/184467440737095516160",
            "/array/1",
            "/scalar/child",
            "/~",
        ] {
            assert!(evaluate_pointer(&value, pointer).is_err(), "{pointer}");
        }
        assert_eq!(append_pointer("/root", "a/b~c"), "/root/a~1b~0c");
        for index in [0, 9, 10, usize::MAX] {
            assert_eq!(
                append_pointer_index("/root", index),
                format!("/root/{index}")
            );
        }
        assert_eq!(unescape_pointer_token("plain"), Ok("plain".to_owned()));
        assert!(validate_pointer("bad").is_err());
    }

    #[test]
    fn context_and_diagnostic_helpers_cover_every_variant() {
        let object = json!({});
        let array = json!([]);
        let boolean = json!(true);
        for context in [
            WalkContext::Schema,
            WalkContext::NonSchema,
            WalkContext::SchemaMap,
            WalkContext::SchemaArray,
            WalkContext::Skip,
        ] {
            let expected = if context == WalkContext::Schema {
                PositionKind::Schema
            } else {
                PositionKind::NonSchema
            };
            assert_eq!(context.position(), expected);
        }
        assert_eq!(
            child_context(WalkContext::SchemaMap, "", "x", &object),
            WalkContext::Schema
        );
        assert_eq!(
            child_context(WalkContext::SchemaArray, "", "x", &object),
            WalkContext::Schema
        );
        assert_eq!(
            child_context(WalkContext::Skip, "", "x", &object),
            WalkContext::Skip
        );
        for (pointer, name, expected) in [
            ("", "schema", WalkContext::Schema),
            ("/components", "schemas", WalkContext::SchemaMap),
            ("", "example", WalkContext::Skip),
            ("", "value", WalkContext::Skip),
            ("", "other", WalkContext::NonSchema),
        ] {
            assert_eq!(
                child_context(WalkContext::NonSchema, pointer, name, &object),
                expected
            );
        }
        for name in [
            "properties",
            "patternProperties",
            "dependentSchemas",
            "$defs",
            "definitions",
        ] {
            assert_eq!(
                child_context(WalkContext::Schema, "", name, &object),
                WalkContext::SchemaMap
            );
        }
        for name in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            assert_eq!(
                child_context(WalkContext::Schema, "", name, &array),
                WalkContext::SchemaArray
            );
        }
        for name in [
            "items",
            "contains",
            "not",
            "if",
            "then",
            "else",
            "propertyNames",
            "additionalProperties",
            "unevaluatedProperties",
            "unevaluatedItems",
            "contentSchema",
        ] {
            assert_eq!(
                child_context(WalkContext::Schema, "", name, &object),
                WalkContext::Schema
            );
            assert_eq!(
                child_context(WalkContext::Schema, "", name, &array),
                WalkContext::SchemaArray
            );
        }
        assert_eq!(
            child_context(WalkContext::Schema, "", "items", &boolean),
            WalkContext::Schema
        );
        assert_eq!(
            child_context(WalkContext::Schema, "", "title", &object),
            WalkContext::Skip
        );

        let input = input_error(CODE_DOCUMENT_PARSE, "bad", Some("source"), Some("/pointer"));
        assert_eq!(input.source_id.as_deref(), Some("source"));
        assert_eq!(input.json_pointer.as_deref(), Some("/pointer"));
        let io = io_error(CODE_DOCUMENT_IO, "bad", Some("source"), Some("/pointer"));
        assert_eq!(io.source_id.as_deref(), Some("source"));
        assert_eq!(io.json_pointer.as_deref(), Some("/pointer"));
        assert_eq!(to_u32(usize::MAX), u32::MAX);
        assert_eq!(encode_relative_path(Path::new("/")), Ok(String::new()));
    }

    #[test]
    fn graph_and_target_base_cover_defensive_resolution_paths() {
        let document = Document {
            id: DocId(0),
            canonical_path: PathBuf::from("relative.yaml"),
            source_id: "workspace/relative.yaml".to_owned(),
            value: json!({}),
            sha256: [0; 32],
        };
        let graph = DocumentGraph {
            documents: vec![document],
            path_to_id: HashMap::new(),
            identifiers: IdentifierRegistry::default(),
            entry_id: DocId(0),
            edges: Vec::new(),
            workspace_root: PathBuf::from("workspace"),
            allow_roots: Vec::new(),
            max_ref_depth: 64,
        };
        assert_eq!(
            graph
                .resolve(DocId(0), "#")
                .expect_err("relative canonical path should fail")
                .code,
            CODE_INVALID_REFERENCE
        );

        let directory = TempDir::new().expect("tempdir should be created");
        write(
            directory.path(),
            "workspace/entry.json",
            r#"{"$id":"./sub/base.json","arr":[{"x":1}],"allOf":[{"type":"string"}],"scalar":true}"#,
        );
        let mut config = resolved_config(directory.path(), "");
        config.input = directory.path().join("workspace/entry.json");
        let mut builder = GraphBuilder::new(&config).expect("builder");
        let id = builder
            .load_document(&config.input)
            .expect("document should load");

        for (pointer, position) in [
            ("", PositionKind::Schema),
            ("/arr/0/x", PositionKind::Schema),
            ("/arr/0", PositionKind::NonSchema),
            ("/allOf/0", PositionKind::Schema),
        ] {
            let base = builder
                .base_at_target(
                    &NodeLocation {
                        doc_id: id,
                        json_pointer: pointer.to_owned(),
                    },
                    position,
                )
                .expect("target base should resolve");
            assert_eq!(base.scheme(), "file");
        }
        for pointer in ["/~2", "/arr/nope", "/scalar/child"] {
            assert!(
                builder
                    .base_at_target(
                        &NodeLocation {
                            doc_id: id,
                            json_pointer: pointer.to_owned(),
                        },
                        PositionKind::Schema,
                    )
                    .is_err(),
                "{pointer}"
            );
        }

        Rc::get_mut(&mut builder.documents[id.0])
            .expect("the builder owns the only document handle")
            .value["$id"] = json!(7);
        assert_eq!(
            builder
                .base_at_target(
                    &NodeLocation {
                        doc_id: id,
                        json_pointer: "/arr".to_owned(),
                    },
                    PositionKind::Schema,
                )
                .expect_err("non-string ID should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
        Rc::get_mut(&mut builder.documents[id.0])
            .expect("the builder owns the only document handle")
            .canonical_path = PathBuf::from("relative.json");
        assert_eq!(
            builder
                .base_at_target(
                    &NodeLocation {
                        doc_id: id,
                        json_pointer: String::new(),
                    },
                    PositionKind::Schema,
                )
                .expect_err("relative path should fail")
                .code,
            CODE_INVALID_REFERENCE
        );
    }

    #[cfg(unix)]
    #[test]
    fn configured_entry_accepts_non_unicode_relative_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![0xff]));
        assert_eq!(configured_entry_path(&path).expect("path"), path);
        assert_eq!(
            configured_entry_path(Path::new("relative.yaml")).expect("relative path"),
            PathBuf::from("relative.yaml")
        );
        let file = Url::parse("file:///tmp/entry.yaml").expect("file URL");
        assert_eq!(
            configured_entry_path(Path::new(file.as_str())).expect("file path"),
            PathBuf::from("/tmp/entry.yaml")
        );
    }
}
