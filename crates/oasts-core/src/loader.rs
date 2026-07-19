//! Local OpenAPI document loading and reference resolution.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::ResolvedConfig;
use crate::diag::{Diagnostic, DiagnosticSink};
use crate::syntax::parse_yaml_document_value;

const CODE_IO: &str = "OASTS1001";
const CODE_REMOTE_UNSUPPORTED: &str = "OASTS1002";
const CODE_REF_ESCAPE: &str = "OASTS1003";
const CODE_NON_UNICODE_PATH: &str = "OASTS1004";
const CODE_PARSE: &str = "OASTS1005";
const CODE_MAX_DOCUMENT_BYTES: &str = "OASTS1006";
const CODE_MAX_TOTAL_BYTES: &str = "OASTS1007";
const CODE_MAX_DOCUMENTS: &str = "OASTS1008";
const CODE_MAX_REF_DEPTH: &str = "OASTS1009";
const CODE_INVALID_REFERENCE: &str = "OASTS1010";
const CODE_POINTER: &str = "OASTS1011";
const CODE_NON_SCHEMA_CYCLE: &str = "OASTS1012";

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
    pub raw: Vec<u8>,
    pub value: Value,
    pub sha256: [u8; 32],
}

/// Location of a resolved node in the document graph.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeLocation {
    pub doc_id: DocId,
    pub json_pointer: String,
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
    entry_id: DocId,
    edges: Vec<ReferenceEdge>,
    workspace_root: PathBuf,
    allow_roots: Vec<AllowRoot>,
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

    /// Returns retained reference edges.
    #[must_use]
    pub fn edges(&self) -> &[ReferenceEdge] {
        &self.edges
    }

    /// Resolves a reference against one document's retrieval URI.
    pub fn resolve(&self, base_doc: DocId, reference: &str) -> Result<Node<'_>, Diagnostic> {
        let Some(base_document) = self.document(base_doc) else {
            return Err(input_error(
                CODE_INVALID_REFERENCE,
                format!(
                    "document ID {} is not present in this graph",
                    base_doc.index()
                ),
                None,
                None,
            ));
        };
        let base = file_url(&base_document.canonical_path).map_err(|message| {
            input_error(
                CODE_INVALID_REFERENCE,
                message,
                Some(&base_document.source_id),
                None,
            )
        })?;
        let target_url = resolve_uri(&base, reference, Some(&base_document.source_id), None)?;
        let target_path = local_path_from_url(&target_url, Some(&base_document.source_id), None)?;
        let canonical = fs::canonicalize(&target_path).map_err(|error| {
            io_error(
                CODE_IO,
                format!("failed to canonicalize referenced document: {error}"),
                Some(&base_document.source_id),
                None,
            )
        })?;
        authorize_path(&canonical, &self.workspace_root, &self.allow_roots).map_err(|message| {
            input_error(
                CODE_REF_ESCAPE,
                message,
                Some(&base_document.source_id),
                None,
            )
        })?;
        let Some(target_id) = self.path_to_id.get(&canonical).copied() else {
            return Err(io_error(
                CODE_IO,
                format!(
                    "referenced document '{}' is not part of the loaded graph",
                    canonical.display()
                ),
                Some(&base_document.source_id),
                None,
            ));
        };
        let pointer = pointer_from_url(&target_url, Some(&base_document.source_id), None)?;
        let target_document = &self.documents[target_id.0];
        let value = evaluate_pointer(&target_document.value, &pointer).map_err(|message| {
            input_error(
                CODE_POINTER,
                message,
                Some(&target_document.source_id),
                Some(&pointer),
            )
        })?;
        Ok(Node {
            doc_id: target_id,
            json_pointer: pointer,
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
        Ok(graph) => Some(graph),
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
struct VisitKey {
    location: NodeLocation,
    context: WalkContext,
    base: String,
}

#[derive(Clone, Debug)]
struct ActiveReference {
    target: NodeLocation,
    position: PositionKind,
}

#[derive(Default)]
struct TraversalState {
    stack: Vec<NodeLocation>,
    active_references: Vec<ActiveReference>,
}

struct GraphBuilder<'a> {
    config: &'a ResolvedConfig,
    documents: Vec<Document>,
    path_to_id: HashMap<PathBuf, DocId>,
    edges: Vec<ReferenceEdge>,
    workspace_root: PathBuf,
    allow_roots: Vec<AllowRoot>,
    total_bytes: u64,
    visited: HashSet<VisitKey>,
}

impl<'a> GraphBuilder<'a> {
    fn new(config: &'a ResolvedConfig) -> Result<Self, Diagnostic> {
        let workspace_root = fs::canonicalize(&config.workspace_root).map_err(|error| {
            io_error(
                CODE_IO,
                format!("failed to canonicalize workspaceRoot: {error}"),
                Some(&config.config_path.to_string_lossy()),
                Some("/workspaceRoot"),
            )
        })?;
        let mut allow_roots = Vec::with_capacity(config.local_allow_paths.len());
        for (config_index, path) in config.local_allow_paths.iter().enumerate() {
            let canonical_path = fs::canonicalize(path).map_err(|error| {
                io_error(
                    CODE_IO,
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
            edges: Vec::new(),
            workspace_root,
            allow_roots,
            total_bytes: 0,
            visited: HashSet::new(),
        })
    }

    fn build(mut self) -> Result<DocumentGraph, Diagnostic> {
        let entry_path = configured_entry_path(&self.config.input)?;
        let entry_id = self.load_document(&entry_path)?;
        let entry_path = self.documents[entry_id.0].canonical_path.clone();
        let entry_base = file_url(&entry_path)
            .expect("a canonical filesystem path is representable as a file URI");
        let mut state = TraversalState::default();
        self.walk_node(
            NodeLocation {
                doc_id: entry_id,
                json_pointer: String::new(),
            },
            WalkContext::NonSchema,
            entry_base,
            0,
            &mut state,
        )?;
        Ok(DocumentGraph {
            documents: self.documents,
            path_to_id: self.path_to_id,
            entry_id,
            edges: self.edges,
            workspace_root: self.workspace_root,
            allow_roots: self.allow_roots,
        })
    }

    fn load_document(&mut self, requested_path: &Path) -> Result<DocId, Diagnostic> {
        let canonical_path = fs::canonicalize(requested_path).map_err(|error| {
            io_error(
                CODE_IO,
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
                CODE_IO,
                format!("failed to read document: {error}"),
                Some(&source_id),
                None,
            )
        })?;
        let value = parse_document(&canonical_path, &raw, &source_id)?;
        let sha256 = Sha256::digest(&raw).into();
        let id = DocId(self.documents.len());
        self.documents.push(Document {
            id,
            canonical_path: canonical_path.clone(),
            source_id,
            raw,
            value,
            sha256,
        });
        self.path_to_id.insert(canonical_path, id);
        self.total_bytes = next_total;
        Ok(id)
    }

    fn walk_node(
        &mut self,
        location: NodeLocation,
        context: WalkContext,
        base: Url,
        ref_depth: u64,
        state: &mut TraversalState,
    ) -> Result<(), Diagnostic> {
        if context == WalkContext::Skip {
            return Ok(());
        }
        let key = VisitKey {
            location: location.clone(),
            context,
            base: base.as_str().to_owned(),
        };
        if !self.visited.insert(key) {
            return Ok(());
        }

        let value = self
            .documents
            .get(location.doc_id.0)
            .and_then(|document| evaluate_pointer(&document.value, &location.json_pointer).ok())
            .cloned()
            .ok_or_else(|| {
                input_error(
                    CODE_POINTER,
                    format!("JSON Pointer '{}' does not resolve", location.json_pointer),
                    self.source_id(location.doc_id),
                    Some(&location.json_pointer),
                )
            })?;

        state.stack.push(location.clone());
        let mut effective_base = base;
        if context == WalkContext::Schema
            && let Value::Object(object) = &value
            && let Some(id_value) = object.get("$id")
        {
            let Some(id) = id_value.as_str() else {
                return Err(input_error(
                    CODE_INVALID_REFERENCE,
                    "Schema Object $id must be a string URI reference",
                    self.source_id(location.doc_id),
                    Some(&append_pointer(&location.json_pointer, "$id")),
                ));
            };
            effective_base = resolve_uri(
                &effective_base,
                id,
                self.source_id(location.doc_id),
                Some(&append_pointer(&location.json_pointer, "$id")),
            )?;
        }

        match value {
            Value::Object(object) => {
                if matches!(context, WalkContext::Schema | WalkContext::NonSchema)
                    && let Some(reference_value) = object.get("$ref")
                {
                    let Some(reference) = reference_value.as_str() else {
                        return Err(input_error(
                            CODE_INVALID_REFERENCE,
                            "$ref must be a string URI reference",
                            self.source_id(location.doc_id),
                            Some(&append_pointer(&location.json_pointer, "$ref")),
                        ));
                    };
                    self.follow_reference(
                        &location,
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
                    let child_context =
                        child_context(context, &location.json_pointer, &name, &child);
                    if child_context == WalkContext::Skip {
                        continue;
                    }
                    self.walk_node(
                        NodeLocation {
                            doc_id: location.doc_id,
                            json_pointer: append_pointer(&location.json_pointer, &name),
                        },
                        child_context,
                        effective_base.clone(),
                        ref_depth,
                        state,
                    )?;
                }
            }
            Value::Array(values) => {
                let child_context = array_child_context(context);
                if child_context != WalkContext::Skip {
                    for (index, _) in values.iter().enumerate() {
                        let result = self.walk_node(
                            NodeLocation {
                                doc_id: location.doc_id,
                                json_pointer: append_pointer(
                                    &location.json_pointer,
                                    &index.to_string(),
                                ),
                            },
                            child_context,
                            effective_base.clone(),
                            ref_depth,
                            state,
                        );
                        result?;
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
        state.stack.pop();
        Ok(())
    }

    fn follow_reference(
        &mut self,
        from: &NodeLocation,
        position: PositionKind,
        base: &Url,
        reference: &str,
        ref_depth: u64,
        state: &mut TraversalState,
    ) -> Result<(), Diagnostic> {
        let reference_pointer = append_pointer(&from.json_pointer, "$ref");
        let target_url = resolve_uri(
            base,
            reference,
            self.source_id(from.doc_id),
            Some(&reference_pointer),
        )?;
        let source_id = self.source_id(from.doc_id);
        let target_path = local_path_from_url(&target_url, source_id, Some(&reference_pointer))?;
        let target_id = self.load_document(&target_path).map_err(|mut diagnostic| {
            if diagnostic.source_id.is_none()
                && let Some(source_id) = self.source_id(from.doc_id)
            {
                diagnostic = diagnostic.with_source(source_id);
            }
            if diagnostic.json_pointer.is_none() {
                diagnostic = diagnostic.with_json_pointer(&reference_pointer);
            }
            diagnostic
        })?;
        let source_id = self.source_id(from.doc_id);
        let target_pointer = pointer_from_url(&target_url, source_id, Some(&reference_pointer))?;
        let target_source = self.documents[target_id.0].source_id.clone();
        evaluate_pointer(&self.documents[target_id.0].value, &target_pointer).map_err(
            |message| {
                input_error(
                    CODE_POINTER,
                    message,
                    Some(&target_source),
                    Some(&target_pointer),
                )
            },
        )?;
        let target = NodeLocation {
            doc_id: target_id,
            json_pointer: target_pointer,
        };
        self.edges.push(ReferenceEdge {
            from: from.clone(),
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

        if state.stack.iter().any(|ancestor| ancestor == &target) {
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

        let target_base = self.base_at_target(&target, position)?;
        state.active_references.push(ActiveReference {
            target: target.clone(),
            position,
        });
        let target_context = match position {
            PositionKind::Schema => WalkContext::Schema,
            PositionKind::NonSchema => WalkContext::NonSchema,
        };
        let result = self.walk_node(target, target_context, target_base, next_depth, state);
        state.active_references.pop();
        result
    }

    fn base_at_target(
        &self,
        target: &NodeLocation,
        expected_position: PositionKind,
    ) -> Result<Url, Diagnostic> {
        let document = &self.documents[target.doc_id.0];
        let mut base = file_url(&document.canonical_path).map_err(|message| {
            input_error(
                CODE_INVALID_REFERENCE,
                message,
                Some(&document.source_id),
                Some(&target.json_pointer),
            )
        })?;
        if target.json_pointer.is_empty() {
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
        for encoded_token in target.json_pointer[1..].split('/') {
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
                base = resolve_uri(&base, id, Some(&document.source_id), Some(&id_pointer))?;
            }

            let token = unescape_pointer_token(encoded_token).map_err(|message| {
                input_error(
                    CODE_INVALID_REFERENCE,
                    message,
                    Some(&document.source_id),
                    Some(&target.json_pointer),
                )
            })?;
            let pointer_error = || {
                input_error(
                    CODE_POINTER,
                    format!("JSON Pointer '{}' does not resolve", target.json_pointer),
                    Some(&document.source_id),
                    Some(&target.json_pointer),
                )
            };
            let (child, next_context) = match value {
                Value::Object(object) => {
                    let child = object.get(&token).ok_or_else(pointer_error)?;
                    (child, child_context(context, &pointer, &token, child))
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
            pointer = append_pointer(&pointer, &token);
            value = child;
        }
        Ok(base)
    }

    fn source_id(&self, id: DocId) -> Option<&str> {
        self.documents
            .get(id.0)
            .map(|document| document.source_id.as_str())
    }
}

fn document_byte_len(path: &Path, source_id: &str) -> Result<u64, Diagnostic> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| {
            io_error(
                CODE_IO,
                format!("failed to read document metadata: {error}"),
                Some(source_id),
                None,
            )
        })
}

fn parse_document(path: &Path, raw: &[u8], source_id: &str) -> Result<Value, Diagnostic> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => parse_json(raw, source_id),
        Some("yaml" | "yml") => parse_yaml(raw, source_id),
        _ => match parse_json(raw, source_id) {
            Ok(value) => Ok(value),
            Err(json_error) => parse_yaml(raw, source_id).map_err(|yaml_error| {
                input_error(
                    CODE_PARSE,
                    format!(
                        "document is neither valid JSON nor YAML: {}; {}",
                        json_error.message, yaml_error.message
                    ),
                    Some(source_id),
                    None,
                )
            }),
        },
    }
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

fn parse_json(raw: &[u8], source_id: &str) -> Result<Value, Diagnostic> {
    serde_json::from_slice(raw).map_err(|error| {
        input_error(
            CODE_PARSE,
            format!("invalid JSON document: {error}"),
            Some(source_id),
            None,
        )
        .with_location(to_u32(error.line()), to_u32(error.column()))
    })
}

fn parse_yaml(raw: &[u8], source_id: &str) -> Result<Value, Diagnostic> {
    let source = std::str::from_utf8(raw).map_err(|error| {
        input_error(
            CODE_PARSE,
            format!("YAML document is not UTF-8: {error}"),
            Some(source_id),
            None,
        )
    })?;
    parse_yaml_document_value(source).map_err(|error| {
        input_error(
            CODE_PARSE,
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

fn resolve_uri(
    base: &Url,
    reference: &str,
    source_id: Option<&str>,
    pointer: Option<&str>,
) -> Result<Url, Diagnostic> {
    let resolved = base.join(reference).map_err(|error| {
        input_error(
            CODE_INVALID_REFERENCE,
            format!("invalid URI reference '{reference}': {error}"),
            source_id,
            pointer,
        )
    })?;
    if resolved.scheme() != "file" {
        return Err(input_error(
            CODE_REMOTE_UNSUPPORTED,
            format!(
                "remote loading is not supported in this build: '{}'",
                resolved.as_str()
            ),
            source_id,
            pointer,
        ));
    }
    Ok(resolved)
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
    if pointer.is_empty() {
        return Ok(value);
    }
    let mut current = value;
    for encoded_token in pointer[1..].split('/') {
        let token = unescape_pointer_token(encoded_token)?;
        current = match current {
            Value::Object(object) => object
                .get(&token)
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
    Ok(result)
}

pub(crate) fn append_pointer(pointer: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{pointer}/{escaped}")
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
                    | "additionalItems"
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
    use crate::diag::Category;

    fn write(root: &Path, relative: &str, contents: &str) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent should be created");
        }
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
    fn input_yaml_resolves_anchors_aliases_and_keeps_merge_keys_literal() {
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
            document["x-merge"]["<<"],
            document["components"]["parameters"]["Common"]
        );
        assert_eq!(
            document["x-merge"].as_object().expect("merge object").len(),
            1
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

        let diagnostic = assert_load_code(&config, CODE_PARSE);

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
            CODE_IO
        );

        write(directory.path(), "workspace/unloaded.yaml", "value: true\n");
        assert_eq!(
            graph
                .resolve(graph.entry().id, "unloaded.yaml")
                .expect_err("unloaded file")
                .code,
            CODE_IO
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
        assert_eq!(sink.as_slice()[0].code, CODE_IO);

        config = resolved_config(directory.path(), "");
        config.local_allow_paths = vec![directory.path().join("missing-allow-root")];
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice()[0].code, CODE_IO);

        config = resolved_config(directory.path(), "");
        config.input = directory.path().join("workspace/missing.yaml");
        let mut sink = DiagnosticSink::new();
        assert!(load_graph(&config, &mut sink).is_none());
        assert_eq!(sink.as_slice()[0].code, CODE_IO);

        for (name, contents) in [
            ("bad.json", "{"),
            ("bad.yaml", "value: ["),
            ("bad.unknown", "{ nope: ["),
        ] {
            config = resolved_config(directory.path(), "");
            config.input = write(directory.path(), &format!("workspace/{name}"), contents);
            assert_load_code(&config, CODE_PARSE);
        }

        let error = document_byte_len(
            &directory.path().join("workspace/missing-metadata.yaml"),
            "workspace/missing-metadata.yaml",
        )
        .expect_err("missing metadata should be an I/O diagnostic");
        assert_eq!(error.code, CODE_IO);
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
        assert_eq!(sink.as_slice()[0].code, CODE_IO);
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
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $id: 'http://['\n      type: string\n",
                CODE_INVALID_REFERENCE,
            ),
            (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Pet:\n      $id: https://example.invalid/schema.json\n      type: string\n",
                CODE_REMOTE_UNSUPPORTED,
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
        assert_eq!(diagnostic.code, CODE_IO);
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
        let base = file_url(&builder.documents[entry_id.0].canonical_path).expect("file URL");
        let location = NodeLocation {
            doc_id: entry_id,
            json_pointer: String::new(),
        };
        let mut state = TraversalState::default();
        builder
            .walk_node(
                location.clone(),
                WalkContext::NonSchema,
                base.clone(),
                0,
                &mut state,
            )
            .expect("document should walk");
        builder
            .walk_node(
                location,
                WalkContext::NonSchema,
                base.clone(),
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
                base.clone(),
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
                base.clone(),
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
    fn document_parsers_cover_extensions_utf8_and_fallbacks() {
        assert_eq!(
            parse_document(Path::new("value.json"), br#"{"ok":true}"#, "json")
                .expect("JSON document"),
            json!({ "ok": true })
        );
        assert_eq!(
            parse_document(Path::new("value.yaml"), b"ok: true\n", "yaml").expect("YAML document"),
            json!({ "ok": true })
        );
        assert_eq!(
            parse_document(Path::new("value.data"), br#"[1,2]"#, "fallback-json")
                .expect("fallback JSON"),
            json!([1, 2])
        );
        assert_eq!(
            parse_document(Path::new("value.data"), b"ok: true\n", "fallback-yaml")
                .expect("fallback YAML"),
            json!({ "ok": true })
        );
        assert_eq!(
            parse_yaml(&[0xff], "bad-utf8").expect_err("UTF-8").code,
            CODE_PARSE
        );
        let yaml_error = parse_yaml(b"value: [", "bad-yaml").expect_err("syntax");
        assert!(yaml_error.line.is_some());
        let json_error = parse_json(b"{", "bad-json").expect_err("syntax");
        assert!(json_error.line.is_some());
    }

    #[test]
    fn uri_and_pointer_helpers_cover_rejections_and_boundaries() {
        let base = Url::parse("file:///tmp/base.yaml").expect("base URL");
        assert_eq!(
            resolve_uri(&base, "http://[", Some("source"), Some("/$ref"))
                .expect_err("invalid URI")
                .code,
            CODE_INVALID_REFERENCE
        );
        assert_eq!(
            resolve_uri(
                &base,
                "https://example.invalid/x",
                Some("source"),
                Some("/$ref"),
            )
            .expect_err("remote URI")
            .code,
            CODE_REMOTE_UNSUPPORTED
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
            "additionalItems",
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

        let input = input_error(CODE_PARSE, "bad", Some("source"), Some("/pointer"));
        assert_eq!(input.source_id.as_deref(), Some("source"));
        assert_eq!(input.json_pointer.as_deref(), Some("/pointer"));
        let io = io_error(CODE_IO, "bad", Some("source"), Some("/pointer"));
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
            raw: Vec::new(),
            value: json!({}),
            sha256: [0; 32],
        };
        let graph = DocumentGraph {
            documents: vec![document],
            path_to_id: HashMap::new(),
            entry_id: DocId(0),
            edges: Vec::new(),
            workspace_root: PathBuf::from("workspace"),
            allow_roots: Vec::new(),
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

        builder.documents[id.0].value["$id"] = json!(7);
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
        builder.documents[id.0].canonical_path = PathBuf::from("relative.json");
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
