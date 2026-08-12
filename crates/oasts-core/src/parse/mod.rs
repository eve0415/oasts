//! OpenAPI 3.0/3.1 parsing into the version-neutral IR.

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use rayon::prelude::*;
use serde_json::{Map, Value};

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, ArrayConstraints, Body, Callback, CallbackExpression,
    ConditionalApplicator, ContainsApplicator, Discriminator, EncodingHeader, EncodingObject,
    EnumExtensionData, ExclusiveBound, FiniteConstraint, Ir, Link, LinkTarget, MediaType,
    NamedSchema, NamedSecurityScheme, NumericConstraints, OAuthFlow, OAuthFlows, OasVersion,
    ObjectConstraints, Operation, Param, ParamLocation, ParamStyle, PatternProperty,
    PatternPropertyKey, PrimitiveType, PropMeta, RemovedDeclarations, ResponseEntry,
    ResponseHeader, ResponseStatus, SchemaDocs, SchemaMeta, SchemaNode, SchemaRef, SecKind,
    SecurityRequirement, Segment, SegmentPart, ServerEntry, ServerVariable, SourceRef,
    StringConstraints, TupleRest, ValidationApplicators, Webhook, box_if_populated,
    is_root_component_pointer, mapping_schema_ref,
};
use crate::loader::{
    DocId, DocumentGraph, DynamicResolution, append_pointer, append_pointer_index,
};
use crate::media::canonical_content_key;

const CODE_VERSION: &str = "OASTS1101";
const CODE_SHAPE: &str = "OASTS1102";
const CODE_UNSUPPORTED: &str = "OASTS1103";
const CODE_RESPONSE_STATUS: &str = "OASTS1104";
/// A status range written in lowercase. OpenAPI specifies the uppercase wildcard, but real
/// documents ship `4xx`, so it is canonicalized and reported rather than rejected.
const CODE_RESPONSE_STATUS_CASE: &str = "OASTS1120";
/// Two keys in one responses object that name the same status once canonicalized.
const CODE_RESPONSE_STATUS_DUPLICATE: &str = "OASTS1121";
const CODE_PATH_PARAMETER: &str = "OASTS1105";
const CODE_REFERENCE: &str = "OASTS1106";
const CODE_MEDIA_TYPE: &str = "OASTS1107";
const CODE_DUPLICATE_MEDIA_TYPE: &str = "OASTS1108";
const CODE_RESERVED_HEADER_PARAMETER: &str = "OASTS1109";
const CODE_REF_SIBLINGS: &str = "OASTS1110";
const CODE_MULTIPLE_OF: &str = "OASTS1112";
const CODE_REF_CYCLE: &str = "OASTS1113";
const CODE_REF_DEPTH: &str = "OASTS1114";
/// A discriminator `mapping` value that is not a JSON string. It cannot name a schema, so it drops
/// out of tag resolution — diagnosed rather than dropped silently so a malformed entry is no
/// quieter than a dangling one.
const CODE_MAPPING_VALUE_SHAPE: &str = "OASTS1115";
const CODE_OPERATION_REF: &str = "OASTS1116";
/// A `$recursiveRef` written with any value other than `"#"`. JSON Schema 2019-09 §8.2.4.2.1:
/// "The behavior of this keyword is defined only for the value '#'. Implementations MAY choose to
/// consider other values to be errors."
const CODE_RECURSIVE_REF_VALUE: &str = "OASTS1117";
/// A dynamic reference whose target genuinely depends on the path evaluation took to reach it,
/// because two or more schema resources declare the anchor it names. No single schema can stand in
/// for it, so the node widens to unknown and the validators artifact refuses rather than guessing.
const CODE_DYNAMIC_SCOPE: &str = "OASTS1118";
const CODE_ENUM_RULE_14: &str = "OASTS1214";
const CODE_SERVER_VAR_ENUM_EMPTY: &str = "OASTS1131";
const CODE_SERVER_VAR_DEFAULT: &str = "OASTS1132";
const CODE_HEADER_CONTENT_TYPE: &str = "OASTS1133";
const CODE_HEADER_DUPLICATE: &str = "OASTS1134";
const CODE_WEBHOOKS_VERSION: &str = "OASTS1135";
const CODE_LINK_TARGET: &str = "OASTS1234";
const CODE_PHANTOM_REQUIRED: &str = "OASTS1111";
const CODE_SECURITY_FLOWS_SHAPE: &str = "OASTS1438";

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];
const PARALLEL_PARSE_MIN_ITEMS: usize = 64;
/// The two reference keywords whose target is chosen by the dynamic scope of evaluation rather
/// than by where they are written. OpenAPI 3.1 resolves them (see `parse_dynamic_ref`); OpenAPI
/// 3.0's dialect is not JSON Schema at all, so there they stay unrepresentable.
const DYNAMIC_REF_KEYWORDS: [&str; 2] = ["$dynamicRef", "$recursiveRef"];

/// Detects the entry document's supported OpenAPI line.
pub fn detect_version(graph: &DocumentGraph, sink: &mut DiagnosticSink) -> Option<OasVersion> {
    let document = graph.entry();
    let Some(version) = document.value.get("openapi").and_then(Value::as_str) else {
        sink.push(
            Diagnostic::input(
                CODE_VERSION,
                "entry document is missing a string 'openapi' field",
            )
            .with_source(&document.source_id)
            .with_json_pointer("/openapi"),
        );
        return None;
    };
    let mut parts = version.split('.');
    let detected = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("3"), Some("0"), Some(patch), None)
            if !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some(OasVersion::V3_0)
        }
        (Some("3"), Some("1"), Some(patch), None)
            if !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some(OasVersion::V3_1)
        }
        _ => None,
    };
    if detected.is_none() {
        sink.push(
            Diagnostic::input(
                CODE_VERSION,
                format!("unsupported OpenAPI version '{version}'; expected 3.0.x or 3.1.x"),
            )
            .with_source(&document.source_id)
            .with_json_pointer("/openapi"),
        );
    }
    detected
}

/// Parses the loaded entry document. Unsupported schema leaves remain in the
/// returned IR as `SchemaNode::Unknown` while diagnostics accumulate.
pub fn parse(graph: &DocumentGraph, sink: &mut DiagnosticSink) -> Option<Ir> {
    match detect_version(graph, sink)? {
        OasVersion::V3_0 => Some(Parser::new(graph, OasVersion::V3_0, sink).parse_ir()),
        OasVersion::V3_1 => Some(Parser::new(graph, OasVersion::V3_1, sink).parse_ir()),
    }
}

struct Parser<'graph, 'sink> {
    graph: &'graph DocumentGraph,
    version: OasVersion,
    sink: &'sink mut DiagnosticSink,
    entry_defs_referenced: bool,
}

#[derive(Clone, Debug)]
struct NodeView<'a> {
    doc_id: DocId,
    pointer: String,
    value: &'a Value,
}

enum ContentSchema {
    NotDeclared,
    Empty,
    Parsed {
        media_type: String,
        schema: Box<SchemaNode>,
    },
    Invalid,
}

#[derive(Clone, Debug)]
struct ParsedFinite {
    declared: bool,
    enum_values: Option<Vec<Value>>,
    const_value: Option<Value>,
}

impl ParsedFinite {
    fn from_object(object: &Map<String, Value>, version: OasVersion) -> Self {
        Self {
            declared: object.contains_key("enum") || object.contains_key("const"),
            enum_values: object.get("enum").and_then(Value::as_array).cloned(),
            const_value: (version == OasVersion::V3_1)
                .then(|| object.get("const").cloned())
                .flatten(),
        }
    }

    fn for_primitive(&self, ty: PrimitiveType) -> Option<Self> {
        let enum_values = self.enum_values.as_ref().map(|values| {
            values
                .iter()
                .filter(|value| value_matches_primitive(value, ty))
                .cloned()
                .collect::<Vec<_>>()
        });
        if enum_values.as_ref().is_some_and(Vec::is_empty)
            || self
                .const_value
                .as_ref()
                .is_some_and(|value| !value_matches_primitive(value, ty))
        {
            return None;
        }
        Some(Self {
            declared: self.declared,
            enum_values,
            const_value: self.const_value.clone(),
        })
    }
}

struct DomainFilter {
    finite: ParsedFinite,
    unsatisfiable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeclaredType {
    String,
    Number,
    Integer,
    Boolean,
    Null,
    Object,
    Array,
}

impl DeclaredType {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "null" => Some(Self::Null),
            "object" => Some(Self::Object),
            "array" => Some(Self::Array),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RefChainMember {
    doc_index: usize,
    pointer: String,
}

#[derive(Debug, Eq, PartialEq)]
enum RefChainError {
    Resolution(Box<Diagnostic>),
    Cycle(Vec<String>),
    Budget(Vec<String>),
}

enum RefChainStep<T> {
    Done,
    Next { member: RefChainMember, node: T },
    Fail(Box<Diagnostic>),
}

fn follow_ref_chain<'graph>(
    start: NodeView<'graph>,
    budget: u64,
    resolve_fn: &mut dyn FnMut(&NodeView<'graph>) -> RefChainStep<NodeView<'graph>>,
) -> Result<NodeView<'graph>, RefChainError> {
    let mut current = start;
    let mut visited = HashSet::new();
    let mut chain = Vec::new();
    let mut hops = 0_u64;
    loop {
        match resolve_fn(&current) {
            RefChainStep::Done => return Ok(current),
            RefChainStep::Fail(diagnostic) => return Err(RefChainError::Resolution(diagnostic)),
            RefChainStep::Next { member, node } => {
                chain.push(member.pointer.clone());
                if !visited.insert(member) {
                    return Err(RefChainError::Cycle(chain));
                }
                hops = hops.saturating_add(1);
                if hops > budget {
                    return Err(RefChainError::Budget(chain));
                }
                current = node;
            }
        }
    }
}

/// Maps a reference-chain failure onto the diagnostic pushed at the referencing site. Mid-chain
/// resolution failures pass their own diagnostic through untouched; cycle and budget failures
/// name the chain so the offending hop sequence is visible.
fn ref_chain_failure_diagnostic(
    kind: &str,
    max_ref_depth: u64,
    source_id: &str,
    pointer: &str,
    error: RefChainError,
) -> Diagnostic {
    match error {
        RefChainError::Resolution(diagnostic) => *diagnostic,
        RefChainError::Cycle(chain) => Diagnostic::input(
            CODE_REF_CYCLE,
            format!(
                "{kind} reference chain contains a cycle: {}",
                chain.join(" -> ")
            ),
        )
        .with_source(source_id)
        .with_json_pointer(pointer),
        RefChainError::Budget(chain) => Diagnostic::input(
            CODE_REF_DEPTH,
            format!(
                "{kind} reference chain exceeds maxRefDepth {max_ref_depth}: {}",
                chain.join(" -> ")
            ),
        )
        .with_source(source_id)
        .with_json_pointer(pointer),
    }
}

const fn should_materialize_external_schemas(
    document_count: usize,
    entry_defs_referenced: bool,
) -> bool {
    document_count > 1 || entry_defs_referenced
}

impl<'graph, 'sink> Parser<'graph, 'sink> {
    fn new(
        graph: &'graph DocumentGraph,
        version: OasVersion,
        sink: &'sink mut DiagnosticSink,
    ) -> Self {
        Self {
            graph,
            version,
            sink,
            entry_defs_referenced: false,
        }
    }

    fn parse_ir(&mut self) -> Ir {
        let entry = self.graph.entry();
        let root = NodeView {
            doc_id: entry.id,
            pointer: String::new(),
            value: &entry.value,
        };
        let default_root_server = ServerEntry {
            url: "/".to_owned(),
            variables: Vec::new(),
            source: self.source(root.doc_id, &root.pointer),
        };
        let root_servers = match root.value.get("servers") {
            Some(Value::Array(servers)) if servers.is_empty() => {
                vec![default_root_server]
            }
            None => {
                vec![default_root_server]
            }
            Some(value) => self.parse_servers(NodeView {
                doc_id: root.doc_id,
                pointer: "/servers".to_owned(),
                value,
            }),
        };
        let root_security = root.value.get("security").map_or_else(Vec::new, |value| {
            self.parse_security_requirements(NodeView {
                doc_id: root.doc_id,
                pointer: "/security".to_owned(),
                value,
            })
        });
        let security_schemes = self.parse_security_schemes(&root);
        let webhooks = self.parse_webhooks(&root);
        let operations = self.parse_operations(root.clone());
        let mut schemas = self.parse_named_schemas(root);
        self.materialize_external_schemas(&mut schemas, &operations, &webhooks);
        Ir {
            operations,
            webhooks,
            schemas,
            root_servers,
            root_security,
            security_schemes,
            removed: RemovedDeclarations::default(),
            version: self.version,
        }
    }

    /// Lowers external-file schema definitions reached through `$ref` into
    /// `NamedSchema` entries so they receive component types ("local
    /// or external references").
    ///
    /// The entry document's `components.schemas` are already lowered; a `$ref`
    /// into another file resolves to that file's `source_id` + pointer but has
    /// no matching `NamedSchema`, so emission's `schema_target` lookup fails.
    /// This walks references transitively (cross-file cycles included) and
    /// materializes every reachable external target. Discovered schemas are
    /// appended in `(source_id, json_pointer)` order so double-generation is
    /// byte-identical regardless of reference traversal order.
    fn materialize_external_schemas(
        &mut self,
        schemas: &mut Vec<NamedSchema>,
        operations: &[Operation],
        webhooks: &[Webhook],
    ) {
        // Most single-document inputs only reference components, which are already materialized.
        // Avoid walking the IR unless another document or an entry non-component target requires it.
        if !should_materialize_external_schemas(
            self.graph.documents().len(),
            self.entry_defs_referenced,
        ) {
            return;
        }
        let entry_source = self.source_id(self.graph.entry().id).to_owned();
        // Index documents by source id once so the worklist reverses each ref
        // target to its document by lookup instead of a linear scan per ref.
        let documents_by_source: HashMap<&str, DocId> = self
            .graph
            .documents()
            .iter()
            .map(|document| (document.source_id.as_str(), document.id))
            .collect();
        let mut materialized: HashSet<(String, String)> = schemas
            .iter()
            .map(|schema| {
                (
                    schema.source.source_id.clone(),
                    schema.source.json_pointer.clone(),
                )
            })
            .collect();

        let mut queue: Vec<(SchemaRef, RefOrigin)> = Vec::new();
        for schema in schemas.iter() {
            collect_schema_refs(&schema.schema, &mut queue);
        }
        for operation in operations {
            collect_operation_refs(operation, &mut queue);
        }
        for webhook in webhooks {
            for operation in &webhook.operations {
                collect_operation_refs(operation, &mut queue);
            }
        }

        let mut discovered = Vec::new();
        let mut cursor = 0;
        while cursor < queue.len() {
            let index = cursor;
            cursor += 1;
            // A root component of the entry document is already a named schema; anything deeper
            // under `components/schemas` is an inline schema that still needs materializing.
            if queue[index].0.source_id == entry_source
                && is_root_component_pointer(&queue[index].0.json_pointer)
            {
                continue;
            }
            let (key, origin) = {
                let (target, origin) = &queue[index];
                (
                    (target.source_id.clone(), target.json_pointer.clone()),
                    *origin,
                )
            };
            if materialized.contains(&key) {
                continue;
            }
            let node = documents_by_source
                .get(key.0.as_str())
                .and_then(|&doc_id| self.graph.node_at(doc_id, &key.1));
            let Some(node) = node else {
                // A mapping value is not a `$ref`, so nothing validated it upstream and a document
                // is free to point one at a pointer that resolves to nothing. Emission reports the
                // dangling entry (OASTS1308) and drops its tag, so there is nothing to materialize
                // here and nothing to say twice. A `$ref` reaching this arm would mean the loader
                // let an unresolved target through, which is why the assert stays.
                debug_assert_eq!(
                    origin,
                    RefOrigin::DiscriminatorMapping,
                    "the loader validated every reference target before parsing"
                );
                continue;
            };
            let doc_id = node.doc_id;
            let document_stem = self
                .graph
                .document(doc_id)
                .and_then(|document| document.canonical_path.file_stem())
                .and_then(|stem| stem.to_str())
                .unwrap_or_default();
            let name = external_schema_name(&key.1, document_stem);
            let source = self.source(doc_id, &key.1);
            let view = NodeView {
                doc_id,
                pointer: key.1.clone(),
                value: node.value,
            };
            // Mark before parsing so a cross-file cycle terminates.
            materialized.insert(key);
            let schema = self.parse_schema(view);
            collect_schema_refs(&schema, &mut queue);
            discovered.push(NamedSchema {
                name,
                schema,
                source,
            });
        }

        discovered.sort_by(|left, right| {
            (&left.source.source_id, &left.source.json_pointer)
                .cmp(&(&right.source.source_id, &right.source.json_pointer))
        });
        schemas.extend(discovered);
    }

    fn parse_named_schemas(&mut self, root: NodeView<'graph>) -> Vec<NamedSchema> {
        let Some(schemas) = root
            .value
            .get("components")
            .and_then(|value| value.get("schemas"))
        else {
            return Vec::new();
        };
        let pointer = "/components/schemas";
        let Some(object) = schemas.as_object() else {
            self.shape_error(root.doc_id, pointer, "components.schemas must be an object");
            return Vec::new();
        };
        if rayon::current_num_threads() == 1 || object.len() < PARALLEL_PARSE_MIN_ITEMS {
            return object
                .iter()
                .map(|(name, value)| self.parse_named_schema(root.doc_id, pointer, name, value))
                .collect();
        }
        let parsed = object
            .iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(name, value)| {
                let mut sink = DiagnosticSink::new();
                let mut parser = Parser::new(self.graph, self.version, &mut sink);
                let schema = parser.parse_named_schema(root.doc_id, pointer, name, value);
                let entry_defs_referenced = parser.entry_defs_referenced;
                (schema, sink.into_vec(), entry_defs_referenced)
            })
            .collect::<Vec<_>>();
        let mut schemas = Vec::with_capacity(parsed.len());
        for (schema, diagnostics, entry_defs_referenced) in parsed {
            schemas.push(schema);
            self.sink.extend(diagnostics);
            self.entry_defs_referenced |= entry_defs_referenced;
        }
        schemas
    }

    #[inline]
    fn parse_named_schema(
        &mut self,
        doc_id: DocId,
        parent_pointer: &str,
        name: &str,
        value: &'graph Value,
    ) -> NamedSchema {
        let schema_pointer = append_pointer(parent_pointer, name);
        let source = self.source(doc_id, &schema_pointer);
        NamedSchema {
            name: name.to_owned(),
            schema: self.parse_schema(NodeView {
                doc_id,
                pointer: schema_pointer,
                value,
            }),
            source,
        }
    }

    fn parse_operations(&mut self, root: NodeView<'graph>) -> Vec<Operation> {
        let Some(paths) = root.value.get("paths") else {
            return Vec::new();
        };
        let Some(paths) = paths.as_object() else {
            self.shape_error(root.doc_id, "/paths", "paths must be an object");
            return Vec::new();
        };
        if rayon::current_num_threads() == 1 || paths.len() < PARALLEL_PARSE_MIN_ITEMS {
            let mut operations = Vec::new();
            for (path, raw_path_item) in paths {
                if !path.starts_with("x-") {
                    operations.extend(self.parse_path_operations(root.doc_id, path, raw_path_item));
                }
            }
            return operations;
        }
        let parsed = paths
            .iter()
            .filter(|(path, _)| !path.starts_with("x-"))
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(|(path, raw_path_item)| {
                let mut sink = DiagnosticSink::new();
                let mut parser = Parser::new(self.graph, self.version, &mut sink);
                let operations = parser.parse_path_operations(root.doc_id, path, raw_path_item);
                let entry_defs_referenced = parser.entry_defs_referenced;
                (operations, sink.into_vec(), entry_defs_referenced)
            })
            .collect::<Vec<_>>();
        let mut operations = Vec::new();
        for (mut path_operations, diagnostics, entry_defs_referenced) in parsed {
            operations.append(&mut path_operations);
            self.sink.extend(diagnostics);
            self.entry_defs_referenced |= entry_defs_referenced;
        }
        operations
    }

    #[inline]
    fn parse_path_operations(
        &mut self,
        doc_id: DocId,
        path: &str,
        raw_path_item: &'graph Value,
    ) -> Vec<Operation> {
        let path_node = NodeView {
            doc_id,
            pointer: append_pointer("/paths", path),
            value: raw_path_item,
        };
        self.parse_path_item_operations(path_node, Some(path))
    }

    fn parse_webhooks(&mut self, root: &NodeView<'graph>) -> Vec<Webhook> {
        let Some(value) = root.value.get("webhooks") else {
            return Vec::new();
        };
        if self.version == OasVersion::V3_0 {
            self.sink.push(self.warning_diagnostic(
                CODE_WEBHOOKS_VERSION,
                root.doc_id,
                "/webhooks",
                "top-level 'webhooks' requires OpenAPI 3.1 and is ignored",
            ));
            return Vec::new();
        }
        let Some(webhooks) = value.as_object() else {
            self.shape_error(root.doc_id, "/webhooks", "webhooks must be an object");
            return Vec::new();
        };
        webhooks
            .iter()
            .filter_map(|(name, value)| {
                if name.starts_with("x-") {
                    return None;
                }
                let pointer = append_pointer("/webhooks", name);
                let path_item = self.resolve_object(
                    NodeView {
                        doc_id: root.doc_id,
                        pointer,
                        value,
                    },
                    "webhook path item",
                )?;
                Some(Webhook {
                    name: name.clone(),
                    operations: self.parse_path_item_operations(path_item.clone(), None),
                    source: self.source(path_item.doc_id, &path_item.pointer),
                })
            })
            .collect()
    }

    fn parse_path_item_operations(
        &mut self,
        path_item: NodeView<'graph>,
        path_context: Option<&str>,
    ) -> Vec<Operation> {
        let Some(path_item) = self.resolve_object(path_item, "path item") else {
            return Vec::new();
        };
        let path_parameters = path_item
            .value
            .get("parameters")
            .map_or_else(Vec::new, |value| {
                let pointer = append_pointer(&path_item.pointer, "parameters");
                self.parse_parameters(NodeView {
                    doc_id: path_item.doc_id,
                    pointer,
                    value,
                })
            });
        let path_servers = path_item
            .value
            .get("servers")
            .map_or_else(Vec::new, |value| {
                let pointer = append_pointer(&path_item.pointer, "servers");
                self.parse_servers(NodeView {
                    doc_id: path_item.doc_id,
                    pointer,
                    value,
                })
            });
        let mut operations = Vec::new();
        for method in METHODS {
            let Some(value) = path_item.value.get(method) else {
                continue;
            };
            let pointer = append_pointer(&path_item.pointer, method);
            let operation_node = NodeView {
                doc_id: path_item.doc_id,
                pointer,
                value,
            };
            let Some(operation_object) = value.as_object() else {
                self.shape_error(
                    operation_node.doc_id,
                    &operation_node.pointer,
                    "operation must be an object",
                );
                continue;
            };
            if operation_object.contains_key("$ref") {
                self.sink.push(self.input_diagnostic(
                    CODE_OPERATION_REF,
                    operation_node.doc_id,
                    &operation_node.pointer,
                    "OpenAPI defines '$ref' on a Path Item Object but not on an Operation Object; bundle the document before compiling, or place '$ref' on the whole path item when its target is a Path Item Object",
                ));
                continue;
            }
            operations.push(self.parse_operation(
                method,
                path_context,
                operation_node,
                operation_object,
                &path_parameters,
                &path_servers,
            ));
        }
        operations
    }

    fn parse_operation(
        &mut self,
        method: &str,
        path_context: Option<&str>,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        path_parameters: &[Param],
        path_servers: &[ServerEntry],
    ) -> Operation {
        let operation_parameters = object.get("parameters").map_or_else(Vec::new, |value| {
            let pointer = append_pointer(&node.pointer, "parameters");
            self.parse_parameters(NodeView {
                doc_id: node.doc_id,
                pointer,
                value,
            })
        });
        let parameters = merge_parameters(path_parameters, operation_parameters);
        let path_template = path_context.map_or_else(Vec::new, parse_path_template);
        if let Some(path) = path_context {
            self.validate_path_parameters(path, &path_template, &parameters, &node);
        }
        let request_body = object.get("requestBody").and_then(|value| {
            let pointer = append_pointer(&node.pointer, "requestBody");
            self.parse_body(NodeView {
                doc_id: node.doc_id,
                pointer,
                value,
            })
        });
        let responses = match object.get("responses") {
            None => {
                if self.version == OasVersion::V3_0 {
                    self.shape_error(node.doc_id, &node.pointer, "operation is missing responses");
                }
                Vec::new()
            }
            Some(value) => {
                let pointer = append_pointer(&node.pointer, "responses");
                self.parse_responses(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })
            }
        };
        let servers = object.get("servers").map_or_else(
            || path_servers.to_vec(),
            |value| {
                let pointer = append_pointer(&node.pointer, "servers");
                self.parse_servers(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })
            },
        );
        let security = object.get("security").map(|value| {
            let pointer = append_pointer(&node.pointer, "security");
            self.parse_security_requirements(NodeView {
                doc_id: node.doc_id,
                pointer,
                value,
            })
        });
        let callbacks = object.get("callbacks").map_or_else(Vec::new, |value| {
            let pointer = append_pointer(&node.pointer, "callbacks");
            self.parse_callbacks(NodeView {
                doc_id: node.doc_id,
                pointer,
                value,
            })
        });
        Operation {
            method: method.to_owned(),
            path_template,
            tags: string_array_field(object, "tags"),
            path: path_context.map(str::to_owned),
            operation_id: string_field(object, "operationId"),
            summary: string_field(object, "summary"),
            description: string_field(object, "description"),
            deprecated: bool_field(object, "deprecated"),
            external_docs: self.parse_external_docs(&node, object.get("externalDocs")),
            parameters,
            request_body,
            responses,
            callbacks,
            servers,
            security,
            source: self.source(node.doc_id, &node.pointer),
        }
    }

    fn parse_callbacks(&mut self, node: NodeView<'graph>) -> Vec<Callback> {
        let Some(callbacks) = node.value.as_object() else {
            self.shape_error(node.doc_id, &node.pointer, "callbacks must be an object");
            return Vec::new();
        };
        callbacks
            .iter()
            .filter_map(|(name, value)| {
                let pointer = append_pointer(&node.pointer, name);
                let callback_node = self.resolve_object(
                    NodeView {
                        doc_id: node.doc_id,
                        pointer,
                        value,
                    },
                    "callback",
                )?;
                let callback = callback_node.value.as_object()?;
                let expressions = callback
                    .iter()
                    .filter_map(|(expression, value)| {
                        if expression.starts_with("x-") {
                            return None;
                        }
                        let pointer = append_pointer(&callback_node.pointer, expression);
                        let path_item = NodeView {
                            doc_id: callback_node.doc_id,
                            pointer,
                            value,
                        };
                        let source = self.source(path_item.doc_id, &path_item.pointer);
                        Some(CallbackExpression {
                            expression: expression.clone(),
                            operations: self.parse_path_item_operations(path_item, None),
                            source,
                        })
                    })
                    .collect();
                Some(Callback {
                    name: name.clone(),
                    expressions,
                    source: self.source(callback_node.doc_id, &callback_node.pointer),
                })
            })
            .collect()
    }

    fn parse_external_docs(
        &mut self,
        parent: &NodeView<'graph>,
        value: Option<&Value>,
    ) -> Option<(String, Option<String>)> {
        let value = value?;
        let pointer = append_pointer(&parent.pointer, "externalDocs");
        let Some(object) = value.as_object() else {
            self.shape_error(parent.doc_id, &pointer, "externalDocs must be an object");
            return None;
        };
        let Some(url) = object.get("url").and_then(Value::as_str) else {
            self.shape_error(parent.doc_id, &pointer, "externalDocs.url must be a string");
            return None;
        };
        Some((url.to_owned(), string_field(object, "description")))
    }

    fn parse_parameters(&mut self, node: NodeView<'graph>) -> Vec<Param> {
        let Some(values) = node.value.as_array() else {
            self.shape_error(node.doc_id, &node.pointer, "parameters must be an array");
            return Vec::new();
        };
        values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let pointer = append_pointer_index(&node.pointer, index);
                self.parse_parameter(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })
            })
            .collect()
    }

    fn parse_parameter(&mut self, node: NodeView<'graph>) -> Option<Param> {
        let node = self.resolve_object(node, "parameter")?;
        let object = node.value.as_object()?;
        let Some(name) = object.get("name").and_then(Value::as_str) else {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                "parameter.name must be a string",
            );
            return None;
        };
        let location = match object.get("in").and_then(Value::as_str) {
            Some("path") => ParamLocation::Path,
            Some("query") => ParamLocation::Query,
            Some("header") => ParamLocation::Header,
            Some("cookie") => ParamLocation::Cookie,
            _ => {
                self.shape_error(
                    node.doc_id,
                    &node.pointer,
                    "parameter.in must be path, query, header, or cookie",
                );
                return None;
            }
        };
        if location == ParamLocation::Header
            && ["accept", "content-type", "authorization"]
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            self.sink.push(self.warning_diagnostic(
                CODE_RESERVED_HEADER_PARAMETER,
                node.doc_id,
                &node.pointer,
                format!(
                    "header parameter '{name}' is ignored because OpenAPI reserves Accept, Content-Type, and Authorization"
                ),
            ));
            return None;
        }
        let content_declared = object.contains_key("content");
        let (schema, content_media_type) =
            match self.parse_content_schema(&node, object, "parameter") {
                ContentSchema::NotDeclared => match object.get("schema") {
                    None => {
                        let pointer = append_pointer(&node.pointer, "schema");
                        (
                            self.unsupported_schema(
                                node.doc_id,
                                &pointer,
                                "parameter content or missing schema is not supported",
                            ),
                            None,
                        )
                    }
                    Some(value) => {
                        let pointer = append_pointer(&node.pointer, "schema");
                        (
                            self.parse_schema(NodeView {
                                doc_id: node.doc_id,
                                pointer,
                                value,
                            }),
                            None,
                        )
                    }
                },
                ContentSchema::Empty => {
                    let pointer = append_pointer(&node.pointer, "schema");
                    (
                        self.unsupported_schema(
                            node.doc_id,
                            &pointer,
                            "parameter content or missing schema is not supported",
                        ),
                        None,
                    )
                }
                ContentSchema::Parsed { media_type, schema } => (*schema, Some(media_type)),
                ContentSchema::Invalid => return None,
            };
        let (style, explode, allow_reserved) = if content_declared {
            (None, None, false)
        } else {
            (
                self.parse_param_style(&node, object, "parameter"),
                object.get("explode").and_then(Value::as_bool),
                bool_field(object, "allowReserved"),
            )
        };
        Some(Param {
            name: name.to_owned(),
            location,
            required: bool_field(object, "required"),
            deprecated: bool_field(object, "deprecated"),
            description: string_field(object, "description"),
            schema,
            content_media_type,
            style,
            explode,
            allow_reserved,
            source: self.source(node.doc_id, &node.pointer),
        })
    }

    fn parse_content_schema(
        &mut self,
        node: &NodeView<'graph>,
        object: &'graph Map<String, Value>,
        kind: &str,
    ) -> ContentSchema {
        let Some(value) = object.get("content") else {
            return ContentSchema::NotDeclared;
        };
        let pointer = append_pointer(&node.pointer, "content");
        let Some(content) = value.as_object() else {
            self.shape_error(
                node.doc_id,
                &pointer,
                format!("{kind} content must be an object"),
            );
            return ContentSchema::Invalid;
        };
        if content.is_empty() {
            return ContentSchema::Empty;
        }
        if content.len() != 1 {
            self.shape_error(
                node.doc_id,
                &pointer,
                format!("{kind} content map must contain exactly one entry"),
            );
            return ContentSchema::Invalid;
        }
        let (raw_name, value) = content.iter().next().expect("one content entry");
        let media_pointer = append_pointer(&pointer, raw_name);
        let Some(canonical) = self.parse_content_key(node.doc_id, &media_pointer, raw_name) else {
            return ContentSchema::Invalid;
        };
        let (schema, _) = self.parse_media_schema(node.doc_id, &media_pointer, value);
        ContentSchema::Parsed {
            media_type: canonical.full,
            schema: Box::new(schema),
        }
    }

    fn parse_content_key(
        &mut self,
        doc_id: DocId,
        pointer: &str,
        raw_name: &str,
    ) -> Option<crate::media::CanonicalMedia> {
        match canonical_content_key(raw_name) {
            Ok(media) => {
                // A wildcard range that carries parameters (`text/*; q=0.5`) has no runtime match
                // tier — `selectedMediaType` admits the range and any tiers only for
                // parameter-free keys — so the branch it would form can never be selected. Drop it
                // with the same media-key warning rather than emit a dead arm. `full != essence`
                // means parameters are present; ranges are every non-`Concrete` kind.
                if media.range_kind != crate::media::MediaRangeKind::Concrete
                    && media.full != media.essence
                {
                    self.sink.push(self.warning_diagnostic(
                        CODE_MEDIA_TYPE,
                        doc_id,
                        pointer,
                        format!(
                            "content key '{raw_name}' is a media range with parameters, which has no runtime match tier; dropping it"
                        ),
                    ));
                    return None;
                }
                Some(media)
            }
            Err(()) => {
                self.sink.push(self.warning_diagnostic(
                    CODE_MEDIA_TYPE,
                    doc_id,
                    pointer,
                    format!(
                        "malformed content key '{raw_name}'; expected an RFC 9110 type/subtype media type or wildcard range"
                    ),
                ));
                None
            }
        }
    }

    fn parse_body(&mut self, node: NodeView<'graph>) -> Option<Body> {
        let node = self.resolve_object(node, "request body")?;
        let object = node.value.as_object()?;
        Some(Body {
            required: bool_field(object, "required"),
            description: string_field(object, "description"),
            media_types: object.get("content").map_or_else(Vec::new, |value| {
                let pointer = append_pointer(&node.pointer, "content");
                self.parse_media_types(
                    NodeView {
                        doc_id: node.doc_id,
                        pointer,
                        value,
                    },
                    true,
                )
            }),
            source: self.source(node.doc_id, &node.pointer),
        })
    }

    fn parse_responses(&mut self, node: NodeView<'graph>) -> Vec<ResponseEntry> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(node.doc_id, &node.pointer, "responses must be an object");
            return Vec::new();
        };
        if object.keys().all(|key| key.starts_with("x-")) {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                "responses object must declare at least one response",
            );
            return Vec::new();
        }
        // A responses object holds a handful of entries, so a linear scan beats hashing and
        // keeps `ResponseStatus` free of a `Hash` bound it needs nowhere else.
        let mut seen_statuses: Vec<ResponseStatus> = Vec::new();
        object
            .iter()
            .filter_map(|(key, value)| {
                if key.starts_with("x-") {
                    return None;
                }
                let pointer = append_pointer(&node.pointer, key);
                let status = match parse_response_status(key) {
                    Some(status) => status,
                    None => {
                        self.sink.push(
                            Diagnostic::input(
                                CODE_RESPONSE_STATUS,
                                format!(
                                    "invalid response status key '{key}'; use 'default', a three-digit code, or a range like '4XX'"
                                ),
                            )
                            .with_source(self.source_id(node.doc_id))
                            .with_json_pointer(&pointer),
                        );
                        return None;
                    }
                };
                if let ResponseStatus::Range(canonical) = &status
                    && canonical != key
                {
                    let mut diagnostic = Diagnostic::input(
                        CODE_RESPONSE_STATUS_CASE,
                        format!(
                            "response status range '{key}' is lowercase; OpenAPI specifies the uppercase wildcard, so it is read as '{canonical}'"
                        ),
                    )
                    .with_source(self.source_id(node.doc_id))
                    .with_json_pointer(&pointer);
                    diagnostic.severity = Severity::Warning;
                    self.sink.push(diagnostic);
                }
                if seen_statuses.contains(&status) {
                    self.sink.push(
                        Diagnostic::input(
                            CODE_RESPONSE_STATUS_DUPLICATE,
                            format!(
                                "response status key '{key}' names a status another key in the same responses object already declares"
                            ),
                        )
                        .with_source(self.source_id(node.doc_id))
                        .with_json_pointer(&pointer),
                    );
                    return None;
                }
                seen_statuses.push(status.clone());
                let response_node = self.resolve_object(
                    NodeView {
                        doc_id: node.doc_id,
                        pointer,
                        value,
                    },
                    "response",
                )?;
                let response = response_node.value.as_object()?;
                let description = response
                    .get("description")
                    .and_then(Value::as_str)
                    .map_or_else(
                        || {
                            self.shape_error(
                                response_node.doc_id,
                                &response_node.pointer,
                                "response.description must be a string",
                            );
                            String::new()
                        },
                        str::to_owned,
                    );
                Some(ResponseEntry {
                    status,
                    description,
                    media_types: response.get("content").map_or_else(Vec::new, |content| {
                        let content_pointer = append_pointer(&response_node.pointer, "content");
                        self.parse_media_types(
                            NodeView {
                                doc_id: response_node.doc_id,
                                pointer: content_pointer,
                                value: content,
                            },
                            false,
                        )
                    }),
                    headers: response.get("headers").map_or_else(Vec::new, |headers| {
                        self.parse_response_headers(NodeView {
                            doc_id: response_node.doc_id,
                            pointer: append_pointer(&response_node.pointer, "headers"),
                            value: headers,
                        })
                    }),
                    links: response.get("links").map_or_else(Vec::new, |links| {
                        self.parse_links(NodeView {
                            doc_id: response_node.doc_id,
                            pointer: append_pointer(&response_node.pointer, "links"),
                            value: links,
                        })
                    }),
                    source: self.source(response_node.doc_id, &response_node.pointer),
                })
            })
            .collect()
    }

    fn parse_response_headers(&mut self, node: NodeView<'graph>) -> Vec<(String, ResponseHeader)> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                "response headers must be an object",
            );
            return Vec::new();
        };
        let mut parsed = Vec::new();
        let mut names = HashMap::new();
        for (name, value) in object {
            let pointer = append_pointer(&node.pointer, name);
            if name.eq_ignore_ascii_case("content-type") {
                self.sink.push(self.warning_diagnostic(
                    CODE_HEADER_CONTENT_TYPE,
                    node.doc_id,
                    &pointer,
                    "response header 'Content-Type' is defined by the media type and is ignored",
                ));
                continue;
            }
            let folded_name = name.to_ascii_lowercase();
            if let Some(prior) = names.get(&folded_name) {
                self.sink.push(self.input_diagnostic(
                    CODE_HEADER_DUPLICATE,
                    node.doc_id,
                    &pointer,
                    format!("response header '{name}' conflicts case-insensitively with '{prior}'"),
                ));
                continue;
            }
            names.insert(folded_name, name.clone());
            let Some(header_node) = self.resolve_object(
                NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                },
                "response header",
            ) else {
                continue;
            };
            let Some(header) = header_node.value.as_object() else {
                continue;
            };
            let (schema, content_media_type) =
                match self.parse_content_schema(&header_node, header, "response header") {
                    ContentSchema::NotDeclared => {
                        let schema_pointer = append_pointer(&header_node.pointer, "schema");
                        let Some(schema) = header.get("schema") else {
                            self.unsupported_schema(
                                header_node.doc_id,
                                &schema_pointer,
                                "response header content or missing schema is not supported",
                            );
                            continue;
                        };
                        (
                            self.parse_schema(NodeView {
                                doc_id: header_node.doc_id,
                                pointer: schema_pointer,
                                value: schema,
                            }),
                            None,
                        )
                    }
                    ContentSchema::Empty => {
                        let schema_pointer = append_pointer(&header_node.pointer, "schema");
                        self.unsupported_schema(
                            header_node.doc_id,
                            &schema_pointer,
                            "response header content or missing schema is not supported",
                        );
                        continue;
                    }
                    ContentSchema::Parsed { media_type, schema } => (*schema, Some(media_type)),
                    ContentSchema::Invalid => continue,
                };
            parsed.push((
                name.clone(),
                ResponseHeader {
                    required: bool_field(header, "required"),
                    deprecated: bool_field(header, "deprecated"),
                    description: string_field(header, "description"),
                    schema,
                    content_media_type,
                    source: self.source(header_node.doc_id, &header_node.pointer),
                },
            ));
        }
        parsed
    }

    fn parse_links(&mut self, node: NodeView<'graph>) -> Vec<Link> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(node.doc_id, &node.pointer, "links must be an object");
            return Vec::new();
        };
        object
            .iter()
            .filter_map(|(name, value)| {
                let pointer = append_pointer(&node.pointer, name);
                let link_node = self.resolve_object(
                    NodeView {
                        doc_id: node.doc_id,
                        pointer: pointer.clone(),
                        value,
                    },
                    "link",
                )?;
                let link = link_node.value.as_object()?;
                let target = match (
                    link.get("operationId").and_then(Value::as_str),
                    link.get("operationRef").and_then(Value::as_str),
                ) {
                    (Some(_), Some(_)) => {
                        self.sink.push(self.input_diagnostic(
                            CODE_LINK_TARGET,
                            node.doc_id,
                            &pointer,
                            format!("link '{name}' declares both operationId and operationRef"),
                        ));
                        return None;
                    }
                    (None, None) => {
                        self.sink.push(self.input_diagnostic(
                            CODE_LINK_TARGET,
                            node.doc_id,
                            &pointer,
                            format!("link '{name}' declares neither operationId nor operationRef"),
                        ));
                        return None;
                    }
                    (Some(operation_id), None) => LinkTarget::OperationId(operation_id.to_owned()),
                    (None, Some(operation_ref)) => {
                        LinkTarget::OperationRef(operation_ref.to_owned())
                    }
                };
                let parameters = link
                    .get("parameters")
                    .and_then(Value::as_object)
                    .map_or_else(Vec::new, |parameters| {
                        parameters
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name.clone(),
                                    value
                                        .as_str()
                                        .map_or_else(|| compact_json(value), str::to_owned),
                                )
                            })
                            .collect()
                    });
                Some(Link {
                    name: name.clone(),
                    target,
                    parameters,
                    description: string_field(link, "description"),
                    source: self.source(link_node.doc_id, &link_node.pointer),
                })
            })
            .collect()
    }

    fn parse_media_types(
        &mut self,
        node: NodeView<'graph>,
        parse_encodings: bool,
    ) -> Vec<MediaType> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(node.doc_id, &node.pointer, "content must be an object");
            return Vec::new();
        };
        let mut parsed = Vec::new();
        let mut canonical_keys = HashMap::new();
        for (raw_name, value) in object {
            let pointer = append_pointer(&node.pointer, raw_name);
            // Dropped rather than fatal, because an unusable content key cannot form a branch
            // and an emptied content map degrades to the no-content branch.
            let Some(canonical) = self.parse_content_key(node.doc_id, &pointer, raw_name) else {
                continue;
            };
            if let Some((first_index, first_raw_name)) = canonical_keys.get(&canonical.full) {
                parsed[*first_index] = None;
                self.sink.push(self.input_diagnostic(
                    CODE_DUPLICATE_MEDIA_TYPE,
                    node.doc_id,
                    &pointer,
                    format!(
                        "duplicate content keys '{first_raw_name}' and '{raw_name}' canonicalize to '{}'",
                        canonical.full
                    ),
                ));
                continue;
            }
            canonical_keys.insert(canonical.full.clone(), (parsed.len(), raw_name.clone()));
            let (schema, schema_present) = self.parse_media_schema(node.doc_id, &pointer, value);
            let encodings = if parse_encodings
                && (canonical.essence == "application/x-www-form-urlencoded"
                    || canonical.essence.starts_with("multipart/"))
            {
                value.get("encoding").map_or_else(Vec::new, |encoding| {
                    self.parse_encodings(NodeView {
                        doc_id: node.doc_id,
                        pointer: append_pointer(&pointer, "encoding"),
                        value: encoding,
                    })
                })
            } else {
                Vec::new()
            };
            parsed.push(Some(MediaType {
                essence: canonical.essence,
                full: canonical.full,
                range_kind: canonical.range_kind,
                raw_name: raw_name.clone(),
                schema,
                schema_present,
                examples: media_type_examples(value),
                encodings,
                streaming_marked: value
                    .get("x-oasts-streaming")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                oas_version: self.version,
                source: self.source(node.doc_id, &pointer),
            }));
        }
        parsed.into_iter().flatten().collect()
    }

    fn parse_media_schema(
        &mut self,
        doc_id: DocId,
        pointer: &str,
        value: &'graph Value,
    ) -> (SchemaNode, bool) {
        let schema_pointer = append_pointer(pointer, "schema");
        match value.get("schema") {
            None => (
                SchemaNode::Any {
                    meta: SchemaMeta {
                        source: self.source(doc_id, &schema_pointer),
                        ..SchemaMeta::default()
                    },
                },
                false,
            ),
            Some(schema) => (
                self.parse_schema(NodeView {
                    doc_id,
                    pointer: schema_pointer,
                    value: schema,
                }),
                true,
            ),
        }
    }

    fn parse_encodings(&mut self, node: NodeView<'graph>) -> Vec<(String, EncodingObject)> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(node.doc_id, &node.pointer, "encoding must be an object");
            return Vec::new();
        };
        object
            .iter()
            .filter_map(|(name, value)| {
                let pointer = append_pointer(&node.pointer, name);
                let Some(encoding) = value.as_object() else {
                    self.shape_error(node.doc_id, &pointer, "encoding value must be an object");
                    return None;
                };
                let encoding_node = NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                };
                let content_type =
                    encoding
                        .get("contentType")
                        .and_then(Value::as_str)
                        .map(|value| {
                            crate::media::split_media_type_list(value)
                                .unwrap_or_else(|()| vec![value])
                                .into_iter()
                                .map(str::trim)
                                .map(str::to_owned)
                                .collect()
                        });
                let headers = encoding.get("headers").map_or_else(Vec::new, |headers| {
                    self.parse_encoding_headers(NodeView {
                        doc_id: node.doc_id,
                        pointer: append_pointer(&encoding_node.pointer, "headers"),
                        value: headers,
                    })
                });
                let style = self.parse_param_style(&encoding_node, encoding, "encoding");
                Some((
                    name.clone(),
                    EncodingObject {
                        content_type,
                        headers,
                        style,
                        explode: encoding.get("explode").and_then(Value::as_bool),
                        allow_reserved: bool_field(encoding, "allowReserved"),
                        allow_reserved_explicit: encoding
                            .get("allowReserved")
                            .is_some_and(Value::is_boolean),
                        source: self.source(encoding_node.doc_id, &encoding_node.pointer),
                    },
                ))
            })
            .collect()
    }

    fn parse_encoding_headers(&mut self, node: NodeView<'graph>) -> Vec<(String, EncodingHeader)> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                "encoding headers must be an object",
            );
            return Vec::new();
        };
        object
            .iter()
            .filter_map(|(name, value)| {
                let pointer = append_pointer(&node.pointer, name);
                let header_node = self.resolve_object(
                    NodeView {
                        doc_id: node.doc_id,
                        pointer,
                        value,
                    },
                    "encoding header",
                )?;
                let header = header_node.value.as_object()?;
                let (schema, content_media_type) =
                    match self.parse_content_schema(&header_node, header, "encoding header") {
                        ContentSchema::NotDeclared => {
                            let schema_pointer = append_pointer(&header_node.pointer, "schema");
                            let schema = match header.get("schema") {
                                Some(schema) => self.parse_schema(NodeView {
                                    doc_id: header_node.doc_id,
                                    pointer: schema_pointer,
                                    value: schema,
                                }),
                                None => self.unsupported_schema(
                                    header_node.doc_id,
                                    &schema_pointer,
                                    "encoding header content or missing schema is not supported",
                                ),
                            };
                            (schema, None)
                        }
                        ContentSchema::Empty => {
                            let schema_pointer = append_pointer(&header_node.pointer, "schema");
                            (
                                self.unsupported_schema(
                                    header_node.doc_id,
                                    &schema_pointer,
                                    "encoding header content or missing schema is not supported",
                                ),
                                None,
                            )
                        }
                        ContentSchema::Parsed { media_type, schema } => (*schema, Some(media_type)),
                        ContentSchema::Invalid => return None,
                    };
                Some((
                    name.clone(),
                    EncodingHeader {
                        required: bool_field(header, "required"),
                        schema,
                        content_media_type,
                        source: self.source(header_node.doc_id, &header_node.pointer),
                    },
                ))
            })
            .collect()
    }

    fn parse_param_style(
        &mut self,
        node: &NodeView<'graph>,
        object: &Map<String, Value>,
        kind: &str,
    ) -> Option<ParamStyle> {
        let value = object.get("style")?;
        let style = match value.as_str() {
            Some("form") => ParamStyle::Form,
            Some("simple") => ParamStyle::Simple,
            Some("label") => ParamStyle::Label,
            Some("matrix") => ParamStyle::Matrix,
            Some("spaceDelimited") => ParamStyle::SpaceDelimited,
            Some("pipeDelimited") => ParamStyle::PipeDelimited,
            Some("deepObject") => ParamStyle::DeepObject,
            _ => {
                self.shape_error(
                    node.doc_id,
                    &append_pointer(&node.pointer, "style"),
                    format!(
                        "{kind}.style must be form, simple, label, matrix, spaceDelimited, pipeDelimited, or deepObject"
                    ),
                );
                return None;
            }
        };
        Some(style)
    }

    fn parse_servers(&mut self, node: NodeView<'graph>) -> Vec<ServerEntry> {
        let Some(values) = node.value.as_array() else {
            self.shape_error(node.doc_id, &node.pointer, "servers must be an array");
            return Vec::new();
        };
        values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let pointer = append_pointer_index(&node.pointer, index);
                let Some(server) = value.as_object() else {
                    self.shape_error(node.doc_id, &pointer, "server must be an object");
                    return None;
                };
                let Some(url) = server.get("url").and_then(Value::as_str) else {
                    self.shape_error(
                        node.doc_id,
                        &append_pointer(&pointer, "url"),
                        "server.url must be a string",
                    );
                    return None;
                };
                let variables = server.get("variables").map_or_else(Vec::new, |variables| {
                    self.parse_server_variables(NodeView {
                        doc_id: node.doc_id,
                        pointer: append_pointer(&pointer, "variables"),
                        value: variables,
                    })
                });
                Some(ServerEntry {
                    url: url.to_owned(),
                    variables,
                    source: self.source(node.doc_id, &pointer),
                })
            })
            .collect()
    }

    fn parse_server_variables(&mut self, node: NodeView<'graph>) -> Vec<(String, ServerVariable)> {
        let Some(object) = node.value.as_object() else {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                "server variables must be an object",
            );
            return Vec::new();
        };
        object
            .iter()
            .filter_map(|(name, value)| {
                let pointer = append_pointer(&node.pointer, name);
                let Some(variable) = value.as_object() else {
                    self.shape_error(node.doc_id, &pointer, "server variable must be an object");
                    return None;
                };
                let Some(default) = variable.get("default").and_then(Value::as_str) else {
                    self.shape_error(
                        node.doc_id,
                        &append_pointer(&pointer, "default"),
                        "server variable default must be a string",
                    );
                    return None;
                };
                let raw_enum_empty = matches!(
                    variable.get("enum"),
                    Some(Value::Array(values)) if values.is_empty()
                );
                let enum_values = match variable.get("enum") {
                    None => Vec::new(),
                    Some(Value::Array(values)) => values
                        .iter()
                        .enumerate()
                        .filter_map(|(index, value)| {
                            value.as_str().map(str::to_owned).or_else(|| {
                                self.shape_error(
                                    node.doc_id,
                                    &append_pointer_index(&append_pointer(&pointer, "enum"), index),
                                    "server variable enum values must be strings",
                                );
                                None
                            })
                        })
                        .collect(),
                    Some(_) => {
                        self.shape_error(
                            node.doc_id,
                            &append_pointer(&pointer, "enum"),
                            "server variable enum must be an array",
                        );
                        Vec::new()
                    }
                };
                if raw_enum_empty {
                    let enum_pointer = append_pointer(&pointer, "enum");
                    let message = format!("server variable '{name}' declares an empty enum");
                    if self.version == OasVersion::V3_1 {
                        self.sink.push(self.input_diagnostic(
                            CODE_SERVER_VAR_ENUM_EMPTY,
                            node.doc_id,
                            &enum_pointer,
                            message,
                        ));
                    } else {
                        self.sink.push(self.warning_diagnostic(
                            CODE_SERVER_VAR_ENUM_EMPTY,
                            node.doc_id,
                            &enum_pointer,
                            message,
                        ));
                    }
                }
                if !enum_values.is_empty() && !enum_values.iter().any(|value| value == default) {
                    let default_pointer = append_pointer(&pointer, "default");
                    let message = format!(
                        "server variable '{name}' default '{default}' is not one of its enum values"
                    );
                    if self.version == OasVersion::V3_1 {
                        self.sink.push(self.input_diagnostic(
                            CODE_SERVER_VAR_DEFAULT,
                            node.doc_id,
                            &default_pointer,
                            message,
                        ));
                    } else {
                        self.sink.push(self.warning_diagnostic(
                            CODE_SERVER_VAR_DEFAULT,
                            node.doc_id,
                            &default_pointer,
                            message,
                        ));
                    }
                }
                Some((
                    name.clone(),
                    ServerVariable {
                        default: default.to_owned(),
                        enum_values,
                    },
                ))
            })
            .collect()
    }

    fn parse_security_requirements(&mut self, node: NodeView<'graph>) -> Vec<SecurityRequirement> {
        let Some(values) = node.value.as_array() else {
            self.shape_error(node.doc_id, &node.pointer, "security must be an array");
            return Vec::new();
        };
        values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let pointer = append_pointer_index(&node.pointer, index);
                let Some(requirement) = value.as_object() else {
                    self.shape_error(
                        node.doc_id,
                        &pointer,
                        "security requirement must be an object",
                    );
                    return None;
                };
                let mut parsed = Vec::new();
                let mut valid = true;
                for (name, value) in requirement {
                    let scopes_pointer = append_pointer(&pointer, name);
                    let Some(scopes) = value.as_array() else {
                        self.shape_error(
                            node.doc_id,
                            &scopes_pointer,
                            "security requirement scopes must be an array",
                        );
                        valid = false;
                        continue;
                    };
                    let mut parsed_scopes = Vec::new();
                    for (index, value) in scopes.iter().enumerate() {
                        match value.as_str() {
                            Some(scope) => parsed_scopes.push(scope.to_owned()),
                            None => {
                                self.shape_error(
                                    node.doc_id,
                                    &append_pointer_index(&scopes_pointer, index),
                                    "security requirement scopes must be strings",
                                );
                                valid = false;
                            }
                        }
                    }
                    parsed.push((name.clone(), parsed_scopes));
                }
                valid.then_some(parsed)
            })
            .collect()
    }

    fn parse_security_schemes(&mut self, root: &NodeView<'graph>) -> Vec<NamedSecurityScheme> {
        let Some(value) = root
            .value
            .get("components")
            .and_then(|components| components.get("securitySchemes"))
        else {
            return Vec::new();
        };
        let pointer = "/components/securitySchemes";
        let Some(object) = value.as_object() else {
            self.shape_error(
                root.doc_id,
                pointer,
                "components.securitySchemes must be an object",
            );
            return Vec::new();
        };
        object
            .iter()
            .filter_map(|(name, value)| {
                let scheme_node = self.resolve_object(
                    NodeView {
                        doc_id: root.doc_id,
                        pointer: append_pointer(pointer, name),
                        value,
                    },
                    "security scheme",
                )?;
                let scheme = scheme_node.value.as_object()?;
                let kind = match scheme.get("type").and_then(Value::as_str) {
                    Some("http") => SecKind::Http {
                        scheme: string_field(scheme, "scheme").unwrap_or_default(),
                        bearer_format: string_field(scheme, "bearerFormat"),
                    },
                    Some("apiKey") => match scheme.get("in").and_then(Value::as_str) {
                        Some("query") => SecKind::ApiKey {
                            location: ParamLocation::Query,
                            name: string_field(scheme, "name").unwrap_or_default(),
                        },
                        Some("header") => SecKind::ApiKey {
                            location: ParamLocation::Header,
                            name: string_field(scheme, "name").unwrap_or_default(),
                        },
                        Some("cookie") => SecKind::ApiKey {
                            location: ParamLocation::Cookie,
                            name: string_field(scheme, "name").unwrap_or_default(),
                        },
                        _ => SecKind::Other,
                    },
                    Some("oauth2") => SecKind::OAuth2 {
                        flows: self.parse_oauth_flows(&scheme_node, scheme),
                    },
                    Some("openIdConnect") => SecKind::OpenIdConnect {
                        url: string_field(scheme, "openIdConnectUrl").unwrap_or_default(),
                    },
                    Some("mutualTLS") => SecKind::MutualTls,
                    _ => SecKind::Other,
                };
                Some(NamedSecurityScheme {
                    name: name.clone(),
                    kind,
                    source: self.source(scheme_node.doc_id, &scheme_node.pointer),
                })
            })
            .collect()
    }

    fn parse_oauth_flows(
        &mut self,
        scheme_node: &NodeView<'graph>,
        scheme: &Map<String, Value>,
    ) -> OAuthFlows {
        let empty = |declared| OAuthFlows {
            declared,
            implicit: None,
            password: None,
            client_credentials: None,
            authorization_code: None,
        };
        let Some(value) = scheme.get("flows") else {
            return empty(false);
        };
        let flows_pointer = append_pointer(&scheme_node.pointer, "flows");
        let Some(flows) = value.as_object() else {
            self.shape_error(
                scheme_node.doc_id,
                &flows_pointer,
                "OAuth2 flows must be an object",
            );
            return empty(true);
        };
        for key in flows.keys() {
            if key.starts_with("x-") {
                continue;
            }
            if !matches!(
                key.as_str(),
                "implicit" | "password" | "clientCredentials" | "authorizationCode"
            ) {
                self.sink.push(self.input_diagnostic(
                    CODE_SECURITY_FLOWS_SHAPE,
                    scheme_node.doc_id,
                    &append_pointer(&flows_pointer, key),
                    format!("unrecognized OAuth2 flow '{key}'"),
                ));
            }
        }
        OAuthFlows {
            declared: true,
            implicit: self.parse_oauth_flow(scheme_node.doc_id, &flows_pointer, flows, "implicit"),
            password: self.parse_oauth_flow(scheme_node.doc_id, &flows_pointer, flows, "password"),
            client_credentials: self.parse_oauth_flow(
                scheme_node.doc_id,
                &flows_pointer,
                flows,
                "clientCredentials",
            ),
            authorization_code: self.parse_oauth_flow(
                scheme_node.doc_id,
                &flows_pointer,
                flows,
                "authorizationCode",
            ),
        }
    }

    fn parse_oauth_flow(
        &mut self,
        doc_id: DocId,
        flows_pointer: &str,
        flows: &Map<String, Value>,
        key: &str,
    ) -> Option<OAuthFlow> {
        let value = flows.get(key)?;
        let pointer = append_pointer(flows_pointer, key);
        let Some(flow) = value.as_object() else {
            self.shape_error(doc_id, &pointer, "OAuth2 flow must be an object");
            return None;
        };
        let scopes = match flow.get("scopes") {
            None => {
                self.sink.push(self.input_diagnostic(
                    CODE_SECURITY_FLOWS_SHAPE,
                    doc_id,
                    &pointer,
                    "OAuth2 flow requires a scopes map",
                ));
                Vec::new()
            }
            Some(value) => {
                let scopes_pointer = append_pointer(&pointer, "scopes");
                match value.as_object() {
                    Some(scopes) if scopes.values().all(Value::is_string) => scopes
                        .iter()
                        .map(|(name, description)| {
                            (
                                name.clone(),
                                description.as_str().unwrap_or_default().to_owned(),
                            )
                        })
                        .collect(),
                    _ => {
                        self.sink.push(self.input_diagnostic(
                            CODE_SECURITY_FLOWS_SHAPE,
                            doc_id,
                            &scopes_pointer,
                            "OAuth2 scopes must map scope names to description strings",
                        ));
                        Vec::new()
                    }
                }
            }
        };
        Some(OAuthFlow {
            authorization_url: string_field(flow, "authorizationUrl"),
            token_url: string_field(flow, "tokenUrl"),
            refresh_url: string_field(flow, "refreshUrl"),
            scopes,
        })
    }

    fn parse_schema(&mut self, node: NodeView<'graph>) -> SchemaNode {
        if let Some(boolean) = node.value.as_bool() {
            let meta = self.schema_meta(&node, None);
            if self.version == OasVersion::V3_1 {
                return if boolean {
                    SchemaNode::Any { meta }
                } else {
                    SchemaNode::Never { meta }
                };
            }
            return self.unsupported_schema(
                node.doc_id,
                &node.pointer,
                "boolean schemas require OpenAPI 3.1",
            );
        }
        let Some(object) = node.value.as_object() else {
            return self.unsupported_schema(
                node.doc_id,
                &node.pointer,
                "schema must be an object or an OpenAPI 3.1 boolean schema",
            );
        };
        let mut meta = self.schema_meta(&node, Some(object));
        let not_admits_everything = meta
            .validation_applicators()
            .not
            .as_deref()
            .is_some_and(schema_admits_everything);
        if not_admits_everything {
            let mut applicators = meta
                .validation_applicators
                .take()
                .map(|applicators| *applicators)
                .unwrap_or_default();
            applicators.not = None;
            meta.validation_applicators = box_if_populated(applicators);
            return SchemaNode::Never { meta };
        }
        if object
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && !(self.version == OasVersion::V3_0
                && object.get("$ref").and_then(Value::as_str).is_some())
        {
            let pointer = append_pointer(&node.pointer, "enum");
            let message = match self.version {
                OasVersion::V3_0 => "enum must contain at least one member in OpenAPI 3.0 (MUST)",
                OasVersion::V3_1 => {
                    "enum should contain at least one member in OpenAPI 3.1 (SHOULD); the schema admits no value and is lowered to never"
                }
            };
            let diagnostic = match self.version {
                OasVersion::V3_0 => {
                    self.input_diagnostic(CODE_ENUM_RULE_14, node.doc_id, &pointer, message)
                }
                OasVersion::V3_1 => {
                    self.warning_diagnostic(CODE_ENUM_RULE_14, node.doc_id, &pointer, message)
                }
            };
            self.sink.push(diagnostic);
            meta.nullable = false;
            return SchemaNode::Never { meta };
        }
        let dialect_unsupported = if self.version == OasVersion::V3_0 {
            [
                "const",
                "prefixItems",
                "dependentRequired",
                "propertyNames",
                "patternProperties",
                "contains",
                "minContains",
                "maxContains",
                "dependentSchemas",
            ]
            .into_iter()
            .find(|keyword| object.contains_key(*keyword))
            .map(|keyword| (keyword, keyword))
            .or_else(|| {
                object
                    .get("type")
                    .is_some_and(Value::is_array)
                    .then_some(("type", "type array"))
            })
        } else {
            None
        };
        if let Some((pointer_keyword, display_keyword)) = dialect_unsupported {
            self.sink.push(self.unsupported_diagnostic(
                node.doc_id,
                &append_pointer(&node.pointer, pointer_keyword),
                format!(
                    "schema keyword '{display_keyword}' requires OpenAPI 3.1 and becomes unknown"
                ),
            ));
            return SchemaNode::Unknown {
                reason: format!("OpenAPI 3.0 does not support {display_keyword}"),
                meta,
            };
        }
        if self.version == OasVersion::V3_1 {
            for keyword in [
                "contains",
                "minContains",
                "maxContains",
                "dependentSchemas",
                "if",
                "then",
                "else",
                "unevaluatedProperties",
                "unevaluatedItems",
            ] {
                if object.contains_key(keyword) {
                    self.sink.push(self.unsupported_diagnostic(
                        node.doc_id,
                        &append_pointer(&node.pointer, keyword),
                        format!(
                            "schema keyword '{keyword}' has no faithful TypeScript representation and becomes unknown on the types surface"
                        ),
                    ));
                }
            }
        }
        if self.version == OasVersion::V3_0
            && let Some(keyword) = [
                "if",
                "then",
                "else",
                "unevaluatedProperties",
                "unevaluatedItems",
                "additionalItems",
            ]
            .into_iter()
            .find(|keyword| object.contains_key(*keyword))
        {
            self.sink.push(self.unsupported_diagnostic(
                node.doc_id,
                &append_pointer(&node.pointer, keyword),
                format!("unsupported schema keyword '{keyword}' becomes unknown"),
            ));
            if !object.contains_key("$ref")
                && !object.contains_key("allOf")
                && !object.contains_key("oneOf")
                && !object.contains_key("anyOf")
                && !has_typed_or_constraint_content(object, self.version)
            {
                return SchemaNode::Unknown {
                    reason: format!("unsupported keyword {keyword}"),
                    meta,
                };
            }
        }
        // A dynamic reference is an applicator, exactly like `$ref`, so it counts as one piece of
        // the conjunction below. Under 3.0 it is not a keyword at all and falls through to the
        // unsupported path instead.
        let dynamic = if self.version == OasVersion::V3_1 {
            DYNAMIC_REF_KEYWORDS
                .iter()
                .find_map(|keyword| object.get(*keyword).map(|value| (*keyword, value)))
        } else {
            None
        };
        // Unsupported keywords are conjuncts like every other keyword on a schema object, so drop
        // only that unrepresentable conjunct while preserving any representable siblings. Without
        // a representable sibling, dropping it would widen the schema to `Any`; retain `Unknown` to
        // record the imprecision reported by the diagnostic.
        if let Some(keyword) = DYNAMIC_REF_KEYWORDS
            .iter()
            .find(|keyword| dynamic.is_none() && object.contains_key(**keyword))
        {
            self.sink.push(self.unsupported_diagnostic(
                node.doc_id,
                &append_pointer(&node.pointer, keyword),
                format!("unsupported schema keyword '{keyword}' becomes unknown"),
            ));
            if !object.contains_key("$ref")
                && !object.contains_key("allOf")
                && !object.contains_key("oneOf")
                && !object.contains_key("anyOf")
                && !has_typed_or_constraint_content(object, self.version)
            {
                return SchemaNode::Unknown {
                    reason: format!("unsupported keyword {keyword}"),
                    meta,
                };
            }
        }
        // JSON Schema (both dialects) applies every keyword on one schema object conjunctively.
        // Detect how many independent "pieces" the object carries; the historical dispatch below
        // picks exactly one and silently drops the rest, which is only correct when there is at
        // most one piece.
        let ref_str = object.get("$ref").and_then(Value::as_str);
        let has_ref = ref_str.is_some();
        let has_allof = object.contains_key("allOf");
        let has_oneof = object.contains_key("oneOf");
        let has_anyof = object.contains_key("anyOf");
        // Only an applicator sibling can push a typed/constraint object to two pieces (the
        // conjunction path) or onto a 3.0 `$ref`'s sibling warning; a plain typed leaf never
        // consumes `has_typed`, so short-circuit past the content scan when no applicator is present.
        let has_dynamic = dynamic.is_some();
        let has_typed = (has_ref || has_allof || has_oneof || has_anyof || has_dynamic)
            && has_typed_or_constraint_content(object, self.version);
        let piece_count = usize::from(has_ref)
            + usize::from(has_allof)
            + usize::from(has_oneof)
            + usize::from(has_anyof)
            + usize::from(has_dynamic)
            + usize::from(has_typed);

        // OpenAPI 3.0 substitutes a Reference Object for the whole schema, so `$ref` wins outright
        // and every sibling keyword is dropped (unchanged semantics). A structural or constraint
        // sibling is almost always an authoring mistake — the author expected composition — so warn
        // and point at how to compose; pure-annotation siblings on a ref are legitimate and silent.
        if self.version == OasVersion::V3_0
            && let Some(reference) = ref_str
        {
            if has_allof || has_oneof || has_anyof || has_typed {
                self.sink.push(self.warning_diagnostic(
                    CODE_REF_SIBLINGS,
                    node.doc_id,
                    &node.pointer,
                    "$ref ignores sibling keyword(s) in OpenAPI 3.0; move them under allOf to compose",
                ));
            }
            meta.validation_applicators = None;
            return self.parse_schema_ref(node, reference, meta);
        }

        if piece_count >= 2 {
            return self.lower_conjunction(node, object, meta, has_typed, dynamic);
        }

        // piece_count <= 1: exactly the historical single-interpretation dispatch. Every existing
        // fixture parses through here unchanged — the determinism guard.
        if let Some(reference) = ref_str {
            return self.parse_schema_ref(node, reference, meta);
        }
        if let Some((keyword, value)) = dynamic {
            return self.parse_dynamic_ref(node, keyword, value, meta);
        }
        if let Some(branches) = object.get("allOf") {
            return SchemaNode::AllOf {
                branches: self.parse_schema_array(node, "allOf", branches),
                meta,
            };
        }
        if let Some(branches) = object.get("oneOf") {
            return SchemaNode::OneOf {
                branches: self.parse_schema_array(node.clone(), "oneOf", branches),
                discriminator: self
                    .parse_discriminator(node, object.get("discriminator"))
                    .map(Box::new),
                meta,
            };
        }
        if let Some(branches) = object.get("anyOf") {
            // Clone the node only to parse a discriminator that is actually present: an `anyOf`
            // without one — the overwhelming majority — keeps its pre-discriminator zero-clone cost.
            let discriminator = object
                .get("discriminator")
                .and_then(|value| self.parse_discriminator(node.clone(), Some(value)))
                .map(Box::new);
            return SchemaNode::AnyOf {
                branches: self.parse_schema_array(node, "anyOf", branches),
                discriminator,
                meta,
            };
        }
        if self.version == OasVersion::V3_1 && object.contains_key("prefixItems") {
            return self.parse_tuple(node, object, meta);
        }
        self.parse_typed_schema(node, object, meta)
    }

    /// Lowers a schema object carrying two or more of {`$ref`, `allOf`, `oneOf`, `anyOf`,
    /// typed/constraint content} into a synthetic `AllOf` conjunction — the fix for the historical
    /// dispatch silently keeping one interpretation and dropping the rest. Branch order is
    /// deterministic so regenerated output stays stable: the `$ref` piece, then the flattened
    /// `allOf` branches (no nested `AllOf`-in-`AllOf`), then the `oneOf`, `anyOf`, and finally the
    /// typed/tuple piece. The typed piece is parsed by the existing `parse_typed_schema`/`parse_tuple`
    /// paths, which turns sibling `properties`/`type`/constraints into a real conjunction branch.
    /// Reached only when `piece_count >= 2`; the OpenAPI 3.0 `$ref`-wins rule is handled by the
    /// caller, so a `$ref` piece here is always OpenAPI 3.1.
    fn lower_conjunction(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        meta: SchemaMeta,
        has_typed: bool,
        dynamic: Option<(&'static str, &'graph Value)>,
    ) -> SchemaNode {
        let (wrapper_meta, typed_meta) = meta.split_for_conjunction();
        let mut branches = Vec::new();
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            branches.push(self.parse_schema_ref(
                node.clone(),
                reference,
                minimal_conjunction_meta(&wrapper_meta.source),
            ));
        }
        if let Some((keyword, value)) = dynamic {
            branches.push(self.parse_dynamic_ref(
                node.clone(),
                keyword,
                value,
                minimal_conjunction_meta(&wrapper_meta.source),
            ));
        }
        if let Some(value) = object.get("allOf") {
            branches.extend(self.parse_schema_array(node.clone(), "allOf", value));
        }
        // The discriminator attaches to a single branch so its proof runs once. oneOf is the
        // conventional carrier, so when both applicators coexist only oneOf takes it; anyOf carries
        // it only in the absence of a oneOf piece.
        let has_one_of = object.contains_key("oneOf");
        if let Some(value) = object.get("oneOf") {
            branches.push(SchemaNode::OneOf {
                branches: self.parse_schema_array(node.clone(), "oneOf", value),
                discriminator: self
                    .parse_discriminator(node.clone(), object.get("discriminator"))
                    .map(Box::new),
                meta: minimal_conjunction_meta(&wrapper_meta.source),
            });
        }
        if let Some(value) = object.get("anyOf") {
            branches.push(SchemaNode::AnyOf {
                branches: self.parse_schema_array(node.clone(), "anyOf", value),
                discriminator: if has_one_of {
                    None
                } else {
                    self.parse_discriminator(node.clone(), object.get("discriminator"))
                        .map(Box::new)
                },
                meta: minimal_conjunction_meta(&wrapper_meta.source),
            });
        }
        if has_typed {
            let typed = if self.version == OasVersion::V3_1 && object.contains_key("prefixItems") {
                self.parse_tuple(node, object, typed_meta)
            } else {
                self.parse_typed_schema(node, object, typed_meta)
            };
            branches.push(typed);
        }
        SchemaNode::AllOf {
            branches,
            meta: wrapper_meta,
        }
    }

    /// Lowers `$dynamicRef` or `$recursiveRef` into an ordinary reference wherever the target is
    /// the same on every evaluation path, and refuses where it is not.
    ///
    /// Most of the work is deciding which of those two it is, and the loader already did it. What
    /// is left here is the one case the specs leave open: a `$recursiveRef: "#"` inside an OpenAPI
    /// document that declares no `$id` resolves to the document root, which is the OpenAPI Object
    /// and not a schema — "a reference target under a known keyword, for which the value is known
    /// not to be a schema, results in undefined behavior" (2020-12 §9.4.2). Rather than leave it
    /// undefined, re-target to the nearest enclosing `$recursiveAnchor: true`. That is what the
    /// keyword is written to mean, it is the only reading under which the document says anything,
    /// and no conforming extension of it is expressible anyway: `$recursiveRef` may only be `"#"`,
    /// which can address nothing but a resource root.
    fn parse_dynamic_ref(
        &mut self,
        node: NodeView<'graph>,
        keyword: &str,
        value: &Value,
        mut meta: SchemaMeta,
    ) -> SchemaNode {
        let keyword_pointer = append_pointer(&node.pointer, keyword);
        let Some(reference) = value.as_str() else {
            self.shape_error(
                node.doc_id,
                &keyword_pointer,
                format!("{keyword} must be a string"),
            );
            return SchemaNode::Unknown {
                reason: format!("{keyword} is not a string"),
                meta,
            };
        };
        let resolution = if keyword == "$recursiveRef" {
            if reference != "#" {
                self.sink.push(self.input_diagnostic(
                    CODE_RECURSIVE_REF_VALUE,
                    node.doc_id,
                    &keyword_pointer,
                    format!("$recursiveRef is defined only for the value '#', not '{reference}'"),
                ));
                return SchemaNode::Unknown {
                    reason: format!("unsupported $recursiveRef value {reference}"),
                    meta,
                };
            }
            self.graph.resolve_recursive_ref(node.doc_id, &node.pointer)
        } else {
            self.graph
                .resolve_dynamic_ref(node.doc_id, &node.pointer, reference)
        };
        match resolution {
            Ok(DynamicResolution::Pinned(target)) => {
                self.schema_ref_node(target.doc_id, target.json_pointer, meta)
            }
            // Bookending failed, so the keyword is identical to `$ref` and takes the same path.
            Ok(DynamicResolution::Plain) => self.parse_schema_ref(node, reference, meta),
            Ok(DynamicResolution::NonSchemaRoot) => match self.enclosing_recursive_anchor(&node) {
                Some(pointer) => self.schema_ref_node(node.doc_id, pointer, meta),
                None => {
                    self.sink.push(self.input_diagnostic(
                        CODE_REFERENCE,
                        node.doc_id,
                        &keyword_pointer,
                        "$recursiveRef resolves to the OpenAPI Object, which is not a schema, \
                             and no enclosing schema declares '$recursiveAnchor: true'",
                    ));
                    SchemaNode::Unknown {
                        reason: "unresolved $recursiveRef".to_owned(),
                        meta,
                    }
                }
            },
            Ok(DynamicResolution::PathDependent {
                declaring_resources,
            }) => {
                self.sink.push(self.warning_diagnostic(
                    CODE_DYNAMIC_SCOPE,
                    node.doc_id,
                    &keyword_pointer,
                    format!(
                        "{keyword} target depends on the evaluation path because \
                         {declaring_resources} schema resources declare the anchor it names; \
                         widened to unknown"
                    ),
                ));
                // The types artifact may keep the approximation with its warning; the validators
                // artifact may not, and this is what makes it refuse.
                meta.rejected_validation_keywords.push(keyword.to_owned());
                SchemaNode::Unknown {
                    reason: format!("path-dependent {keyword}"),
                    meta,
                }
            }
            Err(diagnostic) => {
                self.sink.push(diagnostic);
                self.sink.push(self.input_diagnostic(
                    CODE_REFERENCE,
                    node.doc_id,
                    &keyword_pointer,
                    format!("schema reference '{reference}' could not be resolved"),
                ));
                SchemaNode::Unknown {
                    reason: format!("unresolved reference {reference}"),
                    meta,
                }
            }
        }
    }

    /// Finds the nearest schema object enclosing `node` — `node` itself included — that carries
    /// `$recursiveAnchor: true`.
    fn enclosing_recursive_anchor(&self, node: &NodeView<'graph>) -> Option<String> {
        let mut pointer = node.pointer.as_str();
        loop {
            let anchored = self
                .graph
                .node_at(node.doc_id, pointer)
                .and_then(|found| found.value.get("$recursiveAnchor").and_then(Value::as_bool))
                .unwrap_or(false);
            if anchored {
                return Some(pointer.to_owned());
            }
            let cut = pointer.rfind('/')?;
            pointer = &pointer[..cut];
        }
    }

    fn schema_ref_node(
        &mut self,
        doc_id: DocId,
        json_pointer: String,
        meta: SchemaMeta,
    ) -> SchemaNode {
        if doc_id == self.graph.entry().id && !is_root_component_pointer(&json_pointer) {
            self.entry_defs_referenced = true;
        }
        SchemaNode::Ref {
            target: SchemaRef {
                source_id: self.source_id(doc_id).to_owned(),
                json_pointer,
            },
            meta,
        }
    }

    fn parse_schema_ref(
        &mut self,
        node: NodeView<'graph>,
        reference: &str,
        meta: SchemaMeta,
    ) -> SchemaNode {
        match self
            .graph
            .resolve_from(node.doc_id, &node.pointer, reference)
        {
            Ok(target) => self.schema_ref_node(target.doc_id, target.json_pointer, meta),
            Err(diagnostic) => {
                self.sink.push(diagnostic);
                self.sink.push(
                    Diagnostic::input(
                        CODE_REFERENCE,
                        format!("schema reference '{reference}' could not be resolved"),
                    )
                    .with_source(self.source_id(node.doc_id))
                    .with_json_pointer(&node.pointer),
                );
                SchemaNode::Unknown {
                    reason: format!("unresolved reference {reference}"),
                    meta,
                }
            }
        }
    }

    fn parse_schema_array(
        &mut self,
        parent: NodeView<'graph>,
        key: &str,
        value: &'graph Value,
    ) -> Vec<SchemaNode> {
        let pointer = append_pointer(&parent.pointer, key);
        let Some(values) = value.as_array() else {
            self.shape_error(parent.doc_id, &pointer, format!("{key} must be an array"));
            return Vec::new();
        };
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let child = append_pointer_index(&pointer, index);
                self.parse_schema(NodeView {
                    doc_id: parent.doc_id,
                    pointer: child,
                    value,
                })
            })
            .collect()
    }

    fn parse_discriminator(
        &mut self,
        parent: NodeView<'graph>,
        value: Option<&'graph Value>,
    ) -> Option<Discriminator> {
        let value = value?;
        let pointer = append_pointer(&parent.pointer, "discriminator");
        let object = value.as_object()?;
        let property_name = object.get("propertyName")?.as_str()?.to_owned();
        let mut mapping = Vec::new();
        if let Some(entries) = object.get("mapping").and_then(Value::as_object) {
            for (key, value) in entries {
                match value.as_str() {
                    Some(value) => mapping.push((key.clone(), value.to_owned())),
                    // Dropped either way; the discriminator never shapes the union. Diagnosing it
                    // keeps a malformed value from being quieter than a dangling one (OASTS1308).
                    None => self.sink.push(self.warning_diagnostic(
                        CODE_MAPPING_VALUE_SHAPE,
                        parent.doc_id,
                        &pointer,
                        format!(
                            "discriminator mapping value for '{key}' is not a string; the entry is dropped and contributes no tag"
                        ),
                    )),
                }
            }
        }
        Some(Discriminator {
            property_name,
            mapping,
            source: self.source(parent.doc_id, &pointer),
        })
    }

    fn parse_typed_schema(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        mut meta: SchemaMeta,
    ) -> SchemaNode {
        if self.version == OasVersion::V3_1
            && let Some(types) = object.get("type").and_then(Value::as_array)
        {
            let mut names = Vec::new();
            let finite = ParsedFinite::from_object(object, self.version);
            let mut domains = finite.declared.then(Vec::new);
            for value in types {
                let Some(name) = value.as_str() else {
                    return self.unsupported_schema(
                        node.doc_id,
                        &node.pointer,
                        "schema type arrays must contain strings",
                    );
                };
                match (domains.as_mut(), DeclaredType::from_name(name)) {
                    (Some(domains), Some(domain)) => domains.push(domain),
                    (_, None) => domains = None,
                    (None, Some(_)) => {}
                }
                if name == "null" {
                    meta.nullable = true;
                } else {
                    names.push(name);
                }
            }
            let filtered = match (domains, finite.declared) {
                (Some(domains), true) => {
                    let display = types
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" | ");
                    self.filter_finite_values(&node, finite, &domains, &display, false, &mut meta)
                }
                (Some(_), false) | (None, _) => DomainFilter {
                    finite,
                    unsatisfiable: false,
                },
            };
            if meta.nullable {
                meta.nullable = finite_constraints_admit(&filtered.finite, PrimitiveType::Null);
            }
            if filtered.unsatisfiable {
                meta.nullable = false;
                return SchemaNode::Never { meta };
            }
            if names.is_empty() {
                meta.nullable = false;
                return self.parse_type_name(node, object, "null", filtered.finite, meta);
            }
            if names.len() == 1 {
                return self.parse_type_name(node, object, names[0], filtered.finite, meta);
            }
            let branches = names
                .into_iter()
                .filter_map(|name| {
                    let branch_meta = SchemaMeta {
                        source: meta.source.clone(),
                        numeric_constraints: meta.numeric_constraints.clone(),
                        string_constraints: meta.string_constraints.clone(),
                        array_constraints: meta.array_constraints.clone(),
                        object_constraints: meta.object_constraints.clone(),
                        ..SchemaMeta::default()
                    };
                    let ty = match name {
                        "string" => PrimitiveType::String,
                        "number" => PrimitiveType::Number,
                        "integer" => PrimitiveType::Integer,
                        "boolean" => PrimitiveType::Boolean,
                        _ => {
                            self.sink.push(self.unsupported_diagnostic(
                                node.doc_id,
                                &append_pointer(&node.pointer, "type"),
                                format!(
                                    "non-primitive type '{name}' in a type array becomes unknown"
                                ),
                            ));
                            return Some(SchemaNode::Unknown {
                                reason: format!("non-primitive type '{name}' in a type array"),
                                meta: branch_meta,
                            });
                        }
                    };
                    let finite = filtered.finite.for_primitive(ty)?;
                    Some(self.parse_primitive(object, ty, finite, branch_meta))
                })
                .collect();
            return SchemaNode::AnyOf {
                branches,
                discriminator: None,
                meta,
            };
        }
        if let Some(ty) = object.get("type").and_then(Value::as_str) {
            let finite = ParsedFinite::from_object(object, self.version);
            let Some(domain) = DeclaredType::from_name(ty) else {
                return self.parse_type_name(node, object, ty, finite, meta);
            };
            let nullable = self.version == OasVersion::V3_0
                && object
                    .get("nullable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let filtered =
                self.filter_finite_values(&node, finite, &[domain], ty, nullable, &mut meta);
            if filtered.unsatisfiable {
                let mut never_meta = meta.clone();
                never_meta.nullable = false;
                let _discarded = self.parse_type_name(node, object, ty, filtered.finite, meta);
                return SchemaNode::Never { meta: never_meta };
            }
            return self.parse_type_name(node, object, ty, filtered.finite, meta);
        }
        let finite = ParsedFinite::from_object(object, self.version);
        if object.contains_key("properties")
            || object.contains_key("additionalProperties")
            || (self.version == OasVersion::V3_1 && object.contains_key("dependentRequired"))
        {
            return self.parse_object(node, object, finite, meta);
        }
        if object.contains_key("items") {
            return self.parse_array(node, object, finite, meta);
        }
        if object.contains_key("enum") || object.contains_key("const") {
            return SchemaNode::Finite {
                enum_values: finite.enum_values,
                const_value: finite.const_value,
                meta,
            };
        }
        SchemaNode::Any { meta }
    }

    fn filter_finite_values(
        &mut self,
        node: &NodeView<'graph>,
        mut finite: ParsedFinite,
        domains: &[DeclaredType],
        declared_type: &str,
        nullable: bool,
        meta: &mut SchemaMeta,
    ) -> DomainFilter {
        let track_extension_indices = meta.enum_extensions.is_some();
        let mut retained_indices: Option<Vec<usize>> = None;
        let mut original_enum_len = None;
        let mut enum_became_empty = false;
        if let Some(mut values) = finite.enum_values.take() {
            let original_len = values.len();
            original_enum_len = Some(original_len);
            let mut index = 0;
            values.retain(|value| {
                let retained = value_in_declared_domain(value, domains, nullable);
                if retained {
                    if let Some(indices) = &mut retained_indices {
                        indices.push(index);
                    }
                } else {
                    if track_extension_indices && retained_indices.is_none() {
                        retained_indices = Some((0..index).collect());
                    }
                    self.sink.push(self.warning_diagnostic(
                        CODE_ENUM_RULE_14,
                        node.doc_id,
                        &node.pointer,
                        format!(
                            "enum member {} is outside declared type {declared_type} and can never validate; it is dropped from the generated type and validator",
                            compact_json(value)
                        ),
                    ));
                }
                index += 1;
                retained
            });
            enum_became_empty = original_len > 0 && values.is_empty();
            finite.enum_values = Some(values);
            if enum_became_empty {
                self.sink.push(self.warning_diagnostic(
                    CODE_ENUM_RULE_14,
                    node.doc_id,
                    &node.pointer,
                    format!(
                        "all enum members are outside declared type {declared_type}; the schema admits no value and is lowered to never"
                    ),
                ));
            }
        }

        let const_outside = finite
            .const_value
            .as_ref()
            .is_some_and(|value| !value_in_declared_domain(value, domains, nullable));
        if const_outside && let Some(value) = finite.const_value.take() {
            self.sink.push(self.warning_diagnostic(
                CODE_ENUM_RULE_14,
                node.doc_id,
                &node.pointer,
                format!(
                    "const value {} is outside declared type {declared_type} and can never validate; the schema admits no value and is lowered to never",
                    compact_json(&value)
                ),
            ));
        }

        let unsatisfiable = enum_became_empty || const_outside;
        if unsatisfiable && track_extension_indices && original_enum_len.is_some() {
            retained_indices = Some(Vec::new());
        }
        if let (Some(original_len), Some(indices)) = (original_enum_len, retained_indices) {
            retain_enum_extensions(meta, original_len, &indices);
        }
        DomainFilter {
            finite,
            unsatisfiable,
        }
    }

    fn parse_type_name(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        ty: &str,
        finite: ParsedFinite,
        meta: SchemaMeta,
    ) -> SchemaNode {
        match ty {
            "string" => self.parse_primitive(object, PrimitiveType::String, finite, meta),
            "number" => self.parse_primitive(object, PrimitiveType::Number, finite, meta),
            "integer" => self.parse_primitive(object, PrimitiveType::Integer, finite, meta),
            "boolean" => self.parse_primitive(object, PrimitiveType::Boolean, finite, meta),
            "null" if self.version == OasVersion::V3_1 => {
                self.parse_primitive(object, PrimitiveType::Null, finite, meta)
            }
            "object" => self.parse_object(node, object, finite, meta),
            "array" => self.parse_array(node, object, finite, meta),
            _ => {
                self.sink.push(self.unsupported_diagnostic(
                    node.doc_id,
                    &append_pointer(&node.pointer, "type"),
                    format!("unsupported schema type '{ty}' becomes unknown"),
                ));
                SchemaNode::Unknown {
                    reason: format!("unsupported type {ty}"),
                    meta,
                }
            }
        }
    }

    fn parse_primitive(
        &self,
        object: &Map<String, Value>,
        ty: PrimitiveType,
        finite: ParsedFinite,
        meta: SchemaMeta,
    ) -> SchemaNode {
        SchemaNode::Primitive {
            ty,
            format: object
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned),
            enum_values: finite.enum_values,
            const_value: finite.const_value,
            meta,
        }
    }

    /// The `enum`/`const` finite constraint carried by object/array/tuple schemas, `None` when the
    /// object declares neither. `const` is read only in OpenAPI 3.1 (3.0 has no `const` keyword).
    fn parse_finite_constraint(&self, finite: ParsedFinite) -> Option<Box<FiniteConstraint>> {
        finite.declared.then(|| {
            Box::new(FiniteConstraint {
                enum_values: finite.enum_values,
                const_value: finite.const_value,
            })
        })
    }

    fn parse_object(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        finite: ParsedFinite,
        meta: SchemaMeta,
    ) -> SchemaNode {
        let finite = self.parse_finite_constraint(finite);
        let required_values = object
            .get("required")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let required = required_values
            .iter()
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>();
        let raw_properties = object.get("properties").and_then(Value::as_object);
        let properties = raw_properties
            .map(|properties| {
                let properties_pointer = append_pointer(&node.pointer, "properties");
                properties
                    .iter()
                    .map(|(name, value)| {
                        let pointer = append_pointer(&properties_pointer, name);
                        let schema = self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer,
                            value,
                        });
                        let prop_meta = PropMeta {
                            required: required.contains(name.as_str()),
                            read_only: value
                                .get("readOnly")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            write_only: value
                                .get("writeOnly")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        };
                        (name.clone(), schema, prop_meta)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut seen_required = HashSet::new();
        let mut extra_required = Vec::new();
        let required_pointer = append_pointer(&node.pointer, "required");
        for name in required_values.iter().filter_map(Value::as_str) {
            if seen_required.insert(name)
                && raw_properties.is_none_or(|properties| !properties.contains_key(name))
            {
                self.sink.push(self.warning_diagnostic(
                    CODE_PHANTOM_REQUIRED,
                    node.doc_id,
                    &required_pointer,
                    format!("required lists property '{name}' that is not defined in properties"),
                ));
                extra_required.push(name.to_owned());
            }
        }
        let additional_properties = match object.get("additionalProperties") {
            None | Some(Value::Bool(true)) => AdditionalProperties::Allowed(None),
            Some(Value::Bool(false)) => AdditionalProperties::Forbidden,
            Some(value) => {
                let pointer = append_pointer(&node.pointer, "additionalProperties");
                AdditionalProperties::Schema(Box::new(self.parse_schema(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })))
            }
        };
        let dependent_required = if self.version == OasVersion::V3_1 {
            collect_dependent_required(object)
        } else {
            Vec::new()
        };
        SchemaNode::Object {
            properties,
            additional_properties,
            dependent_required,
            finite,
            extra_required,
            meta,
        }
    }

    fn parse_array(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        finite: ParsedFinite,
        meta: SchemaMeta,
    ) -> SchemaNode {
        let finite = self.parse_finite_constraint(finite);
        let pointer = append_pointer(&node.pointer, "items");
        let items = match object.get("items") {
            None => SchemaNode::Any {
                meta: SchemaMeta {
                    source: self.source(node.doc_id, &pointer),
                    ..SchemaMeta::default()
                },
            },
            Some(items) => self.parse_schema(NodeView {
                doc_id: node.doc_id,
                pointer,
                value: items,
            }),
        };
        SchemaNode::Array {
            items: Box::new(items),
            finite,
            meta,
        }
    }

    fn parse_tuple(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        mut meta: SchemaMeta,
    ) -> SchemaNode {
        let finite = ParsedFinite::from_object(object, self.version);
        let filtered = if finite.declared {
            match declared_value_domain(object) {
                // `nullable` cannot reach here: a tuple is only parsed under OpenAPI 3.1, where
                // nullability is a `null` member of the type array rather than a sibling keyword.
                Some((domains, display)) => {
                    self.filter_finite_values(&node, finite, &domains, &display, false, &mut meta)
                }
                None => DomainFilter {
                    finite,
                    unsatisfiable: false,
                },
            }
        } else {
            DomainFilter {
                finite,
                unsatisfiable: false,
            }
        };
        if self.version == OasVersion::V3_1
            && object
                .get("type")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("null")))
        {
            meta.nullable = finite_constraints_admit(&filtered.finite, PrimitiveType::Null);
        }
        if filtered.unsatisfiable {
            meta.nullable = false;
        }
        let never_meta = filtered.unsatisfiable.then(|| meta.clone());
        let finite = self.parse_finite_constraint(filtered.finite);
        let prefix_pointer = append_pointer(&node.pointer, "prefixItems");
        let prefix_items = object
            .get("prefixItems")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        let pointer = append_pointer_index(&prefix_pointer, index);
                        self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer,
                            value: item,
                        })
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                self.shape_error(node.doc_id, &prefix_pointer, "prefixItems must be an array");
                Vec::new()
            });
        let rest = match object.get("items") {
            None | Some(Value::Bool(true)) => TupleRest::Allowed,
            Some(Value::Bool(false)) => TupleRest::Forbidden,
            Some(value) => {
                let pointer = append_pointer(&node.pointer, "items");
                TupleRest::Schema(Box::new(self.parse_schema(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })))
            }
        };
        let schema = SchemaNode::Tuple {
            prefix_items,
            rest,
            finite,
            meta,
        };
        match never_meta {
            Some(meta) => SchemaNode::Never { meta },
            None => schema,
        }
    }

    fn schema_meta(
        &mut self,
        node: &NodeView<'graph>,
        object: Option<&'graph Map<String, Value>>,
    ) -> SchemaMeta {
        let Some(object) = object else {
            return SchemaMeta {
                source: self.source(node.doc_id, &node.pointer),
                ..SchemaMeta::default()
            };
        };
        let content = schema_meta_content(object);
        if content == SchemaMetaContent::None {
            return SchemaMeta {
                source: self.source(node.doc_id, &node.pointer),
                ..SchemaMeta::default()
            };
        }
        let examples = match self.version {
            OasVersion::V3_0 => object.get("example").cloned().into_iter().collect(),
            OasVersion::V3_1 => match object.get("examples") {
                None => Vec::new(),
                Some(Value::Array(values)) => values.clone(),
                Some(_) => {
                    self.shape_error(
                        node.doc_id,
                        &append_pointer(&node.pointer, "examples"),
                        "schema examples must be an array in OpenAPI 3.1",
                    );
                    Vec::new()
                }
            },
        };
        let mut meta = SchemaMeta {
            nullable: self.version == OasVersion::V3_0
                && object
                    .get("nullable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            additional_properties_present: object.contains_key("additionalProperties"),
            items_present: object.contains_key("items"),
            read_only: object
                .get("readOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            write_only: object
                .get("writeOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            content_encoding: (self.version == OasVersion::V3_1)
                .then(|| string_field(object, "contentEncoding"))
                .flatten(),
            docs: SchemaDocs {
                title: string_field(object, "title"),
                description: string_field(object, "description"),
                deprecated: bool_field(object, "deprecated"),
                default: object.get("default").cloned(),
                examples,
                comment: string_field(object, "$comment"),
                constraints: Vec::new(),
            },
            enum_extensions: box_if_populated(EnumExtensionData {
                enum_varnames: object.get("x-enum-varnames").cloned(),
                enum_names: object.get("x-enumNames").cloned(),
                enum_descriptions: object.get("x-enum-descriptions").cloned(),
                enum_descriptions_camel: object.get("x-enumDescriptions").cloned(),
            }),
            source: self.source(node.doc_id, &node.pointer),
            ..SchemaMeta::default()
        };
        if content == SchemaMetaContent::Annotations {
            return meta;
        }
        let numeric_constraints = collect_numeric_constraints(object, self.version);
        // `collect_numeric_constraints` already dropped an invalid `multipleOf` (non-number, ≤ 0, or
        // outside the binary64 domain) from `multiple_of`, so a present keyword with no surviving
        // value is exactly the invalid case — diagnose it without re-deriving validity here.
        if object.contains_key("multipleOf") && numeric_constraints.multiple_of.is_none() {
            self.sink.push(
                Diagnostic::input(
                    CODE_MULTIPLE_OF,
                    "multipleOf must be a positive number within the binary64 domain",
                )
                .with_source(self.source_id(node.doc_id))
                .with_json_pointer(append_pointer(&node.pointer, "multipleOf")),
            );
        }
        let string_constraints = collect_string_constraints(object);
        let array_constraints = collect_array_constraints(object);
        let object_constraints = collect_object_constraints(object);
        meta.docs.constraints = collect_constraints(object, &numeric_constraints);
        let validation_applicators = if self.version == OasVersion::V3_0
            && object.contains_key("$ref")
        {
            ValidationApplicators::default()
        } else {
            let mut pattern_properties = Vec::new();
            if self.version == OasVersion::V3_1
                && let Some(value) = object.get("patternProperties")
            {
                let pointer = append_pointer(&node.pointer, "patternProperties");
                if let Some(patterns) = value.as_object() {
                    let schema_valued_additional = object
                        .get("additionalProperties")
                        .is_some_and(|value| !value.is_boolean());
                    for (pattern, value) in patterns {
                        let type_key = (!schema_valued_additional)
                            .then(|| pattern_property_type_key(pattern))
                            .flatten();
                        if type_key.is_none() {
                            self.sink.push(self.unsupported_diagnostic(
                                    node.doc_id,
                                    &append_pointer(&pointer, pattern),
                                    format!(
                                        "patternProperties regex '{pattern}' has no faithful TypeScript index-signature representation and becomes unknown on the types surface"
                                    ),
                                ));
                        }
                        pattern_properties.push(PatternProperty {
                            pattern: pattern.clone(),
                            schema: self.parse_schema(NodeView {
                                doc_id: node.doc_id,
                                pointer: append_pointer(&pointer, pattern),
                                value,
                            }),
                            type_key,
                        });
                    }
                    pattern_properties.sort_unstable_by(|left, right| {
                        left.pattern.as_bytes().cmp(right.pattern.as_bytes())
                    });
                } else {
                    self.shape_error(node.doc_id, &pointer, "patternProperties must be an object");
                }
            }
            let min_contains = if self.version == OasVersion::V3_1 {
                object.get("minContains").and_then(|value| {
                    value.as_u64().or_else(|| {
                        self.shape_error(
                            node.doc_id,
                            &append_pointer(&node.pointer, "minContains"),
                            "minContains must be a non-negative integer",
                        );
                        None
                    })
                })
            } else {
                None
            };
            let max_contains = if self.version == OasVersion::V3_1 {
                object.get("maxContains").and_then(|value| {
                    value.as_u64().or_else(|| {
                        self.shape_error(
                            node.doc_id,
                            &append_pointer(&node.pointer, "maxContains"),
                            "maxContains must be a non-negative integer",
                        );
                        None
                    })
                })
            } else {
                None
            };
            let contains = (self.version == OasVersion::V3_1)
                .then(|| object.get("contains"))
                .flatten()
                .map(|value| {
                    Box::new(ContainsApplicator {
                        schema: Box::new(self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: append_pointer(&node.pointer, "contains"),
                            value,
                        })),
                        min_contains,
                        max_contains,
                    })
                });
            let mut dependent_schemas = Vec::new();
            if self.version == OasVersion::V3_1
                && let Some(value) = object.get("dependentSchemas")
            {
                let pointer = append_pointer(&node.pointer, "dependentSchemas");
                if let Some(dependencies) = value.as_object() {
                    dependent_schemas = dependencies
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.clone(),
                                self.parse_schema(NodeView {
                                    doc_id: node.doc_id,
                                    pointer: append_pointer(&pointer, name),
                                    value,
                                }),
                            )
                        })
                        .collect();
                } else {
                    self.shape_error(node.doc_id, &pointer, "dependentSchemas must be an object");
                }
            }
            let conditional = (self.version == OasVersion::V3_1)
                .then(|| object.get("if"))
                .flatten()
                .map(|value| {
                    Box::new(ConditionalApplicator {
                        condition: Box::new(self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: append_pointer(&node.pointer, "if"),
                            value,
                        })),
                        then_schema: object.get("then").map(|value| {
                            Box::new(self.parse_schema(NodeView {
                                doc_id: node.doc_id,
                                pointer: append_pointer(&node.pointer, "then"),
                                value,
                            }))
                        }),
                        else_schema: object.get("else").map(|value| {
                            Box::new(self.parse_schema(NodeView {
                                doc_id: node.doc_id,
                                pointer: append_pointer(&node.pointer, "else"),
                                value,
                            }))
                        }),
                    })
                });
            ValidationApplicators {
                not: object.get("not").map(|value| {
                    Box::new(self.parse_schema(NodeView {
                        doc_id: node.doc_id,
                        pointer: append_pointer(&node.pointer, "not"),
                        value,
                    }))
                }),
                property_names: (self.version == OasVersion::V3_1)
                    .then(|| object.get("propertyNames"))
                    .flatten()
                    .map(|value| {
                        Box::new(self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: append_pointer(&node.pointer, "propertyNames"),
                            value,
                        }))
                    }),
                pattern_properties,
                contains,
                dependent_schemas,
                conditional,
                unevaluated_properties: (self.version == OasVersion::V3_1)
                    .then(|| object.get("unevaluatedProperties"))
                    .flatten()
                    .map(|value| {
                        Box::new(self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: append_pointer(&node.pointer, "unevaluatedProperties"),
                            value,
                        }))
                    }),
                unevaluated_items: (self.version == OasVersion::V3_1)
                    .then(|| object.get("unevaluatedItems"))
                    .flatten()
                    .map(|value| {
                        Box::new(self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: append_pointer(&node.pointer, "unevaluatedItems"),
                            value,
                        }))
                    }),
            }
        };
        meta.numeric_constraints = box_if_populated(numeric_constraints);
        meta.string_constraints = box_if_populated(string_constraints);
        meta.array_constraints = box_if_populated(array_constraints);
        meta.object_constraints = box_if_populated(object_constraints);
        meta.validation_applicators = box_if_populated(validation_applicators);
        // A dynamic reference is rejected only where it could not be pinned; `parse_dynamic_ref`
        // adds it then. Under 3.0 it is not a keyword, so it is rejected outright.
        meta.rejected_validation_keywords = object
            .keys()
            .filter(|key| {
                self.version == OasVersion::V3_0
                    && (DYNAMIC_REF_KEYWORDS.contains(&key.as_str())
                        || matches!(
                            key.as_str(),
                            "propertyNames"
                                | "patternProperties"
                                | "contains"
                                | "minContains"
                                | "maxContains"
                                | "dependentSchemas"
                                | "if"
                                | "then"
                                | "else"
                                | "unevaluatedProperties"
                                | "unevaluatedItems"
                                | "additionalItems"
                        ))
            })
            .cloned()
            .collect();
        meta
    }

    fn resolve_object(&mut self, node: NodeView<'graph>, kind: &str) -> Option<NodeView<'graph>> {
        let object = node.value.as_object().or_else(|| {
            self.shape_error(
                node.doc_id,
                &node.pointer,
                format!("{kind} must be an object"),
            );
            None
        })?;
        let Some(reference) = object.get("$ref").and_then(Value::as_str) else {
            return Some(node);
        };
        match self.graph.resolve(node.doc_id, reference) {
            Ok(target)
                if target
                    .value
                    .as_object()
                    .and_then(|object| object.get("$ref"))
                    .and_then(Value::as_str)
                    .is_none() =>
            {
                return Some(NodeView {
                    doc_id: target.doc_id,
                    pointer: target.json_pointer,
                    value: target.value,
                });
            }
            Ok(_) => {}
            Err(diagnostic) => {
                self.sink.push(diagnostic);
                return None;
            }
        }
        let source_id = self.source_id(node.doc_id).to_owned();
        let pointer = node.pointer.clone();
        let result = follow_ref_chain(node, self.graph.max_ref_depth(), &mut |current| {
            let Some(reference) = current
                .value
                .as_object()
                .and_then(|object| object.get("$ref"))
                .and_then(Value::as_str)
            else {
                return RefChainStep::Done;
            };
            match self.graph.resolve(current.doc_id, reference) {
                Ok(target) => RefChainStep::Next {
                    member: RefChainMember {
                        doc_index: target.doc_id.index(),
                        pointer: target.json_pointer.clone(),
                    },
                    node: NodeView {
                        doc_id: target.doc_id,
                        pointer: target.json_pointer,
                        value: target.value,
                    },
                },
                Err(diagnostic) => RefChainStep::Fail(Box::new(diagnostic)),
            }
        });
        match result {
            Ok(node) => Some(node),
            Err(error) => {
                self.sink.push(ref_chain_failure_diagnostic(
                    kind,
                    self.graph.max_ref_depth(),
                    &source_id,
                    &pointer,
                    error,
                ));
                None
            }
        }
    }

    fn validate_path_parameters(
        &mut self,
        raw_path: &str,
        template: &[Segment],
        parameters: &[Param],
        node: &NodeView<'graph>,
    ) {
        let template_names = template
            .iter()
            .flat_map(|segment| segment.parts.iter())
            .filter_map(|part| match part {
                SegmentPart::Param(name) => Some(name.as_str()),
                SegmentPart::Literal(_) => None,
            })
            .collect::<HashSet<_>>();
        let declared_names = parameters
            .iter()
            .filter(|parameter| parameter.location == ParamLocation::Path)
            .map(|parameter| parameter.name.as_str())
            .collect::<HashSet<_>>();
        // Diagnostic order is observable output, and a `HashSet` iterates in an order that
        // depends on its hasher's per-instance seed — so emitting straight from `difference`
        // makes the sequence within one path vary run to run. Sort both differences first.
        let mut undeclared = template_names
            .difference(&declared_names)
            .copied()
            .collect::<Vec<_>>();
        undeclared.sort_unstable();
        for name in undeclared {
            self.path_parameter_error(
                node,
                format!("path '{raw_path}' template parameter '{name}' is not declared"),
            );
        }
        let mut absent = declared_names
            .difference(&template_names)
            .copied()
            .collect::<Vec<_>>();
        absent.sort_unstable();
        for name in absent {
            self.path_parameter_error(
                node,
                format!("path parameter '{name}' is declared but absent from '{raw_path}'"),
            );
        }
    }

    fn path_parameter_error(&mut self, node: &NodeView<'graph>, message: String) {
        self.sink.push(
            Diagnostic::input(CODE_PATH_PARAMETER, message)
                .with_source(self.source_id(node.doc_id))
                .with_json_pointer(&node.pointer),
        );
    }

    fn unsupported_schema(&mut self, doc_id: DocId, pointer: &str, reason: &str) -> SchemaNode {
        self.sink.push(self.unsupported_diagnostic(
            doc_id,
            pointer,
            format!("unsupported schema construct: {reason}; using unknown"),
        ));
        SchemaNode::Unknown {
            reason: reason.to_owned(),
            meta: SchemaMeta {
                source: self.source(doc_id, pointer),
                ..SchemaMeta::default()
            },
        }
    }

    fn shape_error(&mut self, doc_id: DocId, pointer: &str, message: impl Into<String>) {
        self.sink.push(
            Diagnostic::input(CODE_SHAPE, message)
                .with_source(self.source_id(doc_id))
                .with_json_pointer(pointer),
        );
    }

    fn input_diagnostic(
        &self,
        code: &'static str,
        doc_id: DocId,
        pointer: &str,
        message: impl Into<String>,
    ) -> Diagnostic {
        let source = self.source(doc_id, pointer);
        Diagnostic::input(code, message)
            .with_source(&source.source_id)
            .with_json_pointer(&source.json_pointer)
    }

    /// An input diagnostic downgraded to warning severity. Warnings report
    /// unsupported-but-tolerated constructs that drop out of generation without
    /// failing it; the severity downgrade lives here so every such site is identical.
    fn warning_diagnostic(
        &self,
        code: &'static str,
        doc_id: DocId,
        pointer: &str,
        message: impl Into<String>,
    ) -> Diagnostic {
        let mut diagnostic = self.input_diagnostic(code, doc_id, pointer, message);
        diagnostic.severity = Severity::Warning;
        diagnostic
    }

    fn unsupported_diagnostic(
        &self,
        doc_id: DocId,
        pointer: &str,
        message: impl Into<String>,
    ) -> Diagnostic {
        self.warning_diagnostic(CODE_UNSUPPORTED, doc_id, pointer, message)
    }

    fn source(&self, doc_id: DocId, pointer: &str) -> SourceRef {
        SourceRef::new(self.source_id(doc_id), pointer)
    }

    fn source_id(&self, doc_id: DocId) -> &str {
        self.graph
            .document(doc_id)
            .expect("parser node IDs originate from the document graph")
            .source_id
            .as_str()
    }
}

/// Why a collected target names a schema, which decides whether it is guaranteed to resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefOrigin {
    /// A `$ref`. The loader resolved and validated every one of these before parsing began.
    Reference,
    /// A discriminator `mapping` value. The loader never sees these, so the target may name
    /// nothing at all — real documents ship mappings that point into thin air.
    DiscriminatorMapping,
}

/// Collects every `$ref` target reachable inside one schema tree.
pub(crate) fn collect_schema_refs(schema: &SchemaNode, out: &mut Vec<(SchemaRef, RefOrigin)>) {
    match schema {
        SchemaNode::Ref { target, .. } => out.push((target.clone(), RefOrigin::Reference)),
        SchemaNode::Object {
            properties,
            additional_properties,
            ..
        } => {
            for (_, property, _) in properties {
                collect_schema_refs(property, out);
            }
            match additional_properties {
                AdditionalProperties::Schema(schema) => collect_schema_refs(schema, out),
                AdditionalProperties::Allowed(inner) => {
                    // The parser never builds Allowed(Some(..)) — that shape only appears
                    // in post-parse merge results, after this collection pass has run.
                    debug_assert!(inner.is_none(), "parse-stage Allowed carries no schema");
                }
                AdditionalProperties::Forbidden => {}
            }
        }
        SchemaNode::Array { items, .. } => collect_schema_refs(items, out),
        SchemaNode::Tuple {
            prefix_items, rest, ..
        } => {
            for item in prefix_items {
                collect_schema_refs(item, out);
            }
            if let TupleRest::Schema(schema) = rest {
                collect_schema_refs(schema, out);
            }
        }
        SchemaNode::AllOf { branches, .. } => {
            for branch in branches {
                collect_schema_refs(branch, out);
            }
        }
        SchemaNode::AnyOf {
            branches,
            discriminator,
            ..
        }
        | SchemaNode::OneOf {
            branches,
            discriminator,
            ..
        } => {
            for branch in branches {
                collect_schema_refs(branch, out);
            }
            // A discriminator mapping names a component the branches need not `$ref` — it is a
            // reference in every sense that matters here, even though it is not spelled `$ref`.
            if let Some(discriminator) = discriminator {
                for (_, target) in &discriminator.mapping {
                    out.push((
                        mapping_schema_ref(&discriminator.source, target),
                        RefOrigin::DiscriminatorMapping,
                    ));
                }
            }
        }
        SchemaNode::Primitive { .. }
        | SchemaNode::Finite { .. }
        | SchemaNode::Any { .. }
        | SchemaNode::Never { .. }
        | SchemaNode::Unknown { .. } => {}
    }
    let applicators = schema.meta().validation_applicators();
    if let Some(schema) = &applicators.not {
        collect_schema_refs(schema, out);
    }
    if let Some(schema) = &applicators.property_names {
        collect_schema_refs(schema, out);
    }
    for pattern in &applicators.pattern_properties {
        collect_schema_refs(&pattern.schema, out);
    }
    if let Some(contains) = &applicators.contains {
        collect_schema_refs(&contains.schema, out);
    }
    for (_, schema) in &applicators.dependent_schemas {
        collect_schema_refs(schema, out);
    }
    if let Some(conditional) = &applicators.conditional {
        collect_schema_refs(&conditional.condition, out);
        if let Some(schema) = &conditional.then_schema {
            collect_schema_refs(schema, out);
        }
        if let Some(schema) = &conditional.else_schema {
            collect_schema_refs(schema, out);
        }
    }
    if let Some(schema) = &applicators.unevaluated_properties {
        collect_schema_refs(schema, out);
    }
    if let Some(schema) = &applicators.unevaluated_items {
        collect_schema_refs(schema, out);
    }
}

/// Collects `$ref` targets from the operation schemas that emission renders and
/// validates: parameters, request-body media types (including every request
/// encoding header schema), and response media types. Encoding headers are
/// emitted by the client but were previously not collected, so an external
/// `$ref` there silently degraded to `unknown` with no import or diagnostic.
pub(crate) fn collect_operation_refs(operation: &Operation, out: &mut Vec<(SchemaRef, RefOrigin)>) {
    for parameter in &operation.parameters {
        collect_schema_refs(&parameter.schema, out);
    }
    if let Some(body) = &operation.request_body {
        for media_type in &body.media_types {
            collect_schema_refs(&media_type.schema, out);
            for (_, encoding) in &media_type.encodings {
                for (_, header) in &encoding.headers {
                    collect_schema_refs(&header.schema, out);
                }
            }
        }
    }
    for response in &operation.responses {
        for media_type in &response.media_types {
            collect_schema_refs(&media_type.schema, out);
        }
        for (_, header) in &response.headers {
            collect_schema_refs(&header.schema, out);
        }
    }
    for callback in &operation.callbacks {
        for expression in &callback.expressions {
            for operation in &expression.operations {
                collect_operation_refs(operation, out);
            }
        }
    }
}

const SCHEMA_NAME_STRUCTURAL_SEGMENTS: [&str; 10] = [
    "schema",
    "items",
    "additionalProperties",
    "allOf",
    "anyOf",
    "oneOf",
    "prefixItems",
    "patternProperties",
    "contains",
    "dependentSchemas",
];

/// Names an external schema from its document stem or the named and structural context in its
/// defining pointer.
///
/// A document-root schema uses the referenced file's stem. For a non-root schema, container
/// segments and media types are omitted. Remaining segments are JSON-Pointer unescaped
/// (`~1` → `/`, `~0` → `~`), and structural roles have their first ASCII character uppercased
/// before the parts are joined with spaces.
fn external_schema_name(json_pointer: &str, document_stem: &str) -> String {
    if json_pointer.is_empty() {
        return document_stem.to_owned();
    }

    let segments = json_pointer
        .strip_prefix('/')
        .unwrap_or(json_pointer)
        .split('/')
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    let mut parts = Vec::new();
    let mut index = 0;
    while index < segments.len() {
        let segment = &segments[index];
        if (index == 0 && segment == "components") || (index == 1 && segments[0] == "components") {
            index += 1;
            continue;
        }
        // `content` introduces a Media Type map, and a media range always carries a `/`
        // (`application/json`, `*/*`). Testing the child rather than the keyword keeps a property
        // literally named `content` from swallowing its own child and losing the name.
        if segment == "content"
            && segments
                .get(index + 1)
                .is_some_and(|media| media.contains('/'))
        {
            index += 2;
            continue;
        }
        // A container keyword names nothing itself — its child does. No schema sits at a bare
        // container, so a container word in final position is a property name, not a container.
        if index + 1 < segments.len()
            && matches!(
                segment.as_str(),
                "$defs" | "definitions" | "properties" | "schema"
            )
        {
            index += 1;
            continue;
        }
        parts.push(
            if SCHEMA_NAME_STRUCTURAL_SEGMENTS.contains(&segment.as_str()) {
                uppercase_first_ascii(segment)
            } else {
                segment.clone()
            },
        );
        index += 1;
    }
    parts.join(" ")
}

fn uppercase_first_ascii(value: &str) -> String {
    format!("{}{}", value[..1].to_ascii_uppercase(), &value[1..])
}

fn merge_parameters(path_parameters: &[Param], operation_parameters: Vec<Param>) -> Vec<Param> {
    let overridden = operation_parameters
        .iter()
        .map(|parameter| (parameter.name.as_str(), parameter.location))
        .collect::<HashSet<_>>();
    let mut merged: Vec<Param> = path_parameters
        .iter()
        .filter(|parameter| !overridden.contains(&(parameter.name.as_str(), parameter.location)))
        .cloned()
        .collect();
    merged.extend(operation_parameters);
    merged
}

fn parse_path_template(path: &str) -> Vec<Segment> {
    if path == "/" {
        return Vec::new();
    }
    path.strip_prefix('/')
        .unwrap_or(path)
        .split('/')
        .map(|segment| {
            let mut parts = Vec::new();
            let mut rest = segment;
            while let Some(open) = rest.find('{') {
                if open > 0 {
                    parts.push(SegmentPart::Literal(rest[..open].to_owned()));
                }
                let after_open = &rest[open + 1..];
                let Some(close) = after_open.find('}') else {
                    parts.push(SegmentPart::Literal(rest[open..].to_owned()));
                    rest = "";
                    break;
                };
                let name = &after_open[..close];
                if !name.is_empty() {
                    parts.push(SegmentPart::Param(name.to_owned()));
                }
                rest = &after_open[close + 1..];
            }
            if !rest.is_empty() {
                parts.push(SegmentPart::Literal(rest.to_owned()));
            }
            Segment { parts }
        })
        .collect()
}

fn parse_response_status(value: &str) -> Option<ResponseStatus> {
    if value == "default" {
        return Some(ResponseStatus::Default);
    }
    let bytes = value.as_bytes();
    if bytes.len() == 3
        && matches!(bytes[0], b'1'..=b'5')
        && bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return Some(ResponseStatus::Exact(value.to_owned()));
    }
    if bytes.len() == 3 && matches!(bytes[0], b'1'..=b'5') && bytes[1..].eq_ignore_ascii_case(b"XX")
    {
        // Canonicalized here rather than tolerated downstream: the string reaches emitted MSW
        // matchers and the client's response-match keys verbatim, so a `4xx` that survived parse
        // would ship as a status range no response ever carries.
        return Some(ResponseStatus::Range(value.to_ascii_uppercase()));
    }
    None
}

fn finite_constraints_admit(finite: &ParsedFinite, ty: PrimitiveType) -> bool {
    let enum_admits = finite.enum_values.as_deref().is_none_or(|values| {
        values
            .iter()
            .any(|value| value_matches_primitive(value, ty))
    });
    let const_admits = finite
        .const_value
        .as_ref()
        .is_none_or(|value| value_matches_primitive(value, ty));
    enum_admits && const_admits
}

fn declared_value_domain(object: &Map<String, Value>) -> Option<(Vec<DeclaredType>, String)> {
    match object.get("type")? {
        Value::String(name) => Some((vec![DeclaredType::from_name(name)?], name.clone())),
        Value::Array(values) => {
            let names = values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()?;
            let domains = names
                .iter()
                .map(|name| DeclaredType::from_name(name))
                .collect::<Option<Vec<_>>>()?;
            Some((domains, names.join(" | ")))
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => None,
    }
}

fn value_in_declared_domain(value: &Value, domains: &[DeclaredType], nullable: bool) -> bool {
    if value.is_null() && nullable {
        return true;
    }
    domains.iter().any(|domain| match domain {
        DeclaredType::String => value.is_string(),
        DeclaredType::Number => value.is_number(),
        DeclaredType::Integer => value
            .as_number()
            .is_some_and(json_number_is_mathematical_integer),
        DeclaredType::Boolean => value.is_boolean(),
        DeclaredType::Null => value.is_null(),
        DeclaredType::Object => value.is_object(),
        DeclaredType::Array => value.is_array(),
    })
}

fn retain_enum_extensions(meta: &mut SchemaMeta, original_len: usize, indices: &[usize]) {
    let Some(mut extensions) = meta.enum_extensions.take() else {
        return;
    };
    for extension in [
        &mut extensions.enum_varnames,
        &mut extensions.enum_names,
        &mut extensions.enum_descriptions,
        &mut extensions.enum_descriptions_camel,
    ] {
        if let Some(Value::Array(values)) = extension
            && values.len() == original_len
        {
            *values = indices
                .iter()
                .filter_map(|index| values.get(*index).cloned())
                .collect();
        }
    }
    meta.enum_extensions = box_if_populated(*extensions);
}

fn value_matches_primitive(value: &Value, ty: PrimitiveType) -> bool {
    match ty {
        PrimitiveType::String => value.is_string(),
        PrimitiveType::Number => value.is_number(),
        PrimitiveType::Integer => value
            .as_number()
            .is_some_and(json_number_is_mathematical_integer),
        PrimitiveType::Boolean => value.is_boolean(),
        PrimitiveType::Null => value.is_null(),
    }
}

fn json_number_is_mathematical_integer(number: &serde_json::Number) -> bool {
    if number.is_i64() || number.is_u64() {
        return true;
    }
    let raw = number.to_string();
    let (mantissa, exponent) =
        raw.split_once(['e', 'E'])
            .map_or((raw.as_str(), 0_i64), |(mantissa, exponent)| {
                let exponent = exponent.parse::<i64>().unwrap_or_else(|_| {
                    if exponent.starts_with('-') {
                        i64::MIN
                    } else {
                        i64::MAX
                    }
                });
                (mantissa, exponent)
            });
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.trim_end_matches('0').len());
    exponent >= i64::try_from(fractional_digits).unwrap_or(i64::MAX)
}

fn collect_numeric_constraints(
    object: &Map<String, Value>,
    version: OasVersion,
) -> NumericConstraints {
    let exclusive = |key: &str| match version {
        OasVersion::V3_0 => object
            .get(key)
            .and_then(Value::as_bool)
            .map(ExclusiveBound::Boolean),
        OasVersion::V3_1 => object
            .get(key)
            .and_then(Value::as_number)
            .cloned()
            .map(ExclusiveBound::Number),
    };
    NumericConstraints {
        minimum: object.get("minimum").and_then(Value::as_number).cloned(),
        maximum: object.get("maximum").and_then(Value::as_number).cloned(),
        exclusive_minimum: exclusive("exclusiveMinimum"),
        exclusive_maximum: exclusive("exclusiveMaximum"),
        // JSON Schema requires multipleOf > 0 and codegen requires a finite binary64. Invalid
        // divisors are diagnosed as OASTS1112 in schema_meta; this filter keeps them out of the
        // validator kernel and constraint docs.
        multiple_of: object
            .get("multipleOf")
            .and_then(Value::as_number)
            .filter(|number| number.as_f64().is_some_and(|value| value > 0.0))
            .cloned(),
    }
}

fn collect_string_constraints(object: &Map<String, Value>) -> StringConstraints {
    StringConstraints {
        min_length: object.get("minLength").and_then(Value::as_u64),
        max_length: object.get("maxLength").and_then(Value::as_u64),
        pattern: string_field(object, "pattern"),
    }
}

fn collect_array_constraints(object: &Map<String, Value>) -> ArrayConstraints {
    ArrayConstraints {
        min_items: object.get("minItems").and_then(Value::as_u64),
        max_items: object.get("maxItems").and_then(Value::as_u64),
        unique_items: bool_field(object, "uniqueItems"),
    }
}

fn collect_object_constraints(object: &Map<String, Value>) -> ObjectConstraints {
    let mut seen_required = HashSet::new();
    ObjectConstraints {
        min_properties: object.get("minProperties").and_then(Value::as_u64),
        max_properties: object.get("maxProperties").and_then(Value::as_u64),
        required: object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|name| seen_required.insert(*name))
            .map(str::to_owned)
            .collect(),
    }
}

fn collect_dependent_required(object: &Map<String, Value>) -> Vec<(String, Vec<String>)> {
    object
        .get("dependentRequired")
        .and_then(Value::as_object)
        .map(|dependencies| {
            dependencies
                .iter()
                .map(|(name, required)| {
                    let required = required
                        .as_array()
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    (name.clone(), required)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn pattern_property_type_key(pattern: &str) -> Option<PatternPropertyKey> {
    let anchored_start = pattern.starts_with('^');
    let without_start = pattern.strip_prefix('^').unwrap_or(pattern);
    let anchored_end = without_start.ends_with('$') && !without_start.ends_with("\\$");
    // ECMAScript `$` also matches immediately before a final line terminator, so neither `foo$`
    // nor `^foo$` denotes a plain TypeScript suffix/exact key space. Keep those patterns on the
    // validators-only path instead of emitting an index signature that excludes valid matches.
    if pattern == "$" {
        return Some(PatternPropertyKey::All);
    }
    if anchored_end {
        return None;
    }
    let body = without_start;
    let mut literal = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            let escaped = chars.next()?;
            if !matches!(
                escaped,
                '\\' | '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
            ) {
                return None;
            }
            literal.push(escaped);
        } else if matches!(
            character,
            '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
        ) {
            return None;
        } else {
            literal.push(character);
        }
    }
    match (anchored_start, literal.is_empty()) {
        (false, true) | (true, true) => Some(PatternPropertyKey::All),
        (true, false) => Some(PatternPropertyKey::Prefix(literal)),
        (false, false) => Some(PatternPropertyKey::Contains(literal)),
    }
}

fn collect_constraints(object: &Map<String, Value>, numeric: &NumericConstraints) -> Vec<String> {
    let mut constraints = Vec::new();
    for key in [
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
    ] {
        let numeric_value = match key {
            "minimum" => numeric.minimum.as_ref().map(ToString::to_string),
            "maximum" => numeric.maximum.as_ref().map(ToString::to_string),
            "exclusiveMinimum" => numeric
                .exclusive_minimum
                .as_ref()
                .map(render_exclusive_bound),
            "exclusiveMaximum" => numeric
                .exclusive_maximum
                .as_ref()
                .map(render_exclusive_bound),
            _ => None,
        };
        let rendered = if key == "multipleOf" {
            numeric.multiple_of.as_ref().map(ToString::to_string)
        } else {
            numeric_value.or_else(|| object.get(key).map(compact_json))
        };
        if let Some(rendered) = rendered {
            constraints.push(format!("{key}: {rendered}"));
        }
    }
    if let Some(format) = object.get("format").and_then(Value::as_str) {
        let ty = object.get("type").and_then(Value::as_str).unwrap_or("");
        if !is_consumed_format(ty, format) {
            constraints.push(format!("format: {format}"));
        }
    }
    constraints
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaMetaContent {
    None,
    Annotations,
    Complex,
}

/// Classifies metadata in one key walk. Annotation-only schemas can skip every constraint and
/// applicator collector, while structurally-only schemas retain the existing empty-meta reject.
fn schema_meta_content(object: &Map<String, Value>) -> SchemaMetaContent {
    let mut content = SchemaMetaContent::None;
    for key in object.keys() {
        match key.as_str() {
            "minimum"
            | "maximum"
            | "exclusiveMinimum"
            | "exclusiveMaximum"
            | "multipleOf"
            | "minLength"
            | "maxLength"
            | "pattern"
            | "minItems"
            | "maxItems"
            | "uniqueItems"
            | "minProperties"
            | "maxProperties"
            | "required"
            | "format"
            | "$dynamicRef"
            | "$recursiveRef"
            | "propertyNames"
            | "patternProperties"
            | "contains"
            | "minContains"
            | "maxContains"
            | "dependentSchemas"
            | "if"
            | "then"
            | "else"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "additionalItems"
            | "not" => return SchemaMetaContent::Complex,
            "example"
            | "examples"
            | "nullable"
            | "additionalProperties"
            | "items"
            | "readOnly"
            | "writeOnly"
            | "contentEncoding"
            | "title"
            | "description"
            | "deprecated"
            | "default"
            | "$comment"
            | "x-enum-varnames"
            | "x-enumNames"
            | "x-enum-descriptions"
            | "x-enumDescriptions" => content = SchemaMetaContent::Annotations,
            _ => {}
        }
    }
    content
}

/// True when a schema object carries any typed or value-constraint keyword — the "typed piece" a
/// conjunction lowering must preserve as a real branch. Pure annotations (title, description,
/// default, example(s), deprecated, readOnly, writeOnly, nullable, `x-*`) are not pieces. The
/// version gate mirrors the dispatch: `prefixItems`, `const`, `dependentRequired`, and
/// `contentEncoding` are OpenAPI 3.1 only, so in 3.0 they do not count (and, being early-rejected
/// dialect keywords, never reach here anyway).
fn has_typed_or_constraint_content(object: &Map<String, Value>, version: OasVersion) -> bool {
    const BOTH_VERSIONS: [&str; 20] = [
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "format",
    ];
    const V3_1_ONLY: [&str; 4] = [
        "prefixItems",
        "const",
        "dependentRequired",
        "contentEncoding",
    ];
    BOTH_VERSIONS.iter().any(|key| object.contains_key(*key))
        || (version == OasVersion::V3_1 && V3_1_ONLY.iter().any(|key| object.contains_key(*key)))
}

/// Whether the lowered schema accepts every JSON instance. Typeless constraint groups and
/// validation applicators still narrow an `Any` node, while annotations and content encoding do
/// not. Rejected validation keywords keep the classification conservative because their semantics
/// are unavailable in the lowered IR.
fn schema_admits_everything(schema: &SchemaNode) -> bool {
    matches!(
        schema,
        SchemaNode::Any { meta }
            if meta.numeric_constraints.is_none()
                && meta.string_constraints.is_none()
                && meta.array_constraints.is_none()
                && meta.object_constraints.is_none()
                && meta.validation_applicators.is_none()
                && meta.rejected_validation_keywords.is_empty()
    )
}

/// Source-only meta for a synthetic conjunction branch (`$ref`/`oneOf`/`anyOf` piece). Docs,
/// nullability, and constraints live on the wrapper or the typed branch, never on these pieces.
fn minimal_conjunction_meta(source: &SourceRef) -> SchemaMeta {
    SchemaMeta {
        source: source.clone(),
        ..SchemaMeta::default()
    }
}

fn render_exclusive_bound(bound: &ExclusiveBound) -> String {
    match bound {
        ExclusiveBound::Boolean(value) => value.to_string(),
        ExclusiveBound::Number(value) => value.to_string(),
    }
}

fn media_type_examples(value: &Value) -> Vec<(String, Value)> {
    let mut examples = Vec::new();
    if let Some(example) = value.get("example") {
        examples.push(("example".to_owned(), example.clone()));
    }
    if let Some(named) = value.get("examples").and_then(Value::as_object) {
        for (name, example) in named {
            if let Some(value) = example.get("value") {
                examples.push((name.clone(), value.clone()));
            }
        }
    }
    examples
}

fn is_consumed_format(ty: &str, format: &str) -> bool {
    match ty {
        "string" => matches!(
            format,
            "byte"
                | "binary"
                | "date"
                | "date-time"
                | "time"
                | "password"
                | "uuid"
                | "uri"
                | "email"
                | "hostname"
                | "ipv4"
                | "ipv6"
        ),
        "number" => matches!(format, "float" | "double"),
        "integer" => matches!(format, "int32" | "int64"),
        _ => false,
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serializing a JSON value cannot fail")
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn bool_field(object: &Map<String, Value>, key: &str) -> bool {
    object.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Reads an array-of-strings field, skipping a non-array value and non-string entries.
fn string_array_field(object: &Map<String, Value>, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedConfig, load_config, load_config_from_json};
    use crate::ir::{ParamStyle, SecKind};
    use crate::loader::load_graph;
    use crate::pipeline::compile as compile_pipeline;
    use crate::semantic::{TargetCase, normalize_identifier};

    #[test]
    fn schema_meta_fast_reject_distinguishes_structural_and_metadata_keys() {
        let mut object = Map::new();
        object.insert("type".to_owned(), Value::String("string".to_owned()));
        object.insert("properties".to_owned(), Value::Object(Map::new()));
        object.insert(
            "$ref".to_owned(),
            Value::String("#/components/schemas/X".to_owned()),
        );
        assert_eq!(schema_meta_content(&object), SchemaMetaContent::None);

        for key in [
            "example",
            "examples",
            "nullable",
            "additionalProperties",
            "items",
            "readOnly",
            "writeOnly",
            "contentEncoding",
            "title",
            "description",
            "deprecated",
            "default",
            "$comment",
            "x-enum-varnames",
            "x-enumNames",
            "x-enum-descriptions",
            "x-enumDescriptions",
        ] {
            let mut object = Map::new();
            object.insert(key.to_owned(), Value::Null);
            assert_eq!(
                schema_meta_content(&object),
                SchemaMetaContent::Annotations,
                "{key}"
            );
        }
        for key in [
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
            "minLength",
            "maxLength",
            "pattern",
            "minItems",
            "maxItems",
            "uniqueItems",
            "minProperties",
            "maxProperties",
            "required",
            "format",
            "$dynamicRef",
            "$recursiveRef",
            "propertyNames",
            "patternProperties",
            "contains",
            "minContains",
            "maxContains",
            "dependentSchemas",
            "if",
            "then",
            "else",
            "unevaluatedProperties",
            "unevaluatedItems",
            "additionalItems",
            "not",
        ] {
            let mut object = Map::new();
            object.insert(key.to_owned(), Value::Null);
            assert_eq!(
                schema_meta_content(&object),
                SchemaMetaContent::Complex,
                "{key}"
            );
        }
    }
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    #[test]
    fn external_schema_name_derives_from_pointer_context() {
        let cases = [
            ("/$defs/JsonValue", "JsonValue"),
            ("/$defs/foo~1bar", "foo/bar"),
            (
                "/components/parameters/audit_method_type/schema",
                "audit_method_type Schema",
            ),
            (
                "/components/responses/Conflict/content/application~1json/schema",
                "Conflict Schema",
            ),
            (
                "/components/responses/R/content/application~1json/schema/oneOf/0",
                "R OneOf 0",
            ),
            (
                "/components/requestBodies/B/content/application~1json/schema",
                "B Schema",
            ),
            ("/components/schemas/Foo/properties/bar", "Foo bar"),
            ("/components/schemas/Foo/items", "Foo Items"),
            // A property whose name happens to be a container keyword still names its schema.
            ("/components/schemas/Foo/properties/content", "Foo content"),
            (
                "/components/schemas/Foo/properties/properties",
                "Foo properties",
            ),
        ];

        for (pointer, expected) in cases {
            assert_eq!(
                external_schema_name(pointer, "unused"),
                expected,
                "{pointer}"
            );
        }
        assert_eq!(external_schema_name("", "my-schema.v2"), "my-schema.v2");
    }

    #[test]
    fn an_inline_schema_under_a_declared_component_is_materialized() {
        // `/components/schemas/Envelope/properties/payload` shares the declared component's prefix,
        // so a prefix-only skip would leave it unnamed and every reference to it dangling.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Envelope": {
                    "type": "object",
                    "properties": { "payload": { "type": "object" } }
                },
                "Holder": {
                    "type": "object",
                    "properties": {
                        "inner": { "$ref": "#/components/schemas/Envelope/properties/payload" }
                    }
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors());
        let names = ir
            .schemas
            .iter()
            .map(|schema| schema.name.as_str())
            .collect::<Vec<_>>();
        // Materialized schemas are appended after the declared components, in pointer order.
        assert_eq!(names, ["Envelope", "Holder", "Envelope payload"]);
    }

    #[test]
    fn external_schema_name_normalizes_to_the_final_identifier() {
        for (pointer, expected) in [
            (
                "/components/parameters/audit_method_type/schema",
                "AuditMethodTypeSchema",
            ),
            (
                "/components/responses/R/content/application~1json/schema/oneOf/0",
                "ROneOf0",
            ),
        ] {
            assert_eq!(
                normalize_identifier(&external_schema_name(pointer, "unused"), TargetCase::Pascal),
                Ok(expected.to_owned())
            );
        }
    }

    fn chain_test_graph() -> (TempDir, DocumentGraph) {
        graph_for(&json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {}
        }))
    }

    fn chain_node<'graph>(graph: &'graph DocumentGraph, pointer: &str) -> NodeView<'graph> {
        let entry = graph.entry();
        NodeView {
            doc_id: entry.id,
            pointer: pointer.to_owned(),
            value: &entry.value,
        }
    }

    #[test]
    fn follow_ref_chain_reports_cycles() {
        let (_temp, graph) = chain_test_graph();
        let mut step = 0_u64;
        let error = follow_ref_chain(chain_node(&graph, "/start"), 10, &mut |_| {
            let pointer = format!("/parameters/{}", step % 2);
            step += 1;
            RefChainStep::Next {
                member: RefChainMember {
                    doc_index: 0,
                    pointer: pointer.clone(),
                },
                node: chain_node(&graph, &pointer),
            }
        })
        .expect_err("alternating targets form a cycle");

        assert_eq!(
            error,
            RefChainError::Cycle(vec![
                "/parameters/0".to_owned(),
                "/parameters/1".to_owned(),
                "/parameters/0".to_owned(),
            ])
        );
    }

    #[test]
    fn follow_ref_chain_reports_budget_exhaustion() {
        let (_temp, graph) = chain_test_graph();
        let mut step = 0_u64;
        let error = follow_ref_chain(chain_node(&graph, "/start"), 2, &mut |_| {
            let pointer = format!("/parameters/{step}");
            step += 1;
            RefChainStep::Next {
                member: RefChainMember {
                    doc_index: 0,
                    pointer: pointer.clone(),
                },
                node: chain_node(&graph, &pointer),
            }
        })
        .expect_err("three hops exceed a two-hop budget");

        assert_eq!(
            error,
            RefChainError::Budget(vec![
                "/parameters/0".to_owned(),
                "/parameters/1".to_owned(),
                "/parameters/2".to_owned(),
            ])
        );
    }

    #[test]
    fn follow_ref_chain_propagates_resolution_failures() {
        let (_temp, graph) = chain_test_graph();
        let diagnostic = Diagnostic::input(CODE_SHAPE, "boom".to_owned());
        let error = follow_ref_chain(chain_node(&graph, "/start"), 2, &mut |_| {
            RefChainStep::Fail(Box::new(diagnostic.clone()))
        })
        .expect_err("a failing hop aborts the chain");

        assert_eq!(error, RefChainError::Resolution(Box::new(diagnostic)));
    }

    #[test]
    fn ref_chain_failure_diagnostics_name_the_chain() {
        let resolution = Diagnostic::input(CODE_SHAPE, "inner".to_owned());
        assert_eq!(
            ref_chain_failure_diagnostic(
                "parameter",
                4,
                "entry",
                "/p",
                RefChainError::Resolution(Box::new(resolution.clone())),
            ),
            resolution
        );

        let cycle = ref_chain_failure_diagnostic(
            "parameter",
            4,
            "entry",
            "/p",
            RefChainError::Cycle(vec!["/a".to_owned(), "/b".to_owned()]),
        );
        assert_eq!(cycle.code, CODE_REF_CYCLE);
        assert_eq!(
            cycle.message,
            "parameter reference chain contains a cycle: /a -> /b"
        );
        assert_eq!(cycle.source_id.as_deref(), Some("entry"));
        assert_eq!(cycle.json_pointer.as_deref(), Some("/p"));

        let budget = ref_chain_failure_diagnostic(
            "parameter",
            4,
            "entry",
            "/p",
            RefChainError::Budget(vec!["/a".to_owned(), "/b".to_owned()]),
        );
        assert_eq!(budget.code, CODE_REF_DEPTH);
        assert_eq!(
            budget.message,
            "parameter reference chain exceeds maxRefDepth 4: /a -> /b"
        );
        assert_eq!(budget.source_id.as_deref(), Some("entry"));
        assert_eq!(budget.json_pointer.as_deref(), Some("/p"));
    }

    #[test]
    fn parameter_ref_chain_mid_resolution_failure_reports_the_hop_diagnostic() {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{"/pets":{"get":{"parameters":[{"$ref":"middle.json#/Hop"}],"responses":{"204":{"description":"ok"}}}}}}"#,
        )
        .expect("write entry");
        std::fs::write(
            temp.path().join("middle.json"),
            br#"{"Hop":{"$ref":"last.json#/Concrete"}}"#,
        )
        .expect("write middle");
        std::fs::write(
            temp.path().join("last.json"),
            br#"{"Concrete":{"name":"limit","in":"query","schema":{"type":"integer"}}}"#,
        )
        .expect("write last");
        let resolved = load_config(Some(Path::new("oasts.json")), temp.path()).expect("config");
        let mut load_sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut load_sink).expect("graph");
        assert!(!load_sink.has_errors(), "{:#?}", load_sink.as_slice());
        std::fs::remove_file(temp.path().join("last.json")).expect("remove last hop");

        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("supported OpenAPI version");

        assert!(sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(ir.operations[0].parameters.is_empty());
    }

    #[test]
    fn parallel_parse_preserves_ir_and_diagnostic_order() {
        let mut schemas = Map::new();
        let mut paths = Map::new();
        for index in 0..80 {
            schemas.insert(
                format!("Schema{index:02}"),
                if index == 0 {
                    json!({ "$ref": "#/x-shared" })
                } else {
                    json!({
                        "type": "object",
                        "properties": {},
                        "required": ["missing"]
                    })
                },
            );
            paths.insert(
                format!("/path-{index:02}"),
                json!({
                    "get": {
                        "parameters": "invalid",
                        "responses": { "204": { "description": "ok" } }
                    }
                }),
            );
            // A second family of paths whose template parameters and declared parameters
            // disagree in both directions, so each one emits several OASTS1105 diagnostics
            // out of a HashSet difference. Ordering those by hasher iteration would make the
            // sequence inside one path depend on the hasher's per-instance seed.
            paths.insert(
                format!("/mismatch-{index:02}/{{alpha}}/{{bravo}}/{{charlie}}/{{delta}}"),
                json!({
                    "get": {
                        "parameters": [
                            { "name": "echo", "in": "path", "required": true,
                              "schema": { "type": "string" } },
                            { "name": "foxtrot", "in": "path", "required": true,
                              "schema": { "type": "string" } },
                            { "name": "golf", "in": "path", "required": true,
                              "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }),
            );
        }
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "parallel parse", "version": "1" },
            "paths": paths,
            "components": { "schemas": schemas },
            "x-shared": { "type": "string" }
        });
        let (_temp, graph) = graph_for(&document);
        let mut expected_sink = DiagnosticSink::new();
        let expected = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("serial pool")
            .install(|| parse(&graph, &mut expected_sink).expect("serial parse"));

        for thread_count in [2, 18] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
                .expect("parallel pool");
            for _ in 0..4 {
                let mut sink = DiagnosticSink::new();
                let actual = pool.install(|| parse(&graph, &mut sink).expect("parallel parse"));
                assert_eq!(actual, expected, "thread count {thread_count}");
                assert_eq!(sink, expected_sink, "thread count {thread_count}");
            }
        }
    }

    #[test]
    fn single_document_materialization_fast_reject_depends_on_entry_defs_references() {
        assert!(!should_materialize_external_schemas(1, false));
        assert!(should_materialize_external_schemas(1, true));
    }

    fn load_fixture(name: &str) -> (ResolvedConfig, DocumentGraph) {
        let directory = fixture(name);
        let config_path = directory.join("oasts.yaml");
        let config = load_config(Some(&config_path), &directory).expect("fixture config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&config, &mut sink).expect("fixture graph");
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        (config, graph)
    }

    fn graph_for(document: &Value) -> (TempDir, DocumentGraph) {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config json"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(document).expect("document json"),
        )
        .expect("write document");
        let resolved =
            load_config(Some(Path::new("oasts.json")), temp.path()).expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut sink).expect("graph");
        assert!(!sink.has_errors());
        (temp, graph)
    }

    fn parse_value(document: &Value) -> (TempDir, Ir, DiagnosticSink) {
        let (temp, graph) = graph_for(document);
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("supported OpenAPI version");
        (temp, ir, sink)
    }

    fn compile_value(
        document: &Value,
    ) -> (
        TempDir,
        Option<Vec<crate::emit::GeneratedFile>>,
        DiagnosticSink,
    ) {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config json"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(document).expect("document json"),
        )
        .expect("write document");
        let resolved =
            load_config(Some(Path::new("oasts.json")), temp.path()).expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile_pipeline(&resolved, true, &mut sink);
        (temp, files, sink)
    }

    #[test]
    fn declared_value_domain_helpers_cover_every_json_type() {
        for (name, expected) in [
            ("string", DeclaredType::String),
            ("number", DeclaredType::Number),
            ("integer", DeclaredType::Integer),
            ("boolean", DeclaredType::Boolean),
            ("null", DeclaredType::Null),
            ("object", DeclaredType::Object),
            ("array", DeclaredType::Array),
        ] {
            assert_eq!(DeclaredType::from_name(name), Some(expected));
        }
        assert_eq!(DeclaredType::from_name("unknown"), None);

        for (value, domain) in [
            (json!("value"), DeclaredType::String),
            (json!(1.5), DeclaredType::Number),
            (json!(1.0), DeclaredType::Integer),
            (json!(true), DeclaredType::Boolean),
            (Value::Null, DeclaredType::Null),
            (json!({}), DeclaredType::Object),
            (json!([]), DeclaredType::Array),
        ] {
            assert!(value_in_declared_domain(&value, &[domain], false));
        }
        assert!(!value_in_declared_domain(
            &json!(1.5),
            &[DeclaredType::Integer],
            false
        ));
        assert!(value_in_declared_domain(
            &Value::Null,
            &[DeclaredType::String],
            true
        ));

        let scalar = json!({ "type": "string" });
        assert_eq!(
            declared_value_domain(scalar.as_object().expect("object")),
            Some((vec![DeclaredType::String], "string".to_owned()))
        );
        let union = json!({ "type": ["array", "null"] });
        assert_eq!(
            declared_value_domain(union.as_object().expect("object")),
            Some((
                vec![DeclaredType::Array, DeclaredType::Null],
                "array | null".to_owned()
            ))
        );
        for unrecognized in [
            json!({}),
            json!({ "type": "unknown" }),
            json!({ "type": [1] }),
            json!({ "type": true }),
        ] {
            assert_eq!(
                declared_value_domain(unrecognized.as_object().expect("object")),
                None
            );
        }
    }

    #[test]
    fn enum_extension_filtering_tracks_retained_member_indices() {
        let mut meta = SchemaMeta::default();
        retain_enum_extensions(&mut meta, 2, &[1]);
        assert!(meta.enum_extensions.is_none());

        meta.enum_extensions = box_if_populated(EnumExtensionData {
            enum_varnames: Some(json!(["First", "Second"])),
            enum_names: Some(json!(["First", "Second"])),
            enum_descriptions: Some(json!(["first", "second"])),
            enum_descriptions_camel: Some(json!(["first", "second"])),
        });
        retain_enum_extensions(&mut meta, 2, &[1]);
        let extensions = meta.enum_extensions();
        assert_eq!(extensions.enum_varnames, Some(json!(["Second"])));
        assert_eq!(extensions.enum_names, Some(json!(["Second"])));
        assert_eq!(extensions.enum_descriptions, Some(json!(["second"])));
        assert_eq!(extensions.enum_descriptions_camel, Some(json!(["second"])));

        meta.enum_extensions = box_if_populated(EnumExtensionData {
            enum_varnames: Some(json!("not an array")),
            enum_names: Some(json!(["wrong length"])),
            ..EnumExtensionData::default()
        });
        retain_enum_extensions(&mut meta, 2, &[0]);
        let extensions = meta.enum_extensions();
        assert_eq!(extensions.enum_varnames, Some(json!("not an array")));
        assert_eq!(extensions.enum_names, Some(json!(["wrong length"])));
    }

    #[test]
    fn tuple_finite_values_use_the_same_domain_filter() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Tuple": {
                    "type": "array",
                    "prefixItems": [{ "type": "string" }],
                    "enum": [["value"], false]
                },
                "EmptyAndImpossible": {
                    "type": "string",
                    "enum": [],
                    "const": false
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_ENUM_RULE_14
                && diagnostic.severity == Severity::Warning
                && diagnostic.message.contains("enum member false")
        }));
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_ENUM_RULE_14
                && diagnostic.severity == Severity::Warning
                && diagnostic.message.contains("OpenAPI 3.1 (SHOULD)")
        }));
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Tuple { .. }));
        assert!(matches!(ir.schemas[1].schema, SchemaNode::Never { .. }));
    }

    #[test]
    fn finite_type_array_and_tuple_paths_lower_to_never() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "UnknownUnion": {
                    "type": ["string", "unknown"],
                    "enum": ["value"]
                },
                "ImpossibleUnion": {
                    "type": ["string", "null"],
                    "enum": [false]
                },
                "TrackedConst": {
                    "type": "string",
                    "enum": ["value"],
                    "const": false,
                    "x-enum-varnames": ["Value"]
                },
                "UnknownTupleDomain": {
                    "type": "unknown",
                    "prefixItems": [{ "type": "string" }],
                    "enum": [["value"]]
                },
                "NullableTuple": {
                    "type": ["array", "null"],
                    "prefixItems": [{ "type": "string" }],
                    "enum": [null]
                },
                "ImpossibleTuple": {
                    "type": "array",
                    "prefixItems": [{ "type": "string" }],
                    "enum": [false]
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(matches!(ir.schemas[0].schema, SchemaNode::AnyOf { .. }));
        assert!(matches!(ir.schemas[1].schema, SchemaNode::Never { .. }));
        assert!(matches!(ir.schemas[2].schema, SchemaNode::Never { .. }));
        assert!(matches!(ir.schemas[3].schema, SchemaNode::Tuple { .. }));
        assert!(matches!(ir.schemas[4].schema, SchemaNode::Tuple { .. }));
        assert!(matches!(ir.schemas[5].schema, SchemaNode::Never { .. }));
    }

    #[test]
    fn exhausted_domains_clear_nullability_on_every_lowering_path() {
        let document = schemas_doc(
            "3.0.4",
            json!({
                "Scalar": { "type": "string", "nullable": true, "enum": [false] },
                "Empty": { "type": "string", "nullable": true, "enum": [] }
            }),
        );
        let (_temp, ir, _sink) = parse_value(&document);
        for schema in &ir.schemas {
            assert!(matches!(schema.schema, SchemaNode::Never { .. }));
            assert!(!schema.schema.is_nullable(), "{}", schema.name);
        }

        let document = schemas_doc(
            "3.1.0",
            json!({
                "TypeArray": { "type": ["string", "null"], "enum": [false] },
                "Tuple": {
                    "type": ["array", "null"],
                    "prefixItems": [{ "type": "string" }],
                    "enum": [false]
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        for schema in &ir.schemas {
            assert!(matches!(schema.schema, SchemaNode::Never { .. }));
            assert!(!schema.schema.is_nullable(), "{}", schema.name);
        }
    }

    #[test]
    fn empty_schema_enum_obeys_version_rule_and_lowers_to_never() {
        for (version, severity, rule) in [
            ("3.0.3", Severity::Error, "OpenAPI 3.0 (MUST)"),
            ("3.1.0", Severity::Warning, "OpenAPI 3.1 (SHOULD)"),
        ] {
            let document = schemas_doc(
                version,
                json!({
                    "Empty": {
                        "type": "string",
                        "enum": []
                    }
                }),
            );
            let (_temp, ir, sink) = parse_value(&document);
            let diagnostics = sink
                .as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_ENUM_RULE_14)
                .collect::<Vec<_>>();
            assert_eq!(diagnostics.len(), 1, "{version}: {:#?}", sink.as_slice());
            assert_eq!(diagnostics[0].severity, severity);
            assert!(diagnostics[0].message.contains(rule));
            assert_eq!(
                diagnostics[0].json_pointer.as_deref(),
                Some("/components/schemas/Empty/enum")
            );
            assert!(matches!(ir.schemas[0].schema, SchemaNode::Never { .. }));
        }
    }

    /// A document whose `$defs` entry and `components.schemas` entry can be made to collide.
    ///
    /// The operation references both, because an unreferenced component is pruned before name
    /// allocation runs and a pruned schema cannot collide with anything.
    fn entry_defs_document(definition_name: &str, component_name: Option<&str>) -> Value {
        let mut schemas = Map::new();
        let mut operation = json!({
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/$defs/{definition_name}") }
                        }
                    }
                }
            }
        });
        if let Some(component_name) = component_name {
            schemas.insert(component_name.to_owned(), json!({ "type": "integer" }));
            operation["requestBody"] = json!({
                "content": {
                    "application/json": {
                        "schema": { "$ref": format!("#/components/schemas/{component_name}") }
                    }
                }
            });
        }
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/value": { "get": operation } },
            "$defs": {
                definition_name: { "type": "string" }
            },
            "components": { "schemas": schemas }
        })
    }

    #[test]
    fn entry_defs_reference_materializes_a_named_schema() {
        let document = entry_defs_document("Foo", None);
        let (_temp, files, sink) = compile_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let paths = files
            .expect("entry definition emits")
            .into_iter()
            .map(|file| file.relative_path)
            .collect::<Vec<_>>();
        assert!(
            paths.contains(&"types/components/foo.ts".to_owned()),
            "{paths:#?}"
        );
    }

    #[test]
    fn entry_defs_exact_name_collision_reports_oasts1202() {
        let document = entry_defs_document("Foo", Some("Foo"));
        let (_temp, files, sink) = compile_value(&document);

        assert!(files.is_none(), "exact collision must suppress output");
        let diagnostics = sink.as_slice();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1202"),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn entry_defs_case_only_identifier_difference_allocates_both() {
        let document = entry_defs_document("FOO", Some("Foo"));
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let names = ir
            .schemas
            .iter()
            .map(|schema| schema.name.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(names, ["FOO", "Foo"].into_iter().collect());
    }

    #[test]
    fn parameter_ref_chain_resolves_to_concrete_parameter() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [{ "$ref": "#/components/parameters/A" }],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "components": {
                "parameters": {
                    "A": { "$ref": "#/components/parameters/B" },
                    "B": {
                        "name": "limit",
                        "in": "query",
                        "schema": { "type": "integer" }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(ir.operations[0].parameters.len(), 1);
        assert_eq!(ir.operations[0].parameters[0].name, "limit");
    }

    #[test]
    fn paths_and_webhooks_skip_specification_extensions() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "x-internal": "some string",
                "/pets": {
                    "get": { "responses": { "204": { "description": "ok" } } }
                }
            },
            "webhooks": {
                "x-internal": "some string",
                "pet.created": {
                    "post": { "responses": { "204": { "description": "ok" } } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(ir.operations.len(), 1);
        assert_eq!(ir.webhooks.len(), 1);
        assert_eq!(ir.webhooks[0].name, "pet.created");
    }

    #[test]
    fn responses_skip_specification_extensions() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "responses": {
                            "x-internal": "some string",
                            "204": { "description": "ok" }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(ir.operations[0].responses.len(), 1);
        assert_eq!(
            ir.operations[0].responses[0].status,
            ResponseStatus::Exact("204".to_owned())
        );
    }

    #[test]
    fn callbacks_skip_specification_extensions() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": {
                            "delivery": {
                                "x-internal": "some string",
                                "{$request.body#/callbackUrl}": {
                                    "post": {
                                        "responses": { "204": { "description": "ok" } }
                                    }
                                }
                            }
                        },
                        "responses": { "202": { "description": "accepted" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(ir.operations[0].callbacks[0].expressions.len(), 1);
        assert_eq!(
            ir.operations[0].callbacks[0].expressions[0].expression,
            "{$request.body#/callbackUrl}"
        );
    }

    #[test]
    fn absent_operation_responses_follow_version_requirement() {
        let document = |version| {
            json!({
                "openapi": version,
                "info": { "title": "t", "version": "1" },
                "paths": { "/pets": { "get": {} } }
            })
        };

        let (_temp, ir, sink) = parse_value(&document("3.1.0"));
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
        assert!(ir.operations[0].responses.is_empty());

        let (_temp, ir, sink) = parse_value(&document("3.0.3"));
        assert!(ir.operations[0].responses.is_empty());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref() == Some("/paths/~1pets/get")
                && diagnostic.message == "operation is missing responses"
        }));
    }

    #[test]
    fn operation_refs_are_diagnosed_once_and_never_enter_the_ir() {
        let document = json!({
            "openapi": "3.0.4",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pure/{id}": {
                    "get": { "$ref": "#/x-operation" }
                },
                "/siblings/{id}": {
                    "put": {
                        "$ref": "#/x-operation",
                        "responses": []
                    }
                }
            },
            "x-operation": {
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "responses": { "204": { "description": "ok" } }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(ir.operations.is_empty());
        let diagnostics = sink.as_slice();
        assert_eq!(diagnostics.len(), 2, "{diagnostics:#?}");
        assert!(diagnostics.iter().all(|diagnostic| {
            diagnostic.code == CODE_OPERATION_REF
                && diagnostic.message
                    == "OpenAPI defines '$ref' on a Path Item Object but not on an Operation Object; bundle the document before compiling, or place '$ref' on the whole path item when its target is a Path Item Object"
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/paths/~1pure~1{id}/get")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/paths/~1siblings~1{id}/put")
        }));
    }

    #[test]
    fn callback_and_webhook_operation_refs_use_the_same_rejection() {
        let document = json!({
            "openapi": "3.1.1",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": {
                            "delivery": {
                                "{$request.body#/callbackUrl}": {
                                    "post": { "$ref": "#/x-operation" }
                                }
                            }
                        },
                        "responses": { "202": { "description": "accepted" } }
                    }
                }
            },
            "webhooks": {
                "audit": {
                    "put": {
                        "$ref": "#/x-operation",
                        "responses": { "204": { "description": "ignored sibling" } }
                    }
                }
            },
            "x-operation": {
                "responses": { "204": { "description": "ok" } }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert_eq!(ir.operations.len(), 1);
        assert!(
            ir.operations[0].callbacks[0].expressions[0]
                .operations
                .is_empty()
        );
        assert_eq!(ir.webhooks.len(), 1);
        assert!(ir.webhooks[0].operations.is_empty());
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_OPERATION_REF)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 2, "{:#?}", sink.as_slice());
        assert_eq!(sink.as_slice().len(), diagnostics.len());
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some(
                    "/paths/~1subscribe/post/callbacks/delivery/{$request.body#~1callbackUrl}/post",
                )
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/webhooks/audit/put")
        }));
    }

    #[test]
    fn empty_operation_responses_are_shape_errors_in_both_versions() {
        for version in ["3.0.3", "3.1.0"] {
            let document = json!({
                "openapi": version,
                "info": { "title": "t", "version": "1" },
                "paths": { "/pets": { "get": { "responses": {} } } }
            });
            let (_temp, ir, sink) = parse_value(&document);

            assert!(ir.operations[0].responses.is_empty());
            assert!(sink.as_slice().iter().any(|diagnostic| {
                diagnostic.code == CODE_SHAPE
                    && diagnostic.json_pointer.as_deref() == Some("/paths/~1pets/get/responses")
                    && diagnostic.message == "responses object must declare at least one response"
            }));
        }
    }

    #[test]
    fn extension_only_operation_responses_are_shape_errors() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": { "responses": { "x-internal": "some string" } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(ir.operations[0].responses.is_empty());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref() == Some("/paths/~1pets/get/responses")
                && diagnostic.message == "responses object must declare at least one response"
        }));
    }

    #[test]
    fn webhooks_parse_methods_and_ref_path_items() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "invoice.created": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    },
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": { "202": { "description": "accepted" } }
                    }
                },
                "invoice.deleted": { "$ref": "#/components/pathItems/DeletedHook" }
            },
            "components": {
                "pathItems": {
                    "DeletedHook": {
                        "put": {
                            "requestBody": {
                                "content": {
                                    "application/json": { "schema": { "type": "integer" } }
                                }
                            },
                            "responses": { "204": { "description": "deleted" } }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            ir.webhooks
                .iter()
                .map(|webhook| webhook.name.as_str())
                .collect::<Vec<_>>(),
            ["invoice.created", "invoice.deleted"]
        );
        assert_eq!(
            ir.webhooks[0]
                .operations
                .iter()
                .map(|operation| operation.method.as_str())
                .collect::<Vec<_>>(),
            ["get", "post"]
        );
        assert!(
            ir.webhooks
                .iter()
                .flat_map(|webhook| &webhook.operations)
                .all(|operation| operation.path_template.is_empty()
                    && !operation.responses.is_empty())
        );
        assert!(ir.webhooks[0].operations[1].request_body.is_some());
        assert!(ir.webhooks[1].operations[0].request_body.is_some());
    }

    #[test]
    fn webhooks_on_30_warn_and_drop() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "ignored": {
                    "post": { "responses": { "204": { "description": "ok" } } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(ir.webhooks.is_empty());
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_WEBHOOKS_VERSION)
            .expect("webhooks version warning");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(diagnostic.json_pointer.as_deref(), Some("/webhooks"));
        assert_eq!(
            diagnostic.message,
            "top-level 'webhooks' requires OpenAPI 3.1 and is ignored"
        );
    }

    #[test]
    fn webhook_with_no_operations_is_kept() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "documented": { "description": "No operation yet." }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(ir.webhooks.len(), 1);
        assert_eq!(ir.webhooks[0].name, "documented");
        assert!(ir.webhooks[0].operations.is_empty());
    }

    #[test]
    fn malformed_webhook_and_callback_maps_are_diagnosed_and_dropped() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": [],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "webhooks": { "invalid": 7 }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(ir.webhooks.is_empty());
        assert!(ir.operations[0].callbacks.is_empty());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref() == Some("/webhooks/invalid")
        }));
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref() == Some("/paths/~1subscribe/post/callbacks")
        }));

        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": { "invalid": 7 },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "webhooks": []
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(ir.webhooks.is_empty());
        assert!(ir.operations[0].callbacks.is_empty());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE && diagnostic.json_pointer.as_deref() == Some("/webhooks")
        }));
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref()
                    == Some("/paths/~1subscribe/post/callbacks/invalid")
        }));
    }

    #[test]
    fn callbacks_parse_expressions_in_order() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": {
                            "delivery.status": {
                                "{$request.body#/callbackUrl}": {
                                    "post": {
                                        "responses": { "202": { "description": "accepted" } }
                                    }
                                },
                                "{$request.query.fallback}": {
                                    "get": {
                                        "responses": { "200": { "description": "ok" } }
                                    }
                                }
                            },
                            "audit-log": { "$ref": "#/components/callbacks/Audit" }
                        },
                        "responses": { "201": { "description": "subscribed" } }
                    }
                }
            },
            "components": {
                "callbacks": {
                    "Audit": {
                        "{$request.header.X-Audit-Url}": {
                            "put": {
                                "responses": { "204": { "description": "recorded" } }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let callbacks = &ir.operations[0].callbacks;
        assert_eq!(
            callbacks
                .iter()
                .map(|callback| callback.name.as_str())
                .collect::<Vec<_>>(),
            ["delivery.status", "audit-log"]
        );
        assert_eq!(
            callbacks[0]
                .expressions
                .iter()
                .map(|expression| expression.expression.as_str())
                .collect::<Vec<_>>(),
            ["{$request.body#/callbackUrl}", "{$request.query.fallback}"]
        );
        assert_eq!(callbacks[0].expressions[0].operations[0].method, "post");
        assert_eq!(callbacks[0].expressions[1].operations[0].method, "get");
        assert_eq!(callbacks[1].expressions[0].operations[0].method, "put");
        assert!(
            callbacks
                .iter()
                .flat_map(|callback| &callback.expressions)
                .flat_map(|expression| &expression.operations)
                .all(|operation| operation.path_template.is_empty())
        );
    }

    #[test]
    fn nested_callback_operations_parse() {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/subscribe": {
                    "post": {
                        "callbacks": {
                            "outer": {
                                "{$request.body#/outerUrl}": {
                                    "post": {
                                        "callbacks": {
                                            "inner": {
                                                "{$request.body#/innerUrl}": {
                                                    "get": {
                                                        "responses": {
                                                            "200": { "description": "ok" }
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        "responses": { "202": { "description": "accepted" } }
                                    }
                                }
                            }
                        },
                        "responses": { "201": { "description": "subscribed" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let outer_operation = &ir.operations[0].callbacks[0].expressions[0].operations[0];
        assert_eq!(outer_operation.callbacks[0].name, "inner");
        let inner_operation = &outer_operation.callbacks[0].expressions[0].operations[0];
        assert_eq!(inner_operation.method, "get");
        assert!(inner_operation.callbacks.is_empty());
    }

    #[test]
    fn webhook_external_ref_materializes() {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "webhooks": {
                "external": {
                    "post": {
                        "callbacks": {
                            "nested": {
                                "{$request.body#/callbackUrl}": {
                                    "post": {
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "$ref": "schemas.json#/CallbackPayload"
                                                    }
                                                }
                                            }
                                        },
                                        "responses": {
                                            "204": { "description": "callback ok" }
                                        }
                                    }
                                }
                            }
                        },
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "schemas.json#/WebhookPayload" }
                                }
                            }
                        },
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }
        });
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config json"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(&document).expect("document json"),
        )
        .expect("write document");
        std::fs::write(
            temp.path().join("schemas.json"),
            br#"{"WebhookPayload":{"type":"object","properties":{"id":{"type":"string"}}},"CallbackPayload":{"type":"integer"}}"#,
        )
        .expect("write external schema");
        let resolved =
            load_config(Some(Path::new("oasts.json")), temp.path()).expect("resolved config");
        let mut load_sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut load_sink).expect("graph");
        assert!(!load_sink.has_errors(), "{:#?}", load_sink.as_slice());
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let body = ir.webhooks[0].operations[0]
            .request_body
            .as_ref()
            .expect("webhook request body");
        assert!(matches!(body.media_types[0].schema, SchemaNode::Ref { .. }));
        assert!(ir.schemas.iter().any(|schema| {
            schema.name == "WebhookPayload" && matches!(schema.schema, SchemaNode::Object { .. })
        }));
        let callback_payload = ir
            .schemas
            .iter()
            .find(|schema| schema.name == "CallbackPayload")
            .expect("external callback schema materialized");
        assert!(matches!(
            callback_payload.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Integer,
                ..
            }
        ));
    }

    #[test]
    fn operations_without_callbacks_have_empty_vec() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/plain": {
                    "get": { "responses": { "204": { "description": "ok" } } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(ir.operations[0].callbacks.is_empty());
    }

    #[test]
    fn required_names_undefined_property_warns_oasts1111() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": {
                "schemas": {
                    "Thing": {
                        "type": "object",
                        "required": ["b", "a", "b", "declared"],
                        "properties": { "declared": { "type": "string" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        let warnings = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_PHANTOM_REQUIRED)
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert_eq!(warnings[1].severity, Severity::Warning);
        assert_eq!(
            warnings[0].message,
            "required lists property 'b' that is not defined in properties"
        );
        assert_eq!(
            warnings[1].message,
            "required lists property 'a' that is not defined in properties"
        );
        assert!(warnings.iter().all(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/components/schemas/Thing/required")
        }));
        assert!(matches!(
            &ir.schemas[0].schema,
            SchemaNode::Object { extra_required, .. }
                if extra_required == &["b".to_owned(), "a".to_owned()]
        ));
    }

    #[test]
    fn bare_required_stays_typeless_and_retains_presence_assertions() {
        let document = schemas_doc(
            "3.1.0",
            json!({ "Thing": { "required": ["value", "description", "value"] } }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::Any { meta }
                if meta.object_constraints().required
                    == ["value".to_owned(), "description".to_owned()]
        ));
    }

    #[test]
    fn schema_ref_collection_descends_into_validation_applicators() {
        let reference = |pointer: &str| {
            Box::new(SchemaNode::Ref {
                target: SchemaRef {
                    source_id: "external.json".to_owned(),
                    json_pointer: pointer.to_owned(),
                },
                meta: SchemaMeta::default(),
            })
        };
        let schema = SchemaNode::Any {
            meta: SchemaMeta {
                validation_applicators: Some(Box::new(ValidationApplicators {
                    not: Some(reference("/NotTarget")),
                    property_names: Some(reference("/NameTarget")),
                    pattern_properties: vec![PatternProperty {
                        pattern: "^x".to_owned(),
                        schema: *reference("/PatternTarget"),
                        type_key: Some(PatternPropertyKey::Prefix("x".to_owned())),
                    }],
                    contains: Some(Box::new(ContainsApplicator {
                        schema: reference("/ContainsTarget"),
                        min_contains: None,
                        max_contains: None,
                    })),
                    dependent_schemas: vec![("trigger".to_owned(), *reference("/DependentTarget"))],
                    conditional: Some(Box::new(ConditionalApplicator {
                        condition: reference("/IfTarget"),
                        then_schema: Some(reference("/ThenTarget")),
                        else_schema: Some(reference("/ElseTarget")),
                    })),
                    unevaluated_properties: Some(reference("/UnevaluatedPropertiesTarget")),
                    unevaluated_items: Some(reference("/UnevaluatedItemsTarget")),
                })),
                ..SchemaMeta::default()
            },
        };
        let mut refs = Vec::new();

        collect_schema_refs(&schema, &mut refs);

        assert_eq!(
            refs.iter()
                .map(|(target, _)| target.json_pointer.as_str())
                .collect::<Vec<_>>(),
            [
                "/NotTarget",
                "/NameTarget",
                "/PatternTarget",
                "/ContainsTarget",
                "/DependentTarget",
                "/IfTarget",
                "/ThenTarget",
                "/ElseTarget",
                "/UnevaluatedPropertiesTarget",
                "/UnevaluatedItemsTarget"
            ]
        );
    }

    fn schemas_doc(version: &str, schemas: Value) -> Value {
        json!({
            "openapi": version,
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": schemas }
        })
    }

    fn schema_named<'ir>(ir: &'ir Ir, name: &str) -> &'ir SchemaNode {
        ir.schemas
            .iter()
            .find(|schema| schema.name == name)
            .map(|schema| &schema.schema)
            .expect("named schema present")
    }

    fn ref_sibling_warnings(sink: &DiagnosticSink) -> Vec<&Diagnostic> {
        sink.as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_REF_SIBLINGS)
            .collect()
    }

    #[test]
    fn dynamic_reference_errors_name_the_keyword_and_retain_unknown_ir() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "BadRecursiveValue": { "$recursiveRef": "#other" },
                "MissingRecursiveAnchor": { "$recursiveRef": "#" },
                "BadDynamicShape": { "$dynamicRef": true },
                "BadRecursiveShape": { "$recursiveRef": 7 },
                "BrokenDynamicUri": { "$dynamicRef": "http://[" }
            }),
        );

        let (_temp, ir, sink) = parse_value(&document);

        for name in [
            "BadRecursiveValue",
            "MissingRecursiveAnchor",
            "BadDynamicShape",
            "BadRecursiveShape",
            "BrokenDynamicUri",
        ] {
            assert!(matches!(
                schema_named(&ir, name),
                SchemaNode::Unknown { .. }
            ));
        }
        for (code, pointer) in [
            (
                CODE_RECURSIVE_REF_VALUE,
                "/components/schemas/BadRecursiveValue/$recursiveRef",
            ),
            (
                CODE_REFERENCE,
                "/components/schemas/MissingRecursiveAnchor/$recursiveRef",
            ),
            (
                CODE_SHAPE,
                "/components/schemas/BadDynamicShape/$dynamicRef",
            ),
            (
                CODE_SHAPE,
                "/components/schemas/BadRecursiveShape/$recursiveRef",
            ),
            (
                CODE_REFERENCE,
                "/components/schemas/BrokenDynamicUri/$dynamicRef",
            ),
        ] {
            assert!(sink.as_slice().iter().any(|diagnostic| {
                diagnostic.code == code && diagnostic.json_pointer.as_deref() == Some(pointer)
            }));
        }
    }

    #[test]
    fn dynamic_references_remain_rejected_but_preserve_typed_siblings_in_openapi_30() {
        let document = schemas_doc(
            "3.0.3",
            json!({
                "Dynamic": { "$dynamicRef": "#Node", "type": "string" },
                "Recursive": { "$recursiveRef": "#", "type": "string" }
            }),
        );

        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "Dynamic"),
            SchemaNode::Primitive { .. }
        ));
        assert!(matches!(
            schema_named(&ir, "Recursive"),
            SchemaNode::Primitive { .. }
        ));
        assert_eq!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_UNSUPPORTED)
                .count(),
            2
        );
    }

    #[test]
    fn static_dynamic_references_lower_to_their_exact_schema_targets() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "PlainTarget": { "$anchor": "Plain", "type": "string" },
                "BookendedAsPlain": { "$dynamicRef": "#Plain" },
                "DynamicTarget": {
                    "$id": "https://example.invalid/dynamic",
                    "$dynamicAnchor": "Node",
                    "type": "object",
                    "properties": {
                        "next": { "$dynamicRef": "#Node" }
                    }
                },
                "RecursiveTarget": {
                    "$id": "https://example.invalid/recursive",
                    "$recursiveAnchor": true,
                    "type": "object",
                    "properties": {
                        "next": { "$recursiveRef": "#" }
                    }
                },
                "RecursivePlain": {
                    "$id": "https://example.invalid/recursive-plain",
                    "$recursiveAnchor": false,
                    "type": "object",
                    "properties": {
                        "next": { "$recursiveRef": "#" }
                    }
                }
            }),
        );

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let mut refs = Vec::new();
        collect_schema_refs(schema_named(&ir, "BookendedAsPlain"), &mut refs);
        assert_eq!(refs[0].0.json_pointer, "/components/schemas/PlainTarget");

        for name in ["DynamicTarget", "RecursiveTarget", "RecursivePlain"] {
            let mut refs = Vec::new();
            collect_schema_refs(schema_named(&ir, name), &mut refs);
            assert!(
                refs.iter()
                    .any(|(target, _)| target.json_pointer == format!("/components/schemas/{name}")),
                "{name}: {refs:?}"
            );
        }
    }

    #[test]
    fn recursive_ref_without_id_targets_the_nearest_lexical_anchor() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "LexicalOuter": {
                    "$recursiveAnchor": true,
                    "type": "object",
                    "properties": {
                        "inner": {
                            "$recursiveAnchor": true,
                            "type": "object",
                            "properties": {
                                "next": { "$recursiveRef": "#" }
                            }
                        }
                    }
                }
            }),
        );

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let mut refs = Vec::new();
        collect_schema_refs(schema_named(&ir, "LexicalOuter"), &mut refs);
        assert!(refs.iter().any(|(target, _)| {
            target.json_pointer == "/components/schemas/LexicalOuter/properties/inner"
        }));
    }

    #[test]
    fn path_dependent_dynamic_references_warn_and_widen_to_unknown() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "DynamicFirst": {
                    "$id": "https://example.invalid/dynamic-first",
                    "$dynamicAnchor": "Node",
                    "type": "object",
                    "properties": {
                        "next": { "$dynamicRef": "#Node" }
                    }
                },
                "DynamicSecond": {
                    "$id": "https://example.invalid/dynamic-second",
                    "$dynamicAnchor": "Node"
                },
                "RecursiveFirst": {
                    "$id": "https://example.invalid/recursive-first",
                    "$recursiveAnchor": true,
                    "type": "object",
                    "properties": {
                        "next": { "$recursiveRef": "#" }
                    }
                },
                "RecursiveSecond": {
                    "$id": "https://example.invalid/recursive-second",
                    "$recursiveAnchor": true
                }
            }),
        );

        let (_temp, ir, sink) = parse_value(&document);

        for (name, pointer) in [
            (
                "DynamicFirst",
                "/components/schemas/DynamicFirst/properties/next/$dynamicRef",
            ),
            (
                "RecursiveFirst",
                "/components/schemas/RecursiveFirst/properties/next/$recursiveRef",
            ),
        ] {
            assert!(
                matches!(schema_named(&ir, name), SchemaNode::Object { properties, .. }
                if properties.iter().any(|(property, schema, _)|
                    property == "next" && matches!(schema, SchemaNode::Unknown { .. })))
            );
            let warning = sink
                .as_slice()
                .iter()
                .find(|diagnostic| {
                    diagnostic.code == CODE_DYNAMIC_SCOPE
                        && diagnostic.json_pointer.as_deref() == Some(pointer)
                })
                .expect("path-dependent reference should warn");
            assert_eq!(warning.severity, Severity::Warning);
            assert!(warning.message.contains("2 schema resources"));
        }
    }

    #[test]
    fn allof_with_sibling_properties_lowers_to_conjunction() {
        // allOf beside sibling `properties`/`required` is a conjunction: the sibling object shape is
        // a real branch parsed by the typed path, ordered last after the flattened allOf branches.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "allOf": [{ "$ref": "#/components/schemas/Base" }],
                    "properties": { "name": { "type": "string" } },
                    "required": ["name"]
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        // [flattened allOf branch: Ref, typed piece: Object] — typed piece last.
        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::AllOf { branches, .. }
                if branches.len() == 2
                    && matches!(branches[0], SchemaNode::Ref { .. })
                    && matches!(
                        &branches[1],
                        SchemaNode::Object { properties, .. }
                            if properties.iter().any(|(name, _, prop)| name == "name" && prop.required)
                    )
        ));
    }

    #[test]
    fn lowered_anyof_conjunction_carries_discriminator() {
        // An `anyOf` beside a typed sibling lowers to a conjunction; the discriminator must ride
        // along on the lowered `anyOf`, exactly as it does for `oneOf`.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "A": { "type": "object" },
                "B": { "type": "object" },
                "Wrapped": {
                    "anyOf": [{ "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" }],
                    "type": "object",
                    "properties": { "kind": { "type": "string" } },
                    "discriminator": { "propertyName": "kind" }
                }
            }),
        );
        let (_temp, ir, _sink) = parse_value(&document);
        assert!(matches!(
            schema_named(&ir, "Wrapped"),
            SchemaNode::AllOf { branches, .. }
                if branches.iter().any(|branch| matches!(
                    branch,
                    SchemaNode::AnyOf { discriminator: Some(discriminator), .. }
                        if discriminator.property_name == "kind"
                ))
        ));
    }

    #[test]
    fn oneof_and_anyof_conjunction_carries_single_discriminator() {
        // When oneOf, anyOf, and a discriminator coexist, the lowered conjunction attaches the
        // discriminator to the oneOf branch only (the conventional carrier). Attaching it to both
        // synthetic branches would run the downstream proof — and its OASTS1304 diagnostic — twice.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "A": { "type": "object" },
                "B": { "type": "object" },
                "Wrapped": {
                    "oneOf": [{ "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" }],
                    "anyOf": [{ "$ref": "#/components/schemas/A" }, { "$ref": "#/components/schemas/B" }],
                    "discriminator": { "propertyName": "kind" }
                }
            }),
        );
        let (_temp, ir, _sink) = parse_value(&document);
        // The oneOf branch carries the discriminator; the anyOf branch does not; exactly one branch
        // bears it, so the downstream proof runs once.
        assert!(matches!(
            schema_named(&ir, "Wrapped"),
            SchemaNode::AllOf { branches, .. }
                if branches.iter().any(|branch| matches!(
                    branch,
                    SchemaNode::OneOf { discriminator: Some(discriminator), .. }
                        if discriminator.property_name == "kind"
                ))
                    && branches.iter().any(|branch| matches!(
                        branch,
                        SchemaNode::AnyOf { discriminator: None, .. }
                    ))
                    && branches
                        .iter()
                        .filter(|branch| matches!(
                            branch,
                            SchemaNode::OneOf { discriminator: Some(_), .. }
                                | SchemaNode::AnyOf { discriminator: Some(_), .. }
                        ))
                        .count()
                        == 1
        ));
    }

    #[test]
    fn ref_with_structural_sibling_lowers_in_31() {
        // OpenAPI 3.1 treats `$ref` as one keyword among many, so a structural sibling composes.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "$ref": "#/components/schemas/Base",
                    "properties": { "name": { "type": "string" } }
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::AllOf { branches, .. }
                if branches.len() == 2
                    && matches!(branches[0], SchemaNode::Ref { .. })
                    && matches!(branches[1], SchemaNode::Object { .. })
        ));
        assert!(
            ref_sibling_warnings(&sink).is_empty(),
            "3.1 composes silently"
        );
    }

    #[test]
    fn ref_with_structural_sibling_warns_and_ignores_in_30() {
        // OpenAPI 3.0 substitutes the Reference Object, dropping siblings; the structural sibling
        // earns exactly one OASTS1110 warning at the node pointer, and the node stays a plain Ref.
        let document = schemas_doc(
            "3.0.3",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "$ref": "#/components/schemas/Base",
                    "properties": { "name": { "type": "string" } }
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(schema_named(&ir, "Thing"), SchemaNode::Ref { .. }));
        let warnings = ref_sibling_warnings(&sink);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert_eq!(
            warnings[0].json_pointer.as_deref(),
            Some("/components/schemas/Thing")
        );
    }

    #[test]
    fn ref_with_annotation_sibling_no_warning_in_30() {
        // Annotating a ref is legitimate in 3.0, so a pure-annotation sibling is silent.
        let document = schemas_doc(
            "3.0.3",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": { "$ref": "#/components/schemas/Base", "description": "a thing" }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(schema_named(&ir, "Thing"), SchemaNode::Ref { .. }));
        assert!(ref_sibling_warnings(&sink).is_empty());
    }

    #[test]
    fn ref_with_constraint_sibling_drops_validation_applicators_in_30() {
        let document = schemas_doc(
            "3.0.3",
            json!({
                "Base": { "type": "string" },
                "Thing": {
                    "$ref": "#/components/schemas/Base",
                    "not": { "type": "number" }
                }
            }),
        );
        let (_temp, ir, _sink) = parse_value(&document);
        let thing = schema_named(&ir, "Thing");

        assert!(matches!(thing, SchemaNode::Ref { .. }));
        assert!(thing.meta().validation_applicators.is_none());
    }

    #[test]
    fn single_applicator_shape_unchanged() {
        // The determinism guard: a single-piece schema parses to exactly its historical node, never
        // wrapped in a synthetic AllOf and never meta-split.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "PlainAllOf": { "allOf": [{ "$ref": "#/components/schemas/Base" }] },
                "PlainOneOf": { "oneOf": [{ "type": "string" }, { "type": "number" }] },
                "PlainObject": {
                    "type": "object",
                    "properties": { "x": { "type": "string" } },
                    "description": "d"
                },
                "PlainRef": { "$ref": "#/components/schemas/Base" }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(matches!(
            schema_named(&ir, "PlainAllOf"),
            SchemaNode::AllOf { branches, .. } if branches.len() == 1
        ));
        assert!(matches!(
            schema_named(&ir, "PlainOneOf"),
            SchemaNode::OneOf { .. }
        ));
        // Docs stay on the node — no split happened.
        assert!(matches!(
            schema_named(&ir, "PlainObject"),
            SchemaNode::Object { meta, .. } if meta.docs.description.as_deref() == Some("d")
        ));
        assert!(matches!(
            schema_named(&ir, "PlainRef"),
            SchemaNode::Ref { .. }
        ));
    }

    #[test]
    fn allof_sibling_constraint_lands_on_typed_branch() {
        // {allOf:[...], minLength:3}: the human-readable constraint documents the wrapper exactly
        // once, while the structured constraint rides the typed branch (validators enforce it
        // there) and is absent from the wrapper — the meta split, checked structurally.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "allOf": [{ "$ref": "#/components/schemas/Base" }],
                    "minLength": 3
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::AllOf { branches, meta }
                if meta.docs.constraints == ["minLength: 3".to_owned()]
                    && meta.string_constraints().min_length.is_none()
                    && branches
                        .last()
                        .is_some_and(|typed| typed.meta().string_constraints().min_length == Some(3))
        ));
    }

    #[test]
    fn tuple_piece_coexists_and_lowers() {
        // A prefixItems tuple beside another piece lowers via the tuple path; prefixItems is the
        // 3.1-only trigger for the typed piece.
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Base": { "type": "object", "properties": { "id": { "type": "string" } } },
                "Thing": {
                    "allOf": [{ "$ref": "#/components/schemas/Base" }],
                    "prefixItems": [{ "type": "string" }]
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::AllOf { branches, .. }
                if branches.len() == 2
                    && matches!(branches[0], SchemaNode::Ref { .. })
                    && matches!(branches[1], SchemaNode::Tuple { .. })
        ));
    }

    #[test]
    fn detects_supported_and_rejects_other_versions() {
        for version in ["3.0.3", "3.1.0"] {
            let (_temp, graph) = graph_for(&json!({ "openapi": version }));
            let mut sink = DiagnosticSink::new();
            assert!(detect_version(&graph, &mut sink).is_some());
            assert!(!sink.has_errors());
        }
        for document in [
            json!({ "openapi": "2.0" }),
            json!({ "openapi": "3.2.0" }),
            json!({}),
        ] {
            let (_temp, graph) = graph_for(&document);
            let mut sink = DiagnosticSink::new();
            assert!(detect_version(&graph, &mut sink).is_none());
            assert!(sink.has_errors());
        }
    }

    #[test]
    fn official_fixtures_parse_without_input_errors() {
        for name in ["petstore-3.0", "tictactoe-3.1"] {
            let (_config, graph) = load_fixture(name);
            let mut sink = DiagnosticSink::new();
            let ir = parse(&graph, &mut sink).expect("supported fixture");
            assert!(!ir.schemas.is_empty());
            assert!(!ir.operations.is_empty());
            assert!(!sink.has_errors(), "{name}: {:?}", sink.as_slice());
        }
    }

    #[test]
    fn preserves_schema_and_response_source_order() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/ordered": {
                    "get": {
                        "responses": {
                            "404": { "description": "missing" },
                            "200": { "description": "ok" },
                            "default": { "description": "fallback" }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Zebra": { "type": "string" },
                    "Alpha": { "type": "string" }
                }
            }
        });
        let (_temp, graph) = graph_for(&document);
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");
        assert_eq!(
            ir.schemas
                .iter()
                .map(|schema| schema.name.as_str())
                .collect::<Vec<_>>(),
            ["Zebra", "Alpha"]
        );
        assert_eq!(
            ir.operations[0]
                .responses
                .iter()
                .map(|response| response.status.clone())
                .collect::<Vec<_>>(),
            [
                ResponseStatus::Exact("404".to_owned()),
                ResponseStatus::Exact("200".to_owned()),
                ResponseStatus::Default,
            ]
        );
    }

    #[test]
    fn drops_reserved_header_parameters_before_path_operation_merging() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/headers": {
                    "parameters": [
                        { "name": "Content-TYPE", "in": "header", "schema": { "type": "string" } },
                        { "name": "keep-path", "in": "header", "schema": { "type": "string" } }
                    ],
                    "get": {
                        "parameters": [
                            { "name": "authorization", "in": "header", "schema": { "type": "string" } },
                            { "name": "AcCePt", "in": "header", "schema": { "type": "string" } },
                            { "name": "keep-operation", "in": "header", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert_eq!(
            ir.operations[0]
                .parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<Vec<_>>(),
            ["keep-path", "keep-operation"]
        );
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1109")
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 3);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning)
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/paths/~1headers/parameters/0")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/paths/~1headers/get/parameters/0")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref() == Some("/paths/~1headers/get/parameters/1")
        }));
        assert!(!sink.has_errors());
    }

    #[test]
    fn keeps_fetch_forbidden_header_parameters_in_the_ir() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/headers": {
                    "parameters": [
                        { "name": "Cookie", "in": "header", "schema": { "type": "string" } },
                        { "name": "Host", "in": "header", "required": true, "schema": { "type": "string" } },
                        { "name": "Accept", "in": "header", "schema": { "type": "string" } },
                        { "name": "Cookie", "in": "cookie", "required": true, "schema": { "type": "string" } }
                    ],
                    "get": {
                        "parameters": [
                            { "name": "cookie", "in": "header", "required": true, "schema": { "type": "string" } },
                            { "name": "X-Safe", "in": "header", "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        assert_eq!(
            ir.operations[0]
                .parameters
                .iter()
                .map(|parameter| (parameter.name.as_str(), parameter.location))
                .collect::<Vec<_>>(),
            [
                ("Cookie", ParamLocation::Header),
                ("Host", ParamLocation::Header),
                ("Cookie", ParamLocation::Cookie),
                ("cookie", ParamLocation::Header),
                ("X-Safe", ParamLocation::Header)
            ]
        );
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| diagnostic.code != "OASTS1411")
        );
        assert_eq!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == "OASTS1109")
                .count(),
            1
        );
        assert!(!sink.has_errors());
    }

    #[test]
    fn canonicalizes_valid_media_keys_with_parameters_and_rejects_malformed_keys() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/media": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "Application/JSON": { "schema": { "type": "string" } },
                                "TEXT/*": { "schema": { "type": "string" } },
                                "*/*": { "schema": { "type": "string" } },
                                "application/json; charset=utf-8": { "schema": { "type": "string" } },
                                "*/json": { "schema": { "type": "string" } },
                                "missing-slash": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "IMAGE/PNG": { "schema": { "type": "string" } },
                                    "image/png;quality=high": { "schema": { "type": "string" } },
                                    "image/(png)": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let operation = &ir.operations[0];
        let request_media = &operation
            .request_body
            .as_ref()
            .expect("request body")
            .media_types;
        assert_eq!(
            request_media
                .iter()
                .map(|media| {
                    (
                        media.essence.as_str(),
                        media.full.as_str(),
                        media.raw_name.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("application/json", "application/json", "Application/JSON"),
                ("text/*", "text/*", "TEXT/*"),
                ("*/*", "*/*", "*/*"),
                (
                    "application/json",
                    "application/json;charset=utf-8",
                    "application/json; charset=utf-8"
                ),
            ]
        );
        assert_eq!(
            operation.responses[0]
                .media_types
                .iter()
                .map(|media| {
                    (
                        media.essence.as_str(),
                        media.full.as_str(),
                        media.raw_name.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("image/png", "image/png", "IMAGE/PNG"),
                (
                    "image/png",
                    "image/png;quality=high",
                    "image/png;quality=high"
                ),
            ]
        );

        let invalid = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1107")
            .collect::<Vec<_>>();
        assert_eq!(invalid.len(), 3);
        assert!(
            invalid
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Warning),
            "malformed content keys are unusable branches and are dropped"
        );
        assert!(
            invalid
                .iter()
                .all(|diagnostic| diagnostic.message.contains("malformed"))
        );
        assert!(invalid.iter().all(|diagnostic| {
            diagnostic.source_id.is_some() && diagnostic.json_pointer.is_some()
        }));
        assert!(
            sink.as_slice()
                .iter()
                .all(|diagnostic| diagnostic.code != CODE_DUPLICATE_MEDIA_TYPE)
        );
    }

    #[test]
    fn parameterized_content_key_preserves_quoted_value_in_canonical_full_name() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/watch": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "Application/JSON; stream=watch; Note=\"a;b\"": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        let media = &ir.operations[0].responses[0].media_types[0];
        assert_eq!(media.essence, "application/json");
        assert_eq!(media.full, "application/json;note=\"a;b\";stream=watch");
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn malformed_content_key_warns_and_drops_the_entry_without_erroring() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/watch": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "string": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        // The unusable content key is dropped, leaving the no-content branch.
        assert!(ir.operations[0].responses[0].media_types.is_empty());

        let warnings = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1107")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert!(warnings[0].message.contains("malformed"));
        assert!(!sink.has_errors());
    }

    #[test]
    fn parameterized_media_ranges_warn_and_drop_while_bare_ranges_survive() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/ranges": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "text/*": { "schema": { "type": "string" } },
                                    "text/*; q=0.5": { "schema": { "type": "string" } },
                                    "*/*": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);

        // The bare ranges keep their branches; the parameterized range is dropped.
        let essences = ir.operations[0].responses[0]
            .media_types
            .iter()
            .map(|media| media.essence.as_str())
            .collect::<Vec<_>>();
        assert_eq!(essences, ["text/*", "*/*"]);

        let warnings = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1107")
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert!(warnings[0].message.contains("text/*; q=0.5"));
        assert!(!sink.has_errors());
    }

    #[test]
    fn duplicate_canonical_media_keys_diagnose_the_second_and_drop_both() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/duplicate": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "Application/JSON; Charset=utf-8; version=1": { "schema": { "type": "string" } },
                                "application/json;VERSION=1;charset=utf-8": { "schema": { "type": "integer" } },
                                "text/plain": { "schema": { "type": "string" } }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "TEXT/*": { "schema": { "type": "string" } },
                                    "text/*": { "schema": { "type": "integer" } },
                                    "image/*": { "schema": { "type": "string" } }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let operation = &ir.operations[0];
        assert_eq!(
            operation
                .request_body
                .as_ref()
                .expect("request body")
                .media_types[0]
                .essence,
            "text/plain"
        );
        assert_eq!(operation.responses[0].media_types[0].essence, "image/*");

        let duplicates = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1108")
            .collect::<Vec<_>>();
        assert_eq!(duplicates.len(), 2);
        assert!(
            duplicates
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Error)
        );
        assert!(duplicates.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some("/paths/~1duplicate/post/requestBody/content/application~1json;VERSION=1;charset=utf-8")
                && diagnostic
                    .message
                    .contains("Application/JSON; Charset=utf-8; version=1")
                && diagnostic
                    .message
                    .contains("application/json;VERSION=1;charset=utf-8")
                && diagnostic
                    .message
                    .contains("application/json;charset=utf-8;version=1")
        }));
        assert!(duplicates.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some("/paths/~1duplicate/post/responses/200/content/text~1*")
                && diagnostic.message.contains("TEXT/*")
                && diagnostic.message.contains("text/*")
        }));
        assert!(sink.has_errors());
    }

    #[test]
    fn parses_streaming_media_type_extension_only_from_boolean_true() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/streaming": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/marked": {
                                    "x-oasts-streaming": true,
                                    "schema": { "type": "string" }
                                },
                                "application/unmarked": {
                                    "x-oasts-streaming": false,
                                    "schema": { "type": "string" }
                                },
                                "application/non-boolean": {
                                    "x-oasts-streaming": "true",
                                    "schema": { "type": "string" }
                                },
                                "application/absent": {
                                    "schema": { "type": "string" }
                                }
                            }
                        },
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let media_types = &ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types;

        assert!(media_types[0].streaming_marked);
        assert!(!media_types[1].streaming_marked);
        assert!(!media_types[2].streaming_marked);
        assert!(!media_types[3].streaming_marked);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn preserves_client_media_and_schema_facts_needed_after_parsing() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/facts": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "encoded": {
                                                "type": "string",
                                                "contentEncoding": "8bit"
                                            }
                                        }
                                    },
                                    "encoding": {
                                        "encoded": { "allowReserved": false }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "schema optional",
                                "content": { "text/plain": {} }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let operation = &ir.operations[0];
        let request_media = &operation
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0];
        let first_property_content_encoding = |schema: &SchemaNode| match schema {
            SchemaNode::Object { properties, .. } => {
                properties[0].1.meta().content_encoding.clone()
            }
            _ => None,
        };
        assert_eq!(
            first_property_content_encoding(&request_media.schema),
            Some("8bit".to_owned())
        );
        assert_eq!(
            first_property_content_encoding(&operation.responses[0].media_types[0].schema),
            None
        );
        assert!(request_media.encodings[0].1.allow_reserved_explicit);
        assert!(request_media.schema_present);
        assert!(!operation.responses[0].media_types[0].schema_present);
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn parses_all_parameter_serialization_styles_without_applying_defaults() {
        let styles = [
            "form",
            "simple",
            "label",
            "matrix",
            "spaceDelimited",
            "pipeDelimited",
            "deepObject",
            "invalid",
        ];
        let parameters = styles
            .iter()
            .enumerate()
            .map(|(index, style)| {
                json!({
                    "name": format!("parameter-{index}"),
                    "in": "query",
                    "style": style,
                    "explode": index == 0,
                    "allowReserved": index == 0,
                    "schema": { "type": "string" }
                })
            })
            .chain([json!({
                "name": "defaults",
                "in": "query",
                "schema": { "type": "string" }
            })])
            .collect::<Vec<_>>();
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/styles": {
                    "get": {
                        "parameters": parameters,
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let parameters = &ir.operations[0].parameters;
        assert_eq!(
            parameters
                .iter()
                .take(8)
                .map(|parameter| parameter.style)
                .collect::<Vec<_>>(),
            [
                Some(ParamStyle::Form),
                Some(ParamStyle::Simple),
                Some(ParamStyle::Label),
                Some(ParamStyle::Matrix),
                Some(ParamStyle::SpaceDelimited),
                Some(ParamStyle::PipeDelimited),
                Some(ParamStyle::DeepObject),
                None,
            ]
        );
        assert_eq!(parameters[0].explode, Some(true));
        assert!(parameters[0].allow_reserved);
        assert_eq!(parameters[1].explode, Some(false));
        assert!(!parameters[1].allow_reserved);
        assert_eq!(parameters[8].explode, None);
        assert!(!parameters[8].allow_reserved);
        assert!(
            parameters
                .iter()
                .all(|parameter| parameter.content_media_type.is_none())
        );
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref()
                    == Some("/paths/~1styles/get/parameters/7/style")
                && diagnostic.message.contains("parameter.style")
        }));
    }

    fn document_with_parameter(parameter: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": {
                "/parameter": {
                    "get": {
                        "parameters": [parameter],
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        })
    }

    #[test]
    fn parameter_content_parses_schema_and_ignores_serialization_fields() {
        let document = document_with_parameter(json!({
            "name": "filter",
            "in": "query",
            "content": {
                "Application/JSON": { "schema": { "type": "integer" } }
            },
            "style": "invalid",
            "explode": true,
            "allowReserved": true
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let parameter = &ir.operations[0].parameters[0];

        assert_eq!(
            parameter.content_media_type.as_deref(),
            Some("application/json")
        );
        assert!(matches!(
            parameter.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Integer,
                ..
            }
        ));
        assert_eq!(parameter.style, None);
        assert_eq!(parameter.explode, None);
        assert!(!parameter.allow_reserved);
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn parameter_content_with_two_entries_is_a_shape_error() {
        let document = document_with_parameter(json!({
            "name": "filter",
            "in": "query",
            "content": {
                "application/json": { "schema": { "type": "integer" } },
                "text/plain": { "schema": { "type": "string" } }
            }
        }));
        let (_temp, _ir, sink) = parse_value(&document);

        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.message == "parameter content map must contain exactly one entry"
        }));
        assert!(sink.has_errors());
    }

    #[test]
    fn parameter_without_schema_or_content_keeps_unsupported_warning() {
        for parameter in [
            json!({ "name": "filter", "in": "query" }),
            json!({ "name": "filter", "in": "query", "content": {} }),
        ] {
            let document = document_with_parameter(parameter);
            let (_temp, ir, sink) = parse_value(&document);
            let parameter = &ir.operations[0].parameters[0];

            assert_eq!(parameter.content_media_type, None);
            assert!(matches!(parameter.schema, SchemaNode::Unknown { .. }));
            assert!(sink.as_slice().iter().any(|diagnostic| {
                diagnostic.code == CODE_UNSUPPORTED
                    && diagnostic.json_pointer.as_deref()
                        == Some("/paths/~1parameter/get/parameters/0/schema")
            }));
        }
    }

    #[test]
    fn malformed_parameter_content_shape_or_key_is_diagnosed_and_dropped() {
        for (content, code) in [
            (json!([]), CODE_SHAPE),
            (
                json!({ "missing-slash": { "schema": { "type": "string" } } }),
                CODE_MEDIA_TYPE,
            ),
        ] {
            let document = document_with_parameter(json!({
                "name": "filter",
                "in": "query",
                "content": content
            }));
            let (_temp, ir, sink) = parse_value(&document);

            assert!(ir.operations[0].parameters.is_empty());
            assert!(
                sink.as_slice()
                    .iter()
                    .any(|diagnostic| diagnostic.code == code)
            );
            assert!(
                sink.as_slice()
                    .iter()
                    .all(|diagnostic| { diagnostic.code != CODE_UNSUPPORTED })
            );
        }
    }

    #[test]
    fn parses_applicable_request_encoding_objects_and_resolves_headers() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/encoding": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "APPLICATION/X-WWW-FORM-URLENCODED": {
                                    "schema": { "type": "object" },
                                    "encoding": {
                                        "field-a": {
                                            "contentType": "application/json; note=\"a,b\", text/plain, application/xml",
                                            "headers": {
                                                "X-Required": { "$ref": "#/components/headers/Required" },
                                                "X-Optional": { "schema": { "type": "integer" } }
                                            },
                                            "style": "deepObject",
                                            "explode": true,
                                            "allowReserved": true
                                        },
                                        "field-b": {}
                                    }
                                },
                                "MULTIPART/FORM-DATA": {
                                    "schema": { "type": "object" },
                                    "encoding": { "upload": { "style": "form" } }
                                },
                                "application/json": {
                                    "schema": { "type": "object" },
                                    "encoding": { "ignored": { "style": "simple" } }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "multipart/mixed": {
                                        "schema": { "type": "object" },
                                        "encoding": { "ignored-response": { "style": "form" } }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "headers": {
                    "Required": { "required": true, "schema": { "type": "string" } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let media_types = &ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types;
        let form = media_types
            .iter()
            .find(|media| media.essence == "application/x-www-form-urlencoded")
            .expect("form media type");
        assert_eq!(
            form.encodings
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["field-a", "field-b"]
        );
        let encoding = &form.encodings[0].1;
        assert_eq!(
            encoding.content_type,
            Some(vec![
                "application/json; note=\"a,b\"".to_owned(),
                "text/plain".to_owned(),
                "application/xml".to_owned(),
            ])
        );
        assert_eq!(encoding.style, Some(ParamStyle::DeepObject));
        assert_eq!(encoding.explode, Some(true));
        assert!(encoding.allow_reserved);
        assert_eq!(
            encoding
                .headers
                .iter()
                .map(|(name, header)| (name.as_str(), header.required))
                .collect::<Vec<_>>(),
            [("X-Required", true), ("X-Optional", false)]
        );
        assert_eq!(
            encoding.headers[0].1.source.json_pointer,
            "/components/headers/Required"
        );
        assert!(
            encoding
                .headers
                .iter()
                .all(|(_, header)| header.content_media_type.is_none())
        );
        assert!(matches!(
            encoding.headers[0].1.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            }
        ));
        assert_eq!(form.encodings[1].1.content_type, None);
        assert_eq!(form.encodings[1].1.explode, None);
        assert!(!form.encodings[1].1.allow_reserved);

        let multipart = media_types
            .iter()
            .find(|media| media.essence == "multipart/form-data")
            .expect("multipart media type");
        assert_eq!(multipart.encodings[0].1.style, Some(ParamStyle::Form));
        assert!(
            media_types
                .iter()
                .find(|media| media.essence == "application/json")
                .expect("JSON media type")
                .encodings
                .is_empty()
        );
        assert!(
            ir.operations[0].responses[0].media_types[0]
                .encodings
                .is_empty()
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    fn document_with_encoding_header(header: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "paths": {
                "/encoding-header": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": { "type": "object" },
                                    "encoding": {
                                        "field": { "headers": { "X-Field": header } }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            }
        })
    }

    #[test]
    fn encoding_header_content_parses_schema_without_unsupported_warning() {
        let document = document_with_encoding_header(json!({
            "content": {
                "Application/JSON; Charset=UTF-8": {
                    "schema": { "type": "boolean" }
                }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let header = &ir.operations[0]
            .request_body
            .as_ref()
            .expect("request body")
            .media_types[0]
            .encodings[0]
            .1
            .headers[0]
            .1;

        assert_eq!(
            header.content_media_type.as_deref(),
            Some("application/json;charset=utf-8")
        );
        assert!(matches!(
            header.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Boolean,
                ..
            }
        ));
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn encoding_header_content_with_two_entries_is_a_shape_error() {
        let document = document_with_encoding_header(json!({
            "content": {
                "application/json": { "schema": { "type": "boolean" } },
                "text/plain": { "schema": { "type": "string" } }
            }
        }));
        let (_temp, _ir, sink) = parse_value(&document);

        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.message
                    == "encoding header content map must contain exactly one entry"
        }));
        assert!(sink.has_errors());
    }

    #[test]
    fn encoding_header_without_schema_or_content_keeps_unsupported_warning() {
        for value in [json!({}), json!({ "content": {} })] {
            let document = document_with_encoding_header(value);
            let (_temp, ir, sink) = parse_value(&document);
            let header = &ir.operations[0]
                .request_body
                .as_ref()
                .expect("request body")
                .media_types[0]
                .encodings[0]
                .1
                .headers[0]
                .1;

            assert_eq!(header.content_media_type, None);
            assert!(matches!(header.schema, SchemaNode::Unknown { .. }));
            assert!(sink.as_slice().iter().any(|diagnostic| {
                diagnostic.code == CODE_UNSUPPORTED
                    && diagnostic.json_pointer.as_deref()
                        == Some(
                            "/paths/~1encoding-header/post/requestBody/content/multipart~1form-data/encoding/field/headers/X-Field/schema"
                        )
            }));
        }
    }

    fn document_with_response(response: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/response": {
                    "get": { "responses": { "200": response } }
                }
            },
            "components": {
                "headers": {
                    "Referenced": {
                        "required": true,
                        "deprecated": true,
                        "description": "referenced header",
                        "schema": { "type": "boolean" }
                    }
                }
            }
        })
    }

    #[test]
    fn response_headers_parse_required_optional_and_ref() {
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "X-Required": {
                    "required": true,
                    "description": "required header",
                    "schema": { "type": "string" }
                },
                "x-optional": { "schema": { "type": "integer" } },
                "X-Referenced": { "$ref": "#/components/headers/Referenced" }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let headers = &ir.operations[0].responses[0].headers;

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(
            headers
                .iter()
                .map(|(name, header)| {
                    (
                        name.as_str(),
                        header.required,
                        header.deprecated,
                        header.description.as_deref(),
                    )
                })
                .collect::<Vec<_>>(),
            [
                ("X-Required", true, false, Some("required header")),
                ("x-optional", false, false, None),
                ("X-Referenced", true, true, Some("referenced header")),
            ]
        );
        assert!(matches!(
            headers[0].1.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            }
        ));
        assert!(matches!(
            headers[1].1.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Integer,
                ..
            }
        ));
        assert!(matches!(
            headers[2].1.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::Boolean,
                ..
            }
        ));
        assert_eq!(
            headers[2].1.source.json_pointer,
            "/components/headers/Referenced"
        );
        assert!(
            headers
                .iter()
                .all(|(_, header)| header.content_media_type.is_none())
        );
    }

    #[test]
    fn response_header_content_parses_schema_without_unsupported_warning() {
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "X-Content": {
                    "content": {
                        "Application/JSON; Charset=UTF-8": {
                            "schema": { "type": "string" }
                        }
                    }
                }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let header = &ir.operations[0].responses[0].headers[0].1;

        assert_eq!(
            header.content_media_type.as_deref(),
            Some("application/json;charset=utf-8")
        );
        assert!(matches!(
            header.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            }
        ));
        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn response_header_content_with_two_entries_is_a_shape_error() {
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "X-Content": {
                    "content": {
                        "application/json": { "schema": { "type": "string" } },
                        "text/plain": { "schema": { "type": "string" } }
                    }
                }
            }
        }));
        let (_temp, _ir, sink) = parse_value(&document);

        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.message
                    == "response header content map must contain exactly one entry"
        }));
        assert!(sink.has_errors());
    }

    #[test]
    fn response_header_without_schema_or_content_keeps_unsupported_warning() {
        for value in [json!({}), json!({ "content": {} })] {
            let document = document_with_response(json!({
                "description": "ok",
                "headers": { "X-Missing": value }
            }));
            let (_temp, ir, sink) = parse_value(&document);
            let diagnostic = sink
                .as_slice()
                .iter()
                .find(|diagnostic| diagnostic.code == CODE_UNSUPPORTED)
                .expect("unsupported schema warning");

            assert_eq!(diagnostic.severity, Severity::Warning);
            assert_eq!(
                diagnostic.json_pointer.as_deref(),
                Some("/paths/~1response/get/responses/200/headers/X-Missing/schema")
            );
            assert!(ir.operations[0].responses[0].headers.is_empty());
        }
    }

    #[test]
    fn response_header_content_type_dropped_with_warning() {
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "content-TYPE": { "schema": { "type": "string" } }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_HEADER_CONTENT_TYPE)
            .expect("Content-Type warning");

        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1response/get/responses/200/headers/content-TYPE")
        );
        assert!(ir.operations[0].responses[0].headers.is_empty());
    }

    #[test]
    fn response_header_case_duplicate_is_error() {
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "X-Rate-Limit": { "schema": { "type": "integer" } },
                "x-rate-limit": { "schema": { "type": "string" } }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_HEADER_DUPLICATE)
            .expect("duplicate header error");

        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1response/get/responses/200/headers/x-rate-limit")
        );
        assert_eq!(
            diagnostic.message,
            "response header 'x-rate-limit' conflicts case-insensitively with 'X-Rate-Limit'"
        );
        assert_eq!(ir.operations[0].responses[0].headers.len(), 1);
        assert_eq!(ir.operations[0].responses[0].headers[0].0, "X-Rate-Limit");
    }

    #[test]
    fn links_parse_operation_id_and_ref_forms() {
        let document = document_with_response(json!({
            "description": "ok",
            "links": {
                "ById": {
                    "operationId": "getThing",
                    "parameters": {
                        "id": "{$request.body#/id}",
                        "limit": 10
                    },
                    "description": "lookup"
                },
                "ByRef": { "operationRef": "#/paths/~1things~1{id}/get" }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let links = &ir.operations[0].responses[0].links;

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].name, "ById");
        assert_eq!(
            links[0].target,
            LinkTarget::OperationId("getThing".to_owned())
        );
        assert_eq!(
            links[0].parameters,
            [
                ("id".to_owned(), "{$request.body#/id}".to_owned()),
                ("limit".to_owned(), "10".to_owned()),
            ]
        );
        assert_eq!(links[0].description.as_deref(), Some("lookup"));
        assert_eq!(
            links[1].target,
            LinkTarget::OperationRef("#/paths/~1things~1{id}/get".to_owned())
        );
        assert!(links[1].parameters.is_empty());
    }

    #[test]
    fn link_with_both_targets_is_error() {
        let document = document_with_response(json!({
            "description": "ok",
            "links": {
                "Ambiguous": { "operationId": "getThing", "operationRef": "#/paths/~1things/get" }
            }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_LINK_TARGET)
            .expect("link target error");

        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1response/get/responses/200/links/Ambiguous")
        );
        assert_eq!(
            diagnostic.message,
            "link 'Ambiguous' declares both operationId and operationRef"
        );
        assert!(ir.operations[0].responses[0].links.is_empty());
    }

    #[test]
    fn link_with_neither_target_is_error() {
        let document = document_with_response(json!({
            "description": "ok",
            "links": { "Missing": { "description": "no target" } }
        }));
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_LINK_TARGET)
            .expect("link target error");

        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/paths/~1response/get/responses/200/links/Missing")
        );
        assert_eq!(
            diagnostic.message,
            "link 'Missing' declares neither operationId nor operationRef"
        );
        assert!(ir.operations[0].responses[0].links.is_empty());
    }

    #[test]
    fn malformed_response_header_and_link_shapes_are_diagnosed_and_dropped() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/response": {
                    "get": {
                        "responses": {
                            "200": { "description": "bad headers map", "headers": [] },
                            "201": {
                                "description": "bad header entries",
                                "headers": {
                                    "Scalar": 7,
                                    "ResolvedScalar": { "$ref": "#/components/headers/Scalar" }
                                }
                            },
                            "202": { "description": "bad links map", "links": [] },
                            "203": {
                                "description": "bad link entry",
                                "links": { "Scalar": 7 }
                            }
                        }
                    }
                }
            },
            "components": { "headers": { "Scalar": 7 } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_SHAPE)
            .collect::<Vec<_>>();

        assert_eq!(diagnostics.len(), 4, "{:#?}", sink.as_slice());
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.severity == Severity::Error)
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.json_pointer.as_deref())
                .collect::<Vec<_>>(),
            [
                "/paths/~1response/get/responses/200/headers",
                "/paths/~1response/get/responses/201/headers/Scalar",
                "/paths/~1response/get/responses/202/links",
                "/paths/~1response/get/responses/203/links/Scalar",
            ]
        );
        assert!(
            ir.operations
                .iter()
                .flat_map(|operation| &operation.responses)
                .all(|response| response.headers.is_empty() && response.links.is_empty())
        );
    }

    #[test]
    fn response_header_external_ref_materializes() {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        let document = document_with_response(json!({
            "description": "ok",
            "headers": {
                "X-External": { "schema": { "$ref": "schemas.json#/HeaderValue" } }
            }
        }));
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config json"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(&document).expect("document json"),
        )
        .expect("write document");
        std::fs::write(
            temp.path().join("schemas.json"),
            br#"{"HeaderValue":{"type":"string"}}"#,
        )
        .expect("write external schema");
        let resolved =
            load_config(Some(Path::new("oasts.json")), temp.path()).expect("resolved config");
        let mut load_sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut load_sink).expect("graph");
        assert!(!load_sink.has_errors(), "{:#?}", load_sink.as_slice());
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        assert!(matches!(
            ir.operations[0].responses[0].headers[0].1.schema,
            SchemaNode::Ref { .. }
        ));
        let materialized = ir
            .schemas
            .iter()
            .find(|schema| schema.name == "HeaderValue")
            .expect("external header schema materialized");
        assert!(matches!(
            materialized.schema,
            SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            }
        ));
    }

    #[test]
    fn synthesizes_default_root_server_when_servers_are_absent_or_empty() {
        for document in [
            json!({ "openapi": "3.1.0" }),
            json!({ "openapi": "3.1.0", "servers": [] }),
        ] {
            let (_temp, ir, sink) = parse_value(&document);

            assert_eq!(ir.root_servers.len(), 1);
            assert_eq!(ir.root_servers[0].url, "/");
            assert!(ir.root_servers[0].variables.is_empty());
            assert_eq!(ir.root_servers[0].source.json_pointer, "");
            assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        }
    }

    #[test]
    fn parses_root_servers_and_operation_over_path_server_inheritance() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [
                {
                    "url": "https://{region}.example.test/{version}",
                    "variables": {
                        "region": { "default": "us", "enum": ["us", "eu"] },
                        "version": { "default": "v1" }
                    }
                }
            ],
            "paths": {
                "/inherited": {
                    "servers": [{ "url": "https://path.example.test" }],
                    "get": { "responses": { "204": { "description": "empty" } } },
                    "post": {
                        "servers": [],
                        "responses": { "204": { "description": "empty" } }
                    },
                    "put": {
                        "servers": [{ "url": "https://operation.example.test" }],
                        "responses": { "204": { "description": "empty" } }
                    }
                },
                "/root-fallback-later": {
                    "get": { "responses": { "204": { "description": "empty" } } }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(
            ir.root_servers[0].url,
            "https://{region}.example.test/{version}"
        );
        assert_eq!(
            ir.root_servers[0]
                .variables
                .iter()
                .map(|(name, variable)| (name.as_str(), variable.default.as_str()))
                .collect::<Vec<_>>(),
            [("region", "us"), ("version", "v1")]
        );
        assert_eq!(ir.root_servers[0].variables[0].1.enum_values, ["us", "eu"]);
        let operation = |method: &str| {
            ir.operations
                .iter()
                .find(|operation| operation.method == method)
                .expect("operation")
        };
        assert_eq!(operation("get").servers[0].url, "https://path.example.test");
        assert!(operation("post").servers.is_empty());
        assert_eq!(
            operation("put").servers[0].url,
            "https://operation.example.test"
        );
        let root_fallback = ir
            .operations
            .iter()
            .find(|operation| {
                operation.method == "get"
                    && operation
                        .source
                        .json_pointer
                        .contains("root-fallback-later")
            })
            .expect("root fallback operation");
        assert!(root_fallback.servers.is_empty());
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn server_variable_empty_enum_errors_in_31() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{
                "url": "https://{region}.example.test",
                "variables": { "region": { "default": "us", "enum": [] } }
            }]
        });
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SERVER_VAR_ENUM_EMPTY)
            .expect("empty enum diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/servers/0/variables/region/enum")
        );
        assert!(sink.has_errors());
        assert!(ir.root_servers[0].variables[0].1.enum_values.is_empty());
    }

    #[test]
    fn server_variable_empty_enum_warns_in_30() {
        let document = json!({
            "openapi": "3.0.3",
            "servers": [{
                "url": "https://{region}.example.test",
                "variables": { "region": { "default": "us", "enum": [] } }
            }]
        });
        let (_temp, _ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SERVER_VAR_ENUM_EMPTY)
            .expect("empty enum diagnostic");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/servers/0/variables/region/enum")
        );
        assert!(!sink.has_errors());
    }

    #[test]
    fn server_variable_default_not_in_enum_errors_in_31() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{
                "url": "https://{region}.example.test",
                "variables": { "region": { "default": "ap", "enum": ["us", "eu"] } }
            }]
        });
        let (_temp, _ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SERVER_VAR_DEFAULT)
            .expect("default membership diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/servers/0/variables/region/default")
        );
        assert!(sink.has_errors());
    }

    #[test]
    fn server_variable_default_not_in_enum_warns_in_30() {
        let document = json!({
            "openapi": "3.0.3",
            "servers": [{
                "url": "https://{region}.example.test",
                "variables": { "region": { "default": "ap", "enum": ["us", "eu"] } }
            }]
        });
        let (_temp, _ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SERVER_VAR_DEFAULT)
            .expect("default membership diagnostic");
        assert_eq!(diagnostic.severity, Severity::Warning);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/servers/0/variables/region/default")
        );
        assert!(!sink.has_errors());
    }

    #[test]
    fn server_variable_valid_enum_and_default_clean() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": [{
                "url": "https://{region}.example.test/{version}",
                "variables": {
                    "region": { "default": "us", "enum": ["us", "eu"] },
                    "version": { "default": "v1" }
                }
            }]
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(sink.as_slice(), []);
        assert_eq!(ir.root_servers[0].variables.len(), 2);
        assert_eq!(ir.root_servers[0].variables[0].1.default, "us");
        assert_eq!(ir.root_servers[0].variables[0].1.enum_values, ["us", "eu"]);
        assert_eq!(ir.root_servers[0].variables[1].1.default, "v1");
        assert!(ir.root_servers[0].variables[1].1.enum_values.is_empty());
    }

    #[test]
    fn parses_security_requirements_and_every_security_scheme_kind() {
        let document = json!({
            "openapi": "3.1.0",
            "security": [
                { "oauth": ["read", "write"], "queryKey": [] },
                {}
            ],
            "x-http": { "type": "http", "scheme": "digest" },
            "paths": {
                "/security": {
                    "get": { "responses": { "204": { "description": "empty" } } },
                    "post": {
                        "security": [],
                        "responses": { "204": { "description": "empty" } }
                    },
                    "put": {
                        "security": [{ "mutual": [] }, {}],
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "http": { "type": "http", "scheme": "bearer" },
                    "httpDefault": { "type": "http" },
                    "queryKey": { "type": "apiKey", "in": "query", "name": "key" },
                    "headerKey": { "type": "apiKey", "in": "header", "name": "X-Key" },
                    "cookieKey": { "type": "apiKey", "in": "cookie", "name": "session" },
                    "badKey": { "type": "apiKey", "in": "path", "name": "bad" },
                    "oauth": { "type": "oauth2" },
                    "openid": { "type": "openIdConnect" },
                    "mutual": { "type": "mutualTLS" },
                    "other": { "type": "custom" },
                    "referenced": { "$ref": "#/x-http" }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(
            ir.root_security,
            vec![
                vec![
                    (
                        "oauth".to_owned(),
                        vec!["read".to_owned(), "write".to_owned()]
                    ),
                    ("queryKey".to_owned(), Vec::new())
                ],
                Vec::new()
            ]
        );
        let operation = |method: &str| {
            ir.operations
                .iter()
                .find(|operation| operation.method == method)
                .expect("operation")
        };
        assert_eq!(operation("get").security, None);
        assert_eq!(operation("post").security, Some(Vec::new()));
        assert_eq!(
            operation("put").security,
            Some(vec![vec![("mutual".to_owned(), Vec::new())], Vec::new()])
        );
        assert_eq!(
            ir.security_schemes
                .iter()
                .map(|scheme| scheme.name.as_str())
                .collect::<Vec<_>>(),
            [
                "http",
                "httpDefault",
                "queryKey",
                "headerKey",
                "cookieKey",
                "badKey",
                "oauth",
                "openid",
                "mutual",
                "other",
                "referenced"
            ]
        );
        assert_eq!(
            ir.security_schemes
                .iter()
                .map(|scheme| scheme.kind.clone())
                .collect::<Vec<_>>(),
            [
                SecKind::Http {
                    scheme: "bearer".to_owned(),
                    bearer_format: None
                },
                SecKind::Http {
                    scheme: String::new(),
                    bearer_format: None
                },
                SecKind::ApiKey {
                    location: ParamLocation::Query,
                    name: "key".to_owned()
                },
                SecKind::ApiKey {
                    location: ParamLocation::Header,
                    name: "X-Key".to_owned()
                },
                SecKind::ApiKey {
                    location: ParamLocation::Cookie,
                    name: "session".to_owned()
                },
                SecKind::Other,
                SecKind::OAuth2 {
                    flows: OAuthFlows {
                        declared: false,
                        implicit: None,
                        password: None,
                        client_credentials: None,
                        authorization_code: None
                    }
                },
                SecKind::OpenIdConnect { url: String::new() },
                SecKind::MutualTls,
                SecKind::Other,
                SecKind::Http {
                    scheme: "digest".to_owned(),
                    bearer_format: None
                }
            ]
        );
        assert_eq!(ir.security_schemes[10].source.json_pointer, "/x-http");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn oauth2_flows_parse_all_four_types_and_scope_order() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": " https://example.test/authorize?raw=%2F ",
                            "refreshUrl": "refresh:implicit",
                            "scopes": { "read": "Read access", "shared": "Shared access" }
                        },
                        "password": {
                            "tokenUrl": " token:password ",
                            "scopes": { "write": "Write access", "shared": "Repeated" }
                        },
                        "clientCredentials": {
                            "tokenUrl": "token:client",
                            "refreshUrl": "refresh:client",
                            "scopes": { "admin": "Admin access" }
                        },
                        "authorizationCode": {
                            "authorizationUrl": "authorize:code",
                            "tokenUrl": "token:code",
                            "refreshUrl": "refresh:code",
                            "scopes": { "final": "Final access" }
                        }
                    }
                }
            }}
        });
        let (_temp, ir, sink) = parse_value(&document);
        let flows = OAuthFlows {
            declared: true,
            implicit: Some(OAuthFlow {
                authorization_url: Some(" https://example.test/authorize?raw=%2F ".to_owned()),
                token_url: None,
                refresh_url: Some("refresh:implicit".to_owned()),
                scopes: vec![
                    ("read".to_owned(), "Read access".to_owned()),
                    ("shared".to_owned(), "Shared access".to_owned()),
                ],
            }),
            password: Some(OAuthFlow {
                authorization_url: None,
                token_url: Some(" token:password ".to_owned()),
                refresh_url: None,
                scopes: vec![
                    ("write".to_owned(), "Write access".to_owned()),
                    ("shared".to_owned(), "Repeated".to_owned()),
                ],
            }),
            client_credentials: Some(OAuthFlow {
                authorization_url: None,
                token_url: Some("token:client".to_owned()),
                refresh_url: Some("refresh:client".to_owned()),
                scopes: vec![("admin".to_owned(), "Admin access".to_owned())],
            }),
            authorization_code: Some(OAuthFlow {
                authorization_url: Some("authorize:code".to_owned()),
                token_url: Some("token:code".to_owned()),
                refresh_url: Some("refresh:code".to_owned()),
                scopes: vec![("final".to_owned(), "Final access".to_owned())],
            }),
        };
        assert_eq!(
            ir.security_schemes[0].kind,
            SecKind::OAuth2 {
                flows: flows.clone()
            }
        );
        let implicit = flows.implicit.as_ref().expect("implicit flow");
        assert_eq!(
            implicit.authorization_url.as_deref(),
            Some(" https://example.test/authorize?raw=%2F ")
        );
        assert_eq!(implicit.token_url, None);
        assert_eq!(implicit.refresh_url.as_deref(), Some("refresh:implicit"));
        assert_eq!(
            implicit.scopes,
            [
                ("read".to_owned(), "Read access".to_owned()),
                ("shared".to_owned(), "Shared access".to_owned())
            ]
        );
        let password = flows.password.as_ref().expect("password flow");
        assert_eq!(password.token_url.as_deref(), Some(" token:password "));
        assert_eq!(
            password.scopes,
            [
                ("write".to_owned(), "Write access".to_owned()),
                ("shared".to_owned(), "Repeated".to_owned())
            ]
        );
        let client = flows
            .client_credentials
            .as_ref()
            .expect("client credentials flow");
        assert_eq!(client.token_url.as_deref(), Some("token:client"));
        assert_eq!(client.refresh_url.as_deref(), Some("refresh:client"));
        assert_eq!(
            client.scopes,
            [("admin".to_owned(), "Admin access".to_owned())]
        );
        let code = flows
            .authorization_code
            .as_ref()
            .expect("authorization code flow");
        assert_eq!(code.authorization_url.as_deref(), Some("authorize:code"));
        assert_eq!(code.token_url.as_deref(), Some("token:code"));
        assert_eq!(code.refresh_url.as_deref(), Some("refresh:code"));
        assert_eq!(
            code.scopes,
            [("final".to_owned(), "Final access".to_owned())]
        );
        assert_eq!(
            flows.declared_scopes(),
            ["read", "shared", "write", "admin", "final"]
        );
        assert!(!flows.is_empty());
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn http_bearer_format_parses_verbatim() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "formatted": { "type": "http", "scheme": "bearer", "bearerFormat": " JWT + custom " },
                "plain": { "type": "http", "scheme": "basic" }
            }}
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(
            &ir.security_schemes[0].kind,
            SecKind::Http { scheme, bearer_format }
                if scheme == "bearer" && bearer_format.as_deref() == Some(" JWT + custom ")
        ));
        assert!(matches!(
            &ir.security_schemes[1].kind,
            SecKind::Http { scheme, bearer_format }
                if scheme == "basic" && bearer_format.is_none()
        ));
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn openidconnect_url_parses_verbatim() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "present": { "type": "openIdConnect", "openIdConnectUrl": " oidc://raw value " },
                "missing": { "type": "openIdConnect" }
            }}
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(
            ir.security_schemes[0].kind,
            SecKind::OpenIdConnect {
                url: " oidc://raw value ".to_owned()
            }
        );
        assert_eq!(
            ir.security_schemes[1].kind,
            SecKind::OpenIdConnect { url: String::new() }
        );
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn oauth2_missing_flows_yields_empty_flows() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2" },
                "flowWithoutScopes": {
                    "type": "oauth2",
                    "flows": { "password": { "tokenUrl": "token:password", "scopes": {} } }
                }
            } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(
            ir.security_schemes[0].kind,
            SecKind::OAuth2 {
                flows: OAuthFlows {
                    declared: false,
                    implicit: None,
                    password: None,
                    client_credentials: None,
                    authorization_code: None
                }
            }
        );
        assert!(matches!(
            &ir.security_schemes[1].kind,
            SecKind::OAuth2 { flows }
                if flows.password.as_ref().is_some_and(|flow| flow.scopes.is_empty())
        ));
        assert!(sink.as_slice().is_empty());
    }

    #[test]
    fn flow_without_scopes_map_errors_1438() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": { "oauth": {
                "type": "oauth2",
                "flows": {
                    "password": { "tokenUrl": "https://example.test/token" }
                }
            } } }
        });
        let (_temp, _ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SECURITY_FLOWS_SHAPE)
            .expect("missing scopes diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth/flows/password")
        );
        assert_eq!(diagnostic.message, "OAuth2 flow requires a scopes map");
    }

    #[test]
    fn oauth2_flows_skip_specification_extensions() {
        let document = json!({
            "openapi": "3.1.1",
            "components": { "securitySchemes": { "oauth": {
                "type": "oauth2",
                "flows": {
                    "x-vendor-note": "internal",
                    "implicit": {
                        "authorizationUrl": "https://example.test/authorize",
                        "scopes": {}
                    }
                }
            } } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(
            &ir.security_schemes[0].kind,
            SecKind::OAuth2 { flows } if flows.implicit.is_some()
        ));
        assert!(sink.as_slice().is_empty());
    }

    #[test]
    fn unrecognized_flow_key_is_error_oasts1438() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": { "oauth": {
                "type": "oauth2",
                "flows": { "deviceCode": { "scopes": {} } }
            } } }
        });
        let (_temp, _ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SECURITY_FLOWS_SHAPE)
            .expect("flow shape diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth/flows/deviceCode")
        );
        assert_eq!(diagnostic.message, "unrecognized OAuth2 flow 'deviceCode'");
    }

    #[test]
    fn non_string_scope_value_is_error_oasts1438() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": { "oauth": {
                "type": "oauth2",
                "flows": { "implicit": {
                    "authorizationUrl": "https://example.test/authorize",
                    "scopes": { "read": "Read access", "write": 7 }
                } }
            } } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostic = sink
            .as_slice()
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_SECURITY_FLOWS_SHAPE)
            .expect("scope shape diagnostic");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/components/securitySchemes/oauth/flows/implicit/scopes")
        );
        assert_eq!(
            diagnostic.message,
            "OAuth2 scopes must map scope names to description strings"
        );
        assert_eq!(
            ir.security_schemes[0].kind,
            SecKind::OAuth2 {
                flows: OAuthFlows {
                    declared: true,
                    implicit: Some(OAuthFlow {
                        authorization_url: Some("https://example.test/authorize".to_owned()),
                        token_url: None,
                        refresh_url: None,
                        scopes: Vec::new()
                    }),
                    password: None,
                    client_credentials: None,
                    authorization_code: None
                }
            }
        );
    }

    #[test]
    fn non_object_oauth2_shapes_use_general_shape_error() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": {
                "badFlows": { "type": "oauth2", "flows": 7 },
                "badFlow": { "type": "oauth2", "flows": { "password": 7 } }
            } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(matches!(
            &ir.security_schemes[0].kind,
            SecKind::OAuth2 { flows } if flows.is_empty()
        ));
        assert!(matches!(
            &ir.security_schemes[1].kind,
            SecKind::OAuth2 { flows } if flows.is_empty()
        ));
        assert_eq!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_SHAPE)
                .count(),
            2
        );
    }

    #[test]
    fn security_descriptor_bytes_unchanged_after_seckind_payload() {
        let temp = TempDir::new().expect("temp directory");
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "test", "version": "1" },
            "components": { "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://example.test/authorize",
                            "tokenUrl": "https://example.test/token",
                            "scopes": { "read": "Read access" }
                        }
                    }
                },
                "http": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" },
                "oidc": { "type": "openIdConnect", "openIdConnectUrl": "https://example.test/.well-known/openid-configuration" }
            }},
            "paths": { "/secure": { "get": {
                "operationId": "secure",
                "security": [{ "oauth": ["read"] }, { "http": [] }, { "oidc": [] }],
                "responses": { "204": { "description": "ok" } }
            }}}
        });
        std::fs::write(
            temp.path().join("openapi.json"),
            serde_json::to_vec(&document).expect("OpenAPI JSON"),
        )
        .expect("write OpenAPI");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": { "authEnforcement": "types", "baseUrl": { "source": "runtime" } },
            "validation": { "engine": "off", "unchecked": "allow" }
        });
        let config_path = temp.path().join("oasts.json");
        let resolved = load_config_from_json(
            &config_path,
            &serde_json::to_vec(&config).expect("config JSON"),
        )
        .expect("resolved config");
        let mut sink = DiagnosticSink::new();
        let files = compile_pipeline(&resolved, true, &mut sink).expect("generated files");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let client = files
            .iter()
            .find(|file| file.relative_path == "client/operations/secure.ts")
            .expect("secure client operation");
        let start = client.content.find("  security:").expect("security start");
        let end = client.content[start..]
            .find("  responses:")
            .expect("responses start")
            + start;
        assert_eq!(
            &client.content[start..end],
            "  security: authAlternatives([\n    [{ name: \"oauth\", apply: bearerCredential, scopes: [\"read\"] }],\n    [{ name: \"http\", apply: bearerCredential, scopes: [] }],\n    [{ name: \"oidc\", apply: bearerCredential, scopes: [] }],\n  ]),\n"
        );
    }

    #[test]
    fn malformed_client_metadata_shapes_are_diagnosed_without_blocking_ir() {
        let document = json!({
            "openapi": "3.1.0",
            "servers": {},
            "security": {},
            "paths": {
                "/malformed": {
                    "servers": [
                        7,
                        {},
                        { "url": "https://variables-array.example.test", "variables": [] },
                        {
                            "url": "https://variables.example.test",
                            "variables": {
                                "scalar": 7,
                                "missing-default": {},
                                "enum-scalar": { "default": "x", "enum": "x" },
                                "enum-member": { "default": "x", "enum": ["x", 7] }
                            }
                        }
                    ],
                    "get": {
                        "parameters": [{
                            "name": "raw-booleans",
                            "in": "query",
                            "explode": "yes",
                            "allowReserved": "yes",
                            "schema": { "type": "string" }
                        }],
                        "security": [7, { "scalar-scopes": "read" }, { "mixed-scopes": ["read", 7] }],
                        "requestBody": {
                            "content": {
                                "application/x-www-form-urlencoded": {
                                    "schema": { "type": "object" },
                                    "encoding": []
                                },
                                "multipart/form-data": {
                                    "schema": { "type": "object" },
                                    "encoding": {
                                        "scalar": 7,
                                        "headers-array": { "headers": [] },
                                        "header-scalar": { "headers": { "X-Scalar": 7 } },
                                        "header-schema": { "headers": { "X-Missing": {} } },
                                        "style": { "style": "invalid" }
                                    }
                                }
                            }
                        },
                        "responses": { "204": { "description": "empty" } }
                    }
                }
            },
            "components": { "securitySchemes": [] }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let operation = &ir.operations[0];

        assert!(ir.root_servers.is_empty());
        assert!(ir.root_security.is_empty());
        assert!(ir.security_schemes.is_empty());
        assert_eq!(operation.servers.len(), 2);
        assert_eq!(operation.servers[1].variables.len(), 2);
        assert!(operation.servers[1].variables[0].1.enum_values.is_empty());
        assert_eq!(operation.servers[1].variables[1].1.enum_values, ["x"]);
        assert_eq!(operation.parameters[0].explode, None);
        assert!(!operation.parameters[0].allow_reserved);
        assert_eq!(operation.security, Some(Vec::new()));
        let multipart = operation
            .request_body
            .as_ref()
            .expect("request body")
            .media_types
            .iter()
            .find(|media| media.essence == "multipart/form-data")
            .expect("multipart");
        assert_eq!(multipart.encodings.len(), 4);
        assert!(multipart.encodings[0].1.headers.is_empty());
        assert!(multipart.encodings[1].1.headers.is_empty());
        assert_eq!(multipart.encodings[2].1.headers.len(), 1);
        assert_eq!(multipart.encodings[3].1.style, None);
        assert!(sink.has_errors());
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_UNSUPPORTED && diagnostic.message.contains("encoding header")
        }));

        let scalar_scheme_document = json!({
            "openapi": "3.1.0",
            "components": { "securitySchemes": { "scalar": 7 } }
        });
        let (_temp, ir, sink) = parse_value(&scalar_scheme_document);
        assert!(ir.security_schemes.is_empty());
        assert!(sink.has_errors());
    }

    #[test]
    fn normalizes_nullable_forms_to_the_same_flag() {
        for (version, schema) in [
            ("3.0.3", json!({ "type": "string", "nullable": true })),
            ("3.1.0", json!({ "type": ["string", "null"] })),
        ] {
            let document = json!({
                "openapi": version,
                "components": { "schemas": { "Value": schema } }
            });
            let (_temp, graph) = graph_for(&document);
            let mut sink = DiagnosticSink::new();
            let ir = parse(&graph, &mut sink).expect("IR");
            assert!(ir.schemas[0].schema.is_nullable());
            assert!(matches!(
                ir.schemas[0].schema,
                SchemaNode::Primitive {
                    ty: PrimitiveType::String,
                    ..
                }
            ));
        }
    }

    #[test]
    fn primitive_metadata_carries_structured_numeric_constraints() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "Bounded": {
                        "type": "number",
                        "minimum": 1,
                        "maximum": 9,
                        "exclusiveMinimum": 2,
                        "exclusiveMaximum": 8
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Primitive { .. }));
        let meta = ir.schemas[0].schema.meta();

        assert_eq!(
            meta.numeric_constraints()
                .minimum
                .as_ref()
                .map(ToString::to_string),
            Some("1".to_owned())
        );
        assert_eq!(
            meta.numeric_constraints()
                .maximum
                .as_ref()
                .map(ToString::to_string),
            Some("9".to_owned())
        );
        assert_eq!(
            meta.numeric_constraints().exclusive_minimum,
            Some(crate::ir::ExclusiveBound::Number(serde_json::Number::from(
                2
            )))
        );
        assert_eq!(
            meta.numeric_constraints().exclusive_maximum,
            Some(crate::ir::ExclusiveBound::Number(serde_json::Number::from(
                8
            )))
        );
        assert!(meta.docs.constraints.contains(&"minimum: 1".to_owned()));
        assert!(
            meta.docs
                .constraints
                .contains(&"exclusiveMaximum: 8".to_owned())
        );

        let document = json!({
            "openapi": "3.0.3",
            "components": {
                "schemas": {
                    "Bounded": {
                        "type": "number",
                        "minimum": 1,
                        "exclusiveMinimum": true
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert_eq!(
            ir.schemas[0]
                .schema
                .meta()
                .numeric_constraints()
                .exclusive_minimum,
            Some(crate::ir::ExclusiveBound::Boolean(true))
        );
    }

    #[test]
    fn schema_metadata_carries_structured_validation_constraints() {
        let document: Value = serde_json::from_str(
            r#"{
                "openapi": "3.1.0",
                "components": {
                    "schemas": {
                        "Constrained": {
                            "type": "object",
                            "minLength": 1,
                            "maxLength": 2,
                            "pattern": "^[a-z]+$",
                            "multipleOf": 1.2300,
                            "minItems": 3,
                            "maxItems": 4,
                            "uniqueItems": true,
                            "minProperties": 5,
                            "maxProperties": 6
                        }
                    }
                }
            }"#,
        )
        .expect("valid OpenAPI document");
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        let meta = ir.schemas[0].schema.meta();

        assert_eq!(meta.string_constraints().min_length, Some(1));
        assert_eq!(meta.string_constraints().max_length, Some(2));
        assert_eq!(
            meta.string_constraints().pattern.as_deref(),
            Some("^[a-z]+$")
        );
        assert_eq!(
            meta.numeric_constraints()
                .multiple_of
                .as_ref()
                .map(ToString::to_string),
            Some("1.2300".to_owned())
        );
        assert_eq!(meta.array_constraints().min_items, Some(3));
        assert_eq!(meta.array_constraints().max_items, Some(4));
        assert!(meta.array_constraints().unique_items);
        assert_eq!(meta.object_constraints().min_properties, Some(5));
        assert_eq!(meta.object_constraints().max_properties, Some(6));
    }

    fn assert_invalid_multiple_of(multiple_of: &str) {
        let document: Value = serde_json::from_str(&format!(
            r#"{{
                "openapi": "3.1.0",
                "components": {{
                    "schemas": {{
                        "Value": {{"type": "number", "multipleOf": {multiple_of}}}
                    }}
                }}
            }}"#
        ))
        .expect("valid OpenAPI document");
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPLE_OF)
            .collect::<Vec<_>>();

        assert_eq!(diagnostics.len(), 1, "{:?}", sink.as_slice());
        assert_eq!(diagnostics[0].severity, Severity::Error);
        assert!(
            diagnostics[0]
                .json_pointer
                .as_deref()
                .is_some_and(|pointer| pointer.ends_with("/multipleOf"))
        );
        assert!(
            ir.schemas[0]
                .schema
                .meta()
                .numeric_constraints()
                .multiple_of
                .is_none()
        );
    }

    #[test]
    fn multipleof_zero_is_input_error() {
        assert_invalid_multiple_of("0");
    }

    #[test]
    fn multipleof_negative_is_input_error() {
        assert_invalid_multiple_of("-1");
    }

    #[test]
    fn multipleof_nonrepresentable_is_input_error() {
        assert_invalid_multiple_of("1e999");
    }

    #[test]
    fn invalid_multipleof_absent_from_constraint_docs() {
        let invalid = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "Value": {"type": "number", "multipleOf": 0, "minimum": 1}
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&invalid);
        let constraints = &ir.schemas[0].schema.meta().docs.constraints;
        assert!(sink.has_errors());
        assert!(constraints.contains(&"minimum: 1".to_owned()));
        assert!(
            !constraints
                .iter()
                .any(|entry| entry.starts_with("multipleOf:"))
        );

        let valid = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "Value": {"type": "number", "multipleOf": 2}
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&valid);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(
            ir.schemas[0]
                .schema
                .meta()
                .docs
                .constraints
                .contains(&"multipleOf: 2".to_owned())
        );
    }

    #[test]
    fn multiple_of_and_exclusive_bounds_follow_dialect_spelling() {
        for (version, multiple_of, exclusive_minimum) in [
            ("3.0.3", "2.500", json!(true)),
            ("3.1.0", "2.500", json!(1.25)),
        ] {
            let document: Value = serde_json::from_str(&format!(
                r#"{{
                    "openapi": "{version}",
                    "components": {{
                        "schemas": {{
                            "Constrained": {{
                                "type": "number",
                                "exclusiveMinimum": {exclusive_minimum},
                                "multipleOf": {multiple_of}
                            }}
                        }}
                    }}
                }}"#
            ))
            .expect("valid OpenAPI document");
            let (_temp, ir, sink) = parse_value(&document);
            assert!(!sink.has_errors(), "{:?}", sink.as_slice());
            let numeric = ir.schemas[0].schema.meta().numeric_constraints();

            assert_eq!(
                numeric.multiple_of.as_ref().map(ToString::to_string),
                Some(multiple_of.to_owned())
            );
            if version == "3.0.3" {
                assert_eq!(
                    numeric.exclusive_minimum,
                    Some(crate::ir::ExclusiveBound::Boolean(true))
                );
            } else {
                assert_eq!(version, "3.1.0");
                assert_eq!(
                    numeric.exclusive_minimum,
                    Some(crate::ir::ExclusiveBound::Number(
                        "1.25".parse().expect("number")
                    ))
                );
            }
        }
    }

    #[test]
    fn dependent_required_preserves_document_order() {
        let document: Value = serde_json::from_str(
            r#"{
                "openapi": "3.1.0",
                "components": {
                    "schemas": {
                        "Address": {
                            "type": "object",
                            "dependentRequired": {
                                "billing_address": ["credit_card", "name"],
                                "shipping_address": ["name"]
                            }
                        }
                    }
                }
            }"#,
        )
        .expect("valid OpenAPI document");
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());

        assert!(
            matches!(
                &ir.schemas[0].schema,
                SchemaNode::Object { dependent_required, .. }
                    if *dependent_required
                        == vec![
                            (
                                "billing_address".to_owned(),
                                vec!["credit_card".to_owned(), "name".to_owned()]
                            ),
                            ("shipping_address".to_owned(), vec!["name".to_owned()]),
                        ]
            ),
            "dependentRequired schema should retain its object shape and document order"
        );
    }

    #[test]
    fn new_validation_applicators_are_retained_without_validator_rejections() {
        let document: Value = serde_json::from_str(
            r#"{
                "openapi": "3.1.0",
                "components": {
                    "schemas": {
                        "Rejected": {
                            "propertyNames": {},
                            "if": {},
                            "maxContains": 2,
                            "dependentSchemas": {},
                            "then": {},
                            "patternProperties": {},
                            "contains": {},
                            "else": {},
                            "minContains": 1,
                            "unevaluatedItems": false,
                            "not": { "type": "string" },
                            "unevaluatedProperties": false
                        }
                    }
                }
            }"#,
        )
        .expect("valid OpenAPI document");
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!sink.has_errors(), "{:?}", sink.as_slice());
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Any { .. }));
        assert!(
            ir.schemas[0]
                .schema
                .meta()
                .rejected_validation_keywords
                .is_empty()
        );
        let applicators = ir.schemas[0].schema.meta().validation_applicators();
        assert!(applicators.not.is_some());
        assert!(applicators.property_names.is_some());
        assert!(applicators.pattern_properties.is_empty());
        assert!(applicators.contains.is_some());
        assert!(applicators.dependent_schemas.is_empty());
        assert!(applicators.conditional.is_some());
        assert!(applicators.unevaluated_items.is_some());
        assert!(applicators.unevaluated_properties.is_some());
    }

    #[test]
    fn structural_validation_constraints_default_for_absent_and_malformed_values() {
        let document = json!({
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "Absent": { "type": "object" },
                    "Malformed": {
                        "type": "object",
                        "minLength": "one",
                        "maxLength": -1,
                        "pattern": 7,
                        "multipleOf": "two",
                        "minItems": "three",
                        "maxItems": -4,
                        "uniqueItems": "yes",
                        "minProperties": "five",
                        "maxProperties": -6,
                        "dependentRequired": []
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let diagnostics = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_MULTIPLE_OF)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "{:?}", sink.as_slice());
        assert_eq!(diagnostics[0].severity, Severity::Error);

        for schema in &ir.schemas {
            let meta = schema.schema.meta();
            assert_eq!(meta.string_constraints().min_length, None);
            assert_eq!(meta.string_constraints().max_length, None);
            assert_eq!(meta.string_constraints().pattern, None);
            assert_eq!(meta.numeric_constraints().multiple_of, None);
            assert_eq!(meta.array_constraints().min_items, None);
            assert_eq!(meta.array_constraints().max_items, None);
            assert!(!meta.array_constraints().unique_items);
            assert_eq!(meta.object_constraints().min_properties, None);
            assert_eq!(meta.object_constraints().max_properties, None);
            assert!(meta.rejected_validation_keywords.is_empty());
            assert!(
                matches!(
                    &schema.schema,
                    SchemaNode::Object { dependent_required, .. } if dependent_required.is_empty()
                ),
                "test schemas should retain their object shape with empty dependentRequired"
            );
        }
    }

    #[test]
    fn multiple_of_retains_positive_and_rejects_nonpositive_divisors() {
        // Both dialects share the numeric collection and input-diagnostic paths.
        for version in ["3.0.3", "3.1.0"] {
            for (literal, expected) in [("0", None), ("-2", None), ("2.5", Some("2.5"))] {
                let document: Value = serde_json::from_str(&format!(
                    r#"{{
                        "openapi": "{version}",
                        "components": {{
                            "schemas": {{
                                "N": {{ "type": "number", "multipleOf": {literal} }}
                            }}
                        }}
                    }}"#
                ))
                .expect("valid OpenAPI document");
                let (_temp, ir, sink) = parse_value(&document);
                let diagnostics = sink
                    .as_slice()
                    .iter()
                    .filter(|diagnostic| diagnostic.code == CODE_MULTIPLE_OF)
                    .collect::<Vec<_>>();
                assert_eq!(diagnostics.len(), usize::from(expected.is_none()));
                assert_eq!(
                    ir.schemas[0]
                        .schema
                        .meta()
                        .numeric_constraints()
                        .multiple_of
                        .as_ref()
                        .map(ToString::to_string),
                    expected.map(str::to_owned),
                    "{version} multipleOf {literal}"
                );
            }
        }
    }

    #[test]
    fn conditional_keeps_the_type_approximation_diagnostic_and_validator_ir() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "schemas": { "Conditional": { "if": { "type": "string" } } } }
        });
        let (_temp, graph) = graph_for(&document);
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");
        assert!(!sink.has_errors());
        assert!(!sink.as_slice().is_empty());
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Any { .. }));
        assert!(
            ir.schemas[0]
                .schema
                .meta()
                .validation_applicators()
                .conditional
                .is_some()
        );
    }

    #[test]
    fn not_preserves_object_siblings_and_its_validator_subschema() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Thing": {
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" },
                        "b": { "type": "string" }
                    },
                    "not": { "type": "string" }
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "Thing"),
            SchemaNode::Object { properties, .. }
                if properties.iter().map(|(name, _, _)| name.as_str()).collect::<Vec<_>>()
                    == ["a", "b"]
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
        assert!(matches!(
            schema_named(&ir, "Thing")
                .meta()
                .validation_applicators()
                .not
                .as_deref(),
            Some(SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
            })
        ));
    }

    #[test]
    fn not_without_type_siblings_retains_its_validator_subschema() {
        let document = schemas_doc("3.1.0", json!({ "Thing": { "not": { "type": "string" } } }));
        let (_temp, ir, sink) = parse_value(&document);

        let schema = schema_named(&ir, "Thing");
        assert!(matches!(schema, SchemaNode::Any { .. }));
        assert!(matches!(
            schema.meta().validation_applicators().not.as_deref(),
            Some(SchemaNode::Primitive {
                ty: PrimitiveType::String,
                meta,
                ..
            }) if meta.source.json_pointer == "/components/schemas/Thing/not"
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn not_of_empty_schema_lowers_the_outer_node_to_never() {
        let document = schemas_doc("3.1.0", json!({ "RejectAll": { "not": {} } }));
        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "RejectAll"),
            SchemaNode::Never { meta }
                if meta.source.json_pointer == "/components/schemas/RejectAll"
                    && meta.validation_applicators().not.is_none()
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn not_of_true_schema_lowers_the_outer_node_to_never() {
        let document = schemas_doc("3.1.0", json!({ "RejectAll": { "not": true } }));
        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "RejectAll"),
            SchemaNode::Never { meta }
                if meta.source.json_pointer == "/components/schemas/RejectAll"
                    && meta.validation_applicators().not.is_none()
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn annotations_do_not_block_not_of_everything_lowering() {
        let document = schemas_doc(
            "3.1.0",
            json!({ "RejectAll": { "not": { "description": "x" } } }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "RejectAll"),
            SchemaNode::Never { meta }
                if meta.source.json_pointer == "/components/schemas/RejectAll"
                    && meta.validation_applicators().not.is_none()
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn not_of_never_schema_leaves_the_outer_node_unchanged() {
        let document = schemas_doc("3.1.0", json!({ "AcceptAll": { "not": false } }));
        let (_temp, ir, sink) = parse_value(&document);

        let schema = schema_named(&ir, "AcceptAll");
        assert!(matches!(schema, SchemaNode::Any { .. }));
        assert!(matches!(
            schema.meta().validation_applicators().not.as_deref(),
            Some(SchemaNode::Never { meta })
                if meta.source.json_pointer == "/components/schemas/AcceptAll/not"
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn provably_empty_not_with_a_typed_sibling_emits_no_diagnostic() {
        let document = schemas_doc(
            "3.1.0",
            json!({ "RejectAll": { "type": "string", "not": true } }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        assert!(matches!(
            schema_named(&ir, "RejectAll"),
            SchemaNode::Never { meta }
                if meta.source.json_pointer == "/components/schemas/RejectAll"
                    && meta.validation_applicators().not.is_none()
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn pattern_properties_preserves_object_siblings_and_subschemas() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Thing": {
                    "type": "object",
                    "properties": { "a": { "type": "string" } },
                    "patternProperties": { "^x": { "type": "string" } }
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        let schema = schema_named(&ir, "Thing");
        assert!(matches!(
            schema,
            SchemaNode::Object { properties, .. }
                if properties.iter().map(|(name, _, _)| name.as_str()).collect::<Vec<_>>()
                    == ["a"]
        ));
        assert!(matches!(
            schema
                .meta()
                .validation_applicators()
                .pattern_properties
                .as_slice(),
            [PatternProperty {
                pattern,
                schema: SchemaNode::Primitive {
                ty: PrimitiveType::String,
                ..
                },
                type_key: Some(PatternPropertyKey::Prefix(prefix)),
            }] if pattern == "^x" && prefix == "x"
        ));
        assert!(sink.as_slice().is_empty(), "{:?}", sink.as_slice());
    }

    #[test]
    fn pattern_property_type_keys_accept_only_faithful_literal_key_spaces() {
        assert_eq!(
            pattern_property_type_key(r"prefix\."),
            Some(PatternPropertyKey::Contains("prefix.".to_owned()))
        );
        assert_eq!(
            pattern_property_type_key("$"),
            Some(PatternPropertyKey::All)
        );
        assert_eq!(pattern_property_type_key(r"\d"), None);
        assert_eq!(pattern_property_type_key(r"trailing\"), None);
    }

    #[test]
    fn new_applicator_maps_are_sorted_or_diagnosed_and_contains_retains_bounds() {
        let document = schemas_doc(
            "3.1.0",
            json!({
                "Valid": {
                    "patternProperties": {
                        "^z": { "type": "string" },
                        "^a": { "type": "integer" }
                    },
                    "contains": { "type": "number" },
                    "minContains": 0,
                    "maxContains": 2,
                    "dependentSchemas": {
                        "z": { "required": ["a"] },
                        "a": { "required": ["z"] }
                    }
                },
                "MalformedPatterns": {
                    "patternProperties": []
                },
                "MalformedDependencies": {
                    "dependentSchemas": []
                },
                "MalformedMinContains": {
                    "minContains": -1
                },
                "MalformedMaxContains": {
                    "maxContains": 1.5
                }
            }),
        );
        let (_temp, ir, sink) = parse_value(&document);

        let valid = schema_named(&ir, "Valid").meta().validation_applicators();
        assert_eq!(
            valid
                .pattern_properties
                .iter()
                .map(|pattern| pattern.pattern.as_str())
                .collect::<Vec<_>>(),
            ["^a", "^z"]
        );
        assert!(matches!(
            valid.contains.as_deref(),
            Some(ContainsApplicator {
                min_contains: Some(0),
                max_contains: Some(2),
                ..
            })
        ));
        assert_eq!(
            valid
                .dependent_schemas
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["z", "a"]
        );
        assert_eq!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_SHAPE)
                .count(),
            4
        );
    }

    #[test]
    fn reports_undeclared_path_parameter() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/pets/{id}": {
                    "get": { "responses": { "200": { "description": "ok" } } }
                }
            }
        });
        let (_temp, graph) = graph_for(&document);
        let mut sink = DiagnosticSink::new();
        let _ir = parse(&graph, &mut sink).expect("IR");
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_PATH_PARAMETER)
        );
    }

    #[test]
    fn malformed_openapi_shapes_report_each_diagnostic_path() {
        for document in [
            json!({ "openapi": "3.1.0", "paths": [] }),
            json!({ "openapi": "3.1.0", "components": { "schemas": [] } }),
        ] {
            let (_temp, _ir, sink) = parse_value(&document);
            assert!(sink.has_errors());
            assert!(
                sink.as_slice()
                    .iter()
                    .any(|diagnostic| diagnostic.code == CODE_SHAPE)
            );
        }

        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/scalar": 7,
                "/bad-operation": { "get": false },
                "/missing-responses": { "post": {} },
                "/bad-external": {
                    "put": { "externalDocs": [], "responses": {} },
                    "patch": { "externalDocs": {}, "responses": {} }
                },
                "/bad-collections": {
                    "parameters": {},
                    "get": {
                        "parameters": {},
                        "requestBody": 7,
                        "responses": []
                    }
                },
                "/params/{id}": {
                    "parameters": [
                        7,
                        { "in": "query", "schema": { "type": "string" } },
                        { "name": "bad", "in": "formData", "schema": { "type": "string" } },
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "query", "in": "query" },
                        { "name": "header", "in": "header", "schema": { "type": "integer" } },
                        { "name": "cookie", "in": "cookie", "schema": { "type": "boolean" } },
                        { "name": "extra", "in": "path", "schema": { "type": "string" } }
                    ],
                    "get": {
                        "requestBody": { "content": [] },
                        "responses": {
                            "invalid": { "description": "bad status" },
                            "200": 7,
                            "201": { "description": 7, "content": [] },
                            "2XX": {
                                "description": "range",
                                "content": {
                                    "application/json": {
                                        "example": { "id": 1 },
                                        "examples": {
                                            "named": { "value": { "id": 2 } },
                                            "ignored": { "summary": "no value" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert!(!ir.operations.is_empty());
        for code in [
            CODE_SHAPE,
            CODE_UNSUPPORTED,
            CODE_RESPONSE_STATUS,
            CODE_PATH_PARAMETER,
        ] {
            assert!(
                sink.as_slice()
                    .iter()
                    .any(|diagnostic| diagnostic.code == code)
            );
        }
    }

    #[test]
    fn lowercase_response_status_key_names_casing_as_the_cause() {
        let document = json!({
            "openapi": "3.1.0",
            "paths": {
                "/pets": {
                    "get": {
                        "responses": {
                            "200": { "description": "ok" },
                            "4xx": { "description": "client error" }
                        }
                    }
                }
            }
        });
        let (_temp, _ir, sink) = parse_value(&document);
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_RESPONSE_STATUS_CASE
                && diagnostic.severity == Severity::Warning
                && diagnostic.message.contains("'4xx'")
                && diagnostic.message.contains("'4XX'")
        }));
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    /// A mapping value that is not a JSON string cannot name a schema, so it drops out of tag
    /// resolution the same way a dangling one does — but silently dropping it would make a
    /// malformed entry quieter than a dangling one, which warns from the emitter.
    #[test]
    fn a_non_string_mapping_value_warns_and_drops() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {},
            "components": { "schemas": {
                "Cat": { "type": "object", "properties": { "kind": { "type": "string" } } },
                "Pet": {
                    "oneOf": [{ "$ref": "#/components/schemas/Cat" }],
                    "discriminator": { "propertyName": "kind", "mapping": { "cat": "Cat", "bad": 7 } }
                }
            } }
        });
        let (_temp, ir, sink) = parse_value(&document);
        let flagged: Vec<_> = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == CODE_MAPPING_VALUE_SHAPE)
            .collect();
        assert_eq!(flagged.len(), 1, "{:?}", sink.as_slice());
        assert_eq!(flagged[0].severity, Severity::Warning);
        assert_eq!(
            flagged[0].message,
            "discriminator mapping value for 'bad' is not a string; the entry is dropped and contributes no tag"
        );
        assert_eq!(
            flagged[0].json_pointer.as_deref(),
            Some("/components/schemas/Pet/discriminator")
        );
        // The well-formed sibling entry survives; only the malformed one drops.
        let discriminator = ir
            .schemas
            .iter()
            .find_map(|schema| match &schema.schema {
                SchemaNode::OneOf { discriminator, .. } => discriminator.as_deref(),
                _ => None,
            })
            .expect("the oneOf carries a discriminator");
        assert_eq!(
            discriminator.mapping,
            vec![("cat".to_owned(), "Cat".to_owned())]
        );
    }

    #[test]
    fn schema_parser_covers_every_shape_and_dialect_branch() {
        let document: Value = serde_json::from_str(
            r##"{
                "openapi":"3.1.0",
                "components":{"schemas":{
                    "AnyBoolean":true,
                    "NeverBoolean":false,
                    "BadScalar":7,
                    "AllOf":{"allOf":[{"type":"string"}]},
                    "BadAllOf":{"allOf":{}},
                    "OneOf":{"oneOf":[{"type":"string"},{"type":"integer"}],"discriminator":{"propertyName":"kind","mapping":{"text":"#/components/schemas/String","bad":7}}},
                    "NoDiscriminatorObject":{"oneOf":[],"discriminator":[]},
                    "NoDiscriminatorProperty":{"oneOf":[],"discriminator":{}},
                    "NoDiscriminatorString":{"oneOf":[],"discriminator":{"propertyName":7}},
                    "AnyOf":{"anyOf":[{"type":"boolean"}]},
                    "TupleAllowed":{"prefixItems":[{"type":"string"}]},
                    "TupleForbidden":{"prefixItems":[],"items":false},
                    "TupleSchema":{"prefixItems":[],"items":{"type":"number"}},
                    "TupleBadPrefix":{"prefixItems":{},"items":true},
                    "TypeArrayBad":{"type":[7]},
                    "TypeArrayNull":{"type":["null"]},
                    "TypeArrayOne":{"type":["integer"]},
                    "TypeArrayMany":{"type":["string","number","integer","boolean","object","null"]},
                    "String":{"type":"string","format":"custom","enum":["a"],"const":"a"},
                    "Number":{"type":"number"},
                    "Integer":{"type":"integer"},
                    "Boolean":{"type":"boolean"},
                    "Null":{"type":"null"},
                    "UnknownType":{"type":"funky"},
                    "ObjectDefault":{"type":"object"},
                    "ObjectClosed":{"type":"object","additionalProperties":false},
                    "ObjectSchema":{"required":["id",7],"properties":{"id":{"type":"integer","readOnly":true,"writeOnly":true,"deprecated":true,"description":"identifier","default":1,"examples":[1]}},"additionalProperties":{"type":"string"}},
                    "InferredObject":{"properties":{}},
                    "InferredAdditional":{"additionalProperties":true},
                    "ArrayNoItems":{"type":"array"},
                    "ArrayItems":{"items":{"type":"string"}},
                    "InferredString":{"const":"x"},
                    "InferredInteger":{"const":1},
                    "InferredNumber":{"const":1.5},
                    "InferredBoolean":{"const":true},
                    "InferredNull":{"const":null},
                    "NotInferredArray":{"const":[]},
                    "NotInferredObject":{"const":{}},
                    "BadExamples":{"type":"string","examples":"bad"},
                    "Unsupported":{"not":{"type":"string"}},
                    "Unconstrained":{}
                }}
            }"##,
        )
        .expect("schema corpus should be valid JSON");
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(
            ir.schemas.len(),
            document["components"]["schemas"]
                .as_object()
                .expect("schemas")
                .len()
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_SHAPE)
        );
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_UNSUPPORTED)
        );

        let v30 = json!({
            "openapi": "3.0.3",
            "components": {
                "schemas": {
                    "Boolean": true,
                    "Const": { "const": 1 },
                    "Tuple": { "prefixItems": [] },
                    "TypeArray": { "type": ["string", "null"] },
                    "Null": { "type": "null" },
                    "Example": { "type": "string", "example": "value" }
                }
            }
        });
        let (_temp, ir, sink) = parse_value(&v30);
        assert_eq!(ir.schemas.len(), 6);
        assert!(
            sink.as_slice()
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_UNSUPPORTED)
                .count()
                >= 5
        );
    }

    #[test]
    fn parser_resolves_reusable_objects_and_schema_references() {
        let document = json!({
            "openapi": "3.1.0",
            "x-path": {
                "get": {
                    "parameters": [{ "$ref": "#/components/parameters/Id" }],
                    "requestBody": { "$ref": "#/components/requestBodies/Body" },
                    "responses": { "200": { "$ref": "#/components/responses/Ok" } }
                }
            },
            "paths": { "/pets/{id}": { "$ref": "#/x-path" } },
            "components": {
                "parameters": {
                    "Id": { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
                },
                "requestBodies": {
                    "Body": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } } }
                },
                "responses": {
                    "Ok": { "description": "ok", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } } }
                },
                "schemas": { "Pet": { "type": "object" } }
            }
        });
        let (_temp, ir, sink) = parse_value(&document);
        assert_eq!(ir.operations.len(), 1);
        assert_eq!(ir.operations[0].parameters.len(), 1);
        assert!(ir.operations[0].request_body.is_some());
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
    }

    #[test]
    fn schema_reference_failure_retains_unknown_ir() {
        let temp = TempDir::new().expect("temp directory");
        let config = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated"
        });
        std::fs::write(
            temp.path().join("oasts.json"),
            serde_json::to_vec(&config).expect("config"),
        )
        .expect("write config");
        std::fs::write(
            temp.path().join("openapi.json"),
            br#"{"openapi":"3.1.0","paths":{"/pets":{"$ref":"other.json#/Path"}},"components":{"schemas":{"Pet":{"$ref":"other.json#/Pet"}}}}"#,
        )
        .expect("write entry");
        std::fs::write(
            temp.path().join("other.json"),
            br#"{"Path":{"get":{"responses":{"200":{"description":"ok"}}}},"Pet":{"type":"string"}}"#,
        )
        .expect("write target");
        let resolved = load_config(Some(Path::new("oasts.json")), temp.path()).expect("config");
        let mut load_sink = DiagnosticSink::new();
        let graph = load_graph(&resolved, &mut load_sink).expect("graph");
        std::fs::remove_file(temp.path().join("other.json")).expect("remove target");

        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Unknown { .. }));
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_REFERENCE)
        );
    }

    #[test]
    fn parsing_helpers_cover_boundaries_and_all_value_domains() {
        assert!(parse_path_template("/").is_empty());
        assert_eq!(parse_path_template("plain").len(), 1);
        assert_eq!(parse_path_template("/pre{id}post").len(), 1);
        assert_eq!(parse_path_template("/unclosed{").len(), 1);
        assert_eq!(parse_path_template("/{}tail").len(), 1);
        assert_eq!(
            parse_response_status("2XX"),
            Some(ResponseStatus::Range("2XX".to_owned()))
        );
        for invalid in ["", "099", "600", "20X", "2000"] {
            assert_eq!(parse_response_status(invalid), None);
        }
        let media = canonical_content_key("!#$%&'*+-.^_`|~/!#$%&'*+-.^_`|~")
            .expect("RFC 9110 token characters");
        assert_eq!(media.full, "!#$%&'*+-.^_`|~/!#$%&'*+-.^_`|~");
        for malformed in ["type/", "/subtype", "type/subtype/extra", "type /subtype"] {
            assert!(canonical_content_key(malformed).is_err());
        }
        let parameterized = canonical_content_key("type/subtype;parameter=value")
            .expect("parameterized media type");
        assert_eq!(parameterized.full, "type/subtype;parameter=value");

        for (value, ty, expected) in [
            (json!("x"), PrimitiveType::String, true),
            (json!(1), PrimitiveType::Integer, true),
            (json!(1.5), PrimitiveType::Integer, false),
            (json!(1.5), PrimitiveType::Number, true),
            (json!(true), PrimitiveType::Boolean, true),
            (Value::Null, PrimitiveType::Null, true),
            (json!([]), PrimitiveType::String, false),
        ] {
            assert_eq!(value_matches_primitive(&value, ty), expected);
        }
        for (raw, expected) in [
            ("1e999999999999999999999999", true),
            ("1e-999999999999999999999999", false),
        ] {
            let number = raw.parse().expect("arbitrary-precision JSON number");
            assert_eq!(json_number_is_mathematical_integer(&number), expected);
        }

        let constrained = json!({
            "type": "string",
            "format": "custom",
            "minLength": 1,
            "maxLength": 2,
            "pattern": "x",
            "minimum": 0,
            "maximum": 3,
            "exclusiveMinimum": 0,
            "exclusiveMaximum": 3,
            "multipleOf": 1,
            "minItems": 1,
            "maxItems": 2,
            "uniqueItems": true,
            "minProperties": 1,
            "maxProperties": 2
        });
        let constrained = constrained.as_object().expect("object");
        let numeric = collect_numeric_constraints(constrained, OasVersion::V3_1);
        assert_eq!(collect_constraints(constrained, &numeric).len(), 14);
        for format in [
            "byte",
            "binary",
            "date",
            "date-time",
            "time",
            "password",
            "uuid",
            "uri",
            "email",
            "hostname",
            "ipv4",
            "ipv6",
        ] {
            assert!(is_consumed_format("string", format));
        }
        for format in ["float", "double"] {
            assert!(is_consumed_format("number", format));
        }
        for format in ["int32", "int64"] {
            assert!(is_consumed_format("integer", format));
        }
        assert!(!is_consumed_format("object", "uuid"));

        let examples = media_type_examples(&json!({
            "example": 1,
            "examples": { "two": { "value": 2 }, "ignored": {} }
        }));
        assert_eq!(
            examples,
            vec![
                ("example".to_owned(), json!(1)),
                ("two".to_owned(), json!(2))
            ]
        );
        assert_eq!(append_pointer("/a", "b/c~d"), "/a/b~1c~0d");
    }

    #[test]
    fn operation_parameter_override_and_unknown_source_are_deterministic() {
        let source = SourceRef::new("source", "/parameter");
        let schema = SchemaNode::Any {
            meta: SchemaMeta::default(),
        };
        let parameter = |name: &str, location| Param {
            name: name.to_owned(),
            location,
            required: false,
            deprecated: false,
            description: None,
            schema: schema.clone(),
            content_media_type: None,
            style: None,
            explode: None,
            allow_reserved: false,
            source: source.clone(),
        };
        let path = vec![
            parameter("same", ParamLocation::Query),
            parameter("keep", ParamLocation::Header),
        ];
        let merged = merge_parameters(&path, vec![parameter("same", ParamLocation::Query)]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].name, "keep");
    }

    #[test]
    fn parsed_meta_boxes_are_canonical() {
        // The boxed sparse groups' invariant: `Some(boxed)` always holds a non-default
        // value (box_if_populated is the sanctioned constructor). Derived SchemaMeta
        // equality feeds allOf merge decisions in the emitter, so a `Some(default)`
        // escaping the parser would silently flip merges. Walk every node of the two
        // constraint-heavy fixtures and assert canonical form throughout.
        fn non_default<T: Default + PartialEq>(group: &Option<Box<T>>) -> bool {
            match group.as_deref() {
                None => true,
                Some(value) => *value != T::default(),
            }
        }
        fn assert_canonical(schema: &SchemaNode) {
            let meta = schema.meta();
            assert!(non_default(&meta.enum_extensions));
            assert!(non_default(&meta.numeric_constraints));
            assert!(non_default(&meta.string_constraints));
            assert!(non_default(&meta.array_constraints));
            assert!(non_default(&meta.object_constraints));
            match schema {
                SchemaNode::Object {
                    properties,
                    additional_properties,
                    ..
                } => {
                    for (_, property, _) in properties {
                        assert_canonical(property);
                    }
                    if let AdditionalProperties::Allowed(Some(schema))
                    | AdditionalProperties::Schema(schema) = additional_properties
                    {
                        assert_canonical(schema);
                    }
                }
                SchemaNode::Array { items, .. } => assert_canonical(items),
                SchemaNode::Tuple {
                    prefix_items, rest, ..
                } => {
                    for item in prefix_items {
                        assert_canonical(item);
                    }
                    if let TupleRest::Schema(schema) = rest {
                        assert_canonical(schema);
                    }
                }
                SchemaNode::AllOf { branches, .. }
                | SchemaNode::OneOf { branches, .. }
                | SchemaNode::AnyOf { branches, .. } => {
                    for branch in branches {
                        assert_canonical(branch);
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

        for fixture_name in ["pathological-3.1", "validators-showcase-3.1"] {
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures")
                .join(fixture_name);
            let config = crate::config::load_config(Some(&fixture.join("oasts.yaml")), &fixture)
                .expect("fixture config loads");
            let mut sink = DiagnosticSink::new();
            let graph = crate::loader::load_graph(&config, &mut sink).expect("fixture graph loads");
            let ir = parse(&graph, &mut sink).expect("fixture parses");
            assert!(!sink.has_errors(), "{fixture_name}: {:#?}", sink.as_slice());
            for schema in &ir.schemas {
                assert_canonical(&schema.schema);
            }
            for operation in &ir.operations {
                for parameter in &operation.parameters {
                    assert_canonical(&parameter.schema);
                }
            }
        }

        // The corpus never produces `Allowed(Some(_))`; cover that walk arm directly.
        let open = SchemaNode::Object {
            properties: Vec::new(),
            additional_properties: AdditionalProperties::Allowed(Some(Box::new(SchemaNode::Any {
                meta: SchemaMeta::default(),
            }))),
            dependent_required: Vec::new(),
            finite: None,
            extra_required: Vec::new(),
            meta: SchemaMeta::default(),
        };
        assert_canonical(&open);

        // The walked fixtures never populate the enum-extension group; check its
        // canonicality predicate directly for both the populated and default shapes.
        assert!(non_default(&Some(Box::new(EnumExtensionData {
            enum_varnames: Some(json!(["A"])),
            ..EnumExtensionData::default()
        }))));
        assert!(!non_default(&Some(Box::new(EnumExtensionData::default()))));

        // The walked fixtures have no tuple carrying a rest schema; cover both rest arms.
        for rest in [
            TupleRest::Schema(Box::new(SchemaNode::Any {
                meta: SchemaMeta::default(),
            })),
            TupleRest::Allowed,
        ] {
            let tuple = SchemaNode::Tuple {
                prefix_items: Vec::new(),
                rest,
                finite: None,
                meta: SchemaMeta::default(),
            };
            assert_canonical(&tuple);
        }
    }

    #[test]
    fn collect_schema_refs_descends_into_tuple_rest_schemas() {
        let reference = |pointer: &str| SchemaNode::Ref {
            target: SchemaRef {
                source_id: "entry".to_owned(),
                json_pointer: pointer.to_owned(),
            },
            meta: SchemaMeta::default(),
        };
        let tuple = SchemaNode::Tuple {
            prefix_items: vec![reference("/$defs/First")],
            rest: TupleRest::Schema(Box::new(reference("/$defs/Rest"))),
            finite: None,
            meta: SchemaMeta::default(),
        };

        let mut refs = Vec::new();
        collect_schema_refs(&tuple, &mut refs);

        assert_eq!(
            refs.iter()
                .map(|(target, _)| target.json_pointer.as_str())
                .collect::<Vec<_>>(),
            ["/$defs/First", "/$defs/Rest"]
        );

        let open_tuple = SchemaNode::Tuple {
            prefix_items: vec![reference("/$defs/Only")],
            rest: TupleRest::Allowed,
            finite: None,
            meta: SchemaMeta::default(),
        };
        let mut refs = Vec::new();
        collect_schema_refs(&open_tuple, &mut refs);
        assert_eq!(refs.len(), 1);
    }

    /// A `$ref` is resolved and validated by the loader before parsing, but a discriminator
    /// `mapping` value is not — nothing upstream ever looks at it. Vendor documents ship mappings
    /// that point at pointers resolving to nothing, so materialization has to walk past one
    /// instead of trusting the loader's guarantee and unwrapping.
    ///
    /// The `$defs` reference is what puts materialization on the path at all; without it a
    /// single-document input returns before the worklist runs.
    #[test]
    fn a_discriminator_mapping_naming_nothing_does_not_abort_materialization() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/value": { "get": {
                "operationId": "readValue",
                "responses": { "200": {
                    "description": "ok",
                    "content": { "application/json": { "schema": {
                        "$ref": "#/$defs/Wrapper"
                    } } }
                } }
            } } },
            "$defs": {
                "Wrapper": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Cat" },
                        { "$ref": "#/components/schemas/Dog" }
                    ],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {
                            "cat": "#/components/schemas/Cat",
                            "ghost": "#/paths/~1value/get/responses/200/content/application~1json/schema/allOf/0"
                        }
                    }
                }
            },
            "components": { "schemas": {
                "Cat": { "type": "object", "properties": { "kind": { "const": "cat" } } },
                "Dog": { "type": "object", "properties": { "kind": { "const": "dog" } } }
            } }
        });

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        // The resolvable half of the mapping still reaches its component, so the dangling entry
        // is skipped rather than aborting the walk that would have materialized it.
        let names: Vec<&str> = ir
            .schemas
            .iter()
            .map(|schema| schema.name.as_str())
            .collect();
        assert!(names.contains(&"Cat"), "{names:?}");
    }

    #[test]
    fn a_lowercase_status_range_is_accepted_and_canonicalized() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": {
                "operationId": "listPets",
                "responses": {
                    "200": { "description": "ok" },
                    "4xx": { "description": "client error" }
                }
            } } }
        });

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let statuses: Vec<&ResponseStatus> = ir.operations[0]
            .responses
            .iter()
            .map(|response| &response.status)
            .collect();
        assert!(
            statuses.contains(&&ResponseStatus::Range("4XX".to_owned())),
            "a lowercase range is stored in its canonical form: {statuses:?}"
        );
        let diagnostics = sink.as_slice();
        let reported = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CODE_RESPONSE_STATUS_CASE);
        assert!(reported, "{diagnostics:#?}");
    }

    #[test]
    fn an_uppercase_status_range_is_accepted_without_a_warning() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": {
                "operationId": "listPets",
                "responses": { "4XX": { "description": "client error" } }
            } } }
        });

        let (_temp, ir, sink) = parse_value(&document);

        assert!(sink.as_slice().is_empty(), "{:#?}", sink.as_slice());
        assert_eq!(
            ir.operations[0].responses[0].status,
            ResponseStatus::Range("4XX".to_owned())
        );
    }

    #[test]
    fn two_status_keys_naming_one_range_are_rejected() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": {
                "operationId": "listPets",
                "responses": {
                    "4XX": { "description": "client error" },
                    "4xx": { "description": "the same range again" }
                }
            } } }
        });

        let (_temp, _ir, sink) = parse_value(&document);

        let diagnostics = sink.as_slice();
        let reported = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CODE_RESPONSE_STATUS_DUPLICATE);
        assert!(reported, "{diagnostics:#?}");
    }

    #[test]
    fn a_status_key_that_is_neither_a_code_nor_a_range_is_still_rejected() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": { "/pets": { "get": {
                "operationId": "listPets",
                "responses": { "nonsense": { "description": "no" } }
            } } }
        });

        let (_temp, _ir, sink) = parse_value(&document);

        let diagnostics = sink.as_slice();
        let reported = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CODE_RESPONSE_STATUS);
        assert!(reported, "{diagnostics:#?}");
    }

    #[test]
    fn operations_carry_tags_and_the_raw_path() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/": { "get": { "operationId": "root", "responses": { "204": { "description": "ok" } } } },
                "/pets/{petId}": {
                    "get": {
                        "operationId": "readPet",
                        "tags": ["pets", "public"],
                        "parameters": [
                            { "name": "petId", "in": "path", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            },
            "webhooks": {
                "petCreated": {
                    "post": { "operationId": "onPet", "tags": ["events"], "responses": { "204": { "description": "ok" } } }
                }
            }
        });

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let root = ir
            .operations
            .iter()
            .find(|operation| operation.operation_id.as_deref() == Some("root"))
            .expect("root operation");
        assert_eq!(root.path.as_deref(), Some("/"));
        assert!(root.tags.is_empty());

        let read = ir
            .operations
            .iter()
            .find(|operation| operation.operation_id.as_deref() == Some("readPet"))
            .expect("readPet operation");
        assert_eq!(read.path.as_deref(), Some("/pets/{petId}"));
        assert_eq!(read.tags, vec!["pets".to_owned(), "public".to_owned()]);

        let hook = &ir.webhooks[0].operations[0];
        assert_eq!(hook.path, None, "a webhook operation has no path");
        assert_eq!(hook.tags, vec!["events".to_owned()]);
    }

    #[test]
    fn malformed_tags_are_skipped_rather_than_diagnosed() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "1" },
            "paths": {
                "/pets": {
                    "get": { "operationId": "listPets", "tags": "pets", "responses": { "204": { "description": "ok" } } },
                    "post": { "operationId": "addPet", "tags": ["pets", 7], "responses": { "204": { "description": "ok" } } }
                }
            }
        });

        let (_temp, ir, sink) = parse_value(&document);

        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
        let list = ir
            .operations
            .iter()
            .find(|operation| operation.operation_id.as_deref() == Some("listPets"))
            .expect("listPets operation");
        assert!(
            list.tags.is_empty(),
            "a non-array tags value yields no tags"
        );
        let add = ir
            .operations
            .iter()
            .find(|operation| operation.operation_id.as_deref() == Some("addPet"))
            .expect("addPet operation");
        assert_eq!(
            add.tags,
            vec!["pets".to_owned()],
            "a non-string entry is skipped"
        );
    }
}
