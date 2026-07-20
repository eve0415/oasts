//! OpenAPI 3.0/3.1 parsing into the version-neutral IR.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{
    AdditionalProperties, Body, Discriminator, EncodingHeader, EncodingObject, EnumExtensionData,
    ExclusiveBound, Ir, MediaType, NamedSchema, NamedSecurityScheme, NumericConstraints,
    OasVersion, Operation, Param, ParamLocation, ParamStyle, PrimitiveType, PropMeta,
    ResponseEntry, ResponseStatus, SchemaDocs, SchemaMeta, SchemaNode, SchemaRef, SecKind,
    SecurityRequirement, Segment, SegmentPart, ServerEntry, ServerVariable, SourceRef, TupleRest,
};
use crate::loader::{DocId, DocumentGraph, append_pointer};

const CODE_VERSION: &str = "OASTS1101";
const CODE_SHAPE: &str = "OASTS1102";
const CODE_UNSUPPORTED: &str = "OASTS1103";
const CODE_RESPONSE_STATUS: &str = "OASTS1104";
const CODE_PATH_PARAMETER: &str = "OASTS1105";
const CODE_REFERENCE: &str = "OASTS1106";
const CODE_MEDIA_TYPE: &str = "OASTS1107";
const CODE_DUPLICATE_MEDIA_TYPE: &str = "OASTS1108";
const CODE_RESERVED_HEADER_PARAMETER: &str = "OASTS1109";

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];
const UNSUPPORTED_SCHEMA_KEYWORDS: [&str; 16] = [
    "if",
    "then",
    "else",
    "not",
    "patternProperties",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contains",
    "minContains",
    "maxContains",
    "dependentSchemas",
    "dependentRequired",
    "propertyNames",
    "additionalItems",
    "$dynamicRef",
    "$recursiveRef",
];

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
}

#[derive(Clone)]
struct NodeView<'a> {
    doc_id: DocId,
    pointer: String,
    value: &'a Value,
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
        }
    }

    fn parse_ir(&mut self) -> Ir {
        let entry = self.graph.entry();
        let root = NodeView {
            doc_id: entry.id,
            pointer: String::new(),
            value: &entry.value,
        };
        let root_servers = root.value.get("servers").map_or_else(Vec::new, |value| {
            self.parse_servers(NodeView {
                doc_id: root.doc_id,
                pointer: "/servers".to_owned(),
                value,
            })
        });
        let root_security = root.value.get("security").map_or_else(Vec::new, |value| {
            self.parse_security_requirements(NodeView {
                doc_id: root.doc_id,
                pointer: "/security".to_owned(),
                value,
            })
        });
        let security_schemes = self.parse_security_schemes(&root);
        Ir {
            operations: self.parse_operations(root.clone()),
            schemas: self.parse_named_schemas(root),
            root_servers,
            root_security,
            security_schemes,
        }
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
        object
            .iter()
            .map(|(name, value)| {
                let schema_pointer = append_pointer(pointer, name);
                let node = NodeView {
                    doc_id: root.doc_id,
                    pointer: schema_pointer,
                    value,
                };
                NamedSchema {
                    name: name.clone(),
                    schema: self.parse_schema(node.clone()),
                    source: self.source(node.doc_id, &node.pointer),
                }
            })
            .collect()
    }

    fn parse_operations(&mut self, root: NodeView<'graph>) -> Vec<Operation> {
        let Some(paths) = root.value.get("paths") else {
            return Vec::new();
        };
        let Some(paths) = paths.as_object() else {
            self.shape_error(root.doc_id, "/paths", "paths must be an object");
            return Vec::new();
        };
        let mut operations = Vec::new();
        for (path, raw_path_item) in paths {
            let path_pointer = append_pointer("/paths", path);
            let path_node = NodeView {
                doc_id: root.doc_id,
                pointer: path_pointer,
                value: raw_path_item,
            };
            let Some(path_item) = self.resolve_object(path_node, "path item") else {
                continue;
            };
            let path_parameters =
                path_item
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
                operations.push(self.parse_operation(
                    method,
                    path,
                    operation_node,
                    operation_object,
                    &path_parameters,
                    &path_servers,
                ));
            }
        }
        operations
    }

    fn parse_operation(
        &mut self,
        method: &str,
        path: &str,
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
        let path_template = parse_path_template(path);
        self.validate_path_parameters(path, &path_template, &parameters, &node);
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
                self.shape_error(node.doc_id, &node.pointer, "operation is missing responses");
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
        Operation {
            method: method.to_owned(),
            path_template,
            operation_id: string_field(object, "operationId"),
            summary: string_field(object, "summary"),
            description: string_field(object, "description"),
            deprecated: bool_field(object, "deprecated"),
            external_docs: self.parse_external_docs(&node, object.get("externalDocs")),
            parameters,
            request_body,
            responses,
            servers,
            security,
            source: self.source(node.doc_id, &node.pointer),
        }
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
                let pointer = append_pointer(&node.pointer, &index.to_string());
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
            let mut diagnostic = self.input_diagnostic(
                CODE_RESERVED_HEADER_PARAMETER,
                node.doc_id,
                &node.pointer,
                format!(
                    "header parameter '{name}' is ignored because OpenAPI reserves Accept, Content-Type, and Authorization"
                ),
            );
            diagnostic.severity = Severity::Warning;
            self.sink.push(diagnostic);
            return None;
        }
        let schema = match object.get("schema") {
            None => {
                let pointer = append_pointer(&node.pointer, "schema");
                self.unsupported_schema(
                    node.doc_id,
                    &pointer,
                    "parameter content or missing schema is not supported",
                )
            }
            Some(value) => {
                let pointer = append_pointer(&node.pointer, "schema");
                self.parse_schema(NodeView {
                    doc_id: node.doc_id,
                    pointer,
                    value,
                })
            }
        };
        let style = self.parse_param_style(&node, object, "parameter");
        Some(Param {
            name: name.to_owned(),
            location,
            required: bool_field(object, "required"),
            deprecated: bool_field(object, "deprecated"),
            description: string_field(object, "description"),
            schema,
            style,
            explode: object.get("explode").and_then(Value::as_bool),
            allow_reserved: bool_field(object, "allowReserved"),
            source: self.source(node.doc_id, &node.pointer),
        })
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
        object
            .iter()
            .filter_map(|(key, value)| {
                let pointer = append_pointer(&node.pointer, key);
                let status = match parse_response_status(key) {
                    Some(status) => status,
                    None => {
                        self.sink.push(
                            Diagnostic::input(
                                CODE_RESPONSE_STATUS,
                                format!("invalid response status key '{key}'"),
                            )
                            .with_source(self.source_id(node.doc_id))
                            .with_json_pointer(&pointer),
                        );
                        return None;
                    }
                };
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
                    source: self.source(response_node.doc_id, &response_node.pointer),
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
            let canonical_name = match canonical_media_type(raw_name) {
                Ok(name) => name,
                Err(MediaKeyError::Parameterized) => {
                    self.sink.push(self.input_diagnostic(
                        CODE_MEDIA_TYPE,
                        node.doc_id,
                        &pointer,
                        format!(
                            "parameterized content key '{raw_name}' is not supported; content keys must omit media-type parameters"
                        ),
                    ));
                    continue;
                }
                Err(MediaKeyError::Malformed) => {
                    self.sink.push(self.input_diagnostic(
                        CODE_MEDIA_TYPE,
                        node.doc_id,
                        &pointer,
                        format!(
                            "malformed content key '{raw_name}'; expected an RFC 9110 type/subtype media type or wildcard range"
                        ),
                    ));
                    continue;
                }
            };
            if let Some((first_index, first_raw_name)) = canonical_keys.get(&canonical_name) {
                parsed[*first_index] = None;
                self.sink.push(self.input_diagnostic(
                    CODE_DUPLICATE_MEDIA_TYPE,
                    node.doc_id,
                    &pointer,
                    format!(
                        "duplicate content keys '{first_raw_name}' and '{raw_name}' canonicalize to '{canonical_name}'"
                    ),
                ));
                continue;
            }
            canonical_keys.insert(canonical_name.clone(), (parsed.len(), raw_name.clone()));
            let schema_pointer = append_pointer(&pointer, "schema");
            let (schema, schema_present) = match value.get("schema") {
                None => (
                    SchemaNode::Any {
                        meta: SchemaMeta {
                            source: self.source(node.doc_id, &schema_pointer),
                            ..SchemaMeta::default()
                        },
                    },
                    false,
                ),
                Some(schema) => (
                    self.parse_schema(NodeView {
                        doc_id: node.doc_id,
                        pointer: schema_pointer,
                        value: schema,
                    }),
                    true,
                ),
            };
            let encodings = if parse_encodings
                && (canonical_name == "application/x-www-form-urlencoded"
                    || canonical_name.starts_with("multipart/"))
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
                name: canonical_name,
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
                let content_type = encoding
                    .get("contentType")
                    .and_then(Value::as_str)
                    .map(|value| value.split(',').map(str::trim).map(str::to_owned).collect());
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
                Some((
                    name.clone(),
                    EncodingHeader {
                        required: bool_field(header, "required"),
                        schema,
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
                let pointer = append_pointer(&node.pointer, &index.to_string());
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
                let enum_values = match variable.get("enum") {
                    None => Vec::new(),
                    Some(Value::Array(values)) => values
                        .iter()
                        .enumerate()
                        .filter_map(|(index, value)| {
                            value.as_str().map(str::to_owned).or_else(|| {
                                self.shape_error(
                                    node.doc_id,
                                    &append_pointer(
                                        &append_pointer(&pointer, "enum"),
                                        &index.to_string(),
                                    ),
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
                let pointer = append_pointer(&node.pointer, &index.to_string());
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
                                    &append_pointer(&scopes_pointer, &index.to_string()),
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
                    Some("oauth2") => SecKind::OAuth2,
                    Some("openIdConnect") => SecKind::OpenIdConnect,
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
        let meta = self.schema_meta(&node, Some(object));
        let dialect_unsupported = if self.version == OasVersion::V3_0 {
            ["const", "prefixItems"]
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
        if let Some(keyword) = UNSUPPORTED_SCHEMA_KEYWORDS
            .iter()
            .find(|keyword| object.contains_key(**keyword))
        {
            self.sink.push(self.unsupported_diagnostic(
                node.doc_id,
                &append_pointer(&node.pointer, keyword),
                format!("unsupported schema keyword '{keyword}' becomes unknown"),
            ));
            return SchemaNode::Unknown {
                reason: format!("unsupported keyword {keyword}"),
                meta,
            };
        }
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            return self.parse_schema_ref(node, reference, meta);
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
                discriminator: self.parse_discriminator(node, object.get("discriminator")),
                meta,
            };
        }
        if let Some(branches) = object.get("anyOf") {
            return SchemaNode::AnyOf {
                branches: self.parse_schema_array(node, "anyOf", branches),
                meta,
            };
        }
        if self.version == OasVersion::V3_1 && object.contains_key("prefixItems") {
            return self.parse_tuple(node, object, meta);
        }
        self.parse_typed_schema(node, object, meta)
    }

    fn parse_schema_ref(
        &mut self,
        node: NodeView<'graph>,
        reference: &str,
        meta: SchemaMeta,
    ) -> SchemaNode {
        match self.graph.resolve(node.doc_id, reference) {
            Ok(target) => SchemaNode::Ref {
                target: SchemaRef {
                    source_id: self.source_id(target.doc_id).to_owned(),
                    json_pointer: target.json_pointer,
                },
                meta,
            },
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
                let child = append_pointer(&pointer, &index.to_string());
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
        let mapping = object
            .get("mapping")
            .and_then(Value::as_object)
            .map(|mapping| {
                mapping
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
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
            for value in types {
                let Some(name) = value.as_str() else {
                    return self.unsupported_schema(
                        node.doc_id,
                        &node.pointer,
                        "schema type arrays must contain strings",
                    );
                };
                if name == "null" {
                    meta.nullable = true;
                } else {
                    names.push(name);
                }
            }
            if meta.nullable {
                meta.nullable = finite_constraints_admit(object, PrimitiveType::Null);
            }
            if names.is_empty() {
                meta.nullable = false;
                return self.parse_type_name(node, object, "null", meta);
            }
            if names.len() == 1 {
                return self.parse_type_name(node, object, names[0], meta);
            }
            let branches = names
                .into_iter()
                .filter_map(|name| {
                    let branch_meta = SchemaMeta {
                        source: meta.source.clone(),
                        numeric_constraints: meta.numeric_constraints.clone(),
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
                    let mut branch = object.clone();
                    if let Some(values) = object.get("enum").and_then(Value::as_array) {
                        let filtered = values
                            .iter()
                            .filter(|value| value_matches_primitive(value, ty))
                            .cloned()
                            .collect::<Vec<_>>();
                        if filtered.is_empty() {
                            return None;
                        }
                        branch.insert("enum".to_owned(), Value::Array(filtered));
                    }
                    if object
                        .get("const")
                        .is_some_and(|value| !value_matches_primitive(value, ty))
                    {
                        return None;
                    }
                    Some(self.parse_primitive(&branch, ty, branch_meta))
                })
                .collect();
            return SchemaNode::AnyOf { branches, meta };
        }
        if let Some(ty) = object.get("type").and_then(Value::as_str) {
            return self.parse_type_name(node, object, ty, meta);
        }
        if object.contains_key("properties") || object.contains_key("additionalProperties") {
            return self.parse_object(node, object, meta);
        }
        if object.contains_key("items") {
            return self.parse_array(node, object, meta);
        }
        if object.contains_key("enum") || object.contains_key("const") {
            return SchemaNode::Finite {
                enum_values: object.get("enum").and_then(Value::as_array).cloned(),
                const_value: (self.version == OasVersion::V3_1)
                    .then(|| object.get("const").cloned())
                    .flatten(),
                meta,
            };
        }
        SchemaNode::Any { meta }
    }

    fn parse_type_name(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        ty: &str,
        meta: SchemaMeta,
    ) -> SchemaNode {
        match ty {
            "string" => self.parse_primitive(object, PrimitiveType::String, meta),
            "number" => self.parse_primitive(object, PrimitiveType::Number, meta),
            "integer" => self.parse_primitive(object, PrimitiveType::Integer, meta),
            "boolean" => self.parse_primitive(object, PrimitiveType::Boolean, meta),
            "null" if self.version == OasVersion::V3_1 => {
                self.parse_primitive(object, PrimitiveType::Null, meta)
            }
            "object" => self.parse_object(node, object, meta),
            "array" => self.parse_array(node, object, meta),
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
        meta: SchemaMeta,
    ) -> SchemaNode {
        SchemaNode::Primitive {
            ty,
            format: object
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned),
            enum_values: object.get("enum").and_then(Value::as_array).cloned(),
            const_value: (self.version == OasVersion::V3_1)
                .then(|| object.get("const").cloned())
                .flatten(),
            meta,
        }
    }

    fn parse_object(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        meta: SchemaMeta,
    ) -> SchemaNode {
        let required = object
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let properties = object
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| {
                properties
                    .iter()
                    .map(|(name, value)| {
                        let properties_pointer = append_pointer(&node.pointer, "properties");
                        let pointer = append_pointer(&properties_pointer, name);
                        let schema = self.parse_schema(NodeView {
                            doc_id: node.doc_id,
                            pointer: pointer.clone(),
                            value,
                        });
                        let schema_meta = schema.meta();
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
                            deprecated: schema_meta.docs.deprecated,
                            description: schema_meta.docs.description.clone(),
                            default: schema_meta.docs.default.clone(),
                            examples: schema_meta.docs.examples.clone(),
                            source: self.source(node.doc_id, &pointer),
                        };
                        (name.clone(), schema, prop_meta)
                    })
                    .collect()
            })
            .unwrap_or_default();
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
        SchemaNode::Object {
            properties,
            additional_properties,
            meta,
        }
    }

    fn parse_array(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        meta: SchemaMeta,
    ) -> SchemaNode {
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
                pointer: pointer.clone(),
                value: items,
            }),
        };
        SchemaNode::Array {
            items: Box::new(items),
            meta,
        }
    }

    fn parse_tuple(
        &mut self,
        node: NodeView<'graph>,
        object: &'graph Map<String, Value>,
        meta: SchemaMeta,
    ) -> SchemaNode {
        let prefix_pointer = append_pointer(&node.pointer, "prefixItems");
        let prefix_items = object
            .get("prefixItems")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        let pointer = append_pointer(&prefix_pointer, &index.to_string());
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
        SchemaNode::Tuple {
            prefix_items,
            rest,
            meta,
        }
    }

    fn schema_meta(
        &mut self,
        node: &NodeView<'graph>,
        object: Option<&Map<String, Value>>,
    ) -> SchemaMeta {
        let Some(object) = object else {
            return SchemaMeta {
                source: self.source(node.doc_id, &node.pointer),
                ..SchemaMeta::default()
            };
        };
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
        let numeric_constraints = collect_numeric_constraints(object, self.version);
        let constraints = collect_constraints(object, &numeric_constraints);
        SchemaMeta {
            nullable: self.version == OasVersion::V3_0
                && object
                    .get("nullable")
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
                constraints,
            },
            enum_extensions: EnumExtensionData {
                enum_varnames: object.get("x-enum-varnames").cloned(),
                enum_names: object.get("x-enumNames").cloned(),
                enum_descriptions: object.get("x-enum-descriptions").cloned(),
                enum_descriptions_camel: object.get("x-enumDescriptions").cloned(),
            },
            numeric_constraints,
            source: self.source(node.doc_id, &node.pointer),
        }
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
            Ok(target) => Some(NodeView {
                doc_id: target.doc_id,
                pointer: target.json_pointer,
                value: target.value,
            }),
            Err(diagnostic) => {
                self.sink.push(diagnostic);
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
        for name in template_names.difference(&declared_names) {
            self.path_parameter_error(
                node,
                format!("path '{raw_path}' template parameter '{name}' is not declared"),
            );
        }
        for name in declared_names.difference(&template_names) {
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

    fn unsupported_diagnostic(
        &self,
        doc_id: DocId,
        pointer: &str,
        message: impl Into<String>,
    ) -> Diagnostic {
        let mut diagnostic = Diagnostic::input(CODE_UNSUPPORTED, message)
            .with_source(self.source_id(doc_id))
            .with_json_pointer(pointer);
        diagnostic.severity = Severity::Warning;
        diagnostic
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

fn merge_parameters(path_parameters: &[Param], operation_parameters: Vec<Param>) -> Vec<Param> {
    let overridden = operation_parameters
        .iter()
        .map(|parameter| (parameter.name.clone(), parameter.location))
        .collect::<HashSet<_>>();
    path_parameters
        .iter()
        .filter(|parameter| !overridden.contains(&(parameter.name.clone(), parameter.location)))
        .cloned()
        .chain(operation_parameters)
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediaKeyError {
    Parameterized,
    Malformed,
}

fn canonical_media_type(raw: &str) -> Result<String, MediaKeyError> {
    if raw.contains(';') {
        return Err(MediaKeyError::Parameterized);
    }
    let Some((media_type, subtype)) = raw.split_once('/') else {
        return Err(MediaKeyError::Malformed);
    };
    if subtype.contains('/')
        || !is_rfc_9110_token(media_type)
        || !is_rfc_9110_token(subtype)
        || (media_type == "*" && subtype != "*")
    {
        return Err(MediaKeyError::Malformed);
    }
    Ok(format!(
        "{}/{}",
        media_type.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

fn is_rfc_9110_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
    if bytes.len() == 3 && matches!(bytes[0], b'1'..=b'5') && &bytes[1..] == b"XX" {
        return Some(ResponseStatus::Range(value.to_owned()));
    }
    None
}

fn finite_constraints_admit(object: &Map<String, Value>, ty: PrimitiveType) -> bool {
    let enum_admits = object
        .get("enum")
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values
                .iter()
                .any(|value| value_matches_primitive(value, ty))
        });
    let const_admits = object
        .get("const")
        .is_none_or(|value| value_matches_primitive(value, ty));
    enum_admits && const_admits
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
        if let Some(rendered) = numeric_value.or_else(|| object.get(key).map(compact_json)) {
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedConfig, load_config};
    use crate::ir::{ParamStyle, SecKind};
    use crate::loader::load_graph;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
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
    fn canonicalizes_valid_media_keys_and_rejects_parameterized_or_malformed_keys() {
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
                .map(|media| (media.name.as_str(), media.raw_name.as_str()))
                .collect::<Vec<_>>(),
            [
                ("application/json", "Application/JSON"),
                ("text/*", "TEXT/*"),
                ("*/*", "*/*")
            ]
        );
        assert_eq!(
            operation.responses[0]
                .media_types
                .iter()
                .map(|media| (media.name.as_str(), media.raw_name.as_str()))
                .collect::<Vec<_>>(),
            [("image/png", "IMAGE/PNG")]
        );

        let invalid = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1107")
            .collect::<Vec<_>>();
        assert_eq!(invalid.len(), 5);
        assert_eq!(
            invalid
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("parameterized"))
                .count(),
            2
        );
        assert_eq!(
            invalid
                .iter()
                .filter(|diagnostic| diagnostic.message.contains("malformed"))
                .count(),
            3
        );
        assert!(invalid.iter().all(|diagnostic| {
            diagnostic.source_id.is_some() && diagnostic.json_pointer.is_some()
        }));
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
                                "Application/JSON": { "schema": { "type": "string" } },
                                "application/json": { "schema": { "type": "integer" } },
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
                .name,
            "text/plain"
        );
        assert_eq!(operation.responses[0].media_types[0].name, "image/*");

        let duplicates = sink
            .as_slice()
            .iter()
            .filter(|diagnostic| diagnostic.code == "OASTS1108")
            .collect::<Vec<_>>();
        assert_eq!(duplicates.len(), 2);
        assert!(duplicates.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some("/paths/~1duplicate/post/requestBody/content/application~1json")
                && diagnostic.message.contains("Application/JSON")
                && diagnostic.message.contains("application/json")
        }));
        assert!(duplicates.iter().any(|diagnostic| {
            diagnostic.json_pointer.as_deref()
                == Some("/paths/~1duplicate/post/responses/200/content/text~1*")
                && diagnostic.message.contains("TEXT/*")
                && diagnostic.message.contains("text/*")
        }));
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
        assert!(sink.as_slice().iter().any(|diagnostic| {
            diagnostic.code == CODE_SHAPE
                && diagnostic.json_pointer.as_deref()
                    == Some("/paths/~1styles/get/parameters/7/style")
                && diagnostic.message.contains("parameter.style")
        }));
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
                                            "contentType": "text/plain, application/json",
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
            .find(|media| media.name == "application/x-www-form-urlencoded")
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
            Some(vec!["text/plain".to_owned(), "application/json".to_owned()])
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
            .find(|media| media.name == "multipart/form-data")
            .expect("multipart media type");
        assert_eq!(multipart.encodings[0].1.style, Some(ParamStyle::Form));
        assert!(
            media_types
                .iter()
                .find(|media| media.name == "application/json")
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
                    scheme: "bearer".to_owned()
                },
                SecKind::Http {
                    scheme: String::new()
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
                SecKind::OAuth2,
                SecKind::OpenIdConnect,
                SecKind::MutualTls,
                SecKind::Other,
                SecKind::Http {
                    scheme: "digest".to_owned()
                }
            ]
        );
        assert_eq!(ir.security_schemes[10].source.json_pointer, "/x-http");
        assert!(!sink.has_errors(), "{:#?}", sink.as_slice());
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
            .find(|media| media.name == "multipart/form-data")
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
            meta.numeric_constraints
                .minimum
                .as_ref()
                .map(ToString::to_string),
            Some("1".to_owned())
        );
        assert_eq!(
            meta.numeric_constraints
                .maximum
                .as_ref()
                .map(ToString::to_string),
            Some("9".to_owned())
        );
        assert_eq!(
            meta.numeric_constraints.exclusive_minimum,
            Some(crate::ir::ExclusiveBound::Number(serde_json::Number::from(
                2
            )))
        );
        assert_eq!(
            meta.numeric_constraints.exclusive_maximum,
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
                .numeric_constraints
                .exclusive_minimum,
            Some(crate::ir::ExclusiveBound::Boolean(true))
        );
    }

    #[test]
    fn unsupported_condition_becomes_unknown_and_keeps_ir() {
        let document = json!({
            "openapi": "3.1.0",
            "components": { "schemas": { "Conditional": { "if": { "type": "string" } } } }
        });
        let (_temp, graph) = graph_for(&document);
        let mut sink = DiagnosticSink::new();
        let ir = parse(&graph, &mut sink).expect("IR");
        assert!(!sink.has_errors());
        assert!(!sink.as_slice().is_empty());
        assert!(matches!(ir.schemas[0].schema, SchemaNode::Unknown { .. }));
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
        assert_eq!(
            canonical_media_type("!#$%&'*+-.^_`|~/!#$%&'*+-.^_`|~"),
            Ok("!#$%&'*+-.^_`|~/!#$%&'*+-.^_`|~".to_owned())
        );
        for malformed in ["type/", "/subtype", "type/subtype/extra", "type /subtype"] {
            assert_eq!(
                canonical_media_type(malformed),
                Err(MediaKeyError::Malformed)
            );
        }
        assert_eq!(
            canonical_media_type("type/subtype;parameter=value"),
            Err(MediaKeyError::Parameterized)
        );

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
}
