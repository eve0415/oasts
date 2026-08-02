//! Response media classification shared by artifacts that read or write response bodies.

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{MediaType, Operation, ResponseStatus, SchemaNode, SourceRef};
use crate::media::{is_json, is_xml};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseMediaKind {
    Streaming,
    Json,
    Xml,
    Multipart,
    MultipartUnnamed,
    Text,
    Binary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseSchemaProjection {
    StringWithOptionalNull,
    IncludesString,
    ExcludesString,
    Unsupported,
}

pub(crate) trait ResponseMediaProjector {
    fn response_schema_projection(&self, schema: &SchemaNode) -> ResponseSchemaProjection;
}

pub(crate) fn classify_response_media(
    media: &MediaType,
    projector: &impl ResponseMediaProjector,
) -> ResponseMediaKind {
    if media.streaming_marked || media.essence == "text/event-stream" {
        ResponseMediaKind::Streaming
    } else if is_json(&media.essence) {
        ResponseMediaKind::Json
    } else if xml_requires_structural_mapping(media, projector) {
        ResponseMediaKind::Xml
    } else if is_xml(&media.essence) {
        ResponseMediaKind::Binary
    } else if media.essence == "multipart/form-data" {
        ResponseMediaKind::Multipart
    } else if media.essence.starts_with("multipart/") {
        ResponseMediaKind::MultipartUnnamed
    } else if media.essence == "application/x-www-form-urlencoded"
        || media.essence.starts_with("text/")
    {
        ResponseMediaKind::Text
    } else {
        ResponseMediaKind::Binary
    }
}

pub(crate) fn diagnose_operation_response_media(
    operation: &Operation,
    projector: &impl ResponseMediaProjector,
    sink: &mut DiagnosticSink,
) {
    for response in &operation.responses {
        let static_bodyless = operation.method.eq_ignore_ascii_case("head")
            || matches!(
                &response.status,
                ResponseStatus::Exact(value) if matches!(value.as_str(), "204" | "205" | "304")
            );
        for media in &response.media_types {
            if static_bodyless {
                sink.push(source_diagnostic(
                    "OASTS1406",
                    format!(
                        "response key '{}' is statically bodyless but declares media '{}'",
                        response_status_name(&response.status),
                        media.essence
                    ),
                    &media.source,
                    Severity::Warning,
                ));
                continue;
            }
            if let Some(diagnostic) = response_media_diagnostic(media, projector) {
                sink.push(diagnostic);
            }
        }
    }
}

fn response_media_diagnostic(
    media: &MediaType,
    projector: &impl ResponseMediaProjector,
) -> Option<Diagnostic> {
    let projection = projector.response_schema_projection(&media.schema);
    let (code, message) = match classify_response_media(media, projector) {
        ResponseMediaKind::Streaming => (
            "OASTS1402",
            format!(
                "response media '{}' requires streaming support, which is not yet available",
                media.essence
            ),
        ),
        ResponseMediaKind::Xml => (
            "OASTS1403",
            format!(
                "response media '{}' is XML, which Oasts does not support",
                media.essence
            ),
        ),
        ResponseMediaKind::MultipartUnnamed => (
            "OASTS1404",
            format!(
                "multipart response media '{}' has no part-to-property mapping; only multipart/form-data names its parts (RFC 7578 section 4.2 Content-Disposition), so nothing decides which declared property a part belongs to",
                media.essence
            ),
        ),
        ResponseMediaKind::Text
            if media.schema_present && projection == ResponseSchemaProjection::ExcludesString =>
        {
            (
                "OASTS1405",
                format!(
                    "text response media '{}' requires a schema whose primitive projection contains string",
                    media.essence
                ),
            )
        }
        ResponseMediaKind::Json
        | ResponseMediaKind::Multipart
        | ResponseMediaKind::Text
        | ResponseMediaKind::Binary => return None,
    };
    Some(source_diagnostic(
        code,
        message,
        &media.source,
        Severity::Error,
    ))
}

fn xml_requires_structural_mapping(
    media: &MediaType,
    projector: &impl ResponseMediaProjector,
) -> bool {
    is_xml(&media.essence)
        && media.schema_present
        && matches!(
            projector.response_schema_projection(&media.schema),
            ResponseSchemaProjection::IncludesString | ResponseSchemaProjection::ExcludesString
        )
}

pub(crate) fn response_status_name(status: &ResponseStatus) -> &str {
    match status {
        ResponseStatus::Exact(value) | ResponseStatus::Range(value) => value,
        ResponseStatus::Default => "default",
    }
}

fn source_diagnostic(
    code: &'static str,
    message: impl Into<String>,
    source: &SourceRef,
    severity: Severity,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::input(code, message)
        .with_source(&source.source_id)
        .with_json_pointer(&source.json_pointer);
    diagnostic.severity = severity;
    if let (Some(line), Some(col)) = (source.line, source.col) {
        diagnostic = diagnostic.with_location(line, col);
    }
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_diagnostics_preserve_source_locations() {
        let source = SourceRef {
            source_id: "workspace/openapi.yaml".to_owned(),
            json_pointer: "/paths/~1items/get/responses/200".to_owned(),
            line: Some(7),
            col: Some(9),
        };
        let diagnostic = source_diagnostic(
            "OASTS1403",
            "unsupported response",
            &source,
            Severity::Error,
        );
        assert_eq!((diagnostic.line, diagnostic.col), (Some(7), Some(9)));
    }
}
