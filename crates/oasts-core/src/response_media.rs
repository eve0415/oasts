//! Response media classification shared by artifacts that read or write response bodies.

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::ir::{MediaType, Operation, ResponseStatus, SchemaNode, SourceRef};
use crate::media::{is_json, is_xml};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseMediaKind {
    /// `text/event-stream`: framed events, each event's `data` field JSON-decoded against the
    /// declared schema. The one streaming family with a schema position at all.
    StreamingSse,
    /// A streaming-marked media type that is not `text/event-stream`: opaque bytes, permanently
    /// schema-unchecked.
    StreamingRaw,
    Json,
    Xml,
    Multipart,
    MultipartUnnamed,
    Text,
    Binary,
}

impl ResponseMediaKind {
    pub(crate) fn is_streaming(self) -> bool {
        matches!(self, Self::StreamingSse | Self::StreamingRaw)
    }
}

/// Which streaming family a media entry belongs to. Kept apart from `ResponseMediaKind` because a
/// request body needs the same question answered and never goes through the response classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamKind {
    Sse,
    Raw,
}

/// Whether this entry's declared schema describes a whole JSON value the client will hold — the
/// question every schema-consuming emitter is really asking when it tests for JSON.
///
/// A streaming-marked JSON media is the case that separates the two: it is `+json` by essence, but
/// its payload is a byte stream, so a validator built from its schema would be handed a
/// `ReadableStream` and a transform would be asked to convert one. Both are wrong, and both look
/// right to a bare essence test.
pub(crate) fn media_carries_json_value(essence: &str, streaming_marked: bool) -> bool {
    is_json(essence) && media_stream_kind(essence, streaming_marked).is_none()
}

/// Whether this entry declares a schema a validator can be built from. Two shapes qualify: a JSON
/// value the client holds whole, and an event stream, whose schema describes each event's decoded
/// `data` and so is checked once per event rather than once per body. A raw stream has no schema
/// position at all, which is what the unchecked-data policy reports.
pub(crate) fn media_has_validatable_schema(essence: &str, streaming_marked: bool) -> bool {
    media_carries_json_value(essence, streaming_marked)
        || media_stream_kind(essence, streaming_marked) == Some(StreamKind::Sse)
}

/// `text/event-stream` is SSE whether or not it carries the mark; the mark makes anything else an
/// opaque byte stream. Refusal is not this function's job — the callers that can refuse a media
/// class do so before asking.
pub(crate) fn media_stream_kind(essence: &str, streaming_marked: bool) -> Option<StreamKind> {
    if essence == "text/event-stream" {
        Some(StreamKind::Sse)
    } else if streaming_marked {
        Some(StreamKind::Raw)
    } else {
        None
    }
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

/// `text/event-stream` is a streaming branch whether or not it carries the mark, and its schema
/// describes each event's decoded `data` rather than the whole body — so it is decided before the
/// buffered classification runs and never reaches the `text/*` string-projection rule.
///
/// The mark itself only reaches a media type the buffered classifier does not already refuse. An
/// XML type needing structural mapping, or a `multipart/*` type with no part naming, keeps its own
/// diagnostic instead: a vendor extension must not be able to launder a refused media class into
/// an opaque byte stream that generates cleanly.
pub(crate) fn classify_response_media(
    media: &MediaType,
    projector: &impl ResponseMediaProjector,
) -> ResponseMediaKind {
    if media.essence == "text/event-stream" {
        return ResponseMediaKind::StreamingSse;
    }
    let buffered = classify_buffered_media(media, projector);
    if media.streaming_marked
        && !matches!(
            buffered,
            ResponseMediaKind::Xml | ResponseMediaKind::MultipartUnnamed
        )
    {
        return ResponseMediaKind::StreamingRaw;
    }
    buffered
}

fn classify_buffered_media(
    media: &MediaType,
    projector: &impl ResponseMediaProjector,
) -> ResponseMediaKind {
    if is_json(&media.essence) {
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

/// The bodyless cases generation can know: Fetch sets a final response's body to null for a `HEAD`
/// and for an exact 204/205/304 whatever the description declares, so such a branch delivers
/// `undefined` and no decoder — streaming or otherwise — ever runs on it.
pub(crate) fn statically_bodyless(method: &str, status: &ResponseStatus) -> bool {
    method.eq_ignore_ascii_case("head")
        || matches!(
            status,
            ResponseStatus::Exact(value) if matches!(value.as_str(), "204" | "205" | "304")
        )
}

pub(crate) fn diagnose_operation_response_media(
    operation: &Operation,
    projector: &impl ResponseMediaProjector,
    sink: &mut DiagnosticSink,
) {
    for response in &operation.responses {
        let static_bodyless = statically_bodyless(&operation.method, &response.status);
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
        // A streaming branch decodes at the runtime, per item or per chunk, so there is nothing
        // here to refuse: SSE carries its schema to each event, and a raw stream carries none at
        // all, which the unchecked-data policy is what reports.
        ResponseMediaKind::StreamingSse
        | ResponseMediaKind::StreamingRaw
        | ResponseMediaKind::Json
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

/// The unchecked-data policy's source-dependent half. A raw streaming success branch carries bytes
/// and no schema position at all, so it stays unchecked however `validation.response` is set —
/// unlike the config-only half, which is decided before any document is read. SSE is excluded on
/// purpose: its events are checked one at a time when validation is on.
pub(crate) fn diagnose_unchecked_raw_streams(
    operation: &Operation,
    projector: &impl ResponseMediaProjector,
    reject: bool,
    sink: &mut DiagnosticSink,
) {
    for response in &operation.responses {
        // A statically bodyless branch delivers `undefined` and never creates a handle, so there is
        // no unchecked stream data for this policy to be about — the contradictory declaration is
        // already reported, once, by the bodyless diagnostic.
        if !response_can_succeed(&response.status)
            || statically_bodyless(&operation.method, &response.status)
        {
            continue;
        }
        for media in &response.media_types {
            if classify_response_media(media, projector) != ResponseMediaKind::StreamingRaw {
                continue;
            }
            let (code, severity) = if reject {
                ("OASTS1407", Severity::Error)
            } else {
                ("OASTS1408", Severity::Warning)
            };
            sink.push(source_diagnostic(
                code,
                format!(
                    "response key '{}' streams '{}' as raw bytes, which carries no schema and is never validated",
                    response_status_name(&response.status),
                    media.essence
                ),
                &media.source,
                severity,
            ));
        }
    }
}

/// Whether a declared key can ever be selected on a 2xx status. A range or `default` key can, and
/// so can any exact 2xx; every other exact key is an error branch and its payload is never the
/// successful data the policy is about.
fn response_can_succeed(status: &ResponseStatus) -> bool {
    match status {
        ResponseStatus::Default => true,
        ResponseStatus::Range(value) => value.starts_with('2'),
        ResponseStatus::Exact(value) => value.starts_with('2'),
    }
}

pub(crate) fn xml_requires_structural_mapping(
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

    #[test]
    fn event_stream_is_sse_by_essence_and_the_mark_makes_anything_else_raw() {
        // `text/event-stream` is SSE either way: the media type itself decides the family, so a
        // document that also writes the mark cannot demote its events to opaque bytes.
        assert_eq!(
            media_stream_kind("text/event-stream", false),
            Some(StreamKind::Sse)
        );
        assert_eq!(
            media_stream_kind("text/event-stream", true),
            Some(StreamKind::Sse)
        );
        // Every other media type needs the mark, and the mark only ever buys the raw family.
        assert_eq!(
            media_stream_kind("application/octet-stream", true),
            Some(StreamKind::Raw)
        );
        assert_eq!(media_stream_kind("application/octet-stream", false), None);
    }
}
