//! Parameter serialization is resolved outside the client model so non-client artifacts can use
//! the same defaults and helper selection without triggering client-specific diagnostics.

use crate::config::DeepObjectEncoding;
use crate::ir::{Param, ParamLocation, ParamStyle};
use crate::media::{is_json, media_essence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedParameterSerialization {
    pub location: ParamLocation,
    pub style: ParamStyle,
    pub explode: bool,
    pub allow_reserved: bool,
    pub helper: HelperId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperId {
    PathSimple,
    PathSimpleExplode,
    PathLabel,
    PathLabelExplode,
    PathMatrix,
    PathMatrixExplode,
    QueryForm,
    QueryFormExplode,
    QuerySpaceDelimited,
    QuerySpaceDelimitedObject,
    QueryPipeDelimited,
    QueryPipeDelimitedObject,
    QueryDeepObject,
    /// Bracket encoding for a `deepObject` parameter whose schema is not object-only, dispatching
    /// on the runtime value's shape. Reached only under `compat.deepObjectEncoding: extended`.
    QueryDeepObjectExtended,
    HeaderSimple,
    HeaderSimpleExplode,
    /// Content-sourced JSON-family parameters: `JSON.stringify` then location-appropriate encoding.
    /// One per wire framing (path segment vs `name=value` query/cookie pair vs raw simple-header
    /// value); style/explode/allowReserved never apply. Cookies reuse the query serializer.
    ContentJsonPath,
    ContentJsonQuery,
    ContentJsonHeader,
}

impl HelperId {
    /// Every variant, in declaration order. The client emitter reserves each helper's exported
    /// name against component imports, and that reservation is only sound if this covers the enum;
    /// `helper_id_all_lists_every_variant` fails to compile when a variant is added without being
    /// listed here.
    pub(crate) const ALL: [Self; 19] = [
        Self::PathSimple,
        Self::PathSimpleExplode,
        Self::PathLabel,
        Self::PathLabelExplode,
        Self::PathMatrix,
        Self::PathMatrixExplode,
        Self::QueryForm,
        Self::QueryFormExplode,
        Self::QuerySpaceDelimited,
        Self::QuerySpaceDelimitedObject,
        Self::QueryPipeDelimited,
        Self::QueryPipeDelimitedObject,
        Self::QueryDeepObject,
        Self::QueryDeepObjectExtended,
        Self::HeaderSimple,
        Self::HeaderSimpleExplode,
        Self::ContentJsonPath,
        Self::ContentJsonQuery,
        Self::ContentJsonHeader,
    ];

    /// Whether this helper is a content-sourced JSON serializer, which the runtime feeds the raw
    /// typed value (not a pre-validated `ParamValue`) so its descriptor entry carries `content: true`.
    #[must_use]
    pub(crate) fn is_content_json(self) -> bool {
        matches!(
            self,
            Self::ContentJsonPath | Self::ContentJsonQuery | Self::ContentJsonHeader
        )
    }
}

/// How a parameter reaches the wire, decided by its content media type (OAS Parameter Object
/// `content`). Non-content parameters and content parameters that serialize identically to a
/// schema+style string both resolve to `SchemaStyle`; the class only distinguishes what the
/// serializer and input type must do differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParamContentClass {
    /// Schema+style serialization, or a content text/plain-over-string passthrough that is
    /// byte-for-byte identical to it: the input stays typed from the schema.
    SchemaStyle,
    /// Content JSON family: `JSON.stringify` then location encoding; the input stays typed.
    ContentJson,
    /// Content media the client cannot serialize (any non-JSON that is not a text/plain-over-string
    /// passthrough): the caller pre-serializes to a `string`, and OASTS1443 records it.
    CallerSerialized,
}

fn classify_param_content(parameter: &Param, schema_is_string_only: bool) -> ParamContentClass {
    let Some(media) = parameter.content_media_type.as_deref() else {
        return ParamContentClass::SchemaStyle;
    };
    if is_json(media) {
        return ParamContentClass::ContentJson;
    }
    // text/plain over a string-shaped schema (nullability aside) is a bare passthrough — the value
    // is used as-is with location encoding, exactly like a schema+style string. Every other media,
    // and text/plain over a non-string schema, needs a caller-serialized string.
    if media_essence(media) == "text/plain" && schema_is_string_only {
        return ParamContentClass::SchemaStyle;
    }
    ParamContentClass::CallerSerialized
}

pub(crate) fn parameter_requires_caller_serialization(
    parameter: &Param,
    schema_is_string_only: bool,
) -> bool {
    classify_param_content(parameter, schema_is_string_only) == ParamContentClass::CallerSerialized
}

pub(crate) fn resolve_parameter_serialization(
    parameter: &Param,
    schema_is_object_only: bool,
    schema_is_string_only: bool,
    deep_object: DeepObjectEncoding,
) -> ResolvedParameterSerialization {
    // OAS 3.1 §4.8.12.2.2: the default style for `in: cookie` is `form`, matching `in: query`.
    // Content parameters carry no style/explode (parse zeroes them), so these resolve to the
    // location defaults and only feed the vestigial resolved fields; content classification
    // selects the helper below and serialization ignores style/explode/allowReserved.
    let style = parameter.style.unwrap_or(match parameter.location {
        ParamLocation::Query | ParamLocation::Cookie => ParamStyle::Form,
        ParamLocation::Path | ParamLocation::Header => ParamStyle::Simple,
    });
    let explode = parameter
        .explode
        .unwrap_or(matches!(style, ParamStyle::Form | ParamStyle::DeepObject));
    let helper = match classify_param_content(parameter, schema_is_string_only) {
        ParamContentClass::SchemaStyle => helper_id(
            parameter.location,
            style,
            explode,
            schema_is_object_only,
            deep_object,
        ),
        ParamContentClass::ContentJson => content_json_helper(parameter.location),
        ParamContentClass::CallerSerialized => location_default_helper(parameter.location),
    };
    ResolvedParameterSerialization {
        location: parameter.location,
        style,
        explode,
        // OAS 3.1 §4.8.12: allowReserved applies to `in: query` only. A parser that forwards it
        // for any location would let a non-query serializer emit raw reserved characters — on the
        // cookie path a raw ';'/'=' smuggles extra pairs into the joined Cookie header.
        allow_reserved: parameter.location == ParamLocation::Query && parameter.allow_reserved,
        helper,
    }
}

/// The location-default serializer used when style and explode are irrelevant — the terminal arm of
/// `helper_id`, reused for content parameters whose value is always a single string. A cookie
/// parameter reuses the query-form serializer: its value is always `allowReserved: false` (enforced
/// by `resolve_parameter_serialization`), for which `serializeQueryForm` produces byte-identical
/// output, and the runtime routes it into the Cookie header by the descriptor's `location`, not the
/// helper identity.
fn location_default_helper(location: ParamLocation) -> HelperId {
    match location {
        ParamLocation::Path => HelperId::PathSimple,
        ParamLocation::Query | ParamLocation::Cookie => HelperId::QueryForm,
        ParamLocation::Header => HelperId::HeaderSimple,
    }
}

fn content_json_helper(location: ParamLocation) -> HelperId {
    match location {
        ParamLocation::Path => HelperId::ContentJsonPath,
        // A cookie JSON value serializes identically to a query one; location drives Cookie framing.
        ParamLocation::Query | ParamLocation::Cookie => HelperId::ContentJsonQuery,
        ParamLocation::Header => HelperId::ContentJsonHeader,
    }
}

fn helper_id(
    location: ParamLocation,
    style: ParamStyle,
    explode: bool,
    schema_is_object_only: bool,
    deep_object: DeepObjectEncoding,
) -> HelperId {
    match (location, style, explode) {
        (ParamLocation::Path, ParamStyle::Simple, false) => HelperId::PathSimple,
        (ParamLocation::Path, ParamStyle::Simple, true) => HelperId::PathSimpleExplode,
        (ParamLocation::Path, ParamStyle::Label, false) => HelperId::PathLabel,
        (ParamLocation::Path, ParamStyle::Label, true) => HelperId::PathLabelExplode,
        (ParamLocation::Path, ParamStyle::Matrix, false) => HelperId::PathMatrix,
        (ParamLocation::Path, ParamStyle::Matrix, true) => HelperId::PathMatrixExplode,
        (ParamLocation::Query, ParamStyle::Form, false) => HelperId::QueryForm,
        (ParamLocation::Query, ParamStyle::Form, true) => HelperId::QueryFormExplode,
        (ParamLocation::Query, ParamStyle::SpaceDelimited, _) if schema_is_object_only => {
            HelperId::QuerySpaceDelimitedObject
        }
        (ParamLocation::Query, ParamStyle::SpaceDelimited, _) => HelperId::QuerySpaceDelimited,
        (ParamLocation::Query, ParamStyle::PipeDelimited, _) if schema_is_object_only => {
            HelperId::QueryPipeDelimitedObject
        }
        (ParamLocation::Query, ParamStyle::PipeDelimited, _) => HelperId::QueryPipeDelimited,
        // An object-only schema keeps the OpenAPI-defined serializer in both modes, so opting into
        // `extended` never changes output for a parameter the specification already covers. Every
        // other admitted shape — array, untyped, or a projection the domain analysis cannot pin —
        // may hold either an object or an array at runtime, so it takes the dispatching serializer.
        (ParamLocation::Query, ParamStyle::DeepObject, _)
            if deep_object == DeepObjectEncoding::Strict || schema_is_object_only =>
        {
            HelperId::QueryDeepObject
        }
        (ParamLocation::Query, ParamStyle::DeepObject, _) => HelperId::QueryDeepObjectExtended,
        (ParamLocation::Header, ParamStyle::Simple, false) => HelperId::HeaderSimple,
        (ParamLocation::Header, ParamStyle::Simple, true) => HelperId::HeaderSimpleExplode,
        _ => location_default_helper(location),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimited_query_helpers_follow_the_projected_domain() {
        for (style, schema_is_object_only, expected) in [
            (
                ParamStyle::SpaceDelimited,
                true,
                HelperId::QuerySpaceDelimitedObject,
            ),
            (
                ParamStyle::SpaceDelimited,
                false,
                HelperId::QuerySpaceDelimited,
            ),
            (
                ParamStyle::PipeDelimited,
                true,
                HelperId::QueryPipeDelimitedObject,
            ),
            (
                ParamStyle::PipeDelimited,
                false,
                HelperId::QueryPipeDelimited,
            ),
        ] {
            assert_eq!(
                helper_id(
                    ParamLocation::Query,
                    style,
                    false,
                    schema_is_object_only,
                    DeepObjectEncoding::Strict,
                ),
                expected
            );
        }
    }

    #[test]
    fn parameter_helper_edges_are_total() {
        for (location, style, explode, expected) in [
            (
                ParamLocation::Path,
                ParamStyle::Simple,
                false,
                HelperId::PathSimple,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Simple,
                true,
                HelperId::PathSimpleExplode,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Label,
                false,
                HelperId::PathLabel,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Matrix,
                false,
                HelperId::PathMatrix,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Matrix,
                true,
                HelperId::PathMatrixExplode,
            ),
            (
                ParamLocation::Query,
                ParamStyle::Form,
                false,
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Header,
                ParamStyle::Simple,
                true,
                HelperId::HeaderSimpleExplode,
            ),
            (
                ParamLocation::Path,
                ParamStyle::Form,
                false,
                HelperId::PathSimple,
            ),
            (
                ParamLocation::Query,
                ParamStyle::Simple,
                false,
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Header,
                ParamStyle::Form,
                false,
                HelperId::HeaderSimple,
            ),
            (
                ParamLocation::Cookie,
                ParamStyle::Form,
                false,
                HelperId::QueryForm,
            ),
            (
                ParamLocation::Cookie,
                ParamStyle::Simple,
                false,
                HelperId::QueryForm,
            ),
        ] {
            assert_eq!(
                helper_id(location, style, explode, false, DeepObjectEncoding::Strict,),
                expected
            );
        }
    }

    /// `HelperId::ALL` feeds the client emitter's reserved-name set, so a variant missing from it
    /// would leave that helper's exported name shadowable by a component import. The match below
    /// is exhaustive: adding a variant stops this compiling until `ALL` is extended too.
    #[test]
    fn helper_id_all_lists_every_variant() {
        for helper in HelperId::ALL {
            let position = match helper {
                HelperId::PathSimple => 0,
                HelperId::PathSimpleExplode => 1,
                HelperId::PathLabel => 2,
                HelperId::PathLabelExplode => 3,
                HelperId::PathMatrix => 4,
                HelperId::PathMatrixExplode => 5,
                HelperId::QueryForm => 6,
                HelperId::QueryFormExplode => 7,
                HelperId::QuerySpaceDelimited => 8,
                HelperId::QuerySpaceDelimitedObject => 9,
                HelperId::QueryPipeDelimited => 10,
                HelperId::QueryPipeDelimitedObject => 11,
                HelperId::QueryDeepObject => 12,
                HelperId::QueryDeepObjectExtended => 13,
                HelperId::HeaderSimple => 14,
                HelperId::HeaderSimpleExplode => 15,
                HelperId::ContentJsonPath => 16,
                HelperId::ContentJsonQuery => 17,
                HelperId::ContentJsonHeader => 18,
            };
            assert_eq!(HelperId::ALL[position], helper);
        }
    }
}
