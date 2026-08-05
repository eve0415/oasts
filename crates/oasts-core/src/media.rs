use std::collections::BTreeMap;

/// How wide a media type or range matches on the wire, decided by the RFC 9110 type/subtype
/// wildcards alone — never by a raw `*` substring, so a tchar-legal subtype such as `text/*foo`
/// (subtype `*foo`, not the `*` wildcard) is `Concrete`, and a parameter (`text/*; q=0.5`) never
/// masks the underlying range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MediaRangeKind {
    /// A fully specified type/subtype: `application/json`, `text/*foo`.
    Concrete,
    /// A subtype wildcard under a concrete type: `text/*`.
    TypeRange,
    /// The full wildcard `*/*` (the grammar forbids `*/subtype`).
    Any,
}

pub(crate) struct CanonicalMedia {
    pub full: String,
    pub essence: String,
    pub range_kind: MediaRangeKind,
}

pub(crate) struct ParsedDeclaredMedia {
    pub full: String,
    pub range_kind: MediaRangeKind,
}

struct ParsedMedia {
    essence: String,
    range_kind: MediaRangeKind,
    parameters: BTreeMap<String, String>,
}

/// Canonicalizes an OpenAPI content-map key into the internal identity used for content-map
/// deduplication and body/response media matching. This identity is never emitted to the wire, so
/// it takes the compact unspaced parameter form (see the `spaced` divergence on `canonical_full`).
pub(crate) fn canonical_content_key(raw: &str) -> Result<CanonicalMedia, ()> {
    let mut parsed = parse_media(raw)?;
    // Fold the charset value to lowercase — and only charset, which RFC 2046 defines as
    // case-insensitive; every other parameter value stays byte-preserved. Without this,
    // `text/plain;charset=UTF-8` and `text/plain;charset=utf-8` canonicalize to distinct keys and
    // survive as two content-map branches that are indistinguishable on the wire, instead of
    // colliding into the duplicate-content-key diagnostic.
    if let Some(charset) = parsed.parameters.get_mut("charset") {
        charset.make_ascii_lowercase();
    }
    let full = canonical_full(&parsed.essence, parsed.parameters, false);
    Ok(CanonicalMedia {
        full,
        essence: parsed.essence,
        range_kind: parsed.range_kind,
    })
}

/// Canonicalizes an Encoding Object `contentType` value for emission as a multipart part's
/// `Content-Type` header. Shares essence and parameter folding — including the RFC 2046 charset
/// lowercasing — with `canonical_content_key`; it diverges only in taking the `; `-spaced wire form
/// (see the `spaced` rationale on `canonical_full`), because this string is emitted onto the wire.
pub(crate) fn canonical_encoding_content_type(input: &str) -> Result<ParsedDeclaredMedia, ()> {
    let mut parsed = parse_media(input)?;
    if let Some(charset) = parsed.parameters.get_mut("charset") {
        charset.make_ascii_lowercase();
    }
    Ok(ParsedDeclaredMedia {
        full: canonical_full(&parsed.essence, parsed.parameters, true),
        range_kind: parsed.range_kind,
    })
}

pub(crate) fn split_media_type_list(input: &str) -> Result<Vec<&str>, ()> {
    split_quoted(input, ',')
}

/// The media type essence — everything before the first `;` parameter separator, trailing
/// whitespace trimmed. The essence is what every wire classifier keys on: a parameterized value
/// (`application/json; charset=utf-8`) must route by its base type, never fall through to a
/// schema-shape fallback and corrupt the wire. The first `;` always precedes any parameter, and the
/// essence itself can hold no quotes or `;`, so a plain `split_once` isolates it without the
/// quoted-segment handling `canonical_encoding_content_type` needs.
pub(crate) fn media_essence(media: &str) -> &str {
    media
        .split_once(';')
        .map_or(media, |(essence, _)| essence)
        .trim_end()
}

/// Whether a media type is JSON-family (RFC 8259 `application/json` or any `+json` structured
/// suffix), keyed on the essence so a parameterized value classifies by its base type.
///
/// `text/json` is deliberately absent. It was never registered — RFC 8259 registers
/// `application/json` — and recognizing it split this compiler in two: a `text/json` body decoded
/// as JSON coming back and was carried as text going out, so one document's media type meant two
/// things. A document that carries JSON says `application/json`; one that says `text/json` gets the
/// same treatment as every other `text/*`.
pub(crate) fn is_json(media: &str) -> bool {
    let essence = media_essence(media);
    essence == "application/json"
        || essence
            .rsplit_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+json"))
}

/// Whether a media type is XML-family (`application/xml`, `text/xml`, or any `+xml` structured
/// suffix), keyed on the essence so a parameterized value classifies by its base type.
pub(crate) fn is_xml(media: &str) -> bool {
    let essence = media_essence(media);
    matches!(essence, "application/xml" | "text/xml")
        || essence
            .rsplit_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+xml"))
}

fn parse_media(input: &str) -> Result<ParsedMedia, ()> {
    if !input.as_bytes().contains(&b';') {
        let (essence, range_kind) = parse_media_essence(input)?;
        let mut essence = essence.to_owned();
        essence.make_ascii_lowercase();
        return Ok(ParsedMedia {
            essence,
            range_kind,
            parameters: BTreeMap::new(),
        });
    }

    let segments = split_quoted(input, ';')?;
    let (essence, range_kind) = parse_media_essence(segments.first().copied().ok_or(())?)?;
    let mut canonical_essence = essence.to_owned();
    canonical_essence.make_ascii_lowercase();
    let mut parameters = BTreeMap::new();
    for segment in &segments[1..] {
        let segment = segment.trim_matches([' ', '\t']);
        if segment.is_empty() {
            return Err(());
        }
        let (name, raw_value) = segment.split_once('=').ok_or(())?;
        if name != name.trim_matches([' ', '\t'])
            || raw_value != raw_value.trim_matches([' ', '\t'])
            || name.is_empty()
            || !name.bytes().all(is_tchar)
        {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if parameters.contains_key(&name) {
            return Err(());
        }
        parameters.insert(name, parse_parameter_value(raw_value)?);
    }
    Ok(ParsedMedia {
        essence: canonical_essence,
        range_kind,
        parameters,
    })
}

fn parse_media_essence(input: &str) -> Result<(&str, MediaRangeKind), ()> {
    let essence = input.trim();
    let (media_type, subtype) = essence.split_once('/').ok_or(())?;
    if media_type.is_empty()
        || subtype.is_empty()
        || !media_type.bytes().all(is_tchar)
        || !subtype.bytes().all(is_tchar)
        || media_type == "*" && subtype != "*"
    {
        return Err(());
    }
    let range_kind = if media_type == "*" {
        MediaRangeKind::Any
    } else if subtype == "*" {
        MediaRangeKind::TypeRange
    } else {
        MediaRangeKind::Concrete
    };
    Ok((essence, range_kind))
}

/// Renders the canonical media string: essence followed by the BTreeMap-sorted parameters.
///
/// `spaced` is the divergence point between the two canonical formats. Compact `;`-joined for the
/// content-map key (`canonical_content_key`) over `; `-spaced for the encoding `contentType`
/// (`canonical_encoding_content_type`), because the key is an internal dedup/match identity kept
/// byte-minimal while the encoding value is emitted as a wire `Content-Type` header, where the RFC
/// 9110 conventional form places a space after each `;`.
fn canonical_full(essence: &str, parameters: BTreeMap<String, String>, spaced: bool) -> String {
    let mut canonical = essence.to_owned();
    for (name, value) in parameters {
        canonical.push(';');
        if spaced {
            canonical.push(' ');
        }
        canonical.push_str(&name);
        canonical.push('=');
        if !value.is_empty() && value.bytes().all(is_tchar) {
            canonical.push_str(&value);
        } else {
            canonical.push('"');
            for character in value.chars() {
                if matches!(character, '"' | '\\') {
                    canonical.push('\\');
                }
                canonical.push(character);
            }
            canonical.push('"');
        }
    }
    canonical
}

fn split_quoted(input: &str, separator: char) -> Result<Vec<&str>, ()> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == separator {
            parts.push(&input[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(());
    }
    parts.push(&input[start..]);
    Ok(parts)
}

fn parse_parameter_value(value: &str) -> Result<String, ()> {
    if !value.is_ascii() {
        return Err(());
    }
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut decoded = String::new();
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                if character.is_ascii_control() {
                    return Err(());
                }
                decoded.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_ascii_control() {
                return Err(());
            } else {
                decoded.push(character);
            }
        }
        if escaped {
            return Err(());
        }
        Ok(decoded)
    } else if !value.is_empty() && value.bytes().all(is_tchar) {
        Ok(value.to_owned())
    } else {
        Err(())
    }
}

pub(crate) fn is_tchar(byte: u8) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::{
        MediaRangeKind, canonical_content_key, canonical_encoding_content_type, is_json,
        parse_parameter_value, split_media_type_list, split_quoted,
    };

    #[test]
    fn recognizes_only_the_declared_json_families() {
        for media in [
            "application/json",
            "application/json; charset=utf-8",
            "application/problem+json",
        ] {
            assert!(is_json(media), "{media}");
        }
        // `text/json` sits with the rejections on purpose: unregistered, and recognizing it made
        // one media type mean JSON in a response and text in a request.
        for media in [
            "text/plain",
            "text/json",
            "text/json; charset=utf-8",
            "text/x-json",
            "application/json-seq",
        ] {
            assert!(!is_json(media), "{media}");
        }
    }

    #[test]
    fn splits_media_type_lists_outside_quoted_strings_in_source_order() {
        assert_eq!(
            split_media_type_list(r#"application/json; note="a,b", text/plain"#),
            Ok(vec![r#"application/json; note="a,b""#, " text/plain"])
        );
        assert_eq!(
            split_media_type_list("text/plain, application/json, application/xml"),
            Ok(vec!["text/plain", " application/json", " application/xml"])
        );
    }

    #[test]
    fn rejects_unterminated_quotes_in_media_type_lists() {
        assert!(split_media_type_list(r#"application/json; note="a,b"#).is_err());
    }

    #[test]
    fn canonicalizes_bare_and_uppercase_media_types() {
        let bare = canonical_content_key("application/json").expect("valid media type");
        assert_eq!(bare.full, "application/json");
        assert_eq!(bare.essence, "application/json");
        assert_eq!(bare.range_kind, MediaRangeKind::Concrete);

        let uppercase = canonical_content_key("Application/JSON").expect("valid media type");
        assert_eq!(uppercase.full, "application/json");
        assert_eq!(uppercase.essence, "application/json");
        assert_eq!(uppercase.range_kind, MediaRangeKind::Concrete);
    }

    #[test]
    fn lowercases_only_the_charset_value_leaving_other_values_byte_preserved() {
        let media = canonical_content_key("Text/Plain; Zeta=Last; CHARSET=UTF-8; note=MiXeD")
            .expect("valid media type");
        // charset value folds to lowercase (RFC 2046 case-insensitivity); note/zeta keep their case.
        assert_eq!(media.full, "text/plain;charset=utf-8;note=MiXeD;zeta=Last");
        assert_eq!(media.essence, "text/plain");
        assert_eq!(media.range_kind, MediaRangeKind::Concrete);
    }

    #[test]
    fn charset_value_case_variants_collide_on_one_content_key() {
        let upper = canonical_content_key("text/plain;charset=UTF-8").expect("valid media type");
        let lower = canonical_content_key("text/plain;charset=utf-8").expect("valid media type");
        assert_eq!(upper.full, lower.full);
        assert_eq!(upper.full, "text/plain;charset=utf-8");
    }

    #[test]
    fn canonicalizes_quoted_parameter_separators() {
        let media = canonical_content_key(r#"text/plain; note="a;b,c""#).expect("valid media type");
        assert_eq!(media.full, r#"text/plain;note="a;b,c""#);
    }

    #[test]
    fn classifies_range_kind_by_wildcards_not_raw_asterisks() {
        // A subtype wildcard is a type range; the full wildcard is Any; the grammar forbids
        // `*/subtype`, so those are the only two ranges.
        assert_eq!(
            canonical_content_key("text/*")
                .expect("valid range")
                .range_kind,
            MediaRangeKind::TypeRange
        );
        assert_eq!(
            canonical_content_key("*/*")
                .expect("valid range")
                .range_kind,
            MediaRangeKind::Any
        );
        // A parameter never masks the underlying range: `text/*; q=0.5` stays a TypeRange even
        // though its canonical full string carries the `*` mid-string.
        let ranged = canonical_content_key("text/*; q=0.5").expect("valid range");
        assert_eq!(ranged.full, "text/*;q=0.5");
        assert_eq!(ranged.range_kind, MediaRangeKind::TypeRange);
        // `*` is a tchar, so `*foo` is a legal concrete subtype — not the subtype wildcard.
        assert_eq!(
            canonical_content_key("text/*foo")
                .expect("valid media")
                .range_kind,
            MediaRangeKind::Concrete
        );

        assert!(canonical_content_key("text/plain; note=\"unterminated").is_err());
    }

    #[test]
    fn encoding_content_type_rejects_invalid_grammar() {
        for invalid in [
            "",
            "*/json",
            "text/plain;",
            "text/plain; =value",
            "text/plain; name",
            "text/plain; name=\"unterminated",
            "text/plain; name=\"trailing\\\"",
            "text/plain; name=\"bad\\\u{0001}\"",
            "text/plain; name=",
        ] {
            assert!(
                canonical_encoding_content_type(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(split_quoted("text/plain; note=\"unterminated", ';').is_err());
        assert!(parse_parameter_value(r#""trailing\""#).is_err());
    }

    #[test]
    fn encoding_content_type_matches_canonical_vectors() {
        for (input, expected) in [
            (
                "Application/XML; charset=UTF-8",
                "application/xml; charset=utf-8",
            ),
            (
                "application/vnd.custom; charset=UTF-8; boundary=AbC123",
                "application/vnd.custom; boundary=AbC123; charset=utf-8",
            ),
            (
                "application/vnd.custom2; note=\"a\\\"b\\\\c\"",
                "application/vnd.custom2; note=\"a\\\"b\\\\c\"",
            ),
        ] {
            assert_eq!(
                canonical_encoding_content_type(input)
                    .expect("valid media")
                    .full,
                expected
            );
        }
        for input in [
            "application/json; charset=utf-8; Charset=utf-16",
            "application/xml; charset = utf-8",
            "text/plain; name=\"bad\u{0001}value\"",
            "text/plain; name=\"café\"",
        ] {
            assert!(canonical_encoding_content_type(input).is_err(), "{input}");
        }
    }
}
