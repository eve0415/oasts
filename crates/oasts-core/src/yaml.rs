//! YAML 1.2 documents to `serde_json::Value`.
//!
//! Every item here is about reading YAML: the compiler's config and input
//! documents become the same `Value` shape a JSON document does, so nothing
//! downstream has to know which syntax a document was written in.

use std::collections::VecDeque;
use std::str::FromStr;

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use serde_json::{Map, Number, Value};
use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct YamlValueError {
    pub(crate) message: String,
    pub(crate) line: u32,
    pub(crate) col: u32,
}

impl YamlValueError {
    fn at(marker: Marker, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            line: u32::try_from(marker.line()).unwrap_or(u32::MAX),
            col: u32::try_from(marker.col()).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YamlMode {
    Config,
    Document,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum YamlTag {
    Str,
    Int,
    Bool,
    Float,
    Null,
    Seq,
    Map,
}

const MAX_YAML_ALIAS_EXPANSION_NODES: usize = 1_000_000;

struct YamlContext {
    mode: YamlMode,
    anchors: HashMap<usize, Value>,
    expanded_nodes: usize,
}

impl YamlContext {
    fn new(mode: YamlMode) -> Self {
        Self {
            mode,
            anchors: HashMap::new(),
            expanded_nodes: 0,
        }
    }

    fn check_metadata(
        &self,
        anchor: usize,
        tag: Option<&Tag>,
        marker: Marker,
    ) -> Result<Option<YamlTag>, YamlValueError> {
        if anchor != 0 && self.mode == YamlMode::Config {
            return Err(YamlValueError::at(
                marker,
                "YAML anchors are not supported in configurations",
            ));
        }
        tag.map(parse_yaml_tag).transpose().map_err(|()| {
            YamlValueError::at(
                marker,
                "unsupported explicit YAML tag; only the tag:yaml.org,2002 core schema tags (str, int, float, bool, null, seq, map) are supported",
            )
        })
    }

    fn store_anchor(&mut self, anchor: usize, value: &Value) {
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
    }

    fn resolve_alias(
        &mut self,
        anchor: usize,
        marker: Marker,
        depth: usize,
    ) -> Result<Value, YamlValueError> {
        if self.mode == YamlMode::Config {
            return Err(YamlValueError::at(
                marker,
                "YAML aliases are not supported in configurations",
            ));
        }
        let value = self.anchors.get(&anchor).ok_or_else(|| {
            YamlValueError::at(
                marker,
                format!("YAML alias refers to unknown anchor {anchor}"),
            )
        })?;
        let remaining = MAX_YAML_ALIAS_EXPANSION_NODES.saturating_sub(self.expanded_nodes);
        let Some((nodes, nested_depth)) = alias_shape_within(value, remaining) else {
            return Err(YamlValueError::at(
                marker,
                format!(
                    "YAML alias expansion exceeds the supported budget of {MAX_YAML_ALIAS_EXPANSION_NODES} nodes"
                ),
            ));
        };
        if depth.saturating_add(nested_depth) > MAX_YAML_NESTING_DEPTH {
            return Err(YamlValueError::at(
                marker,
                format!("YAML nesting exceeds the supported depth of {MAX_YAML_NESTING_DEPTH}"),
            ));
        }
        self.expanded_nodes += nodes;
        Ok(value.clone())
    }
}

fn parse_yaml_tag(tag: &Tag) -> Result<YamlTag, ()> {
    if tag.handle != "tag:yaml.org,2002:" {
        return Err(());
    }
    match tag.suffix.as_str() {
        "str" => Ok(YamlTag::Str),
        "int" => Ok(YamlTag::Int),
        "bool" => Ok(YamlTag::Bool),
        "float" => Ok(YamlTag::Float),
        "null" => Ok(YamlTag::Null),
        "seq" => Ok(YamlTag::Seq),
        "map" => Ok(YamlTag::Map),
        _ => Err(()),
    }
}

pub(crate) fn parse_yaml_value(source: &str) -> Result<Value, YamlValueError> {
    parse_yaml_value_in_mode(source, YamlMode::Config)
}

pub(crate) fn parse_yaml_document_value(source: &str) -> Result<Value, YamlValueError> {
    parse_yaml_value_in_mode(source, YamlMode::Document)
}

fn parse_yaml_value_in_mode(source: &str, mode: YamlMode) -> Result<Value, YamlValueError> {
    // Events are pulled through the iterative `next_token` state machine, never
    // the recursive `Parser::load` driver, so hostile nesting cannot overflow
    // the native stack before the depth guard in `parse_yaml_node` runs.
    let mut parser = Parser::new_from_str(source);
    let mut collected = VecDeque::new();
    loop {
        let (event, marker) = parser
            .next_token()
            .map_err(|error| YamlValueError::at(*error.marker(), error.info()))?;
        let done = event == Event::StreamEnd;
        collected.push_back((event, marker));
        if done {
            break;
        }
    }

    expect_yaml_wrapper(&mut collected, Event::StreamStart, "stream start")?;
    let events = &mut collected;
    expect_yaml_wrapper(events, Event::DocumentStart, "document start")?;
    let value = parse_yaml_node_in(events, 0, &mut YamlContext::new(mode))?;
    expect_yaml_wrapper(events, Event::DocumentEnd, "document end")?;

    finish_yaml_document(events, value)
}

fn finish_yaml_document(
    events: &mut VecDeque<(Event, Marker)>,
    value: Value,
) -> Result<Value, YamlValueError> {
    let Some((next, marker)) = events.pop_front() else {
        return Err(YamlValueError {
            message: "missing YAML stream end".to_owned(),
            line: 1,
            col: 1,
        });
    };
    match next {
        Event::StreamEnd if events.is_empty() => Ok(value),
        Event::StreamEnd => Err(YamlValueError::at(
            marker,
            "unexpected YAML events after stream end",
        )),
        Event::DocumentStart => Err(YamlValueError::at(
            marker,
            "multiple YAML documents are not supported",
        )),
        _ => Err(YamlValueError::at(
            marker,
            "unexpected YAML event after document end",
        )),
    }
}

fn expect_yaml_wrapper(
    events: &mut VecDeque<(Event, Marker)>,
    expected: Event,
    name: &str,
) -> Result<(), YamlValueError> {
    let Some((event, marker)) = events.pop_front() else {
        return Err(YamlValueError {
            message: format!("missing YAML {name}"),
            line: 1,
            col: 1,
        });
    };
    if event == expected {
        Ok(())
    } else {
        Err(YamlValueError::at(marker, format!("expected YAML {name}")))
    }
}

// Block-style nesting recurses once per container event; without a bound a
// sub-megabyte document can overflow the native stack. 128 mirrors serde_json.
const MAX_YAML_NESTING_DEPTH: usize = 128;

#[cfg(test)]
fn parse_yaml_node(
    events: &mut VecDeque<(Event, Marker)>,
    depth: usize,
) -> Result<Value, YamlValueError> {
    parse_yaml_node_in(events, depth, &mut YamlContext::new(YamlMode::Config))
}

fn parse_yaml_node_in(
    events: &mut VecDeque<(Event, Marker)>,
    depth: usize,
    context: &mut YamlContext,
) -> Result<Value, YamlValueError> {
    let Some((event, marker)) = events.pop_front() else {
        return Err(YamlValueError {
            message: "unexpected end of YAML event stream".to_owned(),
            line: 1,
            col: 1,
        });
    };
    match event {
        Event::Scalar(value, style, anchor, tag) => {
            let tag = context.check_metadata(anchor, tag.as_ref(), marker)?;
            let value = resolve_yaml_scalar_with_tag(value, style, tag, marker)?;
            context.store_anchor(anchor, &value);
            Ok(value)
        }
        Event::SequenceStart(anchor, tag) => {
            let tag = context.check_metadata(anchor, tag.as_ref(), marker)?;
            if !matches!(tag, None | Some(YamlTag::Seq)) {
                return Err(yaml_tag_kind_error(marker, "a sequence"));
            }
            check_yaml_depth(depth, marker)?;
            let mut values = Vec::new();
            loop {
                match events.front() {
                    Some((Event::SequenceEnd, _)) => {
                        events.pop_front();
                        break;
                    }
                    Some(_) => values.push(parse_yaml_node_in(events, depth + 1, context)?),
                    None => {
                        return Err(YamlValueError::at(marker, "unterminated YAML sequence"));
                    }
                }
            }
            let value = Value::Array(values);
            context.store_anchor(anchor, &value);
            Ok(value)
        }
        Event::MappingStart(anchor, tag) => {
            let tag = context.check_metadata(anchor, tag.as_ref(), marker)?;
            if !matches!(tag, None | Some(YamlTag::Map)) {
                return Err(yaml_tag_kind_error(marker, "a mapping"));
            }
            check_yaml_depth(depth, marker)?;
            let value = parse_yaml_mapping(events, marker, depth, context)?;
            context.store_anchor(anchor, &value);
            Ok(value)
        }
        Event::Alias(anchor) => context.resolve_alias(anchor, marker, depth),
        _ => Err(YamlValueError::at(
            marker,
            "unexpected YAML event while reading a value",
        )),
    }
}

fn check_yaml_depth(depth: usize, marker: Marker) -> Result<(), YamlValueError> {
    if depth >= MAX_YAML_NESTING_DEPTH {
        return Err(YamlValueError::at(
            marker,
            format!("YAML nesting exceeds the supported depth of {MAX_YAML_NESTING_DEPTH}"),
        ));
    }
    Ok(())
}

fn parse_yaml_mapping(
    events: &mut VecDeque<(Event, Marker)>,
    start: Marker,
    depth: usize,
    context: &mut YamlContext,
) -> Result<Value, YamlValueError> {
    let mut object = Map::new();
    let mut keys = HashSet::new();
    let mut merge_sources = Vec::new();
    loop {
        let Some((event, marker)) = events.pop_front() else {
            return Err(YamlValueError::at(start, "unterminated YAML mapping"));
        };
        let (key, is_merge_key) = match event {
            Event::MappingEnd => break,
            Event::Scalar(key, style, anchor, tag) => {
                // Only a plain, untagged `<<` is the YAML merge key; a quoted (`'<<'`) or tagged
                // (`!!str <<`) scalar is a literal property named `<<`. Decide from the source spelling
                // before tag resolution rewrites it, matching reference loaders.
                let is_merge_key = style == TScalarStyle::Plain && tag.is_none() && key == "<<";
                let tag = context.check_metadata(anchor, tag.as_ref(), marker)?;
                let key = if tag.is_some() {
                    let value = resolve_yaml_scalar_with_tag(key, style, tag, marker)?;
                    let Value::String(key) = value else {
                        return Err(YamlValueError::at(
                            marker,
                            "YAML mapping keys must resolve to scalars",
                        ));
                    };
                    key
                } else {
                    key
                };
                context.store_anchor(anchor, &Value::String(key.clone()));
                (key, is_merge_key)
            }
            Event::Alias(anchor) => {
                // The merge trigger is a syntactic property of the key node, so an alias resolving to
                // `<<` is a literal key, never a merge.
                let value = context.resolve_alias(anchor, marker, depth + 1)?;
                let Value::String(key) = value else {
                    return Err(YamlValueError::at(
                        marker,
                        "YAML mapping keys must resolve to scalars",
                    ));
                };
                (key, false)
            }
            _ => {
                return Err(YamlValueError::at(
                    marker,
                    "YAML mapping keys must be scalars",
                ));
            }
        };
        if is_merge_key {
            let value = parse_yaml_node_in(events, depth + 1, context)?;
            collect_yaml_merge_sources(value, marker, &mut merge_sources)?;
        } else {
            insert_yaml_mapping_key(&mut keys, &key, marker)?;
            object.insert(key, parse_yaml_node_in(events, depth + 1, context)?);
        }
    }
    for source in merge_sources {
        for (key, value) in source {
            object.entry(key).or_insert(value);
        }
    }
    Ok(Value::Object(object))
}

fn collect_yaml_merge_sources(
    value: Value,
    marker: Marker,
    sources: &mut Vec<Map<String, Value>>,
) -> Result<(), YamlValueError> {
    match value {
        Value::Object(source) => sources.push(source),
        Value::Array(values) => {
            for value in values {
                let Value::Object(source) = value else {
                    return Err(YamlValueError::at(
                        marker,
                        "merge key value must be a mapping or a sequence of mappings",
                    ));
                };
                sources.push(source);
            }
        }
        _ => {
            return Err(YamlValueError::at(
                marker,
                "merge key value must be a mapping or a sequence of mappings",
            ));
        }
    }
    Ok(())
}

fn insert_yaml_mapping_key(
    keys: &mut HashSet<String>,
    key: &str,
    marker: Marker,
) -> Result<(), YamlValueError> {
    if !keys.insert(key.to_owned()) {
        return Err(YamlValueError::at(
            marker,
            format!("duplicate YAML mapping key '{key}'"),
        ));
    }
    Ok(())
}

fn alias_shape_within(value: &Value, limit: usize) -> Option<(usize, usize)> {
    let mut nodes = 0_usize;
    let mut nested_depth = 0_usize;
    let mut pending = vec![(value, 0_usize)];
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.checked_add(1)?;
        if nodes > limit {
            return None;
        }
        nested_depth = nested_depth.max(depth);
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                nodes = nodes.checked_add(values.len())?;
                if nodes > limit {
                    return None;
                }
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Some((nodes, nested_depth))
}

fn resolve_yaml_scalar(
    value: String,
    style: TScalarStyle,
    marker: Marker,
) -> Result<Value, YamlValueError> {
    if style != TScalarStyle::Plain {
        return Ok(Value::String(value));
    }
    match value.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if let Some(number) = parse_yaml_integer(&value) {
        return number
            .map(Value::Number)
            .map_err(|message| YamlValueError::at(marker, message));
    }
    if let Some(number) = parse_yaml_float(&value, marker)? {
        return Ok(Value::Number(number));
    }
    Ok(Value::String(value))
}

fn resolve_yaml_scalar_with_tag(
    value: String,
    style: TScalarStyle,
    tag: Option<YamlTag>,
    marker: Marker,
) -> Result<Value, YamlValueError> {
    match tag {
        None => resolve_yaml_scalar(value, style, marker),
        Some(YamlTag::Str) => Ok(Value::String(value)),
        Some(YamlTag::Int) => match parse_yaml_integer(&value) {
            Some(Ok(number)) => Ok(Value::Number(number)),
            Some(Err(message)) => Err(YamlValueError::at(marker, message)),
            None => Err(yaml_tag_kind_error(marker, "an integer")),
        },
        Some(YamlTag::Float) => match parse_yaml_float(&value, marker)? {
            Some(number) => Ok(Value::Number(number)),
            // YAML 1.2.2 core schema puts the integer lexical forms inside the float tag's space,
            // so an integer-form scalar under !!float is that integer widened to a float
            // (`!!float 5` is 5.0). Fall back to the integer parser and reproject through f64 so the
            // result matches `!!float 5.0`.
            None => match parse_yaml_integer(&value) {
                Some(Ok(integer)) => integer
                    .as_f64()
                    .and_then(Number::from_f64)
                    .map(Value::Number)
                    .ok_or_else(|| yaml_tag_kind_error(marker, "a float")),
                _ => Err(yaml_tag_kind_error(marker, "a float")),
            },
        },
        Some(YamlTag::Bool) => match value.as_str() {
            "true" | "True" | "TRUE" => Ok(Value::Bool(true)),
            "false" | "False" | "FALSE" => Ok(Value::Bool(false)),
            _ => Err(yaml_tag_kind_error(marker, "a boolean")),
        },
        Some(YamlTag::Null) => match value.as_str() {
            "" | "~" | "null" | "Null" | "NULL" => Ok(Value::Null),
            _ => Err(yaml_tag_kind_error(marker, "null")),
        },
        Some(YamlTag::Seq | YamlTag::Map) => Err(yaml_tag_kind_error(marker, "a scalar")),
    }
}

fn parse_yaml_float(value: &str, marker: Marker) -> Result<Option<Number>, YamlValueError> {
    if is_yaml_non_finite(value) {
        return Err(YamlValueError::at(
            marker,
            "non-finite YAML numbers cannot be represented in JSON data",
        ));
    }
    if !is_yaml_float(value) {
        return Ok(None);
    }
    let normalized = value.replace('_', "");
    // `is_yaml_float` accepted only the decimal grammar implemented by `f64::from_str`.
    let parsed = normalized
        .parse::<f64>()
        .expect("validated YAML float must parse as f64");
    let number = if let Some(number) = Number::from_f64(parsed) {
        number
    } else {
        let normalized = normalize_yaml_float_for_json(&normalized);
        Number::from_str(&normalized).map_err(|_| {
            YamlValueError::at(
                marker,
                format!("YAML float '{value}' is outside the JSON number domain"),
            )
        })?
    };
    Ok(Some(number))
}

fn yaml_tag_kind_error(marker: Marker, expected: &str) -> YamlValueError {
    YamlValueError::at(
        marker,
        format!("explicit YAML tag does not identify {expected}"),
    )
}

fn parse_yaml_integer(value: &str) -> Option<Result<Number, String>> {
    let (negative, radix, digits) = if let Some(rest) = value.strip_prefix("0o") {
        if rest.is_empty() || !rest.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
            return None;
        }
        (false, 8, rest)
    } else if let Some(rest) = value.strip_prefix("0x") {
        if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        (false, 16, rest)
    } else {
        let (negative, unsigned) = match value.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, value.strip_prefix('+').unwrap_or(value)),
        };
        if unsigned.is_empty() || !unsigned.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        (negative, 10, unsigned)
    };

    Some(match u64::from_str_radix(digits, radix) {
        Ok(magnitude) => (|| {
            if negative {
                if magnitude == 0 {
                    // Negative zero is finite, and `Number::from_f64` accepts every finite value.
                    return Ok(Number::from_f64(-0.0)
                        .expect("JSON numbers support every finite f64 value"));
                }
                if magnitude == (i64::MAX as u64) + 1 {
                    return Ok(Number::from(i64::MIN));
                }
                if let Ok(magnitude) = i64::try_from(magnitude) {
                    return Ok(Number::from(-magnitude));
                }
                // The normalizer receives a validated decimal integer and emits JSON number syntax.
                Ok(Number::from_str(&normalize_yaml_integer_for_json(value))
                    .expect("a normalized decimal integer is valid JSON number syntax"))
            } else {
                Ok(Number::from(magnitude))
            }
        })(),
        Err(_) if radix == 10 => {
            // The normalizer receives a validated decimal integer and emits JSON number syntax.
            Ok(Number::from_str(&normalize_yaml_integer_for_json(value))
                .expect("a normalized decimal integer is valid JSON number syntax"))
        }
        Err(_) => Err(format!(
            "YAML integer '{value}' is outside the JSON number domain"
        )),
    })
}

/// Normalize a validated decimal integer spelling into JSON number syntax.
/// YAML accepts a leading `+` and leading zeros that JSON forbids; strip the
/// `+` and collapse leading zeros to a single digit (preserving the sign). The
/// caller has already validated the input as `[-+]?[0-9]+`, so the result is
/// always a syntactically valid JSON number (`-?(0|[1-9][0-9]*)`) that
/// `Number::from_str` parses at arbitrary precision — feeding the raw spelling
/// straight to `from_str` instead panicked on legal YAML like `-09223372036854775809`.
fn normalize_yaml_integer_for_json(value: &str) -> String {
    let (sign, digits) = match value.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", value.strip_prefix('+').unwrap_or(value)),
    };
    let trimmed = digits.trim_start_matches('0');
    let digits = if trimmed.is_empty() { "0" } else { trimmed };
    let mut normalized = String::with_capacity(sign.len() + digits.len());
    normalized.push_str(sign);
    normalized.push_str(digits);
    normalized
}

fn normalize_yaml_float_for_json(value: &str) -> String {
    let mut normalized = value.strip_prefix('+').unwrap_or(value).to_owned();
    let mantissa_start = usize::from(normalized.starts_with('-'));
    if normalized[mantissa_start..].starts_with('.') {
        normalized.insert(mantissa_start, '0');
    }
    let mantissa_end = normalized.find(['e', 'E']).unwrap_or(normalized.len());
    if normalized[..mantissa_end].ends_with('.') {
        normalized.insert(mantissa_end, '0');
    }
    normalized
}

fn is_yaml_non_finite(value: &str) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    matches!(unsigned, ".inf" | ".Inf" | ".INF") || matches!(value, ".nan" | ".NaN" | ".NAN")
}

fn is_yaml_float(value: &str) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut exponent_parts = unsigned.split(['e', 'E']);
    // `split` always yields at least the original string, including for an empty input.
    let mantissa = exponent_parts.next().expect("split always yields one part");
    let exponent = exponent_parts.next();
    if exponent_parts.next().is_some() {
        return false;
    }
    if let Some(exponent) = exponent {
        let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if !is_digit_group(digits) {
            return false;
        }
    }

    if let Some(fraction) = mantissa.strip_prefix('.') {
        return is_digit_group(fraction);
    }
    if let Some((integer, fraction)) = mantissa.split_once('.') {
        return is_digit_group(integer) && (fraction.is_empty() || is_digit_group(fraction));
    }
    exponent.is_some() && is_digit_group(mantissa)
}

fn is_digit_group(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn marker() -> Marker {
        Parser::new_from_str("value")
            .next_token()
            .expect("parser should emit stream start")
            .1
    }

    fn scalar(value: &str) -> Event {
        Event::Scalar(value.to_owned(), TScalarStyle::Plain, 0, None)
    }

    #[test]
    fn preserves_negative_zero_for_semantic_validation() {
        let value = parse_yaml_value("value: -0").expect("YAML value");
        let number = value["value"].as_number().expect("number");
        assert!(number.as_f64().is_some_and(f64::is_sign_negative));
    }

    #[test]
    fn document_tail_validation_rejects_invalid_event_sequences() {
        let marker = marker();
        let value = Value::Null;

        assert_eq!(
            finish_yaml_document(&mut VecDeque::new(), value.clone())
                .expect_err("missing tail should fail")
                .message,
            "missing YAML stream end"
        );
        for (events, message) in [
            (
                vec![(Event::StreamEnd, marker), (Event::Nothing, marker)],
                "unexpected YAML events after stream end",
            ),
            (
                vec![(Event::DocumentStart, marker)],
                "multiple YAML documents are not supported",
            ),
            (
                vec![(Event::Nothing, marker)],
                "unexpected YAML event after document end",
            ),
        ] {
            assert_eq!(
                finish_yaml_document(&mut events.into(), value.clone())
                    .expect_err("invalid tail should fail")
                    .message,
                message
            );
        }
        assert_eq!(
            finish_yaml_document(&mut vec![(Event::StreamEnd, marker)].into(), value.clone())
                .expect("stream end should finish"),
            value
        );
    }

    #[test]
    fn wrapper_and_node_errors_report_structural_failures() {
        let marker = marker();
        assert_eq!(
            expect_yaml_wrapper(&mut VecDeque::new(), Event::StreamStart, "stream start")
                .expect_err("missing wrapper should fail")
                .message,
            "missing YAML stream start"
        );
        assert_eq!(
            expect_yaml_wrapper(
                &mut vec![(Event::Nothing, marker)].into(),
                Event::StreamStart,
                "stream start",
            )
            .expect_err("wrong wrapper should fail")
            .message,
            "expected YAML stream start"
        );
        assert_eq!(
            parse_yaml_node(&mut VecDeque::new(), 0)
                .expect_err("missing node should fail")
                .message,
            "unexpected end of YAML event stream"
        );
        assert!(
            parse_yaml_node(&mut vec![(Event::Alias(1), marker)].into(), 0)
                .expect_err("alias should fail")
                .message
                .contains("aliases")
        );
        assert!(
            parse_yaml_node(&mut vec![(Event::Nothing, marker)].into(), 0)
                .expect_err("non-node should fail")
                .message
                .contains("unexpected YAML event")
        );
    }

    #[test]
    fn deep_block_nesting_is_rejected_instead_of_overflowing_the_stack() {
        let deep_sequence = "- ".repeat(200_000) + "1";
        let error = parse_yaml_value(&deep_sequence).expect_err("deep sequence should fail");
        assert!(error.message.contains("nesting exceeds"));

        let mut deep_mapping = String::new();
        for level in 0..2_000 {
            deep_mapping.push_str(&" ".repeat(level));
            deep_mapping.push_str("k:\n");
        }
        let error = parse_yaml_value(&deep_mapping).expect_err("deep mapping should fail");
        assert!(error.message.contains("nesting exceeds"));

        let shallow = "- ".repeat(MAX_YAML_NESTING_DEPTH - 1) + "1";
        parse_yaml_value(&shallow).expect("nesting below the bound parses");
    }

    #[test]
    fn sequences_mappings_anchors_and_tags_cover_event_errors() {
        let marker = marker();
        let sequence = vec![
            (Event::SequenceStart(0, None), marker),
            (scalar("1"), marker),
            (Event::SequenceEnd, marker),
        ];
        assert_eq!(
            parse_yaml_node(&mut sequence.into(), 0).expect("sequence"),
            json!([1])
        );
        assert!(
            parse_yaml_node(&mut vec![(Event::SequenceStart(0, None), marker)].into(), 0)
                .expect_err("unterminated sequence should fail")
                .message
                .contains("unterminated YAML sequence")
        );

        assert!(
            parse_yaml_node(&mut vec![(Event::MappingStart(0, None), marker)].into(), 0)
                .expect_err("unterminated mapping should fail")
                .message
                .contains("unterminated YAML mapping")
        );
        for key in [Event::Alias(1), Event::SequenceEnd] {
            let error = parse_yaml_node(
                &mut vec![
                    (Event::MappingStart(0, None), marker),
                    (key, marker),
                    (Event::MappingEnd, marker),
                ]
                .into(),
                0,
            )
            .expect_err("invalid key should fail");
            assert!(error.message.contains("aliases") || error.message.contains("keys"));
        }

        let tag = Tag {
            handle: "!!".to_owned(),
            suffix: "str".to_owned(),
        };
        for event in [
            Event::Scalar("x".to_owned(), TScalarStyle::Plain, 1, None),
            Event::Scalar("x".to_owned(), TScalarStyle::Plain, 0, Some(tag.clone())),
        ] {
            assert!(
                parse_yaml_node(&mut vec![(event, marker)].into(), 0)
                    .expect_err("metadata should fail")
                    .message
                    .contains("supported")
            );
        }
    }

    #[test]
    fn document_alias_errors_keys_and_expanded_depth_are_bounded() {
        let marker = marker();
        let mut context = YamlContext::new(YamlMode::Document);
        let unknown = context
            .resolve_alias(99, marker, 0)
            .expect_err("unknown alias should fail");
        assert!(unknown.message.contains("unknown anchor 99"));

        context
            .anchors
            .insert(1, Value::String("alias-key".to_owned()));
        let mapping = vec![
            (Event::MappingStart(0, None), marker),
            (Event::Alias(1), marker),
            (scalar("value"), marker),
            (Event::MappingEnd, marker),
        ];
        assert_eq!(
            parse_yaml_node_in(&mut mapping.into(), 0, &mut context).expect("alias key"),
            json!({ "alias-key": "value" })
        );

        let duplicate = vec![
            (Event::MappingStart(0, None), marker),
            (scalar("alias-key"), marker),
            (scalar("first"), marker),
            (Event::Alias(1), marker),
            (scalar("second"), marker),
            (Event::MappingEnd, marker),
        ];
        assert!(
            parse_yaml_node_in(&mut duplicate.into(), 0, &mut context)
                .expect_err("duplicate alias key")
                .message
                .contains("duplicate")
        );

        context.anchors.insert(2, json!(["not", "a", "key"]));
        let nonscalar = vec![
            (Event::MappingStart(0, None), marker),
            (Event::Alias(2), marker),
            (scalar("value"), marker),
            (Event::MappingEnd, marker),
        ];
        assert!(
            parse_yaml_node_in(&mut nonscalar.into(), 0, &mut context)
                .expect_err("non-scalar alias key")
                .message
                .contains("resolve to scalars")
        );

        let mut nested = Value::Null;
        for _ in 0..MAX_YAML_NESTING_DEPTH {
            nested = Value::Array(vec![nested]);
        }
        context.anchors.insert(3, nested);
        assert!(
            context
                .resolve_alias(3, marker, 1)
                .expect_err("expanded alias depth")
                .message
                .contains("nesting exceeds")
        );

        assert!(alias_shape_within(&json!({ "entry": 1 }), 1).is_none());
    }

    #[test]
    fn scalar_resolution_covers_json_number_boundaries() {
        assert_eq!(
            parse_yaml_value("value: !!str true").expect("string tag"),
            json!({ "value": "true" })
        );
        for spelling in [".inf", "-.Inf", ".NAN"] {
            assert!(
                parse_yaml_value(&format!("value: {spelling}"))
                    .expect_err("non-finite value should fail")
                    .message
                    .contains("non-finite")
            );
        }
        for spelling in ["18446744073709551616", "-9223372036854775809"] {
            let value = parse_yaml_value(&format!("value: {spelling}"))
                .expect("arbitrary-precision number should parse");
            assert_eq!(value["value"].to_string(), spelling);
        }
        let value =
            parse_yaml_value("value: 1e9999").expect("arbitrary-precision float should parse");
        let serialized = serde_json::to_string(&value).expect("JSON serialization");
        assert_eq!(
            serde_json::from_str::<Value>(&serialized).expect("JSON reparsing"),
            value
        );
        assert_eq!(
            parse_yaml_value("values: [-9223372036854775808, -7, +7, .5, 2., 2E-2]")
                .expect("numeric forms"),
            json!({ "values": [i64::MIN, -7, 7, 0.5, 2.0, 0.02] })
        );
        assert!(
            parse_yaml_value("value: 0x10000000000000000")
                .expect_err("out-of-domain hexadecimal integer should fail")
                .message
                .contains("outside the JSON number domain")
        );
        // A leading '+' is a legal YAML integer spelling that JSON rejects;
        // it normalizes and parses at arbitrary precision rather than failing.
        let value = parse_yaml_value("value: +18446744073709551616")
            .expect("leading-plus integer normalizes and parses");
        assert_eq!(value["value"].to_string(), "18446744073709551616");

        for invalid in ["1e", "1e2e3", ".", "1__2", "1._2"] {
            assert!(!is_yaml_float(invalid));
        }
        assert!(parse_yaml_integer("0o8").is_none());
        assert!(parse_yaml_integer("0xG").is_none());
        assert!(!is_yaml_non_finite("+.nan"));
        assert_eq!(normalize_yaml_float_for_json(".5e9999"), "0.5e9999");
        assert_eq!(normalize_yaml_float_for_json("-5.e9999"), "-5.0e9999");
        assert_eq!(normalize_yaml_float_for_json("+1e9999"), "1e9999");
        assert_eq!(normalize_yaml_integer_for_json("+007"), "7");
        assert_eq!(normalize_yaml_integer_for_json("-0000"), "-0");
        assert_eq!(
            normalize_yaml_integer_for_json("-09223372036854775809"),
            "-9223372036854775809"
        );
    }

    #[test]
    fn oversized_integer_spellings_normalize_before_json_parsing() {
        // Leading zeros previously panicked serde_json's from_str in the
        // negative out-of-i64 branch; both leading zeros and a leading '+'
        // are legal YAML integer spellings that JSON rejects, so normalize
        // and parse at arbitrary precision instead of panicking or failing.
        let value = parse_yaml_value("value: -09223372036854775809")
            .expect("leading-zero negative overflow normalizes and parses");
        assert_eq!(value["value"].to_string(), "-9223372036854775809");

        let value = parse_yaml_value("value: +18446744073709551616")
            .expect("leading-plus positive overflow normalizes and parses");
        assert_eq!(value["value"].to_string(), "18446744073709551616");

        // A normalized negative overflow round-trips through JSON unchanged.
        let value = parse_yaml_value("value: -9223372036854775809")
            .expect("normalized negative overflow parses");
        let serialized = serde_json::to_string(&value).expect("JSON serialization");
        assert_eq!(
            serde_json::from_str::<Value>(&serialized).expect("JSON reparsing"),
            value
        );
        assert_eq!(value["value"].to_string(), "-9223372036854775809");
    }

    #[test]
    fn json_schema_ruleset_tags_force_scalar_and_container_kinds() {
        assert_eq!(
            parse_yaml_document_value(
                "plain: !!str 5\nquoted: !!str \"true\"\nblock: !!str |\n  false\ninteger: !!int \"5\"\nfloat: !!float 5.0\nbool: !!bool true\nfalse_bool: !!bool FALSE\nnull: !!null null\nsequence: !!seq [1]\nmapping: !!map {a: 1}\n!!str true: key\n",
            )
            .expect("JSON schema tags"),
            json!({
                "plain": "5",
                "quoted": "true",
                "block": "false\n",
                "integer": 5,
                "float": 5.0,
                "bool": true,
                "false_bool": false,
                "null": null,
                "sequence": [1],
                "mapping": { "a": 1 },
                "true": "key",
            })
        );

        for source in [
            "value: !!int true",
            "value: !!int 0x10000000000000000",
            "value: !!float x",
            "value: !!float 01.2e9999",
            "value: !!bool falsehood",
            "value: !!null nil",
            "value: !!seq {a: 1}",
            "value: !!seq scalar",
            "value: !!map [1]",
            "!!int 5: value",
        ] {
            parse_yaml_document_value(source).expect_err("tag kind mismatch should fail");
        }
        assert_eq!(
            parse_yaml_document_value("value: !!custom x")
                .expect_err("unsupported tag should fail")
                .message,
            "unsupported explicit YAML tag; only the tag:yaml.org,2002 core schema tags (str, int, float, bool, null, seq, map) are supported"
        );
    }

    #[test]
    fn float_tag_widens_integer_forms_to_floats_per_core_schema() {
        // YAML 1.2.2 core schema: an integer-form scalar under !!float is that integer widened to
        // a float, so `!!float 5` is 5.0 and byte-identical to the explicitly-fractional spelling.
        let widened = parse_yaml_document_value("value: !!float 5").expect("integer-form float");
        assert_eq!(widened["value"], json!(5.0));
        let explicit = parse_yaml_document_value("value: !!float 5.0").expect("fractional float");
        assert_eq!(widened, explicit);
        // A non-numeric scalar under !!float stays fatal.
        parse_yaml_document_value("value: !!float x").expect_err("non-numeric float tag is fatal");
        // An integer-form value beyond the f64 range widens to a non-finite float, which JSON cannot
        // represent, so it is fatal like any other non-finite float.
        let overflow = format!("value: !!float {}", "9".repeat(400));
        parse_yaml_document_value(&overflow).expect_err("f64-overflowing integer float is fatal");
    }

    #[test]
    fn merge_keys_apply_sources_after_locals_in_precedence_order() {
        let value = parse_yaml_document_value(
            "base: &base {merged: first, override: base}\ntarget:\n  override: local\n  local: value\n  <<: *base\n",
        )
        .expect("single merge");
        assert_eq!(
            value["target"],
            json!({ "override": "local", "local": "value", "merged": "first" })
        );
        assert_eq!(
            value["target"]
                .as_object()
                .expect("target mapping")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["override", "local", "merged"]
        );

        let value = parse_yaml_document_value(
            "a: &a {shared: a, first: 1}\nb: &b {shared: b, second: 2}\ntarget:\n  <<: [*a, *b]\n",
        )
        .expect("merge sequence");
        assert_eq!(
            value["target"],
            json!({ "shared": "a", "first": 1, "second": 2 })
        );

        let value = parse_yaml_document_value(
            "a: &a {first: 1}\nb: &b {second: 2}\ntarget:\n  <<: *a\n  <<: *b\n",
        )
        .expect("multiple merge keys");
        assert_eq!(value["target"], json!({ "first": 1, "second": 2 }));
    }

    #[test]
    fn only_plain_untagged_double_angle_triggers_a_merge() {
        // A plain, untagged `<<` merges its mapping source.
        let value = parse_yaml_document_value("<<: {a: 1}\nb: 2\n").expect("plain merge");
        assert_eq!(value, json!({ "b": 2, "a": 1 }));

        // A quoted `'<<'` is a literal property, not a merge trigger, so its scalar value survives.
        let value = parse_yaml_document_value("'<<': x\nb: 2\n").expect("quoted literal key");
        assert_eq!(value, json!({ "<<": "x", "b": 2 }));

        // A tagged `!!str <<` is likewise a literal key.
        let value = parse_yaml_document_value("!!str <<: x\nb: 2\n").expect("tagged literal key");
        assert_eq!(value, json!({ "<<": "x", "b": 2 }));

        // An alias resolving to `<<` is a literal key: the trigger is the key node's syntax.
        let marker = marker();
        let mut context = YamlContext::new(YamlMode::Document);
        context.anchors.insert(1, json!("<<"));
        let mapping = vec![
            (Event::MappingStart(0, None), marker),
            (Event::Alias(1), marker),
            (scalar("value"), marker),
            (Event::MappingEnd, marker),
        ];
        let value = parse_yaml_node_in(&mut mapping.into(), 0, &mut context)
            .expect("alias key is literal, not a merge");
        assert_eq!(value, json!({ "<<": "value" }));
    }

    #[test]
    fn merge_keys_reject_invalid_sources_and_charge_alias_budget() {
        for source in [
            "scalar: &scalar 5\ntarget:\n  <<: *scalar\n",
            "base: &base {a: 1}\ntarget:\n  <<: [*base, 5]\n",
        ] {
            assert_eq!(
                parse_yaml_document_value(source)
                    .expect_err("invalid merge source should fail")
                    .message,
                "merge key value must be a mapping or a sequence of mappings"
            );
        }

        let marker = marker();
        let mut context = YamlContext::new(YamlMode::Document);
        context.anchors.insert(1, json!({ "merged": true }));
        context.expanded_nodes = MAX_YAML_ALIAS_EXPANSION_NODES;
        let mapping = vec![
            (Event::MappingStart(0, None), marker),
            (scalar("<<"), marker),
            (Event::Alias(1), marker),
            (Event::MappingEnd, marker),
        ];
        assert!(
            parse_yaml_node_in(&mut mapping.into(), 0, &mut context)
                .expect_err("merge alias over budget should fail")
                .message
                .contains("alias expansion exceeds")
        );
    }
}
