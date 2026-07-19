use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{Map, Number, Value};
use yaml_rust2::parser::{Event, Parser};
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
        has_tag: bool,
        marker: Marker,
    ) -> Result<(), YamlValueError> {
        if anchor != 0 && self.mode == YamlMode::Config {
            return Err(YamlValueError::at(
                marker,
                "YAML anchors are not supported in configurations",
            ));
        }
        if has_tag {
            return Err(YamlValueError::at(
                marker,
                "explicit YAML tags are not supported in documents",
            ));
        }
        Ok(())
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
            context.check_metadata(anchor, tag.is_some(), marker)?;
            let value = resolve_yaml_scalar(value, style, marker)?;
            context.store_anchor(anchor, &value);
            Ok(value)
        }
        Event::SequenceStart(anchor, tag) => {
            context.check_metadata(anchor, tag.is_some(), marker)?;
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
            context.check_metadata(anchor, tag.is_some(), marker)?;
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
    loop {
        let Some((event, marker)) = events.pop_front() else {
            return Err(YamlValueError::at(start, "unterminated YAML mapping"));
        };
        match event {
            Event::MappingEnd => break,
            Event::Scalar(key, _, anchor, tag) => {
                context.check_metadata(anchor, tag.is_some(), marker)?;
                context.store_anchor(anchor, &Value::String(key.clone()));
                insert_yaml_mapping_key(&mut keys, &key, marker)?;
                object.insert(key, parse_yaml_node_in(events, depth + 1, context)?);
            }
            Event::Alias(anchor) => {
                let value = context.resolve_alias(anchor, marker, depth + 1)?;
                let Value::String(key) = value else {
                    return Err(YamlValueError::at(
                        marker,
                        "YAML mapping keys must resolve to scalars",
                    ));
                };
                insert_yaml_mapping_key(&mut keys, &key, marker)?;
                object.insert(key, parse_yaml_node_in(events, depth + 1, context)?);
            }
            _ => {
                return Err(YamlValueError::at(
                    marker,
                    "YAML mapping keys must be scalars",
                ));
            }
        }
    }
    Ok(Value::Object(object))
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
    if is_yaml_non_finite(&value) {
        return Err(YamlValueError::at(
            marker,
            "non-finite YAML numbers cannot be represented in JSON data",
        ));
    }
    if is_yaml_float(&value) {
        let normalized = value.replace('_', "");
        let parsed = normalized
            .parse::<f64>()
            .expect("validated YAML float must parse as f64");
        let number = Number::from_f64(parsed).ok_or_else(|| {
            YamlValueError::at(
                marker,
                format!("YAML float '{value}' is outside the JSON number domain"),
            )
        })?;
        return Ok(Value::Number(number));
    }
    Ok(Value::String(value))
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

    Some(
        u64::from_str_radix(digits, radix)
            .map_err(|_| format!("YAML integer '{value}' is outside the JSON number domain"))
            .and_then(|magnitude| {
                if negative {
                    if magnitude == 0 {
                        return Ok(Number::from_f64(-0.0)
                            .expect("JSON numbers support every finite f64 value"));
                    }
                    let signed = if magnitude == (i64::MAX as u64) + 1 {
                        i64::MIN
                    } else {
                        let magnitude = i64::try_from(magnitude).map_err(|_| {
                            format!("YAML integer '{value}' is outside the JSON number domain")
                        })?;
                        -magnitude
                    };
                    Ok(Number::from(signed))
                } else {
                    Ok(Number::from(magnitude))
                }
            }),
    )
}

fn is_yaml_non_finite(value: &str) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    matches!(unsigned, ".inf" | ".Inf" | ".INF") || matches!(value, ".nan" | ".NaN" | ".NAN")
}

fn is_yaml_float(value: &str) -> bool {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let mut exponent_parts = unsigned.split(['e', 'E']);
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
    use yaml_rust2::parser::Tag;

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
            parse_yaml_value("value: !!str true")
                .expect_err("tag")
                .message,
            "explicit YAML tags are not supported in documents"
        );
        for spelling in [".inf", "-.Inf", ".NAN"] {
            assert!(
                parse_yaml_value(&format!("value: {spelling}"))
                    .expect_err("non-finite value should fail")
                    .message
                    .contains("non-finite")
            );
        }
        assert!(
            parse_yaml_value("value: 1e9999")
                .expect_err("infinite float should fail")
                .message
                .contains("outside the JSON number domain")
        );
        assert_eq!(
            parse_yaml_value("values: [-9223372036854775808, -7, +7, .5, 2., 2E-2]")
                .expect("numeric forms"),
            json!({ "values": [i64::MIN, -7, 7, 0.5, 2.0, 0.02] })
        );
        for spelling in ["18446744073709551616", "-9223372036854775809"] {
            assert!(
                parse_yaml_value(&format!("value: {spelling}"))
                    .expect_err("out-of-domain integer should fail")
                    .message
                    .contains("outside the JSON number domain")
            );
        }

        for invalid in ["1e", "1e2e3", ".", "1__2", "1._2"] {
            assert!(!is_yaml_float(invalid));
        }
        assert!(parse_yaml_integer("0o8").is_none());
        assert!(parse_yaml_integer("0xG").is_none());
        assert!(!is_yaml_non_finite("+.nan"));
    }
}
