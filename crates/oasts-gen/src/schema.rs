use serde_json::{Map, Value};

pub fn config_schema() -> Value {
    let mut schema = oasts_core::config::config_json_schema();
    strip_null_variants(&mut schema);
    derive_shared_config(&mut schema);
    set_root_shapes(&mut schema);
    finalize_metadata(&mut schema);
    schema
}

fn strip_null_variants(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.get("default") == Some(&Value::Null) {
                map.remove("default");
            }
            strip_null_from_type_array(map);
            strip_null_from_any_of(map);
            for (_, v) in map.iter_mut() {
                strip_null_variants(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_null_variants(v);
            }
        }
        _ => {}
    }
}

fn is_null_schema(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|obj| obj.len() == 1 && obj.get("type") == Some(&Value::String("null".into())))
}

fn strip_null_from_any_of(map: &mut Map<String, Value>) {
    for key in ["anyOf", "oneOf"] {
        let Some(arr) = map.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        let before = arr.len();
        arr.retain(|v| !is_null_schema(v));
        if arr.len() == before {
            continue;
        }
        if arr.len() == 1 {
            let single = arr.remove(0);
            map.remove(key);
            if let Value::Object(inner) = single {
                for (k, v) in inner {
                    map.insert(k, v);
                }
            }
        }
    }
}

fn strip_null_from_type_array(map: &mut Map<String, Value>) {
    let Some(type_val) = map.get_mut("type") else {
        return;
    };
    let Some(arr) = type_val.as_array_mut() else {
        return;
    };
    arr.retain(|v| v.as_str() != Some("null"));
    if arr.len() == 1 {
        *type_val = arr.remove(0);
    }
}

/// Derives `shared` from `SpecConfig`, minus the two keys that name one spec.
///
/// The compiler refuses `input` and `output` under `shared` because they name one document and
/// one output root, so the published schema refuses them too rather than leaving an editor to
/// suggest a key the compiler will reject.
fn derive_shared_config(schema: &mut Value) {
    let mut shared = schema["$defs"]["SpecConfig"].clone();
    let properties = shared["properties"]
        .as_object_mut()
        .expect("SpecConfig is an object schema with properties");
    for key in spec_only_keys() {
        properties.remove(key);
    }
    shared["description"] = Value::String(
        "Settings every spec in the workspace inherits. A spec that declares the same block \
         overrides nothing: declaring a block in both places is an error."
            .into(),
    );
    schema["$defs"]["SharedConfig"] = shared;
    schema["properties"]["shared"] = Value::Object(Map::from_iter([(
        "$ref".into(),
        Value::String("#/$defs/SharedConfig".into()),
    )]));
}

/// The keys that configure one compile target, taken from the one place they are declared.
fn target_keys(schema: &Value) -> Vec<String> {
    schema["$defs"]["SpecConfig"]["properties"]
        .as_object()
        .expect("SpecConfig is an object schema with properties")
        .keys()
        .cloned()
        .collect()
}

fn spec_only_keys() -> [&'static str; 2] {
    ["input", "output"]
}

/// States the two shapes a configuration can take, and that it takes exactly one of them.
///
/// A single-spec config names one document and one output root at the root. A workspace names
/// several under `specs`, and then the root carries no target keys at all — `shared` is where the
/// settings they agree on go.
fn set_root_shapes(schema: &mut Value) {
    let target = target_keys(schema);
    let mut workspace_forbids = Map::new();
    for key in &target {
        workspace_forbids.insert(key.clone(), Value::Bool(false));
    }
    let mut single_forbids = Map::new();
    for key in ["specs", "shared"] {
        single_forbids.insert(key.into(), Value::Bool(false));
    }

    let obj = schema
        .as_object_mut()
        .expect("the generated config schema is an object");
    obj.insert(
        "required".into(),
        Value::Array(vec![Value::String("schemaVersion".into())]),
    );
    obj.insert(
        "oneOf".into(),
        Value::Array(vec![
            shape(
                "SingleSpecConfig",
                "One document compiled into one output root.",
                &["input", "output"],
                single_forbids,
            ),
            shape(
                "WorkspaceConfig",
                "Several named specs, each compiled into an output root of its own.",
                &["specs"],
                workspace_forbids,
            ),
        ]),
    );
}

fn shape(
    title: &str,
    description: &str,
    required: &[&str],
    forbidden: Map<String, Value>,
) -> Value {
    Value::Object(Map::from_iter([
        ("title".into(), Value::String(title.into())),
        ("description".into(), Value::String(description.into())),
        (
            "required".into(),
            Value::Array(
                required
                    .iter()
                    .map(|key| Value::String((*key).into()))
                    .collect(),
            ),
        ),
        ("properties".into(), Value::Object(forbidden)),
    ]))
}

fn finalize_metadata(schema: &mut Value) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    obj.insert(
        "$id".into(),
        Value::String("https://eve0415.github.io/oasts/schema/config-v1.json".into()),
    );
    assert_eq!(
        obj.get("title").and_then(Value::as_str),
        Some("UserConfig"),
        "root title must be UserConfig"
    );
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn null_is_stripped_from_all_properties() {
        let schema = config_schema();
        let json = serde_json::to_string(&schema).expect("schema serializes");
        assert!(
            !json.contains("\"null\""),
            "no null type should survive in the schema"
        );
    }

    #[test]
    fn no_default_null_survives() {
        let schema = config_schema();
        fn assert_no_default_null(value: &Value, path: &str) {
            if let Value::Object(map) = value {
                assert!(
                    map.get("default") != Some(&Value::Null),
                    "default: null at {path}"
                );
                for (k, v) in map {
                    assert_no_default_null(v, &format!("{path}/{k}"));
                }
            } else if let Value::Array(arr) = value {
                for (i, v) in arr.iter().enumerate() {
                    assert_no_default_null(v, &format!("{path}[{i}]"));
                }
            }
        }
        assert_no_default_null(&schema, "");
    }

    #[test]
    fn required_fields_are_present() {
        let schema = config_schema();
        let required = schema["required"].as_array().expect("required array");
        let values: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert_eq!(values, ["schemaVersion"]);
    }

    #[test]
    fn the_two_shapes_are_exclusive() {
        let schema = config_schema();
        let shapes = schema["oneOf"].as_array().expect("root shape branches");
        assert_eq!(shapes.len(), 2);
        assert_eq!(shapes[0]["title"], json!("SingleSpecConfig"));
        assert_eq!(shapes[0]["required"], json!(["input", "output"]));
        assert_eq!(shapes[0]["properties"]["specs"], json!(false));
        assert_eq!(shapes[0]["properties"]["shared"], json!(false));

        assert_eq!(shapes[1]["title"], json!("WorkspaceConfig"));
        assert_eq!(shapes[1]["required"], json!(["specs"]));
        let forbidden = shapes[1]["properties"]
            .as_object()
            .expect("the workspace shape forbids the target keys");
        let target = schema["$defs"]["SpecConfig"]["properties"]
            .as_object()
            .expect("SpecConfig properties");
        assert_eq!(
            forbidden.keys().collect::<Vec<_>>(),
            target.keys().collect::<Vec<_>>()
        );
        assert!(forbidden.values().all(|value| value == &json!(false)));
    }

    #[test]
    fn shared_drops_the_keys_that_name_one_spec() {
        let schema = config_schema();
        assert_eq!(
            schema["properties"]["shared"]["$ref"],
            json!("#/$defs/SharedConfig")
        );
        let shared = schema["$defs"]["SharedConfig"]["properties"]
            .as_object()
            .expect("SharedConfig properties");
        assert!(!shared.contains_key("input") && !shared.contains_key("output"));
        let spec = schema["$defs"]["SpecConfig"]["properties"]
            .as_object()
            .expect("SpecConfig properties");
        assert_eq!(shared.len() + 2, spec.len());
        assert_eq!(
            schema["properties"]["specs"]["additionalProperties"]["$ref"],
            json!("#/$defs/SpecConfig")
        );
    }

    #[test]
    fn metadata_is_correct() {
        let schema = config_schema();
        assert_eq!(schema["title"], json!("UserConfig"));
        assert_eq!(
            schema["$id"],
            json!("https://eve0415.github.io/oasts/schema/config-v1.json")
        );
        assert_eq!(
            schema["$schema"],
            json!("https://json-schema.org/draft/2020-12/schema")
        );
    }

    #[test]
    fn compiler_checked_string_literals_are_constrained() {
        let schema = config_schema();
        let naming = &schema["$defs"]["NamingConfig"]["properties"];
        assert_eq!(
            naming["typeCase"],
            json!({ "type": "string", "const": "pascal", "default": "pascal" })
        );
        assert_eq!(
            naming["propertyCase"],
            json!({ "type": "string", "const": "preserve", "default": "preserve" })
        );

        let emit = &schema["$defs"]["EmitConfig"]["properties"];
        assert_eq!(
            emit["importExtension"],
            json!({ "type": "string", "enum": [".js", "none"], "default": ".js" })
        );
        assert_eq!(
            emit["format"],
            json!({ "type": "string", "const": "deterministic", "default": "deterministic" })
        );
    }

    #[test]
    fn compiler_checked_limits_are_constrained_inclusively() {
        let schema = config_schema();
        let limits = &schema["$defs"]["LimitsConfig"]["properties"];
        for (name, minimum, maximum) in [
            ("maxDocumentBytes", 1_024_u64, 1_073_741_824_u64),
            ("maxTotalBytes", 1_024, 4_294_967_296),
            ("maxDocuments", 1, 4_096),
            ("maxRefDepth", 1, 1_024),
        ] {
            assert_eq!(limits[name]["minimum"], json!(minimum), "{name} minimum");
            assert_eq!(limits[name]["maximum"], json!(maximum), "{name} maximum");
        }
    }

    #[test]
    fn fetch_client_has_no_ignored_transport_selector() {
        let schema = config_schema();
        let client = &schema["$defs"]["RawClient"];
        assert_eq!(client["additionalProperties"], json!(false));
        assert!(client["properties"].get("transport").is_none());
        assert!(schema["$defs"].get("ClientTransport").is_none());
    }

    #[test]
    fn input_one_of_is_preserved() {
        let schema = config_schema();
        let input = &schema["$defs"]["Input"];
        let branches = input["oneOf"]
            .as_array()
            .expect("Input oneOf should survive null stripping");
        assert_eq!(branches.len(), 2);
    }

    #[test]
    fn schema_version_const_is_integer_not_string() {
        let schema = config_schema();
        let sv = &schema["properties"]["schemaVersion"]["const"];
        assert!(
            sv.is_number(),
            "schemaVersion const must be a number, got {sv}"
        );
        assert_eq!(sv.as_u64(), Some(1));
    }

    #[test]
    fn option_ref_fields_are_unwrapped_to_plain_ref() {
        let schema = config_schema();
        let input_prop = &schema["properties"]["input"];
        assert!(
            input_prop.get("$ref").is_some(),
            "input property should be a plain $ref after null stripping, got {input_prop}"
        );
    }

    #[test]
    fn artifact_setting_untagged_any_of_preserves_both_branches() {
        let schema = config_schema();
        let setting = &schema["$defs"]["ArtifactSetting"];
        let branches = setting["anyOf"].as_array().expect("ArtifactSetting anyOf");
        assert_eq!(branches.len(), 2);
    }

    #[test]
    fn strip_null_from_type_array_synthetic() {
        let mut map = serde_json::Map::new();
        map.insert("type".into(), json!(["string", "null"]));
        strip_null_from_type_array(&mut map);
        assert_eq!(map["type"], json!("string"));

        let mut map2 = serde_json::Map::new();
        map2.insert("type".into(), json!(["string", "integer", "null"]));
        strip_null_from_type_array(&mut map2);
        assert_eq!(map2["type"], json!(["string", "integer"]));

        let mut noop = serde_json::Map::new();
        noop.insert("type".into(), json!("string"));
        strip_null_from_type_array(&mut noop);
        assert_eq!(noop["type"], json!("string"));
    }

    #[test]
    fn strip_null_from_any_of_synthetic() {
        let mut map = serde_json::Map::new();
        map.insert(
            "anyOf".into(),
            json!([{"$ref": "#/$defs/Foo"}, {"type": "null"}]),
        );
        strip_null_from_any_of(&mut map);
        assert_eq!(map.get("$ref"), Some(&json!("#/$defs/Foo")));
        assert!(map.get("anyOf").is_none());
    }

    #[test]
    fn strip_null_from_any_of_non_object_singleton() {
        let mut map = serde_json::Map::new();
        map.insert("anyOf".into(), json!([true, {"type": "null"}]));
        strip_null_from_any_of(&mut map);
        assert!(map.get("anyOf").is_none());
        assert!(map.get("$ref").is_none());
    }

    #[test]
    fn strip_null_from_any_of_no_null_is_noop() {
        let mut map = serde_json::Map::new();
        map.insert(
            "anyOf".into(),
            json!([{"type": "string"}, {"type": "boolean"}]),
        );
        strip_null_from_any_of(&mut map);
        assert!(map.get("anyOf").is_some());
    }

    #[test]
    fn strip_null_from_any_of_multiple_remaining() {
        let mut map = serde_json::Map::new();
        map.insert(
            "anyOf".into(),
            json!([{"type": "string"}, {"type": "boolean"}, {"type": "null"}]),
        );
        strip_null_from_any_of(&mut map);
        let arr = map["anyOf"].as_array().expect("anyOf should remain");
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn strip_null_variants_removes_default_null() {
        let mut value = json!({"properties": {"x": {"type": ["string", "null"], "default": null}}});
        strip_null_variants(&mut value);
        assert_eq!(value["properties"]["x"]["type"], json!("string"));
        assert!(value["properties"]["x"].get("default").is_none());
    }

    #[test]
    fn finalize_metadata_sets_id() {
        let mut schema = json!({"title": "UserConfig"});
        finalize_metadata(&mut schema);
        assert_eq!(
            schema["$id"],
            json!("https://eve0415.github.io/oasts/schema/config-v1.json")
        );
    }

    #[test]
    fn strip_null_handles_non_object() {
        let mut value = json!("just a string");
        strip_null_variants(&mut value);
        assert_eq!(value, json!("just a string"));
    }

    #[test]
    fn finalize_metadata_noop_on_non_object() {
        let mut value = json!("not an object");
        finalize_metadata(&mut value);
        assert_eq!(value, json!("not an object"));
    }
}
