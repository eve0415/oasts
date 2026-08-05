use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::config::ResolvedBaseUrl;
use crate::ir::{ServerVariable, SourceRef};
use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};

use super::model::EmissionModel;
use super::{GeneratedFile, render_property_key, render_ts_string};

const RESULT_TS: &str = include_str!("../../runtime/result.ts");
const SERIALIZE_TS: &str = include_str!("../../runtime/serialize.ts");
const STANDARD_SCHEMA_TS: &str = include_str!("../../runtime/standard-schema.ts");
const TRANSPORT_TS: &str = include_str!("../../runtime/transport.ts");

const FROZEN_TRANSPORT_BASE_URL_OPTIONAL: &str = "  baseUrl?: string;                                   // generated as REQUIRED when runtime URL resolution needs it";
const FROZEN_TRANSPORT_BASE_URL_REQUIRED: &str = "  baseUrl: string;                                   // generated as REQUIRED when runtime URL resolution needs it";
const FROZEN_TRANSPORT_SERVER_VARIABLES: &str =
    "  serverVariables?: Readonly<Record<string, string>>;";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RegionId {
    Core,
    Helper(String),
    Auth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AssetPart<'asset> {
    Plain(&'asset str),
    Region { id: RegionId, content: &'asset str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedAsset<'asset> {
    parts: Vec<AssetPart<'asset>>,
}

struct RuntimeAssets {
    result: ParsedAsset<'static>,
    serialize: ParsedAsset<'static>,
    standard_schema: ParsedAsset<'static>,
    transport: ParsedAsset<'static>,
}

static RUNTIME_ASSETS: OnceLock<RuntimeAssets> = OnceLock::new();

/// Inputs that determine the shared runtime modules emitted for one client.
pub(crate) struct RuntimeSelection<'selection, 'input, 'sink> {
    pub(crate) model: &'selection mut EmissionModel<'input, 'sink>,
    pub(crate) helper_ids: &'selection BTreeSet<String>,
    pub(crate) base_url: &'selection ResolvedBaseUrl,
    /// Whether any server the client exposes is a relative URL, which needs the runtime transport
    /// URL as its base. This is a client-model fact, distinct from the transport-level requiredness
    /// `emit_runtime_files` derives from it, which additionally forces the base when `base_url` is
    /// `ResolvedBaseUrl::Runtime`.
    pub(crate) relative_server_url: bool,
    pub(crate) source: &'selection SourceRef,
    /// Every `(name, ServerVariable)` declared by any server the client model exposes, across all
    /// operations, in source order. Determines whether `TransportConfig.serverVariables` narrows
    /// from `Readonly<Record<string, string>>` to a per-variable literal-union object type.
    pub(crate) server_variables: &'selection [(String, ServerVariable)],
}

/// Emits selected runtime modules and registers their paths with all other artifacts.
pub(crate) fn emit_runtime_files(selection: RuntimeSelection<'_, '_, '_>) -> Vec<GeneratedFile> {
    let assets = runtime_assets();
    let runtime_directory = selection.model.config.emit.runtime_directory.clone();
    let import_extension = selection.model.config.emit.import_extension.clone();
    let transport_base_url_required =
        matches!(selection.base_url, ResolvedBaseUrl::Runtime) || selection.relative_server_url;
    let mut files = Vec::with_capacity(4);

    push_runtime_file(
        &mut files,
        selection.model,
        selection.source,
        &runtime_directory,
        "result.ts",
        rewrite_relative_ts_imports(
            &render_regions(&assets.result, &|_| true),
            &import_extension,
        ),
    );

    push_runtime_file(
        &mut files,
        selection.model,
        selection.source,
        &runtime_directory,
        "standard-schema.ts",
        rewrite_relative_ts_imports(
            &render_regions(&assets.standard_schema, &|_| true),
            &import_extension,
        ),
    );

    // transport.ts value-imports ./serialize.ts unconditionally, so serialize.ts is always emitted
    // alongside it — never gated — or the emitted transport would import a missing module. Its
    // transport dependencies are therefore always force-included.
    let serialize = render_serialize(&assets.serialize, selection.helper_ids, true);
    push_runtime_file(
        &mut files,
        selection.model,
        selection.source,
        &runtime_directory,
        "serialize.ts",
        rewrite_relative_ts_imports(&serialize, &import_extension),
    );

    let transport = specialize_transport(
        &assets.transport,
        transport_base_url_required,
        selection.server_variables,
    );
    push_runtime_file(
        &mut files,
        selection.model,
        selection.source,
        &runtime_directory,
        "transport.ts",
        rewrite_relative_ts_imports(&transport, &import_extension),
    );
    files
}

fn runtime_assets() -> &'static RuntimeAssets {
    RUNTIME_ASSETS.get_or_init(|| {
        let result = parse_asset("result.ts", RESULT_TS);
        let serialize = parse_asset("serialize.ts", SERIALIZE_TS);
        validate_serialize(&serialize);
        let standard_schema = parse_asset("standard-schema.ts", STANDARD_SCHEMA_TS);
        let transport = parse_asset("transport.ts", TRANSPORT_TS);
        validate_transport(&transport);
        RuntimeAssets {
            result,
            serialize,
            standard_schema,
            transport,
        }
    })
}

fn parse_asset<'asset>(file_name: &str, source: &'asset str) -> ParsedAsset<'asset> {
    assert!(
        !source.contains('\r'),
        "embedded runtime asset {file_name} must use LF line endings"
    );
    let mut parts = Vec::new();
    let mut plain_start = 0;
    let mut open: Option<(RegionId, usize)> = None;
    let mut seen = HashSet::new();
    let mut offset = 0;

    for line in source.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let text = line.strip_suffix('\n').unwrap_or(line);
        if text.starts_with("//#region") {
            let id = parse_region_id(file_name, text);
            assert!(
                open.is_none(),
                "embedded runtime asset {file_name} has nested regions"
            );
            assert!(
                seen.insert(id.clone()),
                "embedded runtime asset {file_name} repeats region {text}"
            );
            if plain_start < line_start {
                parts.push(AssetPart::Plain(&source[plain_start..line_start]));
            }
            open = Some((id, offset));
        } else if text.starts_with("//#endregion") {
            assert_eq!(
                text, "//#endregion",
                "embedded runtime asset {file_name} has invalid end marker {text}"
            );
            let (id, content_start) = open.take().unwrap_or_else(|| {
                panic!("embedded runtime asset {file_name} closes a region that is not open")
            });
            parts.push(AssetPart::Region {
                id,
                content: &source[content_start..line_start],
            });
            plain_start = offset;
        }
    }

    assert!(
        open.is_none(),
        "embedded runtime asset {file_name} has an unclosed region"
    );
    if plain_start < source.len() {
        parts.push(AssetPart::Plain(&source[plain_start..]));
    }
    ParsedAsset { parts }
}

fn parse_region_id(file_name: &str, line: &str) -> RegionId {
    let id = line.strip_prefix("//#region ").unwrap_or_else(|| {
        panic!("embedded runtime asset {file_name} has invalid region marker {line}")
    });
    match id {
        "oxs:core" => RegionId::Core,
        "oxs:auth" => RegionId::Auth,
        _ => {
            let helper = id.strip_prefix("oxs:helper:").unwrap_or_else(|| {
                panic!("embedded runtime asset {file_name} has unknown region {id}")
            });
            assert!(
                !helper.is_empty()
                    && helper.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'),
                "embedded runtime asset {file_name} has invalid helper id {helper}"
            );
            RegionId::Helper(helper.to_owned())
        }
    }
}

fn validate_serialize(asset: &ParsedAsset<'_>) {
    let regions = asset
        .parts
        .iter()
        .filter_map(|part| match part {
            AssetPart::Plain(_) => None,
            AssetPart::Region { id, .. } => Some(id),
        })
        .collect::<Vec<_>>();
    assert!(
        matches!(regions.first(), Some(RegionId::Core)),
        "embedded runtime asset serialize.ts must begin with oxs:core"
    );
    let mut helpers = Vec::new();
    for (index, id) in regions.into_iter().enumerate() {
        match id {
            RegionId::Core => assert_eq!(
                index, 0,
                "embedded runtime asset serialize.ts must begin with oxs:core"
            ),
            RegionId::Helper(helper) => helpers.push(helper.as_str()),
            RegionId::Auth => panic!("embedded runtime asset serialize.ts contains oxs:auth"),
        }
    }
    assert!(
        helpers
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes()),
        "embedded runtime asset serialize.ts helper regions are not byte-lexicographically sorted"
    );
}

fn validate_transport(asset: &ParsedAsset<'_>) {
    let auth_count = asset
        .parts
        .iter()
        .filter(|part| {
            matches!(
                part,
                AssetPart::Region {
                    id: RegionId::Auth,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        auth_count, 1,
        "embedded runtime asset transport.ts must contain exactly one oxs:auth region"
    );
}

fn render_serialize(
    asset: &ParsedAsset<'_>,
    helper_ids: &BTreeSet<String>,
    transport_dependencies: bool,
) -> String {
    let mut selected = helper_ids.clone();
    if transport_dependencies {
        // transport.ts is always emitted and imports these serialize helpers unconditionally, so
        // they always survive helper subsetting — including query-form-explode, which auth
        // serialization uses to place an apiKey query credential.
        selected.extend(
            [
                "form-urlencoded-body",
                "media-canonical",
                "multipart",
                "query-form-explode",
            ]
            .map(str::to_owned),
        );
    }
    let available = asset
        .parts
        .iter()
        .filter_map(|part| match part {
            AssetPart::Region {
                id: RegionId::Helper(helper),
                ..
            } => Some(helper.as_str()),
            AssetPart::Plain(_)
            | AssetPart::Region {
                id: RegionId::Core | RegionId::Auth,
                ..
            } => None,
        })
        .collect::<BTreeSet<_>>();
    for helper in &selected {
        assert!(
            available.contains(helper.as_str()),
            "runtime helper selection references unknown helper id {helper}"
        );
    }

    let rendered = render_regions(asset, &|id| match id {
        RegionId::Core => true,
        RegionId::Helper(helper) => selected.contains(helper),
        RegionId::Auth => false,
    });
    // Every dropped region leaves the blank line that separated it from its neighbour, so the file
    // ends with a run of them whose length is a function of which helpers this client happened to
    // select. That is deterministic but meaningless — and it makes an unrelated document's output
    // move whenever a new region is added to the end of the asset. One trailing newline, always.
    // Truncated in place rather than copied: this runs once per emitted client, and the allocation
    // counters gate that path.
    let mut rendered = rendered;
    rendered.truncate(rendered.trim_end().len());
    rendered.push('\n');
    rendered
}

fn specialize_transport(
    asset: &ParsedAsset<'_>,
    runtime_base_url: bool,
    server_variables: &[(String, ServerVariable)],
) -> String {
    let transport = render_regions(asset, &|_| true);
    let transport = substitute_frozen_once(
        transport,
        FROZEN_TRANSPORT_BASE_URL_OPTIONAL,
        "embedded runtime asset transport.ts must contain the frozen optional baseUrl line exactly once",
        runtime_base_url.then_some(FROZEN_TRANSPORT_BASE_URL_REQUIRED),
    );
    substitute_frozen_once(
        transport,
        FROZEN_TRANSPORT_SERVER_VARIABLES,
        "embedded runtime asset transport.ts must contain the frozen serverVariables line exactly once",
        server_variable_union(server_variables).as_deref(),
    )
}

/// Asserts the frozen `line` appears exactly once in `text` — the embedded runtime asset is the
/// source of truth, so a missing or duplicated anchor is a build-time invariant break — then
/// replaces that single occurrence with `replacement` when one is supplied, leaving `text` as-is
/// otherwise.
fn substitute_frozen_once(
    text: String,
    line: &str,
    message: &str,
    replacement: Option<&str>,
) -> String {
    assert_eq!(text.match_indices(line).count(), 1, "{message}");
    match replacement {
        Some(replacement) => text.replacen(line, replacement, 1),
        None => text,
    }
}

/// Builds the `serverVariables` type from every server the client model exposes, e.g.
/// `Record<string, never> | { version: "v1" | "v2" } | { region: string }`. One single-property
/// branch per variable name, first-seen order across servers, plus a leading empty branch so
/// `{}` (override nothing) stays valid. A name's property type is a literal union only when every
/// server declaring it gives it a non-empty `enum` (unioning first-seen literals across servers);
/// it stays `string` when any declaring server omits the enum, since a runtime substitution from
/// that server could then be any string. Returns `None` when no variable anywhere declares a
/// non-empty enum — the frozen `Readonly<Record<string, string>>` line then applies verbatim, so
/// every existing enum-free fixture's transport.ts stays byte-identical (the determinism guard).
///
/// A single object type with each property individually optional (`{ version?: "v1" | "v2";
/// region?: string }`) reads as the obvious shape but does not survive `freezeRecord`'s generic
/// `Record<Key, Value>` inference: TypeScript infers `Value` from every property's *apparent*
/// type, and an optional property's apparent type always includes `undefined`, which then fails
/// to assign back to `Transport.serverVariables: Readonly<Record<string, string>>` (verified
/// against the pinned `tsc`; every property mandatory-but-optional-object-wide avoids this,
/// because none of the union's branches contain an optional property for inference to poison).
/// The branch count is linear in the declared variable count (n + 1), not its powerset: a
/// caller's object literal is checked for excess properties against the union of every branch's
/// keys, not one branch in isolation, so combining several names in one call (`{ version: "v2",
/// region: "us" }`) still typechecks against these single-property branches.
fn server_variable_union(variables: &[(String, ServerVariable)]) -> Option<String> {
    if variables
        .iter()
        .all(|(_, variable)| variable.enum_values.is_empty())
    {
        return None;
    }

    let mut order: Vec<&str> = Vec::new();
    let mut lacks_enum: HashSet<&str> = HashSet::new();
    let mut literals: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, variable) in variables {
        let name = name.as_str();
        if !order.contains(&name) {
            order.push(name);
        }
        if variable.enum_values.is_empty() {
            lacks_enum.insert(name);
            continue;
        }
        let bucket = literals.entry(name).or_default();
        for value in &variable.enum_values {
            let value = value.as_str();
            if !bucket.contains(&value) {
                bucket.push(value);
            }
        }
    }

    let mut branches = vec!["Record<string, never>".to_owned()];
    branches.extend(order.into_iter().map(|name| {
        let key = render_property_key(name);
        if lacks_enum.contains(name) {
            format!("{{ {key}: string }}")
        } else {
            let union = literals
                .remove(name)
                .expect("a name absent from lacks_enum declared an enum at least once")
                .into_iter()
                .map(render_ts_string)
                .collect::<Vec<_>>()
                .join(" | ");
            format!("{{ {key}: {union} }}")
        }
    }));
    Some(format!("  serverVariables?: {};", branches.join(" | ")))
}

fn render_regions(asset: &ParsedAsset<'_>, include: &dyn Fn(&RegionId) -> bool) -> String {
    let mut output = String::new();
    for part in &asset.parts {
        match part {
            AssetPart::Plain(plain) => output.push_str(plain),
            AssetPart::Region { id, content } if include(id) => output.push_str(content),
            AssetPart::Region { .. } => {}
        }
    }
    output
}

pub(super) fn rewrite_relative_ts_imports(source: &str, extension: &str) -> String {
    let extension = if extension == "none" { "" } else { extension };
    let mut output = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let static_from = trimmed.starts_with("import ")
            || trimmed.starts_with("export ")
            || trimmed.starts_with("} from ");
        let from_single = static_from
            .then(|| line.find("from './"))
            .flatten()
            .map(|index| (index + 6, '\''));
        let from_double = static_from
            .then(|| line.find("from \"./"))
            .flatten()
            .map(|index| (index + 6, '"'));
        let side_effect_single = trimmed
            .starts_with("import './")
            .then(|| (line.len() - trimmed.len() + 8, '\''));
        let side_effect_double = trimmed
            .starts_with("import \"./")
            .then(|| (line.len() - trimmed.len() + 8, '"'));
        let candidate = from_single
            .or(from_double)
            .or(side_effect_single)
            .or(side_effect_double);
        let Some((specifier_start, quote)) = candidate else {
            output.push_str(line);
            continue;
        };
        let remainder = &line[specifier_start..];
        let Some(specifier_end) = remainder.find(quote) else {
            output.push_str(line);
            continue;
        };
        let specifier = &remainder[..specifier_end];
        let Some(stem) = specifier.strip_suffix(".ts") else {
            output.push_str(line);
            continue;
        };
        output.push_str(&line[..specifier_start]);
        output.push_str(stem);
        output.push_str(extension);
        output.push_str(&line[specifier_start + specifier_end..]);
    }
    output
}

fn push_runtime_file(
    files: &mut Vec<GeneratedFile>,
    model: &mut EmissionModel<'_, '_>,
    source: &SourceRef,
    runtime_directory: &str,
    file_name: &str,
    content: String,
) {
    let relative_path = format!("{runtime_directory}/{file_name}");
    model.register_path(&relative_path, source);
    files.push(GeneratedFile {
        relative_path,
        content,
    });
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedConfig, load_config_from_json};
    use crate::diag::DiagnosticSink;
    use crate::semantic::Analyzed;

    fn resolved_config(patch: Value) -> (TempDir, ResolvedConfig) {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("openapi.json"), "{}").expect("input");
        let mut raw = json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.json" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": { "authEnforcement": "types" },
            "validation": { "engine": "off", "unchecked": "allow" }
        });
        raw.as_object_mut()
            .expect("object")
            .extend(patch.as_object().expect("patch object").clone());
        let encoded = serde_json::to_vec(&raw).expect("config JSON");
        let config = load_config_from_json(&temp.path().join("oasts.json"), &encoded)
            .expect("resolved config");
        (temp, config)
    }

    fn source() -> SourceRef {
        SourceRef {
            source_id: "workspace/openapi.json".to_owned(),
            json_pointer: String::new(),
            line: Some(1),
            col: Some(1),
        }
    }

    fn emit_with(
        config: &ResolvedConfig,
        helpers: impl IntoIterator<Item = &'static str>,
        base_url: &ResolvedBaseUrl,
    ) -> (Vec<GeneratedFile>, Vec<crate::diag::Diagnostic>) {
        emit_with_server_variables(config, helpers, base_url, &[])
    }

    fn emit_with_server_variables(
        config: &ResolvedConfig,
        helpers: impl IntoIterator<Item = &'static str>,
        base_url: &ResolvedBaseUrl,
        server_variables: &[(String, ServerVariable)],
    ) -> (Vec<GeneratedFile>, Vec<crate::diag::Diagnostic>) {
        let analyzed = Analyzed {
            ir: crate::ir::Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let helpers = helpers.into_iter().map(str::to_owned).collect();
        let source = source();
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, config, "digest".to_owned(), &mut sink);
        let files = emit_runtime_files(RuntimeSelection {
            model: &mut model,
            helper_ids: &helpers,
            base_url,
            relative_server_url: false,
            source: &source,
            server_variables,
        });
        drop(model);
        (files, sink.into_sorted_vec())
    }

    fn content<'files>(files: &'files [GeneratedFile], suffix: &str) -> &'files str {
        &files
            .iter()
            .find(|file| file.relative_path.ends_with(suffix))
            .expect("runtime file")
            .content
    }

    fn without_markers(source: &str) -> String {
        source
            .split_inclusive('\n')
            .filter(|line| {
                let line = line.strip_suffix('\n').unwrap_or(line);
                !line.starts_with("//#region") && line != "//#endregion"
            })
            .collect()
    }

    #[test]
    fn embedded_assets_parse_once_and_match_the_contract() {
        let first = runtime_assets();
        let second = runtime_assets();
        assert!(std::ptr::eq(first, second));
        assert_eq!(first.result.parts, vec![AssetPart::Plain(RESULT_TS)]);
        assert_eq!(
            first.standard_schema.parts,
            vec![AssetPart::Plain(STANDARD_SCHEMA_TS)]
        );
        assert!(first.serialize.parts.iter().any(|part| matches!(
            part,
            AssetPart::Region {
                id: RegionId::Core,
                ..
            }
        )));
    }

    #[test]
    fn emission_is_deterministic_across_helper_discovery_orders() {
        let (_temp, config) = resolved_config(json!({}));
        let base_url = ResolvedBaseUrl::Server { index: 0 };
        let (first, first_diagnostics) = emit_with(
            &config,
            ["query-form", "path-simple", "media-canonical"],
            &base_url,
        );
        let (second, second_diagnostics) = emit_with(
            &config,
            ["media-canonical", "query-form", "path-simple"],
            &base_url,
        );
        let (third, third_diagnostics) = emit_with(
            &config,
            ["query-form", "path-simple", "media-canonical"],
            &base_url,
        );
        assert_eq!(first, second);
        assert_eq!(first, third);
        assert!(first_diagnostics.is_empty());
        assert!(second_diagnostics.is_empty());
        assert!(third_diagnostics.is_empty());
    }

    #[test]
    fn full_serialize_selection_matches_the_checked_in_asset_without_markers() {
        let (_temp, config) = resolved_config(json!({}));
        let helpers = runtime_assets()
            .serialize
            .parts
            .iter()
            .filter_map(|part| match part {
                AssetPart::Region {
                    id: RegionId::Helper(helper),
                    ..
                } => Some(helper.as_str()),
                AssetPart::Plain(_)
                | AssetPart::Region {
                    id: RegionId::Core | RegionId::Auth,
                    ..
                } => None,
            })
            .collect::<Vec<_>>();
        let (files, diagnostics) =
            emit_with(&config, helpers, &ResolvedBaseUrl::Server { index: 0 });
        assert_eq!(
            content(&files, "serialize.ts"),
            rewrite_relative_ts_imports(&without_markers(SERIALIZE_TS), ".js")
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn runtime_base_url_requiredness_is_specialized_both_ways() {
        let (_temp, config) = resolved_config(json!({}));
        let (runtime, _) = emit_with(&config, [], &ResolvedBaseUrl::Runtime);
        let (configured, _) = emit_with(
            &config,
            [],
            &ResolvedBaseUrl::Literal {
                value: "https://example.test".to_owned(),
            },
        );
        assert!(content(&runtime, "transport.ts").contains(FROZEN_TRANSPORT_BASE_URL_REQUIRED));
        assert!(!content(&runtime, "transport.ts").contains(FROZEN_TRANSPORT_BASE_URL_OPTIONAL));
        assert!(content(&configured, "transport.ts").contains(FROZEN_TRANSPORT_BASE_URL_OPTIONAL));
        assert!(content(&configured, "result.ts").contains("from './standard-schema.js';"));
        assert!(content(&configured, "transport.ts").contains("from './result.js';"));
        assert!(content(&configured, "transport.ts").contains("from './serialize.js';"));

        let analyzed = Analyzed {
            ir: crate::ir::Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let source = source();
        let helpers = BTreeSet::new();
        let base_url = ResolvedBaseUrl::Server { index: 0 };
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        let relative = emit_runtime_files(RuntimeSelection {
            model: &mut model,
            helper_ids: &helpers,
            base_url: &base_url,
            relative_server_url: true,
            source: &source,
            server_variables: &[],
        });
        assert!(content(&relative, "transport.ts").contains(FROZEN_TRANSPORT_BASE_URL_REQUIRED));
        assert!(!content(&relative, "transport.ts").contains(FROZEN_TRANSPORT_BASE_URL_OPTIONAL));
    }

    #[test]
    fn serialize_subset_keeps_core_transport_dependencies_and_only_selected_helpers() {
        let (_temp, config) = resolved_config(json!({}));
        let (files, _) = emit_with(
            &config,
            ["path-simple", "query-form"],
            &ResolvedBaseUrl::Server { index: 0 },
        );
        let serialize = content(&files, "serialize.ts");
        assert!(serialize.contains("export type ParamPrimitive"));
        assert!(serialize.contains("export function serializePathSimple"));
        assert!(serialize.contains("export function serializeQueryForm"));
        // The transport dependencies survive subsetting unconditionally.
        assert!(serialize.contains("export function serializeQueryFormExplode"));
        assert!(serialize.contains("export async function encodeMultipart"));
        // A descriptor-unselected, non-transport-dependency helper is dropped.
        assert!(!serialize.contains("export function serializePathLabel"));
        assert!(!serialize.contains("//#region"));
        assert!(!serialize.contains("//#endregion"));
    }

    #[test]
    fn zero_helper_selection_still_emits_serialize_with_transport_dependencies() {
        let (_temp, config) = resolved_config(json!({}));
        // Even with no descriptor-selected helper, serialize.ts is emitted (transport imports it)
        // alongside result, standard-schema, and transport — four files.
        let (core, _) = emit_with(&config, [], &ResolvedBaseUrl::Server { index: 0 });
        assert_eq!(core.len(), 4);
        assert!(content(&core, "serialize.ts").contains("export type ParamPrimitive"));
        assert!(content(&core, "serialize.ts").contains("encodeFormUrlencodedBody"));
        assert!(content(&core, "serialize.ts").contains("parseMediaType"));
        assert!(content(&core, "serialize.ts").contains("encodeMultipart"));
        // transport.ts's auth serialization imports serializeQueryFormExplode unconditionally,
        // so query-form-explode must survive even when no descriptor references it.
        assert!(
            content(&core, "serialize.ts").contains("export function serializeQueryFormExplode")
        );
        assert!(!content(&core, "serialize.ts").contains("export function serializePathSimple"));
    }

    #[test]
    fn import_extension_none_and_static_import_grammar_are_rewritten() {
        let (_temp, config) = resolved_config(json!({
            "emit": { "importExtension": "none", "runtimeDirectory": "support/runtime" }
        }));
        let (files, _) = emit_with(&config, [], &ResolvedBaseUrl::Server { index: 0 });
        assert_eq!(files[0].relative_path, "support/runtime/result.ts");
        assert_eq!(files[1].relative_path, "support/runtime/standard-schema.ts");
        assert!(content(&files, "result.ts").contains("from './standard-schema';"));
        assert!(content(&files, "transport.ts").contains("from './result';"));
        assert_eq!(
            rewrite_relative_ts_imports(
                "import './side.ts';\nimport \"./double.ts\";\nexport { value } from \"./value.ts\";\nimport('./dynamic.ts');\nimport x from 'pkg.ts';\n",
                ".mjs",
            ),
            "import './side.mjs';\nimport \"./double.mjs\";\nexport { value } from \"./value.mjs\";\nimport('./dynamic.ts');\nimport x from 'pkg.ts';\n"
        );
        assert_eq!(
            rewrite_relative_ts_imports("const text = \"from './value.ts'\";\n", ".js"),
            "const text = \"from './value.ts'\";\n"
        );
        assert_eq!(
            rewrite_relative_ts_imports("import './unterminated.ts\n", ".js"),
            "import './unterminated.ts\n"
        );
        assert_eq!(
            rewrite_relative_ts_imports("export { value } from './value.js';\n", ".js"),
            "export { value } from './value.js';\n"
        );
    }

    #[test]
    fn runtime_paths_share_the_types_collision_namespace() {
        let (_temp, config) = resolved_config(json!({}));
        let analyzed = Analyzed {
            ir: crate::ir::Ir::default(),
            operation_names: Vec::new(),
            schema_names: Vec::new(),
            enum_members: Vec::new(),
            link_targets: Vec::new(),
            webhook_names: Vec::new(),
            callback_names: Vec::new(),
        };
        let source = source();
        let helpers = BTreeSet::new();
        let base_url = ResolvedBaseUrl::Server { index: 0 };
        let mut sink = DiagnosticSink::new();
        let mut model = EmissionModel::new(&analyzed, &config, "digest".to_owned(), &mut sink);
        model.register_path("RUNTIME/standard-schema.ts", &source);
        let files = emit_runtime_files(RuntimeSelection {
            model: &mut model,
            helper_ids: &helpers,
            base_url: &base_url,
            relative_server_url: false,
            source: &source,
            server_variables: &[],
        });
        drop(model);
        assert_eq!(files.len(), 4);
        assert!(
            sink.as_slice()
                .iter()
                .any(|diagnostic| diagnostic.code == "OASTS1302")
        );
    }

    fn server_variable(default: &str, enum_values: &[&str]) -> ServerVariable {
        ServerVariable {
            default: default.to_owned(),
            enum_values: enum_values
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    #[test]
    fn server_variable_union_orders_dedups_and_widens_mixed_names() {
        // No variable anywhere has an enum: `None` leaves the frozen line for the caller to keep.
        assert_eq!(
            server_variable_union(&[("region".to_owned(), server_variable("us", &[]))]),
            None
        );
        assert_eq!(server_variable_union(&[]), None);

        // order: first-seen name order across servers (region, version, mixed, quoted).
        // dedup: version's "v2" repeats across its two occurrences and collapses to one.
        // mixed enum+plain: "mixed" is enum'd in one occurrence and plain in another, so any
        // declaring occurrence lacking the enum widens the whole name to `string`.
        // escaping: "quoted"'s literal contains a double quote, rendered through the same TS
        // string encoder as every other emitted string literal.
        let variables = [
            ("region".to_owned(), server_variable("us", &[])),
            ("version".to_owned(), server_variable("v2", &["v1", "v2"])),
            ("version".to_owned(), server_variable("v2", &["v2", "v3"])),
            ("mixed".to_owned(), server_variable("a", &["a"])),
            ("mixed".to_owned(), server_variable("b", &[])),
            ("quoted".to_owned(), server_variable("a\"b", &["a\"b"])),
        ];
        let expected = format!(
            "  serverVariables?: Record<string, never> | {{ region: string }} | {{ version: {} }} | {{ mixed: string }} | {{ quoted: {} }};",
            ["v1", "v2", "v3"].map(render_ts_string).join(" | "),
            render_ts_string("a\"b"),
        );
        assert_eq!(
            server_variable_union(&variables).as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn no_enum_server_variables_leave_transport_byte_identical() {
        let assets = runtime_assets();
        let frozen = render_regions(&assets.transport, &|_| true);
        assert!(frozen.contains(FROZEN_TRANSPORT_SERVER_VARIABLES));
        let no_enum = [("region".to_owned(), server_variable("us", &[]))];
        assert_eq!(
            specialize_transport(&assets.transport, false, &no_enum),
            frozen
        );
        assert_eq!(specialize_transport(&assets.transport, false, &[]), frozen);
    }

    #[test]
    fn enum_server_variable_rewrites_the_frozen_server_variables_line() {
        let (_temp, config) = resolved_config(json!({}));
        let variables = [
            ("version".to_owned(), server_variable("v2", &["v1", "v2"])),
            ("region".to_owned(), server_variable("us", &[])),
        ];
        let (files, diagnostics) = emit_with_server_variables(
            &config,
            [],
            &ResolvedBaseUrl::Server { index: 0 },
            &variables,
        );
        let transport = content(&files, "transport.ts");
        assert!(!transport.contains(FROZEN_TRANSPORT_SERVER_VARIABLES));
        assert!(transport.contains(
            "  serverVariables?: Record<string, never> | { version: \"v1\" | \"v2\" } | { region: string };"
        ));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn malformed_embedded_region_shapes_and_unknown_helpers_panic() {
        for malformed in [
            "//#region oxs:core\r\n//#endregion\r\n",
            "//#region oxs:core\n//#region oxs:auth\n//#endregion\n//#endregion\n",
            "//#endregion extra\n",
            "//#endregion\n",
            "//#region oxs:core\n",
            "//#region oxs:core\n//#endregion\n//#region oxs:core\n//#endregion\n",
            "//#region\n",
            "//#region oxs:unknown\n//#endregion\n",
            "//#region oxs:helper:BAD\n//#endregion\n",
        ] {
            assert!(std::panic::catch_unwind(|| parse_asset("bad.ts", malformed)).is_err());
        }

        let unknown = ["not-checked-in".to_owned()].into_iter().collect();
        assert!(
            std::panic::catch_unwind(|| {
                render_serialize(&runtime_assets().serialize, &unknown, false)
            })
            .is_err()
        );
    }

    #[test]
    fn asset_semantic_validation_rejects_noncanonical_regions() {
        let auth_in_serialize = parse_asset(
            "serialize.ts",
            "//#region oxs:core\ncore\n//#endregion\n//#region oxs:auth\nauth\n//#endregion\n",
        );
        assert!(std::panic::catch_unwind(|| validate_serialize(&auth_in_serialize)).is_err());
        assert!(render_serialize(&auth_in_serialize, &BTreeSet::new(), false).contains("core"));

        let missing_core = parse_asset("serialize.ts", "//#region oxs:helper:a\na\n//#endregion\n");
        assert!(std::panic::catch_unwind(|| validate_serialize(&missing_core)).is_err());

        let unsorted = parse_asset(
            "serialize.ts",
            "//#region oxs:core\ncore\n//#endregion\n//#region oxs:helper:z\nz\n//#endregion\n//#region oxs:helper:a\na\n//#endregion\n",
        );
        assert!(std::panic::catch_unwind(|| validate_serialize(&unsorted)).is_err());

        let missing_auth = parse_asset("transport.ts", "plain\n");
        assert!(std::panic::catch_unwind(|| validate_transport(&missing_auth)).is_err());
    }
}
