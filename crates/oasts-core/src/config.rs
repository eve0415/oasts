//! Schema-version 1 configuration loading for the local, single-spec wedge.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};

use crate::diag::{Diagnostic, DiagnosticSink, Severity};
use crate::filter::Filters;
use crate::syntax::parse_yaml_value;

const CODE_IO: &str = "OASTS1001";
const CODE_DISCOVERY: &str = "OASTS0011";
const CODE_SCRIPT_CONFIG_UNSUPPORTED: &str = "OASTS9001";
const CODE_PARSE: &str = "OASTS0031";
const CODE_SCHEMA_VERSION: &str = "OASTS0041";
const CODE_SCHEMA_URI: &str = "OASTS0042";
const CODE_WORKSPACE_ROOT: &str = "OASTS0051";
const CODE_SINGLE_SHAPE: &str = "OASTS0061";
pub(crate) const CODE_WORKSPACE_UNSUPPORTED: &str = "OASTS9002";
const CODE_INPUT_SHAPE: &str = "OASTS0071";
const CODE_INPUT_PATH: &str = "OASTS0072";
const CODE_OUTPUT: &str = "OASTS0081";
const CODE_NAMESPACE: &str = "OASTS0091";
const CODE_NO_ARTIFACT: &str = "OASTS0101";
const CODE_ARTIFACT_DIRECTORY: &str = "OASTS0102";
const CODE_DISABLED_ARTIFACT_OPTIONS: &str = "OASTS0103";
const CODE_CLIENT_REQUIRES_TYPES: &str = "OASTS0111";
const CODE_MSW_REQUIRES_TYPES: &str = "OASTS0112";
const CODE_TANSTACK_REQUIRES_CLIENT: &str = "OASTS0113";
const CODE_DISABLED_OPTIONS: &str = "OASTS0121";
const CODE_DATE_REPRESENTATION: &str = "OASTS0131";
const CODE_VALIDATION_REQUIRED: &str = "OASTS0151";
const CODE_VALIDATION_ENGINE_REQUIRED: &str = "OASTS0152";
const CODE_VALIDATION_WITHOUT_CLIENT: &str = "OASTS0161";
const CODE_OFF_VALIDATION_DIRECTIONS: &str = "OASTS0162";
const CODE_VALIDATION_DIRECTION_REQUIRED: &str = "OASTS0163";
const CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT: &str = "OASTS0164";
const CODE_UNCHECKED_RESPONSE: &str = "OASTS0171";
const CODE_UNCHECKED_RESPONSE_WARNING: &str = "OASTS0172";
const CODE_BASE_URL: &str = "OASTS0181";
const CODE_NAMING: &str = "OASTS0201";
const CODE_EMIT: &str = "OASTS0211";
const CODE_TRUST_LIMITS: &str = "OASTS0221";
/// The `typescript` block. Sits above the highest allocated config code, which stops at 0242.
const CODE_TYPESCRIPT: &str = "OASTS0251";
pub(crate) const CODE_BLOCK_UNSUPPORTED: &str = "OASTS9003";

const DISCOVERY_NAMES: [&str; 8] = [
    "oasts.config.ts",
    "oasts.config.mts",
    "oasts.config.cts",
    "oasts.config.js",
    "oasts.config.mjs",
    "oasts.config.cjs",
    "oasts.yaml",
    "oasts.json",
];

const SCRIPT_EXTENSIONS: [&str; 6] = ["ts", "mts", "cts", "js", "mjs", "cjs"];
const DATA_EXTENSIONS: [&str; 2] = ["yaml", "json"];

#[inline(never)]
fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The serde default for boolean options that keep their subject unless turned off.
const fn default_true() -> bool {
    true
}

#[cfg(feature = "json-schema")]
pub fn config_json_schema() -> serde_json::Value {
    schemars::schema_for!(RawConfig).to_value()
}

/// The unvalidated schema-version 1 root object.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(
    feature = "json-schema",
    derive(schemars::JsonSchema),
    schemars(
        rename = "UserConfig",
        rename_all = "camelCase",
        description = "The schema-version-1 single-spec configuration."
    )
)]
pub struct RawConfig {
    #[serde(
        default,
        rename = "$schema",
        deserialize_with = "deserialize_optional_non_null"
    )]
    #[cfg_attr(feature = "json-schema", schemars(rename = "$schema"))]
    pub schema: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    #[cfg_attr(
        feature = "json-schema",
        schemars(schema_with = "schema_version_literal")
    )]
    pub schema_version: Option<Number>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub workspace_root: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub input: Option<Input>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub output: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub namespace: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub specs: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub shared: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub filters: Option<FiltersConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub artifacts: Option<ArtifactsConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub types: Option<TypesConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub zod: Option<ZodConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub client: Option<RawClient>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub validation: Option<RawValidation>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub naming: Option<NamingConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub documentation: Option<DocumentationConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub emit: Option<EmitConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub local: Option<LocalTrustConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub remote: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub limits: Option<LimitsConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub typescript: Option<RawTypescript>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub compat: Option<CompatConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub watch: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub ci: Option<Value>,
}

/// A single input selector. Cross-field validation enforces exactly one field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub path: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub url: Option<String>,
}

#[cfg(feature = "json-schema")]
impl schemars::JsonSchema for Input {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Input".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Exactly one local path or HTTP(S) URL.",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" }
                    },
                    "required": ["url"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

#[cfg(feature = "json-schema")]
fn schema_version_literal(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "integer",
        "const": 1
    })
}

/// Boolean shorthand or an artifact option block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum ArtifactSetting {
    Enabled(bool),
    Options(ArtifactOptions),
}

/// Options accepted by every artifact selector.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ArtifactOptions {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub directory: Option<String>,
}

/// Artifact selectors before defaults are applied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(description = "Artifact selectors. Types default on; everything else defaults off.")
)]
pub struct ArtifactsConfig {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub types: Option<ArtifactSetting>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub client: Option<ArtifactSetting>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub zod: Option<ArtifactSetting>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub validators: Option<ArtifactSetting>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub tanstack: Option<ArtifactSetting>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub msw: Option<ArtifactSetting>,
}

/// One include/exclude pattern list for a single selection axis.
///
/// Both keys are optional; an absent list constrains nothing.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Include and exclude patterns for one selection axis. A pattern is exact string equality, or a slash-delimited regex with an optional trailing 'i' flag. Exclude beats include."
    )
)]
pub struct AxisFilter {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub include: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub exclude: Option<Vec<String>>,
}

/// Operation selection and component pruning, before patterns are compiled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Restricts generated output to a subset of the document. An operation survives when every configured, applicable axis admits it."
    )
)]
pub struct FiltersConfig {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub tags: Option<AxisFilter>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub operations: Option<AxisFilter>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub paths: Option<AxisFilter>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub methods: Option<AxisFilter>,
    /// `false` drops operations marked `deprecated: true`. Never applies to component schemas —
    /// a schema a surviving operation references is kept regardless.
    #[serde(default = "default_true")]
    pub deprecated: bool,
    /// `true` keeps component schemas no surviving operation reaches.
    #[serde(default)]
    pub orphans: bool,
}

/// Client options before defaults and cross-field validation are applied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Fetch client generation options."
    )
)]
pub struct RawClient {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub transport: Option<ClientTransport>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub auth_enforcement: Option<AuthEnforcement>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub aggregate: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub base_url: Option<BaseUrlConfig>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub fetch_options: Option<FetchDefaults>,
}

/// The schema-version 1 client transport.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum ClientTransport {
    Fetch,
}

/// Whether generated auth requirements are enforced by types or only at runtime.
/// Defaults to `Types`: the conditional call signatures hold the typecheck budget
/// on the benchmark baseline, so compile-time enforcement ships unless opted out.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum AuthEnforcement {
    Types,
    Runtime,
}

/// Initial client base URL selection. Resolve-time validation enforces the source-specific shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BaseUrlConfig {
    pub source: BaseUrlSource,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub index: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub value: Option<String>,
}

#[cfg(feature = "json-schema")]
impl schemars::JsonSchema for BaseUrlConfig {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "BaseUrlConfig".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Exactly one runtime, OpenAPI server, or literal base URL source.",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "const": "runtime" }
                    },
                    "required": ["source"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "const": "server" },
                        "index": { "type": "integer", "minimum": 0 }
                    },
                    "required": ["source"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "const": "literal" },
                        "value": { "type": "string" }
                    },
                    "required": ["source", "value"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

/// The source used for a generated client's initial base URL.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum BaseUrlSource {
    Runtime,
    Server,
    Literal,
}

/// Safe static Fetch defaults merged into each generated request.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Safe static defaults from the Fetch RequestInit surface."
    )
)]
pub struct FetchDefaults {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub credentials: Option<CredentialsMode>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub cache: Option<CacheMode>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub redirect: Option<RedirectMode>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub referrer_policy: Option<ReferrerPolicyValue>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub mode: Option<RequestModeValue>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub keepalive: Option<bool>,
}

/// Fetch request credential behavior accepted by generated defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum CredentialsMode {
    Omit,
    #[serde(rename = "same-origin")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "same-origin"))]
    SameOrigin,
    Include,
}

/// Fetch cache behavior accepted by generated defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum CacheMode {
    Default,
    #[serde(rename = "no-store")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "no-store"))]
    NoStore,
    Reload,
    #[serde(rename = "no-cache")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "no-cache"))]
    NoCache,
    #[serde(rename = "force-cache")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "force-cache"))]
    ForceCache,
    #[serde(rename = "only-if-cached")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "only-if-cached"))]
    OnlyIfCached,
}

/// Fetch redirect behavior accepted by generated defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum RedirectMode {
    Follow,
    Error,
    Manual,
}

/// Fetch referrer policy accepted by generated defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum ReferrerPolicyValue {
    #[serde(rename = "no-referrer")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "no-referrer"))]
    NoReferrer,
    #[serde(rename = "no-referrer-when-downgrade")]
    #[cfg_attr(
        feature = "json-schema",
        schemars(rename = "no-referrer-when-downgrade")
    )]
    NoReferrerWhenDowngrade,
    #[serde(rename = "same-origin")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "same-origin"))]
    SameOrigin,
    Origin,
    #[serde(rename = "strict-origin")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "strict-origin"))]
    StrictOrigin,
    #[serde(rename = "origin-when-cross-origin")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "origin-when-cross-origin"))]
    OriginWhenCrossOrigin,
    #[serde(rename = "strict-origin-when-cross-origin")]
    #[cfg_attr(
        feature = "json-schema",
        schemars(rename = "strict-origin-when-cross-origin")
    )]
    StrictOriginWhenCrossOrigin,
    #[serde(rename = "unsafe-url")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "unsafe-url"))]
    UnsafeUrl,
}

/// Fetch request mode accepted by generated defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum RequestModeValue {
    Cors,
    #[serde(rename = "no-cors")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "no-cors"))]
    NoCors,
    #[serde(rename = "same-origin")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "same-origin"))]
    SameOrigin,
}

/// Runtime validation options before defaults and combination checks are applied.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Runtime validation selection and unchecked-response policy."
    )
)]
pub struct RawValidation {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub engine: Option<ValidationEngine>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub request: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub response: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    pub unchecked: Option<UncheckedPolicy>,
}

/// Runtime validation implementation selected for client traffic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum ValidationEngine {
    Off,
    Zod,
    Generated,
}

/// Policy for successful response data not checked against the OpenAPI schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum UncheckedPolicy {
    Warn,
    Error,
    Allow,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum EnumRepresentation {
    #[default]
    Literal,
    Const,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum EnumExtensions {
    #[default]
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum DateTimeRepresentation {
    #[default]
    String,
    Date,
    Temporal,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum DateRepresentation {
    #[default]
    String,
    Temporal,
}

/// How a `oneOf` carrying a `discriminator` is shaped. `structural` emits `Cat | Dog` and lets the
/// discriminator drive diagnostics only; `tagged` intersects each branch with the tag it proves,
/// `(Cat & { petType: "feline" }) | (Dog & { petType: "canine" })`, so TypeScript can narrow it.
///
/// Doc comments belong on the enum, not its variants: a variant description makes `schemars` emit a
/// named `oneOf` rather than a plain `enum`, and the config-surface generator has no alias form for
/// that — the emitted `config.ts` would reference a type it never declares.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum IntegerRepresentation {
    #[default]
    Number,
    Bigint,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum DiscriminatedUnions {
    #[default]
    Structural,
    Tagged,
}

/// Type artifact options with schema defaults applied during deserialization.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(rename_all = "camelCase", description = "Type representation options.")
)]
pub struct TypesConfig {
    #[serde(rename = "enum")]
    #[cfg_attr(feature = "json-schema", schemars(rename = "enum"))]
    pub enum_representation: EnumRepresentation,
    pub enum_extensions: EnumExtensions,
    pub date_time: DateTimeRepresentation,
    pub date: DateRepresentation,
    pub discriminated_unions: DiscriminatedUnions,
    pub integer: IntegerRepresentation,
    pub readonly: bool,
}

/// Which zod entry point the emitted schemas import.
///
/// The two share one parsing core and return identical verdicts; they differ in API shape and in
/// what a bundler can drop. `Mini` is the tree-shakable functional entry point — smaller, but its
/// schemas are `ZodMiniType`, so a consumer handing them to a library that expects the classic
/// `ZodType` wants `Classic`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum ZodFlavor {
    #[default]
    Classic,
    Mini,
}

/// Zod artifact options with schema defaults applied during deserialization.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(rename_all = "camelCase", description = "Zod artifact options.")
)]
pub struct ZodConfig {
    pub flavor: ZodFlavor,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum FileCase {
    #[default]
    Kebab,
    Snake,
    Camel,
    Pascal,
    Preserve,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum OperationCase {
    #[default]
    Camel,
    Preserve,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum EnumMemberCase {
    #[default]
    Pascal,
    Camel,
    ScreamingSnake,
    Preserve,
}

/// Naming options. Fixed casing keys remain strings so rule 20 can name them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Declaration and file naming options."
    )
)]
pub struct NamingConfig {
    pub file_case: FileCase,
    pub type_case: String,
    pub property_case: String,
    pub operation_case: OperationCase,
    pub enum_member_case: EnumMemberCase,
    pub type_prefix: String,
    pub type_suffix: String,
    pub overrides: NameOverrides,
}

impl Default for NamingConfig {
    fn default() -> Self {
        Self {
            file_case: FileCase::Kebab,
            type_case: "pascal".to_owned(),
            property_case: "preserve".to_owned(),
            operation_case: OperationCase::Camel,
            enum_member_case: EnumMemberCase::Pascal,
            type_prefix: String::new(),
            type_suffix: String::new(),
            overrides: NameOverrides::default(),
        }
    }
}

/// Explicit identifier replacements for named declarations, keyed by raw wire name.
///
/// The nested per-namespace shape stays additive: a future namespace is a new field, not a
/// breaking reshape. For `schemas` and `operations`, a value is the complete TypeScript identifier
/// — `typePrefix`/`typeSuffix` are not applied on top, because the user wrote the exact name they
/// want and decorating it would defeat the point. Values are still validated and still participate
/// in collision detection like any generated name, so an override resolves a collision only by
/// naming a distinct identifier, never by bypassing the check; a key matching no declaration in
/// the document is a config error (see identifier allocation), so a typo surfaces instead of
/// silently leaving the original collision unexplained.
///
/// `pathSegments` is keyed by the raw URL path segment text as written in the path template
/// (e.g. `foo-bar`), not by any name derived from it. Its values are validated the same way, but
/// whether a key matches anything in the document is not this layer's concern: the artifact that
/// consumes path-segment overrides may not even be enabled, so an unmatched key is reported there,
/// as a warning, rather than as a config error here.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Explicit identifier replacements keyed by raw wire name, per namespace."
    )
)]
pub struct NameOverrides {
    /// Keyed by a `components/schemas` key or a document-root schema's file stem; the value is the
    /// final type identifier.
    pub schemas: BTreeMap<String, String>,
    /// Keyed by `SourceRef::display()` (`<source_id>#<json_pointer>`); the value is the final type
    /// identifier. A local `source_id` is `workspace/<path>` when the workspace root contains the
    /// target, or `allow/<n>/<path>` for the most specific matching `local.allowPaths` root, where
    /// `<n>` is that root's zero-based config order. Reordering `local.allowPaths` can therefore
    /// change these keys.
    pub schemas_by_source: BTreeMap<String, String>,
    /// Keyed by the `operationId`; the value is the final operation identifier.
    pub operations: BTreeMap<String, String>,
    /// Keyed by a raw document `webhooks` map key; the value replaces its normalized identifier
    /// fragment for every method. This explicit fragment takes precedence over an `operationId`.
    pub webhooks: BTreeMap<String, String>,
    /// Keyed by a raw operation `callbacks` map key; the value replaces its normalized identifier
    /// fragment wherever that callback name appears.
    pub callbacks: BTreeMap<String, String>,
    /// Keyed by the raw URL path segment text; the value is the final identifier fragment bound
    /// for every declaration under that segment.
    pub path_segments: BTreeMap<String, String>,
}

/// Documentation switches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(description = "Schema-derived TSDoc switches.")
)]
pub struct DocumentationConfig {
    pub enabled: bool,
    pub summary: bool,
    pub description: bool,
    pub deprecated: bool,
    pub examples: bool,
    pub constraints: bool,
}

impl Default for DocumentationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            summary: true,
            description: true,
            deprecated: true,
            examples: true,
            constraints: true,
        }
    }
}

/// Emission options. Literal-valued strings are validated as rule 21.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(rename_all = "camelCase", description = "Generated module mechanics.")
)]
pub struct EmitConfig {
    pub runtime_directory: String,
    pub import_extension: String,
    pub banner: Vec<String>,
    pub format: String,
}

impl Default for EmitConfig {
    fn default() -> Self {
        Self {
            runtime_directory: "runtime".to_owned(),
            import_extension: ".js".to_owned(),
            banner: Vec::new(),
            format: "deterministic".to_owned(),
        }
    }
}

/// How the consumer's `tsconfig.json` is located.
///
/// This is the only consumer-side file that reaches emitted bytes: it decides whether generated
/// code carries the `esnext.temporal` reference directive. `off` is therefore the setting a build
/// reaches for when it needs output that does not depend on anything outside version, config and
/// input — it answers "the consumer does not provide Temporal" and always emits the directive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum TsconfigSource {
    /// Nearest `tsconfig.json` at or above the resolved output directory.
    #[default]
    Auto,
    /// Read nothing.
    Off,
    /// A path resolved below `workspaceRoot`, like every other path in this config.
    Path(PathBuf),
}

/// The `typescript` block, before path resolution.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct RawTypescript {
    /// `auto`, `off`, or a path relative to the config directory.
    pub tsconfig: Option<String>,
}

/// Local file trust options.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Local document/ref trust boundary."
    )
)]
pub struct LocalTrustConfig {
    pub allow_paths: Vec<String>,
}

/// Document graph bounds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Document-graph size and depth bounds."
    )
)]
pub struct LimitsConfig {
    pub max_document_bytes: u64,
    pub max_total_bytes: u64,
    pub max_documents: u64,
    pub max_ref_depth: u64,
}

/// How a `deepObject` query parameter is lowered onto the wire.
///
/// OpenAPI defines `deepObject` for `object` schemas only. Real documents declare it on arrays,
/// on schemas with no type, and on scalars, expecting the bracket-path encoding of `qs` — `p[k]=v`
/// for an object, `p[0]=v` for an array, and a plain `p=v` for a scalar, which has no nesting to
/// bracket. That is a wire format the specification does not define, so taking it is a recorded
/// opt-in rather than a default.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "json-schema", schemars(rename_all = "camelCase"))]
pub enum DeepObjectEncoding {
    /// Admit `deepObject` only where OpenAPI defines it: an `object`-projecting schema.
    #[default]
    Strict,
    /// Admit every schema shape, lowering each with the bracket-path encoding of `qs`.
    Extended,
}

/// Opt-in departures from strict OpenAPI conformance.
///
/// oasts follows the OpenAPI and JSON Schema specifications by default and widens only where the
/// ecosystem demonstrably diverges. Every such widening lives here, so a reader can audit the full
/// set of departures in one block of any configuration rather than hunting for them per feature.
/// The section is optional and every key defaults to the strict reading, so a configuration without
/// it behaves exactly as if conformance were unconditional.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "json-schema",
    schemars(
        rename_all = "camelCase",
        description = "Opt-in departures from strict OpenAPI conformance."
    )
)]
pub struct CompatConfig {
    pub deep_object_encoding: DeepObjectEncoding,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_document_bytes: 33_554_432,
            max_total_bytes: 268_435_456,
            max_documents: 256,
            max_ref_depth: 64,
        }
    }
}

/// A resolved artifact selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedArtifact {
    pub enabled: bool,
    /// Where this artifact's files land, relative to the output root, in normalized `/`-separated
    /// form. Emitters build both their own paths and their imports of other artifacts from this,
    /// so the whole layout follows from one string per artifact.
    pub directory: String,
}

/// Fully resolved artifact selectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedArtifactsConfig {
    pub types: ResolvedArtifact,
    pub client: ResolvedArtifact,
    pub zod: ResolvedArtifact,
    pub validators: ResolvedArtifact,
    pub tanstack: ResolvedArtifact,
    pub msw: ResolvedArtifact,
}

/// Fully resolved Fetch client options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub auth_enforcement: AuthEnforcement,
    pub aggregate: bool,
    pub base_url: ResolvedBaseUrl,
    pub fetch_options: FetchDefaults,
}

/// Fully resolved initial base URL selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedBaseUrl {
    Runtime,
    Server { index: u32 },
    Literal { value: String },
}

/// Fully resolved runtime validation options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationConfig {
    pub engine: ValidationEngine,
    pub request: bool,
    pub response: bool,
    pub unchecked: UncheckedPolicy,
}

/// The fully-defaulted, absolute-path configuration consumed by the core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConfig {
    pub diagnostics: Vec<Diagnostic>,
    pub config_path: PathBuf,
    pub config_dir: PathBuf,
    pub schema: Option<String>,
    pub schema_version: u64,
    pub workspace_root: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub namespace: String,
    /// Operation selection and component pruning; `None` when the config declares no block.
    pub filters: Option<Filters>,
    pub artifacts: ResolvedArtifactsConfig,
    pub types: TypesConfig,
    pub zod: ZodConfig,
    pub client: Option<ClientConfig>,
    pub validation: Option<ValidationConfig>,
    pub naming: NamingConfig,
    pub documentation: DocumentationConfig,
    pub emit: EmitConfig,
    pub local_allow_paths: Vec<PathBuf>,
    pub limits: LimitsConfig,
    pub compat: CompatConfig,
    pub tsconfig: TsconfigSource,
}

/// A discovered configuration candidate before script-support policy is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredConfig {
    /// Path of the single discovered configuration file.
    pub path: PathBuf,
    /// Whether the file uses a TypeScript/JavaScript extension.
    pub is_script: bool,
}

/// Discovers a supported configuration file, rejecting script configs.
pub fn discover(cwd: &Path, explicit: Option<&Path>) -> Result<PathBuf, Diagnostic> {
    let candidate = discover_candidate(cwd, explicit)?;
    reject_script_extension(&candidate.path)?;
    Ok(candidate.path)
}

/// Discovers the single configuration candidate without script-support policy.
///
/// Hosts that can evaluate TypeScript/JavaScript configs (the Node CLI) use this
/// entry point and handle `is_script` candidates themselves; the standalone
/// binary goes through [`discover`], which rejects them.
pub fn discover_candidate(
    cwd: &Path,
    explicit: Option<&Path>,
) -> Result<DiscoveredConfig, Diagnostic> {
    if let Some(explicit_path) = explicit {
        let path = if explicit_path.is_absolute() {
            explicit_path.to_path_buf()
        } else {
            cwd.join(explicit_path)
        };
        let extension = path.extension().and_then(OsStr::to_str);
        let supported = extension.is_some_and(|candidate| {
            SCRIPT_EXTENSIONS.contains(&candidate) || DATA_EXTENSIONS.contains(&candidate)
        });
        if !supported {
            return Err(config_error(
                CODE_DISCOVERY,
                format!(
                    "explicit config path '{}' has an unsupported extension",
                    path.display()
                ),
                Some(&path),
                None,
            ));
        }
        if !path.is_file() {
            return Err(config_error(
                CODE_DISCOVERY,
                format!("explicit config path '{}' does not exist", path.display()),
                Some(&path),
                None,
            ));
        }
        return Ok(DiscoveredConfig {
            is_script: is_script_path(&path),
            path,
        });
    }

    let mut candidates = DISCOVERY_NAMES
        .iter()
        .map(|name| cwd.join(name))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(config_error(
            CODE_DISCOVERY,
            format!(
                "config discovery expected exactly one candidate, found {}",
                candidates.len()
            ),
            None,
            None,
        ));
    }

    let path = candidates.swap_remove(0);
    Ok(DiscoveredConfig {
        is_script: is_script_path(&path),
        path,
    })
}

fn is_script_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|candidate| SCRIPT_EXTENSIONS.contains(&candidate))
}

fn reject_script_extension(path: &Path) -> Result<(), Diagnostic> {
    if is_script_path(path) {
        return Err(config_error(
            CODE_SCRIPT_CONFIG_UNSUPPORTED,
            "TypeScript/JavaScript config is not supported in this build",
            Some(path),
            None,
        ));
    }
    Ok(())
}

/// Discovers, parses, validates, and resolves one configuration file.
pub fn load_config(explicit: Option<&Path>, cwd: &Path) -> Result<ResolvedConfig, Vec<Diagnostic>> {
    let discovered = discover(cwd, explicit).map_err(|diagnostic| vec![diagnostic])?;
    let config_path = if discovered.is_absolute() {
        discovered
    } else {
        absolutize_config_path(discovered, std::env::current_dir())?
    };
    let source = fs::read_to_string(&config_path).map_err(|error| {
        vec![config_error(
            CODE_IO,
            format!("failed to read config: {error}"),
            Some(&config_path),
            None,
        )]
    })?;
    let raw = parse_config(&config_path, &source).map_err(|diagnostic| vec![diagnostic])?;
    resolve_config(config_path, raw)
}

/// Loads a configuration from in-memory JSON bytes anchored at `config_path`.
///
/// Hosts that evaluate script configs (the Node CLI) serialize the evaluated
/// module to JSON and pass the bytes here; the file at `config_path` is never
/// read, but every path in the config still resolves from its parent
/// directory exactly as in [`load_config`].
pub fn load_config_from_json(
    config_path: &Path,
    json: &[u8],
) -> Result<ResolvedConfig, Vec<Diagnostic>> {
    let config_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        absolutize_config_path(config_path.to_path_buf(), std::env::current_dir())?
    };
    let raw = parse_config_json(&config_path, json).map_err(|diagnostic| vec![diagnostic])?;
    resolve_config(config_path, raw)
}

/// Parses in-memory JSON config bytes into an unvalidated [`RawConfig`].
pub fn parse_config_json(config_path: &Path, json: &[u8]) -> Result<RawConfig, Diagnostic> {
    serde_json::from_slice(json).map_err(|error| {
        config_error(
            CODE_PARSE,
            format!("invalid JSON config: {error}"),
            Some(config_path),
            None,
        )
        .with_location(to_u32(error.line()), to_u32(error.column()))
    })
}

fn absolutize_config_path(
    discovered: PathBuf,
    current_dir: io::Result<PathBuf>,
) -> Result<PathBuf, Vec<Diagnostic>> {
    current_dir
        .map(|current| current.join(discovered))
        .map_err(|error| {
            vec![config_error(
                CODE_IO,
                format!("failed to resolve current directory: {error}"),
                None,
                None,
            )]
        })
}

fn parse_config(path: &Path, source: &str) -> Result<RawConfig, Diagnostic> {
    if path.extension() == Some(OsStr::new("json")) {
        serde_json::from_str(source).map_err(|error| {
            config_error(
                CODE_PARSE,
                format!("invalid JSON config: {error}"),
                Some(path),
                None,
            )
            .with_location(to_u32(error.line()), to_u32(error.column()))
        })
    } else {
        let value = parse_yaml_value(source).map_err(|error| {
            config_error(CODE_PARSE, error.message, Some(path), None)
                .with_location(error.line, error.col)
        })?;
        serde_json::from_value(value).map_err(|error| {
            config_error(
                CODE_PARSE,
                format!("invalid YAML config value: {error}"),
                Some(path),
                None,
            )
        })
    }
}

/// Validates and resolves a parsed configuration anchored at `config_path`.
pub fn resolve_config(
    config_path: PathBuf,
    raw: RawConfig,
) -> Result<ResolvedConfig, Vec<Diagnostic>> {
    let mut sink = DiagnosticSink::new();
    let source_path = config_path.as_path();
    let config_parent = config_path
        .parent()
        .expect("resolved config paths always have a parent");
    let config_dir = match fs::canonicalize(config_parent) {
        Ok(path) => path,
        Err(error) => {
            sink.push(config_error(
                CODE_IO,
                format!("failed to resolve config directory: {error}"),
                Some(source_path),
                None,
            ));
            config_parent.to_path_buf()
        }
    };

    match raw.schema_version.as_ref().and_then(Number::as_u64) {
        Some(1) => {}
        _ => sink.push(config_error(
            CODE_SCHEMA_VERSION,
            "schemaVersion is required and must be the integer literal 1",
            Some(source_path),
            Some("/schemaVersion"),
        )),
    }
    if raw.schema.as_deref().is_some_and(|uri| !is_uri(uri)) {
        sink.push(config_error(
            CODE_SCHEMA_URI,
            "$schema must be a URI string",
            Some(source_path),
            Some("/$schema"),
        ));
    }

    let workspace_text = raw.workspace_root.as_deref().unwrap_or(".");
    let workspace_root = match resolve_below(&config_dir, Path::new(workspace_text), true) {
        Ok(path) => path,
        Err(reason) => {
            sink.push(config_error(
                CODE_WORKSPACE_ROOT,
                format!("invalid workspaceRoot: {reason}"),
                Some(source_path),
                Some("/workspaceRoot"),
            ));
            config_dir.clone()
        }
    };

    let workspace_shape = raw.specs.is_some() || raw.shared.is_some();
    if workspace_shape {
        sink.push(config_error(
            CODE_WORKSPACE_UNSUPPORTED,
            "multi-spec workspace config is not supported in this build",
            Some(source_path),
            raw.specs.as_ref().map(|_| "/specs").or(Some("/shared")),
        ));
    }

    let input = if workspace_shape {
        None
    } else {
        resolve_input(raw.input.as_ref(), &workspace_root, source_path, &mut sink)
    };
    let output = if workspace_shape {
        None
    } else {
        resolve_output(
            raw.output.as_deref(),
            &workspace_root,
            source_path,
            &mut sink,
        )
    };

    let namespace = raw.namespace.unwrap_or_else(|| "api".to_owned());
    if !is_ts_identifier(&namespace) {
        sink.push(config_error(
            CODE_NAMESPACE,
            format!("namespace '{namespace}' is not a valid TypeScript identifier"),
            Some(source_path),
            Some("/namespace"),
        ));
    }

    let raw_artifacts = raw.artifacts.unwrap_or_default();
    let artifact_states = resolve_artifacts(raw_artifacts, source_path, &mut sink);
    if raw.types.is_some() && !artifact_states.types.enabled {
        sink.push(config_error(
            CODE_DISABLED_OPTIONS,
            "types options are invalid while the types artifact is disabled",
            Some(source_path),
            Some("/types"),
        ));
    }
    if raw.zod.is_some() && !artifact_states.zod.enabled {
        sink.push(config_error(
            CODE_DISABLED_OPTIONS,
            "zod options are invalid while the zod artifact is disabled",
            Some(source_path),
            Some("/zod"),
        ));
    }
    if raw.client.is_some() && !artifact_states.client.enabled {
        sink.push(config_error(
            CODE_DISABLED_OPTIONS,
            "client options are invalid while the client artifact is disabled",
            Some(source_path),
            Some("/client"),
        ));
    }
    if raw.validation.is_some() && !artifact_states.client.enabled {
        sink.push(config_error(
            CODE_VALIDATION_WITHOUT_CLIENT,
            "validation options require the client artifact to be enabled",
            Some(source_path),
            Some("/validation"),
        ));
    }
    validate_client_combinations(
        &artifact_states,
        raw.client.as_ref(),
        raw.validation.as_ref(),
        source_path,
        &mut sink,
    );

    let types = raw.types.unwrap_or_default();
    // The codecs are emitted under the client artifact and only run at client pipeline positions,
    // so a transforming representation without the client artifact has nowhere to bind.
    if (types.date_time != DateTimeRepresentation::String
        || types.date != DateRepresentation::String
        || types.integer != IntegerRepresentation::Number)
        && !artifact_states.client.enabled
    {
        sink.push(config_error(
            CODE_DATE_REPRESENTATION,
            "non-string dateTime/date and bigint integer representations require the client artifact",
            Some(source_path),
            Some("/types"),
        ));
    }
    if types.integer == IntegerRepresentation::Bigint && artifact_states.tanstack.enabled {
        sink.push(config_error(
            CODE_DATE_REPRESENTATION,
            "types.integer 'bigint' is incompatible with TanStack query keys because their default JSON serialization rejects bigint values",
            Some(source_path),
            Some("/types/integer"),
        ));
    }

    let naming = raw.naming.unwrap_or_default();
    validate_naming(&naming, source_path, &mut sink);
    let documentation = raw.documentation.unwrap_or_default();
    let mut emit = raw.emit.unwrap_or_default();
    validate_emit(&emit, source_path, &mut sink);
    emit.runtime_directory = normalize_directory(&emit.runtime_directory);
    validate_directory_overlaps(&artifact_states, &emit, source_path, &mut sink);

    let local = raw.local.unwrap_or_default();
    let local_allow_paths = resolve_local_paths(&local, &config_dir, source_path, &mut sink);
    let limits = raw.limits.unwrap_or_default();
    validate_limits(&limits, source_path, &mut sink);
    let compat = raw.compat.unwrap_or_default();

    for (present, pointer, name) in [
        (raw.remote.is_some(), "/remote", "remote"),
        (raw.watch.is_some(), "/watch", "watch"),
        (raw.ci.is_some(), "/ci", "ci"),
    ] {
        if present {
            sink.push(config_error(
                CODE_BLOCK_UNSUPPORTED,
                format!("{name} config is not supported in this build"),
                Some(source_path),
                Some(pointer),
            ));
        }
    }

    let tsconfig = resolve_tsconfig_source(
        raw.typescript.as_ref(),
        &workspace_root,
        source_path,
        &mut sink,
    );
    let filters = crate::filter::resolve(raw.filters.as_ref(), source_path, &mut sink);

    let has_errors = sink.has_errors();
    let diagnostics = sink.into_sorted_vec();
    if has_errors {
        return Err(diagnostics);
    }

    let input = input.expect("an unresolved input always emits a diagnostic");
    let output = output.expect("an unresolved output always emits a diagnostic");
    let client = resolve_client_config(raw.client.as_ref(), artifact_states.client.enabled);
    let validation =
        resolve_validation_config(raw.validation.as_ref(), artifact_states.client.enabled);
    let artifacts = artifact_states.resolve();

    Ok(ResolvedConfig {
        diagnostics,
        config_path,
        config_dir,
        schema: raw.schema,
        schema_version: 1,
        workspace_root,
        input,
        output,
        namespace,
        filters,
        artifacts,
        types,
        zod: raw.zod.unwrap_or_default(),
        client,
        validation,
        naming,
        documentation,
        emit,
        local_allow_paths,
        limits,
        compat,
        tsconfig,
    })
}

fn resolve_input(
    input: Option<&Input>,
    workspace_root: &Path,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Option<PathBuf> {
    let Some(input) = input else {
        sink.push(config_error(
            CODE_SINGLE_SHAPE,
            "single-spec config requires input",
            Some(source),
            Some("/input"),
        ));
        return None;
    };
    match (input.path.as_deref(), input.url.as_deref()) {
        (Some(path), None) if is_uri(path) => Some(PathBuf::from(path)),
        (Some(path), None) => match resolve_below(workspace_root, Path::new(path), true) {
            Ok(resolved) => Some(resolved),
            Err(reason) => {
                sink.push(config_error(
                    CODE_INPUT_PATH,
                    format!("invalid local input path: {reason}"),
                    Some(source),
                    Some("/input/path"),
                ));
                None
            }
        },
        (None, Some(url)) if is_uri(url) => Some(PathBuf::from(url)),
        (None, Some(_)) => {
            sink.push(config_error(
                CODE_INPUT_PATH,
                "input.url must be an absolute URI",
                Some(source),
                Some("/input/url"),
            ));
            None
        }
        _ => {
            sink.push(config_error(
                CODE_INPUT_SHAPE,
                "input must contain exactly one of path or url",
                Some(source),
                Some("/input"),
            ));
            None
        }
    }
}

/// Resolves `typescript.tsconfig`.
///
/// `auto` and `off` are the two words; anything else is a path, held to the same below-workspace
/// containment every other path in this config gets. A path is resolved against the config
/// directory the way `input` and `output` are, so a config can name a tsconfig beside itself.
fn resolve_tsconfig_source(
    raw: Option<&RawTypescript>,
    workspace_root: &Path,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> TsconfigSource {
    let Some(value) = raw.and_then(|block| block.tsconfig.as_deref()) else {
        return TsconfigSource::Auto;
    };
    match value {
        "auto" => TsconfigSource::Auto,
        "off" => TsconfigSource::Off,
        path => match resolve_below(workspace_root, Path::new(path), false) {
            Ok(resolved) => TsconfigSource::Path(resolved),
            Err(reason) => {
                sink.push(config_error(
                    CODE_TYPESCRIPT,
                    format!("invalid typescript.tsconfig: {reason}"),
                    Some(source),
                    Some("/typescript/tsconfig"),
                ));
                TsconfigSource::Auto
            }
        },
    }
}

fn resolve_output(
    output: Option<&str>,
    workspace_root: &Path,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Option<PathBuf> {
    let Some(output) = output else {
        sink.push(config_error(
            CODE_SINGLE_SHAPE,
            "single-spec config requires output",
            Some(source),
            Some("/output"),
        ));
        return None;
    };
    match resolve_below(workspace_root, Path::new(output), false) {
        Ok(path) => Some(path),
        Err(reason) => {
            sink.push(config_error(
                CODE_OUTPUT,
                format!("invalid output: {reason}"),
                Some(source),
                Some("/output"),
            ));
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactState {
    enabled: bool,
    directory: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactStates {
    types: ArtifactState,
    client: ArtifactState,
    zod: ArtifactState,
    validators: ArtifactState,
    tanstack: ArtifactState,
    msw: ArtifactState,
}

impl ArtifactStates {
    fn resolve(self) -> ResolvedArtifactsConfig {
        ResolvedArtifactsConfig {
            types: resolved_artifact(self.types),
            client: resolved_artifact(self.client),
            zod: resolved_artifact(self.zod),
            validators: resolved_artifact(self.validators),
            tanstack: resolved_artifact(self.tanstack),
            msw: resolved_artifact(self.msw),
        }
    }
}

fn resolved_artifact(state: ArtifactState) -> ResolvedArtifact {
    ResolvedArtifact {
        enabled: state.enabled,
        directory: state.directory,
    }
}

fn resolve_client_config(raw: Option<&RawClient>, enabled: bool) -> Option<ClientConfig> {
    if !enabled {
        return None;
    }
    Some(ClientConfig {
        auth_enforcement: raw
            .and_then(|raw| raw.auth_enforcement)
            .unwrap_or(AuthEnforcement::Types),
        aggregate: raw.and_then(|raw| raw.aggregate).unwrap_or(false),
        base_url: resolve_base_url(raw.and_then(|raw| raw.base_url.as_ref())),
        fetch_options: raw
            .and_then(|raw| raw.fetch_options.clone())
            .unwrap_or_default(),
    })
}

fn resolve_base_url(raw: Option<&BaseUrlConfig>) -> ResolvedBaseUrl {
    match raw {
        None
        | Some(BaseUrlConfig {
            source: BaseUrlSource::Runtime,
            ..
        }) => ResolvedBaseUrl::Runtime,
        Some(BaseUrlConfig {
            source: BaseUrlSource::Server,
            index,
            ..
        }) => ResolvedBaseUrl::Server {
            index: index.unwrap_or(0),
        },
        Some(BaseUrlConfig {
            source: BaseUrlSource::Literal,
            value,
            ..
        }) => ResolvedBaseUrl::Literal {
            value: value.clone().unwrap_or_default(),
        },
    }
}

fn resolve_validation_config(
    raw: Option<&RawValidation>,
    client_enabled: bool,
) -> Option<ValidationConfig> {
    if !client_enabled {
        return None;
    }
    let raw = raw?;
    let engine = raw.engine?;
    Some(ValidationConfig {
        engine,
        request: raw.request.unwrap_or(false),
        response: raw.response.unwrap_or(false),
        unchecked: raw.unchecked.unwrap_or(UncheckedPolicy::Warn),
    })
}

fn validate_client_combinations(
    artifacts: &ArtifactStates,
    client: Option<&RawClient>,
    validation: Option<&RawValidation>,
    source: &Path,
    sink: &mut DiagnosticSink,
) {
    if !artifacts.client.enabled {
        if let Some(base_url) = client.and_then(|options| options.base_url.as_ref()) {
            validate_base_url(base_url, source, sink);
        }
        return;
    }

    if !artifacts.types.enabled {
        sink.push(config_error(
            CODE_CLIENT_REQUIRES_TYPES,
            "the client artifact requires the types artifact to be enabled",
            Some(source),
            Some("/artifacts/client"),
        ));
    }
    if validation.is_none() {
        sink.push(config_error(
            CODE_VALIDATION_REQUIRED,
            "the client artifact requires an explicit validation object",
            Some(source),
            Some("/validation"),
        ));
    } else if validation.and_then(|options| options.engine).is_none() {
        sink.push(config_error(
            CODE_VALIDATION_ENGINE_REQUIRED,
            "validation.engine is required when the client artifact is enabled",
            Some(source),
            Some("/validation/engine"),
        ));
    }
    if let Some(base_url) = client.and_then(|options| options.base_url.as_ref()) {
        validate_base_url(base_url, source, sink);
    }
    validate_validation_options(artifacts, validation, source, sink);
}

fn validate_validation_options(
    artifacts: &ArtifactStates,
    validation: Option<&RawValidation>,
    source: &Path,
    sink: &mut DiagnosticSink,
) {
    if let Some(options) = validation
        && let Some(engine) = options.engine
    {
        let request = options.request.unwrap_or(false);
        let response = options.response.unwrap_or(false);
        match engine {
            ValidationEngine::Off => {
                if request || response {
                    sink.push(config_error(
                        CODE_OFF_VALIDATION_DIRECTIONS,
                        "validation engine 'off' requires request and response to be false",
                        Some(source),
                        Some("/validation"),
                    ));
                }
            }
            // Every non-off engine binds to a standalone artifact, so that artifact must be
            // enabled alongside it. One rule over the engine domain rather than a per-engine arm,
            // so an engine added later cannot be wired up without declaring its artifact.
            ValidationEngine::Zod | ValidationEngine::Generated => {
                require_validation_direction(request, response, source, sink);
                let (engine_name, artifact_name, artifact_enabled) = match engine {
                    ValidationEngine::Zod => ("zod", "zod", artifacts.zod.enabled),
                    _ => ("generated", "validators", artifacts.validators.enabled),
                };
                if !artifact_enabled {
                    sink.push(config_error(
                        CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT,
                        format!(
                            "validation engine '{engine_name}' requires the {artifact_name} artifact to be enabled"
                        ),
                        Some(source),
                        Some("/validation/engine"),
                    ));
                }
            }
        }
    }

    let response = validation
        .and_then(|options| options.response)
        .unwrap_or(false);
    if response {
        return;
    }
    match validation
        .and_then(|options| options.unchecked)
        .unwrap_or(UncheckedPolicy::Warn)
    {
        UncheckedPolicy::Error => sink.push(config_error(
            CODE_UNCHECKED_RESPONSE,
            "successful response data would be decoded but unchecked against the OpenAPI schema",
            Some(source),
            Some("/validation/unchecked"),
        )),
        UncheckedPolicy::Warn => sink.push(config_warning(
            CODE_UNCHECKED_RESPONSE_WARNING,
            "successful response data is decoded but unchecked against the OpenAPI schema; validation.unchecked: \"allow\" acknowledges it",
            Some(source),
            Some("/validation/unchecked"),
        )),
        UncheckedPolicy::Allow => {}
    }
}

fn require_validation_direction(
    request: bool,
    response: bool,
    source: &Path,
    sink: &mut DiagnosticSink,
) {
    if !request && !response {
        sink.push(config_error(
            CODE_VALIDATION_DIRECTION_REQUIRED,
            "a non-off validation engine requires request or response validation",
            Some(source),
            Some("/validation"),
        ));
    }
}

fn validate_base_url(base_url: &BaseUrlConfig, source: &Path, sink: &mut DiagnosticSink) {
    let valid = match base_url.source {
        BaseUrlSource::Runtime => base_url.index.is_none() && base_url.value.is_none(),
        BaseUrlSource::Server => base_url.value.is_none(),
        BaseUrlSource::Literal => {
            base_url.index.is_none()
                && base_url
                    .value
                    .as_deref()
                    .is_some_and(is_valid_literal_base_url)
        }
    };
    if !valid {
        sink.push(config_error(
            CODE_BASE_URL,
            "client.baseUrl must match its source shape, and literal values must be absolute HTTP(S) URLs without credentials",
            Some(source),
            Some("/client/baseUrl"),
        ));
    }
}

fn is_valid_literal_base_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn validate_directory_overlaps(
    artifacts: &ArtifactStates,
    emit: &EmitConfig,
    source: &Path,
    sink: &mut DiagnosticSink,
) {
    let mut entries = [
        ("types", &artifacts.types),
        ("client", &artifacts.client),
        ("zod", &artifacts.zod),
        ("validators", &artifacts.validators),
        ("tanstack", &artifacts.tanstack),
        ("msw", &artifacts.msw),
    ]
    .into_iter()
    .filter(|(_, state)| state.enabled)
    .map(|(name, state)| (name, state.directory.as_str()))
    .collect::<Vec<_>>();
    if artifacts.client.enabled {
        entries.push(("emit.runtimeDirectory", emit.runtime_directory.as_str()));
    }

    for (index, (left_name, left_directory)) in entries.iter().enumerate() {
        for (right_name, right_directory) in entries.iter().skip(index + 1) {
            if directories_overlap(left_directory, right_directory) {
                sink.push(config_error(
                    CODE_ARTIFACT_DIRECTORY,
                    format!(
                        "enabled output directories '{left_name}' ({left_directory}) and '{right_name}' ({right_directory}) overlap"
                    ),
                    Some(source),
                    Some("/artifacts"),
                ));
            }
        }
    }
}

/// Whether two artifact directories are the same, or one is inside the other.
///
/// Compared case-insensitively because generated paths are: `register_path` folds case before
/// looking for collisions, so `Schemas` and `schemas` are one directory as far as emission — and as
/// far as a case-insensitive filesystem — is concerned.
fn directories_overlap(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    let left = Path::new(&left);
    let right = Path::new(&right);
    left.starts_with(right) || right.starts_with(left)
}

fn resolve_artifacts(
    raw: ArtifactsConfig,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> ArtifactStates {
    let types = resolve_artifact_setting(raw.types, true, "types", "types", source, sink);
    let client = resolve_artifact_setting(raw.client, false, "client", "client", source, sink);
    let zod = resolve_artifact_setting(raw.zod, false, "zod", "zod", source, sink);
    let validators = resolve_artifact_setting(
        raw.validators,
        false,
        "validators",
        "validators",
        source,
        sink,
    );
    let tanstack =
        resolve_artifact_setting(raw.tanstack, false, "tanstack", "tanstack", source, sink);
    let msw = resolve_artifact_setting(raw.msw, false, "msw", "msw", source, sink);
    let states = ArtifactStates {
        types,
        client,
        zod,
        validators,
        tanstack,
        msw,
    };

    // Every declared artifact now has an emitter, so this list is only the "at least one enabled"
    // check. It carried a `supported` column while a framework adapter was still stubbed out;
    // an artifact key that names nothing is refused by `deny_unknown_fields` on the selector
    // struct, which is the check that actually protects a user against a typo.
    let artifacts = [
        &states.types,
        &states.client,
        &states.zod,
        &states.validators,
        &states.tanstack,
        &states.msw,
    ];
    if !artifacts.iter().any(|state| state.enabled) {
        sink.push(config_error(
            CODE_NO_ARTIFACT,
            "at least one artifact must be enabled",
            Some(source),
            Some("/artifacts"),
        ));
    }
    // Handlers import the generated request and response types, so the types artifact is a real
    // prerequisite rather than a convention. It is stated here and never inferred: enabling msw
    // does not silently switch types on.
    if states.msw.enabled && !states.types.enabled {
        sink.push(config_error(
            CODE_MSW_REQUIRES_TYPES,
            "the msw artifact requires the types artifact to be enabled",
            Some(source),
            Some("/artifacts/msw"),
        ));
    }
    // Descriptors wrap the client's own `orThrow` surface and propagate its `CallArgs<S>`, so the
    // client is a real prerequisite rather than a convention. Without this the artifact would
    // resolve, emit nothing, and report nothing — the exact silent no-op the check exists to stop.
    if states.tanstack.enabled && !states.client.enabled {
        sink.push(config_error(
            CODE_TANSTACK_REQUIRES_CLIENT,
            "the tanstack artifact requires the client artifact to be enabled",
            Some(source),
            Some("/artifacts/tanstack"),
        ));
    }
    states
}

fn resolve_artifact_setting(
    setting: Option<ArtifactSetting>,
    default_enabled: bool,
    default_directory: &str,
    name: &str,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> ArtifactState {
    let (enabled, directory, disabled_option_block) = match setting {
        None => (default_enabled, default_directory.to_owned(), false),
        Some(ArtifactSetting::Enabled(enabled)) => (enabled, default_directory.to_owned(), false),
        Some(ArtifactSetting::Options(options)) => {
            let enabled = options.enabled.unwrap_or(true);
            let disabled = !enabled && options.directory.is_some();
            (
                enabled,
                options
                    .directory
                    .unwrap_or_else(|| default_directory.to_owned()),
                disabled,
            )
        }
    };
    if disabled_option_block {
        sink.push(config_error(
            CODE_DISABLED_ARTIFACT_OPTIONS,
            format!("disabled artifact '{name}' cannot specify directory options"),
            Some(source),
            Some("/artifacts"),
        ));
    }
    if !is_valid_directory(&directory) {
        sink.push(config_error(
            CODE_ARTIFACT_DIRECTORY,
            format!(
                "artifact '{name}' has invalid directory '{directory}': each segment must be a relative, non-empty run of letters, digits, '_' or '-'"
            ),
            Some(source),
            Some("/artifacts"),
        ));
    }
    ArtifactState {
        enabled,
        directory: normalize_directory(&directory),
    }
}

fn validate_naming(naming: &NamingConfig, source: &Path, sink: &mut DiagnosticSink) {
    if naming.type_case != "pascal" {
        sink.push(config_error(
            CODE_NAMING,
            "naming.typeCase must be 'pascal'",
            Some(source),
            Some("/naming/typeCase"),
        ));
    }
    if naming.property_case != "preserve" {
        sink.push(config_error(
            CODE_NAMING,
            "naming.propertyCase must be 'preserve'",
            Some(source),
            Some("/naming/propertyCase"),
        ));
    }
    if !naming.type_prefix.is_empty() && !is_ts_identifier(&naming.type_prefix) {
        sink.push(config_error(
            CODE_NAMING,
            "naming.typePrefix must be empty or a valid identifier prefix",
            Some(source),
            Some("/naming/typePrefix"),
        ));
    }
    if !naming
        .type_suffix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$')
    {
        sink.push(config_error(
            CODE_NAMING,
            "naming.typeSuffix must contain only identifier characters",
            Some(source),
            Some("/naming/typeSuffix"),
        ));
    }
    // pathSegments has no document to check keys against here (see NameOverrides' doc comment),
    // but values get the identical identifier validation schemas/operations values get, applied
    // eagerly since nothing downstream re-validates an unmatched key's value for us.
    for (key, value) in &naming.overrides.path_segments {
        if let Err(error) = crate::semantic::validate_final_identifier(value) {
            sink.push(config_error(
                CODE_NAMING,
                format!(
                    "naming.overrides.pathSegments value '{value}' is not a valid identifier: {error}"
                ),
                Some(source),
                Some(&format!(
                    "/naming/overrides/pathSegments/{}",
                    crate::semantic::escape_json_pointer_token(key)
                )),
            ));
        }
    }
}

fn validate_emit(emit: &EmitConfig, source: &Path, sink: &mut DiagnosticSink) {
    if !is_valid_directory(&emit.runtime_directory) {
        sink.push(config_error(
            CODE_EMIT,
            "emit.runtimeDirectory segments must each be a relative, non-empty run of letters, digits, '_' or '-'",
            Some(source),
            Some("/emit/runtimeDirectory"),
        ));
    }
    if emit.import_extension != ".js" && emit.import_extension != "none" {
        sink.push(config_error(
            CODE_EMIT,
            "emit.importExtension must be '.js' or 'none'",
            Some(source),
            Some("/emit/importExtension"),
        ));
    }
    if emit.format != "deterministic" {
        sink.push(config_error(
            CODE_EMIT,
            "emit.format must be 'deterministic'",
            Some(source),
            Some("/emit/format"),
        ));
    }
    for (index, line) in emit.banner.iter().enumerate() {
        let forbidden = line.contains('\0')
            || line.contains('\n')
            || line.contains('\r')
            || line.contains('\u{2028}')
            || line.contains('\u{2029}')
            || line.contains("sourceMappingURL=")
            || line.contains("Generated by Oasts");
        if forbidden {
            sink.push(config_error(
                CODE_EMIT,
                format!("emit.banner element {index} contains a forbidden sequence"),
                Some(source),
                Some("/emit/banner"),
            ));
        }
    }
}

fn resolve_local_paths(
    local: &LocalTrustConfig,
    config_dir: &Path,
    source: &Path,
    sink: &mut DiagnosticSink,
) -> Vec<PathBuf> {
    local
        .allow_paths
        .iter()
        .filter_map(|entry| {
            let path = Path::new(entry);
            if path.is_absolute() {
                sink.push(config_error(
                    CODE_TRUST_LIMITS,
                    format!("local.allowPaths entry '{entry}' must be relative"),
                    Some(source),
                    Some("/local/allowPaths"),
                ));
                None
            } else {
                Some(normalize_join(config_dir, path))
            }
        })
        .collect()
}

fn validate_limits(limits: &LimitsConfig, source: &Path, sink: &mut DiagnosticSink) {
    let ranges = [
        (
            "maxDocumentBytes",
            limits.max_document_bytes,
            1_024,
            1_073_741_824,
        ),
        (
            "maxTotalBytes",
            limits.max_total_bytes,
            1_024,
            4_294_967_296,
        ),
        ("maxDocuments", limits.max_documents, 1, 4_096),
        ("maxRefDepth", limits.max_ref_depth, 1, 1_024),
    ];
    for (name, value, minimum, maximum) in ranges {
        if !(minimum..=maximum).contains(&value) {
            sink.push(config_error(
                CODE_TRUST_LIMITS,
                format!("limits.{name} value {value} is outside {minimum}..={maximum}"),
                Some(source),
                Some("/limits"),
            ));
        }
    }
}

fn config_error(
    code: &'static str,
    message: impl Into<String>,
    source: Option<&Path>,
    pointer: Option<&str>,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::config(code, message);
    if let Some(source) = source {
        diagnostic = diagnostic.with_source(source.to_string_lossy());
    }
    if let Some(pointer) = pointer {
        diagnostic = diagnostic.with_json_pointer(pointer);
    }
    diagnostic
}

fn config_warning(
    code: &'static str,
    message: impl Into<String>,
    source: Option<&Path>,
    pointer: Option<&str>,
) -> Diagnostic {
    let mut diagnostic = config_error(code, message, source, pointer);
    diagnostic.severity = Severity::Warning;
    diagnostic
}

fn is_uri(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    !remainder.is_empty()
        && scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn is_ts_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(first, b'_' | b'$'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn is_valid_directory(value: &str) -> bool {
    let path = Path::new(value);
    // `is_absolute` answers for the host platform only, and a config is authored on one platform
    // and consumed on another; the leading-separator check makes the verdict the same everywhere.
    !path.is_absolute() && !value.starts_with(['/', '\\']) && {
        let normalized = normalize_directory(value);
        !normalized.is_empty() && normalized.split('/').all(is_valid_directory_segment)
    }
}

/// Directory segments are held to exactly the charset generated file names are.
///
/// The compiler already refuses to name a *file* anything outside `[A-Za-z0-9_-]`, and a directory
/// it has to place that file in has the same problems: a separator or drive letter is rejected by
/// the writer, a quote produces an unterminated import, a leading dot collides with the ownership
/// manifest, and a Windows device name is unopenable. Catching all of them here means one
/// `OASTS0102` naming the offending value instead of a later failure naming a path the user never
/// wrote.
fn is_valid_directory_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !crate::emit::is_reserved_device(segment)
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Reduces a configured directory to the one spelling everything downstream reads: `/`-separated,
/// with empty and `.` segments dropped. The overlap check compares these, emitters join onto them,
/// and the relative-import computation walks their segments — so `./a/` and `a` must not be able to
/// disagree about how deep the directory is. Absolute and `..` inputs are rejected by
/// [`is_valid_directory`] before this ever runs, so dropping segments here cannot escape the root.
fn normalize_directory(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for segment in value
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
    {
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(segment);
    }
    normalized
}

fn resolve_below(base: &Path, relative: &Path, allow_equal: bool) -> Result<PathBuf, String> {
    if relative.is_absolute() {
        return Err("path must be relative".to_owned());
    }
    let candidate = lexical_join_below(base, relative)
        .ok_or_else(|| "path escapes its allowed root".to_owned())?;
    if !allow_equal && candidate == base {
        return Err("path must be below, not equal to, its allowed root".to_owned());
    }

    if base.exists() {
        let canonical_base = canonicalize_result(fs::canonicalize(base), "allowed root")?;
        let existing_ancestor = nearest_existing_ancestor(&candidate)
            .expect("an existing base is always an ancestor of its lexical child");
        let canonical_ancestor =
            canonicalize_result(fs::canonicalize(&existing_ancestor), "path ancestor")?;
        if !canonical_ancestor.starts_with(&canonical_base) {
            return Err("path resolves through a symlink outside its allowed root".to_owned());
        }
        if candidate.exists() {
            return canonicalize_result(fs::canonicalize(&candidate), "path");
        }
    }
    Ok(candidate)
}

fn canonicalize_result(result: io::Result<PathBuf>, context: &str) -> Result<PathBuf, String> {
    match result {
        Ok(path) => Ok(path),
        Err(error) => Err(format!("failed to canonicalize {context}: {error}")),
    }
}

fn lexical_join_below(base: &Path, relative: &Path) -> Option<PathBuf> {
    let mut result = base.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => result.push(part),
            Component::ParentDir => {
                if result == base || !result.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    result.starts_with(base).then_some(result)
}

fn normalize_join(base: &Path, relative: &Path) -> PathBuf {
    let mut result = base.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => result.push(part),
            Component::ParentDir => {
                result.pop();
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    result
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut candidate = path.to_path_buf();
    loop {
        if candidate.exists() {
            return Some(candidate);
        }
        if !candidate.pop() {
            return None;
        }
    }
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use crate::filter::{CODE_FILTER_PATTERN, PatternKind};

    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::*;
    use crate::diag::Category;

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "oasts-config-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self { path }
        }

        fn new_relative() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = PathBuf::from("../../target").join(format!(
                "oasts-config-relative-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("relative test directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("test config should be written");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("test directory should be removed");
        }
    }

    fn valid_yaml() -> &'static str {
        "schemaVersion: 1\ninput:\n  path: openapi.yaml\noutput: generated\n"
    }

    fn valid_json_value() -> Value {
        json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated"
        })
    }

    fn valid_client_json_value() -> Value {
        json!({
            "schemaVersion": 1,
            "input": { "path": "openapi.yaml" },
            "output": "generated",
            "artifacts": { "types": true, "client": true },
            "client": { "authEnforcement": "types" },
            "validation": { "engine": "off", "unchecked": "allow" }
        })
    }

    fn load_yaml(contents: &str) -> Result<ResolvedConfig, Vec<Diagnostic>> {
        let directory = TestDirectory::new();
        let path = directory.write("config.yaml", contents);
        load_config(Some(&path), directory.path())
    }

    fn load_json(value: &Value) -> Result<ResolvedConfig, Vec<Diagnostic>> {
        let directory = TestDirectory::new();
        let contents = serde_json::to_string(value).expect("test JSON should serialize");
        let path = directory.write("config.json", &contents);
        load_config(Some(&path), directory.path())
    }

    fn assert_code(
        result: Result<ResolvedConfig, Vec<Diagnostic>>,
        code: &'static str,
    ) -> Vec<Diagnostic> {
        let diagnostics = result.expect_err("config should be rejected");
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .expect("expected config diagnostic code");
        assert_eq!(diagnostic.category, Category::Config);
        assert_eq!(diagnostic.category.exit_code(), 2);
        diagnostics
    }

    fn assert_discovery_code(result: Result<PathBuf, Diagnostic>, code: &'static str) {
        let diagnostic = result.expect_err("discovery should fail");
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.category, Category::Config);
        assert_eq!(diagnostic.category.exit_code(), 2);
    }

    #[test]
    fn default_types_only_config_resolves_absolute_paths_and_defaults() {
        let directory = TestDirectory::new();
        let path = directory.write("config.yaml", valid_yaml());

        let resolved =
            load_config(Some(&path), directory.path()).expect("valid config should resolve");

        assert_eq!(resolved.schema_version, 1);
        assert_eq!(resolved.config_dir, directory.path());
        assert_eq!(resolved.workspace_root, directory.path());
        assert_eq!(resolved.input, directory.path().join("openapi.yaml"));
        assert_eq!(resolved.output, directory.path().join("generated"));
        assert_eq!(resolved.namespace, "api");
        assert!(resolved.artifacts.types.enabled);
        assert_eq!(resolved.artifacts.types.directory, "types");
        assert!(!resolved.artifacts.client.enabled);
        assert_eq!(resolved.emit.runtime_directory, "runtime");
        assert_eq!(resolved.limits, LimitsConfig::default());
        assert_eq!(resolved.compat, CompatConfig::default());
        assert_eq!(
            resolved.compat.deep_object_encoding,
            DeepObjectEncoding::Strict
        );
    }

    #[test]
    fn compat_section_parses_and_rejects_unknown_shapes() {
        let mut value = valid_json_value();
        value["compat"] = json!({ "deepObjectEncoding": "extended" });
        let resolved = load_json(&value).expect("extended deepObject should resolve");
        assert_eq!(
            resolved.compat.deep_object_encoding,
            DeepObjectEncoding::Extended
        );

        // An empty section is the strict default, so opting into the block costs nothing.
        value["compat"] = json!({});
        let resolved = load_json(&value).expect("empty compat should resolve");
        assert_eq!(
            resolved.compat.deep_object_encoding,
            DeepObjectEncoding::Strict
        );

        value["compat"] = json!({ "deepObjectEncodings": "extended" });
        assert_code(load_json(&value), CODE_PARSE);

        value["compat"] = json!({ "deepObjectEncoding": "loose" });
        assert_code(load_json(&value), CODE_PARSE);
    }

    #[test]
    fn load_config_from_json_matches_file_based_loading() {
        let directory = TestDirectory::new();
        directory.write("openapi.yaml", "openapi: 3.1.0\npaths: {}\n");
        let json =
            br#"{"schemaVersion":1,"input":{"path":"./openapi.yaml"},"output":"./generated"}"#;
        let file = directory.write("oasts.json", std::str::from_utf8(json).expect("UTF-8"));

        let from_bytes =
            load_config_from_json(&file, json).expect("JSON bytes config should resolve");
        let from_file =
            load_config(Some(&file), directory.path()).expect("file config should resolve");
        assert_eq!(from_bytes.input, from_file.input);
        assert_eq!(from_bytes.output, from_file.output);
        assert_eq!(from_bytes.namespace, from_file.namespace);
        assert_eq!(from_bytes.config_dir, from_file.config_dir);

        let relative_temp = tempfile::tempdir_in("../../target").expect("relative tempdir");
        fs::write(
            relative_temp.path().join("openapi.yaml"),
            "openapi: 3.1.0\npaths: {}\n",
        )
        .expect("relative OpenAPI file");
        let relative = PathBuf::from("../../target")
            .join(relative_temp.path().file_name().expect("tempdir name"))
            .join("oasts.json");
        let resolved = load_config_from_json(&relative, json).expect("relative path resolves");
        assert!(resolved.input.is_absolute());
    }

    #[test]
    fn load_config_from_json_reports_validation_twins_and_parse_errors() {
        let directory = TestDirectory::new();
        directory.write("openapi.yaml", "openapi: 3.1.0\npaths: {}\n");
        let invalid =
            br#"{"schemaVersion":2,"input":{"path":"./openapi.yaml"},"output":"./generated"}"#;
        let file = directory.write("oasts.json", std::str::from_utf8(invalid).expect("UTF-8"));

        let from_bytes =
            load_config_from_json(&file, invalid).expect_err("schemaVersion 2 is invalid");
        let from_file = load_config(Some(&file), directory.path())
            .expect_err("file twin reports the same failure");
        let codes = |diagnostics: &[Diagnostic]| {
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code)
                .collect::<Vec<_>>()
        };
        assert_eq!(codes(&from_bytes), codes(&from_file));
        assert!(codes(&from_bytes).contains(&CODE_SCHEMA_VERSION));

        let malformed = load_config_from_json(&file, b"{").expect_err("malformed JSON");
        assert_eq!(malformed.len(), 1);
        assert_eq!(malformed[0].code, CODE_PARSE);
        assert!(malformed[0].line.is_some());
        assert!(malformed[0].col.is_some());
    }

    #[test]
    fn discovery_rejects_zero_candidates() {
        let directory = TestDirectory::new();
        assert_discovery_code(discover(directory.path(), None), CODE_DISCOVERY);
    }

    #[test]
    fn discovery_rejects_two_candidates() {
        let directory = TestDirectory::new();
        directory.write("oasts.yaml", valid_yaml());
        directory.write("oasts.json", "{}");
        assert_discovery_code(discover(directory.path(), None), CODE_DISCOVERY);
    }

    #[test]
    fn discovery_ignores_yml_alias() {
        let directory = TestDirectory::new();
        directory.write("oasts.yml", valid_yaml());
        let yaml = directory.write("oasts.yaml", valid_yaml());
        assert_eq!(
            discover(directory.path(), None).expect("yaml candidate should be found"),
            yaml
        );
    }

    #[test]
    fn discover_candidate_reports_script_and_data_candidates() {
        let directory = TestDirectory::new();
        let script = directory.write("oasts.config.ts", "export default {};");
        assert_eq!(
            discover_candidate(directory.path(), None).expect("script candidate"),
            DiscoveredConfig {
                path: script.clone(),
                is_script: true
            }
        );
        assert_eq!(
            discover_candidate(directory.path(), Some(&script)).expect("explicit script candidate"),
            DiscoveredConfig {
                path: script,
                is_script: true
            }
        );

        let data = TestDirectory::new();
        let yaml = data.write("oasts.yaml", valid_yaml());
        assert_eq!(
            discover_candidate(data.path(), None).expect("data candidate"),
            DiscoveredConfig {
                path: yaml,
                is_script: false
            }
        );

        let empty = TestDirectory::new();
        assert_discovery_code(
            discover_candidate(empty.path(), None).map(|candidate| candidate.path),
            CODE_DISCOVERY,
        );
        let ambiguous = TestDirectory::new();
        ambiguous.write("oasts.yaml", valid_yaml());
        ambiguous.write("oasts.json", "{}");
        assert_discovery_code(
            discover_candidate(ambiguous.path(), None).map(|candidate| candidate.path),
            CODE_DISCOVERY,
        );
    }

    #[test]
    fn discovery_reports_script_config_as_unsupported() {
        let directory = TestDirectory::new();
        directory.write("oasts.config.ts", "export default {};");
        assert_discovery_code(
            discover(directory.path(), None),
            CODE_SCRIPT_CONFIG_UNSUPPORTED,
        );
    }

    #[test]
    fn explicit_script_config_is_also_unsupported() {
        let directory = TestDirectory::new();
        let script = directory.write("custom.mjs", "export default {};");
        assert_discovery_code(
            discover(directory.path(), Some(&script)),
            CODE_SCRIPT_CONFIG_UNSUPPORTED,
        );
    }

    #[test]
    fn relative_discovery_is_absolutized_before_loading() {
        let directory = TestDirectory::new_relative();
        directory.write("oasts.yaml", valid_yaml());

        let resolved = load_config(None, directory.path()).expect("relative config should load");
        assert!(resolved.config_path.is_absolute());
    }

    #[test]
    fn current_directory_failure_is_a_config_io_diagnostic() {
        let error = absolutize_config_path(
            PathBuf::from("config.yaml"),
            Err(io::Error::other("current directory unavailable")),
        )
        .expect_err("current directory failure should be reported");
        assert_eq!(error[0].code, CODE_IO);
        assert!(error[0].message.contains("current directory unavailable"));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_config_is_a_config_io_diagnostic() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.write("config.yaml", valid_yaml());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
            .expect("config permissions should change");
        let result = load_config(Some(&path), directory.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("config permissions should be restored");
        assert_code(result, CODE_IO);
    }

    #[test]
    fn explicit_yml_extension_is_rejected() {
        let directory = TestDirectory::new();
        let path = directory.write("config.yml", valid_yaml());
        assert_discovery_code(discover(directory.path(), Some(&path)), CODE_DISCOVERY);
    }

    #[test]
    fn explicit_missing_config_is_rejected() {
        let directory = TestDirectory::new();
        let path = directory.path().join("missing.json");
        assert_discovery_code(discover(directory.path(), Some(&path)), CODE_DISCOVERY);
    }

    #[test]
    fn yaml_duplicate_root_key_is_rejected_with_location() {
        let diagnostics = assert_code(
            load_yaml(
                "schemaVersion: 1\nschemaVersion: 1\ninput: { path: openapi.yaml }\noutput: generated\n",
            ),
            CODE_PARSE,
        );
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_PARSE)
            .expect("parse diagnostic should exist");
        assert!(diagnostic.line.is_some());
        assert!(diagnostic.col.is_some());
    }

    #[test]
    fn yaml_duplicate_nested_key_is_rejected() {
        assert_code(
            load_yaml(
                "schemaVersion: 1\ninput: { path: openapi.yaml }\noutput: generated\ntypes:\n  readonly: true\n  readonly: false\n",
            ),
            CODE_PARSE,
        );
    }

    #[test]
    fn yaml_core_schema_leaves_off_yes_and_no_as_strings() {
        let value =
            parse_yaml_value("values: [off, yes, no]").expect("core-schema strings should parse");
        assert_eq!(value, json!({ "values": ["off", "yes", "no"] }));
    }

    #[test]
    fn yaml_quoted_false_stays_a_string() {
        let value = parse_yaml_value("value: \"false\"").expect("quoted string should parse");
        assert_eq!(value, json!({ "value": "false" }));
    }

    #[test]
    fn yaml_core_schema_resolves_supported_numbers_and_literals() {
        let value = parse_yaml_value("values: [0o10, 0x10, 12, 1.5, 1e2, null, TRUE]")
            .expect("core-schema scalars should parse");
        assert_eq!(
            value,
            json!({ "values": [8, 16, 12, 1.5, 100.0, null, true] })
        );
    }

    #[test]
    fn yaml_core_schema_does_not_resolve_non_matching_number_spellings() {
        let value = parse_yaml_value("values: [1_0, -0o7, +0xA, +.nan, 12:34]")
            .expect("non-matching scalars should remain strings");
        assert_eq!(
            value,
            json!({ "values": ["1_0", "-0o7", "+0xA", "+.nan", "12:34"] })
        );
    }

    #[test]
    fn yaml_unknown_key_is_rejected() {
        assert_code(
            load_yaml(&format!("{}unknown: true\n", valid_yaml())),
            CODE_PARSE,
        );

        assert_code(
            load_yaml(
                "schemaVersion: 1\ninput: { path: openapi.yaml, unknown: true }\noutput: generated\n",
            ),
            CODE_PARSE,
        );
    }

    #[test]
    fn yaml_string_is_not_coerced_to_boolean() {
        assert_code(
            load_yaml(&format!("{}types:\n  readonly: \"false\"\n", valid_yaml())),
            CODE_PARSE,
        );
    }

    #[test]
    fn yaml_plain_off_is_not_coerced_to_boolean() {
        assert_code(
            load_yaml(&format!("{}types:\n  readonly: off\n", valid_yaml())),
            CODE_PARSE,
        );
    }

    #[test]
    fn yaml_syntax_error_has_a_location() {
        let diagnostics = assert_code(load_yaml("schemaVersion: [\n"), CODE_PARSE);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_PARSE)
            .expect("parse diagnostic should exist");
        assert!(diagnostic.line.is_some());
        assert!(diagnostic.col.is_some());
    }

    #[test]
    fn yaml_anchors_are_rejected_clearly() {
        assert_code(
            load_yaml(
                "schemaVersion: 1\ninput: &input { path: openapi.yaml }\noutput: generated\n",
            ),
            CODE_PARSE,
        );
    }

    #[test]
    fn missing_schema_version_is_rule_4() {
        assert_code(
            load_yaml("input: { path: openapi.yaml }\noutput: generated\n"),
            CODE_SCHEMA_VERSION,
        );
    }

    #[test]
    fn unsupported_schema_version_is_rule_4() {
        let mut value = valid_json_value();
        value["schemaVersion"] = json!(2);
        assert_code(load_json(&value), CODE_SCHEMA_VERSION);
    }

    #[test]
    fn non_integer_schema_version_is_rule_4() {
        let mut value = valid_json_value();
        value["schemaVersion"] = json!(1.0);
        assert_code(load_json(&value), CODE_SCHEMA_VERSION);
    }

    #[test]
    fn string_schema_version_is_a_wrong_type() {
        let mut value = valid_json_value();
        value["schemaVersion"] = json!("1");
        assert_code(load_json(&value), CODE_PARSE);
    }

    #[test]
    fn schema_uri_is_validated() {
        let mut valid = valid_json_value();
        valid["$schema"] = json!("https://eve0415.github.io/oasts/schema/config-v1.json");
        load_json(&valid).expect("URI schema metadata should be accepted");

        valid["$schema"] = json!("not a uri");
        assert_code(load_json(&valid), CODE_SCHEMA_URI);
    }

    #[test]
    fn workspace_shape_reports_named_unsupported_feature() {
        let value = json!({ "schemaVersion": 1, "specs": {} });
        let diagnostics = assert_code(load_json(&value), CODE_WORKSPACE_UNSUPPORTED);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == CODE_SINGLE_SHAPE)
                .count(),
            0
        );
    }

    #[test]
    fn missing_single_spec_fields_are_rule_6() {
        assert_code(load_yaml("schemaVersion: 1\n"), CODE_SINGLE_SHAPE);
    }

    #[test]
    fn input_with_both_selectors_is_rule_7() {
        assert_code(
            load_yaml(
                "schemaVersion: 1\ninput: { path: openapi.yaml, url: https://example.com/openapi.yaml }\noutput: generated\n",
            ),
            CODE_INPUT_SHAPE,
        );
    }

    #[test]
    fn input_with_neither_selector_is_rule_7() {
        assert_code(
            load_yaml("schemaVersion: 1\ninput: {}\noutput: generated\n"),
            CODE_INPUT_SHAPE,
        );
    }

    #[test]
    fn remote_input_is_deferred_to_the_document_loader() {
        let resolved = load_yaml(
            "schemaVersion: 1\ninput: { url: https://example.com/openapi.yaml }\noutput: generated\n",
        )
        .expect("URL input should resolve for the document loader");
        assert_eq!(
            resolved.input,
            PathBuf::from("https://example.com/openapi.yaml")
        );
    }

    #[test]
    fn input_url_must_be_absolute() {
        assert_code(
            load_yaml("schemaVersion: 1\ninput: { url: openapi.yaml }\noutput: generated\n"),
            CODE_INPUT_PATH,
        );
    }

    #[test]
    fn local_input_cannot_escape_workspace_root() {
        assert_code(
            load_yaml("schemaVersion: 1\ninput: { path: ../openapi.yaml }\noutput: generated\n"),
            CODE_INPUT_PATH,
        );
    }

    #[test]
    fn workspace_root_must_be_relative_and_bounded() {
        let mut absolute = valid_json_value();
        absolute["workspaceRoot"] = json!("/tmp");
        assert_code(load_json(&absolute), CODE_WORKSPACE_ROOT);

        let mut escaping = valid_json_value();
        escaping["workspaceRoot"] = json!("../outside");
        assert_code(load_json(&escaping), CODE_WORKSPACE_ROOT);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_root_cannot_escape_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let outside = TestDirectory::new();
        symlink(outside.path(), directory.path().join("escape"))
            .expect("test symlink should be created");
        let path = directory.write(
            "config.yaml",
            "schemaVersion: 1\nworkspaceRoot: escape\ninput: { path: openapi.yaml }\noutput: generated\n",
        );
        assert_code(
            load_config(Some(&path), directory.path()),
            CODE_WORKSPACE_ROOT,
        );
    }

    #[test]
    fn relative_workspace_root_resolves_successfully() {
        let directory = TestDirectory::new();
        fs::create_dir(directory.path().join("workspace"))
            .expect("workspace directory should be created");
        let path = directory.write(
            "config.yaml",
            "schemaVersion: 1\nworkspaceRoot: workspace\ninput: { path: openapi.yaml }\noutput: generated\n",
        );
        let resolved =
            load_config(Some(&path), directory.path()).expect("workspace should resolve");
        assert_eq!(resolved.workspace_root, directory.path().join("workspace"));
        assert_eq!(
            resolved.output,
            directory.path().join("workspace/generated")
        );
    }

    #[test]
    fn output_must_be_relative_below_workspace_root() {
        for output in ["/tmp/generated", "../generated", "."] {
            let mut value = valid_json_value();
            value["output"] = json!(output);
            assert_code(load_json(&value), CODE_OUTPUT);
        }
    }

    #[test]
    fn typescript_tsconfig_takes_two_words_or_a_contained_path() {
        let base = || {
            json!({
                "schemaVersion": 1,
                "input": { "path": "./openapi.json" },
                "output": "./generated",
                "artifacts": { "types": true }
            })
        };
        // Absent and the two words.
        assert_eq!(
            load_json(&base()).expect("resolves").tsconfig,
            TsconfigSource::Auto
        );
        for (word, expected) in [("auto", TsconfigSource::Auto), ("off", TsconfigSource::Off)] {
            let mut value = base();
            value["typescript"] = json!({ "tsconfig": word });
            assert_eq!(load_json(&value).expect("resolves").tsconfig, expected);
        }
        // A path resolves below the workspace root like every other path in this config.
        let mut value = base();
        value["typescript"] = json!({ "tsconfig": "./tsconfig.build.json" });
        assert!(matches!(
            load_json(&value).expect("resolves").tsconfig,
            TsconfigSource::Path(path) if path.ends_with("tsconfig.build.json")
        ));
        // And one that escapes it is refused by name.
        let mut value = base();
        value["typescript"] = json!({ "tsconfig": "../outside/tsconfig.json" });
        assert_code(load_json(&value), CODE_TYPESCRIPT);
    }

    #[cfg(unix)]
    #[test]
    fn output_cannot_escape_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let outside = TestDirectory::new();
        symlink(outside.path(), directory.path().join("generated"))
            .expect("test symlink should be created");
        let path = directory.write("config.yaml", valid_yaml());
        assert_code(load_config(Some(&path), directory.path()), CODE_OUTPUT);
    }

    #[test]
    fn namespace_must_be_a_ts_identifier() {
        let mut invalid = valid_json_value();
        invalid["namespace"] = json!("1-invalid");
        assert_code(load_json(&invalid), CODE_NAMESPACE);

        let mut valid = valid_json_value();
        valid["namespace"] = json!("$api_2");
        load_json(&valid).expect("valid namespace should resolve");
    }

    #[test]
    fn artifact_defaults_are_types_only() {
        let resolved = load_yaml(valid_yaml()).expect("default artifacts should resolve");
        assert!(resolved.artifacts.types.enabled);
        assert!(!resolved.artifacts.client.enabled);
        assert!(!resolved.artifacts.zod.enabled);
        assert!(!resolved.artifacts.validators.enabled);
        assert!(!resolved.artifacts.tanstack.enabled);
        assert!(!resolved.artifacts.msw.enabled);
    }

    #[test]
    fn an_unknown_artifact_key_is_rejected() {
        // Every declared artifact now has an emitter, so nothing reaches the unsupported-artifact
        // check any more. The mechanism still has to hold: an artifact key the schema does not
        // declare is refused rather than silently ignored, which is what would let a typo read as
        // "that artifact is simply off".
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "solid": true });
        let error = load_json(&value).expect_err("unknown artifact key should be rejected");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.message.contains("solid")),
            "{error:#?}"
        );
    }

    #[test]
    fn every_declared_artifact_is_supported() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({
            "types": true, "client": true, "zod": true,
            "validators": true, "tanstack": true, "msw": true,
        });
        value["validation"] = json!({ "engine": "off", "unchecked": "allow" });
        let resolved = load_json(&value).expect("every artifact should resolve");
        assert!(resolved.artifacts.tanstack.enabled);
        assert_eq!(resolved.artifacts.tanstack.directory, "tanstack");
    }

    #[test]
    fn tanstack_artifact_requires_client() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "tanstack": true });
        let diagnostics = assert_code(load_json(&value), CODE_TANSTACK_REQUIRES_CLIENT);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_TANSTACK_REQUIRES_CLIENT
                && diagnostic.json_pointer.as_deref() == Some("/artifacts/tanstack")
        }));
    }

    #[test]
    fn msw_artifact_resolves_alongside_types() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "msw": true });
        let resolved = load_json(&value).expect("types + msw config should resolve");
        assert!(resolved.artifacts.msw.enabled);
        assert_eq!(resolved.artifacts.msw.directory, "msw");
    }

    #[test]
    fn msw_artifact_requires_types() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": false, "msw": true });
        let diagnostics = assert_code(load_json(&value), CODE_MSW_REQUIRES_TYPES);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_MSW_REQUIRES_TYPES
                && diagnostic.json_pointer.as_deref() == Some("/artifacts/msw")
        }));
    }

    #[test]
    fn validators_artifact_resolves_standalone_and_with_types() {
        let mut standalone = valid_json_value();
        standalone["artifacts"] = json!({ "types": false, "validators": true });
        let resolved = load_json(&standalone).expect("validators-only config should resolve");
        assert!(resolved.artifacts.validators.enabled);
        assert!(!resolved.artifacts.types.enabled);
        assert_eq!(resolved.artifacts.validators.directory, "validators");

        let mut with_types = valid_json_value();
        with_types["artifacts"] = json!({ "types": true, "validators": true });
        let resolved = load_json(&with_types).expect("types+validators config should resolve");
        assert!(resolved.artifacts.types.enabled);
        assert!(resolved.artifacts.validators.enabled);
    }

    #[test]
    fn zod_artifact_resolves_standalone_and_with_types() {
        let mut standalone = valid_json_value();
        standalone["artifacts"] = json!({ "types": false, "zod": true });
        let resolved = load_json(&standalone).expect("zod-only config should resolve");
        assert!(resolved.artifacts.zod.enabled);
        assert!(!resolved.artifacts.types.enabled);
        assert_eq!(resolved.artifacts.zod.directory, "zod");

        let mut with_types = valid_json_value();
        with_types["artifacts"] = json!({ "types": true, "zod": true });
        let resolved = load_json(&with_types).expect("types+zod config should resolve");
        assert!(resolved.artifacts.types.enabled);
        assert!(resolved.artifacts.zod.enabled);
    }

    #[test]
    fn zod_flavor_defaults_to_classic_and_accepts_mini() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "zod": true });
        let resolved = load_json(&value).expect("zod without options should resolve");
        assert_eq!(resolved.zod.flavor, ZodFlavor::Classic);

        value["zod"] = json!({ "flavor": "mini" });
        let resolved = load_json(&value).expect("zod mini should resolve");
        assert_eq!(resolved.zod.flavor, ZodFlavor::Mini);
    }

    #[test]
    fn zod_options_require_the_zod_artifact() {
        // The block only configures the artifact's own output, so naming a flavor while the
        // artifact is off asks for nothing — say so rather than emitting types under a setting the
        // reader believes took effect.
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "zod": false });
        value["zod"] = json!({ "flavor": "mini" });
        let diagnostics = load_json(&value).expect_err("zod options without the artifact");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_DISABLED_OPTIONS),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn zod_artifact_does_not_unlock_the_zod_validation_engine() {
        // Enabling the standalone artifact must not imply the client binding: `validation.engine:
        // zod` stays unsupported until the client seam lands, and a zod artifact without a client
        // leaves validation untouched.
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "zod": true });
        let resolved = load_json(&value).expect("zod without validation should resolve");
        assert!(resolved.validation.is_none());
    }

    #[test]
    fn validators_artifact_does_not_require_generated_validation_engine() {
        // The standalone validators artifact must not drag in the client-binding validation.engine
        // unlock: enabling it without a client leaves validation untouched and still resolves.
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": true, "validators": true });
        let resolved = load_json(&value).expect("validators without validation should resolve");
        assert!(resolved.validation.is_none());
    }

    #[test]
    fn artifact_selector_rejects_string_coercion() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": "true" });
        assert_code(load_json(&value), CODE_PARSE);
    }

    #[test]
    fn disabling_every_artifact_is_rule_10() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": false });
        assert_code(load_json(&value), CODE_NO_ARTIFACT);
    }

    #[test]
    fn disabled_artifact_directory_options_are_rule_10() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({
            "types": { "enabled": false, "directory": "model" }
        });
        assert_code(load_json(&value), CODE_DISABLED_ARTIFACT_OPTIONS);
    }

    #[test]
    fn artifact_directories_are_validated() {
        // Each of these fails somewhere downstream if it gets through: the writer rejects a
        // separator or drive letter, a quote produces an unterminated import, a leading dot
        // collides with the ownership manifest, and a device name is unopenable on Windows.
        for directory in [
            "",
            ".",
            "./",
            "//",
            "/absolute",
            "\\unc",
            "../outside",
            "a/../b",
            "model\\types",
            "sha\"red",
            ".oasts-manifest.json",
            "c:",
            "aux",
            "com1",
            "shared model",
        ] {
            let mut value = valid_json_value();
            value["artifacts"] = json!({ "types": { "directory": directory } });
            assert_code(load_json(&value), CODE_ARTIFACT_DIRECTORY);
        }

        let mut valid = valid_json_value();
        valid["artifacts"] = json!({ "types": { "directory": "model/types" } });
        let resolved = load_json(&valid).expect("nested artifact directory should resolve");
        assert_eq!(resolved.artifacts.types.directory, "model/types");
    }

    #[test]
    fn directories_that_differ_only_in_case_are_one_directory() {
        // Generated paths are compared case-folded, and so are they: two artifacts here would
        // collide at emission, which is late and names a path the user never wrote.
        let mut value = valid_json_value();
        value["artifacts"] = json!({
            "types": true,
            "validators": { "directory": "Schemas" },
            "zod": { "directory": "schemas" },
        });
        assert_code(load_json(&value), CODE_ARTIFACT_DIRECTORY);
    }

    #[test]
    fn configured_directories_resolve_to_one_normalized_spelling() {
        // Emitters count these segments to build relative imports, so two spellings of the same
        // directory must not reach them as different depths.
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": { "directory": "./model//types/" } });
        value["emit"] = json!({ "runtimeDirectory": "./kernel/" });
        let resolved = load_json(&value).expect("redundant separators should resolve");
        assert_eq!(resolved.artifacts.types.directory, "model/types");
        assert_eq!(resolved.emit.runtime_directory, "kernel");
    }

    #[test]
    fn client_and_validation_blocks_deserialize_typed_domains() {
        for (key, values) in [
            ("credentials", &["omit", "same-origin", "include"] as &[_]),
            (
                "cache",
                &[
                    "default",
                    "no-store",
                    "reload",
                    "no-cache",
                    "force-cache",
                    "only-if-cached",
                ],
            ),
            ("redirect", &["follow", "error", "manual"]),
            (
                "referrerPolicy",
                &[
                    "no-referrer",
                    "no-referrer-when-downgrade",
                    "same-origin",
                    "origin",
                    "strict-origin",
                    "origin-when-cross-origin",
                    "strict-origin-when-cross-origin",
                    "unsafe-url",
                ],
            ),
            ("mode", &["cors", "no-cors", "same-origin"]),
        ] {
            for value in values {
                serde_json::from_value::<FetchDefaults>(json!({ (key): value }))
                    .expect("standard Fetch value should deserialize");
            }
        }

        let raw = serde_json::from_value::<RawConfig>(json!({
            "schemaVersion": 1,
            "client": {
                "transport": "fetch",
                "authEnforcement": "runtime",
                "aggregate": true,
                "baseUrl": { "source": "server", "index": 2 },
                "fetchOptions": { "keepalive": true }
            },
            "validation": {
                "engine": "generated",
                "request": true,
                "response": true,
                "unchecked": "error"
            }
        }))
        .expect("typed client and validation blocks should deserialize");
        let client = raw.client.expect("client block");
        assert_eq!(client.transport, Some(ClientTransport::Fetch));
        assert_eq!(client.auth_enforcement, Some(AuthEnforcement::Runtime));
        assert_eq!(
            client.base_url,
            Some(BaseUrlConfig {
                source: BaseUrlSource::Server,
                index: Some(2),
                value: None,
            })
        );
        assert_eq!(
            raw.validation.and_then(|validation| validation.engine),
            Some(ValidationEngine::Generated)
        );
    }

    #[test]
    fn client_and_validation_blocks_reject_unknown_invalid_and_null_values() {
        for value in [
            json!({ "client": { "fetchOptions": { "method": "GET" } } }),
            json!({ "client": { "fetchOptions": { "mode": "navigate" } } }),
            json!({ "client": { "transport": "axios" } }),
            json!({ "client": { "aggregate": null } }),
            json!({ "validation": { "engine": "valibot" } }),
        ] {
            serde_json::from_value::<RawConfig>(value)
                .expect_err("invalid typed config value should be rejected");
        }
    }

    #[test]
    fn resolved_client_and_validation_defaults_are_typed() {
        let client = RawClient::default();
        let resolved = resolve_client_config(Some(&client), true).expect("client config");
        assert_eq!(resolved.auth_enforcement, AuthEnforcement::Types);
        assert!(!resolved.aggregate);
        assert_eq!(resolved.base_url, ResolvedBaseUrl::Runtime);
        assert_eq!(resolved.fetch_options, FetchDefaults::default());
        assert!(resolve_client_config(Some(&client), false).is_none());
        let absent = resolve_client_config(None, true).expect("defaulted client config");
        assert_eq!(absent.auth_enforcement, AuthEnforcement::Types);
        let explicit = RawClient {
            auth_enforcement: Some(AuthEnforcement::Runtime),
            ..RawClient::default()
        };
        let resolved_explicit =
            resolve_client_config(Some(&explicit), true).expect("client config");
        assert_eq!(resolved_explicit.auth_enforcement, AuthEnforcement::Runtime);

        let validation = RawValidation {
            engine: Some(ValidationEngine::Off),
            ..RawValidation::default()
        };
        assert_eq!(
            resolve_validation_config(Some(&validation), true),
            Some(ValidationConfig {
                engine: ValidationEngine::Off,
                request: false,
                response: false,
                unchecked: UncheckedPolicy::Warn,
            })
        );
        assert!(resolve_validation_config(Some(&validation), false).is_none());
        assert!(resolve_validation_config(None, true).is_none());
    }

    #[test]
    fn client_block_is_rule_12_in_types_only_build() {
        let mut value = valid_json_value();
        value["client"] = json!({});
        let diagnostics = assert_code(load_json(&value), CODE_DISABLED_OPTIONS);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.message == "client options are invalid while the client artifact is disabled"
        }));

        value["client"] = json!({
            "baseUrl": { "source": "runtime", "value": "https://example.com" }
        });
        let diagnostics = assert_code(load_json(&value), CODE_DISABLED_OPTIONS);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_BASE_URL)
        );
    }

    #[test]
    fn validation_block_without_client_is_rule_16() {
        let mut value = valid_json_value();
        value["validation"] = json!({});
        assert_code(load_json(&value), CODE_VALIDATION_WITHOUT_CLIENT);
    }

    #[test]
    fn types_options_with_disabled_types_are_rule_12() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": false });
        value["types"] = json!({});
        assert_code(load_json(&value), CODE_DISABLED_OPTIONS);
    }

    #[test]
    fn object_artifact_selector_defaults_to_enabled() {
        let mut value = valid_json_value();
        value["artifacts"] = json!({ "types": { "directory": "model" } });
        let resolved = load_json(&value).expect("object selector should default to enabled");
        assert!(resolved.artifacts.types.enabled);
        assert_eq!(resolved.artifacts.types.directory, "model");
    }

    #[test]
    fn minimal_client_config_resolves_typed_defaults() {
        let resolved =
            load_json(&valid_client_json_value()).expect("minimal client config should resolve");
        assert!(resolved.diagnostics.is_empty());
        assert!(resolved.artifacts.client.enabled);
        assert_eq!(
            resolved.client,
            Some(ClientConfig {
                auth_enforcement: AuthEnforcement::Types,
                aggregate: false,
                base_url: ResolvedBaseUrl::Runtime,
                fetch_options: FetchDefaults::default(),
            })
        );
        assert_eq!(
            resolved.validation,
            Some(ValidationConfig {
                engine: ValidationEngine::Off,
                request: false,
                response: false,
                unchecked: UncheckedPolicy::Allow,
            })
        );
    }

    #[test]
    fn client_requires_types_as_rule_11() {
        let mut value = valid_client_json_value();
        value["artifacts"]["types"] = json!(false);
        let diagnostics = assert_code(load_json(&value), CODE_CLIENT_REQUIRES_TYPES);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("client artifact requires the types artifact")
        }));
    }

    #[test]
    fn client_requires_validation_object_and_engine_as_rule_15() {
        let mut missing_validation = valid_client_json_value();
        missing_validation
            .as_object_mut()
            .expect("config object")
            .remove("validation");
        assert_code(load_json(&missing_validation), CODE_VALIDATION_REQUIRED);

        let mut missing_engine = valid_client_json_value();
        missing_engine["validation"] = json!({ "unchecked": "allow" });
        assert_code(load_json(&missing_engine), CODE_VALIDATION_ENGINE_REQUIRED);

        let mut missing_both = valid_client_json_value();
        let object = missing_both.as_object_mut().expect("config object");
        object.remove("client");
        object.remove("validation");
        assert_code(load_json(&missing_both), CODE_VALIDATION_REQUIRED);
    }

    #[test]
    fn validation_engine_combinations_are_rule_16() {
        for direction in ["request", "response"] {
            let mut value = valid_client_json_value();
            value["validation"][direction] = json!(true);
            assert_code(load_json(&value), CODE_OFF_VALIDATION_DIRECTIONS);
        }

        // Every non-off engine requires at least one direction, whether or not it is implemented.
        for engine in ["zod", "generated"] {
            let mut no_direction = valid_client_json_value();
            no_direction["validation"] = json!({
                "engine": engine,
                "unchecked": "allow"
            });
            assert_code(load_json(&no_direction), CODE_VALIDATION_DIRECTION_REQUIRED);
        }
    }

    #[test]
    fn no_direction_non_off_engine_co_occurs_with_the_engine_diagnostic_rule_16() {
        // The direction-required failure never masks the engine's own diagnostic: both fire from the
        // same config. zod adds the unsupported-engine error; generated-without-validators adds the
        // requires-validators error. Asserting the pair keeps a future refactor from dropping one.
        let mut no_direction_zod = valid_client_json_value();
        no_direction_zod["validation"] = json!({
            "engine": "zod",
            "unchecked": "allow"
        });
        let zod_diagnostics =
            load_json(&no_direction_zod).expect_err("no-direction zod is rejected");
        assert!(
            zod_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_DIRECTION_REQUIRED)
        );
        assert!(
            zod_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT)
        );

        // `generated` with no direction and without the validators artifact enabled.
        let mut no_direction_generated = valid_client_json_value();
        no_direction_generated["validation"] = json!({
            "engine": "generated",
            "unchecked": "allow"
        });
        let generated_diagnostics =
            load_json(&no_direction_generated).expect_err("no-direction generated is rejected");
        assert!(
            generated_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_DIRECTION_REQUIRED)
        );
        assert!(
            generated_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT)
        );
    }

    #[test]
    fn zod_engine_requires_the_zod_artifact_rule_16() {
        // zod binds to the standalone zod artifact, so without it the engine binds against nothing.
        let mut without_zod = valid_client_json_value();
        without_zod["validation"] = json!({
            "engine": "zod",
            "request": true,
            "unchecked": "allow"
        });
        let diagnostics = assert_code(
            load_json(&without_zod),
            CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT,
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_DIRECTION_REQUIRED)
        );

        // The correspondence is per engine: the validators artifact does not satisfy zod.
        let mut crossed = valid_client_json_value();
        crossed["artifacts"] = json!({ "types": true, "client": true, "validators": true });
        crossed["validation"] = json!({
            "engine": "zod",
            "request": true,
            "unchecked": "allow"
        });
        assert_code(
            load_json(&crossed),
            CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT,
        );

        // client + zod + the zod artifact resolves cleanly.
        let mut with_zod = valid_client_json_value();
        with_zod["artifacts"] = json!({ "types": true, "client": true, "zod": true });
        with_zod["validation"] = json!({
            "engine": "zod",
            "request": true,
            "response": true,
            "unchecked": "allow"
        });
        let resolved = load_json(&with_zod).expect("zod + the zod artifact should resolve");
        let validation = resolved.validation.expect("validation should be present");
        assert_eq!(validation.engine, ValidationEngine::Zod);
        assert!(validation.request);
        assert!(validation.response);
    }

    #[test]
    fn generated_engine_requires_the_validators_artifact_rule_16() {
        // generated is implemented; without the validators artifact it binds against nothing, so it
        // is a correspondence error — never the unsupported-engine error zod raises.
        let mut without_validators = valid_client_json_value();
        without_validators["validation"] = json!({
            "engine": "generated",
            "request": true,
            "unchecked": "allow"
        });
        let diagnostics = assert_code(
            load_json(&without_validators),
            CODE_VALIDATION_ENGINE_REQUIRES_ARTIFACT,
        );
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_VALIDATION_DIRECTION_REQUIRED)
        );

        // client + generated + the validators artifact resolves cleanly with typed values.
        let mut with_validators = valid_client_json_value();
        with_validators["artifacts"] = json!({ "types": true, "client": true, "validators": true });
        with_validators["validation"] = json!({
            "engine": "generated",
            "request": true,
            "response": true,
            "unchecked": "allow"
        });
        let resolved = load_json(&with_validators).expect("generated + validators should resolve");
        assert!(resolved.diagnostics.is_empty());
        assert_eq!(
            resolved.validation,
            Some(ValidationConfig {
                engine: ValidationEngine::Generated,
                request: true,
                response: true,
                unchecked: UncheckedPolicy::Allow,
            })
        );
    }

    #[test]
    fn unchecked_response_policies_are_rule_17() {
        let mut rejected = valid_client_json_value();
        rejected["validation"]["unchecked"] = json!("error");
        assert_code(load_json(&rejected), CODE_UNCHECKED_RESPONSE);

        let allowed =
            load_json(&valid_client_json_value()).expect("unchecked allow should resolve");
        assert!(allowed.diagnostics.is_empty());

        let mut warned = valid_client_json_value();
        warned["validation"] = json!({ "engine": "off" });
        let resolved = load_json(&warned).expect("default unchecked warn should preserve success");
        assert!(resolved.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CODE_UNCHECKED_RESPONSE_WARNING
                && diagnostic.severity == Severity::Warning
                && diagnostic
                    .message
                    .contains("decoded but unchecked against the OpenAPI schema")
                && diagnostic
                    .message
                    .contains("validation.unchecked: \"allow\"")
        }));
    }

    #[test]
    fn base_url_shapes_and_literal_urls_are_rule_18() {
        for base_url in [
            json!({ "source": "literal" }),
            json!({ "source": "literal", "value": "/api" }),
            json!({ "source": "literal", "value": "ftp://example.com/api" }),
            json!({ "source": "literal", "value": "http://[" }),
            json!({ "source": "literal", "value": "https://user:secret@example.com/api" }),
            json!({ "source": "runtime", "value": "https://example.com" }),
            json!({ "source": "server", "value": "https://example.com" }),
            json!({ "source": "runtime", "index": 0 }),
            json!({ "source": "literal", "value": "https://example.com", "index": 0 }),
        ] {
            let mut value = valid_client_json_value();
            value["client"]["baseUrl"] = base_url;
            assert_code(load_json(&value), CODE_BASE_URL);
        }

        for base_url in [
            json!({ "source": "runtime" }),
            json!({ "source": "server" }),
            json!({ "source": "server", "index": 3 }),
            json!({ "source": "literal", "value": "https://example.com/api" }),
            json!({ "source": "literal", "value": "http://example.com/api" }),
        ] {
            let mut value = valid_client_json_value();
            value["client"]["baseUrl"] = base_url;
            load_json(&value).expect("valid base URL shape should resolve");
        }

        let mut server_default = valid_client_json_value();
        server_default["client"]["baseUrl"] = json!({ "source": "server" });
        assert_eq!(
            load_json(&server_default)
                .expect("server base URL should resolve")
                .client
                .map(|client| client.base_url),
            Some(ResolvedBaseUrl::Server { index: 0 })
        );
    }

    #[test]
    fn fetch_defaults_enforce_rule_18_at_deserialization() {
        for fetch_options in [
            json!({ "method": "GET" }),
            json!({ "headers": {} }),
            json!({ "body": "secret" }),
            json!({ "signal": "abort" }),
            json!({ "integrity": "sha256-value" }),
            json!({ "arbitrary": true }),
            json!({ "credentials": "credentialless" }),
            json!({ "cache": "stale-while-revalidate" }),
            json!({ "redirect": "same-origin" }),
            json!({ "referrerPolicy": "" }),
            json!({ "mode": "navigate" }),
        ] {
            let mut value = valid_client_json_value();
            value["client"]["fetchOptions"] = fetch_options;
            assert_code(load_json(&value), CODE_PARSE);
        }

        let mut value = valid_client_json_value();
        value["client"]["fetchOptions"] = json!({
            "credentials": "include",
            "cache": "no-store",
            "redirect": "manual",
            "referrerPolicy": "strict-origin-when-cross-origin",
            "mode": "cors",
            "keepalive": true
        });
        load_json(&value).expect("safe Fetch defaults should resolve");
    }

    #[test]
    fn enabled_artifact_and_runtime_directories_must_not_overlap() {
        for client_directory in ["types", "types/sub"] {
            let mut value = valid_client_json_value();
            value["artifacts"]["client"] = json!({ "directory": client_directory });
            assert_code(load_json(&value), CODE_ARTIFACT_DIRECTORY);
        }

        let mut runtime_collision = valid_client_json_value();
        runtime_collision["emit"] = json!({ "runtimeDirectory": "client" });
        assert_code(load_json(&runtime_collision), CODE_ARTIFACT_DIRECTORY);

        load_json(&valid_client_json_value())
            .expect("distinct client, types, and runtime directories should resolve");
    }

    #[test]
    fn object_date_time_without_client_is_rule_13() {
        let mut value = valid_json_value();
        value["types"] = json!({ "dateTime": "date" });
        assert_code(load_json(&value), CODE_DATE_REPRESENTATION);
    }

    #[test]
    fn temporal_date_without_client_is_rule_13() {
        let mut value = valid_json_value();
        value["types"] = json!({ "date": "temporal" });
        assert_code(load_json(&value), CODE_DATE_REPRESENTATION);
    }

    #[test]
    fn bigint_integer_without_client_is_rule_13() {
        let mut value = valid_json_value();
        value["types"] = json!({ "integer": "bigint" });
        assert_code(load_json(&value), CODE_DATE_REPRESENTATION);
    }

    #[test]
    fn bigint_integer_with_tanstack_is_rule_13() {
        let mut value = valid_client_json_value();
        value["artifacts"] = json!({ "types": true, "client": true, "tanstack": true });
        value["types"] = json!({ "integer": "bigint" });
        let diagnostics = assert_code(load_json(&value), CODE_DATE_REPRESENTATION);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("TanStack query keys")
                && diagnostic.json_pointer.as_deref() == Some("/types/integer")
        }));
    }

    #[test]
    fn non_string_dates_with_client_resolve() {
        for (types, expected_date_time, expected_date) in [
            (
                json!({ "dateTime": "date" }),
                DateTimeRepresentation::Date,
                DateRepresentation::String,
            ),
            (
                json!({ "dateTime": "temporal" }),
                DateTimeRepresentation::Temporal,
                DateRepresentation::String,
            ),
            (
                json!({ "date": "temporal" }),
                DateTimeRepresentation::String,
                DateRepresentation::Temporal,
            ),
        ] {
            let mut value = valid_client_json_value();
            value["types"] = types;
            let resolved = load_json(&value)
                .expect("a non-string date representation with the client artifact should resolve");
            assert_eq!(resolved.types.date_time, expected_date_time);
            assert_eq!(resolved.types.date, expected_date);
        }
    }

    #[test]
    fn fixed_naming_cases_are_rule_20() {
        let mut type_case = valid_json_value();
        type_case["naming"] = json!({ "typeCase": "camel" });
        assert_code(load_json(&type_case), CODE_NAMING);

        let mut property_case = valid_json_value();
        property_case["naming"] = json!({ "propertyCase": "camel" });
        assert_code(load_json(&property_case), CODE_NAMING);
    }

    #[test]
    fn naming_affixes_are_validated() {
        for naming in [
            json!({ "typePrefix": "1bad" }),
            json!({ "typeSuffix": "bad-name" }),
        ] {
            let mut value = valid_json_value();
            value["naming"] = naming;
            assert_code(load_json(&value), CODE_NAMING);
        }

        let mut valid = valid_json_value();
        valid["naming"] = json!({ "typePrefix": "$Api_", "typeSuffix": "_2" });
        load_json(&valid).expect("identifier affixes should resolve");
    }

    #[test]
    fn naming_overrides_deserialize_into_resolved_naming() {
        let mut value = valid_json_value();
        value["naming"] = json!({
            "overrides": {
                "schemas": { "stream_liveInput": "StreamLiveInputId" },
                "schemasBySource": {
                    "workspace/models.yaml#/components/schemas/Thing": "SourceThing"
                },
                "operations": { "deleteWebhook": "DeleteRealtimeKitWebhook" },
                "webhooks": { "pet-created": "PetCreatedEvent" },
                "callbacks": { "delivery-status": "DeliveryStatusEvent" }
            }
        });
        let resolved = load_json(&value).expect("overrides should resolve");
        assert_eq!(
            resolved
                .naming
                .overrides
                .schemas
                .get("stream_liveInput")
                .map(String::as_str),
            Some("StreamLiveInputId")
        );
        assert_eq!(
            resolved
                .naming
                .overrides
                .schemas_by_source
                .get("workspace/models.yaml#/components/schemas/Thing")
                .map(String::as_str),
            Some("SourceThing")
        );
        assert_eq!(
            resolved
                .naming
                .overrides
                .operations
                .get("deleteWebhook")
                .map(String::as_str),
            Some("DeleteRealtimeKitWebhook")
        );
        assert_eq!(
            resolved
                .naming
                .overrides
                .webhooks
                .get("pet-created")
                .map(String::as_str),
            Some("PetCreatedEvent")
        );
        assert_eq!(
            resolved
                .naming
                .overrides
                .callbacks
                .get("delivery-status")
                .map(String::as_str),
            Some("DeliveryStatusEvent")
        );
    }

    #[test]
    fn naming_overrides_reject_unknown_namespace() {
        let mut value = valid_json_value();
        value["naming"] = json!({ "overrides": { "params": { "x": "Y" } } });
        assert_code(load_json(&value), CODE_PARSE);
    }

    #[test]
    fn naming_overrides_path_segments_deserialize_into_resolved_naming() {
        let mut value = valid_json_value();
        value["naming"] = json!({
            "overrides": {
                "pathSegments": { "foo_bar": "FooBarSegment" }
            }
        });
        let resolved = load_json(&value).expect("pathSegments overrides should resolve");
        assert_eq!(
            resolved
                .naming
                .overrides
                .path_segments
                .get("foo_bar")
                .map(String::as_str),
            Some("FooBarSegment")
        );
    }

    #[test]
    fn naming_overrides_path_segments_reject_invalid_identifier_value() {
        let mut value = valid_json_value();
        value["naming"] = json!({
            "overrides": {
                "pathSegments": { "foo-bar": "bad-name" }
            }
        });
        assert_code(load_json(&value), CODE_NAMING);
    }

    #[test]
    fn naming_overrides_path_segments_unmatched_key_is_not_a_config_error() {
        // Unlike schemas/operations, pathSegments has no document to check keys against at the
        // config layer: the artifact that consumes it (not yet implemented) reports an unmatched
        // key as a warning instead. A key naming no segment anywhere must still load clean.
        let mut value = valid_json_value();
        value["naming"] = json!({
            "overrides": {
                "pathSegments": { "not-a-segment": "NeverUsed" }
            }
        });
        load_json(&value).expect("an unmatched pathSegments key is not a config error");
    }

    #[test]
    fn all_naming_enum_values_parse() {
        for file_case in ["kebab", "snake", "camel", "pascal", "preserve"] {
            let mut value = valid_json_value();
            value["naming"] = json!({ "fileCase": file_case });
            load_json(&value).expect("fileCase value should parse");
        }
        for operation_case in ["camel", "preserve"] {
            let mut value = valid_json_value();
            value["naming"] = json!({ "operationCase": operation_case });
            load_json(&value).expect("operationCase value should parse");
        }
        for enum_member_case in ["pascal", "camel", "screamingSnake", "preserve"] {
            let mut value = valid_json_value();
            value["naming"] = json!({ "enumMemberCase": enum_member_case });
            load_json(&value).expect("enumMemberCase value should parse");
        }
    }

    #[test]
    fn all_type_enum_values_parse_when_valid_for_types_only() {
        for representation in ["literal", "const"] {
            let mut value = valid_json_value();
            value["types"] = json!({ "enum": representation });
            load_json(&value).expect("enum representation should parse");
        }
        for extensions in ["accept", "reject"] {
            let mut value = valid_json_value();
            value["types"] = json!({ "enumExtensions": extensions });
            load_json(&value).expect("enumExtensions value should parse");
        }
    }

    #[test]
    fn discriminated_unions_defaults_to_structural_and_accepts_tagged() {
        let resolved = load_json(&valid_json_value()).expect("default config should resolve");
        assert_eq!(
            resolved.types.discriminated_unions,
            DiscriminatedUnions::Structural
        );

        let mut tagged = valid_json_value();
        tagged["types"] = json!({ "discriminatedUnions": "tagged" });
        let resolved =
            load_json(&tagged).expect("tagged discriminated union representation should resolve");
        assert_eq!(
            resolved.types.discriminated_unions,
            DiscriminatedUnions::Tagged
        );
    }

    #[test]
    fn integer_defaults_to_number_and_accepts_bigint() {
        let resolved = load_json(&valid_json_value()).expect("default config should resolve");
        assert_eq!(resolved.types.integer, IntegerRepresentation::Number);

        let mut value = valid_client_json_value();
        value["types"] = json!({ "integer": "bigint" });
        let resolved = load_json(&value)
            .expect("bigint integer representation should resolve with the client");
        assert_eq!(resolved.types.integer, IntegerRepresentation::Bigint);
    }

    #[test]
    fn documentation_defaults_true_and_accepts_booleans() {
        let resolved = load_yaml(valid_yaml()).expect("defaults should resolve");
        assert_eq!(resolved.documentation, DocumentationConfig::default());

        let mut value = valid_json_value();
        value["documentation"] = json!({
            "enabled": false,
            "summary": false,
            "description": false,
            "deprecated": false,
            "examples": false,
            "constraints": false
        });
        load_json(&value).expect("documentation booleans should parse");
    }

    #[test]
    fn each_forbidden_banner_sequence_is_rule_21() {
        for forbidden in [
            "before\nafter",
            "before\rafter",
            "before\u{2028}after",
            "before\u{2029}after",
            "before\0after",
            "//# sourceMappingURL=evil.js.map",
            "Generated by Oasts",
        ] {
            let mut value = valid_json_value();
            value["emit"] = json!({ "banner": [forbidden] });
            assert_code(load_json(&value), CODE_EMIT);
        }
    }

    #[test]
    fn valid_banner_and_emit_literals_resolve() {
        let mut value = valid_json_value();
        value["emit"] = json!({
            "runtimeDirectory": "support/runtime",
            "importExtension": "none",
            "banner": ["Copyright Example"],
            "format": "deterministic"
        });
        load_json(&value).expect("valid emit config should resolve");
    }

    #[test]
    fn invalid_emit_literals_and_path_are_rule_21() {
        for emit in [
            json!({ "runtimeDirectory": "../runtime" }),
            json!({ "importExtension": ".ts" }),
            json!({ "format": "prettier" }),
        ] {
            let mut value = valid_json_value();
            value["emit"] = emit;
            assert_code(load_json(&value), CODE_EMIT);
        }
    }

    #[test]
    fn local_allow_paths_must_be_relative() {
        let mut invalid = valid_json_value();
        invalid["local"] = json!({ "allowPaths": ["/tmp/schemas"] });
        assert_code(load_json(&invalid), CODE_TRUST_LIMITS);

        let mut valid = valid_json_value();
        valid["local"] = json!({ "allowPaths": ["../shared-schemas"] });
        let resolved = load_json(&valid).expect("relative allow path should resolve");
        assert_eq!(resolved.local_allow_paths.len(), 1);
        assert!(resolved.local_allow_paths[0].is_absolute());
    }

    #[test]
    fn every_limit_rejects_low_and_high_values() {
        for (name, low, high) in [
            ("maxDocumentBytes", 1_023_u64, 1_073_741_825_u64),
            ("maxTotalBytes", 1_023, 4_294_967_297),
            ("maxDocuments", 0, 4_097),
            ("maxRefDepth", 0, 1_025),
        ] {
            for invalid in [low, high] {
                let mut value = valid_json_value();
                value["limits"] = json!({ name: invalid });
                assert_code(load_json(&value), CODE_TRUST_LIMITS);
            }
        }
    }

    #[test]
    fn boundary_limit_values_are_accepted() {
        for limits in [
            json!({
                "maxDocumentBytes": 1_024,
                "maxTotalBytes": 1_024,
                "maxDocuments": 1,
                "maxRefDepth": 1
            }),
            json!({
                "maxDocumentBytes": 1_073_741_824_u64,
                "maxTotalBytes": 4_294_967_296_u64,
                "maxDocuments": 4_096,
                "maxRefDepth": 1_024
            }),
        ] {
            let mut value = valid_json_value();
            value["limits"] = limits;
            load_json(&value).expect("boundary limits should resolve");
        }
    }

    #[test]
    fn schema_known_unavailable_blocks_report_named_errors() {
        for name in ["remote", "watch", "ci"] {
            let mut value = valid_json_value();
            value[name] = json!({});
            let diagnostics = assert_code(load_json(&value), CODE_BLOCK_UNSUPPORTED);
            assert!(diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CODE_BLOCK_UNSUPPORTED && diagnostic.message.contains(name)
            }));
        }
    }

    #[test]
    fn schema_known_unavailable_null_block_is_still_present() {
        let mut value = valid_json_value();
        value["remote"] = Value::Null;
        assert_code(load_json(&value), CODE_BLOCK_UNSUPPORTED);
    }

    #[test]
    fn null_is_not_accepted_for_typed_optional_fields() {
        for name in ["input", "output", "namespace", "artifacts", "types"] {
            let mut value = valid_json_value();
            value[name] = Value::Null;
            assert_code(load_json(&value), CODE_PARSE);
        }
    }

    #[test]
    fn resolution_helpers_cover_structural_boundaries() {
        assert!(!is_ts_identifier(""));
        assert!(!is_uri(":missing"));
        assert!(!is_uri("1http:value"));
        assert!(!is_uri("http:with space"));

        let base = Path::new("base");
        assert_eq!(
            lexical_join_below(base, Path::new("./one/../two")),
            Some(PathBuf::from("base/two"))
        );
        assert_eq!(lexical_join_below(base, Path::new("..")), None);
        assert_eq!(lexical_join_below(base, Path::new("/absolute")), None);
        assert_eq!(
            normalize_join(base, Path::new("./one/../two")),
            PathBuf::from("base/two")
        );
        assert_eq!(
            normalize_join(base, Path::new("/absolute")),
            PathBuf::from("base/absolute")
        );
        assert_eq!(
            nearest_existing_ancestor(Path::new("missing-relative-path")),
            None
        );
        assert_eq!(to_u32(usize::MAX), u32::MAX);
        assert_eq!(
            canonicalize_result(Ok(PathBuf::from("resolved")), "path"),
            Ok(PathBuf::from("resolved"))
        );
        assert!(
            canonicalize_result(Err(io::Error::other("blocked")), "path")
                .expect_err("canonicalization error")
                .contains("failed to canonicalize path: blocked")
        );
    }

    #[test]
    fn optional_deserializers_accept_each_structured_value_domain() {
        let emit: Option<EmitConfig> =
            deserialize_optional_non_null(json!({})).expect("emit config");
        let naming: Option<NamingConfig> =
            deserialize_optional_non_null(json!({})).expect("naming config");
        let artifact: Option<ArtifactSetting> =
            deserialize_optional_non_null(json!(true)).expect("artifact setting");
        let artifacts: Option<ArtifactsConfig> =
            deserialize_optional_non_null(json!({})).expect("artifacts config");
        let documentation: Option<DocumentationConfig> =
            deserialize_optional_non_null(json!({})).expect("documentation config");
        let value: Option<Value> =
            deserialize_optional_non_null(json!({ "value": true })).expect("JSON value");

        assert!(emit.is_some());
        assert!(naming.is_some());
        assert!(artifact.is_some());
        assert!(artifacts.is_some());
        assert!(documentation.is_some());
        assert_eq!(value, Some(json!({ "value": true })));
    }

    #[test]
    fn missing_config_parent_is_reported_by_resolution() {
        let raw = serde_json::from_value::<RawConfig>(valid_json_value())
            .expect("valid raw config should deserialize");
        let missing = std::env::temp_dir()
            .join("oasts-parent-that-does-not-exist")
            .join("config.json");
        let diagnostics = resolve_config(missing, raw).expect_err("missing parent should fail");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CODE_IO)
        );
    }

    fn config_with_filters(filters: Value) -> Value {
        let mut value = valid_json_value();
        value["filters"] = filters;
        value
    }

    #[test]
    fn filters_block_resolves_with_defaults() {
        let resolved = load_json(&config_with_filters(json!({
            "tags": { "include": ["pets"] }
        })))
        .expect("filters should resolve");
        let filters = resolved.filters.expect("filters");
        assert!(filters.deprecated, "deprecated defaults to keep");
        assert!(!filters.orphans, "orphans defaults to prune");
        assert!(filters.declares_selection_axis());
    }

    #[test]
    fn filters_orphans_only_declares_no_selection_axis() {
        let resolved =
            load_json(&config_with_filters(json!({ "orphans": true }))).expect("filters");
        let filters = resolved.filters.expect("filters");
        assert!(!filters.declares_selection_axis());
        assert!(filters.orphans);
    }

    #[test]
    fn filters_empty_axis_declares_no_selection_axis() {
        let resolved = load_json(&config_with_filters(
            json!({ "tags": {}, "paths": { "include": [] } }),
        ))
        .expect("filters");
        let filters = resolved.filters.expect("filters");
        assert!(
            !filters.declares_selection_axis(),
            "an axis with no patterns selects nothing"
        );
    }

    #[test]
    fn filters_absent_block_resolves_to_none() {
        let resolved = load_json(&valid_json_value()).expect("config");
        assert!(resolved.filters.is_none());
    }

    #[test]
    fn filters_path_shaped_patterns_stay_exact() {
        let resolved = load_json(&config_with_filters(json!({
            "paths": { "include": ["/", "/pets"], "exclude": ["/^get"] }
        })))
        .expect("path-shaped patterns are exact, not malformed");
        let paths = resolved
            .filters
            .expect("filters")
            .paths
            .expect("paths axis");
        assert!(
            paths
                .include
                .iter()
                .chain(&paths.exclude)
                .all(|pattern| matches!(pattern.kind(), PatternKind::Exact)),
            "a leading slash alone does not open a regex"
        );
        assert!(
            paths.include[0].matches("/"),
            "the root path stays expressible"
        );
    }

    #[test]
    fn filters_multi_segment_path_patterns_stay_exact() {
        let resolved = load_json(&config_with_filters(json!({
            "paths": { "include": ["/pets/{petId}"] }
        })))
        .expect("a multi-segment path is not a regex literal");
        let paths = resolved
            .filters
            .expect("filters")
            .paths
            .expect("paths axis");
        assert!(matches!(paths.include[0].kind(), PatternKind::Exact));
        assert!(paths.include[0].matches("/pets/{petId}"));
    }

    #[test]
    fn filters_uncompilable_regex_is_a_config_error() {
        assert_code(
            load_json(&config_with_filters(
                json!({ "methods": { "include": ["/[unclosed/"] } }),
            )),
            CODE_FILTER_PATTERN,
        );
    }

    #[test]
    fn filters_malformed_pattern_names_its_json_pointer() {
        let diagnostics = assert_code(
            load_json(&config_with_filters(
                json!({ "operations": { "include": ["listPets", "/[unclosed/"] } }),
            )),
            CODE_FILTER_PATTERN,
        );
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == CODE_FILTER_PATTERN)
            .expect("pattern diagnostic");
        assert_eq!(
            diagnostic.json_pointer.as_deref(),
            Some("/filters/operations/include/1")
        );
    }

    #[test]
    fn filters_accept_exact_and_regex_patterns() {
        let resolved = load_json(&config_with_filters(json!({
            "tags": { "include": ["pets"], "exclude": ["/^internal$/i"] },
            "paths": { "include": ["/pets"] },
            "methods": { "exclude": ["DELETE"] },
            "deprecated": false
        })))
        .expect("filters should resolve");
        let filters = resolved.filters.expect("filters");
        assert!(!filters.deprecated);
        let tags = filters.tags.as_ref().expect("tags axis");
        assert_eq!(tags.include.len(), 1);
        assert_eq!(tags.exclude.len(), 1);
        let paths = filters.paths.as_ref().expect("paths axis");
        assert!(
            matches!(paths.include[0].kind(), PatternKind::Exact),
            "a path-shaped string with no closing slash is exact"
        );
    }
}

#[cfg(all(test, feature = "json-schema"))]
mod schema_tests {
    use serde_json::json;

    use super::*;

    fn schema() -> serde_json::Value {
        config_json_schema()
    }

    #[test]
    fn root_title_is_user_config() {
        assert_eq!(schema()["title"], json!("UserConfig"));
    }

    #[test]
    fn schema_version_is_const_integer_1() {
        let sv = &schema()["properties"]["schemaVersion"];
        assert_eq!(sv["const"], json!(1));
        assert_eq!(sv["type"], json!("integer"));
    }

    #[test]
    fn input_is_two_branch_one_of() {
        let input = &schema()["$defs"]["Input"];
        let branches = input["oneOf"].as_array().expect("Input should be oneOf");
        assert_eq!(branches.len(), 2);
        let keys: Vec<&str> = branches
            .iter()
            .flat_map(|b| b["required"].as_array().unwrap())
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(keys, ["path", "url"]);
    }

    #[test]
    fn base_url_is_three_branch_one_of() {
        let base_url = &schema()["$defs"]["BaseUrlConfig"];
        let branches = base_url["oneOf"]
            .as_array()
            .expect("BaseUrlConfig should be oneOf");
        assert_eq!(branches.len(), 3);
        assert_eq!(branches[0]["properties"]["source"]["const"], "runtime");
        assert_eq!(branches[1]["properties"]["source"]["const"], "server");
        assert_eq!(branches[1]["properties"]["index"]["minimum"], 0);
        assert_eq!(branches[2]["properties"]["source"]["const"], "literal");
        assert_eq!(branches[2]["required"], json!(["source", "value"]));
        assert!(
            branches
                .iter()
                .all(|branch| branch["additionalProperties"] == json!(false))
        );
    }

    #[test]
    fn fetch_defaults_schema_has_the_fetch_domains() {
        let schema = schema();
        let fetch = &schema["$defs"]["FetchDefaults"]["properties"];
        let definition = |name: &str| {
            let property = &fetch[name];
            property["$ref"]
                .as_str()
                .or_else(|| {
                    property["anyOf"].as_array().and_then(|branches| {
                        branches.iter().find_map(|branch| branch["$ref"].as_str())
                    })
                })
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
                .and_then(|name| schema["$defs"].get(name))
                .map(|definition| definition["enum"].clone())
                .expect("Fetch option should reference an enum")
        };
        assert_eq!(
            definition("credentials"),
            json!(["omit", "same-origin", "include"])
        );
        assert_eq!(
            definition("cache"),
            json!([
                "default",
                "no-store",
                "reload",
                "no-cache",
                "force-cache",
                "only-if-cached"
            ])
        );
        assert_eq!(definition("redirect"), json!(["follow", "error", "manual"]));
        assert_eq!(
            definition("referrerPolicy"),
            json!([
                "no-referrer",
                "no-referrer-when-downgrade",
                "same-origin",
                "origin",
                "strict-origin",
                "origin-when-cross-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url"
            ])
        );
        assert_eq!(
            definition("mode"),
            json!(["cors", "no-cors", "same-origin"])
        );
    }

    #[test]
    fn schema_field_is_present() {
        assert!(schema()["properties"]["$schema"].is_object());
    }

    #[test]
    fn root_has_additional_properties_false() {
        assert_eq!(schema()["additionalProperties"], json!(false));
    }
}
