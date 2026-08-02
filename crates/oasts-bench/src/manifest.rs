//! Typed model of the frozen `bench/manifest.yaml`.
//!
//! The manifest is the single source of truth for what the harness measures; this module parses
//! it with `yaml_rust2` and hand-typed extraction so every malformed field yields a descriptive
//! error naming the offending key rather than a panic. Only fields the pipeline consumes are
//! modeled — clippy's `-D warnings` gate rejects never-read struct fields, so purely descriptive
//! manifest text (runner images, procedure prose) is intentionally not carried here.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use yaml_rust2::{Yaml, YamlLoader};

use crate::Error;

/// The fixture size class, selecting per-class RSS and tsc ceilings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Large,
    Small,
}

impl Class {
    fn parse(value: &str, context: &str) -> Result<Self, Error> {
        match value {
            "large" => Ok(Self::Large),
            "small" => Ok(Self::Small),
            other => Err(Error::new(format!(
                "{context}: unknown class '{other}' (expected 'large' or 'small')"
            ))),
        }
    }

    /// The canonical manifest spelling, for recording in results.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Large => "large",
            Self::Small => "small",
        }
    }
}

/// A per-class ceiling pair.
#[derive(Clone, Copy, Debug)]
pub struct ClassCeilings {
    large: u64,
    small: u64,
}

impl ClassCeilings {
    fn for_class(&self, class: Class) -> u64 {
        match class {
            Class::Large => self.large,
            Class::Small => self.small,
        }
    }
}

/// The sampling procedure parameters.
#[derive(Clone, Copy, Debug)]
pub struct Procedure {
    pub warmup_runs: usize,
    pub samples: usize,
    pub rounds: usize,
    pub repeatability_bound: f64,
}

/// The gate thresholds.
#[derive(Clone, Debug)]
pub struct Thresholds {
    warm_generate_p50_ms: BTreeMap<String, u64>,
    rss_ceiling_bytes: ClassCeilings,
    tsc_ceiling_ms: ClassCeilings,
}

impl Thresholds {
    /// The warm-generate p50 ceiling in milliseconds for a `<fixture>/<config>` key, if one is set.
    pub fn warm_p50_ms(&self, key: &str) -> Option<u64> {
        self.warm_generate_p50_ms.get(key).copied()
    }

    /// The peak-RSS ceiling in bytes for a fixture class.
    pub fn rss_ceiling(&self, class: Class) -> u64 {
        self.rss_ceiling_bytes.for_class(class)
    }

    /// The tsc wall-time ceiling in milliseconds for a fixture class.
    pub fn tsc_ceiling(&self, class: Class) -> u64 {
        self.tsc_ceiling_ms.for_class(class)
    }
}

/// The origin of a fixture's OpenAPI document.
#[derive(Clone, Debug)]
pub enum FixtureSource {
    /// The document is committed alongside the config; nothing to fetch.
    Committed,
    /// The document is fetched from `url` and verified against `sha256` into `path`.
    Spec(SpecSource),
}

/// A fetched-spec descriptor.
#[derive(Clone, Debug)]
pub struct SpecSource {
    pub path: String,
    pub url: String,
    pub sha256: String,
}

/// One benchmark fixture.
#[derive(Clone, Debug)]
pub struct FixtureEntry {
    pub name: String,
    pub class: Class,
    pub config: String,
    /// The fixture directory under `fixtures/`; defaults to `name` when the manifest omits `dir`.
    pub dir: String,
    pub source: FixtureSource,
}

impl FixtureEntry {
    /// The threshold-lookup key, `<name>/<config>`.
    pub fn threshold_key(&self) -> String {
        format!("{}/{}", self.name, self.config)
    }
}

/// The parsed manifest.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub fixtures: Vec<FixtureEntry>,
    pub procedure: Procedure,
    pub thresholds: Thresholds,
}

impl Manifest {
    /// Loads and parses the manifest at `path`.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error::new(format!("reading manifest {}: {error}", path.display())))?;
        Self::from_str(&text)
    }

    pub(crate) fn from_str(text: &str) -> Result<Self, Error> {
        let documents = YamlLoader::load_from_str(text)
            .map_err(|error| Error::new(format!("manifest YAML parse error: {error}")))?;
        let root = documents
            .first()
            .ok_or_else(|| Error::new("manifest is empty"))?;

        Ok(Self {
            fixtures: parse_fixtures(root)?,
            procedure: parse_procedure(root)?,
            thresholds: parse_thresholds(root)?,
        })
    }
}

fn parse_fixtures(root: &Yaml) -> Result<Vec<FixtureEntry>, Error> {
    let node = field(root, "fixtures", "manifest")?;
    let entries = node
        .as_vec()
        .ok_or_else(|| Error::new("manifest: 'fixtures' must be a sequence"))?;
    let mut fixtures = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let context = format!("fixtures[{index}]");
        let name = req_str(entry, "name", &context)?;
        let class = Class::parse(&req_str(entry, "class", &context)?, &context)?;
        let config = req_str(entry, "config", &context)?;
        let dir = match opt_field(entry, "dir") {
            Some(value) => value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::new(format!("{context}: key 'dir' must be a string")))?,
            None => name.clone(),
        };
        // Both paths are joined under `fixtures/` by the harness, so validate here — once, at load —
        // that neither escapes the corpus tree; every downstream join can then trust the invariant.
        ensure_relative(&dir, "dir", &name)?;
        let source = if let Some(spec) = opt_field(entry, "spec") {
            let spec_context = format!("{context}.spec");
            let path = req_str(spec, "path", &spec_context)?;
            ensure_relative(&path, "spec path", &name)?;
            FixtureSource::Spec(SpecSource {
                path,
                url: req_str(spec, "url", &spec_context)?,
                sha256: req_str(spec, "sha256", &spec_context)?,
            })
        } else if opt_field(entry, "committed").and_then(Yaml::as_bool) == Some(true) {
            FixtureSource::Committed
        } else {
            return Err(Error::new(format!(
                "{context}: entry must have either a 'spec' mapping or 'committed: true'"
            )));
        };
        fixtures.push(FixtureEntry {
            name,
            class,
            config,
            dir,
            source,
        });
    }
    Ok(fixtures)
}

fn parse_procedure(root: &Yaml) -> Result<Procedure, Error> {
    let node = field(root, "procedure", "manifest")?;
    Ok(Procedure {
        warmup_runs: req_usize(node, "warmupRuns", "procedure")?,
        samples: req_usize(node, "samples", "procedure")?,
        rounds: req_usize(node, "rounds", "procedure")?,
        repeatability_bound: req_f64(node, "repeatabilityBound", "procedure")?,
    })
}

fn parse_thresholds(root: &Yaml) -> Result<Thresholds, Error> {
    let node = field(root, "thresholds", "manifest")?;

    let warm_node = field(node, "warmGenerateP50Ms", "thresholds")?;
    let warm_hash = match warm_node {
        Yaml::Hash(hash) => hash,
        _ => {
            return Err(Error::new(
                "thresholds.warmGenerateP50Ms: expected a mapping",
            ));
        }
    };
    let mut warm_generate_p50_ms = BTreeMap::new();
    for (key, value) in warm_hash {
        let key = key
            .as_str()
            .ok_or_else(|| Error::new("thresholds.warmGenerateP50Ms: keys must be strings"))?;
        let milliseconds = value.as_i64().ok_or_else(|| {
            Error::new(format!(
                "thresholds.warmGenerateP50Ms['{key}']: must be an integer"
            ))
        })?;
        let milliseconds = u64::try_from(milliseconds).map_err(|_| {
            Error::new(format!(
                "thresholds.warmGenerateP50Ms['{key}']: must be non-negative"
            ))
        })?;
        warm_generate_p50_ms.insert(key.to_owned(), milliseconds);
    }

    let rss = field(node, "rssCeilingBytes", "thresholds")?;
    let rss_ceiling_bytes = ClassCeilings {
        large: req_u64(rss, "large", "thresholds.rssCeilingBytes")?,
        small: req_u64(rss, "small", "thresholds.rssCeilingBytes")?,
    };

    let tsc = field(node, "tscCeilingMs", "thresholds")?;
    let tsc_ceiling_ms = ClassCeilings {
        large: req_u64(tsc, "large", "thresholds.tscCeilingMs")?,
        small: req_u64(tsc, "small", "thresholds.tscCeilingMs")?,
    };

    Ok(Thresholds {
        warm_generate_p50_ms,
        rss_ceiling_bytes,
        tsc_ceiling_ms,
    })
}

/// Rejects a fixture path that is absolute or contains `..`/root components, so it can only ever
/// resolve inside `fixtures/`. The error names the fixture and which field was at fault.
fn ensure_relative(value: &str, field: &str, fixture: &str) -> Result<(), Error> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(Error::new(format!(
            "fixture '{fixture}': {field} '{value}' must be a relative path"
        )));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err(Error::new(format!(
                "fixture '{fixture}': {field} '{value}' must not contain '..' or a root component"
            )));
        }
    }
    Ok(())
}

pub(crate) fn field<'a>(node: &'a Yaml, key: &str, context: &str) -> Result<&'a Yaml, Error> {
    match node {
        Yaml::Hash(hash) => hash
            .get(&Yaml::String(key.to_owned()))
            .filter(|value| !matches!(value, Yaml::BadValue))
            .ok_or_else(|| Error::new(format!("{context}: missing key '{key}'"))),
        _ => Err(Error::new(format!("{context}: expected a mapping"))),
    }
}

fn opt_field<'a>(node: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    node.as_hash()?
        .get(&Yaml::String(key.to_owned()))
        .filter(|value| !matches!(value, Yaml::BadValue))
}

pub(crate) fn req_str(node: &Yaml, key: &str, context: &str) -> Result<String, Error> {
    field(node, key, context)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a string")))
}

pub(crate) fn req_bool(node: &Yaml, key: &str, context: &str) -> Result<bool, Error> {
    field(node, key, context)?
        .as_bool()
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a boolean")))
}

fn req_i64(node: &Yaml, key: &str, context: &str) -> Result<i64, Error> {
    field(node, key, context)?
        .as_i64()
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be an integer")))
}

pub(crate) fn req_usize(node: &Yaml, key: &str, context: &str) -> Result<usize, Error> {
    usize::try_from(req_i64(node, key, context)?)
        .map_err(|_| Error::new(format!("{context}: key '{key}' must be non-negative")))
}

pub(crate) fn req_u64(node: &Yaml, key: &str, context: &str) -> Result<u64, Error> {
    u64::try_from(req_i64(node, key, context)?)
        .map_err(|_| Error::new(format!("{context}: key '{key}' must be non-negative")))
}

pub(crate) fn req_f64(node: &Yaml, key: &str, context: &str) -> Result<f64, Error> {
    // A whole-number float may be written as a YAML integer (e.g. `repeatabilityBound: 1`), which
    // yaml-rust2 tags `Integer`, not `Real`; accept both so an integer-valued float isn't rejected.
    let value = field(node, key, context)?;
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|integer| integer as f64))
        .ok_or_else(|| Error::new(format!("{context}: key '{key}' must be a number")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_real() -> Manifest {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/manifest.yaml");
        Manifest::load(&path).expect("real manifest loads")
    }

    #[test]
    fn parses_every_fixture_including_the_shared_directory_keys() {
        let manifest = load_real();
        assert_eq!(manifest.fixtures.len(), 16);
        // A key may share another key's fixture directory under a different config; the zod keys
        // and MSW keys plus the petstore client key are the cases, and `dir` is what keeps them
        // distinct.
        let zod = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "github-3.0-zod")
            .expect("github zod fixture present");
        assert_eq!(zod.dir, "github-3.0");
        assert_eq!(zod.config, "oasts-zod.yaml");
    }

    #[test]
    fn known_sha256_and_path_round_trip() {
        let manifest = load_real();
        let github = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "github-3.0")
            .expect("github fixture present");
        match &github.source {
            FixtureSource::Spec(spec) => {
                assert_eq!(
                    spec.sha256,
                    "b138e9cdcf4ac29a23fea1f6579d2840668a5f3d41fe7f160b263bec590d2e3f"
                );
                assert_eq!(spec.path, "openapi.json");
            }
            FixtureSource::Committed => panic!("github fixture is fetched, not committed"),
        }
    }

    #[test]
    fn threshold_lookup_by_fixture_slash_config() {
        let manifest = load_real();
        assert_eq!(
            manifest.thresholds.warm_p50_ms("github-3.0/oasts.yaml"),
            Some(1000)
        );
        assert_eq!(
            manifest.thresholds.warm_p50_ms("stripe-3.0/oasts.yaml"),
            None
        );
        let github = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "github-3.0")
            .expect("github fixture present");
        assert_eq!(github.threshold_key(), "github-3.0/oasts.yaml");
    }

    #[test]
    fn ceilings_resolve_for_both_classes() {
        let thresholds = load_real().thresholds;
        assert_eq!(thresholds.rss_ceiling(Class::Large), 2_147_483_648);
        assert_eq!(thresholds.rss_ceiling(Class::Small), 536_870_912);
        assert_eq!(thresholds.tsc_ceiling(Class::Large), 300_000);
        assert_eq!(thresholds.tsc_ceiling(Class::Small), 60_000);
    }

    #[test]
    fn dir_defaults_to_name_and_honors_explicit_override() {
        let manifest = load_real();
        let client = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "petstore-3.0-client")
            .expect("client fixture present");
        assert_eq!(client.dir, "petstore-3.0");
        let github = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "github-3.0")
            .expect("github fixture present");
        assert_eq!(github.dir, "github-3.0");
    }

    #[test]
    fn procedure_parameters_match_manifest() {
        let procedure = load_real().procedure;
        assert_eq!(procedure.warmup_runs, 3);
        assert_eq!(procedure.samples, 10);
        assert_eq!(procedure.rounds, 2);
        assert!((procedure.repeatability_bound - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn committed_fixture_has_no_spec() {
        let manifest = load_real();
        let petstore = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.name == "petstore-3.0")
            .expect("petstore fixture present");
        assert!(matches!(petstore.source, FixtureSource::Committed));
        assert_eq!(petstore.class, Class::Small);
    }

    #[test]
    fn missing_key_names_the_key() {
        let text = concat!(
            "fixtures: []\n",
            "procedure:\n",
            "  warmupRuns: 3\n",
            "  samples: 10\n",
            "  rounds: 2\n",
            "  repeatabilityBound: 0.1\n",
        );
        let error = Manifest::from_str(text).expect_err("manifest without thresholds is rejected");
        assert!(error.to_string().contains("thresholds"), "{error}");
    }

    #[test]
    fn wrong_type_is_rejected_with_context() {
        let error = Manifest::from_str("fixtures: 3\n").expect_err("non-sequence fixtures");
        assert!(error.to_string().contains("fixtures"), "{error}");
    }

    fn manifest_with_fixture(fixture: &str) -> Result<Manifest, Error> {
        let text = format!(
            concat!(
                "fixtures:\n{fixture}",
                "procedure:\n",
                "  warmupRuns: 3\n",
                "  samples: 10\n",
                "  rounds: 2\n",
                "  repeatabilityBound: 0.1\n",
                "thresholds:\n",
                "  warmGenerateP50Ms: {{}}\n",
                "  rssCeilingBytes: {{ large: 1, small: 1 }}\n",
                "  tscCeilingMs: {{ large: 1, small: 1 }}\n",
            ),
            fixture = fixture,
        );
        Manifest::from_str(&text)
    }

    #[test]
    fn dotdot_fixture_dir_is_rejected_naming_the_fixture() {
        let error = manifest_with_fixture(concat!(
            "  - name: evil\n",
            "    class: small\n",
            "    config: oasts.yaml\n",
            "    dir: ../escape\n",
            "    committed: true\n",
        ))
        .expect_err("dot-dot dir rejected at load");
        let message = error.to_string();
        assert!(
            message.contains("evil") && message.contains("dir"),
            "{message}"
        );
    }

    #[test]
    fn integer_valued_repeatability_bound_is_accepted() {
        // yaml-rust2 tags `1` as Integer, not Real; a float field must still accept it.
        let manifest = Manifest::from_str(concat!(
            "fixtures: []\n",
            "procedure:\n",
            "  warmupRuns: 3\n",
            "  samples: 10\n",
            "  rounds: 2\n",
            "  repeatabilityBound: 1\n",
            "thresholds:\n",
            "  warmGenerateP50Ms: {}\n",
            "  rssCeilingBytes: { large: 1, small: 1 }\n",
            "  tscCeilingMs: { large: 1, small: 1 }\n",
        ))
        .expect("integer-valued float accepted");
        assert_eq!(manifest.procedure.repeatability_bound, 1.0);
    }

    #[test]
    fn req_f64_rejects_a_non_number() {
        let documents = YamlLoader::load_from_str("bound: nope\n").expect("yaml");
        let error = req_f64(&documents[0], "bound", "procedure").expect_err("non-number rejected");
        assert!(error.to_string().contains("must be a number"), "{error}");
    }

    #[test]
    fn absolute_spec_path_is_rejected_naming_the_fixture() {
        let error = manifest_with_fixture(concat!(
            "  - name: evil\n",
            "    class: small\n",
            "    config: oasts.yaml\n",
            "    spec:\n",
            "      path: /etc/passwd\n",
            "      url: https://ignored\n",
            "      sha256: abc\n",
        ))
        .expect_err("absolute spec path rejected at load");
        let message = error.to_string();
        assert!(
            message.contains("evil") && message.contains("relative"),
            "{message}"
        );
    }
}
