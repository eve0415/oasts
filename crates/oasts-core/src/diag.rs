//! Stable Oasts diagnostics.
//!
//! The thousands digit is the compiler stage a code comes from. Stages are
//! drawn so that every code within one shares a single exit code:
//!
//! | Stage  | Meaning                                             | Exit |
//! |--------|-----------------------------------------------------|------|
//! | `0xxx` | config validation, as `0rrs` — rule `rr`, sequence `s` | 2  |
//! | `1xxx` | I/O and write failures                              | 2    |
//! | `2xxx` | document loading, structure, and schema keywords    | 1    |
//! | `3xxx` | semantic: names, value domains, links                | 1    |
//! | `4xxx` | type emission                                       | 1    |
//! | `5xxx` | client model                                        | 1    |
//! | `6xxx` | artifacts, one sub-band per artifact                | 1    |
//!
//! The exit code is carried by [`Category`], not parsed out of the number; the
//! table holds because stage membership is chosen to keep it true, and a code
//! whose category disagrees with its stage is a bug.
//!
//! The hundreds digit sub-divides a stage. Sub-bands stay sparse deliberately,
//! so a new code joins its siblings instead of landing at the end of a run.
//!
//! `9xxx` is the provisional band: capabilities this build gates off rather
//! than refuses on the merits. A provisional code retires when its capability
//! lands, so the band is expected to develop holes and nothing may renumber to
//! close them. The second digit mirrors the stage the code would otherwise have
//! had, so it keeps its category. `99xx` is reserved for test sentinels, which
//! are never emitted.

use std::cmp::Ordering;
use std::collections::BTreeMap;

/// The severity of a diagnostic.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Severity {
    Error,
    Warning,
}

/// The failure category that determines the process exit code.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Category {
    Config,
    Input,
}

impl Category {
    /// Returns the process exit code for an error in this category.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Config => 2,
            Self::Input => 1,
        }
    }
}

/// A deterministic naming override shown after the run's diagnostics.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NamingOverrideSuggestion {
    pub namespace: NamingOverrideNamespace,
    pub source_name: String,
    pub identifier: String,
}

/// One supported `naming.overrides` namespace.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NamingOverrideNamespace {
    Schemas,
    SchemasBySource,
    Operations,
    Webhooks,
    Callbacks,
}

impl NamingOverrideNamespace {
    const fn key(self) -> &'static str {
        match self {
            Self::Schemas => "schemas",
            Self::SchemasBySource => "schemasBySource",
            Self::Operations => "operations",
            Self::Webhooks => "webhooks",
            Self::Callbacks => "callbacks",
        }
    }
}

/// A stable, sortable diagnostic emitted by Oasts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    /// The workspace spec this diagnostic belongs to; `None` outside a workspace run.
    ///
    /// This and the two strings beside it are boxed rather than owned inline: a compile builds
    /// diagnostics in bulk, and three `String` headers cost more per diagnostic than the pointers
    /// that replace them.
    pub spec: Option<Box<str>>,
    pub source_id: Option<Box<str>>,
    pub line: Option<u32>,
    pub col: Option<u32>,
    pub json_pointer: Option<Box<str>>,
    pub category: Category,
    pub naming_override_suggestions: Option<Box<Vec<NamingOverrideSuggestion>>>,
}

impl Diagnostic {
    /// Creates a configuration error without source-location metadata.
    #[must_use]
    pub fn config(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            spec: None,
            source_id: None,
            line: None,
            col: None,
            json_pointer: None,
            category: Category::Config,
            naming_override_suggestions: None,
        }
    }

    /// Creates an input error without source-location metadata.
    #[must_use]
    pub fn input(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            spec: None,
            source_id: None,
            line: None,
            col: None,
            json_pointer: None,
            category: Category::Input,
            naming_override_suggestions: None,
        }
    }

    /// Attaches a source ID to this diagnostic.
    #[must_use]
    pub fn with_source(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into().into_boxed_str());
        self
    }

    /// Attaches a one-based line and column to this diagnostic.
    #[must_use]
    pub const fn with_location(mut self, line: u32, col: u32) -> Self {
        self.line = Some(line);
        self.col = Some(col);
        self
    }

    /// Attaches a JSON Pointer to this diagnostic.
    #[must_use]
    pub fn with_json_pointer(mut self, pointer: impl Into<String>) -> Self {
        self.json_pointer = Some(pointer.into().into_boxed_str());
        self
    }

    /// Attaches run-level naming remedies without changing the diagnostic's own message.
    #[must_use]
    pub fn with_naming_override_suggestions(
        mut self,
        suggestions: Vec<NamingOverrideSuggestion>,
    ) -> Self {
        self.naming_override_suggestions = (!suggestions.is_empty()).then(|| Box::new(suggestions));
        self
    }
}

impl Ord for Diagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.spec
            .cmp(&other.spec)
            .then_with(|| self.source_id.cmp(&other.source_id))
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.col.cmp(&other.col))
            .then_with(|| self.code.cmp(other.code))
            .then_with(|| self.message.cmp(&other.message))
            .then_with(|| self.severity.cmp(&other.severity))
            .then_with(|| self.category.cmp(&other.category))
            .then_with(|| self.json_pointer.cmp(&other.json_pointer))
            .then_with(|| {
                self.naming_override_suggestions
                    .cmp(&other.naming_override_suggestions)
            })
    }
}

impl PartialOrd for Diagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// An accumulating diagnostic collection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticSink {
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticSink {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
        }
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn extend(&mut self, diagnostics: impl IntoIterator<Item = Diagnostic>) {
        self.diagnostics.extend(diagnostics);
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    #[must_use]
    pub fn worst_exit_code(&self) -> u8 {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .map(|diagnostic| diagnostic.category.exit_code())
            .max()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn into_sorted_vec(mut self) -> Vec<Diagnostic> {
        self.diagnostics.sort();
        self.diagnostics
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn into_vec(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

/// Renders diagnostics in the stable `severity[CODE]: message` stderr format.
///
/// Diagnostics are sorted before rendering so output order is deterministic. Spec attribution
/// leads that ordering, so a workspace run reports one spec at a time whatever order the specs
/// were compiled in.
pub fn render(
    diagnostics: Vec<Diagnostic>,
    writer: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    writer.write_all(render_to_string(diagnostics).as_bytes())
}

/// Renders diagnostics into a `String` for hosts without a stderr stream.
#[must_use]
pub fn render_to_string(mut diagnostics: Vec<Diagnostic>) -> String {
    diagnostics.sort();
    let mut rendered = String::new();
    let mut suggestions = BTreeMap::<NamingOverrideNamespace, BTreeMap<String, String>>::new();
    for diagnostic in diagnostics {
        if let Some(diagnostic_suggestions) = diagnostic.naming_override_suggestions {
            for suggestion in *diagnostic_suggestions {
                suggestions
                    .entry(suggestion.namespace)
                    .or_default()
                    .entry(suggestion.source_name)
                    .or_insert(suggestion.identifier);
            }
        }
        let severity = match diagnostic.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        // The spec name leads the message rather than sitting on the `-->` line, which only
        // appears for a diagnostic that carries a source. A single-spec run attributes nothing,
        // so its rendering is byte for byte what it was before workspaces existed.
        let spec = match &diagnostic.spec {
            Some(name) => format!("spec '{name}': "),
            None => String::new(),
        };
        rendered.push_str(&format!(
            "{severity}[{}]: {spec}{}\n",
            diagnostic.code, diagnostic.message
        ));
        if let Some(source_id) = diagnostic.source_id {
            let line = diagnostic.line.unwrap_or(1);
            let col = diagnostic.col.unwrap_or(1);
            rendered.push_str(&format!("  --> {source_id}:{line}:{col}"));
            if let Some(pointer) = diagnostic.json_pointer {
                rendered.push_str(&format!(" {pointer}"));
            }
            rendered.push('\n');
        }
    }
    if !suggestions.is_empty() {
        rendered.push_str("help: add these deterministic naming overrides to oasts.yaml:\n");
        rendered.push_str("naming:\n  overrides:\n");
        for (namespace, entries) in suggestions {
            rendered.push_str(&format!("    {}:\n", namespace.key()));
            for (source_name, identifier) in entries {
                rendered.push_str(&format!(
                    "      '{}': '{}'\n",
                    yaml_single_quote(&source_name),
                    yaml_single_quote(&identifier)
                ));
            }
        }
    }
    rendered
}

fn yaml_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic(
        source: Option<&str>,
        line: Option<u32>,
        col: Option<u32>,
        code: &'static str,
        message: &str,
    ) -> Diagnostic {
        Diagnostic {
            code,
            severity: Severity::Error,
            message: message.to_owned(),
            spec: None,
            source_id: source.map(Box::from),
            line,
            col,
            json_pointer: None,
            category: Category::Config,
            naming_override_suggestions: None,
        }
    }

    #[test]
    fn render_to_string_covers_warnings_and_never_invents_a_config_source() {
        let mut warning = Diagnostic::input("OASTS9906", "warning").with_source("source.yaml");
        warning.severity = Severity::Warning;
        let pointer_only = Diagnostic::config("OASTS9902", "config").with_json_pointer("/config");
        let rendered = render_to_string(vec![warning, pointer_only]);
        assert!(rendered.contains("warning[OASTS9906]"));
        assert!(rendered.contains("source.yaml:1:1"));
        assert!(!rendered.contains("<config>"));
        assert!(!rendered.contains("/config"));
    }

    #[test]
    fn render_appends_one_yaml_safe_run_level_override_block() {
        let schemas = Diagnostic::input("OASTS3002", "schema collision")
            .with_naming_override_suggestions(vec![NamingOverrideSuggestion {
                namespace: NamingOverrideNamespace::Schemas,
                source_name: "Owner's pet".to_owned(),
                identifier: "OwnersPet_1".to_owned(),
            }]);
        let operations = Diagnostic::input("OASTS3001", "operation collision")
            .with_naming_override_suggestions(vec![NamingOverrideSuggestion {
                namespace: NamingOverrideNamespace::Operations,
                source_name: "get-pet".to_owned(),
                identifier: "getPet_1".to_owned(),
            }]);

        let rendered = render_to_string(vec![operations, schemas]);
        assert!(rendered.contains("help: add these deterministic naming overrides"));
        assert!(rendered.contains("      'Owner''s pet': 'OwnersPet_1'\n"));
        assert!(rendered.contains("      'get-pet': 'getPet_1'\n"));
        assert_eq!(rendered.matches("naming:\n  overrides:\n").count(), 1);
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("write failed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn attributed_diagnostics_name_their_spec_and_sort_by_it() {
        let mut users = diagnostic(Some("openapi.yaml"), None, None, "OASTS2101", "second");
        users.spec = Some("users".into());
        let mut billing = diagnostic(Some("openapi.yaml"), None, None, "OASTS2101", "first");
        billing.spec = Some("billing".into());
        let unattributed = diagnostic(None, None, None, "OASTS0011", "no spec");

        let rendered = render_to_string(vec![users, billing, unattributed]);

        assert_eq!(
            rendered,
            "error[OASTS0011]: no spec\n\
             error[OASTS2101]: spec 'billing': first\n  --> openapi.yaml:1:1\n\
             error[OASTS2101]: spec 'users': second\n  --> openapi.yaml:1:1\n"
        );
    }

    #[test]
    fn render_propagates_writer_failures() {
        let mut writer = FailingWriter;
        std::io::Write::flush(&mut writer).expect("flush is infallible");
        render(
            vec![Diagnostic::config("OASTS9902", "failure")],
            &mut writer,
        )
        .expect_err("write failure");
    }

    #[test]
    fn render_writes_located_diagnostics_to_writer() {
        let located = Diagnostic::config("OASTS9902", "failure")
            .with_source("config.yaml")
            .with_location(4, 2)
            .with_json_pointer("/input");
        let mut buffer = Vec::new();
        render(vec![located], &mut buffer).expect("render");
        assert_eq!(
            String::from_utf8(buffer).expect("UTF-8"),
            "error[OASTS9902]: failure\n  --> config.yaml:4:2 /input\n"
        );
    }

    #[test]
    fn diagnostics_sort_deterministically_by_contract_fields() {
        let mut diagnostics = [
            diagnostic(Some("b"), Some(1), Some(1), "OASTS0031", "a"),
            diagnostic(Some("a"), Some(2), Some(1), "OASTS0031", "a"),
            diagnostic(Some("a"), Some(1), Some(2), "OASTS0031", "a"),
            diagnostic(Some("a"), Some(1), Some(1), "OASTS0041", "a"),
            diagnostic(Some("a"), Some(1), Some(1), "OASTS0031", "b"),
            diagnostic(None, Some(1), Some(1), "OASTS0031", "a"),
        ];

        diagnostics.sort();

        let keys = diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.source_id.as_deref(),
                    diagnostic.line,
                    diagnostic.col,
                    diagnostic.code,
                    diagnostic.message.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                (None, Some(1), Some(1), "OASTS0031", "a"),
                (Some("a"), Some(1), Some(1), "OASTS0031", "b"),
                (Some("a"), Some(1), Some(1), "OASTS0041", "a"),
                (Some("a"), Some(1), Some(2), "OASTS0031", "a"),
                (Some("a"), Some(2), Some(1), "OASTS0031", "a"),
                (Some("b"), Some(1), Some(1), "OASTS0031", "a"),
            ]
        );
    }

    #[test]
    fn sink_reports_errors_and_worst_exit_code() {
        let warning = Diagnostic {
            severity: Severity::Warning,
            category: Category::Config,
            ..diagnostic(None, None, None, "OASTS0031", "warning")
        };
        let input_error = Diagnostic {
            category: Category::Input,
            ..diagnostic(None, None, None, "OASTS9907", "input")
        };
        let mut sink = DiagnosticSink::new();
        sink.push(warning);
        assert!(!sink.has_errors());
        assert_eq!(sink.worst_exit_code(), 0);
        sink.push(input_error);
        assert!(sink.has_errors());
        assert_eq!(sink.worst_exit_code(), 1);
        sink.push(diagnostic(None, None, None, "OASTS0031", "config"));
        assert_eq!(sink.worst_exit_code(), 2);
    }

    #[test]
    fn constructors_metadata_and_collection_accessors_are_covered() {
        let configured = Diagnostic::config("OASTS9902", "config")
            .with_source("config.yaml")
            .with_location(3, 7)
            .with_json_pointer("/input");
        let input = Diagnostic::input("OASTS9907", "input");

        assert_eq!(configured.source_id.as_deref(), Some("config.yaml"));
        assert_eq!((configured.line, configured.col), (Some(3), Some(7)));
        assert_eq!(configured.json_pointer.as_deref(), Some("/input"));
        assert_eq!(input.category, Category::Input);
        assert_eq!(configured.partial_cmp(&input), Some(configured.cmp(&input)));

        let mut sink = DiagnosticSink::new();
        sink.extend([input.clone(), configured.clone()]);
        assert_eq!(sink.as_slice(), [input, configured]);
        assert_eq!(sink.into_sorted_vec().len(), 2);
    }
}
