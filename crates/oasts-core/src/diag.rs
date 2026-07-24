//! Stable Oasts diagnostics.
//!
//! Configuration diagnostics use `OASTS0rrs`, where `rr` is the two-digit
//! config rejection-rule number and `s` is a per-rule sequence digit.
//! Input and semantic diagnostics use the reserved `OASTS1xxx` range.

use std::cmp::Ordering;

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

/// A stable, sortable diagnostic emitted by Oasts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub source_id: Option<String>,
    pub line: Option<u32>,
    pub col: Option<u32>,
    pub json_pointer: Option<String>,
    pub category: Category,
}

impl Diagnostic {
    /// Creates a configuration error without source-location metadata.
    #[must_use]
    pub fn config(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            source_id: None,
            line: None,
            col: None,
            json_pointer: None,
            category: Category::Config,
        }
    }

    /// Creates an input error without source-location metadata.
    #[must_use]
    pub fn input(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            source_id: None,
            line: None,
            col: None,
            json_pointer: None,
            category: Category::Input,
        }
    }

    /// Attaches a source ID to this diagnostic.
    #[must_use]
    pub fn with_source(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into());
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
        self.json_pointer = Some(pointer.into());
        self
    }
}

impl Ord for Diagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.source_id
            .cmp(&other.source_id)
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.col.cmp(&other.col))
            .then_with(|| self.code.cmp(other.code))
            .then_with(|| self.message.cmp(&other.message))
            .then_with(|| self.severity.cmp(&other.severity))
            .then_with(|| self.category.cmp(&other.category))
            .then_with(|| self.json_pointer.cmp(&other.json_pointer))
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
}

/// Renders diagnostics in the stable `severity[CODE]: message` stderr format.
///
/// Diagnostics are sorted before rendering so output order is deterministic.
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
    for diagnostic in diagnostics {
        let severity = match diagnostic.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        rendered.push_str(&format!(
            "{severity}[{}]: {}\n",
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
        } else if let Some(pointer) = diagnostic.json_pointer {
            rendered.push_str(&format!("  --> <config>:1:1 {pointer}\n"));
        }
    }
    rendered
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
            source_id: source.map(str::to_owned),
            line,
            col,
            json_pointer: None,
            category: Category::Config,
        }
    }

    #[test]
    fn render_to_string_covers_warnings_locations_and_config_pointers() {
        let mut warning = Diagnostic::input("OASTS1999", "warning").with_source("source.yaml");
        warning.severity = Severity::Warning;
        let pointer_only = Diagnostic::config("OASTS0999", "config").with_json_pointer("/config");
        let rendered = render_to_string(vec![warning, pointer_only]);
        assert!(rendered.contains("warning[OASTS1999]"));
        assert!(rendered.contains("source.yaml:1:1"));
        assert!(rendered.contains("<config>:1:1 /config"));
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
    fn render_propagates_writer_failures() {
        let mut writer = FailingWriter;
        std::io::Write::flush(&mut writer).expect("flush is infallible");
        render(
            vec![Diagnostic::config("OASTS0001", "failure")],
            &mut writer,
        )
        .expect_err("write failure");
    }

    #[test]
    fn render_writes_located_diagnostics_to_writer() {
        let located = Diagnostic::config("OASTS0001", "failure")
            .with_source("config.yaml")
            .with_location(4, 2)
            .with_json_pointer("/input");
        let mut buffer = Vec::new();
        render(vec![located], &mut buffer).expect("render");
        assert_eq!(
            String::from_utf8(buffer).expect("UTF-8"),
            "error[OASTS0001]: failure\n  --> config.yaml:4:2 /input\n"
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
            ..diagnostic(None, None, None, "OASTS1001", "input")
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
        let configured = Diagnostic::config("OASTS0001", "config")
            .with_source("config.yaml")
            .with_location(3, 7)
            .with_json_pointer("/input");
        let input = Diagnostic::input("OASTS1001", "input");

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
