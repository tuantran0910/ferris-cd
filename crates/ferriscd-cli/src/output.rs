//! Output formatting for the `ferriscd` CLI (`T14.5`).
//!
//! Three formats, one rule: **the CLI renders what the server sent.** A diff is already
//! `Secret`-redacted by the engine (`ferriscd_engine::diff`), so nothing here decodes, unescapes, or
//! re-derives a value — the renderer is a formatter, never a data path.
//!
//! `--output table` is the human default, `json` is for `jq`, `yaml` is for `kubectl`-shaped eyes and
//! `git`-tracked fixtures. Colour is likewise presentation-only: [`ColorChoice::Auto`] enables it only
//! when stdout is a terminal, so a pipe never receives escape codes.

use std::io::IsTerminal as _;

use anyhow::{Context as _, Result};
use clap::ValueEnum;
use serde::Serialize;

/// `--output table|json|yaml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Aligned, human-readable tables.
    #[default]
    Table,
    /// The server's JSON, indented.
    Json,
    /// The server's JSON as YAML.
    Yaml,
}

/// `--color auto|always|never`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Colour only when stdout is a terminal.
    #[default]
    Auto,
    /// Always colour (CI logs that render ANSI).
    Always,
    /// Never colour (the safe default for a file).
    Never,
}

impl ColorChoice {
    /// Whether colour should be used for a stream that is (or is not) a terminal.
    #[must_use]
    pub fn enabled(self, is_terminal: bool) -> bool {
        match self {
            Self::Auto => is_terminal,
            Self::Always => true,
            Self::Never => false,
        }
    }

    /// The decision for stdout.
    #[must_use]
    pub fn for_stdout(self) -> bool {
        self.enabled(std::io::stdout().is_terminal())
    }
}

/// ANSI styles the CLI uses (foreground colours only: a background colour breaks on light themes).
pub mod style {
    /// Green: synced / healthy.
    pub const GREEN: &str = "\u{1b}[32m";
    /// Red: out of sync / missing / failed.
    pub const RED: &str = "\u{1b}[31m";
    /// Yellow: orphaned / progressing / warning.
    pub const YELLOW: &str = "\u{1b}[33m";
    /// Dim: secondary information (paths, labels).
    pub const DIM: &str = "\u{1b}[2m";
    /// Reset.
    pub const RESET: &str = "\u{1b}[0m";
}

/// Wraps `text` in `code` when colour is enabled (a no-op otherwise, so output bytes are identical).
#[must_use]
pub fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("{code}{text}{}", style::RESET)
    } else {
        text.to_owned()
    }
}

/// A simple left-aligned table.
///
/// Hand-rolled on purpose: the CLI's tables are four columns of short strings, `comfy-table` is not
/// in the lock file, and a formatter is not worth a dependency.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Builds a table from its header row.
    #[must_use]
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    /// Appends one row (padded/truncated to the header width in [`Self::render`]).
    pub fn push<I, S>(&mut self, cells: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }

    /// Whether the table has no data rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Renders the table with a header rule, aligned on the widest cell.
    ///
    /// A row with fewer cells than headers is padded (never a panic: the widths are computed over
    /// what is actually present).
    #[must_use]
    pub fn render(&self) -> String {
        if self.headers.is_empty() {
            return String::new();
        }
        let mut widths: Vec<usize> = self
            .headers
            .iter()
            .map(|header| header.chars().count())
            .collect();
        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.chars().count());
                }
            }
        }
        let mut rendered = String::new();
        rendered.push_str(&render_row(&self.headers, &widths));
        rendered.push('\n');
        for (index, width) in widths.iter().enumerate() {
            if index > 0 {
                rendered.push_str("  ");
            }
            rendered.push_str(&"-".repeat(*width));
        }
        rendered.push('\n');
        for row in &self.rows {
            rendered.push_str(&render_row(row, &widths));
            rendered.push('\n');
        }
        rendered
    }
}

/// Renders one row, padding every column except the last.
fn render_row(cells: &[String], widths: &[usize]) -> String {
    let mut line = String::new();
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            line.push_str("  ");
        }
        let cell = cells.get(index).map(String::as_str).unwrap_or_default();
        line.push_str(cell);
        let padding = width.saturating_sub(cell.chars().count());
        if index + 1 < widths.len() {
            line.push_str(&" ".repeat(padding));
        }
    }
    // Trailing padding on the last column would be invisible but breaks `--color` output diffing.
    line.trim_end().to_owned()
}

/// Serializes `value` as indented JSON.
///
/// # Errors
///
/// Only a serialization failure, which for the API's own DTOs cannot happen.
pub fn render_json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let mut json =
        serde_json::to_string_pretty(value).context("the result cannot be serialized")?;
    json.push('\n');
    Ok(json)
}

/// Serializes `value` as YAML.
///
/// # Errors
///
/// Only a serialization failure.
pub fn render_yaml<T: Serialize>(value: &T) -> Result<String> {
    serde_saphyr::to_string(value).context("the result cannot be serialized as YAML")
}

/// Prints `text` to stdout as-is (`print!`, so callers control the newline).
pub fn emit(text: &str) {
    print!("{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_aligns_columns_and_never_pads_the_last_one() {
        let mut table = Table::new(["NAME", "PROJECT", "SYNC"]);
        table.push(["payments-api", "payments", "Synced"]);
        table.push(["api", "payments", "OutOfSync"]);
        let rendered = table.render();
        assert_eq!(
            rendered,
            "NAME          PROJECT   SYNC\n\
             ------------  --------  ---------\n\
             payments-api  payments  Synced\n\
             api           payments  OutOfSync\n",
            "the header rule follows the widest cell and no line has trailing spaces"
        );
        assert!(
            rendered.lines().all(|line| !line.ends_with(' ')),
            "{rendered:?}"
        );
        assert!(!table.is_empty());
    }

    #[test]
    fn a_table_renders_with_or_without_rows() {
        let empty = Table::new(["NAME"]);
        assert!(empty.is_empty());
        assert_eq!(empty.render(), "NAME\n----\n");

        // A short row is padded instead of panicking.
        let mut short = Table::new(["A", "B", "C"]);
        short.push(["1"]);
        let rendered = short.render();
        assert!(rendered.contains('1'), "{rendered}");
        assert_eq!(rendered.lines().count(), 3, "{rendered}");
    }

    #[test]
    fn json_and_yaml_carry_the_same_document() {
        let value = serde_json::json!({"name": "payments-api", "sync": {"status": "Synced"}});
        let json = render_json(&value).expect("json");
        assert!(json.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed, value);

        let yaml = render_yaml(&value).expect("yaml");
        assert!(yaml.contains("payments-api"), "{yaml}");
        assert!(yaml.contains("status: Synced"), "{yaml}");
        let round_trip: serde_json::Value =
            serde_saphyr::from_str(&yaml).expect("the YAML parses back");
        assert_eq!(round_trip, value, "yaml --output must be the same document");
    }

    #[test]
    fn colour_is_off_unless_asked_for_or_interactive() {
        assert!(!ColorChoice::Never.enabled(true));
        assert!(ColorChoice::Always.enabled(false));
        assert!(!ColorChoice::Auto.enabled(false));
        assert!(ColorChoice::Auto.enabled(true));

        assert_eq!(paint(false, style::RED, "drift"), "drift");
        assert_eq!(paint(true, style::RED, "drift"), "\u{1b}[31mdrift\u{1b}[0m");
    }

    #[test]
    fn the_defaults_are_the_human_ones() {
        assert_eq!(OutputFormat::default(), OutputFormat::Table);
        assert_eq!(ColorChoice::default(), ColorChoice::Auto);
    }
}
