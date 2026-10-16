//! Jupyter notebooks: kernel and language, cell counts, the Markdown heading
//! outline, imports, output types, errors, and whether the notebook was run
//! in order.
//!
//! Specification: <https://nbformat.readthedocs.io/en/latest/format_description.html>

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for Jupyter notebooks.
pub struct Notebook;

static META: ExtractorMeta = ExtractorMeta {
    id: "code.notebook",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "jupyter",
        name: "Jupyter notebook",
        family: "code.notebook",
        mimes: &["application/x-ipynb+json"],
        extensions: &["ipynb"],
        magic: &[],
        parent: Some("json"),
    }],
};

impl Extractor for Notebook {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = String::from_utf8_lossy(&probe.head[..probe.head.len().min(16 * 1024)]);
        let t = head.trim_start();
        (t.starts_with('{') && head.contains("\"nbformat\"") && head.contains("\"cells\""))
            .then_some(Sniff { format: "jupyter", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let nb: Value = serde_json::from_slice(&bytes).map_err(|e| ExtractError::malformed(e.to_string()))?;
        let meta = nb.get("metadata").unwrap_or(&Value::Null);
        let kernel = meta.get("kernelspec");
        let language = meta
            .get("language_info")
            .and_then(|l| l.get("name"))
            .or_else(|| kernel.and_then(|k| k.get("language")))
            .and_then(Value::as_str);
        let cells = nb.get("cells").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();

        let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
        let mut outputs: BTreeMap<String, u64> = BTreeMap::new();
        let mut errors = Vec::new();
        let mut imports: Vec<String> = Vec::new();
        let mut counts: Vec<u64> = Vec::new();
        let (mut executed, mut code_cells) = (0u64, 0u64);
        for (n, cell) in cells.iter().enumerate() {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let kind = cell.get("cell_type").and_then(Value::as_str).unwrap_or("unknown");
            *kinds.entry(kind.to_string()).or_default() += 1;
            let source = cell_source(cell);
            match kind {
                "markdown" => markdown_cell(&source, cx),
                "code" => {
                    code_cells += 1;
                    cx.emit_text(TextRole::Code, &source);
                    for i in python_imports(&source) {
                        if !imports.contains(&i) && imports.len() < 100 {
                            imports.push(i);
                        }
                    }
                    if let Some(c) = cell.get("execution_count").and_then(Value::as_u64) {
                        executed += 1;
                        counts.push(c);
                    }
                    for out in cell.get("outputs").and_then(Value::as_array).into_iter().flatten() {
                        let ty = out.get("output_type").and_then(Value::as_str).unwrap_or("unknown");
                        *outputs.entry(ty.to_string()).or_default() += 1;
                        if ty == "error" && errors.len() < 5 {
                            let name = out.get("ename").and_then(Value::as_str).unwrap_or("Error");
                            let value = out.get("evalue").and_then(Value::as_str).unwrap_or("");
                            errors.push(truncate_chars(&format!("{name}: {value}"), 200));
                        }
                    }
                }
                _ => {}
            }
        }
        let in_order = counts.windows(2).all(|w| w[0] < w[1]);
        if let Some(t) = meta.get("title").and_then(Value::as_str) {
            cx.content().source("notebook.metadata.title").title(t);
        }
        for a in meta.get("authors").and_then(Value::as_array).into_iter().flatten() {
            if let Some(n) = a.get("name").and_then(Value::as_str) {
                cx.content().source("notebook.metadata.authors").author(n);
            }
        }
        cx.format_set("nbformat", format!("{}.{}", nb["nbformat"], nb["nbformat_minor"]));
        if let Some(l) = language {
            cx.format_set("language", l);
        }
        if let Some(k) = kernel.and_then(|k| k.get("display_name").or_else(|| k.get("name"))) {
            cx.format_set("kernel", k.clone());
        }
        cx.format_set("cells", cells.len());
        cx.format_set("cell_types", json!(kinds));
        cx.format_set(
            "executed_cells",
            json!({ "executed": executed, "code_cells": code_cells, "in_order": in_order }),
        );
        if !imports.is_empty() {
            cx.format_set("imports", json!(imports));
        }
        if !outputs.is_empty() {
            cx.format_set("output_types", json!(outputs));
        }
        if !errors.is_empty() {
            cx.format_set("errors", json!(errors));
        }
        Ok(())
    }
}

crate::register_extractor!(Notebook);

/// A cell's source: a string or a list of lines.
fn cell_source(cell: &Value) -> String {
    match cell.get("source") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(lines)) => lines.iter().filter_map(Value::as_str).collect(),
        _ => String::new(),
    }
}

/// Headings into the outline, the rest into the body text.
fn markdown_cell(source: &str, cx: &mut Context<'_>) {
    let mut body = String::new();
    for line in source.lines() {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && line[hashes..].starts_with(' ') {
            let level = u8::try_from(hashes).unwrap_or(6);
            cx.emit_heading(level, line[hashes..].trim());
            if level == 1 {
                cx.content().source("notebook.first_h1").title(line[hashes..].trim());
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    if !body.trim().is_empty() {
        cx.emit_text(TextRole::Body, body.trim());
    }
}

fn python_imports(source: &str) -> Vec<String> {
    static IMPORT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?m)^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import(?-u:\b))").expect("valid"));
    IMPORT
        .captures_iter(source)
        .filter_map(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().split('.').next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports() {
        assert_eq!(
            python_imports("import numpy as np\nfrom pandas.io import x\n%matplotlib inline"),
            ["numpy", "pandas"]
        );
    }

    crate::fixture_tests!("jupyter");
}
