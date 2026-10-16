//! Build and deployment files: Dockerfile / Containerfile (base images,
//! stages, exposed ports, entry point, user, labels) and Makefiles (targets,
//! phony targets, variables, includes).
//!
//! Specifications: <https://docs.docker.com/reference/dockerfile/>,
//! <https://www.gnu.org/software/make/manual/make.html>

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, is_secret_key,
    truncate_chars,
};

/// Extractor for Dockerfiles and Makefiles.
pub struct Infra;

static META: ExtractorMeta = ExtractorMeta {
    id: "code.infra",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "dockerfile",
            name: "Dockerfile",
            family: "code.infra",
            mimes: &["text/x-dockerfile"],
            extensions: &["dockerfile", "containerfile"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "makefile",
            name: "Makefile",
            family: "code.infra",
            mimes: &["text/x-makefile"],
            extensions: &["mk", "mak", "make"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

impl Extractor for Infra {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name?;
        let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let lower = name.to_ascii_lowercase();
        let format = if lower == "dockerfile" || lower == "containerfile" || lower.starts_with("dockerfile.") {
            "dockerfile"
        } else if matches!(name, "Makefile" | "makefile" | "GNUmakefile" | "BSDmakefile") {
            "makefile"
        } else {
            return None;
        };
        Some(Sniff { format, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Code, &text);
        if cx.format_id() == "dockerfile" {
            dockerfile(&text, cx);
        } else {
            makefile(&text, cx);
        }
        Ok(())
    }
}

crate::register_extractor!(Infra);

/// Logical lines: `\` continuations joined, comments dropped.
fn logical_lines(text: &str, escape: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        if cur.is_empty() && line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(body) = line.strip_suffix(escape) {
            cur.push_str(body);
            cur.push(' ');
        } else {
            cur.push_str(line);
            if !cur.trim().is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur.clear();
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn dockerfile(text: &str, cx: &mut Context<'_>) {
    let mut stages = Vec::new();
    let mut instructions: BTreeMap<String, u64> = BTreeMap::new();
    let mut ports = Vec::new();
    let (mut entrypoint, mut cmd, mut user, mut healthcheck) = (None, None, None, false);
    let mut labels = Map::new();
    let mut args = Vec::new();
    let mut envs = Vec::new();
    let mut secret_envs = Vec::new();
    let mut adds_remote = false;
    for line in logical_lines(text, '\\') {
        let line = line.trim();
        let (instr, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let instr = instr.to_ascii_uppercase();
        let rest = rest.trim();
        *instructions.entry(instr.clone()).or_default() += 1;
        match instr.as_str() {
            "FROM" => {
                let words: Vec<&str> = rest.split_whitespace().filter(|p| !p.starts_with("--")).collect();
                let image = words.first().copied().unwrap_or("");
                let alias = words.iter().position(|p| p.eq_ignore_ascii_case("as")).and_then(|i| words.get(i + 1));
                stages.push(json!({ "image": image, "name": alias }));
                // USER applies per stage; only the final stage's user runs the image.
                user = None;
            }
            "EXPOSE" => ports.extend(rest.split_whitespace().map(str::to_string)),
            "ENTRYPOINT" => entrypoint = Some(truncate_chars(rest, 300)),
            "CMD" => cmd = Some(truncate_chars(rest, 300)),
            "USER" => user = Some(rest.to_string()),
            "HEALTHCHECK" => healthcheck = !rest.eq_ignore_ascii_case("none"),
            "LABEL" | "MAINTAINER" => {
                if instr == "MAINTAINER" {
                    labels.insert("maintainer".into(), json!(rest));
                }
                for (k, v) in key_values(rest) {
                    labels.insert(k, json!(truncate_chars(&v, 300)));
                }
            }
            "ARG" => args.extend(rest.split('=').next().map(|n| n.trim().to_string())),
            "ENV" => {
                for (k, _) in key_values(rest) {
                    if is_secret_key(&k) {
                        secret_envs.push(k.clone());
                    }
                    envs.push(k);
                }
            }
            "ADD" => adds_remote |= rest.contains("http://") || rest.contains("https://"),
            _ => {}
        }
    }
    for (key, field) in
        [("org.opencontainers.image.title", "title"), ("org.opencontainers.image.description", "description")]
    {
        if let Some(v) = labels.get(key).and_then(Value::as_str) {
            match field {
                "title" => cx.content().source(key).title(v),
                _ => cx.content().source(key).description(v),
            };
        }
    }
    for key in ["org.opencontainers.image.authors", "maintainer"] {
        if let Some(v) = labels.get(key).and_then(Value::as_str) {
            cx.content().source(key).author(v.split('<').next().unwrap_or(v).trim());
        }
    }
    if let Some(l) = labels.get("org.opencontainers.image.licenses").and_then(Value::as_str) {
        cx.rights().source("org.opencontainers.image.licenses").license(Some(l), None);
    }
    let runs_as_root = user.as_deref().is_none_or(|u| u == "root" || u == "0" || u.starts_with("0:"));
    if runs_as_root {
        cx.security().risk("runs_as_root", Some("no USER, or USER root, in the final stage".into()));
    }
    if !secret_envs.is_empty() {
        cx.security().risk("secret_in_env", Some(format!("ENV sets {}", secret_envs.join(", "))));
    }
    if adds_remote {
        cx.security().risk("remote_add", Some("ADD fetches a URL".into()));
    }
    if let Some(base) = stages.last().and_then(|s| s["image"].as_str()) {
        cx.format_set("base_image", base);
    }
    cx.format_set("stages", Value::Array(stages));
    cx.format_set("instructions", json!(instructions));
    for (k, v) in [("exposed_ports", json!(ports)), ("args", json!(args)), ("env", json!(envs))] {
        if v.as_array().is_some_and(|a| !a.is_empty()) {
            cx.format_set(k, v);
        }
    }
    if let Some(e) = entrypoint {
        cx.format_set("entrypoint", e);
    }
    if let Some(c) = cmd {
        cx.format_set("cmd", c);
    }
    if let Some(u) = user {
        cx.format_set("user", u);
    }
    cx.format_set("healthcheck", healthcheck);
    if !labels.is_empty() {
        cx.format_set("labels", Value::Object(labels));
    }
}

/// `a=1 "b c"="d"` or the legacy `KEY value` form.
fn key_values(rest: &str) -> Vec<(String, String)> {
    if !rest.contains('=') {
        let (k, v) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        return vec![(k.to_string(), v.trim().to_string())];
    }
    let mut out = Vec::new();
    let mut chars = rest.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let key = read_word(&mut chars, '=');
        if key.is_empty() {
            break;
        }
        if chars.next() != Some('=') {
            out.push((key, String::new()));
            continue;
        }
        let value = read_word(&mut chars, ' ');
        out.push((key, value));
    }
    out
}

fn read_word(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, stop: char) -> String {
    let mut w = String::new();
    let mut quote = None;
    while let Some(&c) = chars.peek() {
        match quote {
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == stop || c.is_whitespace() => break,
            _ => w.push(c),
        }
        chars.next();
    }
    w
}

fn makefile(text: &str, cx: &mut Context<'_>) {
    let mut targets = Vec::new();
    let mut phony = Vec::new();
    let mut variables = Vec::new();
    let mut includes = Vec::new();
    let mut default = None;
    for line in logical_lines(text, '\\') {
        if line.starts_with('\t') {
            continue;
        }
        let t = line.trim();
        if let Some(rest) =
            t.strip_prefix("include ").or_else(|| t.strip_prefix("-include ")).or_else(|| t.strip_prefix("sinclude "))
        {
            includes.extend(rest.split_whitespace().map(str::to_string));
        } else if let Some(rest) = t.strip_prefix(".PHONY:") {
            phony.extend(rest.split_whitespace().map(str::to_string));
        } else if let Some(i) = t.find([':', '=']) {
            let (name, op) = (t[..i].trim(), &t[i..]);
            let assignment = op.starts_with('=') || op.starts_with(":=") || op.starts_with("::=");
            let assignment = assignment || name.ends_with(['?', '+', '!']);
            if assignment {
                let n = name.trim_end_matches(['?', '+', '!', ':']).trim();
                if !n.is_empty() && !n.contains(' ') {
                    variables.push(n.to_string());
                }
            } else if !name.starts_with('.') && !name.contains('%') && !name.contains('$') {
                for target in name.split_whitespace() {
                    default.get_or_insert_with(|| target.to_string());
                    if !targets.contains(&target.to_string()) && targets.len() < 200 {
                        targets.push(target.to_string());
                    }
                }
            }
        }
    }
    if let Some(d) = default {
        cx.format_set("default_target", d);
    }
    cx.format_set("targets", json!(targets));
    if !phony.is_empty() {
        cx.format_set("phony", json!(phony));
    }
    if !variables.is_empty() {
        variables.dedup();
        cx.format_set("variables", json!(variables.iter().take(200).collect::<Vec<_>>()));
    }
    if !includes.is_empty() {
        cx.format_set("includes", json!(includes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        assert_eq!(key_values("a=1 \"b c\"=\"d e\""), [("a".into(), "1".into()), ("b c".into(), "d e".into())]);
        assert_eq!(key_values("JAVA_HOME /opt/jdk"), [("JAVA_HOME".into(), "/opt/jdk".into())]);
        assert_eq!(logical_lines("RUN a \\\n  b\n# c\nFROM x", '\\'), ["RUN a    b", "FROM x"]);
    }

    crate::fixture_tests!("dockerfile", "makefile");
}
