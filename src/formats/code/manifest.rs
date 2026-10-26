//! Package manifests and lockfiles: npm `package.json` / `package-lock.json`,
//! Cargo `Cargo.toml` / `Cargo.lock`, Python `pyproject.toml` /
//! `requirements.txt`, Go `go.mod` / `go.sum` and Maven `pom.xml`. Name,
//! version, licence, authors, repository, dependencies with versions, and
//! scripts; install hooks and custom package indexes are flagged.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{
    AnyValue, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Probe, Sniff, Source,
    TextRole, dotted_key_depth, nesting_depth, truncate_chars,
};

/// Extractor for package manifests.
pub struct Manifest;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $parent:literal) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "code.manifest",
            mimes: &[$mime],
            extensions: &[],
            magic: &[],
            parent: Some($parent),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "code.manifest",
    version: 1,
    cost: Cost::Scan,
    priority: 10,
    formats: &[
        spec!("npm_package", "npm package.json", "application/json", "json"),
        spec!("npm_lockfile", "npm package-lock.json", "application/json", "json"),
        spec!("cargo_manifest", "Cargo manifest", "application/toml", "toml"),
        spec!("cargo_lockfile", "Cargo lockfile", "application/toml", "toml"),
        spec!("pyproject", "Python pyproject.toml", "application/toml", "toml"),
        spec!("pip_requirements", "pip requirements file", "text/plain", "text"),
        spec!("go_module", "Go module file", "text/plain", "text"),
        spec!("go_sum", "Go checksum database", "text/plain", "text"),
        spec!("maven_pom", "Maven POM", "application/xml", "xml"),
    ],
};

/// Dependencies listed per group.
const MAX_DEPS: usize = 200;

impl Extractor for Manifest {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name?;
        let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let format = match name {
            "package.json" => "npm_package",
            "package-lock.json" | "npm-shrinkwrap.json" => "npm_lockfile",
            "Cargo.toml" => "cargo_manifest",
            "Cargo.lock" => "cargo_lockfile",
            "pyproject.toml" => "pyproject",
            "go.mod" => "go_module",
            "go.sum" => "go_sum",
            "pom.xml" => "maven_pom",
            n if n.starts_with("requirements") && has_extension(n, "txt") => "pip_requirements",
            n if has_extension(n, "pom") => "maven_pom",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        match cx.format_id() {
            "npm_package" => npm(&parse_json(&text)?, cx),
            "npm_lockfile" => npm_lock(&parse_json(&text)?, cx),
            "cargo_manifest" => cargo(&parse_toml(&text)?, cx),
            "cargo_lockfile" => cargo_lock(&parse_toml(&text)?, cx),
            "pyproject" => pyproject(&parse_toml(&text)?, cx),
            "pip_requirements" => requirements(&text, cx),
            "go_module" => go_mod(&text, cx),
            "go_sum" => go_sum(&text, cx),
            _ => maven(&text, cx),
        }
        Ok(())
    }
}

crate::register_extractor!(Manifest);

fn has_extension(name: &str, ext: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

fn parse_json(text: &str) -> Result<Value, ExtractError> {
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| ExtractError::malformed(e.to_string()))
}

pub(crate) fn parse_toml(text: &str) -> Result<Value, ExtractError> {
    if nesting_depth(text) > MAX_NESTING || dotted_key_depth(text) > MAX_NESTING {
        return Err(ExtractError::malformed("nested too deeply"));
    }
    toml::from_str::<AnyValue>(text)
        .map(|v| v.0)
        .map_err(|e| ExtractError::malformed(truncate_chars(&e.to_string(), 300)))
}

fn s<'v>(v: &'v Value, path: &[&str]) -> Option<&'v str> {
    path.iter().try_fold(v, |v, k| v.get(*k)).and_then(Value::as_str)
}

/// Write the common package facts.
struct Package<'a> {
    ecosystem: &'static str,
    name: Option<&'a str>,
    version: Option<&'a str>,
    description: Option<&'a str>,
    license: Option<&'a str>,
    authors: Vec<String>,
    repository: Option<&'a str>,
}

impl Package<'_> {
    fn write(&self, cx: &mut Context<'_>) {
        let src = format!("{}.manifest", self.ecosystem);
        if let Some(n) = self.name {
            let title = match self.version {
                Some(v) => format!("{n} {v}"),
                None => n.to_string(),
            };
            cx.content().source(src.clone()).title(title);
        }
        if let Some(d) = self.description {
            cx.content().source(src.clone()).description(d);
            cx.emit_text(TextRole::Body, d);
        }
        if let Some(l) = self.license {
            cx.rights().source(src.clone()).license(Some(l), None);
        }
        for a in &self.authors {
            cx.content().source(src.clone()).author(a.clone());
            cx.rights().source(src.clone()).creator(a.clone());
        }
        let f = cx.format();
        f.insert("ecosystem".into(), json!(self.ecosystem));
        for (k, v) in
            [("name", self.name), ("version", self.version), ("license", self.license), ("repository", self.repository)]
        {
            if let Some(v) = v {
                f.insert(k.into(), json!(v));
            }
        }
    }
}

/// `"Ada <ada@x> (https://…)"` or `{ "name": "Ada" }` → `Ada`.
fn person(v: &Value) -> Option<String> {
    let raw = match v {
        Value::String(s) => s.as_str(),
        Value::Object(o) => o.get("name")?.as_str()?,
        _ => return None,
    };
    let name = raw.split(['<', '(']).next().unwrap_or(raw).trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// A dependency table (`{name: version | {version: …}}`) as `{name: version}` plus its size.
fn deps(v: Option<&Value>) -> (Map<String, Value>, usize) {
    let Some(Value::Object(o)) = v else { return (Map::new(), 0) };
    let listed = o
        .iter()
        .take(MAX_DEPS)
        .map(|(k, d)| {
            let version = match d {
                Value::String(s) => json!(s),
                Value::Object(spec) => spec
                    .get("version")
                    .cloned()
                    .or_else(|| spec.get("git").map(|g| json!(format!("git: {}", g.as_str().unwrap_or("?")))))
                    .or_else(|| spec.get("path").map(|p| json!(format!("path: {}", p.as_str().unwrap_or("?")))))
                    .unwrap_or_else(|| json!("*")),
                other => other.clone(),
            };
            (k.clone(), version)
        })
        .collect();
    (listed, o.len())
}

fn put_deps(cx: &mut Context<'_>, group: &str, (listed, n): (Map<String, Value>, usize)) {
    if n > 0 {
        cx.format_set(group, Value::Object(listed));
        cx.format_set(&format!("{group}_count"), n);
    }
}

pub(crate) fn npm(v: &Value, cx: &mut Context<'_>) {
    let authors: Vec<String> = v
        .get("author")
        .into_iter()
        .chain(v.get("contributors").and_then(Value::as_array).into_iter().flatten())
        .filter_map(person)
        .collect();
    let repo = v.get("repository").and_then(|r| r.as_str().or_else(|| s(r, &["url"])));
    let license = v.get("license").and_then(|l| l.as_str().or_else(|| s(l, &["type"])));
    Package {
        ecosystem: "npm",
        name: s(v, &["name"]),
        version: s(v, &["version"]),
        description: s(v, &["description"]),
        license,
        authors,
        repository: repo,
    }
    .write(cx);
    for group in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        put_deps(cx, &snake(group), deps(v.get(group)));
    }
    if let Some(Value::Object(scripts)) = v.get("scripts") {
        cx.format_set("scripts", json!(scripts.keys().collect::<Vec<_>>()));
        let hooks: Vec<&String> = scripts
            .keys()
            .filter(|k| matches!(k.as_str(), "preinstall" | "install" | "postinstall" | "prepare"))
            .collect();
        if !hooks.is_empty() {
            let detail = hooks.iter().map(|h| h.as_str()).collect::<Vec<_>>().join(", ");
            cx.security().active_content("install_scripts").risk("install_script", Some(detail));
        }
    }
    for key in ["main", "module", "types", "type", "private", "engines", "workspaces", "bin", "packageManager"] {
        if let Some(x) = v.get(key) {
            cx.format_set(&snake(key), x.clone());
        }
    }
    if let Some(k) = v.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("npm.keywords").keyword(kw);
        }
    }
}

fn snake(k: &str) -> String {
    let mut out = String::new();
    for c in k.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn npm_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "npm");
    if let Some(n) = s(v, &["name"]) {
        cx.format_set("name", n);
    }
    cx.format_set("lockfile_version", v.get("lockfileVersion").cloned().unwrap_or(Value::Null));
    let packages = match v.get("packages").and_then(Value::as_object) {
        Some(p) => p.keys().filter(|k| !k.is_empty()).count(),
        None => v.get("dependencies").and_then(Value::as_object).map_or(0, Map::len),
    };
    cx.format_set("resolved_packages", packages);
}

pub(crate) fn cargo(v: &Value, cx: &mut Context<'_>) {
    let pkg = v.get("package").unwrap_or(&Value::Null);
    let authors: Vec<String> =
        pkg.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    Package {
        ecosystem: "cargo",
        name: s(pkg, &["name"]),
        version: s(pkg, &["version"]),
        description: s(pkg, &["description"]),
        license: s(pkg, &["license"]),
        authors,
        repository: s(pkg, &["repository"]),
    }
    .write(cx);
    for key in ["edition", "rust-version", "homepage", "documentation"] {
        if let Some(x) = pkg.get(key) {
            cx.format_set(&key.replace('-', "_"), x.clone());
        }
    }
    for group in ["dependencies", "dev-dependencies", "build-dependencies"] {
        put_deps(cx, &group.replace('-', "_"), deps(v.get(group)));
    }
    if let Some(Value::Object(f)) = v.get("features") {
        cx.format_set("features", json!(f.keys().collect::<Vec<_>>()));
    }
    if let Some(m) = v.get("workspace").and_then(|w| w.get("members")) {
        cx.format_set("workspace_members", m.clone());
    }
    for target in ["bin", "example", "test", "bench"] {
        if let Some(Value::Array(a)) = v.get(target) {
            cx.format_set(&format!("{target}_targets"), a.len());
        }
    }
    if pkg.get("build").is_some_and(|b| b != &Value::Bool(false)) {
        cx.format_set("build_script", true);
    }
    if let Some(k) = pkg.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("cargo.keywords").keyword(kw);
        }
    }
}

fn cargo_lock(v: &Value, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "cargo");
    let packages = v.get("package").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let mut sources: BTreeMap<&str, u64> = BTreeMap::new();
    for p in packages {
        let kind = match s(p, &["source"]) {
            Some(src) if src.starts_with("registry+") => "registry",
            Some(src) if src.starts_with("git+") => "git",
            Some(_) => "other",
            None => "local",
        };
        *sources.entry(kind).or_default() += 1;
    }
    cx.format_set("lockfile_version", v.get("version").cloned().unwrap_or(Value::Null));
    cx.format_set("resolved_packages", packages.len());
    cx.format_set("sources", json!(sources));
}

fn pyproject(v: &Value, cx: &mut Context<'_>) {
    let project = v.get("project");
    let poetry = v.get("tool").and_then(|t| t.get("poetry"));
    let p = project.or(poetry).unwrap_or(&Value::Null);
    let license = p.get("license").and_then(|l| l.as_str().or_else(|| s(l, &["text"])));
    let authors: Vec<String> =
        p.get("authors").and_then(Value::as_array).into_iter().flatten().filter_map(person).collect();
    let repo = s(p, &["urls", "Repository"]).or_else(|| s(p, &["urls", "Source"])).or_else(|| s(p, &["repository"]));
    Package {
        ecosystem: "python",
        name: s(p, &["name"]),
        version: s(p, &["version"]),
        description: s(p, &["description"]),
        license,
        authors,
        repository: repo,
    }
    .write(cx);
    if let Some(r) = s(p, &["requires-python"]) {
        cx.format_set("requires_python", r);
    }
    match p.get("dependencies") {
        Some(Value::Array(a)) => {
            let list: Vec<&str> = a.iter().filter_map(Value::as_str).take(MAX_DEPS).collect();
            cx.format_set("dependencies", json!(list));
            cx.format_set("dependencies_count", a.len());
        }
        other => put_deps(cx, "dependencies", deps(other)),
    }
    if let Some(Value::Object(groups)) = p.get("optional-dependencies") {
        cx.format_set("optional_dependency_groups", json!(groups.keys().collect::<Vec<_>>()));
    }
    if let Some(Value::Object(scripts)) = p.get("scripts") {
        cx.format_set("scripts", json!(scripts.keys().collect::<Vec<_>>()));
    }
    if let Some(b) = s(v, &["build-system", "build-backend"]) {
        cx.format_set("build_backend", b);
    }
    if let Some(Value::Object(tools)) = v.get("tool") {
        cx.format_set("tools", json!(tools.keys().collect::<Vec<_>>()));
    }
    if let Some(k) = p.get("keywords").and_then(Value::as_array) {
        for kw in k.iter().filter_map(Value::as_str) {
            cx.content().source("python.keywords").keyword(kw);
        }
    }
}

fn requirements(text: &str, cx: &mut Context<'_>) {
    cx.format_set("ecosystem", "python");
    let mut reqs = Vec::new();
    let (mut pinned, mut editable, mut hashes, mut includes) = (0u64, 0u64, false, Vec::new());
    for line in text.lines() {
        let line = line.split(" #").next().unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(index) = ["--index-url", "-i ", "--extra-index-url"].iter().find(|o| line.starts_with(**o)) {
            let url = line[index.len()..].trim_start_matches(['=', ' ']);
            cx.security().risk("custom_package_index", Some(crate::plugin::redact_secrets(url).into_owned()));
            continue;
        }
        if let Some(f) = line.strip_prefix("-r ").or_else(|| line.strip_prefix("--requirement ")) {
            includes.push(f.trim().to_string());
            continue;
        }
        if line.starts_with("-e ") || line.starts_with("--editable") {
            editable += 1;
            continue;
        }
        if line.starts_with('-') {
            continue;
        }
        hashes |= line.contains("--hash=");
        let spec = line.split(" --").next().unwrap_or(line).split(';').next().unwrap_or(line).trim();
        pinned += u64::from(spec.contains("=="));
        if reqs.len() < MAX_DEPS {
            reqs.push(spec.to_string());
        }
    }
    cx.format_set("requirements", json!(reqs));
    cx.format_set("dependencies_count", reqs.len());
    cx.format_set("pinned", pinned);
    if editable > 0 {
        cx.format_set("editable", editable);
    }
    if hashes {
        cx.format_set("hash_checking", true);
    }
    if !includes.is_empty() {
        cx.format_set("includes", json!(includes));
    }
}

fn go_mod(text: &str, cx: &mut Context<'_>) {
    let mut module = None;
    let mut go = None;
    let mut requires = Map::new();
    let (mut direct, mut indirect) = (0u64, 0u64);
    let mut replaces = Vec::new();
    let mut block: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or(raw).trim();
        let indirect_mark = raw.contains("// indirect");
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = if let Some(b) = &block {
            (b.as_str(), line)
        } else {
            let (d, r) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            if r.trim() == "(" {
                block = Some(d.to_string());
                continue;
            }
            (d, r.trim())
        };
        match directive {
            "module" => module = Some(rest.trim_matches('"').to_string()),
            "go" => go = Some(rest.to_string()),
            "toolchain" => cx.format_set("toolchain", rest),
            "require" => {
                let mut parts = rest.split_whitespace();
                if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
                    if indirect_mark {
                        indirect += 1;
                    } else {
                        direct += 1;
                    }
                    if requires.len() < MAX_DEPS {
                        requires.insert(m.to_string(), json!(v));
                    }
                }
            }
            "replace" => replaces.push(rest.to_string()),
            _ => {}
        }
    }
    Package {
        ecosystem: "go",
        name: module.as_deref(),
        version: None,
        description: None,
        license: None,
        authors: Vec::new(),
        repository: None,
    }
    .write(cx);
    if let Some(g) = go {
        cx.format_set("go_version", g);
    }
    cx.format_set("dependencies", Value::Object(requires));
    cx.format_set("dependencies_count", direct + indirect);
    cx.format_set("indirect_dependencies", indirect);
    if !replaces.is_empty() {
        cx.format_set("replace", json!(replaces.iter().take(50).collect::<Vec<_>>()));
    }
}

fn go_sum(text: &str, cx: &mut Context<'_>) {
    let modules: std::collections::BTreeSet<(&str, &str)> = text
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let (m, v) = (p.next()?, p.next()?);
            (!v.ends_with("/go.mod")).then_some((m, v))
        })
        .collect();
    cx.format_set("ecosystem", "go");
    cx.format_set("resolved_packages", modules.len());
}

/// Maven POM: coordinates, licences, dependencies, modules, plugins.
fn maven(text: &str, cx: &mut Context<'_>) {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = false;
    let mut path: Vec<String> = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut deps = Vec::new();
    let mut dep: BTreeMap<String, String> = BTreeMap::new();
    let (mut modules, mut plugins, mut licenses) = (Vec::new(), Vec::new(), Vec::new());
    let mut text_buf = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                path.push(e.local_name().as_ref().to_string());
                text_buf.clear();
            }
            Ok(Event::Text(t)) => text_buf.push_str(&t.xml10_content()),
            Ok(Event::End(_)) => {
                let p = path.join("/");
                let value = text_buf.trim().to_string();
                match p.as_str() {
                    "project/dependencies/dependency" => {
                        if deps.len() < MAX_DEPS {
                            let coord = format!(
                                "{}:{}",
                                dep.get("groupId").map_or("?", String::as_str),
                                dep.get("artifactId").map_or("?", String::as_str)
                            );
                            deps.push(json!({ "coordinate": coord, "version": dep.get("version"), "scope": dep.get("scope") }));
                        }
                        dep.clear();
                    }
                    "project/modules/module" => modules.push(value.clone()),
                    "project/build/plugins/plugin/artifactId" => plugins.push(value.clone()),
                    "project/licenses/license/name" => licenses.push(value.clone()),
                    _ => {}
                }
                if let Some(field) = p.strip_prefix("project/dependencies/dependency/") {
                    dep.insert(field.to_string(), value.clone());
                } else if path.len() <= 3 && !value.is_empty() && fields.len() < 100 {
                    fields.insert(p.clone(), value);
                }
                path.pop();
                text_buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    let get = |k: &str| fields.get(k).map(String::as_str);
    let group = get("project/groupId").or_else(|| get("project/parent/groupId"));
    let artifact = get("project/artifactId");
    let coord = match (group, artifact) {
        (Some(g), Some(a)) => Some(format!("{g}:{a}")),
        (None, Some(a)) => Some(a.to_string()),
        _ => None,
    };
    Package {
        ecosystem: "maven",
        name: coord.as_deref(),
        version: get("project/version").or_else(|| get("project/parent/version")),
        description: get("project/description"),
        license: licenses.first().map(String::as_str),
        authors: Vec::new(),
        repository: get("project/scm/url").or_else(|| get("project/url")),
    }
    .write(cx);
    if let Some(n) = get("project/name") {
        cx.content().source("maven.name").title(n);
    }
    if let Some(p) = get("project/packaging") {
        cx.format_set("packaging", p);
    }
    if let Some(p) = get("project/parent/artifactId") {
        cx.format_set("parent", format!("{}:{p}", get("project/parent/groupId").unwrap_or("?")));
    }
    let props: Map<String, Value> = fields
        .iter()
        .filter_map(|(k, v)| k.strip_prefix("project/properties/").map(|p| (p.to_string(), json!(v))))
        .take(50)
        .collect();
    if !props.is_empty() {
        cx.format_set("properties", Value::Object(props));
    }
    cx.format_set("dependencies_count", deps.len());
    cx.format_set("dependencies", Value::Array(deps));
    if !modules.is_empty() {
        cx.format_set("modules", json!(modules));
    }
    if !plugins.is_empty() {
        cx.format_set("plugins", json!(plugins));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(person(&json!("Ada Lovelace <ada@example.org> (https://ada.dev)")).as_deref(), Some("Ada Lovelace"));
        assert_eq!(snake("devDependencies"), "dev_dependencies");
        let (m, n) = deps(Some(&json!({ "serde": "1", "x": { "git": "https://g/x" }, "y": { "path": "../y" } })));
        assert_eq!((m["x"].clone(), n), (json!("git: https://g/x"), 3));
    }

    crate::fixture_tests!(
        "npm_package",
        "npm_lockfile",
        "cargo_manifest",
        "cargo_lockfile",
        "pyproject",
        "pip_requirements",
        "go_module",
        "go_sum",
        "maven_pom"
    );
}
