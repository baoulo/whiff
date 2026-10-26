//! Well-known document schemas recognised inside JSON, YAML and TOML:
//! what the configuration *is* and the handful of facts that matter for it.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::plugin::{Context, DateField, TextRole, parse_date, truncate_chars};

/// A detector for one known schema.
type Detector = fn(&Value, &str, &mut Context<'_>) -> Option<Value>;

/// Recognise a known schema in `docs` (one per YAML document). Writes title
/// and description when the schema has them and returns a summary for
/// `format.<id>.known_schema`.
pub(crate) fn detect(docs: &[Value], name: Option<&str>, cx: &mut Context<'_>) -> Option<Value> {
    let name = name.map(str::to_ascii_lowercase).unwrap_or_default();
    let first = docs.first()?;
    let detectors: [Detector; 13] = [
        openapi,
        json_schema,
        geojson,
        har,
        sarif,
        web_manifest,
        browser_extension,
        lottie,
        excalidraw,
        postman,
        compose,
        github_actions,
        helm_chart,
    ];
    if let Some(v) = kubernetes(docs) {
        return Some(v);
    }
    if let Some(v) = ansible(first) {
        return Some(v);
    }
    if let Some(v) = cloudformation(first) {
        return Some(v);
    }
    for d in detectors {
        if let Some(v) = d(first, &name, cx) {
            return Some(v);
        }
    }
    if let Some(v) = gitlab_ci(first, &name) {
        return Some(v);
    }
    if let Some(v) = conda(first, &name) {
        return Some(v);
    }
    json_ld(first).or_else(|| tsconfig(first, &name))
}

/// HTTP methods of `OpenAPI` path items.
const METHODS: [&str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

/// `GeoJSON` geometry types.
const GEOMETRIES: [&str; 7] =
    ["Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon", "GeometryCollection"];

/// Browser-extension permissions that reach every site or the browser itself.
const BROAD: [&str; 9] = [
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
    "tabs",
    "cookies",
    "webRequest",
    "debugger",
    "nativeMessaging",
];

/// Ansible task keys that are not module names.
const TASK_KEYS: [&str; 12] = [
    "name",
    "when",
    "register",
    "become",
    "tags",
    "with_items",
    "loop",
    "notify",
    "vars",
    "args",
    "ignore_errors",
    "delegate_to",
];

/// Top-level GitLab CI keys that are not jobs.
const RESERVED: [&str; 9] =
    ["stages", "variables", "include", "default", "workflow", "image", "services", "cache", "before_script"];

fn s<'v>(v: &'v Value, path: &[&str]) -> Option<&'v str> {
    get(v, path).and_then(Value::as_str)
}

fn get<'v>(v: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter().try_fold(v, |v, k| v.get(*k))
}

fn obj(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

fn len(v: Option<&Value>) -> usize {
    match v {
        Some(Value::Array(a)) => a.len(),
        Some(Value::Object(o)) => o.len(),
        _ => 0,
    }
}

fn keys(v: Option<&Value>, n: usize) -> Vec<String> {
    v.and_then(Value::as_object).map(|o| o.keys().take(n).cloned().collect()).unwrap_or_default()
}

fn title(cx: &mut Context<'_>, source: &str, t: Option<&str>, d: Option<&str>) {
    if let Some(t) = t {
        cx.content().source(source).title(t);
        cx.emit_text(TextRole::Title, t);
    }
    if let Some(d) = d {
        cx.content().source(source).description(truncate_chars(d, 1000));
        cx.emit_text(TextRole::Body, d);
    }
}

fn openapi(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let version = s(v, &["openapi"]).or_else(|| s(v, &["swagger"]))?;
    let paths = obj(v.get("paths")?)?;
    let mut operations: BTreeMap<&str, u64> = BTreeMap::new();
    let mut tags: BTreeMap<String, u64> = BTreeMap::new();
    for item in paths.values().filter_map(Value::as_object) {
        for (m, op) in item.iter().filter(|(m, _)| METHODS.contains(&m.as_str())) {
            *operations.entry(m.as_str()).or_default() += 1;
            for t in op.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                *tags.entry(t.to_string()).or_default() += 1;
            }
        }
    }
    title(cx, "openapi.info", s(v, &["info", "title"]), s(v, &["info", "description"]));
    if let Some(l) = s(v, &["info", "license", "name"]) {
        cx.rights().source("openapi.info.license").license(Some(l), s(v, &["info", "license", "url"]));
    }
    let servers: Vec<&str> = v.get("servers").and_then(Value::as_array).map_or_else(
        || s(v, &["host"]).into_iter().collect(),
        |a| a.iter().filter_map(|x| x.get("url").and_then(Value::as_str)).take(10).collect(),
    );
    let schemas = len(get(v, &["components", "schemas"]).or_else(|| v.get("definitions")));
    Some(json!({
        "id": "openapi",
        "name": if v.get("swagger").is_some() { "Swagger 2.0" } else { "OpenAPI" },
        "spec_version": version,
        "api_version": s(v, &["info", "version"]),
        "servers": servers,
        "paths": paths.len(),
        "operations": operations,
        "schemas": schemas,
        "security_schemes": keys(get(v, &["components", "securitySchemes"]).or_else(|| v.get("securityDefinitions")), 20),
        "tags": tags.keys().take(30).collect::<Vec<_>>(),
    }))
}

fn json_schema(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let schema = s(v, &["$schema"]).filter(|u| u.contains("json-schema.org"))?;
    title(cx, "json_schema", s(v, &["title"]), s(v, &["description"]));
    Some(json!({
        "id": "json_schema",
        "name": "JSON Schema",
        "draft": schema,
        "schema_id": s(v, &["$id"]).or_else(|| s(v, &["id"])),
        "type": v.get("type"),
        "properties": keys(v.get("properties"), 50),
        "required": v.get("required"),
        "definitions": len(v.get("$defs").or_else(|| v.get("definitions"))),
    }))
}

fn geojson(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let ty = s(v, &["type"])?;
    if ty == "Topology" && v.get("objects").is_some() {
        return Some(json!({ "id": "topojson", "name": "TopoJSON", "objects": keys(v.get("objects"), 50) }));
    }
    if ty != "FeatureCollection" && ty != "Feature" && !GEOMETRIES.contains(&ty) {
        return None;
    }
    if ty == "FeatureCollection" && !v.get("features").is_some_and(Value::is_array) {
        return None;
    }
    let features: Vec<&Value> = match v.get("features") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => vec![v],
    };
    let mut geometry: BTreeMap<String, u64> = BTreeMap::new();
    let mut props: BTreeMap<String, u64> = BTreeMap::new();
    for f in &features {
        let g = if ty == "Feature" || ty == "FeatureCollection" { f.get("geometry") } else { Some(*f) };
        if let Some(t) = g.and_then(|g| s(g, &["type"])) {
            *geometry.entry(t.to_string()).or_default() += 1;
        }
        for k in keys(f.get("properties"), 100) {
            *props.entry(k).or_default() += 1;
        }
    }
    Some(json!({
        "id": "geojson",
        "name": "GeoJSON",
        "type": ty,
        "features": features.len(),
        "geometry_types": geometry,
        "property_keys": props.keys().take(50).collect::<Vec<_>>(),
        "bbox": v.get("bbox"),
    }))
}

fn har(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let entries = get(v, &["log", "entries"])?.as_array()?;
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let mut status: BTreeMap<String, u64> = BTreeMap::new();
    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let mut times: Vec<(String, bool)> = Vec::new();
    for e in entries {
        if let Some(u) = s(e, &["request", "url"]) {
            let host = u.split("://").nth(1).and_then(|r| r.split(['/', '?', ':']).next()).unwrap_or("");
            *hosts.entry(host.to_ascii_lowercase()).or_default() += 1;
        }
        if let Some(m) = s(e, &["request", "method"]) {
            *methods.entry(m.to_string()).or_default() += 1;
        }
        if let Some(st) = get(e, &["response", "status"]) {
            *status.entry(st.to_string()).or_default() += 1;
        }
        if let Some(t) = s(e, &["startedDateTime"]).and_then(parse_date) {
            times.push(t);
        }
    }
    times.sort();
    if let Some((t, tz)) = times.first() {
        cx.temporal().source("har.startedDateTime").content_date(DateField::Created, t.clone(), *tz);
    }
    let mut top: Vec<(String, u64)> = hosts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(json!({
        "id": "har",
        "name": "HTTP Archive",
        "creator": s(v, &["log", "creator", "name"]),
        "browser": s(v, &["log", "browser", "name"]),
        "pages": len(get(v, &["log", "pages"])),
        "entries": entries.len(),
        "methods": methods,
        "status": status,
        "top_hosts": top.into_iter().take(10).map(|(h, n)| json!({ "host": h, "requests": n })).collect::<Vec<_>>(),
        "first_request": times.first().map(|t| &t.0),
        "last_request": times.last().map(|t| &t.0),
    }))
}

fn sarif(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let runs = v.get("runs")?.as_array()?;
    if !(s(v, &["$schema"]).is_some_and(|u| u.contains("sarif"))
        || s(v, &["version"]).is_some_and(|x| x.starts_with('2')))
    {
        return None;
    }
    let mut rules: BTreeMap<String, u64> = BTreeMap::new();
    let mut levels: BTreeMap<String, u64> = BTreeMap::new();
    let mut tools = Vec::new();
    let mut results = 0;
    for r in runs {
        if let Some(t) = s(r, &["tool", "driver", "name"]) {
            tools.push(t.to_string());
        }
        for res in r.get("results").and_then(Value::as_array).into_iter().flatten() {
            results += 1;
            if let Some(id) = s(res, &["ruleId"]) {
                *rules.entry(id.to_string()).or_default() += 1;
            }
            *levels.entry(s(res, &["level"]).unwrap_or("warning").to_string()).or_default() += 1;
        }
    }
    let mut top: Vec<(String, u64)> = rules.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Some(json!({
        "id": "sarif",
        "name": "SARIF static-analysis results",
        "version": s(v, &["version"]),
        "tools": tools,
        "results": results,
        "levels": levels,
        "top_rules": top.into_iter().take(10).map(|(r, n)| json!({ "rule": r, "results": n })).collect::<Vec<_>>(),
    }))
}

fn web_manifest(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let o = obj(v)?;
    let looks = o.contains_key("start_url") || (o.contains_key("icons") && o.contains_key("display"));
    if !looks || o.contains_key("manifest_version") {
        return None;
    }
    let _ = name;
    title(cx, "web_manifest.name", s(v, &["name"]), s(v, &["description"]));
    Some(json!({
        "id": "web_manifest",
        "name": "Web app manifest",
        "app_name": s(v, &["name"]),
        "short_name": s(v, &["short_name"]),
        "start_url": s(v, &["start_url"]),
        "display": s(v, &["display"]),
        "icons": len(v.get("icons")),
    }))
}

/// A WebExtension manifest's permissions (API and host), with the
/// broad-permission risk reported.
pub(crate) fn extension_permissions(v: &Value, cx: &mut Context<'_>) -> Vec<String> {
    let mut perms: Vec<String> = Vec::new();
    for key in ["permissions", "host_permissions", "optional_permissions"] {
        for p in v.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            perms.push(p.to_string());
        }
    }
    let broad: Vec<&String> = perms.iter().filter(|p| BROAD.contains(&p.as_str())).collect();
    if !broad.is_empty() {
        let detail = broad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        cx.security().risk("broad_extension_permissions", Some(detail));
    }
    perms
}

fn browser_extension(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    let mv = v.get("manifest_version")?.as_u64()?;
    let o = obj(v)?;
    if !(o.contains_key("permissions") || o.contains_key("background") || o.contains_key("content_scripts")) {
        return None;
    }
    let perms = extension_permissions(v, cx);
    title(cx, "extension.name", s(v, &["name"]).filter(|n| !n.starts_with("__MSG_")), s(v, &["description"]));
    Some(json!({
        "id": "browser_extension",
        "name": "Browser extension manifest",
        "extension_name": s(v, &["name"]),
        "version": s(v, &["version"]),
        "manifest_version": mv,
        "permissions": perms,
        "content_scripts": len(v.get("content_scripts")),
    }))
}

fn lottie(v: &Value, _: &str, _: &mut Context<'_>) -> Option<Value> {
    let o = obj(v)?;
    if !["v", "fr", "ip", "op", "layers"].iter().all(|k| o.contains_key(*k)) {
        return None;
    }
    let fr = v.get("fr").and_then(Value::as_f64).unwrap_or(0.0);
    let frames =
        v.get("op").and_then(Value::as_f64).unwrap_or(0.0) - v.get("ip").and_then(Value::as_f64).unwrap_or(0.0);
    Some(json!({
        "id": "lottie",
        "name": "Lottie animation",
        "version": s(v, &["v"]),
        "fps": fr,
        "frames": frames,
        "duration_s": if fr > 0.0 { Some((frames / fr * 1000.0).round() / 1000.0) } else { None },
        "width": v.get("w"),
        "height": v.get("h"),
        "layers": len(v.get("layers")),
    }))
}

fn excalidraw(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    if s(v, &["type"]) != Some("excalidraw") {
        return None;
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for e in v.get("elements").and_then(Value::as_array).into_iter().flatten() {
        if let Some(t) = s(e, &["type"]) {
            *kinds.entry(t.to_string()).or_default() += 1;
            if t == "text"
                && let Some(text) = s(e, &["text"])
            {
                cx.emit_text(TextRole::Body, text);
            }
        }
    }
    Some(json!({ "id": "excalidraw", "name": "Excalidraw drawing", "elements": kinds }))
}

fn postman(v: &Value, _: &str, cx: &mut Context<'_>) -> Option<Value> {
    s(v, &["info", "schema"]).filter(|u| u.contains("getpostman.com"))?;
    // Count requests in nested folders without recursion.
    let (mut requests, mut folders) = (0u64, 0u64);
    let mut stack: Vec<&Value> =
        v.get("item").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    while let Some(item) = stack.pop() {
        if let Some(children) = item.get("item").and_then(Value::as_array) {
            folders += 1;
            stack.extend(children.iter());
        } else if item.get("request").is_some() {
            requests += 1;
        }
    }
    title(cx, "postman.info", s(v, &["info", "name"]), s(v, &["info", "description"]));
    Some(json!({ "id": "postman", "name": "Postman collection", "requests": requests, "folders": folders }))
}

fn compose(v: &Value, name: &str, _: &mut Context<'_>) -> Option<Value> {
    let services = obj(v.get("services")?)?;
    let named = name.contains("compose");
    let looks = services.values().all(|s| s.get("image").is_some() || s.get("build").is_some());
    if !named && (!looks || services.is_empty()) {
        return None;
    }
    let mut images = Vec::new();
    let mut ports = Vec::new();
    for svc in services.values() {
        if let Some(i) = s(svc, &["image"]) {
            images.push(i.to_string());
        }
        for p in svc.get("ports").and_then(Value::as_array).into_iter().flatten() {
            ports.push(match p {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
    }
    Some(json!({
        "id": "docker_compose",
        "name": "Docker Compose",
        "services": services.keys().collect::<Vec<_>>(),
        "images": images,
        "ports": ports,
        "volumes": keys(v.get("volumes"), 30),
        "networks": keys(v.get("networks"), 30),
    }))
}

fn github_actions(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    let jobs = obj(v.get("jobs")?)?;
    let on = v.get("on")?;
    let _ = name;
    let triggers: Vec<String> = match on {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Value::Object(o) => o.keys().cloned().collect(),
        _ => Vec::new(),
    };
    let mut uses: BTreeMap<String, u64> = BTreeMap::new();
    let mut runs_on = Vec::new();
    for job in jobs.values() {
        if let Some(r) = job.get("runs-on") {
            runs_on.push(match r {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
        for step in job.get("steps").and_then(Value::as_array).into_iter().flatten() {
            if let Some(u) = s(step, &["uses"]) {
                *uses.entry(u.to_string()).or_default() += 1;
            }
        }
        if let Some(u) = s(job, &["uses"]) {
            *uses.entry(u.to_string()).or_default() += 1;
        }
    }
    if let Some(n) = s(v, &["name"]) {
        cx.content().source("workflow.name").title(n);
    }
    runs_on.dedup();
    Some(json!({
        "id": "github_actions",
        "name": "GitHub Actions workflow",
        "workflow": s(v, &["name"]),
        "triggers": triggers,
        "jobs": jobs.keys().collect::<Vec<_>>(),
        "runs_on": runs_on,
        "actions": uses.keys().take(50).collect::<Vec<_>>(),
        "permissions": v.get("permissions"),
    }))
}

fn helm_chart(v: &Value, name: &str, cx: &mut Context<'_>) -> Option<Value> {
    if !name.ends_with("chart.yaml") && !name.ends_with("chart.yml") {
        return None;
    }
    s(v, &["name"])?;
    title(cx, "chart.name", s(v, &["name"]), s(v, &["description"]));
    let deps: Vec<&str> = v
        .get("dependencies")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|d| d.get("name").and_then(Value::as_str)).collect())
        .unwrap_or_default();
    Some(json!({
        "id": "helm_chart",
        "name": "Helm chart",
        "chart": s(v, &["name"]),
        "version": s(v, &["version"]),
        "app_version": v.get("appVersion"),
        "api_version": s(v, &["apiVersion"]),
        "dependencies": deps,
    }))
}

fn kubernetes(docs: &[Value]) -> Option<Value> {
    let resources: Vec<&Value> = docs
        .iter()
        .flat_map(|d| match (s(d, &["kind"]), d.get("items")) {
            (Some("List"), Some(Value::Array(items))) => items.iter().collect::<Vec<_>>(),
            _ => vec![d],
        })
        .filter(|d| s(d, &["apiVersion"]).is_some() && s(d, &["kind"]).is_some())
        .collect();
    if resources.is_empty() {
        return None;
    }
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut images: Vec<String> = Vec::new();
    let mut list = Vec::new();
    for r in &resources {
        let kind = s(r, &["kind"]).unwrap_or_default();
        *kinds.entry(kind.to_string()).or_default() += 1;
        if list.len() < 50 {
            list.push(json!({
                "kind": kind,
                "name": s(r, &["metadata", "name"]),
                "namespace": s(r, &["metadata", "namespace"]),
            }));
        }
        // Containers sit at different depths per kind; search for them.
        let mut stack = vec![*r];
        while let Some(v) = stack.pop() {
            match v {
                Value::Object(o) => {
                    for (k, x) in o {
                        if (k == "containers" || k == "initContainers")
                            && let Value::Array(cs) = x
                        {
                            for c in cs {
                                if let Some(i) = s(c, &["image"])
                                    && !images.iter().any(|x| x == i)
                                    && images.len() < 50
                                {
                                    images.push(i.to_string());
                                }
                            }
                        } else {
                            stack.push(x);
                        }
                    }
                }
                Value::Array(a) => stack.extend(a.iter()),
                _ => {}
            }
        }
    }
    Some(
        json!({ "id": "kubernetes", "name": "Kubernetes manifest", "kinds": kinds, "resources": list, "images": images }),
    )
}

fn ansible(v: &Value) -> Option<Value> {
    let plays = v.as_array()?;
    let is_play = |p: &Value| p.get("hosts").is_some() && (p.get("tasks").is_some() || p.get("roles").is_some());
    if plays.is_empty() || !plays.iter().all(|p| is_play(p) || p.get("import_playbook").is_some()) {
        return None;
    }
    let mut modules: BTreeMap<String, u64> = BTreeMap::new();
    let mut roles = Vec::new();
    let mut hosts = Vec::new();
    for p in plays {
        if let Some(h) = p.get("hosts") {
            hosts.push(h.clone());
        }
        for r in p.get("roles").and_then(Value::as_array).into_iter().flatten() {
            roles.push(
                r.as_str().map(str::to_string).or_else(|| s(r, &["role"]).map(str::to_string)).unwrap_or_default(),
            );
        }
        for t in p.get("tasks").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
            if let Some(m) = t.keys().find(|k| !TASK_KEYS.contains(&k.as_str())) {
                *modules.entry(m.clone()).or_default() += 1;
            }
        }
    }
    Some(
        json!({ "id": "ansible_playbook", "name": "Ansible playbook", "plays": plays.len(), "hosts": hosts, "roles": roles, "modules": modules }),
    )
}

fn cloudformation(v: &Value) -> Option<Value> {
    let resources = obj(v.get("Resources")?)?;
    let typed = resources.values().filter_map(|r| s(r, &["Type"])).filter(|t| t.contains("::")).count();
    if v.get("AWSTemplateFormatVersion").is_none() && typed == 0 {
        return None;
    }
    let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
    for r in resources.values() {
        if let Some(t) = s(r, &["Type"]) {
            *by_type.entry(t.to_string()).or_default() += 1;
        }
    }
    Some(json!({
        "id": "cloudformation",
        "name": if v.get("Transform").is_some() { "AWS SAM template" } else { "AWS CloudFormation template" },
        "description": s(v, &["Description"]),
        "resources": by_type,
        "parameters": keys(v.get("Parameters"), 50),
        "outputs": keys(v.get("Outputs"), 50),
    }))
}

fn gitlab_ci(v: &Value, name: &str) -> Option<Value> {
    if !name.ends_with(".gitlab-ci.yml") && !name.ends_with(".gitlab-ci.yaml") {
        return None;
    }
    let o = obj(v)?;
    let jobs: Vec<&String> = o
        .iter()
        .filter(|(k, j)| !RESERVED.contains(&k.as_str()) && !k.starts_with('.') && j.is_object())
        .map(|(k, _)| k)
        .collect();
    Some(json!({ "id": "gitlab_ci", "name": "GitLab CI pipeline", "stages": v.get("stages"), "jobs": jobs }))
}

fn conda(v: &Value, name: &str) -> Option<Value> {
    let deps = v.get("dependencies")?.as_array()?;
    if !(name.starts_with("environment") || v.get("channels").is_some()) {
        return None;
    }
    Some(
        json!({ "id": "conda_environment", "name": "conda environment", "env": s(v, &["name"]), "channels": v.get("channels"), "dependencies": deps.len() }),
    )
}

fn json_ld(v: &Value) -> Option<Value> {
    v.get("@context")?;
    let types: Vec<&Value> = match v.get("@graph") {
        Some(Value::Array(g)) => g.iter().filter_map(|n| n.get("@type")).take(20).collect(),
        _ => v.get("@type").into_iter().collect(),
    };
    Some(json!({ "id": "json_ld", "name": "JSON-LD", "types": types }))
}

fn tsconfig(v: &Value, name: &str) -> Option<Value> {
    let opts = v.get("compilerOptions")?;
    if !name.starts_with("tsconfig") && !name.starts_with("jsconfig") && v.get("include").is_none() {
        return None;
    }
    Some(json!({
        "id": "tsconfig",
        "name": "TypeScript project config",
        "target": s(opts, &["target"]),
        "module": s(opts, &["module"]),
        "strict": opts.get("strict"),
        "extends": v.get("extends"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_images() {
        let docs = [json!({
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": { "name": "web" },
            "spec": { "template": { "spec": { "containers": [{ "image": "nginx:1.27" }] } } }
        })];
        let k = kubernetes(&docs).unwrap();
        assert_eq!(k["images"], json!(["nginx:1.27"]));
        assert_eq!(k["kinds"]["Deployment"], 1);
    }
}
