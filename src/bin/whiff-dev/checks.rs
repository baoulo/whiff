//! CI checks: dependency budgets, pure Rust, and the plugin boundary.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Transitive normal-dependency budgets (see the plan, §4.2).
const LIB_COMMON_BUDGET: usize = 185;
const DEFAULT_BUDGET: usize = 200;
const SPECIALIST_EXTRA_BUDGET: usize = 60;
const SPECIALIST: [&str; 6] = ["geo", "science", "data", "cad", "forensics", "games"];

fn dependencies(root: &Path, features: Option<&str>) -> Result<BTreeSet<String>, String> {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root).args(["tree", "-e", "normal", "--prefix", "none", "--format", "{p}"]);
    if let Some(f) = features {
        cmd.args(["--no-default-features", "--features", f]);
    }
    let out = cmd.output().map_err(|e| format!("cargo tree: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo tree failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_end_matches(" (*)").trim())
        .filter(|l| !l.is_empty() && !l.starts_with("whiff "))
        .map(|l| l.split(" (").next().unwrap_or(l).to_string())
        .collect())
}

pub fn deps(root: &Path) -> Result<(), String> {
    let mut ok = true;
    let mut report = |label: &str, n: usize, budget: usize| {
        let verdict = if n <= budget { "ok" } else { "OVER BUDGET" };
        println!("{label:<34} {n:>4} / {budget:<4} {verdict}");
        ok &= n <= budget;
    };
    let common = dependencies(root, Some("common"))?;
    report("library, `common`", common.len(), LIB_COMMON_BUDGET);
    report("default (`common` + `cli`)", dependencies(root, None)?.len(), DEFAULT_BUDGET);
    for f in SPECIALIST {
        let with = dependencies(root, Some(&format!("common,{f}")))?;
        report(&format!("`{f}` (extra over common)"), with.difference(&common).count(), SPECIALIST_EXTRA_BUDGET);
    }
    pure_rust(root)?;
    if ok {
        Ok(())
    } else {
        Err("dependency budget exceeded; justify it in the PR and raise the budget in src/bin/whiff-dev/checks.rs"
            .into())
    }
}

/// Crates that build or link native code. Their presence in the library or
/// tool's dependency graph breaks the pure-Rust rule.
const NATIVE_BUILD_CRATES: [&str; 6] = ["cc", "cmake", "bindgen", "pkg-config", "vcpkg", "autotools"];

/// Native-build crates allowed with a reason, if the dependent enables the
/// listed feature: (dependent, crate, required feature of the dependent).
const NATIVE_ALLOWED: [(&str, &str, &str); 1] = [
    // blake3 always declares `cc` for its build script, which compiles C and
    // assembly only without `pure`.
    ("blake3", "cc", "pure"),
];

/// `-sys` crates that are pure-Rust declarations of the operating system's
/// own interfaces (what `std` itself calls), not bindings to a C library.
const OS_API_CRATES: [&str; 2] = ["linux-raw-sys", "windows-sys"];

/// whiff as a library or tool must be pure Rust: no `-sys` crates other than
/// the OS interfaces, and no native build tools (see CONTRIBUTING.md).
/// Development tooling (scripts/, the fixture generators) may use anything.
pub fn pure_rust(root: &Path) -> Result<(), String> {
    use serde_json::Value;
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--all-features", "--locked"])
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let meta: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
    let packages: std::collections::BTreeMap<&str, &Value> =
        meta["packages"].as_array().into_iter().flatten().filter_map(|p| Some((p["id"].as_str()?, p))).collect();
    let nodes: std::collections::BTreeMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let name = |id: &str| packages.get(id).and_then(|p| p["name"].as_str()).unwrap_or(id).to_string();
    let root_id = meta["resolve"]["root"].as_str().ok_or("cargo metadata: no root package")?;
    // Walk normal and build edges only: dev-dependencies never ship.
    let mut seen = BTreeSet::new();
    let mut stack = vec![root_id];
    let mut problems = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(node) = nodes.get(id) else { continue };
        let features: Vec<&str> = node["features"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        for dep in node["deps"].as_array().into_iter().flatten() {
            let shipped = dep["dep_kinds"].as_array().into_iter().flatten().any(|k| k["kind"].as_str() != Some("dev"));
            let Some(dep_id) = dep["pkg"].as_str().filter(|_| shipped) else { continue };
            let (parent, child) = (name(id), name(dep_id));
            if NATIVE_BUILD_CRATES.contains(&child.as_str()) {
                let allowed =
                    NATIVE_ALLOWED.iter().any(|(p, c, f)| *p == parent && *c == child && features.contains(f));
                if !allowed {
                    problems.push(format!("{parent} -> {child}: native build tool"));
                }
            }
            stack.push(dep_id);
        }
    }
    // `links =` alone is not native code (pure-Rust crates such as
    // rayon-core use it to stay unique), so the check is on `-sys` crates.
    for id in seen.iter().filter(|id| **id != root_id) {
        let n = name(id);
        if (n.ends_with("-sys") || n.ends_with("_sys")) && !OS_API_CRATES.contains(&n.as_str()) {
            problems.push(format!("{n}: bindings to a native library"));
        }
    }
    println!("pure Rust: {} crates checked (all features, normal and build dependencies)", seen.len() - 1);
    if problems.is_empty() { Ok(()) } else { Err(format!("whiff must stay pure Rust:\n  {}", problems.join("\n  "))) }
}

/// Paths format modules may use: the plugin API and the crate's exported macros.
fn allowed(rest: &str) -> bool {
    ["plugin", "register_extractor!", "register_block_decoder!", "register_analyzer!", "fixture_tests!"]
        .iter()
        .any(|p| rest.starts_with(p))
}

pub fn boundary(root: &Path) -> Result<(), String> {
    let mut violations = Vec::new();
    let mut stack = vec![root.join("src/formats")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for prefix in ["crate::", "whiff::"] {
                    for (i, _) in code.match_indices(prefix) {
                        if !allowed(&code[i + prefix.len()..]) {
                            violations.push(format!(
                                "{}:{}: {}",
                                path.strip_prefix(root).unwrap_or(&path).display(),
                                n + 1,
                                line.trim()
                            ));
                        }
                    }
                }
            }
        }
    }
    if violations.is_empty() {
        println!("plugin boundary: ok (format modules use only crate::plugin)");
        Ok(())
    } else {
        Err(format!("format modules must import only `crate::plugin::*`:\n{}", violations.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::allowed;

    #[test]
    fn boundary_rules() {
        assert!(allowed("plugin::{Context, Extractor};"));
        assert!(allowed("register_extractor!(Qoi);"));
        assert!(!allowed("engine::pipeline"));
        assert!(!allowed("io::FileSource"));
    }
}
