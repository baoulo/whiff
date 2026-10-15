//! CI checks: dependency budgets and the plugin boundary.

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
    if ok {
        Ok(())
    } else {
        Err("dependency budget exceeded; justify it in the PR and raise the budget in src/bin/whiff-dev/checks.rs"
            .into())
    }
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
