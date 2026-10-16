//! End-to-end tests of the `whiff` binary.
#![cfg(feature = "cli")]

use std::process::Command;

fn whiff() -> Command {
    Command::new(env!("CARGO_BIN_EXE_whiff"))
}

fn json(out: &[u8]) -> serde_json::Value {
    serde_json::from_slice(out).unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", String::from_utf8_lossy(out)))
}

#[test]
fn single_file_report_has_all_sections() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("note.txt");
    std::fs::write(&p, "hello whiff\n").unwrap();
    let out = whiff().arg(&p).output().unwrap();
    assert!(out.status.success());
    let v = json(&out.stdout);
    assert_eq!(v["whiff"]["schema"], "whiff/1");
    for section in [
        "whiff",
        "source",
        "identification",
        "system",
        "temporal",
        "security",
        "rights",
        "physical",
        "integrity",
        "content",
        "metadata",
        "format",
        "diagnostics",
    ] {
        assert!(v.get(section).is_some(), "missing section {section}");
    }
    assert_eq!(v["identification"]["format"], "text");
    assert_eq!(v["system"]["size_bytes"], 12);
    assert_eq!(v["integrity"]["sha256"], "064ca168ef3dd032948160e1d97a865ec7d9bbe00b2bf0dfdf2b541ff79cdad7");
}

#[test]
fn directories_produce_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a.txt", "b.bin", "sub/c.txt"] {
        let p = dir.path().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, name).unwrap();
    }
    std::fs::write(dir.path().join(".hidden"), "x").unwrap();
    let out = whiff().arg(dir.path()).output().unwrap();
    assert!(out.status.success());
    let lines: Vec<_> = out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "hidden files skipped by default");
    for l in lines {
        assert_eq!(json(l)["whiff"]["schema"], "whiff/1");
    }
    let out = whiff().arg("--hidden").arg(dir.path()).output().unwrap();
    assert_eq!(out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count(), 4);
}

#[test]
fn stdin_and_options() {
    use std::io::Write;
    let mut child = whiff()
        .args(["-", "--hash", "blake3", "--profile", "minimal"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"from stdin").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v = json(&out.stdout);
    assert_eq!(v["whiff"]["profile"], "minimal");
    assert_eq!(v["system"]["kind"], "memory");
    assert!(v["source"].get("name").is_none(), "stdin has no name");
    assert!(v["integrity"]["sha256"].is_null());
}

#[test]
fn missing_file_fails_but_others_still_print() {
    let dir = tempfile::tempdir().unwrap();
    let ok = dir.path().join("ok.txt");
    std::fs::write(&ok, "fine").unwrap();
    let out = whiff().arg(&ok).arg(dir.path().join("missing.txt")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing.txt"));
    assert_eq!(out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count(), 1);
}

#[test]
fn schema_and_formats_subcommands() {
    let out = whiff().arg("schema").output().unwrap();
    assert!(out.status.success());
    assert_eq!(json(&out.stdout)["title"], "Report");
    let out = whiff().args(["formats", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(json(&out.stdout).is_array());
}

#[test]
fn llm_profile_prints_the_compact_view() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("guide.md");
    let body = "The harbour is where the fishing boats come home at dusk every evening. ".repeat(20);
    std::fs::write(&p, format!("# Harbour guide\n\n{body}\n\n## Boats\n\nMore about boats.\n")).unwrap();
    let out = whiff().args(["--profile", "llm", "--max-tokens", "300"]).arg(&p).output().unwrap();
    assert!(out.status.success());
    let v = json(&out.stdout);
    assert_eq!(v["title"], "Harbour guide");
    assert_eq!(v["format"], "Markdown (markdown)");
    assert_eq!(v["language"], "en");
    assert!(v.get("whiff").is_none(), "not the full report");
    assert!(out.stdout.len() <= 300 * 4 + 64, "{} bytes", out.stdout.len());
}

#[test]
fn bad_arguments_are_usage_errors() {
    let out = whiff().args(["--profile", "huge", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = whiff().args(["--timeout", "5 years", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
