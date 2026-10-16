//! `physical.text` agrees with the system `wc` on every text fixture: lines,
//! words and bytes always; characters too for UTF-8 files when a UTF-8
//! locale is available. Skipped where `wc` is missing (Windows).

use std::path::Path;
use std::process::Command;

use whiff::Engine;

fn wc(path: &Path, flag: &str, locale: Option<&str>) -> Option<u64> {
    let mut cmd = Command::new("wc");
    cmd.arg(flag).arg(path);
    if let Some(l) = locale {
        cmd.env("LC_ALL", l);
    }
    let out = cmd.output().ok().filter(|o| o.status.success())?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().next()?.parse().ok()
}

/// A UTF-8 locale `wc -m` understands, if the system has one.
fn utf8_locale(sample: &Path) -> Option<&'static str> {
    // "é" is one character in a UTF-8 locale and two bytes otherwise.
    let probe = sample.with_file_name("utf8-probe.txt");
    std::fs::write(&probe, "é").ok()?;
    let found = ["C.UTF-8", "en_US.UTF-8", "C.utf8"].into_iter().find(|l| wc(&probe, "-m", Some(l)) == Some(1));
    let _ = std::fs::remove_file(probe);
    found
}

#[test]
fn counts_match_wc() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    if Command::new("wc").arg("-l").arg(fixtures.join("text/LICENSE")).output().is_err() {
        eprintln!("wc not available; skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let locale = utf8_locale(&tmp.path().join("x"));
    let engine = Engine::new();
    let mut checked = 0;
    for dir in std::fs::read_dir(&fixtures).unwrap().filter_map(Result::ok) {
        for file in std::fs::read_dir(dir.path()).unwrap().filter_map(Result::ok) {
            let path = file.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name == "SOURCE.md" || name.starts_with('.') {
                continue;
            }
            let report = engine.extract_path(&path).unwrap();
            let Some(text) = report.physical.text else { continue };
            for (flag, ours) in [("-l", text.lines), ("-w", text.words), ("-c", text.bytes)] {
                assert_eq!(ours, wc(&path, flag, locale), "wc {flag} {}", path.display());
            }
            let utf8 = std::fs::read(&path).is_ok_and(|b| std::str::from_utf8(&b).is_ok());
            if let (Some(l), true) = (locale, utf8) {
                assert_eq!(text.chars, wc(&path, "-m", Some(l)), "wc -m {}", path.display());
            }
            checked += 1;
        }
    }
    assert!(checked > 50, "only {checked} text fixtures checked");
}
