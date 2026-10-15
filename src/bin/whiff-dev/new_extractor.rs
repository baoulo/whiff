//! `whiff-dev new-extractor`: scaffold a format extractor.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::catalogue::load_families;

pub struct Request {
    pub id: String,
    pub family: String,
    pub name: String,
    pub extensions: Vec<String>,
    pub mimes: Vec<String>,
    pub magic: Vec<String>,
    pub dry_run: bool,
    pub force: bool,
}

const MARKER: &str = "// whiff-dev: group modules below this line";

fn valid_ident(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn camel(s: &str) -> String {
    s.split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect()
}

/// `66747970` or `4:66747970` (offset:hex) → `Magic::prefix(b"...")` / `Magic::at(4, b"...")`.
fn magic_expr(spec: &str) -> Result<String, String> {
    let (offset, hex) = match spec.split_once(':') {
        Some((o, h)) => (o.parse::<usize>().map_err(|_| format!("bad magic offset in `{spec}`"))?, h),
        None => (0, spec),
    };
    let hex = hex.trim_start_matches("0x");
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(format!("magic `{spec}` must be an even number of hex digits"));
    }
    let mut lit = String::from("b\"");
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("bad hex in magic `{spec}`"))?;
        if b.is_ascii_alphanumeric() || b == b' ' {
            lit.push(char::from(b));
        } else {
            let _ = write!(lit, "\\x{b:02x}");
        }
    }
    lit.push('"');
    Ok(if offset == 0 { format!("Magic::prefix({lit})") } else { format!("Magic::at({offset}, {lit})") })
}

fn quoted(items: &[String]) -> String {
    items.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")
}

fn render_template(r: &Request, group: &str, format: &str) -> Result<String, String> {
    let magic: Vec<String> = r.magic.iter().map(|m| magic_expr(m)).collect::<Result<_, _>>()?;
    let mut imports =
        vec!["ByteReader", "Context", "Cost", "ExtractError", "Extractor", "ExtractorMeta", "FormatSpec", "Source"];
    if !magic.is_empty() {
        imports.push("Magic");
    }
    imports.sort_unstable();
    Ok(include_str!("template.rs.txt")
        .replace("{{imports}}", &imports.join(", "))
        .replace("{{struct}}", &camel(format))
        .replace("{{id}}", &r.id)
        .replace("{{group}}", group)
        .replace("{{format}}", format)
        .replace("{{name}}", &r.name.replace('"', "\\\""))
        .replace("{{family}}", &r.family)
        .replace("{{mimes}}", &quoted(&r.mimes))
        .replace("{{extensions}}", &quoted(&r.extensions))
        .replace("{{magic}}", &magic.join(", ")))
}

enum Change {
    Create(PathBuf, String),
    Replace(PathBuf, String),
}

pub fn run(root: &Path, r: &Request) -> Result<(), String> {
    let (group, format) = r.id.split_once('.').ok_or("id must be `<group>.<format>`, e.g. `image.qoi`")?;
    if !valid_ident(group) || !valid_ident(format) {
        return Err("group and format must be lowercase snake_case identifiers".into());
    }
    let families = load_families(root)?;
    let family = families
        .iter()
        .find(|f| f.id == r.family)
        .ok_or_else(|| format!("unknown family `{}` (see data/families.tsv)", r.family))?;
    let feature = family.feature.as_str();
    if r.extensions.is_empty() && r.magic.is_empty() {
        return Err("give at least one --ext or --magic, otherwise the format can never be detected".into());
    }

    let formats_dir = root.join("src/formats");
    let group_dir = formats_dir.join(group);
    let file = group_dir.join(format!("{format}.rs"));
    let mut changes = Vec::new();

    if file.exists() && !r.force {
        return Err(format!("{} already exists (use --force to overwrite)", file.display()));
    }
    changes.push(Change::Create(file.clone(), render_template(r, group, format)?));

    // src/formats/<group>/mod.rs
    let group_mod = group_dir.join("mod.rs");
    let mod_line = format!("pub(crate) mod {format};");
    match std::fs::read_to_string(&group_mod) {
        Ok(text) if text.lines().any(|l| l.trim() == mod_line) => {}
        Ok(text) => changes.push(Change::Replace(group_mod.clone(), format!("{}{mod_line}\n", ensure_newline(&text)))),
        Err(_) => changes.push(Change::Create(
            group_mod.clone(),
            format!("//! `{group}` extractors (feature `{feature}`).\n\n{mod_line}\n"),
        )),
    }

    // src/formats/mod.rs: `#[cfg(feature = "...")] mod <group>;`
    let top = formats_dir.join("mod.rs");
    let text = std::fs::read_to_string(&top).map_err(|e| format!("{}: {e}", top.display()))?;
    let group_line = format!("pub(crate) mod {group};");
    if let Some(pos) = text.lines().position(|l| l.trim() == group_line) {
        let cfg = text.lines().nth(pos.wrapping_sub(1)).unwrap_or("");
        let expected = format!("#[cfg(feature = \"{feature}\")]");
        if cfg.trim() != expected {
            return Err(format!(
                "group `{group}` is gated by `{}` but family `{}` belongs to feature `{feature}`; choose another group",
                cfg.trim(),
                r.family
            ));
        }
    } else {
        if !text.contains(MARKER) {
            return Err(format!("{} lacks the line `{MARKER}`", top.display()));
        }
        changes.push(Change::Replace(
            top,
            format!("{}#[cfg(feature = \"{feature}\")]\n{group_line}\n", ensure_newline(&text)),
        ));
    }

    let source_md = root.join("tests/fixtures").join(format).join("SOURCE.md");
    if !source_md.exists() {
        changes.push(Change::Create(
            source_md,
            format!(
                "# Fixtures for `{format}` ({})\n\nList every sample file: where it came from and its licence.\nFiles must be ≤ 256 KiB and redistributable (self-made, CC0 or permissive).\n\n| File | Origin | Licence |\n|---|---|---|\n",
                r.name
            ),
        ));
    }

    for change in &changes {
        let (path, body, verb) = match change {
            Change::Create(p, b) => (p, b, "create"),
            Change::Replace(p, b) => (p, b, "update"),
        };
        println!("{verb} {}", path.strip_prefix(root).unwrap_or(path).display());
        if !r.dry_run {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    println!(
        "\nNext:\n  1. implement `extract` in {}\n  2. add samples to tests/fixtures/{format}/ and fill in SOURCE.md\n  3. INSTA_UPDATE=always cargo test --features full   (then review tests/snapshots/{format}__*.snap)\n  4. cargo run --features dev --bin whiff-dev -- catalogue",
        file.strip_prefix(root).unwrap_or(&file).display()
    );
    Ok(())
}

fn ensure_newline(s: &str) -> String {
    if s.is_empty() || s.ends_with('\n') { s.to_string() } else { format!("{s}\n") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_literals() {
        assert_eq!(magic_expr("716f6966").unwrap(), "Magic::prefix(b\"qoif\")");
        assert_eq!(magic_expr("4:66747970").unwrap(), "Magic::at(4, b\"ftyp\")");
        assert_eq!(magic_expr("ffd8ff").unwrap(), "Magic::prefix(b\"\\xff\\xd8\\xff\")");
        assert!(magic_expr("abc").is_err());
    }

    #[test]
    fn names() {
        assert_eq!(camel("qoi"), "Qoi");
        assert_eq!(camel("tar_gz"), "TarGz");
        assert!(valid_ident("jpeg2000") && !valid_ident("Jpeg") && !valid_ident("2x"));
    }
}
