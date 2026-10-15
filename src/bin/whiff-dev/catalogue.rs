//! `whiff-dev catalogue`: regenerate `docs/metadata-extracted.md` from
//! `data/families.tsv`, `data/formats.tsv`, `data/catalogue-header.md` and the
//! extractors compiled into this build (the "Extractor" column).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use whiff::Registry;

pub struct Family {
    pub id: String,
    pub category: String,
    pub feature: String,
    pub status: String,
    pub stage: String,
    pub information: String,
    pub llm_value: String,
    pub libraries: String,
}

pub struct Format {
    pub tier: u8,
    pub family: String,
    pub name: String,
    pub extensions: String,
    pub mime: String,
    pub note: String,
    pub order: usize,
}

fn rows(path: &Path, columns: usize) -> Result<Vec<Vec<String>>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let cells: Vec<String> = line.split('\t').map(str::to_string).collect();
        if cells.len() != columns {
            return Err(format!(
                "{}:{}: expected {columns} tab-separated columns, found {}",
                path.display(),
                n + 1,
                cells.len()
            ));
        }
        out.push(cells);
    }
    Ok(out)
}

pub fn load_families(root: &Path) -> Result<Vec<Family>, String> {
    rows(&root.join("data/families.tsv"), 8).map(|rows| {
        rows.into_iter()
            .map(|c| {
                let mut c = c.into_iter();
                let mut next = || c.next().unwrap_or_default();
                Family {
                    id: next(),
                    category: next(),
                    feature: next(),
                    status: next(),
                    stage: next(),
                    information: next(),
                    llm_value: next(),
                    libraries: next(),
                }
            })
            .collect()
    })
}

pub fn load_formats(root: &Path, families: &[Family]) -> Result<Vec<Format>, String> {
    let mut out = Vec::new();
    for (order, c) in rows(&root.join("data/formats.tsv"), 6)?.into_iter().enumerate() {
        let tier: u8 = c[0].parse().map_err(|_| format!("formats.tsv row {}: bad tier `{}`", order + 1, c[0]))?;
        if !families.iter().any(|f| f.id == c[1]) {
            return Err(format!("formats.tsv row {}: unknown family `{}`", order + 1, c[1]));
        }
        out.push(Format {
            tier,
            family: c[1].clone(),
            name: c[2].clone(),
            extensions: c[3].clone(),
            mime: c[4].clone(),
            note: c[5].clone(),
            order,
        });
    }
    Ok(out)
}

fn esc(s: &str) -> String {
    s.replace('<', "&lt;").replace('>', "&gt;").replace('|', "\\|")
}

fn stage_rank(stage: &str) -> u8 {
    stage.get(1..2).and_then(|d| d.parse().ok()).unwrap_or(9)
}

fn stage_for(f: &Format, fam: &Family) -> String {
    let note = f.note.to_lowercase();
    if f.tier == 3 && (fam.status == "impl" || note.contains("header") || note.contains("impl")) {
        return "S8".into();
    }
    if f.tier == 1 { fam.stage.split('/').next().unwrap_or(&fam.stage).to_string() } else { fam.stage.clone() }
}

fn exts_md(e: &str) -> String {
    if e.is_empty() {
        return "—".into();
    }
    e.split_whitespace().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(" ")
}

fn short_lib(lib: &str) -> String {
    let first = lib.split(';').next().unwrap_or("");
    let first = first.split(" (").next().unwrap_or("");
    first.split(", ").take(2).collect::<Vec<_>>().join(", ")
}

/// Counts in first-seen order, then sorted by count (stable), like Python's `Counter.most_common`.
fn most_common<'a>(items: impl Iterator<Item = &'a str>) -> Vec<(&'a str, usize)> {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for item in items {
        match counts.iter_mut().find(|(k, _)| *k == item) {
            Some((_, n)) => *n += 1,
            None => counts.push((item, 1)),
        }
    }
    counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    counts
}

/// Extractor covering a catalogue row: same family and a shared extension.
fn coverage(registry: &Registry, f: &Format) -> Option<&'static str> {
    let exts: Vec<String> = f.extensions.split_whitespace().map(str::to_ascii_lowercase).collect();
    registry
        .formats()
        .find(|(spec, _)| spec.family == f.family && spec.extensions.iter().any(|e| exts.iter().any(|x| x == e)))
        .map(|(_, e)| e.meta().id)
}

pub fn render(root: &Path, registry: &Registry) -> Result<String, String> {
    let families = load_families(root)?;
    let formats = load_formats(root, &families)?;
    let header = std::fs::read_to_string(root.join("data/catalogue-header.md"))
        .map_err(|e| format!("catalogue-header.md: {e}"))?;
    let fam: HashMap<&str, (usize, &Family)> =
        families.iter().enumerate().map(|(i, f)| (f.id.as_str(), (i, f))).collect();

    let mut rows: Vec<&Format> = formats.iter().collect();
    rows.sort_by_key(|r| {
        let (idx, f) = fam[r.family.as_str()];
        (r.tier, stage_rank(&f.stage), idx, r.order)
    });

    let mut out: Vec<String> = vec![header.trim_end().to_string() + "\n", "\n## 3. Parser families\n".into()];
    out.push("Each format in §5 maps to one **family**. A family is one extractor implementation (or one reusable *block decoder*, marked `Block`) that serves every format in it. This is why ~1000 formats need ~60 extractors.\n".into());
    out.push("Status: **crate** means a pure-Rust crate does the heavy lifting. **mixed** means a crate parses the container and whiff maps it to the schema. **impl** means no suitable pure-Rust crate exists, so whiff implements the parser.\n".into());
    out.push("| Family | Category | Feature | Information extracted | Why it helps an LLM | Library / implementation | Status | Stage | # formats |".into());
    out.push("|---|---|---|---|---|---|---|---|---|".into());
    for f in &families {
        let n = rows.iter().filter(|r| r.family == f.id).count();
        out.push(format!(
            "| `{}` | {} | `{}` | {} | {} | {} | {} | {} | {n} |",
            f.id,
            f.category,
            f.feature,
            esc(&f.information),
            esc(&f.llm_value),
            esc(&f.libraries),
            f.status,
            f.stage
        ));
    }

    out.push("\n## 4. Coverage summary\n".into());
    let tier = |t: u8| rows.iter().filter(|r| r.tier == t).count();
    out.push(format!(
        "* **{} formats** in total: tier 1 = {}, tier 2 = {}, tier 3 = {}.",
        rows.len(),
        tier(1),
        tier(2),
        tier(3)
    ));
    let covered = rows.iter().filter(|r| coverage(registry, r).is_some()).count();
    out.push(format!("* Formats with an extractor in this build: **{covered}** of {}.", rows.len()));
    let status = |s: &str| rows.iter().filter(|r| fam[r.family.as_str()].1.status == s).count();
    out.push(format!(
        "* Formats by family status: crate = {}, mixed = {}, impl = {}.",
        status("crate"),
        status("mixed"),
        status("impl")
    ));
    let mut stages: Vec<(String, usize)> = Vec::new();
    for r in &rows {
        let s = stage_for(r, fam[r.family.as_str()].1);
        match stages.iter_mut().find(|(k, _)| *k == s) {
            Some((_, n)) => *n += 1,
            None => stages.push((s, 1)),
        }
    }
    stages.sort();
    out.push(format!(
        "* Formats by target stage: {}.",
        stages.iter().map(|(k, n)| format!("{k} = {n}")).collect::<Vec<_>>().join(", ")
    ));
    let features = most_common(rows.iter().map(|r| fam[r.family.as_str()].1.feature.as_str()));
    out.push(format!(
        "* By feature: {}.",
        features.iter().map(|(k, n)| format!("`{k}` = {n}")).collect::<Vec<_>>().join(", ")
    ));
    let cats = most_common(rows.iter().map(|r| fam[r.family.as_str()].1.category.as_str()));
    out.push(format!(
        "* By category: {}.\n",
        cats.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ")
    ));

    out.push("## 5. Format table\n".into());
    out.push("`#` is the position after sorting by tier, then by stage and family. **Tier 1** is the ~140 formats a general-purpose tool meets every day. **Tier 2** is common in professional or specialist work. **Tier 3** is the long tail. Ordering inside a tier is by family, not a fine-grained popularity rank. \"Stage\" is the implementation stage (S0–S8) in the implementation plan. \"Feature\" is the cargo feature of the `whiff` crate that compiles the extractor: `common` is on by default; `geo`, `science`, `data`, `cad`, `forensics` and `games` are opt-in (`full` enables all). \"Extractor\" is the extractor that handles the format today (`—` = not implemented yet). Tier-3 formats are scheduled for S8, the long-tail stage, when they need an in-house parser (impl family, or the notes say \"header\" / \"impl\").\n".into());
    out.push("| # | Format | Extensions | MIME | Tier | Family | Feature | Extractor | Library | Stage | Format-specific extras |".into());
    out.push("|---|---|---|---|---|---|---|---|---|---|---|".into());
    for (n, r) in rows.iter().enumerate() {
        let f = fam[r.family.as_str()].1;
        let ext = coverage(registry, r).map_or_else(|| "—".to_string(), |id| format!("`{id}`"));
        let mut line = String::new();
        let _ = write!(
            line,
            "| {} | {} | {} | {} | {} | `{}` | `{}` | {ext} | {} | {} | {} |",
            n + 1,
            esc(&r.name),
            exts_md(&r.extensions),
            if r.mime.is_empty() { "—".to_string() } else { esc(&r.mime) },
            r.tier,
            r.family,
            f.feature,
            esc(&short_lib(&f.libraries)),
            stage_for(r, f),
            if r.note.is_empty() { "—".to_string() } else { esc(&r.note) },
        );
        out.push(line);
    }
    Ok(out.join("\n") + "\n")
}
