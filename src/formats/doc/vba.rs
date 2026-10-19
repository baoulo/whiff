//! VBA projects (MS-OVBA) inside compound files: `vbaProject.bin` in OOXML,
//! the `Macros` storage of Word documents, `_VBA_PROJECT_CUR` in Excel.
//!
//! The `dir` stream names the modules and where their compressed source
//! starts; the source is decompressed only to look for auto-run triggers
//! and suspicious calls (and handed to the secret scanner). It is never
//! copied into the report.

use serde_json::{Value, json};

use crate::plugin::{ByteReader, Cfb, CfbKind, Context, ExtractError, Source, TextRole};

/// Decompressed source read per module at most.
const MAX_MODULE: usize = 1 << 20;
const MAX_MODULES: usize = 200;

/// Procedures Office runs by itself.
const AUTO_EXEC: &[&str] = &[
    "autoopen",
    "autoexec",
    "autoclose",
    "autonew",
    "autoexit",
    "auto_open",
    "auto_close",
    "document_open",
    "document_close",
    "document_new",
    "documentopen",
    "workbook_open",
    "workbook_activate",
    "workbook_beforeclose",
    "presentationopen",
    "slideshowbegin",
    "_layout",
    "_resize",
    "_painted",
    "_change",
    "_click",
];

/// Calls typical of droppers and downloaders.
const SUSPICIOUS: &[(&str, &str)] = &[
    ("shell", "shell"),
    ("wscript.shell", "wscript"),
    ("createobject", "createobject"),
    ("getobject", "getobject"),
    ("powershell", "powershell"),
    ("cmd.exe", "cmd"),
    ("urldownloadtofile", "download"),
    ("msxml2.xmlhttp", "http_request"),
    ("winhttp", "http_request"),
    ("adodb.stream", "adodb_stream"),
    ("savetofile", "write_file"),
    ("open ", "file_io"),
    ("kill ", "delete_file"),
    ("environ", "environment"),
    ("callbyname", "callbyname"),
    ("executeexcel4macro", "excel4_macro"),
    ("lib \"kernel32", "win32_api"),
    ("lib \"user32", "win32_api"),
    ("virtualalloc", "memory_injection"),
    ("rtlmovememory", "memory_injection"),
    ("chrw(", "obfuscation"),
    ("strreverse", "obfuscation"),
    ("base64", "base64"),
    ("vbhide", "hidden_window"),
    ("application.run", "dynamic_call"),
];

/// Look through macro source (VBA or StarBasic) for procedures that run by
/// themselves and for calls typical of droppers; adds what is new to the lists.
pub(crate) fn scan(code: &str, auto: &mut Vec<String>, suspicious: &mut Vec<&'static str>) {
    let lower = code.to_ascii_lowercase();
    for (line, original) in lower.lines().zip(code.lines()) {
        let l = line.trim_start();
        let Some(rest) = l
            .strip_prefix("sub ")
            .or_else(|| l.strip_prefix("private sub "))
            .or_else(|| l.strip_prefix("public sub "))
            .or_else(|| l.strip_prefix("function "))
        else {
            continue;
        };
        let proc = rest.split(['(', ' ']).next().unwrap_or("");
        let triggered = AUTO_EXEC.iter().any(|a| if a.starts_with('_') { proc.ends_with(a) } else { proc == *a });
        if triggered && !auto.iter().any(|x| x.eq_ignore_ascii_case(proc)) && auto.len() < 20 {
            let name = original.split('(').next().and_then(|o| o.split_whitespace().last()).unwrap_or(proc);
            auto.push(name.to_string());
        }
    }
    for (needle, kind) in SUSPICIOUS {
        if lower.contains(needle) && !suspicious.contains(kind) {
            suspicious.push(kind);
        }
    }
}

/// MS-OVBA decompression of a compressed container.
pub(crate) fn decompress(data: &[u8], max: usize) -> Result<Vec<u8>, ExtractError> {
    let bad = || ExtractError::malformed("VBA compressed container");
    if data.first() != Some(&1) {
        return Err(bad());
    }
    let mut out = Vec::new();
    let mut pos = 1;
    while pos + 2 <= data.len() && out.len() < max {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let size = usize::from(header & 0x0FFF) + 3;
        let compressed = header & 0x8000 != 0;
        let chunk = &data[pos + 2..data.len().min(pos + size)];
        pos += size;
        let start = out.len();
        if !compressed {
            out.extend_from_slice(&chunk[..chunk.len().min(4096)]);
            continue;
        }
        let mut i = 0;
        while i < chunk.len() {
            let flags = chunk[i];
            i += 1;
            for bit in 0..8 {
                if i >= chunk.len() {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(chunk[i]);
                    i += 1;
                    continue;
                }
                let token = u16::from_le_bytes([chunk[i], *chunk.get(i + 1).ok_or_else(bad)?]);
                i += 2;
                let done = out.len() - start;
                let bits = (usize::BITS - done.saturating_sub(1).leading_zeros()).max(4);
                let length_mask = 0xFFFFu16 >> bits;
                let offset = usize::from(token >> (16 - bits)) + 1;
                let length = usize::from(token & length_mask) + 3;
                if offset > done {
                    return Err(bad());
                }
                for _ in 0..length {
                    let b = out[out.len() - offset];
                    out.push(b);
                }
            }
        }
    }
    out.truncate(max);
    Ok(out)
}

struct Module {
    name: String,
    stream: String,
    offset: usize,
    document: bool,
}

/// The project name, code page and modules listed in a decompressed `dir` stream.
fn parse_dir(dir: &[u8]) -> (Option<String>, u16, Vec<Module>) {
    let mut r = ByteReader::new(dir);
    let mut project = None;
    let mut code_page = 1252u16;
    let mut modules = Vec::new();
    let mut current: Option<Module> = None;
    while let (Ok(id), Ok(size)) = (r.le_u16(), r.le_u32()) {
        // PROJECTVERSION declares 4 bytes but holds 6.
        let size = if id == 0x0009 { 6 } else { size as usize };
        let Ok(body) = r.bytes(size) else { break };
        match id {
            0x0003 if body.len() >= 2 => code_page = u16::from_le_bytes([body[0], body[1]]),
            0x0004 => project = Some(crate::plugin::latin1_or_utf8(body)),
            0x0019 => {
                if let Some(m) = current.take() {
                    modules.push(m);
                }
                current = Some(Module {
                    name: crate::plugin::latin1_or_utf8(body),
                    stream: String::new(),
                    offset: 0,
                    document: false,
                });
            }
            0x0047 => {
                if let Some(m) = current.as_mut() {
                    let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    m.name = String::from_utf16_lossy(&units);
                }
            }
            0x001A => {
                if let Some(m) = current.as_mut() {
                    m.stream = crate::plugin::latin1_or_utf8(body);
                }
            }
            0x0032 => {
                if let Some(m) = current.as_mut() {
                    let units: Vec<u16> = body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    m.stream = String::from_utf16_lossy(&units);
                }
            }
            0x0031 if body.len() >= 4 => {
                if let Some(m) = current.as_mut() {
                    m.offset = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
                }
            }
            0x0022 => {
                if let Some(m) = current.as_mut() {
                    m.document = true;
                }
            }
            0x002B => {
                if let Some(m) = current.take() {
                    modules.push(m);
                }
            }
            _ => {}
        }
        if modules.len() >= MAX_MODULES {
            break;
        }
    }
    if let Some(m) = current {
        modules.push(m);
    }
    (project, code_page, modules)
}

fn decode(bytes: &[u8], code_page: u16) -> String {
    match code_page {
        65001 => String::from_utf8_lossy(bytes).into_owned(),
        1250..=1258 => encoding_rs::Encoding::for_label(format!("windows-{code_page}").as_bytes())
            .unwrap_or(encoding_rs::WINDOWS_1252)
            .decode_without_bom_handling(bytes)
            .0
            .into_owned(),
        _ => crate::plugin::latin1_or_utf8(bytes),
    }
}

/// Storages of `cfb` holding a VBA project (a `VBA` storage with a `dir`
/// stream): their parent paths (`""` for a bare `vbaProject.bin`).
pub(crate) fn projects(cfb: &Cfb) -> Vec<String> {
    cfb.entries
        .iter()
        .filter(|e| e.kind == CfbKind::Stream && e.name.eq_ignore_ascii_case("dir"))
        .filter_map(|e| {
            let vba = e.path.rsplit_once('/')?.0;
            let (parent, name) = vba.rsplit_once('/').unwrap_or(("", vba));
            name.eq_ignore_ascii_case("vba").then(|| parent.to_string())
        })
        .collect()
}

/// Analyse the VBA project under `prefix` (see [`projects`]): module names
/// and kinds, line counts, auto-run triggers and suspicious calls. Writes
/// the security flags; returns the summary for `format.*.vba`.
pub(crate) fn analyze(
    cfb: &Cfb,
    src: &mut dyn Source,
    prefix: &str,
    cx: &mut Context<'_>,
) -> Result<Value, ExtractError> {
    let join = |p: &str| if prefix.is_empty() { p.to_string() } else { format!("{prefix}/{p}") };
    let dir = cfb
        .read_path(src, &join("VBA/dir"), 1 << 20)
        .ok_or_else(|| ExtractError::malformed("VBA project without a dir stream"))??;
    let dir = decompress(&dir, 4 << 20)?;
    let (project, code_page, modules) = parse_dir(&dir);
    let mut auto = Vec::<String>::new();
    let mut suspicious = Vec::<&'static str>::new();
    let mut listed = Vec::new();
    let mut total_lines = 0usize;
    for m in &modules {
        cx.checkpoint()?;
        let stream = if m.stream.is_empty() { &m.name } else { &m.stream };
        let Some(Ok(raw)) = cfb.read_path(src, &join(&format!("VBA/{stream}")), 16 << 20) else {
            listed.push(json!({ "name": m.name, "kind": if m.document { "document" } else { "module" } }));
            continue;
        };
        let source = raw.get(m.offset..).map(|c| decompress(c, MAX_MODULE)).transpose().ok().flatten();
        let mut entry = json!({ "name": m.name, "kind": if m.document { "document" } else { "module" } });
        if let Some(code) = source {
            let code = decode(&code, code_page);
            let lines = code.lines().filter(|l| !l.trim().is_empty() && !l.starts_with("Attribute VB_")).count();
            total_lines += lines;
            entry["lines"] = json!(lines);
            scan(&code, &mut auto, &mut suspicious);
            if lines > 0 {
                cx.emit_text(TextRole::Code, &code);
            }
        }
        listed.push(entry);
    }
    let mut s = cx.security();
    s.active_content("macros");
    s.risk("macros", Some(format!("{} VBA module(s)", modules.len())));
    if !auto.is_empty() {
        s.risk("auto_exec_macro", Some(auto.join(", ")));
    }
    if !suspicious.is_empty() {
        s.risk("suspicious_macro", Some(suspicious.join(", ")));
    }
    let mut out = json!({ "modules": listed, "code_lines": total_lines });
    if let Some(p) = project {
        out["project"] = json!(p);
    }
    if !auto.is_empty() {
        out["auto_exec"] = json!(auto);
    }
    if !suspicious.is_empty() {
        out["suspicious"] = json!(suspicious);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompresses_the_spec_example() {
        // MS-OVBA 3.2.3: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        let compressed = [
            0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70, 0x61, 0x67,
            0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x30, 0x6D, 0x6E, 0x6F, 0x70, 0x06, 0x71, 0x02,
            0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C,
        ];
        let out = decompress(&compressed, 1000).unwrap();
        assert_eq!(out, b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa");
        assert!(decompress(&[2, 0, 0], 10).is_err());
    }

    #[test]
    fn finds_auto_run_procedures_and_calls() {
        let (mut auto, mut calls) = (Vec::new(), Vec::new());
        scan(
            "Private Sub Document_Open()\n  MsgBox \"Welcome\"\nEnd Sub\nSub Tidy()\nEnd Sub\n",
            &mut auto,
            &mut calls,
        );
        assert_eq!(auto, ["Document_Open"]);
        assert_eq!(calls, Vec::<&str>::new());
        scan("Sub Lookup()\n  Set d = CreateObject(\"Scripting.Dictionary\")\nEnd Sub\n", &mut auto, &mut calls);
        assert_eq!(auto.len(), 1);
        assert_eq!(calls, ["createobject"]);
    }
}
