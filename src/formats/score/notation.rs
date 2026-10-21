//! Music notation: MusicXML (partwise and timewise; compressed `.mxl`),
//! MEI, MuseScore (`.mscx`, compressed `.mscz`) and Guitar Pro 3 to 5.
//! Title, movement and work, composer, lyricist and arranger, rights,
//! the writing software, parts with their instruments, measures, notes and
//! rests, the first key, time signature and tempo, repeats, the length in
//! quarter notes (and in seconds when a tempo is marked), and the lyrics.
//!
//! Specifications: MusicXML 4.0 (W3C Music Notation CG), MEI 5, the
//! MuseScore file format as MuseScore 3 and 4 write it, the Guitar Pro 3–5
//! layout as PyGuitarPro reads it.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::super::text::{XmlNode, XmlTree, decode_xml, local, start_tag, xml_root};
use super::{GM_PROGRAMS, key_name, ms};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    TextRole, Zip, parse_date, truncate_chars, zip_first_stored, zip_names,
};

/// Extractor for notation files.
pub struct Notation;

static META: ExtractorMeta = ExtractorMeta {
    id: "score.notation",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "musicxml",
            name: "MusicXML score",
            family: "audio.score",
            mimes: &["application/vnd.recordare.musicxml+xml"],
            extensions: &["musicxml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "mxl",
            name: "Compressed MusicXML score",
            family: "audio.score",
            mimes: &["application/vnd.recordare.musicxml"],
            extensions: &["mxl"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "mei",
            name: "MEI score",
            family: "audio.score",
            mimes: &["application/mei+xml"],
            extensions: &["mei"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "mscx",
            name: "MuseScore score",
            family: "audio.score",
            mimes: &["application/x-musescore+xml"],
            extensions: &["mscx"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "mscz",
            name: "Compressed MuseScore score",
            family: "audio.score",
            mimes: &["application/x-musescore"],
            extensions: &["mscz"],
            magic: &[],
            parent: Some("zip"),
        },
        FormatSpec {
            id: "guitar_pro",
            name: "Guitar Pro tablature",
            family: "audio.score",
            mimes: &["application/x-guitar-pro"],
            extensions: &["gp3", "gp4", "gp5", "gtp"],
            magic: &[Magic::at(1, b"FICHIER GUITAR PRO"), Magic::at(1, b"CLIPBOARD")],
            parent: None,
        },
    ],
};

/// Parts, names and lyrics listed.
const MAX_LISTED: usize = 64;
/// Largest score document read out of an archive.
const MAX_DOCUMENT: usize = 64 << 20;

impl Extractor for Notation {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let found = |format| Some(Sniff { format, confidence: 0.95 });
        if let Some(mime) = zip_first_stored(probe.head, "mimetype") {
            return mime
                .starts_with(b"application/vnd.recordare.musicxml")
                .then_some(Sniff { format: "mxl", confidence: 0.97 });
        }
        if probe.head.starts_with(b"PK\x03\x04") {
            let names = zip_names(probe, 2000);
            if names.iter().any(|n| n == "META-INF/container.xml")
                && probe.extension.is_some_and(|e| e.eq_ignore_ascii_case("mxl"))
            {
                return Some(Sniff { format: "mxl", confidence: 0.9 });
            }
            return names
                .iter()
                .any(|n| !n.contains('/') && n.to_ascii_lowercase().ends_with(".mscx"))
                .then_some(Sniff { format: "mscz", confidence: 0.9 });
        }
        let root = xml_root(probe.head)?;
        match local(&root).as_str() {
            "score-partwise" | "score-timewise" => found("musicxml"),
            "mei" if start_tag(probe.head, &root).is_some_and(|t| t.contains("music-encoding.org")) => found("mei"),
            "museScore" => found("mscx"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut out = Score::default();
        let format = cx.format_id().to_string();
        match format.as_str() {
            "guitar_pro" => {
                let (b, _) = cx.read_bytes(src)?;
                guitar_pro(&b, &mut out).ok_or_else(|| ExtractError::malformed("Guitar Pro header"))?;
            }
            "mxl" | "mscz" => {
                let zip = Zip::open(src, 4096)?;
                let path = if format == "mxl" {
                    mxl_root(&zip, src, cx).ok_or_else(|| ExtractError::malformed("no MusicXML root file"))?
                } else {
                    zip.entries
                        .iter()
                        .map(|e| e.name.clone())
                        .find(|n| !n.contains('/') && n.to_ascii_lowercase().ends_with(".mscx"))
                        .ok_or_else(|| ExtractError::malformed("no .mscx in the archive"))?
                };
                out.format.insert("root_file".into(), json!(path));
                let text = zip
                    .read_text(src, &path, cx, MAX_DOCUMENT)
                    .ok_or_else(|| ExtractError::malformed(format!("cannot read {path}")))??;
                let tree = XmlTree::parse(&text).map_err(ExtractError::malformed)?;
                cx.checkpoint()?;
                if format == "mxl" { musicxml(&tree, &mut out) } else { musescore(&tree, &mut out) }
            }
            id => {
                let (bytes, _) = cx.read_bytes(src)?;
                let tree = XmlTree::parse(&decode_xml(&bytes)).map_err(ExtractError::malformed)?;
                cx.checkpoint()?;
                match id {
                    "mei" => mei(&tree, &mut out),
                    "mscx" => musescore(&tree, &mut out),
                    _ => musicxml(&tree, &mut out),
                }
            }
        }
        out.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Notation);

/// The MusicXML file a compressed score names in `META-INF/container.xml`
/// (else the first `.musicxml` / `.xml` at the top level).
fn mxl_root(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>) -> Option<String> {
    if let Some(Ok(c)) = zip.read_text(src, "META-INF/container.xml", cx, 1 << 20)
        && let Ok(tree) = XmlTree::parse(&c)
    {
        let mut path = None;
        walk(&tree, tree.root(), &mut |n| {
            if n.name == "rootfile" && path.is_none() {
                let media = n.attr("media-type").unwrap_or("application/vnd.recordare.musicxml+xml");
                if media.contains("musicxml") {
                    path = n.attr("full-path").map(str::to_string);
                }
            }
        });
        if path.is_some() {
            return path;
        }
    }
    zip.entries.iter().map(|e| e.name.clone()).find(|n| {
        let ext = std::path::Path::new(n).extension().and_then(|e| e.to_str()).unwrap_or("");
        !n.starts_with("META-INF/") && (ext.eq_ignore_ascii_case("musicxml") || ext.eq_ignore_ascii_case("xml"))
    })
}

/// Visit `node` and everything under it, depth first.
fn walk<'t>(tree: &'t XmlTree, node: &'t XmlNode, f: &mut impl FnMut(&'t XmlNode)) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        f(n);
        let mut kids: Vec<&XmlNode> = tree.children(n, "*").collect();
        kids.reverse();
        stack.extend(kids);
    }
}

/// What every notation format reads into.
#[derive(Default)]
struct Score {
    title: Option<String>,
    subtitle: Option<String>,
    /// (role, name): composer, lyricist, arranger, poet, …
    creators: Vec<(String, String)>,
    rights: Vec<String>,
    software: Vec<String>,
    date: Option<String>,
    parts: Vec<Map<String, Value>>,
    measures: Option<u64>,
    notes: u64,
    rests: u64,
    key: Option<String>,
    time: Option<String>,
    tempo: Option<f64>,
    quarters: Option<f64>,
    seconds: Option<f64>,
    repeats: u64,
    lyrics: String,
    /// Notes and rests were counted (not for Guitar Pro, whose header is read).
    counted: bool,
    format: Map<String, Value>,
}

impl Score {
    fn creator(&mut self, role: &str, name: &str) {
        let name = name.trim();
        if !name.is_empty() && self.creators.len() < MAX_LISTED {
            let role = if role.trim().is_empty() { "creator".to_string() } else { role.trim().to_ascii_lowercase() };
            self.creators.push((role, truncate_chars(name, 200)));
        }
    }

    fn part(&mut self, name: Option<&str>, instrument: Option<&str>, program: Option<u8>) {
        if self.parts.len() >= MAX_LISTED {
            return;
        }
        let mut m = Map::new();
        for (k, v) in [("name", name), ("instrument", instrument)] {
            if let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) {
                m.insert(k.into(), json!(truncate_chars(v, 200)));
            }
        }
        if let Some(p) = program.filter(|p| (1..=128).contains(p)) {
            m.insert("midi_program".into(), json!(p));
            m.insert("gm_name".into(), json!(GM_PROGRAMS[usize::from(p - 1)]));
        }
        self.parts.push(m);
    }

    /// A lyric syllable: `begin` / `middle` join the next one.
    fn syllable(&mut self, text: &str, joined: bool) {
        if self.lyrics.len() < 1 << 20 && !text.trim().is_empty() {
            self.lyrics.push_str(text.trim());
            if !joined {
                self.lyrics.push(' ');
            }
        }
    }

    fn report(mut self, cx: &mut Context<'_>) {
        if let Some(t) = self.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            cx.content().source("score.title").title(truncate_chars(t, 300));
            cx.emit_text(TextRole::Title, t);
        }
        for (role, name) in &self.creators {
            if matches!(role.as_str(), "composer" | "lyricist" | "arranger" | "poet" | "creator" | "artist" | "words") {
                cx.content().source(format!("score.{role}")).author(name.clone());
            }
        }
        for r in &self.rights {
            cx.rights().source("score.rights").copyright(truncate_chars(r, 300));
        }
        if let Some((d, tz)) = self.date.as_deref().and_then(parse_date) {
            cx.temporal().source("score.date").content_date(DateField::Created, d, tz);
        }
        if let Some(s) = self.seconds.filter(|s| *s > 0.0 && s.is_finite()) {
            cx.physical().duration_s(ms(s));
        }
        if !self.lyrics.trim().is_empty() {
            cx.emit_text(TextRole::Body, self.lyrics.trim());
        }
        let mut f = Map::new();
        let mut put = |k: &str, v: Value| {
            if !v.is_null() && v != json!([]) && v != json!({}) {
                f.insert(k.into(), v);
            }
        };
        put("subtitle", json!(self.subtitle));
        let mut roles: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (role, name) in self.creators {
            roles.entry(role).or_default().push(name);
        }
        put("creators", json!(roles));
        self.software.dedup();
        put("software", json!(self.software));
        if self.counted {
            put("parts", json!(self.parts.len()));
            put("notes", json!(self.notes));
            put("rests", json!(self.rests));
        }
        put("part_list", Value::Array(self.parts.into_iter().filter(|p| !p.is_empty()).map(Value::Object).collect()));
        put("measures", json!(self.measures));
        put("key", json!(self.key));
        put("time_signature", json!(self.time));
        put("tempo_bpm", json!(self.tempo.map(|t| (t * 100.0).round() / 100.0)));
        put("quarter_notes", json!(self.quarters.map(|q| (q * 1000.0).round() / 1000.0)));
        if self.repeats > 0 {
            put("repeat_barlines", json!(self.repeats));
        }
        f.append(&mut self.format);
        cx.format().append(&mut f);
    }
}

/// A tempo from a MusicXML `metronome`: the beat unit and beats a minute,
/// as quarter notes a minute.
fn metronome(tree: &XmlTree, m: &XmlNode) -> Option<f64> {
    let per = tree.text(m, "per-minute")?.trim().parse::<f64>().ok()?;
    let unit = match tree.text(m, "beat-unit").unwrap_or("quarter") {
        "whole" => 4.0,
        "half" => 2.0,
        "eighth" => 0.5,
        "16th" => 0.25,
        _ => 1.0,
    } * if tree.child(m, "beat-unit-dot").is_some() { 1.5 } else { 1.0 };
    Some(per * unit).filter(|t| t.is_finite() && *t > 0.0)
}

#[allow(clippy::too_many_lines)] // header, part list, then one pass over the parts
fn musicxml(tree: &XmlTree, s: &mut Score) {
    let root = tree.root();
    s.counted = true;
    s.format.insert("version".into(), json!(root.attr("version").unwrap_or("1.0")));
    if root.name == "score-timewise" {
        s.format.insert("layout".into(), json!("timewise"));
    }
    let work = tree.child(root, "work");
    s.title =
        work.and_then(|w| tree.text(w, "work-title")).or_else(|| tree.text(root, "movement-title")).map(str::to_string);
    if let Some(m) = tree.text(root, "movement-title").filter(|m| Some(*m) != s.title.as_deref()) {
        s.subtitle = Some(m.to_string());
    }
    if let Some(n) = work.and_then(|w| tree.text(w, "work-number")) {
        s.format.insert("work_number".into(), json!(n));
    }
    if let Some(id) = tree.child(root, "identification") {
        for c in tree.children(id, "creator") {
            let (role, text) = (c.attr("type").unwrap_or(""), c.text.clone());
            s.creator(role, &text);
        }
        for r in tree.children(id, "rights") {
            if !r.text.trim().is_empty() {
                s.rights.push(r.text.trim().to_string());
            }
        }
        if let Some(e) = tree.child(id, "encoding") {
            s.software =
                tree.children(e, "software").map(|x| x.text.trim().to_string()).filter(|x| !x.is_empty()).collect();
            s.date = tree.text(e, "encoding-date").map(str::to_string);
        }
    }
    // Credits: the title and composer as printed, when the header lacks them.
    for credit in tree.children(root, "credit") {
        let kind = tree.text(credit, "credit-type").unwrap_or("");
        let words: String =
            tree.children(credit, "credit-words").map(|w| w.text.trim().to_string()).collect::<Vec<_>>().join(" ");
        match kind {
            "title" if s.title.is_none() => s.title = Some(words),
            "subtitle" if s.subtitle.is_none() => s.subtitle = Some(words),
            "composer" if !s.creators.iter().any(|c| c.0 == "composer") => s.creator("composer", &words),
            "rights" if s.rights.is_empty() && !words.is_empty() => s.rights.push(words),
            _ => {}
        }
    }
    if let Some(list) = tree.child(root, "part-list") {
        for p in tree.children(list, "score-part") {
            let program = tree
                .child(p, "midi-instrument")
                .and_then(|m| tree.text(m, "midi-program"))
                .and_then(|v| v.parse::<u8>().ok());
            let instrument = tree.child(p, "score-instrument").and_then(|i| tree.text(i, "instrument-name"));
            s.part(tree.text(p, "part-name"), instrument, program);
        }
    }
    // Partwise: parts hold measures; timewise: measures hold parts.
    let partwise = root.name != "score-timewise";
    let measures_of: Vec<Vec<&XmlNode>> = if partwise {
        tree.children(root, "part").map(|p| tree.children(p, "measure").collect()).collect()
    } else {
        let ms: Vec<&XmlNode> = tree.children(root, "measure").collect();
        let first_parts = ms.first().map_or(0, |m| tree.children(m, "part").count());
        (0..first_parts).map(|i| ms.iter().filter_map(|m| tree.children(m, "part").nth(i)).collect()).collect()
    };
    s.measures = measures_of.first().map(|m| m.len() as u64);
    // Staves: a part of several (a piano) says so in its first attributes.
    let staves: u64 = measures_of
        .iter()
        .map(|ms| {
            ms.iter()
                .flat_map(|m| tree.children(m, "attributes"))
                .find_map(|a| tree.text(a, "staves").and_then(|v| v.parse::<u64>().ok()))
                .unwrap_or(1)
        })
        .sum();
    if staves > 0 {
        s.format.insert("staves".into(), json!(staves));
    }
    let mut lyric_part: Option<usize> = None;
    for (pi, measures) in measures_of.iter().enumerate() {
        let first = pi == 0;
        let (mut divisions, mut quarters, mut seconds, mut tempo) = (1.0f64, 0.0f64, 0.0f64, None::<f64>);
        for m in measures {
            let (mut pos, mut end, mut silent) = (0.0f64, 0.0f64, 0.0f64);
            let mut measure_tempo = tempo;
            for c in tree.children(m, "*") {
                let dur = || tree.text(c, "duration").and_then(|d| d.parse::<f64>().ok()).unwrap_or(0.0);
                match c.name.as_str() {
                    "attributes" => {
                        if let Some(d) =
                            tree.text(c, "divisions").and_then(|d| d.parse::<f64>().ok()).filter(|d| *d > 0.0)
                        {
                            divisions = d;
                        }
                        if first && s.key.is_none() {
                            s.key = tree.child(c, "key").and_then(|k| {
                                let fifths = tree.text(k, "fifths")?.parse::<i64>().ok()?;
                                key_name(fifths, tree.text(k, "mode") == Some("minor"))
                            });
                        }
                        if first && s.time.is_none() {
                            s.time = tree.child(c, "time").and_then(|t| {
                                if tree.child(t, "senza-misura").is_some() {
                                    return Some("senza misura".to_string());
                                }
                                Some(format!("{}/{}", tree.text(t, "beats")?, tree.text(t, "beat-type")?))
                            });
                        }
                    }
                    "note" => {
                        let chord = tree.child(c, "chord").is_some();
                        if tree.child(c, "rest").is_some() {
                            s.rests += 1;
                        } else {
                            s.notes += 1;
                        }
                        if !chord {
                            pos += dur();
                            end = end.max(pos);
                        }
                        if lyric_part.is_none_or(|p| p == pi) {
                            for l in tree.children(c, "lyric").take(1) {
                                if let Some(t) = tree.text(l, "text") {
                                    lyric_part = Some(pi);
                                    let joined = matches!(tree.text(l, "syllabic"), Some("begin" | "middle"));
                                    s.syllable(t, joined);
                                }
                            }
                        }
                    }
                    "backup" => pos = (pos - dur()).max(0.0),
                    // A forward after the last note only fills the bar on
                    // paper; in a bar without notes it is the bar.
                    "forward" => {
                        pos += dur();
                        silent = silent.max(pos);
                    }
                    "direction" | "sound" => {
                        let sound = if c.name == "sound" { Some(c) } else { tree.child(c, "sound") };
                        let t = sound.and_then(|x| x.attr("tempo")).and_then(|t| t.parse::<f64>().ok()).or_else(|| {
                            let dt = tree.child(c, "direction-type")?;
                            metronome(tree, tree.child(dt, "metronome")?)
                        });
                        if let Some(t) = t.filter(|t| *t > 0.0 && t.is_finite()) {
                            tempo = Some(t);
                            if pos == 0.0 || measure_tempo.is_none() {
                                measure_tempo = Some(t);
                            }
                            if first && s.tempo.is_none() {
                                s.tempo = Some(t);
                            }
                        }
                    }
                    "barline" if first && tree.child(c, "repeat").is_some() => s.repeats += 1,
                    _ => {}
                }
            }
            let q = if end > 0.0 { end } else { silent } / divisions;
            quarters += q;
            if let Some(t) = measure_tempo {
                seconds += q * 60.0 / t;
            }
        }
        if first {
            s.quarters = Some(quarters).filter(|q| *q > 0.0);
            s.seconds = s.tempo.map(|_| seconds);
        }
    }
}

/// An MEI key signature: `3s`, `2f`, `0`.
fn mei_key(sig: &str, mode: Option<&str>) -> Option<String> {
    let sig = sig.trim();
    let fifths = match sig.chars().last()? {
        's' => sig[..sig.len() - 1].parse::<i64>().ok()?,
        'f' => -sig[..sig.len() - 1].parse::<i64>().ok()?,
        _ => sig.parse::<i64>().ok()?,
    };
    key_name(fifths, mode == Some("minor"))
}

fn mei(tree: &XmlTree, s: &mut Score) {
    let root = tree.root();
    s.counted = true;
    s.format.insert("version".into(), json!(root.attr("meiversion")));
    let head = tree.child(root, "meiHead");
    let mut in_music = false;
    let mut first_mdiv = true;
    let mut measures = 0u64;
    walk(tree, root, &mut |n| match n.name.as_str() {
        "music" => in_music = true,
        "titleStmt" if head.is_some() && s.title.is_none() => {
            s.title = tree.children(n, "title").map(|t| t.text.trim().to_string()).find(|t| !t.is_empty());
            for c in tree.children(n, "composer") {
                let name = tree.text(c, "persName").map_or_else(|| c.text.clone(), str::to_string);
                s.creator("composer", &name);
            }
            for c in tree.children(n, "lyricist") {
                s.creator("lyricist", &c.text);
            }
        }
        // `workList/work`: the work's title and composer (ABC and Humdrum imports).
        "work" if !in_music => {
            if s.title.is_none() {
                s.title = tree.children(n, "title").map(|t| t.text.trim().to_string()).find(|t| !t.is_empty());
            }
            if !s.creators.iter().any(|c| c.0 == "composer") {
                for c in tree.children(n, "composer") {
                    let name = tree.text(c, "persName").map_or_else(|| c.text.clone(), str::to_string);
                    s.creator("composer", &name);
                }
            }
        }
        "persName" if !in_music => {
            if let Some(role) = n.attr("role")
                && !s.creators.iter().any(|(_, name)| name == n.text.trim())
            {
                s.creator(role, &n.text);
            }
        }
        "availability" if !in_music && s.rights.is_empty() => {
            let t = n.text.trim();
            if !t.is_empty() {
                s.rights.push(t.to_string());
            }
        }
        "application" if !in_music => {
            if let Some(name) = tree.text(n, "name").or_else(|| n.attr("label")) {
                s.software.push(name.to_string());
            }
        }
        "date" if !in_music && s.date.is_none() => {
            s.date = n.attr("isodate").map(str::to_string).or_else(|| Some(n.text.trim().to_string()));
        }
        "mdiv" if in_music => {
            if measures > 0 {
                first_mdiv = false;
            }
        }
        "measure" if first_mdiv => measures += 1,
        "scoreDef" | "staffDef" | "keySig" | "meterSig" => {
            if s.key.is_none()
                && let Some(sig) = n.attr("key.sig").or_else(|| (n.name == "keySig").then(|| n.attr("sig")).flatten())
            {
                let mode = n.attr("key.mode").or_else(|| n.attr("mode"));
                s.key = mei_key(sig, mode);
            }
            if s.time.is_none() {
                let (count, unit) = if n.name == "meterSig" {
                    (n.attr("count"), n.attr("unit"))
                } else {
                    (n.attr("meter.count"), n.attr("meter.unit"))
                };
                if let (Some(c), Some(u)) = (count, unit) {
                    s.time = Some(format!("{c}/{u}"));
                }
            }
            if n.name == "staffDef" {
                let label = n.attr("label").map(str::to_string).or_else(|| tree.text(n, "label").map(str::to_string));
                let program = tree
                    .child(n, "instrDef")
                    .and_then(|i| i.attr("midi.instrnum"))
                    .and_then(|p| p.parse::<u8>().ok())
                    .map(|p| p + 1);
                s.part(label.as_deref(), None, program);
            }
            if s.tempo.is_none()
                && let Some(t) = n.attr("midi.bpm").and_then(|t| t.parse::<f64>().ok())
            {
                s.tempo = Some(t);
            }
        }
        "note" if in_music => s.notes += 1,
        "rest" | "mRest" | "multiRest" if in_music => s.rests += 1,
        "tempo" if s.tempo.is_none() => s.tempo = n.attr("midi.bpm").and_then(|t| t.parse::<f64>().ok()),
        "syl" => {
            let joined = matches!(n.attr("wordpos"), Some("i" | "m")) || n.attr("con") == Some("d");
            s.syllable(&n.text, joined);
        }
        _ => {}
    });
    s.measures = Some(measures).filter(|m| *m > 0);
}

#[allow(clippy::too_many_lines)] // the score's metadata, parts and staves
fn musescore(tree: &XmlTree, s: &mut Score) {
    let root = tree.root();
    s.counted = true;
    s.format.insert("version".into(), json!(root.attr("version")));
    if let Some(v) = tree.text(root, "programVersion") {
        let rev = tree.text(root, "programRevision").map(|r| format!(" ({r})")).unwrap_or_default();
        s.software.push(format!("MuseScore {v}{rev}"));
    }
    let Some(score) = tree.child(root, "Score") else { return };
    for m in tree.children(score, "metaTag") {
        let (Some(name), value) = (m.attr("name"), m.text.trim()) else { continue };
        if value.is_empty() {
            continue;
        }
        match name {
            "workTitle" => s.title = Some(value.to_string()),
            "movementTitle" => s.subtitle = Some(value.to_string()),
            "composer" | "lyricist" | "arranger" | "translator" | "poet" => s.creator(name, value),
            "copyright" => s.rights.push(value.to_string()),
            "creationDate" => s.date = Some(value.to_string()),
            "workNumber" => {
                s.format.insert("work_number".into(), json!(value));
            }
            "source" | "platform" | "originalFormat" => {
                s.format.insert(name.to_ascii_lowercase(), json!(truncate_chars(value, 200)));
            }
            _ => {}
        }
    }
    for p in tree.children(score, "Part") {
        let instrument = tree.child(p, "Instrument");
        let name = tree.text(p, "trackName").or_else(|| instrument.and_then(|i| tree.text(i, "longName")));
        let program = instrument
            .and_then(|i| tree.child(i, "Channel"))
            .and_then(|c| tree.child(c, "program"))
            .and_then(|p| p.attr("value"))
            .and_then(|v| v.parse::<u8>().ok())
            .map(|p| p + 1);
        s.part(name, instrument.and_then(|i| i.attr("id")), program);
    }
    let mut first_staff = true;
    for staff in tree.children(score, "Staff") {
        let measures: Vec<&XmlNode> = tree.children(staff, "Measure").collect();
        if first_staff {
            s.measures = Some(measures.len() as u64);
        }
        walk(tree, staff, &mut |n| match n.name.as_str() {
            "Note" => s.notes += 1,
            "Rest" => s.rests += 1,
            "KeySig" if s.key.is_none() => {
                let fifths = tree.text(n, "concertKey").or_else(|| tree.text(n, "accidental"));
                let minor = tree.text(n, "mode") == Some("minor");
                s.key = fifths.and_then(|f| f.parse::<i64>().ok()).and_then(|f| key_name(f, minor));
            }
            "TimeSig" if s.time.is_none() => {
                if let (Some(a), Some(b)) = (tree.text(n, "sigN"), tree.text(n, "sigD")) {
                    s.time = Some(format!("{a}/{b}"));
                }
            }
            // MuseScore stores tempo in quarter notes a second.
            "Tempo" if s.tempo.is_none() => {
                s.tempo = tree.text(n, "tempo").and_then(|t| t.parse::<f64>().ok()).map(|t| t * 60.0);
            }
            "Lyrics" if first_staff => {
                if let Some(t) = tree.text(n, "text") {
                    let joined = matches!(tree.text(n, "syllabic"), Some("begin" | "middle"));
                    s.syllable(t, joined);
                }
            }
            "Text" if s.title.is_none() => {
                if tree.text(n, "style").is_some_and(|st| st.eq_ignore_ascii_case("title")) {
                    s.title = tree.text(n, "text").map(str::to_string);
                }
            }
            "BarLine" | "startRepeat" | "endRepeat"
                if first_staff
                    && (n.name != "BarLine" || tree.text(n, "subtype").is_some_and(|t| t.contains("repeat"))) =>
            {
                s.repeats += 1;
            }
            _ => {}
        });
        first_staff = false;
    }
    // A VBox title frame anywhere in the score.
    if s.title.is_none() {
        walk(tree, score, &mut |n| {
            if n.name == "Text"
                && s.title.is_none()
                && tree.text(n, "style").is_some_and(|st| st.eq_ignore_ascii_case("title"))
            {
                s.title = tree.text(n, "text").map(str::to_string);
            }
        });
    }
}

/// A little-endian reader over a Guitar Pro file.
struct Gp<'b> {
    d: &'b [u8],
    at: usize,
}

impl Gp<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let v = self.d.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i8(&mut self) -> Option<i8> {
        Some(i8::from_le_bytes([*self.take(1)?.first()?]))
    }

    /// Windows-1252 text.
    fn text(b: &[u8]) -> String {
        encoding_rs::WINDOWS_1252.decode_without_bom_handling(b).0.trim().to_string()
    }

    /// A string with an int total size and a byte length.
    fn int_byte(&mut self) -> Option<String> {
        let size = usize::try_from(self.i32()?).ok()?;
        let field = self.take(size)?;
        let n = usize::from(*field.first()?).min(field.len() - 1);
        Some(Self::text(&field[1..=n]))
    }

    /// A string with an int length.
    fn int_size(&mut self) -> Option<String> {
        let n = usize::try_from(self.i32()?).ok()?;
        Some(Self::text(self.take(n)?))
    }
}

/// Guitar Pro 3 to 5: the score information, lyrics, tempo, key, and the
/// measure and track counts.
#[allow(clippy::many_single_char_names)] // the reader `r`, score `s`, bytes `b`, length `n`
fn guitar_pro(b: &[u8], s: &mut Score) -> Option<()> {
    let n = usize::from(*b.first()?).min(30);
    let version = Gp::text(b.get(1..=n)?);
    let number = version.rsplit('v').next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    let major = number.floor();
    s.format.insert("version".into(), json!(version));
    let mut r = Gp { d: b, at: 31 };
    if version.starts_with("CLIPBOARD") {
        s.format.insert("clipboard".into(), json!(true));
        return Some(());
    }
    let fields = ["title", "subtitle", "artist", "album", "words", "music", "copyright", "tab", "instructions"];
    for f in fields {
        if major < 5.0 && f == "music" {
            continue;
        }
        let v = r.int_byte()?;
        if v.is_empty() {
            continue;
        }
        match f {
            "title" => s.title = Some(v),
            "subtitle" => s.subtitle = Some(v),
            "artist" | "words" | "music" => s.creator(if f == "music" { "composer" } else { f }, &v),
            "copyright" => s.rights.push(v),
            "album" | "tab" | "instructions" => {
                s.format
                    .insert(if f == "tab" { "tab_author".into() } else { f.into() }, json!(truncate_chars(&v, 500)));
            }
            _ => {}
        }
    }
    let notices = r.i32()?.clamp(0, 256);
    let mut notice = Vec::new();
    for _ in 0..notices {
        notice.push(r.int_byte()?);
    }
    let notice: Vec<String> = notice.into_iter().filter(|n| !n.is_empty()).collect();
    if !notice.is_empty() {
        s.format.insert("notice".into(), json!(truncate_chars(&notice.join("\n"), 2000)));
    }
    if major < 5.0 {
        r.take(1)?; // triplet feel
    }
    if major >= 4.0 {
        r.i32()?; // lyrics track
        for _ in 0..5 {
            r.i32()?;
            let line = r.int_size()?;
            s.syllable(&line, false);
        }
    }
    if major >= 5.0 {
        if number > 5.0 {
            r.take(8 + 11)?; // RSE master volume, reserved, equalizer
        }
        r.take(4 * 7 + 2)?; // page size and margins, proportion, header and footer
        // Header and footer texts: title, subtitle, artist, album, words,
        // music, words and music, two copyright lines, page number.
        for _ in 0..10 {
            r.int_byte()?;
        }
        if let Some(name) = r.int_byte().filter(|n| !n.is_empty()) {
            s.format.insert("tempo_name".into(), json!(name));
        }
    }
    let tempo = r.i32()?;
    if major >= 5.0 && number > 5.0 {
        r.take(1)?; // hide tempo
    }
    let key = if major >= 5.0 { i32::from(r.i8()?) } else { r.i32()? };
    if major >= 5.0 {
        r.i32()?; // octave
    } else if major >= 4.0 {
        r.i8()?;
    }
    r.take(64 * 12)?; // MIDI channels
    if major >= 5.0 {
        r.take(19 * 2 + 4)?; // directions, master reverb
    }
    let (measures, tracks) = (r.i32()?, r.i32()?);
    s.tempo = Some(f64::from(tempo)).filter(|t| *t > 0.0);
    s.key = key_name(i64::from(key), false);
    s.measures = u64::try_from(measures).ok();
    s.format.insert("tracks".into(), json!(tracks));
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("musicxml", "mxl", "mei", "mscx", "mscz", "guitar_pro");

    #[test]
    fn musicxml_lengths() {
        let t = XmlTree::parse(
            "<score-partwise version=\"4.0\"><work><work-title>Tide</work-title></work>\
             <identification><creator type=\"composer\">Ana</creator><rights>CC0</rights></identification>\
             <part-list><score-part id=\"P1\"><part-name>Flute</part-name><midi-instrument><midi-program>74</midi-program></midi-instrument></score-part></part-list>\
             <part id=\"P1\"><measure><attributes><divisions>2</divisions><key><fifths>1</fifths></key><time><beats>2</beats><beat-type>4</beat-type></time></attributes>\
             <direction><sound tempo=\"60\"/></direction>\
             <note><pitch/><duration>2</duration><lyric><syllabic>begin</syllabic><text>Har</text></lyric></note>\
             <note><chord/><pitch/><duration>2</duration></note>\
             <note><pitch/><duration>2</duration><lyric><syllabic>end</syllabic><text>bour</text></lyric></note></measure>\
             <measure><note><rest/><duration>4</duration></note><barline><repeat direction=\"backward\"/></barline></measure></part></score-partwise>",
        )
        .unwrap();
        let mut s = Score::default();
        musicxml(&t, &mut s);
        assert_eq!((s.title.as_deref(), s.measures, s.notes, s.rests), (Some("Tide"), Some(2), 3, 1));
        assert_eq!((s.key.as_deref(), s.time.as_deref(), s.tempo), (Some("G major"), Some("2/4"), Some(60.0)));
        assert_eq!((s.quarters, s.seconds), (Some(4.0), Some(4.0)));
        assert_eq!(s.lyrics, "Harbour ");
        assert_eq!(s.parts[0]["gm_name"], "Flute");
        assert_eq!(s.repeats, 1);
        assert_eq!(mei_key("3f", Some("minor")).as_deref(), Some("C minor"));
        assert_eq!(mei_key("0", None).as_deref(), Some("C major"));
    }
}
