//! Reconciliation of EXIF, IPTC and XMP into the normalised sections,
//! following the Metadata Working Group guidelines (MWG 2.0):
//!
//! * precedence: the EXIF field MWG maps (Artist, Copyright,
//!   `ImageDescription`, the dates) when present, as XMP may be stale; then
//!   XMP > IPTC, except that IPTC wins over XMP when the Photoshop IPTC
//!   digest shows the IPTC block was edited after the XMP; title and
//!   keywords have no EXIF field and start at XMP;
//! * capture, digitisation and modification dates in that order of sources
//!   (zone offsets applied); EXIF GPS (or XMP `exif:GPS*`) for the location;
//! * VRA Core (`vra:` in XMP) as a fallback for title, creators and rights.
//!
//! Values an extractor already set (a PNG `Title`, a PSD resolution) are kept.

use serde_json::{Map, Value, json};

use super::xmp::lang_default;
use super::{exif, iptc};
use crate::plugin::{Analyzer, AnalyzerStage, ExtractError, Options, Report, TextStore};
use crate::report::{ContentDate, DateField, ImagePhysical, License, Location, Risk};

/// The MWG reconciliation analyzer.
pub struct Mwg;

impl Analyzer for Mwg {
    fn id(&self) -> &'static str {
        "meta.mwg"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Metadata
    }

    fn run(&self, report: &mut Report, _: &TextStore, _: &Options) -> Result<(), ExtractError> {
        let empty = Map::new();
        let obj = |k: &str| report.metadata.get(k).and_then(Value::as_object).cloned().unwrap_or_default();
        let (xmp, iptc_m, exif_m, ps, icc) = (obj("xmp"), obj("iptc"), obj("exif"), obj("photoshop"), obj("icc"));
        if xmp.is_empty() && iptc_m.is_empty() && exif_m.is_empty() && icc.is_empty() {
            return Ok(());
        }
        let ns = |p: &str| xmp.get(p).and_then(Value::as_object).unwrap_or(&empty);
        let iptc_first = ps.get("iptc_digest_matches").and_then(Value::as_bool) == Some(false);
        let mut w = Writer { report, iptc_first };

        // Title, description, creators, copyright, keywords.
        let title = [
            Src::Xmp(lang_default_of(ns("dc"), "title"), "xmp.dc:title"),
            Src::Iptc(str_of(&iptc_m, "ObjectName"), "iptc.ObjectName"),
            Src::Fallback(str_of(&exif_m, "XPTitle"), "exif.XPTitle"),
            Src::Fallback(vra(ns("vra"), &["title", "titleSet"]), "xmp.vra:title"),
        ];
        if let Some((v, s)) = w.pick(title) {
            w.content_title(v, s);
        }
        let description = [
            Src::Xmp(lang_default_of(ns("dc"), "description"), "xmp.dc:description"),
            Src::Iptc(str_of(&iptc_m, "Caption-Abstract"), "iptc.Caption-Abstract"),
            Src::Native(str_of(&exif_m, "ImageDescription").filter(|d| !is_placeholder(d)), "exif.ImageDescription"),
            Src::Fallback(str_of(&exif_m, "XPSubject").or_else(|| str_of(&exif_m, "XPComment")), "exif.XPComment"),
        ];
        if let Some((v, s)) = w.pick(description) {
            w.content_description(v, s);
        }
        let creators = [
            Src::Xmp(list_of(ns("dc"), "creator"), "xmp.dc:creator"),
            Src::Iptc(list_of(&iptc_m, "By-line"), "iptc.By-line"),
            Src::Native(split(str_of(&exif_m, "Artist")), "exif.Artist"),
            Src::Fallback(split(str_of(&exif_m, "XPAuthor")), "exif.XPAuthor"),
            Src::Fallback(
                list_of(ns("vra"), "agentSet").or_else(|| vra(ns("vra"), &["agent"]).map(|a| vec![a])),
                "xmp.vra:agent",
            ),
        ];
        if let Some((v, s)) = w.pick(creators) {
            w.creators(&v, s);
        }
        let copyright = [
            Src::Xmp(lang_default_of(ns("dc"), "rights"), "xmp.dc:rights"),
            Src::Iptc(str_of(&iptc_m, "CopyrightNotice"), "iptc.CopyrightNotice"),
            Src::Native(str_of(&exif_m, "Copyright"), "exif.Copyright"),
            Src::Fallback(vra(ns("vra"), &["rights", "rightsSet"]), "xmp.vra:rights"),
        ];
        if let Some((v, s)) = w.pick(copyright) {
            w.copyright(v, s);
        }
        let keywords = [
            Src::Xmp(list_of(ns("dc"), "subject"), "xmp.dc:subject"),
            Src::Iptc(list_of(&iptc_m, "Keywords"), "iptc.Keywords"),
            Src::Fallback(split(str_of(&exif_m, "XPKeywords")), "exif.XPKeywords"),
        ];
        if let Some((v, s)) = w.pick(keywords) {
            w.keywords(&v, s);
        }

        // Rights details.
        w.rights_details([ns("photoshop"), ns("xmpRights"), ns("cc"), ns("plus")], &iptc_m, &ps);

        // Dates: capture, digitisation, modification.
        w.content_dates([ns("exif"), ns("photoshop"), ns("xmp")], &iptc_m, &exif_m);

        // Location: EXIF GPS, then XMP's.
        let location =
            exif::gps(&exif_m).map(|l| (l, "exif.GPS")).or_else(|| xmp_gps(ns("exif")).map(|l| (l, "xmp.exif:GPS")));
        if let Some(((lat, lon, alt), src)) = location {
            w.location(lat, lon, alt, src);
        }
        // Place names as tags.
        let places = [
            str_of(ns("Iptc4xmpCore"), "Location").or_else(|| str_of(&iptc_m, "Sub-location")),
            str_of(ns("photoshop"), "City").or_else(|| str_of(&iptc_m, "City")),
            str_of(ns("photoshop"), "State").or_else(|| str_of(&iptc_m, "Province-State")),
            str_of(ns("photoshop"), "Country").or_else(|| str_of(&iptc_m, "Country-PrimaryLocationName")),
        ];
        for p in places.into_iter().flatten() {
            w.tag(&p, "mwg.location");
        }

        // Image properties the container did not state.
        w.image(&exif_m, ns("tiff"), &icc);

        // Synthetic media (IPTC digital source type).
        let source_type = str_of(ns("Iptc4xmpExt"), "DigitalSourceType").unwrap_or_default();
        if ["trainedAlgorithmicMedia", "compositeSynthetic", "algorithmicMedia", "compositeWithTrainedAlgorithmicMedia"]
            .iter()
            .any(|t| source_type.ends_with(t))
        {
            w.risk(
                "ai_generated",
                format!("IPTC digital source type {}", source_type.rsplit('/').next().unwrap_or("")),
            );
        }
        Ok(())
    }
}

crate::register_analyzer!(Mwg);

/// A candidate value from one metadata standard.
/// A candidate value, by MWG rank: `Native` (the EXIF field MWG maps,
/// which wins when it differs, as XMP may be stale), then IPTC when its
/// digest shows it was edited after the XMP, then `Xmp`, `Iptc`, and
/// `Fallback` (XP tags, VRA) last.
enum Src<T> {
    Native(Option<T>, &'static str),
    Xmp(Option<T>, &'static str),
    Iptc(Option<T>, &'static str),
    Fallback(Option<T>, &'static str),
}

struct Writer<'r> {
    report: &'r mut Report,
    iptc_first: bool,
}

impl Writer<'_> {
    /// The first available value in MWG order.
    fn pick<T, const N: usize>(&self, candidates: [Src<T>; N]) -> Option<(T, &'static str)> {
        let (mut native, mut xmp, mut iptc_v, mut rest) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for c in candidates {
            match c {
                Src::Native(Some(v), s) => native.push((v, s)),
                Src::Xmp(Some(v), s) => xmp.push((v, s)),
                Src::Iptc(Some(v), s) => iptc_v.push((v, s)),
                Src::Fallback(Some(v), s) => rest.push((v, s)),
                _ => {}
            }
        }
        let (first, second) = if self.iptc_first { (iptc_v, xmp) } else { (xmp, iptc_v) };
        native.into_iter().chain(first).chain(second).chain(rest).next()
    }

    fn record(&mut self, field: &str, source: &str) {
        if let Some(p) = self.report.diagnostics.provenance.as_mut() {
            p.entry(field.to_string()).or_insert_with(|| json!(source));
        }
    }

    fn content_title(&mut self, v: String, s: &str) {
        if self.report.content.title.is_none() {
            self.report.content.title = Some(v);
            self.record("content.title", s);
        }
    }

    fn content_description(&mut self, v: String, s: &str) {
        if self.report.content.description.is_none() {
            self.report.content.description = Some(v);
            self.record("content.description", s);
        }
    }

    fn creators(&mut self, v: &[String], s: &str) {
        for c in v {
            push_unique(&mut self.report.content.authors, c);
            push_unique(&mut self.report.rights.creators, c);
        }
        self.record("content.authors", s);
        self.record("rights.creators", s);
    }

    fn copyright(&mut self, v: String, s: &str) {
        if self.report.rights.copyright.is_none() {
            self.report.rights.copyright = Some(v);
            self.record("rights.copyright", s);
        }
    }

    fn keywords(&mut self, v: &[String], s: &str) {
        for k in v {
            push_unique(&mut self.report.content.keywords, k);
        }
        self.record("content.keywords", s);
    }

    fn tag(&mut self, v: &str, s: &str) {
        push_unique(&mut self.report.content.tags, v);
        self.record("content.tags", s);
    }

    fn credit(&mut self, v: String) {
        self.report.rights.credit.get_or_insert(v);
    }

    fn usage_terms(&mut self, v: String) {
        self.report.rights.usage_terms.get_or_insert(v);
    }

    fn marked(&mut self, v: bool) {
        self.report.rights.marked.get_or_insert(v);
    }

    fn license_url(&mut self, url: String) {
        if self.report.rights.license.is_none() {
            self.report.rights.license = Some(License { name: None, url: Some(url) });
            self.record("rights.license", "xmp");
        }
    }

    /// Credit, usage terms, the copyright flag and the licence URL. `xmp`
    /// holds the XMP `photoshop`, `xmpRights`, `cc` and `plus` namespaces.
    fn rights_details(&mut self, xmp: [&Map<String, Value>; 4], iptc_m: &Map<String, Value>, ps: &Map<String, Value>) {
        let [x_photoshop, x_rights, x_cc, x_plus] = xmp;
        if let Some(c) = str_of(x_photoshop, "Credit").or_else(|| str_of(iptc_m, "Credit")) {
            self.credit(c);
        }
        if let Some(t) = lang_default_of(x_rights, "UsageTerms") {
            self.usage_terms(t);
        }
        let marked = str_of(x_rights, "Marked")
            .map(|m| m.eq_ignore_ascii_case("true"))
            .or_else(|| ps.get("copyright_flag").and_then(Value::as_bool));
        if let Some(m) = marked {
            self.marked(m);
        }
        let licence_url = str_of(x_cc, "license")
            .or_else(|| str_of(x_rights, "WebStatement"))
            .or_else(|| str_of(x_plus, "LicensorURL"));
        if let Some(url) = licence_url {
            self.license_url(url);
        }
    }

    /// `xmp` holds the XMP `exif`, `photoshop` and `xmp` namespaces.
    fn content_dates(
        &mut self,
        xmp: [&Map<String, Value>; 3],
        iptc_m: &Map<String, Value>,
        exif_m: &Map<String, Value>,
    ) {
        let [x_exif, x_photoshop, x_xmp] = xmp;
        let parse = |m: &Map<String, Value>, k: &str| str_of(m, k).and_then(|d| crate::text::parse_date(&d));
        // MWG order: EXIF, XMP, IPTC. Equal civil times merge in `dates`.
        let captured = [
            ("exif.DateTimeOriginal", exif::date(exif_m, "DateTimeOriginal", "OffsetTimeOriginal")),
            ("xmp.exif:DateTimeOriginal", parse(x_exif, "DateTimeOriginal")),
            ("xmp.photoshop:DateCreated", parse(x_photoshop, "DateCreated")),
            ("iptc.DateCreated", iptc::date(iptc_m, "DateCreated", "TimeCreated")),
        ];
        let digitized = [
            ("exif.DateTimeDigitized", exif::date(exif_m, "DateTimeDigitized", "OffsetTimeDigitized")),
            ("xmp.xmp:CreateDate", parse(x_xmp, "CreateDate")),
            ("iptc.DigitalCreationDate", iptc::date(iptc_m, "DigitalCreationDate", "DigitalCreationTime")),
        ];
        let modified = [
            ("exif.DateTime", exif::date(exif_m, "DateTime", "OffsetTime")),
            ("xmp.xmp:ModifyDate", parse(x_xmp, "ModifyDate")),
        ];
        self.dates(DateField::Captured, &captured);
        self.dates(DateField::Digitized, &digitized);
        self.dates(DateField::Modified, &modified);
    }

    fn dates(&mut self, field: DateField, candidates: &[(&'static str, Option<(String, bool)>)]) {
        for (source, value) in candidates {
            let Some((v, tz)) = value else { continue };
            let content = &mut self.report.temporal.content;
            // The same civil time from another block: keep one entry, with
            // the zone if either has it (MWG: EXIF offsets complete XMP dates).
            let civil = |s: &str| s.get(..19).unwrap_or(s).to_string();
            if let Some(d) = content.iter_mut().find(|d| d.field == field && civil(&d.value) == civil(v)) {
                if !d.tz_known && *tz {
                    d.value.clone_from(v);
                    d.tz_known = true;
                }
                continue;
            }
            content.push(ContentDate { field, value: v.clone(), source: (*source).to_string(), tz_known: *tz });
            self.record("temporal.content", source);
        }
    }

    fn location(&mut self, lat: f64, lon: f64, alt: Option<f64>, source: &str) {
        if self.report.content.location.is_none() {
            self.report.content.location = Some(Location { lat, lon, alt_m: alt, source: source.to_string() });
            self.record("content.location", source);
        }
    }

    fn image(&mut self, exif_m: &Map<String, Value>, tiff: &Map<String, Value>, icc: &Map<String, Value>) {
        let dims = || {
            let w = exif_m.get("PixelXDimension").or_else(|| exif_m.get("ImageWidth")).and_then(Value::as_u64)?;
            let h = exif_m.get("PixelYDimension").or_else(|| exif_m.get("ImageLength")).and_then(Value::as_u64)?;
            Some((u32::try_from(w).ok()?, u32::try_from(h).ok()?))
        };
        if self.report.physical.image.is_none()
            && let Some((w, h)) = dims()
        {
            self.report.physical.image = Some(ImagePhysical { width: w, height: h, ..ImagePhysical::default() });
            self.record("physical.image", "exif.PixelXDimension");
        }
        let Some(img) = self.report.physical.image.as_mut() else { return };
        let orientation = exif_m
            .get("Orientation")
            .and_then(Value::as_u64)
            .or_else(|| tiff.get("Orientation").and_then(Value::as_str).and_then(|s| s.parse().ok()));
        if img.orientation.is_none()
            && let Some(o) = orientation.and_then(|o| u8::try_from(o).ok()).filter(|o| (1..=8).contains(o))
        {
            img.orientation = Some(o);
        }
        if img.dpi.is_none() {
            let x = exif_m.get("XResolution").and_then(Value::as_f64);
            let y = exif_m.get("YResolution").and_then(Value::as_f64);
            let unit = exif_m.get("ResolutionUnit").and_then(Value::as_str).unwrap_or("inch");
            // Unit 1 ("no absolute unit") gives an aspect ratio, not a resolution.
            if let (Some(x), Some(y)) = (x, y)
                && x > 0.0
                && y > 0.0
                && (unit == "inch" || unit.starts_with('c'))
            {
                let k = if unit.starts_with('c') { 2.54 } else { 1.0 };
                img.dpi = Some([(x * k * 100.0).round() / 100.0, (y * k * 100.0).round() / 100.0]);
            }
        }
        if img.color_space.is_none() {
            img.color_space = icc.get("description").and_then(Value::as_str).map(str::to_string).or_else(|| {
                exif_m.get("ColorSpace").and_then(Value::as_str).filter(|c| *c == "sRGB").map(str::to_string)
            });
        }
    }

    fn risk(&mut self, kind: &str, detail: String) {
        let risks = &mut self.report.security.risks;
        if !risks.iter().any(|r| r.kind == kind) {
            risks.push(Risk::new(kind, Some(detail), "meta.mwg"));
        }
    }
}

fn push_unique(list: &mut Vec<String>, v: &str) {
    let v = v.trim();
    if !v.is_empty() && !list.iter().any(|x| x == v) && list.len() < 200 {
        list.push(v.to_string());
    }
}

fn str_of(m: &Map<String, Value>, k: &str) -> Option<String> {
    match m.get(k)? {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Array(a) => a.first().and_then(Value::as_str).map(|s| s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

fn lang_default_of(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k).and_then(|v| lang_default(v).or_else(|| agent(v))).map(|s| s.trim().to_string())
}

/// Creative Commons / Inkscape agents: `{"Agent": {"title": "…"}}`.
fn agent(v: &Value) -> Option<String> {
    v.get("Agent").and_then(|a| a.get("title")).and_then(lang_default)
}

fn list_of(m: &Map<String, Value>, k: &str) -> Option<Vec<String>> {
    let v: Vec<String> = match m.get(k)? {
        Value::Array(a) => {
            a.iter().filter_map(|x| lang_default(x).or_else(|| x.get("name").and_then(lang_default))).collect()
        }
        Value::String(s) => vec![s.clone()],
        other => lang_default(other).or_else(|| agent(other)).into_iter().collect(),
    };
    let v: Vec<String> = v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    (!v.is_empty()).then_some(v)
}

/// `"a; b"` (EXIF Artist, XP tags) → `["a", "b"]`.
fn split(s: Option<String>) -> Option<Vec<String>> {
    let v: Vec<String> = s?.split(';').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
    (!v.is_empty()).then_some(v)
}

/// A VRA field: a plain value, or the `display` / first value of a set.
fn vra(m: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match m.get(*k)? {
        Value::Object(o) => o.get("display").or_else(|| o.values().next()).and_then(lang_default),
        other => lang_default(other),
    })
}

/// Camera firmware fills `ImageDescription` with placeholders.
fn is_placeholder(d: &str) -> bool {
    let t = d.trim();
    t.is_empty()
        || matches!(t, "OLYMPUS DIGITAL CAMERA" | "SONY DSC" | "DCIM" | "Default" | "default")
        || t.chars().all(|c| c == ' ' || c == '?')
}

/// XMP `exif:GPSLatitude` `"43,17.79N"` / `"43,17,47.4N"` → decimal degrees.
fn xmp_gps(m: &Map<String, Value>) -> Option<(f64, f64, Option<f64>)> {
    let coord = |k: &str| -> Option<f64> {
        let s = m.get(k)?.as_str()?.trim();
        let (body, hemi) = s.split_at(s.len().checked_sub(1)?);
        let parts: Vec<f64> = body.split(',').filter_map(|p| p.trim().parse().ok()).collect();
        let deg = parts.first()? + parts.get(1).unwrap_or(&0.0) / 60.0 + parts.get(2).unwrap_or(&0.0) / 3600.0;
        Some(if matches!(hemi, "S" | "W") { -deg } else { deg })
    };
    let (lat, lon) = (coord("GPSLatitude")?, coord("GPSLongitude")?);
    let alt = m.get("GPSAltitude").and_then(Value::as_str).and_then(|a| {
        let (n, d) = a.split_once('/')?;
        Some(n.parse::<f64>().ok()? / d.parse::<f64>().ok()?)
    });
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon))
        .then(|| (((lat * 1e6).round() / 1e6), ((lon * 1e6).round() / 1e6), alt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(metadata: &Value) -> Report {
        Report { metadata: metadata.as_object().cloned().unwrap(), ..Report::default() }
    }

    #[test]
    fn precedence_and_digest() {
        let md = json!({
            "xmp": { "dc": { "title": "XMP title", "creator": ["Ada"], "subject": ["harbour"] } },
            "iptc": { "ObjectName": "IPTC title", "Keywords": ["port"], "CopyrightNotice": "© IPTC" },
            "exif": { "Artist": "Exif Artist; Ben", "DateTimeOriginal": "2026:09:14 17:03:22", "OffsetTimeOriginal": "+02:00",
                      "GPSLatitude": [43.0, 17.0, 47.4], "GPSLatitudeRef": "N", "GPSLongitude": [5.0, 22.0, 11.28], "GPSLongitudeRef": "E",
                      "Orientation": 6, "XResolution": 72.0, "YResolution": 72.0, "ResolutionUnit": "inch",
                      "PixelXDimension": 4032, "PixelYDimension": 3024 }
        });
        let mut r = report(&md);
        Mwg.run(&mut r, &TextStore::default(), &Options::default()).unwrap();
        assert_eq!(r.content.title.as_deref(), Some("XMP title"));
        // EXIF Artist is the native field MWG prefers over a differing dc:creator.
        assert_eq!(r.content.authors, ["Exif Artist", "Ben"]);
        assert_eq!(r.content.keywords, ["harbour"]);
        assert_eq!(r.rights.copyright.as_deref(), Some("© IPTC"));
        assert_eq!(r.temporal.content[0].value, "2026-09-14T17:03:22+02:00");
        assert!(r.content.location.is_some());
        let img = r.physical.image.as_ref().unwrap();
        assert_eq!((img.width, img.orientation, img.dpi), (4032, Some(6), Some([72.0, 72.0])));

        // A stale digest: IPTC was edited after the XMP, so it wins.
        let mut md2 = md;
        md2["photoshop"] = json!({ "iptc_digest_matches": false });
        let mut r = report(&md2);
        Mwg.run(&mut r, &TextStore::default(), &Options::default()).unwrap();
        assert_eq!(r.content.title.as_deref(), Some("IPTC title"));
        assert_eq!(r.content.keywords, ["port"]);
    }

    #[test]
    fn xmp_gps_and_ai_flag() {
        let md = json!({ "xmp": { "exif": { "GPSLatitude": "43,17.79N", "GPSLongitude": "5,22.188E" },
            "Iptc4xmpExt": { "DigitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" } } });
        let mut r = report(&md);
        Mwg.run(&mut r, &TextStore::default(), &Options::default()).unwrap();
        let l = r.content.location.unwrap();
        assert!((l.lat - 43.2965).abs() < 1e-3 && (l.lon - 5.3698).abs() < 1e-3);
        assert_eq!(r.security.risks[0].kind, "ai_generated");
    }
}
