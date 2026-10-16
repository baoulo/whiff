//! PNG and APNG: header (size, bit depth, colour type, interlace), palette,
//! transparency, gamma / sRGB / ICC, resolution, modification time, every
//! text chunk (`tEXt`, `zTXt`, `iTXt`), embedded XMP, EXIF (`eXIf` and
//! ImageMagick raw profiles), APNG animation, C2PA, and data after `IEND`.
//!
//! AI image generators store their parameters in text chunks: Stable
//! Diffusion WebUI (`parameters`), ComfyUI (`prompt` / `workflow`), InvokeAI
//! and NovelAI. The prompt becomes the description and the image is flagged.
//!
//! Specification: PNG 3rd edition (W3C), APNG.

use serde_json::{Map, Value, json};

use crate::plugin::{
    BlockKind, Compression, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe,
    Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for PNG and APNG.
pub struct Png;

const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

static META: ExtractorMeta = ExtractorMeta {
    id: "image.png",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "png",
            name: "PNG image",
            family: "image.raster",
            mimes: &["image/png"],
            extensions: &["png"],
            magic: &[Magic::prefix(SIGNATURE)],
            parent: None,
        },
        FormatSpec {
            id: "apng",
            name: "Animated PNG",
            family: "image.raster",
            mimes: &["image/apng"],
            extensions: &["apng"],
            magic: &[],
            parent: Some("png"),
        },
    ],
};

const MAX_CHUNKS: usize = 200_000;
/// Text and profile chunks larger than this are not read.
const MAX_CHUNK: u32 = 8 << 20;
/// Decompressed text / profile data per chunk.
const MAX_INFLATE: usize = 16 << 20;

impl Extractor for Png {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // `acTL` must come before the first `IDAT`.
        let head = probe.head.strip_prefix(SIGNATURE)?;
        let actl = head.windows(4).position(|w| w == b"acTL")?;
        let idat = head.windows(4).position(|w| w == b"IDAT").unwrap_or(usize::MAX);
        (actl < idat).then_some(Sniff { format: "apng", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if !src.head().starts_with(SIGNATURE) {
            return Err(ExtractError::Unsupported("PNG".into()));
        }
        let mut s = State::default();
        let len = src.len();
        let mut pos = 8u64;
        for n in 0..MAX_CHUNKS {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let Ok(h) = src.read_vec(pos, 8) else {
                cx.warn("truncated before IEND");
                break;
            };
            let size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
            let kind = [h[4], h[5], h[6], h[7]];
            let end = pos + 12 + u64::from(size);
            if end > len {
                cx.warn(format!("chunk {} runs past the end", String::from_utf8_lossy(&kind)));
                break;
            }
            s.chunks += 1;
            if &kind == b"IDAT" || &kind == b"fdAT" {
                s.idat_bytes += u64::from(size);
                if &kind == b"IDAT" {
                    s.idat_chunks += 1;
                }
            } else if &kind == b"IEND" {
                s.iend = true;
                if end < len {
                    s.trailing = len - end;
                }
                break;
            } else if size <= MAX_CHUNK {
                let data = src.read_vec(pos + 8, size as usize)?;
                s.chunk(kind, &data, cx);
            } else {
                s.skipped.push(String::from_utf8_lossy(&kind).into_owned());
            }
            pos = end;
        }
        s.finish(cx);
        Ok(())
    }
}

crate::register_extractor!(Png);

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // independent chunk flags, not options
struct State {
    chunks: u64,
    idat_chunks: u64,
    idat_bytes: u64,
    iend: bool,
    trailing: u64,
    texts: Map<String, Value>,
    apng: Option<(u32, u32)>,
    frame_delay_s: f64,
    c2pa: bool,
    palette: Option<usize>,
    transparency: bool,
    gamma: Option<f64>,
    srgb: bool,
    apple: bool,
    skipped: Vec<String>,
    ai: Option<Value>,
}

impl State {
    fn chunk(&mut self, kind: [u8; 4], d: &[u8], cx: &mut Context<'_>) {
        match &kind {
            b"IHDR" if d.len() >= 13 => {
                let w = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                let h = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
                let (bits, color) = (d[8], d[9]);
                let (channels, space) = match color {
                    0 => (1, "Gray"),
                    2 => (3, "RGB"),
                    3 => (3, "palette"),
                    4 => (2, "Gray"),
                    6 => (4, "RGB"),
                    _ => (0, "unknown"),
                };
                cx.physical().image(w, h).bit_depth(bits).channels(channels);
                cx.format_set("color_type", color);
                cx.format_set("color_model", space);
                cx.format_set("alpha", matches!(color, 4 | 6));
                cx.format_set("interlaced", d[12] == 1);
            }
            b"PLTE" => self.palette = Some(d.len() / 3),
            b"tRNS" => self.transparency = true,
            b"gAMA" if d.len() == 4 => {
                self.gamma = Some(f64::from(u32::from_be_bytes([d[0], d[1], d[2], d[3]])) / 100_000.0);
            }
            b"sRGB" => self.srgb = true,
            b"CgBI" | b"iDOT" => self.apple = true,
            b"iCCP" => {
                if let Some(nul) = d.iter().position(|&b| b == 0)
                    && d.len() > nul + 2
                {
                    cx.format_set("icc_profile_name", String::from_utf8_lossy(&d[..nul]).into_owned());
                    match cx.inflate(&d[nul + 2..], Compression::Zlib, MAX_INFLATE) {
                        Ok(icc) => cx.emit_block(BlockKind::ICC, icc),
                        Err(e) => cx.warn(format!("iCCP: {e}")),
                    }
                }
            }
            b"pHYs" if d.len() == 9 && d[8] == 1 => {
                let x = f64::from(u32::from_be_bytes([d[0], d[1], d[2], d[3]])) * 0.0254;
                let y = f64::from(u32::from_be_bytes([d[4], d[5], d[6], d[7]])) * 0.0254;
                if let Some(mut img) = cx.physical().existing_image() {
                    img.dpi((x * 100.0).round() / 100.0, (y * 100.0).round() / 100.0);
                }
            }
            b"tIME" if d.len() == 7 => {
                let year = u16::from_be_bytes([d[0], d[1]]);
                let t = format!("{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", d[2], d[3], d[4], d[5], d[6]);
                if let Some((v, tz)) = crate::plugin::parse_date(&t) {
                    cx.temporal().source("png.tIME").content_date(DateField::Modified, v, tz);
                }
            }
            b"eXIf" => cx.emit_block(BlockKind::EXIF, d.to_vec()),
            b"acTL" if d.len() >= 8 => {
                self.apng =
                    Some((u32::from_be_bytes([d[0], d[1], d[2], d[3]]), u32::from_be_bytes([d[4], d[5], d[6], d[7]])));
            }
            b"fcTL" if d.len() >= 26 => {
                let num = f64::from(u16::from_be_bytes([d[20], d[21]]));
                let den = match u16::from_be_bytes([d[22], d[23]]) {
                    0 => 100.0,
                    n => f64::from(n),
                };
                self.frame_delay_s += num / den;
            }
            b"caBX" => self.c2pa = true,
            b"tEXt" => {
                if let Some((k, v)) = split_keyword(d) {
                    self.text(k, crate::plugin::latin1_or_utf8(v), cx);
                }
            }
            b"zTXt" => {
                if let Some((k, v)) = split_keyword(d)
                    && v.len() > 1
                {
                    match cx.inflate(&v[1..], Compression::Zlib, MAX_INFLATE) {
                        Ok(t) => self.text(k, crate::plugin::latin1_or_utf8(&t), cx),
                        Err(e) => cx.warn(format!("zTXt {k}: {e}")),
                    }
                }
            }
            b"iTXt" => self.itxt(d, cx),
            _ => {}
        }
    }

    /// `keyword\0 flag method lang\0 translated\0 text`.
    fn itxt(&mut self, d: &[u8], cx: &mut Context<'_>) {
        let Some((k, rest)) = split_keyword(d) else { return };
        if rest.len() < 2 {
            return;
        }
        let (compressed, rest) = (rest[0] == 1, &rest[2..]);
        let mut parts = rest.splitn(3, |&b| b == 0);
        let (_lang, _translated, body) = (parts.next(), parts.next(), parts.next().unwrap_or_default());
        let text = if compressed {
            match cx.inflate(body, Compression::Zlib, MAX_INFLATE) {
                Ok(t) => String::from_utf8_lossy(&t).into_owned(),
                Err(e) => {
                    cx.warn(format!("iTXt {k}: {e}"));
                    return;
                }
            }
        } else {
            String::from_utf8_lossy(body).into_owned()
        };
        self.text(k, text, cx);
    }

    fn text(&mut self, keyword: String, value: String, cx: &mut Context<'_>) {
        let src = format!("png.{keyword}");
        match keyword.as_str() {
            "XML:com.adobe.xmp" => {
                cx.emit_block(BlockKind::XMP, value.into_bytes());
                return;
            }
            k if k.starts_with("Raw profile type ") => {
                if let Some(bytes) = imagemagick_profile(&value) {
                    match &k["Raw profile type ".len()..] {
                        "exif" | "APP1" => cx.emit_block(BlockKind::EXIF, bytes),
                        "xmp" => cx.emit_block(BlockKind::XMP, bytes),
                        "iptc" | "8bim" => cx.emit_block(BlockKind::PHOTOSHOP_IRB, bytes),
                        "icc" | "icm" => cx.emit_block(BlockKind::ICC, bytes),
                        _ => {}
                    }
                }
                return;
            }
            "Title" => {
                cx.content().source(src).title(value.clone());
                cx.emit_text(TextRole::Title, &value);
            }
            "Author" => {
                cx.content().source(src.clone()).author(value.clone());
                cx.rights().source(src).creator(value.clone());
            }
            "Description" => {
                cx.content().source(src).description(value.clone());
                cx.emit_text(TextRole::Caption, &value);
            }
            "Copyright" => {
                cx.rights().source(src).copyright(value.clone());
            }
            "Creation Time" => {
                if let Some((d, tz)) = crate::plugin::parse_date(&value) {
                    cx.temporal().source(src).content_date(DateField::Created, d, tz);
                }
            }
            "Comment" => cx.emit_text(TextRole::Comment, &value),
            "parameters" => self.ai = Some(a1111(&value)),
            "prompt" | "workflow" if value.trim_start().starts_with('{') => {
                if self.ai.is_none() || keyword == "prompt" {
                    self.ai = comfyui(&value).or(self.ai.take());
                }
            }
            "invokeai_metadata" | "sd-metadata" | "Dream" => self.ai = Some(invokeai(&keyword, &value)),
            _ => {}
        }
        if self.texts.len() < 64 {
            self.texts.insert(keyword, json!(truncate_chars(&value, 2000)));
        }
    }

    fn finish(mut self, cx: &mut Context<'_>) {
        if let Some((frames, plays)) = self.apng {
            cx.format_set("animation", json!({ "frames": frames, "plays": plays, "duration_s": (self.frame_delay_s * 1000.0).round() / 1000.0 }));
            if let Some(mut img) = cx.physical().existing_image() {
                img.frames(frames);
            }
            if self.frame_delay_s > 0.0 {
                cx.physical().duration_s((self.frame_delay_s * 1000.0).round() / 1000.0);
            }
        }
        if self.srgb
            && let Some(mut img) = cx.physical().existing_image()
        {
            img.color_space("sRGB");
        }
        if let Some(n) = self.palette {
            cx.format_set("palette_entries", n);
        }
        cx.format_set("transparency", self.transparency);
        if let Some(g) = self.gamma {
            cx.format_set("gamma", g);
        }
        if self.apple {
            cx.format_set("apple_extensions", true);
        }
        cx.format_set("chunks", self.chunks);
        cx.format_set("idat", json!({ "chunks": self.idat_chunks, "bytes": self.idat_bytes }));
        if !self.iend {
            cx.format_set("complete", false);
        }
        if self.trailing > 0 {
            cx.format_set("trailing_bytes", self.trailing);
            cx.security().risk("trailing_data", Some(format!("{} bytes after IEND", self.trailing)));
        }
        if self.c2pa {
            cx.format_set("c2pa", true);
            cx.security().signed(true);
        }
        if let Some(ai) = self.ai.take() {
            if let Some(p) = ai["prompt"].as_str().filter(|p| !p.is_empty()) {
                cx.content().source("png.ai.prompt").description(truncate_chars(p, 2000));
                cx.emit_text(TextRole::Caption, p);
            }
            let tool = ai["tool"].as_str().unwrap_or("unknown").to_string();
            cx.security().risk("ai_generated", Some(format!("generation parameters from {tool}")));
            *cx.metadata("ai_generation") = ai.as_object().cloned().unwrap_or_default();
        }
        if !self.texts.is_empty() {
            *cx.metadata("png_text") = std::mem::take(&mut self.texts);
        }
        if !self.skipped.is_empty() {
            cx.format_set("chunks_not_read", json!(self.skipped));
        }
    }
}

fn split_keyword(d: &[u8]) -> Option<(String, &[u8])> {
    let nul = d.iter().take(80).position(|&b| b == 0)?;
    Some((String::from_utf8_lossy(&d[..nul]).into_owned(), &d[nul + 1..]))
}

/// ImageMagick's text profile (`exif`, the byte count, then hex lines) → bytes.
fn imagemagick_profile(s: &str) -> Option<Vec<u8>> {
    let mut lines = s.trim_start().lines();
    let _name = lines.next()?;
    let len: usize = lines.next()?.trim().parse().ok()?;
    let hex: String = lines.flat_map(|l| l.chars()).filter(char::is_ascii_hexdigit).collect();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect();
    (bytes.len() == len).then_some(bytes)
}

/// Stable Diffusion WebUI: prompt, `Negative prompt: …`, then `Key: value, …`.
fn a1111(text: &str) -> Value {
    let mut prompt = Vec::new();
    let mut negative = None;
    let mut settings = Map::new();
    for line in text.lines() {
        if let Some(n) = line.strip_prefix("Negative prompt:") {
            negative = Some(n.trim().to_string());
        } else if line.starts_with("Steps:") {
            for part in line.split(", ") {
                if let Some((k, v)) = part.split_once(": ") {
                    settings.insert(k.trim().to_string(), json!(v.trim()));
                }
            }
        } else if negative.is_none() {
            prompt.push(line);
        }
    }
    json!({
        "tool": "Stable Diffusion web UI",
        "prompt": truncate_chars(prompt.join("\n").trim(), 4000),
        "negative_prompt": negative.map(|n| truncate_chars(&n, 2000)),
        "model": settings.get("Model").cloned(),
        "settings": settings,
    })
}

/// ComfyUI's API-format graph: node types, checkpoints and text prompts.
fn comfyui(text: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(text).ok()?;
    let nodes: Vec<&Value> = match &v {
        Value::Object(m) if m.contains_key("nodes") => m["nodes"].as_array()?.iter().collect(),
        Value::Object(m) => m.values().collect(),
        _ => return None,
    };
    let mut models = Vec::new();
    let mut prompts = Vec::new();
    let mut types = std::collections::BTreeMap::<String, u64>::new();
    for n in nodes.iter().take(5000) {
        let ty = n.get("class_type").or_else(|| n.get("type")).and_then(Value::as_str).unwrap_or("?");
        *types.entry(ty.to_string()).or_default() += 1;
        let inputs = n.get("inputs");
        if let Some(c) = inputs.and_then(|i| i.get("ckpt_name")).and_then(Value::as_str) {
            models.push(c.to_string());
        }
        if ty.starts_with("CLIPTextEncode")
            && let Some(t) = inputs.and_then(|i| i.get("text")).and_then(Value::as_str)
            && prompts.len() < 4
        {
            prompts.push(truncate_chars(t, 2000));
        }
    }
    Some(json!({
        "tool": "ComfyUI",
        "prompt": prompts.first(),
        "prompts": prompts,
        "models": models,
        "nodes": nodes.len(),
        "node_types": types,
    }))
}

fn invokeai(key: &str, text: &str) -> Value {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let prompt = v
        .get("positive_prompt")
        .or_else(|| v.get("prompt"))
        .or_else(|| v.pointer("/image/prompt/0/prompt"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| (key == "Dream").then(|| text.split(" -").next().unwrap_or(text).trim_matches('"').to_string()));
    json!({
        "tool": "InvokeAI",
        "prompt": prompt.map(|p| truncate_chars(&p, 4000)),
        "model": v.pointer("/model/name").or_else(|| v.get("model_weights")).cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_parameters() {
        let a = a1111(
            "a harbour at dusk, boats\nNegative prompt: blurry\nSteps: 20, Sampler: Euler a, CFG scale: 7, Model: sdxl-base",
        );
        assert_eq!(a["prompt"], "a harbour at dusk, boats");
        assert_eq!(a["negative_prompt"], "blurry");
        assert_eq!(a["model"], "sdxl-base");
        let c = comfyui(
            r#"{"4":{"class_type":"CheckpointLoaderSimple","inputs":{"ckpt_name":"sd_xl.safetensors"}},
                           "6":{"class_type":"CLIPTextEncode","inputs":{"text":"lighthouse at night"}}}"#,
        )
        .unwrap();
        assert_eq!(c["models"], json!(["sd_xl.safetensors"]));
        assert_eq!(c["prompt"], "lighthouse at night");
        assert_eq!(imagemagick_profile("\nexif\n       3\n414243\n"), Some(b"ABC".to_vec()));
    }

    crate::fixture_tests!("png", "apng");
}
