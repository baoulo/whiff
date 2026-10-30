//! Compiled asset catalogs (`Assets.car`): the `CARHEADER` (CoreUI and
//! storage versions, schema, rendition count, build timestamp, the version
//! strings of CoreUI and of the tool that compiled it), the extended
//! metadata (deployment platform and version, authoring tool, thinning
//! arguments), the rendition key format, the asset names (facets), the
//! appearances and a histogram of rendition types (image, PDF, data, color …).
//!
//! The file is a BOM store (the format of package receipts); its named
//! blocks and B-trees are read directly.
//!
//! Specifications: the BOM layout of `lsbom` / Joseph Coffland's notes;
//! CoreUI structures (`CARHEADER`, `CSIHEADER`, `kfmt`) as documented by
//! the `iOS-Asset-Extractor`, `acextract` and `QLCARFiles` projects.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde_json::{Map, Value};

use super::unix_time;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for compiled asset catalogs.
pub struct AssetCatalog;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.car",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "car",
        name: "Apple asset catalog compiled",
        family: "apple",
        mimes: &[],
        extensions: &["car"],
        magic: &[Magic::at(0, b"BOMStore")],
        parent: None,
    }],
};

/// Names listed.
const MAX_NAMES: usize = 200;
/// Tree pages visited per tree.
const MAX_PAGES: usize = 50_000;
/// Entries read per tree.
const MAX_ENTRIES: usize = 200_000;

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_usize(b: &[u8], at: usize) -> Option<usize> {
    usize::try_from(be32(b, at)?).ok()
}

/// A NUL-terminated string in a fixed field (asset names keep their spaces).
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The BOM store: block table and named variables, read through the
/// source (the index sits at the end of large catalogs).
struct Bom<'s> {
    src: &'s mut dyn Source,
    blocks: Vec<(u64, usize)>,
    vars: BTreeMap<String, u32>,
}

impl<'s> Bom<'s> {
    fn open(src: &'s mut dyn Source) -> Option<Self> {
        let head = src.read_vec(0, 32).ok()?;
        let (index, index_len) = (be32(&head, 16)?, be_usize(&head, 20)?);
        let (vars_at, vars_len) = (be32(&head, 24)?, be_usize(&head, 28)?);
        let table = src.read_vec(u64::from(index), index_len.min(8 << 20)).ok()?;
        let n = be_usize(&table, 0)?;
        let blocks = (0..n.min(1 << 20))
            .map_while(|i| Some((u64::from(be32(&table, 4 + 8 * i)?), be_usize(&table, 8 + 8 * i)?)))
            .collect();
        let v = src.read_vec(u64::from(vars_at), vars_len.min(1 << 16)).ok()?;
        let count = be_usize(&v, 0)?;
        let mut at = 4;
        let mut vars = BTreeMap::new();
        for _ in 0..count.min(256) {
            let id = be32(&v, at)?;
            let len = usize::from(*v.get(at + 4)?);
            let name = String::from_utf8_lossy(v.get(at + 5..at + 5 + len)?).into_owned();
            vars.insert(name, id);
            at += 5 + len;
        }
        Some(Self { src, blocks, vars })
    }

    /// The first `max` bytes of block `id`.
    fn block(&mut self, id: u32, max: usize) -> Option<Vec<u8>> {
        let &(off, len) = self.blocks.get(usize::try_from(id).ok()?)?;
        self.src.read_vec(off, len.min(max)).ok()
    }

    fn var(&mut self, name: &str) -> Option<Vec<u8>> {
        let id = *self.vars.get(name)?;
        self.block(id, 1 << 16)
    }

    /// The `(key, value head)` blocks of a B-tree, in order.
    fn tree(&mut self, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let Some(t) = self.var(name).filter(|t| t.starts_with(b"tree")) else { return out };
        let Some(mut page) = be32(&t, 8) else { return out };
        let mut seen = HashSet::new();
        // Down the first children to the leftmost leaf, then along the leaves.
        while seen.insert(page) && seen.len() < MAX_PAGES && out.len() < MAX_ENTRIES {
            let Some(p) = self.block(page, 1 << 16) else { break };
            let (Some(leaf), Some(count)) = (p.get(0..2), p.get(2..4)) else { break };
            let count = usize::from(u16::from_be_bytes([count[0], count[1]]));
            if leaf == [0, 0] {
                match be32(&p, 12) {
                    Some(child) => {
                        page = child;
                        continue;
                    }
                    None => break,
                }
            }
            for i in 0..count {
                let (Some(v), Some(k)) = (be32(&p, 12 + 8 * i), be32(&p, 16 + 8 * i)) else { break };
                if let (Some(k), Some(v)) = (self.block(k, 1024), self.block(v, 512)) {
                    out.push((k, v));
                }
            }
            match be32(&p, 4) {
                Some(next) if next != 0 => page = next,
                _ => break,
            }
        }
        out
    }
}

/// Rendition attribute names (`kfmt` identifiers).
fn attribute(id: u32) -> String {
    let name = match id {
        1 => "element",
        2 => "part",
        3 => "size",
        4 => "direction",
        5 => "placeholder",
        6 => "value",
        7 => "appearance",
        8 => "dimension1",
        9 => "dimension2",
        10 => "state",
        11 => "layer",
        12 => "scale",
        13 => "localization",
        14 => "presentation_state",
        15 => "idiom",
        16 => "subtype",
        17 => "identifier",
        18 => "previous_value",
        19 => "previous_state",
        20 => "size_class_horizontal",
        21 => "size_class_vertical",
        22 => "memory_class",
        23 => "graphics_class",
        24 => "display_gamut",
        25 => "deployment_target",
        26 => "glyph_weight",
        27 => "glyph_size",
        _ => return format!("attribute_{id}"),
    };
    name.to_string()
}

/// The kind of a rendition from its `CSIHEADER`.
fn rendition_kind(v: &[u8]) -> &'static str {
    if !v.starts_with(b"ISTC") {
        return "unknown";
    }
    let body = v.get(184..).unwrap_or_default();
    if body.windows(4).any(|w| w == b"RLOC") {
        return "color";
    }
    match v.get(24..28).map(|f| [f[3], f[2], f[1], f[0]]) {
        Some(ref f) if f == b"DATA" => "data",
        Some(ref f) if f == b"PDF " => "pdf",
        Some(ref f) if f == b"SVG " => "svg",
        Some(ref f) if f == b"JPEG" || f == b"HEIF" => "image_compressed",
        Some(ref f) if f == b"ARGB" || f == b"GA8 " || f == b"GA16" || f == b"RGB5" || f == b"RGBW" || f == b"RGBF" => {
            "image"
        }
        _ => "other",
    }
}

impl Extractor for AssetCatalog {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut bom = Bom::open(src).ok_or_else(|| ExtractError::malformed("BOM store"))?;
        let Some(h) = bom.var("CARHEADER").filter(|h| h.starts_with(b"RATC")) else {
            // A BOM store that is not an asset catalog (a package receipt).
            cx.format_set("kind", "bom");
            cx.format_set("variables", bom.vars.keys().cloned().collect::<Vec<_>>());
            return Ok(());
        };
        cx.format_set("kind", "asset_catalog");
        let u = |at: usize| le32(&h, at).unwrap_or(0);
        cx.format_set("coreui_version", u(4));
        cx.format_set("storage_version", u(8));
        if let Some(t) = unix_time(i64::from(u(12))) {
            cx.format_set("timestamp", t);
        }
        cx.format_set("renditions", u(16));
        let main = cstr(h.get(20..148).unwrap_or_default()).trim().to_string();
        if !main.is_empty() {
            cx.format_set("main_version", truncate_chars(&main, 128));
        }
        let ver = cstr(h.get(148..404).unwrap_or_default()).trim().to_string();
        if !ver.is_empty() {
            cx.format_set("asset_storage_version", truncate_chars(&ver, 256));
        }
        cx.format_set("schema_version", u(424));
        if let Some(m) = bom.var("EXTENDED_METADATA").filter(|m| m.starts_with(b"META")) {
            for (at, key) in
                [(4, "thinning_arguments"), (260, "platform_version"), (516, "platform"), (772, "authoring_tool")]
            {
                let s = cstr(m.get(at..at + 256).unwrap_or_default()).trim().to_string();
                if !s.is_empty() {
                    cx.format_set(key, truncate_chars(&s, 256));
                }
            }
        }
        if let Some(k) = bom.var("KEYFORMAT").filter(|k| k.starts_with(b"tmfk")) {
            let n = le32(&k, 8).unwrap_or(0).min(64);
            let attrs: Vec<String> = (0..n).filter_map(|i| le32(&k, 12 + 4 * i as usize)).map(attribute).collect();
            cx.format_set("key_format", attrs);
        }
        let appearances: Vec<String> =
            bom.tree("APPEARANCEKEYS").iter().map(|(k, _)| truncate_chars(&cstr(k), 128)).collect();
        if !appearances.is_empty() {
            cx.format_set("appearances", appearances);
        }
        cx.checkpoint()?;
        let mut kinds: BTreeMap<&str, u64> = BTreeMap::new();
        let mut rendition_names: BTreeSet<String> = BTreeSet::new();
        for (_, v) in bom.tree("RENDITIONS") {
            *kinds.entry(rendition_kind(&v)).or_default() += 1;
            // CSI metadata: modification time, layout, then the name.
            if v.starts_with(b"ISTC") && rendition_names.len() < 100_000 {
                rendition_names.insert(cstr(v.get(40..168).unwrap_or_default()));
            }
        }
        // Old theme catalogs have no FACETKEYS: their renditions carry the names.
        let facets: Vec<String> = bom.tree("FACETKEYS").iter().map(|(k, _)| cstr(k)).collect();
        let names: Vec<String> = if facets.is_empty() {
            // Packed-image atlases are renditions, not assets.
            rendition_names.into_iter().filter(|n| !n.is_empty() && !n.starts_with("ZZZZPackedAsset-")).collect()
        } else {
            facets
        };
        cx.format_set("assets", names.len());
        let shown: Vec<String> = names.iter().take(MAX_NAMES).map(|n| truncate_chars(n, 128)).collect();
        if !shown.is_empty() {
            cx.format_set("names", shown);
        }
        if !kinds.is_empty() {
            let m: Map<String, Value> = kinds.into_iter().map(|(k, n)| (k.to_string(), n.into())).collect();
            cx.format_set("rendition_types", Value::Object(m));
        }
        Ok(())
    }
}

crate::register_extractor!(AssetCatalog);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_kinds() {
        assert_eq!(attribute(12), "scale");
        assert_eq!(attribute(99), "attribute_99");
        assert_eq!(cstr(b"Tide\0\0junk"), "Tide");
        let mut csi = b"ISTC".to_vec();
        csi.resize(24, 0);
        csi.extend(b"ATAD");
        assert_eq!(rendition_kind(&csi), "data");
    }

    crate::fixture_tests!("car");
}
