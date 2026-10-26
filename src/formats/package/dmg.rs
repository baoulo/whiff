//! Apple disk images (UDIF `.dmg`): the `koly` trailer (version, flags,
//! image variant, sector count and so the disk size, data fork and
//! resource sizes, segment number, checksum kinds) and the XML property
//! list it points to: the partitions (`blkx` entries: name, sectors) and,
//! from each partition's `mish` block table, how its chunks are stored
//! (zlib, bzip2, LZFSE, LZMA, ADC, raw, zero fill). A software licence
//! agreement shown before mounting (`LPic` / `TEXT` resources) is noted.
//! Encrypted images (`encrcdsa`) are recognised as such; an image without
//! the trailer is a raw disk image (`UDRW`, cryptexes). File-system
//! contents are not read here.
//!
//! Specifications: Apple's UDIF layout as documented by the libdmg-hfsplus
//! and `dmg2img` projects (the koly trailer and `mish` block tables).

use std::collections::BTreeMap;

use plist::Value as Plist;

use super::Package;
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
};

/// Extractor for Apple disk images.
pub struct Dmg;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.dmg",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "dmg",
        name: "Apple disk image",
        family: "package",
        mimes: &["application/x-apple-diskimage"],
        extensions: &["dmg"],
        magic: &[],
        parent: None,
    }],
};

/// Largest property list read.
const MAX_XML: u64 = 32 << 20;
/// Partitions listed at most.
const MAX_PARTITIONS: usize = 64;

fn chunk_method(ty: u32) -> Option<&'static str> {
    Some(match ty {
        0x0000_0000 | 0x0000_0002 => "zero",
        0x0000_0001 => "raw",
        0x8000_0004 => "adc",
        0x8000_0005 => "zlib",
        0x8000_0006 => "bzip2",
        0x8000_0007 => "lzfse",
        0x8000_0008 => "lzma",
        _ => return None,
    })
}

fn checksum_kind(ty: u32) -> Option<&'static str> {
    match ty {
        0 => None,
        2 => Some("crc32"),
        4 => Some("md5"),
        _ => Some("other"),
    }
}

/// Chunk methods of a `mish` block table, with their counts.
fn mish(data: &[u8], methods: &mut BTreeMap<&'static str, u64>) -> Option<u64> {
    let mut r = ByteReader::new(data);
    if r.array::<4>().ok()? != *b"mish" {
        return None;
    }
    let _version = r.be_u32().ok()?;
    let _first = r.be_u64().ok()?;
    let sectors = r.be_u64().ok()?;
    let mut r = ByteReader::new(data.get(200..)?);
    let n = r.be_u32().ok()? as usize;
    for _ in 0..n.min(1 << 20) {
        let Ok(ty) = r.be_u32() else { break };
        if r.advance(36).is_err() {
            break;
        }
        if let Some(m) = chunk_method(ty) {
            *methods.entry(m).or_default() += 1;
        }
    }
    Some(sectors)
}

impl Extractor for Dmg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let koly = probe.tail.len() >= 512 && probe.tail[probe.tail.len() - 512..].starts_with(b"koly");
        let encrypted = probe.head.starts_with(b"encrcdsa")
            || probe.tail.len() >= 8 && probe.tail[probe.tail.len() - 8..] == *b"cdsaencr";
        (koly || encrypted && probe.extension == Some("dmg")).then_some(Sniff { format: "dmg", confidence: 0.95 })
    }

    #[allow(clippy::too_many_lines)] // trailer, plist, partitions
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut pkg = Package::new("apple_disk_image");
        if src.head().starts_with(b"encrcdsa") || src.tail().ends_with(b"cdsaencr") {
            pkg.set("encryption", if src.head().starts_with(b"encrcdsa") { "encrcdsa v2" } else { "cdsaencr v1" });
            cx.security().encrypted(true);
            pkg.write(cx);
            return Ok(());
        }
        let k = if len >= 512 { src.read_vec(len - 512, 512)? } else { Vec::new() };
        if !k.starts_with(b"koly") {
            // No UDIF trailer: a raw (read-write or sparse-free) image, the
            // file being the disk itself.
            pkg.set("format", "raw");
            pkg.set("disk_bytes", len);
            pkg.write(cx);
            return Ok(());
        }
        let mut r = ByteReader::new(&k);
        r.advance(4)?;
        let version = r.be_u32()?;
        let _header = r.be_u32()?;
        let flags = r.be_u32()?;
        let _running = r.be_u64()?;
        let data_offset = r.be_u64()?;
        let data_len = r.be_u64()?;
        let _rsrc_offset = r.be_u64()?;
        let rsrc_len = r.be_u64()?;
        let segment = r.be_u32()?;
        let segments = r.be_u32()?;
        let _segment_id = r.array::<16>()?;
        let data_checksum = r.be_u32()?;
        let mut r = ByteReader::new(&k[216..]);
        let xml_offset = r.be_u64()?;
        let xml_len = r.be_u64()?;
        let master_checksum = u32::from_be_bytes([k[352], k[353], k[354], k[355]]);
        let variant = u32::from_be_bytes([k[488], k[489], k[490], k[491]]);
        let sectors = u64::from_be_bytes(k[492..500].try_into().unwrap_or([0; 8]));
        pkg.set("format", "UDIF");
        pkg.set("udif_version", version);
        if flags & 1 != 0 {
            pkg.set("flattened", true);
        }
        pkg.set(
            "image_variant",
            match variant {
                1 => "device",
                2 => "partition",
                _ => "other",
            },
        );
        pkg.set("sectors", sectors);
        pkg.set("disk_bytes", sectors.saturating_mul(512));
        pkg.set("data_fork_bytes", data_len);
        if data_offset > 0 {
            pkg.set("data_fork_offset", data_offset);
        }
        if rsrc_len > 0 {
            pkg.set("resource_fork_bytes", rsrc_len);
        }
        if segments > 1 {
            pkg.set("segment", format!("{segment} of {segments}"));
        }
        for (key, kind) in [("data_checksum", data_checksum), ("master_checksum", master_checksum)] {
            if let Some(k) = checksum_kind(kind) {
                pkg.set(key, k);
            }
        }
        cx.physical().uncompressed_bytes(sectors.saturating_mul(512));
        if xml_len == 0 || xml_len > MAX_XML || xml_offset.saturating_add(xml_len) > len {
            pkg.write(cx);
            return Ok(());
        }
        let xml = src.read_vec(xml_offset, usize::try_from(xml_len).unwrap_or(0))?;
        let Ok(plist) = Plist::from_reader(std::io::Cursor::new(&xml)) else {
            cx.warn("the property list does not parse");
            pkg.write(cx);
            return Ok(());
        };
        let fork = plist.as_dictionary().and_then(|d| d.get("resource-fork")).and_then(Plist::as_dictionary);
        let mut methods: BTreeMap<&'static str, u64> = BTreeMap::new();
        let mut partitions = Vec::new();
        for b in fork.and_then(|f| f.get("blkx")).and_then(Plist::as_array).into_iter().flatten() {
            let Some(d) = b.as_dictionary() else { continue };
            let name = d.get("Name").or_else(|| d.get("CFName")).and_then(Plist::as_string).unwrap_or("").to_string();
            let sectors = d.get("Data").and_then(Plist::as_data).and_then(|m| mish(m, &mut methods));
            if partitions.len() < MAX_PARTITIONS {
                let mut p = serde_json::Map::new();
                p.insert("name".into(), name.into());
                if let Some(s) = sectors {
                    p.insert("bytes".into(), (s * 512).into());
                }
                partitions.push(serde_json::Value::Object(p));
            }
        }
        if !partitions.is_empty() {
            pkg.set("partitions", partitions);
        }
        if !methods.is_empty() {
            pkg.set("chunk_methods", serde_json::to_value(&methods).unwrap_or_default());
        }
        if let Some(f) = fork
            && (f.contains_key("LPic") || f.contains_key("TEXT") || f.contains_key("RTF "))
        {
            pkg.set("license_agreement", true);
        }
        pkg.write(cx);
        Ok(())
    }
}

crate::register_extractor!(Dmg);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_table() {
        let mut m = vec![0u8; 204];
        m[..4].copy_from_slice(b"mish");
        m[16..24].copy_from_slice(&8u64.to_be_bytes());
        m[200..204].copy_from_slice(&2u32.to_be_bytes());
        for ty in [0x8000_0005u32, 0xffff_ffff] {
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&[0; 36]);
        }
        let mut methods = BTreeMap::new();
        assert_eq!(mish(&m, &mut methods), Some(8));
        assert_eq!(methods.get("zlib"), Some(&1));
    }

    crate::fixture_tests!("dmg");
}
