//! Raw disk images (a byte-for-byte copy of a disk: `dd`, `.img`) and
//! file-system images (one volume: ext2 / 3 / 4, FAT, exFAT, NTFS, HFS+,
//! APFS, LUKS). The partition table and every partition's file system are
//! described (type, label, UUID, block size, size and free space, times,
//! APFS volumes and roles, encryption); FAT volumes are listed and their
//! files handed on.
//!
//! Specifications: see [`volume`](crate::plugin::volume).

use serde_json::Value;

use super::report_contents;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, volume};

/// Extractor for raw disk and file-system images.
pub struct RawDisk;

const fn fs(id: &'static str, name: &'static str, extensions: &'static [&'static str]) -> FormatSpec {
    FormatSpec {
        id,
        name,
        family: "disk",
        mimes: &["application/x-raw-disk-image"],
        extensions,
        magic: &[],
        parent: None,
    }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.raw",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        fs("raw_disk", "Raw disk image", &["img", "raw", "dd"]),
        fs("ext", "ext2 / ext3 / ext4 file system image", &["ext2", "ext3", "ext4"]),
        fs("fat", "FAT file system image", &["ima", "vfd", "flp"]),
        fs("exfat", "exFAT file system image", &["exfat"]),
        fs("ntfs", "NTFS file system image", &["ntfs"]),
        fs("hfs_plus", "HFS / HFS+ file system image", &["hfs", "hfsx"]),
        fs("apfs", "APFS container image", &["apfs"]),
        fs("luks", "LUKS encrypted volume", &["luks"]),
    ],
};

/// The format a file-system kind is reported as.
fn format_of(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "ext2" | "ext3" | "ext4" => "ext",
        "fat12" | "fat16" | "fat32" => "fat",
        "exfat" => "exfat",
        "ntfs" => "ntfs",
        "hfs" | "hfs_plus" | "hfsx" => "hfs_plus",
        "apfs" => "apfs",
        "luks" => "luks",
        "xfs" | "swap" | "lvm2" | "bitlocker" | "refs" => "raw_disk",
        _ => return None,
    })
}

impl Extractor for RawDisk {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // ISO 9660 / UDF images (hybrids included) are read as such.
        if h.get(32769..32774).is_some_and(|m| m == b"CD001" || m == b"BEA01") {
            return None;
        }
        if let Some(format) = volume::identify(h).and_then(format_of) {
            let confidence = if format == "fat" || format == "raw_disk" { 0.85 } else { 0.92 };
            return Some(Sniff { format, confidence });
        }
        let gpt = [512usize, 4096].iter().any(|&s| h.get(s..s + 8) == Some(b"EFI PART"));
        let apm = h.starts_with(b"ER") && h.get(512..514) == Some(b"PM");
        if gpt || apm {
            return Some(Sniff { format: "raw_disk", confidence: 0.92 });
        }
        volume::is_mbr(h).then_some(Sniff { format: "raw_disk", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        cx.format_set("disk_bytes", len);
        let fs = volume::filesystem(src, 0, len).filter(volume::FileSystem::whole_disk);
        if let Some(Value::String(label)) = fs.as_ref().and_then(|fs| fs.facts.get("label")) {
            cx.content().title(label.clone());
        }
        report_contents(src, cx);
        if fs.is_none() && cx.format().get("partition_table").is_none() {
            cx.warn("no partition table or file system recognised");
        }
        Ok(())
    }
}

crate::register_extractor!(RawDisk);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_to_formats() {
        assert_eq!(format_of("ext3"), Some("ext"));
        assert_eq!(format_of("fat32"), Some("fat"));
        assert_eq!(format_of("iso9660"), None);
    }

    crate::fixture_tests!("raw_disk", "ext", "fat", "exfat", "ntfs", "hfs_plus", "apfs", "luks");
}
