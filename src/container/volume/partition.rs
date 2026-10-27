//! Partition tables: MBR (with the extended-partition chain), GPT (header
//! and entry checksums checked) and the Apple Partition Map.
//!
//! Specifications: UEFI 2.10 §5 (GPT); the MBR and EBR layouts as IBM PC
//! firmware and every OS read them; Apple "Inside Macintosh: Devices"
//! (driver descriptor and partition map).

use serde_json::{Map, Value, json};

use super::num::{be16, be32, le32, le64};
use super::{MAX_PARTITIONS, guid_le, text_field, utf16_field};
use crate::container::codec::crc32;
use crate::io::Source;

/// One partition.
#[derive(Debug, Clone, Default)]
pub struct Partition {
    /// 1-based number (MBR: 1–4 primary, 5… logical).
    pub index: u32,
    /// Start, in bytes from the start of the disk.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
    /// Readable type name, when known.
    pub kind: Option<&'static str>,
    /// Type as stored: MBR type byte (`0x83`), GPT type GUID, APM type string.
    pub type_id: String,
    /// Partition name (GPT, APM).
    pub name: Option<String>,
    /// Unique partition GUID (GPT).
    pub guid: Option<String>,
    /// Active / legacy-BIOS-bootable flag.
    pub bootable: bool,
    /// GPT attribute names.
    pub attributes: Vec<&'static str>,
    /// An extended-partition container (MBR) or the map itself (APM): holds
    /// no file system.
    pub container: bool,
}

impl Partition {
    /// The partition as report facts.
    pub fn facts(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("index".into(), json!(self.index));
        m.insert("start_bytes".into(), json!(self.start));
        m.insert("size_bytes".into(), json!(self.size));
        if let Some(k) = self.kind {
            m.insert("type".into(), json!(k));
        }
        m.insert("type_id".into(), json!(self.type_id));
        if let Some(n) = &self.name {
            m.insert("name".into(), json!(n));
        }
        if let Some(g) = &self.guid {
            m.insert("guid".into(), json!(g));
        }
        if self.bootable {
            m.insert("bootable".into(), json!(true));
        }
        if !self.attributes.is_empty() {
            m.insert("attributes".into(), json!(self.attributes));
        }
        m
    }
}

/// A partition table.
#[derive(Debug, Clone, Default)]
pub struct Table {
    /// `mbr`, `gpt` or `apm`.
    pub scheme: &'static str,
    /// Logical sector size the table is laid out in.
    pub sector_size: u32,
    /// GPT disk GUID, or the MBR disk signature.
    pub disk_id: Option<String>,
    /// The partitions, in table order.
    pub partitions: Vec<Partition>,
    /// Problems found (checksum mismatches, entries past the end).
    pub notes: Vec<String>,
}

/// Read the partition table, if the disk has one (GPT first, then APM,
/// then MBR).
pub fn table(src: &mut dyn Source) -> Option<Table> {
    let len = src.len();
    let head = src.read_vec(0, usize::try_from(len.min(8192)).ok()?).ok()?;
    for sector in [512u32, 4096] {
        if head.get(sector as usize..sector as usize + 8) == Some(b"EFI PART")
            && let Some(t) = gpt(src, &head, sector)
        {
            return Some(t);
        }
    }
    if head.starts_with(b"ER")
        && head.get(512..514) == Some(b"PM")
        && let Some(t) = apm(src, &head)
    {
        return Some(t);
    }
    mbr(src, &head)
}

fn mbr_type(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x05 | 0x0F => "Extended",
        0x07 => "NTFS / exFAT",
        0x0B | 0x0C => "FAT32",
        0x11 | 0x14 | 0x16 | 0x1E => "Hidden FAT",
        0x17 => "Hidden NTFS",
        0x1B | 0x1C => "Hidden FAT32",
        0x27 => "Windows recovery",
        0x42 => "Windows dynamic disk",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x85 => "Linux extended",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xA6 => "OpenBSD",
        0xA8 => "Apple UFS",
        0xA9 => "NetBSD",
        0xAB => "Apple boot",
        0xAF => "Apple HFS",
        0xBE => "Solaris boot",
        0xBF => "Solaris",
        0xDA => "Non-file-system data",
        0xEE => "GPT protective",
        0xEF => "EFI System",
        0xFB => "VMware VMFS",
        0xFD => "Linux RAID",
        _ => return None,
    })
}

/// One 16-byte MBR entry: `(bootable, type, start LBA, sectors)`.
fn mbr_entry(b: &[u8]) -> Option<(bool, u8, u32, u32)> {
    Some((b.first()? & 0x80 != 0, *b.get(4)?, le32(b, 8)?, le32(b, 12)?))
}

/// Whether sector 0 holds a plausible MBR partition table.
pub fn is_mbr(sector: &[u8]) -> bool {
    if sector.get(510..512) != Some(&[0x55, 0xAA]) {
        return false;
    }
    let mut used = 0;
    for i in 0..4 {
        let Some(e) = sector.get(446 + 16 * i..462 + 16 * i) else { return false };
        if e[0] != 0 && e[0] != 0x80 {
            return false;
        }
        let Some((_, ty, start, count)) = mbr_entry(e) else { return false };
        if ty != 0 {
            if start == 0 || count == 0 {
                return false;
            }
            used += 1;
        }
    }
    used > 0
}

fn mbr(src: &mut dyn Source, head: &[u8]) -> Option<Table> {
    if !is_mbr(head) {
        return None;
    }
    let len = src.len();
    let mut t = Table { scheme: "mbr", sector_size: 512, ..Table::default() };
    if let Some(sig) = le32(head, 440).filter(|&s| s != 0) {
        t.disk_id = Some(format!("{sig:08x}"));
    }
    let mut extended = None;
    for i in 0..4u32 {
        let at = 446 + 16 * i as usize;
        let (boot, ty, start, count) = mbr_entry(&head[at..at + 16])?;
        if ty == 0 {
            continue;
        }
        let container = matches!(ty, 0x05 | 0x0F | 0x85);
        if container && extended.is_none() {
            extended = Some(u64::from(start));
        }
        t.partitions.push(part(i + 1, ty, u64::from(start), count, boot, container));
    }
    // Logical partitions: a chain of EBRs, each relative to the extended
    // partition's start (the next link) or to itself (its partition).
    if let Some(base) = extended {
        let mut ebr = base;
        let mut index = 5;
        let mut seen = std::collections::HashSet::new();
        while t.partitions.len() < MAX_PARTITIONS && seen.insert(ebr) && ebr.saturating_mul(512) < len {
            let Ok(s) = src.read_vec(ebr * 512, 512) else { break };
            if s[510..512] != [0x55, 0xAA] {
                t.notes.push(format!("broken extended partition chain at sector {ebr}"));
                break;
            }
            let (boot, ty, start, count) = mbr_entry(&s[446..462])?;
            if ty != 0 && count > 0 {
                t.partitions.push(part(index, ty, ebr + u64::from(start), count, boot, false));
                index += 1;
            }
            let (_, next_ty, next, _) = mbr_entry(&s[462..478])?;
            if next_ty == 0 || next == 0 {
                break;
            }
            ebr = base + u64::from(next);
        }
    }
    for p in &t.partitions {
        if p.start.saturating_add(p.size) > len && !p.container {
            t.notes.push(format!("partition {} ends past the end of the image", p.index));
            break;
        }
    }
    Some(t)
}

fn part(index: u32, ty: u8, start: u64, count: u32, bootable: bool, container: bool) -> Partition {
    Partition {
        index,
        start: start * 512,
        size: u64::from(count) * 512,
        kind: mbr_type(ty),
        type_id: format!("0x{ty:02x}"),
        bootable,
        container,
        ..Partition::default()
    }
}

/// Well-known GPT partition type GUIDs.
fn gpt_type(g: &str) -> Option<&'static str> {
    Some(match g {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System",
        "024dee41-33e7-11d3-9d69-0008c781f39f" => "MBR partition scheme",
        "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft reserved",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Microsoft basic data",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows recovery",
        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" => "Windows LDM metadata",
        "af9b60a0-1431-4f62-bc68-3311714a69ad" => "Windows LDM data",
        "e75caf8f-f680-4cee-afa3-b001e56efc2d" => "Windows Storage Spaces",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
        "a19d880f-05fc-4d3b-a006-743f0f84911e" => "Linux RAID",
        "44479540-f297-41b2-9af7-d131d5f0458a" => "Linux root (x86)",
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" => "Linux root (x86-64)",
        "b921b045-1df0-41c3-af44-4c6f280d3fae" => "Linux root (ARM64)",
        "69dad710-2ce4-4e3c-b16c-21a1d49abed3" => "Linux root (ARM)",
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "Linux home",
        "3b8f8425-20e0-4f3b-907f-1a25a76f98e8" => "Linux server data",
        "bc13c2ff-59e6-4262-a352-b275fd6f7172" => "Linux extended boot",
        "ca7d7ccb-63ed-4c53-861c-1742536059cc" => "Linux LUKS",
        "7ffec5c9-2d00-49b7-8941-3ea10a5586b7" => "Linux dm-crypt",
        "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
        "426f6f74-0000-11aa-aa11-00306543ecac" => "Apple boot",
        "55465300-0000-11aa-aa11-00306543ecac" => "Apple UFS",
        "52414944-0000-11aa-aa11-00306543ecac" => "Apple RAID",
        "53746f72-6167-11aa-aa11-00306543ecac" => "Apple Core Storage",
        "516e7cb4-6ecf-11d6-8ff8-00022d09712b" => "FreeBSD data",
        "83bd6b9d-7f41-11dc-be0b-001560b84f0f" => "FreeBSD boot",
        "516e7cb5-6ecf-11d6-8ff8-00022d09712b" => "FreeBSD swap",
        "516e7cb6-6ecf-11d6-8ff8-00022d09712b" => "FreeBSD UFS",
        "516e7cba-6ecf-11d6-8ff8-00022d09712b" => "FreeBSD ZFS",
        "6a898cc3-1dd2-11b2-99a6-080020736631" => "ZFS",
        "824cc7a0-36a8-11e3-890a-952519ad3f61" => "OpenBSD data",
        "fe3a2a5d-4f32-41a7-b725-accc3285a309" => "ChromeOS kernel",
        "3cb8e202-3b7e-47dd-8a3c-7ff2a13cfcec" => "ChromeOS root",
        _ => return None,
    })
}

fn gpt(src: &mut dyn Source, head: &[u8], sector: u32) -> Option<Table> {
    let at = sector as usize;
    let h = head.get(at..at + 92)?;
    let header_len = le32(h, 12)? as usize;
    let mut t = Table { scheme: "gpt", sector_size: sector, ..Table::default() };
    if let Some(stored) = head.get(at..at + header_len).filter(|_| (92..=512).contains(&header_len)) {
        let mut copy = stored.to_vec();
        copy[16..20].fill(0);
        if crc32(&copy) != le32(h, 16)? {
            t.notes.push("GPT header checksum mismatch".into());
        }
    }
    t.disk_id = guid_le(&h[56..72]);
    let entries_lba = le64(h, 72)?;
    let count = le32(h, 80)?;
    let entry_len = le32(h, 84)? as usize;
    if !(128..=1024).contains(&entry_len) || count == 0 {
        return Some(t);
    }
    let backup = le64(h, 32)?;
    let len = src.len();
    if backup.saturating_add(1).saturating_mul(u64::from(sector)) > len {
        t.notes.push("backup GPT header past the end of the image".into());
    }
    let n = (count as usize).min(MAX_PARTITIONS * 2);
    let table_len = n * entry_len;
    let Ok(entries) = src.read_vec(entries_lba.saturating_mul(u64::from(sector)), table_len) else {
        t.notes.push("partition entries unreadable".into());
        return Some(t);
    };
    if n == count as usize && crc32(&entries) != le32(h, 88)? {
        t.notes.push("GPT partition entries checksum mismatch".into());
    }
    for (i, e) in (1u32..).zip(entries.chunks_exact(entry_len)) {
        let Some(type_id) = guid_le(&e[..16]) else { continue };
        let first = le64(e, 32)?;
        let last = le64(e, 40)?;
        let flags = le64(e, 48)?;
        let mut attributes = Vec::new();
        for (bit, name) in [
            (0, "required"),
            (1, "no_block_io"),
            (2, "legacy_bios_bootable"),
            (60, "read_only"),
            (62, "hidden"),
            (63, "no_automount"),
        ] {
            if flags >> bit & 1 == 1 {
                attributes.push(name);
            }
        }
        t.partitions.push(Partition {
            index: i,
            start: first.saturating_mul(u64::from(sector)),
            size: last.saturating_sub(first).saturating_add(1).saturating_mul(u64::from(sector)),
            kind: gpt_type(&type_id),
            type_id,
            name: utf16_field(&e[56..128], true),
            guid: guid_le(&e[16..32]),
            bootable: flags & 4 != 0,
            attributes,
            container: false,
        });
        if t.partitions.len() >= MAX_PARTITIONS {
            break;
        }
    }
    Some(t)
}

fn apm(src: &mut dyn Source, head: &[u8]) -> Option<Table> {
    let block = u64::from(be16(head, 2)?);
    let unit = if matches!(block, 512 | 1024 | 2048 | 4096) { block } else { 512 };
    let mut t = Table { scheme: "apm", sector_size: u32::try_from(unit).ok()?, ..Table::default() };
    let count = be32(head, 512 + 4)?.min(u32::try_from(MAX_PARTITIONS).ok()?);
    for i in 1..=count {
        let at = u64::from(i) * 512;
        let Ok(e) = src.read_vec(at, 512) else { break };
        if &e[..2] != b"PM" {
            break;
        }
        let ty = text_field(&e[48..80]).unwrap_or_default();
        t.partitions.push(Partition {
            index: i,
            start: u64::from(be32(&e, 8)?) * unit,
            size: u64::from(be32(&e, 12)?) * unit,
            kind: apm_type(&ty),
            container: matches!(ty.as_str(), "Apple_partition_map" | "Apple_Free"),
            type_id: ty,
            name: text_field(&e[16..48]),
            ..Partition::default()
        });
    }
    Some(t)
}

fn apm_type(t: &str) -> Option<&'static str> {
    Some(match t {
        "Apple_partition_map" => "Partition map",
        "Apple_HFS" => "Apple HFS",
        "Apple_HFSX" => "Apple HFSX",
        "Apple_Free" => "Free space",
        "Apple_Boot" => "Apple boot",
        "Apple_UFS" => "Apple UFS",
        "Apple_APFS" => "Apple APFS",
        "Apple_ISO" | "CD_partition_scheme" => "ISO 9660",
        t if t.starts_with("Apple_Driver") => "Apple driver",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{Budget, BytesSource};

    fn src(data: Vec<u8>) -> BytesSource {
        BytesSource::new(None, data, Budget::unlimited())
    }

    #[test]
    fn mbr_with_logical_partitions() {
        let mut d = vec![0u8; 64 * 512];
        let entry = |d: &mut [u8], at: usize, ty: u8, start: u32, n: u32| {
            d[at + 4] = ty;
            d[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            d[at + 12..at + 16].copy_from_slice(&n.to_le_bytes());
        };
        d[446] = 0x80;
        entry(&mut d, 446, 0x0C, 2, 8);
        entry(&mut d, 462, 0x05, 16, 32);
        d[510..512].copy_from_slice(&[0x55, 0xAA]);
        // EBR at 16: a partition at +2, then the next EBR at base + 10.
        entry(&mut d, 16 * 512 + 446, 0x83, 2, 4);
        entry(&mut d, 16 * 512 + 462, 0x05, 10, 8);
        d[16 * 512 + 510..16 * 512 + 512].copy_from_slice(&[0x55, 0xAA]);
        entry(&mut d, 26 * 512 + 446, 0x82, 1, 4);
        d[26 * 512 + 510..26 * 512 + 512].copy_from_slice(&[0x55, 0xAA]);
        let t = table(&mut src(d)).unwrap();
        assert_eq!(t.scheme, "mbr");
        let got: Vec<(u32, u64, Option<&str>)> =
            t.partitions.iter().map(|p| (p.index, p.start / 512, p.kind)).collect();
        assert_eq!(
            got,
            [(1, 2, Some("FAT32")), (2, 16, Some("Extended")), (5, 18, Some("Linux")), (6, 27, Some("Linux swap"))]
        );
        assert!(t.partitions[0].bootable && t.partitions[1].container);
    }

    #[test]
    fn not_an_mbr() {
        let mut d = vec![0u8; 512];
        d[510..512].copy_from_slice(&[0x55, 0xAA]);
        assert!(!is_mbr(&d));
        d[446] = 0x12;
        d[450] = 0x83;
        assert!(!is_mbr(&d));
    }
}
