//! NTFS master file tables (`$MFT` extracted from a volume): record size,
//! record counts (in use, deleted, directories, extension records, bad or
//! unreadable ones), the range of `$STANDARD_INFORMATION` creation and
//! modification times of the records in use, and a histogram of file
//! extensions. File names are never listed.
//!
//! Specification: libyal "New Technologies File System (NTFS)" (MFT entry,
//! update sequence fixups, `$STANDARD_INFORMATION`, `$FILE_NAME`).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Window, filetime, le, le_usize};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for `$MFT` files.
pub struct Mft;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.mft",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "ntfs_mft",
        name: "NTFS master file table",
        family: "forensic",
        mimes: &[],
        extensions: &["mft"],
        magic: &[],
        parent: None,
    }],
};

/// Records walked.
const MAX_RECORDS: u64 = 20_000_000;
/// Extensions kept in the histogram.
const TOP: usize = 30;

/// Apply the update sequence: the last two bytes of each 512-byte sector
/// were replaced by the sequence number; put the saved bytes back.
fn fixup(r: &mut [u8]) -> bool {
    let off = le_usize(&r[4..6]);
    let n = le_usize(&r[6..8]);
    if n < 1 || off + 2 * n > r.len() {
        return false;
    }
    let usn = [r[off], r[off + 1]];
    for i in 1..n {
        let end = 512 * i;
        if end > r.len() || r[end - 2..end] != usn {
            return false;
        }
        r[end - 2] = r[off + 2 * i];
        r[end - 1] = r[off + 2 * i + 1];
    }
    true
}

impl Extractor for Mft {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Record 0 describes $MFT itself: its $FILE_NAME is "$MFT".
        let h = probe.head;
        if h.get(..4) != Some(b"FILE") || h.len() < 1024 {
            return None;
        }
        let name: Vec<u8> = "$MFT".encode_utf16().flat_map(u16::to_le_bytes).collect();
        h[..1024].windows(8).any(|w| w == name.as_slice()).then_some(Sniff { format: "ntfs_mft", confidence: 0.9 })
    }

    #[allow(clippy::too_many_lines)] // record loop with its attribute walk
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut w = Window::new(src);
        let first = w.get(0, 48).ok_or_else(|| ExtractError::malformed("MFT record"))?.to_vec();
        // The allocated size of record 0 is the record size.
        let size = usize::try_from(le(&first[28..32])).unwrap_or(1024);
        if !(512..=65536).contains(&size) || !size.is_power_of_two() {
            return Err(ExtractError::malformed("MFT record size"));
        }
        cx.format_set("record_size", size);
        let total = w.len() / size as u64;
        let (mut in_use, mut deleted, mut dirs, mut ext_records, mut bad, mut empty) = (0u64, 0, 0, 0, 0, 0);
        let (mut c_lo, mut c_hi, mut m_lo, mut m_hi) = (u64::MAX, 0u64, u64::MAX, 0u64);
        let mut exts: BTreeMap<String, u64> = BTreeMap::new();
        let budget = (cx.parse_limit() / size) as u64;
        let walked = total.min(MAX_RECORDS).min(budget.max(1));
        for i in 0..walked {
            let Some(rec) = w.get(i * size as u64, size) else { break };
            let mut r = rec.to_vec();
            match &r[..4] {
                b"FILE" => {}
                b"BAAD" => {
                    bad += 1;
                    continue;
                }
                _ => {
                    empty += 1;
                    continue;
                }
            }
            if !fixup(&mut r) {
                bad += 1;
                continue;
            }
            let flags = le(&r[22..24]);
            if le(&r[32..40]) & 0x0000_ffff_ffff_ffff != 0 {
                ext_records += 1;
                continue;
            }
            if flags & 1 == 0 {
                deleted += 1;
                continue;
            }
            in_use += 1;
            if flags & 2 != 0 {
                dirs += 1;
            }
            // Attributes.
            let mut at = le_usize(&r[20..22]);
            let mut name: Option<(u8, String)> = None;
            while at + 24 <= r.len() {
                let kind = le(&r[at..at + 4]);
                let len = le_usize(&r[at + 4..at + 8]);
                if kind == 0xffff_ffff || len < 24 || at + len > r.len() {
                    break;
                }
                let resident = r[at + 8] == 0;
                let body = if resident {
                    let (n, off) = (le_usize(&r[at + 16..at + 20]), le_usize(&r[at + 20..at + 22]));
                    r.get(at + off..at + off + n)
                } else {
                    None
                };
                match (kind, body) {
                    (0x10, Some(b)) if b.len() >= 32 => {
                        let (c, m) = (le(&b[0..8]), le(&b[8..16]));
                        if filetime(c).is_some() {
                            c_lo = c_lo.min(c);
                            c_hi = c_hi.max(c);
                        }
                        if filetime(m).is_some() {
                            m_lo = m_lo.min(m);
                            m_hi = m_hi.max(m);
                        }
                    }
                    (0x30, Some(b)) if b.len() >= 66 => {
                        let n = usize::from(b[64]);
                        let space = b[65];
                        let units: Vec<u16> = b
                            .get(66..66 + 2 * n)
                            .unwrap_or_default()
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .collect();
                        // Prefer the Win32 name over the DOS 8.3 one.
                        if name.as_ref().is_none_or(|(s, _)| *s == 2) {
                            name = Some((space, String::from_utf16_lossy(&units)));
                        }
                    }
                    _ => {}
                }
                at += len;
            }
            if flags & 2 == 0
                && let Some((_, n)) = name
                && let Some((_, ext)) = n.rsplit_once('.')
                && !ext.is_empty()
                && ext.len() <= 8
                && !n.starts_with('$')
            {
                *exts.entry(ext.to_ascii_lowercase()).or_default() += 1;
            }
            if i % 65_536 == 65_535 {
                cx.checkpoint()?;
            }
        }
        cx.format_set("records", total);
        if walked < total {
            cx.format_set("records_walked", walked);
        }
        cx.format_set("in_use", in_use);
        cx.format_set("directories", dirs);
        cx.format_set("files", in_use - dirs);
        cx.format_set("deleted", deleted);
        cx.format_set("extension_records", ext_records);
        if bad > 0 {
            cx.format_set("bad_records", bad);
        }
        if empty > 0 {
            cx.format_set("empty_records", empty);
        }
        for (key, lo, hi) in [("created", c_lo, c_hi), ("modified", m_lo, m_hi)] {
            if let (Some(a), Some(b)) = (filetime(lo), filetime(hi)) {
                cx.format_set(&format!("first_{key}"), a);
                cx.format_set(&format!("last_{key}"), b);
            }
        }
        let mut v: Vec<(String, u64)> = exts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if !v.is_empty() {
            cx.format_set("extensions", Value::Object(v.into_iter().take(TOP).map(|(k, n)| (k, n.into())).collect()));
        }
        Ok(())
    }
}

crate::register_extractor!(Mft);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixups_restore_sector_ends() {
        let mut r = vec![0u8; 1024];
        r[4..6].copy_from_slice(&48u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[48..54].copy_from_slice(&[7, 0, 0xaa, 0xbb, 0xcc, 0xdd]);
        r[510..512].copy_from_slice(&[7, 0]);
        r[1022..1024].copy_from_slice(&[7, 0]);
        assert!(fixup(&mut r));
        assert_eq!((&r[510..512], &r[1022..1024]), (&[0xaa, 0xbb][..], &[0xcc, 0xdd][..]));
        r[1022] = 9;
        r[510..512].copy_from_slice(&[7, 0]);
        assert!(!fixup(&mut r));
    }

    crate::fixture_tests!("ntfs_mft");
}
