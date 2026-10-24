//! Hostile archives are reported safely within limits (the Stage 5 exit
//! criteria): a 1 GiB zip bomb, a 42.zip-style nest of them, an
//! overlapping-entry zip bomb, archives whose paths climb out of the target
//! folder, and compressed streams nested in each other. The inputs are
//! built here, in memory; nothing hostile is kept in `tests/fixtures`.
#![allow(clippy::cast_possible_truncation)] // the test archives' fields are small

use std::time::{Duration, Instant};

use whiff::report::Report;
use whiff::{Engine, Limits, Profile};

/// A raw deflate stream (fixed Huffman codes) that inflates to `n` zero
/// bytes: one literal, then matches of 258 at distance 1. About 13 bits per
/// 258 bytes, built without compressing anything.
fn zeros_deflate(n: u64) -> Vec<u8> {
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }
    impl Bits {
        fn put(&mut self, value: u32, count: u32) {
            self.acc |= u64::from(value) << self.n;
            self.n += count;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }
        /// A Huffman code, most significant bit first.
        fn code(&mut self, code: u32, len: u32) {
            self.put(code.reverse_bits() >> (32 - len), len);
        }
    }
    let mut b = Bits { out: Vec::new(), acc: 0, n: 0 };
    b.put(1, 1); // final block
    b.put(1, 2); // fixed Huffman
    b.code(0x30, 8); // literal 0
    let mut left = n - 1;
    while left >= 258 {
        b.code(0xc5, 8); // length 258 (code 285)
        b.code(0, 5); // distance 1
        left -= 258;
    }
    for _ in 0..left {
        b.code(0x30, 8);
    }
    b.code(0, 7); // end of block
    b.put(0, 7);
    b.out
}

struct ZipEntry<'a> {
    name: &'a str,
    method: u16,
    data: &'a [u8],
    size: u64,
    unix_mode: Option<u32>,
}

/// A ZIP of `entries`, each with its own local header and data.
fn zip(entries: &[ZipEntry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let offset = out.len() as u32;
        let fields = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&e.method.to_le_bytes());
            v.extend_from_slice(&[0, 0, 0x21, 0x5b]); // 2025-09-01
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(e.size as u32).to_le_bytes());
            v.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
        };
        out.extend_from_slice(b"PK\x03\x04");
        fields(&mut out);
        out.extend_from_slice(e.name.as_bytes());
        out.extend_from_slice(e.data);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&(if e.unix_mode.is_some() { 0x0314u16 } else { 20 }).to_le_bytes());
        fields(&mut central);
        central.extend_from_slice(&[0; 6]);
        central.extend_from_slice(&(e.unix_mode.unwrap_or(0) << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(e.name.as_bytes());
    }
    let cd_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A tar of `(name, type flag, link, data)` entries (ustar headers).
fn tar(entries: &[(&str, u8, &str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, flag, link, data) in entries {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"15050366500\0");
        h[156] = *flag;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..265].copy_from_slice(b"ustar\x0000");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn engine(limits: Limits) -> Engine {
    Engine::builder().profile(Profile::Standard).limits(limits).build()
}

fn risks(r: &Report) -> Vec<&str> {
    r.security.risks.iter().map(|x| x.kind.as_str()).collect()
}

/// The report, and how long it took.
fn timed(engine: &Engine, name: &str, data: Vec<u8>) -> (Report, Duration) {
    let t = Instant::now();
    let r = engine.extract_bytes(Some(name), data);
    (r, t.elapsed())
}

#[test]
fn one_gib_zip_bomb() {
    let bomb = zeros_deflate(1 << 30);
    let data = zip(&[ZipEntry { name: "zeros.bin", method: 8, data: &bomb, size: 1 << 30, unix_mode: None }]);
    let limits = Profile::Standard.limits();
    let (r, took) = timed(&engine(limits.clone()), "bomb.zip", data);
    assert_eq!(r.identification.format, "zip");
    assert!(risks(&r).contains(&"decompression_bomb"), "{:?}", r.security.risks);
    assert_eq!(r.physical.container.as_ref().and_then(|c| c.uncompressed_bytes), Some(1 << 30));
    // The entry was analysed from its start only: the parse limit, not 1 GiB.
    let child = &r.embedded[0];
    assert_eq!(child.physical.size_bytes, Some(limits.max_parse_bytes));
    assert!(child.diagnostics.truncated);
    assert!(took < Duration::from_secs(60), "{took:?}");
}

#[test]
fn nested_bombs_stay_within_the_budget() {
    // 42.zip-style: 16 zips of 16 zips of a 1 GiB entry (256 GiB in all),
    // each layer deflated.
    let bomb = zeros_deflate(1 << 30);
    let inner = zip(&[ZipEntry { name: "zeros.bin", method: 8, data: &bomb, size: 1 << 30, unix_mode: None }]);
    let layer = |entry: &[u8], prefix: &str| {
        let packed = miniz_oxide::deflate::compress_to_vec(entry, 6);
        let names: Vec<String> = (0..16).map(|i| format!("{prefix}{i}.zip")).collect();
        zip(&names
            .iter()
            .map(|n| ZipEntry { name: n, method: 8, data: &packed, size: entry.len() as u64, unix_mode: None })
            .collect::<Vec<_>>())
    };
    let middle = layer(&inner, "lib");
    let outer = layer(&middle, "book");
    assert!(outer.len() < 1 << 20, "{}", outer.len());
    let mut limits = Profile::Full.limits();
    limits.max_decompressed_bytes = 64 << 20;
    limits.max_parse_bytes = 8 << 20;
    let (r, took) = timed(&engine(limits), "42.zip", outer);
    assert_eq!(r.identification.format, "zip");
    // The innermost zips are reached (depth 2) and flagged; decompression
    // stops at the budget.
    assert!(r.security.embedded_risks.contains_key("decompression_bomb"), "{:?}", r.security.embedded_risks);
    assert!(r.diagnostics.limits_hit.iter().any(|l| l == "decompressed_bytes"), "{:?}", r.diagnostics.limits_hit);
    assert!(took < Duration::from_secs(60), "{took:?}");
}

#[test]
fn overlapping_entries_are_flagged_not_inflated() {
    // Fifield's construction, simplified: every entry's data is the same
    // compressed stream, all central records pointing at one local header.
    let bomb = zeros_deflate(64 << 20);
    let mut data = zip(&[ZipEntry { name: "a", method: 8, data: &bomb, size: 64 << 20, unix_mode: None }]);
    // Add 99 more central records for the same local header.
    let eocd = data.len() - 22;
    let cd_size = u32::from_le_bytes(data[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
    let record = data[eocd - cd_size..eocd].to_vec();
    let mut central = Vec::new();
    for _ in 0..100 {
        central.extend_from_slice(&record);
    }
    let cd_at = eocd - cd_size;
    data.truncate(cd_at);
    data.extend_from_slice(&central);
    data.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    data.extend_from_slice(&100u16.to_le_bytes());
    data.extend_from_slice(&100u16.to_le_bytes());
    data.extend_from_slice(&(central.len() as u32).to_le_bytes());
    data.extend_from_slice(&(cd_at as u32).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let (r, took) = timed(&engine(Profile::Standard.limits()), "overlap.zip", data);
    let kinds = risks(&r);
    assert!(kinds.contains(&"overlapping_entries"), "{kinds:?}");
    assert!(kinds.contains(&"decompression_bomb"), "{kinds:?}");
    assert_eq!(r.embedded.len(), 0, "no entry is inflated");
    assert!(took < Duration::from_secs(30), "{took:?}");
}

#[test]
fn paths_that_leave_the_target_folder() {
    let text = b"tide notes\n";
    let z = zip(&[
        ZipEntry { name: "../../outside.txt", method: 0, data: text, size: text.len() as u64, unix_mode: None },
        ZipEntry { name: "/abs/notes.txt", method: 0, data: text, size: text.len() as u64, unix_mode: None },
        ZipEntry { name: "docs/link", method: 0, data: b"../../../etc", size: 12, unix_mode: Some(0o120_777) },
    ]);
    let r = engine(Profile::Standard.limits()).extract_bytes(Some("paths.zip"), z);
    let kinds = risks(&r);
    for k in ["path_traversal", "absolute_path", "symlink_escape"] {
        assert!(kinds.contains(&k), "{k} missing: {kinds:?}");
    }
    let t = tar(&[
        ("harbour/notes.txt", b'0', "", text),
        ("harbour/../../up.txt", b'0', "", text),
        ("harbour/latest", b'2', "/etc/hosts", b""),
        ("invoice.pdf.exe", b'0', "", text),
    ]);
    let r = engine(Profile::Standard.limits()).extract_bytes(Some("paths.tar"), t);
    assert_eq!(r.identification.format, "tar");
    let kinds = risks(&r);
    for k in ["path_traversal", "symlink_escape", "double_extension"] {
        assert!(kinds.contains(&k), "{k} missing: {kinds:?}");
    }
    // A link that stays inside is fine.
    let t = tar(&[("harbour/notes.txt", b'0', "", text), ("harbour/latest", b'2', "notes.txt", b"")]);
    let r = engine(Profile::Standard.limits()).extract_bytes(Some("ok.tar"), t);
    assert!(r.security.risks.is_empty(), "{:?}", r.security.risks);
}

#[test]
fn compressed_layers_nest_but_not_forever() {
    // gzip of gzip of … a tar: layers do not use up recursion depth, so the
    // tar's entries are listed; past a few layers they count as depth.
    let text = b"Saltmere harbour notes\n";
    let mut data = tar(&[("harbour/notes.txt", b'0', "", text)]);
    let gz = |d: &[u8]| {
        let body = miniz_oxide::deflate::compress_to_vec(d, 6);
        let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        out.extend_from_slice(&body);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out
    };
    data = gz(&data);
    let r = engine(Profile::Standard.limits()).extract_bytes(Some("notes.tar.gz"), data.clone());
    assert_eq!(r.identification.format, "gzip");
    let inner = &r.embedded[0];
    assert_eq!(inner.identification.format, "tar");
    assert_eq!(inner.embedded.len(), 1, "the tar's entry is analysed");
    for _ in 0..10 {
        data = gz(&data);
    }
    let (r, took) = timed(&engine(Profile::Standard.limits()), "deep.gz", data);
    assert!(r.diagnostics.limits_hit.iter().any(|l| l == "max_depth"), "{:?}", r.diagnostics.limits_hit);
    assert!(took < Duration::from_secs(30));
}
