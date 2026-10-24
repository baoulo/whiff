//! `compress` extractors (feature `common`): files that hold one compressed
//! stream. Each reads what its format states in headers, trailers or
//! indexes (original name and time, declared size, checks, block layout),
//! then decompresses the stream within the limits and hands it on as the
//! inner stream, which is detected and extracted in turn: `x.tar.gz` is a
//! gzip file holding `x.tar`, whose entries are listed as for a plain tar.
//!
//! Decompression runs only when children are allowed (not in the `minimal`
//! profile) and stops at `limits.max_parse_bytes` of output: a longer
//! stream is analysed from its start, which is recorded.

pub(crate) mod bzip2;
pub(crate) mod gzip;
pub(crate) mod lz4;
pub(crate) mod lzma;
pub(crate) mod other;
pub(crate) mod zstd;

use crate::plugin::{Codec, Context, End, ExtractError, Source};

/// Uncompressed size from which a high ratio is a decompression bomb.
const BOMB_BYTES: u64 = 1 << 30;
/// Ratio (uncompressed / compressed) above which a large stream is a bomb.
const BOMB_RATIO: u64 = 100;

/// The name of the stream inside a compressed file: the name the format
/// stores, else the file's own name without its compression extension
/// (`x.tar.gz` → `x.tar`, `x.tgz` → `x.tar`, `x.gz` → `x`).
pub(crate) fn inner_name(outer: Option<&str>, stored: Option<&str>) -> String {
    if let Some(n) = stored.map(str::trim).filter(|n| !n.is_empty()) {
        // A stored name is a bare file name; keep only its last component.
        return n.rsplit(['/', '\\']).next().unwrap_or(n).to_string();
    }
    let Some(outer) = outer else { return "data".into() };
    let Some((stem, ext)) = outer.rsplit_once('.') else { return format!("{outer}.out") };
    match ext.to_ascii_lowercase().as_str() {
        "tgz" | "taz" | "tbz" | "tbz2" | "tb2" | "txz" | "tlz" | "tzst" | "tz" => format!("{stem}.tar"),
        "gz" | "gzip" | "z" | "bz2" | "bzip2" | "xz" | "lzma" | "lz" | "zst" | "zstd" | "lz4" | "br" | "sz"
        | "snappy" | "lzo" | "lzfse" | "zz" | "zlib" => stem.to_string(),
        _ => format!("{outer}.out"),
    }
}

/// What a format's headers say about the stream, for [`unpack`].
#[derive(Debug, Default)]
pub(crate) struct Stated {
    /// Uncompressed size from a header, trailer or index.
    pub size: Option<u64>,
    /// Original file name.
    pub name: Option<String>,
}

/// Decompress the whole input with `codec` (within the limits), report
/// sizes, trailing data and decompression bombs, and hand the result on as
/// the inner stream.
pub(crate) fn unpack(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    codec: Codec,
    stated: &Stated,
) -> Result<(), ExtractError> {
    let compressed = src.len();
    if let Some(n) = stated.size {
        cx.format_set("declared_size_bytes", n);
    }
    if cx.child_room() == 0 {
        // No children (the `minimal` profile): the headers are all there is.
        if let Some(n) = stated.size {
            cx.physical().uncompressed_bytes(n);
        }
        return Ok(());
    }
    let (data, cut) = cx.read_bytes(src)?;
    let limit = cx.parse_limit();
    let d = cx.decompress(&data, codec, limit)?;
    match &d.end {
        End::Complete | End::Limit => {}
        End::Truncated => cx.warn("the compressed stream ends early (the file is cut short)"),
        End::Error(e) => cx.warn(format!("decompression stopped: {e}")),
    }
    let whole = d.complete() && !cut;
    let size = if whole { Some(d.data.len() as u64) } else { stated.size };
    if let Some(n) = size {
        cx.physical().uncompressed_bytes(n);
    }
    if whole && d.consumed < data.len() {
        let extra = &data[d.consumed..];
        cx.format_set("trailing_bytes", extra.len() as u64);
        if extra.iter().any(|&b| b != 0) {
            cx.security().risk("trailing_data", Some(format!("{} bytes after the compressed stream", extra.len())));
        }
    }
    // A bomb: a huge declared or measured size at a high ratio, or a stream
    // that ran into the decompression budget (not just the parse limit) at
    // a high ratio already.
    let budget_stop =
        d.end == End::Limit && d.data.len() < limit && d.data.len() as u64 / compressed.max(1) > BOMB_RATIO;
    let huge = size.is_some_and(|n| n >= BOMB_BYTES && n / compressed.max(1) > BOMB_RATIO);
    if huge || budget_stop {
        let detail = match size {
            Some(n) if huge => format!("{n} bytes from {compressed}"),
            _ => format!("decompression stopped at the budget after {} bytes", d.data.len()),
        };
        cx.security().risk("decompression_bomb", Some(detail));
    }
    if d.data.is_empty() {
        return Ok(());
    }
    let name = inner_name(src.name_hint(), stated.name.as_deref());
    cx.emit_inner(&name, d.data, !whole)
}

/// An RFC 3339 UTC time from Unix seconds (0 means "not set").
pub(crate) fn unix_time(secs: i64) -> Option<String> {
    if secs <= 0 {
        return None;
    }
    let ts = jiff::Timestamp::from_second(secs).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_names() {
        assert_eq!(inner_name(Some("logs.tar.gz"), None), "logs.tar");
        assert_eq!(inner_name(Some("logs.TGZ"), None), "logs.tar");
        assert_eq!(inner_name(Some("notes.txt.zst"), None), "notes.txt");
        assert_eq!(inner_name(Some("notes.bin"), None), "notes.bin.out");
        assert_eq!(inner_name(Some("x.gz"), Some("../../etc/harbour.txt")), "harbour.txt");
        assert_eq!(inner_name(None, None), "data");
        assert_eq!(unix_time(1_700_000_000).as_deref(), Some("2023-11-14T22:13:20Z"));
        assert_eq!(unix_time(0), None);
    }
}
