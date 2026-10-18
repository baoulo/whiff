//! Stream filters (ISO 32000-2 §7.4): Flate, LZW, ASCIIHex, ASCII85 and
//! RunLength, with PNG / TIFF predictors. Image codecs (DCT, JPX, CCITT,
//! JBIG2) are left encoded.

use super::object::{Dict, Obj, is_white};
use crate::plugin::{Compression, Context, ExtractError};

/// The filter names of a stream, in order.
pub(crate) fn names(dict: &Dict) -> Vec<String> {
    match dict.get("Filter").or_else(|| dict.get("F").filter(|f| f.as_name().is_some() || f.as_array().is_some())) {
        Some(Obj::Name(n)) => vec![n.clone()],
        Some(Obj::Array(a)) => a.iter().filter_map(Obj::as_name).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// Whether the stream ends in an image codec this module does not decode.
pub(crate) fn is_image_codec(name: &str) -> bool {
    matches!(name, "DCTDecode" | "DCT" | "JPXDecode" | "CCITTFaxDecode" | "CCF" | "JBIG2Decode")
}

/// Decode `data` through every filter of `dict`, producing at most `max` bytes.
pub(crate) fn decode(
    dict: &Dict,
    mut data: Vec<u8>,
    cx: &mut Context<'_>,
    max: usize,
) -> Result<Vec<u8>, ExtractError> {
    let filters = names(dict);
    let params: Vec<Option<&Dict>> = match dict.get("DecodeParms").or_else(|| dict.get("DP")) {
        Some(Obj::Array(a)) => a.iter().map(Obj::as_dict).collect(),
        Some(Obj::Dict(d)) => vec![Some(d)],
        _ => Vec::new(),
    };
    for (i, f) in filters.iter().enumerate() {
        let p = params.get(i).copied().flatten();
        data = match f.as_str() {
            "FlateDecode" | "Fl" => {
                let out = match cx.inflate(&data, Compression::Zlib, max) {
                    Ok(out) => out,
                    Err(ExtractError::LimitExceeded(e)) => return Err(ExtractError::LimitExceeded(e)),
                    // Some writers emit raw deflate, or a stream cut short.
                    Err(_) => cx
                        .inflate(&data, Compression::Deflate, max)
                        .or_else(|_| cx.inflate_prefix(&data, Compression::Zlib, max))?,
                };
                predict(out, p)?
            }
            "LZWDecode" | "LZW" => {
                let early = p.and_then(|p| p.int("EarlyChange")).unwrap_or(1) != 0;
                predict(lzw(&data, early, max)?, p)?
            }
            "ASCIIHexDecode" | "AHx" => ascii_hex(&data),
            "ASCII85Decode" | "A85" => ascii85(&data)?,
            "RunLengthDecode" | "RL" => run_length(&data, max),
            "Crypt" => data,
            other if is_image_codec(other) => return Err(ExtractError::Unsupported(format!("{other} stream"))),
            other => return Err(ExtractError::Unsupported(format!("filter {other}"))),
        };
        if data.len() > max {
            return Err(ExtractError::LimitExceeded("pdf_stream_bytes".into()));
        }
    }
    Ok(data)
}

/// PNG (10–15) and TIFF (2) predictors.
fn predict(data: Vec<u8>, p: Option<&Dict>) -> Result<Vec<u8>, ExtractError> {
    let Some(p) = p else { return Ok(data) };
    let predictor = p.int("Predictor").unwrap_or(1);
    if predictor < 2 {
        return Ok(data);
    }
    let colors = usize::try_from(p.int("Colors").unwrap_or(1).clamp(1, 32)).unwrap_or(1);
    let bpc = usize::try_from(p.int("BitsPerComponent").unwrap_or(8).clamp(1, 16)).unwrap_or(8);
    let columns = usize::try_from(p.int("Columns").unwrap_or(1).clamp(1, 1 << 20)).unwrap_or(1);
    let bpp = (colors * bpc).div_ceil(8);
    let row = (colors * bpc * columns).div_ceil(8);
    if predictor == 2 {
        if bpc != 8 {
            return Ok(data);
        }
        let mut out = data;
        for line in out.chunks_mut(row) {
            for i in bpp..line.len() {
                line[i] = line[i].wrapping_add(line[i - bpp]);
            }
        }
        return Ok(out);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row];
    for chunk in data.chunks(row + 1) {
        let (&kind, src) = chunk.split_first().ok_or_else(|| ExtractError::malformed("predictor row"))?;
        let mut cur = src.to_vec();
        cur.resize(row, 0);
        for i in 0..row {
            let a = if i >= bpp { cur[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            cur[i] = cur[i].wrapping_add(match kind {
                1 => a,
                2 => b,
                3 => u8::midpoint(a, b),
                4 => paeth(a, b, c),
                _ => 0,
            });
        }
        out.extend_from_slice(&cur[..src.len().min(row)]);
        prev = cur;
    }
    Ok(out)
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = ((p - i16::from(a)).abs(), (p - i16::from(b)).abs(), (p - i16::from(c)).abs());
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

fn lzw(data: &[u8], early: bool, max: usize) -> Result<Vec<u8>, ExtractError> {
    let mut table: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
    table.push(Vec::new());
    table.push(Vec::new());
    let mut out = Vec::new();
    let (mut bits, mut acc, mut width) = (0u32, 0u32, 9u32);
    let mut prev: Option<usize> = None;
    for &byte in data {
        acc = acc << 8 | u32::from(byte);
        bits += 8;
        while bits >= width {
            let code = ((acc >> (bits - width)) & ((1 << width) - 1)) as usize;
            bits -= width;
            match code {
                256 => {
                    table.truncate(258);
                    width = 9;
                    prev = None;
                    continue;
                }
                257 => return Ok(out),
                _ => {}
            }
            let entry = if code < table.len() {
                table[code].clone()
            } else if let Some(p) = prev
                && code == table.len()
            {
                let mut e = table[p].clone();
                e.push(table[p][0]);
                e
            } else {
                return Err(ExtractError::malformed("LZW code"));
            };
            out.extend_from_slice(&entry);
            if out.len() > max {
                return Err(ExtractError::LimitExceeded("pdf_stream_bytes".into()));
            }
            if let Some(p) = prev
                && table.len() < 4096
            {
                let mut e = table[p].clone();
                e.push(entry[0]);
                table.push(e);
            }
            prev = Some(code);
            let next = table.len() + usize::from(early);
            width = match next {
                ..512 => 9,
                512..1024 => 10,
                1024..2048 => 11,
                _ => 12,
            };
        }
    }
    Ok(out)
}

fn ascii_hex(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut hi: Option<u8> = None;
    for &b in data {
        if b == b'>' {
            break;
        }
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => continue,
        };
        match hi.take() {
            Some(h) => out.push(h << 4 | v),
            None => hi = Some(v),
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    out
}

fn ascii85(data: &[u8]) -> Result<Vec<u8>, ExtractError> {
    let data = data.strip_prefix(b"<~").unwrap_or(data);
    let mut out = Vec::with_capacity(data.len() * 4 / 5);
    let mut group = [0u8; 5];
    let mut n = 0;
    for &b in data {
        match b {
            b'~' => break,
            b'z' if n == 0 => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                group[n] = b - b'!';
                n += 1;
                if n == 5 {
                    let v = group.iter().fold(0u64, |acc, &d| acc * 85 + u64::from(d));
                    let v = u32::try_from(v).map_err(|_| ExtractError::malformed("ASCII85 group"))?;
                    out.extend_from_slice(&v.to_be_bytes());
                    n = 0;
                }
            }
            _ if is_white(b) => {}
            _ => return Err(ExtractError::malformed("ASCII85 character")),
        }
    }
    if n > 1 {
        for slot in group.iter_mut().skip(n) {
            *slot = 84;
        }
        let v = group.iter().fold(0u64, |acc, &d| acc * 85 + u64::from(d));
        let bytes = u32::try_from(v.min(u64::from(u32::MAX))).unwrap_or(u32::MAX).to_be_bytes();
        out.extend_from_slice(&bytes[..n - 1]);
    }
    Ok(out)
}

fn run_length(data: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() && out.len() < max {
        let len = data[i];
        i += 1;
        match len {
            128 => break,
            0..=127 => {
                let n = usize::from(len) + 1;
                out.extend_from_slice(data.get(i..i + n).unwrap_or(&data[i.min(data.len())..]));
                i += n;
            }
            _ => {
                if let Some(&b) = data.get(i) {
                    out.extend(std::iter::repeat_n(b, 257 - usize::from(len)));
                }
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_filters() {
        assert_eq!(ascii_hex(b"48 65 6C6C6F>"), b"Hello");
        assert_eq!(ascii85(b"<~87cURD]i,\"Ebo80~>").unwrap(), b"Hello World!");
        assert_eq!(run_length(&[2, b'a', b'b', b'c', 254, b'x', 128], 100), b"abcxxx");
    }

    #[test]
    fn png_up_predictor() {
        let mut d = Dict::default();
        d.0.push(("Predictor".into(), Obj::Int(12)));
        d.0.push(("Columns".into(), Obj::Int(3)));
        let rows = [2, 1, 2, 3, 2, 1, 1, 1];
        assert_eq!(predict(rows.to_vec(), Some(&d)).unwrap(), vec![1, 2, 3, 2, 3, 4]);
    }

    #[test]
    fn lzw_spec_example() {
        // ISO 32000-2 §7.4.4.2: "-----A---B" encodes to 80 0B 60 50 22 0C 0C 85 01.
        let out = lzw(&[0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01], true, 100).unwrap();
        assert_eq!(out, b"-----A---B");
    }
}
