//! Video codec configuration: H.264 and HEVC sequence parameter sets (and
//! their `avcC` / `hvcC` records), the AV1 sequence header (and `av1C`),
//! VP9 (`vpcC` and the key-frame header), the MPEG-1 / MPEG-2 sequence
//! header and extensions, the MPEG-4 Part 2 profile, Dolby Vision
//! configuration, and the colour names of ISO/IEC 23091-2 (H.273).
//!
//! Only headers are read; no picture is decoded.
//!
//! Specifications: ITU-T H.264 §7.3.2.1 and Annex E (VUI), ITU-T H.265
//! §7.3.2.2, §7.3.3 and Annex E, ISO/IEC 14496-15 (`avcC`, `hvcC`), AV1
//! Bitstream §5.5 and the AV1 ISOBMFF binding (`av1C`), the VP9 Bitstream
//! §6.2 and the VP codec ISOBMFF binding (`vpcC`), ISO/IEC 13818-2 §6.2.2
//! and 11172-2 §2.4.2, Dolby Vision streams within ISOBMFF (`dvcC`).

use super::Video;

/// A big-endian bit reader with Exp-Golomb codes.
pub(crate) struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.pos)
    }

    /// `n` bits (at most 32).
    pub(crate) fn take(&mut self, n: usize) -> Option<u32> {
        if n > 32 || self.remaining() < n {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let bit = (self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | u32::from(bit);
            self.pos += 1;
        }
        Some(v)
    }

    pub(crate) fn flag(&mut self) -> Option<bool> {
        self.take(1).map(|b| b == 1)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        (self.remaining() >= n).then(|| self.pos += n)
    }

    /// Unsigned Exp-Golomb.
    pub(crate) fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while !self.flag()? {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        let rest = self.take(zeros)?;
        u32::try_from((1u64 << zeros) - 1 + u64::from(rest)).ok()
    }

    /// Signed Exp-Golomb.
    pub(crate) fn se(&mut self) -> Option<i32> {
        let k = i64::from(self.ue()?);
        let v = if k % 2 == 1 { (k + 1) / 2 } else { -(k / 2) };
        i32::try_from(v).ok()
    }

    /// AV1 `uvlc()`.
    fn uvlc(&mut self) -> Option<u32> {
        self.ue()
    }
}

/// Remove emulation-prevention bytes (`00 00 03`) from a NAL unit.
pub(crate) fn unescape(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// The NAL units of an Annex B byte stream (start codes `00 00 01` or
/// `00 00 00 01`), at most `max`.
pub(crate) fn annexb_nals(data: &[u8], max: usize) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() && starts.len() <= max {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::new();
    for (k, &s) in starts.iter().enumerate().take(max) {
        let mut end = starts.get(k + 1).map_or(data.len(), |n| n - 3);
        while end > s && data[end - 1] == 0 {
            end -= 1;
        }
        out.push(&data[s..end]);
    }
    out
}

/// Colour description (ISO/IEC 23091-2 code points).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Colour {
    pub primaries: Option<u8>,
    pub transfer: Option<u8>,
    pub matrix: Option<u8>,
    pub full_range: Option<bool>,
}

impl Colour {
    pub(crate) fn new(primaries: u32, transfer: u32, matrix: u32, full_range: Option<bool>) -> Self {
        let code = |v: u32| u8::try_from(v).ok().filter(|v| *v != 2);
        Self { primaries: code(primaries), transfer: code(transfer), matrix: code(matrix), full_range }
    }
}

/// Colour primaries, as ffprobe names them.
pub(crate) fn primaries_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "bt709",
        4 => "bt470m",
        5 => "bt470bg",
        6 => "smpte170m",
        7 => "smpte240m",
        8 => "film",
        9 => "bt2020",
        10 => "smpte428",
        11 => "smpte431",
        12 => "smpte432",
        22 => "jedec-p22",
        _ => return None,
    })
}

/// Transfer characteristics.
pub(crate) fn transfer_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "bt709",
        4 => "gamma22",
        5 => "gamma28",
        6 => "smpte170m",
        7 => "smpte240m",
        8 => "linear",
        9 => "log100",
        10 => "log316",
        11 => "iec61966-2-4",
        12 => "bt1361e",
        13 => "iec61966-2-1",
        14 => "bt2020-10",
        15 => "bt2020-12",
        16 => "smpte2084",
        17 => "smpte428",
        18 => "arib-std-b67",
        _ => return None,
    })
}

/// Matrix coefficients.
pub(crate) fn matrix_name(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "gbr",
        1 => "bt709",
        4 => "fcc",
        5 => "bt470bg",
        6 => "smpte170m",
        7 => "smpte240m",
        8 => "ycgco",
        9 => "bt2020nc",
        10 => "bt2020c",
        11 => "smpte2085",
        12 => "chroma-derived-nc",
        13 => "chroma-derived-c",
        14 => "ictcp",
        _ => return None,
    })
}

/// Chroma subsampling of an H.264 / HEVC `chroma_format_idc`.
fn chroma_name(idc: u32) -> Option<&'static str> {
    Some(match idc {
        0 => "4:0:0",
        1 => "4:2:0",
        2 => "4:2:2",
        3 => "4:4:4",
        _ => return None,
    })
}

/// H.264 / HEVC / MPEG-4 Table E-1 sample aspect ratios.
fn sar_table(idc: u32) -> Option<(u32, u32)> {
    const T: [(u32, u32); 17] = [
        (0, 0),
        (1, 1),
        (12, 11),
        (10, 11),
        (16, 11),
        (40, 33),
        (24, 11),
        (20, 11),
        (32, 11),
        (80, 33),
        (18, 11),
        (15, 11),
        (64, 33),
        (160, 99),
        (4, 3),
        (3, 2),
        (2, 1),
    ];
    T.get(idc as usize).copied().filter(|s| s.0 > 0)
}

/// The VUI fields H.264 and HEVC share: aspect ratio, colour, and timing.
fn vui_aspect_colour(b: &mut Bits<'_>, v: &mut Video) -> Option<()> {
    if b.flag()? {
        let idc = b.take(8)?;
        v.sar =
            if idc == 255 { Some((b.take(16)?, b.take(16)?)).filter(|s| s.0 > 0 && s.1 > 0) } else { sar_table(idc) };
    }
    if b.flag()? {
        b.skip(1)?; // overscan_appropriate
    }
    if b.flag()? {
        let _format = b.take(3)?;
        let full = b.flag()?;
        let mut c = Colour { full_range: Some(full), ..Colour::default() };
        if b.flag()? {
            c = Colour::new(b.take(8)?, b.take(8)?, b.take(8)?, Some(full));
        }
        v.colour = c;
    }
    if b.flag()? {
        b.ue()?;
        b.ue()?;
    }
    Some(())
}

fn h264_profile(idc: u32, flags: u32) -> &'static str {
    let set = |n: u32| flags & (0x80 >> n) != 0;
    match idc {
        66 if set(1) => "constrained_baseline",
        66 => "baseline",
        77 => "main",
        88 => "extended",
        100 => "high",
        110 if set(3) => "high_10_intra",
        110 => "high_10",
        122 if set(3) => "high_422_intra",
        122 => "high_422",
        244 if set(3) => "high_444_intra",
        244 => "high_444_predictive",
        44 => "cavlc_444",
        83 => "scalable_baseline",
        86 => "scalable_high",
        118 => "multiview_high",
        128 => "stereo_high",
        _ => "unknown",
    }
}

/// An H.264 sequence parameter set (with its NAL header byte).
pub(crate) fn h264_sps(nal: &[u8]) -> Option<Video> {
    if nal.first()? & 0x1f != 7 {
        return None;
    }
    let data = unescape(&nal[1..]);
    let mut b = Bits::new(&data);
    let mut v = Video::new("h264");
    let profile = b.take(8)?;
    let flags = b.take(8)?;
    let level = b.take(8)?;
    v.profile = Some(h264_profile(profile, flags).into());
    // Level 1b: level_idc 9, or 11 with constraint_set3 in the Baseline-family profiles.
    v.level = Some(if level == 9 || (level == 11 && flags & 0x10 != 0 && matches!(profile, 66 | 77 | 88)) {
        "1b".into()
    } else {
        format!("{}.{}", level / 10, level % 10)
    });
    b.ue()?; // seq_parameter_set_id
    let mut chroma = 1;
    let mut separate = false;
    let mut depth = 8;
    if matches!(profile, 100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135) {
        chroma = b.ue()?;
        if chroma == 3 {
            separate = b.flag()?;
        }
        depth = 8 + b.ue()?.min(8);
        b.ue()?; // bit_depth_chroma
        b.skip(1)?; // qpprime_y_zero_transform_bypass
        if b.flag()? {
            for i in 0..if chroma == 3 { 12 } else { 8 } {
                if b.flag()? {
                    let size = if i < 6 { 16 } else { 64 };
                    let (mut last, mut next) = (8i32, 8i32);
                    for _ in 0..size {
                        if next != 0 {
                            next = (last + b.se()? + 256) % 256;
                        }
                        if next != 0 {
                            last = next;
                        }
                    }
                }
            }
        }
    }
    v.chroma = chroma_name(chroma);
    v.bit_depth = u8::try_from(depth).ok();
    b.ue()?; // log2_max_frame_num_minus4
    match b.ue()? {
        0 => {
            b.ue()?;
        }
        1 => {
            b.skip(1)?;
            b.se()?;
            b.se()?;
            for _ in 0..b.ue()?.min(255) {
                b.se()?;
            }
        }
        _ => {}
    }
    b.ue()?; // max_num_ref_frames
    b.skip(1)?; // gaps_in_frame_num_value_allowed
    let w_mbs = u64::from(b.ue()?) + 1;
    let h_units = u64::from(b.ue()?) + 1;
    let frame_mbs_only = b.flag()?;
    if !frame_mbs_only {
        b.skip(1)?; // mb_adaptive_frame_field
    }
    b.skip(1)?; // direct_8x8_inference
    let mut crop = (0u64, 0u64, 0u64, 0u64);
    if b.flag()? {
        crop = (u64::from(b.ue()?), u64::from(b.ue()?), u64::from(b.ue()?), u64::from(b.ue()?));
    }
    let field = if frame_mbs_only { 1 } else { 2 };
    let (sub_w, sub_h) = match (chroma, separate) {
        (1, false) => (2, 2),
        (2, false) => (2, 1),
        _ => (1, 1),
    };
    let (unit_x, unit_y) = if chroma == 0 || separate { (1, field) } else { (sub_w, sub_h * field) };
    v.crop_origin = crop.0 > 0 || crop.2 > 0;
    let width = (w_mbs * 16).saturating_sub(unit_x * (crop.0 + crop.1));
    let height = (field * h_units * 16).saturating_sub(unit_y * (crop.2 + crop.3));
    v.width = u32::try_from(width).ok().filter(|w| *w > 0);
    v.height = u32::try_from(height).ok().filter(|h| *h > 0);
    v.interlaced = Some(!frame_mbs_only);
    if b.flag()? {
        vui_aspect_colour(&mut b, &mut v)?;
        if b.flag()? {
            let (units, scale) = (b.take(32)?, b.take(32)?);
            if units > 0 && scale > 0 {
                v.fps = Some(f64::from(scale) / (2.0 * f64::from(units)));
            }
        }
    }
    Some(v)
}

/// An `avcC` record: the profile and level, then the first SPS.
pub(crate) fn avcc(d: &[u8]) -> Option<Video> {
    if d.len() < 7 || d[0] != 1 {
        return None;
    }
    let n = usize::from(d[5] & 0x1f);
    let mut at = 6;
    for _ in 0..n {
        let len = usize::from(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]));
        let sps = d.get(at + 2..at + 2 + len)?;
        if let Some(v) = h264_sps(sps) {
            return Some(v);
        }
        at += 2 + len;
    }
    let mut v = Video::new("h264");
    v.profile = Some(h264_profile(u32::from(d[1]), u32::from(d[2])).into());
    v.level = Some(format!("{}.{}", d[3] / 10, d[3] % 10));
    Some(v)
}

fn hevc_profile(idc: u32) -> &'static str {
    match idc {
        1 => "main",
        2 => "main_10",
        3 => "main_still_picture",
        4 => "rext",
        5 => "high_throughput",
        6 => "multiview_main",
        7 => "scalable_main",
        8 => "3d_main",
        9 => "screen_content",
        10 => "scalable_rext",
        11 => "high_throughput_scc",
        _ => "unknown",
    }
}

fn hevc_level(idc: u32) -> String {
    // general_level_idc is 30 × the level number.
    format!("{}.{}", idc / 30, (idc % 30) / 3)
}

/// An HEVC sequence parameter set (with its two-byte NAL header).
#[allow(clippy::too_many_lines)] // the SPS fields up to the VUI, in order
pub(crate) fn hevc_sps(nal: &[u8]) -> Option<Video> {
    if (nal.first()? >> 1) & 0x3f != 33 {
        return None;
    }
    let data = unescape(nal.get(2..)?);
    let mut b = Bits::new(&data);
    let mut v = Video::new("hevc");
    b.skip(4)?; // sps_video_parameter_set_id
    let max_sub = b.take(3)? as usize;
    b.skip(1)?; // temporal_id_nesting
    // profile_tier_level(1, max_sub)
    b.skip(2)?;
    let tier = b.flag()?;
    let profile = b.take(5)?;
    b.skip(32 + 4 + 43 + 1)?;
    let level = b.take(8)?;
    v.profile = Some(hevc_profile(profile).into());
    v.tier = Some(if tier { "high" } else { "main" });
    v.level = Some(hevc_level(level));
    let mut present = [(false, false); 8];
    for p in present.iter_mut().take(max_sub) {
        *p = (b.flag()?, b.flag()?);
    }
    if max_sub > 0 {
        b.skip(2 * (8 - max_sub))?;
    }
    for &(profile_present, level_present) in present.iter().take(max_sub) {
        if profile_present {
            b.skip(88)?;
        }
        if level_present {
            b.skip(8)?;
        }
    }
    b.ue()?; // sps_seq_parameter_set_id
    let chroma = b.ue()?;
    let mut separate = false;
    if chroma == 3 {
        separate = b.flag()?;
    }
    let width = b.ue()?;
    let height = b.ue()?;
    let (sub_w, sub_h) = match (chroma, separate) {
        (1, false) => (2, 2),
        (2, false) => (2, 1),
        _ => (1, 1),
    };
    let (mut w, mut h) = (u64::from(width), u64::from(height));
    if b.flag()? {
        let (l, r, t, bo) = (b.ue()?, b.ue()?, b.ue()?, b.ue()?);
        w = w.saturating_sub(sub_w * (u64::from(l) + u64::from(r)));
        h = h.saturating_sub(sub_h * (u64::from(t) + u64::from(bo)));
    }
    v.width = u32::try_from(w).ok().filter(|w| *w > 0);
    v.height = u32::try_from(h).ok().filter(|h| *h > 0);
    v.bit_depth = u8::try_from(8 + b.ue()?.min(8)).ok();
    v.chroma = chroma_name(chroma);
    b.ue()?; // bit_depth_chroma
    let poc_bits = b.ue()?.min(12) as usize + 4;
    let ordering_all = b.flag()?;
    for _ in if ordering_all { 0 } else { max_sub }..=max_sub {
        b.ue()?;
        b.ue()?;
        b.ue()?;
    }
    for _ in 0..6 {
        b.ue()?; // block sizes and transform depths
    }
    if b.flag()? && b.flag()? {
        // scaling_list_data()
        for size in 0..4 {
            let mut matrix = 0;
            while matrix < 6 {
                if b.flag()? {
                    let coefs = 64.min(1 << (4 + (size << 1)));
                    if size > 1 {
                        b.se()?;
                    }
                    for _ in 0..coefs {
                        b.se()?;
                    }
                } else {
                    b.ue()?;
                }
                matrix += if size == 3 { 3 } else { 1 };
            }
        }
    }
    b.skip(2)?; // amp, sample_adaptive_offset
    if b.flag()? {
        b.skip(8)?;
        b.ue()?;
        b.ue()?;
        b.skip(1)?;
    }
    let sets = b.ue()?.min(64) as usize;
    let mut deltas = vec![0u32; sets];
    for i in 0..sets {
        let inter = i != 0 && b.flag()?;
        if inter {
            b.skip(1)?;
            b.ue()?;
            let mut n = 0;
            for _ in 0..=deltas[i - 1] {
                let used = b.flag()?;
                if used || b.flag()? {
                    n += 1;
                }
            }
            deltas[i] = n;
        } else {
            let (neg, pos) = (b.ue()?.min(32), b.ue()?.min(32));
            for _ in 0..neg + pos {
                b.ue()?;
                b.skip(1)?;
            }
            deltas[i] = neg + pos;
        }
    }
    if b.flag()? {
        for _ in 0..b.ue()?.min(32) {
            b.skip(poc_bits + 1)?;
        }
    }
    b.skip(2)?; // temporal_mvp, strong_intra_smoothing
    if b.flag()? {
        vui_aspect_colour(&mut b, &mut v)?;
        let (_neutral, field_seq, _frame_field) = (b.flag()?, b.flag()?, b.flag()?);
        v.interlaced = Some(field_seq);
        if b.flag()? {
            for _ in 0..4 {
                b.ue()?;
            }
        }
        if b.flag()? {
            let (units, scale) = (b.take(32)?, b.take(32)?);
            if units > 0 && scale > 0 {
                v.fps = Some(f64::from(scale) / f64::from(units));
            }
        }
    }
    Some(v)
}

/// An `hvcC` record: profile, tier, level, chroma and depth, then the SPS.
pub(crate) fn hvcc(d: &[u8]) -> Option<Video> {
    if d.len() < 23 {
        return None;
    }
    let mut v = Video::new("hevc");
    let mut at = 23;
    for _ in 0..d[22] {
        let kind = d.get(at)? & 0x3f;
        let n = u16::from_be_bytes([*d.get(at + 1)?, *d.get(at + 2)?]);
        at += 3;
        for _ in 0..n {
            let len = usize::from(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]));
            let nal = d.get(at + 2..at + 2 + len)?;
            at += 2 + len;
            if kind == 33
                && v.width.is_none()
                && let Some(s) = hevc_sps(nal)
            {
                v = s;
            }
        }
    }
    v.profile.get_or_insert_with(|| hevc_profile(u32::from(d[1] & 0x1f)).into());
    v.tier.get_or_insert(if d[1] & 0x20 != 0 { "high" } else { "main" });
    v.level.get_or_insert_with(|| hevc_level(u32::from(d[12])));
    v.chroma = v.chroma.or_else(|| chroma_name(u32::from(d[16] & 3)));
    v.bit_depth = v.bit_depth.or(Some(8 + (d[17] & 7)));
    let avg = u16::from_be_bytes([d[19], d[20]]);
    if v.fps.is_none() && avg > 0 {
        v.fps = Some(f64::from(avg) / 256.0);
    }
    Some(v)
}

fn av1_level(idx: u32) -> String {
    if idx == 31 { "max".into() } else { format!("{}.{}", 2 + (idx >> 2), idx & 3) }
}

fn av1_profile(p: u32) -> &'static str {
    match p {
        0 => "main",
        1 => "high",
        2 => "professional",
        _ => "unknown",
    }
}

/// An `av1C` record, and the sequence header OBU it may carry.
pub(crate) fn av1c(d: &[u8]) -> Option<Video> {
    if d.len() < 4 || d[0] & 0x80 == 0 {
        return None;
    }
    let mut v = av1_obus(&d[4..]).unwrap_or_else(|| Video::new("av1"));
    let profile = u32::from(d[1] >> 5);
    v.profile.get_or_insert_with(|| av1_profile(profile).into());
    v.level.get_or_insert_with(|| av1_level(u32::from(d[1] & 0x1f)));
    v.tier.get_or_insert(if d[2] & 0x80 != 0 { "high" } else { "main" });
    let (high, twelve, mono) = (d[2] & 0x40 != 0, d[2] & 0x20 != 0, d[2] & 0x10 != 0);
    v.bit_depth.get_or_insert(match (high, twelve) {
        (true, true) => 12,
        (true, false) => 10,
        _ => 8,
    });
    v.chroma = v.chroma.or(Some(match (mono, d[2] & 0x08 != 0, d[2] & 0x04 != 0) {
        (true, _, _) => "4:0:0",
        (_, true, true) => "4:2:0",
        (_, true, false) => "4:2:2",
        _ => "4:4:4",
    }));
    Some(v)
}

fn leb128(d: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..8 {
        let b = *d.get(*at)?;
        *at += 1;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The first sequence header among AV1 OBUs (low-overhead format).
pub(crate) fn av1_obus(d: &[u8]) -> Option<Video> {
    let mut at = 0;
    for _ in 0..64 {
        let h = *d.get(at)?;
        let kind = (h >> 3) & 0xf;
        at += 1 + usize::from(h & 4 != 0);
        let size = if h & 2 != 0 { usize::try_from(leb128(d, &mut at)?).ok()? } else { d.len() - at };
        let body = d.get(at..at.checked_add(size)?)?;
        if kind == 1 {
            return av1_sequence(body);
        }
        at += size;
    }
    None
}

/// An AV1 sequence header OBU payload.
#[allow(clippy::too_many_lines)] // the header fields up to the colour config, in order
fn av1_sequence(d: &[u8]) -> Option<Video> {
    let mut b = Bits::new(d);
    let mut v = Video::new("av1");
    let profile = b.take(3)?;
    v.profile = Some(av1_profile(profile).into());
    b.skip(1)?; // still_picture
    let reduced = b.flag()?;
    if reduced {
        v.level = Some(av1_level(b.take(5)?));
    } else {
        let mut buffer_delay = 0;
        let timing = b.flag()?;
        let mut decoder_model = false;
        if timing {
            let (units, scale) = (b.take(32)?, b.take(32)?);
            if b.flag()? {
                let ticks = u64::from(b.uvlc()?) + 1;
                if units > 0 && scale > 0 {
                    v.fps = Some(f64::from(scale) / (f64::from(units) * ticks as f64));
                }
            }
            decoder_model = b.flag()?;
            if decoder_model {
                buffer_delay = b.take(5)? as usize + 1;
                b.skip(32 + 5 + 5)?;
            }
        }
        let initial_display = b.flag()?;
        for i in 0..=b.take(5)? {
            b.skip(12)?;
            let idx = b.take(5)?;
            let tier = if idx > 7 { b.flag()? } else { false };
            if i == 0 {
                v.level = Some(av1_level(idx));
                v.tier = Some(if tier { "high" } else { "main" });
            }
            if decoder_model && b.flag()? {
                b.skip(2 * buffer_delay + 1)?;
            }
            if initial_display && b.flag()? {
                b.skip(4)?;
            }
        }
    }
    let wb = b.take(4)? as usize + 1;
    let hb = b.take(4)? as usize + 1;
    v.width = b.take(wb).map(|w| w + 1);
    v.height = b.take(hb).map(|h| h + 1);
    let frame_ids = !reduced && b.flag()?;
    if frame_ids {
        b.skip(4 + 3)?;
    }
    b.skip(3)?; // 128x128, filter_intra, intra_edge
    if !reduced {
        b.skip(4)?; // interintra, masked, warped, dual_filter
        let order_hint = b.flag()?;
        if order_hint {
            b.skip(2)?;
        }
        let force_sct = if b.flag()? { 2 } else { b.take(1)? };
        if force_sct > 0 && !b.flag()? {
            b.skip(1)?;
        }
        if order_hint {
            b.skip(3)?;
        }
    }
    b.skip(3)?; // superres, cdef, restoration
    let high = b.flag()?;
    let depth = if profile == 2 && high {
        if b.flag()? { 12 } else { 10 }
    } else if high {
        10
    } else {
        8
    };
    v.bit_depth = Some(depth);
    let mono = profile != 1 && b.flag()?;
    let (mut cp, mut tc, mut mc) = (2, 2, 2);
    if b.flag()? {
        (cp, tc, mc) = (b.take(8)?, b.take(8)?, b.take(8)?);
    }
    let full = if mono {
        b.flag()?
    } else if cp == 1 && tc == 13 && mc == 0 {
        true
    } else {
        let full = b.flag()?;
        let (sx, sy) = match profile {
            0 => (1, 1),
            1 => (0, 0),
            _ if depth == 12 => {
                let sx = b.take(1)?;
                (sx, if sx == 1 { b.take(1)? } else { 0 })
            }
            _ => (1, 0),
        };
        v.chroma = Some(match (sx, sy) {
            (1, 1) => "4:2:0",
            (1, 0) => "4:2:2",
            _ => "4:4:4",
        });
        full
    };
    if mono {
        v.chroma = Some("4:0:0");
    }
    v.colour = Colour::new(cp, tc, mc, Some(full));
    Some(v)
}

/// A `vpcC` (version 1) record.
pub(crate) fn vpcc(codec: &str, d: &[u8]) -> Option<Video> {
    // Full box: version and flags first.
    let d = d.get(4..)?;
    if d.len() < 6 {
        return None;
    }
    let mut v = Video::new(codec);
    v.profile = Some(format!("profile_{}", d[0]));
    if d[1] > 0 {
        v.level = Some(format!("{}.{}", d[1] / 10, d[1] % 10));
    }
    v.bit_depth = Some(d[2] >> 4);
    v.chroma = Some(match (d[2] >> 1) & 7 {
        0 | 1 => "4:2:0",
        2 => "4:2:2",
        _ => "4:4:4",
    });
    v.colour = Colour::new(u32::from(d[3]), u32::from(d[4]), u32::from(d[5]), Some(d[2] & 1 == 1));
    Some(v)
}

/// A VP9 key frame's uncompressed header: profile, depth, chroma, size.
pub(crate) fn vp9_frame(d: &[u8]) -> Option<Video> {
    let mut b = Bits::new(d);
    if b.take(2)? != 2 {
        return None;
    }
    let lo = b.take(1)?;
    let profile = (b.take(1)? << 1) | lo;
    if profile == 3 {
        b.skip(1)?;
    }
    if b.flag()? || b.flag()? {
        return None; // show_existing_frame, or not a key frame
    }
    b.skip(2)?; // show_frame, error_resilient
    if b.take(24)? != 0x49_83_42 {
        return None;
    }
    let mut v = Video::new("vp9");
    v.profile = Some(format!("profile_{profile}"));
    let depth = if profile >= 2 { if b.flag()? { 12 } else { 10 } } else { 8 };
    v.bit_depth = Some(depth);
    let space = b.take(3)?;
    if space == 7 {
        v.chroma = Some("4:4:4");
        if profile == 1 || profile == 3 {
            b.skip(1)?;
        }
    } else {
        v.colour.full_range = Some(b.flag()?);
        v.chroma = Some(if profile == 1 || profile == 3 {
            let (x, y) = (b.take(1)?, b.take(1)?);
            b.skip(1)?;
            match (x, y) {
                (1, 1) => "4:2:0",
                (1, 0) => "4:2:2",
                (0, 1) => "4:4:0",
                _ => "4:4:4",
            }
        } else {
            "4:2:0"
        });
    }
    v.width = b.take(16).map(|w| w + 1);
    v.height = b.take(16).map(|h| h + 1);
    Some(v)
}

/// A VP8 key frame: its size.
pub(crate) fn vp8_frame(d: &[u8]) -> Option<Video> {
    if d.len() < 10 || d[0] & 1 != 0 || d[3..6] != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let mut v = Video::new("vp8");
    v.width = Some(u32::from(u16::from_le_bytes([d[6], d[7]]) & 0x3fff));
    v.height = Some(u32::from(u16::from_le_bytes([d[8], d[9]]) & 0x3fff));
    Some(v)
}

/// MPEG-1 / MPEG-2 frame rates by `frame_rate_code`.
const MPEG_RATES: [(u32, u32); 9] =
    [(0, 0), (24000, 1001), (24, 1), (25, 1), (30000, 1001), (30, 1), (50, 1), (60000, 1001), (60, 1)];

/// An MPEG-1 / MPEG-2 video sequence header (from its start code), with the
/// sequence and display extensions that follow it.
pub(crate) fn mpeg_sequence(d: &[u8]) -> Option<Video> {
    let at = d.windows(4).position(|w| w == [0, 0, 1, 0xb3])?;
    let h = d.get(at + 4..at + 12)?;
    let mut v = Video::new("mpeg1video");
    let width = (u32::from(h[0]) << 4) | u32::from(h[1] >> 4);
    let height = ((u32::from(h[1]) & 0xf) << 8) | u32::from(h[2]);
    let aspect = h[3] >> 4;
    let rate = MPEG_RATES.get(usize::from(h[3] & 0xf)).copied().filter(|r| r.0 > 0);
    let bitrate = (u32::from(h[4]) << 10) | (u32::from(h[5]) << 2) | u32::from(h[6] >> 6);
    let (mut w, mut hgt, mut fps, mut br) = (width, height, rate, u64::from(bitrate));
    let mut mpeg2 = false;
    // Extensions follow the quantiser matrices; search the next bytes.
    let rest = d.get(at + 12..d.len().min(at + 12 + 512))?;
    let mut i = 0;
    while let Some(p) = rest.get(i..).and_then(|r| r.windows(4).position(|x| x == [0, 0, 1, 0xb5])) {
        let e = rest.get(i + p + 4..).unwrap_or_default();
        match e.first().map(|b| b >> 4) {
            Some(1) if e.len() >= 6 => {
                mpeg2 = true;
                let pl = ((e[0] & 0xf) << 4) | (e[1] >> 4);
                v.profile = mpeg2_profile(pl).map(Into::into);
                v.level = mpeg2_level(pl & 0xf).map(Into::into);
                v.interlaced = Some(e[1] & 0x08 == 0);
                v.chroma = Some(match (e[1] >> 1) & 3 {
                    2 => "4:2:2",
                    3 => "4:4:4",
                    _ => "4:2:0",
                });
                w |= ((u32::from(e[1]) & 1) << 13) | (u32::from(e[2] >> 7) << 12);
                hgt |= u32::from((e[2] >> 5) & 3) << 12;
                let ext = ((u32::from(e[2]) & 0x1f) << 7) | u32::from(e[3] >> 1);
                br |= u64::from(ext) << 18;
                let (n, dd) = (u32::from((e[5] >> 5) & 3) + 1, u32::from(e[5] & 0x1f) + 1);
                fps = fps.map(|(a, b)| (a * n, b * dd));
            }
            Some(2) if e.len() >= 5 => {
                let mut b = Bits::new(e);
                b.skip(4 + 3)?;
                if b.flag()? {
                    v.colour = Colour::new(b.take(8)?, b.take(8)?, b.take(8)?, None);
                }
            }
            _ => {}
        }
        i += p + 4;
        if rest.get(i..i + 4).is_some_and(|x| x[..3] == [0, 0, 1] && x[3] != 0xb5 && x[3] != 0xb2) {
            break;
        }
    }
    if mpeg2 {
        v.codec = "mpeg2video".into();
        v.dar = match aspect {
            2 => Some((4, 3)),
            3 => Some((16, 9)),
            4 => Some((221, 100)),
            _ => None,
        };
        if aspect == 1 {
            v.sar = Some((1, 1));
        }
    } else {
        v.sar = mpeg1_sar(aspect);
    }
    v.width = Some(w).filter(|w| *w > 0);
    v.height = Some(hgt).filter(|h| *h > 0);
    v.fps = fps.map(|(a, b)| f64::from(a) / f64::from(b));
    if bitrate != 0x3ffff {
        v.bitrate_bps = Some(br * 400).filter(|b| *b > 0);
    }
    v.chroma.get_or_insert("4:2:0");
    v.bit_depth = Some(8);
    Some(v)
}

fn mpeg1_sar(code: u8) -> Option<(u32, u32)> {
    // Pel aspect ratios (height / width) of ISO/IEC 11172-2 Table 2-D.2.
    const T: [u32; 15] = [0, 10000, 6735, 7031, 7615, 8055, 8437, 8935, 9157, 9815, 10255, 10695, 10950, 11575, 12015];
    let h = *T.get(usize::from(code))?;
    (h > 0).then_some((10000, h))
}

fn mpeg2_profile(pl: u8) -> Option<&'static str> {
    if pl & 0x80 != 0 {
        return match pl {
            0x82 | 0x85 => Some("422"),
            0x8a..=0x8e => Some("multiview"),
            _ => None,
        };
    }
    Some(match (pl >> 4) & 7 {
        1 => "high",
        2 => "spatially_scalable",
        3 => "snr_scalable",
        4 => "main",
        5 => "simple",
        _ => return None,
    })
}

fn mpeg2_level(l: u8) -> Option<&'static str> {
    Some(match l {
        4 => "high",
        6 => "high_1440",
        8 => "main",
        10 => "low",
        _ => return None,
    })
}

/// The MPEG-4 Part 2 profile from a visual object sequence start code.
pub(crate) fn mpeg4_visual(d: &[u8]) -> Option<Video> {
    let at = d.windows(4).position(|w| w == [0, 0, 1, 0xb0])?;
    let pl = *d.get(at + 4)?;
    let mut v = Video::new("mpeg4");
    let (profile, level) = match pl {
        0x01..=0x03 => ("simple", pl),
        0x08 => ("simple", 0),
        0x10..=0x12 => ("simple_scalable", pl - 0x10),
        0x21 | 0x22 => ("core", pl - 0x20),
        0x32..=0x34 => ("main", pl - 0x30),
        0xf0..=0xf5 => ("advanced_simple", pl - 0xf0),
        0xf7 => ("advanced_simple", 3),
        _ => return Some(v),
    };
    v.profile = Some(profile.into());
    v.level = Some(level.to_string());
    Some(v)
}

/// A Dolby Vision configuration record (`dvcC`, `dvvC`, `dvwC`, Matroska
/// block addition mapping): profile, level, layers, compatibility.
pub(crate) fn dolby_vision(d: &[u8]) -> Option<serde_json::Value> {
    if d.len() < 5 {
        return None;
    }
    let bits = u16::from_be_bytes([d[2], d[3]]);
    Some(serde_json::json!({
        "version": format!("{}.{}", d[0], d[1]),
        "profile": bits >> 9,
        "level": (bits >> 3) & 0x3f,
        "rpu": bits & 4 != 0,
        "enhancement_layer": bits & 2 != 0,
        "base_layer": bits & 1 != 0,
        "base_layer_compatibility": d[4] >> 4,
    }))
}

/// A Theora identification header: the stream, the key-frame granule shift,
/// and whether granule positions count from 1 (bitstream 3.2.1 and later).
pub(crate) fn theora(d: &[u8]) -> Option<(Video, u32, bool)> {
    if d.len() < 42 || !d.starts_with(b"\x80theora") {
        return None;
    }
    let u24 = |i: usize| (u32::from(d[i]) << 16) | (u32::from(d[i + 1]) << 8) | u32::from(d[i + 2]);
    let u32be = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    let mut v = Video::new("theora");
    v.width = Some(u24(14)).filter(|w| *w > 0);
    v.height = Some(u24(17)).filter(|h| *h > 0);
    let (num, den) = (u32be(22), u32be(26));
    v.fps = (num > 0 && den > 0).then(|| f64::from(num) / f64::from(den));
    v.sar = Some((u24(30), u24(33))).filter(|s| s.0 > 0 && s.1 > 0);
    v.colour = match d[36] {
        1 => Colour::new(4, 2, 2, None),
        2 => Colour::new(5, 2, 2, None),
        _ => Colour::default(),
    };
    v.bitrate_bps = Some(u64::from(u24(37))).filter(|b| *b > 0);
    let bits = u16::from_be_bytes([d[40], d[41]]);
    let shift = u32::from((bits >> 5) & 0x1f);
    v.chroma = Some(match (bits >> 3) & 3 {
        2 => "4:2:2",
        3 => "4:4:4",
        _ => "4:2:0",
    });
    v.bit_depth = Some(8);
    v.profile = Some(format!("{}.{}.{}", d[7], d[8], d[9]));
    let one_based = (d[7], d[8], d[9]) >= (3, 2, 1);
    Some((v, shift, one_based))
}

/// The ProRes flavour of a QuickTime sample-entry type.
pub(crate) fn prores_profile(fourcc: &str) -> Option<&'static str> {
    Some(match fourcc {
        "apco" => "proxy",
        "apcs" => "lt",
        "apcn" => "standard",
        "apch" => "hq",
        "ap4h" => "4444",
        "ap4x" => "4444_xq",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_golomb_and_unescape() {
        // 1, 010, 011, 00100 → 0, 1, 2, 3.
        let mut b = Bits::new(&[0b1010_0110, 0b0100_0000]);
        assert_eq!((b.ue(), b.ue(), b.ue(), b.ue()), (Some(0), Some(1), Some(2), Some(3)));
        let mut b = Bits::new(&[0b0100_1100]);
        assert_eq!((b.se(), b.se()), (Some(1), Some(-1)));
        assert_eq!(unescape(&[0, 0, 3, 1, 0, 0, 3]), [0, 0, 1, 0, 0]);
        assert_eq!(annexb_nals(&[0, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x68, 2], 8), [&[0x67, 1][..], &[0x68, 2][..]]);
    }

    #[test]
    fn h264_sps_with_cropping_and_vui() {
        // x264, High 4.0, 1920x1080 (68 rows of macroblocks cropped by 8), 25 fps, BT.709.
        let sps = [
            0x67, 0x64, 0x00, 0x28, 0xac, 0xd9, 0x40, 0x78, 0x02, 0x27, 0xe5, 0xc0, 0x5a, 0x81, 0x01, 0x00, 0xa0, 0x00,
            0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x06, 0x41, 0xe3, 0x06, 0x32, 0xc0,
        ];
        let v = h264_sps(&sps).unwrap();
        assert_eq!((v.width, v.height, v.fps), (Some(1920), Some(1080), Some(25.0)));
        assert_eq!((v.profile.as_deref(), v.level.as_deref()), (Some("high"), Some("4.0")));
        assert_eq!((v.bit_depth, v.chroma, v.interlaced), (Some(8), Some("4:2:0"), Some(false)));
        // ffmpeg passed only the matrix on to x264.
        assert_eq!((v.colour.primaries, v.colour.transfer, v.colour.matrix), (None, None, Some(1)));
        // x265, Main 3.1, 1280x720, 30 fps.
        let sps = [
            0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x5d,
            0xa0, 0x02, 0x80, 0x80, 0x2d, 0x16, 0x59, 0x59, 0xa4, 0x93, 0x2b, 0xc0, 0x5a, 0x02, 0x00, 0x00, 0x03, 0x00,
            0x02, 0x00, 0x00, 0x03, 0x00, 0x3c, 0x10,
        ];
        let v = hevc_sps(&sps).unwrap();
        assert_eq!((v.width, v.height, v.fps), (Some(1280), Some(720), Some(30.0)));
        assert_eq!((v.profile.as_deref(), v.level.as_deref(), v.tier), (Some("main"), Some("3.1"), Some("main")));
        assert_eq!((v.bit_depth, v.chroma), (Some(8), Some("4:2:0")));
    }

    #[test]
    fn mpeg2_sequence_and_colour_names() {
        // 720x576, 4:3, 25 fps, 8 Mbit/s; sequence extension: Main@Main, progressive.
        let mut d = vec![0, 0, 1, 0xb3, 0x2d, 0x02, 0x40, 0x23, 0x4e, 0x20, 0x00, 0x00];
        d.extend_from_slice(&[0, 0, 1, 0xb5, 0x14, 0x8a, 0x00, 0x01, 0x00, 0x00]);
        let v = mpeg_sequence(&d).unwrap();
        assert_eq!(v.codec, "mpeg2video");
        assert_eq!((v.width, v.height, v.fps, v.dar), (Some(720), Some(576), Some(25.0), Some((4, 3))));
        assert_eq!((v.profile.as_deref(), v.level.as_deref()), (Some("main"), Some("main")));
        assert_eq!(v.interlaced, Some(false));
        assert_eq!(
            (primaries_name(9), transfer_name(16), matrix_name(9)),
            (Some("bt2020"), Some("smpte2084"), Some("bt2020nc"))
        );
        assert_eq!(hevc_level(123), "4.1");
        assert_eq!((hevc_level(120), av1_level(8)), ("4.0".to_string(), "4.0".to_string()));
        assert_eq!(prores_profile("apch"), Some("hq"));
    }

    #[test]
    fn vp_frames_and_records() {
        let v = vp8_frame(&[0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x40, 0x01, 0xf0, 0x00]).unwrap();
        assert_eq!((v.width, v.height), (Some(320), Some(240)));
        let v = vpcc("vp9", &[1, 0, 0, 0, 2, 31, 0x82, 9, 16, 9, 0, 0]).unwrap();
        assert_eq!((v.profile.as_deref(), v.level.as_deref(), v.bit_depth), (Some("profile_2"), Some("3.1"), Some(8)));
        assert_eq!(v.colour.transfer, Some(16));
        let dv = dolby_vision(&[1, 0, 0x10, 0x35, 0x10]).unwrap();
        assert_eq!((dv["profile"].as_u64(), dv["level"].as_u64()), (Some(8), Some(6)));
    }
}
