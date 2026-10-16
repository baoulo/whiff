//! DirectDraw Surface (DDS): size, depth, mipmap levels, cube maps and
//! pixel format (FourCC block compression or the DX10 DXGI format).
//!
//! Specification: Microsoft `DDS_HEADER` / `DDS_HEADER_DXT10`.

use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for DDS.
pub struct Dds;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.dds",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "dds",
        name: "DirectDraw Surface",
        family: "image.texture",
        mimes: &["image/vnd-ms.dds"],
        extensions: &["dds"],
        magic: &[Magic::prefix(b"DDS \x7c\0\0\0")],
        parent: None,
    }],
};

/// A few common DXGI formats by number.
fn dxgi(n: u32) -> &'static str {
    match n {
        2 => "R32G32B32A32_FLOAT",
        10 => "R16G16B16A16_FLOAT",
        24 => "R10G10B10A2_UNORM",
        28 => "R8G8B8A8_UNORM",
        29 => "R8G8B8A8_UNORM_SRGB",
        61 => "R8_UNORM",
        71 => "BC1_UNORM",
        72 => "BC1_UNORM_SRGB",
        74 => "BC2_UNORM",
        77 => "BC3_UNORM",
        78 => "BC3_UNORM_SRGB",
        80 => "BC4_UNORM",
        83 => "BC5_UNORM",
        87 => "B8G8R8A8_UNORM",
        95 => "BC6H_UF16",
        96 => "BC6H_SF16",
        98 => "BC7_UNORM",
        99 => "BC7_UNORM_SRGB",
        _ => "other",
    }
}

impl Extractor for Dds {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(8)?;
        let flags = r.le_u32()?;
        let (h, w) = (r.le_u32()?, r.le_u32()?);
        let _pitch = r.le_u32()?;
        let depth = r.le_u32()?;
        let mips = r.le_u32()?;
        r.advance(44)?;
        // DDS_PIXELFORMAT
        r.advance(4)?;
        let pf_flags = r.le_u32()?;
        let fourcc = r.bytes(4)?.to_vec();
        let bits = r.le_u32()?;
        r.advance(16)?;
        let caps1 = r.le_u32()?;
        let caps2 = r.le_u32()?;
        r.advance(12)?;
        let mut img = cx.physical().image(w, h);
        // DDPF_RGB (0x40), DDPF_ALPHAPIXELS (0x1): bits per pixel over channels.
        if pf_flags & 0x40 != 0 && bits > 0 {
            let channels: u8 = if pf_flags & 1 != 0 { 4 } else { 3 };
            img.bit_depth(u8::try_from(bits / u32::from(channels)).unwrap_or(8)).channels(channels);
        }
        let format = if pf_flags & 4 != 0 {
            if &fourcc == b"DX10" {
                let d = r.le_u32()?;
                let dim = r.le_u32()?;
                let _misc = r.le_u32()?;
                let array = r.le_u32()?;
                cx.format_set("dxgi_format", dxgi(d));
                cx.format_set("dxgi_format_id", d);
                cx.format_set(
                    "dimension",
                    match dim {
                        2 => "1D",
                        3 => "2D",
                        4 => "3D",
                        _ => "unknown",
                    },
                );
                cx.format_set("array_size", array);
                "DX10".to_string()
            } else {
                String::from_utf8_lossy(&fourcc).trim_end_matches('\0').to_string()
            }
        } else {
            format!("uncompressed {bits}-bit")
        };
        cx.format_set("pixel_format", format);
        cx.format_set("mipmaps", if flags & 0x20000 != 0 { mips.max(1) } else { 1 });
        if flags & 0x0080_0000 != 0 && depth > 1 {
            cx.format_set("depth", depth);
        }
        cx.format_set("cubemap", caps2 & 0x200 != 0);
        cx.format_set("complex", caps1 & 0x8 != 0);
        Ok(())
    }
}

crate::register_extractor!(Dds);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("dds");
}
