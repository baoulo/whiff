//! Comic book archives in ZIP form (CBZ): page images and the
//! `ComicInfo.xml` record (Anansi Project schema 2.0).

use serde_json::json;

use super::super::xml::values;
use super::Book;
use crate::plugin::{Context, ExtractError, Source, Zip, truncate_chars};

const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp", "avif", "jxl", "bmp", "tif", "tiff"];

#[allow(clippy::too_many_lines)] // pages, then the ComicInfo fields
pub(super) fn extract(src: &mut dyn Source, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 100_000)?;
    let mut pages: Vec<&str> = zip
        .entries
        .iter()
        .filter(|e| !e.is_dir() && !e.name.starts_with("__MACOSX/"))
        .filter(|e| e.name.rsplit_once('.').is_some_and(|(_, x)| IMAGE_EXTS.contains(&x.to_ascii_lowercase().as_str())))
        .map(|e| e.name.as_str())
        .collect();
    pages.sort_unstable();
    cx.physical().pages(pages.len() as u64);
    if let Some(first) = pages.first() {
        book.cover = Some(json!({ "path": first }));
    }
    if zip.entries.iter().any(crate::plugin::ZipEntry::is_encrypted) {
        book.format.insert("encrypted_entries".into(), json!(true));
    }
    let Some(Ok(xml)) = zip.read_text(src, "ComicInfo.xml", cx, 4 << 20) else { return Ok(()) };
    let fields = values(
        &xml,
        cx,
        &[
            "Title",
            "Series",
            "Number",
            "Count",
            "Volume",
            "Summary",
            "Notes",
            "Year",
            "Month",
            "Day",
            "Writer",
            "Penciller",
            "Inker",
            "Colorist",
            "Letterer",
            "CoverArtist",
            "Editor",
            "Translator",
            "Publisher",
            "Imprint",
            "Genre",
            "Tags",
            "Web",
            "PageCount",
            "LanguageISO",
            "Format",
            "AgeRating",
            "Manga",
            "Characters",
            "Teams",
            "Locations",
            "StoryArc",
            "GTIN",
        ],
    )?;
    let mut date = (None, None, None);
    let mut info = crate::plugin::Map::new();
    for (name, _, v) in fields {
        if v.is_empty() {
            continue;
        }
        info.insert(name.clone(), json!(truncate_chars(&v, 2000)));
        match name.as_str() {
            "Title" => book.title = Some(truncate_chars(&v, 500)),
            "Series" => book.series = Some((v.clone(), book.series.take().and_then(|s| s.1))),
            "Number" => {
                let name = book.series.take().map(|s| s.0).unwrap_or_default();
                book.series = Some((name, Some(v.clone())));
            }
            "Summary" => book.description = Some(truncate_chars(&v, 10_000)),
            "Year" => date.0 = v.parse::<u16>().ok(),
            "Month" => date.1 = v.parse::<u8>().ok(),
            "Day" => date.2 = v.parse::<u8>().ok(),
            "Writer" | "Penciller" | "Inker" | "Colorist" | "Letterer" | "CoverArtist" | "Editor" | "Translator" => {
                let role = match name.as_str() {
                    "Writer" => "aut",
                    "Penciller" => "art",
                    "Inker" => "ink",
                    "Colorist" => "clr",
                    "Letterer" => "ltr",
                    "CoverArtist" => "cov",
                    "Editor" => "edt",
                    _ => "trl",
                };
                for person in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    book.creator(person, role);
                }
            }
            "Publisher" => book.publisher = Some(truncate_chars(&v, 300)),
            "Genre" | "Tags" => {
                for g in v.split(',').map(str::trim).filter(|g| !g.is_empty()).take(50) {
                    book.subjects.push(g.to_string());
                }
            }
            "LanguageISO" => book.language = Some(v.clone()),
            "GTIN" => book.identifier("gtin", &v),
            _ => {}
        }
    }
    if book.series.as_ref().is_some_and(|s| s.0.is_empty()) {
        book.series = None;
    }
    if let (Some(y), m, d) = date {
        book.published = Some(match (m, d) {
            (Some(m), Some(d)) => format!("{y:04}-{m:02}-{d:02}"),
            (Some(m), None) => format!("{y:04}-{m:02}"),
            _ => format!("{y:04}"),
        });
    }
    cx.metadata("comicinfo").extend(info);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_comic_info() {
        let info = br"<ComicInfo><Title>The Lamp</Title><Series>Saltmere Light</Series><Number>3</Number>
<Writer>Ana Lighthouse</Writer><Penciller>Ben Gull</Penciller><Year>2024</Year><Month>5</Month><LanguageISO>en</LanguageISO></ComicInfo>";
        let data = crate::plugin::testing::zip(&[
            ("ComicInfo.xml", info, true),
            ("002.png", b"\x89PNG", false),
            ("001.png", b"\x89PNG", false),
        ]);
        let r = crate::plugin::testing::report_for("lamp.cbz", &data);
        assert_eq!(r.identification.format, "cbz");
        assert_eq!(r.content.title.as_deref(), Some("The Lamp"));
        assert_eq!(r.content.authors, ["Ana Lighthouse"]);
        assert_eq!(r.physical.document.as_ref().and_then(|d| d.pages), Some(2));
        let f = &r.format["cbz"];
        assert_eq!(f["series"]["name"], "Saltmere Light");
        assert_eq!(f["series"]["index"], "3");
        assert_eq!(f["cover"]["path"], "001.png");
    }
}
