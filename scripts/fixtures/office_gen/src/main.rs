//! Office fixtures written by third-party Rust writers:
//!
//! * `xlsx/harbour-dues-xlsxwriter.xlsx`: rust_xlsxwriter (properties, two
//!   sheets one of them hidden, formulas, a defined name, a note, a link)
//! * `xlsx/berths-simple.xlsx`: simple_excel_writer (no document properties)
//! * `docx/notice-docxrs.docx`: docx-rs (headings, a table, a link, a comment,
//!   a custom property)
//! * `pptx/briefing-pptrs.pptx`: ppt-rs (title slide, bullets, speaker notes)
//!
//! Usage: `office_gen <tests/fixtures>`. The writers stamp the current time,
//! so `documents.sh` pins the dates afterwards. Everything is fictitious
//! (Saltmere, `*.example`).

use std::error::Error;
use std::path::{Path, PathBuf};

type Res = Result<(), Box<dyn Error>>;

fn main() -> Res {
    let fx = PathBuf::from(std::env::args().nth(1).ok_or("usage: office_gen <tests/fixtures>")?);
    xlsxwriter(&fx.join("xlsx/harbour-dues-xlsxwriter.xlsx"))?;
    simple_xlsx(&fx.join("xlsx/berths-simple.xlsx"))?;
    docx(&fx.join("docx/notice-docxrs.docx"))?;
    pptx(&fx.join("pptx/briefing-pptrs.pptx"))?;
    Ok(())
}

fn xlsxwriter(path: &Path) -> Res {
    use rust_xlsxwriter::{DocProperties, ExcelDateTime, Format, Note, Url, Workbook};

    let mut wb = Workbook::new();
    let created = ExcelDateTime::from_ymd(2024, 4, 1)?.and_hms(9, 30, 0)?;
    wb.set_properties(
        &DocProperties::new()
            .set_title("Harbour dues 2024")
            .set_subject("Mooring and berthing fees")
            .set_author("Mira Castell")
            .set_manager("Ana Lighthouse")
            .set_company("Example Ferries")
            .set_category("Tariffs")
            .set_keywords("harbour, dues, Saltmere")
            .set_comment("Draft for the harbour board")
            .set_creation_datetime(&created),
    );
    let bold = Format::new().set_bold();
    let money = Format::new().set_num_format("0.00");

    let ws = wb.add_worksheet().set_name("Dues")?;
    ws.write_string_with_format(0, 0, "Vessel class", &bold)?;
    ws.write_string_with_format(0, 1, "Per night", &bold)?;
    for (row, (class, fee)) in [("Dinghy", 4.5), ("Yacht under 10 m", 18.0), ("Ferry", 120.0)].into_iter().enumerate() {
        let row = u32::try_from(row)? + 1;
        ws.write_string(row, 0, class)?;
        ws.write_number_with_format(row, 1, fee, &money)?;
    }
    ws.write_string_with_format(4, 0, "Total", &bold)?;
    ws.write_formula(4, 1, "=SUM(B2:B4)")?;
    ws.insert_note(3, 1, &Note::new("Ferries pay per call, not per night.").set_author("Ana Lighthouse"))?;
    ws.write_url_with_text(6, 0, Url::new("https://harbour.example/dues"), "Published tariff")?;

    let notes = wb.add_worksheet().set_name("Workings")?;
    notes.write_string(0, 0, "Rates follow the 2023 board minutes.")?;
    notes.set_hidden(true);

    wb.define_name("Total_dues", "=Dues!$B$5")?;
    wb.save(path)?;
    Ok(())
}

fn simple_xlsx(path: &Path) -> Res {
    use simple_excel_writer::{Column, Row, Workbook, row};

    let mut wb = Workbook::create(path.to_str().ok_or("path")?);
    let mut sheet = wb.create_sheet("Berths");
    sheet.add_column(Column { width: 12.0 });
    sheet.add_column(Column { width: 18.0 });
    wb.write_sheet(&mut sheet, |w| {
        w.append_row(row!["Berth", "Max draught (m)", "Dries"])?;
        w.append_row(row![3.0, 1.8, true])?;
        w.append_row(row![5.0, 4.5, false])?;
        w.append_row(row!["Quay", 6.0, false])
    })?;
    wb.close()?;
    Ok(())
}

fn docx(path: &Path) -> Res {
    use docx_rs::{
        Comment, Docx, Hyperlink, HyperlinkType, Paragraph, Run, Style, StyleType, Table, TableCell, TableRow,
    };

    let text = |s: &str| Paragraph::new().add_run(Run::new().add_text(s));
    let cell = |s: &str| TableCell::new().add_paragraph(text(s));
    let heading = |s: &str, style: &str| Paragraph::new().add_run(Run::new().add_text(s)).style(style);
    let doc = Docx::new()
        .add_style(Style::new("Heading1", StyleType::Paragraph).name("Heading 1").bold().size(32))
        .add_style(Style::new("Heading2", StyleType::Paragraph).name("Heading 2").bold().size(26))
        .add_paragraph(heading("Notice to mariners", "Heading1"))
        .add_paragraph(text("Berth 3 dries at low water from 1 May. Use berth 5 for vessels over 1.5 m draught."))
        .add_paragraph(heading("Berths", "Heading2"))
        .add_table(Table::new(vec![
            TableRow::new(vec![cell("Berth"), cell("Max draught (m)")]),
            TableRow::new(vec![cell("3"), cell("1.8")]),
            TableRow::new(vec![cell("5"), cell("4.5")]),
        ]))
        .add_paragraph(
            Paragraph::new().add_run(Run::new().add_text("Tide tables: ")).add_hyperlink(
                Hyperlink::new("https://harbour.example/tides", HyperlinkType::External)
                    .add_run(Run::new().add_text("harbour.example/tides")),
            ),
        )
        .add_paragraph(
            Paragraph::new()
                .add_comment_start(
                    Comment::new(1)
                        .author("Ana Lighthouse")
                        .date("2024-04-02T10:00:00Z")
                        .add_paragraph(text("Confirm the date with the harbour board.")),
                )
                .add_run(Run::new().add_text("Issued by the Saltmere harbour office."))
                .add_comment_end(1),
        )
        .custom_property("Notice number", "2024-07")
        .created_at("2024-04-01T09:00:00Z")
        .updated_at("2024-04-02T10:00:00Z");
    doc.build().pack(std::fs::File::create(path)?)?;
    Ok(())
}

fn pptx(path: &Path) -> Res {
    use ppt_rs::{SlideContent, SlideLayout, create_pptx_with_content};

    let slides = vec![
        SlideContent::new("Saltmere ferry briefing").layout(SlideLayout::TitleOnly),
        SlideContent::new("Summer timetable")
            .add_bullet("First sailing 06:40")
            .add_bullet("Extra evening crossing on Fridays")
            .add_bullet("Berth 3 closed at low water")
            .notes("Mention the Friday crossing starts in June."),
        SlideContent::new("Contacts").add_bullet("Harbour office: harbour.example"),
    ];
    std::fs::write(path, create_pptx_with_content("Saltmere ferry briefing", slides)?)?;
    Ok(())
}
