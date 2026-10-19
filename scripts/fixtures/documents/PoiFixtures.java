// Legacy Office fixtures written by Apache POI, so whiff is tested on BIFF8
// workbooks, PowerPoint 97 slide shows and encrypted packages that it did not
// assemble itself. Run by scripts/fixtures/documents.sh:
//
//     java -cp '<poi jars>' PoiFixtures.java <tests/fixtures> <plain.docx>
//
// Everything is fictitious (Saltmere, *.example). The passwords below are
// test values; only the encryption structure is of interest.

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;

import org.apache.poi.common.usermodel.HyperlinkType;
import org.apache.poi.hpsf.DocumentSummaryInformation;
import org.apache.poi.hpsf.SummaryInformation;
import org.apache.poi.hslf.usermodel.HSLFSlide;
import org.apache.poi.hslf.usermodel.HSLFSlideShow;
import org.apache.poi.hslf.usermodel.HSLFTextBox;
import org.apache.poi.hssf.record.crypto.Biff8EncryptionKey;
import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.poifs.crypt.EncryptionInfo;
import org.apache.poi.poifs.crypt.EncryptionMode;
import org.apache.poi.poifs.crypt.Encryptor;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.ss.usermodel.ClientAnchor;
import org.apache.poi.ss.usermodel.Comment;
import org.apache.poi.ss.usermodel.CreationHelper;
import org.apache.poi.ss.usermodel.Drawing;
import org.apache.poi.ss.usermodel.Hyperlink;
import org.apache.poi.ss.usermodel.Name;
import org.apache.poi.ss.usermodel.Row;

public class PoiFixtures {
    // 2024-04-01T09:00:00Z
    static final Date CREATED = new Date(1711962000000L);

    public static void main(String[] args) throws Exception {
        Path fx = Path.of(args[0]);
        Path plainDocx = Path.of(args[1]);
        workbook(fx.resolve("xls/dues-poi.xls"), null);
        workbook(fx.resolve("xls/dues-poi-locked.xls"), "harbourmaster");
        slideShow(fx.resolve("ppt/briefing-poi.ppt"), null);
        slideShow(fx.resolve("ppt/briefing-poi-locked.ppt"), "harbourmaster");
        encrypt(plainDocx, fx.resolve("office_encrypted/notice-agile.docx"), EncryptionMode.agile);
        encrypt(plainDocx, fx.resolve("office_encrypted/notice-standard.docx"), EncryptionMode.standard);
    }

    static void summary(SummaryInformation si, DocumentSummaryInformation dsi, String title) {
        si.setTitle(title);
        si.setSubject("Saltmere harbour");
        si.setAuthor("Mira Castell");
        si.setKeywords("harbour, Saltmere");
        si.setComments("Written by Apache POI for whiff's tests");
        si.setLastAuthor("Ana Lighthouse");
        si.setCreateDateTime(CREATED);
        si.setLastSaveDateTime(CREATED);
        dsi.setCompany("Example Ferries");
        dsi.setManager("Ana Lighthouse");
        dsi.setCategory("Tariffs");
    }

    static void workbook(Path out, String password) throws Exception {
        try (HSSFWorkbook wb = new HSSFWorkbook()) {
            wb.createInformationProperties();
            summary(wb.getSummaryInformation(), wb.getDocumentSummaryInformation(), "Harbour dues 2024");
            CreationHelper help = wb.getCreationHelper();
            HSSFSheet dues = wb.createSheet("Dues");
            String[][] rows = { { "Dinghy", "4.5" }, { "Yacht under 10 m", "18" }, { "Ferry", "120" } };
            Row head = dues.createRow(0);
            head.createCell(0).setCellValue("Vessel class");
            head.createCell(1).setCellValue("Per night");
            for (int i = 0; i < rows.length; i++) {
                Row r = dues.createRow(i + 1);
                r.createCell(0).setCellValue(rows[i][0]);
                r.createCell(1).setCellValue(Double.parseDouble(rows[i][1]));
            }
            Row total = dues.createRow(4);
            total.createCell(0).setCellValue("Total");
            total.createCell(1).setCellFormula("SUM(B2:B4)");
            Drawing<?> drawing = dues.createDrawingPatriarch();
            ClientAnchor anchor = help.createClientAnchor();
            anchor.setCol1(2);
            anchor.setRow1(3);
            anchor.setCol2(5);
            anchor.setRow2(6);
            Comment note = drawing.createCellComment(anchor);
            note.setString(help.createRichTextString("Ferries pay per call, not per night."));
            note.setAuthor("Ana Lighthouse");
            dues.getRow(3).getCell(1).setCellComment(note);
            Hyperlink link = help.createHyperlink(HyperlinkType.URL);
            link.setAddress("https://harbour.example/dues");
            Row lr = dues.createRow(6);
            lr.createCell(0).setCellValue("Published tariff");
            lr.getCell(0).setHyperlink(link);
            HSSFSheet workings = wb.createSheet("Workings");
            workings.createRow(0).createCell(0).setCellValue("Rates follow the 2023 board minutes.");
            wb.setSheetHidden(1, true);
            Name name = wb.createName();
            name.setNameName("Total_dues");
            name.setRefersToFormula("Dues!$B$5");
            Biff8EncryptionKey.setCurrentUserPassword(password);
            try (OutputStream os = new FileOutputStream(out.toFile())) {
                wb.write(os);
            } finally {
                Biff8EncryptionKey.setCurrentUserPassword(null);
            }
        }
    }

    static void slideShow(Path out, String password) throws Exception {
        try (HSLFSlideShow ppt = new HSLFSlideShow()) {
            ppt.createInformationProperties();
            summary(ppt.getSummaryInformation(), ppt.getDocumentSummaryInformation(), "Saltmere ferry briefing");
            String[][] slides = {
                { "Saltmere ferry briefing", "Summer 2024" },
                { "Summer timetable", "First sailing 06:40\rExtra evening crossing on Fridays" },
                { "Contacts", "Harbour office: harbour.example" },
            };
            for (String[] s : slides) {
                HSLFSlide slide = ppt.createSlide();
                slide.addTitle().setText(s[0]);
                HSLFTextBox body = slide.createTextBox();
                body.setText(s[1]);
                body.setAnchor(new java.awt.Rectangle(50, 150, 600, 200));
            }
            Biff8EncryptionKey.setCurrentUserPassword(password);
            try (OutputStream os = new FileOutputStream(out.toFile())) {
                ppt.write(os);
            } finally {
                Biff8EncryptionKey.setCurrentUserPassword(null);
            }
        }
    }

    static void encrypt(Path plain, Path out, EncryptionMode mode) throws Exception {
        try (POIFSFileSystem fs = new POIFSFileSystem()) {
            Encryptor enc = new EncryptionInfo(mode).getEncryptor();
            enc.confirmPassword("harbourmaster");
            try (OutputStream os = enc.getDataStream(fs); InputStream in = Files.newInputStream(plain)) {
                in.transferTo(os);
            }
            try (OutputStream os = new FileOutputStream(out.toFile())) {
                fs.writeFilesystem(os);
            }
        }
    }
}
