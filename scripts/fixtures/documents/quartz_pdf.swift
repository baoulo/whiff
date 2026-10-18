// Usage: quartz_pdf <out.pdf> <key-bits: 0|40|128> — writes a small plain PDF with Core Graphics.
import CoreGraphics
import CoreText
import Foundation

let args = CommandLine.arguments
let out = URL(fileURLWithPath: args[1])
let bits = Int(args[2]) ?? 0
var box = CGRect(x: 0, y: 0, width: 595, height: 842)
var info: [CFString: Any] = [
    kCGPDFContextTitle: "Lighthouse keeper's log",
    kCGPDFContextAuthor: "Ana Lighthouse",
    kCGPDFContextSubject: "Weekly log of the Saltmere light",
    kCGPDFContextCreator: "whiff fixtures",
    kCGPDFContextKeywords: ["lighthouse", "log"],
]
if bits > 0 {
    info[kCGPDFContextOwnerPassword] = "keeper"
    info[kCGPDFContextUserPassword] = ""
    info[kCGPDFContextEncryptionKeyLength] = bits
    info[kCGPDFContextAllowsCopying] = false
}
guard let ctx = CGContext(out as CFURL, mediaBox: &box, info as CFDictionary) else { exit(1) }
let lines = [
    "Lighthouse keeper's log",
    "Monday: lamp lit at 18:02, fog signal sounded for two hours.",
    "Tuesday: lens cleaned; visibility twelve miles.",
]
ctx.beginPDFPage(nil)
var y: CGFloat = 780
for (i, line) in lines.enumerated() {
    let font = CTFontCreateWithName((i == 0 ? "Helvetica-Bold" : "Helvetica") as CFString, i == 0 ? 20 : 12, nil)
    let attr = NSAttributedString(string: line, attributes: [NSAttributedString.Key(kCTFontAttributeName as String): font])
    let ct = CTLineCreateWithAttributedString(attr)
    ctx.textPosition = CGPoint(x: 72, y: y)
    CTLineDraw(ct, ctx)
    y -= i == 0 ? 32 : 18
}
ctx.endPDFPage()
ctx.closePDF()
