//! Word field codes (`HYPERLINK`, `DDEAUTO`, `INCLUDEPICTURE` …), shared by
//! the OOXML, legacy Word and RTF extractors.

/// The field's code word, upper-cased (`HYPERLINK`), if any.
pub(crate) fn code(instr: &str) -> Option<String> {
    instr.split_whitespace().next().map(str::to_ascii_uppercase)
}

/// The risk a field code carries: `dde` for DDE fields (they can run a
/// program when updated), `external_content` for includes from a URL or a
/// UNC path.
pub(crate) fn risk(instr: &str) -> Option<&'static str> {
    match code(instr)?.as_str() {
        "DDE" | "DDEAUTO" => Some("dde"),
        "INCLUDETEXT" | "INCLUDEPICTURE" | "LINK" | "IMPORT"
            if instr.to_ascii_lowercase().contains("http") || instr.contains("\\\\") =>
        {
            Some("external_content")
        }
        _ => None,
    }
}

/// The quoted target of a `HYPERLINK` field.
pub(crate) fn hyperlink(instr: &str) -> Option<String> {
    let rest = instr.trim_start().get(9..)?;
    if !instr.trim_start()[..9].eq_ignore_ascii_case("HYPERLINK") {
        return None;
    }
    let rest = rest.trim_start();
    let target = match rest.strip_prefix('"') {
        Some(q) => q.split('"').next()?,
        None => rest.split_whitespace().next()?,
    };
    (!target.is_empty() && !target.starts_with('\\')).then(|| target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_field_codes() {
        assert_eq!(risk(" DDEAUTO server topic "), Some("dde"));
        assert_eq!(risk("INCLUDEPICTURE \"https://img.example.org/logo.png\""), Some("external_content"));
        assert_eq!(risk("INCLUDEPICTURE \"logo.png\""), None);
        assert_eq!(risk("DATE \\@ \"d MMMM yyyy\""), None);
        assert_eq!(hyperlink(" HYPERLINK \"https://example.org/a\" \\o tip"), Some("https://example.org/a".into()));
        assert_eq!(hyperlink("HYPERLINK \\l \"anchor\""), None);
    }
}
