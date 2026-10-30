//! FlatBuffers binary schemas (`.bfbs`, written by `flatc --schema -b`):
//! the schema's file identifier and extension, root table, tables and
//! structs, enums and unions, services and the `.fbs` files it came from.
//! (Other FlatBuffers binaries cannot be read without their schema.)
//!
//! Specification: FlatBuffers "Internals" (tables, vtables, offsets) and
//! `reflection/reflection.fbs`.

use serde_json::Value;

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for binary FlatBuffers schemas.
pub struct FlatBuffers;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.flatbuffers",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "bfbs",
        name: "FlatBuffers schema / binary",
        family: "data.binser",
        mimes: &[],
        extensions: &["bfbs"],
        magic: &[Magic::at(4, b"BFBS")],
        parent: None,
    }],
};

/// Names listed per kind.
const MAX_NAMES: usize = 200;

/// A FlatBuffer: tables, vectors and strings by offset.
struct Fb<'a>(&'a [u8]);

impl Fb<'_> {
    fn u32(&self, at: usize) -> Option<usize> {
        usize::try_from(u32::from_le_bytes(self.0.get(at..at + 4)?.try_into().ok()?)).ok()
    }

    fn u16(&self, at: usize) -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(self.0.get(at..at + 2)?.try_into().ok()?)))
    }

    /// Where field `n` of the table at `t` is stored.
    fn field(&self, t: usize, n: usize) -> Option<usize> {
        let soff = i64::from(i32::from_le_bytes(self.0.get(t..t + 4)?.try_into().ok()?));
        let vt = usize::try_from(i64::try_from(t).ok()? - soff).ok()?;
        let vsize = self.u16(vt)?;
        let slot = 4 + 2 * n;
        if slot + 2 > vsize {
            return None;
        }
        let off = self.u16(vt + slot)?;
        (off != 0).then_some(t + off)
    }

    /// Follow the offset stored at `at`.
    fn deref(&self, at: usize) -> Option<usize> {
        at.checked_add(self.u32(at)?)
    }

    fn string(&self, t: usize, n: usize) -> Option<String> {
        let s = self.deref(self.field(t, n)?)?;
        let len = self.u32(s)?;
        Some(String::from_utf8_lossy(self.0.get(s + 4..s.checked_add(4 + len)?)?).into_owned())
    }

    fn bool(&self, t: usize, n: usize) -> bool {
        self.field(t, n).and_then(|at| self.0.get(at)).is_some_and(|&b| b != 0)
    }

    /// The tables of a vector of tables.
    fn tables(&self, t: usize, n: usize) -> Vec<usize> {
        let Some(v) = self.field(t, n).and_then(|at| self.deref(at)) else { return Vec::new() };
        let len = self.u32(v).unwrap_or(0).min(1 << 16);
        (0..len).filter_map(|i| self.deref(v + 4 + 4 * i)).collect()
    }

    fn table(&self, t: usize, n: usize) -> Option<usize> {
        self.deref(self.field(t, n)?)
    }
}

fn names(fb: &Fb<'_>, tables: &[usize]) -> Vec<String> {
    tables.iter().take(MAX_NAMES).filter_map(|&t| fb.string(t, 0)).map(|s| truncate_chars(&s, 200)).collect()
}

impl Extractor for FlatBuffers {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let fb = Fb(&data);
        let root = fb.u32(0).filter(|&r| r < data.len()).ok_or_else(|| ExtractError::malformed("root offset"))?;
        let objects = fb.tables(root, 0);
        let enums = fb.tables(root, 1);
        if let Some(i) = fb.string(root, 2).filter(|s| !s.is_empty()) {
            cx.format_set("file_identifier", truncate_chars(&i, 8));
        }
        if let Some(e) = fb.string(root, 3).filter(|s| !s.is_empty()) {
            cx.format_set("file_extension", truncate_chars(&e, 20));
        }
        if let Some(r) = fb.table(root, 4).and_then(|t| fb.string(t, 0)) {
            cx.format_set("root_table", truncate_chars(&r, 200));
        }
        let structs = objects.iter().filter(|&&o| fb.bool(o, 2)).count();
        cx.format_set("tables", objects.len() - structs);
        cx.format_set("structs", structs);
        let fields: usize = objects.iter().map(|&o| fb.tables(o, 1).len()).sum();
        cx.format_set("fields", fields);
        if !objects.is_empty() {
            cx.format_set("objects", names(&fb, &objects));
        }
        let unions = enums.iter().filter(|&&e| fb.bool(e, 2)).count();
        cx.format_set("enums", enums.len() - unions);
        cx.format_set("unions", unions);
        if !enums.is_empty() {
            cx.format_set("enum_names", names(&fb, &enums));
        }
        let services = fb.tables(root, 5);
        if !services.is_empty() {
            cx.format_set("services", names(&fb, &services));
        }
        let files = fb.tables(root, 7);
        if !files.is_empty() {
            cx.format_set("schema_files", Value::from(names(&fb, &files)));
        }
        Ok(())
    }
}

crate::register_extractor!(FlatBuffers);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_and_strings() {
        // root offset 12 → table at 12: soffset 8 → vtable at 4 (size 6, table 8, field 0 at +4).
        let mut b = vec![12, 0, 0, 0, 6, 0, 8, 0, 4, 0, 0, 0];
        b.extend(8i32.to_le_bytes());
        b.extend(4u32.to_le_bytes()); // field 0 → string at 16 + 4 = 20
        b.extend(4u32.to_le_bytes());
        b.extend(b"Tide");
        let fb = Fb(&b);
        assert_eq!(fb.string(12, 0).as_deref(), Some("Tide"));
        assert_eq!(fb.string(12, 1), None);
    }

    crate::fixture_tests!("bfbs");
}
