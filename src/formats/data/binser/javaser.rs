//! Java object serialization streams (`ObjectOutputStream`, `AC ED 00 05`),
//! walked through the stream grammar without instantiating anything:
//! top-level contents, the classes described (name, serialVersionUID
//! count, fields), objects, arrays, strings, enum constants, and the
//! classes of known deserialization gadget chains (Commons Collections
//! transformers, `TemplatesImpl`, `AnnotationInvocationHandler` …), which
//! are flagged.
//!
//! Specification: Java Object Serialization Specification, chapter 6
//! ("Object Serialization Stream Protocol"), version 17.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::Walk;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole, truncate_chars,
};

/// Extractor for Java serialization streams.
pub struct JavaSerialized;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.java_serialized",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "java_serialized",
        name: "Java serialized object",
        family: "data.binser",
        mimes: &["application/x-java-serialized-object"],
        extensions: &["ser"],
        magic: &[Magic::at(0, b"\xac\xed\x00\x05")],
        parent: None,
    }],
};

/// Classes listed.
const MAX_CLASSES: usize = 200;
/// Handles kept.
const MAX_HANDLES: usize = 1 << 20;

/// Classes (or class-name prefixes) used by known gadget chains (ysoserial).
const GADGETS: [&str; 22] = [
    "org.apache.commons.collections.functors.InvokerTransformer",
    "org.apache.commons.collections.functors.ChainedTransformer",
    "org.apache.commons.collections.functors.InstantiateTransformer",
    "org.apache.commons.collections.keyvalue.TiedMapEntry",
    "org.apache.commons.collections.map.LazyMap",
    "org.apache.commons.collections4.functors.InvokerTransformer",
    "org.apache.commons.collections4.functors.ChainedTransformer",
    "org.apache.commons.collections4.functors.InstantiateTransformer",
    "org.apache.commons.beanutils.BeanComparator",
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "org.apache.xalan.xsltc.trax.TemplatesImpl",
    "sun.reflect.annotation.AnnotationInvocationHandler",
    "org.codehaus.groovy.runtime.ConvertedClosure",
    "org.codehaus.groovy.runtime.MethodClosure",
    "org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler",
    "org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider",
    "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
    "org.hibernate.engine.spi.TypedValue",
    "com.sun.syndication.feed.impl.ObjectBean",
    "com.rometools.rome.feed.impl.ObjectBean",
    "bsh.XThis",
    "clojure.core$comp",
];

/// A class description: name, flags, fields (type code, class name), super.
#[derive(Clone, Default)]
struct Desc {
    name: String,
    flags: u8,
    fields: Vec<(u8, String)>,
    sup: Option<usize>,
}

/// What a handle refers to.
#[derive(Clone)]
enum Handle {
    Desc(usize),
    Str(String),
    Other,
}

struct Stream<'a> {
    b: &'a [u8],
    at: usize,
    handles: Vec<Handle>,
    descs: Vec<Desc>,
    objects: u64,
    arrays: u64,
    strings: u64,
    enums: BTreeMap<String, u64>,
    w: Walk,
}

type R<T> = Result<T, &'static str>;

impl<'a> Stream<'a> {
    fn u8(&mut self) -> R<u8> {
        let v = *self.b.get(self.at).ok_or("truncated")?;
        self.at += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("truncated")?;
        let s = self.b.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(s)
    }

    fn be(&mut self, n: usize) -> R<u64> {
        Ok(self.take(n)?.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn utf(&mut self, long: bool) -> R<String> {
        let n = usize::try_from(self.be(if long { 8 } else { 2 })?).map_err(|_| "length too large")?;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn new_handle(&mut self, h: Handle) -> usize {
        if self.handles.len() < MAX_HANDLES {
            self.handles.push(h);
        }
        self.handles.len() - 1
    }

    fn handle(&mut self) -> R<Handle> {
        let h = self.be(4)?;
        let i = h.checked_sub(0x7e_0000).and_then(|i| usize::try_from(i).ok()).ok_or("bad handle")?;
        self.handles.get(i).cloned().ok_or("unknown handle")
    }

    /// `classDesc`: a new description, a proxy, null or a reference.
    fn class_desc(&mut self) -> R<Option<usize>> {
        self.w.enter()?;
        let r = match self.u8()? {
            0x70 => None,
            0x71 => match self.handle()? {
                Handle::Desc(d) => Some(d),
                _ => return Err("reference is not a class description"),
            },
            0x72 => {
                let name = self.utf(false)?;
                self.be(8)?; // serialVersionUID
                let id = self.descs.len();
                self.descs.push(Desc { name: name.clone(), ..Desc::default() });
                self.new_handle(Handle::Desc(id));
                let flags = self.u8()?;
                let n = self.be(2)?;
                let mut fields = Vec::new();
                for _ in 0..n {
                    let ty = self.u8()?;
                    let _field = self.utf(false)?;
                    let class = if ty == b'L' || ty == b'[' {
                        match self.content()? {
                            Some(Value::String(s)) => s,
                            _ => String::new(),
                        }
                    } else {
                        String::new()
                    };
                    fields.push((ty, class));
                }
                self.annotation()?;
                let sup = self.class_desc()?;
                self.descs[id] = Desc { name, flags, fields, sup };
                Some(id)
            }
            0x7d => {
                let n = self.be(4)?;
                let id = self.descs.len();
                self.descs.push(Desc { name: "java.lang.reflect.Proxy".into(), flags: 2, ..Desc::default() });
                self.new_handle(Handle::Desc(id));
                for _ in 0..n.min(1 << 16) {
                    let iface = self.utf(false)?;
                    self.w.tag(format!("proxy:{iface}"));
                }
                self.annotation()?;
                let sup = self.class_desc()?;
                self.descs[id].sup = sup;
                Some(id)
            }
            _ => return Err("expected a class description"),
        };
        self.w.leave();
        Ok(r)
    }

    /// Contents up to `TC_ENDBLOCKDATA`.
    fn annotation(&mut self) -> R<()> {
        loop {
            match self.peek().ok_or("truncated")? {
                0x78 => {
                    self.at += 1;
                    return Ok(());
                }
                _ => {
                    self.content()?;
                }
            }
        }
    }

    /// The value of a field of type `ty`.
    fn field(&mut self, ty: u8) -> R<()> {
        let n = match ty {
            b'B' | b'Z' => 1,
            b'C' | b'S' => 2,
            b'I' | b'F' => 4,
            b'J' | b'D' => 8,
            b'L' | b'[' => {
                self.content()?;
                return Ok(());
            }
            _ => return Err("bad field type"),
        };
        self.take(n)?;
        Ok(())
    }

    /// One content item; strings come back as their value.
    fn content(&mut self) -> R<Option<Value>> {
        self.w.value()?;
        let tc = self.u8()?;
        Ok(match tc {
            0x70 => None,
            0x71 => match self.handle()? {
                Handle::Str(s) => Some(Value::String(s)),
                _ => None,
            },
            0x74 | 0x7c => {
                let s = self.utf(tc == 0x7c)?;
                self.strings += 1;
                self.w.string(&s);
                self.new_handle(Handle::Str(s.clone()));
                Some(Value::String(s))
            }
            0x77 => {
                let n = usize::from(self.u8()?);
                self.take(n)?;
                None
            }
            0x7a => {
                let n = usize::try_from(self.be(4)?).map_err(|_| "bad length")?;
                self.take(n)?;
                None
            }
            0x76 => {
                self.class_desc()?;
                self.new_handle(Handle::Other);
                None
            }
            0x79 => {
                self.handles.clear();
                None
            }
            0x72 | 0x7d => {
                self.at -= 1;
                self.class_desc()?;
                None
            }
            0x7e => {
                let d = self.class_desc()?;
                self.new_handle(Handle::Other);
                let constant = self.content()?;
                let class = d.map(|d| self.descs[d].name.clone()).unwrap_or_default();
                let c = constant.and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                *self.enums.entry(format!("{class}.{c}")).or_default() += 1;
                None
            }
            0x75 => {
                let d = self.class_desc()?;
                self.new_handle(Handle::Other);
                self.arrays += 1;
                let n = usize::try_from(self.be(4)?).map_err(|_| "bad array length")?;
                let name = d.map(|d| self.descs[d].name.clone()).unwrap_or_default();
                let ty = name.as_bytes().get(1).copied().unwrap_or(b'L');
                if n > self.b.len() - self.at {
                    return Err("truncated");
                }
                self.w.enter()?;
                for _ in 0..n {
                    self.field(ty)?;
                }
                self.w.leave();
                None
            }
            0x73 => {
                let d = self.class_desc()?.ok_or("object without a class")?;
                self.new_handle(Handle::Other);
                self.objects += 1;
                // Class data from the topmost superclass down.
                let mut chain = vec![d];
                while let Some(s) = self.descs[*chain.last().unwrap_or(&d)].sup {
                    if chain.len() > 64 || chain.contains(&s) {
                        return Err("class hierarchy too deep");
                    }
                    chain.push(s);
                }
                self.w.enter()?;
                for &c in chain.iter().rev() {
                    let desc = self.descs[c].clone();
                    if desc.flags & 0x04 != 0 {
                        // Externalizable: block data (protocol 2) or opaque (1).
                        if desc.flags & 0x08 == 0 {
                            return Err("protocol 1 externalizable data");
                        }
                        self.annotation()?;
                        continue;
                    }
                    for (ty, _) in &desc.fields {
                        self.field(*ty)?;
                    }
                    if desc.flags & 0x01 != 0 {
                        self.annotation()?;
                    }
                }
                self.w.leave();
                None
            }
            0x7b => return Err("exception in stream"),
            _ => return Err("unknown type code"),
        })
    }
}

impl Extractor for JavaSerialized {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let mut s = Stream {
            b: &data,
            at: 4,
            handles: Vec::new(),
            descs: Vec::new(),
            objects: 0,
            arrays: 0,
            strings: 0,
            enums: BTreeMap::new(),
            w: Walk::default(),
        };
        let mut top: Vec<String> = Vec::new();
        let mut items = 0u64;
        while s.at < data.len() {
            let tc = data[s.at];
            let descs_before = s.descs.len();
            match s.content() {
                Ok(_) => {
                    items += 1;
                    if top.len() < 20 {
                        let what = match tc {
                            0x73 | 0x75 | 0x7e => {
                                s.descs.get(descs_before).map_or_else(|| "object".into(), |d| d.name.clone())
                            }
                            0x74 | 0x7c => "string".into(),
                            0x77 | 0x7a => "block_data".into(),
                            0x70 => "null".into(),
                            _ => "other".into(),
                        };
                        top.push(what);
                    }
                }
                Err(e) => {
                    cx.format_set("decode_error", e);
                    break;
                }
            }
        }
        cx.format_set("contents", items);
        if !top.is_empty() {
            cx.format_set("top_level", top);
        }
        cx.format_set("objects", s.objects);
        cx.format_set("arrays", s.arrays);
        cx.format_set("strings", s.strings);
        let mut classes: Vec<&str> = Vec::new();
        for d in &s.descs {
            if !classes.contains(&d.name.as_str()) {
                classes.push(&d.name);
            }
        }
        cx.format_set("class_count", classes.len());
        if !classes.is_empty() {
            let shown: Vec<String> = classes.iter().take(MAX_CLASSES).map(|c| truncate_chars(c, 200)).collect();
            cx.format_set("classes", shown);
        }
        if !s.enums.is_empty() {
            let m: Map<String, Value> =
                s.enums.iter().take(50).map(|(k, n)| (truncate_chars(k, 200), (*n).into())).collect();
            cx.format_set("enum_constants", Value::Object(m));
        }
        let proxies: Vec<&String> = s.w.tags.keys().filter(|k| k.starts_with("proxy:")).collect();
        if !proxies.is_empty() {
            let p: Vec<&str> = proxies.iter().map(|k| &k[6..]).collect();
            cx.format_set("proxy_interfaces", p);
        }
        let gadgets: Vec<&str> =
            GADGETS.into_iter().filter(|g| classes.iter().any(|c| c == g || c.starts_with(&format!("{g}$")))).collect();
        if !gadgets.is_empty() {
            cx.security().risk("unsafe_deserialization", Some(gadgets.join(", ")));
        }
        if !s.w.text.is_empty() {
            cx.emit_text(TextRole::Data, &s.w.text);
        }
        Ok(())
    }
}

crate::register_extractor!(JavaSerialized);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    /// `new java.util.Date(0)` would be large; this is a hand-built object
    /// of class `Tide` with one int field, then a string.
    fn stream(class: &str) -> Vec<u8> {
        let mut b = b"\xac\xed\x00\x05\x73\x72".to_vec();
        b.extend(u16::try_from(class.len()).unwrap().to_be_bytes());
        b.extend(class.as_bytes());
        b.extend([0u8; 8]); // serialVersionUID
        b.push(0x02); // SC_SERIALIZABLE
        b.extend(1u16.to_be_bytes());
        b.push(b'I');
        b.extend(2u16.to_be_bytes());
        b.extend(b"ht");
        b.push(0x78); // end of class annotation
        b.push(0x70); // no superclass
        b.extend(612i32.to_be_bytes());
        b.push(0x74);
        b.extend(4u16.to_be_bytes());
        b.extend(b"high");
        b
    }

    #[test]
    fn objects_and_strings() {
        let r = report_for("x.ser", &stream("Tide"));
        let f = &r.format["java_serialized"];
        assert_eq!((f["objects"].as_u64(), f["strings"].as_u64(), f["contents"].as_u64()), (Some(1), Some(1), Some(2)));
        assert_eq!(f["classes"][0], "Tide");
        assert!(f.get("decode_error").is_none(), "{f}");
    }

    #[test]
    fn gadget_classes_are_flagged() {
        let r = report_for("x.ser", &stream("org.apache.commons.collections.functors.InvokerTransformer"));
        assert!(r.security.risks.iter().any(|r| r.kind == "unsafe_deserialization"));
    }

    crate::fixture_tests!("java_serialized");
}
