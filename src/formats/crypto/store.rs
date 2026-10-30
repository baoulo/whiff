//! Key stores, described from their unencrypted parts: Java KeyStores
//! (JKS / JCEKS: entries with alias, type, date and the certificate's
//! facts), Kerberos keytabs (principals, encryption types, key versions,
//! timestamps; the keys are skipped) and KeePass databases (version,
//! cipher, compression, key derivation and its cost; KeePass 1 also the
//! group and entry counts). Nothing is decrypted.
//!
//! Specifications: OpenJDK `sun.security.provider.JavaKeyStore` and
//! `com.sun.crypto.provider.JceKeyStore`; MIT Kerberos `keytab.txt`;
//! KeePass "KDBX 4" and the KeePass 1.x source (`PwStructs.h`).

use serde_json::{Map, Value, json};

use super::{check_strength, comment, hex, unix_time};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der,
};

/// Extractor for key stores.
pub struct Store;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.store",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "jks",
            name: "Java KeyStore",
            family: "crypto",
            mimes: &["application/x-java-keystore"],
            extensions: &["jks", "keystore", "ks", "truststore"],
            magic: &[Magic::prefix(b"\xfe\xed\xfe\xed")],
            parent: None,
        },
        FormatSpec {
            id: "jceks",
            name: "Java JCE KeyStore",
            family: "crypto",
            mimes: &["application/x-java-jce-keystore"],
            extensions: &["jceks"],
            magic: &[Magic::prefix(b"\xce\xce\xce\xce")],
            parent: None,
        },
        FormatSpec {
            id: "keytab",
            name: "Kerberos keytab",
            family: "crypto",
            mimes: &["application/x-kerberos-keytab"],
            extensions: &["keytab"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "kdbx",
            name: "KeePass 2 database",
            family: "crypto",
            mimes: &["application/x-keepass2"],
            extensions: &["kdbx"],
            magic: &[Magic::prefix(b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5")],
            parent: None,
        },
        FormatSpec {
            id: "kdb",
            name: "KeePass 1 database",
            family: "crypto",
            mimes: &["application/x-keepass"],
            extensions: &["kdb"],
            magic: &[Magic::prefix(b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5")],
            parent: None,
        },
    ],
};

/// Entries described in full.
const MAX_ENTRIES: usize = 256;
/// Entries walked.
const MAX_WALK: usize = 100_000;

struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }

    fn be(&mut self, n: usize) -> Option<u64> {
        Some(self.take(n)?.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }

    fn le(&mut self, n: usize) -> Option<u64> {
        Some(self.take(n)?.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }
}

impl Extractor for Store {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Keytabs start 05 01 / 05 02: confirm with the first entry.
        let h = probe.head;
        if h.len() < 16 || h[0] != 5 || !matches!(h[1], 1 | 2) {
            return None;
        }
        let mut c = Cur { b: h, at: 2 };
        let size = i32::try_from(c.be(4)?).ok()?;
        let components = c.be(2)?;
        let realm = c.be(2)?;
        (size > 0 && (1..16).contains(&components) && (1..256).contains(&realm))
            .then_some(Sniff { format: "keytab", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        match cx.format_id() {
            "jks" | "jceks" => java(&b, cx),
            "keytab" => keytab(&b, cx),
            "kdb" => kdb(&b, cx),
            _ => kdbx(&b, cx),
        }
    }
}

/// JKS / JCEKS: version, then entries (private key, trusted certificate,
/// secret key), then a keyed SHA-1 over the whole.
fn java(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("keystore header");
    let mut c = Cur { b, at: 4 };
    let version = c.be(4).ok_or_else(bad)?;
    let count = c.be(4).ok_or_else(bad)?;
    cx.format_set("version", version);
    cx.format_set("entries", count);
    let mut entries = Vec::new();
    let mut types = Map::new();
    let mut complete = true;
    for i in 0..count.min(MAX_WALK as u64) {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let Some(e) = java_entry(&mut c, version, cx) else {
            complete = false;
            break;
        };
        let kind = e.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        let n = types.get(&kind).and_then(Value::as_u64).unwrap_or(0);
        types.insert(kind.clone(), (n + 1).into());
        if kind == "secret_key" {
            // A serialised Java object of unknown length follows.
            if entries.len() < MAX_ENTRIES {
                entries.push(Value::Object(e));
            }
            complete = i + 1 == count;
            break;
        }
        if entries.len() < MAX_ENTRIES {
            entries.push(Value::Object(e));
        }
    }
    if !complete {
        cx.warn("the keystore entries could not all be read");
    }
    if types.contains_key("private_key") || types.contains_key("secret_key") {
        cx.security().encrypted(true);
    }
    cx.format_set("entry_types", Value::Object(types));
    cx.format_set("entry_list", entries);
    Ok(())
}

fn java_entry(c: &mut Cur<'_>, version: u64, cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let tag = c.be(4)?;
    let n = usize::try_from(c.be(2)?).ok()?;
    let alias = super::mutf8(c.take(n)?);
    let created = c.be(8)?;
    let mut m = Map::new();
    m.insert("alias".into(), comment(cx, &alias).into());
    if let Some(t) = i64::try_from(created / 1000).ok().and_then(unix_time) {
        m.insert("created".into(), t.into());
    }
    let cert = |c: &mut Cur<'_>| -> Option<Vec<u8>> {
        if version == 2 {
            let n = usize::try_from(c.be(2)?).ok()?;
            c.take(n)?;
        }
        let n = usize::try_from(c.be(4)?).ok()?;
        Some(c.take(n)?.to_vec())
    };
    match tag {
        1 => {
            m.insert("type".into(), "private_key".into());
            let n = usize::try_from(c.be(4)?).ok()?;
            let key = c.take(n)?;
            // EncryptedPrivateKeyInfo: only its protection algorithm.
            if let Some(alg) = der::read(key).and_then(|(k, _)| k.child(0)).and_then(|a| a.child(0)) {
                let name = match der::oid(alg.body).as_str() {
                    "1.3.6.1.4.1.42.2.17.1.1" => "jks_proprietary".to_string(),
                    "1.3.6.1.4.1.42.2.19.1" => "jceks_pbe_md5_3des".to_string(),
                    _ => der::named(alg.body),
                };
                m.insert("protection".into(), name.into());
            }
            let chain = c.be(4)?;
            m.insert("chain_length".into(), chain.into());
            for i in 0..chain.min(16) {
                let der = cert(c)?;
                if i == 0 {
                    certificate(&der, &mut m, cx);
                }
            }
        }
        2 => {
            m.insert("type".into(), "trusted_certificate".into());
            let der = cert(c)?;
            certificate(&der, &mut m, cx);
        }
        3 => {
            m.insert("type".into(), "secret_key".into());
        }
        _ => return None,
    }
    Some(m)
}

/// The facts of an entry's certificate that identify it.
fn certificate(der: &[u8], m: &mut Map<String, Value>, cx: &mut Context<'_>) {
    let Some(c) = der::certificate(der) else { return };
    let mut out = Map::new();
    for k in
        ["subject", "issuer", "not_after", "key_algorithm", "key_bits", "key_curve", "signature_algorithm", "sha256"]
    {
        if let Some(v) = c.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    if let Some(t) = c.get("not_after").and_then(Value::as_str) {
        out.insert("expired".into(), super::is_past(t).into());
    }
    let alg = c.get("key_algorithm").and_then(Value::as_str).unwrap_or("");
    let bits = c.get("key_bits").and_then(Value::as_u64);
    check_strength(cx, "keystore certificate", alg, bits);
    m.insert("certificate".into(), Value::Object(out));
}

fn enctype(id: u64) -> String {
    match id {
        1 => "des-cbc-crc",
        2 => "des-cbc-md4",
        3 => "des-cbc-md5",
        16 => "des3-cbc-sha1",
        17 => "aes128-cts-hmac-sha1-96",
        18 => "aes256-cts-hmac-sha1-96",
        19 => "aes128-cts-hmac-sha256-128",
        20 => "aes256-cts-hmac-sha384-192",
        23 => "arcfour-hmac",
        24 => "arcfour-hmac-exp",
        25 => "camellia128-cts-cmac",
        26 => "camellia256-cts-cmac",
        _ => return format!("enctype-{id}"),
    }
    .to_string()
}

/// A keytab: entries of principal, timestamp, key version and key.
fn keytab(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let version = *b.get(1).ok_or_else(|| ExtractError::malformed("keytab header"))?;
    cx.format_set("version", version);
    let mut c = Cur { b, at: 2 };
    let (mut entries, mut principals, mut enctypes) = (0u64, Vec::<String>::new(), Map::new());
    let (mut first, mut last, mut kvno) = (u64::MAX, 0u64, 0u64);
    let mut weak = Vec::new();
    while c.at + 4 <= b.len() && entries < MAX_WALK as u64 {
        let Some(size) = c.be(4) else { break };
        let size = i64::from(i32::from_be_bytes(u32::try_from(size).unwrap_or(0).to_be_bytes()));
        if size == 0 {
            break;
        }
        let len = usize::try_from(size.unsigned_abs()).unwrap_or(usize::MAX);
        let Some(rec) = c.take(len) else {
            cx.warn("the last keytab entry is cut short");
            break;
        };
        if size < 0 {
            continue; // a hole left by a deleted entry
        }
        let Some(e) = keytab_entry(rec, version) else {
            cx.warn("a keytab entry could not be read");
            continue;
        };
        entries += 1;
        if !principals.contains(&e.principal) && principals.len() < MAX_ENTRIES {
            principals.push(e.principal);
        }
        let name = enctype(e.enctype);
        if matches!(e.enctype, 1..=3 | 23 | 24) && !weak.contains(&name) {
            weak.push(name.clone());
        }
        let n = enctypes.get(&name).and_then(Value::as_u64).unwrap_or(0);
        enctypes.insert(name, (n + 1).into());
        first = first.min(e.timestamp);
        last = last.max(e.timestamp);
        kvno = kvno.max(e.kvno);
    }
    if entries == 0 {
        return Err(ExtractError::malformed("no keytab entry"));
    }
    cx.format_set("entries", entries);
    // Service principals (`HTTP/host@REALM`) name machines; a user's
    // principal is personal data, so strict privacy keeps its realm only.
    let shown: Vec<String> = principals
        .iter()
        .map(|p| match p.rsplit_once('@') {
            Some((user, realm)) if cx.privacy_strict() && !user.contains('/') => format!("[redacted:user]@{realm}"),
            _ => p.clone(),
        })
        .collect();
    cx.format_set("principals", shown);
    cx.format_set("encryption_types", Value::Object(enctypes));
    cx.format_set("max_kvno", kvno);
    if let Some(t) = i64::try_from(first).ok().and_then(unix_time) {
        cx.format_set("oldest_entry", t);
    }
    if let Some(t) = i64::try_from(last).ok().and_then(unix_time) {
        cx.format_set("newest_entry", t);
    }
    // A keytab holds long-term keys in the clear.
    cx.security().risk("unprotected_key", Some("keytab".into()));
    if !weak.is_empty() {
        cx.security().risk("weak_cryptography", Some(format!("keytab: {}", weak.join(", "))));
    }
    Ok(())
}

struct KeytabEntry {
    principal: String,
    timestamp: u64,
    kvno: u64,
    enctype: u64,
}

fn keytab_entry(rec: &[u8], version: u8) -> Option<KeytabEntry> {
    let mut c = Cur { b: rec, at: 0 };
    let mut n = c.be(2)?;
    if version == 1 {
        n = n.checked_sub(1)?;
    }
    let text = |c: &mut Cur<'_>| -> Option<String> {
        let l = usize::try_from(c.be(2)?).ok()?;
        Some(String::from_utf8_lossy(c.take(l)?).into_owned())
    };
    let realm = text(&mut c)?;
    let mut parts = Vec::new();
    for _ in 0..n.min(16) {
        parts.push(text(&mut c)?);
    }
    if version == 2 {
        c.be(4)?; // name type
    }
    let timestamp = c.be(4)?;
    let mut kvno = c.be(1)?;
    let enctype = c.be(2)?;
    let key_len = usize::try_from(c.be(2)?).ok()?;
    c.take(key_len)?; // the key, skipped
    if let Some(v) = c.be(4).filter(|&v| v != 0) {
        kvno = v;
    }
    Some(KeytabEntry { principal: format!("{}@{realm}", parts.join("/")), timestamp, kvno, enctype })
}

fn uuid_name(u: &[u8]) -> String {
    match hex(u).as_str() {
        "31c1f2e6bf714350be5805216afc5aff" => "aes256".into(),
        "d6038a2b8b6f4cb5a524339a31dbb59a" => "chacha20".into(),
        "ad68f29f576f4bb9a36ad47af965346c" => "twofish".into(),
        "c9d9f39a628a4460bf740d08c18a4fea" => "aes_kdf".into(),
        "ef636ddf8c29444b91f7a9a403e30a0c" => "argon2d".into(),
        "9e298b1956db4773b23dfc3ec6f0a1e6" => "argon2id".into(),
        h => h.to_string(),
    }
}

/// KDBX 2–4: the outer header's fields (TLV), KDF parameters as a
/// variant dictionary in version 4.
fn kdbx(data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("KDBX header");
    let mut c = Cur { b: data, at: 8 };
    let minor = c.le(2).ok_or_else(bad)?;
    let major = c.le(2).ok_or_else(bad)?;
    cx.format_set("version", format!("{major}.{minor}"));
    cx.security().encrypted(true);
    let width = if major >= 4 { 4 } else { 2 };
    let mut kdf = Map::new();
    for _ in 0..64 {
        let Some(id) = c.be(1) else { break };
        let Some(n) = c.le(width).and_then(|n| usize::try_from(n).ok()) else { break };
        let Some(v) = c.take(n) else {
            cx.warn("the KDBX header is cut short");
            break;
        };
        match id {
            0 => break,
            2 => cx.format_set("cipher", uuid_name(v)),
            3 => {
                let z = v.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
                cx.format_set("compression", if z == 1 { "gzip" } else { "none" });
            }
            6 => {
                kdf.insert("algorithm".into(), "aes_kdf".into());
                kdf.insert("rounds".into(), v.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)).into());
            }
            11 => variant_dictionary(v, &mut kdf),
            _ => {}
        }
    }
    if !kdf.is_empty() {
        cx.format_set("kdf", Value::Object(kdf));
    }
    Ok(())
}

fn variant_dictionary(v: &[u8], kdf: &mut Map<String, Value>) {
    let mut c = Cur { b: v, at: 2 };
    while let Some(t) = c.be(1).filter(|&t| t != 0) {
        let Some(name) = c.le(4).and_then(|n| c.take(usize::try_from(n).ok()?)) else { return };
        let Some(val) = c.le(4).and_then(|n| c.take(usize::try_from(n).ok()?)) else { return };
        let num = || val.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x));
        let key = match name {
            b"$UUID" => {
                kdf.insert("algorithm".into(), uuid_name(val).into());
                continue;
            }
            b"R" => "rounds",
            b"I" => "iterations",
            b"M" => "memory",
            b"P" => "parallelism",
            b"V" => "argon2_version",
            _ => continue,
        };
        if matches!(t, 0x04 | 0x05 | 0x0c | 0x0d) {
            kdf.insert(key.into(), num().into());
        }
    }
}

/// KeePass 1: a fixed header with the cipher flags, counts and rounds.
fn kdb(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut c = Cur { b, at: 8 };
    let bad = || ExtractError::malformed("KDB header");
    let flags = c.le(4).ok_or_else(bad)?;
    let version = c.le(4).ok_or_else(bad)?;
    c.take(32).ok_or_else(bad)?;
    let groups = c.le(4).ok_or_else(bad)?;
    let entries = c.le(4).ok_or_else(bad)?;
    c.take(64).ok_or_else(bad)?;
    let rounds = c.le(4).ok_or_else(bad)?;
    cx.format_set("version", format!("{}.{}", version >> 16, version & 0xffff));
    cx.format_set("cipher", if flags & 8 != 0 { "twofish" } else { "aes256" });
    cx.format_set("kdf", json!({ "algorithm": "aes_kdf", "rounds": rounds }));
    cx.format_set("groups", groups);
    cx.format_set("entries", entries);
    cx.security().encrypted(true);
    Ok(())
}

crate::register_extractor!(Store);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn fmt(r: &crate::plugin::Report) -> &Value {
        &r.format[&r.identification.format]
    }

    fn keytab_bytes() -> Vec<u8> {
        let s = |t: &str| [u16::try_from(t.len()).unwrap().to_be_bytes().to_vec(), t.as_bytes().to_vec()].concat();
        let entry = [
            2u16.to_be_bytes().to_vec(),
            s("HARBOUR.TEST"),
            s("HTTP"),
            s("tides.harbour.test"),
            1u32.to_be_bytes().to_vec(),
            1_700_000_000u32.to_be_bytes().to_vec(),
            vec![3],
            23u16.to_be_bytes().to_vec(),
            16u16.to_be_bytes().to_vec(),
            vec![0x5c; 16],
            3u32.to_be_bytes().to_vec(),
        ]
        .concat();
        let mut b = vec![5, 2];
        b.extend(u32::try_from(entry.len()).unwrap().to_be_bytes());
        b.extend(entry);
        b
    }

    #[test]
    fn keytab_principals_and_enctypes_without_keys() {
        let r = report_for("krb5.keytab", &keytab_bytes());
        assert_eq!(r.identification.format, "keytab");
        assert_eq!(fmt(&r)["principals"][0], "HTTP/tides.harbour.test@HARBOUR.TEST");
        assert_eq!(fmt(&r)["encryption_types"]["arcfour-hmac"], 1);
        assert_eq!(fmt(&r)["max_kvno"], 3);
        let kinds: Vec<&str> = r.security.risks.iter().map(|x| x.kind.as_str()).collect();
        assert_eq!(kinds, ["unprotected_key", "weak_cryptography"]);
        assert!(!serde_json::to_string(&r).unwrap().contains("5c5c"));
    }

    #[test]
    fn kdbx4_kdf_parameters() {
        let mut vd = vec![0, 1];
        let mut item = |t: u8, k: &[u8], v: &[u8]| {
            vd.push(t);
            vd.extend(u32::try_from(k.len()).unwrap().to_le_bytes());
            vd.extend_from_slice(k);
            vd.extend(u32::try_from(v.len()).unwrap().to_le_bytes());
            vd.extend_from_slice(v);
        };
        let argon2id = [0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6];
        item(0x42, b"$UUID", &argon2id);
        item(0x05, b"I", &2u64.to_le_bytes());
        item(0x05, b"M", &(64u64 << 20).to_le_bytes());
        item(0x04, b"P", &2u32.to_le_bytes());
        vd.push(0);
        let mut b = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5".to_vec();
        b.extend([1, 0, 4, 0]);
        let field = |b: &mut Vec<u8>, id: u8, v: &[u8]| {
            b.push(id);
            b.extend(u32::try_from(v.len()).unwrap().to_le_bytes());
            b.extend_from_slice(v);
        };
        field(
            &mut b,
            2,
            &[0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a],
        );
        field(&mut b, 3, &1u32.to_le_bytes());
        field(&mut b, 11, &vd);
        field(&mut b, 0, b"\r\n\r\n");
        let r = report_for("vault.kdbx", &b);
        assert_eq!(fmt(&r)["version"], "4.1");
        assert_eq!(fmt(&r)["cipher"], "chacha20");
        assert_eq!(
            fmt(&r)["kdf"],
            json!({ "algorithm": "argon2id", "iterations": 2, "memory": 67_108_864, "parallelism": 2 })
        );
    }

    crate::fixture_tests!("jks", "jceks", "keytab", "kdbx", "kdb");
}
