//! ASN.1 DER (and the BER indefinite lengths Apple's code signatures use),
//! X.509 certificates and CMS `SignedData`, read far enough to describe a
//! signature: who signed (subject, issuer, serial, validity, key and
//! signature algorithms, extended key usage, SHA-256 fingerprint), with
//! which digest, when (signing time, RFC 3161 or legacy countersignature
//! timestamps) and the chain that came with it. Signatures are described,
//! never verified, and key material is never returned.
//!
//! Specifications: ITU-T X.690 (BER / DER), RFC 5280 (X.509), RFC 5652
//! (CMS), RFC 3161 (time-stamp tokens).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Deepest nesting followed (certificates nest about ten levels).
const MAX_DEPTH: usize = 32;
/// Most certificates described from one `SignedData`.
const MAX_CERTIFICATES: usize = 16;

/// One ASN.1 element.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The identifier octet (class, constructed bit, tag number).
    pub tag: u8,
    /// The contents, without the end-of-contents octets of an indefinite length.
    pub body: &'a [u8],
    /// The whole element, header included.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// The elements inside a constructed element.
    pub fn children(&self) -> Children<'a> {
        Children { rest: self.body, depth: 0 }
    }

    /// The `n`-th element inside.
    pub fn child(&self, n: usize) -> Option<Tlv<'a>> {
        self.children().nth(n)
    }

    /// Context-specific tag `[n]`, primitive or constructed.
    pub fn is_context(&self, n: u8) -> bool {
        self.tag & 0xdf == 0x80 | n
    }
}

/// The elements of a constructed element, in order.
pub struct Children<'a> {
    rest: &'a [u8],
    depth: usize,
}

impl<'a> Iterator for Children<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        let (t, rest) = read_at_depth(self.rest, self.depth)?;
        self.rest = rest;
        Some(t)
    }
}

/// The first element of `data` and what follows it.
pub fn read(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    read_at_depth(data, 0)
}

fn read_at_depth(data: &[u8], depth: usize) -> Option<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let &tag = data.first()?;
    // High tag numbers (`0x1f`) do not occur in what whiff reads.
    if tag & 0x1f == 0x1f || tag == 0 {
        return None;
    }
    let &first = data.get(1)?;
    let (len, header) = match first {
        0x80 => {
            // Indefinite length (BER): constructed only, ends with 00 00.
            if tag & 0x20 == 0 {
                return None;
            }
            let mut rest = &data[2..];
            while !rest.starts_with(&[0, 0]) {
                rest = read_at_depth(rest, depth + 1)?.1;
            }
            let body_len = data.len() - 2 - rest.len();
            let raw = &data[..body_len + 4];
            return Some((Tlv { tag, body: &data[2..2 + body_len], raw }, &rest[2..]));
        }
        n if n < 0x80 => (usize::from(n), 2),
        n => {
            let count = usize::from(n & 0x7f);
            if count > 4 {
                return None;
            }
            let bytes = data.get(2..2 + count)?;
            (bytes.iter().fold(0usize, |a, &b| a << 8 | usize::from(b)), 2 + count)
        }
    };
    let end = header.checked_add(len)?;
    let raw = data.get(..end)?;
    Some((Tlv { tag, body: &raw[header..], raw }, &data[end..]))
}

/// An object identifier in dotted form.
pub fn oid(body: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v = 0u64;
    for &b in body {
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.extend([first, v - first * 40]);
            } else {
                parts.push(v);
            }
            v = 0;
        }
        if parts.len() > 32 {
            break;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// The well-known name of an algorithm, attribute or usage OID.
pub fn oid_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "1.2.840.113549.1.1.1" => "rsa",
        "1.2.840.10045.2.1" => "ec",
        "1.2.840.10040.4.1" => "dsa",
        "1.3.101.112" => "ed25519",
        "1.3.101.113" => "ed448",
        "1.2.840.113549.1.1.4" => "md5_rsa",
        "1.2.840.113549.1.1.5" => "sha1_rsa",
        "1.2.840.113549.1.1.10" => "rsa_pss",
        "1.2.840.113549.1.1.11" => "sha256_rsa",
        "1.2.840.113549.1.1.12" => "sha384_rsa",
        "1.2.840.113549.1.1.13" => "sha512_rsa",
        "1.2.840.10045.4.1" => "sha1_ecdsa",
        "1.2.840.10045.4.3.2" => "sha256_ecdsa",
        "1.2.840.10045.4.3.3" => "sha384_ecdsa",
        "1.2.840.10045.4.3.4" => "sha512_ecdsa",
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.6.1.5.5.7.3.1" => "server_auth",
        "1.3.6.1.5.5.7.3.2" => "client_auth",
        "1.3.6.1.5.5.7.3.3" => "code_signing",
        "1.3.6.1.5.5.7.3.4" => "email_protection",
        "1.3.6.1.5.5.7.3.8" => "time_stamping",
        "1.3.6.1.5.5.7.3.9" => "ocsp_signing",
        "1.3.6.1.4.1.311.10.3.6" => "windows_system_component",
        "1.3.6.1.4.1.311.61.1.1" => "kernel_mode_code_signing",
        "1.2.840.113635.100.4.13" => "apple_package_signing",
        "1.2.840.113549.1.7.1" => "data",
        "1.2.840.113549.1.7.2" => "signed_data",
        "1.3.6.1.4.1.311.2.1.4" => "authenticode",
        "1.2.840.113549.1.9.16.1.4" => "tst_info",
        _ => return None,
    })
}

fn named(oid_body: &[u8]) -> String {
    let o = oid(oid_body);
    oid_name(&o).map_or(o, str::to_string)
}

/// An X.509 `Name` as `CN=…, O=…, C=…` (most specific first). E-mail
/// address attributes are left out.
pub fn name(t: Tlv<'_>) -> String {
    let mut parts = Vec::new();
    for rdn in t.children() {
        for atv in rdn.children() {
            let (Some(k), Some(v)) = (atv.child(0), atv.child(1)) else { continue };
            let k = oid(k.body);
            if k == "1.2.840.113549.1.9.1" {
                continue;
            }
            let key = oid_name(&k).map_or(k, str::to_string);
            parts.push(format!("{key}={}", string(v)));
        }
    }
    parts.reverse();
    parts.join(", ")
}

/// The value of a directory string (UTF-8, printable, IA5, BMP, T61).
pub fn string(t: Tlv<'_>) -> String {
    match t.tag {
        0x1e => {
            let units: Vec<u16> = t.body.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        0x14 => t.body.iter().map(|&b| char::from(b)).collect(),
        _ => String::from_utf8_lossy(t.body).into_owned(),
    }
}

fn attribute<'a>(name: Tlv<'a>, wanted: &str) -> Option<Tlv<'a>> {
    name.children()
        .flat_map(|rdn| rdn.children())
        .find(|atv| atv.child(0).is_some_and(|k| oid(k.body) == wanted))
        .and_then(|atv| atv.child(1))
}

/// A UTCTime or GeneralizedTime as an RFC 3339 time.
pub fn time(t: Tlv<'_>) -> Option<String> {
    let s = std::str::from_utf8(t.body).ok()?;
    let s = s.strip_suffix('Z').unwrap_or(s);
    let s = s.split('.').next()?;
    let full = match (t.tag, s.len()) {
        (0x17, 12) => {
            let yy: u32 = s[..2].parse().ok()?;
            format!("{}{s}", if yy >= 50 { "19" } else { "20" })
        }
        (0x18, 14) => s.to_string(),
        _ => return None,
    };
    if !full.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let f = |a: usize, b: usize| &full[a..b];
    Some(format!("{}-{}-{}T{}:{}:{}Z", f(0, 4), f(4, 6), f(6, 8), f(8, 10), f(10, 12), f(12, 14)))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// An INTEGER's value as hex, without the sign padding.
fn serial(t: Tlv<'_>) -> String {
    let b = t.body;
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len().saturating_sub(1));
    hex(&b[start..])
}

/// A certificate's facts. `None` when `der` is not a certificate.
pub fn certificate(der: &[u8]) -> Option<Map<String, Value>> {
    let (cert, _) = read(der)?;
    let tbs = cert.child(0)?;
    let sig_alg = cert.child(1)?.child(0)?;
    let mut fields = tbs.children().peekable();
    // `[0] EXPLICIT version` is optional (v1 certificates).
    let version = match fields.peek() {
        Some(t) if t.is_context(0) => {
            fields.next().and_then(|v| v.child(0)).map_or(1, |v| v.body.last().map_or(1, |&n| i64::from(n) + 1))
        }
        _ => 1,
    };
    let serial_number = fields.next()?;
    let _signature = fields.next()?;
    let issuer = fields.next()?;
    let validity = fields.next()?;
    let subject = fields.next()?;
    let spki = fields.next()?;
    let mut out = Map::new();
    out.insert("subject".into(), name(subject).into());
    if let Some(cn) = attribute(subject, "2.5.4.3") {
        out.insert("subject_cn".into(), string(cn).into());
    }
    if let Some(o) = attribute(subject, "2.5.4.10") {
        out.insert("subject_organization".into(), string(o).into());
    }
    out.insert("issuer".into(), name(issuer).into());
    out.insert("serial".into(), serial(serial_number).into());
    out.insert("version".into(), version.into());
    if let Some(t) = validity.child(0).and_then(time) {
        out.insert("not_before".into(), t.into());
    }
    if let Some(t) = validity.child(1).and_then(time) {
        out.insert("not_after".into(), t.into());
    }
    if let Some((alg, bits)) = public_key(spki) {
        out.insert("key_algorithm".into(), alg.into());
        if let Some(bits) = bits {
            out.insert("key_bits".into(), bits.into());
        }
    }
    out.insert("signature_algorithm".into(), named(sig_alg.body).into());
    out.insert("self_signed".into(), (issuer.raw == subject.raw).into());
    for t in fields {
        if t.is_context(3)
            && let Some(exts) = t.child(0)
        {
            extensions(exts, &mut out);
        }
    }
    out.insert("sha256".into(), hex(&Sha256::digest(cert.raw)).into());
    Some(out)
}

/// The algorithm and size of a `SubjectPublicKeyInfo` (the key itself is
/// not kept).
fn public_key(spki: Tlv<'_>) -> Option<(String, Option<u64>)> {
    let alg = spki.child(0)?;
    let kind = named(alg.child(0)?.body);
    let bits = match kind.as_str() {
        "rsa" => {
            let key = spki.child(1)?.body.get(1..)?;
            let modulus = read(key)?.0.child(0)?.body;
            let m = &modulus[modulus.iter().position(|&b| b != 0).unwrap_or(modulus.len())..];
            m.first().map(|&top| (m.len() as u64 - 1) * 8 + u64::from(8 - top.leading_zeros()))
        }
        "ec" => match alg.child(1).map(|c| named(c.body)).as_deref() {
            Some("P-256") => Some(256),
            Some("P-384") => Some(384),
            Some("P-521") => Some(521),
            _ => None,
        },
        "ed25519" => Some(256),
        "ed448" => Some(456),
        _ => None,
    };
    Some((kind, bits))
}

fn extensions(exts: Tlv<'_>, out: &mut Map<String, Value>) {
    for ext in exts.children() {
        let Some(id) = ext.child(0).map(|o| oid(o.body)) else { continue };
        // `critical BOOLEAN DEFAULT FALSE` may come before the value.
        let Some(value) = ext.children().find(|c| c.tag == 0x04).and_then(|v| read(v.body)).map(|v| v.0) else {
            continue;
        };
        match id.as_str() {
            "2.5.29.19" => {
                let ca = value.child(0).is_some_and(|b| b.tag == 0x01 && b.body.first().is_some_and(|&v| v != 0));
                out.insert("ca".into(), ca.into());
            }
            "2.5.29.37" => {
                let usages: Vec<Value> = value.children().map(|o| named(o.body).into()).collect();
                out.insert("extended_key_usage".into(), usages.into());
            }
            "2.5.29.17" => {
                let names: Vec<Value> = value
                    .children()
                    .filter(|n| n.tag == 0x82 || n.tag == 0x86)
                    .take(32)
                    .map(|n| String::from_utf8_lossy(n.body).into_owned().into())
                    .collect();
                if !names.is_empty() {
                    out.insert("subject_alt_names".into(), names.into());
                }
            }
            _ => {}
        }
    }
}

/// What a CMS `SignedData` says about its signature.
#[derive(Debug, Default)]
pub struct Signed {
    /// The type of the signed content (`authenticode`, `data` …).
    pub content_type: String,
    /// The signed content (`eContent`), when it is inside.
    pub content: Option<Vec<u8>>,
    /// Digest algorithms of the signers.
    pub digests: Vec<String>,
    /// The certificates that came with the signature.
    pub certificates: Vec<Map<String, Value>>,
    /// Index in `certificates` of the (first) signer's certificate.
    pub signer: Option<usize>,
    /// The signing time the signer claims.
    pub signing_time: Option<String>,
    /// The time a timestamp authority vouches for.
    pub timestamp: Option<String>,
    /// Signer infos in the envelope.
    pub signers: usize,
}

impl Signed {
    /// The facts as a JSON object: digest, signer (certificate facts),
    /// times, the chain's subjects.
    pub fn facts(&self) -> Map<String, Value> {
        let mut out = Map::new();
        if !self.digests.is_empty() {
            out.insert("digest".into(), self.digests.join(", ").into());
        }
        if let Some(s) = self.signer.and_then(|i| self.certificates.get(i)) {
            out.insert("signer".into(), Value::Object(s.clone()));
        }
        if let Some(t) = &self.signing_time {
            out.insert("signing_time".into(), t.clone().into());
        }
        if let Some(t) = &self.timestamp {
            out.insert("timestamp".into(), t.clone().into());
        }
        out.insert("timestamped".into(), self.timestamp.is_some().into());
        let chain: Vec<Value> = self.certificates.iter().filter_map(|c| c.get("subject").cloned()).collect();
        if !chain.is_empty() {
            out.insert("certificates".into(), json!(chain));
        }
        if self.signers > 1 {
            out.insert("signers".into(), self.signers.into());
        }
        out
    }
}

/// Read a CMS `ContentInfo` holding `SignedData`.
pub fn signed_data(der: &[u8]) -> Option<Signed> {
    let (ci, _) = read(der)?;
    if oid(ci.child(0)?.body) != "1.2.840.113549.1.7.2" {
        return None;
    }
    let sd = ci.child(1)?.child(0)?;
    let mut parts = sd.children();
    let _version = parts.next()?;
    let digest_algs = parts.next()?;
    let encap = parts.next()?;
    let mut s = Signed {
        content_type: encap.child(0).map(|o| named(o.body)).unwrap_or_default(),
        content: encap.child(1).and_then(|c| c.child(0)).map(|c| c.body.to_vec()),
        digests: digest_algs.children().filter_map(|a| a.child(0)).map(|o| named(o.body)).collect(),
        ..Signed::default()
    };
    let mut raw_certs: Vec<(Tlv<'_>, Map<String, Value>)> = Vec::new();
    for part in parts {
        if part.is_context(0) {
            for c in part.children().filter(|c| c.tag == 0x30).take(MAX_CERTIFICATES) {
                if let Some(facts) = certificate(c.raw) {
                    raw_certs.push((c, facts));
                }
            }
        } else if part.tag == 0x31 {
            for (i, si) in part.children().enumerate() {
                s.signers += 1;
                if i == 0 {
                    signer_info(si, &raw_certs, &mut s);
                }
            }
        }
    }
    s.certificates = raw_certs.into_iter().map(|(_, f)| f).collect();
    Some(s)
}

fn signer_info(si: Tlv<'_>, certs: &[(Tlv<'_>, Map<String, Value>)], s: &mut Signed) {
    let mut parts = si.children().skip(1);
    let Some(sid) = parts.next() else { return };
    if sid.tag == 0x30
        && let (Some(issuer), Some(serial)) = (sid.child(0), sid.child(1))
    {
        s.signer = certs.iter().position(|(c, _)| {
            c.child(0).is_some_and(|tbs| {
                let mut f = tbs.children().skip_while(|t| t.is_context(0));
                let cs = f.next();
                let ci = f.nth(1);
                cs.is_some_and(|x| x.body == serial.body) && ci.is_some_and(|x| x.raw == issuer.raw)
            })
        });
    }
    for part in parts {
        if part.is_context(0) {
            for attr in part.children() {
                let Some(id) = attr.child(0).map(|o| oid(o.body)) else { continue };
                if id == "1.2.840.113549.1.9.5" {
                    s.signing_time = attr.child(1).and_then(|v| v.child(0)).and_then(time);
                }
            }
        } else if part.is_context(1) {
            for attr in part.children() {
                let Some(id) = attr.child(0).map(|o| oid(o.body)) else { continue };
                let Some(value) = attr.child(1).and_then(|v| v.child(0)) else { continue };
                match id.as_str() {
                    // RFC 3161 token (Authenticode, Apple): a SignedData over TSTInfo.
                    "1.3.6.1.4.1.311.3.3.1" | "1.2.840.113549.1.9.16.2.14" => {
                        s.timestamp = signed_data(value.raw).and_then(|t| t.content).and_then(|c| {
                            let tst = read(&c)?.0;
                            tst.children().find(|f| f.tag == 0x18).and_then(time)
                        });
                    }
                    // Legacy countersignature: a SignerInfo with a signing time.
                    "1.2.840.113549.1.9.6" => {
                        let mut counter = Signed::default();
                        signer_info(value, &[], &mut counter);
                        s.timestamp = counter.signing_time;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 0x80 {
            v.push(u8::try_from(body.len()).unwrap());
        } else {
            v.push(0x82);
            v.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn lengths_and_oids() {
        let (t, rest) = read(&[0x30, 0x03, 0x02, 0x01, 0x05, 0xff]).unwrap();
        assert_eq!((t.tag, t.body, rest), (0x30, &[0x02, 0x01, 0x05][..], &[0xff][..]));
        // Indefinite length.
        let (t, rest) = read(&[0x30, 0x80, 0x02, 0x01, 0x05, 0, 0, 0xee]).unwrap();
        assert_eq!((t.child(0).unwrap().body, rest), (&[5][..], &[0xee][..]));
        assert!(read(&[0x30, 0x05, 0x00]).is_none());
        assert_eq!(oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), "1.2.840.113549.1.1.11");
    }

    #[test]
    fn times() {
        let utc = read(b"\x17\x0d250901120000Z").unwrap().0;
        assert_eq!(time(utc).as_deref(), Some("2025-09-01T12:00:00Z"));
        let generalized = read(b"\x18\x0f20491231235959Z").unwrap().0;
        assert_eq!(time(generalized).as_deref(), Some("2049-12-31T23:59:59Z"));
    }

    #[test]
    fn names_skip_email() {
        let atv = |oid: &[u8], v: &str| tlv(0x31, &tlv(0x30, &[tlv(0x06, oid), tlv(0x0c, v.as_bytes())].concat()));
        let n = tlv(
            0x30,
            &[
                atv(&[0x55, 0x04, 0x06], "GB"),
                atv(&[0x55, 0x04, 0x03], "Saltmere Harbour"),
                atv(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01], "x@example.org"),
            ]
            .concat(),
        );
        assert_eq!(name(read(&n).unwrap().0), "CN=Saltmere Harbour, C=GB");
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut v = vec![5u8, 0];
        for _ in 0..40 {
            v = tlv(0x30, &v);
        }
        let (t, _) = read(&v).unwrap();
        let mut depth = 0;
        let mut cur = Some(t);
        while let Some(c) = cur {
            depth += 1;
            cur = c.child(0);
        }
        assert!(depth > 30);
        assert!(certificate(&v).is_none() && signed_data(&v).is_none());
    }
}
