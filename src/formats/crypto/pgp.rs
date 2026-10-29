//! OpenPGP, binary or ASCII-armoured, and GnuPG keyboxes: keys
//! (fingerprint and key ID, version, algorithm, size or curve, creation and
//! expiry from the self-signature, usage flags, revocation, user IDs,
//! subkeys; for secret keys how they are protected and whether the key is
//! only a stub), messages (recipients' key IDs, passphrase encryption, the
//! cipher, compression, the literal file name and date, inside zlib / ZIP
//! compression too) and signatures (type, issuer, hash, time). Secret key
//! material is skipped, nothing is decrypted and no signature is verified.
//!
//! Specifications: RFC 9580 (OpenPGP, v6 keys), RFC 4880 (v4) and the
//! LibrePGP draft (v5); GnuPG `kbx/keybox-blob.c` (keybox).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{check_strength, is_past, pem_blocks, unix_time};
use crate::plugin::{
    Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der,
};

/// Extractor for OpenPGP data and GnuPG keyboxes.
pub struct Pgp;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.openpgp",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "openpgp",
            name: "OpenPGP data",
            family: "crypto",
            mimes: &["application/pgp-keys", "application/pgp-encrypted", "application/pgp-signature"],
            extensions: &["asc", "gpg", "pgp", "sig", "key"],
            // Armour and binary packets are both recognised by `sniff`.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "gpg_keybox",
            name: "GnuPG keybox",
            family: "crypto",
            mimes: &["application/x-gnupg-keybox"],
            extensions: &["kbx"],
            magic: &[Magic::at(8, b"KBXf")],
            parent: None,
        },
    ],
};

/// Keys described in full.
const MAX_KEYS: usize = 64;
/// Packets walked.
const MAX_PACKETS: usize = 200_000;
/// Compression layers followed.
const MAX_NESTING: usize = 4;
/// Bytes inflated from a compressed packet.
const MAX_INFLATE: usize = 16 << 20;

/// One packet: tag and body (partial lengths joined).
struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// Split `b` into packets. Stops at the first malformed header.
fn packets(b: &[u8]) -> (Vec<Packet>, bool) {
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() && out.len() < MAX_PACKETS {
        let Some((tag, body, next)) = packet_at(b, at) else { return (out, false) };
        out.push(Packet { tag, body });
        at = next;
    }
    (out, true)
}

fn be(b: &[u8]) -> usize {
    b.iter().fold(0usize, |a, &x| a << 8 | usize::from(x))
}

/// A packet's tag, where its body starts and its length (`None` for
/// partial and indeterminate lengths), from the header alone.
fn header(b: &[u8]) -> Option<(u8, usize, Option<usize>)> {
    let h = *b.first()?;
    if h & 0x80 == 0 {
        return None;
    }
    if h & 0x40 == 0 {
        let start = [2, 3, 5, 1][usize::from(h & 3)];
        let len = (start > 1).then(|| b.get(1..start).map(be)).flatten();
        return Some(((h >> 2) & 0x0f, start, len));
    }
    let l0 = *b.get(1)?;
    let (start, len) = match l0 {
        0..192 => (2, Some(usize::from(l0))),
        192..224 => (3, b.get(2).map(|&l1| ((usize::from(l0) - 192) << 8) + usize::from(l1) + 192)),
        224..255 => (2, None),
        255 => (6, b.get(2..6).map(be)),
    };
    Some((h & 0x3f, start, len))
}

fn packet_at(b: &[u8], at: usize) -> Option<(u8, Vec<u8>, usize)> {
    let h = *b.get(at)?;
    if h & 0x80 == 0 {
        return None;
    }
    if h & 0x40 == 0 {
        // Old format: tag in bits 5–2, length type in bits 1–0.
        let tag = (h >> 2) & 0x0f;
        let (len, hl) = match h & 3 {
            0 => (usize::from(*b.get(at + 1)?), 2),
            1 => (be(b.get(at + 1..at + 3)?), 3),
            2 => (be(b.get(at + 1..at + 5)?), 5),
            _ => (b.len() - at - 1, 1),
        };
        let body = b.get(at + hl..at + hl + len)?;
        return Some((tag, body.to_vec(), at + hl + len));
    }
    let tag = h & 0x3f;
    let mut p = at + 1;
    let mut body = Vec::new();
    loop {
        let l0 = usize::from(*b.get(p)?);
        let (len, hl, partial) = match l0 {
            0..192 => (l0, 1, false),
            192..224 => (((l0 - 192) << 8) + usize::from(*b.get(p + 1)?) + 192, 2, false),
            255 => (be(b.get(p + 1..p + 5)?), 5, false),
            _ => (1 << (l0 & 0x1f), 1, true),
        };
        body.extend_from_slice(b.get(p + hl..p + hl + len)?);
        p += hl + len;
        if !partial {
            return Some((tag, body, p));
        }
    }
}

fn public_algorithm(id: u8) -> &'static str {
    match id {
        1..=3 => "rsa",
        16 | 20 => "elgamal",
        17 => "dsa",
        18 => "ecdh",
        19 => "ecdsa",
        22 => "eddsa",
        25 => "x25519",
        26 => "x448",
        27 => "ed25519",
        28 => "ed448",
        _ => "unknown",
    }
}

fn hash_algorithm(id: u8) -> &'static str {
    match id {
        1 => "md5",
        2 => "sha1",
        3 => "ripemd160",
        8 => "sha256",
        9 => "sha384",
        10 => "sha512",
        11 => "sha224",
        12 => "sha3_256",
        14 => "sha3_512",
        _ => "unknown",
    }
}

fn cipher(id: u8) -> &'static str {
    match id {
        0 => "none",
        1 => "idea",
        2 => "3des",
        3 => "cast5",
        4 => "blowfish",
        7 => "aes128",
        8 => "aes192",
        9 => "aes256",
        10 => "twofish",
        11 => "camellia128",
        12 => "camellia192",
        13 => "camellia256",
        _ => "unknown",
    }
}

fn signature_type(id: u8) -> &'static str {
    match id {
        0x00 => "binary",
        0x01 => "text",
        0x02 => "standalone",
        0x10..=0x13 => "certification",
        0x18 => "subkey_binding",
        0x19 => "primary_key_binding",
        0x1f => "direct_key",
        0x20 => "key_revocation",
        0x28 => "subkey_revocation",
        0x30 => "certification_revocation",
        0x40 => "timestamp",
        0x50 => "third_party_confirmation",
        _ => "unknown",
    }
}

fn curve(oid: &[u8]) -> String {
    let dotted = der::oid(oid);
    match dotted.as_str() {
        "1.3.6.1.4.1.3029.1.5.1" => "cv25519".into(),
        "1.3.6.1.4.1.11591.15.1" => "ed25519".into(),
        "1.3.101.110" => "x25519".into(),
        _ => der::named(oid),
    }
}

/// Upper-case hex, as GnuPG prints fingerprints and key IDs.
fn hex_upper(b: &[u8]) -> String {
    super::hex(b).to_ascii_uppercase()
}

/// A key packet's public facts and the length of its public part.
#[allow(clippy::struct_field_names)] // `key_id` is the OpenPGP term
struct Key {
    version: u8,
    created: u32,
    algorithm: &'static str,
    bits: Option<u64>,
    curve: Option<String>,
    fingerprint: String,
    key_id: String,
    public_len: usize,
}

fn mpi(b: &[u8], at: &mut usize) -> Option<u64> {
    let bits = be(b.get(*at..*at + 2)?) as u64;
    *at += 2 + usize::try_from(bits.div_ceil(8)).ok()?;
    (*at <= b.len()).then_some(bits)
}

fn key(b: &[u8]) -> Option<Key> {
    let version = *b.first()?;
    let created = u32::try_from(be(b.get(1..5)?)).ok()?;
    let mut at = match version {
        3 => 8,
        4 => 6,
        5 | 6 => 10,
        _ => return None,
    };
    let alg_id = *b.get(if version == 3 { 7 } else { 5 })?;
    let algorithm = public_algorithm(alg_id);
    let (mut bits, mut curve_name) = (None, None);
    match alg_id {
        1..=3 => {
            bits = Some(mpi(b, &mut at)?);
            mpi(b, &mut at)?;
        }
        16 | 20 | 17 => {
            bits = Some(mpi(b, &mut at)?);
            for _ in 0..if alg_id == 17 { 3 } else { 2 } {
                mpi(b, &mut at)?;
            }
        }
        18 | 19 | 22 => {
            let n = usize::from(*b.get(at)?);
            let c = curve(b.get(at + 1..at + 1 + n)?);
            at += 1 + n;
            mpi(b, &mut at)?;
            if alg_id == 18 {
                at += 1 + usize::from(*b.get(at)?);
            }
            bits = der::curve_bits(&c).or(match c.as_str() {
                "cv25519" => Some(256),
                _ => None,
            });
            curve_name = Some(c);
        }
        25 | 27 => at += 32,
        26 => at += 56,
        28 => at += 57,
        _ => {
            if version >= 5 {
                at += be(b.get(6..10)?);
            } else {
                return None;
            }
        }
    }
    if version >= 5 {
        // v5 / v6 give the key material length; trust it over our walk.
        at = 10 + be(b.get(6..10)?);
    }
    if matches!(alg_id, 25..=28) {
        bits = der::curve_bits(algorithm);
    }
    let public = b.get(..at)?;
    let (fingerprint, key_id) = match version {
        4 => {
            let mut h = vec![0x99];
            h.extend(u16::try_from(at).ok()?.to_be_bytes());
            h.extend_from_slice(public);
            let fp = der::sha1(&h);
            (hex_upper(&fp), hex_upper(&fp[12..]))
        }
        5 | 6 => {
            let mut h = vec![if version == 6 { 0x9b } else { 0x9a }];
            h.extend(u32::try_from(at).ok()?.to_be_bytes());
            h.extend_from_slice(public);
            let fp = Sha256::digest(&h);
            (hex_upper(&fp), hex_upper(&fp[..8]))
        }
        // v3: the key ID is the low 64 bits of the modulus.
        _ => {
            let n_end = 8 + 2 + usize::try_from(bits?.div_ceil(8)).ok()?;
            (String::new(), hex_upper(b.get(n_end - 8..n_end)?))
        }
    };
    Some(Key { version, created, algorithm, bits, curve: curve_name, fingerprint, key_id, public_len: at })
}

/// How a secret key is protected (`None`: unprotected).
fn secret(b: &[u8], k: &Key) -> Map<String, Value> {
    let mut m = Map::new();
    let mut at = k.public_len;
    let Some(&usage) = b.get(at) else { return m };
    at += 1;
    if k.version == 6 && usage != 0 {
        at += 1; // count of the following fields
    }
    if usage == 0 {
        m.insert("protected".into(), false.into());
        return m;
    }
    m.insert("protected".into(), true.into());
    let Some(&sym) = b.get(at) else { return m };
    if !matches!(usage, 253..=255) {
        m.insert("cipher".into(), cipher(usage).into());
        return m;
    }
    m.insert("cipher".into(), cipher(sym).into());
    at += 1;
    if usage == 253 {
        // AEAD mode, then the S2K.
        m.insert("aead".into(), true.into());
        at += 1;
    }
    if k.version == 6 {
        at += 1; // S2K length
    }
    let Some(&s2k) = b.get(at) else { return m };
    let s2k_name = match s2k {
        0 => "simple",
        1 => "salted",
        3 => "iterated_salted",
        4 => "argon2",
        101 => "gnu",
        _ => "unknown",
    };
    m.insert("s2k".into(), s2k_name.into());
    match s2k {
        1 | 3 => {
            if let Some(&h) = b.get(at + 1) {
                m.insert("hash".into(), hash_algorithm(h).into());
            }
            if s2k == 3
                && let Some(&c) = b.get(at + 10)
            {
                m.insert("iterations".into(), ((16u64 + u64::from(c & 15)) << ((c >> 4) + 6)).into());
            }
        }
        4 => {
            if let Some(&[passes, parallelism, memory_exp]) = b.get(at + 17..at + 20) {
                m.insert(
                    "argon2".into(),
                    json!({ "passes": passes, "parallelism": parallelism, "memory_exp": memory_exp }),
                );
            }
        }
        // GnuPG extension: the secret part is elsewhere.
        101 if b.get(at + 2..at + 5) == Some(b"GNU") => {
            let stub = match b.get(at + 5) {
                Some(1) => "no_secret",
                Some(2) => "smartcard",
                _ => "unknown",
            };
            m.insert("stub".into(), stub.into());
        }
        _ => {}
    }
    m
}

/// A signature's facts: type, algorithms, creation, issuer, and the
/// subpackets that describe the key it binds.
#[derive(Default)]
struct Sig {
    kind: u8,
    algorithm: &'static str,
    hash: &'static str,
    created: Option<u32>,
    issuer: Option<String>,
    key_expires: Option<u32>,
    flags: Option<u8>,
    primary_uid: bool,
}

fn signature(b: &[u8]) -> Option<Sig> {
    let version = *b.first()?;
    let mut s = Sig::default();
    match version {
        3 => {
            s.kind = *b.get(2)?;
            s.created = u32::try_from(be(b.get(3..7)?)).ok();
            s.issuer = Some(hex_upper(b.get(7..15)?));
            s.algorithm = public_algorithm(*b.get(15)?);
            s.hash = hash_algorithm(*b.get(16)?);
        }
        4..=6 => {
            s.kind = *b.get(1)?;
            s.algorithm = public_algorithm(*b.get(2)?);
            s.hash = hash_algorithm(*b.get(3)?);
            let w = if version == 4 { 2 } else { 4 };
            let mut at = 4;
            for _ in 0..2 {
                let n = be(b.get(at..at + w)?);
                subpackets(b.get(at + w..at + w + n)?, &mut s);
                at += w + n;
            }
        }
        _ => return None,
    }
    Some(s)
}

fn subpackets(mut b: &[u8], s: &mut Sig) {
    while let Some(&l0) = b.first() {
        let (len, hl) = match l0 {
            0..192 => (usize::from(l0), 1),
            192..=254 => match b.get(1) {
                Some(&l1) => (((usize::from(l0) - 192) << 8) + usize::from(l1) + 192, 2),
                None => return,
            },
            _ => match b.get(1..5) {
                Some(v) => (be(v), 5),
                None => return,
            },
        };
        let Some(sp) = b.get(hl..hl + len).filter(|sp| !sp.is_empty()) else { return };
        let data = &sp[1..];
        let u32_of = |d: &[u8]| d.get(..4).and_then(|v| u32::try_from(be(v)).ok());
        match sp[0] & 0x7f {
            2 => s.created = u32_of(data),
            9 => s.key_expires = u32_of(data),
            16 if s.issuer.is_none() => s.issuer = Some(hex_upper(data)),
            25 => s.primary_uid = data.first().is_some_and(|&v| v != 0),
            27 => s.flags = data.first().copied(),
            33 if data.len() > 1 => s.issuer = Some(hex_upper(&data[1..])),
            _ => {}
        }
        b = &b[hl + len..];
    }
}

fn usage(flags: u8) -> Vec<&'static str> {
    [
        (0x01, "certify"),
        (0x02, "sign"),
        (0x04, "encrypt_communications"),
        (0x08, "encrypt_storage"),
        (0x20, "authenticate"),
    ]
    .into_iter()
    .filter(|&(bit, _)| flags & bit != 0)
    .map(|(_, n)| n)
    .collect()
}

fn time(t: u32) -> Option<String> {
    unix_time(i64::from(t))
}

/// Everything found, across packets and nested compressed data.
#[derive(Default)]
struct State {
    keys: Vec<Map<String, Value>>,
    /// Facts of the key the next signatures belong to: (index in `keys`,
    /// subkey index or `None` for the primary, creation time).
    current: Option<(usize, Option<usize>, u32)>,
    /// The current primary key's ID: only its own signatures describe it.
    primary_id: Option<String>,
    /// Creation time of the self-signature last applied to `current`: a
    /// newer one (a changed expiry) replaces it.
    bound_at: Option<u32>,
    key_count: u64,
    secret_keys: u64,
    user_ids: u64,
    signatures: Vec<Value>,
    recipients: Vec<Value>,
    passphrase: bool,
    passphrase_cipher: Option<&'static str>,
    encrypted: Option<Map<String, Value>>,
    compression: Vec<&'static str>,
    literal: Option<Map<String, Value>>,
    one_pass: u64,
    weak: Vec<String>,
}

impl State {
    fn target(&mut self) -> Option<&mut Map<String, Value>> {
        let (k, sub, _) = self.current?;
        let primary = self.keys.get_mut(k)?;
        match sub {
            None => Some(primary),
            Some(i) => primary.get_mut("subkeys")?.as_array_mut()?.get_mut(i)?.as_object_mut(),
        }
    }
}

fn key_facts(k: &Key) -> Map<String, Value> {
    let mut m = Map::new();
    if !k.fingerprint.is_empty() {
        m.insert("fingerprint".into(), k.fingerprint.clone().into());
    }
    m.insert("key_id".into(), k.key_id.clone().into());
    m.insert("version".into(), k.version.into());
    m.insert("key_algorithm".into(), k.algorithm.into());
    if let Some(b) = k.bits {
        m.insert("key_bits".into(), b.into());
    }
    if let Some(c) = &k.curve {
        m.insert("key_curve".into(), c.clone().into());
    }
    if let Some(t) = time(k.created) {
        m.insert("created".into(), t.into());
    }
    m
}

#[allow(clippy::too_many_lines)] // one arm per packet type
fn walk(b: &[u8], st: &mut State, depth: usize, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (list, clean) = packets(b);
    if !clean {
        cx.warn("OpenPGP packets end early or are malformed");
    }
    for (i, p) in list.iter().enumerate() {
        if i % 4096 == 4095 {
            cx.checkpoint()?;
        }
        let body = &p.body[..];
        match p.tag {
            5 | 6 | 7 | 14 => {
                let Some(k) = key(body) else {
                    cx.warn("a key packet could not be read");
                    continue;
                };
                let secret_packet = matches!(p.tag, 5 | 7);
                let mut m = key_facts(&k);
                if secret_packet {
                    st.secret_keys += 1;
                    let s = secret(body, &k);
                    if s.get("protected") == Some(&Value::Bool(false)) {
                        cx.security().risk("unprotected_key", Some("openpgp".into()));
                    } else if s.get("protected") == Some(&Value::Bool(true)) && !s.contains_key("stub") {
                        cx.security().encrypted(true);
                    }
                    m.insert("secret".into(), Value::Object(s));
                }
                if !st.weak.contains(&k.key_id) && matches!(k.algorithm, "rsa" | "dsa" | "elgamal") {
                    st.weak.push(k.key_id.clone());
                    check_strength(cx, &format!("OpenPGP key {}", k.key_id), k.algorithm, k.bits);
                }
                if matches!(p.tag, 5 | 6) {
                    st.key_count += 1;
                    if st.keys.len() < MAX_KEYS {
                        st.keys.push(m);
                        st.current = Some((st.keys.len() - 1, None, k.created));
                        st.primary_id = Some(k.key_id.clone());
                        st.bound_at = None;
                    } else {
                        st.current = None;
                    }
                } else if let Some((ki, _, _)) = st.current
                    && let Some(primary) = st.keys.get_mut(ki)
                {
                    let subs = primary.entry("subkeys").or_insert_with(|| Value::Array(Vec::new()));
                    if let Value::Array(a) = subs {
                        a.push(Value::Object(m));
                        st.current = Some((ki, Some(a.len() - 1), k.created));
                        st.bound_at = None;
                    }
                }
            }
            13 => {
                st.user_ids += 1;
                let uid = String::from_utf8_lossy(body);
                let (name, address) = match (uid.find('<'), uid.rfind('>')) {
                    (Some(a), Some(z)) if a < z => (uid[..a].trim().to_string(), Some(uid[a + 1..z].to_string())),
                    _ => (uid.trim().to_string(), None),
                };
                let v = cx.mailbox(Some(&name), address.as_deref());
                if let Some((ki, _, _)) = st.current
                    && let Some(primary) = st.keys.get_mut(ki)
                    && let Value::Array(a) = primary.entry("user_ids").or_insert_with(|| Value::Array(Vec::new()))
                    && a.len() < 32
                {
                    a.push(v);
                }
            }
            2 => {
                let Some(s) = signature(body) else { continue };
                let on_key = matches!(s.kind, 0x10..=0x13 | 0x18 | 0x19 | 0x1f | 0x20 | 0x28 | 0x30);
                if on_key && st.current.is_some() {
                    bind(&s, st);
                } else {
                    let mut m = Map::new();
                    m.insert("type".into(), signature_type(s.kind).into());
                    m.insert("key_algorithm".into(), s.algorithm.into());
                    m.insert("hash".into(), s.hash.into());
                    if let Some(t) = s.created.and_then(time) {
                        m.insert("created".into(), t.into());
                    }
                    if let Some(i) = &s.issuer {
                        m.insert("issuer".into(), i.clone().into());
                    }
                    check_strength(cx, "OpenPGP signature", s.hash, None);
                    cx.security().signed(true);
                    if st.signatures.len() < MAX_KEYS {
                        st.signatures.push(Value::Object(m));
                    }
                }
            }
            1 => {
                // PKESK v3: key ID; v6: fingerprint with its version.
                let id = match body.first() {
                    Some(3) => body.get(1..9).map(hex_upper),
                    Some(6) => body.get(1).and_then(|&n| body.get(3..2 + usize::from(n))).map(hex_upper),
                    _ => None,
                };
                if let Some(id) = id
                    && st.recipients.len() < MAX_KEYS
                {
                    // An all-zero ID is a hidden ("throw-keyids") recipient.
                    let shown = if id.bytes().all(|c| c == b'0') { "hidden".to_string() } else { id };
                    st.recipients.push(shown.into());
                }
            }
            3 => {
                st.passphrase = true;
                st.passphrase_cipher = body.get(1).map(|&c| cipher(c));
            }
            4 => st.one_pass += 1,
            8 => {
                let alg = body.first().copied().unwrap_or(255);
                let name = match alg {
                    0 => "none",
                    1 => "zip",
                    2 => "zlib",
                    3 => "bzip2",
                    _ => "unknown",
                };
                st.compression.push(name);
                let kind = match alg {
                    1 => Some(Compression::Deflate),
                    2 => Some(Compression::Zlib),
                    _ => None,
                };
                if depth < MAX_NESTING
                    && let Some(kind) = kind
                {
                    match cx.inflate_prefix(&body[1..], kind, MAX_INFLATE) {
                        Ok(inner) => walk(&inner, st, depth + 1, cx)?,
                        Err(e) => cx.warn(format!("compressed packet: {e}")),
                    }
                }
            }
            9 | 18 | 20 => {
                let mut m = Map::new();
                m.insert(
                    "packet".into(),
                    match p.tag {
                        9 => "sed",
                        18 => "seipd",
                        _ => "aead",
                    }
                    .into(),
                );
                if p.tag == 18 && body.first() == Some(&2) {
                    m.insert("version".into(), 2.into());
                    if let Some(&c) = body.get(1) {
                        m.insert("cipher".into(), cipher(c).into());
                    }
                }
                if p.tag == 9 {
                    m.insert("integrity_protected".into(), false.into());
                }
                st.encrypted = Some(m);
            }
            11 => {
                let mut m = Map::new();
                let fmt = body.first().copied().unwrap_or(0);
                m.insert("format".into(), char::from(fmt).to_string().into());
                let n = usize::from(body.get(1).copied().unwrap_or(0));
                if let Some(name) = body.get(2..2 + n).filter(|n| !n.is_empty()) {
                    m.insert("file_name".into(), String::from_utf8_lossy(name).into_owned().into());
                }
                if let Some(t) = body.get(2 + n..6 + n).and_then(|v| u32::try_from(be(v)).ok()).and_then(time) {
                    m.insert("date".into(), t.into());
                }
                m.insert("size".into(), body.len().saturating_sub(6 + n).into());
                st.literal = Some(m);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Apply a signature on a key (self-signature, binding, revocation).
fn bind(s: &Sig, st: &mut State) {
    let Some((_, _, created)) = st.current else { return };
    // Certifications by other keys (the web of trust) say nothing about
    // this key's expiry or usage.
    let own = match (&s.issuer, &st.primary_id) {
        (Some(i), Some(p)) => i.ends_with(p.as_str()),
        _ => true,
    };
    if !own {
        return;
    }
    // User ID and subkey binding self-signatures replace each other, the
    // newest winning; a direct-key signature only adds what it states.
    let binding = matches!(s.kind, 0x10..=0x13 | 0x18);
    if binding {
        let at = s.created.unwrap_or(0);
        if st.bound_at.is_some_and(|b| b > at) {
            return;
        }
        st.bound_at = Some(at);
    }
    let Some(target) = st.target() else { return };
    match s.kind {
        0x20 | 0x28 => {
            target.insert("revoked".into(), true.into());
        }
        0x10..=0x13 | 0x18 | 0x1f => {
            if binding {
                target.remove("expires");
                target.remove("expired");
            }
            if let Some(e) = s.key_expires.filter(|&e| e > 0)
                && let Some(t) = time(created.saturating_add(e))
            {
                target.insert("expired".into(), is_past(&t).into());
                target.insert("expires".into(), t.into());
            }
            if let Some(f) = s.flags {
                target.insert("usage".into(), json!(usage(f)));
            }
        }
        _ => {}
    }
}

/// The binary packets of an armoured file, joined; cleartext-signed text
/// is skipped up to its signature.
fn dearmor(text: &str, cx: &mut Context<'_>) -> Vec<u8> {
    let mut text = text;
    if text.trim_start().starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        cx.format_set("cleartext_signed", true);
        let hash = text.lines().nth(1).and_then(|l| l.strip_prefix("Hash: ")).map(str::to_ascii_lowercase);
        if let Some(h) = hash {
            cx.format_set("cleartext_hash", h);
        }
        text = text.find("-----BEGIN PGP SIGNATURE-----").map_or("", |i| &text[i..]);
    }
    let (blocks, _) = pem_blocks(text);
    let mut kinds = Vec::new();
    let mut out = Vec::new();
    for b in blocks.into_iter().filter(|b| b.label.starts_with("PGP ")) {
        kinds.push(b.label.trim_start_matches("PGP ").to_ascii_lowercase().replace(' ', "_"));
        for (k, v) in &b.headers {
            if k == "Comment" || k == "Version" {
                cx.format_set(&format!("armor_{}", k.to_ascii_lowercase()), crate::plugin::truncate_chars(v, 200));
            }
        }
        match b.der {
            Some(d) => out.extend(d),
            None => cx.warn(format!("armoured block {} could not be decoded", b.label)),
        }
    }
    if !kinds.is_empty() {
        cx.format_set("armor", kinds);
    }
    out
}

impl Extractor for Pgp {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = probe.head;
        if head.starts_with(b"-----BEGIN PGP ") {
            return Some(Sniff { format: "openpgp", confidence: 0.95 });
        }
        // The first packet's body may run past the head: its start is enough,
        // but its length must fit in the file.
        let (tag, start, len) = header(head)?;
        if len.is_some_and(|l| (start + l) as u64 > probe.len) {
            return None;
        }
        let body = head.get(start..)?;
        let named = probe.extension.is_some_and(|e| META.formats[0].extensions.contains(&e));
        let ok = match tag {
            5 | 6 => key(body).is_some(),
            2 => signature(body).is_some(),
            1 => body.first().is_some_and(|&v| v == 3 || v == 6) && body.len() > 10,
            3 => body.first().is_some_and(|&v| v == 4 || v == 6) && body.get(1).is_some_and(|&c| (1..=13).contains(&c)),
            // gpg writes compressed packets with an indeterminate length.
            8 => body.first().is_some_and(|&a| (1..=3).contains(&a)) && (len.is_none() || named),
            _ => false,
        };
        ok.then_some(Sniff { format: "openpgp", confidence: 0.7 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        let mut st = State::default();
        if cx.format_id() == "gpg_keybox" {
            keybox(&b, &mut st, cx)?;
        } else if b.starts_with(b"-----BEGIN PGP ") || b.trim_ascii_start().starts_with(b"-----BEGIN PGP ") {
            let data = dearmor(&String::from_utf8_lossy(&b), cx);
            walk(&data, &mut st, 0, cx)?;
        } else {
            walk(&b, &mut st, 0, cx)?;
        }
        finish(st, cx);
        Ok(())
    }
}

/// A keybox: a header blob, then one blob per key (OpenPGP or X.509).
fn keybox(b: &[u8], st: &mut State, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut at = 0;
    let (mut openpgp, mut x509) = (0u64, 0u64);
    while at + 16 <= b.len() {
        let len = be(&b[at..at + 4]);
        if len < 16 || at + len > b.len() {
            break;
        }
        let blob = &b[at..at + len];
        match blob[4] {
            2 => {
                openpgp += 1;
                let (off, n) = (be(&blob[8..12]), be(&blob[12..16]));
                if let Some(kb) = blob.get(off..off + n) {
                    walk(kb, st, 0, cx)?;
                }
            }
            3 => x509 += 1,
            _ => {}
        }
        at += len;
        if (openpgp + x509) % 1024 == 1023 {
            cx.checkpoint()?;
        }
    }
    cx.format_set("openpgp_blobs", openpgp);
    cx.format_set("x509_blobs", x509);
    Ok(())
}

fn finish(st: State, cx: &mut Context<'_>) {
    let kind = if st.secret_keys > 0 {
        "secret_key"
    } else if st.key_count > 0 {
        "public_key"
    } else if st.encrypted.is_some() || !st.recipients.is_empty() || st.passphrase || st.literal.is_some() {
        "message"
    } else if !st.signatures.is_empty() {
        "signature"
    } else {
        "unknown"
    };
    cx.format_set("kind", kind);
    if st.key_count > 0 {
        cx.format_set("key_count", st.key_count);
        cx.format_set("user_id_count", st.user_ids);
        if st.key_count == 1
            && let Some(Value::Object(uid)) = st.keys[0].get("user_ids").and_then(|u| u.get(0))
            && let Some(name) = uid.get("name").and_then(Value::as_str)
        {
            cx.content().source("crypto.openpgp").title(name);
        }
        cx.format_set("keys", st.keys.into_iter().map(Value::Object).collect::<Vec<_>>());
    }
    if !st.recipients.is_empty() {
        cx.format_set("recipients", st.recipients);
    }
    if st.passphrase {
        cx.format_set("passphrase_encrypted", true);
        if let Some(c) = st.passphrase_cipher {
            cx.format_set("passphrase_cipher", c);
        }
    }
    if let Some(e) = st.encrypted {
        cx.security().encrypted(true);
        cx.format_set("encryption", Value::Object(e));
    }
    if !st.compression.is_empty() {
        cx.format_set("compression", st.compression);
    }
    if let Some(l) = st.literal {
        cx.format_set("literal", Value::Object(l));
    }
    if st.one_pass > 0 {
        cx.format_set("one_pass_signatures", st.one_pass);
    }
    if !st.signatures.is_empty() {
        cx.format_set("signatures", st.signatures);
    }
}

crate::register_extractor!(Pgp);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn fmt(r: &crate::plugin::Report) -> &Value {
        &r.format[&r.identification.format]
    }

    fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0xc0 | tag, u8::try_from(body.len()).unwrap()];
        v.extend_from_slice(body);
        v
    }

    /// A v4 Ed25519 (legacy EdDSA) public key with a patterned point.
    fn ed_key(created: u32) -> Vec<u8> {
        let mut b = vec![4];
        b.extend(created.to_be_bytes());
        b.push(22);
        let oid = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
        b.push(9);
        b.extend(oid);
        b.extend([0x01, 0x07, 0x40]);
        b.extend([0x5a; 32]);
        b
    }

    #[test]
    fn unprotected_secret_key_is_flagged_and_not_shown() {
        let mut sk = ed_key(1_700_000_000);
        sk.push(0); // usage 0: unprotected
        sk.extend([0x00, 0xff]);
        sk.extend([0x77; 32]);
        let data = [packet(5, &sk), packet(13, b"Harbour Test <test@example.org>")].concat();
        let r = report_for("k.gpg", &data);
        assert_eq!(fmt(&r)["kind"], "secret_key");
        let k = &fmt(&r)["keys"][0];
        assert_eq!((k["key_algorithm"].as_str(), k["key_curve"].as_str()), (Some("eddsa"), Some("ed25519")));
        assert_eq!(k["secret"]["protected"], false);
        assert_eq!(k["user_ids"][0]["domain"], "example.org");
        assert!(r.security.risks.iter().any(|x| x.kind == "unprotected_key"));
        assert!(!serde_json::to_string(&r).unwrap().contains("7777"));
    }

    #[test]
    fn v4_fingerprint_and_partial_lengths() {
        let k = key(&ed_key(1_700_000_000)).unwrap();
        assert_eq!(k.fingerprint.len(), 40);
        assert_eq!(&k.fingerprint[24..], k.key_id);
        // A literal packet in two partial chunks: 2 bytes, then 3.
        let data = [0xcb, 0xe1, b'b', 0, 0x03, 0, 0, 0];
        let (list, clean) = packets(&data);
        assert!(clean);
        assert_eq!(list[0].body, [b'b', 0, 0, 0, 0]);
    }

    /// A v4 signature of `kind` with hashed creation time, optional key
    /// expiry, and the issuer's fingerprint.
    fn sig(kind: u8, created: u32, expires: Option<u32>, issuer: &[u8; 20]) -> Vec<u8> {
        let mut hashed = vec![5, 2];
        hashed.extend(created.to_be_bytes());
        if let Some(e) = expires {
            hashed.extend([5, 9]);
            hashed.extend(e.to_be_bytes());
        }
        hashed.extend([22, 33, 4]);
        hashed.extend(issuer);
        let mut b = vec![4, kind, 22, 8];
        b.extend(u16::try_from(hashed.len()).unwrap().to_be_bytes());
        b.extend(hashed);
        b.extend([0, 0, 0xab, 0xcd, 0, 8, 0xff]);
        b
    }

    #[test]
    fn only_the_keys_own_signatures_set_its_expiry() {
        let key_body = ed_key(1_700_000_000);
        let k = key(&key_body).unwrap();
        let fpr: [u8; 20] = (0..20)
            .map(|i| u8::from_str_radix(&k.fingerprint[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let other = [0x11; 20];
        let data = [
            packet(6, &key_body),
            // A direct-key signature without an expiry, then the user ID's
            // self-signature with one, then a newer certification by
            // another key: the expiry must survive both.
            packet(2, &sig(0x1f, 1_700_000_100, None, &fpr)),
            packet(13, b"Harbour Test <test@example.org>"),
            packet(2, &sig(0x13, 1_700_000_000, Some(86_400), &fpr)),
            packet(2, &sig(0x10, 1_700_000_500, None, &other)),
        ]
        .concat();
        let r = report_for("k.gpg", &data);
        assert_eq!(fmt(&r)["keys"][0]["expires"], "2023-11-15T22:13:20Z");
    }

    #[test]
    fn encrypted_message_lists_recipients() {
        let mut pkesk = vec![3];
        pkesk.extend([0xab; 8]);
        pkesk.push(1);
        pkesk.extend([0, 8, 0xff]);
        let data = [packet(1, &pkesk), packet(18, &[1, 0, 0, 0])].concat();
        let r = report_for("m.gpg", &data);
        assert_eq!(fmt(&r)["kind"], "message");
        assert_eq!(fmt(&r)["recipients"][0], "ABABABABABABABAB");
        assert_eq!(r.security.encrypted, Some(true));
    }

    crate::fixture_tests!("openpgp", "gpg_keybox");
}
