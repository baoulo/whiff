//! SSH keys: OpenSSH public keys (one per line, RFC 4716 too), the
//! `authorized_keys` and `known_hosts` lists that hold them, OpenSSH
//! certificates (type, key ID, principals, validity, options, CA key),
//! OpenSSH private keys and PuTTY `.ppk` files. Each key gives its type,
//! size or curve, SHA-256 fingerprint (as `ssh-keygen -l` prints it) and
//! comment; private keys add how they are protected (cipher, KDF, rounds).
//! The private part is never read beyond the comment of an unencrypted
//! OpenSSH key.
//!
//! Specifications: RFC 4253 / 4716 / 5656 / 8709 (key blobs, the SSH2
//! public key file); OpenSSH `PROTOCOL.key`, `PROTOCOL.certkeys`,
//! `PROTOCOL.u2f` and `sshd(8)` (`authorized_keys`, `known_hosts`); PuTTY
//! manual appendix C (PPK).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::{base64, base64_encode, check_strength, comment, is_past, pem_blocks, unix_time};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for SSH key files.
pub struct Ssh;

static META: ExtractorMeta = ExtractorMeta {
    id: "crypto.ssh",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ssh_public_key",
            name: "SSH public key",
            family: "crypto",
            mimes: &["application/vnd.openssh.public-key"],
            extensions: &["pub"],
            // One-line keys and RFC 4716 files are recognised by `sniff`.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ssh_authorized_keys",
            name: "SSH authorized_keys",
            family: "crypto",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ssh_known_hosts",
            name: "SSH known_hosts",
            family: "crypto",
            mimes: &[],
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "openssh_private_key",
            name: "OpenSSH private key",
            family: "crypto",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::prefix(b"-----BEGIN OPENSSH PRIVATE KEY-----")],
            parent: None,
        },
        FormatSpec {
            id: "putty_ppk",
            name: "PuTTY private key",
            family: "crypto",
            mimes: &["application/x-putty-private-key"],
            extensions: &["ppk"],
            magic: &[Magic::prefix(b"PuTTY-User-Key-File-")],
            parent: None,
        },
    ],
};

/// Lines read from a key list.
const MAX_LINES: usize = 100_000;
/// Keys described in full from one list.
const MAX_KEYS: usize = 64;

/// The key types a line may name.
fn is_key_type(t: &str) -> bool {
    matches!(t, "ssh-rsa" | "ssh-dss" | "ssh-ed25519" | "ssh-ed448")
        || t.starts_with("ecdsa-sha2-")
        || t.starts_with("sk-")
        || t.ends_with("-cert-v01@openssh.com")
}

/// The position of the key type in a list line (after `authorized_keys`
/// options or `known_hosts` hosts).
fn key_at(words: &[&str]) -> Option<usize> {
    (0..words.len().saturating_sub(1)).find(|&i| is_key_type(words[i]) && words[i + 1].starts_with("AAAA"))
}

/// An SSH wire-format reader (RFC 4251 `string`, `uint32`, `uint64`).
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (v, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*v))
    }

    fn u64(&mut self) -> Option<u64> {
        let (v, rest) = self.0.split_first_chunk::<8>()?;
        self.0 = rest;
        Some(u64::from_be_bytes(*v))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let s = self.0.get(..n)?;
        self.0 = &self.0[n..];
        Some(s)
    }

    fn text(&mut self) -> Option<String> {
        self.string().map(|s| String::from_utf8_lossy(s).into_owned())
    }
}

/// Bits of an `mpint` (two's complement, big-endian).
fn mpint_bits(b: &[u8]) -> Option<u64> {
    crate::plugin::der::bit_length(b)
}

fn curve_name(id: &str) -> Option<(&'static str, u64)> {
    match id {
        "nistp256" => Some(("P-256", 256)),
        "nistp384" => Some(("P-384", 384)),
        "nistp521" => Some(("P-521", 521)),
        _ => None,
    }
}

/// A key blob's facts: type, bits, curve, fingerprint; certificate fields
/// for `*-cert-v01` keys. `cx` is for the strict-privacy comment rules.
fn key_blob(blob: &[u8], cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let mut w = Wire(blob);
    let kind = w.text()?;
    let mut m = Map::new();
    m.insert("key_type".into(), kind.clone().into());
    let base = kind.strip_suffix("-cert-v01@openssh.com").map(str::to_string);
    if base.is_some() {
        w.string()?; // nonce
    }
    let base = base.as_deref().unwrap_or(&kind);
    let fields_start = w.0;
    let (algorithm, bits, curve) = match base {
        "ssh-rsa" => {
            let (_e, n) = (w.string()?, w.string()?);
            ("rsa", mpint_bits(n), None)
        }
        "ssh-dss" => {
            let p = w.string()?;
            for _ in 0..3 {
                w.string()?;
            }
            ("dsa", mpint_bits(p), None)
        }
        "ssh-ed25519" | "sk-ssh-ed25519@openssh.com" => {
            w.string()?;
            ("ed25519", Some(256), None)
        }
        "ssh-ed448" => {
            w.string()?;
            ("ed448", Some(456), None)
        }
        b if b.starts_with("ecdsa-sha2-") || b.starts_with("sk-ecdsa-sha2-") => {
            let id = w.text()?;
            w.string()?;
            let (c, n) = curve_name(&id).unzip();
            ("ecdsa", n, c)
        }
        _ => ("unknown", None, None),
    };
    m.insert("key_algorithm".into(), algorithm.into());
    if let Some(b) = bits {
        m.insert("key_bits".into(), b.into());
    }
    if let Some(c) = curve {
        m.insert("key_curve".into(), c.into());
    }
    if base.starts_with("sk-") {
        m.insert("security_key".into(), true.into());
        if let Some(app) = w.text() {
            m.insert("application".into(), app.into());
        }
    }
    // A certificate's fingerprint is its key's, as `ssh-keygen -l` prints it.
    let key = if base == kind {
        blob.to_vec()
    } else {
        let fields = &fields_start[..fields_start.len() - w.0.len()];
        let mut k = u32::try_from(base.len()).ok()?.to_be_bytes().to_vec();
        k.extend_from_slice(base.as_bytes());
        k.extend_from_slice(fields);
        k
    };
    if kind.ends_with("-cert-v01@openssh.com")
        && let Some(c) = certificate(&mut w, cx)
    {
        m.insert("certificate".into(), Value::Object(c));
    }
    m.insert("fingerprint".into(), format!("SHA256:{}", base64_encode(&Sha256::digest(&key))).into());
    check_strength(cx, "SSH key", algorithm, bits);
    Some(m)
}

/// The fields after a certificate's public key (`PROTOCOL.certkeys`).
fn certificate(w: &mut Wire<'_>, cx: &mut Context<'_>) -> Option<Map<String, Value>> {
    let mut c = Map::new();
    c.insert("serial".into(), w.u64()?.into());
    let kind = w.u32()?;
    c.insert("type".into(), (if kind == 2 { "host" } else { "user" }).into());
    c.insert("key_id".into(), comment(cx, &w.text()?).into());
    let mut principals = Vec::new();
    let mut list = Wire(w.string()?);
    while let Some(p) = list.text() {
        principals.push(Value::from(comment(cx, &p)));
        if principals.len() >= MAX_KEYS {
            break;
        }
    }
    c.insert("principals".into(), principals.into());
    let (after, before) = (w.u64()?, w.u64()?);
    if let Some(t) = i64::try_from(after).ok().and_then(unix_time) {
        c.insert("valid_after".into(), t.into());
    }
    match i64::try_from(before).ok().and_then(unix_time) {
        Some(t) => {
            c.insert("expired".into(), is_past(&t).into());
            c.insert("valid_before".into(), t.into());
        }
        None => {
            c.insert("valid_before".into(), "forever".into());
        }
    }
    for key in ["critical_options", "extensions"] {
        let mut names = Vec::new();
        let mut opts = Wire(w.string()?);
        while let Some(n) = opts.text() {
            opts.string()?;
            names.push(Value::from(n));
        }
        if !names.is_empty() {
            c.insert(key.into(), names.into());
        }
    }
    w.string()?; // reserved
    let ca = w.string()?;
    let mut ca_w = Wire(ca);
    let ca_type = ca_w.text()?;
    c.insert(
        "signing_key".into(),
        json!({ "key_type": ca_type, "fingerprint": format!("SHA256:{}", base64_encode(&Sha256::digest(ca))) }),
    );
    Some(c)
}

impl Extractor for Ssh {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let name = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        match name {
            Some("authorized_keys" | "authorized_keys2") => {
                return Some(Sniff { format: "ssh_authorized_keys", confidence: 0.9 });
            }
            Some("known_hosts" | "known_hosts2" | "ssh_known_hosts") => {
                return Some(Sniff { format: "ssh_known_hosts", confidence: 0.9 });
            }
            _ => {}
        }
        if probe.head.starts_with(b"---- BEGIN SSH2 PUBLIC KEY ----") {
            return Some(Sniff { format: "ssh_public_key", confidence: 0.95 });
        }
        let text = std::str::from_utf8(probe.head.get(..probe.head.len().min(4096))?).ok()?;
        let first = text.lines().find(|l| !l.trim().is_empty() && !l.starts_with('#'))?;
        let words: Vec<&str> = first.split_whitespace().take(64).collect();
        match key_at(&words)? {
            0 => Some(Sniff { format: "ssh_public_key", confidence: 0.85 }),
            // Options or hosts before the key.
            _ if words[0].starts_with('|') || words[0].starts_with('@') => {
                Some(Sniff { format: "ssh_known_hosts", confidence: 0.8 })
            }
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        let text = String::from_utf8_lossy(&b);
        match cx.format_id().to_string().as_str() {
            "openssh_private_key" => openssh_private(&text, cx),
            "putty_ppk" => ppk(&text, cx),
            _ if text.starts_with("---- BEGIN SSH2 PUBLIC KEY ----") => rfc4716(&text, cx),
            id => key_list(&text, id, cx),
        }
    }
}

/// Public keys one per line, in a `.pub` file, `authorized_keys` or
/// `known_hosts`.
fn key_list(text: &str, format: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut keys = Vec::new();
    let mut types: Map<String, Value> = Map::new();
    let (mut count, mut hashed, mut hosts, mut options) = (0u64, 0u64, 0u64, Map::new());
    let mut markers = Map::new();
    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = key_at(&words) else { continue };
        count += 1;
        let n = types.get(words[at]).and_then(Value::as_u64).unwrap_or(0);
        types.insert(words[at].into(), (n + 1).into());
        let before = &words[..at];
        if format == "ssh_known_hosts" {
            let mut rest = before;
            if let Some(m) = rest.first().filter(|w| w.starts_with('@')) {
                let k = m.trim_start_matches('@');
                let n = markers.get(k).and_then(Value::as_u64).unwrap_or(0);
                markers.insert(k.into(), (n + 1).into());
                rest = &rest[1..];
            }
            if rest.first().is_some_and(|h| h.starts_with("|1|")) {
                hashed += 1;
            } else {
                hosts += rest.first().map_or(0, |h| h.split(',').count() as u64);
            }
        } else if !before.is_empty() {
            // authorized_keys options: `command="…"`, `from="…"`, `restrict`, …
            for opt in before.join(" ").split(',') {
                let k = opt.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
                if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    let n = options.get(&k).and_then(Value::as_u64).unwrap_or(0);
                    options.insert(k, (n + 1).into());
                }
            }
        }
        if keys.len() < MAX_KEYS
            && let Some(blob) = base64(words[at + 1])
            && let Some(mut k) = key_blob(&blob, cx)
        {
            if format != "ssh_known_hosts" && words.len() > at + 2 {
                k.insert("comment".into(), comment(cx, &words[at + 2..].join(" ")).into());
            }
            keys.push(Value::Object(k));
        }
    }
    if count == 0 {
        return Err(ExtractError::malformed("no SSH public key"));
    }
    cx.format_set("keys", count);
    cx.format_set("key_types", Value::Object(types));
    if format == "ssh_known_hosts" {
        cx.format_set("hashed_hosts", hashed);
        cx.format_set("named_hosts", hosts);
        if !markers.is_empty() {
            cx.format_set("markers", Value::Object(markers));
        }
    }
    if !options.is_empty() {
        cx.format_set("options", Value::Object(options));
    }
    if format == "ssh_public_key" && keys.len() == 1 {
        if let Value::Object(k) = keys.remove(0) {
            for (key, v) in k {
                cx.format_set(&key, v);
            }
        }
    } else {
        cx.format_set("key_list", keys);
    }
    Ok(())
}

/// The SSH2 public key file (RFC 4716): headers, then the base64 blob.
fn rfc4716(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut body = String::new();
    let mut note = None;
    let mut cont = false;
    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.starts_with("---- END SSH2 PUBLIC KEY") {
            break;
        }
        if cont {
            cont = line.ends_with('\\');
            continue;
        }
        if let Some((k, v)) = line.split_once(": ") {
            cont = v.ends_with('\\');
            if k.eq_ignore_ascii_case("Comment") {
                note = Some(v.trim_matches('"').to_string());
            }
            continue;
        }
        body.push_str(line);
    }
    let blob = base64(&body).ok_or_else(|| ExtractError::malformed("SSH2 public key body"))?;
    let k = key_blob(&blob, cx).ok_or_else(|| ExtractError::malformed("SSH2 public key blob"))?;
    for (key, v) in k {
        cx.format_set(&key, v);
    }
    cx.format_set("encoding", "rfc4716");
    if let Some(n) = note {
        cx.format_set("comment", comment(cx, &n));
    }
    Ok(())
}

/// `openssh-key-v1`: cipher, KDF and rounds, the public keys, and for an
/// unencrypted file the comments.
fn openssh_private(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (blocks, _) = pem_blocks(text);
    let der = blocks
        .into_iter()
        .find(|b| b.label == "OPENSSH PRIVATE KEY")
        .and_then(|b| b.der)
        .ok_or_else(|| ExtractError::malformed("OpenSSH private key armour"))?;
    let body = der.strip_prefix(b"openssh-key-v1\0").ok_or_else(|| ExtractError::malformed("openssh-key-v1"))?;
    let bad = || ExtractError::malformed("openssh-key-v1 header");
    let mut w = Wire(body);
    let cipher = w.text().ok_or_else(bad)?;
    let kdf = w.text().ok_or_else(bad)?;
    let kdf_options = w.string().ok_or_else(bad)?;
    let n = w.u32().ok_or_else(bad)?;
    cx.format_set("cipher", cipher.clone());
    cx.format_set("kdf", kdf.clone());
    if kdf == "bcrypt" {
        let mut o = Wire(kdf_options);
        if let (Some(_salt), Some(rounds)) = (o.string(), o.u32()) {
            cx.format_set("kdf_rounds", rounds);
        }
    }
    let encrypted = cipher != "none";
    cx.format_set("encrypted", encrypted);
    let mut keys = Vec::new();
    for _ in 0..n.min(16) {
        let Some(blob) = w.string() else { break };
        if let Some(k) = key_blob(blob, cx) {
            keys.push(k);
        }
    }
    // Unencrypted: check ints, then per key its type, private fields and
    // comment. Only the comment is kept.
    if !encrypted && let Some(private) = w.string() {
        let mut p = Wire(private);
        let _ = (p.u32(), p.u32());
        for k in &mut keys {
            let Some(c) = private_comment(&mut p) else { break };
            if !c.is_empty() {
                k.insert("comment".into(), comment(cx, &c).into());
            }
        }
    }
    if encrypted {
        cx.security().encrypted(true);
    } else {
        cx.security().risk("unprotected_key", Some("openssh".into()));
    }
    cx.format_set("keys", u64::from(n));
    if keys.len() == 1 {
        for (key, v) in keys.remove(0) {
            cx.format_set(&key, v);
        }
    } else {
        cx.format_set("key_list", keys.into_iter().map(Value::Object).collect::<Vec<_>>());
    }
    Ok(())
}

/// Skip one private key record and return its comment.
fn private_comment(p: &mut Wire<'_>) -> Option<String> {
    let kind = p.text()?;
    let fields = match kind.as_str() {
        "ssh-rsa" => 6,
        "ssh-dss" => 5,
        "ssh-ed25519" | "ssh-ed448" => 2,
        k if k.starts_with("ecdsa-sha2-") => 3,
        "sk-ssh-ed25519@openssh.com" => 4,
        k if k.starts_with("sk-ecdsa-sha2-") => 5,
        _ => return None,
    };
    for i in 0..fields {
        // Security keys keep a flags byte between application and handle.
        if kind.starts_with("sk-") && i == fields - 2 {
            p.0 = p.0.get(1..)?;
        }
        p.string()?;
    }
    p.text()
}

/// PuTTY `.ppk` (versions 2 and 3): key type, encryption, KDF parameters,
/// comment and the public key.
fn ppk(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let (head, kind) = first.split_once(": ").ok_or_else(|| ExtractError::malformed("PPK header"))?;
    let version = head.strip_prefix("PuTTY-User-Key-File-").unwrap_or("");
    cx.format_set("version", version.parse::<u64>().map_or_else(|_| Value::from(version), Value::from));
    cx.format_set("key_type", kind.trim());
    let mut public = String::new();
    let mut kdf = Map::new();
    let mut encrypted = false;
    while let Some(line) = lines.next() {
        let Some((k, v)) = line.split_once(": ") else { continue };
        match k {
            "Encryption" => {
                encrypted = v != "none";
                cx.format_set("encryption", v);
            }
            "Comment" => cx.format_set("comment", comment(cx, v)),
            "Public-Lines" => {
                for l in lines.by_ref().take(v.trim().parse().unwrap_or(0)) {
                    public.push_str(l.trim());
                }
            }
            "Key-Derivation" => {
                kdf.insert("algorithm".into(), v.into());
            }
            "Argon2-Memory" | "Argon2-Passes" | "Argon2-Parallelism" => {
                let key = k.trim_start_matches("Argon2-").to_ascii_lowercase();
                kdf.insert(key, v.trim().parse::<u64>().map_or_else(|_| Value::from(v), Value::from));
            }
            // Private lines and MACs are skipped unread.
            _ => {}
        }
    }
    if !kdf.is_empty() {
        cx.format_set("kdf", Value::Object(kdf));
    }
    cx.format_set("encrypted", encrypted);
    if let Some(k) = base64(&public).and_then(|b| key_blob(&b, cx)) {
        for (key, v) in k {
            if key != "key_type" {
                cx.format_set(&key, v);
            }
        }
    }
    if encrypted {
        cx.security().encrypted(true);
    } else {
        cx.security().risk("unprotected_key", Some("ppk".into()));
    }
    Ok(())
}

crate::register_extractor!(Ssh);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    fn fmt(r: &crate::plugin::Report) -> &Value {
        &r.format[&r.identification.format]
    }

    fn string(b: &[u8]) -> Vec<u8> {
        let mut v = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    fn ed25519_blob() -> Vec<u8> {
        [string(b"ssh-ed25519"), string(&[0x11; 32])].concat()
    }

    #[test]
    fn unencrypted_openssh_key_gives_comment_not_key() {
        let public = ed25519_blob();
        let private = [
            vec![1, 2, 3, 4, 1, 2, 3, 4],
            string(b"ssh-ed25519"),
            string(&[0x11; 32]),
            string(&[0x22; 64]),
            string(b"harbour-test"),
            vec![1, 2, 3],
        ]
        .concat();
        let body = [
            b"openssh-key-v1\0".to_vec(),
            string(b"none"),
            string(b"none"),
            string(b""),
            1u32.to_be_bytes().to_vec(),
            string(&public),
            string(&private),
        ]
        .concat();
        let text = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64_encode(&body)
        );
        let r = report_for("id_ed25519", text.as_bytes());
        assert_eq!(fmt(&r)["key_algorithm"], "ed25519");
        assert_eq!(fmt(&r)["comment"], "harbour-test");
        assert_eq!(fmt(&r)["encrypted"], false);
        assert!(r.security.risks.iter().any(|x| x.kind == "unprotected_key"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains(&base64_encode(&[0x22; 64])[..20]));
    }

    #[test]
    fn certificate_fingerprint_is_the_keys() {
        let cert = [
            string(b"ssh-ed25519-cert-v01@openssh.com"),
            string(&[7; 32]),
            string(&[0x11; 32]),
            42u64.to_be_bytes().to_vec(),
            1u32.to_be_bytes().to_vec(),
            string(b"harbour-ops"),
            string(&string(b"tides")),
            0u64.to_be_bytes().to_vec(),
            u64::MAX.to_be_bytes().to_vec(),
            string(b""),
            string(b""),
            string(b""),
            string(&ed25519_blob()),
            string(&[0; 83]),
        ]
        .concat();
        let line = format!("ssh-ed25519-cert-v01@openssh.com {} tides\n", base64_encode(&cert));
        let r = report_for("id-cert.pub", line.as_bytes());
        let plain = format!("SHA256:{}", base64_encode(&Sha256::digest(ed25519_blob())));
        assert_eq!(fmt(&r)["fingerprint"], plain.as_str());
        assert_eq!(fmt(&r)["certificate"]["valid_before"], "forever");
    }

    #[test]
    fn ppk_header_only() {
        let blob = base64_encode(&ed25519_blob());
        let text = format!(
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: test key\nPublic-Lines: 1\n{blob}\n\
             Key-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 13\nArgon2-Parallelism: 1\n\
             Argon2-Salt: 00\nPrivate-Lines: 1\nAAAA\nPrivate-MAC: 00\n"
        );
        let r = report_for("k.ppk", text.as_bytes());
        assert_eq!(fmt(&r)["version"], 3);
        assert_eq!(fmt(&r)["kdf"]["passes"], 13);
        assert_eq!(fmt(&r)["key_bits"], 256);
        assert_eq!(r.security.encrypted, Some(true));
    }

    #[test]
    fn known_hosts_counts_without_names() {
        let key = base64_encode(&ed25519_blob());
        let text = format!(
            "|1|c2FsdA==|aGFzaA== ssh-ed25519 {key}\nharbour.example,10.0.0.1 ssh-ed25519 {key}\n\
             @cert-authority *.example ssh-ed25519 {key}\n"
        );
        let r = report_for("known_hosts", text.as_bytes());
        assert_eq!(r.identification.format, "ssh_known_hosts");
        assert_eq!((fmt(&r)["keys"].as_u64(), fmt(&r)["hashed_hosts"].as_u64()), (Some(3), Some(1)));
        assert_eq!(fmt(&r)["markers"]["cert-authority"], 1);
        assert!(!serde_json::to_string(fmt(&r)).unwrap().contains("harbour.example"));
    }

    crate::fixture_tests!(
        "ssh_public_key",
        "ssh_authorized_keys",
        "ssh_known_hosts",
        "openssh_private_key",
        "putty_ppk"
    );
}
