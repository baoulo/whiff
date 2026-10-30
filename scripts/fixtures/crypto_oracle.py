#!/usr/bin/env python3
"""Compare whiff's crypto extractors with reference tools.

    crypto_oracle.py collect DIR...   copy a corpus into target/crypto-corpus/mac/
    crypto_oracle.py collect-linux    copy Debian's certificates, keyrings and
                                      Java trust store into target/crypto-corpus/linux/
    crypto_oracle.py check            compare whiff with the references

The references run in the `whiff-crypto` image (scripts/fixtures/crypto.sh):
* certificates (PEM or DER, bundles too): openssl x509 — SHA-256
  fingerprint, serial, validity, key size, per certificate;
* CRLs: openssl crl — revoked count, last and next update;
* PKCS#7 / CMS: openssl pkcs7 -print_certs — certificate count;
* requests: openssl req — key size;
* PKCS#12: openssl pkcs12 -info — MAC digest and iterations, which safes
  are encrypted;
* SSH keys and lists, OpenSSH private keys: ssh-keygen -l — size and
  fingerprint of every key; certificates: ssh-keygen -L — serial, key ID;
* PuTTY keys: puttygen -l — fingerprint;
* OpenPGP keys and keyboxes: gpg --show-keys / --list-keys — key IDs,
  fingerprints, sizes, creation and expiry; messages and signatures:
  gpg --list-packets — recipients and signature issuers;
* Java key stores: keytool -list — entry count, aliases and types;
* keytabs: klist -kte — entries, principals, encryption types.

The corpus is copied (never committed) from system folders, /Applications,
Homebrew and a Debian container, since podman mounts only the home folder.
Files holding a private key in the clear are not copied.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "target", "crypto-corpus")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
WHIFF = os.path.join(ROOT, "target", "release", "whiff")
IMAGE = "whiff-crypto"
NAMES = re.compile(
    r"(\.(pem|crt|cer|der|p7b|p7c|p7s|p12|pfx|csr|crl|asc|gpg|pgp|sig|pub|jks|jceks|keystore|kbx|keytab|cat|jwks|"
    r"minisig|ppk)$|^(cacerts|known_hosts|authorized_keys|.*\.keyring)$)",
    re.I,
)
CLEAR_PRIVATE = (b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY", b"BEGIN DSA PRIVATE KEY",
                 b"BEGIN OPENSSH PRIVATE KEY", b"PRIVATE KEY BLOCK")
MAX_FILES = 3000


def collect(dirs):
    random.seed(7)
    found = []
    for d in dirs:
        for base, subdirs, files in os.walk(d):
            if base.startswith(("/System/Volumes", "/Users")):
                subdirs[:] = []
                continue
            found.extend(os.path.join(base, f) for f in files if NAMES.search(f))
    random.shuffle(found)
    out = os.path.join(CORPUS, "mac")
    os.makedirs(out, exist_ok=True)
    n = 0
    for p in found:
        try:
            if not os.path.isfile(p) or os.path.getsize(p) > 2 << 20:
                continue
            data = open(p, "rb").read()
        except OSError:
            continue
        if any(m in data for m in CLEAR_PRIVATE):
            continue
        shutil.copyfile(p, os.path.join(out, f"{n:05d}-{os.path.basename(p)}"))
        n += 1
        if n >= MAX_FILES:
            break
    print(f"mac: {n} files", file=sys.stderr)


def collect_linux():
    out = os.path.join(CORPUS, "linux")
    os.makedirs(out, exist_ok=True)
    script = r"""
n=0
for f in /etc/ssl/certs/*.pem /etc/ssl/certs/ca-certificates.crt /usr/share/keyrings/* /etc/apt/trusted.gpg.d/* \
         /etc/ssl/certs/java/cacerts /usr/share/ca-certificates/mozilla/*.crt; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    cp -L "$f" "/o/$(printf %05d $n)-$(basename "$f")"
done
echo "linux: $n files" >&2
"""
    subprocess.run(["podman", "run", "--rm", "-v", f"{out}:/o", IMAGE, "bash", "-c", script], check=True)


def whiff(files):
    out = {}
    for i in range(0, len(files), 300):
        r = subprocess.run([WHIFF, "--jsonl", *files[i : i + 300]], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            out[rep["source"]["path"]] = rep
    return out


# The reference side: one Python run in the container over all files.
REF = r"""
import json, os, re, subprocess, sys, tempfile
from datetime import datetime, timezone

def run(*a, inp=None):
    r = subprocess.run(a, capture_output=True, text=True, errors="replace", input=inp)
    return r.stdout + r.stderr

def when(s):
    s = s.strip()
    if s in ("", "NONE"):
        return None
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def certs(path):
    data = open(path, "rb").read()
    blocks = re.findall(rb"-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----.*?-----END (?:X509 |TRUSTED )?CERTIFICATE-----", data, re.S)
    items = [(b, "PEM") for b in blocks] if blocks else [(data, "DER")]
    out = []
    for b, form in items:
        with tempfile.NamedTemporaryFile() as t:
            t.write(b); t.flush()
            txt = run("openssl", "x509", "-inform", form, "-in", t.name, "-noout", "-fingerprint", "-sha256", "-serial", "-dates", "-text")
        fp = re.search(r"Fingerprint=([0-9A-F:]+)", txt)
        if not fp:
            continue
        bits = re.search(r"Public-Key: \((\d+) bit\)", txt)
        out.append({"sha256": fp.group(1).replace(":", "").lower(),
                    "serial": re.search(r"serial=(-?[0-9A-F]*)", txt).group(1).lower().lstrip("0") or "0",
                    "not_before": when(re.search(r"notBefore=(.*)", txt).group(1)),
                    "not_after": when(re.search(r"notAfter=(.*)", txt).group(1)),
                    "bits": int(bits.group(1)) if bits else None})
    return out

def form(path):
    return "PEM" if open(path, "rb").read(11) == b"-----BEGIN " else "DER"

home = tempfile.mkdtemp()
os.chmod(home, 0o700)
for arg in sys.argv[1:]:
    kind, path = arg.split(":", 1)
    r = {"path": path}
    if kind == "certs":
        r["certs"] = certs(path)
    elif kind == "crl":
        txt = run("openssl", "crl", "-inform", form(path), "-in", path, "-noout", "-text")
        r["revoked"] = txt.count("Serial Number:")
        m = re.search(r"Last Update: (.*)", txt)
        r["this_update"] = when(m.group(1)) if m else None
        m = re.search(r"Next Update: (.*)", txt)
        r["next_update"] = when(m.group(1)) if m else None
    elif kind == "p7":
        txt = run("openssl", "pkcs7", "-inform", form(path), "-in", path, "-print_certs", "-noout")
        r["certificates"] = len(re.findall(r"^subject=", txt, re.M))
    elif kind == "req":
        txt = run("openssl", "req", "-inform", form(path), "-in", path, "-noout", "-text")
        m = re.search(r"Public-Key: \((\d+) bit\)", txt)
        r["bits"] = int(m.group(1)) if m else None
    elif kind == "p12":
        txt = run("openssl", "pkcs12", "-info", "-nomacver", "-noout", "-passin", "pass:saltmere", "-in", path)
        m = re.search(r"MAC: (\w+), Iteration (\d+)", txt)
        r["mac"] = [m.group(1).lower(), int(m.group(2))] if m else None
        r["safes"] = [line.startswith("PKCS7 Encrypted") for line in txt.splitlines() if line.startswith("PKCS7 ")]
    elif kind == "ssh":
        txt = run("ssh-keygen", "-l", "-f", path)
        r["keys"] = sorted([int(b), fp] for b, fp in re.findall(r"^(\d+) (SHA256:\S+)", txt, re.M))
        if "-cert" in path:
            txt = run("ssh-keygen", "-L", "-f", path)
            m = re.search(r"Serial: (\d+)", txt)
            r["serial"] = int(m.group(1)) if m else None
    elif kind == "ppk":
        txt = run("puttygen", "-l", "-E", "sha256", path)
        r["keys"] = re.findall(r"(SHA256:\S+)", txt)
    elif kind in ("pgpkeys", "kbx"):
        if kind == "kbx":
            txt = run("gpg", "--homedir", home, "--no-default-keyring", "--keyring", os.path.abspath(path), "--with-colons", "--fixed-list-mode", "--list-keys")
        else:
            txt = run("gpg", "--homedir", home, "--with-colons", "--fixed-list-mode", "--show-keys", path)
        keys = []
        for line in txt.splitlines():
            f = line.split(":")
            if f[0] in ("pub", "sub", "sec", "ssb"):
                keys.append({"key_id": f[4], "bits": int(f[2] or 0), "created": int(f[5] or 0), "expires": int(f[6] or 0) or None})
            elif f[0] == "fpr" and keys and "fingerprint" not in keys[-1]:
                keys[-1]["fingerprint"] = f[9]
        r["keys"] = keys
    elif kind == "pgpmsg":
        txt = run("gpg", "--homedir", home, "--list-packets", path)
        r["recipients"] = sorted(set(re.findall(r":pubkey enc packet: .*keyid ([0-9A-F]+)", txt)))
        r["issuers"] = sorted(set(re.findall(r":signature packet: algo \d+, keyid ([0-9A-F]+)", txt)))
    elif kind == "jks":
        txt = run("keytool", "-list", "-keystore", path, inp="\n")
        m = re.search(r"contains (\d+) entr", txt)
        r["entries"] = int(m.group(1)) if m else None
        r["types"] = dict(__import__("collections").Counter(re.findall(r", (\w+Entry),", txt)))
    elif kind == "keytab":
        txt = run("klist", "-kte", path)
        rows = re.findall(r"^\s*(\d+) \S+ \S+ (\S+) \(([^)]+)\)", txt, re.M)
        r["entries"] = len(rows)
        r["principals"] = sorted(set(p for _, p, _ in rows))
        r["enctypes"] = sorted(set(e for _, _, e in rows))
    print(json.dumps(r))
"""


def reference(jobs):
    out = {}
    for i in range(0, len(jobs), 400):
        args = [f"{k}:{p}" for k, p in jobs[i : i + 400]]
        r = subprocess.run(
            ["podman", "run", "--rm", "-v", f"{ROOT}:/r:ro", "-w", "/r", IMAGE, "python3", "-I", "-c", REF, *args],
            capture_output=True, text=True, errors="replace",
        )
        for line in r.stdout.splitlines():
            rec = json.loads(line)
            out[rec["path"]] = rec
    return out


def fmt(rep):
    return rep.get("format", {}).get(rep["identification"]["format"], {})


def kind_of(rep):
    f = fmt(rep)
    fid = rep["identification"]["format"]
    if fid in ("x509", "pem", "pkcs7", "pkcs12", "x509_crl", "pkcs10", "ms_catalog", "der_key"):
        types = f.get("object_types", {})
        if fid == "pkcs12":
            return "p12"
        if fid in ("pkcs7", "ms_catalog") or types.get("cms"):
            return "p7"
        if types.get("crl"):
            return "crl"
        if types.get("certificate_request"):
            return "req"
        if types.get("certificate"):
            return "certs"
        return None
    if fid in ("ssh_public_key", "ssh_authorized_keys", "ssh_known_hosts", "openssh_private_key"):
        return "ssh"
    if fid == "putty_ppk":
        return "ppk"
    if fid == "gpg_keybox":
        return "kbx"
    if fid == "openpgp":
        return "pgpkeys" if f.get("kind") in ("public_key", "secret_key") else "pgpmsg"
    if fid in ("jks", "jceks"):
        return "jks"
    if fid == "keytab":
        return "keytab"
    return None


def unix(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def compare(kind, got, ref):
    d = {}

    def same(key, ours, theirs):
        if ours != theirs:
            d[key] = {"whiff": ours, "reference": theirs}

    if kind == "certs":
        ours = {c["sha256"]: c for c in got.get("certificates", [])}
        total = got.get("object_types", {}).get("certificate", 0)
        if not ref["certs"]:
            return d  # openssl could not load it (unsupported algorithm)
        same("count", total, len(ref["certs"]))
        for c in ref["certs"]:
            o = ours.get(c["sha256"])
            if o is None:
                if len(ours) < total:
                    continue  # beyond the objects described
                d.setdefault("missing", []).append(c["sha256"][:12])
                continue
            # openssl prints a negative serial (invalid, RFC 5280 4.1.2.2) with
            # a sign; whiff gives its bytes, as browsers do.
            if not c["serial"].startswith("-"):
                same("serial", (o.get("serial") or "").lstrip("0") or "0", c["serial"])
            same("not_before", o.get("not_before"), c["not_before"])
            same("not_after", o.get("not_after"), c["not_after"])
            if c["bits"] is not None:
                same("bits", o.get("key_bits"), c["bits"])
    elif kind == "crl":
        c = got.get("crls", [{}])[0]
        same("revoked", c.get("revoked"), ref["revoked"])
        same("this_update", c.get("this_update"), ref["this_update"])
        same("next_update", c.get("next_update"), ref["next_update"])
    elif kind == "p7":
        same("certificates", got.get("object_types", {}).get("certificate", 0), ref["certificates"])
    elif kind == "req":
        if ref["bits"] is not None:  # openssl gives no size for Ed25519 / Ed448
            same("bits", got.get("requests", [{}])[0].get("key_bits"), ref["bits"])
    elif kind == "p12":
        p = got.get("pkcs12", [{}])[0]
        mac = p.get("mac")
        same("mac", [mac.get("digest"), mac.get("iterations")] if mac else None, ref["mac"])
        # openssl stops at the first safe it cannot decrypt.
        same("safes", [s.get("encrypted") for s in p.get("safes", [])][: len(ref["safes"])], ref["safes"])
    elif kind == "ssh":
        if not ref["keys"]:
            return d  # OpenSSH 10 reads neither DSA keys nor RFC 4716 files
        keys = got.get("key_list") or [got]
        ours = sorted([k.get("key_bits"), k.get("fingerprint")] for k in keys if k.get("fingerprint"))
        # ssh-keygen -l skips @cert-authority and @revoked lines.
        if got.get("markers"):
            ours = [k for k in ours if k in ref["keys"]] if all(k in ours for k in ref["keys"]) else ours
        same("keys", ours, ref["keys"])
        if "serial" in ref:
            same("serial", got.get("certificate", {}).get("serial"), ref["serial"])
    elif kind == "ppk":
        same("fingerprint", [got.get("fingerprint")], ref["keys"])
    elif kind in ("pgpkeys", "kbx"):
        ours = []
        for k in got.get("keys", []):
            ours.append(k)
            ours.extend(k.get("subkeys", []))
        if len(ours) < got.get("key_count", 0):
            return d  # beyond the keys described
        theirs = {k["key_id"]: k for k in ref["keys"]}
        same("keys", sorted(k.get("key_id") for k in ours), sorted(theirs))
        for k in ours:
            t = theirs.get(k.get("key_id"))
            if not t:
                continue
            same("fingerprint", k.get("fingerprint"), t.get("fingerprint"))
            same("created", k.get("created"), unix(t["created"]))
            same("expires", k.get("expires"), unix(t["expires"]))
            if k.get("key_algorithm") in ("rsa", "dsa", "elgamal"):
                same("bits", k.get("key_bits"), t["bits"])
    elif kind == "pgpmsg":
        same("recipients", sorted(r for r in got.get("recipients", []) if r != "hidden"), ref["recipients"])
        issuers = sorted({s.get("issuer", "")[-16:] for s in got.get("signatures", [])})
        if ref["issuers"] or not got.get("cleartext_signed"):  # gpg lists no packets for clear-signed text
            same("issuers", issuers, ref["issuers"])
    elif kind == "jks":
        same("entries", got.get("entries"), ref["entries"])
        names = {"trusted_certificate": "trustedCertEntry", "private_key": "PrivateKeyEntry", "secret_key": "SecretKeyEntry"}
        same("types", {names.get(k, k): v for k, v in got.get("entry_types", {}).items()}, ref["types"])
    elif kind == "keytab":
        same("entries", got.get("entries"), ref["entries"])
        same("principals", sorted(got.get("principals", [])), ref["principals"])
        same("enctypes", sorted(got.get("encryption_types", {})), ref["enctypes"])
    return d


def check():
    files = []
    for base, _, names in os.walk(CORPUS):
        files.extend(os.path.join(base, n) for n in names)
    for base, _, names in os.walk(FIXTURES):
        files.extend(os.path.join(base, n) for n in names if n != "SOURCE.md" and NAMES.search(n) or
                     base.rsplit("/", 1)[-1] in ("openssh_private_key", "putty_ppk", "keytab", "ssh_known_hosts",
                                                 "ssh_authorized_keys", "jceks", "openpgp", "ms_catalog") and n != "SOURCE.md")
    files = sorted(set(files))
    ours = whiff(files)
    jobs, kinds = [], {}
    formats = Counter()
    for path, rep in ours.items():
        formats[rep["identification"]["format"]] += 1
        k = kind_of(rep)
        if k:
            kinds[path] = k
            jobs.append((k, os.path.relpath(path, ROOT)))
    print("identified:", dict(formats.most_common()))
    ref = reference(jobs)
    bad = defaultdict(list)
    total = Counter()
    for path, k in sorted(kinds.items()):
        r = ref.get(os.path.relpath(path, ROOT))
        if r is None:
            continue
        total[k] += 1
        d = compare(k, fmt(ours[path]), r)
        if d:
            bad[k].append((os.path.relpath(path, ROOT), d))
    for k in sorted(total):
        print(f"{k}: {total[k]} compared, {total[k] - len(bad[k])} agree")
        for name, d in bad[k][:12]:
            print(f"  {name}: {d}")
        c = Counter(f for _, d in bad[k] for f in d)
        if c:
            print("  by field:", dict(c))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "collect":
        collect(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "collect-linux":
        collect_linux()
    else:
        check()


if __name__ == "__main__":
    main()
