#!/usr/bin/env bash
# Regenerate the crypto fixtures under tests/fixtures/<format>/.
#
# Real tools make them for a fictitious harbour (Saltmere Harbour, the
# reserved .example domain), in a Debian container run with podman (image
# `whiff-crypto`, built from the Containerfile below): openssl (a CA chain,
# a request, a CRL, PKCS#7 / CMS, PKCS#12 without keys), ssh-keygen,
# gpg, keytool, keepassxc-cli, age, minisign and signify.
#
# Kept: public material, encrypted containers, private keys encrypted with
# the published passphrase "saltmere", and dummy secrets made for the tests
# (a keytab with an all-zero key, an expired HMAC token, the key log of one
# local TLS session). Unencrypted private keys are tested with in-memory
# unit tests only; the keys made on the way stay in target/.
#
#     scripts/fixtures/crypto.sh
#
# Containerfile (`podman build -t whiff-crypto`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         openssl openssh-client gnupg openjdk-21-jre-headless keepassxc-minimal age minisign \
#         signify-openbsd putty-tools krb5-user libfile-keepass-perl python3 ca-certificates

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/crypto-fixtures.XXXXXX")
export TZ=UTC LC_ALL=C

for d in pem x509 pkcs10 x509_crl pkcs7 pkcs12 der_key ssh_public_key ssh_authorized_keys ssh_known_hosts \
    openpgp gpg_keybox jks jceks kdbx age minisign jwk openssh_private_key putty_ppk keytab jwt tls_keylog kdb \
    ms_catalog; do
    mkdir -p "$fx/$d"
done

podman run --rm -i -e TZ=UTC -v "$work:/w" -w /w whiff-crypto bash -euo pipefail <<'EOF'
printf 'High water 06:12 4.1 m\nLow water 12:31 0.9 m\n' >tides.txt

# ------------------------------------------------------------- X.509 chain
cat >ca.cnf <<'CNF'
[ca]
default_ca = harbour
[harbour]
dir = /w/ca
database = $dir/index.txt
new_certs_dir = $dir/new
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 36500
policy = any
copy_extensions = copy
[any]
commonName = supplied
[root]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[intermediate]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
extendedKeyUsage = serverAuth, clientAuth, codeSigning
[leaf]
basicConstraints = CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:tides.saltmere.example, DNS:www.saltmere.example
[signer]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = emailProtection, codeSigning
CNF
mkdir -p ca/new
: >ca/index.txt
echo 1000 >ca/serial
echo 01 >ca/crlnumber
nb=20250901000000Z
na=21250901000000Z
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -subj "/C=GB/O=Saltmere Harbour/CN=Saltmere Harbour Root CA" \
    -config ca.cnf -extensions root -not_before $nb -not_after $na -sha384 -out root.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out int.key
openssl req -new -key int.key -subj "/C=GB/O=Saltmere Harbour/CN=Saltmere Harbour Issuing CA" -out int.csr
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -extfile ca.cnf -extensions intermediate \
    -not_before $nb -not_after $na -set_serial 0x1001 -sha384 -out int.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
openssl req -new -key leaf.key -subj "/C=GB/O=Saltmere Harbour/OU=Tides/CN=tides.saltmere.example" \
    -addext "subjectAltName = DNS:tides.saltmere.example, DNS:www.saltmere.example" -out leaf.csr
openssl x509 -req -in leaf.csr -CA int.pem -CAkey int.key -extfile ca.cnf -extensions leaf \
    -not_before $nb -not_after $na -set_serial 0x2001 -out leaf.pem
openssl genpkey -algorithm ED25519 -out signer.key
openssl req -new -key signer.key -subj "/O=Saltmere Harbour/CN=Saltmere Tide Signer" -out signer.csr
openssl x509 -req -in signer.csr -CA int.pem -CAkey int.key -extfile ca.cnf -extensions signer \
    -not_before $nb -not_after $na -set_serial 0x2002 -out signer.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out old.key 2>/dev/null
openssl req -new -key old.key -subj "/O=Saltmere Harbour/CN=ferry.saltmere.example" -out old.csr
openssl x509 -req -in old.csr -CA int.pem -CAkey int.key -extfile ca.cnf -extensions leaf \
    -not_before 20240101000000Z -not_after 20250101000000Z -set_serial 0x2003 -out old.pem
cat leaf.pem int.pem root.pem >chain.pem

mkdir -p out/pem out/x509 out/pkcs10 out/x509_crl out/pkcs7 out/pkcs12 out/der_key
cp chain.pem out/pem/saltmere-chain.pem
openssl x509 -in leaf.pem -text -certopt no_pubkey,no_sigdump >out/pem/tides-with-text.crt
openssl x509 -in leaf.pem -outform DER -out out/x509/tides.cer
openssl x509 -in root.pem -outform DER -out out/x509/saltmere-root.der
openssl x509 -in old.pem -outform DER -out out/x509/ferry-expired.crt
cp leaf.csr out/pem/tides.csr
openssl req -in leaf.csr -outform DER -out out/pkcs10/tides.p10
openssl req -in signer.csr -outform DER -out out/pkcs10/signer.csr

# A CRL from the issuing CA, revoking the expired ferry certificate.
mkdir -p ica/new
cp ca/index.txt ica/ && cp ca/serial ica/ && cp ca/crlnumber ica/
sed 's#/w/ca#/w/ica#' ca.cnf >ica.cnf
openssl ca -config ica.cnf -cert int.pem -keyfile int.key -revoke old.pem -crl_reason superseded \
    -batch 2>/dev/null
openssl ca -config ica.cnf -cert int.pem -keyfile int.key -gencrl -crl_lastupdate 20250901000000Z \
    -crl_nextupdate 21250901000000Z -out issuing.crl -batch 2>/dev/null
cp issuing.crl out/pem/issuing-ca.crl
openssl crl -in issuing.crl -outform DER -out out/x509_crl/issuing-ca.crl

# PKCS#7 / CMS: a certificate bundle, a detached signature, an envelope.
openssl crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out out/pkcs7/saltmere-chain.p7b
openssl crl2pkcs7 -nocrl -certfile chain.pem -out out/pem/saltmere-chain.p7b
openssl cms -sign -binary -in tides.txt -signer signer.pem -inkey signer.key -certfile int.pem \
    -md sha256 -outform DER -out out/pkcs7/tides.p7s
openssl cms -encrypt -binary -in tides.txt -aes256 -recip leaf.pem -outform DER -out out/pkcs7/tides.p7m

# PKCS#12 without keys: certificates encrypted (default) and in the clear.
openssl pkcs12 -export -nokeys -in chain.pem -passout pass:saltmere -out out/pkcs12/saltmere-chain.p12
openssl pkcs12 -export -nokeys -in chain.pem -certpbe NONE -passout pass:saltmere \
    -out out/pkcs12/saltmere-chain-clear.pfx

# Public keys only.
openssl pkey -in root.key -pubout -outform DER -out out/der_key/saltmere-root-public.der
openssl pkey -in leaf.key -pubout -out out/pem/tides-public.pem
openssl pkey -in signer.key -pubout >>out/pem/tides-public.pem
openssl rsa -in old.key -RSAPublicKey_out -out out/pem/ferry-rsa-public.pem 2>/dev/null

# --------------------------------------------------------------------- SSH
mkdir -p out/ssh_public_key out/ssh_authorized_keys out/ssh_known_hosts ssh
ssh-keygen -q -t ed25519 -N '' -C 'tides@saltmere.example' -f ssh/tides
ssh-keygen -q -t rsa -b 3072 -N '' -C 'ferry-desk' -f ssh/ferry
ssh-keygen -q -t ecdsa -b 384 -N '' -C 'gauge-7' -f ssh/gauge
ssh-keygen -q -t ed25519 -N '' -C 'Saltmere SSH CA' -f ssh/ca
ssh-keygen -q -s ssh/ca -I 'harbour-ops' -n tides,ops -V 20250901:21250901 -z 42 \
    -O no-port-forwarding -O source-address=192.0.2.0/24 ssh/tides.pub
ssh-keygen -q -s ssh/ca -h -I 'tides-host' -n tides.saltmere.example -V 20250901:21250901 -z 7 ssh/gauge.pub
cp ssh/tides.pub out/ssh_public_key/id_ed25519.pub
cp ssh/ferry.pub out/ssh_public_key/ferry_rsa.pub
cp ssh/tides-cert.pub out/ssh_public_key/id_ed25519-cert.pub
cp ssh/gauge-cert.pub out/ssh_public_key/gauge_host-cert.pub
ssh-keygen -e -f ssh/gauge.pub >out/ssh_public_key/gauge-rfc4716.pub
{
    echo '# Saltmere Harbour operators'
    cat ssh/tides.pub
    printf 'restrict,command="/usr/local/bin/tide-report",from="192.0.2.0/24" '
    cat ssh/ferry.pub
    printf 'cert-authority,principals="ops" '
    cat ssh/ca.pub
} >out/ssh_authorized_keys/authorized_keys
{
    printf 'tides.saltmere.example,192.0.2.10 '
    cut -d' ' -f1,2 ssh/gauge.pub
    printf 'ferry.saltmere.example '
    cut -d' ' -f1,2 ssh/ferry.pub
    printf '@cert-authority *.saltmere.example '
    cut -d' ' -f1,2 ssh/ca.pub
} >known_hosts
cp known_hosts hashed_hosts
ssh-keygen -q -H -f hashed_hosts 2>/dev/null
sed -n 1p hashed_hosts >>known_hosts
cp known_hosts out/ssh_known_hosts/known_hosts

# ----------------------------------------------------------------- OpenPGP
mkdir -p out/openpgp out/gpg_keybox
export GNUPGHOME=/w/gnupg
mkdir -m 700 -p "$GNUPGHOME"
g() { gpg --batch --quiet --pinentry-mode loopback --passphrase '' --faked-system-time 20250901T120000! "$@" 2>/dev/null; }
g --quick-gen-key 'Saltmere Harbour Office <tides@saltmere.example>' ed25519 cert 2100-09-01
fpr=$(gpg --batch --with-colons --list-keys tides@saltmere.example | awk -F: '/^fpr/ {print $10; exit}')
g --quick-add-key "$fpr" ed25519 sign 2100-09-01
g --quick-add-key "$fpr" cv25519 encr 2100-09-01
g --quick-add-uid "$fpr" 'Saltmere Tide Tables <tables@saltmere.example>'
g --quick-gen-key 'Old Ferry Desk <ferry@saltmere.example>' rsa3072 cert,sign,encr never
ferry=$(gpg --batch --with-colons --list-keys ferry@saltmere.example | awk -F: '/^fpr/ {print $10; exit}')
g --export "$fpr" >out/openpgp/saltmere-office.gpg
g --local-user "$fpr" --detach-sign --output out/openpgp/tides.txt.sig tides.txt
g --local-user "$fpr" --armor --detach-sign --output out/openpgp/tides.txt.asc tides.txt
g --local-user "$fpr" --clearsign --output out/openpgp/tides-clearsigned.asc tides.txt
g --local-user "$fpr" --sign --output out/openpgp/tides-signed.gpg tides.txt
g --trust-model always --recipient "$fpr" --encrypt --output out/openpgp/tides-for-office.gpg tides.txt
g --trust-model always --recipient "$fpr" --recipient ferry@saltmere.example --armor --encrypt \
    --output out/openpgp/tides-two-recipients.asc tides.txt
g --symmetric --passphrase saltmere --cipher-algo AES256 --output out/openpgp/tides-passphrase.gpg tides.txt
# The ferry desk's key expired at the start of 2026.
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --faked-system-time 20250902T120000! \
    --quick-set-expire "$ferry" 2026-01-01 2>/dev/null
g --armor --export "$ferry" >out/openpgp/ferry-desk.asc
cp "$GNUPGHOME/pubring.kbx" out/gpg_keybox/pubring.kbx

# --------------------------------------------------------- Java key stores
mkdir -p out/jks out/jceks
for t in jks jceks; do
    keytool -importcert -noprompt -storetype $t -keystore out/$t/saltmere-trust.$t -storepass saltmere \
        -alias saltmere-root -file root.pem >/dev/null 2>&1
    keytool -importcert -noprompt -storetype $t -keystore out/$t/saltmere-trust.$t -storepass saltmere \
        -alias issuing-ca -file int.pem >/dev/null 2>&1
done

# ---------------------------------------------------------------- KeePass
mkdir -p out/kdbx
printf 'saltmere\nsaltmere\n' | keepassxc-cli db-create -q -p out/kdbx/harbour-vault.kdbx >/dev/null 2>&1

# ---------------------------------------------------------- age, minisign
mkdir -p out/age out/minisign
age-keygen -o age.key 2>/dev/null
age -r "$(age-keygen -y age.key)" -o out/age/tides.txt.age tides.txt
age -a -r "$(age-keygen -y age.key)" -r "$(cat ssh/tides.pub)" -o out/age/tides-armored.age tides.txt
minisign -G -W -p out/minisign/saltmere.pub -s minisign.key >/dev/null
minisign -S -s minisign.key -m tides.txt -x out/minisign/tides.txt.minisig -t 'Saltmere tide table' >/dev/null
signify-openbsd -G -n -p saltmere-signify.pub -s saltmere-signify.sec -c 'Saltmere signify key'
signify-openbsd -S -s saltmere-signify.sec -m tides.txt -x out/minisign/tides.txt.sig
cp saltmere-signify.pub out/minisign/

# ---------------------------------------------------------------- JWK set
mkdir -p out/jwk
python3 - <<'PY'
import base64, json, re, subprocess
def b64(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
def hexnum(text, field):
    m = re.search(field + r":\s*((?:\s*[0-9a-f]{2}:?)+)", text)
    return int(re.sub(r"[^0-9a-f]", "", m.group(1)), 16)
rsa = subprocess.run(["openssl", "pkey", "-in", "root.key", "-text_pub", "-noout"], capture_output=True, text=True).stdout
ec = subprocess.run(["openssl", "pkey", "-in", "leaf.key", "-text_pub", "-noout"], capture_output=True, text=True).stdout
point = hexnum(ec, "pub").to_bytes(65, "big")
keys = {"keys": [
    {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "saltmere-root", "n": b64(hexnum(rsa, "Modulus")), "e": "AQAB"},
    {"kty": "EC", "use": "sig", "alg": "ES256", "kid": "tides", "crv": "P-256",
     "x": base64.urlsafe_b64encode(point[1:33]).rstrip(b"=").decode(),
     "y": base64.urlsafe_b64encode(point[33:]).rstrip(b"=").decode()},
]}
open("out/jwk/saltmere.jwks", "w").write(json.dumps(keys, indent=2) + "\n")
PY

# ------------------------------------------- encrypted keys, dummy secrets
mkdir -p out/openssh_private_key out/putty_ppk out/keytab out/jwt out/tls_keylog out/kdb out/ms_catalog
ssh-keygen -q -t ed25519 -N saltmere -C 'tides@saltmere.example' -f enc_ed25519
ssh-keygen -q -t ecdsa -b 256 -N saltmere -C 'gauge-7' -f enc_ecdsa
cp enc_ed25519 out/openssh_private_key/id_ed25519
cp enc_ecdsa out/openssh_private_key/id_ecdsa
echo saltmere >passphrase.txt
puttygen ssh/tides -O private -o out/putty_ppk/tides.ppk --new-passphrase passphrase.txt
puttygen ssh/ferry -O private --ppk-param version=2 -o out/putty_ppk/ferry-v2.ppk --new-passphrase passphrase.txt
perl -MFile::KeePass -e 'my $k = File::KeePass->new; my $g = $k->add_group({title => "Harbour"});
    $k->add_entry({title => "Tide gauge 7", username => "gauge", password => "saltmere", group => $g});
    $k->save_db("out/kdb/harbour-vault.kdb", "saltmere");'

# The key log of one TLS 1.3 session on the loopback interface.
openssl s_server -quiet -accept 4433 -cert leaf.pem -key leaf.key -naccept 1 >/dev/null 2>&1 &
sleep 1
echo Q | openssl s_client -quiet -connect 127.0.0.1:4433 -servername tides.saltmere.example \
    -keylogfile out/tls_keylog/tides-session.keylog >/dev/null 2>&1 || true
wait

python3 - <<'PY'
import base64, hashlib, hmac, json, struct, subprocess

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# An HMAC token for a gauge, expired on 2000-01-01 (key "saltmere-demo").
head = b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "tides-2000"}, separators=(",", ":")).encode())
body = b64u(json.dumps({"iss": "https://tides.saltmere.example", "sub": "tide-gauge-7", "aud": "tides-api",
                        "iat": 946681200, "exp": 946684800, "scope": "read:tides"}, separators=(",", ":")).encode())
sig = b64u(hmac.new(b"saltmere-demo", f"{head}.{body}".encode(), hashlib.sha256).digest())
open("out/jwt/tide-gauge.jwt", "w").write(f"{head}.{body}.{sig}\n")

# A keytab (version 2) whose keys are all zero: two service entries.
def kt_entry(realm, comps, ts, kvno, enctype, keylen):
    s = lambda t: struct.pack(">H", len(t)) + t.encode()
    e = struct.pack(">H", len(comps)) + s(realm) + b"".join(s(c) for c in comps)
    e += struct.pack(">IIB", 1, ts, kvno & 0xff) + struct.pack(">HH", enctype, keylen) + bytes(keylen)
    e += struct.pack(">I", kvno)
    return struct.pack(">i", len(e)) + e
kt = b"\x05\x02"
kt += kt_entry("SALTMERE.EXAMPLE", ["HTTP", "tides.saltmere.example"], 1756728000, 3, 18, 32)
kt += kt_entry("SALTMERE.EXAMPLE", ["HTTP", "tides.saltmere.example"], 1756728000, 3, 17, 16)
kt += kt_entry("SALTMERE.EXAMPLE", ["host", "gauge7.saltmere.example"], 1756728000, 1, 20, 32)
open("out/keytab/tides.keytab", "wb").write(kt)

# A Microsoft catalog: a certificate trust list of two members, signed by
# the Ed25519 signer (makecat's layout, built here as no makecat runs on Linux).
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body
def oid(dotted):
    p = [int(x) for x in dotted.split(".")]
    out = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        enc = [v & 0x7f]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7f))
            v >>= 7
        out += bytes(enc)
    return tlv(0x06, out)
def read(b):
    tag, n = b[0], b[1]
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(b[2:2 + k], "big")
        h = 2 + k
    else:
        h = 2
    return tag, b[h:h + n], b[:h + n], b[h + n:]
def children(body):
    while body:
        t, bd, raw, body = read(body)
        yield t, bd, raw
seq = lambda *p: tlv(0x30, b"".join(p))
cert = subprocess.run(["openssl", "x509", "-in", "signer.pem", "-outform", "DER"], capture_output=True).stdout
tbs = list(children(list(children(read(cert)[1]))[0][1]))
serial, issuer = tbs[1][2], tbs[3][2]
members = []
for name in ["tides.txt", "README.txt"]:
    data = open("tides.txt", "rb").read() + name.encode()
    digest = hashlib.sha256(data).hexdigest().upper()
    name_value = seq(tlv(0x1e, "File".encode("utf-16-be")), tlv(0x02, b"\x10\x01\x00\x01"),
                     tlv(0x04, name.encode("utf-16-le") + b"\0\0"))
    attrs = tlv(0x31, seq(oid("1.3.6.1.4.1.311.12.2.1"), tlv(0x31, name_value)))
    members.append(seq(tlv(0x04, digest.encode("utf-16-le") + b"\0\0"), attrs))
ctl = seq(seq(oid("1.3.6.1.4.1.311.12.1.1")), tlv(0x04, bytes(range(16))), tlv(0x17, b"250901120000Z"),
          seq(oid("1.3.6.1.4.1.311.12.1.2"), b"\x05\x00"), seq(*members))
ctl_body = read(ctl)[1]
signed_attrs = [seq(oid("1.2.840.113549.1.9.3"), tlv(0x31, oid("1.3.6.1.4.1.311.10.1"))),
                seq(oid("1.2.840.113549.1.9.4"), tlv(0x31, tlv(0x04, hashlib.sha256(ctl_body).digest())))]
to_sign = tlv(0x31, b"".join(signed_attrs))
open("attrs.der", "wb").write(to_sign)
signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", "signer.key", "-in", "attrs.der"],
                           capture_output=True, check=True).stdout
sha256 = seq(oid("2.16.840.1.101.3.4.2.1"))
signer_info = seq(tlv(0x02, b"\x01"), seq(issuer, serial), sha256, tlv(0xa0, b"".join(signed_attrs)),
                  seq(oid("1.3.101.112")), tlv(0x04, signature))
signed = seq(tlv(0x02, b"\x01"), tlv(0x31, sha256), seq(oid("1.3.6.1.4.1.311.10.1"), tlv(0xa0, ctl)),
             tlv(0xa0, cert), tlv(0x31, signer_info))
open("out/ms_catalog/saltmere-tides.cat", "wb").write(seq(oid("1.2.840.113549.1.7.2"), tlv(0xa0, signed)))
PY
klist -kte out/keytab/tides.keytab >/dev/null
EOF

for d in "$work"/out/*/; do
    name=$(basename "$d")
    cp "$d"* "$fx/$name/"
done
echo "fixtures written; keys and work files are in $work"
