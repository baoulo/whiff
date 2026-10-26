#!/usr/bin/env bash
# Regenerate the package fixtures under tests/fixtures/<format>/.
#
# Real tools write what they can: npm (npm_tarball), cargo (crate),
# setuptools (wheel, python_sdist), RubyGems (gem), Helm (helm_chart), the
# JDK (jar, war, ear; jarsigner), the Android build tools (apk: aapt2, d8,
# zipalign, apksigner) and hdiutil (dmg). craft_packages.py writes the rest
# (see its docstring) and wraps some of the real output (AAB, APK set,
# XAPK, AAR, egg). Times the tools stamp are rewritten to a fixed one.
#
# Needs node/npm, cargo, python3 (setuptools, wheel), gem, helm, a JDK
# (javac, jar, keytool, jarsigner), the Android SDK build tools
# ($ANDROID_HOME/build-tools/<version>, platforms/android-<n>), openssl,
# 7zz, bsdtar and, on macOS, hdiutil and xar. Keys and certificates
# are made for the run and deleted with it.
#
# The packages describe a fictitious harbour app (Saltmere Tides by Ana
# Lighthouse). Run from the repository root:
#
#     scripts/fixtures/packages.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
craft="$root/scripts/fixtures/craft_packages.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TZ=UTC LC_ALL=C COPYFILE_DISABLE=1 SOURCE_DATE_EPOCH=1756728000
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
bt=$(ls -d "$sdk"/build-tools/* | sort -V | tail -1)
platform=$(ls -d "$sdk"/platforms/android-* | sort -V | tail -1)/android.jar

for d in deb udeb rpm npm_tarball crate python_sdist gem helm_chart arch_package alpine_package conda_package \
    freebsd_package slackware_package \
    docker_image jar war ear aar apk aab apks xapk ipa wheel egg nupkg msix msix_bundle vsix xpi crx msi msm msp \
    dmg pkg xar asar; do
    mkdir -p "$fx/$d"
done

# npm
p="$work/npm" && mkdir -p "$p"
cat >"$p/package.json" <<'JSON'
{
  "name": "saltmere-tides",
  "version": "1.2.0",
  "description": "Tide tables for Saltmere harbour",
  "license": "MIT",
  "author": "Ana Lighthouse <ana@example.org>",
  "repository": "https://example.org/saltmere/tides",
  "main": "index.js",
  "keywords": ["tides", "harbour"],
  "scripts": { "postinstall": "node setup.js", "test": "node test.js" },
  "dependencies": { "left-pad": "^1.3.0" }
}
JSON
echo 'module.exports = { high: "06:12" };' >"$p/index.js"
echo 'console.log("Saltmere tides ready");' >"$p/setup.js"
printf '# Saltmere tides\n\nHigh and low water for Saltmere harbour.\n' >"$p/README.md"
(cd "$p" && npm pack --silent --pack-destination "$fx/npm_tarball" >/dev/null)

# cargo
p="$work/crate" && mkdir -p "$p/src"
cat >"$p/Cargo.toml" <<'TOML'
[package]
name = "saltmere-tides"
version = "1.2.0"
edition = "2021"
description = "Tide tables for Saltmere harbour"
license = "MIT OR Apache-2.0"
authors = ["Ana Lighthouse <ana@example.org>"]
repository = "https://example.org/saltmere/tides"
keywords = ["tides", "harbour"]

[dependencies]
TOML
echo 'pub const HIGH: &str = "06:12";' >"$p/src/lib.rs"
(cd "$p" && cargo package -q --allow-dirty --no-verify --offline && cp target/package/*.crate "$fx/crate/")

# setuptools: wheel and sdist (the egg-info is kept for the egg)
p="$work/py" && mkdir -p "$p/saltmere_tides"
echo 'HIGH = "06:12"' >"$p/saltmere_tides/__init__.py"
printf '# Saltmere tides\n\nHigh and low water for Saltmere harbour.\n' >"$p/README.md"
cat >"$p/pyproject.toml" <<'TOML'
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "saltmere-tides"
version = "1.2.0"
description = "Tide tables for Saltmere harbour"
readme = "README.md"
license = "MIT"
authors = [{ name = "Ana Lighthouse", email = "ana@example.org" }]
requires-python = ">=3.9"
dependencies = ["requests>=2.0", "rich; python_version >= '3.10'"]
classifiers = ["Programming Language :: Python :: 3", "Topic :: Scientific/Engineering"]

[project.urls]
Homepage = "https://example.org/saltmere/tides"
Repository = "https://example.org/saltmere/tides.git"

[project.scripts]
tides = "saltmere_tides:main"
TOML
(cd "$p" && python3 -m pip wheel . --no-build-isolation --no-deps -q -w "$fx/wheel" \
    && python3 -c "from setuptools import build_meta as b; b.build_sdist('$fx/python_sdist')" >/dev/null \
    && cp -R saltmere_tides.egg-info "$work/egg-info")
python3 "$craft" --retime "$fx"/python_sdist/*.tar.gz "$fx"/npm_tarball/*.tgz

# RubyGems (a native extension: code that runs when the gem is installed)
p="$work/gem" && mkdir -p "$p/lib" "$p/ext/tides"
echo 'module SaltmereTides; HIGH = "06:12"; end' >"$p/lib/saltmere_tides.rb"
echo 'require "mkmf"; create_makefile("tides/tides")' >"$p/ext/tides/extconf.rb"
cat >"$p/saltmere_tides.gemspec" <<'RUBY'
Gem::Specification.new do |s|
  s.name = "saltmere_tides"
  s.version = "1.2.0"
  s.summary = "Tide tables for Saltmere harbour"
  s.description = "High and low water times for Saltmere harbour."
  s.authors = ["Ana Lighthouse"]
  s.license = "MIT"
  s.homepage = "https://example.org/saltmere/tides"
  s.files = ["lib/saltmere_tides.rb", "ext/tides/extconf.rb"]
  s.extensions = ["ext/tides/extconf.rb"]
  s.required_ruby_version = ">= 2.6"
  s.add_runtime_dependency "json", "~> 2.0"
  s.add_development_dependency "rake", "~> 13.0"
end
RUBY
(cd "$p" && gem build -q saltmere_tides.gemspec >/dev/null 2>&1 && cp saltmere_tides-1.2.0.gem "$fx/gem/")

# Helm
(cd "$work" && helm create saltmere-tides >/dev/null)
cat >"$work/saltmere-tides/Chart.yaml" <<'YAML'
apiVersion: v2
name: saltmere-tides
description: Tide tables for Saltmere harbour
type: application
version: 1.2.0
appVersion: "1.2.0"
home: https://example.org/saltmere/tides
sources:
  - https://example.org/saltmere/tides.git
maintainers:
  - name: Ana Lighthouse
    email: ana@example.org
annotations:
  artifacthub.io/license: MIT
YAML
(cd "$work" && helm package -d "$fx/helm_chart" saltmere-tides >/dev/null)
python3 "$craft" --retime "$fx"/helm_chart/*.tgz

# Java: JAR (plain and signed), WAR, EAR
p="$work/java" && mkdir -p "$p/src/org/saltmere" "$p/classes/META-INF/maven/org.saltmere/tides"
cat >"$p/src/org/saltmere/Tides.java" <<'JAVA'
package org.saltmere;
public class Tides { public static void main(String[] a) { System.out.println("High water 06:12"); } }
JAVA
javac --release 17 -d "$p/classes" "$p/src/org/saltmere/Tides.java"
printf 'groupId=org.saltmere\nartifactId=tides\nversion=1.2.0\n' >"$p/classes/META-INF/maven/org.saltmere/tides/pom.properties"
printf 'Implementation-Title: Saltmere Tides\nImplementation-Version: 1.2.0\nImplementation-Vendor: Saltmere Harbour\nAutomatic-Module-Name: org.saltmere.tides\n' >"$p/manifest.txt"
jar --create --file "$fx/jar/saltmere-tides-1.2.0.jar" --manifest "$p/manifest.txt" --main-class org.saltmere.Tides \
    --date 2025-09-01T12:00:00Z -C "$p/classes" .
keytool -genkeypair -alias harbour -keyalg EC -groupname secp256r1 -dname "CN=Saltmere Harbour, O=Saltmere, C=GB" \
    -validity 3650 -keystore "$work/ks.p12" -storepass saltmere -keypass saltmere -storetype PKCS12 2>/dev/null
cp "$fx/jar/saltmere-tides-1.2.0.jar" "$fx/jar/saltmere-tides-1.2.0-signed.jar"
jarsigner -keystore "$work/ks.p12" -storepass saltmere "$fx/jar/saltmere-tides-1.2.0-signed.jar" harbour >/dev/null 2>&1
python3 "$craft" --retime "$fx/jar/saltmere-tides-1.2.0-signed.jar"
cp "$fx/jar/saltmere-tides-1.2.0.jar" "$work/tides.jar"
w="$work/war" && mkdir -p "$w/WEB-INF/lib"
cat >"$w/WEB-INF/web.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee" version="6.0">
  <display-name>Saltmere Tides Web</display-name>
  <servlet><servlet-name>tides</servlet-name><servlet-class>org.saltmere.Tides</servlet-class></servlet>
  <servlet-mapping><servlet-name>tides</servlet-name><url-pattern>/tides</url-pattern></servlet-mapping>
</web-app>
XML
cp "$work/tides.jar" "$w/WEB-INF/lib/" && echo '<h1>Saltmere tides</h1>' >"$w/index.html"
jar --create --file "$fx/war/saltmere-tides-1.2.0.war" --date 2025-09-01T12:00:00Z -C "$w" .
e="$work/ear" && mkdir -p "$e/META-INF"
cat >"$e/META-INF/application.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<application xmlns="https://jakarta.ee/xml/ns/jakartaee" version="10">
  <display-name>Saltmere Tides Suite</display-name>
  <module><web><web-uri>saltmere-tides-1.2.0.war</web-uri><context-root>/tides</context-root></web></module>
  <module><java>tides.jar</java></module>
</application>
XML
cp "$fx/war/saltmere-tides-1.2.0.war" "$work/tides.jar" "$e/"
jar --create --file "$fx/ear/saltmere-tides-1.2.0.ear" --date 2025-09-01T12:00:00Z -C "$e" .

# Android: a signed APK (v1-v3); aapt2's protocol-buffer manifest for the AAB
a="$work/apk" && mkdir -p "$a/res/values" "$a/lib/arm64-v8a"
cat >"$a/AndroidManifest.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.saltmere.tides"
    android:versionCode="12" android:versionName="1.2.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-feature android:name="android.hardware.location.gps" android:required="false" />
    <application android:label="@string/app_name" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".TideService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true" />
    </application>
</manifest>
XML
printf '<resources><string name="app_name">Saltmere Tides</string></resources>\n' >"$a/res/values/strings.xml"
"$bt/aapt2" compile --dir "$a/res" -o "$a/res.zip"
"$bt/aapt2" link -I "$platform" --manifest "$a/AndroidManifest.xml" -o "$a/base.apk" "$a/res.zip"
"$bt/aapt2" link --proto-format -I "$platform" --manifest "$a/AndroidManifest.xml" -o "$a/proto.apk" "$a/res.zip"
(cd "$a" && unzip -q -p proto.apk AndroidManifest.xml >"$work/proto-manifest.xml")
"$bt/d8" --release --min-api 24 --output "$a" "$p/classes/org/saltmere/Tides.class"
cp "$a/classes.dex" "$work/classes.dex"
printf '\177ELF' >"$a/lib/arm64-v8a/libtides.so"
touch -t 202509011200 "$a/classes.dex" "$a/lib/arm64-v8a/libtides.so"
(cd "$a" && zip -q -X base.apk classes.dex lib/arm64-v8a/libtides.so)
"$bt/zipalign" -f 4 "$a/base.apk" "$a/aligned.apk"
"$bt/apksigner" sign --ks "$work/ks.p12" --ks-pass pass:saltmere --v1-signing-enabled true \
    --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false --out "$fx/apk/saltmere-tides.apk" "$a/aligned.apk"
"$bt/apksigner" verify "$fx/apk/saltmere-tides.apk"
cp "$fx/apk/saltmere-tides.apk" "$work/tides.apk"

# Apple disk images: empty volumes (files made here carry macOS provenance
# attributes, which would end up in the image)
hdiutil create -quiet -size 1m -fs HFS+ -volname "Saltmere Tides" "$work/hfs.dmg"
hdiutil convert -quiet "$work/hfs.dmg" -format UDZO -ov -o "$fx/dmg/saltmere-tides-udzo.dmg"
hdiutil create -quiet -size 2m -fs APFS -volname "Saltmere Tides" "$work/apfs.dmg"
hdiutil convert -quiet "$work/apfs.dmg" -format ULFO -ov -o "$fx/dmg/saltmere-tides-ulfo.dmg"

python3 "$craft" "$fx" "$work"

# Checks: other readers accept what was written.
for f in "$fx"/deb/*.deb "$fx"/udeb/*.udeb "$fx"/rpm/*.rpm "$fx"/msi/*.msi "$fx"/msm/*.msm "$fx"/pkg/*.pkg \
    "$fx"/xar/*.xar "$fx"/dmg/*.dmg; do
    7zz l "$f" >/dev/null || { echo "7-Zip rejects $f" >&2; exit 1; }
done
for f in "$fx"/rpm/*.rpm; do bsdtar -tf "$f" >/dev/null || { echo "bsdtar rejects $f" >&2; exit 1; }; done
for f in "$fx"/pkg/*.pkg "$fx"/xar/*.xar; do xar -tf "$f" >/dev/null || { echo "xar rejects $f" >&2; exit 1; }; done
jarsigner -verify "$fx/jar/saltmere-tides-1.2.0-signed.jar" >/dev/null 2>&1 || {
    echo "jarsigner rejects the signed JAR" >&2
    exit 1
}
echo "package fixtures written"
