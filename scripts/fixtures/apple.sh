#!/usr/bin/env bash
# Regenerate the Apple fixtures under tests/fixtures/<format>/ (macOS with
# Xcode; the signed profiles, .DS_Store, AppleSingle and bookmarks come
# from the `whiff-binser` podman image, see scripts/fixtures/binser.sh).
#
# Everything describes a fictitious harbour (Saltmere Harbour) with fixed
# times:
# * plutil: XML, binary and old-style plists, Info.plist files, a launchd
#   job, iOS backup Info / Manifest / Status plists, a configuration
#   profile, a shortcut, a stringsdict, a compiled .strings;
# * genstrings: a UTF-16 Localizable.strings from a Swift source;
# * swift: an NSKeyedArchiver archive;
# * ditto: the AppleDouble file of a file with extended attributes
#   (`__MACOSX/._buoy.txt`);
# * actool: a compiled asset catalog (a colour and a data set);
# * by hand: an Automator workflow, a string catalog (.xcstrings), an
#   Xcode project (checked with `xcodebuild -list`) and a workspace;
# * craft_apple.py in the container: a signed configuration profile and
#   provisioning profile (openssl cms, throwaway certificate), a .DS_Store
#   (ds_store), an AppleSingle file (RFC 1740 layout), an alias file and
#   bookmark data (the bookmark layout: real ones record the creating
#   user, a disk image's backing path and the boot volume, so these are
#   built from neutral values and checked with Foundation's reader).
#
#     scripts/fixtures/apple.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/apple-fixtures.XXXXXX")
put() { mkdir -p "$fx/$1"; cp "$2" "$fx/$1/${3:-$(basename "$2")}"; }
p() { plutil "$@"; }
when=2025-09-01T12:00:00Z

# ------------------------------------------------------------ plists
f="$work/harbour-prefs.plist"
p -create xml1 "$f"
p -insert Harbour -string "Saltmere Harbour" "$f"
p -insert Berths -array "$f"
for b in 4 7 12; do p -insert Berths -integer "$b" -append "$f"; done
p -insert HighWater -dictionary "$f"
p -insert HighWater.Time -string 06:12 "$f"
p -insert HighWater.Height -float 4.25 "$f"
p -insert Updated -date "$when" "$f"
p -insert ChartTile -data "$(printf 'tide chart' | base64)" "$f"
p -insert Pilots -bool true "$f"
put plist "$f"
p -convert binary1 -o "$work/harbour-prefs-binary.plist" "$f"
put bplist "$work/harbour-prefs-binary.plist" harbour-prefs.plist

f="$work/org.saltmere.tidesync.plist"
p -create xml1 "$f"
p -insert Label -string org.saltmere.tidesync "$f"
p -insert ProgramArguments -array "$f"
for a in /usr/local/bin/tidesync --harbour saltmere; do p -insert ProgramArguments -string "$a" -append "$f"; done
p -insert RunAtLoad -bool true "$f"
p -insert StartInterval -integer 3600 "$f"
p -insert KeepAlive -dictionary "$f"
p -insert KeepAlive.SuccessfulExit -bool false "$f"
put plist "$f"

cat >"$work/old-style.plist" <<'EOF'
// Saltmere Harbour berths, old-style (OpenStep) property list
{
    Harbour = "Saltmere Harbour";
    Berths = (4, 7, 12);
    HighWater = { Time = "06:12"; Height = "4.25"; };
    ChartTile = <74696465206368617274>;
}
EOF
p -lint "$work/old-style.plist" >/dev/null
put plist "$work/old-style.plist"

cat >"$work/archive.swift" <<'EOF'
import Foundation
let berths: NSDictionary = [
    "harbour": "Saltmere Harbour",
    "berths": [4, 7, 12] as NSArray,
    "updated": Date(timeIntervalSince1970: 1_756_728_000),
    "pilot": ["name": "Ana Lighthouse", "licence": 31] as NSDictionary,
]
let data = try NSKeyedArchiver.archivedData(withRootObject: berths, requiringSecureCoding: false)
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
EOF
swift "$work/archive.swift" "$work/harbour-state.plist"
put bplist "$work/harbour-state.plist"

info() {
    local f=$1
    p -create xml1 "$f"
    p -insert CFBundleIdentifier -string org.saltmere.tidesmac "$f"
    p -insert CFBundleName -string Tides "$f"
    p -insert CFBundleDisplayName -string "Saltmere Tides" "$f"
    p -insert CFBundleShortVersionString -string 1.2.0 "$f"
    p -insert CFBundleVersion -string 12 "$f"
    p -insert CFBundleExecutable -string Tides "$f"
    p -insert CFBundlePackageType -string APPL "$f"
    p -insert CFBundleDevelopmentRegion -string en "$f"
    p -insert LSMinimumSystemVersion -string 13.0 "$f"
    p -insert LSApplicationCategoryType -string public.app-category.weather "$f"
    p -insert NSHumanReadableCopyright -string "© 2025 Saltmere Harbour" "$f"
    p -insert NSLocationUsageDescription -string "Shows the tides at the nearest harbour." "$f"
    p -insert CFBundleURLTypes -array "$f"
    p -insert CFBundleURLTypes -dictionary -append "$f"
    p -insert CFBundleURLTypes.0.CFBundleURLSchemes -array "$f"
    p -insert CFBundleURLTypes.0.CFBundleURLSchemes -string saltmere-tides -append "$f"
    p -insert CFBundleDocumentTypes -array "$f"
    p -insert CFBundleDocumentTypes -dictionary -append "$f"
    p -insert CFBundleDocumentTypes.0.CFBundleTypeName -string "Tide table" "$f"
    p -insert UTExportedTypeDeclarations -array "$f"
    p -insert UTExportedTypeDeclarations -dictionary -append "$f"
    p -insert UTExportedTypeDeclarations.0.UTTypeIdentifier -string org.saltmere.tide-table "$f"
    p -insert DTPlatformName -string macosx "$f"
    p -insert DTSDKName -string macosx15.5 "$f"
    p -insert DTXcode -string 1640 "$f"
}
info "$work/Info.plist"
put info_plist "$work/Info.plist"
info "$work/Tides-Info.plist"
p -convert binary1 "$work/Tides-Info.plist"
put info_plist "$work/Tides-Info.plist"

mkdir -p "$work/backup"
f="$work/backup/Info.plist"
p -create xml1 "$f"
p -insert "Device Name" -string "Harbour iPad" "$f"
p -insert "Display Name" -string "Harbour iPad" "$f"
p -insert "Product Type" -string iPad13,1 "$f"
p -insert "Product Version" -string 18.6 "$f"
p -insert "Build Version" -string 22G86 "$f"
p -insert "Serial Number" -string SALTMERE0001 "$f"
p -insert "Target Identifier" -string 00008110-000000000000001E "$f"
p -insert "Target Type" -string Device "$f"
p -insert "Unique Identifier" -string 00008110-000000000000001E "$f"
p -insert "iTunes Version" -string 12.13.7.1 "$f"
p -insert "Last Backup Date" -date "$when" "$f"
p -insert "Installed Applications" -array "$f"
p -insert "Installed Applications" -string org.saltmere.tides -append "$f"
put ios_backup_plist "$f"
f="$work/backup/Manifest.plist"
p -create xml1 "$f"
p -insert Version -string 10.0 "$f"
p -insert Date -date "$when" "$f"
p -insert IsEncrypted -bool false "$f"
p -insert WasPasscodeSet -bool true "$f"
p -insert SystemDomainsVersion -string 24.0 "$f"
p -insert Lockdown -dictionary "$f"
p -insert Lockdown.ProductType -string iPad13,1 "$f"
p -insert Lockdown.ProductVersion -string 18.6 "$f"
p -insert Lockdown.BuildVersion -string 22G86 "$f"
p -insert Lockdown.DeviceName -string "Harbour iPad" "$f"
p -insert Lockdown.SerialNumber -string SALTMERE0001 "$f"
p -insert Lockdown.UniqueDeviceID -string 00008110000000000000001e "$f"
p -insert Applications -dictionary "$f"
p -insert Applications.org\\.saltmere\\.tides -dictionary "$f" 2>/dev/null ||
    p -insert Applications.tides -dictionary "$f"
p -convert binary1 "$f"
put ios_backup_plist "$f"
f="$work/backup/Status.plist"
p -create xml1 "$f"
p -insert IsFullBackup -bool false "$f"
p -insert Version -string 3.3 "$f"
p -insert UUID -string 5A1E0000-0000-4000-8000-000000000001 "$f"
p -insert Date -date "$when" "$f"
p -insert BackupState -string new "$f"
p -insert SnapshotState -string finished "$f"
p -convert binary1 "$f"
put ios_backup_plist "$f"

f="$work/saltmere-guest.mobileconfig"
p -create xml1 "$f"
p -insert PayloadType -string Configuration "$f"
p -insert PayloadVersion -integer 1 "$f"
p -insert PayloadIdentifier -string org.saltmere.guest "$f"
p -insert PayloadUUID -string 5A1E0000-0000-4000-8000-000000000010 "$f"
p -insert PayloadDisplayName -string "Saltmere Harbour guest network" "$f"
p -insert PayloadDescription -string "Wi-Fi and DNS settings for visitors to Saltmere Harbour." "$f"
p -insert PayloadOrganization -string "Saltmere Harbour" "$f"
p -insert PayloadScope -string User "$f"
p -insert RemovalDate -date 2026-09-01T12:00:00Z "$f"
p -insert PayloadContent -array "$f"
p -insert PayloadContent -dictionary -append "$f"
p -insert PayloadContent.0.PayloadType -string com.apple.wifi.managed "$f"
p -insert PayloadContent.0.PayloadIdentifier -string org.saltmere.guest.wifi "$f"
p -insert PayloadContent.0.PayloadUUID -string 5A1E0000-0000-4000-8000-000000000011 "$f"
p -insert PayloadContent.0.PayloadVersion -integer 1 "$f"
p -insert PayloadContent.0.SSID_STR -string SaltmereGuest "$f"
p -insert PayloadContent.0.EncryptionType -string None "$f"
p -insert PayloadContent -dictionary -append "$f"
p -insert PayloadContent.1.PayloadType -string com.apple.dnsSettings.managed "$f"
p -insert PayloadContent.1.PayloadIdentifier -string org.saltmere.guest.dns "$f"
p -insert PayloadContent.1.PayloadUUID -string 5A1E0000-0000-4000-8000-000000000012 "$f"
p -insert PayloadContent.1.PayloadVersion -integer 1 "$f"
p -insert PayloadContent.1.DNSSettings -dictionary "$f"
p -insert PayloadContent.1.DNSSettings.DNSProtocol -string HTTPS "$f"
p -insert PayloadContent.1.DNSSettings.ServerURL -string https://dns.example.org/dns-query "$f"
put mobileconfig "$f"

cat >"$work/shortcut.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>WFWorkflowClientVersion</key><string>2302.0.4</string>
	<key>WFWorkflowMinimumClientVersion</key><integer>900</integer>
	<key>WFWorkflowMinimumClientVersionString</key><string>900</string>
	<key>WFWorkflowIcon</key><dict><key>WFWorkflowIconStartColor</key><integer>463140863</integer><key>WFWorkflowIconGlyphNumber</key><integer>59511</integer></dict>
	<key>WFWorkflowTypes</key><array><string>NCWidget</string><string>WatchKit</string></array>
	<key>WFWorkflowInputContentItemClasses</key><array><string>WFStringContentItem</string></array>
	<key>WFWorkflowImportQuestions</key><array/>
	<key>WFWorkflowActions</key>
	<array>
		<dict><key>WFWorkflowActionIdentifier</key><string>is.workflow.actions.comment</string>
			<key>WFWorkflowActionParameters</key><dict><key>WFCommentActionText</key><string>Next high water at Saltmere Harbour</string></dict></dict>
		<dict><key>WFWorkflowActionIdentifier</key><string>is.workflow.actions.gettext</string>
			<key>WFWorkflowActionParameters</key><dict><key>WFTextActionText</key><string>High water 06:12, 4.25 m</string></dict></dict>
		<dict><key>WFWorkflowActionIdentifier</key><string>is.workflow.actions.showresult</string>
			<key>WFWorkflowActionParameters</key><dict/></dict>
	</array>
</dict>
</plist>
EOF
p -convert binary1 -o "$work/Harbour Tides.shortcut" "$work/shortcut.xml"
put shortcut "$work/Harbour Tides.shortcut"
cat >"$work/document.wflow" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AMApplicationBuild</key><string>523</string>
	<key>AMApplicationVersion</key><string>2.10</string>
	<key>AMDocumentVersion</key><string>2</string>
	<key>actions</key>
	<array>
		<dict><key>action</key><dict>
			<key>AMAccepts</key><dict><key>Container</key><string>List</string><key>Optional</key><true/><key>Types</key><array><string>com.apple.cocoa.string</string></array></dict>
			<key>AMActionVersion</key><string>1.0</string>
			<key>ActionBundlePath</key><string>/System/Library/Automator/Get Specified Text.action</string>
			<key>ActionName</key><string>Get Specified Text</string>
			<key>ActionParameters</key><dict><key>emptyText</key><false/><key>text</key><string>High water 06:12</string></dict>
			<key>BundleIdentifier</key><string>com.apple.Automator.Text</string>
		</dict></dict>
		<dict><key>action</key><dict>
			<key>ActionBundlePath</key><string>/System/Library/Automator/Copy to Clipboard.action</string>
			<key>ActionName</key><string>Copy to Clipboard</string>
			<key>BundleIdentifier</key><string>com.apple.Automator.CopyToClipboard</string>
		</dict></dict>
	</array>
	<key>connectors</key><dict/>
	<key>workflowMetaData</key><dict><key>workflowTypeIdentifier</key><string>com.apple.Automator.servicesMenu</string></dict>
</dict>
</plist>
EOF
p -lint "$work/document.wflow" >/dev/null
put shortcut "$work/document.wflow"

# ------------------------------------------------------------ localisation
mkdir -p "$work/strings"
cat >"$work/strings/Tides.swift" <<'EOF'
import Foundation
let title = NSLocalizedString("harbour.title", value: "Saltmere Harbour", comment: "Window title")
let high = NSLocalizedString("tide.high", value: "High water at %@", comment: "Next high water")
let low = NSLocalizedString("tide.low", value: "Low water at %@ (%lld cm)", comment: "Next low water")
EOF
(cd "$work/strings" && genstrings -o . Tides.swift)
put apple_strings "$work/strings/Localizable.strings"
cat >"$work/fr.strings" <<'EOF'
/* Window title */
"harbour.title" = "Port de Saltmere";

/* Next high water */
"tide.high" = "Pleine mer à %@";

// Next low water
"tide.low" = "Basse mer à %@ (%lld cm)";
EOF
put apple_strings "$work/fr.strings"
p -convert binary1 -o "$work/Compiled.strings" "$work/fr.strings"
put apple_strings "$work/Compiled.strings"
cat >"$work/Localizable.stringsdict" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>berths.free</key>
	<dict>
		<key>NSStringLocalizedFormatKey</key><string>%#@berths@</string>
		<key>berths</key>
		<dict>
			<key>NSStringFormatSpecTypeKey</key><string>NSStringPluralRuleType</string>
			<key>NSStringFormatValueTypeKey</key><string>lld</string>
			<key>zero</key><string>No free berths</string>
			<key>one</key><string>One free berth</string>
			<key>other</key><string>%lld free berths</string>
		</dict>
	</dict>
</dict>
</plist>
EOF
p -lint "$work/Localizable.stringsdict" >/dev/null
put stringsdict "$work/Localizable.stringsdict"
cat >"$work/Localizable.xcstrings" <<'EOF'
{
  "sourceLanguage" : "en",
  "strings" : {
    "harbour.title" : {
      "comment" : "Window title",
      "extractionState" : "manual",
      "localizations" : {
        "en" : { "stringUnit" : { "state" : "translated", "value" : "Saltmere Harbour" } },
        "fr" : { "stringUnit" : { "state" : "translated", "value" : "Port de Saltmere" } },
        "de" : { "stringUnit" : { "state" : "needs_review", "value" : "Hafen Saltmere" } }
      }
    },
    "tide.high %@" : {
      "comment" : "Next high water",
      "localizations" : {
        "en" : { "stringUnit" : { "state" : "translated", "value" : "High water at %@" } },
        "fr" : { "stringUnit" : { "state" : "translated", "value" : "Pleine mer à %@" } }
      }
    },
    "SALTMERE" : {
      "shouldTranslate" : false
    }
  },
  "version" : "1.0"
}
EOF
put xcstrings "$work/Localizable.xcstrings"

# ------------------------------------------------------------ AppleDouble
mkdir -p "$work/ad"
printf 'buoy 7: green, flashing\n' >"$work/ad/buoy.txt"
xattr -w org.saltmere.note "inspected 2025-09-01" "$work/ad/buoy.txt"
xattr -w com.apple.quarantine "0083;68b5a6c0;Safari;" "$work/ad/buoy.txt"
xattr -wx com.apple.metadata:kMDItemWhereFroms \
    "$(printf '<plist version="1.0"><array><string>https://example.org/buoys/buoy.txt</string></array></plist>' |
        plutil -convert binary1 -o - - | xxd -p | tr -d '\n')" "$work/ad/buoy.txt"
xattr -wx com.apple.FinderInfo 54455854534c544d000000000000000000000000000000000000000000000000 "$work/ad/buoy.txt"
(cd "$work/ad" && ditto -c -k --sequesterRsrc buoy.txt "$work/ad.zip")
unzip -p "$work/ad.zip" __MACOSX/._buoy.txt >"$work/buoy.appledouble"
put appledouble "$work/buoy.appledouble"

# ------------------------------------------------------------ asset catalog
cat_dir="$work/Tides.xcassets"
mkdir -p "$cat_dir/Tide.colorset" "$cat_dir/Note.dataset" "$work/car"
echo '{ "info" : { "author" : "xcode", "version" : 1 } }' >"$cat_dir/Contents.json"
cat >"$cat_dir/Tide.colorset/Contents.json" <<'EOF'
{ "colors" : [ { "color" : { "color-space" : "srgb", "components" : { "alpha" : "1.000", "blue" : "0.800", "green" : "0.500", "red" : "0.100" } }, "idiom" : "universal" },
  { "appearances" : [ { "appearance" : "luminosity", "value" : "dark" } ], "color" : { "color-space" : "srgb", "components" : { "alpha" : "1.000", "blue" : "0.900", "green" : "0.700", "red" : "0.300" } }, "idiom" : "universal" } ],
  "info" : { "author" : "xcode", "version" : 1 } }
EOF
printf 'high water 06:12\n' >"$cat_dir/Note.dataset/note.txt"
cat >"$cat_dir/Note.dataset/Contents.json" <<'EOF'
{ "data" : [ { "filename" : "note.txt", "idiom" : "universal", "universal-type-identifier" : "public.plain-text" } ], "info" : { "author" : "xcode", "version" : 1 } }
EOF
xcrun actool "$cat_dir" --compile "$work/car" --platform macosx --minimum-deployment-target 13.0 \
    --output-format human-readable-text >/dev/null
put car "$work/car/Assets.car"

# ------------------------------------------------------------ Xcode
mkdir -p "$work/Tides.xcodeproj"
cp "$root/scripts/fixtures/apple-project.pbxproj" "$work/Tides.xcodeproj/project.pbxproj"
xcodebuild -list -project "$work/Tides.xcodeproj" >/dev/null
put pbxproj "$work/Tides.xcodeproj/project.pbxproj"
cat >"$work/contents.xcworkspacedata" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Workspace
   version = "1.0">
   <FileRef
      location = "group:Tides.xcodeproj">
   </FileRef>
   <Group
      location = "container:"
      name = "Charts">
      <FileRef
         location = "group:Charts/tides.csv">
      </FileRef>
   </Group>
   <FileRef
      location = "group:Pods/Pods.xcodeproj">
   </FileRef>
</Workspace>
EOF
put xcworkspace "$work/contents.xcworkspacedata"

# ------------------------------------------------------------ container part
podman run --rm -v "$root:/whiff" -w /whiff whiff-binser python3 -I scripts/fixtures/craft_apple.py

# Apple's own reader must accept the crafted bookmarks.
cat >"$work/check.swift" <<'EOF'
import Foundation
for path in CommandLine.arguments.dropFirst() {
    let url = URL(fileURLWithPath: path)
    let data = path.hasSuffix(".alias") ? try URL.bookmarkData(withContentsOf: url) : try Data(contentsOf: url)
    let v = URL.resourceValues(forKeys: [.pathKey, .nameKey, .volumeNameKey], fromBookmarkData: data)
    guard let p = v?.path, v?.volumeName == "Saltmere" else { fatalError("\(path): not read") }
    print(path, p)
}
EOF
swift "$work/check.swift" "$fx/alias/tides.alias" "$fx/bookmark_data/tides.bookmark"

echo "Apple fixtures written; scratch files in $work"
