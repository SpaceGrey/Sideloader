#!/bin/bash
# Resign an IPA with a keychain identity + mobileprovision, suffixing
# CFBundleIdentifier of the app and appex with .$TEAM_ID.
set -euo pipefail
IPA="${1:?ipa}"
IDENTITY="${2:?codesign identity}"
PROFILE="${3:?mobileprovision}"
TEAM_ID="${4:?team id}"
OUT="${5:?output ipa}"

WORKDIR="$(mktemp -d /tmp/resign.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT
unzip -q "$IPA" -d "$WORKDIR"
APP="$(find "$WORKDIR/Payload" -maxdepth 1 -name '*.app' -type d | head -1)"

# Suffix app + appex bundle ids only.
python3 - "$APP" "$TEAM_ID" <<'PY'
import os, sys, plistlib
from pathlib import Path
app, team = Path(sys.argv[1]), sys.argv[2]
suffix = "." + team
targets = [app / "Info.plist"]
targets += list(app.glob("PlugIns/*.appex/Info.plist"))
targets += list(app.glob("Watch/*.app/Info.plist"))
for p in targets:
    if not p.exists():
        continue
    data = plistlib.loads(p.read_bytes())
    bid = data.get("CFBundleIdentifier")
    if isinstance(bid, str) and not bid.endswith(suffix):
        data["CFBundleIdentifier"] = bid + suffix
        p.write_bytes(plistlib.dumps(data))
        print("bundle-id", bid, "->", data["CFBundleIdentifier"])
PY

cp "$PROFILE" "$APP/embedded.mobileprovision"
while IFS= read -r -d '' appex; do
  cp "$PROFILE" "$appex/embedded.mobileprovision"
done < <(find "$APP/PlugIns" -name '*.appex' -type d -print0 2>/dev/null || true)

security cms -D -i "$PROFILE" > "$WORKDIR/profile.plist"
/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' "$WORKDIR/profile.plist" > "$WORKDIR/entitlements.plist"

# Sign inside-out: dylibs, frameworks, appex, then the app.
sign() {
  codesign --force --sign "$IDENTITY" --timestamp=none \
    --generate-entitlement-der --entitlements "$WORKDIR/entitlements.plist" "$1"
}

find "$APP" \( -name '*.dylib' -o -name '*.so' \) -type f | sort -r | while read -r f; do
  sign "$f"
done
find "$APP" -name '*.framework' -type d | awk '{ print length, $0 }' | sort -nr | awk '{ $1=""; print substr($0,2) }' | while read -r f; do
  sign "$f"
done
find "$APP" -name '*.appex' -type d | sort -r | while read -r f; do
  sign "$f"
done
sign "$APP"

mkdir -p "$(dirname "$OUT")"
(
  cd "$WORKDIR"
  zip -qr "$OUT" Payload
)
echo "wrote $OUT"
codesign -dv --verbose=2 "$APP" 2>&1 | head -20
