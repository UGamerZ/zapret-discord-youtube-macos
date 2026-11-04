#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export MACOSX_DEPLOYMENT_TARGET=13.0
# Keep build caches inside this source tree for restricted build environments.
export CLANG_MODULE_CACHE_PATH="$PWD/.build/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/ModuleCache"
mkdir -p .build/ModuleCache dist
python3 scripts/import_flowseal.py
./scripts/build_packet.sh
for ARCH in arm64 x86_64; do
    swift build -c release --disable-sandbox --product ZapretMac --triple "${ARCH}-apple-macosx13.0"
done
APP="$PWD/dist/Zapret macOS.app"
# Reassemble resources so a previous SOCKS-only build cannot be mixed in.
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/Licenses"
lipo -create .build/arm64-apple-macosx/release/ZapretMac .build/x86_64-apple-macosx/release/ZapretMac -output "$APP/Contents/MacOS/ZapretMac"
cp .build/packet/zapret-packet "$APP/Contents/Resources/"
cp -R Resources/flowseal "$APP/Contents/Resources/"
cp Resources/pt-root-ui_vf.ttf "$APP/Contents/Resources/"
cp ThirdParty/*LICENSE.txt ThirdParty/FONT-OFL.txt "$APP/Contents/Resources/Licenses/"
cp LICENSE "$APP/Contents/Resources/Licenses/APP-LICENSE.txt"
cp THIRD_PARTY.md README.md PACKET_RESEARCH.md VALIDATION.md "$APP/Contents/Resources/"
# Build a full icon family from the upstream GUI icon.
mkdir -p .build/AppIcon.iconset
for SIZE in 16 32 128 256 512; do
    sips -z "$SIZE" "$SIZE" Resources/AppIcon.png --out ".build/AppIcon.iconset/icon_${SIZE}x${SIZE}.png" >/dev/null
    DOUBLE=$((SIZE * 2))
    sips -z "$DOUBLE" "$DOUBLE" Resources/AppIcon.png --out ".build/AppIcon.iconset/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
done
python3 scripts/icon.py .build/AppIcon.iconset "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ZapretMac</string>
<key>CFBundleIdentifier</key><string>org.zapret.macos.desktop</string>
<key>CFBundleName</key><string>Zapret macOS</string>
<key>CFBundleDisplayName</key><string>Zapret macOS</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.2</string>
<key>CFBundleVersion</key><string>4</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleIconFile</key><string>AppIcon</string>
</dict></plist>
PLIST
codesign --force --sign - "$APP/Contents/Resources/zapret-packet"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
printf 'Built: %s\n' "$APP"
