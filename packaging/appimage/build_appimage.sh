#!/usr/bin/env bash
set -euo pipefail

# Build AppImage for Dexteri++
# Requirements: cargo (built binary), curl/wget, tar, xz

APPDIR="packaging/appimage/Dexteri.AppDir"
APPNAME="Dexteri"
BINARY_CLI="target/release/dexteri"
BINARY_GUI="target/release/dexteri-gui"
DESKTOP="packaging/appimage/dexteri.desktop"
APPRUN_SRC="packaging/appimage/AppRun"
ICON_SRC_SVG="packaging/appimage/dexteri.svg"

if [ ! -f "$BINARY_CLI" ]; then
  echo "CLI binary not found at $BINARY_CLI. Build first: cargo build --release" >&2
  exit 1
fi

if [ ! -f "$BINARY_GUI" ]; then
  echo "GUI binary not found at $BINARY_GUI. Build first: cargo build --release --bin dexteri-gui" >&2
  exit 1
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps" "$APPDIR/usr/share/icons/hicolor/scalable/apps"

install -m 0755 "$BINARY_CLI" "$APPDIR/usr/bin/dexteri"
install -m 0755 "$BINARY_GUI" "$APPDIR/usr/bin/dexteri-gui"
install -m 0644 "$DESKTOP" "$APPDIR/$APPNAME.desktop"
install -m 0755 "$APPRUN_SRC" "$APPDIR/AppRun"
# Include GUI assets and config for reference/runtime use
if [ -d assets ]; then
  mkdir -p "$APPDIR/usr/share/dexteri/assets"
  cp -R assets/* "$APPDIR/usr/share/dexteri/assets/" || true
fi
if [ -f tauri.conf.json ]; then
  mkdir -p "$APPDIR/usr/share/dexteri"
  install -m 0644 tauri.conf.json "$APPDIR/usr/share/dexteri/tauri.conf.json"
fi
# AppStream metadata (install with name matching component id)
if [ -f packaging/appimage/Dexteri.appdata.xml ]; then
  mkdir -p "$APPDIR/usr/share/metainfo"
  install -m 0644 packaging/appimage/Dexteri.appdata.xml "$APPDIR/usr/share/metainfo/com.dexteri.app.metainfo.xml"
fi
# icons
if [ -f "$ICON_SRC_SVG" ]; then
  install -m 0644 "$ICON_SRC_SVG" "$APPDIR/usr/share/icons/hicolor/scalable/apps/dexteri.svg"
  # also place at AppDir root to satisfy appimagetool's Icon lookup
  install -m 0644 "$ICON_SRC_SVG" "$APPDIR/dexteri.svg"
fi

# fallback 256x256 PNG if provided (optional)
if [ -f packaging/appimage/dexteri.png ]; then
  install -m 0644 packaging/appimage/dexteri.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/dexteri.png"
  install -m 0644 packaging/appimage/dexteri.png "$APPDIR/dexteri.png"
fi

# Fix desktop file location for AppImage expectations
mkdir -p "$APPDIR/usr/share/applications"
install -m 0644 "$DESKTOP" "$APPDIR/usr/share/applications/dexteri.desktop"

# Download appimagetool if not available
APPIMAGETOOL="packaging/appimage/appimagetool-x86_64.AppImage"
if ! command -v appimagetool >/dev/null 2>&1; then
  if [ ! -f "$APPIMAGETOOL" ]; then
    echo "Downloading appimagetool..."
    URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
    curl -L "$URL" -o "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
  fi
  APPIMAGETOOL_CMD="$APPIMAGETOOL"
else
  APPIMAGETOOL_CMD="$(command -v appimagetool)"
fi

# Build the AppImage
OUTPUT="packaging/appimage/${APPNAME}-x86_64.AppImage"
"$APPIMAGETOOL_CMD" "$APPDIR" "$OUTPUT"

echo "AppImage created at $OUTPUT"
