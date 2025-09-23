#!/usr/bin/env bash
set -euo pipefail

# Install system dependencies required for Tauri (WebKitGTK-based WebView)
# Supports: Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman), openSUSE (zypper)
# This script will attempt to install webkit2gtk (4.1 preferred, fallback to 4.0)

need_cmd() { command -v "$1" >/dev/null 2>&1; }

install_apt() {
  sudo apt update
  # Prefer 4.1, fallback to 4.0
  if ! sudo apt install -y libwebkit2gtk-4.1-dev; then
    sudo apt install -y libwebkit2gtk-4.0-dev || true
  fi
  sudo apt install -y libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev librsvg2-bin pkg-config curl build-essential \
    libsoup2.4-dev libjavascriptcoregtk-4.0-dev || true
}

install_dnf() {
  # Prefer 4.1, fallback to 4.0
  sudo dnf install -y webkit2gtk4.1-devel || sudo dnf install -y webkit2gtk4.0-devel || true
  sudo dnf install -y gtk3-devel libappindicator-gtk3-devel librsvg2-devel librsvg2-tools pkgconf-pkg-config curl make automake gcc gcc-c++ kernel-devel \
    libsoup-devel javascriptcoregtk4.0-devel || true
}

install_pacman() {
  sudo pacman -Syu --needed --noconfirm webkit2gtk-4.1 || sudo pacman -Syu --needed --noconfirm webkit2gtk-4.0 || true
  sudo pacman -Syu --needed --noconfirm gtk3 libappindicator-gtk3 librsvg pkgconf curl base-devel
}

install_zypper() {
  sudo zypper refresh
  # Package names can vary by version; try common names
  sudo zypper install -y webkit2gtk3-devel gtk3-devel libayatana-appindicator3-devel librsvg-devel librsvg-tools pkg-config curl gcc gcc-c++ make \
    libsoup-devel javascriptcoregtk4.0-devel || true
}

if need_cmd apt-get || need_cmd apt; then
  install_apt
elif need_cmd dnf; then
  install_dnf
elif need_cmd pacman; then
  install_pacman
elif need_cmd zypper; then
  install_zypper
else
  echo "Unsupported distro. Please install WebKitGTK (4.1 or 4.0), GTK3, AppIndicator, and librsvg dev packages manually."
  exit 1
fi

# Verify installation
if pkg-config --exists webkit2gtk-4.1 || pkg-config --exists webkit2gtk-4.0; then
  echo "OK: WebKitGTK detected via pkg-config."
else
  echo "ERROR: webkit2gtk dev package not detected. Ensure pkg-config can find webkit2gtk-4.1 or 4.0."
  exit 2
fi

if pkg-config --exists libsoup-2.4; then
  echo "OK: libsoup-2.4 detected."
else
  echo "WARNING: libsoup-2.4 not detected (libsoup2.4-dev). Some builds may fail without it."
fi

if pkg-config --exists javascriptcoregtk-4.0; then
  echo "OK: javascriptcoregtk-4.0 detected."
else
  echo "WARNING: javascriptcoregtk-4.0 not detected (libjavascriptcoregtk-4.0-dev). Some builds may fail without it."
fi

echo "All set. You can now build the Tauri GUI: cargo build --release --bin dexteri-gui or cargo tauri build"
