# Dexteri++

All-in-one website crawler, link checker, port scanner, basic vuln checks, and full-text indexer. Built in Rust. Free as in free beer. Ship as an AppImage.

Warning: This tool aggressively crawls and scans. Only run against sites you own or have permission to test.

## Features

- Crawl and link-check (internal/external) with concurrency and depth limits.
- Port scan common or custom ranges asynchronously.
- Basic security/misconfiguration checks (headers, mixed content, cookies).
- Generate a clean HTML report with summaries. See `src/report.rs`.
- Index crawled pages with Tantivy and search later.
- CLI subcommands: `crawl`, `ports`, `vuln`, `index`, `search`, `all`.

## Build
You need a modern Rust toolchain (>= 1.82). If your rustc is older, update with rustup.

```bash
# check version
rustc --version

# update to latest stable (recommended)
rustup update stable && rustup default stable

# build
cargo build --release

# run help
./target/release/dexteri --help
```

## Quickstart

```bash
# Crawl and write an HTML report
./target/release/dexteri crawl https://example.com -d 2 -c 32 --externals --report report.html

# Port scan common ports on a host
./target/release/dexteri ports example.com -p 1-1024,3306,5432 --concurrency 800 --timeout-ms 600

# Basic vuln checks
./target/release/dexteri vuln https://example.com

# All-in-one and write a single report
./target/release/dexteri all https://example.com -p 1-1024,3306 -o report.html --externals -d 2

# Index then search
./target/release/dexteri index https://example.com -o dexteri-index -d 2
./target/release/dexteri search -i dexteri-index "contact OR support"
```

## Desktop (Tauri) GUI

The desktop app uses Tauri (WebKitGTK). On Linux you need system dev packages:

- WebKitGTK 4.1 (preferred) or 4.0
- GTK3
- AppIndicator GTK3
- librsvg

Install automatically with our helper script (auto-detects apt/dnf/pacman/zypper):

```bash
chmod +x scripts/install-tauri-deps.sh
./scripts/install-tauri-deps.sh
```

Build and run the GUI:

```bash
cargo build --release --bin dexteri-gui
./target/release/dexteri-gui
```

Notes:

- End-user systems also need WebKitGTK runtime libs installed (Tauri cannot fully bundle them on Linux). Consider providing distro-specific instructions or a metascript.
- The GUI includes: column sorting/resizing, per-column filters, copy-to-clipboard, open URL on click, and saved run params.

## AppImage Packaging
We ship an AppImage for easy distribution.

Dependencies:
- `appimagetool` (the build script will auto-download if missing)
- `bash`, `coreutils`

Build the AppImage:

```bash
# build the binary first
cargo build --release --bin dexteri --bin dexteri-gui

# make the script executable and run it
chmod +x packaging/appimage/build_appimage.sh
./packaging/appimage/build_appimage.sh

# output: packaging/appimage/Dexteri-x86_64.AppImage
```

The AppImage launches the desktop GUI (`dexteri-gui`) by default. The CLI (`dexteri`) is also included inside the AppImage under `usr/bin/`.

## Donationware
Dexteri++ is MIT-licensed. If it saves you time or money, consider tossing a donation to support development.

- Donate: [https://example.com/donate](https://example.com/donate) (placeholder)

## License
MIT. See `LICENSE`.

