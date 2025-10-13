# Dexteri++

All-in-one website crawler, link checker, port/vulnerability scanner, and indexer. Ships as a GUI AppImage and a CLI.

- **GUI binary:** `dexteri` (AppImage)
- **CLI binary:** `dexteri-cli`

## Downloads

- Latest release: [Releases](https://github.com/lquessenberry/dexteri/releases/latest)
  - Dexteri GUI: `Dexteri-x86_64.AppImage`
  - Dexteri CLI: `dexteri-cli` (Linux x86_64)

## Install

### GUI (Linux AppImage)

```bash
chmod +x Dexteri-x86_64.AppImage
./Dexteri-x86_64.AppImage
```

Optional: integrate with your desktop environment using your AppImage launcher.

### CLI (Linux x86_64)

```bash
curl -L -o dexteri-cli https://github.com/lquessenberry/dexteri/releases/latest/download/dexteri-cli
chmod +x dexteri-cli
sudo mv dexteri-cli /usr/local/bin/
```

### Build from source

Prereqs (Ubuntu/Debian) for GUI and web engine support:

```bash
sudo apt-get update
sudo apt-get install -y \
  libwebkit2gtk-4.0-dev \
  libjavascriptcoregtk-4.0-dev \
  libsoup2.4-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  pkg-config curl build-essential
# optional: newer webkit (if available)
sudo apt-get install -y libwebkit2gtk-4.1-dev || true
```

Build:

```bash
# CLI
cargo build --release --bin dexteri-cli
# GUI (App binary)
cargo build --release --bin dexteri
```

Binaries will be in `target/release/`.

## Quickstart

### Crawl a site

```bash
dexteri-cli crawl https://example.com --depth 1 --concurrency 16 --externals --include-subdomains
```

### Scan ports

```bash
dexteri-cli ports example.com -p "1-1024,3306,5432" --concurrency 512 --timeout-ms 800
```

### Full run (crawl + ports + vuln + security) with report

```bash
dexteri-cli all \
  --url https://example.com \
  --ports "80,443" \
  --report report.html \
  --out-json results.json \
  --out-xml results.xml \
  --out-dir exports/
```

### Launch web dashboard

```bash
dexteri-cli web --bind 127.0.0.1:5173
# open http://127.0.0.1:5173
```

## Features

- Crawler with marketing signals extraction (JSON-LD, microdata, Open Graph, Twitter cards)
- Link checker with broken link reporting
- TCP port scanner
- Basic web security checks and findings
- Indexing with Tantivy and simple search
- HTML report, JSON, XML and CSV exports

## License

MIT
