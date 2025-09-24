mod crawler;
mod indexer;
mod models;
mod ports;
mod report;
mod security;
mod util;
mod vuln;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};
use models::{AbResult, PortsResult, SecurityFlag, VulnReport};
use serde::Serialize;
use std::io::Write as IoWrite;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use url::Url;
use zip::{write::FileOptions, ZipWriter};

#[derive(Parser, Debug)]
#[command(
    name = "dexteri",
    about = "Dexteri++: all-in-one web crawler, link checker, port/vuln scanner, and indexer."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Crawl a site and check for broken links
    Crawl {
        /// Start URL
        url: String,
        /// Maximum crawl depth (0 means just the start URL)
        #[arg(short = 'd', long, default_value_t = 2)]
        depth: usize,
        /// Maximum concurrent requests
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
        /// Also check external links (won't follow them)
        #[arg(long, default_value_t = false)]
        externals: bool,
        /// Follow links on subdomains of the main domain
        #[arg(long, default_value_t = false)]
        include_subdomains: bool,
        /// Write HTML report to this file
        #[arg(long)]
        report: Option<PathBuf>,
    },

    /// Scan TCP ports on a host
    Ports {
        /// Hostname or IP (if omitted, extracted from --url)
        #[arg()]
        host: String,
        /// Port list and ranges, e.g. "1-1024,3306,5432"
        #[arg(short = 'p', long)]
        ports: Option<String>,
        /// Concurrency of port checks
        #[arg(short = 'c', long, default_value_t = 512)]
        concurrency: usize,
        /// Timeout in milliseconds per port attempt
        #[arg(short = 't', long, default_value_t = 800)]
        timeout_ms: u64,
    },

    /// Run simple web vulnerability checks
    Vuln {
        /// Target URL
        url: String,
    },

    /// Crawl and index pages with Tantivy
    Index {
        /// Start URL
        url: String,
        /// Output index directory
        #[arg(short = 'o', long, default_value = "dexteri-index")]
        out_dir: PathBuf,
        /// Maximum crawl depth
        #[arg(short = 'd', long, default_value_t = 2)]
        depth: usize,
        /// Also include external links (won't follow them)
        #[arg(long, default_value_t = false)]
        externals: bool,
        /// Follow links on subdomains of the main domain
        #[arg(long, default_value_t = false)]
        include_subdomains: bool,
        /// Concurrency
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
    },

    /// Search an existing index
    Search {
        /// Index directory
        #[arg(short = 'i', long, default_value = "dexteri-index")]
        index_dir: PathBuf,
        /// Query string
        query: String,
        /// Max results
        #[arg(short = 'n', long, default_value_t = 10)]
        limit: usize,
    },

    /// Run everything and generate a single HTML report
    All {
        /// Start URL (used for crawling and vuln checks)
        url: String,
        /// Hostname for port scan (defaults to host of URL)
        #[arg(short = 'H', long)]
        host: Option<String>,
        /// Maximum crawl depth
        #[arg(short = 'd', long, default_value_t = 2)]
        depth: usize,
        /// Concurrency for HTTP crawling
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
        /// Also check external links (won't follow)
        #[arg(long, default_value_t = false)]
        externals: bool,
        /// Follow links on subdomains of the main domain
        #[arg(long, default_value_t = false)]
        include_subdomains: bool,
        /// Optional requests-per-second rate limit
        #[arg(long)]
        rate_limit_rps: Option<u32>,
        /// Ports to scan, e.g. 1-1024,3306
        #[arg(short = 'p', long)]
        ports: Option<String>,
        /// Port scan concurrency
        #[arg(long, default_value_t = 512)]
        port_concurrency: usize,
        /// Port scan timeout ms
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        /// HTML report output path
        #[arg(short = 'o', long, default_value = "report.html")]
        report: PathBuf,
        /// Optional JSON results output
        #[arg(long)]
        out_json: Option<PathBuf>,
        /// Optional XML results output
        #[arg(long)]
        out_xml: Option<PathBuf>,
        /// Optional directory to write CSV exports (pages, broken_links, ports, findings, signals, security)
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },

    /// Launch the web dashboard (local server)
    Web {
        /// Bind address, e.g. 127.0.0.1:5173
        #[arg(short = 'b', long, default_value = "127.0.0.1:5173")]
        bind: String,
    },

    /// Run two crawls concurrently and compare results (A/B)
    Ab {
        /// URL A
        a: String,
        /// URL B
        b: String,
        /// Maximum crawl depth
        #[arg(short = 'd', long, default_value_t = 2)]
        depth: usize,
        /// Concurrency per crawl
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
        /// Validate external links (won't follow them)
        #[arg(long, default_value_t = false)]
        externals: bool,
        /// Include subdomains for same-site crawling
        #[arg(long, default_value_t = false)]
        include_subdomains: bool,
        /// Optional requests-per-second rate limit for both crawls
        #[arg(long)]
        rate_limit_rps: Option<u32>,
        /// Output full JSON instead of human-readable summary
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Output richer JSON object with crawl summaries + diff
        #[arg(long, default_value_t = false)]
        json_verbose: bool,
        /// Write JSON output to file
        #[arg(long)]
        out_json: Option<PathBuf>,
        /// Write an HTML side-by-side comparison page
        #[arg(long)]
        out_html_diff: Option<PathBuf>,
        /// Timeout for the concurrent A/B run (seconds)
        #[arg(long, default_value_t = 180)]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Crawl {
            url,
            depth,
            concurrency,
            externals,
            include_subdomains,
            report,
        } => {
            let start = Url::parse(&url)?;
            let client = util::build_client()?;
            let res = crawler::crawl(
                &client,
                &start,
                depth,
                concurrency,
                externals,
                include_subdomains,
            )
            .await?;
            println!(
                "Crawled {} pages, checked {} links, broken: {}",
                res.pages_crawled,
                res.links_checked,
                res.broken_links.len()
            );
            if let Some(path) = report {
                let ports_empty = PortsResult {
                    open_ports: vec![],
                    scanned: 0,
                };
                let vulns_empty = VulnReport { findings: vec![] };
                let security_empty: Vec<SecurityFlag> = Vec::new();
                report::write_report(
                    &path,
                    &start,
                    &res,
                    &ports_empty,
                    &vulns_empty,
                    &security_empty,
                )?;
                println!("Report written to {}", path.display());
            }
        }
        Commands::Ports {
            host,
            ports,
            concurrency,
            timeout_ms,
        } => {
            let ports_vec = ports
                .as_deref()
                .map(ports::parse_ports)
                .transpose()?
                .unwrap_or_else(ports::common_ports);
            let result = ports::scan_host(&host, &ports_vec, concurrency, timeout_ms, None).await?;
            println!(
                "Open ports ({} of {} scanned): {:?}",
                result.open_ports.len(),
                result.scanned,
                result.open_ports
            );
        }
        Commands::Vuln { url } => {
            let target = Url::parse(&url)?;
            let client = util::build_client()?;
            let report_v = vuln::scan(&client, &target).await?;
            for f in &report_v.findings {
                println!("[{}] {} - {}", f.severity, f.title, f.description);
            }
        }
        Commands::Index {
            url,
            out_dir,
            depth,
            externals,
            include_subdomains,
            concurrency,
        } => {
            let start = Url::parse(&url)?;
            let client = util::build_client()?;
            let crawl = crawler::crawl(
                &client,
                &start,
                depth,
                concurrency,
                externals,
                include_subdomains,
            )
            .await?;
            let stats = indexer::index_pages(&out_dir, &crawl.pages).await?;
            println!(
                "Indexed {} documents into {}",
                stats.docs_indexed,
                out_dir.display()
            );
        }
        Commands::Search {
            index_dir,
            query,
            limit,
        } => {
            let hits = indexer::search_index(&index_dir, &query, limit)?;
            for (i, h) in hits.iter().enumerate() {
                println!(
                    "{}: {}\n   {}",
                    i + 1,
                    h.title.as_deref().unwrap_or("(untitled)"),
                    h.url
                );
            }
        }
        Commands::All {
            url,
            host,
            depth,
            concurrency,
            externals,
            include_subdomains,
            rate_limit_rps,
            ports,
            port_concurrency,
            timeout_ms,
            report,
            out_json,
            out_xml,
            out_dir,
        } => {
            let start = Url::parse(&url)?;
            let host = host.unwrap_or_else(|| {
                util::host_from_url(&start).unwrap_or_else(|| "localhost".to_string())
            });
            let client = util::build_client()?;
            let ports_vec = ports
                .as_deref()
                .map(ports::parse_ports)
                .transpose()?
                .unwrap_or_else(ports::common_ports);

            println!("[1/4] Crawling {} ...", start);
            let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
            let (prog_tx, mut prog_rx) = mpsc::unbounded_channel::<models::CrawlProgress>();
            tokio::spawn(async move {
                while let Some(line) = log_rx.recv().await {
                    eprintln!("[crawl] {}", line);
                }
            });
            tokio::spawn(async move {
                while let Some(p) = prog_rx.recv().await {
                    eprintln!(
                        "[crawl] prog pages={} links={} q={} inflight={}",
                        p.pages_crawled, p.links_checked, p.queue_size, p.in_flight
                    );
                }
            });
            let crawl_res = crawler::crawl_with_logs(
                &client,
                &start,
                depth,
                concurrency,
                externals,
                include_subdomains,
                Some(log_tx),
                Some(prog_tx),
                None,
                rate_limit_rps,
            )
            .await?;
            println!("[2/4] Port scanning {} ...", host);
            let ports_res =
                ports::scan_host(&host, &ports_vec, port_concurrency, timeout_ms, None).await?;
            println!("[3/4] Vulnerability checks {} ...", start);
            let vuln_res = vuln::scan(&client, &start).await?;
            println!("[4/4] Security posture {} ...", start);
            let security_flags = match security::check_security_posture(&client, &start).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[security] error: {}", e);
                    Vec::new()
                }
            };
            report::write_report(
                &report,
                &start,
                &crawl_res,
                &ports_res,
                &vuln_res,
                &security_flags,
            )?;
            println!("Report written to {}", report.display());

            if let Some(path) = out_json.as_ref() {
                let payload = CombinedOut {
                    crawl: &crawl_res,
                    ports: &ports_res,
                    vuln: &vuln_res,
                    security: &security_flags,
                };
                let json = serde_json::to_string_pretty(&payload)?;
                std::fs::write(path, json)?;
                println!("Wrote JSON to {}", path.display());
            }
            if let Some(path) = out_xml.as_ref() {
                let xml = build_xml_out(&crawl_res, &ports_res, &vuln_res, &security_flags);
                std::fs::write(path, xml)?;
                println!("Wrote XML to {}", path.display());
            }
            if let Some(dir) = out_dir.as_ref() {
                std::fs::create_dir_all(dir)?;
                let join = |name: &str| dir.join(name);
                let csv_pages_s = csv_pages(&crawl_res.pages);
                let csv_broken_s = csv_broken(&crawl_res.broken_links);
                let csv_ports_s = csv_ports(&ports_res);
                let csv_findings_s = csv_findings(&vuln_res);
                let csv_signals_s = csv_signals(&crawl_res.pages);
                let csv_security_s = csv_security(&security_flags);
                std::fs::write(join("pages.csv"), &csv_pages_s)?;
                std::fs::write(join("broken_links.csv"), &csv_broken_s)?;
                std::fs::write(join("ports.csv"), &csv_ports_s)?;
                std::fs::write(join("findings.csv"), &csv_findings_s)?;
                std::fs::write(join("marketing_signals.csv"), &csv_signals_s)?;
                std::fs::write(join("security.csv"), &csv_security_s)?;
                println!("Wrote CSVs to {}", dir.display());

                // Also create a ZIP bundle of all CSVs
                let zip_path = dir.join("dexteri_csv_bundle.zip");
                let mut zip = ZipWriter::new(std::fs::File::create(&zip_path)?);
                let opts = FileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .unix_permissions(0o644);
                zip.start_file("pages.csv", opts)?;
                zip.write_all(csv_pages_s.as_bytes())?;
                zip.start_file("broken_links.csv", opts)?;
                zip.write_all(csv_broken_s.as_bytes())?;
                zip.start_file("ports.csv", opts)?;
                zip.write_all(csv_ports_s.as_bytes())?;
                zip.start_file("findings.csv", opts)?;
                zip.write_all(csv_findings_s.as_bytes())?;
                zip.start_file("marketing_signals.csv", opts)?;
                zip.write_all(csv_signals_s.as_bytes())?;
                zip.start_file("security.csv", opts)?;
                zip.write_all(csv_security_s.as_bytes())?;
                zip.finish()?;
                println!("Wrote CSV ZIP bundle to {}", zip_path.display());
            }
        }
        Commands::Web { bind } => {
            let addr: SocketAddr = bind.parse()?;
            println!("Dexteri++ dashboard listening on http://{}", addr);
            web::serve(addr).await?;
        }
        Commands::Ab {
            a,
            b,
            depth,
            concurrency,
            externals,
            include_subdomains,
            rate_limit_rps,
            json,
            json_verbose,
            out_json,
            out_html_diff,
            timeout_secs,
        } => {
            let a_url = Url::parse(&a).or_else(|_| Url::parse(&format!("http://{}", a)))?;
            let b_url = Url::parse(&b).or_else(|_| Url::parse(&format!("http://{}", b)))?;
            let client = util::build_client()?;

            println!("[A/B] Starting concurrent crawls\n  A: {}\n  B: {}\n  depth={} concurrency={} externals={} include_subdomains={} rps={}",
                a_url, b_url, depth, concurrency, externals, include_subdomains, rate_limit_rps.map(|v| v.to_string()).unwrap_or_else(|| "unset".into()));

            // Stream logs and progress to the console for better visibility
            let (log_a_tx, mut log_a_rx) = mpsc::unbounded_channel::<String>();
            let (log_b_tx, mut log_b_rx) = mpsc::unbounded_channel::<String>();
            let (prog_a_tx, mut prog_a_rx) = mpsc::unbounded_channel::<models::CrawlProgress>();
            let (prog_b_tx, mut prog_b_rx) = mpsc::unbounded_channel::<models::CrawlProgress>();
            tokio::spawn(async move {
                while let Some(line) = log_a_rx.recv().await {
                    eprintln!("[A] {}", line);
                }
            });
            tokio::spawn(async move {
                while let Some(line) = log_b_rx.recv().await {
                    eprintln!("[B] {}", line);
                }
            });
            tokio::spawn(async move {
                while let Some(p) = prog_a_rx.recv().await {
                    eprintln!(
                        "[A] prog pages={} links={} q={} inflight={}",
                        p.pages_crawled, p.links_checked, p.queue_size, p.in_flight
                    );
                }
            });
            tokio::spawn(async move {
                while let Some(p) = prog_b_rx.recv().await {
                    eprintln!(
                        "[B] prog pages={} links={} q={} inflight={}",
                        p.pages_crawled, p.links_checked, p.queue_size, p.in_flight
                    );
                }
            });

            let start_ts = std::time::Instant::now();
            let a_fut = crawler::crawl_with_logs(
                &client,
                &a_url,
                depth,
                concurrency,
                externals,
                include_subdomains,
                Some(log_a_tx),
                Some(prog_a_tx),
                None,
                rate_limit_rps,
            );
            let b_fut = crawler::crawl_with_logs(
                &client,
                &b_url,
                depth,
                concurrency,
                externals,
                include_subdomains,
                Some(log_b_tx),
                Some(prog_b_tx),
                None,
                rate_limit_rps,
            );

            let joined = timeout(Duration::from_secs(timeout_secs), async {
                tokio::try_join!(a_fut, b_fut)
            })
            .await;

            let (a_res, b_res) = match joined {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    eprintln!("[A/B] error during crawl: {}", e);
                    return Err(anyhow::anyhow!("A/B crawl error: {}", e));
                }
                Err(_) => {
                    eprintln!(
                        "[A/B] timed out after {} seconds while waiting for both crawls",
                        timeout_secs
                    );
                    return Err(anyhow::anyhow!(
                        "A/B crawl timed out after {} seconds",
                        timeout_secs
                    ));
                }
            };

            let ab: AbResult = AbResult::compute(&a_res, &b_res);
            if let Some(path) = out_html_diff.as_ref() {
                let html = build_ab_diff_html(&ab, &a_url, &b_url);
                std::fs::write(path, html)?;
                println!("Wrote HTML diff to {}", path.display());
            }
            if json || json_verbose {
                #[derive(Serialize)]
                struct CrawlSummary<'a> {
                    pages: usize,
                    links: usize,
                    broken: usize,
                    start: &'a Url,
                }
                #[derive(Serialize)]
                struct AbCliOutput<'a> {
                    a: CrawlSummary<'a>,
                    b: CrawlSummary<'a>,
                    diff: &'a AbResult,
                    duration_ms: u128,
                    settings: AbSettings<'a>,
                }
                #[derive(Serialize)]
                struct AbSettings<'a> {
                    a: &'a Url,
                    b: &'a Url,
                    depth: usize,
                    concurrency: usize,
                    externals: bool,
                    include_subdomains: bool,
                    rate_limit_rps: Option<u32>,
                    timeout_secs: u64,
                }
                let payload = if json_verbose {
                    Some(AbCliOutput {
                        a: CrawlSummary {
                            pages: a_res.pages_crawled,
                            links: a_res.links_checked,
                            broken: a_res.broken_links.len(),
                            start: &a_url,
                        },
                        b: CrawlSummary {
                            pages: b_res.pages_crawled,
                            links: b_res.links_checked,
                            broken: b_res.broken_links.len(),
                            start: &b_url,
                        },
                        diff: &ab,
                        duration_ms: start_ts.elapsed().as_millis(),
                        settings: AbSettings {
                            a: &a_url,
                            b: &b_url,
                            depth,
                            concurrency,
                            externals,
                            include_subdomains,
                            rate_limit_rps,
                            timeout_secs,
                        },
                    })
                } else {
                    None
                };

                let out = if let Some(p) = payload {
                    serde_json::to_string_pretty(&p)?
                } else {
                    serde_json::to_string_pretty(&ab)?
                };
                if let Some(path) = out_json {
                    std::fs::write(&path, &out)?;
                    println!("Wrote JSON to {}", path.display());
                } else {
                    println!("{}", out);
                }
            } else {
                println!(
                    "\n[A] pages={} links={} broken={}",
                    a_res.pages_crawled,
                    a_res.links_checked,
                    a_res.broken_links.len()
                );
                println!(
                    "[B] pages={} links={} broken={}",
                    b_res.pages_crawled,
                    b_res.links_checked,
                    b_res.broken_links.len()
                );
                println!("\nDifferences:");
                println!("  URLs only in A: {}", ab.diff.url_only_in_a.len());
                println!("  URLs only in B: {}", ab.diff.url_only_in_b.len());
                println!(
                    "  Broken delta (A, B): ({}, {})",
                    ab.diff.broken_delta.0, ab.diff.broken_delta.1
                );
                let s = &ab.diff.signals_delta;
                println!("  Signals delta (A - B): jsonld={} microdata={} og={} tw={} robots={} canonical={} hreflang={}",
                    s.json_ld_blocks, s.microdata_items, s.og_tags, s.twitter_tags, s.robots_pages, s.canonical_pages, s.hreflang_total);
                let top = ab.diff.signals_delta.top_trackers.iter().take(10);
                println!("  Top tracker deltas:");
                for (k, v) in top {
                    println!("    {:>3}  {}", v, k);
                }
            }
        }
    }

    Ok(())
}

// ----- Helpers for CLI outputs (JSON/XML/CSV) -----

#[derive(Serialize)]
struct CombinedOut<'a> {
    crawl: &'a models::CrawlResult,
    ports: &'a models::PortsResult,
    vuln: &'a models::VulnReport,
    security: &'a Vec<models::SecurityFlag>,
}

fn csv_escape(s: &str) -> String {
    let needs = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
fn csv_pages(pages: &Vec<models::Page>) -> String {
    let mut out = String::from("url,status,title,content_type,bytes\n");
    for p in pages {
        let url = csv_escape(&p.url);
        let status = p.status.map(|s| s.to_string()).unwrap_or_default();
        let title = csv_escape(p.title.as_deref().unwrap_or(""));
        let ct = csv_escape(p.content_type.as_deref().unwrap_or(""));
        let bytes = p.bytes.map(|b| b.to_string()).unwrap_or_default();
        out.push_str(&format!("{},{},{},{},{}\n", url, status, title, ct, bytes));
    }
    out
}
fn csv_broken(errs: &Vec<models::LinkError>) -> String {
    let mut out = String::from("url,status,reason,parent,external\n");
    for e in errs {
        let url = csv_escape(&e.url);
        let status = e.status.map(|s| s.to_string()).unwrap_or_default();
        let reason = csv_escape(&e.reason);
        let parent = csv_escape(&e.parent);
        let external = e.external.to_string();
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            url, status, reason, parent, external
        ));
    }
    out
}
fn csv_ports(p: &models::PortsResult) -> String {
    let mut out = String::from("port\n");
    for port in &p.open_ports {
        out.push_str(&format!("{}\n", port));
    }
    out
}
fn csv_findings(v: &models::VulnReport) -> String {
    let mut out = String::from("title,description,severity,url\n");
    for f in &v.findings {
        let title = csv_escape(&f.title);
        let desc = csv_escape(&f.description);
        let sev = csv_escape(&f.severity);
        let url = csv_escape(f.url.as_deref().unwrap_or(""));
        out.push_str(&format!("{},{},{},{}\n", title, desc, sev, url));
    }
    out
}
fn csv_security(sec: &Vec<models::SecurityFlag>) -> String {
    let mut out = String::from("level,title,description,url\n");
    for f in sec {
        let lvl = csv_escape(&f.level);
        let t = csv_escape(&f.title);
        let d = csv_escape(&f.description);
        let u = csv_escape(f.url.as_deref().unwrap_or(""));
        out.push_str(&format!("{},{},{},{}\n", lvl, t, d, u));
    }
    out
}
fn csv_signals(pages: &Vec<models::Page>) -> String {
    let mut out = String::from("url,json_ld_blocks,json_ld_types,microdata_items,microdata_types,open_graph_tags,og_props,twitter_tags,twitter_names,meta_robots,canonical_url,hreflang_count,hreflang_langs,trackers\n");
    for p in pages {
        let (j, jtypes, m, mtypes, og, ogprops, tw, twnames, robots, canon, hl, hlangs, trackers) =
            match &p.signals {
                Some(s) => (
                    s.json_ld_blocks.to_string(),
                    csv_escape(&s.json_ld_types.join("; ")),
                    s.microdata_items.to_string(),
                    csv_escape(&s.microdata_types.join("; ")),
                    s.open_graph_tags.to_string(),
                    csv_escape(&s.og_props.join("; ")),
                    s.twitter_tags.to_string(),
                    csv_escape(&s.twitter_names.join("; ")),
                    csv_escape(s.meta_robots.as_deref().unwrap_or("")),
                    csv_escape(s.canonical_url.as_deref().unwrap_or("")),
                    s.hreflang_count.to_string(),
                    csv_escape(&s.hreflang_langs.join("; ")),
                    csv_escape(&s.trackers.join("; ")),
                ),
                None => (
                    "0".into(),
                    String::new(),
                    "0".into(),
                    String::new(),
                    "0".into(),
                    String::new(),
                    "0".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    "0".into(),
                    String::new(),
                    String::new(),
                ),
            };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&p.url),
            j,
            jtypes,
            m,
            mtypes,
            og,
            ogprops,
            tw,
            twnames,
            robots,
            canon,
            hl,
            hlangs,
            trackers
        ));
    }
    out
}

fn xesc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn build_xml_out(
    crawl: &models::CrawlResult,
    ports: &models::PortsResult,
    vuln: &models::VulnReport,
    security: &Vec<models::SecurityFlag>,
) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<dexteri>\n");
    s.push_str(&format!(
        "  <summary pages=\"{}\" links=\"{}\" broken=\"{}\" ports_open=\"{}\" findings=\"{}\"/>\n",
        crawl.pages_crawled,
        crawl.links_checked,
        crawl.broken_links.len(),
        ports.open_ports.len(),
        vuln.findings.len()
    ));
    s.push_str("  <pages>\n");
    for p in &crawl.pages {
        s.push_str(&format!(
            "    <page url=\"{}\" status=\"{}\" bytes=\"{}\">\n      <title>{}</title>\n      <contentType>{}</contentType>\n    </page>\n",
            xesc(&p.url), xesc(&p.status.map(|v| v.to_string()).unwrap_or_default()), xesc(&p.bytes.map(|v| v.to_string()).unwrap_or_default()), xesc(p.title.as_deref().unwrap_or("")), xesc(p.content_type.as_deref().unwrap_or("")),
        ));
    }
    s.push_str("  </pages>\n  <brokenLinks>\n");
    for b in &crawl.broken_links {
        s.push_str(&format!("    <link url=\"{}\" status=\"{}\" external=\"{}\"><reason>{}</reason><parent>{}</parent></link>\n", xesc(&b.url), xesc(&b.status.map(|v| v.to_string()).unwrap_or_default()), b.external, xesc(&b.reason), xesc(&b.parent)));
    }
    s.push_str("  </brokenLinks>\n  <ports>\n");
    for port in &ports.open_ports {
        s.push_str(&format!("    <open>{}</open>\n", port));
    }
    s.push_str("  </ports>\n  <findings>\n");
    for f in &vuln.findings {
        s.push_str(&format!(
            "    <finding severity=\"{}\"><title>{}</title><description>{}</description><url>{}</url></finding>\n",
            xesc(&f.severity),
            xesc(&f.title),
            xesc(&f.description),
            xesc(f.url.as_deref().unwrap_or(""))
        ));
    }
    s.push_str("  </findings>\n  <security>\n");
    for f in security {
        s.push_str(&format!(
            "    <flag level=\"{}\"><title>{}</title><description>{}</description><url>{}</url></flag>\n",
            xesc(&f.level),
            xesc(&f.title),
            xesc(&f.description),
            xesc(f.url.as_deref().unwrap_or(""))
        ));
    }
    s.push_str("  </security>\n</dexteri>\n");
    s
}

fn build_ab_diff_html(ab: &AbResult, a_url: &Url, b_url: &Url) -> String {
    let mut s = String::new();
    s.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"/><title>Dexteri++ A/B Diff</title>\n",
    );
    s.push_str("<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;margin:1rem;background:#0b1020;color:#e6edf3} .wrap{display:grid;grid-template-columns:1fr 1fr;gap:1rem} .card{background:#121a2d;border:1px solid #1e2a47;border-radius:12px;padding:1rem} h2,h3{margin:.2rem 0} table{width:100%;border-collapse:collapse} td,th{border-bottom:1px solid #1e2a47;padding:.35rem .5rem;text-align:left} .muted{color:#9fb1c5}</style></head><body>\n");
    s.push_str(&format!(
        "<h2>Dexteri++ A/B Comparison</h2><div class=muted>A: {} &nbsp; vs &nbsp; B: {}</div>",
        a_url, b_url
    ));
    s.push_str("<div class=wrap>\n");
    s.push_str("<div class=card><h3>Summary</h3><table>\n");
    s.push_str(&format!(
        "<tr><th>URLs only in A</th><td>{}</td></tr>",
        ab.diff.url_only_in_a.len()
    ));
    s.push_str(&format!(
        "<tr><th>URLs only in B</th><td>{}</td></tr>",
        ab.diff.url_only_in_b.len()
    ));
    s.push_str(&format!(
        "<tr><th>Broken (A)</th><td>{}</td></tr>",
        ab.diff.broken_delta.0
    ));
    s.push_str(&format!(
        "<tr><th>Broken (B)</th><td>{}</td></tr>",
        ab.diff.broken_delta.1
    ));
    s.push_str("</table></div>\n");

    let d = &ab.diff.signals_delta;
    s.push_str("<div class=card><h3>Signals Delta (A - B)</h3><table>");
    s.push_str(&format!(
        "<tr><th>JSON-LD</th><td>{}</td></tr>",
        d.json_ld_blocks
    ));
    s.push_str(&format!(
        "<tr><th>Microdata</th><td>{}</td></tr>",
        d.microdata_items
    ));
    s.push_str(&format!(
        "<tr><th>OpenGraph</th><td>{}</td></tr>",
        d.og_tags
    ));
    s.push_str(&format!(
        "<tr><th>Twitter</th><td>{}</td></tr>",
        d.twitter_tags
    ));
    s.push_str(&format!(
        "<tr><th>Robots pages</th><td>{}</td></tr>",
        d.robots_pages
    ));
    s.push_str(&format!(
        "<tr><th>Canonical pages</th><td>{}</td></tr>",
        d.canonical_pages
    ));
    s.push_str(&format!(
        "<tr><th>Hreflang total</th><td>{}</td></tr>",
        d.hreflang_total
    ));
    s.push_str("</table></div>\n");
    s.push_str("</div>\n");

    s.push_str("<div class=wrap>\n");
    s.push_str("<div class=card><h3>URLs only in A</h3><div class=muted>Top 50</div><ul>");
    for u in ab.diff.url_only_in_a.iter().take(50) {
        s.push_str(&format!("<li>{}</li>", html_escape::encode_text(u)));
    }
    s.push_str("</ul></div>\n");
    s.push_str("<div class=card><h3>URLs only in B</h3><div class=muted>Top 50</div><ul>");
    for u in ab.diff.url_only_in_b.iter().take(50) {
        s.push_str(&format!("<li>{}</li>", html_escape::encode_text(u)));
    }
    s.push_str("</ul></div>\n");
    s.push_str("</div>\n");

    s.push_str("<div class=card><h3>Top Tracker Deltas (A - B)</h3><table><thead><tr><th>Tracker</th><th>Delta</th></tr></thead><tbody>");
    for (k, v) in ab.diff.signals_delta.top_trackers.iter().take(50) {
        s.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape::encode_text(k),
            v
        ));
    }
    s.push_str("</tbody></table></div>");

    s.push_str("</body></html>");
    s
}
