mod crawler;
mod indexer;
mod models;
mod ports;
mod report;
mod util;
mod vuln;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};
use models::{PortsResult, VulnReport};
use std::path::PathBuf;
use std::net::SocketAddr;
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "dexteri", about = "Dexteri++: all-in-one web crawler, link checker, port/vuln scanner, and indexer.")]
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
    },

    /// Launch the web dashboard (local server)
    Web {
        /// Bind address, e.g. 127.0.0.1:5173
        #[arg(short = 'b', long, default_value = "127.0.0.1:5173")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Crawl { url, depth, concurrency, externals, report } => {
            let start = Url::parse(&url)?;
            let client = util::build_client()?;
            let res = crawler::crawl(&client, &start, depth, concurrency, externals).await?;
            println!("Crawled {} pages, checked {} links, broken: {}", res.pages_crawled, res.links_checked, res.broken_links.len());
            if let Some(path) = report { 
                let ports_empty = PortsResult { open_ports: vec![], scanned: 0 };
                let vulns_empty = VulnReport { findings: vec![] };
                report::write_report(&path, &start, &res, &ports_empty, &vulns_empty)?; 
                println!("Report written to {}", path.display());
            }
        }
        Commands::Ports { host, ports, concurrency, timeout_ms } => {
            let ports_vec = ports
                .as_deref()
                .map(ports::parse_ports)
                .transpose()? 
                .unwrap_or_else(ports::common_ports);
            let result = ports::scan_host(&host, &ports_vec, concurrency, timeout_ms).await?;
            println!("Open ports ({} of {} scanned): {:?}", result.open_ports.len(), result.scanned, result.open_ports);
        }
        Commands::Vuln { url } => {
            let target = Url::parse(&url)?;
            let client = util::build_client()?;
            let report_v = vuln::scan(&client, &target).await?;
            for f in &report_v.findings { println!("[{}] {} - {}", f.severity, f.title, f.description); }
        }
        Commands::Index { url, out_dir, depth, externals, concurrency } => {
            let start = Url::parse(&url)?;
            let client = util::build_client()?;
            let crawl = crawler::crawl(&client, &start, depth, concurrency, externals).await?;
            let stats = indexer::index_pages(&out_dir, &crawl.pages).await?;
            println!("Indexed {} documents into {}", stats.docs_indexed, out_dir.display());
        }
        Commands::Search { index_dir, query, limit } => {
            let hits = indexer::search_index(&index_dir, &query, limit)?;
            for (i, h) in hits.iter().enumerate() { println!("{}: {}\n   {}", i+1, h.title.as_deref().unwrap_or("(untitled)"), h.url); }
        }
        Commands::All { url, host, depth, concurrency, externals, ports, port_concurrency, timeout_ms, report } => {
            let start = Url::parse(&url)?;
            let host = host.unwrap_or_else(|| util::host_from_url(&start).unwrap_or_else(|| "localhost".to_string()));
            let client = util::build_client()?;
            let ports_vec = ports
                .as_deref()
                .map(ports::parse_ports)
                .transpose()? 
                .unwrap_or_else(ports::common_ports);

            println!("[1/3] Crawling {} ...", start);
            let crawl_res = crawler::crawl(&client, &start, depth, concurrency, externals).await?;
            println!("[2/3] Port scanning {} ...", host);
            let ports_res = ports::scan_host(&host, &ports_vec, port_concurrency, timeout_ms).await?;
            println!("[3/3] Vulnerability checks {} ...", start);
            let vuln_res = vuln::scan(&client, &start).await?;
            report::write_report(&report, &start, &crawl_res, &ports_res, &vuln_res)?;
            println!("Report written to {}", report.display());
        }
        Commands::Web { bind } => {
            let addr: SocketAddr = bind.parse()?;
            println!("Dexteri++ dashboard listening on http://{}", addr);
            web::serve(addr).await?;
        }
    }

    Ok(())
}
