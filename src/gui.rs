use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::RwLock;
use url::Url;

use dexteri::{crawler, models::*, ports, report, util, vuln};

#[derive(Clone, Default)]
struct AppState {
    inner: Arc<RwLock<InnerState>>,
}

#[tauri::command]
fn open_in_browser(app: tauri::AppHandle, url: String) -> Result<(), String> {
    tauri::api::shell::open(&app.shell_scope(), url, None).map_err(|e| e.to_string())
}

#[derive(Default)]
struct InnerState {
    running: bool,
    status: Option<RunStatus>,
    last_results: Option<CombinedResult>,
    last_report_html: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunStatus {
    url: String,
    host: String,
    depth: usize,
    externals: bool,
    pages_crawled: usize,
    links_checked: usize,
    broken_links: usize,
    ports_scanned: usize,
    ports_open: usize,
    vuln_findings: usize,
    phase: String,
    done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedResult {
    crawl: CrawlResult,
    ports: PortsResult,
    vuln: VulnReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAllParams {
    url: String,
    host: Option<String>,
    depth: Option<usize>,
    concurrency: Option<usize>,
    externals: Option<bool>,
    ports: Option<String>,
    port_concurrency: Option<usize>,
    timeout_ms: Option<u64>,
}

#[tauri::command]
async fn run_all(params: RunAllParams, state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut inner = state.inner.write().await;
        if inner.running {
            return Err("A run is already in progress".into());
        }
        inner.running = true;
        inner.status = Some(RunStatus {
            url: params.url.clone(),
            host: params.host.clone().unwrap_or_default(),
            depth: params.depth.unwrap_or(2),
            externals: params.externals.unwrap_or(false),
            pages_crawled: 0,
            links_checked: 0,
            broken_links: 0,
            ports_scanned: 0,
            ports_open: 0,
            vuln_findings: 0,
            phase: "starting".into(),
            done: false,
        });
    }

    let state_arc = state.inner.clone();
    let state_for_task = state_arc.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_pipeline(state_for_task, params).await {
            let mut inner = state_arc.write().await;
            if let Some(st) = inner.status.as_mut() {
                st.phase = format!("error: {}", e);
                st.done = true;
            }
            inner.running = false;
        }
    });

    Ok(())
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<Option<RunStatus>, String> {
    let inner = state.inner.read().await;
    Ok(inner.status.clone())
}

#[tauri::command]
async fn get_results(state: State<'_, AppState>) -> Result<Option<CombinedResult>, String> {
    let inner = state.inner.read().await;
    Ok(inner.last_results.clone())
}

#[tauri::command]
async fn get_report_html(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let inner = state.inner.read().await;
    Ok(inner.last_report_html.clone())
}

#[tauri::command]
async fn export_data(format: String, kind: Option<String>, state: State<'_, AppState>) -> Result<(String, String, String), String> {
    // returns (filename, mime, content)
    let inner = state.inner.read().await;
    let Some(results) = &inner.last_results else { return Err("No results".into()); };
    match format.as_str() {
        "html" => {
            if let Some(html) = &inner.last_report_html {
                Ok(("report.html".into(), "text/html; charset=utf-8".into(), html.clone()))
            } else {
                Err("No report yet".into())
            }
        }
        "json" => Ok(("results.json".into(), "application/json".into(), serde_json::to_string_pretty(results).map_err(|e| e.to_string())?)),
        "xml" => Ok(("results.xml".into(), "application/xml".into(), build_xml(results))),
        "csv" => {
            let k = kind.unwrap_or_else(|| "pages".into());
            let (name, content) = match k.as_str() {
                "pages" => ("pages.csv", csv_pages(&results.crawl.pages)),
                "broken_links" => ("broken_links.csv", csv_broken(&results.crawl.broken_links)),
                "ports" => ("ports.csv", csv_ports(&results.ports)),
                "findings" => ("findings.csv", csv_findings(&results.vuln)),
                _ => ("pages.csv", csv_pages(&results.crawl.pages)),
            };
            Ok((name.into(), "text/csv".into(), content))
        }
        _ => Err("Unsupported format".into()),
    }
}

fn csv_escape(s: &str) -> String { let needs = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r'); if needs { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() } }
fn csv_pages(pages: &Vec<Page>) -> String { let mut out = String::from("url,status,title,content_type,bytes\n"); for p in pages { let url = csv_escape(&p.url); let status = p.status.map(|s| s.to_string()).unwrap_or_default(); let title = csv_escape(p.title.as_deref().unwrap_or("")); let ct = csv_escape(p.content_type.as_deref().unwrap_or("")); let bytes = p.bytes.map(|b| b.to_string()).unwrap_or_default(); out.push_str(&format!("{},{},{},{},{}\n", url, status, title, ct, bytes)); } out }
fn csv_broken(errs: &Vec<LinkError>) -> String { let mut out = String::from("url,status,reason,parent,external\n"); for e in errs { let url = csv_escape(&e.url); let status = e.status.map(|s| s.to_string()).unwrap_or_default(); let reason = csv_escape(&e.reason); let parent = csv_escape(&e.parent); let external = e.external.to_string(); out.push_str(&format!("{},{},{},{},{}\n", url, status, reason, parent, external)); } out }
fn csv_ports(p: &PortsResult) -> String { let mut out = String::from("port\n"); for port in &p.open_ports { out.push_str(&format!("{}\n", port)); } out }
fn csv_findings(v: &VulnReport) -> String { let mut out = String::from("title,description,severity,url\n"); for f in &v.findings { let title = csv_escape(&f.title); let desc = csv_escape(&f.description); let sev = csv_escape(&f.severity); let url = csv_escape(f.url.as_deref().unwrap_or("")); out.push_str(&format!("{},{},{},{}\n", title, desc, sev, url)); } out }

fn build_xml(r: &CombinedResult) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<dexteri>\n");
    s.push_str(&format!("  <summary pages=\"{}\" links=\"{}\" broken=\"{}\" ports_open=\"{}\" findings=\"{}\"/>\n", r.crawl.pages_crawled, r.crawl.links_checked, r.crawl.broken_links.len(), r.ports.open_ports.len(), r.vuln.findings.len()));
    s.push_str("  <pages>\n");
    for p in &r.crawl.pages { s.push_str(&format!("    <page url=\"{}\" status=\"{}\" bytes=\"{}\"><title>{}</title><contentType>{}</contentType></page>\n", xesc(&p.url), p.status.map(|v| v.to_string()).unwrap_or_default(), p.bytes.map(|v| v.to_string()).unwrap_or_default(), xesc(p.title.as_deref().unwrap_or("")), xesc(p.content_type.as_deref().unwrap_or("")))); }
    s.push_str("  </pages>\n  <brokenLinks>\n");
    for b in &r.crawl.broken_links { s.push_str(&format!("    <link url=\"{}\" status=\"{}\" external=\"{}\"><reason>{}</reason><parent>{}</parent></link>\n", xesc(&b.url), b.status.map(|v| v.to_string()).unwrap_or_default(), b.external, xesc(&b.reason), xesc(&b.parent))); }
    s.push_str("  </brokenLinks>\n  <ports>\n");
    for port in &r.ports.open_ports { s.push_str(&format!("    <open>{}</open>\n", port)); }
    s.push_str("  </ports>\n  <findings>\n");
    for f in &r.vuln.findings { s.push_str(&format!("    <finding severity=\"{}\"><title>{}</title><description>{}</description><url>{}</url></finding>\n", xesc(&f.severity), xesc(&f.title), xesc(&f.description), xesc(f.url.as_deref().unwrap_or("")))); }
    s.push_str("  </findings>\n</dexteri>\n");
    s
}
fn xesc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;") }

async fn run_pipeline(state: Arc<RwLock<InnerState>>, params: RunAllParams) -> anyhow::Result<()> {
    let start_url = match Url::parse(&params.url) {
        Ok(u) => u,
        Err(_) => Url::parse(&format!("http://{}", params.url))?,
    };
    let host = match params.host.clone() { Some(h) => h, None => util::host_from_url(&start_url).unwrap_or_else(|| "localhost".to_string()) };
    let depth = params.depth.unwrap_or(2);
    let concurrency = params.concurrency.unwrap_or(32);
    let externals = params.externals.unwrap_or(false);
    let ports_spec = params.ports.as_deref().map(ports::parse_ports).transpose()?;
    let ports_vec = ports_spec.unwrap_or_else(ports::common_ports);
    let port_concurrency = params.port_concurrency.unwrap_or(512);
    let timeout_ms = params.timeout_ms.unwrap_or(800);

    let client = util::build_client()?;

    // Crawl
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() { st.phase = "crawl".into(); }
    }
    let crawl_res = crawler::crawl(&client, &start_url, depth, concurrency, externals).await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.pages_crawled = crawl_res.pages_crawled;
            st.links_checked = crawl_res.links_checked;
            st.broken_links = crawl_res.broken_links.len();
        }
    }

    // Ports
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() { st.phase = "ports".into(); }
    }
    let ports_res = ports::scan_host(&host, &ports_vec, port_concurrency, timeout_ms).await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.ports_scanned = ports_res.scanned;
            st.ports_open = ports_res.open_ports.len();
        }
    }

    // Vuln
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() { st.phase = "vuln".into(); }
    }
    let vuln_res = vuln::scan(&client, &start_url).await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() { st.vuln_findings = vuln_res.findings.len(); }
    }

    // Report
    let path = std::path::PathBuf::from("report.html");
    report::write_report(&path, &start_url, &crawl_res, &ports_res, &vuln_res)?;
    let html = tokio::fs::read_to_string(&path).await.unwrap_or_default();

    {
        let mut inner = state.write().await;
        inner.last_report_html = Some(html);
        inner.last_results = Some(CombinedResult { crawl: crawl_res, ports: ports_res, vuln: vuln_res });
        if let Some(st) = inner.status.as_mut() { st.phase = "done".into(); st.done = true; }
        inner.running = false;
    }

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![run_all, get_status, get_results, get_report_html, export_data, open_in_browser])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
