use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use url::Url;

use crate::{crawler, models::*, ports, report, security, util, vuln};

#[derive(Clone, Default)]
struct AppState {
    inner: Arc<RwLock<InnerState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CombinedResult {
    crawl: CrawlResult,
    ports: PortsResult,
    vuln: VulnReport,
    security: Vec<SecurityFlag>,
}

#[derive(Default)]
struct InnerState {
    running: bool,
    phase: String,
    status: Option<RunStatus>,
    last_report_html: Option<String>,
    last_results: Option<CombinedResult>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RunStatus {
    url: String,
    host: String,
    depth: usize,
    externals: bool,
    // progress
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
struct RunAllParams {
    url: String,
    host: Option<String>,
    depth: Option<usize>,
    concurrency: Option<usize>,
    externals: Option<bool>,
    include_subdomains: Option<bool>,
    ports: Option<String>,
    port_concurrency: Option<usize>,
    timeout_ms: Option<u64>,
    rate_limit_rps: Option<u32>,
}

pub async fn serve(bind: SocketAddr) -> anyhow::Result<()> {
    let state = AppState::default();

    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(get_status))
        .route("/api/results.json", get(get_results_json))
        .route("/api/export", get(export_data))
        .route("/api/run/all", post(run_all))
        .route("/report", get(get_report))
        .route("/charts", get(charts))
        .with_state(state);

    axum::serve(tokio::net::TcpListener::bind(bind).await?, app).await?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    (StatusCode::OK, headers, Html(INDEX_HTML))
}

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.read().await;
    let body = serde_json::to_string(&inner.status).unwrap_or("null".to_string());
    (StatusCode::OK, body)
}

async fn get_report(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.read().await;
    if let Some(html) = &inner.last_report_html {
        (StatusCode::OK, Html(html.clone())).into_response()
    } else {
        (StatusCode::NOT_FOUND, "No report yet").into_response()
    }
}

async fn get_results_json(State(state): State<AppState>) -> impl IntoResponse {
    let inner = state.inner.read().await;
    if let Some(res) = &inner.last_results {
        (StatusCode::OK, Json(res)).into_response()
    } else {
        (StatusCode::NOT_FOUND, "No results yet").into_response()
    }
}

async fn charts() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    (StatusCode::OK, headers, Html(CHARTS_HTML)).into_response()
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    format: String,       // json | xml | csv | html
    kind: Option<String>, // for csv: pages | broken_links | ports | findings
}

async fn export_data(
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    let inner = state.inner.read().await;
    let Some(results) = &inner.last_results else {
        return (StatusCode::NOT_FOUND, "No results to export").into_response();
    };
    match q.format.as_str() {
        "html" => {
            if let Some(html) = &inner.last_report_html {
                let headers = [
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Content-Disposition", "attachment; filename=report.html"),
                ];
                return (StatusCode::OK, headers, html.clone()).into_response();
            }
            (StatusCode::NOT_FOUND, "No report yet").into_response()
        }
        "json" => {
            let headers = [
                ("Content-Type", "application/json"),
                ("Content-Disposition", "attachment; filename=results.json"),
            ];
            (
                StatusCode::OK,
                headers,
                serde_json::to_string_pretty(results).unwrap(),
            )
                .into_response()
        }
        "xml" => {
            let xml = build_xml(results);
            let headers = [
                ("Content-Type", "application/xml"),
                ("Content-Disposition", "attachment; filename=results.xml"),
            ];
            (StatusCode::OK, headers, xml).into_response()
        }
        "csv" => {
            let kind = q.kind.unwrap_or_else(|| "pages".to_string());
            let (name, csv, content_type) = match kind.as_str() {
                "pages" => ("pages.csv", csv_pages(&results.crawl.pages), "text/csv"),
                "broken_links" => (
                    "broken_links.csv",
                    csv_broken(&results.crawl.broken_links),
                    "text/csv",
                ),
                "ports" => ("ports.csv", csv_ports(&results.ports), "text/csv"),
                "findings" => ("findings.csv", csv_findings(&results.vuln), "text/csv"),
                "security" => ("security.csv", csv_security(&results.security), "text/csv"),
                _ => ("pages.csv", csv_pages(&results.crawl.pages), "text/csv"),
            };
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
            headers.insert(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename={}", name).parse().unwrap(),
            );
            (StatusCode::OK, headers, csv).into_response()
        }
        _ => (StatusCode::BAD_REQUEST, "Unsupported format").into_response(),
    }
}

fn csv_escape(s: &str) -> String {
    let needs = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_pages(pages: &Vec<Page>) -> String {
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

fn csv_broken(errs: &Vec<LinkError>) -> String {
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

fn csv_ports(p: &PortsResult) -> String {
    let mut out = String::from("port\n");
    for port in &p.open_ports {
        out.push_str(&format!("{}\n", port));
    }
    out
}

fn csv_findings(v: &VulnReport) -> String {
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

fn csv_security(sec: &Vec<SecurityFlag>) -> String {
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

fn build_xml(r: &CombinedResult) -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<dexteri>\n");
    s.push_str(&format!(
        "  <summary pages=\"{}\" links=\"{}\" broken=\"{}\" ports_open=\"{}\" findings=\"{}\"/>\n",
        r.crawl.pages_crawled,
        r.crawl.links_checked,
        r.crawl.broken_links.len(),
        r.ports.open_ports.len(),
        r.vuln.findings.len()
    ));
    s.push_str("  <pages>\n");
    for p in &r.crawl.pages {
        s.push_str(&format!(
            "    <page url=\"{}\" status=\"{}\" bytes=\"{}\">\n      <title>{}</title>\n      <contentType>{}</contentType>\n    </page>\n",
            xesc(&p.url),
            p.status.map(|v| v.to_string()).unwrap_or_default(),
            p.bytes.map(|v| v.to_string()).unwrap_or_default(),
            xesc(p.title.as_deref().unwrap_or("")),
            xesc(p.content_type.as_deref().unwrap_or("")),
        ));
    }
    s.push_str("  </pages>\n  <brokenLinks>\n");
    for b in &r.crawl.broken_links {
        s.push_str(&format!(
            "    <link url=\"{}\" status=\"{}\" external=\"{}\"><reason>{}</reason><parent>{}</parent></link>\n",
            xesc(&b.url), b.status.map(|v| v.to_string()).unwrap_or_default(), b.external, xesc(&b.reason), xesc(&b.parent)));
    }
    s.push_str("  </brokenLinks>\n  <ports>\n");
    for port in &r.ports.open_ports {
        s.push_str(&format!("    <open>{}</open>\n", port));
    }
    s.push_str("  </ports>\n  <findings>\n");
    for f in &r.vuln.findings {
        s.push_str(&format!(
            "    <finding severity=\"{}\"><title>{}</title><description>{}</description><url>{}</url></finding>\n",
            xesc(&f.severity), xesc(&f.title), xesc(&f.description), xesc(f.url.as_deref().unwrap_or(""))));
    }
    s.push_str("  </findings>\n  <security>\n");
    for f in &r.security {
        s.push_str(&format!("    <flag level=\"{}\"><title>{}</title><description>{}</description><url>{}</url></flag>\n",
            xesc(&f.level), xesc(&f.title), xesc(&f.description), xesc(f.url.as_deref().unwrap_or(""))));
    }
    s.push_str("  </security>\n</dexteri>\n");
    s
}

fn xesc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

async fn run_all(
    State(state): State<AppState>,
    Json(params): Json<RunAllParams>,
) -> impl IntoResponse {
    {
        let mut inner = state.inner.write().await;
        if inner.running {
            return (StatusCode::CONFLICT, "A run is already in progress").into_response();
        }
        println!("POST /api/run/all start: url={}", params.url);
        inner.running = true;
        inner.error = None;
        inner.phase = "starting".to_string();
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

    // Spawn background task
    let state_cl = state.clone();
    tokio::spawn(async move {
        let res = run_pipeline(state_cl.clone(), params).await;
        let mut inner = state_cl.inner.write().await;
        match res {
            Ok(_) => {
                if let Some(st) = inner.status.as_mut() {
                    st.done = true;
                    st.phase = "done".into();
                }
            }
            Err(e) => {
                inner.error = Some(e.to_string());
                if let Some(st) = inner.status.as_mut() {
                    st.phase = "error".into();
                }
            }
        }
        inner.running = false;
    });

    (StatusCode::ACCEPTED, "started").into_response()
}

async fn run_pipeline(state: AppState, params: RunAllParams) -> anyhow::Result<()> {
    println!("run_pipeline begin for {}", params.url);
    let start_url = match Url::parse(&params.url) {
        Ok(u) => u,
        Err(_) => {
            // try with http:// prefix for scheme-less inputs
            let with_http = format!("http://{}", params.url);
            Url::parse(&with_http)?
        }
    };
    let host = match params.host.clone() {
        Some(h) => h,
        None => util::host_from_url(&start_url).unwrap_or_else(|| "localhost".to_string()),
    };
    let depth = params.depth.unwrap_or(2);
    let concurrency = params.concurrency.unwrap_or(32);
    let externals = params.externals.unwrap_or(false);
    let include_subdomains = params.include_subdomains.unwrap_or(false);
    let ports_spec = params
        .ports
        .as_deref()
        .map(ports::parse_ports)
        .transpose()?;
    let ports_vec = ports_spec.unwrap_or_else(ports::common_ports);
    let port_concurrency = params.port_concurrency.unwrap_or(512);
    let timeout_ms = params.timeout_ms.unwrap_or(800);

    let client = util::build_client()?;

    // Crawl
    {
        let mut inner = state.inner.write().await;
        inner.phase = "crawl".into();
        if let Some(st) = inner.status.as_mut() {
            st.phase = "crawl".into();
        }
    }
    let crawl_res = crawler::crawl_with_logs(
        &client,
        &start_url,
        depth,
        concurrency,
        externals,
        include_subdomains,
        None,
        None,
        None,
        params.rate_limit_rps,
    )
    .await?;
    {
        let mut inner = state.inner.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.pages_crawled = crawl_res.pages_crawled;
            st.links_checked = crawl_res.links_checked;
            st.broken_links = crawl_res.broken_links.len();
        }
    }

    // Ports
    {
        let mut inner = state.inner.write().await;
        inner.phase = "ports".into();
        if let Some(st) = inner.status.as_mut() {
            st.phase = "ports".into();
        }
    }
    let ports_res = ports::scan_host(&host, &ports_vec, port_concurrency, timeout_ms, None).await?;
    {
        let mut inner = state.inner.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.ports_scanned = ports_res.scanned;
            st.ports_open = ports_res.open_ports.len();
        }
    }

    // Vuln
    {
        let mut inner = state.inner.write().await;
        inner.phase = "vuln".into();
        if let Some(st) = inner.status.as_mut() {
            st.phase = "vuln".into();
        }
    }
    let vuln_res = vuln::scan(&client, &start_url).await?;
    {
        let mut inner = state.inner.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.vuln_findings = vuln_res.findings.len();
        }
    }

    // Security posture (passive checks)
    {
        let mut inner = state.inner.write().await;
        inner.phase = "security".into();
        if let Some(st) = inner.status.as_mut() {
            st.phase = "security".into();
        }
    }
    let security_flags = match security::check_security_posture(&client, &start_url).await {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };

    // Report: write to a writable temp file and capture contents
    let tmp_name = format!(
        "dexteri-report-{}.html",
        chrono::Local::now().format("%Y%m%d%H%M%S")
    );
    let path = std::env::temp_dir().join(tmp_name);
    report::write_report(
        &path,
        &start_url,
        &crawl_res,
        &ports_res,
        &vuln_res,
        &security_flags,
    )?;
    let html = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    let _ = tokio::fs::remove_file(&path).await;

    {
        let mut inner = state.inner.write().await;
        inner.last_report_html = Some(html);
        inner.last_results = Some(CombinedResult {
            crawl: crawl_res,
            ports: ports_res,
            vuln: vuln_res,
            security: security_flags,
        });
    }

    Ok(())
}

static INDEX_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dexteri++ Dashboard</title>
<style>
:root{--bg:#0b1020;--panel:#0e1426;--card:#121a2d;--text:#E6EDF3;--muted:#9FB1C5;--accent:#6EE7B7;--blue:#93c5fd;--warn:#F59E0B;--err:#EF4444;--border:#1e2a47}
html,body{height:100%}
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;background:linear-gradient(320deg,#081022,#0b1228 50%,#081022);color:var(--text)}
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;background:linear-gradient(90deg,rgba(14,20,38,.85),rgba(14,20,38,.65));backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}
.topbar h1{margin:0;font-size:1.05rem;letter-spacing:.3px}
.controls{display:grid;gap:.75rem;grid-template-columns:repeat(12,1fr);padding:1rem;border-bottom:1px solid var(--border);background:linear-gradient(90deg,rgba(16,24,42,.65),rgba(16,24,42,.35));position:relative;z-index:3}
.controls .cell{display:flex;flex-direction:column;gap:.35rem}
label{font-size:.82rem;color:var(--muted)}
input[type=text],input[type=number]{width:100%;padding:.55rem .65rem;border-radius:8px;border:1px solid var(--border);background:#0a1020;color:var(--text)}
input[type=checkbox]{transform:scale(1.05)}
button,.btn{background:linear-gradient(135deg,#22c55e,#16a34a);border:none;color:#05210d;padding:.6rem .85rem;border-radius:10px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:.4rem}
button[disabled]{opacity:.6;cursor:not-allowed}
.btn.secondary{background:linear-gradient(135deg,#60a5fa,#3b82f6);color:#05152b}
.btn.ghost{background:transparent;border:1px solid var(--border);color:#b9d5f3}
.status{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;padding:1rem;background:linear-gradient(90deg,rgba(10,16,32,.35),rgba(10,16,32,.15));position:relative;z-index:2}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:.8rem}
.kpi b{display:block;color:var(--muted);font-weight:600}
.kpi .v{font-size:1.35rem;margin-top:.25rem;color:#cfe6ff}
.tabs{display:flex;gap:.5rem;padding:.6rem 1rem;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:linear-gradient(90deg,rgba(10,16,32,.45),rgba(10,16,32,.25));position:relative;z-index:2}
.tab{padding:.45rem .8rem;border:1px solid var(--border);border-radius:999px;background:#0f1526;color:#b9d5f3;cursor:pointer}
.tab.active{background:linear-gradient(135deg,#6EE7B7,#93c5fd);color:#05152b;border-color:transparent}
.table-wrap{width:100vw;overflow:auto;padding:1rem;position:relative;z-index:2}
table{width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed;background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
thead th{position:sticky;top:0;background:#0f172a;border-bottom:1px solid var(--border);z-index:1}
th,td{padding:.6rem .6rem;border-right:1px solid var(--border)}
th:last-child,td:last-child{border-right:none}
tbody tr:nth-child(even){background:rgba(255,255,255,.02)}
.trunc{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wrap td{white-space:normal;word-break:break-word}
.row-controls{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;padding:0 1rem 1rem;position:relative;z-index:2}
.spacer{flex:1}
.export{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap}
.export select{padding:.4rem .5rem;border-radius:8px;border:1px solid var(--border);background:#0a1020;color:var(--text)}
.filter{display:flex;align-items:center;gap:.5rem}
.filter input{min-width:280px}
.err{color:var(--err)}
.muted{color:var(--muted)}
.footer{padding:1rem 1rem 2rem;color:#8aa2c4}
.link{color:var(--blue)}
</style>
</head>
<body>
<div class="topbar">
  <svg width="26" height="26" viewBox="0 0 24 24" fill="#6EE7B7"><path d="M12 20a8 8 0 1 1 0-16 8 8 0 0 1 0 16m0-18a10 10 0 1 0 0 20 10 10 0 0 0 0-20M7 10h10v2H7z"/></svg>
  <h1>Dexteri++ Dashboard</h1>
  <span class="spacer"></span>
  <span id="phase" class="muted">idle</span>
</div>

<form id="f" onsubmit="return runAll(event)">
  <div class="controls">
    <div class="cell" style="grid-column:span 3"><label>URL</label><input id="url" type="text" placeholder="https://example.com" required></div>
    <div class="cell" style="grid-column:span 2"><label>Host (optional)</label><input id="host" type="text" placeholder="example.com"></div>
    <div class="cell"><label>Depth</label><input id="depth" type="number" min="0" value="2"></div>
    <div class="cell"><label>HTTP Concurrency</label><input id="concurrency" type="number" min="1" value="32"></div>
    <div class="cell"><label>Requests per second (optional)</label><input id="rate_limit_rps" type="number" min="1" placeholder="unset"></div>
    <div class="cell" style="grid-column:span 2"><label>Port Spec</label><input id="ports" type="text" placeholder="1-1024,3306,5432"></div>
    <div class="cell"><label>Port Concurrency</label><input id="port_concurrency" type="number" min="1" value="512"></div>
    <div class="cell"><label>Port Timeout (ms)</label><input id="timeout_ms" type="number" min="100" value="800"></div>
    <div class="cell" style="display:flex;align-items:center;gap:.5rem"><input id="externals" type="checkbox"><label style="margin:0">Validate external links</label></div>
    <div class="cell" style="display:flex;align-items:center;gap:.35rem"><input id="include_subdomains" type="checkbox">Include subdomains</div>
    <div class="cell" style="display:flex;align-items:flex-end"><button id="run" type="submit">Run All</button></div>
  </div>
</form>

<div class="status">
    <div class="kpi"><b>Pages</b><div class="v" id="k_pages">0</div></div>
    <div class="kpi"><b>Links Checked</b><div class="v" id="k_links">0</div></div>
    <div class="kpi"><b>Broken</b><div class="v" id="k_broken">0</div></div>
    <div class="kpi"><b>Ports Open</b><div class="v" id="k_open">0</div></div>
    <div class="kpi"><b>Findings</b><div class="v" id="k_findings">0</div></div>
  </div>

<div class="tabs">
  <div class="tab active" data-view="pages" onclick="switchView('pages', this)">Pages</div>
  <div class="tab" data-view="broken" onclick="switchView('broken', this)">Broken Links</div>
  <div class="tab" data-view="ports" onclick="switchView('ports', this)">Ports</div>
  <div class="tab" data-view="findings" onclick="switchView('findings', this)">Findings</div>
  <span class="spacer"></span>
  <div class="filter">
    <label class="muted">Filter</label>
    <input id="filter" type="text" placeholder="Type to filter rows..." oninput="applyFilter()"/>
    <label style="display:flex;align-items:center;gap:.35rem"><input id="wrapToggle" type="checkbox" onchange="toggleWrap()">Wrap cells</label>
  </div>
</div>

<div class="row-controls">
  <div class="export">
    <span class="muted">Export:</span>
    <a class="btn ghost" href="/api/export?format=html">HTML</a>
    <a class="btn ghost" href="/api/export?format=json">JSON</a>
    <a class="btn ghost" href="/api/export?format=xml">XML</a>
    <select id="csvKind">
      <option value="pages">CSV: Pages</option>
      <option value="broken_links">CSV: Broken Links</option>
      <option value="ports">CSV: Ports</option>
      <option value="findings">CSV: Findings</option>
      <option value="security">CSV: Security</option>
    </select>
    <button class="btn secondary" onclick="exportCsv(event)">Download CSV</button>
  </div>
  <span class="spacer"></span>
  <a class="link" href="/report" target="_blank">Open full report</a>
  <span id="error" class="err"></span>
</div>

<div id="tableHost" class="table-wrap">
  <table id="dataTable"><thead></thead><tbody></tbody></table>
</div>

<p class="footer">Generated by Dexteri++</p>

<script>
let pollHandle = null;
let currentView = 'pages';
let cachedResults = null;
let isRunning = false;

function v(id){
  const el = document.getElementById(id);
  if(!el || el.value == null) return undefined;
  const x = (''+el.value).trim();
  return x.length ? x : undefined;
}
function num(id){
  const el = document.getElementById(id);
  if(!el || el.value == null) return undefined;
  const n = parseInt(el.value, 10);
  return Number.isFinite(n) ? n : undefined;
}
async function runAll(ev){
  ev.preventDefault();
  document.getElementById('error').textContent = '';
  console.log('Submitting run-all...');
  if(isRunning){ console.log('Run already in progress, ignoring.'); return false; }
  let payload;
  try {
    payload = {
      url: document.getElementById('url').value.trim(),
      host: v("host"),
      depth: num("depth"),
      concurrency: num("concurrency"),
      rate_limit_rps: num("rate_limit_rps"),
      externals: document.getElementById('externals').checked,
      include_subdomains: document.getElementById('include_subdomains').checked,
      ports: v("ports"),
      port_concurrency: num("port_concurrency"),
      timeout_ms: num("timeout_ms")
    };
  } catch(e) {
    console.error('Error building payload', e);
    document.getElementById('error').textContent = 'Error building request: '+e;
    return false;
  }
  try {
    const res = await fetch('/api/run/all', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    if(!res.ok){
      document.getElementById('error').textContent = await res.text();
      return;
    }
    document.getElementById('phase').textContent = 'starting';
    isRunning = true;
    const btn = document.getElementById('run');
    if(btn) btn.disabled = true;
    if(pollHandle) clearInterval(pollHandle);
    pollHandle = setInterval(poll, 1000);
  } catch(e) { console.error(e); }
  return false;
}

async function loadResults(){
  const r = await fetch('/api/results.json');
  if(!r.ok) return;
  cachedResults = await r.json();
  renderTable();
}

async function poll(){
  try{
    const res = await fetch('/api/status');
    const st = await res.json();
    if(!st){ return; }
    document.getElementById('phase').textContent = st.phase || 'idle';
    document.getElementById('k_pages').textContent = st.pages_crawled;
    document.getElementById('k_links').textContent = st.links_checked;
    document.getElementById('k_broken').textContent = st.broken_links;
    document.getElementById('k_open').textContent = st.ports_open;
    document.getElementById('k_findings').textContent = st.vuln_findings;
    if(st.done){
      clearInterval(pollHandle);
      await loadResults();
      isRunning = false;
      const btn = document.getElementById('run');
      if(btn) btn.disabled = false;
    }
  }catch(e){ console.error(e); }
}

function renderTable(){
  if(!cachedResults) return;
  const table = document.getElementById('dataTable');
  const th = table.querySelector('thead');
  const tb = table.querySelector('tbody');
  th.innerHTML = '';
  tb.innerHTML = '';
  if(currentView==='pages'){
    th.innerHTML = '<tr><th style="width:44px">#</th><th>URL</th><th>Status</th><th>Title</th><th>Content-Type</th><th>Bytes</th></tr>';
    cachedResults.crawl.pages.forEach((p,i)=>{
      tb.innerHTML += `<tr><td>${i+1}</td><td class="trunc" title="${esc(p.url)}">${esc(p.url)}</td><td>${p.status??''}</td><td class="trunc" title="${esc(p.title||'')}">${esc(p.title||'')}</td><td class="trunc" title="${esc(p.content_type||'')}">${esc(p.content_type||'')}</td><td>${p.bytes??''}</td></tr>`;
    });
  } else if(currentView==='broken'){
    th.innerHTML = '<tr><th style="width:44px">#</th><th>URL</th><th>Status</th><th>Reason</th><th>Parent</th><th>External</th></tr>';
    cachedResults.crawl.broken_links.forEach((b,i)=>{
      tb.innerHTML += `<tr><td>${i+1}</td><td class="trunc" title="${esc(b.url)}">${esc(b.url)}</td><td>${b.status??''}</td><td class="trunc" title="${esc(b.reason)}">${esc(b.reason)}</td><td class="trunc" title="${esc(b.parent)}">${esc(b.parent)}</td><td>${b.external}</td></tr>`;
    });
  } else if(currentView==='ports'){
    th.innerHTML = '<tr><th style="width:44px">#</th><th>Open Port</th></tr>';
    cachedResults.ports.open_ports.forEach((p,i)=>{
      tb.innerHTML += `<tr><td>${i+1}</td><td>${p}</td></tr>`;
    });
  } else if(currentView==='findings'){
    th.innerHTML = '<tr><th style="width:44px">#</th><th>Severity</th><th>Title</th><th>Description</th><th>URL</th></tr>';
    cachedResults.vuln.findings.forEach((f,i)=>{
      tb.innerHTML += `<tr><td>${i+1}</td><td>${esc(f.severity)}</td><td class="trunc" title="${esc(f.title)}">${esc(f.title)}</td><td class="trunc" title="${esc(f.description)}">${esc(f.description)}</td><td class="trunc" title="${esc(f.url||'')}">${esc(f.url||'')}</td></tr>`;
    });
  } else if(currentView==='security'){
    th.innerHTML = '<tr><th style="width:44px">#</th><th>Level</th><th>Title</th><th>Description</th><th>URL</th></tr>';
    cachedResults.security.forEach((f,i)=>{
      tb.innerHTML += `<tr><td>${i+1}</td><td>${esc(f.level)}</td><td class="trunc" title="${esc(f.title)}">${esc(f.title)}</td><td class="trunc" title="${esc(f.description)}">${esc(f.description)}</td><td class="trunc" title="${esc(f.url||'')}">${esc(f.url||'')}</td></tr>`;
    });
  }
  applyFilter();
}

function esc(s){
  return (s||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function switchView(v, el){
  currentView = v;
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  if(el) el.classList.add('active');
  renderTable();
}

function applyFilter(){
  const q = document.getElementById('filter').value.trim().toLowerCase();
  const rows = document.querySelectorAll('#dataTable tbody tr');
  rows.forEach(row=>{
    if(!q){ row.style.display=''; return; }
    const txt = row.innerText.toLowerCase();
    row.style.display = txt.includes(q)?'':'none';
  });
}

function toggleWrap(){
  const checked = document.getElementById('wrapToggle').checked;
  const host = document.getElementById('tableHost');
  if(checked) host.classList.add('wrap'); else host.classList.remove('wrap');
}

function exportCsv(ev){
  ev.preventDefault();
  const kind = document.getElementById('csvKind').value;
  window.open('/api/export?format=csv&kind='+encodeURIComponent(kind),'_blank');
}

// Ensure handlers are bound even if inline attributes are ignored
window.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('f');
  if(form){ form.addEventListener('submit', runAll); }
  const btn = document.getElementById('run');
  if(btn){ btn.addEventListener('click', runAll); }
});
</script>
</body>
</html>
"###;

static CHARTS_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Dexteri++ Charts</title>
  <script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
  <style> body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;margin:1rem} .wrap{display:grid;grid-template-columns:1fr;gap:1rem} .card{border:1px solid #ddd;border-radius:8px;padding:1rem} </style>
</head>
<body>
  <h2>Dexteri++ Charts</h2>
  <p class="muted">Fetches /api/results.json and renders basic charts for marketing signals and top trackers.</p>
  <div class="wrap">
    <div class="card"><div id="chart_signals"></div></div>
    <div class="card"><div id="chart_trackers"></div></div>
  </div>
  <script>
    async function load(){
      try{
        const r = await fetch('/api/results.json'); if(!r.ok) return;
        const data = await r.json();
        const pages = data.crawl?.pages||[];
        let jsonld=0,micro=0,og=0,tw=0,robots=0,canon=0,hl=0;
        const trackerCounts = new Map();
        for(const p of pages){
          const s=p.signals||{};
          jsonld += s.json_ld_blocks||0; micro += s.microdata_items||0; og += s.open_graph_tags||0; tw += s.twitter_tags||0;
          if((s.meta_robots||'').length>0) robots++;
          if((s.canonical_url||'').length>0) canon++;
          hl += s.hreflang_count||0;
          for(const t of (s.trackers||[])){ trackerCounts.set(t, (trackerCounts.get(t)||0)+1); }
        }
        Plotly.newPlot('chart_signals', [{
          x:['JSON-LD','Microdata','OpenGraph','Twitter','Robots','Canonical','Hreflang'], y:[jsonld,micro,og,tw,robots,canon,hl], type:'bar'
        }], {title:'Marketing Signals Totals'});
        const arr = Array.from(trackerCounts.entries()).sort((a,b)=>b[1]-a[1]).slice(0,10);
        Plotly.newPlot('chart_trackers', [{ x: arr.map(a=>a[0]), y: arr.map(a=>a[1]), type:'bar' }], { title:'Top Trackers (pages)' });
      }catch(e){ console.error(e); }
    }
    load();
  </script>
</body>
</html>
"###;
