use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use chrono::Local;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};
use url::Url;

use dexteri::{crawler, models::*, ports, report, security, util, vuln, web};

#[derive(Clone, Default)]
struct AppState {
    inner: Arc<RwLock<InnerState>>,
}

#[tauri::command]
fn open_in_browser(app: tauri::AppHandle, url: String) -> Result<(), String> {
    tauri::api::shell::open(&app.shell_scope(), url, None).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let inner = state.inner.read().await;
    Ok(inner.logs.clone())
}

#[tauri::command]
async fn clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.write().await;
    inner.logs.clear();
    Ok(())
}

struct InnerState {
    running: bool,
    status: Option<RunStatus>,
    last_results: Option<CombinedResult>,
    last_report_html: Option<String>,
    logs: Vec<String>,
    web_ui_running: bool,
    web_ui_addr: Option<String>,
    cancel_flag: Arc<AtomicBool>,
    // AB mode
    last_ab_result: Option<AbResult>,
    ab_progress: Option<AbProgress>,
}

impl Default for InnerState {
    fn default() -> Self {
        Self {
            running: false,
            status: None,
            last_results: None,
            last_report_html: None,
            logs: Vec::new(),
            web_ui_running: false,
            web_ui_addr: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            last_ab_result: None,
            ab_progress: None,
        }
    }
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
    queue_size: usize,
    in_flight: usize,
    phase: String,
    done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedResult {
    crawl: CrawlResult,
    ports: PortsResult,
    vuln: VulnReport,
    security: Vec<SecurityFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAllParams {
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

// A/B parameters (two independent run configs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAbParams {
    a: RunAllParams,
    b: RunAllParams,
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
async fn get_web_ui_url(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let inner = state.inner.read().await;
    Ok(inner.web_ui_addr.as_ref().map(|s| format!("http://{}", s)))
}

#[tauri::command]
async fn start_web_ui(bind: Option<String>, state: State<'_, AppState>) -> Result<String, String> {
    let addr_s = bind.unwrap_or_else(|| "127.0.0.1:5173".to_string());
    // Avoid double-start
    {
        let mut inner = state.inner.write().await;
        if inner.web_ui_running && inner.web_ui_addr.as_deref() == Some(addr_s.as_str()) {
            return Ok(format!("http://{}", addr_s));
        }
        inner.web_ui_running = true;
        inner.web_ui_addr = Some(addr_s.clone());
        push_log(&mut inner, &format!("Starting Web UI at http://{}", addr_s));
    }
    let addr_clone = addr_s.clone();
    tauri::async_runtime::spawn(async move {
        let parsed: Result<std::net::SocketAddr, _> = addr_clone.parse();
        match parsed {
            Ok(addr) => {
                if let Err(e) = web::serve(addr).await {
                    eprintln!("Web UI server error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Invalid bind address '{}': {}", addr_clone, e);
            }
        }
    });
    Ok(format!("http://{}", addr_s))
}

#[tauri::command]
async fn export_data(
    format: String,
    kind: Option<String>,
    state: State<'_, AppState>,
) -> Result<(String, String, String), String> {
    // returns (filename, mime, content)
    let inner = state.inner.read().await;
    let Some(results) = &inner.last_results else {
        return Err("No results".into());
    };
    match format.as_str() {
        "html" => {
            if let Some(html) = &inner.last_report_html {
                Ok((
                    "report.html".into(),
                    "text/html; charset=utf-8".into(),
                    html.clone(),
                ))
            } else {
                Err("No report yet".into())
            }
        }
        "json" => {
            let json = serde_json::to_string_pretty(results).map_err(|e| e.to_string())?;
            Ok(("results.json".into(), "application/json".into(), json))
        }
        "xml" => {
            let xml = build_xml(results);
            Ok(("results.xml".into(), "application/xml".into(), xml))
        }
        "csv" => {
            let (name, content) = match kind.as_deref().unwrap_or("pages") {
                "pages" => ("pages.csv", csv_pages(&results.crawl.pages)),
                "broken_links" => ("broken_links.csv", csv_broken(&results.crawl.broken_links)),
                "ports" => ("ports.csv", csv_ports(&results.ports)),
                "findings" => ("findings.csv", csv_findings(&results.vuln)),
                "signals" => ("marketing_signals.csv", csv_signals(&results.crawl.pages)),
                "security" => ("security.csv", csv_security(&results.security)),
                _ => ("pages.csv", csv_pages(&results.crawl.pages)),
            };
            Ok((name.into(), "text/csv".into(), content))
        }
        _ => Err("Unsupported format".into()),
    }
}

#[tauri::command]
async fn run_all(params: RunAllParams, state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut inner = state.inner.write().await;
        if inner.running {
            return Err("A run is already in progress".into());
        }
        inner.running = true;
        inner.cancel_flag.store(false, Ordering::Relaxed);
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
            queue_size: 0,
            in_flight: 0,
            phase: "starting".into(),
            done: false,
        });
        inner.logs.clear();
        let (h, d, ex) = {
            let st = inner.status.as_ref().unwrap();
            (st.host.clone(), st.depth, st.externals)
        };
        push_log(
            &mut inner,
            &format!(
                "Starting run: url={} host={} depth={} externals={}",
                params.url, h, d, ex
            ),
        );
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
            push_log(&mut inner, &format!("Error: {}", e));
            inner.running = false;
        }
    });

    Ok(())
}

// A/B run entrypoint
#[tauri::command]
async fn run_ab(params: RunAbParams, state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut inner = state.inner.write().await;
        if inner.running {
            return Err("A run is already in progress".into());
        }
        inner.running = true;
        inner.cancel_flag.store(false, Ordering::Relaxed);
        inner.status = Some(RunStatus {
            url: format!("A: {} | B: {}", params.a.url, params.b.url),
            host: format!(
                "{} | {}",
                params.a.host.clone().unwrap_or_default(),
                params.b.host.clone().unwrap_or_default()
            ),
            depth: params.a.depth.unwrap_or(2),
            externals: params.a.externals.unwrap_or(false),
            pages_crawled: 0,
            links_checked: 0,
            broken_links: 0,
            ports_scanned: 0,
            ports_open: 0,
            vuln_findings: 0,
            queue_size: 0,
            in_flight: 0,
            phase: "ab: starting".into(),
            done: false,
        });
        inner.logs.clear();
        inner.ab_progress = Some(AbProgress::default());
        inner.last_ab_result = None;
        push_log(
            &mut inner,
            &format!("Starting AB run: A={} B={}", params.a.url, params.b.url),
        );
    }

    let state_arc = state.inner.clone();
    let state_for_task = state_arc.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_ab_pipeline(state_for_task, params).await {
            let mut inner = state_arc.write().await;
            if let Some(st) = inner.status.as_mut() {
                st.phase = format!("error: {}", e);
                st.done = true;
            }
            push_log(&mut inner, &format!("Error: {}", e));
            inner.running = false;
        }
    });

    Ok(())
}

#[tauri::command]
async fn get_ab_result(state: State<'_, AppState>) -> Result<Option<AbResult>, String> {
    let inner = state.inner.read().await;
    Ok(inner.last_ab_result.clone())
}

#[tauri::command]
async fn get_ab_progress(state: State<'_, AppState>) -> Result<Option<AbProgress>, String> {
    let inner = state.inner.read().await;
    Ok(inner.ab_progress.clone())
}

async fn run_pipeline(state: Arc<RwLock<InnerState>>, params: RunAllParams) -> anyhow::Result<()> {
    let start_url = match Url::parse(&params.url) {
        Ok(u) => u,
        Err(_) => Url::parse(&format!("http://{}", params.url))?,
    };
    let host = match params.host.clone() {
        Some(h) => h,
        None => util::host_from_url(&start_url).unwrap_or_else(|| "localhost".to_string()),
    };
    let depth = params.depth.unwrap_or(2);
    let concurrency = params.concurrency.unwrap_or(32);
    let externals = params.externals.unwrap_or(false);
    let include_subdomains = params.include_subdomains.unwrap_or(false);

    let client = util::build_client()?;

    // Logs channel for crawl
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let state_for_logs = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(line) = rx.recv().await {
            let mut inner = state_for_logs.write().await;
            push_log(&mut inner, &line);
        }
    });

    // Progress channel: updates status in near-real time (throttled in crawler)
    let (ptx, mut prx) = mpsc::unbounded_channel::<CrawlProgress>();
    let state_for_prog = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(p) = prx.recv().await {
            let mut inner = state_for_prog.write().await;
            if let Some(st) = inner.status.as_mut() {
                st.pages_crawled = p.pages_crawled;
                st.links_checked = p.links_checked;
                st.broken_links = p.broken_links;
                st.queue_size = p.queue_size;
                st.in_flight = p.in_flight;
                st.phase = format!("crawl (q={}, inflight={})", p.queue_size, p.in_flight);
            }
        }
    });
    let cancel_flag = { state.read().await.cancel_flag.clone() };
    let crawl_res = crawler::crawl_with_logs(
        &client,
        &start_url,
        depth,
        concurrency,
        externals,
        include_subdomains,
        Some(tx),
        Some(ptx),
        Some(cancel_flag.clone()),
        params.rate_limit_rps,
    )
    .await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.pages_crawled = crawl_res.pages_crawled;
            st.links_checked = crawl_res.links_checked;
            st.broken_links = crawl_res.broken_links.len();
        }
        push_log(
            &mut inner,
            &format!(
                "Crawl complete: pages={} links={} broken={}",
                crawl_res.pages_crawled,
                crawl_res.links_checked,
                crawl_res.broken_links.len()
            ),
        );
    }

    // If cancelled, stop here gracefully
    if cancel_flag.load(Ordering::Relaxed) {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.phase = "cancelled".into();
            st.done = true;
        }
        push_log(&mut inner, "Run cancelled by user");
        inner.running = false;
        return Ok(());
    }

    // Ports
    let ports_vec = if let Some(spec) = &params.ports {
        ports::parse_ports(spec).unwrap_or_else(|_| ports::common_ports())
    } else {
        ports::common_ports()
    };
    let port_concurrency = params.port_concurrency.unwrap_or(512);
    let timeout_ms = params.timeout_ms.unwrap_or(800);
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.phase = "ports".into();
        }
        push_log(
            &mut inner,
            &format!(
                "Phase: ports (targets={} ports, concurrency={}, timeout_ms={})",
                ports_vec.len(),
                port_concurrency,
                timeout_ms
            ),
        );
    }
    let ports_res = ports::scan_host(
        &host,
        &ports_vec,
        port_concurrency,
        timeout_ms,
        Some(cancel_flag.clone()),
    )
    .await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.ports_scanned = ports_res.scanned;
            st.ports_open = ports_res.open_ports.len();
        }
        push_log(
            &mut inner,
            &format!(
                "Ports complete: scanned={} open={}",
                ports_res.scanned,
                ports_res.open_ports.len()
            ),
        );
    }

    // Vuln
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.phase = "vuln".into();
        }
        push_log(&mut inner, "Phase: vuln");
    }
    let vuln_res = vuln::scan(&client, &start_url).await?;
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.vuln_findings = vuln_res.findings.len();
        }
        push_log(
            &mut inner,
            &format!("Vuln complete: findings={}", vuln_res.findings.len()),
        );
    }

    // Security posture (passive checks)
    {
        let mut inner = state.write().await;
        if let Some(st) = inner.status.as_mut() {
            st.phase = "security".into();
        }
        push_log(&mut inner, "Phase: security posture");
    }
    let security_flags = match security::check_security_posture(&client, &start_url).await {
        Ok(v) => v,
        Err(e) => {
            let mut inner = state.write().await;
            push_log(&mut inner, &format!("Security posture error: {}", e));
            Vec::new()
        }
    };
    {
        let mut inner = state.write().await;
        push_log(
            &mut inner,
            &format!("Security posture flags: {}", security_flags.len()),
        );
    }

    // Report: write to a writable temp file (AppImage mount is read-only)
    let tmp_name = format!(
        "dexteri-report-{}.html",
        Local::now().format("%Y%m%d%H%M%S")
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
    let _ = tokio::fs::remove_file(&path).await; // best-effort cleanup

    {
        let mut inner = state.write().await;
        inner.last_report_html = Some(html);
        inner.last_results = Some(CombinedResult {
            crawl: crawl_res,
            ports: ports_res,
            vuln: vuln_res,
            security: security_flags,
        });
        if let Some(st) = inner.status.as_mut() {
            st.phase = "done".into();
            st.done = true;
            st.queue_size = 0;
            st.in_flight = 0;
        }
        push_log(&mut inner, "Done");
        inner.running = false;
    }

    Ok(())
}

async fn run_ab_pipeline(
    state: Arc<RwLock<InnerState>>,
    params: RunAbParams,
) -> anyhow::Result<()> {
    let a_url = match Url::parse(&params.a.url) {
        Ok(u) => u,
        Err(_) => Url::parse(&format!("http://{}", params.a.url))?,
    };
    let b_url = match Url::parse(&params.b.url) {
        Ok(u) => u,
        Err(_) => Url::parse(&format!("http://{}", params.b.url))?,
    };

    let depth = params.a.depth.unwrap_or(2);
    let concurrency_a = params.a.concurrency.unwrap_or(32);
    let concurrency_b = params.b.concurrency.unwrap_or(32);
    let externals = params.a.externals.unwrap_or(false);
    let include_subdomains = params.a.include_subdomains.unwrap_or(false);

    let client = util::build_client()?;

    // Logs
    let (log_a_tx, mut log_a_rx) = mpsc::unbounded_channel::<String>();
    let (log_b_tx, mut log_b_rx) = mpsc::unbounded_channel::<String>();
    let state_logs_a = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(line) = log_a_rx.recv().await {
            let mut inner = state_logs_a.write().await;
            push_log(&mut inner, &format!("[A] {}", line));
        }
    });
    let state_logs_b = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(line) = log_b_rx.recv().await {
            let mut inner = state_logs_b.write().await;
            push_log(&mut inner, &format!("[B] {}", line));
        }
    });

    // Progress
    let (prog_a_tx, mut prog_a_rx) = mpsc::unbounded_channel::<CrawlProgress>();
    let (prog_b_tx, mut prog_b_rx) = mpsc::unbounded_channel::<CrawlProgress>();
    let state_prog_a = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(p) = prog_a_rx.recv().await {
            let mut inner = state_prog_a.write().await;
            // Compute aggregates within a narrow scope holding the ab_progress mutable borrow
            let (pages_total, links_total, broken_total, queue_total, inflight_total, phase_str) = {
                let ab = inner
                    .ab_progress
                    .get_or_insert_with(|| AbProgress::default());
                ab.a = p.clone();
                let pa = ab.a.clone();
                let pb = ab.b.clone();
                let all_checked = pa.links_checked + pb.links_checked;
                let all_total =
                    all_checked + pa.queue_size + pa.in_flight + pb.queue_size + pb.in_flight;
                let pct = if all_total > 0 {
                    ((all_checked as f64 / all_total as f64) * 100.0).round() as u8
                } else {
                    0
                };
                ab.combined_pct = pct;
                (
                    pa.pages_crawled + pb.pages_crawled,
                    pa.links_checked + pb.links_checked,
                    pa.broken_links + pb.broken_links,
                    pa.queue_size + pb.queue_size,
                    pa.in_flight + pb.in_flight,
                    format!("ab crawl (A q={}, B q={})", pa.queue_size, pb.queue_size),
                )
            };
            // Now update status after releasing ab_progress borrow
            if let Some(st) = inner.status.as_mut() {
                st.pages_crawled = pages_total;
                st.links_checked = links_total;
                st.broken_links = broken_total;
                st.queue_size = queue_total;
                st.in_flight = inflight_total;
                st.phase = phase_str;
            }
        }
    });
    let state_prog_b = state.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(p) = prog_b_rx.recv().await {
            let mut inner = state_prog_b.write().await;
            let (pages_total, links_total, broken_total, queue_total, inflight_total, phase_str) = {
                let ab = inner
                    .ab_progress
                    .get_or_insert_with(|| AbProgress::default());
                ab.b = p.clone();
                let pa = ab.a.clone();
                let pb = ab.b.clone();
                let all_checked = pa.links_checked + pb.links_checked;
                let all_total =
                    all_checked + pa.queue_size + pa.in_flight + pb.queue_size + pb.in_flight;
                let pct = if all_total > 0 {
                    ((all_checked as f64 / all_total as f64) * 100.0).round() as u8
                } else {
                    0
                };
                ab.combined_pct = pct;
                (
                    pa.pages_crawled + pb.pages_crawled,
                    pa.links_checked + pb.links_checked,
                    pa.broken_links + pb.broken_links,
                    pa.queue_size + pb.queue_size,
                    pa.in_flight + pb.in_flight,
                    format!("ab crawl (A q={}, B q={})", pa.queue_size, pb.queue_size),
                )
            };
            if let Some(st) = inner.status.as_mut() {
                st.pages_crawled = pages_total;
                st.links_checked = links_total;
                st.broken_links = broken_total;
                st.queue_size = queue_total;
                st.in_flight = inflight_total;
                st.phase = phase_str;
            }
        }
    });

    let cancel_flag = { state.read().await.cancel_flag.clone() };

    // Spawn both crawls concurrently
    let a_fut = crawler::crawl_with_logs(
        &client,
        &a_url,
        depth,
        concurrency_a,
        externals,
        include_subdomains,
        Some(log_a_tx),
        Some(prog_a_tx),
        Some(cancel_flag.clone()),
        params.a.rate_limit_rps,
    );
    let b_fut = crawler::crawl_with_logs(
        &client,
        &b_url,
        depth,
        concurrency_b,
        externals,
        include_subdomains,
        Some(log_b_tx),
        Some(prog_b_tx),
        Some(cancel_flag.clone()),
        params.b.rate_limit_rps,
    );
    {
        let mut inner = state.write().await;
        push_log(
            &mut inner,
            &format!("AB: waiting for crawls A and B (A={} B={})", a_url, b_url),
        );
    }
    // Enforce a total timeout for AB crawls to avoid indefinite hangs
    let ab_join = timeout(Duration::from_secs(180), async {
        tokio::try_join!(a_fut, b_fut)
    })
    .await;
    let (a_res, b_res) = match ab_join {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            {
                let mut inner = state.write().await;
                push_log(&mut inner, &format!("AB: error during crawl: {}", e));
            }
            return Err(anyhow::anyhow!("AB crawl error: {}", e));
        }
        Err(_elapsed) => {
            {
                let mut inner = state.write().await;
                push_log(
                    &mut inner,
                    "AB: timeout after 180s while waiting for both crawls",
                );
            }
            return Err(anyhow::anyhow!("AB timed out after 180 seconds"));
        }
    };
    {
        let mut inner = state.write().await;
        push_log(
            &mut inner,
            &format!(
                "AB: crawls complete (A pages={}, B pages={})",
                a_res.pages_crawled, b_res.pages_crawled
            ),
        );
    }

    let ab_comp = AbResult::compute(&a_res, &b_res);
    {
        let mut inner = state.write().await;
        push_log(&mut inner, "AB: computed comparison result");
    }
    {
        let mut inner = state.write().await;
        inner.last_ab_result = Some(ab_comp);
        if let Some(st) = inner.status.as_mut() {
            st.phase = "ab: done".into();
            st.done = true;
            st.queue_size = 0;
            st.in_flight = 0;
        }
        push_log(&mut inner, "AB run complete");
        inner.running = false;
    }
    Ok(())
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
fn csv_signals(pages: &Vec<Page>) -> String {
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
            xesc(&p.url), xesc(&p.status.map(|s| s.to_string()).unwrap_or_default()), xesc(&p.bytes.map(|b| b.to_string()).unwrap_or_default()), xesc(p.title.as_deref().unwrap_or("")), xesc(p.content_type.as_deref().unwrap_or(""))
        ));
    }
    s.push_str("  </pages>\n  <brokenLinks>\n");
    for e in &r.crawl.broken_links {
        s.push_str(&format!("    <broken url=\"{}\" status=\"{}\" external=\"{}\"><reason>{}</reason><parent>{}</parent></broken>\n", xesc(&e.url), xesc(&e.status.map(|s| s.to_string()).unwrap_or_default()), e.external, xesc(&e.reason), xesc(&e.parent)));
    }
    s.push_str("  </brokenLinks>\n  <ports>\n");
    for port in &r.ports.open_ports {
        s.push_str(&format!("    <open>{}</open>\n", port));
    }
    s.push_str("  </ports>\n  <findings>\n");
    for f in &r.vuln.findings {
        s.push_str(&format!(
            "    <finding severity=\"{}\"><title>{}</title><description>{}</description><url>{}</url></finding>\n",
            xesc(&f.severity),
            xesc(&f.title),
            xesc(&f.description),
            xesc(f.url.as_deref().unwrap_or(""))
        ));
    }

    s.push_str("  </findings>\n  <security>\n");
    for f in &r.security {
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

fn xesc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn push_log(inner: &mut InnerState, line: &str) {
    let t = Local::now().format("%H:%M:%S");
    inner.logs.push(format!("[{}] {}", t, line));
}

#[tauri::command]
async fn stop_run(state: State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.write().await;
    if !inner.running {
        return Err("No run in progress".into());
    }
    inner.cancel_flag.store(true, Ordering::Relaxed);
    push_log(&mut inner, "Cancellation requested by user");
    Ok(())
}

#[tauri::command]
async fn save_report_to(path: String, state: State<'_, AppState>) -> Result<(), String> {
    let html = {
        let inner = state.inner.read().await;
        inner
            .last_report_html
            .clone()
            .ok_or_else(|| "No report yet".to_string())?
    };
    tokio::fs::write(&path, html)
        .await
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            run_all,
            run_ab,
            get_status,
            get_results,
            get_report_html,
            get_web_ui_url,
            get_ab_result,
            get_ab_progress,
            export_data,
            open_in_browser,
            get_logs,
            clear_logs,
            start_web_ui,
            stop_run,
            save_report_to
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
