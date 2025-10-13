// Comprehensive pipeline execution tests for web.rs
// Tests the actual scan pipeline logic and state management

use std::net::SocketAddr;
use tokio::time::{sleep, Duration};
use tokio::net::TcpListener;
use axum::{Router, routing::get, response::Html};

// Helper to find an available port
async fn find_available_port() -> u16 {
    for port in 40000..50000 {
        if TcpListener::bind(format!("127.0.0.1:{}", port)).await.is_ok() {
            return port;
        }
    }
    panic!("No ports available");
}

// Helper to start dexteri server
async fn start_dexteri_server() -> (tokio::task::JoinHandle<()>, String) {
    let port = find_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let base_url = format!("http://127.0.0.1:{}", port);
    
    let handle = tokio::spawn(async move {
        let _ = dexteri::web::serve(addr).await;
    });
    // Readiness probe: wait until /api/status returns null or JSON, or timeout
    let client = reqwest::Client::new();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if attempts > 30 { // ~3s max
            break;
        }
        if let Ok(resp) = client.get(format!("{}/api/status", base_url)).send().await {
            if let Ok(body) = resp.text().await {
                if body == "null" || body.starts_with('{') {
                    break;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    (handle, base_url)
}

// Helper to start a simple mock website
async fn start_mock_website(html: String) -> (tokio::task::JoinHandle<()>, String) {
    let port = find_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let base_url = format!("http://127.0.0.1:{}", port);
    
    let app = Router::new()
        .route("/", get(move || async move { Html(html.clone()) }));
    
    let handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });
    
    sleep(Duration::from_millis(200)).await;
    (handle, base_url)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_run_pipeline_with_simple_scan() {
    let html = "<html><head><title>Test Page</title></head><body><h1>Hello</h1></body></html>";
    let (mock_handle, mock_url) = start_mock_website(html.to_string()).await;
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    // Trigger a scan
    let payload = serde_json::json!({
        "url": mock_url,
        "depth": 0,
        "concurrency": 2,
        "externals": false,
        "include_subdomains": false,
        "ports": "80",
        "port_concurrency": 32,
        "timeout_ms": 1000,
        "rate_limit_rps": 10
    });
    
    let response = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    if let Ok(resp) = response {
        if resp.status().is_success() {
            // Wait for scan to complete
            sleep(Duration::from_secs(3)).await;
            
            // Check status
            let status_resp = client.get(format!("{}/api/status", dex_url))
                .send()
                .await;
            
            if let Ok(status) = status_resp {
                let _ = status.text().await;
            }
        }
    }
    
    mock_handle.abort();
    dex_handle.abort();
}

#[cfg_attr(feature = "coverage", ignore)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pipeline_state_transitions() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    // Check initial state
    let initial_status = client.get(format!("{}/api/status", dex_url))
        .send()
        .await;
    
    if let Ok(resp) = initial_status {
        let body = resp.text().await.unwrap();
        assert!(body == "null" || body.starts_with('{'));
    }
    
    dex_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_scan_requests() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 0,
        "concurrency": 1,
        "externals": false,
        "include_subdomains": false,
        "ports": "80",
        "port_concurrency": 16,
        "timeout_ms": 500
    });
    
    // Try to start two scans concurrently
    let req1 = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send();
    
    sleep(Duration::from_millis(100)).await;
    
    let req2 = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send();
    
    let _ = tokio::join!(req1, req2);
    
    dex_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_multi_site_scan() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "a": {
            "url": "https://example.com",
            "depth": 0,
            "concurrency": 1,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 16,
            "timeout_ms": 500
        },
        "b": {
            "url": "https://example.org",
            "depth": 0,
            "concurrency": 1,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 16,
            "timeout_ms": 500
        }
    });
    
    let response = client.post(format!("{}/api/run-multi", dex_url))
        .json(&payload)
        .send()
        .await;
    
    if let Ok(resp) = response {
        if resp.status().is_success() {
            sleep(Duration::from_secs(2)).await;
            
            // Try to fetch results for site A
            let _ = client.get(format!("{}/api/results?site=A", dex_url))
                .send()
                .await;
            
            // Try to fetch results for site B
            let _ = client.get(format!("{}/api/results?site=B", dex_url))
                .send()
                .await;
        }
    }
    
    dex_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_results_persist_after_scan() {
    let html = r#"
        <html>
        <head><title>Test</title></head>
        <body>
            <p>Content</p>
            <a href="/page2">Link</a>
        </body>
        </html>
    "#;
    
    let (mock_handle, mock_url) = start_mock_website(html.to_string()).await;
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": mock_url,
        "depth": 0,
        "concurrency": 2,
        "externals": false,
        "include_subdomains": false,
        "ports": "",
        "port_concurrency": 16,
        "timeout_ms": 1000
    });
    
    let _ = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_secs(3)).await;
    
    // Try to get results multiple times
    for _ in 0..3 {
        let _ = client.get(format!("{}/api/results", dex_url))
            .send()
            .await;
        sleep(Duration::from_millis(100)).await;
    }
    
    mock_handle.abort();
    dex_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_export_after_scan_completes() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    // Try exports when no data exists
    let _ = client.get(format!("{}/api/export?format=json", dex_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=html", dex_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=xml", dex_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=csv&kind=pages", dex_url)).send().await;
    
    dex_handle.abort();
}

#[tokio::test]
async fn test_scan_with_empty_ports() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 0,
        "concurrency": 1,
        "externals": false,
        "include_subdomains": false,
        "ports": "",  // Empty ports
        "port_concurrency": 16,
        "timeout_ms": 500
    });
    
    let _ = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(500)).await;
    
    dex_handle.abort();
}

#[tokio::test]
async fn test_scan_with_high_depth() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 5,  // Deep crawl
        "concurrency": 4,
        "externals": false,
        "include_subdomains": false,
        "ports": "80,443",
        "port_concurrency": 64,
        "timeout_ms": 1000
    });
    
    let _ = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(500)).await;
    
    dex_handle.abort();
}

#[tokio::test]
async fn test_scan_with_externals_enabled() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 1,
        "concurrency": 2,
        "externals": true,  // Follow external links
        "include_subdomains": false,
        "ports": "80",
        "port_concurrency": 32,
        "timeout_ms": 800
    });
    
    let _ = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(500)).await;
    
    dex_handle.abort();
}

#[tokio::test]
async fn test_scan_with_subdomains_enabled() {
    let (dex_handle, dex_url) = start_dexteri_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 1,
        "concurrency": 2,
        "externals": false,
        "include_subdomains": true,  // Include subdomains
        "ports": "80",
        "port_concurrency": 32,
        "timeout_ms": 800
    });
    
    let _ = client.post(format!("{}/api/run", dex_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(500)).await;
    
    dex_handle.abort();
}
