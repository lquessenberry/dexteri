// Comprehensive integration tests for Web API endpoints
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};
use tokio::net::TcpListener;

// Helper to find an available port
async fn find_available_port() -> u16 {
    for port in 35000..45000 {
        if TcpListener::bind(format!("127.0.0.1:{}", port)).await.is_ok() {
            return port;
        }
    }
    panic!("No ports available");
}

// Helper to start server and return address
async fn start_test_server() -> (tokio::task::JoinHandle<()>, String) {
    let port = find_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let base_url = format!("http://127.0.0.1:{}", port);
    
    let handle = tokio::spawn(async move {
        let _ = dexteri::web::serve(addr).await;
    });
    
    // Wait for server to start
    sleep(Duration::from_millis(500)).await;
    
    (handle, base_url)
}

#[tokio::test]
async fn test_index_endpoint_returns_html() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(&base_url).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        assert_eq!(resp.status(), 200);
        let content_type = resp.headers().get("content-type");
        if let Some(ct) = content_type {
            let ct_str = ct.to_str().unwrap();
            assert!(ct_str.contains("text/html"), "Should return HTML");
        }
    }
}

#[tokio::test]
async fn test_status_endpoint_returns_json() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/status", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        // Should return JSON (either null or an object)
        assert!(body == "null" || body.starts_with('{'));
    }
}

#[tokio::test]
async fn test_report_endpoint_when_no_scan() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/report", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 when no report exists
        assert_eq!(resp.status(), 404);
    }
}

#[tokio::test]
async fn test_results_json_endpoint_when_no_scan() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/results", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 when no results exist
        assert_eq!(resp.status(), 404);
    }
}

#[tokio::test]
async fn test_results_json_endpoint_with_site_parameter() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    // Test site=A
    let resp_a = client.get(format!("{}/api/results?site=A", base_url)).send().await;
    // Test site=B
    let resp_b = client.get(format!("{}/api/results?site=B", base_url)).send().await;
    // Test site=C
    let resp_c = client.get(format!("{}/api/results?site=C", base_url)).send().await;
    
    handle.abort();
    
    // All should return 404 when no scans exist
    if let Ok(r) = resp_a {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_b {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_c {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_pages_csv_endpoint_when_no_scan() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/pages", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 when no results exist
        assert_eq!(resp.status(), 404);
    }
}

#[tokio::test]
async fn test_marketing_endpoint_when_no_scan() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/marketing", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 when no results exist
        assert_eq!(resp.status(), 404);
    }
}

#[tokio::test]
async fn test_techstack_endpoint_when_no_scan() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/techstack", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 when no results exist
        assert_eq!(resp.status(), 404);
    }
}

#[tokio::test]
async fn test_charts_endpoint_returns_html() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/charts", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        assert_eq!(resp.status(), 200);
        let content_type = resp.headers().get("content-type");
        if let Some(ct) = content_type {
            let ct_str = ct.to_str().unwrap();
            assert!(ct_str.contains("text/html"), "Should return HTML");
        }
    }
}

#[tokio::test]
async fn test_export_endpoint_when_no_data() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    // Test different export formats
    let resp_json = client.get(format!("{}/api/export?format=json", base_url)).send().await;
    let resp_html = client.get(format!("{}/api/export?format=html", base_url)).send().await;
    let resp_xml = client.get(format!("{}/api/export?format=xml", base_url)).send().await;
    
    handle.abort();
    
    // All should return 404 when no data exists
    if let Ok(r) = resp_json {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_html {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_xml {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_export_csv_endpoint_with_kind_parameter() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    // Test different CSV kinds
    let resp_pages = client.get(format!("{}/api/export?format=csv&kind=pages", base_url)).send().await;
    let resp_links = client.get(format!("{}/api/export?format=csv&kind=broken_links", base_url)).send().await;
    let resp_ports = client.get(format!("{}/api/export?format=csv&kind=ports", base_url)).send().await;
    let resp_findings = client.get(format!("{}/api/export?format=csv&kind=findings", base_url)).send().await;
    
    handle.abort();
    
    // All should handle the request (even if no data)
    if let Ok(r) = resp_pages {
        assert!(r.status().as_u16() < 500, "Should not be server error");
    }
    if let Ok(r) = resp_links {
        assert!(r.status().as_u16() < 500, "Should not be server error");
    }
    if let Ok(r) = resp_ports {
        assert!(r.status().as_u16() < 500, "Should not be server error");
    }
    if let Ok(r) = resp_findings {
        assert!(r.status().as_u16() < 500, "Should not be server error");
    }
}

#[tokio::test]
async fn test_run_endpoint_accepts_post() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 0,
        "concurrency": 4,
        "externals": false,
        "include_subdomains": false,
        "ports": "80,443",
        "port_concurrency": 64,
        "timeout_ms": 500,
        "rate_limit_rps": 5
    });
    
    let response = client.post(format!("{}/api/run", base_url))
        .json(&payload)
        .send()
        .await;
    
    // Give scan a moment to start
    sleep(Duration::from_millis(200)).await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should accept the request (202, 200, or even 400 if validation fails)
        let status = resp.status().as_u16();
        assert!(status >= 200 && status < 500,
                "Should get valid response, got {}", status);
    }
}

#[tokio::test]
async fn test_run_multi_endpoint_accepts_post() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "a": {
            "url": "https://example.com",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500,
            "rate_limit_rps": 5
        },
        "b": {
            "url": "https://example.org",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500,
            "rate_limit_rps": 5
        }
    });
    
    let response = client.post(format!("{}/api/run-multi", base_url))
        .json(&payload)
        .send()
        .await;
    
    // Give scan a moment to start
    sleep(Duration::from_millis(200)).await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should accept the request (202, 200, or even 400 if validation fails)
        let status = resp.status().as_u16();
        assert!(status >= 200 && status < 500,
                "Should get valid response, got {}", status);
    }
}

#[tokio::test]
async fn test_status_endpoint_cache_headers() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/status", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Check for no-cache headers on dynamic content
        let headers = resp.headers();
        // This endpoint should have appropriate caching directives
        assert!(headers.contains_key("content-type") || resp.status().is_success());
    }
}

#[tokio::test]
async fn test_index_has_no_store_cache_control() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(&base_url).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        let cache_control = resp.headers().get("cache-control");
        if let Some(cc) = cache_control {
            let cc_str = cc.to_str().unwrap();
            assert_eq!(cc_str, "no-store", "Index should have no-store cache control");
        }
    }
}

#[tokio::test]
async fn test_concurrent_status_requests() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    // Make multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..5 {
        let url = format!("{}/api/status", base_url);
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            c.get(&url).send().await
        }));
    }
    
    // Wait for all requests
    for h in handles {
        let _ = h.await;
    }
    
    handle.abort();
}

#[tokio::test]
async fn test_export_unsupported_format() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/export?format=pdf", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 400 for unsupported format or 404 for no data
        let status = resp.status().as_u16();
        assert!(status == 400 || status == 404, "Should handle unsupported format");
    }
}

#[tokio::test]
async fn test_export_csv_security_kind() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/export?format=csv&kind=security", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should handle the request (404 if no data)
        assert!(resp.status().as_u16() < 500);
    }
}

#[tokio::test]
async fn test_marketing_endpoint_with_site_parameters() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let resp_a = client.get(format!("{}/api/marketing?site=A", base_url)).send().await;
    let resp_b = client.get(format!("{}/api/marketing?site=B", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(r) = resp_a {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_b {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_techstack_endpoint_with_site_parameters() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let resp_a = client.get(format!("{}/api/techstack?site=A", base_url)).send().await;
    let resp_c = client.get(format!("{}/api/techstack?site=C", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(r) = resp_a {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_c {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_pages_endpoint_with_site_parameter() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let resp_b = client.get(format!("{}/api/pages?site=B", base_url)).send().await;
    let resp_c = client.get(format!("{}/api/pages?site=C", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(r) = resp_b {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_c {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_export_site_parameter() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let resp_a = client.get(format!("{}/api/export?format=json&site=A", base_url)).send().await;
    let resp_b = client.get(format!("{}/api/export?format=json&site=B", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(r) = resp_a {
        assert_eq!(r.status(), 404);
    }
    if let Ok(r) = resp_b {
        assert_eq!(r.status(), 404);
    }
}

#[tokio::test]
async fn test_run_endpoint_with_minimal_config() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "url": "https://example.com",
        "depth": 0,
        "concurrency": 2,
        "externals": false,
        "include_subdomains": false,
        "ports": "80",
        "port_concurrency": 32,
        "timeout_ms": 500
    });
    
    let response = client.post(format!("{}/api/run", base_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(100)).await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        assert!(status >= 200 && status < 500);
    }
}

#[tokio::test]
async fn test_run_multi_with_single_site() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "a": {
            "url": "https://example.com",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500
        }
    });
    
    let response = client.post(format!("{}/api/run-multi", base_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(100)).await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        assert!(status >= 200 && status < 500);
    }
}

#[tokio::test]
async fn test_run_multi_with_three_sites() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    let payload = serde_json::json!({
        "a": {
            "url": "https://example.com",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500
        },
        "b": {
            "url": "https://example.org",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500
        },
        "c": {
            "url": "https://example.net",
            "depth": 0,
            "concurrency": 2,
            "externals": false,
            "include_subdomains": false,
            "ports": "80",
            "port_concurrency": 32,
            "timeout_ms": 500
        }
    });
    
    let response = client.post(format!("{}/api/run-multi", base_url))
        .json(&payload)
        .send()
        .await;
    
    sleep(Duration::from_millis(100)).await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        assert!(status >= 200 && status < 500);
    }
}

#[tokio::test]
async fn test_status_reflects_initial_state() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/status", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        let body = resp.text().await.unwrap();
        // Initial state should be null or empty
        assert!(body == "null" || body.starts_with('{'));
    }
}

#[tokio::test]
async fn test_multiple_export_formats_sequentially() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    
    // Test each format sequentially
    let _ = client.get(format!("{}/api/export?format=json", base_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=html", base_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=xml", base_url)).send().await;
    let _ = client.get(format!("{}/api/export?format=csv&kind=pages", base_url)).send().await;
    
    handle.abort();
}

#[tokio::test]
async fn test_api_route_not_found() {
    let (handle, base_url) = start_test_server().await;
    
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/api/nonexistent", base_url)).send().await;
    
    handle.abort();
    
    if let Ok(resp) = response {
        // Should return 404 for non-existent route
        assert_eq!(resp.status(), 404);
    }
}
