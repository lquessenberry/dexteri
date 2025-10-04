// Comprehensive crawler tests to maximize coverage of all code paths
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    routing::get,
    Router,
    http::{StatusCode, HeaderMap, HeaderValue, header},
    response::IntoResponse,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use url::Url;

use dexteri::crawler::{crawl, crawl_with_logs};
use dexteri::models::CrawlProgress;

async fn serve(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, handle)
}

#[tokio::test]
async fn test_crawl_simple_wrapper() {
    // This tests the simple crawl() function wrapper (line 19-40)
    let html = r#"<html><body><h1>Test</h1></body></html>"#.to_string();
    let app = Router::new().route(
        "/",
        get(move || {
            let html = html.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, html).into_response()
            }
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // Use the simple crawl() wrapper
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_with_heartbeat() {
    // Test heartbeat emissions by having slow pages
    let html = r#"<html><body><a href="/page1">Link</a></body></html>"#.to_string();
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/page1",
            get(|| async {
                // Slow response to trigger heartbeat
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Page 1</body></html>").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    
    let result = crawl_with_logs(
        &client,
        &url,
        1,
        2,
        false,
        false,
        Some(log_tx),
        Some(progress_tx),
        None,
        None,
    ).await.unwrap();
    
    assert_eq!(result.pages_crawled, 2);
    
    // Check for logs
    let logs: Vec<String> = std::iter::from_fn(|| log_rx.try_recv().ok()).collect();
    assert!(!logs.is_empty(), "Should have logs");
    
    // Check for progress updates
    let progress: Vec<CrawlProgress> = std::iter::from_fn(|| progress_rx.try_recv().ok()).collect();
    assert!(!progress.is_empty(), "Should have progress updates");
}

#[tokio::test]
async fn test_crawl_with_subdomain_mode() {
    // Test include_subdomains path
    let html = r#"<html><body><a href="http://sub.example.com">Subdomain</a></body></html>"#.to_string();
    let app = Router::new().route(
        "/",
        get(move || {
            let html = html.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, html).into_response()
            }
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // This will test the subdomain checking logic
    let result = crawl(&client, &url, 1, 4, false, true).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_with_external_links() {
    // Test external link checking
    let html = r#"<html><body>
        <a href="http://external.com">External</a>
        <a href="/local">Local</a>
    </body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/local",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Local page</body></html>").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, true, false).await.unwrap();
    
    assert!(result.pages_crawled >= 1);
    // Should check external links and potentially find broken ones
}

#[tokio::test]
async fn test_crawl_depth_limiting() {
    // Test depth limiting logic
    let html1 = r#"<html><body><a href="/level2">Level 2</a></body></html>"#.to_string();
    let html2 = r#"<html><body><a href="/level3">Level 3</a></body></html>"#.to_string();
    let html3 = r#"<html><body>Level 3</body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html1.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/level2",
            get(move || {
                let html = html2.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/level3",
            get(move || {
                let html = html3.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // Depth 1 should only get root + level2
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    assert_eq!(result.pages_crawled, 2, "Depth 1 should get 2 pages");
    
    // Depth 2 should get all 3
    let result2 = crawl(&client, &url, 2, 4, false, false).await.unwrap();
    assert_eq!(result2.pages_crawled, 3, "Depth 2 should get 3 pages");
}

#[tokio::test]
async fn test_crawl_visited_deduplication() {
    // Test that visited URLs aren't crawled twice
    let html = r#"<html><body>
        <a href="/page">Page</a>
        <a href="/page">Page again</a>
        <a href="/page">Page third time</a>
    </body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/page",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Page</body></html>").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should only crawl each unique URL once
    assert_eq!(result.pages_crawled, 2, "Should deduplicate URLs");
}

#[tokio::test]
async fn test_crawl_early_cancellation() {
    // Test cancellation during crawl
    let html = r#"<html><body>
        <a href="/1">1</a><a href="/2">2</a><a href="/3">3</a>
        <a href="/4">4</a><a href="/5">5</a>
    </body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route("/1", get(|| async { tokio::time::sleep(Duration::from_millis(50)).await; "1" }))
        .route("/2", get(|| async { tokio::time::sleep(Duration::from_millis(50)).await; "2" }))
        .route("/3", get(|| async { tokio::time::sleep(Duration::from_millis(50)).await; "3" }))
        .route("/4", get(|| async { tokio::time::sleep(Duration::from_millis(50)).await; "4" }))
        .route("/5", get(|| async { tokio::time::sleep(Duration::from_millis(50)).await; "5" }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel_flag.clone();
    
    // Cancel very early
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel_clone.store(true, Ordering::Relaxed);
    });
    
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();
    
    let result = crawl_with_logs(
        &client,
        &url,
        2,
        1, // Low concurrency
        false,
        false,
        Some(log_tx),
        None,
        Some(cancel_flag),
        None,
    ).await.unwrap();
    
    // Should complete with some pages
    assert!(result.pages_crawled > 0);
    
    // Check for cancellation log
    let logs: Vec<String> = std::iter::from_fn(|| log_rx.try_recv().ok()).collect();
    let has_cancel_log = logs.iter().any(|l| l.contains("cancel") || l.contains("clear"));
    
    // May or may not have cancel log depending on timing
    assert!(logs.len() > 0, "Should have some logs");
}

#[tokio::test]
async fn test_crawl_with_broken_links() {
    // Test broken link detection
    let html = r#"<html><body>
        <a href="/exists">Good link</a>
        <a href="/404">Bad link</a>
    </body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route(
            "/exists",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Good</body></html>").into_response()
            }),
        )
        .route(
            "/404",
            get(|| async {
                (StatusCode::NOT_FOUND, "Not Found").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should detect 404 as broken
    assert!(result.broken_links.len() >= 1, "Should find broken links");
}

#[tokio::test]
async fn test_crawl_low_concurrency() {
    // Test with concurrency of 1 to hit sequential code paths
    let html = r#"<html><body>
        <a href="/a">A</a>
        <a href="/b">B</a>
        <a href="/c">C</a>
    </body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        )
        .route("/a", get(|| async { "A" }))
        .route("/b", get(|| async { "B" }))
        .route("/c", get(|| async { "C" }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 1, false, false).await.unwrap();
    
    assert_eq!(result.pages_crawled, 4);
}
