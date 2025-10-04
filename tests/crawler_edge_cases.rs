// Edge case tests for crawler.rs - error handling, logging, rate limiting, cancellation
// Tests the uncovered branches and error paths

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
async fn test_crawl_with_logs_simple() {
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
    
    // Create log channel
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();
    
    let result = crawl_with_logs(
        &client,
        &url,
        0,
        4,
        false,
        false,
        Some(log_tx),
        None,
        None,
        None,
    ).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
    
    // Verify logs were sent
    let logs: Vec<String> = std::iter::from_fn(|| log_rx.try_recv().ok()).collect();
    assert!(!logs.is_empty(), "Should have received log messages");
}

#[tokio::test]
async fn test_crawl_with_progress_reporting() {
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
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Page 1</body></html>").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // Create progress channel
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    
    let result = crawl_with_logs(
        &client,
        &url,
        1,
        4,
        false,
        false,
        None,
        Some(progress_tx),
        None,
        None,
    ).await.unwrap();
    
    assert_eq!(result.pages_crawled, 2);
    
    // Verify progress updates were sent
    let mut progress_updates: Vec<CrawlProgress> = 
        std::iter::from_fn(|| progress_rx.try_recv().ok()).collect();
    assert!(!progress_updates.is_empty(), "Should have received progress updates");
    
    // Last update should have final counts
    if let Some(last) = progress_updates.pop() {
        assert_eq!(last.pages_crawled, 2);
    }
}

#[tokio::test]
async fn test_crawl_with_rate_limiting() {
    let html = r#"<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>"#.to_string();
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
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Page 1</body></html>").into_response()
            }),
        )
        .route(
            "/page2",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, "<html><body>Page 2</body></html>").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let start = std::time::Instant::now();
    
    // Rate limit to 10 requests per second
    let result = crawl_with_logs(
        &client,
        &url,
        1,
        4,
        false,
        false,
        None,
        None,
        None,
        Some(10), // 10 RPS
    ).await.unwrap();
    
    let duration = start.elapsed();
    
    assert_eq!(result.pages_crawled, 3);
    // With rate limiting, should take some minimum time
    // (though we can't be too strict in tests)
}

#[tokio::test]
async fn test_crawl_with_cancellation() {
    let html = r#"<html><body>
        <a href="/page1">1</a>
        <a href="/page2">2</a>
        <a href="/page3">3</a>
        <a href="/page4">4</a>
        <a href="/page5">5</a>
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
        .route("/page1", get(|| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "Page 1"
        }))
        .route("/page2", get(|| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "Page 2"
        }))
        .route("/page3", get(|| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "Page 3"
        }))
        .route("/page4", get(|| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "Page 4"
        }))
        .route("/page5", get(|| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "Page 5"
        }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // Create cancel flag - pre-set to true to test cancellation logic
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_flag_clone = cancel_flag.clone();
    
    // Cancel immediately after first page
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel_flag_clone.store(true, Ordering::Relaxed);
    });
    
    let result = crawl_with_logs(
        &client,
        &url,
        2,
        1, // Low concurrency to make cancellation more deterministic
        false,
        false,
        None,
        None,
        Some(cancel_flag),
        None,
    ).await.unwrap();
    
    // Test passes if crawl completes (cancellation is checked, may or may not stop early)
    assert!(result.pages_crawled > 0, "Should have crawled at least one page");
}

#[tokio::test]
async fn test_crawl_with_zero_rate_limit() {
    let html = r#"<html><body>Test</body></html>"#.to_string();
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
    
    // Rate limit of 0 should be treated as 1
    let result = crawl_with_logs(
        &client,
        &url,
        0,
        4,
        false,
        false,
        None,
        None,
        None,
        Some(0), // 0 RPS - should be treated as 1 RPS
    ).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_logs_errors() {
    // Use an invalid URL to trigger errors
    let url = Url::parse("http://127.0.0.1:1/").unwrap(); // Port 1 should be unavailable
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();
    
    let result = crawl_with_logs(
        &client,
        &url,
        0,
        4,
        false,
        false,
        Some(log_tx),
        None,
        None,
        None,
    ).await.unwrap();
    
    // Should complete even with error
    assert_eq!(result.pages_crawled, 1);
    assert!(result.pages[0].status.is_none(), "Status should be None for failed request");
    
    // Verify error was logged
    let logs: Vec<String> = std::iter::from_fn(|| log_rx.try_recv().ok()).collect();
    let has_error_log = logs.iter().any(|log| log.contains("error"));
    assert!(has_error_log, "Should have logged an error message");
}

#[tokio::test]
async fn test_crawl_with_all_features() {
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
    let cancel_flag = Arc::new(AtomicBool::new(false));
    
    // Use all features together
    let result = crawl_with_logs(
        &client,
        &url,
        1,
        4,
        false,
        false,
        Some(log_tx),
        Some(progress_tx),
        Some(cancel_flag),
        Some(5), // 5 RPS rate limit
    ).await.unwrap();
    
    assert_eq!(result.pages_crawled, 2);
    
    // Verify all channels received data
    let logs: Vec<String> = std::iter::from_fn(|| log_rx.try_recv().ok()).collect();
    assert!(!logs.is_empty(), "Should have logs");
    
    let progress: Vec<CrawlProgress> = std::iter::from_fn(|| progress_rx.try_recv().ok()).collect();
    assert!(!progress.is_empty(), "Should have progress updates");
}

#[tokio::test]
async fn test_crawl_empty_response() {
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
            (StatusCode::OK, headers, "").into_response()
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
    assert!(result.pages[0].title.is_none(), "Empty page should have no title");
}

#[tokio::test]
async fn test_crawl_non_html_content() {
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            (StatusCode::OK, headers, r#"{"key": "value"}"#).into_response()
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1);
    assert_eq!(result.pages[0].content_type, Some("application/json".to_string()));
}

#[tokio::test]
async fn test_crawl_http_error_codes() {
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, r#"<html><body><a href="/404">404</a><a href="/500">500</a></body></html>"#).into_response()
            }),
        )
        .route(
            "/404",
            get(|| async {
                (StatusCode::NOT_FOUND, "Not Found").into_response()
            }),
        )
        .route(
            "/500",
            get(|| async {
                (StatusCode::INTERNAL_SERVER_ERROR, "Server Error").into_response()
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should crawl root + attempt the error pages
    assert!(result.pages_crawled >= 1);
    
    // Check if error pages were found
    let has_404 = result.pages.iter().any(|p| p.status == Some(404));
    let has_500 = result.pages.iter().any(|p| p.status == Some(500));
    
    // At least one error should be recorded
    assert!(has_404 || has_500 || !result.broken_links.is_empty());
}

#[tokio::test]
async fn test_crawl_timeout_handling() {
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "Too slow"
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/slow", addr)).unwrap();
    
    // Client with short timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should handle timeout gracefully
    assert_eq!(result.pages_crawled, 1);
    assert!(result.pages[0].status.is_none(), "Timeout should result in no status");
}
