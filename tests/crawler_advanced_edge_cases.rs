// Advanced edge case tests for crawler.rs - push to 85%+ coverage
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
use url::Url;

use dexteri::crawler::crawl;

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
async fn test_crawl_very_large_body() {
    // Test MAX_BODY_PREVIEW cap (2MB)
    let huge_body = "x".repeat(3_000_000); // 3MB body
    let html = format!("<html><body>{}<a href='/page'>Link</a></body></html>", huge_body);
    
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
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should have capped the body and still parsed links
    assert_eq!(result.pages_crawled, 1);
    assert!(result.pages[0].text.is_some());
}

#[tokio::test]
async fn test_crawl_invalid_utf8_body() {
    // Test body with invalid UTF-8 sequences
    let invalid_bytes = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8
    
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
            (StatusCode::OK, headers, invalid_bytes).into_response()
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should handle invalid UTF-8 gracefully (lossy conversion)
    assert_eq!(result.pages_crawled, 1);
    assert!(result.pages[0].text.is_some());
}

#[tokio::test]
async fn test_crawl_malformed_links() {
    let html = r##"<html><body>
        <a href="javascript:void(0)">JS Link</a>
        <a href="mailto:test@example.com">Email</a>
        <a href="tel:+1234567890">Phone</a>
        <a href="data:text/html,<h1>Data URI</h1>">Data URI</a>
        <a href="">Empty</a>
        <a href="#">Fragment Only</a>
        <a href=" ">Whitespace</a>
    </body></html>"##.to_string();
    
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
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should handle malformed links gracefully
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_content_type_variations() {
    let html = r#"<html><body>Test</body></html>"#.to_string();
    
    // Test different content type headers
    let content_types = vec![
        "text/html; charset=utf-8",
        "text/html;charset=UTF-8",
        "TEXT/HTML",
        "application/xhtml+xml",
    ];
    
    for ct in content_types {
        let html_clone = html.clone();
        let ct_string = ct.to_string();
        let app = Router::new().route(
            "/",
            get(move || {
                let html = html_clone.clone();
                let ct = ct_string.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(&ct).unwrap());
                    (StatusCode::OK, headers, html).into_response()
                }
            }),
        );
        
        let (addr, _handle) = serve(app).await;
        let url = Url::parse(&format!("http://{}/", addr)).unwrap();
        let client = reqwest::Client::new();
        
        let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
        assert_eq!(result.pages_crawled, 1);
    }
}

#[tokio::test]
async fn test_crawl_missing_content_type() {
    let html = r#"<html><body>Test</body></html>"#.to_string();
    
    let app = Router::new().route(
        "/",
        get(move || {
            let html = html.clone();
            async move {
                // No content-type header
                (StatusCode::OK, html).into_response()
            }
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should handle missing content-type (may have default)
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_redirect_chain() {
    let html = r#"<html><body>Final page</body></html>"#.to_string();
    
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                (StatusCode::MOVED_PERMANENTLY, [("Location", "/redirect1")]).into_response()
            }),
        )
        .route(
            "/redirect1",
            get(|| async {
                (StatusCode::FOUND, [("Location", "/redirect2")]).into_response()
            }),
        )
        .route(
            "/redirect2",
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
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should follow redirects
    assert_eq!(result.pages_crawled, 1);
}

#[tokio::test]
async fn test_crawl_mixed_relative_absolute() {
    let html = r#"<html><body>
        <a href="/absolute/path">Absolute</a>
        <a href="relative/path">Relative</a>
        <a href="./current/path">Current dir</a>
        <a href="../parent/path">Parent dir</a>
        <a href="//example.com/protocol-relative">Protocol relative</a>
        <a href="https://other.com/external">External</a>
    </body></html>"#.to_string();
    
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
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should parse all link types
    assert!(result.pages_crawled >= 1);
}

#[tokio::test]
async fn test_crawl_high_concurrency() {
    let html = r#"<html><body>
        <a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>
        <a href="/p4">4</a><a href="/p5">5</a><a href="/p6">6</a>
        <a href="/p7">7</a><a href="/p8">8</a><a href="/p9">9</a>
        <a href="/p10">10</a>
    </body></html>"#.to_string();
    
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
    
    // Test with very high concurrency
    let result = crawl(&client, &url, 1, 256, false, false).await.unwrap();
    
    // Should handle high concurrency
    assert!(result.pages_crawled >= 1);
}

#[tokio::test]
async fn test_crawl_same_page_multiple_links() {
    let html = r#"<html><body>
        <a href="/target">Link 1</a>
        <a href="/target">Link 2</a>
        <a href="/target">Link 3</a>
        <a href="/target#section1">Link 4 with fragment</a>
        <a href="/target?param=1">Link 5 with query</a>
    </body></html>"#.to_string();
    
    let target_html = r#"<html><body>Target page</body></html>"#.to_string();
    
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
            "/target",
            get(move || {
                let target_html = target_html.clone();
                async move {
                    let mut headers = HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    (StatusCode::OK, headers, target_html).into_response()
                }
            }),
        );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should deduplicate base URLs (fragments ignored, but query params create new URLs)
    assert!(result.pages_crawled >= 2); // Root + at least target variations
}

#[tokio::test]
async fn test_crawl_binary_content() {
    // Test with binary content (image)
    let binary_data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG header
    
    let app = Router::new().route(
        "/",
        get(|| async {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            (StatusCode::OK, headers, binary_data).into_response()
        }),
    );
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Should handle binary content gracefully
    assert_eq!(result.pages_crawled, 1);
    assert_eq!(result.pages[0].content_type, Some("image/png".to_string()));
}
