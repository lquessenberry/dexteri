// Advanced security edge case tests
use dexteri::models::*;
use std::net::SocketAddr;
use std::time::Duration;
use axum::{routing::get, Router, http::{StatusCode, header, HeaderMap, HeaderValue}};
use tokio::net::TcpListener;
use url::Url;

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
async fn test_security_check_http_only() {
    use dexteri::security;
    
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move { (StatusCode::OK, html) }
    }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let page = Page {
        url: url.to_string(),
        status: Some(200),
        title: Some("Test".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(100),
        text: Some("test".to_string()),
        signals: None,
    };
    
    let flags = security::check_security(&url, &vec![page], &client).await;
    // Should detect missing headers on HTTP
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_check_missing_headers() {
    use dexteri::security;
    
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move {
            // No security headers
            (StatusCode::OK, html)
        }
    }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let page = Page {
        url: url.to_string(),
        status: Some(200),
        title: Some("Test".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(100),
        text: Some("test".to_string()),
        signals: None,
    };
    
    let flags = security::check_security(&url, &vec![page], &client).await;
    // Should detect missing security headers deterministically
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_check_with_headers() {
    use dexteri::security;
    
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move {
            let mut headers = HeaderMap::new();
            headers.insert("Strict-Transport-Security", HeaderValue::from_static("max-age=31536000"));
            headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
            headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
            (StatusCode::OK, headers, html)
        }
    }));
    
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let page = Page {
        url: url.to_string(),
        status: Some(200),
        title: Some("Test".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(100),
        text: Some("test".to_string()),
        signals: None,
    };
    
    let flags = security::check_security(&url, &vec![page], &client).await;
    // With provided headers, these should NOT be flagged
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(!titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(!titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_empty_pages() {
    use dexteri::security;
    
    // Use local server to avoid network flakiness
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move { (StatusCode::OK, html) }
    }));
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();

    let flags = security::check_security(&url, &vec![], &client).await;
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_multiple_pages() {
    use dexteri::security;
    
    // Local server for determinism
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move { (StatusCode::OK, html) }
    }));
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();

    let pages = vec![
        Page {
            url: "https://example.com/1".to_string(),
            status: Some(200),
            title: Some("Page 1".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(100),
            text: Some("test".to_string()),
            signals: None,
        },
        Page {
            url: "https://example.com/2".to_string(),
            status: Some(200),
            title: Some("Page 2".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(100),
            text: Some("test".to_string()),
            signals: None,
        },
    ];
    
    let flags = security::check_security(&url, &pages, &client).await;
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_page_no_status() {
    use dexteri::security;
    
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move { (StatusCode::OK, html) }
    }));
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();

    let page = Page {
        url: url.to_string(),
        status: None,
        title: None,
        links: vec![],
        content_type: None,
        bytes: None,
        text: None,
        signals: None,
    };
    
    let flags = security::check_security(&url, &vec![page], &client).await;
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}

#[tokio::test]
async fn test_security_mixed_http_https() {
    use dexteri::security;
    
    let html = "<html><body>Test</body></html>".to_string();
    let app = Router::new().route("/", get(move || {
        let html = html.clone();
        async move { (StatusCode::OK, html) }
    }));
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();

    let pages = vec![
        Page {
            url: "https://example.com".to_string(),
            status: Some(200),
            title: Some("Secure".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(100),
            text: Some("test".to_string()),
            signals: None,
        },
        Page {
            url: "http://example.com/insecure".to_string(),
            status: Some(200),
            title: Some("Insecure".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(100),
            text: Some("test".to_string()),
            signals: None,
        },
    ];
    
    let flags = security::check_security(&url, &pages, &client).await;
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t == "Missing CSP"));
    assert!(titles.iter().any(|t| t == "Missing X-Frame-Options"));
    assert!(titles.iter().any(|t| t == "Missing X-Content-Type-Options"));
    assert!(titles.iter().any(|t| t == "Missing Referrer-Policy"));
}
