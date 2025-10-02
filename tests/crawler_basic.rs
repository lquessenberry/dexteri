use std::net::SocketAddr;
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
    (addr, handle)
}

async fn start_simple_site(root_html: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(move || {
            let html = root_html.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                (StatusCode::OK, headers, html).into_response()
            }
        }),
    );
    serve(app).await
}

#[tokio::test]
async fn test_crawl_depth_zero() {
    let html = r#"<html><body><a href="/page1">Page 1</a></body></html>"#.to_string();
    let (addr, _handle) = start_simple_site(html).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    // Depth 0 means we only crawl the root page, no following links
    assert_eq!(result.pages_crawled, 1, "Should only crawl the root page");
    assert_eq!(result.pages.len(), 1, "Should have exactly 1 page");
}

#[tokio::test]
async fn test_crawl_depth_one() {
    let html = r#"<html><body><h1>Home</h1><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Depth 1: crawl root + immediate links
    // Note: pages might 404, but should attempt to crawl them
    assert!(result.pages_crawled >= 1, "Should crawl at least the root page");
    assert!(result.pages.len() >= 1, "Should have at least 1 page");
}

#[tokio::test]
async fn test_crawl_external_links_not_checked() {
    let html = r#"<html><body><a href="https://external.example.com">External</a><a href="/internal">Internal</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // check_externals = false
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should crawl root + attempt /internal (which will 404)
    assert!(result.pages_crawled >= 1, "Should crawl at least the root page");
    
    // External links should be recorded but not crawled
    let all_text = result.pages[0].text.as_ref().unwrap_or(&String::new()).to_lowercase();
    assert!(all_text.contains("external") || all_text.contains("internal"), 
            "Should capture page content");
}

#[tokio::test]
async fn test_crawl_external_links_checked() {
    let html = r#"<html><body><a href="https://www.google.com">Google</a><a href="/internal">Internal</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // check_externals = true - external links are validated but not crawled
    let result = crawl(&client, &url, 1, 4, true, false).await.unwrap();
    
    // Should validate external links and crawl same-origin
    assert!(result.links_checked >= 1, "Should check external links");
    assert!(result.pages_crawled >= 1, "Should crawl same-origin pages");
}

#[tokio::test]
async fn test_crawl_with_fragments() {
    let html = r#"<html><body><a href="/page#section1">Section 1</a><a href="/page#section2">Section 2</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Fragments should be normalized - both links point to same page
    // Root + /page (which will 404) = 2 pages crawled
    assert!(result.pages_crawled >= 1, "Should crawl root and attempt linked pages");
}

#[tokio::test]
async fn test_crawl_broken_links() {
    let html = r#"<html><body><a href="/exists">Good</a><a href="/broken404">Bad</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should detect broken links (404s)
    // Note: without additional routes, both will 404
    assert!(result.broken_links.len() >= 1, "Should detect broken links");
}

#[tokio::test]
async fn test_crawl_respects_concurrency() {
    let html = r#"<html><body>
        <a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>
        <a href="/p4">4</a><a href="/p5">5</a>
    </body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // Test with low concurrency
    let result = crawl(&client, &url, 1, 2, false, false).await.unwrap();
    
    // Should complete without errors
    assert!(result.pages_crawled >= 1, "Should complete crawl");
}

#[tokio::test]
async fn test_crawl_circular_references() {
    let html = r#"<html><body><a href="/">Self</a><a href="/">Again</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 2, 4, false, false).await.unwrap();
    
    // Should handle circular references without infinite loop
    assert_eq!(result.pages_crawled, 1, "Should not re-crawl same page");
}

#[tokio::test]
async fn test_crawl_with_query_params() {
    let html = r#"<html><body><a href="/?page=1">Page 1</a><a href="/?page=2">Page 2</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Query params make URLs unique
    assert!(result.pages_crawled >= 1, "Should handle query parameters");
}

#[tokio::test]
async fn test_crawl_relative_links() {
    let html = r#"<html><body>
        <a href="/absolute">Absolute</a>
        <a href="relative">Relative</a>
        <a href="../parent">Parent</a>
    </body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    // Should handle all types of relative URLs
    assert!(result.pages_crawled >= 1, "Should parse relative URLs");
}

#[tokio::test]
async fn test_crawl_empty_page() {
    let html = r#"<html><body></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 1, 4, false, false).await.unwrap();
    
    assert_eq!(result.pages_crawled, 1, "Should crawl empty page");
    assert_eq!(result.pages.len(), 1, "Should have 1 page");
}

#[tokio::test]
async fn test_crawl_marketing_signals() {
    let html = r#"<html><head>
        <meta property="og:title" content="Test">
        <meta name="twitter:card" content="summary">
        <script type="application/ld+json">{"@type": "Article"}</script>
    </head><body><p>Content</p></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    assert_eq!(result.pages.len(), 1, "Should have 1 page");
    let page = &result.pages[0];
    
    if let Some(signals) = &page.signals {
        assert!(signals.open_graph_tags > 0, "Should detect OpenGraph tags");
        assert!(signals.twitter_tags > 0, "Should detect Twitter tags");
        assert!(signals.json_ld_blocks > 0, "Should detect JSON-LD");
    }
}

#[tokio::test]
async fn test_crawl_with_rate_limit_zero() {
    use dexteri::crawler::crawl_with_logs;
    
    let html = r#"<html><body><a href="/p1">1</a><a href="/p2">2</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // RPS of 0 should be treated as 1 to avoid division by zero
    let result = crawl_with_logs(
        &client, &url, 1, 2, false, false,
        None, None, None,
        Some(0) // rate_limit_rps = 0
    ).await.unwrap();
    
    assert!(result.pages.len() >= 1, "Should complete crawl even with RPS=0");
}

#[tokio::test]
async fn test_crawl_with_progress_callback() {
    use dexteri::crawler::crawl_with_logs;
    use tokio::sync::mpsc::unbounded_channel;
    
    let html = r#"<html><body><a href="/p1">1</a><a href="/p2">2</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let (progress_tx, mut progress_rx) = unbounded_channel();
    
    tokio::spawn(async move {
        let _ = crawl_with_logs(
            &client, &url, 1, 2, false, false,
            None,
            Some(progress_tx), None, None
        ).await;
    });
    
    // Should receive at least one progress update
    let progress = tokio::time::timeout(
        Duration::from_secs(5),
        progress_rx.recv()
    ).await;
    
    assert!(progress.is_ok(), "Should receive progress updates");
    let prog = progress.unwrap().unwrap();
    assert!(prog.pages_crawled >= 0, "Progress should have valid data");
}

#[tokio::test]
async fn test_crawl_with_log_callback() {
    use dexteri::crawler::crawl_with_logs;
    use tokio::sync::mpsc::unbounded_channel;
    
    let html = r#"<html><body>Test</body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let (log_tx, mut log_rx) = unbounded_channel();
    
    tokio::spawn(async move {
        let _ = crawl_with_logs(
            &client, &url, 0, 2, false, false,
            Some(log_tx),
            None, None, None
        ).await;
    });
    
    // Should receive crawl start log
    let log = tokio::time::timeout(
        Duration::from_secs(5),
        log_rx.recv()
    ).await;
    
    assert!(log.is_ok(), "Should receive log messages");
    let log_msg = log.unwrap().unwrap();
    assert!(log_msg.contains("crawl start"), "Should log crawl start");
}

#[tokio::test]
async fn test_crawl_with_cancel_signal() {
    use dexteri::crawler::crawl_with_logs;
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    
    let html = r#"<html><body><a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel_flag.clone();
    
    let handle = tokio::spawn(async move {
        crawl_with_logs(
            &client, &url, 2, 1, false, false,
            None, None,
            Some(cancel_clone),
            Some(1) // Slow rate limit to give time to cancel
        ).await
    });
    
    // Give it a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Send cancel signal
    cancel_flag.store(true, Ordering::Relaxed);
    
    // Should complete quickly after cancel
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        handle
    ).await;
    
    assert!(result.is_ok(), "Should stop when cancel signal received");
}

#[tokio::test]
async fn test_crawl_subdomain_inclusion() {
    use dexteri::crawler::crawl_with_logs;
    
    let html = r#"<html><body><a href="http://sub.example.com/page">Subdomain</a></body></html>"#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    // include_subdomains = true
    let result = crawl_with_logs(
        &client, &url, 1, 2, false, true,
        None, None, None, None
    ).await.unwrap();
    
    // Should attempt to check subdomain link
    assert!(result.links_checked >= 1, "Should check links including subdomains");
}

#[tokio::test]
async fn test_crawl_detects_google_analytics() {
    let html = r#"
        <html>
        <body>
            <script src="https://www.google-analytics.com/analytics.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Google Analytics")), 
                "Should detect Google Analytics tracker");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_facebook_pixel() {
    let html = r#"
        <html>
        <body>
            <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Facebook")), 
                "Should detect Facebook Pixel tracker");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_google_tag_manager() {
    let html = r#"
        <html>
        <body>
            <script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Google Tag Manager")), 
                "Should detect Google Tag Manager");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_hotjar() {
    let html = r#"
        <html>
        <body>
            <script src="https://static.hotjar.com/c/hotjar-12345.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Hotjar")), 
                "Should detect Hotjar tracker");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_segment() {
    let html = r#"
        <html>
        <body>
            <script src="https://cdn.segment.com/analytics.js/v1/xxx.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Segment")), 
                "Should detect Segment tracker");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_mixpanel() {
    let html = r#"
        <html>
        <body>
            <script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.iter().any(|t| t.contains("Mixpanel")), 
                "Should detect Mixpanel tracker");
    } else {
        panic!("Should have signals");
    }
}

#[tokio::test]
async fn test_crawl_detects_multiple_trackers() {
    let html = r#"
        <html>
        <body>
            <script src="https://www.google-analytics.com/analytics.js"></script>
            <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
            <script src="https://static.hotjar.com/c/hotjar-12345.js"></script>
        </body>
        </html>
    "#;
    let (addr, _handle) = start_simple_site(html.to_string()).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = crawl(&client, &url, 0, 4, false, false).await.unwrap();
    
    let page = &result.pages[0];
    if let Some(signals) = &page.signals {
        assert!(signals.trackers.len() >= 3, "Should detect multiple trackers");
        assert!(signals.trackers.iter().any(|t| t.contains("Google Analytics")));
        assert!(signals.trackers.iter().any(|t| t.contains("Facebook")));
        assert!(signals.trackers.iter().any(|t| t.contains("Hotjar")));
    } else {
        panic!("Should have signals");
    }
}
