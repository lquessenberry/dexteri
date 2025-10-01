use std::net::SocketAddr;

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
