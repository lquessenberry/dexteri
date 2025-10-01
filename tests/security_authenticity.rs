use std::{net::SocketAddr};

use axum::{
    routing::{get, head},
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use tokio::net::TcpListener;
use url::Url;

// Import the real scanner entry point we want to validate
use dexteri::security::check_security_posture;

async fn start_fixture_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // Build routes
    let app = Router::new()
        // Main page with meta generator to simulate WordPress 5.9
        .route(
            "/",
            get(|| async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::SERVER, HeaderValue::from_str("nginx/1.18").unwrap());
                headers.insert(header::HeaderName::from_static("x-powered-by"), HeaderValue::from_str("Express 4.17").unwrap());
                // Intentionally omit CSP, XFO, X-Content-Type-Options, Referrer-Policy
                let body = r#"<!doctype html>
<html><head>
  <meta name=generator content="WordPress 5.9" />
</head><body>
  <h1>Fixture Site</h1>
  <p>wp-content/themes/twentytwenty</p>
</body></html>"#;
                (StatusCode::OK, headers, body).into_response()
            })
            .head(|| async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::SERVER, HeaderValue::from_str("nginx/1.18").unwrap());
                headers.insert(header::HeaderName::from_static("x-powered-by"), HeaderValue::from_str("Express 4.17").unwrap());
                (StatusCode::OK, headers).into_response()
            }),
        )
        // Sensitive file exposed
        .route(
            "/.env",
            get(|| async move {
                let mut headers = HeaderMap::new();
                headers.insert(header::SERVER, HeaderValue::from_str("nginx/1.18").unwrap());
                let body = "SECRET_KEY=abc123";
                (StatusCode::OK, headers, body).into_response()
            })
            .head(|| async move { (StatusCode::OK).into_response() }),
        );

    // Bind random port
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn detects_expected_security_flags() {
    let (addr, _handle) = start_fixture_server().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .unwrap();

    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();

    // Headers missing (HTTP, so HSTS is not required)
    assert!(titles.contains(&"Missing CSP".to_string()));
    assert!(titles.contains(&"Missing X-Frame-Options".to_string()));
    assert!(titles.contains(&"Missing X-Content-Type-Options".to_string()));
    assert!(titles.contains(&"Missing Referrer-Policy".to_string()));

    // Server/X-Powered-By version exposure
    assert!(titles.contains(&"Server header exposes version".to_string()));
    assert!(titles.contains(&"X-Powered-By exposes version".to_string()));

    // CMS detection and version flags based on meta generator
    assert!(titles.iter().any(|t| t.contains("CMS detected: WordPress")));
    assert!(titles.iter().any(|t| t.contains("WordPress version exposed")));
    assert!(titles.iter().any(|t| t.contains("Outdated WordPress version")));

    // Sensitive path exposure (.env)
    assert!(titles.contains(&".env file exposed".to_string()));
}
