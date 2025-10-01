use std::net::SocketAddr;

use axum::{
    routing::get,
    Router,
    http::{StatusCode, HeaderMap, HeaderValue, header},
    response::IntoResponse,
};
use tokio::net::TcpListener;
use url::Url;

use dexteri::vuln::scan;

async fn serve(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn test_http_not_https_flagged() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Site not using HTTPS".to_string()));
}

#[tokio::test]
async fn test_missing_hsts_on_https() {
    use axum_server::tls_rustls::RustlsConfig;
    
    async fn self_signed_config() -> RustlsConfig {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
    }
    
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Missing HSTS".to_string()));
}

#[tokio::test]
async fn test_missing_csp_flagged() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Missing CSP".to_string()));
}

#[tokio::test]
async fn test_missing_x_frame_options_flagged() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Missing X-Frame-Options".to_string()));
}

#[tokio::test]
async fn test_missing_x_content_type_options_flagged() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Missing X-Content-Type-Options".to_string()));
}

#[tokio::test]
async fn test_missing_referrer_policy_flagged() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Missing Referrer-Policy".to_string()));
}

#[tokio::test]
async fn test_server_header_leak() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.18.0"));
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Server header leaks software".to_string()));
}

#[tokio::test]
async fn test_directory_listing_detected() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let html = "<html><body><h1>Index of /</h1><ul><li>file1.txt</li></ul></body></html>";
            (StatusCode::OK, html).into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Possible directory listing".to_string()));
}

#[tokio::test]
async fn test_mixed_content_on_https() {
    use axum_server::tls_rustls::RustlsConfig;
    
    async fn self_signed_config() -> RustlsConfig {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
    }
    
    let app = Router::new().route(
        "/",
        get(|| async move {
            let html = r#"<html><body><img src="http://insecure.example.com/logo.png"></body></html>"#;
            (StatusCode::OK, html).into_response()
        }),
    );
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Mixed content".to_string()));
}

#[tokio::test]
async fn test_cookie_without_secure_on_https() {
    use axum_server::tls_rustls::RustlsConfig;
    
    async fn self_signed_config() -> RustlsConfig {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
    }
    
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, HeaderValue::from_static("session=abc123; HttpOnly"));
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Cookie without Secure".to_string()));
}

#[tokio::test]
async fn test_cookie_without_httponly_on_https() {
    use axum_server::tls_rustls::RustlsConfig;
    
    async fn self_signed_config() -> RustlsConfig {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
    }
    
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SET_COOKIE, HeaderValue::from_static("session=abc123; Secure"));
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let result = scan(&client, &url).await.unwrap();
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    
    assert!(titles.contains(&"Cookie without HttpOnly".to_string()));
}

#[tokio::test]
async fn test_multiple_findings() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SERVER, HeaderValue::from_static("Apache/2.4.41"));
            let html = "<html><body><h1>Index of /</h1></body></html>";
            (StatusCode::OK, headers, html).into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    
    // Should detect multiple issues
    assert!(result.findings.len() >= 5, "Should find multiple vulnerabilities");
    
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&"Site not using HTTPS".to_string()));
    assert!(titles.contains(&"Missing CSP".to_string()));
    assert!(titles.contains(&"Server header leaks software".to_string()));
    assert!(titles.contains(&"Possible directory listing".to_string()));
}

#[tokio::test]
async fn test_secure_site_minimal_findings() {
    use axum_server::tls_rustls::RustlsConfig;
    
    async fn self_signed_config() -> RustlsConfig {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
    }
    
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static("max-age=31536000"),
            );
            headers.insert(
                header::HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static("default-src 'self'"),
            );
            headers.insert(
                header::HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            headers.insert(
                header::HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            );
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    
    let result = scan(&client, &url).await.unwrap();
    
    // Should have minimal findings (all major headers present)
    let titles: Vec<String> = result.findings.iter().map(|f| f.title.clone()).collect();
    assert!(!titles.contains(&"Missing HSTS".to_string()));
    assert!(!titles.contains(&"Missing CSP".to_string()));
    assert!(!titles.contains(&"Missing X-Frame-Options".to_string()));
    assert!(!titles.contains(&"Missing X-Content-Type-Options".to_string()));
    assert!(!titles.contains(&"Missing Referrer-Policy".to_string()));
}

#[tokio::test]
async fn test_severity_levels() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    
    // Check that findings have severity levels
    for finding in &result.findings {
        assert!(
            ["Low", "Medium", "High", "Info"].contains(&finding.severity.as_str()),
            "Severity should be valid: {}",
            finding.severity
        );
    }
}

#[tokio::test]
async fn test_findings_have_urls() {
    let app = Router::new().route(
        "/",
        get(|| async move {
            (StatusCode::OK, "ok").into_response()
        }),
    );
    let (addr, _handle) = serve(app).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    
    let result = scan(&client, &url).await.unwrap();
    
    // Most findings should have associated URLs
    let with_urls = result.findings.iter().filter(|f| f.url.is_some()).count();
    assert!(with_urls > 0, "At least some findings should have URLs");
}
