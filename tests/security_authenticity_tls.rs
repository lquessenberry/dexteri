use std::{net::SocketAddr};

use axum::{
    routing::get,
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use axum_server::tls_rustls::RustlsConfig;
use tokio::net::TcpListener;
use url::Url;

use dexteri::security::check_security_posture;

async fn self_signed_config() -> RustlsConfig {
    let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    RustlsConfig::from_pem(cert_pem.into(), key_pem.into()).await.unwrap()
}

async fn serve_tls(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = self_signed_config().await;
    let handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener.into_std().unwrap(), config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    (addr, handle)
}

async fn start_https_without_hsts() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async move {
            // No HSTS
            let headers = HeaderMap::new();
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    serve_tls(app).await
}

async fn start_https_with_hsts() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::HeaderName::from_static("strict-transport-security"), HeaderValue::from_static("max-age=31536000; includeSubDomains"));
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    serve_tls(app).await
}

#[tokio::test]
async fn https_missing_hsts_is_flagged() {
    let (addr, _h) = start_https_without_hsts().await;
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&"Missing HSTS".to_string()));
}

#[tokio::test]
async fn https_with_hsts_is_not_flagged() {
    let (addr, _h) = start_https_with_hsts().await;
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().all(|t| t != "Missing HSTS"));
}
