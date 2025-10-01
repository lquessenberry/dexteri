use std::net::SocketAddr;

use axum::{
    routing::get,
    Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use tokio::net::TcpListener;
use url::Url;

use dexteri::security::check_security_posture;

async fn serve(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

async fn start_headers_fixture(csp: bool, xfo: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(move || async move {
            let mut headers = HeaderMap::new();
            if csp {
                headers.insert(header::HeaderName::from_static("content-security-policy"), HeaderValue::from_static("default-src 'self'"));
            }
            if xfo {
                headers.insert(header::HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY"));
            }
            (StatusCode::OK, headers, "ok").into_response()
        }),
    );
    serve(app).await
}

#[tokio::test]
async fn csp_present_not_flagged() {
    let (addr, _h) = start_headers_fixture(true, false).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().all(|t| t != "Missing CSP"));
}

#[tokio::test]
async fn xfo_present_not_flagged() {
    let (addr, _h) = start_headers_fixture(false, true).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().all(|t| t != "Missing X-Frame-Options"));
}

#[tokio::test]
async fn csp_and_xfo_present_not_flagged() {
    let (addr, _h) = start_headers_fixture(true, true).await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::new();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().all(|t| t != "Missing CSP"));
    assert!(titles.iter().all(|t| t != "Missing X-Frame-Options"));
}
