use std::net::SocketAddr;

use axum::{
    routing::{get, head},
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

async fn start_wp62_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.24"));
            headers.insert(header::HeaderName::from_static("x-powered-by"), HeaderValue::from_static("Express 4.18"));
            let body = r#"<!doctype html>
<html><head>
  <meta name=generator content=\"WordPress 6.2\" />
</head><body>
  <h1>Fixture WP6 Site</h1>
</body></html>"#;
            (StatusCode::OK, headers, body).into_response()
        })
        .head(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::SERVER, HeaderValue::from_static("nginx/1.24"));
            (StatusCode::OK, headers).into_response()
        }),
    );
    serve(app).await
}

#[tokio::test]
async fn wordpress_6_not_outdated() {
    let (addr, _handle) = start_wp62_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().any(|t| t.contains("CMS detected: WordPress")));
    assert!(titles.iter().all(|t| !t.contains("Outdated WordPress version")));
}

async fn start_server_status_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/", get(|| async move { (StatusCode::OK, "ok").into_response() }))
        .route(
            "/server-status",
            get(|| async move { (StatusCode::OK, "status ok").into_response() })
                .head(|| async move { (StatusCode::OK).into_response() }),
        );
    serve(app).await
}

#[tokio::test]
async fn server_status_exposed_is_detected() {
    let (addr, _handle) = start_server_status_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&"Apache server-status exposed".to_string()));
}

async fn start_git_exposed_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/", get(|| async move { (StatusCode::OK, "ok").into_response() }))
        .route(
            "/.git/",
            // Simulate access-protected but present .git directory
            get(|| async move { (StatusCode::FORBIDDEN, "Forbidden").into_response() })
                .head(|| async move { (StatusCode::FORBIDDEN).into_response() }),
        );
    serve(app).await
}

#[tokio::test]
async fn git_dir_exposed_is_detected() {
    let (addr, _handle) = start_git_exposed_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&".git directory exposed".to_string()));
}
