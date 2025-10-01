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

async fn start_xmlrpc_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/", get(|| async move { (StatusCode::OK, "ok").into_response() }))
        .route(
            "/xmlrpc.php",
            get(|| async move { (StatusCode::OK, "xmlrpc enabled").into_response() })
                .head(|| async move { (StatusCode::OK).into_response() }),
        );
    serve(app).await
}

#[tokio::test]
async fn xmlrpc_enabled_is_detected() {
    let (addr, _handle) = start_xmlrpc_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&"WordPress XML-RPC enabled".to_string()));
}

async fn start_drupal_changelog_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/", get(|| async move { (StatusCode::OK, "ok").into_response() }))
        .route(
            "/CHANGELOG.txt",
            get(|| async move { (StatusCode::OK, "Drupal 10 changelog").into_response() })
                .head(|| async move { (StatusCode::OK).into_response() }),
        );
    serve(app).await
}

#[tokio::test]
async fn drupal_changelog_exposed_is_detected() {
    let (addr, _handle) = start_drupal_changelog_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.contains(&"Drupal changelog exposed".to_string()));
}

async fn start_nosniff_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/",
        get(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
            (StatusCode::OK, headers, "ok").into_response()
        })
        .head(|| async move {
            let mut headers = HeaderMap::new();
            headers.insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
            (StatusCode::OK, headers).into_response()
        }),
    );
    serve(app).await
}

#[tokio::test]
async fn x_content_type_options_nosniff_not_flagged() {
    let (addr, _handle) = start_nosniff_fixture().await;
    let url = Url::parse(&format!("http://{}/", addr)).unwrap();
    let client = reqwest::Client::builder().build().unwrap();
    let flags = check_security_posture(&client, &url).await.expect("scan ok");
    let titles: Vec<String> = flags.iter().map(|f| f.title.clone()).collect();
    assert!(titles.iter().all(|t| t != "Missing X-Content-Type-Options"));
}
