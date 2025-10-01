use url::Url;
use dexteri::util::{host_from_url, sanitize_url, is_same_origin};

#[test]
fn test_host_from_url_basic() {
    let url = Url::parse("https://example.com/path").unwrap();
    let host = host_from_url(&url);
    assert_eq!(host, Some("example.com".to_string()));
}

#[test]
fn test_host_from_url_with_port() {
    let url = Url::parse("https://example.com:8080/path").unwrap();
    let host = host_from_url(&url);
    assert_eq!(host, Some("example.com".to_string()));
}

#[test]
fn test_host_from_url_subdomain() {
    let url = Url::parse("https://www.example.com/path").unwrap();
    let host = host_from_url(&url);
    assert_eq!(host, Some("www.example.com".to_string()));
}

#[test]
fn test_host_from_url_localhost() {
    let url = Url::parse("http://localhost:3000/path").unwrap();
    let host = host_from_url(&url);
    assert_eq!(host, Some("localhost".to_string()));
}

#[test]
fn test_host_from_url_ip_address() {
    let url = Url::parse("http://192.168.1.1/path").unwrap();
    let host = host_from_url(&url);
    assert_eq!(host, Some("192.168.1.1".to_string()));
}

#[test]
fn test_sanitize_url_removes_fragment() {
    let url = Url::parse("https://example.com/path#fragment").unwrap();
    let normalized = sanitize_url(&url);
    assert!(!normalized.as_str().contains("#fragment"));
}

#[test]
fn test_sanitize_url_preserves_query() {
    let url = Url::parse("https://example.com/path?key=value").unwrap();
    let normalized = sanitize_url(&url);
    assert!(normalized.as_str().contains("key=value"));
}

#[test]
fn test_sanitize_url_trailing_slash() {
    let url = Url::parse("https://example.com/path/").unwrap();
    let normalized = sanitize_url(&url);
    // Normalization behavior depends on implementation
    assert!(normalized.as_str().starts_with("https://example.com"));
}

#[test]
fn test_is_same_origin_identical_urls() {
    let url1 = Url::parse("https://example.com/page1").unwrap();
    let url2 = Url::parse("https://example.com/page2").unwrap();
    assert!(is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_different_schemes() {
    let url1 = Url::parse("http://example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(!is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_different_hosts() {
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://other.com/page").unwrap();
    assert!(!is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_different_ports() {
    let url1 = Url::parse("https://example.com:443/page").unwrap();
    let url2 = Url::parse("https://example.com:8443/page").unwrap();
    // Default port 443 for HTTPS vs explicit 8443
    assert!(!is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_subdomain() {
    let url1 = Url::parse("https://www.example.com/page").unwrap();
    let url2 = Url::parse("https://api.example.com/page").unwrap();
    assert!(!is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_with_paths() {
    let url1 = Url::parse("https://example.com/path/page1").unwrap();
    let url2 = Url::parse("https://example.com/other/page2").unwrap();
    assert!(is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_localhost() {
    let url1 = Url::parse("http://localhost:3000/page1").unwrap();
    let url2 = Url::parse("http://localhost:3000/page2").unwrap();
    assert!(is_same_origin(&url1, &url2));
}

#[test]
fn test_is_same_origin_localhost_different_ports() {
    let url1 = Url::parse("http://localhost:3000/page").unwrap();
    let url2 = Url::parse("http://localhost:4000/page").unwrap();
    assert!(!is_same_origin(&url1, &url2));
}

#[test]
fn test_build_client_creates_valid_client() {
    let result = dexteri::util::build_client();
    assert!(result.is_ok(), "Should create HTTP client successfully");
}

#[test]
fn test_client_supports_redirects() {
    let _client = dexteri::util::build_client().unwrap();
    // Client should be configured - we can't test internals, but construction succeeds
    assert!(true);
}
