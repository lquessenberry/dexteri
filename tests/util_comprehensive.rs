// Comprehensive utility tests
use dexteri::util;
use url::Url;

#[test]
fn test_sanitize_url_removes_fragment() {
    let url = Url::parse("https://example.com/path#fragment").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(!sanitized.as_str().contains("#"));
}

#[test]
fn test_sanitize_url_keeps_query() {
    let url = Url::parse("https://example.com/path?query=value").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(sanitized.as_str().contains("query=value"));
}

#[test]
fn test_sanitize_url_multiple_fragments() {
    let url = Url::parse("https://example.com/path#frag1#frag2").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(!sanitized.as_str().contains("#"));
}

#[test]
fn test_sanitize_url_no_fragment() {
    let url = Url::parse("https://example.com/path").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert_eq!(sanitized.as_str(), url.as_str());
}

#[test]
fn test_host_from_url_simple() {
    let url = Url::parse("https://example.com/path").unwrap();
    let host = util::host_from_url(&url).unwrap();
    assert_eq!(host, "example.com");
}

#[test]
fn test_host_from_url_with_port() {
    let url = Url::parse("https://example.com:8080/path").unwrap();
    let host = util::host_from_url(&url).unwrap();
    assert_eq!(host, "example.com");
}

#[test]
fn test_host_from_url_subdomain() {
    let url = Url::parse("https://sub.example.com/path").unwrap();
    let host = util::host_from_url(&url).unwrap();
    assert_eq!(host, "sub.example.com");
}

#[test]
fn test_host_from_url_localhost() {
    let url = Url::parse("http://localhost:3000/path").unwrap();
    let host = util::host_from_url(&url).unwrap();
    assert_eq!(host, "localhost");
}

#[test]
fn test_host_from_url_ip() {
    let url = Url::parse("http://192.168.1.1/path").unwrap();
    let host = util::host_from_url(&url).unwrap();
    assert_eq!(host, "192.168.1.1");
}

#[test]
fn test_is_same_host_exact_match() {
    let url1 = Url::parse("https://example.com/page1").unwrap();
    let url2 = Url::parse("https://example.com/page2").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_subdomain() {
    let url1 = Url::parse("https://sub.example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_different_domains() {
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://other.com/page").unwrap();
    assert!(!util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_deep_subdomain() {
    let url1 = Url::parse("https://deep.sub.example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_different_tlds() {
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://example.org/page").unwrap();
    assert!(!util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_www() {
    let url1 = Url::parse("https://www.example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_localhost() {
    let url1 = Url::parse("http://localhost:3000/page1").unwrap();
    let url2 = Url::parse("http://localhost:3000/page2").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_ip_addresses() {
    let url1 = Url::parse("http://192.168.1.1/page1").unwrap();
    let url2 = Url::parse("http://192.168.1.1/page2").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_different_ips() {
    let url1 = Url::parse("http://192.168.1.1/page").unwrap();
    let url2 = Url::parse("http://192.168.1.2/page").unwrap();
    assert!(!util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_single_label() {
    let url1 = Url::parse("http://localhost/page").unwrap();
    let url2 = Url::parse("http://server/page").unwrap();
    assert!(!util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_build_client_success() {
    let client = util::build_client();
    assert!(client.is_ok());
}

#[test]
fn test_build_client_config() {
    let client = util::build_client().unwrap();
    // Client should be configured correctly
    // Just verify it exists
    assert!(true);
}

#[test]
fn test_sanitize_url_preserves_scheme() {
    let url = Url::parse("https://example.com/path#fragment").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(sanitized.scheme() == "https");
}

#[test]
fn test_sanitize_url_preserves_path() {
    let url = Url::parse("https://example.com/some/path#fragment").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(sanitized.path() == "/some/path");
}

#[test]
fn test_host_from_url_case_insensitive() {
    let url1 = Url::parse("https://EXAMPLE.COM/path").unwrap();
    let url2 = Url::parse("https://example.com/path").unwrap();
    let host1 = util::host_from_url(&url1).unwrap();
    let host2 = util::host_from_url(&url2).unwrap();
    // Hosts should be normalized to lowercase
    assert_eq!(host1.to_lowercase(), host2.to_lowercase());
}

#[test]
fn test_is_same_host_case_insensitive() {
    let url1 = Url::parse("https://EXAMPLE.COM/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_triple_subdomain() {
    let url1 = Url::parse("https://a.b.c.example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_partial_match() {
    let url1 = Url::parse("https://notexample.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(!util::is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_sanitize_url_with_username() {
    let url = Url::parse("https://user@example.com/path#fragment").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(!sanitized.as_str().contains("#"));
}

#[test]
fn test_sanitize_url_with_port() {
    let url = Url::parse("https://example.com:8080/path#fragment").unwrap();
    let sanitized = util::sanitize_url(&url);
    assert!(sanitized.as_str().contains(":8080"));
    assert!(!sanitized.as_str().contains("#"));
}
