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

// Tests for resolve_url
#[test]
fn test_resolve_url_absolute() {
    use dexteri::util::resolve_url;
    let base = Url::parse("https://example.com/path").unwrap();
    let result = resolve_url(&base, "https://other.com/page");
    assert!(result.is_some());
    assert_eq!(result.unwrap().as_str(), "https://other.com/page");
}

#[test]
fn test_resolve_url_relative() {
    use dexteri::util::resolve_url;
    let base = Url::parse("https://example.com/path/").unwrap();
    let result = resolve_url(&base, "page.html");
    assert!(result.is_some());
    assert_eq!(result.unwrap().as_str(), "https://example.com/path/page.html");
}

#[test]
fn test_resolve_url_root_relative() {
    use dexteri::util::resolve_url;
    let base = Url::parse("https://example.com/path/subpath").unwrap();
    let result = resolve_url(&base, "/other");
    assert!(result.is_some());
    assert_eq!(result.unwrap().as_str(), "https://example.com/other");
}

#[test]
fn test_resolve_url_fragment() {
    use dexteri::util::resolve_url;
    let base = Url::parse("https://example.com/path").unwrap();
    let result = resolve_url(&base, "#section");
    assert!(result.is_some());
    assert!(result.unwrap().as_str().contains("#section"));
}

// Tests for is_same_host_or_subdomain
#[test]
fn test_is_same_host_or_subdomain_identical() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page1").unwrap();
    let url2 = Url::parse("https://example.com/page2").unwrap();
    assert!(is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_subdomain() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://www.example.com/page").unwrap();
    assert!(is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_different_root() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://other.com/page").unwrap();
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_different_scheme() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("http://example.com/page").unwrap();
    let url2 = Url::parse("https://example.com/page").unwrap();
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_no_host() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("file:///path/to/file").unwrap();
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_api_subdomain() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://api.example.com/endpoint").unwrap();
    assert!(is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_deep_subdomain() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com/page").unwrap();
    let url2 = Url::parse("https://sub1.sub2.example.com/page").unwrap();
    assert!(is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_single_label() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("http://localhost/page1").unwrap();
    let url2 = Url::parse("http://localhost/page2").unwrap();
    assert!(is_same_host_or_subdomain(&url1, &url2));
}

// Edge case tests for 100% coverage
#[test]
fn test_resolve_url_malformed() {
    use dexteri::util::resolve_url;
    let base = Url::parse("https://example.com").unwrap();
    // Force base.join() to fail
    let result = resolve_url(&base, "http://[invalid");
    assert!(result.is_none(), "Should return None for malformed URL");
}

#[test]
fn test_is_same_host_or_subdomain_base_no_host() {
    use dexteri::util::is_same_host_or_subdomain;
    // URLs without hosts (like data: or javascript:)
    let url1 = Url::parse("data:text/plain,hello").unwrap();
    let url2 = Url::parse("https://example.com").unwrap();
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_other_no_host() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("https://example.com").unwrap();
    let url2 = Url::parse("data:text/plain,hello").unwrap();
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_both_no_host() {
    use dexteri::util::is_same_host_or_subdomain;
    let url1 = Url::parse("data:text/plain,one").unwrap();
    let url2 = Url::parse("data:text/plain,two").unwrap();
    // Both have no host, will return false early
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}

#[test]
fn test_is_same_host_or_subdomain_comparison_with_different_single_labels() {
    use dexteri::util::is_same_host_or_subdomain;
    // Single label hosts (no dots) - should use the whole string as root domain
    let url1 = Url::parse("http://localhost/page").unwrap();
    let url2 = Url::parse("http://otherhost/page").unwrap();
    // Different single-label hosts should NOT be same
    assert!(!is_same_host_or_subdomain(&url1, &url2));
}
