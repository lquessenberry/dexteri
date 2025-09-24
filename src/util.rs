use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use url::Url;

pub fn build_client() -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("Dexteri++/0.1 (+https://example.com/dexteri) reqwest"),
    );

    let client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::limited(10))
        .gzip(true)
        .brotli(true)
        .zstd(true)
        .cookie_store(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(20))
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .use_rustls_tls()
        .build()?;
    Ok(client)
}

pub fn host_from_url(u: &Url) -> Option<String> {
    u.host_str().map(|h| h.to_string())
}

pub fn is_same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

pub fn sanitize_url(u: &Url) -> Url {
    let mut out = u.clone();
    out.set_fragment(None);
    out
}

pub fn resolve_url(base: &Url, href: &str) -> Option<Url> {
    if let Ok(j) = base.join(href) {
        Some(j)
    } else {
        None
    }
}

// Returns a naive root domain by joining the last two labels of the host.
// Note: This does not consider the Public Suffix List (e.g. co.uk). Good enough for common TLDs.
fn root_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_string()
    }
}

// Same scheme and either identical host or same registrable domain (naive) -> treat as same-site for crawling.
pub fn is_same_host_or_subdomain(base: &Url, other: &Url) -> bool {
    if base.scheme() != other.scheme() {
        return false;
    }
    let bh = match base.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };
    let oh = match other.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };
    if bh == oh {
        return true;
    }
    root_domain(&bh) == root_domain(&oh)
}
