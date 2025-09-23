use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use url::Url;

pub fn build_client() -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Dexteri++/0.1 (+https://example.com/dexteri) reqwest",
        ),
    );

    let client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::limited(10))
        .gzip(true)
        .brotli(true)
        .zstd(true)
        .cookie_store(true)
        .timeout(std::time::Duration::from_secs(20))
        .use_rustls_tls()
        .build()?;
    Ok(client)
}

pub fn host_from_url(u: &Url) -> Option<String> {
    u.host_str().map(|h| h.to_string())
}

pub fn is_same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

pub fn sanitize_url(u: &Url) -> Url {
    let mut out = u.clone();
    out.set_fragment(None);
    out
}

pub fn resolve_url(base: &Url, href: &str) -> Option<Url> {
    if let Ok(j) = base.join(href) { Some(j) } else { None }
}
