use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashSet, VecDeque};
use url::Url;

use crate::models::{CrawlResult, LinkError, Page};
use crate::util;

const MAX_BODY_PREVIEW: usize = 2_000_000; // 2 MB cap

pub async fn crawl(
    client: &reqwest::Client,
    start: &Url,
    max_depth: usize,
    concurrency: usize,
    check_externals: bool,
) -> Result<CrawlResult> {
    let start = util::sanitize_url(start);
    let mut visited: HashSet<String> = HashSet::new();
    let mut q: VecDeque<(Url, usize)> = VecDeque::new();
    q.push_back((start.clone(), 0));
    visited.insert(start.as_str().to_string());

    let mut pages: Vec<Page> = Vec::new();
    let mut links_checked: usize = 0;
    let mut broken: Vec<LinkError> = Vec::new();

    let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();

    while !q.is_empty() || !in_flight.is_empty() {
        while in_flight.len() < concurrency {
            if let Some((url, depth)) = q.pop_front() {
                let client_cl = client.clone();
                in_flight.push(async move {
                    let (page, new_links, errs) = fetch_and_parse(&client_cl, &url, MAX_BODY_PREVIEW)
                        .await
                        .unwrap_or_else(|_| {
                            (
                                Page {
                                    url: url.as_str().to_string(),
                                    status: None,
                                    title: None,
                                    links: vec![],
                                    content_type: None,
                                    bytes: None,
                                    text: None,
                                },
                                vec![],
                                vec![LinkError { url: url.as_str().to_string(), status: None, reason: "request error".into(), parent: url.as_str().to_string(), external: false }],
                            )
                        });
                    (url, depth, page, new_links, errs)
                });
            } else {
                break;
            }
        }

        if let Some((_url, depth, page, new_links, errs)) = in_flight.next().await {
            let start_origin = start.clone();
            pages.push(page);
            links_checked += new_links.len();
            broken.extend(errs.into_iter().filter(|e| e.status.unwrap_or(0) >= 400 || e.status.is_none()));

            if depth < max_depth {
                for l in new_links {
                    if let Ok(u) = Url::parse(&l) {
                        let u = util::sanitize_url(&u);
                        let same = util::is_same_origin(&start_origin, &u);
                        if same {
                            let key = u.as_str().to_string();
                            if !visited.contains(&key) {
                                visited.insert(key.clone());
                                q.push_back((u, depth + 1));
                            }
                        } else if check_externals {
                            // External links are validated via HEAD/GET in fetch_and_parse; do not follow
                        }
                    }
                }
            }
        }
    }

    Ok(CrawlResult {
        pages_crawled: pages.len(),
        links_checked,
        broken_links: broken,
        pages,
    })
}

async fn fetch_and_parse(
    client: &reqwest::Client,
    url: &Url,
    max_bytes: usize,
) -> Result<(Page, Vec<String>, Vec<LinkError>)> {
    let resp = client.get(url.clone()).send().await; // follow redirects per client policy
    if let Err(e) = &resp {
        return Ok((
            Page {
                url: url.as_str().to_string(),
                status: None,
                title: None,
                links: vec![],
                content_type: None,
                bytes: None,
                text: None,
            },
            vec![],
            vec![LinkError {
                url: url.as_str().to_string(),
                status: None,
                reason: format!("request error: {}", e),
                parent: url.as_str().to_string(),
                external: false,
            }],
        ));
    }
    let resp = resp?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body_full = resp.bytes().await.unwrap_or_default();
    let body_len_total = body_full.len();
    let body = if body_len_total > max_bytes {
        body_full.slice(0..max_bytes)
    } else {
        body_full
    };
    let body_string = String::from_utf8_lossy(&body).to_string();

    let mut links: Vec<String> = Vec::new();
    let mut page_title: Option<String> = None;
    let mut link_errors: Vec<LinkError> = Vec::new();

    if content_type.as_deref().unwrap_or("").starts_with("text/html") {
        let doc = scraper::Html::parse_document(&body_string);
        let sel_a = scraper::Selector::parse("a[href]").unwrap();
        let sel_img = scraper::Selector::parse("img[src]").unwrap();
        let sel_link = scraper::Selector::parse("link[href]").unwrap();
        let sel_script = scraper::Selector::parse("script[src]").unwrap();
        let sel_title = scraper::Selector::parse("title").unwrap();

        if let Some(t) = doc.select(&sel_title).next() {
            page_title = Some(t.text().collect::<String>().trim().to_string());
        }

        for el in doc.select(&sel_a) {
            if let Some(href) = el.value().attr("href") {
                if let Some(newu) = util::resolve_url(url, href) {
                    links.push(newu.to_string());
                }
            }
        }
        for el in doc.select(&sel_img) {
            if let Some(src) = el.value().attr("src") {
                if let Some(newu) = util::resolve_url(url, src) {
                    links.push(newu.to_string());
                }
            }
        }
        for el in doc.select(&sel_link) {
            if let Some(href) = el.value().attr("href") {
                if let Some(newu) = util::resolve_url(url, href) {
                    links.push(newu.to_string());
                }
            }
        }
        for el in doc.select(&sel_script) {
            if let Some(src) = el.value().attr("src") {
                if let Some(newu) = util::resolve_url(url, src) {
                    links.push(newu.to_string());
                }
            }
        }
    }

    // Validate discovered links (HEAD then optional GET fallback)
    let mut validators = FuturesUnordered::new();
    for l in links.iter().cloned() {
        let client = client.clone();
        let parent = url.to_string();
        validators.push(async move {
            let target = Url::parse(&l).ok();
            // Compare owned domain strings to avoid lifetime issues
            let parent_host = Url::parse(&parent)
                .ok()
                .and_then(|pu| pu.domain().map(|s| s.to_string()));
            let target_host = target
                .as_ref()
                .and_then(|u| u.domain().map(|s| s.to_string()));
            let external = target_host != parent_host;
            // First try HEAD
            let st = match client.head(&l).send().await {
                Ok(r) => Some(r.status().as_u16()),
                Err(_) => None,
            };
            let st = match st {
                Some(s) if s == 405 || s == 501 => {
                    // Fallback to GET for servers that disallow HEAD
                    client
                        .get(&l)
                        .header(reqwest::header::RANGE, "bytes=0-0")
                        .send()
                        .await
                        .ok()
                        .map(|r| r.status().as_u16())
                }
                other => other,
            };
            let err = match st {
                Some(code) if code >= 400 => Some(LinkError { url: l.clone(), status: Some(code), reason: format!("HTTP {}", code), parent: parent.clone(), external }),
                None => Some(LinkError { url: l.clone(), status: None, reason: "request failed".into(), parent: parent.clone(), external }),
                _ => None,
            };
            (l, st, err)
        });
    }

    let mut checked_links: Vec<String> = Vec::new();
    while let Some((l, _st, err)) = validators.next().await {
        checked_links.push(l);
        if let Some(e) = err { link_errors.push(e); }
    }

    let text = if content_type.as_deref().unwrap_or("").starts_with("text/html") {
        Some(html2text::from_read(std::io::Cursor::new(&body_string), 80))
    } else {
        None
    };

    let page = Page {
        url: url.as_str().to_string(),
        status: Some(status.as_u16()),
        title: page_title,
        links: links.clone(),
        content_type,
        bytes: Some(body_len_total),
        text,
    };

    Ok((page, checked_links, link_errors))
}
