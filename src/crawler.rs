use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{Duration, Interval};
use url::Url;

use crate::models::{CrawlProgress, CrawlResult, LinkError, MarketingSignals, Page};
use crate::util;

const MAX_BODY_PREVIEW: usize = 2_000_000; // 2 MB cap
const LINK_CHECK_CONCURRENCY: usize = 64; // throttle external/internal link validations

pub async fn crawl(
    client: &reqwest::Client,
    start: &Url,
    max_depth: usize,
    concurrency: usize,
    check_externals: bool,
    include_subdomains: bool,
) -> Result<CrawlResult> {
    crawl_with_logs(
        client,
        start,
        max_depth,
        concurrency,
        check_externals,
        include_subdomains,
        None,
        None,
        None,
        None,
    )
    .await
}

pub async fn crawl_with_logs(
    client: &reqwest::Client,
    start: &Url,
    max_depth: usize,
    concurrency: usize,
    check_externals: bool,
    include_subdomains: bool,
    log: Option<UnboundedSender<String>>,
    progress: Option<UnboundedSender<CrawlProgress>>,
    cancel_flag: Option<Arc<AtomicBool>>,
    rate_limit_rps: Option<u32>,
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
    let mut limiter: Option<Interval> = rate_limit_rps.map(|rps| {
        let rps = if rps == 0 { 1 } else { rps };
        let ms = std::cmp::max(1u32, 1000 / rps);
        tokio::time::interval(Duration::from_millis(ms as u64))
    });
    // Heartbeat to indicate progress periodically even if no pages complete
    let mut heartbeat = tokio::time::interval(Duration::from_secs(2));

    if let Some(tx) = &log {
        let _ = tx.send(format!(
            "crawl start url={} depth={} concurrency={} externals={} include_subdomains={}",
            start, max_depth, concurrency, check_externals, include_subdomains
        ));
    }
    let mut last_emit = std::time::Instant::now();
    let mut emit = |force: bool,
                    in_flight_len: usize,
                    queue_len: usize,
                    pages_len: usize,
                    links: usize,
                    broken_len: usize| {
        if let Some(p) = &progress {
            let now = std::time::Instant::now();
            if force || now.duration_since(last_emit).as_millis() >= 200 {
                let _ = p.send(CrawlProgress {
                    pages_crawled: pages_len,
                    links_checked: links,
                    queue_size: queue_len,
                    in_flight: in_flight_len,
                    broken_links: broken_len,
                });
                last_emit = now;
            }
        }
    };

    while !q.is_empty() || !in_flight.is_empty() {
        let cancelled = cancel_flag
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false);
        if cancelled {
            if let Some(tx) = &log {
                let _ = tx.send("cancel requested; clearing queue".to_string());
            }
            q.clear();
        }
        while in_flight.len() < concurrency {
            if let Some((url, depth)) = q.pop_front() {
                if let Some(tx) = &log {
                    let _ = tx.send(format!("dequeue depth={} url={}", depth, url));
                }
                let client_cl = client.clone();
                let log_cl = log.clone();
                if cancelled {
                    break;
                }
                if let Some(l) = &mut limiter {
                    l.tick().await;
                }
                in_flight.push(async move {
                    let (page, new_links, errs) = fetch_and_parse(
                        &client_cl,
                        &url,
                        MAX_BODY_PREVIEW,
                        log_cl.clone(),
                        check_externals,
                    )
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
                                signals: None,
                            },
                            vec![],
                            vec![LinkError {
                                url: url.as_str().to_string(),
                                status: None,
                                reason: "request error".into(),
                                parent: url.as_str().to_string(),
                                external: false,
                            }],
                        )
                    });
                    (url, depth, page, new_links, errs)
                });
            } else {
                break;
            }
        }

        if in_flight.is_empty() {
            // Nothing currently in flight; loop will either push more or exit
            continue;
        }
        tokio::select! {
            _ = heartbeat.tick() => {
                if let Some(tx) = &log { let _ = tx.send(format!("heartbeat queue={} in_flight={} pages={} links_checked={}", q.len(), in_flight.len(), pages.len(), links_checked)); }
                emit(false, in_flight.len(), q.len(), pages.len(), links_checked, broken.len());
            }
            maybe = in_flight.next() => {
                if let Some((u, depth, page, new_links, errs)) = maybe {
                    let start_origin = u.clone();
                    if let Some(tx) = &log { let _ = tx.send(format!("page complete depth={} url={} checked_links={} new_errors={}", depth, u, new_links.len(), errs.len())); }
                    pages.push(page);
                    links_checked += new_links.len();
                    broken.extend(errs.into_iter().filter(|e| e.status.unwrap_or(0) >= 400 || e.status.is_none()));
                    emit(true, in_flight.len(), q.len(), pages.len(), links_checked, broken.len());

                    if depth < max_depth && !cancelled {
                        let mut enq_count = 0usize;
                        let mut visited_skip = 0usize;
                        let mut external_cnt = 0usize;
                        for l in new_links {
                            if let Ok(u) = Url::parse(&l) {
                                let u = util::sanitize_url(&u);
                                let same = if include_subdomains {
                                    util::is_same_host_or_subdomain(&start_origin, &u)
                                } else {
                                    util::is_same_origin(&start_origin, &u)
                                };
                                if same {
                                    let key = u.as_str().to_string();
                                    if !visited.contains(&key) {
                                        visited.insert(key.clone());
                                        q.push_back((u, depth + 1));
                                        if let Some(tx) = &log { let _ = tx.send(format!("enqueue depth={} url={} (same-site)", depth+1, key)); }
                                        enq_count += 1;
                                    } else {
                                        if let Some(tx) = &log { let _ = tx.send(format!("skip visited url={}", key)); }
                                        visited_skip += 1;
                                    }
                                } else {
                                    if let Some(tx) = &log {
                                        if check_externals {
                                            let _ = tx.send(format!("external discovered (will validate only): {}", u));
                                        } else {
                                            let _ = tx.send(format!("external discovered (skipping validation and follow): {}", u));
                                        }
                                    }
                                    external_cnt += 1;
                                }
                            }
                        }
                        if let Some(tx) = &log { let _ = tx.send(format!("enqueue summary depth={} enqueued={} visited_skip={} externals={} queue_size={}", depth+1, enq_count, visited_skip, external_cnt, q.len())); }
                        if let Some(tx) = &log { let _ = tx.send(format!("progress: pages={} links_checked={} queue_size={} in_flight={}", pages.len(), links_checked, q.len(), in_flight.len())); }
                        emit(false, in_flight.len(), q.len(), pages.len(), links_checked, broken.len());
                    } else {
                        if let Some(tx) = &log { let _ = tx.send(format!("max depth reached at depth={} for url={}", depth, u)); }
                    }
                }
            }
        }
    }

    emit(
        true,
        in_flight.len(),
        q.len(),
        pages.len(),
        links_checked,
        broken.len(),
    );

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
    log: Option<UnboundedSender<String>>,
    check_externals: bool,
) -> Result<(Page, Vec<String>, Vec<LinkError>)> {
    if let Some(tx) = &log {
        let _ = tx.send(format!("GET {}", url));
    }
    let resp = client.get(url.clone()).send().await;
    if let Err(e) = &resp {
        if let Some(tx) = &log {
            let _ = tx.send(format!("GET error {}: {}", url, e));
        }
        return Ok((
            Page {
                url: url.as_str().to_string(),
                status: None,
                title: None,
                links: vec![],
                content_type: None,
                bytes: None,
                text: None,
                signals: None,
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

    if let Some(tx) = &log {
        let _ = tx.send(format!(
            "status={} ct={} bytes={} url={}",
            status.as_u16(),
            content_type.as_deref().unwrap_or("-"),
            body_len_total,
            url
        ));
    }
    let mut links: Vec<String> = Vec::new();
    let mut page_title: Option<String> = None;
    let mut link_errors: Vec<LinkError> = Vec::new();

    let mut signals: Option<MarketingSignals> = None;
    if content_type
        .as_deref()
        .unwrap_or("")
        .starts_with("text/html")
    {
        let doc = scraper::Html::parse_document(&body_string);
        let sel_a = scraper::Selector::parse("a[href]").unwrap();
        let sel_img = scraper::Selector::parse("img[src]").unwrap();
        let sel_link = scraper::Selector::parse("link[href]").unwrap();
        let sel_script = scraper::Selector::parse("script[src]").unwrap();
        let sel_title = scraper::Selector::parse("title").unwrap();
        let sel_meta_prop_og = scraper::Selector::parse(r#"meta[property^="og:"]"#).unwrap();
        let sel_meta_twitter = scraper::Selector::parse(r#"meta[name^="twitter:"]"#).unwrap();
        let sel_meta_robots = scraper::Selector::parse("meta[name=robots]").unwrap();
        let sel_link_canon = scraper::Selector::parse("link[rel=canonical]").unwrap();
        let sel_link_hreflang = scraper::Selector::parse("link[rel=alternate][hreflang]").unwrap();
        let sel_ld_json = scraper::Selector::parse("script[type=\"application/ld+json\"]").unwrap();
        let sel_itemscope = scraper::Selector::parse("*[itemscope]").unwrap();

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

        if let Some(tx) = &log {
            let _ = tx.send(format!(
                "parse html: anchors={} imgs={} links={} scripts={} url={}",
                doc.select(&sel_a).count(),
                doc.select(&sel_img).count(),
                doc.select(&sel_link).count(),
                doc.select(&sel_script).count(),
                url
            ));
        }
        if let Some(tx) = &log {
            let _ = tx.send(format!("resolved links total={} url={}", links.len(), url));
        }
        let mut json_ld_types_vec: Vec<String> = Vec::new();
        let mut json_ld_raw_vec: Vec<String> = Vec::new();
        for el in doc.select(&sel_ld_json) {
            let raw = el.text().collect::<String>();
            if raw.trim().is_empty() {
                continue;
            }
            json_ld_raw_vec.push(raw.clone());
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                fn collect_types(v: &Value, out: &mut Vec<String>) {
                    match v {
                        Value::Object(map) => {
                            if let Some(t) = map.get("@type") {
                                match t {
                                    Value::String(s) => out.push(s.clone()),
                                    Value::Array(arr) => {
                                        for x in arr {
                                            if let Value::String(s) = x {
                                                out.push(s.clone());
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            if let Some(g) = map.get("@graph") {
                                collect_types(g, out);
                            }
                            for (_, vv) in map {
                                collect_types(vv, out);
                            }
                        }
                        Value::Array(arr) => {
                            for x in arr {
                                collect_types(x, out);
                            }
                        }
                        _ => {}
                    }
                }
                collect_types(&val, &mut json_ld_types_vec);
            }
        }
        json_ld_types_vec.sort();
        json_ld_types_vec.dedup();
        let json_ld_blocks = json_ld_raw_vec.len();

        let mut microdata_types_vec: Vec<String> = Vec::new();
        for el in doc.select(&sel_itemscope) {
            if let Some(itemtype) = el.value().attr("itemtype") {
                for t in itemtype.split_whitespace() {
                    if !t.is_empty() {
                        microdata_types_vec.push(t.to_string());
                    }
                }
            }
        }
        microdata_types_vec.sort();
        microdata_types_vec.dedup();
        let microdata_items = doc.select(&sel_itemscope).count();

        let mut og_props_vec: Vec<String> = Vec::new();
        for el in doc.select(&sel_meta_prop_og) {
            if let Some(p) = el.value().attr("property") {
                og_props_vec.push(p.to_string());
            }
        }
        og_props_vec.sort();
        og_props_vec.dedup();
        let open_graph_tags = doc.select(&sel_meta_prop_og).count();

        let mut twitter_names_vec: Vec<String> = Vec::new();
        for el in doc.select(&sel_meta_twitter) {
            if let Some(n) = el.value().attr("name") {
                twitter_names_vec.push(n.to_string());
            }
        }
        twitter_names_vec.sort();
        twitter_names_vec.dedup();
        let twitter_tags = doc.select(&sel_meta_twitter).count();

        let meta_robots = doc
            .select(&sel_meta_robots)
            .next()
            .and_then(|m| m.value().attr("content").map(|s| s.to_string()));
        let canonical_url = doc
            .select(&sel_link_canon)
            .next()
            .and_then(|l| l.value().attr("href").map(|s| s.to_string()));
        let mut hreflang_langs: Vec<String> = doc
            .select(&sel_link_hreflang)
            .filter_map(|l| l.value().attr("hreflang").map(|s| s.to_string()))
            .collect();
        hreflang_langs.sort();
        hreflang_langs.dedup();
        let hreflang_count = hreflang_langs.len();

        let mut tracker_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for el in doc.select(&sel_script) {
            if let Some(src) = el.value().attr("src") {
                let s = src.to_lowercase();
                if s.contains("googletagmanager.com") {
                    tracker_set.insert("Google Tag Manager".into());
                }
                if s.contains("google-analytics.com") || s.contains("analytics.js") {
                    tracker_set.insert("Google Analytics".into());
                }
                if s.contains("doubleclick.net") {
                    tracker_set.insert("Google Ads / DoubleClick".into());
                }
                if s.contains("connect.facebook.net") {
                    tracker_set.insert("Facebook Pixel".into());
                }
                if s.contains("static.hotjar.com") || s.contains("hotjar") {
                    tracker_set.insert("Hotjar".into());
                }
                if s.contains("cdn.segment.com") {
                    tracker_set.insert("Segment".into());
                }
                if s.contains("mxpnl.com") || s.contains("mixpanel") {
                    tracker_set.insert("Mixpanel".into());
                }
                if s.contains("matomo.js") || s.contains("piwik.js") {
                    tracker_set.insert("Matomo/Piwik".into());
                }
                if s.contains("hs-scripts.com") || s.contains("hs-analytics.net") {
                    tracker_set.insert("HubSpot".into());
                }
                if s.contains("tag.cdn.onesignal.com") {
                    tracker_set.insert("OneSignal".into());
                }
                if s.contains("clarity.ms") {
                    tracker_set.insert("Microsoft Clarity".into());
                }
                if s.contains("optimizely") {
                    tracker_set.insert("Optimizely".into());
                }
                if s.contains("fullstory") {
                    tracker_set.insert("FullStory".into());
                }
                if s.contains("intercom") {
                    tracker_set.insert("Intercom".into());
                }
                if s.contains("snap.licdn.com") {
                    tracker_set.insert("LinkedIn Insight".into());
                }
                if s.contains("static.chartbeat.com") || s.contains("chartbeat") {
                    tracker_set.insert("Chartbeat".into());
                }
                if s.contains("q.quora.com") {
                    tracker_set.insert("Quora Pixel".into());
                }
                if s.contains("analytics.twitter.com") {
                    tracker_set.insert("Twitter Analytics".into());
                }
                if s.contains("mc.yandex.ru") {
                    tracker_set.insert("Yandex Metrica".into());
                }
                if s.contains("crazyegg.com") {
                    tracker_set.insert("Crazy Egg".into());
                }
                if s.contains("munchkin.js") || s.contains("marketo") {
                    tracker_set.insert("Marketo".into());
                }
                if s.contains("pardot.com") {
                    tracker_set.insert("Pardot".into());
                }
                if s.contains("criteo.com") {
                    tracker_set.insert("Criteo".into());
                }
                if s.contains("adroll.com") {
                    tracker_set.insert("AdRoll".into());
                }
                if s.contains("onetrust.com") || s.contains("cookiepro.com") {
                    tracker_set.insert("OneTrust".into());
                }
                if s.contains("cookiebot.com") {
                    tracker_set.insert("Cookiebot".into());
                }
            }
        }
        let body_lc = body_string.to_lowercase();
        if body_lc.contains("gtag(") {
            tracker_set.insert("Google Analytics (gtag)".into());
        }
        if body_lc.contains("fbq(") {
            tracker_set.insert("Facebook Pixel".into());
        }
        if body_lc.contains("mixpanel") {
            tracker_set.insert("Mixpanel".into());
        }
        if body_lc.contains("_hsq") || body_lc.contains("hubspot") {
            tracker_set.insert("HubSpot".into());
        }
        if body_lc.contains("_hjsettings") || body_lc.contains("hotjar") {
            tracker_set.insert("Hotjar".into());
        }
        if body_lc.contains("window.datalayer") || body_lc.contains("datalayer.push(") {
            tracker_set.insert("GTM dataLayer".into());
        }

        let mut trackers: Vec<String> = tracker_set.into_iter().collect();
        trackers.sort();

        let robot_str = meta_robots.as_deref().unwrap_or("-").to_string();
        let canon_str = canonical_url.as_deref().unwrap_or("-").to_string();

        signals = Some(MarketingSignals {
            json_ld_blocks,
            json_ld_types: json_ld_types_vec,
            json_ld_raw: json_ld_raw_vec,
            microdata_items,
            microdata_types: microdata_types_vec,
            open_graph_tags,
            og_props: og_props_vec,
            twitter_tags,
            twitter_names: twitter_names_vec,
            meta_robots,
            canonical_url,
            hreflang_count,
            hreflang_langs,
            trackers,
        });
        if let Some(tx) = &log {
            let _ = tx.send(format!("signals: jsonld={} microdata={} og={} tw={} robots={} canonical={} hreflang={} trackers={}", json_ld_blocks, microdata_items, open_graph_tags, twitter_tags, robot_str, canon_str, hreflang_count, signals.as_ref().map(|s| s.trackers.len()).unwrap_or(0)));
        }
    }

    let mut validators = FuturesUnordered::new();
    let parent_host = Url::parse(&url.to_string())
        .ok()
        .and_then(|pu| pu.domain().map(|s| s.to_string()));
    let mut validate_count = 0usize;
    for l in links.iter() {
        let target_host = Url::parse(l)
            .ok()
            .and_then(|u| u.domain().map(|s| s.to_string()));
        let external = target_host != parent_host;
        if external && !check_externals {
            continue;
        }
        validate_count += 1;
    }
    if let Some(tx) = &log {
        let _ = tx.send(format!(
            "validate {}/{} links for {} (externals={})",
            validate_count,
            links.len(),
            url,
            check_externals
        ));
    }
    let mut checked_links: Vec<String> = Vec::new();
    let mut it = links.iter().cloned();
    while let Some(l) = it.next() {
        if validators.len() >= LINK_CHECK_CONCURRENCY {
            if let Some((l2, _st, err)) = validators.next().await {
                checked_links.push(l2);
                if let Some(e) = err {
                    link_errors.push(e);
                }
            }
        }
        let client = client.clone();
        let parent = url.to_string();
        let log2 = log.clone();
        validators.push(async move {
            let target = Url::parse(&l).ok();
            let parent_host = Url::parse(&parent)
                .ok()
                .and_then(|pu| pu.domain().map(|s| s.to_string()));
            let target_host = target
                .as_ref()
                .and_then(|u| u.domain().map(|s| s.to_string()));
            let external = target_host != parent_host;
            if external && !check_externals {
                if let Some(tx) = &log2 {
                    let _ = tx.send(format!("skip validation (external & disabled): {}", l));
                }
                return (l, None, None);
            }
            let st = match client.head(&l).timeout(Duration::from_secs(3)).send().await {
                Ok(r) => Some(r.status().as_u16()),
                Err(_) => None,
            };
            let st = match st {
                Some(s) if s == 405 || s == 501 => client
                    .get(&l)
                    .header(reqwest::header::RANGE, "bytes=0-0")
                    .timeout(Duration::from_secs(3))
                    .send()
                    .await
                    .ok()
                    .map(|r| r.status().as_u16()),
                other => other,
            };
            let err = match st {
                Some(code) if code >= 400 => Some(LinkError {
                    url: l.clone(),
                    status: Some(code),
                    reason: format!("HTTP {}", code),
                    parent: parent.clone(),
                    external,
                }),
                None => Some(LinkError {
                    url: l.clone(),
                    status: None,
                    reason: "request failed".into(),
                    parent: parent.clone(),
                    external,
                }),
                _ => None,
            };
            if let Some(tx) = &log2 {
                let _ = tx.send(format!(
                    "checked {} status={:?} external={}",
                    l, st, external
                ));
            }
            (l, st, err)
        });
    }

    while let Some((l, _st, err)) = validators.next().await {
        checked_links.push(l);
        if let Some(e) = err {
            link_errors.push(e);
        }
    }

    let text = if content_type
        .as_deref()
        .unwrap_or("")
        .starts_with("text/html")
    {
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
        signals,
    };

    if let Some(tx) = &log {
        let _ = tx.send(format!("done {}", url));
    }
    Ok((page, checked_links, link_errors))
}
