use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkError {
    pub url: String,
    pub status: Option<u16>,
    pub reason: String,
    pub parent: String,
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketingSignals {
    pub json_ld_blocks: usize,
    pub json_ld_types: Vec<String>,
    pub json_ld_raw: Vec<String>,
    pub microdata_items: usize,
    pub microdata_types: Vec<String>,
    pub open_graph_tags: usize,
    pub og_props: Vec<String>,
    pub twitter_tags: usize,
    pub twitter_names: Vec<String>,
    pub meta_robots: Option<String>,
    pub canonical_url: Option<String>,
    pub hreflang_count: usize,
    pub hreflang_langs: Vec<String>,
    pub trackers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub links: Vec<String>,
    pub content_type: Option<String>,
    pub bytes: Option<usize>,
    pub text: Option<String>,
    pub signals: Option<MarketingSignals>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    pub pages_crawled: usize,
    pub links_checked: usize,
    pub broken_links: Vec<LinkError>,
    pub pages: Vec<Page>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsResult {
    pub open_ports: Vec<u16>,
    pub scanned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFlag {
    pub level: String,       // Info | Low | Medium | High | Critical
    pub title: String,       // Short title
    pub description: String, // Details
    pub url: Option<String>, // Related URL if any
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlProgress {
    pub pages_crawled: usize,
    pub links_checked: usize,
    pub queue_size: usize,
    pub in_flight: usize,
    pub broken_links: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub url: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub docs_indexed: usize,
}

// ---- A/B metrics & results ----

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainMetrics {
    // Aggregated signals
    pub json_ld_blocks: usize,
    pub microdata_items: usize,
    pub og_tags: usize,
    pub twitter_tags: usize,
    pub robots_pages: usize,
    pub canonical_pages: usize,
    pub hreflang_total: usize,
    pub tracker_counts: std::collections::HashMap<String, usize>,
    // Lead gen / tooling detections (per-page presence counts)
    pub hubspot: usize,
    pub pardot: usize,
    pub marketo: usize,
    pub salesforce: usize,
    pub segment: usize,
    pub intercom: usize,
    // Crawl aggregates
    pub pages_crawled: usize,
    pub links_checked: usize,
    pub broken_links: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusDelta {
    pub url: String,
    pub a: Option<u16>,
    pub b: Option<u16>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignalsDelta {
    pub json_ld_blocks: i64,
    pub microdata_items: i64,
    pub og_tags: i64,
    pub twitter_tags: i64,
    pub robots_pages: i64,
    pub canonical_pages: i64,
    pub hreflang_total: i64,
    pub top_trackers: Vec<(String, i64)>,
    // Lead gen deltas (A - B)
    pub hubspot: i64,
    pub pardot: i64,
    pub marketo: i64,
    pub salesforce: i64,
    pub segment: i64,
    pub intercom: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbDiff {
    pub url_only_in_a: Vec<String>,
    pub url_only_in_b: Vec<String>,
    pub status_changes: Vec<StatusDelta>,
    pub signals_delta: SignalsDelta,
    pub broken_delta: (usize, usize),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbResult {
    pub a: DomainMetrics,
    pub b: DomainMetrics,
    pub diff: AbDiff,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbProgress {
    pub a: CrawlProgress,
    pub b: CrawlProgress,
    pub combined_pct: u8,
}

impl Default for AbProgress {
    fn default() -> Self {
        Self {
            a: CrawlProgress {
                pages_crawled: 0,
                links_checked: 0,
                queue_size: 0,
                in_flight: 0,
                broken_links: 0,
            },
            b: CrawlProgress {
                pages_crawled: 0,
                links_checked: 0,
                queue_size: 0,
                in_flight: 0,
                broken_links: 0,
            },
            combined_pct: 0,
        }
    }
}

impl DomainMetrics {
    #[allow(dead_code)]
    pub fn from_crawl(crawl: &CrawlResult) -> Self {
        use std::collections::HashMap;
        let mut m = DomainMetrics::default();
        let mut trackers: HashMap<String, usize> = HashMap::new();
        let mut robots_pages = 0usize;
        let mut canonical_pages = 0usize;
        let mut hreflang_total = 0usize;
        for p in &crawl.pages {
            if let Some(s) = &p.signals {
                m.json_ld_blocks += s.json_ld_blocks;
                m.microdata_items += s.microdata_items;
                m.og_tags += s.open_graph_tags;
                m.twitter_tags += s.twitter_tags;
                if s.meta_robots.as_deref().unwrap_or("").len() > 0 {
                    robots_pages += 1;
                }
                if s.canonical_url.as_deref().unwrap_or("").len() > 0 {
                    canonical_pages += 1;
                }
                hreflang_total += s.hreflang_count;
                for t in &s.trackers {
                    *trackers.entry(t.clone()).or_insert(0) += 1;
                }
            }
            // Leadgen/tool detection from page text (presence per page)
            if let Some(txt) = &p.text {
                let body = txt.to_ascii_lowercase();
                if body.contains("hs-scripts.com")
                    || body.contains("hubspot.com")
                    || body.contains("hs-analytics")
                {
                    m.hubspot += 1;
                }
                if body.contains("pardot.com")
                    || body.contains("pi.pardot.com")
                    || body.contains("pardot")
                {
                    m.pardot += 1;
                }
                if body.contains("marketo.com")
                    || body.contains("munchkin.js")
                    || body.contains("mktoforms2")
                {
                    m.marketo += 1;
                }
                if body.contains("salesforce.com") || body.contains("sf-embed") {
                    m.salesforce += 1;
                }
                if body.contains("segment.com/analytics.js")
                    || body.contains("cdn.segment.com")
                    || body.contains("analytics.load(")
                {
                    m.segment += 1;
                }
                if body.contains("intercom.io")
                    || body.contains("widget.intercom.io")
                    || body.contains("window.intercom")
                {
                    m.intercom += 1;
                }
            }
        }
        m.robots_pages = robots_pages;
        m.canonical_pages = canonical_pages;
        m.hreflang_total = hreflang_total;
        m.tracker_counts = trackers;
        m.pages_crawled = crawl.pages_crawled;
        m.links_checked = crawl.links_checked;
        m.broken_links = crawl.broken_links.len();
        m
    }
}

impl AbResult {
    #[allow(dead_code)]
    pub fn compute(a: &CrawlResult, b: &CrawlResult) -> Self {
        use std::collections::{HashMap, HashSet};
        let ma = DomainMetrics::from_crawl(a);
        let mb = DomainMetrics::from_crawl(b);

        // URL sets
        let seta: HashSet<String> = a.pages.iter().map(|p| p.url.clone()).collect();
        let setb: HashSet<String> = b.pages.iter().map(|p| p.url.clone()).collect();
        let mut only_a: Vec<String> = seta.difference(&setb).cloned().collect();
        let mut only_b: Vec<String> = setb.difference(&seta).cloned().collect();
        only_a.sort();
        only_b.sort();

        // Status changes for common URLs
        let mut map_a: HashMap<String, Option<u16>> = HashMap::new();
        for p in &a.pages {
            map_a.insert(p.url.clone(), p.status);
        }
        let mut map_b: HashMap<String, Option<u16>> = HashMap::new();
        for p in &b.pages {
            map_b.insert(p.url.clone(), p.status);
        }
        let mut changes: Vec<StatusDelta> = Vec::new();
        for k in seta.intersection(&setb) {
            let av = map_a.get(k).copied().unwrap_or(None);
            let bv = map_b.get(k).copied().unwrap_or(None);
            if av != bv {
                changes.push(StatusDelta {
                    url: k.to_string(),
                    a: av,
                    b: bv,
                });
            }
        }
        changes.sort_by(|x, y| x.url.cmp(&y.url));

        // Signals delta
        let mut top: Vec<(String, i64)> = Vec::new();
        let mut keys: std::collections::HashSet<String> =
            ma.tracker_counts.keys().cloned().collect();
        keys.extend(mb.tracker_counts.keys().cloned());
        for k in keys {
            let a = *ma.tracker_counts.get(&k).unwrap_or(&0) as i64;
            let b = *mb.tracker_counts.get(&k).unwrap_or(&0) as i64;
            if a != b {
                top.push((k, a - b));
            }
        }
        top.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()).then(a.0.cmp(&b.0)));
        let sig = SignalsDelta {
            json_ld_blocks: ma.json_ld_blocks as i64 - mb.json_ld_blocks as i64,
            microdata_items: ma.microdata_items as i64 - mb.microdata_items as i64,
            og_tags: ma.og_tags as i64 - mb.og_tags as i64,
            twitter_tags: ma.twitter_tags as i64 - mb.twitter_tags as i64,
            robots_pages: ma.robots_pages as i64 - mb.robots_pages as i64,
            canonical_pages: ma.canonical_pages as i64 - mb.canonical_pages as i64,
            hreflang_total: ma.hreflang_total as i64 - mb.hreflang_total as i64,
            top_trackers: top.into_iter().take(50).collect(),
            hubspot: ma.hubspot as i64 - mb.hubspot as i64,
            pardot: ma.pardot as i64 - mb.pardot as i64,
            marketo: ma.marketo as i64 - mb.marketo as i64,
            salesforce: ma.salesforce as i64 - mb.salesforce as i64,
            segment: ma.segment as i64 - mb.segment as i64,
            intercom: ma.intercom as i64 - mb.intercom as i64,
        };

        let diff = AbDiff {
            url_only_in_a: only_a,
            url_only_in_b: only_b,
            status_changes: changes,
            signals_delta: sig,
            broken_delta: (ma.broken_links, mb.broken_links),
        };

        AbResult { a: ma, b: mb, diff }
    }
}
