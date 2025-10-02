use dexteri::models::*;

#[test]
fn test_abc_progress_default() {
    let progress = AbcProgress::default();
    
    assert_eq!(progress.a.pages_crawled, 0);
    assert_eq!(progress.a.links_checked, 0);
    assert_eq!(progress.b.pages_crawled, 0);
    assert_eq!(progress.c.pages_crawled, 0);
    assert_eq!(progress.combined_pct, 0);
}

#[test]
fn test_ab_progress_default() {
    let progress = AbProgress::default();
    
    assert_eq!(progress.a.pages_crawled, 0);
    assert_eq!(progress.a.links_checked, 0);
    assert_eq!(progress.b.pages_crawled, 0);
    assert_eq!(progress.combined_pct, 0);
}

#[test]
fn test_domain_metrics_from_crawl_empty() {
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    
    assert_eq!(metrics.pages_crawled, 0);
    assert_eq!(metrics.links_checked, 0);
    assert_eq!(metrics.broken_links, 0);
    assert_eq!(metrics.json_ld_blocks, 0);
    assert_eq!(metrics.microdata_items, 0);
    assert_eq!(metrics.og_tags, 0);
    assert_eq!(metrics.twitter_tags, 0);
    assert_eq!(metrics.robots_pages, 0);
    assert_eq!(metrics.canonical_pages, 0);
    assert_eq!(metrics.hreflang_total, 0);
    assert!(metrics.tracker_counts.is_empty());
}

#[test]
fn test_domain_metrics_from_crawl_with_signals() {
    let crawl = CrawlResult {
        pages_crawled: 2,
        links_checked: 10,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Some text content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 3,
                    json_ld_types: vec!["Article".to_string()],
                    json_ld_raw: vec![],
                    microdata_items: 2,
                    microdata_types: vec![],
                    open_graph_tags: 5,
                    og_props: vec![],
                    twitter_tags: 4,
                    twitter_names: vec![],
                    meta_robots: Some("index,follow".to_string()),
                    canonical_url: Some("https://example.com".to_string()),
                    hreflang_count: 2,
                    hreflang_langs: vec!["en".to_string(), "es".to_string()],
                    trackers: vec!["Google Analytics".to_string(), "Facebook Pixel".to_string()],
                }),
            },
            Page {
                url: "https://example.com/about".to_string(),
                status: Some(200),
                title: Some("About".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(2048),
                text: Some("About page content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 1,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 0,
                    microdata_types: vec![],
                    open_graph_tags: 3,
                    og_props: vec![],
                    twitter_tags: 2,
                    twitter_names: vec![],
                    meta_robots: None,
                    canonical_url: None,
                    hreflang_count: 0,
                    hreflang_langs: vec![],
                    trackers: vec!["Google Analytics".to_string()],
                }),
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    
    assert_eq!(metrics.pages_crawled, 2);
    assert_eq!(metrics.links_checked, 10);
    assert_eq!(metrics.broken_links, 0);
    assert_eq!(metrics.json_ld_blocks, 4); // 3 + 1
    assert_eq!(metrics.microdata_items, 2); // 2 + 0
    assert_eq!(metrics.og_tags, 8); // 5 + 3
    assert_eq!(metrics.twitter_tags, 6); // 4 + 2
    assert_eq!(metrics.robots_pages, 1); // Only first page has robots
    assert_eq!(metrics.canonical_pages, 1); // Only first page has canonical
    assert_eq!(metrics.hreflang_total, 2); // 2 + 0
    assert_eq!(metrics.tracker_counts.len(), 2);
    assert_eq!(metrics.tracker_counts.get("Google Analytics"), Some(&2)); // Appears in both
    assert_eq!(metrics.tracker_counts.get("Facebook Pixel"), Some(&1)); // Appears in one
}

#[test]
fn test_domain_metrics_hubspot_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("This page uses hs-scripts.com for analytics".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.hubspot, 1, "Should detect HubSpot");
}

#[test]
fn test_domain_metrics_pardot_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Tracking with pardot.com".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.pardot, 1, "Should detect Pardot");
}

#[test]
fn test_domain_metrics_marketo_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Using munchkin.js for tracking".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.marketo, 1, "Should detect Marketo");
}

#[test]
fn test_domain_metrics_salesforce_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Powered by salesforce.com".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.salesforce, 1, "Should detect Salesforce");
}

#[test]
fn test_domain_metrics_segment_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("analytics.load( using cdn.segment.com".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.segment, 1, "Should detect Segment");
}

#[test]
fn test_domain_metrics_intercom_detection() {
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Chat with widget.intercom.io".to_string()),
                signals: None,
            },
        ],
    };
    
    let metrics = DomainMetrics::from_crawl(&crawl);
    assert_eq!(metrics.intercom, 1, "Should detect Intercom");
}

#[test]
fn test_ab_result_compute_identical() {
    let crawl_a = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: None,
            },
        ],
    };
    
    let crawl_b = crawl_a.clone();
    
    let result = AbResult::compute(&crawl_a, &crawl_b);
    
    assert_eq!(result.diff.url_only_in_a.len(), 0);
    assert_eq!(result.diff.url_only_in_b.len(), 0);
    assert_eq!(result.diff.status_changes.len(), 0);
    assert_eq!(result.diff.broken_delta.0, 0);
    assert_eq!(result.diff.broken_delta.1, 0);
}

#[test]
fn test_ab_result_compute_new_page() {
    let crawl_a = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: None,
            },
        ],
    };
    
    let crawl_b = CrawlResult {
        pages_crawled: 2,
        links_checked: 10,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: None,
            },
            Page {
                url: "https://example.com/new".to_string(),
                status: Some(200),
                title: Some("New Page".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(2048),
                text: Some("New content".to_string()),
                signals: None,
            },
        ],
    };
    
    let result = AbResult::compute(&crawl_a, &crawl_b);
    
    assert_eq!(result.diff.url_only_in_a.len(), 0);
    assert_eq!(result.diff.url_only_in_b.len(), 1);
    assert!(result.diff.url_only_in_b.contains(&"https://example.com/new".to_string()));
}

#[test]
fn test_ab_result_compute_status_change() {
    let crawl_a = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/page".to_string(),
                status: Some(200),
                title: Some("Page".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: None,
            },
        ],
    };
    
    let crawl_b = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/page".to_string(),
                status: Some(404),
                title: None,
                links: vec![],
                content_type: None,
                bytes: Some(0),
                text: None,
                signals: None,
            },
        ],
    };
    
    let result = AbResult::compute(&crawl_a, &crawl_b);
    
    assert_eq!(result.diff.status_changes.len(), 1);
    assert_eq!(result.diff.status_changes[0].url, "https://example.com/page");
    assert_eq!(result.diff.status_changes[0].a, Some(200));
    assert_eq!(result.diff.status_changes[0].b, Some(404));
}

#[test]
fn test_ab_result_compute_tracker_changes() {
    let crawl_a = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 1,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 0,
                    microdata_types: vec![],
                    open_graph_tags: 0,
                    og_props: vec![],
                    twitter_tags: 0,
                    twitter_names: vec![],
                    meta_robots: None,
                    canonical_url: None,
                    hreflang_count: 0,
                    hreflang_langs: vec![],
                    trackers: vec!["Google Analytics".to_string()],
                }),
            },
        ],
    };
    
    let crawl_b = CrawlResult {
        pages_crawled: 1,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 2,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 0,
                    microdata_types: vec![],
                    open_graph_tags: 0,
                    og_props: vec![],
                    twitter_tags: 0,
                    twitter_names: vec![],
                    meta_robots: None,
                    canonical_url: None,
                    hreflang_count: 0,
                    hreflang_langs: vec![],
                    trackers: vec!["Google Analytics".to_string(), "Facebook Pixel".to_string()],
                }),
            },
        ],
    };
    
    let result = AbResult::compute(&crawl_a, &crawl_b);
    
    // JSON-LD blocks increased
    assert_eq!(result.diff.signals_delta.json_ld_blocks, -1); // A had 1, B has 2, so delta is 1-2 = -1
    
    // Trackers changed
    assert!(!result.diff.signals_delta.top_trackers.is_empty());
}
