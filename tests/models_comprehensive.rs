// Comprehensive tests for models.rs - push all edge cases
use dexteri::models::*;
use serde_json;

#[test]
fn test_page_full_serialization() {
    let page = Page {
        url: "https://example.com/test".to_string(),
        status: Some(200),
        title: Some("Test Page".to_string()),
        links: vec![
            "https://example.com/link1".to_string(),
            "https://example.com/link2".to_string(),
        ],
        content_type: Some("text/html; charset=utf-8".to_string()),
        bytes: Some(2048),
        text: Some("Page content here".to_string()),
        signals: Some(MarketingSignals {
            json_ld_blocks: 2,
            json_ld_types: vec!["Article".to_string(), "Person".to_string()],
            json_ld_raw: vec!["{}".to_string()],
            microdata_items: 3,
            microdata_types: vec!["Product".to_string()],
            open_graph_tags: 10,
            og_props: vec!["og:title=Title".to_string()],
            twitter_tags: 5,
            twitter_names: vec!["twitter:card=summary".to_string()],
            meta_robots: Some("index,follow".to_string()),
            canonical_url: Some("https://example.com/canonical".to_string()),
            hreflang_count: 2,
            hreflang_langs: vec!["en".to_string(), "es".to_string()],
            trackers: vec!["Google Analytics".to_string(), "Facebook Pixel".to_string()],
        }),
    };
    
    let json = serde_json::to_string(&page).unwrap();
    assert!(json.contains("example.com"));
    assert!(json.contains("Test Page"));
    
    let page2: Page = serde_json::from_str(&json).unwrap();
    assert_eq!(page2.url, page.url);
    assert_eq!(page2.status, page.status);
    assert_eq!(page2.title, page.title);
}

#[test]
fn test_page_minimal() {
    let page = Page {
        url: "https://example.com".to_string(),
        status: None,
        title: None,
        links: vec![],
        content_type: None,
        bytes: None,
        text: None,
        signals: None,
    };
    
    let json = serde_json::to_string(&page).unwrap();
    let page2: Page = serde_json::from_str(&json).unwrap();
    assert_eq!(page2.url, page.url);
}

#[test]
fn test_link_error_serialization() {
    let error = LinkError {
        url: "https://example.com/404".to_string(),
        status: Some(404),
        reason: "Not Found".to_string(),
        parent: "https://example.com".to_string(),
        external: false,
    };
    
    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("404"));
    assert!(json.contains("Not Found"));
    
    let error2: LinkError = serde_json::from_str(&json).unwrap();
    assert_eq!(error2.url, error.url);
    assert_eq!(error2.status, error.status);
}

#[test]
fn test_link_error_external() {
    let error = LinkError {
        url: "https://external.com/broken".to_string(),
        status: None,
        reason: "Connection timeout".to_string(),
        parent: "https://example.com/page".to_string(),
        external: true,
    };
    
    let json = serde_json::to_string(&error).unwrap();
    let error2: LinkError = serde_json::from_str(&json).unwrap();
    assert_eq!(error2.external, true);
}

#[test]
fn test_crawl_result_large() {
    let mut pages = vec![];
    for i in 0..100 {
        pages.push(Page {
            url: format!("https://example.com/page{}", i),
            status: Some(200),
            title: Some(format!("Page {}", i)),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(1024),
            text: None,
            signals: None,
        });
    }
    
    let result = CrawlResult {
        pages_crawled: 100,
        links_checked: 500,
        broken_links: vec![],
        pages,
    };
    
    let json = serde_json::to_string(&result).unwrap();
    let result2: CrawlResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result2.pages_crawled, 100);
    assert_eq!(result2.pages.len(), 100);
}

#[test]
fn test_crawl_result_with_broken_links() {
    let result = CrawlResult {
        pages_crawled: 5,
        links_checked: 20,
        broken_links: vec![
            LinkError {
                url: "https://example.com/404".to_string(),
                status: Some(404),
                reason: "Not Found".to_string(),
                parent: "https://example.com".to_string(),
                external: false,
            },
            LinkError {
                url: "https://external.com/500".to_string(),
                status: Some(500),
                reason: "Server Error".to_string(),
                parent: "https://example.com".to_string(),
                external: true,
            },
        ],
        pages: vec![],
    };
    
    let json = serde_json::to_string(&result).unwrap();
    let result2: CrawlResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result2.broken_links.len(), 2);
}

#[test]
fn test_ports_result_many() {
    let result = PortsResult {
        open_ports: vec![22, 80, 443, 3306, 5432, 8080, 8443, 9000],
        scanned: 65535,
    };
    
    let json = serde_json::to_string(&result).unwrap();
    let result2: PortsResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result2.open_ports.len(), 8);
    assert_eq!(result2.scanned, 65535);
}

#[test]
fn test_finding_all_fields() {
    let finding = Finding {
        title: "SQL Injection Vulnerability".to_string(),
        description: "A critical SQL injection flaw was detected.".to_string(),
        severity: "Critical".to_string(),
        url: Some("https://example.com/vulnerable".to_string()),
    };
    
    let json = serde_json::to_string(&finding).unwrap();
    let finding2: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding2.severity, "Critical");
}

#[test]
fn test_finding_no_url() {
    let finding = Finding {
        title: "Generic Finding".to_string(),
        description: "Description".to_string(),
        severity: "Low".to_string(),
        url: None,
    };
    
    let json = serde_json::to_string(&finding).unwrap();
    let finding2: Finding = serde_json::from_str(&json).unwrap();
    assert!(finding2.url.is_none());
}

#[test]
fn test_vuln_report_multiple() {
    let report = VulnReport {
        findings: vec![
            Finding {
                title: "XSS".to_string(),
                description: "Cross-site scripting".to_string(),
                severity: "High".to_string(),
                url: Some("https://example.com/xss".to_string()),
            },
            Finding {
                title: "CSRF".to_string(),
                description: "Cross-site request forgery".to_string(),
                severity: "Medium".to_string(),
                url: None,
            },
        ],
    };
    
    let json = serde_json::to_string(&report).unwrap();
    let report2: VulnReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report2.findings.len(), 2);
}

#[test]
fn test_security_flag_all_levels() {
    let flags = vec![
        SecurityFlag {
            level: "Critical".to_string(),
            title: "No HTTPS".to_string(),
            description: "Site uses HTTP".to_string(),
            url: Some("http://example.com".to_string()),
        },
        SecurityFlag {
            level: "High".to_string(),
            title: "Missing CSP".to_string(),
            description: "No Content-Security-Policy".to_string(),
            url: Some("https://example.com".to_string()),
        },
        SecurityFlag {
            level: "Medium".to_string(),
            title: "Weak Cookie".to_string(),
            description: "Cookie settings".to_string(),
            url: None,
        },
        SecurityFlag {
            level: "Low".to_string(),
            title: "Info Disclosure".to_string(),
            description: "Server header".to_string(),
            url: None,
        },
    ];
    
    for flag in &flags {
        let json = serde_json::to_string(flag).unwrap();
        let flag2: SecurityFlag = serde_json::from_str(&json).unwrap();
        assert_eq!(flag2.level, flag.level);
    }
}

#[test]
fn test_marketing_signals_full() {
    let signals = MarketingSignals {
        json_ld_blocks: 5,
        json_ld_types: vec!["Article".to_string(), "Person".to_string(), "Organization".to_string()],
        json_ld_raw: vec!["{}".to_string(), "{}".to_string()],
        microdata_items: 10,
        microdata_types: vec!["Product".to_string(), "Review".to_string()],
        open_graph_tags: 15,
        og_props: vec![
            "og:title=Title".to_string(),
            "og:description=Desc".to_string(),
        ],
        twitter_tags: 8,
        twitter_names: vec![
            "twitter:card=summary".to_string(),
            "twitter:site=@site".to_string(),
        ],
        meta_robots: Some("index,follow,noarchive".to_string()),
        canonical_url: Some("https://example.com/canonical".to_string()),
        hreflang_count: 5,
        hreflang_langs: vec!["en".to_string(), "es".to_string(), "fr".to_string()],
        trackers: vec![
            "Google Analytics".to_string(),
            "Facebook Pixel".to_string(),
            "Hotjar".to_string(),
            "Mixpanel".to_string(),
        ],
    };
    
    let json = serde_json::to_string(&signals).unwrap();
    let signals2: MarketingSignals = serde_json::from_str(&json).unwrap();
    assert_eq!(signals2.json_ld_blocks, 5);
    assert_eq!(signals2.trackers.len(), 4);
}

#[test]
fn test_marketing_signals_minimal() {
    let signals = MarketingSignals {
        json_ld_blocks: 0,
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
        trackers: vec![],
    };
    
    let json = serde_json::to_string(&signals).unwrap();
    let signals2: MarketingSignals = serde_json::from_str(&json).unwrap();
    assert_eq!(signals2.json_ld_blocks, 0);
}

#[test]
fn test_search_hit_serialization() {
    let result = SearchHit {
        title: Some("Test Result".to_string()),
        url: "https://example.com/result".to_string(),
    };
    
    let json = serde_json::to_string(&result).unwrap();
    let result2: SearchHit = serde_json::from_str(&json).unwrap();
    assert_eq!(result2.url, result.url);
}

#[test]
fn test_crawl_progress_serialization() {
    let progress = CrawlProgress {
        pages_crawled: 20,
        links_checked: 50,
        queue_size: 10,
        in_flight: 5,
        broken_links: 2,
    };
    
    let json = serde_json::to_string(&progress).unwrap();
    let progress2: CrawlProgress = serde_json::from_str(&json).unwrap();
    assert_eq!(progress2.in_flight, 5);
    assert_eq!(progress2.pages_crawled, 20);
}

#[test]
fn test_page_with_unicode() {
    let page = Page {
        url: "https://example.com/日本語".to_string(),
        status: Some(200),
        title: Some("日本語のタイトル".to_string()),
        links: vec![],
        content_type: Some("text/html; charset=utf-8".to_string()),
        bytes: Some(1024),
        text: Some("コンテンツ".to_string()),
        signals: None,
    };
    
    let json = serde_json::to_string(&page).unwrap();
    let page2: Page = serde_json::from_str(&json).unwrap();
    assert_eq!(page2.title, page.title);
}

#[test]
fn test_page_with_special_chars() {
    let page = Page {
        url: "https://example.com/page?param=value&other=123".to_string(),
        status: Some(200),
        title: Some("Page with \"quotes\" & <tags>".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(512),
        text: Some("Content with\nnewlines\tand\ttabs".to_string()),
        signals: None,
    };
    
    let json = serde_json::to_string(&page).unwrap();
    let page2: Page = serde_json::from_str(&json).unwrap();
    assert_eq!(page2.url, page.url);
}
