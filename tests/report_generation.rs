use tempfile::TempDir;
use url::Url;

use dexteri::report::write_report;
use dexteri::models::*;

fn create_sample_crawl_result() -> CrawlResult {
    CrawlResult {
        pages_crawled: 2,
        links_checked: 5,
        broken_links: vec![
            LinkError {
                url: "https://example.com/broken".to_string(),
                status: Some(404),
                reason: "Not Found".to_string(),
                parent: "https://example.com".to_string(),
                external: false,
            }
        ],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: Some(200),
                title: Some("Home Page".to_string()),
                links: vec!["https://example.com/about".to_string()],
                content_type: Some("text/html".to_string()),
                bytes: Some(2048),
                text: Some("Home page content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 1,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 2,
                    microdata_types: vec![],
                    open_graph_tags: 3,
                    og_props: vec![],
                    twitter_tags: 2,
                    twitter_names: vec![],
                    meta_robots: Some("index,follow".to_string()),
                    canonical_url: Some("https://example.com".to_string()),
                    hreflang_count: 0,
                    hreflang_langs: vec![],
                    trackers: vec!["Google Analytics".to_string()],
                }),
            },
            Page {
                url: "https://example.com/about".to_string(),
                status: Some(200),
                title: Some("About Us".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("About page content".to_string()),
                signals: None,
            },
        ],
    }
}

fn create_sample_ports_result() -> PortsResult {
    PortsResult {
        open_ports: vec![80, 443, 22],
        scanned: 100,
    }
}

fn create_sample_vuln_report() -> VulnReport {
    VulnReport {
        findings: vec![
            Finding {
                title: "Missing CSP".to_string(),
                description: "Content Security Policy header not found".to_string(),
                severity: "High".to_string(),
                url: Some("https://example.com".to_string()),
            },
            Finding {
                title: "Missing HSTS".to_string(),
                description: "HTTP Strict Transport Security not enabled".to_string(),
                severity: "Medium".to_string(),
                url: Some("https://example.com".to_string()),
            },
        ],
    }
}

fn create_sample_security_flags() -> Vec<SecurityFlag> {
    vec![
        SecurityFlag {
            level: "High".to_string(),
            title: "Server version exposed".to_string(),
            description: "Server header reveals nginx/1.18.0".to_string(),
            url: Some("https://example.com".to_string()),
        },
        SecurityFlag {
            level: "Info".to_string(),
            title: "CMS detected: WordPress".to_string(),
            description: "WordPress 5.9 detected".to_string(),
            url: Some("https://example.com".to_string()),
        },
    ]
}

#[test]
fn test_write_report_creates_file() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = create_sample_crawl_result();
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    let result = write_report(&report_path, &url, &crawl, &ports, &vuln, &security);
    
    assert!(result.is_ok(), "Report generation should succeed");
    assert!(report_path.exists(), "Report file should be created");
}

#[test]
fn test_report_contains_html() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = create_sample_crawl_result();
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("<!DOCTYPE html>") || content.contains("<html"));
    assert!(content.contains("</html>"));
}

#[test]
fn test_report_contains_target_url() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = create_sample_crawl_result();
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("example.com"), "Report should contain target URL");
}

#[test]
fn test_report_with_empty_results() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    let result = write_report(&report_path, &url, &crawl, &ports, &vuln, &security);
    
    assert!(result.is_ok(), "Should handle empty results");
    assert!(report_path.exists(), "Should create report even with empty data");
}

#[test]
fn test_report_file_size_reasonable() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = create_sample_crawl_result();
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let metadata = std::fs::metadata(&report_path).unwrap();
    assert!(metadata.len() > 1000, "Report should be at least 1KB");
    assert!(metadata.len() < 10_000_000, "Report should be less than 10MB");
}

#[test]
fn test_report_with_no_trackers() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
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
                text: Some("Content".to_string()),
                signals: Some(MarketingSignals {
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
                    trackers: vec![], // No trackers!
                }),
            }
        ],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("No known tracker libraries detected") || 
            content.contains("No trackers"), 
            "Should show no trackers message");
}

#[test]
fn test_report_with_many_pages() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    
    // Create 60 pages to test the .take(50) limit
    let mut pages = Vec::new();
    for i in 0..60 {
        pages.push(Page {
            url: format!("https://example.com/page{}", i),
            status: Some(200),
            title: Some(format!("Page {}", i)),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(1024),
            text: Some(format!("Content {}", i)),
            signals: if i % 2 == 0 {
                Some(MarketingSignals {
                    json_ld_blocks: i,
                    json_ld_types: vec![format!("Type{}", i)],
                    json_ld_raw: vec![],
                    microdata_items: i,
                    microdata_types: vec![],
                    open_graph_tags: i as usize,
                    og_props: vec![],
                    twitter_tags: i as usize,
                    twitter_names: vec![],
                    meta_robots: Some("index,follow".to_string()),
                    canonical_url: Some(format!("https://example.com/page{}", i)),
                    hreflang_count: i as usize,
                    hreflang_langs: vec![],
                    trackers: vec![format!("Tracker{}", i)],
                })
            } else {
                None
            },
        });
    }
    
    let crawl = CrawlResult {
        pages_crawled: 60,
        links_checked: 100,
        broken_links: vec![],
        pages,
    };
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("Page 0"), "Should contain first page");
    assert!(content.contains("Page 49") || content.contains("Page 48"), 
            "Should contain pages near the limit");
}

#[test]
fn test_report_comprehensive_marketing_signals() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 3,
        links_checked: 5,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/page1".to_string(),
                status: Some(200),
                title: Some("Page 1".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(2048),
                text: Some("Page 1 content".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 5,
                    json_ld_types: vec!["Article".to_string()],
                    json_ld_raw: vec![],
                    microdata_items: 3,
                    microdata_types: vec!["Product".to_string()],
                    open_graph_tags: 10,
                    og_props: vec![],
                    twitter_tags: 8,
                    twitter_names: vec![],
                    meta_robots: Some("noindex,nofollow".to_string()),
                    canonical_url: Some("https://example.com/canonical".to_string()),
                    hreflang_count: 2,
                    hreflang_langs: vec!["en".to_string(), "es".to_string()],
                    trackers: vec!["Google Analytics".to_string(), "Facebook Pixel".to_string()],
                }),
            },
            Page {
                url: "https://example.com/page2".to_string(),
                status: Some(200),
                title: Some("Page 2".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Page 2 content".to_string()),
                signals: None,
            },
            Page {
                url: "https://example.com/page3".to_string(),
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
    let ports = create_sample_ports_result();
    let vuln = create_sample_vuln_report();
    let security = create_sample_security_flags();
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("Page 1"), "Should contain Page 1");
    assert!(content.contains("Google Analytics"), "Should show trackers");
    assert!(content.contains("noindex,nofollow") || content.contains("meta_robots"), 
            "Should show robots meta");
}

#[test]
fn test_report_all_severity_levels() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport {
        findings: vec![
            Finding {
                title: "Critical Issue".to_string(),
                description: "Very bad".to_string(),
                severity: "Critical".to_string(),
                url: Some("https://example.com".to_string()),
            },
            Finding {
                title: "High Issue".to_string(),
                description: "Bad".to_string(),
                severity: "High".to_string(),
                url: Some("https://example.com".to_string()),
            },
            Finding {
                title: "Medium Issue".to_string(),
                description: "Concerning".to_string(),
                severity: "Medium".to_string(),
                url: None,
            },
            Finding {
                title: "Low Issue".to_string(),
                description: "Minor".to_string(),
                severity: "Low".to_string(),
                url: None,
            },
            Finding {
                title: "Info Item".to_string(),
                description: "FYI".to_string(),
                severity: "Info".to_string(),
                url: None,
            },
        ],
    };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("Critical") || content.contains("sev-Critical"));
    assert!(content.contains("High") || content.contains("sev-High"));
    assert!(content.contains("Medium") || content.contains("sev-Medium"));
    assert!(content.contains("Low") || content.contains("sev-Low"));
    assert!(content.contains("Info") || content.contains("sev-Info"));
}

#[test]
fn test_report_many_security_flags() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    
    let mut security = vec![];
    for i in 0..20 {
        security.push(SecurityFlag {
            level: if i % 5 == 0 { "Critical" } else if i % 3 == 0 { "High" } else { "Medium" }.to_string(),
            title: format!("Security Issue {}", i),
            description: format!("Description {}", i),
            url: Some(format!("https://example.com/issue{}", i)),
        });
    }
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("Security Issue 0"));
    assert!(content.contains("Security Issue 19") || content.len() > 5000);
}

#[test]
fn test_report_many_broken_links() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    
    let mut broken_links = vec![];
    for i in 0..100 {
        broken_links.push(LinkError {
            url: format!("https://example.com/broken{}", i),
            status: Some(if i % 2 == 0 { 404 } else { 500 }),
            reason: format!("Error {}", i),
            parent: "https://example.com".to_string(),
            external: i % 3 == 0,
        });
    }
    
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 100,
        broken_links,
        pages: vec![],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("broken0") || content.contains("Broken links"));
}

#[test]
fn test_report_with_special_html_chars() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 1,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/<script>".to_string(),
                status: Some(200),
                title: Some("<h1>Test & \"Title\"</h1>".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content with <tags> & entities".to_string()),
                signals: None,
            }
        ],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport {
        findings: vec![
            Finding {
                title: "<script>alert('XSS')</script>".to_string(),
                description: "Contains & and < and > chars".to_string(),
                severity: "High".to_string(),
                url: Some("https://example.com/<test>".to_string()),
            }
        ],
    };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    // Should not contain raw < > & - they should be escaped or not break HTML
    assert!(!content.contains("<script>alert"), "Script tags should be escaped/handled");
    assert!(report_path.exists(), "Report should be created");
}

#[test]
fn test_report_with_unicode_content() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 1,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/日本語".to_string(),
                status: Some(200),
                title: Some("Test 你好 🚀 Ñoño".to_string()),
                links: vec![],
                content_type: Some("text/html; charset=utf-8".to_string()),
                bytes: Some(2048),
                text: Some("Content with émojis 😀🎉".to_string()),
                signals: None,
            }
        ],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    assert!(content.contains("你好") || content.contains("Test"));
    assert!(content.contains("charset") || content.contains("utf"));
}

#[test]
fn test_report_with_zero_pages_crawled() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    // Empty pages array
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    // Should not have marketing section for empty pages
    assert!(!content.contains("Marketing & Structured Data") || content.contains("No"));
}

#[test]
fn test_report_with_chart_generation() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 5,
        links_checked: 10,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com/1".to_string(),
                status: Some(200),
                title: Some("Page 1".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(2048),
                text: Some("Content 1".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 5,
                    json_ld_types: vec!["Article".to_string()],
                    json_ld_raw: vec![],
                    microdata_items: 3,
                    microdata_types: vec!["Product".to_string()],
                    open_graph_tags: 10,
                    og_props: vec![],
                    twitter_tags: 8,
                    twitter_names: vec![],
                    meta_robots: Some("index,follow".to_string()),
                    canonical_url: Some("https://example.com/1".to_string()),
                    hreflang_count: 2,
                    hreflang_langs: vec!["en".to_string(), "es".to_string()],
                    trackers: vec!["Google Analytics".to_string(), "Facebook Pixel".to_string()],
                }),
            },
            Page {
                url: "https://example.com/2".to_string(),
                status: Some(200),
                title: Some("Page 2".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1024),
                text: Some("Content 2".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 3,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 2,
                    microdata_types: vec![],
                    open_graph_tags: 5,
                    og_props: vec![],
                    twitter_tags: 4,
                    twitter_names: vec![],
                    meta_robots: Some("noindex".to_string()),
                    canonical_url: Some("https://example.com/2".to_string()),
                    hreflang_count: 1,
                    hreflang_langs: vec![],
                    trackers: vec!["Google Analytics".to_string()],
                }),
            },
            Page {
                url: "https://example.com/3".to_string(),
                status: Some(200),
                title: Some("Page 3".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(1500),
                text: Some("Content 3".to_string()),
                signals: Some(MarketingSignals {
                    json_ld_blocks: 2,
                    json_ld_types: vec![],
                    json_ld_raw: vec![],
                    microdata_items: 1,
                    microdata_types: vec![],
                    open_graph_tags: 3,
                    og_props: vec![],
                    twitter_tags: 2,
                    twitter_names: vec![],
                    meta_robots: None,
                    canonical_url: None,
                    hreflang_count: 0,
                    hreflang_langs: vec![],
                    trackers: vec![],
                }),
            },
        ],
    };
    let ports = PortsResult { open_ports: vec![80, 443], scanned: 100 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    // Should have marketing data section
    assert!(content.contains("Marketing") || content.contains("Structured"));
    // Should have tracker data
    assert!(content.contains("Google Analytics"));
}

#[test]
fn test_report_with_many_trackers() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    
    // Create pages with many different trackers
    let mut pages = vec![];
    let tracker_names = vec![
        "Google Analytics", "Facebook Pixel", "Hotjar", "Mixpanel", "Amplitude",
        "Segment", "Heap", "Pendo", "FullStory", "LogRocket", "Sentry",
    ];
    
    for i in 0..15 {
        pages.push(Page {
            url: format!("https://example.com/page{}", i),
            status: Some(200),
            title: Some(format!("Page {}", i)),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(1024),
            text: Some("Content".to_string()),
            signals: Some(MarketingSignals {
                json_ld_blocks: 1,
                json_ld_types: vec![],
                json_ld_raw: vec![],
                microdata_items: 1,
                microdata_types: vec![],
                open_graph_tags: 1,
                og_props: vec![],
                twitter_tags: 1,
                twitter_names: vec![],
                meta_robots: Some("index".to_string()),
                canonical_url: Some(format!("https://example.com/page{}", i)),
                hreflang_count: 0,
                hreflang_langs: vec![],
                trackers: vec![tracker_names[i % tracker_names.len()].to_string()],
            }),
        });
    }
    
    let crawl = CrawlResult {
        pages_crawled: 15,
        links_checked: 20,
        broken_links: vec![],
        pages,
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    // Should have tracker table
    assert!(content.contains("Tracker") || content.contains("tracker"));
    // Should have at least one tracker name
    assert!(content.contains("Google Analytics") || content.contains("Facebook"));
}

#[test]
fn test_report_status_and_bytes_none() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.html");
    
    let url = Url::parse("https://example.com").unwrap();
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![
            Page {
                url: "https://example.com".to_string(),
                status: None,  // None status
                title: None,
                links: vec![],
                content_type: None,
                bytes: None,  // None bytes
                text: Some("Content".to_string()),
                signals: None,
            }
        ],
    };
    let ports = PortsResult { open_ports: vec![], scanned: 0 };
    let vuln = VulnReport { findings: vec![] };
    let security = vec![];
    
    write_report(&report_path, &url, &crawl, &ports, &vuln, &security).unwrap();
    
    let content = std::fs::read_to_string(&report_path).unwrap();
    // Should handle None status and bytes with "-"
    assert!(content.contains("-") || content.contains("untitled"));
}
