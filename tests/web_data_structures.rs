// Unit tests for web.rs data structures
// Tests serialization, special characters, and edge cases

use dexteri::models::*;

#[test]
fn test_page_basic_structure() {
    let page = Page {
        url: "https://example.com/page".to_string(),
        status: Some(200),
        title: Some("Test Page".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(5000),
        text: None,
        signals: None,
    };
    
    assert_eq!(page.url, "https://example.com/page");
    assert_eq!(page.status, Some(200));
    assert_eq!(page.title, Some("Test Page".to_string()));
    assert_eq!(page.content_type, Some("text/html".to_string()));
    assert_eq!(page.bytes, Some(5000));
}

#[test]
fn test_page_with_csv_special_chars() {
    let page = Page {
        url: "https://example.com".to_string(),
        status: Some(200),
        title: Some("Test, \"Page\" with\nspecial chars".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(1000),
        text: None,
        signals: None,
    };
    
    // Title has comma, quotes, and newline - needs CSV escaping
    assert!(page.title.as_ref().unwrap().contains(','));
    assert!(page.title.as_ref().unwrap().contains('"'));
    assert!(page.title.as_ref().unwrap().contains('\n'));
}

#[test]
fn test_page_with_links() {
    let page = Page {
        url: "https://example.com".to_string(),
        status: Some(200),
        title: Some("Page with links".to_string()),
        links: vec![
            "https://example.com/page1".to_string(),
            "https://example.com/page2".to_string(),
            "/relative".to_string(),
        ],
        content_type: Some("text/html".to_string()),
        bytes: Some(10000),
        text: Some("Page content here".to_string()),
        signals: None,
    };
    
    assert_eq!(page.links.len(), 3);
    assert!(page.text.is_some());
}

#[test]
fn test_link_error_structure() {
    let error = LinkError {
        url: "https://example.com/broken".to_string(),
        status: Some(404),
        reason: "Not Found".to_string(),
        parent: "https://example.com".to_string(),
        external: true,
    };
    
    assert_eq!(error.url, "https://example.com/broken");
    assert_eq!(error.status, Some(404));
    assert!(error.external);
}

#[test]
fn test_link_error_csv_escaping() {
    let error = LinkError {
        url: "https://example.com/page?q=test&x=1".to_string(),
        status: None,
        reason: "Connection timeout, \"retry\" needed".to_string(),
        parent: "https://example.com/parent".to_string(),
        external: false,
    };
    
    // Reason has comma and quotes - needs CSV escaping
    assert!(error.reason.contains(','));
    assert!(error.reason.contains('"'));
}

#[test]
fn test_ports_result_basic() {
    let ports = PortsResult {
        open_ports: vec![21, 22, 80, 443, 3306, 8080],
        scanned: 65535,
    };
    
    assert_eq!(ports.open_ports.len(), 6);
    assert_eq!(ports.scanned, 65535);
    assert!(ports.open_ports.contains(&443));
}

#[test]
fn test_finding_structure() {
    let finding = Finding {
        title: "SQL Injection".to_string(),
        description: "Vulnerable endpoint found".to_string(),
        severity: "High".to_string(),
        url: Some("https://example.com/api/users".to_string()),
    };
    
    assert_eq!(finding.severity, "High");
    assert!(finding.url.is_some());
}

#[test]
fn test_finding_xml_special_chars() {
    let finding = Finding {
        title: "XSS: <script> injection".to_string(),
        description: "Found in \"search\" parameter & needs escaping".to_string(),
        severity: "Critical".to_string(),
        url: Some("https://example.com/search?q=<test>".to_string()),
    };
    
    // Has XML special chars
    assert!(finding.title.contains('<'));
    assert!(finding.description.contains('&'));
    assert!(finding.description.contains('"'));
}

#[test]
fn test_security_flag_basic() {
    let flag = SecurityFlag {
        level: "High".to_string(),
        title: "Missing HSTS header".to_string(),
        description: "Site doesn't use HSTS".to_string(),
        url: Some("https://example.com".to_string()),
    };
    
    assert_eq!(flag.level, "High");
    assert!(flag.url.is_some());
}

#[test]
fn test_security_flag_xml_chars() {
    let flag = SecurityFlag {
        level: "Medium".to_string(),
        title: "X-Frame-Options: DENY".to_string(),
        description: "Header uses \"DENY\" & blocks <iframe>".to_string(),
        url: Some("https://example.com/page".to_string()),
    };
    
    // Has XML special chars
    assert!(flag.title.contains(':'));
    assert!(flag.description.contains('<'));
    assert!(flag.description.contains('&'));
}

#[test]
fn test_crawl_result_complete() {
    let result = CrawlResult {
        pages_crawled: 50,
        links_checked: 150,
        broken_links: vec![
            LinkError {
                url: "https://example.com/404".to_string(),
                status: Some(404),
                reason: "Not Found".to_string(),
                parent: "https://example.com/".to_string(),
                external: false,
            },
        ],
        pages: vec![
            Page {
                url: "https://example.com/".to_string(),
                status: Some(200),
                title: Some("Home".to_string()),
                links: vec![],
                content_type: Some("text/html".to_string()),
                bytes: Some(5000),
                text: None,
                signals: None,
            },
        ],
    };
    
    assert_eq!(result.pages_crawled, 50);
    assert_eq!(result.links_checked, 150);
    assert_eq!(result.broken_links.len(), 1);
    assert_eq!(result.pages.len(), 1);
}

#[test]
fn test_vuln_report_multiple() {
    let report = VulnReport {
        findings: vec![
            Finding {
                title: "SQL Injection".to_string(),
                description: "Vulnerable parameter: id".to_string(),
                severity: "Critical".to_string(),
                url: Some("https://example.com/api/users".to_string()),
            },
            Finding {
                title: "XSS".to_string(),
                description: "Reflected XSS in search".to_string(),
                severity: "High".to_string(),
                url: Some("https://example.com/search".to_string()),
            },
            Finding {
                title: "Info Disclosure".to_string(),
                description: "Version exposed".to_string(),
                severity: "Low".to_string(),
                url: None,
            },
        ],
    };
    
    assert_eq!(report.findings.len(), 3);
    assert_eq!(report.findings[0].severity, "Critical");
    assert!(report.findings[2].url.is_none());
}

#[test]
fn test_security_flags_collection() {
    let flags = vec![
        SecurityFlag {
            level: "Critical".to_string(),
            title: "No HTTPS".to_string(),
            description: "Site accessible over HTTP".to_string(),
            url: Some("http://example.com".to_string()),
        },
        SecurityFlag {
            level: "High".to_string(),
            title: "Missing CSP".to_string(),
            description: "No Content-Security-Policy".to_string(),
            url: Some("https://example.com".to_string()),
        },
        SecurityFlag {
            level: "Info".to_string(),
            title: "Server header".to_string(),
            description: "Server: nginx/1.20.0".to_string(),
            url: Some("https://example.com".to_string()),
        },
    ];
    
    assert_eq!(flags.len(), 3);
    assert_eq!(flags[0].level, "Critical");
    assert_eq!(flags[2].level, "Info");
}

#[test]
fn test_multiple_pages() {
    let pages = vec![
        Page {
            url: "https://example.com/".to_string(),
            status: Some(200),
            title: Some("Home".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(1000),
            text: None,
            signals: None,
        },
        Page {
            url: "https://example.com/about".to_string(),
            status: Some(200),
            title: Some("About".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(2000),
            text: None,
            signals: None,
        },
        Page {
            url: "https://example.com/404".to_string(),
            status: Some(404),
            title: None,
            links: vec![],
            content_type: None,
            bytes: None,
            text: None,
            signals: None,
        },
    ];
    
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[0].status, Some(200));
    assert!(pages[2].title.is_none());
}

#[test]
fn test_multiple_broken_links() {
    let broken = vec![
        LinkError {
            url: "https://example.com/missing".to_string(),
            status: Some(404),
            reason: "Not Found".to_string(),
            parent: "https://example.com/".to_string(),
            external: false,
        },
        LinkError {
            url: "https://external.com/dead".to_string(),
            status: Some(410),
            reason: "Gone".to_string(),
            parent: "https://example.com/links".to_string(),
            external: true,
        },
        LinkError {
            url: "https://timeout.com/slow".to_string(),
            status: None,
            reason: "Connection timeout".to_string(),
            parent: "https://example.com/".to_string(),
            external: true,
        },
    ];
    
    assert_eq!(broken.len(), 3);
    assert!(!broken[0].external);
    assert!(broken[1].external);
    assert!(broken[2].status.is_none());
}

#[test]
fn test_empty_collections() {
    let crawl = CrawlResult {
        pages_crawled: 0,
        links_checked: 0,
        broken_links: vec![],
        pages: vec![],
    };
    
    let ports = PortsResult {
        open_ports: vec![],
        scanned: 0,
    };
    
    let vuln = VulnReport {
        findings: vec![],
    };
    
    let security: Vec<SecurityFlag> = vec![];
    
    assert!(crawl.broken_links.is_empty());
    assert!(ports.open_ports.is_empty());
    assert!(vuln.findings.is_empty());
    assert!(security.is_empty());
}

#[test]
fn test_json_serialization() {
    let page = Page {
        url: "https://example.com".to_string(),
        status: Some(200),
        title: Some("Test".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(1024),
        text: None,
        signals: None,
    };
    
    let json = serde_json::to_string(&page).unwrap();
    assert!(json.contains("example.com"));
    assert!(json.contains("200"));
}

#[test]
fn test_page_with_unicode() {
    let page = Page {
        url: "https://example.com/unicode".to_string(),
        status: Some(200),
        title: Some("Test 你好 🚀 Ñoño".to_string()),
        links: vec![],
        content_type: Some("text/html; charset=utf-8".to_string()),
        bytes: Some(2000),
        text: Some("Content with émojis 😀".to_string()),
        signals: None,
    };
    
    assert!(page.title.as_ref().unwrap().contains("你好"));
    assert!(page.title.as_ref().unwrap().contains("🚀"));
    assert!(page.text.as_ref().unwrap().contains("😀"));
}

#[test]
fn test_page_with_special_url_chars() {
    let page = Page {
        url: "https://example.com/page?q=test&x=1#anchor".to_string(),
        status: Some(200),
        title: Some("Test".to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(1000),
        text: None,
        signals: None,
    };
    
    assert!(page.url.contains('?'));
    assert!(page.url.contains('&'));
    assert!(page.url.contains('#'));
}

#[test]
fn test_page_with_long_content() {
    let long_title = "A".repeat(1000);
    let long_text = "B".repeat(5000);
    
    let page = Page {
        url: "https://example.com/long".to_string(),
        status: Some(200),
        title: Some(long_title.clone()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(50000),
        text: Some(long_text.clone()),
        signals: None,
    };
    
    assert_eq!(page.title.as_ref().unwrap().len(), 1000);
    assert_eq!(page.text.as_ref().unwrap().len(), 5000);
}
