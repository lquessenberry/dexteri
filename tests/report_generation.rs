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
