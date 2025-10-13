// Golden-style test for report::write_report() sections
use dexteri::{models::*, report};
use tempfile::TempDir;
use url::Url;

#[test]
fn report_golden_minimal_sections() {
    // Prepare temp output
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("report.html");

    // Inputs
    let start = Url::parse("https://example.com/").unwrap();
    let page = Page {
        url: "https://example.com/page".to_string(),
        status: Some(200),
        title: Some("Example Title".to_string()),
        links: vec!["https://example.com/other".to_string()],
        content_type: Some("text/html".to_string()),
        bytes: Some(1234),
        text: Some("Body content".to_string()),
        signals: None,
    };
    let crawl = CrawlResult {
        pages_crawled: 1,
        links_checked: 1,
        broken_links: vec![],
        pages: vec![page],
    };
    let ports = PortsResult {
        open_ports: vec![80, 443],
        scanned: 2,
    };
    let vuln = VulnReport {
        findings: vec![Finding {
            title: "Missing CSP".to_string(),
            description: "CSP not present".to_string(),
            severity: "High".to_string(),
            url: None,
        }],
    };
    let security = vec![SecurityFlag {
        level: "High".to_string(),
        title: "Missing CSP".to_string(),
        description: "No CSP header".to_string(),
        url: Some("https://example.com/".to_string()),
    }];

    // Generate report
    report::write_report(&path, &start, &crawl, &ports, &vuln, &security).unwrap();

    // Validate key sections and content (robust to styling changes)
    let html = std::fs::read_to_string(&path).unwrap();
    assert!(html.contains("Dexteri++ Report"));
    assert!(html.contains("Target:"));
    assert!(html.contains("example.com"));

    // Broken links section (empty)
    assert!(html.contains("No broken links found"));

    // Open ports list with known ports
    assert!(html.contains("<h2>Open ports</h2>"));
    assert!(html.contains("<code>80</code>") || html.contains(">80<"));
    assert!(html.contains("<code>443</code>") || html.contains(">443<"));

    // Vulnerability findings with severity class
    assert!(html.contains("<h2>Vulnerability findings</h2>"));
    assert!(html.contains("sev-High"));

    // Pages table includes our page title or the pages table header
    assert!(html.contains("Example Title") || html.contains("<h2>Pages crawled</h2>"));

    // Marketing section should render for non-empty pages (values may be zero)
    assert!(html.contains("Marketing & Structured Data"));
}
