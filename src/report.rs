use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::Path;
use url::Url;

use crate::models::{CrawlResult, PortsResult, VulnReport};

pub fn write_report(path: &Path, start: &Url, crawl: &CrawlResult, ports: &PortsResult, vuln: &VulnReport) -> Result<()> {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>Dexteri++ Report</title><style>");
    html.push_str("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#111}");
    html.push_str("h1{font-size:1.8rem;margin-bottom:0.25rem} h2{margin-top:2rem} code,pre{background:#f6f8fa;border-radius:6px;padding:2px 6px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:.5rem;text-align:left} tr:nth-child(even){background:#fafafa} .sev-Info{color:#555}.sev-Low{color:#2a7}.sev-Medium{color:#d88400}.sev-High{color:#d33}.sev-Critical{color:#a00;font-weight:bold}");
    html.push_str(".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1rem 0} .card{border:1px solid #ddd;border-radius:8px;padding:1rem;background:#fff}");
    html.push_str("</style></head><body>");

    html.push_str(&format!("<h1>Dexteri++ Report</h1><p>Target: <a href=\"{}\">{}</a></p>", start, start));

    html.push_str("<section class=\"summary\">");
    html.push_str(&format!("<div class=\"card\"><b>Pages crawled</b><div style=\"font-size:1.4rem\">{}</div></div>", crawl.pages_crawled));
    html.push_str(&format!("<div class=\"card\"><b>Links checked</b><div style=\"font-size:1.4rem\">{}</div></div>", crawl.links_checked));
    html.push_str(&format!("<div class=\"card\"><b>Broken links</b><div style=\"font-size:1.4rem\">{}</div></div>", crawl.broken_links.len()));
    html.push_str(&format!("<div class=\"card\"><b>Open ports</b><div style=\"font-size:1.4rem\">{}</div></div>", ports.open_ports.len()));
    html.push_str(&format!("<div class=\"card\"><b>Vuln findings</b><div style=\"font-size:1.4rem\">{}</div></div>", vuln.findings.len()));
    html.push_str("</section>");

    // Broken links
    html.push_str("<h2>Broken links</h2>");
    if crawl.broken_links.is_empty() {
        html.push_str("<p>No broken links found. 🎉</p>");
    } else {
        html.push_str("<table><thead><tr><th>Status</th><th>URL</th><th>Parent</th><th>External</th><th>Reason</th></tr></thead><tbody>");
        for e in &crawl.broken_links {
            html.push_str(&format!(
                "<tr><td>{}</td><td><a href=\"{}\">{}</a></td><td><a href=\"{}\">{}</a></td><td>{}</td><td><code>{}</code></td></tr>",
                e.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                &e.url,
                &e.url,
                &e.parent,
                &e.parent,
                if e.external { "yes" } else { "no" },
                html_escape::encode_text(&e.reason)
            ));
        }
        html.push_str("</tbody></table>");
    }

    // Ports
    html.push_str("<h2>Open ports</h2>");
    if ports.open_ports.is_empty() {
        html.push_str("<p>No open ports detected from the scanned set.</p>");
    } else {
        html.push_str("<p>Open (subset scanned):</p><ul>");
        for p in &ports.open_ports { html.push_str(&format!("<li><code>{}</code></li>", p)); }
        html.push_str("</ul>");
    }

    // Vulns
    html.push_str("<h2>Vulnerability findings</h2>");
    if vuln.findings.is_empty() {
        html.push_str("<p>No obvious security misconfigurations detected by basic checks.</p>");
    } else {
        html.push_str("<table><thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>URL</th></tr></thead><tbody>");
        for f in &vuln.findings {
            html.push_str(&format!(
                "<tr><td class=\"sev-{}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.severity,
                f.severity,
                html_escape::encode_text(&f.title),
                html_escape::encode_text(&f.description),
                f.url.as_ref().map(|u| format!("<a href=\\\"{}\\\">link</a>", u)).unwrap_or_else(|| "-".into())
            ));
        }
        html.push_str("</tbody></table>");
    }

    // Pages table (top 50)
    html.push_str("<h2>Pages crawled</h2>");
    html.push_str("<table><thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Bytes</th></tr></thead><tbody>");
    for p in crawl.pages.iter().take(50) {
        html.push_str(&format!(
            "<tr><td>{}</td><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td></tr>",
            p.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            &p.url,
            &p.url,
            html_escape::encode_text(p.title.as_deref().unwrap_or("(untitled)")),
            p.bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".into())
        ));
    }
    html.push_str("</tbody></table>");

    html.push_str("<footer style=\"margin-top:2rem;color:#666\">Generated by Dexteri++</footer>");
    html.push_str("</body></html>");

    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let mut f = fs::File::create(path)?;
    f.write_all(html.as_bytes())?;
    Ok(())
}
