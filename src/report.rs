use anyhow::Result;
use plotters::prelude::*;
use plotters_svg::SVGBackend;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use url::Url;

use crate::models::{CrawlResult, PortsResult, SecurityFlag, VulnReport};

pub fn write_report(
    path: &Path,
    start: &Url,
    crawl: &CrawlResult,
    ports: &PortsResult,
    vuln: &VulnReport,
    security: &Vec<SecurityFlag>,
) -> Result<()> {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>Dexteri++ Report</title><style>");
    html.push_str("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#111}");
    html.push_str("h1{font-size:1.8rem;margin-bottom:0.25rem} h2{margin-top:2rem} code,pre{background:#f6f8fa;border-radius:6px;padding:2px 6px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:.5rem;text-align:left} tr:nth-child(even){background:#fafafa} .sev-Info{color:#555}.sev-Low{color:#2a7}.sev-Medium{color:#d88400}.sev-High{color:#d33}.sev-Critical{color:#a00;font-weight:bold}");
    html.push_str(".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1rem 0} .card{border:1px solid #ddd;border-radius:8px;padding:1rem;background:#fff}");
    html.push_str("</style></head><body>");

    html.push_str(&format!(
        "<h1>Dexteri++ Report</h1><p>Target: <a href=\"{}\">{}</a></p>",
        start, start
    ));

    html.push_str("<section class=\"summary\">");
    html.push_str(&format!(
        "<div class=\"card\"><b>Pages crawled</b><div style=\"font-size:1.4rem\">{}</div></div>",
        crawl.pages_crawled
    ));
    html.push_str(&format!(
        "<div class=\"card\"><b>Links checked</b><div style=\"font-size:1.4rem\">{}</div></div>",
        crawl.links_checked
    ));
    html.push_str(&format!(
        "<div class=\"card\"><b>Broken links</b><div style=\"font-size:1.4rem\">{}</div></div>",
        crawl.broken_links.len()
    ));
    html.push_str(&format!(
        "<div class=\"card\"><b>Open ports</b><div style=\"font-size:1.4rem\">{}</div></div>",
        ports.open_ports.len()
    ));
    html.push_str(&format!(
        "<div class=\"card\"><b>Vuln findings</b><div style=\"font-size:1.4rem\">{}</div></div>",
        vuln.findings.len()
    ));
    html.push_str("</section>");

    // Marketing / Structured Data Signals (summary)
    let mut json_ld_total = 0usize;
    let mut microdata_total = 0usize;
    let mut og_total = 0usize;
    let mut tw_total = 0usize;
    let mut robots_pages = 0usize;
    let mut canonical_pages = 0usize;
    let mut hreflang_total = 0usize;
    let mut tracker_counts: HashMap<String, usize> = HashMap::new();
    for p in &crawl.pages {
        if let Some(s) = &p.signals {
            json_ld_total += s.json_ld_blocks;
            microdata_total += s.microdata_items;
            og_total += s.open_graph_tags;
            tw_total += s.twitter_tags;
            if s.meta_robots.as_deref().unwrap_or("").len() > 0 {
                robots_pages += 1;
            }
            if s.canonical_url.as_deref().unwrap_or("").len() > 0 {
                canonical_pages += 1;
            }
            hreflang_total += s.hreflang_count;
            for t in &s.trackers {
                *tracker_counts.entry(t.clone()).or_insert(0) += 1;
            }
        }
    }
    if !crawl.pages.is_empty() {
        html.push_str("<h2>Marketing & Structured Data</h2>");
        html.push_str("<div class=\"summary\">");
        html.push_str(&format!("<div class=\"card\"><b>JSON-LD blocks</b><div style=\"font-size:1.4rem\">{}</div></div>", json_ld_total));
        html.push_str(&format!("<div class=\"card\"><b>Microdata items</b><div style=\"font-size:1.4rem\">{}</div></div>", microdata_total));
        html.push_str(&format!("<div class=\"card\"><b>OpenGraph tags</b><div style=\"font-size:1.4rem\">{}</div></div>", og_total));
        html.push_str(&format!(
            "<div class=\"card\"><b>Twitter tags</b><div style=\"font-size:1.4rem\">{}</div></div>",
            tw_total
        ));
        html.push_str(&format!("<div class=\"card\"><b>Pages with robots</b><div style=\"font-size:1.4rem\">{}</div></div>", robots_pages));
        html.push_str(&format!("<div class=\"card\"><b>Pages with canonical</b><div style=\"font-size:1.4rem\">{}</div></div>", canonical_pages));
        html.push_str(&format!("<div class=\"card\"><b>Hreflang links</b><div style=\"font-size:1.4rem\">{}</div></div>", hreflang_total));
        html.push_str("</div>");

        // Charts: marketing summary + top trackers
        let labels = vec![
            "JSON-LD".to_string(),
            "Microdata".to_string(),
            "OpenGraph".to_string(),
            "Twitter".to_string(),
            "Robots".to_string(),
            "Canonical".to_string(),
            "Hreflang".to_string(),
        ];
        let values = vec![
            json_ld_total as i32,
            microdata_total as i32,
            og_total as i32,
            tw_total as i32,
            robots_pages as i32,
            canonical_pages as i32,
            hreflang_total as i32,
        ];
        if let Some(svg) = chart_svg_bar(&labels, &values, "Marketing Signals Totals", 900, 280) {
            html.push_str("<h3>Charts</h3>");
            html.push_str(&svg);
        }

        // Trackers table
        if !tracker_counts.is_empty() {
            let mut trackers: Vec<(String, usize)> = tracker_counts.into_iter().collect();
            trackers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            html.push_str("<h3>Detected Trackers (by pages)</h3>");
            // Top trackers bar chart
            let top_n: Vec<(String, usize)> = trackers.iter().take(10).cloned().collect();
            if !top_n.is_empty() {
                let labels2: Vec<String> = top_n.iter().map(|(k, _)| k.clone()).collect();
                let values2: Vec<i32> = top_n.iter().map(|(_, v)| *v as i32).collect();
                if let Some(svg2) =
                    chart_svg_bar(&labels2, &values2, "Top Trackers (pages)", 900, 280)
                {
                    html.push_str(&svg2);
                }
            }
            html.push_str("<table><thead><tr><th>Tracker</th><th>Pages</th></tr></thead><tbody>");
            for (name, count) in trackers.iter().take(50) {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    html_escape::encode_text(name),
                    count
                ));
            }
            html.push_str("</tbody></table>");
        } else {
            html.push_str("<p>No known tracker libraries detected.</p>");
        }

        // Per-page details (top 50)
        html.push_str("<h3>Per-page Marketing Details (top 50)</h3>");
        html.push_str("<table><thead><tr><th>URL</th><th>Robots</th><th>Canonical</th><th>JSON-LD types</th><th>Microdata types</th><th>OG tags</th><th>Twitter tags</th><th>Hreflang</th><th>Trackers</th></tr></thead><tbody>");
        for p in crawl.pages.iter().take(50) {
            let (robots, canon, jtypes, mtypes, ogc, twc, hreflang, trackers) = match &p.signals {
                Some(s) => (
                    html_escape::encode_text(s.meta_robots.as_deref().unwrap_or("")).into_owned(),
                    html_escape::encode_text(s.canonical_url.as_deref().unwrap_or("")).into_owned(),
                    html_escape::encode_text(&s.json_ld_types.join(", ")).into_owned(),
                    html_escape::encode_text(&s.microdata_types.join(", ")).into_owned(),
                    s.open_graph_tags.to_string(),
                    s.twitter_tags.to_string(),
                    s.hreflang_count.to_string(),
                    html_escape::encode_text(&s.trackers.join(", ")).into_owned(),
                ),
                None => (
                    "".into(),
                    "".into(),
                    "".into(),
                    "".into(),
                    "0".into(),
                    "0".into(),
                    "0".into(),
                    "".into(),
                ),
            };
            html.push_str(&format!(
                "<tr><td class=\"trunc\"><a href=\"{u}\">{u}</a></td><td>{r}</td><td class=\"trunc\">{c}</td><td class=\"trunc\">{jt}</td><td class=\"trunc\">{mt}</td><td>{og}</td><td>{tw}</td><td>{hl}</td><td class=\"trunc\">{tk}</td></tr>",
                u = p.url,
                r = robots,
                c = canon,
                jt = jtypes,
                mt = mtypes,
                og = ogc,
                tw = twc,
                hl = hreflang,
                tk = trackers
            ));
        }
        html.push_str("</tbody></table>");
    }

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
        for p in &ports.open_ports {
            html.push_str(&format!("<li><code>{}</code></li>", p));
        }
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
                f.url
                    .as_ref()
                    .map(|u| format!("<a href=\\\"{}\\\">link</a>", u))
                    .unwrap_or_else(|| "-".into())
            ));
        }
        html.push_str("</tbody></table>");
    }

    // Security posture
    html.push_str("<h2>Security Posture</h2>");
    if security.is_empty() {
        html.push_str("<p>No security posture flags detected.</p>");
    } else {
        html.push_str("<table><thead><tr><th>Level</th><th>Title</th><th>Description</th><th>URL</th></tr></thead><tbody>");
        for f in security {
            html.push_str(&format!(
                "<tr><td class=\"sev-{}\">{}</td><td>{}</td><td class=\"trunc\">{}</td><td>{}</td></tr>",
                html_escape::encode_text(&f.level),
                html_escape::encode_text(&f.level),
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
            p.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            &p.url,
            &p.url,
            html_escape::encode_text(p.title.as_deref().unwrap_or("(untitled)")),
            p.bytes.map(|b| b.to_string()).unwrap_or_else(|| "-".into())
        ));
    }
    html.push_str("</tbody></table>");

    html.push_str("<footer style=\"margin-top:2rem;color:#666\">Generated by Dexteri++</footer>");
    html.push_str("</body></html>");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(html.as_bytes())?;
    Ok(())
}

fn chart_svg_bar(
    labels: &[String],
    values: &[i32],
    title: &str,
    width: u32,
    height: u32,
) -> Option<String> {
    if labels.is_empty() || values.is_empty() || labels.len() != values.len() {
        return None;
    }
    let max_v = values.iter().cloned().max().unwrap_or(0).max(1);
    let mut svg = String::new();
    {
        let root = SVGBackend::with_string(&mut svg, (width, height)).into_drawing_area();
        root.fill(&WHITE).ok()?;
        let x_range = 0..(values.len() as i32);
        let y_range = 0..(max_v + (max_v / 5).max(1));
        let mut chart = ChartBuilder::on(&root)
            .margin(10)
            .caption(title, ("sans-serif", 16))
            .x_label_area_size(40)
            .y_label_area_size(40)
            .build_cartesian_2d(x_range.clone(), y_range.clone())
            .ok()?;
        chart
            .configure_mesh()
            .disable_mesh()
            .x_labels(values.len())
            .y_desc("Count")
            .x_label_formatter(&|v| {
                let i = (*v as usize).min(labels.len().saturating_sub(1));
                if labels.is_empty() {
                    "".to_string()
                } else {
                    labels[i].clone()
                }
            })
            .label_style(("sans-serif", 10))
            .axis_desc_style(("sans-serif", 12))
            .draw()
            .ok()?;

        let bar_color = RGBColor(86, 156, 214).mix(0.9);
        for (i, &v) in values.iter().enumerate() {
            let x0 = i as i32;
            let x1 = x0 + 1;
            let rect = Rectangle::new([(x0, 0), (x1, v)], bar_color.filled());
            chart.draw_series(std::iter::once(rect)).ok()?;
        }
        root.present().ok()?;
        // chart and root drop here before returning svg
    }
    Some(svg)
}
