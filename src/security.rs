use anyhow::Result;
use regex::Regex;
use reqwest::header::SERVER;
use scraper::{Html, Selector};
use std::time::Duration;
use url::Url;

use crate::models::SecurityFlag;

pub async fn check_security_posture(
    client: &reqwest::Client,
    base: &Url,
) -> Result<Vec<SecurityFlag>> {
    let mut flags: Vec<SecurityFlag> = Vec::new();

    // 1) Fetch main page (GET)
    let resp = match client.get(base.clone()).send().await {
        Ok(r) => r,
        Err(e) => {
            flags.push(SecurityFlag {
                level: "Info".into(),
                title: "Fetch failed".into(),
                description: format!("Failed to fetch {}: {}", base, e),
                url: Some(base.to_string()),
            });
            return Ok(flags);
        }
    };
    let _status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap_or_default();

    // 2) Parse HTML (keep Html/Selector scoped, non-Send types must not live across awaits)
    let gen_vals: Vec<String> = {
        let doc = Html::parse_document(&text);
        let sel_meta_gen = Selector::parse("meta[name=generator]").unwrap();
        doc.select(&sel_meta_gen)
            .filter_map(|m| m.value().attr("content").map(|s| s.to_string()))
            .collect()
    };

    let lc = text.to_lowercase();

    // Helper: add flag
    let mut add = |lvl: &str, title: &str, desc: String, url: Option<String>| {
        flags.push(SecurityFlag {
            level: lvl.into(),
            title: title.into(),
            description: desc,
            url,
        });
    };

    // 3) Security headers presence (Medium if missing)
    let is_https = base.scheme() == "https";
    let get_hdr = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let hsts = get_hdr("strict-transport-security");
    if is_https && hsts.is_empty() {
        add(
            "Medium",
            "Missing HSTS",
            "Strict-Transport-Security header is not present".into(),
            None,
        );
    }
    if get_hdr("content-security-policy").is_empty() {
        add(
            "Medium",
            "Missing CSP",
            "Content-Security-Policy header is not present".into(),
            None,
        );
    }
    if get_hdr("x-frame-options").is_empty() {
        add(
            "Medium",
            "Missing X-Frame-Options",
            "Clickjacking protection header is not present".into(),
            None,
        );
    }
    if get_hdr("x-content-type-options").to_ascii_lowercase() != "nosniff" {
        add(
            "Medium",
            "Missing X-Content-Type-Options",
            "X-Content-Type-Options is not 'nosniff'".into(),
            None,
        );
    }
    if get_hdr("referrer-policy").is_empty() {
        add(
            "Medium",
            "Missing Referrer-Policy",
            "Referrer-Policy header is not present".into(),
            None,
        );
    }

    // 4) Server exposure via headers
    if let Some(sv) = headers.get(SERVER).and_then(|v| v.to_str().ok()) {
        if sv.trim().len() > 0 {
            // With version -> Medium, otherwise Low
            let has_ver = sv.chars().any(|c| c.is_ascii_digit());
            if has_ver {
                add(
                    "Medium",
                    "Server header exposes version",
                    format!("Server: {}", sv),
                    None,
                );
            } else {
                add(
                    "Low",
                    "Server header exposes software",
                    format!("Server: {}", sv),
                    None,
                );
            }
        }
    }
    if let Some(xpb) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        if xpb.trim().len() > 0 {
            let has_ver = xpb.chars().any(|c| c.is_ascii_digit());
            if has_ver {
                add(
                    "Medium",
                    "X-Powered-By exposes version",
                    format!("X-Powered-By: {}", xpb),
                    None,
                );
            } else {
                add(
                    "Low",
                    "X-Powered-By exposes technology",
                    format!("X-Powered-By: {}", xpb),
                    None,
                );
            }
        }
    }

    // 5) CMS detection via meta generator / html markers / headers / cookies
    // gen_vals computed above
    let mut detected_cms: Option<(String, Option<String>)> = None; // (name, version)
    let ver_re = Regex::new(r"(?i)(\d+\.[\d\.]+)").unwrap();

    let mut consider_gen = |val: &str| {
        let v = val.to_lowercase();
        let mut set = |name: &str| {
            let ver = ver_re
                .captures(val)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());
            detected_cms = Some((name.to_string(), ver));
        };
        if v.contains("wordpress") {
            set("WordPress");
        } else if v.contains("joomla") {
            set("Joomla");
        } else if v.contains("drupal") {
            set("Drupal");
        } else if v.contains("magento") {
            set("Magento");
        } else if v.contains("shopify") {
            set("Shopify");
        } else if v.contains("typo3") {
            set("TYPO3");
        } else if v.contains("prestashop") {
            set("PrestaShop");
        } else if v.contains("opencart") {
            set("OpenCart");
        } else if v.contains("ghost") {
            set("Ghost");
        } else if v.contains("wix") {
            set("Wix");
        } else if v.contains("squarespace") {
            set("Squarespace");
        } else if v.contains("contentful") {
            set("Contentful");
        } else if v.contains("hubspot") {
            set("HubSpot CMS");
        } else if v.contains("adobe experience manager") || v.contains("aem") {
            set("Adobe Experience Manager");
        } else if v.contains("sitecore") {
            set("Sitecore");
        } else if v.contains("silverstripe") {
            set("SilverStripe");
        } else if v.contains("concrete") {
            set("Concrete CMS");
        } else if v.contains("modx") {
            set("MODX");
        } else if v.contains("pimcore") {
            set("Pimcore");
        } else if v.contains("bloomreach") {
            set("Bloomreach");
        }
    };
    for g in &gen_vals {
        consider_gen(g);
    }

    // HTML/content heuristics
    if detected_cms.is_none() {
        if lc.contains("wp-content/") || lc.contains("wp-includes/") {
            detected_cms = Some(("WordPress".into(), None));
        }
        if lc.contains("static.squarespace.com") {
            detected_cms = Some(("Squarespace".into(), None));
        }
        if lc.contains("cdn.shopify.com") || headers.contains_key("x-shopify-stage") {
            detected_cms = Some(("Shopify".into(), None));
        }
        if lc.contains("wix.com") || headers.contains_key("x-wix-request-id") {
            detected_cms = Some(("Wix".into(), None));
        }
        if lc.contains("Drupal.settings") || lc.contains("drupal.js") {
            detected_cms = Some(("Drupal".into(), None));
        }
        if lc.contains("requirejs-config.js") && lc.contains("mage") {
            detected_cms = Some(("Magento".into(), None));
        }
        if lc.contains("typo3/") {
            detected_cms = Some(("TYPO3".into(), None));
        }
        if lc.contains("ghost-sdk") || lc.contains("ghost") {
            detected_cms = Some(("Ghost".into(), None));
        }
    }

    if let Some((name, ver)) = &detected_cms {
        add(
            "Info",
            &format!("CMS detected: {}", name),
            ver.clone()
                .map(|v| format!("Version: {}", v))
                .unwrap_or_else(|| "".into()),
            None,
        );
        // Version exposure / outdated
        if let Some(v) = ver {
            add(
                "Medium",
                &format!("{} version exposed", name),
                format!("Version {} visible in generator/meta", v),
                None,
            );
            let outdated = match name.as_str() {
                "WordPress" => is_version_less(v, "6.0"),
                "Magento" => is_version_less(v, "2.4"),
                _ => false,
            };
            if outdated {
                add(
                    "High",
                    &format!("Outdated {} version", name),
                    format!(
                        "{} < {}; known exploits likely",
                        v,
                        if name == "WordPress" { "6.0" } else { "2.4" }
                    ),
                    None,
                );
            }
        }
    }

    // 6) Frontend framework hints (Low)
    let mut fw: Vec<&str> = Vec::new();
    if lc.contains("react") {
        fw.push("React");
    }
    if lc.contains("vue") || lc.contains("v-bind") {
        fw.push("Vue");
    }
    if lc.contains("angular") || lc.contains("ng-app") {
        fw.push("Angular");
    }
    if lc.contains("vite") {
        fw.push("Vite");
    }
    if lc.contains("next") {
        fw.push("Next.js");
    }
    if lc.contains("svelte") {
        fw.push("Svelte");
    }
    if !fw.is_empty() {
        add("Low", "Frontend framework detected", fw.join(", "), None);
    }

    // 7) CMS-specific and sensitive paths (HEAD first, fallback to GET range)
    let mut paths: Vec<(&str, &str, &str)> = vec![
        // path, level, title
        ("/.git/", "Critical", ".git directory exposed"),
        ("/.env", "Critical", ".env file exposed"),
        ("/phpinfo.php", "High", "phpinfo exposed"),
        ("/config.php", "High", "config.php exposed"),
        ("/backup.zip", "High", "Backup archive exposed"),
        ("/node_modules/", "Medium", "node_modules directory exposed"),
        ("/server-status", "High", "Apache server-status exposed"),
        ("/status", "Medium", "Server status endpoint exposed"),
        // CMS/admin areas
        ("/administrator/", "High", "Joomla admin exposed"),
        ("/admin/", "High", "Admin area exposed"),
        ("/adminhtml/", "High", "Magento admin exposed"),
        ("/typo3/", "High", "TYPO3 backend exposed"),
        ("/ghost/", "High", "Ghost admin exposed"),
        ("/CHANGELOG.txt", "Medium", "Drupal changelog exposed"),
        ("/xmlrpc.php", "Medium", "WordPress XML-RPC enabled"),
        ("/wp-login.php", "Low", "WordPress login present"),
    ];

    let mut checked = 0usize;
    for (p, level, title) in paths.drain(..) {
        if checked >= 10 {
            break;
        }
        if let Some(u) = base.join(p).ok() {
            if let Some((st, body_snip)) = head_or_get_snippet(client, &u).await {
                let good = st.is_success() || st.as_u16() == 401 || st.as_u16() == 403;
                if good {
                    // Avoid false positives on custom 404 pages by checking for obvious "not found"
                    let body_lc = body_snip.to_lowercase();
                    let looks_404 = body_lc.contains("not found") && !st.is_success();
                    if !looks_404 {
                        add(
                            level,
                            title,
                            format!("{} returned status {}", u, st.as_u16()),
                            Some(u.to_string()),
                        );
                        checked += 1;
                    }
                }
            }
        }
    }

    Ok(flags)
}

async fn head_or_get_snippet(
    client: &reqwest::Client,
    url: &Url,
) -> Option<(reqwest::StatusCode, String)> {
    // Try HEAD
    match client
        .head(url.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => {
            let st = r.status();
            return Some((st, String::new()));
        }
        Err(_) => {}
    }
    // Fallback to GET with range
    match client
        .get(url.clone())
        .header(reqwest::header::RANGE, "bytes=0-1023")
        .timeout(Duration::from_secs(15))
        .send()
        .await
    {
        Ok(r) => {
            let st = r.status();
            let body = r.text().await.unwrap_or_default();
            Some((st, body))
        }
        Err(_) => None,
    }
}

fn is_version_less(a: &str, b: &str) -> bool {
    // Compare a < b using dot-separated integers
    let pa: Vec<u64> = a.split('.').filter_map(|x| x.parse::<u64>().ok()).collect();
    let pb: Vec<u64> = b.split('.').filter_map(|x| x.parse::<u64>().ok()).collect();
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let xa = *pa.get(i).unwrap_or(&0);
        let xb = *pb.get(i).unwrap_or(&0);
        if xa < xb {
            return true;
        }
        if xa > xb {
            return false;
        }
    }
    false
}
