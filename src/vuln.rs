use anyhow::Result;
use regex::Regex;
use reqwest::header::SET_COOKIE;
use url::Url;

use crate::models::{Finding, VulnReport};

pub async fn scan(client: &reqwest::Client, url: &Url) -> Result<VulnReport> {
    let mut findings: Vec<Finding> = Vec::new();

    let resp = client.get(url.clone()).send().await?;
    let _status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    let is_https = url.scheme() == "https";
    if !is_https {
        findings.push(Finding {
            title: "Site not using HTTPS".into(),
            description: "The target URL is not using HTTPS. Use TLS to protect data in transit."
                .into(),
            severity: "Medium".into(),
            url: Some(url.to_string()),
        });
    }

    // Security headers presence
    let check_header = |name: &str| headers.get(name).is_some();
    if !check_header("Strict-Transport-Security") && is_https {
        findings.push(Finding {
            title: "Missing HSTS".into(),
            description: "Strict-Transport-Security header is missing over HTTPS.".into(),
            severity: "Low".into(),
            url: Some(url.to_string()),
        });
    }
    if !check_header("Content-Security-Policy") {
        findings.push(Finding {
            title: "Missing CSP".into(),
            description: "Content-Security-Policy is not set; this increases XSS risk.".into(),
            severity: "Medium".into(),
            url: Some(url.to_string()),
        });
    }
    if !check_header("X-Frame-Options") {
        findings.push(Finding {
            title: "Missing X-Frame-Options".into(),
            description: "Clickjacking protection missing (X-Frame-Options).".into(),
            severity: "Low".into(),
            url: Some(url.to_string()),
        });
    }
    if !check_header("X-Content-Type-Options") {
        findings.push(Finding {
            title: "Missing X-Content-Type-Options".into(),
            description: "MIME sniffing not disabled (X-Content-Type-Options=nosniff).".into(),
            severity: "Low".into(),
            url: Some(url.to_string()),
        });
    }
    if !check_header("Referrer-Policy") {
        findings.push(Finding {
            title: "Missing Referrer-Policy".into(),
            description: "Referrer-Policy is not set.".into(),
            severity: "Info".into(),
            url: Some(url.to_string()),
        });
    }

    if let Some(server) = headers.get("Server").and_then(|v| v.to_str().ok()) {
        findings.push(Finding {
            title: "Server header leaks software".into(),
            description: format!("Server header present: {}", server),
            severity: "Info".into(),
            url: Some(url.to_string()),
        });
    }

    // Directory listing heuristic
    if body.contains("Index of /") || body.contains("Directory listing for /") {
        findings.push(Finding {
            title: "Possible directory listing".into(),
            description: "Page appears to expose a directory index.".into(),
            severity: "Medium".into(),
            url: Some(url.to_string()),
        });
    }

    // Mixed content on HTTPS pages
    if is_https {
        let re = Regex::new(r"http://[a-zA-Z0-9\-_.:/?#%]+").unwrap();
        if re.is_match(&body) {
            findings.push(Finding {
                title: "Mixed content".into(),
                description: "HTTPS page appears to reference insecure (http://) resources.".into(),
                severity: "Medium".into(),
                url: Some(url.to_string()),
            });
        }
    }

    // Cookies set without Secure on HTTPS
    if is_https {
        for v in headers.get_all(SET_COOKIE).iter() {
            if let Ok(val) = v.to_str() {
                let low = val.to_ascii_lowercase();
                if !low.contains("secure") {
                    findings.push(Finding {
                        title: "Cookie without Secure".into(),
                        description: format!("Set-Cookie missing Secure flag: {}", val),
                        severity: "Low".into(),
                        url: Some(url.to_string()),
                    });
                }
                if !low.contains("httponly") {
                    findings.push(Finding {
                        title: "Cookie without HttpOnly".into(),
                        description: format!("Set-Cookie missing HttpOnly flag: {}", val),
                        severity: "Low".into(),
                        url: Some(url.to_string()),
                    });
                }
            }
        }
    }

    Ok(VulnReport { findings })
}
