use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkError {
    pub url: String,
    pub status: Option<u16>,
    pub reason: String,
    pub parent: String,
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub url: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub links: Vec<String>,
    pub content_type: Option<String>,
    pub bytes: Option<usize>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    pub pages_crawled: usize,
    pub links_checked: usize,
    pub broken_links: Vec<LinkError>,
    pub pages: Vec<Page>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsResult {
    pub open_ports: Vec<u16>,
    pub scanned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnReport {
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub url: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub docs_indexed: usize,
}
