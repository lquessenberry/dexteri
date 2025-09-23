use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::ToSocketAddrs;
use tokio::{net::TcpStream, time::{timeout, Duration}};

use crate::models::PortsResult;

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let p = part.trim();
        if p.is_empty() { continue; }
        if let Some((a, b)) = p.split_once('-') {
            let start: u16 = a.trim().parse()?;
            let end: u16 = b.trim().parse()?;
            if start > end { return Err(anyhow!("invalid range {}", p)); }
            out.extend(start..=end);
        } else {
            out.push(p.parse()?);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub fn common_ports() -> Vec<u16> {
    let mut v = vec![
        21,22,23,25,53,80,110,123,139,143,443,445,465,587,631,636,993,995,
        1433,1521,2049,2375,2376,27017,3000,3306,3389,5432,5672,5900,5984,
        6379,8000,8080,8443,9000,9200,9418,11211,
    ];
    v.sort_unstable();
    v
}

pub async fn scan_host(host: &str, ports: &Vec<u16>, concurrency: usize, timeout_ms: u64) -> Result<PortsResult> {
    let t = Duration::from_millis(timeout_ms);
    let mut futs = FuturesUnordered::new();

    // Resolve host once to avoid repeated DNS lookups
    let addrs: Vec<std::net::SocketAddr> = format!("{}:{}", host, 0)
        .to_socket_addrs()?
        .map(|a| a)
        .collect();

    for &port in ports.iter() {
        let addrs = addrs.clone();
        futs.push(async move {
            // try all resolved addresses with port
            let mut ok = false;
            for mut addr in addrs.clone() {
                addr.set_port(port);
                if timeout(t, TcpStream::connect(addr)).await.is_ok() {
                    ok = true;
                    break;
                }
            }
            if ok { Some(port) } else { None }
        });
        // Throttle concurrency by awaiting every batch of size
        if futs.len() >= concurrency { let _ = futs.next().await; }
    }

    let mut open: Vec<u16> = Vec::new();
    while let Some(res) = futs.next().await { if let Some(p) = res { open.push(p); } }
    open.sort_unstable();

    Ok(PortsResult { open_ports: open, scanned: ports.len() })
}
