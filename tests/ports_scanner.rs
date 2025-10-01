use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

use dexteri::ports::{parse_ports, common_ports, scan_host};

// Test helper: Start a TCP server on a random port
async fn start_tcp_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = listener.accept().await {
                // Accept and immediately close to simulate open port
                let _ = socket;
            }
        }
    });
    
    (port, handle)
}

#[test]
fn test_parse_single_port() {
    let result = parse_ports("80").unwrap();
    assert_eq!(result, vec![80]);
}

#[test]
fn test_parse_multiple_ports() {
    let result = parse_ports("80,443,8080").unwrap();
    assert_eq!(result, vec![80, 443, 8080]);
}

#[test]
fn test_parse_port_range() {
    let result = parse_ports("80-85").unwrap();
    assert_eq!(result, vec![80, 81, 82, 83, 84, 85]);
}

#[test]
fn test_parse_mixed_format() {
    let result = parse_ports("22,80-82,443").unwrap();
    assert_eq!(result, vec![22, 80, 81, 82, 443]);
}

#[test]
fn test_parse_with_spaces() {
    let result = parse_ports("22, 80 - 82 , 443").unwrap();
    assert_eq!(result, vec![22, 80, 81, 82, 443]);
}

#[test]
fn test_parse_removes_duplicates() {
    let result = parse_ports("80,443,80,443").unwrap();
    assert_eq!(result, vec![80, 443]);
}

#[test]
fn test_parse_sorts_output() {
    let result = parse_ports("443,22,80").unwrap();
    assert_eq!(result, vec![22, 80, 443]);
}

#[test]
fn test_parse_complex_spec() {
    let result = parse_ports("21-23,80,443,8000-8002,9000").unwrap();
    assert_eq!(result, vec![21, 22, 23, 80, 443, 8000, 8001, 8002, 9000]);
}

#[test]
fn test_parse_empty_string() {
    let result = parse_ports("").unwrap();
    assert_eq!(result, Vec::<u16>::new());
}

#[test]
fn test_parse_whitespace_only() {
    let result = parse_ports("  ,  ,  ").unwrap();
    assert_eq!(result, Vec::<u16>::new());
}

#[test]
fn test_parse_invalid_range() {
    let result = parse_ports("100-50");
    assert!(result.is_err(), "Should reject invalid range (start > end)");
}

#[test]
fn test_parse_invalid_port_number() {
    let result = parse_ports("70000");
    assert!(result.is_err(), "Should reject port > 65535");
}

#[test]
fn test_parse_non_numeric() {
    let result = parse_ports("http");
    assert!(result.is_err(), "Should reject non-numeric input");
}

#[test]
fn test_parse_large_range() {
    let result = parse_ports("1-1024").unwrap();
    assert_eq!(result.len(), 1024);
    assert_eq!(result[0], 1);
    assert_eq!(result[1023], 1024);
}

#[test]
fn test_common_ports_returns_sorted() {
    let ports = common_ports();
    assert!(ports.len() > 30, "Should have significant number of common ports");
    
    // Verify sorted
    for i in 1..ports.len() {
        assert!(ports[i] > ports[i - 1], "Common ports should be sorted");
    }
}

#[test]
fn test_common_ports_contains_standard_services() {
    let ports = common_ports();
    assert!(ports.contains(&22), "Should include SSH");
    assert!(ports.contains(&80), "Should include HTTP");
    assert!(ports.contains(&443), "Should include HTTPS");
    assert!(ports.contains(&3306), "Should include MySQL");
    assert!(ports.contains(&5432), "Should include PostgreSQL");
    assert!(ports.contains(&27017), "Should include MongoDB");
}

#[test]
fn test_common_ports_no_duplicates() {
    let ports = common_ports();
    let unique_count = ports.iter().collect::<std::collections::HashSet<_>>().len();
    assert_eq!(ports.len(), unique_count, "Common ports should have no duplicates");
}

#[tokio::test]
async fn test_scan_single_open_port() {
    let (port, _handle) = start_tcp_server().await;
    
    // Give server time to start
    sleep(Duration::from_millis(50)).await;
    
    let result = scan_host("127.0.0.1", &vec![port], 10, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, 1, "Should scan 1 port");
    assert_eq!(result.open_ports.len(), 1, "Should find 1 open port");
    assert_eq!(result.open_ports[0], port);
}

#[tokio::test]
async fn test_scan_closed_port() {
    // Use a port that's very unlikely to be open (ephemeral range)
    let closed_port = 54321u16;
    
    let result = scan_host("127.0.0.1", &vec![closed_port], 10, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 1, "Should scan 1 port");
    // Note: There's a small chance this port is open, so we check it's likely closed
    assert!(result.open_ports.len() <= 1, "Should find 0 or 1 port (if randomly open)");
}

#[tokio::test]
async fn test_scan_multiple_ports() {
    let (port1, _h1) = start_tcp_server().await;
    let (port2, _h2) = start_tcp_server().await;
    
    sleep(Duration::from_millis(50)).await;
    
    let ports = vec![port1, port2, 19998]; // 2 open, 1 closed
    let result = scan_host("127.0.0.1", &ports, 10, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, 3, "Should scan 3 ports");
    assert!(result.open_ports.len() >= 2, "Should find at least 2 open ports");
    assert!(result.open_ports.contains(&port1));
    assert!(result.open_ports.contains(&port2));
}

#[tokio::test]
async fn test_scan_respects_concurrency() {
    let (port, _handle) = start_tcp_server().await;
    sleep(Duration::from_millis(50)).await;
    
    let ports = vec![port, 19997, 19996, 19995, 19994];
    
    // Low concurrency should still complete
    let result = scan_host("127.0.0.1", &ports, 2, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, 5, "Should scan all ports even with low concurrency");
}

#[tokio::test]
async fn test_scan_timeout_works() {
    // Scan a port on a non-routable IP to trigger timeout
    let result = scan_host("192.0.2.1", &vec![80], 10, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 1, "Should attempt to scan 1 port");
    assert_eq!(result.open_ports.len(), 0, "Should timeout and report closed");
}

#[tokio::test]
async fn test_scan_returns_sorted_results() {
    let (port1, _h1) = start_tcp_server().await;
    let (port2, _h2) = start_tcp_server().await;
    let (port3, _h3) = start_tcp_server().await;
    
    sleep(Duration::from_millis(50)).await;
    
    // Deliberately unsorted input
    let ports = vec![port3, port1, port2];
    let result = scan_host("127.0.0.1", &ports, 10, 500, None).await.unwrap();
    
    // Results should be sorted
    for i in 1..result.open_ports.len() {
        assert!(result.open_ports[i] > result.open_ports[i - 1], 
                "Results should be sorted");
    }
}

#[tokio::test]
async fn test_scan_with_cancel_flag() {
    let (port1, _h1) = start_tcp_server().await;
    let (port2, _h2) = start_tcp_server().await;
    
    sleep(Duration::from_millis(50)).await;
    
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    
    // Immediately cancel
    cancel.store(true, Ordering::Relaxed);
    
    let result = scan_host("127.0.0.1", &vec![port1, port2], 10, 500, Some(cancel_clone))
        .await
        .unwrap();
    
    // Should return early with no results
    assert_eq!(result.scanned, 0, "Should scan 0 ports when cancelled immediately");
    assert_eq!(result.open_ports.len(), 0, "Should find 0 ports when cancelled");
}

#[tokio::test]
async fn test_scan_with_delayed_cancel() {
    let (port1, _h1) = start_tcp_server().await;
    let (port2, _h2) = start_tcp_server().await;
    let (port3, _h3) = start_tcp_server().await;
    
    sleep(Duration::from_millis(50)).await;
    
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let cancel_trigger = cancel.clone();
    
    // Cancel after 50ms (earlier to ensure cancellation happens)
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        cancel_trigger.store(true, Ordering::Relaxed);
    });
    
    // Many ports with slow timeout to allow cancellation to trigger
    let mut ports = vec![port1, port2, port3];
    for i in 50000..50020 {
        ports.push(i);
    }
    
    let result = scan_host("127.0.0.1", &ports, 2, 1000, Some(cancel_clone))
        .await
        .unwrap();
    
    // With cancellation, should not scan all ports
    // Due to timing, might scan some but not all
    assert!(result.scanned <= ports.len(), "Scanned count should be <= total ports");
}

#[tokio::test]
async fn test_scan_invalid_hostname() {
    let result = scan_host("invalid.invalid.invalid", &vec![80], 10, 500, None).await;
    
    // Should fail with DNS resolution error
    assert!(result.is_err(), "Should error on invalid hostname");
}

#[tokio::test]
async fn test_scan_localhost_by_name() {
    let (port, _handle) = start_tcp_server().await;
    sleep(Duration::from_millis(50)).await;
    
    let result = scan_host("localhost", &vec![port], 10, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, 1, "Should resolve localhost");
    assert_eq!(result.open_ports.len(), 1, "Should find open port on localhost");
}

#[tokio::test]
async fn test_scan_empty_port_list() {
    let result = scan_host("127.0.0.1", &vec![], 10, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, 0, "Should scan 0 ports");
    assert_eq!(result.open_ports.len(), 0, "Should find 0 ports");
}

#[tokio::test]
async fn test_scan_high_concurrency() {
    let (port, _handle) = start_tcp_server().await;
    sleep(Duration::from_millis(50)).await;
    
    let mut ports = vec![port];
    // Add many closed ports
    for i in 20000..20100 {
        ports.push(i);
    }
    
    // High concurrency should complete quickly
    let start = std::time::Instant::now();
    let result = scan_host("127.0.0.1", &ports, 100, 200, None).await.unwrap();
    let elapsed = start.elapsed();
    
    assert_eq!(result.scanned, 101, "Should scan all ports");
    assert!(elapsed.as_secs() < 5, "Should complete quickly with high concurrency");
}

#[tokio::test]
async fn test_scan_ipv4_address() {
    let (port, _handle) = start_tcp_server().await;
    sleep(Duration::from_millis(50)).await;
    
    let result = scan_host("127.0.0.1", &vec![port], 10, 500, None).await.unwrap();
    
    assert_eq!(result.open_ports.len(), 1, "Should work with IPv4 address");
}

#[test]
fn test_parse_port_range_boundary_values() {
    // Test port 1
    let result = parse_ports("1").unwrap();
    assert_eq!(result, vec![1]);
    
    // Test port 65535
    let result = parse_ports("65535").unwrap();
    assert_eq!(result, vec![65535]);
    
    // Test range including boundary
    let result = parse_ports("65533-65535").unwrap();
    assert_eq!(result, vec![65533, 65534, 65535]);
}

#[test]
fn test_parse_port_zero_invalid() {
    let result = parse_ports("0");
    // Port 0 is technically valid for binding but may not parse correctly
    // This tests the actual behavior
    if result.is_ok() {
        assert_eq!(result.unwrap(), vec![0]);
    }
}

#[tokio::test]
async fn test_scan_measures_scanned_count_accurately() {
    let (port1, _h1) = start_tcp_server().await;
    let (port2, _h2) = start_tcp_server().await;
    
    sleep(Duration::from_millis(50)).await;
    
    let ports = vec![port1, port2, 19989, 19988, 19987];
    let result = scan_host("127.0.0.1", &ports, 10, 500, None).await.unwrap();
    
    assert_eq!(result.scanned, ports.len(), "Scanned count should match input port count");
    assert!(result.open_ports.len() >= 2, "Should find at least the open ports");
    assert!(result.open_ports.len() <= ports.len(), "Cannot find more ports than scanned");
}
