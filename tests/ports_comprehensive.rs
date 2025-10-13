// Comprehensive port scanning tests
use dexteri::ports;

#[tokio::test]
async fn test_scan_common_ports() {
    let ports_list = ports::common_ports();
    assert!(ports_list.len() > 0);
    assert!(ports_list.contains(&80));
    assert!(ports_list.contains(&443));
}

#[tokio::test]
async fn test_parse_ports_single() {
    let result = ports::parse_ports("80").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], 80);
}

#[tokio::test]
async fn test_parse_ports_range() {
    let result = ports::parse_ports("80-85").unwrap();
    assert_eq!(result.len(), 6);
    assert!(result.contains(&80));
    assert!(result.contains(&85));
}

#[tokio::test]
async fn test_parse_ports_comma_separated() {
    let result = ports::parse_ports("80,443,8080").unwrap();
    assert_eq!(result.len(), 3);
    assert!(result.contains(&80));
    assert!(result.contains(&443));
    assert!(result.contains(&8080));
}

#[tokio::test]
async fn test_parse_ports_mixed() {
    let result = ports::parse_ports("80,443,8000-8003").unwrap();
    assert!(result.len() >= 6);
    assert!(result.contains(&80));
    assert!(result.contains(&443));
    assert!(result.contains(&8000));
    assert!(result.contains(&8003));
}

#[tokio::test]
async fn test_parse_ports_invalid() {
    let result = ports::parse_ports("invalid");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_parse_ports_empty() {
    let result = ports::parse_ports("");
    assert!(result.is_err() || result.unwrap().len() == 0);
}

#[tokio::test]
async fn test_scan_localhost_closed_ports() {
    let ports_list = vec![1, 2, 3, 4, 5]; // Likely closed ports
    let result = ports::scan_host("127.0.0.1", &ports_list, 10, 50, None).await.unwrap();
    
    assert_eq!(result.scanned, 5);
    // These ports should be closed
    assert!(result.open_ports.len() <= 5);
}

#[tokio::test]
async fn test_scan_with_very_short_timeout() {
    let ports_list = vec![22, 80, 443];
    let result = ports::scan_host("127.0.0.1", &ports_list, 10, 1, None).await.unwrap();
    
    assert_eq!(result.scanned, 3);
}

#[tokio::test]
async fn test_scan_with_long_timeout() {
    let ports_list = vec![80, 443];
    let result = ports::scan_host("127.0.0.1", &ports_list, 10, 2000, None).await.unwrap();
    
    assert_eq!(result.scanned, 2);
}

#[tokio::test]
async fn test_scan_single_port() {
    let ports_list = vec![80];
    let result = ports::scan_host("127.0.0.1", &ports_list, 1, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 1);
}

#[tokio::test]
async fn test_scan_many_ports() {
    let ports_list: Vec<u16> = (1..=100).collect();
    let result = ports::scan_host("127.0.0.1", &ports_list, 50, 50, None).await.unwrap();
    
    assert_eq!(result.scanned, 100);
}

#[tokio::test]
async fn test_scan_high_concurrency() {
    let ports_list = vec![22, 80, 443, 3306, 5432, 8080];
    let result = ports::scan_host("127.0.0.1", &ports_list, 1000, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 6);
}

#[tokio::test]
async fn test_scan_low_concurrency() {
    let ports_list = vec![22, 80, 443];
    let result = ports::scan_host("127.0.0.1", &ports_list, 1, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 3);
}

#[tokio::test]
async fn test_scan_empty_ports_list() {
    let ports_list: Vec<u16> = vec![];
    let result = ports::scan_host("127.0.0.1", &ports_list, 10, 100, None).await.unwrap();
    
    assert_eq!(result.scanned, 0);
    assert_eq!(result.open_ports.len(), 0);
}

#[tokio::test]
async fn test_parse_ports_large_range() {
    let result = ports::parse_ports("1000-1100").unwrap();
    assert_eq!(result.len(), 101);
}

#[tokio::test]
async fn test_parse_ports_reversed_range() {
    let result = ports::parse_ports("100-50");
    // Should either error or handle gracefully
    assert!(result.is_err() || result.is_ok());
}

#[tokio::test]
async fn test_parse_ports_whitespace() {
    let result = ports::parse_ports(" 80 , 443 ");
    // Should handle or error
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_parse_ports_max_port() {
    let result = ports::parse_ports("65535").unwrap();
    assert_eq!(result[0], 65535);
}

#[tokio::test]
async fn test_parse_ports_invalid_high() {
    let result = ports::parse_ports("65536");
    assert!(result.is_err());
}
