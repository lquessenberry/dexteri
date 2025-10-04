use tempfile::TempDir;
use dexteri::indexer::{index_pages, search_index};
use dexteri::models::Page;

fn create_sample_page(url: &str, title: &str, text: &str) -> Page {
    Page {
        url: url.to_string(),
        status: Some(200),
        title: Some(title.to_string()),
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(1024),
        text: Some(text.to_string()),
        signals: None,
    }
}

#[tokio::test]
async fn test_index_empty_pages() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages: Vec<Page> = vec![];
    let result = index_pages(&index_path, &pages).await;
    
    assert!(result.is_ok());
    let stats = result.unwrap();
    assert_eq!(stats.docs_indexed, 0, "Should index 0 pages");
}

#[tokio::test]
async fn test_index_single_page() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![create_sample_page(
        "https://example.com",
        "Example Page",
        "This is example content for indexing"
    )];
    
    let result = index_pages(&index_path, &pages).await;
    assert!(result.is_ok());
    
    let stats = result.unwrap();
    assert_eq!(stats.docs_indexed, 1, "Should index 1 page");
}

#[tokio::test]
async fn test_index_multiple_pages() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com/page1", "Page One", "Content for page one"),
        create_sample_page("https://example.com/page2", "Page Two", "Content for page two"),
    ];
    
    let result = index_pages(&index_path, &pages).await;
    assert!(result.is_ok());
    
    let stats = result.unwrap();
    assert_eq!(stats.docs_indexed, 2, "Should index 2 pages");
}

#[tokio::test]
async fn test_search_empty_index() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages: Vec<Page> = vec![];
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "test", 10);
    assert!(results.is_ok());
    
    let hits = results.unwrap();
    assert_eq!(hits.len(), 0, "Empty index should return no results");
}

#[tokio::test]
async fn test_search_finds_content() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com/rust", "Rust Programming", "Rust is a systems programming language"),
        create_sample_page("https://example.com/python", "Python Programming", "Python is a high-level language"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "rust", 10).unwrap();
    assert!(results.len() > 0, "Should find results for 'rust'");
    assert!(results[0].url.contains("rust") || 
            results[0].title.as_ref().map(|t| t.contains("Rust")).unwrap_or(false), 
            "Result should contain 'rust'");
}

#[tokio::test]
async fn test_search_respects_limit() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages: Vec<Page> = (0..10)
        .map(|i| create_sample_page(
            &format!("https://example.com/page{}", i),
            &format!("Page {}", i),
            "common search term appears here"
        ))
        .collect();
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "common", 3).unwrap();
    assert!(results.len() <= 3, "Should respect search limit of 3");
}

#[tokio::test]
async fn test_search_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![create_sample_page("https://example.com", "Example", "UPPERCASE content here")];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "uppercase", 10).unwrap();
    assert!(results.len() > 0, "Search should be case-insensitive");
}

#[tokio::test]
async fn test_search_nonexistent_term() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![create_sample_page("https://example.com", "Example", "Some content")];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "nonexistentxyz123", 10).unwrap();
    assert_eq!(results.len(), 0, "Should return no results for non-existent term");
}

#[tokio::test]
async fn test_index_pages_without_text() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        Page {
            url: "https://example.com".to_string(),
            status: Some(200),
            title: Some("No Text".to_string()),
            links: vec![],
            content_type: Some("text/html".to_string()),
            bytes: Some(1024),
            text: None,
            signals: None,
        },
    ];
    
    let result = index_pages(&index_path, &pages).await;
    assert!(result.is_ok(), "Should handle pages without text");
    
    let stats = result.unwrap();
    // Pages without text are not indexed
    assert_eq!(stats.docs_indexed, 0, "Should not index pages without text");
}

#[tokio::test]
async fn test_reindex_existing_directory() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    // Create initial index
    let pages1 = vec![create_sample_page("https://example.com/1", "First", "First content")];
    index_pages(&index_path, &pages1).await.unwrap();
    
    // Reindex - should remove old directory and create new
    let pages2 = vec![create_sample_page("https://example.com/2", "Second", "Second content")];
    let result = index_pages(&index_path, &pages2).await;
    
    assert!(result.is_ok(), "Should handle reindexing existing directory");
    let stats = result.unwrap();
    assert_eq!(stats.docs_indexed, 1, "Should index new pages after cleanup");
    
    // Search should only find new content
    let results = search_index(&index_path, "Second", 10).unwrap();
    assert!(results.len() > 0, "Should find new content");
    
    let results_old = search_index(&index_path, "First", 10).unwrap();
    assert_eq!(results_old.len(), 0, "Should not find old content after reindex");
}

#[tokio::test]
async fn test_search_with_no_title() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    // Create page without title
    let pages = vec![Page {
        url: "https://example.com".to_string(),
        status: Some(200),
        title: None,
        links: vec![],
        content_type: Some("text/html".to_string()),
        bytes: Some(1024),
        text: Some("Content with searchable text".to_string()),
        signals: None,
    }];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "searchable", 10).unwrap();
    assert!(results.len() > 0, "Should find results even without title");
    // Title will be empty string since unwrap_or_default() is used
    assert!(results[0].title.as_ref().map(|t| t.is_empty()).unwrap_or(true), 
            "Title should be empty or None");
    assert!(!results[0].url.is_empty(), "URL should still be present");
}

#[tokio::test]
async fn test_search_with_special_characters() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com", "Special & <Chars>", "Content with special chars: @#$%^&*()"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    // Should handle query with special chars
    let results = search_index(&index_path, "special", 10);
    assert!(results.is_ok(), "Should handle queries with special characters");
}

#[tokio::test]
async fn test_search_with_quotes() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com", "Quoted \"Text\"", "Some content with quotes"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "quoted", 10).unwrap();
    assert!(results.len() > 0, "Should find results with quoted text");
}

#[tokio::test]
async fn test_index_very_long_text() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    // Create very long text content
    let long_text = "word ".repeat(10000); // 50KB+ of text
    let pages = vec![create_sample_page("https://example.com", "Long Content", &long_text)];
    
    let result = index_pages(&index_path, &pages).await;
    assert!(result.is_ok(), "Should handle very long text content");
    
    let stats = result.unwrap();
    assert_eq!(stats.docs_indexed, 1, "Should index page with long content");
}

#[tokio::test]
async fn test_search_numeric_content() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com", "Numbers", "Product ID 12345 and reference 67890"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "12345", 10).unwrap();
    assert!(results.len() > 0, "Should find numeric content");
}

#[tokio::test]
async fn test_search_unicode_content() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com", "Unicode 你好", "Content with émojis 😀 and Ñoño"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    let results = search_index(&index_path, "unicode", 10).unwrap();
    assert!(results.len() > 0, "Should handle unicode content");
}

#[tokio::test]
async fn test_search_boolean_query() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com/1", "Rust and Python", "Both Rust and Python are great"),
        create_sample_page("https://example.com/2", "Only Rust", "Rust is amazing"),
    ];
    
    index_pages(&index_path, &pages).await.unwrap();
    
    // Test simple AND query
    let results = search_index(&index_path, "rust", 10).unwrap();
    assert!(results.len() >= 1, "Should find Rust pages");
}

#[tokio::test]
async fn test_index_mixed_content() {
    let temp_dir = TempDir::new().unwrap();
    let index_path = temp_dir.path().to_path_buf();
    
    let pages = vec![
        create_sample_page("https://example.com/1", "Page One", "Content one"),
        Page {
            url: "https://example.com/2".to_string(),
            status: Some(404),
            title: Some("Not Found".to_string()),
            links: vec![],
            content_type: None,
            bytes: Some(0),
            text: None, // No text - won't be indexed
            signals: None,
        },
        create_sample_page("https://example.com/3", "Page Three", "Content three"),
    ];
    
    let result = index_pages(&index_path, &pages).await.unwrap();
    // Only pages with text should be indexed
    assert_eq!(result.docs_indexed, 2, "Should only index pages with text");
}

#[test]
fn test_search_nonexistent_index() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_path = temp_dir.path().join("nonexistent");
    
    let result = search_index(&nonexistent_path, "test", 10);
    assert!(result.is_err(), "Should error when searching non-existent index");
}
