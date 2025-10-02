use dexteri::security::check_security_posture;
use mockito::ServerGuard;
use url::Url;

// Helper to create a mock server with HTML content
async fn setup_mock_with_content(html: &str, headers: Vec<(&str, &str)>) -> (ServerGuard, Url) {
    let mut server = mockito::Server::new_async().await;
    let mut mock = server.mock("GET", "/");
    
    for (key, value) in headers {
        mock = mock.with_header(key, value);
    }
    
    let _m = mock
        .with_status(200)
        .with_body(html)
        .create_async()
        .await;
    
    let url = Url::parse(&server.url()).unwrap();
    (server, url)
}

#[tokio::test]
async fn test_security_detects_wordpress_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="WordPress 6.0">
        </head>
        <body>Test content</body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("WordPress"));
    assert!(cms_detected, "Should detect WordPress via generator tag");
}

#[tokio::test]
async fn test_security_detects_wordpress_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <link rel="stylesheet" href="/wp-content/themes/default/style.css">
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("WordPress"));
    assert!(cms_detected, "Should detect WordPress via content pattern");
}

#[tokio::test]
async fn test_security_detects_drupal_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="Drupal 9">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Drupal"));
    assert!(cms_detected, "Should detect Drupal via generator tag");
}

#[tokio::test]
async fn test_security_detects_drupal_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/misc/drupal.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Drupal"));
    assert!(cms_detected, "Should detect Drupal via content pattern");
}

#[tokio::test]
async fn test_security_detects_shopify_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="//cdn.shopify.com/s/files/theme.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Shopify"));
    assert!(cms_detected, "Should detect Shopify via content");
}

#[tokio::test]
async fn test_security_detects_wix_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="//static.wix.com/app.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Wix"));
    assert!(cms_detected, "Should detect Wix via content");
}

#[tokio::test]
async fn test_security_detects_squarespace_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="//static.squarespace.com/static/core.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Squarespace"));
    assert!(cms_detected, "Should detect Squarespace via content");
}

#[tokio::test]
async fn test_security_detects_magento_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/requirejs-config.js"></script>
            <div class="mage-dropdown-dialog"></div>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Magento"));
    assert!(cms_detected, "Should detect Magento via content");
}

#[tokio::test]
async fn test_security_detects_typo3_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/typo3/sysext/core/Resources/Public/JavaScript/Contrib/require.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("TYPO3"));
    assert!(cms_detected, "Should detect TYPO3 via content");
}

#[tokio::test]
async fn test_security_detects_ghost_via_content() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/assets/js/ghost-sdk.min.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Ghost"));
    assert!(cms_detected, "Should detect Ghost via content");
}

#[tokio::test]
async fn test_security_detects_joomla_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="Joomla! 4.0">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Joomla"));
    assert!(cms_detected, "Should detect Joomla via generator tag");
}

#[tokio::test]
async fn test_security_network_error() {
    // Create a URL that will fail to connect
    let url = Url::parse("http://localhost:1").unwrap();
    let client = reqwest::ClientBuilder::new()
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    // Should get a "Fetch failed" info flag
    let fetch_failed = flags.iter().any(|f| f.title.contains("Fetch failed"));
    assert!(fetch_failed, "Should handle network errors gracefully");
}

#[tokio::test]
async fn test_security_detects_server_header() {
    let html = "<!DOCTYPE html><html><body>Test</body></html>";
    let (_server, url) = setup_mock_with_content(html, vec![
        ("server", "nginx/1.18.0")
    ]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let server_detected = flags.iter().any(|f| 
        f.title.contains("Server header") || f.description.contains("nginx")
    );
    assert!(server_detected, "Should detect Server header exposure");
}

#[tokio::test]
async fn test_security_detects_xpoweredby_with_version() {
    let html = "<!DOCTYPE html><html><body>Test</body></html>";
    let (_server, url) = setup_mock_with_content(html, vec![
        ("x-powered-by", "PHP/7.4.3")
    ]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let xpb_detected = flags.iter().any(|f| 
        f.title.contains("X-Powered-By") && f.level == "Medium"
    );
    assert!(xpb_detected, "Should detect X-Powered-By with version as Medium");
}

#[tokio::test]
async fn test_security_detects_xpoweredby_without_version() {
    let html = "<!DOCTYPE html><html><body>Test</body></html>";
    let (_server, url) = setup_mock_with_content(html, vec![
        ("x-powered-by", "Express")
    ]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let xpb_detected = flags.iter().any(|f| 
        f.title.contains("X-Powered-By") && f.level == "Low"
    );
    assert!(xpb_detected, "Should detect X-Powered-By without version as Low");
}

#[tokio::test]
async fn test_security_wordpress_version_exposed() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    // Should detect both CMS and version exposure
    let version_exposed = flags.iter().any(|f| 
        f.title.contains("version exposed") || f.title.contains("Version")
    );
    assert!(version_exposed, "Should detect WordPress version exposure");
}

#[tokio::test]
async fn test_security_detects_react() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <div id="root"></div>
            <script src="/static/js/react.production.min.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("React")
    );
    assert!(framework_detected, "Should detect React framework");
}

#[tokio::test]
async fn test_security_detects_vue() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <div id="app" v-bind:title="message"></div>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("Vue")
    );
    assert!(framework_detected, "Should detect Vue framework");
}

#[tokio::test]
async fn test_security_detects_angular() {
    let html = r#"
        <!DOCTYPE html>
        <html ng-app="myApp">
        <body>
            <div ng-controller="MainCtrl"></div>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("Angular")
    );
    assert!(framework_detected, "Should detect Angular framework");
}

#[tokio::test]
async fn test_security_detects_vite() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script type="module" src="/@vite/client"></script>
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("Vite")
    );
    assert!(framework_detected, "Should detect Vite build tool");
}

#[tokio::test]
async fn test_security_detects_nextjs() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("Next.js")
    );
    assert!(framework_detected, "Should detect Next.js framework");
}

#[tokio::test]
async fn test_security_detects_svelte() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/build/svelte-bundle.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && f.description.contains("Svelte")
    );
    assert!(framework_detected, "Should detect Svelte framework");
}

#[tokio::test]
async fn test_security_detects_multiple_frameworks() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <div id="root"></div>
            <script src="/react.min.js"></script>
            <script src="/_next/static/main.js"></script>
        </body>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let framework_detected = flags.iter().any(|f| 
        f.title.contains("Frontend framework") && 
        (f.description.contains("React") || f.description.contains("Next.js"))
    );
    assert!(framework_detected, "Should detect multiple frameworks");
}

#[tokio::test]
async fn test_security_detects_magento_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="Magento 2.4">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Magento"));
    assert!(cms_detected, "Should detect Magento via generator tag");
}

#[tokio::test]
async fn test_security_detects_shopify_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="Shopify">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("Shopify"));
    assert!(cms_detected, "Should detect Shopify via generator tag");
}

#[tokio::test]
async fn test_security_detects_prestashop_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="PrestaShop">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("PrestaShop"));
    assert!(cms_detected, "Should detect PrestaShop via generator tag");
}

#[tokio::test]
async fn test_security_detects_opencart_via_generator() {
    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="OpenCart 3.0">
        </head>
        </html>
    "#;
    
    let (_server, url) = setup_mock_with_content(html, vec![]).await;
    let client = reqwest::Client::new();
    
    let flags = check_security_posture(&client, &url).await.unwrap();
    
    let cms_detected = flags.iter().any(|f| f.title.contains("CMS detected") && f.title.contains("OpenCart"));
    assert!(cms_detected, "Should detect OpenCart via generator tag");
}
