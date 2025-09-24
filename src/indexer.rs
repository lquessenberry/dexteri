use anyhow::Result;
use std::path::Path;
use tantivy::collector::TopDocs;
use tantivy::doc;
use tantivy::query::QueryParser;
use tantivy::schema::{
    document::{OwnedValue, TantivyDocument},
    Schema, STORED, TEXT,
};
use tantivy::Index;

use crate::models::{IndexStats, Page, SearchHit};

fn schema() -> Schema {
    let mut builder = tantivy::schema::SchemaBuilder::default();
    builder.add_text_field("title", TEXT | STORED);
    builder.add_text_field("url", TEXT | STORED);
    builder.add_text_field("body", TEXT);
    builder.build()
}

pub async fn index_pages(out_dir: &Path, pages: &Vec<Page>) -> Result<IndexStats> {
    let schema = schema();
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir)?;
    }
    std::fs::create_dir_all(out_dir)?;
    let index = Index::create_in_dir(out_dir, schema.clone())?;
    let title = schema.get_field("title").unwrap();
    let url = schema.get_field("url").unwrap();
    let body = schema.get_field("body").unwrap();

    let mut writer = index.writer(50_000_000)?; // 50MB
    let mut count = 0usize;
    for p in pages {
        if let Some(text) = &p.text {
            let _ = writer.add_document(doc!(title => p.title.clone().unwrap_or_default(), url => p.url.clone(), body => text.clone()));
            count += 1;
        }
    }
    writer.commit()?;

    Ok(IndexStats {
        docs_indexed: count,
    })
}

pub fn search_index(index_dir: &Path, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
    let schema = schema();
    let index = Index::open_in_dir(index_dir)?;
    let reader = index.reader()?;
    let searcher = reader.searcher();

    let title = schema.get_field("title").unwrap();
    let url = schema.get_field("url").unwrap();
    let body = schema.get_field("body").unwrap();

    let parser = QueryParser::for_index(&index, vec![title, body]);
    let q = parser.parse_query(query)?;

    let top_docs = searcher.search(&q, &TopDocs::with_limit(limit))?;

    let mut hits = Vec::new();
    for (_score, addr) in top_docs {
        let retrieved = searcher.doc::<TantivyDocument>(addr)?;
        let t = retrieved.get_first(title).and_then(|v| match v {
            OwnedValue::Str(s) => Some(s.clone()),
            _ => None,
        });
        let u = retrieved
            .get_first(url)
            .and_then(|v| match v {
                OwnedValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();
        hits.push(SearchHit { url: u, title: t });
    }
    Ok(hits)
}
