//! Small legacy-browser search and reading interface.
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use gw_transcode::{
    doc::{Block, Inline},
    proxy::{FetchBody, Proxy},
    transcode::{Limits, html_to_reader_deck, text_to_deck},
};
use scraper::{Html, Selector};
use url::Url;

fn param(query: Option<&str>, name: &str) -> String {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn page(title: &str, body: &str) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], format!("<!doctype html><html><head><title>{}</title></head><body><h1>{}</h1>{}<hr><a href=\"/\">Home</a></body></html>", escape(title), escape(title), body)).into_response()
}
fn reader_link(url: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("url", url)
        .finish();
    format!("/read?{query}")
}
pub async fn search(proxy: &Proxy, query: Option<&str>) -> Response {
    let q = param(query, "q");
    if q.trim().is_empty() || q.chars().count() > 90 {
        return page("Search", "Enter a search of up to 90 characters.");
    }
    let mut url = Url::parse("https://lite.duckduckgo.com/lite/").unwrap();
    url.query_pairs_mut().append_pair("q", &q);
    let result = match proxy.get(url.as_str(), &Default::default()).await {
        Ok(p) if p.status == 200 => p,
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "Search is temporarily unavailable.",
            )
                .into_response();
        }
    };
    let html = Html::parse_document(&String::from_utf8_lossy(&result.bytes));
    let selector = Selector::parse("a.result-link").unwrap();
    let mut body = String::new();
    for link in html.select(&selector).take(10) {
        let Some(href) = link.value().attr("href") else {
            continue;
        };
        let Ok(mut target) = url.join(href) else {
            continue;
        };
        if target
            .domain()
            .is_some_and(|d| d == "duckduckgo.com" || d.ends_with(".duckduckgo.com"))
        {
            let destination = target
                .query_pairs()
                .find(|(k, _)| k == "uddg")
                .map(|(_, v)| v.into_owned());
            let Some(Ok(parsed)) = destination.map(|d| Url::parse(&d)) else {
                continue;
            };
            target = parsed;
        }
        if !matches!(target.scheme(), "http" | "https") || target.host().is_none() {
            continue;
        }
        let title = link.text().collect::<Vec<_>>().join(" ");
        body.push_str(&format!(
            "<p><a href=\"{}\">{}</a></p>",
            escape(&reader_link(target.as_str())),
            escape(&title)
        ));
    }
    if body.is_empty() {
        body.push_str("<p>No results available. Try another search.</p>");
    }
    page("Search results", &body)
}
pub async fn read(proxy: &Proxy, query: Option<&str>) -> Response {
    let target = param(query, "url");
    let fetched = match proxy.get(&target, &Default::default()).await {
        Ok(p) if (200..300).contains(&p.status) => p,
        _ => return (StatusCode::BAD_GATEWAY, "Could not load this page.").into_response(),
    };
    let limits = Limits::default();
    let deck = match fetched.body() {
        FetchBody::Html(html) => html_to_reader_deck(&html, &fetched.final_url, &limits),
        FetchBody::Text(text) => text_to_deck(&text, "Page", &limits),
        FetchBody::Other => return page("Page", "This content cannot be displayed."),
    };
    let mut body = String::new();
    for block in deck.blocks {
        match block {
            Block::Heading(s) => body.push_str(&format!("<h2>{}</h2>", escape(&s))),
            Block::Line(items) => {
                body.push_str("<p>");
                for item in items {
                    match item {
                        Inline::Text(s) => body.push_str(&escape(&s)),
                        Inline::Link { label, dest } => body.push_str(&format!(
                            "<a href=\"{}\">{}</a>",
                            escape(&reader_link(&dest)),
                            escape(&label)
                        )),
                    }
                }
                body.push_str("</p>");
            }
            Block::Break => body.push_str("<br>"),
            Block::Form(_) => {}
        }
    }
    page(deck.title.as_deref().unwrap_or("Page"), &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_and_encodes_untrusted_input() {
        assert_eq!(escape("<a '&\""), "&lt;a &#39;&amp;&quot;");
        assert_eq!(param(Some("q=a%26b"), "q"), "a&b");
        assert!(reader_link("https://example.com/?x=1&y=2").contains("%26"));
    }
}
