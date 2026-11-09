//! Transparent HTTP-to-HTTPS compatibility relay for legacy browsers.
use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use clap::Parser;
use gw_transcode::proxy::{
    FetchBody, MAX_BODY_BYTES, Proxy, ProxyError, forwardable_response_headers,
};
use std::{fs, net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, warn};
use url::Url;
#[path = "http_compat/search.rs"]
mod search;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "HTTP_COMPAT_GW_BIND", default_value = "10.55.0.1:8081")]
    bind: SocketAddr,
    #[arg(long, env = "HTTP_COMPAT_GW_PORTAL_HOSTS", default_value = "")]
    portal_hosts: String,
    #[arg(long, env = "HTTP_COMPAT_GW_REWRITES", default_value = "")]
    rewrites: String,
}
struct AppState {
    proxy: Proxy,
    portal_hosts: Vec<String>,
    rewrites: Vec<RewriteRule>,
}

#[derive(Debug)]
struct RewriteRule {
    host: String,
    path_prefix: String,
    target: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let state = Arc::new(AppState {
        proxy: Proxy::new(
            "Mozilla/5.0 (compatible; 1xBTS HTTP gateway)",
            Duration::from_secs(30),
        )?,
        portal_hosts: args
            .portal_hosts
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_ascii_lowercase)
            .collect(),
        rewrites: load_rewrite_rules(&args.rewrites)?,
    });
    let app = Router::new().fallback(handle).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    info!(bind = %args.bind, "http-compat-gw: HTTP-only listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    if parts.method == Method::CONNECT {
        return (StatusCode::METHOD_NOT_ALLOWED, "CONNECT is disabled").into_response();
    }
    if parts.method == Method::GET && is_portal_request(&parts, &state.portal_hosts) {
        return match parts.uri.path() {
            "/search" => search::search(&state.proxy, parts.uri.query()).await,
            "/read" => search::read(&state.proxy, parts.uri.query()).await,
            "/" => kozume_portal(),
            _ => (StatusCode::NOT_FOUND, "Not found").into_response(),
        };
    }
    let upstream = match rewrite_url(&parts, &state.rewrites) {
        Some(url) => url,
        None => match upstream_url(
            &parts.uri.to_string(),
            parts
                .headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok()),
        ) {
            Ok(url) => url,
            Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
        },
    };
    let page = match parts.method {
        Method::GET | Method::HEAD => state.proxy.get(&upstream, &parts.headers).await,
        Method::POST => match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
            Ok(bytes) => {
                state
                    .proxy
                    .post(&upstream, &parts.headers, bytes.to_vec())
                    .await
            }
            Err(_) => {
                return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
            }
        },
        _ => return (StatusCode::METHOD_NOT_ALLOWED, "method not supported").into_response(),
    };
    match page {
        Ok(page) => response_from_page(page),
        Err(error) => {
            warn!(%upstream, %error, "http-compat-gw: fetch failed");
            let status = match error {
                ProxyError::Blocked(_) => StatusCode::FORBIDDEN,
                ProxyError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::BAD_GATEWAY,
            };
            (status, error.to_string()).into_response()
        }
    }
}

fn load_rewrite_rules(path: &str) -> Result<Vec<RewriteRule>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(path)?;
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some(line)
        })
        .map(|line| {
            let (source, target) = line
                .split_once('|')
                .ok_or_else(|| anyhow::anyhow!("invalid rewrite rule: {line}"))?;
            let source = source
                .trim()
                .strip_prefix("http://")
                .ok_or_else(|| anyhow::anyhow!("rewrite sources must use http://: {source}"))?;
            let (host, path_prefix) = source.split_once('/').unwrap_or((source, ""));
            let target = Url::parse(target.trim())?;
            if !matches!(target.scheme(), "http" | "https") || target.host().is_none() {
                anyhow::bail!("invalid rewrite target: {target}");
            }
            Ok(RewriteRule {
                host: host.to_ascii_lowercase(),
                path_prefix: format!("/{}", path_prefix),
                target,
            })
        })
        .collect()
}

fn rewrite_url(parts: &axum::http::request::Parts, rules: &[RewriteRule]) -> Option<String> {
    let host = parts
        .headers
        .get(header::HOST)?
        .to_str()
        .ok()?
        .split(':')
        .next()?
        .to_ascii_lowercase();
    let path = parts.uri.path();
    let rule = rules.iter().find(|rule| {
        (rule.host == host
            || rule
                .host
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(suffix) && host.len() > suffix.len()))
            && path.starts_with(&rule.path_prefix)
    })?;
    let suffix = path.strip_prefix(&rule.path_prefix).unwrap_or_default();
    let mut target = rule.target.clone();
    if !suffix.is_empty() {
        target.set_path(&format!(
            "{}/{}",
            target.path().trim_end_matches('/'),
            suffix.trim_start_matches('/')
        ));
    }
    target.set_query(parts.uri.query());
    Some(target.into())
}

const KOZUME_PORTAL: &str = r##"<!doctype html>
<html><head><title>Kozume Wireless</title></head>
<body bgcolor="#ffffff" text="#111111" link="#0055aa" vlink="#663399">
<center><h1>Kozume Wireless</h1><p>Welcome to the mobile web.</p></center>
<hr>
<form action="/search" method="get">
<p><b>Search the web</b><br><input name="q" size="18" type="text"><br><input type="submit" value="Search"></p>
</form>
<p><b>Quick links</b></p>
<ul>
<li><a href="http://en.m.wikipedia.org/">Wikipedia</a></li>
<li><a href="http://example.com/">Example site</a></li>
</ul>
<hr>
<p><small>Legacy browser portal &middot; Kozume Wireless</small></p>
</body></html>"##;

fn is_portal_request(parts: &axum::http::request::Parts, portal_hosts: &[String]) -> bool {
    let Some(host) = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    host.split(':').next().is_some_and(|host| {
        portal_hosts
            .iter()
            .any(|portal_host| host.eq_ignore_ascii_case(portal_host))
    })
}

fn kozume_portal() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=iso-8859-1")],
        KOZUME_PORTAL,
    )
        .into_response()
}

fn upstream_url(uri: &str, host: Option<&str>) -> Result<String, &'static str> {
    let raw = if uri.starts_with("http://") {
        uri.to_owned()
    } else {
        format!(
            "http://{}/{}",
            host.ok_or("Host header required")?,
            uri.trim_start_matches('/')
        )
    };
    let mut url = Url::parse(&raw).map_err(|_| "invalid HTTP request URL")?;
    if url.scheme() != "http" {
        return Err("only HTTP requests are accepted");
    }
    url.set_scheme("https")
        .map_err(|_| "could not upgrade URL")?;
    Ok(url.into())
}
fn response_from_page(page: gw_transcode::proxy::FetchedPage) -> Response {
    let status = StatusCode::from_u16(page.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let rewrite = matches!(page.body(), FetchBody::Html(_) | FetchBody::Text(_))
        && (page.content_type.starts_with("text/") || page.content_type.contains("javascript"));
    let bytes = if rewrite {
        String::from_utf8_lossy(&page.bytes)
            .replace("https://", "http://")
            .replace("https%3A%2F%2F", "http%3A%2F%2F")
            .into_bytes()
    } else {
        page.bytes
    };
    let mut response = (status, Body::from(bytes)).into_response();
    for (name, value) in &forwardable_response_headers(&page.headers) {
        response.headers_mut().append(name.clone(), value.clone());
    }
    if let Ok(value) = page.content_type.parse() {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}
#[cfg(test)]
mod tests {
    use axum::http::{Request, Uri};
    use url::Url;

    use super::{KOZUME_PORTAL, RewriteRule, is_portal_request, rewrite_url, upstream_url};
    #[test]
    fn origin_form_uses_host() {
        assert_eq!(
            upstream_url("/x", Some("example.com")).unwrap(),
            "https://example.com/x"
        );
    }

    #[test]
    fn portal_search_stays_on_the_local_gateway() {
        assert!(KOZUME_PORTAL.contains("action=\"/search\""));
        assert!(!KOZUME_PORTAL.contains("google.com"));
    }

    #[test]
    fn uscc_start_page_uses_local_portal() {
        let request = Request::builder()
            .uri(Uri::from_static("http://m.uscellular.com/"))
            .header("host", "m.uscellular.com:8080")
            .body(())
            .unwrap();
        assert!(is_portal_request(
            &request.into_parts().0,
            &["m.uscellular.com".to_owned()]
        ));
    }

    #[test]
    fn rewrite_preserves_suffix_and_query() {
        let request = Request::builder()
            .uri(Uri::from_static("http://Login.Live.Com/login2.srf?lc=1033"))
            .header("host", "Login.Live.Com")
            .body(())
            .unwrap();
        let rules = [RewriteRule {
            host: "login.live.com".to_owned(),
            path_prefix: "/login2.srf".to_owned(),
            target: Url::parse("http://ctas.login.ugnet.xyz/login.srf").unwrap(),
        }];
        assert_eq!(
            rewrite_url(&request.into_parts().0, &rules),
            Some("http://ctas.login.ugnet.xyz/login.srf?lc=1033".to_owned())
        );
    }

    #[test]
    fn wildcard_rewrite_requires_a_subdomain() {
        let request = Request::builder()
            .uri(Uri::from_static("http://pocket.mobile.msn.com/auth"))
            .header("host", "pocket.mobile.msn.com")
            .body(())
            .unwrap();
        let rules = [RewriteRule {
            host: "*.mobile.msn.com".to_owned(),
            path_prefix: "/".to_owned(),
            target: Url::parse("http://ctas.login.ugnet.xyz/").unwrap(),
        }];
        assert_eq!(
            rewrite_url(&request.into_parts().0, &rules),
            Some("http://ctas.login.ugnet.xyz/auth".to_owned())
        );
    }
}
