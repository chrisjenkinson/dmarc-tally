//! Strict AWS HTTP API Gateway v2 / Lambda Function URL event adapter.
//!
//! All reporting authorization, sign-in and session decisions remain in
//! `tally-web::http::handle`. This module only checks/decodes the transport
//! envelope and maps response headers/cookies to HTTP API v2. Never log a
//! request payload: it may contain raw bearer tokens, cookies or email.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};
use tally_core::{authentication::Authentication, identity::DomainSet, ports::ReportRepository};
use tally_web::http::{handle, Request, Response, SiteOrigin};

const MAX_PATH_BYTES: usize = 1024;
const MAX_QUERY_BYTES: usize = 2048;
const MAX_BODY_BYTES: usize = 2048;
const MAX_COOKIE_BYTES: usize = 4096;
const MAX_HEADERS_BYTES: usize = 16 * 1024;
const MAX_HEADERS_COUNT: usize = 64;

struct DecodedRequest {
    method: String,
    path: String,
    query: String,
    origin: Option<String>,
    content_type: Option<String>,
    cookie: Option<String>,
    body: String,
}

fn safe_header<'a>(item: &'a Value, key: &str) -> Result<Option<&'a str>, ()> {
    match item.get(key) {
        None => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or(()),
    }
}

fn decode(input: &Value) -> Result<DecodedRequest, ()> {
    if input.get("version").and_then(Value::as_str) != Some("2.0") {
        return Err(());
    }
    let method = input
        .pointer("/requestContext/http/method")
        .and_then(Value::as_str)
        .ok_or(())?;
    if method.is_empty() || method.len() > 12 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(());
    }
    let path = input.get("rawPath").and_then(Value::as_str).ok_or(())?;
    if !path.starts_with('/') || path.len() > MAX_PATH_BYTES {
        return Err(());
    }
    let query = match input.get("rawQueryString") {
        None | Some(Value::Null) => "",
        Some(Value::String(value)) => value.as_str(),
        _ => return Err(()),
    };
    if query.len() > MAX_QUERY_BYTES {
        return Err(());
    }

    let headers = input.get("headers").and_then(Value::as_object).ok_or(())?;
    if headers.len() > MAX_HEADERS_COUNT {
        return Err(());
    }
    let mut headers_bytes = 0_usize;
    let mut origin: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut cookie_header: Option<String> = None;
    for (key, value) in headers {
        let text = value.as_str().ok_or(())?;
        headers_bytes = headers_bytes
            .saturating_add(key.len())
            .saturating_add(text.len());
        if headers_bytes > MAX_HEADERS_BYTES || text.contains(['\r', '\n']) {
            return Err(());
        }
        let field = match key.to_ascii_lowercase().as_str() {
            "origin" => &mut origin,
            "content-type" => &mut content_type,
            "cookie" => &mut cookie_header,
            _ => continue, // In particular: never trust Host or Forwarded.
        };
        if field.is_some() {
            return Err(()); // Duplicate case variants must not choose a winner.
        }
        *field = Some(text.to_owned());
    }

    let cookie = match input.get("cookies") {
        None | Some(Value::Null) => cookie_header,
        Some(Value::Array(cookies)) if cookies.is_empty() => cookie_header,
        Some(Value::Array(cookies)) => {
            if cookie_header.is_some() || cookies.len() > 32 {
                return Err(());
            }
            let mut values = Vec::with_capacity(cookies.len());
            let mut bytes = 0_usize;
            for cookie in cookies {
                let item = cookie.as_str().ok_or(())?;
                bytes = bytes.saturating_add(item.len()).saturating_add(2);
                if bytes > MAX_COOKIE_BYTES || item.contains(['\r', '\n']) {
                    return Err(());
                }
                values.push(item);
            }
            Some(values.join("; "))
        }
        _ => return Err(()),
    };
    if cookie
        .as_ref()
        .is_some_and(|text| text.len() > MAX_COOKIE_BYTES)
    {
        return Err(());
    }

    let is_base64 = match input.get("isBase64Encoded") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(()),
    };
    let raw = match input.get("body") {
        None | Some(Value::Null) => "",
        Some(Value::String(value)) => value.as_str(),
        _ => return Err(()),
    };
    let body = if is_base64 {
        // Decode only small inputs. The body is form data, never a raw report.
        if raw.len() > MAX_BODY_BYTES * 2 {
            return Err(());
        }
        let decoded = STANDARD.decode(raw).map_err(|_| ())?;
        if decoded.len() > MAX_BODY_BYTES {
            return Err(());
        }
        String::from_utf8(decoded).map_err(|_| ())?
    } else {
        if raw.len() > MAX_BODY_BYTES {
            return Err(());
        }
        raw.to_owned()
    };
    Ok(DecodedRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        origin,
        content_type,
        cookie,
        body,
    })
}

fn invalid_envelope() -> Value {
    json!({
        "statusCode": 400,
        "isBase64Encoded": false,
        "cookies": [],
        "headers": {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"
        },
        "body": "Invalid request."
    })
}

fn encode_response(response: Response) -> Value {
    let mut headers = Map::new();
    let mut cookies = Vec::new();
    for (name, value) in response.headers {
        if name.eq_ignore_ascii_case("Set-Cookie") {
            cookies.push(value);
        } else {
            headers.insert(name.into(), Value::String(value));
        }
    }
    json!({
        "statusCode": response.status,
        "isBase64Encoded": false,
        "headers": headers,
        "cookies": cookies,
        "body": response.body
    })
}

/// Translate one event without touching the network. For the same event, the
/// portable gateway is the *only* route to reporting data, and it checks
/// sessions before using ReportRepository.
pub async fn handle_http_v2(
    event: &Value,
    auth: &Authentication<'_>,
    reports: &dyn ReportRepository,
    domains: &DomainSet,
    site: &SiteOrigin,
    now_epoch_seconds: i64,
) -> Value {
    let Ok(input) = decode(event) else {
        return invalid_envelope();
    };
    let request = Request {
        method: &input.method,
        path: &input.path,
        query: &input.query,
        content_type: input.content_type.as_deref(),
        origin: input.origin.as_deref(),
        cookie: input.cookie.as_deref(),
        body: &input.body,
    };
    encode_response(handle(&request, auth, reports, domains, site, now_epoch_seconds).await)
}
