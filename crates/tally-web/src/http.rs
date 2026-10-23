//! Portable, authorization-first HTTP request handling.
//!
//! This crate does not expose a network listener. A future AWS Lambda HTTP
//! adapter translates its request into this bounded, provider-neutral shape.
//! No report data may be requested until the session store authorizes it.

use std::fmt;

use tally_core::{
    authentication::{Authentication, SESSION_TTL_SECONDS},
    identity::{DomainSet, ReportReference},
    ports::ReportRepository,
};
use url::Url;

use crate::{
    auth_pages::{
        render_link_confirmation, render_link_invalid, render_sign_in_form,
        render_sign_in_requested,
    },
    pages::{render_report_detail, render_report_page, ReportDetailViewModel},
    report_queries::{load_overview, OverviewSelection, SelectionError},
    setup::{render_setup_page, SetupInspector},
};

const SESSION_COOKIE: &str = "__Host-dmarc-session";
const MAX_FORM_BYTES: usize = 2_048;
const MAX_COOKIE_BYTES: usize = 4_096;
const MAX_QUERY_BYTES: usize = 2_048;

/// A site origin accepted only from trusted installation configuration,
/// never from request Host or Forwarded headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteOrigin(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSiteOrigin;

impl fmt::Display for InvalidSiteOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid configured HTTPS site origin")
    }
}
impl std::error::Error for InvalidSiteOrigin {}

impl SiteOrigin {
    pub fn parse(value: &str) -> Result<Self, InvalidSiteOrigin> {
        // Reject backslash normalization, encoded authority separators and
        // whitespace that a URL parser might otherwise normalize away.
        if value.contains(['\\', '%', '?', '#']) || value.chars().any(char::is_whitespace) {
            return Err(InvalidSiteOrigin);
        }
        let url = Url::parse(value).map_err(|_| InvalidSiteOrigin)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(InvalidSiteOrigin);
        }
        Ok(Self(url.origin().ascii_serialization()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Link formation uses only this validated installation origin and a
    /// cryptographically generated hex token, never an arbitrary redirect.
    pub fn login_link(&self, token: &str) -> Option<String> {
        if !valid_token(token) {
            return None;
        }
        Some(format!("{}/auth/confirm?token={token}", self.0))
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|ch| ch.is_ascii_hexdigit())
}

/// Already-decoded HTTP fields supplied by a hosting adapter. The adapter
/// must reject oversized encoded bodies and normalize a path to its literal
/// representation without accepting path traversal.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub content_type: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub cookie: Option<&'a str>,
    pub body: &'a str,
}

impl<'a> Request<'a> {
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Self {
            method,
            path,
            query: "",
            content_type: None,
            origin: None,
            cookie: None,
            body: "",
        }
    }
}

/// Minimal response contract for AWS HTTP adapters (no server dependency).
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

impl Response {
    fn html(status: u16, body: String) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type", "text/html; charset=utf-8".into()),
                ("Cache-Control", "no-store".into()),
                // Preserve form POST origins without exposing paths or tokens in Referer.
                ("Referrer-Policy", "strict-origin".into()),
                ("X-Content-Type-Options", "nosniff".into()),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".into(),
                ),
            ],
            body,
        }
    }

    fn message(status: u16, message: &str) -> Self {
        Self::html(
            status,
            format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>DMARC Tally</title></head><body><main><p>{message}</p></main></body></html>"
            ),
        )
    }

    fn redirect(path: &'static str) -> Self {
        let mut response = Self::html(303, String::new());
        response.headers.push(("Location", path.to_owned()));
        response
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn origin_authorized(request: &Request<'_>, site: &SiteOrigin) -> bool {
    request.origin == Some(site.as_str())
}

fn valid_form_type(request: &Request<'_>) -> bool {
    request
        .content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn valid_percent_escapes(input: &str) -> bool {
    let data = input.as_bytes();
    let mut index = 0;
    while index < data.len() {
        if data[index] == b'%' {
            if index + 2 >= data.len()
                || !data[index + 1].is_ascii_hexdigit()
                || !data[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn single_form_field(data: &str, name: &str, max_len: usize) -> Option<String> {
    if data.len() > max_len || !valid_percent_escapes(data) {
        return None;
    }
    let mut fields = form_urlencoded::parse(data.as_bytes());
    let (key, value) = fields.next()?;
    if key != name || fields.next().is_some() {
        return None;
    }
    Some(value.into_owned())
}

fn session_cookie_value<'a>(request: &Request<'a>) -> Option<&'a str> {
    let text = request.cookie?;
    if text.len() > MAX_COOKIE_BYTES {
        return None;
    }
    let mut found = None;
    for part in text.split(';') {
        if let Some((name, value)) = part.trim().split_once('=') {
            if name.trim() == SESSION_COOKIE {
                if found.is_some() {
                    return None; // duplicate session cookies must never win.
                }
                found = Some(value.trim());
            }
        }
    }
    found
}

async fn authorized(request: &Request<'_>, auth: &Authentication<'_>, now: i64) -> bool {
    let Some(cookie) = session_cookie_value(request) else {
        return false;
    };
    // A storage outage MUST NOT grant access. Error details are deliberately
    // not exposed to the browser or logged with bearer credentials.
    auth.is_authenticated(cookie, now).await.unwrap_or(false)
}

fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"
    )
}

fn expired_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Execute one already-decoded request. This is the only application-level
/// entry to reporting. All private routes are gated before repository reads.
pub async fn handle(
    request: &Request<'_>,
    auth: &Authentication<'_>,
    reports: &dyn ReportRepository,
    domains: &DomainSet,
    site: &SiteOrigin,
    setup: &dyn SetupInspector,
    now: i64,
) -> Response {
    // Only strict canonical route paths are accepted; URL decoding belongs to
    // the hosting adapter, and no arbitrary query/path is used for redirects.
    if request.path.contains(['%', '\\', '?', '#'])
        || request.path.contains("..")
        || request.path.contains("//")
    {
        return Response::message(404, "Not found.");
    }

    match (request.method, request.path) {
        ("GET", "/auth/login") => Response::html(200, render_sign_in_form()),

        ("POST", "/auth/request") => {
            if !origin_authorized(request, site) {
                return Response::message(403, "Request forbidden.");
            }
            if !valid_form_type(request) {
                return Response::message(415, "Unsupported form content type.");
            }
            let Some(email) = single_form_field(request.body, "email", MAX_FORM_BYTES) else {
                return Response::message(400, "Invalid request.");
            };
            // Account recognition, throttling and send failure must not change
            // the visible response. The core handles one configured recipient.
            let _ = auth.request_sign_in(&email, now).await;
            Response::html(200, render_sign_in_requested())
        }

        ("GET", "/auth/confirm") => {
            let result = single_form_field(request.query, "token", MAX_QUERY_BYTES);
            match result {
                Some(token) => Response::html(200, render_link_confirmation(&token)),
                None => Response::html(200, render_link_invalid()),
            }
        }

        ("POST", "/auth/confirm") => {
            if !origin_authorized(request, site) {
                return Response::message(403, "Request forbidden.");
            }
            if !valid_form_type(request) {
                return Response::message(415, "Unsupported form content type.");
            }
            let Some(token) = single_form_field(request.body, "token", MAX_FORM_BYTES) else {
                return Response::html(200, render_link_invalid());
            };
            if !valid_token(&token) {
                return Response::html(200, render_link_invalid());
            }
            match auth.redeem_sign_in(&token, now).await {
                Ok(Some(session)) => {
                    let mut response = Response::redirect("/");
                    response
                        .headers
                        .push(("Set-Cookie", session_cookie(&session.cookie_value())));
                    response
                }
                Ok(None) => Response::html(200, render_link_invalid()),
                Err(_) => Response::message(503, "Authentication temporarily unavailable."),
            }
        }

        ("POST", "/auth/logout") => {
            if !origin_authorized(request, site) {
                return Response::message(403, "Request forbidden.");
            }
            if !valid_form_type(request) || request.body.len() > MAX_FORM_BYTES {
                return Response::message(400, "Invalid logout request.");
            }
            if !authorized(request, auth, now).await {
                return Response::redirect("/auth/login");
            }
            let Some(token) = session_cookie_value(request) else {
                return Response::redirect("/auth/login");
            };
            if auth.sign_out(token).await.is_err() {
                return Response::message(503, "Sign-out temporarily unavailable.");
            }
            let mut response = Response::redirect("/auth/login");
            response.headers.push(("Set-Cookie", expired_cookie()));
            response
        }

        ("GET", "/setup") => {
            if !authorized(request, auth, now).await {
                return Response::redirect("/auth/login");
            }
            if !request.query.is_empty() {
                return Response::message(400, "Invalid request.");
            }
            Response::html(200, render_setup_page(&setup.inspect().await, now))
        }

        ("GET", "/") => {
            if !authorized(request, auth, now).await {
                return Response::redirect("/auth/login");
            }
            let selection = match OverviewSelection::parse(request.query, domains) {
                Ok(selection) => selection,
                Err(
                    SelectionError::MalformedQuery
                    | SelectionError::InvalidPeriod
                    | SelectionError::UnconfiguredDomain,
                ) => {
                    return Response::message(400, "Invalid report filter.");
                }
            };
            match load_overview(reports, domains, &selection, now).await {
                Ok(view) => Response::html(200, render_report_page(&view)),
                Err(_) => Response::message(503, "Report data temporarily unavailable."),
            }
        }

        ("GET", path) if path.starts_with("/reports/") => {
            // Authorization must precede even malformed/guessed IDs and every
            // repository read. No original MIME access from this route.
            if !authorized(request, auth, now).await {
                return Response::redirect("/auth/login");
            }
            if !request.query.is_empty() {
                return Response::message(404, "Not found.");
            }
            let Some(reference) = ReportReference::parse_path(path) else {
                return Response::message(404, "Not found.");
            };
            if !domains.contains(&reference.domain) {
                return Response::message(404, "Not found.");
            }
            match reports.get_report_by_reference(&reference).await {
                Ok(Some(report)) if reference.matches(&report.identity) => Response::html(
                    200,
                    render_report_detail(&ReportDetailViewModel {
                        report,
                        original_available: false,
                    }),
                ),
                Ok(None) => Response::message(404, "Not found."),
                Ok(Some(_)) | Err(_) => {
                    Response::message(503, "Report data temporarily unavailable.")
                }
            }
        }

        (_, "/auth/login" | "/auth/request" | "/auth/confirm" | "/auth/logout") => {
            Response::message(405, "Method not allowed.")
        }
        ("GET", _) => Response::message(404, "Not found."),
        _ => Response::message(405, "Method not allowed."),
    }
}
