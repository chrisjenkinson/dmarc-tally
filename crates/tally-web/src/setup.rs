//! A small, provider-neutral setup-readiness view for the administrator.
//!
//! Inspectors supply evidence for checks; this page renders it without
//! treating the existence of a configured address as proof of delivery.
//! No AWS calls are made by the renderer or on unauthenticated requests.
use async_trait::async_trait;
use tally_core::identity::DomainName;

use crate::pages::{escape_html, finish_page, start_page};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckState {
    Ready,
    ActionRequired,
    NotVerified,
    UnableToCheck,
}

impl CheckState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::ActionRequired => "Action required",
            Self::NotVerified => "Not verified",
            Self::UnableToCheck => "Unable to check",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SetupCheck {
    pub title: &'static str,
    pub state: CheckState,
    /// Plain text, never markup or a raw AWS API error.
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct SetupSnapshot {
    pub receiving_address: Option<String>,
    pub monitored_domains: Vec<DomainName>,
    pub checks: Vec<SetupCheck>,
}

/// Read-only, on-demand installation inspection. The HTTP gateway must
/// authorize its caller before executing this potentially remote operation.
#[async_trait]
pub trait SetupInspector: Send + Sync {
    async fn inspect(&self) -> SetupSnapshot;
}

/// The host supplies its trusted request time; never use a browser timestamp.
pub fn render_setup_page(snapshot: &SetupSnapshot, checked_at: i64) -> String {
    let mut html = start_page("Setup status");
    if let Ok(at) = time::OffsetDateTime::from_unix_timestamp(checked_at) {
        html.push_str(&format!(
            "<p class=\"muted\">Checked on {:04}-{:02}-{:02} at {:02}:{:02} UTC. Results are not continuously monitored.</p>",
            at.year(), u8::from(at.month()), at.day(), at.hour(), at.minute(),
        ));
    }
    let needs_action = snapshot
        .checks
        .iter()
        .filter(|c| c.state == CheckState::ActionRequired)
        .count();
    let unknown = snapshot
        .checks
        .iter()
        .filter(|c| matches!(c.state, CheckState::NotVerified | CheckState::UnableToCheck))
        .count();
    if needs_action > 0 {
        html.push_str(&format!("<p role=\"status\"><strong>{needs_action} setup checks require action.</strong> Review the details below.</p>"));
    }
    if unknown > 0 {
        html.push_str(&format!("<p>{unknown} checks remain unverified or unavailable. This does not mean incoming mail is broken.</p>"));
    }

    html.push_str(
        "<h2>Setup status</h2><p>These checks help identify outstanding configuration. \
         AWS configuration does not prove successful email delivery.</p>\
         <p><a href=\"/setup\">Refresh checks</a> · <a href=\"/\">Back to reports</a></p>\
         <h3>Receiving address</h3>",
    );
    match &snapshot.receiving_address {
        Some(address) => {
            html.push_str(&format!("<p><code>{}</code></p>", escape_html(address)));
        }
        None => html.push_str("<p>Receiving address not configured.</p>"),
    }
    html.push_str("<h3>Monitored domains</h3><ul>");
    for domain in &snapshot.monitored_domains {
        html.push_str(&format!(
            "<li><code>{}</code></li>",
            escape_html(domain.as_str())
        ));
    }
    html.push_str("</ul><h3>Checks</h3><ul>");
    for check in &snapshot.checks {
        html.push_str(&format!(
            "<li><strong>{}: {}</strong><p>{}</p></li>",
            escape_html(check.title),
            check.state.label(),
            escape_html(&check.detail),
        ));
    }
    html.push_str(
        "</ul><p class=\"muted\">Results are checked when this page loads. \
         Refresh to inspect again. An observed AWS configuration is not proof of a successful end-to-end test.</p>",
    );
    finish_page(html)
}
