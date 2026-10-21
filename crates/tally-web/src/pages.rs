//! Small accessible and escaped server-rendered DMARC reporting pages.
//!
//! This crate has no dependency on AWS or Lambda. Its caller is responsible
//! for authentication and data-access checks before invoking a renderer.

use tally_core::{
    identity::{DomainName, StoredReport},
    reporting::Summary,
};

#[derive(Clone)]
pub struct ReportViewModel {
    pub selected_domain: Option<DomainName>,
    pub configured_domains: Vec<DomainName>,
    pub days: u8,
    pub summary: Summary,
}

#[derive(Clone)]
pub struct ReportDetailViewModel {
    pub report: StoredReport,
    /// This is an application permission/retention decision, not an S3 URL.
    pub original_available: bool,
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn start_page(title: &str) -> String {
    let mut html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{} · DMARC Tally</title>"#,
        escape_html(title),
    );
    html.push_str(
        r##"<style>
:root { color-scheme: light dark; font-family: system-ui,-apple-system,sans-serif; }
body { margin:0 auto; max-width: 58rem; padding: 1.2rem; line-height:1.5; }
header,main,footer { display:block; }
a { color:inherit; } a:focus-visible,button:focus-visible,select:focus-visible { outline:3px solid #4a92e7; outline-offset:3px; }
nav { margin-block:1rem; } .stats { display:flex; flex-wrap:wrap; gap:0.8rem; margin:1.1rem 0; }
.stat { border:1px solid #8886; border-radius:0.65rem; padding:0.7rem 1rem; flex:1 1 9rem; }
.stat strong { display:block; font-size:1.45rem; font-variant-numeric:tabular-nums; }
table { border-collapse:collapse; width:100%; min-width:30rem; }
th,td { text-align:left; padding:0.6rem 0.7rem; border-bottom:1px solid #8886; }
th[scope="col"] { font-weight:650; } .table-scroll { overflow-x:auto; }
form { display:flex; flex-wrap:wrap; align-items:end; gap:0.8rem; }
label { display:block; font-weight:600; } select,button { font:inherit; padding:0.45rem; }
.muted { opacity:0.75; } .skip { position:absolute; top:-5rem; }
.skip:focus { top:0; background:Canvas; padding:0.5rem; }
</style></head><body><a class="skip" href="#content">Skip to reports</a>
<header><h1>DMARC Tally</h1><nav><a href="/">Reports</a></nav></header><main id="content">"##,
    );
    html
}

fn finish_page(mut page: String) -> String {
    page.push_str("</main><footer><p class=\"muted\">DMARC Tally · Counts reflect reporting receivers, not all email delivered.</p></footer></body></html>");
    page
}

pub fn render_report_page(view: &ReportViewModel) -> String {
    let mut html = start_page("Overview");
    html.push_str("<h2>Report overview</h2><p>These are messages observed in DMARC reports, not a count of emails sent.</p>");
    html.push_str(r#"<form method="get" action="/"><div><label for="domain">Domain</label><select name="domain" id="domain">"#);
    html.push_str(if view.selected_domain.is_none() {
        r#"<option value="all" selected>All domains</option>"#
    } else {
        r#"<option value="all">All domains</option>"#
    });
    for domain in &view.configured_domains {
        let escaped = escape_html(domain.as_str());
        let selected = if view.selected_domain.as_ref() == Some(domain) {
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{escaped}"{selected}>{escaped}</option>"#,
        ));
    }
    html.push_str(
        r#"</select></div><div><label for="days">Period</label><select name="days" id="days">"#,
    );
    let current_days = if matches!(view.days, 7 | 30 | 90) {
        view.days
    } else {
        30
    };
    for days in [7, 30, 90] {
        let selected = if current_days == days {
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{days}"{selected}>Last {days} days</option>"#,
        ));
    }
    html.push_str("</select></div><button type=\"submit\">Apply</button></form>");
    html.push_str("<section class=\"stats\" aria-label=\"Reported counts\">");
    for (name, value) in [
        ("Reports received", view.summary.reports),
        ("Messages observed", view.summary.messages),
        ("DMARC passed", view.summary.passed),
        ("DMARC failed", view.summary.failed),
    ] {
        html.push_str(&format!(
            "<div class=\"stat\"><span>{}</span><strong>{value}</strong></div>",
            escape_html(name),
        ));
    }
    html.push_str("</section>");

    if view.summary.reports == 0 {
        html.push_str("<p>No DMARC reports for this selection yet. Receiving a report may take time after DNS is configured.</p>");
    } else {
        html.push_str(
            "<section><h2>Reporting organisations</h2><div class=\"table-scroll\"><table>",
        );
        html.push_str("<caption>Observations grouped by reporting organisation</caption>");
        html.push_str("<thead><tr><th scope=\"col\">Reporting organisation</th><th scope=\"col\">Messages</th><th scope=\"col\">Pass</th><th scope=\"col\">Fail</th></tr></thead><tbody>");
        for (reporter, totals) in &view.summary.by_reporter {
            html.push_str(&format!(
                "<tr><th scope=\"row\">{}</th><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(reporter),
                totals.messages,
                totals.passed,
                totals.failed,
            ));
        }
        html.push_str("</tbody></table></div></section>");
    }
    finish_page(html)
}

pub fn render_report_detail(view: &ReportDetailViewModel) -> String {
    let r = &view.report;
    let mut html = start_page("Report details");
    html.push_str("<h2>Report details</h2>");
    html.push_str(&format!(
        "<p><strong>Reporting organisation:</strong> {}<br><strong>Domain:</strong> {}<br><strong>Report ID:</strong> {}</p>",
        escape_html(&r.identity.organisation),
        escape_html(r.identity.domain.as_str()),
        escape_html(&r.identity.report_id),
    ));
    if view.original_available {
        html.push_str(&format!(
            "<p><a href=\"/reports/{}/original\">View original email</a></p>",
            r.identity.digest_hex()
        ));
    } else {
        html.push_str("<p class=\"muted\">Original email is no longer retained or accessible.</p>");
    }
    html.push_str("<div class=\"table-scroll\"><table>");
    html.push_str("<caption>Authentication observations in this report</caption><thead><tr><th scope=\"col\">Sending IP</th><th scope=\"col\">Count</th><th scope=\"col\">Disposition</th><th scope=\"col\">DKIM</th><th scope=\"col\">SPF</th></tr></thead><tbody>");
    for record in &r.report.records {
        html.push_str(&format!(
            "<tr><th scope=\"row\">{}</th><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&record.source_ip),
            record.count,
            escape_html(record.evaluated.value("disposition").unwrap_or("unknown")),
            escape_html(record.evaluated.value("dkim").unwrap_or("unknown")),
            escape_html(record.evaluated.value("spf").unwrap_or("unknown")),
        ));
    }
    html.push_str("</tbody></table></div>");
    html.push_str("<h3>Authentication details</h3>");
    for record in &r.report.records {
        html.push_str(&format!(
            "<h4>Sending IP: {}</h4>",
            escape_html(&record.source_ip)
        ));
        for result in &record.dkim_results {
            html.push_str(&format!(
                "<p>DKIM: {} — {}</p>",
                escape_html(result.value("domain").unwrap_or("unknown")),
                escape_html(result.value("result").unwrap_or("unknown")),
            ));
        }
        for result in &record.spf_results {
            html.push_str(&format!(
                "<p>SPF: {} — {}</p>",
                escape_html(result.value("domain").unwrap_or("unknown")),
                escape_html(result.value("result").unwrap_or("unknown")),
            ));
        }
        for reason in &record.evaluated.reasons {
            html.push_str(&format!(
                "<p>Reported reason: {} — {}</p>",
                escape_html(reason.value("type").unwrap_or("unknown")),
                escape_html(reason.value("comment").unwrap_or("")),
            ));
        }
    }
    finish_page(html)
}
