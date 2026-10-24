//! Small accessible and escaped server-rendered DMARC reporting pages.
//!
//! This crate has no dependency on AWS or Lambda. Its caller is responsible
//! for authentication and data-access checks before invoking a renderer.

use tally_core::{
    identity::{DomainName, ReportReference, StoredReport},
    reporting::Summary,
};

#[derive(Clone)]
pub struct RecentReport {
    pub reference: ReportReference,
    pub organisation: String,
    pub messages: u64,
}

#[derive(Clone)]
pub struct ReportViewModel {
    pub selected_domain: Option<DomainName>,
    pub configured_domains: Vec<DomainName>,
    pub days: u8,
    pub summary: Summary,
    pub recent_reports: Vec<RecentReport>,
}

#[derive(Clone)]
pub struct ReportDetailViewModel {
    pub report: StoredReport,
    /// This is an application permission/retention decision, not an S3 URL.
    pub original_available: bool,
}

pub(crate) fn escape_html(value: &str) -> String {
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

pub(crate) fn start_page(title: &str) -> String {
    let mut html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="strict-origin">
<title>{} · DMARC Tally</title>"#,
        escape_html(title),
    );
    html.push_str(
        r##"<style>
:root { color-scheme: light dark; font-family: system-ui,-apple-system,sans-serif; }
body { margin:0 auto; max-width: 68rem; padding:1.2rem; line-height:1.5; }
header { display:flex; gap:0.75rem 2rem; align-items:baseline; flex-wrap:wrap; border-bottom:1px solid #8886; }
header h1 { margin:0.6rem 0; } header nav { display:flex; gap:1.1rem; }
main { padding-block:0.7rem 1.8rem; } footer { border-top:1px solid #8886; padding-block:0.8rem; }
section { margin-top:2rem; } section h3,section h2 { margin-bottom:0.3rem; }
a { color:inherit; text-underline-offset:0.18em; }
a:focus-visible,button:focus-visible,select:focus-visible { outline:3px solid #4a92e7; outline-offset:3px; }
.stats { display:flex; flex-wrap:wrap; gap:0.8rem; margin:1.1rem 0; }
.stat { border:1px solid #8886; border-radius:0.65rem; padding:0.7rem 1rem; flex:1 1 9rem; }
.stat strong { display:block; font-size:1.45rem; font-variant-numeric:tabular-nums; }
table { border-collapse:collapse; width:100%; min-width:35rem; }
th,td { text-align:left; padding:0.6rem 0.7rem; border-bottom:1px solid #8886; vertical-align:top; }
th[scope="col"] { font-weight:650; } .table-scroll { overflow-x:auto; }
tbody tr:hover { background:Canvas; outline:1px solid #8884; }
form { display:flex; flex-wrap:wrap; align-items:end; gap:0.8rem; }
label { display:block; font-weight:600; } select,input,button { font:inherit; padding:0.45rem; }
.muted { opacity:0.75; } .skip { position:absolute; top:-5rem; }
.skip:focus { top:0; background:Canvas; padding:0.5rem; }
.summary-note { max-width:55rem; } .risk { font-weight:650; }
.metadata { display:grid; grid-template-columns:repeat(auto-fit,minmax(12rem,1fr)); gap:0.7rem; margin-block:1rem; }
.metadata div { padding:0.7rem; border:1px solid #8886; border-radius:0.5rem; min-width:0; }
.metadata dt { font-size:0.87rem; opacity:0.8; } .metadata dd { margin:0.15rem 0 0; overflow-wrap:anywhere; font-weight:600; }
.observation { border-top:1px solid #8886; padding-top:0.8rem; }
.observation ul { margin-top:0.3rem; } .report-filter { margin-block:1rem; }
@media (max-width: 42rem) { body { padding:0.9rem; } .stat { flex-basis:9rem; } form.report-filter > div { flex:1 1 8rem; } form.report-filter select { width:100%; } }
</style></head><body><a class="skip" href="#content">Skip to main content</a>
<header><h1>DMARC Tally</h1><nav aria-label="Main navigation"><a href="/">Reports</a><a href="/setup">Setup</a></nav></header><main id="content">"##,
    );
    html
}

pub(crate) fn finish_page(mut page: String) -> String {
    page.push_str("</main><footer><p class=\"muted\">DMARC Tally · Counts reflect reporting receivers, not all email delivered.</p></footer></body></html>");
    page
}


fn percentage(part: u64, total: u64) -> String {
    if total == 0 {
        return "—".to_owned();
    }
    format!("{:.1}%", (part as f64 / total as f64) * 100.0)
}

fn utc_date(epoch: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(epoch)
        .map(|time| format!("{:04}-{:02}-{:02}", time.year(), u8::from(time.month()), time.day()))
        .unwrap_or_else(|_| "Unknown date".to_owned())
}

fn utc_time(epoch: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(epoch)
        .map(|time| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                time.year(),
                u8::from(time.month()),
                time.day(),
                time.hour(),
                time.minute(),
            )
        })
        .unwrap_or_else(|_| "Unknown date".to_owned())
}

pub fn render_report_page(view: &ReportViewModel) -> String {
    let mut html = start_page("Overview");
    html.push_str("<h2>DMARC overview</h2><p class=\"summary-note\">These are messages observed in DMARC reports, not a count of all email sent. A DMARC pass requires at least one aligned DKIM or SPF pass; a failure does not by itself mean abuse.</p>");
    html.push_str(r#"<form method="post" action="/auth/logout"><button type="submit">Sign out</button></form>"#);
    html.push_str(r#"<form class="report-filter" method="get" action="/"><div><label for="domain">Domain</label><select name="domain" id="domain">"#);
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
    html.push_str("<section class=\"stats\" aria-label=\"DMARC observations\">");
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
    html.push_str(&format!(
        "<div class=\"stat\"><span>Failure rate</span><strong>{}</strong></div>",
        percentage(view.summary.failed, view.summary.messages),
    ));
    html.push_str("</section>");

    if view.summary.reports == 0 {
        html.push_str("<p>No DMARC reports for this selection yet. Receiving a report may take time after DNS is configured.</p>");
        html.push_str("<p><strong>Setup not confirmed from this view.</strong> <a href=\"/setup\">Check receiving configuration</a> before assuming reports will arrive.</p>");
        return finish_page(html);
    }

    html.push_str("<section aria-labelledby=\"failure-sources\"><h2 id=\"failure-sources\">Sources with DMARC failures</h2>");
    html.push_str("<p class=\"muted\">Prioritised by observed failed-message volume. A source with failed DMARC is not necessarily malicious; investigate expected senders and alignment first.</p>");
    let mut failing_sources: Vec<_> = view.summary.by_ip.iter()
        .filter(|(_, traffic)| traffic.failed > 0)
        .collect();
    failing_sources.sort_by(|(left_ip, left), (right_ip, right)| {
        right.failed.cmp(&left.failed)
            .then_with(|| right.messages.cmp(&left.messages))
            .then_with(|| left_ip.cmp(right_ip))
    });
    if failing_sources.is_empty() {
        html.push_str("<p>No DMARC failures observed in the selected reports.</p>");
    } else {
        html.push_str("<div class=\"table-scroll\"><table><caption>Up to 10 sending IP addresses, ordered by failed messages</caption>");
        html.push_str("<thead><tr><th scope=\"col\">Sending IP</th><th scope=\"col\">Failed messages</th><th scope=\"col\">All observed messages</th><th scope=\"col\">Failure rate</th></tr></thead><tbody>");
        for (ip, totals) in failing_sources.iter().take(10) {
            html.push_str(&format!(
                "<tr><th scope=\"row\">{}</th><td class=\"risk\">{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(ip),
                totals.failed,
                totals.messages,
                percentage(totals.failed, totals.messages),
            ));
        }
        html.push_str("</tbody></table></div>");
        if failing_sources.len() > 10 {
            html.push_str("<p class=\"muted\">Showing the ten largest failing sources; totals above include all sources.</p>");
        }
    }
    html.push_str("</section>");

    if !view.summary.dispositions.is_empty() {
        html.push_str("<section aria-labelledby=\"dispositions\"><h2 id=\"dispositions\">Receiver-reported dispositions</h2>");
        html.push_str("<p class=\"muted\">These are actions reported by receivers, not DMARC authentication outcomes. A “none” disposition does not mean authentication passed.</p>");
        html.push_str("<div class=\"table-scroll\"><table><caption>Reported policy actions</caption><thead><tr><th scope=\"col\">Disposition</th><th scope=\"col\">Messages</th></tr></thead><tbody>");
        let mut dispositions: Vec<_> = view.summary.dispositions.iter().collect();
        dispositions.sort_by(|(a_name, a_count), (b_name, b_count)| {
            b_count.cmp(a_count).then_with(|| a_name.cmp(b_name))
        });
        for (disposition, count) in dispositions {
            html.push_str(&format!(
                "<tr><th scope=\"row\">{}</th><td>{count}</td></tr>",
                escape_html(disposition),
            ));
        }
        html.push_str("</tbody></table></div></section>");
    }

    html.push_str("<section aria-labelledby=\"reporters\"><h2 id=\"reporters\">Reporting organisations</h2>");
    html.push_str("<p class=\"muted\">Receivers reporting the highest failed-message volumes appear first.</p>");
    html.push_str("<div class=\"table-scroll\"><table><caption>Observations grouped by reporting organisation</caption>");
    html.push_str("<thead><tr><th scope=\"col\">Reporting organisation</th><th scope=\"col\">Messages</th><th scope=\"col\">Passed</th><th scope=\"col\">Failed</th><th scope=\"col\">Failure rate</th></tr></thead><tbody>");
    let mut reporters: Vec<_> = view.summary.by_reporter.iter().collect();
    reporters.sort_by(|(a_name, a), (b_name, b)| {
        b.failed.cmp(&a.failed).then_with(|| a_name.cmp(b_name))
    });
    for (reporter, totals) in reporters {
        html.push_str(&format!(
            "<tr><th scope=\"row\">{}</th><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(reporter),
            totals.messages,
            totals.passed,
            totals.failed,
            percentage(totals.failed, totals.messages),
        ));
    }
    html.push_str("</tbody></table></div></section>");

    if !view.recent_reports.is_empty() {
        html.push_str("<section aria-labelledby=\"recent-reports\"><h2 id=\"recent-reports\">Recent reports</h2><p class=\"muted\">Showing up to 20 reports in this period. Summary totals above include all reports.</p>");
        html.push_str("<div class=\"table-scroll\"><table><caption>Recent individual DMARC reports</caption>");
        html.push_str("<thead><tr><th scope=\"col\">Reporting organisation</th><th scope=\"col\">Domain</th><th scope=\"col\">Period end (UTC)</th><th scope=\"col\">Messages</th></tr></thead><tbody>");
        for report in &view.recent_reports {
            html.push_str(&format!(
                "<tr><th scope=\"row\"><a href=\"{}\">{}</a></th><td>{}</td><td>{}</td><td>{}</td></tr>",
                report.reference.path(),
                escape_html(&report.organisation),
                escape_html(report.reference.domain.as_str()),
                utc_date(report.reference.period_end),
                report.messages,
            ));
        }
        html.push_str("</tbody></table></div></section>");
    }
    finish_page(html)
}

pub fn render_report_detail(view: &ReportDetailViewModel) -> String {
    let r = &view.report;
    let mut html = start_page("Report details");
    html.push_str("<h2>Report details</h2><p><a href=\"/\">← Back to reports</a></p>");
    html.push_str(r#"<form method="post" action="/auth/logout"><button type="submit">Sign out</button></form>"#);
    html.push_str("<dl class=\"metadata\">");
    for (name, value) in [
        ("Reporting organisation", r.identity.organisation.clone()),
        ("Domain", r.identity.domain.as_str().to_owned()),
        ("Report ID", r.identity.report_id.clone()),
        ("Period start", utc_time(r.identity.period_start)),
        ("Period end", utc_time(r.identity.period_end)),
    ] {
        html.push_str(&format!(
            "<div><dt>{name}</dt><dd>{}</dd></div>",
            escape_html(&value),
        ));
    }
    html.push_str("</dl>");

    let mut messages = 0_u64;
    let mut failures = 0_u64;
    for record in &r.report.records {
        messages = messages.saturating_add(record.count);
        if record.evaluated.value("dkim") != Some("pass")
            && record.evaluated.value("spf") != Some("pass")
        {
            failures = failures.saturating_add(record.count);
        }
    }
    html.push_str(&format!(
        "<p><strong>{messages}</strong> observed messages across <strong>{}</strong> records; \
         <strong>{failures}</strong> did not pass DMARC ({} of observed messages).</p>",
        r.report.records.len(),
        percentage(failures, messages),
    ));
    if view.original_available {
        html.push_str(&format!(
            "<p><a href=\"/reports/{}/original\">View original email</a></p>",
            r.identity.digest_hex()
        ));
    } else {
        html.push_str("<p class=\"muted\">Original email is no longer retained or accessible.</p>");
    }
    html.push_str("<section aria-labelledby=\"observations\"><h3 id=\"observations\">Policy-evaluated observations</h3>");
    html.push_str("<p class=\"muted\">Aligned DKIM and SPF reflect the receiver’s DMARC policy evaluation. The individual authentication results below may differ because they are not necessarily aligned.</p>");
    html.push_str("<div class=\"table-scroll\"><table>");
    html.push_str("<caption>DMARC policy evaluation of each reported source observation</caption><thead><tr><th scope=\"col\">Sending IP</th><th scope=\"col\">Messages</th><th scope=\"col\">DMARC</th><th scope=\"col\">Aligned DKIM</th><th scope=\"col\">Aligned SPF</th><th scope=\"col\">Disposition</th></tr></thead><tbody>");
    for (index, record) in r.report.records.iter().enumerate() {
        let pass = record.evaluated.value("dkim") == Some("pass")
            || record.evaluated.value("spf") == Some("pass");
        html.push_str(&format!(
            "<tr><th scope=\"row\"><a href=\"#observation-{}\">{}</a></th><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            index + 1,
            escape_html(&record.source_ip),
            record.count,
            if pass { "Pass" } else { "Not passed" },
            escape_html(record.evaluated.value("dkim").unwrap_or("unknown")),
            escape_html(record.evaluated.value("spf").unwrap_or("unknown")),
            escape_html(record.evaluated.value("disposition").unwrap_or("unknown")),
        ));
    }
    html.push_str("</tbody></table></div></section>");
    html.push_str("<section aria-labelledby=\"authentication-details\"><h3 id=\"authentication-details\">Authentication details by observation</h3>");
    for (index, record) in r.report.records.iter().enumerate() {
        html.push_str(&format!(
            "<section class=\"observation\" aria-labelledby=\"observation-{}\"><h4 id=\"observation-{}\">Observation {} · Sending IP {}</h4>",
            index + 1,
            index + 1,
            index + 1,
            escape_html(&record.source_ip),
        ));
        if !record.dkim_results.is_empty() {
            html.push_str("<h5>Reported DKIM authentication results</h5><ul>");
            for result in &record.dkim_results {
                html.push_str(&format!(
                    "<li>{}: {}</li>",
                    escape_html(result.value("domain").unwrap_or("unknown")),
                    escape_html(result.value("result").unwrap_or("unknown")),
                ));
            }
            html.push_str("</ul>");
        }
        if !record.spf_results.is_empty() {
            html.push_str("<h5>Reported SPF authentication results</h5><ul>");
            for result in &record.spf_results {
                html.push_str(&format!(
                    "<li>{}: {}</li>",
                    escape_html(result.value("domain").unwrap_or("unknown")),
                    escape_html(result.value("result").unwrap_or("unknown")),
                ));
            }
            html.push_str("</ul>");
        }
        if record.dkim_results.is_empty() && record.spf_results.is_empty() {
            html.push_str("<p class=\"muted\">No detailed authentication results supplied.</p>");
        }
        if !record.evaluated.reasons.is_empty() {
            html.push_str("<h5>Receiver-reported policy reasons</h5><ul>");
            for reason in &record.evaluated.reasons {
                html.push_str(&format!(
                    "<li>{}: {}</li>",
                    escape_html(reason.value("type").unwrap_or("unknown")),
                    escape_html(reason.value("comment").unwrap_or("")),
                ));
            }
            html.push_str("</ul>");
        }
        html.push_str("</section>");
    }
    html.push_str("</section>");
    finish_page(html)
}
