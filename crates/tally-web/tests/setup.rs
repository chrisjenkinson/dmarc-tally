use tally_core::identity::DomainName;
use tally_web::setup::{render_setup_page, CheckState, SetupCheck, SetupSnapshot};

fn snapshot() -> SetupSnapshot {
    SetupSnapshot {
        receiving_address: Some("aggregate@dmarc.example.com".into()),
        monitored_domains: vec![DomainName::parse("example.com").unwrap()],
        checks: vec![
            SetupCheck {
                title: "SES receiving rule",
                state: CheckState::ActionRequired,
                detail: "The configured rule is not enabled in the active rule set.".into(),
            },
            SetupCheck {
                title: "Receiving MX / DMARC DNS",
                state: CheckState::NotVerified,
                detail: "DNS records have not been checked.".into(),
            },
            SetupCheck {
                title: "Sending identity",
                state: CheckState::Ready,
                detail: "The configured identity appears verified in SES.".into(),
            },
            SetupCheck {
                title: "Inbound delivery",
                state: CheckState::UnableToCheck,
                detail: "No end-to-end test result is available.".into(),
            },
        ],
    }
}

#[test]
fn setup_page_shows_configured_address_monitored_domains_and_distinct_states() {
    let html = render_setup_page(&snapshot());
    assert!(html.contains("Setup status"));
    assert!(html.contains("aggregate@dmarc.example.com"));
    assert!(html.contains("example.com"));
    for label in [
        "Action required",
        "Not verified",
        "Ready",
        "Unable to check",
    ] {
        assert!(html.contains(label), "missing status: {label}");
    }
    assert!(html.contains("SES receiving rule"));
    assert!(html.contains("Receiving MX / DMARC DNS"));
    assert!(html.contains("Inbound delivery"));
    assert!(html.contains("Refresh checks"));
    assert!(html.contains("AWS configuration does not prove successful email delivery"));
    assert!(!html.contains("All checks passed"));
}

#[test]
fn page_never_renders_untrusted_status_details_as_markup() {
    let mut snapshot = snapshot();
    snapshot.receiving_address = Some("<svg/onload=alert(1)>@example.com".into());
    snapshot.checks[0].detail = "<script>exfiltrate()</script>".into();
    let html = render_setup_page(&snapshot);
    assert!(!html.contains("<script>exfiltrate()"));
    assert!(!html.contains("<svg/onload"));
    assert!(html.contains("&lt;script&gt;exfiltrate()&lt;/script&gt;"));
    assert!(html.contains("&lt;svg/onload=alert(1)&gt;"));
}

#[test]
fn missing_configuration_must_not_claim_readiness() {
    let mut snapshot = snapshot();
    snapshot.receiving_address = None;
    let html = render_setup_page(&snapshot);
    assert!(html.contains("Receiving address not configured"));
    assert!(!html.contains("aggregate@dmarc.example.com"));
}

#[test]
fn setup_link_is_not_an_automatic_aws_probe_on_report_render() {
    use tally_core::reporting::Summary;
    use tally_web::pages::{render_report_page, ReportViewModel};
    let page = render_report_page(&ReportViewModel {
        selected_domain: None,
        configured_domains: vec![DomainName::parse("example.com").unwrap()],
        days: 30,
        summary: Summary::default(),
    });
    assert!(page.contains("href=\"/setup\""));
    assert!(page.contains("No DMARC reports"));
}
