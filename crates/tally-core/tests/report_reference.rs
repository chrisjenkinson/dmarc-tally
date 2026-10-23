use tally_core::{
    identity::{DomainName, ReportIdentity, ReportReference},
    ports::{InMemoryReportRepository, ReportRepository},
};

#[test]
fn direct_reference_is_canonical_small_and_storage_independent() {
    let identity = ReportIdentity {
        domain: DomainName::parse("Example.COM").unwrap(),
        organisation: "example reporter".into(),
        report_id: "id/with spaces".into(),
        period_start: 1_700_000_000,
        period_end: 1_700_086_400,
    };
    let reference = ReportReference::from_identity(&identity);
    let path = reference.path();
    assert!(
        path.starts_with("/reports/example.com/0000000001700086400/")
            || path.starts_with("/reports/example.com/00000000001700086400/")
    );
    assert!(!path.contains("example reporter"));
    assert!(!path.contains("id/with spaces"));
    assert!(ReportReference::parse_path(&path)
        .unwrap()
        .matches(&identity));
}

#[test]
fn malformed_and_ambiguous_references_are_rejected() {
    let good = format!(
        "/reports/example.com/{:020}/{}",
        1_700_086_400,
        "a".repeat(64)
    );
    assert!(ReportReference::parse_path(&good).is_some());
    for invalid in [
        "/reports/example.com/0/".to_string() + &"a".repeat(64),
        format!(
            "/reports/EXAMPLE.com/{:020}/{}",
            1_700_086_400,
            "a".repeat(64)
        ),
        format!(
            "/reports/example.com/{:020}/{}",
            1_700_086_400,
            "A".repeat(64)
        ),
        format!(
            "/reports/example.com/{:020}/{}",
            1_700_086_400,
            "a".repeat(63)
        ),
        format!(
            "/reports/example.com/{:020}/{}/original",
            1_700_086_400,
            "a".repeat(64)
        ),
        format!(
            "/reports/other..example/{:020}/{}",
            1_700_086_400,
            "a".repeat(64)
        ),
    ] {
        assert!(ReportReference::parse_path(&invalid).is_none(), "{invalid}");
    }
}

#[tokio::test]
async fn unknown_references_are_not_resolved_as_unrelated_reports() {
    let repo = InMemoryReportRepository::default();
    let unknown = ReportReference::parse_path(&format!(
        "/reports/example.com/{:020}/{}",
        1_700_086_400,
        "a".repeat(64),
    ))
    .unwrap();
    assert!(repo
        .get_report_by_reference(&unknown)
        .await
        .unwrap()
        .is_none());
}
