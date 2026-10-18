use tally_core::model::{DmarcFormat, ParseLimits};
use tally_core::xml::parse_dmarc_xml;

const LEGACY: &[u8] = include_bytes!("../../../tests/fixtures/xml/legacy.xml");
const MODERN: &[u8] = include_bytes!("../../../tests/fixtures/xml/modern.xml");
const EXTENSIONS: &[u8] = include_bytes!("../../../tests/fixtures/xml/unknown-extension.xml");
const MALFORMED: &[u8] = include_bytes!("../../../tests/fixtures/xml/malformed.xml");

#[test]
fn preserves_legacy_metadata_policy_repeated_results_and_reasons() {
    let report = parse_dmarc_xml(LEGACY, &ParseLimits::default()).unwrap();
    assert_eq!(report.format_version, DmarcFormat::Rfc7489);
    assert_eq!(report.metadata.org_name, "Receiver Example");
    assert_eq!(report.metadata.report_id, "legacy-001");
    assert_eq!(report.metadata.date_range.begin, 1791849600);
    assert_eq!(report.metadata.error, vec!["One message evaluated under local policy"]);
    assert_eq!(report.published_policy.domain, "example.com");
    assert_eq!(report.published_policy.value("fo"), Some("1"));
    assert_eq!(report.records.len(), 1);
    let record = &report.records[0];
    assert_eq!(record.source_ip, "192.0.2.10");
    assert_eq!(record.count, 7);
    assert_eq!(record.evaluated.value("dkim"), Some("pass"));
    assert_eq!(record.evaluated.reasons.len(), 1);
    assert_eq!(record.dkim_results.len(), 2);
    assert_eq!(record.dkim_results[1].value("selector"), Some("two"));
    assert_eq!(record.spf_results.len(), 2);
    assert_eq!(record.spf_results[0].value("scope"), Some("mfrom"));
    assert!(report.unknown_fields.is_empty(), "{:?}", report.unknown_fields);
}

#[test]
fn parses_modern_namespaced_format_without_discarding_new_fields() {
    let report = parse_dmarc_xml(MODERN, &ParseLimits::default()).unwrap();
    assert_eq!(report.format_version, DmarcFormat::Rfc9990);
    assert_eq!(report.metadata.generator.as_deref(), Some("Example v2"));
    assert_eq!(report.published_policy.value("np"), Some("reject"));
    assert_eq!(report.published_policy.value("testing"), Some("n"));
    assert_eq!(report.published_policy.value("discovery_method"), Some("treewalk"));
    assert_eq!(report.records[0].evaluated.value("disposition"), Some("pass"));
    assert!(report.unknown_fields.is_empty(), "{:?}", report.unknown_fields);
}

#[test]
fn retains_unknown_elements_and_namespaced_attributes_for_review() {
    let report = parse_dmarc_xml(EXTENSIONS, &ParseLimits::default()).unwrap();
    assert_eq!(report.records.len(), 1);
    assert!(report.unknown_fields.iter().any(|e| e.path.ends_with("/extension/override") && e.namespace.as_deref()==Some("https://example.net/dmarc/custom")));
    assert!(report.unknown_fields.iter().any(|e| e.path.ends_with("/org_name/@provenance") && e.namespace.as_deref()==Some("https://example.net/dmarc/custom")));
}

#[test]
fn refuses_malformed_and_entity_bearing_xml() {
    assert!(parse_dmarc_xml(MALFORMED, &ParseLimits::default()).is_err());
    let entity = br#"<!DOCTYPE feedback [<!ENTITY x "boom">]><feedback>&x;</feedback>"#;
    assert!(parse_dmarc_xml(entity, &ParseLimits::default()).is_err());
}

#[test]
fn enforces_input_nesting_and_record_limits() {
    let mut limits = ParseLimits::default();
    limits.max_xml_bytes = 20;
    assert!(parse_dmarc_xml(MODERN, &limits).is_err());
    limits = ParseLimits::default();
    limits.max_depth = 3;
    assert!(parse_dmarc_xml(MODERN, &limits).is_err());
    limits = ParseLimits::default();
    limits.max_records = 0;
    assert!(parse_dmarc_xml(MODERN, &limits).is_err());
}
