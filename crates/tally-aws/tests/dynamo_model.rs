use tally_aws::dynamodb::{
    decode_report, encode_meta, encode_record, DynamoKeys, DynamoModelError,
};
use tally_core::identity::{StoredRecord, StoredReport};
use tally_core::model::ParseLimits;
use tally_core::xml::parse_dmarc_xml;

fn stored() -> StoredReport {
    let parsed = parse_dmarc_xml(
        include_bytes!("../../../tests/fixtures/xml/legacy.xml"),
        &ParseLimits::default(),
    )
    .unwrap();
    StoredReport::from_parsed(parsed, "parser-v1")
}

#[test]
fn dynamo_keys_are_stable_and_sort_chronologically() {
    let report = stored();
    let key = DynamoKeys::from_identity(&report.identity);
    assert_eq!(key.partition, "DOMAIN#example.com");
    assert!(key.metadata.ends_with("#META"));
    assert!(key.record_sort_key(0).ends_with("#REC#00000000"));
    assert!(key.record_sort_key(1).ends_with("#REC#00000001"));
    assert!(DynamoKeys::query_start(1_791_000_000) < DynamoKeys::query_start(1_792_000_000));
    assert!(DynamoKeys::query_end(1_792_000_000) > key.metadata);
}

#[test]
fn roundtrips_every_report_field_and_repeated_authentication_result() {
    let report = stored();
    let meta = encode_meta(&report).unwrap();
    let records = report
        .report
        .records
        .iter()
        .enumerate()
        .map(|(ordinal, full_record)| {
            encode_record(&StoredRecord {
                ordinal: ordinal as u32,
                full_record: full_record.clone(),
            })
            .unwrap()
        })
        .collect::<Vec<_>>();
    let roundtrip = decode_report(&meta, &records).unwrap();
    assert_eq!(roundtrip, report);
    assert_eq!(roundtrip.report.records[0].dkim_results.len(), 2);
    assert_eq!(roundtrip.report.records[0].spf_results.len(), 2);
}

#[test]
fn refuses_oversized_record_instead_of_silently_truncating_it() {
    let report = stored();
    let mut r = report.report.records[0].clone();
    r.raw.text = "a".repeat(410_000);
    let result = encode_record(&StoredRecord {
        ordinal: 0,
        full_record: r,
    });
    assert!(matches!(result, Err(DynamoModelError::TooLarge)));
}
