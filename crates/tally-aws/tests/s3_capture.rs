use aws_sdk_s3::types::Tag;
use tally_aws::s3::capture_tags;

fn tag(key: &str, value: &str) -> Tag {
    Tag::builder().key(key).value(value).build().unwrap()
}

#[test]
fn preserves_unrelated_s3_tags_when_marking_captured() {
    let result = capture_tags(&[tag("source", "ses")]).unwrap();
    assert_eq!(result.len(), 2);
    assert!(result
        .iter()
        .any(|t| t.key() == "source" && t.value() == "ses"));
    assert!(result
        .iter()
        .any(|t| t.key() == "captured" && t.value() == "true"));
}

#[test]
fn repeating_capture_tag_keeps_one_canonical_value() {
    let tags = capture_tags(&[tag("captured", "false"), tag("source", "ses")]).unwrap();
    let again = capture_tags(&tags).unwrap();
    assert_eq!(again.len(), 2);
    assert_eq!(
        again.iter().filter(|tag| tag.key() == "captured").count(),
        1
    );
    assert_eq!(
        again
            .iter()
            .find(|tag| tag.key() == "captured")
            .unwrap()
            .value(),
        "true"
    );
}

#[test]
fn refuses_to_drop_existing_tags_if_full() {
    let tags = (0..10)
        .map(|n| tag(&format!("t{n}"), "v"))
        .collect::<Vec<_>>();
    assert!(capture_tags(&tags).is_err());
}
