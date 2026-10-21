use serde_json::json;
use tally_lambda::s3_event::{created_intake_objects, EventError};

fn s3_event(bucket: &str, key: &str) -> serde_json::Value {
    json!({
        "Records": [{
            "eventSource": "aws:s3",
            "eventName": "ObjectCreated:Put",
            "s3": {
                "bucket": {"name": bucket},
                "object": {"key": key}
            }
        }]
    })
}

#[test]
fn decodes_s3_url_encoded_key_without_losing_plus_signs() {
    let e = s3_event("example-intake-bucket", "incoming%2Freport+one%2Btwo.eml");
    let objects = created_intake_objects(&e, "example-intake-bucket").unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].bucket, "example-intake-bucket");
    assert_eq!(objects[0].key, "incoming/report one+two.eml");
}

#[test]
fn accepts_multiple_created_objects_but_ignores_unrelated_events() {
    let mut e = s3_event("example-intake-bucket", "incoming%2Ffirst.eml");
    let records = e["Records"].as_array_mut().unwrap();
    records.push(s3_event("example-intake-bucket", "incoming%2Fsecond.eml")["Records"][0].clone());
    records.push(json!({
        "eventSource": "aws:s3",
        "eventName": "ObjectRemoved:Delete",
        "s3": {"bucket":{"name":"example-intake-bucket"},"object":{"key":"incoming%2Fdeleted.eml"}}
    }));
    let objects = created_intake_objects(&e, "example-intake-bucket").unwrap();
    assert_eq!(objects.len(), 2);
}

#[test]
fn rejects_other_buckets_and_invalid_keys() {
    assert!(matches!(
        created_intake_objects(
            &s3_event("other-bucket", "incoming%2Freport.eml"),
            "example-intake-bucket"
        ),
        Err(EventError::WrongBucket)
    ));
    assert!(created_intake_objects(
        &s3_event("example-intake-bucket", "outgoing%2Fsecret.eml"),
        "example-intake-bucket"
    )
    .is_err());
    assert!(created_intake_objects(
        &s3_event("example-intake-bucket", "incoming%2F..%2Fsecret"),
        "example-intake-bucket"
    )
    .is_err());
    assert!(created_intake_objects(
        &s3_event("example-intake-bucket", "incoming%2Fbad%XX"),
        "example-intake-bucket"
    )
    .is_err());
}

#[test]
fn rejects_malformed_event_instead_of_acknowledging_it() {
    assert!(created_intake_objects(
        &json!({"Records":[{"eventName":"ObjectCreated:Put"}]}),
        "example-intake-bucket"
    )
    .is_err());
    assert!(created_intake_objects(&json!({}), "example-intake-bucket").is_err());
}

fn eventbridge_event(bucket: &str, key: &str) -> serde_json::Value {
    json!({
        "version": "0",
        "source": "aws.s3",
        "detail-type": "Object Created",
        "detail": {
            "bucket": {"name": bucket},
            "object": {"key": key, "version-id": "version+1"}
        }
    })
}

#[test]
fn eventbridge_keys_are_literal_including_plus_and_percent_sequences() {
    let event = eventbridge_event(
        "example-intake-bucket",
        "incoming/one+two%2Fnot-decoded.eml",
    );
    let objects = created_intake_objects(&event, "example-intake-bucket").unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].key, "incoming/one+two%2Fnot-decoded.eml");
    assert_eq!(objects[0].version_id.as_deref(), Some("version+1"));
}

#[test]
fn eventbridge_rejects_wrong_bucket_and_unsafe_key() {
    let other = eventbridge_event("other-bucket", "incoming/report.eml");
    assert!(matches!(
        created_intake_objects(&other, "example-intake-bucket"),
        Err(EventError::WrongBucket)
    ));
    let traversal = eventbridge_event("example-intake-bucket", "incoming/../secret.eml");
    assert!(matches!(
        created_intake_objects(&traversal, "example-intake-bucket"),
        Err(EventError::InvalidKey)
    ));
    let wrong_prefix = eventbridge_event("example-intake-bucket", "outgoing/secret.eml");
    assert!(matches!(
        created_intake_objects(&wrong_prefix, "example-intake-bucket"),
        Err(EventError::InvalidKey)
    ));
}

#[test]
fn eventbridge_ignores_non_creation_notifications_and_rejects_malformed_creates() {
    let mut tag_event = eventbridge_event("example-intake-bucket", "incoming/report.eml");
    tag_event["detail-type"] = json!("Object Tags Added");
    assert!(created_intake_objects(&tag_event, "example-intake-bucket")
        .unwrap()
        .is_empty());

    let mut malformed = eventbridge_event("example-intake-bucket", "incoming/report.eml");
    malformed["detail"]["object"] = json!({});
    assert!(matches!(
        created_intake_objects(&malformed, "example-intake-bucket"),
        Err(EventError::MalformedRecord)
    ));
}
