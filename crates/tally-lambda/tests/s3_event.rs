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
        created_intake_objects(&s3_event("other-bucket", "incoming%2Freport.eml"), "example-intake-bucket"),
        Err(EventError::WrongBucket)
    ));
    assert!(created_intake_objects(&s3_event("example-intake-bucket", "outgoing%2Fsecret.eml"), "example-intake-bucket").is_err());
    assert!(created_intake_objects(&s3_event("example-intake-bucket", "incoming%2F..%2Fsecret"), "example-intake-bucket").is_err());
    assert!(created_intake_objects(&s3_event("example-intake-bucket", "incoming%2Fbad%XX"), "example-intake-bucket").is_err());
}

#[test]
fn rejects_malformed_event_instead_of_acknowledging_it() {
    assert!(created_intake_objects(&json!({"Records":[{"eventName":"ObjectCreated:Put"}]}), "example-intake-bucket").is_err());
    assert!(created_intake_objects(&json!({}), "example-intake-bucket").is_err());
}
