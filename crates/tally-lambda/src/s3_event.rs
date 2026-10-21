//! Translate S3 ObjectCreated events into validated AWS-only intake references.
//!
//! Object keys in S3 notifications use application/x-www-form-urlencoded rules:
//! "+" is a space and "%2B" is a literal plus. Decode once, reject malformed
//! encodings, and never let the event select an unrelated object or bucket.

use serde_json::Value;
use std::fmt;

const INTAKE_PREFIX: &str = "incoming/";

pub use tally_aws::s3::S3ObjectRef as IntakeObject;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventError {
    MissingRecords,
    MalformedRecord,
    WrongBucket,
    InvalidKey,
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRecords => write!(f, "Expected a nonempty S3 Records array"),
            Self::MalformedRecord => write!(f, "Malformed S3 event record"),
            Self::WrongBucket => write!(f, "S3 notification refers to another bucket"),
            Self::InvalidKey => write!(f, "S3 notification has an invalid intake object key"),
        }
    }
}

impl std::error::Error for EventError {}

/// A notification can hold more than one record. A failed record rejects the
/// whole invocation, so AWS retries the batch and idempotent report storage
/// prevents duplicates. Non-creation S3 notifications are simply ignored.
pub fn created_intake_objects(
    event: &Value,
    expected_bucket: &str,
) -> Result<Vec<IntakeObject>, EventError> {
    if expected_bucket.is_empty() {
        return Err(EventError::WrongBucket);
    }
    let records = event
        .get("Records")
        .and_then(Value::as_array)
        .filter(|records| !records.is_empty())
        .ok_or(EventError::MissingRecords)?;
    let mut objects = Vec::new();
    for record in records {
        if record.get("eventSource").and_then(Value::as_str) != Some("aws:s3") {
            return Err(EventError::MalformedRecord);
        }
        let kind = record
            .get("eventName")
            .and_then(Value::as_str)
            .ok_or(EventError::MalformedRecord)?;
        if !kind.starts_with("ObjectCreated:") {
            continue;
        }
        let s3 = record.get("s3").ok_or(EventError::MalformedRecord)?;
        let bucket = s3
            .pointer("/bucket/name")
            .and_then(Value::as_str)
            .ok_or(EventError::MalformedRecord)?;
        if bucket != expected_bucket {
            return Err(EventError::WrongBucket);
        }
        let encoded_key = s3
            .pointer("/object/key")
            .and_then(Value::as_str)
            .ok_or(EventError::MalformedRecord)?;
        let key = decode_form_key(encoded_key)?;
        if !key.starts_with(INTAKE_PREFIX)
            || key.len() <= INTAKE_PREFIX.len()
            || key[INTAKE_PREFIX.len()..]
                .split('/')
                .any(|segment| segment.is_empty() || segment == "." || segment == "..")
            || key.bytes().any(|ch| ch == 0 || ch == b'\\')
        {
            return Err(EventError::InvalidKey);
        }
        let version_id = s3
            .pointer("/object/versionId")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .map(str::to_owned);
        objects.push(IntakeObject {
            bucket: bucket.to_owned(),
            key,
            version_id,
        });
    }
    Ok(objects)
}

fn decode_form_key(key: &str) -> Result<String, EventError> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let input = key.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => output.push(b' '),
            b'%' => {
                if i + 2 >= input.len() {
                    return Err(EventError::InvalidKey);
                }
                let high = hex(input[i + 1]).ok_or(EventError::InvalidKey)?;
                let low = hex(input[i + 2]).ok_or(EventError::InvalidKey)?;
                output.push((high << 4) | low);
                i += 2;
            }
            other => output.push(other),
        }
        i += 1;
    }
    String::from_utf8(output).map_err(|_| EventError::InvalidKey)
}
