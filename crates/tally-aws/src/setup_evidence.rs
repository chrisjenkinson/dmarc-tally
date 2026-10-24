//! Small, privacy-preserving proof that an S3 intake email was fully
//! persisted and tagged. Neither its identity nor MIME is ever recorded.
//! The marker is NOT proof that an email arrived through SES.

use aws_sdk_s3::{primitives::ByteStream, Client};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

const MARKER: &str = "setup/last-captured.json";
const DELIVERY_MARKER: &str = "setup/end-to-end-confirmed.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryEvidence {
    OperatorConfirmed,
    NotVerified,
    UnableToCheck,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryConfirmation {
    version: u8,
    verified_at: i64,
    observed_at: i64,
}

fn classify_delivery(input: &[u8], now: i64) -> DeliveryEvidence {
    let Ok(record) = serde_json::from_slice::<DeliveryConfirmation>(input) else {
        return DeliveryEvidence::UnableToCheck;
    };
    if record.version != 1
        || record.observed_at <= 0
        || record.verified_at < record.observed_at
        || record.verified_at > now + 300
    {
        return DeliveryEvidence::UnableToCheck;
    }
    DeliveryEvidence::OperatorConfirmed
}

const MAX_BYTES: usize = 256;
const RECENT_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessingEvidence {
    Recent,
    Old,
    NotObserved,
    UnableToCheck,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    processed_at: i64,
}

fn classify(input: &[u8], now: i64) -> ProcessingEvidence {
    let Ok(marker) = serde_json::from_slice::<Marker>(input) else {
        return ProcessingEvidence::UnableToCheck;
    };
    if marker.version != 1 || marker.processed_at <= 0 || marker.processed_at > now + 300 {
        return ProcessingEvidence::UnableToCheck;
    }
    if now - marker.processed_at <= RECENT_SECONDS {
        ProcessingEvidence::Recent
    } else {
        ProcessingEvidence::Old
    }
}

fn epoch_now() -> Result<i64, &'static str> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Invalid system clock")?
            .as_secs(),
    )
    .map_err(|_| "Invalid system clock")
}

#[derive(Clone)]
pub struct ProcessingEvidenceStore {
    client: Client,
}

impl ProcessingEvidenceStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Called strictly after capture tagging. Failure retries idempotently.
    pub async fn record_success(&self, bucket: &str) -> Result<(), &'static str> {
        let marker = Marker {
            version: 1,
            processed_at: epoch_now()?,
        };
        let bytes = serde_json::to_vec(&marker).map_err(|_| "Evidence encoding failed")?;
        self.client
            .put_object()
            .bucket(bucket)
            .key(MARKER)
            .content_type("application/json")
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|_| "Could not write private ingestion evidence")?;
        Ok(())
    }

    /// S3 may conceal a missing GetObject key with HTTP 403 when this
    /// Lambda cannot list the bucket. On that one response only, check
    /// existence by a one-result prefix listing of exactly this marker.
    /// IAM restricts the list to these two named setup objects.
    async fn marker_is_absent(&self, bucket: &str, marker: &str) -> bool {
        self.client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(marker)
            .max_keys(1)
            .send()
            .await
            .is_ok_and(|page| page.contents().iter().all(|item| item.key() != Some(marker)))
    }

    /// A separate, explicit operator attestation of one controlled delivery
    /// test, not a claim of cryptographic SES object provenance.
    pub async fn inspect_delivery(&self, bucket: &str) -> DeliveryEvidence {
        let output = match self
            .client
            .get_object()
            .bucket(bucket)
            .key(DELIVERY_MARKER)
            .send()
            .await
        {
            Ok(value) => value,
            Err(error) => {
                if error.as_service_error().is_some_and(|e| e.is_no_such_key())
                    || (error.raw_response().is_some_and(|response| response.status().as_u16() == 403)
                        && self.marker_is_absent(bucket, DELIVERY_MARKER).await)
                {
                    return DeliveryEvidence::NotVerified;
                }
                return DeliveryEvidence::UnableToCheck;
            }
        };
        if output
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as i64)
        {
            return DeliveryEvidence::UnableToCheck;
        }
        let mut reader = output.body.into_async_read().take(MAX_BYTES as u64 + 1);
        let mut bytes = Vec::new();
        if reader.read_to_end(&mut bytes).await.is_err() || bytes.len() > MAX_BYTES {
            return DeliveryEvidence::UnableToCheck;
        }
        match epoch_now() {
            Ok(now) => classify_delivery(&bytes, now),
            Err(_) => DeliveryEvidence::UnableToCheck,
        }
    }

    pub async fn inspect(&self, bucket: &str) -> ProcessingEvidence {
        let result = self
            .client
            .get_object()
            .bucket(bucket)
            .key(MARKER)
            .send()
            .await;
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_no_such_key())
                {
                    return ProcessingEvidence::NotObserved;
                }
                if error.raw_response().is_some_and(|response| response.status().as_u16() == 403)
                    && self.marker_is_absent(bucket, MARKER).await
                {
                    return ProcessingEvidence::NotObserved;
                }
                return ProcessingEvidence::UnableToCheck;
            }
        };
        if output
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as i64)
        {
            return ProcessingEvidence::UnableToCheck;
        }
        let mut reader = output.body.into_async_read().take(MAX_BYTES as u64 + 1);
        let mut bytes = Vec::new();
        if reader.read_to_end(&mut bytes).await.is_err() || bytes.len() > MAX_BYTES {
            return ProcessingEvidence::UnableToCheck;
        }
        let Ok(now) = epoch_now() else {
            return ProcessingEvidence::UnableToCheck;
        };
        classify(&bytes, now)
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, classify_delivery, DeliveryEvidence, ProcessingEvidence};
    #[test]
    fn explicit_operator_attestation_must_be_valid() {
        assert_eq!(
            classify_delivery(br#"{"version":1,"observed_at":100,"verified_at":200}"#, 210),
            DeliveryEvidence::OperatorConfirmed
        );
        assert_eq!(
            classify_delivery(br#"{"version":1,"observed_at":300,"verified_at":200}"#, 210),
            DeliveryEvidence::UnableToCheck
        );
        assert_eq!(
            classify_delivery(b"{}", 210),
            DeliveryEvidence::UnableToCheck
        );
    }

    #[test]
    fn real_recent_marker_is_needed_to_show_ready() {
        assert_eq!(
            classify(br#"{"version":1,"processed_at":100}"#, 101),
            ProcessingEvidence::Recent
        );
        assert_eq!(
            classify(br#"{"version":1,"processed_at":100}"#, 800000),
            ProcessingEvidence::Old
        );
        assert_eq!(
            classify(br#"{"version":1,"processed_at":500}"#, 100),
            ProcessingEvidence::UnableToCheck
        );
        assert_eq!(
            classify(br#"{"version":2,"processed_at":100}"#, 101),
            ProcessingEvidence::UnableToCheck
        );
        assert_eq!(classify(br#"{}"#, 101), ProcessingEvidence::UnableToCheck);
    }
}
