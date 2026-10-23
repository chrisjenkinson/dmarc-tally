//! Small, privacy-preserving proof that an S3 intake email was fully
//! persisted and tagged. Neither its identity nor MIME is ever recorded.
//! The marker is NOT proof that an email arrived through SES.

use aws_sdk_s3::{primitives::ByteStream, Client};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

const MARKER: &str = "setup/last-captured.json";
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
    use super::{classify, ProcessingEvidence};
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
