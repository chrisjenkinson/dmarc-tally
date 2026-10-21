//! AWS S3 intake reads and capture eligibility tagging.
//!
//! Raw MIME objects are transient. The caller must mark an object as captured
//! ONLY after core confirms every nested report was durably persisted.
//! Missing/unsupported inputs are retained; tagging failures are retryable.

use async_trait::async_trait;
use aws_sdk_s3::{
    types::{Tag, Tagging},
    Client,
};
use std::fmt;
use tokio::io::AsyncReadExt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3ObjectRef {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3StoreError {
    Unavailable(String),
    TooLarge,
    TooManyTags,
}

impl fmt::Display for S3StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "S3 intake operation unavailable: {message}"),
            Self::TooLarge => write!(f, "S3 intake object exceeds the allowed MIME size"),
            Self::TooManyTags => write!(f, "S3 object already has the maximum number of tags"),
        }
    }
}
impl std::error::Error for S3StoreError {}

/// S3-specific port for testing the thin Lambda orchestration without AWS
/// credentials. Core is completely unaware of this trait and its references.
#[async_trait]
pub trait S3EmailStore: Send + Sync {
    async fn read_email(
        &self,
        object: &S3ObjectRef,
        max_bytes: usize,
    ) -> Result<Vec<u8>, S3StoreError>;
    async fn mark_captured(&self, object: &S3ObjectRef) -> Result<(), S3StoreError>;
}

#[derive(Clone)]
pub struct AwsS3EmailStore {
    client: Client,
}

impl AwsS3EmailStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

/// Produce a complete S3 tag set without deleting unrelated tags, and never
/// create two \`captured\` keys. The lifecycle policy matches captured=true.
pub fn capture_tags(existing: &[Tag]) -> Result<Vec<Tag>, S3StoreError> {
    let mut tags: Vec<Tag> = existing
        .iter()
        .filter(|tag| tag.key() != "captured")
        .cloned()
        .collect();
    if tags.len() >= 10 {
        return Err(S3StoreError::TooManyTags);
    }
    let capture = Tag::builder()
        .key("captured")
        .value("true")
        .build()
        .map_err(|error| S3StoreError::Unavailable(format!("Invalid S3 capture tag: {error}")))?;
    tags.push(capture);
    Ok(tags)
}

#[async_trait]
impl S3EmailStore for AwsS3EmailStore {
    async fn read_email(
        &self,
        object: &S3ObjectRef,
        max_bytes: usize,
    ) -> Result<Vec<u8>, S3StoreError> {
        let result = self
            .client
            .get_object()
            .bucket(&object.bucket)
            .key(&object.key)
            .set_version_id(object.version_id.clone())
            .send()
            .await
            .map_err(|error| S3StoreError::Unavailable(format!("GetObject: {error}")))?;
        if result
            .content_length()
            .is_some_and(|len| len > max_bytes as i64)
        {
            return Err(S3StoreError::TooLarge);
        }
        // A streaming bound protects Lambda memory even if the length is not
        // supplied. Never collect an unbounded S3 stream into memory.
        let mut reader = result.body.into_async_read().take(max_bytes as u64 + 1);
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| S3StoreError::Unavailable(format!("ReadObject: {error}")))?;
        if bytes.len() > max_bytes {
            return Err(S3StoreError::TooLarge);
        }
        Ok(bytes)
    }

    async fn mark_captured(&self, object: &S3ObjectRef) -> Result<(), S3StoreError> {
        // PUT tagging replaces all tags, so always merge rather than discarding
        // pre-existing tags. A retried call is harmless when already captured.
        let existing = self
            .client
            .get_object_tagging()
            .bucket(&object.bucket)
            .key(&object.key)
            .set_version_id(object.version_id.clone())
            .send()
            .await
            .map_err(|error| S3StoreError::Unavailable(format!("GetObjectTagging: {error}")))?;
        if existing
            .tag_set()
            .iter()
            .any(|tag| tag.key() == "captured" && tag.value() == "true")
        {
            return Ok(());
        }
        let tags = capture_tags(existing.tag_set())?;
        let tagging = Tagging::builder()
            .set_tag_set(Some(tags))
            .build()
            .map_err(|error| S3StoreError::Unavailable(format!("Invalid S3 tag set: {error}")))?;
        self.client
            .put_object_tagging()
            .bucket(&object.bucket)
            .key(&object.key)
            .set_version_id(object.version_id.clone())
            .tagging(tagging)
            .send()
            .await
            .map_err(|error| S3StoreError::Unavailable(format!("PutObjectTagging: {error}")))?;
        Ok(())
    }
}
