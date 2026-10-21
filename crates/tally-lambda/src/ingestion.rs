//! Thin coordination of AWS S3 intake with portable DMARC ingestion.
//!
//! AWS's asynchronous S3/Lambda invocation may retry. Only fully persisted
//! emails are tagged; all incomplete/malformed inputs remain untagged, while
//! transient AWS/repository errors bubble up so Lambda can retry the event.

use std::fmt;

use tally_aws::s3::{S3EmailStore, S3ObjectRef, S3StoreError};
use tally_core::{
    identity::DomainSet,
    ingest::{import_email, ImportError, ImportOutcome, IngestLimits},
    ports::ReportRepository,
};

#[derive(Debug)]
pub enum RetainedInput {
    /// At least one logical report was incomplete, unsupported or in conflict.
    Incomplete(ImportOutcome),
    /// MIME decoding or compressed-report extraction was not understood.
    Unsupported,
    /// The email exceeds the safe size limit; the original remains for review.
    TooLarge,
}

#[derive(Debug)]
pub enum ProcessingOutcome {
    Captured(ImportOutcome),
    Retained(RetainedInput),
}

#[derive(Debug)]
pub enum ProcessingError {
    S3(S3StoreError),
    Database(tally_core::ports::StoreError),
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S3(_) => write!(f, "S3 intake operation failed"),
            Self::Database(_) => write!(f, "Report repository operation failed"),
        }
    }
}
impl std::error::Error for ProcessingError {}

/// Import the original email and tag only after the *whole email* is
/// verified complete. A later replay (including after tag failure) is safe:
/// the repository is idempotent and tagging itself is repeatable.
pub async fn ingest_s3_object(
    object: &S3ObjectRef,
    s3: &dyn S3EmailStore,
    reports: &dyn ReportRepository,
    domains: &DomainSet,
    limits: &IngestLimits,
) -> Result<ProcessingOutcome, ProcessingError> {
    let message = match s3.read_email(object, limits.mail.max_message_bytes).await {
        Ok(message) => message,
        Err(S3StoreError::TooLarge) => {
            return Ok(ProcessingOutcome::Retained(RetainedInput::TooLarge))
        }
        Err(error) => return Err(ProcessingError::S3(error)),
    };
    let imported = match import_email(&message, domains, reports, limits).await {
        Ok(result) => result,
        Err(ImportError::Mail(_)) => {
            return Ok(ProcessingOutcome::Retained(RetainedInput::Unsupported));
        }
        Err(ImportError::Storage(error)) => return Err(ProcessingError::Database(error)),
    };
    if !imported.fully_captured {
        return Ok(ProcessingOutcome::Retained(RetainedInput::Incomplete(
            imported,
        )));
    }
    s3.mark_captured(object)
        .await
        .map_err(ProcessingError::S3)?;
    Ok(ProcessingOutcome::Captured(imported))
}
