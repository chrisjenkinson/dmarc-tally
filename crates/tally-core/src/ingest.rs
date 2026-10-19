//! Provider-neutral import use case: complete MIME bytes to structured reports.
//!
//! Transport acknowledgements, intake storage keys and S3 capture tags are
//! deliberately outside the core. Callers may delete an original only when
//! \`ImportOutcome::fully_captured\` and their own writes are durable.

use std::fmt;
use crate::identity::{report_identity, DomainSet, StoredReport};
use crate::mail::{extract_dmarc_documents, MailError, MailLimits};
use crate::model::{ParseError, ParseLimits};
use crate::ports::{PersistOutcome, ReportRepository, StoreError};
use crate::xml::parse_dmarc_xml;

#[derive(Debug, Clone, Copy)]
pub struct IngestLimits {
    pub mail: MailLimits,
    pub xml: ParseLimits,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self { mail: MailLimits::default(), xml: ParseLimits::default() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedReason {
    UnknownFields { report_id: String, count: usize },
    InvalidReport { path: String, error: String },
    UnconfiguredDomain(String),
    ConflictingReport(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub documents_seen: usize,
    pub newly_completed: usize,
    pub previously_completed: usize,
    pub retained: Vec<RetainedReason>,
    pub fully_captured: bool,
}

#[derive(Debug)]
pub enum ImportError {
    Mail(MailError),
    Storage(StoreError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mail(e) => write!(f, "{e}"),
            Self::Storage(e) => write!(f, "Storage operation failed: {e}"),
        }
    }
}
impl std::error::Error for ImportError {}

impl From<MailError> for ImportError {
    fn from(value: MailError) -> Self { Self::Mail(value) }
}
impl From<StoreError> for ImportError {
    fn from(value: StoreError) -> Self { Self::Storage(value) }
}

/// All supported logical reports in a MIME email are processed independently.
/// Permanently unrecognised content keeps the *whole* source email from being
/// expired. Transient persistence errors propagate to trigger an event retry.
pub async fn import_email(
    mime_bytes: &[u8],
    domains: &DomainSet,
    reports: &dyn ReportRepository,
    limits: &IngestLimits,
) -> Result<ImportOutcome, ImportError> {
    let extracted = extract_dmarc_documents(mime_bytes, &limits.mail)?;
    let mut outcome = ImportOutcome {
        documents_seen: extracted.xml_documents.len(),
        newly_completed: 0,
        previously_completed: 0,
        retained: Vec::new(),
        fully_captured: false,
    };

    for document in extracted.xml_documents {
        let parsed = match parse_dmarc_xml(&document.xml, &limits.xml) {
            Ok(parsed) => parsed,
            Err(error) => {
                outcome.retained.push(RetainedReason::InvalidReport {
                    path: document.origin_path,
                    error: concise_parse_error(error),
                });
                continue;
            }
        };

        let identity = report_identity(&parsed);
        if !domains.contains(&identity.domain) {
            outcome.retained.push(RetainedReason::UnconfiguredDomain(
                identity.domain.as_str().to_owned(),
            ));
            continue;
        }

        let unrecognised = parsed.unknown_fields.len();
        let stored = StoredReport::from_parsed(parsed, env!("CARGO_PKG_VERSION"));
        match reports.persist_report(&stored).await? {
            PersistOutcome::NewlyCompleted => outcome.newly_completed += 1,
            PersistOutcome::PreviouslyCompleted => outcome.previously_completed += 1,
            PersistOutcome::CompletedWithUnknownFields => {}
            PersistOutcome::Conflict => {
                outcome.retained.push(RetainedReason::ConflictingReport(identity.digest_hex()));
            }
        }

        if unrecognised != 0 {
            outcome.retained.push(RetainedReason::UnknownFields {
                report_id: identity.report_id,
                count: unrecognised,
            });
        }
    }

    outcome.fully_captured = outcome.retained.is_empty();
    Ok(outcome)
}

fn concise_parse_error(error: ParseError) -> String {
    // The parser errors contain structural details but no source content.
    // Avoid storing or logging raw XML or attacker-controlled message bodies.
    match error {
        ParseError::Malformed(_) => "Unparseable DMARC XML".into(),
        ParseError::InputTooLarge => "Report too large".into(),
        ParseError::TooDeep => "Report too deeply nested".into(),
        ParseError::TooManyRecords => "Too many records".into(),
        ParseError::TooManyNodes => "Too many XML nodes".into(),
    }
}
