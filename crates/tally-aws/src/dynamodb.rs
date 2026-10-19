//! DynamoDB item layout and lossless conversion for portable report types.
//!
//! There is one metadata item and one item for each XML \`record\`; a large
//! report must never be packed into one DynamoDB item.

use serde::{Deserialize, Serialize};
use std::fmt;
use tally_core::identity::{ReportIdentity, StoredRecord, StoredReport};

/// Conservative size ceiling allowing room for DynamoDB attributes and keys.
const MAX_VALUE_BYTES: usize = 350 * 1024;

#[derive(Debug)]
pub enum DynamoModelError {
    TooLarge,
    InvalidRecord(String),
}

impl fmt::Display for DynamoModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "Structured DMARC item exceeds DynamoDB size budget"),
            Self::InvalidRecord(message) => write!(f, "Invalid stored DMARC record: {message}"),
        }
    }
}
impl std::error::Error for DynamoModelError {}

#[derive(Debug, Clone)]
pub struct DynamoKeys {
    pub partition: String,
    pub metadata: String,
    prefix: String,
}

impl DynamoKeys {
    pub fn from_identity(identity: &ReportIdentity) -> Self {
        let prefix = format!(
            "END#{:020}#REPORT#{}#",
            identity.period_end,
            identity.digest_hex(),
        );
        Self {
            partition: format!("DOMAIN#{}", identity.domain.as_str()),
            metadata: format!("{prefix}META"),
            prefix,
        }
    }

    pub fn record_sort_key(&self, ordinal: u32) -> String {
        format!("{}REC#{ordinal:08}", self.prefix)
    }

    pub fn record_prefix(&self) -> String {
        format!("{}REC#", self.prefix)
    }

    pub fn query_start(timestamp: i64) -> String {
        format!("END#{timestamp:020}")
    }

    pub fn query_end(timestamp: i64) -> String {
        format!("END#{timestamp:020}~")
    }
}

#[derive(Serialize, Deserialize)]
struct MetaDocument {
    stored: StoredReport,
    record_count: usize,
}

/// Store full metadata, policy and extensions without duplicating records.
pub fn encode_meta(report: &StoredReport) -> Result<String, DynamoModelError> {
    let mut copy = report.clone();
    let record_count = copy.report.records.len();
    copy.report.records.clear();
    serialise(&MetaDocument {
        stored: copy,
        record_count,
    })
}

pub fn encode_record(record: &StoredRecord) -> Result<String, DynamoModelError> {
    serialise(record)
}

fn serialise<T: Serialize>(value: &T) -> Result<String, DynamoModelError> {
    let json = serde_json::to_string(value)
        .map_err(|e| DynamoModelError::InvalidRecord(e.to_string()))?;
    if json.len() > MAX_VALUE_BYTES {
        return Err(DynamoModelError::TooLarge);
    }
    Ok(json)
}

/// The reader rejects missing, duplicated or reordered records and payload
/// tampering, rather than pretending an incomplete report is finished.
pub fn decode_report(
    metadata: &str,
    records: &[String],
) -> Result<StoredReport, DynamoModelError> {
    let mut meta: MetaDocument = serde_json::from_str(metadata)
        .map_err(|e| DynamoModelError::InvalidRecord(e.to_string()))?;
    if records.len() != meta.record_count {
        return Err(DynamoModelError::InvalidRecord("Wrong record count".into()));
    }
    let mut parsed = records.iter()
        .map(|json| serde_json::from_str::<StoredRecord>(json)
            .map_err(|e| DynamoModelError::InvalidRecord(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort_by_key(|r| r.ordinal);
    for (index, record) in parsed.iter().enumerate() {
        if record.ordinal as usize != index {
            return Err(DynamoModelError::InvalidRecord("Missing or repeated record ordinal".into()));
        }
    }
    meta.stored.report.records = parsed.into_iter().map(|entry| entry.full_record).collect();
    if tally_core::identity::report_content_hash(&meta.stored.report) != meta.stored.content_hash {
        return Err(DynamoModelError::InvalidRecord("Content hash mismatch".into()));
    }
    Ok(meta.stored)
}

// Implementation details remain AWS-only; callers use the core port.
pub use crate::dynamo_repository::DynamoReportRepository;
