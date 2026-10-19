//! Provider-neutral application capabilities and an in-memory port adapter.
//!
//! No S3, DynamoDB or Lambda concepts enter this interface. Implementations
//! must offer idempotent completion and never expose incomplete report writes.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use crate::identity::{DomainName, ReportIdentity, StoredReport};
use crate::model::DateRange;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistOutcome {
    NewlyCompleted,
    PreviouslyCompleted,
    CompletedWithUnknownFields,
    Conflict,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Unavailable(String),
    Corrupt(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(v) | Self::Corrupt(v) => write!(f, "{v}"),
        }
    }
}
impl std::error::Error for StoreError {}

/// Query continuation state is opaque to the application and callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportPage {
    pub reports: Vec<StoredReport>,
    pub next_cursor: Option<Cursor>,
}

#[async_trait]
pub trait ReportRepository: Send + Sync {
    /// Persist a logical report without double counting identical deliveries.
    /// A conflict must never replace an existing completed report.
    async fn persist_report(&self, stored: &StoredReport) -> Result<PersistOutcome, StoreError>;

    /// Return only completed reports in the requested domain and reporting
    /// period end range. Adapter implementations may store incomplete writes
    /// internally, but callers never see them through these methods.
    async fn list_for_domain(
        &self,
        domain: &DomainName,
        range: DateRange,
        cursor: Option<Cursor>,
    ) -> Result<ReportPage, StoreError>;

    async fn get_report(
        &self,
        identity: &ReportIdentity,
    ) -> Result<Option<StoredReport>, StoreError>;
}

/// Reference implementation and test double; data is process-local only.
#[derive(Default)]
pub struct InMemoryReportRepository {
    completed: Mutex<BTreeMap<String, StoredReport>>,
}

#[async_trait]
impl ReportRepository for InMemoryReportRepository {
    async fn persist_report(&self, stored: &StoredReport) -> Result<PersistOutcome, StoreError> {
        let key = stored.identity.digest_hex();
        let mut reports = self.completed.lock().map_err(|_| {
            StoreError::Unavailable("Report repository lock poisoned".into())
        })?;
        if let Some(existing) = reports.get(&key) {
            return Ok(if existing.content_hash == stored.content_hash {
                PersistOutcome::PreviouslyCompleted
            } else {
                PersistOutcome::Conflict
            });
        }
        reports.insert(key, stored.clone());
        Ok(if stored.capture_complete {
            PersistOutcome::NewlyCompleted
        } else {
            PersistOutcome::CompletedWithUnknownFields
        })
    }

    async fn list_for_domain(
        &self,
        domain: &DomainName,
        range: DateRange,
        cursor: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        let reports = self.completed.lock().map_err(|_| {
            StoreError::Unavailable("Report repository lock poisoned".into())
        })?;
        let mut matching: Vec<_> = reports
            .values()
            .filter(|r| {
                &r.identity.domain == domain
                    && (range.begin..=range.end).contains(&r.identity.period_end)
            })
            .map(|report| {
                (
                    format!(
                        "{:020}/{}",
                        report.identity.period_end,
                        report.identity.digest_hex(),
                    ),
                    report,
                )
            })
            .collect();
        matching.sort_by(|left, right| left.0.cmp(&right.0));
        let after = cursor.as_ref().map(|cursor| cursor.0.as_str());
        let mut results = matching
            .into_iter()
            .filter(|(key, _)| after.map(|cursor| key.as_str() > cursor).unwrap_or(true))
            .take(101)
            .collect::<Vec<_>>();
        let next_cursor = if results.len() > 100 {
            results.truncate(100);
            results.last().map(|(key, _)| Cursor((*key).clone()))
        } else {
            None
        };
        Ok(ReportPage {
            reports: results.into_iter().map(|(_, r)| r.clone()).collect(),
            next_cursor,
        })
    }

    async fn get_report(
        &self,
        identity: &ReportIdentity,
    ) -> Result<Option<StoredReport>, StoreError> {
        Ok(self.completed.lock().map_err(|_| {
            StoreError::Unavailable("Report repository lock poisoned".into())
        })?.get(&identity.digest_hex()).cloned())
    }
}
