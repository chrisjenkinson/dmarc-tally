//! Read-only aggregation over complete, persisted DMARC reports.
//!
//! Nothing in this module assumes a database, provider, HTTP framework,
//! or email-delivery implementation.

use std::collections::BTreeMap;
use crate::identity::StoredReport;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub messages: u64,
    pub passed: u64,
    pub failed: u64,
}

impl Traffic {
    fn observe(&mut self, count: u64, pass: bool) {
        self.messages = self.messages.saturating_add(count);
        if pass {
            self.passed = self.passed.saturating_add(count);
        } else {
            self.failed = self.failed.saturating_add(count);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub reports: u64,
    pub messages: u64,
    pub passed: u64,
    pub failed: u64,
    pub by_ip: BTreeMap<String, Traffic>,
    pub by_reporter: BTreeMap<String, Traffic>,
    pub dispositions: BTreeMap<String, u64>,
}

/// Calculate report and record totals; a pass requires at least one aligned
/// DKIM or SPF result, not both. A "none" disposition does not imply pass.
/// Incoming reports count observations, not the total number of sent emails.
pub fn summarise<I>(reports: I) -> Summary
where
    I: IntoIterator<Item = StoredReport>,
{
    let mut summary = Summary::default();
    for stored in reports {
        summary.reports += 1;
        for record in stored.report.records {
            let passed = record.evaluated.value("dkim") == Some("pass")
                || record.evaluated.value("spf") == Some("pass");
            summary.messages = summary.messages.saturating_add(record.count);
            if passed {
                summary.passed = summary.passed.saturating_add(record.count);
            } else {
                summary.failed = summary.failed.saturating_add(record.count);
            }

            summary.by_ip.entry(record.source_ip.clone())
                .or_default().observe(record.count, passed);
            summary.by_reporter.entry(stored.identity.organisation.clone())
                .or_default().observe(record.count, passed);
            let disposition = record.evaluated.value("disposition")
                .unwrap_or("unknown").to_ascii_lowercase();
            let accumulated = summary.dispositions.entry(disposition).or_default();
            *accumulated = accumulated.saturating_add(record.count);
        }
    }
    summary
}
