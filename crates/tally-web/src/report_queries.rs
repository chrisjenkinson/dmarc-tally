//! Provider-independent report query application for an authenticated web host.
//!
//! This module never authenticates an HTTP request. The eventual HTTP adapter
//! must verify the current administrator's session BEFORE calling it.
//! Unauthenticated endpoints must not expose query results or report metadata.

use std::collections::BTreeSet;
use std::fmt;

use tally_core::{
    identity::{DomainName, DomainSet},
    model::DateRange,
    ports::{Cursor, ReportRepository, StoreError},
    reporting::{summarise, Summary, Traffic},
};

use crate::pages::ReportViewModel;

const MAX_QUERY_BYTES: usize = 2_048;
const MAX_PAGES_PER_DOMAIN: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverviewSelection {
    /// None means all configured domains, not all domains in the database.
    pub selected_domain: Option<DomainName>,
    pub days: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionError {
    MalformedQuery,
    InvalidPeriod,
    UnconfiguredDomain,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedQuery => write!(f, "Invalid report filter"),
            Self::InvalidPeriod => write!(f, "Reporting period must be 7, 30 or 90 days"),
            Self::UnconfiguredDomain => write!(f, "Domain is not configured for reporting"),
        }
    }
}
impl std::error::Error for SelectionError {}

impl OverviewSelection {
    /// Parse just the query string (without the leading URL path).
    /// The accepted URL parameter names are deliberately only domain/days.
    pub fn parse(query: &str, monitored: &DomainSet) -> Result<Self, SelectionError> {
        let query = query.strip_prefix('?').unwrap_or(query);
        if query.len() > MAX_QUERY_BYTES || !valid_percent_escapes(query) {
            return Err(SelectionError::MalformedQuery);
        }

        let mut selected_domain = None;
        let mut seen_domain = false;
        let mut days = None;

        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            match name.as_ref() {
                "domain" if !seen_domain => {
                    seen_domain = true;
                    if value != "all" {
                        let domain = DomainName::parse(&value)
                            .map_err(|_| SelectionError::UnconfiguredDomain)?;
                        if !monitored.contains(&domain) {
                            return Err(SelectionError::UnconfiguredDomain);
                        }
                        selected_domain = Some(domain);
                    }
                }
                "days" if days.is_none() => {
                    days = Some(match value.as_ref() {
                        "7" => 7,
                        "30" => 30,
                        "90" => 90,
                        _ => return Err(SelectionError::InvalidPeriod),
                    });
                }
                _ => return Err(SelectionError::MalformedQuery),
            }
        }

        Ok(Self {
            selected_domain,
            days: days.unwrap_or(30),
        })
    }
}

fn valid_percent_escapes(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

#[derive(Debug)]
pub enum OverviewError {
    InvalidSelection,
    Storage(StoreError),
    PaginationLoop,
    PaginationLimit,
}

impl fmt::Display for OverviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelection => write!(f, "Report selection is no longer valid"),
            Self::Storage(_) => write!(f, "Report data is temporarily unavailable"),
            Self::PaginationLoop => write!(f, "Report query cursor did not advance"),
            Self::PaginationLimit => write!(f, "Report query exceeded its page limit"),
        }
    }
}
impl std::error::Error for OverviewError {}

impl From<StoreError> for OverviewError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

/// Query complete, persisted report pages for an already-authenticated user.
/// A repository failure or incomplete pagination propagates as an error: a
/// report overview must never silently present an incomplete total.
pub async fn load_overview(
    repository: &dyn ReportRepository,
    monitored: &DomainSet,
    selection: &OverviewSelection,
    now_epoch_seconds: i64,
) -> Result<ReportViewModel, OverviewError> {
    if !matches!(selection.days, 7 | 30 | 90)
        || selection
            .selected_domain
            .as_ref()
            .is_some_and(|domain| !monitored.contains(domain))
    {
        return Err(OverviewError::InvalidSelection);
    }

    let range = DateRange {
        begin: now_epoch_seconds.saturating_sub(i64::from(selection.days) * 86_400),
        end: now_epoch_seconds,
    };
    let domains: Vec<DomainName> = match &selection.selected_domain {
        Some(domain) => vec![domain.clone()],
        None => monitored.domains().iter().cloned().collect(),
    };
    let mut summary = Summary::default();

    for domain in domains {
        let mut cursor: Option<Cursor> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut exhausted = false;

        for _ in 0..MAX_PAGES_PER_DOMAIN {
            let page = repository
                .list_for_domain(&domain, range.clone(), cursor)
                .await?;
            merge_summary(&mut summary, summarise(page.reports));

            match page.next_cursor {
                Some(next) => {
                    if !seen_cursors.insert(next.0.clone()) {
                        return Err(OverviewError::PaginationLoop);
                    }
                    cursor = Some(next);
                }
                None => {
                    exhausted = true;
                    break;
                }
            }
        }
        if !exhausted {
            return Err(OverviewError::PaginationLimit);
        }
    }

    Ok(ReportViewModel {
        selected_domain: selection.selected_domain.clone(),
        configured_domains: monitored.domains().iter().cloned().collect(),
        days: selection.days,
        summary,
    })
}

fn merge_traffic(acc: &mut Traffic, next: Traffic) {
    acc.messages = acc.messages.saturating_add(next.messages);
    acc.passed = acc.passed.saturating_add(next.passed);
    acc.failed = acc.failed.saturating_add(next.failed);
}

fn merge_summary(acc: &mut Summary, next: Summary) {
    acc.reports = acc.reports.saturating_add(next.reports);
    acc.messages = acc.messages.saturating_add(next.messages);
    acc.passed = acc.passed.saturating_add(next.passed);
    acc.failed = acc.failed.saturating_add(next.failed);
    for (ip, traffic) in next.by_ip {
        merge_traffic(acc.by_ip.entry(ip).or_default(), traffic);
    }
    for (reporter, traffic) in next.by_reporter {
        merge_traffic(acc.by_reporter.entry(reporter).or_default(), traffic);
    }
    for (disposition, count) in next.dispositions {
        let total = acc.dispositions.entry(disposition).or_default();
        *total = total.saturating_add(count);
    }
}
