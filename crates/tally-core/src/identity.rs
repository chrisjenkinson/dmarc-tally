//! Stable logical DMARC report identities, complete records and configured domains.
//!
//! Report identities do not depend on MIME headers, receipt timestamps,
//! forwarding, or storage-provider details.

use crate::model::ParsedReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct DomainName(String);

impl DomainName {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let normalised = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalised.len() > 253
            || normalised.is_empty()
            || !normalised.contains('.')
            || normalised.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(DomainError(value.to_owned()));
        }
        Ok(Self(normalised))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError(pub String);

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid domain name: {}", self.0)
    }
}

impl std::error::Error for DomainError {}

#[derive(Clone, Debug)]
pub struct DomainSet(BTreeSet<DomainName>);

impl DomainSet {
    pub fn new<I, S>(domains: I) -> Result<Self, DomainError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set: BTreeSet<_> = domains
            .into_iter()
            .map(|domain| DomainName::parse(domain.as_ref()))
            .collect::<Result<_, _>>()?;
        if set.is_empty() {
            return Err(DomainError(
                "At least one monitored domain is required".into(),
            ));
        }
        Ok(Self(set))
    }

    pub fn domains(&self) -> &BTreeSet<DomainName> {
        &self.0
    }

    pub fn contains(&self, domain: &DomainName) -> bool {
        self.0.contains(domain)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ReportIdentity {
    pub domain: DomainName,
    pub organisation: String,
    pub report_id: String,
    pub period_start: i64,
    pub period_end: i64,
}

impl ReportIdentity {
    pub fn digest_hex(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [self.domain.as_str(), &self.organisation, &self.report_id] {
            update_string(&mut hasher, part);
        }
        hasher.update(self.period_start.to_be_bytes());
        hasher.update(self.period_end.to_be_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// A compact, source-independent direct-lookup reference. URL parts carry
/// only a monitored domain, report period end and the deterministic digest.
/// They do not expose raw MIME or DynamoDB keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportReference {
    pub domain: DomainName,
    pub period_end: i64,
    pub digest: String,
}

impl ReportReference {
    pub fn from_identity(identity: &ReportIdentity) -> Self {
        Self {
            domain: identity.domain.clone(),
            period_end: identity.period_end,
            digest: identity.digest_hex(),
        }
    }

    pub fn parse_path(path: &str) -> Option<Self> {
        let body = path.strip_prefix("/reports/")?;
        let mut fields = body.split('/');
        let (domain, end, digest) = (fields.next()?, fields.next()?, fields.next()?);
        if fields.next().is_some()
            || end.len() != 20
            || !end.bytes().all(|v| v.is_ascii_digit())
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return None;
        }
        let canonical = DomainName::parse(domain).ok()?;
        if canonical.as_str() != domain {
            return None;
        }
        let period_end = end.parse::<i64>().ok()?;
        Some(Self {
            domain: canonical,
            period_end,
            digest: digest.to_owned(),
        })
    }

    pub fn path(&self) -> String {
        format!(
            "/reports/{}/{:020}/{}",
            self.domain.as_str(),
            self.period_end,
            self.digest
        )
    }

    pub fn matches(&self, identity: &ReportIdentity) -> bool {
        self.domain == identity.domain
            && self.period_end == identity.period_end
            && self.digest == identity.digest_hex()
    }
}

fn update_string(hasher: &mut Sha256, data: &str) {
    hasher.update((data.len() as u64).to_be_bytes());
    hasher.update(data.as_bytes());
}

pub fn report_identity(report: &ParsedReport) -> ReportIdentity {
    // The XML parser requires a valid policy-domain field; domain allowlist
    // validation is performed before persistence by the ingestion use case.
    let normalised = report
        .published_policy
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    ReportIdentity {
        domain: DomainName(normalised),
        organisation: report.metadata.org_name.trim().to_ascii_lowercase(),
        report_id: report.metadata.report_id.trim().to_owned(),
        period_start: report.metadata.date_range.begin,
        period_end: report.metadata.date_range.end,
    }
}

/// Identical logical XML content hashes equally regardless of MIME envelope.
/// Preserves every recognised XML leaf, attribute and repeated authentication
/// result through serde's canonical field and Vec ordering. Content order is
/// retained, deliberately, because a reordered XML payload is not guaranteed
/// semantically equivalent.
pub fn report_content_hash(report: &ParsedReport) -> [u8; 32] {
    let content = serde_json::to_vec(report)
        .expect("serialising the trusted, owned DMARC report cannot fail");
    Sha256::digest(content).into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredReport {
    pub identity: ReportIdentity,
    pub content_hash: [u8; 32],
    pub report: ParsedReport,
    /// Version of the parser producing this representation.
    pub parser_version: String,
    /// Optional opaque, backend-independent reference to an input source.
    pub source_provenance: Option<String>,
    /// Structured fields were stored; \`false\` means original content must be retained.
    pub capture_complete: bool,
}

impl StoredReport {
    pub fn from_parsed(report: ParsedReport, parser_version: &str) -> Self {
        let identity = report_identity(&report);
        let content_hash = report_content_hash(&report);
        let capture_complete = report.has_complete_field_coverage();
        Self {
            identity,
            content_hash,
            report,
            parser_version: parser_version.to_owned(),
            source_provenance: None,
            capture_complete,
        }
    }
}

/// Numbering is deterministic within each logical report.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredRecord {
    pub ordinal: u32,
    pub full_record: crate::model::DmarcRecord,
}
