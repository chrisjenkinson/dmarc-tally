//! Lossless representations of recognised DMARC aggregate-report fields.
//!
//! All recognised fields are retained in their structured \`raw\` nodes,
//! including optional children and repeated authentication results. Unknown
//! extensions are also preserved and explicitly marked so their source email
//! is never considered eligible for automatic deletion.

use std::fmt;
use serde::{Deserialize, Serialize};

/// An input safety limit, independent of Lambda memory or timeout settings.
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    pub max_xml_bytes: usize,
    pub max_nodes: u32,
    pub max_depth: usize,
    pub max_records: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_xml_bytes: 16 * 1024 * 1024,
            max_nodes: 200_000,
            max_depth: 64,
            max_records: 10_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmarcFormat {
    Rfc7489,
    Rfc9990,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlAttribute {
    pub name: String,
    pub namespace: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlNode {
    pub name: String,
    pub namespace: Option<String>,
    pub attributes: Vec<XmlAttribute>,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// Find one immediate child text value, without flattening other fields.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.children
            .iter()
            .find(|node| node.name == name)
            .map(|node| node.text.trim())
    }

    pub fn named_children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |node| node.name == name)
    }
}

/// A field not recognised by the corresponding DMARC version's vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownField {
    pub path: String,
    pub namespace: Option<String>,
    pub attribute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateRange {
    pub begin: i64,
    pub end: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub report_id: String,
    pub date_range: DateRange,
    pub error: Vec<String>,
    pub generator: Option<String>,
    pub raw: XmlNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedPolicy {
    pub domain: String,
    pub raw: XmlNode,
}

impl PublishedPolicy {
    pub fn value(&self, field: &str) -> Option<&str> {
        self.raw.value(field)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    pub reasons: Vec<XmlNode>,
    pub raw: XmlNode,
}

impl PolicyEvaluated {
    pub fn value(&self, field: &str) -> Option<&str> {
        self.raw.value(field)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: u64,
    pub evaluated: PolicyEvaluated,
    pub dkim_results: Vec<XmlNode>,
    pub spf_results: Vec<XmlNode>,
    pub raw: XmlNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedReport {
    pub metadata: ReportMetadata,
    pub published_policy: PublishedPolicy,
    pub records: Vec<DmarcRecord>,
    pub unknown_fields: Vec<UnknownField>,
    pub format_version: DmarcFormat,
}

impl ParsedReport {
    /// An email containing this report may be deleted only when this is true
    /// AND all reports in its MIME envelope were durably persisted.
    pub fn has_complete_field_coverage(&self) -> bool {
        self.unknown_fields.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseError {
    InputTooLarge,
    TooManyNodes,
    TooDeep,
    TooManyRecords,
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => write!(formatter, "DMARC XML exceeds the configured size limit"),
            Self::TooManyNodes => write!(formatter, "DMARC XML exceeds the configured node limit"),
            Self::TooDeep => write!(formatter, "DMARC XML exceeds the configured nesting limit"),
            Self::TooManyRecords => {
                write!(formatter, "DMARC XML exceeds the configured record limit")
            }
            Self::Malformed(message) => write!(formatter, "Malformed DMARC XML: {message}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, PartialEq, Eq)]
pub enum DateRangeError {
    UnsupportedWindow(u8),
}

impl std::fmt::Display for DateRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedWindow(days) => write!(f, "Unsupported reporting window: {days} days"),
        }
    }
}
impl std::error::Error for DateRangeError {}

impl DateRange {
    /// Include report-period ends inside the preceding 7, 30 or 90 days.
    pub fn last_days(days: u8, now: time::OffsetDateTime) -> Result<Self, DateRangeError> {
        if !matches!(days, 7 | 30 | 90) {
            return Err(DateRangeError::UnsupportedWindow(days));
        }
        let end = now.unix_timestamp();
        Ok(Self {
            begin: end - i64::from(days) * 86_400,
            end,
        })
    }
}
