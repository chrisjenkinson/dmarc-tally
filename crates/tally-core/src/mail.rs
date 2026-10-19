//! Bounded extraction of DMARC aggregate XML from MIME attachments.
//!
//! The same entry point handles direct reports and batches of attached
//! original messages forwarded by an email client. Unknown DMARC-like
//! attachments are never silently marked as fully captured.

use flate2::read::MultiGzDecoder;
use mailparse::{parse_mail, ParsedMail};
use std::fmt;
use std::io::{Cursor, Read};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy)]
pub struct MailLimits {
    pub max_message_bytes: usize,
    pub max_nesting_depth: usize,
    pub max_mime_parts: usize,
    pub max_expanded_bytes: usize,
}

impl Default for MailLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 30 * 1024 * 1024,
            max_nesting_depth: 6,
            max_mime_parts: 200,
            max_expanded_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct XmlAttachment {
    pub origin_path: String,
    pub xml: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExtractedDocuments {
    pub xml_documents: Vec<XmlAttachment>,
    pub discarded_non_dmarc_parts: usize,
}

#[derive(Debug)]
pub enum MailError {
    TooLarge,
    TooDeep,
    TooManyParts,
    ExpandedLimit,
    MissingReports,
    UnsupportedReport(String),
    Malformed(String),
}

impl fmt::Display for MailError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(fmt, "MIME email is too large"),
            Self::TooDeep => write!(fmt, "Too many nested forwarded emails"),
            Self::TooManyParts => write!(fmt, "Too many MIME or ZIP parts"),
            Self::ExpandedLimit => write!(fmt, "DMARC attachment exceeds decompression limit"),
            Self::MissingReports => write!(fmt, "No DMARC aggregate reports found"),
            Self::UnsupportedReport(name) => write!(fmt, "Unsupported DMARC attachment: {name}"),
            Self::Malformed(message) => write!(fmt, "Invalid MIME or compressed report: {message}"),
        }
    }
}

impl std::error::Error for MailError {}

struct State {
    documents: Vec<XmlAttachment>,
    discarded: usize,
    parts_seen: usize,
    expanded_bytes: usize,
}

/// Extract all DMARC XML payloads from a complete RFC 5322/MIME message.
///
/// Refuses to succeed if a DMARC-like attachment is not understood, because
/// the upstream S3 email must then remain available for later reprocessing.
pub fn extract_dmarc_documents(
    mime: &[u8],
    limits: &MailLimits,
) -> Result<ExtractedDocuments, MailError> {
    if mime.len() > limits.max_message_bytes {
        return Err(MailError::TooLarge);
    }
    let parsed = parse_mail(mime).map_err(|e| MailError::Malformed(e.to_string()))?;
    let mut state = State {
        documents: Vec::new(),
        discarded: 0,
        parts_seen: 0,
        expanded_bytes: 0,
    };
    visit(&parsed, "email", 0, &mut state, limits)?;
    if state.documents.is_empty() {
        return Err(MailError::MissingReports);
    }
    Ok(ExtractedDocuments {
        xml_documents: state.documents,
        discarded_non_dmarc_parts: state.discarded,
    })
}

fn visit(
    part: &ParsedMail<'_>,
    path: &str,
    depth: usize,
    state: &mut State,
    limits: &MailLimits,
) -> Result<(), MailError> {
    if depth > limits.max_nesting_depth {
        return Err(MailError::TooDeep);
    }
    state.parts_seen += 1;
    if state.parts_seen > limits.max_mime_parts {
        return Err(MailError::TooManyParts);
    }
    if !part.subparts.is_empty() {
        for (index, subpart) in part.subparts.iter().enumerate() {
            visit(
                subpart,
                &format!("{path}/part-{index}"),
                depth,
                state,
                limits,
            )?;
        }
        return Ok(());
    }

    let content_type = part.ctype.mimetype.to_ascii_lowercase();
    let disposition = part.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .map(String::as_str)
        .unwrap_or("");
    let filename_lower = filename.to_ascii_lowercase();
    let location = if filename.is_empty() {
        path.to_owned()
    } else {
        format!("{path}/{filename}")
    };

    if content_type == "message/rfc822" || filename_lower.ends_with(".eml") {
        let payload = part
            .get_body_raw()
            .map_err(|e| MailError::Malformed(e.to_string()))?;
        if payload.len() > limits.max_message_bytes {
            return Err(MailError::TooLarge);
        }
        let embedded = parse_mail(&payload).map_err(|e| MailError::Malformed(e.to_string()))?;
        return visit(&embedded, &location, depth + 1, state, limits);
    }

    let kind = if filename_lower.ends_with(".xml.gz")
        || filename_lower.ends_with(".gz")
        || content_type == "application/gzip"
        || content_type == "application/x-gzip"
    {
        Some("gzip")
    } else if filename_lower.ends_with(".zip")
        || content_type == "application/zip"
        || content_type == "application/x-zip-compressed"
    {
        Some("zip")
    } else if filename_lower.ends_with(".xml")
        || content_type == "application/xml"
        || content_type == "text/xml"
    {
        Some("xml")
    } else {
        None
    };

    match kind {
        Some(kind) => {
            let payload = part
                .get_body_raw()
                .map_err(|e| MailError::Malformed(e.to_string()))?;
            if payload.len() > limits.max_message_bytes {
                return Err(MailError::TooLarge);
            }
            match kind {
                "gzip" => {
                    let mut gzip = MultiGzDecoder::new(payload.as_slice());
                    let xml = read_expanded(&mut gzip, state, limits)?;
                    state.documents.push(XmlAttachment {
                        origin_path: location,
                        xml,
                    });
                }
                "zip" => {
                    extract_zip(&payload, &location, state, limits)?;
                }
                "xml" => {
                    account_bytes(payload.len(), state, limits)?;
                    state.documents.push(XmlAttachment {
                        origin_path: location,
                        xml: payload,
                    });
                }
                _ => unreachable!(),
            }
        }
        None if filename_lower.contains("dmarc") || filename_lower.contains(".xml") => {
            return Err(MailError::UnsupportedReport(location));
        }
        None => state.discarded += 1,
    }
    Ok(())
}

fn account_bytes(size: usize, state: &mut State, limits: &MailLimits) -> Result<(), MailError> {
    if size
        > limits
            .max_expanded_bytes
            .saturating_sub(state.expanded_bytes)
    {
        return Err(MailError::ExpandedLimit);
    }
    state.expanded_bytes += size;
    Ok(())
}

fn read_expanded(
    reader: &mut impl Read,
    state: &mut State,
    limits: &MailLimits,
) -> Result<Vec<u8>, MailError> {
    let remaining = limits
        .max_expanded_bytes
        .saturating_sub(state.expanded_bytes);
    let mut payload = Vec::new();
    reader
        .take((remaining as u64).saturating_add(1))
        .read_to_end(&mut payload)
        .map_err(|e| MailError::Malformed(e.to_string()))?;
    account_bytes(payload.len(), state, limits)?;
    Ok(payload)
}

fn extract_zip(
    bytes: &[u8],
    location: &str,
    state: &mut State,
    limits: &MailLimits,
) -> Result<(), MailError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| MailError::Malformed(e.to_string()))?;
    if archive.len() > limits.max_mime_parts.saturating_sub(state.parts_seen) {
        return Err(MailError::TooManyParts);
    }
    let start = state.documents.len();
    for index in 0..archive.len() {
        state.parts_seen += 1;
        if state.parts_seen > limits.max_mime_parts {
            return Err(MailError::TooManyParts);
        }
        let mut entry = archive
            .by_index(index)
            .map_err(|e| MailError::Malformed(e.to_string()))?;
        if entry.enclosed_name().is_none() {
            return Err(MailError::Malformed("Unsafe ZIP entry path".into()));
        }
        if entry.is_dir() {
            continue;
        }
        let name = entry
            .name()
            .map_err(|e| MailError::Malformed(e.to_string()))?
            .into_owned();
        if !name.to_ascii_lowercase().ends_with(".xml") {
            return Err(MailError::UnsupportedReport(format!("{location}/{name}")));
        }
        if !matches!(
            entry.compression(),
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
        ) {
            return Err(MailError::UnsupportedReport(format!("{location}/{name}")));
        }
        let xml = read_expanded(&mut entry, state, limits)?;
        state.documents.push(XmlAttachment {
            origin_path: format!("{location}/{name}"),
            xml,
        });
    }
    if state.documents.len() == start {
        return Err(MailError::MissingReports);
    }
    Ok(())
}
