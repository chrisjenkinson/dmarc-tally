use std::io::{Cursor, Write};

use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{write::GzEncoder, Compression};
use tally_core::mail::{extract_dmarc_documents, MailLimits};
use zip::{write::SimpleFileOptions, ZipWriter};

const REPORT: &[u8] = include_bytes!("../../../tests/fixtures/xml/legacy.xml");
const MODERN: &[u8] = include_bytes!("../../../tests/fixtures/xml/modern.xml");

fn gzip(xml: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml).unwrap();
    encoder.finish().unwrap()
}

fn zip_xml(filename: &str, xml: &[u8]) -> Vec<u8> {
    let buffer = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(buffer);
    writer
        .start_file(filename, SimpleFileOptions::default())
        .unwrap();
    writer.write_all(xml).unwrap();
    writer.finish().unwrap().into_inner()
}

fn part(mime_type: &str, filename: &str, body: &[u8]) -> String {
    format!(
        "--tally\r\nContent-Type: {mime_type}\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        STANDARD.encode(body)
    )
}

fn email(parts: &str) -> Vec<u8> {
    format!(
        "From: reports@receiver.example\r\nTo: reports@example.net\r\nSubject: Just some text\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=tally\r\n\r\n{parts}--tally--\r\n"
    )
    .into_bytes()
}

#[test]
fn extracts_direct_gzip_and_plain_xml() {
    let parts = format!(
        "{}{}",
        part("application/gzip", "report.xml.gz", &gzip(REPORT)),
        part("application/xml", "another.xml", MODERN)
    );
    let docs = extract_dmarc_documents(&email(&parts), &MailLimits::default()).unwrap();
    assert_eq!(docs.xml_documents.len(), 2);
    assert_eq!(docs.xml_documents[0].xml, REPORT);
    assert_eq!(docs.xml_documents[1].xml, MODERN);
}

#[test]
fn extracts_zip_without_ignoring_other_xml_in_email() {
    let parts = part(
        "application/zip",
        "aggregate.zip",
        &zip_xml("report.xml", REPORT),
    );
    let docs = extract_dmarc_documents(&email(&parts), &MailLimits::default()).unwrap();
    assert_eq!(docs.xml_documents.len(), 1);
    assert_eq!(docs.xml_documents[0].xml, REPORT);
}

#[test]
fn extracts_nested_forwarded_eml_attachments_from_single_batch() {
    let older = email(&part("application/gzip", "old.xml.gz", &gzip(REPORT)));
    let newer = email(&part("text/xml", "new.xml", MODERN));
    let parts = format!(
        "{}{}",
        part("message/rfc822", "previous-1.eml", &older),
        part("application/octet-stream", "previous-2.eml", &newer)
    );
    let docs = extract_dmarc_documents(&email(&parts), &MailLimits::default()).unwrap();
    assert_eq!(docs.xml_documents.len(), 2);
    assert_eq!(docs.xml_documents[0].xml, REPORT);
    assert_eq!(docs.xml_documents[1].xml, MODERN);
    assert!(docs.xml_documents[0].origin_path.contains("previous-1.eml"));
}

#[test]
fn rejects_zip_traversal_and_unsupported_dmarc_compression() {
    let traversal = part(
        "application/zip",
        "reports.zip",
        &zip_xml("../report.xml", REPORT),
    );
    assert!(extract_dmarc_documents(&email(&traversal), &MailLimits::default()).is_err());
    let unknown = part("application/octet-stream", "report.xml.br", b"not-a-brotli");
    assert!(extract_dmarc_documents(&email(&unknown), &MailLimits::default()).is_err());
}

#[test]
fn rejects_decompression_bomb_before_unbounded_allocation() {
    let big = vec![b'X'; 20_000];
    let parts = part("application/gzip", "report.xml.gz", &gzip(&big));
    let limits = MailLimits {
        max_expanded_bytes: 100,
        ..Default::default()
    };
    assert!(extract_dmarc_documents(&email(&parts), &limits).is_err());
}

#[test]
fn rejects_excessive_nested_forwarding() {
    let mut inner = email(&part("application/xml", "report.xml", REPORT));
    for _ in 0..8 {
        inner = email(&part("message/rfc822", "forwarded.eml", &inner));
    }
    let limits = MailLimits {
        max_nesting_depth: 6,
        ..Default::default()
    };
    assert!(extract_dmarc_documents(&inner, &limits).is_err());
}
