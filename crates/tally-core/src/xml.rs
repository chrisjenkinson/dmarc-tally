//! Strict, bounded DMARC aggregate XML reader supporting RFC 7489/9990.
//!
//! Uses roxmltree with DTDs disabled and an explicit node limit. A bounded
//! walk validates depth and shape before converting into owned structured
//! nodes. The parser never silently ignores unfamiliar XML fields.

use crate::model::{
    DateRange, DmarcFormat, DmarcRecord, ParseError, ParseLimits, ParsedReport,
    PolicyEvaluated, PublishedPolicy, ReportMetadata, UnknownField, XmlAttribute, XmlNode,
};
use roxmltree::{Document, Node, ParsingOptions, NS_XML_URI};
use std::net::IpAddr;

const DMARC_LEGACY_NS: &str = "http://dmarc.org/dmarc-xml/0.1";
const DMARC_V2_NS: &str = "urn:ietf:params:xml:ns:dmarc-2.0";

/// Parse an aggregate report. Unknown elements/attributes are returned as
/// \`unknown_fields\` and cannot be considered fully captured.
pub fn parse_dmarc_xml(input: &[u8], limits: &ParseLimits) -> Result<ParsedReport, ParseError> {
    if input.len() > limits.max_xml_bytes {
        return Err(ParseError::InputTooLarge);
    }

    let xml = std::str::from_utf8(input)
        .map_err(|e| ParseError::Malformed(format!("Not UTF-8: {e}")))?;
    // A known DTD, even empty, is excluded. External entities must never be fetched.
    if xml.to_ascii_lowercase().contains("<!doctype") {
        return Err(ParseError::Malformed("DOCTYPE is not supported".into()));
    }
    let document = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: limits.max_nodes,
            ..Default::default()
        },
    )
    .map_err(|e| ParseError::Malformed(e.to_string()))?;

    let root = document.root_element();
    if !root.has_tag_name("feedback") {
        return Err(ParseError::Malformed("Expected a <feedback> root".into()));
    }
    let format_version = match root.tag_name().namespace() {
        Some(DMARC_V2_NS) => DmarcFormat::Rfc9990,
        None | Some(DMARC_LEGACY_NS) => DmarcFormat::Rfc7489,
        Some(other) => return Err(ParseError::Malformed(format!("Unknown DMARC namespace: {other}"))),
    };

    let mut records_seen = 0_usize;
    for node in root.descendants().filter(|node| node.is_element()) {
        let depth = node.ancestors().filter(|node| node.is_element()).count();
        if depth > limits.max_depth {
            return Err(ParseError::TooDeep);
        }
        if node.parent_element().is_some_and(|p| p == root) && node.has_tag_name("record") {
            records_seen += 1;
            if records_seen > limits.max_records {
                return Err(ParseError::TooManyRecords);
            }
        }
    }

    let mut unknown_fields = Vec::new();
    inspect_fields(root, None, "feedback", format_version, root.tag_name().namespace(), &mut unknown_fields);
    let metadata_node = one_child(root, "report_metadata")?;
    let policy_node = one_child(root, "policy_published")?;

    let date_node = one_child(metadata_node, "date_range")?;
    let begin: i64 = one_text(date_node, "begin")?
        .parse()
        .map_err(|_| ParseError::Malformed("Invalid report begin timestamp".into()))?;
    let end: i64 = one_text(date_node, "end")?
        .parse()
        .map_err(|_| ParseError::Malformed("Invalid report end timestamp".into()))?;
    if begin < 0 || end < begin {
        return Err(ParseError::Malformed("Invalid report date range".into()));
    }
    let metadata = ReportMetadata {
        org_name: one_text(metadata_node, "org_name")?,
        email: one_text(metadata_node, "email")?,
        report_id: one_text(metadata_node, "report_id")?,
        date_range: DateRange { begin, end },
        error: metadata_node
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("error"))
            .map(|c| c.text().unwrap_or("").to_owned())
            .collect(),
        generator: optional_text(metadata_node, "generator")?,
        raw: own_node(metadata_node),
    };
    let published_policy = PublishedPolicy {
        domain: one_text(policy_node, "domain")?.trim_end_matches('.').to_ascii_lowercase(),
        raw: own_node(policy_node),
    };
    one_text(policy_node, "p")?;

    let mut records = Vec::with_capacity(records_seen);
    for record_node in root.children().filter(|c| c.is_element() && c.has_tag_name("record")) {
        let row = one_child(record_node, "row")?;
        let evaluated_node = one_child(row, "policy_evaluated")?;
        one_text(evaluated_node, "disposition")?;
        one_text(evaluated_node, "dkim")?;
        one_text(evaluated_node, "spf")?;
        let source_ip = one_text(row, "source_ip")?;
        source_ip
            .parse::<IpAddr>()
            .map_err(|_| ParseError::Malformed("Invalid sending IP".into()))?;
        let count = one_text(row, "count")?
            .parse::<u64>()
            .map_err(|_| ParseError::Malformed("Invalid message count".into()))?;
        if count == 0 {
            return Err(ParseError::Malformed("Zero count is not valid".into()));
        }
        let identifiers = one_child(record_node, "identifiers")?;
        one_text(identifiers, "header_from")?;
        let authentication = one_child(record_node, "auth_results")?;
        let dkim_results = authentication
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("dkim"))
            .map(own_node)
            .collect();
        let spf_results = authentication
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("spf"))
            .map(own_node)
            .collect();
        let evaluated = PolicyEvaluated {
            reasons: evaluated_node
                .children()
                .filter(|c| c.is_element() && c.has_tag_name("reason"))
                .map(own_node)
                .collect(),
            raw: own_node(evaluated_node),
        };
        records.push(DmarcRecord {
            source_ip,
            count,
            evaluated,
            dkim_results,
            spf_results,
            raw: own_node(record_node),
        });
    }
    if records.is_empty() {
        return Err(ParseError::Malformed("At least one record is required".into()));
    }

    Ok(ParsedReport {
        metadata,
        published_policy,
        records,
        unknown_fields,
        format_version,
    })
}

fn one_child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Result<Node<'a, 'input>, ParseError> {
    let mut children = node.children().filter(|c| c.is_element() && c.has_tag_name(name));
    let first = children.next().ok_or_else(|| ParseError::Malformed(format!("Missing {name}")))?;
    if children.next().is_some() {
        return Err(ParseError::Malformed(format!("Duplicate {name}")));
    }
    Ok(first)
}

fn one_text(node: Node<'_, '_>, name: &str) -> Result<String, ParseError> {
    let child = one_child(node, name)?;
    let text = child.text().unwrap_or("").trim();
    if text.is_empty() {
        return Err(ParseError::Malformed(format!("Empty {name}")));
    }
    Ok(text.to_owned())
}

fn optional_text(node: Node<'_, '_>, name: &str) -> Result<Option<String>, ParseError> {
    let mut children = node.children().filter(|c| c.is_element() && c.has_tag_name(name));
    let first = children.next().map(|child| child.text().unwrap_or("").trim().to_owned());
    if children.next().is_some() {
        return Err(ParseError::Malformed(format!("Duplicate {name}")));
    }
    Ok(first)
}

/// Converted only after bounded parsing and nesting checks.
fn own_node(node: Node<'_, '_>) -> XmlNode {
    XmlNode {
        name: node.tag_name().name().to_owned(),
        namespace: node.tag_name().namespace().map(str::to_owned),
        attributes: node.attributes().map(|a| XmlAttribute {
            name: a.name().to_owned(),
            namespace: a.namespace().map(str::to_owned),
            value: a.value().to_owned(),
        }).collect(),
        text: node.children()
            .filter(|c| c.is_text())
            .filter_map(|c| c.text())
            .collect::<String>(),
        children: node.children().filter(|c| c.is_element()).map(own_node).collect(),
    }
}

/// Consult the appropriate DMARC vocabulary for each node, not just leaf names.
fn known_child(parent: &str, child: &str, version: DmarcFormat) -> bool {
    match (parent, child) {
        ("feedback", "report_metadata" | "policy_published" | "record") => true,
        ("feedback", "version" | "extension") => version == DmarcFormat::Rfc9990,
        ("report_metadata", "org_name" | "email" | "extra_contact_info" | "report_id" | "date_range" | "error") => true,
        ("report_metadata", "generator") => version == DmarcFormat::Rfc9990,
        ("date_range", "begin" | "end") => true,
        ("policy_published", "domain" | "p" | "sp" | "adkim" | "aspf" | "fo") => true,
        ("policy_published", "rf" | "ri" | "pct") => version == DmarcFormat::Rfc7489,
        ("policy_published", "np" | "testing" | "discovery_method") => version == DmarcFormat::Rfc9990,
        ("record", "row" | "identifiers" | "auth_results") => true,
        ("row", "source_ip" | "count" | "policy_evaluated") => true,
        ("policy_evaluated", "disposition" | "dkim" | "spf" | "reason") => true,
        ("reason", "type" | "comment") => true,
        ("identifiers", "envelope_to" | "envelope_from" | "header_from") => true,
        ("auth_results", "dkim" | "spf") => true,
        ("dkim", "domain" | "selector" | "result" | "human_result") => true,
        ("spf", "domain" | "scope" | "result" | "human_result") => true,
        _ => false,
    }
}

fn inspect_fields(
    node: Node<'_, '_>,
    parent_name: Option<&str>,
    path: &str,
    version: DmarcFormat,
    standard_namespace: Option<&str>,
    unknown: &mut Vec<UnknownField>,
) {
    let node_namespace = node.tag_name().namespace();
    if let Some(parent) = parent_name {
        if !known_child(parent, node.tag_name().name(), version)
            || node_namespace != standard_namespace
        {
            unknown.push(UnknownField {
                path: path.to_owned(),
                namespace: node_namespace.map(str::to_owned),
                attribute: false,
            });
        }
    }

    for attr in node.attributes() {
        let allowed_language = attr.name() == "lang"
            && (attr.namespace().is_none() || attr.namespace() == Some(NS_XML_URI))
            && matches!(
                node.tag_name().name(),
                "error" | "extra_contact_info" | "human_result" | "comment"
            );
        if !allowed_language {
            unknown.push(UnknownField {
                path: format!("{path}/@{}", attr.name()),
                namespace: attr.namespace().map(str::to_owned),
                attribute: true,
            });
        }
    }

    for child in node.children().filter(|c| c.is_element()) {
        let next_path = format!("{path}/{}", child.tag_name().name());
        inspect_fields(
            child,
            Some(node.tag_name().name()),
            &next_path,
            version,
            standard_namespace,
            unknown,
        );
    }
}
