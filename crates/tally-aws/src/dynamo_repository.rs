//! DynamoDB implementation of the platform-neutral ReportRepository port.
//!
//! Each report is first represented by a WRITING metadata item. Deterministic
//! record items are written conditionally; only after they all succeed is
//! metadata transitioned to COMPLETE. Reads never expose WRITING reports.
//! The write protocol is retry-safe after crashes and duplicate S3 events.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue as Value, Client};
use tally_core::{
    identity::{DomainName, ReportIdentity, ReportReference, StoredRecord, StoredReport},
    model::DateRange,
    ports::{Cursor, PersistOutcome, ReportPage, ReportRepository, StoreError},
};

use crate::dynamodb::{decode_report, encode_meta, encode_record, DynamoKeys};

#[derive(Clone)]
pub struct DynamoReportRepository {
    client: Client,
    table: String,
}

#[derive(Clone, Debug)]
struct MetadataItem {
    state: String,
    content_hash: String,
    payload: String,
}

fn attr<'a>(item: &'a HashMap<String, Value>, key: &str) -> Result<&'a str, StoreError> {
    item.get(key)
        .and_then(|item| item.as_s().ok())
        .map(String::as_str)
        .ok_or_else(|| StoreError::Corrupt(format!("Missing DynamoDB attribute {key}")))
}

fn unavailable(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Unavailable(format!("{context}: {error}"))
}

fn corrupt(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt(format!("{context}: {error}"))
}

impl DynamoReportRepository {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    async fn metadata(
        &self,
        identity: &ReportIdentity,
    ) -> Result<Option<MetadataItem>, StoreError> {
        let keys = DynamoKeys::from_identity(identity);
        let result = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("PK", Value::S(keys.partition))
            .key("SK", Value::S(keys.metadata))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| unavailable("Read report metadata", e))?;
        result
            .item()
            .map(|item| {
                Ok(MetadataItem {
                    state: attr(item, "State")?.to_owned(),
                    content_hash: attr(item, "Hash")?.to_owned(),
                    payload: attr(item, "Data")?.to_owned(),
                })
            })
            .transpose()
    }

    async fn assert_existing_record(
        &self,
        partition: &str,
        sort_key: &str,
        expected: &str,
    ) -> Result<bool, StoreError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("PK", Value::S(partition.to_owned()))
            .key("SK", Value::S(sort_key.to_owned()))
            .consistent_read(true)
            .send()
            .await
            .map_err(|e| unavailable("Check existing DMARC record", e))?;
        Ok(result
            .item()
            .map(|item| attr(item, "Data"))
            .transpose()?
            .is_some_and(|actual| actual == expected))
    }

    async fn read_records(&self, identity: &ReportIdentity) -> Result<Vec<String>, StoreError> {
        let keys = DynamoKeys::from_identity(identity);
        let mut records = Vec::new();
        let mut next: Option<HashMap<String, Value>> = None;
        loop {
            let mut request = self
                .client
                .query()
                .table_name(&self.table)
                .consistent_read(true)
                .key_condition_expression("PK = :partition AND begins_with(SK, :prefix)")
                .expression_attribute_values(":partition", Value::S(keys.partition.clone()))
                .expression_attribute_values(":prefix", Value::S(keys.record_prefix()));
            if let Some(last) = next.take() {
                request = request.set_exclusive_start_key(Some(last));
            }
            let page = request
                .send()
                .await
                .map_err(|e| unavailable("Read DMARC record page", e))?;
            for item in page.items() {
                records.push(attr(item, "Data")?.to_owned());
            }
            next = page.last_evaluated_key().cloned();
            if next.is_none() {
                break;
            }
        }
        Ok(records)
    }
}

#[async_trait]
impl ReportRepository for DynamoReportRepository {
    async fn persist_report(&self, stored: &StoredReport) -> Result<PersistOutcome, StoreError> {
        let keys = DynamoKeys::from_identity(&stored.identity);
        let hash = stored
            .content_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let data = encode_meta(stored).map_err(|e| corrupt("Encode report metadata", e))?;
        let expected_count = stored.report.records.len();

        match self.metadata(&stored.identity).await? {
            Some(existing) if existing.content_hash != hash => return Ok(PersistOutcome::Conflict),
            Some(existing) if existing.state == "COMPLETE" => {
                return Ok(PersistOutcome::PreviouslyCompleted);
            }
            Some(_) => {}
            None => {
                let created = self
                    .client
                    .put_item()
                    .table_name(&self.table)
                    .item("PK", Value::S(keys.partition.clone()))
                    .item("SK", Value::S(keys.metadata.clone()))
                    .item("State", Value::S("WRITING".into()))
                    .item("Hash", Value::S(hash.clone()))
                    .item("Count", Value::N(expected_count.to_string()))
                    .item("Data", Value::S(data))
                    .condition_expression("attribute_not_exists(PK)")
                    .send()
                    .await;
                if let Err(error) = created {
                    if error
                        .as_service_error()
                        .is_some_and(|e| e.is_conditional_check_failed_exception())
                    {
                        let current = self.metadata(&stored.identity).await?;
                        match current {
                            Some(other) if other.content_hash != hash => {
                                return Ok(PersistOutcome::Conflict)
                            }
                            Some(other) if other.state == "COMPLETE" => {
                                return Ok(PersistOutcome::PreviouslyCompleted);
                            }
                            Some(_) => {}
                            None => {
                                return Err(StoreError::Unavailable(
                                    "Metadata disappeared during write".into(),
                                ))
                            }
                        }
                    } else {
                        return Err(unavailable("Create DMARC report", error));
                    }
                }
            }
        }

        for (ordinal, record) in stored.report.records.iter().enumerate() {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| StoreError::Corrupt("Report has too many records".into()))?;
            let record_data = encode_record(&StoredRecord {
                ordinal,
                full_record: record.clone(),
            })
            .map_err(|e| corrupt("Encode record", e))?;
            let sort_key = keys.record_sort_key(ordinal);
            let saved = self
                .client
                .put_item()
                .table_name(&self.table)
                .item("PK", Value::S(keys.partition.clone()))
                .item("SK", Value::S(sort_key.clone()))
                .item("Data", Value::S(record_data.clone()))
                .condition_expression("attribute_not_exists(PK)")
                .send()
                .await;
            if let Err(error) = saved {
                if error
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception())
                {
                    if !self
                        .assert_existing_record(&keys.partition, &sort_key, &record_data)
                        .await?
                    {
                        return Ok(PersistOutcome::Conflict);
                    }
                } else {
                    return Err(unavailable("Save DMARC record", error));
                }
            }
        }

        let completed = self
            .client
            .update_item()
            .table_name(&self.table)
            .key("PK", Value::S(keys.partition))
            .key("SK", Value::S(keys.metadata))
            .update_expression("SET #state = :complete")
            .condition_expression("#state = :writing AND #hash = :hash AND #count = :count")
            .expression_attribute_names("#state", "State")
            .expression_attribute_names("#hash", "Hash")
            .expression_attribute_names("#count", "Count")
            .expression_attribute_values(":complete", Value::S("COMPLETE".into()))
            .expression_attribute_values(":writing", Value::S("WRITING".into()))
            .expression_attribute_values(":hash", Value::S(hash.clone()))
            .expression_attribute_values(":count", Value::N(expected_count.to_string()))
            .send()
            .await;
        if let Err(error) = completed {
            if error
                .as_service_error()
                .is_some_and(|e| e.is_conditional_check_failed_exception())
            {
                return match self.metadata(&stored.identity).await? {
                    Some(meta) if meta.content_hash == hash && meta.state == "COMPLETE" => {
                        Ok(PersistOutcome::PreviouslyCompleted)
                    }
                    Some(meta) if meta.content_hash != hash => Ok(PersistOutcome::Conflict),
                    _ => Err(StoreError::Unavailable(
                        "Could not complete report after record writes".into(),
                    )),
                };
            }
            return Err(unavailable("Complete DMARC report", error));
        }

        Ok(if stored.capture_complete {
            PersistOutcome::NewlyCompleted
        } else {
            PersistOutcome::CompletedWithUnknownFields
        })
    }

    async fn get_report(
        &self,
        identity: &ReportIdentity,
    ) -> Result<Option<StoredReport>, StoreError> {
        let meta = match self.metadata(identity).await? {
            Some(meta) if meta.state == "COMPLETE" => meta,
            _ => return Ok(None),
        };
        let payloads = self.read_records(identity).await?;
        let report = decode_report(&meta.payload, &payloads)
            .map_err(|e| corrupt("Read complete report", e))?;
        if &report.identity != identity {
            return Err(StoreError::Corrupt("Report identity mismatch".into()));
        }
        Ok(Some(report))
    }

    async fn get_report_by_reference(
        &self,
        reference: &ReportReference,
    ) -> Result<Option<StoredReport>, StoreError> {
        // One exact, strongly consistent metadata lookup using the existing
        // (domain, period end, digest) key layout. Never scan for a digest.
        let partition = format!("DOMAIN#{}", reference.domain.as_str());
        let key = format!(
            "END#{:020}#REPORT#{}#META",
            reference.period_end, reference.digest
        );
        let result = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("PK", Value::S(partition))
            .key("SK", Value::S(key))
            .consistent_read(true)
            .send()
            .await
            .map_err(|err| unavailable("Read report metadata by reference", err))?;
        let Some(item) = result.item() else {
            return Ok(None);
        };
        if attr(item, "State")? != "COMPLETE" {
            return Ok(None);
        }
        let payload = attr(item, "Data")?;
        let identity =
            metadata_identity(payload).map_err(|err| corrupt("Decode report reference", err))?;
        if !reference.matches(&identity) {
            return Err(StoreError::Corrupt("Report reference mismatch".into()));
        }
        let records = self.read_records(&identity).await?;
        let report = decode_report(payload, &records)
            .map_err(|err| corrupt("Read referenced report", err))?;
        if !reference.matches(&report.identity) {
            return Err(StoreError::Corrupt(
                "Decoded report reference mismatch".into(),
            ));
        }
        Ok(Some(report))
    }

    async fn list_for_domain(
        &self,
        domain: &DomainName,
        range: DateRange,
        cursor: Option<Cursor>,
    ) -> Result<ReportPage, StoreError> {
        let lower = DynamoKeys::query_start(range.begin);
        let upper = DynamoKeys::query_end(range.end);
        let after = cursor.as_ref().map(|c| c.0.as_str());
        if after.is_some_and(|v| v < lower.as_str() || v > upper.as_str()) {
            return Err(StoreError::Corrupt("Invalid date-range cursor".into()));
        }

        let partition = format!("DOMAIN#{}", domain.as_str());
        let mut key: Option<HashMap<String, Value>> = None;
        let mut matches = Vec::new();
        'pages: loop {
            let mut query = self
                .client
                .query()
                .table_name(&self.table)
                .consistent_read(true)
                .key_condition_expression("PK = :partition AND SK BETWEEN :start AND :end")
                .expression_attribute_values(":partition", Value::S(partition.clone()))
                .expression_attribute_values(":start", Value::S(lower.clone()))
                .expression_attribute_values(":end", Value::S(upper.clone()));
            if let Some(start_key) = key.take() {
                query = query.set_exclusive_start_key(Some(start_key));
            }
            let response = query
                .send()
                .await
                .map_err(|e| unavailable("Query DMARC reporting period", e))?;
            for item in response.items() {
                let sk = attr(item, "SK")?;
                if !sk.ends_with("#META") || after.is_some_and(|cursor| sk <= cursor) {
                    continue;
                }
                if attr(item, "State")? != "COMPLETE" {
                    continue;
                }
                let meta_data = attr(item, "Data")?;
                let identity = metadata_identity(meta_data)
                    .map_err(|e| corrupt("Decode report metadata", e))?;
                if &identity.domain != domain
                    || !(range.begin..=range.end).contains(&identity.period_end)
                {
                    return Err(StoreError::Corrupt(
                        "Stored report is outside its DynamoDB range".into(),
                    ));
                }
                matches.push((sk.to_owned(), identity));
                if matches.len() == 100 {
                    break 'pages;
                }
            }
            key = response.last_evaluated_key().cloned();
            if key.is_none() {
                break;
            }
        }

        let next_cursor = (matches.len() == 100)
            .then(|| Cursor(matches.last().expect("100 report IDs exist").0.clone()));
        let mut reports = Vec::with_capacity(matches.len());
        for (_, identity) in matches {
            let report = self.get_report(&identity).await?.ok_or_else(|| {
                StoreError::Corrupt("Complete metadata has missing records".into())
            })?;
            reports.push(report);
        }
        Ok(ReportPage {
            reports,
            next_cursor,
        })
    }
}

/// Parse the stored metadata payload without exposing DynamoDB fields in core.
fn metadata_identity(data: &str) -> Result<ReportIdentity, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct SummaryMetadata {
        stored: StoredReport,
    }
    serde_json::from_str::<SummaryMetadata>(data).map(|m| m.stored.identity)
}
