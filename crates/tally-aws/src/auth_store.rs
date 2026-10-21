//! DynamoDB implementation of the one-administrator AuthenticationStore.
//!
//! Use a dedicated, access-restricted DynamoDB table with String PK/SK and
//! TTL enabled for ExpiresAt. The fixed LOGIN row must NOT expire: preserving
//! its IssuedAt field is necessary for throttling after redemption.
//! DynamoDB TTL is cleanup only; every session check validates its expiry.
//!
//! Only SHA-256 token digests enter DynamoDB. Errors returned to callers are
//! deliberately generic: never include authentication keys or credentials.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue as Value, Client};
use tally_core::authentication::{AuthError, AuthenticationStore, TokenDigest};

const LOGIN_PK: &str = "AUTH#ADMIN";
const LOGIN_SK: &str = "LOGIN";
const SESSION_SK: &str = "SESSION";
const CHALLENGE_EXPIRY_ATTRIBUTE: &str = "ChallengeExpiresAt";
const SESSION_TTL_ATTRIBUTE: &str = "ExpiresAt";

// Conditions, rather than pre-read/check/write, make issuance and redemption
// safe under Lambda concurrency, retries and eventually consistent delivery.
const CHALLENGE_CONDITION: &str = "attribute_not_exists(PK) OR #issued <= :cutoff";
const CONSUME_CONDITION: &str = "#digest = :digest AND #expiry > :now AND #consumed = :unused";
const SESSION_INSERT_CONDITION: &str = "attribute_not_exists(PK)";

fn challenge_key() -> HashMap<String, Value> {
    HashMap::from([
        ("PK".into(), Value::S(LOGIN_PK.into())),
        ("SK".into(), Value::S(LOGIN_SK.into())),
    ])
}

fn session_key(digest_hex: &str) -> HashMap<String, Value> {
    HashMap::from([
        ("PK".into(), Value::S(format!("AUTH#SESSION#{digest_hex}"))),
        ("SK".into(), Value::S(SESSION_SK.into())),
    ])
}

fn issue_cutoff(issued_at: i64, cooldown_seconds: i64) -> Result<i64, AuthError> {
    if cooldown_seconds < 0 {
        return Err(AuthError::Clock);
    }
    issued_at
        .checked_sub(cooldown_seconds)
        .ok_or(AuthError::Clock)
}

fn session_is_valid(item: &HashMap<String, Value>, now: i64) -> Result<bool, AuthError> {
    let expiry = item
        .get(SESSION_TTL_ATTRIBUTE)
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(AuthError::Storage)?;
    Ok(expiry > now)
}

#[derive(Clone)]
pub struct DynamoAuthenticationStore {
    client: Client,
    table: String,
}

impl DynamoAuthenticationStore {
    pub fn new(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }
}

#[async_trait]
impl AuthenticationStore for DynamoAuthenticationStore {
    async fn issue_login_challenge(
        &self,
        digest: TokenDigest,
        issued_at: i64,
        expires_at: i64,
        cooldown_seconds: i64,
    ) -> Result<bool, AuthError> {
        if expires_at <= issued_at {
            return Err(AuthError::Clock);
        }
        let cutoff = issue_cutoff(issued_at, cooldown_seconds)?;
        // Reuse the fixed row. An UPDATE is essential, not a PUT+DELETE:
        // the previous IssuedAt timestamp continues to enforce cooldown
        // even after a login link has already been consumed.
        let result = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(challenge_key()))
            .update_expression(
                "SET #digest = :digest, #issued = :issued, #expiry = :expiry, #consumed = :unused",
            )
            .condition_expression(CHALLENGE_CONDITION)
            .expression_attribute_names("#digest", "Digest")
            .expression_attribute_names("#issued", "IssuedAt")
            .expression_attribute_names("#expiry", CHALLENGE_EXPIRY_ATTRIBUTE)
            .expression_attribute_names("#consumed", "Consumed")
            .expression_attribute_values(":digest", Value::S(digest.hex()))
            .expression_attribute_values(":issued", Value::N(issued_at.to_string()))
            .expression_attribute_values(":expiry", Value::N(expires_at.to_string()))
            .expression_attribute_values(":cutoff", Value::N(cutoff.to_string()))
            .expression_attribute_values(":unused", Value::Bool(false))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(_) => Err(AuthError::Storage),
        }
    }

    async fn consume_login_challenge(
        &self,
        digest: &TokenDigest,
        now: i64,
    ) -> Result<bool, AuthError> {
        let result = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(challenge_key()))
            .update_expression("SET #consumed = :used")
            .condition_expression(CONSUME_CONDITION)
            .expression_attribute_names("#digest", "Digest")
            .expression_attribute_names("#expiry", CHALLENGE_EXPIRY_ATTRIBUTE)
            .expression_attribute_names("#consumed", "Consumed")
            .expression_attribute_values(":digest", Value::S(digest.hex()))
            .expression_attribute_values(":now", Value::N(now.to_string()))
            .expression_attribute_values(":unused", Value::Bool(false))
            .expression_attribute_values(":used", Value::Bool(true))
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(_) => Err(AuthError::Storage),
        }
    }

    async fn issue_session(&self, digest: TokenDigest, expires_at: i64) -> Result<(), AuthError> {
        let mut item = session_key(&digest.hex());
        // An optional DynamoDB TTL rule on this attribute provides cleanup
        // *after* expiry, but authorization never depends on removal timing.
        item.insert(
            SESSION_TTL_ATTRIBUTE.into(),
            Value::N(expires_at.to_string()),
        );
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression(SESSION_INSERT_CONDITION)
            .send()
            .await
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }

    async fn is_session_valid(&self, digest: &TokenDigest, now: i64) -> Result<bool, AuthError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(session_key(&digest.hex())))
            .consistent_read(true)
            .send()
            .await
            .map_err(|_| AuthError::Storage)?;

        match result.item() {
            None => Ok(false),
            Some(item) => session_is_valid(item, now),
        }
    }

    async fn revoke_session(&self, digest: &TokenDigest) -> Result<(), AuthError> {
        // An unconditional delete is naturally idempotent. A strongly
        // consistent subsequent read rejects a successfully revoked token.
        self.client
            .delete_item()
            .table_name(&self.table)
            .set_key(Some(session_key(&digest.hex())))
            .send()
            .await
            .map_err(|_| AuthError::Storage)?;
        Ok(())
    }
}

// Local no-account tests below; production use also requires DynamoDB Local
// concurrency tests before deployment.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aws_sdk_dynamodb::types::AttributeValue as Value;
    use tally_core::authentication::{AuthError, AuthenticationStore};

    use super::{
        challenge_key, issue_cutoff, session_is_valid, session_key, DynamoAuthenticationStore,
        CHALLENGE_CONDITION, CHALLENGE_EXPIRY_ATTRIBUTE, CONSUME_CONDITION,
        SESSION_INSERT_CONDITION, SESSION_TTL_ATTRIBUTE,
    };

    #[test]
    fn challenge_has_single_fixed_record_key() {
        // The login record MUST NEVER have the table TTL attribute;
        // otherwise DynamoDB could erase the cooldown as the link expires.
        assert_ne!(CHALLENGE_EXPIRY_ATTRIBUTE, SESSION_TTL_ATTRIBUTE);
        let key = challenge_key();
        assert_eq!(key["PK"].as_s().unwrap(), "AUTH#ADMIN");
        assert_eq!(key["SK"].as_s().unwrap(), "LOGIN");
    }

    #[test]
    fn session_partition_is_isolated_and_uses_only_digest() {
        let digest = "a".repeat(64);
        let key = session_key(&digest);
        assert_eq!(key["PK"].as_s().unwrap(), &format!("AUTH#SESSION#{digest}"));
        assert_eq!(key["SK"].as_s().unwrap(), "SESSION");
        assert!(!key["PK"].as_s().unwrap().contains("example.com"));
    }

    #[test]
    fn challenge_writes_are_atomic_and_enforce_throttle() {
        assert!(CHALLENGE_CONDITION.contains("attribute_not_exists(PK)"));
        assert!(CHALLENGE_CONDITION.contains("#issued <= :cutoff"));
        assert_eq!(issue_cutoff(120, 60), Ok(60));
        assert_eq!(issue_cutoff(i64::MIN, 60), Err(AuthError::Clock));
        assert_eq!(issue_cutoff(120, -1), Err(AuthError::Clock));
    }

    #[test]
    fn consuming_requires_the_matching_unexpired_unused_challenge() {
        assert!(CONSUME_CONDITION.contains("#digest = :digest"));
        assert!(CONSUME_CONDITION.contains("#expiry > :now"));
        assert!(CONSUME_CONDITION.contains("#consumed = :unused"));
        // Consumption is an UPDATE, not DELETE: issued-at remains in place to
        // enforce email cooldown after the one-time token was redeemed.
    }

    #[test]
    fn sessions_are_conditionally_created_and_have_strict_expiry() {
        assert_eq!(SESSION_INSERT_CONDITION, "attribute_not_exists(PK)");
        let mut item = HashMap::new();
        item.insert("ExpiresAt".to_string(), Value::N("100".into()));
        assert_eq!(session_is_valid(&item, 99), Ok(true));
        assert_eq!(session_is_valid(&item, 100), Ok(false));
        assert_eq!(session_is_valid(&item, 101), Ok(false));
    }

    #[test]
    fn missing_or_corrupt_expiration_fails_closed() {
        let mut item = HashMap::new();
        assert_eq!(session_is_valid(&item, 100), Err(AuthError::Storage));
        item.insert("ExpiresAt".to_string(), Value::S("100".into()));
        assert_eq!(session_is_valid(&item, 100), Err(AuthError::Storage));
        item.insert("ExpiresAt".to_string(), Value::N("broken".into()));
        assert_eq!(session_is_valid(&item, 100), Err(AuthError::Storage));
    }

    #[test]
    fn adapter_exposes_only_the_existing_core_port() {
        fn assert_implementation<T: AuthenticationStore + Send + Sync>() {}
        assert_implementation::<DynamoAuthenticationStore>();
    }
}
