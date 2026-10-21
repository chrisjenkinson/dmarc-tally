//! Real conditional-write tests against a local DynamoDB server.
//!
//! GitHub Actions runs this with a pinned DynamoDB Local Docker service and
//! fake AWS credentials. Without DYNAMODB_LOCAL_URL, the test is skipped.
//! This never contacts a real AWS account.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use aws_sdk_dynamodb::{types::AttributeValue as Value, Client};
use tally_aws::auth_store::DynamoAuthenticationStore;
use tally_core::authentication::{
    AdminEmail, AuthError, Authentication, EmailSender, SecureTokenSource, LOGIN_COOLDOWN_SECONDS,
    LOGIN_TTL_SECONDS, SESSION_TTL_SECONDS,
};

const NOW: i64 = 1_800_000_000;

struct TestEntropy(AtomicU8);

impl Default for TestEntropy {
    fn default() -> Self {
        Self(AtomicU8::new(1))
    }
}
impl SecureTokenSource for TestEntropy {
    fn fresh_secret(&self) -> Result<[u8; 32], AuthError> {
        // Test-only deterministic fake. Production must use OS randomness.
        Ok([self.0.fetch_add(1, Ordering::SeqCst); 32])
    }
}

#[derive(Default)]
struct TestEmail(Mutex<Vec<String>>);

impl TestEmail {
    fn tokens(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl EmailSender for TestEmail {
    async fn send_sign_in_link(&self, _: &str, token: &str) -> Result<(), AuthError> {
        self.0.lock().unwrap().push(token.to_owned());
        Ok(())
    }
}

async fn create_private_table(client: &Client, table: &str) {
    let pk = AttributeDefinition::builder()
        .attribute_name("PK")
        .attribute_type(ScalarAttributeType::S)
        .build()
        .expect("partition schema");
    let sk = AttributeDefinition::builder()
        .attribute_name("SK")
        .attribute_type(ScalarAttributeType::S)
        .build()
        .expect("sort schema");
    let partition_key = KeySchemaElement::builder()
        .attribute_name("PK")
        .key_type(KeyType::Hash)
        .build()
        .expect("partition key");
    let sort_key = KeySchemaElement::builder()
        .attribute_name("SK")
        .key_type(KeyType::Range)
        .build()
        .expect("sort key");

    client
        .create_table()
        .table_name(table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(pk)
        .attribute_definitions(sk)
        .key_schema(partition_key)
        .key_schema(sort_key)
        .send()
        .await
        .expect("create isolated local authentication table");

    for attempt in 0..40 {
        if client
            .describe_table()
            .table_name(table)
            .send()
            .await
            .is_ok()
        {
            return;
        }
        assert!(attempt < 39, "local table never became available");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn concurrent_login_and_session_workflows_use_atomic_dynamodb_operations() {
    let Ok(endpoint) = std::env::var("DYNAMODB_LOCAL_URL") else {
        eprintln!("Skipping: DYNAMODB_LOCAL_URL is not configured");
        return;
    };

    // Uses the official SDK's local test credentials, not the AWS account.
    let config = aws_config::defaults(BehaviorVersion::latest())
        .test_credentials()
        .region("ap-southeast-2")
        .endpoint_url(endpoint)
        .load()
        .await;
    let client = Client::new(&config);
    for attempt in 0..40 {
        if client.list_tables().send().await.is_ok() {
            break;
        }
        assert!(attempt < 39, "DynamoDB Local did not become ready");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let table = format!("DmarcTallyAuth{}", std::process::id());
    create_private_table(&client, &table).await;
    let store = DynamoAuthenticationStore::new(client.clone(), &table);
    let administrator = AdminEmail::parse("admin@example.com").unwrap();
    let entropy = TestEntropy::default();
    let sender = TestEmail::default();
    let auth = Authentication::new(&administrator, &store, &sender, &entropy);

    // Concurrent requests must produce a single email and a single stored
    // challenge, not two concurrently redeemable secrets.
    let (one, two) = tokio::join!(
        auth.request_sign_in("admin@example.com", NOW),
        auth.request_sign_in("ADMIN@example.com", NOW)
    );
    one.unwrap();
    two.unwrap();
    assert_eq!(sender.tokens().len(), 1);
    let first = sender.tokens().pop().unwrap();

    // Validate the real DynamoDB item: challenge expiry is not the TTL field,
    // because an expiring fixed row would reset the email cooldown.
    let challenge = client
        .get_item()
        .table_name(&table)
        .consistent_read(true)
        .key("PK", Value::S("AUTH#ADMIN".into()))
        .key("SK", Value::S("LOGIN".into()))
        .send()
        .await
        .unwrap();
    let row = challenge.item().expect("challenge row");
    assert!(row.contains_key("ChallengeExpiresAt"));
    assert!(!row.contains_key("ExpiresAt"));
    let digest = row["Digest"].as_s().unwrap();
    assert_ne!(digest, &first, "must persist hash, not raw sign-in token");
    assert_eq!(row["IssuedAt"].as_n().unwrap(), &NOW.to_string(),);

    let (a, b) = tokio::join!(
        auth.redeem_sign_in(&first, NOW + 1),
        auth.redeem_sign_in(&first, NOW + 1)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(
        usize::from(a.is_some()) + usize::from(b.is_some()),
        1,
        "exactly one simultaneous redemption must succeed",
    );
    let session = a.or(b).expect("one redemption");
    let cookie = session.cookie_value();
    assert!(auth
        .redeem_sign_in(&first, NOW + 1)
        .await
        .unwrap()
        .is_none());
    assert!(auth.is_authenticated(&cookie, NOW + 1).await.unwrap());

    // Separate adapter object proves tokens are persisted, not process-local.
    let next_store = DynamoAuthenticationStore::new(client.clone(), &table);
    let next_auth = Authentication::new(&administrator, &next_store, &sender, &entropy);
    assert!(next_auth.is_authenticated(&cookie, NOW + 1).await.unwrap());
    assert!(!next_auth
        .is_authenticated(&cookie, NOW + 1 + SESSION_TTL_SECONDS)
        .await
        .unwrap());

    // Redemption must preserve last-issued timestamp and retain cooldown.
    auth.request_sign_in("admin@example.com", NOW + LOGIN_COOLDOWN_SECONDS - 1)
        .await
        .unwrap();
    assert_eq!(sender.tokens().len(), 1);
    auth.request_sign_in("admin@example.com", NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap();
    assert_eq!(sender.tokens().len(), 2);
    let second = sender.tokens()[1].clone();
    assert_ne!(first, second);
    assert!(auth
        .redeem_sign_in(&first, NOW + LOGIN_COOLDOWN_SECONDS)
        .await
        .unwrap()
        .is_none());

    assert!(auth
        .redeem_sign_in(&second, NOW + LOGIN_COOLDOWN_SECONDS + LOGIN_TTL_SECONDS)
        .await
        .unwrap()
        .is_none());

    auth.sign_out(&cookie).await.unwrap();
    auth.sign_out(&cookie).await.unwrap();
    assert!(!next_auth.is_authenticated(&cookie, NOW + 1).await.unwrap());

    client
        .delete_table()
        .table_name(&table)
        .send()
        .await
        .unwrap();
}
