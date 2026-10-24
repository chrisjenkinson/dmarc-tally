//! Exercise the real S3 SDK response handling without AWS credentials or services.
use aws_config::retry::RetryConfig;
use aws_sdk_s3::{
    config::{BehaviorVersion, Credentials, Region},
    Client,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tally_aws::setup_evidence::{DeliveryEvidence, ProcessingEvidence, ProcessingEvidenceStore};

struct S3Fixture {
    endpoint: String,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl S3Fixture {
    fn new(get_status: u16, get_body: String, list_status: u16, list_body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let server = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut buffer = [0; 1024];
                        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                            let length = stream.read(&mut buffer).unwrap();
                            assert!(length > 0 && request.len() < 8192);
                            request.extend_from_slice(&buffer[..length]);
                        }
                        let request = String::from_utf8(request).unwrap();
                        let (status, body) =
                            if request.lines().next().unwrap().contains("list-type=2") {
                                (list_status, list_body)
                            } else {
                                (get_status, get_body.as_str())
                            };
                        write!(stream,
                            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n{body}",
                            body.len()).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("S3 fixture accept failed: {error}"),
                }
            }
        });
        Self {
            endpoint,
            stop,
            server: Some(server),
        }
    }

    fn store(&self) -> ProcessingEvidenceStore {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("ap-southeast-2"))
            .credentials_provider(Credentials::new("fixture", "fixture", None, None, "test"))
            .endpoint_url(&self.endpoint)
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .build();
        ProcessingEvidenceStore::new(Client::from_conf(config))
    }
}

impl Drop for S3Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.take().unwrap().join().unwrap();
    }
}

const DENIED: &str = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
const EMPTY: &str = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>intake</Name><Prefix>setup/last-captured.json</Prefix><KeyCount>0</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";
const PRESENT: &str = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>intake</Name><Prefix>setup/last-captured.json</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>setup/last-captured.json</Key><Size>40</Size></Contents></ListBucketResult>";
const NEIGHBOR: &str = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>intake</Name><Prefix>setup/last-captured.json</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>setup/last-captured.json.backup</Key><Size>40</Size></Contents></ListBucketResult>";

#[tokio::test]
async fn missing_evidence_is_distinct_from_access_and_service_failures() {
    for (get_status, get_body, list_status, list_body, expected) in [
        (403, DENIED, 200, EMPTY, ProcessingEvidence::NotObserved),
        (403, DENIED, 200, NEIGHBOR, ProcessingEvidence::NotObserved),
        (403, DENIED, 200, PRESENT, ProcessingEvidence::UnableToCheck),
        (403, DENIED, 403, DENIED, ProcessingEvidence::UnableToCheck),
        (
            500,
            "<Error><Code>InternalError</Code></Error>",
            200,
            EMPTY,
            ProcessingEvidence::UnableToCheck,
        ),
        (
            404,
            "<Error><Code>NoSuchKey</Code></Error>",
            403,
            DENIED,
            ProcessingEvidence::NotObserved,
        ),
    ] {
        let fixture = S3Fixture::new(get_status, get_body.to_owned(), list_status, list_body);
        assert_eq!(
            fixture.store().inspect("intake").await,
            expected,
            "GetObject {get_status}, ListObjectsV2 {list_status}, listing {list_body}"
        );
    }
}

#[tokio::test]
async fn readable_recent_evidence_does_not_require_listing() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let fixture = S3Fixture::new(
        200,
        format!("{{\"version\":1,\"processed_at\":{now}}}"),
        403,
        DENIED,
    );
    assert_eq!(
        fixture.store().inspect("intake").await,
        ProcessingEvidence::Recent
    );
}

const EMPTY_DELIVERY: &str = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>intake</Name><Prefix>setup/end-to-end-confirmed.json</Prefix><KeyCount>0</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";
const PRESENT_DELIVERY: &str = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>intake</Name><Prefix>setup/end-to-end-confirmed.json</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>setup/end-to-end-confirmed.json</Key><Size>48</Size></Contents></ListBucketResult>";

#[tokio::test]
async fn missing_operator_confirmation_is_not_an_aws_inspection_failure() {
    for (get_status, get_body, list_status, list_body, expected) in [
        (403, DENIED, 200, EMPTY_DELIVERY, DeliveryEvidence::NotVerified),
        (403, DENIED, 200, PRESENT_DELIVERY, DeliveryEvidence::UnableToCheck),
        (403, DENIED, 403, DENIED, DeliveryEvidence::UnableToCheck),
        (500, "<Error><Code>InternalError</Code></Error>", 200, EMPTY_DELIVERY, DeliveryEvidence::UnableToCheck),
        (404, "<Error><Code>NoSuchKey</Code></Error>", 403, DENIED, DeliveryEvidence::NotVerified),
    ] {
        let fixture = S3Fixture::new(get_status, get_body.to_owned(), list_status, list_body);
        assert_eq!(
            fixture.store().inspect_delivery("intake").await,
            expected,
            "GetObject {get_status}, ListObjectsV2 {list_status}, listing {list_body}",
        );
    }
}
