"""Production DMARC ingestion must remain independent of smoke infrastructure.

Source-only safety tests; deployment is never performed by GitHub CI.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROD = (ROOT / "infra/production-ingestion.yaml").read_text()
ARTIFACTS = (ROOT / "infra/production-artifacts.yaml").read_text()
SMOKE = (ROOT / "infra/smoke-ingestion.yaml").read_text()


def resource(template, name):
    m = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|^Outputs:|\Z)",
        template,
    )
    if m is None:
        raise AssertionError(f"Missing resource {name}")
    return m.group(1)


class ProductionIngestionContract(unittest.TestCase):
    def test_production_is_not_smoke_and_has_required_inputs(self):
        self.assertIn("production", PROD)
        self.assertNotIn("isolated-smoke-test", PROD)
        self.assertNotIn("Default: example.com,example.net", PROD)
        self.assertNotIn("Default: ''", PROD)
        self.assertNotIn("HasNotificationEmail", PROD)
        self.assertIn("MonitoredDomains:", PROD)
        self.assertIn("NotificationEmail:", PROD)
        self.assertIn("CodeBucket:", PROD)
        self.assertIn("CodeKey:", PROD)
        self.assertIn("Purpose\n          Value: production", PROD)

    def test_production_intake_is_private_and_originals_expire_only_when_captured(self):
        bucket = resource(PROD, "IntakeBucket")
        for expected in (
            "Type: AWS::S3::Bucket",
            "DeletionPolicy: Retain",
            "UpdateReplacePolicy: Retain",
            "SSEAlgorithm: AES256",
            "BlockPublicAcls: true",
            "BlockPublicPolicy: true",
            "IgnorePublicAcls: true",
            "RestrictPublicBuckets: true",
            "ObjectOwnership: BucketOwnerEnforced",
            "EventBridgeEnabled: true",
            "LifecycleConfiguration:",
            "Prefix: incoming/",
            "TagFilters:",
            "- Key: captured",
            "Value: 'true'",
            "ExpirationInDays: 1",
            "Status: Enabled",
        ):
            self.assertIn(expected, bucket)
        self.assertEqual(bucket.count("ExpirationInDays:"), 1)
        self.assertNotIn("VersioningConfiguration", bucket)
        # No broad prefix-only expiration rule that would remove
        # unsupported, untagged or failed messages.
        self.assertNotIn("ExpirationDate:", bucket)

    def test_production_s3_policy_retains_https_and_ingest_has_scoped_iam(self):
        policy = resource(PROD, "IntakeBucketTlsPolicy")
        self.assertIn("aws:SecureTransport:", policy)
        self.assertIn("DenyInsecureTransport", policy)
        role = resource(PROD, "IngestRole")
        for action in (
            "s3:GetObject",
            "s3:GetObjectTagging",
            "s3:PutObjectTagging",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Query",
            "sqs:SendMessage",
        ):
            self.assertIn(action, role)
        self.assertIn("Resource: !Sub '${IntakeBucket.Arn}/incoming/*'", role)
        for forbidden in ("s3:DeleteObject", "dynamodb:Scan", "s3:*", "Resource: '*'"):
            self.assertNotIn(forbidden, role)

    def test_eventbridge_and_lambda_have_distinct_recoverable_failure_paths(self):
        rule = resource(PROD, "IntakeObjectCreatedRule")
        self.assertIn("Type: AWS::Events::Rule", rule)
        self.assertIn("State: ENABLED", rule)
        self.assertIn("prefix: incoming/", rule)
        self.assertIn("EventBridgeFailureQueue.Arn", rule)
        invoke = resource(PROD, "IngestFailureInvokeConfig")
        self.assertIn("LambdaFailureQueue.Arn", invoke)
        self.assertIn("MaximumRetryAttempts: 2", invoke)
        for queue in ("EventBridgeFailureQueue", "LambdaFailureQueue"):
            r = resource(PROD, queue)
            self.assertIn("SqsManagedSseEnabled: true", r)
            self.assertIn("MessageRetentionPeriod: 1209600", r)
            self.assertIn("DeletionPolicy: Retain", r)
        for name in (
            "EventBridgeFailureBacklogAlarm",
            "LambdaFailureBacklogAlarm",
            "EventBridgeDlqDeliveryFailureAlarm",
            "LambdaDestinationDeliveryFailureAlarm",
        ):
            alarm = resource(PROD, name)
            self.assertIn("FailureAlertTopic", alarm)
        subscription = resource(PROD, "FailureEmailSubscription")
        self.assertNotIn("Condition:", subscription)
        self.assertIn("Endpoint: !Ref NotificationEmail", subscription)

    def test_email_receiving_is_separate_and_no_public_web_is_created(self):
        for forbidden in (
            "AWS::SES::", "AWS::Route53::", "AWS::ApiGateway",
            "AWS::CloudFront::", "AWS::Lambda::Url",
            "s3:DeleteObject",
        ):
            self.assertNotIn(forbidden, PROD)

    def test_release_artifacts_bucket_is_distinct_and_retained(self):
        self.assertNotIn("isolated-smoke-test", ARTIFACTS)
        for required in (
            "AWS::S3::Bucket",
            "DeletionPolicy: Retain",
            "UpdateReplacePolicy: Retain",
            "SSEAlgorithm: AES256",
            "BlockPublicAcls: true",
            "BlockPublicPolicy: true",
            "IgnorePublicAcls: true",
            "RestrictPublicBuckets: true",
            "DenyInsecureTransport",
            "Value: production",
        ):
            self.assertIn(required, ARTIFACTS)

    def test_smoke_template_remains_separate_and_has_no_lifecycle(self):
        self.assertIn("isolated-smoke-test", SMOKE)
        self.assertNotIn("LifecycleConfiguration:", SMOKE)


if __name__ == "__main__":
    unittest.main()
