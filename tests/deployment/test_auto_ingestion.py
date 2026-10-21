"""Contract tests for automatic S3 event routing in the isolated smoke stack.

Checks the CloudFormation wiring statically before any AWS-side deployment.
The actual S3 -> EventBridge -> Lambda integration is separately smoke-tested.
"""
from pathlib import Path
import unittest

TEMPLATE = (Path(__file__).resolve().parents[2] / "infra/smoke-ingestion.yaml").read_text()


class AutomaticS3IngestionTests(unittest.TestCase):
    def test_s3_events_are_enabled_without_direct_s3_lambda_notification(self):
        self.assertIn("EventBridgeConfiguration:", TEMPLATE)
        self.assertIn("EventBridgeEnabled: true", TEMPLATE)
        self.assertNotIn("LambdaConfigurations:", TEMPLATE)

    def test_only_created_objects_in_incoming_prefix_reach_lambda(self):
        self.assertIn("Type: AWS::Events::Rule", TEMPLATE)
        self.assertIn("State: ENABLED", TEMPLATE)
        self.assertIn("source:", TEMPLATE)
        self.assertIn("- aws.s3", TEMPLATE)
        self.assertIn("detail-type:", TEMPLATE)
        self.assertIn("- Object Created", TEMPLATE)
        self.assertIn("name: [!Ref IntakeBucket]", TEMPLATE)
        self.assertIn("prefix: incoming/", TEMPLATE)
        self.assertIn("Arn: !GetAtt IngestFunction.Arn", TEMPLATE)

    def test_rule_transforms_event_into_existing_s3_event_contract(self):
        self.assertIn("InputTransformer:", TEMPLATE)
        self.assertIn("bucket: '$.detail.bucket.name'", TEMPLATE)
        self.assertIn("key: '$.detail.object.key'", TEMPLATE)
        self.assertIn('eventSource', TEMPLATE)
        self.assertIn('ObjectCreated:Put', TEMPLATE)
        self.assertIn('Records', TEMPLATE)

    def test_only_the_named_event_rule_can_invoke_lambda(self):
        self.assertIn("Type: AWS::Lambda::Permission", TEMPLATE)
        self.assertIn("Principal: events.amazonaws.com", TEMPLATE)
        self.assertIn("Action: lambda:InvokeFunction", TEMPLATE)
        self.assertIn("SourceArn: !GetAtt IntakeObjectCreatedRule.Arn", TEMPLATE)

    def test_no_ses_dns_new_public_access_or_automatic_deletion(self):
        for forbidden in (
            "AWS::SES::", "AWS::Route53::", "AWS::ApiGateway",
            "AWS::CloudFront::", "LifecycleConfiguration:",
            "s3:DeleteObject",
        ):
            self.assertNotIn(forbidden, TEMPLATE)
        self.assertIn("DeletionPolicy: Retain", TEMPLATE)
        self.assertIn("BlockPublicPolicy: true", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
