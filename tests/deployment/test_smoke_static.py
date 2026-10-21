"""Safety checks for the deliberately isolated AWS ingestion smoke stack.

cfn-lint checks CloudFormation's schema; these checks protect its scope.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SmokeTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = (ROOT / "infra/smoke-ingestion.yaml").read_text()
        cls.assets = (ROOT / "infra/smoke-artifacts.yaml").read_text()

    def test_private_assets_and_ingestion_resources(self):
        self.assertIn("AWS::S3::Bucket", self.assets)
        for resource in (
            "AWS::S3::Bucket", "AWS::DynamoDB::Table", "AWS::Lambda::Function",
            "AWS::Logs::LogGroup", "AWS::IAM::Role",
        ):
            self.assertIn(resource, self.resources)
        for property_name in (
            "CodeBucket:", "CodeKey:", "MONITORED_DOMAINS:",
            "provided.al2023", "x86_64",
        ):
            self.assertIn(property_name, self.resources)

    def test_no_ses_dns_public_http_or_automatic_s3_triggers(self):
        for forbidden in (
            "AWS::SES::", "AWS::Route53::", "AWS::ApiGateway",
            "AWS::CloudFront::", "NotificationConfiguration:",
            "FunctionUrlConfig", "s3:DeleteObject",
        ):
            self.assertNotIn(forbidden, self.resources)

    def test_data_retained_and_s3_private(self):
        for template in (self.resources, self.assets):
            self.assertIn("DeletionPolicy: Retain", template)
            self.assertIn("UpdateReplacePolicy: Retain", template)
            for line in (
                "BlockPublicAcls: true", "BlockPublicPolicy: true",
                "IgnorePublicAcls: true", "RestrictPublicBuckets: true",
                "SSEAlgorithm: AES256",
            ):
                self.assertIn(line, template)

    def test_lambda_iam_scoped_to_test_bucket_table_and_logs(self):
        for statement in (
            "ReadAndTagOnlySmokeInput", "ReadAndWriteOnlySmokeTable",
            "WriteOnlySmokeLogGroup", "Resource: !GetAtt ReportsTable.Arn",
            "Resource: !Sub 'PLACEHOLDER'",
        ):
            self.assertIn(statement.replace("PLACEHOLDER", "$" + "{IntakeBucket.Arn}/incoming/*"), self.resources)
        for forbidden in ("dynamodb:*", "iam:PassRole", "s3:DeleteObject"):
            self.assertNotIn(forbidden, self.resources)


if __name__ == "__main__":
    unittest.main()
