"""Conservative source contract for a *private*, non-public web Lambda stack.

These assertions are intentionally static. cfn-lint additionally validates
schema; an isolated CloudFormation change set/live role test is still needed
before any AWS provisioning.
"""
from pathlib import Path
import re
import unittest

TEMPLATE = (Path(__file__).resolve().parents[2] / "infra/web-private.yaml").read_text()


def resource(name):
    pattern = rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|^Outputs:|\Z)"
    match = re.search(pattern, TEMPLATE)
    if match is None:
        raise AssertionError(f"Missing CloudFormation resource: {name}")
    return match.group(1)


class PrivateWebFoundationContract(unittest.TestCase):
    def test_no_public_network_or_live_email_infrastructure(self):
        for forbidden in (
            "AWS::ApiGateway", "AWS::Lambda::Url", "AWS::Lambda::Permission",
            "AWS::SES::", "AWS::Route53::", "AWS::S3::Bucket",
            "AWS::Events::", "AWS::CloudFront::", "AWS::WAF",
        ):
            self.assertNotIn(forbidden, TEMPLATE)
        self.assertIn("No public HTTP", TEMPLATE)

    def test_authentication_table_is_distinct_encrypted_and_retained(self):
        table = resource("AuthTable")
        for expected in (
            "Type: AWS::DynamoDB::Table",
            "DeletionPolicy: Retain",
            "UpdateReplacePolicy: Retain",
            "BillingMode: PAY_PER_REQUEST",
            "SSEEnabled: true",
            "AttributeName: PK", "AttributeName: SK",
            "AttributeName: ExpiresAt", "Enabled: true",
        ):
            self.assertIn(expected, table)
        self.assertNotIn("AttributeName: ChallengeExpiresAt", table)
        self.assertNotIn("GlobalSecondaryIndexes", table)

    def test_iam_permissions_are_capability_scoped_and_read_only_for_reports(self):
        role = resource("WebRole")
        for expected in (
            "Service: lambda.amazonaws.com",
            "dynamodb:UpdateItem", "dynamodb:PutItem",
            "dynamodb:DeleteItem", "dynamodb:GetItem",
            "Resource: !GetAtt AuthTable.Arn",
            "dynamodb:Query",
            "Resource: !Sub",
            "ses:SendEmail",
            "ses:FromAddress: !Ref SenderEmail",
            "ForAllValues:StringEqualsIgnoreCase:",
            "ses:Recipients: !Ref AdministratorEmail",
            "ses:Recipients: 'false'",
            "identity/${VerifiedSenderIdentity}",
            "logs:CreateLogStream", "logs:PutLogEvents",
        ):
            self.assertIn(expected, role)
        for forbidden in (
            "dynamodb:Scan", "dynamodb:*", "ses:*",
            "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
            "logs:CreateLogGroup", "Action: '*'", "Resource: '*'",
        ):
            self.assertNotIn(forbidden, role)
        # Read-only reporting: report permissions must NOT share an IAM
        # statement with authentication writes.
        report_read = re.search(r"Sid: ReadOnlyDMARCReports\n(.*?)(?=\n              - Sid:|\n      Tags:)", role, re.S)
        self.assertIsNotNone(report_read)
        self.assertIn("dynamodb:GetItem", report_read.group(1))
        self.assertIn("dynamodb:Query", report_read.group(1))
        self.assertNotIn("dynamodb:PutItem", report_read.group(1))
        self.assertNotIn("dynamodb:UpdateItem", report_read.group(1))
        self.assertNotIn("dynamodb:DeleteItem", report_read.group(1))

    def test_private_web_binary_is_wired_only_to_explicit_installation_config(self):
        function = resource("WebFunction")
        for expected in (
            "Type: AWS::Lambda::Function",
            "Runtime: provided.al2023",
            "Handler: bootstrap",
            "- x86_64",
            "S3Bucket: !Ref CodeBucket",
            "S3Key: !Ref CodeKey",
            "Role: !GetAtt WebRole.Arn",
            "AUTH_TABLE: !Ref AuthTable",
            "REPORTS_TABLE: !Ref ReportsTableName",
            "ADMIN_EMAIL: !Ref AdministratorEmail",
            "SES_FROM_EMAIL: !Ref SenderEmail",
            "PUBLIC_ORIGIN: !Ref PublicOrigin",
            "MONITORED_DOMAINS: !Ref MonitoredDomains",
        ):
            self.assertIn(expected, function)
        self.assertNotIn("INTAKE_BUCKET", function)
        self.assertNotIn("FunctionUrlConfig", function)
        self.assertNotIn("VpcConfig", function)

    def test_verified_sender_and_auth_expiration_are_not_assumed(self):
        self.assertIn("VerifiedSenderIdentity:", TEMPLATE)
        self.assertIn("SenderEmail:", TEMPLATE)
        self.assertIn("AdministratorEmail:", TEMPLATE)
        self.assertIn("PublicOrigin:", TEMPLATE)
        self.assertIn("ReportsTableName:", TEMPLATE)
        self.assertIn("CodeBucket:", TEMPLATE)
        self.assertIn("CodeKey:", TEMPLATE)
        self.assertIn("TimeToLiveSpecification:", TEMPLATE)
        self.assertNotIn("Default: admin@", TEMPLATE)
        self.assertNotIn("Default: http://", TEMPLATE)

    def test_diagnostics_have_bounded_retention_and_no_secret_outputs(self):
        log = resource("WebLogGroup")
        self.assertIn("RetentionInDays: 7", log)
        for sensitive in ("AdministratorEmail", "SenderEmail", "AUTH_TABLE", "PublicOrigin"):
            outputs = TEMPLATE.split("\nOutputs:", 1)[-1]
            self.assertNotIn("Value: !Ref " + sensitive, outputs)


if __name__ == "__main__":
    unittest.main()
