"""AWS SES receipt-rule safety contract; no account, DNS or email activity.

CloudFormation syntax is also checked separately using cfn-lint.
These assertions protect the receiving boundary, not a deployed stack.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "infra" / "ses-receiving.yaml").read_text()


def resource(name):
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|^Outputs:|\Z)",
        TEMPLATE,
    )
    if not match:
        raise AssertionError(f"Missing CloudFormation resource: {name}")
    return match.group(1)


class SesReceivingRules(unittest.TestCase):
    def test_no_receiving_or_dns_activation_is_automatic(self):
        for required in (
            "ReceiptRuleSetName:",
            "ReceiptRuleName:",
            "ReceivingAddress:",
            "IntakeBucketName:",
            "EnableReceiving:",
            "Default: 'false'",
            "Enabled: !If [ReceivingEnabled, true, false]",
        ):
            self.assertIn(required, TEMPLATE)
        for forbidden in (
            "AWS::SES::ReceiptRuleSet",
            "AWS::SES::EmailIdentity",
            "AWS::Route53::",
            "AWS::S3::Bucket",
            "AWS::S3::BucketPolicy",
            "AWS::S3::BucketNotification",
            "AWS::Lambda::",
            "AWS::Events::",
            "AWS::SNS::",
            "AWS::KMS::",
        ):
            self.assertNotIn(forbidden, TEMPLATE)

    def test_one_envelope_recipient_only_and_unmodified_s3_input(self):
        rule = resource("ReportReceiptRule")
        for required in (
            "Type: AWS::SES::ReceiptRule",
            "RuleSetName: !Ref ReceiptRuleSetName",
            "Name: !Ref ReceiptRuleName",
            "Recipients:",
            "- !Ref ReceivingAddress",
            "Enabled: !If [ReceivingEnabled, true, false]",
            "ScanEnabled: true",
            "TlsPolicy: Optional",
            "S3Action:",
            "BucketName: !Ref IntakeBucketName",
            "ObjectKeyPrefix: incoming/",
            "IamRoleArn: !GetAtt SesS3DeliveryRole.Arn",
        ):
            self.assertIn(required, rule)
        # No automatic bounce/forward/SNS, Lambda invocation, extra recipients
        # or SES client-side encryption: existing parser reads raw MIME from S3.
        for forbidden in (
            "KmsKeyArn:", "TopicArn:", "LambdaAction:", "BounceAction:",
            "SNSAction:", "StopAction:",
        ):
            self.assertNotIn(forbidden, rule)

    def test_receiving_role_can_only_write_to_existing_incoming_prefix(self):
        role = resource("SesS3DeliveryRole")
        for required in (
            "Service: ses.amazonaws.com",
            "Action: sts:AssumeRole",
            "aws:SourceAccount: !Ref 'AWS::AccountId'",
            "aws:SourceArn: !Sub",
            "receipt-rule-set/${ReceiptRuleSetName}:receipt-rule/${ReceiptRuleName}",
            "Action: s3:PutObject",
            "arn:${AWS::Partition}:s3:::${IntakeBucketName}/incoming/*",
        ):
            self.assertIn(required, role)
        for forbidden in (
            "s3:GetObject", "s3:DeleteObject", "s3:PutBucketPolicy",
            "s3:*", "Resource: '*'", "Principal: '*'", "kms:",
            "iam:PassRole",
        ):
            self.assertNotIn(forbidden, role)

    def test_recipient_validation_allows_normal_addresses_and_rejects_spaces(self):
        parameters = TEMPLATE.split("Parameters:", 1)[1].split("Conditions:", 1)[0]
        recipient = re.search(
            r"(?ms)^  ReceivingAddress:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|\Z)",
            parameters,
        )
        self.assertIsNotNone(recipient)
        allowed = re.search(r"AllowedPattern: '([^']+)'", recipient.group(1))
        self.assertIsNotNone(allowed)
        self.assertIsNotNone(re.fullmatch(allowed.group(1), "reports@sub.example.com"))
        self.assertIsNone(re.fullmatch(allowed.group(1), "reports invalid@example.com"))

    def test_no_default_real_address_or_rule_set(self):
        params = TEMPLATE.split("Parameters:", 1)[1].split("Conditions:", 1)[0]
        for name in ("ReceiptRuleSetName", "ReceivingAddress", "IntakeBucketName"):
            param = re.search(
                rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|\Z)",
                params,
            )
            self.assertIsNotNone(param)
            self.assertNotIn("Default:", param.group(1))
        self.assertNotIn("example.com", TEMPLATE)
        self.assertNotIn("amazonaws.com:25", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
