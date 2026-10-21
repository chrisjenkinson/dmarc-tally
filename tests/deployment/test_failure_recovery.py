"""Static contract for independent EventBridge and Lambda failure recovery.

These tests guard template intent. CloudFormation lint checks schema; a live
failure/replay test in the isolated smoke stack remains mandatory before use.
"""
from pathlib import Path
import re
import unittest

TEMPLATE = (Path(__file__).resolve().parents[2] / "infra/smoke-ingestion.yaml").read_text()


def resource(name):
    """Limit assertions to one top-level CloudFormation resource."""
    pattern = rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|^Outputs:|\Z)"
    match = re.search(pattern, TEMPLATE)
    if match is None:
        raise AssertionError(f"Missing CloudFormation resource: {name}")
    return match.group(1)


class IngestionFailureRecoveryTests(unittest.TestCase):
    def test_eventbridge_has_separate_failure_queue_and_scoped_sender_policy(self):
        rule = resource("IntakeObjectCreatedRule")
        self.assertIn("DeadLetterConfig:", rule)
        self.assertIn("Arn: !GetAtt EventBridgeFailureQueue.Arn", rule)
        policy = resource("EventBridgeFailureQueuePolicy")
        for expected in (
            "Type: AWS::SQS::QueuePolicy",
            "Principal:",
            "Service: events.amazonaws.com",
            "Action: sqs:SendMessage",
            "Resource: !GetAtt EventBridgeFailureQueue.Arn",
            "aws:SourceArn: !GetAtt IntakeObjectCreatedRule.Arn",
        ):
            self.assertIn(expected, policy)

    def test_lambda_has_its_own_async_failure_destination_and_send_permission(self):
        config = resource("IngestFailureInvokeConfig")
        for expected in (
            "Type: AWS::Lambda::EventInvokeConfig",
            "FunctionName: !Ref IngestFunction",
            "Qualifier: '$LATEST'",
            "MaximumRetryAttempts: 2",
            "MaximumEventAgeInSeconds: 21600",
            "OnFailure:",
            "Destination: !GetAtt LambdaFailureQueue.Arn",
        ):
            self.assertIn(expected, config)
        role = resource("IngestRole")
        self.assertIn("sqs:SendMessage", role)
        self.assertIn("Resource: !GetAtt LambdaFailureQueue.Arn", role)
        self.assertNotIn("sqs:*", role)

    def test_failed_events_are_private_encrypted_and_retained_for_replay(self):
        for name in ("EventBridgeFailureQueue", "LambdaFailureQueue"):
            queue = resource(name)
            for expected in (
                "Type: AWS::SQS::Queue",
                "DeletionPolicy: Retain",
                "UpdateReplacePolicy: Retain",
                "SqsManagedSseEnabled: true",
                "MessageRetentionPeriod: 1209600",
            ):
                self.assertIn(expected, queue)

    def test_both_failure_queues_have_backlog_alarms(self):
        for name, queue in (
            ("EventBridgeFailureBacklogAlarm", "EventBridgeFailureQueue"),
            ("LambdaFailureBacklogAlarm", "LambdaFailureQueue"),
        ):
            alarm = resource(name)
            for expected in (
                "Type: AWS::CloudWatch::Alarm",
                "Namespace: AWS/SQS",
                "MetricName: ApproximateNumberOfMessagesVisible",
                f"Value: !GetAtt {queue}.QueueName",
                "TreatMissingData: notBreaching",
                "AlarmActions:",
                "- !Ref FailureAlertTopic",
            ):
                self.assertIn(expected, alarm)

    def test_alarm_when_eventbridge_or_lambda_cannot_deliver_failed_events(self):
        eventbridge = resource("EventBridgeDlqDeliveryFailureAlarm")
        self.assertIn("MetricName: InvocationsFailedToBeSentToDlq", eventbridge)
        self.assertIn("Namespace: AWS/Events", eventbridge)
        self.assertIn("Value: !Ref IntakeObjectCreatedRule", eventbridge)
        lambda_alarm = resource("LambdaDestinationDeliveryFailureAlarm")
        self.assertIn("MetricName: DestinationDeliveryFailures", lambda_alarm)
        self.assertIn("Namespace: AWS/Lambda", lambda_alarm)
        self.assertIn("Value: !Ref IngestFunction", lambda_alarm)
        for alarm in (eventbridge, lambda_alarm):
            self.assertIn("- !Ref FailureAlertTopic", alarm)
            self.assertIn("Statistic: Sum", alarm)

    def test_cloudwatch_can_publish_to_alarm_topic_without_broad_permissions(self):
        policy = resource("FailureAlertTopicPolicy")
        for expected in (
            "Type: AWS::SNS::TopicPolicy",
            "Service: cloudwatch.amazonaws.com",
            "Action: sns:Publish",
            "Resource: !Ref FailureAlertTopic",
            "aws:SourceAccount: !Ref AWS::AccountId",
            "aws:SourceArn: !Sub",
            "alarm:${AWS::StackName}-*",
        ):
            self.assertIn(expected, policy)
        self.assertNotIn("Principal: '*'", policy)
        for alarm_name in (
            "EventBridgeFailureBacklogAlarm", "LambdaFailureBacklogAlarm",
            "EventBridgeDlqDeliveryFailureAlarm", "LambdaDestinationDeliveryFailureAlarm",
        ):
            self.assertIn("DependsOn: FailureAlertTopicPolicy", resource(alarm_name))

    def test_notifications_require_explicit_email_subscription(self):
        self.assertIn("NotificationEmail:", TEMPLATE)
        self.assertIn("HasNotificationEmail:", TEMPLATE)
        subscription = resource("FailureEmailSubscription")
        for expected in (
            "Type: AWS::SNS::Subscription",
            "Condition: HasNotificationEmail",
            "Protocol: email",
            "Endpoint: !Ref NotificationEmail",
            "TopicArn: !Ref FailureAlertTopic",
        ):
            self.assertIn(expected, subscription)

    def test_no_live_email_or_automatic_replay_added(self):
        for forbidden in (
            "AWS::SES::", "AWS::Route53::",
            "AWS::Lambda::EventSourceMapping", "s3:DeleteObject",
        ):
            self.assertNotIn(forbidden, TEMPLATE)


if __name__ == "__main__":
    unittest.main()
