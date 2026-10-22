"""Security contract for a small HTTPS edge to the private web Lambda.

The edge is *publicly routable*, but the Lambda's portable HTTP gateway
checks DynamoDB sessions before reading any report data. No deployments
or AWS credentials are involved in these static tests.
"""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "infra" / "web-http-edge.yaml").read_text()


def resource(name):
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z][A-Za-z0-9]*:\n|^Outputs:|\Z)",
        TEMPLATE,
    )
    if match is None:
        raise AssertionError(f"Missing CloudFormation resource {name}")
    return match.group(1)


class HttpApiEdgeTests(unittest.TestCase):
    def test_edge_reuses_exact_existing_web_lambda_without_data_permissions(self):
        self.assertIn("WebFunctionArn:", TEMPLATE)
        for forbidden in (
            "AWS::Lambda::Function", "AWS::Lambda::Url",
            "AWS::DynamoDB::", "AWS::S3::", "AWS::SES::",
            "AWS::Route53::", "AWS::CertificateManager::",
            "AWS::IAM::Role", "AWS::ApiGatewayV2::Authorizer",
            "AWS::CloudFront::", "AWS::WAF",
        ):
            self.assertNotIn(forbidden, TEMPLATE)
        api = resource("WebHttpApi")
        self.assertIn("ProtocolType: HTTP", api)
        self.assertIn("DisableExecuteApiEndpoint: false", api)
        self.assertNotIn("CorsConfiguration:", api)

    def test_single_gateway_proxy_is_exactly_lambda_payload_v2(self):
        integration = resource("WebLambdaProxy")
        for item in (
            "IntegrationType: AWS_PROXY",
            "IntegrationMethod: POST",
            "PayloadFormatVersion: '2.0'",
            "WebFunctionArn",
            "IntegrationUri: !Sub",
        ):
            self.assertIn(item, integration)
        route = resource("WebDefaultRoute")
        self.assertIn("RouteKey: '$default'", route)
        self.assertIn("Target: !Sub 'integrations/${WebLambdaProxy}'", route)
        self.assertIn("AuthorizationType: NONE", route)
        # Only application HTTP code determines which route is public and
        # revalidates sessions before all report reads.

    def test_lambda_can_be_invoked_only_by_this_api(self):
        permission = resource("PermitOnlyThisApiInvoke")
        for item in (
            "Type: AWS::Lambda::Permission",
            "Action: lambda:InvokeFunction",
            "Principal: apigateway.amazonaws.com",
            "FunctionName: !Ref WebFunctionArn",
            "SourceArn: !Sub",
            ":${WebHttpApi}/*/*",
        ):
            self.assertIn(item, permission)
        self.assertNotIn("Principal: '*'", permission)

    def test_stage_has_throttling_and_no_payload_tracing(self):
        stage = resource("WebDefaultStage")
        for item in (
            "StageName: '$default'",
            "AutoDeploy: true",
            "ThrottlingBurstLimit: 5",
            "ThrottlingRateLimit: 2",
            "DefaultRouteSettings:",
        ):
            self.assertIn(item, stage)
        self.assertNotIn("DataTraceEnabled: true", TEMPLATE)

    def test_access_log_format_never_contains_user_input(self):
        stage = resource("WebDefaultStage")
        log_group = resource("EdgeLogGroup")
        self.assertIn("RetentionInDays: 7", log_group)
        self.assertIn("AccessLogSettings:", stage)
        self.assertIn("DestinationArn: !GetAtt EdgeLogGroup.Arn", stage)
        pattern = re.search(r"(?m)^        Format: '([^']+)'$", stage)
        self.assertIsNotNone(pattern, "Expected auditable one-line JSON logging format")
        raw = pattern.group(1)
        self.assertEqual(set(json.loads(raw)), {"requestId", "status", "routeKey", "responseLatency"})
        variables = set(re.findall(r"\$context\.[A-Za-z.]+", raw))
        self.assertEqual(
            variables,
            {"$context.requestId", "$context.status", "$context.routeKey",
             "$context.responseLatency"},
        )
        for disallowed in (
            "path", "query", "email", "cookie", "userAgent", "sourceIp",
            "requestHeader", "requestBody", "integrationError",
            "authorization", "httpMethod",
        ):
            self.assertNotIn(disallowed, raw)

    def test_outputs_include_only_generated_https_origin(self):
        self.assertIn("WebHttpsOrigin:", TEMPLATE)
        outputs = TEMPLATE.split("\nOutputs:", 1)[1]
        self.assertIn("https://${WebHttpApi}.execute-api.${AWS::Region}.amazonaws.com", outputs)
        self.assertNotIn("apiKey", outputs)


if __name__ == "__main__":
    unittest.main()
