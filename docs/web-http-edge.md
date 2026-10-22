# HTTPS edge for the private DMARC Tally dashboard

`infra/web-http-edge.yaml` supplies the **public HTTPS interface** for
the existing, session-protected `tally-lambda` web binary. It is intentionally
a separate stack from `infra/web-private.yaml`: the latter owns the private
web Lambda, DynamoDB authentication table and scoped IAM. The edge stack
owns only a small API Gateway HTTP API and its log group.

**This is code, not a deployed API.** Creating this stack would expose the
authentication endpoints and must be explicitly approved after the private
Lambda, DNS/SES settings and access-control tests have been reviewed.

## First release: use the AWS-managed HTTPS hostname

There is no requirement to choose a custom domain, edit DNS or provision an
ACM certificate merely to use the initial dashboard. API Gateway supplies an
HTTPS endpoint of the form
`https://<api-id>.execute-api.ap-southeast-2.amazonaws.com` when deployed
in Sydney. The default stage is `$default`, so there is **no extra stage path**
in the application or redirect URLs. A later custom domain is optional, and
would require coordinating the HTTPS certificate, API mapping and the
web Lambda's trusted `PUBLIC_ORIGIN` configuration.

The stack takes one required parameter: `WebFunctionArn`, which must
identify the **existing** private web Lambda from `web-private.yaml`
in the same AWS account/region. It does not create a Lambda, DynamoDB
table, SES identity, receipt rule or IAM execution role.

API Gateway's single `$default` route proxies requests using AWS Lambda
payload **format 2.0**, as required by `tally-lambda::web_event`.
It is deliberately public at the gateway layer because login pages and
magic-link confirmation must be reachable before authentication.
**Report confidentiality rests on the existing authorization-first
`tally-web::http` application gateway**, which validates a persisted
session before any report repository read. No new business route or
authentication bypass is added by this edge stack.

## Operational and privacy controls

The `$default` stage automatically deploys changes and uses a best-effort
default route throttle of **2 requests/second, burst 5**, appropriate for a
single-administrator installation's initial traffic. These are stage/route
targets, **not per-IP guarantees** and not a WAF/anti-bot service. The core
also enforces a one-minute magic-link issuance cooldown. Revisit throttling
based on actual traffic and costs rather than introducing more infrastructure
preemptively.

The seven-day CloudWatch API access log contains **only four fields**:
request ID, route key (always `$default`), HTTP status and response
latency. It never includes URL paths, query strings, cookies, Origin,
request bodies, email addresses, user agents or response contents. This
is important because the login GET URL contains the one-time token in its
query string. The Lambda adapter itself must continue to avoid logging
the complete event or response. Review any account-level log delivery
configurations separately before deploying.

AWS's HTTP API access logging may require the CloudFormation deployment
identity to have CloudWatch Logs log-delivery permissions (including
`logs:CreateLogDelivery` / `logs:PutResourcePolicy`). These are
deployment permissions, **not** broad runtime privileges granted to the
web Lambda. Do not replace any shared regional API Gateway account-wide
logging role just to deploy this stack. Review and scope the actual
deployment permissions through the AWS change-set process.

The API-scoped `AWS::Lambda::Permission` permits invocation **only**
from the created API's execute-api ARN. The private web Lambda has its
own minimal role, defined elsewhere, and gains no S3, SES receiving or
additional database permissions here.

## Two-stage production setup (approval-gated)

1. Compile and verify immutable `web/bootstrap.zip` and
   `ingest/bootstrap.zip` artifacts. Prepare the production ingest stack,
   reports table and private web stack first, without public HTTP.
   Configure actual admin, monitored domains, verified sender identity
   and its IAM permissions.
2. In an isolated environment, manually invoke the private web Lambda
   with the existing synthetic HTTP v2 tests. Prove anonymously requested
   report data is denied before any DynamoDB report query.
3. Review an explicit CloudFormation change set for this edge template.
   Confirm the web Lambda ARN and CloudWatch log destination. **Provision
   only after approval**, knowing that the managed HTTPS hostname becomes
   publicly reachable when the `$default` stage is created.
4. Read `WebHttpsOrigin` from the edge stack's Outputs and update the
   **private web Lambda's `PUBLIC_ORIGIN` parameter** to that exact
   HTTPS origin. Do not derive it from incoming `Host`/`Forwarded`
   headers or allow arbitrary redirect destinations.
5. Confirm SES outbound sandbox/verified sending identity, then test one
   approved login email and the **real browser flow**: anonymous redirect;
   no report data before session validation; GET link prefetch does not
   consume it; same-origin explicit POST redeems once; Secure/HttpOnly
   host-only cookie; logout revokes; expired/replayed links fail; unexpected
   paths, stored-session failures, Cross-Origin POST and wrong origins
   do not disclose report content. Check URL/query/body/cookie privacy in
   CloudWatch and browser network diagnostics.
6. Verify HTTP API CloudWatch request/error metrics and throttling
   responses. Review alarm requirements with production observability.
   Revalidate the same checks when changing site hostname or auth routes.

**No deployment, DNS record, SES identity or real email is changed by
merging this CloudFormation template.** A production-ready release
still requires an approved ingestion installation, actual SES receiving
and retained original-message lifecycle configuration.
