# Private HTTP Lambda (source implementation)

The Rust `tally-lambda` binary `web` is the composition root for the
portable authenticated HTTP gateway. It accepts **only HTTP API Gateway v2
or Lambda Function URL 2.0 events**. There is no deployment, endpoint,
custom domain or DNS configuration in this change.

## Application wiring

At Lambda startup, validate these environment variables:

| Environment key | Meaning |
| --- | --- |
| `AUTH_TABLE` | Dedicated DynamoDB authentication table (PK and SK strings; optional TTL on `ExpiresAt` for sessions only) |
| `REPORTS_TABLE` | Existing DynamoDB DMARC report table; must differ from `AUTH_TABLE` |
| `MONITORED_DOMAINS` | Comma-separated monitored domain allowlist |
| `ADMIN_EMAIL` | Exactly one configured administrator |
| `SES_FROM_EMAIL` | Verified sending identity/address for SES outbound mail |
| `PUBLIC_ORIGIN` | Absolute trusted HTTPS origin, e.g. `https://reports.example.invalid`, with no path, query, userinfo or fragment |

The entry point constructs one `DynamoAuthenticationStore`, one
`DynamoReportRepository`, one `SesEmailSender`, the existing
`OsTokenSource` and `SiteOrigin`. All decisions about email issuance,
single-use challenges, origin checks, session validation, CSRF and
report-query authorization remain in `tally-web::http::handle`, rather
than being duplicated in the Lambda adapter.

`web_event::handle_http_v2` decodes the AWS event into the portable
request, rejecting non-v2 envelopes, invalid body encoding, overly long
fields, oversized header collections and ambiguous duplicate header/cookie
sources. It supports HTTP API v2's `cookies` array as well as a single
Cookie header (not both). It encodes `Set-Cookie` using the HTTP API v2
**response cookies array**, with Secure, HttpOnly, SameSite and Path
attributes provided by the portable gateway.

The session clock comes from the Lambda runtime, **never** from an
incoming request field. Neither event payloads nor responses may be
logged because they can contain raw magic links, email addresses and
session cookies.

## Routes and access controls

`GET /auth/login`, `POST /auth/request`,
`GET /auth/confirm?token=...`, `POST /auth/confirm` and
`POST /auth/logout` use the same portable gateway that was previously
unit-tested. Opening a magic link with GET is non-consuming; a deliberate
same-origin POST is required to issue the session cookie.

`GET /` lists reports only after authorization against DynamoDB.
`/reports/...` currently returns an authenticated 404: report details and
original MIME downloads have **not** been wired up. Unauthenticated
report requests never invoke `ReportRepository`. There is no test-mode
session bypass or anonymous reporting path.

All application responses include `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and a
restrictive content-security policy. The event decoder returns generic
HTTP 400 errors for invalid transports without echoing credentials.

## Before any public or production deployment

- Configure a **private** Lambda role with narrowly scoped DynamoDB
  permissions for the two distinct tables, `ses:SendEmail` only for the
  configured SES sender identity, and the minimum CloudWatch log rights.
  No S3 access is needed for the web Lambda until an authenticated original
  retrieval feature actually exists. No SES receipt-rule changes are implied.
- Provision HTTPS hosting/API Gateway through a **separate reviewed
  CloudFormation change set**. Enable server-side request limits/throttling.
  Do not trust forwarded host headers; configuration must match the actual
  public HTTPS origin.
- Disable any access logging of auth query strings (magic-link token),
  full request bodies, Cookie and Set-Cookie headers. Neither GitHub CI nor
  application logs may expose these values.
- Smoke-test anonymous denial, login email delivery, scanner-safe landing
  GET, explicit POST, expired/replayed links, logout, storage/SES failures,
  throttling and CSRF in an isolated approved stack. Verify cross-origin
  behaviours through a real browser and actual HTTP API v2 transport.
- **Do not deploy an unauthenticated public Function URL.** The edge must
  enforce appropriate public request limits, HTTPS and observability before
  exposing the login endpoints. Security review of edge configuration is
  distinct from source-code compilation.

No AWS resources, credentials, DNS records or live emails are changed by
building this binary.
