# Private web CloudFormation foundation

`infra/web-private.yaml` defines the **non-public** AWS resources for the
DMARC Tally web Lambda. It can be deployed separately from the isolated S3
ingestion smoke stack without modifying that stack or existing SES receipt
rules. **No stack has been provisioned by this repository change.**

The template creates an encrypted, on-demand authentication DynamoDB table
with PK/SK and TTL on `ExpiresAt` for sessions, a private Rust
`provided.al2023` web Lambda, a seven-day CloudWatch log group, and a narrow
execution role. It creates **no public HTTP API, Function URL, Lambda
invocation permission, domain, DNS record or SES identity**.

## Inputs and existing prerequisites

The template deliberately has no default administrator, monitored domains,
verified SES sender identity, public origin, code artifact or report table.
The installer must explicitly supply:

- `CodeBucket` / `CodeKey`: private same-region S3 location of an immutable,
  reviewed `web/bootstrap.zip` from the
  `Package private web Lambda` GitHub Actions job. Check the included
  `bootstrap.sha256` before uploading; the source PR being merged is not
  permission to deploy.
- `ReportsTableName`: existing DynamoDB report table in the **same AWS
  account and region**. The web role gets only `GetItem` and `Query` on it;
  ingestion write permissions remain with the separate ingest Lambda.
- `MonitoredDomains`: comma-separated configured domain allowlist.
- `AdministratorEmail`: exactly one administrator and permitted link recipient.
- `SenderEmail`: the SES From address. `VerifiedSenderIdentity` is the
  specific verified email or parent domain IAM is allowed to use. Send rights
  additionally require `ses:FromAddress` to equal `SenderEmail` exactly.
  This template never verifies or changes an SES identity.
- `PublicOrigin`: a separately planned trusted HTTPS origin. This template
  does **not** configure that URL or provide DNS. The web binary validates
  it again at startup and rejects invalid or insecure origins.

The function also refuses to start if the authentication and reports table
names are equal. The CloudFormation-generated authentication table has a
distinct name. No S3 permission is granted to the web runtime: original-email
retrieval remains disabled until separately implemented and authorised.

## Authentication item lifespan and stack deletion

The dedicated authentication table is **retained** if the CloudFormation
stack is deleted or the table replaced. Session items use the integer
`ExpiresAt` attribute for optional DynamoDB TTL cleanup, but authorization
checks expiry on each read irrespective of cleanup timing. The fixed
`AUTH#ADMIN/LOGIN` challenge uses **`ChallengeExpiresAt`** instead,
preserving the issuance cooldown after redemption or expiry. Never change
this distinction without updating the authentication adapter.

Before creating a change set, inspect resource replacements and confirm the
intended account/region. Do not execute a change set that unexpectedly
replaces or deletes authentication/report data. Retained resources require
deliberate, separately approved cleanup if the stack is later removed.

## Validation and rollout boundary

GitHub Actions validates the template with pinned `cfn-lint` and the
static `test_web_private.py` security contract using **no AWS credentials**.
These checks do not prove the actual IAM behaviour, SES status or deployed
Lambda runtime. The future deployment must use an explicitly reviewed
CloudFormation change set and a synthetic, permission-restricted manual
Lambda invoke before live mail.

**The Lambda is not publicly reachable after this template alone.** A later
separate, reviewed AWS HTTP API payload-v2 integration must configure HTTPS,
request throttling and logs that omit full URLs/query tokens, request bodies,
Cookie/Set-Cookie headers and email addresses. The production origin and
sender identity must be confirmed before any first live sign-in email. The
same portable session checks must remain mandatory for every report route.

No AWS account changes, SES tests, DNS changes or email sends are authorised
by merging this template.
