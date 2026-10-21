# Persistent authentication storage: DynamoDB adapter

This adapter implements `tally_core::authentication::AuthenticationStore`
without changing any application or core API. It is **not** deployed. Its
repository code is independent of SES, HTTP request handling and CloudFormation.

## One small dedicated DynamoDB table

Create a private, on-demand DynamoDB table with a string partition key `PK`
and string sort key `SK`, and configure time-to-live on **`ExpiresAt`**
(Numeric Unix timestamp, seconds). Separate it from the DMARC reporting
table so that the ingestion Lambda cannot accidentally read authentication
items and IAM permissions can be independently scoped. No secondary
index, stream or scan is needed.

| Record | PK | SK | Attributes | Lifetime |
| --- | --- | --- | --- | --- |
| One installation's login challenge | `AUTH#ADMIN` | `LOGIN` | `Digest` (SHA-256 hex), `IssuedAt`, `ChallengeExpiresAt`, `Consumed` | Permanent/overwritten on new issue; **no table TTL attribute** |
| A session | `AUTH#SESSION#<sha256>` | `SESSION` | `ExpiresAt` | Expiry checked on every read; optional TTL cleanup afterward |

The session's `ExpiresAt` attribute and the challenge's
`ChallengeExpiresAt` attribute are **intentionally different**. If the
challenge used `ExpiresAt` as well, DynamoDB TTL could remove the fixed
challenge row when a link expires, potentially resetting issuance throttling.

There is no need to store an administrator email, plaintext link secret
or plaintext cookie value. The administrator email is configuration,
not a queryable attribute in this table.

## Conditional write protocol

- Issue link: one `UpdateItem` on the fixed challenge key with
  `attribute_not_exists(PK) OR IssuedAt <= now - cooldown`. On success set
  a new token digest, issue/expiry timestamps and `Consumed=false`.
  Conditional rejection means cooldown is active and causes no new email.
- Consume link: one `UpdateItem` conditioned on digest equality,
  `ChallengeExpiresAt > now` and `Consumed=false`; it sets
  `Consumed=true`. The `IssuedAt` field is retained so redeeming
  a link does not bypass the request cooldown.
- Create session: one `PutItem` with `attribute_not_exists(PK)`.
  A digest collision fails closed.
- Validate session: a single strongly consistent `GetItem` and
  `ExpiresAt > now`. Missing sessions are denied; malformed expiry values
  are an internal error and never confer access.
- Sign out: one unconditional `DeleteItem`, idempotent when the item
  does not exist.

All DynamoDB errors other than expected conditional rejections are returned
as generic `AuthError::Storage`, without credential-bearing exception
messages. Expired sessions are denied **even if the service has not yet
processed TTL deletion**. Do not retry a failed one-time challenge
redemption by creating a second session.

## Remaining tests and deployment boundaries

The Rust unit tests cover key layout, expiry and condition-expression
invariants. A dedicated `auth_dynamodb_local.rs` test also exercises actual
SDK requests, concurrent issue/consume operations, expiry, retention of
the challenge cooldown and idempotent logout using a **pinned DynamoDB Local
container**, fake AWS credentials and no AWS account. GitHub Actions runs
it in `.github/workflows/auth-dynamodb-local.yml`. When run outside that
workflow, set `DYNAMODB_LOCAL_URL` to a running local DynamoDB endpoint.
Workspace formatting, tests and strict Clippy checks remain mandatory.

This is a meaningful test of DynamoDB API semantics, but it does not verify
production IAM, table TTL configuration or deployed HTTP access controls.

Before production: implement/test a restricted CloudFormation table and
IAM role, service configuration, SES sender, OS CSPRNG, authenticated HTTP
handlers and negative access-control tests. The temporary integration
branch used for this development merges the heads of the core-auth and
existing DynamoDB report-store branches **without merging them into main**.
Rebase the adapter onto the eventual merged main branch and remove the
integration branch after its dependencies land.

No AWS account, credentials, DNS or existing mail configuration are needed
for this source change.
