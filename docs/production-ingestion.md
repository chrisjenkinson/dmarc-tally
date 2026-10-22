# Production DMARC ingestion infrastructure

These are **source-only, separately deployable** CloudFormation stacks for
production report intake. Neither template deploys itself or changes SES
receiving, DNS or the public dashboard:

| Template | Creates |
| --- | --- |
| `infra/production-artifacts.yaml` | Retained, encrypted and private S3 bucket for approved immutable ingest/web Lambda ZIPs. |
| `infra/production-ingestion.yaml` | Private SES destination intake bucket, on-demand DynamoDB report table, Rust ingest Lambda, S3 → EventBridge rule, bounded CloudWatch logs, separate failure DLQs/alarms and required SNS alarm subscription. |

The production ingestion stack is deliberately separate from the isolated
synthetic `smoke-ingestion.yaml`. Both use the same successfully tested
event flow and permissions. This is a little CloudFormation duplication,
but preserves a hard operational boundary: updating or deleting the smoke
stack must never affect live DMARC reports.

## Required installation inputs

`production-ingestion.yaml` has **no monitored-domain or alarm-recipient
defaults**. Supply an explicit list of monitored domains, the intended
alerts mailbox, and the S3 location of an immutable, reviewed
`ingest/bootstrap.zip` from GitHub's packaging workflow.
The production artifacts bucket must be in the same AWS region and account
as the Lambda that loads from it. Use version-specific, content-hash-based
S3 keys, verify the `bootstrap.sha256` checksum, and retain prior versions
for rollback.

CloudFormation Outputs include the private intake bucket, reports table,
ingest Lambda name and recovery queues; pass those outputs to the separate
`ses-receiving.yaml` and `web-private.yaml` stacks. The exact SES address
and receiving rule are decided **later**; the ingestion stack never changes
SES, MX, `rua` authorization or DNS.

The alarm email subscription is **required**, but SNS still sends the
recipient a confirmation email. Successful stack creation does not prove
alerts are delivered—confirm the subscription and deliberately test both
failure boundaries before relying on it.

## Incoming MIME retention and privacy

The production S3 bucket is encrypted with SSE-S3, disallows public ACLs
and policies, enforces bucket-owner-only object ownership and denies HTTP
transport. It has an EventBridge S3 Object Created notification. The
Lambda role has `GetObject`, `GetObjectTagging`, and `PutObjectTagging`
only for `incoming/*`, not `DeleteObject`; report persistence is to its
own DynamoDB table.

On successful *complete* persistent capture of every supported report in
a MIME message, the ingest Lambda adds `captured=true` to that exact S3
object. The production bucket has **one** lifecycle rule that expires only
objects under `incoming/` with that tag, one day after **object creation**
(rounded and applied asynchronously by S3). S3 checks tags again before
deleting; it does not guarantee deletion at precisely 24 hours. An older
object reprocessed and tagged later can become eligible for deletion
immediately—because all its structured report data is already persisted.

Unsupported attachments, malformed or oversized emails, partial imports,
and S3/DynamoDB failures do **not** carry the `captured=true` marker and
therefore have **no automatic expiry in this stack**. They need review
or controlled cleanup, not blanket retention policy or unattended deletion.
The bucket and table have `DeletionPolicy: Retain` /
`UpdateReplacePolicy: Retain`. Retention on stack deletion does **not**
disable an already-configured S3 lifecycle rule. This behaviour is
important when decommissioning the stack or retaining investigative email.

The production bucket has no versioning enabled by these templates. If
S3 versioning is enabled separately, lifecycle and noncurrent-version
retention must be reviewed afresh before using this release.

## Rollout — explicit approval gates

1. Confirm the intended AWS account/region, existing SES setup and smoke
   environment. Read current CloudFormation stacks. Inspect/approve
   separate production artifacts and ingestion CloudFormation change
   sets—ensure **no replacement or deletion** of durable data.
2. Upload one immutable, checksummed `ingest/bootstrap.zip` into the
   private production artifacts bucket under a new versioned S3 key.
   Provision the production ingestion stack with the expected artifact
   reference, monitored domains and alerts email. Do not reuse smoke
   table/bucket names or real-account report fixtures.
3. **Before enabling SES** manually place a sanitised, synthetic DMARC
   MIME email under a new production `incoming/` test key in this
   *approved test phase* and verify S3 → EventBridge → Lambda →
   DynamoDB/record persistence and `captured=true` tagging. Check
   replays, malformed/unsupported retention and special S3 object keys
   (`+`, `%`) using the native EventBridge payload.
4. Verify both SQS failure destinations, alarms, SNS subscription and a
   safe manually approved replay of an undelivered event. Never bulk-purge
   the queues; retain source originals until resolution. Confirm untagged
   malformed messages remain available.
5. Provision the separate `web-private.yaml` Lambda with **read-only**
   access to this reports table, its separate authentication table, one
   verified SES sender and the monitored domain allowlist. The web
   HTTPS API edge and trusted origin are independent, reviewed changes.
6. Create and review the **disabled** `ses-receiving.yaml` receipt rule
   for the exact mailbox on a verified dedicated receiving subdomain.
   Check active SES rule-set conflicts, MX and external DMARC `rua`
   authorization. Only after the ingestion stack and failures pass
   tests should the rule and DNS be enabled by explicit approval.
7. Verify one real inbound report end-to-end, the associated report
   data in the authenticated browser dashboard, IAM/log privacy,
   expected latency and costs. Only then direct monitored domains'
   ongoing DMARC aggregate reports to the new recipient.
8. Keep immutable previous Lambda artifacts for rollback. Changes to
   DynamoDB schema, email retention or S3 event semantics require
   separate review and recovery tests.

**Deferred:** Original MIME download is intentionally unavailable from
the dashboard, and individual report-detail HTTP views still require
their separate work. The initial overview and source ingestion may be
smoke-tested independently of that UI enhancement.

No AWS account credentials are used by these static CI tests, and no
production stack or SES/DNS change is made simply by merging the templates.
