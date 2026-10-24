# Administrator setup-status page

The private `GET /setup` route is protected by the **same durable session
check** as the report overview. Any anonymous or expired session is redirected
to sign-in **before** an inspection is run. Only an authenticated, explicit
page request invokes the `SetupInspector` port; ordinary report views do
not poll external services.

The page distinguishes four states:

- **Ready**: the particular listed check has positive evidence. It does not
  automatically imply the entire DMARC receiving path works.
- **Action required**: observed configuration is missing or incorrect.
- **Not verified**: the check has not been performed; absence of reports is
  not evidence of a broken receiving address.
- **Unable to check**: the inspection could not complete; errors never mean
  Ready and must not expose raw AWS responses.

The setup page shows a trusted UTC inspection timestamp, counts of checks requiring action or further evidence, and the configured receiving mailbox, monitored domains and
setup steps. On an authenticated visit to `/setup`, the host performs two
read-only SES v2 `GetEmailIdentity` calls for the configured sender identity
and the *exact* receiving address domain. These checks report verified
identity state; a sending identity must also be enabled for sending.
They never send email or change configuration. AWS API failures (including
missing or inaccessible identity records) remain **Unable to check**, not
Ready. Verification of a parent identity can apply to subdomains, so
exact-domain verification status is not conclusive proof of mail delivery.

The on-demand **classic SES** `DescribeActiveReceiptRuleSet` inspector
checks whether the configured receipt rule set is active; the expected
receipt rule exists and is enabled; it targets only the configured address;
and its single S3 action writes to the configured production intake bucket
and `incoming/` prefix, with no SES client-side KMS encryption and a
configured SES delivery IAM role. The read-only API is rate-limited by AWS
to once per second; it runs only after an authenticated setup-page request.
The permission has no resource-level scope, so IAM limits it to this one
read action in the deployment region. No rule set is ever activated by
this inspector.

On successful complete ingestion (after DynamoDB persistence and the
`captured=true` tag), the ingest Lambda writes a tiny S3 marker under
`setup/last-captured.json`, containing a schema version and timestamp only.
The web Lambda may read this exact object, but not raw MIME. Its check is
**Ready** only for processing evidence observed within seven days. Old,
missing or malformed evidence never proves health. S3 EventBridge filters
only `incoming/`, so this marker cannot trigger another import. The
marker is retained independently of one-day MIME expiration and is not a
customer-facing history.

This is evidence of *processing*, **not** an SES-to-S3 delivery test:
manual S3 uploads can also be processed. End-to-end delivery is Ready
only after a **separate operator confirmation** of a controlled email test.
The administrator explicitly records that confirmation via the installation
CLI after independently checking SES receiving configuration, the matching
captured S3 object and successful processing. It is kept under
`setup/end-to-end-confirmed.json`, independently from the rolling capture
marker and one-day raw MIME lifecycle. It contains only schema version and
timestamps; it never stores the object's name or email content. The web
Lambda may read this exact object but cannot write it.

This attestation reflects an administrator-confirmed operational test, **not
cryptographic proof** that SES put the object: the existing bucket lacks
CloudTrail S3 data-event provenance. A new S3 ingestion or a healthy SES
rule alone can never create this attestation. The confirmation requires
explicit CLI consent and is not part of an unattended deployment.

After independently identifying the controlled SES test's exact
`incoming/<SES-message-id>` S3 object, use the local
`python3 scripts/install.py confirm-delivery --object-key incoming/<SES-message-id> --confirm-observed-delivery`
command **only with explicit approval**. It checks account, current active
SES rule and destination, S3 object recency and `captured=true` tagging
before storing the compact attestation. A failure makes no assertion of
success. This CLI writes **only** the named private S3 confirmation marker,
not mail, configuration, CloudFormation, or DNS. The web Lambda additionally
needs an approved stack update to read it. Do not record the message ID
or any private email contents in public issues or logs.

DNS checks use the system resolver on authenticated page requests (bounded,
read-only MX/TXT DNS queries, no third-party DoH endpoint). They inspect the
receiving hostname's MX against the expected regional SES inbound endpoint;
each monitored domain's explicitly published DMARC `rua` address; and,
where relevant, the destination `._report._dmarc.` authorisation TXT.
When a policy might be inherited or organisational-domain equivalence is
uncertain, a missing record is **Not verified**, not an assertion of
misconfiguration. NXDOMAIN/timeout/resolver failures are distinguished from
evidence of an actually wrong published record. No DNS writes occur.

A **Ready** receipt-rule status proves only these observed settings.
Earlier rules, IAM role permission issues, bucket policy, DNS MX/rua,
S3 EventBridge notification routing and ingestion can still prevent delivery.
True successful end-to-end delivery and operational alarm testing require
distinct evidence; until then, the UI marks those checks **Not verified**.

`RECEIVING_ADDRESS` is provided to the web Lambda through the generic
CloudFormation `ReceivingAddress` parameter and `scripts/install.py` from
its ignored local config, never hard-coded personal values. Existing older
web Lambda deployments with no `RECEIVING_ADDRESS` show
"Receiving address not configured" until a reviewed template upgrade.

The same setup concerns may be checked from a generic local CLI later, but
do not create customer-facing monitoring history, new DynamoDB tables,
scheduled polling or a separate setup aggregate for one administrator.

A reviewed future CloudFormation update is necessary to grant the web
Lambda narrowly scoped `ses:GetEmailIdentity` for the configured sender and
receiving-domain identities, and `ses:DescribeActiveReceiptRuleSet` in the
deployed region. The generic installer supplies identity, rule and production
intake bucket parameters from the ignored local configuration plus ingestion
stack outputs. Until a separately approved deployment, the existing Lambda
is unchanged.

The operational-notifications section checks the one configured SNS topic
for a **confirmed email subscription** and checks that all four expected
ingestion CloudWatch metric alarms exist, have actions enabled, and include
that exact topic in their alarm actions. Missing/pending subscriptions and
miswired alarms are Action required. AWS read failures are Unable to check.
The two read permissions are limited to that topic and the ingestion stack's
alarm-name prefix. No SNS Publish, alarm-state changes or email tests run.
A separate alarm **delivery test** remains Not verified until an approved
real test has been observed by the administrator.

No AWS or DNS changes are made by merging this source change. A green installation
badge must never be shown until individual checks are backed by real
evidence.
