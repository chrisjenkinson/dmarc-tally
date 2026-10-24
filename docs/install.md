# Install and operate DMARC Tally (pre-release)

DMARC Tally runs in your own AWS account. This is the **single first-install
journey**, followed by upgrades and recovery. The other documents explain the
underlying resources; they are not additional independent setup checklists.

The public repository holds source, templates and installer. Installation-
specific addresses, AWS profile/account and selected release belong in
ignored `.local/`; no second deployment repository is required.

**Never merge or run CI as permission to deploy.** Source changes cannot
change AWS or DNS. Every CloudFormation deployment needs its own reviewed
change set and explicit `apply` approval. Activation of SES and DNS edits
are separate manual decisions.

## 1. Plan the installation without disrupting mail

Use **a dedicated receiving subdomain** (e.g. `dmarc.example.org`) and
exact report address (e.g. `reports@dmarc.example.org`). Its MX can point
to SES without moving the MX for your normal mailbox. Do not replace
existing mailbox MX or current domain DMARC policy.

The local configuration identifies different roles:

| Setting | Purpose |
| --- | --- |
| `monitored_domains` | Domains whose DMARC aggregate reports the dashboard displays |
| `email.receiving` | Dedicated mailbox addressed in future DMARC `rua` and for controlled forwarding tests |
| `email.administrator` | One private dashboard administrator; receives SES magic-link login mail |
| `email.sender` / `sender_identity` | Outgoing SES login-mail address and corresponding SES verified identity |
| `email.alerts` | Destination for production failure alarms; must confirm its SNS subscription |
| `email.receipt_rule_set` / `receipt_rule_name` | Existing SES receipt rule set and exact rule expected in this region |

The receiving address is **not** a mailbox in Fastmail unless you separately
configure it that way; its DNS will route to SES after activation. Keep
the normal mail domain untouched.

Prerequisites: Python 3.11+, Git, AWS CLI v2 and a configured AWS profile
with the intended AWS account/region. For the **current source-build**
installer, also install Rust stable, Zig and cargo-lambda. Prebuilt release
bundles are not yet published. AWS must support SES receiving in the chosen
region (infrastructure and tests currently target `ap-southeast-2`).
You need permission to create reviewed CloudFormation change sets, create
the specified resources and upload verified private S3 artifacts. Receiving
and sending identities/DNS require independent SES/DNS permissions when
manually configured.

Use a **pinned commit or release tag**, not a moving `main`, for an install
or upgrade. Preserve a clean checkout: the installer verifies its exact
commit and its two Lambda ZIP checksums.

```sh
python3 scripts/install.py init
# Fill .local/production.json (never commit it).
python3 scripts/install.py check
```

The example configuration intentionally cannot deploy. Store an encrypted
backup of `.local/production.json`, which is not an AWS credentials file.
The installer does not print private settings in public CI output.

### Pre-login read-only preflight

Before attempting the first browser login, run:

```sh
python3 scripts/install.py preflight
```

This reads the selected AWS account via STS and queries SES in the configured
region. It checks sending access, configured sending-identity verification,
whether SES sandbox restrictions require the administrator address/domain to
be verified, receiving-domain identity and the expected receipt rule set.
It also identifies an active rule set belonging to another application and
earlier/broad recipient rules that need manual review. No email is sent,
receipt rule enabled, rule set activated, DNS changed or stack deployed.

Preflight also checks tools for the **currently supported source-build**
installation: Python 3.11+, Git, AWS CLI, Cargo, Zig and cargo-lambda.
It prints `READY`, `ACTION`, `LATER` or `UNKNOWN` with a concrete
next step but never outputs AWS errors or configured email addresses.
`ACTION` or `UNKNOWN` for **login prerequisites** returns a non-zero
exit code. Receiving-configuration diagnostics are advisory for first login:
an unprovisioned, inactive or conflicting receiving rule must be reviewed
**before receiving activation** but need not prevent signing in to the
dashboard. `LATER` is expected for a rule not yet provisioned/activated.
If credentials point to the wrong account, SES probes are skipped.
SES sandbox/identity checks establish *configuration*, not actual delivery:
confirm a real login message before enabling receiving.

The read-only checks require AWS permissions for
`sts:GetCallerIdentity`, SES v2 `GetAccount` and
`GetEmailIdentity`, and classic SES
`DescribeActiveReceiptRuleSet`/`DescribeReceiptRuleSet`.
Missing permission yields `UNKNOWN`, not a false green status.
The installer uses bounded AWS CLI calls and does not store another
readiness database. Repeat preflight after making necessary changes.

After configuration, `status` reads live CloudFormation stack status and
expected outputs in the configured account. It neither deploys nor enables
anything, does not require a clean checkout or compiled ZIPs, and never
prints private email addresses. It is useful on the first run, after each
approved change, and when resuming an interrupted installation:

```sh
python3 scripts/install.py status
```

The command reports which stacks are deployed, absent, incomplete or
unavailable, flags a missing ingestion output or unreconciled public web
origin, and suggests the next **manual** step. It cannot prove SES
sandbox/sender status, DNS correctness, login, end-to-end mail or alarm
delivery: use separate checks and `/setup` once signed in. A suggested
`plan` still requires its own reviewed change set and explicit `apply`.

## 2. Prepare SES sending and review SES receiving

**Before attempting login**, run `preflight` as above and verify the
configured sending identity in SES in the target region; determine whether
the SES account is in the sandbox.
Sandbox sending can require the **administrator recipient** to be verified
as well. A verified sending identity alone does not guarantee delivery; a
controlled sign-in attempt is still required.

For inbound receiving, check the active SES rule set, other rules and
their ordering **before** creating or activating your rule. Only one receipt
rule set is active per region; do not displace existing receivers. Verify
the dedicated receiving domain in SES and plan its regional MX and any
required external reporting authorisation TXT records. **Do not change the
monitored domains' `rua` yet.** The private `/setup` page will later show
read-only diagnostics; it is inaccessible until first login works.

For the security rationale, exact recipient semantics and region-specific
MX example, see [SES receiving](ses-receiving.md).

## 3. Build and deploy the application in dependency order

```sh
python3 scripts/install.py build
python3 scripts/install.py plan artifacts
# Review the CloudFormation change set carefully; then run the printed
# apply command with that exact change-set ARN.
python3 scripts/install.py apply artifacts --approve <REVIEWED_CHANGE_SET_ARN>
python3 scripts/install.py upload
```

`build` creates and validates two x86-64 Linux bootstrap ZIPs, recording
their SHA-256, immutable S3 object keys and source commit in
`.local/release.json`. `upload` checks object checksums and refuses to
overwrite different content at a release key.

There are five independent plain CloudFormation components:

| Component | Depends on | Result |
| --- | --- | --- |
| `artifacts` | — | Encrypted private retained artifact bucket |
| `ingestion` | artifacts | Private S3 intake, EventBridge/Lambda, DynamoDB reports, failure alarms and SNS |
| `web` | artifacts, ingestion | Private authenticated Lambda, retained auth state and read-only setup diagnostics |
| `edge` | web | Publicly reachable HTTPS API Gateway with authenticated private routes |
| `receiving` | ingestion | SES S3 receipt rule, **disabled on creation** |

After upload, plan, review and apply **ingestion → web → edge → web
again**. Each component uses the same two commands, for example:

```sh
python3 scripts/install.py plan ingestion
python3 scripts/install.py apply ingestion --approve <REVIEWED_CHANGE_SET_ARN>
```

Do not reuse the example ARN: `plan` prints the actual one. `plan`
creates a change set but does **not** execute it. It prints generic
resource changes only. `apply` validates the same config, source, ZIP
manifest, template, parameters and change set; it rejects deletes,
replacements and ordinary updates to durable S3/DynamoDB resources.
Explicit review is still required for other IAM/configuration changes.

When creating `edge`, `apply` additionally requires
`--allow-public-edge`. The **first web install** uses a deliberately
nonfunctional `https://bootstrap.invalid` origin because the HTTPS endpoint
does not yet exist. After `edge` is deployed, **plan and apply `web`
again** to replace that origin with the real `WebHttpsOrigin` output.
The site cannot complete login before this second web update.

For new installs and upgrades of alert diagnostics, the **ingestion**
stack must expose the `FailureAlarmNames` output before the web stack
can be planned. Confirm the SNS email subscription for `email.alerts` in
the message sent by AWS. An unconfirmed subscription is not alert delivery.

Expected application checkpoint: you have an HTTPS dashboard URL from the
edge stack and can request a login link at `/auth/login`. Confirm the
configured administrator receives the message and completes sign-in.
If it does not arrive, check SES sender identity, region, sandbox recipient
requirements, delivery restrictions and the configured origin before
working on receiving DNS. Do **not** publish tokens or email contents
into tickets/logs.

## 4. Activate dedicated receiving **only after reviewing its impact**

Create the disabled receiving rule using reviewed `plan receiving` /
`apply receiving` commands. Those commands **cannot enable** inbound mail.
For an existing receiving stack, the installer uses
`UsePreviousValue=true` for `EnableReceiving` so routine upgrades
do not silently disable previously approved receiving.

Then explicitly review and, where appropriate, perform these *manual*
operations outside the generic installer:

1. Verify SES identity, existing active rule set/order and precise S3
   action permissions; create/publish the **dedicated** receiving-domain
   MX (not the ordinary mailbox MX).
2. Enable only the approved exact-recipient receipt rule. Select/activate
   a rule set only if reviewed against other receivers.
3. From your normal mail provider, send one controlled email to the
   dedicated address and confirm SES stored the corresponding raw MIME
   in the production S3 `incoming/` prefix. A regular message tests
   routing, **not** DMARC parsing.
4. Send/forward a supported DMARC aggregate-report fixture **as an
   attachment** and verify S3 → EventBridge → Lambda → DynamoDB, plus
   the `captured=true` tag. Do not publish fixtures containing private
   mail to the public repository. Test replay/failure handling and alarm
   delivery separately.
5. **Only after that end-to-end test succeeds**, update the monitored
   domains' existing DMARC `rua` entries, without clobbering their
   other policy tags. Publish external-destination authorisation where
   the domain relationship requires it.

For a local, **private** completion summary, run:

```sh
python3 scripts/install.py summary
```

It displays the deployed HTTPS origin (where available), configured
administrator/receiving/sender/alert addresses, the local release commit
(and whether both deployed Lambda code keys match), plus the next action.
This command intentionally prints private configuration: never paste its
output into public issues, CI or installation logs. It derives the live
part from CloudFormation and does not track progress in a new database.
If the dashboard is not installed, a deployed URL cannot yet be confirmed.

Once you have personally confirmed a controlled incoming SES email
reached S3 and a supported attached DMARC report was successfully
persisted/capture-tagged, an optional **operator-confirmed**
end-to-end check can be recorded using:

```sh
python3 scripts/install.py confirm-delivery \\
  --object-key incoming/<SES-message-id> \\
  --confirm-observed-delivery
```

This is a **separate, explicit production S3 write**, not a read-only
installer status or an automatic deployment step. Use it only with reviewed
approval after independently confirming SES provenance. The installer
checks the active SES rule, configured bucket/recipient, and captured
object; it stores a timestamp-only confirmation under
`setup/end-to-end-confirmed.json`. It does not independently prove who
uploaded the object. The updated web stack needs narrowly scoped read
permission for that marker, so do not assume the check changes on the live
page merely by merging the code. Never share the object key or receipt
details publicly.

Use the authenticated `/setup` page to review live SES, MX/`rua`/
authorisation, recent processing and alarm *configuration*. It is not
continuous monitoring. The processing marker may reflect an S3 upload
rather than an SES-delivered message. Similarly, a configured SNS
subscription and alarms do **not** prove a real alarm email arrived.

## Troubleshooting and recovery

| Observation | Next action |
| --- | --- |
| `check` passes but login email does not arrive | Inspect SES sending identity, account sandbox, admin recipient and second web origin deployment |
| No dashboard URL | Confirm `edge` stack is deployed; inspect its `WebHttpsOrigin` output |
| Unable to plan web | Confirm artifact/ingestion stacks and their expected outputs, and upload verified ZIPs |
| SES rule looks correct but email not received | Inspect exact envelope recipient, active rule set/order, dedicated MX, SES IAM role and intake bucket; do not change ordinary mailbox MX |
| S3 mail arrives but no report appears | Check EventBridge, ingest Lambda, retained untagged input and failure queues; a non-DMARC message is not a parser test |
| Alarms look wired but no alerts arrive | Confirm SNS email subscription, then perform a separately approved real alarm test |
| Failed / incomplete CloudFormation operation | Inspect the exact stack/change-set in AWS; do not blindly rerun `apply` or bypass replacement safeguards |

For component-specific details, see [production ingestion](production-ingestion.md),
[private web](web-private-infra.md), [HTTPS edge](web-http-edge.md)
and [setup status](setup-status.md).

## Upgrade, rollback and decommissioning

For an upgrade, back up `.local/` securely, check out the intended new
immutable commit, rebuild and upload the new checked ZIPs, then plan and
review each **affected** stack in dependency order. Existing S3 intake
and DynamoDB reports/auth are retained; the ordinary installer blocks
their modification, deletion and replacement. Deploying new source does
not automatically change the running Lambdas.

For rollback, use a **known previous commit and its verified ZIPs** and
review new change sets. Revert the intended Lambda/config changes without
assuming a schema downgrade is safe. Investigate any failed deployment
before running another change set. Keep retained resources and existing
domain DNS in place unless separately reviewed.

Decommissioning is **not** an installer command. Stop new DMARC reporting
first by deliberately updating `rua` (and, where appropriate, the dedicated
MX and receipt rule), without touching ordinary email. Review SES and
subscription implications, then remove AWS stacks only with explicit
approval. `DeletionPolicy: Retain` means durable S3/DynamoDB (and some
failure queues) **are not automatically deleted** with the stack.
Inventory retained data, backups, S3 lifecycle policies and continuing
storage charges before deleting anything manually. Successfully captured
raw MIME normally expires by the S3 one-day lifecycle; incomplete,
untagged mail is retained for investigation.

## Permissions, costs and privacy

Installation provisions billable AWS services including Lambda,
API Gateway, S3, DynamoDB, EventBridge, SQS, SES, CloudWatch Logs/Alarms
and SNS. Usage, retained objects, retries and testing affect charges;
the free tier is not a zero-cost guarantee. Use normal AWS billing alerts
and review the actual region/service prices before installation.

The scoped application roles are not the same as the broader **deployer**
AWS permissions required for change sets/IAM/stack resources. Never put
AWS credentials, private email, sign-in links or raw DMARC XML into tracked
config, public CI, issues or examples. Keep `.local/` securely backed up.

A second private deployment repository, unattended deployment agent,
new infrastructure framework or installer state database is not required
for the initial single-owner installation.
