# Installing DMARC Tally from a local checkout (pre-release)

This guide separates the **public, generic source repository** from **one
owner's private deployment settings**. No separate private repository, fork,
configuration service or infrastructure framework is needed. The public
CloudFormation templates, Rust crates, tests and installer can be used in any
AWS account with appropriate SES support.

**Merging this code does not approve AWS/DNS changes.** All real stack
changes, SES activation, mail and DNS need separate review and approval.
Commands below are intended for the owner to run locally; CI never has an
AWS profile, personal parameters or a public-facing deployed endpoint.

## Prerequisites

Python 3.11+, Git, a configured AWS CLI v2 profile, Rust stable, Zig and
cargo-lambda (the same Rust Lambda ZIP packaging tested by CI). The AWS
identity you select must have deployment permissions, including permissions
to create CloudFormation change sets, stack resources and upload private
S3 artifacts. SES receiving must be supported in the selected region.
The current AWS infrastructure has been validated for ap-southeast-2.

Checkout a **known tag or full commit SHA**, not a moving branch, before
building or installing. Keep the checkout clean. The installer records the
exact Git commit and refuses to reuse an artifact manifest from another
commit. Your ignored local config survives normal Git pull/checkout, but
back it up securely before upgrading or replacing your computer.

From the repository root:

    python3 scripts/install.py init
    # Edit .local/production.json and replace every example value.
    python3 scripts/install.py check

The public example is in config/production.example.json. The installer
**deliberately refuses** to use its example account, .invalid domains
or email addresses. The real file and any release/change-set records live
under .local/, which .gitignore already excludes. Never pass your real
values to GitHub Actions, a public issue or a PR. Do not put credentials,
access keys, raw DMARC messages or session tokens in this config. Use your
local AWS profile or temporary role credentials.

## Build immutable Lambda artifacts

    python3 scripts/install.py build

This builds the Rust ingest and web binaries locally, checks each ZIP
contains an executable x86-64 Linux bootstrap, and saves the ZIPs with
their SHA-256 values and **exact Git commit** in .local/release.json.
It uses cargo-lambda and your working checkout; it does not contact AWS.
The manifest is refused if the checkout changes, a ZIP checksum fails,
a ZIP is replaced, or the version-specific object key does not match.

## Review one stack at a time

The installer uses five distinct, generic CloudFormation templates:

| Component | Dependencies | What happens |
| --- | --- | --- |
| artifacts | None | Encrypted private, retained versioned Lambda ZIP bucket |
| ingestion | artifacts | Private S3 intake, reports table, EventBridge Lambda and failure alarms |
| web | artifacts, ingestion | Private web Lambda, auth table and narrow SES sending role |
| edge | web | Publicly reachable managed HTTPS API Gateway route (session-gated app) |
| receiving | ingestion | **Disabled** SES receipt rule in an existing rule set; no mail activation |

For each component, run:

    python3 scripts/install.py plan artifacts

The command first confirms that the configured AWS **account ID matches**
the active AWS CLI profile. It creates a CloudFormation change set only:
**no stack resources are created or updated by plan**. It prints generic
actions, resource types and logical IDs, not domain/email parameters or
raw AWS responses. Resource deletions, replacements, conditional
replacements and **any update to a durable S3 bucket or DynamoDB table**
are blocked from this ordinary upgrade workflow. Such changes require a
separate reviewed recovery/migration procedure. The change-set ARN,
configuration/template hashes and selected release are recorded in the
ignored .local/plans/ directory.

**Review that change set, the region, account and intended operations**
using your locally authenticated AWS tools. Only after explicit owner
approval, run the exact apply command printed by plan:

    python3 scripts/install.py apply artifacts --approve <REVIEWED_CHANGE_SET_ARN>

Apply refuses a different change-set ARN, a changed config/checkout/ZIP,
changed stack output, an unavailable change set or any deletion/replacement.
It executes the already-reviewed set and waits for CloudFormation to
finish. It never runs DNS commands or enables SES mail delivery.
The public HTTPS edge needs one **additional** explicit
--allow-public-edge flag because creating it makes a login endpoint
reachable on the internet (though private reports stay session-protected).

Once the artifacts stack exists, upload the two verified ZIPs:

    python3 scripts/install.py upload

The uploader uses content-addressed release keys
releases/<commit>/<binary>/<sha256>/bootstrap.zip; it refuses overwriting
a different existing object and verifies the S3 object's checksum metadata.
It doesn't need a public GitHub release or a short-lived Actions artifact.

Continue in this order: **ingestion**, **web**, **edge**, then **web again**.
The first web install uses a reserved, intentionally nonfunctional
https://bootstrap.invalid origin because the API Gateway URL does not
exist yet. After the edge is approved and deployed, planning **web again**
automatically uses its actual WebHttpsOrigin output and prompts a reviewed
web Lambda configuration update. Don't attempt a real browser login until
this second update is complete and SES sending is verified.

Finally, plan **receiving** only after manually inspecting any existing
active SES rule set, SES identity and MX/rua DNS. It always sets
EnableReceiving=false, so deploying the receipt rule is *not* permission
to redirect or accept mail. Explicitly enabling inbound mail, selecting
or activating the rule set, and changing DNS require separate reviewed
actions outside this installer. See docs/ses-receiving.md.

## Upgrades, recovery and privacy

Before upgrading, back up .local/production.json and the pinned release
manifest securely; store encrypted/off-site if appropriate. Keep previous
S3 release ZIPs for rollback. Checkout the chosen new Git tag/full commit
and run build, upload and reviewed stack changes again. A deployed
DynamoDB table and S3 intake bucket are retained across ordinary stack
updates and deletion, but **captured=true originals still expire via their
S3 lifecycle policy**. Never accept a CloudFormation replacement or
removal of a durable resource without a separate recovery plan.

The installer makes no claim that the live account, alarms, SES sandbox,
DNS or browser flow have been verified. Before real use, conduct the
isolated S3 ingestion, duplicate/failure/replay, outbound email and browser
auth tests described in docs/production-ingestion.md,
docs/web-private-infra.md and docs/web-http-edge.md.

A private deployment repository becomes optional only if the team later
needs collaborative GitOps or automation. For one administrator and one
installation, the ignored local configuration is the simpler choice.
