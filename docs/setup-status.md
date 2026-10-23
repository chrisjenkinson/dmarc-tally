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

The v1 page shows the configured receiving mailbox, monitored domains and
setup steps. On an authenticated visit to `/setup`, the host performs two
read-only SES v2 `GetEmailIdentity` calls for the configured sender identity
and the *exact* receiving address domain. These checks report verified
identity state; a sending identity must also be enabled for sending.
They never send email or change configuration. AWS API failures (including
missing or inaccessible identity records) remain **Unable to check**, not
Ready. Verification of a parent identity can apply to subdomains, so
exact-domain verification status is not conclusive proof of mail delivery.

The active receipt rule, exact recipient, S3 bucket/prefix and rule ordering
still require an on-demand SES classic API inspector in a subsequent PR.
DNS MX / DMARC rua, true successful end-to-end delivery and operational
alarm testing require distinct evidence; until then, the UI marks them
**Not verified**. A verified identity alone does not prove incoming delivery.

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
receiving-domain identities and to supply `SES_SENDER_IDENTITY`. Until
deployed, the existing Lambda is unchanged.

No AWS or DNS changes are made by merging this source change. A green installation
badge must never be shown until individual checks are backed by real
evidence.
