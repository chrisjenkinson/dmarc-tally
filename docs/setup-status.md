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
setup steps. The initial host inspector marks all operational checks as
**Not verified** deliberately: installation parameters alone prove nothing.
The next small change will implement **on-demand, read-only SES inspections**
via the same `SetupInspector` port: active receipt rule, correct recipient,
S3 bucket/prefix and SES identity verification. These will not activate
rules, send email, update DNS or create AWS resources. DNS MX / DMARC rua,
true successful end-to-end delivery, and operational alarm testing require
distinct evidence; until then, the UI will keep them Not verified.

`RECEIVING_ADDRESS` is provided to the web Lambda through the generic
CloudFormation `ReceivingAddress` parameter and `scripts/install.py` from
its ignored local config, never hard-coded personal values. Existing older
web Lambda deployments with no `RECEIVING_ADDRESS` show
"Receiving address not configured" until a reviewed template upgrade.

The same setup concerns may be checked from a generic local CLI later, but
do not create customer-facing monitoring history, new DynamoDB tables,
scheduled polling or a separate setup aggregate for one administrator.

No AWS or DNS changes are made by building this page. A green installation
badge must never be shown until individual checks are backed by real
evidence.
