# Outbound sign-in emails

The `SesEmailSender` adapter in `tally-aws` implements the existing
provider-independent `EmailSender` contract. It is not a deployed
mail service and does not configure SES identities, DNS or receipt rules.

The administrator email, verified sender email and public HTTPS site origin
are explicit installation configuration. The adapter independently verifies
that the requested recipient is the configured administrator, checks the
64-character one-time token syntax, and builds a plain-text message containing
`https://<configured-origin>/auth/confirm?token=<secret>`.

The recipient and link host never come from an incoming request's Host,
Forwarded, body, query parameters, or arbitrary redirect location. Invalid
configuration is rejected before sign-in requests can be processed. The
adapter never logs the token, generated link, SES request, message ID, or
recipient. SES exceptions return a generic `AuthError::Delivery`.

The core creates and persists the token digest *before* calling the sender.
If SES fails after a challenge is issued, the administrator can request
another link after the one-minute cooldown. Do not retry the same send
unboundedly or log the complete SES request.

## Deployment prerequisites

- Select and verify an SES sending identity in the deployment region, and
  explicitly configure its From email. Do not infer an address from existing
  account identities or change existing receipt-rule sets.
- If the SES account is in its sandbox, recipients must also be verified.
  There are no real-recipient test sends in the repository's CI.
- Grant the private web Lambda only `ses:SendEmail` on the configured
  verified sender identity, not blanket SES administration permissions.
- Supply an explicit trusted HTTPS public origin and private HTTP adapter.
  Ensure the callback uses GET only to display a confirmation and POST only
  to consume the challenge.
- Test one real administrator link end-to-end in the isolated deployment only
  after explicit AWS/email approval, and check delivery failures without
  exposing secrets in logs.

The SES SDK is instantiated by the eventual Lambda HTTP composition root;
`tally-core` and `tally-web` are independent of the SES implementation.
