# One-administrator authentication (v1)

This document specifies the provider-independent authentication behaviour in
`tally-core::authentication`. It does **not** deploy sign-in, expose HTTP
endpoints or send real emails. It is independent of any AWS account.

## User flow and initial policy

One administrator email is configured at installation. An unauthenticated
visitor can submit an email address, but **only that configured recipient**
receives a sign-in link. HTTP responses must not reveal whether an address
was recognised, throttled or temporarily undeliverable.

1. Request sign-in: atomically store the SHA-256 digest of a fresh 256-bit
   token, replacing any prior sign-in challenge. The challenge expires after
   **15 minutes**; requests are throttled to at most **one issued link per
   minute**, including if the previous token has already been redeemed.
2. Deliver email: the `EmailSender` adapter constructs a link against a
   configured **trusted HTTPS origin**, never from request Host/Forwarded
   headers. The link contains the raw one-time token; the store does not.
3. Open link: a GET shows a confirmation form but **must not consume the
   token**. Mail security scanners commonly fetch links ahead of users.
   The explicit POST confirmation calls `redeem_sign_in`, which atomically
   checks the digest, unexpired timestamp and unused state.
4. Start session: a successful redemption generates a separate 256-bit
   secret and persists **only its hash** with a **7-day** expiry. The adapter
   sets it in an HttpOnly, Secure, SameSite cookie (for example,
   `__Host-dmarc-session`, `Path=/`, no Domain attribute). On success use
   a 303 redirect to a clean URL, removing the login token from the address
   bar. Never put a session token in a URL.
5. Access and logout: every private reporting endpoint (including downloads
   and originals) checks the stored session digest and expiry **before**
   retrieving content. Logout revokes the session and clears the browser
   cookie. An expired session is invalid even if its database TTL item has
   not yet been removed.

These TTL/cooldown values are initial defaults; changes should consider
administrator usability, email volume and security.

## Provider contracts and failure semantics

`AuthenticationStore` has separate responsibilities:

- **One login challenge per installation:** write new hash, issue time,
  expiry and unused flag only when the cooldown has elapsed; conditional
  writes must be atomic even under concurrent requests.
- **Consume challenge:** conditionally mark used if both hash and expiry
  match. Preserve the last-issue timestamp after redemption so cooldown
  cannot be bypassed. Only one concurrent redemption may win.
- **Sessions:** conditionally create a new digest entry, check its expiry on
  reads, and revoke by digest; no scan is needed to validate a session.

A DynamoDB implementation could use one fixed login-challenge key and one
item per session hash, with conditional updates. A DynamoDB TTL setting is
cleanup only, not the authentication decision. The in-memory adapter in
`tally-core` is a reference/test double, **not** production authentication:
Lambda instances cannot share its state.

`SecureTokenSource` must return fresh bytes from a **cryptographically
secure operating-system random generator**. The deterministic fake in the
tests is never suitable for production. `EmailSender` is the only capability
given the raw login token. It must neither log it nor send to a recipient
taken from untrusted request input.

Storage errors, email-send errors and entropy failures fail closed. An
email may fail after its hashed challenge is already saved; the token expires
normally and the administrator can request another after the cooldown.
Failure to persist a session after consuming the link also fails closed,
requiring another link.

## HTTP and security requirements before exposing the dashboard

- The first HTTP handler or middleware must validate the cookie session on
  every protected route; merely hiding links or displaying a login page is
  **not** an access-control boundary.
- Use CSRF protection/Origin validation on authenticated state-changing POST
  requests (including logout), and avoid accepting credentials through GET.
- Use `Cache-Control: no-store` on auth and private pages, and
  `Referrer-Policy: strict-origin` in both HTTP responses and rendered HTML.
  This excludes paths and token queries from `Referer` while preserving the
  HTTPS origin on native form POSTs. `no-referrer` makes their `Origin` header
  `null`, which must remain forbidden by the CSRF checks.
  No external fonts, scripts or tracking pixels on the link landing page.
  Exclude auth queries and cookies from access/error logs.
- Validate the trusted public HTTPS origin at configuration time, using
  explicit paths rather than arbitrary return URLs. Prevent open redirects.
- Give the same visible response to unrecognised and recognised emails,
  including mail-delivery errors, and apply edge request limits. A synchronous
  email send can still create a timing difference, so avoid claiming perfect
  account-enumeration resistance until the HTTP delivery flow is reviewed.
- Ensure a session is issued **only** if redemption succeeded; do not add a
  bypass or fallback for development or the smoke stack.
- Use the same application behaviour for any CLI administration function,
  rather than creating a separate authentication state machine.

The portable `tally-web::http` handler accepts already-decoded request
fields; verifies configured HTTPS origin for POST; enforces session checks
**before any report query**;
shows emailed GET links without consuming them; redeems only on an explicit
POST; and issues or clears Secure, HttpOnly, SameSite=Lax, Path=/ session
cookies. All responses set `Cache-Control: no-store`, an origin-only
referrer policy and a restrictive content-security policy.

The login request POST has a generic response regardless of account
recognition or mail-delivery errors; this does not eliminate possible timing
differences, so the deployed HTTP edge should also use conservative request
limits. Report details and original-email retrieval are deliberately not
implemented: the routing gateway rejects these paths until a subsequent
authenticated read use case is available.

The hosting adapter must map method/path/query/form-body/Origin/Cookie
without trusting Host or Forwarded headers, enforce decoded-body size limits,
avoid logging cookies and query strings containing link tokens, and reject
malformed or multiple credential headers. `tally-web` intentionally has no
AWS SDK, HTTP listener or public routing infrastructure. A future Lambda
entry point must call this same handler rather than implementing another,
possibly bypassable authorization path.

There is currently **no deployed authentication feature**. The separate
integration still needs a verified SES sender, CloudFormation authentication
table and scoped IAM, HTTPS hosting and Lambda request adapter, and end-to-end
checks proving unauthenticated users cannot access report content or
retained original messages.
