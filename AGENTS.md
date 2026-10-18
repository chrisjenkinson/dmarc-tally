# Repository guidance

DMARC Tally is a small, independent Rust/AWS project intended for a future open-source release. Prefer simple, testable designs, minimal dependencies and low ongoing operational overhead.

## Agreed product direction

- Deploy with plain CloudFormation and prebuilt, versioned Rust Lambda artifacts; do not introduce SAM or OSLS without discussion.
- One installation handles one or more domains configured via CloudFormation, with exactly one administrator and SES email magic-link authentication.
- An SES inbound receipt rule stores original emails in S3; S3 events asynchronously invoke the Rust ingestion Lambda.
- Persist all recognised structured DMARC report and individual-record fields in DynamoDB. Detect unknown XML elements and attributes rather than silently dropping them.
- Expire original emails after about one day only when every DMARC report within them has been fully captured; retain incomplete or unsupported inputs.
- Support historical import via attached email messages; validate with Fastmail's "Forward as attachment" behaviour.
- Keep v1 reporting simple: basic counts, reporting organisations, sending IPs and date filters. Defer sender attribution, charts and alerting.
- Protect existing SES receipt-rule configurations, authentication tokens and durable reporting data across deployment, updates and deletion.

## Working rules

- Follow test-driven development. Verify behaviour before claiming completion, especially retries, partial writes, parser completeness and authentication.
- Do not deploy to AWS or change DNS without explicit approval.
- Do not commit secrets, personal email messages, account credentials or unsanitised DMARC fixtures.
- **Only this root AGENTS.md may contain agent-specific instructions.** Do not commit other agent-oriented documents or artifacts, including `docs/superpowers/`, implementation plans, design drafts, session transcripts, `.claude/`, `.codex/`, or similar files.
- Normal README, product and technical documentation, source files, sanitized fixtures and tests are welcome; keep them product-focused.
- The approved external design and implementation plan remain outside this repository. Implementation awaits the maintainer's review of the plan and selection of an execution approach.
