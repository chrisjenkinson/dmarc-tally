# Repository guidance

DMARC Tally is a small, independent, GPLv3-licensed Rust application with an AWS-first deployment. Prefer simple, testable designs, minimal dependencies and low ongoing operational overhead.

## Agreed product direction

- Deploy with plain CloudFormation and prebuilt, versioned Rust Lambda artifacts; do not introduce SAM or OSLS without discussion.
- One installation handles one or more domains configured via CloudFormation, with exactly one administrator and SES email magic-link authentication.
- An SES inbound receipt rule stores original emails in S3; S3 events asynchronously invoke the Rust ingestion Lambda.
- Persist all recognised structured DMARC report and individual-record fields in DynamoDB. Detect unknown XML elements and attributes rather than silently dropping them.
- Expire original emails after about one day only when every DMARC report within them has been fully captured; retain incomplete or unsupported inputs.
- Support historical import from standard attached email messages (`message/rfc822` and `.eml`); test nested MIME and compressed report attachments using sanitised fixtures.
- Keep v1 reporting simple: basic counts, reporting organisations, sending IPs and date filters. Defer sender attribution, charts and alerting.
- Protect existing SES receipt-rule configurations, authentication tokens and durable reporting data across deployment, updates and deletion.

## Architecture boundaries

- **Implement only AWS Lambda hosting in v1.** Do not add IMAP polling, an alternative database, Azure deployments, SMTP or a conventional web server unless separately requested.
- Keep `tally-core` independent of AWS: DMARC/MIME parsing, report identity, ingestion, reporting and authentication behaviour, with minimal capability-oriented `ReportRepository`, `AuthenticationStore` and `EmailSender` interfaces.
- Keep `tally-web` independent of AWS/Lambda: portable HTTP handlers and rendering behind those core capabilities.
- Put DynamoDB, S3 and SES SDK usage in `tally-aws`. Keep `tally-lambda` thin: map AWS events/HTTP requests to the portable application and interpret its outcomes.
- Pass raw MIME bytes to the core ingestion use case and return a typed fully-captured/retained outcome. Reading S3 objects, setting expiry tags and interpreting Lambda events belong exclusively to AWS adapters.
- Do not expose DynamoDB keys, `AttributeValue`, S3 object keys, SES identities or Lambda event objects through core contracts. Use an in-memory repository/sender in contract tests.
- Support future alternative adapters/entry points through existing contracts **without changes to the core for existing functionality**, where feasible. A genuinely new application capability may require deliberate core evolution. Avoid generic cloud frameworks and speculative abstractions.

## Working rules

- Follow test-driven development. Verify behaviour before claiming completion, especially retries, partial writes, parser completeness and authentication.
- Do not deploy to AWS or change DNS without explicit approval.
- Do not commit secrets, personal email messages, account credentials or unsanitised DMARC fixtures.
- **Only this root AGENTS.md may contain agent-specific instructions.** Do not commit other agent-oriented documents or artifacts, including `docs/superpowers/`, implementation plans, design drafts, session transcripts, `.claude/`, `.codex/`, or similar files.
- Normal README, product and technical documentation, source files, sanitized fixtures and tests are welcome; keep them product-focused.
- Keep implementation and maintenance guidance generic; never include an individual maintainer's contact details, personal domains, AWS resources, mailbox exports, or unrelated project references.
