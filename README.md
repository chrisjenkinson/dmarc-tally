# DMARC Tally

**DMARC Tally** is a lightweight, self-hosted DMARC aggregate-report viewer planned for AWS.

The goal is to replace a stream of XML reporting emails with a simple, private dashboard. A single deployment will support one or more monitored domains.

## Planned v1

- Deploy to your own AWS account using a CloudFormation template and precompiled Rust Lambda binaries.
- Receive aggregate DMARC reports through Amazon SES and S3.
- Import historical reports by forwarding existing emails **as attachments** to the reporting address.
- Parse reports in Rust and store complete recognised report and record data in DynamoDB.
- View message totals, authentication results, reporting organisations and sending IPs over selectable date ranges.
- Allow one administrator to sign in using single-use links delivered by SES.
- Automatically expire original emails once all DMARC data has been captured, with exceptions retained for investigation.
- Upgrade through versioned CloudFormation stack updates without deleting reporting history.

**Status:** Pre-release. The generic, approval-gated installation workflow
is documented in [docs/install.md](docs/install.md).

To configure a local installation without a fork or second repository:

```sh
python3 scripts/install.py init
# Edit .local/production.json (already excluded by .gitignore).
python3 scripts/install.py check
```

CloudFormation planning and execution are separate, explicit commands;
merging public source does not deploy or change DNS.

## Development

Rust is the primary language. AWS infrastructure is described with plain CloudFormation (no SAM or other deployment framework).

This repository contains public application documentation and will host application source, tests, and infrastructure code as development proceeds.

## Architecture

V1 runs on AWS Lambda using SES for inbound/outbound email, S3 for incoming messages, and DynamoDB for stored DMARC reports. The implementation separates the portable Rust application from AWS integration:

- `tally-core`: DMARC parsing, report models, ingestion/reporting logic and capability-oriented storage/email interfaces.
- `tally-web`: reusable HTTP handlers and report rendering; no Lambda-specific types.
- `tally-aws`: AWS implementations of storage, intake retention and outbound email.
- `tally-lambda`: thin AWS event/HTTP entry points.

The core and HTTP application are designed for other adapters to be added independently. Other cloud providers, databases, IMAP polling and conventional web-server hosting are **not implemented or supported in v1**.

## Licence

GNU General Public License, version 3 (GPL-3.0). See [LICENSE](LICENSE).
