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

**Status:** Pre-release. Installation instructions will be added with the first release.

## Development

Rust is the primary language. AWS infrastructure is described with plain CloudFormation (no SAM or other deployment framework).

This repository contains public application documentation and will host application source, tests, and infrastructure code as development proceeds.

## Licence

GNU General Public License, version 3 (GPL-3.0). See [LICENSE](LICENSE).
