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

**Status:** Design approved; implementation has not started. Installation instructions will be added with the first release.

## Development

Rust is the primary language. AWS infrastructure is described with plain CloudFormation (no SAM or other deployment framework).

This repository will contain application source, tests, infrastructure, and product/developer documentation. Agent workflow artifacts and internal plans are not tracked.

## Licence

An open-source licence has not yet been selected. Until one is added, public access to the repository does not grant general rights to reuse or redistribute the code.
