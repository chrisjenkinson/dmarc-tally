# Receiving DMARC aggregate emails through SES

`infra/ses-receiving.yaml` is a **separate, disabled-by-default**
CloudFormation template for one exact SMTP recipient. It adds a receipt rule
to an existing SES rule set and uses a dedicated SES-assumed IAM role to
store the complete MIME email in an **existing private S3 bucket**, under
`incoming/`. The already-implemented S3 → EventBridge → ingestion Lambda
reads those objects. No new parser, queue, or Lambda is needed.

This template deliberately does not create a rule set or select/activate one,
modify any bucket policy, create a bucket, manage domain identities, or edit
DNS. In particular, do **not** provision another
`AWS::S3::BucketPolicy` for the intake bucket: S3 has a single bucket
policy per bucket, and replacing the existing ingestion stack's policy could
silently remove TLS/privacy protections. For a same-account intake bucket,
SES can assume a tightly scoped S3-action IAM role instead.

## Deployment parameters (no real defaults)

| Parameter | Purpose |
| --- | --- |
| `ReceiptRuleSetName` | **Existing** rule set in the intended SES region. It may be inactive when staging; a separate explicit operation activates the chosen rule set. |
| `ReceiptRuleName` | Stable SES rule name, default `dmarc-tally-reports`. Keep stable when updating to avoid replacing the rule. |
| `ReceivingAddress` | Exact SMTP envelope address, ideally a dedicated receiving subdomain and mailbox local-part. |
| `IntakeBucketName` | Existing same-account, same-region bucket with SSE-S3, private access controls and EventBridge notifications, created by the ingestion stack. |
| `EnableReceiving` | **`false` by default.** Set to `true` only in a separately approved CloudFormation update after safety checks and controlled testing. |

The rule matches one exact **SMTP envelope recipient** (not a user-controlled
`To` header). It enables SES spam/malware scanning and allows optional
transport TLS to avoid dropping DMARC aggregate senders that cannot negotiate
TLS. It includes exactly one S3 action with `ObjectKeyPrefix: incoming/`,
`BucketName` and the IAM role ARN. There is no optional SES `KmsKeyArn`:
the intake bucket's normal **SSE-S3 at rest** handles encryption; enabling
SES client-side KMS encryption would make raw MIME unreadable by the
existing Rust importer without a separate decryption step.

### Why a scoped IAM role?

`SesS3DeliveryRole` trusts `ses.amazonaws.com` only for a matching
`aws:SourceAccount` and the **exact** receipt-rule ARN assembled from the
given rule set/name. Its sole action is `s3:PutObject` to
`arn:aws:s3:::<IntakeBucketName>/incoming/*` (using the target partition).
There are no read, list, delete, bucket-policy, KMS or cross-account grants.
Use the existing bucket policy and do not change it. This design assumes
**the SES rule and bucket belong to the same AWS account**; cross-account
writing would require separate bucket-owner permissions and security review.

## Rollout checklist — explicit approval required

1. Confirm which region/account will host the production intake bucket and
   its EventBridge ingestion stack; the tests used **ap-southeast-2
   (Sydney)**. Verify the real stack is not the isolated synthetic smoke
   environment. Production ingestion, retained-report storage and failure
   alarms must already exist.
2. Choose a **dedicated receiving domain/subdomain and exact recipient**
   before provisioning. Verify that domain with SES, publishing the
   validation/DKIM records it requires. Do not move existing mailbox MX
   records: changing MX on a shared mail domain can disrupt ordinary email.
3. Inspect SES's **active** rule set and all rules in the intended region
   (e.g. read-only `aws ses describe-active-receipt-rule-set` and
   `aws ses describe-receipt-rule-set --rule-set-name ...`). SES has only
   one active rule set per region. If another application owns one, do not
   replace or activate another one. Check all recipient conditions and rule
   ordering. This new rule would otherwise be inserted at the **beginning**
   of the selected rule set when no `After` is supplied.
4. Review and approve a CloudFormation **change set** creating the disabled
   rule and role. Inspect its exact recipients, bucket name, `incoming/`
   prefix, role trust and permissions. Rule creation is not authorization
   to change a currently active receipt rule set's traffic.
5. Verify the dedicated receiving hostname's MX record will point to the
   intended SES inbound endpoint; for Sydney that is
   `10 inbound-smtp.ap-southeast-2.amazonaws.com`. Publish MX only on
   explicit approval and ensure the dedicated subdomain is being used.
6. Update each monitored domain's DMARC `rua` entry to
   `mailto:<ReceivingAddress>`, after validating its existing DMARC
   policy. **External** reporting destinations may require a TXT
   authorization record at
   `<policy-domain>._report._dmarc.<destination-domain>`
   with a `v=DMARC1` value, per DMARC external destination verification.
   Do not overwrite existing DMARC policy elements accidentally.
7. With the destination, identity, MX, rule order and incoming S3 IAM
   rights reviewed, explicitly set `EnableReceiving=true` in a
   CloudFormation change set. Where needed, separately activate the
   reviewed rule set. Never switch the active set out from under an
   unrelated receiving application.
8. Send a **single approved real test message** to the dedicated address,
   then verify exactly one corresponding complete MIME S3 object
   `incoming/<SES-message-id>`, EventBridge invocation, DynamoDB report
   persistence and `captured=true` tagging for a supported test report.
   A non-DMARC message should remain retained and untagged. Use a real
   aggregate-report fixture only with appropriate privacy controls; keep
   its MIME out of the public repository, issues and CloudWatch logs.
9. Exercise malformed/oversized mail and duplicate delivery handling and
   confirm existing EventBridge/Lambda failure alarms and replay procedures.
   The Lambda's current MIME size limit is **30 MiB**; report messages larger
   than the application limit are intentionally retained without capture.
   Do not assume SES accepts exactly the same upper limit.
10. Only after one full integration test has passed should you redirect
    monitored domains' ongoing DMARC reports to the receiving address.

## Not in this PR

The template does not deploy the production ingestion stack or add
captured-object lifecycle expiry. An isolated test stack can validate
functionality, but **real production installation still needs an
ingestion/base-stack template, artifact/version management, and a reviewed
retention policy**. Those are tracked separately.

No AWS account changes, real email sends, SES activation, DNS changes or
CloudFormation deployments are performed by CI or by merging this source PR.
