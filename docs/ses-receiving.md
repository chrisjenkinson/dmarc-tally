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
6. Review any existing DMARC policies and prepare, where needed, an
   external-reporting authorisation TXT at
   `<policy-domain>._report._dmarc.<destination-domain>` with `v=DMARC1`.
   **Do not change the monitored domains' `rua` yet.**
7. With identity, dedicated MX, rule ordering and S3 IAM reviewed,
   explicitly enable only the approved receipt rule via a separately
   reviewed CloudFormation change set outside the generic installer.
   Where needed, separately activate the reviewed rule set, never
   displacing other receiving applications.
8. Send **one controlled ordinary test email** to the dedicated address
   from the normal mail provider. Verify arrival through SES in S3 as a
   complete MIME object under `incoming/`. Ordinary mail tests routing,
   not DMARC parsing; it should remain untagged.
9. Separately send/forward a supported aggregate-report fixture **as an
   attachment**. Verify SES → S3 → EventBridge → Lambda → DynamoDB
   persistence and `captured=true` tagging. Exercise replay and failure
   alarms (including a separately approved delivery test); keep private
   fixtures out of public logs/issues. The current importer limit is
   **30 MiB**, which is not necessarily the SES acceptance limit.
10. **Only after a successful end-to-end test**, update monitored domains'
    DMARC `rua` to `mailto:<ReceivingAddress>`, preserving the remaining
    existing DMARC tags. Publish additional external authorisation where
    required; do not disrupt normal mailbox MX.

## Relation to the rest of the installation

Production ingestion and captured-only S3 lifecycle expiration are
implemented in `infra/production-ingestion.yaml`. The separate
`scripts/install.py` workflow builds/releases and deploys that stack
with reviewed change sets; it creates this receiving rule disabled
on the first deployment and preserves the existing enabled state on
updates. **It never activates receiving or edits DNS automatically.**

Follow the single end-to-end [installation guide](install.md) for the
actual deployment order, browser login, controlled delivery test and
upgrade/recovery steps. CI and merging do not alter AWS or DNS.
