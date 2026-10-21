# Isolated AWS ingestion smoke test

This is a **non-production** test of DMARC Tally's Rust Lambda ingestion
path. It supports both manual invocation and automatic S3 object-creation
routing through EventBridge. It does not configure SES receipt rules, DNS,
public access, web hosting or S3 object expiration.
Use **only the synthetic .eml files in this repository**, not real email.

## Resources created

| Stack | Contents |
| --- | --- |
| `dmarc-tally-smoke-artifacts` | Private encrypted S3 bucket holding one Rust Lambda ZIP |
| `dmarc-tally-smoke` | Private test intake bucket, on-demand DynamoDB table, Rust Lambda, narrow IAM role, CloudWatch log group and scoped EventBridge rule. The failure-recovery version also adds two SQS queues, four CloudWatch alarms and an SNS topic |

The buckets and table have CloudFormation `DeletionPolicy: Retain`
and `UpdateReplacePolicy: Retain`. Data is *not* automatically deleted
when a stack is removed. Review resources before later manual cleanup.

The examples use `ap-southeast-2` (Sydney). An existing smoke stack may
already be deployed. Always inspect it and review a CloudFormation change
set before updating it; these commands are **instructions**, not approval
to deploy or change any AWS resources.

## 1. Build and obtain the Lambda ZIP

The GitHub Actions check on PR #7 runs `cargo lambda build`
for the `ingest` binary and uploads a short-lived artifact named
`ingest-smoke-<commit-sha>`, with `bootstrap.zip` and
`bootstrap.sha256`. It does not use AWS credentials.

Download the artifact from the PR's Actions run, unzip the GitHub artifact
and verify `sha256sum -c bootstrap.sha256`. The file deployed to
Lambda is the *inner* `bootstrap.zip`.

## 2. Deploy the isolated artifacts bucket

Only after reviewing the templates and approving AWS provisioning,
with AWS CLI v2 and credentials for the intended account:

```sh
export AWS_REGION=ap-southeast-2
aws sts get-caller-identity

aws cloudformation deploy --region "$AWS_REGION" \
  --stack-name dmarc-tally-smoke-artifacts \
  --template-file infra/smoke-artifacts.yaml \
  --tags Project=dmarc-tally Purpose=isolated-smoke-test

CODE_BUCKET=$(aws cloudformation describe-stacks \
  --region "$AWS_REGION" --stack-name dmarc-tally-smoke-artifacts \
  --query "Stacks[0].Outputs[?OutputKey=='ArtifactBucket'].OutputValue | [0]" \
  --output text)

ZIP_SHA=$(sha256sum bootstrap.zip | awk '{print $1}')
CODE_KEY="smoke/$ZIP_SHA/bootstrap.zip"
aws s3 cp bootstrap.zip "s3://$CODE_BUCKET/$CODE_KEY" --region "$AWS_REGION"
```

The SHA-based code path is version-specific. Keep the original uploaded
ZIP available while the Lambda stack exists.

## 3. Deploy the isolated ingestion stack

```sh
aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name dmarc-tally-smoke \
  --template-file infra/smoke-ingestion.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    "CodeBucket=$CODE_BUCKET" \
    "CodeKey=$CODE_KEY" \
    "MonitoredDomains=example.com,example.net" \
  --tags Project=dmarc-tally Purpose=isolated-smoke-test
```

CloudFormation Outputs show the generated test bucket, table, function and
log group. Lambda can read and tag only `incoming/*` objects in its
own bucket, read/write only its test table, and write to its log group.
No public endpoint or receipt rule is installed. The automatic-ingestion
version adds a narrowly scoped EventBridge rule; the recovery version adds
SQS failure queues and CloudWatch alarms. The original manual smoke script
remains available for regression testing. An email recipient is *not*
subscribed unless the optional `NotificationEmail` parameter is supplied
and the SNS confirmation link is accepted.

## 4. Execute the synthetic verification

From the repository checkout:

```sh
bash scripts/smoke-run.sh
```

The script first verifies the test stack's `Purpose=isolated-smoke-test`
tag and prints the resources. It requires typing `RUN-SMOKE`
before it changes anything.

It uploads a valid synthetic email, manually invokes Lambda with an S3
`ObjectCreated` payload, verifies one complete DynamoDB report
(metadata + record) and the `captured=true` S3 tag, replays the event
to prove no duplicate writes, then checks that an invalid XML report remains
untagged. On an updated automatic-ingestion stack, a new upload under
`incoming/` also triggers an independent EventBridge invocation. Account
for the extra (idempotent) run when assessing the results.

View logs using the CloudWatch log group in the stack Outputs. CI tests do
not replace this live AWS verification.

## 5. Cleanup

Do not delete test data until you've inspected it. Before deleting stacks,
save the generated intake-bucket and DynamoDB-table names from Outputs.

```sh
aws cloudformation delete-stack --region "$AWS_REGION" --stack-name dmarc-tally-smoke
aws cloudformation wait stack-delete-complete --region "$AWS_REGION" --stack-name dmarc-tally-smoke
```

This removes Lambda, IAM and logs, **not** the retained intake bucket or
DynamoDB table. Inspect their contents first, then delete them deliberately
using their exact generated names. The artifacts stack likewise retains
the artifact bucket; remove only its smoke ZIPs and delete that bucket
explicitly after deleting its stack.

Never run recursive S3 deletion against an unverified bucket. Production
deployment and its retention semantics are separate work.

## 6. Automatic S3-triggered ingestion (separate PR)

After the manual smoke test is confirmed, update the existing
`dmarc-tally-smoke` CloudFormation stack with the version of
`infra/smoke-ingestion.yaml` from the automatic-ingestion PR. Review the
CloudFormation change set before executing it. The original routing update
changed the S3 notification configuration and added the EventBridge rule
and Lambda permission; the subsequent recovery update adds SQS queues,
alerts and the Lambda on-failure destination.
**Do not accept any replacement of the intake bucket or reports table.**

S3 forwards object events to EventBridge; the rule filters to
`source=aws.s3`, `detail-type=Object Created`, this test bucket, and
keys beginning `incoming/`. The native S3 EventBridge event is passed to the Rust Lambda unchanged.
Tagging events do not match and cannot cause an ingestion loop.
No SES or DNS configuration is involved.

To test without manually invoking Lambda, upload the synthetic valid email
as a **new key** such as `incoming/automatic-smoke-20261020.eml`. Confirm
the S3 `captured=true` tag, DynamoDB report idempotency and CloudWatch
invocation logs. Upload malformed XML under a second unique key: it should
be retained untagged, with a corresponding CloudWatch log message. A
non-`incoming/` object must not invoke Lambda.

**Native EventBridge payload upgrade (separate follow-up PR):**
The EventBridge rule passes the original AWS event directly to the Lambda;
there is no input transformer. The updated Rust Lambda event adapter reads
literal keys, including `+` and `%`, without URL-decoding them. Direct S3
Lambda notifications still follow their own form-URL-decoding rules.

**Apply the updated Lambda executable before removing the transformer** on
an active stack. Do not enable real SES delivery until the new executable
and rule change have both been deployed and verified against unusual key
names. Manual smoke-test invocation remains supported.

## 7. Failure recovery and operational alerts (separate PR)

This feature creates two independent, private failure queues. **No queue
automatically invokes Lambda and neither queue is automatically emptied.**

| Failure boundary | What is retained | Trigger |
| --- | --- | --- |
| EventBridge cannot deliver an event to the Lambda target | Original native EventBridge S3 event | EventBridge retries according to its service defaults; permanently undeliverable events enter `EventBridgeFailureQueue` |
| Lambda receives an asynchronous event but cannot process it | Lambda invocation record containing `requestPayload` and failure context | Lambda retries function errors up to two times, within the six-hour maximum event age, then delivers to `LambdaFailureQueue` |

Each SQS queue is encrypted with SQS-managed keys and holds messages for
**14 days**, including when CloudFormation removes its stack. CloudWatch
alarms notify if either failure queue has messages, if EventBridge cannot
write to its failure queue, or if Lambda cannot write to its on-failure
destination. A topic resource policy allows only CloudWatch alarms from this
stack and account to publish; the alarms are created after this permission.
Alarm descriptions and SNS messages contain resource/metric
details, **not raw email, message bodies or S3 object keys**. Queue messages
*do* contain the event's original S3 object key and may include error
details. Restrict access and avoid pasting messages into issues/logs.

The optional `NotificationEmail` CloudFormation parameter attaches an
email recipient to the SNS topic. Example for an **approved** deployment:

```sh
# Add to the existing cloudformation deploy --parameter-overrides:
"NotificationEmail=admin@example.invalid"
```

Replace the example address when deploying. The recipient **must confirm**
the SNS subscription email; CloudFormation success is not proof that anyone
receives alarms. A blank parameter leaves alarm monitoring in place but
sends no email until a subscription is added. Inspect the stack Outputs for
`EventBridgeFailureQueueUrl`, `LambdaFailureQueueUrl` and
`FailureAlertTopicArn`.

### Triage and replay, after fixing the underlying problem

1. Identify which queue has messages. Check the matching SQS backlog alarm
   and EventBridge/Lambda error metrics. Inspect the private queue body
   through an access-controlled terminal, never public logs or an issue.
2. Confirm that the source S3 email still exists. The application retains
   originals unless fully captured; bad XML, unexpected formats and
   oversized messages are **intentionally retained**, not Lambda failures.
3. For an **EventBridge failure queue** message, the SQS body is the
   original native S3 EventBridge event. For a **Lambda failure queue**
   message, the body is a Lambda invocation record; extract only its
   `requestPayload` (the native S3 event), **not** the outer record.
   Check that the bucket/key match this smoke stack. Do not replay events
   from an unknown stack or message with an unexpected schema.
4. Reinvoke the verified event against the intended smoke Lambda with
   `aws lambda invoke --invocation-type RequestResponse`, using a
   permission-restricted local JSON file and
   `--cli-binary-format raw-in-base64-out --payload fileb://...`.
   Inspect both the invocation's `FunctionError` metadata and its result.
   An invocation returning HTTP status 200 can still indicate an error.
5. Confirm the expected DynamoDB completed report and S3
   `captured=true` tag (or explicitly investigate an intentionally
   retained original). A duplicate report is safe because persistence
   and the capture tag are idempotent.
6. **Only after successful verification**, delete the original SQS message
   with its current receipt handle. If recovery fails, leave it there for
   investigation; do not bulk-purge the queue. SQS receipt handles expire
   when message visibility times out, so receive it again if necessary.

A safe read-only check using the Queue URL from Outputs is:

```sh
aws sqs get-queue-attributes --region "$AWS_REGION" \
  --queue-url "$QUEUE_URL" \
  --attribute-names ApproximateNumberOfMessages
```

**Failure smoke-test plan (not yet performed):** After CloudFormation
review/approval on the isolated stack, invoke the Lambda asynchronously
with a synthetic native EventBridge event for a *nonexistent* private
`incoming/` key. That should exhaust retries and place a failure record
in the Lambda queue. Test an EventBridge delivery failure separately using
a temporary, deliberately invalid target/permission in the **isolated
smoke environment only**, restoring the original rule immediately. Verify
the correct queue, its alarm and subscription, successful replay, idempotency
and safe SQS message deletion. Also simulate a queue-delivery failure and
verify the matching failure-to-DLQ CloudWatch alarm. Do not manipulate
the production EventBridge rule or other applications to run these tests.

### Retained but unprocessed emails

Unsupported, oversized or malformed messages are intentionally left in S3
without a `captured=true` tag. Their Lambda invocation **succeeds**, so
they do not appear in these failure queues. For v1, investigate retention
through categorical Lambda logs and occasional manual inspection; do not
email on every invalid or unwanted inbound message, which would generate
noise. Add a bounded aggregate retention alarm only if real-volume
experience shows it is needed.

**Limitations:** The four alarms cover delivered failure messages and
failures to write those messages. They do not guarantee detection of every
possible S3 → EventBridge source-delivery problem or provide an audit of
intentionally retained inputs. This is smoke-stack infrastructure; the
production template and real-mail tests remain separate work.
