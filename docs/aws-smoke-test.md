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
| `dmarc-tally-smoke` | Private test intake bucket, on-demand DynamoDB table, Rust Lambda, narrow IAM role, CloudWatch log group, and scoped EventBridge creation rule |

The buckets and table have CloudFormation `DeletionPolicy: Retain`
and `UpdateReplacePolicy: Retain`. Data is *not* automatically deleted
when a stack is removed. Review resources before later manual cleanup.

Initial Region: `ap-southeast-2` (Sydney). The existing AWS
connector can access CloudFormation there, but **no resources have been
created yet**. Deployment requires separate approval.

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
No public endpoint or receipt rule is installed. The separate automatic
S3-ingestion change adds a narrowly scoped EventBridge rule. The original
manual smoke script remains available for regression testing.

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
untagged. An upload **alone** will not invoke Lambda in this template.

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
CloudFormation change set before executing it: the only permitted changes
are an update to the intake bucket's EventBridge notification configuration
and additions of the EventBridge rule and scoped Lambda invoke permission.
**Do not accept any replacement of a bucket or table.**

S3 forwards object events to EventBridge; the rule filters to
`source=aws.s3`, `detail-type=Object Created`, this test bucket, and
keys beginning `incoming/`. An input transformer translates that event
into the S3 notification envelope already supported by the Rust Lambda.
Tagging events do not match and cannot cause an ingestion loop.
No SES or DNS configuration is involved.

To test without manually invoking Lambda, upload the synthetic valid email
as a **new key** such as `incoming/automatic-smoke-20261020.eml`. Confirm
the S3 `captured=true` tag, DynamoDB report idempotency and CloudWatch
invocation logs. Upload malformed XML under a second unique key: it should
be retained untagged, with a corresponding CloudWatch log message. A
non-`incoming/` object must not invoke Lambda.

**Limitation before production:** EventBridge supplies literal object keys,
but the existing Lambda S3 notification adapter performs form-URL-decoding.
For this interim synthetic test use safe filenames without `+` or `%`.
The adapter must support EventBridge's native event format or distinguish
its key encoding before accepting real SES delivery. EventBridge's input
transformer does not perform URL encoding.
