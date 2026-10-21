#!/usr/bin/env bash
# Explicitly manual, synthetic-only ingestion smoke check.
# No CloudFormation, SES, DNS, retention expiry or bucket notifications.
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
STACK="${SMOKE_STACK:-dmarc-tally-smoke}"

if [[ "$STACK" != dmarc-tally-smoke && "$STACK" != dmarc-tally-smoke-* ]]; then
  echo "Refusing to run outside an explicitly named dmarc-tally-smoke stack" >&2
  exit 1
fi
for executable in aws python3; do
  command -v "$executable" >/dev/null || { echo "$executable is required" >&2; exit 1; }
done

root="$(cd "$(dirname "$0")/.." && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

stack_tag="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Tags[?Key=='Purpose'].Value | [0]" --output text)"
if [[ "$stack_tag" != "isolated-smoke-test" ]]; then
  echo "Stack is missing the required Purpose=isolated-smoke-test tag; refusing" >&2
  exit 1
fi

output() {
  aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text
}
bucket="$(output IntakeBucket)"
table="$(output ReportsTable)"
function="$(output IngestFunction)"
for value in "$bucket" "$table" "$function"; do
  if [[ -z "$value" || "$value" == "None" ]]; then
    echo "Missing CloudFormation output; refusing" >&2
    exit 1
  fi
done

echo "Synthetic-only AWS smoke target:"
echo "  Region:   $REGION"
echo "  Stack:    $STACK"
echo "  Function: $function"
echo "  Table:    $table"
echo "  Bucket:   $bucket"
echo
read -r -p "Type RUN-SMOKE to upload synthetic fixtures and invoke Lambda: " confirmation
if [[ "$confirmation" != "RUN-SMOKE" ]]; then
  echo "Cancelled without modifying AWS resources."
  exit 0
fi

invoke() {
  local key="$1" expected="$2" response="$3"
  python3 - "$bucket" "$key" > "$workdir/event.json" <<'PY'
import json
import sys
from urllib.parse import quote
bucket, key = sys.argv[1:]
print(json.dumps({
    "Records": [{
        "eventSource": "aws:s3",
        "eventName": "ObjectCreated:Put",
        "s3": {"bucket": {"name": bucket}, "object": {"key": quote(key, safe="")}},
    }],
}))
PY
  aws lambda invoke \
    --region "$REGION" --function-name "$function" \
    --cli-binary-format raw-in-base64-out \
    --payload "fileb://$workdir/event.json" \
    "$workdir/response.json" >/dev/null

  python3 - "$workdir/response.json" "$expected" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
expected = sys.argv[2]
if not isinstance(payload, dict):
    raise SystemExit("Unexpected non-JSON Lambda response")
if payload.get("processed") != 1:
    raise SystemExit(f"Expected one processed S3 record: {payload}")
if expected == "captured" and (payload.get("captured"), payload.get("retained")) != (1, 0):
    raise SystemExit(f"Expected captured report: {payload}")
if expected == "retained" and (payload.get("captured"), payload.get("retained")) != (0, 1):
    raise SystemExit(f"Expected retained invalid report: {payload}")
print("Lambda result:", json.dumps(payload, sort_keys=True))
PY
}

aws s3 cp "$root/tests/fixtures/mime/smoke-valid.eml" \
  "s3://$bucket/incoming/smoke-valid.eml" --region "$REGION" >/dev/null
echo "1. First synthetic report import:"
invoke "incoming/smoke-valid.eml" captured

captured="$(aws s3api get-object-tagging --region "$REGION" --bucket "$bucket" \
  --key "incoming/smoke-valid.eml" --query "TagSet[?Key=='captured'].Value | [0]" --output text)"
if [[ "$captured" != "true" ]]; then
  echo "Expected S3 captured=true tag on valid input; got $captured" >&2
  exit 1
fi
count="$(aws dynamodb query --region "$REGION" --table-name "$table" \
  --key-condition-expression 'PK = :pk' \
  --expression-attribute-values '{":pk":{"S":"DOMAIN#example.com"}}' \
  --query 'Count' --output text)"
if [[ "$count" != "2" ]]; then
  echo "Expected one metadata + one record item; got $count" >&2
  exit 1
fi

echo "2. Replay the same message (must not duplicate):"
invoke "incoming/smoke-valid.eml" captured
count_after="$(aws dynamodb query --region "$REGION" --table-name "$table" \
  --key-condition-expression 'PK = :pk' \
  --expression-attribute-values '{":pk":{"S":"DOMAIN#example.com"}}' \
  --query 'Count' --output text)"
if [[ "$count_after" != "$count" ]]; then
  echo "Duplicate delivery changed report item count" >&2
  exit 1
fi

aws s3 cp "$root/tests/fixtures/mime/smoke-invalid.eml" \
  "s3://$bucket/incoming/smoke-invalid.eml" --region "$REGION" >/dev/null
echo "3. Import a malformed synthetic report (must remain untagged):"
invoke "incoming/smoke-invalid.eml" retained
invalid_tag="$(aws s3api get-object-tagging --region "$REGION" --bucket "$bucket" \
  --key "incoming/smoke-invalid.eml" --query "TagSet[?Key=='captured'].Value | [0]" --output text)"
if [[ "$invalid_tag" == "true" ]]; then
  echo "Invalid report was incorrectly marked captured" >&2
  exit 1
fi

echo "Smoke assertions passed: captured metadata/record, idempotent replay, invalid retained."
echo "Isolated S3 and DynamoDB resources have NOT been deleted."
echo "Use CloudWatch log group from the stack outputs to investigate any warnings."
