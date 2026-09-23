#!/usr/bin/env bash
# Trigger detection 1 (S3 bucket made public) on a throwaway bucket and
# watch the pipeline revert it. Deletes the bucket at the end (KEEP=1 to keep).
#
#   scripts/simulate_s3_public.sh             delete Block Public Access (default, safe)
#   scripts/simulate_s3_public.sh policy      also attach a public-read policy
#   scripts/simulate_s3_public.sh allowlist   tagged bucket, pipeline should leave it alone
set -euo pipefail

PROFILE="${AWS_PROFILE:-detlab}"
MODE="${1:-bpa}"
BUCKET="detlab-sim-s3-$(date +%s)"

aws_() { aws --profile "$PROFILE" --region us-east-1 "$@"; }

bpa_state() {
  aws_ s3api get-public-access-block --bucket "$BUCKET" \
    --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
    --output text 2>/dev/null | xargs || echo "none"
}

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    aws_ s3 rb "s3://$BUCKET" --force >/dev/null 2>&1 && echo "deleted $BUCKET"
  else
    echo "kept $BUCKET (delete with: aws s3 rb s3://$BUCKET --force --profile $PROFILE)"
  fi
}
trap cleanup EXIT

echo "creating $BUCKET"
aws_ s3api create-bucket --bucket "$BUCKET" >/dev/null

if [[ "$MODE" == "allowlist" ]]; then
  aws_ s3api put-bucket-tagging --bucket "$BUCKET" \
    --tagging 'TagSet=[{Key=detlab:allow-public,Value=true}]'
  echo "tagged detlab:allow-public=true"
fi

START=$(date +%s)
aws_ s3api delete-public-access-block --bucket "$BUCKET"
echo "$(date -u +%H:%M:%S) deleted Block Public Access"

if [[ "$MODE" == "policy" ]]; then
  cat > /tmp/detlab-public-policy.json <<POLICY
{"Version":"2012-10-17","Statement":[{"Sid":"SimPublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::$BUCKET/*"}]}
POLICY
  if aws_ s3api put-bucket-policy --bucket "$BUCKET" --policy file:///tmp/detlab-public-policy.json 2>/dev/null; then
    echo "$(date -u +%H:%M:%S) attached public-read policy"
  else
    echo "put-bucket-policy was denied, most likely account-level Block Public Access is on."
    echo "That's fine, the BPA deletion above still exercises the pipeline."
  fi
fi

echo "watching for remediation (up to 90s)..."
for _ in $(seq 1 45); do
  sleep 2
  if [[ "$(bpa_state)" == "True True True True" ]]; then
    echo "REVERTED: Block Public Access back on ~$(( $(date +%s) - START ))s after the change (polled every 2s)"
    exit 0
  fi
done

if [[ "$MODE" == "allowlist" ]]; then
  echo "OK: still unprotected after 90s, the allowlist was respected"
else
  echo "NOT reverted after 90s. Check: aws logs tail /aws/lambda/aws-detect-remediate-handler --profile $PROFILE"
  exit 1
fi
