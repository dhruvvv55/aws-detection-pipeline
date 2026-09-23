#!/usr/bin/env bash
# Trigger detection 2 (IAM privilege escalation) on a throwaway IAM user
# that has no password and no console access. The user is deleted at the
# end (KEEP=1 to keep it).
#
#   scripts/simulate_iam_privesc.sh            attach AdministratorAccess (default)
#   scripts/simulate_iam_privesc.sh inline     inline policy allowing * on *
#   scripts/simulate_iam_privesc.sh key        create an access key for the user (you are a different identity)
#   scripts/simulate_iam_privesc.sh group      add the user to your admin group (ADMIN_GROUP, default "admins")
#   scripts/simulate_iam_privesc.sh allowlist  tagged user gets AdministratorAccess, should be left alone
set -euo pipefail

PROFILE="${AWS_PROFILE:-detlab}"
MODE="${1:-admin}"
ADMIN_GROUP="${ADMIN_GROUP:-admins}"
USER_NAME="detlab-sim-user-$(date +%s)"
INLINE_NAME="detlab-sim-wildcard"
ADMIN_ARN="arn:aws:iam::aws:policy/AdministratorAccess"
KEY_ID=""

aws_() { aws --profile "$PROFILE" --region us-east-1 "$@"; }

case "$MODE" in
  admin|inline|key|group|allowlist) ;;
  *) echo "usage: $0 [admin|inline|key|group|allowlist]"; exit 2 ;;
esac

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "kept $USER_NAME"
    return
  fi
  local items
  items=$(aws_ iam list-attached-user-policies --user-name "$USER_NAME" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)
  for a in $items; do [[ "$a" == None ]] || aws_ iam detach-user-policy --user-name "$USER_NAME" --policy-arn "$a" || true; done
  items=$(aws_ iam list-user-policies --user-name "$USER_NAME" --query 'PolicyNames' --output text 2>/dev/null || true)
  for p in $items; do [[ "$p" == None ]] || aws_ iam delete-user-policy --user-name "$USER_NAME" --policy-name "$p" || true; done
  items=$(aws_ iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null || true)
  for k in $items; do [[ "$k" == None ]] || aws_ iam delete-access-key --user-name "$USER_NAME" --access-key-id "$k" || true; done
  items=$(aws_ iam list-groups-for-user --user-name "$USER_NAME" --query 'Groups[].GroupName' --output text 2>/dev/null || true)
  for g in $items; do [[ "$g" == None ]] || aws_ iam remove-user-from-group --user-name "$USER_NAME" --group-name "$g" || true; done
  if aws_ iam delete-user --user-name "$USER_NAME" 2>/dev/null; then
    echo "deleted $USER_NAME"
  else
    echo "could not delete $USER_NAME, remove it by hand"
  fi
}

# Returns 0 once the pipeline has undone the change
reverted() {
  local out
  case "$MODE" in
    admin|allowlist)
      out=$(aws_ iam list-attached-user-policies --user-name "$USER_NAME" --query 'AttachedPolicies[].PolicyName' --output text) || return 1
      [[ "$out" != *AdministratorAccess* ]] ;;
    inline)
      out=$(aws_ iam list-user-policies --user-name "$USER_NAME" --query 'PolicyNames' --output text) || return 1
      [[ "$out" != *"$INLINE_NAME"* ]] ;;
    key)
      out=$(aws_ iam list-access-keys --user-name "$USER_NAME" --query "AccessKeyMetadata[?AccessKeyId=='$KEY_ID'].Status" --output text) || return 1
      [[ "$out" == "Inactive" ]] ;;
    group)
      out=$(aws_ iam list-groups-for-user --user-name "$USER_NAME" --query 'Groups[].GroupName' --output text) || return 1
      for g in $out; do [[ "$g" == "$ADMIN_GROUP" ]] && return 1; done
      return 0 ;;
  esac
}

TAGS="Key=detlab:simulation,Value=true"
[[ "$MODE" == "allowlist" ]] && TAGS="$TAGS Key=detlab:allow-privileged,Value=true"
# shellcheck disable=SC2086
aws_ iam create-user --user-name "$USER_NAME" --tags $TAGS >/dev/null
trap cleanup EXIT
echo "created $USER_NAME (no password, no console)"

START=$(date +%s)
case "$MODE" in
  admin|allowlist)
    aws_ iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$ADMIN_ARN"
    echo "$(date -u +%H:%M:%S) attached AdministratorAccess" ;;
  inline)
    aws_ iam put-user-policy --user-name "$USER_NAME" --policy-name "$INLINE_NAME" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    echo "$(date -u +%H:%M:%S) put inline policy allowing * on *" ;;
  key)
    # Only the key ID is captured. The secret is never printed or stored.
    KEY_ID=$(aws_ iam create-access-key --user-name "$USER_NAME" --query 'AccessKey.AccessKeyId' --output text)
    echo "$(date -u +%H:%M:%S) created access key $KEY_ID (secret discarded)" ;;
  group)
    aws_ iam add-user-to-group --group-name "$ADMIN_GROUP" --user-name "$USER_NAME"
    echo "$(date -u +%H:%M:%S) added user to group $ADMIN_GROUP" ;;
esac

echo "watching for remediation (up to 120s)..."
for _ in $(seq 1 60); do
  sleep 2
  if reverted; then
    if [[ "$MODE" == "allowlist" ]]; then
      echo "FAIL: allowlisted user was remediated anyway"
      exit 1
    fi
    echo "REVERTED: undone ~$(( $(date +%s) - START ))s after the change (polled every 2s)"
    exit 0
  fi
done

if [[ "$MODE" == "allowlist" ]]; then
  echo "OK: still has AdministratorAccess after 120s, the allowlist was respected"
else
  echo "NOT reverted after 120s. Check: aws logs tail /aws/lambda/aws-detect-remediate-handler --profile $PROFILE"
  exit 1
fi
