#!/usr/bin/env bash
# Trigger detection 3 (security group opened to the internet) on a throwaway
# security group with nothing attached to it. The group (and a temporary VPC,
# if one had to be created) is deleted at the end (KEEP=1 to keep).
#
#   scripts/simulate_sg_open.sh            SSH (22) from 0.0.0.0/0 (default)
#   scripts/simulate_sg_open.sh rdp        RDP (3389) from ::/0
#   scripts/simulate_sg_open.sh all        all traffic from 0.0.0.0/0
#   scripts/simulate_sg_open.sh benign     HTTPS (443) from 0.0.0.0/0, should NOT be reverted
#   scripts/simulate_sg_open.sh allowlist  tagged group, SSH from 0.0.0.0/0, should NOT be reverted
set -euo pipefail

PROFILE="${AWS_PROFILE:-detlab}"
MODE="${1:-ssh}"
SG_NAME="detlab-sim-sg-$(date +%s)"
SG_ID=""
CREATED_VPC=""

aws_() { aws --profile "$PROFILE" --region us-east-1 "$@"; }

case "$MODE" in
  ssh|allowlist) PERMS='[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"detlab simulation"}]}]' ;;
  rdp)           PERMS='[{"IpProtocol":"tcp","FromPort":3389,"ToPort":3389,"Ipv6Ranges":[{"CidrIpv6":"::/0","Description":"detlab simulation"}]}]' ;;
  all)           PERMS='[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"detlab simulation"}]}]' ;;
  benign)        PERMS='[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"detlab simulation"}]}]' ;;
  *) echo "usage: $0 [ssh|rdp|all|benign|allowlist]"; exit 2 ;;
esac

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "kept $SG_ID ${CREATED_VPC:+and VPC $CREATED_VPC}"
    return
  fi
  if [[ -n "$SG_ID" ]]; then
    if aws_ ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1; then echo "deleted $SG_ID"; fi
  fi
  if [[ -n "$CREATED_VPC" ]]; then
    if aws_ ec2 delete-vpc --vpc-id "$CREATED_VPC" 2>/dev/null; then echo "deleted temporary VPC $CREATED_VPC"; fi
  fi
}
trap cleanup EXIT

VPC_ID=$(aws_ ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  VPC_ID=$(aws_ ec2 create-vpc --cidr-block 10.99.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=detlab:simulation,Value=true}]' \
    --query 'Vpc.VpcId' --output text)
  CREATED_VPC="$VPC_ID"
  echo "no default VPC, created temporary $VPC_ID"
fi

TAGS='ResourceType=security-group,Tags=[{Key=detlab:simulation,Value=true}]'
if [[ "$MODE" == "allowlist" ]]; then
  TAGS='ResourceType=security-group,Tags=[{Key=detlab:simulation,Value=true},{Key=detlab:allow-public-ingress,Value=true}]'
fi

SG_ID=$(aws_ ec2 create-security-group --group-name "$SG_NAME" --vpc-id "$VPC_ID" \
  --description "detlab simulation, safe to delete" --tag-specifications "$TAGS" \
  --query GroupId --output text)
echo "created $SG_ID in $VPC_ID (nothing attached)"

START=$(date +%s)
RULE_ID=$(aws_ ec2 authorize-security-group-ingress --group-id "$SG_ID" --ip-permissions "$PERMS" \
  --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text)
echo "$(date -u +%H:%M:%S) added $MODE rule $RULE_ID"

rule_gone() {
  local out
  out=$(aws_ ec2 describe-security-group-rules --filters "Name=group-id,Values=$SG_ID" \
    --query "SecurityGroupRules[?SecurityGroupRuleId=='$RULE_ID'].SecurityGroupRuleId" --output text) || return 1
  [[ -z "$out" || "$out" == "None" ]]
}

if [[ "$MODE" == "benign" || "$MODE" == "allowlist" ]]; then
  echo "rule should survive, watching for 90s..."
  for _ in $(seq 1 45); do
    sleep 2
    if rule_gone; then echo "FAIL: rule was revoked but should have been left alone"; exit 1; fi
  done
  echo "OK: rule still there after 90s, correctly left alone"
  exit 0
fi

echo "watching for remediation (up to 120s)..."
for _ in $(seq 1 60); do
  sleep 2
  if rule_gone; then
    echo "REVERTED: rule revoked ~$(( $(date +%s) - START ))s after the change (polled every 2s)"
    exit 0
  fi
done
echo "NOT reverted after 120s. Check: aws logs tail /aws/lambda/aws-detect-remediate-handler --profile $PROFILE"
exit 1
