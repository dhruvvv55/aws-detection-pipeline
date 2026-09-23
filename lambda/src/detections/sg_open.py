"""Detection 3: security group opened to the internet on SSH or RDP.

ATT&CK T1562.007 (Disable or Modify Cloud Firewall). An SG allowing 22/3389
from 0.0.0.0/0 or ::/0 puts a login prompt in front of every scanner on the
internet. The fix revokes only the offending rule, nothing else in the group.
"""

import logging

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

NAME = "security_group_open_to_internet"
TECHNIQUE = "T1562.007"
TECHNIQUE_NAME = "Disable or Modify Cloud Firewall"
EVENT_NAMES = {"AuthorizeSecurityGroupIngress"}

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"
ALLOWLIST_TAG_KEY = "detlab:allow-public-ingress"
ALLOWLIST_TAG_VALUE = "true"


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _items(value):
    """EC2 CloudTrail events wrap lists as {"items": [...]}."""
    if isinstance(value, dict):
        return _as_list(value.get("items"))
    return _as_list(value)


def exposed_ports(protocol, from_port, to_port):
    """Which sensitive ports a rule covers. Protocol -1 means all traffic."""
    proto = str(protocol).lower()
    if proto in ("-1", "all"):
        return sorted(SENSITIVE_PORTS)
    if proto not in ("tcp", "6"):
        return []
    try:
        low, high = int(from_port), int(to_port)
    except (TypeError, ValueError):
        return []
    return [p for p in sorted(SENSITIVE_PORTS) if low <= p <= high]


def _open_ranges(permission):
    v4 = [r["cidrIp"] for r in _items(permission.get("ipRanges")) if r.get("cidrIp") == OPEN_V4]
    v6 = [r["cidrIpv6"] for r in _items(permission.get("ipv6Ranges")) if r.get("cidrIpv6") == OPEN_V6]
    return v4 + v6


def _offending_rule_ids(response):
    """Rule IDs AWS assigned to the risky rules. Lets us revoke exactly those."""
    ids, group_id = [], None
    for rule in _items((response or {}).get("securityGroupRuleSet")):
        group_id = group_id or rule.get("groupId")
        if str(rule.get("isEgress")).lower() == "true":
            continue
        cidr = rule.get("cidrIpv4") or rule.get("cidrIpv6")
        if cidr in (OPEN_V4, OPEN_V6) and exposed_ports(rule.get("ipProtocol"), rule.get("fromPort"), rule.get("toPort")):
            ids.append(rule["securityGroupRuleId"])
    return ids, group_id


def evaluate(detail):
    params = detail.get("requestParameters") or {}
    offending, ports, cidrs = [], set(), set()

    for perm in _items(params.get("ipPermissions")):
        perm_ports = exposed_ports(perm.get("ipProtocol"), perm.get("fromPort"), perm.get("toPort"))
        ranges = _open_ranges(perm)
        if perm_ports and ranges:
            offending.append({
                "protocol": str(perm.get("ipProtocol")),
                "from_port": perm.get("fromPort"),
                "to_port": perm.get("toPort"),
                "cidrs": ranges,
            })
            ports.update(perm_ports)
            cidrs.update(ranges)

    if not offending:
        return None

    rule_ids, response_group = _offending_rule_ids(detail.get("responseElements"))
    group_id = params.get("groupId") or response_group
    group_name = params.get("groupName")
    if not (group_id or group_name):
        return None

    region = detail.get("awsRegion")
    account = detail.get("recipientAccountId", "")
    port_text = ", ".join(f"{SENSITIVE_PORTS[p]} ({p})" for p in sorted(ports))
    return {
        "group_id": group_id,
        "group_name": group_name,
        "region": region,
        "rule_ids": rule_ids,
        "permissions": offending,
        "resource": f"arn:aws:ec2:{region}:{account}:security-group/{group_id or group_name}",
        "reason": f"ingress from {', '.join(sorted(cidrs))} opened to {port_text}",
    }


def is_allowlisted(result, client):
    if not result.get("group_id"):
        return False
    try:
        groups = client("ec2", region=result["region"]).describe_security_groups(
            GroupIds=[result["group_id"]])["SecurityGroups"]
    except ClientError as err:
        logger.warning("could not read tags for %s: %s", result["group_id"], err)
        return False  # fail closed
    tags = groups[0].get("Tags", []) if groups else []
    return any(t["Key"] == ALLOWLIST_TAG_KEY and t["Value"].lower() == ALLOWLIST_TAG_VALUE for t in tags)


def _permissions_to_revoke(result):
    """Fallback when the event has no rule IDs: revoke by exact permission match."""
    perms = []
    for p in result["permissions"]:
        perm = {"IpProtocol": p["protocol"]}
        if p["protocol"] not in ("-1", "all"):
            perm["FromPort"], perm["ToPort"] = int(p["from_port"]), int(p["to_port"])
        v4 = [{"CidrIp": c} for c in p["cidrs"] if ":" not in c]
        v6 = [{"CidrIpv6": c} for c in p["cidrs"] if ":" in c]
        if v4:
            perm["IpRanges"] = v4
        if v6:
            perm["Ipv6Ranges"] = v6
        perms.append(perm)
    return perms


def remediate(result, client):
    ec2 = client("ec2", region=result["region"])
    target = {"GroupId": result["group_id"]} if result.get("group_id") else {"GroupName": result["group_name"]}
    label = result.get("group_id") or result["group_name"]

    if result["rule_ids"]:
        resp = ec2.revoke_security_group_ingress(**target, SecurityGroupRuleIds=result["rule_ids"])
        done = f"revoked rule {', '.join(result['rule_ids'])} on {label}"
    else:
        resp = ec2.revoke_security_group_ingress(**target, IpPermissions=_permissions_to_revoke(result))
        done = f"revoked open ingress on {label} by permission match"

    # Revoke doesn't raise when nothing matched, it just says so. Treat that
    # as a failure so the finding says FAILED instead of lying about success.
    if resp.get("Return") is False or resp.get("UnknownIpPermissions"):
        raise RuntimeError(f"revoke on {label} matched nothing: {resp}")
    return done
