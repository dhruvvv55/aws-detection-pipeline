"""Detection 2: IAM privilege escalation.

Covers four ways to quietly give someone admin-level access:
  * attaching AdministratorAccess / IAMFullAccess     T1098.003
  * an inline policy allowing * or iam:* on *         T1098.003
  * adding a user to a group that is effectively admin T1098.003
  * creating an access key for a *different* user      T1098.001

Every remediation only ever removes access. The Lambda role has no
permission to grant anything.
"""

import json
import logging
from urllib.parse import unquote

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

NAME = "iam_privilege_escalation"
TECHNIQUE = "T1098"
TECHNIQUE_NAME = "Account Manipulation"
ROLES = {"technique": "T1098.003", "technique_name": "Additional Cloud Roles"}
CREDS = {"technique": "T1098.001", "technique_name": "Additional Cloud Credentials"}

ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
INLINE_EVENTS = {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"}
EVENT_NAMES = ATTACH_EVENTS | INLINE_EVENTS | {"CreateAccessKey", "AddUserToGroup"}

HIGH_RISK_MANAGED = {"AdministratorAccess", "IAMFullAccess"}
ALLOWLIST_TAG_KEY = "detlab:allow-privileged"
ALLOWLIST_TAG_VALUE = "true"


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _kind(event_name):
    """AttachUserPolicy -> 'user', PutRolePolicy -> 'role', etc."""
    for kind in ("User", "Role", "Group"):
        if event_name.endswith(f"{kind}Policy"):
            return kind.lower()
    return None


def load_policy_document(doc):
    """CloudTrail usually logs policy JSON as a string, sometimes URL-encoded."""
    if isinstance(doc, dict):
        return doc
    if not doc:
        return {}
    try:
        return json.loads(doc)
    except json.JSONDecodeError:
        return json.loads(unquote(doc))


def is_high_risk_managed(policy_arn):
    # Only AWS-managed ones (account field "aws"). A customer policy that
    # happens to be named AdministratorAccess could contain anything.
    parts = (policy_arn or "").split(":")
    return (
        len(parts) >= 6
        and parts[2] == "iam"
        and parts[4] == "aws"
        and parts[5].split("/")[-1] in HIGH_RISK_MANAGED
    )


def wildcard_statement(doc):
    """Return the first Allow statement granting * or iam:* on every resource."""
    for stmt in _as_list(doc.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
        if any(a in ("*", "iam:*") for a in actions) and "*" in _as_list(stmt.get("Resource")):
            return stmt
    return None


def evaluate(detail):
    event_name = detail.get("eventName")
    params = detail.get("requestParameters") or {}
    account = detail.get("recipientAccountId", "")

    def arn(kind, name):
        return f"arn:aws:iam::{account}:{kind}/{name}"

    if event_name in ATTACH_EVENTS:
        kind = _kind(event_name)
        principal = params.get(f"{kind}Name")
        policy_arn = params.get("policyArn")
        if principal and is_high_risk_managed(policy_arn):
            policy = policy_arn.split("/")[-1]
            return {
                "action": "detach", "kind": kind, "principal": principal,
                "policy_arn": policy_arn, "resource": arn(kind, principal),
                "reason": f"{policy} attached to {kind} {principal}", **ROLES,
            }
        return None

    if event_name in INLINE_EVENTS:
        kind = _kind(event_name)
        principal = params.get(f"{kind}Name")
        policy_name = params.get("policyName")
        try:
            doc = load_policy_document(params.get("policyDocument"))
        except (json.JSONDecodeError, TypeError):
            logger.warning("could not parse policy document in %s", detail.get("eventID"))
            return None
        stmt = wildcard_statement(doc)
        if principal and policy_name and stmt:
            return {
                "action": "delete_inline", "kind": kind, "principal": principal,
                "policy_name": policy_name, "resource": arn(kind, principal),
                "reason": f"inline policy '{policy_name}' on {kind} {principal} allows "
                          f"{stmt.get('Action')} on *",
                "evidence": json.dumps(doc),  # the policy gets deleted, so keep a copy
                **ROLES,
            }
        return None

    if event_name == "CreateAccessKey":
        target = params.get("userName")  # absent means "a key for myself"
        identity = detail.get("userIdentity", {})
        actor_user = identity.get("userName") if identity.get("type") == "IAMUser" else None
        key_id = ((detail.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
        if target and target != actor_user and key_id:
            return {
                "action": "deactivate_key", "kind": "user", "principal": target,
                "access_key_id": key_id, "resource": arn("user", target),
                "reason": f"access key {key_id} created for user {target} by a different identity",
                **CREDS,
            }
        return None

    if event_name == "AddUserToGroup":
        group, user = params.get("groupName"), params.get("userName")
        if group and user:
            # Whether this is escalation depends on what the group grants,
            # which isn't in the event. confirm() checks that with an API call.
            return {
                "action": "remove_from_group", "kind": "user", "principal": user,
                "group": group, "resource": arn("group", group),
                "reason": f"user {user} added to group {group}",
                "needs_confirmation": True, **ROLES,
            }
    return None


def _group_admin_reason(group, iam):
    for p in iam.list_attached_group_policies(GroupName=group)["AttachedPolicies"]:
        if is_high_risk_managed(p["PolicyArn"]):
            return f"group has {p['PolicyName']} attached"
    for name in iam.list_group_policies(GroupName=group)["PolicyNames"]:
        doc = load_policy_document(iam.get_group_policy(GroupName=group, PolicyName=name)["PolicyDocument"])
        if wildcard_statement(doc):
            return f"group has wildcard inline policy '{name}'"
    return None


def confirm(result, client):
    """Extra check for results that can't be judged from the event alone."""
    if not result.get("needs_confirmation"):
        return True
    try:
        why = _group_admin_reason(result["group"], client("iam"))
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return False  # group is already gone, nothing to fix
        logger.warning("could not inspect group %s, treating as privileged: %s", result["group"], err)
        return True  # fail closed
    if why:
        result["reason"] += f" ({why})"
        return True
    return False


def is_allowlisted(result, client):
    iam = client("iam")
    name = result["principal"]
    try:
        if result["kind"] == "user":
            tags = iam.list_user_tags(UserName=name)["Tags"]
        elif result["kind"] == "role":
            tags = iam.list_role_tags(RoleName=name)["Tags"]
        else:
            return False  # IAM groups can't be tagged, so they're never allowlisted
    except ClientError as err:
        logger.warning("could not read tags for %s %s: %s", result["kind"], name, err)
        return False  # fail closed
    return any(t["Key"] == ALLOWLIST_TAG_KEY and t["Value"].lower() == ALLOWLIST_TAG_VALUE for t in tags)


def remediate(result, client):
    iam = client("iam")
    kind, name, action = result["kind"], result["principal"], result["action"]
    name_param = f"{kind.capitalize()}Name"

    if action == "detach":
        getattr(iam, f"detach_{kind}_policy")(**{name_param: name, "PolicyArn": result["policy_arn"]})
        return f"detached {result['policy_arn'].split('/')[-1]} from {kind} {name}"

    if action == "delete_inline":
        getattr(iam, f"delete_{kind}_policy")(**{name_param: name, "PolicyName": result["policy_name"]})
        return f"deleted inline policy '{result['policy_name']}' from {kind} {name} (original saved in evidence)"

    if action == "deactivate_key":
        # Deactivate, don't delete. Reversible, and the key stays around for the investigation.
        iam.update_access_key(UserName=name, AccessKeyId=result["access_key_id"], Status="Inactive")
        return f"deactivated access key {result['access_key_id']} on user {name}"

    if action == "remove_from_group":
        iam.remove_user_from_group(GroupName=result["group"], UserName=name)
        return f"removed user {name} from group {result['group']}"

    raise ValueError(f"unknown action {action}")
