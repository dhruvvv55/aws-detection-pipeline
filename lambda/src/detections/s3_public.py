"""Detection 1: S3 bucket made public.

ATT&CK T1530 (Data from Cloud Storage). A public bucket is how most cloud
data exposure starts, so the fix is to put S3 Block Public Access back on.
"""

import json
import logging

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

NAME = "s3_bucket_public"
TECHNIQUE = "T1530"
TECHNIQUE_NAME = "Data from Cloud Storage"
EVENT_NAMES = {
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeleteBucketPublicAccessBlock",
    "PutBucketPublicAccessBlock",
}

ALLOWLIST_TAG_KEY = "detlab:allow-public"
ALLOWLIST_TAG_VALUE = "true"

PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)
PUBLIC_CANNED_ACLS = {"public-read", "public-read-write", "authenticated-read"}
BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _truthy(value):
    return value is True or str(value).lower() == "true"


def _is_wildcard_principal(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _as_list(principal.get("AWS"))
    return False


def _public_policy_reason(policy):
    if isinstance(policy, str):
        policy = json.loads(policy) if policy else {}
    for stmt in _as_list(policy.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        if not _is_wildcard_principal(stmt.get("Principal")):
            continue
        # A Condition (source VPC, org ID, IP range...) usually narrows who can
        # get in. Treating those as not public avoids false positives; the
        # README lists this as a known limitation.
        if stmt.get("Condition"):
            continue
        return f"bucket policy statement '{stmt.get('Sid', 'no Sid')}' allows Principal * with no conditions"
    return None


def _public_acl_reason(params):
    for canned in _as_list(params.get("x-amz-acl")):
        if canned in PUBLIC_CANNED_ACLS:
            return f"canned ACL '{canned}' applied"
    grants = json.dumps(params.get("AccessControlPolicy", {}))
    for group in PUBLIC_GROUPS:
        if group in grants:
            return f"ACL grants access to {group.rsplit('/', 1)[1]}"
    return None


def _weakened_bpa_reason(params):
    config = params.get("PublicAccessBlockConfiguration") or {}
    # An omitted flag means false, which is how AWS treats it too
    disabled = [flag for flag in BPA_FLAGS if not _truthy(config.get(flag, False))]
    if disabled:
        return "Block Public Access weakened, disabled: " + ", ".join(disabled)
    return None


def evaluate(detail):
    """Return a result dict if this CloudTrail event made a bucket public, else None."""
    params = detail.get("requestParameters") or {}
    bucket = params.get("bucketName")
    event_name = detail.get("eventName")

    if event_name == "PutBucketPolicy":
        reason = _public_policy_reason(params.get("bucketPolicy") or {})
    elif event_name == "PutBucketAcl":
        reason = _public_acl_reason(params)
    elif event_name == "DeleteBucketPublicAccessBlock":
        reason = "Block Public Access configuration deleted"
    elif event_name == "PutBucketPublicAccessBlock":
        # Our own remediation shows up here with every flag true, which is
        # why this returns None for it instead of looping forever
        reason = _weakened_bpa_reason(params)
    else:
        return None

    if not reason or not bucket:
        return None
    return {"bucket": bucket, "resource": f"arn:aws:s3:::{bucket}", "reason": reason}


def is_allowlisted(result, client):
    try:
        tags = client("s3").get_bucket_tagging(Bucket=result["bucket"])["TagSet"]
    except ClientError as err:
        # NoSuchTagSet just means untagged. Anything else, fail closed and remediate.
        if err.response["Error"]["Code"] != "NoSuchTagSet":
            logger.warning("could not read tags for %s: %s", result["bucket"], err)
        return False
    return any(t["Key"] == ALLOWLIST_TAG_KEY and t["Value"].lower() == ALLOWLIST_TAG_VALUE for t in tags)


def remediate(result, client):
    # One fix covers every trigger. BlockPublicPolicy and RestrictPublicBuckets
    # neutralize a public policy, IgnorePublicAcls neutralizes public ACLs.
    client("s3").put_public_access_block(
        Bucket=result["bucket"],
        PublicAccessBlockConfiguration={flag: True for flag in BPA_FLAGS},
    )
    return "re-applied S3 Block Public Access (all four settings)"
