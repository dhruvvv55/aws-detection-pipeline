from detections import s3_public


def public_policy(principal="*", condition=None, effect="Allow"):
    stmt = {"Sid": "Pub", "Effect": effect, "Principal": principal,
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::victim-bucket/*"}
    if condition:
        stmt["Condition"] = condition
    return {"bucketPolicy": {"Version": "2012-10-17", "Statement": [stmt]}}


# ---------- bucket policies ----------

def test_real_deny_policy_is_benign(benign_policy_detail):
    assert s3_public.evaluate(benign_policy_detail) is None


def test_allow_star_principal_is_public(make_s3_event):
    result = s3_public.evaluate(make_s3_event("PutBucketPolicy", public_policy("*")))
    assert result["bucket"] == "victim-bucket"
    assert result["resource"] == "arn:aws:s3:::victim-bucket"


def test_allow_aws_star_principal_is_public(make_s3_event):
    assert s3_public.evaluate(make_s3_event("PutBucketPolicy", public_policy({"AWS": "*"})))
    assert s3_public.evaluate(make_s3_event("PutBucketPolicy", public_policy({"AWS": ["*"]})))


def test_specific_principal_is_benign(make_s3_event):
    policy = public_policy({"AWS": "arn:aws:iam::123456789012:role/reader"})
    assert s3_public.evaluate(make_s3_event("PutBucketPolicy", policy)) is None


def test_conditioned_star_principal_is_not_flagged(make_s3_event):
    policy = public_policy("*", condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})
    assert s3_public.evaluate(make_s3_event("PutBucketPolicy", policy)) is None


def test_policy_as_json_string_is_parsed(make_s3_event):
    import json
    policy = {"bucketPolicy": json.dumps(public_policy("*")["bucketPolicy"])}
    assert s3_public.evaluate(make_s3_event("PutBucketPolicy", policy))


# ---------- ACLs ----------

def test_acl_grant_to_all_users_is_public(make_s3_event):
    params = {"AccessControlPolicy": {"AccessControlList": {"Grant": [{
        "Grantee": {"xsi:type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
        "Permission": "READ"}]}}}
    result = s3_public.evaluate(make_s3_event("PutBucketAcl", params))
    assert "AllUsers" in result["reason"]


def test_canned_public_read_is_public(make_s3_event):
    assert s3_public.evaluate(make_s3_event("PutBucketAcl", {"x-amz-acl": ["public-read"]}))


def test_private_canned_acl_is_benign(make_s3_event):
    assert s3_public.evaluate(make_s3_event("PutBucketAcl", {"x-amz-acl": ["private"]})) is None


# ---------- Block Public Access ----------

def test_deleting_bpa_is_flagged(make_s3_event):
    assert s3_public.evaluate(make_s3_event("DeleteBucketPublicAccessBlock", {}))


def test_weakening_one_bpa_flag_is_flagged(make_s3_event):
    cfg = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
           "BlockPublicPolicy": False, "RestrictPublicBuckets": True}
    result = s3_public.evaluate(make_s3_event("PutBucketPublicAccessBlock",
                                              {"PublicAccessBlockConfiguration": cfg}))
    assert "BlockPublicPolicy" in result["reason"]


def test_our_own_remediation_is_benign(make_s3_event):
    """Re-applying BPA creates this exact event. It must not trigger again."""
    cfg = {flag: True for flag in s3_public.BPA_FLAGS}
    assert s3_public.evaluate(make_s3_event("PutBucketPublicAccessBlock",
                                            {"PublicAccessBlockConfiguration": cfg})) is None


def test_unrelated_event_is_ignored(make_s3_event):
    assert s3_public.evaluate(make_s3_event("PutBucketTagging", {})) is None
