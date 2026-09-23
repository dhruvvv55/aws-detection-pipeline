import json
from urllib.parse import quote

import pytest
from botocore.exceptions import ClientError

from detections import iam_privesc

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
WILDCARD = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


class FakeIAM:
    def __init__(self, attached=(), inline=None, tags=None, missing_group=False):
        self.attached = list(attached)          # [(name, arn)] on the group
        self.inline = inline or {}              # {policy_name: doc} on the group
        self.tags = tags or {}
        self.missing_group = missing_group
        self.calls = []

    def list_attached_group_policies(self, GroupName):
        if self.missing_group:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "ListAttachedGroupPolicies")
        return {"AttachedPolicies": [{"PolicyName": n, "PolicyArn": a} for n, a in self.attached]}

    def list_group_policies(self, GroupName):
        return {"PolicyNames": list(self.inline)}

    def get_group_policy(self, GroupName, PolicyName):
        return {"PolicyDocument": self.inline[PolicyName]}

    def list_user_tags(self, UserName):
        return {"Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def list_role_tags(self, RoleName):
        return self.list_user_tags(RoleName)

    def __getattr__(self, name):
        # Any remediation call (detach_user_policy, update_access_key, ...) gets recorded
        def record(**kwargs):
            self.calls.append((name, kwargs))
        return record


# ---------- managed policy attachments ----------

@pytest.mark.parametrize("event,kind", [
    ("AttachUserPolicy", "user"), ("AttachRolePolicy", "role"), ("AttachGroupPolicy", "group"),
])
def test_admin_attach_is_flagged_for_every_principal_type(make_iam_event, event, kind):
    result = iam_privesc.evaluate(make_iam_event(event, {f"{kind}Name": "victim", "policyArn": ADMIN}))
    assert result["action"] == "detach"
    assert result["kind"] == kind
    assert result["technique"] == "T1098.003"
    assert result["resource"].endswith(f":{kind}/victim")


def test_iam_full_access_is_flagged(make_iam_event):
    arn = "arn:aws:iam::aws:policy/IAMFullAccess"
    assert iam_privesc.evaluate(make_iam_event("AttachUserPolicy", {"userName": "u", "policyArn": arn}))


def test_read_only_attach_is_benign(make_iam_event):
    arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert iam_privesc.evaluate(make_iam_event("AttachUserPolicy", {"userName": "u", "policyArn": arn})) is None


def test_customer_policy_named_admin_is_not_matched_by_name(make_iam_event):
    arn = "arn:aws:iam::123456789012:policy/AdministratorAccess"
    assert iam_privesc.evaluate(make_iam_event("AttachUserPolicy", {"userName": "u", "policyArn": arn})) is None


# ---------- inline policies ----------

def test_wildcard_inline_policy_is_flagged_and_evidence_kept(make_iam_event):
    params = {"userName": "u", "policyName": "p", "policyDocument": json.dumps(WILDCARD)}
    result = iam_privesc.evaluate(make_iam_event("PutUserPolicy", params))
    assert result["action"] == "delete_inline"
    assert json.loads(result["evidence"]) == WILDCARD


def test_url_encoded_policy_document_is_parsed(make_iam_event):
    params = {"roleName": "r", "policyName": "p", "policyDocument": quote(json.dumps(WILDCARD))}
    assert iam_privesc.evaluate(make_iam_event("PutRolePolicy", params))


def test_iam_star_on_star_is_flagged(make_iam_event):
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "iam:*"], "Resource": "*"}]}
    params = {"groupName": "g", "policyName": "p", "policyDocument": json.dumps(doc)}
    assert iam_privesc.evaluate(make_iam_event("PutGroupPolicy", params))


def test_scoped_inline_policy_is_benign(make_iam_event):
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
    params = {"userName": "u", "policyName": "p", "policyDocument": json.dumps(doc)}
    assert iam_privesc.evaluate(make_iam_event("PutUserPolicy", params)) is None


def test_star_action_on_specific_resource_is_benign(make_iam_event):
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}]}
    params = {"userName": "u", "policyName": "p", "policyDocument": json.dumps(doc)}
    assert iam_privesc.evaluate(make_iam_event("PutUserPolicy", params)) is None


def test_wildcard_deny_is_benign(make_iam_event):
    doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    params = {"userName": "u", "policyName": "p", "policyDocument": json.dumps(doc)}
    assert iam_privesc.evaluate(make_iam_event("PutUserPolicy", params)) is None


# ---------- access keys ----------

def key_response(key_id="AKIDEXAMPLE0000001"):
    return {"accessKey": {"accessKeyId": key_id, "status": "Active", "userName": "victim"}}


def test_key_for_another_user_is_flagged(make_iam_event):
    result = iam_privesc.evaluate(make_iam_event("CreateAccessKey", {"userName": "victim"}, key_response()))
    assert result["action"] == "deactivate_key"
    assert result["technique"] == "T1098.001"
    assert result["access_key_id"] == "AKIDEXAMPLE0000001"


def test_key_for_yourself_is_benign(make_iam_event):
    # Fixture actor is the IAM user dhruv-admin
    assert iam_privesc.evaluate(make_iam_event("CreateAccessKey", {"userName": "dhruv-admin"}, key_response())) is None
    assert iam_privesc.evaluate(make_iam_event("CreateAccessKey", {}, key_response())) is None


def test_role_creating_key_for_a_user_is_flagged(make_iam_event):
    detail = make_iam_event("CreateAccessKey", {"userName": "victim"}, key_response())
    detail["userIdentity"] = {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/ci/x"}
    assert iam_privesc.evaluate(detail)


# ---------- groups ----------

def group_event(make_iam_event):
    return make_iam_event("AddUserToGroup", {"groupName": "admins", "userName": "victim"})


def test_add_to_admin_group_is_confirmed(make_iam_event):
    result = iam_privesc.evaluate(group_event(make_iam_event))
    iam = FakeIAM(attached=[("AdministratorAccess", ADMIN)])
    assert iam_privesc.confirm(result, lambda _: iam)
    assert "AdministratorAccess" in result["reason"]


def test_add_to_group_with_wildcard_inline_is_confirmed(make_iam_event):
    result = iam_privesc.evaluate(group_event(make_iam_event))
    assert iam_privesc.confirm(result, lambda _: FakeIAM(inline={"all": WILDCARD}))


def test_add_to_ordinary_group_is_benign(make_iam_event):
    result = iam_privesc.evaluate(group_event(make_iam_event))
    iam = FakeIAM(attached=[("ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess")])
    assert not iam_privesc.confirm(result, lambda _: iam)


def test_add_to_deleted_group_is_benign(make_iam_event):
    result = iam_privesc.evaluate(group_event(make_iam_event))
    assert not iam_privesc.confirm(result, lambda _: FakeIAM(missing_group=True))


# ---------- allowlist + remediation ----------

def test_tagged_user_is_allowlisted(make_iam_event):
    result = iam_privesc.evaluate(make_iam_event("AttachUserPolicy", {"userName": "u", "policyArn": ADMIN}))
    assert iam_privesc.is_allowlisted(result, lambda _: FakeIAM(tags={"detlab:allow-privileged": "true"}))
    assert not iam_privesc.is_allowlisted(result, lambda _: FakeIAM())


def test_groups_are_never_allowlisted(make_iam_event):
    result = iam_privesc.evaluate(make_iam_event("AttachGroupPolicy", {"groupName": "g", "policyArn": ADMIN}))
    assert not iam_privesc.is_allowlisted(result, lambda _: FakeIAM(tags={"detlab:allow-privileged": "true"}))


@pytest.mark.parametrize("event,params,resp,expected_call", [
    ("AttachRolePolicy", {"roleName": "r", "policyArn": ADMIN}, None,
     ("detach_role_policy", {"RoleName": "r", "PolicyArn": ADMIN})),
    ("PutUserPolicy", {"userName": "u", "policyName": "p", "policyDocument": json.dumps(WILDCARD)}, None,
     ("delete_user_policy", {"UserName": "u", "PolicyName": "p"})),
    ("CreateAccessKey", {"userName": "victim"}, key_response("AKIDEXAMPLE0000009"),
     ("update_access_key", {"UserName": "victim", "AccessKeyId": "AKIDEXAMPLE0000009", "Status": "Inactive"})),
    ("AddUserToGroup", {"groupName": "admins", "userName": "victim"}, None,
     ("remove_user_from_group", {"GroupName": "admins", "UserName": "victim"})),
])
def test_remediation_makes_the_right_api_call(make_iam_event, event, params, resp, expected_call):
    iam = FakeIAM()
    result = iam_privesc.evaluate(make_iam_event(event, params, resp))
    iam_privesc.remediate(result, lambda _: iam)
    assert iam.calls == [expected_call]
