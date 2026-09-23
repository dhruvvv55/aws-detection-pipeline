import json

import pytest
from botocore.exceptions import ClientError

import handler
from detections import s3_public


class FakeS3:
    def __init__(self, tags=None, fail=False):
        self.tags = tags
        self.fail = fail
        self.remediated = []

    def get_bucket_tagging(self, Bucket):
        if self.tags is None:
            raise ClientError({"Error": {"Code": "NoSuchTagSet"}}, "GetBucketTagging")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def put_public_access_block(self, Bucket, PublicAccessBlockConfiguration):
        if self.fail:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutPublicAccessBlock")
        self.remediated.append(Bucket)


class FakeSNS:
    def __init__(self):
        self.messages = []

    def publish(self, **kwargs):
        self.messages.append(kwargs)


@pytest.fixture
def fakes(monkeypatch):
    s3, sns, saved = FakeS3(), FakeSNS(), []
    monkeypatch.setattr(handler, "client", lambda name: {"s3": s3, "sns": sns}[name])
    monkeypatch.setattr(handler, "save_finding", lambda f: saved.append(f) or True)
    monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test")
    monkeypatch.setenv("DRY_RUN", "false")
    return s3, sns, saved


def sqs_record(detail):
    return {"messageId": "m1", "body": json.dumps({"detail": detail})}


def test_public_bucket_is_remediated_and_alerted(fakes, make_s3_event):
    s3, sns, saved = fakes
    handler.process_record(sqs_record(make_s3_event("DeleteBucketPublicAccessBlock", {})))
    assert s3.remediated == ["victim-bucket"]
    assert saved[0]["remediation_status"] == "REMEDIATED"
    assert saved[0]["technique"] == "T1530"
    assert saved[0]["seconds_to_remediate"] > 0
    assert len(sns.messages) == 1


def test_dry_run_detects_without_remediating(fakes, make_s3_event, monkeypatch):
    s3, sns, saved = fakes
    monkeypatch.setenv("DRY_RUN", "true")
    handler.process_record(sqs_record(make_s3_event("DeleteBucketPublicAccessBlock", {})))
    assert s3.remediated == []
    assert saved[0]["remediation_status"] == "DRY_RUN"
    assert len(sns.messages) == 1


def test_allowlisted_bucket_is_left_alone(fakes, make_s3_event):
    s3, sns, saved = fakes
    s3.tags = {"detlab:allow-public": "true"}
    handler.process_record(sqs_record(make_s3_event("DeleteBucketPublicAccessBlock", {})))
    assert s3.remediated == []
    assert saved[0]["remediation_status"] == "ALLOWLISTED"
    assert sns.messages == []


def test_failed_api_call_is_skipped(fakes, make_s3_event):
    s3, sns, saved = fakes
    detail = make_s3_event("DeleteBucketPublicAccessBlock", {}, errorCode="AccessDenied")
    handler.process_record(sqs_record(detail))
    assert saved == [] and s3.remediated == []


def test_benign_event_records_nothing(fakes, benign_policy_detail):
    s3, sns, saved = fakes
    handler.process_record(sqs_record(benign_policy_detail))
    assert saved == [] and sns.messages == []


def test_remediation_failure_is_recorded_then_retried(fakes, make_s3_event):
    s3, sns, saved = fakes
    s3.fail = True
    with pytest.raises(ClientError):
        handler.process_record(sqs_record(make_s3_event("DeleteBucketPublicAccessBlock", {})))
    assert saved[0]["remediation_status"] == "FAILED"
    assert "AccessDenied" in saved[0]["remediation_error"]


def test_bad_message_is_reported_as_batch_failure(fakes):
    out = handler.lambda_handler({"Records": [{"messageId": "bad", "body": "not json"}]}, None)
    assert out == {"batchItemFailures": [{"itemIdentifier": "bad"}]}


def test_add_to_non_admin_group_records_nothing(fakes, make_iam_event, monkeypatch):
    s3, sns, saved = fakes

    class NoAdminIAM:
        def list_attached_group_policies(self, GroupName):
            return {"AttachedPolicies": []}

        def list_group_policies(self, GroupName):
            return {"PolicyNames": []}

    monkeypatch.setattr(handler, "client", lambda name: {"s3": s3, "sns": sns, "iam": NoAdminIAM()}[name])
    handler.process_record(sqs_record(make_iam_event("AddUserToGroup", {"groupName": "devs", "userName": "u"})))
    assert saved == [] and sns.messages == []


def test_finding_uses_sub_technique_from_result(fakes, make_iam_event, monkeypatch):
    s3, sns, saved = fakes
    calls = []

    class IAM:
        def list_user_tags(self, UserName):
            return {"Tags": []}

        def update_access_key(self, **kw):
            calls.append(kw)

    monkeypatch.setattr(handler, "client", lambda name: {"s3": s3, "sns": sns, "iam": IAM()}[name])
    detail = make_iam_event("CreateAccessKey", {"userName": "victim"},
                            {"accessKey": {"accessKeyId": "AKIDEXAMPLE0000001"}})
    handler.process_record(sqs_record(detail))
    assert saved[0]["technique"] == "T1098.001"
    assert saved[0]["remediation_status"] == "REMEDIATED"
    assert calls[0]["Status"] == "Inactive"
