import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def benign_policy_detail():
    return load_fixture("PutBucketPolicy_benign.json")["detail"]


@pytest.fixture
def make_s3_event(benign_policy_detail):
    """Build variations of a real CloudTrail S3 event without extra fixture files."""

    def make(event_name, request_parameters, **extra):
        detail = copy.deepcopy(benign_policy_detail)
        detail["eventName"] = event_name
        detail["requestParameters"] = {"bucketName": "victim-bucket", **request_parameters}
        detail.update(extra)
        return detail

    return make


@pytest.fixture
def make_iam_event(benign_policy_detail):
    """IAM event built on the same real CloudTrail skeleton. Actor is dhruv-admin (IAMUser)."""

    def make(event_name, request_parameters, response_elements=None, **extra):
        detail = copy.deepcopy(benign_policy_detail)
        detail["eventSource"] = "iam.amazonaws.com"
        detail["eventName"] = event_name
        detail["requestParameters"] = request_parameters
        detail["responseElements"] = response_elements
        detail.update(extra)
        return detail

    return make


@pytest.fixture
def make_ec2_event(benign_policy_detail):
    def make(request_parameters, response_elements=None, **extra):
        detail = copy.deepcopy(benign_policy_detail)
        detail["eventSource"] = "ec2.amazonaws.com"
        detail["eventName"] = "AuthorizeSecurityGroupIngress"
        detail["awsRegion"] = "us-east-1"
        detail["requestParameters"] = request_parameters
        detail["responseElements"] = response_elements
        detail.update(extra)
        return detail

    return make
