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
