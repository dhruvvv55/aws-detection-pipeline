"""Detection registry. Each detection module exposes:

    NAME, TECHNIQUE, TECHNIQUE_NAME, EVENT_NAMES
    evaluate(detail) -> dict | None      pure logic, no AWS calls
    is_allowlisted(result, client) -> bool
    remediate(result, client) -> str      returns a description of what it did

`client` is a factory like client("s3") so tests can pass fakes.
"""

from . import s3_public

DETECTIONS = [s3_public]


def for_event(event_name):
    return [d for d in DETECTIONS if event_name in d.EVENT_NAMES]
