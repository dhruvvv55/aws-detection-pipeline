"""Detection registry. Each detection module exposes:

    NAME, TECHNIQUE, TECHNIQUE_NAME, EVENT_NAMES
    evaluate(detail) -> dict | None      pure logic, no AWS calls
    confirm(result, client) -> bool       optional, for checks that need an API call
    is_allowlisted(result, client) -> bool
    remediate(result, client) -> str      returns a description of what it did

A result may carry its own "technique"/"technique_name" to override the
module default (one detection can map to several ATT&CK sub-techniques).
`client` is a factory like client("s3") so tests can pass fakes.
"""

from . import iam_privesc, s3_public

DETECTIONS = [s3_public, iam_privesc]


def for_event(event_name):
    return [d for d in DETECTIONS if event_name in d.EVENT_NAMES]
