"""SQS -> Lambda entry point.

Step 2: parse each EventBridge/CloudTrail event, log a summary plus how long
it took to reach us, and report per-message failures so SQS can retry them
and eventually move them to the DLQ.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def parse_record(record: dict) -> dict:
    """Pull the fields we care about out of one SQS record."""
    event = json.loads(record["body"])  # EventBridge envelope
    detail = event["detail"]            # the actual CloudTrail event
    return {
        "event_id": detail.get("eventID"),
        "event_name": detail["eventName"],
        "event_source": detail["eventSource"],
        "event_time": detail["eventTime"],
        "actor_arn": detail.get("userIdentity", {}).get("arn"),
        "source_ip": detail.get("sourceIPAddress"),
        "region": detail.get("awsRegion"),
        "request_parameters": detail.get("requestParameters"),
    }


def seconds_since(event_time: str) -> float:
    """CloudTrail eventTime (e.g. 2026-09-23T19:02:11Z) to now, in seconds."""
    ts = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    return round((datetime.now(timezone.utc) - ts).total_seconds(), 2)


def lambda_handler(event, context):
    failures = []

    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            logger.debug("raw message %s: %s", message_id, record["body"])
            summary = parse_record(record)
            summary["lag_seconds"] = seconds_since(summary["event_time"])
            logger.info(json.dumps({"msg": "event_received", **summary}, default=str))
        except Exception:
            logger.exception("failed to process message %s", message_id)
            failures.append({"itemIdentifier": message_id})

    # Only the failed messages go back to the queue for retry
    return {"batchItemFailures": failures}
