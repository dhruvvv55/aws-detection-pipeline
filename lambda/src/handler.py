"""SQS -> Lambda entry point shared by every detection.

For each CloudTrail event: skip failed API calls, run matching detections,
then either remediate, record a dry run, or respect the allowlist. Every
finding goes to DynamoDB and (unless allowlisted) out as an SNS alert.
"""

import json
import logging
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

import detections

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_clients = {}


def client(name, region=None):
    """Cached boto3 clients, reused across warm invocations.

    Regional detections (EC2) pass the event's region so remediation hits the
    right place if events from other regions are ever forwarded here.
    """
    key = (name, region)
    if key not in _clients:
        _clients[key] = boto3.client(name, region_name=region) if region else boto3.client(name)
    return _clients[key]


def _now():
    return datetime.now(timezone.utc)


def _parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def dry_run_enabled():
    return os.environ.get("DRY_RUN", "false").lower() == "true"


def should_skip(detail):
    """Return a reason to ignore this event, or None to process it."""
    if detail.get("errorCode"):
        # The call was denied or failed, so nothing actually changed
        return f"API call failed with {detail['errorCode']}"
    return None


def build_finding(detection, result, detail):
    finding = {
        "finding_id": f"{detection.NAME}#{detail['eventID']}",
        "detection": detection.NAME,
        "technique": result.get("technique", detection.TECHNIQUE),
        "technique_name": result.get("technique_name", detection.TECHNIQUE_NAME),
        "reason": result["reason"],
        "resource": result["resource"],
        "event_name": detail["eventName"],
        "event_id": detail["eventID"],
        "event_time": detail["eventTime"],
        "actor_arn": detail.get("userIdentity", {}).get("arn", "unknown"),
        "source_ip": detail.get("sourceIPAddress", "unknown"),
        "detected_at": _iso(_now()),
    }
    if result.get("evidence"):
        finding["evidence"] = result["evidence"][:4000]
    return finding


def save_finding(finding):
    """Write the finding. Returns False if it's a duplicate we already handled.

    SQS delivers at least once, so the same event can show up twice. The
    condition lets a retry overwrite a FAILED finding but never a finished one.
    """
    item = {k: Decimal(str(v)) if isinstance(v, float) else v for k, v in finding.items()}
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(finding_id) OR remediation_status = :failed",
            ExpressionAttributeValues={":failed": "FAILED"},
        )
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("duplicate delivery for %s, skipping alert", finding["finding_id"])
            return False
        raise


def send_alert(finding):
    subject = f"[{finding['remediation_status']}] {finding['detection']} ({finding['technique']})"
    lines = [
        f"Detection:   {finding['detection']} ({finding['technique']} {finding['technique_name']})",
        f"Status:      {finding['remediation_status']}",
        f"Resource:    {finding['resource']}",
        f"Reason:      {finding['reason']}",
        f"Actor:       {finding['actor_arn']}",
        f"Source IP:   {finding['source_ip']}",
        f"Event:       {finding['event_name']} at {finding['event_time']}",
    ]
    if "seconds_to_remediate" in finding:
        lines.append(f"Remediated:  {finding['remediation_action']} in {finding['seconds_to_remediate']}s")
    if "remediation_error" in finding:
        lines.append(f"Error:       {finding['remediation_error']}")
    lines.append(f"Finding ID:  {finding['finding_id']}")
    client("sns").publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=subject[:100],
        Message="\n".join(lines),
    )


def record(finding):
    logger.info(json.dumps({"msg": "finding", **finding}, default=str))
    is_new = save_finding(finding)
    if is_new and finding["remediation_status"] != "ALLOWLISTED":
        send_alert(finding)


def handle_detection(detection, result, detail):
    finding = build_finding(detection, result, detail)

    if detection.is_allowlisted(result, client):
        finding["remediation_status"] = "ALLOWLISTED"
    elif dry_run_enabled():
        finding["remediation_status"] = "DRY_RUN"
    else:
        try:
            action = detection.remediate(result, client)
        except Exception as err:
            finding["remediation_status"] = "FAILED"
            finding["remediation_error"] = str(err)[:500]
            record(finding)
            raise  # let SQS retry; after 3 tries it lands in the DLQ
        done = _now()
        finding["remediation_status"] = "REMEDIATED"
        finding["remediation_action"] = action
        finding["remediation_time"] = _iso(done)
        finding["seconds_to_remediate"] = round((done - _parse_time(detail["eventTime"])).total_seconds(), 2)

    record(finding)
    return finding


def process_record(record_):
    event = json.loads(record_["body"])
    detail = event["detail"]
    event_name = detail.get("eventName")

    skip = should_skip(detail)
    if skip:
        logger.info("skipping %s %s: %s", event_name, detail.get("eventID"), skip)
        return

    for detection in detections.for_event(event_name):
        result = detection.evaluate(detail)
        if result is None:
            logger.info("%s %s is benign for %s", event_name, detail.get("eventID"), detection.NAME)
            continue
        confirm = getattr(detection, "confirm", None)
        if confirm and not confirm(result, client):
            logger.info("%s %s is benign for %s after confirmation", event_name, detail.get("eventID"), detection.NAME)
            continue
        handle_detection(detection, result, detail)


def lambda_handler(event, context):
    failures = []
    for record_ in event.get("Records", []):
        try:
            process_record(record_)
        except Exception:
            logger.exception("failed to process message %s", record_.get("messageId"))
            failures.append({"itemIdentifier": record_["messageId"]})
    return {"batchItemFailures": failures}
