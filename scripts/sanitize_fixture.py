#!/usr/bin/env python3
"""Scrub real identifiers out of CloudTrail/EventBridge fixture files.

Replaces account IDs, source IPs, and access key / principal IDs with
placeholders, then rewrites each file as pretty-printed JSON. Run it on every
fixture before committing.

    python3 scripts/sanitize_fixture.py lambda/tests/fixtures/*.json
"""

import json
import re
import sys
from pathlib import Path

FAKE_ACCOUNT = "123456789012"
FAKE_IP = "203.0.113.10"  # TEST-NET-3, reserved for documentation
KEY_ID_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
PRINCIPAL_ID_RE = re.compile(r"\b(AIDA|AROA)[A-Z0-9]{16,}\b")


def find_values(obj, keys, found):
    """Collect every value stored under any of the given keys, at any depth."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                found.add(v)
            find_values(v, keys, found)
    elif isinstance(obj, list):
        for item in obj:
            find_values(item, keys, found)
    return found


def sanitize(data: dict) -> dict:
    accounts = find_values(data, {"account", "accountId", "recipientAccountId"}, set())
    ips = find_values(data, {"sourceIPAddress"}, set())

    text = json.dumps(data)
    for acct in accounts:
        if re.fullmatch(r"\d{12}", acct):
            text = text.replace(acct, FAKE_ACCOUNT)
    for ip in ips:
        if re.fullmatch(r"[0-9a-fA-F:.]+", ip):  # skip values like "s3.amazonaws.com"
            text = text.replace(ip, FAKE_IP)
    text = KEY_ID_RE.sub("EXAMPLEKEYID", text)
    text = PRINCIPAL_ID_RE.sub("EXAMPLEPRINCIPALID", text)
    return json.loads(text)


def main(paths):
    for p in map(Path, paths):
        raw = p.read_text().strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"SKIP {p}: not valid JSON ({e})")
            continue
        p.write_text(json.dumps(sanitize(data), indent=2) + "\n")
        print(f"sanitized {p}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: sanitize_fixture.py FILE [FILE ...]")
    main(sys.argv[1:])
