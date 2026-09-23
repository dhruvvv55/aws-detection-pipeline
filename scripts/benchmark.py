#!/usr/bin/env python3
"""Run each detection's simulation N times and report remediation times.

Every remediation time is split in two:
  delivery  CloudTrail eventTime -> Lambda starts handling it (AWS side)
  handling  Lambda starts -> remediation API call returns (our code)

Results print as a table and are written to docs/benchmark-results.md.

    python3 scripts/benchmark.py              # 10 runs per detection
    python3 scripts/benchmark.py --runs 3     # quicker
    python3 scripts/benchmark.py --since 2026-09-23T20:30:00Z   # re-analyze only
"""

import argparse
import math
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent
TABLE = "aws-detect-remediate-findings"

# Modes cycle so every attack variant gets measured, not just the default.
# S3 "policy" mode is left out because account-level BPA now blocks it.
SIMULATIONS = {
    "s3_bucket_public": ("simulate_s3_public.sh", ["bpa"]),
    "iam_privilege_escalation": ("simulate_iam_privesc.sh", ["admin", "inline", "key", "group"]),
    "security_group_open_to_internet": ("simulate_sg_open.sh", ["ssh", "rdp", "all"]),
}


def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def run_simulations(runs):
    failures = 0
    for detection, (script, modes) in SIMULATIONS.items():
        for i in range(runs):
            mode = modes[i % len(modes)]
            print(f"[{detection}] run {i + 1}/{runs} mode={mode}", flush=True)
            proc = subprocess.run([str(ROOT / "scripts" / script), mode],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                failures += 1
                print(f"  simulation failed:\n{proc.stdout}{proc.stderr}")
    return failures


def fetch_findings(since, profile):
    table = boto3.Session(profile_name=profile, region_name="us-east-1").resource("dynamodb").Table(TABLE)
    items, kwargs = [], {}
    while True:
        page = table.scan(**kwargs)
        items.extend(page["Items"])
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return [
        i for i in items
        if i.get("remediation_status") == "REMEDIATED" and parse_ts(i["detected_at"]) >= since
    ]


def percentile(values, pct):
    """Nearest-rank percentile, no interpolation."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


def summarize(findings):
    rows = []
    for detection in SIMULATIONS:
        group = [f for f in findings if f["detection"] == detection]
        if not group:
            continue
        total = [float(f["seconds_to_remediate"]) for f in group]
        delivery = [(parse_ts(f["detected_at"]) - parse_ts(f["event_time"])).total_seconds() for f in group]
        handling = [(parse_ts(f["remediation_time"]) - parse_ts(f["detected_at"])).total_seconds() for f in group]
        rows.append({
            "detection": detection,
            "n": len(group),
            "median": statistics.median(total),
            "p90": percentile(total, 90),
            "worst": max(total),
            "best": min(total),
            "delivery": statistics.median(delivery),
            "handling": statistics.median(handling),
        })
    return rows


def render(rows, since):
    lines = [
        f"Measured {since:%Y-%m-%d}, us-east-1, Lambda python3.13 arm64 256 MB.",
        "",
        "| Detection | Runs | Median | p90 | Worst | Best | Median delivery (AWS) | Median handling (pipeline) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['detection']} | {r['n']} | {r['median']:.2f}s | {r['p90']:.2f}s | {r['worst']:.2f}s "
            f"| {r['best']:.2f}s | {r['delivery']:.2f}s | {r['handling']:.2f}s |"
        )
    lines += [
        "",
        "All times run from the CloudTrail eventTime to the moment the remediation API call returned.",
        "CloudTrail truncates eventTime to whole seconds, so each value carries about ±1s of uncertainty.",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--profile", default="detlab")
    parser.add_argument("--since", help="skip simulations, analyze findings after this ISO time")
    args = parser.parse_args()

    if args.since:
        since = parse_ts(args.since)
    else:
        since = datetime.now(timezone.utc)
        print(f"benchmark started {iso(since)} (re-analyze later with --since {iso(since)})\n")
        failures = run_simulations(args.runs)
        if failures:
            print(f"\n{failures} simulation(s) failed, results below only include successful runs")
        print("\nwaiting 20s for the last findings to land...")
        time.sleep(20)

    rows = summarize(fetch_findings(since, args.profile))
    if not rows:
        sys.exit("no REMEDIATED findings found in that window")

    report = render(rows, since)
    print("\n" + report)
    out = ROOT / "docs" / "benchmark-results.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("# Benchmark results\n\n" + report + "\n")
    print(f"\nwritten to {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
