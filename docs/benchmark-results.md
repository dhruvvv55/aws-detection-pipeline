# Benchmark results

Measured 2026-09-23, us-east-1, Lambda python3.13 arm64 256 MB.

| Detection | Runs | Median | p90 | Worst | Best | Median delivery (AWS) | Median handling (pipeline) |
|---|---|---|---|---|---|---|---|
| s3_bucket_public | 10 | 9.54s | 11.23s | 12.03s | 6.13s | 8.76s | 0.26s |
| iam_privilege_escalation | 10 | 2.88s | 4.11s | 4.64s | 1.53s | 2.80s | 0.08s |
| security_group_open_to_internet | 10 | 4.40s | 6.15s | 6.28s | 3.00s | 3.46s | 0.55s |

All times run from the CloudTrail eventTime to the moment the remediation API call returned.
CloudTrail truncates eventTime to whole seconds, so each value carries about ±1s of uncertainty.
