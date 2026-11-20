#!/usr/bin/env python3
"""Evaluate a Kryptos relay experiment without presenting a Poisson model as orphan rate.

Input is the JSON report produced by tests/propagation.rs. The input reports elapsed
monotonic time from source submission (before validation) to a follower's accepted tip.
This is a conservative application-path observation, not majority-hashrate propagation.
"""

import argparse
import json
import math
from pathlib import Path


def percentile(samples: list[int], percentage: int) -> float:
    ordered = sorted(samples)
    return ordered[math.ceil(len(ordered) * percentage / 100) - 1] / 1_000_000


def evaluate(report: dict) -> dict:
    if report.get("measurement") != "source_submission_to_follower_tip":
        raise ValueError("unsupported measurement: expected source_submission_to_follower_tip")
    paths = []
    for label in ("first_hop", "second_hop"):
        if label not in report:
            continue
        samples = report[label].get("samples_us", [])
        if not samples or any(type(value) is not int or value < 0 for value in samples):
            raise ValueError(f"{label}: samples_us must contain nonnegative integer durations")
        paths.append({
            "path": label,
            "samples": len(samples),
            "p50_seconds": percentile(samples, 50),
            "p90_seconds": percentile(samples, 90),
            "p95_seconds": percentile(samples, 95),
        })
    if not paths:
        raise ValueError("report has no measured path")
    worst_p95 = max(path["p95_seconds"] for path in paths)
    found = report.get("valid_local_blocks", 0)
    stale = report.get("stale_local_blocks", 0)
    if type(found) is not int or type(stale) is not int or not 0 <= stale <= found:
        raise ValueError("invalid local block counts")
    candidates = []
    for interval in (10, 30, 60):
        candidates.append({
            "target_seconds": interval,
            "measured_path_p95_fraction_of_interval": worst_p95 / interval,
            "poisson_next_block_during_path_probability": -math.expm1(-worst_p95 / interval),
        })
    return {
        "transport": report.get("transport"),
        "paths": paths,
        "local_stale_fraction": stale / found if found else None,
        "competing_miners": bool(report.get("competing_miners")),
        "candidate_interval_model": candidates,
        "decision": "Keep the current consensus interval unchanged pending a distributed public-Tor campaign with competing miners.",
        "limitations": [
            "The Poisson calculation is P(at least one new block in a fixed delay) at constant aggregate block arrival rate; it is not an orphan or attack-cost estimate.",
            "No candidate is approved by this calculation, and a small path-to-interval ratio is not a security proof.",
            "Path timing includes source validation; it does not establish propagation to most hashrate.",
            "Zero observed stales without competing miners does not establish a low stale rate under contention.",
            "Small samples produce unstable tail quantiles. Repeat warm/cold, geographic, block-size and proof-count scenarios before changing consensus.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = json.dumps(evaluate(json.loads(args.report.read_text())), indent=2) + "\n"
    if args.out:
        args.out.write_text(result)
    print(result, end="")


if __name__ == "__main__":
    main()
