#!/usr/bin/env python3
"""Summarize the Week 01 synthetic Windows event CSV using the Python stdlib."""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "week1_authentication_events_300.csv"
KEY_EVENTS = {"4624", "4625", "4672", "4688", "4634", "4647"}


def load_events(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"TimeCreated", "EventID", "Computer", "Account", "SourceIP", "LogonType", "Keywords"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")
        return list(reader)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="Path to the training CSV")
    parser.add_argument("--source-ip", default="10.10.50.23", help="Source IP to summarize")
    args = parser.parse_args()

    try:
        events = load_events(args.csv)
    except (OSError, ValueError, csv.Error) as exc:
        parser.error(str(exc))

    ids = Counter(row["EventID"].strip() for row in events)
    failures = [row for row in events if row["EventID"].strip() == "4625"]
    failures_by_ip = Counter(row["SourceIP"].strip() for row in failures)
    failures_by_account = Counter(
        row["Account"].strip() for row in failures if row["SourceIP"].strip() == args.source_ip
    )
    selected = [row for row in events if row["SourceIP"].strip() == args.source_ip]
    selected_ids = Counter(row["EventID"].strip() for row in selected)
    keyword_mismatch = [
        row for row in failures
        if row["Keywords"].strip().lower() == "audit success"
    ]
    selected_successes = sorted(
        (row for row in selected if row["EventID"].strip() == "4624"),
        key=lambda row: row["TimeCreated"],
    )

    print("WINDOWS EVENT LOG — WEEK 01 SUMMARY")
    print(f"Dataset: {args.csv}")
    print(f"Total events: {len(events)}")
    print("\nEvent ID counts:")
    for event_id in sorted(ids):
        print(f"  {event_id}: {ids[event_id]}")

    print("\nFailed logons by source IP:")
    for source_ip, count in failures_by_ip.most_common():
        print(f"  {source_ip or '(blank)'}: {count}")

    print(f"\nSelected source: {args.source_ip}")
    print(f"  Associated events: {len(selected)}")
    for event_id, count in sorted(selected_ids.items()):
        print(f"  Event {event_id}: {count}")

    print("\nFailed logons by account for selected source:")
    if failures_by_account:
        for account, count in failures_by_account.most_common():
            print(f"  {account or '(blank)'}: {count}")
    else:
        print("  No Event 4625 records found for this source.")

    print("\nSuccessful logons for selected source:")
    for row in selected_successes:
        print(
            f"  {row['TimeCreated']} | host={row['Computer']} | account={row['Account']} "
            f"| logon_type={row['LogonType']} | auth={row.get('Authentication', '')}"
        )

    print("\nProcess creation for selected source:")
    process_rows = sorted(
        (row for row in selected if row["EventID"].strip() == "4688"),
        key=lambda row: row["TimeCreated"],
    )
    for row in process_rows:
        command = row.get("CommandLine", "").strip() or row.get("ProcessName", "").strip() or "(not present)"
        print(f"  {row['TimeCreated']} | {row['Computer']} | {row['Account']} | {command}")

    print("\nData-quality check:")
    print(f"  Event 4625 rows labelled 'Audit Success': {len(keyword_mismatch)}")
    if keyword_mismatch:
        print("  Warning: Keywords conflicts with Event ID meaning for these rows; inspect raw evidence before a verdict.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
