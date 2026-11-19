"""Read and validate the released structural tool-event evidence.

This utility does not generate Full PathScope predictions. It exposes the
released evidence records and checks their proposal/execution/result links.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def iter_records(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                yield line_number, json.loads(line)


def validate_record(record: dict) -> list[str]:
    issues: list[str] = []
    events = record.get("events")
    if not isinstance(events, list):
        return ["events is not a list"]
    by_id = {}
    for event in events:
        event_id = event.get("event_id")
        if not event_id:
            issues.append("event without event_id")
        elif event_id in by_id:
            issues.append(f"duplicate event_id: {event_id}")
        else:
            by_id[event_id] = event
    for event in events:
        kind = event.get("kind")
        if kind == "tool_executed":
            proposal = event.get("proposal_event_id")
            if proposal not in by_id or by_id[proposal].get("kind") != "tool_proposed":
                issues.append(f"invalid proposal link: {event.get('event_id')}")
        if kind == "tool_result":
            execution = event.get("execution_event_id")
            if execution not in by_id or by_id[execution].get("kind") != "tool_executed":
                issues.append(f"invalid result execution link: {event.get('event_id')}")
                continue
            proposal = event.get("proposal_event_id") or by_id[execution].get("proposal_event_id")
            if proposal not in by_id or by_id[proposal].get("kind") != "tool_proposed":
                issues.append(f"invalid result proposal link: {event.get('event_id')}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=Path("data/rq2/evidence/tool_events.jsonl"))
    parser.add_argument("--trace-id")
    args = parser.parse_args()
    found = 0
    issue_count = 0
    for line_number, record in iter_records(args.evidence):
        if args.trace_id and record.get("trace_id") != args.trace_id:
            continue
        found += 1
        issues = validate_record(record)
        issue_count += len(issues)
        print(json.dumps({"line": line_number, "trace_id": record.get("trace_id"),
                          "issues": issues, "record": record}, ensure_ascii=False, indent=2))
    if args.trace_id and found != 1:
        raise SystemExit(f"expected one record for {args.trace_id}, found {found}")
    return 1 if issue_count else 0


if __name__ == "__main__":
    raise SystemExit(main())

