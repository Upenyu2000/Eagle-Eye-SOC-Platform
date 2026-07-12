from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from eagle_eye.models import AnalysisResult, Finding
from eagle_eye.services.common import find_value, parse_time

EVENT_ID_FIELDS = [
    "event_id",
    "eventid",
    "EventID",
    "win.system.eventID",
    "data.win.system.eventID",
]


def _event_id(record: dict[str, Any]) -> str:
    return str(find_value(record, EVENT_ID_FIELDS, "")).strip()


def _source_ip(record: dict[str, Any]) -> str:
    return str(
        find_value(
            record,
            ["source_ip", "src_ip", "ipAddress", "win.eventdata.ipAddress", "source.ip"],
            "unknown",
        )
    ).strip() or "unknown"


def _username(record: dict[str, Any]) -> str:
    return str(
        find_value(
            record,
            ["username", "targetUserName", "win.eventdata.targetUserName", "user.name"],
            "unknown",
        )
    ).strip() or "unknown"


def analyse_auth_records(
    records: list[dict[str, Any]],
    failure_threshold: int = 3,
    window_seconds: int = 120,
) -> AnalysisResult:
    successes = [item for item in records if _event_id(item) == "4624"]
    failures = [item for item in records if _event_id(item) == "4625"]
    findings: list[Finding] = []

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in failures:
        grouped[_source_ip(record)].append(record)

    window = timedelta(seconds=window_seconds)
    for source_ip, items in grouped.items():
        ordered = sorted(
            items,
            key=lambda item: parse_time(
                find_value(item, ["timestamp", "@timestamp", "TimeCreated", "time"], "")
            ),
        )
        start = 0
        for end, current in enumerate(ordered):
            current_time = parse_time(
                find_value(current, ["timestamp", "@timestamp", "TimeCreated", "time"], "")
            )
            while start < end:
                start_time = parse_time(
                    find_value(
                        ordered[start],
                        ["timestamp", "@timestamp", "TimeCreated", "time"],
                        "",
                    )
                )
                if current_time - start_time <= window:
                    break
                start += 1
            count = end - start + 1
            if count >= failure_threshold:
                users = sorted({_username(item) for item in ordered[start : end + 1]})
                findings.append(
                    Finding(
                        module="SIEM",
                        title="Repeated Windows authentication failures",
                        severity="high",
                        description=(
                            f"{count} failed logons from {source_ip} occurred within "
                            f"{window_seconds} seconds."
                        ),
                        evidence={
                            "source_ip": source_ip,
                            "usernames": users,
                            "count": count,
                            "event_id": 4625,
                            "mitre": "T1110 / T1110.003",
                        },
                        recommendation=(
                            "Validate the source, check whether a successful logon followed, "
                            "and tune approved scanners or jump hosts."
                        ),
                    )
                )
                break

    success_pairs = {(_source_ip(item), _username(item)) for item in successes}
    failure_pairs = {(_source_ip(item), _username(item)) for item in failures}
    for source_ip, username in sorted(success_pairs & failure_pairs):
        findings.append(
            Finding(
                module="SIEM",
                title="Successful logon followed failed attempts",
                severity="high",
                description=(
                    f"A successful logon for {username} from {source_ip} also has failed "
                    "authentication activity in the imported telemetry."
                ),
                evidence={
                    "source_ip": source_ip,
                    "username": username,
                    "event_ids": [4625, 4624],
                },
                recommendation="Review the session, endpoint, source host and account activity.",
            )
        )

    summary = {
        "records": len(records),
        "successful_logons": len(successes),
        "failed_logons": len(failures),
        "unique_failure_sources": len(grouped),
        "findings": len(findings),
    }
    return AnalysisResult(module="SIEM", summary=summary, findings=findings, records=records)
