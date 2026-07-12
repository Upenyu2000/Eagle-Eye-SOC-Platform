from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from eagle_eye.models import AnalysisResult, Finding
from eagle_eye.services.common import find_value, parse_time


def _event_id(record: dict[str, Any]) -> str:
    return str(find_value(record, ["event_id", "eventid", "EventID", "win.system.eventID"], ""))


def _field(record: dict[str, Any], *names: str, default: str = "unknown") -> str:
    return str(find_value(record, names, default)).strip() or default


def analyse_ad_records(
    records: list[dict[str, Any]],
    ticket_burst_threshold: int = 5,
    window_seconds: int = 300,
) -> AnalysisResult:
    findings: list[Finding] = []
    kerberos = [record for record in records if _event_id(record) == "4769"]
    rc4_records = [
        record
        for record in kerberos
        if _field(record, "TicketEncryptionType", "ticket_encryption_type", default="").lower()
        in {"0x17", "23", "rc4", "rc4-hmac"}
    ]

    if rc4_records:
        accounts = sorted(
            {
                _field(record, "TargetUserName", "target_user_name", "user.name")
                for record in rc4_records
            }
        )
        findings.append(
            Finding(
                module="Active Directory",
                title="Kerberos service tickets used RC4 encryption",
                severity="medium",
                description=f"{len(rc4_records)} Event ID 4769 records used RC4-compatible encryption.",
                evidence={"accounts": accounts, "count": len(rc4_records), "event_id": 4769},
                recommendation=(
                    "Confirm legacy dependencies, prefer AES, rotate service-account passwords, "
                    "and assess whether requests originated from expected hosts."
                ),
            )
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in kerberos:
        key = _field(record, "IpAddress", "source_ip", "ClientAddress", "WorkstationName")
        grouped[key].append(record)

    window = timedelta(seconds=window_seconds)
    for source, items in grouped.items():
        ordered = sorted(
            items,
            key=lambda item: parse_time(
                find_value(item, ["timestamp", "@timestamp", "TimeCreated"], "")
            ),
        )
        start = 0
        for end, current in enumerate(ordered):
            current_time = parse_time(
                find_value(current, ["timestamp", "@timestamp", "TimeCreated"], "")
            )
            while start < end:
                earliest = parse_time(
                    find_value(ordered[start], ["timestamp", "@timestamp", "TimeCreated"], "")
                )
                if current_time - earliest <= window:
                    break
                start += 1
            count = end - start + 1
            if count >= ticket_burst_threshold:
                services = sorted(
                    {
                        _field(item, "ServiceName", "service_name", default="unknown")
                        for item in ordered[start : end + 1]
                    }
                )
                findings.append(
                    Finding(
                        module="Active Directory",
                        title="Burst of Kerberos service-ticket requests",
                        severity="high",
                        description=(
                            f"{count} Event ID 4769 requests from {source} occurred within "
                            f"{window_seconds} seconds."
                        ),
                        evidence={"source": source, "services": services, "count": count},
                        recommendation="Validate whether this host and account normally request these SPNs.",
                    )
                )
                break

    lsass_access = [
        record
        for record in records
        if _event_id(record) == "10"
        and "lsass.exe" in _field(record, "TargetImage", "target_image", default="").lower()
    ]
    if lsass_access:
        source_images = sorted(
            {
                _field(record, "SourceImage", "source_image", default="unknown")
                for record in lsass_access
            }
        )
        findings.append(
            Finding(
                module="Active Directory",
                title="Process accessed LSASS",
                severity="high",
                description=f"{len(lsass_access)} Sysmon Event ID 10 records targeted lsass.exe.",
                evidence={"source_images": source_images, "count": len(lsass_access)},
                recommendation="Validate process signature, access mask, parent process and host role.",
            )
        )

    network_ntlm = [
        record
        for record in records
        if _event_id(record) == "4624"
        and _field(record, "LogonType", "logon_type", default="") == "3"
        and "ntlm" in _field(record, "AuthenticationPackageName", "authentication_package", default="").lower()
    ]
    privileged = [record for record in records if _event_id(record) == "4672"]
    privileged_ids = Counter(
        _field(record, "SubjectLogonId", "LogonId", "logon_id", default="")
        for record in privileged
    )
    correlated = []
    for record in network_ntlm:
        logon_id = _field(record, "TargetLogonId", "LogonId", "logon_id", default="")
        if logon_id and privileged_ids[logon_id]:
            correlated.append(record)
    if correlated:
        findings.append(
            Finding(
                module="Active Directory",
                title="Privileged NTLM network logon correlation",
                severity="high",
                description=(
                    f"{len(correlated)} NTLM network logons correlate with special-privilege events."
                ),
                evidence={"event_ids": [4624, 4672], "count": len(correlated)},
                recommendation=(
                    "Investigate source host, account, admin-share access and nearby process activity."
                ),
            )
        )

    summary = {
        "records": len(records),
        "kerberos_tickets": len(kerberos),
        "rc4_tickets": len(rc4_records),
        "lsass_access_events": len(lsass_access),
        "ntlm_network_logons": len(network_ntlm),
        "findings": len(findings),
    }
    return AnalysisResult(
        module="Active Directory", summary=summary, findings=findings, records=records
    )
