from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

from eagle_eye.models import AnalysisResult, Finding
from eagle_eye.services.common import find_value, flatten


def analyse_azure_records(records: list[dict[str, Any]]) -> AnalysisResult:
    findings: list[Finding] = []
    public_changes = 0

    for record in records:
        flat = flatten(record)
        text = json.dumps(flat, ensure_ascii=False).lower()
        operation = str(
            find_value(record, ["OperationNameValue", "operationName", "operation", "eventName"], "")
        )
        resource_id = str(find_value(record, ["ResourceId", "resourceId", "resource_id"], "unknown"))
        caller = str(find_value(record, ["Caller", "caller", "identity", "initiatedBy"], "unknown"))
        caller_ip = str(find_value(record, ["CallerIpAddress", "callerIpAddress", "source_ip"], "unknown"))

        clean_text = text.replace("\\", "")
        account_public = bool(
            re.search(r"allowblobpublicaccess.{0,100}(?:true|\"true\")", clean_text)
        )
        container_public = bool(
            re.search(r"(?:\"?publicaccess\"?).{0,100}\"(?:blob|container)\"", clean_text)
        )
        storage_write = "storage" in operation.lower() or "microsoft.storage" in text

        if storage_write and (account_public or container_public):
            public_changes += 1
            findings.append(
                Finding(
                    module="Azure",
                    title="Public blob access configuration detected",
                    severity="high",
                    description=(
                        "An Azure storage control-plane event appears to enable anonymous "
                        "blob or container access."
                    ),
                    evidence={
                        "resource_id": resource_id,
                        "operation": operation,
                        "caller": caller,
                        "caller_ip": caller_ip,
                    },
                    recommendation=(
                        "Validate the change, disable anonymous access, review data-plane access, "
                        "and confirm whether an approved exception exists."
                    ),
                )
            )

    summary = {
        "records": len(records),
        "public_access_changes": public_changes,
        "findings": len(findings),
        "azure_cli_available": bool(shutil.which("az")),
    }
    return AnalysisResult(module="Azure", summary=summary, findings=findings, records=records)


def remediation_command(
    resource_group: str,
    storage_account: str,
    subscription: str = "",
) -> list[str]:
    if not resource_group.strip() or not storage_account.strip():
        raise ValueError("Resource group and storage account are required")
    command = [
        "az",
        "storage",
        "account",
        "update",
        "--resource-group",
        resource_group.strip(),
        "--name",
        storage_account.strip(),
        "--allow-blob-public-access",
        "false",
        "--only-show-errors",
        "--output",
        "json",
    ]
    if subscription.strip():
        command.extend(["--subscription", subscription.strip()])
    return command


def remediate_public_access(
    resource_group: str,
    storage_account: str,
    subscription: str = "",
    timeout: int = 120,
) -> dict[str, Any]:
    if not shutil.which("az"):
        raise RuntimeError("Azure CLI was not found. Install it and sign in with 'az login'.")
    command = remediation_command(resource_group, storage_account, subscription)
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Azure CLI remediation failed")
    return {
        "command": command,
        "result": json.loads(completed.stdout or "{}"),
        "return_code": completed.returncode,
    }
