from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests

from eagle_eye.services.phishing import VirusTotalClient


@dataclass(slots=True)
class PipelineDecision:
    score: int
    outcome: str
    reason: str
    enrichments: list[dict[str, Any]]


def calculate_score(enrichments: list[dict[str, Any]]) -> int:
    score = 0
    for item in enrichments:
        if not item.get("found", True):
            continue
        score += 3 * int(item.get("malicious", 0))
        score += int(item.get("suspicious", 0))
        if item.get("known_phishing") is True:
            score += 2
        if item.get("internal_high_confidence") is True:
            score += 2
    return score


def enrich_alert_indicators(alert: dict[str, Any], vt_api_key: str) -> list[dict[str, Any]]:
    client = VirusTotalClient(vt_api_key)
    output: list[dict[str, Any]] = []
    for indicator in alert.get("indicators", []):
        indicator_type = str(indicator.get("type", "")).lower()
        value = str(indicator.get("value", "")).strip()
        if not value or indicator_type == "email":
            continue
        try:
            output.append(client.lookup(indicator_type, value))
        except requests.HTTPError as exc:
            output.append(
                {
                    "indicator": value,
                    "type": indicator_type,
                    "error": f"HTTP {exc.response.status_code if exc.response else 'error'}",
                    "verdict": "unknown",
                }
            )
        except Exception as exc:
            output.append(
                {
                    "indicator": value,
                    "type": indicator_type,
                    "error": str(exc),
                    "verdict": "unknown",
                }
            )
    return output


def decide(enrichments: list[dict[str, Any]], case_threshold: int = 6, review_threshold: int = 2) -> PipelineDecision:
    score = calculate_score(enrichments)
    if score >= case_threshold:
        return PipelineDecision(score, "create_case", "Enrichment score exceeded the case threshold", enrichments)
    if score >= review_threshold:
        return PipelineDecision(score, "analyst_review", "Enrichment requires analyst review", enrichments)
    return PipelineDecision(score, "no_external_hit", "No strong external reputation hit was returned", enrichments)


def send_webhook(url: str, payload: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    if not url:
        raise ValueError("Webhook URL is not configured")
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    try:
        body: Any = response.json()
    except ValueError:
        body = response.text
    return {"status_code": response.status_code, "body": body}


class TheHiveClient:
    def __init__(self, base_url: str, api_key: str, timeout: int = 20) -> None:
        if not base_url or not api_key:
            raise ValueError("TheHive URL and API key are required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def create_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/api/v1/case",
            json=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


def build_thehive_case(alert: dict[str, Any], decision: PipelineDecision) -> dict[str, Any]:
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = severity_map.get(str(alert.get("severity", "medium")).lower(), 2)
    alert_id = str(alert.get("alert_id", "UNKNOWN"))
    title = str(alert.get("title", "Security alert"))
    host = str(alert.get("host", "unknown"))
    return {
        "title": f"[{alert_id}] {title} — {host}",
        "description": (
            "Created by Eagle Eye after explicit analyst execution.\n\n"
            f"Automation score: {decision.score}\n"
            f"Decision: {decision.outcome}\n"
            f"Reason: {decision.reason}\n\n"
            f"Original alert:\n{json.dumps(alert, indent=2, default=str)}"
        ),
        "severity": severity,
        "tlp": 2,
        "pap": 2,
        "tags": ["eagle-eye", "automated-enrichment", str(alert.get("source", "manual"))],
        "customFields": {
            "sourceAlertId": {"string": alert_id},
            "automationScore": {"integer": decision.score},
        },
        "tasks": [
            {"title": "Validate endpoint and identity telemetry", "group": "investigation"},
            {"title": "Scope related indicators", "group": "investigation"},
            {"title": "Record containment decision", "group": "response"},
        ],
    }
