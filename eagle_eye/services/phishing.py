from __future__ import annotations

import base64
import ipaddress
import re
from email import policy
from email.parser import Parser
from typing import Any
from urllib.parse import quote, urlparse

import requests

from eagle_eye.models import AnalysisResult, Finding

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def defang(value: str) -> str:
    value = re.sub(r"(?i)\bhttps://", "hxxps://", value)
    value = re.sub(r"(?i)\bhttp://", "hxxp://", value)
    value = value.replace("@", "[@]")
    return re.sub(r"(?<!\[)\.(?!\])", "[.]", value)


def _domain_from_address(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip("> ") if "@" in address else ""


def analyse_message(headers_text: str, body_text: str = "") -> tuple[AnalysisResult, list[dict[str, str]]]:
    message = Parser(policy=policy.default).parsestr(headers_text + "\n\n" + body_text)
    findings: list[Finding] = []
    from_value = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    auth_results = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    auth_lower = auth_results.lower()

    from_domain = _domain_from_address(from_value)
    reply_domain = _domain_from_address(reply_to)
    return_domain = _domain_from_address(return_path)

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            Finding(
                module="Phishing",
                title="Reply-To domain differs from visible sender",
                severity="high",
                description=f"From uses {from_domain}, while Reply-To uses {reply_domain}.",
                evidence={"from": from_value, "reply_to": reply_to},
                recommendation="Treat replies as untrusted and verify the sender through a known channel.",
            )
        )
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(
            Finding(
                module="Phishing",
                title="Envelope sender does not align with visible sender",
                severity="medium",
                description=f"From uses {from_domain}, while Return-Path uses {return_domain}.",
                evidence={"from": from_value, "return_path": return_path},
                recommendation="Review SPF alignment and the trusted Received chain.",
            )
        )

    failed_controls = [control for control in ("spf", "dkim", "dmarc") if f"{control}=fail" in auth_lower]
    if failed_controls:
        findings.append(
            Finding(
                module="Phishing",
                title="Email authentication control failure",
                severity="high" if "dmarc" in failed_controls else "medium",
                description=f"Authentication-Results reports failure for: {', '.join(failed_controls)}.",
                evidence={"authentication_results": auth_results},
                recommendation="Validate alignment and confirm whether the sending infrastructure is authorised.",
            )
        )

    combined = headers_text + "\n" + body_text
    urls = sorted(set(URL_RE.findall(combined)))
    hashes = sorted(set(HASH_RE.findall(combined)))
    ips: set[str] = set()
    for candidate in IP_RE.findall(combined):
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    emails = sorted(set(EMAIL_RE.findall(combined)))
    domains = {from_domain, reply_domain, return_domain}
    for url in urls:
        hostname = urlparse(url.rstrip(",.);]")).hostname
        if hostname:
            domains.add(hostname.lower())
    domains.discard("")

    indicators: list[dict[str, str]] = []
    for value in urls:
        indicators.append({"type": "url", "value": value, "defanged": defang(value)})
    for value in sorted(domains):
        indicators.append({"type": "domain", "value": value, "defanged": defang(value)})
    for value in sorted(ips):
        indicators.append({"type": "ip", "value": value, "defanged": defang(value)})
    for value in hashes:
        indicators.append({"type": "sha256", "value": value, "defanged": value})
    for value in emails:
        indicators.append({"type": "email", "value": value, "defanged": defang(value)})

    if urls:
        findings.append(
            Finding(
                module="Phishing",
                title="Message contains clickable URLs",
                severity="medium",
                description=f"The message contains {len(urls)} URL artefact(s).",
                evidence={"urls": [defang(value) for value in urls]},
                recommendation="Enrich links without opening them in a normal browser session.",
            )
        )

    summary = {
        "from": from_value,
        "reply_to": reply_to,
        "return_path": return_path,
        "spf": "fail" if "spf=fail" in auth_lower else "pass" if "spf=pass" in auth_lower else "unknown",
        "dkim": "fail" if "dkim=fail" in auth_lower else "pass" if "dkim=pass" in auth_lower else "unknown",
        "dmarc": "fail" if "dmarc=fail" in auth_lower else "pass" if "dmarc=pass" in auth_lower else "unknown",
        "indicators": len(indicators),
        "findings": len(findings),
    }
    return AnalysisResult(module="Phishing", summary=summary, findings=findings), indicators


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: int = 20) -> None:
        if not api_key:
            raise ValueError("VirusTotal API key is not configured")
        self.api_key = api_key
        self.timeout = timeout

    @staticmethod
    def _path(indicator_type: str, value: str) -> str:
        if indicator_type == "url":
            encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").strip("=")
            return f"urls/{encoded}"
        if indicator_type == "domain":
            return f"domains/{quote(value, safe='')}"
        if indicator_type == "ip":
            return f"ip_addresses/{quote(value, safe='')}"
        if indicator_type in {"sha256", "hash", "file"}:
            return f"files/{quote(value, safe='')}"
        raise ValueError(f"Unsupported VirusTotal indicator type: {indicator_type}")

    def lookup(self, indicator_type: str, value: str) -> dict[str, Any]:
        response = requests.get(
            f"{self.BASE_URL}/{self._path(indicator_type, value)}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return {"found": False, "indicator": value, "type": indicator_type}
        response.raise_for_status()
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "found": True,
            "indicator": value,
            "type": indicator_type,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }


class PhishTankClient:
    ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, app_key: str = "", timeout: int = 20) -> None:
        self.app_key = app_key
        self.timeout = timeout

    def check(self, url: str) -> dict[str, Any]:
        payload = {"url": url, "format": "json"}
        if self.app_key:
            payload["app_key"] = self.app_key
        response = requests.post(
            self.ENDPOINT,
            data=payload,
            headers={"User-Agent": "EagleEyeSOCPlatform/1.0"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
