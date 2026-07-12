# Eagle Eye User Guide

## 1. Command Centre

The Command Centre displays total incidents, open incidents, high or critical incidents, represented modules and the most recent locally recorded cases. Use **Load demo incidents** only to populate synthetic examples.

## 2. SIEM Detection

1. Export authentication telemetry from Wazuh, OpenSearch or Windows Event Viewer as JSON, NDJSON or CSV.
2. Select **Import JSON / NDJSON / CSV**.
3. Set the failure count and time window.
4. Select **Analyse telemetry**.
5. Review repeated Event ID 4625 failures and success-after-failure findings.
6. Select a finding and create a local incident, or export the analysis as JSON.

The included Wazuh and Sysmon files are in `configs/`.

## 3. Active Directory Defence

Import domain-controller and Sysmon telemetry. Eagle Eye hunts:

- Event ID 4769 using RC4-compatible encryption.
- bursts of service-ticket requests from one source.
- Sysmon Event ID 10 targeting `lsass.exe`.
- Event ID 4624 Logon Type 3 using NTLM followed by Event ID 4672 for the same logon identifier.

The workspace does not execute credential attacks. Use the supplied PowerShell lab script only in an isolated domain you own.

## 4. Phishing Analysis

1. Export a suspicious message as `.eml` or copy its full raw headers.
2. Load the file or paste headers and body.
3. Select **Analyse email**.
4. Review sender alignment, authentication results and extracted artefacts.
5. Select an indicator and query VirusTotal or PhishTank.

Configure API credentials under **Settings**. Do not upload sensitive files to public analysis services.

## 5. Azure Security Monitoring

Import Azure Activity data and run the analysis. For controlled remediation:

1. Install Azure CLI.
2. Run `az login` in PowerShell.
3. Enter the subscription, resource group and storage account.
4. Preview the exact command.
5. Select **Disable anonymous blob access** and confirm.

Eagle Eye executes the Azure CLI with an argument list and without a shell, reducing command-injection risk.

## 6. SOC Automation

Create an alert using one indicator per line:

```text
domain,example.test
ip,203.0.113.50
sha256,0000000000000000000000000000000000000000000000000000000000000000
```

Available actions:

- **Preview payload** — local JSON only.
- **Send to Shuffle** — sends the alert to the configured webhook.
- **Enrich and evaluate** — performs VirusTotal lookups and calculates the score.
- **Create TheHive case** — creates an external case after confirmation.

A missing reputation result is not treated as safe.

## 7. Settings

Service URLs are stored in local SQLite. API keys and webhook URLs are stored through the system keyring. The tool check shows whether Azure CLI, PowerShell, Docker and Git are installed.
