# Eagle Eye SOC Platform

**Eagle Eye** is a standalone Windows desktop security operations platform that combines five portfolio projects into one usable analyst console:

1. **SIEM Detection** — analyse Wazuh or Windows authentication exports, detect repeated Event ID 4625 failures, and identify successful-logon-after-failure patterns.
2. **Active Directory Defence** — hunt Event ID 4769 Kerberoasting indicators, RC4 service tickets, Sysmon access to LSASS, and privileged NTLM network logons.
3. **Phishing Analysis** — parse raw email headers, assess SPF/DKIM/DMARC, identify sender alignment problems, defang artefacts, and enrich selected indicators through VirusTotal and PhishTank.
4. **Azure Security Monitoring** — analyse Azure Activity exports for public blob-access changes and, after explicit confirmation, disable anonymous access through Azure CLI.
5. **SOC Automation** — compose alerts, send them to Shuffle, enrich indicators, calculate an explainable score, and create TheHive cases after analyst approval.

The project is independent and does not depend on A-Guard or any other repository.

## Interface

Eagle Eye uses a dark-green, black and white Windows interface with these workspaces:

- Command Centre
- SIEM Detection
- Active Directory Defence
- Phishing Analysis
- Azure Security Monitoring
- SOC Automation
- Settings and Integrations

Incident history is stored locally in SQLite. Integration secrets are stored through the operating-system keyring, which uses **Windows Credential Manager** on Windows.

## Safety model

Eagle Eye is designed for authorised defensive work:

- It does not execute Kerberoasting, pass-the-hash, credential dumping or phishing delivery.
- Active Directory functions analyse telemetry and provide isolated lab configuration files.
- Azure remediation requires the analyst to enter the exact resource and confirm the command.
- Shuffle and TheHive actions run only when the analyst presses the corresponding button.
- VirusTotal integration performs lookups only; it does not upload files.
- API failures and missing reputation are treated as unknown, not benign.

## Windows installation from source

### Requirements

- Windows 10 or Windows 11 x64
- Python 3.11 or newer
- PowerShell

Optional tools:

- Azure CLI for storage remediation
- Docker for Wazuh, Shuffle or TheHive labs
- Git

### Install

```powershell
git clone https://github.com/Upenyu2000/Eagle-Eye-SOC-Platform.git
cd Eagle-Eye-SOC-Platform
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install_windows.ps1
.\run_eagle_eye.bat
```

## Downloadable Windows build

Every push to `main` runs the Windows build workflow and produces:

- `Eagle-Eye-SOC-Platform-Windows-x64.zip` — portable application folder.
- `Eagle-Eye-Setup-x64.exe` — Windows installer.

Open the latest GitHub Actions run and download the `eagle-eye-windows` artifact.

## Development

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python main.py
```

Build locally:

```powershell
.\scripts\build_windows.ps1
```

## Supported telemetry input

The SIEM, Active Directory and Azure workspaces accept:

- JSON arrays
- JSON objects containing `records`, `events`, `value` or `alerts`
- OpenSearch-style `hits.hits` exports
- NDJSON / JSONL
- CSV

Eagle Eye searches common flat and nested field names so it can handle Wazuh, Windows Event Viewer and Azure Activity exports without requiring one rigid schema.

## Repository structure

```text
Eagle-Eye-SOC-Platform/
├── eagle_eye/                 Application package
│   ├── services/              Detection, enrichment and remediation logic
│   ├── ui/                    PySide6 Windows interface
│   └── assets/                Styles and application artwork
├── configs/                   Wazuh, Sysmon, Sentinel, Bicep and SOAR artefacts
├── demo/                      Synthetic safe demonstration data
├── docs/                      User and security documentation
├── scripts/                   Windows setup, build and AD lab scripts
├── tests/                     Automated unit tests
├── installer/                 Inno Setup definition
├── EagleEye.spec              PyInstaller build configuration
└── .github/workflows/         Windows build automation
```

## Included lab artefacts

- Sysmon configuration
- Wazuh event-channel collection blocks
- Wazuh custom authentication rules
- Synthetic Active Directory deployment script
- Microsoft Sentinel KQL for public-storage changes
- Azure storage Bicep template
- Managed-identity Logic App remediation template
- Shuffle workflow blueprint
- TheHive case payload template

## Data and credential handling

Eagle Eye stores runtime data under:

```text
%LOCALAPPDATA%\EagleEye
```

Do not commit real email samples, BloodHound collections, EVTX files, packet captures, credentials, API keys, tenant identifiers or customer information. See [`docs/SECURITY.md`](docs/SECURITY.md).

## Tests

The repository includes automated tests for:

- repeated authentication failures and success-after-failure
- Kerberos ticket bursts and RC4 use
- LSASS access and NTLM privilege correlation
- phishing header and indicator parsing
- Azure public-access detection and safe command construction
- SOAR scoring and decisions
- SQLite incident lifecycle

```powershell
python -m unittest discover -s tests -v
```

## Author

**Upenyu Hlangabeza**  
Fraud Investigator and security/data practitioner.
