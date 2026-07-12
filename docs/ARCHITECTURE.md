# Architecture

```mermaid
flowchart LR
    UI[PySide6 Windows GUI] --> DB[(Local SQLite)]
    UI --> KS[Windows Credential Manager via keyring]
    UI --> SIEM[SIEM analysis service]
    UI --> AD[AD analysis service]
    UI --> PH[Phishing analysis service]
    UI --> AZ[Azure analysis and remediation service]
    UI --> SOAR[Automation service]
    PH --> VT[VirusTotal API]
    PH --> PT[PhishTank API]
    AZ --> CLI[Azure CLI]
    SOAR --> SH[Shuffle webhook]
    SOAR --> TH[TheHive API]
```

Detection and integration logic is separated from UI code so that it can be unit tested without a graphical session. Long-running network and remediation actions execute through Qt's thread pool to keep the interface responsive.
