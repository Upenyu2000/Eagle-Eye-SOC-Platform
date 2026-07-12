# Security Policy and Lab Boundaries

## Intended use

Eagle Eye is for authorised defensive security operations, training environments and systems owned or explicitly controlled by the user.

## Prohibited repository content

Never commit:

- live credentials, password hashes, Kerberos tickets or API keys
- real phishing messages containing personal or organisational data
- BloodHound collection archives
- EVTX or packet-capture files from live environments
- cloud tenant identifiers or production resource details
- customer, claimant, employee or investigation data

## Credential storage

The application uses Python `keyring`. On Windows this normally stores values in Windows Credential Manager. URL settings that are not secrets are stored in `%LOCALAPPDATA%\EagleEye\eagle_eye.db`.

## External requests

- VirusTotal: lookup only; no file-upload function is implemented.
- PhishTank: URL lookup only.
- Shuffle: explicit analyst-initiated webhook request.
- TheHive: explicit analyst-confirmed case creation.
- Azure: explicit analyst-confirmed CLI update.

## Offensive lab boundaries

The Active Directory module does not execute Mimikatz, credential dumping, Kerberoasting or pass-the-hash. Those techniques are documented only as isolated-lab telemetry scenarios. The application focuses on detection and defensive analysis.

## Reporting issues

Do not include secrets or sensitive evidence in a public GitHub issue. Describe the problem with synthetic data and sanitised logs.
