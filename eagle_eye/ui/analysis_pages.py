from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Callable

from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from eagle_eye.database import Database
from eagle_eye.models import AnalysisResult, Incident
from eagle_eye.paths import export_dir, resource_path
from eagle_eye.services.active_directory import analyse_ad_records
from eagle_eye.services.azure import analyse_azure_records, remediate_public_access, remediation_command
from eagle_eye.services.common import load_records
from eagle_eye.services.reporting import export_analysis
from eagle_eye.services.siem import analyse_auth_records
from eagle_eye.ui.common import FindingTable, PageHeader, horizontal_actions
from eagle_eye.workers import Worker


class TelemetryPage(QWidget):
    def __init__(self, title: str, subtitle: str, module: str, database: Database, thread_pool, analyser: Callable[..., AnalysisResult], demo_file: str) -> None:
        super().__init__()
        self.module = module
        self.database = database
        self.thread_pool = thread_pool
        self.analyser = analyser
        self.demo_file = demo_file
        self.records: list[dict] = []
        self.result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        self.root_layout = root
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(PageHeader(title, subtitle))
        self.source_label = QLabel("No telemetry loaded")
        self.source_label.setObjectName("Muted")
        import_button = QPushButton("Import JSON / NDJSON / CSV")
        import_button.clicked.connect(self.import_file)
        demo_button = QPushButton("Load demo telemetry")
        demo_button.setObjectName("SecondaryButton")
        demo_button.clicked.connect(self.load_demo)
        self.analyse_button = QPushButton("Analyse telemetry")
        self.analyse_button.clicked.connect(self.run_analysis)
        root.addWidget(horizontal_actions(import_button, demo_button, self.analyse_button))
        root.addWidget(self.source_label)
        self.parameters = QGroupBox("Detection parameters")
        form = QFormLayout(self.parameters)
        self.threshold = QSpinBox()
        self.threshold.setRange(2, 100)
        self.threshold.setValue(3 if module == "SIEM" else 5)
        self.window = QSpinBox()
        self.window.setRange(30, 3600)
        self.window.setValue(120 if module == "SIEM" else 300)
        form.addRow("Event threshold", self.threshold)
        form.addRow("Window (seconds)", self.window)
        root.addWidget(self.parameters)
        self.summary_label = QLabel("Run an analysis to view the result summary.")
        self.summary_label.setWordWrap(True)
        self.summary_label.setObjectName("Muted")
        root.addWidget(self.summary_label)
        self.findings_table = FindingTable()
        root.addWidget(self.findings_table, 1)
        create_button = QPushButton("Create incident from selected finding")
        create_button.clicked.connect(self.create_incident)
        export_button = QPushButton("Export analysis JSON")
        export_button.setObjectName("SecondaryButton")
        export_button.clicked.connect(self.export_report)
        root.addWidget(horizontal_actions(create_button, export_button))

    def import_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import telemetry", str(Path.home()), "Telemetry (*.json *.ndjson *.jsonl *.csv);;All files (*)")
        if not path:
            return
        try:
            self.records = load_records(path)
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self.source_label.setText(f"Loaded {len(self.records)} records from {path}")
        self.database.log_activity(self.module, "Imported telemetry", path)

    def load_demo(self) -> None:
        path = resource_path("demo", self.demo_file)
        try:
            self.records = load_records(path)
        except Exception as exc:
            QMessageBox.critical(self, "Demo load failed", str(exc))
            return
        self.source_label.setText(f"Loaded {len(self.records)} synthetic demo records")
        self.database.log_activity(self.module, "Loaded demo telemetry")

    def _analyse(self) -> AnalysisResult:
        if self.module == "SIEM":
            return self.analyser(self.records, failure_threshold=self.threshold.value(), window_seconds=self.window.value())
        return self.analyser(self.records, ticket_burst_threshold=self.threshold.value(), window_seconds=self.window.value())

    def run_analysis(self) -> None:
        if not self.records:
            QMessageBox.information(self, "No telemetry", "Import or load telemetry first.")
            return
        self.analyse_button.setEnabled(False)
        self.summary_label.setText("Analysing telemetry…")
        worker = Worker(self._analyse)
        worker.signals.result.connect(self._analysis_complete)
        worker.signals.error.connect(self._analysis_error)
        worker.signals.finished.connect(lambda: self.analyse_button.setEnabled(True))
        self.thread_pool.start(worker)

    def _analysis_complete(self, result: AnalysisResult) -> None:
        self.result = result
        self.findings_table.set_findings(result.findings)
        self.summary_label.setText("  •  ".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in result.summary.items()))
        self.database.log_activity(self.module, "Analysed telemetry", json.dumps(result.summary))

    def _analysis_error(self, trace: str) -> None:
        QMessageBox.critical(self, "Analysis failed", trace.splitlines()[-1])
        self.summary_label.setText("Analysis failed.")

    def create_incident(self) -> None:
        finding = self.findings_table.selected_finding()
        if finding is None:
            QMessageBox.information(self, "Select a finding", "Select one finding first.")
            return
        incident_id = self.database.add_incident(Incident(module=finding.module, title=finding.title, severity=finding.severity, description=finding.description, evidence=finding.evidence))
        QMessageBox.information(self, "Incident created", f"Incident #{incident_id} was created.")

    def export_report(self) -> None:
        if self.result is None:
            QMessageBox.information(self, "Nothing to export", "Run an analysis first.")
            return
        default = export_dir() / f"{self.module.lower().replace(' ', '-')}-analysis.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export analysis", str(default), "JSON (*.json)")
        if path:
            export_analysis(self.result, path)
            QMessageBox.information(self, "Export complete", path)


class SiemPage(TelemetryPage):
    def __init__(self, database: Database, thread_pool) -> None:
        super().__init__("SIEM Detection", "Analyse Windows Security and Wazuh-exported authentication telemetry, detect repeated failures and identify success-after-failure patterns.", "SIEM", database, thread_pool, analyse_auth_records, "siem_events.json")
        chart = QGroupBox("Authentication visualisation")
        chart_form = QFormLayout(chart)
        self.success_bar = QProgressBar()
        self.success_bar.setFormat("Successful logons: %v")
        self.failure_bar = QProgressBar()
        self.failure_bar.setFormat("Failed logons: %v")
        chart_form.addRow("Event ID 4624", self.success_bar)
        chart_form.addRow("Event ID 4625", self.failure_bar)
        self.root_layout.insertWidget(5, chart)

    def _analysis_complete(self, result: AnalysisResult) -> None:
        super()._analysis_complete(result)
        successes = int(result.summary.get("successful_logons", 0))
        failures = int(result.summary.get("failed_logons", 0))
        maximum = max(1, successes, failures)
        self.success_bar.setMaximum(maximum)
        self.failure_bar.setMaximum(maximum)
        self.success_bar.setValue(successes)
        self.failure_bar.setValue(failures)


class ActiveDirectoryPage(TelemetryPage):
    def __init__(self, database: Database, thread_pool) -> None:
        super().__init__("Active Directory Defence", "Hunt Kerberoasting indicators, LSASS access and privileged NTLM network-logon correlations from exported Windows or Sysmon records.", "Active Directory", database, thread_pool, analyse_ad_records, "ad_events.json")


class AzurePage(QWidget):
    def __init__(self, database: Database, thread_pool) -> None:
        super().__init__()
        self.database = database
        self.thread_pool = thread_pool
        self.records: list[dict] = []
        self.result: AnalysisResult | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(PageHeader("Azure Security Monitoring", "Detect public blob-access changes in Azure Activity telemetry and explicitly remediate a selected storage account through Azure CLI."))
        import_button = QPushButton("Import Azure Activity JSON / CSV")
        import_button.clicked.connect(self.import_file)
        demo_button = QPushButton("Load demo activity")
        demo_button.setObjectName("SecondaryButton")
        demo_button.clicked.connect(self.load_demo)
        analyse_button = QPushButton("Analyse activity")
        analyse_button.clicked.connect(self.run_analysis)
        root.addWidget(horizontal_actions(import_button, demo_button, analyse_button))
        self.source_label = QLabel("No activity data loaded")
        self.source_label.setObjectName("Muted")
        root.addWidget(self.source_label)
        self.summary_label = QLabel("Run an analysis to identify public-storage changes.")
        self.summary_label.setObjectName("Muted")
        root.addWidget(self.summary_label)
        self.findings_table = FindingTable()
        root.addWidget(self.findings_table, 1)
        remediation = QGroupBox("Controlled remediation")
        form = QFormLayout(remediation)
        self.subscription = QLineEdit()
        self.subscription.setPlaceholderText("Optional subscription ID or name")
        self.resource_group = QLineEdit()
        self.resource_group.setPlaceholderText("rg-cloud-security-lab")
        self.storage_account = QLineEdit()
        self.storage_account.setPlaceholderText("storage account name")
        form.addRow("Subscription", self.subscription)
        form.addRow("Resource group", self.resource_group)
        form.addRow("Storage account", self.storage_account)
        preview = QPushButton("Preview Azure CLI command")
        preview.setObjectName("SecondaryButton")
        preview.clicked.connect(self.preview_command)
        remediate = QPushButton("Disable anonymous blob access")
        remediate.setObjectName("DangerButton")
        remediate.clicked.connect(self.remediate)
        form.addRow(horizontal_actions(preview, remediate))
        root.addWidget(remediation)

    def import_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Azure activity", str(Path.home()), "Telemetry (*.json *.ndjson *.jsonl *.csv)")
        if not path:
            return
        try:
            self.records = load_records(path)
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self.source_label.setText(f"Loaded {len(self.records)} records from {path}")

    def load_demo(self) -> None:
        path = resource_path("demo", "azure_activity.json")
        self.records = load_records(path)
        self.source_label.setText(f"Loaded {len(self.records)} synthetic demo records")

    def run_analysis(self) -> None:
        if not self.records:
            QMessageBox.information(self, "No telemetry", "Import or load Azure activity first.")
            return
        self.result = analyse_azure_records(self.records)
        self.findings_table.set_findings(self.result.findings)
        self.summary_label.setText("  •  ".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in self.result.summary.items()))
        self.database.log_activity("Azure", "Analysed activity", json.dumps(self.result.summary))

    def preview_command(self) -> None:
        try:
            command = remediation_command(self.resource_group.text(), self.storage_account.text(), self.subscription.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Missing values", str(exc))
            return
        QMessageBox.information(self, "Dry-run command", shlex.join(command))

    def remediate(self) -> None:
        try:
            command = remediation_command(self.resource_group.text(), self.storage_account.text(), self.subscription.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Missing values", str(exc))
            return
        prompt = "This will execute Azure CLI and set allowBlobPublicAccess=false for:\n\n" f"Resource group: {self.resource_group.text()}\n" f"Storage account: {self.storage_account.text()}\n\n" f"Command:\n{shlex.join(command)}\n\nContinue?"
        if QMessageBox.question(self, "Confirm remediation", prompt) != QMessageBox.StandardButton.Yes:
            return
        worker = Worker(remediate_public_access, self.resource_group.text(), self.storage_account.text(), self.subscription.text())
        worker.signals.result.connect(self._remediation_complete)
        worker.signals.error.connect(lambda trace: QMessageBox.critical(self, "Remediation failed", trace.splitlines()[-1]))
        self.thread_pool.start(worker)

    def _remediation_complete(self, result: dict) -> None:
        self.database.log_activity("Azure", "Disabled anonymous blob access", json.dumps(result))
        self.database.add_incident(Incident(module="Azure", title="Anonymous blob access remediated", severity="medium", status="Closed", description="Eagle Eye executed the approved Azure CLI remediation command.", evidence={"resource_group": self.resource_group.text(), "storage_account": self.storage_account.text()}))
        QMessageBox.information(self, "Remediation complete", "Azure reported a successful update.")
