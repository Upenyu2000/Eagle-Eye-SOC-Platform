from __future__ import annotations

import json
from datetime import datetime, timezone

from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from eagle_eye.database import Database
from eagle_eye.models import Incident
from eagle_eye.secrets import SecretStore
from eagle_eye.services.automation import TheHiveClient, build_thehive_case, decide, enrich_alert_indicators, send_webhook
from eagle_eye.ui.common import PageHeader, horizontal_actions
from eagle_eye.workers import Worker


class AutomationPage(QWidget):
    def __init__(self, database: Database, secrets: SecretStore, thread_pool) -> None:
        super().__init__()
        self.database = database
        self.secrets = secrets
        self.thread_pool = thread_pool
        self.last_alert: dict | None = None
        self.last_decision = None
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(PageHeader("SOC Automation", "Compose an alert, send it to Shuffle, enrich indicators through VirusTotal, and explicitly create a TheHive case when the score meets your threshold."))
        editor = QGroupBox("Alert builder")
        form = QFormLayout(editor)
        self.alert_id = QLineEdit("LAB-2026-0001")
        self.title = QLineEdit("Suspicious outbound connection")
        self.severity = QComboBox()
        self.severity.addItems(["low", "medium", "high", "critical"])
        self.severity.setCurrentText("high")
        self.host = QLineEdit("WS01")
        self.user = QLineEdit(r"LAB\alice")
        self.indicators = QTextEdit()
        self.indicators.setPlaceholderText("One indicator per line: type,value\nExample: domain,example.test")
        self.indicators.setPlainText("domain,example.test\nip,203.0.113.50\nsha256," + "0" * 64)
        self.case_threshold = QSpinBox()
        self.case_threshold.setRange(1, 1000)
        self.case_threshold.setValue(6)
        form.addRow("Alert ID", self.alert_id)
        form.addRow("Title", self.title)
        form.addRow("Severity", self.severity)
        form.addRow("Host", self.host)
        form.addRow("User", self.user)
        form.addRow("Indicators", self.indicators)
        form.addRow("TheHive case threshold", self.case_threshold)
        root.addWidget(editor)
        preview = QPushButton("Preview payload")
        preview.clicked.connect(self.preview)
        shuffle = QPushButton("Send to Shuffle")
        shuffle.setObjectName("SecondaryButton")
        shuffle.clicked.connect(self.send_to_shuffle)
        pipeline = QPushButton("Enrich and evaluate")
        pipeline.clicked.connect(self.run_pipeline)
        thehive = QPushButton("Create TheHive case")
        thehive.setObjectName("DangerButton")
        thehive.clicked.connect(self.create_thehive_case)
        root.addWidget(horizontal_actions(preview, shuffle, pipeline, thehive))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("Workflow output appears here. No case or external request is created without an explicit button click.")
        root.addWidget(self.output, 1)

    def build_alert(self) -> dict:
        indicators = []
        for line in self.indicators.toPlainText().splitlines():
            if not line.strip():
                continue
            if "," not in line:
                raise ValueError(f"Invalid indicator line: {line}")
            indicator_type, value = line.split(",", 1)
            indicators.append({"type": indicator_type.strip().lower(), "value": value.strip()})
        if not indicators:
            raise ValueError("At least one indicator is required")
        return {"alert_id": self.alert_id.text().strip(), "source": "eagle-eye", "title": self.title.text().strip(), "severity": self.severity.currentText(), "timestamp": datetime.now(timezone.utc).isoformat(), "host": self.host.text().strip(), "user": self.user.text().strip(), "indicators": indicators}

    def preview(self) -> None:
        try:
            self.last_alert = self.build_alert()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid alert", str(exc))
            return
        self.output.setPlainText(json.dumps(self.last_alert, indent=2))

    def send_to_shuffle(self) -> None:
        try:
            alert = self.build_alert()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid alert", str(exc))
            return
        webhook = self.secrets.get("shuffle_webhook_url")
        if not webhook:
            QMessageBox.warning(self, "Missing webhook", "Configure the Shuffle webhook URL in Settings.")
            return
        self.output.setPlainText("Sending alert to Shuffle…")
        worker = Worker(send_webhook, webhook, alert)
        worker.signals.result.connect(lambda result: self._display_and_log("Shuffle", "Sent alert", result))
        worker.signals.error.connect(lambda trace: self.output.setPlainText(f"Shuffle request failed:\n{trace.splitlines()[-1]}"))
        self.thread_pool.start(worker)

    def run_pipeline(self) -> None:
        try:
            self.last_alert = self.build_alert()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid alert", str(exc))
            return
        vt_key = self.secrets.get("virustotal_api_key")
        if not vt_key:
            QMessageBox.warning(self, "Missing API key", "Configure VirusTotal in Settings.")
            return
        self.output.setPlainText("Enriching alert indicators…")
        worker = Worker(enrich_alert_indicators, self.last_alert, vt_key)
        worker.signals.result.connect(self._pipeline_complete)
        worker.signals.error.connect(lambda trace: self.output.setPlainText(f"Pipeline failed:\n{trace.splitlines()[-1]}"))
        self.thread_pool.start(worker)

    def _pipeline_complete(self, enrichments: list[dict]) -> None:
        self.last_decision = decide(enrichments, case_threshold=self.case_threshold.value())
        payload = {"score": self.last_decision.score, "outcome": self.last_decision.outcome, "reason": self.last_decision.reason, "enrichments": enrichments}
        self.output.setPlainText(json.dumps(payload, indent=2, default=str))
        self.database.log_activity("Automation", "Evaluated alert", json.dumps(payload, default=str))

    def create_thehive_case(self) -> None:
        if not self.last_alert or not self.last_decision:
            QMessageBox.information(self, "Run enrichment first", "Enrich and evaluate the alert before creating a case.")
            return
        if self.last_decision.outcome != "create_case":
            answer = QMessageBox.question(self, "Below case threshold", f"The current outcome is {self.last_decision.outcome} with score {self.last_decision.score}. Create a case anyway?")
            if answer != QMessageBox.StandardButton.Yes:
                return
        base_url = self.database.get_setting("thehive_base_url")
        api_key = self.secrets.get("thehive_api_key")
        if not base_url or not api_key:
            QMessageBox.warning(self, "Missing configuration", "Configure TheHive URL and API key in Settings.")
            return
        case_payload = build_thehive_case(self.last_alert, self.last_decision)
        if QMessageBox.question(self, "Create external case", f"Create a TheHive case at {base_url}?") != QMessageBox.StandardButton.Yes:
            return
        self.output.setPlainText("Creating TheHive case…")
        worker = Worker(TheHiveClient(base_url, api_key).create_case, case_payload)
        worker.signals.result.connect(self._thehive_complete)
        worker.signals.error.connect(lambda trace: self.output.setPlainText(f"TheHive request failed:\n{trace.splitlines()[-1]}"))
        self.thread_pool.start(worker)

    def _thehive_complete(self, result: dict) -> None:
        self.output.setPlainText(json.dumps(result, indent=2, default=str))
        incident_id = self.database.add_incident(Incident(module="Automation", title=self.last_alert.get("title", "Automated alert") if self.last_alert else "Automated alert", severity=self.last_alert.get("severity", "medium") if self.last_alert else "medium", description="TheHive case created after explicit analyst approval.", evidence={"thehive_result": result, "automation_score": self.last_decision.score}))
        self.database.log_activity("Automation", "Created TheHive case", json.dumps(result, default=str))
        notification_webhook = self.secrets.get("team_webhook_url")
        if notification_webhook:
            message = {"text": f"Eagle Eye created a TheHive case for {self.last_alert.get('alert_id', 'UNKNOWN')} — {self.last_alert.get('title', 'Security alert')}. Automation score: {self.last_decision.score}."}
            worker = Worker(send_webhook, notification_webhook, message)
            worker.signals.error.connect(lambda trace: self.database.log_activity("Automation", "Team notification failed", trace.splitlines()[-1]))
            worker.signals.result.connect(lambda response: self.database.log_activity("Automation", "Sent team notification", json.dumps(response, default=str)))
            self.thread_pool.start(worker)
        QMessageBox.information(self, "Case created", f"TheHive accepted the case. Local incident #{incident_id} was recorded.")

    def _display_and_log(self, module: str, action: str, result: dict) -> None:
        self.output.setPlainText(json.dumps(result, indent=2, default=str))
        self.database.log_activity(module, action, json.dumps(result, default=str))
