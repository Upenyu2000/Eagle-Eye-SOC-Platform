from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QLabel, QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout, QWidget

from eagle_eye.database import Database
from eagle_eye.models import Incident
from eagle_eye.paths import export_dir, resource_path
from eagle_eye.secrets import SecretStore
from eagle_eye.services.phishing import PhishTankClient, VirusTotalClient, analyse_message
from eagle_eye.services.reporting import export_phishing_markdown
from eagle_eye.ui.common import FindingTable, PageHeader, horizontal_actions
from eagle_eye.workers import Worker


class PhishingPage(QWidget):
    def __init__(self, database: Database, secrets: SecretStore, thread_pool) -> None:
        super().__init__()
        self.database = database
        self.secrets = secrets
        self.thread_pool = thread_pool
        self.result = None
        self.indicators: list[dict[str, str]] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(PageHeader("Phishing Analysis", "Parse raw headers, assess SPF/DKIM/DMARC alignment, extract and defang indicators, then enrich selected artefacts without opening them."))
        load_button = QPushButton("Load .eml / text")
        load_button.clicked.connect(self.load_message)
        demo_button = QPushButton("Load demo phishing email")
        demo_button.setObjectName("SecondaryButton")
        demo_button.clicked.connect(self.load_demo)
        analyse_button = QPushButton("Analyse email")
        analyse_button.clicked.connect(self.analyse)
        root.addWidget(horizontal_actions(load_button, demo_button, analyse_button))
        splitter = QSplitter(Qt.Orientation.Vertical)
        input_tabs = QTabWidget()
        self.headers = QTextEdit()
        self.headers.setPlaceholderText("Paste the full raw email headers here…")
        self.body = QTextEdit()
        self.body.setPlaceholderText("Paste the email body here. Do not open attachments or click links.")
        input_tabs.addTab(self.headers, "Raw headers")
        input_tabs.addTab(self.body, "Message body")
        splitter.addWidget(input_tabs)
        output_tabs = QTabWidget()
        findings_widget = QWidget()
        findings_layout = QVBoxLayout(findings_widget)
        self.summary = QLabel("Analyse an email to display authentication results and findings.")
        self.summary.setObjectName("Muted")
        self.summary.setWordWrap(True)
        findings_layout.addWidget(self.summary)
        self.finding_table = FindingTable()
        findings_layout.addWidget(self.finding_table)
        create_incident = QPushButton("Create incident from selected finding")
        create_incident.clicked.connect(self.create_incident)
        export_report = QPushButton("Export incident report")
        export_report.setObjectName("SecondaryButton")
        export_report.clicked.connect(self.export_report)
        findings_layout.addWidget(horizontal_actions(create_incident, export_report))
        output_tabs.addTab(findings_widget, "Findings")
        indicators_widget = QWidget()
        indicators_layout = QVBoxLayout(indicators_widget)
        self.indicator_table = QTableWidget(0, 3)
        self.indicator_table.setHorizontalHeaderLabels(["Type", "Indicator", "Defanged"])
        self.indicator_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.indicator_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.indicator_table.verticalHeader().setVisible(False)
        self.indicator_table.horizontalHeader().setStretchLastSection(True)
        indicators_layout.addWidget(self.indicator_table)
        vt_button = QPushButton("Check selected in VirusTotal")
        vt_button.clicked.connect(self.lookup_virustotal)
        pt_button = QPushButton("Check selected URL in PhishTank")
        pt_button.setObjectName("SecondaryButton")
        pt_button.clicked.connect(self.lookup_phishtank)
        indicators_layout.addWidget(horizontal_actions(vt_button, pt_button))
        self.enrichment_output = QTextEdit()
        self.enrichment_output.setReadOnly(True)
        self.enrichment_output.setPlaceholderText("Enrichment results appear here. A zero-detection result is not proof that an indicator is safe.")
        indicators_layout.addWidget(self.enrichment_output)
        output_tabs.addTab(indicators_widget, "Indicators & enrichment")
        splitter.addWidget(output_tabs)
        splitter.setSizes([330, 430])
        root.addWidget(splitter, 1)

    def load_message(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load email", str(Path.home()), "Email and text (*.eml *.txt);;All files (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.critical(self, "Load failed", str(exc))
            return
        if "\n\n" in text:
            header_text, body_text = text.split("\n\n", 1)
        elif "\r\n\r\n" in text:
            header_text, body_text = text.split("\r\n\r\n", 1)
        else:
            header_text, body_text = text, ""
        self.headers.setPlainText(header_text)
        self.body.setPlainText(body_text)
        self.database.log_activity("Phishing", "Loaded email", path)

    def load_demo(self) -> None:
        text = resource_path("demo", "phishing_message.eml").read_text(encoding="utf-8")
        header_text, body_text = text.split("\n\n", 1)
        self.headers.setPlainText(header_text)
        self.body.setPlainText(body_text)
        self.database.log_activity("Phishing", "Loaded demo email")

    def analyse(self) -> None:
        header_text = self.headers.toPlainText().strip()
        if not header_text:
            QMessageBox.information(self, "No headers", "Paste or load the full raw headers first.")
            return
        self.result, self.indicators = analyse_message(header_text, self.body.toPlainText())
        self.finding_table.set_findings(self.result.findings)
        self.summary.setText("  •  ".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in self.result.summary.items()))
        self.indicator_table.setRowCount(len(self.indicators))
        for row, indicator in enumerate(self.indicators):
            self.indicator_table.setItem(row, 0, QTableWidgetItem(indicator["type"]))
            self.indicator_table.setItem(row, 1, QTableWidgetItem(indicator["value"]))
            self.indicator_table.setItem(row, 2, QTableWidgetItem(indicator["defanged"]))
        self.indicator_table.resizeColumnsToContents()
        self.indicator_table.horizontalHeader().setStretchLastSection(True)
        self.database.log_activity("Phishing", "Analysed email", json.dumps(self.result.summary))

    def _selected_indicator(self) -> dict[str, str] | None:
        row = self.indicator_table.currentRow()
        if row < 0 or row >= len(self.indicators):
            QMessageBox.information(self, "Select an indicator", "Select one indicator first.")
            return None
        return self.indicators[row]

    def lookup_virustotal(self) -> None:
        indicator = self._selected_indicator()
        if not indicator:
            return
        if indicator["type"] == "email":
            QMessageBox.information(self, "Unsupported type", "VirusTotal lookup is not used for email addresses here.")
            return
        api_key = self.secrets.get("virustotal_api_key")
        if not api_key:
            QMessageBox.warning(self, "Missing API key", "Configure the VirusTotal API key in Settings.")
            return
        self.enrichment_output.setPlainText("Querying VirusTotal…")
        worker = Worker(VirusTotalClient(api_key).lookup, indicator["type"], indicator["value"])
        worker.signals.result.connect(lambda result: self.enrichment_output.setPlainText(json.dumps(result, indent=2, default=str)))
        worker.signals.error.connect(lambda trace: self.enrichment_output.setPlainText(f"Lookup failed:\n{trace.splitlines()[-1]}"))
        self.thread_pool.start(worker)

    def lookup_phishtank(self) -> None:
        indicator = self._selected_indicator()
        if not indicator:
            return
        if indicator["type"] != "url":
            QMessageBox.information(self, "URL required", "Select a URL indicator for PhishTank.")
            return
        app_key = self.secrets.get("phishtank_api_key")
        self.enrichment_output.setPlainText("Querying PhishTank…")
        worker = Worker(PhishTankClient(app_key).check, indicator["value"])
        worker.signals.result.connect(lambda result: self.enrichment_output.setPlainText(json.dumps(result, indent=2, default=str)))
        worker.signals.error.connect(lambda trace: self.enrichment_output.setPlainText(f"Lookup failed:\n{trace.splitlines()[-1]}"))
        self.thread_pool.start(worker)

    def create_incident(self) -> None:
        finding = self.finding_table.selected_finding()
        if not finding:
            QMessageBox.information(self, "Select a finding", "Select one finding first.")
            return
        incident_id = self.database.add_incident(Incident(module="Phishing", title=finding.title, severity=finding.severity, description=finding.description, evidence={**finding.evidence, "indicators": self.indicators}))
        QMessageBox.information(self, "Incident created", f"Incident #{incident_id} was created.")

    def export_report(self) -> None:
        if self.result is None:
            QMessageBox.information(self, "Nothing to export", "Analyse an email first.")
            return
        default = export_dir() / "phishing-incident-report.md"
        path, _ = QFileDialog.getSaveFileName(self, "Export phishing report", str(default), "Markdown (*.md)")
        if path:
            export_phishing_markdown(self.result, self.indicators, path)
            QMessageBox.information(self, "Report exported", path)
