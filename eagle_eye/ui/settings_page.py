from __future__ import annotations

import os
import shutil
import subprocess

from PySide6.QtWidgets import QFormLayout, QGroupBox, QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout, QWidget

from eagle_eye.database import Database
from eagle_eye.paths import data_dir
from eagle_eye.secrets import SecretStore, SecretStoreError
from eagle_eye.ui.common import PageHeader, horizontal_actions


class SettingsPage(QWidget):
    def __init__(self, database: Database, secrets: SecretStore) -> None:
        super().__init__()
        self.database = database
        self.secrets = secrets
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        root.addWidget(PageHeader("Settings & Integrations", "URLs are stored in the local SQLite database. API keys and webhook secrets are stored through the operating system keyring, including Windows Credential Manager."))
        endpoints = QGroupBox("Service endpoints")
        endpoint_form = QFormLayout(endpoints)
        self.thehive_url = QLineEdit()
        self.thehive_url.setPlaceholderText("https://thehive.lab.local")
        endpoint_form.addRow("TheHive base URL", self.thehive_url)
        root.addWidget(endpoints)
        credentials = QGroupBox("Protected credentials")
        credential_form = QFormLayout(credentials)
        self.vt_key = self._secret_field("VirusTotal API key")
        self.pt_key = self._secret_field("PhishTank app key")
        self.thehive_key = self._secret_field("TheHive API key")
        self.shuffle_webhook = self._secret_field("Shuffle webhook URL")
        self.team_webhook = self._secret_field("Team notification webhook URL")
        credential_form.addRow("VirusTotal API key", self.vt_key)
        credential_form.addRow("PhishTank app key", self.pt_key)
        credential_form.addRow("TheHive API key", self.thehive_key)
        credential_form.addRow("Shuffle webhook URL", self.shuffle_webhook)
        credential_form.addRow("Team notification webhook", self.team_webhook)
        root.addWidget(credentials)
        tools = QGroupBox("Local tool availability")
        tool_form = QFormLayout(tools)
        self.tool_labels: dict[str, QLabel] = {}
        for tool in ("az", "powershell", "pwsh", "docker", "git"):
            label = QLabel()
            self.tool_labels[tool] = label
            tool_form.addRow(tool, label)
        root.addWidget(tools)
        save_button = QPushButton("Save settings")
        save_button.clicked.connect(self.save)
        refresh_button = QPushButton("Refresh tool checks")
        refresh_button.setObjectName("SecondaryButton")
        refresh_button.clicked.connect(self.refresh_tools)
        open_data = QPushButton("Open local data folder")
        open_data.setObjectName("SecondaryButton")
        open_data.clicked.connect(self.open_data_folder)
        root.addWidget(horizontal_actions(save_button, refresh_button, open_data))
        root.addStretch(1)
        self.load()
        self.refresh_tools()

    @staticmethod
    def _secret_field(placeholder: str) -> QLineEdit:
        field = QLineEdit()
        field.setPlaceholderText(placeholder)
        field.setEchoMode(QLineEdit.EchoMode.Password)
        return field

    def load(self) -> None:
        self.thehive_url.setText(self.database.get_setting("thehive_base_url"))
        try:
            self.vt_key.setText(self.secrets.get("virustotal_api_key"))
            self.pt_key.setText(self.secrets.get("phishtank_api_key"))
            self.thehive_key.setText(self.secrets.get("thehive_api_key"))
            self.shuffle_webhook.setText(self.secrets.get("shuffle_webhook_url"))
            self.team_webhook.setText(self.secrets.get("team_webhook_url"))
        except SecretStoreError as exc:
            QMessageBox.warning(self, "Credential store unavailable", str(exc))

    def save(self) -> None:
        self.database.set_setting("thehive_base_url", self.thehive_url.text().strip())
        try:
            self.secrets.set("virustotal_api_key", self.vt_key.text().strip())
            self.secrets.set("phishtank_api_key", self.pt_key.text().strip())
            self.secrets.set("thehive_api_key", self.thehive_key.text().strip())
            self.secrets.set("shuffle_webhook_url", self.shuffle_webhook.text().strip())
            self.secrets.set("team_webhook_url", self.team_webhook.text().strip())
        except SecretStoreError as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.database.log_activity("Settings", "Updated integration configuration")
        QMessageBox.information(self, "Settings saved", "Integration settings were saved locally.")

    def refresh_tools(self) -> None:
        for tool, label in self.tool_labels.items():
            path = shutil.which(tool)
            label.setText(path if path else "Not found")
            label.setStyleSheet("color: #42dca3;" if path else "color: #f7768e;")

    def open_data_folder(self) -> None:
        path = data_dir()
        if os.name == "nt":
            os.startfile(path)
        elif shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", str(path)])
        else:
            QMessageBox.information(self, "Data folder", str(path))
