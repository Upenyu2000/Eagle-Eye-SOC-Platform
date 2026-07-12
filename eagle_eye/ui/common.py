from __future__ import annotations

import json
from typing import Iterable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QFrame, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from eagle_eye.models import Finding

SEVERITY_COLOURS = {"informational": "#7aa2f7", "low": "#7dcfff", "medium": "#e0af68", "high": "#f7768e", "critical": "#ff3b5c"}


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 12)
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("PageSubtitle")
        subtitle_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)


class StatCard(QFrame):
    def __init__(self, label: str, value: str = "0") -> None:
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        label_widget = QLabel(label)
        label_widget.setObjectName("Muted")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")
        layout.addWidget(label_widget)
        layout.addWidget(self.value_label)

    def set_value(self, value: object) -> None:
        self.value_label.setText(str(value))


class FindingTable(QTableWidget):
    HEADERS = ["Severity", "Finding", "Description", "Evidence"]

    def __init__(self) -> None:
        super().__init__(0, len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.resizeSection(0, 100)
        header.resizeSection(1, 260)
        header.resizeSection(2, 420)
        self.findings: list[Finding] = []

    def set_findings(self, findings: Iterable[Finding]) -> None:
        self.findings = list(findings)
        self.setRowCount(len(self.findings))
        for row, finding in enumerate(self.findings):
            severity = QTableWidgetItem(finding.severity.upper())
            severity.setForeground(QColor(SEVERITY_COLOURS.get(finding.severity.lower(), "#ffffff")))
            severity.setData(Qt.ItemDataRole.UserRole, finding)
            self.setItem(row, 0, severity)
            self.setItem(row, 1, QTableWidgetItem(finding.title))
            self.setItem(row, 2, QTableWidgetItem(finding.description))
            self.setItem(row, 3, QTableWidgetItem(json.dumps(finding.evidence, ensure_ascii=False, default=str)))
        self.resizeRowsToContents()

    def selected_finding(self) -> Finding | None:
        row = self.currentRow()
        if row < 0 or row >= len(self.findings):
            return None
        return self.findings[row]


def horizontal_actions(*widgets: QWidget) -> QWidget:
    container = QWidget()
    layout = QHBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    for widget in widgets:
        layout.addWidget(widget)
    layout.addStretch(1)
    return container
