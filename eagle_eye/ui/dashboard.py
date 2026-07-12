from __future__ import annotations

from PySide6.QtWidgets import QAbstractItemView, QGridLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from eagle_eye.database import Database
from eagle_eye.models import Incident
from eagle_eye.ui.common import PageHeader, StatCard


class DashboardPage(QWidget):
    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)
        root.addWidget(PageHeader("Command Centre", "Unified visibility across authentication, identity, phishing, cloud and automation workflows."))
        cards = QGridLayout()
        cards.setSpacing(12)
        self.total_card = StatCard("Total incidents")
        self.open_card = StatCard("Open incidents")
        self.high_card = StatCard("High / critical")
        self.module_card = StatCard("Modules represented")
        for index, card in enumerate((self.total_card, self.open_card, self.high_card, self.module_card)):
            cards.addWidget(card, 0, index)
        root.addLayout(cards)
        action_row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        demo = QPushButton("Load demo incidents")
        demo.setObjectName("SecondaryButton")
        demo.clicked.connect(self.load_demo_incidents)
        close_button = QPushButton("Close selected incident")
        close_button.setObjectName("SecondaryButton")
        close_button.clicked.connect(self.close_selected_incident)
        action_row.addWidget(refresh)
        action_row.addWidget(demo)
        action_row.addWidget(close_button)
        action_row.addStretch(1)
        root.addLayout(action_row)
        title = QLabel("Recent incidents")
        title.setStyleSheet("font-size: 13pt; font-weight: 700;")
        root.addWidget(title)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Module", "Severity", "Status", "Title", "Created"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self.table, 1)
        self.refresh()

    def refresh(self) -> None:
        stats = self.database.dashboard_stats()
        self.total_card.set_value(stats["total"])
        self.open_card.set_value(stats["open"])
        self.high_card.set_value(stats["high"])
        self.module_card.set_value(stats["modules"])
        rows = self.database.list_incidents(limit=50)
        self.table.setRowCount(len(rows))
        for row_index, item in enumerate(rows):
            values = [item["id"], item["module"], item["severity"].upper(), item["status"], item["title"], item["created_at"]]
            for column, value in enumerate(values):
                self.table.setItem(row_index, column, QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    def load_demo_incidents(self) -> None:
        examples = [
            Incident(module="SIEM", title="Repeated authentication failures", severity="high", description="Synthetic demo incident from the SIEM workspace."),
            Incident(module="Active Directory", title="RC4 Kerberos ticket activity", severity="medium", description="Synthetic demo incident from the AD workspace."),
            Incident(module="Phishing", title="DMARC failure and Reply-To mismatch", severity="high", description="Synthetic demo phishing incident."),
            Incident(module="Azure", title="Anonymous blob access enabled", severity="high", description="Synthetic cloud-security incident."),
        ]
        for incident in examples:
            self.database.add_incident(incident)
        self.database.log_activity("Dashboard", "Loaded demo incidents")
        self.refresh()

    def close_selected_incident(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        self.database.update_incident_status(int(item.text()), "Closed")
        self.database.log_activity("Dashboard", "Closed incident", item.text())
        self.refresh()
