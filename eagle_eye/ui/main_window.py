from __future__ import annotations

from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPushButton, QStackedWidget, QVBoxLayout, QWidget

from eagle_eye.database import Database
from eagle_eye.paths import resource_path
from eagle_eye.secrets import SecretStore
from eagle_eye.ui.analysis_pages import ActiveDirectoryPage, AzurePage, SiemPage
from eagle_eye.ui.automation_page import AutomationPage
from eagle_eye.ui.dashboard import DashboardPage
from eagle_eye.ui.phishing_page import PhishingPage
from eagle_eye.ui.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Eagle Eye — Unified SOC Platform")
        self.resize(1500, 920)
        self.setMinimumSize(1180, 760)
        self.setWindowIcon(QIcon(str(resource_path("eagle_eye", "assets", "eagle_eye.svg"))))
        self.database = Database()
        self.secrets = SecretStore()
        self.thread_pool = QThreadPool.globalInstance()
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(245)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 22, 16, 16)
        sidebar_layout.setSpacing(8)
        brand = QLabel("EAGLE EYE")
        brand.setObjectName("BrandTitle")
        subtitle = QLabel("UNIFIED SOC PLATFORM")
        subtitle.setObjectName("BrandSubtitle")
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(18)
        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(self.database)
        pages = [
            ("Command Centre", self.dashboard),
            ("SIEM Detection", SiemPage(self.database, self.thread_pool)),
            ("Active Directory", ActiveDirectoryPage(self.database, self.thread_pool)),
            ("Phishing Analysis", PhishingPage(self.database, self.secrets, self.thread_pool)),
            ("Azure Security", AzurePage(self.database, self.thread_pool)),
            ("SOC Automation", AutomationPage(self.database, self.secrets, self.thread_pool)),
            ("Settings", SettingsPage(self.database, self.secrets)),
        ]
        group = QButtonGroup(self)
        group.setExclusive(True)
        for index, (label, page) in enumerate(pages):
            self.stack.addWidget(page)
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, page_index=index: self.show_page(page_index))
            group.addButton(button)
            sidebar_layout.addWidget(button)
            if index == 0:
                button.setChecked(True)
        sidebar_layout.addStretch(1)
        scope = QLabel("Authorised environments only\nNo automated exploitation\nExternal actions require confirmation")
        scope.setObjectName("Muted")
        scope.setWordWrap(True)
        sidebar_layout.addWidget(scope)
        layout.addWidget(sidebar)
        layout.addWidget(self.stack, 1)
        self.statusBar().showMessage("Ready — local data is stored in the Eagle Eye application directory")
        refresh_action = QAction("Refresh dashboard", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.dashboard.refresh)
        self.addAction(refresh_action)

    def show_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.dashboard.refresh()

    def closeEvent(self, event) -> None:
        if self.thread_pool.activeThreadCount() > 0:
            answer = QMessageBox.question(self, "Background work running", "A background request is still running. Close Eagle Eye anyway?")
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        event.accept()
