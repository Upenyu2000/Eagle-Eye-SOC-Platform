from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from eagle_eye.paths import resource_path
from eagle_eye.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Eagle Eye")
    app.setOrganizationName("Upenyu Hlangabeza")
    style_path = resource_path("eagle_eye", "assets", "styles.qss")
    if style_path.exists():
        app.setStyleSheet(style_path.read_text(encoding="utf-8"))
    window = MainWindow()
    window.show()
    return app.exec()
