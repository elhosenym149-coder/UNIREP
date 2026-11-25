"""Optional PySide6 desktop front end. Analysis runs off the UI thread."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from unirep.core.models import AnalysisJob, AnalysisTarget
from unirep.core.runner import AnalysisRunner
from unirep.cli import build_registry


def main(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt
        from PySide6.QtWidgets import (
            QApplication, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
            QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
            QPushButton, QVBoxLayout, QWidget
        )
    except ImportError as exc:
        raise RuntimeError("Desktop UI requires: pip install '.[desktop]'") from exc

    class Worker(QObject):
        finished = Signal(object)
        failed = Signal(str)

        def __init__(self, target: AnalysisTarget, engines: list[str]):
            super().__init__()
            self.target = target
            self.engines = engines

        @Slot()
        def run(self):
            try:
                job = AnalysisRunner(build_registry()).run(
                    AnalysisJob(target=self.target, requested_engines=self.engines)
                )
                self.finished.emit(job.to_dict())
            except Exception as exc:
                self.failed.emit(f"{type(exc).__name__}: {exc}")

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("UNIREP / Reforge")
            self.resize(1080, 720)
            self.thread = None
            self.worker = None

            root = QWidget()
            layout = QVBoxLayout(root)
            layout.setContentsMargins(24, 22, 24, 22)
            layout.setSpacing(14)

            title = QLabel("REFORGE")
            title.setObjectName("title")
            subtitle = QLabel("Software analysis workspace · read-only by default")
            subtitle.setObjectName("subtitle")
            layout.addWidget(title)
            layout.addWidget(subtitle)

            target_row = QHBoxLayout()
            self.target = QLineEdit()
            self.target.setPlaceholderText("Choose a local file or project folder…")
            choose_file = QPushButton("Choose file")
            choose_folder = QPushButton("Choose folder")
            choose_file.clicked.connect(self.choose_file)
            choose_folder.clicked.connect(self.choose_folder)
            target_row.addWidget(self.target, 1)
            target_row.addWidget(choose_file)
            target_row.addWidget(choose_folder)
            layout.addLayout(target_row)

            layout.addWidget(QLabel("Analysis engines"))
            self.engine_list = QListWidget()
            self.engine_list.setMaximumHeight(190)
            for engine in build_registry().list():
                if engine["name"] == "web_browser":
                    continue
                item = QListWidgetItem(f"{engine['name']} — {engine['description']}")
                item.setData(256, engine["name"])
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked)
                self.engine_list.addItem(item)
            layout.addWidget(self.engine_list)

            output_row = QHBoxLayout()
            self.output = QLineEdit("reports/analysis.json")
            output_row.addWidget(QLabel("Report path"))
            output_row.addWidget(self.output, 1)
            layout.addLayout(output_row)

            actions = QHBoxLayout()
            self.run_button = QPushButton("Run analysis")
            self.run_button.setObjectName("primary")
            self.status = QLabel("Ready")
            actions.addWidget(self.run_button)
            actions.addWidget(self.status, 1)
            layout.addLayout(actions)
            self.run_button.clicked.connect(self.start_analysis)

            layout.addWidget(QLabel("Results"))
            self.results = QPlainTextEdit()
            self.results.setReadOnly(True)
            self.results.setPlaceholderText("Analysis results and warnings will appear here.")
            layout.addWidget(self.results, 1)
            self.setCentralWidget(root)
            self.setStyleSheet("""
                QMainWindow, QWidget { background: #11151b; color: #e7edf5; }
                QLabel#title { color: #f2c14e; font-size: 30px; font-weight: 800; letter-spacing: 3px; }
                QLabel#subtitle { color: #8f9baa; font-size: 12px; }
                QLineEdit, QListWidget, QPlainTextEdit {
                    background: #1a2029; border: 1px solid #303a48; border-radius: 8px;
                    padding: 9px; color: #e7edf5; selection-background-color: #566b85;
                }
                QPushButton { background: #273241; border: 1px solid #3b4859; border-radius: 8px; padding: 10px 14px; }
                QPushButton:hover { background: #344357; }
                QPushButton#primary { background: #d6a93c; color: #15191f; font-weight: 700; border: 0; }
                QPushButton#primary:disabled { background: #625631; color: #a6a092; }
            """)

        def choose_file(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select software package")
            if path:
                self.target.setText(path)

        def choose_folder(self):
            path = QFileDialog.getExistingDirectory(self, "Select project folder")
            if path:
                self.target.setText(path)

        def start_analysis(self):
            raw = self.target.text().strip()
            path = Path(raw).expanduser()
            if not raw or not path.exists():
                QMessageBox.warning(self, "Target required", "Choose an existing file or folder first.")
                return
            kind = "folder" if path.is_dir() else "file"
            engines = [
                self.engine_list.item(i).data(256)
                for i in range(self.engine_list.count())
                if self.engine_list.item(i).checkState() == Qt.CheckState.Checked
            ]
            self.run_button.setEnabled(False)
            self.status.setText("Analyzing…")
            self.results.clear()
            self.thread = QThread()
            self.worker = Worker(AnalysisTarget(str(path), kind), engines)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.on_finished)
            self.worker.failed.connect(self.on_failed)
            self.worker.finished.connect(self.thread.quit)
            self.worker.failed.connect(self.thread.quit)
            self.thread.finished.connect(self.cleanup)
            self.thread.start()

        def on_finished(self, report):
            output = Path(self.output.text()).expanduser()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            self.status.setText(f"Completed: {report['status']}")
            self.results.setPlainText(json.dumps(report, indent=2, ensure_ascii=False))
            self.run_button.setEnabled(True)

        def on_failed(self, message):
            self.status.setText("Failed")
            self.results.setPlainText(message)
            self.run_button.setEnabled(True)

        def cleanup(self):
            self.worker = None
            self.thread = None

    app = QApplication(argv if argv is not None else sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
