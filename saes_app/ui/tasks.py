from threading import Event

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import QProgressBar, QVBoxLayout, QWidget

from .widgets import actions, button, label


class Worker(QThread):
    progress = Signal(int, int)

    def __init__(self, function, parent=None):
        super().__init__(parent)
        self.function = function
        self.cancel_event = Event()
        self.result = None
        self.error = ""

    def run(self):
        try:
            self.result = self.function(progress=self.progress.emit, cancel=self.cancel_event)
        except Exception as issue:
            self.error = str(issue) or type(issue).__name__


class TaskPanel(QWidget):
    succeeded = Signal(object)
    failed = Signal(str)
    idle = Signal()

    def __init__(self, title):
        super().__init__()
        self.worker = None
        self.start_button = button(title, primary=True)
        self.cancel_button = button("取消", self.cancel)
        self.cancel_button.setEnabled(False)
        self.status = label("就绪")
        self.progress = QProgressBar()
        self.progress.setRange(0, 131072)
        self.progress.setTextVisible(False)
        self.progress.setValue(0)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(actions(self.start_button, self.cancel_button))
        layout.addWidget(self.progress)
        layout.addWidget(self.status)

    @property
    def running(self):
        return self.worker is not None

    def start(self, function):
        if self.running:
            return False
        self.worker = Worker(function, self)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.finish)
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.setText("计算中…")
        self.progress.setValue(0)
        self.worker.start()
        return True

    @Slot(int, int)
    def update_progress(self, checked, total):
        self.progress.setRange(0, max(1, total))
        self.progress.setValue(checked)
        self.status.setText(f"已检查 {checked:,} / {total:,}")

    @Slot()
    def cancel(self):
        if self.worker:
            self.worker.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status.setText("正在取消…")

    @Slot()
    def finish(self):
        worker, self.worker = self.worker, None
        result, error = worker.result, worker.error
        worker.deleteLater()
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        if error:
            self.status.setText("任务失败：" + error)
            self.failed.emit(error)
        elif result is not None:
            state = "已完成" if result.completed else "未完成 / 已取消"
            self.status.setText(f"{state} · 计算耗时 {result.elapsed * 1000:.3f} ms")
            self.succeeded.emit(result)
        self.idle.emit()
