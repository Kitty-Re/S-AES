from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)


def label(text, name="hint"):
    item = QLabel(text)
    item.setObjectName(name)
    item.setWordWrap(True)
    item.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return item


def button(text, callback=None, primary=False):
    item = QPushButton(text)
    item.setProperty("primary", primary)
    if callback:
        item.clicked.connect(callback)
    return item


def actions(*items):
    row = QHBoxLayout()
    row.setSpacing(8)
    for item in items:
        row.addWidget(item)
    row.addStretch()
    return row


def field(title, widget):
    column = QVBoxLayout()
    column.setSpacing(6)
    column.addWidget(label(title))
    column.addWidget(widget)
    return column


def bits_input(width=16, value="", title="二进制输入"):
    item = QLineEdit(value)
    item.setAccessibleName(title)
    item.setPlaceholderText(f"{width} 位二进制，保留前导零")
    item.setFont(QFont("Consolas", 11))
    item.setMinimumHeight(25)
    item.setMaxLength(max(width + 16, 80))
    return item


def text_input(height=100, readonly=False):
    item = QPlainTextEdit()
    item.setMinimumHeight(height)
    item.setMaximumHeight(height + 30)
    item.setReadOnly(readonly)
    item.setFont(QFont("Consolas", 10))
    item.setTabChangesFocus(True)
    return item


class Card(QFrame):
    def __init__(self, title=""):
        super().__init__()
        self.setObjectName("card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 17, 20, 18)
        self.body.setSpacing(12)
        if title:
            self.body.addWidget(label(title, "section"))


class Table(QTableWidget):
    def __init__(self, headers, height=250, editable=False):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().hide()
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setMinimumSectionSize(90)
        self.setMinimumHeight(height)
        self.setMaximumHeight(height + 40)
        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        if not editable:
            self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setDefaultSectionSize(36)

    def set_rows(self, rows):
        self.setRowCount(0)
        for row in rows:
            index = self.rowCount()
            self.insertRow(index)
            for column, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.setItem(index, column, item)


class Page(QWidget):
    def __init__(self, eyebrow, title, description):
        super().__init__()
        self.setObjectName("page")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(28, 26, 28, 28)
        self.body.setSpacing(17)
        self.body.addWidget(label(eyebrow, "eyebrow"))
        self.body.addWidget(label(title, "title"))
        self.body.addWidget(label(description, "subtitle"))
        self.error = label("", "error")
        self.body.addWidget(self.error)
        self.error.hide()

    def guard(self, function):
        self.error.clear()
        self.error.hide()
        try:
            return function()
        except (ValueError, OSError, UnicodeError) as issue:
            self.show_error(str(issue))
            return None

    def show_error(self, message):
        self.error.setText(message)
        self.error.show()

    def finish_layout(self):
        self.body.addStretch()


class Output(Card):
    def __init__(self, title="运算结果"):
        super().__init__()
        self.title = label(title, "section")
        self.copy_button = button("复制结果", self.copy)
        row = QHBoxLayout()
        row.addWidget(self.title, 1)
        row.addWidget(self.copy_button)
        self.body.addLayout(row)
        self.value = label("等待运算", "hero")
        self.detail = label("")
        self.body.addWidget(self.value)
        self.body.addWidget(self.detail)
        self.copy_value = ""
        self.copy_button.setEnabled(False)

    def set_value(self, value, detail="", title="运算结果"):
        self.copy_value = value
        self.value.setText(value)
        self.detail.setText(detail)
        self.title.setText(title)
        self.copy_button.setEnabled(bool(value))

    def clear(self):
        self.copy_value = ""
        self.value.setText("等待运算")
        self.detail.clear()
        self.copy_button.setEnabled(False)

    def copy(self):
        QApplication.clipboard().setText(self.copy_value)
