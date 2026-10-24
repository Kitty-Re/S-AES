import os
from pathlib import Path

from PySide6.QtGui import QFont, QFontDatabase


def apply_theme(app):
    if os.name == "nt" and app.platformName() == "offscreen":
        font_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for filename in ("msyh.ttc", "msyhbd.ttc", "consola.ttf"):
            if (font_dir / filename).is_file():
                QFontDatabase.addApplicationFont(str(font_dir / filename))
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet("""
    QWidget { color: #20343E; }
    QMainWindow, QScrollArea, QWidget#page { background: #F2F5F4; }
    QScrollArea { border: none; }
    QFrame#sidebar { background: #142D34; }
    QLabel#brand { color: #FFFFFF; font-size: 24px; font-weight: 700; }
    QLabel#sidebarHint { color: #9CB6BC; }
    QLabel#eyebrow { color: #168077; font-size: 11px; font-weight: 700; }
    QLabel#title { font-size: 27px; font-weight: 700; }
    QLabel#subtitle, QLabel#hint { color: #60747B; }
    QLabel#section { font-size: 15px; font-weight: 600; }
    QLabel#error { color: #B33A2E; }
    QLabel#success { color: #087A6E; font-weight: 600; }
    QLabel#hero { color: #087A6E; font-family: Consolas; font-size: 22px; font-weight: 700; }
    QFrame#card { background: white; border: 1px solid #DEE7E3; border-radius: 12px; }
    QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
        background: #F3F6F5; border: 1px solid #DCE5E1; border-radius: 6px;
        padding: 8px; selection-background-color: #168077;
    }
    QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #168077; }
    QLineEdit:disabled, QPlainTextEdit:disabled { color: #87958F; }
    QPushButton { background: #EAF0EE; border: 1px solid transparent; border-radius: 6px;
        padding: 8px 14px; min-height: 20px; }
    QPushButton:hover { background: #DBE9E4; }
    QPushButton:pressed { background: #C9DED6; }
    QPushButton:focus { border: 1px solid #168077; }
    QPushButton[primary="true"] { background: #087A6E; color: white; }
    QPushButton[primary="true"]:hover { background: #06685F; }
    QPushButton:disabled { color: #96A49E; background: #F0F3F1; }
    QComboBox { padding-right: 24px; }
    QComboBox::drop-down { border: none; width: 22px; }
    QComboBox QAbstractItemView { background: white; selection-background-color: #DCEEE7; selection-color: #20343E; }
    QListWidget#navigation { background: transparent; border: none; outline: none; }
    QListWidget#navigation::item { color: #C3D5D7; padding: 12px 13px; border-radius: 7px; }
    QListWidget#navigation::item:hover { background: #203E45; }
    QListWidget#navigation::item:selected { color: #FFFFFF; background: #276058; font-weight: 600; }
    QTableWidget { background: white; border: 1px solid #E1E8E4; border-radius: 5px;
        gridline-color: #EDF1EF; selection-background-color: #E0F0E9; selection-color: #20343E; }
    QTableWidget::item { padding: 5px 8px; }
    QHeaderView::section { background: #F1F5F3; color: #567068; border: none;
        border-bottom: 1px solid #DFE7E2; padding: 9px 8px; font-weight: 600; }
    QCheckBox { spacing: 8px; padding: 4px 0; }
    QProgressBar { border: none; background: #E3ECE7; border-radius: 3px; min-height: 7px; max-height: 7px; }
    QProgressBar::chunk { background: #168077; border-radius: 3px; }
    QScrollBar:vertical { background: #EDF2EF; width: 10px; }
    QScrollBar::handle:vertical { background: #B9CEC3; border-radius: 4px; min-height: 30px; }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    QScrollBar:horizontal { background: #EDF2EF; height: 10px; }
    QScrollBar::handle:horizontal { background: #B9CEC3; min-width: 30px; }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
    QToolTip { background: white; color: #20343E; border: 1px solid #C5D5CD; padding: 5px; }
    """)
