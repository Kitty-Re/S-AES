from PySide6.QtCore import QSize, QTimer, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QFrame, QHBoxLayout, QListWidget, QMainWindow, QScrollArea, QStackedWidget, QVBoxLayout, QWidget

from .pages.attack import AttackPage
from .pages.binary import BinaryPage
from .pages.cbc import CbcPage
from .pages.multiple import MultiplePage
from .pages.testing import TestingPage
from .pages.text import TextPage
from .tasks import TaskPanel
from .widgets import label


def application_icon():
    pixmap = QPixmap(64, 64)
    pixmap.fill(QColor("#142D34"))
    painter = QPainter(pixmap)
    for x, y, color in ((12, 12, "#87CEC0"), (35, 12, "#168077"), (12, 35, "#168077"), (35, 35, "#E4F1EC")):
        painter.fillRect(x, y, 17, 17, QColor(color))
    painter.end()
    return QIcon(pixmap)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-AES 实验室 · 信息安全导论第二次作业")
        self.setWindowIcon(application_icon())
        self.resize(1180, 900)
        self.setMinimumSize(960, 640)
        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(210)
        menu = QVBoxLayout(sidebar)
        menu.setContentsMargins(20, 30, 20, 24)
        menu.setSpacing(14)
        menu.addWidget(label("S-AES\n实验室", "brand"))
        menu.addWidget(label("信息安全导论 / 作业 02", "sidebarHint"))
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setAccessibleName("功能导航")
        self.navigation.addItems(("01  二进制加解密", "02  ASCII 文本", "03  双重与三重", "04  中间相遇攻击", "05  CBC 与篡改", "06  自检与交叉测试"))
        self.navigation.setSpacing(5)
        self.navigation.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        for index in range(self.navigation.count()):
            self.navigation.item(index).setSizeHint(QSize(160, 46))
        menu.addWidget(self.navigation, 1)
        menu.addWidget(label("16 bit BLOCK\n16 bit KEY\n\n教材附录 D · 两轮 S-AES", "sidebarHint"))
        layout.addWidget(sidebar)
        self.stack = QStackedWidget()
        self.pages = [BinaryPage(), TextPage(), MultiplePage(), AttackPage(), CbcPage(), TestingPage()]
        for page in self.pages:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            self.stack.addWidget(scroll)
        layout.addWidget(self.stack, 1)
        self.navigation.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.navigation.setCurrentRow(0)
        self.setCentralWidget(root)

    def closeEvent(self, event):
        active = [task for task in self.findChildren(TaskPanel) if task.running]
        if active:
            for task in active:
                task.cancel()
            event.ignore()
            self.statusBar().showMessage("正在停止后台计算…")
            QTimer.singleShot(30, self.close)
        else:
            event.accept()
