from PySide6.QtWidgets import QFileDialog, QTableWidgetItem

from ...services.attack import meet_in_the_middle
from ...services.exchange import write_csv
from ...services.formats import parse_bits
from ...services.multiple import encrypt_multiple
from ..tasks import TaskPanel
from ..widgets import Card, Page, Table, actions, button, label


class AttackPage(Page):
    def __init__(self):
        super().__init__("LEVEL 04 / MEET IN THE MIDDLE", "中间相遇攻击", "输入同一双重密钥生成的一组或多组明密文对。搜索覆盖两侧完整的 16 位密钥空间。")
        card = Card("已知明密文对")
        self.pairs = Table(("明文 · 16 bit", "双重加密密文 · 16 bit"), 150, True)
        card.body.addWidget(self.pairs)
        self.add_button = button("添加一行", self.add_pair)
        self.remove_button = button("删除选中", self.remove_pair)
        self.example_button = button("填入三组示例", self.example)
        card.body.addLayout(actions(self.add_button, self.remove_button, self.example_button))
        card.body.addWidget(label("示例密钥 K1=4AF5、K2=3A94。单组数据通常保留多个候选；增加已知对可进一步筛选。"))
        self.task = TaskPanel("开始完整搜索")
        self.task.start_button.clicked.connect(self.start)
        self.task.succeeded.connect(self.show_result)
        self.task.idle.connect(lambda: self.lock_inputs(False))
        card.body.addWidget(self.task)
        self.body.addWidget(card)
        result = Card("候选密钥")
        self.summary = label("等待搜索", "success")
        self.detail = label("")
        self.candidates = Table(("K1 · HEX", "K2 · HEX", "组合密钥 · 32 bit"), 225)
        self.export_button = button("导出完整候选 CSV", self.export)
        self.export_button.setEnabled(False)
        result.body.addWidget(self.summary)
        result.body.addWidget(self.detail)
        result.body.addWidget(self.candidates)
        result.body.addLayout(actions(self.export_button))
        self.body.addWidget(result)
        self.result = None
        self.pairs.itemChanged.connect(self.clear)
        self.example()
        self.finish_layout()

    def clear(self):
        self.result = None
        self.summary.setText("等待搜索")
        self.detail.clear()
        self.candidates.setRowCount(0)
        self.export_button.setEnabled(False)

    def example(self):
        self.pairs.set_rows((f"{plain:016b}", f"{encrypt_multiple(plain, 0x4AF53A94):016b}") for plain in (0xD728, 0x1234, 0xABCD))
        self.clear()

    def add_pair(self):
        index = self.pairs.rowCount()
        self.pairs.insertRow(index)
        for column in range(2):
            self.pairs.setItem(index, column, QTableWidgetItem(""))
        self.clear()

    def remove_pair(self):
        for index in sorted({item.row() for item in self.pairs.selectedItems()}, reverse=True):
            self.pairs.removeRow(index)
        self.clear()

    def lock_inputs(self, locked):
        for item in (self.pairs, self.add_button, self.remove_button, self.example_button):
            item.setEnabled(not locked)

    def start(self):
        if self.task.running:
            return
        self.clear()

        def operation():
            pairs = []
            for row in range(self.pairs.rowCount()):
                cells = [self.pairs.item(row, col) for col in range(2)]
                pairs.append(tuple(parse_bits(cell.text() if cell else "", name=f"第 {row + 1} 行") for cell in cells))
            if not pairs:
                raise ValueError("至少添加一组明密文对。")
            self.lock_inputs(True)
            self.task.start(lambda **kwargs: meet_in_the_middle(pairs, **kwargs))
        self.guard(operation)

    def show_result(self, result):
        self.result = result
        status = "完整搜索" if result.completed else "搜索未完成，以下仅为已检查范围内的候选"
        self.summary.setText(f"{status} · 候选 {len(result.candidates):,} 个")
        self.detail.setText(f"首组匹配 {result.first_pair_matches:,} 对 · 不同中间值 {result.distinct_intermediates:,} 个 · "
                            f"检查 {result.checked:,} / {result.total:,}。表格最多显示前 200 对，CSV 保存全部候选。")
        self.candidates.set_rows((f"{first:04X}", f"{second:04X}", f"{first:016b}{second:016b}") for first, second in result.candidates[:200])
        self.export_button.setEnabled(True)

    def export(self):
        if self.result is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出候选密钥", "mitm-candidates.csv", "CSV (*.csv)")
        if not path:
            return
        result = self.result
        headers = ("key1", "key2", "combined_key", "completed", "checked", "elapsed_seconds", "known_pairs")
        # 没有候选时也写一条元数据行，保留完整/取消状态。
        rows = [(f"{a:016b}", f"{b:016b}", f"{a:016b}{b:016b}", result.completed, result.checked, f"{result.elapsed:.9f}", len(result.pairs)) for a, b in result.candidates]
        if not rows:
            rows = [("", "", "", result.completed, result.checked, f"{result.elapsed:.9f}", len(result.pairs))]
        self.guard(lambda: write_csv(path, headers, rows))
