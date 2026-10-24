from PySide6.QtWidgets import QComboBox

from ...services.formats import parse_bits
from ...services.multiple import MODE_WIDTHS, multiple_trace, split_keys
from ..widgets import Card, Output, Page, Table, actions, bits_input, button, field, label


class MultiplePage(Page):
    def __init__(self):
        super().__init__("LEVEL 04 / MULTIPLE ENCRYPTION", "双重与三重加密", "组合密钥从左向右切分为 K1、K2、K3。双重采用 EE；两种三重模式均采用 EEE。")
        card = Card("选择模式")
        self.mode = QComboBox()
        self.mode.addItem("双重 EE · 32 位密钥", "double")
        self.mode.addItem("三重 EEE · 32 位密钥（K1 / K2 / K1）", "triple2")
        self.mode.addItem("三重 EEE · 48 位密钥（K1 / K2 / K3）", "triple3")
        self.block = bits_input(title="多重加密输入分组")
        self.key = bits_input(32, title="组合密钥")
        self.key.setMaxLength(80)
        self.key_label = label("组合密钥 · 32 bit")
        card.body.addWidget(self.mode)
        card.body.addLayout(field("明文 / 密文分组 · 16 bit", self.block))
        card.body.addWidget(self.key_label)
        card.body.addWidget(self.key)
        self.encrypt_button = button("加密", lambda: self.calculate(False), True)
        self.decrypt_button = button("解密", lambda: self.calculate(True))
        self.example_button = button("填入示例", self.example)
        card.body.addLayout(actions(self.encrypt_button, self.decrypt_button, self.example_button))
        self.body.addWidget(card)
        self.output = Output()
        self.body.addWidget(self.output)
        steps = Card("各级运算")
        self.table = Table(("级数", "操作密钥 HEX", "输入 HEX", "输出 HEX"), 175)
        steps.body.addWidget(self.table)
        self.body.addWidget(steps)
        self.mode.currentIndexChanged.connect(self.change_mode)
        self.key.textChanged.connect(self.clear)
        self.block.textChanged.connect(self.clear)
        self.finish_layout()

    def clear(self):
        self.output.clear()
        self.table.setRowCount(0)

    def change_mode(self):
        width = MODE_WIDTHS[self.mode.currentData()]
        self.key_label.setText(f"组合密钥 · {width} bit")
        self.key.setPlaceholderText(f"{width} 位二进制，保留前导零")
        self.clear()

    def example(self):
        self.block.setText(f"{0xD728:016b}")
        value = 0x4AF53A941234 if self.mode.currentData() == "triple3" else 0x4AF53A94
        self.key.setText(f"{value:0{MODE_WIDTHS[self.mode.currentData()]}b}")
        self.calculate(False)

    def calculate(self, decrypt=False):
        self.clear()

        def operation():
            mode = self.mode.currentData()
            block, key = parse_bits(self.block.text()), parse_bits(self.key.text(), MODE_WIDTHS[mode], "组合密钥")
            keys = split_keys(key, mode)
            keys = tuple(reversed(keys)) if decrypt else keys
            values = multiple_trace(block, key, mode, decrypt)
            self.output.set_value(f"{values[-1]:016b}", f"HEX  {values[-1]:04X}  ·  {len(keys)} 级运算", "解密结果" if decrypt else "加密结果")
            self.table.set_rows((i + 1, f"{subkey:04X}", f"{values[i]:04X}", f"{values[i + 1]:04X}") for i, subkey in enumerate(keys))
        self.guard(operation)
