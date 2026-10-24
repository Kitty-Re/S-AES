from PySide6.QtWidgets import QHBoxLayout

from ...core import expand_words, trace_block
from ...services.formats import parse_bits
from ..widgets import Card, Output, Page, Table, actions, bits_input, button, field, label


class BinaryPage(Page):
    def __init__(self):
        super().__init__("LEVEL 01 / BASIC", "二进制加解密", "16 位分组与 16 位密钥。查看每一步的位串、半字节矩阵和扩展密钥。")
        inputs = Card("输入数据")
        self.block = bits_input(title="16 位输入分组")
        self.key = bits_input(title="16 位主密钥")
        row = QHBoxLayout()
        row.addLayout(field("明文 / 密文分组 · 16 bit", self.block), 1)
        row.addLayout(field("主密钥 · 16 bit", self.key), 1)
        inputs.body.addLayout(row)
        self.encrypt_button = button("加密", lambda: self.calculate(False), True)
        self.decrypt_button = button("解密", lambda: self.calculate(True))
        self.example_button = button("填入示例", self.example)
        inputs.body.addLayout(actions(self.encrypt_button, self.decrypt_button, self.example_button))
        self.body.addWidget(inputs)
        self.output = Output()
        self.body.addWidget(self.output)
        self.key_summary = label("扩展密钥将在运算后显示。")
        self.trace = Table(("步骤", "状态 · 二进制", "十六进制", "状态矩阵"), 285)
        details = Card("计算过程")
        details.body.addWidget(self.key_summary)
        details.body.addWidget(self.trace)
        self.body.addWidget(details)
        self.block.textChanged.connect(self.clear)
        self.key.textChanged.connect(self.clear)
        self.block.returnPressed.connect(lambda: self.calculate(False))
        self.key.returnPressed.connect(lambda: self.calculate(False))
        self.finish_layout()

    def clear(self):
        self.output.clear()
        self.trace.setRowCount(0)
        self.key_summary.setText("扩展密钥将在运算后显示。")

    def example(self):
        self.block.setText(f"{0xD728:016b}")
        self.key.setText(f"{0x4AF5:016b}")
        self.calculate(False)

    def calculate(self, decrypt=False):
        self.clear()

        def operation():
            block, key = parse_bits(self.block.text()), parse_bits(self.key.text(), name="密钥")
            result = trace_block(block, key, decrypt)
            self.output.set_value(f"{result.output:016b}", f"HEX  {result.output:04X}  ·  16 bit", "解密结果" if decrypt else "加密结果")
            words = " ".join(f"{word:02X}" for word in expand_words(key))
            self.key_summary.setText("K0 / K1 / K2  =  " + " / ".join(f"{value:04X}" for value in result.round_keys) + f"    ·    w0…w5  =  {words}")
            self.trace.set_rows((step.name, f"{step.value:016b}", f"{step.value:04X}", step.detail) for step in result.steps)
        self.guard(operation)
