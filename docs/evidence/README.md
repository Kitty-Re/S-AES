# 实验材料索引

所有数值由程序实际运行得到。`results` 为脚本记录，`screenshots` 为真实 Qt 窗口截图；二者在不同次运行中计时，候选和密文应一致，耗时可不同。组间交叉测试按用户要求暂不进行。

## 测试与本地参考

| 文件 | 内容 |
|---|---|
| [summary.json](results/summary.json) | 软件版本、测试汇总、实验结果与教材文件哈希，不含个人路径或硬件标识 |
| [unittest.txt](results/unittest.txt) | 49 项完整测试原始输出 |
| [binary-trace.json](results/binary-trace.json) | A749 / 2D55 的轮密钥与逐步状态 |
| [local-vectors.csv](results/local-vectors.csv) | 本地生成 8 条 16 位向量，供交换工具自测 |
| [independent-reference.csv](results/independent-reference.csv) | 同 8 条向量的生产实现与独立参考对照 |
| [ascii.json](results/ascii.json) | ASCII 样例、填充、密文及恢复结果 |
| [multiple.json](results/multiple.json) | 双重与两种三重的密钥、密文、恢复结果 |

## 中间相遇

| 文件 | 内容 |
|---|---|
| [mitm-known-pairs.csv](results/mitm-known-pairs.csv) | 三组双重 EE 已知明密文对 |
| [mitm.json](results/mitm.json) | 1、2、3 组已知对的完整搜索统计 |
| [mitm-candidates-1.csv](results/mitm-candidates-1.csv) | 单组 65,470 个候选，约 6 MB |
| [mitm-candidates-2.csv](results/mitm-candidates-2.csv) | 两组唯一候选，含完成状态及耗时 |
| [mitm-candidates-3.csv](results/mitm-candidates-3.csv) | 三组唯一候选，含完成状态及耗时 |

候选 CSV 的位串使用文本保存以保留前导零；电子表格软件打开时应把位串列指定为文本，避免自动转为数值或科学计数法。

## CBC

| 文件 | 内容 |
|---|---|
| [cbc.json](results/cbc.json) | 消息、密钥、IV、密文、恢复与篡改结果 |
| [cbc-packet.json](results/cbc-packet.json) | 可直接从界面导入的 IV / 密文数据包，不包含密钥 |
| [cbc-tamper.csv](results/cbc-tamper.csv) | 9 个分组逐组的原值、改后值、异或差与改变位数 |

## 窗口截图

| 文件 | 内容 |
|---|---|
| [01-binary.png](screenshots/01-binary.png) | 基本加密、轮密钥和中间状态 |
| [02-ascii.png](screenshots/02-ascii.png) | ASCII 加解密及字节视图 |
| [03-double.png](screenshots/03-double.png) | 双重 EE 及各级结果 |
| [04-mitm.png](screenshots/04-mitm.png) | 三组已知对的完整攻击与唯一候选 |
| [05-cbc.png](screenshots/05-cbc.png) | CBC 参数、密文与恢复消息 |
| [06-checks-local.png](screenshots/06-checks-local.png) | 自检及本地 CSV，未使用他组数据 |
| [07-triple32.png](screenshots/07-triple32.png) | 32 位两密钥三重 EEE |
| [08-triple48.png](screenshots/08-triple48.png) | 48 位三密钥三重 EEE |
| [09-cbc-tamper.png](screenshots/09-cbc-tamper.png) | 滚动到篡改实验，展示差异表 |
| [10-binary-scale-1_5.png](screenshots/10-binary-scale-1_5.png) | 150% 缩放 |
| [10-binary-scale-2.png](screenshots/10-binary-scale-2.png) | 200% 缩放 |

六个主要页面另有 `-compact.png` 同名文件，记录 960×640 小窗口布局。每张图片保存整个应用窗口；长表格可滚动，完整数据以 CSV / JSON 为准。

## 复现

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe tools/verify_project.py
.\.venv\Scripts\python.exe tools/capture_screenshots.py
$env:QT_SCALE_FACTOR = '1.5'
.\.venv\Scripts\python.exe tools/gui_probe.py
$env:QT_SCALE_FACTOR = '2'
.\.venv\Scripts\python.exe tools/gui_probe.py
Remove-Item Env:QT_SCALE_FACTOR
```

重跑会覆盖对应生成材料，时间会变化；文档中的交付时历史计时不会自动改写。教材获取及本地副本说明见 [reference](../reference/README.md)。组间材料目录说明见 [cross-test/README.md](cross-test/README.md)。
