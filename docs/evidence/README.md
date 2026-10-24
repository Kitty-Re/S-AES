# 实验材料索引

本组按本地实验、组间交叉验证和界面截图整理了全部材料。`results` 保存算法实验记录，`cross-test` 保存他组原包和本组交叉结果，`screenshots` 保存实际 Qt 窗口截图。另一组数据的 119 个用例、220 行结果全部通过。

## 测试与本地参考

| 文件 | 内容 |
|---|---|
| [summary.json](results/summary.json) | 软件版本、测试汇总、实验结果与教材文件哈希，不含个人路径或硬件标识 |
| [unittest.txt](results/unittest.txt) | 56 项完整测试原始输出 |
| [binary-trace.json](results/binary-trace.json) | A749 / 2D55 的轮密钥与逐步状态 |
| [local-vectors.csv](results/local-vectors.csv) | 本地生成 8 条 16 位向量，供交换工具自测 |
| [independent-reference.csv](results/independent-reference.csv) | 同 8 条向量的本组算法与独立参考对照 |
| [ascii.json](results/ascii.json) | ASCII 样例、填充、密文及恢复结果 |
| [multiple.json](results/multiple.json) | 双重与两种三重的密钥、密文、恢复结果 |

## 他组交叉验证

| 文件 | 内容 |
|---|---|
| [原始压缩包](cross-test/S-AES-cross-test-20261024.zip) | 另一组提供的完整数据包，按原字节保存 |
| [原始清单](cross-test/peer-original/manifest.sha256) | 13 份原始文件的 SHA-256 |
| [peer-vectors-import.csv](cross-test/peer-vectors-import.csv) | 64 组基础数据，保留原位串及行顺序 |
| [basic-cross-results.csv](cross-test/basic-cross-results.csv) | 64 组实际密文、恢复明文、独立参考与轮密钥一致性 |
| [cross-test-results.csv](cross-test/cross-test-results.csv) | 原结果模板 220 行完整回填，全部 PASS |
| [cross-test-summary.json](cross-test/cross-test-summary.json) | 8 类测试计数、来源哈希、MITM 散列及完成状态 |
| [cross-test-details.json](cross-test/cross-test-details.json) | 多重阶段输出、MITM 统计及篡改逐块差异 |
| [M001-candidates.txt](cross-test/M001-candidates.txt) | 单对数据的完整 66,009 个候选，规范 LF 文本 |
| [M002-candidates.txt](cross-test/M002-candidates.txt) | 三对数据的唯一候选 1234ABCD |
| [ui-evidence.json](cross-test/ui-evidence.json) | 真实 Qt 按钮导入后，全部 64 行加密与解密显示核验 |

本组将对方完整原包保存在 ZIP 中，算法输入和清单保存在 `cross-test/peer-original/`，正式实验结果单独存放。对方说明、原始结果表和自检记录通过 ZIP 原样归档，详细结论见[交叉测试报告](../cross-test-record.md)。

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
| [11-peer-cross-top.png](screenshots/11-peer-cross-top.png) | 他组 64/64 通过，首批向量及双向结果 |
| [12-peer-cross-bottom.png](screenshots/12-peer-cross-bottom.png) | 同一文件末批向量及双向结果 |

六个主要页面另有 `-compact.png` 同名文件，记录 960×640 小窗口布局。每张图片保存整个应用窗口；长表格可滚动，完整数据以 CSV / JSON 为准。

## 复现

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe tools/verify_project.py
.\.venv\Scripts\python.exe tools/verify_cross_test.py
.\.venv\Scripts\python.exe tools/capture_screenshots.py
$env:QT_SCALE_FACTOR = '1.5'
.\.venv\Scripts\python.exe tools/gui_probe.py
$env:QT_SCALE_FACTOR = '2'
.\.venv\Scripts\python.exe tools/gui_probe.py
Remove-Item Env:QT_SCALE_FACTOR
```

复现实验会更新本组生成的记录，原始数据包和算法输入保持不变。本文所列计时来自本次实验，重复运行时可根据输出核对实际耗时。参考资料见 [reference](../reference/README.md)，他组数据与结果说明见 [cross-test/README.md](cross-test/README.md)。
