# 组间交叉测试材料

本组于 2026-10-24 使用程序 1.1.0 验证了另一组提供的数据，119 个用例对应的 220 行结果全部为 PASS。详细方法与结论见[交叉测试报告](../../cross-test-record.md)。

## 原始材料

- [S-AES-cross-test-20261024.zip](S-AES-cross-test-20261024.zip)：原始 ZIP，SHA-256 为 `b57ef988afaa6f38a4e14fefb01ab25917646be177980e7019e2cff2fe60209d`。
- [peer-original/manifest.sha256](peer-original/manifest.sha256)：13 个文件的传输完整性清单，全部核验一致。
- `peer-original/`：算法向量与完整性清单，Git 禁用换行转换，保持原始字节。
- 完整 ZIP：包含全部 14 个原始文件，发送方说明、原始结果表和自检记录均按原样归档，验证脚本直接从 ZIP 读取这三份材料。

本组的正式交叉验证结果保存在下表所列文件中。每一项实际值均由本组程序计算，并与对方给出的期望值逐项比较。

## 本组生成材料

| 文件 | 内容 |
|---|---|
| [peer-vectors-import.csv](peer-vectors-import.csv) | 原 64 组数据的三列二进制适配文件 |
| [basic-cross-results.csv](basic-cross-results.csv) | 64 组双向结果、参考密文、轮密钥一致性 |
| [cross-test-results.csv](cross-test-results.csv) | 原 220 行模板完整回填，全部 PASS |
| [cross-test-summary.json](cross-test-summary.json) | 日期、程序、来源哈希、8 类计数、耗时和 MITM 完成状态 |
| [cross-test-details.json](cross-test-details.json) | 多重各级输出、候选集合散列及篡改原始分组 |
| [M001-candidates.txt](M001-candidates.txt) | 单对的完整 66,009 个候选，按对方规则规范编码 |
| [M002-candidates.txt](M002-candidates.txt) | 三对的唯一候选 1234ABCD |
| [ui-evidence.json](ui-evidence.json) | Qt 实际按钮导入后，全部 64 行的双向显示核验 |

截图见[首部](../screenshots/11-peer-cross-top.png)和[末部](../screenshots/12-peer-cross-bottom.png)。本地自产 8 条样例仍在 [results/local-vectors.csv](../results/local-vectors.csv)，与本目录他组输入分开保存。

在项目根目录执行 `.\.venv\Scripts\python.exe tools/verify_cross_test.py` 可复现全部结果。脚本读取原始输入，更新本组实验记录，并保留完整数据包和源文件的字节内容。
