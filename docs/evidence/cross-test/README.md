# 组间交叉测试材料

另一组数据由用户转交，本组程序 1.1.0 于 2026-10-24 完成全部 119 个用例、220 行结果验证，全部 PASS。详细方法与结论见[交叉测试报告](../../cross-test-record.md)。

## 原始材料

- [S-AES-cross-test-20261024.zip](S-AES-cross-test-20261024.zip)：原始 ZIP，SHA-256 为 `b57ef988afaa6f38a4e14fefb01ab25917646be177980e7019e2cff2fe60209d`。
- [peer-original/00_互测说明.md](peer-original/00_互测说明.md)：发送方约定及说明，原样保存。
- [peer-original/manifest.sha256](peer-original/manifest.sha256)：13 个文件的传输完整性清单，全部核验一致。
- `peer-original/`：14 个原始文件，包含原始向量、模板和发送方自检记录，Git 禁用该目录的换行转换以保留字节。

原包内的“待互测”“PENDING”等文字是发送方发包时的原始状态，不是本组当前结论。本组没有修改对方文件或冒称对方已经执行本组向量。

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

复现：在项目根目录执行 `.\.venv\Scripts\python.exe tools/verify_cross_test.py`。脚本保留全部原始文件，只覆盖本组生成材料。未自动向其他小组发送回填结果。
