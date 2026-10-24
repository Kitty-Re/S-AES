# 第 2 关：交叉测试状态记录

**当前状态：组间交叉测试按用户要求暂不进行。** 没有其他小组的数据、实际交换记录或组间通过结论。

## 已完成的功能

程序“06 自检与交叉测试”页提供 CSV 样例导出和导入验证；服务接口为 `saes_app.services.exchange.export_vectors` / `verify_csv`。每行均检查 16 位明文、密钥和密文，并执行：

1. `E_K(P)` 与文件密文 C 比较。
2. 直接计算 `D_K(C)` 与文件明文 P 比较。
3. 只有格式、加密、解密同时一致才判定该行通过。

测试覆盖列顺序变化、BOM、前导零、列数错误、非法位串、结果不一致和空文件。本地生成的 [local-vectors.csv](evidence/results/local-vectors.csv) 有 8 条，双向验证 8/8 一致；[independent-reference.csv](evidence/results/independent-reference.csv) 另记录独立实现对照。

这些材料用于工具自测，不属于实际组间交叉测试。

## 后续正式实验记录位置

`docs/evidence/cross-test/` 当前只有状态说明。后续取得真实他组文件后，在该目录保存：

| 建议材料 | 内容 |
|---|---|
| `peer-vectors-original.csv` | 未修改的他组原始数据 |
| `peer-vectors-import.csv` | 必要时适配列名后的文件，保留所有位串 |
| `cross-test-results.csv` | 各行实际加密、解密及结论 |
| `cross-test-summary.json` | 数据来源、时间、哈希、程序与参数信息 |
| 界面截图 | 完整窗口、通过数量、所有测试行 |

组别、成员、数据来源、实际测试日期及结论当前均留空。取得数据并实际验证后，再补全记录。
