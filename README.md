# S-AES 实验室

本组依据[信息安全导论第二次作业要求](https://shimo.im/docs/zm1FlCxE3eYCQSSo)和教材[附录 D：简化 AES](docs/reference/README.md)，使用 Python + Qt 实现了 S-AES 实验程序，并完成五个关卡的测试与分析。

## 运行

安装依赖后，双击 **`启动程序.bat`**，或在项目目录执行：

```powershell
.\.venv\Scripts\python.exe -m saes_app
```

首次运行时，使用 CPython 3.11 及以上版本创建环境：

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m saes_app
```

本组在 Windows 11、CPython 3.13.7、PySide6 / Qt 6.11.1 环境下完成验证。核心算法与服务仅依赖标准库，GUI 依赖 PySide6。

## 功能与完成情况

| 作业关卡 | 实现与验证 | 状态 |
|---|---|---|
| 第 1 关：基本测试 | 16 位加解密、密钥扩展、逐轮位串及矩阵 | 完成 |
| 第 2 关：交叉测试 | 他组 64 组基础向量双向验证，完整数据包 220 行通过 | 完成 |
| 第 3 关：扩展功能 | ASCII 两字节分组、原始字节视图、三种密文格式、可选填充 | 完成 |
| 第 4 关：多重加密 | 双重 EE、完整中间相遇攻击、32 位及 48 位三重 EEE | 完成 |
| 第 5 关：工作模式 | CBC、随机 IV、共享数据包、翻转及替换分组对比 | 完成 |

![程序预览](docs/evidence/screenshots/01-binary.png)

默认示例：明文 `1101011100101000`（D728），密钥 `0100101011110101`（4AF5），密文 `0010010011101100`（24EC）。

## 文档

- [通关说明：操作步骤、输入与预期输出](docs/通关说明.md)
- [用户指南](docs/user-guide.md) · [开发手册与接口](docs/developer-guide.md)
- [五关测试报告](docs/test-report.md) · [交叉验证报告](docs/cross-test-record.md)
- [界面设计说明](docs/ui-design.md) · [演示流程](docs/demo-recording.md)
- [实验材料索引](docs/evidence/README.md) · [作业要求与范围记录](docs/assignment-requirements.md)

## 复现验证

```powershell
# 完整单元、服务与 GUI 测试
.\.venv\Scripts\python.exe -m unittest discover -v

# 重建测试日志、实验 JSON / CSV
.\.venv\Scripts\python.exe tools/verify_project.py

# 单独验证他组数据，回填 220 行结果
.\.venv\Scripts\python.exe tools/verify_cross_test.py

# 重建真实 Qt 窗口截图
.\.venv\Scripts\python.exe tools/capture_screenshots.py
```

本组的 **56 项自动测试全部通过**。验证覆盖固定密钥下全部 65,536 个分组、固定分组下全部 65,536 个密钥，以及 4,096 组独立矩阵实现对照。另一组提供的原始数据包已完整归档，清单中 13 个文件的 SHA-256 均一致，119 个用例对应的 **220 行交叉结果全部通过**。详细结果见[交叉验证报告](docs/cross-test-record.md)和[实验汇总](docs/evidence/results/summary.json)。

本组将源代码、使用说明、算法接口、他组数据、实测结果和程序截图一并整理在本仓库中。虚拟环境、缓存和个人凭据通过忽略规则排除，实验环境记录仅保留复现所需的软件版本。

## 小组成员

| 姓名 | 学号 |
|---|---|
| 王楷睿 | 20240164 |
| 方裕涵 | 20241352 |
