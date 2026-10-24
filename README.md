# S-AES 实验室

信息安全导论第二次作业。依据[作业要求](https://shimo.im/docs/zm1FlCxE3eYCQSSo)与教材[附录 D：简化 AES](docs/reference/README.md)，实现 Python + Qt 桌面程序、自动测试及关卡实验材料。

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

实际验证环境：Windows 11、CPython 3.13.7、PySide6 / Qt 6.11.1。核心算法与服务仅依赖标准库；GUI 依赖 PySide6。

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
- [五关测试报告](docs/test-report.md) · [交叉测试状态](docs/cross-test-record.md)
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

当前 **56 项自动测试全部通过**。验证包括固定密钥下全部 65,536 个分组、固定分组下全部 65,536 个密钥及 4,096 组独立矩阵实现对照。他组提供的压缩包已原样保存，13 份清单文件 SHA-256 一致，119 个用例对应的 **220 行交叉结果全部通过**。详情见[交叉测试报告](docs/cross-test-record.md)与[实验汇总](docs/evidence/results/summary.json)。

仓库包含源代码、文档、他组原始数据、本组实测结果与程序截图。小组成员留空。虚拟环境、缓存、个人凭据和本地教材 PDF 不纳入版本管理；测试汇总仅保留复现需要的软件版本。

## 小组成员

| 姓名 | 学号 |
|---|---|
| | |
| | |
| | |
