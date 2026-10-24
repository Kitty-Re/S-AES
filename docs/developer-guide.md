# 开发手册与接口文档

## 1. 目录与职责

```text
saes_app/
  core/cipher.py        S-AES、GF 运算、密钥扩展与过程追踪
  services/
    formats.py          二进制 / 字节编码、分组及 PKCS#7
    text_cipher.py      ASCII 及原始 bytes 接口
    multiple.py         EE、32 / 48 位 EEE
    attack.py           完整中间相遇搜索
    cbc.py              CBC、IV 数据包与篡改比较
    exchange.py         CSV 交换及双向验证
    checks.py           界面自检
  ui/
    main_window.py      导航、页面与安全关闭
    widgets.py          表单、卡片、结果和表格
    tasks.py            QThread 后台任务与取消
    theme.py            统一主题及测试字体
    pages/              六个独立功能页
tests/                  独立参考实现、核心、服务与 GUI 测试
tools/                  验证、截图与缩放检查脚本
docs/                   项目文档、教材副本和实验材料
```

核心和服务只依赖标准库，导入时无需 Qt。UI 负责收集与解析输入、调用服务并展示结果，不在控件回调中编写轮函数。命名采用 snake_case / PascalCase，复杂部分用注释说明状态布局、查表与碰撞处理。

## 2. 算法与数据表示

16 位状态从高位到低位的半字节是 `n0,n1,n2,n3`，矩阵为 `[n0 n2; n1 n3]`。所有 bytes 分组采用大端，每两个字节映射一个 16 位整数。

S 盒按行展开为 `9 4 A B D 1 8 5 6 2 0 3 C E F 7`，逆盒为 `A 5 9 B 1 7 8 F 6 0 2 3 C 4 D E`。有限域模多项式是 `x^4+x+1`。正向列矩阵为 `[1 4;4 1]`，逆矩阵为 `[9 2;2 9]`。

加密依次执行：密钥加 K0 → 半字节代替 → 行移位 → 列混淆 → 密钥加 K1 → 半字节代替 → 行移位 → 密钥加 K2。解密按逆顺序执行逆操作；第二行交换自身为逆，逆代替与行移位可交换次序。

密钥字节 `w0,w1` 扩展为：

```text
w2 = w0 XOR 80 XOR SubNib(RotNib(w1))
w3 = w2 XOR w1
w4 = w2 XOR 30 XOR SubNib(RotNib(w3))
w5 = w4 XOR w3
K0 = w0||w1, K1 = w2||w3, K2 = w4||w5
```

生产加解密合并与密钥无关的 NS+SR 查表（65,536 项）以及列变换查表（256 项），扩展密钥缓存最多 65,536 个。`trace_block` 使用逐步变换，实现可读过程并与优化路径互相验证。`tests/reference.py` 独立使用矩阵和多项式运算，并从求逆与仿射变换生成 S 盒，不导入生产核心。

## 3. 核心公开接口

从 `saes_app.core` 导入：

| 接口 | 返回 / 约束 |
|---|---|
| `encrypt_block(block, key)` | 16 位密文整数 |
| `decrypt_block(block, key)` | 16 位明文整数 |
| `generate_subkeys(key)` | `(K0,K1,K2)`，各为 16 位整数 |
| `expand_words(key)` | `(w0,...,w5)`，各为 8 位整数 |
| `gf_multiply(left,right)` | GF(2^4) 乘积，输入输出均 0～15 |
| `substitute(state,inverse=False)` | 半字节代替或逆代替 |
| `shift_rows(state)` | 第二行交换 |
| `mix_columns(state,inverse=False)` | 列混淆或逆列混淆 |
| `trace_block(block,key,decrypt=False)` | `BlockTrace(output,round_keys,steps)` |

`TraceStep` 包含 `name,value,detail`。分组、状态、密钥范围为 0～65535，只接受真正的 int，拒绝 bool、浮点数、字符串和越界值。公开函数在缓存查询之前校验输入，失败抛 `ValueError`。

```python
from saes_app.core import encrypt_block, decrypt_block

cipher = encrypt_block(0xD728, 0x4AF5)
assert cipher == 0x24EC
assert decrypt_block(cipher, 0x4AF5) == 0xD728
```

## 4. 编码、文本与多重加密

`services.formats` 提供 `parse_bits(text,width=16,name='输入')`、`format_bytes(data,kind)`、`parse_bytes(text,kind)`，kind 为“十六进制”“二进制”“Base64”。密文字节格式允许排版空白；Base64 要求规范填充与零填充位。未知格式抛 `ValueError`。

`to_blocks(data)` 和 `from_blocks(blocks)` 实现大端两字节映射；原始 bytes 长度必须为偶数。`pad(data)` / `unpad(data)` 为 2 字节 PKCS#7。填充永远增加 1 或 2 字节，移除时检查长度及所有填充字节。

`services.text_cipher`：

| 接口 | 行为 |
|---|---|
| `encrypt_bytes(data,key)` / `decrypt_bytes(data,key)` | 原始 bytes、无填充、等长转换 |
| `encrypt_text(text,key,padding=True)` | 严格 ASCII 编码，返回 bytes |
| `decrypt_text(data,key,padding=True)` | 解密、按约定移除填充、严格 ASCII 解码 |
| `ascii_bytes(text)` | 编码失败给出字符位置 |
| `escaped_bytes(data)` | 无损 Latin-1 转义显示 |

原始字节接口不会因文本解码失败丢弃数据；界面先显示原始字节再尝试解码。实际密文不是 ASCII 文本，使用可逆的 HEX / Base64 / 二进制交换。

`services.multiple` 提供 `split_keys(key,mode)`、`encrypt_multiple(block,key,mode)`、`decrypt_multiple(block,key,mode)` 和 `multiple_trace(block,key,mode,decrypt=False)`。模式为：

| mode | 密钥宽度 | 加密定义 |
|---|---|---|
| `double` | 32 | `E_K2(E_K1(P))` |
| `triple2` | 32 | `E_K1(E_K2(E_K1(P)))` |
| `triple3` | 48 | `E_K3(E_K2(E_K1(P)))` |

`multiple_trace` 返回含初始输入的各级状态 tuple。组合密钥高位段是 K1；解密反序执行 D。这一实现明确采用 EEE。

## 5. 中间相遇接口

```python
from saes_app.services.attack import meet_in_the_middle

result = meet_in_the_middle([(0xD728, 0xB2DD), (0x1234, 0x61AF)])
assert result.completed
assert result.candidates == ((0x4AF5, 0x3A94),)
```

`meet_in_the_middle(pairs,progress=None,cancel=None)` 接收一个或多个 `(P,C)` 对；C 必须是双重 EE 密文。先保存 `E_K1(P0) → list[K1]`，再枚举 K2 查 `D_K2(C0)`。同一中间值对应多个 K1，使用列表保留全部值，不能覆盖为单个密钥。每次匹配再验证余下所有已知对。

`AttackResult` 字段：

| 字段 | 含义 |
|---|---|
| `candidates` | 升序 `(K1,K2)` tuple，满足全部已知对 |
| `checked,total` | 实际枚举数、完整总数 131072 |
| `first_pair_matches` | 首组数据的候选匹配数量 |
| `distinct_intermediates` | 正向表不同中间值个数 |
| `elapsed` | `perf_counter` 实测计算秒数，包含建表与筛选 |
| `completed` | 是否完整枚举两侧空间 |
| `pairs` | 此次搜索使用的不可变已知对 |

时间复杂度为 `O(2^16 + 2^16 + M×r)`，M 为首组匹配数，r 为额外已知对数；空间为 `O(2^16+候选数)`。进度每 512 个密钥上报一次，循环逐次检查 `threading.Event`。建表取消时不启动反向匹配；反向阶段取消保留已匹配的候选但 `completed=False`。候选验证阶段的计算包含在耗时中，不增加进度分母。

## 6. CBC 与数据包

`services.cbc` 接口：

| 接口 | 行为 |
|---|---|
| `random_iv()` | 系统随机源生成 0～65535 |
| `encrypt_blocks(blocks,key,iv)` | 原始 16 位整数分组，无填充 |
| `decrypt_blocks(blocks,key,iv)` | 返回整数分组 tuple，无解码 |
| `encrypt_cbc(data,key,iv,padding=True)` | bytes CBC 加密 |
| `decrypt_cbc(data,key,iv,padding=True)` | bytes CBC 解密并按约定移除填充 |
| `export_packet(ciphertext,iv,padding=True)` | 格式化 JSON 字符串 |
| `import_packet(text)` | `(ciphertext_bytes,iv,padding_bool)` |
| `compare_tampering(blocks,key,iv,index=0,xor_mask=1,replacement=None)` | 原始解密差异的 `TamperRow` tuple |

CBC 定义 `C[-1]=IV`，`C[i]=E_K(P[i] XOR C[i-1])`，`P[i]=D_K(C[i]) XOR C[i-1]`。原始空分组合法；开启填充的空明文产生一个分组，开启填充的空密文会被拒绝。

数据包格式：

```json
{
  "algorithm": "S-AES-CBC",
  "version": 1,
  "iv": "1234",
  "padding": "PKCS7-2",
  "ciphertext_base64": "4zRFJ0jyD0BTV/Qx60Yb0UCs"
}
```

IV 为四位 HEX，padding 是 `PKCS7-2` 或 `none`。数据包不包含密钥；文本编码由双方另行约定。导入验证算法、版本、IV、规范 Base64、分组长度和填充名称。额外字段忽略。

`TamperRow` 包含 `index,ciphertext,modified_ciphertext,plaintext,modified_plaintext,xor_difference,changed_bits`。replacement 非 None 时整组替换，否则异或 xor_mask；原密文不被修改。比较接口保留原始填充块，以观察任意位置篡改，不依赖解码或去填充成功。

## 7. CSV 与界面自检

`exchange.export_vectors(path,pairs=SAMPLE_PAIRS)` 导出 UTF-8 BOM CSV；`verify_csv(path)` 返回 `CrossCheck` tuple，保留行号、原始三列、实际密文、恢复明文、passed 与 error。表头只有 `plaintext,key,ciphertext`，可改变列顺序。结构问题或无数据抛 `ValueError`；逐行问题保留为失败行。文件系统错误向调用方传播。

`checks.run_checks(exhaustive=False,progress=None,cancel=None)` 返回 `CheckResult(rows,checked,elapsed,completed)`；rows 包含名称、实际、期望和通过状态。可选固定密钥下全部分组往返。完整测试另由 unittest 执行。

### 他组数据包验证

`tools/verify_cross_test.py` 提供 `run_bundle(source=SOURCE,output=None)`，返回 `(summary,rows)`。source 是含原始 manifest 的数据目录；output 非 None 时写入适配 CSV、220 行模板回填结果、基础逐条结果、详细 JSON、统计 JSON 及两个 MITM 候选文件。没有 output 时不写文件，供回归测试调用。

`verify_manifest(source)` 逐字节检查 13 个原始文件，拒绝重复名称、目录穿越和哈希不一致；仓库对 `peer-original/**` 禁用换行转换，以保持与 ZIP 完全相同。脚本仅读取数据，不执行数据包内容。原包发送说明及自检记录原样保存，当前实测写入独立文件。

基础数据同时核对 CSV / GUI JSON 的位串、三轮密钥、加密、直接解密对方密文及独立矩阵参考。多重加密比较每一级输出；ASCII 多重消息复合现有公开分组接口，填充只在最外层处理一次。CBC 对比固定 IV 的密文和解密结果。

MITM 以 `(K1,K2)` 升序生成每行 `K1K2` 的 8 位大写 HEX，加一个 LF；ASCII 编码后的 SHA-256 必须与原包相同，不能只比较候选数量。篡改数据将原包的 1 起始分组序号转换为本组 0 起始序号，核对原始解密、逐块 XOR、影响范围及填充损坏状态。非法输入必须由对应公开接口抛出 `ValueError`；其他异常记录为失败，不视为正常拒绝。

每行保留原模板的 case_id、feature、direction、expected，仅回填 actual、status、note。合法空明文的 actual 可以为空，但状态必须为 PASS。组名与个人信息不预填；报告仅声明“本组运行他组数据”，不推断对方已执行本组向量。

GUI 的交叉表同时显示加密与解密结果，`last_checks` 保留本次 `CrossCheck` tuple 供截图和回归核对。新增测试覆盖原始包完整性、全部 220 行、MITM 完整集合散列、空输出、篡改输入文件的拒绝及错误计算不得误判 PASS。

## 8. 后台生命周期、测试与取证

`Worker(QThread)` 只执行服务，使用信号上报进度，在成员中保存结果或异常；`TaskPanel` 在 finished 后读取结果、释放线程并恢复按钮。服务回调在工作线程内执行，不直接操作 Qt。界面不添加最短加载时间，显示的耗时来自服务计时。

关闭主窗口时，对所有 TaskPanel 请求取消；尚有线程运行则暂缓关闭，用 QTimer 检查退出后完成关闭。取消、异常后可重新启动任务。UI 测试临时捕获 `sys.excepthook`，槽函数未处理异常会使测试失败。

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe tools/verify_project.py
.\.venv\Scripts\python.exe tools/verify_cross_test.py
.\.venv\Scripts\python.exe tools/capture_screenshots.py
.\.venv\Scripts\python.exe tools/capture_screenshots.py --peer-only
$env:QT_SCALE_FACTOR = '1.5'
.\.venv\Scripts\python.exe tools/gui_probe.py
Remove-Item Env:QT_SCALE_FACTOR
```

测试与截图使用真实 Qt 控件及离屏平台；高 DPI 检查必须在新进程中改变缩放。工具生成的原始 JSON / CSV / PNG 见[材料索引](evidence/README.md)。
