# 分析方法论

**状态**: ✅ 已记录
**最后更新**: 2026-01-29

---

## 工具概览

### 已安装的工具

| 工具 | 路径 | 用途 |
|------|------|------|
| ghidra | `/run/current-system/sw/bin/ghidra` | Ghidra GUI |
| ghidra-analyzeHeadless | `/run/current-system/sw/bin/ghidra-analyzeHeadless` | 命令行分析 |
| rizin | `/run/current-system/sw/bin/rizin` | 函数分析、反汇编 |
| radare2 | `/run/current-system/sw/bin/radare2` | 函数分析、交叉引用 |
| Python 3.12.12 | 系统默认 | 脚本运行 |

### Python 依赖包

**状态**: ✅ 已安装

分析所需的外部包：

| 包名 | 版本 | 用途 | 安装状态 |
|------|------|------|----------|
| `capstone` | 5.0.6 | ARM Thumb 指令解码 | ✅ 已安装 |
| `pyhidra` | 1.3.0 | Ghidra Python 原生集成 | ✅ 本地版本 (lib2/pyhidra/) |
| `ghidra-bridge` | - | Ghidra 远程桥接 | ✅ 已安装 |
| `r2pipe` | - | radare2 Python 管道 | ✅ 已安装 |
| `rzpipe` | - | rizin Python 管道 | ✅ 已安装 |
| `angr` | - | 符号执行 | ✅ 已安装 |
| `bap` | - | Platform for binary analysis | ❌ 未安装 |

> **注意**: `pyhidra` 已包含在 `lib2/pyhidra/` 和 `lib/pyhidra/` 目录中，版本为 1.3.0。
> **重要**: 本地 pyhidra 版本不包含 `flat` API，需要使用 `HeadlessPyhidraLauncher` 类。


### Ghidra 项目

**项目位置**: `ghidra_project/`

**当前状态**: ⚠️ 目录为空，需要创建项目

---

## Python 包使用指南

### 1. Capstone - ARM Thumb 指令解码

**用途**: 精确解码 ARM Thumb 指令，获取指令详细信息

```python
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

# 读取固件
with open("HIFIEC10_Fixed.bin", "rb") as f:
    firmware = f.read()

# 初始化 (ARM Thumb 模式)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

# 解码 0x2DB58 处的指令
addr = 0x2DB58
code = firmware[addr:addr+32]

for insn in md.disasm(code, addr):
    print(f"0x{insn.address:06X}: {insn.mnemonic:12s} {insn.op_str}")
```

**实际输出**:
```
0x02DB58: ldrh         r2, [r6, #6]
0x02DB5A: subs         r0, #0x46
0x02DB5C: lsls         r0, r6, #3
0x02DB5E: str          r0, [r7, #0x1c]
0x02DB64: ldrh         r0, [r7, #6]
0x02DB72: adr          r0, #0x3d8
0x02DB74: lsls         r4, r5, #5
0x02DB76: pop          {r0, r4, r5, r6, r7}
```

**关键发现**: `0x02DB58: ldrh r2, [r6, #6]` 是像素数据加载指令

---

### 2. rzpipe - rizin Python 管道

**用途**: 快速反汇编、函数分析、交叉引用查找

```python
import rzpipe

# 打开固件
rz = rzpipe.open("HIFIEC10_Fixed.bin")

# 设置架构
rz.cmd("e asm.arch=arm")
rz.cmd("e asm.bits=16")

# 反汇编指定地址
result = rz.cmdj("pdj 20 @ 0x2DB58")
for insn in result:
    print(f"0x{insn['offset']:06X}: {insn['disasm']}")

# 获取函数列表
rz.cmd("aaa")  # 分析
functions = rz.cmdj("aflj")  # JSON 格式
print(f"函数总数: {len(functions)}")

# 查找交叉引用
refs = rz.cmdj("axtj 0x2DB58")  # 谁引用了 0x2DB58
for ref in refs:
    print(f"引用来自: 0x{ref['from']:X}")
```

**实际输出**:
```
0x02DB58: ldrh r2, [r6, 6]
0x02DB5A: subs r0, 0x46
0x02DB5C: lsls r0, r6, 3
0x02DB5E: str r0, [r7, 0x1c]
0x02DB64: ldrh r0, [r7, 6]
```

---

### 3. r2pipe - radare2 Python 管道

**用途**: 与 rzpipe 类似，使用 radare2 引擎

```python
import r2pipe

# 打开固件
r2 = r2pipe.open("HIFIEC10_Fixed.bin")

# 设置架构
r2.cmd("e asm.arch=arm")
r2.cmd("e asm.bits=16")

# 反汇编 (字符串模式)
result = r2.cmd("pd 20 @ 0x2DB58")
print(result)

# 获取函数列表
r2.cmd("aaa")
func_count = r2.cmd("afl | wc -l")
print(f"函数总数: {func_count}")
```

**实际输出**:
```
            0x0002db58      f288           ldrh r2, [r6, 6]
            0x0002db5a      4638           subs r0, 0x46
            0x0002db5c      f000           lsls r0, r6, 3
            0x0002db5e      f861           str r0, [r7, 0x1c]
            0x0002db64      f888           ldrh r0, [r7, 6]
            0x0002db72      f6a0           adr r0, 0x3d8               ; 0x2df4c
```

---

### 4. angr - 符号执行

**用途**: 符号执行、控制流分析、漏洞挖掘

```python
import angr

# 加载固件 (使用 blob loader 处理原始二进制)
proj = angr.Project(
    "HIFIEC10_Fixed.bin",
    main_opts={
        'backend': 'blob',
        'arch': 'ARMLE',
        'base_addr': 0x0,
    }
)

print(f"架构: {proj.arch}")
print(f"基址: 0x{proj.loader.main_object.mapped_base:X}")

# 获取指定地址的指令块
block = proj.factory.block(0x2DB58)
print(f"指令: {block.disassembly}")

# 获取控制流图
cfg = proj.analyses.CFGFast(data_references=True, normalize=True)
print(f"函数总数: {len(cfg.functions)}")
```

**注意**: angr 默认使用 ARM 模式反汇编，固件是 Thumb 模式，结果可能与 Capstone 不同。

---

### 5. pyhidra - Ghidra Python 原生集成

**用途**: 完整的 Ghidra API 访问，支持反编译、数据流分析

**重要**: 本地 pyhidra v1.3.0 **不包含** `flat` API，必须使用 `HeadlessPyhidraLauncher` 或 `open_program`。

```python
import os
import sys

# 设置环境
os.environ['GHIDRA_INSTALL_DIR'] = '/nix/store/gimigjjf2si4ddpjwy1r1fibck4g0h6y-ghidra-11.4.2/lib/ghidra'
sys.path.insert(0, '/home/losses/Downloads/ECHO MINI V3.1.0/lib2')

from pyhidra import open_program

def analyze():
    from ghidra.app.decompiler import DecompInterface

    program = getCurrentProgram()
    addr_factory = program.getAddressFactory()
    function_manager = program.getFunctionManager()

    print(f"程序名称: {program.getName()}")
    print(f"函数总数: {function_manager.getFunctionCount()}")

    # 获取指定地址的指令
    addr = addr_factory.getAddress('0x2DB58')
    func = function_manager.getFunctionContaining(addr)

    if func:
        print(f"\n所在函数: {func.getName()} @ {func.getEntryPoint()}")

        # 反编译函数
        decompiler = DecompInterface()
        decompiler.openProgram(program)

        try:
            result = decompiler.decompileFunction(func, 30, None)
            if result and result.decompileCompleted():
                code = result.getDecompiledFunction().getC()
                print(f"\n反编译代码:\n{code}")
        finally:
            decompiler.dispose()

# 使用 context manager
with open_program(
    binary_path="HIFIEC10_Fixed.bin",
    project_location="ghidra_project",
    project_name="ECHO_PROJECT",
    analyze=True,
    language="ARM:LE:32:v6"
) as api:
    analyze()
```

**替代方案 - 使用 HeadlessPyhidraLauncher**:

```python
import os
import sys

os.environ['GHIDRA_INSTALL_DIR'] = '/nix/store/gimigjjf2si4ddpjwy1r1fibck4g0h6y-ghidra-11.4.2/lib/ghidra'
sys.path.insert(0, '/home/losses/Downloads/ECHO MINI V3.1.0/lib2')

from pyhidra import HeadlessPyhidraLauncher

launcher = HeadlessPyhidraLauncher()
launcher.add_vmargs('-Xmx8G')
launcher.start()

try:
    from ghidra.base.project import GhidraProject
    from java.io import File

    project = GhidraProject.createProject(File("ghidra_project"), "ECHO_PROJECT", False)
    program = project.importProgram(File("HIFIEC10_Fixed.bin"))

    # 使用 program 进行分析
    print(f"函数数: {program.getFunctionManager().getFunctionCount()}")

    project.save(program)
finally:
    launcher.dispose()
```

---

### 6. ghidra-bridge - Ghidra 远程桥接

**用途**: 连接到运行中的 Ghidra GUI，进行交互式分析

**前提**: 需要先启动 Ghidra GUI

```bash
# 首先启动 Ghidra
ghidra

# 在 Ghidra 中创建项目并导入固件
# 然后在 Python 中连接
```

```python
from ghidra_bridge import GhidraBridge

# 连接到运行中的 Ghidra (默认端口 20000)
bridge = GhidraBridge()
ghidra = bridge.get_ghidra_api()

# 获取当前程序
program = ghidra.getCurrentProgram()
print(f"程序名称: {program.getName()}")

# 获取函数管理器
function_manager = program.getFunctionManager()
functions = list(function_manager.getFunctions(True))
print(f"函数总数: {len(functions)}")

# 分析指定地址
addr_factory = program.getAddressFactory()
addr = addr_factory.getAddress('0x2DB58')
listing = program.getListing()

code_unit = listing.getCodeUnitAt(addr)
print(f"\n0x2DB58: {code_unit.toString()}")

bridge.close()
```

---

## 工具对比

| 任务 | 推荐工具 | 理由 |
|------|----------|------|
| 快速反汇编 | Capstone / rzpipe | 轻量、快速、准确 |
| 函数分析 | rzpipe / r2pipe | 内置函数识别 |
| 交叉引用 | rzpipe / Ghidra | axt/axf 命令 |
| 反编译 | pyhidra / Ghidra | 完整的反编译器 |
| 符号执行 | angr | 强大的符号执行引擎 |
| 数据流分析 | pyhidra | Ghidra 的数据流分析 |

---

## 常见模式

### 模式 1: 快速查看指令

```python
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

with open("HIFIEC10_Fixed.bin", "rb") as f:
    firmware = f.read()

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
addr = 0x2DB58
code = firmware[addr:addr+32]

for insn in md.disasm(code, addr):
    print(f"0x{insn.address:06X}: {insn.mnemonic} {insn.op_str}")
```

### 模式 2: 查找所有函数

```python
import rzpipe

rz = rzpipe.open("HIFIEC10_Fixed.bin")
rz.cmd("aaa")  # 分析
functions = rz.cmdj("aflj")

for func in functions:
    print(f"{func['name']} @ 0x{func['offset']:X}")
```

### 模式 3: 查找交叉引用

```python
import rzpipe

rz = rzpipe.open("HIFIEC10_Fixed.bin")
rz.cmd("aaa")

# 查找谁引用了 0x2DB58
refs = rz.cmdj("axtj 0x2DB58")
for ref in refs:
    print(f"引用来自: 0x{ref['from']:X}")
```

### 模式 4: 反编译函数

```python
from pyhidra import open_program

def decompile_at_addr(addr):
    from ghidra.app.decompiler import DecompInterface
    program = getCurrentProgram()
    function_manager = program.getFunctionManager()

    func = function_manager.getFunctionContaining(
        program.getAddressFactory().getAddress(addr))

    if func:
        decompiler = DecompInterface()
        decompiler.openProgram(program)

        result = decompiler.decompileFunction(func, 30, None)
        if result and result.decompileCompleted():
            print(result.getDecompiledFunction().getC())

with open_program("HIFIEC10_Fixed.bin", "ghidra_project", "PROJECT") as api:
    decompile_at_addr("0x2DB58")
```

---

## 环境设置

### 环境变量

创建 `.envrc` 或添加到 `~/.bashrc`:

```bash
# Ghidra 安装目录
export GHIDRA_INSTALL_DIR="/nix/store/gimigjjf2si4ddpjwy1r1fibck4g0h6y-ghidra-11.4.2/lib/ghidra"

# JAVA_HOME (Ghidra 自带)
export JAVA_HOME="/nix/store/1hsjv46ywn8frcnc4c4zr7qj1w39rymh-zulu-ca-fx-jdk-25.0.0"

# Python 路径 (包含本地 pyhidra)
export PYTHONPATH="/home/losses/Downloads/ECHO MINI V3.1.0/lib2:$PYTHONPATH"

# 固件项目路径
export ECHO_PROJECT_DIR="/home/losses/Downloads/ECHO MINI V3.1.0"
export FIRMWARE_PATH="$ECHO_PROJECT_DIR/HIFIEC10_Fixed.bin"
export GHIDRA_PROJECT_DIR="$ECHO_PROJECT_DIR/ghidra_project"
```

### 创建 Ghidra 项目

```bash
cd "/home/losses/Downloads/ECHO MINI V3.1.0"

# 方法 1: 使用提供的脚本
./ghidra_server.sh

# 方法 2: 手动运行
/nix/store/gimigjjf2si4ddpjwy1r1fibck4g0h6y-ghidra-11.4.2/lib/ghidra/support/analyzeHeadless \
  ghidra_project ECHO_PROJECT \
  -import HIFIEC10_Fixed.bin \
  -processor ARM:LE:32:v6
```

---

## 分析步骤

### 1. 固件预处理

```bash
# 使用 03-fixer.py 处理固件
python3 03-fixer.py HIFIEC10.IMG HIFIEC10_Fixed.bin
```

### 2. 函数分析

**方法 A: 使用 rizin 命令行**
```bash
rizin -a arm -b 16 HIFIEC10_Fixed.bin
rizin> aaa          # 自动分析
rizin> afl          # 列出函数
rizin> pdf @ 0x2DB58  # 反汇编指定地址
```

**方法 B: 使用 rzpipe (Python)**
```python
import rzpipe
rz = rzpipe.open("HIFIEC10_Fixed.bin")
rz.cmd("aaa")
functions = rz.cmdj("aflj")  # 获取函数列表
```

**方法 C: 使用 Ghidra analyzeHeadless**
```bash
analyzeHeadless ghidra_project ECHO_PROJECT -import HIFIEC10_Fixed.bin -processor ARM:LE:32:v6
```

**方法 D: 使用 Capstone (Python)**
```python
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
with open("HIFIEC10_Fixed.bin", "rb") as f:
    firmware = f.read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for insn in md.disasm(firmware[0x2DB58:0x2DB58+32], 0x2DB58):
    print(f"0x{insn.address:06X}: {insn.mnemonic} {insn.op_str}")
```

### 3. 数据分析

- 统计各表首字节分布规律
- 对比好坏字符在序列位置上的差异
- 用已知样本文件验证不同编码假设

### 4. 代码追踪

**使用 pyhidra 进行反编译和数据流分析**:
```python
from pyhidra import open_program
from ghidra.app.decompiler import DecompInterface

def analyze():
    program = getCurrentProgram()
    func = program.getFunctionManager().getFunctionContaining(
        program.getAddressFactory().getAddress('0x2DB58'))

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    result = decompiler.decompileFunction(func, 30, None)
    print(result.getDecompiledFunction().getC())

with open_program("HIFIEC10_Fixed.bin", "ghidra_project", "PROJECT") as api:
    analyze()
```

---

## 关键发现路径

### 发现 1: Bit 7 测试位置

```
0x2DAC8: cmp r2, #0x80     ; CMP #128 (bit 7 test!)
0x2DB12: cmp r0, #0x80     ; CMP #128 (bit 7 test!)
```

### 发现 2: 字节交换机制

```
0x2DB0A: revsh r1, r6      ; Reverse half-word with sign extension
0x2DB2A: revsh r1, r6      ; Reverse half-word with sign extension
```

### 发现 3: 像素数据位置

```
r6 = 0x100000 + r5 × 4
ldrh r2, [r6, #6]  ; 从 r6+6 加载像素数据
```

### 发现 4: Unicode 映射

```
U+6CA8 → r5 = 0x0FDE  (差值: -0x5CCA)
r5 = Unicode - 偏移量
```

---

## 验证方法

### 数据验证

对比多个假设地址的数据模式：

| 假设 | 公式 | 数据特征 | 结果 |
|------|------|----------|------|
| r5 × 4 | 0x103F78 | 高非零密度，有意义位图 | ✅ 正确 |
| r5 × 2 | 0x101FBC | 重复模式 (2A A5 00 00...) | ✗ 错误 |
| r5 × 1 | 0x100FDE | 低密度 | ✗ 错误 |

### 代码验证

使用 Capstone 精确解码，验证 rizin 的反汇编结果：

| 工具 | 指令 | 目标地址 |
|------|------|----------|
| rizin | `ldr r7, [0x0002dff0]` | 0x2dff0 |
| Capstone | `ldr r7, [pc, #0x3c0]` | 0x2DFF2 |

**结论**: Capstone 的 PC-relative 地址计算是正确的

### 加载指令扫描 (2026-01-29)

**扫描范围**: 0x20000 - 0x50000（固件代码区域）
**方法**: Capstone 反汇编 + 模式匹配

**指令统计**:

| 指令 | 数量 | 用途 |
|------|------|------|
| ldr | 137 | 字加载（32位） |
| ldm | 36 | 多寄存器加载 |
| ldrh | 46 | 半字加载（16位） |
| ldrb | 17 | 字节加载 |
| ldrsb | 6 | 有符号字节加载 |
| ldrsh | 5 | 有符号半字加载 |

**总计**: 247 条加载指令

**关键发现**:

1. **`ldr r6, [r?, #0x14]` 模式**: 大多数此类指令不是字体渲染代码，而是其他数据结构访问
2. **已确认的渲染代码**: 0x02D500 - 0x02DB58 区域包含主要的字体渲染函数
3. **指令验证**: Capstone 分段扫描成功避免了超时问题

**方法论教训**:

| 策略 | 结果 | 评价 |
|------|------|------|
| 搜索 `ldr r6, [r0, #0x14]` | 266处 | ❌ 大多数不相关 |
| 上下文分析 | 部分成功 | ⚠️ 需要逐个验证 |
| Capstone分段扫描 | ✅ 成功 | ✅ 避免超时 |
| 手动追踪数据流 | ⚠️ 复杂 | ⚠️ 容易迷失 |

---

## 已拒绝的方法

| 方法 | 结果 | 结论 |
|------|------|------|
| 偏移读取假设 | 14.3% 匹配率 | ❌ 证伪 |
| strh/ldrh 密集区搜索 | 找到区域但无有效代码 | ❌ 数据区域 |
| 语言表引用搜索 | 未找到直接指针 | ❓ 可能间接访问 |

---


## 硬件平台信息

**芯片**: Rockchip RKnano

**硬件架构文档**:
- [DMA 架构分析](../HARDWARE/DMA_ARCHITECTURE.md) - DMAC 控制器、LLI 结构
- [显示系统分析](../HARDWARE/DISPLAY_SYSTEM.md) - VOP、revsh 指令
- [TRM 寄存器列表](./TRM_REGISTER_LIST.md) - 完整寄存器参考

---
## 研究进展总结 (2026-01-29)

### 核心发现

1. **查找表结构完整识别** ✅
   - 位置: 0x080000-0x080800 (2KB)
   - 128 条目 × 16 字节
   - 包含 ASCII UI 字符串 ("Charging", "-6mm")
   - UTF-16 LE 编码

2. **三级查找机制发现** ✅
   - Level 1: 查找表 (0x080000)
   - Level 2: 函数指针表 (条目 44-52, 72 个函数)
   - Level 3: 像素数据 (位置待确定)

3. **函数指针表确认** ✅
   - 条目 44-52 是函数指针，不是数据
   - 函数地址 = 0x080000 + 偏移值
   - 每个函数处理一个 Unicode 块 (256 字符)
   - 覆盖范围: 0x8F00-0xD600 (18,432 个 CJK 字符)

4. **渲染函数数据流确认** ✅
   - `param_2` 在整个函数期间保持不变
   - 像素数据地址 = `param_2 + 6`
   - `param_2` 指向包含渲染数据的结构体

5. **代码引用编码模式** ✅
   - 39 处 `0x0800xxxx` 格式的引用
   - 编码: 条目索引 + 偏移

### 硬件平台信息

**芯片**: Rockchip RKnano
**固件**: 地址 0 包含 "Rockchip" 字符串

### 文档结构

**已创建的文档**:
- `docs/04_DATA_DISCOVERY/LOOKUP_TABLE_0x080000.md` - 查找表结构
- `docs/03_CODE_ANALYSIS/DATA_FLOW_SUMMARY.md` - 数据流分析
- `docs/03_CODE_ANALYSIS/VERIFIED_INSTRUCTIONS_ANALYSIS.md` - 指令验证

**整合的文档**:
- `docs/04_DATA_DISCOVERY/LOOKUP_TABLE_0x080000.md` - 包含了查找机制和函数指针表发现

### 剩余问题

| 问题 | 优先级 | 状态 |
|------|--------|------|
| param_2 的来源 | 🔴 最高 | ❓ 需要追踪调用者 |
| 像素数据位置 | 🔴 高 | ❓ 可能在 0x090000+ |
| Unicode → r5 转换 | 🔴 高 | ❌ 代码未找到 |
| 函数调用链 | 🟡 中 | ⚠️ 部分确认 |

### 下一步研究方向

1. **Ghidra 深度分析** (优先级最高)
   - 自动化数据流分析
   - 交叉引用所有渲染相关函数
   - 理解完整调用图

2. **字体数据定位**
   - 基于像素数据指针公式追踪实际存储
   - 分析字体格式和压缩方式

---

## 研究进展总结 (2026-01-29 晚期)

### 四级渲染架构确认 ✅

通过深入的指令追踪和符号执行分析，完整确认了四级渲染机制：

```
Level 0: Unicode 字符 (如 U+8F12)
  ↓
Level 1: 查找表 (0x080000)
  - 128 条目 × 16 字节
  - 包含 UI 字符串和函数指针
  ↓
Level 2: 函数指针表 (条目 44-52+)
  - 条目 44-52: CJK 函数指针 (0x8F00-0xD600)
  - 条目 48+: 扩展函数指针 (0xAF00-0xB600+)
  - 总计 72+ 个 CJK 处理函数
  ↓
Level 3: CJK 处理函数 (0x088F00-0x08A000+)
  - 每个 Unicode 块 (256 字符) 一个函数
  ↓
Level 4: 渲染函数 (0x02DB18)
  - 从内存读取像素数据并输出
```

### 关键函数地址表 ✅

| 地址 | 功能 | 说明 |
|------|------|------|
| **0x080000** | 查找表基址 | 128 条目，UI 字符串 + 函数指针 |
| **0x088F00+** | CJK 处理函数 | 处理特定 Unicode 块 |
| **0x02DB18** | 渲染函数 | 核心像素渲染代码 |
| **0x02DDDC** | 调度函数 | 协调 CJK 处理和渲染 |
| **0x02DF70** | 跳转指令 | `b #0x2db18` 跳转到渲染 |

### 参数转换公式推导 ✅

通过指令追踪确认的完整数据流：

```
输入: r6 (与 Unicode 相关)
  ↓
r1 = r6 >> 0x13
  ↓
r4 = r1 << 4 = r6 >> 0xF
  ↓
像素数据指针 = [r4 + 0xC]
  ↓
像素数据地址 = 像素数据指针 >> 1
  ↓
像素数据 = [像素数据地址 + 6]
```

**简化公式**：`pixel_data = [[(r6 >> 0xF) + 0xC] >> 1 + 6]`

### 字符描述符结构体推断 ✅

```
struct char_descriptor {
    // +0x00: 未知字段
    // ...
    +0x0C: u32 pixel_ptr;  // 像素数据指针 (右移1位存储)
    // ...
};
```

### 使用的分析方法

| 方法 | 工具 | 结果 |
|------|------|------|
| 指令追踪 | Capstone | 确认渲染函数和调用链 |
| 符号执行 | angr (简化) | 数据依赖分析 |
| 字节模式搜索 | Python | 定位查找表和函数指针 |
| 交叉引用分析 | 自定义脚本 | 追踪函数调用 |

### 更新的文档

- `docs/04_DATA_DISCOVERY/LOOKUP_TABLE_0x080000.md` - 更新至 v1.5
  - 添加函数指针表扩展发现
  - 添加参数转换公式
  - 添加字符描述符结构体推断
  - 添加调用链分析

### 剩余问题

| 问题 | 优先级 | 状态 |
|------|--------|------|
| Unicode → r6 映射 | 🔴 最高 | ❓ 需要追踪调用 0x02DDDC 的函数 |
| 字体数据位置 | 🔴 高 | ❓ 基于公式可推导但未验证 |
| 完整调用链 | 🟡 中 | ⚠️ 部分确认 (0x02DF70 → 0x02DB18) |
| 批量渲染机制 | 🟢 低 | ❓ 未开始研究 |

3. **定位像素数据**
   - 搜索 0x090000+ 区域
   - 理解数据格式

---

**参见**: [失败的假设](../06_FAILED_HYPOTHESES/WRONG_ASSUMPTIONS.md)
