# 分析脚本索引

**状态**: ✅ 已记录
**最后更新**: 2026-01-29

---

## Python 脚本（大多数都在 legacy 目录里）

### 固件处理

| 脚本 | 用途 |
|------|------|
| `03-fixer.py` | 固件修复脚本，处理 HIFIEC10.IMG |
| `extract_fonts_correct.py` | 字体提取脚本 (基于汇编代码分析) |

### 字体提取脚本 (extract_fonts_correct.py)

**功能**: 从符号表提取字体数据

**基于**: `r6 = 0x100000 + r5 × 4` (来自 INLINE_RENDERING.md)

**数据结构**:
- 基址: 0x100000
- 每字符: 64 字节 (16 行 × 4 字节/行)
- 像素数据: 每行前 2 字节

**使用方法**:
```bash
python3 extract_fonts_correct.py
```

**输出**: `extracted_parts/fonts_correct/` (7,039 个非空字符 BMP 文件)

### 分析脚本

| 脚本 | 用途 |
|------|------|
| `trace_bne_condition.py` | 追踪 bne 条件判断 |
| `verify_ldm_flags.py` | 验证 ldm 标志位设置 |
| `analyze_2dc22.py` | 0x2DC22 代码路径分析 |
| `complete_flow_analysis.py` | 完整流程分析 |
| `revsh_decode_mechanism.py` | REVSH 解码机制分析 |
| `rendering_pipeline_analyzer.py` | 渲染管线分析 (Capstone) |
| `r5_register_tracer.py` | R5 寄存器追踪 |
| `r5_mapping_table_analyzer.py` | R5 映射表分析 |

### 数据验证脚本

| 脚本 | 用途 |
|------|------|
| `manual_trace_r6.py` | R6 计算验证 |
| `actual_structure_analysis.py` | 数据结构分析 |
| `angr_symbolic_analysis.py` | 符号执行尝试 |

---

## Ghidra 脚本 (scripts/)

### 数据流分析

| 脚本 | 用途 |
|------|------|
| `dataflow_capstone.py` | Capstone 数据流分析 |
| `dataflow_analysis.py` | Ghidra 数据流分析脚本 |
| `mark_code_areas.py` | 在 Ghidra 中标记代码区域并创建函数 |

### 使用方法

```bash
# 1. 标记代码区域并创建函数
ghidra-analyzeHeadless ghidra_project/ ECHO_PROJECT -process HIFIEC10_Fixed.bin -postScript scripts/mark_code_areas.py

# 2. 运行数据流分析
ghidra-analyzeHeadless ghidra_project/ ECHO_PROJECT -process HIFIEC10_Fixed.bin -postScript scripts/dataflow_analysis.py

# 3. 使用 Capstone 分析（独立运行）
python3 scripts/dataflow_capstone.py
```

### Ghidra 分析发现

通过 Ghidra 数据流分析，发现了以下关键信息：

**创建的函数**:
- `func_pixel_load_0x2DB58` (134 bytes) - 像素加载主函数
- `func_r5_load_0x2DA8E` (6 bytes) - r5 加载点
- `func_utf16_ldrh_0x2FCF4` - UTF-16 字符串处理

**渲染函数内的 ADR 指令**:
```
0x2DB72: adr r0, #0x3d8    ; r0 = 0x2DF4C
0x2DB7C: adr r0, #0x3d8    ; r0 = 0x2DF58
0x2DB92: adr r0, #0x3d4    ; r0 = 0x2DF68
```

**数据加载点**:
```
0x2DB84: ldr r7, [0x2DF48]  ; 从 0x2DF48 加载
0x2DB8A: ldr r0, [0x2DCA0]  ; 从 0x2DCA0 加载
0x2DB90: ldr r5, [0x2DD14]  ; 从 0x2DD14 加载到 r5
```

**LDRH UTF-16 候选指令** (从 1 个增加到 3 个):
```
0x2DB58: ldrh r2, [r6, #6]  ; 像素数据
0x2DB64: ldrh r0, [r7, #6]  ; UTF-16 候选
0x2FCF4: ldrh r6, [r7, #0xe] ; UTF-16 候选
```

**字符串区域引用**: 确认 **无直接引用**（与文档一致）

---

## 工具使用

### rizin/radare2

```bash
# 分析固件
rizin -a arm -b 16 HIFIEC10_Fixed.bin

# 查找函数
afl

# 查找交叉引用
axt 0x2DB58

# 反汇编
pd 20 @ 0x2DB58
```

### Capstone

```python
from capstone import *

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

code = b"\x58\x2d"  # 示例字节
for insn in md.disasm(code, 0x2DB58):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

### Ghidra

```bash
# 命令行分析
analyzeHeadless HIFIEC10_Fixed.bin -import

# 导出分析结果
analyzeHeadless . . -postScript ExportScript.java
```


---

**参见**:
- [调试指南](./DEBUGGING_GUIDE.md)
- [数据流分析结果](../../04_DATA_DISCOVERY/LANGUAGE_TABLE.md#ghidra-数据分析结果-2026-01-29)
