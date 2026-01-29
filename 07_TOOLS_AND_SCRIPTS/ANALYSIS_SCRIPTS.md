# 分析脚本索引

**状态**: ✅ 已记录
**最后更新**: 2026-01-28

---

## Python 脚本

### 固件处理

| 脚本 | 用途 |
|------|------|
| `03-fixer.py` | 固件修复脚本，处理 HIFIEC10.IMG |
| `extract_fonts_correct.py` | 字体提取脚本 |

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
