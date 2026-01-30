# 寄存器追踪日志

**状态**: 🔄 已迁移
**最后更新**: 2026-01-29

---

> **注意**: 本文档的内容已被整理并迁移到 `docs/03_CODE_ANALYSIS/REGISTERS/` 目录下的独立文档中。请参考以下链接查看最新内容：

---

## 迁移后的文档

| 寄存器 | 文档 | 描述 |
|--------|------|------|
| r0 | [R0_BIT7_TEST.md](../03_CODE_ANALYSIS/REGISTERS/R0_BIT7_TEST.md) | Bit 7 测试与临时数据 |
| r2 | [R2_PARAMETER.md](../03_CODE_ANALYSIS/REGISTERS/R2_PARAMETER.md) | 函数参数与 Bit 7 测试载体 |
| r3 | [R3_ROW_INDEX.md](../03_CODE_ANALYSIS/REGISTERS/R3_ROW_INDEX.md) | 行索引与偏移量 |
| r4 | [R4_SYMBOL_TABLE.md](../03_CODE_ANALYSIS/REGISTERS/R4_SYMBOL_TABLE.md) | 符号表指针与编码判定 |
| **r5** | [R5_CHARACTER_INDEX.md](../03_CODE_ANALYSIS/REGISTERS/R5_CHARACTER_INDEX.md) | **字符内部索引** |
| **r6** | [R6_PIXEL_DATA_POINTER.md](../03_CODE_ANALYSIS/REGISTERS/R6_PIXEL_DATA_POINTER.md) | **像素数据指针** |
| **r7** | [R7_RENDER_CONTEXT.md](../03_CODE_ANALYSIS/REGISTERS/R7_RENDER_CONTEXT.md) | **渲染上下文基址** |

---

## 快速参考

### r5 寄存器完整生命周期

```
Unicode 输入 (U+6CA8) → 映射函数 (0x2CFC8) → r5 = 0x0FDE
    ↓
存储到渲染上下文 (0x2D040)
    ↓
渲染时加载 (0x2DA8E: ldm r1!, {r3, r4, r5, r6, r7})
    ↓
符号表计算 (0x2DB74: lsls r4, r5, #5 → r4 = r5 × 32)
    ↓
加载符号字节 (0x2DB94: ldrsb r0, [r4, r1])
```

### r6 寄存器计算公式

```
r6 = 0x100000 + r5 × 4

沨字示例:
r5 = 0x0FDE
r6 = 0x100000 + 0x0FDE × 4 = 0x103F78
```

### r7 寄存器 (渲染上下文)

**初始化**:
```assembly
0x2DA94: eor r0, r7, #0x28
0x2DABA: lsrs r6, r0, #0x19
0x2DABC: lsls r0, r0, #4
0x2DAC0: lsrs r5, r0, #0x10
0x2DAC2: asrs r6, r0, #0x1d
0x2DAC6: movs r2, r0
```

**使用**:
```assembly
0x2DB5E: str r0, [r7, #0x1c]    ; 存储地址指针
0x2DB64: ldrh r0, [r7, #6]     ; 读取像素数据
```

---

## 分支条件追踪

### 编码类型判定 (0x2DB12)

```assembly
0x2DB10: lsls r0, r4, #4       ; r0 = r4 << 4
0x2DB12: cmp r0, #0x80         ; 比较 r0 与 0x80
0x2DB2C: bne #0x2db4e          ; 如果 Z=0 则跳转
```

### 沨字分支

```
metadata[0] = 0x39
r4 = 0x39 >> 4 = 0x03
r0 = 0x03 << 4 = 0x30
cmp 0x30, 0x80  →  r0 < 0x80 → Z=1 → bne 不跳转
→ 继续执行 0x2DB2E (标准编码路径)
```

---

**参见**:
- [指令级追踪](../03_CODE_ANALYSIS/INSTRUCTION_TRACE.md)
- [原始数据转储](./RAW_DATA_DUMPS.md)
- [寄存器文档目录](../03_CODE_ANALYSIS/REGISTERS/)
