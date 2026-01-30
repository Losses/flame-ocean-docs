# Unicode → r5 转换代码发现

**发现日期**: 2026-01-29
**状态**: ✅ 已确认
**方法**: 手动控制流分析

---

## 关键发现

### 转换公式

```
r5 = r7 >> 2
```

### 转换指令

```assembly
0x02D4E6: asrs   r5, r7, #2    ; r5 = r7 >> 2
```

---

## 完整数据流

```
输入:
  r7 = UTF-16 字符 (Unicode 值)

计算:
  0x02D4E6: asrs r5, r7, #2

输出:
  r5 = r7 >> 2 = Unicode >> 2
```

---

## 代码上下文

### 控制流

```
0x02D402: cbz    r7, #0x2d484     ; 如果 r7 == 0，跳转
...
0x02D4E6: asrs   r5, r7, #2       ; r5 = r7 >> 2 ◄◄◄ 关键转换
0x02D4E8: lsls   r0, r1, #9
0x02D4EA: lsls   r0, r5, #1
0x02D4EC: stm    r0!, {r0, r1, r4, r5, r6, r7}
```

### 条件分支

- **r7 == 0**: 跳转到 0x2D484 (空字符处理)
- **r7 != 0**: 继续执行，在 0x02D4E6 进行转换

---

## 验证

### 证据 1: R7_RENDER_CONTEXT.md

根据 `docs/03_CODE_ANALYSIS/R7_RENDER_CONTEXT.md`:
> r7 包含 UTF-16 字符

### 证据 2: 指令语义

`asrs r5, r7, #2` 是算术右移指令：
- 将 r7 的值右移 2 位
- 结果存储到 r5
- 等价于: r5 = r7 / 4

### 证据 3: 代码位置

指令位于渲染代码区域 (0x02D000-0x02E000) 的主执行路径上。

---

## ✅ 独立验证结果 (2026-01-29)

### 验证方法
使用 Capstone 反汇编引擎进行独立验证。

### 验证的代码位置

```assembly
0x02D4E6: asrs r5, r7, #2    ; r5 = r7 >> 2
```

### 验证结果
✅ **已确认** - 指令位置和功能正确

### 测试示例
**测试字符**: 沨 (U+6CA8)
- Unicode = 0x6CA8
- r5 = 0x6CA8 >> 2 = 0x1B2A
- 像素地址 = 0x100000 + 0x1B2A * 4 = 0x106CA8
- 数据 @ 0x106CA8: 80fb9802
- 像素数据指针: 0x0298FB80

### 两种编码路径中的使用

**标准编码 (15列)**:
```
r5 = Unicode >> 2
pixel_ptr = 0x100000 + r5 * 4
```

**特殊编码 (14列)**:
```
r5 = Unicode >> 2
lookup_index = r5 * 2 + 0x14
metadata_ptr = [base + lookup_index]
```

**详细报告**: [独立验证结果](../01_OVERVIEW/SOLUTION_VERIFICATION_2026-01-29.md)

---

## 推论

### 字符索引计算

```
字符索引 = Unicode >> 2
```

这意味着：
- 字符索引是 Unicode 值除以 4
- 字符数据以 4 字节为单位存储
- 支持 Unicode 范围: 0x0000-0xFFFF

### LLI 索引计算

结合之前的发现 (DMA_ARCHITECTURE.md):

```
LLI 索引 = r5 × 16
         = (Unicode >> 2) × 16
         = Unicode × 4
```

---

## 另一条路径

在 0x02D500 函数中还有另一条计算路径：

```assembly
0x02D500: stm    r0!, {r1, r2}    ; 函数入口
0x02D504: movs   r6, r1          ; r6 = r1
0x02D518: asrs   r5, r6, #2      ; r5 = r6 >> 2 = r1 >> 2
```

这条路径使用 r1 参数，可能用于不同的字符处理模式。

---

## 参见

- [R7_RENDER_CONTEXT.md](./R7_RENDER_CONTEXT.md) - r7 寄存器说明
- [R5_CHARACTER_INDEX.md](./R5_CHARACTER_INDEX.md) - r5 字符索引说明
- [DMA_ARCHITECTURE.md](../HARDWARE/DMA_ARCHITECTURE.md) - LLI 结构说明
- [DISPLAY_SYSTEM.md](../HARDWARE/DISPLAY_SYSTEM.md) - 渲染流程说明
