# 编码规则

**状态**: ✅ 已确认
**最后更新**: 2026-01-28

---

## 编码类型判定

### 判定机制

```assembly
0x2DAD2: ldr   r4, [r1, #4]    ; r4 = [r1+4] (从渲染上下文加载)
0x2DB10: lsls r0, r4, #4       ; r0 = r4 << 4
0x2DB12: cmp   r0, #0x80       ; 比较 r0 与 0x80
```

### 判定规则

```
encoding = (metadata[0] >> 4) >= 0x8 ? 特殊编码 : 标准编码
```

| metadata[0] 高4位 | 编码类型 | 列数 | 说明 |
|------------------|----------|------|------|
| 0x0-0x7 | 标准 | 15 | 首字节 < 0x80 |
| 0x8-0xF | 特殊 | 14 | 首字节 ≥ 0x80 |

---

## 验证数据

| 字符 | Unicode | metadata[0] | 高4位 | r0 = 高4位 << 4 | 编码 | 验证 |
|------|---------|-------------|------|--------------|------|------|
| 沨 | U+6CA8 | 0x39 | 0x03 | 0x30 (< 0x80) | 标准 | ✅ |
| 沤 | U+6CA4 | 0x29 | 0x02 | 0x20 (< 0x80) | 标准 | ✅ |
| 沦 | U+6CA6 | 0xF1 | 0x0F | 0xF0 (>= 0x80) | 特殊 | ✅ |
| 沪 | U+6CAA | 0x20 | 0x02 | 0x20 (< 0x80) | 标准 | ✅ |

---

## 标准编码 (15列)

### 数据结构

```c
struct character_data {
    uint8_t metadata[6];         // +0x00: 6 bytes of metadata
    uint16_t row_data[16];       // +0x06: 16 rows × 16 bits
};
```

### 格式

- 列数: 15
- 行数: 16
- 数据: 连续的 16 位 little-endian 值
- 像素数据起始: r6 + 6

### Python 渲染函数

```python
def render_standard(raw_data):
    """标准编码渲染 (15列 × 16行)"""
    rows = []
    for row in range(16):
        odd = raw_data[row * 2]      # 第 1 个字节
        even = raw_data[row * 2 + 1]  # 第 2 个字节

        # MSB first: bit 7 → 位置 0, bit 0 → 位置 7
        even_bits = ''.join('#' if (even >> i) & 1 else '.' for i in range(7, -1, -1))
        odd_bits = ''.join('#' if (odd >> i) & 1 else '.' for i in range(7, -1, -1))

        # 前 8 位来自 even，后 7 位来自 odd（取 15 列）
        rows.append((even_bits + odd_bits)[:15])

    return rows
```

---

## 特殊编码 (14列)

### 格式

- 列数: 14
- 行数: 16
- 数据: 连续的 16 位 little-endian 值
- 像素数据起始: r6 + 6
- 首字节: ≥ 0x80 (metadata[0] Bit 7 = 1)

### 与标准编码的差异

| 特性 | 标准编码 (15列) | 特殊编码 (14列) |
|------|-----------------|-----------------|
| metadata[0] Bit 7 | 0 | 1 |
| 列数 | 15 | 14 |
| 分支目标 | 0x2DB2E (顺序执行) | 0x2DB4E (跳转) |
| adds r7,r7,#2 | ✅ 执行 | ❌ 不执行 |
| 字节交换 | ❌ 否 | ✅ 是 (revsh) |

**像素提取规则**:
- 数据存储为 16 位 little-endian 值
- 只有**前 14 位**用于像素显示
- **最高 2 位** (Bit 15-14) 可能是其他信息或填充

### Python 渲染函数 (来自原分析)

```python
def render_special(raw_data):
    """特殊编码渲染 (首字节 ≥ 0x80) - Skip+Swap 14列"""
    rows = []
    for row in range(16):
        # 跳过第 1 个字节
        idx = row * 2 + 1
        if idx + 1 >= 32:
            break

        odd = raw_data[idx]      # 原始第 2 个字节
        even = raw_data[idx + 1]  # 原始第 3 个字节

        # MSB first: bit 7 → 位置 0, bit 0 → 位置 7
        even_bits = ''.join('#' if (even >> i) & 1 else '.' for i in range(7, -1, -1))
        odd_bits = ''.join('#' if (odd >> i) & 1 else '.' for i in range(7, -1, -1))

        # 交换顺序: odd 先，even 后，取 14 列
        rows.append((odd_bits + even_bits)[:14])

    return rows
```

### 未解问题

| 问题 | 状态 |
|------|------|
| 最高 2 位 (Bit 15-14) 的含义 | ❓ 未知 |
| 字节交换 (revsh) 的具体影响 | ⚠️ 部分理解 |
| 14 列的精确位映射 | ⚠️ 需要验证 |

---

## 渲染上下文结构更新

```c
struct rendering_context {
    uint32_t field_0x00;        // +0x00: r3
    uint32_t field_0x04;        // +0x04: r4 = metadata[0] >> 4  ← 编码类型标志
    uint16_t char_index;        // +0x08: r5 = 字符索引
    uint32_t font_data_ptr;     // +0x0C: r6 = 0x100000 + r5 × 4
    uint32_t field_0x10;        // +0x10: r7
};
```

---

## metadata[0] Bit 3-0 调查

### 调查结果

**关键发现**: metadata[0] Bit 3-0 **不被渲染代码使用**。

### 证据

1. **代码搜索结果**: 未发现任何 `and 0xF` 或 `and #15` 指令
2. **像素数据分析**: Bit 3-0 值与像素密度无关，与列数无关
3. **渲染代码行为**: `ldrh r2, [r6, #6]` 直接跳过全部 6 字节 metadata

### 结论

**metadata[0] Bit 3-0 可能的用途**:
1. **遗留数据**: 旧版本字体系统使用的标志位
2. **编辑器标记**: 字体编辑工具使用的元数据
3. **未实现功能**: 设计时预留的标志位

**最终结论**: Bit 3-0 在当前固件的渲染流程中**不起作用**。

---

**参见**:
- [像素数据位置](./PIXEL_DATA_LOCATION.md)
- [元数据分析](./METADATA_ANALYSIS.md)
