# 像素数据位置

**状态**: ✅ 已确认
**最后更新**: 2026-01-28

---

## 核心发现

**像素数据位置**: `0x100000 + r5 × 4`

```
Character Data @ r6 = 0x100000 + r5 × 4:
  +0:  Metadata (6 bytes)
  +6:  First 16-bit pixel value  ← ARM: ldrh r2, [r6, #6]
  +8:  Second 16-bit pixel value
  ...
  +38: 16th 16-bit pixel value
```

---

## R6 寄存器计算 ✅

### 公式验证

| 假设 | 公式 | 地址 (沨 r5=0x0FDE) | 数据特征 | 结果 |
|------|------|-------------------|----------|------|
| 假设 1 | r5 × 4 | 0x103F78 | 高非零密度，有意义位图 | ✅ 正确 |
| 假设 2 | r5 × 2 | 0x101FBC | 重复模式 (2A A5 00 00...) | ✗ 错误 |
| 假设 3 | r5 × 1 | 0x100FDE | 低密度 | ✗ 错误 |

---

## 像素数据结构 ✅

### 格式定义

**格式**: 连续的 16 位 little-endian 值，从偏移 +6 开始

```
Character data @ r6:
  Offset +0:  [6 bytes metadata]
  Offset +6:  [16-bit value 1] [16-bit value 2] ... [16-bit value 16]
```

### 示例数据 (沨 @ 0x103F78)

```
Offset +6: 39 96 40 88 47 70 F3 C1 52 0A B5 10 F3 C1 01 13 ...

Value 1: 0x9639 (little-endian) = bits for row 0
Value 2: 0x8840 (little-endian) = bits for row 1
```

---

## ARM 代码证据 ✅

### 关键指令

```assembly
0x0002DB58: ldrh r2, [r6, #6]  ; Load 16-bit from r6+6
```

这确认了：
- 像素数据从 r6+6 开始 (偏移 +6)
- 前 6 字节是元数据
- 数据是 16 位 little-endian

---

## 0x96 不是标记 ✅

### 错误假设

```
❌ 错误: 0x96 是分隔标记，需要跳过
```

### 正确理解

```
✅ 0x96 是像素数据内容的一部分，不是分隔符
```

### 证据

| 字符 | r5 | 0x96 位置 | 结论 |
|------|----|----------|------|
| 沨 | 0x0FDE | [1] | 0x96 在第 2 字节 |
| 沤 | 0x0FDB | [1, 7, 13] | 0x96 在多个位置 |
| 沦 | 0x0FDC | [3, 9] | 0x96 在不同位置 |

---

## 正确的提取算法 (来自原分析)

**正确的提取逻辑**:
```python
# ✅ 正确：从 r6+6 读取
r6 = 0x100000 + r5 * 4
pixel_start = r6 + 6  # 跳过 6 字节元数据

for i in range(0, 32, 2):  # 16 行 × 2 字节
    val = struct.unpack('<H', firmware[pixel_start + i:pixel_start + i + 2])[0]
    bitmap_data.append(val)
```

---

## 元数据结构

```c
struct character_data {
    // 元数据区
    uint8_t metadata[6];         // +0x00: 6 bytes of metadata
    // metadata[0] Bit 7-4: 编码类型 (0x0-0x7=标准, 0x8-0xF=特殊)
    // metadata[0] Bit 3-0: 未使用
    // metadata[1-5]: 部分是像素数据的一部分

    // 像素位图区
    uint16_t row_data[16];       // +0x06: 16 rows × 16 bits
    // 格式: 连续的 little-endian 16 位值
};
```

---

**参见**:
- [编码规则](./ENCODING_RULES.md)
- [Unicode查找表](./UNICODE_LOOKUP_TABLE.md)
