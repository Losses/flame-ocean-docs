# 数据结构定义

**状态**: ✅ 已确认
**最后更新**: 2026-01-28

---

## 核心数据结构

### 字符数据结构

```c
struct character_data {
    // 元数据区 (6 字节)
    uint8_t metadata[6];         // +0x00
    // metadata[0] Bit 7-4: 编码类型 (0x0-0x7=标准, 0x8-0xF=特殊)
    // metadata[0] Bit 3-0: 未使用
    // metadata[1-5]: 未知

    // 像素位图区 (32 字节 = 16 行 × 2 字节)
    uint16_t row_data[16];       // +0x06
    // 格式: 连续的 16 位 little-endian 值
    // 注意: 0x96 是数据内容的一部分，不是标记
};
```

### 渲染上下文结构

```c
struct rendering_context {
    uint32_t field_0x00;        // +0x00: r3 (用途未知)
    uint32_t field_0x04;        // +0x04: r4 = metadata[0] >> 4
    uint16_t char_index;        // +0x08: r5 = 字符索引 (从 Unicode 映射)
    uint32_t font_data_ptr;     // +0x0C: r6 = 0x100000 + r5 × 4
    uint32_t field_0x10;        // +0x10: r7 (用途未知)
};
```

---

## 内存布局图

### 固件结构

| 偏移范围 | 区域 | 说明 |
|----------|------|------|
| 0x000 - 0x460 | Boot Header | SDK 版本信息 |
| 0x460 - 0x4A0 | Vector Table | 中断向量表 |
| 0x4A0 - End | .text / .data | 代码与数据 |
| 0x100000 | Font Data Base | 字体数据基址 |

### 关键地址

| 内容 | 地址 |
|------|------|
| 渲染代码 | 0x2DA00-0x2DB60 |
| 编码判定 | 0x2DB12 |
| 像素加载 | 0x2DB58 |
| 偏移表 | 0x14AD6 |
| 语言表 | 0x778000 |

---

## Unicode 映射数据

### 偏移表结构

```
偏移表 @ 0x14AD6:
  - 格式: 16 位值数组，小端序存储
  - 索引公式: (Unicode 低位 & 0x0F) - 2
  - 适用于 U+6CAx 范围的字符
```

### 映射示例

| 字符 | Unicode | r5 | 偏移量 | 验证 |
|------|---------|-----|--------|------|
| 沨 | U+6CA8 | 0x0FDE | 0x5CCA | 0x6CA8 - 0x5CCA = 0x0FDE ✅ |
| 沦 | U+6CA6 | 0x0FDC | 0x5CCA | 0x6CA6 - 0x5CCA = 0x0FDC ✅ |
| 沪 | U+6CAA | 0x0FDA | 0x5CD0 | 0x6CAA - 0x5CD0 = 0x0FDA ✅ |

---

## 符号表结构

### 地址计算

```
符号表地址 = 0x1C000 + r5 × 8
或者
符号表地址 = r5 << 5 (r5 × 32)
```

### 数据模式

```
沨字符号表 @ 0x1FBC0:
  偶数索引: 0xCD = -51 (基准值)
  奇数索引: 0xDE, 0xDF, 0xE0, 0xE1... = -34, -33, -32, -31...
```

---

**参见**:
- [渲染管线总览](./RENDERING_PIPELINE.md)
- [Unicode查找表](../04_DATA_DISCOVERY/UNICODE_LOOKUP_TABLE.md)
