# 渲染管线总览

**状态**: ✅ 已确认
**最后更新**: 2026-01-28

---

## 完整渲染管线

```
┌─────────────────────────────────────────────────────────────────┐
│                     Character Rendering Pipeline                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: Unicode (e.g., U+6CA8 沨)                              │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────┐                   │
│ │ Stage 1: Unicode → r5 Mapping            │                   │
│ ├─────────────────────────────────────────┤                   │
│ │ r5_hi = u_hi - 0x5D                      │                   │
│ │ r5_lo = u_lo + offset(u_lo)               │                   │
│ │ r5 = (r5_hi << 8) │ r5_lo                 │                   │
│ │ U+6CA8 → r5 = 0x0FDE                       │                   │
│ └─────────────────────────────────────────┘                   │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────┐                   │
│ │ Stage 2: Calculate R6                    │                   │
│ ├─────────────────────────────────────────┤                   │
│ │ r6 = 0x100000 + r5 × 4                   │                   │
│ │ Store in rendering context              │                   │
│ │ r6 = 0x103F78 for 沨 (r5=0x0FDE)          │                   │
│ └─────────────────────────────────────────┘                   │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────┐                   │
│ │ Stage 3: Encoding Type Decision          │                   │
│ ├─────────────────────────────────────────┤                   │
│ │ encoding = (metadata[0] >> 4) >= 0x8     │                   │
│ │   ? special (14 columns)                 │                   │
│ │   : standard (15 columns)                │                   │
│ └─────────────────────────────────────────┘                   │
│         │                                        │             │
│    Standard                                Special              │
│    (15 列)                                  (14 列)              │
│         │                                        │             │
│         └────────────────┬─────────────────────┘             │
│                          ▼                                   │
│  ┌─────────────────────────────────────────┐                   │
│ │ Stage 4: Load Pixel Data                 │                   │
│ ├─────────────────────────────────────────┤                   │
│ │ ARM: ldrh r2, [r6, #6] @ 0x2DB58        │                   │
│ │ ↓                                          │                   │
│ │ Skip 6 bytes metadata                     │                   │
│ │ Read 16 × 16-bit values                   │                   │
│ │ Format: little-endian, continuous        │                   │
│ └─────────────────────────────────────────┘                   │
│         │                                                       │
│         ▼                                                       │
│  Output: Display Buffer (pixel data)                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 关键代码位置

| 阶段 | 地址 | 说明 |
|------|------|------|
| Unicode → r5 | 0x2CFxx | 映射函数 |
| r6 计算 | 0x2Dxxx | 地址计算 |
| 编码判定 | 0x2DB12 | `cmp r0, #0x80` |
| 像素加载 | 0x2DB58 | `ldrh r2, [r6, #6]` |

---

## 渲染上下文结构

```c
struct rendering_context {
    uint32_t field_0x00;        // +0x00: r3
    uint32_t field_0x04;        // +0x04: r4 = metadata[0] >> 4
    uint16_t char_index;        // +0x08: r5 = 字符索引
    uint32_t font_data_ptr;     // +0x0C: r6 = 0x100000 + r5 × 4
    uint32_t field_0x10;        // +0x10: r7
};
```

---

## 主要渲染路径 (0x2DB58)

### 标准编码 (15列)

```assembly
0x0002DB58:  ldrh   r2, [r6, #6]    ; 从 r6+6 加载16位数据
0x0002DB5E:  str    r0, [r7, #0x1c]  ; 存储地址指针
0x0002DB60:  strh   r6, [r0, r1]    ; 存储像素数据
```

### 特殊编码 (14列)

通过分支到不同的处理逻辑实现。

---

## 字符数据结构

```c
struct character_data {
    uint8_t metadata[6];         // +0x00: 6 bytes of metadata
    uint16_t row_data[16];       // +0x06: 16 rows × 16 bits
                                 // Format: continuous little-endian
};
```

---

**参见**:
- [数据结构定义](./DATA_STRUCTURES.md)
- [内联渲染逻辑](../03_CODE_ANALYSIS/INLINE_RENDERING.md)
