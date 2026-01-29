# 内联渲染逻辑

**状态**: ✅ 已确认
**位置**: 0x2db50-0x2DBE0 (Bit 7 = 0 路径)
**最后更新**: 2026-01-28

---

## 执行摘要

**重要发现**: 实际渲染代码是**内联**的，不是函数调用！

```
渲染管线 (Bit 7 = 0, 标准15列编码)
    │
    ├─ 0x2DB58: ldrh r2, [r6, 6]     # 加载字体数据
    ├─ 0x2DB5E: str r0, [r7, 0x1c]    # 存储地址指针
    ├─ 0x2DB60: strh r6, [r0, r1]    # 存储像素数据！
    ├─ 0x2DB64: ldrh r0, [r7, 6]     # 加载更多数据
    └─ 0x2DB94: ldrsb r0, [r4, r1]   # 加载符号字节
```

---

## 关键指令序列

### 1. 像素数据加载 (0x2DB58)

```assembly
0x0002DB58:  ldrh   r2, [r6, #6]    ; 从 r6+6 加载16位数据
                                      ; r6 = 0x100000 + r5 × 4
```

### 2. 地址计算 (0x2DB5A-0x2DB5C)

```assembly
0x0002DB5A:  subs   r0, r0, #0x46   ; r0 = r0 - 0x46
0x0002DB5C:  lsls   r0, r6, #3      ; r0 = r6 << 3
```

### 3. 像素数据存储 (0x2DB5E-0x2DB60)

```assembly
0x0002DB5E:  str    r0, [r7, #0x1c]  ; 存储地址指针
0x0002DB60:  strh   r6, [r0, r1]    ; 存储像素数据到显示缓冲区
```

### 4. 符号字节加载 (0x2DB94)

```assembly
0x0002DB94:  ldrsb  r0, [r4, r1]    ; 加载符号字节并扩展
```

---

## 寄存器用途

| 寄存器 | 用途 | 证据 |
|--------|------|------|
| r6 | 字体数据指针 | `ldrh r2, [r6, #6]` |
| r7 | 渲染上下文 | `str r0, [r7, #0x1c]` |
| r4 | 符号表基址 | `ldrsb r0, [r4, r1]` |
| r1 | 偏移量/列索引 | `strh r6, [r0, r1]` |
| r2 | 临时数据 | `ldrh r2, [r6, #6]` |

---

## 渲染上下文结构分析

### 发现的所有 r7 内存访问

| 偏移 | 指令 | 用途 |
|------|------|------|
| **+0x06** | `ldrh r0, [r7, 6]` | 读取像素数据 |
| +0x06 | `strh r3, [r7, 6]` | 存储处理后的数据 |
| **+0x14** | `strh r7, [r7, 0x14]` | 存储状态/值 |
| **+0x1C** | `str r0, [r7, 0x1C]` | 存储地址指针 |

### 推导的数据结构

```c
struct rendering_context {
    uint16_t index_data;        // +0x04: 索引数据 (只读)
    uint16_t pixel_data;        // +0x06: 主要工作寄存器
    uint16_t status_or_counter;  // +0x14: 状态/计数器
    void* address_pointer;      // +0x1C: 地址指针
};
```

---

## LDSB 深度分析

### 发现的所有 ldrsb 指令

| 地址 | 指令 | 上下文 |
|------|------|--------|
| 0x2DB04 | `ldrsb r0, [r4, r1]` | 渲染循环开始 |
| 0x2DB94 | `ldrsb r0, [r4, r1]` | **关键位置** - 主渲染逻辑 |

### LDSB 语义

```
ldrsb Rt, [Rn, Rm]

操作：
  1. 计算地址 = Rn + Rm
  2. 从内存读取 1 字节
  3. 符号扩展到 32 位
  4. 更新标志位: N (负数), Z (零)
```

### 符号表数据模式

```
沨字符号表 @ 0x1FBC0:
  偶数索引: 0xCD = -51 (基准值)
  奇数索引: 0xDE, 0xDF, 0xE0, 0xE1... = -34, -33, -32, -31...
```

---

## 符号表地址计算

```
r4 = r5 << 5  (r5 × 32)
符号表地址 = r4

| 字符 | r5 | 符号表地址 |
|------|----|-----------|
| 沨 | 0x0FDE | 0x1FBC0 |
| 沤 | 0x0FDB | 0x1FB60 |
| 沪 | 0x0FDA | 0x1FB40 |
```

---

## 渲染流程伪代码

```c
void render_inline(
    uint16_t char_index,         // r5: 字符索引
    rendering_context* ctx,      // r7: 渲染上下文
    int column_index             // r1: 0-14
) {
    // 1. 计算符号表地址
    int8_t* symbol_table = (int8_t*)(char_index << 5);  // r4 = r5 * 32

    // 2. 加载该列的符号字节
    int8_t adjustment = symbol_table[column_index];     // ldrsb r0, [r4, r1]

    // 3. 计算中心偏移
    int center_offset = column_index - 7;               // subs r2, r7, #7

    // 4. 存储处理后的像素数据
    ctx->pixel_data = processed;  // strh r3, [r7, 6]
}
```

---

**参见**:
- [标准路径分析](./PATH_0x2DB58_STANDARD.md)
- [符号表机制](../04_DATA_DISCOVERY/UNICODE_LOOKUP_TABLE.md)
