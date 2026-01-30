# R0 寄存器 - 分支2数据来源

**状态**: ✅ 部分完成 - 追踪到函数参数
**创建日期**: 2026-01-29
**分析目标**: 追踪分支2 (r5 = 0xE9) 中 r0 的来源

---

## 关键发现

### r0 的来源链

```
函数参数 (r7)
    ↓
0x2DA94: eor r0, r7, #0x28    ; r0 = r7 XOR 0x28
    ↓
0x2DABA: lsrs r6, r0, #0x19    ; 使用 r0
0x2DABC: lsls r0, r0, #4       ; r0 = r0 << 4
    ↓
0x2DAC0: lsrs r5, r0, #0x10    ; r5 = r0 >> 16 (提取高16位)
```

### 关键结论

**r0 来自函数参数 r7**，通过异或操作初始化：
- `r0 = r7 XOR 0x28`

这意味着 **r7 包含编码的字符数据**，r5 从 r7 的高位提取。

---

## 完整代码流程

### 函数入口点分析

此函数有多个入口点（基于不同的条件）：

| 入口 | 条件 | 说明 |
|------|------|------|
| 0x2DA62 | 默认路径 | pop 返回 |
| 0x2DA6C | bls 条件 | r0 = r2 >> 3 |
| 0x2DA76 | bge 条件 | 直接跳转 |
| 0x2DA7E | bne 条件 | 循环结束 |
| 0x2DA82 | cbnz 条件 | 可能不可达 |
| 0x2DA88 | cbnz 条件 | 可能不可达 |
| 0x2DA92 | cbnz 条件 | pop 返回 |

### 主要代码路径

```assembly
; 入口汇聚点
0x2DA72: lsls r3, r7, #3
0x2DA74: lsls r1, r6, #0x19   ; r1 = r6 << 25
0x2DA76: movs r3, r4
0x2DA78: adds r2, #0x46
0x2DA7A: eors r6, r0          ; r6 = r6 XOR r0
0x2DA7C: lsls r0, r6, #3      ; r0 = r6 << 3
0x2DA7E: bne 0x2DA72          ; 循环回退
0x2DA80: b 0x2D3E8            ; 或继续到 0x2DA82

; 可选路径
0x2DA82-0x2DA8C: ... (正常流程不可达)
0x2DA8E: ldm r1!, {r3,r4,r5,r6,r7}  ; 从渲染上下文加载
0x2DA90: lsls r0, r4, #4
0x2DA92: pop {r3,r5,r6,r7,pc}   ; 函数返回

; 分支2 入口点 (r5 = 0xE9 情况)
0x2DA94: eor r0, r7, #0x28     ; ← r0 来源！
0x2DA98: asrs r7, r7, #0x12
0x2DA9A: movs r0, r4
0x2DA9C: strb r0, [r1, #0x15]
0x2DA9E: cmp r0, #0xb1
0x2DAA0: bics r0, r1
0x2DAA2: lsrs r0, r0, #0xe
0x2DAA4: strh r0, [r1, #4]
0x2DAA6: asrs r0, r0, #2
0x2DAA8: lsls r0, r4, #4
0x2DAAA: strb r7, [r0, #1]
0x2DAAC: movs r0, r4
0x2DAAE: lsrs r0, r0, #2
0x2DAB0: asrs r0, r0, #2
0x2DAB2: strb r7, [r0, #1]

; 0xE9 阈值检查
0x2DAB4: cmp r5, #0xe9        ; 比较 r5 与 0xE9
0x2DAB6: bne.w 0x3d21a        ; 如果 r5 ≠ 0xE9，跳转

; 分支2 继续 (r5 = 0xE9)
0x2DABA: lsrs r6, r0, #0x19   ; r6 = r0 >> 25
0x2DABC: lsls r0, r0, #4      ; r0 = r0 << 4
0x2DABE: ble 0x2da94          ; 如果 ≤ 0，跳回 0x2DA94
0x2DAC0: lsrs r5, r0, #0x10   ; r5 = r0 >> 16 ← 从 r0 提取 r5！
```

---

## r7 参数的含义

### 数据编码分析

由于 `r0 = r7 XOR 0x28`，且 r5 从 r0 的高16位提取，我们可以推断：

```
r7 包含编码后的字符数据：
- 高16位 → r5 (字符内部索引)
- 低16位 → 其他元数据
```

### 可能的编码格式

```c
struct encoded_char {
    uint16_t character_index;  // 高16位 → r5
    uint16_t metadata;         // 低16位 → r6, r7
};

// 或作为32位值：
uint32_t encoded_value = r7;
uint16_t r5 = (encoded_value ^ 0x28) >> 16;
```

---

## 关键问题

| 问题 | 状态 | 说明 |
|------|------|------|
| r0 在分支2的来源 | ✅ 已解决 | r0 = r7 XOR 0x28 |
| r7 参数的来源 | 🔴 未解决 | 需要查找调用此函数的代码 |
| 0x28 的含义 | ⚠️ 部分理解 | 可能是解密密钥或偏移值 |
| r5 与 Unicode 的关系 | 🔴 未解决 | 需要找到 Unicode → r7 的转换 |

---

## 下一步方向

### 优先级 1: 查找函数调用者

搜索 BL/BLX 指令跳转到以下地址：
- 0x2DA62 (主入口)
- 0x2DA6C, 0x2DA76, 0x2DA88, 0x2DA92 (替代入口)

这将帮助我们找到：
1. r7 参数是如何设置的
2. Unicode 字符如何转换为 r7

### 优先级 2: 分析 r7 加载模式 🆕

发现多个 r7 加载指令，可能与 Unicode 字符加载相关：

| 地址 | 指令 | 说明 |
|------|------|------|
| 0x28180 | `ldrh r7, [r6, #0x1a]` | 从 r6+0x1A 加载16位 |
| 0x28568 | `ldrh r7, [r5, #2]` | 从 r5+2 加载16位 |
| 0x2893A | `ldrh r7, [r1, #2]` | 从 r1+2 加载16位 |
| 0x28D30 | `ldrh r7, [r5, #0x32]` | 从 r5+0x32 加载16位 |

**注意**: `ldrh` (加载半字) 常用于 UTF-16 字符加载。需要追踪这些加载点的上游代码。

### 优先级 2: 理解 0xE9 阈值

- 为什么 0xE9 是特殊值？
- r5 = 0xE9 时的特殊处理是什么？

### 优先级 3: 分析其他分支

- 分支1 (r5 ≠ 0xE9) 的 r0 来源
- 其他入口点的 r0 来源

---

## 相关文档

- [E9 阈值分析](./E9_THRESHOLD_ANALYSIS.md)
- [R5 字符索引](./R5_CHARACTER_INDEX.md)
- [R6 像素数据指针](./R6_PIXEL_DATA_POINTER.md)
- [R1 渲染上下文指针](./R1_RENDER_CONTEXT_POINTER.md)
- [未解决问题](../../01_OVERVIEW/REMAINING_WORK.md)
