# 指令级追踪

**状态**: ✅ 已记录
**最后更新**: 2026-01-28

---

## 关键追踪点

### 1. Unicode → r5 映射

```assembly
; 映射函数入口 (位置未知)
0x2CFC8: subs r0, r6, r7    ; r0 = r6 - r7 (执行 Unicode - 偏移量)
0x2CFB8: pop {r3, r5, r6, r7, pc}
```

### 2. 渲染函数入口 (0x2D3C6)

```assembly
0x0002D3C6:  push   {r0, r1, r2, r3, r4, r5, r6, r7}
0x0002D3C8:  movs   r2, r4
0x0002D3CA:  lsrs   r1, r4, #0x10
0x0002D3CC:  asrs   r6, r0, #1
0x0002D3D0:  ldm    r3, {r0, r1, r2, r3, r4, r5, r6, r7}
```

### 3. 内联渲染入口 (0x2DA88)

```assembly
0x0002DA8E:  ldm    r1!, {r3, r4, r5, r6, r7}  ; r5 = [r1 + 8]
0x0002DAD4:  movs   r4, r5                     ; r4 = r5
0x0002DB10:  lsls   r0, r4, #4                 ; r0 = r4 << 4
0x0002DB12:  cmp    r0, #0x80                  ; 测试编码类型
0x0002DB2C:  bne    #0x2db4e                   ; 条件分支
```

### 4. 符号表计算 (0x2DB74)

```assembly
0x0002DB74:  lsls   r4, r5, #5                 ; r4 = r5 * 32
0x0002DB78:  subs   r1, r1, #0xf               ; r1 = r1 - 15
0x0002DB94:  ldrsb  r0, [r4, r1]               ; 加载符号字节
```

### 5. 像素数据加载 (0x2DB58)

```assembly
0x0002DB58:  ldrh   r2, [r6, #6]               ; 从 r6+6 加载16位数据
0x0002DB5E:  str    r0, [r7, #0x1c]
0x0002DB60:  strh   r6, [r0, r1]               ; 存储像素数据
```

---

## 寄存器生命周期追踪

### r5 寄存器

```
1. Unicode 输入
    │
    ▼
2. 映射函数: r5 = Unicode - 偏移量
    │
    ▼
3. 存储到渲染上下文: [r1 + 8] = r5
    │
    ▼
4. 渲染时加载: ldm r1!, {r3, r4, r5, r6, r7}
    │
    ▼
5. 计算符号表: r4 = r5 << 5
    │
    ▼
6. ldrsb r0, [r4, r1]  → 加载符号字节
```

### r6 寄存器

```
1. r6 = 0x100000 + r5 × 4
    │
    ▼
2. ldrh r2, [r6, #6]  → 加载像素数据 (跳过 6 字节元数据)
```

### r7 寄存器 (渲染上下文)

```
1. r7 = 渲染上下文指针
    │
    ▼
2. str r0, [r7, #0x1c]  → 存储地址指针
    │
    ▼
3. ldrh r0, [r7, #6]    → 读取像素数据
```

---

## 分支条件追踪

### 编码类型判定 (0x2DB12)

```assembly
0x2DB10: lsls r0, r4, #4      ; r0 = r4 << 4
0x2DB12: cmp r0, #0x80        ; 比较 r0 与 0x80

分支逻辑:
  如果 r0 < 0x80 (Bit 7 = 0): Z=1, bne 不跳转 → 继续执行 0x2DB2E
  如果 r0 >= 0x80 (Bit 7 = 1): Z=0, bne 跳转 → 跳到 0x2DB4E
```

### 列处理循环 (0x2DB9A)

```assembly
0x2DB94: ldrsb r0, [r4, r1]    ; 加载符号字节
0x2DB96: subs r2, r7, #7       ; 计算中心偏移
0x2DB98: strh r3, [r7, #6]     ; 存储结果
0x2DB9A: cbnz r1, #0x2dc1a     ; 循环条件
```

---

## 指令统计

| 指令类型 | 数量 | 用途 |
|----------|------|------|
| CMP #128 | 133 | Bit 7 测试 |
| revsh | 16 | 字节交换 |
| ldrsb | 6 | 符号扩展 |
| ldrh/strh | 密集 | 16 位像素操作 |

---

**参见**:
- [内联渲染逻辑](./INLINE_RENDERING.md)
- [数据结构定义](../02_ARCHITECTURE/DATA_STRUCTURES.md)
