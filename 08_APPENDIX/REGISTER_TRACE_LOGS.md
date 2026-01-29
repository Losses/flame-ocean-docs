# 寄存器追踪日志

**状态**: ✅ 已记录
**最后更新**: 2026-01-28

---

## r5 寄存器完整生命周期

### 1. Unicode 输入

```
输入: U+6CA8 (沨)
```

### 2. 映射函数

```assembly
; 映射函数 (位置未知)
0x2CFC8: subs r0, r6, r7    ; r0 = r6 - r7 (执行 Unicode - 偏移量)
```

```
r0 = 0x6CA8 - 0x5CCA = 0x0FDE
```

### 3. 存储到渲染上下文

```assembly
0x2D040: str r0, [r5, #4]   ; 将 r5 存储到渲染上下文
```

### 4. 渲染时加载

```assembly
0x0002DA8E:  ldm    r1!, {r3, r4, r5, r6, r7}  ; r5 = [r1 + 8]
```

### 5. 计算符号表

```assembly
0x0002DAD4:  movs   r4, r5                     ; r4 = r5
0x0002DB74:  lsls   r4, r5, #5                 ; r4 = r5 * 32
```

```
r4 = 0x0FDE << 5 = 0x1FBC0
```

### 6. 加载符号字节

```assembly
0x0002DB94:  ldrsb  r0, [r4, r1]                ; 从符号表加载
```

---

## r6 寄存器追踪

### 计算公式

```
r6 = 0x100000 + r5 × 4
```

### 沨字示例

```
r5 = 0x0FDE
r6 = 0x100000 + 0x0FDE × 4 = 0x100000 + 0x3F78 = 0x103F78
```

### 像素数据加载

```assembly
0x0002DB58:  ldrh   r2, [r6, #6]    ; 从 r6+6 加载16位数据
```

---

## r7 寄存器 (渲染上下文) 追踪

### 初始化

```assembly
0x2DA94: eor r0, r7, #0x28
0x2DABA: lsrs r6, r0, #0x19
0x2DABC: lsls r0, r0, #4
0x2DAC0: lsrs r5, r0, #0x10
0x2DAC2: asrs r6, r0, #0x1d
0x2DAC6: movs r2, r0
```

### 使用

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
