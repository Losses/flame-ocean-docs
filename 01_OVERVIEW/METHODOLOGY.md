# 分析方法论

**状态**: ✅ 已记录
**最后更新**: 2026-01-28

---

## 工具

| 工具 | 用途 |
|------|------|
| rizin/radare2 | 函数分析、交叉引用查找 |
| capstone | ARM Thumb 指令解码 |
| Ghidra | 函数识别和反编译 |
| Python | 数据提取和验证 |

### Python 依赖包

分析所需的外部包（通过 pip 安装）：

| 包名 | 用途 |
|------|------|
| `capstone` | ARM Thumb 指令解码 |
| `pyhidra` | Ghidra Python 原生集成 |
| `ghidra-bridge` | Ghidra 远程桥接 |
| `r2pipe` | radare2/rizin Python 管道 |
| `rzpipe` | rizin Python 管道 |


### Ghidra 项目

**项目位置**: `ghidra_project/ECHO_PROJECT/`

```
ghidra_project/
├── ECHO_PROJECT.gpr          # Ghidra 项目文件
└── ECHO_PROJECT.rep/          # 项目仓库
    ├── idata/                 # 中间数据
    ├── user/                  # 用户分析数据
    ├── versioned/             # 版本控制数据
    └── project.prp            # 项目属性
```

使用 Ghidra GUI 或 analyzeHeadless 可直接打开此项目进行分析。

---

## 分析步骤

### 1. 固件预处理

```bash
# 使用 03-fixer.py 处理固件
python 03-fixer.py HIFIEC10.IMG HIFIEC10_Fixed.bin
```

### 2. 函数分析

```bash
# 使用 rizin 进行函数分析
rizin -a arm -b 16 HIFIEC10_Fixed.bin

# 使用 Ghidra analyzeHeadless 识别函数
analyzeHeadless HIFIEC10_Fixed.bin -import
```

### 3. 数据分析

- 统计各表首字节分布规律
- 对比好坏字符在序列位置上的差异
- 用已知样本文件验证不同编码假设

### 4. 代码追踪

- 追踪关键寄存器数据流
- 分析分支条件
- 验证指令序列

---

## 关键发现路径

### 发现 1: Bit 7 测试位置

```
0x2DAC8: cmp r2, #0x80     ; CMP #128 (bit 7 test!)
0x2DB12: cmp r0, #0x80     ; CMP #128 (bit 7 test!)
```

### 发现 2: 字节交换机制

```
0x2DB0A: revsh r1, r6      ; Reverse half-word with sign extension
0x2DB2A: revsh r1, r6      ; Reverse half-word with sign extension
```

### 发现 3: 像素数据位置

```
r6 = 0x100000 + r5 × 4
ldrh r2, [r6, #6]  ; 从 r6+6 加载像素数据
```

### 发现 4: Unicode 映射

```
U+6CA8 → r5 = 0x0FDE  (差值: -0x5CCA)
r5 = Unicode - 偏移量
```

---

## 验证方法

### 数据验证

对比多个假设地址的数据模式：

| 假设 | 公式 | 数据特征 | 结果 |
|------|------|----------|------|
| r5 × 4 | 0x103F78 | 高非零密度，有意义位图 | ✅ 正确 |
| r5 × 2 | 0x101FBC | 重复模式 (2A A5 00 00...) | ✗ 错误 |
| r5 × 1 | 0x100FDE | 低密度 | ✗ 错误 |

### 代码验证

使用 Capstone 精确解码，验证 rizin 的反汇编结果：

| 工具 | 指令 | 目标地址 |
|------|------|----------|
| rizin | `ldr r7, [0x0002dff0]` | 0x2dff0 |
| Capstone | `ldr r7, [pc, #0x3c0]` | 0x2DFF2 |

**结论**: Capstone 的 PC-relative 地址计算是正确的

---

## 已拒绝的方法

| 方法 | 结果 | 结论 |
|------|------|------|
| 偏移读取假设 | 14.3% 匹配率 | ❌ 证伪 |
| strh/ldrh 密集区搜索 | 找到区域但无有效代码 | ❌ 数据区域 |
| 语言表引用搜索 | 未找到直接指针 | ❓ 可能间接访问 |

---

**参见**: [失败的假设](../06_FAILED_HYPOTHESES/WRONG_ASSUMPTIONS.md)
