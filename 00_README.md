# ECHO MINI V3.1.0 字体渲染分析文档

**固件**: HIFIEC10.IMG / HIFIEC10_Fixed.bin
**架构**: ARM Cortex-M (Rockchip RKnano)
**大小**: 33 MB (0x2000004 字节)
**最后更新**: 2026-01-28

---

## 快速导航：从零到渲染完整流程

本文档库按照分析流程组织，从发现问题到完全理解渲染机制。按顺序阅读即可掌握整个系统。

---

### 第一阶段：理解问题

如果你想了解**原始问题是什么**，或者**为什么字体提取会出错**：

1. **[问题描述](./01_OVERVIEW/PROBLEM_STATEMENT.md)** - 用户报告的字体问题
   - 小号字体：所有带 `+U` 后缀的字符都是坏字
   - 大号字体：特定文件损坏
   - 观察到的模式：好、坏、好、坏交替出现

2. **[执行摘要](./01_OVERVIEW/EXECUTIVE_SUMMARY.md)** - 核心发现摘要
   - 像素数据位置: `0x100000 + r5 × 4`
   - 编码判定: `metadata[0] >> 4 >= 8`
   - 两条渲染路径的关系

---

### 第二阶段：系统架构

如果你想了解**固件的内存布局**和**数据结构**：

1. **[内存布局图](./02_ARCHITECTURE/MEMORY_MAP.md)** - 固件地址映射
   ```
   0x000000 - 0x460:     Boot Header
   0x100000:              字体数据基址
   0x14AD6:               偏移表
   0x778000:              语言表 (日本語、繁體中文... UTF-16 BE)
   ```

2. **[数据结构定义](./02_ARCHITECTURE/DATA_STRUCTURES.md)** - 关键数据结构
   ```c
   struct character_data {
       uint8_t metadata[6];     // 元数据
       uint16_t row_data[16];   // 像素位图 (16行×16位)
   };
   ```

3. **[语言表发现](./04_DATA_DISCOVERY/LANGUAGE_TABLE.md)** - UTF-16 字符串表
   ```
   0x778666: 65 E5 67 2C 8A 9E → 日本語
   0x778462: 7E 41 9A D4 4E 2D → 繁體中文
   ```

4. **[寄存器参考](./02_ARCHITECTURE/REGISTER_REFERENCE.md)** - 渲染过程中使用的寄存器
   | 寄存器 | 用途 | 查看文档 |
   |--------|------|----------|
   | r5 | Unicode → 内部索引 | [Unicode查找表](./04_DATA_DISCOVERY/UNICODE_LOOKUP_TABLE.md) |
   | r6 | 字体数据指针 @ 0x100000 + r5 × 4 | [像素数据位置](./04_DATA_DISCOVERY/PIXEL_DATA_LOCATION.md) |
   | r7 | 渲染上下文 / 基址指针 | [数据结构定义](./02_ARCHITECTURE/DATA_STRUCTURES.md) |
   | r4 | 首字节高4位 / 符号表指针 | [内联渲染逻辑](./03_CODE_ANALYSIS/INLINE_RENDERING.md) |
   | r0, r1, r2, r3 | 临时寄存器和参数 | [指令级追踪](./03_CODE_ANALYSIS/INSTRUCTION_TRACE.md) |

5. **[渲染管线总览](./02_ARCHITECTURE/RENDERING_PIPELINE.md)** - 完整渲染流程
   ```
   Unicode → r5映射 → r6计算 → 编码判定 → 像素加载 → 显示缓冲区
   ```

---

### 第三阶段：从 Unicode 到字符数据

如果你想了解**如何从 Unicode 找到字符数据**：

1. **[Unicode查找表](./04_DATA_DISCOVERY/UNICODE_LOOKUP_TABLE.md)** → 映射关系
   - 已知映射: U+6CA8 (沨) → r5=0x0FDE, 差值=-0x5CCA
   - 映射公式: `r5 = Unicode - 0x5CCA + sub_offset`

2. **[调试用字符表](./04_DATA_DISCOVERY/DEBUG_CHARACTER_TABLE.md)** → 31个已知字符映射
   - 0x44xxxx 范围: 寸、出、岑、岌、岈
   - 0x46xxxx 范围: 氵部系列 (26个字符)

---

### 第四阶段：代码路径与寄存器分析

如果你想了解**渲染代码如何工作**：

**代码路径**:
1. **[标准路径分析](./03_CODE_ANALYSIS/PATH_0x2DB58_STANDARD.md)** - 主渲染路径
2. **[0x13365E 函数分析](./03_CODE_ANALYSIS/FUNCTION_0x13365E.md)** - 孤立函数 (未被调用)
3. **[特殊路径分析](./03_CODE_ANALYSIS/PATH_0x2DC22_SPECIAL.md)** - 死代码路径
4. **[内联渲染逻辑](./03_CODE_ANALYSIS/INLINE_RENDERING.md)** - 内联代码分析

**寄存器详细分析**:
5. **[R0 - Bit 7 测试](./03_CODE_ANALYSIS/REGISTERS/R0_BIT7_TEST.md)** - 编码类型判定
6. **[R2 - 函数参数](./03_CODE_ANALYSIS/REGISTERS/R2_PARAMETER.md)** - 参数传递与测试载体
7. **[R3 - 行索引](./03_CODE_ANALYSIS/REGISTERS/R3_ROW_INDEX.md)** - 行索引与偏移量
8. **[R4 - 符号表指针](./03_CODE_ANALYSIS/REGISTERS/R4_SYMBOL_TABLE.md)** - 符号表计算
9. **[指令级追踪](./03_CODE_ANALYSIS/INSTRUCTION_TRACE.md)** - 综合追踪

---

### 第五阶段：数据发现

如果你想了解**像素数据在哪里**和**编码规则**：

1. **[像素数据位置](./04_DATA_DISCOVERY/PIXEL_DATA_LOCATION.md)**
   ```
   r6 = 0x100000 + r5 × 4
   像素数据从 r6 + 6 开始 (跳过6字节元数据)
   ```

2. **[编码规则](./04_DATA_DISCOVERY/ENCODING_RULES.md)** - 标准 vs 特殊编码
   - 标准 (15列): `metadata[0] >> 4 < 8`
   - 特殊 (14列): `metadata[0] >> 4 >= 8`

3. **[元数据分析](./04_DATA_DISCOVERY/METADATA_ANALYSIS.md)** - 元数据结构
   - Bit 7-4: 编码类型标志
   - Bit 3-0: 不被使用

---

### 第六阶段：验证与调试

如果你想**验证自己的分析**或**调试字体提取**：

1. **[验证数据](./05_VERIFICATION/VERIFICATION_DATA.md)** - 测试样本和已知字符映射
   - 用户提供的测试样本 (好/坏字符)
   - 31 个调试用字符映射数据
   - 扫描公式验证结果
   - Unicode 到 r5 映射验证

---

### 第七阶段：工具使用

如果你想**使用工具进行分析**：

1. **[分析方法论](./01_OVERVIEW/METHODOLOGY.md)** - 工具和步骤
   - rizin/radare2, capstone, Ghidra
   - Python 依赖: capstone, pyhidra, ghidra-bridge, r2pipe, rzpipe

2. **[分析脚本索引](./07_TOOLS_AND_SCRIPTS/ANALYSIS_SCRIPTS.md)** - Python 脚本
   - 03-fixer.py, angr_symbolic_analysis.py 等

3. **[调试指南](./07_TOOLS_AND_SCRIPTS/DEBUGGING_GUIDE.md)** - 常用调试命令

---

### 第八阶段：失败的尝试

如果你想**避免重复踩坑**：

1. **[错误假设记录](./06_FAILED_HYPOTHESES/WRONG_ASSUMPTIONS.md)** - 已证伪的假设
   - ❌ 错位读取假设 (14.3% 匹配率)
   - ❌ 0x96 标记假设
   - ❌ 0x80 偏移问题

2. **[废弃代码路径](./06_FAILED_HYPOTHESES/DEAD_CODE_PATHS.md)** - 0x2DC22 死代码分析

---

## 核心发现速查

### 已确认的机制

| 发现 | 公式/位置 | 状态 |
|------|----------|------|
| 像素数据位置 | `0x100000 + r5 × 4` | ✅ |
| 编码判定 | `metadata[0] >> 4 >= 8` | ✅ |
| Unicode 映射 | `r5 = Unicode - 偏移量` | ✅ |
| 主渲染路径 | 0x2DB58 | ✅ |
| 0x2DC22 路径 | 死代码，不执行 | ✅ |

### 待解决问题

## 待解决问题

详细的未解决问题已汇总到 **[REMAINING_WORK.md](./01_OVERVIEW/REMAINING_WORK.md)**，按渲染流程的 6 个阶段组织：

| 阶段 | 主要问题 |
|------|----------|
| 阶段 1 | Unicode → r5 映射函数位置、offset() 函数实现 |
| 阶段 3 | 符号表数据用途、14 列编码的像素布局 |
| 阶段 4 | r2, r3, r0 寄存器的精确用途 |
| 阶段 5 | metadata[2], [4], [5] 的功能 |
| 阶段 6 | 4 个缺失字符的像素数据 |

---

## 原始文档归档

以下大文档已被拆分到此结构中：

- `@FONT_RENDERING_ANALYSIS.md` → 分布在多个章节
- `0x2DC22_PATH_ANALYSIS.md` → `03_CODE_ANALYSIS/PATH_0x2DC22_SPECIAL.md`
- `INLINE_RENDERING_ANALYSIS.md` → `03_CODE_ANALYSIS/INLINE_RENDERING.md`
- `PIXEL_DATA_DISCOVERY.md` → `04_DATA_DISCOVERY/`
- `legacy/MAPPING_REPORT_2026-01-28.md` → `04_DATA_DISCOVERY/DEBUG_CHARACTER_TABLE.md`
