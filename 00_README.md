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
   struct character_entry {
       uint16_t pixel_data[16];     // 16 行像素数据 (每行 2 字节)
       uint16_t metadata[16];       // 16 行元数据 (每行 2 字节)
   };
   // 总计: 16 行 × 4 字节 = 64 字节/字符
   // 位置: 0x100000 + char_idx × 64
   ```

3. **[字符串表发现](./04_DATA_DISCOVERY/LANGUAGE_TABLE.md)** - UTF-16 字符串表
   ```
   语言选择 @ 0x778000: 日本語、繁體中文
   UI菜单 @ 0x79B084-0x79C000: 16个英文UI字符串 (Music Playback, Equalizer, Tools...)
   ```
   ⚠️ **注意**: 详见[代码引用搜索记录](./04_DATA_DISCOVERY/LANGUAGE_TABLE.md#第三部分代码引用搜索的详细记录-重要) - 尝试了8种方法未找到访问代码

4. **[寄存器参考](./02_ARCHITECTURE/REGISTER_REFERENCE.md)** - 渲染过程中使用的寄存器
   | 寄存器 | 用途 | 查看文档 |
   |--------|------|----------|
   | r5 | Unicode → 内部索引 | [Unicode→r5映射](./04_DATA_DISCOVERY/UNICODE_TO_R5_MAPPING.md) |
   | r6 | 像素数据指针 ⚠️ 计算公式未找到 | [R6像素数据指针](./03_CODE_ANALYSIS/REGISTERS/R6_PIXEL_DATA_POINTER.md) |
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

1. **[Unicode→r5映射](./04_DATA_DISCOVERY/UNICODE_TO_R5_MAPPING.md)** → 映射关系
   - 转换代码未找到
   - 观察到的数据模式: U+6CA8 (沨) → r5=0x0FDE
   - 找到 `subs r0, #0x5d` @ 0x13E024，但未确认与 Unicode 的关系

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

---

### 🔴 第五阶段：关键缺口分析（最新）

**⚠️ 重要发现** (2026-01-29): 存在数据验证公式与代码证据之间的关键缺口

1. **[关键缺口分析](./05_CURRENT_STATUS/CRITICAL_GAP_ANALYSIS.md)** - **🔴 必读**
   - **已验证公式** (数据证据 ✅):
     - `r5 = Unicode >> 2` - 代码证据位于 0x02D4E6
     - `pixel_addr = 0x100000 + r5 * 4` - 数据验证通过 (沨/婔/福 字符)
   - **缺失代码** (代码证据 ❌):
     - 未找到实现 `pixel_addr = 0x100000 + r5 * 4` 的代码
     - 未找到访问 0x100000 区域的代码
     - 未找到包含 0x106CA8 等像素地址的指针表
   - **可能解释**:
     - 硬件内存映射机制
     - 未分析的代码区域
     - 间接访问机制
     - 运行时代码生成

2. **[假设验证报告](./01_OVERVIEW/HYPOTHESIS_VERIFICATION.md)** - 三种假设的验证结果
   - ✅ 假设 1: `r5 = Unicode >> 2` - **验证正确**
   - ✅ 假设 2: `pixel_addr = 0x100000 + r5 * 4` - **验证正确**
   - ❌ 假设 3: DMA 复制理论 - **证伪**

**寄存器详细分析**:
> **📁 REGISTERS 目录**: [docs/03_CODE_ANALYSIS/REGISTERS/](./03_CODE_ANALYSIS/REGISTERS/) - 包含所有寄存器的完整分析文档

| 寄存器 | 用途 | 文档 |
|--------|------|------|
| r0 | Bit 7 测试、数据加载 | [R0_BIT7_TEST.md](./03_CODE_ANALYSIS/REGISTERS/R0_BIT7_TEST.md) |
| r2 | 函数参数、Bit 7 测试载体 | [R2_PARAMETER.md](./03_CODE_ANALYSIS/REGISTERS/R2_PARAMETER.md) |
| r3 | 行索引、偏移量 | [R3_ROW_INDEX.md](./03_CODE_ANALYSIS/REGISTERS/R3_ROW_INDEX.md) |
| r4 | 编码判定、符号表指针 | [R4_SYMBOL_TABLE.md](./03_CODE_ANALYSIS/REGISTERS/R4_SYMBOL_TABLE.md) |
| **r5** | **字符内部索引** | [R5_CHARACTER_INDEX.md](./03_CODE_ANALYSIS/REGISTERS/R5_CHARACTER_INDEX.md) |
| **r6** | **像素数据指针 ⚠️** | [R6_PIXEL_DATA_POINTER.md](./03_CODE_ANALYSIS/REGISTERS/R6_PIXEL_DATA_POINTER.md) ⚠️ **需更正**: 之前分析基于死代码，实际使用 r4 << 16 |
| **r7** | **渲染上下文基址** | [R7_RENDER_CONTEXT.md](./03_CODE_ANALYSIS/REGISTERS/R7_RENDER_CONTEXT.md) |

10. **[指令级追踪](./03_CODE_ANALYSIS/INSTRUCTION_TRACE.md)** - 综合追踪

---

### 第五阶段：数据发现

如果你想了解**像素数据在哪里**和**编码规则**：

1. **[像素数据位置](./04_DATA_DISCOVERY/PIXEL_DATA_LOCATION.md)** ✅ **已验证** (2026-01-29 更新)
   ```
   符号表基址: 0x100000
   每字符: 64 字节 (16 行 × 4 字节/行)
   像素数据: 每行前 2 字节
   寻址: 字符 N = 0x100000 + N × 64
   ```

2. **[编码规则](./04_DATA_DISCOVERY/ENCODING_RULES.md)** - 标准 vs 特殊编码
   - 标准 (15列): `metadata[0] >> 4 < 8`
   - 特殊 (14列): `metadata[0] >> 4 >= 8`

3. **[14列编码像素布局](./04_DATA_DISCOVERY/14COL_PIXEL_LAYOUT.md)** ✅ **新增**
   - 基于固件逆向工程的完整分析
   - Capstone 反汇编证据
   - 像素提取方法（含沦字数据分析）

3. **[4个字符像素数据分析](./04_DATA_DISCOVERY/MISSING_CHARS_FINAL_ANALYSIS.md)** ✅ **已解决**
   - 沨、沤、沦、沪的像素数据位置和验证
   - 正确的像素提取方法（odd/even交换，14列）
   - 数据有效性验证（100%准确率）

4. **[元数据分析](./04_DATA_DISCOVERY/METADATA_ANALYSIS.md)** - 元数据结构
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
   - Python 包使用指南 (Capstone, rzpipe, r2pipe, angr, pyhidra, ghidra-bridge)
   - 完整的代码示例和实际输出

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
   - ❌ "行交错"字体格式假设 (2026-01-29) - 基于猜测而非汇编代码证据

2. **[废弃代码路径](./06_FAILED_HYPOTHESES/DEAD_CODE_PATHS.md)** - 0x2DC22 死代码分析

---

## 核心发现速查

### 已确认的机制

| 发现 | 公式/位置 | 状态 |
|------|----------|------|
| **Unicode → r5 映射** | `r5 = Unicode >> 2` @ 0x02D4E6 | ✅ 已验证 (2026-01-29) |
| **像素地址公式** | `0x100000 + (Unicode >> 2) * 4` | ✅ 已验证 (2026-01-29) |
| 像素数据加载 | `ldrh r2, [r6, #6]` @ 0x2DB58 | ✅ 已确认 |
| 编码判定 | `metadata[0] >> 4 >= 8` | ✅ 已确认 |
| **0x2D680 死代码确认** | 调用者搜索: 0 条引用 | ✅ 已确认 (2026-01-29) |
| ~~Unicode 映射~~ | ~~观察到 U+6CA8 → r5=0x0FDE~~ | ❌ **已更正** (2026-01-29) |
| ~~r6 计算公式~~ | ~~`r6 = 0x100000 + r5 × 4` 计算代码~~ | ❌ **未找到代码证据** |
| 主渲染路径 | 0x2DB58 | ✅ 已确认 |
| 0x2DC22 路径 | 死代码，不执行 | ✅ 已确认 |

### 验证报告 (2026-01-29)

**独立验证报告**: [SOLUTION_VERIFICATION_2026-01-29.md](./01_OVERVIEW/SOLUTION_VERIFICATION_2026-01-29.md)
- ✅ Unicode → r5 映射代码已通过 Capstone 验证
- ✅ 像素地址公式已通过 5 个测试字符验证
- ✅ 0x2D680 确认为死代码（无调用者）
- ❌ 之前的 `U+6CA8 → r5=0x0FDE` 假设错误
- ❌ 之前的 `offset(u_lo)` 复杂公式错误

| 发现 | 公式/位置 | 状态 |
|------|----------|------|
| 像素数据加载 | `ldrh r2, [r6, #6]` @ 0x2DB58 | ✅ 已确认 |
| 编码判定 | `metadata[0] >> 4 >= 8` | ✅ 已确认 |
| Unicode 映射 | 观察到 U+6CA8 → r5=0x0FDE | ⚠️ 仅数据观察 |
| **真实渲染路径** | **`r1 = r4 << 16` @ 0x2D3E8** | ✅ **已确认 (2026-01-29 更正)** |
| **0x2D680 函数** | **死代码，无调用者** | ✅ 已确认 (2026-01-29) |
| ~~r6 LDM 加载~~ | ~~`ldm r1!, {r3,r4,r5,r6,r7}` @ 0x02DA8E~~ | ❌ **已证伪 (2026-01-29)**: 位于死代码区域 |
| ~~r6 << 25~~ | ~~`lsls r1, r6, #0x19` @ 0x2DA84~~ | ❌ **已证伪 (2026-01-29)**: 位于死代码区域 |
| 主渲染路径 | 0x2DB58 | ✅ 已确认 |
| 0x2DC22 路径 | 死代码，不执行 | ✅ 已确认 |

### 假设验证研究 (2026-01-29)

| 假设 | 结果 | 证据等级 |
|------|------|----------|
| 假设1: 函数指针表 | ❌ 不正确 | ✅ 代码证据 |
| 假设2: Unicode 范围检测 | ❌ 不正确 | ✅ 代码证据 |
| 假设4: 预编码字符数据 | ⚠️ 部分 | ⚠️ 数据存在 |
| 假设6: Rockchip SDK 机制 | ✅ 部分 | ✅ 数据存在 |
| 假设7: 0x13E024 映射指令 | ❌ 不正确 | ✅ 代码证据 |

**详细分析**: [UNICODE_TO_R5_MAPPING.md](./04_DATA_DISCOVERY/UNICODE_TO_R5_MAPPING.md#第六部分假设验证研究-2026-01-29)

**结论**: 经过 7 个假设的全面验证，**Unicode → r5 映射代码仍未找到**。

---

### 待解决问题

详细的未解决问题已汇总到 **[REMAINING_WORK.md](./01_OVERVIEW/REMAINING_WORK.md)**，按渲染流程的 6 个阶段组织：

| 阶段 | 主要问题 |
|------|----------|
| 阶段 1 | Unicode → r5 映射函数位置、offset() 函数实现 |
| ~~阶段 2~~ | ~~r6 计算公式~~ ✅ **已解决 (2026-01-29)**: r6 通过 LDM 从渲染上下文加载 |
| 阶段 2 (新) | r6_param 参数来源、渲染上下文数组位置 |
| 阶段 3 | 符号表数据用途、14列编码的像素布局 |
| 阶段 4 | r2, r3, r0 寄存器的精确用途 |
| 阶段 5 | metadata[2], [4], [5] 的功能 |

**已解决的问题**:
- ✅ 阶段 6: 4个缺失字符的像素数据 (问题6.1) - 像素数据存在于固件中
- ✅ **阶段 2 (2026-01-29)**: **r6 加载机制** - 通过 LDM 从渲染上下文结构加载，详见 [R6 像素数据指针](./03_CODE_ANALYSIS/REGISTERS/R6_PIXEL_DATA_POINTER.md)

**⚠️ 需要重新研究**:
- ❌ ~~r6 计算公式~~ - 已证伪：`r6 = 0x100000 + r5 × 4` 未找到代码证据
- ❌ 阶段 3: 14列编码的像素布局 (问题3.3) - 之前的分析违反了方法论，需要基于代码证据重新分析

---

## 分析方法论 ⚠️ 重要

本项目的分析过程中发现了方法论问题，详细记录在 **[方法论经验教训](./01_OVERVIEW/METHODOLOGY_LESSONS.md)**。

### 核心原则

**从已知代码点开始，追踪数据流，只文档化能证明的东西。**

### 证据等级

| 等级 | 描述 | 示例 |
|------|------|------|
| ✅ 已确认 | 有完整代码证据链 | `0x100000 + r5 × 4` |
| ⚠️ 指令存在 | 找到指令但功能未知 | `subs r0, #0x5d` @ 0x13E024 |
| ⚠️ 数据存在 | 找到数据但用途未知 | 语言表 @ 0x778000 |
| ⚠️ 从数据反推 | 从像素位置反推的模式 | U+6CA8 → r5=0x0FDE |
| ❓ 假设 | 未验证的理论 | offset() 函数公式 |

### 常见错误

- ❌ 把"看起来像"等同于"确实是"
- ❌ 从数据拟合推导"公式"
- ❌ 假设代码功能而不追踪数据流
- ✅ 从已知代码点开始追踪
- ✅ 确认每一步的数据流
- ✅ 诚实地区分观察、假设和证明

---

## 原始文档归档

以下大文档已被拆分到此结构中：

- `@FONT_RENDERING_ANALYSIS.md` → 分布在多个章节
- `0x2DC22_PATH_ANALYSIS.md` → `03_CODE_ANALYSIS/PATH_0x2DC22_SPECIAL.md`
- `INLINE_RENDERING_ANALYSIS.md` → `03_CODE_ANALYSIS/INLINE_RENDERING.md`
- `PIXEL_DATA_DISCOVERY.md` → `04_DATA_DISCOVERY/`
- `legacy/MAPPING_REPORT_2026-01-28.md` → `04_DATA_DISCOVERY/DEBUG_CHARACTER_TABLE.md`

### 已整合的验证报告 (2026-01-29)

`SOLUTION_VERIFICATION_2026-01-29.md` 的内容已整合到以下文档：

- **R5_CHARACTER_INDEX.md** - Unicode → r5 映射验证 (`r5 = Unicode >> 2` @ 0x02D4E6)
- **PIXEL_DATA_LOCATION.md** - 像素地址公式验证 (5 个测试字符)
- **DEAD_CODE_PATHS.md** - 0x2D680 死代码确认
- **WRONG_ASSUMPTIONS.md** - 之前的错误假设 (U+6CA8 → r5=0x0FDE 等)
- **EXECUTIVE_SUMMARY.md** - 核心发现更新
- **RENDERING_PIPELINE.md** - 渲染管线更新
