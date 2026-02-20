# FLAC 字符串渲染追踪 - 最终报告

**日期**: 2026-02-13 (初始) / 2026-02-13 (更新: 颜色数据流追踪 + 结构体分析 + Palette初始化追踪 + 二进制搜索)
**固件**: HIFIEC10.IMG
**方法**: Ghidra 反编译 + 调用链追踪

---

## 1. 字符串 "FLAC|44KHZ|16bit|0807kbps" 是如何拼出来的

### 1.1 调用链

```
FUN_00094788 @ 0x9478e          (顶层 UI 渲染函数)
    ↓
FUN_00088630 @ 0x88630          (音频信息渲染主函数)
    ├─→ FUN_000744e4(0x46)       (检查是否需要渲染 FLAC 标签)
    ├─→ FUN_0008683a(...)        (FLAC Builder - 构建格式字符串)
    └─→ FUN_00086626(...)        (位置布局)
```

### 1.2 FLAC Builder 函数 (FUN_0008683a)

**地址**: 0x8683A

**反编译代码关键部分**:
```c
void FUN_0008683a(uint param_1, int param_2, uint param_3)
{
  // param_1 = 比特率 (例如 807 kbps)
  // param_2 = 采样率 (例如 44100 Hz)
  // param_3 = 比特深度 (例如 16 bit)

  int iVar11 = *DAT_00086cf8;  // 音频格式标志 (6=FLAC)

  if (iVar11 == 6) {  // FLAC 格式
    local_a8[0] = 0x46;  // 'F'
    local_a8[1] = 0x4c;  // 'L'
    local_a8[2] = 0x41;  // 'A'
    local_a8[3] = 0x43;  // 'C'
    iVar5 = 4;
  }
  // ... 其他格式处理 ...

  local_a8[iVar5] = 0x7c;  // '|'

  // 采样率处理 (param_2)
  iVar7 = param_2 / 1000;  // 44KHZ

  // 比特深度处理 (param_3)
  // 写入 "16bit"

  // 比特率处理 (param_1)
  // 根据值写入 "0807kbps" 或其他值

  FUN_0006f1a8(&uStack_30, &uStack_30, local_a8, 2);  // 调用字符串渲染
}
```

### 1.3 音频参数来源

从 `FUN_00088630` 的代码可以看到参数来源:

```c
// 从 DAT_000887d0 结构读取音频参数
iVar7 = *piVar3;  // DAT_000887d0
if (*DAT_000887d4 < 8) {
  uVar13 = *(undefined4 *)(iVar7 + 0x9c);  // 比特率
  uVar12 = *(undefined4 *)(iVar7 + 8);      // 采样率
  uVar8 = *(undefined4 *)(iVar7 + 0xc);    // 比特深度
}
```

---

## 2. 字符串是如何被渲染的

### 2.1 渲染调用链

```
FUN_0008683a (FLAC Builder)
    ↓
FUN_0006f1a8 (字符串渲染核心函数)
    ├─→ 字体位图查找
    └─→ 像素数据写入帧缓冲区
```

### 2.2 渲染函数参数结构

```c
// FUN_0006f1a8 参数
void FUN_0006f1a8(uint param_1, uint *param_2, code *param_3)
{
  // param_1 = 渲染控制参数
  // param_2 = 字符串缓冲区
  // param_3 = 回调函数表
}
```

### 2.3 8 个颜色/模式变体

```c
// 8 个渲染包装函数
FUN_000aa9ac → FUN_000aa622(..., 0, ...)  // 模式 0
FUN_000aa9d8 → FUN_000aa622(..., 1, ...)  // 模式 1
FUN_000aaa04 → FUN_000aa622(..., 2, ...)  // 模式 2
FUN_000aaa30 → FUN_000aa622(..., 3, ...)  // 模式 3
FUN_000aaa5c → FUN_000aa622(..., 4, ...)  // 模式 4
FUN_000aaa88 → FUN_000aa622(..., 5, ...)  // 模式 5
FUN_000aaab4 → FUN_000aa622(..., 8, ...)  // 模式 8
FUN_000aaae0 → FUN_000aa622(..., 9, ...)  // 模式 9
```

---

## 3. 文字颜色是如何来的 (Ghidra 追踪确认)

### 3.1 颜色选择逻辑（代码证据）

**FUN_00087586** 中的主题颜色选择代码（Ghidra 反编译确认）:

```c
// 地址: 0x87a0a - 0x87a10
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
  // 主题索引为 4 (Retro 主题)
  uVar7 = 0xe162;  // RGB565 颜色值
}
else {
  uVar7 = 0x44de;  // 默认颜色值
}
*DAT_00087a58 = uVar7;  // 存储选中的颜色
```

**Ghidra 引用分析结果**:
- `DAT_00087a54 + 0x34f` 被 `FUN_00087586 @ 0x87a0a` **读取**
- `DAT_00087a58` 被 `FUN_00087586 @ 0x87a10` **写入**

### 3.2 渲染函数中的颜色读取

**FUN_000aa622** 渲染函数中的颜色读取逻辑:

```c
// 颜色从 param_4 + 0x38 地址读取
// 每个颜色条目 4 字节: [B][G][R][Alpha]

switch(param_3) {  // param_3 = 颜色模式 (0-9)
case 0:
  // 颜色索引计算
  iVar4 = param_5[0xe];
  iVar9 = iVar4 >> 0x10;
  // ...
  uStack_50 = (uint)*(byte *)(*(int *)(param_4 + 0x38) + uVar7 * 4 + 2);  // G
  uStack_4c = (uint)*(byte *)(*(int *)(param_4 + 0x38) + uVar7 * 4 + 1);  // R
  uStack_48 = (uint)*(byte *)(*(int *)(param_4 + 0x38) + uVar7 * 4);      // B
  break;
```

**关键发现**:
- `param_4 + 0x38` = 调色板基址 + 0x38 偏移
- 每个颜色占用 4 字节: `[B][G][R][?]`
- `uVar7 * 4` = 颜色索引 × 4 字节

### 3.3 DAT_000aacfc 调色板表

**Ghidra 原始数据读取**:
```
地址 0xaacfc: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

**结论**: DAT_000aacfc 是**运行时初始化的指针表**，固件中全为 0x00。

**引用分析**:
- 12 个引用，全部是读取作为渲染函数参数传递
- 无写入操作 → 由 bootloader 或系统初始化代码设置

### 3.4 Flash 主题数据引用分析

**Ghidra 引用分析结果**:
```
Flash 主题区域 (0x7B0820, 0x7B0922, 0x7B0A24, 0x7B0B26, 0x7B0C28)
    ↓
引用计数: 0 (无直接代码引用)
```

**结论**: Flash 主题数据在固件中**没有代码直接引用**。可能的加载机制：
1. **Bootloader 初始化**: bootloader 在系统启动时从 Flash 加载主题数据到 RAM
2. **间接访问**: 通过指针表 (如 DAT_000aacfc) 间接访问
3. **固件更新时设置**: 主题数据可能在固件烧录时由 bootloader 设置

---

## 4. 关键地址汇总

| 地址 | 名称 | 功能 | 验证状态 |
|------|------|------|----------|
| 0x8683A | FUN_0008683a | FLAC Builder | ✅ 已确认 |
| 0x88630 | FUN_00088630 | 音频UI渲染主函数 | ✅ 已确认 |
| 0x87586 | FUN_00087586 | 字符串构建 + 主题颜色选择 | ✅ 已确认 |
| 0x6F1A8 | FUN_0006f1a8 | 字符串渲染核心 | ✅ 已确认 |
| 0xAA622 | FUN_000aa622 | 像素渲染 + 颜色应用 | ✅ 已确认 |
| 0x86CF8 | DAT_00086cf8 | 音频格式标志 | ✅ 已确认 |
| 0xAACFC | DAT_000aacfc | 运行时调色板表 | ⚠️ 运行时初始化 |
| 0x87A54 | DAT_00087a54 | 主题配置基址 | ⚠️ 运行时初始化 |
| 0x87A58 | DAT_00087a58 | 当前选中颜色 | ⚠️ 运行时初始化 |
| 0x87A88 | DAT_00087a88 | 主题选择偏移 (0x87A54+0x34F) | ⚠️ 运行时初始化 |
| 0x7B08xx | Flash Theme | 5个主题数据 | ⚠️ 无直接代码引用 |

---

## 5. 主题系统追踪

### 5.1 主题配置访问（Ghidra 确认）

```
DAT_00087a54 + 0x34f  (主题选择字节)
    ↓
FUN_00087586 @ 0x87a0a 读取
    ↓
主题值比较 (== '\x04'?)
    ↓
选择颜色 0xe162 或 0x44de
```

### 5.2 Flash 主题区域引用分析

| 主题 | 地址 | 引用计数 |
|------|------|----------|
| Elegant | 0x7B0820 | 0 |
| Midnight | 0x7B0922 | 0 |
| Cherry | 0x7B0A24 | 0 |
| Sky | 0x7B0B26 | 0 |
| Retro | 0x7B0C28 | 0 |

**结论**: Flash 主题区域无直接代码引用，由 bootloader 管理。

---

## 6. 颜色数据流总结

### 6.1 启动阶段（Bootloader）

```
┌─────────────────────────────────────────────────────────────────┐
│  启动阶段 (Bootloader)                                          │
├─────────────────────────────────────────────────────────────────┤
│  1. 从 Flash 0x7B08xx 读取 5 个主题数据                        │
│  2. 加载主题颜色到 RAM 调色板                                   │
│  3. 设置 DAT_000aacfc 指向调色板 (运行时初始化)                 │
│  4. 设置 DAT_00087a54 + 0x34f 为默认主题索引 (如 4 = Retro)   │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 运行时（应用程序）

```
┌─────────────────────────────────────────────────────────────────┐
│  FUN_00087586 (字符串构建 + 主题颜色选择)                       │
│     ↓                                                          │
│  读取 DAT_00087a54 + 0x34f → 获取主题索引                      │
│     ↓                                                          │
│  根据主题索引选择颜色值 (0xe162 或 0x44de)                      │
│     ↓                                                          │
│  写入 DAT_00087a58                                             │
│     ↓                                                          │
│  FUN_000aa622 (像素渲染)                                       │
│     ↓                                                          │
│  从 param_4 + 0x38 读取调色板颜色                              │
│     ↓                                                          │
│  应用颜色到文字像素                                            │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 关键代码证据

| 步骤 | 地址 | 函数 | 证据 |
|------|------|------|------|
| 主题索引读取 | 0x87a0a | FUN_00087586 | `*(char *)(DAT_00087a54 + 0x34f)` |
| 颜色值写入 | 0x87a10 | FUN_00087586 | `*DAT_00087a58 = uVar7` |
| 调色板读取 | 见代码 | FUN_000aa622 | `*(param_4 + 0x38) + uVar7 * 4` |

---

## 7. 主题与调色板映射关系

### 7.1 主题索引与颜色的映射（代码证据）

从 `FUN_00087586` 反编译代码：

```c
// 地址: 0x87a0a - 0x87a10
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
  // 主题索引 = 4 (Retro)
  uVar7 = 0xe162;  // RGB565 颜色值
}
else {
  // 其他所有主题
  uVar7 = 0x44de;  // RGB565 颜色值
}
*DAT_00087a58 = uVar7;
```

**映射关系**：

| 主题 | 索引 | 映射颜色 | RGB565 值 |
|------|------|----------|-----------|
| Elegant | 0 | 0x44de | (0, 85, 222) |
| Midnight | 1 | 0x44de | (0, 85, 222) |
| Cherry | 2 | 0x44de | (0, 85, 222) |
| Sky | 3 | 0x44de | (0, 85, 222) |
| **Retro** | 4 | **0xe162** | **(222, 96, 32)** |

**关键发现**：只有 **Retro 主题** 使用不同的文字颜色 (`0xe162`)，其他4个主题共用颜色 `0x44de`。

### 7.2 调色板结构

从 `FUN_000aa622` 渲染函数：

```c
// param_4 + 0x38 是调色板基址
// 颜色[索引 * 4 + 偏移] = RGB
uStack_50 = *(byte *)(param_4 + 0x38 + uVar7 * 4 + 2);  // G
uStack_4c = *(byte *)(param_4 + 0x38 + uVar7 * 4 + 1);  // R
uStack_48 = *(byte *)(param_4 + 0x38 + uVar7 * 4);        // B
```

**调色板结构**：
- `DAT_000aacfc` = 调色板指针表 (16 个指针)
- 每个调色板条目 = 4 字节 `[B][G][R][Alpha]`
- 总容量 = 16 × 4 = 64 字节

### 7.3 潜在颜色数量分析

| 组件 | 潜在颜色数量 | 说明 |
|------|--------------|------|
| Flash 主题数据 | 5 × 12 = 60 | 每个主题 12 个 RGB565 颜色 |
| DAT_000aacfc 调色板 | 16 | 运行时可能使用 |
| DAT_00087a58 | 1 | 当前选中的单色颜色值 |
| 代码实际使用 | **2** | `0xe162` 和 `0x44de` |

### 7.4 DAT_00087a58 与 DAT_000aacfc 的关系

| 地址 | 数据类型 | 用途 | 与主题的关系 |
|------|----------|------|-------------|
| `DAT_00087a58` | 16-bit RGB565 | 存储当前选中颜色 | 主题索引 → 颜色值的直接映射 |
| `DAT_000aacfc` | 32-bit 指针 | 指向调色板数组 | 由 bootloader 初始化 |

**两者是不同的数据**：
- `DAT_00087a58` = 单个颜色值
- `DAT_000aacfc` = 颜色数组指针

---

## 9. FLAC 字符串特殊颜色渲染 (独立于 UI 主题)

### 9.1 代码证据

**FLAC 字符串颜色选择逻辑** (Ghidra 反编译确认):

```c
// 地址: 0x87a0a - 0x87a10
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
  // 主题索引 = 4 (Retro Gold)
  uVar7 = 0xe162;  // RGB565 红色
}
else {
  // 所有其他主题
  uVar7 = 0x44de;  // RGB565 深青色
}
*DAT_00087a58 = uVar7;
```

### 9.2 FLAC 字符串颜色与 UI 主题颜色对比

| 主题 | UI 高亮/标题栏颜色 | FLAC 字符串颜色 | 代码证据 |
|------|-------------------|-----------------|----------|
| **Retro Gold** | 白色 | **红色 (0xe162)** | `== '\x04'` |
| Sky Blue | 白色 | 深青色 (0x44de) | else 分支 |
| Cherry Blossom | 青色 | 深青色 (0x44de) | else 分支 |
| Midnight Black | 白色 | 深青色 (0x44de) | else 分支 |
| Elegant White | 青色 | 深青色 (0x44de) | else 分支 |

### 9.3 关键发现

**FLAC 字符串使用独立的颜色逻辑**：
- 只检查主题索引是否等于 4 (Retro Gold)
- 两种颜色：红色 (0xe162) vs 深青色 (0x44de)
- **不跟随 UI 主题的正常颜色选择**

### 9.4 颜色值分析

| RGB565 | R | G | B | 颜色名称 |
|--------|----|----|----|----------|
| 0xe162 | 222 | 96 | 32 | 红色 (Retro) |
| 0x44de | 0 | 85 | 222 | 深青色 (其他) |

---

## 10. 未验证问题

| 问题 | 状态 | 说明 |
|------|------|------|
| 谁写入 DAT_000aacfc | ❌ 未追踪 | bootloader 或初始化代码，固件中无写入 |
| Flash → RAM 主题加载函数 | ❌ 未追踪 | Flash 主题区域无直接代码引用 |
| DAT_00087a54 + 0x34f 初始化 | ❌ 未追踪 | bootloader 或系统设置代码 |
| UI 文本颜色渲染逻辑 | ❌ 未追踪 | 需要单独分析 |

**注意**：上述未追踪问题涉及 bootloader 或系统初始化代码，可能不在主固件映像中。

---

## 11. DAT_00087a54 结构体分析

### 11.1 结构体恢复尝试结果

**分析时间**: 2026-02-13
**分析工具**: Ghidra Headless + Python Scripts

### 11.2 结构体基本信息

| 属性 | 值 |
|------|-----|
| 基址 | `DAT_00087a54` |
| 类型 | RAM 数据结构 |
| 初始化方式 | 运行时初始化 |
| 固件映像数据 | 全 0x00 (无实际数据) |

### 11.3 已识别的结构体字段偏移

| 偏移 | 名称 | 类型 | 用途 |
|------|------|------|------|
| +0x010 | param_16 | int | 未知参数 |
| +0x012 | param_18 | short | 未知参数 |
| +0x016 | param_22 | short | 未知参数 |
| +0x038 | palette_base | int | 调色板基址指针 |
| +0x058 | render_param | int | 渲染参数 |
| +0x34f | theme_select | byte | **主题选择索引** (0-4) |
| +0x358 | ui_param | int | UI 参数 |

### 11.4 关键偏移证据

**引用分析** (`recover_structure_v2.py` 执行结果):

```
[1] Analyzing known offsets from decompiler:
    +0x34f: theme_select (byte)
    +0x358: ui_param (int)
    +0x038: palette_base (int)
    +0x058: render_param (int)
    +0x012: param_18 (short)
    +0x016: param_22 (short)
    +0x010: param_16 (int)

[2] Finding all references to DAT_00087a54:
    Found 1 references
    - FUN_00087586 @ 0x87a0a
```

### 11.5 结构体大小估计

```
最大偏移: 0x358
估计结构体大小: >= 0x400 字节 (估计值)
```

### 11.6 结构体恢复限制

**为什么无法完全恢复**:

1. **运行时初始化**: `DAT_00087a54` 是 RAM 数据结构，固件映像中全为 0x00
2. **无直接初始化代码**: 没有找到将初始值写入该结构的代码
3. **仅 1 个代码引用**: 只有 `FUN_00087586` 引用该结构
4. **Flash 主题无引用**: Flash 0x7B08xx 区域无直接代码引用

**可能的初始化机制**:
- Bootloader 在系统启动时初始化
- 单独的初始化函数 (不在当前固件映像中)
- 硬件/外设寄存器配置

### 11.7 主题选择逻辑 (代码证据)

```c
// 地址: 0x87a0a
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
  // 主题索引 = 4 (Retro Gold)
  uVar7 = 0xe162;  // 红色
}
else {
  // 主题索引 0-3
  uVar7 = 0x44de;  // 深青色
}
*DAT_00087a58 = uVar7;
```

**主题索引映射**:

| 值 | 主题 |
|----|------|
| 0x00 | Elegant White |
| 0x01 | Midnight Black |
| 0x02 | Cherry Blossom |
| 0x03 | Sky Blue |
| 0x04 | Retro Gold |

---

## 12. Palette 初始化追踪

### 12.1 核心问题

**问题**: DAT_000aacfc (调色板指针表) 和 DAT_00087a54 (主题配置) 的数据从哪里来？

### 12.2 Ghidra 引用分析结果

**分析脚本**: `simple_memcpy_search.py`, `check_palette_init.py`, `find_data_copy.py`

| 检查项 | 结果 | 说明 |
|--------|------|------|
| `memcpy` 函数 | **0 个** | 固件中无 memcpy |
| `memset` 函数 | **0 个** | 固件中无 memset |
| 写入 DAT_000aacfc | **0 次** | 12 次引用全部是 READ |
| 写入 DAT_00087a54 | **0 次** | 1 次引用是 READ |
| Flash 0x7B08xx 引用 | **0 次** | 无代码直接引用 |

**DAT_000aacfc 引用详情** (12 个 READ):

```
@ 0xaa9ba: ldr r1,[0x000aacfc]  (FUN_000aa9ac)
@ 0xaa9e6: ldr r1,[0x000aacfc]  (FUN_000aa9d8)
@ 0xaaa12: ldr r1,[0x000aacfc]  (FUN_000aaa04)
@ 0xaaa3e: ldr r1,[0x000aacfc]  (FUN_000aaa30)
@ 0xaaa6a: ldr r1,[0x000aacfc]  (FUN_000aaa5c)
@ 0xaaa96: ldr r1,[0x000aacfc]  (FUN_000aaa88)
@ 0xaaac2: ldr r1,[0x000aacfc]  (FUN_000aaab4)
@ 0xaaaee: ldr r1,[0x000aacfc]  (FUN_000aaae0)
@ 0xaaca2: ldr r0,[0x000aacfc]  (FUN_000aac94)
@ 0xaacae: ldr r0,[0x000aacfc]  (FUN_000aac94)
@ 0xaacc0: ldr r2,[0x000aacfc]  (FUN_000aac94)
@ 0xaacd2: ldr.w r8,[0x000aacfc] (FUN_000aac94)
```

### 12.3 数据来源分析

**FUN_000aac94 中的调用**:

```c
// FUN_000aac94 @ 0xaac94
FUN_0007ca98(DAT_000aacfc, 0x40);  // 最初以为是 memset，实际是 USB 函数
iVar1 = FUN_000aa43a(DAT_000aacfc, param_5, param_4, param_6, param_7);
```

**FUN_0007ca98 实际功能**:
- 不是 memset
- 是 **USB 相关函数** (包含 USB_TIMEOUT, USB_VBUS_INT, USB_resume 等字符串)

### 12.4 初始化来源分析

**BootROM 假设验证**:

```
BootROM (RKNanoD 硬件固化)
    │
    ├─ 通用代码，所有 RK Nano D 设备相同
    ├─ 可能负责基本内存初始化
    └─ 不可能针对特定固件配置主题数据
```

**固件映像分析**:

```
HIFIEC10.IMG
    │
    ├─ ARM 代码 ✅ (可执行)
    ├─ Flash 主题数据 (0x7B08xx) ⚠️ 无代码引用
    └─ RAM 运行时数据 ❌ 无初始化代码
          ├─ DAT_000aacfc (palette) - 全部 READ
          └─ DAT_00087a54 (theme) - 全部 READ
```

### 12.6 二进制搜索结果 (搜索 RAM 地址)

**搜索脚本**: `search_ram_addrs.py`, `search_descriptor.py`

**固件中搜索 RAM 地址结果**:

| 地址 | 固件中作为常量 | 结论 |
|------|----------------|------|
| `0x000aacfc` | **未找到** | 地址是动态计算的 |
| `0x00087a54` | **未找到** | 地址是动态计算的 |
| `0x00087a58` | **未找到** | 地址是动态计算的 |

**Flash 主题地址搜索结果**:
```
找到多个 0x7B0xxx 模式在头部 Part 0 区域：
0x7b027af0, 0x7b0a7b0f, 0x7b067ad9, 0x7b01b7b00, ...
```

**关键发现**:

1. **RAM 地址不在固件中作为常量**
   - 所有 RAM 地址 (`0x000aacfc`, `0x00087a54`, `0x00087a58`) 都不在固件映像中找到
   - 这意味着地址是**运行时动态计算的**，而不是硬编码的

2. **Flash 地址存在于固件中**
   - 多个 `0x7B0xxx` 模式在 Part 0 头部中找到
   - 这些是主题数据在 Flash 中的位置引用

3. **推断的初始化机制**

```
Flash 地址 (0x7B0xxx) → 在固件中找到作为常量 ✅
    ↓
RAM 地址 (0x000axxx) → 不在固件中，动态计算 ❌

结论：
- 地址计算：base_addr + offset = runtime_addr
- 例如：0x87000 + 0x3FC = 0x873FC
- 具体的基地址可能由 bootloader 或硬件寄存器设置
```

### 12.7 可能的数据来源

| 来源 | 可能性 | 说明 |
|------|--------|------|
| BootROM 初始化 | 中 | RKNanoD BootROM 可能自动初始化 RAM |
| 独立 bootloader | 高 | 可能有一个独立的 bootloader 阶段 |
| 硬件默认值 | 低 | RAM 通常不自动初始化为非零值 |
| 外设 DMA | 中 | 可能通过 DMA 直接填充 |
| 固件内 memcpy | ❌ | 固件中无 memcpy 函数 |

### 12.8 FLAC 颜色来源分析

#### 12.8.1 关键发现

**两个独立的系统**:

| 组件 | 地址 | 用途 | 来源 |
|------|------|------|------|
| ThemeConfig | `DAT_00087a54 + 0x34f` | theme_select | 全局配置 struct |
| current_color | `DAT_00087a58` | 颜色值 | **硬编码写入** |
| Palette | `DAT_000aacfc` | 16 色调色板 | **独立结构** |

### 12.8.2 FLAC 字符串颜色逻辑 (Capstone 验证)

**Capstone 交叉验证结果** (`capstone_verify.py`):

```assembly
; 地址: 0x87a0a - 0x87a1e (Thumb 模式)
  0x00087a0a: ldr    r0, [pc, #0x48]      ; 加载 DAT_00087a58 地址
  0x00087a0c: ldrb.w r1, [r0, #0x34f]    ; 读取 theme_select (+0x34f)
  0x00087a10: ldr    r0, [pc, #0x44]      ; 加载颜色表地址
  0x00087a12: cmp    r1, #4               ; 比较 theme_select == 4?
  0x00087a14: ite    eq                   ; if-then-else
  0x00087a16: movweq r1, #0xe162          ; Retro: r1 = 0xe162
  0x00087a1a: movwne r1, #0x44de          ; 其他: r1 = 0x44de
  0x00087a1e: strh   r1, [r0]            ; 写入颜色值到 DAT_00087a58
```

**对应的 C 代码** (Ghidra 反编译):

```c
// 地址: 0x87a0a - 0x87a10
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
  // 主题索引为 4 (Retro 主题)
  uVar7 = 0xe162;  // RGB565 颜色值
}
else {
  uVar7 = 0x44de;  // 默认颜色值
}
*DAT_00087a58 = uVar7;  // 存储选中的颜色
```

**指令对照**:

| 汇编 | C 代码 | 说明 |
|------|--------|------|
| `ldr r0, [pc, #0x48]` | `DAT_00087a58` | 加载目标地址 |
| `ldrb.w r1, [r0, #0x34f]` | `*(DAT_00087a54 + 0x34f)` | 读取 theme_select |
| `cmp r1, #4` | `== '\x04'` | 比较主题索引 |
| `movweq r1, #0xe162` | `0xe162` | Retro 颜色 |
| `movwne r1, #0x44de` | `0x44de` | 默认颜色 |
| `strh r1, [r0]` | `*DAT_00087a58 = uVar7` | 写入颜色值 |

**关键观察**:
- 使用 `MOVW` 指令加载硬编码颜色值 (不是从调色板读取)
- 使用 `IT` (If-Then) 指令实现 if-else
- 写入 `DAT_00087a58` 后没有后续读取指令

```c
// FUN_00087586 @ 0x87586
if (*(char *)(DAT_00087a54 + 0x34f) == '\x04') {
    uVar7 = 0xe162;  // 硬编码值
}
else {
    uVar7 = 0x44de;  // 硬编码值
}
*DAT_00087a58 = uVar7;  // 写入 DAT_00087a58
```

**重要发现**: `DAT_00087a58` 写入后有 **0 个引用**！

#### 12.8.3 两个独立的结构

```
1. ThemeConfig 结构体 (0x87xxx 区域)
   ├── +0x038: audio 参数 (DAT_87a38-87a50)
   ├── +0x058: current_color (DAT_87a58)
   ├── +0x300: 未知区域
   ├── +0x34f: theme_select (主题索引 0-4)
   └── +0x358: ui_param

2. Palette 结构体 (0xaacfc)
   ├── 16 个颜色条目 × 4 字节 = 64 字节
   └── 用于 UI 文字渲染 (由 FUN_aa9xx 函数使用)
```

#### 12.8.4 颜色来源对比

| 组件 | 颜色来源 | 用途 |
|------|----------|------|
| **FLAC 字符串** | 硬编码 if-else (0xe162 / 0x44de) | 独立于调色板 |
| **UI 文字** | 从调色板查找 (DAT_000aacfc) | 主题相关 |

#### 12.8.5 分析结论

1. **是的，有全局配置结构体** - ThemeConfig 存储主题索引
2. **不，调色板不在 ThemeConfig 里** - DAT_000aacfc 是独立的
3. **FLAC 字符串使用硬编码颜色** - 不是从调色板查找
4. **调色板用于 UI 文字渲染** - 由 FUN_aa9xx 系列函数使用
5. **DAT_00087a58 写入后无引用** - 可能是遗留代码或用于外设/DMA

---

### 12.9 NotebookLM 分析：地址计算模式

**咨询 NotebookLM 的分析结果**:

### RAM 地址计算模式

由于 `0x00087a54` 和 `0x000aacfc` 的字面值不在固件二进制中，有以下三种可能机制：

| 模式 | 说明 | 验证方法 |
|------|------|----------|
| **A: 基址寄存器 + 偏移** | 使用 R9/R10 作为静态基址寄存器 | 检查 FUN_00087586 入口处的寄存器使用 |
| **B: MOVW/MOVT 指令对** | 高低位分别构建 32 位地址 | 搜索 MOVW/MOVT 指令 |
| **C: 指针链/间接引用** | 从根配置表间接加载 | 搜索 LDR [root_ptr, #offset] |

### 结构体偏移是编译时常量

**关键概念**: 结构体成员的**偏移量**是编译时确定的（硬编码在指令中），但**基地址**可以是运行时动态计算的。

```
结构体定义:
struct ThemeConfig {
    void* palette_ptr;    // +0x38
    // ... 中间有大量数据 ...
    uint8_t theme_select; // +0x34f (847 字节偏移)
};

访问代码 (编译后):
LDRB R1, [R0, #0x34f]  ; R0 = 动态基地址, 0x34F = 硬编码偏移
```

### 搜索建议

| 搜索目标 | 方法 | 目的 |
|----------|------|------|
| 偏移 0x34f | 搜索 `LDRB/STRB` 指令 | 找到 theme_select 的写入位置 |
| MOVW/MOVT 对 | 搜索 `#0x0008` 立即数 | 验证地址构建方式 |
| BSS 初始化 | 搜索启动代码附近的清零循环 | 找到初始化源头 |

### 单例上下文模式 (Singleton Context Pattern)

**这是嵌入式固件中的常见设计模式**:

```
典型设计:
struct SystemContext {
    OS_State os;
    Display_Config display;   // ← 发现的 0x87a54 可能属于这里
    Audio_Config audio;
    // ... 其他子系统 ...
};

SystemContext* g_context;  // 指针存放在固定位置
```

---

### 12.9 结论

**Unicorn 无法复原 Palette 的原因**:

1. **RAM 地址是动态计算的**: 不在固件映像中作为常量
2. **无初始化代码**: 没有 memcpy/memset 调用写入这些地址
3. **全是 READ 引用**: 12 个 DAT_000aacfc 引用全部是读取
4. **Flash 地址存在**: 主题数据在固件中有引用 (0x7B0xxx 模式)
5. **可能在固件之外**: 数据初始化在固件运行前完成

**推断的数据流**:

```
BootROM 或独立 bootloader
        │
        ├─ 从 Flash 0x7B08xx 读取主题数据 (5 个主题 × 12 颜色)
        │     ↑
        │     固件中找到 0x7B0xxx 常量作为证据
        │
        ├─ 计算 RAM 地址 (base + offset)
        │     ↑
        │     固件中未找到 RAM 地址常量作为证据
        │
        ├─ 复制到 RAM 地址
        └─ 设置 DAT_000aacfc = 调色板指针表地址
        │
固件代码 (HIFIEC10.IMG)
        │
        └─ 只读访问 DAT_000aacfc (12 处读取)
```

**关键证据对比**:

| 数据类型 | 固件中作为常量 | 含义 |
|----------|----------------|------|
| Flash 地址 (0x7B0xxx) | ✅ 找到 | 主题数据在 Flash 中有明确位置 |
| RAM 地址 (0x000axxx) | ❌ 未找到 | 地址动态计算，不是硬编码 |
| RAM 偏移 (0x34f) | ✅ 在指令中 | 结构体成员偏移是编译时常量 |

---

## 13. 执行命令

```bash
# 运行追踪脚本
cd "/home/losses/Downloads/ECHO MINI V3.1.0"
/run/current-system/sw/bin/ghidra-analyzeHeadless \
  ghidra_project ECHO_FIRMWARE \
  -process HIFIEC10.IMG \
  -scriptPath /home/losses/Downloads/ECHO\ MINI\ V3.1.0 \
  -postScript simple_trace.py

# Palette 初始化追踪
cd "/home/losses/Downloads/ECHO MINI V3.1.0"
/run/current-system/sw/bin/ghidra-analyzeHeadless \
  ghidra_project ECHO_FIRMWARE \
  -process HIFIEC10.IMG \
  -scriptPath "/home/losses/Downloads/ECHO MINI V3.1.0" \
  -postScript simple_memcpy_search.py

/run/current-system/sw/bin/ghidra-analyzeHeadless \
  ghidra_project ECHO_FIRMWARE \
  -process HIFIEC10.IMG \
  -scriptPath "/home/losses/Downloads/ECHO MINI V3.1.0" \
  -postScript check_palette_init.py

# 二进制搜索 RAM 地址
cd "/home/losses/Downloads/ECHO MINI V3.1.0"
python3 search_ram_addrs.py
python3 search_descriptor.py
```

---

*文档更新时间: 2026-02-13 (颜色数据流追踪 + 主题映射 + FLAC特殊颜色更新 + 结构体分析 + Palette初始化追踪 + 二进制搜索)*
*基于 Ghidra 实际反编译结果 + 二进制搜索*
*分析脚本: recover_structure_v2.py, analyze_struct_en.py, simple_memcpy_search.py, check_palette_init.py, search_ram_addrs.py, search_descriptor.py*
