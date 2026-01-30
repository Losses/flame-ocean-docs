# 调试指南

**状态**: ⚠️ 开发中
**最后更新**: 2026-01-28

---

## 分析工具

### rizin 命令

```bash
# 基本分析
rizin -a arm -b 16 HIFIEC10_Fixed.bin

# 查找函数
afl

# 查找字符串
iz

# 反汇编指定地址
pd 20 @ 0x2DB58

# 查找交叉引用
axt 0x2DB58
```

### Capstone 解码

```python
from capstone import *

# 初始化
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

# 解码
code = firmware[offset:offset+length]
for insn in md.disasm(code, base_addr):
    print(f"{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

---

## 关键地址

| 地址 | 内容 |
|------|------|
| 0x2D3C6 | 渲染函数入口 |
| 0x2DA88 | 内联渲染代码 |
| 0x2DB12 | 编码类型判定 |
| 0x2DB58 | 像素数据加载 |
| 0x2DC22 | 死代码路径 |

---

## 调试步骤

### 1. 定位字符数据

```python
def find_char_data(r5):
    """根据 r5 查找字符数据"""
    r6 = 0x100000 + r5 * 4
    pixel_start = r6 + 6  # 跳过 6 字节元数据
    return r6, pixel_start
```

### 2. 提取像素数据

```python
def extract_pixel_data(firmware, r5):
    """提取像素数据"""
    r6 = 0x100000 + r5 * 4
    pixel_start = r6 + 6

    bitmap_data = []
    for i in range(0, 32, 2):
        val = struct.unpack('<H', firmware[pixel_start + i:pixel_start + i + 2])[0]
        bitmap_data.append(val)

    return bitmap_data
```

### 3. 确定编码类型

```python
def get_encoding_type(firmware, r5):
    """确定编码类型"""
    r6 = 0x100000 + r5 * 4
    metadata_0 = firmware[r6]

    if (metadata_0 >> 4) >= 8:
        return "special"  # 14列
    else:
        return "standard"  # 15列
```

---

## 常见问题

### Q: 如何找到字符的 r5 值？

参考 [Unicode查找表](../04_DATA_DISCOVERY/UNICODE_TO_R5_MAPPING.md)。

已知映射关系:
- U+6CA8 (沨) → r5 = 0x0FDE
- U+6CA4 (沤) → r5 = 0x0FDB
- U+6CA6 (沦) → r5 = 0x0FDC
- U+6CAA (沪) → r5 = 0x0FDA

映射公式: `r5 = Unicode - 0x5CCA + sub_offset`

**注意**: offset() 函数的具体实现尚未完全确定，原分析中测试了多个公式但均未达到 100% 匹配。

### Q: 如何渲染字符？

参见 [编码规则](../04_DATA_DISCOVERY/ENCODING_RULES.md)

---

**参见**:
- [分析脚本索引](./ANALYSIS_SCRIPTS.md)
