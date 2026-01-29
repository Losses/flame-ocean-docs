# 调试用字符表

**状态**: ✅ 可用于调试验证
**数据来源**: legacy/MAPPING_REPORT_2026-01-28.md
**最后更新**: 2026-01-28

---

## 说明

本文档包含 31 个已知字符的完整映射数据，可用于调试和验证。

**注意**: 研究方法可能不完美，但字符偏移数据是实际验证过的。

---

## 0x44xxxx 范围 (基址 0x440000)

| 字符 | Unicode | 偏移 | 相对偏移 | Unicode 表 | 索引 |
|------|---------|------|----------|------------|------|
| 寸 | U+5BF8 | 0x4440C2 | 0x040C2 | 0x02FE0 | 55 |
| 出 | U+51FA | 0x44524A | 0x0524A | 0x02CE0 | 133 |
| 岑 | U+5C91 | 0x44528C | 0x0528C | 0x045E0 | 62 |
| 岌 | U+5C8C | 0x4453D6 | 0x053D6 | 0x045E0 | 61 |
| 岈 | U+5C88 | 0x445310 | 0x05310 | 0x142E0 | 28 |

---

## 0x46xxxx 范围 (基址 0x466000) - 氵部系列

### 完整映射表 (按偏移排序)

| 字符 | Unicode | 偏移 | 相对偏移 | Unicode 表 | 索引 |
|------|---------|------|----------|------------|------|
| 汰 | U+6C70 | 0x46603A | 0x003A | 0x0FDE0 | 41 |
| 汲 | U+6C72 | 0x46607C | 0x007C | 0x0FDE0 | 48 |
| 汶 | U+6C76 | 0x466100 | 0x0100 | 0x0FDE0 | 52 |
| 汸 | U+6C78 | 0x466142 | 0x0142 | 0x143E0 | 37 |
| 決 | U+6C7A | 0x466184 | 0x0184 | 0x0FDE0 | 39 |
| 汾 | U+6C7E | 0x466208 | 0x0208 | 0x0FDE0 | 49 |
| 沂 | U+6C82 | 0x46628C | 0x028C | 0x0FDE0 | 56 |
| 沄 | U+6C84 | 0x4662CE | 0x02CE | 0x143E0 | 40 |
| 沆 | U+6C86 | 0x466310 | 0x0310 | 0x0FDE0 | 51 |
| 沈 | U+6C88 | 0x466352 | 0x0352 | 0x0FDE0 | 34 |
| 沌 | U+6C8C | 0x4663D6 | 0x03D6 | 0x0FDE0 | 42 |
| 沢 | U+6CA2 | 0x4663D6 | 0x03D6 | 0x031E0 | 136 |
| 沖 | U+6C96 | 0x466520 | 0x0520 | 0x021E0 | 65 |
| 沘 | U+6C98 | 0x466562 | 0x0562 | 0x0FDE0 | 55 |
| 沚 | U+6C9A | 0x4665A4 | 0x05A4 | 0x04DE0 | 35 |
| 沜 | U+6C9C | 0x4665E6 | 0x05E6 | 0x143E0 | 50 |
| 沨 | U+6CA8 | 0x4666AC | 0x06AC | **未找到** | - |
| 沤 | U+6CA4 | 0x4666EE | 0x06EE | **未找到** | - |
| 沦 | U+6CA6 | 0x466730 | 0x0730 | **未找到** | - |
| 沪 | U+6CAA | 0x4667B4 | 0x07B4 | **未找到** | - |
| 沬 | U+6CAC | 0x4667F6 | 0x07F6 | 0x101E0 | 84 |
| 氵 | U+6CB0 | 0x46687A | 0x087A | 0x147E0 | 37 |
| 沮 | U+6CAE | 0x466838 | 0x0838 | 0x04DE0 | 50 |
| 沲 | U+6CB2 | 0x4668BC | 0x08BC | 0x1AEE0 | None |
| 沴 | U+6CB4 | 0x4668FE | 0x08FE | 0x147E0 | 28 |
| 泄 | U+6CC4 | 0x466B0E | 0x0B0E | 0x04DE0 | 43 |
| 泊 | U+6CCA | 0x466BD4 | 0x0BD4 | 0x037E0 | 39 |

---

## 未在 Unicode 表中找到的字符

以下 4 个字符**未在任何 Unicode 表中找到**：

| 字符 | Unicode | 偏移 | 相邻字符 |
|------|---------|------|----------|
| 沨 | U+6CA8 | 0x4666AC | 沜(0x4665E6), 沤(0x4666EE) |
| 沤 | U+6CA4 | 0x4666EE | 沨(0x4666AC), 沦(0x466730) |
| 沦 | U+6CA6 | 0x466730 | 沤(0x4666EE), 沪(0x4667B4) |
| 沪 | U+6CAA | 0x4667B4 | 沦(0x466730), 沬(0x4667F6) |

**注意**: 这 4 个字符在 Unicode 序列中是连续的 (U+6CA4, U+6CA6, U+6CA8, U+6CAA)

---

## 字符按 Unicode 排序

```
U+51FA  出   0x44524A
U+5BF8  寸   0x4440C2
U+5C88  岈   0x445310
U+5C8C  岌   0x4453D6
U+5C91  岑   0x44528C
U+6C70  汰   0x46603A
U+6C72  汲   0x46607C
U+6C76  汶   0x466100
U+6C78  汸   0x466142
U+6C7A  決   0x466184
U+6C7E  汾   0x466208
U+6C82  沂   0x46628C
U+6C84  沄   0x4662CE
U+6C86  沆   0x466310
U+6C88  沈   0x466352
U+6C8C  沌   0x4663D6
U+6C96  沖   0x466520
U+6C98  沘   0x466562
U+6C9A  沚   0x4665A4
U+6C9C  沜   0x4665E6
U+6CA2  沢   0x4663D6  [与沌共享]
U+6CA4  沤   0x4666EE  [未找到表]
U+6CA6  沦   0x466730  [未找到表]
U+6CA8  沨   0x4666AC  [未找到表]
U+6CAA  沪   0x4667B4  [未找到表]
U+6CAC  沬   0x4667F6
U+6CAE  沮   0x466838
U+6CB0  氵   0x46687A
U+6CB2  沲   0x4668BC
U+6CB4  沴   0x4668FE
U+6CC4  泄   0x466B0E
U+6CCA  泊   0x466BD4
```

---

## 调试使用示例

### 验证 r5 计算

```python
# 使用已知字符验证 r5 计算公式
test_chars = [
    (0x6CA8, "沨", 0x4666AC),
    (0x6CA4, "沤", 0x4666EE),
    (0x6CA6, "沦", 0x466730),
    (0x6CAA, "沪", 0x4667B4),
]

for unicode, char_name, expected_offset in test_chars:
    r5 = unicode_to_r5(unicode)
    actual_offset = 0x466000 + (r5 * 4)
    print(f"{char_name} U+{unicode:04X}: r5=0x{r5:04X}, offset=0x{actual_offset:04X}")
```

### 验证像素数据提取

```python
def verify_pixel_extraction(firmware, unicode, expected_offset):
    """验证像素数据提取"""
    r5 = unicode_to_r5(unicode)
    r6 = 0x100000 + r5 * 4

    # 提取像素数据
    pixel_start = r6 + 6
    bitmap_data = []
    for i in range(0, 32, 2):
        val = struct.unpack('<H', firmware[pixel_start + i:pixel_start + i + 2])[0]
        bitmap_data.append(val)

    return bitmap_data
```

---

**参见**:
- [Unicode查找表](./UNICODE_LOOKUP_TABLE.md)
- [像素数据位置](./PIXEL_DATA_LOCATION.md)
