# Critical Gap Analysis: Data-Verified Formula vs Missing Code Evidence

**Date**: 2026-01-29
**Status**: 🔴 CRITICAL GAP IDENTIFIED

---

## Executive Summary

We have a **data-verified pixel address formula** but **no code evidence** for its implementation. This document analyzes this critical gap.

---

## Verified Formulas (Data Evidence ✅)

### Formula 1: Unicode to r5 Conversion

```python
r5 = Unicode >> 2
```

**Verification**:
- 沨 (U+6CA8): r5 = 0x1B2A ✅
- 婔 (U+5A54): r5 = 0x1695 ✅
- 福 (U+798F): r5 = 0x1E63 ✅

**Code Evidence**: ✅ Found at 0x02D4E6: `asrs r5, r7, #2`

### Formula 2: Pixel Address Calculation

```python
pixel_addr = 0x100000 + (r5 * 4)
```

**Verification**:
| Character | Unicode | r5 | Calculated Address | Non-zero Bytes | Valid? |
|-----------|---------|-----|-------------------|----------------|--------|
| 沨 | U+6CA8 | 0x1B2A | 0x00106CA8 | 29/32 (90.6%) | ✅ |
| 婔 | U+5A54 | 0x1695 | 0x00105A54 | 31/32 (96.9%) | ✅ |
| 福 | U+798F | 0x1E63 | 0x0010798C | 30/32 (93.8%) | ✅ |

**Code Evidence**: ❌ NOT FOUND

---

## Extensive Code Search Results

### Search 1: Direct Calculation Pattern

**Target**: `lsls rX, r5, #2` (r5 * 4) followed by address calculation

**Result**: ❌ Not found in 0x020000-0x040000 or 0x080000-0x0A0000

### Search 2: Base Address Loading

**Target**: PC-relative load of 0x100000 base address

**Result**: ❌ No direct PC-relative loads to 0x10xxxx region found

### Search 3: Register Indirect Addressing

**Target**: `ldr r6, [rX, rY, lsl #2]` pattern

**Result**: ❌ Not found

### Search 4: Pointer Table Lookup

**Target**: Pointer table containing 0x106CA8 (沨 pixel address)

**Result**: ❌ 0x106CA8 not found as a direct pointer in firmware

### Search 5: Lookup Table Formula

**Target**: Code implementing `[(r5 >> 5) + 0x14]`

**Result**: ⚠️ Found at 0x02D680, but verified as **DEAD CODE**

### Search 6: Live Code Path (0x2D3E8)

**Target**: `lsls r1, r4, #0x10` (documented as live path)

**Result**: ⚠️ Found, but does not lead to pixel address calculation

---

## Dead Code vs Live Code

### Dead Code Path (0x2D680-0x2D688)

```assembly
0x2D680: lsrs r0, r5, #5      ; r0 = r5 >> 5
0x2D688: ldr r6, [r0, #0x14]  ; r6 = [r0 + 0x14]
```

**Status**: ❌ DEAD CODE (verified: 0x2DA80: b #0x2d3e8 jumps over this)

### Live Code Path (0x2DAC0-0x2DAC2)

```assembly
0x2DAC0: lsrs r5, r0, #0x10   ; r5 = r0 >> 16
0x2DAC2: asrs r6, r0, #0x1d   ; r6 = r0 >> 29
```

**Result**: r6 = (r7 ^ 0x28) >> 25 (small index value, not pixel address)

---

## CJK Handler Analysis

### Examined Functions

| Address | Description | Finding |
|---------|-------------|---------|
| 0x088F00 | U+88xx handler | ❌ Infinite loop |
| 0x089000 | U+89xx handler | ⚠️ Short function |
| 0x089100 | U+89xx handler | ⚠️ Various operations |
| 0x08AF00 | U+AFxx handler | ✅ `ldr r6, [r0, #0x14]` pattern |
| 0x08B000 | U+B0xx handler | ✅ `ldr r6, [r0, #0x14]` pattern |

### Key Pattern Found

```assembly
0x08AF04: ldr r6, [r0, #0x14]  ; Load r6 from lookup table
```

**Issue**: r0 value source unknown; lookup table location unknown

---

## Possible Explanations

### 1. Hardware Memory Mapping

**Theory**: 0x100000 is accessed via special hardware mechanism (MMU, memory-mapped I/O)

**Evidence**: None (would require hardware documentation)

### 2. DMA Transfer

**Theory**: Pixel data copied from Flash (0x4xxxxx) to RAM (0x106CA8) via DMA

**Evidence**: ❌ Falsified - Flash and RAM data are different

### 3. Unanalyzed Code Region

**Theory**: Pixel address calculation code is in region not yet searched

**Searched**: 0x020000-0x040000, 0x080000-0x090000

**Not Searched**: 0x000000-0x020000, 0x040000-0x080000, 0x090000+

### 4. Indirect Access Mechanism

**Theory**: Pixel address calculated through function call or complex data structure

**Evidence**: CJK handlers use lookup table pattern, but table not found

### 5. Runtime Code Generation

**Theory**: Address calculation code generated dynamically at runtime

**Evidence**: None (would require dynamic analysis)

---

## Remaining Questions

1. **How does the firmware actually access pixel data at 0x100000 + r5 * 4?**
   - No direct calculation code found
   - No pointer table found
   - No base address loading found

2. **What is the purpose of the live code at 0x2DAC0-0x2DAC2?**
   - Calculates r6 = (r7 ^ 0x28) >> 25
   - Result is small index, not pixel address
   - How does this lead to pixel data access?

3. **Where is the lookup table accessed by `ldr r6, [r0, #0x14]` at 0x08AF04?**
   - r0 value source unknown
   - Table structure unknown
   - Table location unknown

---

## Next Steps

### Priority 1: Expand Code Search

Search additional code regions:
- 0x000000-0x020000 (bootloader/vector table)
- 0x040000-0x080000 (potential additional code)
- 0x090000-0x100000 (remaining code before pixel data)

### Priority 2: Dynamic Analysis

Use emulator/debugger to:
- Set breakpoint at 0x2DB58 (`ldrh r2, [r6, #6]`)
- Trace r6 value at runtime
- Identify actual code path

### Priority 3: Hardware Documentation

Research:
- GC9107 LCD controller memory mapping
- DMA controller configuration
- Any special font/pixel hardware acceleration

### Priority 4: Alternative Approach

If code cannot be found:
- Document data-verified formula as empirical finding
- Extract pixel data using formula
- Note that code implementation remains unknown

---

## Conclusion

The formula `pixel_addr = 0x100000 + r5 * 4` is **reliably verified by data** but **not yet found in code**.

This represents a critical gap between reverse engineering findings:
- ✅ **Data analysis**: Formula works perfectly for tested characters
- ❌ **Code analysis**: No implementation found despite extensive searching

**Possible resolution**:
- Hardware mechanism (requires documentation)
- Unsearched code region (requires broader search)
- Indirect access (requires deeper analysis)
- **Accept empirical finding without code evidence**

---

## References

- [VERIFIED_INSTRUCTIONS_ANALYSIS.md](../03_CODE_ANALYSIS/VERIFIED_INSTRUCTIONS_ANALYSIS.md)
- [R6_PIXEL_DATA_POINTER.md](../03_CODE_ANALYSIS/REGISTERS/R6_PIXEL_DATA_POINTER.md)
- [PIXEL_DATA_LOCATION.md](../04_DATA_DISCOVERY/PIXEL_DATA_LOCATION.md)
- [LOOKUP_TABLE_0x080000.md](../04_DATA_DISCOVERY/LOOKUP_TABLE_0x080000.md)
