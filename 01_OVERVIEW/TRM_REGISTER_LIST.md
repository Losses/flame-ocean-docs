
### **第 3 章：CRU（时钟与复位单元）**
**基地址：未明确给出，通常为 SoC 分配的 APB 地址（如 0x20000000 等）**

| 寄存器名 | 偏移量 | 说明 |
|----------|--------|------|
| CRU_APLL_CON0 | 0x00000 | ARM PLL 控制寄存器0 |
| CRU_APLL_CON1 | 0x00004 | ARM PLL 控制寄存器1 |
| CRU_APLL_CON2 | 0x00008 | ARM PLL 控制寄存器2 |
| CRU_MODE_CON | 0x00010 | 系统工作模式控制寄存器 |
| CRU_CLKSEL0_CON | 0x00014 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL1_CON | 0x00018 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL2_CON | 0x0001C | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL3_CON | 0x00020 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL4_CON | 0x00024 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL5_CON | 0x00028 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL6_CON | 0x0002C | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL7_CON | 0x00030 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL8_CON | 0x00034 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL9_CON | 0x00038 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL10_CON | 0x0003C | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL11_CON | 0x00040 | 内部时钟选择与分频寄存器 |
| CRU_CLKSEL12_CON | 0x00044 | 内部时钟选择与分频寄存器 |
| CRU_CLK_FRACDIV_CON0 | 0x00050 | 内部时钟分数分频寄存器0 |
| CRU_CLK_FRACDIV_CON1 | 0x00054 | 内部时钟分数分频寄存器1 |
| CRU_CLKGATE0_CON | 0x00080 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE1_CON | 0x00084 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE2_CON | 0x00088 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE3_CON | 0x0008C | 内部时钟门控控制寄存器 |
| CRU_CLKGATE4_CON | 0x00090 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE5_CON | 0x00094 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE6_CON | 0x00098 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE7_CON | 0x0009C | 内部时钟门控控制寄存器 |
| CRU_CLKGATE8_CON | 0x000A0 | 内部时钟门控控制寄存器 |
| CRU_CLKGATE9_CON | 0x000A4 | 内部时钟门控控制寄存器 |
| CRU_SOFTRST0_CON | 0x000C0 | 内部软件复位控制寄存器0 |
| CRU_SOFTRST1_CON | 0x000C4 | 内部软件复位控制寄存器1 |
| CRU_SOFTRST2_CON | 0x000C8 | 内部软件复位控制寄存器2 |
| CRU_SOFTRST3_CON | 0x000CC | 内部软件复位控制寄存器3 |
| CRU_STCLK_CON0 | 0x000E0 | 系统 tick 时钟计数器0 |
| CRU_STCLK_CON1 | 0x000E4 | 系统 tick 时钟计数器1 |
| CRU_GLB_SRST_FST_VALUE | 0x000F4 | 全局软件复位配置值 |
| CRU_GLB_CNT_TH | 0x000F8 | 全局复位等待计数器阈值 |

---

### **第 4 章：GRF（通用寄存器文件）**
**基地址：0x50010000**

| 寄存器名 | 偏移量 | 说明 |
|----------|--------|------|
| GRF_GPIO0A_IOMUX | 0x0000 | GPIO0A 引脚复用控制 |
| GRF_GPIO0B_IOMUX | 0x0004 | GPIO0B 引脚复用控制 |
| GRF_GPIO0C_IOMUX | 0x0008 | GPIO0C 引脚复用控制 |
| GRF_GPIO0D_IOMUX | 0x000C | GPIO0D 引脚复用控制 |
| GRF_GPIO0A_PULL | 0x0010 | GPIO0A 上拉/下拉控制 |
| GRF_GPIO0B_PULL | 0x0014 | GPIO0B 上拉/下拉控制 |
| GRF_GPIO0C_PULL | 0x0018 | GPIO0C 上拉/下拉控制 |
| GRF_GPIO0D_PULL | 0x001C | GPIO0D 上拉/下拉控制 |
| GRF_GPIO1A_IOMUX | 0x0020 | GPIO1A 引脚复用控制 |
| GRF_GPIO1B_IOMUX | 0x0024 | GPIO1B 引脚复用控制 |
| GRF_GPIO1C_IOMUX | 0x0028 | GPIO1C 引脚复用控制 |
| GRF_GPIO1D_IOMUX | 0x002C | GPIO1D 引脚复用控制 |
| GRF_GPIO1A_PULL | 0x0030 | GPIO1A 上拉/下拉控制 |
| GRF_GPIO1B_PULL | 0x0034 | GPIO1B 上拉/下拉控制 |
| GRF_GPIO1C_PULL | 0x0038 | GPIO1C 上拉/下拉控制 |
| GRF_GPIO1D_PULL | 0x003C | GPIO1D 上拉/下拉控制 |
| GRF_GPIO2A_IOMUX | 0x0040 | GPIO2A 引脚复用控制 |
| GRF_GPIO2B_IOMUX | 0x0044 | GPIO2B 引脚复用控制 |
| GRF_GPIO2C_IOMUX | 0x0048 | GPIO2C 引脚复用控制 |
| GRF_GPIO2D_IOMUX | 0x004C | GPIO2D 引脚复用控制 |
| GRF_GPIO2A_PULL | 0x0050 | GPIO2A 上拉/下拉控制 |
| GRF_GPIO2B_PULL | 0x0054 | GPIO2B 上拉/下拉控制 |
| GRF_GPIO2C_PULL | 0x0058 | GPIO2C 上拉/下拉控制 |
| GRF_GPIO2D_PULL | 0x005C | GPIO2D 上拉/下拉控制 |
| GRF_PVTM_CON0 | 0x0060 | PVT 监控控制寄存器0 |
| GRF_PVTM_CON1 | 0x0064 | PVT 监控控制寄存器1 |
| GRF_PVTM_CON2 | 0x0068 | PVT 监控控制寄存器2 |
| GRF_PVTM_STATUS0 | 0x006C | PVT 状态寄存器0 |
| GRF_PVTM_STATUS1 | 0x0070 | PVT 状态寄存器1 |
| GRF_USBPHY_CON0 | 0x0080 | USB PHY 控制寄存器0 |
| GRF_USBPHY_CON1 | 0x0084 | USB PHY 控制寄存器1 |
| GRF_USBPHY_CON2 | 0x0088 | USB PHY 控制寄存器2 |
| GRF_USBPHY_CON3 | 0x008C | USB PHY 控制寄存器3 |
| GRF_USBPHY_CON4 | 0x0090 | USB PHY 控制寄存器4 |
| GRF_USBPHY_CON5 | 0x0094 | USB PHY 控制寄存器5 |
| GRF_USBPHY_CON6 | 0x0098 | USB PHY 控制寄存器6 |
| GRF_USBPHY_CON7 | 0x009C | USB PHY 控制寄存器7 |
| GRF_USBPHY_CON8 | 0x00A0 | USB PHY 控制寄存器8 |
| GRF_USBPHY_CON9 | 0x00A4 | USB PHY 控制寄存器9 |
| GRF_USBPHY_CON10 | 0x00A8 | USB PHY 控制寄存器10 |
| GRF_USBPHY_CON11 | 0x00AC | USB PHY 控制寄存器11 |
| GRF_UOC_CON0 | 0x00B0 | USB OTG 控制寄存器0 |
| GRF_UOC_CON1 | 0x00B4 | USB OTG 控制寄存器1 |
| GRF_UOC_CON2 | 0x00B8 | USB OTG 控制寄存器2 |
| GRF_IOMUX_CON | 0x00BC | 全局 IOMUX 控制寄存器 |
| GRF_INTER_CON0 | 0x00C4 | 系统互联控制寄存器0 |
| GRF_GRF_VREF_CON | 0x00CC | VREF 控制寄存器 |
| GRF_SOC_STATUS0 | 0x00E0 | SoC 状态寄存器0 |
| GRF_SOC_STATUS1 | 0x00E4 | SoC 状态寄存器1 |
| GRF_SCC_USB_STATUS | 0x00E8 | USB 状态寄存器 |
| GRF_PRJ_ID | 0x00F8 | 项目 ID 寄存器 |
| GRF_CPU_ID | 0x00FC | CPU ID 寄存器 |

根据《RKNanoD TRM-99-195.pdf》文档内容，以下是**完整且未精简**的寄存器地址列表，包括所有通道和变体：

---

## **1. GRF (General Register File)**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| GRF_SOC_STATUS0 | 0x00e0 | Operational Base + offset (0x00e0) |
| GRF_SOC_STATUS1 | 0x00e4 | Operational Base + offset (0x00e4) |
| GRF_SOC_USB_STATUS | 0x00e8 | Operational Base + offset (0x00e8) |
| GRF_PRJ_ID | 0x00f8 | Operational Base + offset (0x00f8) |
| GRF_CPU_ID | 0x00fc | Operational Base + offset (0x00fc) |

---

## **2. PMU (Power Management Unit)**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| PMU_PMU_WAKEUP_CFG0 | 0x00000 | Operational Base + offset (0x00000) |
| PMU_PMU_WAKEUP_CFG1 | 0x00004 | Operational Base + offset (0x00004) |
| PMU_PMU_WAKEUP_CFG2 | 0x00008 | Operational Base + offset (0x00008) |
| PMU_PMU_PWRDN_CON | 0x0000c | Operational Base + offset (0x0000c) |
| PMU_PMU_PWRDN_ST | 0x00010 | Operational Base + offset (0x00010) |
| PMU_PMU_PWRMODE_CON | 0x00014 | Operational Base + offset (0x00014) |
| PMU_PMU_OSC_CNT | 0x0001c | Operational Base + offset (0x0001c) |
| PMU_VD_LOGIC_PWRDWN_CNT | 0x00020 | Operational Base + offset (0x00020) |
| PMU_VD_LOGIC_PWRUP_CNT | 0x00024 | Operational Base + offset (0x00024) |
| PMU_SOFT_CON | 0x00028 | Operational Base + offset (0x00028) |
| PMU_PMU_PLLLOCK_CNT | 0x0002c | Operational Base + offset (0x0002c) |
| PMU_PMU_INT_CON | 0x00030 | Operational Base + offset (0x00030) |
| PMU_PMU_INT_ST | 0x00034 | Operational Base + offset (0x00034) |
| PMU_PMU_GPIO_POS_INT_ST | 0x00038 | Operational Base + offset (0x00038) |
| PMU_PMU_GPIO_NEG_INT_ST | 0x0003c | Operational Base + offset (0x0003c) |
| PMU_PMU_SYS_REG0 | 0x00040 | Operational Base + offset (0x00040) |
| PMU_PMU_SYS_REG1 | 0x00044 | Operational Base + offset (0x00044) |
| PMU_PMU_SYS_REG2 | 0x00048 | Operational Base + offset (0x00048) |
| PMU_PMU_SYS_REG3 | 0x0004c | Operational Base + offset (0x0004c) |
| PMU_PMU_GPIO_POS_INT_CON | 0x00060 | Operational Base + offset (0x00060) |
| PMU_PMU_GPIO_NEG_INT_CON | 0x00064 | Operational Base + offset (0x00064) |
| PMU_SOFTRST_CON | 0x00080 | Operational Base + offset (0x00080) |

---

## **3. DMAC1 (Direct Memory Access Controller 1)**

### **通道寄存器**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| DWDMA_SAR0 | 0x0000 | Operational Base + offset (0x0000) |
| DWDMA_DAR0 | 0x0008 | Operational Base + offset (0x0008) |
| DWDMA_LLP0 | 0x0010 | Operational Base + offset (0x0010) |
| DWDMA_CTL0 | 0x0018 | Operational Base + offset (0x0018) |
| DWDMA_CTL0_H | 0x001c | Operational Base + offset (0x001c) |
| DWDMA_SSTAT0 | 0x0020 | Operational Base + offset (0x0020) |
| DWDMA_DSTAT0 | 0x0028 | Operational Base + offset (0x0028) |
| DWDMA_SSTATAR0 | 0x0030 | Operational Base + offset (0x0030) |
| DWDMA_DSTATAR0 | 0x0038 | Operational Base + offset (0x0038) |
| DWDMA_CFG0 | 0x0040 | Operational Base + offset (0x0040) |
| DWDMA_CFG0_H | 0x0044 | Operational Base + offset (0x0044) |
| DWDMA_SGR0 | 0x0048 | Operational Base + offset (0x0048) |
| DWDMA_DSR0 | 0x0050 | Operational Base + offset (0x0050) |
| DWDMA_SAR1 | 0x0058 | Operational Base + offset (0x0058) |
| DWDMA_DAR1 | 0x0060 | Operational Base + offset (0x0060) |
| DWDMA_LLP1 | 0x0068 | Operational Base + offset (0x0068) |
| DWDMA_CTL1 | 0x0070 | Operational Base + offset (0x0070) |
| DWDMA_CTL1_H | 0x0074 | Operational Base + offset (0x0074) |
| DWDMA_SSTAT1 | 0x0078 | Operational Base + offset (0x0078) |
| DWDMA_DSTAT1 | 0x0080 | Operational Base + offset (0x0080) |
| DWDMA_SSTATAR1 | 0x0088 | Operational Base + offset (0x0088) |
| DWDMA_DSTATAR1 | 0x0090 | Operational Base + offset (0x0090) |
| DWDMA_CFG1 | 0x0098 | Operational Base + offset (0x0098) |
| DWDMA_CFG1_H | 0x009c | Operational Base + offset (0x009c) |
| DWDMA_SGR1 | 0x00a0 | Operational Base + offset (0x00a0) |
| DWDMA_DSR1 | 0x00a8 | Operational Base + offset (0x00a8) |
| DWDMA_SAR2 | 0x00b0 | Operational Base + offset (0x00b0) |
| DWDMA_DAR2 | 0x00b8 | Operational Base + offset (0x00b8) |
| DWDMA_LLP2 | 0x00c0 | Operational Base + offset (0x00c0) |
| DWDMA_CTL2 | 0x00c8 | Operational Base + offset (0x00c8) |
| DWDMA_CTL2_H | 0x00cc | Operational Base + offset (0x00cc) |
| DWDMA_SSTAT2 | 0x00d0 | Operational Base + offset (0x00d0) |
| DWDMA_DSTAT2 | 0x00d8 | Operational Base + offset (0x00d8) |
| DWDMA_SSTATAR2 | 0x00e0 | Operational Base + offset (0x00e0) |
| DWDMA_DSTATAR2 | 0x00e8 | Operational Base + offset (0x00e8) |
| DWDMA_CFG2 | 0x00f0 | Operational Base + offset (0x00f0) |
| DWDMA_CFG2_H | 0x00f4 | Operational Base + offset (0x00f4) |
| DWDMA_SGR2 | 0x00f8 | Operational Base + offset (0x00f8) |
| DWDMA_DSR2 | 0x0100 | Operational Base + offset (0x0100) |
| DWDMA_SAR3 | 0x0108 | Operational Base + offset (0x0108) |
| DWDMA_DAR3 | 0x0110 | Operational Base + offset (0x0110) |
| DWDMA_LLP3 | 0x0118 | Operational Base + offset (0x0118) |
| DWDMA_CTL3 | 0x0120 | Operational Base + offset (0x0120) |
| DWDMA_CTL3_H | 0x0124 | Operational Base + offset (0x0124) |
| DWDMA_SSTAT3 | 0x0128 | Operational Base + offset (0x0128) |
| DWDMA_DSTAT3 | 0x0130 | Operational Base + offset (0x0130) |
| DWDMA_SSTATAR3 | 0x0138 | Operational Base + offset (0x0138) |
| DWDMA_DSTATAR3 | 0x0140 | Operational Base + offset (0x0140) |
| DWDMA_CFG3 | 0x0148 | Operational Base + offset (0x0148) |
| DWDMA_CFG3_H | 0x014c | Operational Base + offset (0x014c) |
| DWDMA_SGR3 | 0x0150 | Operational Base + offset (0x0150) |
| DWDMA_DSR3 | 0x0158 | Operational Base + offset (0x0158) |
| DWDMA_SAR4 | 0x0160 | Operational Base + offset (0x0160) |
| DWDMA_DAR4 | 0x0168 | Operational Base + offset (0x0168) |
| DWDMA_LLP4 | 0x0170 | Operational Base + offset (0x0170) |
| DWDMA_CTL4 | 0x0178 | Operational Base + offset (0x0178) |
| DWDMA_CTL4_H | 0x017c | Operational Base + offset (0x017c) |
| DWDMA_SSTAT4 | 0x0180 | Operational Base + offset (0x0180) |
| DWDMA_DSTAT4 | 0x0188 | Operational Base + offset (0x0188) |
| DWDMA_SSTATAR4 | 0x0190 | Operational Base + offset (0x0190) |
| DWDMA_DSTATAR4 | 0x0198 | Operational Base + offset (0x0198) |
| DWDMA_CFG4 | 0x01a0 | Operational Base + offset (0x01a0) |
| DWDMA_CFG4_H | 0x01a4 | Operational Base + offset (0x01a4) |
| DWDMA_SGR4 | 0x01a8 | Operational Base + offset (0x01a8) |
| DWDMA_DSR4 | 0x01b0 | Operational Base + offset (0x01b0) |
| DWDMA_SAR5 | 0x01b8 | Operational Base + offset (0x01b8) |
| DWDMA_DAR5 | 0x01c0 | Operational Base + offset (0x01c0) |
| DWDMA_LLP5 | 0x01c8 | Operational Base + offset (0x01c8) |
| DWDMA_CTL5 | 0x01d0 | Operational Base + offset (0x01d0) |
| DWDMA_CTL5_H | 0x01d4 | Operational Base + offset (0x01d4) |
| DWDMA_SSTAT5 | 0x01d8 | Operational Base + offset (0x01d8) |
| DWDMA_DSTAT5 | 0x01e0 | Operational Base + offset (0x01e0) |
| DWDMA_SSTATAR5 | 0x01e8 | Operational Base + offset (0x01e8) |
| DWDMA_DSTATAR5 | 0x01f0 | Operational Base + offset (0x01f0) |
| DWDMA_CFG5 | 0x01f8 | Operational Base + offset (0x01f8) |
| DWDMA_CFG5_H | 0x01fc | Operational Base + offset (0x01fc) |
| DWDMA_SGR5 | 0x0200 | Operational Base + offset (0x0200) |
| DWDMA_DSR5 | 0x0208 | Operational Base + offset (0x0208) |

### **全局中断状态与控制寄存器**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| DWDMA_RAWTER | 0x02c0 | Operational Base + offset (0x02c0) |
| DWDMA_RAWBLOCK | 0x02c8 | Operational Base + offset (0x02c8) |
| DWDMA_RAWSRCT | 0x02d0 | Operational Base + offset (0x02d0) |
| DWDMA_RAWDSTT | 0x02d8 | Operational Base + offset (0x02d8) |
| DWDMA_RAWERR | 0x02e0 | Operational Base + offset (0x02e0) |
| DWDMA_STATUSTFR | 0x02e8 | Operational Base + offset (0x02e8) |
| DWDMA_STATUSBLOCK | 0x02f0 | Operational Base + offset (0x02f0) |
| DWDMA_STATUSS0 | 0x02f8 | Operational Base + offset (0x02f8) |
| DWDMA_STATUSD0 | 0x0300 | Operational Base + offset (0x0300) |
| DWDMA_STATUSER | 0x0308 | Operational Base + offset (0x0308) |
| DWDMA_MASKTFR | 0x0310 | Operational Base + offset (0x0310) |
| DWDMA_MASKBL0 | 0x0318 | Operational Base + offset (0x0318) |
| DWDMA_MASKSRC | 0x0320 | Operational Base + offset (0x0320) |
| DWDMA_MASKDST | 0x0328 | Operational Base + offset (0x0328) |
| DWDMA_MASKERR | 0x0330 | Operational Base + offset (0x0330) |
| DWDMA_CLEARTR | 0x0338 | Operational Base + offset (0x0338) |
| DWDMA_CLEARBL | 0x0340 | Operational Base + offset (0x0340) |
| DWDMA_CLEARSR | 0x0348 | Operational Base + offset (0x0348) |
| DWDMA_CLEARDS | 0x0350 | Operational Base + offset (0x0350) |
| DWDMA_CLEARER | 0x0358 | Operational Base + offset (0x0358) |
| DWDMA_STATUSIN | 0x0360 | Operational Base + offset (0x0360) |
| DWDMA_DMACFGR | 0x0398 | Operational Base + offset (0x0398) |
| DWDMA_CHENREG | 0x03a0 | Operational Base + offset (0x03a0) |

---

## **4. DMAC2 (Direct Memory Access Controller 2)**

### **通道寄存器**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| DWDMA_SAR0 | 0x0000 | Operational Base + offset (0x0000) |
| DWDMA_DAR0 | 0x0008 | Operational Base + offset (0x0008) |
| DWDMA_LLP0 | 0x0010 | Operational Base + offset (0x0010) |
| DWDMA_CTL0 | 0x0018 | Operational Base + offset (0x0018) |
| DWDMA_CTL0_H | 0x001c | Operational Base + offset (0x001c) |
| DWDMA_SSTAT0 | 0x0020 | Operational Base + offset (0x0020) |
| DWDMA_DSTAT0 | 0x0028 | Operational Base + offset (0x0028) |
| DWDMA_SSTATAR0 | 0x0030 | Operational Base + offset (0x0030) |
| DWDMA_DSTATAR0 | 0x0038 | Operational Base + offset (0x0038) |
| DWDMA_CFG0 | 0x0040 | Operational Base + offset (0x0040) |
| DWDMA_CFG0_H | 0x0044 | Operational Base + offset (0x0044) |
| DWDMA_SGR0 | 0x0048 | Operational Base + offset (0x0048) |
| DWDMA_DSR0 | 0x0050 | Operational Base + offset (0x0050) |
| DWDMA_SAR1 | 0x0058 | Operational Base + offset (0x0058) |
| DWDMA_DAR1 | 0x0060 | Operational Base + offset (0x0060) |
| DWDMA_LLP1 | 0x0068 | Operational Base + offset (0x0068) |
| DWDMA_CTL1 | 0x0070 | Operational Base + offset (0x0070) |
| DWDMA_CTL1_H | 0x0074 | Operational Base + offset (0x0074) |
| DWDMA_SSTAT1 | 0x0078 | Operational Base + offset (0x0078) |
| DWDMA_DSTAT1 | 0x0080 | Operational Base + offset (0x0080) |
| DWDMA_SSTATAR1 | 0x0088 | Operational Base + offset (0x0088) |
| DWDMA_DSTATAR1 | 0x0090 | Operational Base + offset (0x0090) |
| DWDMA_CFG1 | 0x0098 | Operational Base + offset (0x0098) |
| DWDMA_CFG1_H | 0x009c | Operational Base + offset (0x009c) |
| DWDMA_SGR1 | 0x00a0 | Operational Base + offset (0x00a0) |
| DWDMA_DSR1 | 0x00a8 | Operational Base + offset (0x00a8) |

### **全局中断状态与控制寄存器**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| DWDMA_RAWTFR | 0x02c0 | Operational Base + offset (0x02c0) |
| DWDMA_RAWBLOCK | 0x02c8 | Operational Base + offset (0x02c8) |
| DWDMA_RAWSRCTRAN | 0x02d0 | Operational Base + offset (0x02d0) |
| DWDMA_RAWDSTTRAN | 0x02d8 | Operational Base + offset (0x02d8) |
| DWDMA_RAWERR | 0x02e0 | Operational Base + offset (0x02e0) |
| DWDMA_STATUSTFR | 0x02e8 | Operational Base + offset (0x02e8) |
| DWDMA_STATUSBLOCK | 0x02f0 | Operational Base + offset (0x02f0) |
| DWDMA_STATUSSRCTRAN | 0x02f8 | Operational Base + offset (0x02f8) |
| DWDMA_STATUSDSTTRAN | 0x0300 | Operational Base + offset (0x0300) |
| DWDMA_STATUSER | 0x0308 | Operational Base + offset (0x0308) |
| DWDMA_MASKTFR | 0x0310 | Operational Base + offset (0x0310) |
| DWDMA_MASKLOCK | 0x0318 | Operational Base + offset (0x0318) |
| DWDMA_MASKSRCTRAN | 0x0320 | Operational Base + offset (0x0320) |
| DWDMA_MASKDSTTRAN | 0x0328 | Operational Base + offset (0x0328) |
| DWDMA_MASKERR | 0x0330 | Operational Base + offset (0x0330) |
| DWDMA_CLEARTFR | 0x0338 | Operational Base + offset (0x0338) |
| DWDMA_CLEARLOCK | 0x0340 | Operational Base + offset (0x0340) |
| DWDMA_CLEARSRCTRAN | 0x0348 | Operational Base + offset (0x0348) |
| DWDMA_CLEARDSTTRAN | 0x0350 | Operational Base + offset (0x0350) |
| DWDMA_CLEARERR | 0x0358 | Operational Base + offset (0x0358) |
| DWDMA_STATUSINT | 0x0360 | Operational Base + offset (0x0360) |
| DWDMA_DMACFGREG | 0x0398 | Operational Base + offset (0x0398) |
| DWDMA_CHENREG | 0x03a0 | Operational Base + offset (0x03a0) |

---

## **5. ACODEC (Audio Codec)**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| ACODEC_VCTL | 0x0040 | Operational Base + offset (0x0040) |
| ACODEC_VCTIME | 0x0044 | Operational Base + offset (0x0044) |
| ACODEC_LPST | 0x0048 | Operational Base + offset (0x0048) |
| ACODEC_LPT | 0x004c | Operational Base + offset (0x004c) |
| ACODEC_SRST | 0x0054 | Operational Base + offset (0x0054) |
| ACODEC_DIGEN | 0x0058 | Operational Base + offset (0x0058) |
| ACODEC_CLKE | 0x0060 | Operational Base + offset (0x0060) |
| ACODEC_RTCFG0 | 0x0080 | Operational Base + offset (0x0080) |
| ACODEC_RTCFG1 | 0x0084 | Operational Base + offset (0x0084) |
| ACODEC_RTCFG2 | 0x0088 | Operational Base + offset (0x0088) |
| ACODEC_ADCCFG0 | 0x00c0 | Operational Base + offset (0x00c0) |
| ACODEC_ADCCFG1 | 0x00c4 | Operational Base + offset (0x00c4) |
| ACODEC_ADCVCTLL | 0x00c8 | Operational Base + offset (0x00c8) |
| ACODEC_ADCVCTLR | 0x00cc | Operational Base + offset (0x00cc) |
| ACODEC_ADCSR | 0x00d0 | Operational Base + offset (0x00d0) |
| ACODEC_ALC0 | 0x00d4 | Operational Base + offset (0x00d4) |
| ACODEC_ALC1 | 0x00d8 | Operational Base + offset (0x00d8) |
| ACODEC_ALC2 | 0x00dc | Operational Base + offset (0x00dc) |
| ACODEC_ADCNG | 0x00e0 | Operational Base + offset (0x00e0) |
| ACODEC_ADCNGST | 0x00e4 | Operational Base + offset (0x00e4) |
| ACODEC_ADCHPF | 0x00e8 | Operational Base + offset (0x00e8) |
| ACODEC_ADCVSTL | 0x00ec | Operational Base + offset (0x00ec) |
| ACODEC_ADCVSTR | 0x00f0 | Operational Base + offset (0x00f0) |
| ACODEC_DACCFG0 | 0x0100 | Operational Base + offset (0x0100) |
| ACODEC_DACCFG1 | 0x0104 | Operational Base + offset (0x0104) |
| ACODEC_DACCFG2 | 0x0108 | Operational Base + offset (0x0108) |
| ACODEC_DACPOPD | 0x0140 | Operational Base + offset (0x0140) |
| ACODEC_DACST | 0x0144 | Operational Base + offset (0x0144) |
| ACODEC_DACVCTLL | 0x0148 | Operational Base + offset (0x0148) |
| ACODEC_DACVCTLR | 0x014c | Operational Base + offset (0x014c) |
| ACODEC_DACSR | 0x0150 | Operational Base + offset (0x0150) |
| ACODEC_LMT0 | 0x0154 | Operational Base + offset (0x0154) |
| ACODEC_LMT1 | 0x0158 | Operational Base + offset (0x0158) |
| ACODEC_LMT2 | 0x015c | Operational Base + offset (0x015c) |
| ACODEC_DACMUTE | 0x0160 | Operational Base + offset (0x0160) |
| ACODEC_MIXCTRL | 0x0164 | Operational Base + offset (0x0164) |
| ACODEC_DACVSTL | 0x0168 | Operational Base + offset (0x0168) |
| ACODEC_DACVSTR | 0x016c | Operational Base + offset (0x016c) |
| ACODEC_LICFG0 | 0x0180 | Operational Base + offset (0x0180) |
| ACODEC_LICFG1 | 0x0184 | Operational Base + offset (0x0184) |
| ACODEC_LICFG2 | 0x0188 | Operational Base + offset (0x0188) |
| ACODEC_LICFG3 | 0x018c | Operational Base + offset (0x018c) |
| ACODEC_LICFG4 | 0x0190 | Operational Base + offset (0x0190) |
| ACODEC_LILMT0 | 0x0198 | Operational Base + offset (0x0198) |
| ACODEC_LILMT1 | 0x019c | Operational Base + offset (0x019c) |
| ACODEC_LILMT2 | 0x01a0 | Operational Base + offset (0x01a0) |
| ACODEC_ADCNGLMTCFG | 0x01a4 | Operational Base + offset (0x01a4) |
| ACODEC_ADCNGLMTST | 0x01a8 | Operational Base + offset (0x01a8) |
| ACODEC_HPLOCFG0 | 0x01c0 | Operational Base + offset (0x01c0) |
| ACODEC_HPLOCFG1 | 0x01c4 | Operational Base + offset (0x01c4) |
| ACODEC_HPLOCFG2 | 0x01c8 | Operational Base + offset (0x01c8) |
| ACODEC_HPLOCFG3 | 0x01cc | Operational Base + offset (0x01cc) |
| ACODEC_HPLOCFG4 | 0x01d0 | Operational Base + offset (0x01d0) |
| ACODEC_HPLOCFG5 | 0x01d4 | Operational Base + offset (0x01d4) |
| ACODEC_PLLCFG0 | 0x0200 | Operational Base + offset (0x0200) |
| ACODEC_PLLCFG1 | 0x0204 | Operational Base + offset (0x0204) |
| ACODEC_PLLCFG2 | 0x0208 | Operational Base + offset (0x0208) |
| ACODEC_PLLCFG3 | 0x020c | Operational Base + offset (0x020c) |
| ACODEC_PLLCFG4 | 0x0210 | Operational Base + offset (0x0210) |
| ACODEC_PLLCFG5 | 0x0214 | Operational Base + offset (0x0214) |
| ACODEC_I2SCKM | 0x0240 | Operational Base + offset (0x0240) |
| ACODEC_I2SRXCR0 | 0x0244 | Operational Base + offset (0x0244) |
| ACODEC_I2SRXCR1 | 0x0248 | Operational Base + offset (0x0248) |
| ACODEC_I2SRXCR2 | 0x024c | Operational Base + offset (0x024c) |
| ACODEC_I2SRXCMD | 0x0250 | Operational Base + offset (0x0250) |
| ACODEC_I2STXCR0 | 0x0260 | Operational Base + offset (0x0260) |
| ACODEC_I2STXCR1 | 0x0264 | Operational Base + offset (0x0264) |
| ACODEC_I2STXCR2 | 0x0268 | Operational Base + offset (0x0268) |
| ACODEC_I2STXCMD | 0x0270 | Operational Base + offset (0x0270) |
| ACODEC_TMCFG0 | 0x0300 | Operational Base + offset (0x0300) |

---

## **6. SDMMC (SD/MMC Controller)**

| 寄存器名称 | 偏移量 | 完整地址表达式 |
|-----------|--------|----------------|
| SDMMC_CTRL | 0x0000 | Operational Base + offset (0x0000) |
| SDMMC_PWREN | 0x0004 | Operational Base + offset (0x0004) |
| SDMMC_CLKDIV | 0x0008 | Operational Base + offset (0x0008) |
| SDMMC_CLKENA | 0x0010 | Operational Base + offset (0x0010) |
| SDMMC_TMOUT | 0x0014 | Operational Base + offset (0x0014) |
| SDMMC_CTYPE | 0x0018 | Operational Base + offset (0x0018) |
| SDMMC_BLKSIZ | 0x001c | Operational Base + offset (0x001c) |
| SDMMC_BYTCNT | 0x0020 | Operational Base + offset (0x0020) |
| SDMMC_INTMASK | 0x0024 | Operational Base + offset (0x0024) |
| SDMMC_CMDARG | 0x0028 | Operational Base + offset (0x0028) |
| SDMMC_CMD | 0x002c | Operational Base + offset (0x002c) |
| SDMMC_RESP0 | 0x0030 | Operational Base + offset (0x0030) |
| SDMMC_RESP1 | 0x0034 | Operational Base + offset (0x0034) |
| SDMMC_RESP2 | 0x0038 | Operational Base + offset (0x0038) |
| SDMMC_RESP3 | 0x003c | Operational Base + offset (0x003c) |
| SDMMC_MINTSTS | 0x0040 | Operational Base + offset (0x0040) |
| SDMMC_RINTSTS | 0x0044 | Operational Base + offset (0x0044) |
| SDMMC_STATUS | 0x0048 | Operational Base + offset (0x0048) |
| SDMMC_FIFOTH | 0x004c | Operational Base + offset (0x004c) |
| SDMMC_CDETECT | 0x0050 | Operational Base + offset (0x0050) |
| SDMMC_WRTPRT | 0x0054 | Operational Base + offset (0x0054) |
| SDMMC_TCBCNT | 0x005c | Operational Base + offset (0x005c) |
| SDMMC_TBBCNT | 0x0060 | Operational Base + offset (0x0060) |
| SDMMC_DEBNCE | 0x0064 | Operational Base + offset (0x0064) |
| SDMMC_USRID | 0x0068 | Operational Base + offset (0x0068) |
| SDMMC_RST_n | 0x0078 | Operational Base + offset (0x0078) |
| SDMMC_BACK_END_POWER | 0x0104 | Operational Base + offset (0x0104) |
| SDMMC_FIFO_BASE | 0x0200 | Operational Base + offset (0x0200) |



---

## **1. SD/MMC 控制器（SDMMC）**
| 寄存器名称 | 偏移量（Hex） | 说明 |
|------------|---------------|------|
| SDMMC_CTRL | 0x0000 | 控制寄存器 |
| SDMMC_PWREN | 0x0004 | 电源使能寄存器 |
| SDMMC_CLKDIV | 0x0008 | 时钟分频寄存器 |
| SDMMC_CLKENA | 0x0010 | 时钟使能寄存器 |
| SDMMC_TMOUT | 0x0014 | 超时寄存器 |
| SDMMC_CTYPE | 0x0018 | 卡类型寄存器 |
| SDMMC_BLKSIZ | 0x001C | 块大小寄存器 |
| SDMMC_BYTCNT | 0x0020 | 字节计数寄存器 |
| SDMMC_INTMASK | 0x0024 | 中断掩码寄存器 |
| SDMMC_CMDARG | 0x0028 | 命令参数寄存器 |
| SDMMC_CMD | 0x002C | 命令寄存器 |
| SDMMC_RESP0 | 0x0030 | 响应寄存器0 |
| SDMMC_RESP1 | 0x0034 | 响应寄存器1 |
| SDMMC_RESP2 | 0x0038 | 响应寄存器2 |
| SDMMC_RESP3 | 0x003C | 响应寄存器3 |
| SDMMC_MINTSTS | 0x0040 | 已屏蔽中断状态寄存器 |
| SDMMC_RINTSTS | 0x0044 | 原始中断状态寄存器 |
| SDMMC_STATUS | 0x0048 | 状态寄存器 |
| SDMMC_FIFOTH | 0x004C | FIFO 阈值寄存器 |
| SDMMC_CDETECT | 0x0050 | 卡检测寄存器 |
| SDMMC_WRTPRT | 0x0054 | 写保护寄存器 |
| SDMMC_TCBCNT | 0x005C | 传输至卡的字节计数 |
| SDMMC_TBBCNT | 0x0060 | 传输至 FIFO 的字节计数 |
| SDMMC_DEBNCE | 0x0064 | 卡检测去抖动寄存器 |
| SDMMC_USRID | 0x0068 | 用户 ID 寄存器 |
| SDMMC_RST_n | 0x0078 | 硬件复位寄存器 |
| SDMMC_BACK_END_POWER | 0x0104 | 后端电源寄存器 |
| SDMMC_FIFO_BASE | 0x0200 | FIFO 基地址寄存器 |

---

## **2. I2S/PCM 控制器（I2Sx）**
| 寄存器名称 | 偏移量（Hex） | 说明 |
|------------|---------------|------|
| I2Sx_TXCR | 0x0000 | 发送控制寄存器 |
| I2Sx_RXCR | 0x0004 | 接收控制寄存器 |
| I2Sx_CKR | 0x0008 | 时钟控制寄存器 |
| I2Sx_FIFOLR | 0x000C | FIFO 水位寄存器 |
| I2Sx_DMACR | 0x0010 | DMA 控制寄存器 |
| I2Sx_INTCR | 0x0014 | 中断控制寄存器 |
| I2Sx_INTSR | 0x0018 | 中断状态寄存器 |
| I2Sx_XFER | 0x001C | 传输启动寄存器 |
| I2Sx_CLR | 0x0020 | SCLK 域逻辑清零寄存器 |
| I2Sx_TXDR | 0x0024 | 发送 FIFO 数据寄存器 |
| I2Sx_RXDR | 0x0028 | 接收 FIFO 数据寄存器 |

---

## **3. USB OTG 控制器**
> 注：本部分文档中未详细列出所有寄存器地址，仅包含部分控制信号和配置位。

| 信号/配置位 | 相关寄存器/控制位 | 说明 |
|-------------|-------------------|------|
| OTGDSIABLE0 | grf_uoc_con[0] | OTG 禁用控制 |
| BYPASSDMENO | grf_uoc_con[1] | DM0 发送器数字旁路使能 |
| BYPASSSEL0 | grf_uoc_con[2] | 发送器数字旁路模式使能 |
| COMMONONN | uoc0_con[0] | 公共块掉电控制 |

---

## **4. VOP（显示控制器）**
| 寄存器名称 | 偏移量（Hex） | 说明 |
|------------|---------------|------|
| VOP_MCU_CON | 0x0000 | MCU 控制寄存器 |

---

## **5. 嵌入式 SRAM**
| SRAM 名称 | 地址范围 | 大小 | 电源域 |
|-----------|----------|------|--------|
| SYSRAM0 | 0x0300_0000 ~ 0x0304_FFFF | 320 KB | PD_LOGIC |
| SYSRAM1 | 0x0305_0000 ~ 0x0308_FFFF | 256 KB | PD_LOGIC |
| HIGHRAM0 | 0x0100_0000 ~ 0x0101_FFFF | 128 KB | PD_HIGH |
| HIGHRAM1 | 0x0102_0000 ~ 0x0105_FFFF | 256 KB | PD_HIGH |
| PMUSRAM | 0x0309_0000 ~ 0x0309_FFFF | 64 KB | PD_PMU |

---

### **第16章：SPI 控制器**
#### 16.4.1 寄存器列表：

| 寄存器名称        | 偏移地址 | 大小 | 复位值     | 描述                       |
|-------------------|----------|------|------------|----------------------------|
| SPI_CTRLR0        | 0x0000   | W    | 0x00000002 | 控制寄存器 0               |
| SPI_CTRLR1        | 0x0004   | W    | 0x00000000 | 控制寄存器 1               |
| SPI_ENR           | 0x0008   | W    | 0x00000000 | SPI 使能寄存器             |
| SPI_SER           | 0x000c   | W    | 0x00000000 | 从机使能寄存器             |
| SPI_BAUDR         | 0x0010   | W    | 0x00000000 | 波特率选择寄存器           |
| SPI_TXFTLR        | 0x0014   | W    | 0x00000000 | 发送 FIFO 阈值寄存器       |
| SPI_RXFTLR        | 0x0018   | W    | 0x00000000 | 接收 FIFO 阈值寄存器       |
| SPI_TXFLR         | 0x001c   | W    | 0x00000000 | 发送 FIFO 当前数据数量     |
| SPI_RXFLR         | 0x0020   | W    | 0x00000000 | 接收 FIFO 当前数据数量     |
| SPI_SR            | 0x0024   | W    | 0x0000000c | 状态寄存器                 |
| SPI_IPR           | 0x0028   | W    | 0x00000000 | 中断极性寄存器             |
| SPI_IMR           | 0x002c   | W    | 0x00000000 | 中断掩码寄存器             |
| SPI_ISR           | 0x0030   | W    | 0x00000000 | 中断状态寄存器             |
| SPI_RISR          | 0x0034   | W    | 0x00000001 | 原始中断状态寄存器         |
| SPI_ICR           | 0x0038   | W    | 0x00000000 | 中断清除寄存器             |
| SPI_DMACR         | 0x003c   | W    | 0x00000000 | DMA 控制寄存器             |
| SPI_DMATDLR       | 0x0040   | W    | 0x00000000 | DMA 发送数据阈值           |
| SPI_DMARDLR       | 0x0044   | W    | 0x00000000 | DMA 接收数据阈值           |
| SPI_TXDR          | 0x0048   | W    | 0x00000000 | 发送 FIFO 数据寄存器       |
| SPI_RXDR          | 0x004c   | W    | 0x00000000 | 接收 FIFO 数据寄存器       |

---

### **第17章：SAR-ADC**
#### 17.4.1 寄存器列表：

| 寄存器名称     | 偏移地址 | 大小 | 复位值     | 描述                     |
|----------------|----------|------|------------|--------------------------|
| SARADC_DATA    | 0x0000   | W    | 0x00000000 | ADC 转换数据寄存器       |
| SARADC_STAS    | 0x0004   | W    | 0x00000000 | ADC 状态寄存器           |
| SARADC_CTRL    | 0x0008   | W    | 0x00000000 | ADC 控制寄存器           |
| GRF_VREF_CON   | GRF基址+0x00cc | W | 0x00000018 | ADC 参考电压控制寄存器 |

---

### **第18章：定时器**
#### 18.4.1 寄存器列表（Timer0 & Timer1）：

| 寄存器名称              | 偏移地址 | 大小 | 复位值     | 描述                     |
|-------------------------|----------|------|------------|--------------------------|
| TIMER0_LOAD_COUNT0      | 0x0000   | W    | 0x00000000 | Timer0 加载计数值低 32 位 |
| TIMER0_LOAD_COUNT1      | 0x0004   | W    | 0x00000000 | Timer0 加载计数值高 32 位 |
| TIMER0_CURRENT_VALUE0   | 0x0008   | W    | 0x00000000 | Timer0 当前值低 32 位     |
| TIMER0_CURRENT_VALUE1   | 0x000c   | W    | 0x00000000 | Timer0 当前值高 32 位     |
| TIMER0_CONTROLREG       | 0x0010   | W    | 0x00000000 | Timer0 控制寄存器         |
| TIMER0_INTSTATUS        | 0x0018   | W    | 0x00000000 | Timer0 中断状态寄存器     |
| TIMER1_LOAD_COUNT0      | 0x0020   | W    | 0x00000000 | Timer1 加载计数值低 32 位 |
| TIMER1_LOAD_COUNT1      | 0x0024   | W    | 0x00000000 | Timer1 加载计数值高 32 位 |
| TIMER1_CURRENT_VALUE0   | 0x0028   | W    | 0x00000000 | Timer1 当前值低 32 位     |
| TIMER1_CURRENT_VALUE1   | 0x002c   | W    | 0x00000000 | Timer1 当前值高 32 位     |
| TIMER1_CONTROLREG       | 0x0030   | W    | 0x00000000 | Timer1 控制寄存器         |
| TIMER1_INTSTATUS        | 0x0038   | W    | 0x00000000 | Timer1 中断状态寄存器     |

---

### **第19章：GPIO**
#### GPIO0 基地址：`0x40160000`
#### GPIO1 基地址：`0x40170000`
#### GPIO2 基地址：`0x50030000`

**通用寄存器结构（适用于 GPIO0/1/2）：**

| 寄存器名称           | 偏移地址 | 大小 | 复位值     | 描述                     |
|----------------------|----------|------|------------|--------------------------|
| GPIO_SWPORT_DR       | 0x0000   | W    | 0x00000000 | I/O 端口数据寄存器       |
| GPIO_SWPORT_DDR      | 0x0004   | W    | 0x00000000 | I/O 端口方向寄存器       |
| GPIO_INTEN           | 0x0030   | W    | 0x00000000 | 中断使能寄存器           |
| GPIO_INTMASK         | 0x0034   | W    | 0x00000000 | 中断掩码寄存器           |
| GPIO_INTTYPE_LEVEL   | 0x0038   | W    | 0x00000000 | 中断电平类型寄存器       |
| GPIO_INT_POLARITY    | 0x003c   | W    | 0x00000000 | 中断极性寄存器           |
| GPIO_INT_STATUS      | 0x0040   | W    | 0x00000000 | 中断状态寄存器           |
| GPIO_INT_RAWSTATUS   | 0x0044   | W    | 0x00000000 | 原始中断状态寄存器       |
| GPIO_DEBOUNCE        | 0x0048   | W    | 0x00000000 | 去抖使能寄存器           |
| GPIO_PORT_EOI        | 0x004c   | W    | 0x00000000 | 中断清除寄存器           |
| GPIO_EXT_PORT        | 0x0050   | W    | 0x00000000 | 外部端口读取寄存器       |
| GPIO_LS_SYNC         | 0x0060   | W    | 0x00000000 | 电平敏感同步使能寄存器   |

---

### **第20章：看门狗定时器**
#### 20.4.1 寄存器列表：

| 寄存器名称 | 偏移地址 | 大小 | 复位值     | 描述                     |
|------------|----------|------|------------|--------------------------|
| WDT_CR     | 0x0000   | W    | 0x0000000a | 控制寄存器               |
| WDT_TORR   | 0x0004   | W    | 0x00000000 | 超时范围寄存器           |
| WDT_CCVR   | 0x0008   | W    | 0x00000000 | 当前计数值寄存器         |
| WDT_CRR    | 0x000c   | W    | 0x00000000 | 计数器重启寄存器         |
| WDT_STAT   | 0x0010   | W    | 0x00000000 | 中断状态寄存器           |
| WDT_EOI    | 0x0014   | W    | 0x00000000 | 中断清除寄存器           |

---

### **第21章：PWM**
#### PWM 基地址 + 通道偏移（PWM0~PWM3）
| 寄存器名称              | 偏移地址 | 大小 | 复位值     | 描述                     |
|-------------------------|----------|------|------------|--------------------------|
| PWM_PWMx_CNT            | 0x0000 + n*0x10 | W | 0x00000000 | 通道计数器寄存器         |
| PWM_PWMx_PERIOD_HPR     | 0x0004 + n*0x10 | W | 0x00000000 | 周期/高电平捕获寄存器    |
| PWM_PWMx_DUTY_LPR       | 0x0008 + n*0x10 | W | 0x00000000 | 占空比/低电平捕获寄存器  |
| PWM_PWMx_CTRL           | 0x000c + n*0x10 | W | 0x00000000 | 通道控制寄存器           |

**公共寄存器：**
| 寄存器名称     | 偏移地址 | 大小 | 复位值     | 描述                     |
|----------------|----------|------|------------|--------------------------|
| PWM_INTSTS     | 0x0040   | W    | 0x00000000 | 中断状态寄存器           |
| PWM_INT_EN     | 0x0044   | W    | 0x00000000 | 中断使能寄存器           |

---

### **第22章：I2C**
#### 22.4.1 寄存器列表：

| 寄存器名称     | 偏移地址 | 大小 | 复位值     | 描述                     |
|----------------|----------|------|------------|--------------------------|
| I2C_CON        | 0x0000   | W    | 0x00000000 | 控制寄存器               |
| I2C_CLKDIV     | 0x0004   | W    | 0x00060006 | 时钟分频寄存器           |
| I2C_MRXADDR    | 0x0008   | W    | 0x00000000 | 主接收地址寄存器         |
| I2C_MRXRADDR   | 0x000c   | W    | 0x00000000 | 主接收寄存器地址         |
| I2C_MTXCNT     | 0x0010   | W    | 0x00000000 | 主发送字节数             |
| I2C_MRXCNT     | 0x0014   | W    | 0x00000000 | 主接收字节数             |
| I2C_IEN        | 0x0018   | W    | 0x00000000 | 中断使能寄存器           |
| I2C_IPD        | 0x001c   | W    | 0x00000000 | 中断挂起寄存器           |
| I2C_FCNT       | 0x0020   | W    | 0x00000000 | 已完成字节数             |
| I2C_TXDATA0~7  | 0x0100~0x011c | W | 0x00000000 | 发送数据寄存器 0~7       |
| I2C_RXDATA0~7  | 0x0200~0x021c | W | 0x00000000 | 接收数据寄存器 0~7       |

---

### **第23章：UART**
#### UART0~UART5 基地址独立，寄存器结构相同：

| 寄存器名称     | 偏移地址 | 大小 | 复位值     | 描述                     |
|----------------|----------|------|------------|--------------------------|
| UART_RBR       | 0x0000   | W    | 0x00000000 | 接收缓冲寄存器           |
| UART_THR       | 0x0000   | W    | 0x00000000 | 发送保持寄存器           |
| UART_DLL       | 0x0000   | W    | 0x00000000 | 分频锁存器低字节         |
| UART_DLH       | 0x0004   | W    | 0x00000000 | 分频锁存器高字节         |
| UART_IER       | 0x0004   | W    | 0x00000000 | 中断使能寄存器           |
| UART_IIR       | 0x0008   | W    | 0x00000000 | 中断识别寄存器           |
| UART_FCR       | 0x0008   | W    | 0x00000000 | FIFO 控制寄存器          |
| UART_LCR       | 0x000c   | W    | 0x00000000 | 线路控制寄存器           |
| UART_MCR       | 0x0010   | W    | 0x00000000 | 调制解调器控制寄存器     |
| UART_LSR       | 0x0014   | W    | 0x00000000 | 线路状态寄存器           |
| UART_MSR       | 0x0018   | W    | 0x00000000 | 调制解调器状态寄存器     |
| UART_SCR       | 0x001c   | W    | 0x00000000 | 暂存寄存器               |
| UART_SRBR      | 0x0030   | W    | 0x00000000 | 影子接收缓冲寄存器       |
| UART_STHR      | 0x006c   | W    | 0x00000000 | 影子发送保持寄存器       |
| UART_FAR       | 0x0070   | W    | 0x00000000 | FIFO 访问寄存器          |
| UART_TFR       | 0x0074   | W    | 0x00000000 | 发送 FIFO 读取寄存器     |
| UART_RFW       | 0x0078   | W    | 0x00000000 | 接收 FIFO 写入寄存器     |
| UART_USR       | 0x007c   | W    | 0x00000000 | UART 状态寄存器          |
| UART_TFL       | 0x0080   | W    | 0x00000000 | 发送 FIFO 当前数据数量   |
| UART_RFL       | 0x0084   | W    | 0x00000000 | 接收 FIFO 当前数据数量   |
| UART_SRR       | 0x0088   | W    | 0x00000000 | 软件复位寄存器           |
| UART_SRTS      | 0x008c   | W    | 0x00000000 | 影子请求发送寄存器       |
| UART_SBCR      | 0x0090   | W    | 0x00000000 | 影子中断控制寄存器       |
| UART_SDMAM     | 0x0094   | W    | 0x00000000 | 影子 DMA 模式寄存器      |
| UART_SFE       | 0x0098   | W    | 0x00000000 | 影子 FIFO 使能寄存器     |
| UART_SRT       | 0x009c   | W    | 0x00000000 | 影子接收触发寄存器       |
| UART_STET      | 0x00a0   | W    | 0x00000000 | 影子发送空触发寄存器     |
| UART_HTX       | 0x00a4   | W    | 0x00000000 | 暂停发送寄存器           |
| UART_DMASA     | 0x00a8   | W    | 0x00000000 | DMA 软件应答寄存器       |
| UART_CPR       | 0x00f4   | W    | 0x00000000 | 组件参数寄存器           |
| UART_UCV       | 0x00f8   | W    | 0x0330372a | 组件版本寄存器           |
| UART_CTR       | 0x00fc   | W    | 0x44570110 | 组件类型寄存器           |

根据你提供的《RKNanoD TRM》文档内容，我已提取所有明确标注的**寄存器地址（偏移量）**，按章节与模块分类整理如下：

---

### ✅ 一、UART 相关寄存器
| 寄存器名称 | 偏移地址 | 说明 |
|------------|----------|------|
| UART_CPR | 0x00F4 | Component Parameter Register |
| UART_UCV | 0x00F8 | UART Component Version |
| UART_CTR | 0x00FC | Component Type Register |

---

### ✅ 二、EBC（电子墨水屏控制器）寄存器
| 寄存器名称 | 偏移地址 | 说明 |
|------------|----------|------|
| EBC_DSP_ST | 0x0000 | 帧启动寄存器 |
| EBC_EPD_CTRL | 0x0004 | EPD 控制寄存器 |
| EBC_DSP_CTRL | 0x0008 | 显示控制寄存器 |
| EBC_DSP_HTIMING0 | 0x000C | 水平时序设置0 |
| EBC_DSP_HTIMING1 | 0x0010 | 水平时序设置1 |
| EBC_DSP_VTIMING0 | 0x0014 | 垂直时序设置0 |
| EBC_DSP_VTIMING1 | 0x0018 | 垂直时序设置1 |
| EBC_DSP_ACT_INFO | 0x001C | 显示有效宽度/高度 |
| EBC_WIN_CTRL | 0x0020 | 窗口控制寄存器 |
| EBC_WIN_MST0 | 0x0024 | 旧窗口层内存起始地址 |
| EBC_WIN_MST1 | 0x0028 | 新窗口层内存起始地址 |
| EBC_WIN_VIR | 0x002C | 窗口虚拟宽度 |
| EBC_WIN_ACT | 0x0030 | 窗口有效宽度/高度 |
| EBC_WIN_DSP | 0x0034 | 窗口显示宽度/高度 |
| EBC_WIN_DSP_ST | 0x0038 | 窗口显示起始位置 |
| EBC_INT_CTRL | 0x003C | 中断控制寄存器 |
| EBC_VCOM0 | 0x0040 | VCOM0 |
| EBC_VCOM1 | 0x0044 | VCOM1 |
| EBC_VCOM2 | 0x0048 | VCOM2 |
| EBC_VCOM3 | 0x004C | VCOM3 |
| EBC_CONFIG_DONE | 0x0050 | 配置完成寄存器 |
| EBC_LUT_ADDR_MAP | 0x1000 | LUT 地址映射寄存器 |

---

### ✅ 三、SFC（串行闪存控制器）寄存器
| 寄存器名称 | 偏移地址 | 说明 |
|------------|----------|------|
| SFC_CTRL | 0x0000 | 控制寄存器 |
| SFC_IMR | 0x0004 | 中断屏蔽寄存器 |
| SFC_ICLR | 0x0008 | 中断清除寄存器 |
| SFC_FTLR | 0x000C | FIFO 阈值寄存器 |
| SFC_RCVR | 0x0010 | SFC 恢复寄存器 |
| SFC_AX | 0x0014 | SFC AX 值寄存器 |
| SFC_ABIT | 0x0018 | 闪存地址位宽设置 |
| SFC_ISR | 0x001C | 中断状态寄存器 |
| SFC_FSR | 0x0020 | FIFO 状态寄存器 |
| SFC_SR | 0x0024 | SFC 状态寄存器 |
| SFC_DMATR | 0x0080 | DMA 触发寄存器 |
| SFC_DMAADDR | 0x0084 | DMA 地址寄存器 |
| SFC_CMD | 0x0100 | SFC 命令寄存器 |
| SFC_ADDR | 0x0104 | SFC 地址寄存器 |
| SFC_DATA | 0x0108 | SFC 数据寄存器 |

---

### ✅ 四、HIFIACC、SYNTH、IMDCT36 模块
文档中未明确列出这些模块的寄存器偏移地址，仅说明其功能与内存映射范围。如需进一步提取，建议提供更完整的寄存器描述章节。

---

### 📌 说明：
- 所有偏移地址为十六进制，需与模块的 **Operational Base Address** 相加得到实际物理地址。
- 例如 EBC 的基地址为 `0x60040000`，则 `EBC_DSP_ST` 的实际地址为 `0x60040000 + 0x0000 = 0x60040000`。
