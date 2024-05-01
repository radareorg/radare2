# -------------------------------------------------------------------
# GPIOR bit definitions
# -------------------------------------------------------------------
# FLASH_CR1 bits
f ioreg.FLASH_CR1_IE_bp=1
f ioreg.FLASH_CR1_FIX_bp=0

# FLASH_CR2 bits
f ioreg.FLASH_CR2_OPT_bp=7
f ioreg.FLASH_CR2_WPRG_bp=6
f ioreg.FLASH_CR2_ERASE_bp=5
f ioreg.FLASH_CR2_FPRG_bp=4
f ioreg.FLASH_CR2_PRG_bp=0

# FLASH_IAPSR bits
f ioreg.FLASH_IAPSR_DUL_bp=3
f ioreg.FLASH_IAPSR_EOP_bp=2
f ioreg.FLASH_IAPSR_PUL_bp=1
f ioreg.FLASH_IAPSR_WR_PG_DIS_bp=0

# CLK_CKDIVR bits
f ioreg.CLK_CKDIVR_CKM0_bp=0
f ioreg.CLK_CKDIVR_CKM1_bp=1
f ioreg.CLK_CKDIVR_CKM2_bp=2

f ioreg.CLK_CKDIVR_CKM_DIV1_gc=0x00
f ioreg.CLK_CKDIVR_CKM_DIV2_gc=0x01
f ioreg.CLK_CKDIVR_CKM_DIV4_gc=0x02
f ioreg.CLK_CKDIVR_CKM_DIV8_gc=0x03
f ioreg.CLK_CKDIVR_CKM_DIV16_gc=0x04
f ioreg.CLK_CKDIVR_CKM_DIV32_gc=0x05
f ioreg.CLK_CKDIVR_CKM_DIV64_gc=0x06
f ioreg.CLK_CKDIVR_CKM_DIV128_gc=0x07

# CLK_PCKENR1 bits
f ioreg.CLK_PCKENR1_TIM2_bp=0
f ioreg.CLK_PCKENR1_TIM3_bp=1
f ioreg.CLK_PCKENR1_TIM4_bp=2
f ioreg.CLK_PCKENR1_I2C1_bp=3
f ioreg.CLK_PCKENR1_SPI1_bp=4
f ioreg.CLK_PCKENR1_USART1_bp=5
f ioreg.CLK_PCKENR1_BEEP_bp=6
f ioreg.CLK_PCKENR1_DAC_bp=7

#CLK_PCKENR2 bits
f ioreg.CLK_PCKENR2_ADC1_bp=0
f ioreg.CLK_PCKENR2_TIM1_bp=1
f ioreg.CLK_PCKENR2_RTC_bp=2
f ioreg.CLK_PCKENR2_LCD_bp=3
f ioreg.CLK_PCKENR2_DMA1_bp=4
f ioreg.CLK_PCKENR2_COMP_bp=5
f ioreg.CLK_PCKENR2_BOOTROM_bp=7

# CLK_PCKENR3 bits
f ioreg.CLK_PCKENR3_AES_bp=0
f ioreg.CLK_PCKENR3_TIM5_bp=1
f ioreg.CLK_PCKENR3_SPI2_bp=2
f ioreg.CLK_PCKENR3_USART2_bp=3
f ioreg.CLK_PCKENR3_USART3_bp=4
f ioreg.CLK_PCKENR3_CSS_LSE_bp=5

# SPI_CR1 bits
f ioreg.SPI_CR1_LSBFIRST_bp=7
f ioreg.SPI_CR1_SPE_bp=6
f ioreg.SPI_CR1_BR2_bp=5
f ioreg.SPI_CR1_BR1_bp=4
f ioreg.SPI_CR1_BR0_bp=3
f ioreg.SPI_CR1_MSTR_bp=2
f ioreg.SPI_CR1_CPOL_bp=1
f ioreg.SPI_CR1_CPHA_bp=0

# SPI_CR2 bits
f ioreg.SPI_CR2_BDM_bp=7
f ioreg.SPI_CR2_BDOE_bp=6
f ioreg.SPI_CR2_RXONLY_bp=2
f ioreg.SPI_CR2_SSM_bp=1
f ioreg.SPI_CR2_SSI_bp=0

# SPI_ICR bits
f ioreg.SPI_ICR_TXIE_bp=7
f ioreg.SPI_ICR_RXIE_bp=6
f ioreg.SPI_ICR_ERRIE_bp=5
f ioreg.SPI_ICR_WKIE_bp=4

# SPI_SR bits
f ioreg.SPI_SR_BSY_bp=7
f ioreg.SPI_SR_OVR_bp=6
f ioreg.SPI_SR_MODF_bp=5
f ioreg.SPI_SR_WKUP_bp=3
f ioreg.SPI_SR_TXE_bp=1
f ioreg.SPI_SR_RXNE_bp=0

# USART_CR1 bits
f ioreg.USART_CR1_R8_bp=7
f ioreg.USART_CR1_T8_bp=6
f ioreg.USART_CR1_UARTD_bp=5
f ioreg.USART_CR1_M_bp=4
f ioreg.USART_CR1_WAKE_bp=3
f ioreg.USART_CR1_PCEN_bp=2
f ioreg.USART_CR1_PS_bp=1
f ioreg.USART_CR1_PIEN_bp=0

# USART_CR2 bits
f ioreg.USART_CR2_TIEN_bp=7
f ioreg.USART_CR2_TCIEN_bp=6
f ioreg.USART_CR2_RIEN_bp=5
f ioreg.USART_CR2_ILIEN_bp=4
f ioreg.USART_CR2_TEN_bp=3
f ioreg.USART_CR2_REN_bp=2
f ioreg.USART_CR2_RWU_bp=1
f ioreg.USART_CR2_SBK_bp=0

# USART_CR3 bits
f ioreg.USART_CR3_LINEN_bp=6
f ioreg.USART_CR3_STOP2_bp=5
f ioreg.USART_CR3_STOP1_bp=4
f ioreg.USART_CR3_CLKEN_bp=3
f ioreg.USART_CR3_CPOL_bp=2
f ioreg.USART_CR3_CPHA_bp=1
f ioreg.USART_CR3_LBCL_bp=0

# USART_SR bits
f ioreg.USART_SR_TXE_bp=7
f ioreg.USART_SR_TC_bp=6
f ioreg.USART_SR_RXNE_bp=5
f ioreg.USART_SR_IDLE_bp=4
f ioreg.USART_SR_OR_bp=3
f ioreg.USART_SR_NF_bp=2
f ioreg.USART_SR_FE_bp=1
f ioreg.USART_SR_PE_bp=0

# TIM_IER bits
f ioreg.TIM_IER_BIE_bp=7
f ioreg.TIM_IER_TIE_bp=6
f ioreg.TIM_IER_COMIE_bp=5
f ioreg.TIM_IER_CC4IE_bp=4
f ioreg.TIM_IER_CC3IE_bp=3
f ioreg.TIM_IER_CC2IE_bp=2
f ioreg.TIM_IER_CC1IE_bp=1
f ioreg.TIM_IER_UIE_bp=0

# TIM_CR1 bits
f ioreg.TIM_CR1_APRE_bp=7
f ioreg.TIM_CR1_CMSH_bp=6
f ioreg.TIM_CR1_CMSL_bp=5
f ioreg.TIM_CR1_DIR_bp=4
f ioreg.TIM_CR1_OPM_bp=3
f ioreg.TIM_CR1_URS_bp=2
f ioreg.TIM_CR1_UDIS_bp=1
f ioreg.TIM_CR1_CEN_bp=0

# TIM_SR1 bits
f ioreg.TIM_SR1_BIF_bp=7
f ioreg.TIM_SR1_TIF_bp=6
f ioreg.TIM_SR1_COMIF_bp=5
f ioreg.TIM_SR1_CC4IF_bp=4
f ioreg.TIM_SR1_CC3IF_bp=3
f ioreg.TIM_SR1_CC2IF_bp=2
f ioreg.TIM_SR1_CC1IF_bp=1
f ioreg.TIM_SR1_UIF_bp=0

# TIM_EGR bits
f ioreg.TIM_EGR_BG_bp=7
f ioreg.TIM_EGR_TG_bp=6
f ioreg.TIM_EGR_CC2G_bp=2
f ioreg.TIM_EGR_CC1G_bp=1
f ioreg.TIM_EGR_UG_bp=0

# CFG_GCR
f ioreg.CFG_GCR_SWD_bp=0
f ioreg.CFG_GCR_AL_bp=1

# CLK_CBEEPR
f ioreg.CLK_CBEEPR_SWBSY_bp=0
f ioreg.CLK_CBEEPR_SEL0_bp=1
f ioreg.CLK_CBEEPR_SEL1_bp=2

f ioreg.CLK_CBEEPR_NO_CLOCK_gc=0x00
f ioreg.CLK_CBEEPR_LSI_gc=0x02
f ioreg.CLK_CBEEPR_LSE_gc=0x04

# TIM4_CR1
f ioreg.TIM4_CR1_CEN_bp=0
f ioreg.TIM4_CR1_UDIS_bp=1
f ioreg.TIM4_CR1_URS_bp=2
f ioreg.TIM4_CR1_OPM_bp=3
f ioreg.TIM4_CR1_ARPE_bp=7

# TIM4_SR
f ioreg.TIM4_SR_UIF_bp=0
f ioreg.TIM4_SR_TIF_bp=6

# TIM4_IER
f ioreg.TIM4_IER_UIE_bp=0
f ioreg.TIM4_IER_TIE_bp=6

# BEEP_CSR2
f ioreg.BEEP_CSR2_BEEPDIV0=0
f ioreg.BEEP_CSR2_BEEPDIV1=1
f ioreg.BEEP_CSR2_BEEPDIV2=2
f ioreg.BEEP_CSR2_BEEPDIV3=3
f ioreg.BEEP_CSR2_BEEPDIV4=4
f ioreg.BEEP_CSR2_BEEPEN_bp=5
f ioreg.BEEP_CSR2_BEEPSEL0_bp=6
f ioreg.BEEP_CSR2_BEEPSEL1_bp=7

# I2C1_CR1
f ioreg.I2C_CR1_PE_bp=0
f ioreg.I2C_CR1_SMBUS_bp=1
f ioreg.I2C_CR1_SMBTYPE_bp=3
f ioreg.I2C_CR1_ENARP_bp=4
f ioreg.I2C_CR1_ENPEC_bp=5
f ioreg.I2C_CR1_ENGC_bp=6
f ioreg.I2C_CR1_NOSTRETCH_bp=7

# I2C1_CR2
f ioreg.I2C_CR2_START_bp=0
f ioreg.I2C_CR2_STOP_bp=1
f ioreg.I2C_CR2_ACK_bp=2
f ioreg.I2C_CR2_POS_bp=3
f ioreg.I2C_CR2_PEC_bp=4
f ioreg.I2C_CR2_ALERT_bp=5
f ioreg.I2C_CR2_SWRST_bp=7

# I2C_ITR
f ioreg.I2C_ITR_ITERREN_bp=0
f ioreg.I2C_ITR_ITEVTEN_bp=1
f ioreg.I2C_ITR_ITBUFEN_bp=2
f ioreg.I2C_ITR_DMAEN_bp=3
f ioreg.I2C_ITR_LAST_bp=4

# I2C_SR1
f ioreg.I2C_SR1_SB_bp=0
f ioreg.I2C_SR1_ADDR_bp=1
f ioreg.I2C_SR1_BTF_bp=2
f ioreg.I2C_SR1_ADD10_bp=3
f ioreg.I2C_SR1_STOPF_bp=4
f ioreg.I2C_SR1_RXNE_bp=6
f ioreg.I2C_SR1_TXE_bp=7

# I2C_SR2
f ioreg.I2C_SR2_BERR_bp=0
f ioreg.I2C_SR2_ARLO_bp=1
f ioreg.I2C_SR2_AF_bp=2
f ioreg.I2C_SR2_OVR_bp=3
f ioreg.I2C_SR2_PECERR_bp=4
f ioreg.I2C_SR2_WURF_bp=5
f ioreg.I2C_SR2_TIMEOUT_bp=6
f ioreg.I2C_SR2_SMBALERT_bp=7

# I2C_SR3
f ioreg.I2C_SR3_MSL_bp=0
f ioreg.I2C_SR3_BUSY_bp=1
f ioreg.I2C_SR3_TRA_bp=2
f ioreg.I2C_SR3_GENCALL_bp=4
f ioreg.I2C_SR3_SMBDEFAULT_bp=5
f ioreg.I2C_SR3_SMBHOST_bp=6
f ioreg.I2C_SR3_DUALF_bp=7

# DMA_GCSR
f ioreg.DMA_GCSR_GEN_bp=0
f ioreg.DMA_GCSR_GP_bp=1
f ioreg.DMA_GCSR_TO_bp=2

# DMA_GIR1
f ioreg.DMA_GIR1_IFC0_bp=0
f ioreg.DMA_GIR1_IFC1_bp=1
f ioreg.DMA_GIR1_IFC2_bp=2
f ioreg.DMA_GIR1_IFC3_bp=3

# DMA_CCR
f ioreg.DMA_CCR_EN_bp=0
f ioreg.DMA_CCR_TCIE_bp=1
f ioreg.DMA_CCR_HTIE_bp=2
f ioreg.DMA_CCR_DIR_bp=3
f ioreg.DMA_CCR_CIRC_bp=4
f ioreg.DMA_CCR_MINCDEC_bp=5
f ioreg.DMA_CCR_MEM_bp=6

# DMA_CxSPR
f ioreg.DMA_CSPR_TCIF_bp=1
f ioreg.DMA_CSPR_HTIF_bp=2
f ioreg.DMA_CSPR_TSIZE_bp=3
f ioreg.DMA_CSPR_PL0_bp=4
f ioreg.DMA_CSPR_PL1_bp=5
f ioreg.DMA_CSPR_PEND_bp=6
f ioreg.DMA_CSPR_BUSY_bp=7


# ADC_CR1
f ioreg.ADC_CR1_ADON_bp=0
f ioreg.ADC_CR1_START_bp=1
f ioreg.ADC_CR1_CONT_bp=2
f ioreg.ADC_CR1_EOCIE_bp=3
f ioreg.ADC_CR1_AWDIE_bp=4
f ioreg.ADC_CR1_RES0_bp=5
f ioreg.ADC_CR1_RES1_bp=6
f ioreg.ADC_CR1_OVERIE_bp=7
f ioreg.ADC_CR1_ADON_START_CONT_gc=0x07

# ADC_CR2
f ioreg.ADC_CR2_SMTP0_bp=0
f ioreg.ADC_CR2_SMTP1_bp=1
f ioreg.ADC_CR2_SMTP2_bp=2
f ioreg.ADC_CR2_EXTSEL0_bp=3
f ioreg.ADC_CR2_EXTSEL1_bp=4
f ioreg.ADC_CR2_TRIG_EDGE0_bp=5
f ioreg.ADC_CR2_TRIG_EDGE1_bp=6
f ioreg.ADC_CR2_PRESC_bp=7

# ADC_SQR1
f ioreg.ADC_SQR1_CHSEL_SVREFINT_bp=4
f ioreg.ADC_SQR1_CHSEL_STS_bp=5
f ioreg.ADC_SQR1_DMAOFF_bp=7

# ADC_TRIG1
f ioreg.ADC_TRIG1_VREFINTON_bp=4

# TIM_CCMR1/2
# output
f ioreg.TIM_CCMR_CCS0_bp=0
f ioreg.TIM_CCMR_CCS1_bp=1
f ioreg.TIM_CCMR_OCFE_bp=2
f ioreg.TIM_CCMR_OCPE_bp=3
f ioreg.TIM_CCMR_OCM0_bp=4
f ioreg.TIM_CCMR_OCM1_bp=5
f ioreg.TIM_CCMR_OCM2_bp=6
f ioreg.TIM_CCMR_OCM_SET_gc=0x10
f ioreg.TIM_CCMR_OCM_RES_gc=0x20
f ioreg.TIM_CCMR_OCM_TGL_gc=0x30
f ioreg.TIM_CCMR_OCM_LOW_gc=0x40
f ioreg.TIM_CCMR_OCM_HIGH_gc=0x50
f ioreg.TIM_CCMR_OCM_PWM1_gc=0x60
f ioreg.TIM_CCMR_OCM_PWM2_gc=0x70

# input
f ioreg.TIM_CCMR_ICPSC_bp=2
f ioreg.TIM_CCMR_ICPSC_bp=3
f ioreg.TIM_CCMR_ICF0_bp=4
f ioreg.TIM_CCMR_ICF1_bp=5
f ioreg.TIM_CCMR_ICF2_bp=6
f ioreg.TIM_CCMR_ICF3_bp=7

# TIM_CCER1
f ioreg.TIM_CCER1_CC1E_bp=0
f ioreg.TIM_CCER1_CC1P_bp=1
f ioreg.TIM_CCER1_CC2E_bp=4
f ioreg.TIM_CCER1_CC2P_bp=5

# TIM_BKR
f ioreg.TIM_BKR_LOCK0_bp=0
f ioreg.TIM_BKR_LOCK1_bp=1
f ioreg.TIM_BKR_OSSI_bp=2
f ioreg.TIM_BKR_BKE_bp=4
f ioreg.TIM_BKR_BKP_bp=5
f ioreg.TIM_BKR_AOE_bp=6
f ioreg.TIM_BKR_MOE_bp=7

# ADC_SR
f ioreg.ADC_SR_EOC_bp=0
f ioreg.ADC_SR_AWD_bp=1
f ioreg.ADC_SR_OVER_bp=2

# CLK_SWCR
f ioreg.CLK_SWCR_SWBSY_bp=0
f ioreg.CLK_SWCR_SWEN_bp=1
f ioreg.CLK_SWCR_SWIEN_bp=2
f ioreg.CLK_SWCR_SWIF_bp=3

# CLK_SWR
f ioreg.CLK_SWR_HSI_gc=0x01
f ioreg.CLK_SWR_LSI_gc=0x02
f ioreg.CLK_SWR_HSE_gc=0x04
f ioreg.CLK_SWR_LSE_gc=0x08

# CLK_ICKCR
f ioreg.CLK_ICKCR_HSION_bp=0
f ioreg.CLK_ICKCR_HSIRDY_bp=1
f ioreg.CLK_ICKCR_LSION_bp=2
f ioreg.CLK_ICKCR_LSIRDY_bp=3
f ioreg.CLK_ICKCR_SAHALT_bp=4
f ioreg.CLK_ICKCR_FHWU_bp=5
f ioreg.CLK_ICKCR_BEEPAHALT_bp=6

# CLK_CRTCR
f ioreg.CLK_CRTCR_DIV_1_gc=0x00
f ioreg.CLK_CRTCR_DIV_2_gc=0x20
f ioreg.CLK_CRTCR_DIV_4_gc=0x40
f ioreg.CLK_CRTCR_DIV_8_gc=0x60
f ioreg.CLK_CRTCR_DIV_16_gc=0x80
f ioreg.CLK_CRTCR_DIV_32_gc=0xA0
f ioreg.CLK_CRTCR_DIV_64_gc=0xC0
f ioreg.CLK_CRTCR_DIV_128_gc=0xE0

f ioreg.CLK_CRTCR_SEL_NONE_gc=0x00
f ioreg.CLK_CRTCR_SEL_HSI_gc=0x02
f ioreg.CLK_CRTCR_SEL_LSI_gc=0x04
f ioreg.CLK_CRTCR_SEL_HSE_gc=0x08
f ioreg.CLK_CRTCR_SEL_LSE_gc=0x10

f ioreg.CLK_CRTCR_SWBSY_bp=0

# RTC_CR1
f ioreg.RTC_CR1_WUCKSEL_DIV16_gc=0x00
f ioreg.RTC_CR1_WUCKSEL_DIV8_gc=0x01
f ioreg.RTC_CR1_WUCKSEL_DIV4_gc=0x02
f ioreg.RTC_CR1_WUCKSEL_DIV2_gc=0x03
f ioreg.RTC_CR1_WUCKSEL_CK_SPRE_gc=0x04
f ioreg.RTC_CR1_WUCKSEL_2CK_SPRE_gc=0x06

# RTC_CR2
f ioreg.RTC_CR2_ALRAE_bp=0
f ioreg.RTC_CR2_WUTE_bp=2
f ioreg.RTC_CR2_ALRAIE_bp=4
f ioreg.RTC_CR2_WUTIE_bp=6

# RTC_ISR2
f ioreg.RTC_ISR2_ALRAF_bp=0
f ioreg.RTC_ISR2_WUTF_bp=2
f ioreg.RTC_ISR2_TAMP1F_bp=5
f ioreg.RTC_ISR2_TAMP2F_bp=6
f ioreg.RTC_ISR2_TAMP3F_bp=7

# RTC_ISR1
f ioreg.RTC_ISR1_ALRAWF_bp=0
f ioreg.RTC_ISR1_RECALPF_bp=1
f ioreg.RTC_ISR1_WUTWF_bp=2
f ioreg.RTC_ISR1_SHPF_bp=3
f ioreg.RTC_ISR1_INITS_bp=4
f ioreg.RTC_ISR1_RSF_bp=5
f ioreg.RTC_ISR1_INITF_bp=6
f ioreg.RTC_ISR1_INIT_bp=7

# CLK_ECKCR
f ioreg.CLK_ECKCR_HSEON_bp=0
f ioreg.CLK_ECKCR_HSERDY_bp=1
f ioreg.CLK_ECKCR_LSEON_bp=2
f ioreg.CLK_ECKCR_LSERDY_bp=3
f ioreg.CLK_ECKCR_HSEBYP_bp=4
f ioreg.CLK_ECKCR_LSEBYP_bp=5

# RST_SR
f ioreg.RST_SR_PORF_bp=0
f ioreg.RST_SR_IWDGF_bp=1
f ioreg.RST_SR_ILLOPF_bp=2
f ioreg.RST_SR_SWIMF_bp=3
f ioreg.RST_SR_WWDGF_bp=4
f ioreg.RST_SR_BORF_bp=5

# PWR_CSR1
f ioreg.PWR_CSR1_PVDE_bp=0
f ioreg.PWR_CSR1_PLS_0=1
f ioreg.PWR_CSR1_PLS_0=2
f ioreg.PWR_CSR1_PLS_0=3
f ioreg.PWR_CSR1_PVDIEN_bp=4
f ioreg.PWR_CSR1_PVDIF_bp=5
f ioreg.PWR_CSR1_PVDOF_bp=6

f ioreg.PWR_CSR1_PLS_1V85_gc=0x00
f ioreg.PWR_CSR1_PLS_2V05_gc=0x02
f ioreg.PWR_CSR1_PLS_2V26_gc=0x04
f ioreg.PWR_CSR1_PLS_2V45_gc=0x06
f ioreg.PWR_CSR1_PLS_2V65_gc=0x08
f ioreg.PWR_CSR1_PLS_2V85_gc=0x0A
f ioreg.PWR_CSR1_PLS_3V05_gc=0x0C
f ioreg.PWR_CSR1_PLS_IN_gc=0x0E

f ioreg.PWR_CSR1_PLS_gm=0x0E

# TIM_DER
f ioreg.TIM_DER_UDE_bp=0
f ioreg.TIM_DER_CC1DE_bp=1
f ioreg.TIM_DER_CC2DE_bp=2
f ioreg.TIM_DER_CC3DE_bp=3
f ioreg.TIM_DER_CC4DE_bp=4
f ioreg.TIM_DER_COMDE_bp=5

# -------------------------------------------------------------------------------
# Fin
