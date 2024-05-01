; Port A
.equ PA_ODR,		0x5000
.equ PA_IDR,		0x5001
.equ PA_DDR,		0x5002
.equ PA_CR1, 		0x5003
.equ PA_CR2, 		0x5004

; Port B
.equ PB_ODR, 		0x5005
.equ PB_IDR, 		0x5006
.equ PB_DDR, 		0x5007
.equ PB_CR1, 		0x5008
.equ PB_CR2, 		0x5009

; Port C
.equ PC_ODR, 		0x500A
.equ PC_IDR, 		0x500B
.equ PC_DDR, 		0x500C
.equ PC_CR1, 		0x500D
.equ PC_CR2, 		0x500E

; Port D
.equ PD_ODR, 		0x500F
.equ PD_IDR, 		0x5010
.equ PD_DDR, 		0x5011
.equ PD_CR1, 		0x5012
.equ PD_CR2, 		0x5013

; Port E
.equ PE_ODR, 		0x5014
.equ PE_IDR, 		0x5015
.equ PE_DDR, 		0x5016
.equ PE_CR1, 		0x5017
.equ PE_CR2, 		0x5018

; Port F
.equ PF_ODR, 		0x5019
.equ PF_IDR, 		0x501A
.equ PF_DDR, 		0x501B
.equ PF_CR1, 		0x501C
.equ PF_CR2, 		0x501D

; Flash
.equ FLASH_CR1,		0x5050
.equ FLASH_CR2,		0x5051
.equ FLASH_PUKR,	0x5052
.equ FLASH_DUKR,	0x5053
.equ FLASH_IAPSR,	0x5054

; DMA1
.equ DMA1_GCSR,		0x5070
.equ DMA1_GIR1,		0x5071
.equ DMA1_C0CR,		0x5075
.equ DMA1_C0SPR,	0x5076
.equ DMA1_C0NDTR,	0x5077
.equ DMA1_C0PARH,	0x5078
.equ DMA1_C0PARL,	0x5079
.equ DMA1_C0M0ARH,	0x507B
.equ DMA1_C0M0ARL,	0x507C
.equ DMA1_C1CR,		0x507F
.equ DMA1_C1SPR,	0x5080
.equ DMA1_C1NDTR,	0x5081
.equ DMA1_C1PARH,	0x5082
.equ DMA1_C1PARL,	0x5083
.equ DMA1_C1M0ARH,	0x5085
.equ DMA1_C1M0ARL,	0x5086
.equ DMA1_C2CR,		0x5089
.equ DMA1_C2SPR,	0x508A
.equ DMA1_C2NDTR,	0x508B
.equ DMA1_C2PARH,	0x508C
.equ DMA1_C2PARL,	0x508D
.equ DMA1_C2M0ARH,	0x508F
.equ DMA1_C2M0ARL,	0x5090
.equ DMA1_C3CR,		0x5093
.equ DMA1_C3SPR,	0x5094
.equ DMA1_C3NDTR,	0x5095
.equ DMA1_C3PARH_C3M1ARH,	0x5096
.equ DMA1_C3PARL_C3M1ARL,	0x5097
.equ DMA_C3M0EAR,	0x5098
.equ DMA1_C3M0ARH,	0x5099
.equ DMA1_C3M0ARL,	0x509A

; SYS_CFG
.equ SYSCFG_RMPCR3,	0x509D
.equ SYSCFG_RMPCR1,	0x509E
.equ SYSCFG_RMPCR2,	0x509F

; ITC_EXTI
.equ EXTI_CR1,		0x50A0
.equ EXTI_CR2,		0x50A1
.equ EXTI_CR3,		0x50A2
.equ EXTI_SR1,		0x50A3
.equ EXTI_SR2,		0x50A4
.equ EXTI_CONF1,	0x50A5

; WFE
.equ WFE_CR1,		0x50A6
.equ WFE_CR2,		0x50A7
.equ WFE_CR3,		0x50A8
.equ WFE_CR4,		0x50A9

; ITC_EXTI
.equ EXTI_CR4,		0x50AA
.equ EXTI_CONF2,	0x50AB

; RST
.equ RST_CR,		0x50B0
.equ RST_SR,		0x50B1

; PWR
.equ PWR_CSR1,		0x50B2
.equ PWR_CSR2,		0x50B3

; CLK 
.equ CLK_CKDIVR,	0x50C0
.equ CLK_CRTCR,		0x50C1
.equ CLK_ICKCR,		0x50C2
.equ CLK_PCKENR1,	0x50C3
.equ CLK_PCKENR2,	0x50C4
.equ CLK_CCOR,		0x50C5
.equ CLK_ECKCR,		0x50C6
.equ CLK_SCSR,		0x50C7
.equ CLK_SWR,		0x50C8
.equ CLK_SWCR,		0x50C9
.equ CLK_CSSR,		0x50CA
.equ CLK_CBEEPR,	0x50CB
.equ CLK_HSICALR,	0x50CC
.equ CLK_HSITRIMR,	0x50CD
.equ CLK_HSIUNLCKR,	0x50CE
.equ CLK_REGCSR,	0x50CF
.equ CLK_PCKENR3,	0x50D0

; WWDG
.equ WWDG_CR,		0x50D3
.equ WWDG_WR,		0x50D4

; IWDG
.equ IWDG_KR,		0x50E0
.equ IWDG_PR,		0x50E1
.equ IWDG_RLR,		0x50E2

; BEEP
.equ BEEP_CSR1,		0x50F0
.equ BEEP_CSR2,		0x50F3

; RTC
.equ RTC_TR1,		0x5140
.equ RTC_TR2,		0x5141
.equ RTC_TR3,		0x5142
.equ RTC_DR1,		0x5144
.equ RTC_DR2,		0x5145
.equ RTC_DR3,		0x5146
.equ RTC_CR1,		0x5148
.equ RTC_CR2,		0x5149
.equ RTC_CR3,		0x514A
.equ RTC_ISR1,		0x514C
.equ RTC_ISR2,		0x514D
.equ RTC_SPRERH,	0x5150
.equ RTC_SPRERL,	0x5151
.equ RTC_APRER,		0x5152
.equ RTC_WUTRH,		0x5154
.equ RTC_WUTRL,		0x5155

.equ RTC_SSRH,		0x5157
.equ RTC_SSRL,		0x5158
.equ RTC_WPR,		0x5159
.equ RTC_SHIFTRH,	0x515A
.equ RTC_SHIFTRL,	0x515B
.equ RTC_ALRMAR1,	0x515C
.equ RTC_ALRMAR2,	0x515D
.equ RTC_ALRMAR3,	0x515E
.equ RTC_ALRMAR4,	0x515F
.equ RTC_ALRMASSRH,	0x5164
.equ RTC_ALRMASSRL,	0x5165
.equ RTC_ALRMASSMSKR,	0x5166
.equ RTC_CALRH,		0x516A
.equ RTC_CALRL,		0x516B
.equ RTC_TCR1,		0x516C
.equ RTC_TCR2,		0x516D

; CSS
.equ CSSLSE_CSR,	0x5190

; SPI1
.equ SPI1_CR1,		0x5200
.equ SPI1_CR2,		0x5201
.equ SPI1_ICR,		0x5202
.equ SPI1_SR,		0x5203
.equ SPI1_DR,		0x5204
.equ SPI1_CRCPR,	0x5205
.equ SPI1_RXCRCR,	0x5206
.equ SPI1_TXCRCR,	0x5207

; I2C
.equ I2C1_CR1,		0x5210
.equ I2C1_CR2,		0x5211
.equ I2C1_FREQR,	0x5212
.equ I2C1_OARL,		0x5213
.equ I2C1_OARH,		0x5214
.equ I2C1_OAR2,		0X5215
.equ I2C1_DR,		0x5216
.equ I2C1_SR1,		0x5217
.equ I2C1_SR2,		0x5218
.equ I2C1_SR3,		0x5219
.equ I2C1_ITR,		0x521A
.equ I2C1_CCRL,		0x521B
.equ I2C1_CCRH,		0x521C
.equ I2C1_TRISER,	0x521D
.equ I2C1_PECR,		0x521E

; USART
.equ USART1_SR, 	0x5230
.equ USART1_DR, 	0x5231
.equ USART1_BRR1, 	0x5232
.equ USART1_BRR2, 	0x5233
.equ USART1_CR1, 	0x5234
.equ USART1_CR2, 	0x5235
.equ USART1_CR3, 	0x5236
.equ USART1_CR4, 	0x5237
.equ USART1_CR5, 	0x5238
.equ USART1_GTR, 	0x5239
.equ USART1_PSCR, 	0x523A

; TIM2
.equ TIM2_CR1, 		0x5250
.equ TIM2_CR2, 		0x5251
.equ TIM2_SMCR,		0x5252
.equ TIM2_ETR, 		0x5253
.equ TIM2_DER,		0x5254
.equ TIM2_IER, 		0x5255
.equ TIM2_SR1, 		0x5256
.equ TIM2_SR2, 		0x5257
.equ TIM2_EGR, 		0x5258
.equ TIM2_CCMR1,	0x5259
.equ TIM2_CCMR2,	0x525A
.equ TIM2_CCER1,	0x525B
.equ TIM2_CNTRH,	0x525C
.equ TIM2_CNTRL,	0x525D
.equ TIM2_PSCR,		0x525E
.equ TIM2_ARRH, 	0x525F
.equ TIM2_ARRL, 	0x5260
.equ TIM2_CCR1H,	0x5261
.equ TIM2_CCR1L,	0x5262
.equ TIM2_CCR2H,	0x5263
.equ TIM2_CCR2L,	0x5264
.equ TIM2_BKR, 		0x5265
.equ TIM2_OISR, 	0x5266

; TIM3
.equ TIM3_CR1, 		0x5280
.equ TIM3_CR2, 		0x5281
.equ TIM3_SMCR,		0x5282
.equ TIM3_ETR, 		0x5283
.equ TIM3_DER,		0x5284
.equ TIM3_IER, 		0x5285
.equ TIM3_SR1, 		0x5286
.equ TIM3_SR2, 		0x5287
.equ TIM3_EGR, 		0x5288
.equ TIM3_CCMR1,	0x5289
.equ TIM3_CCMR2,	0x528A
.equ TIM3_CCER1,	0x528B
.equ TIM3_CNTRH,	0x528C
.equ TIM3_CNTRL,	0x528D
.equ TIM3_PSCR,		0x528E
.equ TIM3_ARRH,		0x528F
.equ TIM3_ARRL,		0x5290
.equ TIM3_CCR1H,	0x5291
.equ TIM3_CCR1L,	0x5292
.equ TIM3_CCR2H, 	0x5293
.equ TIM3_CCR2L, 	0x5294
.equ TIM3_BKR, 		0x5295
.equ TIM3_OISR,		0x5296

; TIM4
.equ TIM4_CR1, 		0x52E0
.equ TIM4_CR2, 		0x52E1
.equ TIM4_SMCR,		0x52E2
.equ TIM4_DER,		0x52E3
.equ TIM4_IER, 		0x52E4
.equ TIM4_SR, 		0x52E5
.equ TIM4_EGR, 		0x52E6
.equ TIM4_CNTR,		0x52E7
.equ TIM4_PSCR,		0x52E8
.equ TIM4_ARR, 		0x52E9

; IRTIM
.equ IR_CR,		0x52FF

; COMP
.equ COMP_CR,		0x5300
.equ COMP_CSR,		0x5301
.equ COMP_CCS,		0x5302

; ADC1
.equ ADC1_CR1,		0x5340
.equ ADC1_CR2,		0x5341
.equ ADC1_CR3,		0x5342
.equ ADC1_SR,		0x5343
.equ ADC1_DRH,		0x5344
.equ ADC1_DRL,		0x5345
.equ ADC1_HTRH,		0x5346
.equ ADC1_HTRL,		0x5347
.equ ADC1_LTRH,		0x5348
.equ ADC1_LTRL,		0x5349
.equ ADC1_SQR1,		0x534A
.equ ADC1_SQR2,		0x534B
.equ ADC1_SQR3,		0x534C
.equ ADC1_SQR4,		0x534D
.equ ADC1_TRIGR1,	0x534E
.equ ADC1_TRIGR2,	0x534F
.equ ADC1_TRIGR3,	0x5350
.equ ADC1_TRIGR4,	0x5351

; RI
.equ RI_ICR1,		0x5431
.equ RI_ICR2,		0x5432
.equ RI_IOIR1,		0x5433
.equ RI_IOIR2,		0x5434
.equ RI_IOIR3,		0x5435
.equ RI_IOCMR1,		0x5436
.equ RI_IOCMR2,		0x5437
.equ RI_IOCMR3,		0x5438
.equ RI_IOSR1,		0x5439
.equ RI_IOSR2,		0x543A
.equ RI_IOSR3,		0x543B
.equ RI_IOGCR,		0x543C
.equ RI_ASCR1,		0x543D
.equ RI_ASCR2,		0x543E
.equ RI_RCR,		0x543F

; COMP1/2
.equ COMP_CSR1,		0x5440
.equ COMP_CSR2,		0x5441
.equ COMP_CSR3,		0x5442
.equ COMP_CSR4,		0x5443
.equ COMP_CSR5,		0x5444

; RI - continuare!
.equ RI_CR,		0x5450
.equ RI_MASKR1,		0x5451
.equ RI_MASKR2,		0x5452
.equ RI_MASKR3,		0x5453
.equ RI_MASKR4,		0x5454
.equ RI_IOIR4,		0x5455
.equ RI_IOCMR4,		0x5456
.equ RI_IOSR4,		0x5457

; CPU
.equ A,			0x7F00
.equ PCE,		0x7F01
.equ PCH,		0x7F02
.equ PCL,		0x7F03
.equ XH,		0x7F04
.equ XL,		0x7F05
.equ YH,		0x7F06
.equ YL,		0x7F07
.equ SPH,		0x7F08
.equ SPL,		0x7F09
.equ CCR,		0x7F0A

; CFG
.equ CFG_GCR,		0x7F60

; ITC-SPR
.equ ITC_SPR1,		0x7F70
.equ ITC_SPR2,		0x7F71
.equ ITC_SPR3,		0x7F72
.equ ITC_SPR4,		0x7F73
.equ ITC_SPR5,		0x7F74
.equ ITC_SPR6,		0x7F75
.equ ITC_SPR7,		0x7F76
.equ ITC_SPR8,		0x7F77

; SWIM
.equ SWIM_CSR,		0x7F80

; DM
.equ DM_BK1RE,		0x7F90
.equ DM_BK1RH,		0x7F91
.equ DM_BK1RL,		0x7F92
.equ DM_BK2RE,		0x7F93
.equ DM_BK2RH,		0x7F94
.equ DM_BK2RL,		0x7F95
.equ DM_CR1,		0x7F96
.equ DM_CR2,		0x7F97
.equ DM_CSR1,		0x7F98
.equ DM_CSR2,		0x7F99
.equ DM_ENFCTR,		0x7F9A

;-------------------------------------------------------------------
; GPIOR bit definitions
;-------------------------------------------------------------------
; FLASH_CR1 bits
.equ FLASH_CR1_IE_bp,		1
.equ FLASH_CR1_FIX_bp,		0

; FLASH_CR2 bits
.equ FLASH_CR2_OPT_bp,		7
.equ FLASH_CR2_WPRG_bp,		6
.equ FLASH_CR2_ERASE_bp,	5
.equ FLASH_CR2_FPRG_bp,		4
.equ FLASH_CR2_PRG_bp,		0

; FLASH_IAPSR bits
.equ FLASH_IAPSR_DUL_bp,	3
.equ FLASH_IAPSR_EOP_bp,	2
.equ FLASH_IAPSR_PUL_bp,	1
.equ FLASH_IAPSR_WR_PG_DIS_bp,	0

; CLK_CKDIVR bits
.equ CLK_CKDIVR_CKM0_bp,	0
.equ CLK_CKDIVR_CKM1_bp,	1
.equ CLK_CKDIVR_CKM2_bp,	2

.equ CLK_CKDIVR_CKM_DIV1_gc,	0x00
.equ CLK_CKDIVR_CKM_DIV2_gc,	0x01
.equ CLK_CKDIVR_CKM_DIV4_gc,	0x02
.equ CLK_CKDIVR_CKM_DIV8_gc,	0x03
.equ CLK_CKDIVR_CKM_DIV16_gc,	0x04
.equ CLK_CKDIVR_CKM_DIV32_gc,	0x05
.equ CLK_CKDIVR_CKM_DIV64_gc,	0x06
.equ CLK_CKDIVR_CKM_DIV128_gc,	0x07

; CLK_PCKENR1 bits
.equ CLK_PCKENR1_TIM2_bp,	0
.equ CLK_PCKENR1_TIM3_bp,	1
.equ CLK_PCKENR1_TIM4_bp,	2
.equ CLK_PCKENR1_I2C1_bp,	3
.equ CLK_PCKENR1_SPI1_bp,	4
.equ CLK_PCKENR1_USART1_bp,	5
.equ CLK_PCKENR1_BEEP_bp,	6
.equ CLK_PCKENR1_DAC_bp,	7

; CLK_PCKENR2 bits
.equ CLK_PCKENR2_ADC1_bp,	0
.equ CLK_PCKENR2_TIM1_bp,	1
.equ CLK_PCKENR2_RTC_bp,	2
.equ CLK_PCKENR2_LCD_bp,	3
.equ CLK_PCKENR2_DMA1_bp,	4
.equ CLK_PCKENR2_COMP_bp,	5
.equ CLK_PCKENR2_BOOTROM_bp,	7

; CLK_PCKENR3 bits
.equ CLK_PCKENR3_AES_bp,	0
.equ CLK_PCKENR3_TIM5_bp,	1
.equ CLK_PCKENR3_SPI2_bp,	2
.equ CLK_PCKENR3_USART2_bp,	3
.equ CLK_PCKENR3_USART3_bp,	4
.equ CLK_PCKENR3_CSS_LSE_bp,	5

; SPI_CR1 bits
.equ SPI_CR1_LSBFIRST_bp,	7
.equ SPI_CR1_SPE_bp,		6
.equ SPI_CR1_BR2_bp,		5
.equ SPI_CR1_BR1_bp,		4
.equ SPI_CR1_BR0_bp,		3
.equ SPI_CR1_MSTR_bp,		2
.equ SPI_CR1_CPOL_bp,		1
.equ SPI_CR1_CPHA_bp,		0

; SPI_CR2 bits
.equ SPI_CR2_BDM_bp,		7
.equ SPI_CR2_BDOE_bp,		6
.equ SPI_CR2_RXONLY_bp,		2
.equ SPI_CR2_SSM_bp,		1
.equ SPI_CR2_SSI_bp,		0

; SPI_ICR bits
.equ SPI_ICR_TXIE_bp,		7
.equ SPI_ICR_RXIE_bp,		6
.equ SPI_ICR_ERRIE_bp,		5
.equ SPI_ICR_WKIE_bp,		4

; SPI_SR bits
.equ SPI_SR_BSY_bp,		7
.equ SPI_SR_OVR_bp,		6
.equ SPI_SR_MODF_bp,		5
.equ SPI_SR_WKUP_bp,		3
.equ SPI_SR_TXE_bp,		1
.equ SPI_SR_RXNE_bp,		0

; USART_CR1 bits 
.equ USART_CR1_R8_bp,		7
.equ USART_CR1_T8_bp,		6
.equ USART_CR1_UARTD_bp,	5
.equ USART_CR1_M_bp,		4
.equ USART_CR1_WAKE_bp,		3
.equ USART_CR1_PCEN_bp,		2
.equ USART_CR1_PS_bp,		1
.equ USART_CR1_PIEN_bp,		0

; USART_CR2 bits
.equ USART_CR2_TIEN_bp,		7
.equ USART_CR2_TCIEN_bp,	6
.equ USART_CR2_RIEN_bp,		5
.equ USART_CR2_ILIEN_bp,	4
.equ USART_CR2_TEN_bp,		3
.equ USART_CR2_REN_bp,		2
.equ USART_CR2_RWU_bp,		1
.equ USART_CR2_SBK_bp,		0

; USART_CR3 bits 
.equ USART_CR3_LINEN_bp,	6
.equ USART_CR3_STOP2_bp,	5
.equ USART_CR3_STOP1_bp,	4
.equ USART_CR3_CLKEN_bp,	3
.equ USART_CR3_CPOL_bp,		2
.equ USART_CR3_CPHA_bp,		1
.equ USART_CR3_LBCL_bp,		0

; USART_SR bits
.equ USART_SR_TXE_bp,		7
.equ USART_SR_TC_bp,		6
.equ USART_SR_RXNE_bp,		5
.equ USART_SR_IDLE_bp,		4
.equ USART_SR_OR_bp,		3
.equ USART_SR_NF_bp,		2
.equ USART_SR_FE_bp,		1
.equ USART_SR_PE_bp,		0

; TIM_IER bits 
.equ TIM_IER_BIE_bp,		7
.equ TIM_IER_TIE_bp,		6
.equ TIM_IER_COMIE_bp,		5
.equ TIM_IER_CC4IE_bp,		4
.equ TIM_IER_CC3IE_bp,		3
.equ TIM_IER_CC2IE_bp,		2
.equ TIM_IER_CC1IE_bp,		1
.equ TIM_IER_UIE_bp,		0

; TIM_CR1 bits 
.equ TIM_CR1_APRE_bp,		7
.equ TIM_CR1_CMSH_bp,		6
.equ TIM_CR1_CMSL_bp,		5
.equ TIM_CR1_DIR_bp,		4
.equ TIM_CR1_OPM_bp,		3
.equ TIM_CR1_URS_bp,		2
.equ TIM_CR1_UDIS_bp,		1
.equ TIM_CR1_CEN_bp,		0

; TIM_SR1 bits 
.equ TIM_SR1_BIF_bp,		7
.equ TIM_SR1_TIF_bp,		6
.equ TIM_SR1_COMIF_bp,		5
.equ TIM_SR1_CC4IF_bp,		4
.equ TIM_SR1_CC3IF_bp,		3
.equ TIM_SR1_CC2IF_bp,		2
.equ TIM_SR1_CC1IF_bp,		1
.equ TIM_SR1_UIF_bp,		0

; TIM_EGR bits
.equ TIM_EGR_BG_bp,			7
.equ TIM_EGR_TG_bp,			6
.equ TIM_EGR_CC2G_bp,		2
.equ TIM_EGR_CC1G_bp,		1
.equ TIM_EGR_UG_bp,			0

; CFG_GCR
.equ CFG_GCR_SWD_bp,		0
.equ CFG_GCR_AL_bp,		1

; CLK_CBEEPR
.equ CLK_CBEEPR_SWBSY_bp,	0
.equ CLK_CBEEPR_SEL0_bp,	1
.equ CLK_CBEEPR_SEL1_bp,	2

.equ CLK_CBEEPR_NO_CLOCK_gc,	0x00
.equ CLK_CBEEPR_LSI_gc,		0x02
.equ CLK_CBEEPR_LSE_gc,		0x04

; TIM4_CR1
.equ TIM4_CR1_CEN_bp,		0
.equ TIM4_CR1_UDIS_bp,		1
.equ TIM4_CR1_URS_bp,		2
.equ TIM4_CR1_OPM_bp,		3
.equ TIM4_CR1_ARPE_bp,		7

; TIM4_SR
.equ TIM4_SR_UIF_bp,		0
.equ TIM4_SR_TIF_bp,		6

; TIM4_IER
.equ TIM4_IER_UIE_bp,		0
.equ TIM4_IER_TIE_bp,		6

; BEEP_CSR2
.equ BEEP_CSR2_BEEPDIV0,	0
.equ BEEP_CSR2_BEEPDIV1,	1
.equ BEEP_CSR2_BEEPDIV2,	2
.equ BEEP_CSR2_BEEPDIV3,	3
.equ BEEP_CSR2_BEEPDIV4,	4
.equ BEEP_CSR2_BEEPEN_bp,	5
.equ BEEP_CSR2_BEEPSEL0_bp,	6
.equ BEEP_CSR2_BEEPSEL1_bp,	7

; I2C1_CR1
.equ I2C_CR1_PE_bp,		0
.equ I2C_CR1_SMBUS_bp,		1
.equ I2C_CR1_SMBTYPE_bp,	3
.equ I2C_CR1_ENARP_bp,		4
.equ I2C_CR1_ENPEC_bp,		5
.equ I2C_CR1_ENGC_bp,		6
.equ I2C_CR1_NOSTRETCH_bp,	7

; I2C1_CR2
.equ I2C_CR2_START_bp,		0
.equ I2C_CR2_STOP_bp,		1
.equ I2C_CR2_ACK_bp,		2
.equ I2C_CR2_POS_bp,		3
.equ I2C_CR2_PEC_bp,		4
.equ I2C_CR2_ALERT_bp,		5
.equ I2C_CR2_SWRST_bp,		7

; I2C_ITR
.equ I2C_ITR_ITERREN_bp,	0
.equ I2C_ITR_ITEVTEN_bp,	1
.equ I2C_ITR_ITBUFEN_bp,	2
.equ I2C_ITR_DMAEN_bp,		3
.equ I2C_ITR_LAST_bp,		4

; I2C_SR1
.equ I2C_SR1_SB_bp,		0
.equ I2C_SR1_ADDR_bp,		1
.equ I2C_SR1_BTF_bp,		2
.equ I2C_SR1_ADD10_bp,		3
.equ I2C_SR1_STOPF_bp,		4
.equ I2C_SR1_RXNE_bp,		6
.equ I2C_SR1_TXE_bp,		7

; I2C_SR2
.equ I2C_SR2_BERR_bp,		0
.equ I2C_SR2_ARLO_bp,		1
.equ I2C_SR2_AF_bp,		2
.equ I2C_SR2_OVR_bp,		3
.equ I2C_SR2_PECERR_bp,		4
.equ I2C_SR2_WURF_bp,		5
.equ I2C_SR2_TIMEOUT_bp,	6
.equ I2C_SR2_SMBALERT_bp,	7

; I2C_SR3
.equ I2C_SR3_MSL_bp,		0
.equ I2C_SR3_BUSY_bp,		1
.equ I2C_SR3_TRA_bp,		2
.equ I2C_SR3_GENCALL_bp,	4
.equ I2C_SR3_SMBDEFAULT_bp,	5
.equ I2C_SR3_SMBHOST_bp,	6
.equ I2C_SR3_DUALF_bp,		7

;DMA_GCSR
.equ DMA_GCSR_GEN_bp,		0
.equ DMA_GCSR_GP_bp,		1
.equ DMA_GCSR_TO_bp,		2

;DMA_GIR1
.equ DMA_GIR1_IFC0_bp,		0
.equ DMA_GIR1_IFC1_bp,		1
.equ DMA_GIR1_IFC2_bp,		2
.equ DMA_GIR1_IFC3_bp,		3

;DMA_CCR
.equ DMA_CCR_EN_bp,		0
.equ DMA_CCR_TCIE_bp,		1
.equ DMA_CCR_HTIE_bp,		2
.equ DMA_CCR_DIR_bp,		3
.equ DMA_CCR_CIRC_bp,		4
.equ DMA_CCR_MINCDEC_bp,	5
.equ DMA_CCR_MEM_bp,		6

;DMA_CxSPR
.equ DMA_CSPR_TCIF_bp,		1
.equ DMA_CSPR_HTIF_bp,		2
.equ DMA_CSPR_TSIZE_bp,		3
.equ DMA_CSPR_PL0_bp,		4
.equ DMA_CSPR_PL1_bp,		5
.equ DMA_CSPR_PEND_bp,		6
.equ DMA_CSPR_BUSY_bp,		7


;ADC_CR1
.equ ADC_CR1_ADON_bp,		0
.equ ADC_CR1_START_bp,		1
.equ ADC_CR1_CONT_bp,		2
.equ ADC_CR1_EOCIE_bp,		3
.equ ADC_CR1_AWDIE_bp,		4
.equ ADC_CR1_RES0_bp,		5
.equ ADC_CR1_RES1_bp,		6
.equ ADC_CR1_OVERIE_bp,		7
.equ ADC_CR1_ADON_START_CONT_gc,	0x07

;ADC_CR2
.equ ADC_CR2_SMTP0_bp,		0
.equ ADC_CR2_SMTP1_bp,		1
.equ ADC_CR2_SMTP2_bp,		2
.equ ADC_CR2_EXTSEL0_bp,	3
.equ ADC_CR2_EXTSEL1_bp,	4
.equ ADC_CR2_TRIG_EDGE0_bp,	5
.equ ADC_CR2_TRIG_EDGE1_bp,	6
.equ ADC_CR2_PRESC_bp,		7

;ADC_SQR1
.equ ADC_SQR1_CHSEL_SVREFINT_bp, 4
.equ ADC_SQR1_CHSEL_STS_bp,	5
.equ ADC_SQR1_DMAOFF_bp,	7

;ADC_TRIG1
.equ ADC_TRIG1_VREFINTON_bp,	4

;TIM_CCMR1/2
;output
.equ TIM_CCMR_CCS0_bp,		0
.equ TIM_CCMR_CCS1_bp,		1
.equ TIM_CCMR_OCFE_bp,		2
.equ TIM_CCMR_OCPE_bp,		3
.equ TIM_CCMR_OCM0_bp,		4
.equ TIM_CCMR_OCM1_bp,		5
.equ TIM_CCMR_OCM2_bp,		6
.equ TIM_CCMR_OCM_SET_gc,	0x10
.equ TIM_CCMR_OCM_RES_gc,	0x20
.equ TIM_CCMR_OCM_TGL_gc,	0x30
.equ TIM_CCMR_OCM_LOW_gc,	0x40
.equ TIM_CCMR_OCM_HIGH_gc,	0x50
.equ TIM_CCMR_OCM_PWM1_gc,	0x60
.equ TIM_CCMR_OCM_PWM2_gc,	0x70

;input
.equ TIM_CCMR_ICPSC_bp,		2
.equ TIM_CCMR_ICPSC_bp,		3
.equ TIM_CCMR_ICF0_bp,		4
.equ TIM_CCMR_ICF1_bp,		5
.equ TIM_CCMR_ICF2_bp,		6
.equ TIM_CCMR_ICF3_bp,		7

;TIM_CCER1
.equ TIM_CCER1_CC1E_bp,		0
.equ TIM_CCER1_CC1P_bp,		1
.equ TIM_CCER1_CC2E_bp,		4
.equ TIM_CCER1_CC2P_bp,		5

;TIM_BKR
.equ TIM_BKR_LOCK0_bp,		0
.equ TIM_BKR_LOCK1_bp,		1
.equ TIM_BKR_OSSI_bp,		2
.equ TIM_BKR_BKE_bp,		4
.equ TIM_BKR_BKP_bp,		5
.equ TIM_BKR_AOE_bp,		6
.equ TIM_BKR_MOE_bp,		7

;ADC_SR
.equ ADC_SR_EOC_bp,		0
.equ ADC_SR_AWD_bp,		1
.equ ADC_SR_OVER_bp,		2

;CLK_SWCR
.equ CLK_SWCR_SWBSY_bp,		0
.equ CLK_SWCR_SWEN_bp,		1
.equ CLK_SWCR_SWIEN_bp,		2
.equ CLK_SWCR_SWIF_bp,		3

;CLK_SWR
.equ CLK_SWR_HSI_gc,		0x01
.equ CLK_SWR_LSI_gc,		0x02
.equ CLK_SWR_HSE_gc,		0x04
.equ CLK_SWR_LSE_gc,		0x08

;CLK_ICKCR
.equ CLK_ICKCR_HSION_bp,	0
.equ CLK_ICKCR_HSIRDY_bp,	1
.equ CLK_ICKCR_LSION_bp,	2
.equ CLK_ICKCR_LSIRDY_bp,	3
.equ CLK_ICKCR_SAHALT_bp,	4
.equ CLK_ICKCR_FHWU_bp,		5
.equ CLK_ICKCR_BEEPAHALT_bp,	6

;CLK_CRTCR
.equ CLK_CRTCR_DIV_1_gc,	0x00
.equ CLK_CRTCR_DIV_2_gc,	0x20
.equ CLK_CRTCR_DIV_4_gc,	0x40
.equ CLK_CRTCR_DIV_8_gc,	0x60
.equ CLK_CRTCR_DIV_16_gc,	0x80
.equ CLK_CRTCR_DIV_32_gc,	0xA0
.equ CLK_CRTCR_DIV_64_gc,	0xC0
.equ CLK_CRTCR_DIV_128_gc,	0xE0

.equ CLK_CRTCR_SEL_NONE_gc,	0x00
.equ CLK_CRTCR_SEL_HSI_gc,	0x02
.equ CLK_CRTCR_SEL_LSI_gc,	0x04
.equ CLK_CRTCR_SEL_HSE_gc,	0x08
.equ CLK_CRTCR_SEL_LSE_gc,	0x10

.equ CLK_CRTCR_SWBSY_bp,	0

;RTC_CR1
.equ RTC_CR1_WUCKSEL_DIV16_gc,	0x00
.equ RTC_CR1_WUCKSEL_DIV8_gc,	0x01
.equ RTC_CR1_WUCKSEL_DIV4_gc,	0x02
.equ RTC_CR1_WUCKSEL_DIV2_gc,	0x03
.equ RTC_CR1_WUCKSEL_CK_SPRE_gc,	0x04
.equ RTC_CR1_WUCKSEL_2CK_SPRE_gc,	0x06

;RTC_CR2
.equ RTC_CR2_ALRAE_bp,		0
.equ RTC_CR2_WUTE_bp,		2
.equ RTC_CR2_ALRAIE_bp,		4
.equ RTC_CR2_WUTIE_bp,		6

;RTC_ISR2
.equ RTC_ISR2_ALRAF_bp,		0
.equ RTC_ISR2_WUTF_bp,		2
.equ RTC_ISR2_TAMP1F_bp,	5
.equ RTC_ISR2_TAMP2F_bp,	6
.equ RTC_ISR2_TAMP3F_bp,	7

;RTC_ISR1
.equ RTC_ISR1_ALRAWF_bp,	0
.equ RTC_ISR1_RECALPF_bp,	1
.equ RTC_ISR1_WUTWF_bp,		2
.equ RTC_ISR1_SHPF_bp,		3
.equ RTC_ISR1_INITS_bp,		4
.equ RTC_ISR1_RSF_bp,		5
.equ RTC_ISR1_INITF_bp,		6
.equ RTC_ISR1_INIT_bp,		7

;CLK_ECKCR
.equ CLK_ECKCR_HSEON_bp,	0
.equ CLK_ECKCR_HSERDY_bp,	1
.equ CLK_ECKCR_LSEON_bp,	2
.equ CLK_ECKCR_LSERDY_bp,	3
.equ CLK_ECKCR_HSEBYP_bp,	4
.equ CLK_ECKCR_LSEBYP_bp,	5

;RST_SR
.equ RST_SR_PORF_bp,		0
.equ RST_SR_IWDGF_bp,		1
.equ RST_SR_ILLOPF_bp,		2
.equ RST_SR_SWIMF_bp,		3
.equ RST_SR_WWDGF_bp,		4
.equ RST_SR_BORF_bp,		5

;PWR_CSR1
.equ PWR_CSR1_PVDE_bp,		0
.equ PWR_CSR1_PLS_0,		1
.equ PWR_CSR1_PLS_0,		2
.equ PWR_CSR1_PLS_0,		3
.equ PWR_CSR1_PVDIEN_bp,	4
.equ PWR_CSR1_PVDIF_bp,		5
.equ PWR_CSR1_PVDOF_bp,		6

.equ PWR_CSR1_PLS_1V85_gc,	0x00
.equ PWR_CSR1_PLS_2V05_gc,	0x02
.equ PWR_CSR1_PLS_2V26_gc,	0x04
.equ PWR_CSR1_PLS_2V45_gc,	0x06
.equ PWR_CSR1_PLS_2V65_gc,	0x08
.equ PWR_CSR1_PLS_2V85_gc,	0x0A
.equ PWR_CSR1_PLS_3V05_gc,	0x0C
.equ PWR_CSR1_PLS_IN_gc,	0x0E

.equ PWR_CSR1_PLS_gm,		0x0E

;TIM_DER
.equ TIM_DER_UDE_bp,		0
.equ TIM_DER_CC1DE_bp,		1
.equ TIM_DER_CC2DE_bp,		2
.equ TIM_DER_CC3DE_bp,		3
.equ TIM_DER_CC4DE_bp,		4
.equ TIM_DER_COMDE_bp,		5

;-------------------------------------------------------------------------------
; Fin
