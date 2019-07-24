#undef Elf_
#undef Elf_Vword
#undef ELF_ST_BIND
#undef ELF_ST_TYPE
#undef ELF_ST_INFO
#undef ELF_ST_VISIBILITY
#undef ELF_R_SYM
#undef ELF_R_TYPE
#undef ELF_R_INFO
#undef ELF_M_SYM
#undef ELF_M_SIZE
#undef ELF_M_INFO

#ifdef R_BIN_ELF64
# define Elf_(name) Elf64_##name
# define ELF_ST_BIND       ELF64_ST_BIND
# define ELF_ST_TYPE       ELF64_ST_TYPE
# define ELF_ST_INFO       ELF64_ST_INFO
# define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY
# define ELF_R_SYM         ELF64_R_SYM
# define ELF_R_TYPE        ELF64_R_TYPE
# define ELF_R_INFO        ELF64_R_INFO
# define ELF_M_SYM         ELF64_M_SYM
# define ELF_M_SIZE        ELF64_M_SIZE
# define ELF_M_INFO        ELF64_M_INFO
#else
# define Elf_(name) Elf32_##name
# define ELF_ST_BIND       ELF32_ST_BIND
# define ELF_ST_TYPE       ELF32_ST_TYPE
# define ELF_ST_INFO       ELF32_ST_INFO
# define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY
# define ELF_R_SYM         ELF32_R_SYM
# define ELF_R_TYPE        ELF32_R_TYPE
# define ELF_R_INFO        ELF32_R_INFO
# define ELF_M_SYM         ELF32_M_SYM
# define ELF_M_SIZE        ELF32_M_SIZE
# define ELF_M_INFO        ELF32_M_INFO
#endif

/* MingW doesn't define __BEGIN_DECLS / __END_DECLS. */
#ifndef __BEGIN_DECLS
#  ifdef __cplusplus
#    define __BEGIN_DECLS extern "C" {
#  else
#    define __BEGIN_DECLS
#  endif
#endif
#ifndef __END_DECLS
#  ifdef __cplusplus
#    define __END_DECLS }
#  else
#    define __END_DECLS
#  endif
#endif

#include "glibc_elf.h"

#ifndef _INCLUDE_ELF_SPECS_H
#define _INCLUDE_ELF_SPECS_H

#define ELF_STRING_LENGTH 256

// not strictly ELF, but close enough:
#define        CGCMAG          "\177CGC"
#define        SCGCMAG         4

#define ELFOSABI_HURD          4       /* GNU/HURD */
#define ELFOSABI_86OPEN        5       /* 86open */
#define ELFOSABI_OPENVMS       13      /* OpenVMS  */
#define ELFOSABI_ARM_AEABI     64      /* ARM EABI */

#define EM_PROPELLER           0x5072
#define EM_LANAI               0x8123
#define EM_VIDEOCORE4          200

#define EM_PDP10               64         /* Digital Equipment Corp. PDP-10 */
#define EM_PDP11               65         /* Digital Equipment Corp. PDP-11 */

#define EM_VIDEOCORE           95         /* Alphamosaic VideoCore processor */  // XXX dupe for EM_NUM
#define EM_TMM_GPP             96         /* Thompson Multimedia General Purpose Processor */
#define EM_NS32K               97         /* National Semiconductor 32000 series */
#define EM_TPC                 98         /* Tenor Network TPC processor */
#define EM_SNP1K               99         /* Trebia SNP 1000 processor */
#define EM_ST200               100        /* STMicroelectronics (www.st.com) ST200 microcontroller */
#define EM_IP2K                101        /* Ubicom IP2xxx microcontroller family */
#define EM_MAX                 102        /* MAX Processor */
#define EM_CR                  103        /* National Semiconductor CompactRISC microprocessor */
#define EM_F2MC16              104        /* Fujitsu F2MC16 */
#define EM_MSP430              105        /* Texas Instruments embedded microcontroller msp430 */
#define EM_BLACKFIN            106        /* Analog Devices Blackfin (DSP) processor */
#define EM_SE_C33              107        /* S1C33 Family of Seiko Epson processors */
#define EM_SEP                 108        /* Sharp embedded microprocessor */
#define EM_ARCA                109        /* Arca RISC Microprocessor */
#define EM_UNICORE             110        /* Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University */
#define EM_EXCESS              111        /* eXcess: 16/32/64-bit configurable embedded CPU */
#define EM_DXP                 112        /* Icera Semiconductor Inc. Deep Execution Processor */

// http://www.sco.com/developers/gabi/latest/ch4.eheader.html

#define EM_CRX                 114        /* National Semiconductor CompactRISC CRX microprocessor */
#define EM_XGATE               115        /* Motorola XGATE embedded processor */
#define EM_C166                116        /* Infineon C16x/XC16x processor */
#define EM_M16C                117        /* Renesas M16C series microprocessors */
#define EM_DSPIC30F            118        /* Microchip Technology dsPIC30F Digital Signal Controller */
#define EM_CE                  119        /* Freescale Communication Engine RISC core */
#define EM_M32C                120        /* Renesas M32C series microprocessors */
#define EM_TSK3000             131        /* Altium TSK3000 core */
#define EM_RS08                132        /* Freescale RS08 embedded processor */
#define EM_SHARC               133        /* Analog Devices SHARC family of 32-bit DSP processors */
#define EM_ECOG2               134        /* Cyan Technology eCOG2 microprocessor */
#define EM_SCORE7              135        /* Sunplus S+core7 RISC processor */
#define EM_DSP24               136        /* New Japan Radio (NJR) 24-bit DSP Processor */
#define EM_VIDEOCORE3          137        /* Broadcom VideoCore III processor */
#define EM_LATTICEMICO32       138        /* RISC processor for Lattice FPGA architecture */
#define EM_SE_C17              139        /* Seiko Epson C17 family */
#define EM_TI_C6000            140        /* The Texas Instruments TMS320C6000 DSP family */
#define EM_TI_C2000            141        /* The Texas Instruments TMS320C2000 DSP family */
#define EM_TI_C5500            142        /* The Texas Instruments TMS320C55x DSP family */
#define EM_TI_ARP32            143        /* Texas Instruments Application Specific RISC Processor, 32bit fetch */
#define EM_TI_PRU              144        /* Texas Instruments Programmable Realtime Unit */
#define EM_MMDSP_PLUS          160        /* STMicroelectronics 64bit VLIW Data Signal Processor */
#define EM_CYPRESS_M8C         161        /* Cypress M8C microprocessor */
#define EM_R32C                162        /* Renesas R32C series microprocessors */
#define EM_TRIMEDIA            163        /* NXP Semiconductors TriMedia architecture family */
#define EM_QDSP6               164        /* QUALCOMM DSP6 Processor */  // Nonstandard
#define EM_8051                165        /* Intel 8051 and variants */
#define EM_STXP7X              166        /* STMicroelectronics STxP7x family of configurable and extensible RISC processors */
#define EM_NDS32               167        /* Andes Technology compact code size embedded RISC processor family */
#define EM_ECOG1               168        /* Cyan Technology eCOG1X family */
#define EM_MAXQ30              169        /* Dallas Semiconductor MAXQ30 Core Micro-controllers */
#define EM_XIMO16              170        /* New Japan Radio (NJR) 16-bit DSP Processor */
#define EM_MANIK               171        /* M2000 Reconfigurable RISC Microprocessor */
#define EM_CRAYNV2             172        /* Cray Inc. NV2 vector architecture */
#define EM_RX                  173        /* Renesas RX family */
#define EM_METAG               174        /* Imagination Technologies META processor architecture */
#define EM_MCST_ELBRUS         175        /* MCST Elbrus general purpose hardware architecture */
#define EM_ECOG16              176        /* Cyan Technology eCOG16 family */
#define EM_CR16                177        /* National Semiconductor CompactRISC CR16 16-bit microprocessor */
#define EM_ETPU                178        /* Freescale Extended Time Processing Unit */
#define EM_SLE9X               179        /* Infineon Technologies SLE9X core */
#define EM_L10M                180        /* Intel L10M */
#define EM_K10M                181        /* Intel K10M */
#define EM_AARCH64             183        /* ARM 64-bit architecture (AARCH64) */
#define EM_AVR32               185        /* Atmel Corporation 32-bit microprocessor family */
#define EM_STM8                186        /* STMicroeletronics STM8 8-bit microcontroller */
#define EM_TILE64              187        /* Tilera TILE64 multicore architecture family */
#define EM_TILEPRO             188        /* Tilera TILEPro multicore architecture family */
#define EM_MICROBLAZE          189        /* Xilinx MicroBlaze 32-bit RISC soft processor core */
#define EM_CUDA                190        /* NVIDIA CUDA architecture */
#define EM_TILEGX              191        /* Tilera TILE-Gx multicore architecture family */
#define EM_CLOUDSHIELD         192        /* CloudShield architecture family */
#define EM_COREA_1ST           193        /* KIPO-KAIST Core-A 1st generation processor family */
#define EM_COREA_2ND           194        /* KIPO-KAIST Core-A 2nd generation processor family */
#define EM_ARC_COMPACT2        195        /* Synopsys ARCompact V2 */
#define EM_OPEN8               196        /* Open8 8-bit RISC soft processor core */
#define EM_RL78                197        /* Renesas RL78 family */
#define EM_VIDEOCORE5          198        /* Broadcom VideoCore V processor */
#define EM_78KOR               199        /* Renesas 78KOR family */
#define EM_56800EX             200        /* Freescale 56800EX Digital Signal Controller (DSC) */
#define EM_BA1                 201        /* Beyond BA1 CPU architecture */
#define EM_BA2                 202        /* Beyond BA2 CPU architecture */
#define EM_XCORE               203        /* XMOS xCORE processor family */
#define EM_MCHP_PIC            204        /* Microchip 8-bit PIC(r) family */
#define EM_INTEL205            205        /* Reserved by Intel */
#define EM_INTEL206            206        /* Reserved by Intel */
#define EM_INTEL207            207        /* Reserved by Intel */
#define EM_INTEL208            208        /* Reserved by Intel */
#define EM_INTEL209            209        /* Reserved by Intel */
#define EM_KM32                210        /* KM211 KM32 32-bit processor */
#define EM_KMX32               211        /* KM211 KMX32 32-bit processor */
#define EM_KMX16               212        /* KM211 KMX16 16-bit processor */
#define EM_KMX8                213        /* KM211 KMX8 8-bit processor */
#define EM_KVARC               214        /* KM211 KVARC processor */
#define EM_CDP                 215        /* Paneve CDP architecture family */
#define EM_COGE                216        /* Cognitive Smart Memory Processor */
#define EM_COOL                217        /* Bluechip Systems CoolEngine */
#define EM_NORC                218        /* Nanoradio Optimized RISC */
#define EM_CSR_KALIMBA         219        /* CSR Kalimba architecture family */
#define EM_Z80                 220        /* Zilog Z80 */
#define EM_VISIUM              221        /* Controls and Data Services VISIUMcore processor */
#define EM_FT32                222        /* FTDI Chip FT32 high performance 32-bit RISC architecture */
#define EM_MOXIE               223        /* Moxie processor family */
#define EM_AMDGPU              224        /* AMD GPU architecture */
#define EM_RISCV               243        /* RISC-V */


// specific OpenBSD sections
#ifndef PT_OPENBSD_RANDOMIZE
#define PT_OPENBSD_RANDOMIZE	0x65a3dbe6	/* Random data */
#define PT_OPENBSD_WXNEEDED	0x65a3dbe7	/* Allowing writable/executable mapping */
#define PT_OPENBSD_BOOTDATA	0x65a41be6	/* Boot time data */
#endif


#endif // _INCLUDE_ELF_SPECS_H
