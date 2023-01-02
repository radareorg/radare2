/* ARM assembler/disassembler support.
   Copyright (C) 2004-2017 Free Software Foundation, Inc.

   This file is part of GDB and GAS.

   GDB and GAS are free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 3, or (at
   your option) any later version.

   GDB and GAS are distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GDB or GAS; see the file COPYING3.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* The following bitmasks control CPU extensions:  */
#define ARM_EXT_V1	 0x00000001	/* All processors (core set).  */
#define ARM_EXT_V2	 0x00000002	/* Multiply instructions.  */
#define ARM_EXT_V2S	 0x00000004	/* SWP instructions.       */
#define ARM_EXT_V3	 0x00000008	/* MSR MRS.                */
#define ARM_EXT_V3M	 0x00000010	/* Allow long multiplies.  */
#define ARM_EXT_V4	 0x00000020	/* Allow half word loads.  */
#define ARM_EXT_V4T	 0x00000040	/* Thumb.                  */
#define ARM_EXT_V5	 0x00000080	/* Allow CLZ, etc.         */
#define ARM_EXT_V5T	 0x00000100	/* Improved interworking.  */
#define ARM_EXT_V5ExP	 0x00000200	/* DSP core set.           */
#define ARM_EXT_V5E	 0x00000400	/* DSP Double transfers.   */
#define ARM_EXT_V5J	 0x00000800	/* Jazelle extension.	   */
#define ARM_EXT_V6       0x00001000     /* ARM V6.                 */
#define ARM_EXT_V6K      0x00002000     /* ARM V6K.                */
#define ARM_EXT_V8	 0x00004000     /* ARMv8 w/o atomics.      */
#define ARM_EXT_V6T2	 0x00008000	/* Thumb-2.                */
#define ARM_EXT_DIV	 0x00010000	/* Integer division.       */
/* The 'M' in Arm V7M stands for Microcontroller.
   On earlier architecture variants it stands for Multiply.  */
#define ARM_EXT_V5E_NOTM 0x00020000	/* Arm V5E but not Arm V7M. */
#define ARM_EXT_V6_NOTM	 0x00040000	/* Arm V6 but not Arm V7M. */
#define ARM_EXT_V7	 0x00080000	/* Arm V7.                 */
#define ARM_EXT_V7A	 0x00100000	/* Arm V7A.                */
#define ARM_EXT_V7R	 0x00200000	/* Arm V7R.                */
#define ARM_EXT_V7M	 0x00400000	/* Arm V7M.                */
#define ARM_EXT_V6M	 0x00800000	/* ARM V6M.		    */
#define ARM_EXT_BARRIER	 0x01000000	/* DSB/DMB/ISB.		    */
#define ARM_EXT_THUMB_MSR 0x02000000	/* Thumb MSR/MRS.	    */
#define ARM_EXT_V6_DSP 0x04000000	/* ARM v6 (DSP-related),
					   not in v7-M.  */
#define ARM_EXT_MP       0x08000000     /* Multiprocessing Extensions.  */
#define ARM_EXT_SEC	 0x10000000	/* Security extensions.  */
#define ARM_EXT_OS	 0x20000000	/* OS Extensions.  */
#define ARM_EXT_ADIV	 0x40000000	/* Integer divide extensions in ARM
					   state.  */
#define ARM_EXT_VIRT	 0x80000000	/* Virtualization extensions.  */

#define ARM_EXT2_PAN	 0x00000001     /* PAN extension.  */
#define ARM_EXT2_V8_2A	 0x00000002     /* ARM V8.2A.  */
#define ARM_EXT2_V8M	 0x00000004	/* ARM V8M.  */
#define ARM_EXT2_ATOMICS 0x00000008	/* ARMv8 atomics.  */
#define ARM_EXT2_V6T2_V8M  0x00000010	/* V8M Baseline from V6T2.  */
#define ARM_EXT2_FP16_INST 0x00000020	/* ARM V8.2A FP16 instructions.  */
#define ARM_EXT2_V8M_MAIN  0x00000040	/* ARMv8-M Mainline.  */
#define ARM_EXT2_RAS	 0x00000080	/* RAS extension.  */
#define ARM_EXT2_V8_3A	 0x00000100	/* ARM V8.3A.  */

/* Co-processor space extensions.  */
#define ARM_CEXT_XSCALE   0x00000001	/* Allow MIA etc.          */
#define ARM_CEXT_MAVERICK 0x00000002	/* Use Cirrus/DSP coprocessor.  */
#define ARM_CEXT_IWMMXT   0x00000004    /* Intel Wireless MMX technology coprocessor.   */
#define ARM_CEXT_IWMMXT2  0x00000008    /* Intel Wireless MMX technology coprocessor version 2.   */

#define FPU_ENDIAN_PURE	 0x80000000	/* Pure-endian doubles.	      */
#define FPU_ENDIAN_BIG	 0		/* Double words-big-endian.   */
#define FPU_FPA_EXT_V1	 0x40000000	/* Base FPA instruction set.  */
#define FPU_FPA_EXT_V2	 0x20000000	/* LFM/SFM.		      */
#define FPU_MAVERICK	 0x10000000	/* Cirrus Maverick.	      */
#define FPU_VFP_EXT_V1xD 0x08000000	/* Base VFP instruction set.  */
#define FPU_VFP_EXT_V1	 0x04000000	/* Double-precision insns.    */
#define FPU_VFP_EXT_V2	 0x02000000	/* ARM10E VFPr1.	      */
#define FPU_VFP_EXT_V3xD 0x01000000	/* VFPv3 single-precision.    */
#define FPU_VFP_EXT_V3	 0x00800000	/* VFPv3 double-precision.    */
#define FPU_NEON_EXT_V1	 0x00400000	/* Neon (SIMD) insns.	      */
#define FPU_VFP_EXT_D32  0x00200000	/* Registers D16-D31.	      */
#define FPU_VFP_EXT_FP16 0x00100000	/* Half-precision extensions. */
#define FPU_NEON_EXT_FMA 0x00080000	/* Neon fused multiply-add    */
#define FPU_VFP_EXT_FMA	 0x00040000	/* VFP fused multiply-add     */
#define FPU_VFP_EXT_ARMV8 0x00020000	/* Double-precision FP for ARMv8.  */
#define FPU_NEON_EXT_ARMV8 0x00010000	/* Neon for ARMv8.  */
#define FPU_CRYPTO_EXT_ARMV8 0x00008000	/* Crypto for ARMv8.  */
#define CRC_EXT_ARMV8	 0x00004000	/* CRC32 for ARMv8.  */
#define FPU_VFP_EXT_ARMV8xD 0x00002000	/* Single-precision FP for ARMv8.  */
#define FPU_NEON_EXT_RDMA 0x00001000     /* v8.1 Adv.SIMD extensions.  */

/* Architectures are the sum of the base and extensions.  The ARM ARM (rev E)
   defines the following: ARMv3, ARMv3M, ARMv4xM, ARMv4, ARMv4TxM, ARMv4T,
   ARMv5xM, ARMv5, ARMv5TxM, ARMv5T, ARMv5TExP, ARMv5TE.  To these we add
   three more to cover cores prior to ARM6.  Finally, there are cores which
   implement further extensions in the co-processor space.  */
#define ARM_AEXT_V1			  ARM_EXT_V1
#define ARM_AEXT_V2	(ARM_AEXT_V1	| ARM_EXT_V2)
#define ARM_AEXT_V2S	(ARM_AEXT_V2	| ARM_EXT_V2S)
#define ARM_AEXT_V3	(ARM_AEXT_V2S	| ARM_EXT_V3)
#define ARM_AEXT_V3M	(ARM_AEXT_V3	| ARM_EXT_V3M)
#define ARM_AEXT_V4xM	(ARM_AEXT_V3	| ARM_EXT_V4)
#define ARM_AEXT_V4	(ARM_AEXT_V3M	| ARM_EXT_V4)
#define ARM_AEXT_V4TxM	(ARM_AEXT_V4xM	| ARM_EXT_V4T)
#define ARM_AEXT_V4T	(ARM_AEXT_V4	| ARM_EXT_V4T)
#define ARM_AEXT_V5xM	(ARM_AEXT_V4xM	| ARM_EXT_V5)
#define ARM_AEXT_V5	(ARM_AEXT_V4	| ARM_EXT_V5)
#define ARM_AEXT_V5TxM	(ARM_AEXT_V5xM	| ARM_EXT_V4T | ARM_EXT_V5T)
#define ARM_AEXT_V5T	(ARM_AEXT_V5	| ARM_EXT_V4T | ARM_EXT_V5T)
#define ARM_AEXT_V5TExP	(ARM_AEXT_V5T	| ARM_EXT_V5ExP)
#define ARM_AEXT_V5TE	(ARM_AEXT_V5TExP | ARM_EXT_V5E)
#define ARM_AEXT_V5TEJ	(ARM_AEXT_V5TE	| ARM_EXT_V5J)
#define ARM_AEXT_V6     (ARM_AEXT_V5TEJ | ARM_EXT_V6)
#define ARM_AEXT_V6K    (ARM_AEXT_V6    | ARM_EXT_V6K)
#define ARM_AEXT_V6Z    (ARM_AEXT_V6K	| ARM_EXT_SEC)
#define ARM_AEXT_V6KZ   (ARM_AEXT_V6K	| ARM_EXT_SEC)
#define ARM_AEXT_V6T2   (ARM_AEXT_V6 \
    | ARM_EXT_V6T2 | ARM_EXT_V6_NOTM | ARM_EXT_THUMB_MSR \
    | ARM_EXT_V6_DSP )
#define ARM_AEXT_V6KT2  (ARM_AEXT_V6T2 | ARM_EXT_V6K)
#define ARM_AEXT_V6ZT2  (ARM_AEXT_V6T2 | ARM_EXT_SEC)
#define ARM_AEXT_V6KZT2 (ARM_AEXT_V6T2 | ARM_EXT_V6K | ARM_EXT_SEC)
#define ARM_AEXT_V7_ARM	(ARM_AEXT_V6KT2 | ARM_EXT_V7 | ARM_EXT_BARRIER)
#define ARM_AEXT_V7A	(ARM_AEXT_V7_ARM | ARM_EXT_V7A)
#define ARM_AEXT_V7VE	(ARM_AEXT_V7A  | ARM_EXT_DIV | ARM_EXT_ADIV \
    | ARM_EXT_VIRT | ARM_EXT_SEC | ARM_EXT_MP)
#define ARM_AEXT_V7R	(ARM_AEXT_V7_ARM | ARM_EXT_V7R | ARM_EXT_DIV)
#define ARM_AEXT_NOTM \
  (ARM_AEXT_V4 | ARM_EXT_V5ExP | ARM_EXT_V5J | ARM_EXT_V6_NOTM \
   | ARM_EXT_V6_DSP )
#define ARM_AEXT_V6M_ONLY \
  ((ARM_EXT_BARRIER | ARM_EXT_V6M | ARM_EXT_THUMB_MSR) & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V6M \
  ((ARM_AEXT_V6K | ARM_AEXT_V6M_ONLY) & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V6SM (ARM_AEXT_V6M | ARM_EXT_OS)
#define ARM_AEXT_V7M \
  ((ARM_AEXT_V7_ARM | ARM_EXT_V6M | ARM_EXT_V7M | ARM_EXT_DIV) \
   & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V7 (ARM_AEXT_V7A & ARM_AEXT_V7R & ARM_AEXT_V7M)
#define ARM_AEXT_V7EM \
  (ARM_AEXT_V7M | ARM_EXT_V5ExP | ARM_EXT_V6_DSP)
#define ARM_AEXT_V8A \
  (ARM_AEXT_V7A | ARM_EXT_MP | ARM_EXT_SEC | ARM_EXT_DIV | ARM_EXT_ADIV \
   | ARM_EXT_VIRT | ARM_EXT_V8)
#define ARM_AEXT2_V8A	(ARM_EXT2_V6T2_V8M | ARM_EXT2_ATOMICS)
#define ARM_AEXT2_V8_1A	(ARM_AEXT2_V8A | ARM_EXT2_PAN)
#define ARM_AEXT2_V8_2A	(ARM_AEXT2_V8_1A | ARM_EXT2_V8_2A | ARM_EXT2_RAS)
#define ARM_AEXT2_V8_3A	(ARM_AEXT2_V8_2A | ARM_EXT2_V8_3A)
#define ARM_AEXT_V8M_BASE (ARM_AEXT_V6SM | ARM_EXT_DIV)
#define ARM_AEXT_V8M_MAIN ARM_AEXT_V7M
#define ARM_AEXT_V8M_MAIN_DSP ARM_AEXT_V7EM
#define ARM_AEXT2_V8M	(ARM_EXT2_V8M | ARM_EXT2_ATOMICS | ARM_EXT2_V6T2_V8M)
#define ARM_AEXT2_V8M_MAIN (ARM_AEXT2_V8M | ARM_EXT2_V8M_MAIN)
#define ARM_AEXT2_V8M_MAIN_DSP ARM_AEXT2_V8M_MAIN

/* Processors with specific extensions in the co-processor space.  */
#define ARM_ARCH_XSCALE	ARM_FEATURE_LOW (ARM_AEXT_V5TE, ARM_CEXT_XSCALE)
#define ARM_ARCH_IWMMXT	\
 ARM_FEATURE_LOW (ARM_AEXT_V5TE, ARM_CEXT_XSCALE | ARM_CEXT_IWMMXT)
#define ARM_ARCH_IWMMXT2	\
 ARM_FEATURE_LOW (ARM_AEXT_V5TE, ARM_CEXT_XSCALE | ARM_CEXT_IWMMXT \
		  | ARM_CEXT_IWMMXT2)

#define FPU_VFP_V1xD	(FPU_VFP_EXT_V1xD | FPU_ENDIAN_PURE)
#define FPU_VFP_V1	(FPU_VFP_V1xD | FPU_VFP_EXT_V1)
#define FPU_VFP_V2	(FPU_VFP_V1 | FPU_VFP_EXT_V2)
#define FPU_VFP_V3D16	(FPU_VFP_V2 | FPU_VFP_EXT_V3xD | FPU_VFP_EXT_V3)
#define FPU_VFP_V3	(FPU_VFP_V3D16 | FPU_VFP_EXT_D32)
#define FPU_VFP_V3xD	(FPU_VFP_V1xD | FPU_VFP_EXT_V2 | FPU_VFP_EXT_V3xD)
#define FPU_VFP_V4D16	(FPU_VFP_V3D16 | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_V4	(FPU_VFP_V3 | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_V4_SP_D16 (FPU_VFP_V3xD | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_V5D16	(FPU_VFP_V4D16 | FPU_VFP_EXT_ARMV8xD | FPU_VFP_EXT_ARMV8)
#define FPU_VFP_V5_SP_D16 (FPU_VFP_V4_SP_D16 | FPU_VFP_EXT_ARMV8xD)
#define FPU_VFP_ARMV8	(FPU_VFP_V4 | FPU_VFP_EXT_ARMV8 | FPU_VFP_EXT_ARMV8xD)
#define FPU_NEON_ARMV8	(FPU_NEON_EXT_V1 | FPU_NEON_EXT_FMA | FPU_NEON_EXT_ARMV8)
#define FPU_CRYPTO_ARMV8 (FPU_CRYPTO_EXT_ARMV8)
#define FPU_VFP_HARD	(FPU_VFP_EXT_V1xD | FPU_VFP_EXT_V1 | FPU_VFP_EXT_V2 \
			 | FPU_VFP_EXT_V3xD | FPU_VFP_EXT_FMA | FPU_NEON_EXT_FMA \
                         | FPU_VFP_EXT_V3 | FPU_NEON_EXT_V1 | FPU_VFP_EXT_D32)
#define FPU_FPA		(FPU_FPA_EXT_V1 | FPU_FPA_EXT_V2)

/* Deprecated.  */
#define FPU_ARCH_VFP	ARM_FEATURE_COPROC (FPU_ENDIAN_PURE)

#define FPU_ARCH_FPE	ARM_FEATURE_COPROC (FPU_FPA_EXT_V1)
#define FPU_ARCH_FPA	ARM_FEATURE_COPROC (FPU_FPA)

#define FPU_ARCH_VFP_V1xD ARM_FEATURE_COPROC (FPU_VFP_V1xD)
#define FPU_ARCH_VFP_V1	  ARM_FEATURE_COPROC (FPU_VFP_V1)
#define FPU_ARCH_VFP_V2	  ARM_FEATURE_COPROC (FPU_VFP_V2)
#define FPU_ARCH_VFP_V3D16	ARM_FEATURE_COPROC (FPU_VFP_V3D16)
#define FPU_ARCH_VFP_V3D16_FP16 \
  ARM_FEATURE_COPROC (FPU_VFP_V3D16 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_V3	  ARM_FEATURE_COPROC (FPU_VFP_V3)
#define FPU_ARCH_VFP_V3_FP16	ARM_FEATURE_COPROC (FPU_VFP_V3 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_V3xD	ARM_FEATURE_COPROC (FPU_VFP_V3xD)
#define FPU_ARCH_VFP_V3xD_FP16	ARM_FEATURE_COPROC (FPU_VFP_V3xD \
						 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_NEON_V1  ARM_FEATURE_COPROC (FPU_NEON_EXT_V1)
#define FPU_ARCH_VFP_V3_PLUS_NEON_V1 \
  ARM_FEATURE_COPROC (FPU_VFP_V3 | FPU_NEON_EXT_V1)
#define FPU_ARCH_NEON_FP16 \
  ARM_FEATURE_COPROC (FPU_VFP_V3 | FPU_NEON_EXT_V1 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_HARD ARM_FEATURE_COPROC (FPU_VFP_HARD)
#define FPU_ARCH_VFP_V4 ARM_FEATURE_COPROC (FPU_VFP_V4)
#define FPU_ARCH_VFP_V4D16 ARM_FEATURE_COPROC (FPU_VFP_V4D16)
#define FPU_ARCH_VFP_V4_SP_D16 ARM_FEATURE_COPROC (FPU_VFP_V4_SP_D16)
#define FPU_ARCH_VFP_V5D16 ARM_FEATURE_COPROC (FPU_VFP_V5D16)
#define FPU_ARCH_VFP_V5_SP_D16 ARM_FEATURE_COPROC (FPU_VFP_V5_SP_D16)
#define FPU_ARCH_NEON_VFP_V4 \
  ARM_FEATURE_COPROC (FPU_VFP_V4 | FPU_NEON_EXT_V1 | FPU_NEON_EXT_FMA)
#define FPU_ARCH_VFP_ARMV8 ARM_FEATURE_COPROC (FPU_VFP_ARMV8)
#define FPU_ARCH_NEON_VFP_ARMV8 ARM_FEATURE_COPROC (FPU_NEON_ARMV8 \
						 | FPU_VFP_ARMV8)
#define FPU_ARCH_CRYPTO_NEON_VFP_ARMV8 \
  ARM_FEATURE_COPROC (FPU_CRYPTO_ARMV8 | FPU_NEON_ARMV8 | FPU_VFP_ARMV8)
#define ARCH_CRC_ARMV8 ARM_FEATURE_COPROC (CRC_EXT_ARMV8)
#define FPU_ARCH_NEON_VFP_ARMV8_1 \
  ARM_FEATURE_COPROC (FPU_NEON_ARMV8				 \
		      | FPU_VFP_ARMV8				 \
		      | FPU_NEON_EXT_RDMA)
#define FPU_ARCH_CRYPTO_NEON_VFP_ARMV8_1 \
  ARM_FEATURE_COPROC (FPU_CRYPTO_ARMV8 | FPU_NEON_ARMV8 | FPU_VFP_ARMV8 \
		      | FPU_NEON_EXT_RDMA)


#define FPU_ARCH_ENDIAN_PURE ARM_FEATURE_COPROC (FPU_ENDIAN_PURE)

#define FPU_ARCH_MAVERICK ARM_FEATURE_COPROC (FPU_MAVERICK)

#define ARM_ARCH_V1	ARM_FEATURE_CORE_LOW (ARM_AEXT_V1)
#define ARM_ARCH_V2	ARM_FEATURE_CORE_LOW (ARM_AEXT_V2)
#define ARM_ARCH_V2S	ARM_FEATURE_CORE_LOW (ARM_AEXT_V2S)
#define ARM_ARCH_V3	ARM_FEATURE_CORE_LOW (ARM_AEXT_V3)
#define ARM_ARCH_V3M	ARM_FEATURE_CORE_LOW (ARM_AEXT_V3M)
#define ARM_ARCH_V4xM	ARM_FEATURE_CORE_LOW (ARM_AEXT_V4xM)
#define ARM_ARCH_V4	ARM_FEATURE_CORE_LOW (ARM_AEXT_V4)
#define ARM_ARCH_V4TxM	ARM_FEATURE_CORE_LOW (ARM_AEXT_V4TxM)
#define ARM_ARCH_V4T	ARM_FEATURE_CORE_LOW (ARM_AEXT_V4T)
#define ARM_ARCH_V5xM	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5xM)
#define ARM_ARCH_V5	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5)
#define ARM_ARCH_V5TxM	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5TxM)
#define ARM_ARCH_V5T	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5T)
#define ARM_ARCH_V5TExP	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5TExP)
#define ARM_ARCH_V5TE	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5TE)
#define ARM_ARCH_V5TEJ	ARM_FEATURE_CORE_LOW (ARM_AEXT_V5TEJ)
#define ARM_ARCH_V6	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6)
#define ARM_ARCH_V6K	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6K)
#define ARM_ARCH_V6Z	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6Z)
#define ARM_ARCH_V6KZ	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6KZ)
#define ARM_ARCH_V6T2	ARM_FEATURE_CORE (ARM_AEXT_V6T2, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V6KT2	ARM_FEATURE_CORE (ARM_AEXT_V6KT2, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V6ZT2	ARM_FEATURE_CORE (ARM_AEXT_V6ZT2, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V6KZT2	ARM_FEATURE_CORE (ARM_AEXT_V6KZT2, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V6M	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6M)
#define ARM_ARCH_V6SM	ARM_FEATURE_CORE_LOW (ARM_AEXT_V6SM)
#define ARM_ARCH_V7	ARM_FEATURE_CORE (ARM_AEXT_V7, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V7A	ARM_FEATURE_CORE (ARM_AEXT_V7A, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V7VE	ARM_FEATURE_CORE (ARM_AEXT_V7VE, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V7R	ARM_FEATURE_CORE (ARM_AEXT_V7R, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V7M	ARM_FEATURE_CORE (ARM_AEXT_V7M, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V7EM	ARM_FEATURE_CORE (ARM_AEXT_V7EM, ARM_EXT2_V6T2_V8M)
#define ARM_ARCH_V8A	ARM_FEATURE_CORE (ARM_AEXT_V8A, ARM_AEXT2_V8A)
#define ARM_ARCH_V8A_CRC ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8A, \
				      CRC_EXT_ARMV8)
#define ARM_ARCH_V8_1A	ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_1A,	\
				     CRC_EXT_ARMV8 | FPU_NEON_EXT_RDMA)
#define ARM_ARCH_V8_2A	ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_2A,	\
				     CRC_EXT_ARMV8 | FPU_NEON_EXT_RDMA)
#define ARM_ARCH_V8_3A	ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_3A,	\
				     CRC_EXT_ARMV8 | FPU_NEON_EXT_RDMA)
#define ARM_ARCH_V8M_BASE ARM_FEATURE_CORE (ARM_AEXT_V8M_BASE, ARM_AEXT2_V8M)
#define ARM_ARCH_V8M_MAIN ARM_FEATURE_CORE (ARM_AEXT_V8M_MAIN, \
					    ARM_AEXT2_V8M_MAIN)
#define ARM_ARCH_V8M_MAIN_DSP ARM_FEATURE_CORE (ARM_AEXT_V8M_MAIN_DSP, \
						ARM_AEXT2_V8M_MAIN_DSP)

/* Some useful combinations:  */
#define ARM_ARCH_NONE	ARM_FEATURE_LOW (0, 0)
#define FPU_NONE	ARM_FEATURE_LOW (0, 0)
#define ARM_ANY		ARM_FEATURE (-1, -1, 0)	/* Any basic core.  */
#define ARM_FEATURE_ALL	ARM_FEATURE (-1, -1, -1)/* All CPU and FPU features.  */
#define FPU_ANY_HARD	ARM_FEATURE_COPROC (FPU_FPA | FPU_VFP_HARD | FPU_MAVERICK)
/* Extensions containing some Thumb-2 instructions.  If any is present, Thumb
   ISA is Thumb-2.  */
#define ARM_ARCH_THUMB2 ARM_FEATURE_CORE (ARM_EXT_V6T2 | ARM_EXT_V7	\
					  | ARM_EXT_DIV | ARM_EXT_V8,	\
					  ARM_EXT2_ATOMICS | ARM_EXT2_V6T2_V8M)
/* v7-a+sec.  */
#define ARM_ARCH_V7A_SEC \
  ARM_FEATURE_CORE (ARM_AEXT_V7A | ARM_EXT_SEC, ARM_EXT2_V6T2_V8M)
/* v7-a+mp+sec.  */
#define ARM_ARCH_V7A_MP_SEC \
  ARM_FEATURE_CORE (ARM_AEXT_V7A | ARM_EXT_MP | ARM_EXT_SEC, ARM_EXT2_V6T2_V8M)
/* v7-r+idiv.  */
#define ARM_ARCH_V7R_IDIV \
  ARM_FEATURE_CORE (ARM_AEXT_V7R | ARM_EXT_ADIV, ARM_EXT2_V6T2_V8M)
/* Features that are present in v6M and v6S-M but not other v6 cores.  */
#define ARM_ARCH_V6M_ONLY ARM_FEATURE_CORE_LOW (ARM_AEXT_V6M_ONLY)
/* v8-a+fp.  */
#define ARM_ARCH_V8A_FP	\
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8A, FPU_ARCH_VFP_ARMV8)
/* v8-a+simd (implies fp).  */
#define ARM_ARCH_V8A_SIMD \
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8A, FPU_ARCH_NEON_VFP_ARMV8)
/* v8-a+crypto (implies simd+fp).  */
#define ARM_ARCH_V8A_CRYPTOV1 \
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8A, FPU_ARCH_CRYPTO_NEON_VFP_ARMV8)

/* v8.1-a+fp.  */
#define ARM_ARCH_V8_1A_FP \
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_1A, FPU_ARCH_VFP_ARMV8)
/* v8.1-a+simd (implies fp).  */
#define ARM_ARCH_V8_1A_SIMD \
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_1A, FPU_ARCH_NEON_VFP_ARMV8_1)
/* v8.1-a+crypto (implies simd+fp).  */
#define ARM_ARCH_V8_1A_CRYPTOV1 \
  ARM_FEATURE (ARM_AEXT_V8A, ARM_AEXT2_V8_1A, FPU_ARCH_CRYPTO_NEON_VFP_ARMV8_1)


/* There are too many feature bits to fit in a single word, so use a
   structure.  For simplicity we put all core features in array CORE
   and everything else in the other.  All the bits in element core[0]
   have been occupied, so new feature should use bit in element core[1]
   and use macro ARM_FEATURE to initialize the feature set variable.  */
typedef struct
{
  unsigned long core[2];
  unsigned long coproc;
} arm_feature_set;

/* Test whether CPU and FEAT have any features in common.  */
#define ARM_CPU_HAS_FEATURE(CPU,FEAT) \
  (((CPU).core[0] & (FEAT).core[0]) != 0 \
   || ((CPU).core[1] & (FEAT).core[1]) != 0 \
   || ((CPU).coproc & (FEAT).coproc) != 0)

/* Tests whether the features of A are a subset of B.  */
#define ARM_FSET_CPU_SUBSET(A,B) \
  (((A).core[0] & (B).core[0]) == (A).core[0] \
   && ((A).core[1] & (B).core[1]) == (A).core[1] \
   && ((A).coproc & (B).coproc) == (A).coproc)

#define ARM_CPU_IS_ANY(CPU) \
  ((CPU).core[0] == ((arm_feature_set)ARM_ANY).core[0] \
   && (CPU).core[1] == ((arm_feature_set)ARM_ANY).core[1])

#define ARM_MERGE_FEATURE_SETS(TARG,F1,F2)	\
  do {						\
    (TARG).core[0] = (F1).core[0] | (F2).core[0];\
    (TARG).core[1] = (F1).core[1] | (F2).core[1];\
    (TARG).coproc = (F1).coproc | (F2).coproc;	\
  } while (0)

#define ARM_CLEAR_FEATURE(TARG,F1,F2)		\
  do {						\
    (TARG).core[0] = (F1).core[0] &~ (F2).core[0];\
    (TARG).core[1] = (F1).core[1] &~ (F2).core[1];\
    (TARG).coproc = (F1).coproc &~ (F2).coproc;	\
  } while (0)

#define ARM_FEATURE_COPY(F1, F2)		\
  do {						\
      (F1).core[0] = (F2).core[0];		\
      (F1).core[1] = (F2).core[1];		\
      (F1).coproc = (F2).coproc;		\
  } while (0)

#define ARM_FEATURE_EQUAL(T1,T2)		\
  ((T1).core[0] == (T2).core[0]			\
   && (T1).core[1] == (T2).core[1]		\
   && (T1).coproc == (T2).coproc)

#define ARM_FEATURE_ZERO(T)			\
  ((T).core[0] == 0 && (T).core[1] == 0 && (T).coproc == 0)

#define ARM_FEATURE_CORE_EQUAL(T1, T2)		\
  ((T1).core[0] == (T2).core[0] && (T1).core[1] == (T2).core[1])

#define ARM_FEATURE_LOW(core, coproc) {{(core), 0}, (coproc)}
#define ARM_FEATURE_CORE(core1, core2) {{(core1), (core2)}, 0}
#define ARM_FEATURE_CORE_LOW(core) {{(core), 0}, 0}
#define ARM_FEATURE_CORE_HIGH(core) {{0, (core)}, 0}
#define ARM_FEATURE_COPROC(coproc) {{0, 0}, (coproc)}
#define ARM_FEATURE(core1, core2, coproc) {{(core1), (core2)}, (coproc)}
