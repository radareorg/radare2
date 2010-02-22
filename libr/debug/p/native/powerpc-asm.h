/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
#ifndef	_PPC_ASM_H_
#define	_PPC_ASM_H_

#define	__ASMNL__	@
#define STRINGD .ascii

#ifdef ASSEMBLER


#define br0 0

#define ARG0 r3
#define ARG1 r4
#define ARG2 r5
#define ARG3 r6
#define ARG4 r7
#define ARG5 r8
#define ARG6 r9
#define ARG7 r10

#define tmp0	r0	/* Temporary GPR remapping (603e specific) */
#define tmp1	r1
#define tmp2	r2
#define tmp3	r3

/* SPR registers */

#define mq		0		/* MQ register for 601 emulation */
#define rtcu	4		/* RTCU - upper word of RTC for 601 emulation */
#define rtcl	5		/* RTCL - lower word of RTC for 601 emulation */
#define dsisr	18
#define ppcDAR	19
#define ppcdar	19
#define dar		19
#define SDR1	25
#define sdr1	25
#define srr0	26
#define srr1	27
#define vrsave	256		/* Vector Register save */
#define sprg0	272
#define sprg1	273
#define sprg2	274
#define sprg3	275
#define scomc	276
#define scomd	277
#define pvr		287

#define IBAT0U	528
#define IBAT0L	529
#define IBAT1U	530
#define IBAT1L	531
#define IBAT2U	532
#define IBAT2L	533
#define IBAT3U	534
#define IBAT3L	535
#define ibat0u	528
#define ibat0l	529
#define ibat1u	530
#define ibat1l	531
#define ibat2u	532
#define ibat2l	533
#define ibat3u	534
#define ibat3l	535

#define DBAT0U	536
#define DBAT0L	537
#define DBAT1U	538
#define DBAT1L	539
#define DBAT2U	540
#define DBAT2L	541
#define DBAT3U	542
#define DBAT3L	543
#define dbat0u	536
#define dbat0l	537
#define dbat1u	538
#define dbat1l	539
#define dbat2u	540
#define dbat2l	541
#define dbat3u	542
#define dbat3l	543

#define ummcr2	928		/* Performance monitor control */
#define upmc5   929     /* Performance monitor counter */
#define upmc6   930     /* Performance monitor counter */
#define ubamr	935		/* Performance monitor mask */
#define ummcr0	936		/* Performance monitor control */
#define upmc1	937		/* Performance monitor counter */
#define upmc2	938		/* Performance monitor counter */
#define usia	939		/* User sampled instruction address */
#define ummcr1	940		/* Performance monitor control */
#define upmc3	941		/* Performance monitor counter */
#define upmc4	942		/* Performance monitor counter */
#define usda	943		/* User sampled data address */
#define mmcr2	944		/* Performance monitor control */
#define pmc5    945     /* Performance monitor counter */
#define pmc6    946     /* Performance monitor counter */
#define bamr	951		/* Performance monitor mask */
#define mmcr0	952
#define pmc1	953
#define	pmc2	954
#define	sia		955
#define	mmcr1	956
#define	pmc3	957
#define	pmc4	958
#define	sda		959		/* Sampled data address */
#define dmiss	976		/* ea that missed */
#define trig0	976		
#define dcmp	977		/* compare value for the va that missed */
#define trig1	977		
#define hash1	978		/* pointer to first hash pteg */
#define trig2	978		
#define	hash2	979		/* pointer to second hash pteg */
#define imiss	980		/* ea that missed */
#define tlbmiss	980		/* ea that missed */
#define icmp	981		/* compare value for the va that missed */
#define ptehi	981		/* compare value for the va that missed */
#define rpa		982		/* required physical address register */
#define ptelo	982		/* required physical address register */
#define l3pdet	984		/* l3pdet */

#define HID0	1008	/* Checkstop and misc enables */
#define hid0	1008	/* Checkstop and misc enables */
#define HID1	1009	/* Clock configuration */
#define hid1	1009	/* Clock configuration */
#define HID2	1016	/* Other processor controls */
#define hid2	1016	/* Other processor controls */
#define iabr	1010	/* Instruction address breakpoint register */
#define ictrl	1011	/* Instruction Cache Control */
#define ldstdb	1012	/* Load/Store Debug */
#define hid4	1012	/* Misc stuff */
#define dabr	1013	/* Data address breakpoint register */
#define msscr0	1014	/* Memory subsystem control */
#define hid5	1014	/* Misc stuff */
#define msscr1	1015	/* Memory subsystem debug */
#define msssr0	1015	/* Memory Subsystem Status */
#define ldstcr	1016	/* Load/Store Status/Control */
#define l2cr2	1016	/* L2 Cache control 2 */
#define l2cr	1017	/* L2 Cache control */
#define l3cr	1018	/* L3 Cache control */
#define ictc	1019	/* I-cache throttling control */
#define thrm1	1020	/* Thermal management 1 */
#define thrm2	1021	/* Thermal management 2 */
#define thrm3	1022	/* Thermal management 3 */
#define pir		1023	/* Processor ID Register */


/* SPR registers (64-bit, PPC970 specific) */

#define scomc_gp	276
#define scomd_gp	277

#define hsprg0		304
#define hsprg1		305
#define hdec		310
#define hior		311
#define rmor		312
#define hrmor		313
#define hsrr0		314
#define hsrr1		315
#define lpcr		318
#define lpidr		319

#define ummcra_gp	770
#define upmc1_gp	771
#define upmc2_gp	772
#define upmc3_gp	773
#define upmc4_gp	774
#define upmc5_gp	775
#define upmc6_gp	776
#define upmc7_gp	777
#define upmc8_gp	778
#define ummcr0_gp	779
#define usiar_gp	780
#define usdar_gp	781
#define ummcr1_gp	782
#define uimc_gp		783

#define mmcra_gp	786
#define pmc1_gp		787
#define pmc2_gp		788
#define pmc3_gp		789
#define pmc4_gp		790
#define pmc5_gp		791
#define pmc6_gp		792
#define pmc7_gp		793
#define pmc8_gp		794
#define mmcr0_gp	795
#define siar_gp		796
#define sdar_gp		797
#define mmcr1_gp	798
#define imc_gp		799

#define trig0_gp	976		
#define trig1_gp	977		
#define trig2_gp	978		

#define dabrx		1015

;	hid0 bits
#define emcp	0
#define emcpm	0x80000000
#define dbp		1
#define dbpm	0x40000000
#define eba		2
#define ebam	0x20000000
#define ebd		3
#define ebdm	0x10000000
#define sbclk	4
#define sbclkm	0x08000000
#define eclk	6
#define eclkm	0x02000000
#define par		7
#define parm	0x01000000
#define sten	7
#define stenm	0x01000000
#define dnap	7
#define dnapm	0x01000000
#define doze	8
#define dozem	0x00800000
#define nap		9
#define napm	0x00400000
#define sleep	10
#define sleepm	0x00200000
#define dpm		11
#define dpmm	0x00100000
#define riseg	12
#define risegm	0x00080000
#define eiec	13
#define eiecm	0x00040000
#define mum		14
#define mumm	0x00020000
#define nhr		15
#define nhrm	0x00010000
#define ice		16
#define icem	0x00008000
#define dce		17
#define dcem	0x00004000
#define ilock	18
#define ilockm	0x00002000
#define dlock	19
#define dlockm	0x00001000
#define exttben	19
#define icfi	20
#define icfim	0x00000800
#define dcfi	21
#define dcfim	0x00000400
#define spd		22
#define spdm	0x00000200
#define hdice	23
#define hdicem	0x00000100
#define sge		24
#define sgem	0x00000080
#define dcfa	25
#define dcfam	0x00000040
#define btic	26
#define bticm	0x00000020
#define lrstk	27
#define lrstkm	0x00000010
#define abe		28
#define abem	0x00000008
#define fold	28
#define foldm	0x00000008
#define bht		29
#define bhtm	0x00000004
#define nopdst	30
#define nopdstm	0x00000002
#define nopti	31
#define noptim	0x00000001

;	hid1 bits
#define hid1pcem	0xF8000000
#define hid1prem	0x06000000
#define hid1dfs0	8
#define hid1dfs0m	0x00800000
#define hid1dfs1	9
#define hid1dfs1m	0x00400000
#define hid1pi0		14
#define hid1pi0m	0x00020000
#define hid1FCPErr	14
#define hid1ps		15
#define hid1FCD0PErr	15
#define hid1psm		0x00010000
#define hid1pc0		0x0000F800
#define hid1pr0		0x00000600
#define hid1pc1		0x000000F8
#define hid1pc0		0x0000F800
#define hid1pr1		0x00000006
#define hid1FCD1PErr	16
#define hid1FIERATErr	17

;	hid2 bits
#define hid2vmin	18
#define hid2vminm	0x00002000

;	msscr0 bits
#define shden	0
#define shdenm	0x80000000
#define shden3	1
#define shdenm3	0x40000000
#define l1intvs	2	
#define l1intve	4	
#define l1intvb	0x38000000	
#define l2intvs	5	
#define l2intve	7	
#define l2intvb	0x07000000	
#define dl1hwf	8
#define dl1hwfm	0x00800000
#define dbsiz	9
#define dbsizm	0x00400000
#define emode	10
#define emodem	0x00200000
#define abgd	11
#define abgdm	0x00100000
#define tfsts	24
#define tfste	25
#define tfstm	0x000000C0
#define	l2pfes	30
#define	l2pfee	31
#define	l2pfem	0x00000003

;	msscr1 bits
#define cqd		15
#define cqdm	0x00010000
#define csqs	1
#define csqe	2
#define csqm	0x60000000

;	msssr1 bits - 7450
#define vgL2PARA	0
#define vgL3PARA	1
#define vgL2COQEL	2
#define vgL3COQEL	3
#define vgL2CTR		4
#define vgL3CTR		5
#define vgL2COQR	6
#define vgL3COQR	7
#define vgLMQ		8
#define vgSMC		9
#define vgSNP		10
#define vgBIU		11
#define vgSMCE		12
#define vgL2TAG		13
#define vgL2DAT		14
#define vgL3TAG		15
#define vgL3DAT		16
#define vgAPE		17
#define vgDPE		18
#define vgTEA		19

;	srr1 bits
#define icmck	1
#define icmckm	0x40000000
#define dcmck	2
#define dcmckm	0x20000000
#define l2mck	3
#define l2mckm	0x10000000
#define tlbmck	4
#define tlbmckm	0x08000000
#define brmck	5
#define brmckm	0x04000000
#define othmck	10
#define othmckm	0x00200000
#define l2dpmck	11
#define l2dpmckm	0x00100000
#define mcpmck	12
#define mcpmckm	0x00080000
#define teamck	13
#define teamckm	0x00040000
#define dpmck	14
#define dpmckm	0x00020000
#define apmck	15
#define apmckm	0x00010000

#define mckIFUE	42
#define mckLDST	43
#define mckXCs	44
#define mckXCe	45
#define mckNoErr	0
#define mckIFSLBPE	1
#define mckIFTLBPE	2
#define mckIFTLBUE	3

;	dsisr bits
#define mckUEdfr	16
#define mckUETwDfr	17
#define mckL1DCPE	18
#define	mckL1DTPE	19
#define	mckDEPE		20
#define mckTLBPE	21
#define mckSLBPE	23

;	Async MCK source
#define AsyMCKSrc 0x0226
#define AsyMCKRSrc 0x0227
#define AsyMCKext 0
#define AsyMCKfir 1
#define AsyMCKhri 2
#define AsyMCKdbg 3
#define AsyMCKncstp 4

;	Core FIR
#define cFIR 0x0300
#define cFIRrst 0x0310
#define cFIRICachePE 0
#define cFIRITagPE0 1
#define cFIRITagPE1 2
#define cFIRIEratPE 3
#define cFIRIFUL2UE 4
#define cFIRIFUCS 5
#define cFIRDCachePE 6
#define cFIRDTagPE 7
#define cFIRDEratPE 8
#define cFIRTLBPE 9
#define cFIRSLBPE 10
#define cFIRSL2UE 11

;	Core Error Inject
#define CoreErrI 0x0350
#define CoreIFU 0
#define CoreLSU 1
#define CoreRate0 2
#define CoreRate1 3
#define CoreOnce 0
#define CoreSolid 2
#define CorePulse 3

;	L2 FIR
#define l2FIR 0x0400
#define l2FIRrst 0x0410

;	Bus FIR
#define busFIR 0x0A00
#define busFIRrst 0x0A10

; PowerTune
#define PowerTuneControlReg	0x0AA001
#define PowerTuneStatusReg	0x408001

;	HID4
#define hid4RMCI 23
#define hid4FAlgn 24
#define hid4DisPF 25
#define hid4ResPF 26
#define hid4EnSPTW 27
#define hid4L1DCFI 28
#define hid4DisDERpg 31
#define hid4DisDCTpg 36
#define hid4DisDCpg 41
#define hid4DisTLBpg 48
#define hid4DisSLBpg 54
#define hid4MckEIEna 55

;	L2 cache control
#define l2e		0
#define l2em	0x80000000
#define l2pe	1
#define l2pem	0x40000000
#define l2siz	2
#define l2sizf	3
#define l2sizm	0x30000000
#define l2clk	4
#define l2clkf	6
#define l2clkm	0x0E000000
#define l2ram	7
#define l2ramf	8
#define l2ramm	0x01800000
#define l2do	9
#define l2dom	0x00400000
#define l2i		10
#define l2im	0x00200000
#define l2ctl	11
#define l2ctlm	0x00100000
#define l2ionly	11
#define l2ionlym	0x00100000
#define l2wt	12
#define l2wtm	0x00080000
#define l2ts	13
#define l2tsm	0x00040000
#define l2oh	14
#define l2ohf	15
#define l2ohm	0x00030000
#define l2donly	15
#define l2donlym	0x00010000
#define l2sl	16
#define l2slm	0x00008000
#define l2df	17
#define l2dfm	0x00004000
#define l2byp	18
#define l2bypm	0x00002000
#define l2fa	19
#define l2fam	0x00001000
#define l2hwf	20
#define l2hwfm	0x00000800
#define l2io	21
#define l2iom	0x00000400
#define l2clkstp	22
#define	l2clkstpm	0x00000200
#define l2dro	23
#define l2drom	0x00000100 
#define l2ctr	24
#define l2ctrf	30
#define l2ctrm	0x000000FE
#define	l2ip	31
#define l2ipm	0x00000001

;	L3 cache control
#define l3e		0
#define l3em	0x80000000
#define l3pe	1
#define l3pem	0x40000000
#define l3siz	3
#define l3sizm	0x10000000
#define l3clken	4
#define l3clkenm	0x08000000
#define l3dx	5
#define l3dxm	0x04000000
#define l3clk	6
#define l3clkf	8
#define l3clkm	0x03800000
#define l3io	9
#define l3iom	0x00400000
#define l3spo	13
#define l3spom	0x00040000
#define l3cksp	14
#define l3ckspf	15
#define l3ckspm	0x00030000
#define l3psp	16
#define l3pspf	18
#define l3pspm	0x0000E000
#define l3rep	19
#define l3repm	0x00001000
#define l3hwf	20
#define l3hwfm	0x00000800
#define l3i		21
#define l3im	0x00000400
#define l3rt	22
#define l3rtf	23
#define	l3rtm	0x00000300
#define l3dro	23
#define l3drom	0x00000100 
#define l3cya	24
#define l3cyam	0x00000080
#define l3donly	25
#define l3donlym	0x00000040
#define l3dmem	29
#define l3dmemm	0x00000004
#define l3dmsiz	31
#define l3dmsizm	0x00000001

#define	thrmtin		0
#define	thrmtinm	0x80000000
#define	thrmtiv		1
#define thrmtivm	0x40000000
#define thrmthrs	2
#define thrmthre	8
#define thrmthrm	0x3F800000
#define thrmtid		29
#define thrmtidm	0x00000004
#define thrmtie		30
#define thrmtiem	0x00000002
#define thrmv		31
#define thrmvm		0x00000001

#define thrmsitvs	15
#define thrmsitve	30
#define thrmsitvm	0x0001FFFE
#define thrme		31
#define thrmem		0x00000001

#define ictcfib		23
#define ictcfie		30
#define ictcfim		0x000001FE
#define ictce		31
#define ictcem		0x00000001

#define cr0_lt	0
#define cr0_gt	1
#define cr0_eq	2
#define cr0_so	3
#define cr0_un	3
#define cr1_lt	4
#define cr1_gt	5
#define cr1_eq	6
#define cr1_so	7
#define cr1_un	7
#define cr2_lt	8
#define cr2_gt	9
#define cr2_eq	10
#define cr2_so	11
#define cr2_un	11
#define cr3_lt	12
#define cr3_gt	13
#define cr3_eq	14
#define cr3_so	15
#define cr3_un	15
#define cr4_lt	16
#define cr4_gt	17
#define cr4_eq	18
#define cr4_so	19
#define cr4_un	19
#define cr5_lt	20
#define cr5_gt	21
#define cr5_eq	22
#define cr5_so	23
#define cr5_un	23
#define cr6_lt	24
#define cr6_gt	25
#define cr6_eq	26
#define cr6_so	27
#define cr6_un	27
#define cr7_lt	28
#define cr7_gt	29
#define cr7_eq	30
#define cr7_so	31
#define cr7_un	31

#define slbESID	36
#define slbKey	52
#define slbIndex 52
#define slbV	36
#define slbVm	0x08000000
#define slbCnt	64

/*
 * Macros to access high and low word values of an address
 */

#define	HIGH_CADDR(x)	ha16(x)
#define	HIGH_ADDR(x)	hi16(x)
#define	LOW_ADDR(x)	lo16(x)

#endif	/* ASSEMBLER */

/*	GUS Mode Register */
#define GUSModeReg 0x0430
#define GUSMdmapen 0x00008000
#define GUSMstgtdis 0x00000080
#define GUSMstgttim 0x00000038
#define GUSMstgttoff 0x00000004

/* Tags are placed before Immediately Following Code (IFC) for the debugger
 * to be able to deduce where to find various registers when backtracing
 * 
 * We only define the values as we use them, see SVR4 ABI PowerPc Supplement
 * for more details (defined in ELF spec).
 */

#define TAG_NO_FRAME_USED 0x00000000

/* (should use genassym to get these offsets) */

#define FM_BACKPTR 0
#define	FM_CR_SAVE 4
#define FM_LR_SAVE 8 /* MacOSX is NOT following the ABI at the moment.. */
#define FM_SIZE    64   /* minimum frame contents, backptr and LR save. Make sure it is quadaligned */
#define FM_ARG0	   56
#define FM_ALIGN(l) ((l+15)&-16)
#define	PK_SYSCALL_BEGIN	0x7000


/* redzone is the area under the stack pointer which must be preserved
 * when taking a trap, interrupt etc.
 */
#define FM_REDZONE 224				/* is ((32-14+1)*4) */

#define COPYIN_ARG0_OFFSET FM_ARG0

#ifdef	MACH_KERNEL
#include <mach_kdb.h>
#else	/* MACH_KERNEL */
#define MACH_KDB 0
#endif	/* MACH_KERNEL */

#define BREAKPOINT_TRAP tw	4,r4,r4

/* There is another definition of ALIGN for .c sources */
#ifndef __LANGUAGE_ASSEMBLY
#define ALIGN 4
#endif /* __LANGUAGE_ASSEMBLY */

#ifndef FALIGN
#define FALIGN 4 /* Align functions on words for now. Cachelines is better */
#endif

#define LB(x,n) n
#if	__STDC__
#define	LCL(x)	L ## x
#define EXT(x) _ ## x
#define LEXT(x) _ ## x ## :
#define LBc(x,n) n ## :
#define LBb(x,n) n ## b
#define LBf(x,n) n ## f
#else /* __STDC__ */
#define LCL(x) L/**/x
#define EXT(x) _/**/x
#define LEXT(x) _/**/x/**/:
#define LBc(x,n) n/**/:
#define LBb(x,n) n/**/b
#define LBf(x,n) n/**/f
#endif /* __STDC__ */

#define String	.asciz
#define Value	.word
#define Times(a,b) (a*b)
#define Divide(a,b) (a/b)

#define data16	.byte 0x66
#define addr16	.byte 0x67

#define MCOUNT

#define ELF_FUNC(x)
#define ELF_DATA(x)
#define ELF_SIZE(x,s)

#define	Entry(x,tag)	.text@.align FALIGN@ .globl EXT(x)@ LEXT(x)
#define	ENTRY(x,tag)	Entry(x,tag)@MCOUNT
#define	ENTRY2(x,y,tag)	.text@ .align FALIGN@ .globl EXT(x)@ .globl EXT(y)@ \
			LEXT(x)@ LEXT(y) @\
			MCOUNT
#if __STDC__
#define	ASENTRY(x) 	.globl x @ .align FALIGN; x ## @ MCOUNT
#else
#define	ASENTRY(x) 	.globl x @ .align FALIGN; x @ MCOUNT
#endif /* __STDC__ */
#define	DATA(x)		.globl EXT(x) @ .align ALIGN @ LEXT(x)


#define End(x)		ELF_SIZE(x,.-x)
#define END(x)		End(EXT(x))
#define ENDDATA(x)	END(x)
#define Enddata(x)	End(x)

/* These defines are here for .c files that wish to reference global symbols
 * within __asm__ statements. 
 */
#define CC_SYM_PREFIX "_"

#endif /* _PPC_ASM_H_ */
