#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "arm64dis.h"

#ifdef __cplusplus
using namespace arm64;
#define restrict __restrict
#endif

//bitfield extraction macros
#define BIT(n) ( 1<<(n) )
#define BIT_MASK(len) ( BIT(len)-1 )
#define BF_GET(y, start, len) ( ((y)>>(start)) & BIT_MASK(len) )
#define BF_GETI(start, len) (BF_GET(instructionValue, start, len))

static const char* OperationString[] = {
	"UNDEFINED",
	"abs",
	"adc",
	"adcs",
	"add",
	"addg", //Added for MTE
	"addhn",
	"addhn2",
	"addp",
	"adds",
	"addv",
	"adr",
	"adrp",
	"aesd",
	"aese",
	"aesimc",
	"aesmc",
	"and",
	"ands",
	"asr",
	"at",
	"autda", //Added for 8.3
	"autdb", //Added for 8.3
	"autdza", //Added for 8.3
	"autdzb", //Added for 8.3
	"autia", //Added for 8.3
	"autia1716", //Added for 8.3
	"autiasp", //Added for 8.3
	"autiaz", //Added for 8.3
	"autib", //Added for 8.3
	"autib1716", //Added for 8.3
	"autibsp", //Added for 8.3
	"autibz", //Added for 8.3
	"autiza", //Added for 8.3
	"autizb", //Added for 8.3
	"b",
	"b.al",
	"b.cc",
	"b.cs",
	"b.eq",
	"bfi",
	"bfm",
	"bfxil",
	"b.ge",
	"b.gt",
	"b.hi",
	"bic",
	"bics",
	"bif",
	"bit",
	"bl",
	"b.le",
	"blr",
	"blraa",
	"blraaz",
	"blrab",
	"blrabz",
	"b.ls",
	"b.lt",
	"b.mi",
	"b.ne",
	"b.nv",
	"b.pl",
	"br",
	"braa",
	"braaz",
	"brab",
	"brabz",
	"brk",
	"bsl",
	"b.vc",
	"b.vs",
	"cbnz",
	"cbz",
	"ccmn",
	"ccmp",
	"cinc",
	"cinv",
	"clrex",
	"cls",
	"clz",
	"cmeq",
	"cmge",
	"cmgt",
	"cmhi",
	"cmhs",
	"cmle",
	"cmlt",
	"cmn",
	"cmp",
	"cmpp", //Added for MTE
	"cmtst",
	"cneg",
	"cnt",
	"crc32b",
	"crc32cb",
	"crc32ch",
	"crc32cw",
	"crc32cx",
	"crc32h",
	"crc32w",
	"crc32x",
	"csel",
	"cset",
	"csetm",
	"csinc",
	"csinv",
	"csneg",
	"dc",
	"dcps1",
	"dcps2",
	"dcps3",
	"dmb",
	"drps",
	"dsb",
	"dup",
	"eon",
	"eor",
	"eret",
	"eretaa",
	"eretab",
	"esb", //Added for 8.2
	"ext",
	"extr",
	"fabd",
	"fabs",
	"facge",
	"facgt",
	"fadd",
	"faddp",
	"fccmp",
	"fccmpe",
	"fcmeq",
	"fcmge",
	"fcmgt",
	"fcmle",
	"fcmlt",
	"fcmp",
	"fcmpe",
	"fcsel",
	"fctns",
	"fctnu",
	"fcvt",
	"fcvtas",
	"fcvtau",
	"fcvtl",
	"fcvtl2",
	"fcvtms",
	"fcvtmu",
	"fcvtn",
	"fcvtn2",
	"fcvtns",
	"fcvtnu",
	"fcvtps",
	"fcvtpu",
	"fcvtxn",
	"fcvtxn2",
	"fcvtzs",
	"fcvtzu",
	"fdiv",
	"fmadd",
	"fmax",
	"fmaxnm",
	"fmaxnmp",
	"fmaxnmv",
	"fmaxp",
	"fmaxv",
	"fmin",
	"fminnm",
	"fminnmp",
	"fminnmv",
	"fminp",
	"fminv",
	"fmla",
	"fmls",
	"fmov",
	"fmsub",
	"fmul",
	"fmulx",
	"fneg",
	"fnmadd",
	"fnmsub",
	"fnmul",
	"frecpe",
	"frecps",
	"frecpx",
	"frinta",
	"frinti",
	"frintm",
	"frintn",
	"frintp",
	"frintx",
	"frintz",
	"frsqrte",
	"frsqrts",
	"fsqrt",
	"fsub",
	"gmi", //Added for MTE
	"hint",
	"hlt",
	"hvc",
	"ic",
	"ins",
	"irg", //Added for MTE
	"isb",
	"ld1",
	"ld1r",
	"ld2",
	"ld2r",
	"ld3",
	"ld3r",
	"ld4",
	"ld4r",
	"ldar",
	"ldarb",
	"ldarh",
	"ldaxp",
	"ldaxr",
	"ldaxrb",
	"ldaxrh",
	"ldg", //Added for MTE
	"ldgm", //Added for MTE
	"ldnp",
	"ldp",
	"ldpsw",
	"ldr",
	"ldraa",
	"ldrab",
	"ldrb",
	"ldrh",
	"ldrsb",
	"ldrsh",
	"ldrsw",
	"ldtr",
	"ldtrb",
	"ldtrh",
	"ldtrsb",
	"ldtrsh",
	"ldtrsw",
	"ldur",
	"ldurb",
	"ldurh",
	"ldursb",
	"ldursh",
	"ldursw",
	"ldxp",
	"ldxr",
	"ldxrb",
	"ldxrh",
	"lsl",
	"lsr",
	"madd",
	"mla",
	"mls",
	"mneg",
	"mov",
	"movi",
	"movk",
	"movn",
	"movz",
	"mrs",
	"msr",
	"msub",
	"mul",
	"mvn",
	"mvni",
	"neg",
	"negs",
	"ngc",
	"ngcs",
	"nop",
	"not",
	"orn",
	"orr",
	"pacda", //Added for 8.3
	"pacdb", //Added for 8.3
	"pacdza", //Added for 8.3
	"pacdzb", //Added for 8.3
	"pacia", //Added for 8.3
	"pacia1716", //Added for 8.3
	"paciasp", //Added for 8.3
	"paciaz", //Added for 8.3
	"pacib", //Added for 8.3
	"pacib1716", //Added for 8.3
	"pacibsp", //Added for 8.3
	"pacibz", //Added for 8.3
	"paciza", //Added for 8.3
	"pacizb", //Added for 8.3
	"pmul",
	"pmull",
	"pmull2",
	"prfm",
	"prfum",
	"psb", //Added for 8.2
	"raddhn",
	"raddhn2",
	"rbit",
	"ret",
	"retaa", //Added for 8.3
	"retab", //Added for 8.3
	"rev",
	"rev16",
	"rev32",
	"rev64",
	"ror",
	"rshrn",
	"rshrn2",
	"rsubhn",
	"rsubhn2",
	"saba",
	"sabal",
	"sabal2",
	"sabd",
	"sabdl",
	"sabdl2",
	"sadalp",
	"saddl",
	"saddl2",
	"saddlp",
	"saddlv",
	"saddw",
	"saddw2",
	"sbc",
	"sbcs",
	"sbfiz",
	"sbfm",
	"sbfx",
	"scvtf",
	"sdiv",
	"sev",
	"sevl",
	"sha1c",
	"sha1h",
	"sha1m",
	"sha1p",
	"sha1su0",
	"sha1su1",
	"sha256h",
	"sha256h2",
	"sha256su0",
	"sha256su1",
	"shadd",
	"shl",
	"shll",
	"shll2",
	"shrn",
	"shrn2",
	"shsub",
	"sli",
	"smaddl",
	"smax",
	"smaxp",
	"smaxv",
	"smc",
	"smin",
	"sminp",
	"sminv",
	"smlal",
	"smlal2",
	"smlsl",
	"smlsl2",
	"smnegl",
	"smov",
	"smsubl",
	"smulh",
	"smull",
	"smull2",
	"sqabs",
	"sqadd",
	"sqdmlal",
	"sqdmlal2",
	"sqdmlsl",
	"sqdmlsl2",
	"sqdmulh",
	"sqdmull",
	"sqdmull2",
	"sqneg",
	"sqrdmulh",
	"sqrshl",
	"sqrshrn",
	"sqrshrn2",
	"sqrshrun",
	"sqrshrun2",
	"sqshl",
	"sqshlu",
	"sqshrn",
	"sqshrn2",
	"sqshrun",
	"sqshrun2",
	"sqsub",
	"sqxtn",
	"sqxtn2",
	"sqxtun",
	"sqxtun2",
	"srhadd",
	"sri",
	"srshl",
	"srshr",
	"srsra",
	"sshl",
	"sshll",
	"sshll2",
	"sshr",
	"ssra",
	"ssubl",
	"ssubl2",
	"ssubw",
	"ssubw2",
	"st1",
	"st2",
	"st2g", //Added for MTE
	"st3",
	"st4",
	"stg", //Added for MTE
	"stgm", //Added for MTE
	"stgp", //Added for MTE
	"stlr",
	"stlrb",
	"stlrh",
	"stlxp",
	"stlxr",
	"stlxrb",
	"stlxrh",
	"stnp",
	"stp",
	"str",
	"strb",
	"strh",
	"sttr",
	"sttrb",
	"sttrh",
	"stur",
	"sturb",
	"sturh",
	"stxp",
	"stxr",
	"stxrb",
	"stxrh",
	"stz2g", //Added for MTE
	"stzg", //Added for MTE
	"stzgm", //Added for MTE
	"sub",
	"subg", //Added for MTE
	"subhn",
	"subhn2",
	"subp", //Added for MTE
	"subps", //Added for MTE
	"subs",
	"suqadd",
	"svc",
	"sxtb",
	"sxth",
	"sxtw",
	"sys",
	"sysl",
	"tbl",
	"tbnz",
	"tbx",
	"tbz",
	"tlbi",
	"trn1",
	"trn2",
	"tst",
	"uaba",
	"uabal",
	"uabal2",
	"uabd",
	"uabdl",
	"uabdl2",
	"uadalp",
	"uaddl",
	"uaddl2",
	"uaddlp",
	"uaddlv",
	"uaddw",
	"uaddw2",
	"ubfiz",
	"ubfm",
	"ubfx",
	"ucvtf",
	"udiv",
	"uhadd",
	"uhsub",
	"umaddl",
	"umax",
	"umaxp",
	"umaxv",
	"umin",
	"uminp",
	"uminv",
	"umlal",
	"umlal2",
	"umlsl",
	"umlsl2",
	"umnegl",
	"umov",
	"umsubl",
	"umulh",
	"umull",
	"umull2",
	"uqadd",
	"uqrshl",
	"uqrshrn",
	"uqrshrn2",
	"uqshl",
	"uqshrn",
	"uqshrn2",
	"uqsub",
	"uqxtn",
	"uqxtn2",
	"urecpe",
	"urhadd",
	"urshl",
	"urshr",
	"ursqrte",
	"ursra",
	"ushl",
	"ushll",
	"ushll2",
	"ushr",
	"usqadd",
	"usra",
	"usubl",
	"usubl2",
	"usubw",
	"usubw2",
	"uxtb",
	"uxth",
	"uzp1",
	"uzp2",
	"wfe",
	"wfi",
	"xpacd",
	"xpaci",
	"xpaclri",
	"xtn",
	"xtn2",
	"yield",
	"zip1",
	"zip2",
	"END_OPERATION_LIST" //NOT AN INSTRUCTION
};

static const char* SystemRegisterString[] = {
	"NONE",
	"actlr_el1",
	"actlr_el2",
	"actlr_el3",
	"afsr0_el1",
	"afsr1_el2",
	"afsr0_el2",
	"afsr0_el3",
	"afsr1_el1",
	"afsr1_el3",
	"aidr_el1",
	"alle1",
	"alle1is",
	"alle2",
	"alle2is",
	"alle3",
	"alle3is",
	"amair_el1",
	"amair_el2",
	"amair_el3",
	"aside1",
	"aside1is",
	"ccsidr_el1",
	"cisw",
	"civac",
	"clidr_el1",
	"cntfrq_el0",
	"cnthctl_el2",
	"cnthp_ctl_el2",
	"cnthp_cval_el2",
	"cnthp_tval_el2",
	"cntkctl_el1",
	"cntpct_el0",
	"cntps_ctl_el1",
	"cntps_cval_el1",
	"cntps_tval_el1",
	"cntp_ctl_el0",
	"cntp_cval_el0",
	"cntp_tval_el0",
	"cntvct_el0",
	"cntv_ctl_el0",
	"cntv_cval_el0",
	"cntv_tval_el0",
	"contextidr_el1",
	"cpacr_el1",
	"cptr_el2",
	"cptr_el3",
	"csselr_el1",
	"csw",
	"ctr_el0",
	"cvac",
	"cvau",
	"dacr32_el2",
	"daifclr",
	"daifset",
	"dbgauthstatus_el1",
	"dbgclaimclr_el1",
	"dbgclaimset_el1",
	"dbgbcr0_el1",
	"dbgbcr10_el1",
	"dbgbcr11_el1",
	"dbgbcr12_el1",
	"dbgbcr13_el1",
	"dbgbcr14_el1",
	"dbgbcr15_el1",
	"dbgbcr1_el1",
	"dbgbcr2_el1",
	"dbgbcr3_el1",
	"dbgbcr4_el1",
	"dbgbcr5_el1",
	"dbgbcr6_el1",
	"dbgbcr7_el1",
	"dbgbcr8_el1",
	"dbgbcr9_el1",
	"dbgdtrrx_el0",
	"dbgdtrtx_el0",
	"dbgdtr_el0",
	"dbgprcr_el1",
	"dbgvcr32_el2",
	"dbgbvr0_el1",
	"dbgbvr10_el1",
	"dbgbvr11_el1",
	"dbgbvr12_el1",
	"dbgbvr13_el1",
	"dbgbvr14_el1",
	"dbgbvr15_el1",
	"dbgbvr1_el1",
	"dbgbvr2_el1",
	"dbgbvr3_el1",
	"dbgbvr4_el1",
	"dbgbvr5_el1",
	"dbgbvr6_el1",
	"dbgbvr7_el1",
	"dbgbvr8_el1",
	"dbgbvr9_el1",
	"dbgwcr0_el1",
	"dbgwcr10_el1",
	"dbgwcr11_el1",
	"dbgwcr12_el1",
	"dbgwcr13_el1",
	"dbgwcr14_el1",
	"dbgwcr15_el1",
	"dbgwcr1_el1",
	"dbgwcr2_el1",
	"dbgwcr3_el1",
	"dbgwcr4_el1",
	"dbgwcr5_el1",
	"dbgwcr6_el1",
	"dbgwcr7_el1",
	"dbgwcr8_el1",
	"dbgwcr9_el1",
	"dbgwvr0_el1",
	"dbgwvr10_el1",
	"dbgwvr11_el1",
	"dbgwvr12_el1",
	"dbgwvr13_el1",
	"dbgwvr14_el1",
	"dbgwvr15_el1",
	"dbgwvr1_el1",
	"dbgwvr2_el1",
	"dbgwvr3_el1",
	"dbgwvr4_el1",
	"dbgwvr5_el1",
	"dbgwvr6_el1",
	"dbgwvr7_el1",
	"dbgwvr8_el1",
	"dbgwvr9_el1",
	"dczid_el0",
	"el1",
	"esr_el1",
	"esr_el2",
	"esr_el3",
	"far_el1",
	"far_el2",
	"far_el3",
	"hacr_el2",
	"hcr_el2",
	"hpfar_el2",
	"hstr_el2",
	"iallu",
	"ivau",
	"ialluis",
	"id_aa64dfr0_el1",
	"id_aa64isar0_el1",
	"id_aa64isar1_el1",
	"id_aa64mmfr0_el1",
	"id_aa64mmfr1_el1",
	"id_aa64pfr0_el1",
	"id_aa64pfr1_el1",
	"ipas2e1is",
	"ipas2le1is",
	"ipas2e1",
	"ipas2le1",
	"isw",
	"ivac",
	"mair_el1",
	"mair_el2",
	"mair_el3",
	"mdccint_el1",
	"mdccsr_el0",
	"mdcr_el2",
	"mdcr_el3",
	"mdrar_el1",
	"mdscr_el1",
	"mvfr0_el1",
	"mvfr1_el1",
	"mvfr2_el1",
	"osdtrrx_el1",
	"osdtrtx_el1",
	"oseccr_el1",
	"oslar_el1",
	"osdlr_el1",
	"oslsr_el1",
	"pan",
	"par_el1",
	"pmccntr_el0",
	"pmceid0_el0",
	"pmceid1_el0",
	"pmcntenset_el0",
	"pmcr_el0",
	"pmcntenclr_el0",
	"pmintenclr_el1",
	"pmintenset_el1",
	"pmovsclr_el0",
	"pmovsset_el0",
	"pmselr_el0",
	"pmswinc_el0",
	"pmuserenr_el0",
	"pmxevcntr_el0",
	"pmxevtyper_el0",
	"rmr_el1",
	"rmr_el2",
	"rmr_el3",
	"rvbar_el1",
	"rvbar_el2",
	"rvbar_el3",
	"s12e0r",
	"s12e0w",
	"s12e1r",
	"s12e1w",
	"s1e0r",
	"s1e0w",
	"s1e1r",
	"s1e1w",
	"s1e2r",
	"s1e2w",
	"s1e3r",
	"s1e3w",
	"scr_el3",
	"sder32_el3",
	"sctlr_el1",
	"sctlr_el2",
	"sctlr_el3",
	"spsel",
	"tcr_el1",
	"tcr_el2",
	"tcr_el3",
	"tpidrro_el0",
	"tpidr_el0",
	"tpidr_el1",
	"tpidr_el2",
	"tpidr_el3",
	"ttbr0_el1",
	"ttbr1_el1",
	"ttbr0_el2",
	"ttbr0_el3",
	"vaae1",
	"vaae1is",
	"vaale1",
	"vaale1is",
	"vae1",
	"vae1is",
	"vae2",
	"vae2is",
	"vae3",
	"vae3is",
	"vale1",
	"vale1is",
	"vale2",
	"vale2is",
	"vale3",
	"vale3is",
	"vbar_el1",
	"vbar_el2",
	"vbar_el3",
	"vmalle1",
	"vmalle1is",
	"vmalls12e1",
	"vmalls12e1is",
	"vmpidr_el0",
	"vpidr_el2",
	"vtcr_el2",
	"vttbr_el2",
	"zva",
	"#0x0",
	"oshld",
	"oshst",
	"osh",
	"#0x4",
	"nshld",
	"nshst",
	"nsh",
	"#0x8",
	"ishld",
	"ishst",
	"ish",
	"#0xc",
	"ld",
	"st",
	"sy",
	"pmevcntr0_el0",
	"pmevcntr1_el0",
	"pmevcntr2_el0",
	"pmevcntr3_el0",
	"pmevcntr4_el0",
	"pmevcntr5_el0",
	"pmevcntr6_el0",
	"pmevcntr7_el0",
	"pmevcntr8_el0",
	"pmevcntr9_el0",
	"pmevcntr10_el0",
	"pmevcntr11_el0",
	"pmevcntr12_el0",
	"pmevcntr13_el0",
	"pmevcntr14_el0",
	"pmevcntr15_el0",
	"pmevcntr16_el0",
	"pmevcntr17_el0",
	"pmevcntr18_el0",
	"pmevcntr19_el0",
	"pmevcntr20_el0",
	"pmevcntr21_el0",
	"pmevcntr22_el0",
	"pmevcntr23_el0",
	"pmevcntr24_el0",
	"pmevcntr25_el0",
	"pmevcntr26_el0",
	"pmevcntr27_el0",
	"pmevcntr28_el0",
	"pmevcntr29_el0",
	"pmevcntr30_el0",

	"pmevtyper0_el0",
	"pmevtyper1_el0",
	"pmevtyper2_el0",
	"pmevtyper3_el0",
	"pmevtyper4_el0",
	"pmevtyper5_el0",
	"pmevtyper6_el0",
	"pmevtyper7_el0",
	"pmevtyper8_el0",
	"pmevtyper9_el0",
	"pmevtyper10_el0",
	"pmevtyper11_el0",
	"pmevtyper12_el0",
	"pmevtyper13_el0",
	"pmevtyper14_el0",
	"pmevtyper15_el0",
	"pmevtyper16_el0",
	"pmevtyper17_el0",
	"pmevtyper18_el0",
	"pmevtyper19_el0",
	"pmevtyper20_el0",
	"pmevtyper21_el0",
	"pmevtyper22_el0",
	"pmevtyper23_el0",
	"pmevtyper24_el0",
	"pmevtyper25_el0",
	"pmevtyper26_el0",
	"pmevtyper27_el0",
	"pmevtyper28_el0",
	"pmevtyper29_el0",
	"pmevtyper30_el0",
	"pmccfiltr_el0",

	"c0",
	"c1",
	"c2",
	"c3",
	"c4",
	"c5",
	"c6",
	"c7",
	"c8",
	"c9",
	"c10",
	"c11",
	"c12",
	"c13",
	"c14",
	"c15",

	"spsr_el1",
	"elr_el1",
	"sp_el0",
	"current_el",
	"nzcv",
	"fpcr",
	"dspsr_el0",
	"daif",
	"fpsr",
	"dlr_el0",
	"spsr_el2",
	"elr_el2",
	"sp_el1",
	"sp_el2",
	"spsr_irq",
	"spsr_abt",
	"spsr_und",
	"spsr_fiq",
	"spsr_el3",
	"elr_el3",
	"ifsr32_el2",
	"fpexc32_el2",
	"cntvoff_el2",

	"midr_el1",
	"mpidr_el1",
	"revidr_el1",
	"id_pfr0_el1",
	"id_pfr1_el1",
	"id_dfr0_el1",
	"id_afr0_el1",
	"id_mmfr0_el1",
	"id_mmfr1_el1",
	"id_mmfr2_el1",
	"id_mmfr3_el1",
	"id_isar0_el1",
	"id_isar1_el1",
	"id_isar2_el1",
	"id_isar3_el1",
	"id_isar4_el1",
	"id_isar5_el1",
	"id_mmfr4_el1",

	"icc_iar0_el1",
	"icc_eoir0_el1",
	"icc_hppir0_el1",
	"icc_bpr0_el1",
	"icc_ap0r0_el1",
	"icc_ap0r1_el1",
	"icc_ap0r2_el1",
	"icc_ap0r3_el1",
	"icc_ap1r0_el1",
	"icc_ap1r1_el1",
	"icc_ap1r2_el1",
	"icc_ap1r3_el1",
	"icc_dir_el1",
	"icc_rpr_el1",
	"icc_iar1_el1",
	"icc_eoir1_el1",
	"icc_hppir1_el1",
	"icc_bpr1_el1",
	"icc_ctlr_el1",
	"icc_sre_el1",
	"icc_igrpen0_el1",
	"icc_igrpen1_el1",

	"icc_asgi1r_el2",
	"icc_sgi0r_el2",
	"ich_ap0r0_el2",
	"ich_ap0r1_el2",
	"ich_ap0r2_el2",
	"ich_ap0r3_el2",
	"ich_ap1r0_el2",
	"ich_ap1r1_el2",
	"ich_ap1r2_el2",
	"ich_ap1r3_el2",
	"ich_ap1r4_el2",
	"icc_hsre_el2",
	"ich_hcr_el2",
	"ich_vtr_el2",
	"ich_misr_el2",
	"ich_eisr_el2",
	"ich_elrsr_el2",
	"ich_vmcr_el2",

	"ich_lr0_el2",
	"ich_lr1_el2",
	"ich_lr2_el2",
	"ich_lr3_el2",
	"ich_lr4_el2",
	"ich_lr5_el2",
	"ich_lr6_el2",
	"ich_lr7_el2",
	"ich_lr8_el2",
	"ich_lr9_el2",
	"ich_lr10_el2",
	"ich_lr11_el2",
	"ich_lr12_el2",
	"ich_lr13_el2",
	"ich_lr14_el2",
	"ich_lr15_el2",

	"ich_lrc0_el2",
	"ich_lrc1_el2",
	"ich_lrc2_el2",
	"ich_lrc3_el2",
	"ich_lrc4_el2",
	"ich_lrc5_el2",
	"ich_lrc6_el2",
	"ich_lrc7_el2",
	"ich_lrc8_el2",
	"ich_lrc9_el2",
	"ich_lrc10_el2",
	"ich_lrc11_el2",
	"ich_lrc12_el2",
	"ich_lrc13_el2",
	"ich_lrc14_el2",
	"ich_lrc15_el2",

	"icc_mctlr_el3",
	"icc_msre_el3",
	"icc_mgrpen1_el3",

	"teecr32_el1",
	"teehbr32_el1",

	"icc_pmr_el1",
	"icc_sgi1r_el1",
	"icc_sgi0r_el1",
	"icc_asgi1r_el1",
	"icc_seien_el1",
	"END_REG"
};
static const char* RegisterString[] = {
	"NONE",
	"w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
	"w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
	"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
	"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr", "wsp",
	"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
	"x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
	"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "sp",
	"v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",
	"v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
	"v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
	"v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "v31",
	"b0",  "b1",  "b2",  "b3",  "b4",  "b5",  "b6",  "b7",
	"b8",  "b9",  "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31", "b31",
	"h0",  "h1",  "h2",  "h3",  "h4",  "h5",  "h6",  "h7",
	"h8",  "h9",  "h10", "h11", "h12", "h13", "h14", "h15",
	"h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
	"h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31", "h31",
	"s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
	"s8",  "s9",  "s10", "s11", "s12", "s13", "s14", "s15",
	"s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
	"s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31", "s31",
	"d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
	"d8",  "d9",  "d10", "d11", "d12", "d13", "d14", "d15",
	"d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
	"d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31", "d31",
	"q0",  "q1",  "q2",  "q3",  "q4",  "q5",  "q6",  "q7",
	"q8",  "q9",  "q10", "q11", "q12", "q13", "q14", "q15",
	"q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
	"q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31", "q31",
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
	"pldl3keep", "pldl3strm", "#0x6",	  "#0x7",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm",
	"plil3keep", "plil3strm", "#0xe",		"#0xf",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
	"pstl3keep", "pstl3strm",
	"#0x17", "#0x18", "#0x19", "#0x1a", "#0x1b", "#0x1c", "#0x1d", "#0x1e", "#0x1f",
};

static const char* ConditionString[] = {
	"eq",
	"ne",
	"cs",
	"cc",
	"mi",
	"pl",
	"vs",
	"vc",
	"hi",
	"ls",
	"ge",
	"lt",
	"gt",
	"le",
	"al",
	"nv" };

static const Register regMap[2][9][32] = {
	{
		{
		REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
		REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
		REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
		REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WSP,
		},{
		REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
		REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
		REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
		REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_SP
		},{
		REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
		REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
		REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
		REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_V31
		},{
		REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
		REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
		REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
		REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_B31
		},{
		REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
		REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
		REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
		REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_H31
		},{
		REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
		REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
		REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
		REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31
		},{
		REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
		REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
		REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
		REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_D31
		},{
		REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
		REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
		REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
		REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31
		},{
		REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
		REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
		REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
		REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31
		},
	},{
		{
		REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
		REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
		REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
		REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WZR,
		},{
		REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
		REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
		REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
		REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_XZR,
		},{
		REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
		REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
		REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
		REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_VZR,
		},{
		REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
		REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
		REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
		REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_BZR,
		},{
		REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
		REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
		REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
		REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_HZR,
		},{
		REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
		REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
		REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
		REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_SZR,
		},{
		REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
		REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
		REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
		REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_DZR,
		},{
		REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
		REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
		REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
		REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_QZR
		},{
		REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
		REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
		REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
		REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31
		}
	}
};
#define REG_W_BASE 0
#define REG_X_BASE 1
#define REG_V_BASE 2
#define REG_B_BASE 3
#define REG_H_BASE 4
#define REG_S_BASE 5
#define REG_D_BASE 6
#define REG_Q_BASE 7
#define REG_PF_BASE 8

#define REGSET_SP 0
#define REGSET_ZR 1
#define REG(USE_SP, REG_BASE, REG_NUM) (regMap[USE_SP][REG_BASE][REG_NUM])
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

static const char* ShiftString[] = {
	"NONE", "lsl", "lsr", "asr",
	"ror",  "uxtw", "sxtw", "sxtx",
	"uxtx", "sxtb", "sxth", "uxth",
	"uxtb", "msl"
};


const char* barrierOptionString[] = {
	"#0x0",  "oshld", "oshst", "osh",
	"#0x4",  "nshld", "nshst", "nsh",
	"#0x8",  "ishld", "ishst", "ish",
	"#0xc",  "ld",	"st",	"sy"
};


uint32_t regSize[] = {REG_W_BASE, REG_X_BASE};
uint32_t simdRegSize[] = {REG_S_BASE, REG_D_BASE, REG_Q_BASE};
uint8_t dataSize[] = {32, 64};

uint32_t get_register_size(Register reg)
{
	//Comparison done in order of likelyhood to occur
	if (reg >= REG_X0 && reg <= REG_SP)
		return 8;
	else if ((reg >= REG_W0 && reg <= REG_WSP) ||
			(reg >= REG_S0 && reg <= REG_S31))
		return 4;
	else if (reg >= REG_B0 && reg <= REG_B31)
		return 1;
	else if (reg >= REG_H0 && reg <= REG_H31)
		return 2;
	else if ((reg >= REG_Q0 && reg <= REG_Q31) ||
			(reg >= REG_V0 && reg <= REG_V31))
		return 16;
	return 0;
}


uint32_t bfxPreferred(uint32_t sf, uint32_t uns, uint32_t imms, uint32_t immr)
{
	if (imms < immr)
		return 0;
	if (sf == 0 && imms == 31)
		return 0;
	else if (sf == 1 && imms == 63)
		return 0;

	if (immr == 0)
	{
		if (sf == 0 && (imms == 7 || imms == 15))
			return 0;
		if (sf == 1 && uns == 0 && (imms == 7 || imms == 15 || imms == 31))
			return 0;
	}
	return 1;
}


uint32_t HighestSetBit(uint32_t x)
{
	for (uint32_t i = 0; i < 31; i++)
	{
		if (((x<<i) & 0x80000000) != 0)
		{
			return 31-i;
		}
	}
	return 0;
}


#define ONES(x) (((uint64_t)-1) >> (64-(x)))
#define ROR(x,N,nbits) (((x) >> (N)) | ((x&ONES(N)) << (nbits-(N))))
uint32_t DecodeBitMasks( uint64_t immN, uint64_t imms, uint64_t immr, uint64_t* out, uint64_t outBits)
{
	/*
	* bits(M) DecodeBitMasks (bit immN, bits(6) imms, bits(6) immr, boolean immediate)
	* bits(M) wmask;
	* bits(6) levels;
	*
	* // Compute log2 of element size
	* // 2^len must be in range [2, M]
	* len = HighestSetBit(immN:NOT(imms));
	* if len < 1 then ReservedValue();
	* assert M >= (1 << len);
	*
	* // Determine S, R and S - R parameters
	* levels = ZeroExtend(Ones(len), 6);
	*
	* // For logical immediates an all-ones value of S is reserved
	* // since it would generate a useless all-ones result (many times)
	* if immediate && (imms AND levels) == levels then
	* ReservedValue();
	*
	* S = UInt(imms AND levels);
	* R = UInt(immr AND levels);
	* diff = S - R; // 6-bit subtract with borrow
	*
	* esize = 1 << len;
	* d = UInt(diff<len-1:0>);
	* welem = ZeroExtend(Ones(S + 1), esize);
	* wmask = Replicate(ROR(welem, R));
	* return wmask;
	*/
	uint64_t len = HighestSetBit((uint32_t)(immN<<6|((~imms) & 0x3f)));
	if (len < 1)
		return 0;

	uint64_t levels = ONES(len) & 0x3f;

	if ((imms & levels) == levels)
		return 0;

	uint64_t S = imms & levels;
	uint64_t R = immr & levels;
	//uint32_t diff = S-R;
	uint64_t esize = 1LL << len;
	//uint32_t d = diff & ONES(len);
	uint64_t welm = ONES(S+1) & ONES(esize);
	//uint32_t telm = (1<<(d+2))-1;
	uint64_t wmask = ROR(welm, R, esize) & ONES(esize);
	if (outBits/esize != 0)
	{
		for(uint64_t i = 0; i < ((outBits/esize)-1); i++)
			wmask |= wmask << esize;
	}
	*out = wmask;
	return 1;
}


static inline uint32_t get_shifted_register(
	const InstructionOperand* restrict instructionOperand,
	uint32_t registerNumber,
	char* outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[32] = {0};
	char shiftBuff[64] = {0};

	const char* reg = get_register_name((Register)instructionOperand->reg[registerNumber]);
	if (reg == NULL)
		return FAILED_TO_DISASSEMBLE_REGISTER;
	if (instructionOperand->shiftType != SHIFT_NONE)
	{
		if (instructionOperand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) < 0)
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char* shiftStr = get_shift(instructionOperand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (snprintf(outBuffer, outBufferSize, "%s%s", reg, shiftBuff) < 0)
		return FAILED_TO_DISASSEMBLE_REGISTER;
	return DISASM_SUCCESS;
}


uint32_t get_memory_operand(
	const InstructionOperand* restrict instructionOperand,
	char* outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[32]= {0};
	char extendBuff[48] = {0};
	char paramBuff[32] = {0};
	const char* reg1 = get_register_name((Register)instructionOperand->reg[0]);
	const char* reg2 = get_register_name((Register)instructionOperand->reg[1]);

	const char* sign = "";
	int64_t imm = instructionOperand->immediate;
	if (instructionOperand->signedImm && (int64_t)imm < 0)
	{
		sign = "-";
		imm = -imm;
	}

	switch (instructionOperand->operandClass)
	{
		case MEM_REG:
			if (snprintf(outBuffer,
						outBufferSize,
						"[%s]",
						RegisterString[instructionOperand->reg[0]]) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;
		case MEM_PRE_IDX:
			if (snprintf(outBuffer,
						outBufferSize,
						"[%s, #%s%#" PRIx64 "]!",
						RegisterString[instructionOperand->reg[0]],
						sign,
						(uint64_t)imm) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;
		case MEM_POST_IDX: // [<reg>], <reg|imm>
			if (instructionOperand->reg[1] != REG_NONE)
			{
				snprintf(paramBuff, sizeof(paramBuff), ", %s",
						RegisterString[instructionOperand->reg[1]]);
			}
			else if (snprintf(paramBuff, sizeof(paramBuff), ", #%s%#" PRIx64, sign, (uint64_t)imm) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			if (snprintf(outBuffer,
						outBufferSize,
						"[%s]%s",
						RegisterString[instructionOperand->reg[0]],
						paramBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;
		case MEM_OFFSET: // [<reg> optional(imm)]
			if (instructionOperand->immediate != 0 &&
				snprintf(immBuff, 32, ", #%s%#" PRIx64, sign, (uint64_t)imm) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			if (snprintf(outBuffer,
						outBufferSize,
						"[%s%s]",
						RegisterString[instructionOperand->reg[0]],
						immBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;
		case MEM_EXTENDED:
			if (reg1 == NULL || reg2 == NULL)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			if (instructionOperand->shiftValueUsed != 0 &&
					snprintf(immBuff, 32, ", #%#x", instructionOperand->shiftValue) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			if (instructionOperand->shiftType != SHIFT_NONE)
			{
				if (snprintf(extendBuff, sizeof(extendBuff), ", %s%s",
						ShiftString[instructionOperand->shiftType],
						immBuff) < 0)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
			}
			if (snprintf(outBuffer, outBufferSize, "[%s, %s%s]", reg1, reg2, extendBuff) < 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;
		default:
			return NOT_MEMORY_OPERAND;
	}
	return DISASM_SUCCESS;
}


uint32_t get_register(const InstructionOperand* restrict operand, uint32_t registerNumber, char* outBuffer, uint32_t outBufferSize)
{
	char scale[32] = {0};
	if (operand->scale != 0)
	{
		snprintf(scale, sizeof(scale), "[%u]", 0x7fffffff & operand->scale);
	}
	if (operand->operandClass == SYS_REG)
	{
		if (snprintf(outBuffer, outBufferSize, "%s", get_system_register_name((SystemReg)operand->reg[registerNumber])) < 0)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}
	else if (operand->operandClass != REG && operand->operandClass != MULTI_REG)
		return OPERAND_IS_NOT_REGISTER;

	if (operand->shiftType != SHIFT_NONE)
	{
		return get_shifted_register(operand, registerNumber, outBuffer, outBufferSize);
	}
	else if (operand->elementSize == 0)
	{
		if (snprintf(outBuffer, outBufferSize, "%s", get_register_name((Register)operand->reg[registerNumber])) < 0)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}
	char elementSize;
	switch (operand->elementSize)
	{
		case 1:  elementSize = 'b'; break;
		case 2:  elementSize = 'h'; break;
		case 4:  elementSize = 's'; break;
		case 8:  elementSize = 'd'; break;
		case 16: elementSize = 'q'; break;
		default:
			return FAILED_TO_DISASSEMBLE_REGISTER;
	}

	if (operand->dataSize != 0)
	{
		if (registerNumber > 3 || (operand->dataSize != 1 && operand->dataSize != 2 &&
			operand->dataSize != 4 && operand->dataSize != 8 && operand->dataSize != 16) ||
			snprintf(outBuffer,
				outBufferSize,
				"%s.%u%c%s",
				get_register_name((Register)operand->reg[registerNumber]),
				operand->dataSize,
				elementSize, scale) < 0)
		{
			return FAILED_TO_DISASSEMBLE_REGISTER;
		}
	}
	else
	{
		if (registerNumber > 3 ||
			snprintf(outBuffer,
				outBufferSize,
				"%s.%c%s",
				get_register_name((Register)operand->reg[registerNumber]),
				elementSize, scale) < 0)
		{
			return FAILED_TO_DISASSEMBLE_REGISTER;
		}
	}
	return 0;
}


const char* get_register_name(Register reg)
{
	if (reg < REG_END && reg > REG_NONE)
		return RegisterString[reg];
	return NULL;
}


uint32_t get_multireg_operand(const InstructionOperand* restrict operand, char* outBuffer, uint32_t outBufferSize)
{
	char indexBuff[32] = {0};
	char regBuff[4][32];
	uint32_t elementCount = 0;
	memset(&regBuff, 0, sizeof(regBuff));

	for (; elementCount < 4 && operand->reg[elementCount] != REG_NONE; elementCount++)
	{
		if (get_register(operand, elementCount, regBuff[elementCount], 32) != 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}

	if(operand->index != 0)
	{
		snprintf(indexBuff, sizeof(indexBuff), "[%d]", operand->index);
	}
	int32_t result = 0;
	switch (elementCount)
	{
		case 1:
			result = snprintf(outBuffer, outBufferSize, "{%s}%s",
				regBuff[0],
				indexBuff);
			break;
		case 2:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s}%s",
				regBuff[0],
				regBuff[1],
				indexBuff);
			break;
		case 3:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s, %s}%s",
				regBuff[0],
				regBuff[1],
				regBuff[2],
				indexBuff);
			break;
		case 4:
			result = snprintf(outBuffer, outBufferSize, "{%s, %s, %s, %s}%s",
				regBuff[0],
				regBuff[1],
				regBuff[2],
				regBuff[3],
				indexBuff);
			break;
		default:
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	return result < 0?FAILED_TO_DISASSEMBLE_OPERAND:DISASM_SUCCESS;
}


uint32_t get_shifted_immediate(const InstructionOperand* restrict instructionOperand, char* outBuffer, uint32_t outBufferSize, uint32_t type)
{
	char shiftBuff[48] = {0};
	char immBuff[32] = {0};
	const char* sign = "";
	if (instructionOperand == NULL)
		return FAILED_TO_DISASSEMBLE_OPERAND;

	uint64_t imm = instructionOperand->immediate;
	if (instructionOperand->signedImm == 1 && ((int64_t)imm) < 0)
	{
		sign = "-";
		imm = -(int64_t)imm;
	}
	if (instructionOperand->shiftType != SHIFT_NONE)
	{
		if (instructionOperand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) < 0)
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char* shiftStr = get_shift(instructionOperand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (type == FIMM32)
	{
		float f = *(const float*)&instructionOperand->immediate;
		if (snprintf(outBuffer, outBufferSize, "#%f%s", f, shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == IMM32)
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#x%s", sign, (uint32_t)imm, shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#" PRIx64 "%s",
					sign,
					imm,
					shiftBuff) < 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	return DISASM_SUCCESS;
}


static uint32_t disassemble_instruction(const Instruction* restrict instruction, char* outBuffer, uint32_t outBufferSize)
{
	char operandStrings[MAX_OPERANDS][130];
	char tmpOperandString[128];
	const char* operand = tmpOperandString;
	if (instruction == NULL || outBufferSize == 0 || outBuffer == NULL)
		return INVALID_ARGUMENTS;

	memset(operandStrings, 0, sizeof(operandStrings));
	const char* operation = get_operation(instruction);
	if (operation == NULL)
		return FAILED_TO_DISASSEMBLE_OPERATION;

	for (uint32_t i = 0; i < MAX_OPERANDS; i++)
		memset(&(operandStrings[i][0]), 0, 128);

	for (uint32_t i = 0; i < MAX_OPERANDS && instruction->operands[i].operandClass != NONE; i++)
	{
		switch (instruction->operands[i].operandClass)
		{
			case FIMM32:
			case IMM32:
			case IMM64:
			case LABEL:
				if (get_shifted_immediate(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString),
							instruction->operands[i].operandClass) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case REG:
				if (get_register(
						&instruction->operands[i],
						0,
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case SYS_REG:
				operand = get_system_register_name((SystemReg)instruction->operands[i].reg[0]);
				if (operand == NULL)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				break;
			case MULTI_REG:
				if (get_multireg_operand(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case IMPLEMENTATION_SPECIFIC:
				if (get_implementation_specific(
						&instruction->operands[i],
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case MEM_REG:
			case MEM_OFFSET:
			case MEM_EXTENDED:
			case MEM_PRE_IDX:
			case MEM_POST_IDX:
				if (get_memory_operand(&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case CONDITION:
				if (snprintf(tmpOperandString, sizeof(tmpOperandString), "%s", get_condition((Condition)instruction->operands[i].reg[0])) < 0)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
			case NONE:
				break;
		}
		snprintf(operandStrings[i], sizeof(operandStrings[i]), i==0?"\t%s":", %s", operand);
	}
	memset(outBuffer, 0, outBufferSize);
	if (snprintf(outBuffer, outBufferSize, "%s%s%s%s%s%s",
			OperationString[instruction->operation],
			operandStrings[0],
			operandStrings[1],
			operandStrings[2],
			operandStrings[3],
			operandStrings[4]) < 0)
		return OUTPUT_BUFFER_TOO_SMALL;
	return DISASM_SUCCESS;
}


const char* get_operation(const Instruction* restrict instruction)
{
	if ((uint32_t)instruction->operation < COUNT_OF(OperationString))
		return OperationString[instruction->operation];
	return NULL;
}


uint32_t get_implementation_specific(const InstructionOperand* restrict operand, char* outBuffer, uint32_t outBufferSize)
{
	return snprintf(outBuffer,
			outBufferSize,
			"s%d_%d_c%d_c%d_%d",
			operand->reg[0],
			operand->reg[1],
			operand->reg[2],
			operand->reg[3],
			operand->reg[4]) < 0;
}


const char* get_system_register_name(SystemReg reg)
{
	//REG_W0 is the first of the general purpose registers
	if (reg >= COUNT_OF(SystemRegisterString))
		return NULL;
	return SystemRegisterString[reg];
}


const char* get_condition(Condition cond)
{
	if (cond >= END_CONDITION)
		return NULL;
	return ConditionString[cond];
}


const char* get_shift(ShiftType shift)
{
	if (shift == SHIFT_NONE || shift >= END_SHIFT)
		return NULL;
	return ShiftString[shift];
}


//------------------------------------------------------------------------------------------------
//Decomposition Instructions
//------------------------------------------------------------------------------------------------
void delete_operand(InstructionOperand* restrict operand, uint32_t index, uint32_t size)
{
	if (index == 4)
		memset(&operand[index], 0, sizeof(InstructionOperand));
	else
	{
		memmove(&operand[index], &operand[index+1], sizeof(InstructionOperand)*(4-index));
		memset(&operand[size], 0, sizeof(InstructionOperand) * (4-size));
	}
}


uint32_t aarch64_decompose_add_sub_carry(uint32_t instructionValue, Instruction* restrict instruction)
{
	ADD_SUB_WITH_CARRY decode = *(ADD_SUB_WITH_CARRY*)&instructionValue;
	static const Operation operation[2][2] = {
		{ARM64_ADC, ARM64_ADCS},
		{ARM64_SBC, ARM64_SBCS}
	};
	instruction->operation = operation[decode.op][decode.S];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	if (decode.Rn == 31)
	{
		if (instruction->operation == ARM64_SBC)
		{
			instruction->operation = ARM64_NGC;
			delete_operand(instruction->operands, 1, 3);
		}
		else if (instruction->operation == ARM64_SBCS)
		{
			instruction->operation = ARM64_NGCS;
			delete_operand(instruction->operands, 1, 3);
		}
	}
	return decode.opcode2 != 0;
}


uint32_t aarch64_decompose_add_sub_extended_reg(uint32_t instructionValue, Instruction* restrict instruction)
{
	ADD_SUB_EXTENDED_REG decode = *(ADD_SUB_EXTENDED_REG*)&instructionValue;
	static const Operation operation[2][2] = {{ARM64_ADD, ARM64_ADDS}, {ARM64_SUB, ARM64_SUBS}};
	static const uint32_t regBaseMap[2] = {REG_W_BASE, REG_X_BASE};
	static const uint32_t regBaseMap2[8] = {
		REG_W_BASE, REG_W_BASE, REG_W_BASE, REG_X_BASE,
		REG_W_BASE, REG_W_BASE, REG_W_BASE, REG_X_BASE
	};
	static const uint32_t decodeOptionMap[2] = {2,3};
	static const ShiftType shiftMap[2][8] = {
		{
			SHIFT_UXTB, SHIFT_UXTH, SHIFT_UXTW, SHIFT_UXTX,
			SHIFT_SXTB, SHIFT_SXTH, SHIFT_SXTW, SHIFT_SXTX
		},{
			SHIFT_UXTB, SHIFT_UXTH, SHIFT_UXTW, SHIFT_UXTX,
			SHIFT_SXTB, SHIFT_SXTH, SHIFT_SXTW, SHIFT_SXTX
		}
	};
	instruction->operation = operation[decode.op][decode.S];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_SP, regBaseMap[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, regBaseMap[decode.sf], decode.Rn);
	instruction->operands[2].operandClass = REG;
	if (decode.sf == 0)
	{
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rm);
	}
	else
	{
		instruction->operands[2].reg[0] = REG(REGSET_ZR, regBaseMap2[decode.option], decode.Rm);
	}
	instruction->operands[2].shiftType = shiftMap[decode.sf][decode.option];
	instruction->operands[2].shiftValueUsed = 0;
	//SUBS => Rn == 31
	//ADDS => Rn == 31
	//SUB  => Rd|Rn == 31
	//ADD  => Rd|Rn == 31
	if ((decode.option == decodeOptionMap[decode.sf]) &&
		((decode.S == 1 && decode.Rn == 31) ||
		(decode.S == 0 && (decode.Rd == 31 || decode.Rn == 31))))
	{
		if (decode.imm != 0)
		{
			instruction->operands[2].shiftType = SHIFT_LSL;
			instruction->operands[2].shiftValueUsed = 1;
			instruction->operands[2].shiftValue = decode.imm;
		}
		else
		{
			instruction->operands[2].shiftType = SHIFT_NONE;
		}
	}
	else if (decode.imm != 0)
	{
		instruction->operands[2].shiftValueUsed = 1;
		instruction->operands[2].shiftValue = decode.imm;
	}
	//Now handle aliases
	if (decode.Rd == 31)
	{
		if (instruction->operation == ARM64_ADDS)
		{
			instruction->operation = ARM64_CMN;
			delete_operand(instruction->operands, 0, 3);
		}
		else if (instruction->operation == ARM64_SUBS)
		{
			instruction->operation = ARM64_CMP;
			delete_operand(instruction->operands, 0, 3);
		}
	}
	return decode.opt != 0;
}


uint32_t aarch64_decompose_add_sub_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.4.1 - Add/subtract (immediate)
	 *
	 * ADD  <Wd|WSP>, <Wn|WSP>, #<imm>{, <shift>}
	 * ADDS <Wd>,	 <Wn|WSP>, #<imm>{, <shift>}
	 * SUB  <Wd|WSP>, <Wn|WSP>, #<imm>{, <shift>}
	 * SUBS <Wd>,	 <Wn|WSP>, #<imm>{, <shift>}
	 *
	 * ADD  <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
	 * ADDS <Xd>,	<Xn|SP>, #<imm>{, <shift>}
	 * SUB  <Xd|SP>, <Xn|SP>, #<imm>{, <shift>}
	 * SUBS <Xd>,	<Xn|SP>, #<imm>{, <shift>}
	 */
	struct decodeRec {
		Operation operation;
		uint32_t regType;
	};
	static const struct decodeRec operationMap[2][2] = {
		{{ARM64_ADD, REGSET_SP}, {ARM64_ADDS, REGSET_ZR}},
		{{ARM64_SUB, REGSET_SP}, {ARM64_SUBS, REGSET_ZR}}};
	static const uint32_t regBaseMap[2] = {REG_W_BASE, REG_X_BASE};
	ADD_SUB_IMM decode = *(ADD_SUB_IMM*)&instructionValue;
	instruction->operation = operationMap[decode.op][decode.S].operation;

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(
			operationMap[decode.op][decode.S].regType, regBaseMap[decode.sf], decode.Rd);

	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, regBaseMap[decode.sf], decode.Rn);

	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = decode.imm;
	if (decode.shift == 1)
	{
		instruction->operands[2].shiftValue = 12;
		instruction->operands[2].shiftValueUsed = 1;
		instruction->operands[2].shiftType = SHIFT_LSL;
	}
	else if (decode.shift > 1)
	{
		return FAILED_TO_DECODE_INSTRUCTION;
	}
	//Check for alias
	if (instruction->operation == ARM64_SUBS && decode.Rd == 31)
	{
		instruction->operation = ARM64_CMP;
		delete_operand(instruction->operands, 0, 3);
	}
	else if (instruction->operation == ARM64_ADD &&
			instruction->operands[2].immediate == 0 &&
			decode.shift == 0 &&
			(decode.Rd == 31 || decode.Rn == 31))
	{
		instruction->operation = ARM64_MOV;
		instruction->operands[2].operandClass = NONE;
	}
	else if (instruction->operation == ARM64_ADDS && decode.Rd == 31)
	{
		instruction->operation = ARM64_CMN;
		delete_operand(instruction->operands, 0, 3);
	}
	return 0;
}

uint32_t aarch64_decompose_add_sub_imm_tags(uint32_t instructionValue, Instruction* restrict instruction)
{
	/*
	 * ADDG <Xd|SP>, <Xn|SP>, #<uimm6>, #<uimm4>
	 * SUBG <Xd|SP>, <Xn|SP>, #<uimm6>, #<uimm4>
	 */
	ADD_SUB_IMM_TAGS decode = *(ADD_SUB_IMM_TAGS*)&instructionValue;

	// ADDG: 1	0	0	1	0	0	0	1	1	0	uimm6	(0)	(0)	uimm4	Xn	Xd
	// SUBG: 1	1	0	1	0	0	0	1	1	0	uimm6	(0)	(0)	uimm4	Xn	Xd
	instruction->operation = BF_GETI(30,1) ? ARM64_SUBG : ARM64_ADDG;

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Xd);

	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Xn);

	// offset
	instruction->operands[2].operandClass = IMM64;
	instruction->operands[2].immediate = 16*decode.uimm6;

	// tag_offset
	instruction->operands[3].operandClass = IMM32;
	instruction->operands[3].immediate = decode.uimm4;

	return 0;
}

uint32_t aarch64_decompose_add_sub_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.2 Add/subtract (shifted register)
	 *
	 * ADD  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * ADDS <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * SUB  <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * SUBS <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 *
	 * ADD  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * ADDS <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * SUB  <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * SUBS <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 *
	 * Alias
	 * ADDS WZR, <Wn>, <Wm> {, <shift> #<amount>} -> CMN <Wn>, <Wm>{, <shift> #<amount>}
	 * ADDS XZR, <Xn>, <Xm> {, <shift> #<amount>} -> CMN <Xn>, <Xm>{, <shift> #<amount>}
	 * SUB  <Wd>, WZR, <Wm> {, <shift> #<amount>} -> NEG <Wd>, <Wm>{, <shift> #<amount>}
	 * SUB  <Xd>, XZR, <Xm> {, <shift> #<amount>} -> NEG <Xd>, <Xm>{, <shift> #<amount>}
	 * SUBS WZR, <Wn>, <Wm> {, <shift> #<amount>} -> CMP <Wn>, <Wm>{, <shift> #<amount>}
	 * SUBS XZR, <Xn>, <Xm> {, <shift> #<amount>} -> CMP <Xn>, <Xm>{, <shift> #<amount>}
	 */
	ADD_SUB_SHIFTED_REG decode = *(ADD_SUB_SHIFTED_REG*)&instructionValue;
	static const Operation operation[2][2] = {
		{ARM64_ADD, ARM64_SUB},
		{ARM64_ADDS, ARM64_SUBS}};
	static const ShiftType shift[4] = {SHIFT_LSL, SHIFT_LSR, SHIFT_ASR, SHIFT_NONE};
	instruction->operation = operation[decode.S][decode.op];

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);

	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);

	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);

	if (!(decode.shift == 0 && decode.imm == 0))
	{
		instruction->operands[2].shiftType = shift[decode.shift];
		instruction->operands[2].shiftValue = decode.imm;
		instruction->operands[2].shiftValueUsed = 1;
	}
	//Handle aliases
	if (instruction->operation == ARM64_ADDS&& decode.Rd == 31)
	{
		instruction->operation = ARM64_CMN;
		delete_operand(instruction->operands, 0, 3);
	}
	else if (instruction->operation == ARM64_SUB&& decode.Rn == 31)
	{
		instruction->operation = ARM64_NEG;
		delete_operand(instruction->operands, 1, 3);
	}
	else if (instruction->operation == ARM64_SUBS)
	{
		if (decode.Rd == 31)
		{
			instruction->operation = ARM64_CMP;
			delete_operand(instruction->operands, 0, 3);
		}
		else if (decode.Rn == 31)
		{
			instruction->operation = ARM64_NEGS;
			delete_operand(instruction->operands, 1, 3);
		}
	}
	return 0;
}


uint32_t aarch64_decompose_bitfield(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.4.2 Bitfield
	 *
	 * SBFM <Wd>, <Wn>, #<immr>, #<imms>
	 * BFM  <Wd>, <Wn>, #<immr>, #<imms>
	 * UBFM <Wd>, <Wn>, #<immr>, #<imms>
	 *
	 * SBFM <Xd>, <Xn>, #<immr>, #<imms>
	 * BFM  <Xd>, <Xn>, #<immr>, #<imms>
	 * UBFM <Xd>, <Xn>, #<immr>, #<imms>
	 *
	 * Alias
	 * SBFM <Wd>, <Wn>, #<shift>, #31 -> ASR <Wd>, <Wn>, #<shift>
	 * SBFM <Xd>, <Xn>, #<shift>, #63 -> ASR <Xd>, <Xn>, #<shift>
	 * SBFM <Wd>, <Wn>, #(-<lsb> MOD 32), #(<width>-1) -> SBFIZ <Wd>, <Wn>, #<lsb>, #<width>
	 * SBFM <Xd>, <Xn>, #(-<lsb> MOD 64), #(<width>-1) -> SBFIZ <Xd>, <Xn>, #<lsb>, #<width>
	 * SBFM <Wd>, <Wn>, #0, #7 -> SXTB <Wd>, <Wn>
	 * SBFM <Xd>, <Xn>, #0, #7 -> SXTB <Xd>, <Wn>
	 * SBFM <Wd>, <Wn>, #0, #15 -> SXTH <Wd>, <Wn>
	 * SBFM <Xd>, <Xn>, #0, #15 -> SXTH <Xd>, <Wn>
	 * SBFM <Xd>, <Xn>, #0, #31 -> SXTW <Xd>, <Wn>
	 *
	 * BFM <Wd>, <Wn>, #(-<lsb> MOD 32), #(<width>-1) -> BFI <Wd>, <Wn>, #<lsb>, #<width>
	 * BFM <Xd>, <Xn>, #(-<lsb> MOD 64), #(<width>-1) -> BFI <Xd>, <Xn>, #<lsb>, #<width>
	 * BFM <Wd>, <Wn>, #<lsb>, #(<lsb>+<width>-1) -> BFXIL <Wd>, <Wn>, #<lsb>, #<width>
	 * BFM <Xd>, <Xn>, #<lsb>, #(<lsb>+<width>-1) -> BFXIL <Xd>, <Xn>, #<lsb>, #<width>
	 *
	 * UBFM <Wd>, <Wn>, #(-<shift> MOD 32), #(31-<shift>) -> LSL <Wd>, <Wn>, #<shift>
	 * UBFM <Xd>, <Xn>, #(-<shift> MOD 64), #(63-<shift>) -> LSL <Xd>, <Xn>, #<shift>
	 * UBFM <Wd>, <Wn>, #(-<lsb> MOD 32), #(<width>-1) -> UBFIZ <Wd>, <Wn>, #<lsb>, #<width>
	 * UBFM <Xd>, <Xn>, #(-<lsb> MOD 64), #(<width>-1) -> UBFIZ <Xd>, <Xn>, #<lsb>, #<width>
	 *
	 */
	BITFIELD decode = *(BITFIELD*)&instructionValue;
	static const Operation operation[] = {ARM64_SBFM, ARM64_BFM, ARM64_UBFM, ARM64_UNDEFINED};
	instruction->operation = operation[decode.opc];

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);

	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);

	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = decode.immr;

	instruction->operands[3].operandClass = IMM32;
	instruction->operands[3].immediate = decode.imms;

	//Handle aliases
	uint32_t usebfx = bfxPreferred(decode.sf, decode.opc>>1 , decode.imms, decode.immr);
	if (instruction->operation == ARM64_SBFM)
	{
		if (decode.sf == decode.N && decode.imms == dataSize[decode.sf]-1)
		{
			instruction->operation = ARM64_ASR;
			instruction->operands[3].operandClass = NONE;
		}
		else if (decode.imms < decode.immr)
		{
			instruction->operation = ARM64_SBFIZ;
			instruction->operands[2].immediate = dataSize[decode.sf] - decode.immr;
			instruction->operands[3].immediate++;
		}
		else if (usebfx)
		{
			instruction->operation = ARM64_SBFX;
			instruction->operands[3].immediate -= instruction->operands[2].immediate-1;
		}
		else if (instruction->operands[2].immediate == 0)
		{
			switch (decode.imms)
			{
				case 7:
					instruction->operation = ARM64_SXTB;
					instruction->operands[1].operandClass = REG;
					instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rn);
					instruction->operands[2].operandClass = NONE;
					instruction->operands[3].operandClass = NONE;
					break;
				case 15:
					instruction->operation = ARM64_SXTH;
					instruction->operands[1].operandClass = REG;
					instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rn);
					instruction->operands[2].operandClass = NONE;
					instruction->operands[3].operandClass = NONE;
					break;
				case 31:
					instruction->operation = ARM64_SXTW;
					instruction->operands[1].operandClass = REG;
					instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rn);
					instruction->operands[2].operandClass = NONE;
					instruction->operands[3].operandClass = NONE;
					break;
				default:
					break;
			}
		}
	}
	else if (instruction->operation == ARM64_BFM)
	{
		if (decode.imms < decode.immr)
		{
			instruction->operation = ARM64_BFI;
			instruction->operands[2].operandClass = IMM32;
			instruction->operands[2].immediate = dataSize[decode.sf] - decode.immr;
			instruction->operands[3].operandClass = IMM32;
			instruction->operands[3].immediate++;
		}
		else
		{
			instruction->operation = ARM64_BFXIL;
			instruction->operands[3].operandClass = IMM32;
			instruction->operands[3].immediate -= instruction->operands[2].immediate-1;
		}
	}
	else if (instruction->operation == ARM64_UBFM)
	{
		if (decode.imms != dataSize[decode.sf]-1 && decode.imms + 1 == decode.immr)
		{
			instruction->operation = ARM64_LSL;
			instruction->operands[2].operandClass = IMM32;
			instruction->operands[2].immediate = dataSize[decode.sf] - decode.immr;
			instruction->operands[3].operandClass = NONE;
		}
		else if (decode.imms == dataSize[decode.sf]-1)
		{
			instruction->operation = ARM64_LSR;
			instruction->operands[3].operandClass = IMM32;
			instruction->operands[3].operandClass = NONE;
		}
		else if (decode.imms < decode.immr)
		{
			instruction->operation = ARM64_UBFIZ;
			instruction->operands[2].operandClass = IMM32;
			instruction->operands[2].immediate = dataSize[decode.sf] - decode.immr;
			instruction->operands[3].operandClass = IMM32;
			instruction->operands[3].immediate++;
		}
		else if (usebfx)
		{
			instruction->operation = ARM64_UBFX;
			instruction->operands[3].operandClass = IMM32;
			instruction->operands[3].immediate -= instruction->operands[2].immediate-1;
		}
		else if (decode.immr == 0)
		{
			if (decode.imms == 7)
			{
				instruction->operation = ARM64_UXTB;
				instruction->operands[2].operandClass = NONE;
				instruction->operands[3].operandClass = NONE;
			}
			else if (decode.imms == 15)
			{
				instruction->operation = ARM64_UXTH;
				instruction->operands[2].operandClass = NONE;
				instruction->operands[3].operandClass = NONE;
			}
		}
	}
	return 0;
}


uint32_t aarch64_decompose_compare_branch_imm(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/*
	 * C4.2.1 Compare & branch (immediate)
	 *
	 * CBZ <Wt>, <label>
	 * CBZ <Xt>, <label>
	 * CBNZ <Xt>, <label>
	 * CBNZ <Wt>, <label>
	 */
	COMPARE_BRANCH_IMM decode = *(COMPARE_BRANCH_IMM* restrict)&instructionValue;
	static const Operation operation[] = {ARM64_CBZ, ARM64_CBNZ};
	instruction->operation = operation[decode.op];

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rt);

	instruction->operands[1].operandClass = LABEL;
	instruction->operands[1].immediate = address +  (decode.imm << 2);
	return 0;
}


uint32_t aarch64_decompose_conditional_branch(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/* C4.2.2 Conditional branch (immediate)
	 *
	 * B.<cond> <label>
	 */
	CONDITIONAL_BRANCH_IMM decode = *(CONDITIONAL_BRANCH_IMM* restrict)&instructionValue;
	static const Operation operation[] = {
		ARM64_B_EQ, ARM64_B_NE, ARM64_B_CS, ARM64_B_CC,
		ARM64_B_MI, ARM64_B_PL, ARM64_B_VS, ARM64_B_VC,
		ARM64_B_HI, ARM64_B_LS, ARM64_B_GE, ARM64_B_LT,
		ARM64_B_GT, ARM64_B_LE, ARM64_B_AL, ARM64_B_NV};
	instruction->operation = operation[decode.cond];

	instruction->operands[0].operandClass = LABEL;
	instruction->operands[0].immediate = address + (decode.imm << 2);
	return !(decode.o0 == 0 && decode.o1 == 0);
}


uint32_t aarch64_decompose_conditional_compare_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.4 Conditional compare (immediate)
	 *
	 * CCMN <Wn>, #<imm>, #<nzcv>, <cond>
	 * CCMN <Xn>, #<imm>, #<nzcv>, <cond>
	 * CCMP <Wn>, #<imm>, #<nzcv>, <cond>
	 * CCMP <Xn>, #<imm>, #<nzcv>, <cond>
	 */
	CONDITIONAL_COMPARE_IMM decode = *(CONDITIONAL_COMPARE_IMM*)&instructionValue;
	static const Operation operation [2] = {ARM64_CCMN, ARM64_CCMP};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[1].operandClass = IMM32;
	instruction->operands[1].immediate = decode.imm;
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = decode.nzcv;
	instruction->operands[3].operandClass = CONDITION;
	instruction->operands[3].reg[0] = (Register)decode.cond;
	return decode.o2 != 0 || decode.o3 != 0;
}


uint32_t aarch64_decompose_conditional_compare_reg(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.5 Conditional compare (register)
	 *
	 * CCMN <Wn>, <Wm>, #<nzcv>, <cond>
	 * CCMN <Xn>, <Xm>, #<nzcv>, <cond>
	 * CCMP <Wn>, <Wm>, #<nzcv>, <cond>
	 * CCMP <Xn>, <Xm>, #<nzcv>, <cond>
	 */
	CONDITIONAL_COMPARE_REG decode = *(CONDITIONAL_COMPARE_REG*)&instructionValue;
	static const Operation operation [2] = {ARM64_CCMN, ARM64_CCMP};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = decode.nzcv;
	instruction->operands[3].operandClass = CONDITION;
	instruction->operands[3].reg[0] = decode.cond;
	return decode.o2 != 0 || decode.o3 != 0;
}


uint32_t aarch64_decompose_conditional_select(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.6 Conditional select
	 *
	 * CSEL  <Wd>, <Wn>, <Wm>, <cond>
	 * CSEL  <Xd>, <Xn>, <Xm>, <cond>
	 * CSINC <Wd>, <Wn>, <Wm>, <cond>
	 * CSINC <Xd>, <Xn>, <Xm>, <cond>
	 * CSINV <Wd>, <Wn>, <Wm>, <cond>
	 * CSINV <Xd>, <Xn>, <Xm>, <cond>
	 * CSNEG <Wd>, <Wn>, <Wm>, <cond>
	 * CSNEG <Xd>, <Xn>, <Xm>, <cond>
	 */
	CONDITIONAL_SELECT decode = *(CONDITIONAL_SELECT*)&instructionValue;
	static const Operation operation[2][2] = {
		{ARM64_CSEL, ARM64_CSINC},
		{ARM64_CSINV, ARM64_CSNEG}
	};
	instruction->operation = operation[decode.op][decode.op2&1];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	instruction->operands[3].operandClass = CONDITION;
	instruction->operands[3].reg[0] = decode.cond;

	if (decode.Rm != 31 && decode.cond < 14 && decode.Rn != 31 && decode.Rn == decode.Rm)
	{
		if (instruction->operation == ARM64_CSINC)
		{
			instruction->operation = ARM64_CINC;
			instruction->operands[3].reg[0] = INVERT_CONDITION(instruction->operands[3].reg[0]);
			delete_operand(instruction->operands, 1, 3);
		}
		else if (instruction->operation == ARM64_CSINV)
		{
			instruction->operation = ARM64_CINV;
			instruction->operands[3].reg[0] = INVERT_CONDITION(instruction->operands[3].reg[0]);
			delete_operand(instruction->operands, 1, 3);
		}
	}

	if (decode.Rm == 31 && decode.Rn == 31 && decode.cond < 14)
	{
		if (instruction->operation == ARM64_CSINC)
		{
			instruction->operation = ARM64_CSET;
			instruction->operands[1].reg[0] = INVERT_CONDITION(decode.cond);
			instruction->operands[1].operandClass = CONDITION;
			instruction->operands[2].operandClass = NONE;
		}
		else if (instruction->operation == ARM64_CSINV)
		{
			instruction->operation = ARM64_CSETM;
			instruction->operands[1].reg[0] = INVERT_CONDITION(decode.cond);
			instruction->operands[1].operandClass = CONDITION;
			instruction->operands[2].operandClass = NONE;
		}
	}

	if (instruction->operation == ARM64_CSNEG && decode.cond < 14 && decode.Rn == decode.Rm)
	{
		instruction->operation = ARM64_CNEG;
		instruction->operands[3].reg[0] = INVERT_CONDITION(instruction->operands[3].reg[0]);
		delete_operand(instruction->operands, 1, 3);
	}
	return decode.S != 0 || decode.op2 > 1;
}


uint32_t aarch64_decompose_cryptographic_2_register_sha(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.21 Cryptographic two-register SHA
	 *
	 * SHA1H <Sd>, <Sn>
	 * SHA1SU1 <Vd>.4S, <Vn>.4S
	 * SHA256SU0 <Vd>.4S, <Vn>.4S
	 */
	CRYPTOGRAPHIC_2_REG_SHA decode = *(CRYPTOGRAPHIC_2_REG_SHA*)&instructionValue;
	static const Operation operation[4] = {ARM64_SHA1H, ARM64_SHA1SU1, ARM64_SHA256SU0, ARM64_UNDEFINED};
	instruction->operation = operation[decode.opcode & 3];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	switch (decode.opcode)
	{
		case 0:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_S_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_S_BASE, decode.Rn);
			break;
		case 1:
		case 2:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
			instruction->operands[0].elementSize = 4;
			instruction->operands[0].dataSize = 4;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			instruction->operands[1].elementSize = 4;
			instruction->operands[1].dataSize = 4;
			break;
		default:
			return 1;
	}
	return decode.size != 0;
}


uint32_t aarch64_decompose_cryptographic_3_register_sha(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.20 - Cryptographic three-register SHA
	 *
	 * SHA1C	 <Qd>, <Sn>, <Vm>.4S
	 * SHA1P	 <Qd>, <Sn>, <Vm>.4S
	 * SHA1M	 <Qd>, <Sn>, <Vm>.4S
	 * SHA256H   <Qd>, <Qn>, <Vm>.4S
	 * SHA256H2  <Qd>, <Qn>, <Vm>.4S
	 * SHA1SU0   <Vd>.4S, <Vn>.4S, <Vm>.4S
	 * SHA256SU1 <Vd>.4S, <Vn>.4S, <Vm>.4S
	 */
	CRYPTOGRAPHIC_3_REG_SHA decode = *(CRYPTOGRAPHIC_3_REG_SHA*)&instructionValue;
	static const Operation operation[8] = {
		ARM64_SHA1C,
		ARM64_SHA1P,
		ARM64_SHA1M,
		ARM64_SHA1SU0,
		ARM64_SHA256H,
		ARM64_SHA256H2,
		ARM64_SHA256SU1,
		ARM64_UNDEFINED,
	};

	instruction->operation = operation[decode.opcode];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	switch(decode.opcode)
	{
		case 0:
		case 1:
		case 2:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_Q_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_S_BASE, decode.Rn);
			instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			instruction->operands[2].elementSize = 4;
			instruction->operands[2].dataSize = 4;
			break;
		case 4:
		case 5:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_Q_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_Q_BASE, decode.Rn);
			instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			instruction->operands[2].elementSize = 4;
			instruction->operands[2].dataSize = 4;
			break;
		case 3:
		case 6:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			instruction->operands[0].elementSize = 4;
			instruction->operands[0].dataSize = 4;
			instruction->operands[1].elementSize = 4;
			instruction->operands[1].dataSize = 4;
			instruction->operands[2].elementSize = 4;
			instruction->operands[2].dataSize = 4;
			break;
		default:
			return 1;
	}
	return decode.size != 0;
}


uint32_t aarch64_decompose_cryptographic_aes(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.19 Cryptographic AES
	 *
	 * AESE   <Vd>.16B, <Vn>.16B
	 * AESD   <Vd>.16B, <Vn>.16B
	 * AESMC  <Vd>.16B, <Vn>.16B
	 * AESIMC <Vd>.16B, <Vn>.16B
	 */
	CRYPTOGRAPHIC_AES decode = *(CRYPTOGRAPHIC_AES*)&instructionValue;
	static const Operation operation[8] = {
		ARM64_UNDEFINED,
		ARM64_UNDEFINED,
		ARM64_UNDEFINED,
		ARM64_UNDEFINED,
		ARM64_AESE,
		ARM64_AESD,
		ARM64_AESMC,
		ARM64_AESIMC,
	};
	instruction->operation = operation[decode.opcode&7];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[0].elementSize = 1;
	instruction->operands[0].dataSize = 16;
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[1].elementSize = 1;
	instruction->operands[1].dataSize = 16;

	return decode.size != 0 || decode.opcode > 7;
}


uint32_t aarch64_decompose_data_processing_1(uint32_t instructionValue, Instruction* restrict instruction)
{
	DATA_PROCESSING_1 decode = *(DATA_PROCESSING_1 *) &instructionValue;
	POINTER_AUTH pac = *(POINTER_AUTH *) &instructionValue;

	/* C4.5.7 Data-processing (1 source)
	 *
	 * RBIT <Wd>, <Wn>
	 * RBIT <Xd>, <Xn>
	 * REV16 <Wd>, <Wn>
	 * REV16 <Xd>, <Xn>
	 * REV <Wd>, <Wn>
	 * REV <Xd>, <Xn>
	 * CLZ <Wd>, <Wn>
	 * CLZ <Xd>, <Xn>
	 * CLS <Wd>, <Wn>
	 * CLS <Xd>, <Xn>
	 */
	static const Operation operation[2][8] = {
		{ARM64_RBIT, ARM64_REV16, ARM64_REV,   ARM64_UNDEFINED, ARM64_CLZ, ARM64_CLS, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_RBIT, ARM64_REV16, ARM64_REV32, ARM64_REV, ARM64_CLZ, ARM64_CLS, ARM64_UNDEFINED, ARM64_UNDEFINED}
	};

	static const Operation pacOperation[2][8] = {
		{ARM64_PACIA,  ARM64_PACIB,  ARM64_PACDA,  ARM64_PACDB,  ARM64_AUTIA,  ARM64_AUTIB,  ARM64_AUTDA,  ARM64_AUTDB},
		{ARM64_PACIZA, ARM64_PACIZB, ARM64_PACDZA, ARM64_PACDZB, ARM64_AUTIZA, ARM64_AUTIZB, ARM64_AUTDZA, ARM64_AUTDZB},
	};

	switch (decode.opcode2)
	{
	case 0:
		if (decode.opcode > 5)
			return 1;
		instruction->operation = operation[decode.sf][decode.opcode];
		instruction->operands[0].operandClass = REG;
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
		instruction->operands[1].operandClass = REG;
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
		return decode.S != 0 || decode.opcode2 != 0 || instruction->operation == ARM64_UNDEFINED;
	case 1:
		if ((decode.opcode > 17) || (decode.sf != 1))
			return 1;
		switch (decode.opcode)
		{
			default: instruction->operation = pacOperation[pac.Z][pac.group1]; break;
			case 16: instruction->operation = ARM64_XPACI; break;
			case 17: instruction->operation = ARM64_XPACD; break;
		}
		instruction->operands[0].operandClass = REG;
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], pac.Rd);
		if (decode.opcode < 8)
		{
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(REGSET_SP, regSize[decode.sf], pac.Rn);
		}
		return (decode.opcode >= 8) && (pac.Rn != 0x1f);
	default:
		return 1;
	}
}


uint32_t aarch64_decompose_data_processing_2(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.8 Data-processing (2 source)
	 *
	 * UDIV <Wd>, <Wn>, <Wm>
	 * UDIV <Xd>, <Xn>, <Xm>
	 * SDIV <Wd>, <Wn>, <Wm>
	 * SDIV <Wd>, <Wn>, <Wm>
	 * LSLV <Wd>, <Wn>, <Wm>
	 * LSLV <Xd>, <Xn>, <Xm>
	 * LSRV <Wd>, <Wn>, <Wm>
	 * LSRV <Xd>, <Xn>, <Xm>
	 * ASRV <Wd>, <Wn>, <Wm>
	 * ASRV <Xd>, <Xn>, <Xm>
	 * RORV <Wd>, <Wn>, <Wm>
	 * RORV <Xd>, <Xn>, <Xm>
	 * CRC32B <Wd>, <Wn>, <Wm>
	 * CRC32H <Wd>, <Wn>, <Wm>
	 * CRC32W <Wd>, <Wn>, <Wm>
	 * CRC32X <Wd>, <Wn>, <Xm>
	 * CRC32CB <Wd>, <Wn>, <Wm>
	 * CRC32CH <Wd>, <Wn>, <Wm>
	 * CRC32CW <Wd>, <Wn>, <Wm>
	 * CRC32CX <Wd>, <Wn>, <Xm>
	 * SUBP <Xd>, <Xn|SP>, <Xm|SP>
	 * SUBPS <Xd>, <Xn|SP>, <Xm|SP>
	 */
	static const Operation operation[2][32] = {
		{
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UDIV,      ARM64_SDIV,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_LSL,       ARM64_LSR,       ARM64_ASR,       ARM64_ROR,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_CRC32B,    ARM64_CRC32H,    ARM64_CRC32W,    ARM64_UNDEFINED,
			ARM64_CRC32CB,   ARM64_CRC32CH,   ARM64_CRC32CW,   ARM64_UNDEFINED,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
		},{
			ARM64_SUBP,      ARM64_UNDEFINED, ARM64_UDIV,      ARM64_SDIV,
			ARM64_IRG,       ARM64_GMI,       ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_LSL,       ARM64_LSR,       ARM64_ASR,       ARM64_ROR,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_CRC32X,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_CRC32CX,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
			ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
		}
	};
	DATA_PROCESSING_2 decode = *(DATA_PROCESSING_2*)&instructionValue;
	if (decode.opcode > 31)
		return 1;
	if (decode.S) {
		if (decode.opcode != 0 || decode.sf != 1)
			return 1;
		instruction->operation = ARM64_SUBPS;
	}
	else {
		instruction->operation = operation[decode.sf][decode.opcode];
	}
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);

	switch(instruction->operation) {
		case ARM64_CRC32X:
		case ARM64_CRC32CX:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rn);
			break;
		case ARM64_IRG:
			if(decode.Rm == 0x1f)
				instruction->operands[2].operandClass = NONE;
			/* intended fall-through */
		case ARM64_SUBP:
		case ARM64_SUBPS:
			instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
			instruction->operands[2].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rm);
			break;
		case ARM64_GMI:
			instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
		default:
			break;
	}

	// aliases
	if(instruction->operation == ARM64_SUBPS && decode.S == 1 && decode.Rd == 0x1f) {
		instruction->operation = ARM64_CMPP;
		instruction->operands[0] = instruction->operands[1];
		instruction->operands[1] = instruction->operands[2];
		instruction->operands[2].operandClass = NONE;
	}

	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_data_processing_3(uint32_t instructionValue, Instruction* restrict instruction)
{
	DATA_PROCESSING_3 decode = *(DATA_PROCESSING_3*)&instructionValue;
	static const Operation operation[8][2] = {
		{ARM64_MADD,	   ARM64_MSUB},
		{ARM64_SMADDL,	 ARM64_SMSUBL},
		{ARM64_SMULH,	  ARM64_UNDEFINED},
		{ARM64_UNDEFINED,  ARM64_UNDEFINED},
		{ARM64_UNDEFINED,  ARM64_UNDEFINED},
		{ARM64_UMADDL, ARM64_UMSUBL},
		{ARM64_UMULH,  ARM64_UNDEFINED},
		{ARM64_UNDEFINED,  ARM64_UNDEFINED}
	};
	if (decode.op31 != 0 && decode.sf == 0)
		return 1;

	instruction->operation = operation[decode.op31][decode.o0];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	if (decode.op31 == 1 || decode.op31 == 5)
	{
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rn);
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_W_BASE, decode.Rm);
	}
	else
	{
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
		instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	}
	instruction->operands[3].operandClass = REG;
	instruction->operands[3].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Ra);
	if (decode.Ra == 31)
	{
		uint32_t hasAlias = 1;
		switch (instruction->operation)
		{
			case ARM64_MADD:	instruction->operation = ARM64_MUL; break;
			case ARM64_MSUB:	instruction->operation = ARM64_MNEG; break;
			case ARM64_SMADDL:  instruction->operation = ARM64_SMULL; break;
			case ARM64_SMSUBL:  instruction->operation = ARM64_SMNEGL; break;
			case ARM64_UMADDL:  instruction->operation = ARM64_UMULL; break;
			case ARM64_UMSUBL:  instruction->operation = ARM64_UMNEGL; break;
			case ARM64_UMULH:
			case ARM64_SMULH:
				/*Just so we delete the extra operand*/
				break;
			default:
				hasAlias = 0;
		}
		if (hasAlias == 1)
		{
			instruction->operands[3].operandClass = NONE;
			instruction->operands[3].reg[0] = REG_NONE;
		}
	}
	return instruction->operation == ARM64_UNDEFINED || decode.op54 != 0;
}


uint32_t aarch64_decompose_exception_generation(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.2.3  - Exception generation
	 *
	 * SVC #<imm>
	 * HVC #<imm>
	 * SMC #<imm>
	 * BRK #<imm>
	 * HLT #<imm>
	 * DCPS1 {#<imm>}
	 * DCPS2 {#<imm>}
	 * DCPS3 {#<imm>}
	 */
	EXCEPTION_GENERATION decode = *(EXCEPTION_GENERATION*)&instructionValue;
	static const Operation operation[8][4] = {
		{ARM64_UNDEFINED, ARM64_SVC,       ARM64_HVC,       ARM64_SMC},
		{ARM64_BRK,       ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_HLT,       ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_DCPS1,     ARM64_DCPS2,     ARM64_DCPS3},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
	};
	instruction->operation = operation[decode.opc][decode.LL];
	instruction->operands[0].operandClass = IMM32;
	instruction->operands[0].immediate = decode.imm;
	if (decode.opc == 5 && decode.imm == 0)
		instruction->operands[0].operandClass = NONE;

	return instruction->operation == ARM64_UNDEFINED || decode.op2 != 0;
}


uint32_t aarch64_decompose_extract(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.4.3 Extract
	 *
	 * EXTR <Wd>, <Wn>, <Wm>, #<lsb>
	 * EXTR <Xd>, <Xn>, <Xm>, #<lsb>
	 * ROR <Wd>, <Ws>, #<shift> -> EXTR <Wd>, <Ws>, <Ws>, #<shift>
	 * ROR <Xd>, <Xs>, #<shift> -> EXTR <Xd>, <Xs>, <Xs>, #<shift>
	 */

	EXTRACT decode = *(EXTRACT*)&instructionValue;
	instruction->operation = ARM64_EXTR;
	if (decode.sf != decode.N)
		return 1;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	instruction->operands[3].operandClass = IMM32;
	instruction->operands[3].immediate = decode.imms;
	if (decode.Rn == decode.Rm)
	{
		instruction->operation = ARM64_ROR;
		delete_operand(instruction->operands, 2, 4);
	}
	return (decode.sf == 0 && decode.imms > 32);
}


uint32_t aarch64_decompose_fixed_floating_conversion(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.29 Conversion between floating-point and fixed-point
	 *
	 * SCVTF  <Sd>, <Wn>, #<fbits>
	 * SCVTF  <Dd>, <Wn>, #<fbits>
	 * SCVTF  <Sd>, <Xn>, #<fbits>
	 * SCVTF  <Dd>, <Xn>, #<fbits>
	 * UCVTF  <Sd>, <Wn>, #<fbits>
	 * UCVTF  <Dd>, <Wn>, #<fbits>
	 * UCVTF  <Sd>, <Xn>, #<fbits>
	 * UCVTF  <Dd>, <Xn>, #<fbits>
	 *
	 * FCVTZS <Wd>, <Sn>, #<fbits>
	 * FCVTZS <Xd>, <Sn>, #<fbits>
	 * FCVTZS <Wd>, <Dn>, #<fbits>
	 * FCVTZS <Xd>, <Dn>, #<fbits>
	 * FCVTZU <Wd>, <Sn>, #<fbits>
	 * FCVTZU <Xd>, <Sn>, #<fbits>
	 * FCVTZU <Wd>, <Dn>, #<fbits>
	 * FCVTZU <Xd>, <Dn>, #<fbits>
	 */
	/*ERROR: Oracle: 'scvtf	s22, s13, #0x20'
	 * ERROR: You:	'scvtf	h22, h13, #0x20'
	 * ERROR: Oracle: 'scvtf	d21, d12, #0x40'
	 * ERROR: You:	'scvtf	h21, h12, #0x40'
	 * ERROR: Oracle: 'fcvtzs	s21, s12, #1'
	 * ERROR: You:	'fcvtzs	b21, b12, #0x1'
	 *
	 */
	FLOATING_FIXED_CONVERSION decode = *(FLOATING_FIXED_CONVERSION*)&instructionValue;
	static const Operation operation[4] = {ARM64_FCVTZS, ARM64_FCVTZU, ARM64_SCVTF, ARM64_UCVTF};
	static const uint32_t sdReg[2] = {REG_S_BASE, REG_D_BASE};
	instruction->operation = operation[decode.opcode&3];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = 64-decode.scale;
	if (decode.opcode <= 1)
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, sdReg[decode.type&1], decode.Rn);
	}
	else
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, sdReg[decode.type&1], decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	}
	return (decode.sf == 0 && (decode.scale >> 5) == 0) || decode.type > 1 || decode.opcode > 3;
}


uint32_t aarch64_decompose_floating_compare(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.22 Floating-point compare
	 *
	 * FCMP  <Sn>, <Sm>
	 * FCMP  <Dn>, <Dm>
	 * FCMPE <Sn>, <Sm>
	 * FCMPE <Dn>, <Dm>
	 * FCMP  <Sn>, #0.0
	 * FCMP  <Dn>, #0.0
	 * FCMPE <Sn>, #0.0
	 * FCMPE <Dn>, #0.0
	 */
	static const Operation operation[2] = {ARM64_FCMP, ARM64_FCMPE};
	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	FLOATING_COMPARE decode = *(FLOATING_COMPARE*)&instructionValue;
	instruction->operation = operation[(decode.opcode2 >> 4) & 1];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	if (((decode.opcode2 >> 3) & 1) == 1)
	{
		//zero variant
		float f = 0.0;
		instruction->operands[1].operandClass = FIMM32;
		instruction->operands[1].immediate = *(uint32_t*)&f;
	}
	else
	{
		instruction->operands[1].operandClass = REG;
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rm);
	}
	return decode.M != 0 || decode.S != 0 || decode.op != 0 || decode.type > 1 || (decode.opcode2 & (~0x18)) != 0;
}


uint32_t aarch64_decompose_floating_conditional_compare(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.23 Floating-point conditional compare
	 *
	 * FCCMP  <Sn>, <Sm>, #<nzcv>, <cond>
	 * FCCMP  <Dn>, <Dm>, #<nzcv>, <cond>
	 * FCCMPE <Sn>, <Sm>, #<nzcv>, <cond>
	 * FCCMPE <Dn>, <Dm>, #<nzcv>, <cond>
	 */

	FLOATING_CONDITIONAL_COMPARE decode = *(FLOATING_CONDITIONAL_COMPARE*)&instructionValue;
	static const Operation operation[2] = {ARM64_FCCMP, ARM64_FCCMPE};
	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rm);
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].immediate = decode.nzvb;

	instruction->operands[3].operandClass = CONDITION;
	instruction->operands[3].reg[0] = (Register)decode.cond;
	return decode.S != 0 || decode.M != 0 || decode.type > 1;
}


uint32_t aarch64_decompose_floating_cselect(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.24 Floating-point conditional select
	 *
	 * FCSEL <Sd>, <Sn>, <Sm>, <cond>
	 * FCSEL <Dd>, <Dn>, <Dm>, <cond>
	 */

	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	FLOATING_CONDITIONAL_SELECT decode = *(FLOATING_CONDITIONAL_SELECT*)&instructionValue;
	instruction->operation = ARM64_FCSEL;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	instruction->operands[2].operandClass = REG;
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rm);
	instruction->operands[3].operandClass = CONDITION;
	instruction->operands[3].reg[0] = (Register)decode.cond;
	return decode.M != 0 || decode.S != 0 || decode.type > 1;
}


uint32_t aarch64_decompose_floating_data_processing1(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.25 Floating-point data-processing (1 source)
	 *
	 * FMOV   <Sd>, <Sn>
	 * FABS   <Sd>, <Sn>
	 * FNEG   <Sd>, <Sn>
	 * FSQRT  <Sd>, <Sn>
	 * FCVT   <Sd>, <Hn>
	 * FCVT   <Hd>, <Sn>
	 * FCVT   <Hd>, <Dn>
	 * FCVT   <Sd>, <Dn>
	 * FRINTN <Sd>, <Sn>
	 * FRINTP <Sd>, <Sn>
	 * FRINTM <Sd>, <Sn>
	 * FRINTZ <Sd>, <Sn>
	 * FRINTA <Sd>, <Sn>
	 * FRINTX <Sd>, <Sn>
	 * FRINTI <Sd>, <Sn>
	 * FMOV   <Dd>, <Dn>
	 * FABS   <Dd>, <Dn>
	 * FNEG   <Dd>, <Dn>
	 * FSQRT  <Dd>, <Dn>
	 * FRINTN <Dd>, <Dn>
	 * FRINTP <Dd>, <Dn>
	 * FRINTM <Dd>, <Dn>
	 * FRINTZ <Dd>, <Dn>
	 * FRINTA <Dd>, <Dn>
	 * FRINTX <Dd>, <Dn>
	 * FRINTI <Dd>, <Dn>
	 * FCVT   <Dd>, <Hn>
	 * FCVT   <Dd>, <Sn>
	 */

	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	FLOATING_DATA_PROCESSING_1 decode = *(FLOATING_DATA_PROCESSING_1*)&instructionValue;
	static const Operation operation[16] = {
		ARM64_FMOV,   ARM64_FABS,      ARM64_FNEG,      ARM64_FSQRT,
		ARM64_FCVT,   ARM64_FCVT,      ARM64_UNDEFINED, ARM64_FCVT,
		ARM64_FRINTN, ARM64_FRINTP,    ARM64_FRINTM,    ARM64_FRINTZ,
		ARM64_FRINTA, ARM64_UNDEFINED, ARM64_FRINTX,    ARM64_FRINTI
	};
	instruction->operation = operation[decode.opcode & 0xf];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	if ((decode.type == 3 && (decode.opcode == 4 || decode.opcode == 5)) || instruction->operation == ARM64_FCVT)
	{
		static const uint32_t regChoiceCVT[4] = {REG_S_BASE, REG_D_BASE, (uint32_t)-1, REG_H_BASE};
		uint32_t regBase0 = regChoiceCVT[decode.opcode & 3];
		uint32_t regBase1 = regChoiceCVT[decode.type];
		if (regBase0 == (uint32_t)-1 || regBase1 == (uint32_t)-1)
			return 1;

		instruction->operation = ARM64_FCVT;
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regBase0, decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regBase1, decode.Rn);
	}
	else
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	}
	return decode.M != 0 || decode.S != 0 || decode.opcode > 15 || instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_floating_data_processing2(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.26  Floating-point data-processing (2 source)
	 *
	 * FMUL   <Sd>, <Sn>, <Sm>
	 * FDIV   <Sd>, <Sn>, <Sm>
	 * FADD   <Sd>, <Sn>, <Sm>
	 * FSUB   <Sd>, <Sn>, <Sm>
	 * FMAX   <Sd>, <Sn>, <Sm>
	 * FMIN   <Sd>, <Sn>, <Sm>
	 * FMAXNM <Sd>, <Sn>, <Sm>
	 * FMINNM <Sd>, <Sn>, <Sm>
	 * FNMUL  <Sd>, <Sn>, <Sm>
	 *
	 * FMUL   <Dd>, <Dn>, <Dm>
	 * FDIV   <Dd>, <Dn>, <Dm>
	 * FADD   <Dd>, <Dn>, <Dm>
	 * FSUB   <Dd>, <Dn>, <Dm>
	 * FMAX   <Dd>, <Dn>, <Dm>
	 * FMIN   <Dd>, <Dn>, <Dm>
	 * FMAXNM <Dd>, <Dn>, <Dm>
	 * FMINNM <Dd>, <Dn>, <Dm>
	 * FNMUL  <Dd>, <Dn>, <Dm>
	 */
	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	static const Operation operation[16] = {
		ARM64_FMUL,      ARM64_FDIV,      ARM64_FADD,      ARM64_FSUB,
		ARM64_FMAX,      ARM64_FMIN,      ARM64_FMAXNM,    ARM64_FMINNM,
		ARM64_FNMUL,     ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED,
		ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
	};
	FLOATING_DATA_PROCESSING_2 decode = *(FLOATING_DATA_PROCESSING_2*)&instructionValue;
	instruction->operation = operation[decode.opcode];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rm);
	return decode.M != 0 || decode.S != 0 || decode.type > 1 || decode.opcode > 8;
}


uint32_t aarch64_decompose_floating_data_processing3(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.27 Floating-point data-processing (3 source)
	 *
	 * FMADD  <Sd>, <Sn>, <Sm>, <Sa>
	 * FMSUB  <Sd>, <Sn>, <Sm>, <Sa>
	 * FNMADD <Sd>, <Sn>, <Sm>, <Sa>
	 * FNMSUB <Sd>, <Sn>, <Sm>, <Sa>
	 * FMADD  <Dd>, <Dn>, <Dm>, <Da>
	 * FMSUB  <Dd>, <Dn>, <Dm>, <Da>
	 * FNMADD <Dd>, <Dn>, <Dm>, <Da>
	 * FNMSUB <Dd>, <Dn>, <Dm>, <Da>
	 */
	static const Operation operation[2][2] = {
		{ARM64_FMADD, ARM64_FMSUB  },
		{ARM64_FNMADD, ARM64_FNMSUB}
	};
	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	FLOATING_DATA_PROCESSING_3 decode = *(FLOATING_DATA_PROCESSING_3*)&instructionValue;
	instruction->operation = operation[decode.o1][decode.o0];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[3].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rm);
	instruction->operands[3].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Ra);

	return decode.M != 0 || decode.S != 0 || decode.type > 1;
}


uint32_t VFPExpandImm(uint32_t imm8)
{
	ieee754 t;
	uint32_t bit6 = (imm8>>6) & 1;
	uint32_t bit54 = (imm8>>4) & 3;
	uint32_t x = bit6?0x1f:0;

	t.sign = imm8>>7;
	t.exponent = (~bit6) << 7 | x << 2 | bit54;
	t.fraction = (imm8 & 0xf) << 19;
	return *(uint32_t*)&t;
}


uint32_t aarch64_decompose_floating_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.28 Floating-point immediate
	 *
	 * FMOV <Sd>, #<imm>
	 * FMOV <Dd>, #<imm>
	 */
	static const uint32_t regChoice[2] = {REG_S_BASE, REG_D_BASE};
	FLOATING_IMM decode = *(FLOATING_IMM*)&instructionValue;
	instruction->operation = ARM64_FMOV;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = FIMM32;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.type&1], decode.Rd);
	instruction->operands[1].immediate = VFPExpandImm(decode.imm8);
	return decode.imm5 != 0 || decode.type > 1 || decode.M != 0 || decode.S != 0;
}


uint32_t aarch64_decompose_floating_integer_conversion(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.30 Conversion between floating-point and integer
	 *
	 * FCVTNS <Wd>, <Sn>
	 * FCVTNS <Xd>, <Sn>
	 * FCVTNS <Wd>, <Dn>
	 * FCVTNS <Xd>, <Dn>
	 * FCVTNU <Wd>, <Sn>
	 * FCVTNU <Xd>, <Sn>
	 * FCVTNU <Wd>, <Dn>
	 * FCVTNU <Xd>, <Dn>
	 * FCVTAS <Wd>, <Sn>
	 * FCVTAS <Xd>, <Sn>
	 * FCVTAS <Wd>, <Dn>
	 * FCVTAS <Xd>, <Dn>
	 * FCVTAU <Wd>, <Sn>
	 * FCVTAU <Xd>, <Sn>
	 * FCVTAU <Wd>, <Dn>
	 * FCVTAU <Xd>, <Dn>
	 * FCVTPS <Wd>, <Sn>
	 * FCVTPS <Xd>, <Sn>
	 * FCVTPS <Wd>, <Dn>
	 * FCVTPS <Xd>, <Dn>
	 * FCVTPU <Wd>, <Sn>
	 * FCVTPU <Xd>, <Sn>
	 * FCVTPU <Wd>, <Dn>
	 * FCVTPU <Xd>, <Dn>
	 * FCVTMS <Wd>, <Sn>
	 * FCVTMS <Xd>, <Sn>
	 * FCVTMS <Wd>, <Dn>
	 * FCVTMS <Xd>, <Dn>
	 * FCVTMU <Wd>, <Sn>
	 * FCVTMU <Xd>, <Sn>
	 * FCVTMU <Wd>, <Dn>
	 * FCVTMU <Xd>, <Dn>
	 * FCVTZS <Wd>, <Sn>
	 * FCVTZS <Xd>, <Sn>
	 * FCVTZS <Wd>, <Dn>
	 * FCVTZS <Xd>, <Dn>
	 * FCVTZU <Wd>, <Sn>
	 * FCVTZU <Xd>, <Sn>
	 * FCVTZU <Wd>, <Dn>
	 * FCVTZU <Xd>, <Dn>
	 *
	 * SCVTF  <Sd>, <Wn>
	 * SCVTF  <Dd>, <Wn>
	 * SCVTF  <Sd>, <Xn>
	 * SCVTF  <Dd>, <Xn>
	 * UCVTF  <Sd>, <Wn>
	 * UCVTF  <Dd>, <Wn>
	 * UCVTF  <Sd>, <Xn>
	 * UCVTF  <Dd>, <Xn>
	 *
	 * FMOV   <Sd>, <Wn>
	 * FMOV   <Wd>, <Sn>
	 * FMOV   <Xd>, <Dn>
	 * FMOV   <Dd>, <Xn>
	 * FMOV   <Vd>.D[1], <Xn>
	 * FMOV   <Xd>, <Vn>.D[1]
	 */
	static const Operation operation[2][4][8] = {
		{
			{
			 ARM64_FCVTNS, ARM64_FCVTNU, ARM64_SCVTF, ARM64_UCVTF,
			 ARM64_FCVTAS, ARM64_FCVTAU, ARM64_FMOV,  ARM64_FMOV
			},{
			 ARM64_FCVTPS,    ARM64_FCVTPU,    ARM64_UNDEFINED, ARM64_UNDEFINED,
			 ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
			 ARM64_FCVTMS,    ARM64_FCVTMU,    ARM64_UNDEFINED, ARM64_UNDEFINED,
			 ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
			 ARM64_FCVTZS,    ARM64_FCVTZU,    ARM64_SCVTF,     ARM64_UCVTF,
			 ARM64_FCVTAS,    ARM64_FCVTAU,    ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		},{
			{
			 ARM64_FCVTNS,  ARM64_FCVTNU,  ARM64_SCVTF, ARM64_UCVTF,
			 ARM64_FCVTAS,  ARM64_FCVTAU,  ARM64_FMOV,  ARM64_FMOV
			},{
			 ARM64_FCVTPS,    ARM64_FCVTPU,    ARM64_UNDEFINED, ARM64_UNDEFINED,
			 ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
			 ARM64_FCVTMS,    ARM64_FCVTMU,    ARM64_UNDEFINED, ARM64_UNDEFINED,
			 ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
			 ARM64_FCVTZS,    ARM64_FCVTZU,    ARM64_UNDEFINED, ARM64_UNDEFINED,
			 ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		}
	};

	static const uint32_t srcReg[2] =  {REG_S_BASE, REG_D_BASE};
	static const uint32_t dstReg[2] = {REG_W_BASE, REG_X_BASE};
	FLOATING_INTEGER_CONVERSION decode = *(FLOATING_INTEGER_CONVERSION*)&instructionValue;
	instruction->operation = operation[decode.type & 1][decode.rmode][decode.opcode];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	if (decode.type == 2 && decode.sf == 1 && decode.rmode == 1 && decode.opcode >= 6)
	{
		instruction->operation = ARM64_FMOV;
	}

	switch (instruction->operation)
	{
		case ARM64_SCVTF:
		case ARM64_UCVTF:
			{
				static const uint32_t sdReg[2] = {REG_S_BASE, REG_D_BASE};
				static const uint32_t wxReg[2] = {REG_W_BASE, REG_X_BASE};
				instruction->operands[0].reg[0] = REG(REGSET_ZR, sdReg[decode.type&1], decode.Rd);
				instruction->operands[1].reg[0] = REG(REGSET_ZR, wxReg[decode.sf], decode.Rn);
			}
			break;
		case ARM64_FMOV:
			if (decode.sf == 0)
			{
				static const uint32_t swReg[2] = {REG_W_BASE, REG_S_BASE};
				instruction->operands[0].reg[0] = REG(REGSET_ZR, swReg[decode.opcode&1], decode.Rd);
				instruction->operands[1].reg[0] = REG(REGSET_ZR, swReg[!(decode.opcode&1)], decode.Rn);
			}
			else
			{
				uint32_t reg1 = 1^(decode.opcode & 1);
				uint32_t reg2 = decode.opcode & 1;
				static const uint32_t vxReg[2] = {REG_V_BASE, REG_X_BASE};
				static const uint32_t dxReg[2] = {REG_D_BASE, REG_X_BASE};
				if (decode.rmode == 1)
				{
					instruction->operands[reg1].index = 1;
					instruction->operands[reg1].elementSize = 8;
					instruction->operands[0].reg[0] = REG(REGSET_ZR, vxReg[reg1], decode.Rd);
					instruction->operands[1].reg[0] = REG(REGSET_ZR, vxReg[reg2], decode.Rn);
					instruction->operands[reg1].scale = (0x80000000 | 1);
				}
				else
				{
					instruction->operands[0].reg[0] = REG(REGSET_ZR, dxReg[reg1], decode.Rd);
					instruction->operands[1].reg[0] = REG(REGSET_ZR, dxReg[reg2], decode.Rn);
				}
			}
			break;
		default:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, dstReg[decode.sf], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, srcReg[decode.type&1], decode.Rn);
			break;
	}
	return decode.S != 0 || instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_register_literal(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/* C4.3.5 Load register (literal)
	 *
	 * LDR <Wt>, <label>
	 * LDR <Xt>, <label>
	 * LDR <St>, <label>
	 * LDR <Dt>, <label>
	 * LDR <Qt>, <label>
	 * LDRSW <Xt>, <label>
	 * PRFM <prfop>, <label>
	 */
	LOAD_REGISTER_LITERAL decode = *(LOAD_REGISTER_LITERAL*)&instructionValue;
	struct option {
		Operation operation;
		uint32_t regBase;
		uint32_t signedImm;
	};
	static const struct option operand[2][4] = {
		{
			{ARM64_LDR,   REG_W_BASE, 0},
			{ARM64_LDR,   REG_X_BASE, 0},
			{ARM64_LDRSW, REG_X_BASE, 1},
			{ARM64_PRFM,  REG_W_BASE, 0}
		},{
			{ARM64_LDR,   REG_S_BASE, 0},
			{ARM64_LDR,   REG_D_BASE, 0},
			{ARM64_LDR,   REG_Q_BASE, 0},
			{ARM64_UNDEFINED, 0,	  0}
		}
	};
	const struct option* op = &operand[decode.V][decode.opc];
	instruction->operation = op->operation;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->regBase, decode.Rt);

	instruction->operands[1].operandClass = LABEL;
	instruction->operands[1].signedImm = op->signedImm;
	if (op->signedImm)
		instruction->operands[1].immediate = address - (decode.imm << 2);
	else
		instruction->operands[1].immediate = address + (decode.imm << 2);

	return instruction->operation == ARM64_UNDEFINED;
}

uint32_t aarch64_decompose_load_store_mem_tags(uint32_t instructionValue, Instruction* restrict instruction)
{
	/*
	 * STG <Xt|SP>, [<Xn|SP>], #<simm> // post-index
	 * STG <Xt|SP>, [<Xn|SP>, #<simm>]! // pre-index
	 * STG <Xt|SP>, [<Xn|SP>{, #<simm>}] // signed offset
	 *
	 * STZGM <Xt>, [<Xn|SP>]
	 *
	 * LDG <Xt>, [<Xn|SP>{, #<simm>}]
	 *
	 * STZG <Xt|SP>, [<Xn|SP>], #<simm>
	 * STZG <Xt|SP>, [<Xn|SP>, #<simm>]!
	 * STZG <Xt|SP>, [<Xn|SP>{, #<simm>}]
	 *
	 * ST2G <Xt|SP>, [<Xn|SP>], #<simm>
	 * ST2G <Xt|SP>, [<Xn|SP>, #<simm>]!
	 * ST2G <Xt|SP>, [<Xn|SP>{, #<simm>}]
	 *
	 * STGM <Xt>, [<Xn|SP>]
	 *
	 * STZ2G <Xt|SP>, [<Xn|SP>], #<simm>
	 * STZ2G <Xt|SP>, [<Xn|SP>, #<simm>]!
	 * STZ2G <Xt|SP>, [<Xn|SP>{, #<simm>}]
	 *
	 * LDGM <Xt>, [<Xn|SP>]
	 */

	LDST_TAGS decode = *(LDST_TAGS*)&instructionValue;

	static const Operation operation[4][2][4] = {
		{{	ARM64_STZGM, ARM64_STG, ARM64_STG, ARM64_STG		},
		 {	ARM64_UNDEFINED, ARM64_STG, ARM64_STG, ARM64_STG	}
		},
		{{	ARM64_LDG, ARM64_STZG, ARM64_STZG, ARM64_STZG		},
		 {	ARM64_LDG, ARM64_STZG, ARM64_STZG, ARM64_STZG		}
		},
		{{	ARM64_STGM, ARM64_ST2G, ARM64_ST2G, ARM64_ST2G,		},
		 {	ARM64_UNDEFINED, ARM64_ST2G, ARM64_ST2G, ARM64_ST2G }
		},
		{{	ARM64_LDGM, ARM64_STZ2G, ARM64_STZ2G, ARM64_STZ2G,	},
		 {	ARM64_UNDEFINED, ARM64_STZ2G, ARM64_STZ2G, ARM64_STZ2G	}
		}
	};

	instruction->operation = operation[decode.opc][!!(decode.imm9)][decode.op2];
	if(instruction->operation == ARM64_UNDEFINED)
		return 1;

	instruction->operands[0].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);

	switch((decode.opc<<2) | decode.op2) {
		case 0b0001: case 0b0101: case 0b1001: case 0b1101:
		case 0b0010: case 0b0110: case 0b1010: case 0b1110:
		case 0b0011: case 0b0111: case 0b1011: case 0b1111:
		case 0b0100:
			if(instruction->operation == ARM64_LDG)
				instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			else
				instruction->operands[0].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rt);

			instruction->operands[1].signedImm = 1;
			instruction->operands[1].immediate = (decode.imm9 << 4);
			if(decode.imm9 & 0x100)
				instruction->operands[1].immediate |= 0xFFFFFFFFFFFFF000;

			break;
		default:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			break;
	}

	switch((decode.opc<<2) | decode.op2) {
		/* post-index, like: MNEMONIC <Xt|SP> [<Xn|SP>], #<simm> */
		case 0b0001: case 0b0101: case 0b1001: case 0b1101:
			instruction->operands[1].operandClass = MEM_POST_IDX;
			break;
		/* signed-offset, like: MNEMONIC <Xt|SP>, [<Xn|SP>{, #<simm>}] */
		case 0b0010: case 0b0110: case 0b1010: case 0b1110: case 0b0100:
			instruction->operands[1].operandClass = MEM_OFFSET;
			break;
		/* pre-index, like: MNEMONIC <Xt|SP>, [<Xn|SP>{, #<simm>}]! */
		case 0b0011: case 0b0111: case 0b1011: case 0b1111:
			instruction->operands[1].operandClass = MEM_PRE_IDX;
			break;
		/* MNEMONIC <Xt>, [<Xn|SP>] */
		case 0b0000: case 0b1000: case 0b1100:
			instruction->operands[1].operandClass = MEM_REG;
	}

	return 0;
}

uint32_t aarch64_decompose_load_store_exclusive(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.6 Load/store exclusive
	 *
	 * STXRB  <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STLXRB <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STLRB  <Wt>, [<Xn|SP>{,#0}]
	 *
	 * STXRH  <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STLXRH <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STLRH  <Wt>, [<Xn|SP>{,#0}]
	 *
	 * STXR  <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STLXR <Ws>, <Wt>, [<Xn|SP>{,#0}]
	 * STXP  <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
	 * STLXP <Ws>, <Wt1>, <Wt2>, [<Xn|SP>{,#0}]
	 * STLR  <Wt>, [<Xn|SP>{,#0}]
	 *
	 * STXR  <Ws>, <Xt>, [<Xn|SP>{,#0}]
	 * STLXR <Ws>, <Xt>, [<Xn|SP>{,#0}]
	 * STXP  <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
	 * STLXP <Ws>, <Xt1>, <Xt2>, [<Xn|SP>{,#0}]
	 * STLR  <Xt>, [<Xn|SP>{,#0}]
 	*/
	LDST_EXCLUSIVE decode = *(LDST_EXCLUSIVE*)&instructionValue;
	uint32_t opcode = decode.o2 << 2 | decode.o1 << 1 | decode.o0;
	static const Operation operation[4][2][8] = {
		{
			{
				ARM64_STXRB, ARM64_STLXRB, ARM64_UNDEFINED, ARM64_UNDEFINED,
				ARM64_UNDEFINED, ARM64_STLRB, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
				ARM64_LDXRB, ARM64_LDAXRB, ARM64_UNDEFINED, ARM64_UNDEFINED,
				ARM64_UNDEFINED, ARM64_LDARB, ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		},{
			{
				ARM64_STXRH, ARM64_STLXRH, ARM64_UNDEFINED, ARM64_UNDEFINED,
				ARM64_UNDEFINED, ARM64_STLRH, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
				ARM64_LDXRH, ARM64_LDAXRH, ARM64_UNDEFINED, ARM64_UNDEFINED,
				ARM64_UNDEFINED, ARM64_LDARH, ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		},{
			{
				ARM64_STXR, ARM64_STLXR, ARM64_STXP, ARM64_STLXP,
				ARM64_UNDEFINED, ARM64_STLR, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
				ARM64_LDXR, ARM64_LDAXR, ARM64_LDXP, ARM64_LDAXP,
				ARM64_UNDEFINED, ARM64_LDAR, ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		},{
			{
				ARM64_STXR, ARM64_STLXR, ARM64_STXP, ARM64_STLXP,
				ARM64_UNDEFINED, ARM64_STLR, ARM64_UNDEFINED, ARM64_UNDEFINED
			},{
				ARM64_LDXR, ARM64_LDAXR, ARM64_LDXP, ARM64_LDAXP,
				ARM64_UNDEFINED, ARM64_LDAR, ARM64_UNDEFINED, ARM64_UNDEFINED
			}
		}
	};

	static const uint32_t regBase[] = {REG_W_BASE, REG_X_BASE};
	instruction->operation = operation[decode.size][decode.L][opcode];
	uint32_t i = 0;
	if (decode.size < 2)
	{
		instruction->operands[i].operandClass = REG;
		instruction->operands[(opcode==5||decode.L)?i:i++].reg[0]= REG(REGSET_ZR, REG_W_BASE, decode.Rs);
		instruction->operands[i].operandClass = REG;
		instruction->operands[i++].reg[0]= REG(REGSET_ZR, REG_W_BASE, decode.Rt);
		instruction->operands[i].operandClass = MEM_REG;
		instruction->operands[i].reg[0]= REG(REGSET_SP, REG_X_BASE, decode.Rn);
	}
	else
	{
		instruction->operands[i].operandClass = REG;
		instruction->operands[(opcode==5||decode.L)?i:i++].reg[0]= REG(REGSET_ZR, REG_W_BASE, decode.Rs);
		instruction->operands[i].operandClass = REG;
		instruction->operands[i++].reg[0]= REG(REGSET_ZR, regBase[decode.size == 3], decode.Rt);
		if (opcode == 2 || opcode == 3)
		{
			instruction->operands[i].operandClass = REG;
			instruction->operands[i++].reg[0]= REG(REGSET_ZR, regBase[decode.size == 3], decode.Rt2);
		}
		instruction->operands[i].operandClass = MEM_REG;
		instruction->operands[i].reg[0]= REG(REGSET_SP, REG_X_BASE, decode.Rn);
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_imm_post_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.8 Load/store register (immediate post-indexed)
	 *
	 * LDRB/STRB <Wt>, [<Xn|SP>], #<simm>	  //PI
	 * LDRSB	 <Xt>, [<Xn|SP>], #<simm>	 //64bit
	 * LDRSB	 <Wt>, [<Xn|SP>], #<simm>	 //32bit
	 * LDR/STR   <Bt>, [<Xn|SP>], #<simm>   //8bit
	 * LDR/STR   <Ht>, [<Xn|SP>], #<simm>   //16bit
	 * LDR/STR   <St>, [<Xn|SP>], #<simm>   //32bit
	 * LDR/STR   <Dt>, [<Xn|SP>], #<simm>   //64bit
	 * LDR/STR   <Qt>, [<Xn|SP>], #<simm>   //128bit
	 * LDRH/STRH <Wt>, [<Xn|SP>], #<simm>  //pi
	 * LDRSH	 <Wt>, [<Xn|SP>], #<simm>	 //32bit
	 * LDRSH	 <Xt>, [<Xn|SP>], #<simm>	 //64bit
	 * LDRSW	 <Xt>, [<Xn|SP>], #<simm>	 //pi
	 */

	LDST_REG_PAIR_POST_IDX decode = *(LDST_REG_PAIR_POST_IDX*)&instructionValue;
	struct opreg{
		Operation operation;
		uint32_t registerBase;
	};
	static const struct opreg operation[4][2][4] = {
		{
			{{ARM64_STRB, REG_W_BASE}, {ARM64_LDRB, REG_W_BASE} , {ARM64_LDRSB, REG_X_BASE}, {ARM64_LDRSB, REG_W_BASE}},
			{{ARM64_STR, REG_B_BASE}, {ARM64_LDR, REG_B_BASE}, {ARM64_STR, REG_Q_BASE}, {ARM64_LDR, REG_Q_BASE}}
		},{
			{{ARM64_STRH, REG_W_BASE}, {ARM64_LDRH, REG_W_BASE} , {ARM64_LDRSH, REG_X_BASE}, {ARM64_LDRSH, REG_W_BASE}},
			{{ARM64_STR, REG_H_BASE}, {ARM64_LDR, REG_H_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		},{
			{{ARM64_STR, REG_W_BASE}, {ARM64_LDR, REG_W_BASE}, {ARM64_LDRSW, REG_X_BASE}, {ARM64_UNDEFINED, 0}},
			{{ARM64_STR, REG_S_BASE}, {ARM64_LDR, REG_S_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		},{
			{{ARM64_STR, REG_X_BASE}, {ARM64_LDR, REG_X_BASE}, {ARM64_UNDEFINED,0}, {ARM64_UNDEFINED,0}},
			{{ARM64_STR, REG_D_BASE}, {ARM64_LDR, REG_D_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		}
	};
	const struct opreg* op =  &operation[decode.size][decode.V][decode.opc];
	instruction->operation = op->operation;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->registerBase, decode.Rt);

	instruction->operands[1].operandClass = MEM_POST_IDX;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.imm;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_reg_imm_pre_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	LDST_REG_IMM_PRE_IDX decode = *(LDST_REG_IMM_PRE_IDX*)&instructionValue;
	struct opreg{
		Operation operation;
		uint32_t registerBase;
	};

	/* C4.3.9 Load/store register (immediate pre-indexed)
	 *
	 * LDRB/STRB <Wt>, [<Xn|SP>, #<simm>]!
	 * LDRSB	 <Wt>, [<Xn|SP>, #<simm>]!	 //32bit
	 * LDRSB	 <Xt>, [<Xn|SP>, #<simm>]!	 //64bit
	 * LDR/STR   <Bt>, [<Xn|SP>, #<simm>]!
	 * LDR/STR   <Ht>, [<Xn|SP>, #<simm>]!
	 * LDR/STR   <St>, [<Xn|SP>, #<simm>]!
	 * LDR/STR   <Dt>, [<Xn|SP>, #<simm>]!
	 * LDR/STR   <Qt>, [<Xn|SP>, #<simm>]!
	 * LDRH/STRH <Wt>, [<Xn|SP>, #<simm>]!
	 * LDRSH	 <Wt>, [<Xn|SP>, #<simm>]!		   /32bit
	 * LDRSH	 <Xt>, [<Xn|SP>, #<simm>]!		   //64bit
	 * LDRSW	 <Xt>, [<Xn|SP>, #<simm>]!
	 */
	static const struct opreg operation[4][2][4] = {
		{
			{{ARM64_STRB, REG_W_BASE}, {ARM64_LDRB, REG_W_BASE} , {ARM64_LDRSB, REG_X_BASE}, {ARM64_LDRSB, REG_W_BASE}},
			{{ARM64_STR, REG_B_BASE}, {ARM64_LDR, REG_B_BASE}, {ARM64_STR, REG_Q_BASE}, {ARM64_LDR, REG_Q_BASE}}
		},{
			{{ARM64_STRH, REG_W_BASE}, {ARM64_LDRH, REG_W_BASE} , {ARM64_LDRSH, REG_X_BASE}, {ARM64_LDRSH, REG_W_BASE}},
			{{ARM64_STR, REG_H_BASE}, {ARM64_LDR, REG_H_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		},{
			{{ARM64_STR, REG_W_BASE}, {ARM64_LDR, REG_W_BASE}, {ARM64_LDRSW, REG_X_BASE}, {ARM64_UNDEFINED, 0}},
			{{ARM64_STR, REG_S_BASE}, {ARM64_LDR, REG_S_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		},{
			{{ARM64_STR, REG_X_BASE}, {ARM64_LDR, REG_X_BASE}, {ARM64_UNDEFINED,0}, {ARM64_UNDEFINED,0}},
			{{ARM64_STR, REG_D_BASE}, {ARM64_LDR, REG_D_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0}}
		}
	};
	const struct opreg* op =  &operation[decode.size][decode.V][decode.opc];
	instruction->operation = op->operation;

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->registerBase, decode.Rt);

	instruction->operands[1].operandClass = MEM_PRE_IDX;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.imm;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_pac(uint32_t instructionValue, Instruction* restrict instruction)
{
	static const Operation operation[] = {ARM64_LDRAA, ARM64_LDRAB};
	LDST_REG_IMM_PAC decode = *(LDST_REG_IMM_PAC *) &instructionValue;

	instruction->operation = operation[decode.M];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
	instruction->operands[1].operandClass = decode.W ? MEM_PRE_IDX : MEM_OFFSET;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.S ? ~0xfff : 0;
	instruction->operands[1].immediate |= decode.imm << decode.size;

	return 0;
}


uint32_t aarch64_decompose_load_store_no_allocate_pair_offset(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.7  Load/store no-allocate pair (offset)
	 *
	 * STNP <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * STNP <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * LDNP <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * LDNP <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * STNP <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * STNP <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * STNP <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 * LDNP <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * LDNP <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * LDNP <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 */
	LDST_NO_ALLOC_PAIR decode = *(LDST_NO_ALLOC_PAIR*)&instructionValue;
	static const Operation operation[2] = {ARM64_STNP, ARM64_LDNP};
	static const uint32_t regChoice[2][4] = {
		{REG_W_BASE, REG_X_BASE, REG_X_BASE, REG_X_BASE},
		{REG_S_BASE, REG_D_BASE, REG_Q_BASE, REG_Q_BASE},
	};
	uint32_t immShiftBase = (decode.V?decode.opc:(decode.opc>>1))+2;
	instruction->operation = operation[decode.L];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = MEM_OFFSET;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regChoice[decode.V][decode.opc], decode.Rt);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regChoice[decode.V][decode.opc], decode.Rt2);
	instruction->operands[2].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[2].immediate = ((int64_t)decode.imm) << immShiftBase;
	instruction->operands[2].signedImm = 1;
	return instruction->operation == ARM64_UNDEFINED || decode.opc > 2;
}


uint32_t aarch64_decompose_load_store_reg_imm_common(uint32_t instructionValue, Instruction* restrict instruction)
{
	/*C4.3.14 Load/store register pair (offset)
	 *
	 * STP   <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 * LDPSW <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * STGP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
	 *
	 */
	LDST_REG_PAIR_OFFSET decode = *(LDST_REG_PAIR_OFFSET*)&instructionValue;
	static const uint8_t shiftBase[] = {2,3};
	static const uint8_t simdShiftBase[] = {2,3,4};

	instruction->operands[2].signedImm = 1;
	if (instruction->operation == ARM64_LDPSW ||
		instruction->operation == ARM64_LDPSW ||
		instruction->operation == ARM64_LDPSW ||
		instruction->operation == ARM64_STGP)
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt2);
		instruction->operands[2].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
		instruction->operands[2].immediate = decode.imm <<
			((instruction->operation == ARM64_STGP) ? 4 : shiftBase[decode.opc>>1]);
	}
	else if (decode.V == 0)
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.opc>>1], decode.Rt);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.opc>>1], decode.Rt2);
		instruction->operands[2].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
		instruction->operands[2].immediate = decode.imm << shiftBase[decode.opc>>1];
	}
	else
	{
		if (decode.opc == 3)
			return 1;

		instruction->operands[0].reg[0] = REG(REGSET_ZR, simdRegSize[decode.opc], decode.Rt);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, simdRegSize[decode.opc], decode.Rt2);
		instruction->operands[2].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
		instruction->operands[2].immediate = decode.imm << simdShiftBase[decode.opc];
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_reg_pair_pre_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.16 Load/store register pair (pre-indexed)
	 *
	 * STP   <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
	 * STP   <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
	 * LDP   <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
	 * LDP   <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
	 * STP   <St1>, <St2>, [<Xn|SP>, #<imm>]!
	 * STP   <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
	 * STP   <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
	 * LDP   <St1>, <St2>, [<Xn|SP>, #<imm>]!
	 * LDP   <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]!
	 * LDP   <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]!
	 * LDPSW <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
	 */
	static const Operation operation[4][2][2] = {
		{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STGP, ARM64_LDPSW},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
		}
	};
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = MEM_PRE_IDX;

	LDST_REG_PAIR_OFFSET decode = *(LDST_REG_PAIR_OFFSET*)&instructionValue;
	instruction->operation = operation[decode.opc][decode.V][decode.L];
	return aarch64_decompose_load_store_reg_imm_common(instructionValue, instruction);
}


uint32_t aarch64_decompose_load_store_reg_pair_offset(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.14 Load/store register pair (offset)
	 *
	 * STP   <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * STP   <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <St1>, <St2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Dt1>, <Dt2>, [<Xn|SP>{, #<imm>}]
	 * LDP   <Qt1>, <Qt2>, [<Xn|SP>{, #<imm>}]
	 * LDPSW <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
	 */
	LDST_REG_PAIR_OFFSET decode = *(LDST_REG_PAIR_OFFSET*)&instructionValue;
	static const Operation operation[4][2][2] = {
		{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STGP, ARM64_LDPSW},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
		}
	};
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = MEM_OFFSET;
	instruction->operation = operation[decode.opc][decode.V][decode.L];
	return aarch64_decompose_load_store_reg_imm_common(instructionValue, instruction);
}


uint32_t aarch64_decompose_load_store_reg_pair_post_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* 4.3.15 Load/store register pair (post-indexed)
	 *
	 * STP   <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
	 * STP   <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
	 * LDP   <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
	 * LDP   <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
	 * STP   <St1>, <St2>, [<Xn|SP>], #<imm>
	 * STP   <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
	 * STP   <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
	 * LDP   <St1>, <St2>, [<Xn|SP>], #<imm>
	 * LDP   <Dt1>, <Dt2>, [<Xn|SP>], #<imm>
	 * LDP   <Qt1>, <Qt2>, [<Xn|SP>], #<imm>
	 * LDPSW <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
	 * STGP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
	 */
	LDST_REG_PAIR_OFFSET decode = *(LDST_REG_PAIR_OFFSET*)&instructionValue;
	static const Operation operation[4][2][2] = {
		{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STGP, ARM64_LDPSW},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_STP, ARM64_LDP},
			{ARM64_STP, ARM64_LDP},
		},{
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
			{ARM64_UNDEFINED, ARM64_UNDEFINED},
		}
	};
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = MEM_POST_IDX;
	instruction->operation = operation[decode.opc][decode.V][decode.L];
	return aarch64_decompose_load_store_reg_imm_common(instructionValue, instruction);
}


uint32_t aarch64_decompose_load_store_reg_reg_offset(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.10 Load/store register (register offset)
	 *
	 * STRB   <Wt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDRB   <Wt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDRSB  <Wt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDRSB  <Xt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STR	<Bt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STR	<Ht>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STR	<St>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STR	<Dt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STR	<Qt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDR	<Bt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDR	<Ht>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDR	<St>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDR	<Dt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDR	<Qt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * STRH   <Wt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDRH   <Wt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * LDRSW  <Xt>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 * PRFM <prfop>, [<Xn|SP>, <R><m>{, <extend> {<amount>}}]
	 */
	LDST_REG_REG_OFFSET decode = *(LDST_REG_REG_OFFSET*)&instructionValue;
	struct opreg{
		Operation operation;
		uint32_t registerBase;
		int32_t amount[2];
	};
	static const struct opreg operation[4][2][4] = {
		{
			{
				{ARM64_STRB,  REG_W_BASE, {-1,0}},
				{ARM64_LDRB,  REG_W_BASE, {-1,0}},
				{ARM64_LDRSB, REG_X_BASE, {-1,0}},
				{ARM64_LDRSB, REG_W_BASE, {-1,0}}
			},{
				{ARM64_STR, REG_B_BASE, {-1,0}},
				{ARM64_LDR, REG_B_BASE, {-1,0}},
				{ARM64_STR, REG_Q_BASE, { 0,4}},
				{ARM64_LDR, REG_Q_BASE, { 0,4}}
			}
		},{
			{
				{ARM64_STRH,  REG_W_BASE, {0,1}},
				{ARM64_LDRH,  REG_W_BASE, {0,1}},
				{ARM64_LDRSH, REG_X_BASE, {0,1}},
				{ARM64_LDRSH, REG_W_BASE, {0,1}}
			},{
				{ARM64_STR, REG_H_BASE, {0,1}},
				{ARM64_LDR, REG_H_BASE, {0,1}},
				{ARM64_UNDEFINED, 0, {0,0}},
				{ARM64_UNDEFINED, 0, {0,0}}
			}
		},{
			{
				{ARM64_STR,   REG_W_BASE, {0,2}},
				{ARM64_LDR,   REG_W_BASE, {0,2}},
				{ARM64_LDRSW, REG_X_BASE, {0,2}},
				{ARM64_UNDEFINED, 0, {0,0}}
			},{
				{ARM64_STR, REG_S_BASE, {0,2}},
				{ARM64_LDR, REG_S_BASE, {0,2}},
				{ARM64_UNDEFINED, 0, {0,0}},
				{ARM64_UNDEFINED, 0, {0,0}}
			}
		},{
			{
				{ARM64_STR,  REG_X_BASE,  {0,3}},
				{ARM64_LDR,  REG_X_BASE,  {0,3}},
				{ARM64_PRFM, REG_PF_BASE, {0,0}},
				{ARM64_UNDEFINED,0, {0,0}}
			},{
				{ARM64_STR, REG_D_BASE, {0,3}},
				{ARM64_LDR, REG_D_BASE, {0,3}},
				{ARM64_UNDEFINED, 0, {0,0}},
				{ARM64_UNDEFINED, 0, {0,0}}
			}
		}
	};

	const struct opreg* op =  &operation[decode.size][decode.V][decode.opc];
	static const uint32_t extendRegister[] = {0, 0, REG_W_BASE, REG_X_BASE};
	static const ShiftType extendMap[] = {
		SHIFT_NONE, SHIFT_NONE, SHIFT_UXTW, SHIFT_LSL,
		SHIFT_NONE, SHIFT_NONE, SHIFT_SXTW, SHIFT_SXTX};

	if (decode.option >> 1 == 0 || decode.option >> 1 == 2)
		return 1;
	instruction->operation = op->operation;

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->registerBase, decode.Rt);

	instruction->operands[1].operandClass = MEM_EXTENDED;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].reg[1] = REG(REGSET_ZR, extendRegister[decode.option&3], decode.Rm);

	ShiftType extend = extendMap[decode.option];
	instruction->operands[1].shiftType = extend;
	instruction->operands[1].shiftValueUsed = 1;
	instruction->operands[1].shiftValue = op->amount[decode.S];

	if (instruction->operands[1].shiftValue == (uint32_t)-1)
	{
		instruction->operands[1].shiftValueUsed = 0;
		instruction->operands[1].shiftValue = 0;
		if (instruction->operands[1].shiftType == SHIFT_LSL)
			instruction->operands[1].shiftType = SHIFT_NONE;
	}
	else if (instruction->operation == ARM64_LDRB)
	{
		if (instruction->operands[1].shiftType == SHIFT_LSL &&
			instruction->operands[1].shiftValue == 0)
		{
			instruction->operands[1].shiftValueUsed = 1;
		}
		else if (instruction->operands[1].shiftType != SHIFT_LSL &&
				instruction->operands[1].shiftValue == 0)
		{
			instruction->operands[1].shiftValueUsed = 0;
		}
	}
	else if (instruction->operands[1].shiftValue == 0 &&
		(instruction->operation == ARM64_LDRSB ||
		instruction->operation == ARM64_STRB))
	{
			instruction->operands[1].shiftValueUsed = 1;
	}
	else if (instruction->operands[1].shiftValue == 0)
	{
		if (instruction->operands[1].shiftType == SHIFT_LSL)
			instruction->operands[1].shiftType = SHIFT_NONE;
		instruction->operands[1].shiftValueUsed = 0;
	}
	return instruction->operation == ARM64_UNDEFINED || extend == SHIFT_NONE;
}


uint32_t aarch64_decompose_load_store_reg_unpriv(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.11  Load/store register (unprivileged)
	 *
	 * STTRB  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTRB  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTRSB <Wt>, [<Xn|SP>{, #<simm>}]
	 * STTRH  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTRH  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTRSH <Wt>, [<Xn|SP>{, #<simm>}]
	 * STTR   <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTR   <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDTRSB <Xt>, [<Xn|SP>{, #<simm>}]
	 * LDTRSH <Xt>, [<Xn|SP>{, #<simm>}]
	 * STTR   <Xt>, [<Xn|SP>{, #<simm>}]
	 * LDTR   <Xt>, [<Xn|SP>{, #<simm>}]
	 * LDTRSW <Xt>, [<Xn|SP>{, #<simm>}]
	 */
	LDST_REGISTER_UNPRIV decode = *(LDST_REGISTER_UNPRIV*)&instructionValue;
	static const Operation operation[4][4] = {
		{ARM64_STTRB, ARM64_LDTRB, ARM64_LDTRSB, ARM64_LDTRSB},
		{ARM64_STTRH, ARM64_LDTRH, ARM64_LDTRSH, ARM64_LDTRSH},
		{ARM64_STTR,  ARM64_LDTR,  ARM64_LDTRSW, ARM64_UNDEFINED},
		{ARM64_STTR,  ARM64_LDTR,  ARM64_UNDEFINED, ARM64_UNDEFINED}
	};
	instruction->operation = operation[decode.size][decode.opc];
	uint32_t regChoice = decode.opc==2 || decode.size == 3;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[regChoice], decode.Rt);
	instruction->operands[1].operandClass = MEM_OFFSET;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.imm;
	instruction->operands[1].signedImm = 1;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_reg_unscalled_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.12 - Load/store register (unscaled immediate)
	 *
	 * LDURB/STURB <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDURSB	  <Xt>, [<Xn|SP>{, #<simm>}]
	 * LDURSB	  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDURH/STURH <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDURSH	  <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Wt>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Xt>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Bt>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Ht>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <St>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Dt>, [<Xn|SP>{, #<simm>}]
	 * LDUR/STUR   <Qt>, [<Xn|SP>{, #<simm>}]
	 */
	LDST_REG_UNSCALED_IMM decode = *(LDST_REG_UNSCALED_IMM*)&instructionValue;
	struct opreg{
		Operation operation;
		uint32_t registerBase;
	};
	static const struct opreg operation[4][2][4] = {
		{
			{{ARM64_STURB, REG_W_BASE}, {ARM64_LDURB, REG_W_BASE}, {ARM64_LDURSB, REG_X_BASE}, {ARM64_LDURSB, REG_W_BASE}},
			{{ARM64_STUR, REG_B_BASE},  {ARM64_LDUR, REG_B_BASE}, {ARM64_STUR, REG_Q_BASE}, {ARM64_LDUR, REG_Q_BASE}}
		},{
			{{ARM64_STURH, REG_W_BASE}, {ARM64_LDURH, REG_W_BASE}, {ARM64_LDURSH, REG_X_BASE}, {ARM64_LDURSH, REG_W_BASE}},
			{{ARM64_STUR, REG_H_BASE}, {ARM64_LDUR, REG_H_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED,0}}
		},{
			{{ARM64_STUR, REG_W_BASE}, {ARM64_LDUR, REG_W_BASE}, {ARM64_LDURSW, REG_X_BASE}, {ARM64_UNDEFINED, REG_X_BASE}},
			{{ARM64_STUR, REG_S_BASE}, {ARM64_LDUR, REG_S_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED,0}}
		},{
			{{ARM64_STUR, REG_X_BASE}, {ARM64_LDUR, REG_X_BASE}, {ARM64_PRFUM, REG_PF_BASE}, {ARM64_UNDEFINED,0}},
			{{ARM64_STUR, REG_D_BASE}, {ARM64_LDUR, REG_D_BASE}, {ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED,0}}
		}
	};
	const struct opreg* op = &operation[decode.size][decode.V][decode.opc];
	instruction->operation = op->operation;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = MEM_OFFSET;

	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->registerBase, decode.Rt);
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.imm;
	instruction->operands[1].signedImm = 1;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_load_store_reg_unsigned_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.13 Load/store register (unsigned immediate)
	 *
	 * STRB	<Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRB	<Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRSB   <Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRSB   <Xt>, [<Xn|SP>{, #<pimm>}]
	 * STR	 <Bt>, [<Xn|SP>{, #<pimm>}]
	 * STR	 <Ht>, [<Xn|SP>{, #<pimm>}]
	 * STR	 <St>, [<Xn|SP>{, #<pimm>}]
	 * STR	 <Dt>, [<Xn|SP>{, #<pimm>}]
	 * STR	 <Qt>, [<Xn|SP>{, #<pimm>}]
	 * LDR	 <Bt>, [<Xn|SP>{, #<pimm>}]
	 * LDR	 <Ht>, [<Xn|SP>{, #<pimm>}]
	 * LDR	 <St>, [<Xn|SP>{, #<pimm>}]
	 * LDR	 <Dt>, [<Xn|SP>{, #<pimm>}]
	 * LDR	 <Qt>, [<Xn|SP>{, #<pimm>}]
	 * STRH	<Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRH	<Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRSH   <Wt>, [<Xn|SP>{, #<pimm>}]
	 * LDRSH   <Xt>, [<Xn|SP>{, #<pimm>}]
	 * LDRSW   <Xt>, [<Xn|SP>{, #<pimm>}]
	 * PRFM <prfop>, [<Xn|SP>{, #<pimm>}]
	 */
	LDST_REG_UNSIGNED_IMM decode = *(LDST_REG_UNSIGNED_IMM*)&instructionValue;
	struct opreg{
		Operation operation;
		uint32_t registerBase;
		uint32_t amount;
	};
	static const struct opreg operation[4][2][4] = {
		{
			{
				{ARM64_STRB,  REG_W_BASE, 0},
				{ARM64_LDRB,  REG_W_BASE, 0},
				{ARM64_LDRSB, REG_X_BASE, 0},
				{ARM64_LDRSB, REG_W_BASE, 0}
			},{
				{ARM64_STR, REG_B_BASE, 0},
				{ARM64_LDR, REG_B_BASE, 0},
				{ARM64_STR, REG_Q_BASE, 4},
				{ARM64_LDR, REG_Q_BASE, 4}
			}
		},{
			{
				{ARM64_STRH, REG_W_BASE, 1},
				{ARM64_LDRH, REG_W_BASE, 1} ,
				{ARM64_LDRSH, REG_X_BASE, 1},
				{ARM64_LDRSH, REG_W_BASE, 1}
			},{
				{ARM64_STR, REG_H_BASE, 1},
				{ARM64_LDR, REG_H_BASE, 1},
				{ARM64_UNDEFINED, 0, 0},
				{ARM64_UNDEFINED, 0, 0}
			}
		},{
			{
				{ARM64_STR, REG_W_BASE, 2},
				{ARM64_LDR, REG_W_BASE, 2},
				{ARM64_LDRSW, REG_X_BASE, 2},
				{ARM64_UNDEFINED, 0, 2}
			},{
				{ARM64_STR, REG_S_BASE, 2},
				{ARM64_LDR, REG_S_BASE, 2},
				{ARM64_UNDEFINED, 0, 0},
				{ARM64_UNDEFINED, 0, 0}
			}
		},{
			{
				{ARM64_STR, REG_X_BASE, 3},
				{ARM64_LDR, REG_X_BASE, 3},
				{ARM64_PRFM,REG_PF_BASE, 3},
				{ARM64_UNDEFINED,0, 0}
			},{
				{ARM64_STR, REG_D_BASE, 3},
				{ARM64_LDR, REG_D_BASE, 3},
				{ARM64_UNDEFINED, 0, 0},
				{ARM64_UNDEFINED, 0, 0}
			}
		}
	};

	const struct opreg* op =  &operation[decode.size][decode.V][decode.opc];
	instruction->operation = op->operation;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = MEM_OFFSET;

	instruction->operands[0].reg[0] = REG(REGSET_ZR, op->registerBase, decode.Rt);
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	instruction->operands[1].immediate = decode.imm << op->amount;
	instruction->operands[1].signedImm = 0;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t moveWidePreferred(uint32_t sf, uint32_t immn, uint32_t imms, uint32_t immr)
{
	/*
	 * boolean MoveWidePreferred(bit sf, bit immN, bits(6) imms, bits(6) immr)
	 *  integer S = UInt (imms);
	 *  integer R = UInt (immr);
	 *  integer width = if sf == '1' then 64 else 32;
	 *  //element size must equal total immediate size
	 *  if sf == '1' && immN:imms != '1xxxxxx' then
	 *	  return FALSE;
	 *  if sf == '0' && immN:imms != '00xxxxx' then
	 *	  return FALSE;
	 *
	 *	// for MOVZ must contain no more than 16 ones
	 *	if S < 16 then
	 *	 // ones must not span halfword boundary when rotated
	 *	   return (-R MOD 16) <= (15 - S);
	 *
	 *  // for MOVN must contain no more than 16 zeros
	 *  if S >= width - 15 then
	 *   // zeros must not span halfword boundary when rotated
	 *   return (R MOD 16) <= (S - (width - 15));
	 *	return FALSE;
	 */
	int32_t S = (int32_t)imms;
	int32_t R = (int32_t)immr;
	int32_t width = sf==1?64:32;

	if (sf == 1 && (((immn<<6|imms) >> 6) & 1) != 1)
		return 0;
	if (sf == 0 && (((immn<<6|imms) >> 5) & 3) != 0)
		return 0;

	if (S < 16)
		return (-R % 16) <= (15-S);
	if (S >= width - 15)
		return (R % 16) <= (S - (width - 15));
	return 0;
}


uint32_t aarch64_decompose_logical_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.4.4 Logical (immediate)
	 *
	 * AND <Wd|WSP>, <Wn>, #<imm>
	 * AND <Xd|SP>, <Xn>, #<imm>
	 * ORR <Wd|WSP>, <Wn>, #<imm>
	 * ORR <Xd|SP>, <Xn>, #<imm>
	 * EOR <Wd|WSP>, <Wn>, #<imm>
	 * EOR <Xd|SP>, <Xn>, #<imm>
	 * ANDS <Wd>, <Wn>, #<imm>
	 * ANDS <Xd>, <Xn>, #<imm>
	 */
	LOGICAL_IMM decode = *(LOGICAL_IMM*)&instructionValue;
	static const Operation operation[4] = {ARM64_AND, ARM64_ORR, ARM64_EOR, ARM64_ANDS};
	instruction->operation = operation[decode.opc];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_SP, regSize[decode.sf], decode.Rd);

	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);

	instruction->operands[2].operandClass = IMM64;
	if (DecodeBitMasks(decode.N, decode.imms, decode.immr, &instruction->operands[2].immediate, decode.sf?64:32) == 0)
		return 1;

	if (instruction->operation == ARM64_ORR && decode.Rn == 31 && !moveWidePreferred(decode.sf, decode.N, decode.imms, decode.immr))
	{
		instruction->operation = ARM64_MOV;
		delete_operand(instruction->operands, 1, 3);
	}
	if (instruction->operation == ARM64_ANDS && decode.Rd == 31)
	{
		instruction->operation = ARM64_TST;
		delete_operand(instruction->operands, 0, 3);
	}
	return (decode.sf == 0) && (decode.N != 0);
}


uint32_t aarch64_decompose_logical_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.5.10 Logical (shifted register)
	 *
	 * AND <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * AND <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * BIC <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * BIC <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * ORR <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * ORR <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * ORN <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * ORN <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * EOR <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * EOR <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * EON <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * EON <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * ANDS <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * ANDS <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 * BICS <Wd>, <Wn>, <Wm>{, <shift> #<amount>}
	 * BICS <Xd>, <Xn>, <Xm>{, <shift> #<amount>}
	 *
	 * Aliases
	 * ORR <Wd>, <Wn>, <Wm>{, <shift> #<amount>} -> MOV <Wd>, <Wm>
	 * ORN <Wd>, WZR, <Wm>{, <shift> #<amount>}  -> MVN <Wd>, <Wm>{, <shift> #<amount>}
	 * ANDS WZR, <Wn>, <Wm>{, <shift> #<amount>} -> TST <Wn>, <Wm>{, <shift> #<amount>}
	 */
	LOGICAL_SHIFTED_REG decode = *(LOGICAL_SHIFTED_REG*)&instructionValue;
	static const Operation operation[2][4] = {
		{ARM64_AND, ARM64_ORR, ARM64_EOR, ARM64_ANDS},
		{ARM64_BIC, ARM64_ORN, ARM64_EON, ARM64_BICS}};
	static const ShiftType shiftMap[4] = {SHIFT_LSL, SHIFT_LSR, SHIFT_ASR, SHIFT_ROR};
	instruction->operation = operation[decode.N][decode.opc];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;

	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rm);
	instruction->operands[2].shiftType = shiftMap[decode.shift];
	instruction->operands[2].shiftValue = decode.imm;
	instruction->operands[2].shiftValueUsed = 1;

	if (instruction->operands[2].shiftType == SHIFT_LSL &&
		instruction->operands[2].shiftValue == 0)
	{
		instruction->operands[2].shiftType = SHIFT_NONE;
	}
	if (instruction->operation == ARM64_ORR &&
		 decode.shift == 0 &&
		 decode.imm == 0 &&
		 decode.Rn == 31)
	{
		instruction->operation = ARM64_MOV;
		instruction->operands[2].shiftType = SHIFT_NONE;
		instruction->operands[2].shiftValue = 0;
		delete_operand(instruction->operands, 1, 4);
	}
	else if (instruction->operation == ARM64_ORN &&
			 decode.Rn == 31)
	{
		instruction->operation = ARM64_MVN;
		delete_operand(instruction->operands, 1, 4);
	}
	else if (instruction->operation == ARM64_ANDS && decode.Rd == 31)
	{
		instruction->operation = ARM64_TST;
		delete_operand(instruction->operands, 0, 4);
	}
	return 0;
}


uint32_t aarch64_decompose_move_wide_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.4.5 Move wide (immediate)
	 *
	 * MOVN <Wd>, #<imm>{, LSL #<shift>}
	 * MOVN <Xd>, #<imm>{, LSL #<shift>}
	 * MOVZ <Wd>, #<imm>{, LSL #<shift>}
	 * MOVZ <Xd>, #<imm>{, LSL #<shift>}
	 * MOVK <Wd>, #<imm>{, LSL #<shift>}
	 * MOVK <Xd>, #<imm>{, LSL #<shift>}
	 */
	MOVE_WIDE_IMM decode = *(MOVE_WIDE_IMM*)&instructionValue;
	static const Operation operation[4] = {ARM64_MOVN, ARM64_UNDEFINED, ARM64_MOVZ, ARM64_MOVK};
	instruction->operation = operation[decode.opc];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.sf], decode.Rd);

	instruction->operands[1].operandClass = IMM32;
	instruction->operands[1].immediate = decode.imm;
	if (decode.hw != 0)
	{
		instruction->operands[1].shiftType = SHIFT_LSL;
		instruction->operands[1].shiftValue = decode.hw << 4;
		instruction->operands[1].shiftValueUsed = 1;
	}
	if ((decode.sf == 0 && decode.hw >> 1 == 1) || instruction->operation == ARM64_UNDEFINED)
		return 1;

	if (decode.imm != 0 || decode.hw == 0)
	{
		if (instruction->operation == ARM64_MOVN &&
			((decode.sf == 0 && decode.imm != 0xffff) || decode.sf == 1))
		{
			instruction->operation = ARM64_MOV;
			if (decode.sf == 1)
				instruction->operands[1].operandClass = IMM64;
			else
				instruction->operands[1].operandClass = IMM32;

			instruction->operands[1].immediate =
				~((instruction->operands[1].immediate << (decode.hw<<4)));
			instruction->operands[1].shiftType = SHIFT_NONE;
			instruction->operands[1].shiftValue = 0;
		}
		else if (instruction->operation == ARM64_MOVZ)
		{
			instruction->operation = ARM64_MOV;
			instruction->operands[1].operandClass = IMM64;
			instruction->operands[1].immediate <<= instruction->operands[1].shiftValue;
			instruction->operands[1].shiftType = SHIFT_NONE;
			instruction->operands[1].shiftValue = 0;
		}
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_pc_rel_addr(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/* C4.4.6 PC-rel. addressing
	 *
	 * ADR <Xd>, <label>
	 * ADRP <Xd>, <label>
	 */
	PC_REL_ADDRESSING decode = *(PC_REL_ADDRESSING*)&instructionValue;
	static const Operation operation[] = {ARM64_ADR, ARM64_ADRP};
	static const uint8_t shiftBase[] = {0,12};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rd);
	instruction->operands[1].operandClass = LABEL;
	int64_t x = decode.immhi;
	instruction->operands[1].immediate = (((x << 2) | decode.immlo) << shiftBase[decode.op]);
	if (decode.op == 1)
		instruction->operands[1].immediate += address & ~((1<<12)-1);
	else
		instruction->operands[1].immediate += address;
	//printf("imm: %lx %lx %lx %lx\n", instruction->operands[1].immediate, x, x<<2, ((x<<2)| decode.immlo)<< 12);
	return 0;
}


uint32_t aarch64_decompose_simd_2_reg_misc(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.17 Advanced SIMD two-register miscellaneous
	 *
	 * REV64	 <Vd>.<T>, <Vn>.<T>
	 * REV16	 <Vd>.<T>, <Vn>.<T>
	 * SADDLP	<Vd>.<Ta>, <Vn>.<Tb>
	 * SUQADD	<Vd>.<T>, <Vn>.<T>
	 * CLS	   <Vd>.<T>, <Vn>.<T>
	 * CNT	   <Vd>.<T>, <Vn>.<T>
	 * SADALP	<Vd>.<Ta>, <Vn>.<Tb>
	 * SQABS	 <Vd>.<T>, <Vn>.<T>
	 * CMGT	  <V><d>, <V><n>, #0
	 * CMEQ	  <V><d>, <V><n>, #0
	 * CMLT	  <V><d>, <V><n>, #0
	 * ABS	   <Vd>.<T>, <Vn>.<T>
	 * XTN{2}	<Vd>.<Tb>, <Vn>.<Ta>
	 * SQXTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
	 * FCVTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
	 * FCVTL{2}  <Vd>.<Ta>, <Vn>.<Tb>
	 * FRINTN	<Vd>.<T>, <Vn>.<T>
	 * FRINTM	<Vd>.<T>, <Vn>.<T>
	 * FCVTAS	<Vd>.<T>, <Vn>.<T>
	 * SCVTF	 <Vd>.<T>, <Vn>.<T>
	 * FCMGT	 <Vd>.<T>, <Vn>.<T>, #0.0
	 * FCMEQ	 <Vd>.<T>, <Vn>.<T>, #0.0
	 * FCMLT	 <Vd>.<T>, <Vn>.<T>, #0.0
	 * FABS	  <Vd>.<T>, <Vn>.<T>
	 * FRINTP	<Vd>.<T>, <Vn>.<T>
	 * FRINTZ	<Vd>.<T>, <Vn>.<T>
	 * FCVTPS	<Vd>.<T>, <Vn>.<T>
	 * FCVTZS	<Vd>.<T>, <Vn>.<T>
	 * URECPE	<Vd>.<T>, <Vn>.<T>
	 * FRECPE	<Vd>.<T>, <Vn>.<T>
	 * REV32	 <Vd>.<T>, <Vn>.<T>
	 * UADDLP	<Vd>.<Ta>, <Vn>.<Tb>
	 * USQADD	<Vd>.<T>, <Vn>.<T>
	 * CLZ	   <Vd>.<T>, <Vn>.<T>
	 * UADALP	<Vd>.<Ta>, <Vn>.<Tb>
	 * SQNEG	 <Vd>.<T>, <Vn>.<T>
	 * CMGE	  <Vd>.<T>, <Vn>.<T>, #0
	 * CMLE	  <Vd>.<T>, <Vn>.<T>, #0
	 * NEG	   <Vd>.<T>, <Vn>.<T>
	 * SQXTUN{2} <Vd>.<Tb>, <Vn>.<Ta>
	 * SHLL{2}   <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
	 * UQXTN{2}  <Vd>.<Tb>, <Vn>.<Ta>
	 * FCVTXN{2} <Vd>.<Tb>, <Vn>.<Ta>
	 * FRINTA	<Vd>.<T>, <Vn>.<T>
	 * FRINTX	<Vd>.<T>, <Vn>.<T>
	 * FCVTNU	<Vd>.<T>, <Vn>.<T>
	 * FCVTMU	<Vd>.<T>, <Vn>.<T>
	 * FCVTAU	<Vd>.<T>, <Vn>.<T>
	 * UCVTF	 <Vd>.<T>, <Vn>.<T>
	 * NOT	   <Vd>.<T>, <Vn>.<T>
	 * RBIT	  <Vd>.<T>, <Vn>.<T>
	 * FCMGE	 <Vd>.<T>, <Vn>.<T>, #0.0
	 * FCMLE	 <Vd>.<T>, <Vn>.<T>, #0.0
	 * FNEG	  <Vd>.<T>, <Vn>.<T>
	 * FRINTI	<Vd>.<T>, <Vn>.<T>
	 * FCVTPU	<Vd>.<T>, <Vn>.<T>
	 * FCVTZU	<Vd>.<T>, <Vn>.<T>
	 * URSQRTE   <Vd>.<T>, <Vn>.<T>
	 * FRSQRTE   <Vd>.<T>, <Vn>.<T>
	 * FSQRT	 <Vd>.<T>, <Vn>.<T>
	 *
	 * 0 - <Vd>.<T>, <Vn>.<T>
	 * 1 - <Vd>.<Ta>, <Vn>.<Tb>
	 * 2 - <Vd>.<Tb>, <Vn>.<Ta>
	 * 3 - <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
	 * 4 - <Vd>.<T>, <Vn>.<T>, #0
	 * 5 - <Vd>.<T>, <Vn>.<T>, #0.0
	 * 6 - {2} <Vd>.<Tb>, <Vn>.<Ta>
	 * 7 - {2} <Vd>.<Ta>, <Vn>.<Tb>
	 * 8 - <V><d>, <V><n>, #0
	 */
	SIMD_2_REG_MISC decode = *(SIMD_2_REG_MISC*)&instructionValue;
	struct opInfo {
		Operation op;
		uint32_t type;
		uint32_t maxSize;
	};
	const struct opInfo* info;
	if (decode.U == 0)
	{
		static const struct opInfo operation1[] = {
			{ARM64_REV64,  0, 3},
			{ARM64_REV16,  0, 1},
			{ARM64_SADDLP, 1, 2},
			{ARM64_SUQADD, 0, 0},
			{ARM64_CLS,    0, 3},
			{ARM64_CNT,    0, 1},
			{ARM64_SADALP, 1, 3},
			{ARM64_SQABS,  0, 4},
			{ARM64_CMGT,   4, 4},
			{ARM64_CMEQ,   4, 4},
			{ARM64_CMLT,   4, 4},
			{ARM64_ABS,    0, 4},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_XTN,    6, 3}, //{2}
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_SQXTN,  6, 3}, //{2}
		};

		static const struct opInfo operation2[] = {
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FCVTN,    10, 3}, //{2}
			{ARM64_FCVTL,    12, 1}, //{2}
			{ARM64_FRINTN,   13, 7},
			{ARM64_FRINTM,   13, 7},
			{ARM64_FCVTNS,   13, 7},
			{ARM64_FCVTMS,   13, 7},
			{ARM64_FCVTAS,   13, 7},
			{ARM64_SCVTF,    13, 7},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
		};

		static const struct opInfo operation3[] = {
			{ARM64_FCMGT,     5, 7},
			{ARM64_FCMEQ,     5, 7},
			{ARM64_FCMLT,     5, 7},
			{ARM64_FABS,      0, 7},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FRINTP,    0, 7},
			{ARM64_FRINTZ,    0, 7},
			{ARM64_FCVTPS,    0, 7},
			{ARM64_FCVTZS,    0, 7},
			{ARM64_URECPE,    0, 8},
			{ARM64_FRECPE,    0, 7},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
		};

		if (decode.opcode < COUNT_OF(operation1) && operation1[decode.opcode].op != ARM64_UNDEFINED)
		{
			info = &operation1[decode.opcode];
		}
		else if (decode.size < 2 && decode.opcode > COUNT_OF(operation1))
		{
			info = &operation2[decode.opcode-COUNT_OF(operation1)];
		}
		else if (decode.size > 1)
		{
			info = &operation3[decode.opcode-12];
		}
		else
			return 1;
	}
	else
	{
		static const struct opInfo operation1[] = {
			{ARM64_REV32,     0, 3},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UADDLP,    1, 3},
			{ARM64_USQADD,    0, 3},
			{ARM64_CLZ,       0, 3},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UADALP,    1, 3},
			{ARM64_SQNEG,     0, 4},
			{ARM64_CMGE,      4, 4},
			{ARM64_CMLE,      4, 4},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_NEG,       0, 4},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_SQXTUN,    6, 3}, //{2}
			{ARM64_SHLL,      3, 3}, //{2}
			{ARM64_UQXTN,     6, 3}, //{2}
			{ARM64_UNDEFINED, 0, 0},
		};

		static const struct opInfo operation2[] = {
			{ARM64_FCVTXN,   11, 5}, //{2}
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FRINTA,   13, 0},
			{ARM64_FRINTX,   13, 7},
			{ARM64_FCVTNU,   13, 7},
			{ARM64_FCVTMU,   13, 7},
			{ARM64_FCVTAU,   13, 7},
			{ARM64_UCVTF,    13, 7},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
		};

		static const struct opInfo operation3[] = {
			{ARM64_FCMGE,     5, 5},
			{ARM64_FCMLE,     5, 5},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FNEG,      0, 5},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FRINTI,    0, 5},
			{ARM64_FCVTPU,    0, 5},
			{ARM64_FCVTZU,    0, 5},
			{ARM64_URSQRTE,   0, 5},
			{ARM64_FRSQRTE,   0, 5},
			{ARM64_UNDEFINED, 0, 0},
			{ARM64_FSQRT,     0, 7},
		};

		static const struct opInfo operation4[] = {
			{ARM64_MVN,  9, 0},
			{ARM64_RBIT, 9, 0}
		};
		if (decode.opcode == 5)
		{
			info = &operation4[decode.size&1];
		}
		else if (decode.opcode < COUNT_OF(operation1) && operation1[decode.opcode].op != ARM64_UNDEFINED)
		{
			info = &operation1[decode.opcode];
		}
		else if (decode.size < 2 && decode.opcode >= 22)
		{
			info = &operation2[decode.opcode-22];
		}
		else if (decode.size > 1 && decode.opcode >= 12)
		{
			info = &operation3[decode.opcode-12];
		}
		else
			return 1;
	}
	instruction->operation = info->op;
	/* 0 - <Vd>.<T>, <Vn>.<T>
	 * 1 - <Vd>.<Ta>, <Vn>.<Tb>
	 * 2 - <Vd>.<Tb>, <Vn>.<Ta>
	 * 3 - {2} <Vd>.<Ta>, <Vn>.<Tb>, #<shift>
	 * 4 - <Vd>.<T>, <Vn>.<T>, #0
	 * 5 - <Vd>.<T>, <Vn>.<T>, #0.0
	 * 6 - {2} <Vd>.<Tb>, <Vn>.<Ta>
	 * 7 - {2} <Vd>.<Ta>, <Vn>.<Tb>
	 * 8 - <V><d>, <V><n>, #0
	 */
	uint32_t elemSize1 = 0;
	uint32_t elemSize2 = 0;
	uint32_t dataSize1 = 0;
	uint32_t dataSize2 = 0;
	static const uint32_t dsizeMap[2] = {64, 128};
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	switch (info->type)
	{
		case 0:
			elemSize1 = 1<<decode.size;
			dataSize1 = dsizeMap[decode.Q]/(8<<decode.size);
			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			break;
		case 1:
			elemSize1 = 2<<decode.size;
			dataSize1 = dsizeMap[decode.Q]/(16<<decode.size);
			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			break;
		case 2:
			elemSize1 = 1<<decode.size;
			dataSize1 = dsizeMap[decode.Q]/(8<<decode.size);
			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			break;
		case 3:
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 2<<decode.size;
			dataSize1 = 16 / (2<<decode.size);

			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);

			instruction->operands[2].immediate = 8 << decode.size;
			instruction->operands[2].operandClass = IMM32;
			break;
		case 4:
			elemSize1 = 1<<decode.size;
			dataSize1 = dsizeMap[decode.Q]/(8<<decode.size);
			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			instruction->operands[2].immediate = 0;
			instruction->operands[2].operandClass = IMM32;
			break;
		case 5:
			elemSize1 = 1<<decode.size;
			dataSize1 = dsizeMap[decode.Q]/(8<<decode.size);
			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			instruction->operands[2].immediate = 0;
			instruction->operands[2].operandClass = IMM32;
			break;
		case 6:
			//good
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 1 << decode.size;
			dataSize1 = dsizeMap[decode.Q]/(elemSize1<<3);

			elemSize2 = 2<<decode.size;
			dataSize2 = 64/(8<<decode.size);
			break;
		case 7:
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 2<<decode.size;
			dataSize1 = 16 / (2<<decode.size);

			elemSize2 = 1<<decode.size;
			dataSize2 = dsizeMap[decode.Q]/(8<<decode.size);
			break;
		case 8:
			break;
		case 9:
			dataSize1 = dsizeMap[decode.Q]/8;
			elemSize1 = 1;
			dataSize2 = dsizeMap[decode.Q]/8;
			elemSize2 = 1;
			break;
		case 10:
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 2 << decode.size;
			dataSize1 = dsizeMap[decode.Q]/(16<<decode.size);

			elemSize2 = 4 << decode.size;
			dataSize2 = 4 >> decode.size;
			break;
		case 11:
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 4;
			dataSize1 = 2 << decode.Q;

			elemSize2 = 8;
			dataSize2 = 2;
			break;
		case 12:
			instruction->operation = (Operation)(instruction->operation + decode.Q); //the '2' variant is always +1
			elemSize1 = 4 << decode.size;
			dataSize1 = 4 >> decode.size;

			elemSize2 = 2 << decode.size;
			dataSize2 = dsizeMap[decode.Q]/(16<<decode.size);
			break;
		case 13:
			elemSize1 = 4 << decode.size;
			dataSize1 = dsizeMap[decode.Q]/(32<<decode.size);
			elemSize2 = elemSize1;
			dataSize2 = dataSize1;
			break;
	}
	//element = b(1),h(2),s(4),d(8)
	//data 1,2,3,8,16
	instruction->operands[0].elementSize = elemSize1;
	instruction->operands[0].dataSize = dataSize1;

	instruction->operands[1].elementSize = elemSize2;
	instruction->operands[1].dataSize = dataSize2;

	switch (info->maxSize)
	{
		case 1:
		case 2:
		case 3:
			if (decode.size > info->maxSize)
				return 1;
			break;
		case 4:
			if (decode.size == 3 && decode.Q == 0)
				return 1;
			break;
		case 5:
			if (decode.size == 0)
				return 1;
			break;
		case 6:
		case 7:
			if (decode.size == 1 && decode.Q == 0)
				return 1;
			break;
		case 8:
			if (decode.size == 1)
				return 1;
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_3_different(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.15 Advanced SIMD three different
	 *
	 * SADDL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SADDW{2}   <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
	 * SSUBL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SSUBW{2}   <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
	 * ADDHN{2}   <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
	 * SABAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SUBHN{2}   <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
	 * SABDL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SMLAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SQDMLAL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SMLSL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SQDMLSL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SMULL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * SQDMULL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * PMULL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * UADDL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * UADDW{2}   <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
	 * USUBL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * USUBW{2}   <Vd>.<Ta>, <Vn>.<Ta>, <Vm>.<Tb>
	 * RADDHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
	 * UABAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * RSUBHN{2}  <Vd>.<Tb>, <Vn>.<Ta>, <Vm>.<Ta>
	 * UABDL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * UMLAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * UMLSL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 * UMULL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Tb>
	 */

	static const Operation operation[2][2][16] = {
		{
			{
				ARM64_SADDL,
				ARM64_SADDW,
				ARM64_SSUBL,
				ARM64_SSUBW,
				ARM64_ADDHN,
				ARM64_SABAL,
				ARM64_SUBHN,
				ARM64_SABDL,
				ARM64_SMLAL,
				ARM64_SQDMLAL,
				ARM64_SMLSL,
				ARM64_SQDMLSL,
				ARM64_SMULL,
				ARM64_SQDMULL,
				ARM64_PMULL,
				ARM64_UNDEFINED,
			},{
				ARM64_UADDL,
				ARM64_UADDW,
				ARM64_USUBL,
				ARM64_USUBW,
				ARM64_RADDHN,
				ARM64_UABAL,
				ARM64_RSUBHN,
				ARM64_UABDL,
				ARM64_UMLAL,
				ARM64_UNDEFINED,
				ARM64_UMLSL,
				ARM64_UNDEFINED,
				ARM64_UMULL,
				ARM64_UNDEFINED,
				ARM64_UNDEFINED,
				ARM64_UNDEFINED,
			}
		},{
			{
				ARM64_SADDL2,
				ARM64_SADDW2,
				ARM64_SSUBL2,
				ARM64_SSUBW2,
				ARM64_ADDHN2,
				ARM64_SABAL2,
				ARM64_SUBHN2,
				ARM64_SABDL2,
				ARM64_SMLAL2,
				ARM64_SQDMLAL2,
				ARM64_SMLSL2,
				ARM64_SQDMLSL2,
				ARM64_SMULL2,
				ARM64_SQDMULL2,
				ARM64_PMULL2,
				ARM64_UNDEFINED,
			},{
				ARM64_UADDL2,
				ARM64_UADDW2,
				ARM64_USUBL2,
				ARM64_USUBW2,
				ARM64_RADDHN2,
				ARM64_UABAL2,
				ARM64_RSUBHN2,
				ARM64_UABDL2,
				ARM64_UMLAL2,
				ARM64_UNDEFINED,
				ARM64_UMLSL2,
				ARM64_UNDEFINED,
				ARM64_UMULL2,
				ARM64_UNDEFINED,
				ARM64_UNDEFINED,
				ARM64_UNDEFINED,
			}
		}
	};
	SIMD_3_DIFFERENT decode = *(SIMD_3_DIFFERENT*)&instructionValue;
	instruction->operation = operation[decode.Q][decode.U][decode.opcode];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	uint32_t esize1 = 1<<decode.size;
	static const uint32_t dsizeMap[2] = {64, 128};
	uint32_t dsize1 = dsizeMap[decode.Q]/(8 * esize1);
	uint32_t esize2 = 0, dsize2 = 0;
	switch (decode.size)
	{
		case 0: esize2 = 2;  dsize2 = 8; break;
		case 1: esize2 = 4;  dsize2 = 4; break;
		case 2: esize2 = 8;  dsize2 = 2; break;
		case 3: esize2 = 16; dsize2 = 1; break;
	}
	static const uint32_t elementMap[16][3] = {
		{0,1,1},
		{0,0,1},
		{0,1,1},
		{0,0,1},
		{1,0,0},
		{0,1,1},
		{1,0,0},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
		{0,1,1},
	};
	for (uint32_t i = 0; i < 3; i++)
	{
		if (elementMap[decode.opcode][i] == 0)
		{
			instruction->operands[i].elementSize = esize2;
			instruction->operands[i].dataSize = dsize2;
		}
		else
		{
			instruction->operands[i].elementSize = esize1;
			instruction->operands[i].dataSize = dsize1;
		}
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_3_same(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.16 Advanced SIMD three same
	 *
	 * SHADD    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SQADD    <V><d>, <V><n>, <V><m>
	 * SRHADD   <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SHSUB    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SQSUB    <V><d>, <V><n>, <V><m>
	 * CMGT     <V><d>, <V><n>, <V><m>
	 * CMGE     <V><d>, <V><n>, <V><m>
	 * SSHL     <V><d>, <V><n>, <V><m>
	 * SQSHL    <V><d>, <V><n>, <V><m>
	 * SRSHL    <V><d>, <V><n>, <V><m>
	 * SQRSHL   <V><d>, <V><n>, <V><m>
	 * SMAX     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SMIN     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SABD     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SABA     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * ADD      <V><d>, <V><n>, <V><m>
	 * CMTST    <V><d>, <V><n>, <V><m>
	 * MLA      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * MUL      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SMAXP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SMINP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SQDMULH  <V><d>, <V><n>, <V><m>
	 * ADDP     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMAXNM   <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMLA     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FADD     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMULX    <V><d>, <V><n>, <V><m>
	 * FCMEQ    <V><d>, <V><n>, <V><m>
	 * FMAX     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FRECPS   <V><d>, <V><n>, <V><m>
	 * AND      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * BIC      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMINNM   <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMLS     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FSUB     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMIN     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FRSQRTS  <V><d>, <V><n>, <V><m>
	 * ORR      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * ORN      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UHADD    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UQADD    <V><d>, <V><n>, <V><m>
	 * URHADD   <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UHSUB    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UQSUB    <V><d>, <V><n>, <V><m>
	 * CMHI     <V><d>, <V><n>, <V><m>
	 * CMHS     <V><d>, <V><n>, <V><m>
	 * USHL     <V><d>, <V><n>, <V><m>
	 * UQRSHL   <V><d>, <V><n>, <V><m>
	 * UMAX     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UMIN     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UABD     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UABA     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SUB      <V><d>, <V><n>, <V><m>
	 * CMEQ     <V><d>, <V><n>, <V><m>
	 * MLS      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * PMUL     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UMAXP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UMINP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * SQRDMULH <V><d>, <V><n>, <V><m>
	 * FMAXNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FADDP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMUL     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FCMGE    <V><d>, <V><n>, <V><m>
	 * FMAXP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FDIV     <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * EOR      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * BSL      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FMINNMP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * FABD     <V><d>, <V><n>, <V><m>
	 * FCMGT    <V><d>, <V><n>, <V><m>
	 * FACGT    <V><d>, <V><n>, <V><m>
	 * FMINP    <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * BIT      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * BIF      <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 */
	SIMD_3_SAME decode = *(SIMD_3_SAME*)&instructionValue;
	struct opInfo {
		Operation op;
		uint32_t vector;
	};
	uint32_t alternateEncode = 0;
	if (decode.U == 0)
	{
		static const struct opInfo operation1[] = {
			{ARM64_SHADD, 0},
			{ARM64_SQADD, 0},
			{ARM64_SRHADD, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_SHSUB, 0},
			{ARM64_SQSUB, 0},
			{ARM64_CMGT, 0},
			{ARM64_CMGE, 0},
			{ARM64_SSHL, 0},
			{ARM64_SQSHL, 0},
			{ARM64_SRSHL, 0},
			{ARM64_SQRSHL, 0},
			{ARM64_SMAX, 0},
			{ARM64_SMIN, 0},
			{ARM64_SABD, 0},
			{ARM64_SABA, 0},
			{ARM64_ADD, 0},
			{ARM64_CMTST, 0},
			{ARM64_MLA, 0},
			{ARM64_MUL, 0},
			{ARM64_SMAXP, 0},
			{ARM64_SMINP, 0},
			{ARM64_SQDMULH, 0},
			{ARM64_ADDP, 0}
		};
		static const struct opInfo operation2[] = {
			{ARM64_FMAXNM, 1},
			{ARM64_FMLA, 1},
			{ARM64_FADD, 1},
			{ARM64_FMULX, 1},
			{ARM64_FCMEQ, 1},
			{ARM64_UNDEFINED, 0},
			{ARM64_FMAX, 1},
			{ARM64_FRECPS, 1},
		};
		static const struct opInfo operation3[] = {
			{ARM64_FMINNM, 0},
			{ARM64_FMLS, 0},
			{ARM64_FSUB, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_FMIN, 0},
			{ARM64_FRSQRTS, 0},
		};
		if (decode.opcode < COUNT_OF(operation1))
		{
			if (decode.opcode == 3)
			{
				switch (decode.size)
				{
					case 0: instruction->operation = ARM64_AND; break;
					case 1:	instruction->operation = ARM64_BIC; break;
					case 2:	instruction->operation = ARM64_ORR; break;
					case 3:	instruction->operation = ARM64_ORN; break;
				}
			}
			else
			{
				instruction->operation = operation1[decode.opcode].op;
			}
		}
		else if (decode.size < 2)
		{
			instruction->operation = operation2[decode.opcode-COUNT_OF(operation1)].op;
			alternateEncode = 1;
		}
		else
		{
			instruction->operation = operation3[decode.opcode-COUNT_OF(operation1)].op;
		}
	}
	else
	{
		static const struct opInfo operation1[] = {
			{ARM64_UHADD, 0},
			{ARM64_UQADD, 0},
			{ARM64_URHADD, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_UHSUB, 0},
			{ARM64_UQSUB, 0},
			{ARM64_CMHI, 0},
			{ARM64_CMHS, 0},
			{ARM64_USHL, 0},
			{ARM64_UQSHL, 0},
			{ARM64_URSHL,  0},
			{ARM64_UQRSHL, 0},
			{ARM64_UMAX, 0},
			{ARM64_UMIN, 0},
			{ARM64_UABD, 0},
			{ARM64_UABA, 0},
			{ARM64_SUB, 0},
			{ARM64_CMEQ, 0},
			{ARM64_MLS, 0},
			{ARM64_PMUL, 0},
			{ARM64_UMAXP, 0},
			{ARM64_UMINP, 0},
			{ARM64_SQRDMULH, 0},
			{ARM64_UNDEFINED, 0},
		};

		static const struct opInfo operation2[] = {
			{ARM64_FMAXNMP, 1},
			{ARM64_UNDEFINED, 0},
			{ARM64_FADDP, 1},
			{ARM64_FMUL, 1},
			{ARM64_FCMGE, 1},
			{ARM64_FACGE, 1},
			{ARM64_FMAXP, 1},
			{ARM64_FDIV, 0}
		};

		static const struct opInfo operation3[] = {
			{ARM64_FMINNMP, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_FABD, 0},
			{ARM64_UNDEFINED, 0},
			{ARM64_FCMGT, 0},
			{ARM64_FACGT, 0},
			{ARM64_FMINP, 0},
			{ARM64_UNDEFINED, 0},
		};

		if (decode.opcode < COUNT_OF(operation1))
		{
			if (decode.opcode == 3)
			{
				switch (decode.size)
				{
					case 0: instruction->operation = ARM64_EOR; break;
					case 1:	instruction->operation = ARM64_BSL; break;
					case 2:	instruction->operation = ARM64_BIT; break;
					case 3:	instruction->operation = ARM64_BIF; break;
				}
			}
			else
			{
				instruction->operation = operation1[decode.opcode].op;
			}
		}
		else if (decode.size < 2)
		{
			instruction->operation = operation2[decode.opcode-COUNT_OF(operation1)].op;
			alternateEncode = 1;
		}
		else
		{
			instruction->operation = operation3[decode.opcode-COUNT_OF(operation1)].op;
		}

	}
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	if (decode.opcode == 3)
	{
		static const uint32_t dsizeMap[2] = {8, 16};
		instruction->operands[0].elementSize = 1;
		instruction->operands[0].dataSize = dsizeMap[decode.Q];
		instruction->operands[1].elementSize = 1;
		instruction->operands[1].dataSize = dsizeMap[decode.Q];
		instruction->operands[2].elementSize = 1;
		instruction->operands[2].dataSize = dsizeMap[decode.Q];
	}
	else
	{
		if (alternateEncode == 1)
		{
			uint32_t esize = 32<<decode.size;
			static const uint32_t dsizeMap[2] = {64, 128};
			uint32_t dsize = dsizeMap[decode.Q]/(esize);
			instruction->operands[0].elementSize = esize/8;
			instruction->operands[1].elementSize = esize/8;
			instruction->operands[2].elementSize = esize/8;
			instruction->operands[0].dataSize = dsize;
			instruction->operands[1].dataSize = dsize;
			instruction->operands[2].dataSize = dsize;
		}
		else
		{
			uint32_t esize = 1<<decode.size;
			static const uint32_t dsizeMap[2] = {64, 128};
			uint32_t dsize = dsizeMap[decode.Q]/(8 * esize);
			instruction->operands[0].elementSize = esize;
			instruction->operands[1].elementSize = esize;
			instruction->operands[2].elementSize = esize;
			instruction->operands[0].dataSize = dsize;
			instruction->operands[1].dataSize = dsize;
			instruction->operands[2].dataSize = dsize;
		}
	}
	//Aliases
	if (instruction->operation == ARM64_ORR && decode.Rn == decode.Rm)
	{
		instruction->operation = ARM64_MOV;
		instruction->operands[2].operandClass = NONE;
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_across_lanes(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.1 Advanced SIMD across lanes
	 *
	 * SADDLV  <V><d>, <Vn>.<T>
	 * SMAXV   <V><d>, <Vn>.<T>
	 * SMINV   <V><d>, <Vn>.<T>
	 * ADDV    <V><d>, <Vn>.<T>
	 * UADDLV  <V><d>, <Vn>.<T>
	 * UMAXV   <V><d>, <Vn>.<T>
	 * UMINV   <V><d>, <Vn>.<T>
	 * FMAXNMV <V><d>, <Vn>.<T>
	 * FMAXV   <V><d>, <Vn>.<T>
	 * FMINNMV <V><d>, <Vn>.<T>
	 * FMINV   <V><d>, <Vn>.<T>
	 */
	SIMD_ACROSS_LANES decode = *(SIMD_ACROSS_LANES*)&instructionValue;
	uint32_t esize = 1<<decode.size;
	static const uint32_t dsizeMap[2] = {64, 128};
	uint32_t dsize = dsizeMap[decode.Q]/(8 * esize);
	static const uint32_t regBaseMap[3] = {REG_B_BASE, REG_H_BASE, REG_S_BASE};
	static const uint32_t regBaseMap2[3] = {REG_H_BASE, REG_S_BASE, REG_D_BASE};
	uint32_t reg1 = 0, reg2 = 0;
	if (decode.size == 3)
		return 1;

	switch(decode.opcode)
	{
		case 3:
			if (decode.U == 0)
				instruction->operation = ARM64_SADDLV;
			else
				instruction->operation = ARM64_UADDLV;
			reg1 = REG(REGSET_ZR, regBaseMap2[decode.size], decode.Rd);
			reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			break;
		case 10:
			if (decode.U == 0)
				instruction->operation = ARM64_SMAXV;
			else
				instruction->operation = ARM64_UMAXV;
			reg1 = REG(REGSET_ZR, regBaseMap[decode.size], decode.Rd);
			reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			break;
		case 12:
			if (decode.U == 1)
			{
				if (decode.size < 2)
					instruction->operation = ARM64_FMAXNMV;
				else
					instruction->operation = ARM64_FMINNMV;

				if (decode.Q == 0 || decode.size == 1)
					return 1;
				reg1 = REG(REGSET_ZR, REG_S_BASE, decode.Rd);
				reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
				esize = 4;
				dsize = 4;
			}
			break;
		case 15:
			if (decode.U == 1)
			{
				if (decode.size < 2)
					instruction->operation = ARM64_FMAXV;
				else
					instruction->operation = ARM64_FMINV;
				reg1 = REG(REGSET_ZR, REG_S_BASE, decode.Rd);
				reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
				esize = 4;
				dsize = 4;
			}
			break;
		case 26:
			if (decode.U == 0)
				instruction->operation = ARM64_SMINV;
			else
				instruction->operation = ARM64_UMINV;

			reg1 = REG(REGSET_ZR, regBaseMap[decode.size], decode.Rd);
			reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			break;
		case 27:
			instruction->operation = ARM64_ADDV;
			reg1 = REG(REGSET_ZR, regBaseMap[decode.size], decode.Rd);
			reg2 = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			break;
		default:
			return 1;
	}
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[0].reg[0] = reg1;
	instruction->operands[1].reg[0] = reg2;
	instruction->operands[1].elementSize = esize;
	instruction->operands[1].dataSize = dsize;
	return 0;
}


uint32_t aarch64_decompose_simd_copy(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.2 - Advanced SIMD copy
	 *
	 * DUP  <V><d>, <Vn>.<T>[<index>]
	 * DUP  <Vd>.<T>, <R><n>
	 * SMOV <Wd>, <Vn>.<Ts>[<index>]
	 * SMOV <Xd>, <Vn>.<Ts>[<index>]
	 * UMOV <Wd>, <Vn>.<Ts>[<index>]
	 * UMOV <Xd>, <Vn>.<Ts>[<index>]
	 * INS  <Vd>.<Ts>[<index>], <R><n>
	 * INS  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
	 *
	 * Aliases:
	 * INS  <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>] -> MOV <Vd>.<Ts>[<index1>], <Vn>.<Ts>[<index2>]
	 * DUP  <V><d>, <Vn>.<T>[<index>] -> MOV <V><d>, <Vn>.<T>[<index>]
	 * UMOV <Wd>, <Vn>.S[<index>] -> MOV <Wd>, <Vn>.S[<index>]
	 * UMOV <Xd>, <Vn>.D[<index>] -> MOV <Xd>, <Vn>.D[<index>]
	 */
	SIMD_COPY decode = *(SIMD_COPY*)&instructionValue;

	uint32_t elemSize1 = 0;
	uint32_t size = 0;
	static const uint32_t dsizeMap[2] = {64, 128};
	static const uint32_t dupRegMap[5] = {REG_W_BASE, REG_W_BASE, REG_W_BASE, REG_X_BASE, REG_X_BASE};
	for (; size < 4; size++)
	{
		if (((decode.imm5 >> size) & 1) == 1)
			break;
	}
	elemSize1 = 1 << size;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].operandClass = REG;
	if (decode.op == 0)
	{
		switch (decode.imm4)
		{
		case 0:
			instruction->operation = ARM64_DUP;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			instruction->operands[0].elementSize = elemSize1;
			instruction->operands[0].dataSize = dsizeMap[decode.Q]/(8<<size);
			instruction->operands[1].elementSize = 1 << size;
			instruction->operands[1].scale = (0x80000000 | (decode.imm5 >> (size+1)));
			break;
		case 1:
			instruction->operation = ARM64_DUP;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, dupRegMap[size], decode.Rn);
			instruction->operands[0].elementSize = elemSize1;
			instruction->operands[0].dataSize = dsizeMap[decode.Q]/(8<<size);
			break;
		case 3:
			instruction->operation = ARM64_INS;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, dupRegMap[size], decode.Rn);
			instruction->operands[0].elementSize = elemSize1;
			instruction->operands[0].scale = 0x80000000 |  (decode.imm5 >> (size+1));
			break;
		case 5:
			instruction->operation = ARM64_SMOV;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.Q], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			instruction->operands[1].elementSize = elemSize1;
			instruction->operands[1].scale = 0x80000000 | (decode.imm5 >> (size+1));
			if ((decode.Q == 0 && (decode.imm5 & 3) == 0) || (decode.Q == 1 && (decode.imm5 & 7) == 0))
				return 1;
			break;
		case 7:
			instruction->operation = ARM64_UMOV;
			if (elemSize1 == ((uint32_t)4<<decode.Q))
				instruction->operation = ARM64_MOV;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.Q], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
			instruction->operands[1].elementSize = elemSize1;
			instruction->operands[1].scale = 0x80000000 | (decode.imm5 >> (size+1));
			/*printf("Q %d imm5 %d\n", decode.Q, decode.imm5);
			if ((decode.Q == 0 && (decode.imm5 & 3) == 0) || (decode.Q == 1 &&
					(((decode.imm5 & 15) == 0) ||
					 ((decode.imm5 & 1) == 1) ||
					 ((decode.imm5 & 3) == 2) ||
					 ((decode.imm5 & 7) == 4))))
				return 1;
			*/
			break;
		default:
			return 1;
		}
	}
	else
	{
		instruction->operation = ARM64_INS;
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
		instruction->operands[0].elementSize = elemSize1;
		instruction->operands[0].scale = 0x80000000 | (decode.imm5 >> (size+1));

		instruction->operands[1].elementSize = elemSize1;
		instruction->operands[1].scale = decode.imm4 >> size;
		if ((decode.imm5 & 15) == 0)
			return 1;
	}
	return 0;
}


uint32_t aarch64_decompose_simd_extract(uint32_t instructionValue, Instruction* restrict instruction)
{
	SIMD_EXTRACT decode = *(SIMD_EXTRACT*)&instructionValue;
	static const uint8_t sizeMap[] = {8,16};
	instruction->operation = ARM64_EXT;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[3].operandClass = IMM32;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	instruction->operands[0].elementSize = 1;
	instruction->operands[1].elementSize = 1;
	instruction->operands[2].elementSize = 1;
	instruction->operands[0].dataSize = sizeMap[decode.Q];
	instruction->operands[1].dataSize = sizeMap[decode.Q];
	instruction->operands[2].dataSize = sizeMap[decode.Q];
	if (decode.Q == 0)
		instruction->operands[3].immediate = decode.imm & 7;
	else
		instruction->operands[3].immediate = decode.imm;

	return decode.imm > 7;
}


uint32_t aarch64_decompose_simd_load_store_multiple(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.1 Advanced SIMD load/store multiple structures
	 *
	 * LD1/ST1 { <Vt>.<T> },								  [<Xn|SP>]
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T> },						  [<Xn|SP>]
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			  [<Xn|SP>]
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
	 * LD2/ST2 { <Vt>.<T>, <Vt2>.<T> },						  [<Xn|SP>]
	 * LD3/ST3 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			  [<Xn|SP>]
	 * LD4/ST4 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
	 */
	SIMD_LDST_MULT decode = *(SIMD_LDST_MULT*)&instructionValue;
	static const char regCount[] = {4, 0, 4, 0, 3, 0, 3, 1, 2, 0, 2, 0, 0, 0, 0, 0};
	static const char elementDataSize[4][2] = {{8, 16}, {4, 8}, {2, 4}, {1, 2}};
	static const Operation operation[2][16] = {
		{
		ARM64_ST4,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_UNDEFINED,
		ARM64_ST3,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_ST1,
		ARM64_ST2,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_UNDEFINED,
		ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
		},{
		ARM64_LD4,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_UNDEFINED,
		ARM64_LD3,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_LD1,
		ARM64_LD2,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_UNDEFINED,
		ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
		}
	};

	instruction->operation = operation[decode.L][decode.opcode];
	uint32_t elements = regCount[decode.opcode];
	instruction->operands[0].operandClass = MULTI_REG;
	for (uint32_t i = 0; i < elements; i++)
		instruction->operands[0].reg[i] = REG(REGSET_ZR, REG_V_BASE, ((decode.Rt+i)%32));

	instruction->operands[0].dataSize = elementDataSize[decode.size][decode.Q];
	instruction->operands[0].elementSize = 1 << decode.size;
	instruction->operands[1].operandClass = MEM_REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_load_store_multiple_post_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.2 Advanced SIMD load/store multiple structures (post-indexed)
	 *
	 * LD1/ST1 { <Vt>.<T> }								   [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T> },					   [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			[<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
	 * LD2/ST2 { <Vt>.<T>, <Vt2>.<T> },					   [<Xn|SP>], <Xm>
	 * LD3/ST3 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			[<Xn|SP>], <Xm>
	 * LD4/ST4 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.<T> },								  [<Xn|SP>], <imm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T> },					   [<Xn|SP>], <imm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			[<Xn|SP>], <imm>
	 * LD1/ST1 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
	 * LD2/ST2 { <Vt>.<T>, <Vt2>.<T> },					   [<Xn|SP>], <imm>
	 * LD3/ST3 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> },			[<Xn|SP>], <imm>
	 * LD4/ST4 { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
	 */
	SIMD_LDST_MULT_PI decode = *(SIMD_LDST_MULT_PI*)&instructionValue;
	static const char regCount[] = {4, 0, 4, 0, 3, 0, 3, 1, 2, 0, 2, 0, 0, 0, 0, 0};
	static const char elementDataSize[4][2] = {{8, 16}, {4, 8}, {2, 4}, {1, 2}};
	static const Operation operation[2][16] = {
	{
		ARM64_ST4,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_UNDEFINED,
		ARM64_ST3,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_ST1,
		ARM64_ST2,       ARM64_UNDEFINED, ARM64_ST1,       ARM64_UNDEFINED,
		ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
	},{
		ARM64_LD4,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_UNDEFINED,
		ARM64_LD3,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_LD1,
		ARM64_LD2,       ARM64_UNDEFINED, ARM64_LD1,       ARM64_UNDEFINED,
		ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED
	}};
	static const char imm[4][2] = {{8,16}, {16,32}, {24,48}, {32,64}};
	instruction->operation = (Operation)((uint32_t)operation[decode.L][decode.opcode]);
	uint32_t elements = regCount[decode.opcode];
	if (elements == 0)
	{
		return 1;
	}
	instruction->operands[0].operandClass = MULTI_REG;
	for (uint32_t i = 0; i < elements; i++)
		instruction->operands[0].reg[i] = REG(REGSET_ZR, REG_V_BASE, ((decode.Rt+i)%32));

	instruction->operands[0].dataSize = elementDataSize[decode.size][decode.Q];
	instruction->operands[0].elementSize = 1 << decode.size;

	instruction->operands[1].operandClass = MEM_POST_IDX;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	if (decode.Rm == 31)
	{
		instruction->operands[1].immediate = imm[elements-1][decode.Q];
		instruction->operands[1].reg[1] = REG_NONE;
	}
	else
		instruction->operands[1].reg[1] = REG(REGSET_ZR, REG_X_BASE, decode.Rm);

	return (instruction->operation == ARM64_UNDEFINED) ||
		   ((instruction->operation != ARM64_ST1 && instruction->operation != ARM64_LD1 ) &&
			decode.Q == 0 && decode.size == 3);
}


uint32_t aarch64_decompose_simd_load_store_single(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.3  Advanced SIMD load/store single structure
	 *
	 * LD1/ST1 { <Vt>.B }[<index>], [<Xn|SP>]
	 * LD1/ST1 { <Vt>.H }[<index>], [<Xn|SP>]
	 * LD1/ST1 { <Vt>.S }[<index>], [<Xn|SP>]
	 * LD1/ST1 { <Vt>.D }[<index>], [<Xn|SP>]
	 * LD2/ST2 { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>]
	 * LD2/ST2 { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>]
	 * LD2/ST2 { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>]
	 * LD2/ST2 { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>]
	 * LD3/ST3 { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>]
	 * LD3/ST3 { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>]
	 * LD3/ST3 { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>]
	 * LD3/ST3 { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>]
	 * LD4/ST4 { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>]
	 * LD4/ST4 { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>]
	 * LD4/ST4 { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>]
	 * LD4/ST4 { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>]
	 * LD1R { <Vt>.<T> }, [<Xn|SP>]
	 * LD2R { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>]
	 * LD3R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>]
	 * LD4R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>]
	 */
	SIMD_LDST_SINGLE decode = *(SIMD_LDST_SINGLE*)&instructionValue;
	static const Operation operation[4][8] = {
		{ARM64_ST1, ARM64_ST3, ARM64_ST1, ARM64_ST3, ARM64_ST1, ARM64_ST3, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_ST2, ARM64_ST4, ARM64_ST2, ARM64_ST4, ARM64_ST2, ARM64_ST4, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_LD1, ARM64_LD3, ARM64_LD1, ARM64_LD3, ARM64_LD1, ARM64_LD3, ARM64_LD1R, ARM64_LD3R},
		{ARM64_LD2, ARM64_LD4, ARM64_LD2, ARM64_LD4, ARM64_LD2, ARM64_LD4, ARM64_LD2R, ARM64_LD4R}};

	static const char elementMap[4][8] = {
		{1, 3, 1, 3, 1, 3, 0, 0},
		{2, 4, 2, 4, 2, 4, 0, 0},
		{1, 3, 1, 3, 1, 3, 1, 3},
		{2, 4, 2, 4, 2, 4, 2, 4},
		};
	instruction->operation = (Operation)((uint32_t)operation[(decode.L<<1) + decode.R][decode.opcode]);
	instruction->operands[0].operandClass = MULTI_REG;
	uint32_t elements = elementMap[(decode.L<<1) + decode.R][decode.opcode];
	for (uint32_t i = 0; i < elements; i++)
		instruction->operands[0].reg[i] = REG(REGSET_ZR, REG_V_BASE, ((decode.Rt+i)%32));

	static const uint32_t sizemap[2] = {64,128};
	switch (decode.opcode >> 1)
	{
		case 0:
			instruction->operands[0].elementSize = 1;
			instruction->operands[0].index = (decode.Q << 3) | (decode.S << 2) | (decode.size);
			break;
		case 1:
			if (decode.size == 2 || decode.size == 0)
			{
				instruction->operands[0].elementSize = 2;
				instruction->operands[0].index = (decode.Q << 2) | (decode.S << 1) | (decode.size >> 1);
			}
			else
				return 1;
			break;
		case 2:
			if (decode.size == 0)
			{
				instruction->operands[0].elementSize = 4;
				instruction->operands[0].index = (decode.Q << 1) | decode.S;
			}
			else if (decode.size == 1 && decode.S == 0)
			{
				instruction->operands[0].elementSize = 8;
				instruction->operands[0].index = decode.Q;
			}
			else
				return 1;
			break;
		case 3:
			instruction->operands[0].elementSize = 1 << decode.size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(8<<decode.size);
			break;
		default:
			return 1;
	}
	instruction->operands[1].operandClass = REG;
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_load_store_single_post_idx(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.3.4 Advanced SIMD load/store single structure (post-indexed)
	 *
	 * LD1/ST1 { <Vt>.B }[<index>], [<Xn|SP>], #1
	 * LD1/ST1 { <Vt>.H }[<index>], [<Xn|SP>], #2
	 * LD1/ST1 { <Vt>.S }[<index>], [<Xn|SP>], #4
	 * LD1/ST1 { <Vt>.D }[<index>], [<Xn|SP>], #8
	 * LD1/ST1 { <Vt>.B }[<index>], [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.H }[<index>], [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.S }[<index>], [<Xn|SP>], <Xm>
	 * LD1/ST1 { <Vt>.D }[<index>], [<Xn|SP>], <Xm>
	 * LD2/ST2 { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], #2
	 * LD2/ST2 { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], #4
	 * LD2/ST2 { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], #8
	 * LD2/ST2 { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], #16
	 * LD2/ST2 { <Vt>.B, <Vt2>.B }[<index>], [<Xn|SP>], <Xm>
	 * LD2/ST2 { <Vt>.H, <Vt2>.H }[<index>], [<Xn|SP>], <Xm>
	 * LD2/ST2 { <Vt>.S, <Vt2>.S }[<index>], [<Xn|SP>], <Xm>
	 * LD2/ST2 { <Vt>.D, <Vt2>.D }[<index>], [<Xn|SP>], <Xm>
	 * LD3/ST3 { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], #3
	 * LD3/ST3 { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], #6
	 * LD3/ST3 { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], #12
	 * LD3/ST3 { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], #24
	 * LD3/ST3 { <Vt>.B, <Vt2>.B, <Vt3>.B }[<index>], [<Xn|SP>], <Xm>
	 * LD3/ST3 { <Vt>.H, <Vt2>.H, <Vt3>.H }[<index>], [<Xn|SP>], <Xm>
	 * LD3/ST3 { <Vt>.S, <Vt2>.S, <Vt3>.S }[<index>], [<Xn|SP>], <Xm>
	 * LD3/ST3 { <Vt>.D, <Vt2>.D, <Vt3>.D }[<index>], [<Xn|SP>], <Xm>
	 * LD4/ST4 { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], #4
	 * LD4/ST4 { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], #8
	 * LD4/ST4 { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], #16
	 * LD4/ST4 { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], #32
	 * LD4/ST4 { <Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>], [<Xn|SP>], <Xm>
	 * LD4/ST4 { <Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>], [<Xn|SP>], <Xm>
	 * LD4/ST4 { <Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>], [<Xn|SP>], <Xm>
	 * LD4/ST4 { <Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>], [<Xn|SP>], <Xm>
	 * LD1R { <Vt>.<T> }, [<Xn|SP>], <imm>
	 * LD1R { <Vt>.<T> }, [<Xn|SP>], <Xm>
	 * LD2R { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <imm>
	 * LD2R { <Vt>.<T>, <Vt2>.<T> }, [<Xn|SP>], <Xm>
	 * LD3R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <imm>
	 * LD3R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }, [<Xn|SP>], <Xm>
	 * LD4R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <imm>
	 * LD4R { <Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }, [<Xn|SP>], <Xm>
	 */
	SIMD_LDST_SINGLE_PI decode = *(SIMD_LDST_SINGLE_PI*)&instructionValue;
	uint32_t immIdx = 0;
	static const Operation operation[4][8] = {
		{ARM64_ST1, ARM64_ST3, ARM64_ST1, ARM64_ST3, ARM64_ST1, ARM64_ST3, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_ST2, ARM64_ST4, ARM64_ST2, ARM64_ST4, ARM64_ST2, ARM64_ST4, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_LD1, ARM64_LD3, ARM64_LD1, ARM64_LD3, ARM64_LD1, ARM64_LD3, ARM64_LD1R, ARM64_LD3R},
		{ARM64_LD2, ARM64_LD4, ARM64_LD2, ARM64_LD4, ARM64_LD2, ARM64_LD4, ARM64_LD2R, ARM64_LD4R}};

	static const char elementMap[4][8] = {
		{1, 3, 1, 3, 1, 3, 0, 0},
		{2, 4, 2, 4, 2, 4, 0, 0},
		{1, 3, 1, 3, 1, 3, 1, 3},
		{2, 4, 2, 4, 2, 4, 2, 4},
		};

	static const char immediateValues[4][4] = {
		{1, 2, 4, 8},
		{2, 4, 8, 16},
		{3, 6, 12, 24},
		{4, 8, 16, 32}
	};
	instruction->operation = (Operation)((uint32_t)operation[(decode.L<<1) + decode.R][decode.opcode]);
	instruction->operands[0].operandClass = MULTI_REG;
	instruction->operands[1].operandClass = MEM_POST_IDX;
	uint32_t elements = elementMap[(decode.L<<1) + decode.R][decode.opcode];
	for (uint32_t i = 0; i < elements; i++)
		instruction->operands[0].reg[i] = REG(REGSET_ZR, REG_V_BASE, ((decode.Rt+i)%32));

	static const uint32_t sizemap[2] = {64,128};
	switch (decode.opcode >> 1)
	{
		case 0:
			instruction->operands[0].elementSize = 1;
			instruction->operands[0].index = (decode.Q << 3) | (decode.S << 2) | (decode.size);
			immIdx = 0;
			break;
		case 1:
			if (decode.size == 2 || decode.size == 0)
			{
				instruction->operands[0].elementSize = 2;
				instruction->operands[0].index = (decode.Q << 2) | (decode.S << 1) | (decode.size >> 1);
				immIdx = 1;
			}
			else
				return 1;
			break;
		case 2:
			if (decode.size == 0)
			{
				instruction->operands[0].elementSize = 4;
				instruction->operands[0].index = (decode.Q << 1) | decode.S;
				immIdx = 2;
			}
			else if (decode.size == 1 && decode.S == 0)
			{
				instruction->operands[0].elementSize = 8;
				instruction->operands[0].index = decode.Q;
				immIdx = 3;
			}
			else
				return 1;
			break;
		case 3:
			instruction->operands[0].elementSize = 1 << decode.size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(8<<decode.size);
			break;
		default:
			return 1;
	}

	if (decode.Rm == 31 && elements != 0)
	{
		if (decode.opcode >> 1 == 3)
			instruction->operands[1].immediate = immediateValues[elements-1][decode.size];
		else
			instruction->operands[1].immediate = immediateValues[elements-1][immIdx];
		instruction->operands[1].reg[1] = REG_NONE;
	}
	else
	{
		instruction->operands[1].reg[1] = REG(REGSET_ZR, REG_X_BASE, decode.Rm);
	}
	instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.Rn);
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_modified_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.4 Advanced SIMD modified immediate
	 *
	 * MOVI <Vd>.<T>, #<imm8>{, LSL #0}
	 * MOVI <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * MOVI <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * MOVI <Vd>.<T>, #<imm8>, MSL #<amount>
	 * ORR  <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * ORR  <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * FMOV <Vd>.<T>, #<imm>
	 * FMOV <Vd>.2D, #<imm>
	 * MVNI <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * MVNI <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * MVNI <Vd>.<T>, #<imm8>, MSL #<amount>
	 * BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 * BIC  <Vd>.<T>, #<imm8>{, LSL #<amount>}
	 */
	SIMD_MODIFIED_IMM decode = *(SIMD_MODIFIED_IMM*)&instructionValue;
	struct opInfo{
		Operation op;
		uint32_t variant;
	};
	static const struct opInfo operation[2][16] = {
		{
			{ARM64_MOVI, 4},
			{ARM64_ORR,  4},
			{ARM64_MOVI, 4},
			{ARM64_ORR,  4},
			{ARM64_MOVI, 4},
			{ARM64_ORR,  4},
			{ARM64_MOVI, 4},
			{ARM64_ORR,  4},
			{ARM64_MOVI, 2},
			{ARM64_ORR,  2},
			{ARM64_MOVI, 2},
			{ARM64_ORR,  2},
			{ARM64_MOVI, 6},
			{ARM64_MOVI, 6},
			{ARM64_MOVI, 1},
			{ARM64_FMOV, 5}
		},{
			{ARM64_MVNI, 4},
			{ARM64_BIC,  4},
			{ARM64_MVNI, 4},
			{ARM64_BIC,  4},
			{ARM64_MVNI, 4},
			{ARM64_BIC,  4},
			{ARM64_MVNI, 4},
			{ARM64_BIC,  4},
			{ARM64_MVNI, 2},
			{ARM64_BIC,  2},
			{ARM64_MVNI, 2},
			{ARM64_BIC,  2},
			{ARM64_MVNI, 6},
			{ARM64_MVNI, 6},
			{ARM64_MOVI, 8},
			{ARM64_FMOV, 7},
		}
	};
	const struct opInfo* opinfo = &operation[decode.op][decode.cmode];
	instruction->operation = opinfo->op;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = IMM32;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	uint32_t esize = 0;
	uint32_t dsize = 0;
	uint32_t shiftValue = 0;
	ShiftType shiftType = SHIFT_NONE;
	uint64_t immediate =  decode.a << 7 | decode.b << 6 | decode.c << 5 | decode.d << 4 | decode.e << 3 | decode.f << 2 | decode.g << 1 | decode.h;
	static const int32_t sign[2] = {1,-1};
	ieee754	fvalue;
	switch(opinfo->variant)
	{
		case 1:
			esize = 1;
			dsize = 8 << decode.Q;
			shiftType = SHIFT_LSL;
			break;
		case 2:
			esize = 2;
			dsize = 4 << decode.Q;
			shiftValue = 8 * ((decode.cmode & 2)>>1);
			shiftType = SHIFT_LSL;
			break;
		case 4:
			esize = 4;
			dsize = 2 << decode.Q;
			shiftValue = 8 * ((decode.cmode & 6)>>1);
			shiftType = SHIFT_LSL;
			break;
		case 5:
			esize = 4;
			dsize = 2 << decode.Q;
			instruction->operands[1].operandClass = FIMM32;
			fvalue.sign = (uint32_t)(immediate >> 7);
			fvalue.exponent = (uint32_t)((immediate >> 4) & 7);
			fvalue.fraction = (uint32_t)(immediate & 15) ;
			fvalue.fvalue = (float)(sign[fvalue.sign] * (1<<(fvalue.exponent-7)) * (1.0+((float)fvalue.fraction/16)));
			immediate = fvalue.value;
			break;
		case 6:
			esize = 4;
			dsize = 2 << decode.Q;
			shiftValue = 8 << (decode.cmode & 1);
			shiftType = SHIFT_MSL;
			break;
		case 7:
			esize = 8;
			dsize = 2;
			instruction->operands[1].operandClass = FIMM32;
			fvalue.sign = immediate & 1;
			fvalue.exponent = (immediate >> 4) & 7;
			fvalue.fraction = (immediate & 15) ;
			fvalue.fvalue = (float)(sign[fvalue.sign] * (1<<(fvalue.exponent-7)) * (1.0+((float)fvalue.fraction/16)));
			immediate = fvalue.value;
			break;
		case 8:
			if (decode.Q == 1)
			{
				esize = 8;
				dsize = 2;
				instruction->operands[1].operandClass = IMM64;
				shiftType = SHIFT_NONE;
			}
			else
			{
				instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_D_BASE, decode.Rd);
				instruction->operands[1].operandClass = IMM64;
				shiftType = SHIFT_NONE;
			}
			//ugh this encoding is terrible
			//Is a 64-bit immediate 'aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhh',
			// encoded in "a:b:c:d:e:f:g:h".
			// To do this we pretend that the bit is a sign bit in each byte then right shift them
			union longImmediate {
				uint64_t value;
				int8_t bytes[8];
			};
			union longImmediate li;
			li.bytes[7] = decode.a << 7;
			li.bytes[6] = decode.b << 7;
			li.bytes[5] = decode.c << 7;
			li.bytes[4] = decode.d << 7;
			li.bytes[3] = decode.e << 7;
			li.bytes[2] = decode.f << 7;
			li.bytes[1] = decode.g << 7;
			li.bytes[0] = decode.h << 7;
			for (uint32_t i = 0; i < 8; i++)
				li.bytes[i] >>= 7;
			immediate = li.value;
			break;
	}
	instruction->operands[0].elementSize = esize;
	instruction->operands[0].dataSize = dsize;
	instruction->operands[1].immediate = immediate;

	if (shiftValue == 0 && shiftType == SHIFT_LSL)
		shiftType = SHIFT_NONE;
	instruction->operands[1].shiftValue = shiftValue;
	instruction->operands[1].shiftType = shiftType;
	instruction->operands[1].shiftValueUsed = 1;

	return decode.o2 != 0;
}


uint32_t aarch64_decompose_simd_permute(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.5 Advanced SIMD permute
	 *
	 * UZP1 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * TRN1 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * ZIP1 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * UZP2 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * TRN2 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 * ZIP2 <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	 */
	static const Operation operation[] = {
		ARM64_UNDEFINED,
		ARM64_UZP1,
		ARM64_TRN1,
		ARM64_ZIP1,
		ARM64_UNDEFINED,
		ARM64_UZP2,
		ARM64_TRN2,
		ARM64_ZIP2,
	};
	SIMD_PERMUTE  decode = *(SIMD_PERMUTE *)&instructionValue;
	static const uint8_t esizeMap[2] = {64,128};
	instruction->operation = operation[decode.opcode];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	instruction->operands[0].elementSize = 1<<decode.size;
	instruction->operands[0].dataSize = esizeMap[decode.Q]/(8<<decode.size);
	instruction->operands[1].elementSize = 1<<decode.size;
	instruction->operands[1].dataSize = esizeMap[decode.Q]/(8<<decode.size);
	instruction->operands[2].elementSize = 1<<decode.size;
	instruction->operands[2].dataSize = esizeMap[decode.Q]/(8<<decode.size);
	return instruction->operation == ARM64_UNDEFINED || (decode.size == 3 && decode.Q == 0);
}


uint32_t aarch64_decompose_simd_scalar_2_reg_misc(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.11 Advanced SIMD scalar two-register miscellaneous
	 *
	 * SUQADD  <V><d>, <V><n>
	 * SQABS   <V><d>, <V><n>
	 * CMGT	<V><d>, <V><n>, #0
	 * CMEQ	<V><d>, <V><n>, #0
	 * CMLT	<V><d>, <V><n>, #0
	 * ABS	 <V><d>, <V><n>
	 * SQXTN   <Vb><d>, <Va><n>
	 * FCVTNS  <V><d>, <V><n>
	 * FCVTMS  <V><d>, <V><n>
	 * FCVTAS  <V><d>, <V><n>
	 * SCVTF   <V><d>, <V><n>
	 * FCMGT   <V><d>, <V><n>, #0.0
	 * FCMEQ   <V><d>, <V><n>, #0.0
	 * FCMLT   <V><d>, <V><n>, #0.0
	 * FCVTPS  <V><d>, <V><n>
	 * FCVTZS  <V><d>, <V><n>
	 * FRECPE  <V><d>, <V><n>
	 * FRECPX  <V><d>, <V><n>
	 * FRECPX  <V><d>, <V><n>
	 * USQADD  <V><d>, <V><n>
	 * SQNEG   <V><d>, <V><n>
	 * CMGE	<V><d>, <V><n>, #0
	 * CMLE	<V><d>, <V><n>, #0
	 * NEG	 <V><d>, <V><n>
	 * SQXTUN  <Vb><d>, <Va><n>
	 * UQXTN   <Vb><d>, <Va><n>
	 * FCVTXN  <Vb><d>, <Va><n>
	 * FCVTNU  <V><d>, <V><n>
	 * FCVTMU  <V><d>, <V><n>
	 * FCVTAU  <V><d>, <V><n>
	 * UCVTF   <V><d>, <V><n>
	 * FCMGE   <V><d>, <V><n>, #0.0
	 * FCMLE   <V><d>, <V><n>, #0.0
	 * FCVTPU  <V><d>, <V><n>
	 * FCVTZU  <V><d>, <V><n>
	 * FRSQRTE <V><d>, <V><n>
	 *
	 * 0: <V><d>,  <V><n>
	 * 1: <V><d>,  <V><n>, #0.0
	 * 2: <Vb><d>, <Va><n>
	 * 3: (decode.size < 2)->  <V><d>, <V><n>
	 * 4: (decode.size < 2)->  <V><d>, <V><n>, #0.0
	 * 5: (decode.size < 2)->  <Vb><d>, <Va><n>
	 * 6: (decode.size > 1)->  <V><d>, <V><n>
	 * 7: (decode.size > 1)->  <V><d>, <V><n>, #0.0
	 * 8: (decode.size > 2)->  <Vb><d>, <Va><n>
	 */
	/*static const Operation operation[] = {*/
		/*0 - xx - 3  - v: 0 {ARM64_SUQADD,  0},*/
		/*0 - xx - 7  - v: 0 {ARM64_SQABS,   0},*/
		/*0 - xx - 8  - v: 1 {ARM64_CMGT,	1},*/
		/*0 - xx - 9  - v: 1 {ARM64_CMEQ,	1},*/
		/*0 - xx - 10 - v: 1 {ARM64_CMLT,	1},*/
		/*0 - xx - 11 - v: 0 {ARM64_ABS,	 0},*/
		/*0 - xx - 20 - v: 2 {ARM64_SQXTN,   2},*/
		/*0 - 0x - 26 - v: 3 {ARM64_FCVTNS,  3},*/
		/*0 - 0x - 27 - v: 3 {ARM64_FCVTMS,  3},*/
		/*0 - 0x - 28 - v: 3 {ARM64_FCVTAS,  3},*/
		/*0 - 0x - 29 - v: 3 {ARM64_SCVTF,   3},*/
		/*0 - 1x - 12 - v: 7 {ARM64_FCMGT,   7},*/
		/*0 - 1x - 13 - v: 7 {ARM64_FCMEQ,   7},*/
		/*0 - 1x - 14 - v: 7 {ARM64_FCMLT,   7},*/
		/*0 - 1x - 26 - v: 6 {ARM64_FCVTPS,  6},*/
		/*0 - 1x - 27 - v: 6 {ARM64_FCVTZS,  6},*/
		/*0 - 1x - 29 - v: 6 {ARM64_FRECPE,  6},*/
		/*0 - 1x - 31 - v: 6 {ARM64_FRECPX,  6},*/
		/*1 - xx - 3  - v: 0 {ARM64_USQADD,  0},*/
		/*1 - xx - 7  - v: 0 {ARM64_SQNEG,   0},*/
		/*1 - xx - 8  - v: 1 {ARM64_CMGE,	1},*/
		/*1 - xx - 9  - v: 1 {ARM64_CMLE,	1},*/
		/*1 - xx - 11 - v: 0 {ARM64_NEG,	 0},*/
		/*1 - xx - 18 - v: 2 {ARM64_SQXTUN,  2},*/
		/*1 - xx - 20 - v: 2 {ARM64_UQXTN,   2},*/
		/*1 - 0x - 22 - v: 5 {ARM64_FCVTXN,  5},*/
		/*1 - 0x - 26 - v: 3 {ARM64_FCVTNU,  3},*/
		/*1 - 0x - 27 - v: 3 {ARM64_FCVTMU,  3},*/
		/*1 - 0x - 28 - v: 6 {ARM64_FCVTAU,  6},*/
		/*1 - 0x - 29 - v: 6 {ARM64_UCVTF,   6},*/
		/*1 - 1x - 12 - v: 7 {ARM64_FCMGE,   7},*/
		/*1 - 1x - 13 - v: 7 {ARM64_FCMLE,   7},*/
		/*1 - 1x - 26 - v: 6 {ARM64_FCVTPU,  6},*/
		/*1 - 1x - 27 - v: 6 {ARM64_FCVTZU,  6},*/
		/*1 - 1x - 29 - v: 6 {ARM64_FRSQRTE, 6},*/
	/*};*/
	struct OpInfo {
		Operation op;
		uint32_t var;
	};
	static const struct OpInfo operation[2][2][32] = {
	{
		{
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SUQADD,    0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SQABS,     0},
		{ARM64_CMGT,      1}, {ARM64_CMEQ,      1},{ARM64_CMLT,      1}, {ARM64_ABS,       0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_SQXTN,     2}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_FCVTNS,    3}, {ARM64_FCVTMS,    3},
		{ARM64_FCVTAS,    3}, {ARM64_SCVTF,     3},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
	  },{
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SUQADD,    0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SQABS,     0},
		{ARM64_CMGT,      1}, {ARM64_CMEQ,      1},{ARM64_CMLT,      1}, {ARM64_ABS,       0},
		{ARM64_FCMGT,     7}, {ARM64_FCMEQ,     7},{ARM64_FCMLT,     7}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_SQXTN,     2}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_FCVTPS,    6}, {ARM64_FCVTZS,    6},
		{ARM64_UNDEFINED, 0}, {ARM64_FRECPE,    6},{ARM64_UNDEFINED, 0}, {ARM64_FRECPX,    6},
	  }
	},{
	  {
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_USQADD,    0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SQNEG,     0},
		{ARM64_CMGE,      1}, {ARM64_CMLE,      1},{ARM64_UNDEFINED, 0}, {ARM64_NEG,       0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_SQXTUN,    2}, {ARM64_UNDEFINED, 0},
		{ARM64_UQXTN,     2}, {ARM64_UNDEFINED, 0},{ARM64_FCVTXN,    5}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_FCVTNU,    3}, {ARM64_FCVTMU,    3},
		{ARM64_FCVTAU,    6}, {ARM64_UCVTF,     6},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
	  },{
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_USQADD,    0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_SQNEG,     0},
		{ARM64_CMGE,      1}, {ARM64_CMLE,      1},{ARM64_UNDEFINED, 0}, {ARM64_NEG,       0},
		{ARM64_FCMGE,     7}, {ARM64_FCMLE,     7},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_SQXTUN,    2}, {ARM64_UNDEFINED, 0},
		{ARM64_UQXTN,     2}, {ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},{ARM64_FCVTPU,    6}, {ARM64_FCVTZU,    6},
		{ARM64_UNDEFINED, 0}, {ARM64_FRSQRTE,   6},{ARM64_UNDEFINED, 0}, {ARM64_UNDEFINED, 0},
		}
		}
	};
	SIMD_SCALAR_2_REGISTER_MISC  decode = *(SIMD_SCALAR_2_REGISTER_MISC *)&instructionValue;
	const struct OpInfo* opinfo = &operation[decode.U][decode.size>>1][decode.opcode];
	static const uint8_t regbase[4] = {REG_B_BASE, REG_H_BASE, REG_S_BASE, REG_D_BASE};
	static const uint8_t regbase2[3] = {REG_H_BASE, REG_S_BASE, REG_D_BASE};
	static const uint8_t regbase3[2] = {REG_S_BASE, REG_D_BASE};
	instruction->operation = opinfo->op;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	switch (opinfo->var)
	{
		case 0:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rn);
			break;
		case 6:
		case 3:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rn);
			break;
		case 1:
		case 4:
			if (decode.size != 3)
				return 1;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rn);
			instruction->operands[2].operandClass = IMM32;
			instruction->operands[2].immediate = 0;
			break;
		case 7:
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rn);
			instruction->operands[2].operandClass = IMM32;
			instruction->operands[2].immediate = 0;
			break;
		case 2:
		case 8:
			if (decode.size == 3)
				return 1;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			break;
		case 5:
			if ((decode.size & 1) == 0)
				return 1;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_S_BASE, decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_D_BASE, decode.Rn);
			break;
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_scalar_3_different(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.9 Advanced SIMD scalar three different
	 *
	 * SQDMLAL <Va><d>, <Vb><n>, <Vb><m>
	 * SQDMLSL <Va><d>, <Vb><n>, <Vb><m>
	 * SQDMULL <Va><d>, <Vb><n>, <Vb><m>
	 */
	static const Operation operation[] = {
		ARM64_UNDEFINED,
		ARM64_SQDMLAL,
		ARM64_UNDEFINED,
		ARM64_SQDMLSL,
		ARM64_UNDEFINED,
		ARM64_SQDMULL,
		ARM64_UNDEFINED,
		ARM64_UNDEFINED,
	};
	SIMD_SCALAR_3_DIFFERENT  decode = *(SIMD_SCALAR_3_DIFFERENT *)&instructionValue;
	static const uint8_t regbase1[4] = {0, REG_S_BASE, REG_D_BASE, 0};
	static const uint8_t regbase2[4] = {0, REG_H_BASE, REG_S_BASE, 0};
	instruction->operation = operation[decode.opcode & 7];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase1[decode.size], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rm);
	return decode.opcode < 7 || decode.size == 0 || decode.size == 3 || instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_scalar_3_same(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.10 Advanced SIMD scalar three same
	 *
	 * SQADD	<V><d>, <V><n>, <V><m>
	 * SQSUB	<V><d>, <V><n>, <V><m>
	 * CMGT	 <V><d>, <V><n>, <V><m>
	 * CMGE	 <V><d>, <V><n>, <V><m>
	 * SSHL	 <V><d>, <V><n>, <V><m>
	 * SQSHL	<V><d>, <V><n>, <V><m>
	 * SQRSHL   <V><d>, <V><n>, <V><m>
	 * ADD	  <V><d>, <V><n>, <V><m>
	 * CMTST	<V><d>, <V><n>, <V><m>
	 * SQDMULH  <V><d>, <V><n>, <V><m>
	 * FMULX	<V><d>, <V><n>, <V><m>
	 * FCMEQ	<V><d>, <V><n>, <V><m>
	 * FRECPS   <V><d>, <V><n>, <V><m>
	 * FRSQRTS  <V><d>, <V><n>, <V><m>
	 * UQADD	<V><d>, <V><n>, <V><m>
	 * UQSUB	<V><d>, <V><n>, <V><m>
	 * CMHI	 <V><d>, <V><n>, <V><m>
	 * CMHS	 <V><d>, <V><n>, <V><m>
	 * USHL	 <V><d>, <V><n>, <V><m>
	 * UQRSHL   <V><d>, <V><n>, <V><m>
	 * URSHL	<V><d>, <V><n>, <V><m>
	 * SUB	  <V><d>, <V><n>, <V><m>
	 * CMEQ	 <V><d>, <V><n>, <V><m>
	 * CMEQ	 <V><d>, <V><n>, <V><m>
	 * SQRDMULH <V><d>, <V><n>, <V><m>
	 * FCMGE	<V><d>, <V><n>, <V><m>
	 * FACGE	<V><d>, <V><n>, <V><m>
	 * FABD	 <V><d>, <V><n>, <V><m>
	 * FCMGT	<V><d>, <V><n>, <V><m>
	 * FACGT	<V><d>, <V><n>, <V><m>
	 *
	 * Variants:
	 * 0: BHSD
	 * 1: D
	 * 2: HS
	 * 3: SD
	 */
	struct OpInfo {
		Operation op;
		uint32_t var;
	};
	/*static const Operation operation[] = {*/
	/*0 - xx - 0 	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 1 	{ARM64_SQADD,	 0},*/
	/*0 - xx - 2 	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 3 	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 4 	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 5 	{ARM64_SQSUB,	 0},*/
	/*0 - xx - 6 	{ARM64_CMGT,	  1},*/
	/*0 - xx - 7 	{ARM64_CMGE,	  1},*/
	/*0 - xx - 8 	{ARM64_SSHL,	  1},*/
	/*0 - xx - 9 	{ARM64_SQSHL,	 0},*/
	/*0 - xx - 10 	{ARM64_SRSHL,	 0},*/
	/*0 - xx - 11	{ARM64_SQRSHL,	0},*/
	/*0 - xx - 12	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 13	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 14	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 15	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 16	{ARM64_ADD,	   1},*/
	/*0 - xx - 17	{ARM64_CMTST,	 1},*/
	/*0 - xx - 18	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 19	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 20	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 21	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 22	{ARM64_SQDMULH,   3},*/
	/*0 - xx - 23	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 24	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 25	{ARM64_UNDEFINED, 0},*/
	/*0 - xx - 26	{ARM64_UNDEFINED, 0},*/
	/*0 - 0x - 27	{ARM64_FMULX,	 3},*/
	/*0 - 0x - 28	{ARM64_FCMEQ,	 3},*/
	/*0 - xx - 30	{ARM64_UNDEFINED, 0},*/
	/*0 - 0x - 31	{ARM64_FRECPS,	3},*/
	/*0 - 1x - 31	{ARM64_FRSQRTS,   3},*/

	/*1 - xx - 0 	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 1 	{ARM64_UQADD,	 0},*/
	/*1 - xx - 2 	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 3 	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 4 	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 5 	{ARM64_UQSUB,	 0},*/
	/*1 - xx - 6 	{ARM64_CMHI,	  1},*/
	/*1 - xx - 7 	{ARM64_CMHS,	  1},*/
	/*1 - xx - 8 	{ARM64_USHL,	  1},*/
	/*1 - xx - 9 	{ARM64_UQRSHL,	0},*/
	/*1 - xx - 10	{ARM64_URSHL,	 1},*/
	/*1 - xx - 11	{ARM64_UQRSHL,	0},*/
	/*1 - xx - 12	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 13	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 14	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 15	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 16	{ARM64_SUB,	   1},*/
	/*1 - xx - 17	{ARM64_CMEQ,	  1},*/
	/*1 - xx - 18	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 19	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 20	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 21	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 22	{ARM64_SQRDMULH,  2},*/
	/*1 - xx - 23	{ARM64_UNDEFINED, 0},*/
	/*1 - 0x - 24	{ARM64_FCMGE,	 3},*/
	/*1 - 0x - 25	{ARM64_FACGE,	 3},*/
	/*1 - 1x - 26	{ARM64_FABD,	  3},*/
	/*1 - 1x - 27	{ARM64_UNDEFINED, 0},*/
	/*1 - 1x - 28	{ARM64_FCMGT,	 3},*/
	/*1 - 1x - 29	{ARM64_FACGT,	  3},*/
	/*1 - xx - 30	{ARM64_UNDEFINED, 0},*/
	/*1 - xx - 31	{ARM64_UNDEFINED, 0},*/
	/*};*/
	SIMD_SCALAR_3_SAME  decode = *(SIMD_SCALAR_3_SAME *)&instructionValue;
	static const struct OpInfo operation[2][2][32] = {
	  {
		{
		{ARM64_UNDEFINED, 0},{ARM64_SQADD,     0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_SQSUB,     0},{ARM64_CMGT,      1},{ARM64_CMGE,      1},
		{ARM64_SSHL,      1},{ARM64_SQSHL,     0},{ARM64_SRSHL,     0},{ARM64_SQRSHL,    0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_ADD,       1},{ARM64_CMTST,     1},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_SQDMULH,   2},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_FMULX,     3},
		{ARM64_FCMEQ,     3},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_FRECPS,    3},
		},{
		{ARM64_UNDEFINED, 0},{ARM64_SQADD,     0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_SQSUB,     0},{ARM64_CMGT,      1},{ARM64_CMGE,      1},
		{ARM64_SSHL,      1},{ARM64_SQSHL,     0},{ARM64_SRSHL,     0},{ARM64_SQRSHL,    0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_ADD,       1},{ARM64_CMTST,     1},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_SQDMULH,   2},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_FMULX,     3},
		{ARM64_FCMEQ,     3},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_FRSQRTS,   3},
		}
		},{
		{
		{ARM64_UNDEFINED, 0},{ARM64_UQADD,     0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UQSUB,     0},{ARM64_CMHI,      1},{ARM64_CMHS,      1},
		{ARM64_USHL,      1},{ARM64_UQSHL,     0},{ARM64_URSHL,     1},{ARM64_UQRSHL,    0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_SUB,       1},{ARM64_CMEQ,      1},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_SQRDMULH,  2},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_FCMGE,     3},{ARM64_FACGE,     3},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		},{
		{ARM64_UNDEFINED, 0},{ARM64_UQADD,     0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UQSUB,     0},{ARM64_CMHI,      1},{ARM64_CMHS,      1},
		{ARM64_USHL,      1},{ARM64_UQSHL,     0},{ARM64_URSHL,     1},{ARM64_UQRSHL,    0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_SUB,       1},{ARM64_CMEQ,      1},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_SQRDMULH,  2},{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},{ARM64_FABD,      3},{ARM64_UNDEFINED, 0},
		{ARM64_FCMGT,     3},{ARM64_FACGT,     3},{ARM64_UNDEFINED, 0},{ARM64_UNDEFINED, 0},
		}
	  }
	};

	const struct OpInfo* opinfo = &operation[decode.U][decode.size>>1][decode.opcode];
	static const uint8_t regbase[4][4] = {
		{REG_B_BASE, REG_H_BASE, REG_S_BASE, REG_D_BASE},
		{REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE},
		{REG_S_BASE, REG_H_BASE, REG_S_BASE, REG_H_BASE},
		{REG_S_BASE, REG_D_BASE, REG_S_BASE, REG_D_BASE}
	};
	instruction->operation = opinfo->op;
	//printf("U: %d s: %d opc: %d - str: %s\n", decode.U, decode.size>>1, decode.opcode, OperationString[opinfo->op]);
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[opinfo->var][decode.size], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase[opinfo->var][decode.size], decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, regbase[opinfo->var][decode.size], decode.Rm);
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_scalar_copy(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.6 Advanced SIMD scalar copy
	 *
	 * DUP <V><d>, <Vn>.<T>[<index>]
	 */
	SIMD_SCALAR_COPY  decode = *(SIMD_SCALAR_COPY *)&instructionValue;
	uint32_t size = 0;
	if (decode.imm5 == 0 || decode.imm5 == 16)
		return 1;
	for (; size < 4; size++)
		if (((decode.imm5 >> size) & 1) == 1)
			break;
	instruction->operation = ARM64_MOV;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	static const uint8_t regset[4] = {REG_B_BASE, REG_H_BASE, REG_S_BASE, REG_D_BASE};
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regset[size], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[1].elementSize = 1 << size;
	instruction->operands[1].scale = 0x80000000 | (decode.imm5 >> (1+size));
	return decode.op != 0 || decode.imm4 != 0;
}


uint32_t aarch64_decompose_simd_scalar_indexed_element(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.12 Advanced SIMD scalar x indexed element
	 *
	 * SQDMLAL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
	 * SQDMLSL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
	 * SQDMULL  <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
	 * SQDMULH  <V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 * SQRDMULH <V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 * FMLA	 <V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 * FMLS	 <V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 * FMUL	 <V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 * FMULX	<V><d>,  <V><n>,  <Vm>.<Ts>[<index>]
	 */
	SIMD_SCALAR_X_INDEXED_ELEMENT  decode = *(SIMD_SCALAR_X_INDEXED_ELEMENT *)&instructionValue;
	uint32_t index = 0;
	uint32_t hireg = decode.M << 4;
	static const uint32_t regbase[4] = {0, REG_S_BASE, REG_D_BASE, 0};
	static const uint32_t regbase2[4] = {0 ,REG_H_BASE, REG_S_BASE, 0};
	static const uint32_t regbase3[2] = {REG_S_BASE, REG_D_BASE};

	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase3[decode.size & 1], decode.Rn);

	if (decode.size == 1)
	{
		index = decode.H << 2 | decode.L << 1 | decode.M;
	}
	else if (decode.size == 2)
	{
		index = decode.H << 1 | decode.L;
	}
	instruction->operands[2].elementSize = 4 << (decode.size & 1);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, hireg | decode.Rm);
	switch (decode.opcode)
	{
		case 1:
			if (decode.size < 2)
				return 1;
			instruction->operation = ARM64_FMLA;
			if ((decode.size & 1) == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H << 1 | decode.L;
			else if ((decode.size & 1) == 1 && decode.L == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H;
			break;
		case 3:
			instruction->operation = ARM64_SQDMLAL;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			if (decode.size == 1)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			else if (decode.size == 2)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
			instruction->operands[2].scale = 0x80000000 | index;
			instruction->operands[2].elementSize = 1<<decode.size;
			break;
		case 5:
			if (decode.size < 2)
				return 1;
			instruction->operation = ARM64_FMLS;
			if ((decode.size & 1) == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H << 1 | decode.L;
			else if ((decode.size & 1) == 1 && decode.L == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H;
			break;
		case 7:
			instruction->operation = ARM64_SQDMLSL;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			if (decode.size == 1)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			else if (decode.size == 2)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
			instruction->operands[2].scale = 0x80000000 | index;
			instruction->operands[2].elementSize = 1<<decode.size;
			break;
		case 9:
			if (decode.size < 2)
				return 1;
			if (decode.U == 0)
				instruction->operation = ARM64_FMUL;
			else
				instruction->operation = ARM64_FMULX;
			if ((decode.size & 1) == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H << 1 | decode.L;
			else if ((decode.size & 1) == 1 && decode.L == 0)
				instruction->operands[2].scale = 0x80000000 | decode.H;
			break;
		case 11:
			instruction->operation = ARM64_SQDMULL;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			if (decode.size == 1)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			else if (decode.size == 2)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
			instruction->operands[2].scale = 0x80000000 | index;
			instruction->operands[2].elementSize = 1<<decode.size;
			break;
		case 12:
			instruction->operation = ARM64_SQDMULH;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			if (decode.size == 1)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			else if (decode.size == 2)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
			instruction->operands[2].scale = 0x80000000 | index;
			instruction->operands[2].elementSize = 1<<decode.size;
			break;
		case 13:
			instruction->operation = ARM64_SQRDMULH;
			instruction->operands[0].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rd);
			instruction->operands[1].reg[0] = REG(REGSET_ZR, regbase2[decode.size], decode.Rn);
			if (decode.size == 1)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
			else if (decode.size == 2)
				instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
			instruction->operands[2].scale = 0x80000000 | index;
			instruction->operands[2].elementSize = 1<<decode.size;
			break;
	}

	return 0;
}


uint32_t aarch64_decompose_simd_scalar_pairwise(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.7 Advanced SIMD scalar pairwise
	 *
	 * ADDP	<V><d>, <Vn>.<T>
	 * FMAXNMP <V><d>, <Vn>.<T>
	 * FADDP   <V><d>, <Vn>.<T>
	 * FADDP   <V><d>, <Vn>.<T>
	 * FMAXP   <V><d>, <Vn>.<T>
	 * FMINNMP <V><d>, <Vn>.<T>
	 * FMINP   <V><d>, <Vn>.<T>
	 */
	SIMD_SCALAR_PAIRWISE decode = *(SIMD_SCALAR_PAIRWISE*)&instructionValue;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	static const uint8_t regset[2] = {REG_S_BASE, REG_D_BASE};
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regset[decode.size&1], decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[1].elementSize = 4 << decode.size;
	instruction->operands[1].dataSize = 2;
	switch (decode.opcode)
	{
		case 27:
			if (decode.U == 0)
			{
				instruction->operation = ARM64_ADDP;
				if (decode.size != 3)
					return 1;
				instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_D_BASE, decode.Rd);
				instruction->operands[1].elementSize = 8;
				instruction->operands[1].dataSize = 2;
			}
			break;
		case 12:
			 if (decode.U == 1)
			 {
				 if (decode.size < 2)
					instruction->operation = ARM64_FMAXNMP;
				else
					instruction->operation = ARM64_FMINNMP;
			 }
			 else
				 return 1;
			 break;
		case 13:
			 instruction->operation = ARM64_FADDP;
			 break;
		case 15:
			if (decode.U == 1)
			{
				if (decode.size < 2)
					instruction->operation = ARM64_FMAXP;
				else
					instruction->operation = ARM64_FMINP;
			}
			else
				return 1;
			break;
		default:
			 return 1;
	}
	return 0;
}


uint32_t aarch64_decompose_simd_scalar_shift_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.8 Advanced SIMD scalar shift by immediate
	 *
	 * SSHR	 <V><d>, <V><n>, #<shift>
	 * SSRA	 <V><d>, <V><n>, #<shift>
	 * SRSHR	<V><d>, <V><n>, #<shift>
	 * SRSRA	<V><d>, <V><n>, #<shift>
	 * SHL	  <V><d>, <V><n>, #<shift>
	 * SQSHL	<V><d>, <V><n>, #<shift>
	 * SQSHRN   <Vb><d>, <Va><n>, #<shift>
	 * SQRSHRN  <Vb><d>, <Va><n>, #<shift>
	 * SCVTF	<V><d>, <V><n>, #<fbits>
	 * FCVTZS   <V><d>, <V><n>, #<fbits>
	 * USHR	 <V><d>, <V><n>, #<shift>
	 * USRA	 <V><d>, <V><n>, #<shift>
	 * URSHR	<V><d>, <V><n>, #<shift>
	 * URSRA	<V><d>, <V><n>, #<shift>
	 * SRI	  <V><d>, <V><n>, #<shift>
	 * SLI	  <V><d>, <V><n>, #<shift>
	 * SQSHLU   <V><d>, <V><n>, #<shift>
	 * UQSHL	<V><d>, <V><n>, #<shift>
	 * SQSHRUN  <Vb><d>, <Va><n>, #<shift>
	 * SQRSHRUN <Vb><d>, <Va><n>, #<shift>
	 * UQSHRN   <Vb><d>, <Va><n>, #<shift>
	 * UQRSHRN  <Vb><d>, <Va><n>, #<shift>
	 * UCVTF	<V><d>, <V><n>, #<fbits>
	 * FCVTZU   <V><d>, <V><n>, #<fbits>
	 */
	typedef enum _shiftCalc {SH_3, SH_HB, SH_IH} shiftCalc;
	struct decodeOperation {
		Operation op;
		uint32_t esize;
		shiftCalc calc;
		uint32_t regBase;
	};
	SIMD_SHIFT_BY_IMM decode = *(SIMD_SHIFT_BY_IMM*)&instructionValue;
	static const struct decodeOperation operation[2][32] = {
		{
			{ARM64_SSHR,      8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SSRA,      8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SRSHR,     8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SRSRA,     8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SHL,       8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SQSHL,     8, SH_HB, 1},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SQSHRN,    8, SH_HB, 2},  {ARM64_SQRSHRN,   8, SH_HB, 2},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SCVTF,    32, SH_IH, 3},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_FCVTZS,   32, SH_IH, 3}
		},{
			{ARM64_USHR,      8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_USRA,      8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_URSHR,     8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_URSRA,     8, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SRI,       8, SH_3,  1},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SLI,       8, SH_3,  1},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SQSHLU,    8, SH_HB, 1},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UQSHL,     8, SH_HB, 1},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_SQSHRUN,   8, SH_HB, 2},  {ARM64_SQRSHRUN,  8, SH_HB, 2},
			{ARM64_UQSHRN,    8, SH_HB, 2},  {ARM64_UQRSHRN,   8, SH_HB, 2},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UCVTF,    32, SH_IH, 3},  {ARM64_UNDEFINED, 0, SH_3, 0},
			{ARM64_UNDEFINED, 0, SH_3,  0},  {ARM64_FCVTZU,   32, SH_IH, 3}
		}
	};

	static const uint32_t regBaseMap[4][16] = {
		{
			REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE,
			REG_D_BASE,REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE
		},{
			REG_NONE, REG_B_BASE, REG_H_BASE, REG_H_BASE, REG_S_BASE, REG_S_BASE, REG_S_BASE, REG_S_BASE,
			REG_D_BASE,REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE
		},{
			REG_NONE, REG_B_BASE, REG_H_BASE, REG_H_BASE, REG_S_BASE, REG_S_BASE, REG_S_BASE, REG_S_BASE,
			REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_NONE,
		},{
			REG_NONE, REG_NONE, REG_NONE, REG_NONE, REG_S_BASE,	REG_S_BASE, REG_S_BASE,	REG_S_BASE,
			REG_D_BASE,REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE, REG_D_BASE
		}
	};

	const struct decodeOperation* decodeOp = &operation[decode.U][decode.opcode];
	uint32_t regBase = regBaseMap[decodeOp->regBase][decode.immh];
	if (regBase == REG_NONE)
		return 1;
	instruction->operation = decodeOp->op;
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regBase, decode.Rd);

	instruction->operands[1].operandClass = REG;
	uint32_t regOffset = 0;
	if (decode.opcode >= 16 && decode.opcode <= 19)
	{
		regOffset = 1;
	}
	instruction->operands[1].reg[0] = REG(REGSET_ZR, regBase+regOffset, decode.Rn);

	uint32_t esize = 0;
	switch (decodeOp->calc)
	{
		case SH_3:   esize = decodeOp->esize << 3; break;
		case SH_HB:  esize = decodeOp->esize << HighestSetBit(decode.immh); break;
		case SH_IH:  esize = decodeOp->esize << ((decode.immh >> 3)&1); break;
	}
	if (decode.opcode == 10 || decode.opcode == 14 || instruction->operation == ARM64_SQSHLU)
	{
		instruction->operands[2].immediate = ((decode.immh << 3)|decode.immb) - (esize);
	}
	else
	{
		instruction->operands[2].immediate = (esize*2) - ((decode.immh << 3)|decode.immb);
	}
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[2].signedImm = decode.U;
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_shift_imm(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.13 Advanced SIMD shift by immediate
	 *
	 * SSHR		<Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SSRA		<Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SRSHR	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SRSRA	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SHL		 <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SQSHL	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SHRN{2}	 <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * RSHRN{2}	<Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * SQSHRN{2}   <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * SQRSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * SSHLL{2}	<Vd>.<Ta>, <Vn>.<Tb>, #<shift>
	 * SCVTF	   <Vd>.<T>,  <Vn>.<T>,  #<fbits>
	 * FCVTZS	  <Vd>.<T>,  <Vn>.<T>,  #<fbits>
	 * USHR		<Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * USRA		<Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * URSHR	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * URSRA	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SRI		 <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SLI		 <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SQSHLU	  <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * UQSHL	   <Vd>.<T>,  <Vn>.<T>,  #<shift>
	 * SQSHRUN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * SQRSHRUN{2} <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * UQSHRN{2}   <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * UQRSHRN{2}  <Vd>.<Tb>, <Vn>.<Ta>, #<shift>
	 * USHLL{2}	<Vd>.<Ta>, <Vn>.<Tb>, #<shift>
	 * UCVTF	   <Vd>.<T>,  <Vn>.<T>,  #<fbits>
	 * FCVTZU	  <Vd>.<T>,  <Vn>.<T>,  #<fbits>
	 *
	 * Alias
	 * SSHLL{2} <Vd>.<Ta>, <Vn>.<Tb>, #0 -> SCVTF <V><d>, <V><n>, #<fbits>
	 * USHLL{2} <Vd>.<Ta>, <Vn>.<Tb>, #0 -> UXTL{2} <Vd>.<Ta>, <Vn>.<Tb>
	 */
	struct OpInfo {
		Operation op;
		uint32_t var;
	};

	static const struct OpInfo operation[2][32] = {
	  {
		{ARM64_SSHR,       0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SSRA,       0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SRSHR,      0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SRSRA,      0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SHL,        3},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SQSHL,      3},
		{ARM64_UNDEFINED,  0},
		{ARM64_SHRN,       1},
		{ARM64_RSHRN,      1},
		{ARM64_SQSHRN,     1},
		{ARM64_SQRSHRN,    1},
		{ARM64_SSHLL,      4},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SCVTF,      2},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_FCVTZS,     2},
	},{
		{ARM64_USHR,       0},
		{ARM64_UNDEFINED,  0},
		{ARM64_USRA,       0},
		{ARM64_UNDEFINED,  0},
		{ARM64_URSHR,      0},
		{ARM64_UNDEFINED,  0},
		{ARM64_URSRA,      0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SRI,        0},
		{ARM64_UNDEFINED,  0},
		{ARM64_SLI,        3},
		{ARM64_UNDEFINED,  0},
		{ARM64_SQSHLU,     3},
		{ARM64_UNDEFINED,  0},
		{ARM64_UQSHL,      3},
		{ARM64_UNDEFINED,  0},
		{ARM64_SQSHRUN,    1},
		{ARM64_SQRSHRUN,   1},
		{ARM64_UQSHRN,     1},
		{ARM64_UQRSHRN,    1},
		{ARM64_USHLL,      4},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_UCVTF,      2},
		{ARM64_UNDEFINED,  0},
		{ARM64_UNDEFINED,  0},
		{ARM64_FCVTZU,     2},
	  }
	};
	SIMD_SHIFT_BY_IMM  decode = *(SIMD_SHIFT_BY_IMM *)&instructionValue;
	const struct OpInfo* opinfo = &operation[decode.U][decode.opcode];
	//printf("opcod: %d U: %d '%s'\n", decode.opcode, decode.U, OperationString[opinfo->op]);
	static const uint8_t sizemap[2] = {64,128};
	uint32_t size = 0;
	for (; size < 4; size++)
		if ((decode.immh >> size) == 1)
			break;
	instruction->operation = opinfo->op;
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = IMM32;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].immediate = (16 << size) - (decode.immh << 3 | decode.immb);
	switch (opinfo->var)
	{
		case 0:
			instruction->operands[0].elementSize = 1 << size;
			instruction->operands[1].elementSize = 1 << size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(8<<size);
			instruction->operands[1].dataSize = sizemap[decode.Q]/(8<<size);
			//instruction->operands[2].immediate =(decode.immh << 3 | decode.immb) - (8 << size);
			break;
		case 1:
			instruction->operation = (Operation)(instruction->operation + decode.Q);
			instruction->operands[0].elementSize = 1 << size;
			instruction->operands[1].elementSize = 2 << size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(8<<size);
			instruction->operands[1].dataSize = 64/(8<<size);
			break;
		case 2:
			if (decode.immh >> 2 == 1)
				size = 0;
			else if (decode.immh >> 3 == 1)
				size = 1;
			else
				return 1;
			instruction->operands[0].elementSize = 4 << size;
			instruction->operands[1].elementSize = 4 << size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(32 << size);
			instruction->operands[1].dataSize = sizemap[decode.Q]/(32 << size);
			break;
		case 3:
			instruction->operands[0].elementSize = 1 << size;
			instruction->operands[1].elementSize = 1 << size;
			instruction->operands[0].dataSize = sizemap[decode.Q]/(8<<size);
			instruction->operands[1].dataSize = sizemap[decode.Q]/(8<<size);
			instruction->operands[2].immediate =(decode.immh << 3 | decode.immb) - (8 << size);
			break;
		case 4:
			instruction->operation = (Operation)(instruction->operation + decode.Q);
			instruction->operands[0].elementSize = 2 << size;
			instruction->operands[1].elementSize = 1 << size;
			instruction->operands[0].dataSize = 64/(8<<size);
			instruction->operands[1].dataSize = sizemap[decode.Q]/(8<<size);
			instruction->operands[2].immediate =(decode.immh << 3 | decode.immb) - (8 << size);
			break;

	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_simd_table_lookup(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.14 Advanced SIMD table lookup
	 *
	 * TBL <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
	 * TBX <Vd>.<Ta>, { <Vn>.16B }, <Vm>.<Ta>
	 * TBL <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
	 * TBX <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
	 * TBL <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B }, <Vm>.<Ta>
	 * TBL <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B }, <Vm>.<Ta>
	 * TBX <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B }, <Vm>.<Ta>
	 * TBL <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B, <Vn+3>.16B }, <Vm>.<Ta>
	 * TBX <Vd>.<Ta>, { <Vn>.16B, <Vn+1>.16B, <Vn+2>.16B, <Vn+3>.16B }, <Vm>.<Ta>
	 */
	SIMD_TABLE_LOOKUP decode = *(SIMD_TABLE_LOOKUP*)&instructionValue;
	static const Operation operation[] = {
		ARM64_TBL,
		ARM64_TBX,
	};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = MULTI_REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	for (uint32_t i = 0; i < (uint32_t)(decode.len+1); i++)
		instruction->operands[1].reg[i] = REG(REGSET_ZR, REG_V_BASE, ((decode.Rn+i)%32));
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	instruction->operands[0].elementSize = 1;
	instruction->operands[1].elementSize = 1;
	instruction->operands[2].elementSize = 1;
	instruction->operands[0].dataSize = 8<<decode.Q;
	instruction->operands[1].dataSize = 16;
	instruction->operands[2].dataSize = 8<<decode.Q;
	return 0;
}


uint32_t aarch64_decompose_simd_vector_indexed_element(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.6.18 Advanced SIMD vector x indexed element
	 *
	 * SMLAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * SQDMLAL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * SMLSL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * SQDMLSL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * MUL        <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * SMULL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * SQDMULL{2} <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * SQDMULH    <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * SQRDMULH   <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * FMLA       <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * FMLS       <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * FMUL       <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * MLA        <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * UMLAL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * MLS        <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 * UMLSL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * UMULL{2}   <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>]
	 * FMULX      <Vd>.<T>,  <Vn>.<T>,  <Vm>.<Ts>[<index>]
	 */
	struct OpInfo {
		Operation op;
		uint32_t var;
	};
	const struct OpInfo* opinfo;
	static const struct OpInfo operation[2][16] = {
	{
		{ARM64_UNDEFINED, 0},
		{ARM64_FMLA,      3},
		{ARM64_SMLAL,     1},
		{ARM64_SQDMLAL,   1},
		{ARM64_UNDEFINED, 0},
		{ARM64_FMLS,      3},
		{ARM64_SMLSL,     1},
		{ARM64_SQDMLSL,   1},
		{ARM64_MUL,       0},
		{ARM64_FMUL,      3},
		{ARM64_SMULL,     1},
		{ARM64_SQDMULL,   1},
		{ARM64_SQDMULH,   0},
		{ARM64_SQRDMULH,  0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
	},{
		{ARM64_MLA,       0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UMLAL,     1},
		{ARM64_UNDEFINED, 0},
		{ARM64_MLS,       0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UMLSL,     1},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
		{ARM64_FMULX,     3},
		{ARM64_UMULL,     1},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
		{ARM64_UNDEFINED, 0},
	}
	};
	SIMD_VECTOR_X_INDEXED_ELEMENT decode = *(SIMD_VECTOR_X_INDEXED_ELEMENT*)&instructionValue;
	opinfo = &operation[decode.U][decode.opcode];
	instruction->operation = opinfo->op;

	instruction->operands[0].operandClass = REG;
	instruction->operands[1].operandClass = REG;
	instruction->operands[2].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
	instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
	instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rm);
	uint32_t index = decode.H << 2 | decode.L << 1 | decode.M;
	if (opinfo->var == 1)
	{
		if (decode.size == 0 || decode.size == 3)
			return 1;
		uint32_t reghi = decode.size == 2?(decode.M << 4):0;
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, reghi | decode.Rm);
		//'2' variant is always the next enumeration value
		instruction->operation = (Operation)(instruction->operation + decode.Q);
		instruction->operands[0].elementSize = 2 << decode.size;
		instruction->operands[1].elementSize = 1 << decode.size;
		instruction->operands[2].elementSize = 1 << decode.size;
		instruction->operands[0].dataSize = 8 >> decode.size;
		instruction->operands[1].dataSize = 8 >> (decode.size-decode.Q);
		instruction->operands[2].dataSize = 0;
		instruction->operands[2].scale = 0x80000000 | (index >> (decode.size-1));
	}
	else if (opinfo->var == 2)
	{
		if (((decode.size & 1) == 1 && decode.Q == 0) || (decode.size == 1 && decode.L == 1))
			return 1;
		instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.M << 4 | decode.Rm);
		instruction->operands[0].elementSize = 2 << (decode.size & 1);
		instruction->operands[1].elementSize = 2 << (decode.size & 1);
		instruction->operands[2].elementSize = 4 << (decode.size & 1);
		instruction->operands[0].dataSize = 2 << ((decode.size & 1) - decode.Q);
		instruction->operands[1].dataSize = 2 << ((decode.size & 1) - decode.Q);
		instruction->operands[2].dataSize = 0;
		instruction->operands[2].scale = 0x80000000 | (index >> ((decode.size & 1) + 1));
	}
	else if (opinfo->var == 3)
	{
		instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, (decode.M << 4) | decode.Rm);
		instruction->operands[0].elementSize = 1 << decode.size;
		instruction->operands[1].elementSize = 1 << decode.size;
		instruction->operands[2].elementSize = 1 << decode.size;
		instruction->operands[0].dataSize = 8 >> (decode.size - decode.Q);
		instruction->operands[1].dataSize = 8 >> (decode.size - decode.Q);
		instruction->operands[2].dataSize = 0;
		instruction->operands[2].scale = 0x80000000 | (index >> (decode.size-1));
	}
	else
	{
		uint32_t reghi = decode.size == 2?(decode.M << 4):0;
		instruction->operands[0].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rd);
		instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_V_BASE, decode.Rn);
		instruction->operands[2].reg[0] = REG(REGSET_ZR, REG_V_BASE, reghi | decode.Rm);
		instruction->operands[0].elementSize = 1 << decode.size;
		instruction->operands[1].elementSize = 1 << decode.size;
		instruction->operands[2].elementSize = 1 << decode.size;
		instruction->operands[0].dataSize = 8 >> (decode.size - decode.Q);
		instruction->operands[1].dataSize = 8 >> (decode.size - decode.Q);
		instruction->operands[2].dataSize = 0;
		instruction->operands[2].scale = 0x80000000 | (index >> (decode.size-1));
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_system_arch_hints(SYSTEM decode, Instruction* restrict instruction)
{
	switch (decode.CRn)
	{
	case 2: //Architectural hints
		switch ((decode.CRm << 3) | decode.op2)
		{
		default:
			instruction->operation = ARM64_HINT;
			instruction->operands[0].operandClass = IMM32;
			instruction->operands[0].immediate = (decode.CRm << 3) | decode.op2;
			break;
		case 0: instruction->operation = ARM64_NOP; break;
		case 1: instruction->operation = ARM64_YIELD; break;
		case 2: instruction->operation = ARM64_WFE; break;
		case 3: instruction->operation = ARM64_WFI; break;
		case 4: instruction->operation = ARM64_SEV; break;
		case 5: instruction->operation = ARM64_SEVL; break;

		// Added with 8.2
		case 16: instruction->operation = ARM64_ESB; break;
		case 17: instruction->operation = ARM64_PSBCSYNC; break;

		// Added for 8.3
		case  7: instruction->operation = ARM64_XPACLRI; break;

		case  8: instruction->operation = ARM64_PACIA1716; break;
		case 10: instruction->operation = ARM64_PACIB1716; break;
		case 12: instruction->operation = ARM64_AUTIA1716; break;
		case 14: instruction->operation = ARM64_AUTIB1716; break;

		case 24: instruction->operation = ARM64_PACIAZ; break;
		case 25: instruction->operation = ARM64_PACIASP; break;
		case 26: instruction->operation = ARM64_PACIBZ; break;
		case 27: instruction->operation = ARM64_PACIBSP; break;
		case 28: instruction->operation = ARM64_AUTIAZ; break;
		case 29: instruction->operation = ARM64_AUTIASP; break;
		case 30: instruction->operation = ARM64_AUTIBZ; break;
		case 31: instruction->operation = ARM64_AUTIBSP; break;
		}
		break;
	case 3: //Barriers and CLREX
		switch (decode.op2)
		{
		case 2:
			instruction->operation = ARM64_CLREX;
			if (decode.CRm != 0xf)
			{
				instruction->operands[0].operandClass = IMM32;
				instruction->operands[0].immediate = decode.CRm;
			}
			break;
		case 4:
			instruction->operation = ARM64_DSB;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = REG_NUMBER0 + decode.CRm;
			break;
		case 5:
			instruction->operation = ARM64_DMB;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = REG_NUMBER0 + decode.CRm;
			break;
		case 6:
			instruction->operation = ARM64_ISB;
			if (decode.CRm != 15)
			{
				instruction->operands[0].operandClass = IMM32;
				instruction->operands[0].immediate = decode.CRm;
			}
			break;
		default:
			return 1;
		}
		break;
	case 4: //PSTATE Access
		switch(decode.op2)
		{
		case 5:
			if (decode.op1 != 0)
				return 1;
			instruction->operands[0].reg[0] = (Register)REG_SPSEL;
			break;
		case 6:
			if (decode.op1 != 3)
				return 1;
			instruction->operands[0].reg[0] = (Register)REG_DAIFSET;
			break;
		case 7:
			instruction->operands[0].reg[0] = (Register)REG_DAIFCLR;
			break;
		default:
			return 1;
		}
		instruction->operation = ARM64_MSR;
		instruction->operands[0].operandClass = SYS_REG;
		instruction->operands[1].operandClass = IMM32;
		instruction->operands[1].immediate = decode.CRm;
		break;
	default:
		{
		static const Operation operation[2] = {ARM64_SYS, ARM64_SYSL};
		static const uint32_t operandSet[2][5] = {{0,1,2,3,4},{1,2,3,4,0}};
		instruction->operation = operation[decode.L];
		instruction->operands[operandSet[decode.L][0]].operandClass = IMM32;
		instruction->operands[operandSet[decode.L][0]].immediate = decode.op1;
		instruction->operands[operandSet[decode.L][1]].operandClass = SYS_REG;
		instruction->operands[operandSet[decode.L][1]].reg[0] = REG_C0 + decode.CRn;
		instruction->operands[operandSet[decode.L][2]].operandClass = SYS_REG;
		instruction->operands[operandSet[decode.L][2]].reg[0] = REG_C0 + decode.CRm;
		instruction->operands[operandSet[decode.L][3]].operandClass = IMM32;
		instruction->operands[operandSet[decode.L][3]].immediate = decode.op2;
		if (decode.Rt != 31)
		{
			instruction->operands[operandSet[decode.L][4]].operandClass = REG;
			instruction->operands[operandSet[decode.L][4]].reg[0] =
				REG(REGSET_ZR, REG_X_BASE, decode.Rt);
		}
		}
	}
	return 0;
}


uint32_t aarch64_decompose_system_cache_maintenance(SYSTEM decode, Instruction* restrict instruction)
{
	instruction->operands[1].operandClass = REG;
	switch (decode.CRn)
	{
	case 7:
		switch (decode.CRm)
		{
		case 1: //Instruction cache maintenance instructions
			instruction->operation = ARM64_IC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = (Register)REG_IALLUIS;
			instruction->operands[1].operandClass = NONE;
			break;
		case 5: //Instruction cache maintenance instructions
			instruction->operation = ARM64_IC;
			instruction->operands[0].operandClass = SYS_REG;
			if (decode.op1 == 3)
			{
				instruction->operands[0].reg[0] = (Register)REG_IVAU;
				instruction->operands[1].operandClass = REG;
				instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			}
			else
			{
				instruction->operands[0].reg[0] = (Register)REG_IALLU;
				instruction->operands[1].operandClass = NONE;
			}
			break;
		case 4: //Data cache zero operation
			instruction->operation = ARM64_DC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = (Register)REG_ZVA;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			break;
		case 6:
			instruction->operation = ARM64_DC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			if (decode.op2 == 1)
				instruction->operands[0].reg[0] = (Register)REG_IVAC;
			else if (decode.op2 == 2)
				instruction->operands[0].reg[0] = (Register)REG_ISW;
			break;
		case 10:
			instruction->operation = ARM64_DC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = (Register)REG_CSW;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] =  REG(1, REG_X_BASE, decode.Rt);
			if (decode.op1 == 3 && decode.op2 == 1)
				instruction->operands[0].reg[0] = (Register)REG_CVAC;
			else if (decode.op1 != 0 || decode.op2 != 2)
				return 1;
			break;
		case 11:
			instruction->operation = ARM64_DC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = (Register)REG_CVAU;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(1, REG_X_BASE, decode.Rt);
			if (decode.op1 != 3 || decode.op2 != 1)
				return 1;
			break;
		case 14: //Data cache maintenance instructions
			instruction->operation = ARM64_DC;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = (Register)REG_CIVAC;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			if (decode.op1 == 0 && decode.op2 == 2)
				instruction->operands[0].reg[0] = (Register)REG_CISW;
			else if (decode.op1 != 3 || decode.op2 != 1)
				return 1;
			break;
		case 8: //Address translation instructions
			instruction->operation = ARM64_AT;
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[1].operandClass = REG;
			instruction->operands[1].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
			if (decode.op1 == 0 && decode.op2 < 4)
			{
				static const SystemReg sysregs[] = {REG_S1E1R, REG_S1E1W, REG_S1E0R, REG_S1E0W };
				instruction->operands[0].reg[0] = (Register)sysregs[decode.op2];
			}
			else if (decode.op1 == 4)
			{
				static const SystemReg sysregs[] = {
					REG_S1E2R,  REG_S1E2W, SYSREG_NONE, SYSREG_NONE,
					REG_S12E1R, REG_S12E1W, REG_S12E0R, REG_S12E0W
				};
				instruction->operands[0].reg[0] = (Register)sysregs[decode.op2];
			}
			else if (decode.op1 == 6 && decode.op2 < 2)
			{
				static const SystemReg sysregs[] = {REG_S1E3R, REG_S1E3W};
				instruction->operands[0].reg[0] = sysregs[decode.op2];
			}
			break;
		}
		break;
	case 8: //TLB maintenance instruction
		{
			instruction->operation = ARM64_TLBI;
			SystemReg sysreg = SYSREG_NONE;
			switch (decode.op1)
			{
			case 0:
				switch (decode.CRm)
				{
				case 3:
					{
					static const SystemReg sysregs[] = {
						REG_VMALLE1IS, REG_VAE1IS,  REG_ASIDE1IS, REG_VAAE1IS,
						SYSREG_NONE,   REG_VALE1IS, SYSREG_NONE,  REG_VAALE1IS
					};
					sysreg = sysregs[decode.op2];
					instruction->operands[1].operandClass = decode.op2==0?NONE:REG;
					break;
					}
				case 7:
					{
					static const SystemReg sysregs[] = {
						REG_VMALLE1, REG_VAE1,  REG_ASIDE1,  REG_VAAE1,
						SYSREG_NONE, REG_VALE1, SYSREG_NONE, REG_VAALE1
					};
					sysreg = sysregs[decode.op2];
					instruction->operands[1].operandClass = decode.op2==0?NONE:REG;
					instruction->operands[1].operandClass = decode.op2==0?NONE:REG;
					break;
					}
				}
				break;
			case 4:
				switch (decode.CRm)
				{
				case 0:
					{
					static const SystemReg sysregs[] = {
						SYSREG_NONE, REG_IPAS2E1IS, SYSREG_NONE,
						SYSREG_NONE,SYSREG_NONE, REG_IPAS2LE1IS};
					sysreg = sysregs[decode.op2];
					break;
					}
				case 3:
					{
					static const SystemReg sysregs[] = {
						REG_ALLE2IS, REG_VAE2IS, SYSREG_NONE, SYSREG_NONE,
						REG_ALLE1IS, REG_VALE2IS, REG_VMALLS12E1IS, SYSREG_NONE};
					sysreg = sysregs[decode.op2];
					if (decode.op2 == 0 || decode.op2 == 4 || decode.op2 == 6)
						instruction->operands[1].operandClass = NONE;
					break;
					}
				case 4:
					if (decode.op2 == 1)
						sysreg = REG_IPAS2E1;
					else if (decode.op2 == 5)
						sysreg = REG_IPAS2LE1;
					break;
				case 7:
					{
					static const SystemReg sysregs[] = {
						REG_ALLE2, REG_VAE2, SYSREG_NONE, SYSREG_NONE,
						REG_ALLE1, REG_VALE2, REG_VMALLS12E1, SYSREG_NONE};
					sysreg = sysregs[decode.op2];
					if (decode.op2 == 0 || decode.op2 == 4 || decode.op2 == 6)
						instruction->operands[1].operandClass = NONE;
					break;
					}
				}
				break;
			case 6:
				switch (decode.CRm)
				{
				case 3:
					{
					static const SystemReg sysregs[] = {
						REG_ALLE3IS, REG_VAE3IS, SYSREG_NONE, SYSREG_NONE,
						SYSREG_NONE, REG_VALE3IS, SYSREG_NONE, SYSREG_NONE};
					sysreg = sysregs[decode.op2];
					instruction->operands[1].operandClass = decode.op2==0?NONE:REG;
					break;
					}
				case 7:
					{
					static const SystemReg sysregs[] = {
						REG_ALLE3, REG_VAE3, SYSREG_NONE, SYSREG_NONE,
						SYSREG_NONE, REG_VALE3, SYSREG_NONE, SYSREG_NONE};
					sysreg = sysregs[decode.op2];
					instruction->operands[1].operandClass = decode.op2==0?NONE:REG;
					break;
					}
				}
				break;
			}
			instruction->operands[0].operandClass = SYS_REG;
			instruction->operands[0].reg[0] = sysreg;
			instruction->operands[1].reg[0] = REG(1, REG_X_BASE, decode.Rt);
		}
		break;
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:
	default:
		{
		static const Operation operation[2] = {ARM64_SYS, ARM64_SYSL};
		static const uint32_t operandSet[2][5] = {{0,1,2,3,4},{1,2,3,4,0}};
		instruction->operation = operation[decode.L];
		instruction->operands[operandSet[decode.L][0]].operandClass = IMM32;
		instruction->operands[operandSet[decode.L][0]].immediate = decode.op1;
		instruction->operands[operandSet[decode.L][1]].operandClass = SYS_REG;
		instruction->operands[operandSet[decode.L][1]].reg[0] = REG_C0 + decode.CRn;
		instruction->operands[operandSet[decode.L][2]].operandClass = SYS_REG;
		instruction->operands[operandSet[decode.L][2]].reg[0] = REG_C0 + decode.CRm;
		instruction->operands[operandSet[decode.L][3]].operandClass = IMM32;
		instruction->operands[operandSet[decode.L][3]].immediate = decode.op2;
		if (decode.Rt != 31)
		{
			instruction->operands[operandSet[decode.L][4]].operandClass = REG;
			instruction->operands[operandSet[decode.L][4]].reg[0] =
				REG(REGSET_ZR, REG_X_BASE, decode.Rt);
		}
		}
	}
	return instruction->operation == ARM64_UNDEFINED;
}


uint32_t aarch64_decompose_system_debug_and_trace_regs(SYSTEM decode, Instruction* restrict instruction)
{
	uint32_t sysreg = SYSREG_NONE;
	static const Operation operation[2] = {ARM64_MSR, ARM64_MRS};
	static const uint32_t dbgreg[4][16] = {
		{
			REG_DBGBVR0_EL1,  REG_DBGBVR1_EL1,  REG_DBGBVR2_EL1,  REG_DBGBVR3_EL1,
			REG_DBGBVR4_EL1,  REG_DBGBVR5_EL1,  REG_DBGBVR6_EL1,  REG_DBGBVR7_EL1,
			REG_DBGBVR8_EL1,  REG_DBGBVR9_EL1,  REG_DBGBVR10_EL1, REG_DBGBVR11_EL1,
			REG_DBGBVR12_EL1, REG_DBGBVR13_EL1, REG_DBGBVR14_EL1, REG_DBGBVR15_EL1
		},{
			REG_DBGBCR0_EL1,  REG_DBGBCR1_EL1,  REG_DBGBCR2_EL1,  REG_DBGBCR3_EL1,
			REG_DBGBCR4_EL1,  REG_DBGBCR5_EL1,  REG_DBGBCR6_EL1,  REG_DBGBCR7_EL1,
			REG_DBGBCR8_EL1,  REG_DBGBCR9_EL1,  REG_DBGBCR10_EL1, REG_DBGBCR11_EL1,
			REG_DBGBCR12_EL1, REG_DBGBCR13_EL1, REG_DBGBCR14_EL1, REG_DBGBCR15_EL1
		},{
			REG_DBGWVR0_EL1,  REG_DBGWVR1_EL1,  REG_DBGWVR2_EL1,  REG_DBGWVR3_EL1,
			REG_DBGWVR4_EL1,  REG_DBGWVR5_EL1,  REG_DBGWVR6_EL1,  REG_DBGWVR7_EL1,
			REG_DBGWVR8_EL1,  REG_DBGWVR9_EL1,  REG_DBGWVR10_EL1, REG_DBGWVR11_EL1,
			REG_DBGWVR12_EL1, REG_DBGWVR13_EL1, REG_DBGWVR14_EL1, REG_DBGWVR15_EL1
		},{
			REG_DBGWCR0_EL1,  REG_DBGWCR1_EL1,  REG_DBGWCR2_EL1,  REG_DBGWCR3_EL1,
			REG_DBGWCR4_EL1,  REG_DBGWCR5_EL1,  REG_DBGWCR6_EL1,  REG_DBGWCR7_EL1,
			REG_DBGWCR8_EL1,  REG_DBGWCR9_EL1,  REG_DBGWCR10_EL1, REG_DBGWCR11_EL1,
			REG_DBGWCR12_EL1, REG_DBGWCR13_EL1, REG_DBGWCR14_EL1, REG_DBGWCR15_EL1
		}
	};
	switch (decode.op1) //Table C5-5 System instruction encodings for debug System register access
	{
	case 0:
		switch (decode.CRn)
		{
		case 0:
			if (decode.CRm == 0 && decode.op2 == 2)
				sysreg = REG_OSDTRRX_EL1;
			else if (decode.CRm == 2 && decode.op2 == 0)
				sysreg = REG_MDCCINT_EL1;
			else if (decode.CRm == 2 && decode.op2 == 2)
				sysreg = REG_MDSCR_EL1;
			else if (decode.CRm == 3 && decode.op2 == 2)
				sysreg = REG_OSDTRTX_EL1;
			else if (decode.CRm == 6 && decode.op2 == 2)
				sysreg = REG_OSECCR_EL1;
			else
			{
				if (decode.op2 > 3 && decode.op2 < 8)
					sysreg = dbgreg[decode.op2-4][decode.CRm];
			}
			break;
		case 1:
			switch (decode.CRm)
			{
			case 0:
				if (decode.op2 == 0)
					sysreg = REG_MDRAR_EL1;
				else if (decode.op2 == 4)
					sysreg = REG_OSLAR_EL1;
				break;
			case 1:
				if (decode.op2 == 4)
					sysreg = REG_OSLSR_EL1;
				break;
			case 3:
				if (decode.op2 == 4)
					sysreg = REG_OSDLR_EL1;
				break;
			case 4:
				if (decode.op2 == 4)
					sysreg = REG_DBGPRCR_EL1;
				break;
			}
			break;
		case 7:
			if (decode.op2 != 6)
				break;
			switch (decode.CRm)
			{
				case 8:  sysreg = REG_DBGCLAIMSET_EL1; break;
				case 9:  sysreg = REG_DBGCLAIMCLR_EL1; break;
				case 14: sysreg = REG_DBGAUTHSTATUS_EL1; break;
			}
		}
		break;
	case 1:
		{
		//Switch operands depending on load vs store
		uint32_t op1 = !!decode.L;
		uint32_t op2 = !decode.L;
		instruction->operation = operation[op1];
		instruction->operands[op1].operandClass = IMPLEMENTATION_SPECIFIC;
		instruction->operands[op1].reg[0] = decode.op0;
		instruction->operands[op1].reg[1] = decode.op1;
		instruction->operands[op1].reg[2] = decode.CRn;
		instruction->operands[op1].reg[3] = decode.CRm;
		instruction->operands[op1].reg[4] = decode.op2;
		instruction->operands[op2].operandClass = REG;
		instruction->operands[op2].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
		return 0;
		}
	case 2:
		if (decode.CRn == 0 && decode.CRm == 0)
			sysreg = REG_TEECR32_EL1;
		else if (decode.CRn == 1 && decode.CRm == 0)
			sysreg = REG_TEEHBR32_EL1;

		break;
	case 3:
		if (decode.CRn != 0 || decode.op2 != 0)
			break;
		switch (decode.CRm)
		{
		case 1: sysreg = REG_MDCCSR_EL0; break;
		case 4: sysreg = REG_DBGDTR_EL0; break;
		case 5:
			if (decode.L)
				sysreg = REG_DBGDTRTX_EL0;
			else
				sysreg = REG_DBGDTRRX_EL0;
		}
		break;
	case 4:
		if (decode.CRn == 0 && decode.CRm == 7 && decode.op2 == 0)
			sysreg = REG_DBGVCR32_EL2;
		break;
	//default:
	//	printf("%s\n", __FUNCTION__);
	}
	uint32_t op1 = !!decode.L;
	uint32_t op2 = !decode.L;
	instruction->operation = operation[op1];
	instruction->operands[op1].operandClass = SYS_REG;
	instruction->operands[op1].reg[0] = sysreg;
	instruction->operands[op2].operandClass = REG;
	instruction->operands[op2].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
	return sysreg == SYSREG_NONE;
}


uint32_t aarch64_decompose_system_debug_and_trace_regs2(SYSTEM decode, Instruction* restrict instruction)
{
	uint32_t sysreg = SYSREG_NONE;
	static const Operation operation[2] = {ARM64_MSR, ARM64_MRS};
	//printf("op0: %d op1: %d CRn: %d CRm: %d op2: %d %s\n", decode.op0, decode.op1, decode.CRn, decode.CRm, decode.op2, __FUNCTION__);
	switch (decode.CRn)
	{
	case 0:
		if (decode.op1 == 0)
		{
			static const SystemReg sysregs[8][8] = {
				{REG_MIDR_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, REG_MPIDR_EL1, REG_REVIDR_EL1 ,SYSREG_NONE},
				{REG_ID_PFR0_EL1, REG_ID_PFR1_EL1, REG_ID_DFR0_EL1, REG_ID_AFR0_EL1,
					REG_ID_MMFR0_EL1, REG_ID_MMFR1_EL1, REG_ID_MMFR2_EL1 ,REG_ID_MMFR3_EL1},
				{REG_ID_ISAR0_EL1, REG_ID_ISAR1_EL1, REG_ID_ISAR2_EL1, REG_ID_ISAR3_EL1,
					REG_ID_ISAR4_EL1, REG_ID_ISAR5_EL1, REG_ID_MMFR4_EL1,SYSREG_NONE},
				{REG_MVFR0_EL1, REG_MVFR1_EL1, REG_MVFR2_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{REG_ID_AA64PFR0_EL1, REG_ID_AA64PFR1_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{REG_ID_AA64DFR0_EL1, REG_ID_AA64DFR0_EL1, SYSREG_NONE, SYSREG_NONE, REG_ID_AA64DFR0_EL1, REG_ID_AA64DFR0_EL1, SYSREG_NONE, SYSREG_NONE},
				{REG_ID_AA64ISAR0_EL1, REG_ID_AA64ISAR1_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{REG_ID_AA64MMFR0_EL1, REG_ID_AA64MMFR1_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			};
			sysreg = sysregs[decode.CRm][decode.op2];
		}
		else if (decode.CRm == 0)
		{
			static const SystemReg sysregs[8][8] = {
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE,SYSREG_NONE},
				{REG_CCSIDR_EL1, REG_CLIDR_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, REG_AIDR_EL1},
				{REG_CSSELR_EL1, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, REG_CTR_EL0, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, REG_DCZID_EL0},
				{REG_VPIDR_EL2, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, REG_VMPIDR_EL0, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE,SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE,SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE,SYSREG_NONE}
			};
			sysreg = sysregs[decode.op1][decode.op2];
		}
		break;
	case 1:
		switch (decode.op1)
		{
		case 0:
			if (decode.CRm == 0)
			{
				switch (decode.op2)
				{
				case 0: sysreg = REG_SCTLR_EL1; break;
				case 1: sysreg = REG_ACTLR_EL1; break;
				case 2: sysreg = REG_CPACR_EL1; break;
				}
			}
			break;
		case 4:
			if (decode.CRm == 0)
			{
				switch (decode.op2)
				{
				case 0: sysreg = REG_SCTLR_EL2; break;
				case 1: sysreg = REG_ACTLR_EL2; break;
				}
			}
			else if (decode.CRm == 1)
			{
				static const SystemReg sysregs[] = {
					REG_HCR_EL2, REG_MDCR_EL2, REG_CPTR_EL2, REG_HSTR_EL2,
					SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, REG_HACR_EL2
				};
				sysreg = sysregs[decode.op2];
			}
			else if (decode.CRm == 6)
			{
				sysreg = REG_ICC_PMR_EL1;
			}
			break;
		case 6:
			switch (decode.CRm)
			{
			case 0:
				if (decode.op2 == 0)
					sysreg = REG_SCTLR_EL3;
				else if (decode.op2 == 1)
					sysreg = REG_ACTLR_EL3;
				break;
			case 1:
				switch (decode.op2)
				{
					case 0: sysreg = REG_SCR_EL3; break;
					case 1: sysreg = REG_SDER32_EL3; break;
					case 2: sysreg = REG_CPTR_EL3; break;
				}
				break;
			case 3:
				if (decode.op2 == 1)
					sysreg = REG_MDCR_EL3;
				break;
			}
			break;
		}
		break;
	case 2:
		switch (decode.op1)
		{
		case 0:
			if (decode.CRm == 0)
			{
				switch (decode.op2)
				{
				case 0: sysreg = REG_TTBR0_EL1; break;
				case 1: sysreg = REG_TTBR1_EL1; break;
				case 2: sysreg = REG_TCR_EL1; break;
				}
			}
			break;
		case 4:
			if (decode.CRm == 0)
			{
				switch (decode.op2)
				{
				case 0: sysreg = REG_TTBR0_EL2; break;
				case 2: sysreg = REG_TCR_EL2; break;
				}
			}
			else if (decode.CRm == 1)
			{
				switch (decode.op2)
				{
				case 0: sysreg = REG_VTTBR_EL2; break;
				case 2: sysreg = REG_VTCR_EL2; break;
				}
			}
			break;
		case 6:
			if (decode.CRm == 0)
			{
				if (decode.op2 == 0)
					sysreg = REG_TTBR0_EL3;
				else if (decode.op2 == 2)
					sysreg = REG_TCR_EL3;
			}
			break;
		}
		break;
	case 3:
		if (decode.op1 != 4 || decode.CRm != 0 || decode.op2 != 0)
			break;
		sysreg = REG_DACR32_EL2;
		break;
	case 4:
		switch (decode.op1)
		{
			case 0:
				switch (decode.CRm)
				{
				case 0:
					if (decode.op2 == 1)
						sysreg = REG_ELR_EL1;
					else if (decode.op2 == 0)
						sysreg = REG_SPSR_EL1;
					break;
				case 1:
					if (decode.op2 == 0)
						sysreg = REG_SP_EL0;
					break;
				case 2:
					if (decode.op2 == 0)
						sysreg = REG_SPSEL;
					else if (decode.op2 == 2)
						sysreg = REG_CURRENT_EL;
					else if (decode.op2 == 3)
						sysreg = REG_PAN;
					break;
				case 6:
					sysreg = REG_ICC_PMR_EL1;
					break;
				}
				break;
			case 3:
				if (decode.op2 == 0)
				{
					switch (decode.CRm)
					{
						case 2: sysreg = REG_NZCV; break;
						case 4: sysreg = REG_FPCR; break;
						case 5: sysreg = REG_DSPSR_EL0; break;
					}
				}
				else if (decode.op2 == 1)
				{
					switch (decode.CRm)
					{
						case 2: sysreg = REG_DAIF; break;
						case 4: sysreg = REG_FPSR; break;
						case 5: sysreg = REG_DLR_EL0; break;
					}
				}
				break;
			case 4:
				switch (decode.CRm)
				{
					case 0:
						if (decode.op2 == 0)
							sysreg = REG_SPSR_EL2;
						else if (decode.op2 == 1)
							sysreg = REG_ELR_EL2;
						break;
					case 1:
						if (decode.op2 == 0)
							sysreg = REG_SP_EL1;
						break;
					case 3:
						switch (decode.op2)
						{
							case 0: sysreg = REG_SPSR_IRQ; break;
							case 1: sysreg = REG_SPSR_ABT; break;
							case 2: sysreg = REG_SPSR_UND; break;
							case 3: sysreg = REG_SPSR_FIQ; break;
						}
						break;
				}
				break;
			case 6:
				if (decode.CRm == 0)
				{
					if (decode.op2 == 0)
						sysreg = REG_SPSR_EL3;
					else if (decode.op2 == 1)
						sysreg = REG_ELR_EL3;
				}
				else if (decode.CRm == 1)
				{
					if (decode.op2 == 0)
						sysreg = REG_SP_EL2;
				}
				break;
		}
		break;
	case 5:
		{
		if (decode.CRm > 3 || decode.op2 > 1)
			break;
		static const SystemReg sysregs[3][4][2] = {
			{
				{SYSREG_NONE,SYSREG_NONE},
				{REG_AFSR0_EL1, REG_AFSR1_EL1},
				{REG_ESR_EL1,  SYSREG_NONE},
				{SYSREG_NONE,SYSREG_NONE},
			},{
				{SYSREG_NONE,REG_IFSR32_EL2},
				{REG_AFSR0_EL2, REG_AFSR1_EL2},
				{REG_ESR_EL2,  SYSREG_NONE},
				{REG_FPEXC32_EL2,SYSREG_NONE},
			},{
				{SYSREG_NONE,SYSREG_NONE},
				{REG_AFSR0_EL3, REG_AFSR1_EL3},
				{REG_ESR_EL3,  SYSREG_NONE},
				{SYSREG_NONE,SYSREG_NONE},
			}
		};
		switch (decode.op1)
		{
		case 0: sysreg = sysregs[0][decode.CRm][decode.op2]; break;
		case 4: sysreg = sysregs[1][decode.CRm][decode.op2]; break;
		case 6: sysreg = sysregs[2][decode.CRm][decode.op2]; break;
		}
		break;
		}
	case 6:
			if (decode.op1 == 0 && decode.CRm == 0 && decode.op2 == 0)
				sysreg = REG_FAR_EL1;
			else if (decode.op1 == 4 && decode.CRm == 0)
			{
				if (decode.op2 == 0)
					sysreg = REG_FAR_EL2;
				else if (decode.op2 == 4)
					sysreg = REG_HPFAR_EL2;
			}
			else if (decode.op1 == 6 && decode.CRm == 0 && decode.op2 == 0)
				sysreg = REG_FAR_EL3;
			else if (decode.op1 == 0 && decode.CRm == 11 && decode.op2 == 5)
				sysreg = REG_ICC_SGI1R_EL1;
		break;
	case 7:
			if (decode.op1 == 0 && decode.CRm == 4 && decode.op2 == 0)
				sysreg = REG_PAR_EL1;
		break;
	case 9:
		{
			if (decode.op1 == 0 && decode.CRm == 14)
			{
				if (decode.op2 == 1)
					sysreg = REG_PMINTENSET_EL1;
				else if (decode.op2 == 2)
					sysreg = REG_PMINTENCLR_EL1;
			}
			else if (decode.op1 == 3)
			{
				static const SystemReg sysregs[3][8] = {
					{
						REG_PMCR_EL0,	REG_PMCNTENSET_EL0, REG_PMCNTENCLR_EL0, REG_PMOVSCLR_EL0,
						REG_PMSWINC_EL0, REG_PMSELR_EL0,	 REG_PMCEID0_EL0,   REG_PMCEID1_EL0
					},
					{REG_PMCCNTR_EL0, REG_PMXEVTYPER_EL0, REG_PMXEVCNTR_EL0, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
					{REG_PMUSERENR_EL0, SYSREG_NONE, SYSREG_NONE, REG_PMOVSSET_EL0, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
				};
				if (decode.CRm > 11 && decode.CRm < 15)
				{
					sysreg = sysregs[decode.CRm-12][decode.op2];
				}
			}
			break;
		}
	case 10:
		{
			if (decode.op2 == 0)
			{
				static const SystemReg sysregs[8][2] = {
					{REG_MAIR_EL1, REG_AMAIR_EL1},
					{SYSREG_NONE, SYSREG_NONE},
					{SYSREG_NONE, SYSREG_NONE},
					{SYSREG_NONE, SYSREG_NONE},
					{REG_MAIR_EL2, REG_AMAIR_EL2},
					{SYSREG_NONE, SYSREG_NONE},
					{REG_MAIR_EL3, REG_AMAIR_EL3},
					{SYSREG_NONE, SYSREG_NONE}
				};
				sysreg = sysregs[decode.op1][decode.CRm-2];
			}
		break;
		}
	case 12:
		if (decode.op1 == 0)
		{
			switch (decode.CRm)
			{
				case 0:
					switch (decode.op2)
					{
						case 0: sysreg = REG_VBAR_EL1; break;
						case 1: sysreg = REG_RVBAR_EL1; break;
						case 2: sysreg = REG_RMR_EL1; break;
					}
					break;
				case 1:
					if (decode.op2 == 0)
						sysreg = REG_EL1;
					break;
				case 8:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICC_IAR0_EL1; break;
						case 1: sysreg = REG_ICC_EOIR0_EL1; break;
						case 2: sysreg = REG_ICC_HPPIR0_EL1; break;
						case 3: sysreg = REG_ICC_BPR0_EL1; break;
						case 4: sysreg = REG_ICC_AP0R0_EL1; break;
						case 5: sysreg = REG_ICC_AP0R1_EL1; break;
						case 6: sysreg = REG_ICC_AP0R2_EL1; break;
						case 7: sysreg = REG_ICC_AP0R3_EL1; break;
					}
					break;
				case 9:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICC_AP1R0_EL1; break;
						case 1: sysreg = REG_ICC_AP1R1_EL1; break;
						case 2: sysreg = REG_ICC_AP1R2_EL1; break;
						case 3: sysreg = REG_ICC_AP1R3_EL1; break;
					}
					break;
				case 11:
					if (decode.op2 == 1)
						sysreg = REG_ICC_DIR_EL1;
					else if (decode.op2 == 3)
						sysreg = REG_ICC_RPR_EL1;
					else if (decode.op2 == 5)
						sysreg = REG_ICC_SGI1R_EL1;
					else if (decode.op2 == 6)
						sysreg = REG_ICC_ASGI1R_EL1;
					else if (decode.op2 == 7)
						sysreg = REG_ICC_SGI0R_EL1;
					break;
				case 12:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICC_IAR1_EL1; break;
						case 1: sysreg = REG_ICC_EOIR1_EL1; break;
						case 2: sysreg = REG_ICC_HPPIR1_EL1; break;
						case 3: sysreg = REG_ICC_BPR1_EL1; break;
						case 4: sysreg = REG_ICC_CTLR_EL1; break;
						case 5: sysreg = REG_ICC_SRE_EL1; break;
						case 6: sysreg = REG_ICC_IGRPEN0_EL1; break;
						case 7: sysreg = REG_ICC_IGRPEN1_EL1; break;
					}
					break;
				case 13:
					if (decode.op2 == 0)
						sysreg = REG_ICC_SEIEN_EL1;
					break;
				default:
					break;
			}
		}
		else if (decode.op1 == 1 && decode.CRm == 12)
		{
			sysreg = REG_ICC_ASGI1R_EL2;
		}
		else if (decode.op1 == 2 && decode.CRm == 12)
		{
			sysreg = REG_ICC_SGI0R_EL2;
		}
		else if (decode.op1 == 4)
		{
			switch (decode.CRm)
			{
				case 0:
					switch (decode.op2)
					{
						case 0: sysreg = REG_VBAR_EL2; break;
						case 1: sysreg = REG_RVBAR_EL2; break;
						case 2: sysreg = REG_RMR_EL2; break;
					}
					break;
				case 8:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_AP0R0_EL2; break;
						case 1: sysreg = REG_ICH_AP0R1_EL2; break;
						case 2: sysreg = REG_ICH_AP0R2_EL2; break;
						case 3: sysreg = REG_ICH_AP0R3_EL2; break;
					}
					break;
				case 9:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_AP1R0_EL2; break;
						case 1: sysreg = REG_ICH_AP1R1_EL2; break;
						case 2: sysreg = REG_ICH_AP1R2_EL2; break;
						case 3: sysreg = REG_ICH_AP1R3_EL2; break;
						case 4: sysreg = REG_ICH_AP1R4_EL2; break;
						case 5: sysreg = REG_ICC_HSRE_EL2;  break;
					}
					break;
				case 11:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_HCR_EL2; break;
						case 1: sysreg = REG_ICH_VTR_EL2; break;
						case 2: sysreg = REG_ICH_MISR_EL2; break;
						case 3: sysreg = REG_ICH_EISR_EL2; break;
						case 5: sysreg = REG_ICH_ELRSR_EL2; break;
						case 7: sysreg = REG_ICH_VMCR_EL2; break;
					}
					break;
				case 12:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_LR0_EL2; break;
						case 1: sysreg = REG_ICH_LR1_EL2; break;
						case 2: sysreg = REG_ICH_LR2_EL2; break;
						case 3: sysreg = REG_ICH_LR3_EL2; break;
						case 4: sysreg = REG_ICH_LR4_EL2; break;
						case 5: sysreg = REG_ICH_LR5_EL2; break;
						case 6: sysreg = REG_ICH_LR6_EL2; break;
						case 7: sysreg = REG_ICH_LR7_EL2; break;
					}
					break;
				case 13:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_LR8_EL2;  break;
						case 1: sysreg = REG_ICH_LR9_EL2;  break;
						case 2: sysreg = REG_ICH_LR10_EL2; break;
						case 3: sysreg = REG_ICH_LR11_EL2; break;
						case 4: sysreg = REG_ICH_LR12_EL2; break;
						case 5: sysreg = REG_ICH_LR13_EL2; break;
						case 6: sysreg = REG_ICH_LR14_EL2; break;
						case 7: sysreg = REG_ICH_LR15_EL2; break;
					}
					break;
				case 14:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_LRC0_EL2; break;
						case 1: sysreg = REG_ICH_LRC1_EL2; break;
						case 2: sysreg = REG_ICH_LRC2_EL2; break;
						case 3: sysreg = REG_ICH_LRC3_EL2; break;
						case 4: sysreg = REG_ICH_LRC4_EL2; break;
						case 5: sysreg = REG_ICH_LRC5_EL2; break;
						case 6: sysreg = REG_ICH_LRC6_EL2; break;
						case 7: sysreg = REG_ICH_LRC7_EL2; break;
					}
					break;
				case 15:
					switch (decode.op2)
					{
						case 0: sysreg = REG_ICH_LRC8_EL2;  break;
						case 1: sysreg = REG_ICH_LRC9_EL2;  break;
						case 2: sysreg = REG_ICH_LRC10_EL2; break;
						case 3: sysreg = REG_ICH_LRC11_EL2; break;
						case 4: sysreg = REG_ICH_LRC12_EL2; break;
						case 5: sysreg = REG_ICH_LRC13_EL2; break;
						case 6: sysreg = REG_ICH_LRC14_EL2; break;
						case 7: sysreg = REG_ICH_LRC15_EL2; break;
					}
					break;
			}
		}
		else if (decode.op1 == 6)
		{
			if (decode.CRm == 0)
			{
				switch (decode.op2)
				{
					case 0: sysreg = REG_VBAR_EL3; break;
					case 1: sysreg = REG_RVBAR_EL3; break;
					case 2: sysreg = REG_RMR_EL3; break;
				}
			}
			else if (decode.CRm == 12)
			{
				switch (decode.op2)
				{
					case 4: sysreg = REG_ICC_MCTLR_EL3; break;
					case 5: sysreg = REG_ICC_MSRE_EL3; break;
					case 7: sysreg = REG_ICC_MGRPEN1_EL3; break;
				}
			}
		}
		break;
	case 13:
		{
			if (decode.CRm != 0 || decode.op2 > 4)
				break;
			static const SystemReg sysregs[8][5] = {
				{SYSREG_NONE, REG_CONTEXTIDR_EL1, SYSREG_NONE, SYSREG_NONE, REG_TPIDR_EL1},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, REG_TPIDR_EL0, REG_TPIDRRO_EL0, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, REG_TPIDR_EL2, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, REG_TPIDR_EL3, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			};
			sysreg = sysregs[decode.op1][decode.op2];
		break;
		}
	case 14:
		{
		if (decode.op1 == 3)
		{
			uint32_t reg = ((decode.CRm&3) << 3)|decode.op2;
			if ((decode.CRm >=8 && decode.CRm <= 10 && decode.op2 <= 7)||
				(decode.CRm == 11 && decode.op2 <= 6))
			{
				sysreg = REG_PMEVCNTR0_EL0 + reg;
				break;
			}
			else if ((decode.CRm >= 12 && decode.CRm <= 14 && decode.op2 <= 7)||
					 (decode.CRm == 15 && decode.op2 <= 6))
			{
				sysreg = REG_PMEVTYPER0_EL0 + reg;
				break;
			}
			else if (decode.CRm == 15 && decode.op2 == 7)
			{
				sysreg = REG_PMCCFILTR_EL0;
				break;
			}
		}
		else if (decode.op1 == 4 && decode.CRm == 0 && decode.op2 == 3)
		{
			sysreg = REG_CNTVOFF_EL2;
			break;
		}
		else if (decode.op2 > 2)
			break;
		static const SystemReg sysregs[8][4][3] = {
			{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{REG_CNTKCTL_EL1, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			},{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			},{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			},{
				{REG_CNTFRQ_EL0,    REG_CNTPCT_EL0,   REG_CNTVCT_EL0},
				{SYSREG_NONE,       SYSREG_NONE,      SYSREG_NONE},
				{REG_CNTP_TVAL_EL0, REG_CNTP_CTL_EL0, REG_CNTP_CVAL_EL0},
				{REG_CNTV_TVAL_EL0, REG_CNTV_CTL_EL0, REG_CNTV_CVAL_EL0}
			},{
				{SYSREG_NONE,        SYSREG_NONE,       SYSREG_NONE},
				{REG_CNTHCTL_EL2,    SYSREG_NONE,       SYSREG_NONE},
				{REG_CNTHP_TVAL_EL2, REG_CNTHP_CTL_EL2, REG_CNTHP_CVAL_EL2},
				{SYSREG_NONE,        SYSREG_NONE,       SYSREG_NONE}
			},{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			},{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			},{
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE},
				{REG_CNTPS_TVAL_EL1, REG_CNTPS_CTL_EL1, REG_CNTPS_CVAL_EL1},
				{SYSREG_NONE, SYSREG_NONE, SYSREG_NONE}
			}
		};
		sysreg = sysregs[decode.op1][decode.CRm][decode.op2];
		}
		break;
	case 11:
	case 15:
		{
		//Switch operands depending on load vs store
		uint32_t op1 = !!decode.L;
		uint32_t op2 = !decode.L;
		instruction->operation = operation[op1];
		instruction->operands[op1].operandClass = IMPLEMENTATION_SPECIFIC;
		instruction->operands[op1].reg[0] = decode.op0;
		instruction->operands[op1].reg[1] = decode.op1;
		instruction->operands[op1].reg[2] = decode.CRn;
		instruction->operands[op1].reg[3] = decode.CRm;
		instruction->operands[op1].reg[4] = decode.op2;
		instruction->operands[op2].operandClass = REG;
		instruction->operands[op2].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
		return 0;
		}
		break;
	}
	uint32_t op1 = !!decode.L;
	uint32_t op2 = !decode.L;
	instruction->operation = operation[op1];
	instruction->operands[op1].operandClass = SYS_REG;
	instruction->operands[op1].reg[0] = sysreg;
	instruction->operands[op2].operandClass = REG;
	instruction->operands[op2].reg[0] = REG(REGSET_ZR, REG_X_BASE, decode.Rt);
	return sysreg == SYSREG_NONE;
}


uint32_t aarch64_decompose_system(uint32_t instructionValue, Instruction* restrict instruction)
{
	SYSTEM decode = *(SYSTEM*)&instructionValue;
	switch(decode.op0)
	{
	case 0: //C5.2.3 - Architectural hints, barriers and CLREX, PSTATE Access
		return aarch64_decompose_system_arch_hints(decode, instruction);
	case 1: //C5.2.4 - Cache maintenance, TLB maintenance, and address translation instructions
		return aarch64_decompose_system_cache_maintenance(decode, instruction);
	case 2: //C5.2.5 - Moves to and from debug and trace system registers
		return aarch64_decompose_system_debug_and_trace_regs(decode, instruction);
	case 3: //C5.2.6 - Moves to and from non-debug System registers and special purpose registers
		return aarch64_decompose_system_debug_and_trace_regs2(decode, instruction);
	}
	return FAILED_TO_DECODE_INSTRUCTION;
}


uint32_t aarch64_decompose_test_branch_imm(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/* C4.2.5 Test & branch (immediate)
	 *
	 * TBZ <R><t>, #<imm>, <label>
	 * TBNZ <R><t>, #<imm>, <label>
	 */
	TEST_AND_BRANCH decode = *(TEST_AND_BRANCH*)&instructionValue;
	static const Operation operation[2] = {ARM64_TBZ, ARM64_TBNZ};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = REG(REGSET_ZR, regSize[decode.b5], decode.Rt);
	instruction->operands[1].operandClass = IMM32;
	instruction->operands[1].immediate = decode.b5 << 5 | decode.b40;

	instruction->operands[2].operandClass = LABEL;
	instruction->operands[2].immediate = address + (decode.imm << 2);
	return DISASM_SUCCESS;
}


uint32_t aarch64_decompose_unconditional_branch(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	/*
	 * B <label>
	 * BL <label>
	 */
	UNCONDITIONAL_BRANCH decode = *(UNCONDITIONAL_BRANCH*)&instructionValue;
	static const Operation operation[] = {ARM64_B, ARM64_BL};
	instruction->operation = operation[decode.op];
	instruction->operands[0].operandClass = LABEL;
	instruction->operands[0].immediate = address + (decode.imm << 2);
	return 0;
}


uint32_t aarch64_decompose_unconditional_branch_reg(uint32_t instructionValue, Instruction* restrict instruction)
{
	/* C4.2.7 Unconditional branch (register)
	 *
	 * BR <Xn>
	 * BLR <Xn>
	 * RET {<Xn>}
	 * ERET
	 * DRPS
	 */
	UNCONDITIONAL_BRANCH_REG decode = *(UNCONDITIONAL_BRANCH_REG*)&instructionValue;
	static const Operation operations[][4] = {
		{ARM64_BR,        ARM64_UNDEFINED, ARM64_BRAAZ,     ARM64_BRABZ},
		{ARM64_BLR,       ARM64_UNDEFINED, ARM64_BLRAAZ,    ARM64_BLRABZ},
		{ARM64_RET,       ARM64_UNDEFINED, ARM64_RETAA,     ARM64_RETAB},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},

		{ARM64_ERET,      ARM64_UNDEFINED, ARM64_ERETAA,    ARM64_ERETAB},
		{ARM64_DRPS,      ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_UNDEFINED},

		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_BRAA,      ARM64_BRAB},
		{ARM64_UNDEFINED, ARM64_UNDEFINED, ARM64_BLRAA,     ARM64_BLRAB},
	};

	if (decode.opc > 9)
		return 1;
	if (decode.op3 > 3)
		return 1;
	if (decode.opc < 8 && decode.op3 != 0 && decode.op4 != 0x1f)
		return 1;
	if (decode.op3 == 0 && decode.op4 != 0)
		return 1;
	if (decode.op2 != 0x1f)
		return 1;

	instruction->operation = operations[decode.opc][decode.op3];
	Register reg = REG(1, REG_X_BASE, decode.Rn);

	switch (decode.opc)
	{
	case 2: // RET
		if (!decode.op3)
		{
			if (reg == REG_X30)
				return 0;
			break;
		}
		FALL_THROUGH
	case 4: // ERET
	case 5: // DRPS
		if (decode.Rn != 0x1f)
			return 1;
		return 0;
	case 8:
	case 9:
		instruction->operands[1].operandClass = REG;
		instruction->operands[1].reg[0] = REG(REGSET_SP, REG_X_BASE, decode.op4);
		break;
	default:
		break;
	}

	instruction->operands[0].operandClass = REG;
	instruction->operands[0].reg[0] = reg;

	return 0;
}


uint32_t aarch64_decompose(uint32_t instructionValue, Instruction* restrict instruction, uint64_t address)
{
	instruction->operation = ARM64_UNDEFINED;
	switch (BF_GETI(25, 4))
	{
		case 0: case 1: case 2: case 3:
			instruction->group = GROUP_UNALLOCATED;
			return 2;
		case 8: case 9:
			instruction->group = GROUP_DATA_PROCESSING_IMM;
			switch (BF_GETI(23,3))
			{
				case 0:
				case 1:
					return aarch64_decompose_pc_rel_addr(instructionValue, instruction, address);
				case 2:
					return aarch64_decompose_add_sub_imm(instructionValue, instruction);
				case 3:
					return aarch64_decompose_add_sub_imm_tags(instructionValue, instruction);
				case 4:
					return aarch64_decompose_logical_imm(instructionValue, instruction);
				case 5:
					return aarch64_decompose_move_wide_imm(instructionValue, instruction);
				case 6:
					return aarch64_decompose_bitfield(instructionValue, instruction);
				case 7:
					return aarch64_decompose_extract(instructionValue, instruction);
			}
			break;
		case 10: case 11:
			instruction->group = GROUP_BRANCH_EXCEPTION_SYSTEM;
			switch (BF_GETI(25, 7))
			{
				case 0xa:
				case 0xb:
				case 0x4a:
				case 0x4b:
					return aarch64_decompose_unconditional_branch(instructionValue, instruction, address);
				case 0x1a:
				case 0x5a:
					return aarch64_decompose_compare_branch_imm(instructionValue, instruction, address);
				case 0x1b:
				case 0x5b:
					return aarch64_decompose_test_branch_imm(instructionValue, instruction, address);
				case 0x2a:
					return aarch64_decompose_conditional_branch(instructionValue, instruction, address);
				case 0x6a:
					if (BF_GETI(24, 1) == 0)
						return aarch64_decompose_exception_generation(instructionValue, instruction);
					else if (BF_GETI(22, 3) == 4)
					{
						return aarch64_decompose_system(instructionValue, instruction);
					}
					return 2;
				case 0x6b:
					return aarch64_decompose_unconditional_branch_reg(instructionValue, instruction);
				default:
					return 2; //shouldn't be able to get here
			}
			break;
		case 4: case 6: case 12: case 14:
		{
			instruction->group = GROUP_LOAD_STORE;

			uint32_t op0 = BF_GETI(28,4);
			uint32_t op1 = BF_GETI(26,1);
			uint32_t op2 = BF_GETI(23,2);
			uint32_t op3 = BF_GETI(16,6);
			uint32_t op4 = BF_GETI(10,2);

			if((op0 & 0b1011)==0 && (op1==1)) {
				if(op2==0 && op3==0)
					return aarch64_decompose_simd_load_store_multiple(instructionValue, instruction);
				if(op2==1 && (op3>>5)==0)
					return aarch64_decompose_simd_load_store_multiple_post_idx(instructionValue, instruction);
				if(op2==2 && (op3 & 0x1f)==0)
					return aarch64_decompose_simd_load_store_single(instructionValue, instruction);
				if(op2==3)
					return aarch64_decompose_simd_load_store_single_post_idx(instructionValue, instruction);
			}

			if(op0 == 0x0d)
				return aarch64_decompose_load_store_mem_tags(instructionValue, instruction);

			if((op0 & 3)==0 && op1==0 && (op2>>1)==0)
				return aarch64_decompose_load_store_exclusive(instructionValue, instruction);
			if((op0 & 3)==1 && (op2>>1)==0)
				return aarch64_decompose_load_register_literal(instructionValue, instruction, address);

			if((op0 & 3)==2) {
				if(op2==0)
					return aarch64_decompose_load_store_no_allocate_pair_offset(instructionValue, instruction);
				if(op2==1)
					return aarch64_decompose_load_store_reg_pair_post_idx(instructionValue, instruction);
				if(op2==2)
					return aarch64_decompose_load_store_reg_pair_offset(instructionValue, instruction);
				if(op2==3)
					return aarch64_decompose_load_store_reg_pair_pre_idx(instructionValue, instruction);
			}

			if((op0 & 3)==3) {
				if((op2>>1)==0) {
					if((op3>>5)==0) {
						if(op4==0)
							return aarch64_decompose_load_store_reg_unscalled_imm(instructionValue, instruction);
						if(op4==1)
							return aarch64_decompose_load_store_imm_post_idx(instructionValue, instruction);
						if(op4==2)
							return aarch64_decompose_load_store_reg_unpriv(instructionValue, instruction);
						if(op4==3)
							return aarch64_decompose_load_store_reg_imm_pre_idx(instructionValue, instruction);
					}
					if((op3>>5)==1) {
						//if(op4==0) return aarch64_decompose_atomic_memory_ops(instructionValue, instruction);
						if(op4==2)
							return aarch64_decompose_load_store_reg_reg_offset(instructionValue, instruction);
						if(op4==1 || op4==3)
							return aarch64_decompose_load_store_pac(instructionValue, instruction);
					}
				}
				else {
					return aarch64_decompose_load_store_reg_unsigned_imm(instructionValue, instruction);
				}
			}

			break;
		}
		case 5:
		case 13:
			instruction->group = GROUP_DATA_PROCESSING_REG;
			switch (BF_GETI(21,8))
			{
				case 0x50:
				case 0x51:
				case 0x52:
				case 0x53:
				case 0x54:
				case 0x55:
				case 0x56:
				case 0x57:
					return aarch64_decompose_logical_shifted_reg(instructionValue, instruction);
				case 0x58:
				case 0x5a:
				case 0x5c:
				case 0x5e:
					return aarch64_decompose_add_sub_shifted_reg(instructionValue, instruction);
				case 0x59:
				case 0x5b:
				case 0x5d:
				case 0x5f:
					return aarch64_decompose_add_sub_extended_reg(instructionValue, instruction);
				case 0xd0:
					return aarch64_decompose_add_sub_carry(instructionValue, instruction);
				case 0xd2:
					if (BF_GETI(11,1) == 1)
						return aarch64_decompose_conditional_compare_imm(instructionValue, instruction);
					else
						return aarch64_decompose_conditional_compare_reg(instructionValue, instruction);
				case 0xd4:
					return aarch64_decompose_conditional_select(instructionValue, instruction);
				case 0xd8:
				case 0xd9:
				case 0xda:
				case 0xdb:
				case 0xdc:
				case 0xdd:
				case 0xde:
				case 0xdf:
					return aarch64_decompose_data_processing_3(instructionValue, instruction);
				case 0xd6:
					if (BF_GETI(30,1) == 1)
						return aarch64_decompose_data_processing_1(instructionValue, instruction);
					else
						return aarch64_decompose_data_processing_2(instructionValue, instruction);
				default:
					return 2;
			}
			break;
		case 7:
		case 15:
			instruction->group = GROUP_DATA_PROCESSING_SIMD;
			switch(BF_GETI(24, 8))
			{
				case 0x1e:
				case 0x3e:
				case 0x9e:
				case 0xbe:
					if (BF_GETI(21, 1) == 0)
						return aarch64_decompose_fixed_floating_conversion(instructionValue, instruction);
					switch (BF_GETI(10, 2))
					{
						case 0:
							if (BF_GETI(12, 1) == 1)
								return aarch64_decompose_floating_imm(instructionValue, instruction);
							else if (BF_GETI(12, 2) == 2)
								return aarch64_decompose_floating_compare(instructionValue, instruction);
							else if (BF_GETI(12, 3) == 4)
								return aarch64_decompose_floating_data_processing1(instructionValue, instruction);
							else if (BF_GETI(12, 4) == 0)
								return aarch64_decompose_floating_integer_conversion(instructionValue, instruction);
							break;
						case 1:
							return aarch64_decompose_floating_conditional_compare(instructionValue, instruction);
						case 2:
							return aarch64_decompose_floating_data_processing2(instructionValue, instruction);
						case 3:
							return aarch64_decompose_floating_cselect(instructionValue, instruction);
					}
					break;
				case 0x1f:
				case 0x3f:
				case 0x9f:
				case 0xbf:
					return aarch64_decompose_floating_data_processing3(instructionValue, instruction);
				case 0x0e:
				case 0x2e:
				case 0x4e:
				case 0x6e:
					if (BF_GETI(21, 1) == 1)
					{
						switch (BF_GETI(10, 2))
						{
							case 1:
							case 3:
								return aarch64_decompose_simd_3_same(instructionValue, instruction);
							case 0:
								return aarch64_decompose_simd_3_different(instructionValue, instruction);
							case 2:
								if (BF_GETI(17, 4) == 0)
									return aarch64_decompose_simd_2_reg_misc(instructionValue, instruction);
								else if (BF_GETI(17, 4) == 8)
									return aarch64_decompose_simd_across_lanes(instructionValue, instruction);
						}
					}
					if ((instructionValue & 0x9fe08400) == 0x0e000400)
						return aarch64_decompose_simd_copy(instructionValue, instruction);
					if ((instructionValue & 0x003e0c00) == 0x00280800)
						return aarch64_decompose_cryptographic_aes(instructionValue, instruction);
					if ((instructionValue & 0xbf208c00) == 0x0e000000)
						return aarch64_decompose_simd_table_lookup(instructionValue, instruction);
					if ((instructionValue & 0xbf208c00) == 0x0e000800)
						return aarch64_decompose_simd_permute(instructionValue, instruction);
					if ((instructionValue & 0x00208400) == 0)
						return aarch64_decompose_simd_extract(instructionValue, instruction);
					break;
				case 0x0f:
				case 0x2f:
				case 0x4f:
				case 0x6f:
					if (BF_GETI(10,1) == 0)
						return aarch64_decompose_simd_vector_indexed_element(instructionValue, instruction);
					if (BF_GETI(19,5) == 0)
						return aarch64_decompose_simd_modified_imm(instructionValue, instruction);
					else
						return aarch64_decompose_simd_shift_imm(instructionValue, instruction);
					break;
				case 0x5e:
				case 0x7e:
					if (BF_GETI(21, 1) == 1)
					{
						switch (BF_GETI(10,2))
						{
							case 1:
							case 3:
								return aarch64_decompose_simd_scalar_3_same(instructionValue, instruction);
							case 0:
								return aarch64_decompose_simd_scalar_3_different(instructionValue, instruction);
							case 2:
								if (BF_GETI(17,4) == 0)
									return aarch64_decompose_simd_scalar_2_reg_misc(instructionValue, instruction);
								else if (BF_GETI(17,4) == 8)
									return aarch64_decompose_simd_scalar_pairwise(instructionValue, instruction);
						}
					}
					if ((instructionValue & 0xdfe08400) == 0x5e000400)
						return aarch64_decompose_simd_scalar_copy(instructionValue, instruction);
					else if ((instructionValue & 0xff208c00) == 0x5e000000)
						return aarch64_decompose_cryptographic_3_register_sha(instructionValue, instruction);
					else if ((instructionValue & 0xff3e0c00) == 0x5e280800)
						return aarch64_decompose_cryptographic_2_register_sha(instructionValue, instruction);
					break;
				case 0x5f:
				case 0x7f:
					if (BF_GETI(10,1) == 0)
						return aarch64_decompose_simd_scalar_indexed_element(instructionValue, instruction);
					else if (BF_GETI(23,1) == 0 && BF_GETI(10,1) == 1)
						return aarch64_decompose_simd_scalar_shift_imm(instructionValue, instruction);
					break;
			}
		default:
			break; //should never get here
	}
	return 2;
}


uint32_t aarch64_disassemble(Instruction* restrict instruction, char* outBuffer, uint32_t outBufferSize)
{
	if (instruction->operation < AMD64_END_TYPE)
	{
		return disassemble_instruction(instruction, outBuffer, outBufferSize);
	}
	return 1;
}
