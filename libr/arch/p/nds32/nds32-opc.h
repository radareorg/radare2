#include "nds32.h"
#define USRIDX(group, usr)	((group) | ((usr) << 5))
#define SRIDX(major, minor, ext) (((major) << 7) | ((minor) << 3) | (ext))
#include "nds32-asm.h"
enum{
  /* This is a field (operand) of just a separator char.  */
  SYN_FIELD = 0x100,

  /* This operand is used for input or output.  (define or use)  */
  SYN_INPUT = 0x1000,
  SYN_OUTPUT = 0x2000,
  SYN_LOPT = 0x4000,
  SYN_ROPT = 0x8000,

  /* Hardware resources.  */
  HW_GPR = 0,
  HW_USR,
  HW_DXR,
  HW_SR,
  HW_FSR,
  HW_FDR,
  HW_CP,	/* Co-processor ID.  */
  HW_CPR,	/* Co-processor registers.  */
  HW_ABDIM,	/* [ab][di]m? flag for LSMWA?.  */
  HW_ABM,	/* [ab]m? flag for LSMWZB.  */
  HW_DTITON,
  HW_DTITOFF,
  HW_DPREF_ST,
  HW_CCTL_ST0,
  HW_CCTL_ST1,
  HW_CCTL_ST2,
  HW_CCTL_ST3,
  HW_CCTL_ST4,
  HW_CCTL_ST5,
  HW_CCTL_LV,
  HW_TLBOP_ST,
  HW_STANDBY_ST,
  HW_MSYNC_ST,
  _HW_LAST,
  /* TODO: Maybe we should add a new type to distinguish address and
	   const int.  Only the former allows symbols and relocations.  */
  HW_INT,
  HW_UINT
};


/* These are operand prefixes for input/output semantic.

     %   input
     =   output
     &   both
     {}  optional operand

   Field table for operands and bit-fields.  */

#if 0
static const field_t operand_fields[] =
{
  {"rt",	20, 5, 0, HW_GPR, NULL},
  {"ra",	15, 5, 0, HW_GPR, NULL},
  {"rb",	10, 5, 0, HW_GPR, NULL},
  {"rd",	5, 5, 0, HW_GPR, NULL},
  {"fst",	20, 5, 0, HW_FSR, NULL},
  {"fsa",	15, 5, 0, HW_FSR, NULL},
  {"fsb",	10, 5, 0, HW_FSR, NULL},
  {"fdt",	20, 5, 0, HW_FDR, NULL},
  {"fda",	15, 5, 0, HW_FDR, NULL},
  {"fdb",	10, 5, 0, HW_FDR, NULL},
  {"cprt",	20, 5, 0, HW_CPR, NULL},
  {"cp",	13, 2, 0, HW_CP, NULL},
  {"sh",	5, 5, 0, HW_UINT, NULL},	/* sh in ALU instructions.  */
  {"sv",	8, 2, 0, HW_UINT, NULL},	/* sv in MEM instructions.  */
  {"dt",	21, 1, 0, HW_DXR, NULL},
  {"usr",	10, 10, 0, HW_USR, NULL},	/* User Special Registers.  */
  {"sr",	10, 10, 0, HW_SR, NULL},	/* System Registers.  */
  {"ridx",	10, 10, 0, HW_UINT, NULL},	/* Raw value for mfusr/mfsr.  */
  {"enb4",	6, 9, 0, HW_UINT, NULL},	/* Enable4 for LSMW.  */
  {"swid",	5, 15, 0, HW_UINT, NULL},
  {"stdby_st",	5, 2, 0, HW_STANDBY_ST, NULL},
  {"tlbop_st",	5, 5, 0, HW_TLBOP_ST, NULL},
  {"tlbop_stx",	5, 5, 0, HW_UINT, NULL},
  {"cctl_st0",	5, 5, 0, HW_CCTL_ST0, NULL},
  {"cctl_st1",	5, 5, 0, HW_CCTL_ST1, NULL},
  {"cctl_st2",	5, 5, 0, HW_CCTL_ST2, NULL},
  {"cctl_st3",	5, 5, 0, HW_CCTL_ST3, NULL},
  {"cctl_st4",	5, 5, 0, HW_CCTL_ST4, NULL},
  {"cctl_st5",	5, 5, 0, HW_CCTL_ST5, NULL},
  {"cctl_stx",	5, 5, 0, HW_UINT, NULL},
  {"cctl_lv",	10, 1, 0, HW_CCTL_LV, NULL},
  {"msync_st",	5, 3, 0, HW_MSYNC_ST, NULL},
  {"msync_stx",	5, 3, 0, HW_UINT, NULL},
  {"dpref_st",	20, 5, 0, HW_DPREF_ST, NULL},
  {"rt5",	5, 5, 0, HW_GPR, NULL},
  {"ra5",	0, 5, 0, HW_GPR, NULL},
  {"rt4",	5, 4, 0, HW_GPR, NULL},
  {"rt3",	6, 3, 0, HW_GPR, NULL},
  {"rt38",	8, 3, 0, HW_GPR, NULL},	/* rt3 used in 38 form.  */
  {"ra3",	3, 3, 0, HW_GPR, NULL},
  {"rb3",	0, 3, 0, HW_GPR, NULL},
  {"rt5e",	4, 4, 1, HW_GPR, NULL},	/* movd44 */
  {"ra5e",	0, 4, 1, HW_GPR, NULL},	/* movd44 */
  {"re2",	5, 2, 0, HW_GPR, parse_re2},	/* re in push25/pop25.  */
  {"fe5",	0, 5, 2, HW_UINT, parse_fe5},	/* imm5u in lwi45.fe.  */
  {"pi5",	0, 5, 0, HW_UINT, parse_pi5},	/* imm5u in movpi45.  */
  {"abdim",	2, 3, 0, HW_ABDIM, NULL},	/* Flags for LSMW.  */
  {"abm",	2, 3, 0, HW_ABM, NULL},	/* Flags for LSMWZB.  */
  {"dtiton",	8, 2, 0, HW_DTITON, NULL},
  {"dtitoff",	8, 2, 0, HW_DTITOFF, NULL},

  {"i5s",	0, 5, 0, HW_INT, NULL},
  {"i10s",	0, 10, 0, HW_INT, NULL},
  {"i15s",	0, 15, 0, HW_INT, NULL},
  {"i19s",	0, 19, 0, HW_INT, NULL},
  {"i20s",	0, 20, 0, HW_INT, NULL},
  {"i8s1",	0, 8, 1, HW_INT, NULL},
  {"i11br3",	8, 11, 0, HW_INT, NULL},
  {"i14s1",	0, 14, 1, HW_INT, NULL},
  {"i15s1",	0, 15, 1, HW_INT, NULL},
  {"i16s1",	0, 16, 1, HW_INT, NULL},
  {"i18s1",	0, 18, 1, HW_INT, NULL},
  {"i24s1",	0, 24, 1, HW_INT, NULL},
  {"i8s2",	0, 8, 2, HW_INT, NULL},
  {"i12s2",	0, 12, 2, HW_INT, NULL},
  {"i15s2",	0, 15, 2, HW_INT, NULL},
  {"i17s2",	0, 17, 2, HW_INT, NULL},
  {"i19s2",	0, 19, 2, HW_INT, NULL},
  {"i3u",	0, 3, 0, HW_UINT, NULL},
  {"i5u",	0, 5, 0, HW_UINT, NULL},
  {"ib5u",	10, 5, 0, HW_UINT, NULL},	/* imm5 field in ALU.  */
  {"ib5s",	10, 5, 0, HW_INT, NULL},	/* imm5 field in ALU.  */
  {"i9u",	0, 9, 0, HW_UINT, NULL},	/* break16/ex9.it */
  {"ia3u",	3, 3, 0, HW_UINT, NULL},	/* bmski33, fexti33 */
  {"i8u",	0, 8, 0, HW_UINT, NULL},
  {"i15u",	0, 15, 0, HW_UINT, NULL},
  {"i20u",	0, 20, 0, HW_UINT, NULL},
  {"i3u1",	0, 3, 1, HW_UINT, NULL},
  {"i9u1",	0, 9, 1, HW_UINT, NULL},
  {"i3u2",	0, 3, 2, HW_UINT, NULL},
  {"i6u2",	0, 6, 2, HW_UINT, NULL},
  {"i7u2",	0, 7, 2, HW_UINT, NULL},
  {"i5u3",	0, 5, 3, HW_UINT, NULL},	/* pop25/pop25 */
  {"i15s3",	0, 15, 3, HW_UINT, NULL},	/* dprefi.d */

  {NULL, 0, 0, 0, 0, NULL}
};
#endif

#undef OP6
#undef RA5
#define OP6(op6)		(N32_OP6_ ## op6 << 25)
#define DEF_REG(r)		(__BIT (r))
#define USE_REG(r)		(__BIT (r))
#define RT(r)			(r << 20)
#define RA(r)			(r << 15)
#define RB(r)			(r << 10)
#define RA5(r)			(r)

#if 0
// unused
static struct nds32_opcode nds32_opcodes[] =
{
  /* ALU1 */
#define ALU1(sub)	(OP6 (ALU1) | N32_ALU1_ ## sub)
  {"add", "=rt,%ra,%rb",		ALU1 (ADD), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sub", "=rt,%ra,%rb",		ALU1 (SUB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"and", "=rt,%ra,%rb",		ALU1 (AND), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"xor", "=rt,%ra,%rb",		ALU1 (XOR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"or", "=rt,%ra,%rb",			ALU1 (OR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"nor", "=rt,%ra,%rb",		ALU1 (NOR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"slt", "=rt,%ra,%rb",		ALU1 (SLT), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"slts", "=rt,%ra,%rb",		ALU1 (SLTS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"slli", "=rt,%ra,%ib5u",		ALU1 (SLLI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"srli", "=rt,%ra,%ib5u",		ALU1 (SRLI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"srai", "=rt,%ra,%ib5u",		ALU1 (SRAI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"rotri", "=rt,%ra,%ib5u",		ALU1 (ROTRI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sll", "=rt,%ra,%rb",		ALU1 (SLL), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"srl", "=rt,%ra,%rb",		ALU1 (SRL), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sra", "=rt,%ra,%rb",		ALU1 (SRA), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"rotr", "=rt,%ra,%rb",		ALU1 (ROTR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"seb", "=rt,%ra",			ALU1 (SEB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"seh", "=rt,%ra",			ALU1 (SEH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"bitc", "=rt,%ra,%rb",		ALU1 (BITC), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"zeh", "=rt,%ra",			ALU1 (ZEH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"wsbh", "=rt,%ra",			ALU1 (WSBH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"divsr", "=rt,=rd,%ra,%rb",		ALU1 (DIVSR), 4, ATTR (DIV) | ATTR_V2UP, 0, NULL, 0, NULL},
  {"divr", "=rt,=rd,%ra,%rb",		ALU1 (DIVR), 4, ATTR (DIV) | ATTR_V2UP, 0, NULL, 0, NULL},
  {"sva", "=rt,%ra,%rb",		ALU1 (SVA), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"svs", "=rt,%ra,%rb",		ALU1 (SVS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"cmovz", "=rt,%ra,%rb",		ALU1 (CMOVZ), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"cmovn", "=rt,%ra,%rb",		ALU1 (CMOVN), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"add_slli", "=rt,%ra,%rb,%sh",	ALU1 (ADD), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"sub_slli", "=rt,%ra,%rb,%sh",	ALU1 (SUB), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"and_slli", "=rt,%ra,%rb,%sh",	ALU1 (AND), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"xor_slli", "=rt,%ra,%rb,%sh",	ALU1 (XOR), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"or_slli", "=rt,%ra,%rb,%sh",	ALU1 (OR), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"or_srli", "=rt,%ra,%rb,%sh",	ALU1 (OR_SRLI), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"add_srli", "=rt,%ra,%rb,%sh",	ALU1 (ADD_SRLI), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"sub_srli", "=rt,%ra,%rb,%sh",	ALU1 (SUB_SRLI), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"and_srli", "=rt,%ra,%rb,%sh",	ALU1 (AND_SRLI), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"xor_srli", "=rt,%ra,%rb,%sh",	ALU1 (XOR_SRLI), 4, ATTR_V3, 0, NULL, 0, NULL},

  /* ALU2 */
#define ALU2(sub)	(OP6 (ALU2) | N32_ALU2_ ## sub)
  {"max", "=rt,%ra,%rb",	ALU2 (MAX), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"min", "=rt,%ra,%rb",	ALU2 (MIN), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"ave", "=rt,%ra,%rb",	ALU2 (AVE), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"abs", "=rt,%ra",		ALU2 (ABS), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"clips", "=rt,%ra,%ib5s",	ALU2 (CLIPS), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"clip", "=rt,%ra,%ib5u",	ALU2 (CLIP), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"clo", "=rt,%ra",		ALU2 (CLO), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"clz", "=rt,%ra",		ALU2 (CLZ), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"bset", "=rt,%ra,%ib5u",	ALU2 (BSET), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"bclr", "=rt,%ra,%ib5u",	ALU2 (BCLR), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"btgl", "=rt,%ra,%ib5u",	ALU2 (BTGL), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"btst", "=rt,%ra,%ib5u",	ALU2 (BTST), 4, ATTR (PERF_EXT), 0, NULL, 0, NULL},
  {"bse", "=rt,%ra,=rb",	ALU2 (BSE), 4, ATTR (PERF2_EXT), 0, NULL, 0, NULL},
  {"bsp", "=rt,%ra,=rb",	ALU2 (BSP), 4, ATTR (PERF2_EXT), 0, NULL, 0, NULL},
  {"ffb", "=rt,%ra,%rb",	ALU2 (FFB), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"ffmism", "=rt,%ra,%rb",	ALU2 (FFMISM), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"ffzmism", "=rt,%ra,%rb",	ALU2 (FFZMISM), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"mfusr", "=rt,%usr",		ALU2 (MFUSR), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"mtusr", "%rt,%usr",		ALU2 (MTUSR), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"mfusr", "=rt,%ridx",	ALU2 (MFUSR), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"mtusr", "%rt,%ridx",	ALU2 (MTUSR), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"mul", "=rt,%ra,%rb",	ALU2 (MUL), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"mults64", "=dt,%ra,%rb",	ALU2 (MULTS64), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"mult64", "=dt,%ra,%rb",	ALU2 (MULT64), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"madds64", "=dt,%ra,%rb",	ALU2 (MADDS64), 4, ATTR (MAC) | ATTR_ALL, 0, NULL, 0, NULL},
  {"madd64", "=dt,%ra,%rb",	ALU2 (MADD64), 4, ATTR (MAC) | ATTR_ALL, 0, NULL, 0, NULL},
  {"msubs64", "=dt,%ra,%rb",	ALU2 (MSUBS64), 4, ATTR (MAC) | ATTR_ALL, 0, NULL, 0, NULL},
  {"msub64", "=dt,%ra,%rb",	ALU2 (MSUB64), 4, ATTR (MAC) | ATTR_ALL, 0, NULL, 0, NULL},
  {"divs", "=dt,%ra,%rb",	ALU2 (DIVS), 4, ATTR (DIV) | ATTR (DXREG), 0, NULL, 0, NULL},
  {"div", "=dt,%ra,%rb",	ALU2 (DIV), 4, ATTR (DIV) | ATTR (DXREG), 0, NULL, 0, NULL},
  {"mult32", "=dt,%ra,%rb",	ALU2 (MULT32), 4, ATTR (DXREG) | ATTR_ALL, 0, NULL, 0, NULL},
  {"madd32", "=dt,%ra,%rb",	ALU2 (MADD32), 4, ATTR (MAC) | ATTR (DXREG) | ATTR_ALL, 0, NULL, 0, NULL},
  {"msub32", "=dt,%ra,%rb",	ALU2 (MSUB32), 4, ATTR (MAC) | ATTR (DXREG) | ATTR_ALL, 0, NULL, 0, NULL},
  {"ffbi", "=rt,%ra,%ib5u",	ALU2 (FFBI) | __BIT (6), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"flmism", "=rt,%ra,%rb",	ALU2 (FLMISM) | __BIT (6), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"mulsr64", "=rt,%ra,%rb",	ALU2 (MULSR64)| __BIT (6), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"mulr64", "=rt,%ra,%rb",	ALU2 (MULR64) | __BIT (6), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"maddr32", "=rt,%ra,%rb",	ALU2 (MADDR32) | __BIT (6), 4, ATTR (MAC) | ATTR_V2UP, 0, NULL, 0, NULL},
  {"msubr32", "=rt,%ra,%rb",	ALU2 (MSUBR32) | __BIT (6), 4, ATTR (MAC) | ATTR_V2UP, 0, NULL, 0, NULL},

  /* MISC */
#define MISC(sub)	(OP6 (MISC) | N32_MISC_ ## sub)
  {"standby", "%stdby_st",	MISC (STANDBY), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"cctl", "%ra,%cctl_st0",	MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"cctl", "%ra,%cctl_st1{,%cctl_lv}", MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"cctl", "=rt,%ra,%cctl_st2",	MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"cctl", "%rt,%ra,%cctl_st3",	MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"cctl", "%cctl_st4",		MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"cctl", "%cctl_st5{,%cctl_lv}", MISC (CCTL), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"cctl", "=rt,%ra,%cctl_stx,%cctl_lv", MISC (CCTL), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"mfsr", "=rt,%sr",		MISC (MFSR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"mtsr", "%rt,%sr",		MISC (MTSR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"mfsr", "=rt,%ridx",		MISC (MFSR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"mtsr", "%rt,%ridx",		MISC (MTSR), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"iret", "",			MISC (IRET), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"trap", "%swid",		MISC (TRAP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"trap", "",			MISC (TRAP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"teqz", "%rt,%swid",		MISC (TEQZ), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"tnez", "%rt,%swid",		MISC (TNEZ), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"dsb", "",			MISC (DSB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"isb", "",			MISC (ISB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"break", "%swid",		MISC (BREAK), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"break", "",			MISC (BREAK), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"syscall", "%swid",		MISC (SYSCALL), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"msync", "%msync_st",	MISC (MSYNC), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"msync", "%msync_stx",	MISC (MSYNC), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"isync", "%rt",		MISC (ISYNC), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"tlbop", "%ra,%tlbop_st",	MISC (TLBOP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"tlbop", "%ra,%tlbop_stx",	MISC (TLBOP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"tlbop", "%rt,%ra,pb",	MISC (TLBOP) | (5 << 5), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"tlbop", "flua",		MISC (TLBOP) | (7 << 5), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},

  {"setend.l", "",		MISC (MTSR)
				| (SRIDX (1, 0, 0) << 10) | __BIT (5), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"setend.b", "",		MISC (MTSR)
				| (SRIDX (1, 0, 0) << 10) | __BIT (5) | __BIT (20), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"setgie.d", "",		MISC (MTSR)
				| (SRIDX (1, 0, 0) << 10) | __BIT (6), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"setgie.e", "",		MISC (MTSR)
				| (SRIDX (1, 0, 0) << 10) | __BIT (6) | __BIT (20), 4, ATTR_ALL, 0, NULL, 0, NULL},

  /* JI */
  {"jal", "%i24s1",		OP6 (JI) | __BIT (24), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"j", "%i24s1",		OP6 (JI), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},

  /* BR1 */
  {"beq", "%rt,%ra,%i14s1",	OP6 (BR1), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bne", "%rt,%ra,%i14s1",	OP6 (BR1) | __BIT (14), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},

  /* BR2 */
#define BR2(sub)	(OP6 (BR2) | (N32_BR2_ ## sub << 16))
  {"beqz", "%rt,%i16s1",	BR2 (BEQZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bnez", "%rt,%i16s1",	BR2 (BNEZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bgez", "%rt,%i16s1",	BR2 (BGEZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bltz", "%rt,%i16s1",	BR2 (BLTZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bgtz", "%rt,%i16s1",	BR2 (BGTZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"blez", "%rt,%i16s1",	BR2 (BLEZ), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bgezal", "%rt,%i16s1",	BR2 (BGEZAL), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bltzal", "%rt,%i16s1",	BR2 (BLTZAL), 4, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},

  /* BR3 */
  {"beqc", "%rt,%i11br3,%i8s1",	OP6 (BR3), 4, ATTR_PCREL | ATTR_V3MUP, 0, NULL, 0, NULL},
  {"bnec", "%rt,%i11br3,%i8s1",	OP6 (BR3) | __BIT (19), 4, ATTR_PCREL | ATTR_V3MUP, 0, NULL, 0, NULL},

#define JREG(sub)	(OP6 (JREG) | N32_JREG_ ## sub)
  /* JREG */
  {"jr", "%rb",			JREG (JR), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jral", "%rt,%rb",		JREG (JRAL), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jral", "%rb",		JREG (JRAL) | RT (30), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jrnez", "%rb",		JREG (JRNEZ), 4, ATTR (BRANCH) | ATTR_V3, 0, NULL, 0, NULL},
  {"jralnez", "%rt,%rb",	JREG (JRALNEZ), 4, ATTR (BRANCH) | ATTR_V3, 0, NULL, 0, NULL},
  {"jralnez", "%rb",		JREG (JRALNEZ) | RT (30), 4, ATTR (BRANCH) | ATTR_V3, 0, NULL, 0, NULL},

#define JREG_RET	(1 << 5)
#define JREG_IFC	(1 << 6)
  {"ret", "%rb",		JREG (JR) | JREG_RET, 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"ret", "",			JREG (JR) | JREG_RET | RB (30), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jral", "%dtiton %rt,%rb",	JREG (JRAL), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jral", "%dtiton %rb",	JREG (JRAL) | RT (30), 4, ATTR (BRANCH) | ATTR_ALL, 0, NULL, 0, NULL},
  {"jr", "%dtitoff %rb",	JREG (JR), 4, ATTR (BRANCH) | ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"ret", "%dtitoff %rb",	JREG (JR) | JREG_RET, 4, ATTR (BRANCH) | ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"ifret", "",			JREG (JR) | JREG_IFC | JREG_RET, 4, ATTR (BRANCH) | ATTR (IFC_EXT), 0, NULL, 0, NULL},

  /* MEM */
#define MEM(sub)	(OP6 (MEM) | N32_MEM_ ## sub)
  {"lb", "=rt,[%ra+(%rb<<%sv)]",                MEM (LB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lb", "=rt,[%ra+%rb{<<%sv}]",		MEM (LB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lh", "=rt,[%ra+(%rb<<%sv)]",                MEM (LH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lh", "=rt,[%ra+%rb{<<%sv}]",		MEM (LH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lw", "=rt,[%ra+(%rb<<%sv)]",                MEM (LW), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lw", "=rt,[%ra+%rb{<<%sv}]",		MEM (LW), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sb", "=rt,[%ra+(%rb<<%sv)]",                MEM (SB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sb", "%rt,[%ra+%rb{<<%sv}]",		MEM (SB), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sh", "=rt,[%ra+(%rb<<%sv)]",                MEM (SH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sh", "%rt,[%ra+%rb{<<%sv}]",		MEM (SH), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sw", "=rt,[%ra+(%rb<<%sv)]",                MEM (SW), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sw", "%rt,[%ra+%rb{<<%sv}]",		MEM (SW), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lb.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (LB_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lb.bi", "=rt,[%ra],%rb{<<%sv}",		MEM (LB_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lh.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (LH_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lh.bi", "=rt,[%ra],%rb{<<%sv}",		MEM (LH_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lw.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (LW_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lw.bi", "=rt,[%ra],%rb{<<%sv}",		MEM (LW_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sb.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (SB_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sb.bi", "%rt,[%ra],%rb{<<%sv}",		MEM (SB_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sh.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (SH_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sh.bi", "%rt,[%ra],%rb{<<%sv}",		MEM (SH_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sw.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (SW_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sw.bi", "%rt,[%ra],%rb{<<%sv}",		MEM (SW_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbs", "=rt,[%ra+(%rb<<%sv)]",		MEM (LBS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbs", "=rt,[%ra+%rb{<<%sv}]",		MEM (LBS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhs", "=rt,[%ra+(%rb<<%sv)]",		MEM (LHS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhs", "=rt,[%ra+%rb{<<%sv}]",		MEM (LHS), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbs.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (LBS_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbs.bi", "=rt,[%ra],%rb{<<%sv}",		MEM (LBS_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhs.bi", "=rt,[%ra],(%rb<<%sv)",		MEM (LHS_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhs.bi", "=rt,[%ra],%rb{<<%sv}",		MEM (LHS_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"llw", "=rt,[%ra+(%rb<<%sv)]",		MEM (LLW), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"llw", "=rt,[%ra+%rb{<<%sv}]",		MEM (LLW), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"scw", "%rt,[%ra+(%rb<<%sv)]",		MEM (SCW), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"scw", "%rt,[%ra+%rb{<<%sv}]",		MEM (SCW), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"lbup", "=rt,[%ra+(%rb<<%sv)]",		MEM (LBUP), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"lbup", "=rt,[%ra+%rb{<<%sv}]",		MEM (LBUP), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"lwup", "=rt,[%ra+(%rb<<%sv)]",		MEM (LWUP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"lwup", "=rt,[%ra+%rb{<<%sv}]",		MEM (LWUP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"sbup", "%rt,[%ra+(%rb<<%sv)]",		MEM (SBUP), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"sbup", "%rt,[%ra+%rb{<<%sv}]",		MEM (SBUP), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"swup", "%rt,[%ra+(%rb<<%sv)]",		MEM (SWUP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"swup", "%rt,[%ra+%rb{<<%sv}]",		MEM (SWUP), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"dpref", "%dpref_st,[%ra+(%rb<<%sv)]",	MEM (DPREF), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"dpref", "%dpref_st,[%ra+%rb{<<%sv}]",	MEM (DPREF), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},

  /* LBGP */
  {"lbi.gp", "=rt,[+%i19s]",	OP6 (LBGP), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"lbsi.gp", "=rt,[+%i19s]",	OP6 (LBGP) | __BIT (19), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},

  /* SBGP */
  {"sbi.gp", "%rt,[+%i19s]",	OP6 (SBGP), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"addi.gp", "=rt,%i19s",	OP6 (SBGP) | __BIT (19), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},

  /* HWGP */
  {"lhi.gp", "=rt,[+%i18s1]",	OP6 (HWGP), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"lhsi.gp", "=rt,[+%i18s1]",	OP6 (HWGP) | (2 << 17), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"shi.gp", "%rt,[+%i18s1]",	OP6 (HWGP) | (4 << 17), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"lwi.gp", "=rt,[+%i17s2]",	OP6 (HWGP) | (6 << 17), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},
  {"swi.gp", "%rt,[+%i17s2]",	OP6 (HWGP) | (7 << 17), 4, ATTR (GPREL) | ATTR_V2UP, USE_REG (29), NULL, 0, NULL},

#define LSMW(sub)	(OP6 (LSMW) | N32_LSMW_ ## sub)
  {"lmw", "%abdim %rt,[%ra],%rb{,%enb4}",		LSMW (LSMW), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"smw", "%abdim %rt,[%ra],%rb{,%enb4}",		LSMW (LSMW) | __BIT (5), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lmwa", "%abdim %rt,[%ra],%rb{,%enb4}",	LSMW (LSMWA), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"smwa", "%abdim %rt,[%ra],%rb{,%enb4}",	LSMW (LSMWA) | __BIT (5), 4, ATTR_V3MEX_V2, 0, NULL, 0, NULL},
  {"lmwzb", "%abm %rt,[%ra],%rb{,%enb4}",	LSMW (LSMWZB), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},
  {"smwzb", "%abm %rt,[%ra],%rb{,%enb4}",	LSMW (LSMWZB) | __BIT (5), 4, ATTR (STR_EXT), 0, NULL, 0, NULL},


#define SIMD(sub)	(OP6 (SIMD) | N32_SIMD_ ## sub)
  {"pbsad", "%rt,%rb,%ra",	SIMD (PBSAD), 4, ATTR (PERF2_EXT), 0, NULL, 0, NULL},
  {"pbsada", "%rt,%rb,%ra",	SIMD (PBSADA), 4, ATTR (PERF2_EXT), 0, NULL, 0, NULL},

  /* COP */
#if 0
  {"cpe1", 0, 0, NULL, 0, NULL},
  {"mfcp", 0, 0, NULL, 0, NULL},
  {"cplw", 0, 0, NULL, 0, NULL},
  {"cplw.bi", 0, 0, NULL, 0, NULL},
  {"cpld", 0, 0, NULL, 0, NULL},
  {"cpld.bi", 0, 0, NULL, 0, NULL},
  {"cpe2", 0, 0, NULL, 0, NULL},

  {"cpe3", 0, 0, NULL, 0, NULL},
  {"mtcp", 0, 0, NULL, 0, NULL},
  {"cpsw", 0, 0, NULL, 0, NULL},
  {"cpsw.bi", 0, 0, NULL, 0, NULL},
  {"cpsd", 0, 0, NULL, 0, NULL},
  {"cpsd.bi", 0, 0, NULL, 0, NULL},
  {"cpe4", 0, 0, NULL, 0, NULL},
#endif

  /* FPU */
#define FS1(sub)	(OP6 (COP) | N32_FPU_FS1 | (N32_FPU_FS1_ ## sub << 6))
  {"fadds",   "=fst,%fsa,%fsb",	FS1 (FADDS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fsubs",   "=fst,%fsa,%fsb",	FS1 (FSUBS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcpynss", "=fst,%fsa,%fsb",	FS1 (FCPYNSS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcpyss",  "=fst,%fsa,%fsb",	FS1 (FCPYSS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fmadds",  "=fst,%fsa,%fsb", FS1 (FMADDS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fmsubs",  "=fst,%fsa,%fsb", FS1 (FMSUBS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmovns", "=fst,%fsa,%fsb", FS1 (FCMOVNS),  4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmovzs", "=fst,%fsa,%fsb", FS1 (FCMOVZS),  4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fnmadds", "=fst,%fsa,%fsb", FS1 (FNMADDS),  4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fnmsubs", "=fst,%fsa,%fsb", FS1 (FNMSUBS),  4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fmuls",   "=fst,%fsa,%fsb", FS1 (FMULS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fdivs",   "=fst,%fsa,%fsb", FS1 (FDIVS),	4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},

#define FS1_F2OP(sub)	(OP6 (COP) | N32_FPU_FS1 | (N32_FPU_FS1_F2OP << 6) \
			 | (N32_FPU_FS1_F2OP_ ## sub << 10))
  {"fs2d",    "=fdt,%fsa",	FS1_F2OP (FS2D),    4, ATTR (FPU) | ATTR (FPU_SP_EXT) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fsqrts",  "=fst,%fsa",	FS1_F2OP (FSQRTS),  4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fabss",   "=fst,%fsa",	FS1_F2OP (FABSS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fui2s",   "=fst,%fsa",	FS1_F2OP (FUI2S),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fsi2s",   "=fst,%fsa",	FS1_F2OP (FSI2S),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fs2ui",   "=fst,%fsa",	FS1_F2OP (FS2UI),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fs2ui.z", "=fst,%fsa",	FS1_F2OP (FS2UI_Z), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fs2si",   "=fst,%fsa",	FS1_F2OP (FS2SI),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fs2si.z", "=fst,%fsa",	FS1_F2OP (FS2SI_Z), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},

#define FS2(sub)	(OP6 (COP) | N32_FPU_FS2 | (N32_FPU_FS2_ ## sub << 6))
  {"fcmpeqs",   "=fst,%fsa,%fsb", FS2 (FCMPEQS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmplts",   "=fst,%fsa,%fsb", FS2 (FCMPLTS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmples",   "=fst,%fsa,%fsb", FS2 (FCMPLES),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmpuns",   "=fst,%fsa,%fsb", FS2 (FCMPUNS),   4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmpeqs.e", "=fst,%fsa,%fsb", FS2 (FCMPEQS_E), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmplts.e", "=fst,%fsa,%fsb", FS2 (FCMPLTS_E), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmples.e", "=fst,%fsa,%fsb", FS2 (FCMPLES_E), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},
  {"fcmpuns.e", "=fst,%fsa,%fsb", FS2 (FCMPUNS_E), 4, ATTR (FPU) | ATTR (FPU_SP_EXT), 0, NULL, 0, NULL},

#define FD1(sub)	(OP6 (COP) | N32_FPU_FD1 | (N32_FPU_FD1_ ## sub << 6))
  {"faddd",   "=fdt,%fda,%fdb", FD1 (FADDD),    4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fsubd",   "=fdt,%fda,%fdb", FD1 (FSUBD),    4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcpynsd", "=fdt,%fda,%fdb", FD1 (FCPYNSD),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcpysd",  "=fdt,%fda,%fdb", FD1 (FCPYSD),   4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fmaddd",  "=fdt,%fda,%fdb", FD1 (FMADDD),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fmsubd",  "=fdt,%fda,%fdb", FD1 (FMSUBD),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmovnd", "=fdt,%fda,%fsb", FD1 (FCMOVND),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmovzd", "=fdt,%fda,%fsb", FD1 (FCMOVZD),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fnmaddd", "=fdt,%fda,%fdb", FD1 (FNMADDD),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fnmsubd", "=fdt,%fda,%fdb", FD1 (FNMSUBD),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fmuld",   "=fdt,%fda,%fdb", FD1 (FMULD),    4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fdivd",   "=fdt,%fda,%fdb", FD1 (FDIVD),    4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},

#define FD1_F2OP(sub)	(OP6 (COP) | N32_FPU_FD1 | (N32_FPU_FD1_F2OP << 6) \
			 | (N32_FPU_FD1_F2OP_ ## sub << 10))
  {"fd2s",    "=fst,%fda",	FD1_F2OP (FD2S),    4, ATTR (FPU) | ATTR (FPU_SP_EXT) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fsqrtd",  "=fdt,%fda",	FD1_F2OP (FSQRTD),  4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fabsd",   "=fdt,%fda",	FD1_F2OP (FABSD),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fui2d",   "=fdt,%fsa",	FD1_F2OP (FUI2D),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fsi2d",   "=fdt,%fsa",	FD1_F2OP (FSI2D),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fd2ui",   "=fst,%fda",	FD1_F2OP (FD2UI),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fd2ui.z", "=fst,%fda",	FD1_F2OP (FD2UI_Z), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fd2si",   "=fst,%fda",	FD1_F2OP (FD2SI),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fd2si.z", "=fst,%fda",	FD1_F2OP (FD2SI_Z), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},

#define FD2(sub)	(OP6 (COP) | N32_FPU_FD2 | (N32_FPU_FD2_ ## sub << 6))
  {"fcmpeqd",   "=fst,%fda,%fdb", FD2 (FCMPEQD),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpltd",   "=fst,%fda,%fdb", FD2 (FCMPLTD),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpled",   "=fst,%fda,%fdb", FD2 (FCMPLED),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpund",   "=fst,%fda,%fdb", FD2 (FCMPUND),   4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpeqd.e", "=fst,%fda,%fdb", FD2 (FCMPEQD_E), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpltd.e", "=fst,%fda,%fdb", FD2 (FCMPLTD_E), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpled.e", "=fst,%fda,%fdb", FD2 (FCMPLED_E), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},
  {"fcmpund.e", "=fst,%fda,%fdb", FD2 (FCMPUND_E), 4, ATTR (FPU) | ATTR (FPU_DP_EXT), 0, NULL, 0, NULL},

#define MFCP(sub)	(OP6 (COP) | N32_FPU_MFCP | (N32_FPU_MFCP_ ## sub << 6))
  {"fmfsr",   "=rt,%fsa", MFCP (FMFSR),   4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fmfdr",   "=rt,%fda", MFCP (FMFDR),   4, ATTR (FPU), 0, NULL, 0, NULL},

#define MFCP_XR(sub)	(OP6 (COP) | N32_FPU_MFCP | (N32_FPU_MFCP_XR << 6) \
			 | (N32_FPU_MFCP_XR_ ## sub << 10))
  {"fmfcfg", "=rt"	, MFCP_XR(FMFCFG), 4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fmfcsr", "=rt"	, MFCP_XR(FMFCSR), 4, ATTR (FPU), 0, NULL, 0, NULL},

#define MTCP(sub)	(OP6 (COP) | N32_FPU_MTCP | (N32_FPU_MTCP_ ## sub << 6))
  {"fmtsr",   "%rt,=fsa", MTCP (FMTSR),   4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fmtdr",   "%rt,=fda", MTCP (FMTDR),   4, ATTR (FPU), 0, NULL, 0, NULL},

#define MTCP_XR(sub)	(OP6 (COP) | N32_FPU_MTCP | (N32_FPU_MTCP_XR << 6) \
			 | (N32_FPU_MTCP_XR_ ## sub << 10))
  {"fmtcsr", "%rt"	, MTCP_XR(FMTCSR), 4, ATTR (FPU), 0, NULL, 0, NULL},

#define FPU_MEM(sub)		(OP6 (COP) | N32_FPU_ ## sub)
#define FPU_MEMBI(sub)	(OP6 (COP) | N32_FPU_ ## sub | 0x2 << 6)
#define FPU_RA_IMMBI(sub)	(OP6 (sub) | __BIT (12))
  {"fls",     "=fst,[%ra+(%rb<<%sv)]", FPU_MEM (FLS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fls",     "=fst,[%ra+%rb{<<%sv}]", FPU_MEM (FLS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fls.bi",  "=fst,[%ra],(%rb<<%sv)", FPU_MEMBI (FLS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fls.bi",  "=fst,[%ra],%rb{<<%sv}", FPU_MEMBI (FLS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fss",     "=fst,[%ra+(%rb<<%sv)]", FPU_MEM (FSS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fss",     "=fst,[%ra+%rb{<<%sv}]", FPU_MEM (FSS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fss.bi",  "=fst,[%ra],(%rb<<%sv)", FPU_MEMBI (FSS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fss.bi",  "=fst,[%ra],%rb{<<%sv}", FPU_MEMBI (FSS),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fld",     "=fdt,[%ra+(%rb<<%sv)]", FPU_MEM (FLD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fld",     "=fdt,[%ra+%rb{<<%sv}]", FPU_MEM (FLD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fld.bi",  "=fdt,[%ra],(%rb<<%sv)", FPU_MEMBI (FLD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fld.bi",  "=fdt,[%ra],%rb{<<%sv}", FPU_MEMBI (FLD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsd",     "=fdt,[%ra+(%rb<<%sv)]", FPU_MEM (FSD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsd",     "=fdt,[%ra+%rb{<<%sv}]", FPU_MEM (FSD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsd.bi",  "=fdt,[%ra],(%rb<<%sv)", FPU_MEMBI (FSD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsd.bi",  "=fdt,[%ra],%rb{<<%sv}", FPU_MEMBI (FSD),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"flsi",    "=fst,[%ra{+%i12s2}]",   OP6 (LWC),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"flsi.bi", "=fst,[%ra],%i12s2",     FPU_RA_IMMBI (LWC),4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fssi",    "=fst,[%ra{+%i12s2}]",   OP6 (SWC),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fssi.bi", "=fst,[%ra],%i12s2",     FPU_RA_IMMBI (SWC),4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fldi",    "=fdt,[%ra{+%i12s2}]",   OP6 (LDC),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fldi.bi", "=fdt,[%ra],%i12s2",     FPU_RA_IMMBI (LDC),4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsdi",    "=fdt,[%ra{+%i12s2}]",   OP6 (SDC),	  4, ATTR (FPU), 0, NULL, 0, NULL},
  {"fsdi.bi", "=fdt,[%ra],%i12s2",     FPU_RA_IMMBI (SDC),4, ATTR (FPU), 0, NULL, 0, NULL},

  /* AEXT */

  {"lbi", "=rt,[%ra{+%i15s}]",			OP6 (LBI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhi", "=rt,[%ra{+%i15s1}]",			OP6 (LHI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwi", "=rt,[%ra{+%i15s2}]",			OP6 (LWI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbi.bi", "=rt,[%ra],%i15s",			OP6 (LBI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhi.bi", "=rt,[%ra],%i15s1",		OP6 (LHI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwi.bi", "=rt,[%ra],%i15s2",		OP6 (LWI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sbi", "%rt,[%ra{+%i15s}]",			OP6 (SBI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"shi", "%rt,[%ra{+%i15s1}]",			OP6 (SHI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"swi", "%rt,[%ra{+%i15s2}]",			OP6 (SWI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sbi.bi", "%rt,[%ra],%i15s",			OP6 (SBI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"shi.bi", "%rt,[%ra],%i15s1",		OP6 (SHI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"swi.bi", "%rt,[%ra],%i15s2",		OP6 (SWI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbsi", "=rt,[%ra{+%i15s}]",			OP6 (LBSI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhsi", "=rt,[%ra{+%i15s1}]",		OP6 (LHSI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwsi", "=rt,[%ra{+%i15s2}]",		OP6 (LWSI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbsi.bi", "=rt,[%ra],%i15s",		OP6 (LBSI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhsi.bi", "=rt,[%ra],%i15s1",		OP6 (LHSI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwsi.bi", "=rt,[%ra],%i15s2",		OP6 (LWSI_BI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"cplwi", "%cp,=cprt,[%ra{+%i12s2}]",		OP6 (LWC), 4, 0, 0, NULL, 0, NULL},
  {"cpswi", "%cp,=cprt,[%ra{+%i12s2}]",		OP6 (SWC), 4, 0, 0, NULL, 0, NULL},
  {"cpldi", "%cp,%cprt,[%ra{+%i12s2}]",		OP6 (LDC), 4, 0, 0, NULL, 0, NULL},
  {"cpsdi", "%cp,%cprt,[%ra{+%i12s2}]",		OP6 (SDC), 4, 0, 0, NULL, 0, NULL},
  {"cplwi.bi", "%cp,=cprt,[%ra],%i12s2",	OP6 (LWC) | __BIT (12), 4, 0, 0, NULL, 0, NULL},
  {"cpswi.bi", "%cp,=cprt,[%ra],%i12s2",	OP6 (SWC) | __BIT (12), 4, 0, 0, NULL, 0, NULL},
  {"cpldi.bi", "%cp,%cprt,[%ra],%i12s2",	OP6 (LDC) | __BIT (12), 4, 0, 0, NULL, 0, NULL},
  {"cpsdi.bi", "%cp,%cprt,[%ra],%i12s2",	OP6 (SDC) | __BIT (12), 4, 0, 0, NULL, 0, NULL},
  {"movi", "=rt,%i20s",				OP6 (MOVI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sethi", "=rt,%i20u",			OP6 (SETHI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"addi", "=rt,%ra,%i15s",			OP6 (ADDI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"subri", "=rt,%ra,%i15s",			OP6 (SUBRI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"andi", "=rt,%ra,%i15u",			OP6 (ANDI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"xori", "=rt,%ra,%i15u",			OP6 (XORI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"ori", "=rt,%ra,%i15u",			OP6 (ORI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"slti", "=rt,%ra,%i15s",			OP6 (SLTI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"sltsi", "=rt,%ra,%i15s",			OP6 (SLTSI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"bitci", "=rt,%ra,%i15u",			OP6 (BITCI), 4, ATTR_V3, 0, NULL, 0, NULL},
  {"dprefi.w", "%dpref_st,[%ra{+%i15s2]}",	OP6 (DPREFI), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},
  {"dprefi.d", "%dpref_st,[%ra{+%i15s3]}",	OP6 (DPREFI) | __BIT (24), 4, ATTR_V3MEX_V1, 0, NULL, 0, NULL},

  /* 16-bit instructions.  */
  {"mov55", "=rt5,%ra5",		0x8000, 2, ATTR_ALL, 0, NULL, 0, NULL},	/* mov55, $sp, $sp == ifret */
  {"ifret16", "",			0x83ff, 2, ATTR (IFC_EXT), 0, NULL, 0, NULL},
  {"movi55", "=rt5,%i5s",		0x8400, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"add45", "=rt4,%ra5",		0x8800, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"sub45", "=rt4,%ra5",		0x8a00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"addi45", "=rt4,%i5u",		0x8c00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"subi45", "=rt4,%i5u",		0x8e00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"srai45", "=rt4,%i5u",		0x9000, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"srli45", "=rt4,%i5u",		0x9200, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"slli333", "=rt3,%ra3,%i3u",		0x9400, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"zeb33", "=rt3,%ra3",		0x9600, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"zeh33", "=rt3,%ra3",		0x9601, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"seb33", "=rt3,%ra3",		0x9602, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"seh33", "=rt3,%ra3",		0x9603, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"xlsb33", "=rt3,%ra3",		0x9604, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"x11b33", "=rt3,%ra3",		0x9605, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"bmski33", "=rt3,%ia3u",		0x9606, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"fexti33", "=rt3,%ia3u",		0x9607, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"add333", "=rt3,%ra3,%rb3",		0x9800, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"sub333", "=rt3,%ra3,%rb3",		0x9a00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"addi333", "=rt3,%ra3,%i3u",		0x9c00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"subi333", "=rt3,%ra3,%i3u",		0x9e00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwi333", "=rt3,[%ra3{+%i3u2}]",	0xa000, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwi333.bi", "=rt3,[%ra3],%i3u2",	0xa200, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"lhi333", "=rt3,[%ra3{+%i3u1}]",	0xa400, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"lbi333", "=rt3,[%ra3{+%i3u}]",	0xa600, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"swi333", "%rt3,[%ra3{+%i3u2}]",	0xa800, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"swi333.bi", "%rt3,[%ra3],%i3u2",	0xaa00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"shi333", "%rt3,[%ra3{+%i3u1}]",	0xac00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"sbi333", "%rt3,[%ra3{+%i3u}]",	0xae00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"addri36.sp", "%rt3,%i6u2",		0xb000, 2, ATTR_V3MUP, USE_REG (31), NULL, 0, NULL},
  {"lwi45.fe", "=rt4,%fe5",		0xb200, 2, ATTR_V3MUP, USE_REG (8), NULL, 0, NULL},
  {"lwi450", "=rt4,[%ra5]",		0xb400, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"swi450", "%rt4,[%ra5]",		0xb600, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"lwi37", "=rt38,[$fp{+%i7u2}]",	0xb800, 2, ATTR_ALL, USE_REG (28), NULL, 0, NULL},
  {"swi37", "%rt38,[$fp{+%i7u2}]",	0xb880, 2, ATTR_ALL, USE_REG (28), NULL, 0, NULL},
  {"beqz38", "%rt38,%i8s1",		0xc000, 2, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bnez38", "%rt38,%i8s1",		0xc800, 2, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"beqs38", "%rt38,%i8s1",		0xd000, 2, ATTR_PCREL | ATTR_ALL, USE_REG (5), NULL, 0, NULL},
  {"j8", "%i8s1",			0xd500, 2, ATTR_PCREL | ATTR_ALL, 0, NULL, 0, NULL},
  {"bnes38", "%rt38,%i8s1",		0xd800, 2, ATTR_PCREL | ATTR_ALL, USE_REG (5), NULL, 0, NULL},
  {"jr5", "%ra5",			0xdd00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"ex9.it", "%i5u",			0xdd40, 2, ATTR (EX9_EXT), 0, NULL, 0, NULL},
  {"ret5", "%ra5",			0xdd80, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"ret5", "",				0xdd80 | RA5 (30), 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"jral5", "%ra5",			0xdd20, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"add5.pc", "%ra5",			0xdda0, 2, ATTR_V3, 0, NULL, 0, NULL},
  {"slts45", "%rt4,%ra5",		0xe000, 2, ATTR_ALL, DEF_REG (15), NULL, 0, NULL},
  {"slt45", "%rt4,%ra5",		0xe200, 2, ATTR_ALL, DEF_REG (15), NULL, 0, NULL},
  {"sltsi45", "%rt4,%i5u",		0xe400, 2, ATTR_ALL, DEF_REG (15), NULL, 0, NULL},
  {"slti45", "%rt4,%i5u",		0xe600, 2, ATTR_ALL, DEF_REG (15), NULL, 0, NULL},
  {"beqzs8", "%i8s1",			0xe800, 2, ATTR_PCREL | ATTR_ALL, USE_REG (5), NULL, 0, NULL},
  {"bnezs8", "%i8s1",			0xe900, 2, ATTR_PCREL | ATTR_ALL, USE_REG (5), NULL, 0, NULL},
  {"ex9.it", "%i9u",			0xea00, 2, ATTR (EX9_EXT), 0, NULL, 0, NULL},
  {"break16", "%i9u",			0xea00, 2, ATTR_ALL, 0, NULL, 0, NULL},
  {"addi10.sp", "%i10s",		0xec00, 2, ATTR_V2UP, USE_REG (31) | DEF_REG (31), NULL, 0, NULL},
  {"lwi37.sp", "=rt38,[+%i7u2]",	0xf000, 2, ATTR_V2UP, USE_REG (31), NULL, 0, NULL},
  {"swi37.sp", "%rt38,[+%i7u2]",	0xf080, 2, ATTR_V2UP, USE_REG (31), NULL, 0, NULL},
  {"ifcall9", "%i9u1",			0xf800, 2, ATTR (IFC_EXT), 0, NULL, 0, NULL},
  {"movpi45", "=rt4,%pi5",		0xfa00, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"push25", "%re2,%i5u3",		0xfc00, 2, ATTR_V3MUP, USE_REG (31) | DEF_REG (31), NULL, 0, NULL},
  {"pop25", "%re2,%i5u3",		0xfc80, 2, ATTR_V3MUP, USE_REG (31) | DEF_REG (31), NULL, 0, NULL},
  {"movd44", "=rt5e,%ra5e",		0xfd00, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"neg33", "=rt3,%ra3",		0xfe02, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"not33", "=rt3,%ra3",		0xfe03, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"mul33", "=rt3,%ra3",		0xfe04, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"xor33", "=rt3,%ra3",		0xfe05, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"and33", "=rt3,%ra3",		0xfe06, 2, ATTR_V3MUP, 0, NULL, 0, NULL},
  {"or33", "=rt3,%ra3",			0xfe07, 2, ATTR_V3MUP, 0, NULL, 0, NULL},

  /* Alias instructions.  */
  {"neg", "=rt,%ra",			OP6 (SUBRI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"zeb", "=rt,%ra",			OP6 (ANDI) | 0xff, 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"nop", "",				ALU1 (SRLI), 4, ATTR_ALL, 0, NULL, 0, NULL},
  {"nop16", "",				0x9200, 2, ATTR_ALL, 0, NULL, 0, NULL},

  /* TODO: For some instruction, an operand may refer to a pair of
	   register, e.g., mulsr64 or movd44.

     Some instruction need special constrain, e.g., movpi45,
	  break16, ex9.it.  */
};
#endif

static const keyword_t keyword_gpr[] =
{
  {"a0", 0, ATTR (RDREG)}, {"a1", 1, ATTR (RDREG)}, {"a2", 2, ATTR (RDREG)},
  {"a3", 3, ATTR (RDREG)}, {"a4", 4, ATTR (RDREG)}, {"a5", 5, ATTR (RDREG)},
  {"s0", 6, ATTR (RDREG)}, {"s1", 7, ATTR (RDREG)}, {"s2", 8, ATTR (RDREG)},
  {"s3", 9, ATTR (RDREG)}, {"s4", 10, ATTR (RDREG)},
  {"s5", 11, 0}, {"s6", 12, 0}, {"s7", 13, 0}, {"s8", 14, 0},
  {"ta", 15, ATTR (RDREG)},
  {"t0", 16, 0}, {"t1", 17, 0}, {"t2", 18, 0}, {"t3", 19, 0}, {"t4", 20, 0},
  {"t5", 21, 0}, {"t6", 22, 0}, {"t7", 23, 0}, {"t8", 24, 0}, {"t9", 25, 0},
  {"p0", 26, 0}, {"p1", 27, 0},
  {"fp", 28, ATTR (RDREG)}, {"gp", 29, ATTR (RDREG)},
  {"lp", 30, ATTR (RDREG)}, {"sp", 31, ATTR (RDREG)},

  {NULL, 0, 0}
};

static const keyword_t keyword_usr[] =
{
  {"d0.lo", USRIDX (0, 0), 0},
  {"d0.hi", USRIDX (0, 1), 0},
  {"d1.lo", USRIDX (0, 2), 0},
  {"d1.hi", USRIDX (0, 3), 0},
  {"itb", USRIDX (0, 28), 0},
  {"ifc_lp", USRIDX (0, 29), 0},
  {"pc", USRIDX (0, 31), 0},

  {"dma_cfg", USRIDX (1, 0), 0},
  {"dma_gcsw", USRIDX (1, 1), 0},
  {"dma_chnsel", USRIDX (1, 2), 0},
  {"dma_act", USRIDX (1, 3), 0},
  {"dma_setup", USRIDX (1, 4), 0},
  {"dma_isaddr", USRIDX (1, 5), 0},
  {"dma_esaddr", USRIDX (1, 6), 0},
  {"dma_tcnt", USRIDX (1, 7), 0},
  {"dma_status", USRIDX (1, 8), 0},
  {"dma_2dset", USRIDX (1, 9), 0},
  {"dma_rcnt", USRIDX (1, 23), 0},
  {"dma_hstatus", USRIDX (1, 24), 0},
  {"dma_2dsctl", USRIDX (1, 25), 0},

  {"pfmc0", USRIDX (2, 0), 0},
  {"pfmc1", USRIDX (2, 1), 0},
  {"pfmc2", USRIDX (2, 2), 0},
  {"pfm_ctl", USRIDX (2, 4), 0},

  {NULL, 0, 0}
};

static const keyword_t keyword_dxr[] =
{
  {"d0", 0, 0}, {"d1", 1, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_sr[] =
{
  {"cr0", SRIDX (0, 0, 0), 0}, {"cpu_ver", SRIDX (0, 0, 0), 0},
  {"cr1", SRIDX (0, 1, 0), 0}, {"icm_cfg", SRIDX (0, 1, 0), 0},
  {"cr2", SRIDX (0, 2, 0), 0}, {"dcm_cfg", SRIDX (0, 2, 0), 0},
  {"cr3", SRIDX (0, 3, 0), 0}, {"mmu_cfg", SRIDX (0, 3, 0), 0},
  {"cr4", SRIDX (0, 4, 0), 0}, {"msc_cfg", SRIDX (0, 4, 0), 0},
  {"cr5", SRIDX (0, 0, 1), 0}, {"core_id", SRIDX (0, 0, 1), 0},
  {"cr6", SRIDX (0, 5, 0), 0}, {"fucop_exist", SRIDX (0, 5, 0), 0},

  {"ir0", SRIDX (1, 0, 0), 0}, {"psw", SRIDX (1, 0, 0), 0},
  {"ir1", SRIDX (1, 0, 1), 0}, {"ipsw", SRIDX (1, 0, 1), 0},
  {"ir2", SRIDX (1, 0, 2), 0}, {"p_ipsw", SRIDX (1, 0, 2), 0},
  {"ir3", SRIDX (1, 1, 1), 0}, {"ivb", SRIDX (1, 1, 1), 0},
  {"ir4", SRIDX (1, 2, 1), 0}, {"p_eva", SRIDX (1, 2, 2), 0},
  {"ir5", SRIDX (1, 2, 2), 0}, {"eva", SRIDX (1, 2, 1), 0},
  {"ir6", SRIDX (1, 3, 1), 0}, {"itype", SRIDX (1, 3, 1), 0},
  {"ir7", SRIDX (1, 3, 2), 0}, {"p_itype", SRIDX (1, 3, 2), 0},
  {"ir8", SRIDX (1, 4, 1), 0}, {"merr", SRIDX (1, 4, 1), 0},
  {"ir9", SRIDX (1, 5, 1), 0}, {"ipc", SRIDX (1, 5, 1), 0},
  {"ir10", SRIDX (1, 5, 2), 0}, {"p_ipc", SRIDX (1, 5, 2), 0},
  {"ir11", SRIDX (1, 5, 3), 0}, {"oipc", SRIDX (1, 5, 3), 0},
  {"ir12", SRIDX (1, 6, 2), 0}, {"p_p0", SRIDX (1, 6, 2), 0},
  {"ir13", SRIDX (1, 7, 2), 0}, {"p_p1", SRIDX (1, 7, 2), 0},
  {"ir14", SRIDX (1, 8, 0), 0}, {"int_mask", SRIDX (1, 8, 0), 0},
  {"ir15", SRIDX (1, 9, 0), 0}, {"int_pend", SRIDX (1, 9, 0), 0},
  {"ir16", SRIDX (1, 10, 0), 0}, {"sp_usr", SRIDX (1, 10, 0), 0},
  {"ir17", SRIDX (1, 10, 1), 0}, {"sp_priv", SRIDX (1, 10, 1), 0},
  {"ir18", SRIDX (1, 11, 0), 0}, {"int_pri", SRIDX (1, 11, 0), 0},
  {"ir19", SRIDX (1, 1, 2), 0}, {"int_ctrl", SRIDX (1, 1, 2), 0},
  {"ir20", SRIDX (1, 10, 2), 0}, {"sp_usr1", SRIDX (1, 10, 2), 0},
  {"ir21", SRIDX (1, 10, 3), 0}, {"sp_priv1", SRIDX (1, 10, 3), 0},
  {"ir22", SRIDX (1, 10, 4), 0}, {"sp_usr2", SRIDX (1, 10, 4), 0},
  {"ir23", SRIDX (1, 10, 5), 0}, {"sp_priv2", SRIDX (1, 10, 5), 0},
  {"ir24", SRIDX (1, 10, 6), 0}, {"sp_usr3", SRIDX (1, 10, 6), 0},
  {"ir25", SRIDX (1, 10, 7), 0}, {"sp_priv3", SRIDX (1, 10, 7), 0},
  {"ir26", SRIDX (1, 8, 1), 0}, {"int_mask2", SRIDX (1, 8, 1), 0},
  {"ir27", SRIDX (1, 9, 1), 0}, {"int_pend2", SRIDX (1, 9, 1), 0},
  {"ir28", SRIDX (1, 11, 1), 0}, {"int_pri2", SRIDX (1, 11, 1), 0},
  {"ir29", SRIDX (1, 9, 4), 0}, {"int_trigger", SRIDX (1, 9, 4), 0},
  {"ir30", SRIDX (1, 1, 3), 0},

  {"mr0", SRIDX (2, 0, 0), 0}, {"mmu_ctl", SRIDX (2, 0, 0), 0},
  {"mr1", SRIDX (2, 1, 0), 0}, {"l1_pptb", SRIDX (2, 1, 0), 0},
  {"mr2", SRIDX (2, 2, 0), 0}, {"tlb_vpn", SRIDX (2, 2, 0), 0},
  {"mr3", SRIDX (2, 3, 0), 0}, {"tlb_data", SRIDX (2, 3, 0), 0},
  {"mr4", SRIDX (2, 4, 0), 0}, {"tlb_misc", SRIDX (2, 4, 0), 0},
  {"mr5", SRIDX (2, 5, 0), 0}, {"vlpt_idx", SRIDX (2, 5, 0), 0},
  {"mr6", SRIDX (2, 6, 0), 0}, {"ilmb", SRIDX (2, 6, 0), 0},
  {"mr7", SRIDX (2, 7, 0), 0}, {"dlmb", SRIDX (2, 7, 0), 0},
  {"mr8", SRIDX (2, 8, 0), 0}, {"cache_ctl", SRIDX (2, 8, 0), 0},
  {"mr9", SRIDX (2, 9, 0), 0}, {"hsmp_saddr", SRIDX (2, 9, 0), 0},
  {"mr10", SRIDX (2, 9, 1), 0}, {"hsmp_eaddr", SRIDX (2, 9, 1), 0},
  {"mr11", SRIDX (2, 0, 1), 0}, {"bg_region", SRIDX (2, 0, 1), 0},

  {"pfr0", SRIDX (4, 0, 0), 0}, {"pfmc0", SRIDX (4, 0, 0), 0},
  {"pfr1", SRIDX (4, 0, 1), 0}, {"pfmc1", SRIDX (4, 0, 1), 0},
  {"pfr2", SRIDX (4, 0, 2), 0}, {"pfmc2", SRIDX (4, 0, 2), 0},
  {"pfr3", SRIDX (4, 1, 0), 0}, {"pfm_ctl", SRIDX (4, 1, 0), 0},

  {"dmar0", SRIDX (5, 0, 0), 0}, {"dma_cfg", SRIDX (5, 0, 0), 0},
  {"dmar1", SRIDX (5, 1, 0), 0}, {"dma_gcsw", SRIDX (5, 1, 0), 0},
  {"dmar2", SRIDX (5, 2, 0), 0}, {"dma_chnsel", SRIDX (5, 2, 0), 0},
  {"dmar3", SRIDX (5, 3, 0), 0}, {"dma_act", SRIDX (5, 3, 0), 0},
  {"dmar4", SRIDX (5, 4, 0), 0}, {"dma_setup", SRIDX (5, 4, 0), 0},
  {"dmar5", SRIDX (5, 5, 0), 0}, {"dma_isaddr", SRIDX (5, 5, 0), 0},
  {"dmar6", SRIDX (5, 6, 0), 0}, {"dma_esaddr", SRIDX (5, 6, 0), 0},
  {"dmar7", SRIDX (5, 7, 0), 0}, {"dma_tcnt", SRIDX (5, 7, 0), 0},
  {"dmar8", SRIDX (5, 8, 0), 0}, {"dma_status", SRIDX (5, 8, 0), 0},
  {"dmar9", SRIDX (5, 9, 0), 0}, {"dma_2dset", SRIDX (5, 9, 0), 0},
  {"dmar10", SRIDX (5, 9, 1), 0}, {"dma_2dsctl", SRIDX (5, 9, 1), 0},
  {"dmar11", SRIDX (5, 7, 1), 0}, {"dma_rcnt", SRIDX (5, 7, 1), 0},
  {"dmar12", SRIDX (5, 8, 1), 0}, {"dma_hstatus", SRIDX (5, 8, 1), 0},

  {"idr0", SRIDX (2, 15, 0), 0}, {"sdz_ctl", SRIDX (2, 15, 0), 0},
  {"idr1", SRIDX (2, 15, 1), 0}, {"n12misc_ctl", SRIDX (2, 15, 1), 0},
			      {"misc_ctl", SRIDX (2, 15, 1), 0},

  {"secur0", SRIDX (6, 0, 0), 0}, {"sfcr", SRIDX (6, 0, 0), 0},

  {"prusr_acc_ctl", SRIDX (4, 4, 0), 0},
  {"fucpr", SRIDX (4, 5, 0), 0}, {"fucop_ctl", SRIDX (4, 5, 0), 0},

  {"dr0", SRIDX (3, 0, 0), 0}, {"bpc0", SRIDX (3, 0, 0), 0},
  {"dr1", SRIDX (3, 0, 1), 0}, {"bpc1", SRIDX (3, 0, 1), 0},
  {"dr2", SRIDX (3, 0, 2), 0}, {"bpc2", SRIDX (3, 0, 2), 0},
  {"dr3", SRIDX (3, 0, 3), 0}, {"bpc3", SRIDX (3, 0, 3), 0},
  {"dr4", SRIDX (3, 0, 4), 0}, {"bpc4", SRIDX (3, 0, 4), 0},
  {"dr5", SRIDX (3, 0, 5), 0}, {"bpc5", SRIDX (3, 0, 5), 0},
  {"dr6", SRIDX (3, 0, 6), 0}, {"bpc6", SRIDX (3, 0, 6), 0},
  {"dr7", SRIDX (3, 0, 7), 0}, {"bpc7", SRIDX (3, 0, 7), 0},
  {"dr8", SRIDX (3, 1, 0), 0}, {"bpa0", SRIDX (3, 1, 0), 0},
  {"dr9", SRIDX (3, 1, 1), 0}, {"bpa1", SRIDX (3, 1, 1), 0},
  {"dr10", SRIDX (3, 1, 2), 0}, {"bpa2", SRIDX (3, 1, 2), 0},
  {"dr11", SRIDX (3, 1, 3), 0}, {"bpa3", SRIDX (3, 1, 3), 0},
  {"dr12", SRIDX (3, 1, 4), 0}, {"bpa4", SRIDX (3, 1, 4), 0},
  {"dr13", SRIDX (3, 1, 5), 0}, {"bpa5", SRIDX (3, 1, 5), 0},
  {"dr14", SRIDX (3, 1, 6), 0}, {"bpa6", SRIDX (3, 1, 6), 0},
  {"dr15", SRIDX (3, 1, 7), 0}, {"bpa7", SRIDX (3, 1, 7), 0},
  {"dr16", SRIDX (3, 2, 0), 0}, {"bpam0", SRIDX (3, 2, 0), 0},
  {"dr17", SRIDX (3, 2, 1), 0}, {"bpam1", SRIDX (3, 2, 1), 0},
  {"dr18", SRIDX (3, 2, 2), 0}, {"bpam2", SRIDX (3, 2, 2), 0},
  {"dr19", SRIDX (3, 2, 3), 0}, {"bpam3", SRIDX (3, 2, 3), 0},
  {"dr20", SRIDX (3, 2, 4), 0}, {"bpam4", SRIDX (3, 2, 4), 0},
  {"dr21", SRIDX (3, 2, 5), 0}, {"bpam5", SRIDX (3, 2, 5), 0},
  {"dr22", SRIDX (3, 2, 6), 0}, {"bpam6", SRIDX (3, 2, 6), 0},
  {"dr23", SRIDX (3, 2, 7), 0}, {"bpam7", SRIDX (3, 2, 7), 0},
  {"dr24", SRIDX (3, 3, 0), 0}, {"bpv0", SRIDX (3, 3, 0), 0},
  {"dr25", SRIDX (3, 3, 1), 0}, {"bpv1", SRIDX (3, 3, 1), 0},
  {"dr26", SRIDX (3, 3, 2), 0}, {"bpv2", SRIDX (3, 3, 2), 0},
  {"dr27", SRIDX (3, 3, 3), 0}, {"bpv3", SRIDX (3, 3, 3), 0},
  {"dr28", SRIDX (3, 3, 4), 0}, {"bpv4", SRIDX (3, 3, 4), 0},
  {"dr29", SRIDX (3, 3, 5), 0}, {"bpv5", SRIDX (3, 3, 5), 0},
  {"dr30", SRIDX (3, 3, 6), 0}, {"bpv6", SRIDX (3, 3, 6), 0},
  {"dr31", SRIDX (3, 3, 7), 0}, {"bpv7", SRIDX (3, 3, 7), 0},
  {"dr32", SRIDX (3, 4, 0), 0}, {"bpcid0", SRIDX (3, 4, 0), 0},
  {"dr33", SRIDX (3, 4, 1), 0}, {"bpcid1", SRIDX (3, 4, 1), 0},
  {"dr34", SRIDX (3, 4, 2), 0}, {"bpcid2", SRIDX (3, 4, 2), 0},
  {"dr35", SRIDX (3, 4, 3), 0}, {"bpcid3", SRIDX (3, 4, 3), 0},
  {"dr36", SRIDX (3, 4, 4), 0}, {"bpcid4", SRIDX (3, 4, 4), 0},
  {"dr37", SRIDX (3, 4, 5), 0}, {"bpcid5", SRIDX (3, 4, 5), 0},
  {"dr38", SRIDX (3, 4, 6), 0}, {"bpcid6", SRIDX (3, 4, 6), 0},
  {"dr39", SRIDX (3, 4, 7), 0}, {"bpcid7", SRIDX (3, 4, 7), 0},
  {"dr40", SRIDX (3, 5, 0), 0}, {"edm_cfg", SRIDX (3, 5, 0), 0},
  {"dr41", SRIDX (3, 6, 0), 0}, {"edmsw", SRIDX (3, 6, 0), 0},
  {"dr42", SRIDX (3, 7, 0), 0}, {"edm_ctl", SRIDX (3, 7, 0), 0},
  {"dr43", SRIDX (3, 8, 0), 0}, {"edm_dtr", SRIDX (3, 8, 0), 0},
  {"dr44", SRIDX (3, 9, 0), 0}, {"bpmtc", SRIDX (3, 9, 0), 0},
  {"dr45", SRIDX (3, 10, 0), 0}, {"dimbr", SRIDX (3, 10, 0), 0},
  {"dr46", SRIDX (3, 14, 0), 0}, {"tecr0", SRIDX (3, 14, 0), 0},
  {"dr47", SRIDX (3, 14, 1), 0}, {"tecr1", SRIDX (3, 14, 1), 0},
  {NULL,0 ,0}
};

static const keyword_t keyword_cp[] =
{
  {"cp0", 0, 0}, {"cp1", 1, 0}, {"cp2", 2, 0}, {"cp3", 3, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_cpr[] =
{
  {"cpr0", 0, 0}, {"cpr1", 1, 0}, {"cpr2", 2, 0}, {"cpr3", 3, 0}, {"cpr4", 4, 0},
  {"cpr5", 5, 0}, {"cpr6", 6, 0}, {"cpr7", 7, 0}, {"cpr8", 8, 0}, {"cpr9", 9, 0},
  {"cpr10", 10, 0}, {"cpr11", 11, 0}, {"cpr12", 12, 0}, {"cpr13", 13, 0},
  {"cpr14", 14, 0}, {"cpr15", 15, 0}, {"cpr16", 16, 0}, {"cpr17", 17, 0},
  {"cpr18", 18, 0}, {"cpr19", 19, 0}, {"cpr20", 20, 0}, {"cpr21", 21, 0},
  {"cpr22", 22, 0}, {"cpr23", 23, 0}, {"cpr24", 24, 0}, {"cpr25", 25, 0},
  {"cpr26", 26, 0}, {"cpr27", 27, 0}, {"cpr28", 28, 0}, {"cpr29", 29, 0},
  {"cpr30", 30, 0}, {"cpr31", 31, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_fsr[] =
{
  {"fs0", 0, 0}, {"fs1", 1, 0}, {"fs2", 2, 0}, {"fs3", 3, 0}, {"fs4", 4, 0},
  {"fs5", 5, 0}, {"fs6", 6, 0}, {"fs7", 7, 0}, {"fs8", 8, 0}, {"fs9", 9, 0},
  {"fs10", 10, 0}, {"fs11", 11, 0}, {"fs12", 12, 0}, {"fs13", 13, 0},
  {"fs14", 14, 0}, {"fs15", 15, 0}, {"fs16", 16, 0}, {"fs17", 17, 0},
  {"fs18", 18, 0}, {"fs19", 19, 0}, {"fs20", 20, 0}, {"fs21", 21, 0},
  {"fs22", 22, 0}, {"fs23", 23, 0}, {"fs24", 24, 0}, {"fs25", 25, 0},
  {"fs26", 26, 0}, {"fs27", 27, 0}, {"fs28", 28, 0}, {"fs29", 29, 0},
  {"fs30", 30, 0}, {"fs31", 31, 0}, {NULL, 0 ,0}
};

static const keyword_t keyword_fdr[] =
{
  {"fd0", 0, 0}, {"fd1", 1, 0}, {"fd2", 2, 0}, {"fd3", 3, 0}, {"fd4", 4, 0},
  {"fd5", 5, 0}, {"fd6", 6, 0}, {"fd7", 7, 0}, {"fd8", 8, 0}, {"fd9", 9, 0},
  {"fd10", 10, 0}, {"fd11", 11, 0}, {"fd12", 12, 0}, {"fd13", 13, 0},
  {"fd14", 14, 0}, {"fd15", 15, 0}, {"fd16", 16, 0}, {"fd17", 17, 0},
  {"fd18", 18, 0}, {"fd19", 19, 0}, {"fd20", 20, 0}, {"fd21", 21, 0},
  {"fd22", 22, 0}, {"fd23", 23, 0}, {"fd24", 24, 0}, {"fd25", 25, 0},
  {"fd26", 26, 0}, {"fd27", 27, 0}, {"fd28", 28, 0}, {"fd29", 29, 0},
  {"fd30", 30, 0}, {"fd31", 31, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_abdim[] =
{
  {"bi", 0, 0}, {"bim", 1, 0}, {"bd", 2, 0}, {"bdm", 3, 0},
  {"ai", 4, 0}, {"aim", 5, 0}, {"ad", 6, 0}, {"adm", 7, 0},
  {NULL, 0, 0}
};

static const keyword_t keyword_abm[] =
{
  {"b", 0, 0}, {"bm", 1, 0}, {"a", 4, 0}, {"am", 5, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_dtiton[] =
{
  {"iton", 1, 0}, {"ton", 3, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_dtitoff[] =
{
  {"itoff", 1, 0}, {"toff", 3, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_dpref_st[] =
{
  {"srd", 0, 0}, {"mrd", 1, 0}, {"swr", 2, 0}, {"mwr", 3, 0},
  {"pte", 4, 0}, {"clwr", 5, 0}, {NULL, 0, 0}
};

/* CCTL Ra, SubType */
static const keyword_t keyword_cctl_st0[] =
{
  {"l1d_ix_inval", 0X0, 0}, {"l1d_ix_wb", 0X1, 0}, {"l1d_ix_wbinval", 0X2, 0},
  {"l1d_va_fillck", 0XB, 0}, {"l1d_va_ulck", 0XC, 0}, {"l1i_ix_inval", 0X10, 0},
  {"l1i_va_fillck", 0X1B, 0}, {"l1i_va_ulck", 0X1C, 0},
  {NULL, 0, 0}
};

/* CCTL Ra, SubType, level */
static const keyword_t keyword_cctl_st1[] =
{
  {"l1d_va_inval", 0X8, 0}, {"l1d_va_wb", 0X9, 0},
  {"l1d_va_wbinval", 0XA, 0}, {"l1i_va_inval", 0X18, 0},
  {NULL, 0, 0}
};

/* CCTL Rt, Ra, SubType */
static const keyword_t keyword_cctl_st2[] =
{
  {"l1d_ix_rtag", 0X3, 0}, {"l1d_ix_rwd", 0X4, 0},
  {"l1i_ix_rtag", 0X13, 0}, {"l1i_ix_rwd", 0X14, 0},
  {NULL, 0, 0}
};

/* CCTL Rb, Ra, SubType */
static const keyword_t keyword_cctl_st3[] =
{
  {"l1d_ix_wtag", 0X5, 0}, {"l1d_ix_wwd", 0X6, 0},
  {"l1i_ix_wtag", 0X15, 0}, {"l1i_ix_wwd", 0X16, 0},
  {NULL, 0, 0}
};

/* CCTL L1D_INVALALL */
static const keyword_t keyword_cctl_st4[] =
{
  {"l1d_invalall", 0x7, 0}, {NULL, 0, 0}
};

/* CCTL L1D_WBALL, level */
static const keyword_t keyword_cctl_st5[] =
{
  {"l1d_wball", 0xf, 0}, {NULL, 0, 0}
};

static const keyword_t keyword_cctl_lv[] =
{
  {"1level", 0, 0}, {"alevel", 1, 0}, {"0", 0, 0}, {"1", 1, 0},
  {NULL, 0, 0},
};

static const keyword_t keyword_tlbop_st[] =
{
  {"trd", 0, 0}, {"targetread", 0, 0},
  {"twr", 1, 0}, {"targetwrite", 1, 0},
  {"rwr", 2, 0}, {"rwrite", 2, 0},
  {"rwlk", 3, 0}, {"rwritelock", 3, 0},
  {"unlk", 4, 0}, {"unlock", 4, 0},
  {"inv", 6, 0}, {"invalidate", 6, 0},
  {NULL, 0, 0},
  /* "pb" requries two operand and "flua" requires none.  */
  /* {"pb", 5, 0}, {"probe", 5, 0},
     {"flua", 7, 0}, {"flushall", 0}, */
};

static const keyword_t keyword_standby_st[] =
{
  {"no_wake_grant", 0, 0},
  {"wake_grant", 1, 0},
  {"wait_done", 2, 0},
  {"0", 0, 0},
  {"1", 1, 0},
  {"2", 2, 0},
  {"3", 3, 0},
  {NULL, 0, 0},
};
