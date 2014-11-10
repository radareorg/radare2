/* radare - LGPL - Copyright 2011 -- pancake<nopcode.org> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
enum
  {
    GPR_G0 = 0,
    GPR_G1 = 1,
    GPR_G2 = 2,
    GPR_G3 = 3,
    GPR_G4 = 4,
    GPR_G5 = 5,
    GPR_G6 = 6,
    GPR_G7 = 7,
    GPR_O0 = 8,
    GPR_O1 = 9,
    GPR_O2 = 10,
    GPR_O3 = 11,
    GPR_O4 = 12,
    GPR_O5 = 13,
    GPR_O6 = 14,
    GPR_O7 = 15,
    GPR_L0 = 16,
    GPR_L1 = 17,
    GPR_L2 = 18,
    GPR_L3 = 19,
    GPR_L4 = 20,
    GPR_L5 = 21,
    GPR_L6 = 22,
    GPR_L7 = 23,
    GPR_I0 = 24,
    GPR_I1 = 25,
    GPR_I2 = 26,
    GPR_I3 = 27,
    GPR_I4 = 28,
    GPR_I5 = 29,
    GPR_I6 = 30,
    GPR_I7 = 31,
  };

const char * gpr_regs[] = {"g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7", 
			   "o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7", 
			   "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", 
			   "i0", "i1", "i2", "i3", "i4", "i5", "i6","i7"};

enum 
  {
    ICC_A = 0x8,
    ICC_CC = 0xd,
    ICC_CS = 0x5,
    ICC_E = 0x1,
    ICC_G = 0xa,
    ICC_GE = 0xb,
    ICC_GU = 0xc,
    ICC_L = 0x3,
    ICC_LE = 0x2,
    ICC_LEU = 0x4,
    ICC_N = 0x0,
    ICC_NE = 0x9,
    ICC_NEG = 0x6,
    ICC_POS = 0xe,
    ICC_VC = 0xf,
    ICC_VS = 0x7,
  };

enum
  {
    FCC_A = 0x8,
    FCC_E = 0x9,
    FCC_G = 0x6,
    FCC_GE = 0xb,
    FCC_L = 0x4,
    FCC_LE = 0xd,
    FCC_LG = 0x2,
    FCC_N = 0x0,
    FCC_NE = 0x1,
    FCC_O = 0xf,
    FCC_U = 0x7,
    FCC_UE = 0xa,
    FCC_UG = 0x5,
    FCC_UGE = 0xc,
    FCC_UL = 0x3,
    FCC_ULE = 0xe,
  };
/* Define some additional conditions that are nor mapable to
   the existing R_ANAL_COND* ones and need to be handled in a
   special way. */
enum
  {
    R_ANAL_COND_ALWAYS = -1,
    R_ANAL_COND_NEVER = -2,
    R_ANAL_COND_UNKNOWN = -3,
  };

static int
icc_to_r_cond(const int cond)
{
  /* we treat signed and unsigned the same here */
  switch(cond)
    {
    case ICC_A:
      return R_ANAL_COND_ALWAYS;
    case ICC_CC:
      return R_ANAL_COND_GE;
    case ICC_CS:
      return R_ANAL_COND_LT;
    case ICC_E:
      return R_ANAL_COND_EQ;
    case ICC_G:
      return R_ANAL_COND_GT;
    case ICC_GE:
      return R_ANAL_COND_GE;
    case ICC_GU:
      return R_ANAL_COND_GT;
    case ICC_L:
      return R_ANAL_COND_LT;
    case ICC_LE:
      return R_ANAL_COND_LE;
    case ICC_LEU:
      return R_ANAL_COND_LE;
    case ICC_N:
      return R_ANAL_COND_NEVER;
    case ICC_NE:
      return R_ANAL_COND_NE;
    case ICC_NEG:
    case ICC_POS:
    case ICC_VC:
    case ICC_VS:
    default:
      return R_ANAL_COND_UNKNOWN;
    }
}

static int
fcc_to_r_cond(const int cond)
{
  switch(cond)
    {
    case FCC_A:
      return R_ANAL_COND_ALWAYS;
    case FCC_E:
      return R_ANAL_COND_EQ;
    case FCC_G:
      return R_ANAL_COND_GT;
    case FCC_GE:
      return R_ANAL_COND_GE;
    case FCC_L:
      return R_ANAL_COND_LT;
    case FCC_LE:
      return R_ANAL_COND_LE;
    case FCC_LG:
      return R_ANAL_COND_NE;
    case FCC_N:
      return R_ANAL_COND_NEVER;
    case FCC_NE:
      return R_ANAL_COND_NE;
    case FCC_O:
    case FCC_U:
    case FCC_UE:
    case FCC_UG:
    case FCC_UGE:
    case FCC_UL:
    case FCC_ULE:
    default:
      return R_ANAL_COND_UNKNOWN;
    }
}

#define X_OP(i) (((i) >> 30) & 0x3)
#define X_OP2(i) (((i) >> 22) & 0x7)
#define X_OP3(i) (((i) >> 19) & 0x3f)
#define X_COND(i) (((i) >> 25) & 0x1f)

#define X_RD(i)      (((i) >> 25) & 0x1f)
#define X_RS1(i)     (((i) >> 14) & 0x1f)
#define X_LDST_I(i)  (((i) >> 13) & 1)
#define X_ASI(i)     (((i) >> 5) & 0xff)
#define X_RS2(i)     (((i) >> 0) & 0x1f)
#define X_IMM(i,n)   (((i) >> 0) & ((1 << (n)) - 1))
#define X_SIMM(i,n)  SEX (X_IMM ((i), (n)), (n))
#define X_DISP22(i)  (((i) >> 0) & 0x3fffff)
#define X_IMM22(i)   X_DISP22 (i)
#define X_DISP30(i)  (((i) >> 0) & 0x3fffffff)

/* These are for v9.  */
#define X_DISP16(i)  (((((i) >> 20) & 3) << 14) | (((i) >> 0) & 0x3fff))
#define X_DISP19(i)  (((i) >> 0) & 0x7ffff)
#define X_MEMBAR(i)  ((i) & 0x7f)

enum
  {
    OP_0 = 0,
    OP_1 = 1,
    OP_2 = 2,
    OP_3 = 3,
  };

enum
  {
    OP2_ILLTRAP = 0,
    OP2_BPcc = 1,
    OP2_Bicc = 2,
    OP2_BPr = 3,
    OP2_SETHI = 4,
    OP2_FBPfcc = 5,
    OP2_FBfcc = 6,
    OP2_INV = 7,
  };

enum
  {
    OP32_ADD = 0x00,
    OP32_ADDcc = 0x10,
    OP32_TADDcc = 0x20,
    OP32_WRY = 0x30, /* or WRCCR WRASI WRASR WRFPRS SIR */
    OP32_AND = 0x01,
    OP32_ANDcc = 0x11,
    OP32_TSUBcc = 0x21,
    OP32_SAVED = 0x31, /* or RESTORED */
    OP32_OR = 0x02,
    OP32_ORcc = 0x12,
    OP32_TADDccTV = 0x22,
    OP32_WRPR = 0x32,
    OP32_XOR = 0x03,
    OP32_XORcc = 0x13,
    OP32_TSUBccTV = 0x23,
    OP32_SUB = 0x04,
    OP32_SUBcc = 0x14,
    OP32_MULSccD = 0x24,
    OP32_FPop1 = 0x34,
    OP32_ANDN = 0x05,
    OP32_ANDNcc = 0x15,
    OP32_SLL = 0x25, /* or SLLX */
    OP32_FPop2 = 0x35,
    OP32_ORN = 0x06,
    OP32_ORNcc = 0x16,
    OP32_SRL = 0x26, /* or SLRX */
    OP32_XNOR = 0x07,
    OP32_XNORcc = 0x17,
    OP32_SRA = 0x27, /* or SRAX */
    OP32_ADDC = 0x08,
    OP32_ADDCcc = 0x18,
    OP32_RDY = 0x28, /* or RDCCR RDASI RDTICK RDPC RDFPRS RDASR
		       MEMBAR STBAR  */
    OP32_JMPL = 0x38,
    OP32_MULX = 0x09,
    OP32_RETURN = 0x39,
    OP32_UMUL = 0x0a,
    OP32_UMULcc = 0x1a,
    OP32_RDPR = 0x2a,
    OP32_Tcc = 0x3a,
    OP32_SMULD = 0x0b,
    OP32_SMULcc = 0x1b,
    OP32_FLUSHW = 0x2b,
    OP32_FLUSH = 0x3b,
    OP32_SUBC = 0x0c,
    OP32_SUBCcc = 0x1c,
    OP32_MOVcc = 0x2c,
    OP32_SAVE = 0x3c,
    OP32_UDIVX = 0x0d,
    OP32_SDIVX = 0x2d,
    OP32_RESTORE = 0x3d,
    OP32_UDIV = 0x0e,
    OP32_UDIVcc = 0x1e,
    OP32_POPC = 0x2e,
    OP32_DONE = 0x3e, /* or RETRY */
    OP32_SDIV = 0x0f,
    OP32_SDIVcc = 0x1f,
    OP32_MOVr = 0x2f,
    /* always invalid */
    OP32_INV1 = 0x33,
    OP32_INV2 = 0x19,
    OP32_INV3 = 0x29,
    OP32_INV4 = 0x1d,
    OP32_INV5 = 0x3f,
    /* invalid under certain conditions */
    OP32_CONDINV1 = 0x30,
    OP32_CONDINV2 = 0x28,
    OP32_CONDINV3 = 0x2e,
  };

enum
  {
    OP33_INV1 = 0x31,
    OP33_INV2 = 0x35,
    OP33_INV3 = 0x28,
    OP33_INV4 = 0x38,
    OP33_INV5 = 0x29,
    OP33_INV6 = 0x39,
    OP33_INV7 = 0x2a,
    OP33_INV8 = 0x3a,
    OP33_INV9 = 0x2b,
    OP33_INV10 = 0x3b,
    OP33_INV11 = 0x0c,
    OP33_INV12 = 0x1c,
    OP33_INV13 = 0x2c,
    OP33_INV14 = 0x2e,
    OP33_INV15 = 0x2f,
    OP33_INV16 = 0x3f,
  };    

static st64
get_immed_sgnext(const ut64 insn, const ut8 nbit)
{
  const ut64 mask = ~((1 << (nbit + 1)) - 1);
  return (st64) ((insn & ~mask)
		 | (((insn & (1 << nbit)) >> nbit) * mask));
}

static RAnalValue *
value_fill_addr_pc_disp(const ut64 addr, const st64 disp)
{
  RAnalValue *val = r_anal_value_new();
  val->base = addr + disp;
  return val;
}

static RAnalValue *
value_fill_addr_reg_regdelta(RAnal const * const anal,
			     const int ireg, const int iregdelta)
{
  RAnalValue *val = r_anal_value_new();
  val->reg = r_reg_get(anal->reg, gpr_regs[ireg], R_REG_TYPE_GPR);
  val->reg = r_reg_get(anal->reg, gpr_regs[iregdelta], R_REG_TYPE_GPR);
  return val;
}

static RAnalValue *
value_fill_addr_reg_disp(RAnal const * const anal,
			     const int ireg, const st64 disp)
{
  RAnalValue *val = r_anal_value_new();
  val->reg = r_reg_get(anal->reg, gpr_regs[ireg], R_REG_TYPE_GPR);
  val->delta = disp;
  return val;
}

static void
anal_call(RAnalOp *op, const ut32 insn, const ut64 addr)
{
  const st64 disp = (get_immed_sgnext(insn, 29) * 4);
  
  op->type = R_ANAL_OP_TYPE_CALL;
  op->dst = value_fill_addr_pc_disp(addr, disp);
  op->jump = addr + disp;
  op->fail = addr + 4;
}

static void
anal_jmpl(RAnal const * const anal, RAnalOp *op, 
	  const ut32 insn, const ut64 addr)
{
  st64 disp = 0;
  if(X_LDST_I(insn))
    disp = get_immed_sgnext(insn, 12);
  
  if(X_RD(insn) == GPR_O7)
    {
      op->type = R_ANAL_OP_TYPE_UCALL;
      op->fail = addr + 4;
    }
  else if(X_RD(insn) == GPR_G0
	  && X_LDST_I(insn) == 1
	  && (X_RS1(insn) == GPR_I7 || X_RS1(insn) == GPR_O7)
	  && disp == 8)
    {
      op->type = R_ANAL_OP_TYPE_RET;
      op->eob = R_TRUE;
      return;
    }
  else
    {
      op->type = R_ANAL_OP_TYPE_UJMP;
      op->eob = R_TRUE;
    }
  
  if(X_LDST_I(insn) == 0)
    {
      op->dst = value_fill_addr_reg_regdelta(anal, X_RS1(insn), X_RS2(insn));
    }
  else
    {
      op->dst = value_fill_addr_reg_disp(anal, X_RS1(insn), disp);
    }
}

static void
anal_branch(RAnalOp *op, const ut32 insn, const ut64 addr)
{
  st64 disp = 0;
  int r_cond = 0;
  op->eob = R_TRUE;

  /* handle the conditions */
  if(X_OP2(insn) == OP2_Bicc || X_OP2(insn) == OP2_BPcc)
    {
      r_cond = icc_to_r_cond (X_COND(insn));
    }
  else if(X_OP2(insn) == OP2_FBfcc || X_OP2(insn) == OP2_FBPfcc)
    {
      r_cond = fcc_to_r_cond (X_COND(insn));
    }
  else if(X_OP2(insn) == OP2_BPr)
    {
      r_cond = R_ANAL_COND_UNKNOWN;
    }

  if(r_cond == R_ANAL_COND_ALWAYS)
    {
      op->type = R_ANAL_OP_TYPE_JMP;
    }
  else if(r_cond == R_ANAL_COND_NEVER)
    {
      op->type = R_ANAL_OP_TYPE_NOP;
      return;
    }
  else
    {
      op->type = R_ANAL_OP_TYPE_CJMP;
      op->fail = addr + 4;
    }

 
  /* handle displacement */
  if (X_OP2 (insn) == OP2_Bicc || X_OP2 (insn) == OP2_FBfcc)
    {
      disp = get_immed_sgnext(insn, 21) * 4;
    }
  else if (X_OP2(insn) == OP2_BPcc || X_OP2 (insn) == OP2_FBPfcc)
    {
      disp = get_immed_sgnext (insn, 18) * 4;
    }
  else if (X_OP2(insn) == OP2_BPr)
    {
      disp = get_immed_sgnext (X_DISP16 (insn), 15) * 4;
    }
  op->dst = value_fill_addr_pc_disp (addr, disp);
  op->jump = addr + disp;
}

// TODO: this implementation is just a fast hack. needs to be rewritten and completed
static int sparc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
  int sz = 4;
  ut32 insn;
  
  memset (op, 0, sizeof (RAnalOp));
  op->family = R_ANAL_OP_FAMILY_CPU;
  op->addr = addr;
  op->size = sz;
  op->jump = op->fail = -1;
  op->ptr = op->val = -1;

  if(LIL_ENDIAN)
    {
      ((char*)&insn)[0] = data[3];
      ((char*)&insn)[1] = data[2];
      ((char*)&insn)[2] = data[1];
      ((char*)&insn)[3] = data[0];
    }
  else
    {
      memcpy(&insn, data, sz);
    }

	
  if(X_OP(insn) == OP_0)
    {
      switch(X_OP2(insn))
	{
	case OP2_ILLTRAP:
	case OP2_INV:
	  op->type = R_ANAL_OP_TYPE_ILL;
	  sz = 0; /* make r_core_anal_bb stop */
	  break;
	case OP2_BPcc:
	case OP2_Bicc:
	case OP2_BPr:
	case OP2_FBPfcc:
	case OP2_FBfcc:
	  anal_branch(op, insn, addr);
	  break;
	}
    }
  else if(X_OP(insn) == OP_1)
    {
      anal_call(op, insn, addr);
    }
  else if(X_OP(insn) == OP_2)
    {
      switch(X_OP3(insn))
	{
	case OP32_INV1:
	case OP32_INV2:
	case OP32_INV3:
	case OP32_INV4:
	case OP32_INV5:
	  op->type = R_ANAL_OP_TYPE_ILL;
	  sz = 0; /* make r_core_anal_bb stop */
	  break;
	case OP32_CONDINV1:
	  if(X_RD(insn) == 1)
	    {
	      op->type = R_ANAL_OP_TYPE_ILL;
	      sz = 0; /* make r_core_anal_bb stop */
	    }
	  break;
	case OP32_CONDINV2:
	  if(X_RS1(insn) == 1)
	    {
	      op->type = R_ANAL_OP_TYPE_ILL;
	      sz = 0; /* make r_core_anal_bb stop */
	    }
	  break;
	case OP32_CONDINV3:
	  if(X_RS1(insn) != 0)
	    {
	      op->type = R_ANAL_OP_TYPE_ILL;
	      sz = 0; /* make r_core_anal_bb stop */
	    }
	  break;
	  
	case OP32_JMPL:
	  anal_jmpl(anal, op, insn, addr);
	  break;
	}
    }
  else if(X_OP(insn) == OP_3)
    {
      switch(X_OP3(insn))
	{
	case OP33_INV1:
	case OP33_INV2:
	case OP33_INV3:
	case OP33_INV4:
	case OP33_INV5:
	case OP33_INV6:
	case OP33_INV7:
	case OP33_INV8:
	case OP33_INV9:
	case OP33_INV10:
	case OP33_INV11:
	case OP33_INV12:
	case OP33_INV13:
	case OP33_INV14:
	case OP33_INV15:
	case OP33_INV16:
	  op->type = R_ANAL_OP_TYPE_ILL;
	  sz = 0; /* make r_core_anal_bb stop */
	  break;
	}
    }

  return sz;
}

static int set_reg_profile(RAnal *anal) 
{
  /* As far as I can see, sparc v9 register and instruction set
     don't depened  on bits of the running application.
     But: They depend on the bits of the consuming application,
     that is the bits radare had been compiled with. 
     See sys/procfs_isa.h on a Solaris10 Sparc machine and 
     'man 4 core' for reference.
  */
  const char *p = "=pc	pc\n"
	"=sp	o6\n"
	"=bp	i6\n"
	/* prgregset_t for _LP64 */
	"gpr	g0	.64	0	0\n"
	"gpr	g1	.64	8	0\n"
	"gpr	g2	.64	16	0\n"
	"gpr	g3	.64	24	0\n"
	"gpr	g4	.64	32	0\n"
	"gpr	g5	.64	40	0\n"
	"gpr	g6	.64	48	0\n"
	"gpr	g7	.64	56	0\n"
	"gpr	o0	.64	64	0\n"
	"gpr	o1	.64	72	0\n"
	"gpr	o2	.64	80	0\n"
	"gpr	o3	.64	88	0\n"
	"gpr	o4	.64	96	0\n"
	"gpr	o5	.64	104	0\n"
	"gpr	o6	.64	112	0\n"
	"gpr	o7	.64	120	0\n"
	"gpr	l0	.64	128	0\n"
	"gpr	l1	.64	136	0\n"
	"gpr	l2	.64	144	0\n"
	"gpr	l3	.64	152	0\n"
	"gpr	l4	.64	160	0\n"
	"gpr	l5	.64	168	0\n"
	"gpr	l6	.64	176	0\n"
	"gpr	l7	.64	184	0\n"
	"gpr	i0	.64	192	0\n"
	"gpr	i1	.64	200	0\n"
	"gpr	i2	.64	208	0\n"
	"gpr	i3	.64	216	0\n"
	"gpr	i4	.64	224	0\n"
	"gpr	i5	.64	232	0\n"
	"gpr	i6	.64	240	0\n"
	"gpr	i7	.64	248	0\n"
	"gpr	ccr	.64	256	0\n"
	"gpr	pc	.64	264	0\n"
	"gpr	ncp	.64	272	0\n"
	"gpr	y	.64	280	0\n"
	"gpr	asi	.64	288	0\n"
	"gpr	fprs	.64	296	0\n"
	/* beginning of prfpregset_t for __sparcv9 */
	"fpu	sf0	.32	304	0\n"
	"fpu	sf1	.32	308	0\n"
	"fpu	sf2	.32	312	0\n"
	"fpu	sf3	.32	316	0\n"
	"fpu	sf4	.32	320	0\n"
	"fpu	sf5	.32	324	0\n"
	"fpu	sf6	.32	328	0\n"
	"fpu	sf7	.32	332	0\n"
	"fpu	sf8	.32	336	0\n"
	"fpu	sf9	.32	340	0\n"
	"fpu	sf10	.32	344	0\n"
	"fpu	sf11	.32	348	0\n"
	"fpu	sf12	.32	352	0\n"
	"fpu	sf13	.32	356	0\n"
	"fpu	sf14	.32	360	0\n"
	"fpu	sf15	.32	364	0\n"
	"fpu	sf16	.32	368	0\n"
	"fpu	sf17	.32	372	0\n"
	"fpu	sf18	.32	376	0\n"
	"fpu	sf19	.32	380	0\n"
	"fpu	sf20	.32	384	0\n"
	"fpu	sf21	.32	388	0\n"
	"fpu	sf22	.32	392	0\n"
	"fpu	sf23	.32	396	0\n"
	"fpu	sf24	.32	400	0\n"
	"fpu	sf25	.32	404	0\n"
	"fpu	sf26	.32	408	0\n"
	"fpu	sf27	.32	412	0\n"
	"fpu	sf28	.32	416	0\n"
	"fpu	sf29	.32	420	0\n"
	"fpu	sf30	.32	424	0\n"
	"fpu	sf31	.32	428	0\n"
	"fpu	df0	.64	304	0\n"	/* sf0 sf1 */
	"fpu	df2	.64	312	0\n"	/* sf2 sf3 */
	"fpu	df4	.64	320	0\n"	/* sf4 sf5 */
	"fpu	df6	.64	328	0\n"	/* sf6 sf7 */
	"fpu	df8	.64	336	0\n"	/* sf8 sf9 */
	"fpu	df10	.64	344	0\n"	/* sf10 sf11 */
	"fpu	df12	.64	352	0\n"	/* sf12 sf13 */
	"fpu	df14	.64	360	0\n"	/* sf14 sf15 */
	"fpu	df16	.64	368	0\n"	/* sf16 sf17 */
	"fpu	df18	.64	376	0\n"	/* sf18 sf19 */
	"fpu	df20	.64	384	0\n"	/* sf20 sf21 */
	"fpu	df22	.64	392	0\n"	/* sf22 sf23 */
	"fpu	df24	.64	400	0\n"	/* sf24 sf25 */
	"fpu	df26	.64	408	0\n"	/* sf26 sf27 */
	"fpu	df28	.64	416	0\n"	/* sf28 sf29 */
	"fpu	df30	.64	424	0\n"	/* sf30 sf31 */
	"fpu	df32	.64	432	0\n"
	"fpu	df34	.64	440	0\n"
	"fpu	df36	.64	448	0\n"
	"fpu	df38	.64	456	0\n"
	"fpu	df40	.64	464	0\n"
	"fpu	df42	.64	472	0\n"
	"fpu	df44	.64	480	0\n"
	"fpu	df46	.64	488	0\n"
	"fpu	df48	.64	496	0\n"
	"fpu	df50	.64	504	0\n"
	"fpu	df52	.64	512	0\n"
	"fpu	df54	.64	520	0\n"
	"fpu	df56	.64	528	0\n"
	"fpu	df58	.64	536	0\n"
	"fpu	df60	.64	544	0\n"
	"fpu	df62	.64	552	0\n"
	"fpu	qf0	.128	304	0\n"	/* sf0 sf1 sf2 sf3 */
	"fpu	qf4	.128	320	0\n"	/* sf4 sf5 sf6 sf7 */
	"fpu	qf8	.128	336	0\n"	/* sf8 sf9 sf10 sf11 */
	"fpu	qf12	.128	352	0\n"	/* sf12 sf13 sf14 sf15 */
	"fpu	qf16	.128	368	0\n"	/* sf16 sf17 sf18 sf19 */
	"fpu	qf20	.128	384	0\n"	/* sf20 sf21 sf22 sf23 */
	"fpu	qf24	.128	400	0\n"	/* sf24 sf25 sf26 sf27 */
	"fpu	qf28	.128	416	0\n"	/* sf28 sf29 sf30 sf31 */
	"fpu	qf32	.128	432	0\n"	/* df32 df34 */
	"fpu	qf36	.128	448	0\n"	/* df36 df38 */
	"fpu	qf40	.128	464	0\n"	/* df40 df42 */
	"fpu	qf44	.128	480	0\n"	/* df44 df46 */
	"fpu	qf48	.128	496	0\n"	/* df48 df50 */
	"fpu	qf52	.128	512	0\n"	/* df52 df54 */
	"fpu	qf56	.128	528	0\n"	/* df56 df68 */
	"fpu	qf60	.128	544	0\n"	/* df60 df62 */
	"gpr	fsr	.64	560	0\n";	/* note that
						   we've left out the filler */
	return r_reg_set_profile_string (anal->reg, p);
}


RAnalPlugin r_anal_plugin_sparc_gnu = {
	.name = "sparc.gnu",
	.desc = "SPARC analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_SPARC,
	.bits = 32 | 64,
	.init = NULL,
	.fini = NULL,
	.op = &sparc_op,
	.set_reg_profile = set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_sparc_gnu
};
#endif
