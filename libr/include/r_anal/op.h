#ifndef R2_ANAL_OP_H
#define R2_ANAL_OP_H

#include <r_reg.h>
#include <r_anal/hint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	R_ANAL_OP_PREFIX_COND     = 1,
	R_ANAL_OP_PREFIX_REP      = 1<<1,
	R_ANAL_OP_PREFIX_REPNE    = 1<<2,
	R_ANAL_OP_PREFIX_LOCK     = 1<<3,
	R_ANAL_OP_PREFIX_LIKELY   = 1<<4,
	R_ANAL_OP_PREFIX_UNLIKELY = 1<<5
	/* TODO: add segment override typemods? */
} RAnalOpPrefix;

typedef enum {
	R_ANAL_STACK_NULL = 0,
	R_ANAL_STACK_NOP,
	R_ANAL_STACK_INC,
	R_ANAL_STACK_GET,
	R_ANAL_STACK_SET,
	R_ANAL_STACK_RESET,
	R_ANAL_STACK_ALIGN,
} RAnalStackOp;
typedef enum {
	R_ANAL_ACC_UNKNOWN = 0,
	R_ANAL_ACC_R = (1 << 0),
	R_ANAL_ACC_W = (1 << 1),
} RAnalValueAccess;

typedef enum {
	R_ANAL_VAL_REG,
	R_ANAL_VAL_MEM,
	R_ANAL_VAL_IMM,
} RAnalValueType;

// base + reg + regdelta * mul + delta
typedef struct r_anal_value_t {
	RAnalValueType type;
	RAnalValueAccess access;
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	// XXX can be invalidated if regprofile changes causing an UAF
	RRegItem *seg; // segment selector register
	RRegItem *reg; // register item reference
	RRegItem *regdelta; // register index used
} RAnalValue;

typedef enum {
	R_ANAL_OP_DIR_READ = 1,
	R_ANAL_OP_DIR_WRITE = 2,
	R_ANAL_OP_DIR_EXEC = 4,
	R_ANAL_OP_DIR_REF = 8,
} RAnalOpDirection;

typedef enum {
	R_ANAL_OP_FAMILY_UNKNOWN = -1,
	R_ANAL_OP_FAMILY_CPU = 0,	/* normal cpu instruction */
	R_ANAL_OP_FAMILY_FPU,    	/* fpu (floating point) */
	R_ANAL_OP_FAMILY_MMX,    	/* multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_SSE,    	/* extended multimedia instruction (packed data) */
	R_ANAL_OP_FAMILY_PRIV,   	/* privileged instruction */
	R_ANAL_OP_FAMILY_CRYPTO, 	/* cryptographic instructions */
	R_ANAL_OP_FAMILY_THREAD, 	/* thread/lock/sync instructions */
	R_ANAL_OP_FAMILY_VIRT,   	/* virtualization instructions */
	R_ANAL_OP_FAMILY_SECURITY,	/* security instructions */
	R_ANAL_OP_FAMILY_IO,     	/* IO instructions (i.e. IN/OUT) */
	R_ANAL_OP_FAMILY_LAST
} RAnalOpFamily;

#if 0
On x86 according to Wikipedia

	Prefix group 1
	0xF0: LOCK prefix
	0xF2: REPNE/REPNZ prefix
	0xF3: REP or REPE/REPZ prefix
	Prefix group 2
	0x2E: CS segment override
	0x36: SS segment override
	0x3E: DS segment override
	0x26: ES segment override
	0x64: FS segment override
	0x65: GS segment override
	0x2E: Branch not taken    (hinting)
	0x3E: Branch taken
	Prefix group 3
	0x66: Operand-size override prefix
	Prefix group 4
	0x67: Address-size override prefix
#endif

// XXX: this definition is plain wrong. use enum or empower bits
#define R_ANAL_OP_TYPE_MASK 0x8000ffff
#define R_ANAL_OP_HINT_MASK 0xf0000000
typedef enum {
	R_ANAL_OP_TYPE_COND  = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by anal_java.. must be updated
	R_ANAL_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	R_ANAL_OP_TYPE_MEM   = 0x20000000, // TODO must be moved to prefix?
	R_ANAL_OP_TYPE_REG   = 0x10000000, // operand is a register
	R_ANAL_OP_TYPE_IND   = 0x08000000, // operand is indirect
	R_ANAL_OP_TYPE_NULL  = 0,
	R_ANAL_OP_TYPE_JMP   = 1,  /* mandatory jump */
	R_ANAL_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	R_ANAL_OP_TYPE_RJMP  = R_ANAL_OP_TYPE_UJMP| R_ANAL_OP_TYPE_REG,
	R_ANAL_OP_TYPE_UCJMP = R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_COND, /* conditional unknown jump */
	R_ANAL_OP_TYPE_IJMP  = R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND,
	R_ANAL_OP_TYPE_IRJMP = R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_IND,
	R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_COND,  /* conditional jump */
	R_ANAL_OP_TYPE_MJMP  = R_ANAL_OP_TYPE_JMP | R_ANAL_OP_TYPE_MEM,   /* memory jump */
	R_ANAL_OP_TYPE_RCJMP = R_ANAL_OP_TYPE_CJMP | R_ANAL_OP_TYPE_REG,  /* conditional jump register */
	R_ANAL_OP_TYPE_MCJMP = R_ANAL_OP_TYPE_CJMP | R_ANAL_OP_TYPE_MEM,  /* memory conditional jump */
	R_ANAL_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	R_ANAL_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	R_ANAL_OP_TYPE_RCALL = R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_REG,
	R_ANAL_OP_TYPE_ICALL = R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_IND,
	R_ANAL_OP_TYPE_IRCALL= R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_IND,
	R_ANAL_OP_TYPE_CCALL = R_ANAL_OP_TYPE_CALL | R_ANAL_OP_TYPE_COND, /* conditional call to subroutine */
	R_ANAL_OP_TYPE_UCCALL= R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_COND, /* conditional unknown call */
	R_ANAL_OP_TYPE_RET   = 5, /* returns from subroutine */
	R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET, /* conditional return from subroutine */
	R_ANAL_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	R_ANAL_OP_TYPE_UNK   = 7, /* unknown opcode type */
	R_ANAL_OP_TYPE_NOP   = 8, /* does nothing */
	R_ANAL_OP_TYPE_MOV   = 9, /* register move */
	R_ANAL_OP_TYPE_CMOV  = 9 | R_ANAL_OP_TYPE_COND, /* conditional move */
	R_ANAL_OP_TYPE_TRAP  = 10, /* it's a trap! */
	R_ANAL_OP_TYPE_SWI   = 11,  /* syscall, software interrupt */
	R_ANAL_OP_TYPE_CSWI  = 11 | R_ANAL_OP_TYPE_COND,  /* syscall, software interrupt */
	R_ANAL_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	R_ANAL_OP_TYPE_RPUSH = R_ANAL_OP_TYPE_UPUSH | R_ANAL_OP_TYPE_REG, /* push register */
	R_ANAL_OP_TYPE_PUSH  = 13,  /* push value into stack */
	R_ANAL_OP_TYPE_POP   = 14,   /* pop value from stack to register */
	R_ANAL_OP_TYPE_CMP   = 15,  /* compare something */
	R_ANAL_OP_TYPE_ACMP  = 16,  /* compare via and */
	R_ANAL_OP_TYPE_ADD   = 17,
	R_ANAL_OP_TYPE_SUB   = 18,
	R_ANAL_OP_TYPE_IO    = 19,
	R_ANAL_OP_TYPE_MUL   = 20,
	R_ANAL_OP_TYPE_DIV   = 21,
	R_ANAL_OP_TYPE_SHR   = 22,
	R_ANAL_OP_TYPE_SHL   = 23,
	R_ANAL_OP_TYPE_SAL   = 24,
	R_ANAL_OP_TYPE_SAR   = 25,
	R_ANAL_OP_TYPE_OR    = 26,
	R_ANAL_OP_TYPE_AND   = 27,
	R_ANAL_OP_TYPE_XOR   = 28,
	R_ANAL_OP_TYPE_NOR   = 29,
	R_ANAL_OP_TYPE_NOT   = 30,
	R_ANAL_OP_TYPE_STORE = 31,  /* store from register to memory */
	R_ANAL_OP_TYPE_LOAD  = 32,  /* load from memory to register */
	R_ANAL_OP_TYPE_LEA   = 33, /* TODO add ulea */
	R_ANAL_OP_TYPE_LEAVE = 34,
	R_ANAL_OP_TYPE_ROR   = 35,
	R_ANAL_OP_TYPE_ROL   = 36,
	R_ANAL_OP_TYPE_XCHG  = 37,
	R_ANAL_OP_TYPE_MOD   = 38,
	R_ANAL_OP_TYPE_SWITCH = 39,
	R_ANAL_OP_TYPE_CASE = 40,
	R_ANAL_OP_TYPE_LENGTH = 41,
	R_ANAL_OP_TYPE_CAST = 42,
	R_ANAL_OP_TYPE_NEW = 43,
	R_ANAL_OP_TYPE_ABS = 44,
	R_ANAL_OP_TYPE_CPL = 45,	/* complement */
	R_ANAL_OP_TYPE_CRYPTO = 46,
	R_ANAL_OP_TYPE_SYNC = 47,
	//R_ANAL_OP_TYPE_DEBUG = 43, // monitor/trace/breakpoint
#if 0
	R_ANAL_OP_TYPE_PRIV = 40, /* privileged instruction */
	R_ANAL_OP_TYPE_FPU = 41, /* floating point stuff */
#endif
} _RAnalOpType;


/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	R_ANAL_COND_AL = 0,        // Always executed (no condition)
	R_ANAL_COND_EQ,            // Equal
	R_ANAL_COND_NE,            // Not equal
	R_ANAL_COND_GE,            // Greater or equal
	R_ANAL_COND_GT,            // Greater than
	R_ANAL_COND_LE,            // Less or equal
	R_ANAL_COND_LT,            // Less than
	R_ANAL_COND_NV,            // Never executed             must be a nop? :D
	R_ANAL_COND_HS,            // Carry set                  >, ==, or unordered
	R_ANAL_COND_LO,            // Carry clear                Less than
	R_ANAL_COND_MI,            // Minus, negative            Less than
	R_ANAL_COND_PL,            // Plus, positive or zero     >, ==, or unordered
	R_ANAL_COND_VS,            // Overflow                   Unordered
	R_ANAL_COND_VC,            // No overflow                Not unordered
	R_ANAL_COND_HI,            // Unsigned higher            Greater than, or unordered
	R_ANAL_COND_LS             // Unsigned lower or same     Less than or equal
} _RAnalCond;

enum {
	R_ANAL_REFLINE_TYPE_UTF8 = 1,
	R_ANAL_REFLINE_TYPE_WIDE = 2,  /* reflines have a space between them */
	R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE = 4, /* do not consider starts/ends of
	                                        * reflines (used for comment lines before disasm) */
	R_ANAL_REFLINE_TYPE_MIDDLE_AFTER = 8 /* as above but for lines after disasm */
};

enum {
	R_ANAL_RET_NOP = 0,
	R_ANAL_RET_ERROR = -1,
	R_ANAL_RET_DUP = -2,
	R_ANAL_RET_NEW = -3,
	R_ANAL_RET_END = -4
};

typedef struct r_anal_case_obj_t {
	ut64 addr;
	ut64 jump;
	ut64 value;
} RAnalCaseOp;

typedef struct r_anal_switch_obj_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RList/*<RAnalCaseOp>*/ *cases;
} RAnalSwitchOp;

typedef enum r_anal_data_type_t {
	R_ANAL_DATATYPE_NULL = 0,
	R_ANAL_DATATYPE_ARRAY,
	R_ANAL_DATATYPE_OBJECT, // instance
	R_ANAL_DATATYPE_STRING,
	R_ANAL_DATATYPE_CLASS,
	R_ANAL_DATATYPE_BOOLEAN,
	R_ANAL_DATATYPE_INT16,
	R_ANAL_DATATYPE_INT32,
	R_ANAL_DATATYPE_INT64,
	R_ANAL_DATATYPE_FLOAT,
} RAnalDataType;

typedef struct r_anal_op_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	ut64 addr;      /* address */
	ut32 type;	/* type of opcode */
	RAnalOpPrefix prefix;	/* type of opcode prefix (rep,lock,..) */
	ut32 type2;	/* used by java */
	RAnalStackOp stackop;	/* operation on stack? */
	_RAnalCond cond;	/* condition type */
	int size;       /* size in bytes of opcode */
	int nopcode;    /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles;	/* cpu-cycles taken by instruction */
	int failcycles;	/* conditional cpu-cycles */
	RAnalOpFamily family;	/* family of opcode */
	int id;         /* instruction id */
	bool eob;       /* end of block (boolean) */
	bool sign;      /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	RAnalOpDirection direction;
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;       /* reference to value */ /* XXX signed? */
	int ptrsize;    /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr;  /* stack pointer */
	int refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RVector/*RAnalValue*/ srcs;
	RVector/*RAnalValue*/ dsts;
	RList *access; /* RAnalValue access information */
	RStrBuf esil;
	RStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RAnalSwitchOp *switch_op;
	RAnalHint hint;
	RAnalDataType datatype;
	int vliw; // begin of opcode block.
} RAnalOp;

#ifdef __cplusplus
}
#endif

#endif

