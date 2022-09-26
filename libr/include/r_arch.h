/* radare2 - LGPL - Copyright 2022 - pancake, condret */

#ifndef R2_ARCH_H
#define R2_ARCH_H

#include <r_util.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_arch);
#include <r_util.h>
struct r_reg_item_t;
struct r_reg_t;
#include <r_reg.h>
#include <r_io.h>
#include <sdb.h>

enum {
	R_ARCH_SYNTAX_NONE = 0,
	R_ARCH_SYNTAX_INTEL,
	R_ARCH_SYNTAX_ATT,
	R_ARCH_SYNTAX_MASM,
	R_ARCH_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	R_ARCH_SYNTAX_JZ, // hack to use jz instead of je on x86
};

// TODO: add reference counting and accessor APIs
typedef struct r_arch_config_t {
	char *decoder;
	char *arch;
	char *cpu;
	char *os;
	int bits;
	union {
		int big_endian;
		ut32 endian;
	};
	int syntax;
	//
	int pcalign;
	int dataalign;
	int segbas;
	int seggrn;
	int invhex;
	int bitshift;
	char *abi;
	R_REF_TYPE;
} RArchConfig;

// XXX: this definition is plain wrong. use enum or empower bits
#define R_ARCH_OP_TYPE_MASK 0x8000ffff
#define R_ARCH_OP_HINT_MASK 0xf0000000
typedef enum {
	R_ARCH_OP_TYPE_COND  = 0x80000000, // TODO must be moved to prefix?
	//TODO: MOVE TO PREFIX .. it is used by anal_java.. must be updated
	R_ARCH_OP_TYPE_REP   = 0x40000000, /* repeats next instruction N times */
	R_ARCH_OP_TYPE_MEM   = 0x20000000, // TODO must be moved to prefix?
	R_ARCH_OP_TYPE_REG   = 0x10000000, // operand is a register
	R_ARCH_OP_TYPE_IND   = 0x08000000, // operand is indirect
	R_ARCH_OP_TYPE_NULL  = 0,
	R_ARCH_OP_TYPE_JMP   = 1,  /* mandatory jump */
	R_ARCH_OP_TYPE_UJMP  = 2,  /* unknown jump (register or so) */
	R_ARCH_OP_TYPE_RJMP  = R_ARCH_OP_TYPE_UJMP| R_ARCH_OP_TYPE_REG,
	R_ARCH_OP_TYPE_UCJMP = R_ARCH_OP_TYPE_UJMP | R_ARCH_OP_TYPE_COND, /* conditional unknown jump */
	R_ARCH_OP_TYPE_IJMP  = R_ARCH_OP_TYPE_UJMP | R_ARCH_OP_TYPE_IND,
	R_ARCH_OP_TYPE_IRJMP = R_ARCH_OP_TYPE_UJMP | R_ARCH_OP_TYPE_REG | R_ARCH_OP_TYPE_IND,
	R_ARCH_OP_TYPE_CJMP  = R_ARCH_OP_TYPE_JMP | R_ARCH_OP_TYPE_COND,  /* conditional jump */
	R_ARCH_OP_TYPE_MJMP  = R_ARCH_OP_TYPE_JMP | R_ARCH_OP_TYPE_MEM,   /* memory jump */
	R_ARCH_OP_TYPE_RCJMP = R_ARCH_OP_TYPE_CJMP | R_ARCH_OP_TYPE_REG,  /* conditional jump register */
	R_ARCH_OP_TYPE_MCJMP = R_ARCH_OP_TYPE_CJMP | R_ARCH_OP_TYPE_MEM,  /* memory conditional jump */
	R_ARCH_OP_TYPE_CALL  = 3,  /* call to subroutine (branch+link) */
	R_ARCH_OP_TYPE_UCALL = 4, /* unknown call (register or so) */
	R_ARCH_OP_TYPE_RCALL = R_ARCH_OP_TYPE_UCALL | R_ARCH_OP_TYPE_REG,
	R_ARCH_OP_TYPE_ICALL = R_ARCH_OP_TYPE_UCALL | R_ARCH_OP_TYPE_IND,
	R_ARCH_OP_TYPE_IRCALL= R_ARCH_OP_TYPE_UCALL | R_ARCH_OP_TYPE_REG | R_ARCH_OP_TYPE_IND,
	R_ARCH_OP_TYPE_CCALL = R_ARCH_OP_TYPE_CALL | R_ARCH_OP_TYPE_COND, /* conditional call to subroutine */
	R_ARCH_OP_TYPE_UCCALL= R_ARCH_OP_TYPE_UCALL | R_ARCH_OP_TYPE_COND, /* conditional unknown call */
	R_ARCH_OP_TYPE_RET   = 5, /* returns from subroutine */
	R_ARCH_OP_TYPE_CRET  = R_ARCH_OP_TYPE_COND | R_ARCH_OP_TYPE_RET, /* conditional return from subroutine */
	R_ARCH_OP_TYPE_ILL   = 6,  /* illegal instruction // trap */
	R_ARCH_OP_TYPE_UNK   = 7, /* unknown opcode type */
	R_ARCH_OP_TYPE_NOP   = 8, /* does nothing */
	R_ARCH_OP_TYPE_MOV   = 9, /* register move */
	R_ARCH_OP_TYPE_CMOV  = 9 | R_ARCH_OP_TYPE_COND, /* conditional move */
	R_ARCH_OP_TYPE_TRAP  = 10, /* it's a trap! */
	R_ARCH_OP_TYPE_SWI   = 11,  /* syscall, software interrupt */
	R_ARCH_OP_TYPE_CSWI  = 11 | R_ARCH_OP_TYPE_COND,  /* syscall, software interrupt */
	R_ARCH_OP_TYPE_UPUSH = 12, /* unknown push of data into stack */
	R_ARCH_OP_TYPE_RPUSH = R_ARCH_OP_TYPE_UPUSH | R_ARCH_OP_TYPE_REG, /* push register */
	R_ARCH_OP_TYPE_PUSH  = 13,  /* push value into stack */
	R_ARCH_OP_TYPE_POP   = 14,   /* pop value from stack to register */
	R_ARCH_OP_TYPE_CMP   = 15,  /* compare something */
	R_ARCH_OP_TYPE_ACMP  = 16,  /* compare via and */
	R_ARCH_OP_TYPE_ADD   = 17,
	R_ARCH_OP_TYPE_SUB   = 18,
	R_ARCH_OP_TYPE_IO    = 19,
	R_ARCH_OP_TYPE_MUL   = 20,
	R_ARCH_OP_TYPE_DIV   = 21,
	R_ARCH_OP_TYPE_SHR   = 22,
	R_ARCH_OP_TYPE_SHL   = 23,
	R_ARCH_OP_TYPE_SAL   = 24,
	R_ARCH_OP_TYPE_SAR   = 25,
	R_ARCH_OP_TYPE_OR    = 26,
	R_ARCH_OP_TYPE_AND   = 27,
	R_ARCH_OP_TYPE_XOR   = 28,
	R_ARCH_OP_TYPE_NOR   = 29,
	R_ARCH_OP_TYPE_NOT   = 30,
	R_ARCH_OP_TYPE_STORE = 31,  /* store from register to memory */
	R_ARCH_OP_TYPE_LOAD  = 32,  /* load from memory to register */
	R_ARCH_OP_TYPE_LEA   = 33, /* TODO add ulea */
	R_ARCH_OP_TYPE_LEAVE = 34,
	R_ARCH_OP_TYPE_ROR   = 35,
	R_ARCH_OP_TYPE_ROL   = 36,
	R_ARCH_OP_TYPE_XCHG  = 37,
	R_ARCH_OP_TYPE_MOD   = 38,
	R_ARCH_OP_TYPE_SWITCH = 39,
	R_ARCH_OP_TYPE_CASE = 40,
	R_ARCH_OP_TYPE_LENGTH = 41,
	R_ARCH_OP_TYPE_CAST = 42,
	R_ARCH_OP_TYPE_NEW = 43,
	R_ARCH_OP_TYPE_ABS = 44,
	R_ARCH_OP_TYPE_CPL = 45,	/* complement */
	R_ARCH_OP_TYPE_CRYPTO = 46,
	R_ARCH_OP_TYPE_SYNC = 47,
	//R_ARCH_OP_TYPE_DEBUG = 43, // monitor/trace/breakpoint
#if 0
	R_ARCH_OP_TYPE_PRIV = 40, /* privileged instruction */
	R_ARCH_OP_TYPE_FPU = 41, /* floating point stuff */
#endif
} RArchOpType;

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
typedef enum {
	R_ARCH_OP_PREFIX_COND     = 1,
	R_ARCH_OP_PREFIX_REP      = 1<<1,
	R_ARCH_OP_PREFIX_REPNE    = 1<<2,
	R_ARCH_OP_PREFIX_LOCK     = 1<<3,
	R_ARCH_OP_PREFIX_LIKELY   = 1<<4,
	R_ARCH_OP_PREFIX_UNLIKELY = 1<<5
	/* TODO: add segment override typemods? */
} RArchOpPrefix;

typedef enum {
	R_ARCH_STACK_NULL = 0,
	R_ARCH_STACK_NOP,
	R_ARCH_STACK_INC,
	R_ARCH_STACK_GET,
	R_ARCH_STACK_SET,
	R_ARCH_STACK_RESET,
	R_ARCH_STACK_ALIGN,
} RArchStackOp;

/* TODO: what to do with signed/unsigned conditionals? */
typedef enum {
	R_ARCH_COND_AL = 0,        // Always executed (no condition)
	R_ARCH_COND_EQ,            // Equal
	R_ARCH_COND_NE,            // Not equal
	R_ARCH_COND_GE,            // Greater or equal
	R_ARCH_COND_GT,            // Greater than
	R_ARCH_COND_LE,            // Less or equal
	R_ARCH_COND_LT,            // Less than
	R_ARCH_COND_NV,            // Never executed             must be a nop? :D
	R_ARCH_COND_HS,            // Carry set                  >, ==, or unordered
	R_ARCH_COND_LO,            // Carry clear                Less than
	R_ARCH_COND_MI,            // Minus, negative            Less than
	R_ARCH_COND_PL,            // Plus, positive or zero     >, ==, or unordered
	R_ARCH_COND_VS,            // Overflow                   Unordered
	R_ARCH_COND_VC,            // No overflow                Not unordered
	R_ARCH_COND_HI,            // Unsigned higher            Greater than, or unordered
	R_ARCH_COND_LS             // Unsigned lower or same     Less than or equal
} RArchCond;

typedef enum {
	R_ARCH_OP_FAMILY_UNKNOWN = -1,
	R_ARCH_OP_FAMILY_CPU = 0,	/* normal cpu instruction */
	R_ARCH_OP_FAMILY_FPU,    	/* fpu (floating point) */
	R_ARCH_OP_FAMILY_MMX,    	/* multimedia instruction (packed data) */
	R_ARCH_OP_FAMILY_SSE,    	/* extended multimedia instruction (packed data) */
	R_ARCH_OP_FAMILY_PRIV,   	/* privileged instruction */
	R_ARCH_OP_FAMILY_CRYPTO, 	/* cryptographic instructions */
	R_ARCH_OP_FAMILY_THREAD, 	/* thread/lock/sync instructions */
	R_ARCH_OP_FAMILY_VIRT,   	/* virtualization instructions */
	R_ARCH_OP_FAMILY_SECURITY,	/* security instructions */
	R_ARCH_OP_FAMILY_IO,     	/* IO instructions (i.e. IN/OUT) */
	R_ARCH_OP_FAMILY_LAST
} RArchOpFamily;

typedef enum {
	R_ARCH_OP_DIR_READ = 1,
	R_ARCH_OP_DIR_WRITE = 2,
	R_ARCH_OP_DIR_EXEC = 4,
	R_ARCH_OP_DIR_REF = 8,
} RArchOpDirection;

typedef enum {
	R_ARCH_ACC_UNKNOWN = 0,
	R_ARCH_ACC_R = (1 << 0),
	R_ARCH_ACC_W = (1 << 1),
} RArchValueAccess;

typedef enum {
	R_ARCH_VAL_REG,
	R_ARCH_VAL_MEM,
	R_ARCH_VAL_IMM,
} RArchValueType;

// base + reg + regdelta * mul + delta
typedef struct r_arch_value_t {
	RArchValueType type;
	RArchValueAccess access;
	int absolute; // if true, unsigned cast is used
	int memref; // is memory reference? which size? 1, 2 ,4, 8
	ut64 base ; // numeric address
	st64 delta; // numeric delta
	st64 imm; // immediate value
	int mul; // multiplier (reg*4+base)
	// XXX can be invalidated if regprofile changes causing an UAF
	struct r_reg_item_t *seg; // segment selector register
	struct r_reg_item_t *reg; // register item reference
	struct r_reg_item_t *regdelta; // register index used
} RArchValue;

typedef struct r_arch_case_op_t {
	ut64 addr;
	ut64 jump;
	ut64 value;
} RArchCaseOp;

typedef struct r_arch_switch_op_t {
	ut64 addr;
	ut64 min_val;
	ut64 def_val;
	ut64 max_val;
	RList /*<RArchCaseOp>*/ *cases;
} RArchSwitchOp;

typedef enum {
	R_ARCH_DATATYPE_NULL = 0,
	R_ARCH_DATATYPE_ARRAY,
	R_ARCH_DATATYPE_OBJECT, // instance
	R_ARCH_DATATYPE_STRING,
	R_ARCH_DATATYPE_CLASS,
	R_ARCH_DATATYPE_BOOLEAN,
	R_ARCH_DATATYPE_INT16,
	R_ARCH_DATATYPE_INT32,
	R_ARCH_DATATYPE_INT64,
	R_ARCH_DATATYPE_FLOAT,
} RArchDataType;

typedef struct r_arch_op_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	ut64 addr;      /* address */
	RArchOpType type;	/* type of opcode */
	RArchOpPrefix prefix;	/* type of opcode prefix (rep,lock,..) */
	RArchOpType type2;	/* used by java */
	RArchStackOp stackop;	/* operation on stack? */
	RArchCond cond;	/* condition type */
	int size;       /* size in bytes of opcode */
	ut32 nopcode;    /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	ut32 cycles;	/* cpu-cycles taken by instruction */
	ut32 failcycles;	/* conditional cpu-cycles */
	RArchOpFamily family;	/* family of opcode */
	int id;         /* instruction id */
	bool eob;       /* end of block (boolean) */
	bool sign;      /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay;      /* delay N slots (mips, ..)*/
	ut64 jump;      /* true jmp */
	ut64 fail;      /* false jmp */
	RArchOpDirection direction;
	st64 ptr;       /* reference to memory */ /* XXX signed? */
	ut64 val;       /* reference to value */ /* XXX signed? */
	ut32 ptrsize;    /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr;  /* stack pointer */
	bool refptr;     /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	RVector /*RArchValue*/	*srcs;
	RVector /*RArchValue*/	*dsts;
	RList *access; /* RArchValue access information */
	RStrBuf esil;
	RStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RArchSwitchOp *switch_op;
	ut32 new_bits;
	RArchDataType datatype;
	int vliw; // begin of opcode block.
} RArchOp;

#define R_ARCH_INFO_MIN_OP_SIZE	0
#define R_ARCH_INFO_MAX_OP_SIZE	1
#define R_ARCH_INFO_INV_OP_SIZE	2
#define R_ARCH_INFO_ALIGN	4
#define R_ARCH_INFO_DATA_ALIGN	8
#define R_ARCH_INFO_JMPMID	16	//supported jmpmid

#define	R_ARCH_OP_MASK_BASIC	0	// Just fills basic op info , it's fast
#define R_ARCH_OP_MASK_ESIL	1	// It fills RAnalop->esil info
#define R_ARCH_OP_MASK_VAL	2	// It fills RAnalop->dst/src info
#define	R_ARCH_OP_MASK_OPEX	4	// It fills RAnalop->opex info
#define	R_ARCH_OP_MASK_DISASM	8	// It fills RAnalop->mnemonic // should be RAnalOp->disasm // only from r_core_anal_op()

typedef struct r_arch_decoder_t {
	struct r_arch_plugin_t *p;
	void *user;
	ut32 refctr;
} RArchDecoder;

typedef struct r_arch_t {
	RList *plugins;	//all plugins
	RArchDecoder *current;	//currently used decoder
	HtPP *decoders;	//as decoders instantiated plugins
	RArchConfig *cfg;	//config
} RArch;

typedef struct r_arch_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	char *cpus;
	ut32 endian;
	ut32 bits;
	ut32 addr_bits;
	bool esil;
	bool (*init)(void **user);
	void (*fini)(void *user);
	int (*info)(RArchConfig *cfg, ut32 query);
	int (*decode)(void *user, RArchConfig *cfg, RArchOp *op, ut64 addr, const ut8 *data, int len, ut32 mask);
	bool (*set_reg_profile)(RArchConfig *cfg, struct r_reg_t *reg);
//TODO: reenable this later
//	bool (*esil_init)(RAnalEsil *esil);
//	void (*esil_fini)(RAnalEsil *esil);
} RArchPlugin;

// decoder.c
//dname is name of decoder to use, NULL if current
R_API bool r_arch_load_decoder(RArch *arch, const char *dname);
R_API bool r_arch_use_decoder(RArch *arch, const char *dname);
R_API bool r_arch_unload_decoder(RArch *arch, const char *dname);
R_API int r_arch_info(RArch *arch, const char *dname, ut32 query);
R_API int r_arch_decode(RArch *arch, const char *dname, RArchOp *op, ut64 addr, const ut8 *data, int len, ut32 mask);
R_API bool r_arch_set_reg_profile(RArch *arch, const char *dname, struct r_reg_t *reg);
//R_API bool r_arch_esil_init(RArch *arch, const char *dname, RAnalEsil *esil);
//R_API void r_arch_esil_fini(RArch *arch, const char *dname, RAnalEsil *esil);

// arch.c
R_API RArch *r_arch_new(void);
R_API bool r_arch_use(RArch *arch, RArchConfig *config);
R_API bool r_arch_add(RArch *arch, RArchPlugin *ap);
R_API bool r_arch_del(RArch *arch, const char *name);
R_API void r_arch_free(RArch *arch);

// aconfig.c
R_API void r_arch_config_use(RArchConfig *config, R_NULLABLE const char *arch);
R_API void r_arch_config_set_cpu(RArchConfig *config, R_NULLABLE const char *cpu);
R_API void r_arch_config_set_bits(RArchConfig *config, int bits);
R_API RArchConfig *r_arch_config_new(void);

// switchop
R_API RArchSwitchOp *r_arch_switch_op_new(ut64 addr, ut64 min_val, ut64 max_val, ut64 def_val);
R_API RArchCaseOp *r_arch_case_op_new(ut64 addr, ut64 val, ut64 jump);
R_API void r_arch_switch_op_free(RArchSwitchOp *swop);
R_API RArchCaseOp* r_arch_switch_op_add_case(RArchSwitchOp *swop, ut64 addr, ut64 value, ut64 jump);

// archvalue.c
R_API RArchValue *r_arch_value_new(void);
R_API RArchValue *r_arch_value_copy(RArchValue *ov);
R_API void r_arch_value_free(RArchValue *value);
R_API ut64 r_arch_value_to_ut64(RArchValue *val, struct r_reg_t *reg);
R_API bool r_arch_value_set_ut64(RArchValue *val, struct r_reg_t *reg, RIOBind *iob, ut64 num);
R_API char *r_arch_value_to_string(RArchValue *value);

// archop.c
R_API RArchOp *r_arch_op_new(void);
R_API void r_arch_op_init(RArchOp *op);
R_API void r_arch_op_fini(RArchOp *op);
R_API void r_arch_op_free(void *_op);
R_API RArchOp *r_arch_op_copy(RArchOp *op);
R_API int r_arch_optype_from_string(const char *type);
R_API const char *r_arch_optype_to_string(int t);
R_API const char *r_arch_stackop_to_string(int s);
R_API const char *r_arch_op_family_to_string(int n);
R_API int r_arch_op_family_from_string(const char *f);
R_API const char *r_arch_op_direction_to_string(RArchOp *op);

// archcond.c
R_API const char *r_arch_cond_to_string(RArchCond cc);

extern RArchPlugin r_arch_plugin_null;
extern RArchPlugin r_arch_plugin_i4004;

#ifdef __cplusplus
}
#endif

#endif
