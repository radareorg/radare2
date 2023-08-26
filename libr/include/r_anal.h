/* radare2 - LGPL - Copyright 2009-2023 - nibble, pancake, xvilka */

#ifndef R2_ANAL_H
#define R2_ANAL_H

/* use old refs and function storage */
// still required by core in lot of places
#define USE_VARSUBS 0

#include <r_types.h>
#include <r_io.h>
#include <r_esil.h>
#include <r_arch.h>
#include <r_list.h>
#include <r_util/r_print.h>
#include <r_search.h>
#include <r_util.h>
#include <r_bind.h>
#include <r_syscall.h>
#include <r_flag.h>
#include <r_bin.h>
#include <r_codemeta.h>
#include <sdb/set.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_anal);

/* dwarf processing context */
typedef struct r_anal_dwarf_context {
	const RBinDwarfDebugInfo *info;
	HtUP/*<offset, RBinDwarfLocList*>*/  *loc;
	// const RBinDwarfCfa *cfa; TODO
} RAnalDwarfContext;

// TODO: save memory2 : fingerprints must be pointers to a buffer
// containing a dupped file in memory

/* save memory:
   bb_has_ops=1 -> 600M
   bb_has_ops=0 -> 350MB
 */

typedef struct {
	struct r_anal_t *anal;
	int type;
	int rad;
	SdbForeachCallback cb;
	void *user;
	int count;
	struct r_anal_function_t *fcn;
	PJ *pj;
} RAnalMetaUserItem;

typedef struct r_anal_range_t {
	ut64 from;
	ut64 to;
	int bits;
	ut64 rb_max_addr;
	RBNode rb;
} RAnalRange;

enum {
	R_ANAL_DATA_TYPE_NULL = 0,
	R_ANAL_DATA_TYPE_UNKNOWN = 1,
	R_ANAL_DATA_TYPE_STRING = 2,
	R_ANAL_DATA_TYPE_WIDE_STRING = 3,
	R_ANAL_DATA_TYPE_POINTER = 4,
	R_ANAL_DATA_TYPE_NUMBER = 5,
	R_ANAL_DATA_TYPE_INVALID = 6,
	R_ANAL_DATA_TYPE_HEADER = 7,
	R_ANAL_DATA_TYPE_SEQUENCE = 8,
	R_ANAL_DATA_TYPE_PATTERN = 9,
	R_ANAL_DATA_TYPE_ZERO = 10,
};

// used from core/anal.c
#define R_ANAL_ADDR_TYPE_EXEC      1
#define R_ANAL_ADDR_TYPE_READ      1 << 1
#define R_ANAL_ADDR_TYPE_WRITE     1 << 2
#define R_ANAL_ADDR_TYPE_FLAG      1 << 3
#define R_ANAL_ADDR_TYPE_FUNC      1 << 4
#define R_ANAL_ADDR_TYPE_HEAP      1 << 5
#define R_ANAL_ADDR_TYPE_STACK     1 << 6
#define R_ANAL_ADDR_TYPE_REG       1 << 7
#define R_ANAL_ADDR_TYPE_PROGRAM   1 << 8
#define R_ANAL_ADDR_TYPE_LIBRARY   1 << 9
#define R_ANAL_ADDR_TYPE_ASCII     1 << 10
#define R_ANAL_ADDR_TYPE_SEQUENCE  1 << 11

/* type = (R_ANAL_VAR_TYPE_BYTE & R_ANAL_VAR_TYPE_SIZE_MASK) |
 *			( RANAL_VAR_TYPE_SIGNED & RANAL_VAR_TYPE_SIGN_MASK) |
 *			( RANAL_VAR_TYPE_CONST & RANAL_VAR_TYPE_MODIFIER_MASK)
 */
typedef struct r_anal_type_var_t {
	char *name;
	int index;
	int scope;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8  v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RAnalTypeVar;

typedef struct r_anal_type_ptr_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	union {
		ut8  v8;
		ut16 v16;
		ut32 v32;
		ut64 v64;
	} value;
} RAnalTypePtr;

typedef struct r_anal_type_array_t {
	char *name;
	ut16 type; // contain (type || signedness || modifier)
	ut8 size;
	ut64 count;
	union {
		ut8 *v8;
		ut16 *v16;
		ut32 *v32;
		ut64 *v64;
	} value;
} RAnalTypeArray;

typedef struct r_anal_type_struct_t RAnalTypeStruct;
typedef struct r_anal_type_t RAnalType;

struct r_anal_type_struct_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RAnalType *items;
};

typedef struct r_anal_type_union_t {
	char *name;
	ut8 type;
	ut32 size;
	void *parent;
	RAnalType *items;
} RAnalTypeUnion;

typedef struct r_anal_type_alloca_t {
	long address;
	long size;
	void *parent;
	RAnalType *items;
} RAnalTypeAlloca;

enum {
	R_ANAL_FQUALIFIER_NONE = 0,
	R_ANAL_FQUALIFIER_STATIC = 1,
	R_ANAL_FQUALIFIER_VOLATILE = 2,
	R_ANAL_FQUALIFIER_INLINE = 3,
	R_ANAL_FQUALIFIER_NAKED	= 4,
	R_ANAL_FQUALIFIER_VIRTUAL = 5,
};

#define R_ANAL_CC_MAXARG 16

enum {
	R_ANAL_FCN_TYPE_NULL = 0,
	R_ANAL_FCN_TYPE_FCN = 1 << 0,
	R_ANAL_FCN_TYPE_LOC = 1 << 1,
	R_ANAL_FCN_TYPE_SYM = 1 << 2,
	R_ANAL_FCN_TYPE_IMP = 1 << 3,
	R_ANAL_FCN_TYPE_INT = 1 << 4,  /* privileged function - ends with iret/reti/.. */
	R_ANAL_FCN_TYPE_ROOT = 1 << 5, /* matching flag */
	R_ANAL_FCN_TYPE_ANY = -1       /* all the bits set */
};

#define RAnalBlock struct r_anal_bb_t

enum {
	R_ANAL_DIFF_TYPE_NULL = 0,
	R_ANAL_DIFF_TYPE_MATCH = 'm',
	R_ANAL_DIFF_TYPE_UNMATCH = 'u'
};

typedef struct r_anal_enum_case_t {
	char *name;
	int val;
} RAnalEnumCase;

typedef struct r_anal_struct_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits? rename to 'bitsize'
} RAnalStructMember;

typedef struct r_anal_union_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits? TODO rename to 'bitsize'
} RAnalUnionMember;

typedef enum {
	R_ANAL_BASE_TYPE_KIND_STRUCT,
	R_ANAL_BASE_TYPE_KIND_UNION,
	R_ANAL_BASE_TYPE_KIND_ENUM,
	R_ANAL_BASE_TYPE_KIND_TYPEDEF, // probably temporary addition, dev purposes
	R_ANAL_BASE_TYPE_KIND_ATOMIC, // For real atomic base types
} RAnalBaseTypeKind;

typedef struct r_anal_base_type_struct_t {
	RVector/*<RAnalStructMember>*/ members;
} RAnalBaseTypeStruct;

typedef struct r_anal_base_type_union_t {
	RVector/*<RAnalUnionMember>*/ members;
} RAnalBaseTypeUnion;

typedef struct r_anal_base_type_enum_t {
	RVector/*<RAnalEnumCase*/ cases; // list of all the enum casessssss
} RAnalBaseTypeEnum;

typedef struct r_anal_base_type_t {
	char *name;
	char *type; // Used by typedef, atomic type, enum
	ut64 size; // size of the whole type in bits
	RAnalBaseTypeKind kind;
	union {
		RAnalBaseTypeStruct struct_data;
		RAnalBaseTypeEnum enum_data;
		RAnalBaseTypeUnion union_data;
	};
} RAnalBaseType;

typedef struct r_anal_diff_t {
	int type;
	ut64 addr;
	double dist;
	char *name;
	ut32 size;
} RAnalDiff;
typedef struct r_anal_attr_t RAnalAttr;
struct r_anal_attr_t {
	char *key;
	long value;
	RAnalAttr *next;
};

/* Stores useful function metadata */
typedef struct r_anal_function_meta_t {
	// _min and _max are calculated lazily when queried.
	// On changes, they will either be updated (if this can be done trivially) or invalidated.
	// They are invalid iff _min == UT64_MAX.
	ut64 _min;          // PRIVATE, min address, use r_anal_function_min_addr() to access
	ut64 _max;          // PRIVATE, max address, use r_anal_function_max_addr() to access

	int numrefs;        // number of cross references
	int numcallrefs;    // number of calls
} RAnalFcnMeta;

typedef struct r_anal_function_t {
	char *name;
	char *realname; // R2_590: add realname for the mangled one
	int bits; // ((> bits 0) (set-bits bits))
	int type;
	const char *cc; // calling convention, should come from RAnal.constpool
	ut64 addr;
	HtUP/*<ut64, char *>*/ *labels;
	HtPP/*<char *, ut64 *>*/ *label_addrs;
	RPVector vars;
	HtUP/*<st64, RPVector<RAnalVar *>>*/ *inst_vars; // offset of instructions => the variables they access
	ut64 reg_save_area; // size of stack area pre-reserved for saving registers
	st64 bp_off; // offset of bp inside owned stack frame
	st64 stack;  // stack frame size
	int maxstack;
	int ninstr;
	bool folded;
	bool is_pure;
	bool is_variadic;
	bool has_changed; // true if function may have changed since last anaysis TODO: set this attribute where necessary
	bool bp_frame;
	bool is_noreturn; // true if function does not return
	ut8 *fingerprint; // TODO: make is fuzzy and smarter
	size_t fingerprint_size;
	RAnalDiff *diff;
	RList *bbs; // TODO: should be RPVector
	RAnalFcnMeta meta;
	RList *imports; // maybe bound to class?
	struct r_anal_t *anal; // this function is associated with this instance
} RAnalFunction;

typedef struct r_anal_func_arg_t {
	const char *name;
	const char *fmt;
	const char *cc_source;
	char *orig_c_type;
	char *c_type;
	ut64 size;
	ut64 src; //Function-call argument value or pointer to it
} RAnalFuncArg;

struct r_anal_type_t {
	char *name;
	ut32 type;
	ut32 size;
	RList *content;
};

typedef enum {
	R_META_TYPE_ANY = -1,
	R_META_TYPE_DATA = 'd',
	R_META_TYPE_CODE = 'c',
	R_META_TYPE_STRING = 's',
	R_META_TYPE_FORMAT = 'f',
	R_META_TYPE_MAGIC = 'm',
	R_META_TYPE_HIDE = 'h',
	R_META_TYPE_COMMENT = 'C',
	R_META_TYPE_RUN = 'r',
	R_META_TYPE_HIGHLIGHT = 'H',
	R_META_TYPE_VARTYPE = 't',
} RAnalMetaType;

/* meta */
typedef struct r_anal_meta_item_t {
	// XXX missing size
	RAnalMetaType type;
	int subtype;
	char *str;
	const RSpace *space;
} RAnalMetaItem;

struct r_anal_t;
struct r_anal_bb_t;
typedef struct r_anal_callbacks_t {
	int (*on_fcn_new) (struct r_anal_t *, void *user, RAnalFunction *fcn);
	int (*on_fcn_delete) (struct r_anal_t *, void *user, RAnalFunction *fcn);
	int (*on_fcn_rename) (struct r_anal_t *, void *user, RAnalFunction *fcn, const char *oldname);
	int (*on_fcn_bb_new) (struct r_anal_t *, void *user, RAnalFunction *fcn, struct r_anal_bb_t *bb);
} RAnalCallbacks;

#define R_ESIL_GOTO_LIMIT 4096

typedef struct r_anal_options_t {
	int depth;
	int graph_depth;
	bool vars; //analyze local var and arguments
	bool varname_stack; // name vars based on their offset in the stack
	bool var_newstack; // new sp-relative variable analysis
	int cjmpref;
	int jmpref;
	int jmpabove;
	bool ijmp;
	bool jmpmid; // continue analysis after jmp into middle of insn
	bool loads;
	bool ignbithints;
	int followdatarefs;
	int searchstringrefs;
	int followbrokenfcnsrefs;
	int bb_max_size;
	bool trycatch;
	bool norevisit;
	int recont; // continue on recurse analysis mode
	int noncode;
	bool nopskip; // skip nops at the beginning of functions
	int hpskip; // skip `mov reg,reg` and `lea reg,[reg]`
	int jmptbl; // analyze jump tables
	int nonull;
	bool pushret; // analyze push+ret as jmp
	bool armthumb; //
	bool delay;
	bool tailcall;
	int tailcall_delta;
	bool retpoline;
	bool propagate_noreturn;
	bool recursive_noreturn; // anal.rnr
} RAnalOptions;

typedef enum {
	R_ANAL_CPP_ABI_ITANIUM = 0, // default for GCC
	R_ANAL_CPP_ABI_MSVC
} RAnalCPPABI;

typedef struct r_anal_hint_cb_t {
	//add more cbs as needed
	void (*on_bits) (struct r_anal_t *a, ut64 addr, int bits, bool set);
} RHintCb;

typedef struct r_anal_thread_t {
	int id;
	int map; // tls map id
	ut64 birth;
	RReg *reg;
} RAnalThread;

typedef struct r_ref_manager_t RefManager;

typedef struct r_anal_t {
	RArchConfig *config;
	int lineswidth; // asm.lines.width
	int sleep;      // anal.sleep, sleep some usecs before analyzing more (avoid 100% cpu usages)
	RAnalCPPABI cxxabi; // anal.cpp.abi
	void *user;
	ut64 gp;        // anal.gp, global pointer. used for mips. but can be used by other arches too in the future
	RBTree bb_tree; // all basic blocks by address. They can overlap each other, but must never start at the same address.
	RList *fcns;
	HtUP *ht_addr_fun; // address => function
	HtPP *ht_name_fun; // name => function
	RReg *reg;
	ut8 *last_disasm_reg;
	int last_disasm_reg_size;
	RSyscall *syscall;
	int diff_ops;
	double diff_thbb;
	double diff_thfcn;
	RIOBind iob;
	RFlagBind flb;
	RFlagSet flg_class_set;
	RFlagGet flg_class_get;
	RFlagSet flg_fcn_set;
	RBinBind binb; // Set only from core when an analysis plugin is called.
	RCoreBind coreb;
	int maxreflines; // asm.lines.maxref
	int esil_goto_limit; // esil.gotolimit
	struct r_esil_t *esil; // R2_590 remove
	struct r_anal_plugin_t *cur;
	struct r_esil_plugin_t *esil_cur; // ???
	RArch *arch;
	RAnalRange *limit; // anal.from, anal.to
	RList *plugins; // anal plugins
	Sdb *sdb_types;
	Sdb *sdb_fmts;
	Sdb *sdb_zigns;
	RefManager *rm;
	RSpaces zign_spaces;
	char *zign_path; // dir.zigns
	PrintfCallback cb_printf;
	RPrint *print;
	//moved from RAnalFcn
	Sdb *sdb; // root
	Sdb *sdb_pins;
	HtUP/*<RVector<RAnalAddrHintRecord>>*/ *addr_hints; // all hints that correspond to a single address
	RBTree/*<RAnalArchHintRecord>*/ arch_hints;
	RBTree/*<RAnalArchBitsRecord>*/ bits_hints;
	RHintCb hint_cbs;
	RIntervalTree meta;
	RSpaces meta_spaces;
	Sdb *sdb_cc; // calling conventions
	Sdb *sdb_classes;
	Sdb *sdb_classes_attrs;
	RAnalCallbacks cb;
	RAnalOptions opt;
	RList *reflines;
	RListComparator columnSort;
	int stackptr;
	bool (*log)(struct r_anal_t *anal, const char *msg);
	bool (*read_at)(struct r_anal_t *anal, ut64 addr, ut8 *buf, int len);
	bool verbose;
	RFlagGetAtAddr flag_get;
	REvent *ev;
	RList/*<char *>*/ *imports; // global imports
	SetU *visited;
	RStrConstPool constpool;
	RList *leaddrs;
	char *pincmd;
	/* private */
	RThreadLock *lock;
	ut64 cmpval;
	ut64 lea_jmptbl_ip;
	int cs_obits;
	int cs_omode;
	size_t cs_handle;
	int thread; // see apt command
	RList *threads;
	RColor tracetagcolors[64]; // each trace color for each bit
	/* end private */
	R_DIRTY_VAR;
} RAnal;

typedef const char *(*RAnalLabelAt) (RAnalFunction *fcn, ut64);

typedef enum {
	R_ANAL_VAR_KIND_REG = 'r',
	R_ANAL_VAR_KIND_BPV = 'b',
	R_ANAL_VAR_KIND_SPV = 's'
} RAnalVarKind;

#define VARPREFIX "var"
#define ARGPREFIX "arg"

typedef enum {
	R_ANAL_VAR_ACCESS_TYPE_PTR = 0,
	R_ANAL_VAR_ACCESS_TYPE_READ = (1 << 0),
	R_ANAL_VAR_ACCESS_TYPE_WRITE = (1 << 1)
} RAnalVarAccessType;

typedef struct r_anal_var_access_t {
	const char *reg; // register used for access
	st64 offset; // relative to the function's entrypoint
	st64 stackptr; // delta added to register to get the var, e.g. [rbp - 0x10]
	ut8 type; // RAnalVarAccessType bits
} RAnalVarAccess;

typedef struct r_anal_var_constraint_t {
	_RAnalCond cond;
	ut64 val;
} RAnalVarConstraint;

// generic for args and locals
typedef struct r_anal_var_t {
	RAnalFunction *fcn;
	char *name; // name of the variable
	char *type; // cparse type of the variable
	RAnalVarKind kind;
	bool isarg;
	int delta;   /* delta offset inside stack frame */
	char *regname; // name of the register
	RVector/*<RAnalVarAccess>*/ accesses; // ordered by offset, touch this only through API or expect uaf
	char *comment;
	RVector/*<RAnalVarConstraint>*/ constraints;

	// below members are just for caching, TODO: remove them and do it better
	int argnum;
} RAnalVar;

// RAnalVar "prototype", RAnalVar w/o function used for serialization
typedef struct r_anal_var_proto_t {
	char *name;
	char *type;
	RAnalVarKind kind;
	bool isarg;
	int delta;
} RAnalVarProt;

// Refers to a variable or a struct field inside a variable, only for varsub
R_DEPRECATE typedef struct r_anal_var_field_t {
	char *name;
	st64 delta;
	bool field;
} RAnalVarField;

// TO DEPRECATE R2_590
// Use r_anal_get_functions_in¿() instead
R_DEPRECATE R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type);
R_DEPRECATE R_API RAnalFunction *r_anal_get_fcn_in_bounds(RAnal *anal, ut64 addr, int type);
R_API R_DEPRECATE RList/*<RAnalVar *>*/ *r_anal_var_all_list(RAnal *anal, RAnalFunction *fcn);
R_API R_DEPRECATE RList/*<RAnalVarField *>*/ *r_anal_function_get_var_fields(RAnalFunction *fcn, int kind);
// There could be multiple vars used in multiple functions. Use r_anal_get_functions_in()+r_anal_function_get_vars_used_at() instead.
R_API R_DEPRECATE RAnalVar *r_anal_get_used_function_var(RAnal *anal, ut64 addr);

typedef RAnalFunction *(* RAnalGetFcnIn)(RAnal *anal, ut64 addr, int type);
typedef RAnalHint *(* RAnalGetHint)(RAnal *anal, ut64 addr);
typedef char *(* RAnalMnemonics)(RAnal *anal, int id, bool json);
typedef int (* RAnalEncode)(RAnal *anal, ut64 addr, const char *s, ut8 *data, int len);
typedef int (* RAnalDecode)(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
typedef void (* RAnalOpInit)(RAnalOp *op);
typedef void (* RAnalOpFini)(RAnalOp *op);
typedef bool (* RAnalUse)(RAnal *op, const char *name); // TODO: add bits and cpu too imho

typedef struct r_anal_bind_t {
	RAnal *anal;
	RAnalGetFcnIn get_fcn_in;
	RAnalGetHint get_hint;
	RAnalMnemonics mnemonics;
	RAnalEncode encode;
	RAnalDecode decode;
	RAnalOpInit opinit;
	RAnalOpFini opfini;
	RAnalUse use;
} RAnalBind;

#define R_ANAL_COND_SINGLE(x) (!x->arg[1] || x->arg[0]==x->arg[1])

typedef struct r_anal_cond_t {
	int type; // filled by CJMP opcode
	RArchValue *arg[2]; // filled by CMP opcode
} RAnalCond;

typedef struct r_anal_bb_t {
	RBNode _rb;     // private, node in the RBTree
	ut64 _max_end;  // private, augmented value for RBTree
	ut64 addr;
	ut64 size;
	ut64 jump;
	ut64 fail;
	ut64 traced; // bitfield (each bit represents 1 trace)
	bool folded;
	RColor color;
	ut8 *fingerprint;
	RAnalDiff *diff;
	RAnalCond *cond;
	RAnalSwitchOp *switch_op;
	ut16 *op_pos; // offsets of instructions in this block, count is ninstr - 1 (first is always 0)
	ut8 *op_bytes;
	ut8 *parent_reg_arena;
	int parent_reg_arena_size;
	int op_pos_size; // size of the op_pos array
	int ninstr;
	int stackptr;
	int parent_stackptr;
	ut64 cmpval;
	const char *cmpreg;
	ut32 bbhash; // calculated with xxhash

	RList *fcns;
	RAnal *anal;
	char *esil;
	int ref;
	int depth;
#undef RAnalBlock
} RAnalBlock;

typedef enum {
	R_ANAL_REF_TYPE_NULL = 0, // find better name
	R_ANAL_REF_TYPE_CODE = 'c', // code ref
	R_ANAL_REF_TYPE_CALL = 'C', // code ref (call) -- maybe use 'k' for kall?
	R_ANAL_REF_TYPE_JUMP = 'j', // code ref (call)
	R_ANAL_REF_TYPE_DATA = 'd', // mem ref
	R_ANAL_REF_TYPE_ICOD = 'i', // indirect code reference
	R_ANAL_REF_TYPE_STRN = 's', // string ref
	// perm / direction
	R_ANAL_REF_TYPE_READ = 4 << 8,
	R_ANAL_REF_TYPE_WRITE = 2 << 8,
	R_ANAL_REF_TYPE_EXEC = 1 << 8,
	R_ANAL_REF_TYPE_MASK = 0xff,
	R_ANAL_REF_TYPE_DIRECTION_MASK = 0xff00
} RAnalRefType;

#define R_ANAL_REF_TYPE_PERM(x) (((x)>>8) & 0xff)
// #define R_ANAL_REF_TYPE_MASK(x) ((x) & 0xff)
#define R_ANAL_REF_TYPE_MASK(x) r_anal_ref_typemask((x))

typedef struct r_anal_ref_t {
	ut64 at;
	ut64 addr;
	RAnalRefType type;
} RAnalRef;

typedef struct r_vec_RVecAnalRef_t RVecAnalRef;

/* represents a reference line from one address (from) to another (to) */
typedef struct r_anal_refline_t {
	ut64 from;
	ut64 to;
	int index;
	int level;
	int type;
	int direction;
} RAnalRefline;

typedef struct r_anal_cycle_frame_t {
	ut64 naddr;			//next addr
	RList *hooks;
	struct r_anal_cycle_frame_t *prev;
} RAnalCycleFrame;

typedef struct r_anal_cycle_hook_t {	//rename ?
	ut64 addr;
	int cycles;
} RAnalCycleHook;

typedef struct r_esil_word_t {
	int type;
	const char *str;
} REsilWord;


enum {
	R_ANAL_TRAP_NONE = 0,
	R_ANAL_TRAP_UNHANDLED = 1,
	R_ANAL_TRAP_BREAKPOINT = 2,
	R_ANAL_TRAP_DIVBYZERO = 3,
	R_ANAL_TRAP_WRITE_ERR = 4,
	R_ANAL_TRAP_READ_ERR = 5,
	R_ANAL_TRAP_EXEC_ERR = 6,
	R_ANAL_TRAP_INVALID = 7,
	R_ANAL_TRAP_UNALIGNED = 8,
	R_ANAL_TRAP_TODO = 9,
	R_ANAL_TRAP_HALT = 10,
};



typedef struct r_anal_esil_cfg_t {
	RGraphNode *start;
	RGraphNode *end;
	RGraph *g;
} RAnalEsilCFG;

enum {
	R_ANAL_ESIL_DFG_TAG_CONST = 1,
	R_ANAL_ESIL_DFG_TAG_VAR = 2,
	R_ANAL_ESIL_DFG_TAG_PTR = 4,
	R_ANAL_ESIL_DFG_TAG_RESULT = 8,
	R_ANAL_ESIL_DFG_TAG_GENERATIVE = 16,
	R_ANAL_ESIL_DFG_TAG_REG = 32,
	R_ANAL_ESIL_DFG_TAG_MEM = 64,
	R_ANAL_ESIL_DFG_TAG_MERGE = 128,
	R_ANAL_ESIL_DFG_TAG_SIBLING = 256,
};	//RAnalEsilDFGTagType

typedef struct r_anal_esil_dfg_t {
	ut32 idx;
	int fd;
	RIOBind iob;
	RReg *reg;
	Sdb *regs;		//resolves regnames to intervals
	RRBTree *vars;		//vars represented in regs and mem
	RQueue *todo;		//todo-queue allocated in this struct for perf
	void *insert;		//needed for setting regs in dfg
	RGraph *flow;
	RGraphNode *cur;
	RGraphNode *old;
	REsil *esil;
	bool use_map_info;
	bool use_maps;
	bool malloc_failed;
} RAnalEsilDFG;

typedef struct r_anal_esil_dfg_node_t {
	// add more info here
	ut32 idx;
	RStrBuf *content;
	ut32 /*RAnalEsilDFGTagType*/ type;
} RAnalEsilDFGNode;

typedef bool (*RAnalCmdCallback)(/* Rcore */RAnal *anal, const char* input);

typedef int (*RAnalOpCallback)(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
typedef int (*RAnalOpAsmCallback)(RAnal *a, ut64 addr, const char *str, ut8 *outbuf, int outlen);

typedef bool (*RAnalRegProfCallback)(RAnal *a);
typedef char*(*RAnalRegProfGetCallback)(RAnal *a);
typedef int (*RAnalFPBBCallback)(RAnal *a, RAnalBlock *bb);
typedef int (*RAnalFPFcnCallback)(RAnal *a, RAnalFunction *fcn);
typedef int (*RAnalDiffBBCallback)(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
typedef int (*RAnalDiffFcnCallback)(RAnal *anal, RList *fcns, RList *fcns2);
typedef int (*RAnalDiffEvalCallback)(RAnal *anal);

typedef int (*REsilCB)(REsil *esil);
typedef int (*REsilLoopCB)(REsil *esil, RAnalOp *op);
typedef int (*REsilTrapCB)(REsil *esil, int trap_type, int trap_code);

typedef struct r_anal_plugin_t {
	RPluginMeta meta;

	const char *depends; // comma separated list of dependencies

	bool (*init)(RAnal *a);
	bool (*fini)(RAnal *a);

	// legacy r_anal_functions
	RAnalOpCallback op;
	RAnalCmdCallback cmd;
#if 1
	/// XXX unused but referenced, maybe worth checking in case we want them for anal
	RAnalFPBBCallback fingerprint_bb;
	RAnalFPFcnCallback fingerprint_fcn;
	RAnalDiffBBCallback diff_bb;
	RAnalDiffFcnCallback diff_fcn;
	RAnalDiffEvalCallback diff_eval;
#endif
} RAnalPlugin;

/*----------------------------------------------------------------------------------------------*/
int * (r_anal_compare) (RAnalFunction , RAnalFunction );
/*----------------------------------------------------------------------------------------------*/

#ifdef R_API
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RArchValue *val);
R_API bool r_anal_value_set_ut64(RAnal *anal, RArchValue *val, ut64 num);
/* --------- */ /* R2_590 REFACTOR */ /* ---------- */
R_API RListRange* r_listrange_new(void);
R_API void r_listrange_free(RListRange *s);
R_API void r_listrange_add(RListRange *s, RAnalFunction *f);
R_API void r_listrange_del(RListRange *s, RAnalFunction *f);
R_API void r_listrange_resize(RListRange *s, RAnalFunction *f, int newsize);
R_API RAnalFunction *r_listrange_find_in_range(RListRange* s, ut64 addr);
R_API RAnalFunction *r_listrange_find_root(RListRange* s, ut64 addr);
/* --------- */ /* REFACTOR */ /* ---------- */
/* type.c */
R_API RAnalType *r_anal_type_new(void);
R_API void r_anal_type_add(RAnal *l, RAnalType *t);
R_API RAnalType *r_anal_type_find(RAnal *a, const char* name);
R_API void r_anal_type_list(RAnal *a, short category, short enabled);
R_API const char *r_anal_datatype_tostring(RAnalDataType t);
R_API RAnalType *r_anal_str_to_type(RAnal *a, const char* s);
R_API RAnalType *r_anal_type_free(RAnalType *t);
R_API RAnalType *r_anal_type_loadfile(RAnal *a, const char *path);

R_API bool r_anal_cmd(RAnal *a, const char *cmd);

/* block.c */
typedef bool (*RAnalBlockCb)(RAnalBlock *block, void *user);
typedef bool (*RAnalAddrCb)(ut64 addr, void *user);

// lifetime
R_API void r_anal_block_ref(RAnalBlock *bb);
R_API void r_anal_block_unref(RAnalBlock *bb);
R_API void r_anal_block_reset(RAnal *a);

// Create one block covering the given range.
// This will fail if the range overlaps any existing blocks.
R_API RAnalBlock *r_anal_create_block(RAnal *anal, ut64 addr, ut64 size);

static inline bool r_anal_block_contains(RAnalBlock *bb, ut64 addr) {
	return (addr >= bb->addr) && (addr < bb->addr + bb->size);
}

// Split the block at the given address into two blocks.
// bb will stay the first block, the second block will be returned (or NULL on failure)
// The returned block will always be refd, i.e. it is necessary to always call r_anal_block_unref() on the return value!
R_API RAnalBlock *r_anal_block_split(RAnalBlock *bb, ut64 addr);

static inline bool r_anal_block_is_contiguous(RAnalBlock *a, RAnalBlock *b) {
	return (a->addr + a->size) == b->addr;
}

// Merge block b into a.
// b will be FREED (not just unrefd) and is NOT VALID anymore if this function is successful!
// This only works if b follows directly after a and their function lists are identical.
// returns true iff the blocks could be merged
R_API bool r_anal_block_merge(RAnalBlock *a, RAnalBlock *b);

// Manually delete a block and remove it from all its functions
// If there are more references to it than from its functions only, it will not be removed immediately!
R_API void r_anal_delete_block(RAnalBlock *bb);
R_API void r_anal_delete_block_at(RAnal *anal, ut64 addr);

R_API void r_anal_block_set_size(RAnalBlock *block, ut64 size);

// Set the address and size of the block.
// This can fail (and return false) if there is already another block at the new address
R_API bool r_anal_block_relocate(RAnalBlock *block, ut64 addr, ut64 size);
R_API ut64 r_anal_block_ninstr(RAnalBlock *block, int pos);

R_API RAnalBlock *r_anal_get_block_at(RAnal *anal, ut64 addr);
R_API bool r_anal_blocks_foreach_in(RAnal *anal, ut64 addr, RAnalBlockCb cb, void *user);
R_API RList *r_anal_get_blocks_in(RAnal *anal, ut64 addr); // values from r_anal_blocks_foreach_in as a list
R_API void r_anal_blocks_foreach_intersect(RAnal *anal, ut64 addr, ut64 size, RAnalBlockCb cb, void *user);
R_API RList *r_anal_get_blocks_intersect(RAnal *anal, ut64 addr, ut64 size); // values from r_anal_blocks_foreach_intersect as a list

// Call cb on every direct successor address of block
// returns false if the loop was breaked by cb
R_API bool r_anal_block_successor_addrs_foreach(RAnalBlock *block, RAnalAddrCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// returns false if the loop was breaked by cb
R_API bool r_anal_block_recurse(RAnalBlock *block, RAnalBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// If cb returns false, recursion stops only for that block
// returns false if the loop was breaked by cb
R_API bool r_anal_block_recurse_followthrough(RAnalBlock *block, RAnalBlockCb cb, void *user);

// Call cb on block and every (recursive) successor of it
// Call on_exit on block that doesn't have non-visited successors
// returns false if the loop was breaked by cb
R_API bool r_anal_block_recurse_depth_first(RAnalBlock *block, RAnalBlockCb cb, R_NULLABLE RAnalBlockCb on_exit, void *user);

// same as r_anal_block_recurse, but returns the blocks as a list
R_API RList *r_anal_block_recurse_list(RAnalBlock *block);

// return one shortest path from block to dst or NULL if none exists.
R_API R_NULLABLE RList/*<RAnalBlock *>*/ *r_anal_block_shortest_path(RAnalBlock *block, ut64 dst);

// Add a case to the block's switch_op.
// If block->switch_op is NULL, it will be created with the given switch_addr.
R_API void r_anal_block_add_switch_case(RAnalBlock *block, ut64 switch_addr, ut64 case_value, ut64 case_addr);

// Chop off the block at the specified address and remove all destinations.
// Blocks that have become unreachable after this operation will be automatically removed from all functions of block.
// addr must be the address directly AFTER the noreturn call!
// After the chopping, an r_anal_block_automerge() is performed on the touched blocks.
// IMPORTANT: The automerge might also FREE block! This function returns block iff it is still valid afterwards.
// If this function returns NULL, the pointer to block MUST not be touched anymore!
R_API RAnalBlock *r_anal_block_chop_noreturn(RAnalBlock *block, ut64 addr);

// Merge every block in blocks with their contiguous predecessor, if possible.
// IMPORTANT: Merged blocks will be FREED! The blocks list will be updated to contain only the survived blocks.
R_API void r_anal_block_automerge(RList *blocks);

// return true iff an instruction in the given basic block starts at the given address
R_API bool r_anal_block_op_starts_at(RAnalBlock *block, ut64 addr);

// Updates bbhash based on current bytes inside the block
R_API void r_anal_block_update_hash(RAnalBlock *block);

// returns true if a byte in the given basic block was modified
R_API bool r_anal_block_was_modified(RAnalBlock *block);

// ---------------------------------------

/* function.c */

R_API RAnalFunction *r_anal_function_new(RAnal *anal);
R_API void r_anal_function_free(RAnalFunction *fcn);

// Add a function created with r_anal_function_new() to anal
R_API bool r_anal_add_function(RAnal *anal, RAnalFunction *fcn);

// Create a new function and add it to anal (r_anal_function_new() + set members + r_anal_add_function())
R_API RAnalFunction *r_anal_create_function(RAnal *anal, const char *name, ut64 addr, int type, RAnalDiff *diff);

// returns all functions that have a basic block containing the given address
R_API RList *r_anal_get_functions_in(RAnal *anal, ut64 addr);

// returns the function that has its entrypoint at addr or NULL
R_API RAnalFunction *r_anal_get_function_at(RAnal *anal, ut64 addr);

R_API bool r_anal_function_delete(RAnalFunction *fcn);

// rhange the entrypoint of fcn
// This can fail (and return false) if there is already another function at the new address
R_API bool r_anal_function_relocate(RAnalFunction *fcn, ut64 addr);

// rename the given function
// This can fail (and return false) if there is another function with the name given
R_API bool r_anal_function_rename(RAnalFunction *fcn, const char *name);

R_API void r_anal_function_add_block(RAnalFunction *fcn, RAnalBlock *bb);
R_API void r_anal_function_remove_block(RAnalFunction *fcn, RAnalBlock *bb);


// size of the entire range that the function spans, including holes.
// this is exactly r_anal_function_max_addr() - r_anal_function_min_addr()
R_API ut64 r_anal_function_linear_size(RAnalFunction *fcn);

// lowest address covered by the function
R_API ut64 r_anal_function_min_addr(RAnalFunction *fcn);

// first address directly after the function
R_API ut64 r_anal_function_max_addr(RAnalFunction *fcn);

// size from the function entrypoint (fcn->addr) to the end of the function (r_anal_function_max_addr)
R_API ut64 r_anal_function_size_from_entry(RAnalFunction *fcn);

// the "real" size of the function, that is the sum of the size of the
// basicblocks this function is composed of
R_API ut64 r_anal_function_realsize(const RAnalFunction *fcn);

// returns whether the function contains a basic block that contains addr
// This is completely independent of fcn->addr, which is only the entrypoint!
R_API bool r_anal_function_contains(RAnalFunction *fcn, ut64 addr);

// returns true if function bytes were modified
R_API bool r_anal_function_was_modified(RAnalFunction *fcn);

R_API RGraph *r_anal_function_get_graph(RAnalFunction *fcn, RGraphNode **node_ptr, ut64 addr);

/* anal.c */
R_API RAnal *r_anal_new(void);
R_API void r_anal_purge(RAnal *anal);
R_API void r_anal_free(RAnal *r);
R_API void r_anal_set_user_ptr(RAnal *anal, void *user);
R_API void r_anal_plugin_free(RAnalPlugin *p);
R_API int r_anal_plugin_add(RAnal *anal, RAnalPlugin *plugin);
R_API bool r_anal_plugin_remove(RAnal *anal, RAnalPlugin *plugin);
R_API int r_anal_archinfo(RAnal *anal, int query);
R_API bool r_anal_is_aligned(RAnal *anal, const ut64 addr);
R_API bool r_anal_use(RAnal *anal, const char *name);
R_API bool r_esil_use(RAnal *anal, const char *name);
R_API const char *r_esil_trapstr(int type);
R_API bool r_anal_set_reg_profile(RAnal *anal, const char *rp);
R_API char *r_anal_get_reg_profile(RAnal *anal);
R_API ut64 r_anal_get_bbaddr(RAnal *anal, ut64 addr);
R_API bool r_anal_set_bits(RAnal *anal, int bits);
R_API bool r_anal_set_os(RAnal *anal, const char *os);
R_API ut8 *r_anal_mask(RAnal *anal, int size, const ut8 *data, ut64 at);
R_API void r_anal_trace_bb(RAnal *anal, ut64 addr);
R_API const char *r_anal_functiontype_tostring(int type);
R_API int r_anal_function_coverage(RAnalFunction *fcn);
R_API int r_anal_function_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, int depth);
R_API void r_anal_bind(RAnal *b, RAnalBind *bnd);
R_API bool r_anal_set_triplet(RAnal *anal, const char *os, const char *arch, int bits);
R_API void r_anal_add_import(RAnal *anal, const char *imp);
R_API void r_anal_remove_import(RAnal *anal, const char *imp);
R_API void r_anal_purge_imports(RAnal *anal);

/* bb.c */
R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off);
R_API bool r_anal_bb_set_offset(RAnalBlock *bb, int i, ut16 v);
R_API ut16 r_anal_bb_offset_inst(const RAnalBlock *bb, int i);
R_API ut64 r_anal_bb_opaddr_i(RAnalBlock *bb, int i);
R_API ut64 r_anal_bb_opaddr_at(RAnalBlock *bb, ut64 addr);
R_API ut64 r_anal_bb_size_i(RAnalBlock *bb, int i);

/* op.c */
R_API const char *r_anal_stackop_tostring(int s);
R_API RAnalOp *r_anal_op_new(void);
R_API void r_anal_op_free(void *op);
R_API void r_anal_op_init(RAnalOp *op);
R_API void r_anal_op_fini(RAnalOp *op);
R_API char *r_anal_mnemonics(RAnal *anal, int id, bool json);
R_API int r_anal_op_reg_delta(RAnal *anal, ut64 addr, const char *name);
R_API bool r_anal_op_is_eob(RAnalOp *op);
R_API RList *r_anal_op_list_new(void);
R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask);
R_API int r_anal_opasm(RAnal *anal, ut64 pc, const char *s, ut8 *outbuf, int outlen);
R_API char *r_anal_op_tostring(RAnal *anal, RAnalOp *op);


/* pin */
R_API void r_anal_pin_init(RAnal *a);
R_API void r_anal_pin_fini(RAnal *a);
R_API void r_anal_pin(RAnal *a, ut64 addr, const char *name);
R_API const char *r_anal_pin_call(RAnal *a, ut64 addr);
R_API void r_anal_pin_list(RAnal *a);
R_API void r_anal_pin_unset(RAnal *a, ut64 addr);

/* fcn.c */
R_API ut32 r_anal_function_cost(RAnalFunction *fcn);
R_API int r_anal_function_count_edges(const RAnalFunction *fcn, R_NULLABLE int *ebbs);

R_API RAnalFunction *r_anal_get_function_byname(RAnal *anal, const char *name);

R_API int r_anal_function(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int reftype);
R_API int r_anal_function_del(RAnal *anal, ut64 addr);
R_API int r_anal_function_del_locs(RAnal *anal, ut64 addr);
R_API bool r_anal_function_add_bb(RAnal *anal, RAnalFunction *fcn,
		ut64 addr, ut64 size,
		ut64 jump, ut64 fail, R_BORROW RAnalDiff *diff);
R_API bool r_anal_check_fcn(RAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high);

R_API void r_anal_function_check_bp_use(RAnalFunction *fcn);
R_API void r_anal_update_analysis_range(RAnal *anal, ut64 addr, int size);
R_API void r_anal_function_update_analysis(RAnalFunction *fcn);

#define R_ANAL_FCN_VARKIND_LOCAL 'v'


R_API int r_anal_function_var_del_byindex(RAnal *a, ut64 fna, const char kind, int scope, ut32 idx);
/* args */
R_API int r_anal_var_count(RAnal *a, RAnalFunction *fcn, int kind, int type);
R_API int r_anal_var_count_all(RAnalFunction *fcn);
R_API int r_anal_var_count_args(RAnalFunction *fcn);
R_API int r_anal_var_count_locals(RAnalFunction *fcn);

/* vars // globals. not here  */
R_API bool r_anal_var_display(RAnal *anal, RAnalVar *var);

R_API int r_anal_function_complexity(RAnalFunction *fcn);
R_API int r_anal_function_loops(RAnalFunction *fcn);
R_API void r_anal_trim_jmprefs(RAnal *anal, RAnalFunction *fcn);
R_API void r_anal_del_jmprefs(RAnal *anal, RAnalFunction *fcn);
R_API char *r_anal_function_get_json(RAnalFunction *function);
R_API RAnalFunction *r_anal_function_next(RAnal *anal, ut64 addr);
R_API char *r_anal_function_get_signature(RAnalFunction *function);
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *_str);
R_API int r_anal_function_count(RAnal *a, ut64 from, ut64 to);
R_API RAnalBlock *r_anal_function_bbget_in(RAnal *anal, RAnalFunction *fcn, ut64 addr);
R_API RAnalBlock *r_anal_function_bbget_at(RAnal *anal, RAnalFunction *fcn, ut64 addr);
R_API bool r_anal_function_bbadd(RAnalFunction *fcn, RAnalBlock *bb);
R_API int r_anal_function_resize(RAnalFunction *fcn, int newsize);
R_API bool r_anal_function_purity(RAnalFunction *fcn);
R_API int r_anal_function_instrcount(RAnalFunction *fcn);
R_API bool r_anal_function_islineal(RAnalFunction *fcn);
R_API const char *r_anal_pin_get(RAnal *a, const char *name);
R_API const char *r_anal_pin_at(RAnal *a, ut64 addr);
R_API bool r_anal_pin_set(RAnal *a, const char *name, const char *cmd);

typedef bool (* RAnalRefCmp)(RAnalRef *ref, void *data);
R_API RList *r_anal_ref_list_new(void);
R_API const char *r_anal_ref_type_tostring(RAnalRefType t);
R_API int r_anal_ref_typemask(int x);
R_DEPRECATE R_API RAnalRefType r_anal_xrefs_type(char ch);

R_API const char *r_anal_ref_perm_tostring(RAnalRef *ref);
R_API char r_anal_ref_perm_tochar(RAnalRef *ref);
R_API char r_anal_ref_permchar_tostring(RAnalRef *ref);

R_API bool r_anal_xrefs_init(RAnal *anal);
R_API void r_anal_xrefs_free(RAnal *anal);
R_API RAnalRefType r_anal_xrefs_type_from_string(const char *s);
R_API RVecAnalRef *r_anal_xrefs_get(RAnal *anal, ut64 to);
R_API RVecAnalRef *r_anal_refs_get(RAnal *anal, ut64 from);
R_API bool r_anal_xrefs_has_xrefs_at(RAnal *anal, ut64 at);
R_API RVecAnalRef *r_anal_xrefs_get_from(RAnal *anal, ut64 to);
R_API void r_anal_xrefs_list(RAnal *anal, int rad, const char *arg);
R_API ut64 r_anal_xrefs_count(RAnal *anal);
R_API ut64 r_anal_xrefs_count_at(RAnal *anal, ut64 to);
R_API RVecAnalRef *r_anal_function_get_refs(RAnalFunction *fcn);
R_API RVecAnalRef *r_anal_function_get_all_xrefs(RAnalFunction *fcn);
R_API RVecAnalRef *r_anal_function_get_xrefs(RAnalFunction *fcn);
R_API bool r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type);
R_API bool r_anal_xref_del(RAnal *anal, ut64 from, ut64 to);

R_API RList *r_anal_get_fcns(RAnal *anal);

/* type.c */
R_API void r_anal_remove_parsed_type(RAnal *anal, const char *name);
R_API void r_anal_save_parsed_type(RAnal *anal, const char *parsed);

/* var.c */
R_API R_OWN char *r_anal_function_autoname_var(RAnalFunction *fcn, char kind, const char *pfx, int ptr);
R_API R_BORROW RAnalVar *r_anal_function_set_var(RAnalFunction *fcn, int delta, char kind, R_NULLABLE const char *type, int size, bool isarg, R_NONNULL const char *name);
R_API bool r_anal_function_set_var_prot(RAnalFunction *fcn, RList /*<RAnalVarProt>*/ *l);
R_API R_BORROW RAnalVar *r_anal_function_get_var(RAnalFunction *fcn, char kind, int delta);
R_API RList *r_anal_var_deserialize(const char *ser);
R_API char *r_anal_var_prot_serialize(RList /*<RAnalVarProt>*/ *l, bool spaces);
R_API RList /*<RAnalVarProt>*/ *r_anal_var_get_prots(RAnalFunction *fcn);
R_API R_BORROW RAnalVar *r_anal_function_get_var_byname(RAnalFunction *fcn, const char *name);
R_API void r_anal_function_delete_vars_by_kind(RAnalFunction *fcn, RAnalVarKind kind);
R_API void r_anal_function_delete_all_vars(RAnalFunction *fcn);
R_API void r_anal_function_delete_unused_vars(RAnalFunction *fcn);
R_API void r_anal_function_delete_var(RAnalFunction *fcn, RAnalVar *var);
R_API bool r_anal_function_rebase_vars(RAnal *a, RAnalFunction *fcn);
R_API st64 r_anal_function_get_var_stackptr_at(RAnalFunction *fcn, st64 delta, ut64 addr);
R_API const char *r_anal_function_get_var_reg_at(RAnalFunction *fcn, st64 delta, ut64 addr);
R_API R_BORROW RPVector *r_anal_function_get_vars_used_at(RAnalFunction *fcn, ut64 op_addr);

R_API bool r_anal_var_rename(RAnalVar *var, const char *new_name, bool verbose);
R_API void r_anal_var_set_type(RAnalVar *var, const char *type);
R_API void r_anal_var_delete(RAnalVar *var);
R_API ut64 r_anal_var_addr(RAnalVar *var);
R_API void r_anal_var_set_access(RAnalVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr);
R_API void r_anal_var_remove_access_at(RAnalVar *var, ut64 address);
R_API void r_anal_var_clear_accesses(RAnalVar *var);
R_API void r_anal_var_add_constraint(RAnalVar *var, R_BORROW RAnalVarConstraint *constraint);
R_API char *r_anal_var_get_constraints_readable(RAnalVar *var);

// Get the access to var at exactly addr if there is one
R_API RAnalVarAccess *r_anal_var_get_access_at(RAnalVar *var, ut64 addr);

R_API int r_anal_var_get_argnum(RAnalVar *var);

R_API void r_anal_extract_vars(RAnal *anal, RAnalFunction *fcn, RAnalOp *op);
R_API void r_anal_extract_rarg(RAnal *anal, RAnalOp *op, RAnalFunction *fcn, int *reg_set, int *count);

// Get the variable that var is written to at one of its accesses
// Useful for cases where a register-based argument is written away into a stack variable,
// so if var is the reg arg then this will return the stack var.
R_API RAnalVar *r_anal_var_get_dst_var(RAnalVar *var);

typedef struct r_anal_function_vars_cache {
	RList *bvars;
	RList *rvars;
	RList *svars;
} RAnalFcnVarsCache;
R_API void r_anal_function_vars_cache_init(RAnal *anal, RAnalFcnVarsCache *cache, RAnalFunction *fcn);
R_API void r_anal_function_vars_cache_fini(RAnalFcnVarsCache *cache);

R_API char *r_anal_function_format_sig(R_NONNULL RAnal *anal, R_NONNULL RAnalFunction *fcn, R_NULLABLE char *fcn_name,
		R_NULLABLE RAnalFcnVarsCache *reuse_cache, R_NULLABLE const char *fcn_name_pre, R_NULLABLE const char *fcn_name_post);


/* project */
#define R_ANAL_THRESHOLDFCN 0.7F
#define R_ANAL_THRESHOLDBB 0.7F

/* diff.c */
R_API RAnalDiff *r_anal_diff_new(void);
R_API void r_anal_diff_setup(RAnal *anal, int doops, double thbb, double thfcn);
R_API void r_anal_diff_setup_i(RAnal *anal, int doops, int thbb, int thfcn);
R_API void r_anal_diff_free(RAnalDiff *diff);
R_API int r_anal_diff_fingerprint_bb(RAnal *anal, RAnalBlock *bb);
R_API size_t r_anal_diff_fingerprint_fcn(RAnal *anal, RAnalFunction *fcn);
R_API bool r_anal_diff_bb(RAnal *anal, RAnalFunction *fcn, RAnalFunction *fcn2);
R_API int r_anal_diff_fcn(RAnal *anal, RList *fcns, RList *fcns2);
R_API int r_anal_diff_eval(RAnal *anal);

R_API RAnalCond *r_anal_cond_new(void);
R_API RAnalCond *r_anal_cond_new_from_op(RAnalOp *op);
R_API void r_anal_cond_fini(RAnalCond *c);
R_API void r_anal_cond_free(RAnalCond *c);
R_API char *r_anal_cond_tostring(RAnalCond *cond);
R_API int r_anal_cond_eval(RAnal *anal, RAnalCond *cond);
R_API RAnalCond *r_anal_cond_new_from_string(const char *str);
R_API const char *r_anal_cond_type_tostring(int cc);

/* jmptbl */
R_API bool r_anal_jmptbl(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr);

// TODO: should be renamed
R_API bool try_get_delta_jmptbl_info(RAnal *a, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift);
R_API bool try_walkthrough_jmptbl(RAnal *analysis, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
R_API bool try_walkthrough_casetbl(RAnal *analysis, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, st64 start_casenum_shift, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0);
R_API bool try_get_jmptbl_info(RAnal *analysis, RAnalFunction *fcn, ut64 addr, RAnalBlock *my_bb, ut64 *table_size, ut64 *default_case, st64 *start_casenum_shift);
R_API int walkthrough_arm_jmptbl_style(RAnal *anal, RAnalFunction *fcn, RAnalBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0);

/* reflines.c */
R_API RList* /*<RAnalRefline>*/ r_anal_reflines_get(RAnal *anal,
		ut64 addr, const ut8 *buf, ut64 len, int nlines, int linesout, int linescall);
R_API int r_anal_reflines_middle(RAnal *anal, RList *list, ut64 addr, int len);
R_API RAnalRefStr *r_anal_reflines_str(void *core, ut64 addr, int opts);
R_API void r_anal_reflines_str_free(RAnalRefStr *refstr);
/* TODO move to r_core */
R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode, PJ* pj);
R_API RList *r_anal_var_list(RAnal *anal, RAnalFunction *fcn, int kind);

// calling conventions API
R_API bool r_anal_cc_exist(RAnal *anal, const char *convention);
R_API void r_anal_cc_reset(RAnal *anal);
R_API void r_anal_cc_del(RAnal *anal, const char *name);
R_API bool r_anal_cc_set(RAnal *anal, const char *expr);
R_API char *r_anal_cc_get(RAnal *anal, const char *name);
R_API bool r_anal_cc_once(RAnal *anal);
R_API void r_anal_cc_get_json(RAnal *anal, PJ *pj, const char *name);
R_API const char *r_anal_cc_arg(RAnal *anal, const char *convention, int n, int lastn);
R_API const char *r_anal_cc_self(RAnal *anal, const char *convention);
R_API void r_anal_cc_set_self(RAnal *anal, const char *convention, const char *self);
R_API const char *r_anal_cc_error(RAnal *anal, const char *convention);
R_API void r_anal_cc_set_error(RAnal *anal, const char *convention, const char *error);
R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc);
R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention);
R_API const char *r_anal_cc_default(RAnal *anal);
R_API void r_anal_set_cc_default(RAnal *anal, const char *convention);
R_API const char *r_anal_syscc_default(RAnal *anal);
R_API void r_anal_set_syscc_default(RAnal *anal, const char *convention);
R_API const char *r_anal_cc_func(RAnal *anal, const char *func_name);
R_API bool r_anal_noreturn_at(RAnal *anal, ut64 addr);

typedef struct r_anal_data_t {
	ut64 addr;
	int type;
	ut64 ptr;
	char *str;
	int len;
	ut8 *buf;
	ut8 sbuf[8];
} RAnalData;

R_API RAnalData *r_anal_data(RAnal *anal, ut64 addr, const ut8 *buf, int size, int wordsize);
R_API const char *r_anal_data_kind(RAnal *anal, ut64 addr, const ut8 *buf, int len);
R_API int r_anal_data_type(RAnal *a, ut64 da);
R_API RAnalData *r_anal_data_new_string(ut64 addr, const char *p, int size, int wide);
R_API RAnalData *r_anal_data_new(ut64 addr, int type, ut64 n, const ut8 *buf, int len);
R_API void r_anal_data_free(RAnalData *d);
#include <r_cons.h>
R_API char *r_anal_data_tostring(RAnalData *d, RConsPrintablePalette *pal);

/* meta
 *
 * Meta uses Condret's Klemmbaustein Priciple, i.e. intervals are defined inclusive/inclusive.
 * A meta item from 0x42 to 0x42 has a size of 1. Items with size 0 do not exist.
 * Meta items are allowed to overlap and the internal data structure allows for multiple meta items
 * starting at the same address.
 * Meta items are saved in an RIntervalTree. To access the interval of an item, use the members of RIntervalNode.
 */

static inline ut64 r_meta_item_size(ut64 start, ut64 end) {
	// meta items use inclusive/inclusive intervals
	return end - start + 1;
}

static inline ut64 r_meta_node_size(RIntervalNode *node) {
	return r_meta_item_size (node->start, node->end);
}

// Set a meta item at addr with the given contents in the current space.
// If there already exists an item with this type and space at addr (regardless of its size) it will be overwritten.
R_API bool r_meta_set(RAnal *a, RAnalMetaType type, ut64 addr, ut64 size, const char *str);

// Same as r_meta_set() but also sets the subtype.
R_API bool r_meta_set_with_subtype(RAnal *m, RAnalMetaType type, int subtype, ut64 addr, ut64 size, const char *str);

// Delete all meta items in the current space that intersect with the given interval.
// If size == UT64_MAX, everything in the current space will be deleted.
R_API void r_meta_del(RAnal *a, RAnalMetaType type, ut64 addr, ut64 size);

// Same as r_meta_set() with a size of 1.
R_API bool r_meta_set_string(RAnal *a, RAnalMetaType type, ut64 addr, const char *s);

// Convenience function to get the str content of the item at addr with given type in the current space.
R_API const char *r_meta_get_string(RAnal *a, RAnalMetaType type, ut64 addr);

// Convenience function to add an R_META_TYPE_DATA item at the given addr in the current space.
R_API void r_meta_set_data_at(RAnal *a, ut64 addr, ut64 wordsz);

// Returns the item with given type that starts at addr in the current space or NULL. The size of this item  optionally returned through size.
R_API RAnalMetaItem *r_meta_get_at(RAnal *a, ut64 addr, RAnalMetaType type, R_OUT R_NULLABLE ut64 *size);

// Returns the node for one meta item with the given type that contains addr in the current space or NULL.
// To get all the nodes, use r_meta_get_all_in().
R_API RIntervalNode *r_meta_get_in(RAnal *a, ut64 addr, RAnalMetaType type);

// Returns all nodes for items starting at the given address in the current space.
R_API RPVector/*<RIntervalNode<RMetaItem> *>*/ *r_meta_get_all_at(RAnal *a, ut64 at);

// Returns all nodes for items with the given type containing the given address in the current space.
R_API RPVector/*<RIntervalNode<RMetaItem> *>*/ *r_meta_get_all_in(RAnal *a, ut64 at, RAnalMetaType type);

// Returns all nodes for items with the given type intersecting the given interval in the current space.
R_API RPVector/*<RIntervalNode<RMetaItem> *>*/ *r_meta_get_all_intersect(RAnal *a, ut64 start, ut64 size, RAnalMetaType type);

// Delete all meta items in the given space
R_API void r_meta_space_unset_for(RAnal *a, const RSpace *space);

// Returns the number of meta items in the given space
R_API int r_meta_space_count_for(RAnal *a, const RSpace *space);

// Shift all meta items by the given delta, for rebasing between different memory layouts.
R_API void r_meta_rebase(RAnal *anal, ut64 diff);

// Calculate the total size covered by meta items of the given type.
R_API ut64 r_meta_get_size(RAnal *a, RAnalMetaType type);

R_API const char *r_meta_type_tostring(int type);
R_API void r_meta_print(RAnal *a, RAnalMetaItem *d, ut64 start, ut64 size, int rad, PJ *pj, bool show_full);
R_API void r_meta_print_list_all(RAnal *a, int type, int rad, const char *tq);
R_API void r_meta_print_list_at(RAnal *a, ut64 addr, int rad, const char *tq);
R_API void r_meta_print_list_in_function(RAnal *a, int type, int rad, ut64 addr, const char *tq);

/* hints */

R_API void r_anal_hint_del(RAnal *anal, ut64 addr, ut64 size); // delete all hints that are contained within the given range, if size > 1, this operation is quite heavy!
R_API void r_anal_hint_clear(RAnal *a);
R_API void r_anal_hint_free(RAnalHint *h);
R_API void r_anal_hint_set_syntax(RAnal *a, ut64 addr, const char *syn);
R_API void r_anal_hint_set_type(RAnal *a, ut64 addr, int type);
R_API void r_anal_hint_set_jump(RAnal *a, ut64 addr, ut64 jump);
R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 fail);
R_API void r_anal_hint_set_newbits(RAnal *a, ut64 addr, int bits);
R_API void r_anal_hint_set_nword(RAnal *a, ut64 addr, int nword);
R_API void r_anal_hint_set_offset(RAnal *a, ut64 addr, const char *typeoff);
R_API void r_anal_hint_set_immbase(RAnal *a, ut64 addr, int base);
R_API void r_anal_hint_set_size(RAnal *a, ut64 addr, ut64 size);
R_API void r_anal_hint_set_opcode(RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_esil(RAnal *a, ut64 addr, const char *str);
R_API void r_anal_hint_set_pointer(RAnal *a, ut64 addr, ut64 ptr);
R_API void r_anal_hint_set_ret(RAnal *a, ut64 addr, ut64 val);
R_API void r_anal_hint_set_high(RAnal *a, ut64 addr);
R_API void r_anal_hint_set_stackframe(RAnal *a, ut64 addr, ut64 size);
R_API void r_anal_hint_set_val(RAnal *a, ut64 addr, ut64 v);
R_API void r_anal_hint_set_arch(RAnal *a, ut64 addr, R_NULLABLE const char *arch); // arch == NULL => use global default
R_API void r_anal_hint_set_bits(RAnal *a, ut64 addr, int bits); // bits == NULL => use global default
R_API void r_anal_hint_unset_val(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_high(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_immbase(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_nword(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_size(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_type(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_esil(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_opcode(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_syntax(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_pointer(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_ret(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_offset(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_jump(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_fail(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_newbits(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_stackframe(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_arch(RAnal *a, ut64 addr);
R_API void r_anal_hint_unset_bits(RAnal *a, ut64 addr);
R_API R_NULLABLE const RVector/*<const RAnalAddrHintRecord>*/ *r_anal_addr_hints_at(RAnal *anal, ut64 addr);
typedef bool (*RAnalAddrHintRecordsCb)(ut64 addr, const RVector/*<const RAnalAddrHintRecord>*/ *records, void *user);
R_API void r_anal_addr_hints_foreach(RAnal *anal, RAnalAddrHintRecordsCb cb, void *user);
typedef bool (*RAnalArchHintCb)(ut64 addr, R_NULLABLE const char *arch, void *user);
R_API void r_anal_arch_hints_foreach(RAnal *anal, RAnalArchHintCb cb, void *user);
typedef bool (*RAnalBitsHintCb)(ut64 addr, int bits, void *user);
R_API void r_anal_bits_hints_foreach(RAnal *anal, RAnalBitsHintCb cb, void *user);

// get the hint-specified arch value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
R_API R_NULLABLE R_BORROW const char *r_anal_hint_arch_at(RAnal *anal, ut64 addr, R_NULLABLE ut64 *hint_addr);

// get the hint-specified bits value to be considered at addr
// hint_addr will optionally be set to the address where the hint that specifies this arch is placed or UT64_MAX
// if there is no hint affecting addr.
R_API int r_anal_hint_bits_at(RAnal *anal, ut64 addr, R_NULLABLE ut64 *hint_addr);

R_API RAnalHint *r_anal_hint_get(RAnal *anal, ut64 addr); // accumulate all available hints affecting the given address

/* cycles.c */
R_API RAnalCycleFrame* r_anal_cycle_frame_new(void);
R_API void r_anal_cycle_frame_free(RAnalCycleFrame *cf);

/* labels */
R_API ut64 r_anal_function_get_label(RAnalFunction *fcn, const char *name);
R_API const char *r_anal_function_get_label_at(RAnalFunction *fcn, ut64 addr);
R_API bool r_anal_function_set_label(RAnalFunction *fcn, const char *name, ut64 addr);
R_API bool r_anal_function_delete_label(RAnalFunction *fcn, const char *name);
R_API bool r_anal_function_delete_label_at(RAnalFunction *fcn, ut64 addr);

/* limits */
R_API void r_anal_set_limits(RAnal *anal, ut64 from, ut64 to);
R_API void r_anal_unset_limits(RAnal *anal);

/* ESIL to REIL */
R_API int r_esil_to_reil_setup(REsil *esil, RAnal *anal, int romem, int stats);

/* no-return stuff */
R_API void r_anal_noreturn_list(RAnal *anal, int mode);
R_API bool r_anal_noreturn_add(RAnal *anal, const char *name, ut64 addr);
R_API bool r_anal_noreturn_drop(RAnal *anal, const char *expr);
R_API bool r_anal_noreturn_at_addr(RAnal *anal, ut64 addr);

/* zign spaces */
R_API int r_sign_space_count_for(RAnal *a, const RSpace *space);
R_API void r_sign_space_unset_for(RAnal *a, const RSpace *space);
R_API void r_sign_space_rename_for(RAnal *a, const RSpace *space, const char *oname, const char *nname);

/* vtables */
typedef struct {
	RAnal *anal;
	RAnalCPPABI abi;
	ut8 word_size;
	bool (*read_addr) (RAnal *anal, ut64 addr, ut64 *buf);
} RVTableContext;

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	RVector methods;
} RVTableInfo;

typedef struct vtable_method_info_t {
	ut64 addr;           // addr of the function
	ut64 vtable_offset;  // offset inside the vtable
} RVTableMethodInfo;

R_API void r_anal_vtable_info_free(RVTableInfo *vtable);
R_API ut64 r_anal_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable);
R_API bool r_anal_vtable_begin(RAnal *anal, RVTableContext *context);
R_API RVTableInfo *r_anal_vtable_parse_at(RVTableContext *context, ut64 addr);
R_API RList *r_anal_vtable_search(RVTableContext *context);
R_API void r_anal_list_vtables(RAnal *anal, int rad);

/* rtti */
R_API char *r_anal_rtti_msvc_demangle_class_name(RVTableContext *context, const char *name);
R_API void r_anal_rtti_msvc_print_complete_object_locator(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_type_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_class_hierarchy_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_msvc_print_base_class_descriptor(RVTableContext *context, ut64 addr, int mode);
R_API bool r_anal_rtti_msvc_print_at_vtable(RVTableContext *context, ut64 addr, int mode, bool strict);
R_API void r_anal_rtti_msvc_recover_all(RVTableContext *vt_context, RList *vtables);

R_API char *r_anal_rtti_itanium_demangle_class_name(RVTableContext *context, const char *name);
R_API void r_anal_rtti_itanium_print_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_print_si_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_print_vmi_class_type_info(RVTableContext *context, ut64 addr, int mode);
R_API bool r_anal_rtti_itanium_print_at_vtable(RVTableContext *context, ut64 addr, int mode);
R_API void r_anal_rtti_itanium_recover_all(RVTableContext *vt_context, RList *vtables);

R_API char *r_anal_rtti_demangle_class_name(RAnal *anal, const char *name);
R_API void r_anal_rtti_print_at_vtable(RAnal *anal, ut64 addr, int mode);
R_API void r_anal_rtti_print_all(RAnal *anal, int mode);
R_API void r_anal_rtti_recover_all(RAnal *anal);

R_API RList *r_anal_preludes(RAnal *anal);
R_API bool r_anal_is_prelude(RAnal *anal, ut64 addr, const ut8 *data, int len);

/* classes */
typedef struct r_anal_method_t {
	char *name;
	ut64 addr;
	st64 vtable_offset; // >= 0 if method is virtual, else -1
} RAnalMethod;

typedef struct r_anal_base_class_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset of the base class inside the derived class
	char *class_name;
} RAnalBaseClass;

typedef struct r_anal_vtable_t {
	char *id; // id to identify the class attr
	ut64 offset; // offset inside the class
	ut64 addr; // where the content of the vtable is
	ut64 size; // size (in bytes) of the vtable
} RAnalVTable;

typedef enum {
	R_ANAL_CLASS_ERR_SUCCESS = 0,
	R_ANAL_CLASS_ERR_CLASH,
	R_ANAL_CLASS_ERR_NONEXISTENT_ATTR,
	R_ANAL_CLASS_ERR_NONEXISTENT_CLASS,
	R_ANAL_CLASS_ERR_OTHER
} RAnalClassErr;

/* c */
R_API char *r_anal_cparse(RAnal *anal, const char *code, char **error_msg);
R_API char *r_anal_cparse_file(RAnal *anal, const char *path, const char *dir, char **error_msg);

R_API void r_anal_class_create(RAnal *anal, const char *name);
R_API void r_anal_class_delete(RAnal *anal, const char *name);
R_API bool r_anal_class_exists(RAnal *anal, const char *name);
R_API SdbList *r_anal_class_get_all(RAnal *anal, bool sorted);
R_API void r_anal_class_foreach(RAnal *anal, SdbForeachCallback cb, void *user);
R_API RAnalClassErr r_anal_class_rename(RAnal *anal, const char *old_name, const char *new_name);

R_API void r_anal_class_method_fini(RAnalMethod *meth);
R_API RAnalClassErr r_anal_class_method_get(RAnal *anal, const char *class_name, const char *meth_name, RAnalMethod *meth);
R_API RVector/*<RAnalMethod>*/ *r_anal_class_method_get_all(RAnal *anal, const char *class_name);
R_API RAnalClassErr r_anal_class_method_set(RAnal *anal, const char *class_name, RAnalMethod *meth);
R_API RAnalClassErr r_anal_class_method_rename(RAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name);
R_API RAnalClassErr r_anal_class_method_delete(RAnal *anal, const char *class_name, const char *meth_name);

R_API void r_anal_class_base_fini(RAnalBaseClass *base);
R_API RAnalClassErr r_anal_class_base_get(RAnal *anal, const char *class_name, const char *base_id, RAnalBaseClass *base);
R_API RVector/*<RAnalBaseClass>*/ *r_anal_class_base_get_all(RAnal *anal, const char *class_name);
R_API RAnalClassErr r_anal_class_base_set(RAnal *anal, const char *class_name, RAnalBaseClass *base);
R_API RAnalClassErr r_anal_class_base_delete(RAnal *anal, const char *class_name, const char *base_id);

R_API void r_anal_class_vtable_fini(RAnalVTable *vtable);
R_API RAnalClassErr r_anal_class_vtable_get(RAnal *anal, const char *class_name, const char *vtable_id, RAnalVTable *vtable);
R_API RVector/*<RAnalVTable>*/ *r_anal_class_vtable_get_all(RAnal *anal, const char *class_name);
R_API RAnalClassErr r_anal_class_vtable_set(RAnal *anal, const char *class_name, RAnalVTable *vtable);
R_API RAnalClassErr r_anal_class_vtable_delete(RAnal *anal, const char *class_name, const char *vtable_id);

R_API void r_anal_class_print(RAnal *anal, const char *class_name, bool detailed);
R_API void r_anal_class_json(RAnal *anal, PJ *j, const char *class_name);
R_API void r_anal_class_list(RAnal *anal, int mode);
R_API void r_anal_class_list_bases(RAnal *anal, const char *class_name);
R_API void r_anal_class_list_vtables(RAnal *anal, const char *class_name);
R_API void r_anal_class_list_vtable_offset_functions(RAnal *anal, const char *class_name, ut64 offset);
R_API RGraph/*<RGraphNodeInfo>*/ *r_anal_class_get_inheritance_graph(RAnal *anal);

R_API RAnalEsilCFG *r_anal_esil_cfg_new(void);
R_API RAnalEsilCFG *r_anal_esil_cfg_expr(RAnalEsilCFG *cfg, RAnal *anal, const ut64 off, char *expr);
R_API RAnalEsilCFG *r_anal_esil_cfg_op(RAnalEsilCFG *cfg, RAnal *anal, RAnalOp *op);
R_API void r_anal_esil_cfg_merge_blocks(RAnalEsilCFG *cfg);
R_API void r_anal_esil_cfg_free(RAnalEsilCFG *cfg);
R_API SdbGperf *r_anal_get_gperf_cc(const char *k);
R_API SdbGperf *r_anal_get_gperf_types(const char *k);

R_API RAnalEsilDFGNode *r_anal_esil_dfg_node_new(RAnalEsilDFG *edf, const char *c);
R_API RAnalEsilDFG *r_anal_esil_dfg_new(RAnal *anal, bool use_map_info, bool use_maps);
R_API void r_anal_esil_dfg_free(RAnalEsilDFG *dfg);
R_API RAnalEsilDFG *r_anal_esil_dfg_expr(RAnal *anal, RAnalEsilDFG *dfg, const char *expr, bool use_map_info, bool use_maps);
R_API void r_anal_esil_dfg_fold_const(RAnal *anal, RAnalEsilDFG *dfg);
R_API RStrBuf *r_anal_esil_dfg_filter(RAnalEsilDFG *dfg, const char *reg);
R_API RStrBuf *r_anal_esil_dfg_filter_expr(RAnal *anal, const char *expr, const char *reg, bool use_map_info, bool use_maps);
R_API bool r_anal_esil_dfg_reg_is_const(RAnalEsilDFG *dfg, const char *reg);
R_API RList *r_anal_types_from_fcn(RAnal *anal, RAnalFunction *fcn);

R_API RAnalBaseType *r_anal_get_base_type(RAnal *anal, const char *name);
R_API void r_parse_pdb_types(const RAnal *anal, const RPdb *pdb);
R_API void r_anal_save_base_type(const RAnal *anal, const RAnalBaseType *type);
R_API void r_anal_base_type_free(RAnalBaseType *type);
R_API RAnalBaseType *r_anal_base_type_new(RAnalBaseTypeKind kind);
R_API void r_anal_dwarf_process_info(const RAnal *anal, RAnalDwarfContext *ctx);
R_API void r_anal_dwarf_integrate_functions(RAnal *anal, RFlag *flags, Sdb *dwarf_sdb);
/* global.c */
R_API RFlagItem *r_anal_global_get(RAnal *anal, ut64 addr);
R_API bool r_anal_global_add(RAnal *anal, ut64 addr, const char *type_name, const char *name);
R_API bool r_anal_global_del(RAnal *anal, ut64 addr);
R_API bool r_anal_global_retype(RAnal *anal, ut64 addr, const char *new_type);
R_API bool r_anal_global_rename(RAnal *anal, ut64 addr, const char *new_name);
R_API const char *r_anal_global_get_type(RAnal *anal, ut64 addr);
/*return anal->is_dirty and sets it to false*/
R_API bool r_anal_is_dirty(RAnal *anal);

// threads
R_API bool r_anal_tid_kill(RAnal *anal, int tid);
R_API RAnalThread *r_anal_tid_get(RAnal *anal, int tid);
R_API int r_anal_tid_add(RAnal *anal, int map);
R_API bool r_anal_tid_select(RAnal *anal, int tid);

/* plugin pointers */
extern RAnalPlugin r_anal_plugin_null;
extern RAnalPlugin r_anal_plugin_a2f;

#ifdef __cplusplus
}
#endif

#endif
#endif
