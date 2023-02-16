/* radare2 - LGPL - Copyright 2022 - pancake */

#ifndef R_ESIL_H
#define R_ESIL_H

#include <r_reg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)
// only flags that affect control flow
enum {
	R_ESIL_FLAG_ZERO = 1,
	R_ESIL_FLAG_CARRY = 2,
	R_ESIL_FLAG_OVERFLOW = 4,
	R_ESIL_FLAG_PARITY = 8,
	R_ESIL_FLAG_SIGN = 16,
	// ...
};

#define ESIL_INTERNAL_PREFIX '$'
#define ESIL_STACK_NAME "esil.ram"

typedef struct r_esil_t ESIL;

typedef bool (*REsilHandlerCB)(ESIL *esil, ut32 h, void *user);

typedef struct r_esil_handler_t {
	REsilHandlerCB cb;
	void *user;
} REsilHandler;

typedef struct r_esil_change_reg_t {
	int idx;
	ut64 data;
} REsilRegChange;

typedef struct r_esil_change_mem_t {
	int idx;
	ut8 data;
} REsilMemChange;

typedef struct r_esil_trace_t {
	int idx;
	int end_idx;
	HtUP *registers;
	HtUP *memory;
	RRegArena *arena[R_REG_TYPE_LAST];
	ut64 stack_addr;
	ut64 stack_size;
	ut8 *stack_data;
	//TODO remove `db` and reuse info above
	Sdb *db;
} REsilTrace;

typedef bool (*REsilHookRegWriteCB)(ESIL *esil, const char *name, ut64 *val);

typedef struct r_esil_callbacks_t {
	void *user;
	/* callbacks */
	bool (*hook_flag_read)(ESIL *esil, const char *flag, ut64 *num);
	bool (*hook_command)(ESIL *esil, const char *op);
	bool (*hook_mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	bool (*mem_read)(ESIL *esil, ut64 addr, ut8 *buf, int len);
	bool (*hook_mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	bool (*mem_write)(ESIL *esil, ut64 addr, const ut8 *buf, int len);
	bool (*hook_reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	bool (*reg_read)(ESIL *esil, const char *name, ut64 *res, int *size);
	REsilHookRegWriteCB hook_reg_write;
	bool (*reg_write)(ESIL *esil, const char *name, ut64 val);
} REsilCallbacks;

#if R2_590
typedef struct r_esil_options_t {
	int nowrite;
	int iotrap;
	int exectrap;
} REsilOptions;
#endif

typedef struct r_esil_t {
	struct r_anal_t *anal; // XXX maybe just use arch?
	char **stack;
	ut64 addrmask;
	int stacksize;
	int stackptr;
	ut32 skip;
	int nowrite;
	int iotrap;
	int exectrap;
	int parse_stop;
	int parse_goto;
	int parse_goto_count;
	int verbose;
	ut64 flags;
	ut64 address;
	ut64 stack_addr;
	ut32 stack_size;
	int delay; 		// mapped to $ds in ESIL
	ut64 jump_target; 	// mapped to $jt in ESIL
	int jump_target_set; 	// mapped to $js in ESIL
	int trap;
	int data_align;
	ut32 trap_code; // extend into a struct to store more exception info?
	// parity flag? done with cur
	ut64 old;	//used for carry-flagging and borrow-flagging
	ut64 cur;	//used for carry-flagging and borrow-flagging
	ut8 lastsz;	//in bits //used for signature-flag
	/* native ops and custom ops */
	HtPP *ops;
	char *current_opstr;
	SdbMini *interrupts;
	SdbMini *syscalls;
	//this is a disgusting workaround, because we have no ht-like storage without magic keys, that you cannot use, with int-keys
	REsilHandler *intr0;
	REsilHandler *sysc0;
	RList *plugins;
	RList *active_plugins;
	/* deep esil parsing fills this */
	Sdb *stats;
	REsilTrace *trace;
	REsilCallbacks cb;
#if 0
	struct r_anal_reil_t *Reil;
#endif
	char *pending; // pending op computed as a macro
	// this is so cursed, can we please remove external commands from esil internals.
	// Function pointers are fine, but not commands
	char *cmd_step; // r2 (external) command to run before a step is performed
	char *cmd_step_out; // r2 (external) command to run after a step is performed
	char *cmd_intr; // r2 (external) command to run when an interrupt occurs
	char *cmd_trap; // r2 (external) command to run when a trap occurs
	char *cmd_mdev; // r2 (external) command to run when an memory mapped device address is used
	char *cmd_todo; // r2 (external) command to run when esil expr contains TODO
	char *cmd_ioer; // r2 (external) command to run when esil fails to IO
	char *mdev_range; // string containing the r_str_range to match for read/write accesses
	bool (*cmd)(ESIL *esil, const char *name, ut64 a0, ut64 a1);
	void *user;
	int stack_fd;	// ahem, let's not do this
	bool in_cmd_step;
} REsil;

enum {
	R_ESIL_PARM_INVALID = 0,
	R_ESIL_PARM_REG,
	R_ESIL_PARM_NUM,
};

typedef struct r_anal_ref_char_t {
	char *str;
	char *cols;
} RAnalRefStr;

#if 0

/* reil -- must be deprecated */
/* Constructs to convert from ESIL to REIL */
#define FOREACHOP(GENERATE)                     \
/* No Operation */               GENERATE(NOP)  \
/* Unknown/Undefined */          GENERATE(UNK)  \
/* Conditional Jump */           GENERATE(JCC)  \
/* Store Value to register */    GENERATE(STR)  \
/* Store value to memory */      GENERATE(STM)  \
/* Load value from memory */     GENERATE(LDM)  \
/* Addition */                   GENERATE(ADD)  \
/* Subtraction */                GENERATE(SUB)  \
/* Negation */                   GENERATE(NEG)  \
/* Multiplication */             GENERATE(MUL)  \
/* Division */                   GENERATE(DIV)  \
/* Modulo */                     GENERATE(MOD)  \
/* Signed Multiplication */      GENERATE(SMUL) \
/* Sugned Division */            GENERATE(SDIV) \
/* Signed Modulus */             GENERATE(SMOD) \
/* Shift Left */                 GENERATE(SHL)  \
/* Shift Right */                GENERATE(SHR)  \
/* Binary and */                 GENERATE(AND)  \
/* Binary or */                  GENERATE(OR)   \
/* Binary xor */                 GENERATE(XOR)  \
/* Binary not */                 GENERATE(NOT)  \
/* Equation */                   GENERATE(EQ)   \
/* Less Than */                  GENERATE(LT)

#define MAKE_ENUM(OP) REIL_##OP,
#define REIL_OP_STRING(STRING) #STRING,

typedef enum {
	FOREACHOP(MAKE_ENUM)
} RAnalReilOpcode;

typedef enum {
	ARG_REG,           // CPU Register
	ARG_TEMP,          // Temporary register used by REIL
	ARG_CONST,         // Constant value
	ARG_ESIL_INTERNAL, // Used to resolve ESIL internal flags
	ARG_NONE           // Operand not used by the instruction
} RAnalReilArgType;

// Arguments to a REIL instruction.
typedef struct r_anal_reil_arg {
	RAnalReilArgType type; // Type of the argument
	ut8 size;              // Size of the argument in bytes
	char name[32];         // Name of the argument
} RAnalReilArg;

// Instruction arg1, arg2, arg3
typedef struct r_anal_reil_inst_t {
	RAnalReilOpcode opcode;
	RAnalReilArg *arg[3];
} RAnalReilInst;

typedef struct r_anal_reil_t {
	char old[32]; // Used to compute flags.
	char cur[32];
	ut8 lastsz;
	ut64 reilNextTemp;   // Used to store the index of the next REIL temp register to be used.
	ut64 addr;           // Used for instruction sequencing. Check esil2reil.c for details.
	ut8 seq_num;         // Incremented and used when noInc is set to 1.
	int skip;
	int cmd_count;
	char if_buf[64];
	char pc[8];
} RAnalReil;
#endif

typedef struct r_esil_plugin_t {
	char *name;
	char *desc;
	char *license;
	char *arch;
	char *author;
	char *version;
	void *(*init)(REsil *esil);			// can allocate stuff and return that
	void (*fini)(REsil *esil, void *user);	// deallocates allocated things from init
} REsilPlugin;

// Some kind of container, pointer to plugin + pointer to user
typedef struct r_esil_active_plugin_t {
	REsilPlugin *plugin;
	void *user;
} REsilActivePlugin;


extern REsilPlugin r_esil_plugin_dummy;

#ifdef __cplusplus
}
#endif

#endif
