/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#ifndef OPCODE_H
#define OPCODE_H

#include <r_types.h>
#include <r_list.h>
#include <r_util.h>
#include <r_anal.h>

#define OBJECT_SIZE_ON_STACK 1

typedef enum {
	HASCOMPARE = 0x1,
	HASCONDITION = 0x2, // conditional operator; has jump offset
	HASCONST = 0x4,
	HASFREE = 0x8,
	HASJABS = 0x10, // Will appear with HASCONDITION sometimes
	HASJREL = 0x20, // Will appear with HASCONDITION sometimes
	HASLOCAL = 0x40,
	HASNAME = 0x80,
	HASNARGS = 0x100, // For function-like calls
	HASSTORE = 0x200, // Some sort of store operation
	HASVARGS = 0x400, // Similar but for operators BUILD_xxx
	NOFOLLOW = 0x800, // Instruction doesn't fall to the next opcode
} pyc_opcode_type;

typedef enum {
	NAME_OP = 0x1,
	LOCAL_OP = 0x2,
	FREE_OP = 0x4,
	DEF_OP = 0x8,
} pyc_store_op_func;

typedef struct {
	char *op_name;
	ut16 type;
	ut8 op_code;
	st8 op_push;
	st8 op_pop;
} pyc_opcode_object;

typedef struct {
	ut8 extended_arg;
	ut8 have_argument;
	ut8 bits;
	void *(*version_sig)();
	RList *opcode_arg_fmt;
	pyc_opcode_object *opcodes;
} pyc_opcodes;

typedef struct {
	char *op_name;
	const char *(*formatter)(ut32 oparg);
} pyc_arg_fmt;

typedef struct {
	char *version;
	pyc_opcodes *(*opcode_func)();
} version_opcode;

typedef struct {
	char *op_name;
	void (*func)(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg);
} op_anal_func;

void anal_pyc_op(RAnalOp *op, pyc_opcode_object *op_obj, ut32 oparg);

pyc_opcodes *opcode_2x(void);
pyc_opcodes *opcode_3x(void);
pyc_opcodes *opcode_10(void);
pyc_opcodes *opcode_11(void);
pyc_opcodes *opcode_12(void);
pyc_opcodes *opcode_13(void);
pyc_opcodes *opcode_14(void);
pyc_opcodes *opcode_15(void);
pyc_opcodes *opcode_16(void);
pyc_opcodes *opcode_20(void);
pyc_opcodes *opcode_21(void);
pyc_opcodes *opcode_22(void);
pyc_opcodes *opcode_23(void);
pyc_opcodes *opcode_24(void);
pyc_opcodes *opcode_25(void);
pyc_opcodes *opcode_26(void);
pyc_opcodes *opcode_27(void);
pyc_opcodes *opcode_30(void);
pyc_opcodes *opcode_31(void);
pyc_opcodes *opcode_32(void);
pyc_opcodes *opcode_33(void);
pyc_opcodes *opcode_34(void);
pyc_opcodes *opcode_35(void);
pyc_opcodes *opcode_36(void);
pyc_opcodes *opcode_37(void);
pyc_opcodes *opcode_38(void);
pyc_opcodes *opcode_39(void);

pyc_opcodes *get_opcode_by_version(char *version);

pyc_opcodes *new_pyc_opcodes();
void free_opcode(pyc_opcodes *opcodes);
bool pyc_opcodes_equal(pyc_opcodes *op, const char *version);

void add_arg_fmt(pyc_opcodes *ret, char *op_name, const char *(*formatter) (ut32 oparg));

const char *format_MAKE_FUNCTION_arg_3x(ut32 oparg);
const char *format_extended_arg(ut32 oparg);
const char *format_CALL_FUNCTION_pos_name_encoded(ut32 oparg);
const char *format_CALL_FUNCTION_KW_36(ut32 oparg);
const char *format_CALL_FUNCTION_EX_36(ut32 oparg);
const char *format_MAKE_FUNCTION_arg_36(ut32 oparg);
const char *format_value_flags_36(ut32 oparg);
const char *format_extended_arg_36(ut32 oparg);

struct op_parameter {
	pyc_opcode_object *op_obj;
	const char *op_name;
	ut8 op_code;
	st8 pop;
	st8 push;
	pyc_store_op_func func;
	bool conditional;
	bool fallthrough;
};

#define def_op(...) def_opN((struct op_parameter){ .fallthrough = true, __VA_ARGS__ })
#define def_op0(...) def_opN((struct op_parameter){ .pop = -2, .push = -2, .fallthrough = true, __VA_ARGS__ })
#define def_op00(...) def_opN((struct op_parameter){ __VA_ARGS__ })
void (def_opN)(struct op_parameter par);

#define name_op0(...) name_opN((struct op_parameter){ .pop = -2, .push = -2, __VA_ARGS__ })
#define name_op(...) name_opN((struct op_parameter){ __VA_ARGS__ })
void (name_opN)(struct op_parameter par);

#define local_op0(...) local_opN((struct op_parameter){ .pop = 0, .push = 1, __VA_ARGS__ })
#define local_op(...) local_opN((struct op_parameter){  __VA_ARGS__ })
void (local_opN)(struct op_parameter par);

#define free_op0(...) free_opN((struct op_parameter){ .pop = 0, .push = 1, __VA_ARGS__ })
#define free_op(...) free_opN((struct op_parameter){ __VA_ARGS__ })
void (free_opN)(struct op_parameter par);

#define store_op00(...) store_opN((struct op_parameter){ __VA_ARGS__ })
#define store_op(...) store_opN((struct op_parameter){ .func = DEF_OP, __VA_ARGS__ })
#define store_op0(...) store_opN((struct op_parameter){ .pop = 0, .push = 1, .func = DEF_OP, __VA_ARGS__ })
void (store_opN)(struct op_parameter par);

#define varargs_op(...) varargs_op((struct op_parameter){ __VA_ARGS__ })
#define varargs_op0(...) varargs_op((struct op_parameter){ .pop = -1, .push = 1, __VA_ARGS__ })
void (varargs_op)(struct op_parameter par);

#define const_op(...) const_opN((struct op_parameter){ .pop = 0, .push = 1, __VA_ARGS__ })
#define const_op00(...) const_opN((struct op_parameter){ __VA_ARGS__ })
void (const_opN)(struct op_parameter par);

#define compare_op0(...) compare_op((struct op_parameter){ .pop = 2, .push = 1, __VA_ARGS__ })
#define compare_op(...) compare_op((struct op_parameter){ __VA_ARGS__ })
void (compare_op)(struct op_parameter par);

#define jabs_op00(...) jabs_opN((struct op_parameter){ __VA_ARGS__ })
#define jabs_op0(...) jabs_opN((struct op_parameter){ .pop = 0, .push = 0, .conditional = false, .fallthrough = true, __VA_ARGS__ })
#define jabs_op(...) jabs_opN((struct op_parameter){ .fallthrough = true, __VA_ARGS__ })
void (jabs_opN)(struct op_parameter par);

#define jrel_op00(...) jrel_opN((struct op_parameter){ __VA_ARGS__ })
#define jrel_op0(...) jrel_opN((struct op_parameter){ .pop = 0, .push = 0, .conditional = false, .fallthrough = true, __VA_ARGS__ })
#define jrel_op(...) jrel_opN((struct op_parameter){ .fallthrough = true, __VA_ARGS__ })
void (jrel_opN)(struct op_parameter par);

#define nargs_op(...) nargs_op((struct op_parameter){ __VA_ARGS__ })
#define nargs_op0(...) nargs_op((struct op_parameter){ .pop = -2, .push = -2, __VA_ARGS__ })
void (nargs_op)(struct op_parameter par);

#define rm_op(...) rm_op((struct op_parameter){ __VA_ARGS__ })
void (rm_op)(struct op_parameter par);

#endif
