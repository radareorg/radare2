#include "opcode.h"

pyc_opcodes *opcode_30(void) {
	pyc_opcodes *ret = opcode_31 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_30;

	// These are in Python 3.x but not in Python 3.0

	rm_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111);
	rm_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112);
	rm_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 114);
	rm_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 115);
	rm_op (.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 145);
	rm_op (.op_obj = ret->opcodes, .op_name = "MAP_ADD", .op_code = 147);

	// These are are in 3.0 but are not in 3.1 or they have
	// different opcode numbers. Note: As a result of opcode value
	// changes, these have to be applied *after* removing ops (with
	// the same name).

	def_op (.op_obj = ret->opcodes, .op_name = "SET_ADD", .op_code = 17, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 18, .pop = 2, .push = 1);

	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE", .op_code = 111, .pop = 1, .push = 1, .conditional = true);
	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE", .op_code = 112, .pop = 1, .push = 1, .conditional = true);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_3x);

	return ret;
}
