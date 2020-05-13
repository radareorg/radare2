#include "opcode.h"

pyc_opcodes *opcode_27(void) {
	pyc_opcodes *ret = opcode_26 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_27;

	// Below are opcode changes since Python 2.6
	rm_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 104);
	rm_op (.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 105);
	rm_op (.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 106);
	rm_op (.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 107);
	rm_op (.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 108);
	rm_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE", .op_code = 111);
	rm_op (.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 143);
	rm_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE", .op_code = 112);

	def_op (.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 94, .pop = 2, .push = 1); // Calls list.append(TOS[-i], TOS).
	// Used to implement list comprehensions.
	def_op (.op_obj = ret->opcodes, .op_name = "BUILD_SET", .op_code = 104); // Number of set items
	def_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 105);
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 106);
	compare_op (.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 107);

	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 108, .pop = 2, .push = 1); // Index in name list
	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 109, .pop = 0, .push = 1);

	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111, .conditional = true); // Target byte offset from beginning of code
	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112, .conditional = true); // ""
	jabs_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 114, .conditional = true); // ""
	jabs_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 115, .conditional = true); // ""
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_WITH", .op_code = 143, .pop = 0, .push = 2);

	def_op (.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 145);
	def_op (.op_obj = ret->opcodes, .op_name = "SET_ADD", .op_code = 146, .pop = 1, .push = 0); // Calls set.add(TOS1[-i], TOS).
	// Used to implement set comprehensions.
	def_op (.op_obj = ret->opcodes, .op_name = "MAP_ADD", .op_code = 147, .pop = 2, .push = 1); // Calls dict.setitem(TOS1[-i], TOS, TOS1)
	// Used to implement dict comprehensions.

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);
	add_arg_fmt (ret, "CALL_FUNCTION", format_CALL_FUNCTION_pos_name_encoded);

	return ret;
}
