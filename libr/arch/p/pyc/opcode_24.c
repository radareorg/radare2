#include "opcode.h"

pyc_opcodes *opcode_24(void) {
	pyc_opcodes *ret = opcode_2x ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_24;

	// Bytecodes added since 2.3
	def_op (.op_obj = ret->opcodes, .op_name = "NOP", .op_code = 9, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 18, .pop = 2, .push = 1); // Calls list.append(TOS[-i], TOS).
	// Used to implement list comprehensions.
	def_op (.op_obj = ret->opcodes, .op_name = "YIELD_VALUE", .op_code = 86, .pop = 1, .push = 0);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
