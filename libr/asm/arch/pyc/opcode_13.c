#include "opcode.h"

pyc_opcodes *opcode_13(void) {
	pyc_opcodes *ret = opcode_14 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_13;

	// 1.3 - 1.4 bytecodes differences
	rm_op (.op_obj = ret->opcodes, .op_name = "BINARY_POWER", .op_code = 19);
	def_op (.op_obj = ret->opcodes, .op_name = "LOAD_GLOBALS", .op_code = 84);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
