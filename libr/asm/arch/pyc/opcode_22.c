#include "opcode.h"

pyc_opcodes *opcode_22(void) {
	pyc_opcodes *ret = opcode_2x ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_22;

	// 2.2 Bytecodes not in 2.3
	def_op (.op_obj = ret->opcodes, .op_name = "FOR_LOOP", .op_code = 114);
	def_op (.op_obj = ret->opcodes, .op_name = "SET_LINENO", .op_code = 127, .pop = 0, .push = 0);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
