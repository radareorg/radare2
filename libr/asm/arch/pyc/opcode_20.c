#include "opcode.h"

pyc_opcodes *opcode_20(void) {
	pyc_opcodes *ret = opcode_21 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_20;

	// 2.1 Bytecodes not in 2.0
	rm_op (.op_obj = ret->opcodes, .op_name = "CONTINUE_LOOP", .op_code = 119);
	rm_op (.op_obj = ret->opcodes, .op_name = "MAKE_CLOSURE", .op_code = 134);
	rm_op (.op_obj = ret->opcodes, .op_name = "LOAD_CLOSURE", .op_code = 135);
	rm_op (.op_obj = ret->opcodes, .op_name = "LOAD_DEREF", .op_code = 136);
	rm_op (.op_obj = ret->opcodes, .op_name = "STORE_DEREF", .op_code = 137);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
