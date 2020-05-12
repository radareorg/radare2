#include "opcode.h"

pyc_opcodes *opcode_21(void) {
	pyc_opcodes *ret = opcode_22 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_21;

	// 2.1 bytecodes changes from 2.2
	rm_op (.op_obj = ret->opcodes, .op_name = "BINARY_FLOOR_DIVIDE", .op_code = 26);
	rm_op (.op_obj = ret->opcodes, .op_name = "BINARY_TRUE_DIVIDE", .op_code = 27);
	rm_op (.op_obj = ret->opcodes, .op_name = "INPLACE_FLOOR_DIVIDE", .op_code = 28);
	rm_op (.op_obj = ret->opcodes, .op_name = "INPLACE_TRUE_DIVIDE", .op_code = 29);
	rm_op (.op_obj = ret->opcodes, .op_name = "GET_ITER", .op_code = 68);
	rm_op (.op_obj = ret->opcodes, .op_name = "YIELD_VALUE", .op_code = 86);
	rm_op (.op_obj = ret->opcodes, .op_name = "FOR_ITER", .op_code = 93);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
