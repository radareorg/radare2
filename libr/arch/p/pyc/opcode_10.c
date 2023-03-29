#include "opcode.h"

pyc_opcodes *opcode_10(void) {
	pyc_opcodes *ret = opcode_11 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_10;

	// 1.0 - 1.1 bytecodes differences
	rm_op (.op_obj = ret->opcodes, .op_name = "LOAD_GLOBALS", .op_code = 84);
	rm_op (.op_obj = ret->opcodes, .op_name = "EXEC_STMT", .op_code = 85);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
