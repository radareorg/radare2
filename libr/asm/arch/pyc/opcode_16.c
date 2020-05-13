#include "opcode.h"

pyc_opcodes *opcode_16(void) {
	pyc_opcodes *ret = opcode_15 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_16;

	// 1.6 Bytecodes not in 1.5
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR", .op_code = 140, .pop = -1, .push = 1); // #args + (#kwargs << 8)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_KW", .op_code = 141, .pop = -1, .push = 1); // #args + (#kwargs << 8)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR_KW", .op_code = 142, .pop = -1, .push = 1); // #args + (#kwargs << 8)

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
