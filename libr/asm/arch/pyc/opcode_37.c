#include "opcode.h"

pyc_opcodes *opcode_37(void) {
	pyc_opcodes *ret = opcode_36 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_37;

	// These are removed since 3.6...
	// and STORE_ANNOTATION introduced in 3.6!
	rm_op (.op_obj = ret->opcodes, .op_name = "STORE_ANNOTATION", .op_code = 127);

	// These are new since Python 3.7
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_METHOD", .op_code = 160);
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_METHOD", .op_code = 161);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "CALL_FUNCTION_KW", format_CALL_FUNCTION_KW_36);
	add_arg_fmt (ret, "CALL_FUNCTION_EX", format_CALL_FUNCTION_EX_36);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_36);
	add_arg_fmt (ret, "FORMAT_VALUE", format_value_flags_36);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg_36);

	return ret;
}
