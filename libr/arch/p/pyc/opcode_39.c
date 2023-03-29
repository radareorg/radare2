#include "opcode.h"

pyc_opcodes *opcode_39(void) {
	pyc_opcodes *ret = opcode_38 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_39;

	// These are removed since 3.8...
	rm_op (.op_obj = ret->opcodes, .op_name = "BEGIN_FINALLY", .op_code = 53);
	rm_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP_START", .op_code = 81);
	rm_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP_FINISH", .op_code = 82);
	rm_op (.op_obj = ret->opcodes, .op_name = "END_FINALLY", .op_code = 88);
	rm_op (.op_obj = ret->opcodes, .op_name = "CALL_FINALLY", .op_code = 162);
	rm_op (.op_obj = ret->opcodes, .op_name = "POP_FINALLY", .op_code = 163);

	// These are new since Python 3.9
	//          OP NAME              OPCODE  POP PUSH
	def_op (.op_obj = ret->opcodes, .op_name = "RERAISE", .op_code = 48, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "WITH_EXCEPT_START", .op_code = 49, .pop = 3, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "LOAD_ASSERTION_ERROR", .op_code = 74, .pop = 0, .push = 1);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "CALL_FUNCTION_KW", format_CALL_FUNCTION_KW_36);
	add_arg_fmt (ret, "CALL_FUNCTION_EX", format_CALL_FUNCTION_EX_36);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_36);
	add_arg_fmt (ret, "FORMAT_VALUE", format_value_flags_36);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg_36);

	return ret;
}
