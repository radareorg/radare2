#include "opcode.h"

pyc_opcodes *opcode_38(void) {
	pyc_opcodes *ret = opcode_37 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_38;

	// These are removed since 3.7...
	rm_op (.op_obj = ret->opcodes, .op_name = "BREAK_LOOP", .op_code = 80);
	rm_op (.op_obj = ret->opcodes, .op_name = "CONTINUE_LOOP", .op_code = 119);
	rm_op (.op_obj = ret->opcodes, .op_name = "SETUP_LOOP", .op_code = 120);
	rm_op (.op_obj = ret->opcodes, .op_name = "SETUP_EXCEPT", .op_code = 121);

	// These are new since Python 3.7

	//          OP NAME            OPCODE POP PUSH
	// --------------------------------------------
	def_op (.op_obj = ret->opcodes, .op_name = "ROT_FOUR", .op_code = 6, .pop = 4, .push = 4);
	def_op (.op_obj = ret->opcodes, .op_name = "BEGIN_FINALLY", .op_code = 53, .pop = 0, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "END_ASYNC_FOR", .op_code = 54, .pop = 7, .push = 0); // POP is 0, when not 7
	def_op (.op_obj = ret->opcodes, .op_name = "END_FINALLY", .op_code = 88, .pop = 1, .push = 0); // POP is 6, when not 1
	jrel_op (.op_obj = ret->opcodes, .op_name = "CALL_FINALLY", .op_code = 162, .pop = 0, .push = 1);
	nargs_op (.op_obj = ret->opcodes, .op_name = "POP_FINALLY", .op_code = 163, .pop = 0, .push = 0); // PUSH/POP vary

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "CALL_FUNCTION_KW", format_CALL_FUNCTION_KW_36);
	add_arg_fmt (ret, "CALL_FUNCTION_EX", format_CALL_FUNCTION_EX_36);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_36);
	add_arg_fmt (ret, "FORMAT_VALUE", format_value_flags_36);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg_36);

	return ret;
}
