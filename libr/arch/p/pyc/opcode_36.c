#include "opcode.h"

pyc_opcodes *opcode_36(void) {
	pyc_opcodes *ret = opcode_35 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_36;

	// These are removed since Python 3.6
	rm_op (.op_obj = ret->opcodes, .op_name = "MAKE_CLOSURE", .op_code = 134);
	rm_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR", .op_code = 140);
	rm_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR_KW", .op_code = 142);

	// These are new since Python 3.6
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_ANNOTATION", .op_code = 127, .func = NAME_OP); // Index in name list
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_ASYNC_WITH", .op_code = 154);
	def_op (.op_obj = ret->opcodes, .op_name = "FORMAT_VALUE", .op_code = 155);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_CONST_KEY_MAP", .op_code = 156, .pop = -1, .push = 1); // TOS is count of kwargs
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_EX", .op_code = 142, .pop = -1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "SETUP_ANNOTATIONS", .op_code = 85);
	def_op (.op_obj = ret->opcodes, .op_name = "BUILD_STRING", .op_code = 157);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE_UNPACK_WITH_CALL", .op_code = 158);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "CALL_FUNCTION_KW", format_CALL_FUNCTION_KW_36);
	add_arg_fmt (ret, "CALL_FUNCTION_EX", format_CALL_FUNCTION_EX_36);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_36);
	add_arg_fmt (ret, "FORMAT_VALUE", format_value_flags_36);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg_36);

	return ret;
}
