#include "opcode.h"

pyc_opcodes *opcode_14(void) {
	pyc_opcodes *ret = opcode_15 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_14;

	// 1.4 Bytecodes not in 1.5
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_CALL", .op_code = 14);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_CALL", .op_code = 26);
	def_op (.op_obj = ret->opcodes, .op_name = "RAISE_EXCEPTION", .op_code = 81);
	def_op (.op_obj = ret->opcodes, .op_name = "BUILD_FUNCTION", .op_code = 86);
	varargs_op (.op_obj = ret->opcodes, .op_name = "UNPACK_ARG", .op_code = 94); // Number of arguments expected
	varargs_op (.op_obj = ret->opcodes, .op_name = "UNPACK_VARARG", .op_code = 99); // Minimal number of arguments
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_LOCAL", .op_code = 115);
	varargs_op (.op_obj = ret->opcodes, .op_name = "SET_FUNC_ARGS", .op_code = 117); // Argcount
	varargs_op (.op_obj = ret->opcodes, .op_name = "RESERVE_FAST", .op_code = 123); // Number of local variables

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
