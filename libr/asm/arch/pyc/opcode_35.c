#include "opcode.h"

pyc_opcodes *opcode_35(void) {
	pyc_opcodes *ret = opcode_34 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_35;

	// These are removed since Python 3.5.
	// Removals happen before adds since
	// some opcodes are reused
	rm_op (.op_obj = ret->opcodes, .op_name = "STORE_MAP", .op_code = 54);
	rm_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP", .op_code = 81);

	// These are new since Python 3.5
	//          OP NAME                   OPCODE POP PUSH
	//---------------------------------------------------
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_MATRIX_MULTIPLY", .op_code = 16, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_MATRIX_MULTIPLY", .op_code = 17, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "GET_AITER", .op_code = 50, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "GET_ANEXT", .op_code = 51, .pop = 0, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BEFORE_ASYNC_WITH", .op_code = 52);
	def_op (.op_obj = ret->opcodes, .op_name = "GET_YIELD_FROM_ITER", .op_code = 69, .pop = 0, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "GET_AWAITABLE", .op_code = 73, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP_START", .op_code = 81, .pop = 0, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP_FINISH", .op_code = 82, .pop = -1, .push = 1);

	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_LIST_UNPACK", .op_code = 149, .pop = -1, .push = 1);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP_UNPACK", .op_code = 150, .pop = -1, .push = 1);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP_UNPACK_WITH_CALL", .op_code = 151, .pop = -1, .push = 1);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE_UNPACK", .op_code = 152, .pop = -1, .push = 1);
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_SET_UNPACK", .op_code = 153, .pop = -1, .push = 1);

	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_ASYNC_WITH", .op_code = 154, .pop = 0, .push = 6);

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_3x);

	return ret;
}
