#include "opcode.h"

pyc_opcodes *opcode_15(void) {
	pyc_opcodes *ret = new_pyc_opcodes ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_15;

	def_opN ((struct op_parameter) {.op_obj = ret->opcodes, .op_name = "STOP_CODE", .op_code = 0, .pop = 0, .push = 0, .fallthrough = false});
	def_op (.op_obj = ret->opcodes, .op_name = "POP_TOP", .op_code = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "ROT_TWO", .op_code = 2);
	def_op (.op_obj = ret->opcodes, .op_name = "ROT_THREE", .op_code = 3);
	def_op (.op_obj = ret->opcodes, .op_name = "DUP_TOP", .op_code = 4);

	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_POSITIVE", .op_code = 10, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_NEGATIVE", .op_code = 11, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_NOT", .op_code = 12, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_CONVERT", .op_code = 13, .pop = 1, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_INVERT", .op_code = 15, .pop = 1, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_POWER", .op_code = 19, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_MULTIPLY", .op_code = 20, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_DIVIDE", .op_code = 21, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_MODULO", .op_code = 22, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_ADD", .op_code = 23, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_SUBTRACT", .op_code = 24, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR", .op_code = 25, .pop = 2, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "SLICE_0", .op_code = 30, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "SLICE_1", .op_code = 31, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "SLICE_2", .op_code = 32, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "SLICE_3", .op_code = 33, .pop = 3, .push = 1);

	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SLICE_0", .op_code = 40, .pop = 2, .push = 0);
	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SLICE_1", .op_code = 41, .pop = 3, .push = 0);
	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SLICE_2", .op_code = 42, .pop = 3, .push = 0);
	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SLICE_3", .op_code = 43, .pop = 4, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SLICE_0", .op_code = 50, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SLICE_1", .op_code = 51, .pop = 2, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SLICE_2", .op_code = 52, .pop = 2, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SLICE_3", .op_code = 53, .pop = 3, .push = 0);

	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR", .op_code = 60, .pop = 3, .push = 0); // Implements TOS1[TOS] = TOS2.
	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SUBSCR", .op_code = 61, .pop = 2, .push = 0); // Implements del TOS1[TOS].

	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_LSHIFT", .op_code = 62, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_RSHIFT", .op_code = 63, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_AND", .op_code = 64, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_XOR", .op_code = 65, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_OR", .op_code = 66, .pop = 2, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "PRINT_EXPR", .op_code = 70, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "PRINT_ITEM", .op_code = 71, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "PRINT_NEWLINE", .op_code = 72, .pop = 1, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "BREAK_LOOP", .op_code = 80, .pop = 0, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "LOAD_LOCALS", .op_code = 82, .pop = 0, .push = 1);
	def_op00 (.op_obj = ret->opcodes, .op_name = "RETURN_VALUE", .op_code = 83, .pop = 1, .push = 0, .fallthrough = false);

	def_op (.op_obj = ret->opcodes, .op_name = "EXEC_STMT", .op_code = 85, .pop = 3, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "POP_BLOCK", .op_code = 87, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "END_FINALLY", .op_code = 88, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "BUILD_CLASS", .op_code = 89, .pop = 3, .push = 0);

	ret->have_argument = 90; // Opcodes from here have an argument:

	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_NAME", .op_code = 90, .pop = 1, .push = 0, .func = NAME_OP); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_NAME", .op_code = 91, .pop = 0, .push = 0); // ""
	varargs_op (.op_obj = ret->opcodes, .op_name = "UNPACK_TUPLE", .op_code = 92); // Number of tuple items
	def_op (.op_obj = ret->opcodes, .op_name = "UNPACK_LIST", .op_code = 93); // Number of list items
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_ATTR", .op_code = 95, .pop = 2, .push = 0, .func = NAME_OP); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_ATTR", .op_code = 96, .pop = 1, .push = 0); // ""
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_GLOBAL", .op_code = 97, .pop = 1, .push = 0, .func = NAME_OP); // ""
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_GLOBAL", .op_code = 98, .pop = 0, .push = 0); // ""

	const_op00 (.op_obj = ret->opcodes, .op_name = "LOAD_CONST", .op_code = 100, .pop = 0, .push = 1); // Operand is in const list
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_NAME", .op_code = 101, .pop = 0, .push = 1); // Operand is in name list
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE", .op_code = 102, .pop = -1, .push = 1); // Number of tuple items
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_LIST", .op_code = 103, .pop = -1, .push = 1); // Number of list items
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 104, .pop = -1, .push = 1); // Always zero for now
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 105, .pop = 1, .push = 1); // Operand is in name list
	compare_op (.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 106, .pop = 2, .push = 1); // Comparison operator

	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 107, .pop = 2, .push = 1); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 108, .pop = 0, .push = 1); // Operand is in name list

	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_FORWARD", .op_code = 110, .pop = 0, .push = 0); // Number of bytes to skip
	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE", .op_code = 111, .pop = 1, .push = 1, .conditional = true); // ""
	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE", .op_code = 112, .pop = 1, .push = 1, .conditional = true); // ""
	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_ABSOLUTE", .op_code = 113, .pop = 0, .push = 0); // Target byte offset from beginning of code
	def_op (.op_obj = ret->opcodes, .op_name = "FOR_LOOP", .op_code = 114); // Number of bytes to skip

	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL", .op_code = 116, .pop = 0, .push = 1); // Operand is in name list

	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_LOOP", .op_code = 120, .pop = 0, .push = 0, .conditional = true); // Distance to target address
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_EXCEPT", .op_code = 121, .pop = 0, .push = 0, .conditional = true); // ""
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_FINALLY", .op_code = 122, .pop = 0, .push = 0, .conditional = true); // ""

	local_op (.op_obj = ret->opcodes, .op_name = "LOAD_FAST", .op_code = 124, .pop = 0, .push = 1); // Local variable number
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_FAST", .op_code = 125, .pop = 1, .push = 0, .func = LOCAL_OP); // Local variable number
	local_op0 (.op_obj = ret->opcodes, .op_name = "DELETE_FAST", .op_code = 126); // Local variable number

	def_op (.op_obj = ret->opcodes, .op_name = "SET_LINENO", .op_code = 127); // Current line number

	def_op00 (.op_obj = ret->opcodes, .op_name = "RAISE_VARARGS", .op_code = 130, .pop = -1, .push = 0, .fallthrough = false);
	// Number of raise arguments (1, 2, or 3)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION", .op_code = 131, .pop = -1, .push = 1); // //args + (//kwargs << 8)

	def_op (.op_obj = ret->opcodes, .op_name = "MAKE_FUNCTION", .op_code = 132, .pop = -1, .push = 1); // Number of args with default values
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_SLICE", .op_code = 133, .pop = -1, .push = 1); // Number of items

	def_op (.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 143);
	ret->extended_arg = 143;

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
