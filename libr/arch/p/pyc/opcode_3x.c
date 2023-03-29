#include "opcode.h"

pyc_opcodes *opcode_3x(void) {
	pyc_opcodes *ret = new_pyc_opcodes ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_3x;

	def_op00 (.op_obj = ret->opcodes, .op_name = "STOP_CODE", .op_code = 0, .pop = 0, .push = 0, .fallthrough = false);
	def_op (.op_obj = ret->opcodes, .op_name = "POP_TOP", .op_code = 1, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "ROT_TWO", .op_code = 2, .pop = 2, .push = 2);
	def_op (.op_obj = ret->opcodes, .op_name = "ROT_THREE", .op_code = 3, .pop = 3, .push = 3);
	def_op (.op_obj = ret->opcodes, .op_name = "DUP_TOP", .op_code = 4, .pop = 0, .push = 1);

	// Python 3.2+
	def_op (.op_obj = ret->opcodes, .op_name = "DUP_TOP_TWO", .op_code = 5, .pop = 0, .push = 2);

	def_op (.op_obj = ret->opcodes, .op_name = "NOP", 9);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_POSITIVE", .op_code = 10, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_NEGATIVE", .op_code = 11, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_NOT", .op_code = 12, .pop = 1, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "UNARY_INVERT", .op_code = 15, .pop = 1, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_POWER", .op_code = 19, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_MULTIPLY", .op_code = 20, .pop = 2, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_MODULO", .op_code = 22, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_ADD", .op_code = 23, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_SUBTRACT", .op_code = 24, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_SUBSCR", .op_code = 25, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_FLOOR_DIVIDE", .op_code = 26, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_TRUE_DIVIDE", .op_code = 27, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_FLOOR_DIVIDE", .op_code = 28, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_TRUE_DIVIDE", .op_code = 29, .pop = 2, .push = 1);

	// Gone from Python 3 are Python2's
	// SLICE+0 .. SLICE+3
	// STORE_SLICE+0 .. STORE_SLICE+3
	// DELETE_SLICE+0 .. DELETE_SLICE+3

	store_op (.op_obj = ret->opcodes, .op_name = "STORE_MAP", .op_code = 54, .pop = 3, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_ADD", .op_code = 55, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_SUBTRACT", .op_code = 56, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_MULTIPLY", .op_code = 57, .pop = 2, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_MODULO", .op_code = 59, .pop = 2, .push = 1);
	store_op (.op_obj = ret->opcodes, .op_name = "STORE_SUBSCR", .op_code = 60, .pop = 3, .push = 0); // Implements TOS1[TOS] = TOS2.
	def_op (.op_obj = ret->opcodes, .op_name = "DELETE_SUBSCR", .op_code = 61, .pop = 2, .push = 0); // Implements del TOS1[TOS].
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_LSHIFT", .op_code = 62, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_RSHIFT", .op_code = 63, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_AND", .op_code = 64, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_XOR", .op_code = 65, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BINARY_OR", .op_code = 66, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_POWER", .op_code = 67, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "GET_ITER", .op_code = 68, .pop = 1, .push = 1);
	store_op (.op_obj = ret->opcodes, .op_name = "STORE_LOCALS", .op_code = 69, .pop = 1, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "PRINT_EXPR", .op_code = 70, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "LOAD_BUILD_CLASS", .op_code = 71, .pop = 0, .push = 1);

	// Python3 drops/changes:
	//  def_op(.op_obj = ret->opcodes, .op_name = "PRINT_ITEM", 71)
	//  def_op(.op_obj = ret->opcodes, .op_name = "PRINT_NEWLINE", 72)
	//  def_op(.op_obj = ret->opcodes, .op_name = "PRINT_ITEM_TO", 73)
	//  def_op(.op_obj = ret->opcodes, .op_name = "PRINT_NEWLINE_TO", 74)

	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_LSHIFT", .op_code = 75, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_RSHIFT", .op_code = 76, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_AND", .op_code = 77, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_XOR", .op_code = 78, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "INPLACE_OR", .op_code = 79, .pop = 2, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "BREAK_LOOP", .op_code = 80, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "WITH_CLEANUP", .op_code = 81, .pop = 1, .push = 0); // Cleans up the stack when a with statement
		// block exits.  Handle stack special

	def_op00 (.op_obj = ret->opcodes, .op_name = "RETURN_VALUE", .op_code = 83, .pop = 1, .push = 0, .fallthrough = false);
	def_op (.op_obj = ret->opcodes, .op_name = "IMPORT_STAR", .op_code = 84, .pop = 1, .push = 0);

	def_op (.op_obj = ret->opcodes, .op_name = "YIELD_VALUE", .op_code = 86, .pop = 1, .push = 1);
	def_op (.op_obj = ret->opcodes, .op_name = "POP_BLOCK", .op_code = 87, .pop = 0, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "END_FINALLY", .op_code = 88, .pop = 1, .push = 0);
	def_op (.op_obj = ret->opcodes, .op_name = "POP_EXCEPT", .op_code = 89, .pop = 1, .push = -1);

	ret->have_argument = 90; // Opcodes from here have an argument:

	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_NAME", .op_code = 90, .pop = 1, .push = 0, .func = NAME_OP); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_NAME", .op_code = 91, .pop = 0, .push = 0); // ""
	varargs_op (.op_obj = ret->opcodes, .op_name = "UNPACK_SEQUENCE", .op_code = 92, .pop = 9, .push = 1); // TOS is number of tuple items
	jrel_op (.op_obj = ret->opcodes, .op_name = "FOR_ITER", .op_code = 93, .pop = 9, .push = 1);

	def_op (.op_obj = ret->opcodes, .op_name = "UNPACK_EX", .op_code = 94, .pop = 9, .push = 1); // assignment with a starred target; TOS is #entries
		// argument has a count
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_ATTR", .op_code = 95, .pop = 2, .push = 0, .func = NAME_OP); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_ATTR", .op_code = 96, .pop = 1, .push = 0); // ""
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_GLOBAL", .op_code = 97, .pop = 1, .push = 0, .func = NAME_OP); // ""
	name_op (.op_obj = ret->opcodes, .op_name = "DELETE_GLOBAL", .op_code = 98, .pop = 0, .push = 0); // ""

	// Python 2's DUP_TOPX is gone starting in Python 3.2

	const_op00 (.op_obj = ret->opcodes, .op_name = "LOAD_CONST", .op_code = 100, .pop = 0, .push = 1); // Operand is in const list
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_NAME", .op_code = 101, .pop = 0, .push = 1); // Operand is in name list
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_TUPLE", .op_code = 102, .pop = 9, .push = 1); // TOS is count of tuple items
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_LIST", .op_code = 103, .pop = 9, .push = 1); // TOS is count of list items
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_SET", .op_code = 104, .pop = 9, .push = 1); // TOS is count of set items
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_MAP", .op_code = 105, .pop = 0, .push = 1); // TOS is count of kwarg items
	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_ATTR", .op_code = 106, .pop = 1, .push = 1); // Operand is in name list
	compare_op (.op_obj = ret->opcodes, .op_name = "COMPARE_OP", .op_code = 107, .pop = 2, .push = 1); // Comparison operator
	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_NAME", .op_code = 108, .pop = 1, .push = 1); // Operand is in name list
	name_op (.op_obj = ret->opcodes, .op_name = "IMPORT_FROM", .op_code = 109, .pop = 0, .push = 1); // Operand is in name list

	jrel_op (.op_obj = ret->opcodes, .op_name = "JUMP_FORWARD", .op_code = 110, .pop = 0, .push = 0); // Number of bytes to skip
	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_FALSE_OR_POP", .op_code = 111, .conditional = true); // Target byte offset from beginning of code
	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_IF_TRUE_OR_POP", .op_code = 112, .conditional = true); // ""
	jabs_op (.op_obj = ret->opcodes, .op_name = "JUMP_ABSOLUTE", .op_code = 113, .pop = 0, .push = 0); // Target byte offset from beginning of code
	jabs_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_FALSE", .op_code = 114, .pop = 9, .push = 1, .conditional = true); // ""
	jabs_op (.op_obj = ret->opcodes, .op_name = "POP_JUMP_IF_TRUE", .op_code = 115, .pop = 9, .push = 1, .conditional = true); // ""

	name_op (.op_obj = ret->opcodes, .op_name = "LOAD_GLOBAL", .op_code = 116, .pop = 0, .push = 1); // Operand is in name list

	jabs_op (.op_obj = ret->opcodes, .op_name = "CONTINUE_LOOP", .op_code = 119, .pop = 0, .push = 0); // Target address
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_LOOP", .op_code = 120, .pop = 0, .push = 0, .conditional = true); // Distance to target address
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_EXCEPT", .op_code = 121, .pop = 0, .push = 6, .conditional = true); // ""
	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_FINALLY", .op_code = 122, .pop = 0, .push = 6, .conditional = true); // ""

	local_op (.op_obj = ret->opcodes, .op_name = "LOAD_FAST", .op_code = 124, .pop = 0, .push = 1); // Local variable number
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_FAST", .op_code = 125, .pop = 1, .push = 0, .func = LOCAL_OP); // Local variable number
	local_op (.op_obj = ret->opcodes, .op_name = "DELETE_FAST", .op_code = 126, .pop = 0, .push = 0); // Local variable number

	def_op00 (.op_obj = ret->opcodes, .op_name = "RAISE_VARARGS", .op_code = 130, .pop = 9, .push = 1, .fallthrough = false);
	// Number of raise arguments (1, 2, or 3)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION", .op_code = 131, .pop = 9, .push = 1); // #args + (#kwargs << 8)

	def_op (.op_obj = ret->opcodes, .op_name = "MAKE_FUNCTION", .op_code = 132, .pop = 9, .push = 1); // TOS is number of args if < 3.6
	varargs_op (.op_obj = ret->opcodes, .op_name = "BUILD_SLICE", .op_code = 133, .pop = 9, .push = 1); // TOS is number of items to pop

	def_op (.op_obj = ret->opcodes, .op_name = "MAKE_CLOSURE", .op_code = 134, .pop = 9, .push = 1); // TOS is number of items to pop
	free_op (.op_obj = ret->opcodes, .op_name = "LOAD_CLOSURE", .op_code = 135, .pop = 0, .push = 1);
	free_op (.op_obj = ret->opcodes, .op_name = "LOAD_DEREF", .op_code = 136, .pop = 0, .push = 1);
	store_op00 (.op_obj = ret->opcodes, .op_name = "STORE_DEREF", .op_code = 137, .pop = 1, .push = 0, .func = FREE_OP);
	free_op (.op_obj = ret->opcodes, .op_name = "DELETE_DEREF", .op_code = 138, .pop = 0, .push = 0);

	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR", .op_code = 140, .pop = 9, .push = 1); // #args + (#kwargs << 8)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_KW", .op_code = 141, .pop = 9, .push = 1); // #args + (#kwargs << 8)
	nargs_op (.op_obj = ret->opcodes, .op_name = "CALL_FUNCTION_VAR_KW", .op_code = 142, .pop = 9, .push = 1); // #args + (#kwargs << 8)

	jrel_op (.op_obj = ret->opcodes, .op_name = "SETUP_WITH", .op_code = 143, .pop = 0, .push = 7);

	def_op (.op_obj = ret->opcodes, .op_name = "LIST_APPEND", .op_code = 145, .pop = 2, .push = 1); // Calls list.append(TOS[-i], TOS).
		// Used to implement list comprehensions.
	def_op (.op_obj = ret->opcodes, .op_name = "SET_ADD", .op_code = 146, .pop = 1, .push = 0); // Calls set.add(TOS1[-i], TOS).
		// Used to implement set comprehensions.
	def_op (.op_obj = ret->opcodes, .op_name = "MAP_ADD", .op_code = 147, .pop = 2, .push = 1); // Calls dict.setitem(TOS1[-i], TOS, TOS1)
		// Used to implement dict comprehensions.

	def_op (.op_obj = ret->opcodes, .op_name = "EXTENDED_ARG", .op_code = 144);
	ret->extended_arg = 144;

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
