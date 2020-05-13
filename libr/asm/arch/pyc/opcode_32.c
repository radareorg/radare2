#include "opcode.h"

pyc_opcodes *opcode_32(void) {
	pyc_opcodes *ret = opcode_3x ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_32;

	// There are no opcodes to add or change.
	// If there were, they'd be listed below.

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);
	add_arg_fmt (ret, "MAKE_FUNCTION", format_MAKE_FUNCTION_arg_3x);

	return ret;
}
