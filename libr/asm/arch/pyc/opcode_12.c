#include "opcode.h"

pyc_opcodes *opcode_12(void) {
	pyc_opcodes *ret = opcode_13 ();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_12;

	r_list_purge (ret->opcode_arg_fmt);
	add_arg_fmt (ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
