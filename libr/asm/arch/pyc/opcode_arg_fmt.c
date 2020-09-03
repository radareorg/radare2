#include "opcode.h"

const char *format_extended_arg(ut32 oparg) {
	return r_str_newf ("%u", oparg * (1 << 16));
}

const char *format_CALL_FUNCTION_pos_name_encoded(ut32 oparg) {
	ut32 pos_args = oparg & 0xFF;
	ut32 name = (oparg >> 8) & 0xFF;
	return r_str_newf ("%u positional, %u named", pos_args, name);
}

const char *format_MAKE_FUNCTION_arg_3x(ut32 oparg) {
	ut32 pos_args = oparg & 0xFF;
	ut32 name_default = (oparg >> 8) & 0xFF;
	ut32 annotate_args = (oparg >> 16) & 0x7FFF;
	return r_str_newf ("%u positional, %u name and default, %u annotations", pos_args, name_default, annotate_args);
}

const char *format_CALL_FUNCTION_KW_36(ut32 oparg) {
	return r_str_newf ("%u total positional and keyword args", oparg);
}

const char *format_CALL_FUNCTION_EX_36(ut32 oparg) {
	return r_str_new ((oparg & 0x01)? "keyword args": "");
}

static const char *MAKE_FUNCTION_FLAGS[] = { "default", "keyword-only", "annotation", "closure" };

const char *format_MAKE_FUNCTION_arg_36(ut32 oparg) {
	size_t i;
	char *ret = r_str_new (" ");
	for (i = 0; i < sizeof (MAKE_FUNCTION_FLAGS) / sizeof (char *); ++i) {
		if (oparg & 0x1) {
			r_str_appendf (ret, ", %s", MAKE_FUNCTION_FLAGS[i]);
		} else {
			free (ret);
			ret = r_str_new (MAKE_FUNCTION_FLAGS[i]);
		}
		oparg >>= 1;
	}
	return ret;
}

const char *format_value_flags_36(ut32 oparg) {
	const char *ret = "";
	switch (oparg & 0x3) {
	case 1:
		ret = "!s";
		break;
	case 2:
		ret = "!r";
		break;
	case 3:
		ret = "!a";
		break;
	}
	if ((oparg & 0x4) == 0x4) {
		// pop fmt_spec from the stack and use it, else use an
		// empty fmt_spec.
		ret = "";
	}
	return r_str_new (ret);
}

const char *format_extended_arg_36(ut32 oparg) {
	return r_str_newf ("%u", oparg * (1 << 8));
}
