/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#include "pyc.h"
#include "marshal.h"

bool pyc_get_sections_symbols(RList *sections, RList *symbols, RList *cobjs, RBuffer *buf, ut32 magic) {
	return get_sections_symbols_from_code_objects (buf, sections, symbols, cobjs, magic);
}

static bool pyc_is_object(ut8 b, pyc_marshal_type type) {
	return b == type;
}

bool pyc_is_code(ut8 b, ut32 magic) {
	if ((magic == 0x00949494 || magic == 0x0099be2a || magic == 0x0099be3a || magic == 0x00999901) && (pyc_is_object ((b & ~FLAG_REF), TYPE_CODE_v0))) {
		//TYPE_CODE_V0 for Python < 1.0
		return true;
	}
	if (pyc_is_object ((b & ~FLAG_REF), TYPE_CODE_v1)) {
		return true;
	}
	return false;
}
