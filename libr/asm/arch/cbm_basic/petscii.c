
#include "petscii.h"

#include "petscii_map.inl"

R_API char r_petscii_char_to_ascii(ut8 petscii) {
	if (petscii < 0x80) {
		return petscii_ascii[petscii];
	}
	return '\0';
}

R_API const char *r_petscii_char_to_utf8(ut8 petscii) {
	return petscii_utf8[petscii];
}

R_API bool r_petscii_is_utf8_printable(ut8 petscii) {
	if (petscii < 0x20 || petscii == 0x8d || petscii == 0xa0) {
		return false;
	}
	return r_petscii_char_to_utf8 (petscii) != NULL;
}

R_API const char *r_petscii_char_to_utf8_style(ut8 petscii) {
	return petscii_utf8_style[petscii];
}