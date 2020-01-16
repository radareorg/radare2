
#ifndef R_PETSCII_H
#define R_PETSCII_H

#include <r_util.h>

// Map PETSCII to ASCII
// returns '\0' if no mapping exists
R_API char r_petscii_char_to_ascii(ut8 petscii);

// Map PETSCII to UTF-8 using similarly-looking common Unicode characters
// returns NULL if no mapping exists
R_API const char *r_petscii_char_to_utf8(ut8 petscii);

// returns whether the return of r_petscii_char_to_utf8() will be printable (no \n, etc.)
R_API bool r_petscii_is_utf8_printable(ut8 petscii);

// Map PETSCII to UTF-8 specifically for the font at https://style64.org/c64-truetype
// returns NULL if no mapping exists
R_API const char *r_petscii_char_to_utf8_style(ut8 petscii);

#endif //R_PETSCII_H
