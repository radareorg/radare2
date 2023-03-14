#ifndef _INCLUDE_ARMASS_H_
#define _INCLUDE_ARMASS_H_

#include <r_types_base.h>

ut32 armass_assemble(const char *str, ut64 off, int thumb);
bool arm64ass(const char *str, ut64 addr, ut32 *op);

#endif
