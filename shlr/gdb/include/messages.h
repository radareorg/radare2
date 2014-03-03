/*! \file */
/**
 * See Appendix E in the gdb manual (GDB Remote Serial Protocol)
 * Packets look following: $ starts a command/packet, the end is indicated
 * with # and a final checksum
 * $<command>#<checksum>
 */

#ifndef MESSAGES_H
#define MESSAGES_H

#include <string.h>
#include "libgdbr.h"
#include "utils.h"

int handle_g(libgdbr_t* instance);
int handle_m(libgdbr_t* instance);
int handle_cmd(libgdbr_t* instance);
int handle_cont(libgdbr_t* instance);
int handle_connect(libgdbr_t* instance);
int handle_setbp(libgdbr_t* instance);
int handle_unsetbp(libgdbr_t* instance);

#endif
