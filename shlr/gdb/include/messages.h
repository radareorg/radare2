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

int handle_g(libgdbr_t* g);
int handle_G(libgdbr_t* g);
int handle_m(libgdbr_t* g);
int handle_M(libgdbr_t* g);
int handle_P(libgdbr_t* g);
int handle_cmd(libgdbr_t* g);
int handle_cont(libgdbr_t* g);
int handle_connect(libgdbr_t* g);
int handle_setbp(libgdbr_t* g);
int handle_removebp(libgdbr_t* g);

#endif
