/*! For handling responses from gdbserver */
/**
 * See Appendix E in the gdb manual (GDB Remote Serial Protocol)
 * Packets look following: $ starts a command/packet, the end is indicated
 * with # and a final checksum
 * $<command>#<checksum>
 */

#ifndef RESPONSES_H
#define RESPONSES_H

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
int handle_qStatus(libgdbr_t* g);
int handle_qC(libgdbr_t* g);
int handle_execFileRead(libgdbr_t* g);
int handle_qSupported(libgdbr_t* g);
int handle_setbp(libgdbr_t* g);
int handle_removebp(libgdbr_t* g);
int handle_attach(libgdbr_t* g);
int handle_vFile_open(libgdbr_t *g);
int handle_vFile_pread(libgdbr_t *g, ut8 *buf);
int handle_vFile_close(libgdbr_t *g);

#endif  // RESPONSES_H
