#ifndef GDB_SERVER_CORE_H
#define GDB_SERVER_CORE_H

#include <r_socket.h>
#include "../libgdbr.h"

int gdbr_server_serve(libgdbr_t *g, int (*cmd_cb) (void*, const char*, char*, size_t), void *core_ptr);


#endif  // GDB_SERVER_CORE_H
