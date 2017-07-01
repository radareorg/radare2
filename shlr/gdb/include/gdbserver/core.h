#ifndef GDB_SERVER_CORE_H
#define GDB_SERVER_CORE_H

#include <r_socket.h>
#include "../libgdbr.h"

typedef int (*gdbr_server_cmd_cb) (libgdbr_t*, void*, const char*, char*, size_t);

int gdbr_server_serve(libgdbr_t *g, gdbr_server_cmd_cb cmd_cb, void *core_ptr);


#endif  // GDB_SERVER_CORE_H
