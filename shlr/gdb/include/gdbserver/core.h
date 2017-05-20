#ifndef GDB_SERVER_CORE_H
#define GDB_SERVER_CORE_H

#include <r_socket.h>
#include "../libgdbr.h"

// Read command from socket, parse into r2 debugger command in buffer. Return 0
// on success, failure code (currently -1) on failure
int gdbr_server_read(libgdbr_t *g, char *buf, size_t max_len);

// Send command to the remote gdb instance
int gdbr_server_send(libgdbr_t *g, const char *buf, size_t max_len);

#endif  // GDB_SERVER_CORE_H
