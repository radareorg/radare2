#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "../libgdbr.h"
#include "r_types_base.h"


/*!
 * \brief Function connects to a gdbserver instance
 * \param server string that represents the host
 * \param number that represents the port
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_connect(libgdbr_t *g, const char *server, int port);

/*!
 * \brief disconnects the lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_disconnect(libgdbr_t *g);

// Commands
int gdbr_continue(libgdbr_t *g, int thread_id);
int gdbr_step(libgdbr_t *g, int thread_id);
int gdbr_read_registers(libgdbr_t *g);

/*!
 * \brief Function writes general purpose registers
 * \param gdbr instance that contains the current context
 * \param reg contains the registers that should be written
 * reg contains a comma separated string that uses <regname>=value,<regname>=value
 * i.e. eax=0x123,ebx=0x234
 * \returns a failurre code (currently -1) or 0 if call successfully
 */
int gdbr_write_bin_registers(libgdbr_t *g);
int gdbr_write_reg(libgdbr_t *g, const char *name, char *value, int len);
int gdbr_write_register(libgdbr_t *g, int index, char *value, int len);
int gdbr_write_registers(libgdbr_t *g, char *registers);
int gdbr_read_memory(libgdbr_t *g, ut64 address, ut64 len);
int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len);
int gdbr_send_command(libgdbr_t *g, char *command);
int test_command(libgdbr_t *g, const char *command);

/*!
 * \brief Function sets normal breakpoint (0xcc, int3)
 * \param gdbr instance that contains the current context
 * \param addrress at this position the breakpoint will be added
 * \param conditions TODO: examine how this condition string should look like
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions);
int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions);
int gdbr_remove_bp(libgdbr_t *g, ut64 address);
int gdbr_remove_hwbp(libgdbr_t *g, ut64 address);


#endif  // CLIENT_COMMANDS_H
