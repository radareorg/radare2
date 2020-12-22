#ifndef CLIENT_COMMANDS_H
#define CLIENT_COMMANDS_H

#include "../libgdbr.h"
#include "r_types_base.h"
#include <r_util.h>

/*!
 * \brief Acquires the gdbr lock and sets up breaking
 * \returns true on success, false on failure
 */
bool gdbr_lock_enter(libgdbr_t *g);

/*!
 * \brief Releases the gdbr lock
 */
void gdbr_lock_leave(libgdbr_t *g);

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

/*!
 * \brief invalidates the reg cache
 */
void gdbr_invalidate_reg_cache(void);

/*!
 * \brief gets reason why remote target stopped
 */
int gdbr_stop_reason(libgdbr_t *g);

/*!
 * \brief checks for extended mode availability
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_check_extended_mode(libgdbr_t *g);

/*!
 * \brief checks which subcommands of the vCont packet are supported
 */
int gdbr_check_vcont(libgdbr_t *g);

/*!
 * \brief sends a qRcmd packet which basically passes a command to the
 * remote target's interpreter.
 * \returns 0 on success and -1 on failure
 */
int gdbr_send_qRcmd(libgdbr_t *g, const char *cmd, PrintfCallback cb_printf);

/*!
 * \brief attaches to a process
 * \param pid of the process to attach to
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_attach(libgdbr_t *g, int pid);

/*!
 * \brief detaches from a process
 * \param pid of the process to detach from (only the multiprocess/pid variant)
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_detach(libgdbr_t *g);
int gdbr_detach_pid(libgdbr_t *g, int pid);

/*!
 * \brief kills the process the remote gdbserver is debugging (TODO: handle pid)
 * \param pid of the process to detach from (only the multiprocess/pid variant)
 * \retuns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_kill(libgdbr_t *g);
int gdbr_kill_pid(libgdbr_t *g, int pid);

// Commands
int gdbr_continue(libgdbr_t *g, int pid, int tid, int sig);
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
int gdbr_write_bin_registers(libgdbr_t *g, const char *regs, int len);
int gdbr_write_reg(libgdbr_t *g, const char *name, char *value, int len);
int gdbr_write_register(libgdbr_t *g, int index, char *value, int len);
int gdbr_write_registers(libgdbr_t *g, char *registers);
int gdbr_read_memory(libgdbr_t *g, ut64 address, ut8 *buf, int len);
int gdbr_write_memory(libgdbr_t *g, ut64 address, const uint8_t *data, ut64 len);
int test_command(libgdbr_t *g, const char *command);

/*!
 * \brief Function sets normal breakpoint (0xcc, int3)
 * \param gdbr instance that contains the current context
 * \param addrress at this position the breakpoint will be added
 * \param conditions TODO: examine how this condition string should look like
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_set_bp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp);
int gdbr_set_hwbp(libgdbr_t *g, ut64 address, const char *conditions, int sizebp);
int gdbr_set_hww(libgdbr_t *g, ut64 address, const char *conditions, int sizebp);
int gdbr_set_hwr(libgdbr_t *g, ut64 address, const char *conditions, int sizebp);
int gdbr_set_hwa(libgdbr_t *g, ut64 address, const char *conditions, int sizebp);
int gdbr_remove_bp(libgdbr_t *g, ut64 address, int sizebp);
int gdbr_remove_hwbp(libgdbr_t *g, ut64 address, int sizebp);
int gdbr_remove_hww(libgdbr_t *g, ut64 address, int sizebp);
int gdbr_remove_hwr(libgdbr_t *g, ut64 address, int sizebp);
int gdbr_remove_hwa(libgdbr_t *g, ut64 address, int sizebp);
/*!
 * File read from remote target (only one file open at a time for now)
 */
int gdbr_open_file(libgdbr_t *g, const char *filename, int flags, int mode);
int gdbr_read_file(libgdbr_t *g, ut8 *buf, ut64 max_len);
int gdbr_close_file(libgdbr_t *g);

/*!
 * \brief get list of threads for given pid
 */
RList* gdbr_threads_list(libgdbr_t *g, int pid);

/*!
 * \brief get a list of the child processes of the given pid
 */
RList* gdbr_pids_list(libgdbr_t *g, int pid);

/*!
 * Get absolute name of file executed to create a process
 */
char* gdbr_exec_file_read(libgdbr_t *g, int pid);

/*!
 * Get offset of lowest segment returned by 'qOffsets'
 */
ut64 gdbr_get_baddr(libgdbr_t *g);

/*!
 * Select pid-tid
 */
int gdbr_select(libgdbr_t *g, int pid, int tid);

#endif  // CLIENT_COMMANDS_H
