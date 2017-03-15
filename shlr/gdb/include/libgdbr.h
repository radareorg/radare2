/*! \file */
#ifndef LIBGDBR_H
#define LIBGDBR_H

#include <stdint.h>
#include <unistd.h>

#include "arch.h"
#include "r_types_base.h"
#include "r_socket.h"

#define X86_64 ARCH_X86_64
#define X86_32 ARCH_X86_32
#define ARM_32 ARCH_ARM_32
#define ARM_64 ARCH_ARM_64
#define MIPS ARCH_MIPS
#define AVR ARCH_AVR
#define LM32 ARCH_LM32

#define MSG_OK 0
#define MSG_NOT_SUPPORTED -1
#define MSG_ERROR_1 -2

/*!
 * Structure that saves a gdb message
 */
typedef struct libgdbr_message_t {
	ssize_t len; /*! Len of the message */
	char* msg;	/*! Pointer to the buffer that contains the message */
	uint8_t chk;	/*! Cheksum of the current message read from the packet */
} libgdbr_message_t;

/*!
 * Structure that stores features supported
 */

typedef struct libgdbr_stub_features_t {
	ssize_t pkt_sz; /* Max packet size */
	unsigned qXfer_btrace_read : 1;
	unsigned qXfer_btrace_conf_read : 1;
	unsigned qXfer_spu_read : 1;
	unsigned qXfer_spu_write : 1;
	unsigned qXfer_libraries_read : 1;
	unsigned qXfer_libraries_svr4_read : 1;
	unsigned qXfer_siginfo_read : 1;
	unsigned qXfer_siginfo_write : 1;
	unsigned qXfer_auxv_read : 1;
	unsigned qXfer_exec_file_read : 1;
	unsigned qXfer_features_read : 1;
	unsigned qXfer_memory_map_read : 1;
	unsigned qXfer_sdata_read : 1;
	unsigned qXfer_threads_read : 1;
	unsigned qXfer_traceframe_info_read : 1;
	unsigned qXfer_uib_read : 1;
	unsigned qXfer_fdpic_read : 1;
	unsigned qXfer_osdata_read : 1;
	unsigned Qbtrace_off : 1;
	unsigned Qbtrace_bts : 1;
	unsigned Qbtrace_pt : 1;
	unsigned Qbtrace_conf_bts_size : 1;
	unsigned Qbtrace_conf_pt_size: 1;
	unsigned QNonStop : 1;
	unsigned QCatchSyscalls : 1;
	unsigned QPassSignals : 1;
	unsigned QStartNoAckMode : 1;
	unsigned QAgent : 1;
	unsigned QAllow : 1;
	unsigned QDisableRandomization : 1;
	unsigned QTBuffer_size : 1;
	unsigned QThreadEvents : 1;
	unsigned StaticTracepoint : 1;
	unsigned InstallInTrace : 1;
	unsigned ConditionalBreakpoints : 1;
	unsigned ConditionalTracepoints : 1;
	unsigned ReverseContinue : 1;
	unsigned ReverseStep : 1;
	unsigned swbreak : 1;
	unsigned hwbreak : 1;
	unsigned fork_events : 1;
	unsigned vfork__events : 1;
	unsigned exec_events : 1;
	unsigned vContSupported : 1;
	unsigned no_resumed : 1;
	unsigned augmented_libraries_svr4_read : 1;
	unsigned multiprocess : 1;
	unsigned TracepointSource : 1;
	unsigned EnableDisableTracepoints : 1;
	unsigned tracenz : 1;
	unsigned BreakpointCommands : 1;
} libgdbr_stub_features_t;

/*!
 * Core "object" that saves
 * the instance of the lib
 */
typedef struct libgdbr_t {
	char* send_buff; // defines a buffer for reading and sending stuff
	ssize_t send_len;
	ssize_t send_max; // defines the maximal len for the given buffer
	char* read_buff;
	ssize_t read_max; // defines the maximal len for the given buffer

	// is already handled (i.e. already send or ...)
	RSocket* sock;
	int connected;
	int acks;
	char* data;
	ssize_t data_len;
	ssize_t data_max;
	uint8_t architecture;
	registers_t* registers;
	int last_code;
	ssize_t pid; // little endian
	ssize_t tid; // little endian
	bool attached; // Remote server attached to process or created
	libgdbr_stub_features_t stub_features;
	char* exec_file_name;
} libgdbr_t;

/*!
 * \brief Function initializes the libgdbr lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_init(libgdbr_t* g);

/*!
 * \brief Function initializes the architecture of the gdbsession
 * \param architecture defines the architecure used (registersize, and such)
 * \returns a failure code
 */
int gdbr_set_architecture(libgdbr_t* g, uint8_t architecture);

/*!
 * \brief frees all buffers and cleans the libgdbr instance stuff
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_cleanup(libgdbr_t* g);

/*!
 * \brief Function connects to a gdbserver instance
 * \param server string that represents the host
 * \param number that represents the port
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_connect(libgdbr_t* g, const char* server, int port);

/*!
 * \brief disconnects the lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_disconnect(libgdbr_t* g);

// Commands
int gdbr_continue(libgdbr_t* g, int thread_id);
int gdbr_step(libgdbr_t* g, int thread_id);
int gdbr_read_registers(libgdbr_t* g);

/*!
 * \brief Function writes general purpose registers
 * \param gdbr instance that contains the current context
 * \param reg contains the registers that should be written
 * reg contains a comma separated string that uses <regname>=value,<regname>=value
 * i.e. eax=0x123,ebx=0x234
 * \returns a failurre code (currently -1) or 0 if call successfully
 */
int gdbr_write_bin_registers(libgdbr_t* g);
int gdbr_write_reg(libgdbr_t* g, const char* name, char* value, int len);
int gdbr_write_register(libgdbr_t* g, int index, char* value, int len);
int gdbr_write_registers(libgdbr_t* g, char* registers);
int gdbr_read_memory(libgdbr_t* g, ut64 address, ut64 len);
int gdbr_write_memory(libgdbr_t* g, ut64 address, const uint8_t* data, ut64 len);
int gdbr_send_command(libgdbr_t* g, char* command);
int test_command(libgdbr_t* g, const char* command);

/*!
 * \brief Function sets normal breakpoint (0xcc, int3)
 * \param gdbr instance that contains the current context
 * \param addrress at this position the breakpoint will be added
 * \param conditions TODO: examine how this condition string should look like
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_set_bp(libgdbr_t* g, ut64 address, const char* conditions);
int gdbr_set_hwbp(libgdbr_t* g, ut64 address, const char* conditions);
int gdbr_remove_bp(libgdbr_t* g, ut64 address);
int gdbr_remove_hwbp(libgdbr_t* g, ut64 address);

#endif
