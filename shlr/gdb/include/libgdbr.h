/*! \file */
#ifndef LIBGDBR_H
#define LIBGDBR_H

#include <stdint.h>
#include <unistd.h>
#if __UNIX__
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#elif __WINDOWS__
#include <windows.h>
#include <winsock.h>
#endif

#include "arch.h"

#define X86_64 ARCH_X86_64
#define X86_32 ARCH_X86_32

/*! 
 * Structure that saves a gdb message
 */
typedef struct libgdbr_message_t
{
	ssize_t len; /*! Len of the message */
	char* msg;	/*! Pointer to the buffer that contains the message */
	uint8_t chk;	/*! Cheksum of the current message read from the packet */
} libgdbr_message_t;


/*! 
 * Message stack
 */
typedef struct libgdbr_message_stack_t
{
	int count; 
} libgdbr_message_stack_t;


/*! 
 * Core "object" that saves
 * the instance of the lib
 */
typedef struct libgdbr_t 
{
	char* send_buff; // defines a buffer for reading and sending stuff
	ssize_t send_len; // definses the maximal len for the given buffer
	ssize_t send_max; // definses the maximal len for the given buffer
	char* read_buff;
	ssize_t read_len;
	ssize_t read_max;

	// is already handled (i.e. already send or ...)
	int fd; // Filedescriptor // TODO add r_socket stuff from radare
	int connected;
	int acks;
	char* data;
	ssize_t data_len;
	ssize_t data_max;
	uint8_t architecture;
	registers_t* registers;
} libgdbr_t;

/*!
 * \brief Function initializes the libgdbr lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_init(libgdbr_t* instance);

/*!
 * \brief Function initializes the architecture of the gdbsession
 * \param architecture defines the architecure used (registersize, and such)
 * \returns a failure code
 */
int gdbr_set_architecture(libgdbr_t* instance, uint8_t architecture);

/*!
 * \brief frees all buffers and cleans the libgdbr instance stuff
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_cleanup(libgdbr_t* instance);

/*!
 * \brief Function connects to a gdbserver instance
 * \param server string that represents the host
 * \param number that represents the port
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_connect(libgdbr_t* instance, const char* server, int port);

/*!
 * \brief disconnects the lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_disconnect(libgdbr_t* instance);

// Commands
int gdbr_continue(libgdbr_t* instance, int thread_id);
int gdbr_step(libgdbr_t* instance, int thread_id);
int gdbr_read_registers(libgdbr_t* instance);

/*!
 * \brief Function writes general purpose registers
 * \param gdbr instance that contains the current context
 * \param reg contains the registers that should be written
 * reg contains a comma separated string that uses <regname>=value,<regname>=value
 * i.e. eax=0x123,ebx=0x234
 * \returns a failurre code (currently -1) or 0 if call successfully
 */
int gdbr_write_bin_registers(libgdbr_t* instance, char* registers);
int gdbr_write_registers(libgdbr_t* instance, char* registers);
int gdbr_read_memory(libgdbr_t* instance, uint64_t address, uint64_t len);
int gdbr_write_memory(libgdbr_t* instance, uint64_t address, char* data, uint64_t len);
int gdbr_send_command(libgdbr_t* instance, char* command);
int test_command(libgdbr_t* instance, char* command);

/*!
 * \brief Function sets normal breakpoint (0xcc, int3)
 * \param gdbr instance that contains the current context
 * \param addrress at this position the breakpoint will be added
 * \param conditions TODO: examine how this condition string should look like
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_set_breakpoint(libgdbr_t* instance, uint64_t address, char* conditions);
int gdbr_unset_breakpoint(libgdbr_t* instance, uint64_t address);

#endif
