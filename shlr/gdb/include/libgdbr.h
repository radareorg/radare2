/*! \file */
#ifndef LIBGDBR_H
#define LIBGDBR_H

#include <stdint.h>
#ifdef _MSC_VER
typedef unsigned int ssize_t;
#endif

#include "arch.h"
#include "r_types_base.h"
#include "r_socket.h"
#include "r_th.h"

#define MSG_OK 0
#define MSG_NOT_SUPPORTED -1
#define MSG_ERROR_1 -2

#define GDB_REMOTE_TYPE_GDB 0
#define GDB_REMOTE_TYPE_LLDB 1
#define GDB_MAX_PKTSZ 4

/*!
 * Structure that saves a gdb message
 */
typedef struct libgdbr_message_t {
	ssize_t len; /*! Len of the message */
	char *msg;      /*! Pointer to the buffer that contains the message */
	uint8_t chk;    /*! Cheksum of the current message read from the packet */
} libgdbr_message_t;

/*!
 * Structure that stores features supported
 */

typedef struct libgdbr_stub_features_t {
	ut32 pkt_sz; /* Max packet size */
	bool qXfer_btrace_read;
	bool qXfer_btrace_conf_read;
	bool qXfer_spu_read;
	bool qXfer_spu_write;
	bool qXfer_libraries_read;
	bool qXfer_libraries_svr4_read;
	bool qXfer_siginfo_read;
	bool qXfer_siginfo_write;
	bool qXfer_auxv_read;
	bool qXfer_exec_file_read;
	bool qXfer_features_read;
	bool qXfer_memory_map_read;
	bool qXfer_sdata_read;
	bool qXfer_threads_read;
	bool qXfer_traceframe_info_read;
	bool qXfer_uib_read;
	bool qXfer_fdpic_read;
	bool qXfer_osdata_read;
	bool Qbtrace_off;
	bool Qbtrace_bts;
	bool Qbtrace_pt;
	bool Qbtrace_conf_bts_size;
	bool Qbtrace_conf_pt_size;
	bool QNonStop;
	bool QCatchSyscalls;
	bool QPassSignals;
	bool QStartNoAckMode;
	bool QAgent;
	bool QAllow;
	bool QDisableRandomization;
	bool QTBuffer_size;
	bool QThreadEvents;
	bool StaticTracepoint;
	bool InstallInTrace;
	bool ConditionalBreakpoints;
	bool ConditionalTracepoints;
	bool ReverseContinue;
	bool ReverseStep;
	bool swbreak;
	bool hwbreak;
	bool fork_events;
	bool vfork__events;
	bool exec_events;
	bool vContSupported;
	bool no_resumed;
	bool augmented_libraries_svr4_read;
	bool multiprocess;
	bool TracepointSource;
	bool EnableDisableTracepoints;
	bool tracenz;
	bool BreakpointCommands;
	// lldb-specific features
	struct {
		bool g;
		bool QThreadSuffixSupported;
		bool QListThreadsInStopReply;
		bool qEcho;
	} lldb;
	// Cannot be determined with qSupported, found out on query
	bool qC;
	int extended_mode;
	struct {
		bool c, C, s, S, t, r;
	} vcont;
	bool P;
} libgdbr_stub_features_t;

/*!
 * Structure for fstat data sent by gdb remote server
 */
R_PACKED(
typedef struct libgdbr_fstat_t {
	unsigned dev;
	unsigned ino;
	unsigned mode;
	unsigned numlinks;
	unsigned uid;
	unsigned gid;
	unsigned rdev;
	uint64_t size;
	uint64_t blksize;
	uint64_t blocks;
	unsigned atime;
	unsigned mtime;
	unsigned ctime;
}) libgdbr_fstat_t;

/*!
 * Stores information from the stop-reply packet (why target stopped)
 */
typedef struct libgdbr_stop_reason {
	unsigned signum;
	int core;
	int reason;
	bool syscall;
	bool library;
	bool swbreak;
	bool hwbreak;
	bool create;
	bool vforkdone;
	bool is_valid;
	struct {
		bool present;
		ut64 addr;
	} watchpoint;
	struct {
		bool present;
		char *path;
	} exec;
	struct {
		bool present;
		int pid;
		int tid;
	} thread, fork, vfork;
} libgdbr_stop_reason_t;

/*!
 * Core "object" that saves
 * the instance of the lib
 */
typedef struct libgdbr_t {
	char *send_buff; // defines a buffer for reading and sending stuff
	ssize_t send_len;
	ssize_t send_max; // defines the maximal len for the given buffer
	char *read_buff;
	ssize_t read_max; // defines the maximal len for the given buffer
	ssize_t read_len; // len of read_buff (if read_buff not fully consumed)

	// is already handled (i.e. already send or ...)
	RSocket *sock;
	int connected;
	int acks;
	char *data;
	ssize_t data_len;
	ssize_t data_max;
	gdb_reg_t *registers;
	int last_code;
	int pid; // little endian
	int tid; // little endian
	int page_size; // page size for target (useful for qemu)
	bool attached; // Remote server attached to process or created
	libgdbr_stub_features_t stub_features;

	int remote_file_fd; // For remote file I/O
	int num_retries; // number of retries for packet reading

	int remote_type;
	bool no_ack;
	bool is_server;
	bool server_debug;
	bool get_baddr;
	libgdbr_stop_reason_t stop_reason;

	RThreadLock *gdbr_lock;
	int gdbr_lock_depth; // current depth inside the recursive lock

	// parsed from target
	struct {
		char *regprofile;
		int arch, bits;
		bool valid;
	} target;

	bool isbreaked;
} libgdbr_t;

/*!
 * \brief Function initializes the libgdbr lib
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_init(libgdbr_t *g, bool is_server);

/*!
 * \brief Function initializes the architecture of the gdbsession
 * \param architecture defines the architecure used (registersize, and such)
 * \returns false on failure
 */
bool gdbr_set_architecture(libgdbr_t *g, int arch, int bits);

/*!
 * \brief Function get gdb registers profile based on arch and bits
 * \param architecture and bit size.
 * \returns a failure code
 */
const char *gdbr_get_reg_profile(int arch, int bits);

/*!
 * \brief Function set the gdbr internal registers profile
 * \param registers profile string which shares the same format as RReg API
 * \returns a failure code
 */
int gdbr_set_reg_profile(libgdbr_t *g, const char *str);

/*!
 * \brief frees all buffers and cleans the libgdbr instance stuff
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int gdbr_cleanup(libgdbr_t *g);

#endif
