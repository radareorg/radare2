/*! \file */
#ifndef LIBQNXR_H
#define LIBQNXR_H

#include <stdint.h>
#include <unistd.h>

#include "arch.h"
#include "r_types_base.h"
#include "r_socket.h"
#include "dsmsgs.h"

#define MSG_OK 0
#define MSG_NOT_SUPPORTED -1
#define MSG_ERROR_1 -2

#define X86_64 ARCH_X86_64
#define X86_32 ARCH_X86_32
#define ARM_32 ARCH_ARM_32
#define ARM_64 ARCH_ARM_64

typedef struct
	{
	st32 pid;
	st64 tid;
} ptid_t;

/*! 
 * Core "object" that saves
 * the instance of the lib
 */
typedef struct libqnxr_t {
	char *read_buff;
	char *send_buff;
	ssize_t send_len;
	ssize_t read_len;
	ssize_t read_ptr;
	RSocket *sock;
	char host[256];
	int port;
	int connected;
	ut8 mid;
	union {
		ut8 data[DS_DATA_MAX_SIZE];
		DSMsg_union_t pkt;
	} tran, recv;
	ssize_t data_len;
	ut8 architecture;
	registers_t *registers;
	int channelrd;
	int channelwr;
	int target_proto_minor;
	int target_proto_major;
	int stop_flags;
	ut8 notify_type;
	ut32 stop_pc;
	int signal;
	ptid_t inferior_ptid;
	int waiting_for_stop;
} libqnxr_t;

typedef void(pidlist_cb_t)(void *ctx, pid_t pid, char *name);

int qnxr_init (libqnxr_t *g);
int qnxr_set_architecture (libqnxr_t *g, ut8 architecture);
int qnxr_cleanup (libqnxr_t *g);
int qnxr_connect (libqnxr_t *g, const char *server, int port);
int qnxr_disconnect (libqnxr_t *g);
void qnxr_pidlist (libqnxr_t *g, void *ctx, pidlist_cb_t *cb);
int qnxr_select (libqnxr_t *g, pid_t pid, int tid);
ptid_t qnxr_run (libqnxr_t *g, const char *file, char **args, char **env);
ptid_t qnxr_attach (libqnxr_t *g, pid_t pid);
ptid_t qnxr_wait (libqnxr_t *g, pid_t pid);
int qnxr_stop (libqnxr_t *g);

// Commands
int qnxr_continue (libqnxr_t *g, int thread_id);
int qnxr_step (libqnxr_t *g, int thread_id);
int qnxr_read_registers (libqnxr_t *g);

int qnxr_write_reg (libqnxr_t *g, const char *name, char *value, int len);
int qnxr_write_register (libqnxr_t *g, int index, char *value, int len);
int qnxr_read_memory (libqnxr_t *g, ut64 address, ut8 *data, ut64 len);
int qnxr_write_memory (libqnxr_t *g, ut64 address, const ut8 *data, ut64 len);

int qnxr_set_bp (libqnxr_t *g, ut64 address, const char *conditions);
int qnxr_set_hwbp (libqnxr_t *g, ut64 address, const char *conditions);
int qnxr_remove_bp (libqnxr_t *g, ut64 address);
int qnxr_remove_hwbp (libqnxr_t *g, ut64 address);

// ptid
extern ptid_t null_ptid;
int ptid_equal (ptid_t ptid1, ptid_t ptid2);

#endif
