/* radare - MIT - Copyright 2026 - pancake */

// team debugging session over the <kernel/debugger.h> port protocol, owned by the haiku io plugin (desc->data) and shared with the debug plugin

#ifndef R2_HAIKU_H
#define R2_HAIKU_H

#ifdef __HAIKU__

#include <r_types.h>
#include <string.h>
#include <kernel/OS.h>
#include <kernel/image.h>
#include <kernel/debugger.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_io_haiku_dbg_t {
	team_id team;
	thread_id main_thread;
	port_id debugger_port; // kernel debugger events arrive here
	port_id nub_port; // requests to the team's debug nub go here
	port_id reply_port; // synchronous nub replies arrive here
	thread_id stopped_thread; // thread currently stopped in the debugger, -1 if none
	int32 event_code; // code of the last debugger event received
	int pending; // stop reason recorded at attach time for the next wait
} RIOHaikuDbg;

static inline status_t r_haiku_send_msg(RIOHaikuDbg *hdbg, int32 code, const void *msg, size_t msg_size, void *reply, size_t reply_size) {
	status_t res;
	do {
		res = write_port (hdbg->nub_port, code, msg, msg_size);
	} while (res == B_INTERRUPTED);
	if (res == B_OK && reply) {
		int32 reply_code;
		ssize_t n;
		do {
			n = read_port (hdbg->reply_port, &reply_code, reply, reply_size);
		} while (n == B_INTERRUPTED);
		if (n < 0) {
			return (status_t)n;
		}
	}
	return res;
}

// read from or write into the team's memory; exactly one of rbuf/wbuf is set
static inline int r_haiku_mem(RIOHaikuDbg *hdbg, ut64 addr, ut8 *rbuf, const ut8 *wbuf, int len) {
	int left = len;
	while (left > 0) {
		const int32 chunk = R_MIN (left, B_MAX_READ_WRITE_MEMORY_SIZE);
		int32 done;
		if (wbuf) {
			debug_nub_write_memory msg = {
				.reply_port = hdbg->reply_port,
				.address = (void *)(size_t)addr,
				.size = chunk
			};
			debug_nub_write_memory_reply reply;
			memcpy (msg.data, wbuf, chunk);
			// shrink the message to the actual payload like debug_support does
			if (r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_WRITE_MEMORY, &msg,
					sizeof (msg) - sizeof (msg.data) + chunk,
					&reply, sizeof (reply)) != B_OK || reply.error != B_OK || reply.size < 1) {
				break;
			}
			done = reply.size;
			wbuf += done;
		} else {
			debug_nub_read_memory msg = {
				.reply_port = hdbg->reply_port,
				.address = (void *)(size_t)addr,
				.size = chunk
			};
			debug_nub_read_memory_reply reply;
			if (r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_READ_MEMORY, &msg,
					sizeof (msg), &reply, sizeof (reply)) != B_OK
					|| reply.error != B_OK || reply.size < 1) {
				break;
			}
			done = reply.size;
			memcpy (rbuf, reply.data, done);
			rbuf += done;
		}
		addr += done;
		left -= done;
	}
	return len - left;
}

// resume a thread that is stopped in the debugger behind the given nub port
static inline bool r_haiku_continue_thread(port_id nub_port, thread_id tid, bool single_step, uint32 handle_event) {
	debug_nub_continue_thread msg = {
		.thread = tid,
		.handle_event = handle_event,
		.single_step = single_step
	};
	status_t res;
	do {
		res = write_port (nub_port, B_DEBUG_MESSAGE_CONTINUE_THREAD, &msg, sizeof (msg));
	} while (res == B_INTERRUPTED);
	return res == B_OK;
}

static inline void r_haiku_dbg_free(RIOHaikuDbg *hdbg, bool detach) {
	if (hdbg) {
		if (detach) {
			if (hdbg->stopped_thread >= 0) {
				r_haiku_continue_thread (hdbg->nub_port, hdbg->stopped_thread, false, B_THREAD_DEBUG_HANDLE_EVENT);
			}
			remove_team_debugger (hdbg->team);
		}
		if (hdbg->debugger_port >= 0) {
			delete_port (hdbg->debugger_port);
		}
		if (hdbg->reply_port >= 0) {
			delete_port (hdbg->reply_port);
		}
		free (hdbg);
	}
}

// install ourselves as the debugger of the given team
static inline RIOHaikuDbg *r_haiku_dbg_new(int pid) {
	RIOHaikuDbg *hdbg = R_NEW0 (RIOHaikuDbg);
	if (!hdbg) {
		return NULL;
	}
	hdbg->team = (team_id)pid;
	hdbg->main_thread = hdbg->stopped_thread = -1;
	hdbg->debugger_port = create_port (10, "radare2 debugger port");
	hdbg->reply_port = create_port (10, "radare2 debug reply port");
	hdbg->nub_port = (hdbg->debugger_port < 0 || hdbg->reply_port < 0)
		? B_ERROR: install_team_debugger (hdbg->team, hdbg->debugger_port);
	if (hdbg->nub_port < 0) {
		r_haiku_dbg_free (hdbg, false);
		return NULL;
	}
	// stop on signals, images and threads; exceptions, breakpoints and debugger() calls are always delivered
	debug_nub_set_team_flags flags = {
		.flags = B_TEAM_DEBUG_SIGNALS | B_TEAM_DEBUG_IMAGES | B_TEAM_DEBUG_THREADS
	};
	r_haiku_send_msg (hdbg, B_DEBUG_MESSAGE_SET_TEAM_FLAGS, &flags, sizeof (flags), NULL, 0);
	thread_info ti;
	int32 cookie = 0;
	if (get_next_thread_info (hdbg->team, &cookie, &ti) == B_OK) {
		hdbg->main_thread = ti.thread;
	}
	return hdbg;
}

#ifdef __cplusplus
}
#endif

#endif // __HAIKU__

#endif // R2_HAIKU_H
