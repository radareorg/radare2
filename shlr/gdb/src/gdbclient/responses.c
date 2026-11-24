/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "arch.h"
#include "gdbclient/responses.h"
#include "gdbr_common.h"
#include "utils.h"
#include "r_util/r_str.h"
#include "r_util/r_log.h"

static int handle_ok(libgdbr_t *g) {
	return g->data_len == 2 && !memcmp (g->data, "OK", 2)? 0: -1;
}

int handle_G(libgdbr_t *g) {
	return handle_ok (g);
}

int handle_M(libgdbr_t *g) {
	return handle_ok (g);
}

int handle_P(libgdbr_t *g) {
	if (!g->data_len) {
		g->last_code = MSG_NOT_SUPPORTED;
		return 0;
	}
	int ret = handle_ok (g);
	g->last_code = ret < 0? MSG_ERROR_1: MSG_OK;
	return ret;
}

int handle_m(libgdbr_t *g, int requested) {
	if (!g->data_len || (g->data_len & 1) || g->data_len / 2 > requested) {
		return -1;
	}
	int i;
	for (i = 0; i < g->data_len / 2; i++) {
		int high = hex2int (g->data[i * 2]);
		int low = hex2int (g->data[i * 2 + 1]);
		if (high < 0 || low < 0) {
			return -1;
		}
		g->data[i] = (char)((high << 4) | low);
	}
	g->data_len = i;
	return 0;
}

int handle_qStatus(libgdbr_t *g) {
	if (!g || !g->data || !*g->data) {
		return -1;
	}
	char *data = strdup (g->data);
	char *save_ptr = NULL;
	char *tok = r_str_tok_r (data, ";", &save_ptr);
	if (!tok) {
		free (data);
		return -1;
	}
	// TODO: We do not yet handle the case where a trace is already running
	if (!r_str_startswith (tok, "T0")) {
		free (data);
		return -1;
	}
	// Ensure that trace was never run
	while (tok) {
		if (r_str_startswith (tok, "tnotrun:0")) {
			free (data);
			return 0;
		}
		tok = r_str_tok_r (NULL, ";", &save_ptr);
	}
	free (data);
	return -1;
}

int handle_qC(libgdbr_t *g) {
	// We get process and thread ID
	if (strncmp (g->data, "QC", 2)) {
		return -1;
	}
	g->data[g->data_len] = '\0';
	if (read_thread_id (g->data + 2, &g->pid, &g->tid, g->stub_features.multiprocess) < 0) {
		return -1;
	}
	return 0;
}

int handle_setbp(libgdbr_t *g) {
	return handle_ok (g);
}

int handle_attach(libgdbr_t *g) {
	if (g->data_len > 0 && g->data[0] == 'E') {
		return -1;
	}
	return 0;
}

int handle_vFile_open(libgdbr_t *g) {
	if (g->data_len < 2 || g->data[0] != 'F' || g->data[1] == '-'
	    || !isxdigit ((unsigned char)g->data[1])) {
		return -1;
	}
	g->data[g->data_len] = '\0';
	if ((g->remote_file_fd = strtol (g->data + 1, NULL, 16)) <= 0) {
		return -1;
	}
	return 0;
}

int handle_vFile_pread(libgdbr_t *g, ut8 *buf, size_t max_len) {
	char *ptr, *end;
	if (g->data_len < 3 || g->data[0] != 'F') {
		return -1;
	}
	// F-1 is an error, yes, but it probably should not be fatal, since it might
	// mean we're reading beyond file end. So this is handled in gdbr_read_file
	if (g->data[1] == '-') {
		return 0;
	}
	if (!isxdigit ((ut8)g->data[1])) {
		return -1;
	}
	ptr = memchr (g->data + 2, ';', g->data_len - 2);
	if (!ptr) {
		return -1;
	}
	unsigned long declared_len = strtoul (g->data + 1, &end, 16);
	if (end != ptr || declared_len > INT_MAX) {
		return -1;
	}
	// Again, this is probably the end of file
	if (!declared_len) {
		return 0;
	}
	ptr++;
	size_t available_len = g->data_len - (ptr - g->data);
	size_t copy_len = R_MIN ((size_t)declared_len, max_len);
	copy_len = R_MIN (copy_len, available_len);
	if (copy_len > 0) {
		memcpy (buf, ptr, copy_len);
	}
	return (int)copy_len;
}

int handle_vFile_close(libgdbr_t *g) {
	if (g->data_len < 2 || g->data[0] != 'F' || g->data[1] == '-'
	    || !isxdigit ((unsigned char)g->data[1])) {
		return -1;
	}
	return 0;
}

#include <r_debug.h>
#include <gdbclient/commands.h>

static bool parse_thread_stop(const char *data, const char *prefix, int *pid, int *tid, bool multiprocess, bool *present) {
	if (*present || !r_str_startswith (data, prefix)) {
		return false;
	}
	const char *colon = strchr (data, ':');
	if (!colon || read_thread_id (colon + 1, pid, tid, multiprocess) < 0) {
		return false;
	}
	*present = true;
	return true;
}

// A stop reply pair "n:r" whose n is a hex number states register n.
// Its value is kept unless 'g' is known to fetch the whole block anyway.
static bool stop_reason_register(libgdbr_t *g, const char *tok) {
	const char *colon = tok;
	while (isxdigit ((ut8)*colon)) {
		colon++;
	}
	if (colon == tok || *colon != ':') {
		return false;
	}
	if (g->caps.g != 1) {
		gdbr_regs_store (g, strtoull (tok, NULL, 16), colon + 1, strlen (colon + 1));
	}
	return true;
}

static int stop_reason_death(libgdbr_t *g, bool is_signal) {
	ut64 value, pid = g->pid;
	const char *end = gdbr_parse_hex_value (g->data + 1, &value);
	if (!end || value > (is_signal? UT8_MAX: UT32_MAX)) {
		return -1;
	}
	const bool multi = *end != '\0';
	if (multi) {
		const char *prefix = ";process:";
		if (!g->stub_features.multiprocess || !r_str_startswith (end, prefix)) {
			return -1;
		}
		end = gdbr_parse_hex_value (end + strlen (prefix), &pid);
		if (!end || (*end && strcmp (end, ";")) || pid == 0 || pid > INT_MAX) {
			return -1;
		}
	} else {
		gdbr_disconnect (g);
	}
	libgdbr_stop_reason_t *stop = &g->stop_reason;
	gdbr_stop_reason_reset (stop);
	stop->reason = R_DEBUG_REASON_DEAD;
	stop->thread.pid = pid;
	stop->thread.tid = pid;
	stop->thread.present = multi;
	if (is_signal) {
		stop->signum = value;
	} else {
		stop->exited_normally = true;
		stop->exit_code = value;
	}
	stop->is_valid = true;
	return 0;
}

static bool parse_watch_stop(libgdbr_stop_reason_t *reason, const char *field) {
	int type;
	if (r_str_startswith (field, "watch:")) {
		type = R_DEBUG_REASON_WATCHPOINT_WRITE;
	} else if (r_str_startswith (field, "rwatch:")) {
		type = R_DEBUG_REASON_WATCHPOINT_READ;
	} else if (r_str_startswith (field, "awatch:")) {
		type = R_DEBUG_REASON_WATCHPOINT_ACCESS;
	} else {
		return false;
	}
	ut64 address;
	const char *end = gdbr_parse_hex_value (strchr (field, ':') + 1, &address);
	if (!end || *end) {
		return false;
	}
	reason->watchpoint.addr = address;
	reason->watchpoint.present = true;
	reason->reason = type;
	return true;
}

int handle_stop_reason(libgdbr_t *g) {
	if (g->data_len < 2 || memchr (g->data, '\0', g->data_len)) {
		return -1;
	}
	switch (g->data[0]) {
	case 'W':
		return stop_reason_death (g, false);
	case 'X':
		return stop_reason_death (g, true);
	}
	if (g->data_len < 3 || (g->data[0] != 'T' && g->data[0] != 'S')
	    || (g->data[0] == 'S' && g->data_len != 3)) {
		return -1;
	}
	const int high = hex2int ((ut8)g->data[1]);
	const int low = hex2int ((ut8)g->data[2]);
	if (high < 0 || low < 0) {
		return -1;
	}
	gdbr_stop_reason_reset (&g->stop_reason);
	g->stop_reason.core = -1;
	g->stop_reason.signum = high * 16 + low;
	g->stop_reason.is_valid = true;
	g->stop_reason.reason = g->stop_reason.signum == 5? R_DEBUG_REASON_BREAKPOINT: R_DEBUG_REASON_SIGNAL;
	if (g->data[0] == 'S') {
		return 0;
	}
	char *ptr1, *ptr2;
	char *save_ptr = NULL;
	g->data[g->data_len] = '\0';
	for (ptr1 = r_str_tok_r (g->data + 3, ";", &save_ptr); ptr1; ptr1 = r_str_tok_r (NULL, ";", &save_ptr)) {
		if (stop_reason_register (g, ptr1)) {
			continue;
		}
		if (parse_thread_stop (ptr1, "thread", &g->stop_reason.thread.pid,
				&g->stop_reason.thread.tid, g->stub_features.multiprocess,
				&g->stop_reason.thread.present)) {
			continue;
		}
		if (r_str_startswith (ptr1, "core")) {
			if (!(ptr2 = strchr (ptr1, ':'))) {
				continue;
			}
			ptr2++;
			if (!isxdigit ((unsigned char)*ptr2)) {
				continue;
			}
			g->stop_reason.core = (int) strtol (ptr2, NULL, 16);
			continue;
		}
		if (g->stop_reason.signum == 5) {
			if (parse_watch_stop (&g->stop_reason, ptr1)) {
				continue;
			}
			if (r_str_startswith (ptr1, "exec") && !g->stop_reason.exec.present) {
				if (!(ptr2 = strchr (ptr1, ':'))) {
					continue;
				}
				ptr2++;
				if (!(g->stop_reason.exec.path = calloc (strlen (ptr1) / 2, 1))) {
					continue;
				}
				unpack_hex (ptr2, strlen (ptr2), g->stop_reason.exec.path);
				g->stop_reason.exec.present = true;
				continue;
			}
			if (parse_thread_stop (ptr1, "fork", &g->stop_reason.fork.pid,
					&g->stop_reason.fork.tid, g->stub_features.multiprocess,
					&g->stop_reason.fork.present)) {
				continue;
			}
			if (parse_thread_stop (ptr1, "vfork", &g->stop_reason.vfork.pid,
					&g->stop_reason.vfork.tid, g->stub_features.multiprocess,
					&g->stop_reason.vfork.present)) {
				continue;
			}
			if (r_str_startswith (ptr1, "vforkdone")) {
				g->stop_reason.vforkdone = true;
				continue;
			}
			if (r_str_startswith (ptr1, "library:")) {
				if (!g->stop_reason.library) {
					g->library_generation++;
				}
				g->stop_reason.library = true;
				g->stop_reason.reason = R_DEBUG_REASON_STOPPED;
				continue;
			}
			if (r_str_startswith (ptr1, "swbreak")) {
				g->stop_reason.swbreak = true;
				continue;
			}
			if (r_str_startswith (ptr1, "hwbreak")) {
				g->stop_reason.hwbreak = true;
				continue;
			}
			if (r_str_startswith (ptr1, "create")) {
				g->stop_reason.create = true;
				continue;
			}
		}
	}
	// The registers a stop reply states are its thread's, not those of the thread register packets address
	if (g->stop_reason.thread.present && g->tid > 0 && g->stop_reason.thread.tid != g->tid) {
		gdbr_regs_invalidate (g);
	}
	return 0;
}

int handle_cont(libgdbr_t *g) {
	return handle_stop_reason (g);
}
