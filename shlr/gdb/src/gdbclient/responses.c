/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "arch.h"
#include "gdbclient/responses.h"
#include "gdbclient/core.h"
#include "gdbr_common.h"
#include "utils.h"
#include "r_util/r_str.h"


int handle_g(libgdbr_t *g) {
	if (unpack_hex (g->data, g->data_len, g->data) < 0) {
		return -1;
	}
	g->data_len = g->data_len / 2;
	return send_ack (g);
}

int handle_G(libgdbr_t *g) {
	return send_ack (g);
}

int handle_M(libgdbr_t *g) {
	return send_ack (g);
}

int handle_P(libgdbr_t *g) {
	if (g->data_len == 0) {
		g->last_code = MSG_NOT_SUPPORTED;
	} else {
		g->last_code = MSG_OK;
	}
	return send_ack (g);
}

int handle_m(libgdbr_t *g) {
	if (g->data_len == 3 && g->data[0] == 'E') {
		// TODO: figure out if this is a problem
		send_ack (g);
		return -1;
	}
	int len = strlen (g->data);
	g->data_len = len / 2;
	unpack_hex (g->data, len, g->data);
	return send_ack (g);
}

int handle_qStatus(libgdbr_t *g) {
	if (!g || !g->data || !*g->data) {
		return -1;
	}
	char *data = strdup (g->data);
	char *tok = strtok (data, ";");
	if (!tok) {
		free (data);
		return -1;
	}
	// TODO: We do not yet handle the case where a trace is already running
	if (strncmp (tok, "T0", 2)) {
		send_ack (g);
		free (data);
		return -1;
	}
	// Ensure that trace was never run
	while (tok != NULL) {
		if (!strncmp (tok, "tnotrun:0", 9)) {
			free (data);
			return send_ack (g);
		}
		tok = strtok (NULL, ";");
	}
	send_ack (g);
	free (data);
	return -1;
}

int handle_qC(libgdbr_t *g) {
	// We get process and thread ID
	if (strncmp (g->data, "QC", 2)) {
		send_ack (g);
		return -1;
	}
	g->data[g->data_len] = '\0';
	if (read_thread_id (g->data + 2, &g->pid, &g->tid, g->stub_features.multiprocess) < 0) {
		send_ack (g);
		return -1;
	}
	return send_ack (g);
}

/*
int handle_execFileRead(libgdbr_t *g) {
	if (g->data[0] == 'E') {
		send_ack (g);
		return -1;
	}
	if (!g->data[1]) {
		// We're supposed to get filename too
		send_ack (g);
		return -1;
	}
	g->exec_file_name = strdup (g->data + 1);
	return send_ack (g);
}

int handle_fOpen(libgdbr_t *g) {
	if (!*g->data || g->data[0] != 'F') {
		send_ack (g);
		return -1;
	}
	g->exec_fd = strtol (g->data + 1, NULL, 16);
	return send_ack (g);
}
 */

int handle_setbp(libgdbr_t *g) {
	return send_ack (g);
}

int handle_removebp(libgdbr_t *g) {
	return send_ack (g);
}

int handle_attach(libgdbr_t *g) {
	if (g->data_len == 3 && g->data[0] == 'E') {
		send_ack (g);
		return -1;
	}
	return send_ack (g);
}

int handle_vFile_open(libgdbr_t *g) {
	if (g->data_len < 2 || g->data[0] != 'F' || g->data[1] == '-'
	    || !isxdigit ((unsigned char)g->data[1])) {
		send_ack (g);
		return -1;
	}
	g->data[g->data_len] = '\0';
	if ((g->remote_file_fd = strtol (g->data + 1, NULL, 16)) <= 0) {
		send_ack (g);
		return -1;
	}
	return send_ack (g);
}

int handle_vFile_pread(libgdbr_t *g, ut8 *buf) {
	send_ack (g);
	char *ptr;
	int len;
	if (g->data_len < 3 || g->data[0] != 'F') {
		return -1;
	}
	// F-1 is an error, yes, but it probably should not be fatal, since it might
	// mean we're reading beyond file end. So this is handled in gdbr_read_file
	if (g->data[1] == '-') {
		return 0;
	}
	if (!isxdigit ((unsigned char)g->data[1])) {
		return -1;
	}
	if (sscanf (g->data, "F%x;", &len) != 1) {
		return -1;
	}
	// Again, this is probably the end of file
	if (len == 0) {
		return 0;
	}
	if (!(ptr = strchr (g->data, ';')) || ptr >= g->data + g->data_len) {
		return -1;
	}
	ptr++;
	if (len > 0) {
		memcpy (buf, ptr, len);
	}
	return len;
}

int handle_vFile_close(libgdbr_t *g) {
	if (g->data_len < 2 || g->data[0] != 'F' || g->data[1] == '-'
	    || !isxdigit ((unsigned char)g->data[1])) {
		send_ack (g);
		return -1;
	}
	return send_ack (g);
}

#include <r_debug.h>
#include <gdbclient/commands.h>

static int stop_reason_exit(libgdbr_t *g) {
	int status = 0, pid = g->pid;
	g->stop_reason.reason = R_DEBUG_REASON_DEAD;
	if (g->stub_features.multiprocess && g->data_len > 3) {
		if (sscanf (g->data + 1, "%x;process:%x", &status, &pid) != 2) {
			eprintf ("Message from remote: %s\n", g->data);
			return -1;
		}
		eprintf ("Process %d exited with status %d\n", pid, status);
		g->stop_reason.thread.pid = pid;
		g->stop_reason.thread.tid = pid;
		g->stop_reason.is_valid = true;
		return 0;
	}
	if (!isxdigit ((unsigned char)g->data[1])) {
		eprintf ("Message from remote: %s\n", g->data);
		return -1;
	}
	status = (int) strtol (g->data + 1, NULL, 16);
	eprintf ("Process %d exited with status %d\n", g->pid, status);
	g->stop_reason.thread.pid = pid;
	g->stop_reason.thread.tid = pid;
	g->stop_reason.is_valid = true;
	// Just to be sure, disconnect
	return gdbr_disconnect (g);
}

static int stop_reason_terminated(libgdbr_t *g) {
	int signal = 0, pid = g->pid;
	g->stop_reason.reason = R_DEBUG_REASON_DEAD;
	if (g->stub_features.multiprocess && g->data_len > 3) {
		if (sscanf (g->data + 1, "%x;process:%x", &signal, &pid) != 2) {
			eprintf ("Message from remote: %s\n", g->data);
			return -1;
		}
		eprintf ("Process %d terminated with signal %d\n", pid, signal);
		g->stop_reason.thread.pid = pid;
		g->stop_reason.thread.tid = pid;
		g->stop_reason.signum = signal;
		g->stop_reason.is_valid = true;
		return 0;
	}
	if (!isxdigit ((unsigned char)g->data[1])) {
		eprintf ("Message from remote: %s\n", g->data);
		return -1;
	}
	signal = (int) strtol (g->data + 1, NULL, 16);
	eprintf ("Process %d terminated with signal %d\n", g->pid, signal);
	g->stop_reason.thread.pid = pid;
	g->stop_reason.thread.tid = pid;
	g->stop_reason.signum = signal;
	g->stop_reason.is_valid = true;
	// Just to be sure, disconnect
	return gdbr_disconnect (g);
}

int handle_stop_reason(libgdbr_t *g) {
	send_ack (g);
	if (g->data_len < 3) {
		return -1;
	}
	switch (g->data[0]) {
	case 'O':
		unpack_hex (g->data + 1, g->data_len - 1, g->data + 1);
		//g->data[g->data_len - 1] = '\0';
		eprintf ("%s", g->data + 1);
		if (send_ack (g) < 0) {
			return -1;
		}
		memset (&g->stop_reason, 0, sizeof (libgdbr_stop_reason_t));
		g->stop_reason.signum = -1;
		g->stop_reason.reason = R_DEBUG_REASON_NONE;
		return 0;
	case 'W':
		return stop_reason_exit (g);
	case 'X':
		return stop_reason_terminated (g);
	}
	if (g->data[0] != 'T') {
		return -1;
	}
	char *ptr1, *ptr2;
	g->data[g->data_len] = '\0';
	free (g->stop_reason.exec.path);
	memset (&g->stop_reason, 0, sizeof (libgdbr_stop_reason_t));
	g->stop_reason.core = -1;
	if (sscanf (g->data + 1, "%02x", &g->stop_reason.signum) != 1) {
		return -1;
	}
	g->stop_reason.is_valid = true;
	g->stop_reason.reason = R_DEBUG_REASON_SIGNAL;
	for (ptr1 = strtok (g->data + 3, ";"); ptr1; ptr1 = strtok (NULL, ";")) {
		if (r_str_startswith (ptr1, "thread") && !g->stop_reason.thread.present) {
			if (!(ptr2 = strchr (ptr1, ':'))) {
				continue;
			}
			ptr2++;
			if (read_thread_id (ptr2, &g->stop_reason.thread.pid,
					    &g->stop_reason.thread.tid,
					    g->stub_features.multiprocess) < 0) {
				continue;
			}
			g->stop_reason.thread.present = true;
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
			if (r_str_startswith (ptr1, "watch")
			    || r_str_startswith (ptr1, "rwatch")
			    || r_str_startswith (ptr1, "awatch")) {
				if (!(ptr2 = strchr (ptr1, ':'))) {
					continue;
				}
				ptr2++;
				if (!isxdigit ((unsigned char)*ptr2)) {
					continue;
				}
				g->stop_reason.watchpoint.addr = strtoll (ptr2, NULL, 16);
				g->stop_reason.watchpoint.present = true;
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
			if (r_str_startswith (ptr1, "fork") && !g->stop_reason.fork.present) {
				if (!(ptr2 = strchr (ptr1, ':'))) {
					continue;
				}
				ptr2++;
				if (read_thread_id (ptr2, &g->stop_reason.fork.pid,
						    &g->stop_reason.fork.tid,
						    g->stub_features.multiprocess) < 0) {
					continue;
				}
				g->stop_reason.fork.present = true;
				continue;
			}
			if (r_str_startswith (ptr1, "vfork") && !g->stop_reason.vfork.present) {
				if (!(ptr2 = strchr (ptr1, ':'))) {
					continue;
				}
				ptr2++;
				if (read_thread_id (ptr2, &g->stop_reason.vfork.pid,
						    &g->stop_reason.vfork.tid,
						    g->stub_features.multiprocess) < 0) {
					continue;
				}
				g->stop_reason.vfork.present = true;
				continue;
			}
			if (r_str_startswith (ptr1, "vforkdone")) {
				g->stop_reason.vforkdone = true;
				continue;
			}
			if (r_str_startswith (ptr1, "library")) {
				g->stop_reason.library = true;
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
	if (g->stop_reason.signum == 5) {
		g->stop_reason.reason = R_DEBUG_REASON_BREAKPOINT;
	}
	return 0;
}

int handle_cont(libgdbr_t *g) {
	return handle_stop_reason (g);
}

int handle_lldb_read_reg(libgdbr_t *g) {
	if (send_ack (g) < 0) {
		return -1;
	}
	char *ptr, *ptr2, *buf;
	size_t regnum, tot_regs, buflen = 0;

	// Get maximum register number
	for (regnum = 0; *g->registers[regnum].name; regnum++) {
		if (g->registers[regnum].offset + g->registers[regnum].size > buflen) {
			buflen = g->registers[regnum].offset + g->registers[regnum].size;
		}
	}
	tot_regs = regnum;

	// We're not using the receive buffer till next packet anyway. Better use it
	buf = g->read_buff;
	memset (buf, 0, buflen);

	if (!(ptr = strtok (g->data, ";"))) {
		return -1;
	}
	while (ptr) {
		if (!isxdigit ((unsigned char)*ptr)) {
			// This is not a reg value. Skip
			ptr = strtok (NULL, ";");
			continue;
		}
		// Get register number
		regnum = (int) strtoul (ptr, NULL, 16);
		if (regnum >= tot_regs || !(ptr2 = strchr (ptr, ':'))) {
			ptr = strtok (NULL, ";");
			continue;
		}
		ptr2++;
		// Write to offset
		unpack_hex (ptr2, strlen (ptr2), buf + g->registers[regnum].offset);
		ptr = strtok (NULL, ";");
		continue;
	}
	memcpy (g->data, buf, buflen);
	g->data_len = buflen;
	return 0;
}
