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
	g->data_len = strlen (g->data) / 2;
	unpack_hex (g->data, len, g->data);
	return send_ack (g);
}

int handle_cmd(libgdbr_t *g) {
	unpack_hex (g->data, strlen (g->data), g->data);
	g->data_len = strlen (g->data) / 2;
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
	char *t1, *t2;
	// We get process and thread ID
	if (strncmp (g->data, "QC", 2)) {
		send_ack (g);
		return -1;
	}
	t2 = g->data + 2;
	if ((t1 = strchr (g->data, 'p'))) {
		if (!(t2 = strchr (g->data, '.'))) {
			send_ack (g);
			return -1;
		} else {
			t1++;
			g->pid = (int) strtol (t1, NULL, 16);
			t2++;
		}
	}
	g->tid = (int) strtol (t2, NULL, 16);
	return send_ack (g);
}

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

int handle_fstat(libgdbr_t *g) {
	// no data just mean this is not supported by gdb
	if (!*g->data) {
        send_ack (g);
        return 0;
    }

    if (g->data[0] != 'F' || g->data[1] == '-') {
		send_ack (g);
		return -1;
	}
	int size = strtol (g->data + 1, NULL, 16);
	if (size < sizeof (libgdbr_fstat_t)) {
		send_ack (g);
		return -1;
	}
	char *ptr = strchr (g->data, ';');
	if (!ptr) {
		send_ack (g);
		return -1;
	}
/*
        libgdbr_fstat_t *fstat = (libgdbr_fstat_t*) (ptr + 1);
        g->exec_file_sz = 0;
        unsigned char *c = &fstat->size;
        for (int i = 0; i < 8; i++) {
                g->exec_file_sz <<= 4;
                g->exec_file_sz |= *c;
        }
 */
	return send_ack (g);
}

int handle_cont(libgdbr_t *g) {
	// Possible answers here 'S,T,W,X,O,F'
	return send_ack (g);
}

int handle_setbp(libgdbr_t *g) {
	return send_ack (g);
}

int handle_removebp(libgdbr_t *g) {
	return send_ack (g);
}
