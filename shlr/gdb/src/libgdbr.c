/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libgdbr.h"
#include "arch.h"

#include <stdio.h>

int gdbr_init(libgdbr_t *g, bool is_server) {
	if (!g) {
		return -1;
	}
	memset (g, 0, sizeof (libgdbr_t));
	g->no_ack = false;
	g->stub_features.extended_mode = -1;
	g->stub_features.pkt_sz = 64;
	g->stub_features.P = true;
	g->remote_file_fd = -1;
	g->is_server = is_server;
	g->send_max = 2500;
	g->send_buff = (char *) calloc (g->send_max, 1);
	g->page_size = 4096;
	g->num_retries = 40; // safe number, should be ~10 seconds
	if (!g->send_buff) {
		return -1;
	}
	g->send_len = 0;
	g->read_max = 4096;
	g->read_buff = (char *) calloc (g->read_max, 1);
	if (!g->read_buff) {
		R_FREE (g->send_buff);
		return -1;
	}
	g->sock = r_socket_new (0);
	g->gdbr_lock = r_th_lock_new (true);
	g->gdbr_lock_depth = 0;
	g->last_code = MSG_OK;
	g->connected = 0;
	g->data_len = 0;
	g->data_max = 4096;
	g->data = calloc (g->data_max, 1);
	if (!g->data) {
		R_FREE (g->send_buff);
		R_FREE (g->read_buff);
		return -1;
	}
	g->remote_type = GDB_REMOTE_TYPE_GDB;
	g->isbreaked = false;
	return 0;
}

int gdbr_set_architecture(libgdbr_t *g, const char *arch, int bits) {
	if (!g) {
		return -1;
	}
	if (g->target.valid && g->registers) {
		return 0;
	}
	if (!strcmp (arch, "mips")) {
		g->registers = gdb_regs_mips;
	} else if (!strcmp (arch, "lm32")) {
		g->registers = gdb_regs_lm32;
	} else if (!strcmp (arch, "avr")) {
		g->registers = gdb_regs_avr;
	} else if (!strcmp (arch, "v850")) {
		g->registers = gdb_regs_v850;
	} else if (!strcmp (arch, "x86")) {
		if (bits == 32) {
			g->registers = gdb_regs_x86_32;
		} else if (bits == 64) {
			g->registers = gdb_regs_x86_64;
		} else {
			eprintf ("%s: unsupported x86 bits: %d\n", __func__, bits);
			return -1;
		}
	} else if (!strcmp (arch, "arm")) {
		if (bits == 32) {
			g->registers = gdb_regs_arm32;
		} else if (bits == 64) {
			g->registers = gdb_regs_aarch64;
		} else {
			eprintf ("%s: unsupported arm bits: %d\n", __func__, bits);
			return -1;
		}
	}
	return 0;
}

int gdbr_cleanup(libgdbr_t *g) {
	if (!g) {
		return -1;
	}
	R_FREE (g->data);
	g->send_len = 0;
	R_FREE (g->send_buff);
	R_FREE (g->read_buff);
	r_socket_free (g->sock);
	r_th_lock_free (g->gdbr_lock);
	return 0;
}
