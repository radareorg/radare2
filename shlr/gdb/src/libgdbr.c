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

bool gdbr_set_architecture(libgdbr_t *g, int arch, int bits) {
	if (!g) {
		return false;
	}
	if (g->target.valid && g->registers) {
		return true;
	}

	const char *regprofile = gdbr_get_reg_profile (arch, bits);
	if (!regprofile) {
		eprintf ("cannot find gdb reg_profile\n");
		return false;
	}
	if (!gdbr_set_reg_profile (g, regprofile)) {
		return false;
	}
	g->target.arch = arch;
	g->target.bits = bits;
	g->target.valid = true;

	return true;
}

const char *gdbr_get_reg_profile(int arch, int bits) {
	switch (arch) {
	case R_SYS_ARCH_X86:
		if (bits == 32) {
#include "reg/x86_32.h"
		} else if (bits == 64) {
#include "reg/x86_64.h"
		} else {
			eprintf ("%s: unsupported x86 bits: %d\n", __func__, bits);
			return NULL;
		}
		break;
	case R_SYS_ARCH_ARM:
		if (bits == 32) {
#include "reg/arm32.h"
		} else if (bits == 64) {
#include "reg/arm64.h"
		} else {
			eprintf ("%s: unsupported arm bits: %d\n", __func__, bits);
			return NULL;
		}
		break;
	case R_SYS_ARCH_SH:
#include "reg/sh.h"
		break;
	case R_SYS_ARCH_LM32:
#include "reg/lm32.h"
		break;
	case R_SYS_ARCH_RISCV:
#include "reg/riscv.h"
		break;
	case R_SYS_ARCH_MIPS:
#include "reg/mips.h"
		break;
	case R_SYS_ARCH_AVR:
#include "reg/avr.h"
		break;
	case R_SYS_ARCH_V850:
#include "reg/v850.h"
		break;
	}
	return NULL;
}

int gdbr_set_reg_profile(libgdbr_t *g, const char *str) {
	if (!g || !str) {
		return -1;
	}
	gdb_reg_t *registers = arch_parse_reg_profile (str);
	if (!registers) {
		eprintf ("cannot parse reg profile\n");
		return -1;
	}
	if (g->target.regprofile) {
		free (g->target.regprofile);
	}
	g->target.regprofile = strdup (str);
	if (g->registers) {
		free (g->registers);
	}
	g->registers = arch_parse_reg_profile (str);

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
