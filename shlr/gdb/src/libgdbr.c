/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "libgdbr.h"
#include "arch.h"

#include <stdio.h>

int gdbr_init(libgdbr_t *g) {
	if (!g) {
		return -1;
	}
	memset (g, 0, sizeof (libgdbr_t));
	g->send_max = 2500;
	g->send_buff = (char *) calloc (g->send_max, 1);
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
	return 0;
}

int gdbr_set_architecture(libgdbr_t *g, uint8_t architecture) {
	if (!g) {
		return -1;
	}
	g->architecture = architecture;
	switch (architecture) {
	case ARCH_X86_32:
		g->registers = x86_32;
		break;
	case ARCH_X86_64:
		g->registers = x86_64;
		break;
	case ARCH_ARM_32:
		g->registers = arm32;
		break;
	case ARCH_ARM_64:
		g->registers = aarch64;
		break;
	case ARCH_MIPS:
		g->registers = mips;
		break;
	case ARCH_AVR:
		g->registers = avr;
		break;
	case ARCH_LM32:
		g->registers = lm32;
		break;
	default:
		eprintf ("Error unknown architecture set\n");
	}
	return 0;
}

int gdbr_cleanup(libgdbr_t *g) {
	if (!g) {
		return -1;
	}
	free (g->data);
	free (g->send_buff);
	g->send_len = 0;
	free (g->read_buff);
	free (g->exec_file_name);
	return 0;
}
