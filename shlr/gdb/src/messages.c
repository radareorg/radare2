/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "messages.h"
#include "arch.h"
#include "core.h"
#include "utils.h"

int handle_g(libgdbr_t* g) {
	unpack_hex(g->data, g->data_len, g->data);
	g->data_len = g->data_len / 2;
	send_ack(g);
	return 0;
}

int handle_G(libgdbr_t* g) {
	send_ack (g);
	return 0;
}

int handle_m(libgdbr_t* g) {
	int len = strlen (g->data);
	g->data_len = strlen (g->data) / 2;
	unpack_hex (g->data, len, g->data);
	send_ack (g);
	return 0;
}

int handle_cmd(libgdbr_t* g) {
	unpack_hex (g->data, strlen (g->data), g->data);
	g->data_len = strlen (g->data) / 2;
	send_ack (g);
	return 0;
}

int handle_connect(libgdbr_t* g) {
	// TODO handle the message correct and set all infos
	// .... like packetsize, thread stuff and features.
	send_ack (g);
	return 0;
}

int handle_cont(libgdbr_t* g) {
	send_ack (g);
	return 0;
}

int handle_setbp(libgdbr_t* g) {
	send_ack (g);
	return 0;
}

int handle_unsetbp(libgdbr_t* g) {
	send_ack (g);
	return 0;
}

