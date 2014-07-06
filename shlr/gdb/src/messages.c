/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "messages.h"
#include "arch.h"
#include "core.h"
#include "utils.h"


int handle_g(libgdbr_t* g) {
	if (unpack_hex (g->data, g->data_len, g->data) < 0) {
		return -1;
	}
	g->data_len = g->data_len / 2;
	return send_ack (g);
}

int handle_G(libgdbr_t* g) {
	return send_ack (g);
}

int handle_M(libgdbr_t* g) {
	return send_ack (g);
}

int handle_P(libgdbr_t* g) {
	if (g->data_len == 0) {
		g->last_code = MSG_NOT_SUPPORTED;
	}
	else {
		g->last_code = MSG_OK;
	}
	return send_ack (g);
}

int handle_m(libgdbr_t* g) {
	int len = strlen (g->data);
	g->data_len = strlen (g->data) / 2;
	unpack_hex (g->data, len, g->data);
	return send_ack (g);
}

int handle_cmd(libgdbr_t* g) {
	unpack_hex (g->data, strlen (g->data), g->data);
	g->data_len = strlen (g->data) / 2;
	return send_ack (g);
}

int handle_connect(libgdbr_t* g) {
	// TODO handle the message correct and set all infos like packetsize, thread stuff and features
	return send_ack (g);
}

int handle_cont(libgdbr_t* g) {
	// Possible answers here 'S,T,W,X,O,F'
	return send_ack (g);
}

int handle_setbp(libgdbr_t* g) {
	return send_ack (g);
}

int handle_removebp(libgdbr_t* g) {
	return send_ack (g);
}

