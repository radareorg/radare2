#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libdapr.h"


int dapr_init(libdapr_t *dap, bool is_server) {
	if (!dap) {
		return -1;
	}
	memset (dap, 0, sizeof (libdapr_t));
	/*dap->no_ack = false;
	dap->stub_features.extended_mode = -1;
	dap->stub_features.pkt_sz = 64;
	dap->stub_features.P = true;*/
	dap->remote_file_fd = -1;
	dap->is_server = is_server;
	dap->send_max = 2500;
	dap->send_buff = (char *) calloc (dap->send_max, 1);
	dap->page_size = 4096;
	dap->num_retries = 40; // safe number, should be ~10 seconds
	if (!dap->send_buff) {
		return -1;
	}
	dap->send_len = 0;
	dap->read_max = 4096;
	dap->read_buff = (char *) calloc (dap->read_max, 1);
	if (!dap->read_buff) {
		//R_FREE (dap->send_buff);
		return -1;
	}
	/*dap->sock = r_socket_new (0);
	dap->gdbr_lock = r_th_lock_new (true);
	dap->gdbr_lock_depth = 0;
	dap->last_code = MSG_OK;*/
	dap->connected = 0;
	dap->data_len = 0;
	dap->data_max = 4096;
	dap->data = calloc (dap->data_max, 1);
	if (!dap->data) {
		//R_FREE (dap->send_buff);
		//R_FREE (dap->read_buff);
		return -1;
	}
	//dap->remote_type = GDB_REMOTE_TYPE_GDB;
	//dap->isbreaked = false;
	return 0;
}

int dapr_connect (libdapr_t *g, const char *host, int port) {
	return -1;
}

int dapr_attach(libdapr_t *g, int pid) {
	return -1;
}
