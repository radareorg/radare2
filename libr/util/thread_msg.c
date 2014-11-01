/* radare - LGPL - Copyright 2014 - pancake */

#include <r_th.h>

R_API RThreadMsg* r_th_msg_new (const char *cmd, void *cb) {
	RThreadMsg *msg = R_NEW0 (RThreadMsg);
	if (msg) {
		msg->text = strdup (cmd);
		//msg->cb = cb;
		msg->done = 0;
	}
	return msg;
}

R_API void r_th_msg_free (RThreadMsg* msg) {
	free (msg->text);
	free (msg->res);
	free (msg);
}

/*
R_API void r_th_msg_push (RThread *th, RThreadMsg* msg) {
	//r_list_push (th->messages, msg);
}

R_API RThreadMsg *r_th_msg_pop (RThread *th) {
	return NULL; //r_list_pop (th->messages);
}
*/
