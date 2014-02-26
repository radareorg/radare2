#include "messages.h"
#include "arch.h"
#include "core.h"
#include "utils.h"


int handle_g(libgdbr_t* instance) {
	unpack_hex(instance->data, instance->data_len, instance->data);
	instance->data_len = instance->data_len / 2;
	send_ack(instance);
	return 0;
}


int handle_G(libgdbr_t* instance) {
	send_ack(instance);
	return 0;
}


int handle_m(libgdbr_t* instance) {
	int len = strlen(instance->data);
	instance->data_len = strlen(instance->data) / 2;
	unpack_hex(instance->data, len, instance->data);
	send_ack(instance);
	return 0;
}


int handle_cmd(libgdbr_t* instance) {
	unpack_hex(instance->data, strlen(instance->data), instance->data);
	instance->data_len = strlen(instance->data) / 2;
	send_ack(instance);
	return 0;
}


int handle_connect(libgdbr_t* instance) {
	// TODO handle the message correct and set all infos like packetsize, thread stuff and features
	send_ack(instance);
	return 0;
}


int handle_cont(libgdbr_t* instance) {
	send_ack(instance);
	return 0;
}


int handle_setbp(libgdbr_t* instance) {
	send_ack(instance);
	return 0;
}


int handle_unsetbp(libgdbr_t* instance) {
	send_ack(instance);
	return 0;
}

