#include "packet.h"


char get_next_token(parsing_object_t* current) {
	return current->buffer[current->position++];
}


void handle_escape(parsing_object_t* current) {
	if (current->position >= current->length) return;
	char token = get_next_token(current);
	if (token == '}') handle_data(current);
	else handle_escape(current);
}


void handle_chk(parsing_object_t* current) {
	if (current->position >= current->length) return;
	char checksum[3];
	checksum[0] = get_next_token(current);
	checksum[1] = get_next_token(current);
	checksum[2] = '\0';
	current->checksum = (uint8_t) strtol(checksum, NULL, 16);
}


void handle_data(parsing_object_t* current) {
	if (current->position >= current->length) return;
	char token = get_next_token(current);
	if (token == '#') {
		current->end = current->position - 1; // subtract 2 cause of # itself and the incremented position after getNextToken
		handle_chk(current);
	}
	else if	(token == '{') handle_escape(current);
	else handle_data(current);
}


void handle_packet(parsing_object_t* current) {
	if(current->position >= current->length) return;

	char token = get_next_token(current);
	if (token == '$') {
		current->start = current->position;
		handle_data(current);
	}
	else if	(token == '+') {
		current->acks++;
		handle_packet(current);
	}
}

/**
 * helper function that should unpack
 * run-length encoded streams of data
 */
int unpack_data(char* dst, char* src, uint64_t len) {
	int i = 0;
	char last;
	int ret_len = 0;
	char* p_dst = dst;
	while ( i < len) {
		if (src[i] == '*') {
			if (++i >= len ) printf("Error\n");
			char size = src[i++];
			uint8_t runlength = size - 29;
			ret_len += runlength - 2;
			while ( i < len && runlength-- > 0) {
				*(p_dst++) = last;
			}
			continue;
		}
		last = src[i++];
		*(p_dst++) = last;
	}
	return ret_len;
}


int parse_packet(libgdbr_t* instance, int data_offset) {
	parsing_object_t new;
	memset(&new, 0, sizeof(parsing_object_t));
	new.length = instance->read_len;
	new.buffer = instance->read_buff;
	uint64_t target_pos = 0;
	while(new.position < new.length) {
		handle_packet(&new);
		new.start += data_offset;
		uint64_t current_size = new.end - new.start;
		//if ( instance->data_max <= (instance->data_len + current_size)) {
		//	instance->data = realloc(instance->data, instance->data_len + current_size + 1);
		//	instance->data_len += current_size;
		//	instance->data_max += current_size;
		//}
		int runlength = unpack_data(instance->data + target_pos, new.buffer + new.start, current_size);
		//memcpy(instance->data + target_pos , new.buffer + new.start, current_size);
		target_pos += current_size + runlength;
	}
	instance->data_len = target_pos; // setting the resulting length
	instance->read_len = 0; // reset the read_buf len
	return 0;
}


int send_packet(libgdbr_t* instance) {
	if (!instance) {
		// TODO corect error handling here
		printf("Initialize libgdbr_t first\n");
		return -1;
	}
	int ret = send(instance->fd, instance->send_buff, instance->send_len, 0);
	return ret;
}


int read_packet(libgdbr_t* instance) {
	if (!instance) {
		// TODO correct error handling here
		printf("Initialize libgdbr_t first\n");
		return -1;
	}
	int ret = 0;
	int current_size = 0;
	fd_set readset;
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100*1000;
	int result = 1;
	while (result > 0) {
		FD_ZERO(&readset);
		FD_SET(instance->fd, &readset);
		result = select(instance->fd + 1, &readset, NULL, NULL, &tv);
		if (result > 0) {
			if (FD_ISSET(instance->fd, &readset)) {
				//if ( instance->read_len <= (current_size + instance->max_read_size)) {
				//	instance->read_buff = realloc(instance->read_buff, instance->read_len + instance->read_size);
				//	instance->read_max += instance->read_max;
				//}
				ret = recv(instance->fd, (instance->read_buff + current_size), (instance->read_max - current_size), 0);
				current_size += ret;
			}
		}
	}
	instance->read_len = current_size;
	return current_size;
}
