/* libgdbr - LGPL - Copyright 2014 - defragger */

#include "packet.h"

char get_next_token(parsing_object_t* po) {
	return po->buffer[po->position++];
}

void handle_escape(parsing_object_t* po) {
	char token;
	if (po->position >= po->length) return;
	token = get_next_token (po);
	if (token == '}') handle_data (po);
	else handle_escape (po);
}

void handle_chk(parsing_object_t* po) {
	char checksum[3];
	if (po->position >= po->length) return;
	checksum[0] = get_next_token(po);
	checksum[1] = get_next_token(po);
	checksum[2] = '\0';
	po->checksum = (uint8_t) strtol(checksum, NULL, 16);
}

void handle_data(parsing_object_t* po) {
	char token;
	if (po->position >= po->length) return;
	token = get_next_token(po);
	if (token == '#') {
		po->end = po->position - 1; // subtract 2 cause of # itself and the incremented position after getNextToken
		handle_chk(po);
	} else if (token == '{') {
		handle_escape(po);
	} else handle_data(po);
}

void handle_packet(parsing_object_t* po) {
	char token;
	if(po->position >= po->length) return;
	token = get_next_token(po);
	if (token == '$') {
		po->start = po->position;
		handle_data(po);
	}
	else if	(token == '+') {
		po->acks++;
		handle_packet(po);
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

int parse_packet(libgdbr_t* g, int data_offset) {
	int runlength;
	uint64_t po_size, target_pos = 0;
	parsing_object_t new;
	memset (&new, 0, sizeof (parsing_object_t));
	new.length = g->read_len;
	new.buffer = g->read_buff;
	while (new.position < new.length) {
		handle_packet (&new);
		new.start += data_offset;
		po_size = new.end - new.start;
		runlength = unpack_data (g->data + target_pos,
			new.buffer + new.start, po_size);
		target_pos += po_size + runlength;
	}
	g->data_len = target_pos; // setting the resulting length
	g->read_len = 0; // reset the read_buf len
	return 0;
}

int send_packet(libgdbr_t* g) {
	if (!g) {
		// TODO corect error handling here
		printf("Initialize libgdbr_t first\n");
		return -1;
	}
	return send (g->fd, g->send_buff, g->send_len, 0);
}

int read_packet(libgdbr_t* g) {
	int ret = 0;
	int po_size = 0;
	fd_set readset;
	int result = 1;
	struct timeval tv;
	if (!g) {
		// TODO correct error handling here
		fprintf (stderr, "Initialize libgdbr_t first\n");
		return -1;
	}
	tv.tv_sec = 0;
	tv.tv_usec = 100*1000;
	while (result > 0) {
		FD_ZERO (&readset);
		FD_SET (g->fd, &readset);
		result = select (g->fd + 1, &readset, NULL, NULL, &tv);
		if (result > 0) {
			if (FD_ISSET (g->fd, &readset)) {
				ret = recv (g->fd, (g->read_buff + \
					po_size), (g->read_max - \
					po_size), 0);
				po_size += ret;
			}
		}
	}
	g->read_len = po_size;
	return po_size;
}
