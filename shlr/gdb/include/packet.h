/*! \file */
#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "libgdbr.h"
#include <stdio.h>
#if __WINDOWS__
#include <windows.h>
#if !__CYGWIN__
#include <winsock.h>
#endif
#endif

typedef struct parsing_object_t {
	char* buffer;
	ssize_t length;
	int start;
	int end;
	int position;
	uint8_t checksum;
	int acks;
} parsing_object_t;

int parse_packet(libgdbr_t* instance, int data_offset);
/*!
 * \brief sends a packet sends a packet to the established connection
 * \param instance the "instance" of the current libgdbr session
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int send_packet(libgdbr_t* instance);

/*!
 * \brief Function reads data from the established connection
 * \param instance the "instance" of the current libgdbr session
 * \returns a failure code (currently -1) or 0 if call successfully
 */
int read_packet(libgdbr_t* instance);
void handle_data(parsing_object_t* current);
void handle_chk(parsing_object_t* current);
void handle_packet(parsing_object_t* current);
void handle_escape(parsing_object_t* current);
char get_next_token(parsing_object_t* current);

#endif
