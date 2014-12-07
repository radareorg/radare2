// Copyright (c) 2014, The Lemon Man, All rights reserved.

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport.h"
#include "kd.h"

uint32_t kd_data_checksum (const uint8_t *buf, const uint64_t buf_len) {
	uint32_t i, acc;

	if (!buf || !buf_len)
		return 0;

	for (i = acc = 0; i < buf_len; i++)
		acc += buf[i];

	return acc;
}

int kd_send_ctrl_packet (void *fp, const uint32_t type, const uint32_t id) {
	kd_packet_t pkt;

	pkt.leader = KD_PACKET_CTRL;
	pkt.length = 0;
	pkt.checksum = 0;
	pkt.id = id;
	pkt.type = type;

	if (iob_write(fp, (uint8_t *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	return KD_E_OK;
}

int kd_send_data_packet (void *fp, const uint32_t type, const uint32_t id, const uint8_t *req, 
		const int req_len, const uint8_t *buf, const uint32_t buf_len) {
	kd_packet_t pkt;

	if (req_len + buf_len > KD_MAX_PAYLOAD)
		return KD_E_MALFORMED;

	pkt.leader = KD_PACKET_DATA;
	pkt.length = req_len + buf_len;
	pkt.checksum = kd_data_checksum(req, req_len) +
			kd_data_checksum(buf, buf_len);
	pkt.id = id;
	pkt.type = type;

	if (iob_write(fp, (uint8_t *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	if (iob_write(fp, (uint8_t *)req, req_len) < 0)
		return KD_E_IOERR;

	if (buf && iob_write(fp, (uint8_t *)buf, buf_len) < 0)
		return KD_E_IOERR;

	if (iob_write(fp, (uint8_t *)"\xAA", 1) < 0)
		return KD_E_IOERR;

	return KD_E_OK;
}

int kd_read_packet (void *fp, kd_packet_t **p) {
	kd_packet_t pkt;
	uint8_t *buf;

	*p = NULL;

	if (iob_read(fp, (uint8_t *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	if (!kd_packet_is_valid(&pkt)) {
		printf("invalid leader %08x\n", pkt.leader);
		return KD_E_MALFORMED;
	}

	buf = malloc(sizeof(kd_packet_t) + pkt.length);
	memcpy(buf, &pkt, sizeof(kd_packet_t));

	if (pkt.length)
		iob_read(fp, (uint8_t *)buf + sizeof(kd_packet_t), pkt.length);

	if (pkt.checksum != kd_data_checksum(buf + sizeof(kd_packet_t), pkt.length)) {
		printf("Checksum mismatch!\n");
		free(buf);
		return KD_E_MALFORMED;
	}

	if (pkt.leader == KD_PACKET_DATA) {
		uint8_t trailer;
		iob_read(fp, (uint8_t *)&trailer, 1);

		if (trailer != 0xAA) {
			printf("Missing trailer 0xAA\n");
			free(buf);
			return KD_E_MALFORMED;
		}

		kd_send_ctrl_packet(fp, KD_PACKET_TYPE_ACK, ((kd_packet_t *)buf)->id & ~(0x800));
	}

	*p = (kd_packet_t *)buf;

	return KD_E_OK;
}

int kd_packet_is_valid (const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL || p->leader == KD_PACKET_DATA;
}

int kd_packet_is_ack (const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL && p->type == KD_PACKET_TYPE_ACK;
}
