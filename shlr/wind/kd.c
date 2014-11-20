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

#include "transport.h"
#include "kd.h"

ut32 kd_data_checksum (const ut8 *buf, const ut64 buf_len) {
	ut32 i, acc;

	if (!buf || !buf_len)
		return 0;

	for (i = acc = 0; i < buf_len; i++)
		acc += buf[i];

	return acc;
}

int kd_send_ctrl_packet (void *fp, const ut32 type, const ut32 id) {
	kd_packet_t pkt;

	pkt.leader = KD_PACKET_CTRL;
	pkt.lenght = 0;
	pkt.checksum = 0;
	pkt.id = id;
	pkt.type = type;

	if (iob_write(fp, (ut8 *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	return KD_E_OK;
}

int kd_send_data_packet (void *fp, const ut32 type, const ut32 id, const ut8 *req, 
		const int req_len, const ut8 *buf, const ut32 buf_len) {
	kd_packet_t pkt;

	if (req_len + buf_len > KD_MAX_PAYLOAD)
		return KD_E_MALFORMED;

	pkt.leader = KD_PACKET_DATA;
	pkt.lenght = req_len + buf_len;
	pkt.checksum = kd_data_checksum(req, req_len) +
			kd_data_checksum(buf, buf_len);
	pkt.id = id;
	pkt.type = type;

	if (iob_write(fp, (ut8 *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	if (iob_write(fp, (ut8 *)req, req_len) < 0)
		return KD_E_IOERR;

	if (buf && iob_write(fp, (ut8 *)buf, buf_len) < 0)
		return KD_E_IOERR;

	if (iob_write(fp, (ut8 *)"\xAA", 1) < 0)
		return KD_E_IOERR;

	return KD_E_OK;
}

int kd_read_packet (void *fp, kd_packet_t **p) {
	kd_packet_t pkt;
	ut8 *buf;

	*p = NULL;

	if (iob_read(fp, (ut8 *)&pkt, sizeof(kd_packet_t)) < 0)
		return KD_E_IOERR;

	if (!kd_packet_is_valid(&pkt)) {
		printf("invalid leader %08x\n", pkt.leader);
		return KD_E_MALFORMED;
	}

	buf = malloc(sizeof(kd_packet_t) + pkt.lenght);
	memcpy(buf, &pkt, sizeof(kd_packet_t));

	if (pkt.lenght)
		iob_read(fp, (ut8 *)buf + sizeof(kd_packet_t), pkt.lenght);

	if (pkt.checksum != kd_data_checksum(buf + sizeof(kd_packet_t), pkt.lenght)) {
		printf("Checksum mismatch!\n");
		free(buf);
		return KD_E_MALFORMED;
	}

	if (pkt.leader == KD_PACKET_DATA) {
		ut8 trailer;
		iob_read(fp, (ut8 *)&trailer, 1);

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
