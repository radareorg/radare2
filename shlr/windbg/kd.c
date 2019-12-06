// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport.h"
#include "kd.h"

#define KD_DBG if (false)

uint32_t kd_data_checksum(const uint8_t *buf, const uint64_t buf_len) {
	uint32_t i, acc;

	if (!buf || !buf_len) {
		return 0;
	}

	for (i = acc = 0; i < buf_len; i++) {
		acc += buf[i];
	}

	return acc;
}

int kd_send_ctrl_packet(void *fp, const uint32_t type, const uint32_t id) {
	kd_packet_t pkt;

	pkt.leader = KD_PACKET_CTRL;
	pkt.length = 0;
	pkt.checksum = 0;
	pkt.id = id;
	pkt.type = type;

	if (iob_write (fp, (uint8_t *) &pkt, sizeof(kd_packet_t)) < 0) {
		return KD_E_IOERR;
	}

	return KD_E_OK;
}

int kd_send_data_packet(void *fp, const uint32_t type, const uint32_t id, const uint8_t *req,
			const int req_len, const uint8_t *buf, const uint32_t buf_len) {
	kd_packet_t pkt;

	if (req_len + buf_len > KD_MAX_PAYLOAD) {
		return KD_E_MALFORMED;
	}

	//kd_req_t *r = (kd_req_t*) req;
	//eprintf ("==== Send ====\n%08x\n", r->req);

	pkt.leader = KD_PACKET_DATA;
	pkt.length = req_len + buf_len;
	pkt.checksum = kd_data_checksum (req, req_len) +
		       kd_data_checksum (buf, buf_len);
	pkt.id = id;
	pkt.type = type;

	if (iob_write (fp, (uint8_t *) &pkt, sizeof(kd_packet_t)) < 0) {
		return KD_E_IOERR;
	}

	if (iob_write (fp, (uint8_t *) req, req_len) < 0) {
		return KD_E_IOERR;
	}

	if (buf && iob_write (fp, (uint8_t *) buf, buf_len) < 0) {
		return KD_E_IOERR;
	}

	if (iob_write (fp, (uint8_t *) "\xAA", 1) < 0) {
		return KD_E_IOERR;
	}

	return KD_E_OK;
}

int kd_read_packet(void *fp, kd_packet_t **p) {
	kd_packet_t pkt;
	uint8_t *buf;

	*p = NULL;

	if (iob_read (fp, (uint8_t *) &pkt, sizeof (kd_packet_t)) <= 0) {
		return KD_E_IOERR;
	}

	if (!kd_packet_is_valid (&pkt)) {
		KD_DBG eprintf ("invalid leader %08x, trying to recover\n", pkt.leader);
		while (!kd_packet_is_valid (&pkt)) {
			kd_send_ctrl_packet (fp, KD_PACKET_TYPE_RESEND, 0);
			char sig[4];
			// Read byte-by-byte searching for the start of a packet
			int ret;
			while ((ret = iob_read (fp, (uint8_t *)&sig, 1)) > 0) {
				if (sig[0] == '0' || sig[0] == 'i') {
					if (iob_read (fp, (uint8_t *)&sig + 1, 3) == 3) {
						if (strncmp (sig, "000", 3) && strncmp (sig, "iii", 3)) {
							continue;
						}
						memcpy (&pkt, sig, sizeof (sig));
						if (iob_read (fp, (uint8_t *)&pkt + 4, sizeof (kd_packet_t) - 4) <= 0) {
							return KD_E_IOERR;
						}
						break;
					} else {
						return KD_E_IOERR;
					}
				}
			}
			if (!ret) {
				return KD_E_IOERR;
			}
		}
	}

	buf = malloc (sizeof (kd_packet_t) + pkt.length);
	if (!buf) {
		return KD_E_IOERR;
	}
	memcpy (buf, &pkt, sizeof(kd_packet_t));

	if (pkt.length) {
		iob_read (fp, (uint8_t *) buf + sizeof(kd_packet_t), pkt.length);
	}

	if (pkt.checksum != kd_data_checksum (buf + sizeof(kd_packet_t), pkt.length)) {
		KD_DBG eprintf ("Checksum mismatch!\n");
		free (buf);
		return KD_E_MALFORMED;
	}

	if (pkt.leader == KD_PACKET_DATA) {
		uint8_t trailer;
		iob_read (fp, (uint8_t *) &trailer, 1);

		if (trailer != 0xAA) {
			KD_DBG eprintf ("Missing trailer 0xAA\n");
			free (buf);
			return KD_E_MALFORMED;
		}

		kd_send_ctrl_packet (fp, KD_PACKET_TYPE_ACKNOWLEDGE, ((kd_packet_t *) buf)->id & ~(0x800));
	}

	*p = (kd_packet_t *) buf;

	return KD_E_OK;
}

int kd_packet_is_valid(const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL || p->leader == KD_PACKET_DATA;
}

int kd_packet_is_ack(const kd_packet_t *p) {
	return p->leader == KD_PACKET_CTRL && p->type == KD_PACKET_TYPE_ACKNOWLEDGE;
}
