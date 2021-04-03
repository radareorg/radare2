// Copyright (c) 2014-2020, abcSup, All rights reserved. LGPLv3
#include <errno.h>

#include <r_crypto.h>
#include <r_hash.h>
#include <r_socket.h>
#include <r_util.h>

#include "kd.h"
#include "transport.h"

typedef struct iobnet_t {
	RSocket *sock;
	bool hasDatakey;

	// Internal buffer
	ut8 buf[4096];
	int off;
	int size;

	// AES-256 Control Key for enc/decrypting KDNet packets of type KDNET_PACKET_TYPE_CONTROL
	ut8 key[32];
	// AES-256 Data Key for enc/decrypting KDNet packets of type KDNET_PACKET_TYPE_DATA
	ut8 datakey[32];
	// HMAC Key
	ut8 hmackey[KDNET_HMACKEY_SIZE];
	// KDNet Protocol version of the debuggee
	ut8 version;
} iobnet_t;

// Constants to convert ASCII to its base36 value
static const char d32[] = "[\\]^_`abcd$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$efghijklmnopqrstuvwxyz{|}~";
// The powers of 36 up to the 13th for 64-bit values
static const ut64 pow36[] = { 1, 36, 1296, 46656, 1679616, 60466176, 2176782336,
	78364164096, 2821109907456, 101559956668416, 3656158440062976,
	131621703842267136, 4738381338321616896 };

static ut64 base36_decode(const char *str) {
	ut64 ret = 0;
	size_t i;
	size_t len = strlen (str);
	// 64-bit base36 str has at most 13 characters
	if (len > 13) {
		eprintf ("Error: base36_decode supports up to 64-bit values only\n");
		return 0;
	}
	for (i = 0; i < len; i++) {
		char c = str[len - i - 1];
		// "01234567890abcdefghijklmnopqrstuvwxyz"
		if (c < '0' || c > 'z' || ('9' < c && c < 'a')) {
			eprintf ("Error: %s is not a valid base36 encoded string\n", str);
			return 0;
		}
		ut8 v = d32[c - '0'];
		// Character does not exist in base36 encoding
		if (v == '$') {
			eprintf ("Error: %s is not a valid base36 encoded string\n", str);
			return 0;
		}
		v -= 91;
		// Check for overflow
		if (i == 12) {
			if (v > 3 || UT64_ADD_OVFCHK (ret, v * pow36[i])) {
				printf ("Error: base36_decode supports up to 64-bit values only\n");
				return 0;
			}
		}
		ret += v * pow36[i];
	}
	return ret;
}

/*
 * @brief Initialize the key for enc/decrypting KDNet packet with the type Data.
 *
 * @param resbuf, the buffer that contains the KDNet Data of a Response packet.
 */
static bool _initializeDatakey(iobnet_t *obj, ut8 *resbuf, int size) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	if (!ctx) {
		return false;
	}
	// Data Key = SHA256 (Key || resbuf)
	r_hash_do_begin (ctx, R_HASH_SHA256);
	r_hash_do_sha256 (ctx, obj->key, R_HASH_SIZE_SHA256);
	r_hash_do_sha256 (ctx, resbuf, size);
	r_hash_do_end (ctx, R_HASH_SHA256);
	memcpy (obj->datakey, ctx->digest, R_HASH_SIZE_SHA256);

	r_hash_free (ctx);
	return true;
}

static void *iob_net_open(const char *path) {
	size_t i;

	iobnet_t *obj = R_NEW0 (iobnet_t);
	if (!obj) {
		return NULL;
	}

	char *host = strdup (path);
	char *port = strchr (host, ':');
	if (R_STR_ISEMPTY (port)) {
		free (host);
		free (obj);
		return NULL;
	}
	*port++ = 0;
	char *key = strchr (port, ':');
	if (R_STR_ISEMPTY (key)) {
		free (host);
		free (obj);
		return NULL;
	}
	*key++ = 0;

	// Decode AES-256 Control Key (x.x.x.x) from base36
	char *nkey;
	for (i = 0; i < 4 && key; key = nkey, i++) {
		nkey = strchr (key, '.');
		if (nkey) {
			*nkey++ = 0;
		}
		r_write_le64 (obj->key + i * 8, base36_decode (key));
	}

	// HMAC Key is the negation of AES-256 Control Key bytes
	for (i = 0; i < 32; i++) {
		obj->hmackey[i] = ~(obj->key[i]);
	}

	RSocket *sock = r_socket_new (0);
	if (!r_socket_connect_udp (sock, host, port, 1)) {
		free (host);
		free (obj);
		r_socket_free (sock);
		return NULL;
	}
	obj->sock = sock;

	free (host);
	return (void *)obj;
}

static bool iob_net_close(void *p) {
	int ret = true;
	iobnet_t *obj = (iobnet_t *)p;

	if (r_socket_close (obj->sock)) {
		ret = false;
	}

	r_socket_free (obj->sock);
	free (obj);
	return ret;
}

static bool _encrypt(iobnet_t *obj, ut8 *buf, int size, int type) {
	bool ret = false;
	RCrypto *cry = r_crypto_new ();
	if (!cry) {
		return false;
	}
	if (!r_crypto_use (cry, "aes-cbc")) {
		goto end;
	}

	// Set AES-256 Key based on the KDNet packet type
	switch (type) {
	case KDNET_PACKET_TYPE_DATA:
		if (!r_crypto_set_key (cry, obj->datakey, sizeof (obj->datakey), 0, 0)) {
			goto end;
		}
		break;
	case KDNET_PACKET_TYPE_CONTROL: // Control Channel
		if (!r_crypto_set_key (cry, obj->key, sizeof (obj->key), 0, 0)) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	// Set IV to the 16 bytes HMAC at the end of KDNet packet
	if (!r_crypto_set_iv (cry, buf + size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE)) {
		goto end;
	}

	// Encrypt the buffer except HMAC
	if (r_crypto_final (cry, buf, size - KDNET_HMAC_SIZE) == 0) {
		goto end;
	}
	// Overwrite the buffer with encrypted data
	int sz;
	ut8 *encbuf = r_crypto_get_output (cry, &sz);
	if (!encbuf) {
		goto end;
	}
	memcpy (buf, encbuf, size - KDNET_HMAC_SIZE);

	free (encbuf);
	ret = true;
end:
	r_crypto_free (cry);
	return ret;
}

/*
 * KDNet packet format:
 * - KDNet Header, struct kdnet_packet_t
 * - KDNet Data, 8 bytes (seqno (7 bytes) | direction (4 bits) | padsize (4 bits))
 * - KD packet (16-byte aligned)
 * - KDNet HMAC, HMAC generated with the decrypted KDNet Data and KD Packet.
 *
 * The KDNet Data and KD packet are encrypted together with key based on
 * the packet type in KDNet Header.
 */
static ut8 *_createKDNetPacket(iobnet_t *obj, const ut8 *buf, int size, int *osize, ut64 seqno, ut8 type) {
	// Calculate the pad size for KD packet.
	// The KD packet is 16-byte aligned in KDNet.
	ut8 padsize = -(size + 8) & 0x0F;

	int encsize = sizeof (kdnet_packet_t) + KDNET_DATA_SIZE + size + padsize + KDNET_HMAC_SIZE;
	ut8 *encbuf = calloc (1, encsize);
	if (!encbuf) {
		return NULL;
	}

	// Write KDNet Header
	r_write_at_be32 (encbuf, KDNET_MAGIC, 0); // Magic
	r_write_at_be8 (encbuf, obj->version, 4); // Protocol Number
	r_write_at_be8 (encbuf, type, 5); // Channel Type
	// Write KDNet Data (8 bytes)
	// seqno (7 bytes) | direction (4 bits) | padsize (4 bits)
	// seqno - sequence number
	// direction - 0x0 Debuggee -> Debugger, 0x8 Debugger -> Debuggee
	r_write_at_be64 (encbuf, ((seqno << 8) | 0x8 << 4 | padsize), 6);

	// Copy KD Packet from buffer
	memcpy (encbuf + sizeof (kdnet_packet_t) + KDNET_DATA_SIZE, buf, size);

	// Generate HMAC from KDNet Data to KD packet
	int off = sizeof (kdnet_packet_t) + KDNET_DATA_SIZE + size + padsize;
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	if (!ctx) {
		free (encbuf);
		return NULL;
	}
	r_hash_do_hmac_sha256 (ctx, encbuf, off, obj->hmackey, KDNET_HMACKEY_SIZE);
	// Append KDNet HMAC at the end of encbuf
	memcpy (encbuf + off, ctx->digest, KDNET_HMAC_SIZE);
	r_hash_free (ctx);

	// Encrypt the KDNet Data, KD Packet and padding
	if (!_encrypt (obj, encbuf + sizeof (kdnet_packet_t), encsize - sizeof (kdnet_packet_t), type)) {
		free (encbuf);
		return NULL;
	}

	if (osize) {
		*osize = encsize;
	}
	return encbuf;
}

static bool _decrypt(iobnet_t *obj, ut8 *buf, int size, int type) {
	bool ret = false;
	RCrypto *cry = r_crypto_new ();
	if (!cry) {
		return false;
	}
	if (!r_crypto_use (cry, "aes-cbc")) {
		goto end;
	}

	// Set AES-256 Key based on the KDNet packet type
	switch (type) {
	case KDNET_PACKET_TYPE_DATA:
		if (!r_crypto_set_key (cry, obj->datakey, sizeof (obj->datakey), 0, 1)) {
			goto end;
		}
		break;
	case KDNET_PACKET_TYPE_CONTROL:
		if (!r_crypto_set_key (cry, obj->key, sizeof (obj->key), 0, 1)) {
			goto end;
		}
		break;
	default:
		goto end;
	}

	// Set IV to the 16 bytes HMAC at the end of KDNet packet
	if (!r_crypto_set_iv (cry, buf + size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE)) {
		goto end;
	}

	// Decrypt the buffer except HMAC
	if (r_crypto_final (cry, buf, size - KDNET_HMAC_SIZE) == 0) {
		goto end;
	}
	// Overwrite it with decrypted data
	int sz;
	ut8 *decbuf = r_crypto_get_output (cry, &sz);
	if (!decbuf) {
		goto end;
	}
	memcpy (buf, decbuf, size - KDNET_HMAC_SIZE);
	ret = true;

	free (decbuf);
end:
	r_crypto_free (cry);
	return ret;
}

/*
 * @brief Respond to the Poke packet with a Response packet
 *
 * @param pokedata, the buffer than contains the KDNet Data of a Poke packet
 */
static bool _sendResponsePacket(iobnet_t *obj, const ut8 *pokedata) {
	size_t i;
	int size;

	// Create the following buffer as the KD packet in the KDNet Response packet:
	// 0x01
	// 0x02
	// 32 bytes of Client Key from the first 32 bytes data of the Poke packet,
	// 32 bytes of Randomly generated Host Key,
	// 256 bytes of zeroes
	ut8 *resbuf = calloc (1, 322);
	if (!resbuf) {
		return false;
	}
	// 0x01 0x02
	resbuf[0] = 0x01;
	resbuf[1] = 0x02;
	// Copy 32 bytes Client Key after the KDNet Data
	memcpy (resbuf + 2, pokedata + 10, 32);
	// Generate 32 bytes random Host Key
	for (i = 0; i < 32; i++) {
		int rand = r_num_rand (0xFF);
		resbuf[i + 34] = rand & 0xFF;
	}

	// Set seqno to the same seqno in Poke packet
	ut64 seqno = r_read_be64 (pokedata) >> 8;
	ut8 *pkt = _createKDNetPacket (obj, resbuf, 322, &size, seqno, 1);
	if (!pkt) {
		R_FREE (resbuf);
	}

	if (r_socket_write (obj->sock, (void *)pkt, size) < 0) {
		free (pkt);
		free (resbuf);
		return false;
	}

	_initializeDatakey (obj, resbuf, 322);
	obj->hasDatakey = true;

	free (pkt);
	free (resbuf);
	return true;
}

static bool _processControlPacket(iobnet_t *obj, const ut8 *ctrlbuf, int size) {
	if (obj->hasDatakey) {
		return true;
	}
	// Read KDNet Data to verify direction flag
	ut64 kdnetdata = r_read_be64 (ctrlbuf);
	if ((kdnetdata & 0x80) != 0) {
		eprintf ("Error: KdNet wrong direction flag\n");
		return false;
	}

	// Respond to the control packet
	if (!_sendResponsePacket (obj, ctrlbuf)) {
		eprintf ("Error: KdNet sending the response packet\n");
		return false;
	}

	return true;
}

bool _verifyhmac(iobnet_t *obj) {
	RHash *ctx = r_hash_new (true, R_HASH_SHA256);
	if (!ctx) {
		return false;
	}
	r_hash_do_hmac_sha256 (ctx, obj->buf, obj->size - KDNET_HMAC_SIZE, obj->hmackey, KDNET_HMACKEY_SIZE);
	int ret = memcmp (ctx->digest, obj->buf + obj->size - KDNET_HMAC_SIZE, KDNET_HMAC_SIZE);

	r_hash_free (ctx);
	return ret == 0;
}

static int iob_net_read(void *p, uint8_t *obuf, const uint64_t count, const int timeout) {
	kdnet_packet_t pkt = { 0 };
	iobnet_t *obj = (iobnet_t *)p;

	if (obj->size == 0) {
		do {
			obj->size = r_socket_read (obj->sock, obj->buf, 4096);
			if (obj->size < 0) {
				// Continue if RCons breaks
				if (errno == EINTR) {
					continue;
				}
				obj->size = 0;
				return -1;
			}
			memcpy (&pkt, obj->buf, sizeof (kdnet_packet_t));

			// Verify the KDNet Header magic
			if (r_read_be32 (obj->buf) != KDNET_MAGIC) {
				eprintf ("Error: KdNet bad magic\n");
				obj->size = 0;
				return -1;
			}

			// Decrypt the KDNet Data and KD Packet
			if (!_decrypt (obj, obj->buf + sizeof (kdnet_packet_t), obj->size - sizeof (kdnet_packet_t), pkt.type)) {
				obj->size = 0;
				return -1;
			}

			// Verify the KDNet HMAC
			if (!_verifyhmac (obj)) {
				eprintf ("Error: KdNet failed authentication\n");
				obj->size = 0;
				return -1;
			}

			// Process KDNet Control Packets
			if (pkt.type == KDNET_PACKET_TYPE_CONTROL) {
				obj->version = pkt.version;
				if (!_processControlPacket (obj, obj->buf + sizeof (kdnet_packet_t), obj->size)) {
					eprintf ("Error: KdNet failed to process Control packet\n");
					obj->size = 0;
					return -1;
				};
				obj->size = 0;
			}
		} while (pkt.type == KDNET_PACKET_TYPE_CONTROL);

		// Remove padding from the buffer
		ut8 padsize = r_read_at_be64 (obj->buf, sizeof (kdnet_packet_t)) & 0xF;
		obj->size -= KDNET_HMAC_SIZE + padsize;

		// Seek to KD packet
		obj->off = sizeof (kdnet_packet_t) + KDNET_DATA_SIZE;

		// KD_PACKET_TYPE_UNUSED KD packet does not have a checksum,
		// but kd_read_packet always read for the 4-byte checksum
		if (r_read_at_be16 (obj->buf, obj->off + 4) == KD_PACKET_TYPE_UNUSED) {
			obj->size += 4;
		}
	}

	if (count + obj->off > obj->size) {
		eprintf ("Error: KdNet out-of-bounds read\n");
		obj->size = 0;
		return -1;
	}

	// Copy remaining data in buffer
	memcpy (obuf, obj->buf + obj->off, count);
	obj->off += count;

	// Reset the internal buffer when finished
	if (obj->off == obj->size) {
		obj->size = 0;
	}

	return count;
}

static int iob_net_write(void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	static ut64 seqno = 1;
	iobnet_t *obj = (iobnet_t *)p;

	if (obj->size == 0) {
		// kd_packet_t
		if (count == sizeof (kd_packet_t)) {
			kd_packet_t pkt;
			memcpy (&pkt, buf, sizeof (kd_packet_t));

			obj->size = sizeof (kd_packet_t) + pkt.length;
			obj->off = count;
			memcpy (obj->buf, buf, count);
		} else { // breakin packet "b"
			memcpy (obj->buf, buf, count);
			obj->size = count;
			obj->off = count;
		}
	} else {
		memcpy (obj->buf + obj->off, buf, count);
		obj->off += count;
	}

	if (obj->off == obj->size) {
		int size;
		ut8 *pkt = _createKDNetPacket (obj, obj->buf, obj->size, &size, seqno, 0);
		if (!pkt) {
			return -1;
		}
		if (r_socket_write (obj->sock, (void *)pkt, size) < 0) {
			free (pkt);
			return -1;
		}
		seqno++;

		obj->size = 0;
		free (pkt);
	}

	return count;
}

io_backend_t iob_net = {
	.name = "kdnet",
	.type = KD_IO_NET,
	.init = NULL,
	.deinit = NULL,
	.config = NULL,
	.open = &iob_net_open,
	.close = &iob_net_close,
	.read = &iob_net_read,
	.write = &iob_net_write,
};
