/* libgdbr - LGPL - Copyright 2014-2016 - defragger */

#include "packet.h"
#include "utils.h"

#define READ_TIMEOUT (250 * 1000)

enum {
	HEADER	= 1 << 0,
	CHKSUM	= 1 << 1,
	DUP	= 1 << 2,
	ESC	= 1 << 3,
};

struct parse_ctx {
	unsigned long flags;
	unsigned char last;
	unsigned char sum;
	int chksum_nibble;
};

static bool append(libgdbr_t *g, const char ch) {
	char *ptr;

	if (g->data_len == g->data_max) {
		int newsize = g->data_max * 2;
		if (newsize < 1) {
			return false;
		}
		ptr = realloc (g->data, newsize);
		if (!ptr) {
			eprintf ("%s: Failed to reallocate buffer\n",
				 __func__);
			return false;
		}
		g->data = ptr;
		g->data_max = newsize;
	}

	g->data[g->data_len++] = ch;
	return true;
}

static int unpack(libgdbr_t *g, struct parse_ctx *ctx, int len) {
	int i = 0;
	int j = 0;

	for (i = 0; i < len; i++) {
		char cur = g->read_buff[i];

		if (ctx->flags & CHKSUM) {
			ctx->sum -= hex2int (cur) << (ctx->chksum_nibble * 4);

			if (!--ctx->chksum_nibble) {
				continue;
			}

			if (i != len - 1) {
				eprintf ("%s: Packet too long\n", __func__);
				return -1;
			}

			if (ctx->sum != '#') {
				eprintf ("%s: Invalid checksum\n", __func__);
				return -1;
			}

			return 0;
		}

		ctx->sum += cur;

		if (ctx->flags & ESC) {
			if (!append (g, cur ^ 0x20)) {
				return -1;
			}

			ctx->flags &= ~ESC;
			continue;
		}

		if (ctx->flags & DUP) {
			if (cur < 32 || cur > 126) {
				eprintf ("%s: Invalid repeat count\n",
					 __func__);
				return -1;
			}

			for (j = cur - 29; j > 0; j--) {
				if (!append (g, ctx->last)) {
					return -1;
				}
			}

			ctx->last = 0;
			ctx->flags &= ~DUP;
			continue;
		}

		switch (cur) {
		case '$':
			if (ctx->flags & HEADER) {
				eprintf ("%s: More than one $\n", __func__);
				return -1;
			}

			ctx->flags |= HEADER;
			/* Disregard any characters preceding $ */
			ctx->sum = 0;
			break;

		case '#':
			ctx->flags |= CHKSUM;
			ctx->chksum_nibble = 1;
			break;

		case '}':
			ctx->flags |= ESC;
			break;

		case '*':
			if (!ctx->last) {
				eprintf ("%s: Invalid repeat\n", __func__);
				return -1;
			}

			ctx->flags |= DUP;
			break;

		case '+':
		case '-':
			if (!(ctx->flags & HEADER)) {
				/* TODO: Handle acks/nacks */
				break;
			}
			/* Fall-through */
		default:
			if (!append (g, cur)) {
				return -1;
			}
			ctx->last = cur;
		}
	}

	return 1;
}

int read_packet(libgdbr_t *g) {
	struct parse_ctx ctx = { 0 };
	int ret;

	if (!g) {
		eprintf ("Initialize libgdbr_t first\n");
		return -1;
	}
	g->data_len = 0;
	while (r_socket_ready (g->sock, 0, READ_TIMEOUT) > 0) {
		int sz = r_socket_read (g->sock, (void *)g->read_buff, g->read_max);
		if (sz <= 0) {
			eprintf ("%s: read failed\n", __func__);
			return -1;
		}
		ret = unpack (g, &ctx, sz);
		if (ret < 0) {
			eprintf ("%s: unpack failed\n", __func__);
			return -1;
		}
		if (!ret) {
			return 0;
		}
	}
	return -1;
}

int send_packet(libgdbr_t *g) {
	if (!g) {
		eprintf ("Initialize libgdbr_t first\n");
		return -1;
	}
	return r_socket_write (g->sock, g->send_buff, g->send_len);
}
