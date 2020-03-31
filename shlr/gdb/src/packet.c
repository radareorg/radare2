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
	ut32 flags;
	ut8  last;
	ut8  sum;
	int  chksum_nibble;
};

static bool append(libgdbr_t *g, const char ch) {
	char *ptr;
	if (g->data_len == g->data_max - 1) {
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
	bool first = true;
	g->read_buff[len] = '\0';
	for (i = 0; i < len; i++) {
		char cur = g->read_buff[i];
		if (ctx->flags & CHKSUM) {
			ctx->sum -= hex2int (cur) << (ctx->chksum_nibble * 4);
			if (!--ctx->chksum_nibble) {
				continue;
			}
			if (ctx->sum != '#') {
				eprintf ("%s: Invalid checksum\n", __func__);
				return -1;
			}
			if (i != len - 1) {
				if (g->read_buff[i + 1] == '$' ||
				    (g->read_buff[i + 1] == '+' && g->read_buff[i + 2] == '$')) {
					// Packets clubbed together
					g->read_len = len - i - 1;
					memcpy (g->read_buff, g->read_buff + i + 1, g->read_len);
					g->read_buff[g->read_len] = '\0';
					return 0;
				}
				eprintf ("%s: Garbage at end of packet: %s (%s)\n",
					 __func__, g->read_buff + i + 1, g->read_buff + i + 1);
			}
			g->read_len = 0;
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
				eprintf ("%s: Invalid repeat count: %d\n",
					 __func__, cur);
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
			if (first) {
				eprintf ("%s: Invalid repeat\n", __func__);
				return -1;
			}
			ctx->flags |= DUP;
			break;
		case '+':
		case '-':
			if (!(ctx->flags & HEADER)) {
				/* TODO: Handle acks/nacks */
				if (g->server_debug && !g->no_ack) {
					eprintf ("[received '%c' (0x%x)]\n", cur,
						 (int) cur);
				}
				break;
			}
			/* Fall-through */
		default:
			first = false;
			if (!append (g, cur)) {
				return -1;
			}
			ctx->last = cur;
		}
	}
	return 1;
}

int read_packet(libgdbr_t *g, bool vcont) {
	struct parse_ctx ctx = { 0 };
	int ret, i;
	if (!g) {
		eprintf ("Initialize libgdbr_t first\n");
		return -1;
	}
	g->data_len = 0;
	if (g->read_len > 0) {
		if (unpack (g, &ctx, g->read_len) == 0) {
			// TODO: Evaluate if partial packets are clubbed
			g->data[g->data_len] = '\0';
			if (g->server_debug) {
				eprintf ("getpkt (\"%s\");  %s\n", g->data,
					 g->no_ack ? "[no ack sent]" : "[sending ack]");
			}
			return 0;
		}
	}
	g->data_len = 0;
	for (i = 0; i < g->num_retries && !g->isbreaked; vcont ? 0 : i++) {
		ret = r_socket_ready (g->sock, 0, READ_TIMEOUT);
		if (ret == 0 && !vcont) {
			continue;
		}
		if (ret <= 0) {
			return -1;
		}
		int sz = r_socket_read (g->sock, (void *)g->read_buff, g->read_max - 1);
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
			g->data[g->data_len] = '\0';
			if (g->server_debug) {
				eprintf ("getpkt (\"%s\");  %s\n", g->data,
					 g->no_ack ? "[no ack sent]" : "[sending ack]");
			}
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
	if (g->server_debug) {
		g->send_buff[g->send_len] = '\0';
		eprintf ("putpkt (\"%s\");  %s\n", g->send_buff,
			 g->no_ack ? "[noack mode]" : "[looking for ack]");
	}
	return r_socket_write (g->sock, g->send_buff, g->send_len);
}

int pack(libgdbr_t *g, const char *msg) {
	int run_len;
	size_t msg_len;
	const char *src;
	char prev;
	if (!g || !msg) {
		return -1;
	}
	msg_len = strlen (msg);
	if (msg_len > g->send_max + 5) {
		eprintf ("%s: message too long: %s", __func__, msg);
		return -1;
	}
	if (!g->send_buff) {
		return -1;
	}
	g->send_buff[0] = '$';
	g->send_len = 1;
	src = msg;
	while (*src) {
		if (*src == '#' || *src == '$' || *src == '}') {
			msg_len += 1;
			if (msg_len > g->send_max + 5) {
				eprintf ("%s: message too long: %s", __func__, msg);
				return -1;
			}
			g->send_buff[g->send_len++] = '}';
			g->send_buff[g->send_len++] = *src++ ^ 0x20;
			continue;
		}
		g->send_buff[g->send_len++] = *src++;
		if (!g->is_server) {
			continue;
		}
		prev = *(src - 1);
		run_len = 0;
		while (src[run_len] == prev) {
			run_len++;
		}
		if (run_len < 3) {                    // 3 specified in RSP documentation
			while (run_len--) {
				g->send_buff[g->send_len++] = *src++;
			}
			continue;
		}
		run_len += 29;                        // Encode as printable character
		if (run_len == 35 || run_len == 36) { // Cannot use '$' or '#'
			run_len = 34;
		} else if (run_len > 126) {           // Max printable ascii value
			run_len = 126;
		}
		g->send_buff[g->send_len++] = '*';
		g->send_buff[g->send_len++] = run_len;
		msg_len -= run_len - 27;              // 2 chars to encode run length
		src += run_len - 29;
	}
	g->send_buff[g->send_len] = '\0';
	snprintf (g->send_buff + g->send_len, 4, "#%.2x", cmd_checksum(g->send_buff + 1));
	g->send_len += 3;
	return g->send_len;
}
