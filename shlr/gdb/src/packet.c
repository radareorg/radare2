/* libgdbr - LGPL - Copyright 2014-2022 - defragger, pancake */

#include "packet.h"
#include "utils.h"
#include "gdbr_common.h"
#include <r_util.h>
#include <r_cons.h>

#define READ_TIMEOUT (250 * 1000)

enum {
	HEADER	= 1 << 0,
	CHKSUM	= 1 << 1,
	DUP	= 1 << 2,
	ESC	= 1 << 3,
};

struct parse_ctx {
	ut32 flags;
	ut8 last;
	ut8 sum;
	int chksum_nibble;
};

static bool append(libgdbr_t *g, const char ch) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	if (!gdbr_data_reserve (g, g->data_len + 1)) {
		R_LOG_ERROR ("%s: Failed to reallocate buffer", __func__);
		return false;
	}
	g->data[g->data_len++] = ch;
	return true;
}

static int unpack(libgdbr_t *g, struct parse_ctx *ctx, int len) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	int i = 0;
	int j = 0;
	g->read_buff[len] = '\0';
	for (i = 0; i < len; i++) {
		char cur = g->read_buff[i];
		if (ctx->flags & CHKSUM) {
			const int digit = hex2int ((ut8)cur);
			if (digit < 0) {
				return -1;
			}
			ctx->sum -= digit << (ctx->chksum_nibble * 4);
			if (!--ctx->chksum_nibble) {
				continue;
			}
			if (ctx->sum != '#') {
				R_LOG_ERROR ("%s: Invalid checksum", __func__);
				return -1;
			}
			if (i != len - 1) {
				if (g->read_buff[i + 1] == '$' ||
				    (g->read_buff[i + 1] == '+' && g->read_buff[i + 2] == '$')) {
					// Packets clubbed together
					g->read_len = len - i - 1;
					memmove (g->read_buff, g->read_buff + i + 1, g->read_len);
					g->read_buff[g->read_len] = '\0';
					return 0;
				}
				R_LOG_ERROR ("%s: Garbage at end of packet: %s (%s)",
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
				R_LOG_ERROR ("%s: Invalid repeat count: %d",
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
				R_LOG_ERROR ("%s: More than one $", __func__);
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
			if (!g->data_len) {
				R_LOG_ERROR ("%s: Invalid repeat", __func__);
				return -1;
			}
			ctx->flags |= DUP;
			break;
		case '+':
		case '-':
			if (!(ctx->flags & HEADER)) {
				/* TODO: Handle acks/nacks */
				if (!g->no_ack) {
					R_LOG_DEBUG ("[received '%c' (0x%x)]", cur, (int) cur);
				}
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

static bool send_pending_interrupt(libgdbr_t *g, bool polling) {
	if (!g->isbreaked) {
		return true;
	}
	if (!polling || !g->connected) {
		return false;
	}
	g->isbreaked = false;
	if (r_socket_write (g->sock, "\x03", 1) != 1) {
		return false;
	}
	r_cons_break_clear (r_cons_singleton ());
	return true;
}

int read_packet(libgdbr_t *g, bool vcont) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	struct parse_ctx ctx = {0};
	int ret, retries = 0;
	g->data_len = 0;
	if (!send_pending_interrupt (g, vcont)) {
		return -1;
	}
	if (g->read_len > 0) {
		ret = unpack (g, &ctx, g->read_len);
		if (ret < 0) {
			return -1;
		}
		if (!ret) {
			goto complete;
		}
		g->read_len = 0;
	}
	while (retries < g->num_retries) {
		if (!send_pending_interrupt (g, vcont)) {
			return -1;
		}
		ret = r_socket_ready (g->sock, 0, READ_TIMEOUT);
		if (ret < 0) {
			if (vcont && g->connected && g->isbreaked) {
				continue;
			}
			return -1;
		}
		if (!ret) {
			if (vcont && !(ctx.flags & HEADER)) {
				return GDBR_READ_TIMEOUT;
			}
			if (!vcont || !g->connected) {
				retries++;
			}
			continue;
		}
		int sz = r_socket_read (g->sock, (void *)g->read_buff, g->read_max - 1);
		if (sz < 0 && vcont && g->connected && g->isbreaked) {
			continue;
		}
		if (sz <= 0) {
			R_LOG_ERROR ("%s: read failed", __func__);
			return -1;
		}
		ret = unpack (g, &ctx, sz);
		if (ret < 0) {
			R_LOG_ERROR ("%s: unpack failed", __func__);
			return -1;
		}
		if (!ret) {
			goto complete;
		}
		retries = 0;
	}
	return -1;
complete:
	g->data[g->data_len] = '\0';
	R_LOG_DEBUG ("getpkt (\"%s\");  %s", g->data,
		g->no_ack? "[no ack sent]": "[sending ack]");
	if (!send_pending_interrupt (g, vcont)) {
		return -1;
	}
	return 0;
}

int send_packet(libgdbr_t *g) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	g->send_buff[g->send_len] = '\0';
	R_LOG_DEBUG ("putpkt (\"%s\");  %s", g->send_buff,
			g->no_ack ? "[noack mode]" : "[looking for ack]");
	return r_socket_write (g->sock, g->send_buff, g->send_len);
}

int pack(libgdbr_t *g, const char *msg) {
	R_RETURN_VAL_IF_FAIL (g && msg, -1);
	int run_len;
	size_t msg_len;
	const char *src;
	char prev;
	// Reserve the framing bytes and terminator separately from the peer's payload limit.
	if (!g->send_buff || g->send_max < 5) {
		return -1;
	}
	size_t payload_max = (size_t)g->send_max - 5;
	if (!g->is_server) {
		payload_max = R_MIN (payload_max, g->stub_features.pkt_sz);
	}
	msg_len = strlen (msg);
	if (msg_len > payload_max) {
		R_LOG_ERROR ("%s: message too long: %s", __func__, msg);
		return -1;
	}
	g->send_buff[0] = '$';
	g->send_len = 1;
	src = msg;
	while (*src) {
		if (*src == '#' || *src == '$' || *src == '}') {
			msg_len += 1;
			if (msg_len > payload_max) {
				R_LOG_ERROR ("%s: message too long: %s", __func__, msg);
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
	snprintf (g->send_buff + g->send_len, 4, "#%.2x", cmd_checksum (g->send_buff + 1));
	g->send_len += 3;
	return g->send_len;
}
