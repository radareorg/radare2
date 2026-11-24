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
	if (!gdbr_data_reserve (g, g->data_len + 1)) {
		R_LOG_ERROR ("%s: Failed to reallocate buffer", __func__);
		return false;
	}
	g->data[g->data_len++] = ch;
	return true;
}

enum {
	PACKET_READY,
	PACKET_PARTIAL,
	PACKET_CORRUPT,
};

static void consume(libgdbr_t *g, int count) {
	g->read_len -= count;
	memmove (g->read_buff, g->read_buff + count, g->read_len);
}

static int unpack(libgdbr_t *g, struct parse_ctx *ctx) {
	int i;
	for (i = 0; i < g->read_len; i++) {
		const ut8 cur = g->read_buff[i];
		if (!(ctx->flags & HEADER)) {
			if (cur == '$') {
				ctx->flags = HEADER;
			} else if (!g->no_ack && cur == '+') {
				g->ack_retries = -1;
			} else if (!g->no_ack && cur == '-' && g->ack_retries >= 0) {
				if (g->ack_retries++ >= g->num_retries || send_packet (g) < 0) {
					g->ack_retries = -1;
					g->read_len = 0;
					return -1;
				}
			}
			continue;
		}
		if (ctx->flags & CHKSUM) {
			const int digit = hex2int (cur);
			if (digit < 0) {
				consume (g, i + (cur != '$'));
				return PACKET_CORRUPT;
			}
			ctx->sum -= digit << (ctx->chksum_nibble * 4);
			if (ctx->chksum_nibble--) {
				continue;
			}
			consume (g, i + 1);
			return ctx->sum == 0? PACKET_READY: PACKET_CORRUPT;
		}
		ctx->sum += cur;
		if (ctx->flags & ESC) {
			ctx->last = cur ^ 0x20;
			if (!append (g, ctx->last)) {
				return -1;
			}
			ctx->flags &= ~ESC;
			continue;
		}
		if (ctx->flags & DUP) {
			if (cur < 32 || cur > 126 || cur == '$' || cur == '#') {
				consume (g, i + (cur != '$'));
				return PACKET_CORRUPT;
			}
			int count;
			for (count = cur - 29; count > 0; count--) {
				if (!append (g, ctx->last)) {
					return -1;
				}
			}
			ctx->flags &= ~DUP;
			continue;
		}
		switch (cur) {
		case '$':
			consume (g, i);
			return PACKET_CORRUPT;
		case '#':
			ctx->sum -= cur;
			ctx->flags |= CHKSUM;
			ctx->chksum_nibble = 1;
			break;
		case '}':
			ctx->flags |= ESC;
			break;
		case '*':
			if (!g->data_len) {
				consume (g, i + 1);
				return PACKET_CORRUPT;
			}
			ctx->flags |= DUP;
			break;
		default:
			if (!append (g, cur)) {
				return -1;
			}
			ctx->last = cur;
			break;
		}
	}
	g->read_len = 0;
	return PACKET_PARTIAL;
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
	int timeouts = 0;
	int corrupt = 0;
	g->data_len = 0;
	while (timeouts < g->num_retries) {
		if (!send_pending_interrupt (g, vcont)) {
			return -1;
		}
		if (g->read_len > 0) {
			int ret = unpack (g, &ctx);
			if (ret < 0) {
				return -1;
			}
			if (ret == PACKET_READY) {
				g->ack_retries = -1;
				g->data[g->data_len] = '\0';
				return send_ack (g) < 0 || !send_pending_interrupt (g, vcont)? -1: 0;
			}
			if (ret == PACKET_CORRUPT) {
				if (g->no_ack || r_socket_write (g->sock, "-", 1) != 1 || ++corrupt > g->num_retries) {
					return -1;
				}
				ctx = (struct parse_ctx){0};
				g->data_len = 0;
			}
			continue;
		}
		int ready = r_socket_ready (g->sock, 0, READ_TIMEOUT);
		if (ready < 0) {
			if (vcont && g->connected && g->isbreaked) {
				continue;
			}
			return -1;
		}
		if (!ready) {
			if (vcont && !(ctx.flags & HEADER)) {
				return GDBR_READ_TIMEOUT;
			}
			timeouts++;
			continue;
		}
		int size = r_socket_read (g->sock, (ut8 *)g->read_buff, g->read_max - 1);
		if (size < 0 && vcont && g->connected && g->isbreaked) {
			continue;
		}
		if (size <= 0) {
			return -1;
		}
		g->read_len = size;
		timeouts = 0;
	}
	return -1;
}

int send_packet(libgdbr_t *g) {
	R_RETURN_VAL_IF_FAIL (g, -1);
	R_LOG_DEBUG ("putpkt (\"%s\")", g->send_buff);
	return r_socket_write (g->sock, g->send_buff, g->send_len) == g->send_len? g->send_len: -1;
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
		if (*src == '#' || *src == '$' || *src == '}' || *src == '*') {
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
		if (run_len == '#' || run_len == '$' || run_len == '+' || run_len == '-') {
			run_len--;
			if (run_len == '#') {
				run_len--;
			}
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
