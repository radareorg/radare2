/* libqnxr - GPL - Copyright 2014-2016 - defragger, madprogrammer */

#include <errno.h>
#include "packet.h"
#include "utils.h"
#include "dsmsgs.h"

#define READ_TIMEOUT (300 * 1000 * 1000)
#define FRAME_CHAR 0x7e
#define ESC_CHAR 0x7d

#define SET_CHANNEL_RESET 0
#define SET_CHANNEL_DEBUG 1
#define SET_CHANNEL_TEXT 2
#define SET_CHANNEL_NAK 0xff

static ut8 nak_packet[] =
	{FRAME_CHAR, SET_CHANNEL_NAK, 0, FRAME_CHAR};
static ut8 ch_reset_packet[] =
	{FRAME_CHAR, SET_CHANNEL_RESET, 0xff, FRAME_CHAR};
static ut8 ch_debug_packet[] =
	{FRAME_CHAR, SET_CHANNEL_DEBUG, 0xfe, FRAME_CHAR};
static ut8 ch_text_packet[] =
	{FRAME_CHAR, SET_CHANNEL_TEXT, 0xfd, FRAME_CHAR};

static int append (libqnxr_t *g, char ch) {
	if (g->data_len == DS_DATA_MAX_SIZE + 16) {
		eprintf ("%s: data too long\n", __func__);
		return -1;
	}

	g->recv.data[g->data_len++] = ch;
	return 0;
}

static int unpack (libqnxr_t *g) {
	ut8 modifier = 0;
	ut8 sum = 0xff;

	for (; g->read_ptr < g->read_len; g->read_ptr++) {
		char cur = g->read_buff[g->read_ptr];
		switch (cur) {
		case ESC_CHAR:
			modifier = 0x20;
			continue;
		case FRAME_CHAR:
			/* Ignore multiple start frames */
			if (g->data_len == 0)
				continue;
			if (sum != 0x00) {
				eprintf ("%s: Checksum error\n", __func__);
				return -1;
			}
			g->read_ptr++;
			return 0;
		default:
			cur ^= modifier;
			sum -= cur;
			append (g, cur);
		}
		modifier = 0;
	}

	return 1;
}

int qnxr_read_packet (libqnxr_t *g) {
	int ret;

	if (!g) {
		eprintf ("Initialize libqnxr_t first\n");
		return -1;
	}
	g->data_len = 0;

	// read from network if we've exhausted our buffer
	// or the buffer is empty
	if (g->read_len == 0 || g->read_ptr == g->read_len) {
		while (true) {
			int ret = r_socket_ready (g->sock, 0, READ_TIMEOUT);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				else
					return -1;
			}

			g->read_ptr = 0;
			g->read_len = r_socket_read (g->sock, (void *)g->read_buff,

						     DS_DATA_MAX_SIZE * 2);
			if (g->read_len <= 0) {
				g->read_len = 0;
				eprintf ("%s: read failed\n", __func__);
				return -1;
			}

			break;
		}
	}

	ret = unpack (g);
	if (ret < 0) {
		eprintf ("%s: unpack failed\n", __func__);
		return -1;
	}

	if (g->data_len >= sizeof (struct DShdr)) {
		if (g->recv.pkt.hdr.channel)
			g->channelrd = g->recv.pkt.hdr.channel;
	} else if (g->data_len >= 1) {
		if (g->recv.data[0] == SET_CHANNEL_NAK) {
			eprintf ("%s: NAK received\n", __func__);
			g->channelrd = SET_CHANNEL_NAK;
			return -1;
		}
		if (g->recv.data[0] <= SET_CHANNEL_TEXT)
			g->channelrd = g->recv.data[0];
	}

	if (!ret) {
		// Skip the checksum
		return g->data_len - 1;
	}

	return -1;
}

int qnxr_send_nak (libqnxr_t *g) {
	return r_socket_write (g->sock, nak_packet, sizeof (nak_packet));
}

int qnxr_send_ch_reset (libqnxr_t *g) {
	return r_socket_write (g->sock, ch_reset_packet, sizeof (ch_reset_packet));
}

int qnxr_send_ch_debug (libqnxr_t *g) {
	return r_socket_write (g->sock, ch_debug_packet, sizeof (ch_debug_packet));
}

int qnxr_send_ch_text (libqnxr_t *g) {
	return r_socket_write (g->sock, ch_text_packet, sizeof (ch_text_packet));
}

int qnxr_send_packet (libqnxr_t *g) {
	if (!g) {
		eprintf ("Initialize libqnxr_t first\n");
		return -1;
	}

	int i;
	ut8 csum = 0;
	char *p;

	p = g->send_buff;
	*p++ = FRAME_CHAR;

	for (i = 0; i < g->send_len; i++) {
		ut8 c = g->tran.data[i];
		csum += c;

		switch (c) {
		case FRAME_CHAR:
		case ESC_CHAR:
			*p++ = ESC_CHAR;
			c ^= 0x20;
			break;
		}
		*p++ = c;
	}

	csum ^= 0xff;
	switch (csum) {
	case FRAME_CHAR:
	case ESC_CHAR:
		*p++ = ESC_CHAR;
		csum ^= 0x20;
		break;
	}
	*p++ = csum;
	*p++ = FRAME_CHAR;

	if (g->channelwr != g->tran.pkt.hdr.channel) {
		switch (g->tran.pkt.hdr.channel) {
		case SET_CHANNEL_TEXT:
			qnxr_send_ch_text (g);
			break;
		case SET_CHANNEL_DEBUG:
			qnxr_send_ch_debug (g);
			break;
		}
		g->channelwr = g->tran.pkt.hdr.channel;
	}

	return r_socket_write (g->sock, g->send_buff, p - g->send_buff);
}
