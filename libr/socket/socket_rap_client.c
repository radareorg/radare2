/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_socket.h>
#include <r_util.h>

static ut8 *r_rap_packet(ut8 type, ut32 len) {
	/* Prevent size overflow in allocation */
	if (SZT_ADD_OVFCHK ((size_t)len, 5)) {
		R_LOG_ERROR ("rap: packet length overflow %u", len);
		return NULL;
	}
	ut8 *buf = malloc (len + 5);
	if (buf) {
		buf[0] = type;
		r_write_be32 (buf + 1, len);
	}
	return buf;
}

static void r_rap_packet_fill(ut8 *buf, const ut8* src, int len) {
	if (buf && src && len > 0) {
		ut32 curlen = r_read_be32 (buf + 1);
		memcpy (buf + 5, src, R_MIN (curlen, len));
	}
}

R_API int r_socket_rap_client_open(RSocket *s, const char *file, int rw) {
	r_socket_block_time (s, true, 1, 0);
	size_t file_len0 = strlen (file) + 1;
	if (file_len0 > 255) {
		R_LOG_ERROR ("Filename too long");
		return -1;
	}
	char *buf = malloc (file_len0 + 7);
	if (!buf) {
		return -1;
	}
	// >>
	buf[0] = RAP_PACKET_OPEN;
	buf[1] = rw;
	buf[2] = (ut8)(file_len0 & 0xff);
	memcpy (buf + 3, file, file_len0);
	(void)r_socket_write (s, buf, 3 + file_len0);
	r_socket_flush (s);
	// <<
	int fd = -1;
	memset (buf, 0, 5);
	int r = r_socket_read_block (s, (ut8*)buf, 5);
	if (r == 5) {
		if (buf[0] == (char)(RAP_PACKET_OPEN | RAP_PACKET_REPLY)) {
			fd = r_read_at_be32 (buf + 1, 1);
		} else {
			R_LOG_ERROR ("RapClientOpen: Bad packet 0x%02x", buf[0]);
		}
	} else {
		R_LOG_ERROR ("Cannot read 5 bytes from server");
	}
	free (buf);
	return fd;
}

R_API char *r_socket_rap_client_command(RSocket *s, const char *cmd, RCoreBind *c) {
	char *buf = malloc (strlen (cmd) + 8);
	if (!buf) {
		return NULL;
	}
	/* send request */
	buf[0] = RAP_PACKET_CMD;
	size_t i = strlen (cmd) + 1;
	r_write_be32 (buf + 1, i);
	memcpy (buf + 5, cmd, i);
	r_socket_write (s, buf, 5 + i);
	r_socket_flush (s);
	free (buf);
	/* read response */
	char bufr[8];
	r_socket_read_block (s, (ut8*)bufr, 5);
	while (bufr[0] == (char)(RAP_PACKET_CMD)) {
		size_t cmd_len = r_read_at_be32 (bufr, 1);
		char *rcmd = calloc (1, cmd_len + 1);
		if (rcmd) {
			r_socket_read_block (s, (ut8*)rcmd, cmd_len);
			// char *res = r_core_cmd_str (core, rcmd);
			char *res = c->cmdStr (c->core, rcmd);
			if (res) {
				int res_len = strlen (res) + 1;
				ut8 *pkt = r_rap_packet ((RAP_PACKET_CMD | RAP_PACKET_REPLY), res_len);
				r_rap_packet_fill (pkt, (const ut8*)res, res_len);
				r_socket_write (s, pkt, 5 + res_len);
				r_socket_flush (s);
				free (res);
				free (pkt);
			}
			free (rcmd);
		}
		/* read response */
		bufr[0] = -1;
		(void) r_socket_read_block (s, (ut8*)bufr, 5);
	}
	if (bufr[0] != (char)(RAP_PACKET_CMD | RAP_PACKET_REPLY)) {
		R_LOG_ERROR ("Wrong reply for command 0x%02x", bufr[0]);
		return NULL;
	}
	size_t cmd_len = r_read_at_be32 (bufr, 1);
	if (cmd_len < 1 || cmd_len > 16384) {
		R_LOG_ERROR ("cmd_len is wrong");
		return NULL;
	}
	char *cmd_output = calloc (1, cmd_len + 1);
	if (!cmd_output) {
		R_LOG_ERROR ("Allocating cmd output");
		return NULL;
	}
	r_socket_read_block (s, (ut8*)cmd_output, cmd_len);
	//ensure the termination
	cmd_output[cmd_len] = 0;
	return cmd_output;
}

R_API int r_socket_rap_client_write(RSocket *s, const ut8 *buf, int count) {
	ut8 *tmp;
	int ret;
	if (count < 1) {
		return count;
	}
	// TOOD: if count > RAP_PACKET_MAX iterate !
	if (count > RAP_PACKET_MAX) {
		count = RAP_PACKET_MAX;
	}
	if (!(tmp = (ut8 *)malloc (count + 5))) {
		R_LOG_ERROR ("rap_write malloc failed");
		return -1;
	}
	tmp[0] = RAP_PACKET_WRITE;
	r_write_be32 (tmp + 1, count);
	memcpy (tmp + 5, buf, count);

	(void)r_socket_write (s, tmp, count + 5);
	r_socket_flush (s);
	if (r_socket_read_block (s, tmp, 5) != 5) { // TODO read_block?
		R_LOG_ERROR ("cannot read from socket");
		ret = -1;
	} else {
		ret = r_read_be32 (tmp + 1);
		if (!ret) {
			ret = -1;
		}
	}
	free (tmp);
	return ret;
}

R_API int r_socket_rap_client_read(RSocket *s, ut8 *buf, int count) {
	ut8 tmp[32];
	if (count < 1) {
		return count;
	}
	r_socket_block_time (s, 1, 1, 0);
	// XXX. if count is > RAP_PACKET_MAX, just perform multiple queries
	if (count > RAP_PACKET_MAX) {
		count = RAP_PACKET_MAX;
	}
	// send
	tmp[0] = RAP_PACKET_READ;
	r_write_be32 (tmp + 1, count);
	(void)r_socket_write (s, tmp, 5);
	r_socket_flush (s);
	// recv
	int ret = r_socket_read_block (s, tmp, 5);
	if (ret != 5 || tmp[0] != (RAP_PACKET_READ | RAP_PACKET_REPLY)) {
		R_LOG_WARN ("Unexpected rap read reply (%d=0x%02x) expected (%d=0x%02x)",
			ret, tmp[0], 2, (RAP_PACKET_READ | RAP_PACKET_REPLY));
		return -1;
	}
	int i = r_read_at_be32 (tmp, 1);
	if (i > count) {
		R_LOG_WARN ("Unexpected data size %d vs %d", i, count);
		return -1;
	}
	r_socket_read_block (s, buf, i);
	return count;
}

R_API ut64 r_socket_rap_client_seek(RSocket *s, ut64 offset, int whence) {
	R_RETURN_VAL_IF_FAIL (s, UT64_MAX);
	ut8 tmp[10];
	tmp[0] = RAP_PACKET_SEEK;
	tmp[1] = (ut8)whence;
	r_write_be64 (tmp + 2, offset);
	int ret = r_socket_write (s, &tmp, 10);
	if (ret != 10) {
		R_LOG_ERROR ("Truncated socket write %d vs %d", ret, 10);
		r_sys_backtrace ();
		return UT64_MAX;
	}
	r_socket_flush (s);
	ret = r_socket_read_block (s, (ut8*)&tmp, 9);
	if (ret != 9) {
		R_LOG_ERROR ("Truncated socket read %d vs %d", ret, 9);
		return UT64_MAX;
	}
	if (tmp[0] != (RAP_PACKET_SEEK | RAP_PACKET_REPLY)) {
		// eprintf ("%d %d  - %02x %02x %02x %02x %02x %02x %02x\n",
		// ret, whence, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6]);
		R_LOG_WARN ("Unexpected seek reply (%02x -> %02x)", tmp[0], (RAP_PACKET_SEEK | RAP_PACKET_REPLY));
		return UT64_MAX;
	}
	return r_read_at_be64 (tmp, 1);
}
