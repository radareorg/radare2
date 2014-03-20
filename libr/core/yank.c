/* radare - LGPL - Copyright 2009-2013 - pancake & dso */

#include "r_core.h"
#include "r_print.h"

R_API int r_core_yank_set (RCore *core, ut64 addr, const char *str, ut32 len) {
	//free (core->yank_buf);
	if (str && len) {
		r_buf_set_bytes (core->yank_buf, (const ut8 *)str, len);
		core->yank_off = addr;
		return R_TRUE;
	}
	return R_FALSE;
}
// Call set and then null terminate the bytes.
R_API int r_core_yank_set_str (RCore *core, ut64 addr, const char *str, ut32 len) {
	//free (core->yank_buf);
	int res = r_core_yank_set (core, addr, str, len);
	if (res == R_TRUE)
		core->yank_buf->buf[len-1] = 0;
	return res;
}

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 oldbsz = 0LL;
	ut64 curseek = core->offset;
	char *buf = NULL;
	if (len<0) {
		eprintf ("r_core_yank: cannot yank negative bytes\n");
		return R_FALSE;
	}
	if (len == 0) len = core->blocksize;
	//free (core->yank_buf);
	buf = malloc (len);
	//core->yank_buf = (ut8 *)malloc (len);
	if (addr != core->offset)
		r_core_seek (core, addr, 1);

	r_core_read_at (core, addr, buf, len);
	r_core_yank_set (core, addr, buf, len);

	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	return R_TRUE;
}

R_API int r_core_yank_paste(RCore *core, ut64 addr, int len) {
	if (len<0) return R_FALSE;
	if (len == 0 || len >= core->yank_buf->length) len = core->yank_buf->length;
	r_core_write_at (core, addr, core->yank_buf->buf, len);
	return R_TRUE;
}

R_API int r_core_yank_to(RCore *core, const char *_arg) {
	ut64 len = 0;
	ut64 pos = -1;
	char *str, *arg;
	int res = R_FALSE;


	while (*_arg==' ') _arg++;
	arg = strdup (_arg);
	str = strchr (arg, ' ');
	if (str) {
		str[0]='\0';
		len = r_num_math (core->num, arg);
		pos = r_num_math (core->num, str+1);
		str[0]=' ';
	}
	if (len<1)
		return res;
	if ((str == NULL) || (pos == -1) || (len == 0)) {
		eprintf ("Usage: yt [len] [dst-addr]\n");
		free (arg);
		return res;
	}

	if (r_core_yank(core, core->offset, len) == R_TRUE)
		res = r_core_yank_paste (core, pos, len);

	free (arg);
	return res;
}


R_API int r_core_yank_dump (RCore *core, ut64 pos) {
	int res = R_FALSE, i =0;
	if (pos >= core->yank_buf->length) {
		eprintf ("Position exceeds buffer length.\n");
	} else if (core->yank_buf->length > 0) {
		r_cons_printf ("0x%08"PFMT64x" %d ", core->yank_off+pos,
			core->yank_buf->length-pos);

		for (i=pos; i < core->yank_buf->length; i++)
			r_cons_printf ("%02x", core->yank_buf->buf[i]);

		r_cons_newline ();
		res = R_TRUE;
	} else eprintf ("No buffer yanked already\n");
	return res;
}

R_API int r_core_yank_hexdump (RCore *core, ut64 pos) {
	int res = R_FALSE;
	if (pos >= core->yank_buf->length) {
		eprintf ("Position exceeds buffer length.\n");
	} else if (core->yank_buf->length > 0) {
		r_print_hexdump (core->print, pos, core->yank_buf->buf+pos, core->yank_buf->length-pos, 16, 4);
		res = R_TRUE;
	} else eprintf ("No buffer yanked already\n");
	return res;
}


R_API int r_core_yank_cat (RCore *core, ut64 pos) {
	int res = R_FALSE;
	if (pos >= core->yank_buf->length && core->yank_buf->length != 0) {
		eprintf ("Position exceeds buffer length.\n");
	} else if (core->yank_buf->length > 0) {
		r_cons_memcat ((const char*)core->yank_buf->buf+pos, core->yank_buf->length-pos);
		r_cons_newline ();
		res = R_TRUE;
	} else r_cons_newline ();
	return res;
}

R_API int r_core_yank_hud_file (RCore *core, const char *input) {
	char *buf = NULL;
	ut32 len = 0;
	int res = R_FALSE;

	for (input++; *input==' '; input++);

	buf = r_cons_hud_file (input);
	len = buf? strlen ((const char *)buf) + 1: 0;
	res = r_core_yank_set_str (core, -1, buf, len);
	return res;
}

R_API int r_core_yank_hud_path (RCore *core, const char *input, int dir) {
	char *buf = NULL;
	ut32 len = 0;
	int res = R_FALSE;
	for (input++; *input==' '; input++);

	buf = r_cons_hud_path (input, dir);
	len = buf? strlen ((const char *)buf) + 1: 0;
	res = r_core_yank_set_str (core, -1, buf, len);
	return res;
}