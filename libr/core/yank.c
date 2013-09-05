/* radare - LGPL - Copyright 2009-2013 - pancake */

#include "r_core.h"

R_API int r_core_yank_set (RCore *core, const char *str) {
	free (core->yank_buf);
	if (str && *str) {
		core->yank_buf = (ut8*)strdup (str);
		core->yank_off = core->offset;
		core->yank_len = strlen (str);
		return R_TRUE;
	}
	core->yank_buf = NULL;
	core->yank_len = 0;
	return R_FALSE;
}

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 oldbsz = 0LL;
	ut64 curseek = core->offset;
	free (core->yank_buf);
	if (len<0)
		return R_FALSE;
	core->yank_buf = (ut8 *)malloc (len);
	if (addr != core->offset)
		r_core_seek (core, addr, 1);
	if (len == 0) {
		len = core->blocksize;
		core->yank_buf = realloc (core->yank_buf, len);
	} else
	if (len > core->blocksize) {
		oldbsz = core->blocksize;
		r_core_block_size (core, len);
	}
	memcpy (core->yank_buf, core->block, len);
	core->yank_off = addr;
	core->yank_len = len;
	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	if (oldbsz)
		r_core_block_size (core, oldbsz);
	return R_TRUE;
}

R_API int r_core_yank_paste(RCore *core, ut64 addr, int len) {
	if (len<0) return R_FALSE;
	if (len == 0) len = core->yank_len;
	if (len > core->yank_len)
		len = core->yank_len;
	r_core_write_at (core, addr, core->yank_buf, len);
	return R_TRUE;
}

R_API int r_core_yank_to(RCore *core, const char *_arg) {
	ut64 src = core->offset;
	ut64 len = 0;
	ut64 pos = -1;
	char *str, *arg;
	ut8 *buf;

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
		return R_FALSE;
	if ((str == NULL) || (pos == -1) || (len == 0)) {
		eprintf ("Usage: yt [len] [dst-addr]\n");
		free (arg);
		return 1;
	}
#if 0
	if (!config_get("file.write")) {
		eprintf("You are not in read-write mode.\n");
		return 1;
	}
#endif
	buf = (ut8*)malloc (len);
	if (!buf) {
		free (arg);
		return R_FALSE;
	}
	r_core_read_at (core, src, buf, len);
	r_core_write_at (core, pos, buf, len);
	free (buf);

	core->offset = src;
	r_core_block_read (core, 0);
	free (arg);
	return 0;
}
