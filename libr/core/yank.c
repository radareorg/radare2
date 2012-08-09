/* radare - LGPL - Copyright 2009-2012 - pancake */

#include "r_core.h"

R_API void r_core_yank_set (RCore *core, const char *str) {
	free (core->yank);
	if (str) {
		core->yank = (ut8*)strdup (str);
		core->yank_off = core->offset;
		core->yank_len = strlen (str);
	} else {
		core->yank = NULL;
		core->yank_len = 0;
	}
}

R_API int r_core_yank(struct r_core_t *core, ut64 addr, int len) {
	ut64 oldbsz = 0LL;
	ut64 curseek = core->offset;
	free (core->yank);
	core->yank = (ut8 *)malloc (len);
	if (addr != core->offset)
		r_core_seek (core, addr, 1);
	if (len == 0)
		len = core->blocksize;
	if (len > core->blocksize) {
		oldbsz = core->blocksize;
		r_core_block_size (core, len);
	}
	memcpy (core->yank, core->block, len);
	core->yank_off = addr;
	core->yank_len = len;
	if (curseek != addr)
		r_core_seek (core, curseek, 1);
	if (oldbsz)
		r_core_block_size (core, oldbsz);
	return R_TRUE;
}

R_API int r_core_yank_paste(struct r_core_t *core, ut64 addr, int len) {
	if (len == 0)
		len = core->yank_len;
	if (len > core->yank_len)
		len = core->yank_len;
	r_core_write_at (core, addr, core->yank, len);
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
	r_core_read_at (core, src, buf, len);
	r_core_write_at (core, pos, buf, len);
	free (buf);

	core->offset = src;
	r_core_block_read (core, 0);
	free (arg);
	return 0;
}
