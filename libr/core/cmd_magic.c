/* radare - LGPL - Copyright 2009-2015 - pancake */
#include <stddef.h>

#include "r_config.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_magic.h"
#include "r_types.h"

/* ugly global vars */
static int magicdepth = 99; //XXX: do not use global var here
static RMagic *ck = NULL; // XXX: Use RCore->magic
static char *ofile = NULL;

static int r_core_magic_at(RCore *core, const char *file, ut64 addr, int depth, int v) {
	const char *fmt;
	char *q, *p;
	const char *str;
	int found = 0, delta = 0, adelta = 0, ret;
	ut64 curoffset = core->offset;
#define NAH 32

	if (--depth<0) {
		ret = 0;
		goto seek_exit;
	}
	if (addr != core->offset) {
#if 1
		if (addr >= core->offset && (addr+NAH) < (core->offset + core->blocksize)) {
			delta = addr - core->offset;
		} else {
			r_core_seek (core, addr, true);
		}
#endif
	}
	if (core->search->align) {
		int mod = addr % core->search->align;
		if (mod) {
			eprintf ("Unaligned search at %d\n", mod);
			ret = mod;
			goto seek_exit;
		}
	}
	if (((addr&7)==0) && ((addr&(7<<8))==0))
		eprintf ("0x%08"PFMT64x"\r", addr);
	if (file) {
		if (*file == ' ') file++;
		if (!*file) file = NULL;
	}
	if (file && ofile && file != ofile) {
		if (strcmp (file, ofile)) {
			r_magic_free (ck);
			ck = NULL;
		}
	}
	if (ck==NULL) {
		// TODO: Move RMagic into RCore
		r_magic_free (ck);
		// allocate once
		ck = r_magic_new (0);
		if (file) {
			free (ofile);
			ofile = strdup (file);
			if (r_magic_load (ck, file) == -1) {
				eprintf ("failed r_magic_load (\"%s\") %s\n", file, r_magic_error (ck));
				ck = NULL;
				ret = -1;
				goto seek_exit;
			}
		} else {
			const char *magicpath = r_config_get (core->config, "dir.magic");
			if (r_magic_load (ck, magicpath) == -1) {
				ck = NULL;
				eprintf ("failed r_magic_load (dir.magic) %s\n", r_magic_error (ck));
				ret = -1;
				goto seek_exit;
			}
		}
	}
//repeat:
	//if (v) r_cons_printf ("  %d # pm %s @ 0x%"PFMT64x"\n", depth, file? file: "", addr);
	if (delta+2>core->blocksize) {
		eprintf ("EOB\n");
		ret = -1;
		goto seek_exit;
	}
	str = r_magic_buffer (ck, core->block+delta, core->blocksize-delta);
	if (str) {
		const char *cmdhit;
#if USE_LIB_MAGIC
		if (!v && (!strcmp (str, "data") || strstr(str, "ASCII") || strstr(str, "ISO") || strstr(str, "no line terminator"))) {
#else
		if (!v && (!strcmp (str, "data"))) {
#endif
			int mod = core->search->align;
			if (mod<1) mod = 1;
			//r_magic_free (ck);
			//ck = NULL;
			//return -1;
			ret = mod + 1;
			goto seek_exit;
		}
		p = strdup (str);
		fmt = p;
		// processing newlinez
		for (q=p; *q; q++) {
			if (q[0]=='\\' && q[1]=='n') {
				*q = '\n';
				strcpy (q+1, q+((q[2]==' ')? 3: 2));
			}
		}
		cmdhit = r_config_get (core->config, "cmd.hit");
		if (cmdhit && *cmdhit) {
			r_core_cmd0 (core, cmdhit);
		}
		// TODO: This must be a callback .. move this into RSearch?
		r_cons_printf ("0x%08"PFMT64x" %d %s\n", addr + adelta, magicdepth-depth, p);
		r_cons_clear_line (1);
		eprintf ("0x%08"PFMT64x" 0x%08"PFMT64x" %d %s\n",
			addr+adelta, addr+adelta, magicdepth-depth, p);
		// walking children
		for (q=p; *q; q++) {
			switch (*q) {
			case ' ':
				fmt = q+1;
				break;
			case '@':
				{
					ut64 addr = 0LL;
					*q = 0;
					if (!memcmp (q+1, "0x", 2))
						sscanf (q+3, "%"PFMT64x, &addr);
					else sscanf (q+1, "%"PFMT64d, &addr);
					if (!fmt || !*fmt) fmt = file;
					r_core_magic_at (core, fmt, addr, depth, 1);
					*q = '@';
				}
				break;
			}
		}
		free (p);
		r_magic_free (ck);
		ck = NULL;

		found ++;
//		return adelta+1;
	}
	adelta ++;
	delta ++;
#if 0
	if((core->blocksize-delta)>16)
		goto repeat;
#endif
#if 0
	r_magic_free (ck);
	ck = NULL;
#endif
{
	int mod = core->search->align;
	if (mod) {
		ret = mod; //adelta%addr + deR_ABS(mod-adelta)+1;
		goto seek_exit;
	}
}
	ret = adelta; //found;

seek_exit:
	r_core_seek (core, curoffset, true);
	return ret;
}

static void r_core_magic(RCore *core, const char *file, int v) {
	ut64 addr = core->offset;
	magicdepth = r_config_get_i (core->config, "magic.depth"); // TODO: do not use global var here
	r_core_magic_at (core, file, addr, magicdepth, v);
	if (addr != core->offset)
		r_core_seek (core, addr, true);
}
