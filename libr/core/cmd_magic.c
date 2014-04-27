/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */

static int magicdepth = 99; //XXX: do not use global var here

static int r_core_magic_at(RCore *core, const char *file, ut64 addr, int depth, int v) {
	const char *fmt;
	char *q, *p;
	const char *str;
	static RMagic *ck = NULL; // XXX: Use RCore->magic
	static char *oldfile = NULL;

	if (--depth<0)
		 return 1;
	if (addr != core->offset)
		r_core_seek (core, addr, R_TRUE);
	if (file) {
		if (*file == ' ') file++;
		if (!*file) file = NULL;
	}
	if (!oldfile || ck==NULL || (file && strcmp (file, oldfile))) {
		// TODO: Move RMagic into RCore
		r_magic_free (ck);
		ck = r_magic_new (0);
	}
	if (file) {
		if (r_magic_load (ck, file) == -1) {
			eprintf ("failed r_magic_load (\"%s\") %s\n", file, r_magic_error (ck));
			return -1;
		}
	} else {
		const char *magicpath = r_config_get (core->config, "dir.magic");
		if (r_magic_load (ck, magicpath) == -1) {
			eprintf ("failed r_magic_load (dir.magic) %s\n", r_magic_error (ck));
			return -1;
		}
	}
	//if (v) r_cons_printf ("  %d # pm %s @ 0x%"PFMT64x"\n", depth, file? file: "", addr);
	str = r_magic_buffer (ck, core->block, core->blocksize);
	if (str) {
		if (!v && !strcmp (str, "data"))
			return -1;
		p = strdup (str);
		fmt = p;
		// processing newlinez
		for (q=p; *q; q++)
			if (q[0]=='\\' && q[1]=='n') {
				*q = '\n';
				strcpy (q+1, q+((q[2]==' ')? 3: 2));
			}
		// TODO: This must be a callback .. move this into RSearch?
		r_cons_printf ("0x%08"PFMT64x" %d %s\n", addr, magicdepth-depth, p);
		// walking children
		for (q=p; *q; q++) {
			switch (*q) {
			case ' ':
				fmt = q+1;
				break;
			case '@':
				*q = 0;
				if (!memcmp (q+1, "0x", 2))
					sscanf (q+3, "%"PFMT64x, &addr);
				else sscanf (q+1, "%"PFMT64d, &addr);
				if (!fmt || !*fmt) fmt = file;
				r_core_magic_at (core, fmt, addr, depth, 1);
				*q = '@';
			}
		}
		free (p);
		return 1;
	}
	return 0;
}

static void r_core_magic(RCore *core, const char *file, int v) {
	ut64 addr = core->offset;
	magicdepth = r_config_get_i (core->config, "magic.depth"); // TODO: do not use global var here
	r_core_magic_at (core, file, addr, magicdepth, v);
	if (addr != core->offset)
		r_core_seek (core, addr, R_TRUE);
}
