/* radare - LGPL - Copyright 2009-2023 - pancake */

#if R_INCLUDE_BEGIN

#define NAH 32

static R_TH_LOCAL RMagic *ck = NULL; // XXX: Use RCore->magic
static R_TH_LOCAL char *ofile = NULL;

#define MAX_MAGIC_DEPTH 64

static int r_core_magic_at(RCore *core, RSearchKeyword *kw, const char *file, ut64 addr, int depth, bool v, PJ *pj, int *hits) {
	const char *fmt;
	char *q, *p;
	const char *str;
	int delta = 0, adelta = 0, ret;
	ut64 curoffset = core->addr;
	int max_hits = r_config_get_i (core->config, "search.maxhits");
	char *flag;

	if (max_hits > 0 && *hits >= max_hits) {
		return 0;
	}

	if (depth > MAX_MAGIC_DEPTH) {
		ret = 0;
		goto seek_exit;
	}
	bool must_report_progress = !pj;
	if (must_report_progress) {
		must_report_progress = r_config_get_b (core->config, "search.verbose");
		if (must_report_progress) {
			must_report_progress = r_config_get_b (core->config, "scr.interactive");
		}
	}
	if (addr != core->addr) {
		if (addr >= core->addr && (addr + NAH) < (core->addr + core->blocksize)) {
			delta = addr - core->addr;
		} else {
			r_core_seek (core, addr, true);
		}
	}
	if (core->search->align) {
		int mod = addr % core->search->align;
		if (mod) {
			R_LOG_WARN ("Unaligned search result at %d", mod);
			ret = mod;
			goto seek_exit;
		}
	}
	if (((addr & 7) == 0) && ((addr & (7 << 8)) == 0)) {
		if (must_report_progress) {
			eprintf ("0x%08" PFMT64x " [%d matches found]\r", addr, *hits);
		}
	}
	if (file) {
		file = r_str_trim_head_ro (file);
		if (R_STR_ISEMPTY (file)) {
			file = NULL;
		}
	}
	if (file && ofile && file != ofile) {
		if (strcmp (file, ofile)) {
			r_magic_free (ck);
			ck = NULL;
		}
	}
	if (!ck) {
		// TODO: Move RMagic into RCore
		r_magic_free (ck);
		// allocate once
		ck = r_magic_new (0);
		if (file) {
			free (ofile);
			ofile = strdup (file);
			if (!r_magic_load (ck, file)) {
				R_LOG_ERROR ("failed r_magic_load (\"%s\") %s", file, r_magic_error (ck));
				ck = NULL;
				ret = -1;
				goto seek_exit;
			}
		} else {
			const char *magicpath = r_config_get (core->config, "dir.magic");
			if (!r_magic_load (ck, magicpath)) {
				ck = NULL;
				R_LOG_ERROR ("failed r_magic_load (dir.magic) %s", r_magic_error (ck));
				ret = -1;
				goto seek_exit;
			}
		}
	}
	//if (v) r_cons_printf ("  %d # pm %s @ 0x%"PFMT64x"\n", depth, r_str_get (file), addr);
	if (delta + 2 > core->blocksize) {
		R_LOG_WARN ("magic result happens between block reads");
		ret = -1;
		goto seek_exit;
	}
	str = r_magic_buffer (ck, core->block + delta, core->blocksize - delta);
	if (str) {
		const char *cmdhit;
#if USE_LIB_MAGIC
		if (!v && (!strcmp (str, "data") || strstr (str, "ASCII") || strstr (str, "ISO") || strstr (str, "no line terminator"))) {
#else
		if (!v && (!strcmp (str, "data"))) {
#endif
			int mod = core->search->align;
			if (mod < 1) {
				mod = 1;
			}
			//r_magic_free (ck);
			//ck = NULL;
			//return -1;
			ret = mod + 1;
			goto seek_exit;
		}
		p = strdup (str);
		fmt = p;
		// processing newline
		for (q = p; *q; q++) {
			if (q[0] == '\\' && q[1] == 'n') {
				*q = '\n';
				strcpy (q + 1, q + ((q[2] == ' ')? 3: 2));
			}
		}
		(*hits)++;
		cmdhit = r_config_get (core->config, "cmd.hit");
		if (cmdhit && *cmdhit) {
			r_core_cmd0 (core, cmdhit);
		}

		const char *searchprefix = r_config_get (core->config, "search.prefix");

		// We do not flag for pm command.
		if (kw) {
			flag = r_str_newf ("%s%d_%d", searchprefix, kw->kwidx, kw->count);
			kw->count++;
			r_flag_set (core->flags, flag, addr + adelta, 1);
		}
		// TODO: This must be a callback .. move this into RSearch?
		if (!pj) {
			if (kw) {
				r_cons_printf ("0x%08" PFMT64x " %d %s %s\n", addr + adelta, depth, flag, p);
				R_FREE (flag);
			} else {
				r_cons_printf ("0x%08" PFMT64x " %d %s\n", addr + adelta, depth, p);
			}
		} else {
			pj_o (pj);
			pj_kN (pj, "offset", addr + adelta);
			pj_ki (pj, "depth", depth);
			pj_ks (pj, "info", p);
			pj_end (pj);
		}

		if (must_report_progress) {
			r_cons_clear_line (1);
		}
		//eprintf ("0x%08"PFMT64x" 0x%08"PFMT64x" %d %s\n", addr+adelta, addr+adelta, depth, p);
		// walking children
		for (q = p; *q; q++) {
			switch (*q) {
			case ' ':
				fmt = q + 1;
				break;
			case '@':
				{
					ut64 addr = 0LL;
					*q = 0;
					if (r_str_startswith (q + 1, "0x")) {
						sscanf (q + 3, "%"PFMT64x, &addr);
					} else {
						sscanf (q + 1, "%"PFMT64d, &addr);
					}
					if (R_STR_ISEMPTY (fmt)) {
						fmt = file;
					}
					r_core_magic_at (core, kw, fmt, addr, depth + 1, true, pj, hits);
					*q = '@';
				}
				break;
			}
		}
		R_FREE (p);
		r_magic_free (ck);
		ck = NULL;
	}
	adelta ++;
	delta ++;
#if 0
	r_magic_free (ck);
	ck = NULL;
#endif
	int mod = core->search->align;
	if (mod) {
		ret = mod; //adelta%addr + deR_ABS(mod-adelta)+1;
		goto seek_exit;
	}
	ret = adelta; //found;

seek_exit:
	r_core_seek (core, curoffset, true);
	return ret;
}

static void r_core_magic(RCore *core, const char *file, int v, PJ *pj) {
	ut64 addr = core->addr;
	int hits = 0;

	r_core_magic_at (core, NULL, file, addr, 0, v, pj, &hits);
	if (pj) {
		r_cons_newline ();
	}
	if (addr != core->addr) {
		r_core_seek (core, addr, true);
	}
}

#endif
