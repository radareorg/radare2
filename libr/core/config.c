/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_core.h>

#define SETI(x,y,z) r_config_set_i(cfg,x,y)->desc = strdup(z);
#define SETICB(w,x,y,z) r_config_set_i_cb(cfg,w,x,y)->desc = strdup(z);
#define SETPREF(x,y,z) r_config_set(cfg,x,y)->desc = strdup(z);
#define SETCB(w,x,y,z) r_config_set_cb(cfg,w,x,y)->desc = strdup(z);

static inline void __setsegoff(RConfig *cfg, const char *asmarch, int asmbits) {
	if (!strcmp (asmarch, "x86"))
		r_config_set (cfg, "asm.segoff", (asmbits==16)?"true":"false");
}

static int asm_profile(RConfig *cfg, const char *profile) {
	if (!strcmp (profile, "help") || *profile == '?') {
		r_cons_printf ("Available asm.profile:\n"
				" default, gas, smart, graph, debug, full, simple\n");
		return R_FALSE;
	} else if (!strcmp (profile, "default")) {
		r_config_set (cfg, "asm.bytes", "true");
		r_config_set (cfg, "asm.lines", "true");
		r_config_set (cfg, "asm.linesout", "false");
		r_config_set (cfg, "asm.lineswide", "false");
		r_config_set (cfg, "asm.offset", "true");
		r_config_set (cfg, "asm.comments", "true");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "anal.split", "true");
		r_config_set (cfg, "asm.flags", "true");
		r_config_set (cfg, "asm.size", "false");
		r_config_set (cfg, "asm.xrefs", "true");
		r_config_set (cfg, "asm.functions", "true");
		r_config_set (cfg, "scr.color", "true");
	} else if (!strcmp(profile, "compact")) {
		asm_profile (cfg, "simple");
		r_config_set (cfg, "asm.lines", "true");
		r_config_set (cfg, "asm.comments", "false");
		r_config_set (cfg, "scr.color", "false");
	} else if (!strcmp(profile, "gas")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.lines", "false");
		r_config_set (cfg, "asm.comments", "false");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.stackptr", "false");
		r_config_set (cfg, "asm.offset", "false");
		r_config_set (cfg, "asm.flags", "true");
		r_config_set (cfg, "scr.color", "false");
	} else if (!strcmp(profile, "smart")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.stackptr", "false");
	} else if (!strcmp (profile, "graph")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "scr.color", "false");
		r_config_set (cfg, "asm.lines", "false");
		r_config_set (cfg, "asm.stackptr", "false");
		if (r_config_get (cfg, "graph.offset"))
			r_config_set (cfg, "asm.offset", "true");
		else r_config_set (cfg, "asm.offset", "false");
	} else if (!strcmp (profile, "debug")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.trace", "true");
	} else if (!strcmp (profile, "full")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.bytes", "true");
		r_config_set (cfg, "asm.lines", "true");
		r_config_set (cfg, "asm.linesout", "true");
		r_config_set (cfg, "asm.lineswide", "true");
		r_config_set (cfg, "asm.size", "true");
	} else if (!strcmp (profile, "simple")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.lines", "false");
		r_config_set (cfg, "asm.comments", "true");
		r_config_set (cfg, "anal.split", "false");
		r_config_set (cfg, "asm.flags", "false");
		r_config_set (cfg, "asm.xrefs", "false");
		r_config_set (cfg, "asm.stackptr", "false");
	}
	return R_TRUE;
}

static int cb_analplugin(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_anal_list (core->anal);
		return R_FALSE;
	} else if (!r_anal_use (core->anal, node->value)) {
		const char *aa = r_config_get (core->config, "asm.arch");
		if (!aa || strcmp (aa, node->value))
			eprintf ("anal.arch: cannot find '%s'\n", node->value);
		return R_FALSE;
	}
	return R_TRUE;
}

static int cb_analsplit(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->split = node->i_value;
	return R_TRUE;
}

static int cb_asmarch(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	const char *asmos = core->config? r_config_get (core->config, "asm.os"): NULL;
	r_egg_setup (core->egg, node->value, core->anal->bits, 0, R_SYS_OS);
	if (!r_asm_use (core->assembler, node->value))
		eprintf ("asm.arch: cannot find (%s)\n", node->value);
	{
		char asmparser[32];
		snprintf (asmparser, sizeof (asmparser), "%s.pseudo", node->value);

		r_config_set (core->config, "asm.parser", asmparser);
	}
	if (!r_config_set (core->config, "anal.arch", node->value)) {
		char *p, *s = strdup (node->value);
		p = strchr (s, '.');
		if (p) *p = 0;
		r_config_set (core->config, "anal.arch", s);
		free (s);
	}
	if (!r_syscall_setup (core->anal->syscall, node->value,
				asmos, core->anal->bits)) {
		//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
		//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
	}
	//if (!strcmp (node->value, "bf"))
	//	r_config_set (core->config, "dbg.backend", "bf");
	__setsegoff (core->config, node->value, core->assembler->bits);
	return R_TRUE;
}

static int cb_asmbits(void *user, void *data) {
	const char *asmos, *asmarch;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	int ret = r_asm_set_bits (core->assembler, node->i_value);
	if (ret == R_FALSE) {
		RAsmPlugin *h = core->assembler->cur;
		if (h) {
			eprintf ("Cannot set bits %"PFMT64d" to '%s'\n",
					node->i_value, h->name);
		} else {
			eprintf ("e asm.bits: Cannot set value, no plugins defined yet\n");
			ret = R_TRUE;
		}
	}
	if (!r_anal_set_bits (core->anal, node->i_value))
		eprintf ("asm.arch: Cannot setup '%i' bits analysis engine\n", (int)node->i_value);
	core->print->bits = node->i_value;
	if (core->dbg  && core->anal && core->anal->cur)
		r_debug_set_arch (core->dbg, core->anal->cur->arch, node->i_value);

	asmos = r_config_get (core->config, "asm.os");
	asmarch = r_config_get (core->config, "asm.arch");
	if (core && core->anal)
		if (!r_syscall_setup (core->anal->syscall, asmarch,
					asmos, node->i_value)) {
			//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
	__setsegoff (core->config, asmarch, core->anal->bits);
	return ret;
}

static int cb_asmcpu(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_asm_set_cpu (core->assembler, node->value);
	return R_TRUE;
}

static int cb_asmlineswidth(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->anal->lineswidth = node->i_value;
	return R_TRUE;
}

static int cb_asmos(void *user, void *data) {
	RCore *core = (RCore*) user;
	int asmbits = r_config_get_i (core->config, "asm.bits");
	RConfigNode *asmarch = r_config_node_get (core->config, "asm.arch");
	RConfigNode *node = (RConfigNode*) data;
	if (asmarch) {
		r_syscall_setup (core->anal->syscall, asmarch->value,
				node->value, core->anal->bits);
		__setsegoff (core->config, asmarch->value, asmbits);
	}
	//if (!ret) eprintf ("asm.os: Cannot setup syscall os/arch for '%s'\n", node->value);
	return R_TRUE;
}

static int cb_asmparser(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX this is wrong? snprintf(buf, 127, "parse_%s", node->value),
	return r_parse_use (core->parser, node->value);
	// TODO: control error and restore old value (return false?) show errormsg?
	//return R_TRUE;
}

static int cb_asmprofile(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	return asm_profile (core->config, node->value);
}

static int cb_asmsyntax(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "intel"))
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
	else if (!strcmp (node->value, "att"))
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_ATT);
	else return R_FALSE;
	return R_TRUE;
}

static int cb_bigendian(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->assembler->big_endian = node->i_value;
	core->anal->big_endian = node->i_value;
	core->print->big_endian = node->i_value;
	return R_TRUE;
}

static int cb_cfgdatefmt(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	strncpy (core->print->datefmt, node->value, 32);
	return R_TRUE;
}

static int cb_cfgdebug(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!core) return R_FALSE;
	if (core->io)
		core->io->debug = node->i_value;
	if (core->dbg && node->i_value) {
		const char *dbgbackend = r_config_get (core->config, "dbg.backend");
		r_debug_use (core->dbg, dbgbackend);
		if (!strcmp (dbgbackend, "bf"))
			r_config_set (core->config, "asm.arch", "bf");
		if (core->file) {
			r_debug_select (core->dbg, core->file->fd->fd,
					core->file->fd->fd);
		}
	} else r_debug_use (core->dbg, NULL);
	return R_TRUE;
}

static int cb_cfgsanbox(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	int ret = r_sandbox_enable (node->i_value);
	return (!node->i_value && ret)? 0: 1;
}

static int cb_cmdrepeat(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cmdrepeat = node->i_value;
	return R_TRUE;
}

static int cb_scrnull(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->null = node->i_value;
	return R_TRUE;
}

static int cb_color(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOR;
	} else {
		//c:core->print->flags ^= R_PRINT_FLAGS_COLOR;
		core->print->flags &= (~R_PRINT_FLAGS_COLOR);
	}
	r_print_set_flags (core->print, core->print->flags);
	return R_TRUE;
}

static int cb_dbgbackend(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX: remove this spagetti
	if (!strcmp (node->value, "bf"))
		r_config_set (core->config, "asm.arch", "bf");
	r_debug_use (core->dbg, node->value);
	return R_TRUE;
}

static int cb_fixrows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_rows = node->i_value;
	return R_TRUE;
}

static int cb_fixcolumns(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_columns = node->i_value;
	return R_TRUE;
}

static int cb_rows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->force_rows = node->i_value;
	return R_TRUE;
}

static int cb_fsview(void *user, void *data) {
	int type = R_FS_VIEW_NORMAL;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (!strcmp (node->value, "?")) {
		eprintf ("Values: all|deleted|special\n");
		return R_FALSE;
	}
	if (!strcmp (node->value, "all"))
		type = R_FS_VIEW_ALL;
	if (!strstr (node->value, "del"))
		type |= R_FS_VIEW_DELETED;
	if (!strstr (node->value, "spe"))
		type |= R_FS_VIEW_SPECIAL;
	r_fs_view (core->fs, type);
	return R_TRUE;
}

static int cb_cmddepth(void *user, void *data) {
	int c = R_MAX (((RConfigNode*)data)->i_value, 0);
	((RCore *)user)->cmd_depth = c;
	return R_TRUE;
}

static int cb_hexcols(void *user, void *data) {
	int c = R_MIN (128, R_MAX (((RConfigNode*)data)->i_value, 0));
	((RCore *)user)->print->cols = c & ~1;
	return R_TRUE;
}

static int cb_hexstride(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	((RCore *)user)->print->stride = node->i_value;
	return R_TRUE;
}

static int cb_iobuffer(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		ut64 from, to;
		from = r_config_get_i (core->config, "io.buffer.from");
		to = r_config_get_i (core->config, "io.buffer.to");
		if (from>=to) {
			eprintf ("ERROR: io.buffer.from >= io.buffer.to"
					" (0x%"PFMT64x" >= 0x%"PFMT64x")\n", from, to);
		} else r_io_buffer_load (core->io, from, (int)(to-from));
	} else r_io_buffer_close (core->io);
	r_core_block_read (core, 0);
	return R_TRUE;
}

static int cb_iocache(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_io_cache_enable (core->io, node->i_value, node->i_value);
	return R_TRUE;
}

static int cb_iova(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value != core->io->va) {
		core->io->va = node->i_value;
		r_core_block_read (core, 0);
		// reload symbol information
		if (r_list_length (r_bin_get_sections (core->bin))>0)
			r_core_cmd0 (core, ".ia*");
	}
	return R_TRUE;
}

static int cb_iozeromap(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->zeromap = node->i_value;
	return R_TRUE;
}

static int cb_ioffio(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->ffio = node->i_value;
	return R_TRUE;
}

static int cb_pager(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	/* Let cons know we have a new pager. */
	core->cons->pager = node->value;
	return R_TRUE;
}

static int cb_rgbcolors(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	RCore *core = (RCore *) user;
	if (node->i_value) {
		r_cons_singleton()->truecolor =
			(r_config_get_i (core->config, "scr.truecolor"))?2:1;
	} else {
		r_cons_singleton()->truecolor = 0;
	}
	return R_TRUE;
}

static int cb_scrcolumns(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_columns = n;
	return R_TRUE;
}

static int cb_scrfgets(void* user, void* data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value) 
		core->cons->user_fgets = NULL;
	else core->cons->user_fgets = (void *)r_core_fgets;
	return R_TRUE;
}

static int cb_scrhtml(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->is_html = node->i_value;
	// TODO: control error and restore old value (return false?) show errormsg?
	return R_TRUE;
}

static int cb_scrint(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->is_interactive = node->i_value;
	return R_TRUE;
}

static int cb_scrnkey(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		r_cons_printf ("scr.nkey = fun, hit, flag\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int cb_scrprompt(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_line_singleton()->echo = node->i_value;
	return R_TRUE;
}

static int cb_scrrows(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_rows = n;
	return R_TRUE;
}

static int cb_searchalign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return R_TRUE;
}

static int cb_segoff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value)
		core->print->flags |= R_PRINT_FLAGS_SEGOFF;
	else core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SEGOFF));
	return R_TRUE;
}


static int cb_stopthreads(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->stop_all_threads = node->i_value;
	return R_TRUE;
}

static int cb_swstep(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->swstep = node->i_value;
	return R_TRUE;
}

static int cb_teefile(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->teefile = node->value;
	return R_TRUE;
}

static int cb_trace(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->enabled = node->i_value;
	return R_TRUE;
}

static int cb_tracetag(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->tag = node->i_value;
	return R_TRUE;
}

static int cb_truecolor(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (r_cons_singleton()->truecolor)
		r_cons_singleton()->truecolor = (node->i_value)? 2: 1;
	return R_TRUE;
}

static int cb_utf8(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->utf8 = node->i_value;
	return R_TRUE;
}

static int cb_zoombyte(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	switch (*node->value) {
		case 'p': case 'f': case 's': case '0':
		case 'F': case 'e': case 'h':
			core->print->zoom->mode = *node->value;
			break;
		default:
			eprintf ("Invalid zoom.byte value. See pz? for help\n");
			return R_FALSE;
	}
	return R_TRUE;
}

static int cb_binminstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		if (v<1) v = 4; // HACK
		core->bin->minstrlen = v;
	// TODO: Do not refresh if nothing changed (minstrlen ?)
		r_core_bin_refresh_strings (core);
		return R_TRUE;
	}
	return R_TRUE;
}

#define SLURP_LIMIT (10*1024*1024)
R_API int r_core_config_init(RCore *core) {
	int i;
	char buf[128], *p, *tmpdir;
	RConfig *cfg = cfg = core->config = r_config_new (core);
	cfg->printf = r_cons_printf;
	cfg->num = core->num;

	/* anal */
	SETI("anal.depth", 50, "Max depth at code analysis"); // XXX: warn if depth is > 50 .. can be problematic
	SETPREF("anal.hasnext", "true", "Continue analysis after each function");
	SETCB("anal.arch", R_SYS_ARCH, &cb_analplugin, "Specify the anal.arch to use");
	SETPREF("anal.prelude", "", "Specify an hexpair to find preludes in code");
	SETCB("anal.split", "true", &cb_analsplit, "Split functions into basic blocks in analysis.");
	SETI("anal.ptrdepth", 3, "Maximum number of nested pointers to follow in analysis");

	/* asm */
	//asm.os needs to be first, since other asm.* depend on it
	SETCB("asm.os", R_SYS_OS, &cb_asmos, "Select operating system (kernel) (linux, darwin, w32,..)");
	SETPREF("asm.bytes", "true",  "Display the bytes of each instruction");
	SETPREF("asm.cmtflgrefs", "true", "Show comment flags associated to branch referece");
	SETPREF("asm.cmtright", "false", "Show comments at right of disassembly if they fit in screen");
	SETPREF("asm.comments", "true", "Show comments in disassembly view");
	SETPREF("asm.decode", "false", "Use code analysis as a disassembler");
	SETPREF("asm.dwarf", "false", "Show dwarf comment at disassembly");
	SETPREF("asm.esil", "false", "Show ESIL instead of mnemonic");
	SETPREF("asm.filter", "true", "Replace numbers in disassembly using flags containing a dot in the name in disassembly");
	SETPREF("asm.flags", "true", "Show flags");
	SETPREF("asm.lbytes", "true", "Align disasm bytes to left");
	SETPREF("asm.lines", "true", "If enabled show ascii-art lines at disassembly");
	SETPREF("asm.linescall", "false", "Enable call lines");
	SETPREF("asm.linesout", "true", "If enabled show out of block lines");
	SETPREF("asm.linesright", "false", "If enabled show lines before opcode instead of offset");
	SETPREF("asm.linesstyle", "false", "If enabled iterate the jump list backwards");
	SETPREF("asm.lineswide", "false", "If enabled put an space between lines");
	SETPREF("asm.middle", "false", "Allow disassembling jumps in the middle of an instruction");
	SETPREF("asm.offset", "true", "Show offsets at disassembly");
	SETPREF("asm.pseudo", "false", "Enable pseudo syntax"); // DEPRECATED ?
	SETPREF("asm.size", "false", "Show size of opcodes in disassembly (pd)");
	SETPREF("asm.stackptr", "false", "Show stack pointer at disassembly");
	SETI("asm.tabs", 0, "Use tabs in disassembly");
	SETPREF("asm.trace", "true", "Show execution traces for each opcode");
	SETPREF("asm.ucase", "false", "Use uppercase syntax at disassembly");
	SETPREF("asm.varsub", "true", "Substitute variables in disassembly");
	SETCB("asm.arch", R_SYS_ARCH, &cb_asmarch, "Set the arch to be usedd by asm");
	SETCB("asm.cpu", R_SYS_ARCH, &cb_asmcpu, "Set the kind of asm.arch cpu");
	SETCB("asm.parser", "x86.pseudo", &cb_asmparser, "Set the asm parser to use");
	SETCB("asm.profile", "default", &cb_asmprofile, "configure disassembler (default, simple, gas, smart, debug, full)");
	SETCB("asm.segoff", "false", &cb_segoff, "Show segmented address in prompt (x86-16)");
	SETCB("asm.syntax", "intel", &cb_asmsyntax, "Select assembly syntax");
	SETI("asm.nbytes", 6, "Number of bytes for each opcode at disassembly");
	SETICB("asm.bits", 32, &cb_asmbits, "Word size in bits at assembler");
	SETICB("asm.lineswidth", 7, &cb_asmlineswidth, "Number of columns for program flow arrows");
	SETPREF("asm.functions", "true", "Show functions in disassembly");
	SETPREF("asm.xrefs", "true", "Show xrefs in disassembly");
#if 0
	r_config_set (cfg, "asm.offseg", "false");
	r_config_desc (cfg, "asm.offseg", "Show offsets as in 16 bit segment addressing mode");
#endif

	/* bin */
	SETI("bin.baddr", 0, "Set base address for loading binaries ('o')");
	SETPREF("bin.dwarf", "false", "Load dwarf information on startup if available");
	SETICB("bin.minstr", 0, &cb_binminstr, "Minimum string length for r_bin");
	SETPREF("bin.rawstr", "false", "Load strings from raw binaries");
	SETPREF("bin.strings", "true", "Load strings from rbin on startup");

	/* cfg */
#if LIL_ENDIAN
	r_config_set_cb (cfg, "cfg.bigendian", "false", &cb_bigendian);
#else
	r_config_set_cb (cfg, "cfg.bigendian", "true", &cb_bigendian);
#endif
	r_config_desc (cfg, "cfg.bigendian", "Use little (false) or big (true) endiannes");
	SETCB("cfg.datefmt", "%d:%m:%Y %H:%M:%S %z", &cb_cfgdatefmt, "Date format (%d:%m:%Y %H:%M:%S %z)");
	SETCB("cfg.debug", "false", &cb_cfgdebug, "set/unset the debugger mode");
	p = r_sys_getenv ("EDITOR");
#if __WINDOWS__
	r_config_set (cfg, "cfg.editor", p? p: "notepad");
#else
	r_config_set (cfg, "cfg.editor", p? p: "vi");
#endif
	free (p);
	r_config_desc (cfg, "cfg.editor", "Select default editor program");
	SETPREF("cfg.fortunes", "true", "If enabled show tips at start");
	SETI("cfg.hashlimit", SLURP_LIMIT, "If the file its bigger than hashlimit don't calculate the hash");
	SETCB("cfg.sandbox", "false", &cb_cfgsanbox, "Sandbox mode disables systems and open on upper directories");
	SETPREF("cfg.wseek", "false", "Seek after write");

	/* diff */
	SETI("diff.from", 0, "Set source diffing address for px (uses cc command)");
	SETI("diff.to", 0, "Set destination diffing address for px (uses cc command)");

	/* dir */
	SETPREF("dir.magic", R_MAGIC_PATH, "Path to r_magic files");
	SETPREF("dir.plugins", R2_LIBDIR"/radare2/"R2_VERSION"/", "Path to plugin files to be loaded at startup");
	SETPREF("dir.source", "", "Path to find source files");
	SETPREF("dir.types", "/usr/include", "Default path to look for cparse type files");
	SETPREF("dir.projects", "~/"R2_HOMEDIR"/rdb", "Default path for projects");

	/* debug */
	SETCB("dbg.backend", "native", &cb_dbgbackend, "Select the debugger backend");
	SETPREF("dbg.bep", "loader", "break on entrypoint (loader, entry, constructor, main)");
	if (core->cons->rows>30) // HACKY
		r_config_set_i (cfg, "dbg.follow", 64);
	else r_config_set_i (cfg, "dbg.follow", 32);
	r_config_desc (cfg, "dbg.follow", "Follow program counter when pc > core->offset + dbg.follow");
	SETCB("dbg.stopthreads", "true", &cb_stopthreads, "Stop all threads when debugger breaks");
	SETCB("dbg.swstep", "false", &cb_swstep, "If enabled forces the use of software steps (code analysis+breakpoint)");
	SETCB("dbg.trace", "false", &cb_trace, "Trace program execution (see asm.trace)");
	SETCB("dbg.trace.tag", "0xff", &cb_tracetag, "Set trace tag");

	/* cmd */
	if (r_file_exists ("/usr/bin/xdot"))
		r_config_set (cfg, "cmd.graph", "!xdot a.dot");
	else
		if (r_file_exists ("/usr/bin/open"))
			r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!open a.gif");
		else
			if (r_file_exists ("/usr/bin/gqview"))
				r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!gqview a.gif");
			else
				if (r_file_exists ("/usr/bin/eog"))
					r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!eog a.gif");
				else
					if (r_file_exists ("/usr/bin/xdg-open"))
						r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!xdg-open a.gif");
					else
						r_config_set (cfg, "cmd.graph", "?e cannot find a valid picture viewer");
	r_config_desc (cfg, "cmd.graph", "Command executed by 'agv' command to view graphs");
	SETICB("cmd.depth", 10, &cb_cmddepth, "Maximum command depth");
	SETPREF("cmd.bp", "", "Command to executed every breakpoint hit");
	SETPREF("cmd.cprompt", "", "Column visual prompt commands");
	SETPREF("cmd.hit", "", "Command to execute on every search hit");
	SETPREF("cmd.open", "", "Command executed when file its opened");
	SETPREF("cmd.prompt", "", "Prompt commands");
	SETCB("cmd.repeat", "true", &cb_cmdrepeat, "Alias newline (empty command) as '..'");
	SETPREF("cmd.visual", "", "Replace current print mode");
	SETPREF("cmd.vprompt", "", "Visual prompt commands");

	/* filesystem */
	SETCB("fs.view", "normal", &cb_fsview, "Set visibility options for filesystems");

	/* hexdump */
	SETICB("hex.cols", 16, &cb_hexcols, "Configure the number of columns in hexdump");
	SETICB("hex.stride", 0, &cb_hexstride, "Define the line stride in hexdump (default is 0)");

	/* http */
	SETPREF("http.allow", "", "http firewall. only accept clients from the comma separated IP list");
#if __WINDOWS__
	r_config_set (cfg, "http.browser", "start");
#else
	if (r_file_exists ("/usr/bin/openURL")) // iOS ericautils
		r_config_set (cfg, "http.browser", "/usr/bin/openURL");
	else if (r_file_exists ("/system/bin/toolbox"))
		r_config_set (cfg, "http.browser",
				"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d");
	else if (r_file_exists ("/usr/bin/xdg-open"))
		r_config_set (cfg, "http.browser", "xdg-open");
	else if (r_file_exists ("/usr/bin/open"))
		r_config_set (cfg, "http.browser", "open");
	else r_config_set (cfg, "http.browser", "firefox");
	r_config_desc (cfg, "http.browser", "command to open http urls");
#endif
	SETI("http.maxsize", 0, "Define maximum file size to upload");
	SETPREF("http.public", "false", "Set to true to listen on 0.0.0.0");
	SETPREF("http.root", R2_WWWROOT, "Http root directory");
	SETPREF("http.port", "9090", "Port to listen for http connections");
	SETPREF("http.sandbox", "false", "Sandbox the http");
	SETI("http.timeout", 3, "Disconnect clients after N seconds if no data sent");
	SETPREF("http.upget", "false", "/up/ can be GET, not only POST");
	SETPREF("http.upload", "false", "Dnable file POST uploads in /up/<filename>");
	SETPREF("http.uri", "", "Base uri to remote host proxy host");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc(cfg, "http.uproot", "Path to store uploaded files");

	/* graph */
	SETPREF("graph.font", "Courier", "Font to be used by the dot graphs");
	SETPREF("graph.offset", "false", "Show offsets in graphs");

	/* hud */
	SETPREF("hud.once", "false", "Run the HUD one");

	/* scr */
#if __EMSCRIPTEN__
	r_config_set_cb (cfg, "scr.fgets", "true", cb_scrfgets);
#else
	r_config_set_cb (cfg, "scr.fgets", "false", cb_scrfgets);
#endif
	r_config_desc (cfg, "scr.fgets", "Use fgets instead of dietline for prompt input");
	SETPREF("scr.colorops", "true", "Colorize in numbers/registers in opcodes");
	SETI("scr.colpos", 80, "Column position of cmd.cprompt in visual");
	SETICB("scr.columns", 0, &cb_scrcolumns, "Set the columns number");
	SETICB("scr.rows", 0, &cb_rows, "Force specific console rows (height)");
	SETICB("scr.fix_rows", 0, &cb_fixrows, "Workaround for Linux TTY");
	SETICB("scr.fix_columns", 0, &cb_fixcolumns, "Workaround for Prompt iOS ssh client");
	SETCB("scr.interactive", "true", &cb_scrint, "Start in interractive mode");
	SETCB("scr.html", "false", &cb_scrhtml, "If enabled disassembly uses HTML syntax");
	SETCB("scr.nkey", "hit", &cb_scrnkey, "Select the seek mode in visual");
	SETCB("scr.pager", "", &cb_pager, "Select pager program (used if output doesn't fit on window)");
	SETPREF("scr.pipecolor", "false", "Enable colors when using pipes if true");
	SETCB("scr.prompt", "true", &cb_scrprompt, "Show/hide user prompt (used by r2 -q)");
	SETCB("scr.rows", "0", &cb_scrrows, "Set the rows number");
	SETCB("scr.tee", "", &cb_teefile, "Pipe console output to file if not empty");
	SETPREF("scr.seek", "", "Seek to the specified address on startup");
#if __WINDOWS__
	r_config_set_cb (cfg, "scr.rgbcolor", "false", &cb_rgbcolors);
#else
	r_config_set_cb (cfg, "scr.rgbcolor", "true", &cb_rgbcolors);
#endif
	r_config_desc (cfg, "scr.rgbcolor", "Use RGB colors (no available on windows)");
	SETCB("scr.truecolor", "false", &cb_truecolor, "Manage color palette (0: ansi 16, 1: 256, 2: 16M)");
	SETCB("scr.color", (core->print->flags&R_PRINT_FLAGS_COLOR)?"true":"false", &cb_color, "Enable/Disable colors");
	SETCB("scr.null", "false", &cb_scrnull, "if set shows no output (disable console)");
#if 0
	{
		const char *val;
		char *sval = r_sys_getenv ("LC_CTYPE");
		r_str_case (sval, 0);
		val = strcmp (sval, "utf-8")? "false": "true";
		free (sval);
		r_config_set_cb (cfg, "scr.utf8", val, &cb_utf8);
	}
#else
	SETCB("scr.utf8", "false", &cb_utf8, "Show UTF-8 characters instead of ANSI");
#endif

	/* search */
	SETICB("search.align", 0, &cb_searchalign, "Only catch aligned search hits");
	SETI("search.count", 0, "Start index number at search hits");
	SETI("search.distance", 0, "Search string distance");
	SETPREF("search.flags", "true", "If enabled all search results are flagged, else just printed r2 commands");
	SETI("search.from", -1, "Search start address");
	SETPREF("search.in", "file", "Specify search boundaries (raw, block, file, section)");
	SETI("search.kwidx", 0, "Store last search index count");
	SETPREF("search.prefix", "hit", "Prefix name in search hits label");
	SETPREF("search.show", "true", "Show search results while found (disable if lot of hits)");
	SETI("search.to", -1, "Search end address");

	/* io */
	SETCB("io.buffer", "false", &cb_iobuffer, "Load and use buffer cache if enabled");
	SETI("io.buffer.from", 0, "Lower address of buffered cache");
	SETI("io.buffer.to", 0, "Higher address of buffered cache");
	SETCB("io.cache", "false", &cb_iocache, "Enable cache for io changes");
	SETCB("io.ffio", "true", &cb_ioffio, "Fill invalid buffers with 0xff instead of returning error");
	SETCB("io.va", "true", &cb_iova, "If enabled virtual address layout can be used");
	SETCB("io.zeromap", "0", &cb_iozeromap, "Double map the last opened file to address zero");

	/* file */
	SETPREF("file.analyze", "false", "Analyze file on load. Same as r2 -c aa ..");
	SETPREF("file.desc", "", "User defined file description. Used by projects");
	SETPREF("file.md5", "", "md5 sum of current file");
	SETPREF("file.path", "", "Path of current file");
	SETPREF("file.project", "", "Name of current project");
	SETPREF("file.sha1", "", "sha1 hash of current file");
	SETPREF("file.type", "", "Type of current file");

	/* magic */
	SETI("magic.depth", 100, "Recursivity depth in magic description strings");

	/* rap */
	SETPREF("rap.loop", "true", "Run rap as a forever-listening daemon");

	/* nkeys */
	for (i=1; i<13; i++) {
		snprintf (buf, sizeof (buf), "key.f%d", i);
		snprintf (buf+10, sizeof (buf)-10,
				"Run this when F%d key is pressed in visual mode", i);
		switch (i) {
			case 2: p = "dbs $$"; break;
			case 7: p = "ds"; break;
			case 8: p = "dso"; break;
			case 9: p = "dc"; break;
			default: p = ""; break;
		}
		r_config_set (cfg, buf, p);
		r_config_desc (cfg, buf, buf+10);
	}

	/* zoom */
	SETCB("zoom.byte", "h", &cb_zoombyte, "Zoom callback to calculate each byte (See pz? for help)");
	SETI("zoom.from", 0, "Zoom start address");
	SETI("zoom.maxsz", 512, "Zoom max size of block");
	SETI("zoom.to", 0, "Zoom end address");

	r_config_lock (cfg, R_TRUE);
	return R_TRUE;
}
