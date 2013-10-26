/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_core.h>

static int config_scrfgets_callback(void* user, void* data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value) 
		core->cons->user_fgets = NULL;
	else core->cons->user_fgets = (void *)r_core_fgets;
	return R_TRUE;
}

static int config_scrcolumns_callback(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_columns = n;
	return R_TRUE;
}

static int config_scrrows_callback(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_rows = n;
	return R_TRUE;
}

static int config_cfgsandbox_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	int ret = r_sandbox_enable (node->i_value);
	return (!node->i_value && ret)? 0: 1;
}

static int config_scrnkey_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		r_cons_printf ("scr.nkey = fun, hit, flag\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int config_hexstride_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	((RCore *)user)->print->stride = node->i_value;
	return R_TRUE;
}

static int config_hexcols_callback(void *user, void *data) {
	int c = R_MIN (128, R_MAX (((RConfigNode*)data)->i_value, 0));
	((RCore *)user)->print->cols = c & ~1;
	return R_TRUE;
}

static int config_heightfix_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->heightfix = node->i_value;
	return R_TRUE;
}
static int config_widthfix_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->widthfix = node->i_value;
	return R_TRUE;
}

static int config_scrhtml_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->is_html = node->i_value;
// TODO: control error and restore old value (return false?) show errormsg?
	return R_TRUE;
}

static int config_searchalign_callback(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return R_TRUE;
}

static int config_iobuffer_callback(void *user, void *data) {
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

static int config_iozeromap_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->zeromap = node->i_value;
	return R_TRUE;
}

static int config_ioffio_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->ffio = node->i_value;
	return R_TRUE;
}

static int config_bigendian_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->assembler->big_endian = node->i_value;
	core->anal->big_endian = node->i_value;
	core->print->big_endian = node->i_value;
	return R_TRUE;
}

static int config_iova_callback(void *user, void *data) {
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

static int config_zoombyte_callback(void *user, void *data) {
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

static int config_iocache_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_io_cache_enable (core->io, node->i_value, node->i_value);
	return R_TRUE;
}

static int config_dbgbackend_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX: remove this spagetti
	if (!strcmp (node->value, "bf"))
		r_config_set (core->config, "asm.arch", "bf");
	r_debug_use (core->dbg, node->value);
	return R_TRUE;
}

static int config_cfgdebug_callback(void *user, void *data) {
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

static int config_cfgdatefmt_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	strncpy (core->print->datefmt, node->value, 32);
	return R_TRUE;
}

static int config_analplugin_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_anal_list (core->anal);
		return R_FALSE;
	} else if (!r_anal_use (core->anal, node->value)) {
		const char *aa = r_config_get (core->config, "asm.arch");
		if (!aa || strcmp (aa, node->value))
			eprintf ("anal.plugin: cannot find '%s'\n", node->value);
		return R_FALSE;
	}
	return R_TRUE;
}

static int config_analsplit_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->split = node->i_value;
	return R_TRUE;
}

static inline void __setsegoff(RConfig *cfg, const char *asmarch, int asmbits) {
	if (!strcmp (asmarch, "x86"))
		r_config_set_i (cfg, "asm.segoff", (asmbits==16)?1:0);
}

static int config_asmos_callback(void *user, void *data) {
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

static int config_asmsyntax_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "intel"))
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
	else if (!strcmp (node->value, "att"))
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_ATT);
	else return R_FALSE;
	return R_TRUE;
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

static int config_asmprofile_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	return asm_profile (core->config, node->value);
}

static int config_stopthreads_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->stop_all_threads = node->i_value;
	return R_TRUE;
}

static int config_trace_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->enabled = node->i_value;
	return R_TRUE;
}

static int config_tracetag_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->tag = node->i_value;
	return R_TRUE;
}

static int config_cmdrepeat_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cmdrepeat = node->i_value;
	return R_TRUE;
}

static int config_fsview_callback(void *user, void *data) {
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

static int config_scrprompt_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_line_singleton()->echo = node->i_value;
	return R_TRUE;
}

static int config_scrint_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->is_interactive = node->i_value;
	return R_TRUE;
}

static int config_teefile_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->teefile = node->value;
	return R_TRUE;
}

static int config_swstep_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->swstep = node->i_value;
	return R_TRUE;
}

static int config_segoff_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value)
		core->print->flags |= R_PRINT_FLAGS_SEGOFF;
	else core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SEGOFF));
	return R_TRUE;
}

static int config_asmlineswidth_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->anal->lineswidth = node->i_value;
	return R_TRUE;
}

static int config_asmcpu_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_asm_set_cpu (core->assembler, node->value);
	return R_TRUE;
}

static int config_asmarch_callback(void *user, void *data) {
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
	if (!r_config_set (core->config, "anal.plugin", node->value)) {
		char *p, *s = strdup (node->value);
		p = strchr (s, '.');
		if (p) *p = 0;
		r_config_set (core->config, "anal.plugin", s);
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

static int config_asmparser_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX this is wrong? snprintf(buf, 127, "parse_%s", node->value),
	return r_parse_use (core->parser, node->value);
	// TODO: control error and restore old value (return false?) show errormsg?
	//return R_TRUE;
}

static int config_asmbits_callback(void *user, void *data) {
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

static int config_rgbcolor_callback(void *user, void *data) {
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

static int config_truecolor_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (r_cons_singleton()->truecolor)
		r_cons_singleton()->truecolor = (node->i_value)? 2: 1;
	return R_TRUE;
}

static int config_color_callback(void *user, void *data) {
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

static int config_pager_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	/* Let cons know we have a new pager. */
	core->cons->pager = node->value;
	return R_TRUE;
}

static int config_utf8_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->utf8 = node->i_value;
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
	r_config_set_i (cfg, "anal.depth", 50)->desc = strdup("Max depth at code analysis"); // XXX: warn if depth is > 50 .. can be problematic
	r_config_set (cfg, "anal.hasnext", "true")->desc = strdup("Continue analysis after each function");
	r_config_set_cb (cfg, "anal.plugin", R_SYS_ARCH, &config_analplugin_callback)->desc = strdup("Specify the anal plugin to use");
	r_config_set (cfg, "anal.prelude", "")->desc = strdup("Specify an hexpair to find preludes in code");
	r_config_set_cb (cfg, "anal.split", "true", &config_analsplit_callback)->desc = strdup("Split functions into basic blocks in analysis.");
	r_config_set_i (cfg, "anal.ptrdepth", 3)->desc = strdup("Maximum number of nested pointers to follow in analysis");

	/* asm */
    //asm.os needs to be first, since other asm.* depend on it
	r_config_set_cb (cfg, "asm.os", R_SYS_OS, &config_asmos_callback)->desc = strdup("Select operating system (kernel) (linux, darwin, w32,..)");
	r_config_set (cfg, "asm.bytes", "true")->desc = strdup( "Display the bytes of each instruction");
	r_config_set (cfg, "asm.cmtflgrefs", "true")->desc = strdup("Show comment flags associated to branch referece");
	r_config_set (cfg, "asm.cmtright", "false")->desc = strdup("Show comments at right of disassembly if they fit in screen");
	r_config_set (cfg, "asm.comments", "true")->desc = strdup("Show comments in disassembly view");
	r_config_set (cfg, "asm.decode", "false")->desc = strdup("Use code analysis as a disassembler");
	r_config_set (cfg, "asm.dwarf", "false")->desc = strdup("Show dwarf comment at disassembly");
	r_config_set (cfg, "asm.filter", "true")->desc = strdup("Replace numbers in disassembly using flags containing a dot in the name in disassembly");
	r_config_set (cfg, "asm.flags", "true")->desc = strdup("Show flags");
	r_config_set (cfg, "asm.lbytes", "true")->desc = strdup("Align disasm bytes to left");
	r_config_set (cfg, "asm.lines", "true")->desc = strdup("If enabled show ascii-art lines at disassembly");
	r_config_set (cfg, "asm.linescall", "false")->desc = strdup("Enable call lines");
	r_config_set (cfg, "asm.linesout", "true")->desc = strdup("If enabled show out of block lines");
	r_config_set (cfg, "asm.linesright", "false")->desc = strdup("If enabled show lines before opcode instead of offset");
	r_config_set (cfg, "asm.linesstyle", "false")->desc = strdup("If enabled iterate the jump list backwards");
	r_config_set (cfg, "asm.lineswide", "false")->desc = strdup("If enabled put an space between lines");
	r_config_set (cfg, "asm.middle", "false")->desc = strdup("Allow disassembling jumps in the middle of an instruction");
	r_config_set (cfg, "asm.offset", "true")->desc = strdup("Show offsets at disassembly");
	r_config_set (cfg, "asm.pseudo", "false")->desc = strdup("Enable pseudo syntax"); // DEPRECATED ?
	r_config_set (cfg, "asm.size", "false")->desc = strdup("Show size of opcodes in disassembly (pd)");
	r_config_set (cfg, "asm.stackptr", "false")->desc = strdup("Show stack pointer at disassembly");
	r_config_set (cfg, "asm.tabs", "false")->desc = strdup("Use tabs in disassembly");
	r_config_set (cfg, "asm.trace", "true")->desc = strdup("Show execution traces for each opcode");
	r_config_set (cfg, "asm.ucase", "false")->desc = strdup("Use uppercase syntax at disassembly");
	r_config_set (cfg, "asm.varsub", "true")->desc = strdup("Substitute variables in disassembly");
	r_config_set_cb (cfg, "asm.arch", R_SYS_ARCH, &config_asmarch_callback)->desc = strdup("Set the arch to be usedd by asm");
	r_config_set_cb (cfg, "asm.cpu", R_SYS_ARCH, &config_asmcpu_callback)->desc = strdup("Set the kind of asm.arch cpu");
	r_config_set_cb (cfg, "asm.parser", "x86.pseudo", &config_asmparser_callback);
	r_config_set_cb (cfg, "asm.profile", "default", &config_asmprofile_callback)->desc = strdup("configure disassembler (default, simple, gas, smart, debug, full)");
	r_config_set_cb (cfg, "asm.segoff", "false", &config_segoff_callback)->desc = strdup("Show segmented address in prompt (x86-16)");
	r_config_set_cb (cfg, "asm.syntax", "intel", &config_asmsyntax_callback)->desc = strdup("Select assembly syntax");
	r_config_set_i (cfg, "asm.nbytes", 8)->desc = strdup("Number of bytes for each opcode at disassembly");
	r_config_set_i_cb (cfg, "asm.bits", 32, &config_asmbits_callback)->desc = strdup("Word size in bits at assembler");
	r_config_set_i_cb (cfg, "asm.lineswidth", 10, &config_asmlineswidth_callback)->desc = strdup("Number of columns for program flow arrows");
	r_parse_use (core->parser, "x86.pseudo"); // XXX: not portable
    r_config_set (cfg, "asm.functions", "true")->desc = strdup("Show functions in disassembly");
    r_config_set (cfg, "asm.xrefs", "true")->desc = strdup("Show xrefs in disassembly");
#if 0
	r_config_set (cfg, "asm.offseg", "false");
	r_config_desc (cfg, "asm.offseg", "Show offsets as in 16 bit segment addressing mode");
#endif

	/* bin */
	r_config_set (cfg, "bin.dwarf", "false")->desc = strdup("Load dwarf information on startup if available");
	r_config_set_i (cfg, "bin.minstr", 0)->desc = strdup("Minimum string length for r_bin");
	r_config_set (cfg, "bin.rawstr", "false")->desc = strdup("Load strings from raw binaries");
	r_config_set (cfg, "bin.strings", "true")->desc = strdup("Load strings from rbin on startup");

	/* cfg */
#if LIL_ENDIAN
	r_config_set_cb (cfg, "cfg.bigendian", "false", &config_bigendian_callback);
#else
	r_config_set_cb (cfg, "cfg.bigendian", "true", &config_bigendian_callback);
#endif
	r_config_desc (cfg, "cfg.bigendian", "Use little (false) or big (true) endiannes");
	r_config_set_cb (cfg, "cfg.datefmt", "%d:%m:%Y %H:%M:%S %z", &config_cfgdatefmt_callback)->desc = strdup("Date format (%d:%m:%Y %H:%M:%S %z)");
	r_config_set_cb (cfg, "cfg.debug", "false", &config_cfgdebug_callback)->desc = strdup("set/unset the debugger mode");
	p = r_sys_getenv ("EDITOR");
#if __WINDOWS__
	r_config_set (cfg, "cfg.editor", p? p: "notepad");
#else
	r_config_set (cfg, "cfg.editor", p? p: "vi");
#endif
	free (p);
	r_config_desc (cfg, "cfg.editor", "Select default editor program");
	r_config_set (cfg, "cfg.fortunes", "true")->desc = strdup("If enabled show tips at start");
	r_config_set_i (cfg, "cfg.hashlimit", SLURP_LIMIT)->desc = strdup("If the file its bigger than hashlimit don't calculate the hash");
	r_config_set_cb (cfg, "cfg.sandbox", "false", &config_cfgsandbox_callback)->desc = strdup("Sandbox mode disables systems and open on upper directories");
	r_config_set (cfg, "cfg.wseek", "false")->desc = strdup("Seek after write");

	/* diff */
	r_config_set_i (cfg, "diff.from", 0)->desc = strdup("Set source diffing address for px (uses cc command)");
	r_config_set_i (cfg, "diff.to", 0)->desc = strdup("Set destination diffing address for px (uses cc command)");
	
    /* dir */
	r_config_set (cfg, "dir.magic", R_MAGIC_PATH)->desc = strdup("Path to r_magic files");
	r_config_set (cfg, "dir.plugins", R2_LIBDIR"/radare2/"R2_VERSION"/")->desc = strdup("Path to plugin files to be loaded at startup");
	r_config_set (cfg, "dir.source", "")->desc = strdup("Path to find source files");
	r_config_set (cfg, "dir.types", "/usr/include")->desc = strdup("Default path to look for cparse type files");
	r_config_set (cfg, "dir.projects", R2_HOMEDIR"/rdb")->desc = strdup("Default path for projects");
	
    /* debug */
	r_config_set_cb (cfg, "dbg.backend", "native", &config_dbgbackend_callback)->desc = strdup("Select the debugger backend");
	r_config_set (cfg, "dbg.bep", "loader"); // loader, entry, constructor, mai->desc = strdup("break on entrypoint (loader, entry, constructor, main)");
	if (core->cons->rows>30) // HACKY
		r_config_set_i (cfg, "dbg.follow", 64);
	else r_config_set_i (cfg, "dbg.follow", 32);
	r_config_desc (cfg, "dbg.follow", "Follow program counter when pc > core->offset + dbg.follow");
	r_config_set_cb (cfg, "dbg.stopthreads", "true", &config_stopthreads_callback)->desc = strdup("Stop all threads when debugger breaks");
	r_config_set_cb (cfg, "dbg.swstep", "false", &config_swstep_callback)->desc = strdup("If enabled forces the use of software steps (code analysis+breakpoint)");
	r_config_set_cb (cfg, "dbg.trace", "true", &config_trace_callback)->desc = strdup("Enable debugger trace (see asm.trace)");
	r_config_set_cb (cfg, "dbg.trace.tag", "0xff", &config_tracetag_callback)->desc = strdup("Set trace tag");

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
	r_config_set (cfg, "cmd.bp", "")->desc = strdup("Command to executed every breakpoint hit");
	r_config_set (cfg, "cmd.cprompt", "")->desc = strdup("Column visual prompt commands");
	r_config_set (cfg, "cmd.hit", "")->desc = strdup("Command to execute on every search hit");
	r_config_set (cfg, "cmd.open", "")->desc = strdup("Command executed when file its opened");
	r_config_set (cfg, "cmd.prompt", "")->desc = strdup("Prompt commands");
	r_config_set_cb (cfg, "cmd.repeat", "true", &config_cmdrepeat_callback)->desc = strdup("Alias newline (empty command) as '..'");
	r_config_set (cfg, "cmd.visual", "")->desc = strdup("Replace current print mode");
	r_config_set (cfg, "cmd.vprompt", "")->desc = strdup("Visual prompt commands");

    /* filesystem */
	r_config_set_cb (cfg, "fs.view", "normal", &config_fsview_callback)->desc = strdup("Set visibility options for filesystems");

    /* hexdump */
	r_config_set_i_cb (cfg, "hex.cols", 16, &config_hexcols_callback)->desc = strdup("Configure the number of columns in hexdump");
	r_config_set_i_cb (cfg, "hex.stride", 0, &config_hexstride_callback)->desc = strdup("Define the line stride in hexdump (default is 0)");

    /* http */
	r_config_set (cfg, "http.allow", "")->desc = strdup("http firewall. only accept clients from the comma separated IP list");
#if __WINDOWS__
	r_config_set (cfg, "http.browser", "start");
#else
	if (r_file_exists ("/system/bin/toolbox"))
		r_config_set (cfg, "http.browser",
			"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d");
	else if (r_file_exists ("/usr/bin/xdg-open"))
		r_config_set (cfg, "http.browser", "xdg-open");
	else if (r_file_exists ("/usr/bin/open"))
		r_config_set (cfg, "http.browser", "open");
	else r_config_set (cfg, "http.browser", "firefox");
	r_config_desc (cfg, "http.browser", "command to open http urls");
#endif
	r_config_set_i (cfg, "http.maxsize", 0)->desc = strdup("Define maximum file size to upload");
	r_config_set (cfg, "http.public", "false")->desc = strdup("Set to true to listen on 0.0.0.0");
	r_config_set (cfg, "http.root", R2_WWWROOT)->desc = strdup("Http root directory");
	r_config_set (cfg, "http.port", "9090")->desc = strdup("Port to listen for http connections");
	r_config_set (cfg, "http.sandbox", "false")->desc = strdup("Sandbox the http");
	r_config_set_i (cfg, "http.timeout", 3)->desc = strdup("Disconnect clients after N seconds if no data sent");
	r_config_set (cfg, "http.upget", "false")->desc = strdup("/up/ can be GET, not only POST");
	r_config_set (cfg, "http.upload", "false")->desc = strdup("Dnable file POST uploads in /up/<filename>");
	r_config_set (cfg, "http.uri", "")->desc = strdup("Base uri to remote host proxy host");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc (cfg, "http.uproot", "Path to store uploaded files");

    /* graph */
	r_config_set (cfg, "graph.font", "Courier")->desc = strdup("Font to be used by the dot graphs");
	r_config_set (cfg, "graph.offset", "false")->desc = strdup("Show offsets in graphs");

    /* hud */
	r_config_set (cfg, "hud.once", "false")->desc = strdup("Run the HUD one");

    /* scr */
#if __EMSCRIPTEN__
	r_config_set_cb (cfg, "scr.fgets", "true", config_scrfgets_callback);
#else
	r_config_set_cb (cfg, "scr.fgets", "false", config_scrfgets_callback);
#endif
	r_config_desc (cfg, "scr.fgets", "Use fgets instead of dietline for prompt input");
	r_config_set (cfg, "scr.colorops", "true")->desc = strdup("Colorize in numbers/registers in opcodes");
	r_config_set_i(cfg, "scr.colpos", 80)->desc = strdup("Column position of cmd.cprompt in visual");
	r_config_set_cb (cfg, "scr.columns", "0", config_scrcolumns_callback)->desc = strdup("Set the columns number");
	r_config_set_cb (cfg, "scr.heightfix", "false", &config_heightfix_callback)->desc = strdup("Workaround for Linux TTY");
	r_config_set_cb (cfg, "scr.interactive", "true", config_scrint_callback)->desc = strdup("Start in interractive mode");
	r_config_set_cb (cfg, "scr.html", "false", &config_scrhtml_callback)->desc = strdup("If enabled disassembly uses HTML syntax");
	r_config_set_cb (cfg, "scr.nkey", "hit", &config_scrnkey_callback)->desc = strdup("Select the seek mode in visual");
	r_config_set_cb (cfg, "scr.pager", "", &config_pager_callback)->desc = strdup("Select pager program (used if output doesn't fit on window)");
	r_config_set (cfg, "scr.pipecolor", "false")->desc = strdup("Enable colors when using pipes if true");
	r_config_set_cb (cfg, "scr.prompt", "true", &config_scrprompt_callback)->desc = strdup("Show/hide user prompt (used by r2 -q)");
	r_config_set_cb (cfg, "scr.rows", "0", config_scrrows_callback)->desc = strdup("Set the rows number");
	r_config_set_cb (cfg, "scr.tee", "", config_teefile_callback)->desc = strdup("Pipe console output to file if not empty");
	r_config_set_cb (cfg, "scr.widthfix", "false", &config_widthfix_callback)->desc = strdup("Workaround for Prompt iOS ssh client");
	r_config_set (cfg, "scr.seek", "")->desc = strdup("Seek to the specified address on startup");
#if __WINDOWS__
	r_config_set_cb (cfg, "scr.rgbcolor", "false", &config_rgbcolor_callback);
#else
	r_config_set_cb (cfg, "scr.rgbcolor", "true", &config_rgbcolor_callback);
#endif
	r_config_desc (cfg, "scr.rgbcolor", "Use RGB colors (no available on windows)");
	r_config_set_cb (cfg, "scr.truecolor", "false", &config_truecolor_callback)->desc = strdup("Manage color palette (0: ansi 16, 1: 256, 2: 16M)");
	r_config_set_cb (cfg, "scr.color", (core->print->flags&R_PRINT_FLAGS_COLOR)?"true":"false", &config_color_callback)->desc = strdup("Enable/Disable colors");
#if 0
{
	const char *val;
	char *sval = r_sys_getenv ("LC_CTYPE");
	r_str_case (sval, 0);
	val = strcmp (sval, "utf-8")? "false": "true";
	free (sval);
	r_config_set_cb (cfg, "scr.utf8", val, &config_utf8_callback);
}
#else
	r_config_set_cb (cfg, "scr.utf8", "false", &config_utf8_callback)->desc = strdup("Show UTF-8 characters instead of ANSI");
#endif

    /* search */
	r_config_set_i_cb (cfg, "search.align", 0, &config_searchalign_callback)->desc = strdup("Only catch aligned search hits");
	r_config_set_i (cfg, "search.count", 0)->desc = strdup("Start index number at search hits");
	r_config_set_i (cfg, "search.distance", 0); // TODO: use i_cb here and remove code in cmd.->desc = strdup("Search string distance");
	r_config_set (cfg, "search.flags", "true")->desc = strdup("If enabled all search results are flagged, else just printed r2 commands");
	r_config_set_i (cfg, "search.from", -1)->desc = strdup("Search start address");
	r_config_set (cfg, "search.in", "file")->desc = strdup("Specify search boundaries (raw, block, file, section)");
	r_config_set_i (cfg, "search.kwidx", 0)->desc = strdup("Store last search index count");
	r_config_set (cfg, "search.prefix", "hit")->desc = strdup("Prefix name in search hits label");
	r_config_set (cfg, "search.show", "true")->desc = strdup("Show search results while found (disable if lot of hits)");
	r_config_set_i (cfg, "search.to", -1)->desc = strdup("Search end address");

    /* io */
	r_config_set_cb (cfg, "io.buffer", "false", &config_iobuffer_callback)->desc = strdup("Load and use buffer cache if enabled");
	r_config_set_i (cfg, "io.buffer.from", 0)->desc = strdup("Lower address of buffered cache");
	r_config_set_i (cfg, "io.buffer.to", 0)->desc = strdup("Higher address of buffered cache");
	r_config_set_cb (cfg, "io.cache", "false", &config_iocache_callback)->desc = strdup("Enable cache for io changes");
	r_config_set_cb (cfg, "io.ffio", "true", &config_ioffio_callback)->desc = strdup("Fill invalid buffers with 0xff instead of returning error");
	r_config_set_cb (cfg, "io.va", "true", &config_iova_callback)->desc = strdup("If enabled virtual address layout can be used");
	r_config_set_cb (cfg, "io.zeromap", "0", &config_iozeromap_callback)->desc = strdup("Double map the last opened file to address zero");

    /* file */
	r_config_set (cfg, "file.analyze", "false")->desc = strdup("Analyze file on load. Same as r2 -c aa ..");
	r_config_set (cfg, "file.desc", "")->desc = strdup("User defined file description. Used by projects");
	r_config_set (cfg, "file.md5", "")->desc = strdup("md5 sum of current file");
	r_config_set (cfg, "file.path", "")->desc = strdup("Path of current file");
	r_config_set (cfg, "file.project", "")->desc = strdup("Name of current project");
	r_config_set (cfg, "file.sha1", "")->desc = strdup("sha1 hash of current file");
	r_config_set (cfg, "file.type", "")->desc = strdup("Type of current file");

    /* magic */
	r_config_set_i (cfg, "magic.depth", 100)->desc = strdup("Recursivity depth in magic description strings");

    /* rap */
	r_config_set (cfg, "rap.loop", "true")->desc = strdup("Run rap as a forever-listening daemon");

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
	r_config_set_cb (cfg, "zoom.byte", "h", &config_zoombyte_callback)->desc = strdup("Zoom callback to calculate each byte (See pz? for help)");
	r_config_set_i (cfg, "zoom.from", 0)->desc = strdup("Zoom start address");
	r_config_set_i (cfg, "zoom.maxsz", 512)->desc = strdup("Zoom max size of block");
	r_config_set_i (cfg, "zoom.to", 0)->desc = strdup("Zoom end address");

	r_config_lock (cfg, R_TRUE);
	return R_TRUE;
}
