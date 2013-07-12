/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_core.h>
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

static int config_iomaxblk_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->blocksize_max = node->i_value;
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
	// TODO: Do a cleanup on those configurations
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
		r_config_set (cfg, "asm.flagsline", "false");
		r_config_set (cfg, "asm.section", "false");
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
		r_config_set (cfg, "asm.section", "false");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.stackptr", "false");
		r_config_set (cfg, "asm.offset", "false");
		r_config_set (cfg, "asm.flags", "true");
		r_config_set (cfg, "asm.flagsline", "true");
		r_config_set (cfg, "asm.jmpflags", "true");
		r_config_set (cfg, "scr.color", "false");
	} else if (!strcmp(profile, "smart")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.section", "false");
		r_config_set (cfg, "asm.trace", "false");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.stackptr", "false");
	} else if (!strcmp (profile, "graph")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.section", "false");
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
		r_config_set (cfg, "asm.section", "true");
		r_config_set (cfg, "asm.size", "true");
	} else if (!strcmp (profile, "simple")) {
		asm_profile (cfg, "default");
		r_config_set (cfg, "asm.bytes", "false");
		r_config_set (cfg, "asm.lines", "false");
		r_config_set (cfg, "asm.comments", "true");
		r_config_set (cfg, "anal.split", "false");
		r_config_set (cfg, "asm.flags", "false");
		r_config_set (cfg, "asm.flagsline", "true");
		r_config_set (cfg, "asm.xrefs", "false");
		r_config_set (cfg, "asm.stackptr", "false");
		r_config_set (cfg, "asm.section", "false");
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

static int config_scrsparse_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	RCore *core = (RCore *) user;
	if (node->i_value) core->print->flags |= R_PRINT_FLAGS_SPARSE;
	else core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SPARSE));
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

static int config_color_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOR;
	} else if (core->print->flags&R_PRINT_FLAGS_COLOR)
		core->print->flags ^= R_PRINT_FLAGS_COLOR;
	return R_TRUE;
}

static int config_pager_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	/* Let cons know we have a new pager. */
	core->cons->pager = node->value;
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
	r_config_set (cfg, "anal.prelude", "");
	r_config_desc (cfg, "anal.prelude", "Specify an hexpair to find preludes in code");
	r_config_set (cfg, "anal.hasnext", "true");
	r_config_desc (cfg, "anal.hasnext", "Continue analysis after each function");
	r_config_set_i (cfg, "anal.depth", 50); // XXX: warn if depth is > 50 .. can be problematic
	r_config_desc (cfg, "anal.depth", "Max depth at code analysis");
	r_config_set_i (cfg, "anal.ptrdepth", 3);
	r_config_set_cb (cfg, "anal.split", "true", &config_analsplit_callback);
	r_config_set_cb (cfg, "anal.plugin", R_SYS_ARCH, &config_analplugin_callback);
	r_config_desc (cfg, "anal.plugin", "Specify the anal plugin to use");
	/* asm */
r_config_set (cfg, "asm.arch", R_SYS_ARCH);
	r_config_set_cb (cfg, "asm.os", R_SYS_OS, &config_asmos_callback);
	r_config_desc (cfg, "asm.os", "Select operating system (kernel) (linux, darwin, w32,..)");
	r_config_set_cb (cfg, "asm.arch", R_SYS_ARCH, &config_asmarch_callback);
	r_config_desc (cfg, "asm.arch", "Set the arch to be usedd by asm");
	r_config_set_cb (cfg, "asm.cpu", R_SYS_ARCH, &config_asmcpu_callback);
	r_config_desc (cfg, "asm.cpu", "Set the kind of asm.arch cpu");
	// XXX: not portable
	r_parse_use (core->parser, "x86.pseudo");
	r_config_set_cb (cfg, "asm.parser", "x86.pseudo", &config_asmparser_callback);
	r_config_set_i_cb (cfg, "asm.bits", 32, &config_asmbits_callback);
	r_config_desc (cfg, "asm.bits", "Word size in bits at assembler");
	r_config_set (cfg, "asm.bytes", "true");
	r_config_desc (cfg, "asm.bytes", "Display the bytes of each instruction");
	r_config_set (cfg, "asm.flags", "true");
	r_config_desc (cfg, "asm.bytes", "Show flags in disassembly (pd)");
	r_config_set (cfg, "asm.size", "false");
	r_config_desc (cfg, "asm.size", "Show size of opcodes in disassembly (pd)");
	r_config_set (cfg, "asm.lbytes", "true");
	r_config_desc (cfg, "asm.lbytes", "Align disasm bytes to left");
	r_config_set (cfg, "asm.middle", "false"); // jump in the middle because of antidisasm tricks
	r_config_set (cfg, "asm.comments", "true");
	r_config_desc (cfg, "asm.comments", "Show comments in disassembly view");
	r_config_set (cfg, "asm.cmtright", "false");
	r_config_desc (cfg, "asm.cmtright", "Show comments at right of disassembly if they fit in screen");
	r_config_set (cfg, "asm.ucase", "false");
	r_config_desc (cfg, "asm.ucase", "Use uppercase syntax at disassembly");
	r_config_set (cfg, "asm.stackptr", "false");
	r_config_desc (cfg, "asm.stackptr", "Show stack pointer at disassembly");
	r_config_set (cfg, "asm.dwarf", "false");
	r_config_desc (cfg, "asm.dwarf", "Show dwarf comment at disassembly");
	r_config_set_i (cfg, "asm.nbytes", 8);
	r_config_set (cfg, "asm.tabs", "false");
	r_config_desc (cfg, "asm.nbytes", "Number of bytes for each opcode at disassembly");
	r_config_set (cfg, "asm.pseudo", "false");  // DEPRECATED ???
	r_config_desc (cfg, "asm.pseudo", "Enable pseudo syntax");
	r_config_set (cfg, "asm.filter", "true");
	r_config_desc (cfg, "asm.filter", "Show filtered flags at disassembly");
	r_config_set (cfg, "asm.varsub", "true");
	r_config_desc (cfg, "asm.varsub", "Substitute variables in disasm");
	r_config_set (cfg, "asm.trace", "true");
	r_config_desc (cfg, "asm.trace", "Show execution traces for each opcode");
	r_config_set (cfg, "asm.cmtflgrefs", "true");
	r_config_desc (cfg, "asm.cmtflgrefs", "Show comment flags associated to branch referece");
	r_config_set (cfg, "asm.decode", "false");
	r_config_desc (cfg, "asm.decode", "Use code analysis as a disassembler");
	r_config_set (cfg, "asm.offset", "true");
	r_config_desc (cfg, "asm.offset", "Show offsets at disassembly");
#if 0
	r_config_set (cfg, "asm.offseg", "false");
	r_config_desc (cfg, "asm.offseg", "Show offsets as in 16 bit segment addressing mode");
#endif
	r_config_set_cb (cfg, "asm.segoff", "false", &config_segoff_callback);
	r_config_desc (cfg, "asm.segoff", "show segmented address in prompt (x86-16)");
	r_config_set (cfg, "asm.lines", "true");
	r_config_desc (cfg, "asm.lines", "If enabled show ascci-art lines at disassembly");
	r_config_set (cfg, "asm.linesright", "false");
	r_config_desc (cfg, "asm.linesright", "If enabled show lines before opcode instead of offset");
	r_config_set (cfg, "asm.linesout", "true");
	r_config_desc (cfg, "asm.linesout", "If enabled show out of block lines");
	r_config_set (cfg, "asm.linesstyle", "false");
	r_config_desc (cfg, "asm.linesstyle", "If enabled iterate the jump list backwards");
	r_config_set (cfg, "asm.lineswide", "false");
	r_config_desc (cfg, "asm.lineswide", "If enabled put an space between lines");
	r_config_set_i_cb (cfg, "asm.lineswidth", 10, &config_asmlineswidth_callback);
	r_config_desc (cfg, "asm.lineswidth", "");
	r_config_set (cfg, "asm.linescall", "false");
	r_config_desc (cfg, "asm.linescall", "Enable call lines");
	r_config_set_cb (cfg, "asm.syntax", "intel", &config_asmsyntax_callback);
	r_config_desc (cfg, "asm.syntax", "Select assembly syntax");
	r_config_set_cb (cfg, "asm.profile", "default", &config_asmprofile_callback);
	r_config_desc (cfg, "asm.profile", "configure disassembler (default, simple, gas, smart, debug, full)");
	/* bin */
	r_config_set (cfg, "bin.strings", "true");
	r_config_desc (cfg, "bin.strings", "Load strings or not\n");
	r_config_set_i (cfg, "bin.minstr", 0);
	r_config_desc (cfg, "bin.minstr", "Minimum string length for r_bin");
	r_config_set (cfg, "bin.rawstr", "false");
	r_config_desc (cfg, "bin.rawstr", "Load strings from raw binaries");
	/* misc */
#if LIL_ENDIAN
	r_config_set_cb (cfg, "cfg.bigendian", "false", &config_bigendian_callback);
#else
	r_config_set_cb (cfg, "cfg.bigendian", "true", &config_bigendian_callback);
#endif
	r_config_desc (cfg, "cfg.bigendian", "Use little (false) or big (true) endiannes");
	r_config_set_cb (cfg, "cfg.debug", "false", &config_cfgdebug_callback);
	r_config_desc (cfg, "cfg.debug", "set/unset the debugger mode");
	r_config_set_cb (cfg, "cfg.datefmt", "%d:%m:%Y %H:%M:%S %z", &config_cfgdatefmt_callback);
	r_config_desc (cfg, "cfg.datefmt", "Date format (%d:%m:%Y %H:%M:%S %z)");
	r_config_set (cfg, "cfg.fortunes", "true");
	r_config_desc (cfg, "cfg.fortunes", "If enabled show tips at start");
	r_config_set_cb (cfg, "cfg.sandbox", "false", &config_cfgsandbox_callback);
	r_config_desc (cfg, "cfg.sandbox", "sandbox mode disables systems and open on upper directories");
	r_config_set (cfg, "cfg.wseek", "false");
	r_config_desc (cfg, "cfg.wseek", "Seek after write");
	r_config_set_i (cfg, "cfg.hashlimit", SLURP_LIMIT);
	r_config_desc (cfg, "cfg.hashlimit", "If the file its bigger than hashlimit don't calculate the hash");
	/* diff */
	r_config_set_i (cfg, "diff.from", 0);
	r_config_desc (cfg, "diff.from", "set source diffing address for px (uses cc command)");
	r_config_set_i (cfg, "diff.to", 0);
	r_config_desc (cfg, "diff.to", "set destination diffing address for px (uses cc command)");
	/* dir */
	r_config_set (cfg, "dir.projects", R2_HOMEDIR"/rdb");
	r_config_set (cfg, "dir.types", "/usr/include");
	r_config_desc (cfg, "dir.types", "Default path to look for cparse type files");
	r_config_set (cfg, "dir.source", "");
	r_config_desc (cfg, "dir.source", "Path to find source files");
	r_config_set (cfg, "dir.magic", R_MAGIC_PATH);
	r_config_desc (cfg, "dir.magic", "Path to r_magic files");
	r_config_set (cfg, "dir.plugins", R2_LIBDIR"/radare2/"R2_VERSION"/");
	r_config_desc (cfg, "dir.plugins", "Path to plugin files to be loaded at startup");
	/* debug */
	if (core->cons->rows>30) // HACKY
		r_config_set_i (cfg, "dbg.follow", 64);
	else r_config_set_i (cfg, "dbg.follow", 32);
	r_config_desc (cfg, "dbg.follow", "Follow program counter when pc > core->offset + dbg.follow");
	r_config_set_cb (cfg, "dbg.backend", "native", &config_dbgbackend_callback);
	r_config_desc (cfg, "dbg.backend", "Select the debugger backend");
	r_config_set (cfg, "dbg.bep", "loader"); // loader, entry, constructor, main
	r_config_desc (cfg, "cfg.bep", "break on entrypoint (loader, entry, constructor, main)");
	r_config_set_cb (cfg, "dbg.stopthreads", "true", &config_stopthreads_callback);
	r_config_desc (cfg, "dbg.stopthreads", "stop all threads when debugger breaks");
	r_config_set_cb (cfg, "dbg.swstep", "false", &config_swstep_callback);
	r_config_desc (cfg, "dbg.swstep", "If enabled forces the use of software steps (code analysis+breakpoint)");
	r_config_set_cb (cfg, "dbg.trace", "true", &config_trace_callback);
	r_config_desc (cfg, "dbg.trace", "enable debugger trace (see asm.trace)");
	r_config_set_cb (cfg, "dbg.trace.tag", "0xff", &config_tracetag_callback);
	r_config_set_cb (cfg, "fs.view", "normal", &config_fsview_callback);
	r_config_desc (cfg, "fs.view", "Set visibility options for filesystems");
	r_config_set (cfg, "hud.once", "false");
	r_config_desc (cfg, "hud.once", "run");
	r_config_set (cfg, "bin.dwarf", "false");
	r_config_desc (cfg, "bin.dwarf", "Load dwarf information on startup if available");
	r_config_set (cfg, "bin.strings", "true");
	r_config_desc (cfg, "bin.strings", "Load strings from rbin on startup");
	p = r_sys_getenv ("EDITOR");
#if __WINDOWS__
	r_config_set (cfg, "cfg.editor", p? p: "notepad");
#else
	r_config_set (cfg, "cfg.editor", p? p: "vi");
#endif
	r_config_desc (cfg, "cfg.editor", "Select default editor program");
	free (p);
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
	r_config_set (cfg, "cmd.hit", "");
	r_config_desc (cfg, "cmd.hit", "Command to execute on every search hit");
	r_config_set (cfg, "cmd.open", "");
	r_config_desc (cfg, "cmd.open", "Command executed when file its opened");
	r_config_set_cb (cfg, "cmd.repeat", "true", &config_cmdrepeat_callback);
	r_config_desc (cfg, "cmd.repeat", "Alias newline (empty command) as '..'");
	r_config_set (cfg, "cmd.prompt", "");
	r_config_desc (cfg, "cmd.prompt", "Prompt commands");
	r_config_set (cfg, "cmd.cprompt", "");
	r_config_desc (cfg, "cmd.cprompt", "Column visual prompt commands");
	r_config_set (cfg, "cmd.visual", "");
	r_config_desc (cfg, "cmd.visual", "Replace current print mode");
	r_config_set (cfg, "cmd.vprompt", "");
	r_config_desc (cfg, "cmd.vprompt", "Visual prompt commands");
	r_config_set (cfg, "cmd.bp", "");
	r_config_desc (cfg, "cmd.bp", "Command to executed every breakpoint hitted");
	r_config_set (cfg, "http.allow", "");
	r_config_desc (cfg, "http.allow", "http firewall. only accept clients from the comma separated IP list");
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
#endif
	r_config_desc (cfg, "http.browser", "command to open http urls");
	r_config_set (cfg, "http.sandbox", "false");
	r_config_set_i (cfg, "http.timeout", 3);
	r_config_desc (cfg, "http.timeout", "disconnect clients after N seconds if no data sent");
	r_config_set (cfg, "http.public", "false");
	r_config_desc (cfg, "http.public", "set to true to listen on 0.0.0.0");
	r_config_set (cfg, "http.port", "9090");
	r_config_desc (cfg, "http.root", "port to listen for http connections");
	r_config_set (cfg, "http.uri", "");
	r_config_desc (cfg, "http.uri", "base uri to remote host proxy host");
	r_config_set (cfg, "http.root", R2_WWWROOT);
	r_config_desc (cfg, "http.root", "http root directory");

	r_config_set (cfg, "http.upload", "false");
	r_config_desc (cfg, "http.upload", "enable file POST uploads in /up/<filename>");
	r_config_set_i (cfg, "http.maxsize", 0);
	r_config_desc (cfg, "http.maxsize", "define maximum file size to upload");
	r_config_set (cfg, "http.upget", "false");
	r_config_desc (cfg, "http.upget", "/up/ can be GET, not only POST");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc (cfg, "http.uproot", "path to store uploaded files");

	r_config_set (cfg, "graph.font", "Courier");
	r_config_desc (cfg, "graph.font", "font to be used by the dot graphs");
	r_config_set_cb (cfg, "scr.columns", "0", config_scrcolumns_callback);
	r_config_set_cb (cfg, "scr.rows", "0", config_scrrows_callback);
	r_config_set_cb (cfg, "scr.sparse", "false", config_scrsparse_callback);
	r_config_set_cb (cfg, "scr.interactive", "true", config_scrint_callback);
	r_config_set_cb (cfg, "scr.tee", "", config_teefile_callback);
	r_config_desc (cfg, "scr.tee", "Pipe console output to file if not empty");
	r_config_set_cb (cfg, "scr.prompt", "true", &config_scrprompt_callback);
	r_config_set (cfg, "scr.pipecolor", "false");
	r_config_desc (cfg, "scr.pipecolor", "enable colors when using pipes if true");
	r_config_set_cb (cfg, "scr.color",
		(core->print->flags&R_PRINT_FLAGS_COLOR)?"true":"false",
		&config_color_callback);
	r_config_desc (cfg, "scr.color", "enable/Disable colors");
	r_config_set (cfg, "scr.colorops", "true");
	r_config_desc (cfg, "scr.colorops", "colorize in numbers/registers in opcodes");
	r_config_set_cb (cfg, "scr.pager", "", &config_pager_callback);
	r_config_desc (cfg, "scr.pager", "Select pager program (used if output doesn't fit on window)");
	//r_config_set_cb (cfg, "scr.nkey", "function", &config_scrnkey_callback);
	r_config_set_cb (cfg, "scr.nkey", "hit", &config_scrnkey_callback);
	r_config_desc (cfg, "scr.nkey", "Select the seek mode in visual");
	r_config_set (cfg, "scr.seek", "");
	r_config_set_i(cfg, "scr.colpos", 80);
	r_config_desc (cfg, "scr.colpos", "Column position of cmd.cprompt in visual");
	r_config_set_i_cb (cfg, "hex.stride", 0, &config_hexstride_callback);
	r_config_desc (cfg, "hex.stride", "Define the line stride in hexdump (default is 0)");
	r_config_set_i_cb (cfg, "hex.cols", 16, &config_hexcols_callback);
	r_config_desc (cfg, "hex.cols", "Configure the number of columns in hexdump");
	r_config_set_cb (cfg, "scr.html", "false", &config_scrhtml_callback);
	r_config_desc (cfg, "scr.html", "If enabled disassembly use HTML syntax");
	r_config_set_cb (cfg, "scr.widthfix", "false", &config_widthfix_callback);
	r_config_desc (cfg, "scr.widthfix", "Workaround for Prompt iOS ssh client");
	r_config_set (cfg, "search.in", "file");
	r_config_desc (cfg, "search.in", "Specify search boundaries (raw, block, file, section)");
	r_config_set_i (cfg, "search.kwidx", 0);
	r_config_desc (cfg, "search.kwidx", "Store last search index count");
	r_config_set (cfg, "search.show", "true");
	r_config_desc (cfg, "search.show", "Show search results while found (disable if lot of hits)");
	r_config_set (cfg, "search.flags", "true");
	r_config_desc (cfg, "search.flags", "If enabled all search results are flagged, else just printed r2 commands");
	r_config_set_i (cfg, "search.count", 0);
	r_config_desc (cfg, "search.count", "Start index number at search hits");
	r_config_set (cfg, "search.prefix", "hit");
	r_config_desc (cfg, "search.prefix", "Prefix name in search hits label");
	r_config_set_i (cfg, "search.from", -1);
	r_config_desc (cfg, "search.from", "Search start address");
	r_config_set_i (cfg, "search.to", -1);
	r_config_desc (cfg, "search.to", "Search end address");
	r_config_set_i (cfg, "search.distance", 0); // TODO: use i_cb here and remove code in cmd.c
	r_config_desc (cfg, "search.distance", "Search string distance");
	r_config_set_i_cb (cfg, "search.align", 0, &config_searchalign_callback);
	r_config_desc (cfg, "search.align", "Only catch aligned search hits");

	r_config_set_cb (cfg, "io.buffer", "false", &config_iobuffer_callback);
	r_config_desc (cfg, "io.buffer", "load and use buffer cache if enabled");
	r_config_set_i (cfg, "io.buffer.from", 0);
	r_config_desc (cfg, "io.buffer.from", "lower address of buffered cache");
	r_config_set_i (cfg, "io.buffer.to", 0);
	r_config_desc (cfg, "io.buffer.to", "higher address of buffered cache");
	sprintf (buf, "0");
	r_config_set_cb (cfg, "io.zeromap", buf, &config_iozeromap_callback);
	r_config_desc (cfg, "io.zeromap", "double map the last opened file to address zero");
	r_config_set_cb (cfg, "io.maxblk", buf, &config_iomaxblk_callback);
	r_config_desc (cfg, "io.maxblk", "set max block size (soft limit)");

	r_config_set_cb (cfg, "io.ffio", "true", &config_ioffio_callback);
	r_config_desc (cfg, "io.ffio", "fill invalid buffers with 0xff instead of returning error");
	r_config_set_cb (cfg, "io.va", "true", &config_iova_callback);
	r_config_desc (cfg, "io.va", "If enabled virtual address layout can be used");
	r_config_set_cb (cfg, "io.cache", "false", &config_iocache_callback);
	r_config_desc (cfg, "io.cache", "Enable cache for io changes");
	r_config_set (cfg, "file.analyze", "false");
	r_config_desc (cfg, "file.analyze", "Analyze file on load. Same as r2 -c aa ..");
	r_config_set (cfg, "file.path", "");
	r_config_desc (cfg, "file.path", "Path of current file");
	r_config_set (cfg, "file.desc", "");
	r_config_desc (cfg, "file.desc", "User defined file description. Used by projects");
	r_config_set (cfg, "file.project", "");
	r_config_desc (cfg, "file.project", "Name of current project");
	r_config_set (cfg, "file.md5", "");
	r_config_desc (cfg, "file.md5", "md5 sum of current file");
	r_config_set (cfg, "file.sha1", "");
	r_config_desc (cfg, "file.sha1", "sha1 hash of current file");
	r_config_set (cfg, "file.type", "");
	r_config_desc (cfg, "file.type", "Type of current file");
	r_config_set_i (cfg, "magic.depth", 100);
	r_config_desc (cfg, "magic.depth", "Recursivity depth in magic description strings");
	r_config_set (cfg, "rap.loop", "true");
	r_config_desc (cfg, "rap.loop", "run rap as a forever-listening daemon");
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
	r_config_set_i (cfg, "zoom.maxsz", 512);
	r_config_desc (cfg, "zoom.maxsz", "Zoom max size of block");
	r_config_set_i (cfg, "zoom.from", 0);
	r_config_desc (cfg, "zoom.from", "Zoom start address");
	r_config_set_i (cfg, "zoom.to", 0);
	r_config_desc (cfg, "zoom.to", "Zoom end address");
	r_config_set_cb (cfg, "zoom.byte", "h", &config_zoombyte_callback);
	r_config_desc (cfg, "zoom.byte", "Zoom callback to calculate each byte (See pz? for help)");
	/* TODO cmd */
#if 0
	config_set("asm.section", "true");
	config_set("asm.reladdr", "false"); // relative offset
	config_set("asm.functions", "true");
	config_set_i("asm.nlines", 6); // show left ref lines
	config_set("asm.lineswide", "false"); // show left ref lines
	config_set("asm.trace", "false"); // trace counter
	config_set("asm.split", "true"); // split code blocks
	config_set("asm.splitall", "false"); // split code blocks

	// config_set("asm.follow", "");
	config_set("cmd.wp", "");
	config_set("cmd.flag", "true");
	config_set("cmd.asm", "");
	config_set("cmd.user", "");
	config_set("cmd.trace", "");
	config_set("cmd.visual", "");
	config_set("cmd.visualbind", "");
	config_set("cmd.touchtrace", "");

	config_set("search.flag", "true");
	config_set("search.verbose", "true");

	config_set("file.id", "false");
	config_set("file.flag", "false");
	config_set("file.trace", "trace.log");
	config_set("file.project", "");
	config_set("file.entrypoint", "");
	node = config_set("file.scrfilter", "");
	node->callback = &config_filterfile_callback;
	config_set_i("file.size", 0);

	node = config_set_i("io.vaddr", 0); // OLD file.baddr
	node->callback = &config_vaddr_callback;
	node = config_set_i("io.paddr", 0); // physical address
	node->callback = &config_paddr_callback;

	config_set("dump.regs", "true");
	config_set("dump.user", "true");
	config_set("dump.libs", "true");
	config_set("dump.fds", "true");

	config_set("trace.bt", "false");
	config_set("trace.bps", "false");
	config_set("trace.calls", "false");
	config_set_i("trace.sleep", 0);
	config_set("trace.smart", "false");
	config_set("trace.libs", "true");
	config_set("trace.log", "false");
	config_set("trace.dup", "false");
	config_set("trace.cmtregs", "false");

	config_set("cfg.editor", "vi");
	node = config_set("cfg.debug", "false");
	node->callback = &config_debug_callback;
	config_set("cfg.noscript", "false");
	config_set("cfg.sections", "true");
	config_set("cfg.encoding", "ascii"); // cp850
	config_set_i("cfg.delta", 4096); // cp850
	node = config_set("cfg.verbose", "true");
	node->callback = &config_verbose_callback;

	config_set("cfg.inverse", "false");
	config_set_i("cfg.analdepth", 6);
	config_set("file.insert", "false");
	config_set("file.insertblock", "false");
	config_set("file.undowrite", "true");
	if (first) {
		node = config_set("file.write", "false");
		node->callback = &config_wmode_callback;
	}
	node = config_set("cfg.limit", "0");
	node->callback = &config_limit_callback;
#if __mips__
	// ???
	config_set("cfg.addrmod", "32");
#else
	config_set("cfg.addrmod", "4");
#endif
	config_set("cfg.datefmt", "%d:%m:%Y %H:%M:%S %z");
	config_set_i("cfg.count", 0);
	node = config_set_i("cfg.bsize", 512);
	node->callback = &config_bsize_callback;
	config_set_i("cfg.vbsize", 1024);
	config_set("cfg.vbsize_enabled", "false");

	config_set_i("range.from", 0);
	config_set_i("range.to", 0xffff);
	config_set("range.traces", "true");
	config_set("range.graphs", "true");
	config_set("range.functions", "true");

#if __mips__
	config_set("dbg.fpregs", "true");
#else
	config_set("dbg.fpregs", "false");
#endif
	config_set("dbg.forks", "false"); // stop debugger in any fork or clone
	config_set("dbg.controlc", "true"); // stop debugger if ^C is pressed
	config_set_i("dbg.focus", 0); // focus on ps.pid or not (ignore events of rest of procs)
	config_set("dbg.fullbt", "false"); // user backtrace or lib+user backtrace
	config_set("dbg.bttype", "default"); // default, st and orig or so!
#if __APPLE__ || __ARM__ || __mips__
	config_set("dbg.hwbp", "false"); // default, st and orig or so!
#else
	config_set("dbg.hwbp", "true"); // hardware breakpoints by default // ALSO BSD
#endif
	config_set("dir.home", getenv("HOME"));

	/* dir.monitor */
	ptr = getenv("MONITORPATH");
	if (ptr == NULL) {
		sprintf(buf, "%s/.radare/monitor/", ("HOME"));
		ptr = (const char *)&buf;
	}
	config_set("dir.monitor", ptr);

	config_set("graph.split", "false"); // split blocks // SHOULD BE TRUE, but true algo is buggy
	config_set("graph.jmpblocks", "true");
	config_set("graph.refblocks", "false"); // must be circle nodes
	config_set("graph.callblocks", "false");
	config_set("graph.flagblocks", "true");
	config_set_i("graph.depth", 9);
	config_set("graph.offset", "true");
	config_set("graph.render", "cairo");    // aalib/ncurses/text
	config_set("graph.layout", "default");  // graphviz
#endif
	r_config_lock (cfg, R_TRUE);
	return R_TRUE;
}
