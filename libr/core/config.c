/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>

static int config_scrhtml_callback(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->is_html = node->i_value;
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
	return R_TRUE;
}

static int config_iova_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (r_config_get_i (core->config, "cfg.debug"))
		core->io->va = 0;
	else core->io->va = node->i_value;
	return R_TRUE;
}

static int config_iocache_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_io_cache_enable (core->io, node->i_value, node->i_value);
	return R_TRUE;
}

static int config_cfgdebug_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value) {
		r_debug_use (core->dbg, r_config_get (core->config, "dbg.backend"));
		r_debug_select (core->dbg, core->file->fd, core->file->fd);
	}
	return R_TRUE;
}

static int config_asmos_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!r_syscall_setup (core->syscall, 
			r_config_get (core->config, "asm.arch"), node->value))
		eprintf ("asm.os: Cannot setup syscall os/arch for '%s'\n", node->value);
	return R_TRUE;
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

static int config_swstep_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->swstep = node->i_value;
	return R_TRUE;
}

static int config_asmarch_callback(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	// TODO: control error and restore old value (return false?) show errormsg?
	if (!r_asm_use (core->assembler, node->value))
		eprintf ("asm.arch: Cannot set this arch (%s)\n", node->value);
	if (!r_anal_use (core->anal, node->value))
		eprintf ("asm.arch: Cannot setup analysis engine for '%s'\n", node->value);
	if (!r_syscall_setup (core->syscall, node->value,
			r_config_get (core->config, "asm.os")))
		eprintf ("asm.arch: Cannot setup syscall os/arch for '%s'\n", node->value);
	return R_TRUE;
}

static int config_asm_parser_callback(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX this is wrong? snprintf(buf, 127, "parse_%s", node->value),
	r_parse_use (core->parser, node->value);
	// TODO: control error and restore old value (return false?) show errormsg?
	return R_TRUE;
}

static int config_asm_bits_callback(void *user, void *data) {
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
	// TODO: change debugger backend bit profile here
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

R_API int r_core_config_init(RCore *core) {
	RConfig *cfg = cfg = core->config = r_config_new (core);
	cfg->printf = r_cons_printf;

	r_config_set_cb (cfg, "asm.arch", R_SYS_ARCH, &config_asmarch_callback);
	// XXX: not portable
	r_parse_use (core->parser, "x86.pseudo");
	r_config_set_cb (cfg, "asm.parser", "x86.pseudo",
		&config_asm_parser_callback);

	r_config_set (cfg, "dir.plugins", LIBDIR"/radare2/");
	/* anal */
	r_config_set_i (cfg, "anal.depth", 10);
	r_config_set (cfg, "anal.split", "false");
	/* asm */
	r_config_set_i_cb (cfg, "asm.bits", 32,
		&config_asm_bits_callback);
	r_config_set (cfg, "asm.bytes", "true"); 
	r_config_set (cfg, "asm.middle", "false"); // jump in the middle because of antidisasm tricks
	r_config_set (cfg, "asm.comments", "true");
	r_config_set (cfg, "asm.stackptr", "true");
	r_config_set (cfg, "asm.dwarf", "false");
	r_config_set_i (cfg, "asm.nbytes", 8);
	r_config_set (cfg, "asm.pseudo", "false");  // DEPRECATED ???
	r_config_set (cfg, "asm.filter", "true");
	r_config_set (cfg, "asm.trace", "true");
	r_config_set (cfg, "asm.decode", "false"); 
	r_config_set (cfg, "asm.bytes", "true"); 
	r_config_set (cfg, "asm.offset", "true"); 
	r_config_set (cfg, "asm.lines", "true");
	r_config_set (cfg, "asm.linesout", "true");
	r_config_set (cfg, "asm.linesstyle", "false");
	r_config_set (cfg, "asm.lineswide", "false");
	r_config_set (cfg, "asm.linescall", "false");
	r_config_set (cfg, "asm.offset", "true"); 
	r_config_set_cb (cfg, "asm.os", R_SYS_OS, &config_asmos_callback);
	r_config_set (cfg, "asm.pseudo", "false");  // DEPRECATED ???
	r_config_set (cfg, "asm.syntax", "intel");
#if LIL_ENDIAN
	r_config_set_cb (cfg, "cfg.bigendian", "false", &config_bigendian_callback);
#else
	r_config_set_cb (cfg, "cfg.bigendian", "true", &config_bigendian_callback);
#endif
	r_config_set_cb (cfg, "cfg.debug", "false", &config_cfgdebug_callback);
	r_config_set (cfg, "cfg.fortunes", "true");
	r_config_set (cfg, "dbg.backend", "native");
	r_config_set_cb (cfg, "dbg.stopthreads", "true", &config_stopthreads_callback);
	r_config_set_cb (cfg, "dbg.swstep", "false", &config_swstep_callback);
	r_config_set_cb (cfg, "dbg.trace", "true", &config_trace_callback);
	r_config_set_cb (cfg, "dbg.trace.tag", "0xff", &config_tracetag_callback);
	r_config_set (cfg, "cmd.hit", ""); 
	r_config_set (cfg, "cmd.open", ""); 
	r_config_set (cfg, "cmd.prompt", ""); 
	r_config_set (cfg, "cmd.vprompt", "");
	r_config_set (cfg, "cmd.bp", "");
	r_config_set (cfg, "scr.prompt", "true");
	r_config_set_cb (cfg, "scr.color",
		(core->print->flags&R_PRINT_FLAGS_COLOR)?"true":"false",
		&config_color_callback);
	r_config_set (cfg, "scr.seek", "");
	r_config_set_i (cfg, "search.from", 0);
	r_config_set_i (cfg, "search.to", 0);
	r_config_set_i (cfg, "search.distance", 0); // TODO: use i_cb here and remove code in cmd.c
	r_config_set_i_cb (cfg, "search.align", 0, &config_searchalign_callback);
	r_config_set_cb (cfg, "scr.html", "false", &config_scrhtml_callback);
	r_config_set_cb (cfg, "io.ffio", "false", &config_ioffio_callback);
	r_config_set_cb (cfg, "io.va", "true", &config_iova_callback);
	r_config_set_cb (cfg, "io.cache", "false", &config_iocache_callback);
	r_config_set (cfg, "file.path", "");
	r_config_set (cfg, "file.desc", "");
	r_config_set (cfg, "file.project", "");
	r_config_set (cfg, "file.md5", "");
	r_config_set (cfg, "file.sha1", "");
	r_config_set (cfg, "file.type", "");
	/* TODO cmd */
#if 0
	node = config_set("asm.profile", "default");
//	node->callback = &config_asm_profile;

//	node->callback = &config_arch_callback;
	config_set("asm.comments", "true"); // show comments in disassembly
	config_set_i("asm.cmtmargin", 10); // show comments in disassembly
	config_set_i("asm.cmtlines", 0); // show comments in disassembly
	config_set("asm.case", "false"); // uppercase = true
	config_set("asm.objdump", "objdump -m i386 --target=binary -D");
	config_set("asm.offset", "true"); // show offset
	config_set("asm.section", "true");
	config_set("asm.stackptr", "true");
	config_set("asm.reladdr", "false"); // relative offset
	config_set_i("asm.nbytes", 8); // show hex bytes
	config_set("asm.bytes", "true"); // show hex bytes
	config_set("asm.jmpflags", "false");
	config_set("asm.flags", "true");
	config_set("asm.flagsall", "true");
	config_set("asm.functions", "true");
	config_set("asm.lines", "true"); // show left ref lines
	config_set_i("asm.nlines", 6); // show left ref lines
	config_set("asm.lineswide", "false"); // show left ref lines
	config_set("asm.trace", "false"); // trace counter
	config_set("asm.linesout", "false"); // show left ref lines
	config_set("asm.linestyle", "false"); // foreach / prev
	config_set("asm.split", "true"); // split code blocks
	config_set("asm.splitall", "false"); // split code blocks
	config_set("asm.size", "false"); // opcode size
	config_set("asm.xrefs", "xrefs");

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
	config_set("file.analyze", "false");
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
	config_set("cfg.rdbdir", "TODO");
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

	config_set("child.stdio", "");
	config_set("child.stdin", "");
	config_set("child.stdout", "");
	config_set("child.stderr", "");
	config_set("child.setgid", ""); // must be int ?
	config_set("child.chdir", ".");
	config_set("child.chroot", "/");
	config_set("child.setuid", "");
#if __mips__
	config_set("dbg.fpregs", "true");
#else
	config_set("dbg.fpregs", "false");
#endif
	config_set("dbg.forks", "false"); // stop debugger in any fork or clone
	config_set("dbg.controlc", "true"); // stop debugger if ^C is pressed
	config_set_i("dbg.focus", 0); // focus on ps.pid or not (ignore events of rest of procs)
	config_set("dbg.syms", "true");
	config_set("dbg.stepo", "false"); // step over for !contu (debug_step())
	config_set("dbg.maps", "true");
	config_set("dbg.sections", "true");
	config_set("dbg.strings", "false");
	config_set("dbg.stop", "false");
	config_set("dbg.threads", "false");
	config_set("dbg.contscbt", "true");
	config_set("dbg.contsc2", "true"); // WTF?
	config_set("dbg.regs", "true");
	config_set("dbg.regs2", "false");
	config_set("dbg.stack", "true");
	config_set("dbg.vstack", "true");
	config_set("dbg.wptrace", "false");
	config_set_i("dbg.stacksize", 66);
	config_set("dbg.stackreg", "esp");
	config_set("dbg.bt", "false");
	config_set_i("dbg.btlast", 0);
	config_set("dbg.fullbt", "false"); // user backtrace or lib+user backtrace
	config_set("dbg.bttype", "default"); // default, st and orig or so!
#if __APPLE__ || __ARM__ || __mips__
	config_set("dbg.hwbp", "false"); // default, st and orig or so!
#else
	config_set("dbg.hwbp", "true"); // hardware breakpoints by default // ALSO BSD
#endif
	config_set("dbg.bep", "loader"); // loader, main
	config_set("dir.home", getenv("HOME"));

	/* dir.monitor */
	ptr = getenv("MONITORPATH");
	if (ptr == NULL) {
		sprintf(buf, "%s/.radare/monitor/", getenv("HOME"));
		ptr = (const char *)&buf;
	}
	config_set("dir.monitor", ptr);

	/* dir.spcc */
	ptr = getenv("SPCCPATH");
	if (ptr == NULL) {
		sprintf(buf, "%s/.radare/spcc/", getenv("HOME"));
		ptr = buf;
	}
	config_set("dir.spcc", ptr);

	snprintf(buf, 1023, "%s/.radare/rdb/", getenv("HOME"));
	config_set("dir.project", buf); // ~/.radare/rdb/
	config_set("dir.tmp", get_tmp_dir());
	config_set("graph.color", "magic");
	config_set("graph.split", "false"); // split blocks // SHOULD BE TRUE, but true algo is buggy
	config_set("graph.jmpblocks", "true");
	config_set("graph.refblocks", "false"); // must be circle nodes
	config_set("graph.callblocks", "false");
	config_set("graph.flagblocks", "true");
	config_set_i("graph.depth", 9);
	config_set("graph.offset", "true");
	config_set("graph.render", "cairo");    // aalib/ncurses/text
	config_set("graph.layout", "default");  // graphviz

	/* gui */
	config_set("gui.top", "gtk-topbar");  // graphviz
	config_set("gui.tabs", "gtk-prefs");  // graphviz
	config_set("gui.left", "scriptedit gtk-actions");  // graphviz
	config_set("gui.right", "gtk-hello");  // graphviz
	config_set("gui.bottom", "gtk-hello");  // graphviz

	node = config_set_i("zoom.from", 0);
	node = config_set_i("zoom.to", config.size);
	node = config_set("zoom.byte", "head");
	node->callback = &config_zoombyte_callback;

	node = config_set("scr.palette", cons_palette_default);
	node->callback = &config_palette_callback;
	cons_palette_init(config_get("scr.palette"));
#define config_set_scr_pal(x,y) \
	node = config_set("scr.pal."x"", y); \
	node->callback = &config_palette_callback; \
	node->callback(node);
	config_set_scr_pal("prompt","yellow")
		config_set_scr_pal("default","white")
		config_set_scr_pal("changed","green")
		config_set_scr_pal("jumps","green")
		config_set_scr_pal("calls","green")
		config_set_scr_pal("push","green")
		config_set_scr_pal("trap","red")
		config_set_scr_pal("cmp","yellow")
		config_set_scr_pal("ret","red")
		config_set_scr_pal("nop","gray")
		config_set_scr_pal("metadata","gray")
		config_set_scr_pal("header","green")
		config_set_scr_pal("printable","bwhite")
		config_set_scr_pal("lines0","white")
		config_set_scr_pal("lines1","yellow")
		config_set_scr_pal("lines2","bwhite")
		config_set_scr_pal("address","green")
		config_set_scr_pal("ff","red")
		config_set_scr_pal("00","white")
		config_set_scr_pal("7f","magenta")

	config_set("scr.grephigh", "");
	node = config_set("scr.tee", "");
	node->callback = &config_teefile_callback;
	node = config_set("scr.buf", "false");
	node->callback = &config_scrbuf_callback;
	node = config_set_i("scr.width", config.width);
	node->callback = &config_scrwidth;
	node = config_set_i("scr.height", config.height);
	node->callback = &config_scrheight;
#endif
	r_config_lock (cfg, R_TRUE);
	return R_TRUE;
}
