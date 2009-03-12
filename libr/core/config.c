/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_core.h>

void config_color_callback(void *user, void *data)
{
	struct r_core_t *core = (struct r_core_t *) user;
	struct r_config_node_t *node =
		(struct r_config_node_t *) data;
		
	if (node->i_value) {
		core->print.flags|=R_PRINT_FLAGS_COLOR;
	} else {
		// XXX ??? sure
		if (core->print.flags&R_PRINT_FLAGS_COLOR)
			core->print.flags^=R_PRINT_FLAGS_COLOR;
	}
}

int r_core_config_init(struct r_core_t *core)
{
	struct r_config_t *cfg = &core->config;
	r_config_init(cfg, (void *)core);
	r_config_set(cfg, "asm.arch", "x86");
	r_config_set_i(cfg, "asm.bits", 32);
	r_config_set(cfg, "asm.syntax", "x86");
	r_config_set(cfg, "asm.pseudo", "false"); 
	r_config_set(cfg, "asm.bytes", "true"); 
	r_config_set(cfg, "asm.offset", "true"); 
	r_config_set(cfg, "asm.os", "linux"); 
	r_config_set(cfg, "cmd.prompt", ""); 
	r_config_set(cfg, "cmd.vprompt", ""); 
	r_config_set_cb(cfg, "scr.color",
		(core->print.flags&R_PRINT_FLAGS_COLOR)?"true":"false",
		&config_color_callback);
#if 0
	node = config_set("asm.profile", "default");
//	node->callback = &config_asm_profile;

#if __POWERPC__
	node = config_set("asm.arch", "ppc");
#elif __x86_64__
	node = config_set("asm.arch", "intel64");
#elif __arm__
	node = config_set("asm.arch", "arm");
#elif __mips__
	node = config_set("asm.arch", "mips");
#else
	node = config_set("asm.arch", "intel");
#endif
//	node->callback = &config_arch_callback;
	config_set("asm.comments", "true"); // show comments in disassembly
	config_set_i("asm.cmtmargin", 10); // show comments in disassembly
	config_set_i("asm.cmtlines", 0); // show comments in disassembly
	config_set("asm.syntax", "intel");
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
	config_set("asm.flagsline", "false");
	config_set("asm.functions", "true");
	config_set("asm.lines", "true"); // show left ref lines
	config_set_i("asm.nlines", 6); // show left ref lines
	config_set("asm.lineswide", "false"); // show left ref lines
	config_set("asm.trace", "false"); // trace counter
	config_set("asm.linesout", "false"); // show left ref lines
	config_set("asm.linestyle", "false"); // foreach / prev
	// asm.os = used for syscall tables and so.. redefined with rabin -rI
	config_set("asm.pseudo", "false"); 
#if __linux__
	config_set("asm.os", "linux"); 
#elif __FreeBSD__
	config_set("asm.os", "freebsd");
#elif __NetBSD__
	config_set("asm.os", "netbsd");
#elif __OpenBSD__
	config_set("asm.os", "openbsd");
#elif __Windows__
	config_set("asm.os", "linux");
#endif
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
	config_set("cmd.hit", "");
	config_set("cmd.visualbind", "");
	config_set("cmd.touchtrace", "");
#endif
	r_config_set(cfg, "cmd.prompt", "");
	r_config_set(cfg, "cmd.vprompt", "p%");
	r_config_set(cfg, "cmd.vprompt2", "CFV");
	r_config_set(cfg, "cmd.vprompt3", "");
	r_config_set(cfg, "cmd.bp", "");

#if 0
	config_set_i("search.from", 0);
	config_set_i("search.to", 0);
	config_set_i("search.align", 0);
	config_set("search.flag", "true");
	config_set("search.verbose", "true");

	config_set("file.id", "false");
	config_set("file.analyze", "false");
	config_set("file.type", "");
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
#if LIL_ENDIAN
	node = config_set("cfg.bigendian", "false");
#else
	node = config_set("cfg.bigendian", "true");
#endif
	node->callback = &config_bigendian_callback;

	config.endian = config_get_i("cfg.bigendian");
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
	config_set("cfg.fortunes", "true");
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
	config_set("dbg.dwarf", "false");
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

	config_set("dir.plugins", LIBDIR"/radare/");
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

	node = config_set("scr.html", "false");
	node->callback = &config_scrhtml_callback;
	config_set_i("scr.accel", 0);

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

		config_set("scr.seek", "eip");
	config_set("scr.grephigh", "");
	node = config_set("scr.tee", "");
	node->callback = &config_teefile_callback;
	node = config_set("scr.buf", "false");
	node->callback = &config_scrbuf_callback;
	node = config_set_i("scr.width", config.width);
	node->callback = &config_scrwidth;
	node = config_set_i("scr.height", config.height);
	node->callback = &config_scrheight;
	r_config_set("vm.realio", "false");
#endif

	return 0;
}
