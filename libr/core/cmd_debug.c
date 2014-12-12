/* radare - LGPL - Copyright 2009-2014 - pancake */

static int checkbpcallback(RCore *core);

static void cmd_debug_cont_syscall (RCore *core, const char *_str) {
	// TODO : handle more than one stopping syscall
	int i, *syscalls = NULL;
	int count = 0;
	if (_str && *_str) {
		char *str = strdup (_str);
		count = r_str_word_set0 (str);
		syscalls = calloc (sizeof (int), count);
		for (i=0; i<count; i++) {
			const char *sysnumstr = r_str_word_get0 (str, i);
			int sig = (int)r_num_math (core->num, sysnumstr);
			if (sig == -1) { // trace ALL syscalls
				syscalls[i] = -1;
			} else
			if (sig == 0) {
				sig = r_syscall_get_num (core->anal->syscall, sysnumstr);
				if (sig == -1) {
					eprintf ("Unknown syscall number\n");
					free (str);
					free (syscalls);
					return;
				}
				syscalls[i] = sig;
			}
		}
		eprintf ("Running child until syscalls:");
		for (i=0; i<count; i++)
			eprintf ("%d ", syscalls[i]);
		eprintf ("\n");
		free (str);
	} else {
		eprintf ("Running child until next syscall\n");
	}
	r_reg_arena_swap (core->dbg->reg, R_TRUE);
	r_debug_continue_syscalls (core->dbg, syscalls, count);
	checkbpcallback (core);
	free (syscalls);
}

static void dot_r_graph_traverse(RCore *core, RGraph *t) {
	RGraphNode *n, *n2;
	RListIter *iter, *iter2;
	const char *gfont = r_config_get (core->config, "graph.font");
	r_cons_printf ("digraph code {\n"
		"graph [bgcolor=white];\n"
		"    node [color=lightgray, style=filled"
		" shape=box fontname=\"%s\" fontsize=\"8\"];\n", gfont);
	r_list_foreach (t->nodes, iter, n) {
		r_cons_printf ("\"0x%08"PFMT64x"\" [URL=\"0x%08"PFMT64x
			"\" color=\"lightgray\" label=\"0x%08"PFMT64x
			" (%d)\"]\n", n->addr, n->addr, n->addr, n->refs);
		r_list_foreach (n->children, iter2, n2) {
			r_cons_printf ("\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x
				"\" [color=\"red\"];\n", n->addr, n2->addr);
		}
	}
	r_cons_printf ("}\n");
}

static int checkbpcallback(RCore *core) ;
static int step_until(RCore *core, ut64 addr) {
	ut64 off = r_debug_reg_get (core->dbg, "pc");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return R_FALSE;
	}
	if (addr == 0LL) {
		eprintf ("Cannot continue until address 0\n");
		return R_FALSE;
	}
	do {
		r_debug_step (core->dbg, 1);
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		off = r_debug_reg_get (core->dbg, "pc");
		// check breakpoint here
	} while (off != addr);
	return R_TRUE;
}

static int step_until_esil(RCore *core, const char *esilstr) {
	if (!core || !esilstr || !core->dbg || !core->dbg->anal \
			|| !core->dbg->anal->esil) {
		eprintf ("Not initialized %p. Run 'aei' first.\n", core->anal->esil);
		return R_FALSE;
	}
	for (;;) {
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, -1, 0);
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		if (r_anal_esil_condition (core->anal->esil, esilstr)) {
			eprintf ("ESIL BREAK!\n");
			break;
		}
	}
	return R_TRUE;
}

/* until end of frame */
static int step_until_eof(RCore *core) {
	ut64 off, now = r_debug_reg_get (core->dbg, "sp");
	do {
		if (!r_debug_step (core->dbg, 1))
			break;
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		off = r_debug_reg_get (core->dbg, "sp");
		// check breakpoint here
	} while (off <= now);
	return R_TRUE;
}

static int step_line(RCore *core, int times) {
	char file[512], file2[512];
	int find_meta, line = -1, line2 = -1;
	char *tmp_ptr = NULL;
	ut64 off = r_debug_reg_get (core->dbg, "pc");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return R_FALSE;
	}
	file[0] = 0;
	file2[0] = 0;
	if (r_bin_addr2line (core->bin, off, file, sizeof (file), &line)) {
		char* ptr = r_file_slurp_line (file, line, 0);
		eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file, line);
		eprintf ("--> %s\n", ptr);
		find_meta = R_FALSE;
		free (ptr);
	} else {
		eprintf ("--> Stepping until dwarf line\n");
		find_meta = R_TRUE;
	}
	do {
		r_debug_step (core->dbg, 1);
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
		off = r_debug_reg_get (core->dbg, "pc");
		if (!r_bin_addr2line (core->bin, off, file2, sizeof (file2), &line2)) {
			if (find_meta)
				continue;
			eprintf ("Cannot retrieve dwarf info at 0x%08"PFMT64x"\n", off);
			return R_FALSE;
		}
	} while (!strcmp (file, file2) && line == line2);

	eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file2, line2);
	tmp_ptr = r_file_slurp_line (file2, line2, 0);
	eprintf ("--> %s\n", tmp_ptr);
	free (tmp_ptr);

	return R_TRUE;
}

static void cmd_debug_pid(RCore *core, const char *input) {
	const char *ptr;
	int pid, sig;
	switch (input[1]) {
	case 'k':
		/* stop, print, pass -- just use flags*/
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
		pid = atoi (input+2);
		ptr = strchr (input, ' ');
		sig = ptr? atoi (ptr+1): 0;
		if (pid > 0) {
			eprintf ("Sending signal '%d' to pid '%d'\n", sig, pid);
			r_debug_kill (core->dbg, 0, R_FALSE, sig);
		} else eprintf ("cmd_debug_pid: Invalid arguments (%s)\n", input);
		break;
	case 'n':
		eprintf ("TODO: debug_fork: %d\n", r_debug_child_fork (core->dbg));
		break;
	case 't':
		switch (input[2]) {
		case 'n':
			eprintf ("TODO: debug_clone: %d\n", r_debug_child_clone (core->dbg));
			break;
		case '=':
		case ' ':
			r_debug_select (core->dbg, core->dbg->pid,
				(int) r_num_math (core->num, input+3));
			break;
		default:
			r_debug_thread_list (core->dbg, core->dbg->pid);
			break;
		}
		break;
	case 'a':
		if (input[2]) {
			r_debug_attach (core->dbg, (int) r_num_math (
				core->num, input+2));
		} else {
			if (core->file && core->file->desc) {
				r_debug_attach (core->dbg, core->file->desc->fd);
			}
		}
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
		r_config_set_i (core->config, "dbg.swstep",
			(core->dbg->h && !core->dbg->h->canstep));
		r_core_cmdf (core, "=!pid %d", core->dbg->pid);
		break;
	case 'f':
		if (core->file && core->file->desc) {
			r_debug_select (core->dbg, core->file->desc->fd, core->dbg->tid);
		}
		break;
	case '=':
		r_debug_select (core->dbg,
			(int) r_num_math (core->num, input+2), core->dbg->tid);
		break;
	case '*':
		r_debug_pid_list (core->dbg, 0, 0);
		break;
	case 'j':
		r_debug_pid_list (core->dbg, core->dbg->pid, 'j');
		break;
	case 'e':
		{
			int pid = (input[2] == ' ')? atoi(input+2): core->dbg->pid;
			char *exe = r_sys_pid_to_path (pid);
			if (exe) {
				r_cons_printf ("%s\n", exe);
				free (exe);
			}
		}
		break;
	case ' ':
		r_debug_pid_list (core->dbg,
			(int) R_MAX (0, (int)r_num_math (core->num, input+2)), 0);
		break;
	case '?': {
			const char* help_msg[] = {
				"Usage:", "dp", " # Process commands",
				"dp", "", "List current pid and childrens",
				"dp", " <pid>", "List children of pid",
				"dp*", "", "List all attachable pids",
				"dp=", "<pid>", "Select pid",
				"dpa", " <pid>", "Attach and select pid",
				"dpe", "", "Show path to executable",
				"dpf", "", "Attach to pid like file fd // HACK",
				"dpk", " <pid> <signal>", "Send signal to process",
				"dpn", "", "Create new process (fork)",
				"dpnt", "", "Create new thread (clone)",
				"dpt", "", "List threads of current pid",
				"dpt", " <pid>", "List threads of process",
				"dpt=", "<thread>", "Attach to thread",
				NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	default:
		eprintf ("Selected: %d %d\n", core->dbg->pid, core->dbg->tid);
		r_debug_pid_list (core->dbg, core->dbg->pid, 0);
		break;
	}
}

static void cmd_debug_backtrace (RCore *core, const char *input) {
	RAnalOp analop;
	ut64 addr, len = r_num_math (core->num, input);
	if (len == 0) {
		r_bp_traptrace_list (core->dbg->bp);
	} else {
		ut64 oaddr = 0LL;
		eprintf ("Trap tracing 0x%08"PFMT64x"-0x%08"PFMT64x"\n",
			core->offset, core->offset+len);
		r_reg_arena_swap (core->dbg->reg, R_TRUE);
		r_bp_traptrace_reset (core->dbg->bp, R_TRUE);
		r_bp_traptrace_add (core->dbg->bp, core->offset, core->offset+len);
		r_bp_traptrace_enable (core->dbg->bp, R_TRUE);
		do {
			ut8 buf[32];
			r_debug_continue (core->dbg);
			if (checkbpcallback (core)) {
				eprintf ("Interrupted by breakpoint\n");
				break;
			}
			addr = r_debug_reg_get (core->dbg, "pc");
			if (addr == 0LL) {
				eprintf ("pc=0\n");
				break;
			}
			if (addr == oaddr) {
				eprintf ("pc=opc\n");
				break;
			}
			oaddr = addr;
			/* XXX Bottleneck..we need to reuse the bytes read by traptrace */
			// XXX Do asm.arch should define the max size of opcode?
			r_core_read_at (core, addr, buf, 32); // XXX longer opcodes?
			r_anal_op (core->anal, &analop, addr, buf, sizeof (buf));
		} while (r_bp_traptrace_at (core->dbg->bp, addr, analop.size));
		r_bp_traptrace_enable (core->dbg->bp, R_FALSE);
	}
}

static int cmd_debug_map(RCore *core, const char *input) {
	char file[128];
	RListIter *iter;
	RDebugMap *map;
	ut64 addr = core->offset;

	switch (input[0]) {
	case '?': {
			const char* help_msg[] = {
			"Usage:", "dm", " # Memory maps commands",
			"dm", "", "List memory maps of target process",
			"dm", " <address> <size>", "Allocate <size> bytes at <address> (anywhere if address is -1) in child process",
			"dm*", "", "List memmaps in radare commands",
			"dm-", "<address>", "Deallocate memory map of <address>",
			"dmd", " [file]", "Dump current debug map region to a file (from-to.dmp) (see Sd)",
			"dmi", " [addr|libname] [symname]", "List symbols of target lib",
			"dmi*", " [addr|libname] [symname]", "List symbols of target lib in radare commands",
			"dmj", "", "List memmaps in JSON format",
			"dml", " <file>", "Load contents of file into the current map region (see Sl)",
			"dmp", " <address> <size> <perms>", "Change page at <address> with <size>, protection <perms> (rwx)",
			//"dm, " rw- esp 9K", "set 9KB of the stack as read+write (no exec)",
			"TODO:", "", "map files in process memory. (dmf file @ [addr])",
			NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	case 'p':
		if (input[1] == ' ') {
			int perms;
			char *p, *q;
			ut64 size, addr;
			p = strchr (input+2, ' ');
			if (p) {
				*p++ = 0;
				q = strchr (p, ' ');
				if (q) {
					*q++ = 0;
					addr = r_num_math (core->num, input+2);
					size = r_num_math (core->num, p);
					perms = r_str_rwx (q);
					eprintf ("(%s)(%s)(%s)\n", input+2, p, q);
					eprintf ("0x%08"PFMT64x" %d %o\n", addr, (int) size, perms);
					r_debug_map_protect (core->dbg, addr, size, perms);
				} else eprintf ("See dm?\n");
			} else eprintf ("See dm?\n");
		} else eprintf ("See dm?\n");
		break;
	case 'd':
		r_debug_map_sync (core->dbg); // update process memory maps
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				ut8 *buf = malloc (map->size);
				//TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", map->size);
					return R_FALSE;
				}
				r_io_read_at (core->io, map->addr, buf, map->size);
				if (input[1]==' ' && input[2]) {
					snprintf (file, sizeof (file), "%s", input+2);
				} else snprintf (file, sizeof (file),
					"0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
					map->addr, map->addr_end, r_str_rwx_i (map->perm));
				if (!r_file_dump (file, buf, map->size)) {
					eprintf ("Cannot write '%s'\n", file);
					free (buf);
					return R_FALSE;
				}
				eprintf ("Dumped %d bytes into %s\n", (int)map->size, file);
				free (buf);
				return R_TRUE;
			}
		}
		eprintf ("No debug region found here\n");
		return R_FALSE;
	case 'l':
		if (input[1] != ' ') {
			eprintf ("Usage: dml [file]\n");
			return R_FALSE;
		}
		r_debug_map_sync (core->dbg); // update process memory maps
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				int sz;
				char *buf = r_file_slurp (input+2, &sz);
				//TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", map->size);
					return R_FALSE;
				}
				r_io_write_at (core->io, map->addr, (const ut8*)buf, sz);
				if (sz != map->size)
					eprintf	("File size differs from region size (%d vs %"PFMT64d")\n",
						sz, map->size);
				eprintf ("Loaded %d bytes into the map region at 0x%08"PFMT64x"\n",
					sz, map->addr);
				free (buf);
				return R_TRUE;
			}
		}
		eprintf ("No debug region found here\n");
		return R_FALSE;
	case 'i':
		{ // Move to a separate function
		RCoreBinFilter filter;
		const char *libname = NULL, *symname = NULL;
		char *ptr = strdup (r_str_trim_head ((char*)input+2));
		int i;
		ut64 baddr;

		addr = 0LL;
		i = r_str_word_set0 (ptr);
		switch (i) {
		case 2: // get symname
			symname = r_str_word_get0 (ptr, 1);
		case 1: // get addr|libname
			addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			if (!addr) libname = r_str_word_get0 (ptr, 0);
		}
		r_debug_map_sync (core->dbg); // update process memory maps
		r_list_foreach (core->dbg->maps, iter, map) {
			if (core && core->bin && core->bin->cur && core->bin->cur->o && \
					((addr != -1 && (addr >= map->addr && addr < map->addr_end)) ||
					(libname != NULL && (strstr (map->name, libname))))) {
				RBinObject *o = core->bin->cur->o;
				filter.offset = 0LL;
				filter.name = (char *)symname;
				baddr = o->baddr;
				o->baddr = map->addr;
				r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, (input[1]=='*'),
						R_TRUE, &filter, 0, NULL);
				o->baddr = baddr;
				break;
			}
		}
		free (ptr);
		}
		break;
	case ' ':
		{
			char *p;
			int size;
			p = strchr (input+2, ' ');
			if (p) {
				*p++ = 0;
				addr = r_num_math (core->num, input+1);
				size = r_num_math (core->num, p);
				r_debug_map_alloc(core->dbg, addr, size);
			} else {
				eprintf ("Usage: dm addr size\n");
				return R_FALSE;
			}
		}
		break;
	case '-':
		addr = r_num_math (core->num, input+2);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				r_debug_map_dealloc(core->dbg, map);
				r_debug_map_sync (core->dbg);
				return R_TRUE;
			}
		}
		eprintf ("The address doesn't match with any map.\n");
		break;
	case '\0':
	case '*':
	case 'j':
		r_debug_map_sync (core->dbg); // update process memory maps
		r_debug_map_list (core->dbg, core->offset, input[0]);
		break;
	}
	return R_TRUE;
}

static void cmd_debug_reg(RCore *core, const char *str) {
	int size, i, type = R_REG_TYPE_GPR;
	int bits = (core->dbg->bits & R_SYS_BITS_64)? 64: 32;
	int use_colors = r_config_get_i(core->config, "scr.color");
	const char *use_color;
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP(creg): Color_BWHITE;
	} else {
		use_color = NULL;
	}
	struct r_reg_item_t *r;
	const char *name;
	char *arg;
	switch (str[0]) {
	case '-':
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, '-', 0);
		break;
	case '?':
		if (str[1]) {
			ut64 off;
			r_debug_reg_sync (core->dbg, -1, 0); //R_REG_TYPE_GPR, R_FALSE);
			off = r_debug_reg_get (core->dbg, str+1);
	//		r = r_reg_get (core->dbg->reg, str+1, 0);
	//		if (r == NULL) eprintf ("Unknown register (%s)\n", str+1);
			r_cons_printf ("0x%08"PFMT64x"\n", off);
			core->num->value = off;
			//r_reg_get_value (core->dbg->reg, r));
		} else {
			const char * help_message[] = {
				"Usage: dr", "", "Registers commands",
				"dr", "", "Show 'gpr' registers",
				"dr", " 16", "Show 16 bit registers",
				"dr", " 32", "Show 32 bit registers",
				"dr", " all", "Show all registers",
				"dr", " <type>", "Show flag registers",
				"dr", " <register>=<val>", "Set register value",
				"dr=", "", "Show registers in columns",
				"dr?", "<register>", "Show value of given register",
				"drb", " [type]", "Display hexdump of gpr arena (WIP)",
				"drc", " [name]", "Related to conditional flag registers",
				"drd", "", "Show only different registers",
				"drl", "", "List all register names",
				"drn", " <pc>", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
				"dro", "", "Show previous (old) values of registers",
				"drp", " <file>", "Load register metadata file",
				"drp", "", "Display current register profile",
				"drs", " [?]", "Stack register states",
				"drt", "", "Show all register types",
				"drx", "", "Show all debug registers",
				"drx", " number addr len rwx", "Modify hardware breakpoint",
				"drx-", "number", "Clear hardware breakpoint",
				".dr", "*", "Include common register values in flags",
				".dr", "-", "Unflag all registers",
				NULL
			};
			// TODO: 'drs' to swap register arenas and display old register valuez

			r_core_cmd_help (core, help_message);
		}
		break;
	case 'l':
		//r_core_cmd0 (core, "drp~[1]");
		{
			RRegSet *rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
			if (rs) {
				RRegItem *r;
				RListIter *iter;
				r_list_foreach (rs->regs, iter, r) {
					r_cons_printf ("%s\n", r->name);
				}
			}
		}
		break;
	case 'b':
		{ // WORK IN PROGRESS // DEBUG COMMAND
		int len;
		const ut8 *buf = r_reg_get_bytes (core->dbg->reg, R_REG_TYPE_GPR, &len);
		//r_print_hexdump (core->print, 0LL, buf, len, 16, 16);
		r_print_hexdump (core->print, 0LL, buf, len, 32, 4);
		}
		break;
	case 'c':
// TODO: set flag values with drc zf=1
		{
		RRegItem *r;
		const char *name = str+1;
		while (*name==' ') name++;
		if (*name && name[1]) {
			r = r_reg_cond_get (core->dbg->reg, name);
			if (r) {
				r_cons_printf ("%s\n", r->name);
			} else {
				int id = r_reg_cond_from_string (name);
				RRegFlags* rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					int o = r_reg_cond_bits (core->dbg->reg, id, rf);
					core->num->value = o;
					// ORLY?
					r_cons_printf ("%d\n", o);
free (rf);
				} else eprintf ("unknown conditional or flag register\n");
			}
		} else {
			RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
			if (rf) {
				r_cons_printf ("| s:%d z:%d c:%d o:%d p:%d\n",
					rf->s, rf->z, rf->c, rf->o, rf->p);
				if (*name=='=') {
					for (i=0; i<R_REG_COND_LAST; i++) {
						r_cons_printf ("%s:%d ",
							r_reg_cond_to_string (i),
							r_reg_cond_bits (core->dbg->reg, i, rf));
					}
					r_cons_newline ();
				} else {
					for (i=0; i<R_REG_COND_LAST; i++) {
						r_cons_printf ("%d %s\n",
							r_reg_cond_bits (core->dbg->reg, i, rf),
							r_reg_cond_to_string (i));
					}
				}
				free (rf);
			}
		}
		}
		break;
	case 'x':
		switch (str[1]) {
		case '-':
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_FALSE);
			r_debug_drx_unset (core->dbg, atoi (str+2));
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_TRUE);
			break;
		case ' ': {
			char *s = strdup (str+2);
			char sl, n, rwx;
			int len;
			ut64 off;

			sl = r_str_word_set0 (s);
			if (sl == 4) {
#define ARG(x) r_str_word_get0(s,x)
				n = (char)r_num_math (core->num, ARG(0));
				off = r_num_math (core->num, ARG(1));
				len = (int)r_num_math (core->num, ARG(2));
				rwx = (char)r_str_rwx (ARG(3));
				if (len== -1) {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_FALSE);
					r_debug_drx_set (core->dbg, n, 0, 0, 0, 0);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_TRUE);
				} else {
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_FALSE);
					r_debug_drx_set (core->dbg, n, off, len, rwx, 0);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_TRUE);
				}
			} else eprintf ("|Usage: drx N [address] [length] [rwx]\n");
			free (s);
			} break;
		case '\0':
			r_debug_reg_sync (core->dbg, R_REG_TYPE_DRX, R_FALSE);
			r_debug_drx_list (core->dbg);
			break;
		default: {
			const char * help_message[] = {
				"Usage: drx", "", "Hardware breakpoints commands",
				"drx", "", "List all (x86?) hardware breakpoints",
				"drx", " <number> <address> <length> <perms>", "Modify hardware breakpoint",
				"drx-", "<number>", "Clear hardware breakpoint",
				NULL
			};
			r_core_cmd_help (core, help_message);
			}
			break;
		}
		break;
	case 's':
		switch (str[1]) {
		case '-':
			r_reg_arena_pop (core->dbg->reg);
			// restore debug registers if in debugger mode
			r_debug_reg_sync (core->dbg, 0, 1);
			break;
		case '+':
			r_reg_arena_push (core->dbg->reg);
			break;
		case '?': {
			const char * help_message[] = {
				"Usage: drs", "", "Register states commands",
				"drs", "", "List register stack",
				"drs", "+", "Push register state",
				"drs", "-", "Pop register state",
				NULL
			};
			r_core_cmd_help (core, help_message);
			}
			break;
		default:
			r_cons_printf ("%d\n", r_list_length (
				core->dbg->reg->regset[0].pool));
			break;
		}
		break;
	case 'p':
		if (!str[1]) {
			if (core->dbg->reg->reg_profile_str) {
				//core->anal->reg = core->dbg->reg;
				r_cons_printf ("%s\n", core->dbg->reg->reg_profile_str);
				//r_cons_printf ("%s\n", core->anal->reg->reg_profile);
			} else eprintf ("No register profile defined. Try 'dr.'\n");
		} else r_reg_set_profile (core->dbg->reg, str+2);
		break;
	case 't':
		for (i=0; (name=r_reg_get_type (i)); i++)
			r_cons_printf ("%s\n", name);
		break;
	case 'n':
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str+2));
		if (name && *name)
			r_cons_printf ("%s\n", name);
		else eprintf ("Oops. try drn [pc|sp|bp|a0|a1|a2|a3|zf|sf|nf|of]\n");
		break;
	case 'd':
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3, use_color); // XXX detect which one is current usage
		break;
	case 'o':
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0, use_color); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		break;
	case '=':
		if (r_config_get_i (core->config, "cfg.debug")) {
			if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
				r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 2, use_color); // XXX detect which one is current usage
			} //else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		} else {
			RReg *orig = core->dbg->reg;
			core->dbg->reg = core->anal->reg;
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 2, use_color); // XXX detect which one is current usage
			core->dbg->reg = orig;
		}
		break;
	case '*':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE))
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, '*', use_color);
		break;
	case 'r': // "drr"
		{
		ut64 type, value;
		int bits = core->assembler->bits;
		RList *list = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		RAnalFunction *fcn;
		RListIter *iter;
		RFlagItem *fi;
		RRegItem *r;
		r_list_foreach (list, iter, r) {
			if (r->size != bits)
				continue;
			value = r_reg_get_value (core->dbg->reg, r);
			fi = r_flag_get_i2 (core->flags, value);
			type = r_core_anal_address (core, value);
			fcn = r_anal_get_fcn_in (core->anal, value, 0);
			if (bits==64) {
				r_cons_printf ("%6s 0x%016"PFMT64x, r->name, value);
			} else {
				r_cons_printf ("%6s 0x%08"PFMT64x, r->name, value);
			}
			if (value && fi) {
				if (strcmp (fi->name, r->name))
					r_cons_printf (" %s", fi->name);
			}
			if (fcn) {
				if (strcmp (fcn->name, r->name))
					r_cons_printf (" %s", fcn->name);
			}
			if (type) {
				const char *c = r_core_anal_optype_colorfor (core, value);
				const char *cend = (c&&*c)? Color_RESET: "";
				if (!c) c = "";
				if (type & R_ANAL_ADDR_TYPE_HEAP) {
					r_cons_printf (" %sheap%s", c, cend);
				} else if (type & R_ANAL_ADDR_TYPE_STACK) {
					r_cons_printf (" %sstack%s", c, cend);
				}
				if (type & R_ANAL_ADDR_TYPE_PROGRAM)
					r_cons_printf (" %sprogram%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_LIBRARY)
					r_cons_printf (" %slibrary%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_ASCII)
					r_cons_printf (" %sascii%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
					r_cons_printf (" %ssequence%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_READ)
					r_cons_printf (" %sR%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_WRITE)
					r_cons_printf (" %sW%s", c, cend);
				if (type & R_ANAL_ADDR_TYPE_EXEC)
					r_cons_printf (" %sX%s", c, cend);
			}
			r_cons_newline ();
		}
		}
		break;
	case 'j':
	case '\0':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, str[0], use_color);
		} else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case ' ':
		arg = strchr (str+1, '=');
		if (arg) {
			char *string;
			const char *regname;
			*arg = 0;
			string = r_str_chop (strdup (str+1));
			regname = r_reg_get_name (core->dbg->reg,
				r_reg_get_name_idx (string));
			if (!regname)
				regname = string;
			r = r_reg_get (core->dbg->reg, regname, -1); //R_REG_TYPE_GPR);
			if (r) {
				if (r->flags) {
					r_cons_printf ("0x%08"PFMT64x" ->",
							r_reg_get_value (core->dbg->reg, r));
					r_reg_set_bvalue (core->dbg->reg, r, arg+1);
					r_debug_reg_sync (core->dbg, -1, R_TRUE);
					r_cons_printf ("0x%08"PFMT64x"\n",
							r_reg_get_value (core->dbg->reg, r));
				} else {
					r_cons_printf ("0x%08"PFMT64x" ->", str,
							r_reg_get_value (core->dbg->reg, r));
					r_reg_set_value (core->dbg->reg, r,
							r_num_math (core->num, arg+1));
					r_debug_reg_sync (core->dbg, -1, R_TRUE);
					r_cons_printf ("0x%08"PFMT64x"\n",
							r_reg_get_value (core->dbg->reg, r));
				}
			} else eprintf ("Unknown register '%s'\n", string);
			free (string);
			return;
		} else {
			int role = r_reg_get_name_idx (str+1);
			const char *regname = r_reg_get_name (core->dbg->reg, role);
			if (!regname)
				regname = str+1;
			size = atoi (regname);
			if (size==0) {
				arg = strchr (str+1, ' ');
				if (arg && size==0) {
					*arg='\0';
					size = atoi (arg);
				} else size = bits;
				type = r_reg_type_by_name (str+1);
			}
			if (type != R_REG_TYPE_LAST) {
				r_debug_reg_sync (core->dbg, type, R_FALSE);
				r_debug_reg_list (core->dbg, type, size, str[0]=='*', use_color);
			} else eprintf ("cmd_debug_reg: Unknown type\n");
		}
	}
}

static int checkbpcallback(RCore *core) {
	ut64 pc = r_debug_reg_get (core->dbg, "pc");
	RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, pc);
	if (bpi) {
		const char *cmdbp = r_config_get (core->config, "cmd.bp");
		if (bpi->data)
			r_core_cmd (core, bpi->data, 0);
		if (cmdbp && *cmdbp)
			r_core_cmd (core, cmdbp, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

static int bypassbp(RCore *core) {
	RBreakpointItem *bpi;
	ut64 addr;
	r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
	addr = r_debug_reg_get (core->dbg, "pc");
	bpi = r_bp_get_at (core->dbg->bp, addr);
	if (!bpi) return R_FALSE;
	/* XXX 2 if libr/debug/debug.c:226 is enabled */
	r_debug_step (core->dbg, 1);
	return R_TRUE;
}

static int validAddress(RCore *core, ut64 addr) {
	ut8 buf[8];
	int word = r_io_read_at (core->io, addr, buf, 8);
	core->num->value = 1;
	if (word != 8)
		return 0;
	core->num->value = 0;
	return 1;
}

static void static_debug_stop(void *u) {
	RDebug *dbg = (RDebug *)u;
	r_debug_stop (dbg);
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	int i, hwbp = r_config_get_i (core->config, "dbg.hwbp");
	RDebugFrame *frame;
	RListIter *iter;
	const char *p;
	RList *list;
	ut64 addr;
	p = strchr (input, ' ');
	if (p) {
		addr = r_num_math (core->num, p+1);
	} else addr = 0;
	switch (input[1]) {
	case 't':
		switch (input[2]) {
		case 'e':
			for (p=input+3; *p==' ';p++);
			if (*p == '*') {
				r_bp_set_trace_all(core->dbg->bp,R_TRUE);
			} else	if (!r_bp_set_trace (core->dbg->bp, addr, R_TRUE))
				eprintf ("Cannot set tracepoint\n");
			break;
		case 'd':
			for (p=input+3; *p==' ';p++);
			if (*p == '*') {
				r_bp_set_trace_all(core->dbg->bp,R_FALSE);
			} else if (!r_bp_set_trace (core->dbg->bp, addr, R_FALSE))
				eprintf ("Cannot unset tracepoint\n");
			break;
		case 's':
			{
			RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
			if (bpi) {
				bpi->trace = !!!bpi->trace;
			} else {
				eprintf ("Cannot unset tracepoint\n");
			}
			}
			break;
		case 0:
			addr = UT64_MAX;
			if (input[2]==' ' && input[3])
				addr = r_num_math (core->num, input+2);
			i = 0;
			list = r_debug_frames (core->dbg, addr);
			r_list_foreach (list, iter, frame) {
				r_cons_printf ("%d  0x%08"PFMT64x"  %d\n",
					i++, frame->addr, frame->size);
			}
			r_list_purge (list);
			break;
		default:
			eprintf ("See db?\n");
			break;
		}
		break;
	case '*': r_bp_list (core->dbg->bp, 1); break;
	case '\0': r_bp_list (core->dbg->bp, 0); break;
	case '-':
		if (input[2] == '*') {
			r_bp_del_all (core->dbg->bp);
		} else r_bp_del (core->dbg->bp, r_num_math (core->num, input+2));
		break;
	case 'c':
		addr = r_num_math (core->num, input+2);
		RBreakpointItem *bpi = r_bp_get_at (core->dbg->bp, addr);
		if (bpi) {
			char *arg = strchr (input+2, ' ');
			if (arg)
				arg = strchr (arg+1, ' ');
			if (arg) {
				free (bpi->data);
				bpi->data = strdup (arg+1);
			} else {
				free (bpi->data);
				bpi->data = NULL;
			}
		} else eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", addr);
		break;
	case 's':
		addr = r_num_math (core->num, input+2);
		RBreakpointItem *bp = r_bp_get_at (core->dbg->bp, addr);
		if (bp) {
			//bp->enabled = !bp->enabled;
			r_bp_del (core->dbg->bp, addr);
		} else {
			if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
		}
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 0);
		break;
	case 'e':
		for (p=input+2; *p==' ';p++);
		if (*p == '*') {
			r_bp_enable_all (core->dbg->bp,R_TRUE);
		} else r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), R_TRUE);
		break;
	case 'd':
		for (p=input+2; *p==' ';p++);
		if (*p == '*') {
			r_bp_enable_all (core->dbg->bp,R_FALSE);
		} r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), R_FALSE);
		break;
	case 'h':
		if (input[2]==' ') {
			if (!r_bp_use (core->dbg->bp, input+3))
				eprintf ("Invalid name: '%s'.\n", input+3);
		} else r_bp_plugin_list (core->dbg->bp);
		break;
	case ' ':
		for (p=input+1; *p==' ';p++);
		if (*p == '-') {
			r_bp_del (core->dbg->bp, r_num_math (core->num, p+1));
		} else {
			addr = r_num_math (core->num, input+2);
			if (validAddress (core, addr)) {
				if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
				else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
				if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
			} else eprintf ("Can't place a breakpoint here. No mapped memory\n");
		}
		break;
	case 'i':
		switch (input[2]) {
		case 0: // "dbi"
			{
			int i = 0;
			for (i=0;i<core->dbg->bp->bps_idx_count;i++) {
				RBreakpointItem *bpi = core->dbg->bp->bps_idx[i];
				if (bpi) {
					r_cons_printf ("%d 0x%08"PFMT64x" E:%d T:%d\n",
						i, bpi->addr, bpi->enabled, bpi->trace);
				}
			}
			}
			break;
		case 'c': // "dbic"
			{
				const char *cmd = strchr (input+3, ' ');
				if (cmd) {
					RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
					if (bpi) { bpi->data = strdup (cmd+1); }
					else { eprintf ("Cannot set command\n"); }
				} else {
					eprintf ("|Usage: dbic # cmd\n");
				}
			}
			break;
		case 'e': // "dbie"
			{
				RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
				if (bpi) { bpi->enabled = R_TRUE; }
				else { eprintf ("Cannot unset tracepoint\n"); }
			}
			break;
		case 'd': // "dbid"
			{
				RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
				if (bpi) { bpi->enabled = R_FALSE; }
				else { eprintf ("Cannot unset tracepoint\n"); }
			}
			break;
		case 's': // "dbis"
			{
				RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
				if (bpi) { bpi->enabled = !!!bpi->enabled; }
				else { eprintf ("Cannot unset tracepoint\n"); }
			}
			break;
		case 't': // "dbite" "dbitd" ...
			switch (input[3]) {
			case 'e':
				{
					RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
					if (bpi) { bpi->trace = R_TRUE; }
					else { eprintf ("Cannot unset tracepoint\n"); }
				}
				break;
			case 'd':
				{
					RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
					if (bpi) { bpi->trace = R_FALSE; }
					else { eprintf ("Cannot unset tracepoint\n"); }
				}
				break;
			case 's':
				{
					RBreakpointItem *bpi = r_bp_get_index (core->dbg->bp, addr);
					if (bpi) { bpi->trace = !!!bpi->trace; }
					else { eprintf ("Cannot unset tracepoint\n"); }
				}
				break;
			}
			break;
		}
		break;
	case '?':
	default:{
			const char* help_msg[] = {
				"Usage: db", "", " # Breakpoints commands",
				"db", "", "List breakpoints",
				"db", " sym.main", "Add breakpoint into sym.main",
				"db", " <addr>", "Add breakpoint",
				"db", " -<addr>", "Remove breakpoint",
				// "dbi", " 0x848 ecx=3", "stop execution when condition matches",
				"dbc", " <addr> <cmd>", "Run command when breakpoint is hit",
				"dbd", " <addr>", "Disable breakpoint",
				"dbe", " <addr>", "Enable breakpoint",
				"dbs", " <addr>", "Toggle breakpoint",

				"dbte", " <addr>", "Enable Breakpoint Trace",
				"dbtd", " <addr>", "Disable Breakpoint Trace",
				"dbts", " <addr>", "Swap Breakpoint Trace",
				//
				"dbi", "", "List breakpoint indexes",
				"dbic", " <index> <cmd>", "Run command at breakpoint index",
				"dbie", " <index>", "Enable breakpoint by index",
				"dbid", " <index>", "Disable breakpoint by index",
				"dbis", " <index>", "Swap Nth breakpoint",
				"dbite", " <index>", "Enable breakpoint Trace by index",
				"dbitd", " <index>", "Disable breakpoint Trace by index",
				"dbits", " <index>", "Swap Nth breakpoint trace",
				//
				"dbh", " x86", "Set/list breakpoint plugin handlers",
				NULL};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
}

static void r_core_debug_trace_calls (RCore *core) {
	int n = 0, t = core->dbg->trace->enabled;
	/*RGraphNode *gn;*/
	core->dbg->trace->enabled = 0;
	r_graph_plant (core->dbg->graph);
	r_cons_break (static_debug_stop, core->dbg);
	r_reg_arena_swap (core->dbg->reg, R_TRUE);
	for (;;) {
		ut8 buf[32];
		ut64 addr;
		RAnalOp aop;
		if (r_cons_singleton ()->breaked)
			break;
		if (r_debug_is_dead (core->dbg))
			break;
		if (!r_debug_step (core->dbg, 1))
			break;
		if (!r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE))
			break;
		addr = r_debug_reg_get (core->dbg, "pc");
		r_io_read_at (core->io, addr, buf, sizeof (buf));
		r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
		eprintf (" %d %"PFMT64x"\r", n++, addr);
		switch (aop.type) {
			case R_ANAL_OP_TYPE_UCALL:
				// store regs
				// step into
				// get pc
				r_debug_step (core->dbg, 1);
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
				addr = r_debug_reg_get (core->dbg, "pc");
				//eprintf ("0x%08"PFMT64x" ucall. computation may fail\n", addr);
				r_graph_push (core->dbg->graph, addr, NULL);
				// TODO: push pc+aop.length into the call path stack
				break;
			case R_ANAL_OP_TYPE_CALL:
				r_graph_push (core->dbg->graph, addr, NULL);
				break;
			case R_ANAL_OP_TYPE_RET:
#if 0
				// TODO: we must store ret value for each call in the graph path to do this check
				r_debug_step (core->dbg, 1);
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
				addr = r_debug_reg_get (core->dbg, "pc");
				// TODO: step into and check return address if correct
				// if not correct we are hijacking the control flow (exploit!)
#endif
				/*gn =*/ r_graph_pop (core->dbg->graph);
#if 0
				if (addr != gn->addr) {
					eprintf ("Oops. invalid return address 0x%08"PFMT64x
							"\n0x%08"PFMT64x"\n", addr, gn->addr);
				}
#endif
				break;
		}
		if (checkbpcallback (core)) {
			eprintf ("Interrupted by a breakpoint\n");
			break;
		}
	}
	r_graph_traverse (core->dbg->graph);
	core->dbg->trace->enabled = t;
	r_cons_break_end();
}

static void r_core_debug_kill (RCore *core, const char *input) {
	if (!input || *input=='?') {
		if (input && input[1]) {
			const char *signame, *arg = input+1;
			int signum = atoi (arg);
			if (signum>0) {
				signame = r_debug_signal_resolve_i (core->dbg, signum);
				if (signame)
					r_cons_printf ("%s\n", signame);
			} else {
				signum = r_debug_signal_resolve (core->dbg, arg);
				if (signum>0)
					r_cons_printf ("%d\n", signum);
			}
		} else {
			const char * help_message[] = {
				"Usage: dk", "", "Signal commands",
				"dk", "", "List all signal handlers of child process",
				"dk", " <signal>", "Send KILL signal to child",
				"dk", " <signal>=1", "Set signal handler for <signal> in child",
				"dk?", "<signal>", "Name/signum resolver",
				"dko", " <signal>", "Reset skip or cont options for given signal",
				"dko", " <signal> [|skip|cont]", "On signal SKIP handler or CONT into",
				NULL
			};
			r_core_cmd_help (core, help_message);
		}
	} else if (*input=='o') {
		char *p, *name = strdup (input+2);
		int signum = atoi (name);
		p = strchr (name, ' ');
		if (p) {
			*p++ = 0;
			// Actions:
			//  - pass
			//  - trace
			//  - stop
			if (signum<1) signum = r_debug_signal_resolve (core->dbg, name);
			if (signum>0) {
				if (strchr (p, 's')) {
					r_debug_signal_setup (core->dbg, signum, R_DBG_SIGNAL_SKIP);
				} else if (strchr (p, 'c')) {
					r_debug_signal_setup (core->dbg, signum, R_DBG_SIGNAL_CONT);
				} else {
					eprintf ("Invalid option\n");
				}
			} else {
				eprintf ("Invalid signal\n");
			}
		} else {
			switch (input[1]) {
			case 0:
				r_debug_signal_list (core->dbg, 1);
				break;
			case '?':
				eprintf ("|Usage: dko SIGNAL [skip|cont]\n"
					"| 'SIGNAL' can be a number or a string that resolves with dk?..\n"
					"| s - skip (do not enter into the signal handler\n"
					"| c - continue into the signal handler\n"
					"|   - no option means stop when signal is catched\n");
				break;
			default:
				if (signum<1) signum = r_debug_signal_resolve (core->dbg, name);
				r_debug_signal_setup (core->dbg, signum, 0);
				break;
			}
		}
		free (name);
	} else if (!*input) {
		r_debug_signal_list (core->dbg, 0);
#if 0
		RListIter *iter;
		RDebugSignal *ds;
		eprintf ("TODO: list signal handlers of child\n");
		RList *list = r_debug_kill_list (core->dbg);
		r_list_foreach (list, iter, ds) {
			// TODO: resolve signal name by number and show handler offset
			eprintf ("--> %d\n", ds->num);
		}
		r_list_free (list);
#endif
	} else {
		int sig = atoi (input);
		char *p = strchr (input, '=');
		if (p) {
			r_debug_kill_setup (core->dbg, sig, r_num_math (core->num, p+1));
		} else {
			r_debug_kill (core->dbg, core->dbg->pid, core->dbg->tid, sig);
		}
	}
}

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, times=0, follow=0;
	ut64 addr;
	char *ptr;

	if (r_sandbox_enable (0)) {
		eprintf ("Debugger commands disabled in sandbox mode\n");
		return 0;
	}

	switch (input[0]) {
	case 't':
// TODO: define ranges? to display only some traces, allow to scroll on this disasm? ~.. ?
		switch (input[1]) {
		case '?': {
			const char * help_message[] = {
				"Usage: dt", "", "Trace commands",
				"dt", "", "List all traces ",
				"dtd", "", "List all traced disassembled",
				"dtc", "", "Trace call/ret",
				"dtg", "", "Graph call/ret trace",
				"dtr", "", "Reset traces (instruction//cals)",
				NULL
			};
			r_core_cmd_help (core, help_message);
			}
			break;
		case 'c': // "dtc"
			if (r_debug_is_dead (core->dbg))
				eprintf ("No process to debug.");
			else r_core_debug_trace_calls (core);
			break;
		case 'd':
			// TODO: reimplement using the api
			r_core_cmd0 (core, "pd 1 @@= `dt~[0]`");
			break;
		case 'g': // "dtg"
			dot_r_graph_traverse (core, core->dbg->graph);
			break;
		case 'r':
			r_graph_reset (core->dbg->graph);
			r_debug_trace_free (core->dbg);
			core->dbg->trace = r_debug_trace_new ();
			break;
		case '\0':
			r_debug_trace_list (core->dbg, -1);
			break;
		default:
			eprintf ("Wrong arg. See dt?\n");
			break;
		}
		break;
	case 'd':
		switch (input[1]) {
		case '\0':
			r_debug_desc_list (core->dbg, 0);
			break;
		case '*':
			r_debug_desc_list (core->dbg, 1);
			break;
		case 's':
			// r_debug_desc_seek()
			break;
		case 'd':
			// r_debug_desc_dup()
			break;
		case 'r':
			// r_debug_desc_read()
			break;
		case 'w':
			// r_debug_desc_write()
			break;
		case '-':
			// close file
			//r_core_syscallf (core, "close", "%d", atoi (input+2));
			r_core_cmdf (core, "dis close %d", atoi (input+2));
			// TODO: run
			break;
		case ' ':
			// TODO: handle read, readwrite, append
			r_core_syscallf (core, "open", "%s, %d, %d",
				input+2, 2, 0644);
			// open file
			break;
		case '?':
		default: {
			const char * help_message[] = {
				"Usage: dd", "", "Descriptors commands",
				"dd", "", "List file descriptors",
				"dd", " <file>", "Open and map that file into the UI",
				"dd-", "<fd>", "Close stdout fd",
				"dd*", "", "List file descriptors (in radare commands)",
				NULL
			};
			r_core_cmd_help (core, help_message);
			}
			break;
		}
		break;
	case 's':
		if (strlen (input) > 2)
			times = atoi (input+2);
		if (times<1) times = 1;
		switch (input[1]) {
		case '?': {
			const char * help_message[] = {
				"Usage: ds", "", "Step commands",
				"ds", "", "Step one instruction",
				"ds", " <num>", "Step <num> instructions",
				"dsf", "", "Step until end of frame",
				"dsi", " <cond>", "Continue until condition matches",
				"dsl", "", "Step one source line",
				"dsl", " <num>", "Step <num> source lines",
				"dso", " <num>", "Step over <num> instructions",
				"dsp", "", "Step into program (skip libs)",
				"dss", " <num>", "Skip <num> step instructions",
				"dsu", " <address>", "Step until address",
				"dsue", " <esil>", "Step until esil expression matches",
				NULL
			};

			r_core_cmd_help (core, help_message);
			}
			break;
		case 'i':
			if (input[2] == ' ') {
				int n = 0;
				r_cons_break (static_debug_stop, core->dbg);
				do {
					if (r_cons_singleton ()->breaked)
						break;
					r_debug_step (core->dbg, 1);
					if (r_debug_is_dead (core->dbg))
						break;
					if (checkbpcallback (core)) {
						eprintf ("Interrupted by a breakpoint\n");
						break;
					}
					r_core_cmd0 (core, ".dr*");
					n++;
				} while (!r_num_conditional (core->num, input+3));
				eprintf ("Stopped after %d instructions\n", n);
			} else {
				eprintf ("Missing argument\n");
			}
			break;
		case 'f':
			step_until_eof (core);
			break;
		case 'u':
			if (input[2]=='e') {
				step_until_esil (core, input+3);
			} else {
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				step_until (core, r_num_math (core->num, input+2)); // XXX dupped by times
			}
			break;
		case 'p':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			for (i=0; i<times; i++) {
				ut8 buf[64];
				ut64 addr;
				RAnalOp aop;
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
				addr = r_debug_reg_get (core->dbg, "pc");
				r_io_read_at (core->io, addr, buf, sizeof (buf));
				r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
				if (aop.type == R_ANAL_OP_TYPE_CALL) {
					RIOSection *s = r_io_section_vget (core->io, aop.jump);
					if (!s) {
						r_debug_step_over (core->dbg, times);
						continue;
					}
				}
				r_debug_step (core->dbg, 1);
				if (checkbpcallback (core)) {
					eprintf ("Interrupted by a breakpoint\n");
					break;
				}
			}
			break;
		case 's':
			{
			ut64 addr = r_debug_reg_get (core->dbg, "pc");
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			for (i=0; i<times; i++) {
				ut8 buf[64];
				RAnalOp aop;
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
				r_io_read_at (core->io, addr, buf, sizeof (buf));
				r_anal_op (core->anal, &aop, addr, buf, sizeof (buf));
				if (aop.jump != UT64_MAX && aop.fail != UT64_MAX) {
					eprintf ("Don't know how to skip this instruction\n");
					break;
				}
				addr += aop.size;
			}
			r_debug_reg_set (core->dbg, "pc", addr);
			}
			break;
		case 'o':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_step_over (core->dbg, times);
			if (checkbpcallback (core)) {
				eprintf ("Interrupted by a breakpoint\n");
				break;
			}
			break;
		case 'l':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			step_line (core, times);
			break;
		default:
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
			r_debug_step (core->dbg, times);
			if (checkbpcallback (core)) {
				eprintf ("Interrupted by a breakpoint\n");
				break;
			}
		}
		follow = r_config_get_i (core->config, "dbg.follow");
		break;
	case 'b':
		r_core_cmd_bp (core, input);
		break;
	case 'H':
		eprintf ("TODO: transplant process\n");
		break;
	case 'c':
		// TODO: we must use this for step 'ds' too maybe...
		r_cons_break (static_debug_stop, core->dbg);
		switch (input[1]) {
		case '?': {
				const char * help_message[] = {
				"Usage: dc", "", "Execution continuation commands",
				"dc", "", "Continue execution of all children",
				"dc", " <pid>", "Continue execution of pid",
				"dc", "[-pid]", "Stop execution of pid",
				"dca", " [sym] [sym].", "Continue at every hit on any given symbol",
				"dcc", "", "Continue until call (use step into)",
				"dccu", "", "Continue until unknown call (call reg)",
				"dcf", "", "Continue until fork (TODO)",
				"dck", " <signal> <pid>", "Continue sending signal to process",
				"dco", " <num>", "Step over <num> instructions",
				"dcp", "", "Continue until program code (mapped io section)",
				"dcr", "", "Continue until ret (uses step over)",
				"dcs", " <num>", "Continue until syscall",
				"dct", " <len>", "Traptrace from curseek to len, no argument to list",
				"dcu", " [addr]", "Continue until address",
				"dcu", " <address> [end]", "Continue until given address range",
				/*"TODO: dcu/dcr needs dbg.untilover=true??",*/
				/*"TODO: same for only user/libs side, to avoid steping into libs",*/
				/*"TODO: support for threads?",*/
				NULL
				};

				r_core_cmd_help (core, help_message);
				}
			break;
		case 'a':
			eprintf ("TODO: dca\n");
			break;
		case 'f':
			eprintf ("[+] Running 'dcs vfork' behind the scenes...\n");
			// we should stop in fork and vfork syscalls
			//TODO: multiple syscalls not handled yet
			// r_core_cmd0 (core, "dcs vfork fork");
			r_core_cmd0 (core, "dcs vfork fork");
			break;
		case 'c':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			if (input[2] == 'u') {
				r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_UCALL, 0);
			} else {
				r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 0);
			}
			checkbpcallback (core);
			break;
		case 'r':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_RET, 1);
			checkbpcallback (core);
			break;
		case 'k':
			// select pid and r_debug_continue_kill (core->dbg,
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			ptr = strchr (input+3, ' ');
			if (ptr) {
				bypassbp (core);
				int old_pid = core->dbg->pid;
				int old_tid = core->dbg->tid;
				int pid = atoi (ptr+1);
				int tid = pid; // XXX
				*ptr = 0;
				r_debug_select (core->dbg, pid, tid);
				r_debug_continue_kill (core->dbg, atoi (input+2));
				r_debug_select (core->dbg, old_pid, old_tid);
			} else r_debug_continue_kill (core->dbg, atoi (input+2));
			checkbpcallback (core);
			break;
		case 's':
			switch (input[2]) {
			case '*':
				cmd_debug_cont_syscall (core, "-1");
				break;
			case ' ':
				cmd_debug_cont_syscall (core, input+3);
				break;
			case '\0':
				cmd_debug_cont_syscall (core, NULL);
				break;
			default:
			case '?':
				eprintf ("|Usage: dcs [syscall-name-or-number]\n");
				eprintf ("|dcs         : continue until next syscall\n");
				eprintf ("|dcs mmap    : continue until next call to mmap\n");
				eprintf ("|dcs*        : trace all syscalls (strace)\n");
				eprintf ("|dcs?        : show this help\n");
				break;
			}
			break;
		case 'p':
			{ // XXX: this is very slow
				RIOSection *s;
				ut64 pc;
				int n = 0;
				int t = core->dbg->trace->enabled;
				core->dbg->trace->enabled = 0;
				r_cons_break (static_debug_stop, core->dbg);
				do {
					r_debug_step (core->dbg, 1);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
					pc = r_debug_reg_get (core->dbg, "pc");
					eprintf (" %d %"PFMT64x"\r", n++, pc);
					s = r_io_section_vget (core->io, pc);
					if (r_cons_singleton ()->breaked)
						break;
				} while (!s);
				eprintf ("\n");
				core->dbg->trace->enabled = t;
				r_cons_break_end();
				return 1;
			}
		case 'u':
			if (input[2] != ' ') {
				eprintf ("|Usage: dcu <address>\n");
				return 1;
			}
			ptr = strchr (input+3, ' ');
// TODO : handle ^C here
			if (ptr) { // TODO: put '\0' in *ptr to avoid
				ut64 from, to, pc;
				from = r_num_math (core->num, input+3);
				to = r_num_math (core->num, ptr+1);
				do {
					r_debug_step (core->dbg, 1);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
					pc = r_debug_reg_get (core->dbg, "pc");
					eprintf ("Continue 0x%08"PFMT64x" > 0x%08"PFMT64x" < 0x%08"PFMT64x"\n",
							from, pc, to);
				} while (pc < from || pc > to);
				return 1;
			}
			addr = r_num_math (core->num, input+2);
			if (addr) {
				eprintf ("Continue until 0x%08"PFMT64x"\n", addr);
				bypassbp (core);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
				r_debug_continue (core->dbg);
				checkbpcallback (core);
				r_bp_del (core->dbg->bp, addr);
			} else eprintf ("Cannot continue until address 0\n");
			break;
		case ' ':
			{
				int old_pid = core->dbg->pid;
				int pid = atoi (input+2);
				bypassbp (core);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_debug_select (core->dbg, pid, core->dbg->tid);
				r_debug_continue (core->dbg);
				r_debug_select (core->dbg, old_pid, core->dbg->tid);
				checkbpcallback (core);
			}
			break;
		case 't':
			cmd_debug_backtrace (core, input+2);
			break;
		default:
			bypassbp (core);
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue (core->dbg);
			checkbpcallback (core);
		}
		follow = r_config_get_i (core->config, "dbg.follow");
		r_cons_break_end();
		break;
	case 'm':
		cmd_debug_map (core, input+1);
		break;
	case 'r':
		if (core->io->debug || input[1]=='?') {
			cmd_debug_reg (core, input+1);
		} else {
			void cmd_anal_reg(RCore *core, const char *str);
			cmd_anal_reg (core, input+1);
		}
		//r_core_cmd (core, "|reg", 0);
		break;
	case 'p':
		cmd_debug_pid (core, input);
		break;
	case 'h':
		if (input[1]==' ')
			r_debug_use (core->dbg, input+2);
		else r_debug_plugin_list (core->dbg);
		break;
	case 'i':
		{
#define P r_cons_printf
		RDebugInfo *rdi = r_debug_info (core->dbg, input+2);
		if (rdi) {
			P ("pid=%d\n", rdi->pid);
			P ("tid=%d\n", rdi->tid);
			if (rdi->exe) P ("exe=%s\n", rdi->exe);
			if (rdi->cmdline) P ("cmdline=%s\n", rdi->cmdline);
			if (rdi->cwd) P ("cwd=%s\n", rdi->cwd);
			r_debug_info_free (rdi);
		}
#undef P
		}
		break;
	case 'x':
		switch (input[1]) {
		case 'a':
			{
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, input+2);
			if (acode && *acode->buf_hex) {
				r_reg_arena_push (core->dbg->reg);
				r_debug_execute (core->dbg, acode->buf, acode->len, 0);
				r_reg_arena_pop (core->dbg->reg);
			}
			r_asm_code_free (acode);
			}
			break;
		case 's':
			// XXX: last byte fails (ret) should not be generated
			r_core_cmdf (core, "dir `gs %s`", input+2);
			break;
		case 'r':
			r_reg_arena_push (core->dbg->reg);
			if (input[2]==' ') {
				ut8 bytes[4096];
				int bytes_len = r_hex_str2bin (input+2, bytes);
				r_debug_execute (core->dbg, bytes, bytes_len, 0);
			}
			r_reg_arena_pop (core->dbg->reg);
			break;
		case ' ':
			{
			ut8 bytes[4096];
			int bytes_len = r_hex_str2bin (input+2, bytes);
			if (bytes_len>0)
				r_debug_execute (core->dbg, bytes, bytes_len, 0);
			}
			break;
		default:{
			const char* help_msg[] = {
			"Usage: dx", "", " # Code injection commands",
			"dx", " <opcode>...", "Inject opcodes",
			"dxr", " <opcode>...", "Inject opcodes and restore state",
			"dxs", " write 1, 0x8048, 12", "Syscall injection (see gs)",
			"\nExamples:", "", "",
			"dx", " 9090", "Inject two x86 nop",
			"\"dia mov eax,6;mov ebx,0;int 0x80\"", "", "Inject and restore state",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		}
		break;
	case 'o':
		r_core_file_reopen (core, input[1]? input+2: NULL, 0, 1);
		break;
	case 'w':
		r_cons_break (static_debug_stop, core->dbg);
		for (;!r_cons_singleton ()->breaked;) {
			int pid = atoi (input+1);
			//int opid = core->dbg->pid = pid;
			int res = r_debug_kill (core->dbg, pid, 0, 0);
			if (!res) break;
			r_sys_usleep (200);
		}
			r_cons_break_end();
		break;
	case 'k':
		r_core_debug_kill (core, input+1);
		break;
	default:{
			const char* help_msg[] = {
			"Usage:", "d", " # Debug commands",
			"db", "[?]", "Breakpoints commands",
			"dbt", "", "Display backtrace",
			"dc", "[?]", "Continue execution",
			"dd", "[?]", "File descriptors (!fd in r1)",
			"dh", " [handler]", "List or set debugger handler",
			"dH", " [handler]", "Transplant process to a new handler",
			"di", "", "Show debugger backend information (See dh)",
			"dk", "[?]", "List, send, get, set, signal handlers of child",
			"dm", "[?]", "Show memory maps",
			"do", "", "Open process (reload, alias for 'oo')",
			"dp", "[?]", "List, attach to process or thread id",
			"dr", "[?]", "Cpu registers",
			"ds", "[?]", "Step, over, source line",
			"dt", "[?]", "Display instruction traces (dtr=reset)",
			"dw", " <pid>", "Block prompt until pid dies",
			"dx", "[?]", "Inject code on running process and execute it (See gs)",
			NULL};
			r_core_cmd_help (core, help_msg);
		}
		break;
	}
	if (follow>0) {
		ut64 pc = r_debug_reg_get (core->dbg, "pc");
		if ((pc<core->offset) || (pc > (core->offset+follow)))
			r_core_cmd0 (core, "sr pc");
	}
	return 0;
}
