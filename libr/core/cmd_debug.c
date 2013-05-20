/* radare - LGPL - Copyright 2009-2013 - pancake */

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

/* until end of frame */
static int step_until_eof(RCore *core) {
	ut64 off, now = r_debug_reg_get (core->dbg, "sp");
	do {
		r_debug_step (core->dbg, 1);
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
	ut64 off = r_debug_reg_get (core->dbg, "pc");
	if (off == 0LL) {
		eprintf ("Cannot 'drn pc'\n");
		return R_FALSE;
	}
	file[0] = 0;
	file2[0] = 0;
	if (r_bin_meta_get_line (core->bin, off, file, sizeof (file), &line)) {
		eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file, line);
		eprintf ("--> %s\n", r_file_slurp_line (file, line, 0));
		find_meta = R_FALSE;
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
		if (!r_bin_meta_get_line (core->bin, off, file2, sizeof (file2), &line2)) {
			if (find_meta)
				continue;
			eprintf ("Cannot retrieve dwarf info at 0x%08"PFMT64x"\n", off);
			return R_FALSE;
		}
	} while (!strcmp (file, file2) && line == line2);
	eprintf ("--> 0x%08"PFMT64x" %s : %d\n", off, file2, line2);
	eprintf ("--> %s\n", r_file_slurp_line (file2, line2, 0));
	return R_TRUE;
}

static void cmd_debug_pid(RCore *core, const char *input) {
	const char *ptr;
	int pid, sig;
	switch (input[1]) {
	case 'k':
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
		eprintf ("TODO: debug_fork: %d\n", r_debug_fork (core->dbg));
		break;
	case 't':
		switch (input[2]) {
		case 'n':
			eprintf ("TODO: debug_clone: %d\n", r_debug_clone (core->dbg));
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
		} else r_debug_attach (core->dbg, core->file->fd->fd);
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
		r_config_set_i (core->config, "dbg.swstep",
			(core->dbg->h && !core->dbg->h->canstep));
		break;
	case 'f':
		r_debug_select (core->dbg, core->file->fd->fd, core->dbg->tid);
		break;
	case '=':
		r_debug_select (core->dbg,
			(int) r_num_math (core->num, input+2), core->dbg->tid);
		break;
	case '*':
		r_debug_pid_list (core->dbg, 0);
		break;
	case ' ':
		r_debug_pid_list (core->dbg,
			(int) r_num_math (core->num, input+2));
		break;
	case '?':
		r_cons_printf ("Usage: dp[=][pid]\n"
			" dp      list current pid and childrens\n"
			" dp 748  list children of pid\n"
			" dp*     list all attachable pids\n"
			" dpa 377 attach and select this pid\n"
			" dp=748  select this pid\n"
			" dpn     Create new process (fork)\n"
			" dpnt    Create new thread (clone)\n"
			" dpt     List threads of current pid\n"
			" dpt 74  List threads of given process\n"
			" dpt=64  Attach to thread\n"
			" dpk P S send signal S to P process id\n");
		break;
	default:
		eprintf ("selected: %d %d\n", core->dbg->pid, core->dbg->tid);
		r_debug_pid_list (core->dbg, core->dbg->pid);
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
		} while (r_bp_traptrace_at (core->dbg->bp, addr, analop.length));
		r_bp_traptrace_enable (core->dbg->bp, R_FALSE);
	}
}

static int cmd_debug_map(RCore *core, const char *input) {
	char file[128];
	RListIter *iter;
	RDebugMap *map;
	ut64 addr = core->offset;

	switch (input[0]) {
	case '?':
		r_cons_printf (
		"Usage: dm [size]\n"
		" dm            List memory maps of target process\n"
		" dm*           Same as above but in radare commands\n"
		" dm 4096       Allocate 4096 bytes in child process\n"
		" dm-0x8048     Deallocate memory map of address 0x8048\n"
		" dmp A S rwx   Change page at A with size S protection permissions\n"
		" dmd [file]    Dump current debug map region to a file (from-to.dmp) (see Sd)\n"
		" dml file      Load contents of file into the current map region (see Sl)\n"
		" dmi [addr|libname] [symname]   List symbols of target lib\n"
		" dmi* [addr|libname] [symname]  Same as above but in radare commands\n"
		//" dm rw- esp 9K  set 9KB of the stack as read+write (no exec)\n"
		"TODO: map files in process memory. (dmf file @ [addr])\n");
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
#warning TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", map->size);
					return R_FALSE;
				}
				r_io_read_at (core->io, map->addr, buf, map->size);
				if (input[1]==' ' && input[2]) {
					strncpy (file, input+2, sizeof (file));
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
#warning TODO: use mmap here. we need a portable implementation
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
			if ((addr != -1 && (addr >= map->addr && addr < map->addr_end)) ||
				(libname != NULL && (strstr (map->name, libname)))) {
				RBinObject *o = core->bin->cur.o;
				filter.offset = 0LL;
				filter.name = (char *)symname;
				baddr = o->baddr;
				o->baddr = map->addr;
				r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, (input[1]=='*'),
						R_TRUE, &filter, 0);
				o->baddr = baddr;
				break;
			}
		}
		free (ptr);
		}
		break;
	case '*':
		r_debug_map_sync (core->dbg); // update process memory maps
		r_debug_map_list (core->dbg, core->offset, 1);
		break;
	case '-':
	case ' ':
		eprintf ("TODO\n");
		break;
	default:
		r_debug_map_sync (core->dbg); // update process memory maps
		r_debug_map_list (core->dbg, core->offset, 0);
		break;
	}
	return R_TRUE;
}

static void cmd_debug_reg(RCore *core, const char *str) {
	struct r_reg_item_t *r;
	const char *name;
	char *arg;
	int size, i, type = R_REG_TYPE_GPR;
	int bits = (core->dbg->bits & R_SYS_BITS_64)? 64: 32;
	switch (str[0]) {
	case '?':
		if (str[1]) {
			ut64 off;
			r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
			off = r_debug_reg_get (core->dbg, str+1);
	//		r = r_reg_get (core->dbg->reg, str+1, 0);
	//		if (r == NULL) eprintf ("Unknown register (%s)\n", str+1);
			r_cons_printf ("0x%08"PFMT64x"\n", off); 
			//r_reg_get_value (core->dbg->reg, r));
		} else
		eprintf ("Usage: dr[*] [type] [size] - get/set registers\n"
			" dr         show 'gpr' registers\n"
			" dr all     show all registers\n"
			" dr flg 1   show flag registers ('flg' is type, see drt)\n"
			" dr 16      show 16 bit registers\n"
			" dr 32      show 32 bit registers\n"
			" dr eax=33  set register value. eax = 33\n"
			" dr?        display this help message\n"
			" drt        show all register types\n"
			" drn [pc]   get register name for pc,sp,bp,a0-3\n"
			" dro        show previous (old) values of registers\n"
			" dr=        show registers in columns\n"
			" dr?eax     show value of eax register\n"
			" .dr*       include common register values in flags\n"
			" .dr-       unflag all registers\n"
			" drp [file] load register metadata file\n"
			" drp        display current register profile\n"
			" drb [type] display hexdump of gpr arena (WIP)\n");
		// TODO: 'drs' to swap register arenas and display old register valuez
		break;
	case 'b':
		{ // WORK IN PROGRESS // DEBUG COMMAND
		int len;
		const ut8 *buf = r_reg_get_bytes (core->dbg->reg, R_REG_TYPE_GPR, &len);
		//r_print_hexdump (core->print, 0LL, buf, len, 16, 16);
		r_print_hexdump (core->print, 0LL, buf, len, 32, 4);
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
		else eprintf ("Oops. try dn [pc|sp|bp|a0|a1|a2|a3]\n");
		break;
	case 'd':
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3); // XXX detect which one is current usage
		break;
	case 'o':
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		break;
	case '=':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 2); // XXX detect which one is current usage
		} //else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case '*':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE))
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, '*');
		break;
	case 'j':
	case '\0':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, str[0]);
		} else
			eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case ' ':
		arg = strchr (str+1, '=');
		if (arg) {
			*arg = 0;
			r = r_reg_get (core->dbg->reg, str+1, R_REG_TYPE_GPR);
			if (r) {
				r_cons_printf ("0x%08"PFMT64x" ->", str,
					r_reg_get_value (core->dbg->reg, r));
				r_reg_set_value (core->dbg->reg, r,
					r_num_math (core->num, arg+1));
				r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_TRUE);
				r_cons_printf ("0x%08"PFMT64x"\n",
					r_reg_get_value (core->dbg->reg, r));
			} else eprintf ("Unknown register '%s'\n", str+1);
			return;
		}
		size = atoi (str+1);
		if (size==0) {
			arg = strchr (str+1, ' ');
			if (arg && size==0) {
				*arg='\0';
				size = atoi (arg);
			} else size = core->dbg->bits;
			type = r_reg_type_by_name (str+1);
		}
		if (type != R_REG_TYPE_LAST) {
			r_debug_reg_sync (core->dbg, type, R_FALSE);
			r_debug_reg_list (core->dbg, type, size, str[0]=='*');
		} else eprintf ("cmd_debug_reg: Unknown type\n");
	}
}

static int checkbpcallback(RCore *core) {
	ut64 pc = r_debug_reg_get (core->dbg, "pc");
	RBreakpointItem *bpi = r_bp_get (core->dbg->bp, pc);
	if (bpi) {
		if (bpi->data)
			r_core_cmd (core, bpi->data, 0);
		return R_TRUE;
	}
	return R_FALSE;
}

static int bypassbp(RCore *core) {
	RBreakpointItem *bpi;
	ut64 addr;
	r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
	addr = r_debug_reg_get (core->dbg, "pc");
	bpi = r_bp_get (core->dbg->bp, addr);
	if (!bpi) return R_FALSE;
	/* XXX 2 if libr/debug/debug.c:226 is enabled */
	r_debug_step (core->dbg, 1);
	return R_TRUE;
}


static void static_debug_stop(void *u) {
	RDebug *dbg = (RDebug *)u;
	r_debug_stop (dbg);
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	ut64 addr;
	RList *list;
	RListIter *iter;
	RDebugFrame *frame;
	int i, hwbp = r_config_get_i (core->config, "dbg.hwbp");
	switch (input[1]) {
	case 't':
		addr = UT64_MAX;
		if (input[2]==' ' && input[3])
			addr = r_num_math (core->num, input+2);
		i = 0;
		list = r_debug_frames (core->dbg, addr);
		r_list_foreach (list, iter, frame) {
			r_cons_printf ("%d  0x%08"PFMT64x"  %d\n",
				i++, frame->addr, frame->size);
		}
		r_list_destroy (list);
		break;
	case '\0':
		r_bp_list (core->dbg->bp, input[1]=='*');
		break;
	case '-':
		r_bp_del (core->dbg->bp, r_num_math (core->num, input+2));
		break;
	case 'c':
		addr = r_num_math (core->num, input+2);
		RBreakpointItem *bpi = r_bp_get (core->dbg->bp, addr);
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
		RBreakpointItem *bp = r_bp_get (core->dbg->bp, addr);
		if (bp) bp->enabled = !bp->enabled;
		else {
			if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
		}
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 0);
		break;
	case 'e':
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 1);
		break;
	case 'd':
		r_bp_enable (core->dbg->bp, r_num_math (core->num, input+2), 0);
		break;
	case 'h':
		if (input[2]==' ') {
			if (!r_bp_use (core->dbg->bp, input+3))
				eprintf ("Invalid name: '%s'.\n", input+3);
		} else r_bp_plugin_list (core->dbg->bp);
		break;
	case '?':
		r_cons_printf (
		"Usage: db[ecdht] [[-]addr] [len] [rwx] [condstring]\n"
		"db                ; list breakpoints\n"
		"db sym.main       ; add breakpoint into sym.main\n"
		"db 0x804800       ; add breakpoint\n"
		"db -0x804800      ; remove breakpoint\n"
		// "dbi 0x848 ecx=3   ; stop execution when condition matches\n"
		"dbs 0x8048000     ; toggle breakpoint on given address\n"
		"dbe 0x8048000     ; enable breakpoint\n"
		"dbc 0x8048000 cmd ; run command when breakpoint is hit\n"
		"dbd 0x8048000     ; disable breakpoint\n"
		"dbh x86           ; set/list breakpoint plugin handlers\n"
		"Unrelated:\n"
		"dbt [ebp]         ; debug backtrace\n");
		break;
	default:
		addr = r_num_math (core->num, input+2);
		if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
		else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
		if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
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
		r_debug_step (core->dbg, 1);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE);
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
				eprintf ("0x%08"PFMT64x" ucall. computation may fail\n", addr);
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

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, times, sig, follow=0;
	ut64 addr;
	char *ptr;

	switch (input[0]) {
	case 't':
		switch (input[1]) {
		case '?':
			r_cons_printf ("Usage: dt[*] [tag]\n");
			r_cons_printf ("  dtc  - trace call/ret\n");
			r_cons_printf ("  dtg  - graph call/ret trace\n");
			r_cons_printf ("  dtr  - reset traces (instruction//cals)\n");
			break;
		case 'c':
			if (r_debug_is_dead (core->dbg))
				eprintf ("No process to debug.");
			else r_core_debug_trace_calls (core);
			break;
		case 'g':
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
			break;
		case ' ':
			// open file
			break;
		case '?':
		default:
			r_cons_printf ("Usage: dd[*sdrw-?]\n"
				" dd       list filedescriptors\n"
				" dd*      list filedescriptors (in radare commands)\n"
				" dd?      show this help\n");
			break;
		}
		break;
	case 's':
		times = atoi (input+2);
		if (times<1) times = 1;
		switch (input[1]) {
		case '?':
			r_cons_printf ("Usage: ds[ol] [count]\n"
				" ds          step one instruction\n"
				" ds 4        step 4 instructions\n"
				" dsf         step until end of frame\n"
				" dsi [cond]  continue until condition matches\n"
				" dsl         step one source line\n"
				" dsl 40      step 40 source lines\n"
				" dso 3       step over 3 instructions\n"
				" dsp         step into program (skip libs)\n"
				" dss 3       skip 3 step instructions\n"
				" dsu addr    step until address\n"
				);
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
			step_until_eof(core);
			break;
		case 'u':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			step_until (core, r_num_math (core->num, input+2)); // XXX dupped by times
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
					RIOSection *s = r_io_section_get (core->io, aop.jump);
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
					eprintf ("Dont know how to skip this instruction\n");
					break;
				}
				addr += aop.length;
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
		case '?':
			eprintf("Usage: dc[?]  -- continue execution\n"
				" dc?              show this help\n"
				" dc               continue execution of all children\n"
				" dcf              continue until fork (TODO)\n"
				" dca [sym] [sym]. continue at every hit on any given symbol\n"
				" dct [len]        traptrace from curseek to len, no argument to list\n"
				" dcu [addr]       continue until address\n"
				" dcu [addr] [end] continue until given address range\n"
				" dco [num]        step over N instructions\n"
				" dcp              continue until program code (mapped io section)\n"
				" dcs [num]        continue until syscall\n"
				" dcc              continue until call (use step into)\n"
				" dcr              continue until ret (uses step over)\n"
				" dck [sig] [pid]  continue sending kill 9 to process\n"
				" dc [pid]         continue execution of pid\n"
				" dc[-pid]         stop execution of pid\n"
				"TODO: dcu/dcr needs dbg.untilover=true??\n"
				"TODO: same for only user/libs side, to avoid steping into libs\n"
				"TODO: support for threads?\n");
			break;
		case 'a':
			eprintf ("TODO: dca\n");
			break;
		case 'c':
			r_reg_arena_swap (core->dbg->reg, R_TRUE);
			r_debug_continue_until_optype (core->dbg, R_ANAL_OP_TYPE_CALL, 0);
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
			if (input[2]==' ') {
				sig = r_num_math (core->num, input+3);
				if (sig <= 0) {
					sig = r_syscall_get_num (core->anal->syscall, input+3);
					if (sig == -1) {
						eprintf ("Unknown syscall number\n");
						return 0;
					}
				}
				eprintf ("Running child until syscall %d\n", sig);
				r_reg_arena_swap (core->dbg->reg, R_TRUE);
				r_debug_continue_syscall (core->dbg, sig);
				checkbpcallback (core);
			} else eprintf ("Usage: dcs [syscall-name-or-number]\n");
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
					s = r_io_section_get (core->io, pc);
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
				eprintf ("Usage: dcu [address]\n");
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
		cmd_debug_reg (core, input+1);
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
		if (input[1] ==' ') {
			ut8 bytes[4096];
			int bytes_len = r_hex_str2bin (input+2, bytes);
			r_debug_execute (core->dbg, bytes, bytes_len, 0);
		} else {
			eprintf ("Usage: di 9090\n");
			eprintf ("TODO: option to not restore registers\n");
		}
		break;
	case 'o':
		r_core_file_reopen (core, input[1]? input+2: NULL, 0);
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
	default:
		r_cons_printf ("Usage: d[sbhcrbo] [arg]\n"
		" dh [handler]   list or set debugger handler\n"
		" dH [handler]   transplant process to a new handler\n"
		" dd             file descriptors (!fd in r1)\n"
		" ds[ol] N       step, over, source line\n"
		" do             open process (reload, alias for 'oo')\n"
		" di [bytes]     inject code on running process and execute it\n"
		" dp[=*?t][pid]  list, attach to process or thread id\n"
		" dc[?]          continue execution. dc? for more\n"
		" dr[?]          cpu registers, dr? for extended help\n"
		" db[?]          breakpoints\n"
		" dbt            display backtrace\n"
		" dt[?r] [tag]   display instruction traces (dtr=reset)\n"
		" dm[?*]         show memory maps\n"
		" dw [pid]       block prompt until pid dies\n");
		break;
	}
	if (follow>0) {
		ut64 pc = r_debug_reg_get (core->dbg, "pc");
		if ((pc<core->offset) || (pc > (core->offset+follow)))
			r_core_cmd0 (core, "sr pc");
	}
	return 0;
}
