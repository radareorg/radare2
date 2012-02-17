/* radare - LGPL - Copyright 2009-2012 // nibble<.ds@gmail.com>, pancake<nopcode.org> */

#include "r_core.h"

#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>

static int magicdepth = 99; //XXX: do not use global var here

static void static_debug_stop(void *u) {
	RDebug *dbg = (RDebug *)u;
	r_debug_stop (dbg);
}

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RCore *core = (RCore *) user;
	int j, ret = 0;
	RListIter *iter;
	RFlagItem *flag;

	switch (mode) {
	case 'p':
		for (j=0; j<size; j++)
			if (IS_PRINTABLE (bufz[j]))
				ret++;
		break;
	case 'f':
		r_list_foreach (core->flags->flags, iter, flag)
			if (flag->offset <= addr  && addr < flag->offset+flag->size)
				ret++;
		break;
	case 's':
		j = r_flag_space_get (core->flags, "strings");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->space == j && ((addr <= flag->offset
					&& flag->offset < addr+size)
					|| (addr <= flag->offset+flag->size
					&& flag->offset+flag->size < addr+size)))
				ret++;
		}
		break;
	case '0': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0)
				ret++;
		break;
	case 'F': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0xff)
				ret++;
		break;
	case 'e': // entropy
		ret = (ut8) (r_hash_entropy_fraction (bufz, size)*255);
		break;
	case 'h': // head
	default:
		ret = *bufz;
	}
	return ret;
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

// TODO: move somewhere else
R_API RAsmOp *r_core_disassemble (RCore *core, ut64 addr) {
	ut8 buf[4096];
	static RBuffer *b = NULL; // XXX: never freed and non-thread safe. move to RCore
	RAsmOp *op = R_NEW (RAsmOp);
	if (b == NULL) {
		b = r_buf_new ();
		if (r_core_read_at (core, addr, buf, sizeof (buf))) {
			b->base = addr;
			r_buf_set_bytes (b, buf, sizeof (buf));
		} else return NULL;
	} else {
		if (addr < b->base || addr > b->base+b->length-32) {
			if (r_core_read_at (core, addr, buf, sizeof (buf))) {
				b->base = addr;
				r_buf_set_bytes (b, buf, sizeof (buf));
			} else return NULL;
		}
	}
	if (r_asm_disassemble (core->assembler, op, b->buf, b->length)<1) {
		free (op);
		return NULL;
	}
	return op;
}

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *arg = input+1;
	char *str = strdup (r_config_get (core->config, "file.project"));
	if (*arg==' ') arg++;
	switch (input[0]) {
	case 'o': r_core_project_open (core, input[1]?arg:str); break;
	case 's': r_core_project_save (core, input[1]?arg:str); break;
	case 'i': free (r_core_project_info (core, input[1]?arg:str)); break;
	default:
		r_cons_printf (
		"Usage: P[?osi] [file]\n"
		" Po [file]  open project\n"
		" Ps [file]  save project\n"
		" Pi [file]  info\n"
		"NOTE: project files are stored in ~/.radare2/rdb\n");
		break;
	}
	free (str);
	return R_TRUE;
}

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RAnalFcn *fcni;
	RListIter *iter;
	RSignItem *item;
	int i, fd = -1, len;
	char *ptr, *name;

	switch (*input) {
	case 'g':
		if (input[1]==' ' && input[2]) {
			int fdold = r_cons_singleton ()->fdout;
			ptr = strchr (input+2, ' ');
			if (ptr) {
				*ptr = '\0';
				fd = open (ptr+1, O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (fd == -1) {
					eprintf ("Cannot open %s in read-write\n", ptr+1);
					return R_FALSE;
				}
				r_cons_singleton ()->fdout = fd;
				r_cons_strcat ("# Signatures\n");
			}
			r_cons_printf ("zp %s\n", input+2);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				ut8 buf[128];
				if (r_io_read_at (core->io, fcni->addr, buf, sizeof (buf)) == sizeof (buf)) {
					RFlagItem *flag = r_flag_get_i (core->flags, fcni->addr);
					if (flag) {
						name = flag->name;
						r_cons_printf ("zb %s ", name);
						len = (fcni->size>sizeof (buf))?sizeof (buf):fcni->size;
						for (i=0; i<len; i++)
							r_cons_printf ("%02x", buf[i]);
						r_cons_newline ();
					} else eprintf ("Unnamed function at 0x%08"PFMT64x"\n", fcni->addr);
				} else eprintf ("Cannot read at 0x%08"PFMT64x"\n", fcni->addr);
			}
			r_cons_strcat ("zp-\n");
			if (ptr) {
				r_cons_flush ();
				r_cons_singleton ()->fdout = fdold;
				close (fd);
			}
		} else eprintf ("Usage: zg libc [libc.sig]\n");
		break;
	case 'p':
		if (!input[1])
			r_cons_printf ("%s", core->sign->prefix);
		else if (!strcmp ("-", input+1))
			r_sign_prefix (core->sign, "");
		else r_sign_prefix (core->sign, input+2);
		break;
	case 'a':
	case 'b':
	case 'h':
	case 'f':
		ptr = strchr (input+3, ' ');
		if (ptr) {
			*ptr = 0;
			r_sign_add (core->sign, core->anal, (int)*input, input+2, ptr+1);
		} else eprintf ("Usage: z%c [name] [arg]\n", *input);
		break;
	case 'c':
		item = r_sign_check (core->sign, core->block, core->blocksize);
		if (item)
			r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n", item->name, core->offset);
		break;
	case '-':
		if (input[1] == '*')
			r_sign_reset (core->sign);
		else eprintf ("TODO\n");
		break;
	case '/':
		{
			// TODO: parse arg0 and arg1
			ut8 *buf;
			int len, idx;
			ut64 ini, fin;
			RSignItem *si;
			RIOSection *s;
			if (input[1]) {
				char *ptr = strchr (input+2, ' ');
				if (ptr) {
					*ptr = '\0';
					ini = r_num_math (core->num, input+2);
					fin = r_num_math (core->num, ptr+1);
				} else {
					ini = core->offset;
					fin = ini+r_num_math (core->num, input+2);
				}
			} else {
				s = r_io_section_get (core->io, core->io->off);
				if (s) {
					ini = core->io->va?s->vaddr:s->offset;
					fin = ini + (core->io->va?s->vsize:s->size);
				} else {
					eprintf ("No section identified, please provide range.\n");
					return R_FALSE;
				}
			}
			if (ini>=fin) {
				eprintf ("Invalid range (0x%"PFMT64x"-0x%"PFMT64x").\n", ini, fin);
				return R_FALSE;
			}
			len = fin-ini;
			buf = malloc (len);
			if (buf != NULL) {
				eprintf ("Ranges are: 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ini, fin);
				r_cons_printf ("f-sign*\n");
				if (r_io_read_at (core->io, ini, buf, len) == len) {
					for (idx=0; idx<len; idx++) {
						si = r_sign_check (core->sign, buf+idx, len-idx);
						if (si) {
							if (si->type == 'f')
								r_cons_printf ("f sign.fun_%s_%d @ 0x%08"PFMT64x"\n",
									si->name, idx, ini+idx); //core->offset);
							else r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n",
								si->name, ini+idx); //core->offset+idx);
						}
					}
				} else eprintf ("Cannot read %d bytes at 0x%08"PFMT64x"\n", len, ini);
				free (buf);
			} else eprintf ("Cannot alloc %d bytes\n", len);
		}
		break;
	case '\0':
	case '*':
		r_sign_list (core->sign, (*input=='*'));
		break;
	default:
	case '?':
		r_cons_printf (
			"Usage: z[abcp/*-] [arg]\n"
			" z              show status of zignatures\n"
			" z*             display all zignatures\n"
			" zp             display current prefix\n"
			" zp prefix      define prefix for following zignatures\n"
			" zp-            unset prefix\n"
			" z-prefix       unload zignatures prefixed as\n"
			" z-*            unload all zignatures\n"
			" za ...         define new zignature for analysis\n"
			" zf name fmt    define function zignature (fast/slow, args, types)\n"
			" zb name bytes  define zignature for bytes\n"
			" zh name bytes  define function header zignature\n"
			" zg pfx [file]  generate signature for current file\n"
			" .zc @ fcn.foo  flag signature if matching (.zc@@fcn)\n"
			" z/ [ini] [end] search zignatures between these regions\n"
			"NOTE: bytes can contain '.' (dots) to specify a binary mask\n");
		break;
	}
	return 0;
}

static int cmd_rap(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0':
		r_core_rtr_list (core);
		break;
	case '?':
		r_core_rtr_help (core);
		break;
	case '+':
		r_core_rtr_add (core, input+1);
		break;
	case '-':
		r_core_rtr_remove (core, input+1);
		break;
	case '=':
		r_core_rtr_session (core, input+1);
		break;
	case '<':
		r_core_rtr_pushout (core, input+1);
		break;
	case '!':
		r_io_system (core->io, input+1);
		break;
	default:
		r_core_rtr_cmd (core, input);
	}
#if 0
	switch (input[0]) {
	case '\0':
		r_lib_list (core->lib);
		r_io_plugin_list (core->io);
		break;
	case '?':
		eprintf ("usage: =[fd] [cmd]\n"
			"TODO: import the rest of functionality from r1\n");
		break;
	default:
		r_io_set_fd (core->io, core->file->fd);
		if (input[0]==' ')
			input++;
		r_io_system (core->io, input);
		break;
	}
#endif
	return R_TRUE;
}

static void cmd_debug_reg(RCore *core, const char *str) {
	struct r_reg_item_t *r;
	const char *name;
	char *arg;
	int size, i, type = R_REG_TYPE_GPR;
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
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 3); // XXX detect which one is current usage
		break;
	case 'o':
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 0); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, R_FALSE);
		break;
	case '=':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 2); // XXX detect which one is current usage
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 2);
		} //else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case '*':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 1); // XXX detect which one is current usage
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 1);
		} //else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case '\0':
		if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, R_FALSE)) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 32, 0);
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 64, 0);
		} //else eprintf ("Cannot retrieve registers from pid %d\n", core->dbg->pid);
		break;
	case ' ':
		arg = strchr (str+1, '=');
		if (arg) {
			*arg = 0;
			r = r_reg_get (core->dbg->reg, str+1, R_REG_TYPE_GPR);
			if (r) {
				//eprintf ("SET(%s)(%s)\n", str, arg+1);
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
			} else size = 32;
			//eprintf ("ARG(%s)\n", str+1);
			type = r_reg_type_by_name (str+1);
		}
		//printf("type = %d\nsize = %d\n", type, size);
		if (type != R_REG_TYPE_LAST) {
			r_debug_reg_sync (core->dbg, type, R_FALSE);
			r_debug_reg_list (core->dbg, type, size, str[0]=='*');
		} else eprintf ("cmd_debug_reg: Unknown type\n");
	}
}

static void r_core_cmd_bp(RCore *core, const char *input) {
	RBreakpointItem *bp;
	int hwbp = r_config_get_i (core->config, "dbg.hwbp");
	switch (input[1]) {
	case 't':
		{
		int i = 0;
		RList *list = r_debug_frames (core->dbg);
		RListIter *iter;
		RDebugFrame *frame;
		r_list_foreach (list, iter, frame) {
			r_cons_printf ("%d  0x%08"PFMT64x"  %d\n",
				i++, frame->addr, frame->size);
		}
		r_list_destroy (list);
		}
		break;
	case '\0':
		r_bp_list (core->dbg->bp, input[1]=='*');
		break;
	case '-':
		r_bp_del (core->dbg->bp, r_num_math (core->num, input+2));
		break;
	case 'c': {
			ut64 off = r_num_math (core->num, input+2);
			RBreakpointItem *bpi = r_bp_get (core->dbg->bp, off);
			if (bpi) {
				char *arg = strchr (input+2, ' ');
				if (arg) {
					free (bpi->data);
					bpi->data = strdup (arg+1);
				} else {
					free (bpi->data);
					bpi->data = NULL;
				}
			} else eprintf ("No breakpoint defined at 0x%08"PFMT64x"\n", off);
		}
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
		"dbe 0x8048000     ; enable breakpoint\n"
		"dbc 0x8048000 cmd ; run command when breakpoint is hit\n"
		"dbd 0x8048000     ; disable breakpoint\n"
		"dbh x86           ; set/list breakpoint plugin handlers\n"
		"Unrelated:\n"
		"dbt               ; debug backtrace\n");
		break;
	default:
		{
			ut64 addr = r_num_math (core->num, input+2);
			if (hwbp) bp = r_bp_add_hw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			else bp = r_bp_add_sw (core->dbg->bp, addr, 1, R_BP_PROT_EXEC);
			if (!bp) eprintf ("Cannot set breakpoint (%s)\n", input+2);
		}
		break;
	}
}

static int cmd_mount(void *data, const char *_input) {
	ut64 off = 0;
	char *input, *oinput, *ptr, *ptr2;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	RFSPlugin *plug;
	RFSPartition *part;
	RCore *core = (RCore *)data;
	input = oinput = strdup (_input);

	switch (*input) {
	case ' ':
		input++;
		if (input[0]==' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			ptr++;
			ptr2 = strchr (ptr, ' ');
			if (ptr2) {
				*ptr2 = 0;
				off = r_num_math (core->num, ptr2+1);
			}
			if (!r_fs_mount (core->fs, ptr, input, off))
				eprintf ("Cannot mount %s\n", input);
		} else {
			if (!(ptr = r_fs_name (core->fs, core->offset)))
				eprintf ("Unknown filesystem type\n");
			else if (!r_fs_mount (core->fs, ptr, input, core->offset))
				eprintf ("Cannot mount %s\n", input);
			free (ptr);
		}
		break;
	case '-':
		r_fs_umount (core->fs, input+1);
		break;
	case '*':
		eprintf ("List commands in radare format\n");
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("m %s %s 0x%"PFMT64x"\n",
				root-> path, root->p->name, root->delta);
		}
		break;
	case '\0':
		r_list_foreach (core->fs->roots, iter, root) {
			r_cons_printf ("%s\t0x%"PFMT64x"\t%s\n",
				root->p->name, root->delta, root->path);
		}
		break;
	case 'l': // list of plugins
		r_list_foreach (core->fs->plugins, iter, plug) {
			r_cons_printf ("%10s  %s\n", plug->name, plug->desc);
		}
		break;
	case 'd':
		input++;
		if (input[0]==' ')
			input++;
		list = r_fs_dir (core->fs, input);
		if (list) {
			r_list_foreach (list, iter, file) {
				r_cons_printf ("%c %s\n", file->type, file->name);
			}
			r_list_free (list);
		} else eprintf ("Cannot open '%s' directory\n", input);
		break;
	case 'p':
		input++;
		if (*input == ' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr) {
			*ptr = 0;
			off = r_num_math (core->num, ptr+1);
		}
		list = r_fs_partitions (core->fs, input, off);
		if (list) {
			r_list_foreach (list, iter, part) {
				r_cons_printf ("%d %02x 0x%010"PFMT64x" 0x%010"PFMT64x"\n",
					part->number, part->type,
					part->start, part->start+part->length);
			}
			r_list_free (list);
		} else eprintf ("Cannot read partition\n");
		break;
	case 'o':
		input++;
		if (input[0]==' ')
			input++;
		file = r_fs_open (core->fs, input);
		if (file) {
			// XXX: dump to file or just pipe?
			r_fs_read (core->fs, file, 0, file->size);
			r_cons_printf ("f file %d 0x%08"PFMT64x"\n", file->size, file->off);
			r_fs_close (core->fs, file);
		} else eprintf ("Cannot open file\n");
		break;
	case 'g':
		input++;
		if (*input == ' ')
			input++;
		ptr = strchr (input, ' ');
		if (ptr)
			*ptr++ = 0;
		else
			ptr = "./";
		file = r_fs_open (core->fs, input);
		if (file) {
			r_fs_read (core->fs, file, 0, file->size);
			write (1, file->data, file->size);
			r_fs_close (core->fs, file);
			write (1, "\n", 1);
		} else if (!r_fs_dir_dump (core->fs, input, ptr))
			eprintf ("Cannot open file\n");
		break;
	case 'f':
		input++;
		switch (*input) {
		case '?':
			r_cons_printf (
			"Usage: mf[no] [...]\n"
			" mfn /foo *.c       ; search files by name in /foo path\n"
			" mfo /foo 0x5e91    ; search files by offset in /foo path\n"
			);
			break;
		case 'n':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				list = r_fs_find_name (core->fs, input, ptr);
				r_list_foreach (list, iter, ptr) {
					r_str_chop_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: r_list_destroy (list);
			} else eprintf ("Unknown store path\n");
			break;
		case 'o':
			input++;
			if (*input == ' ')
				input++;
			ptr = strchr (input, ' ');
			if (ptr) {
				*ptr++ = 0;
				ut64 off = r_num_math (core->num, ptr);
				list = r_fs_find_off (core->fs, input, off);
				r_list_foreach (list, iter, ptr) {
					r_str_chop_path (ptr);
					printf ("%s\n", ptr);
				}
				//XXX: r_list_destroy (list);
			} else eprintf ("Unknown store path\n");
			break;
		}
		break;
	case 's':
		input++;
		if (input[0]==' ')
			input++;
		r_fs_prompt (core->fs, input);
		break;
	case 'y':
		eprintf ("TODO\n");
		break;
	case '?':
		r_cons_printf (
		"Usage: m[-?*dgy] [...]\n"
		" m              ; list all mountpoints in human readable format\n"
		" m*             ; same as above, but in r2 commands\n"
		" ml             ; list filesystem plugins\n"
		" m /mnt         ; mount fs at /mnt with autodetect fs and current offset\n"
		" m /mnt ext2 0  ; mount ext2 fs at /mnt with delta 0 on IO\n"
		" m-/            ; umount given path (/)\n"
		" my             ; yank contents of file into clipboard\n"
		" mo /foo        ; get offset and size of given file\n"
		" mg /foo        ; get contents of file/dir dumped to disk (XXX?)\n"
		" mf[o|n]        ; search files for given filename or for offset\n"
		" md /           ; list directory contents for path\n"
		" mp             ; list all supported partition types\n"
		" mp msdos 0     ; show partitions in msdos format at offset 0\n"
		" ms /mnt        ; open filesystem prompt at /mnt\n"
		" m?             ; show this help\n"
		"TODO: support multiple mountpoints and RFile IO's (need io+core refactor)\n"
		);
		break;
	}
	free (oinput);
	return 0;
}

static int cmd_yank(void *data, const char *input) {
	int i;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ':
		r_core_yank (core, core->offset, r_num_math (core->num, input+1));
		break;
	case 'y':
		r_core_yank_paste (core, r_num_math (core->num, input+2), 0);
		break;
	case 'x':
		r_print_hexdump (core->print, 0LL, core->yank, core->yank_len, 16, 4);
		break;
	case 'p':
		r_cons_memcat ((const char*)core->yank, core->yank_len);
		r_cons_newline ();
		break;
	case 't':
		{ /* hacky implementation */
			char *arg = strdup (input+1);
			r_core_yank_to (core, arg);
			free (arg);
		}
		break;
	case '\0':
		if (core->yank) {
			r_cons_printf ("0x%08"PFMT64x" %d ",
				core->yank_off, core->yank_len);
			for (i=0; i<core->yank_len; i++)
				r_cons_printf ("%02x", core->yank[i]);
			r_cons_newline ();
		} else eprintf ("No buffer yanked already\n");
		break;
	default:
		r_cons_printf (
		"Usage: y[ptxy] [len] [[@]addr]\n"
		" y            ; show yank buffer information (srcoff len bytes)\n"
		" y 16         ; copy 16 bytes into clipboard\n"
		" y 16 0x200   ; copy 16 bytes into clipboard from 0x200\n"
		" y 16 @ 0x200 ; copy 16 bytes into clipboard from 0x200\n"
		" yp           ; print contents of clipboard\n"
		" yx           ; print contents of clipboard in hexadecimal\n"
		" yt 64 0x200  ; copy 64 bytes from current seek to 0x200\n"
		" yy 0x3344    ; paste clipboard\n");
		break;
	}
	return R_TRUE;
}

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input)
	switch (*input) {
	case '?':
		r_cons_printf (
		"Usage: q[!] [retvalue]\n"
		" q     ; quit program\n"
		" q!    ; force quit (no questions)\n"
		" q 1   ; quit with return value 1\n"
		" q a-b ; quit with return value a-b\n");
		break;
	case ' ':
	case '!':
		input++;
	case '\0':
		// TODO
	default:
		r_line_hist_save (".radare2_history");
		if (*input)
			r_num_math (core->num, input);
		else core->num->value = 0LL;
		//exit (*input?r_num_math (core->num, input+1):0);
		return -2;
	}
	return R_FALSE;
}

static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol;
	RCore *core = (RCore *)data;
	switch (*input) {
	case '\0':
		r_core_cmd_repeat (core, 0);
		break;
	case '.': // same as \n
		r_core_cmd_repeat (core, 1);
		break;
	case ' ':
		if (!r_core_cmd_file (core, input+1))
			eprintf ("Cannot interpret file.\n");
		break;
	case '!':
		/* from command */
		r_core_cmd_command (core, input+1);
		break;
	case '(':
		//eprintf ("macro call (%s)\n", input+1);
		r_cmd_macro_call (&core->cmd->macro, input+1);
		break;
	case '?':
		r_cons_printf (
		"Usage: . [file] | [!command] | [(macro)]\n"
		" .                 ; repeat last command backward\n"
		" ..                ; repeat last command forward (same as \\n)\n"
		" . foo.rs          ; interpret r script\n"
		" .!rabin -ri $FILE ; interpret output of command\n"
		" .(foo 1 2 3)      ; run macro 'foo' with args 1, 2, 3\n"
		" ./ ELF            ; interpret output of command /m ELF as r. commands\n");
		break;
	default:
		ptr = str = r_core_cmd_str (core, input);
		for (;;) {
			eol = strchr (ptr, '\n');
			if (eol) *eol = '\0';
			if (*ptr)
			r_core_cmd0 (core, ptr);
			if (!eol) break;
			ptr = eol+1;
		}
		free (str);
		break;
	}
	return 0;
}

static int cmd_section(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (*input) {
	case '?':
		r_cons_printf (
		" S                ; list sections\n"
		" S.               ; show current section name\n"
		" S?               ; show this help message\n"
		" S*               ; list sections (in radare commands)\n"
		" S=               ; list sections (in nice ascii-art bars)\n"
		" Sd [file]        ; dump current section to a file (see dmd)\n"
		" Sl [file]        ; load contents of file into current section (see dml)\n"
		" S [off] [vaddr] [sz] [vsz] [name] [rwx] ; add new section\n"
		" S-[id|0xoff|*]   ; remove this section definition\n");
		break;
	case 'd':
		{
		char file[128];
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				ut8 *buf = malloc (s->size);
				r_io_read_at (core->io, s->offset, buf, s->size);
				if (input[1]==' ' && input[2]) {
					strncpy (file, input+2, sizeof (file));
				} else snprintf (file, sizeof (file), "0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
					s->vaddr, s->vaddr+s->size, r_str_rwx_i (s->rwx));
				if (!r_file_dump (file, buf, s->size)) {
					eprintf ("Cannot write '%s'\n", file);
					free (buf);
					return R_FALSE;
				}
				eprintf ("Dumped %d bytes into %s\n", (int)s->size, file);
				free (buf);
				return R_TRUE;
			}
		}
		}
		break;
	case 'l':
		{
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (input[1] != ' ') {
			eprintf ("Usage: Sl [file]\n");
			return R_FALSE;
		}
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				int sz;
				char *buf = r_file_slurp (input+2, &sz);
#warning TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf ("Cannot allocate 0x%08"PFMT64x" bytes\n", s->size);
					return R_FALSE;
				}
				r_io_write_at (core->io, s->vaddr, (const ut8*)buf, sz);
				eprintf ("Loaded %d bytes into the map region at 0x%08"PFMT64x"\n", sz, s->vaddr);
				free (buf);
				return R_TRUE;
			}
		}
		eprintf ("No debug region found here\n");
		return R_FALSE;
		}
		break;
	case '-':
		if (input[1] == '*') {
			// remove all sections
			r_io_section_init (core->io);
		} else
		if (input[1] == '0' && input[2]=='x') {
			RIOSection *s = r_io_section_get (core->io, r_num_get (NULL, input+1));
			// use offset
			r_io_section_rm (core->io, s->id);
		} else {
			r_io_section_rm (core->io, atoi (input+1));
		}
		break;
	case ' ':
		switch (input[1]) {
		case '-': // remove
			if (input[2]=='?' || input[2]=='\0')
				eprintf ("Usage: S -N   # where N is the section index\n");
			else r_io_section_rm (core->io, atoi (input+1));
			break;
		default:
			{
			int i, rwx = 7;
			char *ptr = strdup(input+1);
			const char *name = NULL;
			ut64 vaddr = 0LL;
			ut64 offset = 0LL;
			ut64 size = 0LL;
			ut64 vsize = 0LL;

			i = r_str_word_set0 (ptr);
			switch (i) {
			case 6: // get rwx
				rwx = r_str_rwx (r_str_word_get0 (ptr, 5));
			case 5: // get name
				name = r_str_word_get0 (ptr, 4);
			case 4: // get vsize
				vsize = r_num_math (core->num, r_str_word_get0 (ptr, 3));
			case 3: // get size
				size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
			case 2: // get vaddr
				vaddr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get offset
				offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			r_io_section_add (core->io, offset, vaddr, size, vsize, rwx, name);
			free (ptr);
			}
			break;
		}
		break;
	case '=':
		r_io_section_list_visual (core->io, core->offset, core->blocksize);
		break;
	case '.':
		{
		ut64 o = core->offset;
		RListIter *iter;
		RIOSection *s;
		if (core->io->va || core->io->debug)
			o = r_io_section_vaddr_to_offset (core->io, o);
		r_list_foreach (core->io->sections, iter, s) {
			if (o>=s->offset && o<s->offset+s->size) {
				r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s\n",
					s->offset + s->vaddr,
					s->offset + s->vaddr + s->size,
					s->name);
				break;
			}
		}
		}
		break;
	case '\0':
		r_io_section_list (core->io, core->offset, 0);
		break;
	case '*':
		r_io_section_list (core->io, core->offset, 1);
		break;
	}
	return 0;
}

static int cmd_seek(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *cmd, *p;
	ut64 off;

	if (*input=='r') {
		if (input[1] && input[2]) {
			if (core->io->debug) {
				off = r_debug_reg_get (core->dbg, input+2);
				r_io_sundo_push (core->io, core->offset);
				r_core_seek (core, off, 1);
			}// else eprintf ("cfg.debug is false\n");
		} else eprintf ("Usage: 'sr pc' ; seek to register\n");
	} else
	if (*input) {
		int sign = 1;
		st32 delta = (input[1]==' ')? 2: 1;
		off = r_num_math (core->num, input + delta);
		if ((st64)off<0)off =-off; // hack to fix s-2;s -2
		if (isalpha (input[delta]) && off == 0) {
			if (!r_flag_get (core->flags, input+delta)) {
				eprintf ("Invalid address (%s)\n", input+delta);
				return R_FALSE;
			}
		}
		if (input[0]==' ') {
			switch (input[1]) {
			case '-': sign=-1;
			case '+': input++; break;
			}
		}

		switch (*input) {
		case 'C':
			if (input[1]==' ') {
				int n = 0;
				RListIter *iter;
				RMetaItem *d, *item = NULL;
				/* seek to comment */
				r_list_foreach (core->anal->meta->data, iter, d) {
					if (d->type == R_META_TYPE_COMMENT) {
						if (strstr (d->str, input+2)) {
							if (n==1) {
								r_cons_printf ("0x%08"PFMT64x"  %s\n", item->from, item->str);
								r_cons_printf ("0x%08"PFMT64x"  %s\n", d->from, d->str);
							} else if (n>1) {
								r_cons_printf ("0x%08"PFMT64x"  %s\n", d->from, d->str);
							}
							item = d;
							n++;
						}
					}
				}
				switch (n) {
				case 0:
					eprintf ("No matching comments\n");
					break;
				case 1:
					r_cons_printf ("0x%08"PFMT64x"  %s\n", item->from, item->str);
					r_io_sundo_push (core->io, core->offset);
					r_core_seek (core, off, 1);
					r_core_block_read (core, 0);
					break;
				}

			} else eprintf ("Usage: sC comment grep\n");
			break;
		case ' ':
			r_io_sundo_push (core->io, core->offset);
			r_core_seek (core, off*sign, 1);
			r_core_block_read (core, 0);
			break;
		case '/':
			{
			const char *pfx = r_config_get (core->config, "search.prefix");
			int kwidx = (int)r_config_get_i (core->config, "search.kwidx")-1;
			if (kwidx<0) kwidx = 0;
			//r_core_seek (core, off+1, 0);
			eprintf ("s+1;.%s ; ? %s%d_0 ; ?! s %s%d_0\n", input, pfx, kwidx, pfx, kwidx);
			r_core_cmdf (core, "s+1;.%s ; ? %s%d_0 ; ?! s %s%d_0", input, pfx, kwidx, pfx, kwidx);
			}
			break;
		case '*':
			r_io_sundo_list (core->io);
			break;
		case '+':
			if (input[1]!='\0') {
				delta = (input[1]=='+')? core->blocksize: off;
				r_io_sundo_push (core->io, core->offset);
				r_core_seek_delta (core, delta);
			} else {
				off = r_io_sundo_redo (core->io);
				if (off != UT64_MAX)
					r_core_seek (core, off, 0);
			}
			break;
		case '-':
			if (input[1]!='\0') {
				if (input[1]=='-') delta = -core->blocksize; else delta = -off;
				r_io_sundo_push (core->io, core->offset);
				r_core_seek_delta (core, delta);
			} else {
				off = r_io_sundo (core->io, core->offset);
				if (off != UT64_MAX)
					r_core_seek (core, off, 0);
			}
			break;
		case 'f':
			r_io_sundo_push (core->io, core->offset);
			r_core_seek_next (core, r_config_get (core->config, "scr.fkey"));
			break;
		case 'F':
			r_io_sundo_push (core->io, core->offset);
			r_core_seek_previous (core, r_config_get (core->config, "scr.fkey"));
			break;
		case 'a':
			off = core->blocksize;
			if (input[1]&&input[2]) {
				cmd = strdup (input);
				p = strchr (cmd+2, ' ');
				if (p) {
					off = r_num_math (core->num, p+1);;
					*p = '\0';
				}
				cmd[0] = 's';
				// perform real seek if provided
				r_cmd_call (core->cmd, cmd);
				free (cmd);
			}
			r_io_sundo_push (core->io, core->offset);
			r_core_seek_align (core, off, 0);
			break;
		case 'b':
			r_io_sundo_push (core->io, core->offset);
			r_core_anal_bb_seek (core, off);
			break;
		case 'n':
			{
			RAnalOp op;
			int ret = r_anal_op (core->anal, &op,
				core->offset, core->block, core->blocksize);
			r_core_seek_delta (core, ret);
			}
			break;
		case '?':
			r_cons_printf (
			"Usage: s[+-] [addr]\n"
			" s 0x320    ; seek to this address\n"
			" s-         ; undo seek\n"
			" s+         ; redo seek\n"
			" s*         ; list undo seek history\n"
			" s++        ; seek blocksize bytes forward\n"
			" s--        ; seek blocksize bytes backward\n"
			" s+ 512     ; seek 512 bytes forward\n"
			" s- 512     ; seek 512 bytes backward\n"
			" sa [[+-]a] [asz] ; seek asz (or bsize) aligned to addr\n"
			" sf|sF      ; seek next/prev scr.fkey\n"
			" s/ DATA    ; search for next occurrence of 'DATA'\n"
			" sb         ; seek aligned to bb start\n"
			" sn         ; seek to next opcode\n"
			" sC str     ; seek to comment matching given string\n"
			" sr pc      ; seek to register\n");
			break;
		}
	} else r_cons_printf ("0x%"PFMT64x"\n", core->offset);
	return 0;
}

static int cmd_help(void *data, const char *input) {
	int i;
	RCore *core = (RCore *)data;
	char out[128];
	ut64 n;
	switch (input[0]) {
	case 'r':
		{ // TODO : Add support for 64bit random numbers
		char *p;
		ut64 b = 0;
		ut32 r = UT32_MAX;
		if (input[1]) {
			strncpy (out, input+(input[1]==' '? 2: 1), sizeof (out)-1);
			p = strchr (out+1, ' ');
			if (p) {
				*p = 0;
				b = (ut32)r_num_math (core->num, out);
				r = (ut32)r_num_math (core->num, p+1)-b;
			} else {
				r = (ut32)r_num_math (core->num, out);
			}
		} else {
			r = 0LL;
		}
		if (r == 0)
			r = UT32_MAX>>1;
		core->num->value = (ut64) (b + r_num_rand (r));
		r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case 'b':
		{
		n = r_num_get (core->num, input+1);
		r_num_to_bits (out, n);
		r_cons_printf ("%s\n", out);
		}
		break;
	case 'd':
		if (input[1]==' '){
			char *d = r_asm_describe (core->assembler, input+2);
			if (d && *d) {
				r_cons_printf ("%s\n", d);
				free (d);
			} else eprintf ("Unknown opcode\n");
		} else eprintf ("Use: ?d [opcode]    to get the description of the opcode\n");
		break;
	case 'y':
		for (input++; input[0]==' '; input++);
		if (*input) {
			free (core->yank);
			core->yank = (ut8*)strdup (input);
			core->yank_len = strlen ((const char*)core->yank);
		} else {
			r_cons_memcat ((const char *)core->yank, core->yank_len);
			r_cons_newline ();
		}
		break;
	case 'F':
		r_cons_flush ();
		break;
	case 'f':
		if (input[1]==' ') {
			char *q, *p = strdup (input+2);
			if (!p) {
				eprintf ("Cannot strdup\n");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n), q+1);
				r_cons_printf ("%s\n", out);
			} else eprintf ("Usage: \"?b value bitstring\"\n");
			free (p);
		} else eprintf ("Whitespace expected after '?f'\n");
		break;
	case ' ':
		{
		ut32 n32, s, a;
		float f;
		n = r_num_math (core->num, input+1);
		n32 = (ut32)n;
		memcpy (&f, &n32, sizeof (f));
		/* decimal, hexa, octal */
		a = n & 0xffff;
		s = (n-a) >> 4;
		r_cons_printf ("%"PFMT64d" 0x%"PFMT64x" 0%"PFMT64o" %04X:%04X ",
			n, n, n, s, a);
		/* binary and floating point */
		r_str_bits (out, (const ut8*)&n, sizeof (n), NULL);
		r_cons_printf ("%s %.01lf %f\n", out, core->num->fvalue, f);
		}
		break;
	case 'v':
		n = (input[1] != '\0') ? r_num_math (core->num, input+2) : 0;
		r_cons_printf ("0x%"PFMT64x"\n", n);
		core->num->value = n;
		break;
	case '=':
		r_num_math (core->num, input+1);
		break;
	case '+':
		if (input[1]) {
			if (core->num->value & UT64_GT0)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '-':
		if (input[1]) {
			if (core->num->value & UT64_LT0)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '!': // ??
		if (input[1]) {
			if (core->num->value != UT64_MIN)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '$':
		return cmd_help (data, " $?");
	case 'V':
		r_cons_printf ("%s\n", R2_VERSION);
		break;
	case 'l':
		for (input++; input[0]==' '; input++);
		core->num->value = strlen (input);
		break;
	case 'X':
		{
			for (input++; input[0]==' '; input++);
			ut64 n = r_num_math (core->num, input);
			r_cons_printf ("%"PFMT64x"\n", n);
		}
		break;
	case 'x':
		for (input++; input[0]==' '; input++);
		if (!memcmp (input, "0x", 2) || (*input>='0' && *input<='9')) {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i=0; i<bits; i++)
				r_cons_printf ("%02x", (ut8)((n>>(i*8)) &0xff));
			r_cons_newline ();
		} else {
			for (i=0; input[i]; i++)
				r_cons_printf ("%02x", input[i]);
			r_cons_newline ();
		}
		break;
	case 'e': // echo
		for (input++; *input==' '; input++);
		r_cons_printf ("%s\n", input);
		break;
	case 's': // sequence from to step
		{
		ut64 from, to, step;
		char *p, *p2;
		for (input++; *input==' '; input++);
		p = strchr (input, ' ');
		if (p) {
			*p='\0';
			from = r_num_math (core->num, input);
			p2 = strchr (p+1, ' ');
			if (p2) {
				*p2='\0';
				step = r_num_math (core->num, p2+1);
			} else step = 1;
			to = r_num_math (core->num, p+1);
			for (;from<=to; from+=step)
				r_cons_printf ("%"PFMT64d" ", from);
			r_cons_newline ();
		}
		}
		break;
	case 'p':
		if (core->io->va) {
		// physical address
		ut64 o, n = (input[0] && input[1])?
			r_num_math (core->num, input+2): core->offset;
		o = r_io_section_vaddr_to_offset (core->io, n);
		r_cons_printf ("0x%08"PFMT64x"\n", o);
		} else {
			eprintf ("Virtual addresses not enabled!\n");
		}
		break;
	case 'S': {
		// section name
		RIOSection *s;
		ut64 n = (input[0] && input[1])?
			r_num_math (core->num, input+2): core->offset;
		n = r_io_section_vaddr_to_offset (core->io, n);
		s = r_io_section_get (core->io, n);
		if (s && s->name)
			r_cons_printf ("%s\n", s->name);
		} break;
	case 'I': // hud input
		free (core->yank);
		for (input++; *input==' '; input++);
		core->yank = (ut8*)r_cons_hud_file (input);
		core->yank_len = core->yank? strlen ((const char *)core->yank): 0;
		break;
	case 'k': // key=value utility
		for (input++; *input==' '; input++);
		if (*input) {
			char *p = strchr (input, '='); 
			if (p) {
				// set
				*p = 0;
				r_pair_set (core->kv, input, p+1);
			} else {
				// get
				char *g = r_pair_get (core->kv, input);
				if (g) {
					r_cons_printf ("%s\n", g);
					free (g);
				}
			}
		}
		break;
	case 'i': // input num
		if (input[1]=='m') {
			r_cons_message (input+2);
		} else
		if (input[1]=='p') {
			char *p = r_cons_hud_path (input+2, 0);
			core->yank = (ut8*)p;
			core->yank_len = p? strlen (p): 0;
			core->num->value = (p != NULL);
		} else
		if (input[1]=='k') {
			r_cons_any_key ();
		} else
		if (input[1]=='y') {
			for (input+=2; *input==' '; input++);
			core->num->value =
			r_cons_yesno (1, "%s? (Y/n)", input);
		} else
		if (input[1]=='n') {
			for (input+=2; *input==' '; input++);
			core->num->value =
			r_cons_yesno (0, "%s? (y/N)", input);
		} else {
			char foo[1024];
			r_cons_flush ();
			for (input++; *input==' '; input++);
			// TODO: use prompt input
			eprintf ("%s: ", input);
			fgets (foo, sizeof (foo)-1, stdin);
			foo[strlen (foo)-1] = 0;
			free (core->yank);
			core->yank = (ut8 *)strdup (foo);
			core->yank_len = strlen (foo);
			core->num->value = r_num_math (core->num, foo);
		}
		break;
	case 't': {
		struct r_prof_t prof;
		r_prof_start (&prof);
		r_core_cmd (core, input+1, 0);
		r_prof_end (&prof);
		core->num->value = (ut64)(int)prof.result;
		eprintf ("%lf\n", prof.result);
		} break;
	case '?': // ???
		if (input[1]=='?') {
			r_cons_printf (
			"Usage: ?[?[?]] expression\n"
			" ? eip-0x804800  ; show hex and dec result for this math expr\n"
			" ?v eip-0x804800 ; show hex value of math expr\n"
			" ?V              ; show library version of r_core\n"
			" ?= eip-0x804800 ; same as above without user feedback\n"
			" ?? [cmd]        ; ? == 0 run command when math matches\n"
			" ?i[ynmkp] arg   ; prompt for number or Yes,No,Msg,Key,Path and store in $$?\n"
#if DONE 
//BUT NOT DOCUMENTED AT ALL
			" ?iy prompt      ; yesno input prompt\n"
			" ?in prompt      ; yesno input prompt\n"
			" ?im message     ; show message centered in screen\n"
			" ?ik             ; press any key input dialog\n"
#endif
			" ?I hudfile      ; load hud menu with given file\n"
			" ?d opcode       ; describe opcode for asm.arch\n"
			" ?e string       ; echo string\n"
			" ?r [from] [to]  ; generate random number between from-to\n"
			" ?y [str]        ; show contents of yank buffer, or set with string\n"
			" ?k k[=v]        ; key-value temporal storage for the user\n"
			" ?b [num]        ; show binary value of number\n"
			" ?f [num] [str]  ; map each bit of the number as flag string index\n"
			" ?p vaddr        ; get physical address for given vaddr\n"
			" ?s from to step ; sequence of numbers from to by steps\n"
			" ?S addr         ; return section name of given address\n"
			" ?x num|0xnum|str; returns the hexpair of number or string\n"
			" ?X num|expr     ; returns the hexadecimal value numeric expr\n"
			" ?l str          ; returns the length of string (0 if null)\n"
			" ?t cmd          ; returns the time to run a command\n"
			" ?! [cmd]        ; ? != 0\n"
			" ?+ [cmd]        ; ? > 0\n"
			" ?- [cmd]        ; ? < 0\n"
			" ???             ; show this help\n"
			"$variables:\n"
			" $$  = here (current seek)\n"
			" $o  = here (current io offset)\n"
			" $s  = file size\n"
			" $b  = block size\n"
			" $j  = jump address (e.g. jmp 0x10, jz 0x10 => 0x10)\n"
			" $f  = jump fail address (e.g. jz 0x10 => next instruction)\n"
			" $r  = opcode memory reference (e.g. mov eax,[0x10] => 0x10)\n"
			" $l  = opcode length\n"
			" $e  = 1 if end of block, else 0\n"
			" ${eval} = get value of eval config variable # TODO: use ?k too\n"
			" $?  = last comparision value\n");
			return 0;
		} else
		if (input[1]) {
			if (core->num->value == UT64_MIN)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '\0':
	default:
		r_cons_printf (
		" a                 ; perform analysis of code\n"
		" b [bsz]           ; get or change block size\n"
		" c[dqxXfg] [arg]   ; compare block with given data\n"
		" C[Cf..]           ; Code metadata management\n"
		" d[hrscb]          ; debugger commands\n"
		" e [a[=b]]         ; list/get/set config evaluable vars\n"
		" f [name][sz][at]  ; set flag at current address\n"
		" g[wcilper] [arg]  ; go compile shellcodes with r_egg\n"
		" i [file]          ; get info about opened file\n"
		" m[lyogfdps]       ; mountpoints commands\n"
		" o [file] (addr)   ; open file at optional address\n"
		" p?[len]           ; print current block with format and length\n"
		" P[osi?]           ; project management utilities\n"
		" r[+- ][len]       ; resize file\n"
		" s [addr]          ; seek to address\n"
		" S?[size] [vaddr]  ; IO section manipulation information\n"
		" V[vcmds]          ; enter visual mode (vcmds=visualvisual  keystrokes)\n"
		" w[mode] [arg]     ; multiple write operations\n"
		" x [len]           ; alias for 'px' (print hexadecimal)\n"
		" y [len] [off]     ; yank/paste bytes from/to memory\n"
		" ?[??] [expr]      ; help or evaluate math expression\n"
		" /[xmp/]           ; search for bytes, regexps, patterns, ..\n"
		" ![cmd]            ; run given command as in system(3)\n"
		" = [cmd]           ; run this command via rap://\n"
		" (macro arg0 arg1) ; define scripting macros\n"
		" #[algo] [len]     ; calculate hash checksum of current block\n"
		" .[ file|!cmd|cmd|(macro)]  ; interpret as radare cmds\n"
		" :                 ; list all command plugins\n"
		" q [ret]           ; quit program with a return value\n"
		"Append '?' to any char command to get detailed help\n"
		"Prefix with number to repeat command N times (f.ex: 3x)\n"
		"Suffix '@ addr[:bsize]' for a temporary seek and/or bsize\n"
		"Suffix '@@ glob1 glob2i ..' space separated glob greps for flags to seek\n"
		"Suffix '~string:linenumber[column]' to filter output\n"
		);
		break;
	}
	return 0;
}

static int cmd_bsize(void *data, const char *input) {
	RFlagItem *flag;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'f':
		if (input[1]==' ') {
			flag = r_flag_get (core->flags, input+2);
			if (flag)
				r_core_block_size (core, flag->size);
			else eprintf ("bf: Cannot find flag named '%s'\n", input+2);
		} else eprintf ("Usage: bf [flagname]\n");
		break;
	case '\0':
		r_cons_printf ("0x%x\n", core->blocksize);
		break;
	case '?':
		r_cons_printf ("Usage: b[f] [arg]\n"
			" b        # display current block size\n"
			" b 33     # set block size to 33\n"
			" b eip+4  # numeric argument can be an expression\n"
			" bf foo   # set block size to flag size\n");
		break;
	default:
		//input = r_str_clean(input);
		r_core_block_size (core, r_num_math (core->num, input));
		break;
	}
	return 0;
}

// move it out // r_diff maybe?
static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len) {
	int i, eq = 0;
	for (i=0; i<len; i++) {
		if (f[i]==d[i]) {
			eq++;
			continue;
		}
		r_cons_printf ("0x%08"PFMT64x" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
			core->offset+i, i+1,
			f[i], (IS_PRINTABLE(f[i]))?f[i]:' ',
			d[i], (IS_PRINTABLE(d[i]))?d[i]:' ');
	}
	eprintf ("Compare %d/%d equal bytes\n", eq, len);
	return len-eq;
}

static int cmd_cmp(void *data, const char *input) {
	RCore *core = data;
	FILE *fd;
	ut8 *buf;
	int ret;
	ut32 v32;
	ut64 v64;

	switch (*input) {
	case ' ':
		radare_compare (core, core->block, (ut8*)input+1, strlen (input+1)+1);
		break;
	case 'x':
		if (input[1]!=' ') {
			eprintf ("Usage: cx 001122'\n");
			return 0;
		}
		buf = (ut8*)malloc (strlen (input+2));
		ret = r_hex_str2bin (input+2, buf);
		if (ret<1) eprintf ("Cannot parse hexpair\n");
		else radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'X':
		buf = malloc (core->blocksize);
		ret = r_io_read_at (core->io, r_num_math (core->num, input+1), buf, core->blocksize);
		radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'f':
		if (input[1]!=' ') {
			eprintf ("Please. use 'cf [file]'\n");
			return 0;
		}
		fd = fopen (input+2, "rb");
		if (fd == NULL) {
			eprintf ("Cannot open file '%s'\n", input+2);
			return 0;
		}
		buf = (ut8 *)malloc (core->blocksize);
		fread (buf, 1, core->blocksize, fd);
		fclose (fd);
		radare_compare (core, core->block, buf, core->blocksize);
		free (buf);
		break;
	case 'q':
		v64 = (ut64) r_num_math (core->num, input+1);
		radare_compare (core, core->block, (ut8*)&v64, sizeof (v64));
		break;
	case 'd':
		v32 = (ut32) r_num_math (core->num, input+1);
		radare_compare (core, core->block, (ut8*)&v32, sizeof (v32));
		break;
#if 0
	case 'c':
		radare_compare_code (
			r_num_math (core->num, input+1),
			core->block, core->blocksize);
		break;
	case 'D':
		{ // XXX ugly hack
		char cmd[1024];
		sprintf (cmd, "radiff -b %s %s", ".curblock", input+2);
		r_file_dump (".curblock", config.block, config.block_size);
		radare_system(cmd);
		unlink(".curblock");
		}
		break;
#endif
	case 'g':
		{ // XXX: this is broken
			int diffops = 0;
		RCore *core2;
		char *file2 = NULL;
		if (input[1]=='o') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_TRUE, -1, -1);
		} else
		if (input[1]==' ') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_FALSE, -1, -1);
		} else {
			eprintf ("Usage: cg[o] [file]\n");
			eprintf (" cg  - byte-per-byte code graph diff\n");
			eprintf (" cgo - opcode-bytes code graph diff\n");
			return R_FALSE;
		}

		if (!(core2 = r_core_new ())) {
			eprintf ("Cannot init diff core\n");
			return R_FALSE;
		}
		core2->io->va = core->io->va;
		core2->anal->split = core->anal->split;
		if (!r_core_file_open (core2, file2, 0, 0LL)) {
			eprintf ("Cannot open diff file '%s'\n", file2);
			r_core_free (core2);
			return R_FALSE;
		}
		// TODO: must replicate on core1 too
		r_config_set_i (core2->config, "io.va", R_TRUE);
		r_config_set_i (core2->config, "anal.split", R_TRUE);
                r_anal_diff_setup (core->anal, diffops, -1, -1);
                r_anal_diff_setup (core2->anal, diffops, -1, -1);

		r_core_bin_load (core2, file2);
		r_core_gdiff (core, core2);
		r_core_diff_show (core, core2);
		r_core_free (core2);
		}
		break;
	case '?':
		r_cons_strcat (
		"Usage: c[?cdfx] [argument]\n"
		" c  [string]   Compares a plain with escaped chars string\n"
		//" cc [offset]   Code bindiff current block against offset\n"
		" cd [value]    Compare a doubleword from a math expression\n"
		//" cD [file]     Like above, but using radiff -b\n");
		" cq [value]    Compare a quadword from a math expression\n"
		" cx [hexpair]  Compare hexpair string\n"
		" cX [addr]     Like 'cc' but using hexdiff output\n"
		" cf [file]     Compare contents of file at current seek\n"
		" cg[o] [file]  Graphdiff current file and [file]\n");
		break;
	default:
		eprintf ("Usage: c[?Ddxf] [argument]\n");
	}

	return 0;
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 offset = r_bin_get_offset (core->bin);
	int va = core->io->va || core->io->debug;
	int mode = (input[1]=='*')?R_CORE_BIN_RADARE:R_CORE_BIN_PRINT;
	switch (*input) {
	case 'S':
		r_core_bin_info (core, R_CORE_BIN_ACC_SECTIONS|R_CORE_BIN_ACC_FIELDS, mode, va, NULL, offset);
		break;
	case 's':
		r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, mode, va, NULL, offset);
		break;
	case 'i':
		r_core_bin_info (core, R_CORE_BIN_ACC_IMPORTS, mode, va, NULL, offset);
		break;
	case 'I':
		r_core_bin_info (core, R_CORE_BIN_ACC_INFO, mode, va, NULL, offset);
		break;
	case 'e':
		r_core_bin_info (core, R_CORE_BIN_ACC_ENTRIES, mode, va, NULL, offset);
		break;
	case 'z':
		r_core_bin_info (core, R_CORE_BIN_ACC_STRINGS, mode, va, NULL, offset);
		break;
	case 'a':
		if (input[1]=='*') {
			cmd_info (core, "I*");
			cmd_info (core, "e*");
			cmd_info (core, "i*");
			cmd_info (core, "s*");
			cmd_info (core, "S*");
			cmd_info (core, "z*");
		} else {
			cmd_info (core, "I");
			cmd_info (core, "e");
			cmd_info (core, "i");
			cmd_info (core, "s");
			cmd_info (core, "S");
			cmd_info (core, "z");
		}
		break;
	case '?':
		r_cons_printf (
		"Usage: i[aeiIsSz]*      ; get info from opened file\n"
		"NOTE: Append a '*' to get the output in radare commands\n"
		" ia    ; show all info (imports, exports, sections..)\n"
		" ii    ; imports\n"
		" iI    ; binary info\n"
		" ie    ; entrypoint\n"
		" is    ; symbols\n"
		" iS    ; sections\n"
		" iz    ; strings\n");
		break;
	case '*':
		break;
	default:
		if (core->file) {
			const char *fn = NULL;
			int dbg = r_config_get_i (core->config, "cfg.debug");
			RBinInfo *info = r_bin_get_info (core->bin);
			if (info) {
				fn = info->file;
				r_cons_printf ("type\t%s\n", info->type);
				r_cons_printf ("os\t%s\n", info->os);
				r_cons_printf ("arch\t%s\n", info->machine);
				r_cons_printf ("bits\t%d\n", info->bits);
				r_cons_printf ("endian\t%s\n", info->big_endian? "big": "little");
			} else {
				fn = core->file->filename;
			}
			r_cons_printf ("file\t%s\n", fn);
			if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
			r_cons_printf ("fd\t%d\n", core->file->fd->fd);
			r_cons_printf ("size\t0x%x\n", core->file->size);
			r_cons_printf ("mode\t%s\n", r_str_rwx_i (core->file->rwx | dbg));
			r_cons_printf ("block\t0x%x\n", core->blocksize);
			r_cons_printf ("uri\t%s\n", core->file->uri);
			if (core->bin->curxtr)
				r_cons_printf ("packet\t%s\n", core->bin->curxtr->name);
			if (core->bin->curxtr)
				r_cons_printf ("format\t%s\n", core->bin->curarch.curplugin->name);
		} else eprintf ("No selected file\n");
	}
	return 0;
}

static void r_core_magic_at(RCore *core, const char *file, ut64 addr, int depth, int v) {
	const char *fmt;
	char *q, *p;
	const char *str;
	static RMagic *ck = NULL; // XXX: Use RCore->magic
	static char *oldfile = NULL;

	if (--depth<0)
		return;
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
			return;
		}
	} else {
		const char *magicpath = r_config_get (core->config, "dir.magic");
		if (r_magic_load (ck, magicpath) == -1)
			eprintf ("failed r_magic_load (dir.magic) %s\n", r_magic_error (ck));
	}
	//if (v) r_cons_printf ("  %d # pm %s @ 0x%"PFMT64x"\n", depth, file? file: "", addr);
	str = r_magic_buffer (ck, core->block, core->blocksize);
	if (str) {
		if (!v && !strcmp (str, "data"))
			return;
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
	}
}

static void r_core_magic(RCore *core, const char *file, int v) {
	ut64 addr = core->offset;
	magicdepth = r_config_get_i (core->config, "magic.depth"); // TODO: do not use global var here
	r_core_magic_at (core, file, addr, magicdepth, v);
	if (addr != core->offset)
		r_core_seek (core, addr, R_TRUE);
}

static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, l, len = core->blocksize;
	ut32 tbs = core->blocksize;

	/* TODO: Change also blocksize for 'pd'.. */
	l = len;
	if (input[0] && input[1]) {
		if (input[2]) {
			l = (int) r_num_math (core->num, input+(input[1]==' '?2:3));
			/* except disasm and memoryfmt (pd, pm) */
			if (input[0] != 'd' && input[0] != 'm') {
				if (l>0) len = l;
				if (l>tbs) r_core_block_size (core, l);
				l = len;
			}
		}// else l = 0;
	} else l = len;

	i = r_config_get_i (core->config, "cfg.maxbsize");
	if (i && l > i) {
		eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
				*input, input+2);
		return R_FALSE;
	}

	if (input[0] && input[1] == 'f') {
		RAnalFcn *f = r_anal_fcn_find (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) len = f->size;
		else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
	}
	core->num->value = len;
	switch (*input) {
	case '%':
		{
			ut64 off = core->io->off;
			ut64 s = core->file?core->file->size:0;
			ut64 piece = 0;
			int w = core->print->cols * 4;
			piece = s/w;
			r_cons_strcat ("  [");
			for (i=0; i<w; i++) {
				ut64 from = (piece*i);
				ut64 to = from+piece;
				if (off>=from && off<to)
					r_cons_memcat ("#", 1);
				else r_cons_memcat (".", 1);
				// TODO: print where flags are.. code, ..
			}
			r_cons_strcat ("]\n");
		}
		break;
	case '=':
		/* TODO: Reimplement using API */ {
			char *out = r_sys_cmd_strf ("rahash2 -a entropy -b 512 '%s'", core->file->filename);
			if (out) {
				r_cons_strcat (out);
				free (out);
			}
		}
		break;
	case 'b': {
		const int size = len*8;
		char *buf = malloc (size+1);
		if (buf) {
			r_str_bits (buf, core->block, size, NULL);
			r_cons_printf ("%s\n", buf);
			free (buf);
		} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		}
		break;
	case 'w':
		r_print_hexdump (core->print, core->offset, core->block, len, 32, 4);
		break;
	case 'q':
		r_print_hexdump (core->print, core->offset, core->block, len, 64, 8);
		break;
	case 'i': {
		RAsmOp asmop;
		int j, ret, err = 0;
		const ut8 *buf = core->block;
		if (l==0) l = len;
		for (i=j=0; i<core->blocksize && j<len; i+=ret,j++ ) {
			ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
			if (ret<1) {
				ret = err = 1;
				r_cons_printf ("???\n");
			} else r_cons_printf ("%s\n", asmop.buf_asm);
		}
		return err;
		}
	case 'D':
	case 'd':
		switch (input[1]) {
		case 'i': {// TODO
			RAsmOp asmop;
			int j, ret, err = 0;
			const ut8 *buf = core->block;
			if (l==0) l = len;
			for (i=j=0; i<core->blocksize && j<len; i+=ret,j++ ) {
				ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
				if (ret<1) {
					ret = err = 1;
					r_cons_printf ("0x%08"PFMT64x" %14s%02x  %s\n", core->offset+i, "", buf[i], "???");
				} else r_cons_printf ("0x%08"PFMT64x" %16s  %s\n",
					core->offset+i, asmop.buf_hex, asmop.buf_asm);
			}
			return err;
			}
			break;
		case 'a':
			{
				RAsmOp asmop;
				int j, ret, err = 0;
				const ut8 *buf = core->block;
				if (l==0) l = len;
				for (i=j=0; i<core->blocksize && j<len; i++,j++ ) {
					ret = r_asm_disassemble (core->assembler, &asmop, buf+i, core->blocksize-i);
					if (ret<1) {
						ret = err = 1;
						r_cons_printf ("???\n");
					} else r_cons_printf ("0x%08"PFMT64x" %16s  %s\n",
						core->offset+i, asmop.buf_hex, asmop.buf_asm);
				}
				return R_TRUE;
			}
			break;
		case 'b': {
			RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->offset);
			if (b) {
				ut8 *block = malloc (b->size+1);
				if (block) {
					r_core_read_at (core, b->addr, block, b->size);
					core->num->value = r_core_print_disasm (core->print, core, b->addr, block, b->size, 9999);
					free (block);
					return 0;
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			} break;
			break;
		case 'f': {
			RAnalFcn *f = r_anal_fcn_find (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (f) {
				ut8 *block = malloc (f->size+1);
				if (block) {
					r_core_read_at (core, f->addr, block, f->size);
					core->num->value = r_core_print_disasm (core->print, core, f->addr, block, f->size, 9999);
					free (block);
					return 0;
				}
			} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			} break;
		case 'l':
			{
			RAsmOp asmop;
			int j, ret;
			const ut8 *buf = core->block;
			if (l==0) l= len;
			for (i=j=0; i<core->blocksize && j<l; i+=ret,j++ ) {
				ret = r_asm_disassemble (core->assembler, &asmop, buf+i, len-i);
				printf ("%d\n", ret);
				if (ret<1) ret = 1;
			}
			return 0;
			}
			break;
		case '?':
			eprintf ("Usage: pd[f|i|l] [len] @ [addr]\n");
			//TODO: eprintf ("  pdr  : disassemble resume\n");
			eprintf ("  pda  : disassemble all possible opcodes (byte per byte)\n");
			eprintf ("  pdb  : disassemble basic block\n");
			eprintf ("  pdf  : disassemble function\n");
			eprintf ("  pdi  : like 'pi', with offset and bytes\n");
			eprintf ("  pdl  : show instruction sizes\n");
return 0;
			break;
		}
		//if (core->visual)
		//	l = core->cons->rows-core->cons->lines;
		if (l<0) {
			RList *bwdhits;
			RListIter *iter;
			RCoreAsmHit *hit;
			ut8 *block = malloc (core->blocksize);
			if (block) {
				l = -l;
				bwdhits = r_core_asm_bwdisassemble (core, core->offset, l, core->blocksize);
				if (bwdhits) {
					r_list_foreach (bwdhits, iter, hit) {
						r_core_read_at (core, hit->addr, block, core->blocksize);
						core->num->value = r_core_print_disasm (core->print,
							core, hit->addr, block, core->blocksize, l);
						r_cons_printf ("------\n");
					}
					r_list_free (bwdhits);
				}
				free (block);
			}
		} else {
			core->num->value = r_core_print_disasm (core->print, core, core->offset, core->block, len, l);
		}
		break;
	case 's':
		if (input[1]=='p') {
			int mylen = core->block[0];
			// TODO: add support for 2-4 byte length pascal strings
			r_print_string (core->print, core->offset, core->block, mylen, 0, 1, 0); //, 78, 1);
			core->num->value = mylen;
		} else
		if (input[1]==' ') {
			len = r_num_math (core->num, input+2);
			r_print_string (core->print, core->offset, core->block, len, 0, 0, 0); //, 78, 1);
		} else r_print_string (core->print, core->offset, core->block, len, 0, 1, 0); //, 78, 1);
		break;
	case 'S':
		r_print_string (core->print, core->offset, core->block, len, 1, 1, 0); //, 78, 1);
		break;
	case 'm':
		if (input[1]=='?') {
			r_cons_printf ("Usage: pm [file|directory]\n"
				" r_magic will use given file/dir as reference\n"
				" output of those magic can contain expressions like:\n"
				"   foo@0x40   # use 'foo' magic file on address 0x40\n"
				"   @0x40      # use current magic file on address 0x40\n"
				"   \\n         # append newline\n"
				" e dir.magic  # defaults to "R_MAGIC_PATH"\n"
				);
		} else r_core_magic (core, input+1, R_TRUE);
		break;
	case 'u':
		r_print_string (core->print, core->offset, core->block, len, 0, 1, 1); //, 78, 1);
		break;
	case 'U':
		r_print_string (core->print, core->offset, core->block, len, 1, 1, 1); //, 78, 1);
		break;
	case 'c':
		r_print_code (core->print, core->offset, core->block, len); //, 78, 1);
		break;
	case 'r':
		r_print_raw (core->print, core->block, len);
		break;
	case 'o':
		r_print_hexdump (core->print, core->offset, core->block, len, 8, 1); //, 78, !(input[1]=='-'));
		break;
	case 'x':
		r_print_hexdump (core->print, core->offset, core->block, len, 16, 1); //, 78, !(input[1]=='-'));
		break;
	case '6':
		{
		int malen = (core->blocksize*4)+1;
		ut8 *buf = malloc (malen);
		memset (buf, 0, malen);
		switch (input[1]) {
		case 'e':
			r_base64_encode (buf, core->block, core->blocksize);
			printf ("%s\n", buf);
			break;
		case 'd':
			if (r_base64_decode (buf, core->block, core->blocksize))
				printf ("%s\n", buf);
			else eprintf ("r_base64_decode: invalid stream\n");
			break;
		default:
			eprintf ("Usage: p6[ed] [len]  ; base 64 encode/decode\n");
			break;
		}
		free (buf);
		}
		break;
	case '8':
		r_print_bytes (core->print, core->block, len, "%02x");
		break;
	case 'f':
		r_print_format (core->print, core->offset, core->block, len, input+1);
		break;
	case 'n': // easter penis
		for (l=0; l<10; l++) {
			printf ("\r8");
			for (len=0;len<l;len++)
				printf ("=");
			printf ("D");
			r_sys_usleep (100000);
			fflush (stdout);
		}
		for (l=0; l<3; l++) {
			printf ("~");
			fflush (stdout);
			r_sys_usleep (100000);
		}
		printf ("\n");
		break;
	case 't':
		switch (input[1]) {
			case ' ':
			case '\0':
				for (l=0; l<len; l+=sizeof (time_t))
					r_print_date_unix (core->print, core->block+l, sizeof (time_t));
				break;
			case 'd':
				for (l=0; l<len; l+=4)
					r_print_date_dos (core->print, core->block+l, 4);
				break;
			case 'n':
				core->print->bigendian = !core->print->bigendian;
				for (l=0; l<len; l+=sizeof (ut64))
					r_print_date_w32 (core->print, core->block+l, sizeof (ut64));
				core->print->bigendian = !core->print->bigendian;
				break;
		case '?':
			r_cons_printf (
			"Usage: pt[dn?]\n"
			" pt      print unix time (32 bit cfg.bigendian)\n"
			" ptd     print dos time (32 bit cfg.bigendian)\n"
			" ptn     print ntfs time (64 bit !cfg.bigendian)\n"
			" pt?     show help message\n");
			break;
		}
		break;
	case 'Z':
		if (input[1]=='?') {
			r_cons_printf (
			"Usage: pZ [len]\n"
			" print N bytes where each byte represents a block of filesize/N\n"
			"Configuration:\n"
			" zoom.maxsz : max size of block\n"
			" zoom.from  : start address\n"
			" zoom.to    : end address\n"
			" zoom.byte  : specify how to calculate each byte\n"
			"   p : number of printable chars\n"
			"   f : count of flags in block\n"
			"   s : strings in range\n"
			"   0 : number of bytes with value '0'\n"
			"   F : number of bytes with value 0xFF\n"
			"   e : calculate entropy and expand to 0-255 range\n"
			"   h : head (first byte value)\n"
			"WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
		} else {
			char *oldzoom = NULL;
			ut64 maxsize = r_config_get_i (core->config, "zoom.maxsz");
			ut64 from, to;
			int oldva = core->io->va;

			from = 0;
			core->io->va = 0;
			to = r_io_size (core->io);
			from = r_config_get_i (core->config, "zoom.from");
			to = r_config_get_i (core->config, "zoom.to");
			if (input[1] != '\0' && input[1] != ' ') {
				oldzoom = strdup (r_config_get (core->config, "zoom.byte"));
				if (!r_config_set (core->config, "zoom.byte", input+1)) {
					eprintf ("Invalid zoom.byte mode (%s)\n", input+1);
					free (oldzoom);
					return R_FALSE;
				}
			}
			r_print_zoom (core->print, core, printzoomcallback,
				from, to, core->blocksize, (int)maxsize);
			if (oldzoom) {
				r_config_set (core->config, "zoom.byte", oldzoom);
				free (oldzoom);
			}
			if (oldva)
				core->io->va = oldva;
		}
		break;
	default:
		r_cons_printf (
		"Usage: p[fmt] [len]\n"
		" p=           show entropy bars of full file\n"
		" p6[de] [len] base64 decode/encode\n"
		" p8 [len]     8bit hexpair list of bytes\n"
		" pb [len]     bitstream of N bytes\n"
		" pi[f] [len]  show opcodes of N bytes\n"
		" pd[lf] [l]   disassemble N opcodes (see pd?)\n"
		" pD [len]     disassemble N bytes\n"
		" p[w|q] [len] word (32), qword (64) value dump\n"
		" po [len]     octal dump of N bytes\n"
		" pc [len]     output C format\n"
		" pf [fmt]     print formatted data\n"
		" pm [magic]   print libmagic data (pm? for more information)\n"
		" ps [len]     print string\n"
		" psp          print pascal string\n"
		" pS [len]     print wide string\n"
		" pt [len]     print different timestamps\n"
		" pr [len]     print N raw bytes\n"
		" pu [len]     print N url encoded bytes\n"
		" pU [len]     print N wide url encoded bytes\n"
		" px [len]     hexdump of N bytes\n"
		" pZ [len]     print zoom view (see pZ? for help)\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	return 0;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input-1);
}

static void cmd_egg_option (REgg *egg, const char *key, const char *input) {
	if (input[1]!=' ') {
		char *a = r_egg_option_get (egg, key);
		if (a) {
			r_cons_printf ("%s\n", a);
			free (a);
		}
	} else r_egg_option_set (egg, key, input+2);
}
static int cmd_egg_compile(REgg *egg) {
	int i;
	RBuffer *b;
	int ret = R_FALSE;
	char *p = r_egg_option_get (egg, "egg.shellcode");
	if (p && *p) {
		if (!r_egg_shellcode (egg, p)) {
			free (p);
			return R_FALSE;
		}
		free (p);
	}
	r_egg_compile (egg);
	if (!r_egg_assemble (egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
		return R_FALSE;
	}
	p = r_egg_option_get (egg, "egg.padding");
	if (p && *p) {
		r_egg_padding (egg, p);
		free (p);
	}
	p = r_egg_option_get (egg, "egg.encoder");
	if (p && *p) {
		r_egg_encode (egg, p);
		free (p);
	}
	if ((b = r_egg_get_bin (egg))) {
		if (b->length>0) {
			for (i=0; i<b->length; i++)
				r_cons_printf ("%02x", b->buf[i]);
			r_cons_printf ("\n");
		}
		ret = R_TRUE;
	}
	// we do not own this buffer!!
	// r_buf_free (b);
	r_egg_reset (egg);
	return ret;
}

static int cmd_egg(void *data, const char *input) {
	RCore *core = (RCore *)data;
	REgg *egg = core->egg;
	char *oa, *p;
	r_egg_setup (egg,
		r_config_get (core->config, "asm.arch"),
		core->assembler->bits, 0,
		r_config_get (core->config, "asm.os")); // XXX
	switch (*input) {
	case ' ':
		r_egg_load (egg, input+2, 0);
		if (!cmd_egg_compile (egg))
			eprintf ("Cannot compile '%s'\n", input+2);
		break;
	case '\0':
		if (!cmd_egg_compile (egg))
			eprintf ("Cannot compile\n");
		break;
	case 'p':
		cmd_egg_option (egg, "egg.padding", input);
		break;
	case 'e':
		cmd_egg_option (egg, "egg.encoder", input);
		break;
	case 'i':
		cmd_egg_option (egg, "egg.shellcode", input);
		break;
	case 'l':
		{
			RListIter *iter;
			REggPlugin *p;
			r_list_foreach (egg->plugins, iter, p) {
				printf ("%s  %6s : %s\n",
				(p->type==R_EGG_PLUGIN_SHELLCODE)?
					"shc":"enc", p->name, p->desc);
			}
		}
		break;
	case 'r':
		cmd_egg_option (egg, "egg.padding", "");
		cmd_egg_option (egg, "egg.shellcode", "");
		cmd_egg_option (egg, "egg.encoder", "");
		break;
	case 'c':
		// list, get, set egg options
		switch (input[1]) {
		case ' ':
			oa = strdup (input+2);
			p = strchr (oa, '=');
			if (p) {
				*p = 0;
				r_egg_option_set (egg, oa, p+1);
			} else {
				char *o = r_egg_option_get (egg, oa);
				if (o) {
					r_cons_printf ("%s\n", o);
					free (o);
				}
			}
			break;
		case '\0':
			// list
			r_pair_list (egg->pair,NULL);
			eprintf ("list options\n");
			break;
		default:
			eprintf ("Usage: gc [k=v]\n");
			break;
		}
		break;
	case '?':
		eprintf ("Usage: g[wcilper] [arg]\n"
			" g foo.r        : compile r_egg source file\n"
			" gw             : compile and write\n"
			" gc cmd=/bin/ls : set config option for shellcodes and encoders\n"
			" gc             : list all config options\n"
			" gl             : list plugins (shellcodes, encoders)\n"
			" gi exec        : compile shellcode. like ragg2 -i\n"
			" gp padding     : define padding for command\n"
			" ge xor         : specify an encoder\n"
			" gr             : reset r_egg\n"
			"EVAL VARS: asm.arch, asm.bits, asm.os\n"
		);
		break;
	}
	return R_TRUE;
}

static int cmd_flag(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = NULL;
	ut64 off = core->offset;

	if (*input)
		str = strdup (input+1);
	switch (*input) {
	case '+':
	case ' ': {
		char *s = NULL, *s2 = NULL;
		ut32 bsze = core->blocksize;
		s = strchr (str, ' ');
		if (s) {
			*s = '\0';
			s2 = strchr (s+1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1]&&s2[2])
					off = r_num_math (core->num, s2+1);
			}
			bsze = r_num_math (core->num, s+1);
		}
		r_flag_set (core->flags, str, off, bsze, (*input=='+'));
		}
		break;
	case '-':
		if (input[1]) {
			if (strchr (input+1, '*'))
				r_flag_unset_glob (core->flags, input+1);
			else r_flag_unset (core->flags, input+1, NULL);
		} else r_flag_unset_i (core->flags, off, NULL);
		break;
	case 'l':
		if (input[1] == ' ') {
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
			}
		} else eprintf ("Missing arguments\n");
		break;
	case 'S':
		r_flag_sort (core->flags, (input[1]=='n'));
		break;
	case 's':
		if (input[1]==' ') r_flag_space_set (core->flags, input+2);
		else r_flag_space_list (core->flags);
		break;
	case 'o':
		{ // TODO: use file.fortunes
			char *file = R2_PREFIX"/share/doc/radare2/fortunes";
			char *line = r_file_slurp_random_line (file);
			if (line) {
				r_cons_printf (" -- %s\n", line);
				free (line);
			}
		}
		break;
	case 'r':
		{
			char *old, *new;
			RFlagItem *item;
			old = str+1;
			new = strchr (old, ' ');
			if (new) {
				*new = 0;
				new++;
				item = r_flag_get (core->flags, old);
			} else {
				new = old;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) r_flag_rename (core->flags, item, new);
			else eprintf ("Cannot find flag\n");
		}
		break;
	case '*':
		r_flag_list (core->flags, 1);
		break;
	case '\0':
		r_flag_list (core->flags, 0);
		break;
	case 'd':
		{
			ut64 addr = 0;
			RFlagItem *f = NULL;
			switch (input[1]) {
			case '?':
				eprintf ("Usage: fd [off]\n");
				return R_FALSE;
			case '\0':
				addr = core->offset;
				break;
			default:
				addr = r_num_math (core->num, input+2);
				break;
			}
			f = r_flag_get_at (core->flags, addr);
			if (f) {
				if (f->offset != addr) {
					r_cons_printf ("%s+%d\n", f->name, (int)(addr-f->offset));
				} else r_cons_printf ("%s\n", f->name);
			}
		}
		break;
	case '?':
		r_cons_printf (
		"Usage: f[?] [flagname]\n"
		" f name 12 @ 33   ; set flag 'name' with length 12 at offset 33\n"
		" f name 12 33     ; same as above\n"
		" f+name 12 @ 33   ; like above but creates new one if doesnt exist\n"
		" f-name           ; remove flag 'name'\n"
		" f-@addr          ; remove flag at address expression\n"
		" fd addr          ; return flag+delta\n"
		" f                ; list flags\n"
		" f*               ; list flags in r commands\n"
		" fr [old] [new]   ; rename flag\n"
		" fs functions     ; set flagspace\n"
		" fs *             ; set no flagspace\n"
		" fs               ; display flagspaces\n"
		" fl [flagname]    ; show flag length (size)\n"
		" fS[on]           ; sort flags by offset or name\n"
		" fo               ; show fortunes\n");
		break;
	}
	if (str)
		free (str);
	return 0;
}

static void cmd_syscall_do(RCore *core, int num) {
	int i;
	char str[64];
	RSyscallItem *item = r_syscall_get (core->anal->syscall, num, -1);
	if (item == NULL) {
		r_cons_printf ("%d = unknown ()", num);
		return;
	}
	r_cons_printf ("%d = %s (", item->num, item->name);
	// TODO: move this to r_syscall
	for (i=0; i<item->args; i++) {
		ut64 arg = r_debug_arg_get (core->dbg, R_TRUE, i+1);
		if (item->sargs==NULL)
			r_cons_printf ("0x%08"PFMT64x"", arg);
		else
		switch (item->sargs[i]) {
		case 'p': // pointer
			r_cons_printf ("0x%08"PFMT64x"", arg);
			break;
		case 'i':
			r_cons_printf ("%"PFMT64d"", arg);
			break;
		case 'z':
			r_io_read_at (core->io, arg, (ut8*)str, sizeof (str));
			// TODO: filter zero terminated string
			str[63] = '\0';
			r_str_filter (str, strlen (str));
			r_cons_printf ("\"%s\"", str);
			break;
		default:
			r_cons_printf ("0x%08"PFMT64x"", arg);
			break;
		}
		if (i+1<item->args)
			r_cons_printf (", ");
	}
	r_cons_printf (")\n");
}


#if 1
/* TODO: Move into cmd_anal() */
static void var_help() {
	eprintf("Try afv?\n"
	" afv 12 int buffer[3]\n"
	" afv 12 byte buffer[1024]\n"
	"Try af[aAv][gs] [delta] [[addr]]\n"
	" afag 0  = arg0 get\n"
	" afvs 12 = var12 set\n"
	"a = arg, A = fastarg, v = var\n"
	"TODO: [[addr]] is not yet implemented. use @\n");
}

static int var_cmd(RCore *core, const char *str) {
	RAnalFcn *fcn = r_anal_fcn_find (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
	char *p, *p2, *p3, *ostr;
	int type, delta;

	ostr = p = strdup (str);
	str = (const char *)ostr;

	switch (*str) {
	case 'V': // show vars in human readable format
		r_anal_var_list_show (core->anal, fcn, core->offset);
		break;
	case '?':
		var_help ();
		break;
	case 'v': // frame variable
	case 'a': // stack arg
	case 'A': // fastcall arg
		// XXX nested dup
		switch (*str) {
		case 'v': type = R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE; break;
		case 'a': type = R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN; break;
		case 'A': type = R_ANAL_VAR_TYPE_ARGREG|R_ANAL_VAR_DIR_IN; break;
		default:
			eprintf ("Unknown type\n");
			return 0;
		}

		/* Variable access CFvs = set fun var */
		switch (str[1]) {
		case '\0': r_anal_var_list (core->anal, fcn, 0, 0); return 0;
		case '?': var_help(); return 0;
		case '.': r_anal_var_list (core->anal, fcn, core->offset, 0); return 0;
		case 's':
		case 'g':
			if (str[2]!='\0') {
				if (fcn != NULL) {
					RAnalVar *var = r_anal_var_get (core->anal, fcn, atoi (str+2), R_ANAL_VAR_TYPE_LOCAL);
					if (var != NULL)
						return r_anal_var_access_add (core->anal, var, atoi (str+2), (str[1]=='g')?0:1);
					eprintf ("Can not find variable in: '%s'\n", str);
				} else eprintf ("Unknown variable in: '%s'\n", str);
				return R_FALSE;
			} else eprintf ("Missing argument\n");
			break;
		}
		str++;
		if (str[0]==' ') str++;
		delta = atoi (str);
		p = strchr (str, ' ');
		if (p==NULL) {
			var_help();
			break;
		}
		p[0]='\0'; p++;
		p2 = strchr (p, ' ');
		if (p2) {
			p2[0]='\0'; p2 = p2+1;
			p3 = strchr (p2,'[');
			if (p3 != NULL) {
				p3[0]='\0';
				p3=p3+1;
			}
			r_anal_var_add (core->anal, fcn, core->offset, delta, type, p, p2, p3?atoi(p3):0);
		} else var_help ();
		break;
	default:
		var_help ();
		break;
	}
	free (ostr);
	return 0;
}
#endif

static int preludecnt = 0;
static int __prelude_cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	int depth = r_config_get_i (core->config, "anal.depth");
	//eprintf ("ap: Found function prelude %d at 0x%08"PFMT64x"\n", preludecnt, addr);
	r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	preludecnt++;
	return R_TRUE;
}

R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	int ret;
	ut64 at;
	ut8 *b = (ut8 *)malloc (core->blocksize);
// TODO: handle sections ?
	r_search_reset (core->search, R_SEARCH_KEYWORD);
	r_search_kw_add (core->search,
		r_search_keyword_new (buf, blen, mask, mlen, NULL));
	r_search_begin (core->search);
	r_search_set_callback (core->search, &__prelude_cb_hit, core);
	preludecnt = 0;
	for (at = from; at < to; at += core->blocksize) {
		if (r_cons_singleton ()->breaked)
			break;
		ret = r_io_read_at (core->io, at, b, core->blocksize);
		if (ret != core->blocksize)
			break;
		if (r_search_update (core->search, &at, b, ret) == -1) {
			eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
			break;
		}
	}
	eprintf ("Analized %d functions based on preludes\n", preludecnt);
	free (b);
	return preludecnt;
}

R_API int r_core_search_preludes(RCore *core) {
	int ret = -1;
	const char *prelude = r_config_get (core->config, "anal.prelude");
	const char *arch = r_config_get (core->config, "asm.arch");
	int bits = r_config_get_i (core->config, "asm.bits");
	ut64 from = core->offset;
	ut64 to = core->offset+0xffffff; // hacky!
	// TODO: this is x86 only
	if (prelude && *prelude) {
		ut8 *kw = malloc (strlen (prelude));
		int kwlen = r_hex_str2bin (prelude, kw);
		ret = r_core_search_prelude (core, from, to, kw, kwlen, NULL, 0);
		free (kw);
	} else
	if (strstr (arch, "x86")) {
		switch (bits) {
		case 32:
			ret = r_core_search_prelude (core, from, to, (const ut8 *)"\x55\x89\xe5", 3, NULL, 0);
			break;
		case 64:
			ret = r_core_search_prelude (core, from, to, (const ut8 *)"\x55\x48\x89\xe5", 3, NULL, 0);
			//r_core_cmd0 (core, "./x 554989e5");
			break;
		default:
			eprintf ("ap: Unsupported bits: %d\n", bits);
		}
	} else eprintf ("ap: Unsupported asm.arch and asm.bits\n");
	return ret;
}

static void r_core_anal_bytes (RCore *core, const ut8 *buf, int len) {
	int ret, idx;
	RAnalOp op;

	for (idx=ret=0; idx<len; idx+=ret) {
		ret = r_anal_op (core->anal, &op,
				core->offset+idx, buf + idx, (len-idx));
		if (ret<1) {
			eprintf ("Oops at 0x%08"PFMT64x" (%02x %02x %02x ...)\n",
					core->offset+idx, buf[idx], buf[idx+1], buf[idx+2]);
			break;
		}
		r_cons_printf ("addr: 0x%08"PFMT64x"\n", core->offset+idx);
		r_cons_printf ("size: %d\n", op.length);
		r_cons_printf ("type: %d\n", op.type); // TODO: string
		r_cons_printf ("eob: %d\n", op.eob);
		r_cons_printf ("jump: 0x%08"PFMT64x"\n", op.jump);
		r_cons_printf ("fail: 0x%08"PFMT64x"\n", op.fail);
		r_cons_printf ("stack: %d\n", op.stackop); // TODO: string
		r_cons_printf ("cond: %d\n", op.cond); // TODO: string
		r_cons_printf ("family: %d\n", op.family);
		r_cons_printf ("\n");
		//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
	}
}

static int cmd_anal(void *data, const char *input) {
	const char *ptr;
	RCore *core = (RCore *)data;
	int l, len = core->blocksize;
	ut64 addr = core->offset;
	ut32 tbs = core->blocksize;

	if (input[0] && input[1]) {
		l = (int) r_num_get (core->num, input+2);
		if (l>0) len = l;
		if (l>tbs) {
			r_core_block_size (core, l);
			len = l;
		}
	}

	r_cons_break (NULL, NULL);

	switch (input[0]) {
	case 'b':
		if (input[1]==' ') {
			int len;
			ut8 *buf = malloc (strlen (input));
			len = r_hex_str2bin (input+2, buf);
			if (len>0) {
				r_core_anal_bytes (core, buf, len);
			}
			free (buf);
		} else eprintf ("Usage: ab [hexpair-bytes]\n");
		break;
	case '8':
		if (input[1]==' ') {
			RAsmCode *c = r_asm_mdisassemble_hexstr (core->assembler, input+2);
			r_cons_puts (c->buf_asm);
			r_asm_code_free (c);
		} else eprintf ("Usage: a8 [hexpair-bytes]\n");
		break;
	case 'x':
		switch (input[1]) {
		case '\0':
		case ' ':
			// list xrefs from current address
			{
				ut64 addr = input[1]?  r_num_math (core->num, input+1): core->offset;
				RAnalFcn *fcn = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					RAnalRef *ref;
					RListIter *iter;
					r_list_foreach (fcn->refs, iter, ref) {
						r_cons_printf ("%c 0x%08"PFMT64x" -> 0x%08"PFMT64x"\n",
							ref->type, ref->at, ref->addr);
					}
				} else eprintf ("Cant find function\n");
			}
			break;
		case 'c': // add meta xref
		case 'd':
		case 'C': {
				char *p;
				ut64 a, b;
				RAnalFcn *fcn;
				char *mi = strdup (input);
				if (mi && mi[2]==' ' && (p=strchr (mi+3, ' '))) {
					*p = 0;
					a = r_num_math (core->num, mi+2);
					b = r_num_math (core->num, p+1);
					fcn = r_anal_fcn_find (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					if (fcn) {
						r_anal_fcn_xref_add (core->anal, fcn, a, b, input[1]);
					} else eprintf ("Cannot add reference to non-function\n");
				} else eprintf ("Usage: ax[cCd?] [src] [dst]\n");
				free (mi);
			}
			break;
		case '-': {
				char *p;
				ut64 a, b;
				RAnalFcn *fcn;
				char *mi = strdup (input);
				if (mi && mi[2]==' ' && (p=strchr (mi+3, ' '))) {
					*p = 0;
					a = r_num_math (core->num, mi+2);
					b = r_num_math (core->num, p+1);
					fcn = r_anal_fcn_find (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
					if (fcn) {
						r_anal_fcn_xref_del (core->anal, fcn, a, b, -1);
					} else eprintf ("Cannot del reference to non-function\n");
				} else eprintf ("Usage: ax- [src] [dst]\n");
				free (mi);
			}
			break;
		default:
		case '?':
			r_cons_printf (
			"Usage: ax[-cCd?] [src] [dst]\n"
			" axc sym.main+0x38 sym.printf   ; add code ref\n"
			" axC sym.main sym.puts          ; add call ref\n"
			" axd sym.main str.helloworld    ; add data ref\n"
			" ax- sym.main str.helloworld    ; remove reference\n");
			break;
		}
		break;
	case 'o':
		if (input[1] == '?') {
			r_cons_printf (
			"Usage: ao[e?] [len]\n"
			" aoe      ; emulate opcode at current offset\n"
			" aoe 4    ; emulate 4 opcodes starting at current offset\n"
			" ao 5     ; display opcode analysis of 5 opcodes\n");
		} else
		if (input[1] == 'e') {
			eprintf ("TODO: r_anal_op_execute\n");
		} else {
			r_core_anal_bytes (core, core->block, len);
		}
		break;
	case 'f':
		switch (input[1]) {
		case '-':
			r_anal_fcn_del (core->anal, r_num_math (core->num, input+2));
			break;
		case '+':
			{
			char *ptr = strdup(input+3), *ptr2;
			int n = r_str_word_set0 (ptr);
			const char *name = NULL;
			ut64 addr = -1LL;
			ut64 size = 0LL;
			RAnalDiff *diff = NULL;
			int type = R_ANAL_FCN_TYPE_FCN;

			if (n > 2) {
				switch(n) {
				case 5:
					ptr2 = r_str_word_get0 (ptr, 4);
					if (!(diff = r_anal_diff_new ())) {
						eprintf ("error: Cannot init RAnalDiff\n");
						free (ptr);
						return R_FALSE;
					}
					if (ptr2[0] == 'm')
						diff->type = R_ANAL_DIFF_TYPE_MATCH;
					else if (ptr2[0] == 'u')
						diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
				case 4:
					ptr2 = r_str_word_get0 (ptr, 3);
					if (strchr (ptr2, 'l'))
						type = R_ANAL_FCN_TYPE_LOC;
					else if (strchr (ptr2, 'i'))
						type = R_ANAL_FCN_TYPE_IMP;
					else if (strchr (ptr2, 's'))
						type = R_ANAL_FCN_TYPE_SYM;
					else type = R_ANAL_FCN_TYPE_FCN;
				case 3:
					name = r_str_word_get0 (ptr, 2);
				case 2:
					size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				case 1:
					addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if (!r_anal_fcn_add (core->anal, addr, size, name, type, diff))
					eprintf ("Cannot add function (duplicated)\n");
			}
			r_anal_diff_free (diff);
			free (ptr);
			}
			break;
		case 'i':
			r_core_anal_fcn_list (core, input+2, 0);
			break;
		case 'l':
			{
				RAnalFcn *fcn;
				RListIter *iter;

				r_list_foreach (core->anal->fcns, iter, fcn) {
					int bbs = r_list_length (fcn->bbs);
					r_cons_printf ("0x%08"PFMT64x" %6"PFMT64d" %3d  %s\n",
						fcn->addr, fcn->size, bbs, fcn->name);
				}
			}
			break;
		case '*':
			r_core_anal_fcn_list (core, input+2, 1);
			break;
		case 's': {
			ut64 addr;
			RAnalFcn *f;
			const char *arg = input+3;
			if (input[2] && (addr = r_num_math (core->num, arg))) {
				arg = strchr (arg, ' ');
				if (arg) arg++;
			} else addr = core->offset;
			if ((f = r_anal_fcn_find (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
				if (arg && *arg) {
					r_anal_fcn_from_string (core->anal, f, arg);
				} else {
					char *str = r_anal_fcn_to_string (core->anal, f);
					r_cons_printf ("%s\n", str);
					free (str);
				}
			} else eprintf("No function defined at 0x%08"PFMT64x"\n", addr);
			}
			break;
		case 'a':
		case 'A':
		case 'v':
			var_cmd (core, input+1);
			break;
		case 'c':
			{
			RAnalFcn *fcn;
			int cc;
			if ((fcn = r_anal_get_fcn_at (core->anal, core->offset)) != NULL) {
				cc = r_anal_fcn_cc (fcn);
				r_cons_printf ("CyclomaticComplexity 0x%08"PFMT64x" = %i\n",
						fcn->addr, cc);
			} else eprintf ("Error: function not found\n");
			}
			break;
		case 'b':
			{
			char *ptr = strdup(input+3), *ptr2 = NULL;
			ut64 fcnaddr = -1LL, addr = -1LL;
			ut64 size = 0LL;
			ut64 jump = -1LL;
			ut64 fail = -1LL;
			int type = R_ANAL_BB_TYPE_NULL;
			RAnalFcn *fcn = NULL;
			RAnalDiff *diff = NULL;

			switch(r_str_word_set0 (ptr)) {
			case 7:
				ptr2 = r_str_word_get0 (ptr, 6);
				if (!(diff = r_anal_diff_new ())) {
					eprintf ("error: Cannot init RAnalDiff\n");
					free (ptr);
					return R_FALSE;
				}
				if (ptr2[0] == 'm')
					diff->type = R_ANAL_DIFF_TYPE_MATCH;
				else if (ptr2[0] == 'u')
					diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			case 6:
				ptr2 = r_str_word_get0 (ptr, 5);
				if (strchr (ptr2, 'h'))
					type |= R_ANAL_BB_TYPE_HEAD;
				if (strchr (ptr2, 'b'))
					type |= R_ANAL_BB_TYPE_BODY;
				if (strchr (ptr2, 'l'))
					type |= R_ANAL_BB_TYPE_LAST;
				if (strchr (ptr2, 'f'))
					type |= R_ANAL_BB_TYPE_FOOT;
			case 5: // get fail
				fail = r_num_math (core->num, r_str_word_get0 (ptr, 4));
			case 4: // get jump
				jump = r_num_math (core->num, r_str_word_get0 (ptr, 3));
			case 3: // get size
				size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
			case 2: // get addr
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get fcnaddr
				fcnaddr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			if ((fcn = r_anal_get_fcn_at (core->anal, fcnaddr)) == NULL ||
				!r_anal_fcn_add_bb (fcn, addr, size, jump, fail, type, diff))
				eprintf ("Error: Cannot add bb\n");
			r_anal_diff_free (diff);
			free (ptr);
			}
			break;
		case '?':
			r_cons_printf (
			"Usage: af[?+-l*]\n"
			" af @ [addr]               ; Analyze functions (start at addr)\n"
			" af+ addr size name [type] [diff] ; Add function\n"
			" afb fcnaddr addr size name [type] [diff] ; Add bb to function @ fcnaddr\n"
			" af- [addr]                ; Clean all function analysis data (or function at addr)\n"
			" afl [fcn name]            ; List functions (addr, size, bbs, name)\n"
			" afi [fcn name]            ; Show function(s) information (verbose afl)\n"
			" afs [addr] [fcnsign]      ; Get/set function signature at current address\n"
			" af[aAv][?] [arg]          ; Manipulate args, fastargs and variables in function\n"
			" afc @ [addr]              ; Calculate the Cyclomatic Complexity (starting at addr)\n"
			" af*                       ; Output radare commands\n");
			break;
		default:
			r_core_anal_fcn (core, core->offset, -1, R_ANAL_REF_TYPE_NULL,
					r_config_get_i (core->config, "anal.depth"));
		}
		break;
	case 'g':
		switch (input[1]) {
		case 'c':
			r_core_anal_refs (core, r_num_math (core->num, input+2), 1);
			break;
		case 'l':
			r_core_anal_graph (core, r_num_math (core->num, input+2), R_CORE_ANAL_GRAPHLINES);
			break;
		case 'a':
			r_core_anal_graph (core, r_num_math (core->num, input+2), 0);
			break;
		case 'd':
			r_core_anal_graph (core, r_num_math (core->num, input+2),
					R_CORE_ANAL_GRAPHBODY|R_CORE_ANAL_GRAPHDIFF);
			break;
		case '?':
			r_cons_printf (
			"Usage: ag[?f]\n"
			" ag [addr]       ; Output graphviz code (bb at addr and children)\n"
			" aga [addr]      ; Idem, but only addresses\n"
			" agc [addr]      ; Output graphviz call graph of function\n"
			" agl [fcn name]  ; Output graphviz code using meta-data\n"
			" agd [fcn name]  ; Output graphviz code of diffed function\n"
			" agfl [fcn name] ; Output graphviz code of function using meta-data\n");
			break;
		default:
			r_core_anal_graph (core, r_num_math (core->num, input+1),
				R_CORE_ANAL_GRAPHBODY);
		}
		break;
	case 't':
		switch (input[1]) {
		case '?':
			r_cons_strcat ("Usage: at[*] [addr]\n"
			" at?                ; show help message\n"
			" at                 ; list all traced opcode ranges\n"
			" at-                ; reset the tracing information\n"
			" at*                ; list all traced opcode offsets\n"
			" at+ [addr] [times] ; add trace for address N times\n"
			" at [addr]          ; show trace info at address\n"
			" att [tag]          ; select trace tag (no arg unsets)\n"
			" at%                ; TODO\n"
			" ata 0x804020 ...   ; only trace given addresses\n"
			" atr                ; show traces as range commands (ar+)\n"
			" atd                ; show disassembly trace\n"
			" atD                ; show dwarf trace (at*|rsc dwarf-traces $FILE)\n");
			eprintf ("Current Tag: %d\n", core->dbg->trace->tag);
			break;
		case 'a':
			eprintf ("NOTE: Ensure given addresses are in 0x%%08"PFMT64x" format\n");
			r_debug_trace_at (core->dbg, input+2);
			break;
		case 't':
			r_debug_trace_tag (core->dbg, atoi (input+2));
			break;
		case 'd':
			//trace_show (2, trace_tag_get());
			eprintf ("TODO\n");
			break;
		case 'D':
			// XXX: not yet tested..and rsc dwarf-traces comes from r1
			r_core_cmd (core, "at*|rsc dwarf-traces $FILE", 0);
			break;
		case '+':
			ptr = input+3;
			addr = r_num_math (core->num, ptr);
			ptr = strchr (ptr, ' ');
			if (ptr != NULL) {
				RAnalOp *op = r_core_op_anal (core, addr);
				if (op != NULL) {
					//eprintf("at(0x%08"PFMT64x")=%d (%s)\n", addr, atoi(ptr+1), ptr+1);
					//trace_set_times(addr, atoi(ptr+1));
					RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, op->length);
					tp->count = atoi (ptr+1);
					r_anal_trace_bb (core->anal, addr);
					r_anal_op_free (op);
				} else eprintf ("Cannot analyze opcode at 0x%"PFMT64x"\n", addr);
			}
			break;
		case '-':
			r_debug_trace_free (core->dbg);
			core->dbg->trace = r_debug_trace_new (core->dbg);
			break;
		case ' ': {
			RDebugTracepoint *t = r_debug_trace_get (core->dbg,
				r_num_math (core->num, input+1));
			if (t != NULL) {
				r_cons_printf ("offset = 0x%"PFMT64x"\n", t->addr);
				r_cons_printf ("opsize = %d\n", t->size);
				r_cons_printf ("times = %d\n", t->times);
				r_cons_printf ("count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			} }
			break;
		case '*':
			r_debug_trace_list (core->dbg, 1);
			break;
		case 'r':
			eprintf ("TODO\n");
			//trace_show(-1, trace_tag_get());
			break;
		default:
			r_debug_trace_list (core->dbg, 0);
		}
		break;
	case 's':
		switch (input[1]) {
		case 'l':
			if (input[2] == ' ') {
				int n = atoi (input+3);
				if (n>0) {
					RSyscallItem *si = r_syscall_get (core->anal->syscall, n, -1);
					if (si) r_cons_printf ("%s\n", si->name);
					else eprintf ("Unknown syscall number\n");
				} else {
					int n = r_syscall_get_num (core->anal->syscall, input+3);
					if (n != -1) r_cons_printf ("%d\n", n);
					else eprintf ("Unknown syscall name\n");
				}
			} else {
				RSyscallItem *si;
				RListIter *iter;
				RList *list = r_syscall_list (core->anal->syscall);
				r_list_foreach (list, iter, si) {
					r_cons_printf ("%s = 0x%02x.%d\n", si->name, si->swi, si->num);
				}
				r_list_free (list);
			}
			break;
		case '\0': {
			int a0 = (int)r_debug_reg_get (core->dbg, "oeax"); //XXX
			cmd_syscall_do (core, a0);
			} break;
		case ' ':
			cmd_syscall_do (core, (int)r_num_get (core->num, input+2));
			break;
		default:
		case '?':
			r_cons_printf (
			"Usage: as[l?]\n"
			" as         Display syscall and arguments\n"
			" as 4       Show syscall 4 based on asm.os and current regs/mem\n"
			" asl        List of syscalls by asm.os and asm.arch\n"
			" asl close  Returns the syscall number for close\n"
			" asl 4      Returns the name of the syscall number 4\n");
			break;
		}
		break;
	case 'r':
		switch(input[1]) {
		case '?':
			r_cons_printf (
			"Usage: ar[?d-l*]\n"
			" ar addr [at]   ; Add code ref\n"
			" ard addr [at]  ; Add dara ref\n"
			" ar- [at]       ; Clean all refs (or refs from addr)\n"
			" arl            ; List refs\n"
			" ar*            ; Output radare commands\n");
			break;
		case '-':
			r_anal_ref_del (core->anal, r_num_math (core->num, input+2));
			break;
		case 'l':
			r_core_anal_ref_list (core, R_FALSE);
			break;
		case '*':
			r_core_anal_ref_list (core, R_TRUE);
			break;
		default:
			{
			char *ptr = strdup (r_str_trim_head ((char*)input+2));
			int n = r_str_word_set0 (ptr);
			ut64 at = core->offset;
			ut64 addr = -1LL;
			switch (n) {
			case 2: // get at
				at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1: // get addr
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				break;
			default:
				return R_FALSE;
			}
			r_anal_ref_add (core->anal, addr, at,
					input[1]=='d'?R_ANAL_REF_TYPE_DATA:R_ANAL_REF_TYPE_CODE);
			free (ptr);
			}
		}
		break;
	case 'a':
		r_cons_break (NULL, NULL);
		r_core_anal_all (core);
		if (core->cons->breaked)
			eprintf ("Interrupted\n");
		r_cons_break_end();
		break;
	case 'p':
		r_core_search_preludes (core);
		break;
	case 'd':
		{
			int i, bits = r_config_get_i (core->config, "asm.bits");
			char *p, *inp = strdup (input+2);
			p = strchr (inp, ' ');
			if (p) *p=0;
			ut64 a = r_num_math (core->num, inp);
			ut64 b = p?r_num_math (core->num, p+1):0;
			free (inp);
			switch (bits) {
			case 32:
				for (i=0; i<core->blocksize; i+=4) {
					ut32 n;
					memcpy (&n, core->block+i, sizeof(ut32));
					if (n>=a && n<=b) {
						r_cons_printf ("f trampoline.%x @ 0x%"PFMT64x"\n", n, core->offset+i);
						r_cons_printf ("Cd 4 @ 0x%"PFMT64x":4\n", core->offset+i);
						// TODO: add data xrefs
					}
				}
				break;
			case 64:
				for (i=0; i<core->blocksize; i+=8) {
					ut32 n;
					memcpy (&n, core->block+i, sizeof(ut32));
					if (n>=a && n<=b) {
						r_cons_printf ("f trampoline.%"PFMT64x" @ 0x%"PFMT64x"\n", n, core->offset+i);
						r_cons_printf ("Cd 8 @ 0x%"PFMT64x":8\n", core->offset+i);
						// TODO: add data xrefs
					}
				}
				break;
			}
		}
		break;
	default:
		r_cons_printf (
		"Usage: a[?obdfrgtv]\n"
		" aa               ; analyze all (fcns + bbs)\n"
		" a8 [hexpairs]    ; analyze bytes as disassemble\n"
		" ab [hexpairs]    ; analyze bytes as opcodes\n"
		" ad               ; analyze data trampoline (wip)\n"
		" ap               ; find and analyze function preludes\n"
		" ad [from] [to]   ; analyze data pointers to (from-to)\n"
		" as [num]         ; analyze syscall using dbg.reg\n"
		" ax[-cCd] [f] [t] ; manage code/call/data xrefs\n"
		" ao[e?] [len]     ; analyze Opcodes (or emulate it)\n"
		" af[bcsl?+-*]     ; analyze Functions\n"
		" ar[?ld-*]        ; manage refs/xrefs\n"
		" ag[?acgdlf]      ; output Graphviz code\n"
		" at[trd+-*?] [.]  ; analyze execution Traces\n"
		"Examples:\n"
		" f ts @ `S*~text:0[3]`; f t @ section..text\n"
		" f ds @ `S*~data:0[3]`; f d @ section..data\n"
		" .ad t t+ts @ d:ds\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	if (core->cons->breaked)
		eprintf ("Interrupted\n");
	r_cons_break_end();
	return 0;
}

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	ut64 off;
	ut8 *buf;
	const char *arg;
	int wseek, i, size, len = strlen (input);
	char *tmp, *str, *ostr;
	RCore *core = (RCore *)data;
	#define WSEEK(x,y) if(wseek)r_core_seek_delta(x,y)
	wseek = r_config_get_i (core->config, "cfg.wseek");
	str = ostr = strdup (input+1);

	switch (*input) {
	case 'p':
		if (input[1]==' ' && input[2]) {
			r_core_patch (core, input+2);
		} else {
			eprintf ("Usage: wp [rapatch-file]\n"
			         "TODO: rapatch format documentation here\n");
		}
		break;
	case 'r':
		off = r_num_math (core->num, input+1);
		len = (int)off;
		if (len>0) {
			buf = malloc (len);
			if (buf != NULL) {
				r_num_irand ();
				for (i=0; i<len; i++)
					buf[i] = r_num_rand (256);
				r_core_write_at (core, core->offset, buf, len);
				WSEEK (core, len);
				free (buf);
			} else eprintf ("Cannot allocate %d bytes\n", len);
		}
		break;
	case 'A':
		switch (input[1]) {
		case ' ':
			if (input[2] && input[3]==' ') {
				r_asm_set_pc (core->assembler, core->offset);
				eprintf ("modify (%c)=%s\n", input[2], input+4);
				len = r_asm_modify (core->assembler, core->block, input[2],
					r_num_math (core->num, input+4));
				eprintf ("len=%d\n", len);
				if (len>0) {
					r_core_write_at (core, core->offset, core->block, len);
					WSEEK (core, len);
				} else eprintf ("r_asm_modify = %d\n", len);
			} else eprintf ("Usage: wA [type] [value]\n");
			break;
		case '?':
		default:
			r_cons_printf ("Usage: wA [type] [value]\n"
			"Types:\n"
			" r   raw write value\n"
			" v   set value (taking care of current address)\n"
			" d   destination register\n"
			" 0   1st src register\n"
			" 1   2nd src register\n"
			"Example: wA r 0 # e800000000\n");
			break;
		}
		break;
	case 'c':
		switch (input[1]) {
		case 'i':
			r_io_cache_commit (core->io);
			r_core_block_read (core, 0);
			break;
		case 'r':
			r_io_cache_reset (core->io, R_TRUE);
			/* Before loading the core block we have to make sure that if
			 * the cache wrote past the original EOF these changes are no
			 * longer displayed. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '-':
			if (input[2]=='*') {
				r_io_cache_reset (core->io, R_TRUE);
			} else if (input[2]==' ') {
				char *p = strchr (input+3, ' ');
				ut64 to, from = core->offset;
				if (p) {
					*p = 0;
					from = r_num_math (core->num, input+3);
					to = r_num_math (core->num, input+3);
					if (to<from) {
						eprintf ("Invalid range (from>to)\n");
						return 0;
					}
				} else {
					from = r_num_math (core->num, input+3);
					to = from + core->blocksize;
				}
				r_io_cache_invalidate (core->io, from, to);
			} else {
				eprintf ("Invalidate write cache at 0x%08"PFMT64x"\n", core->offset);
				r_io_cache_invalidate (core->io, core->offset, core->offset+core->blocksize);
			}
			/* See 'r' above. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '?':
			r_cons_printf (
			"Usage: wc[ir*?]\n"
			" wc           list all write changes\n"
			" wc- [a] [b]  remove write op at curseek or given addr\n"
			" wc*          \"\" in radare commands\n"
			" wcr          reset all write changes in cache\n"
			" wci          commit write cache\n"
			"NOTE: Requires 'e io.cache=true'\n");
			break;
		case '*':
			r_io_cache_list (core->io, R_TRUE);
			break;
		case '\0':
			r_io_cache_list (core->io, R_FALSE);
			break;
		}
		break;
	case ' ':
		/* write string */
		len = r_str_escape (str);
		r_io_set_fd (core->io, core->file->fd);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
		WSEEK (core, len);
		r_core_block_read (core, 0);
		break;
	case 't':
		/* TODO: support userdefined size? */
		arg = (const char *)(input+((input[1]==' ')?2:1));
		r_file_dump (arg, core->block, core->blocksize);
		break;
	case 'T':
		eprintf ("TODO\n");
		break;
	case 'f':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if ((buf = (ut8*) r_file_slurp (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free(buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'F':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if ((buf = r_file_slurp_hexpairs (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'w':
		str++;
		len = (len-1)<<1;
		if (len>0) tmp = malloc (len+1);
		else tmp = NULL;
		if (tmp) {
			for (i=0; i<len; i++) {
				if (i%2) tmp[i] = 0;
				else tmp[i] = str[i>>1];
			}
			str = tmp;
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, (const ut8*)str, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
			free (tmp);
		} else eprintf ("Cannot malloc %d\n", len);
		break;
	case 'x':
		{
		int len = strlen (input);
		ut8 *buf = malloc (len+1);
		len = r_hex_str2bin (input+1, buf);
		if (len != -1) {
			r_core_write_at (core, core->offset, buf, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
		} else eprintf ("Error: invalid hexpair string\n");
		free (buf);
		}
		break;
	case 'a':
		switch (input[1]) {
		case 'o':
			if (input[2] == ' ')
				r_core_hack (core, input+3);
			else r_core_hack_help (core);
			break;
		case ' ':
		case '*':
			{ const char *file = input[1]=='*'? input+2: input+1;
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, file);
			if (acode) {
				if (input[1]=='*') {
					r_cons_printf ("wx %s\n", acode->buf_hex);
				} else {
					if (r_config_get_i (core->config, "scr.prompt"))
					eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
					r_core_write_at (core, core->offset, acode->buf, acode->len);
					WSEEK (core, acode->len);
					r_core_block_read (core, 0);
				}
				r_asm_code_free (acode);
			}
			} break;
		case 'f':
			if ((input[2]==' '||input[2]=='*')) {
				const char *file = input[2]=='*'? input+4: input+3;
				RAsmCode *acode;
				r_asm_set_pc (core->assembler, core->offset);
				acode = r_asm_assemble_file (core->assembler, file);
				if (acode) {
					if (input[2]=='*') {
						r_cons_printf ("wx %s\n", acode->buf_hex);
					} else {
						if (r_config_get_i (core->config, "scr.prompt"))
						eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
						r_core_write_at (core, core->offset, acode->buf, acode->len);
						WSEEK (core, acode->len);
						r_core_block_read (core, 0);
					}
					r_asm_code_free (acode);
				} else eprintf ("Cannot assemble file\n");
			} else eprintf ("Wrong argument\n");
			break;
		default:
			eprintf ("Usage: wa[of*] [arg]\n"
				" wa nop           : write nopcode using asm.arch and asm.bits\n"
				" wa* mov eax, 33  : show 'wx' op with hexpair bytes of sassembled opcode\n"
				" \"wa nop;nop\"     : assemble more than one instruction (note the quotes)\n"
				" waf foo.asm      : assemble file and write bytes\n"
				" wao nop          : convert current opcode into nops\n"
				" wao?             : show help for assembler operation on current opcode (hack)\n");
			break;
		}
		break;
	case 'b':
		{
		int len = strlen (input);
		ut8 *buf = malloc (len+1);
		if (buf) {
			len = r_hex_str2bin (input+1, buf);
			if (len > 0) {
				r_mem_copyloop (core->block, buf, core->blocksize, len);
				r_core_write_at (core, core->offset, core->block, core->blocksize);
				WSEEK (core, core->blocksize);
				r_core_block_read (core, 0);
			} else eprintf ("Wrong argument\n");
		} else eprintf ("Cannot malloc %d\n", len+1);
		}
		break;
	case 'm':
		size = r_hex_str2bin (input+1, (ut8*)str);
		switch (input[1]) {
		case '\0':
			eprintf ("Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask(core->io, 0, 0);
			eprintf ("Write mask disabled\n");
			break;
		case ' ':
			if (size>0) {
				r_io_set_fd (core->io, core->file->fd);
				r_io_set_write_mask (core->io, (const ut8*)str, size);
				WSEEK (core, size);
				eprintf ("Write mask set to '");
				for (i=0; i<size; i++)
					eprintf ("%02x", str[i]);
				eprintf ("'\n");
			} else eprintf ("Invalid string\n");
			break;
		}
		break;
	case 'v':
		off = r_num_math (core->num, input+1);
		r_io_set_fd (core->io, core->file->fd);
		r_io_seek (core->io, core->offset, R_IO_SEEK_SET);
		if (off&UT64_32U) {
			/* 8 byte addr */
			ut64 addr8;
			memcpy((ut8*)&addr8, (ut8*)&off, 8); // XXX needs endian here
		//	endian_memcpy((ut8*)&addr8, (ut8*)&off, 8);
			r_io_write(core->io, (const ut8 *)&addr8, 8);
			WSEEK (core, 8);
		} else {
			/* 4 byte addr */
			ut32 addr4, addr4_ = (ut32)off;
			//drop_endian((ut8*)&addr4_, (ut8*)&addr4, 4); /* addr4_ = addr4 */
			//endian_memcpy((ut8*)&addr4, (ut8*)&addr4_, 4); /* addr4 = addr4_ */
			memcpy ((ut8*)&addr4, (ut8*)&addr4_, 4); // XXX needs endian here too
			r_io_write (core->io, (const ut8 *)&addr4, 4);
			WSEEK (core, 4);
		}
		r_core_block_read (core, 0);
		break;
	case 'o':
		switch (input[1]) {
			case 'a':
			case 's':
			case 'A':
			case 'x':
			case 'r':
			case 'l':
			case 'm':
			case 'd':
			case 'o':
				if (input[2]!=' ') {
					r_cons_printf ("Usage: 'wo%c 00 11 22'\n", input[1]);
					return 0;
				}
			case '2':
			case '4':
				r_core_write_op (core, input+3, input[1]);
				r_core_block_read (core, 0);
				break;
			case 'n':
				r_core_write_op (core, "ff", 'x');
				r_core_block_read (core, 0);
				break;
			case '\0':
			case '?':
			default:
				r_cons_printf (
						"Usage: wo[asmdxoArl24] [hexpairs] @ addr[:bsize]\n"
						"Example:\n"
						"  wox 0x90   ; xor cur block with 0x90\n"
						"  wox 90     ; xor cur block with 0x90\n"
						"  wox 0x0203 ; xor cur block with 0203\n"
						"  woa 02 03  ; add [0203][0203][...] to curblk\n"
						"Supported operations:\n"
						"  woa  +=  addition\n"
						"  wos  -=  substraction\n"
						"  wom  *=  multiply\n"
						"  wod  /=  divide\n"
						"  wox  ^=  xor\n"
						"  woo  |=  or\n"
						"  woA  &=  and\n"
						"  wor  >>= shift right\n"
						"  wol  <<= shift left\n"
						"  wo2  2=  2 byte endian swap\n"
						"  wo4  4=  4 byte endian swap\n"
						);
				break;
		}
		break;
	default:
	case '?':
		if (core->oobi) {
			eprintf ("Writing oobi buffer!\n");
			r_io_set_fd (core->io, core->file->fd);
			r_io_write (core->io, core->oobi, core->oobi_len);
			WSEEK (core, core->oobi_len);
			r_core_block_read (core, 0);
		} else r_cons_printf (
			"Usage: w[x] [str] [<file] [<<EOF] [@addr]\n"
			" w foobar     write string 'foobar'\n"
			" wr 10        write 10 random bytes\n"
			" ww foobar    write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'\n"
			" wa push ebp  write opcode, separated by ';' (use '\"' around the command)\n"
			" waf file     assemble file and write bytes\n"
			" wA r 0       alter/modify opcode at current seek (see wA?)\n"
			" wb 010203    fill current block with cyclic hexpairs\n"
			" wc[ir*?]     write cache commit/reset/list\n"
			" wx 9090      write two intel nops\n"
			" wv eip+34    write 32-64 bit value\n"
			" wo? hex      write in block with operation. 'wo?' fmi\n"
			" wm f0ff      set binary mask hexpair to be used as cyclic write mask\n"
			" wf file      write contents of file at current offset\n"
			" wF file      write contents of hexpairs file here\n"
			" wt file      write current block to file\n"
			" wp file      apply radare patch file. See wp? fmi\n");
			//TODO: add support for offset+seek
			// " wf file o s ; write contents of file from optional offset 'o' and size 's'.\n"
		break;
	}
	free (ostr);
	return 0;
}

static int cmd_resize(void *data, const char *input) {
	RCore *core = (RCore *)data;
	ut64 oldsize, newsize;
	st64 delta = 0;
	int grow;

	oldsize = core->file->size;
	while (*input==' ')
		input++;
	switch (*input) {
		case '+':
		case '-':
			delta = (st64)r_num_math (NULL, input);
			newsize = oldsize + delta;
			break;
		case '\0':
		case '?':
			r_cons_printf (
					"Usage: r[+-][ size]\n"
					" r size   expand or truncate file to given size\n"
					" r-num    remove num bytes, move following data down\n"
					" r+num    insert num bytes, move following data up\n");
			return R_TRUE;
		default:
			newsize = r_num_math (core->num, input+1);
	}

	grow = (newsize > oldsize);

	if (grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (delta && core->offset < newsize)
		r_io_shift (core->io, core->offset, grow?newsize:oldsize, delta);

	if (!grow) {
		r_io_resize (core->io, newsize);
		core->file->size = newsize;
	}

	if (newsize < core->offset+core->blocksize ||
			oldsize < core->offset+core->blocksize)
		r_core_block_read (core, 0);

	return R_TRUE;
}

static const char *cmdhit = NULL;
static const char *searchprefix = NULL;
static unsigned int searchcount = 0;
static int searchflags = 0;

static int __cb_hit(RSearchKeyword *kw, void *user, ut64 addr) {
	RCore *core = (RCore *)user;
/*
	if (searchcount) {
		if (!--searchcount) {
			eprintf ("search.count reached\n");
			return R_FALSE;
		}
	}
*/
	searchcount++;
	if (searchflags) {
		r_cons_printf ("%s%d_%d\n", searchprefix, kw->kwidx, kw->count);
		r_core_cmdf (core, "f %s%d_%d %d 0x%08"PFMT64x"\n", searchprefix,
			kw->kwidx, kw->count, kw->keyword_length, addr);
	} else r_cons_printf ("f %s%d_%d %d 0x%08"PFMT64x"\n", searchprefix,
			kw->kwidx, kw->count, kw->keyword_length, addr);
	if (!strnull (cmdhit)) {
		ut64 here = core->offset;
		r_core_seek (core, addr, R_FALSE);
		r_core_cmd (core, cmdhit, 0);
		r_core_seek (core, here, R_TRUE);
	}
	return R_TRUE;
}

static inline void print_search_progress(ut64 at, ut64 to, int n) {
	static int c = 0;
	if ((++c%23))
		return;
	eprintf ("\r[  ]  0x%08"PFMT64x" < 0x%08"PFMT64x"  hits = %d                      \r%s",
			at, to, n, (c%2)?"[ #]":"[# ]");
}

static int cmd_search(void *data, const char *input) {
	const char *mode;
	char *inp;
	RCore *core = (RCore *)data;
	ut64 at, from, to;
	//RIOSection *section;
	int i, len, ret, dosearch = R_FALSE;
	int inverse = R_FALSE;
	int aes_search = R_FALSE;
	int ignorecase = R_FALSE;
	ut64 n64;
	ut32 n32;
	ut16 n16;
	ut8 *buf;

	mode = r_config_get (core->config, "search.in");
	if (!strcmp (mode, "block")) {
		from = core->offset;
		to = core->offset + core->blocksize;
	} else
	if (!strcmp (mode, "file")) {
		if (core->io->va) {
			RListIter *iter;
			RIOSection *s;
			from = core->offset;
			to = from;
			r_list_foreach (core->io->sections, iter, s) {
				if ((s->vaddr+s->size) > to && from>=s->vaddr) {
					to = s->vaddr+s->size;
				}
			}
			if (to == 0LL || to == UT64_MAX || to == UT32_MAX)
				to = r_io_size (core->io);
		} else {
			from = core->offset;
			to = r_io_size (core->io);
		}
	} else
	if (!strcmp (mode, "section")) {
		if (core->io->va) {
			RListIter *iter;
			RIOSection *s;
			from = core->offset;
			to = from;
			r_list_foreach (core->io->sections, iter, s) {
				if (from >= s->vaddr && from < (s->vaddr+s->size)) {
					to = s->vaddr+s->size;
					break;
				}
			}
		} else {
			from = core->offset;
			to = r_io_size (core->io);
		}
	} else {
		//if (!strcmp (mode, "raw")) {
		/* obey temporary seek if defined '/x 8080 @ addr:len' */
		if (core->tmpseek) {
			from = core->offset;
			to = core->offset + core->blocksize;
		} else {
			// TODO: repeat last search doesnt works for /a
			from = r_config_get_i (core->config, "search.from");
			if (from == UT64_MAX)
				from = core->offset;
			to = r_config_get_i (core->config, "search.to");
			if (to == UT64_MAX) {
				if (core->io->va) {
					/* TODO: section size? */
				} else {
					to = core->file->size;
				}
			}
		}
	}

	core->search->align = r_config_get_i (core->config, "search.align");
	searchflags = r_config_get_i (core->config, "search.flags");
	//TODO: handle section ranges if from&&to==0
/*
	section = r_io_section_get (core->io, core->offset);
	if (section) {
		from += section->vaddr;
		//fin = ini + s->size;
	}
*/
	searchprefix = r_config_get (core->config, "search.prefix");
	// TODO: get ranges from current IO section
	/* XXX: Think how to get the section ranges here */
	if (from == 0LL) from = core->offset;
	if (to == 0LL) to = UT32_MAX; // XXX?

	reread:
	switch (*input) {
	case '!':
		input++;
		inverse = R_TRUE;
		goto reread;
		break;
	case 'r':
		if (input[1]==' ')
			r_core_anal_search (core, from, to, r_num_math (core->num, input+2));
		else r_core_anal_search (core, from, to, core->offset);
		break;
	case 'a': {
		char *kwd;
		if (!(kwd = r_core_asm_search (core, input+2, from, to)))
			return R_FALSE;
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search,
				r_search_keyword_new_hexmask (kwd, NULL));
		r_search_begin (core->search);
		free (kwd);
		dosearch = R_TRUE;
		} break;
	case 'A':
		dosearch = aes_search = R_TRUE;
		break;
	case '/':
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'm':
		dosearch = R_FALSE;
		if (input[1]==' ' || input[1]=='\0') {
			const char *file = input[1]? input+2: NULL;
			ut64 addr = from;
			r_cons_break (NULL, NULL);
			for (; addr<to; addr++) {
				if (r_cons_singleton ()->breaked)
					break;
				r_core_magic_at (core, file, addr, 99, R_FALSE);
			}
			r_cons_break_end ();
		} else eprintf ("Usage: /m [file]\n");
		break;
	case 'p':
		{
			int ps = atoi (input+1);
			if (ps>1) {
				r_search_pattern_size (core->search, ps);
				r_search_pattern (core->search, from, to);
			} else eprintf ("Invalid pattern size (must be >0)\n");
		}
		break;
	case 'v':
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		switch (input[1]) {
		case '?':
			eprintf ("Usage: /v[2|4|8] [value]\n");
			return R_TRUE;
		case '8':
			n64 = r_num_math (core->num, input+2);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n64, 8, NULL, 0, NULL));
			break;
		case '2':
			n16 = (ut16)r_num_math (core->num, input+2);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n16, 2, NULL, 0, NULL));
			break;
		default: // default size
		case '4':
			n32 = (ut32)r_num_math (core->num, input+1);
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)&n32, 4, NULL, 0, NULL));
			break;
		}
// TODO: Add support for /v4 /v8 /v2
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'w': /* search wide string */
		if (input[1]==' ') {
			int len = strlen (input+2);
			const char *p2;
			char *p, *str = malloc ((len+1)*2);
			for (p2=input+2, p=str; *p2; p+=2, p2++) {
				p[0] = *p2;
				p[1] = 0;
			}
			r_search_reset (core->search, R_SEARCH_KEYWORD);
			r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
			r_search_kw_add (core->search,
				r_search_keyword_new ((const ut8*)str, len*2, NULL, 0, NULL));
			r_search_begin (core->search);
			dosearch = R_TRUE;
		}
		break;
	case 'i':
		if (input[1]!= ' ') {
			eprintf ("Missing ' ' after /i\n");
			return R_FALSE;
		}
		ignorecase = R_TRUE;
	case ' ': /* search string */
		inp = strdup (input+1+ignorecase);
		if (ignorecase)
			for (i=1; inp[i]; i++)
				inp[i] = tolower (inp[i]);
		len = r_str_escape (inp);
		eprintf ("Searching %d bytes from 0x%08"PFMT64x" to 0x%08"PFMT64x": ", len, from, to);
		for (i=0; i<len; i++) eprintf ("%02x ", inp[i]);
		eprintf ("\n");
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		{
		RSearchKeyword *skw;
		skw = r_search_keyword_new ((const ut8*)inp, len, NULL, 0, NULL);
		skw->icase = ignorecase;
		r_search_kw_add (core->search, skw);
		}
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'e': /* match regexp */
		{
		char *inp = strdup (input+2);
		char *res = r_str_lchr (inp+1, inp[0]);
		char *opt = NULL;
		if (res > inp) {
			opt = strdup (res+1);
			res[1]='\0';
		}
		r_search_reset (core->search, R_SEARCH_REGEXP);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search,
			r_search_keyword_new_str (inp, opt, NULL, 0));
		r_search_begin (core->search);
		dosearch = R_TRUE;
		free (inp);
		free (opt);
		}
		break;
	case 'd': /* search delta key */
		r_search_reset (core->search, R_SEARCH_DELTAKEY);
		r_search_kw_add (core->search,
			r_search_keyword_new_hexmask (input+2, NULL));
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'x': /* search hex */
		r_search_reset (core->search, R_SEARCH_KEYWORD);
		r_search_set_distance (core->search, (int)
			r_config_get_i (core->config, "search.distance"));
// TODO: add support for binmask here
{
	char *s, *p = strdup (input+2);
	s = strchr (p, ' ');
	if (s) {
		*s++ = 0;
		r_search_kw_add (core->search,
			r_search_keyword_new_hex (p, s, NULL));
	} else {
		r_search_kw_add (core->search,
			r_search_keyword_new_hexmask (input+2, NULL));
	}
}
		r_search_begin (core->search);
		dosearch = R_TRUE;
		break;
	case 'c': /* search asm */
		{
		RCoreAsmHit *hit;
		RListIter *iter;
		int count = 0;
		RList *hits;
		if ((hits = r_core_asm_strsearch (core, input+2, from, to))) {
			r_list_foreach (hits, iter, hit) {
				r_cons_printf ("f %s_%i @ 0x%08"PFMT64x"   # %i: %s\n",
					searchprefix, count, hit->addr, hit->len, hit->code);
				count++;
			}
			r_list_destroy (hits);
		}
		dosearch = 0;
		}
		break;
	case 'z': /* search asm */
		{
		char *p;
		ut32 min, max;
		if (!input[1]) {
			eprintf ("Usage: /z min max\n");
			break;
		}
		if ((p = strchr (input+2, ' '))) {
			*p = 0;
			max = r_num_math (core->num, p+1);
		} else {
			eprintf ("Usage: /z min max\n");
			break;
		}
		min = r_num_math (core->num, input+2);
		if (!r_search_set_string_limits (core->search, min, max)) {
			eprintf ("Error: min must be lower than max\n");
			break;
		}
		r_search_reset (core->search, R_SEARCH_STRING);
		r_search_set_distance (core->search, (int)
				r_config_get_i (core->config, "search.distance"));
		r_search_kw_add (core->search,
			r_search_keyword_new_hexmask ("00", NULL)); //XXX
		r_search_begin (core->search);
		dosearch = R_TRUE;
		}
		break;
	default:
		r_cons_printf (
		"Usage: /[amx/] [arg]\n"
		" / foo\\x00       ; search for string 'foo\\0'\n"
		" /w foo          ; search for wide string 'f\\0o\\0o\\0'\n"
		" /! ff           ; search for first occurrence not matching\n"
		" /i foo          ; search for string 'foo' ignoring case\n"
		" /e /E.F/i       ; match regular expression\n"
		" /x ff0033       ; search for hex string\n"
		" /x ff..33       ; search for hex string ignoring some nibbles\n"
		" /x ff43 ffd0    ; search for hexpair with mask\n"
		" /d 101112       ; search for a deltified sequence of bytes\n"
		" /!x 00          ; inverse hexa search (find first byte != 0x00)\n"
		" /c jmp [esp]    ; search for asm code (see search.asmstr)\n"
		" /a jmp eax      ; assemble opcode and search its bytes\n"
		" /A              ; search for AES expanded keys\n"
		" /r sym.printf   ; analyze opcode reference an offset\n"
		" /m magicfile    ; search for matching magic file (use blocksize)\n"
		" /p patternsize  ; search for pattern of given size\n"
		" /z min max      ; search for strings of given size\n"
		" /v[?248] num    ; look for a asm.bigendian 32bit value\n"
		" //              ; repeat last search\n"
		" ./ hello        ; search 'hello string' and import flags\n"
		"Configuration:\n"
		" e cmd.hit = x         ; command to execute on every search hit\n"
		" e search.distance = 0 ; search string distance\n"
		" e search.align = 4    ; only catch aligned search hits\n"
		" e search.from = 0     ; start address\n"
		" e search.to = 0       ; end address\n"
		" e search.asmstr = 0   ; search string instead of assembly\n"
		" e search.flags = true ; if enabled store flags on keyword hits\n");
		break;
	}
	if (core->io->va) {
		eprintf ("Search is broken in io.va. Please fix or e io.va=0\n");
	}
	r_config_set_i (core->config, "search.kwidx", core->search->n_kws);
	if (dosearch) {
		if (!searchflags)
			r_cons_printf ("fs hits\n");
		core->search->inverse = inverse;
		searchcount = r_config_get_i (core->config, "search.count");
		if (searchcount)
			searchcount++;
		if (core->search->n_kws>0 || aes_search) {
			RSearchKeyword aeskw;
			if (aes_search) {
				memset (&aeskw, 0, sizeof (aeskw));
				aeskw.keyword_length = 31;
			}
			/* set callback */
			/* TODO: handle last block of data */
			/* TODO: handle ^C */
			/* TODO: launch search in background support */
			// REMOVE OLD FLAGS r_core_cmdf (core, "f-%s*", r_config_get (core->config, "search.prefix"));
			buf = (ut8 *)malloc (core->blocksize);
			r_search_set_callback (core->search, &__cb_hit, core);
			cmdhit = r_config_get (core->config, "cmd.hit");
			r_cons_break (NULL, NULL);
			// XXX required? imho nor_io_set_fd (core->io, core->file->fd);
			for (at = from; at < to; at += core->blocksize) {
				print_search_progress (at, to, searchcount);
				if (r_cons_singleton ()->breaked) {
					eprintf ("\n\n");
					break;
				}
				ret = r_io_read_at (core->io, at, buf, core->blocksize);
				//ret = r_core_read_at (core, at, buf, core->blocksize); 
/*
				if (ignorecase) {
					int i;
					for (i=0; i<core->blocksize; i++)
						buf[i] = tolower (buf[i]);
				}
*/
				if (ret <1)
					break;
				if (aes_search) {
					int delta = r_search_aes_update (core->search, at, buf, ret);
					if (delta != -1) {
						if (!r_search_hit_new (core->search, &aeskw, at+delta)) {
							break;
						}
						aeskw.count++;
					}
				} else
				if (r_search_update (core->search, &at, buf, ret) == -1) {
					eprintf ("search: update read error at 0x%08"PFMT64x"\n", at);
					break;
				}
			}
			r_cons_break_end ();
			free (buf);
			//r_cons_clear_line ();
			if (searchflags && searchcount>0) {
				eprintf ("hits: %d  %s%d_0 .. %s%d_%d\n",
					searchcount,
					searchprefix, core->search->n_kws-1,
					searchprefix, core->search->n_kws-1, searchcount-1);
			} else eprintf ("hits: 0\n");
		} else eprintf ("No keywords defined\n");
	}
	return R_TRUE;
}

static int cmd_eval(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0':
		r_config_list (core->config, NULL, 0);
		break;
	case 'e':
		if (input[1]==' ') {
			char *p;
			const char *val = r_config_get (core->config, input+2);
			p = r_core_editor (core, val);
			r_str_subchr (p, '\n', ';');
			r_config_set (core->config, input+2, p);
		} else eprintf ("Usage: ee varname\n");
		break;
	case '!':
		input = r_str_chop_ro (input+1);
		if (!r_config_swap (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init (core);
		eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*':
		r_config_list (core->config, NULL, 1);
		break;
	case '?':
		switch (input[1]) {
		case '?':
			r_config_list (core->config, NULL, 2);
			break;
		default:
			if (input[2]) {
				const char *desc = r_config_desc (core->config, input+1, NULL);
				if (desc) r_cons_strcat (desc);
				r_cons_newline ();
			}
			break;
		case 0:
			r_cons_printf (
			"Usage: e[?] [var[=value]]\n"
			"  e?           ; show this help\n"
			"  e?asm.bytes  ; show description\n"
			"  e??          ; list config vars with description\n"
			"  e            ; list config vars\n"
			"  e-           ; reset config vars\n"
			"  e*           ; dump config vars in r commands\n"
			"  e!a          ; invert the boolean value of 'a' var\n"
			"  e a          ; get value of var 'a'\n"
			"  e a=b        ; set var 'a' the 'b' value\n");
		}
		break;
	case ' ':
		r_config_eval (core->config, input+1);
		break;
	default:
		r_config_eval (core->config, input);
	}
	return 0;
}

static int cmd_hash(void *data, const char *input) {
	char *p, algo[32];
	RCore *core = (RCore *)data;
	ut32 i, len = core->blocksize;
	const char *ptr;

	if (input[0]=='!') {
#if 0
	TODO: Honor OOBI
		#!lua < file
		#!lua <<EOF
		#!lua
		#!lua foo bar
                        //r_lang_run (core->lang, p+1, strlen (p+1));
                                //core->oobi, core->oobi_len);
#endif
		if (input[1]=='?' || input[1]=='*' || input[1]=='\0') {
			r_lang_list (core->lang);
			return R_TRUE;
		}
		p = strchr (input+1, ' ');
		if (p) *p=0;
		// TODO: set argv here
		if (r_lang_use (core->lang, input+1)) {
			r_lang_setup (core->lang);
			if (p) r_lang_run_file (core->lang, p+1);
			else r_lang_prompt (core->lang);
		} else eprintf ("Invalid hashbang plugin name. Try '#!'\n");
		return R_TRUE;
	}

	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr != NULL)
		len = r_num_math (core->num, ptr+1);
	/* TODO: Simplify this spaguetti monster */
	if (!r_str_ccmp (input, "md4", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD4);
		const ut8 *c = r_hash_do_md4 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD4; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "md5", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_MD5);
		const ut8 *c = r_hash_do_md5 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_MD5; i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha1", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA1);
		const ut8 *c = r_hash_do_sha1 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA1;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha256", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA256);
		const ut8 *c = r_hash_do_sha256 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA256;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "sha512", ' ')) {
		RHash *ctx = r_hash_new (R_TRUE, R_HASH_SHA512);
		const ut8 *c = r_hash_do_sha512 (ctx, core->block, len);
		for (i=0; i<R_HASH_SIZE_SHA512;i++) r_cons_printf ("%02x", c[i]);
		r_cons_newline ();
		r_hash_free (ctx);
	} else
	if (!r_str_ccmp (input, "entropy", ' ')) {
		r_cons_printf ("%lf\n", r_hash_entropy (core->block, len));
	} else
	if (!r_str_ccmp (input, "hamdist", ' ')) {
		r_cons_printf ("%d\n", r_hash_hamdist (core->block, len));
	} else
	if (!r_str_ccmp (input, "pcprint", ' ')) {
		r_cons_printf ("%d\n", r_hash_pcprint (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc32", ' ')) {
		r_cons_printf ("%04x\n", r_hash_crc32 (core->block, len));
	} else
	if (!r_str_ccmp (input, "xor", ' ')) {
		r_cons_printf ("%02x\n", r_hash_xor (core->block, len));
	} else
	if (!r_str_ccmp (input, "crc16", ' ')) {
		r_cons_printf ("%02x\n", r_hash_crc16 (0, core->block, len));
	} else
	if (input[0]=='?') {
		r_cons_printf (
		"Usage: #algo <size> @ addr\n"
		" #xor                 ; calculate xor of all bytes in current block\n"
		" #crc32               ; calculate crc32 of current block\n"
		" #crc32 < /etc/fstab  ; calculate crc32 of this file\n"
		" #pcprint             ; count printable chars in current block\n"
		" #hamdist             ; calculate hamming distance in current block\n"
		" #entropy             ; calculate entropy of current block\n"
		" #md4                 ; calculate md4\n"
		" #md5 128K @ edi      ; calculate md5 of 128K from 'edi'\n"
		" #sha1                ; calculate SHA-1\n"
		" #sha256              ; calculate SHA-256\n"
		" #sha512              ; calculate SHA-512\n"
		"Usage #!interpreter [<args>] [<file] [<<eof]\n"
		" #!                   ; list all available interpreters\n"
		" #!python             ; run python commandline\n"
		" #!python < foo.py    ; run foo.py python script\n"
		" #!python <<EOF       ; get python code until 'EOF' mark\n"
		" #!python arg0 a1 <<q ; set arg0 and arg1 and read until 'q'\n"
		"Comments:\n"
		" # this is a comment  ; note the space after the sharp sign\n");
	}

	return 0;
}

static int cmd_visual(void *data, const char *input) {
	r_cons_show_cursor (R_FALSE);
	int ret = r_core_visual ((RCore *)data, input);
	r_cons_show_cursor (R_TRUE);
	return ret;
}

static int cmd_system(void *data, const char *input) {
	int ret = 0;
	if (*input!='?') {
		char *cmd = r_core_sysenv_begin ((RCore*)data, input);
		if (cmd) {
			ret = r_sys_cmd (cmd);
			r_core_sysenv_end ((RCore*)data, input);
			free (cmd);
		} else eprintf ("Error setting up system environment\n");
	} else r_core_sysenv_help ();
	return ret;
}

static int cmd_open(void *data, const char *input) {
	ut64 addr;
	int num = -1;
	RCore *core = (RCore*)data;
	RCoreFile *file;
	char *ptr;

	switch (*input) {
	case '\0':
		r_core_file_list (core);
		break;
	case ' ':
		ptr = strchr (input+1, ' ');
		if (ptr && ptr[1]=='0' && ptr[2]=='x') { // hack to fix opening files with space in path
			*ptr = '\0';
			addr = r_num_math (core->num, ptr+1);
		} else {
			num = atoi (input+1);
			addr = 0LL;
		}
		if (num<=0) {
			file = r_core_file_open (core, input+1, R_IO_READ, addr);
			if (file) {
				//eprintf ("Map '%s' in 0x%08"PFMT64x" with size 0x%"PFMT64x"\n",
				//	input+1, addr, file->size);
			} else eprintf ("Cannot open file '%s'\n", input+1);
		} else r_io_raise (core->io, num);
		r_core_block_read (core, 0);
		break;
	case '-':
		if (!r_core_file_close_fd (core, atoi (input+1)))
			eprintf ("Unable to find filedescriptor %d\n", atoi (input+1));
		r_core_block_read (core, 0);
		break;
	case 'm':
		switch (input[1]) {
		case ' ':
			// i need to parse delta, offset, size
			{
			ut64 fd = 0LL;
			ut64 addr = 0LL;
			ut64 size = 0LL;
			ut64 delta = 0LL;
			char *s = strdup (input+2);
			char *p = strchr (s, ' ');
			if (p) {
				char *q = strchr (p+1, ' ');
				*p = 0;
				fd = r_num_math (core->num, s);
				addr = r_num_math (core->num, p+1);
				if (q) {
					char *r = strchr (q+1, ' ');
					*q = 0;
					if (r) {
						*r = 0;
						size = r_num_math (core->num, q+1);
						delta = r_num_math (core->num, r+1);
					} else size = r_num_math (core->num, q+1);
				} else size = r_io_size (core->io);
				r_io_map_add (core->io, fd, 0, delta, addr, size);
			} else eprintf ("Usage: om fd addr [size] [delta]\n");
			free (s);
			}
			break;
		case '-':
			r_io_map_del_at (core->io, r_num_math (core->num, input+2));
			break;
		case '\0':
			{
			RIOMap *im = NULL;
			RListIter *iter;
			r_list_foreach (core->io->maps, iter, im) { // _prev?
				r_cons_printf (
					"%d 0x%08"PFMT64x" 0x%08"PFMT64x" - 0x%08"PFMT64x"\n", 
					im->fd, im->delta, im->from, im->to);
			}
			}
			break;
		default:
		case '?':
			r_cons_printf ("Usage: om[-] [arg]       file maps\n");
			r_cons_printf ("om                  list all defined IO maps\n");
			r_cons_printf ("om-0x10000          remove the map at given address\n");
			r_cons_printf ("om fd addr [size]   create new io map\n");
			break;
		}
		break;
	case 'o':
		r_core_file_reopen (core, input+2);
		break;
	case '?':
	default:
		eprintf ("Usage: o[o-] [file] ([offset])\n"
		" o                     list opened files\n"
		" oo                    reopen current file (kill+fork in debugger)\n"
		" o 4                   priorize io on fd 4 (bring to front)\n"
		" o-1                   close file index 1\n"
		" o /bin/ls             open /bin/ls file\n"
		" o /bin/ls 0x8048000   map file\n"
		" om[?]                 create, list, remove IO maps\n");
		break;
	}
	return 0;
}

// XXX this command is broken. output of _list is not compatible with input
static int cmd_meta(void *data, const char *input) {
	RAnalVarType *var;
	RListIter *iter;
	RCore *core = (RCore*)data;
	int i, ret, line = 0;
	ut64 addr_end = 0LL;
	ut64 addr = core->offset;
	char file[1024];
	switch (*input) {
	case '*':
		r_meta_list (core->anal->meta, R_META_TYPE_ANY, 1);
		break;
	case 't':
		switch (input[1]) {
		case '-':
			r_anal_var_type_del (core->anal, input+2);
			break;
		case ' ':
			{
			int size;
			const char *fmt = NULL;
			const char *ptr, *name = input+2;
			ptr = strchr (name, ' ');
			if (ptr) {
				size = atoi (ptr+1);
				ptr = strchr (ptr+2, ' ');
				if (ptr)
					fmt = ptr+1;
			}
			if (fmt==NULL)
				eprintf ("Usage: Ct name size format\n");
			else r_anal_var_type_add (core->anal, name, size, fmt);
			}
			break;
		case '\0':
			r_list_foreach (core->anal->vartypes, iter, var) {
				r_cons_printf ("Ct %s %d %s\n", var->name, var->size, var->fmt);
			}
			break;
		default:
			eprintf ("Usage: Ct[..]\n"
				" Ct-int       : remove 'int' type\n"
				" Ct int 4 d   : define int type\n");
			break;
		}
		break;
	case 'l':
		{
		int num;
		char *f, *p, *line, buf[4096];
		f = strdup (input +2);
		p = strchr (f, ':');
		if (p) {
			*p=0;
			num = atoi (p+1);
			line = r_file_slurp_line (input+2, num, 0);
			if (!line) {
				const char *dirsrc = r_config_get (core->config, "dir.source");
				if (dirsrc && *dirsrc) {
					f = r_str_concat (strdup (dirsrc), f);
					line = r_file_slurp_line (f, num, 0);
				}
				if (!line) {
					eprintf ("Cannot slurp file\n");
					return R_FALSE;
				}
			}
			p = strchr (p+1, ' ');
			if (p) {
				snprintf (buf, sizeof (buf), "CC %s:%d %s @ %s",
					f, num, line, p+1);
			} else {
				snprintf (buf, sizeof (buf), "\"CC %s:%d %s\"",
					f, num, line);
			}
			r_core_cmd0 (core, buf);
			free (line);
			free (f);
		}
		}
		break;
	case 'L': // debug information of current offset
		ret = r_bin_meta_get_line (core->bin, core->offset, file, 1023, &line);
		if (ret) {
			r_cons_printf ("file %s\nline %d\n", file, line);
			ret = (line<5)? 5-line: 5;
			line -= 2;
			for (i = 0; i<ret; i++) {
				char *row = r_file_slurp_line (file, line+i, 0);
				r_cons_printf ("%c %.3x  %s\n", (i==2)?'>':' ', line+i, row);
				free (row);
			}
		} else eprintf ("Cannot find meta information at 0x%08"PFMT64x"\n", core->offset);
		break;
	// XXX: use R_META_TYPE_XXX here
	case 'C': /* comment */
	case 's': /* string */
	case 'd': /* data */
	case 'm': /* magic */
	case 'f': /* formatted */
		switch (input[1]) {
		case '?':
			eprintf ("See C?\n");
			break;
		case '-':
			addr = core->offset;
			switch (input[2]) {
			case '*':
				core->num->value = r_meta_del (core->anal->meta, input[0], 0, UT64_MAX, NULL);
				break;
			case ' ':
				addr = r_num_math (core->num, input+3);
			default:
				core->num->value = r_meta_del (core->anal->meta, input[0], addr, 1, NULL);
				break;
			}
			break;
		case '\0':
			r_meta_list (core->anal->meta, input[0], 0);
			break;
		case '*':
			r_meta_list (core->anal->meta, input[0], 1);
			break;
		case '!':
			{
				char *out, *comment = r_meta_get_string (core->anal->meta, R_META_TYPE_COMMENT, addr);
				out = r_core_editor (core, comment);
				//r_meta_add (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmdf (core, "CC-@0x%08"PFMT64x, addr);
				//r_meta_del (core->anal->meta, input[0], addr, addr+1, NULL);
				r_meta_set_string (core->anal->meta, R_META_TYPE_COMMENT, addr, out);
				free (out);
				free (comment);
			}
			break;
		default: {
			char *t, *p, name[256];
			int n = 0, type = input[0];
			t = strdup (input+2);
			if (atoi (t)>0) {
				p = strchr (t, ' ');
				if (p) {
					*p = '\0';
					strncpy (name, p+1, sizeof (name)-1);
				} else switch (type) {
				case 's':
					// TODO: filter \n and so on :)
					strncpy (name, t, sizeof (name)-1);
					r_core_read_at (core, addr, (ut8*)name, sizeof (name));
					break;
				default: {
					RFlagItem *fi = r_flag_get_i (core->flags, addr);
					if (fi) strncpy (name, fi->name, sizeof (name)-1);
					else sprintf (name, "ptr_%08"PFMT64x"", addr);
					}
				}
				n = atoi (input+1);
			} else {
				p = NULL;
				strncpy (name, t, sizeof (name)-1);
			}
			if (!n) n++;
			addr_end = addr + n;
			r_meta_add (core->anal->meta, type, addr, addr_end, name);
			free (t);
			}
		}
		break;
	case 'v':
		switch (input[1]) {
		case '-':
			{
			RAnalFcn *f;
			RListIter *iter;
			ut64 offset;
			if (input[2]==' ') {
				offset = r_num_math (core->num, input+3);
				if ((f = r_anal_fcn_find (core->anal, offset, R_ANAL_FCN_TYPE_NULL)) != NULL)
					memset (f->varsubs, 0, sizeof(f->varsubs));
			} else if (input[2]=='*') {
				r_list_foreach (core->anal->fcns, iter, f)
					memset (f->varsubs, 0, sizeof(f->varsubs));
			}
			}
			break;
		case '*':
			{
			RAnalFcn *f;
			RListIter *iter;
			r_list_foreach (core->anal->fcns, iter, f) {
				for (i = 0; i < R_ANAL_VARSUBS; i++) {
					if (f->varsubs[i].pat[0] != '\0')
						r_cons_printf ("Cv 0x%08"PFMT64x" %s %s\n", f->addr, f->varsubs[i].pat, f->varsubs[i].sub);
					else break;
				}
			}
			}
			break;
		default:
			{
			RAnalFcn *f;
			char *ptr = strdup(input+2), *pattern = NULL, *varsub = NULL;
			ut64 offset = -1LL;
			int i, n = r_str_word_set0 (ptr);
			if (n > 2) {
				switch(n) {
				case 3: varsub = r_str_word_get0 (ptr, 2);
				case 2: pattern = r_str_word_get0 (ptr, 1);
				case 1: offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if ((f = r_anal_fcn_find (core->anal, offset, R_ANAL_FCN_TYPE_NULL)) != NULL) {
					if (pattern && varsub)
					for (i = 0; i < R_ANAL_VARSUBS; i++)
						if (f->varsubs[i].pat[0] == '\0' || !strcmp (f->varsubs[i].pat, pattern)) {
							strncpy (f->varsubs[i].pat, pattern, 1023);
							strncpy (f->varsubs[i].sub, varsub, 1023);
							break;
						}
				} else eprintf ("Error: Function not found\n");
			}
			free (ptr);
			}
		break;
		}
	case '-':
		if (input[1]!='*') {
			i = r_num_math (core->num, input+((input[1]==' ')?2:1));
			r_meta_del (core->anal->meta, R_META_TYPE_ANY, core->offset, i, "");
		} else r_meta_cleanup (core->anal->meta, 0LL, UT64_MAX);
		break;
	case '\0':
	case '?':
		eprintf (
		"Usage: C[-LCvsdfm?] [...]\n"
		" C*                     # List meta info in r2 commands\n"
		" C- [len] [@][ addr]    # delete metadata at given address range\n"
		" CL[-] [addr]           # show 'code line' information (bininfo)\n"
		" Cl  file:line [addr]   # add comment with line information\n"
		" CC[-] [size] [string]  # add/remove comment. Use CC! to edit with $EDITOR\n"
		" Cv[-] offset reg name  # add var substitution\n"
		" Cs[-] [size] [[addr]]  # add string\n"
		" Cd[-] [size]           # hexdump data\n"
		" Cf[-] [sz] [fmt..]     # format memory (see pf?)\n"
		" Cm[-] [sz] [fmt..]     # magic parse (see pm?)\n");
		break;
	case 'F':
		{
		RAnalFcn *f = r_anal_fcn_find (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) r_anal_fcn_from_string (core->anal, f, input+2);
		else eprintf ("Cannot find function here\n");
		}
		break;
	}
	return R_TRUE;
}

static int cmd_macro(void *data, const char *input) {
	char *buf = NULL;
	char *p, *ptr = (char *)input;
	RCore *core = (RCore*)data;
	switch (*input) {
	case ')':
		r_cmd_macro_break (&core->cmd->macro, input+1);
		break;
	case '-':
		r_cmd_macro_rm (&core->cmd->macro, input+1);
		break;
	case '*':
	case '\0':
		r_cmd_macro_list (&core->cmd->macro);
		break;
	case '?':
		eprintf (
		"Usage: (foo\\n..cmds..\\n)\n"
		" Record macros grouping commands\n"
		" (foo args\\n ..)     ; define a macro\n"
		" (-foo)              ; remove a macro\n"
		" .(foo)              ; to call it\n"
		" ()                  ; break inside macro\n"
		" (*                  ; list all defined macros\n"
		"Argument support:\n"
		" (foo x y\\n$1 @ $2)  ; define fun with args\n"
		" .(foo 128 0x804800) ; call it with args\n"
		"Iterations:\n"
		" .(foo\\n() $@)       ; define iterator returning iter index\n"
		" x @@ .(foo)         ; iterate over them\n"
		);
		break;
	default:
		if (input[strlen (input)-1] != ')') {
			buf = malloc (4096); // XXX: possible heap overflow here
			strcpy (buf, input);
			do {
				ptr = buf + strlen (buf);
				strcpy (ptr, ",");
				ptr++;
				fgets (ptr, 1024, stdin); // XXX: possible overflow // TODO: use r_cons here
				p = strchr (ptr, '#');
				if (p) *p = 0;
				else ptr[strlen (ptr)-1] = 0; // chop \n
				if (feof (stdin))
					break;
			} while (ptr[strlen (ptr)-1] != ')');
			ptr = buf;
		} else {
			buf = strdup (input);
			buf[strlen (input)-1] = 0;
		}
		r_cmd_macro_add (&core->cmd->macro, buf);
		free (buf);
		break;
	}
	return 0;
}

static int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd) {
#if __UNIX__
	int fds[2];
	int stdout_fd, status = 0;

	stdout_fd = dup (1);
	pipe (fds);
	radare_cmd = (char*)r_str_trim_head (radare_cmd);
	shell_cmd = (char*)r_str_trim_head (shell_cmd);
	if (fork ()) {
		dup2 (fds[1], 1);
		close (fds[1]);
		close (fds[0]);
		r_core_cmd (core, radare_cmd, 0);
		r_cons_flush ();
		close (1);
		wait (&status);
		dup2 (stdout_fd, 1);
		close (stdout_fd);
	} else {
		close (fds[1]);
		dup2 (fds[0], 0);
		dup2 (2, 1);
		execl ("/bin/sh", "sh", "-c", shell_cmd, (char*)NULL);
	}
	return status;
#else
#warning r_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
	eprintf ("r_core_cmd_pipe: unimplemented for this platform\n");
	return -1;
#endif
}

static int r_core_cmd_subst(RCore *core, char *cmd) {
	char *ptr, *ptr2, *str;
	int i, len = strlen (cmd), pipefd, ret;
	const char *quotestr = "\"`";
	quotestr = "`"; // tmp

	cmd = r_str_trim_head_tail (cmd);

	/* quoted / raw command */
	switch (*cmd) {
	case '.':
		if (cmd[1] == '"') { /* interpret */
			ret = r_cmd_call (core->cmd, cmd);
			return ret;
		}
		break;
	case '"':
		if (cmd[len-1] != '"') {
			eprintf ("parse: Missing ending '\"'\n");
			return -1;
		}
		cmd[len-1]='\0';
		return r_cmd_call (core->cmd, cmd+1);
	case '(':
		return r_cmd_call (core->cmd, cmd);
	}

// TODO must honor " and `
	/* comments */
	if (*cmd!='#') {
		ptr = (char *)r_str_lastbut (cmd, '#', quotestr);
		if (ptr) *ptr = '\0';
	}

	/* multiple commands */
// TODO: must honor " and ` boundaries
	//ptr = strrchr (cmd, ';');
	ptr = (char *)r_str_lastbut (cmd, ';', quotestr);
	if (ptr) {
		*ptr = '\0';
		if (r_core_cmd_subst (core, cmd) == -1)
			return -1;
		cmd = ptr+1;
		//r_cons_flush ();
	}

// TODO must honor " and `
	/* pipe console to shell process */
	//ptr = strchr (cmd, '|');
	ptr = (char *)r_str_lastbut (cmd, '|', quotestr);
	if (ptr) {
		*ptr = '\0';
		cmd = r_str_clean (cmd);
		if (*cmd) r_core_cmd_pipe (core, cmd, ptr+1);
		else r_io_system (core->io, ptr+1);
		return 0;
	}

// TODO must honor " and `
	/* bool conditions */
	ptr = (char *)r_str_lastbut (cmd, '&', quotestr);
	//ptr = strchr (cmd, '&');
	while (ptr && ptr[1]=='&') {
		*ptr = '\0';
		ret = r_cmd_call (core->cmd, cmd);
		if (ret == -1) {
			eprintf ("command error(%s)\n", cmd);
			return ret;
		}
		for (cmd=ptr+2; cmd && *cmd==' '; cmd++);
		ptr = strchr (cmd, '&');
	}

	/* Out Of Band Input */
	free (core->oobi);
	core->oobi = NULL;
// XXX: must honor quotestr
	ptr = strchr (cmd, '<');
	if (ptr) {
		ptr[0] = '\0';
		if (ptr[1]=='<') {
			/* this is a bit mess */
			//const char *oprompt = strdup (r_line_singleton ()->prompt);
			//oprompt = ">";
			for (str=ptr+2; str[0]==' '; str++);
			eprintf ("==> Reading from stdin until '%s'\n", str);
			free (core->oobi);
			core->oobi = malloc (1);
			core->oobi[0] = '\0';
			core->oobi_len = 0;
			for (;;) {
				char buf[1024];
				int ret;
				write (1, "> ", 2);
				fgets (buf, sizeof (buf)-1, stdin); // XXX use r_line ??
				if (feof (stdin))
					break;
				buf[strlen (buf)-1]='\0';
				ret = strlen (buf);
				core->oobi_len += ret;
				core->oobi = realloc (core->oobi, core->oobi_len+1);
				if (!strcmp (buf, str))
					break;
				strcat ((char *)core->oobi, buf);
			}
			//r_line_set_prompt (oprompt);
		} else {
			for (str=ptr+1; *str== ' ';str++);
			eprintf ("SLURPING FILE '%s'\n", str);
			core->oobi = (ut8*)r_file_slurp (str, &core->oobi_len);
			if (core->oobi == NULL)
				eprintf ("Cannot open file\n");
			else if (ptr == cmd)
				return r_core_cmd_buffer (core, (const char *)core->oobi);
		}
	}

// TODO must honor " and `
	/* pipe console to file */
	ptr = strchr (cmd, '>');
	if (ptr) {
		/* r_cons_flush() handles interactive output (to the terminal)
		 * differently (e.g. asking about too long output). This conflicts
		 * with piping to a file. Disable it while piping. */
		r_cons_set_interactive (R_FALSE);
		*ptr = '\0';
		str = r_str_trim_head_tail (ptr+1+(ptr[1]=='>'));
		pipefd = r_cons_pipe_open (str, ptr[1]=='>');
		ret = r_core_cmd_subst (core, cmd);
		r_cons_flush ();
		r_cons_pipe_close (pipefd);
		r_cons_set_last_interactive ();
		return ret;
	}

	/* sub commands */
	ptr = strchr (cmd, '`');
	if (ptr) {
		ptr2 = strchr (ptr+1, '`');
		if (!ptr2) {
			eprintf ("parse: Missing '´' in expression.\n");
			return -1;
		} else {
			*ptr = '\0';
			*ptr2 = '\0';
			str = r_core_cmd_str (core, ptr+1);
			for (i=0; str[i]; i++)
				if (str[i]=='\n')
					str[i]=' ';
			str = r_str_concat (str, ptr2+1);
			cmd = r_str_concat (strdup (cmd), str);
			ret = r_core_cmd_subst (core, cmd);
			free (cmd);
			free (str);
			return ret;
		}
	}

// TODO must honor " and `
	/* grep the content */
	ptr = (char *)r_str_lastbut (cmd, '~', quotestr);
	//ptr = strchr (cmd, '~');
	if (ptr) {
		*ptr = '\0';
		ptr++;
	}
	r_cons_grep (ptr);

	/* seek commands */
	if (*cmd!='(' && *cmd!='"')
		ptr = strchr (cmd, '@');
	else ptr = NULL;
	core->tmpseek = ptr? R_TRUE: R_FALSE;
	if (ptr) {
		ut64 tmpoff, tmpbsz;
		char *ptr2 = strchr (ptr+1, ':');
		*ptr = '\0';
		cmd = r_str_clean (cmd);
		tmpoff = core->offset;
		tmpbsz = core->blocksize;
		if (ptr2) {
			*ptr2 = '\0';
			r_core_block_size (core, r_num_math (core->num, ptr2+1));
		}

		if (ptr[1]=='@') {
			// TODO: remove temporally seek (should be done by cmd_foreach)
			ret = r_core_cmd_foreach (core, cmd, ptr+2);
			//ret = -1; /* do not run out-of-foreach cmd */
		} else {
			if (!ptr[1] || r_core_seek (core, r_num_math (core->num, ptr+1), 1)) {
				r_core_block_read (core, 0);
				ret = r_cmd_call (core->cmd, r_str_trim_head (cmd));
			} else ret = 0;
		}
		if (ptr2) {
			*ptr2 = ':';
			r_core_block_size (core, tmpbsz);
		}
		r_core_seek (core, tmpoff, 1);
		*ptr = '@';
		return ret;
	}

	ret = r_cmd_call (core->cmd, r_str_trim_head (cmd));
	return ret;
}

R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each) {
	int i, j;
	char ch;
	char *word = NULL;
	char *str, *ostr;
	RListIter *iter;
	RFlagItem *flag;
	ut64 oseek, addr;

	for (; *each==' '; each++);
	for (; *cmd==' '; cmd++);

	oseek = core->offset;
	ostr = str = strdup(each);
	//r_cons_break();

	switch (each[0]) {
	case '?':
		r_cons_printf (
		"Foreach '@@' iterator command:\n"
		" This command is used to repeat a command over a list of offsets.\n"
		" x @@ sym.           Run 'x' over all flags matching 'sym.'\n"
		" x @@.file           \"\" over the offsets specified in the file (one offset per line)\n"
		" x @@=off1 off2 ..   Manual list of offsets\n"
		" x @@=`pdf~call[0]`  Run 'x' at every call offset of the current function\n");
		break;
	case '=':
		/* foreach list of items */
		each = str+1;
		do {
			while (*each==' ') each++;
			if (!*each) break;
			str = strchr (each, ' ');
			if (str) {
				*str = '\0';
				addr = r_num_math (core->num, each);
				*str = ' ';
			} else addr = r_num_math (core->num, each);
			eprintf ("; 0x%08"PFMT64x":\n", addr);
			each = str+1;
			r_core_seek (core, addr, 1);
			r_core_cmd (core, cmd, 0);
			r_cons_flush ();
		} while (str != NULL);
		break;
	case '.':
		if (each[1]=='(') {
			char cmd2[1024];
			// TODO: use r_cons_break() here
			// XXX whats this 999 ?
			i = 0;
			r_cons_break (NULL, NULL);
			for (core->cmd->macro.counter=0;i<999;core->cmd->macro.counter++) {
				if (r_cons_singleton ()->breaked)
					break;
				r_cmd_macro_call (&core->cmd->macro, each+2);
				if (core->cmd->macro.brk_value == NULL)
					break;

				addr = core->cmd->macro._brk_value;
				sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
				eprintf ("0x%08"PFMT64x" (%s)\n", addr, cmd2);
				r_core_seek (core, addr, 1);
				r_core_cmd (core, cmd2, 0);
				i++;
			}
			r_cons_break_end();
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = fopen (each+1, "r");
			if (fd) {
				core->cmd->macro.counter=0;
				while (!feof (fd)) {
					buf[0] = '\0';
					if (fgets (buf, 1024, fd) == NULL)
						break;
					addr = r_num_math (core->num, buf);
					eprintf ("0x%08"PFMT64x": %s\n", addr, cmd);
					sprintf (cmd2, "%s @ 0x%08"PFMT64x"", cmd, addr);
					r_core_seek (core, addr, 1); // XXX
					r_core_cmd (core, cmd2, 0);
					core->cmd->macro.counter++;
				}
				fclose (fd);
			} else eprintf ("Cannot open file '%s' to read offsets\n", each+1);
		}
		break;
	default:
		core->cmd->macro.counter = 0;
		//while(str[i]) && !core->interrupted) {
		// split by keywords
		i = 0;
		while (str[i]) {
			j = i;
			for (;str[j]&&str[j]==' ';j++); // skip spaces
			for (i=j;str[i]&&str[i]!=' ';i++); // find EOS
			ch = str[i];
			str[i] = '\0';
			word = strdup (str+j);
			if (word == NULL)
				break;
			str[i] = ch;
			{
				/* for all flags in current flagspace */
				// XXX: dont ask why, but this only works with _prev..
				r_list_foreach_prev (core->flags->flags, iter, flag) {
					if (r_cons_singleton()->breaked)
						break;
					/* filter per flag spaces */
					if ((core->flags->space_idx != -1) && (flag->space != core->flags->space_idx))
						continue;
					if (r_str_glob (flag->name, word)) {
						r_core_seek (core, flag->offset, 1);
						//r_cons_printf ("# @@ 0x%08"PFMT64x" (%s)\n", core->offset, flag->name);
						r_cons_printf ("0x%08"PFMT64x"  ", core->offset);
						r_core_cmd (core, cmd, 0);
					}
				}
	#if 0
				/* ugly copypasta from tmpseek .. */
				if (strstr(word, each)) {
					if (word[i]=='+'||word[i]=='-')
						core->offset = core->offset + r_num_math (get_math(core->num, word);
					else	core->offset = r_num_math (get_math(core->num, word);
					radare_read(0);
					cons_printf("; @@ 0x%08"PFMT64x"\n", core->offset);
					radare_cmd(cmd,0);
				}
	#endif
				r_cons_break (NULL, NULL);

				core->cmd->macro.counter++ ;
				free (word);
				word = NULL;
			}
		}
	}
	r_cons_break_end ();
	// XXX: use r_core_seek here
	core->offset = oseek;

	free (word);
	free (ostr);
	return R_TRUE;
}

R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
	int rep, ret = R_FALSE;
	char *cmd, *ocmd;
	if (cstr==NULL)
		return R_FALSE;
	if (log && *cstr && *cstr!='.') {
		free (core->lastcmd);
		core->lastcmd = strdup (cstr);
	}
	/* list r_cmd plugins */
	if (!strcmp (cstr, ":")) {
		RListIter *iter;
		RCmdPlugin *cp;
		r_list_foreach (core->cmd->plist, iter, cp) {
			r_cons_printf ("%s: %s\n", cp->name, cp->desc);
		}
		return 0;
	}
	ocmd = cmd = malloc (strlen (cstr)+8192);
	if (ocmd == NULL)
		return R_FALSE;
	r_str_cpy (cmd, cstr);
	cmd = r_str_trim_head_tail (cmd);

	/* ignore comments */
	if (cmd[0] == '#')
		goto out;

	rep = atoi (cmd);
	if (rep<1) rep = 1;
	if (rep>0) {
		ret = R_TRUE;
		while (*cmd>='0' && *cmd<='9')
			cmd++;
		while (rep--) {
			ret = r_core_cmd_subst (core, cmd);
			if (ret<0)
				break;
		}
	}
	if (log) r_line_hist_add (cstr);

out:
	free (ocmd);
	free (core->oobi);
	core->oobi = NULL;
	core->oobi_len = 0;
	return ret;
}

R_API int r_core_cmd_file(RCore *core, const char *file) {
	int ret = R_TRUE;
	char *data, *odata = r_file_slurp (file, NULL);
	if (odata != NULL) {
		char *nl = strchr (odata, '\n');
		if (nl) {
			data = odata;
			do {
				*nl = '\0';
				if (r_core_cmd (core, data, 0) == -1) {
					eprintf ("r_core_cmd_file: Failed to run '%s'\n", data);
					ret = R_FALSE;
					break;
				}
				r_cons_flush ();
				data = nl+1;
			} while ((nl = strchr (data, '\n')));
		}
		free (odata);
	} else ret = R_FALSE;
	return ret;
}

R_API int r_core_cmd_command(RCore *core, const char *command) {
	int len;
	char *buf, *rcmd, *ptr;
	rcmd = ptr = buf = r_sys_cmd_str (command, 0, &len);
	if (buf == NULL)
		return -1;
	while ((ptr = strstr (rcmd, "\n"))) {
		*ptr = '\0';
		if (r_core_cmd (core, rcmd, 0) == -1) {
			eprintf ("Error running command '%s'\n", rcmd);
			break;
		}
		rcmd += strlen (rcmd)+1;
	}
	free (buf);
	return 0;
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
				} else snprintf (file, sizeof (file), "0x%08"PFMT64x"-0x%08"PFMT64x"-%s.dmp",
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
		char *libname = NULL, *symname = NULL;
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
				filter.offset = 0LL;
				filter.name = symname;
				baddr = core->bin->curarch.baddr;
				core->bin->curarch.baddr = map->addr;
				r_core_bin_info (core, R_CORE_BIN_ACC_SYMBOLS, (input[1]=='*'),
						R_TRUE, &filter, 0);
				core->bin->curarch.baddr = baddr;
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
			r_debug_kill (core->dbg, R_FALSE, sig);
		} else eprintf ("Invalid arguments\n");
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
	case 'a':
		r_debug_attach (core->dbg, (int) r_num_math (core->num, input+2));
		r_debug_select (core->dbg, core->dbg->pid, core->dbg->tid);
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
		eprintf ("Trap tracing 0x%08"PFMT64x"-0x%08"PFMT64x"\n", core->offset, core->offset+len);
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

static void dot_r_graph_traverse(RCore *core, RGraph *t) {
	RGraphNode *n, *n2;
	RListIter *iter, *iter2;
	const char *gfont = r_config_get (core->config, "graph.font");
	r_cons_printf ("digraph code {\n");
	r_cons_printf ("graph [bgcolor=white];\n");
	r_cons_printf ("   node [color=lightgray, style=filled shape=box fontname=\"%s\" fontsize=\"8\"];\n", gfont);
	r_list_foreach (t->nodes, iter, n) {
		r_cons_printf ("\"0x%08"PFMT64x"\" [URL=\"0x%08"PFMT64x"\" color=\"lightgray\" "
			"label=\"0x%08"PFMT64x" (%d)\"]\n", n->addr, n->addr, n->addr, n->refs);
		r_list_foreach (n->children, iter2, n2) {
			r_cons_printf ("\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" [color=\"red\"];\n", n->addr, n2->addr);
		}
	}
	r_cons_printf ("}\n");
}

static int cmd_debug(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int i, times, sig, follow=0;
	ut64 addr;
	char *ptr;

	switch (input[0]) {
	case 'x': // XXX : only for testing
		r_debug_execute (core->dbg, (ut8*)
			"\xc7\xc0\x03\x00\x00\x00\x33\xdb\x33"
			"\xcc\xc7\xc2\x10\x00\x00\x00\xcd\x80", 18);
		break;
	case 't':
		switch (input[1]) {
		case '?':
			r_cons_printf ("Usage: dt[*] [tag]\n");
			r_cons_printf ("  dtc  - trace call/ret\n");
			r_cons_printf ("  dtg  - graph call/ret trace\n");
			r_cons_printf ("  dtr  - reset traces (instruction//cals)\n");
			break;
		case 'c':
			{
			int n = 0;
			int t = core->dbg->trace->enabled;
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
				" ds       step one instruction\n"
				" ds 4     step 4 instructions\n"
				" dso 3    step over 3 instructions\n"
				" dsp      step into program (skip libs)\n"
				" dsu addr step until address\n"
				" dsl      step one source line\n"
				" dsl 40   step 40 source lines\n");
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
	case 'o':
		r_core_file_reopen (core, input[1]? input+2: NULL);
		break;
	default:
		r_cons_printf ("Usage: d[sbhcrbo] [arg]\n"
		" dh [handler]   list or set debugger handler\n"
		" dH [handler]   transplant process to a new handler\n"
		" dd             file descriptors (!fd in r1)\n"
		" ds[ol] N       step, over, source line\n"
		" do             open process (reload, alias for 'oo')\n"
		" dp[=*?t][pid]  list, attach to process or thread id\n"
		" dc[?]          continue execution. dc? for more\n"
		" dr[?]          cpu registers, dr? for extended help\n"
		" db[?]          breakpoints\n"
		" dbt            display backtrace\n"
		" dt[?r] [tag]   display instruction traces (dtr=reset)\n"
		" dm[?*]         show memory maps\n");
		break;
	}
	if (follow>0) {
		ut64 pc = r_debug_reg_get (core->dbg, "pc");
		if ((pc<core->offset) || (pc > (core->offset+follow)))
			r_core_cmd0 (core, "sr pc");
	}
	return 0;
}

//TODO: Fix disasm loop is mandatory
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l) {
	char *cmd, *ret = NULL;
	cmd = r_str_dup_printf ("pd %i @ 0x%08"PFMT64x, l, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b) {
	char *cmd, *ret = NULL;
	cmd = r_str_dup_printf ("pD %i @ 0x%08"PFMT64x, b, addr);
	if (cmd) {
		ret = r_core_cmd_str (core, cmd);
		free (cmd);
	}
	return ret;
}

R_API int r_core_cmd_buffer(void *user, const char *buf) {
	char *ptr, *optr, *str = strdup (buf);
	optr = str;
	ptr = strchr (str, '\n');
	while (ptr) {
		*ptr = '\0';
		r_core_cmd (user, optr, 0);
		optr = ptr+1;
		ptr = strchr (str, '\n');
	}
	r_core_cmd (user, optr, 0);
	free (str);
	return R_TRUE;
}

R_API int r_core_cmdf(void *user, const char *fmt, ...) {
	char string[1024];
	int ret;
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (string, sizeof (string), fmt, ap);
	ret = r_core_cmd ((RCore *)user, string, 0);
	va_end (ap);
	return ret;
}

R_API int r_core_cmd0(void *user, const char *cmd) {
	return r_core_cmd ((RCore *)user, cmd, 0);
}

/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	const char *static_str;
	char *retstr = NULL;
	r_cons_reset ();
	if (r_core_cmd (core, cmd, 0) == -1) {
		eprintf ("Invalid command: %s\n", cmd);
		retstr = strdup ("");
	} else {
		r_cons_filter ();
		static_str = r_cons_get_buffer ();
		retstr = strdup (static_str? static_str: "");
		r_cons_reset ();
	}
	return retstr;
}

R_API void r_core_cmd_repeat(RCore *core, int next) {
	// Alias for ".."
	if (core->lastcmd)
	switch (*core->lastcmd) {
	case 'd': // debug
		r_core_cmd0 (core, core->lastcmd);
		switch (core->lastcmd[1]) {
		case 's':
		case 'c':
			r_core_cmd0 (core, "sr pc && pd 1");
		}
		break;
	case 'p': // print
	case 'x':
		r_core_cmd0 (core, next? "s++": "s--");
		r_core_cmd0 (core, core->lastcmd);
		break;
	}
}

static int r_core_cmd_nullcallback(void *data) {
	RCore *core = (RCore*) data;
	if (core->cmdrepeat) {
		r_core_cmd_repeat (core, 1);
		return 1;
	}
	return 0;
}

R_API void r_core_cmd_init(RCore *core) {
	core->cmd = r_cmd_new ();
	core->cmd->macro.printf = r_cons_printf;
	core->cmd->macro.num = core->num;
	core->cmd->macro.user = core;
	core->cmd->macro.cmd = r_core_cmd0;
	core->cmd->nullcallback = r_core_cmd_nullcallback;
	r_cmd_set_data (core->cmd, core);
	r_cmd_add (core->cmd, "x",        "alias for px", &cmd_hexdump);
	r_cmd_add (core->cmd, "mount",    "mount filesystem", &cmd_mount);
	r_cmd_add (core->cmd, "analysis", "analysis", &cmd_anal);
	r_cmd_add (core->cmd, "flag",     "get/set flags", &cmd_flag);
	r_cmd_add (core->cmd, "g",        "egg manipulation", &cmd_egg);
	r_cmd_add (core->cmd, "debug",    "debugger operations", &cmd_debug);
	r_cmd_add (core->cmd, "info",     "get file info", &cmd_info);
	r_cmd_add (core->cmd, "cmp",      "compare memory", &cmd_cmp);
	r_cmd_add (core->cmd, "seek",     "seek to an offset", &cmd_seek);
	r_cmd_add (core->cmd, "zign",     "zignatures", &cmd_zign);
	r_cmd_add (core->cmd, "Section",  "setup section io information", &cmd_section);
	r_cmd_add (core->cmd, "bsize",    "change block size", &cmd_bsize);
	r_cmd_add (core->cmd, "eval",     "evaluate configuration variable", &cmd_eval);
	r_cmd_add (core->cmd, "print",    "print current block", &cmd_print);
	r_cmd_add (core->cmd, "write",    "write bytes", &cmd_write);
	r_cmd_add (core->cmd, "Code",     "code metadata", &cmd_meta);
	r_cmd_add (core->cmd, "Project",  "project", &cmd_project);
	r_cmd_add (core->cmd, "open",     "open or map file", &cmd_open);
	r_cmd_add (core->cmd, "yank",     "yank bytes", &cmd_yank);
	r_cmd_add (core->cmd, "resize",   "change file size", &cmd_resize);
	r_cmd_add (core->cmd, "Visual",   "enter visual mode", &cmd_visual);
	r_cmd_add (core->cmd, "!",        "run system command", &cmd_system);
	r_cmd_add (core->cmd, "=",        "io pipe", &cmd_rap);
	r_cmd_add (core->cmd, "#",        "calculate hash", &cmd_hash);
	r_cmd_add (core->cmd, "?",        "help message", &cmd_help);
	r_cmd_add (core->cmd, ".",        "interpret", &cmd_interpret);
	r_cmd_add (core->cmd, "/",        "search kw, pattern aes", &cmd_search);
	r_cmd_add (core->cmd, "(",        "macro", &cmd_macro);
	r_cmd_add (core->cmd, "quit",     "exit program session", &cmd_quit);
}
