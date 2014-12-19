/* radare - LGPL - Copyright 2009-2014 - pancake */

#include <r_core.h>
#include <r_socket.h>
#include "../config.h"
#if __UNIX__
#include <signal.h>
#endif

#define DB core->sdb

R_LIB_VERSION(r_core);

static void r_core_debug_breakpoint_hit(RCore *core, RBreakpointItem *bpi) {
	const char *cmdbp;
	int oecho = core->cons->echo; // should be configurable by user?
	core->cons->echo = 1; // should be configurable by user?
	cmdbp = r_config_get (core->config, "cmd.bp");
	if (cmdbp && *cmdbp)
		r_core_cmd0 (core, cmdbp);
	r_core_cmd0 (core, bpi->data);
	core->cons->echo = oecho;
}

R_API int r_core_bind(RCore *core, RCoreBind *bnd) {
	bnd->core = core;
	bnd->bphit = (RCoreDebugBpHit)r_core_debug_breakpoint_hit;
	bnd->cmd = (RCoreCmd)r_core_cmd0;
	bnd->cmdstr = (RCoreCmdStr)r_core_cmd_str;
	bnd->puts = (RCorePuts)r_cons_strcat;
	return R_TRUE;
}

R_API RCore *r_core_ncast(ut64 p) {
	return (RCore*)(size_t)p;
}

R_API RCore *r_core_cast(void *p) {
	return (RCore*)p;
}

R_API void r_core_cmd_flush (RCore *core) {
	// alias
	r_cons_flush ();
}

static int core_cmd_callback (void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	return r_core_cmd0 (core, cmd);
}

static ut64 getref (RCore *core, int n, char t, int type) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	RListIter *iter;
	RAnalRef *r;
	RList *list;
	int i=0;
	if (!fcn) return UT64_MAX;
#if FCN_OLD
	list = (t=='r')? fcn->refs: fcn->xrefs;
	r_list_foreach (list, iter, r) {
		if (r->type == type) {
			if (i == n)
				return r->addr;
			i++;
		}
	}
#else
#warning implement getref() using sdb
#endif
	return UT64_MAX;
}

static ut64 num_callback(RNum *userptr, const char *str, int *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	RAnalFunction *fcn;
	char *ptr, *bptr;
	RFlagItem *flag;
	RIOSection *s;
	RAnalOp op;
	ut64 ret = 0;

	if (ok) *ok = R_FALSE;
	if (*str=='[') {
		ut64 n;
		int refsz = (core->assembler->bits & R_SYS_BITS_64)? 8: 4;
		const char *p = NULL;
		if (strlen (str)>5)
			p = strchr (str+5, ':');
		// TODO: honor LE
		if (p) {
			refsz = atoi (str+1);
			str = p;
		}
		// push state
		{
			char *o = strdup (str+1);
			const char *q = r_num_calc_index (core->num, NULL);
			r_str_replace_char (o, ']', 0);
			n = r_num_math (core->num, o);
			r_num_calc_index (core->num, q);
			free (o);
		}
		// pop state
		if (ok) *ok = 1;
		ut32 num = 0;
		switch (refsz) {
		case 8:
		case 4:
		case 2:
		case 1:
			(void)r_io_read_at (core->io, n, (ut8*)&num, refsz);
			r_mem_copyendian ((ut8*)&num, (ut8*)&num, refsz, !core->assembler->big_endian);
			return num;
		default:
			eprintf ("Invalid reference size: %d (%s)\n", refsz, str);
			return 0LL;
		}
	} else
	if (str[0]=='$') {
		if (ok) *ok = 1;
		// TODO: group analop-dependant vars after a char, so i can filter
		r_anal_op (core->anal, &op, core->offset,
			core->block, core->blocksize);
		switch (str[1]) {
		case '.': // can use pc, sp, a0, a1, ...
			return r_debug_reg_get (core->dbg, str+2);
		case '{':
			bptr = strdup (str+2);
			ptr = strchr (bptr, '}');
			if (ptr != NULL) {
				ut64 ret;
				ptr[0] = '\0';
				ret = r_config_get_i (core->config, bptr);
				free (bptr);
				return ret;
			}
			free (bptr);
			break;
		case 'c': return r_cons_get_size (NULL);
		case 'r': { int rows; r_cons_get_size (&rows); return rows; }
		case 'e': return r_anal_op_is_eob (&op);
		case 'j': return op.jump;
		case 'p': return r_sys_getpid ();
		case 'f': return op.fail;
		case 'm': return op.ptr; // memref
		case 'v': return op.val; // immediate value
		case 'l': return op.size;
		case 'b': return core->blocksize;
		case 's': return r_io_desc_size (core->io, core->file->desc);
		case 'w': return r_config_get_i (core->config, "asm.bits") / 8;
		case 'S':
			s = r_io_section_vget (core->io, core->offset);
			return s? (str[2]=='S'? s->size: s->vaddr): 3;
		case '?': return core->num->value;
		case '$': return core->offset;
		case 'o': return r_io_section_vaddr_to_offset (core->io,
				core->offset);
		case 'C': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_CALL);
		case 'J': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_CODE);
		case 'D': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_DATA);
		case 'X': return getref (core, atoi (str+2), 'x',
				R_ANAL_REF_TYPE_CALL);
		case 'I':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			return fcn? fcn->ninstr: 0;
		case 'F':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			return fcn? fcn->size: 0;
		}
	} else
	if (*str>'A') {
#if 0
		ut64 addr = r_anal_fcn_label_get (core->anal, core->offset, str);
		if (addr != 0) {
			ret = addr;
		} else {
#endif
			if ((flag = r_flag_get (core->flags, str))) {
				ret = flag->offset;
				if (ok) *ok = R_TRUE;
			}
//		}
	}

	return ret;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW0 (RCore);
	r_core_init (c);
	return c;
}

/*-----------------------------------*/
#define CMDS (sizeof (radare_argv)/sizeof(const char*))
static const char *radare_argv[] = {
	"?", "?v", "whereis", "which", "ls", "pwd", "cat", "less",
	"dH", "ds", "dso", "dsl", "dc", "dd", "dm", "db ", "db-",
        "dp", "dr", "dcu", "dmd", "dmp", "dml",
	"ec","ecs",
	"S",
	"s", "s+", "s++", "s-", "s--", "s*", "sa", "sb", "sr",
	"!", "!!",
	"#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5",
	"#!python", "#!perl", "#!vala",
	"V",
	"aa", "ab", "af", "ar", "ag", "at", "a?", "ax",
	"af", "afc", "afi", "afb", "afbb", "afr", "afs", "af*",
	"aga", "agc", "agd", "agl", "agfl",
	"e", "e-", "e*", "e!", "e?", "env ",
	"i", "ii", "iI", "is", "iS", "iz",
	"q",
	"f", "fl", "fr", "f-", "f*", "fs", "fS", "fr", "fo", "f?",
	"m", "m*", "ml", "m-", "my", "mg", "md", "mp", "m?",
	"o", "o+", "oc", "on", "op", "o-", "x", "wf", "wF", "wt", "wp",
	"(", "(*", "(-", "()", ".", ".!", ".(", "./",
	"r", "r+", "r-",
	"b", "bf", "b?",
	"/", "//", "/a", "/c", "/m", "/x", "/v", "/v2", "/v4", "/v8", "/r"
	"y", "yy", "y?",
	"wx", "ww", "w?",
	"p6d", "p6e", "p8", "pb", "pc",
	"pd", "pda", "pdj", "pdb", "pdr", "pdf", "pdi", "pdl",
	"pD", "px", "pX", "po",
	"pm", "pr", "pt", "ptd", "ptn", "pt?", "ps", "pz", "pu", "pU", "p?",
	NULL
};

#define TMP_ARGV_SZ 256
static const char *tmp_argv[TMP_ARGV_SZ];
static int autocomplete(RLine *line) {
	RCore *core = line->user;
	RListIter *iter;
	RFlagItem *flag;
	line->completion.argc = 0;
	line->completion.argv = tmp_argv;
	if (core) {
		char *ptr = strchr (line->buffer.data, '@');
		if (ptr && line->buffer.data+line->buffer.index >= ptr) {
			int sdelta, n, i = 0;
			ptr = (char *)r_str_chop_ro (ptr+1);
			n = strlen (ptr);//(line->buffer.data+sdelta);
			sdelta = (int)(size_t)(ptr - line->buffer.data);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!memcmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i==TMP_ARGV_SZ-1)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else
		if ((!memcmp (line->buffer.data, "o ", 2)) ||
		     !memcmp (line->buffer.data, "o+ ", 3) ||
		     !memcmp (line->buffer.data, "oc ", 3) ||
		     !memcmp (line->buffer.data, "on ", 3) ||
		     !memcmp (line->buffer.data, "op ", 3) ||
		     !memcmp (line->buffer.data, ". ", 2) ||
		     !memcmp (line->buffer.data, "wf ", 3) ||
		     !memcmp (line->buffer.data, "ls ", 3) ||
		     !memcmp (line->buffer.data, "ls -l ", 5) ||
		     !memcmp (line->buffer.data, "wF ", 3) ||
		     !memcmp (line->buffer.data, "cat ", 4) ||
		     !memcmp (line->buffer.data, "less ", 5) ||
		     !memcmp (line->buffer.data, "wt ", 3) ||
		     !memcmp (line->buffer.data, "wp ", 3) ||
		     !memcmp (line->buffer.data, "tf ", 3) ||
		     !memcmp (line->buffer.data, "pm ", 3) ||
		     !memcmp (line->buffer.data, "dml ", 4) ||
		     !memcmp (line->buffer.data, "/m ", 3)) {
			// XXX: SO MANY FUCKING MEMORY LEAKS
			char *str, *p, *path;
			int n = 0, i = 0;
			RList *list;
			int sdelta = (line->buffer.data[1]==' ')? 2:
				(line->buffer.data[2]==' ')? 3:
				(line->buffer.data[3]==' ')? 4: 5;
			path = line->buffer.data[sdelta]?
				strdup (line->buffer.data+sdelta):
				r_sys_getdir ();
			p = (char *)r_str_lchr (path, '/');
			if (p) {
				if (p==path) path = strdup ("/");
				else if (p!=path+1) *p = 0;
				p++;
			}
			if (p) { if (*p) n = strlen (p); else p = ""; }
			if (*path=='~') {
				char *lala = r_str_home (path+1);
				free (path);
				path = lala;
			} else if (*path!='.' && *path!='/') {
				char *o = malloc (strlen (path)+4);
				memcpy (o, "./", 3);
				p = o+3;
				n = strlen (path);
				memcpy (o+3, path, strlen (path)+1);
				free (path);
				path = o;
			}
 			list = p? r_sys_dir (path): NULL;
			if (list) {
				char buf[4096];
				r_list_foreach (list, iter, str) {
					if (*str == '.')
						continue;
					if (!p || !*p || !strncmp (str, p, n)) {
						snprintf (buf, sizeof (buf), "%s%s%s",
							path, strlen (path)>1?"/":"", str);
						tmp_argv[i++] = strdup (buf);
						if (i==TMP_ARGV_SZ) {
							i--;
							break;
						}
					}
				}
				r_list_purge (list);
				free (list);
			} else eprintf ("\nInvalid directory\n");
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
			free (path);
			//free (p);
		} else
		if((!memcmp (line->buffer.data, ".(", 2))  ||
		   (!memcmp (line->buffer.data, "(-", 2))) {
			const char *str = line->buffer.data;
			RCmdMacroItem *item;
			char buf[1024];
			int n, i = 0;

			n = line->buffer.length-2;
			if (str && !strchr (str+2, ' ')) {
				str += 2;
				r_list_foreach (core->rcmd->macro.macros, iter, item) {
					char *p = item->name;
					if (!str || !*str || !memcmp (str, p, n)) {
						snprintf (buf, sizeof (buf), "%c%c%s)",
							line->buffer.data[0],
							line->buffer.data[1],
							p);
						eprintf ("------ %p\n", tmp_argv[i]);
						if (r_is_heap ((void*)tmp_argv[i]))
							free ((char *)tmp_argv[i]);
						tmp_argv[i] = strdup (buf); // LEAKS
						i++;
						if (i==TMP_ARGV_SZ)
							break;
					}
				}
			}
			tmp_argv[(i-1>0)?i-1:0] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else
		if ((!memcmp (line->buffer.data, "s ", 2)) ||
		    (!memcmp (line->buffer.data, "bf ", 3)) ||
		    (!memcmp (line->buffer.data, "ag ", 3)) ||
		    (!memcmp (line->buffer.data, "afi ", 4)) ||
		    (!memcmp (line->buffer.data, "afb ", 4)) ||
		    (!memcmp (line->buffer.data, "afc ", 4)) ||
		    (!memcmp (line->buffer.data, "axt ", 4)) ||
		    (!memcmp (line->buffer.data, "axf ", 4)) ||
		    (!memcmp (line->buffer.data, "aga ", 5)) ||
		    (!memcmp (line->buffer.data, "agc ", 4)) ||
		    (!memcmp (line->buffer.data, "agl ", 4)) ||
		    (!memcmp (line->buffer.data, "agd ", 4)) ||
		    (!memcmp (line->buffer.data, "agfl ", 5)) ||
		    (!memcmp (line->buffer.data, "b ", 2)) ||
		    (!memcmp (line->buffer.data, "dcu ", 4)) ||
		    (!memcmp (line->buffer.data, "/v ", 3)) ||
		    (!memcmp (line->buffer.data, "db ", 3)) ||
		    (!memcmp (line->buffer.data, "db- ", 4)) ||
		    (!memcmp (line->buffer.data, "f ", 2)) ||
		    (!memcmp (line->buffer.data, "fr ", 3)) ||
		    (!memcmp (line->buffer.data, "/a ", 3)) ||
		    (!memcmp (line->buffer.data, "?v ", 3)) ||
		    (!memcmp (line->buffer.data, "? ", 2))) {
			int n, i = 0;
			int sdelta = (line->buffer.data[1]==' ')?2:
				(line->buffer.data[2]==' ')?3:4;
			n = strlen (line->buffer.data+sdelta);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!memcmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i>255?255:i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else
		if (!memcmp (line->buffer.data, "-", 1)) {
			int count;
			char **keys = r_cmd_alias_keys(core->rcmd, &count);
			char *data = line->buffer.data;
			if (keys) {
				int i, j;
				for (i=j=0; i<count; i++) {
					if (!strncmp (keys[i], data, line->buffer.index)) {
						tmp_argv[j++] = keys[i];
					}
				}
				tmp_argv[j] = NULL;
				line->completion.argc = j;
				line->completion.argv = tmp_argv;
			} else {
				line->completion.argc = 0;
				line->completion.argv = NULL;
			}
		} else
		if ( (!strncmp (line->buffer.data, "e ", 2))
		   ||(!strncmp (line->buffer.data, "e? ", 3))) {
			int m = (line->buffer.data[1] == '?')? 3: 2;
			int i = 0, n = strlen (line->buffer.data+m);
			RConfigNode *bt;
			RListIter *iter;
			r_list_foreach (core->config->nodes, iter, bt) {
				if (!strncmp (bt->name, line->buffer.data+m, n)) {
					tmp_argv[i++] = bt->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else {
			int i, j;
			for (i=j=0; i<CMDS && radare_argv[i]; i++)
				if (!strncmp (radare_argv[i], line->buffer.data,
						line->buffer.index))
					tmp_argv[j++] = radare_argv[i];
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		}
	} else {
		int i,j;
		for (i=j=0; i<CMDS && radare_argv[i]; i++)
			if (!memcmp (radare_argv[i], line->buffer.data,
					line->buffer.index))
				tmp_argv[j++] = radare_argv[i];
		tmp_argv[j] = NULL;
		line->completion.argc = j;
		line->completion.argv = tmp_argv;
	}
	return R_TRUE;
}

R_API int r_core_fgets(char *buf, int len) {
	/* TODO: link against dietline if possible for autocompletion */
	char *ptr;
	RLine *rli = r_line_singleton ();
	buf[0]='\0';
	rli->completion.argc = CMDS;
	rli->completion.argv = radare_argv;
	rli->completion.run = autocomplete;
	ptr = r_line_readline (); //CMDS, radare_argv);
	if (ptr == NULL)
		return -1;
	strncpy (buf, ptr, len);
	//free(ptr); // XXX leak
	return strlen (buf)+1;
}
/*-----------------------------------*/

#if 0
static int __dbg_read(void *user, int pid, ut64 addr, ut8 *buf, int len)
{
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_read_at(core, addr, buf, len);
}

static int __dbg_write(void *user, int pid, ut64 addr, const ut8 *buf, int len) {
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_write_at(core, addr, buf, len);
}
#endif

static const char *r_core_print_offname(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_i (c->flags, addr);
	if (item) return item->name;
	return NULL;
}

static int __disasm(void *_core, ut64 addr) {
	RCore *core = _core;
	ut8 buf[32], *oblock;
	int len;
	oblock = core->block;
	r_io_read_at (core->io, addr, (ut8*)buf, sizeof (buf));
	len = r_core_print_disasm_instructions (core, sizeof (buf), 1);
	core->block = oblock;
	return len;
}

static void update_sdb(RCore *core) {
	RBinObject *o;
	if (!core)
		return;
	//SDB// anal/
	if (core->anal && core->anal->sdb)
		sdb_ns_set (DB, "anal", core->anal->sdb);
	//SDB// bin/
	if (core->bin && core->bin->sdb)
		sdb_ns_set (DB, "bin", core->bin->sdb);
	//SDB// bin/info
	o = r_bin_get_object (core->bin);
	if (o) {
		sdb_ns_set (sdb_ns (DB, "bin", 1), "info", o->kv);
	}
	//sdb_ns_set (core->sdb, "flags", core->flags->sdb);
	//sdb_ns_set (core->sdb, "bin", core->bin->sdb);
	//SDB// syscall/
	if (core->assembler && core->assembler->syscall && core->assembler->syscall->db) {
		core->assembler->syscall->db->refs++;
		sdb_ns_set (DB, "syscall", core->assembler->syscall->db);
	}
	{
		Sdb *d = sdb_ns (DB, "debug", 1);
		core->dbg->sgnls->refs++;
		sdb_ns_set (d, "signals", core->dbg->sgnls);
	}
}

// dupped in cmd_type.c
static char *getenumname(void *_core, const char *name, ut64 val) {
	const char *isenum;
	RCore *core = (RCore*)_core;
	isenum = sdb_const_get (core->anal->sdb_types, name, 0);
	if (isenum && !strcmp (isenum, "enum")) {
		const char *q = sdb_fmt (0, "%s.0x%x", name, val);
		return sdb_get (core->anal->sdb_types, q, 0);
	} else {
		eprintf ("This is not an enum\n");
	}
	return NULL;
}

// TODO: dupped in cmd_type.c
static char *getbitfield(void *_core, const char *name, ut64 val) {
	const char *isenum;
	char *ret = NULL;
	int i;
	RCore *core = (RCore*)_core;
	isenum = sdb_const_get (core->anal->sdb_types, name, 0);
	if (isenum && !strcmp (isenum, "enum")) {
		int empty = 1;
		ret = r_str_concatf (ret, "0x%08"PFMT64x" : ", val);
		for (i=0; i< 32; i++) {
			if (val & (1<<i)) {
				const char *q = sdb_fmt (0, "%s.0x%x", name, (1<<i));
				const char *res = sdb_const_get (core->anal->sdb_types, q, 0);
				if (!empty)
					ret = r_str_concat (ret, " | ");
				if (res) ret = r_str_concat (ret, res);
				else ret = r_str_concatf (ret, "0x%x", (1<<i));
				empty = 0;
			}
		}
	} else {
		eprintf ("This is not an enum\n");
	}
	return ret;
}

// TODO: return string instead of printing it. reuse from 'drr'
R_API const char *r_core_anal_hasrefs(RCore *core, ut64 value) {
	ut64 type;
	//int bits = core->assembler->bits;
	//RList *list = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
	RAnalFunction *fcn;
	RFlagItem *fi;
	fi = r_flag_get_i (core->flags, value);
	type = r_core_anal_address (core, value);
	fcn = r_anal_get_fcn_in (core->anal, value, 0);
	if (value && fi) {
		r_cons_printf (" %s", fi->name);
	}
	if (fcn) {
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
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			r_cons_printf (" %sX%s", c, cend);
			{
				RAsmOp op;
				ut8 buf[32];
				r_io_read_at (core->io, value, buf, sizeof (buf));
				r_asm_set_pc (core->assembler, value);
				r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
				r_cons_printf (" '%s'", op.buf_asm);
			}
			/* get library name */
			{
				RDebugMap *map;
				RListIter *iter;
				r_list_foreach (core->dbg->maps, iter, map) {
					if ((value >=map->addr) && (value<map->addr_end)) {
						const char *lastslash = r_str_lchr (map->name, '/');
						r_cons_printf (" '%s'", lastslash?
							lastslash+1:map->name);
						break;
					}
				}
			}
		}
	}
	return NULL;
}

R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr) {
	ut64 type;
	if (!(core->print->flags & R_PRINT_FLAGS_COLOR))
		return NULL;
	type = r_core_anal_address (core, addr);
	if (type & R_ANAL_ADDR_TYPE_EXEC)
		return core->cons->pal.ai_exec; //Color_RED;
	if (type & R_ANAL_ADDR_TYPE_WRITE)
		return core->cons->pal.ai_write; //Color_BLUE;
	if (type & R_ANAL_ADDR_TYPE_READ)
		return core->cons->pal.ai_read; //Color_GREEN;
	if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
		return core->cons->pal.ai_seq; //Color_MAGENTA;
	if (type & R_ANAL_ADDR_TYPE_ASCII)
		return core->cons->pal.ai_ascii; //Color_YELLOW;
	return NULL;
}

R_API int r_core_init(RCore *core) {
	static int singleton = R_TRUE;
	core->cmd_depth = R_CORE_CMD_DEPTH+1;
	core->sdb = sdb_new (NULL, "r2kv.sdb", 0); // XXX: path must be in home?
	core->zerosep = R_FALSE;
	core->incomment = R_FALSE;
	core->screen_bounds = 0LL;
	core->config = NULL;
	core->http_up = R_FALSE;
	core->print = r_print_new ();
	core->print->user = core;
	core->print->get_enumname = getenumname;
	core->print->get_bitfield = getbitfield;
	core->print->offname = r_core_print_offname;
	core->print->printf = (void *)r_cons_printf;
	core->print->write = (void *)r_cons_memcat;
	core->print->disasm = __disasm;
	core->print->colorfor = (RPrintColorFor)r_core_anal_optype_colorfor;
	core->print->hasrefs = (RPrintColorFor)r_core_anal_hasrefs;
	core->rtr_n = 0;
	core->blocksize_max = R_CORE_BLOCKSIZE_MAX;
	core->tasks = r_list_new ();
	core->watchers = r_list_new ();
	core->watchers->free = (RListFree)r_core_cmpwatch_free;
	core->scriptstack = r_list_new ();
	core->scriptstack->free = (RListFree)free;
	core->log = r_core_log_new ();
	core->vmode = R_FALSE;
	core->section = NULL;
	core->oobi = NULL;
	core->oobi_len = 0;
	core->printidx = 0;
	core->lastcmd = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = R_TRUE;
	core->reflines = NULL;
	core->reflines2 = NULL;
	core->yank_buf = r_buf_new();
	core->num = r_num_new (&num_callback, core);
	//core->num->callback = &num_callback;
	//core->num->userptr = core;
	core->curasmstep = 0;
	core->egg = r_egg_new ();
	r_egg_setup (core->egg, R_SYS_ARCH, R_SYS_BITS, 0, R_SYS_OS);

	/* initialize libraries */
	core->cons = r_cons_singleton ();
	if (singleton) {
		r_cons_new ();
		core->cons = r_cons_singleton ();
		if (core->cons->line) {
			core->cons->line->user = core;
			core->cons->line->editor_cb = \
				(RLineEditorCb)&r_core_editor;
		}
#if __EMSCRIPTEN__
		core->cons->user_fgets = NULL;
#else
		core->cons->user_fgets = (void *)r_core_fgets;
#endif
		//r_line_singleton()->user = (void *)core;
		r_line_hist_load (R2_HOMEDIR"/history");
		singleton = R_FALSE;
	}
	core->print->cons = core->cons;
	core->cons->num = core->num;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8*)malloc (R_CORE_BLOCKSIZE);
	if (core->block == NULL) {
		eprintf ("Cannot allocate %d bytes\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return R_FALSE;
	}
	core->lang = r_lang_new ();
	core->cons->editor = (RConsEditorCallback)r_core_editor;
	core->cons->user = (void*)core;
	core->lang->printf = r_cons_printf;
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->assembler = r_asm_new ();
	core->assembler->num = core->num;
	r_asm_set_user_ptr (core->assembler, core);
	core->anal = r_anal_new ();
	core->assembler->syscall = \
		core->anal->syscall; // BIND syscall anal/asm
	r_anal_set_user_ptr (core->anal, core);
	core->anal->printf = (void *) r_cons_printf;
	core->parser = r_parse_new ();
	core->parser->anal = core->anal;
	core->parser->varlist = r_anal_var_list;
	r_parse_set_user_ptr (core->parser, core);
	core->bin = r_bin_new ();
	core->bin->printf = (PrintfCallback) r_cons_printf;
	r_bin_set_user_ptr (core->bin, core);
	core->io = r_io_new ();
	core->io->ff = 1;
	core->io->user = (void *)core;
	core->io->core_cmd_cb = core_cmd_callback;
	core->sign = r_sign_new ();
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	core->flags = r_flag_new ();

	r_bin_bind (core->bin, &(core->assembler->binb));
	r_bin_bind (core->bin, &(core->anal->binb));
	r_bin_bind (core->bin, &(core->anal->binb));

	r_io_bind (core->io, &(core->search->iob));
	r_io_bind (core->io, &(core->print->iob));
	r_io_bind (core->io, &(core->anal->iob));
	r_io_bind (core->io, &(core->fs->iob));
	r_io_bind (core->io, &(core->bin->iob));
	r_flag_bind (core->flags, &(core->anal->flb));

	core->file = NULL;
	core->files = r_list_new ();
	core->files->free = (RListFree)r_core_file_free;
	core->offset = 0LL;
	r_core_cmd_init (core);
	core->dbg = r_debug_new (R_TRUE);
	r_core_bind (core, &core->dbg->corebind);
	core->dbg->graph->printf = (PrintfCallback)r_cons_printf;
	core->dbg->printf = (PrintfCallback)r_cons_printf;
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	//r_debug_use (core->dbg, "native");
// XXX pushing unititialized regstate results in trashed reg values
//	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->sign->printf = r_cons_printf;
	core->io->printf = r_cons_printf;
	core->dbg->printf = r_cons_printf;
	core->dbg->bp->printf = r_cons_printf;
	r_debug_io_bind (core->dbg, core->io);

	r_core_config_init (core);

	r_core_loadlibs_init (core);
	//r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (core->assembler, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64)
		r_config_set_i (core->config, "asm.bits", 64);
	else
	if (R_SYS_BITS & R_SYS_BITS_32)
		r_config_set_i (core->config, "asm.bits", 32);
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	update_sdb (core);
	return 0;
}

R_API RCore *r_core_fini(RCore *c) {
	if (!c) return NULL;
	/* TODO: it leaks as shit */
	//update_sdb (c);
	r_core_task_join (c, NULL);
	free (c->cmdqueue);
	free (c->lastcmd);
	r_io_free (c->io);
	r_num_free (c->num);
	// TODO: sync or not? sdb_sync (c->sdb);
	// TODO: sync all dbs?
	//r_core_file_free (c->file);
	//c->file = NULL;
	r_list_free (c->files);
	r_list_free (c->watchers);
	r_list_free (c->scriptstack);
	c->rcmd = r_cmd_free (c->rcmd);
	c->anal = r_anal_free (c->anal);
	c->assembler = r_asm_free (c->assembler);
	c->print = r_print_free (c->print);
	c->bin = r_bin_free (c->bin); // XXX segfaults rabin2 -c
	c->lang = r_lang_free (c->lang); // XXX segfaults
	c->dbg = r_debug_free (c->dbg);
	r_config_free (c->config);
	/* after r_config_free, the value of I.teefile is trashed */
	/* rconfig doesnt knows how to deinitialize vars, so we
	should probably need to add a r_config_free_payload callback */
	r_cons_free ();
	r_cons_singleton()->teefile = NULL; // HACK
	r_search_free (c->search);
	r_sign_free (c->sign);
	r_flag_free (c->flags);
	r_fs_free (c->fs);
	r_egg_free (c->egg);
	r_lib_free (c->lib);
	r_buf_free (c->yank_buf);
	sdb_free (c->sdb);
	return NULL;
}

R_API RCore *r_core_free(RCore *c) {
	if (c) r_core_fini (c);
	free (c);
	return NULL;
}

R_API void r_core_prompt_loop(RCore *r) {
	int ret;
	do {
		if (r_core_prompt (r, R_FALSE)<1)
			break;
//			if (lock) r_th_lock_enter (lock);
		if ((ret = r_core_prompt_exec (r))==-1)
			eprintf ("Invalid command\n");
/*			if (lock) r_th_lock_leave (lock);
		if (rabin_th && !r_th_wait_async (rabin_th)) {
			eprintf ("rabin thread end \n");
			r_th_free (rabin_th);
			r_th_lock_free (lock);
			lock = NULL;
			rabin_th = NULL;
		}
*/
	} while (ret != R_CORE_CMD_EXIT);
}

R_API int r_core_prompt(RCore *r, int sync) {
	int ret, rnv;
	char line[4096];
	char prompt[64];
	const char *filename = "";
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");
	const char *BEGIN = r->cons->pal.prompt;
	const char *END = r->cons->pal.reset;
	rnv = r->num->value;

	if (!BEGIN) BEGIN = "";
	if (!END) END = "";
	// hacky fix fo rio
	r_core_block_read (r, 0);
	if (cmdprompt && *cmdprompt)
		r_core_cmd (r, cmdprompt, 0);

	if (!r_line_singleton ()->echo)
		*prompt = 0;
	if (r_config_get_i (r->config, "scr.fileprompt"))
		filename = r->io->desc->name;
	// TODO: also in visual prompt and disasm/hexdump ?
	if (r_config_get_i (r->config, "asm.segoff")) {
		ut32 a, b;
		a = ((r->offset >>16)<<12);
		b = (r->offset & 0xffff);
#if __UNIX__
		if (r_config_get_i (r->config, "scr.color"))
			snprintf (prompt, sizeof (prompt),
				"%s%s%s[%04x:%04x]>%s ",
				filename, *filename?" ":"",
				BEGIN, a, b, END);
		else
#endif
		snprintf (prompt, sizeof (prompt),
			"%s%s[%04x:%04x]> ",
			filename, *filename?" ":"",
			a, b);
	} else {
#if __UNIX__
		if (r_config_get_i (r->config, "scr.color"))
			snprintf (prompt, sizeof (prompt),
				"%s%s%s[0x%08"PFMT64x"]>%s ",
				filename, *filename?" ":"",
				BEGIN, r->offset, END);
		else
#endif
		snprintf (prompt, sizeof (prompt),
			"%s%s[0x%08"PFMT64x"]> ",
			filename, *filename?" ":"",
			r->offset);
	}
	r_line_set_prompt (prompt);
	ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2) return R_CORE_CMD_EXIT; // ^D
	if (ret == -1) return R_FALSE; // FD READ ERROR
	r->num->value = rnv;
	if (sync) {
		return r_core_prompt_exec (r);
	}
	free (r->cmdqueue);
	r->cmdqueue = strdup (line);
	return R_TRUE;
}

R_API int r_core_prompt_exec(RCore *r) {
	int ret = r_core_cmd (r, r->cmdqueue, R_TRUE);
	r_cons_flush ();
	if (r->zerosep)
		r_cons_zero ();
	return ret;
}

R_API int r_core_block_size(RCore *core, int bsize) {
	ut8 *bump;
	int ret = R_FALSE;
	if (bsize == core->blocksize)
		return R_FALSE;
	if (bsize<0 || bsize > core->blocksize_max) {
		eprintf ("Block size %d is too big\n", bsize);
		return R_FALSE;
	}
	if (bsize<1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize>core->blocksize_max) {
		eprintf ("bsize is bigger than `bm`. dimmed to 0x%x > 0x%x\n",
			bsize, core->blocksize_max);
		bsize = core->blocksize_max;
	} else ret = R_TRUE;
	bump = realloc (core->block, bsize+1);
	if (bump == NULL) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		ret = R_FALSE;
	} else {
		ret = R_TRUE;
		core->block = bump;
		core->blocksize = bsize;
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core, 0);
	}
	return ret;
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int diff, inc = (times>=0)?1:-1;
	ut64 seek = core->offset;

	if (!align)
		return R_FALSE;
	diff = core->offset%align;
	if (times == 0)
		diff = -diff;
	else if (diff) {
		if (inc>0) diff += align-diff;
		else diff = -diff;
		if (times) times -= inc;
	}
	while ((times*inc)>0) {
		times -= inc;
		diff += align*inc;
	}
	if (diff<0 && -diff>seek)
		seek = diff = 0;
	return r_core_seek (core, seek+diff, 1);
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAsmOp op;
	ut8 buf[64];
	int ret;
	r_asm_set_pc (core->assembler, addr);
	r_core_read_at (core, addr, buf, sizeof (buf));
	ret = r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
	return (ret>0)?strdup (op.buf_asm): NULL;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr) {
	ut8 buf[64];
	RAnalOp *op = R_NEW (RAnalOp);
	r_core_read_at (core, addr, buf, sizeof (buf));
	r_anal_op (core->anal, op, addr, buf, sizeof (buf));
	return op;
}

static void rap_break (void *u) {
	RIORap *rior = (RIORap*) u;
	if (u) {
		r_socket_free (rior->fd);
		rior->fd = NULL;
	}
}

// TODO: PLEASE move into core/io/rap? */
// TODO: use static buffer instead of mallocs all the time. it's network!
R_API int r_core_serve(RCore *core, RIODesc *file) {
	ut8 cmd, flg, *ptr = NULL, buf[1024];
	RSocket *c, *fd;
	int i, pipefd;
	RIORap *rior;
	ut64 x;
	int LE = 1; // 1 if host is little LE

	rior = (RIORap *)file->data;
	if (rior == NULL|| rior->fd == NULL) {
		eprintf ("rap: cannot listen.\n");
		return -1;
	}
	fd = rior->fd;

	eprintf ("RAP Server started (rap.loop=%s)\n",
			r_config_get (core->config, "rap.loop"));
#if __UNIX__
	// XXX: ugly workaround
	//signal (SIGINT, exit);
	//signal (SIGPIPE, SIG_DFL);
#endif
reaccept:
	core->io->plugin = NULL;
	r_cons_break (rap_break, rior);
	while (!core->cons->breaked) {
		c = r_socket_accept (fd);
		if (!c) break;
		if (core->cons->breaked)
			return -1;
		if (c == NULL) {
			eprintf ("rap: cannot accept\n");
			r_socket_close (c);
			return -1;
		}
		eprintf ("rap: client connected\n");
		for (;!core->cons->breaked;) {
			if (!r_socket_read (c, &cmd, 1)) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					goto reaccept;
				}
				return -1;
			}

			switch ((ut8)cmd) {
			case RMT_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				eprintf ("open (%d): ", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				ptr = malloc (cmd);
				//XXX cmd is ut8..so <256 if (cmd<RMT_MAX)
				if (ptr == NULL) {
					eprintf ("Cannot malloc in rmt-open len = %d\n", cmd);
				} else {
					RCoreFile *file;
					ut64 baddr = r_config_get_i (core->config, "bin.laddr");
					r_socket_read_block (c, ptr, cmd); //filename
					ptr[cmd] = 0;
					file = r_core_file_open (core, (const char *)ptr, R_IO_READ, 0); // XXX: write mode?
					if (file) {
						r_core_bin_load (core, NULL, baddr);
						file->map = r_io_map_add (core->io, file->desc->fd,
							R_IO_READ, 0, 0, r_io_desc_size (core->io, file->desc));
						pipefd = core->file->desc->fd;
						eprintf ("(flags: %d) len: %d filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					} else {
						pipefd = -1;
						eprintf ("Cannot open file (%s)\n", ptr);
						return -1; //XXX: Close conection and goto accept
					}
				}
				buf[0] = RMT_OPEN | RMT_REPLY;
				r_mem_copyendian (buf+1, (ut8 *)&pipefd, 4, !LE);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);

#if 0
				/* Write meta info */
				RMetaItem *d;
				r_list_foreach (core->anal->meta->data, iter, d) {
					if (d->type == R_META_TYPE_COMMENT)
						snprintf ((char *)buf, sizeof (buf), "%s %s @ 0x%08"PFMT64x,
							r_meta_type_to_string (d->type), d->str, d->from);
					else
						snprintf ((char *)buf, sizeof (buf),
							"%s %d %s @ 0x%08"PFMT64x,
							r_meta_type_to_string (d->type),
							(int)(d->to-d->from), d->str, d->from);
					i = strlen ((char *)buf);
					r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !LE);
					r_socket_write (c, (ut8 *)&j, 4);
					r_socket_write (c, buf, i);
					r_socket_flush (c);
				}
#endif
#if 0
				RIOSection *s;
				r_list_foreach_prev (core->io->sections, iter, s) {
					snprintf ((char *)buf, sizeof (buf),
							"S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d",
							s->offset, s->vaddr, s->size, s->vsize, s->name, s->rwx);
					i = strlen ((char *)buf);
					r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !LE);
					r_socket_write (c, (ut8 *)&j, 4);
					r_socket_write (c, buf, i);
					r_socket_flush (c);
				}
#endif
#if 0
				int fs = -1;
				RFlagItem *flag;
				r_list_foreach_prev (core->flags->flags, iter, flag) {
					if (fs == -1 || flag->space != fs) {
						fs = flag->space;
						snprintf ((char *)buf, sizeof (buf),
								"fs %s", r_flag_space_get_i (core->flags, fs));
						i = strlen ((char *)buf);
						r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !LE);
						r_socket_write (c, (ut8 *)&j, 4);
						r_socket_write (c, buf, i);
					}
					snprintf ((char *)buf, sizeof (buf),
									"f %s %"PFMT64d" 0x%08"PFMT64x,
									flag->name, flag->size, flag->offset);
						i = strlen ((char *)buf);
						r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !LE);
						r_socket_write (c, (ut8 *)&j, 4);
						r_socket_write (c, buf, i);
						r_socket_flush (c);
				}

				snprintf ((char *)buf, sizeof (buf), "s 0x%"PFMT64x, core->offset);
				i = strlen ((char *)buf);
				r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !LE);
				r_socket_write (c, (ut8 *)&j, 4);
				r_socket_write (c, buf, i);

				i = 0;
				r_socket_write (c, (ut8 *)&i, 4);
				r_socket_flush (c);
#endif
				free (ptr);
				ptr = NULL;
				break;
			case RMT_READ:
				r_socket_read_block (c, (ut8*)&buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, !LE);
				ptr = (ut8 *)malloc (i+core->blocksize+5);
				if (ptr==NULL) {
					eprintf ("Cannot read %d bytes\n", i);
					r_socket_close (c);
					// TODO: reply error here
					return -1;
				} else {
					r_core_block_read (core, 0);
					ptr[0] = RMT_READ|RMT_REPLY;
					if (i>RMT_MAX)
						i = RMT_MAX;
					if (i>core->blocksize)
						r_core_block_size (core, i);
					r_mem_copyendian (ptr+1, (ut8 *)&i, 4, !LE);
					memcpy (ptr+5, core->block, i); //core->blocksize);
					r_socket_write (c, ptr, i+5);
					r_socket_flush (c);
					free(ptr);
					ptr = NULL;
				}
				break;
			case RMT_CMD:
				{
				char bufr[8], *bufw = NULL;
				char *cmd = NULL, *cmd_output = NULL;
				ut32 cmd_len = 0;
				int i;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				r_mem_copyendian ((ut8*)&i, (ut8 *)bufr, 4, !LE);
				if (i>0 && i<RMT_MAX) {
					if ((cmd=malloc (i+1))) {
						r_socket_read_block (c, (ut8*)cmd, i);
						cmd[i] = '\0';
						eprintf ("len: %d cmd: '%s'\n",
							i, cmd); fflush(stdout);
						cmd_output = r_core_cmd_str (core, cmd);
						free (cmd);
					} else eprintf ("rap: cannot malloc\n");
				} else eprintf ("rap: invalid length '%d'\n", i);
				/* write */
				if (cmd_output) {
					cmd_len = strlen (cmd_output) + 1;
				} else {
					cmd_output = strdup ("");
					cmd_len = 0;
				}
				bufw = malloc (cmd_len + 5);
				bufw[0] = RMT_CMD | RMT_REPLY;
				r_mem_copyendian ((ut8*)bufw+1,
					(ut8 *)&cmd_len, 4, !LE);
				memcpy (bufw+5, cmd_output, cmd_len);
				r_socket_write (c, bufw, cmd_len+5);
				r_socket_flush (c);
				free (bufw);
				free (cmd_output);
				break;
				}
			case RMT_WRITE:
				r_socket_read (c, buf, 5);
				r_mem_copyendian((ut8 *)&x, buf+1, 4, LE);
				ptr = malloc (x);
				r_socket_read (c, ptr, x);
				r_core_write_at (core, core->offset, ptr, x);
				free (ptr);
				ptr = NULL;
				break;
			case RMT_SEEK:
				r_socket_read_block (c, buf, 9);
				r_mem_copyendian((ut8 *)&x, buf+1, 8, !LE);
				if (buf[0]!=2) {
					r_core_seek (core, x, buf[0]);
					x = core->offset;
				} else x = r_io_desc_size (core->io, core->file->desc);
				buf[0] = RMT_SEEK | RMT_REPLY;
				r_mem_copyendian (buf+1, (ut8*)&x, 8, !LE);
				r_socket_write (c, buf, 9);
				r_socket_flush (c);
				break;
			case RMT_CLOSE:
				eprintf ("CLOSE\n");
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, LE);
				{
				//FIXME: Use r_socket_close
				int ret = close (i);
				r_mem_copyendian (buf+1, (ut8*)&ret, 4, !LE);
				buf[0] = RMT_CLOSE | RMT_REPLY;
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				}
				break;
			case RMT_SYSTEM:
				// read
				r_socket_read_block (c, buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, !LE);
				if (i>0&&i<RMT_MAX) {
					ptr = (ut8 *) malloc (i+7);
					if (!ptr) return R_FALSE;
					ptr[5]='!';
					r_socket_read_block (c, ptr+6, i);
					ptr[6+i]='\0';
					//env_update();
					//pipe_stdout_to_tmp_file((char*)&buf, (char*)ptr+5);
					strcpy ((char*)buf, "/tmp/.out");
					pipefd = r_cons_pipe_open ((const char *)buf, 1, 0);
					//eprintf("SYSTEM(%s)\n", ptr+6);
					system ((const char*)ptr+6);
					r_cons_pipe_close (pipefd);
					{
						FILE *fd = r_sandbox_fopen((char*)buf, "r");
						i = 0;
						if (fd) {
							fseek (fd, 0, SEEK_END);
							i = ftell (fd);
							fseek (fd, 0, SEEK_SET);
							free (ptr);
							ptr = NULL; // potential use after free if i == 0
							if (i>0) {
								int r;
								ptr = (ut8 *) malloc (i+6);
								if (!ptr) {
									fclose (fd);
									return R_FALSE;
								}
								r = fread (ptr+5, i, 1, fd);
								ptr[5+r]='\0';
							}
							fclose (fd);
						} else {
							eprintf ("Cannot open tmpfile\n");
							i = -1;
						}
					}
					{
					char *out = r_file_slurp ((char*)buf, &i);
					free (ptr);
					//eprintf("PIPE(%s)\n", out);
					ptr = (ut8 *) malloc (i+5);
					if (ptr) {
						memcpy (ptr+5, out, i);
					}
					free (out);
					}
					//unlink((char*)buf);
				}

				if (!ptr) ptr = (ut8 *) malloc (5); // malloc for 5 byets? c'mon!
				if (!ptr) return R_FALSE;

				// send
				ptr[0] = (RMT_SYSTEM | RMT_REPLY);
				r_mem_copyendian ((ut8*)ptr+1, (ut8*)&i, 4, !LE);
				if (i<0) i = 0;
				r_socket_write (c, ptr, i+5);
				r_socket_flush (c);
				eprintf ("REPLY SENT (%d) (%s)\n", i, ptr+5);
				free (ptr);
				ptr = NULL;
				break;
			default:
				eprintf ("unknown command 0x%02x\n", cmd);
				r_socket_close (c);
				free (ptr);
				ptr = NULL;
				return -1;
			}
		}
		r_cons_break_end ();
		eprintf ("client: disconnected\n");
	}
	return -1;
}

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf;
	if ((buf = malloc (len)) == NULL)
		eprintf ("Cannot allocate blocksize\n");
	else while (from<to) {
		ut64 delta = to-from;
		if (delta<len)
			len = (int)delta;
		if (!r_io_read_at (core->io, from, buf, len)) {
			eprintf ("Cannot read at 0x%"PFMT64x"\n", from);
			break;
		}
		for (ret=0; ret<len;) {
			int done = cb (core, from, buf+ret, len-ret);
			if (done<1) { /* interrupted */
				free (buf);
				return R_FALSE;
			}
			ret += done;
		}
		from += len;
	}
	free (buf);
	return R_TRUE;
}

R_API char *r_core_editor (const RCore *core, const char *file, const char *str) {
	const char *editor;
	char *name, *ret = NULL;
	int len, fd;
	if (file) {
		name = strdup (file);
		fd = r_sandbox_open (file, O_RDWR, 0644);
	} else {
		name = NULL;
		fd = r_file_mkstemp ("r2ed", &name);
	}
	if (fd == -1) {
		free (name);
		return NULL;
	}
	if (str) write (fd, str, strlen (str));
	close (fd);

	editor = r_config_get (core->config, "cfg.editor");
	if (!editor || !*editor || !strcmp (editor, "-")) {
		r_cons_editor (name, NULL);
	} else r_sys_cmdf ("%s '%s'", editor, name);
	ret = r_file_slurp (name, &len);
	if (ret) {
		if (len && ret[len - 1] == '\n')
			ret[len-1] = 0; // chop
		if (!file) {
			r_file_rm (name);
		}
	}
	free (name);
	return ret;
}

/* weak getters */
R_API RCons *r_core_get_cons (RCore *core) { return core->cons; }
R_API RConfig *r_core_get_config (RCore *core) { return core->config; }
R_API RBin *r_core_get_bin (RCore *core) { return core->bin; }

R_API RBuffer *r_core_syscallf (RCore *core, const char *name, const char *fmt, ...) {
	char str[1024];
	RBuffer *buf;
	va_list ap;
	va_start (ap, fmt);

	vsnprintf (str, sizeof (str), fmt, ap);
	buf = r_core_syscall (core, name, str);

	va_end (ap);
	return buf;
}

R_API RBuffer *r_core_syscall (RCore *core, const char *name, const char *args) {
	int i, num;
	RBuffer *b = NULL;
	char code[1024];

	num = r_syscall_get_num (core->anal->syscall, name);
	snprintf (code, sizeof (code),
		"ptr@syscall(%d);\n"
		"main@global(0) { ptr(%s);\n"
		":int3\n" /// XXX USE trap
		"}\n", num, args);
	r_egg_reset (core->egg);
	// TODO: setup arch/bits/os?
	r_egg_load (core->egg, code, 0);
	if (!r_egg_compile (core->egg))
		eprintf ("Cannot compile.\n");
	if (!r_egg_assemble (core->egg))
		eprintf ("r_egg_assemble: invalid assembly\n");
	if ((b = r_egg_get_bin (core->egg))) {
		if (b->length>0) {
			for (i=0; i<b->length; i++)
				r_cons_printf ("%02x", b->buf[i]);
			r_cons_printf ("\n");
		}
	}
	return b;
}
