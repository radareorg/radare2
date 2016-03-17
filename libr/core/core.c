/* radare2 - LGPL - Copyright 2009-2016 - pancake */

#include <r_core.h>
#include <r_socket.h>
#include "../config.h"
#include <r_util.h>
#if __UNIX__
#include <signal.h>
#endif

#define DB core->sdb

R_LIB_VERSION(r_core);

static ut64 letter_divs[R_CORE_ASMQJMPS_LEN_LETTERS - 1] = {
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS
};

#define TMP_ARGV_SZ 512
static const char *tmp_argv[TMP_ARGV_SZ];
static bool tmp_argv_heap = false;

static void r_core_free_autocomplete(RCore *core) {
	int i;
	RLine *line;
	if (!core || !core->cons || !core->cons->line)
		return;
	line = core->cons->line;
	if (tmp_argv_heap) {
		int argc = line->completion.argc;
		for (i = 0; i < argc; i++) {
			free ((char*)tmp_argv[i]);
			tmp_argv[i] = NULL;
		}
		tmp_argv_heap = false;
	}
	line->completion.argc = 0;
	line->completion.argv = tmp_argv;
}


static int on_fcn_new(void *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.new");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, 1);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, 1);
	}
	return 0;
}

static int on_fcn_delete (void *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.delete");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, 1);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, 1);
	}
	return 0;
}

static int on_fcn_rename(void *_anal, void* _user, RAnalFunction *fcn, const char *oname) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.rename");
	if (cmd && *cmd) {
// XXX: wat do with old name here?
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, 1);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, 1);
	}
	return 0;
}

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

/* returns the address of a jmp/call given a shortcut by the user or UT64_MAX
 * if there's no valid shortcut. When is_asmqjmps_letter is true, the string
 * should be of the form XYZWu, where XYZW are uppercase letters and u is a
 * lowercase one. If is_asmqjmps_letter is false, the string should be a number
 * between 1 and 9 included. */
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str) {
	if (!core->asmqjmps) return UT64_MAX;

	if (core->is_asmqjmps_letter) {
		int i, pos = 0;
		int len = strlen (str);

		for (i = 0; i < len - 1; ++i) {
			if (!isupper ((ut8)str[i])) return UT64_MAX;
			pos *= R_CORE_ASMQJMPS_LETTERS;
			pos += str[i] - 'A' + 1;
		}
		if (!islower ((ut8)str[i])) return UT64_MAX;
		pos *= R_CORE_ASMQJMPS_LETTERS;
		pos += str[i] - 'a';
		if (pos < core->asmqjmps_count) return core->asmqjmps[pos + 1];
	} else if (str[0] > '0' && str[1] <= '9') {
		int pos = str[0] - '0';
		if (pos <= core->asmqjmps_count) return core->asmqjmps[pos];
	}
	return UT64_MAX;
}

/* returns in str a string that represents the shortcut to access the asmqjmp
 * at position pos. When is_asmqjmps_letter is true, pos is converted into a
 * multiletter shortcut of the form XYWZu and returned (see r_core_get_asmqjmps
 * for more info). Otherwise, the shortcut is the string representation of pos. */
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int pos) {
	if (core->is_asmqjmps_letter) {
		int i, j = 0;

		pos -= 1;
		for (i = 0; i < R_CORE_ASMQJMPS_LEN_LETTERS - 1; ++i) {
			ut64 div = pos / letter_divs[i];
			pos %= letter_divs[i];
			if (div != 0 && j < len) {
				str[j++] = 'A' + div - 1;
			}
		}
		if (j < len) {
			ut64 div = pos % R_CORE_ASMQJMPS_LETTERS;
			str[j++] = 'a' + div;
		}
		str[j] = '\0';
	} else {
		snprintf (str, len, "%d", pos);
	}
}

R_API int r_core_bind(RCore *core, RCoreBind *bnd) {
	bnd->core = core;
	bnd->bphit = (RCoreDebugBpHit)r_core_debug_breakpoint_hit;
	bnd->cmd = (RCoreCmd)r_core_cmd0;
	bnd->cmdstr = (RCoreCmdStr)r_core_cmd_str;
	bnd->puts = (RCorePuts)r_cons_strcat;
	return true;
}

R_API RCore *r_core_ncast(ut64 p) {
	return (RCore*)(size_t)p;
}

R_API RCore *r_core_cast(void *p) {
	return (RCore*)p;
}

static int core_cmd_callback (void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	return r_core_cmd0 (core, cmd);
}

static char *core_cmdstr_callback (void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	return r_core_cmd_str (core, cmd);
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
	char *ptr, *bptr, *out;
	RFlagItem *flag;
	RIOSection *s;
	RAnalOp op;
	ut64 ret = 0;

	if (ok) *ok = false;
	switch (*str) {
	case '[':
{
		ut64 n = 0LL;
		int refsz = core->assembler->bits / 8;
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
			if (str[0] && str[1]) {
				const char *q;
				char *o = strdup (str+1);
				if (o) {
					q = r_num_calc_index (core->num, NULL);
					if (q) {
						if (r_str_replace_char (o, ']', 0)>0) {
							n = r_num_math (core->num, o);
							r_num_calc_index (core->num, q);
						}
					}
					free (o);
				}
			}
		}
		// pop state
		if (ok) *ok = 1;
		ut64 num = 0;
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
}
		break;
	case '$':
		if (ok) *ok = 1;
		// TODO: group analop-dependant vars after a char, so i can filter
		r_anal_op (core->anal, &op, core->offset,
			core->block, core->blocksize);
		switch (str[1]) {
		case '.': // can use pc, sp, a0, a1, ...
			return r_debug_reg_get (core->dbg, str+2);
		case 'k':
			if (str[2]!='{') {
				eprintf ("Expected '{' after 'k'.\n");
				break;
			}
			bptr = strdup (str+3);
			ptr = strchr (bptr, '}');
			if (ptr == NULL) {
				// invalid json
				free (bptr);
				break;
			}
			*ptr = '\0';
			ret = 0LL;
			out = sdb_querys (core->sdb, NULL, 0, bptr);
			if (out && *out) {
				if (strstr (out, "$k{")) {
					eprintf ("Recursivity is not permitted here\n");
				} else {
					ret = r_num_math (core->num, out);
				}
			}
			free (bptr);
			free (out);
			return ret;
			break;
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
		case 'P': return (core->dbg->pid>0)? core->dbg->pid: 0;
		case 'f': return op.fail;
		case 'm': return op.ptr; // memref
		case 'v': return op.val; // immediate value
		case 'l': return op.size;
		case 'b': return core->blocksize;
		case 's':
			if (core->file) {
				return r_io_desc_size (core->io, core->file->desc);
			}
			return 0LL;
		case 'w': return r_config_get_i (core->config, "asm.bits") / 8;
		case 'S':
			s = r_io_section_vget (core->io, core->offset);
			return s? (str[2]=='S'? s->size: s->vaddr): 3;
		case '?': return core->num->value;
		case '$': return core->offset;
		case 'o': return r_io_section_vaddr_to_maddr_try (core->io,
				core->offset);
		case 'C': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_CALL);
		case 'J': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_CODE);
		case 'D': return getref (core, atoi (str+2), 'r',
				R_ANAL_REF_TYPE_DATA);
		case 'X': return getref (core, atoi (str+2), 'x',
				R_ANAL_REF_TYPE_CALL);
		case 'B':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			return fcn? fcn->addr: 0;
		case 'I':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			return fcn? fcn->ninstr: 0;
		case 'F':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			return fcn? fcn->size: 0;
		}
		break;
	default:
		if (*str>'A') {
			// NOTE: functions override flags
			RAnalFunction *fcn = r_anal_fcn_find_name (core->anal, str);
			if (fcn) {
				if (ok) *ok = true;
				return fcn->addr;
			}
#if 0
			ut64 addr = r_anal_fcn_label_get (core->anal, core->offset, str);
			if (addr != 0) {
				ret = addr;
			} else {
				...
			}
#endif
			if ((flag = r_flag_get (core->flags, str))) {
				ret = flag->offset;
				if (ok) *ok = true;
			}
		}
		break;
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
	"?", "?v", "whereis", "which", "ls", "rm", "mkdir", "pwd", "cat", "less",
	"dH", "ds", "dso", "dsl", "dc", "dd", "dm", "db ", "db-",
        "dp", "dr", "dcu", "dmd", "dmp", "dml",
	"ec","ecs",
	"S", "S.", "S*", "S-", "S=", "Sa", "Sa-", "Sd", "Sl", "SSj", "Sr",
	"s", "s+", "s++", "s-", "s--", "s*", "sa", "sb", "sr",
	"!", "!!",
	"#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5",
	"#!python", "#!perl", "#!vala",
	"V",
	"aa", "ab", "af", "ar", "ag", "at", "a?", "ax", "ad",
	"af", "afa", "afan", "afc", "afi", "afb", "afbb", "afn", "afr", "afs", "af*", "afv", "afvn",
	"aga", "agc", "agd", "agl", "agfl",
	"e", "et", "e-", "e*", "e!", "e?", "env ",
	"i", "ii", "iI", "is", "iS", "iz",
	"q", "q!",
	"f", "fl", "fr", "f-", "f*", "fs", "fS", "fr", "fo", "f?",
	"m", "m*", "ml", "m-", "my", "mg", "md", "mp", "m?",
	"o", "o+", "oc", "on", "op", "o-", "x", "wf", "wF", "wt", "wp",
	"t", "to ", "t-", "tf", "td", "td-", "tb", "te", "tl", "tk", "ts",
	"(", "(*", "(-", "()", ".", ".!", ".(", "./",
	"r", "r+", "r-",
	"b", "bf", "b?",
	"/", "//", "/a", "/c", "/m", "/x", "/v", "/v2", "/v4", "/v8", "/r"
	"y", "yy", "y?",
	"wx", "ww", "w?",
	"p6d", "p6e", "p8", "pb", "pc",
	"pd", "pda", "pdb", "pdc", "pdj", "pdr", "pdf", "pdi", "pdl", "pds", "pdt",
	"pD", "px", "pX", "po", "pf", "pf.", "pf*", "pf*.", "pfd", "pfd.", "pv", "p=", "p-",
	"pfj", "pfj.", "pfv", "pfv.",
	"pm", "pr", "pt", "ptd", "ptn", "pt?", "ps", "pz", "pu", "pU", "p?",
	"#!pipe", "z", "zf", "zF", "zFd", "zh", "zn", "zn-",
	NULL
};

static int getsdelta(const char *data) {
	int i;
	for (i=1; data[i]; i++) {
		if (data[i] == ' ')
			return i + 1;
	}
	return 0;
}

static int autocomplete(RLine *line) {
	int pfree = 0;
	RCore *core = line->user;
	RListIter *iter;
	RFlagItem *flag;
	if (core) {
		r_core_free_autocomplete (core);
		char *ptr = strchr (line->buffer.data, '@');
		if (ptr && line->buffer.data+line->buffer.index >= ptr) {
			int sdelta, n, i = 0;
			ptr = (char *)r_str_chop_ro (ptr+1);
			n = strlen (ptr);//(line->buffer.data+sdelta);
			sdelta = (int)(size_t)(ptr - line->buffer.data);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!strncmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i == TMP_ARGV_SZ-1)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "#!pipe ", 7)) {
			int j = 0;
			if (strchr (line->buffer.data + 7, ' ')) {
				goto openfile;
			}
			tmp_argv_heap = false;
#define ADDARG(x) if (!strncmp (line->buffer.data+7, x, strlen (line->buffer.data+7))) { tmp_argv[j++] = x; }
			ADDARG("node");
			ADDARG("vala");
			ADDARG("ruby");
			ADDARG("newlisp");
			ADDARG("perl");
			ADDARG("python");
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "pf.", 3))
		||  (!strncmp (line->buffer.data, "pf*.", 4))
		||  (!strncmp (line->buffer.data, "pfd.", 4))
		||  (!strncmp (line->buffer.data, "pfv.", 4))
		||  (!strncmp (line->buffer.data, "pfj.", 4))) {
			char pfx[2];
			int chr = (line->buffer.data[2]=='.')? 3: 4;
			if (chr == 4) {
				pfx[0] = line->buffer.data[2];
				pfx[1] = 0;
			} else {
				*pfx = 0;
			}
			RStrHT *sht = core->print->formats;
			int *i, j = 0;
			r_list_foreach (sht->ls, iter, i) {
				int idx = ((int)(size_t)i)-1;
				const char *key = r_strpool_get (sht->sp, idx);
				int len = strlen (line->buffer.data + chr);
				if (!len || !strncmp (line->buffer.data + chr, key, len)) {
					tmp_argv[j++] = r_str_newf ("pf%s.%s", pfx, key);
				}
			}
			if (j > 0) tmp_argv_heap = true;
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "afvn ", 5))) {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			RList *vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_VAR);
			const char *f_ptr, *l_ptr;
			RAnalVar *var;
			int j = 0, len = strlen (line->buffer.data);

			f_ptr = r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, ' ');
			f_ptr = f_ptr != NULL ? f_ptr + 1 : line->buffer.data;
			l_ptr = r_sub_str_rchr (line->buffer.data, line->buffer.index, len, ' ');
			if (l_ptr == NULL) {
				l_ptr = line->buffer.data + strlen (line->buffer.data);
			}

			r_list_foreach (vars, iter, var) {
				if (!strncmp (f_ptr, var->name, l_ptr - f_ptr)) {
					tmp_argv[j++] = strdup(var->name);
				}
			}
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "te ", 3))) {
			int i = 0;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types);
			SdbListIter *iter;
			SdbKv *kv;
			int chr = 3;
			ls_foreach (l, iter, kv) {
				int len = strlen (line->buffer.data + chr);
				if (!len || !strncmp (line->buffer.data + chr, kv->key, len)) {
					if (!strncmp (kv->value, "0x", 2)) {
						tmp_argv[i++] = strdup (kv->key);
					}
				}
			}
			if (i > 0) tmp_argv_heap = true;
			tmp_argv[i] = NULL;
			ls_free (l);
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "o ", 2)) ||
		     !strncmp (line->buffer.data, "o+ ", 3) ||
		     !strncmp (line->buffer.data, "oc ", 3) ||
		     !strncmp (line->buffer.data, "r2 ", 3) ||
		     !strncmp (line->buffer.data, "cd ", 3) ||
		     !strncmp (line->buffer.data, "zF ", 3) ||
		     !strncmp (line->buffer.data, "on ", 3) ||
		     !strncmp (line->buffer.data, "op ", 3) ||
		     !strncmp (line->buffer.data, ". ", 2) ||
		     !strncmp (line->buffer.data, "wf ", 3) ||
		     !strncmp (line->buffer.data, "rm ", 3) ||
		     !strncmp (line->buffer.data, "ls ", 3) ||
		     !strncmp (line->buffer.data, "ls -l ", 5) ||
		     !strncmp (line->buffer.data, "wF ", 3) ||
		     !strncmp (line->buffer.data, "cat ", 4) ||
		     !strncmp (line->buffer.data, "less ", 5) ||
		     !strncmp (line->buffer.data, "wt ", 3) ||
		     !strncmp (line->buffer.data, "wp ", 3) ||
		     !strncmp (line->buffer.data, "Sd ", 3) ||
		     !strncmp (line->buffer.data, "Sl ", 3) ||
		     !strncmp (line->buffer.data, "to ", 3) ||
		     !strncmp (line->buffer.data, "pm ", 3) ||
		     !strncmp (line->buffer.data, "dml ", 4) ||
		     !strncmp (line->buffer.data, "/m ", 3)) {
			// XXX: SO MANY FUCKING MEMORY LEAKS
			char *str, *p, *path;
			int n = 0, i = 0, isroot = 0, iscwd = 0;
			RList *list;
			int sdelta;
openfile:
			if (!strncmp (line->buffer.data, "#!pipe ", 7)) {
				sdelta = getsdelta (line->buffer.data + 7) + 7;
			} else {
				sdelta = getsdelta (line->buffer.data);
			}
			path = sdelta > 0 ? strdup (line->buffer.data + sdelta):
				r_sys_getdir ();
			p = (char *)r_str_lchr (path, '/');
			if (p) {
				if (p == path) { // ^/
					isroot = 1;
					*p = 0;
					p++;
				} else if (p==path + 1) { // ^./
					*p = 0;
					iscwd = 1;
					p++;
				} else { // *
					*p = 0;
					p++;
				}
			} else {
				iscwd = 1;
				pfree = 1;
				p = strdup (path);
				free (path);
				path = strdup (".");
			}
			if (pfree) {
				if (p) {
					if (*p) {
						n = strlen (p);
					} else {
						free (p);
						p = strdup ("");
					}
				}
			} else {
				if (p) { if (*p) n = strlen (p); else p = ""; }
			}
			if (iscwd) {
				list = r_sys_dir ("./");
			} else if (isroot) {
				const char *lastslash = r_str_lchr (path, '/');
				if (lastslash && lastslash[1]) {
					list = r_sys_dir (path);
				} else {
					list = r_sys_dir ("/");
				}
			} else {
				if (*path=='~') { // if implicit home
					char *lala = r_str_home (path + 1);
					free (path);
					path = lala;
				} else if (*path!='.' && *path!='/') { // ifnot@home
					char *o = malloc (strlen (path) + 4);
					memcpy (o, "./", 2);
					p = o+2;
					n = strlen (path);
					memcpy (o + 2, path, strlen (path) + 1);
					free (path);
					path = o;
				}
				list = p? r_sys_dir (path): NULL;
			}
			i = 0;
			if (list) {
			//	bool isroot = !strcmp (path, "/");
				r_list_foreach (list, iter, str) {
					if (*str == '.') // also list hidden files
						continue;
					if (!p || !*p || !strncmp (str, p, n)) {
						tmp_argv[i++] = r_str_newf ("%s/%s", path, str);
						if (i == TMP_ARGV_SZ) {
							i--;
							break;
						}
					}
				}
				r_list_purge (list);
				free (list);
			} else {
				eprintf ("\nInvalid directory (%s)\n", path);
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
			free (path);
			if (pfree)
				free (p);
		} else if ((!strncmp (line->buffer.data, ".(", 2))  ||
		   (!strncmp (line->buffer.data, "(-", 2))) {
			const char *str = line->buffer.data;
			RCmdMacroItem *item;
			char buf[1024];
			int n, i = 0;

			n = line->buffer.length-2;
			if (str && !strchr (str+2, ' ')) {
				str += 2;
				r_list_foreach (core->rcmd->macro.macros, iter, item) {
					char *p = item->name;
					if (!str || !*str || !strncmp (str, p, n)) {
						snprintf (buf, sizeof (buf), "%c%c%s)",
							line->buffer.data[0],
							line->buffer.data[1],
							p);
						// eprintf ("------ %p (%s) = %s\n", tmp_argv[i], buf, p);
						if (r_is_heap ((void*)tmp_argv[i]))
							free ((char *)tmp_argv[i]);
						tmp_argv[i] = strdup (buf); // LEAKS
						i++;
						if (i == TMP_ARGV_SZ)
							break;
					}
				}
			}
			//tmp_argv[(i-1>0)?i-1:0] = NULL;
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "fs ", 3)) {
			const char *msg = line->buffer.data + 3;
			RFlag *flag = core->flags;
			int j, i = 0;
			for (j=0; j<R_FLAG_SPACES_MAX-1; j++) {
				if (flag->spaces[j] && flag->spaces[j][0]) {
					if (i==TMP_ARGV_SZ)
						break;
					if (!strncmp (msg, flag->spaces[j], strlen (msg))) {
						tmp_argv[i++] = flag->spaces[j];
					}
				}
			}
			if (flag->spaces[j] && !strncmp (msg, flag->spaces[j],
							strlen (msg))) {
				tmp_argv[i++] = "*";
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "s ", 2)) ||
		    (!strncmp (line->buffer.data, "ad ", 3)) ||
		    (!strncmp (line->buffer.data, "bf ", 3)) ||
		    (!strncmp (line->buffer.data, "ag ", 3)) ||
		    (!strncmp (line->buffer.data, "afi ", 4)) ||
		    (!strncmp (line->buffer.data, "afb ", 4)) ||
		    (!strncmp (line->buffer.data, "afc ", 4)) ||
		    (!strncmp (line->buffer.data, "axt ", 4)) ||
		    (!strncmp (line->buffer.data, "axf ", 4)) ||
		    (!strncmp (line->buffer.data, "aga ", 5)) ||
		    (!strncmp (line->buffer.data, "agc ", 4)) ||
		    (!strncmp (line->buffer.data, "agl ", 4)) ||
		    (!strncmp (line->buffer.data, "agd ", 4)) ||
		    (!strncmp (line->buffer.data, "agfl ", 5)) ||
		    (!strncmp (line->buffer.data, "b ", 2)) ||
		    (!strncmp (line->buffer.data, "dcu ", 4)) ||
		    (!strncmp (line->buffer.data, "/v ", 3)) ||
		    (!strncmp (line->buffer.data, "db ", 3)) ||
		    (!strncmp (line->buffer.data, "db- ", 4)) ||
		    (!strncmp (line->buffer.data, "f ", 2)) ||
		    (!strncmp (line->buffer.data, "f- ", 3)) ||
		    (!strncmp (line->buffer.data, "fr ", 3)) ||
		    (!strncmp (line->buffer.data, "tf ", 3)) ||
		    (!strncmp (line->buffer.data, "/a ", 3)) ||
		    (!strncmp (line->buffer.data, "?v ", 3)) ||
		    (!strncmp (line->buffer.data, "? ", 2))) {
			int n, i = 0;
			int sdelta = (line->buffer.data[1]==' ')?2:
				(line->buffer.data[2]==' ')?3:4;
			n = strlen (line->buffer.data+sdelta);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!strncmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i>255?255:i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "-", 1)) {
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
		} else if ( (!strncmp (line->buffer.data, "e ", 2))
		   || (!strncmp (line->buffer.data, "et ", 3))
		   || (!strncmp (line->buffer.data, "e? ", 3))
		   || (!strncmp (line->buffer.data, "e! ", 3))) {
			const char p = line->buffer.data[1];
			int m = (p == '?' || p == '!') ? 3 : 2;
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
			tmp_argv[R_MIN(i, TMP_ARGV_SZ - 1)] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else {
			int i, j;
			for (i = j = 0; i < CMDS && radare_argv[i]; i++)
				if (!strncmp (radare_argv[i], line->buffer.data,
						line->buffer.index))
					tmp_argv[j++] = radare_argv[i];
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		}
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
	return true;
}

R_API int r_core_fgets(char *buf, int len) {
	const char *ptr;
	RLine *rli = r_line_singleton ();
	buf[0] = '\0';
	rli->completion.argc = CMDS;
	rli->completion.argv = radare_argv;
	rli->completion.run = autocomplete;
	ptr = r_line_readline ();
	if (ptr == NULL)
		return -1;
	strncpy (buf, ptr, len);
	buf[len-1] = 0;
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
	Sdb *d;
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
	d = sdb_ns (DB, "debug", 1);
	core->dbg->sgnls->refs++;
	sdb_ns_set (d, "signals", core->dbg->sgnls);
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
	const char *isenum, *q, *res;
	RCore *core = (RCore*)_core;
	char *ret = NULL;
	int i;

	isenum = sdb_const_get (core->anal->sdb_types, name, 0);
	if (isenum && !strcmp (isenum, "enum")) {
		int isFirst = true;
		ret = r_str_concatf (ret, "0x%08"PFMT64x" : ", val);
		for (i=0; i < 32; i++) {
			if (!(val & (1<<i)))
				continue;
			q = sdb_fmt (0, "%s.0x%x", name, (1<<i));
			res = sdb_const_get (core->anal->sdb_types, q, 0);
			if (isFirst) {
				isFirst = false;
			} else {
				ret = r_str_concat (ret, " | ");
			}
			if (res) {
				ret = r_str_concat (ret, res);
			} else {
				ret = r_str_concatf (ret, "0x%x", (1<<i));
			}
		}
	} else {
		eprintf ("This is not an enum\n");
	}
	return ret;
}

#define MINLEN 1
static int is_string (const ut8 *buf, int size, int *len) {
	int i;
	if (size < 1) return 0;
	if (size > 3 && buf[0] && !buf[1] && buf[2] && !buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i = 0; i < size; i++) {
		if (!buf[i] && i > MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i] == 10|| buf[i] == 13|| buf[i] == 9) {
			continue;
		}
		if (buf[i] < 32 || buf[i] > 127) {
			// not ascii text
			return 0;
		}
		if (!IS_PRINTABLE (buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

static char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, int depth);
R_API char *r_core_anal_hasrefs(RCore *core, ut64 value) {
	return r_core_anal_hasrefs_to_depth(core, value, r_config_get_i(core->config, "hex.depth"));
}

static char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, int depth) {
	RStrBuf *s = r_strbuf_new (NULL);
	ut64 type;
	RIOSection *sect;
	char *mapname;
	RAnalFunction *fcn;
	RFlagItem *fi;
	fi = r_flag_get_i (core->flags, value);
	type = r_core_anal_address (core, value);
	fcn = r_anal_get_fcn_in (core->anal, value, 0);
	if (value && value != UT64_MAX) {
		RDebugMap *map = r_debug_map_get (core->dbg, value);
		if (map && map->name && map->name[0]) {
			mapname = strdup (map->name);
		} else {
			mapname = NULL;
		}
	} else {
		mapname = NULL;
	}
	sect = value? r_io_section_vget (core->io, value): NULL;
	if(! ((type&R_ANAL_ADDR_TYPE_HEAP)||(type&R_ANAL_ADDR_TYPE_STACK)) ) {
		// Do not repeat "stack" or "heap" words unnecessarily.
		if (sect && sect->name[0]) {
			r_strbuf_appendf (s," (%s)", sect->name);
		}
		if (mapname) {
			r_strbuf_appendf (s, " (%s)", mapname);
			free (mapname);
		}
	}
	if (fi) r_strbuf_appendf (s, " %s", fi->name);
	if (fcn) r_strbuf_appendf (s, " %s", fcn->name);
	if (type) {
		const char *c = r_core_anal_optype_colorfor (core, value);
		const char *cend = (c && *c) ? Color_RESET: "";
		if (!c) c = "";
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			r_strbuf_appendf (s, " %sheap%s", c, cend);
		} else if (type & R_ANAL_ADDR_TYPE_STACK) {
			r_strbuf_appendf (s, " %sstack%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_strbuf_appendf (s, " %sprogram%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_strbuf_appendf (s, " %slibrary%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_strbuf_appendf (s, " %sascii%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_strbuf_appendf (s, " %ssequence%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_strbuf_appendf (s, " %sR%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_strbuf_appendf (s, " %sW%s", c, cend);
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			RAsmOp op;
			ut8 buf[32];
			r_strbuf_appendf (s, " %sX%s", c, cend);
			/* instruction disassembly */
			r_io_read_at (core->io, value, buf, sizeof (buf));
			r_asm_set_pc (core->assembler, value);
			r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
			r_strbuf_appendf (s, " '%s'", op.buf_asm);
			/* get library name */
			{ // NOTE: dup for mapname?
				RDebugMap *map;
				RListIter *iter;
				r_list_foreach (core->dbg->maps, iter, map) {
					if ((value >= map->addr) &&
						(value<map->addr_end)) {
						const char *lastslash = r_str_lchr (map->name, '/');
						r_strbuf_appendf (s, " '%s'", lastslash?
							lastslash+1:map->name);
						break;
					}
				}
			}
		} else if (type & R_ANAL_ADDR_TYPE_READ) {
			ut8 buf[32];
			ut32 *n32 = (ut32 *)buf;
			ut64 *n64 = (ut64*)buf;
			r_io_read_at (core->io, value, buf, sizeof (buf));
			ut64 n = (core->assembler->bits == 64)? *n64: *n32;
			r_strbuf_appendf (s, " 0x%"PFMT64x, n);
		}
	}
	{
		ut8 buf[128], widebuf[256];
		const char *c = core->cons->pal.ai_ascii;
		const char *cend = Color_RESET;
		int len, r;
		r = r_io_read_at (core->io, value, buf, sizeof(buf));
		if (r) {
			switch (is_string (buf, sizeof(buf), &len)) {
			case 1:
				r_strbuf_appendf (s, " (%s%s%s)", c, buf, cend);
				break;
			case 2:
				r = r_utf8_encode_str ((const RRune *)buf, widebuf,
							sizeof(widebuf) - 1);
				if (r == -1) {
					eprintf ("Something was wrong %s-%d\n",
						__FILE__, __LINE__);
				} else {
					r_strbuf_appendf (s, " (%s%s%s)", c, widebuf, cend);
				}
				break;
			}
		}

	}
	if ((type & R_ANAL_ADDR_TYPE_READ) && !(type & R_ANAL_ADDR_TYPE_EXEC) && depth) {
		// Try to telescope further, but only several levels deep.
		ut8 buf[32];
		ut32 *n32 = (ut32 *)buf;
		ut64 *n64 = (ut64*)buf;
		r_io_read_at (core->io, value, buf, sizeof (buf));
		ut64 n = (core->assembler->bits == 64)? *n64: *n32;
		if(n != value) {
			char* rrstr = r_core_anal_hasrefs_to_depth (core, n, depth-1);
			if(rrstr) {
				if(rrstr[0]) {
					r_strbuf_appendf (s, " -->%s", rrstr);
				}
				free(rrstr);
			}
		}
	}
	return r_strbuf_drain (s);
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

static void r_core_setenv (RCore *core) {
	char *e = r_sys_getenv ("PATH");
	char *h = r_str_home (".config/radare2/bin");
	char *n = r_str_newf ("%s:%s", h, e);
	r_sys_setenv ("PATH", n);
	free (n);
	free (h);
	free (e);
}

R_API int r_core_init(RCore *core) {
	r_core_setenv(core);
	core->cmd_depth = R_CORE_CMD_DEPTH+1;
	core->sdb = sdb_new (NULL, "r2kv.sdb", 0); // XXX: path must be in home?
	core->lastsearch = NULL;
	core->incomment = false;
	core->screen_bounds = 0LL;
	core->config = NULL;
	core->http_up = false;
	core->print = r_print_new ();
	core->print->user = core;
	core->print->get_enumname = getenumname;
	core->print->get_bitfield = getbitfield;
	core->print->offname = r_core_print_offname;
	core->print->cb_printf = (void *)r_cons_printf;
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
	core->times = R_NEW0 (RCoreTimes);
	core->vmode = false;
	core->section = NULL;
	core->oobi = NULL;
	core->oobi_len = 0;
	core->printidx = 0;
	core->lastcmd = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = true;
	core->yank_buf = r_buf_new();
	core->num = r_num_new (&num_callback, core);
	//core->num->callback = &num_callback;
	//core->num->userptr = core;
	core->curasmstep = 0;
	core->egg = r_egg_new ();
	r_egg_setup (core->egg, R_SYS_ARCH, R_SYS_BITS, 0, R_SYS_OS);

	/* initialize libraries */
	core->cons = r_cons_new ();
	if (core->cons->refcnt == 1) {
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
	}
	core->print->cons = core->cons;
	core->cons->num = core->num;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8*)malloc (R_CORE_BLOCKSIZE+1);
	if (core->block == NULL) {
		eprintf ("Cannot allocate %d bytes\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return false;
	}
	core->lang = r_lang_new ();
	core->lang->cmd_str = (char *(*)(void *, const char *))r_core_cmd_str;
	core->cons->editor = (RConsEditorCallback)r_core_editor;
	core->cons->user = (void*)core;
	core->lang->cb_printf = r_cons_printf;
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->assembler = r_asm_new ();
	core->assembler->num = core->num;
	r_asm_set_user_ptr (core->assembler, core);
	core->anal = r_anal_new ();

	/* default noreturn functions */
	/* osx */
	r_anal_noreturn_add (core->anal, "sym.imp.__assert_rtn", UT64_MAX);
	r_anal_noreturn_add (core->anal, "sym.imp.exit", UT64_MAX);
	r_anal_noreturn_add (core->anal, "sym.imp._exit", UT64_MAX);
	r_anal_noreturn_add (core->anal, "sym.imp.__stack_chk_fail", UT64_MAX);
	/* linux */
	r_anal_noreturn_add (core->anal, "sym.__assert_fail", UT64_MAX);
	r_anal_noreturn_add (core->anal, "sym.abort", UT64_MAX);
	r_anal_noreturn_add (core->anal, "sym.exit", UT64_MAX);

	core->anal->meta_spaces.cb_printf = r_cons_printf;
	core->anal->cb.on_fcn_new = on_fcn_new;
	core->anal->cb.on_fcn_delete = on_fcn_delete;
	core->anal->cb.on_fcn_rename = on_fcn_rename;
	core->assembler->syscall = \
		core->anal->syscall; // BIND syscall anal/asm
	r_anal_set_user_ptr (core->anal, core);
	core->anal->cb_printf = (void *) r_cons_printf;
	core->parser = r_parse_new ();
	core->parser->anal = core->anal;
	core->parser->varlist = r_anal_var_list;
	r_parse_set_user_ptr (core->parser, core);
	core->bin = r_bin_new ();
	core->bin->cb_printf = (PrintfCallback) r_cons_printf;
	r_bin_set_user_ptr (core->bin, core);
	core->io = r_io_new ();
	core->io->ff = 1;
	core->io->user = (void *)core;
	core->io->cb_core_cmd = core_cmd_callback;
	core->io->cb_core_cmdstr = core_cmdstr_callback;
	core->sign = r_sign_new ();
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	core->flags = r_flag_new ();
	core->graph = r_agraph_new (r_cons_canvas_new (1, 1));
	core->graph->need_reload_nodes = false;
	core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
	if (sizeof(ut64) * core->asmqjmps_size < core->asmqjmps_size) {
		core->asmqjmps_size = 0;
		core->asmqjmps = NULL;
	} else {
		core->asmqjmps = R_NEWS (ut64, core->asmqjmps_size);
	}

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
	core->dbg = r_debug_new (true);
	r_core_bind (core, &core->dbg->corebind);
	core->dbg->cb_printf = (PrintfCallback)r_cons_printf;
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	//r_debug_use (core->dbg, "native");
// XXX pushing unititialized regstate results in trashed reg values
//	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->sign->cb_printf = r_cons_printf;
	core->io->cb_printf = r_cons_printf;
	core->dbg->cb_printf = r_cons_printf;
	core->dbg->bp->cb_printf = r_cons_printf;
	r_debug_io_bind (core->dbg, core->io);

	r_core_config_init (core);

	r_core_loadlibs_init (core);
	//r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (core->assembler, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64)
		r_config_set_i (core->config, "asm.bits", 64);
	else
	if (R_SYS_BITS & R_SYS_BITS_32)
		r_config_set_i (core->config, "asm.bits", 32);
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH, core->anal->bits);
	update_sdb (core);
	return 0;
}

R_API RCore *r_core_fini(RCore *c) {
	if (!c) return NULL;
	/* TODO: it leaks as shit */
	//update_sdb (c);
	// avoid double free
	r_core_free_autocomplete(c);
	R_FREE (c->lastsearch);
	c->cons->pager = NULL;
	r_core_task_join (c, NULL);
	free (c->cmdqueue);
	free (c->lastcmd);
	free (c->block);
	r_io_free (c->io);
	r_num_free (c->num);
	// TODO: sync or not? sdb_sync (c->sdb);
	// TODO: sync all dbs?
	//r_core_file_free (c->file);
	//c->file = NULL;
	r_list_free (c->files);
	r_list_free (c->watchers);
	r_list_free (c->scriptstack);
	r_list_free (c->tasks);
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
	r_agraph_free (c->graph);
	R_FREE (c->asmqjmps);
	sdb_free (c->sdb);
	return NULL;
}

R_API RCore *r_core_free(RCore *c) {
	if (c) {
		r_core_fini (c);
		free (c);
	}
	return NULL;
}

R_API void r_core_prompt_loop(RCore *r) {
	int ret;
	do {
		if (r_core_prompt (r, false)<1)
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

static int prompt_flag (RCore *r, char *s, size_t maxlen) {
	const char DOTS[] = "...";
	const RFlagItem *f = r_flag_get_at (r->flags, r->offset);
	if (!f) return false;

	if (f->offset < r->offset) {
		snprintf (s, maxlen, "%s + %" PFMT64u, f->name,
			r->offset - f->offset);
	} else {
		snprintf (s, maxlen, "%s", f->name);
	}
	if (strlen (s) > maxlen - sizeof (DOTS)) {
		s[maxlen - sizeof (DOTS) - 1] = '\0';
		strcat (s, DOTS);
	}
	return true;
}

static void prompt_sec(RCore *r, char *s, size_t maxlen) {
	const RIOSection *sec = r_io_section_vget (r->io, r->offset);
	if (!sec) return;

	snprintf (s, maxlen, "%s:", sec->name);
}

static void chop_prompt (const char *filename, char *tmp, size_t max_tmp_size) {
	size_t tmp_len, file_len;
	unsigned int OTHRSCH = 3;
	const char DOTS[] = "...";
	int w, p_len;

	w = r_cons_get_size (NULL);
	file_len = strlen (filename);
	tmp_len = strlen (tmp);
	p_len = R_MAX (0, w - 6);
	if (file_len + tmp_len + OTHRSCH >= p_len) {
		size_t dots_size = sizeof (DOTS);
		size_t chop_point = (size_t)(p_len - OTHRSCH - file_len - dots_size - 1);
		if (chop_point < (max_tmp_size - dots_size - 1)) {
			tmp[chop_point] = '\0';
			strncat (tmp, DOTS, dots_size);
		}
	}
}

static void set_prompt (RCore *r) {
	size_t max_tmp_size = 128;
	char tmp[max_tmp_size];
	char *prompt = NULL;
	char *filename = strdup ("");
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");
	const char *BEGIN = "";
	const char *END = "";
	const char *remote = "";

	// hacky fix fo rio
	r_core_block_read (r, 0);
	if (cmdprompt && *cmdprompt)
		r_core_cmd (r, cmdprompt, 0);

	if (r_config_get_i (r->config, "scr.promptfile")) {
		free (filename);
		filename = r_str_newf ("\"%s\"",
			r_file_basename (r->io->desc->name));
	}
	if (r->cmdremote) {
		char *s = r_core_cmd_str (r, "s");
		r->offset = r_num_math (NULL, s);
		free (s);
		remote = "=!";
	}
#if __UNIX__
	if (r_config_get_i (r->config, "scr.color")) {
		BEGIN = r->cons->pal.prompt;
		END = r->cons->pal.reset;
	}
#endif
	// TODO: also in visual prompt and disasm/hexdump ?
	if (r_config_get_i (r->config, "asm.segoff")) {
		ut32 a, b;

		a = ((r->offset >> 16) << 12);
		b = (r->offset & 0xffff);
		snprintf (tmp, max_tmp_size, "%04x:%04x", a, b);
	} else {
		char p[64], sec[32];
		int promptset = false;

		sec[0] = '\0';
		if (r_config_get_i (r->config, "scr.promptflag")) {
			promptset = prompt_flag (r, p, sizeof (p));
		}
		if (r_config_get_i (r->config, "scr.promptsect")) {
			prompt_sec (r, sec, sizeof (sec));
		}

		if (!promptset) {
			snprintf (p, sizeof (p), "0x%08" PFMT64x, r->offset);
		}
		snprintf (tmp, sizeof (tmp), "%s%s", sec, p);
	}

	chop_prompt (filename, tmp, max_tmp_size);
	prompt = r_str_newf ("%s%s[%s%s]>%s ", filename, BEGIN, remote,
		tmp, END);
	r_line_set_prompt (prompt ? prompt : "");

	R_FREE (filename);
	R_FREE (prompt);
}

R_API int r_core_prompt(RCore *r, int sync) {
	int ret, rnv;
	char line[4096];

	rnv = r->num->value;
	set_prompt (r);

	ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2) return R_CORE_CMD_EXIT; // ^D
	if (ret == -1) return false; // FD READ ERROR
	r->num->value = rnv;
	if (sync) {
		return r_core_prompt_exec (r);
	}
	free (r->cmdqueue);
	r->cmdqueue = strdup (line);
	return true;
}

R_API int r_core_prompt_exec(RCore *r) {
	int ret = r_core_cmd (r, r->cmdqueue, true);
	r_cons_flush ();
	if (r->cons && r->cons->line && r->cons->line->zerosep)
		r_cons_zero ();
	return ret;
}

R_API int r_core_block_size(RCore *core, int bsize) {
	ut8 *bump;
	int ret = false;
	if (bsize<0) return false;
	if (bsize == core->blocksize)
		return true;
	if (r_sandbox_enable (0)) {
		// TODO : restrict to filesize?
		if (bsize > 1024*32) {
			eprintf ("Sandbox mode restricts blocksize bigger than 32k\n");
			return false;
		}
	}
	if (bsize > core->blocksize_max) {
		eprintf ("Block size %d is too big\n", bsize);
		return false;
	}
	if (bsize<1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize>core->blocksize_max) {
		eprintf ("bsize is bigger than `bm`. dimmed to 0x%x > 0x%x\n",
			bsize, core->blocksize_max);
		bsize = core->blocksize_max;
	}
	bump = realloc (core->block, bsize+1);
	if (bump == NULL) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		ret = false;
	} else {
		ret = true;
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
		return false;
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
			/*r_socket_close (c);*/
			r_socket_free (c);
			return -1;
		}
		eprintf ("rap: client connected\n");
		for (;!core->cons->breaked;) {
			if (!r_socket_read (c, &cmd, 1)) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					/*r_socket_close (c);*/
					r_socket_free (c);
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
						if (core->file && core->file->desc) {
							pipefd = core->file->desc->fd;
						} else {
							pipefd = -1;
						}
						eprintf ("(flags: %d) len: %d filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					} else {
						pipefd = -1;
						eprintf ("Cannot open file (%s)\n", ptr);
						r_socket_close (c);
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
				} else {
					if (core->file) {
						x = r_io_desc_size (core->io, core->file->desc);
					} else {
						x = 0;
					}
				}
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
				return false;
			}
			ret += done;
		}
		from += len;
	}
	free (buf);
	return true;
}

R_API char *r_core_editor (const RCore *core, const char *file, const char *str) {
	const char *editor = r_config_get (core->config, "cfg.editor");
	char *name, *ret = NULL;
	int len, fd;

	if (!editor || !*editor) {
		return NULL;
	}

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

	if (name && (!editor || !*editor || !strcmp (editor, "-"))) {
		r_cons_editor (name, NULL);
	} else {
		if (editor && name)
			r_sys_cmdf ("%s '%s'", editor, name);
	}
	ret = name? r_file_slurp (name, &len): 0;
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
	if (!num) {
		num = atoi (name);
	}
	snprintf (code, sizeof (code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%s);\n"
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
