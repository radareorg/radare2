/* radare2 - LGPL - Copyright 2009-2018 - pancake */

#include <r_core.h>
#include <r_socket.h>
#include <config.h>
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

extern int r_is_heap (void *p);
extern bool r_core_is_project (RCore *core, const char *name);

static void r_line_free_autocomplete(RLine *line) {
	int i;
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

static void r_core_free_autocomplete(RCore *core) {
	if (!core || !core->cons || !core->cons->line) {
		return;
	}
	r_line_free_autocomplete (core->cons->line);
}

static int on_fcn_new(RAnal *_anal, void* _user, RAnalFunction *fcn) {
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

static int on_fcn_delete (RAnal *_anal, void* _user, RAnalFunction *fcn) {
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

static int on_fcn_rename(RAnal *_anal, void* _user, RAnalFunction *fcn, const char *oname) {
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
	const char *cmdbp = r_config_get (core->config, "cmd.bp");
	const bool cmdbp_exists = (cmdbp && *cmdbp);
	const bool bpcmd_exists = (bpi->data && bpi->data[0]);
	const bool may_output = (cmdbp_exists || bpcmd_exists);
	if (may_output) {
		r_cons_push ();
	}
	if (cmdbp_exists) {
		r_core_cmd0 (core, cmdbp);
	}
	if (bpcmd_exists) {
		r_core_cmd0 (core, bpi->data);
	}
	if (may_output) {
		r_cons_flush ();
		r_cons_pop ();
	}
}

static void r_core_debug_syscall_hit(RCore *core) {
	const char *cmdhit = r_config_get (core->config, "cmd.onsyscall");

	if (cmdhit && cmdhit[0] != 0) {
		r_core_cmd0 (core, cmdhit);
		r_cons_flush();
	}
}

/* returns the address of a jmp/call given a shortcut by the user or UT64_MAX
 * if there's no valid shortcut. When is_asmqjmps_letter is true, the string
 * should be of the form XYZWu, where XYZW are uppercase letters and u is a
 * lowercase one. If is_asmqjmps_letter is false, the string should be a number
 * between 1 and 9 included. */
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str) {
	if (!core->asmqjmps) {
		return UT64_MAX;
	}
	if (core->is_asmqjmps_letter) {
		int i, pos = 0;
		int len = strlen (str);
		for (i = 0; i < len - 1; ++i) {
			if (!isupper ((ut8)str[i])) {
				return UT64_MAX;
			}
			pos *= R_CORE_ASMQJMPS_LETTERS;
			pos += str[i] - 'A' + 1;
		}
		if (!islower ((ut8)str[i])) {
			return UT64_MAX;
		}
		pos *= R_CORE_ASMQJMPS_LETTERS;
		pos += str[i] - 'a';
		if (pos < core->asmqjmps_count) {
			return core->asmqjmps[pos + 1];
		}
	} else if (str[0] > '0' && str[1] <= '9') {
		int pos = str[0] - '0';
		if (pos <= core->asmqjmps_count) {
			return core->asmqjmps[pos];
		}
	}
	return UT64_MAX;
}

/**
 * Takes addr and returns already saved shortcut or a new one
 * The returned buffer needs to be freed
 */
R_API char* r_core_add_asmqjmp(RCore *core, ut64 addr) {
	bool found = false;
	if (!core->asmqjmps) {
		return NULL;
	}
	if (core->is_asmqjmps_letter) {
		if (core->asmqjmps_count >= R_CORE_ASMQJMPS_MAX_LETTERS) {
			return NULL;
		}
		if (core->asmqjmps_count >= core->asmqjmps_size - 2) {
			core->asmqjmps = realloc (core->asmqjmps, core->asmqjmps_size * 2 * sizeof (ut64));
			if (!core->asmqjmps) {
				return NULL;
			}
			core->asmqjmps_size *= 2;
		}
	}
	if (core->asmqjmps_count < core->asmqjmps_size - 1) {
		int i;
		char t[R_CORE_ASMQJMPS_LEN_LETTERS + 1] = {0};
		for (i = 0; i < core->asmqjmps_count + 1; i++) {
			if (core->asmqjmps[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found) {
			i = ++core->asmqjmps_count;
			core->asmqjmps[i] = addr;
		}
		r_core_set_asmqjmps (core, t, sizeof (t), i);
		return strdup (t);
	}
	return NULL;
}

/* returns in str a string that represents the shortcut to access the asmqjmp
 * at position pos. When is_asmqjmps_letter is true, pos is converted into a
 * multiletter shortcut of the form XYWZu and returned (see r_core_get_asmqjmps
 * for more info). Otherwise, the shortcut is the string representation of pos. */
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int pos) {
	if (core->is_asmqjmps_letter) {
		int i, j = 0;
		// if (pos > 0) {
			pos --;
		////  }
		for (i = 0; i < R_CORE_ASMQJMPS_LEN_LETTERS - 1; i++) {
			ut64 div = pos / letter_divs[i];
			pos %= letter_divs[i];
			if (div > 0 && j < len) {
				str[j] = 'A' + div - 1;
				j++;
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

static void setab(RCore *core, const char *arch, int bits) {
	if (arch) {
		r_config_set (core->config, "asm.arch", arch);
	}
	if (bits > 0) {
		r_config_set_i (core->config, "asm.bits", bits);
	}
}

static const char *getName(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_i (core->flags, addr);
	return item ? item->name : NULL;
}

static char *getNameDelta(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_at (core->flags, addr, true);
	if (item) {
		if (item->offset != addr) {
			return r_str_newf ("%s + %d", item->name, (int)(addr - item->offset));
		}
		return strdup (item->name);
	}
	return NULL;
}

static void archbits(RCore *core, ut64 addr) {
	r_anal_build_range_on_hints (core->anal);
	r_core_seek_archbits (core, addr);
}

static int cfggeti(RCore *core, const char *k) {
	return r_config_get_i (core->config, k);
}

static const char *cfgget(RCore *core, const char *k) {
	return r_config_get (core->config, k);
}

static ut64 numget(RCore *core, const char *k) {
	return r_num_math (core->num, k);
}

R_API int r_core_bind(RCore *core, RCoreBind *bnd) {
	bnd->core = core;
	bnd->bphit = (RCoreDebugBpHit)r_core_debug_breakpoint_hit;
	bnd->syshit = (RCoreDebugSyscallHit)r_core_debug_syscall_hit;
	bnd->cmd = (RCoreCmd)r_core_cmd0;
	bnd->cmdf = (RCoreCmdF)r_core_cmdf;
	bnd->cmdstr = (RCoreCmdStr)r_core_cmd_str;
	bnd->cmdstrf = (RCoreCmdStrF)r_core_cmd_strf;
	bnd->puts = (RCorePuts)r_cons_strcat;
	bnd->setab = (RCoreSetArchBits)setab;
	bnd->getName = (RCoreGetName)getName;
	bnd->getNameDelta = (RCoreGetNameDelta)getNameDelta;
	bnd->archbits = (RCoreSeekArchBits)archbits;
	bnd->cfggeti = (RCoreConfigGetI)cfggeti;
	bnd->cfgGet = (RCoreConfigGet)cfgget;
	bnd->numGet = (RCoreNumGet)numget;
	return true;
}

R_API RCore *r_core_ncast(ut64 p) {
	return (RCore*)(size_t)p;
}

R_API RCore *r_core_cast(void *p) {
	return (RCore*)p;
}

static void core_post_write_callback(void *user, ut64 maddr, ut8 *bytes, int cnt) {
	RCore *core = (RCore *)user;
	RBinSection *sec;
	ut64 vaddr;

	if (!r_config_get_i (core->config, "asm.cmt.patch")) {
		return;
	}

	char *hex_pairs = r_hex_bin2strdup (bytes, cnt);
	if (!hex_pairs) {
		eprintf ("core_post_write_callback: Cannot obtain hex pairs\n");
		return;
	}

	char *comment = r_str_newf ("patch: %d byte(s) (%s)", cnt, hex_pairs);
	free (hex_pairs);
	if (!comment) {
		eprintf ("core_post_write_callback: Cannot create comment\n");
		return;
	}

	if ((sec = r_bin_get_section_at (r_bin_cur_object (core->bin), maddr, false))) {
		vaddr = maddr + sec->vaddr - sec->paddr;
	} else {
		vaddr = maddr;
	}

	r_meta_add (core->anal, R_META_TYPE_COMMENT, vaddr, vaddr, comment);
	free (comment);
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
	int i = 0;
	if (!fcn) {
		return UT64_MAX;
	}
#if FCN_OLD
	if (t == 'r') {
		list = r_anal_fcn_get_refs (core->anal, fcn);
	} else {
		list = r_anal_fcn_get_xrefs (core->anal, fcn);
	}
	r_list_foreach (list, iter, r) {
		if (r->type == type) {
			if (i == n) {
				ut64 addr = r->addr;
				r_list_free (list);
				return addr;
			}
			i++;
		}
	}
	r_list_free (list);
#else
#warning implement getref() using sdb
#endif
	return UT64_MAX;
}

static ut64 bbInstructions(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->ninstr;
		}
	}
	return UT64_MAX;
}

static ut64 bbBegin(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->addr;
		}
	}
	return UT64_MAX;
}

static ut64 bbJump(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->jump;
		}
	}
	return UT64_MAX;
}

static ut64 bbFail(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->fail;
		}
	}
	return UT64_MAX;
}

static ut64 bbSize(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->size;
		}
	}
	return 0;
}

static const char *str_callback(RNum *user, ut64 off, int *ok) {
	RFlag *f = (RFlag*)user;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		RFlagItem *item = r_flag_get_i (f, off);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static ut64 num_callback(RNum *userptr, const char *str, int *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	RAnalFunction *fcn;
	char *ptr, *bptr, *out = NULL;
	RFlagItem *flag;
	RBinSection *s;
	RAnalOp op;
	ut64 ret = 0;

	if (ok) {
		*ok = false;
	}
	switch (*str) {
	case '.':
		if (str[1] == '.') {
			if (ok) {
				*ok = true;
			}
			return r_num_tail (core->num, core->offset, str + 2);
		} else if (core->num->nc.curr_tok == '+') {
			ut64 off = core->num->nc.number_value.n;
			if (!off) {
				off = core->offset;
			}
			RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, off, 0);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				ut64 dst = r_anal_fcn_label_get (core->anal, fcn, str + 1);
				if (dst == UT64_MAX) {
					dst = fcn->addr;
				}
				st64 delta = dst - off;
				if (delta < 0) {
					core->num->nc.curr_tok = '-';
					delta = off - dst;
				}
				return delta;
			}
		}
		break;
	case '[':
{
		ut64 n = 0LL;
		int refsz = core->assembler->bits / 8;
		const char *p = NULL;
		if (strlen (str) > 5) {
			p = strchr (str + 5, ':');
		}
		if (p) {
			refsz = atoi (str + 1);
			str = p;
		}
		// push state
		if (str[0] && str[1]) {
			const char *q;
			char *o = strdup (str + 1);
			if (o) {
				q = r_num_calc_index (core->num, NULL);
				if (q) {
					if (r_str_replace_char (o, ']', 0)>0) {
						n = r_num_math (core->num, o);
						if (core->num->nc.errors) {
							return 0;
						}
						r_num_calc_index (core->num, q);
					}
				}
				free (o);
			}
		} else {
			return 0;
		}
		// pop state
		if (ok) {
			*ok = 1;
		}
		ut8 buf[sizeof (ut64)] = R_EMPTY;
		(void)r_io_read_at (core->io, n, buf, R_MIN (sizeof (buf), refsz));
		switch (refsz) {
		case 8:
			return r_read_ble64 (buf, core->print->big_endian);
		case 4:
			return r_read_ble32 (buf, core->print->big_endian);
		case 2:
			return r_read_ble16 (buf, core->print->big_endian);
		case 1:
			return r_read_ble8 (buf);
		default:
			eprintf ("Invalid reference size: %d (%s)\n", refsz, str);
			return 0LL;
		}
}
		break;
	case '$':
		if (ok) {
			*ok = 1;
		}
		// TODO: group analop-dependant vars after a char, so i can filter
		r_anal_op (core->anal, &op, core->offset, core->block, core->blocksize, R_ANAL_OP_MASK_BASIC);
		r_anal_op_fini (&op); // we dont need strings or pointers, just values, which are not nullified in fini
		switch (str[1]) {
		case '.': // can use pc, sp, a0, a1, ...
			return r_debug_reg_get (core->dbg, str + 2);
		case 'k': // $k{kv}
			if (str[2] != '{') {
				eprintf ("Expected '{' after 'k'.\n");
				break;
			}
			bptr = strdup (str + 3);
			ptr = strchr (bptr, '}');
			if (!ptr) {
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
		case '{': // ${ev} eval var
			bptr = strdup (str + 2);
			ptr = strchr (bptr, '}');
			if (ptr) {
				ptr[0] = '\0';
				ut64 ret = r_config_get_i (core->config, bptr);
				free (bptr);
				return ret;
			}
			// take flag here
			free (bptr);
			break;
		case 'c': // $c console width
			return r_cons_get_size (NULL);
		case 'r': // $r
			if (str[2] == '{') {
				bptr = strdup (str + 3);
				ptr = strchr (bptr, '}');
				if (!ptr) {
					break;
				}
				*ptr = 0;
				if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
					RRegItem *r = r_reg_get (core->dbg->reg, bptr, -1);
					if (r) {
						return r_reg_get_value (core->dbg->reg, r);
					}
				}
				return 0; // UT64_MAX;
			} else {
				int rows;
				(void)r_cons_get_size (&rows);
				return rows;
			}
			break;
		case 'e': // $e
			if (str[2] == '{') { // $e{flag} flag off + size
				char *flagName = strdup (str + 3);
				int flagLength = strlen (flagName);
				if (flagLength > 0) {
					flagName[flagLength - 1] = 0;
				}
				RFlagItem *flag = r_flag_get (core->flags, flagName);
				free (flagName);
				if (flag) {
					return flag->offset + flag->size;
				}
				return UT64_MAX;
			}
			return r_anal_op_is_eob (&op);
		case 'j': // $j jump address
			return op.jump;
		case 'p': // $p
			return r_sys_getpid ();
		case 'P': // $P
			return core->dbg->pid > 0 ? core->dbg->pid : 0;
		case 'f': // $f jump fail address
			if (str[2] == 'l') { // $fl flag length
				RFlagItem *fi = r_flag_get_i (core->flags, core->offset);
				if (fi) {
					return fi->size;
				}
				return 0;
			}
			return op.fail;
		case 'm': // $m memref
			return op.ptr;
		case 'B': // $B base address
		case 'M': { // $M map address
				ut64 lower = UT64_MAX;
				ut64 size = 0LL;
				RIOMap *map = r_io_map_get (core->io, core->offset);
				if (map) {
					lower = r_itv_begin (map->itv);
					size = r_itv_size (map->itv);
				}

				if (str[1] == 'B') {
					/* clear lower bits of the lowest map address to define the base address */
					const int clear_bits = 16;
					lower >>= clear_bits;
					lower <<= clear_bits;
				}
				if (str[2] == 'M') {
					return size;
				}
				return (lower == UT64_MAX)? 0LL: lower;
			}
			break;
		case 'v': // $v immediate value
			return op.val;
		case 'l': // $l opcode length
			return op.size;
		case 'b': // $b
			return core->blocksize;
		case 's': // $s file size
			if (str[2] == '{') { // $s{flag} flag size
				bptr = strdup (str + 3);
				ptr = strchr (bptr, '}');
				if (!ptr) {
					// invalid json
					free (bptr);
					break;
				}
				*ptr = '\0';
				RFlagItem *flag = r_flag_get (core->flags, bptr);
				ret = flag? flag->size: 0LL; // flag 
				free (bptr);
				free (out);
				return ret;
			} else if (core->file) {
				return r_io_fd_size (core->io, core->file->fd);
			}
			return 0LL;
		case 'w': // $w word size
			return r_config_get_i (core->config, "asm.bits") / 8;
		case 'S': // $S section offset
			if ((s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->offset, true))) {
				return (str[2] == 'S'? s->size: s->vaddr);
			}
			return 0LL;
		case 'D': // $D
			if (IS_DIGIT (str[2])) {
				return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_DATA);
			} else {
				RDebugMap *map;
				RListIter *iter;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (core->offset >= map->addr && core->offset < map->addr_end) {
						return (str[2] == 'D')? map->size: map->addr;
					}
				}
			}
			return 0LL; // maybe // return UT64_MAX;
		case '?': // $?
			return core->num->value;
		case '$': // $$ offset
			return str[2] == '$' ? core->prompt_offset : core->offset;
		case 'o': { // $o
			RBinSection *s;
			s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->offset, true);
			return s ? core->offset - s->vaddr + s->paddr : core->offset;
			break;
		}
		case 'C': // $C nth call
			return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_CALL);
		case 'J': // $J nth jump
			return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_CODE);
		case 'X': // $X nth xref
			return getref (core, atoi (str + 2), 'x', R_ANAL_REF_TYPE_CALL);
		case 'F': // $F function size
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				switch (str[2]) {
				/* function bounds (uppercase) */
				case 'B': return fcn->addr; // begin
				case 'E': return fcn->addr + fcn->_size; // end
				case 'S': return (str[3]=='S')? r_anal_fcn_realsize (fcn): r_anal_fcn_size (fcn);
				case 'I': return fcn->ninstr;
				/* basic blocks (lowercase) */
				case 'b': return bbBegin (fcn, core->offset);
				case 'e': return bbBegin (fcn, core->offset) + bbSize (fcn, core->offset);
				case 'i': return bbInstructions (fcn, core->offset);
				case 's': return bbSize (fcn, core->offset);
				case 'j': return bbJump (fcn, core->offset); // jump
				case 'f': return bbFail (fcn, core->offset); // fail
				}
				return fcn->addr;
			}
			return 0;
		}
		break;
	default:
		if (*str >= 'A') {
			// NOTE: functions override flags
			RAnalFunction *fcn = r_anal_fcn_find_name (core->anal, str);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
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
				if (ok) {
					*ok = true;
				}
				return ret;
			}

			// check for reg alias
			struct r_reg_item_t *r = r_reg_get (core->dbg->reg, str, -1);
			if (!r) {
				int role = r_reg_get_name_idx (str);
				if (role != -1) {
					const char *alias = r_reg_get_name (core->dbg->reg, role);
					r = r_reg_get (core->dbg->reg, alias, -1);
					if (r) {
						if (ok) {
							*ok = true;
						}
						ret = r_reg_get_value (core->dbg->reg, r);
						return ret;
					}
				}
			} else {
				if (ok) {
					*ok = true;
				}
				ret = r_reg_get_value (core->dbg->reg, r);
				return ret;
			}
		}
		break;
	}

	return ret;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW0 (RCore);
	if (!c) {
		return NULL;
	}
	r_core_init (c);
	return c;
}

/*-----------------------------------*/
#define radare_argc (sizeof (radare_argv)/sizeof(const char*))
static const char *radare_argv[] = {
	"?", "?v", "whereis", "which", "ls", "rm", "mkdir", "pwd", "cat", "less",
	"dH", "ds", "dso", "dsl", "dc", "dd", "dm",
	"db ", "db-", "dbd", "dbe", "dbs", "dbte", "dbtd", "dbts",
	"dp", "dr", "dcu", "dmd", "dmp", "dml",
	"ec","ecs", "eco",
	"s", "s+", "s++", "s-", "s--", "s*", "sa", "sb", "sr",
	"!", "!!", "!!!", "!!!-",
	"#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5",
	"#!python", "#!perl", "#!vala",
	"V", "v",
	"aa", "ab", "af", "ar", "ag", "at", "a?", "ax", "ad",
	"ae", "aec", "aex", "aep", "aepc", "aea", "aeA", "aes", "aeso", "aesu", "aesue", "aer", "aei", "aeim", "aef",
	"aaa", "aac","aae", "aai", "aar", "aan", "aas", "aat", "aap", "aav",
	"af", "afa", "afan", "afc", "afC", "afi", "afb", "afbb", "afn", "afr", "afs", "af*", "afv", "afvn",
	"aga", "agc", "agd", "agl", "agfl",
	"e", "et", "e-", "e*", "e!", "e?", "env ",
	"i", "ie", "ii", "iI", "ir", "iR", "is", "iS", "il", "iz", "id", "idp", "idpi", "idpi*", "idpd",
	"q", "q!", "q!!", "q!!!",
	"f", "fl", "fr", "f-", "f*", "fs", "fS", "fr", "fo", "f?",
	"m", "m*", "ml", "m-", "my", "mg", "md", "mp", "m?",
	"o", "o+", "oc", "on", "op", "o-", "x", "wf", "wF", "wt", "wta", "wtf", "wp", "obf",
	"L", "La", "Li", "Lo", "Lc", "Lh", "Ld", "L-",
	"t", "to", "t-", "tf", "td", "td-", "tb", "tn", "te", "tl", "tk", "ts", "tu",
	"(", "(*", "(-", "()", ".", ".!", ".(", "./",
	"r", "r+", "r-",
	"b", "bf", "b?",
	"/", "//", "/a", "/c", "/h", "/m", "/x", "/v", "/v2", "/v4", "/v8", "/r", "/re",
	"y", "yy", "y?",
	"wa", "waf", "wao", 
	"wv", "wv1", "wv2",  "wv4", "wv8",
	"wx", "wxf", "ww", "w?",
	"p6d", "p6e", "p8", "pb", "pc",
	"pd", "pda", "pdb", "pdc", "pdj", "pdr", "pdf", "pdi", "pdl", "pds", "pdt",
	"pD", "px", "pX", "po", "pf", "pf.", "pf*", "pf*.", "pfd", "pfd.", "pv", "p=", "p-",
	"pfj", "pfj.", "pfv", "pfv.",
	"pm", "pr", "pt", "ptd", "ptn", "pt?", "ps", "pz", "pu", "pU", "p?",
	"z", "z*", "zj", "z-", "z-*",
	"za", "zaf", "zaF",
	"zo", "zoz", "zos",
	"zfd", "zfs", "zfz",
	"z/", "z/*",
	"zc",
	"zs", "zs+", "zs-", "zs-*", "zsr",
	"#!pipe",
	NULL
};



static int autocomplete_process_path(RLine* line, const char* str, const char *path, int argv_idx) {
	char *lpath = NULL, *dirname = NULL , *basename = NULL;
	char *home = NULL, *filename = NULL, *p = NULL;
	int n = 0, i = argv_idx;
	RList *list;
	RListIter *iter;

	if (!path) {
		goto out;
	}

	lpath = r_str_new (path);
	p = (char *)r_str_last (lpath, R_SYS_DIR);
	if (p) {
		*p = 0;
		if (p == lpath) { // /xxx
			dirname = r_str_new ("/");
		} else if (lpath[0] == '~' && lpath[1]) { // ~/xxx/yyy
			dirname = r_str_home (lpath + 2);
		} else if (lpath[0] == '~') { // ~/xxx
			if (!(home = r_str_home (NULL))) {
				goto out;
			}
			dirname = r_str_newf ("%s%s", home, R_SYS_DIR);
			free (home);
		} else if (lpath[0] == '.' || lpath[0] == '/' ) { // ./xxx/yyy || /xxx/yyy
			dirname = r_str_newf ("%s%s", lpath, R_SYS_DIR);
		} else { // xxx/yyy
			dirname = r_str_newf (".%s%s%s", R_SYS_DIR, lpath, R_SYS_DIR);
		}
		basename = r_str_new (p + 1);
	} else { // xxx
		dirname = r_str_newf (".%s", R_SYS_DIR);
		basename = r_str_new (lpath);
	}

	if (!dirname || !basename) {
		goto out;
	}

	list= r_sys_dir (dirname);
	n = strlen (basename);
	bool chgdir = !strncmp (str, "cd ", 3);
	if (list) {
		r_list_foreach (list, iter, filename) {
			if (*filename == '.') {
				continue;
			}
			if (!basename[0] || !strncmp (filename, basename, n))  {
				char *tmpstring = r_str_newf ("%s%s", dirname, filename);
				if (r_file_is_directory (tmpstring) && chgdir) {
					tmp_argv[i++] = r_str_newf ("%s/", tmpstring);
					free (tmpstring);
				} else if (r_file_is_directory (tmpstring) && !chgdir) {
					tmp_argv[i++] = r_str_newf ("%s/", tmpstring);
					free (tmpstring);
				} else if (!chgdir) {
					tmp_argv[i++] = tmpstring;
				} else {
					free (tmpstring);
				}
				if (i == TMP_ARGV_SZ - 1) {
					i--;
					break;
				}
			}
		}
		r_list_free (list);
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;

out:
	free (lpath);
	free (dirname);
	free (basename);

	return i;
}

static void autocompleteFilename(RLine *line, char **extra_paths, int narg) {
	char *args = NULL, *input = NULL;
	int n = 0, i = 0;
	char *pipe = strchr (line->buffer.data, '>');
	if (pipe) {
		args = r_str_new (pipe + 1);
	} else {
		args = r_str_new (line->buffer.data);
	}
	if (!args) {
		goto out;
	}

	n = r_str_word_set0 (args);
	if (n < narg) {
		goto out;
	}

	input = r_str_new (r_str_word_get0 (args, narg));
	if (!input) {
		goto out;
	}
	const char *tinput = r_str_trim_ro (input);

	int argv_idx = autocomplete_process_path (line, line->buffer.data, tinput, 0);

	if (input[0] == '/' || input[0] == '.' || !extra_paths) {
		goto out;
	}

	for (i = 0; extra_paths[i]; i ++) {
		char *buf = r_str_newf ("%s%s%s", extra_paths[i], R_SYS_DIR, tinput);
		if (!buf) {
			break;
		}
		argv_idx += autocomplete_process_path (line, line->buffer.data, buf, argv_idx);
		free (buf);
	}

out:
	free (args);
	free (input);
}

//TODO: make it recursive to handle nested struct
static int autocomplete_pfele (RCore *core, char *key, char *pfx, int idx, char *ptr) {
	int i, ret = 0;
	int len = strlen (ptr);
	char* fmt = sdb_get (core->print->formats, key, NULL);
	if (fmt) {
		int nargs = r_str_word_set0_stack (fmt);
		if (nargs > 1) {
			for (i = 1; i < nargs; i++) {
				const char *arg = r_str_word_get0 (fmt, i);
				char *p = strchr (arg, '(');
				char *p2 = strchr (arg, ')');
				// remove '(' and ')' from fmt
				if (p && p2) {
					arg = p + 1;
					*p2 = '\0';
				}
				if (!len || !strncmp (ptr, arg, len)) {
					tmp_argv[ret++] = r_str_newf ("pf%s.%s.%s", pfx, key, arg);
				}
			}
		}
	}
	free (fmt);
	return ret;
}

#define ADDARG(x) if (!strncmp (line->buffer.data+chr, x, strlen (line->buffer.data+chr))) { tmp_argv[j++] = x; }

static void autocomplete_default(RLine *line) {
	RCore *core = line->user;
	if (!core) {
		return;
	}
	RCoreAutocomplete *a = core->autocomplete;
	int i, j;
	j = 0;
	if (a) {
		for (i = 0; j < (TMP_ARGV_SZ - 1) && i < a->n_subcmds; i++) {
			if (line->buffer.data[0] == 0 || !strncmp (a->subcmds[i]->cmd, line->buffer.data, a->subcmds[i]->length)) {
				tmp_argv[j++] = a->subcmds[i]->cmd;
			}
		}
	} else {
		for (i = 0; j < (TMP_ARGV_SZ - 1) && i < radare_argc && radare_argv[i]; i++) {
			int length = strlen (radare_argv[i]);
			if (!strncmp (radare_argv[i], line->buffer.data, length)) {
				tmp_argv[j++] = radare_argv[i];
			}
		}
	}
	tmp_argv[j] = NULL;
	line->completion.argc = j;
	line->completion.argv = tmp_argv;
}

static void autocomplete_evals(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	int i = 0, n = strlen (str);
	RConfigNode *bt;
	RListIter *iter;
	r_list_foreach (core->config->nodes, iter, bt) {
		if (!strncmp (bt->name, str, n)) {
			tmp_argv[i++] = bt->name;
			if (i == TMP_ARGV_SZ - 1) {
				break;
			}
		}
	}
	tmp_argv[R_MIN(i, TMP_ARGV_SZ - 1)] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_project(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	char *foo, *projects_path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	RList *list = r_sys_dir (projects_path);
	RListIter *iter;
	int n = strlen (str);
	int i = 0;
	if (projects_path) {
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				if (!strncmp (foo, str, n)) {
					tmp_argv[i++] = r_str_newf ("%s", foo);
					if (i == TMP_ARGV_SZ - 1) {
						break;
					}
				}
			}
		}
		free (projects_path);
		r_list_free (list);
	}
	tmp_argv[R_MIN(i, TMP_ARGV_SZ - 1)] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_minus(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	int count;
	int length = strlen (str);
	char **keys = r_cmd_alias_keys(core->rcmd, &count);
	if (keys) {
		int i, j;
		for (i=j=0; i<count; i++) {
			if (!strncmp (keys[i], str, length)) {
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
}

static void autocomplete_breakpoints(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	RListIter *iter;
	RBreakpoint *bp = core->dbg->bp;
	RBreakpointItem *b;
	int n, i = 0;
	n = strlen (str);
	r_list_foreach (bp->bps, iter, b) {
		char *addr = r_str_newf ("0x%"PFMT64x"", b->addr);
		if (!strncmp (addr, str, n)) {
			tmp_argv[i++] = addr;
		} else {
			free (addr);
		}
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_flags(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	RListIter *iter;
	RFlagItem *flag;
	int n, i = 0;
	n = strlen (str);
	r_list_foreach (core->flags->flags, iter, flag) {
		if (!strncmp (flag->name, str, n)) {
			tmp_argv[i++] = flag->name;
			if (i == (TMP_ARGV_SZ - 1)) {
				break;
			}
		}
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_zignatures(RLine* line, const char* msg) {
	RCore *core = line->user;
	if (!core || !msg) {
		return;
	}
	int length = strlen (msg);
	RSpaces zs = core->anal->zign_spaces;
	int j, i = 0;
	for (j = 0; j < R_SPACES_MAX; j++) {
		if (zs.spaces[j]) {
			if (i == TMP_ARGV_SZ - 1) {
				break;
			}
			if (!strncmp (msg, zs.spaces[j], length)) {
				if (i + 1 < TMP_ARGV_SZ) {
					tmp_argv[i++] = zs.spaces[j];
				}
			}
		}
	}
	if (strlen (msg) == 0 && i + 1 < TMP_ARGV_SZ) {
		tmp_argv[i++] = "*";
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_flagspaces(RLine* line, const char* msg) {
	RCore *core = line->user;
	if (!core || !msg) {
		return;
	}
	int length = strlen (msg);
	RFlag *flag = core->flags;
	int j, i = 0;
	for (j = 0; j < R_FLAG_SPACES_MAX - 1; j++) {
		if (flag->spaces[j] && flag->spaces[j][0]) {
			if (i == TMP_ARGV_SZ - 1) {
				break;
			}
			if (!strncmp (msg, flag->spaces[j], length)) {
				if (i + 1 < TMP_ARGV_SZ) {
					tmp_argv[i++] = flag->spaces[j];
				}
			}
		}
	}
	if (flag->spaces[j] && !strncmp (msg, flag->spaces[j], strlen (msg))) {
		if (i + 1 < TMP_ARGV_SZ) {
			tmp_argv[i++] = "*";
		}
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_functions (RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	RListIter *iter;
	RAnalFunction *fcn;
	int n = strlen (str), i = 0;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		char *name = r_core_anal_fcn_name (core, fcn);
		if (!strncmp (name, str, n)) {
			tmp_argv[i++] = name;
		} else {
			free (name);
		}
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_macro(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	RCmdMacroItem *item;
	RListIter *iter;
	char buf[1024];
	int n, i = 0;
	n = strlen(str);
	r_list_foreach (core->rcmd->macro.macros, iter, item) {
		char *p = item->name;
		if (!*str || !strncmp (str, p, n)) {
			snprintf (buf, sizeof (buf), "%s%s)", str, p);
			// eprintf ("------ %p (%s) = %s\n", tmp_argv[i], buf, p);
			if (r_is_heap ((void*)tmp_argv[i])) {
				free ((char *)tmp_argv[i]);
			}
			tmp_argv[i] = strdup (buf); // LEAKS
			i++;
			if (i == TMP_ARGV_SZ - 1) {
				break;
			}
		}
	}
	//tmp_argv[(i-1>0)?i-1:0] = NULL;
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static void autocomplete_file(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	char *pipe = strchr (str, '>');

	if (pipe) {
		str = r_str_trim_ro (pipe + 1);
	}
	if (str && !*str) {
		autocomplete_process_path (line, str, "./", 0);
	} else {
		autocomplete_process_path (line, str, str, 0);
	}

}

static void autocomplete_theme(RLine* line, const char* str) {
	RCore *core = line->user;
	if (!core || !str) {
		return;
	}
	int i = 0;
	int len = strlen (str);
	char *theme;
	RListIter *iter;
	RList *themes = r_core_list_themes (core);
	r_list_foreach (themes, iter, theme) {
		if (!len || !strncmp (str, theme, len)) {
			tmp_argv[i++] = strdup (theme);
		}
	}
	tmp_argv[i] = NULL;
	r_list_free (themes);
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
}

static bool find_e_opts(RLine *line) {
	RCore *core = line->user;
	if (!core) {
		return false;
	}
	const char *pattern = "e (.*)=";
	RRegex *rx = r_regex_new (pattern, "e");
	const size_t nmatch = 2;
	RRegexMatch pmatch[2];
	bool ret = false;

	if (r_regex_exec (rx, line->buffer.data, nmatch, pmatch, 1)) {
		goto out;
	}
	int i;
	char *str = NULL;
	for (i = pmatch[1].rm_so; i < pmatch[1].rm_eo; i++) {
		str = r_str_appendch (str, line->buffer.data[i]);
	}
	RConfigNode *node = r_config_node_get (core->config, str);
	if (!node) {
		return false;
	}
	RListIter *iter;
	char *option;
	char *p = (char *) r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, '=');
	p++;
	i = 0;
	int n = strlen (p);
	r_list_foreach (node->options, iter, option) {
		if (!strncmp (option, p, n)) {
			tmp_argv[i++] = option;
		}
	}
	tmp_argv[i] = NULL;
	line->completion.argc = i;
	line->completion.argv = tmp_argv;
	line->completion.opt = true;
	ret = true;

 out:
	r_regex_free (rx);
	return ret;
}

static bool find_autocomplete(RLine *line) {
	RCore *core = line->user;
	if (!core) {
		return false;
	}
	RCoreAutocomplete* child = NULL;
	RCoreAutocomplete* parent = core->autocomplete;
	const char* p = line->buffer.data;
	if (!p || !*p) {
		return false;
	}
	char arg[256];
	arg[0] = 0;
	while (*p) {
		const char* e = r_str_trim_wp (p);
		if (!e || (e - p) >= 256 || e == p) {
			return false;
		}
		memcpy (arg, p, e - p);
		arg[e - p] = 0;
		child = r_core_autocomplete_find (parent, arg, false);
		if (child && child->length < line->buffer.length && p[child->length] == ' ') {
			// if is spaced then i can provide the
			// next subtree as suggestion..
			p = r_str_trim_ro (p + child->length);
			if (child->type == R_CORE_AUTOCMPLT_OPTN) {
				continue;
			}
			parent = child;
		} else {
			break;
		}
	}
	int i;
	/* if something went wrong this will prevent bad behavior */
	tmp_argv[0] = NULL;
	line->completion.argc = 0;
	line->completion.argv = tmp_argv;
	switch (parent->type) {
	case R_CORE_AUTOCMPLT_FLAG:
		autocomplete_flags (line, p);
		break;
	case R_CORE_AUTOCMPLT_FLSP:
		autocomplete_flagspaces (line, p);
		break;
	case R_CORE_AUTOCMPLT_FCN:
		autocomplete_functions (line, p);
		break;
	case R_CORE_AUTOCMPLT_ZIGN:
		autocomplete_zignatures (line, p);
		break;
	case R_CORE_AUTOCMPLT_EVAL:
		autocomplete_evals (line, p);
		break;
	case R_CORE_AUTOCMPLT_PRJT:
		autocomplete_project (line, p);
		break;
	case R_CORE_AUTOCMPLT_MINS:
		autocomplete_minus (line, p);
		break;
	case R_CORE_AUTOCMPLT_BRKP:
		autocomplete_breakpoints (line, p);
		break;
	case R_CORE_AUTOCMPLT_MACR:
		autocomplete_macro (line, p);
		break;
	case R_CORE_AUTOCMPLT_FILE:
		autocomplete_file (line, p);
		break;
	case R_CORE_AUTOCMPLT_THME:
		autocomplete_theme (line, p);
		break;
	case R_CORE_AUTOCMPLT_OPTN:
		// handled before
		break;
	default:
		if (r_config_get_i (core->config, "cfg.newtab")) {
			RCmdDescriptor *desc = &core->root_cmd_descriptor;
			for (i = 0; arg[i] && desc; i++) {
				ut8 c = arg[i];
				desc = c < R_ARRAY_SIZE (desc->sub) ? desc->sub[c] : NULL;
			}
			if (desc && desc->help_msg) {
				r_core_cmd_help (core, desc->help_msg);
				r_cons_flush ();
				return true;
			}
			// fallback to command listing
		}
		int length = strlen (arg), j = 0;
		for (i = 0; j < (TMP_ARGV_SZ - 1) && i < parent->n_subcmds; i++) {
			if (!strncmp (arg, parent->subcmds[i]->cmd, length)) {
				tmp_argv[j++] = parent->subcmds[i]->cmd;
			}
		}
		tmp_argv[j] = NULL;
		line->completion.argc = j;
		break;
	}
	return true;
}

static int autocomplete(RLine *line) {
	RCore *core = line->user;
	RListIter *iter;
	RFlagItem *flag;
	if (core) {
		r_core_free_autocomplete (core);
		char *pipe = strchr (line->buffer.data, '>');
		char *ptr = strchr (line->buffer.data, '@');
		if (pipe && strchr (pipe + 1, ' ') && line->buffer.data+line->buffer.index >= pipe) {
			autocompleteFilename (line, NULL, 1);
		} else if (ptr && strchr (ptr + 1, ' ') && line->buffer.data + line->buffer.index >= ptr) {
			int sdelta, n, i = 0;
			ptr = (char *)r_str_trim_ro (ptr + 1);
			n = strlen (ptr);//(line->buffer.data+sdelta);
			sdelta = (int)(size_t)(ptr - line->buffer.data);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!strncmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i == TMP_ARGV_SZ - 1) {
						break;
					}
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "#!pipe ", 7)) {
			if (strchr (line->buffer.data + 7, ' ')) {
				autocompleteFilename (line, NULL, 2);
			} else {
				int chr = 7;
				int j = 0;

				tmp_argv_heap = false;
				ADDARG ("node");
				ADDARG ("vala");
				ADDARG ("ruby");
				ADDARG ("newlisp");
				ADDARG ("perl");
				ADDARG ("python");
				tmp_argv[j] = NULL;
				line->completion.argc = j;
				line->completion.argv = tmp_argv;
			}
		} else if (!strncmp (line->buffer.data, "ec ", 3)) {
			if (strchr (line->buffer.data + 3, ' ')) {
				autocompleteFilename (line, NULL, 2);
			} else {
				int chr = 3;
				int j = 0;

				tmp_argv_heap = false;
				ADDARG("comment")
				ADDARG("usrcmt")
				ADDARG("args")
				ADDARG("fname")
				ADDARG("floc")
				ADDARG("fline")
				ADDARG("flag")
				ADDARG("label")
				ADDARG("help")
				ADDARG("flow")
				ADDARG("prompt")
				ADDARG("offset")
				ADDARG("input")
				ADDARG("invalid")
				ADDARG("other")
				ADDARG("b0x00")
				ADDARG("b0x7f")
				ADDARG("b0xff")
				ADDARG("math")
				ADDARG("bin")
				ADDARG("btext")
				ADDARG("push")
				ADDARG("pop")
				ADDARG("crypto")
				ADDARG("jmp")
				ADDARG("cjmp")
				ADDARG("call")
				ADDARG("nop")
				ADDARG("ret")
				ADDARG("trap")
				ADDARG("swi")
				ADDARG("cmp")
				ADDARG("reg")
				ADDARG("creg")
				ADDARG("num")
				ADDARG("mov")
				ADDARG("func_var")
				ADDARG("func_var_type")
				ADDARG("func_var_addr")
				ADDARG("widget_bg")
				ADDARG("widget_sel")
				ADDARG("ai.read")
				ADDARG("ai.write")
				ADDARG("ai.exec")
				ADDARG("ai.seq")
				ADDARG("ai.ascii")
				ADDARG("ai.unmap")
				ADDARG("graph.box")
				ADDARG("graph.box2")
				ADDARG("graph.box3")
				ADDARG("graph.box4")
				ADDARG("graph.true")
				ADDARG("graph.false")
				ADDARG("graph.trufae")
				ADDARG("graph.current")
				ADDARG("graph.traced")
				ADDARG("gui.cflow")
				ADDARG("gui.dataoffset")
				ADDARG("gui.background")
				ADDARG("gui.alt_background")
				ADDARG("gui.border")
				tmp_argv[j] = NULL;
				line->completion.argc = j;
				line->completion.argv = tmp_argv;
			}
		} else if (!strncmp (line->buffer.data, "pf.", 3)
		|| !strncmp (line->buffer.data, "pf*.", 4)
		|| !strncmp (line->buffer.data, "pfd.", 4)
		|| !strncmp (line->buffer.data, "pfv.", 4)
		|| !strncmp (line->buffer.data, "pfj.", 4)) {
			char pfx[2];
			int chr = (line->buffer.data[2]=='.')? 3: 4;
			if (chr == 4) {
				pfx[0] = line->buffer.data[2];
				pfx[1] = 0;
			} else {
				*pfx = 0;
			}
			SdbList *sls = sdb_foreach_list (core->print->formats, false);
			SdbListIter *iter;
			SdbKv *kv;
			int j = 0;
			ls_foreach (sls, iter, kv) {
				int len = strlen (line->buffer.data + chr);
				int minlen = R_MIN (len,  strlen (sdbkv_key (kv)));
				if (!len || !strncmp (line->buffer.data + chr, sdbkv_key (kv), minlen)) {
					char *p = strchr (line->buffer.data + chr, '.');
					if (p) {
						j += autocomplete_pfele (core, sdbkv_key (kv), pfx, j, p + 1);
						break;
					} else {
						tmp_argv[j++] = r_str_newf ("pf%s.%s", pfx, sdbkv_key (kv));
					}
				}
			}
			if (j > 0) {
				tmp_argv_heap = true;
			}
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "afvn ", 5))
		|| (!strncmp (line->buffer.data, "afan ", 5))) {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			RList *vars;
			if (!strncmp (line->buffer.data, "afvn ", 5)) {
				vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_BPV);
			} else {
				vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_ARG);
			}
			const char *f_ptr, *l_ptr;
			RAnalVar *var;
			int j = 0, len = strlen (line->buffer.data);

			f_ptr = r_sub_str_lchr (line->buffer.data, 0, line->buffer.index, ' ');
			f_ptr = f_ptr != NULL ? f_ptr + 1 : line->buffer.data;
			l_ptr = r_sub_str_rchr (line->buffer.data, line->buffer.index, len, ' ');
			if (!l_ptr) {
				l_ptr = line->buffer.data + len;
			}
			r_list_foreach (vars, iter, var) {
				if (!strncmp (f_ptr, var->name, l_ptr - f_ptr)) {
					tmp_argv[j++] = strdup (var->name);
				}
			}
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "t ", 2)
		|| !strncmp (line->buffer.data, "t- ", 3)) {
			int i = 0;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
			SdbListIter *iter;
			SdbKv *kv;
			int chr = (line->buffer.data[1] == ' ')? 2: 3;
			ls_foreach (l, iter, kv) {
				int len = strlen (line->buffer.data + chr);
				if (!len || !strncmp (line->buffer.data + chr, sdbkv_key (kv), len)) {
					if (!strcmp (sdbkv_value (kv), "type") || !strcmp (sdbkv_value (kv), "enum")
					|| !strcmp (sdbkv_value (kv), "struct")) {
						tmp_argv[i++] = strdup (sdbkv_key (kv));
					}
				}
			}
			if (i > 0) {
				tmp_argv_heap = true;
			}
			tmp_argv[i] = NULL;
			ls_free (l);
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if ((!strncmp (line->buffer.data, "te ", 3))) {
			int i = 0;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
			SdbListIter *iter;
			SdbKv *kv;
			int chr = 3;
			ls_foreach (l, iter, kv) {
				int len = strlen (line->buffer.data + chr);
				if (!len || !strncmp (line->buffer.data + chr, sdbkv_key (kv), len)) {
					if (!strcmp (sdbkv_value (kv), "enum")) {
						tmp_argv[i++] = strdup (sdbkv_key (kv));
					}
				}
			}
			if (i > 0) {
				tmp_argv_heap = true;
			}
			tmp_argv[i] = NULL;
			ls_free (l);
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "ts ", 3)
		|| !strncmp (line->buffer.data, "ta ", 3)
		|| !strncmp (line->buffer.data, "tp ", 3)
		|| !strncmp (line->buffer.data, "tl ", 3)
		|| !strncmp (line->buffer.data, "tpx ", 4)
		|| !strncmp (line->buffer.data, "tss ", 4)
		|| !strncmp (line->buffer.data, "ts* ", 4)) {
			int i = 0;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
			SdbListIter *iter;
			SdbKv *kv;
			int chr = (line->buffer.data[2] == ' ')? 3: 4;
			ls_foreach (l, iter, kv) {
				int len = strlen (line->buffer.data + chr);
				if (!len || !strncmp (line->buffer.data + chr, sdbkv_key (kv), len)) {
					if (!strncmp (sdbkv_value (kv), "struct", strlen ("struct") + 1)) {
						tmp_argv[i++] = strdup (sdbkv_key (kv));
					}
				}
			}
			if (i > 0) {
				tmp_argv_heap = true;
			}
			tmp_argv[i] = NULL;
			ls_free (l);
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else if (!strncmp (line->buffer.data, "zo ", 3)
		|| !strncmp (line->buffer.data, "zoz ", 4)) {
			if (core->anal->zign_path && core->anal->zign_path[0]) {
				char *zignpath = r_file_abspath (core->anal->zign_path);
				char *paths[2] = { zignpath, NULL };
				autocompleteFilename (line, paths, 1);
				free (zignpath);
			} else {
				autocompleteFilename (line, NULL, 1);
			}
		} else if (find_e_opts (line)) {
			return true;
		} else if (line->offset_prompt) {
			autocomplete_flags (line, line->buffer.data);
		} else if (line->file_prompt) {
			autocomplete_file (line, line->buffer.data);
		} else if (!find_autocomplete (line)) {
			autocomplete_default (line);
		}
	} else {
		autocomplete_default (line);
	}
	return true;
}

R_API int r_core_fgets(char *buf, int len) {
	const char *ptr;
	RLine *rli = r_line_singleton ();
	buf[0] = '\0';
	if (rli->completion.argv != radare_argv) {
		r_line_free_autocomplete (rli);
	}
	rli->completion.argc = radare_argc;
	rli->completion.argv = radare_argv;
 	rli->completion.run = autocomplete;
	ptr = r_line_readline ();
	if (!ptr) {
		return -1;
	}
	strncpy (buf, ptr, len);
	buf[len - 1] = 0;
	return strlen (buf) + 1;
}

static const char *r_core_print_offname(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_i (c->flags, addr);
	return item ? item->name : NULL;
}

/**
 * Disassemble one instruction at specified address.
 */
static int __disasm(void *_core, ut64 addr) {
	RCore *core = _core;
	ut64 prevaddr = core->offset;
	int len;

	r_core_seek (core, addr, true);
	len = r_core_print_disasm_instructions (core, 0, 1);
	r_core_seek (core, prevaddr, true);

	return len;
}

static void update_sdb(RCore *core) {
	Sdb *d;
	RBinObject *o;
	if (!core) {
		return;
	}
	//SDB// anal/
	if (core->anal && core->anal->sdb) {
		sdb_ns_set (DB, "anal", core->anal->sdb);
	}
	//SDB// bin/
	if (core->bin && core->bin->sdb) {
		sdb_ns_set (DB, "bin", core->bin->sdb);
	}
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
	if (core->dbg->sgnls) {
		core->dbg->sgnls->refs++;
		sdb_ns_set (d, "signals", core->dbg->sgnls);
	}
}

#define MINLEN 1
static int is_string (const ut8 *buf, int size, int *len) {
	int i;
	if (size < 1) {
		return 0;
	}
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
R_API char *r_core_anal_hasrefs(RCore *core, ut64 value, bool verbose) {
	if (verbose) {
		return r_core_anal_hasrefs_to_depth(core, value, r_config_get_i (core->config, "hex.depth"));
	}
	RFlagItem *fi = r_flag_get_i (core->flags, value);
	if (fi) {
		return strdup (fi->name);
	}
	return NULL;
}

static char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, int depth) {
	RStrBuf *s = r_strbuf_new (NULL);
	ut64 type;
	RBinSection *sect;
	char *mapname = NULL;
	RAnalFunction *fcn;
	RFlagItem *fi = r_flag_get_i (core->flags, value);
	type = r_core_anal_address (core, value);
	fcn = r_anal_get_fcn_in (core->anal, value, 0);
	if (value && value != UT64_MAX) {
		RDebugMap *map = r_debug_map_get (core->dbg, value);
		if (map && map->name && map->name[0]) {
			mapname = strdup (map->name);
		}
	}
	sect = value? r_bin_get_section_at (r_bin_cur_object (core->bin), value, true): NULL;
	if(! ((type&R_ANAL_ADDR_TYPE_HEAP)||(type&R_ANAL_ADDR_TYPE_STACK)) ) {
		// Do not repeat "stack" or "heap" words unnecessarily.
		if (sect && sect->name[0]) {
			r_strbuf_appendf (s," (%s)", sect->name);
		}
		if (mapname) {
			r_strbuf_appendf (s, " (%s)", mapname);
			R_FREE (mapname);
		}
	}
	if (fi) {
		r_strbuf_appendf (s, " %s", fi->name);
	}
	if (fcn) {
		r_strbuf_appendf (s, " %s", fcn->name);
	}
	if (type) {
		const char *c = r_core_anal_optype_colorfor (core, value, true);
		const char *cend = (c && *c) ? Color_RESET: "";
		if (!c) {
			c = "";
		}
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			r_strbuf_appendf (s, " %sheap%s", c, cend);
		} else if (type & R_ANAL_ADDR_TYPE_STACK) {
			r_strbuf_appendf (s, " %sstack%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_PROGRAM) {
			r_strbuf_appendf (s, " %sprogram%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_LIBRARY) {
			r_strbuf_appendf (s, " %slibrary%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_ASCII) {
			r_strbuf_appendf (s, " %sascii%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
			r_strbuf_appendf (s, " %ssequence%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_READ) {
			r_strbuf_appendf (s, " %sR%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_WRITE) {
			r_strbuf_appendf (s, " %sW%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			RAsmOp op;
			ut8 buf[32];
			r_strbuf_appendf (s, " %sX%s", c, cend);
			/* instruction disassembly */
			r_io_read_at (core->io, value, buf, sizeof (buf));
			r_asm_set_pc (core->assembler, value);
			r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
			r_strbuf_appendf (s, " '%s'", r_asm_op_get_asm (&op));
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
		const char *c = r_config_get_i (core->config, "scr.color")? core->cons->pal.ai_ascii: "";
		const char *cend = (c && *c) ? Color_RESET: "";
		int len, r;
		if (r_io_read_at (core->io, value, buf, sizeof (buf))) {
			buf[sizeof (buf) - 1] = 0;
			switch (is_string (buf, sizeof(buf), &len)) {
			case 1:
				r_strbuf_appendf (s, " (%s%s%s)", c, buf, cend);
				break;
			case 2:
				r = r_utf8_encode_str ((const RRune *)buf, widebuf,
						       sizeof (widebuf) - 1);
				if (r == -1) {
					eprintf ("Something was wrong with refs\n");
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
			if (rrstr) {
				if (rrstr[0]) {
					r_strbuf_appendf (s, " --> %s", rrstr);
				}
				free (rrstr);
			}
		}
	}
	free (mapname);
	return r_strbuf_drain (s);
}

R_API char *r_core_anal_get_comments(RCore *core, ut64 addr) {
	if (core) {
		char *type = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		char *cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		if (type && cmt) {
			char *ret = r_str_newf ("%s %s", type, cmt);
			free (type);
			free (cmt);
			return ret;
		} else if (type) {
			return type;
		} else if (cmt) {
			return cmt;
		}
	}
	return NULL;
}

R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr, bool verbose) {
	ut64 type;
	if (!(core->print->flags & R_PRINT_FLAGS_COLOR)) {
		return NULL;
	}
	if (!r_config_get_i (core->config, "scr.color")) {
		return NULL;
	}
	type = r_core_anal_address (core, addr);
	if (type & R_ANAL_ADDR_TYPE_EXEC) {
		return core->cons->pal.ai_exec; //Color_RED;
	}
	if (type & R_ANAL_ADDR_TYPE_WRITE) {
		return core->cons->pal.ai_write; //Color_BLUE;
	}
	if (type & R_ANAL_ADDR_TYPE_READ) {
		return core->cons->pal.ai_read; //Color_GREEN;
	}
	if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
		return core->cons->pal.ai_seq; //Color_MAGENTA;
	}
	if (type & R_ANAL_ADDR_TYPE_ASCII) {
		return core->cons->pal.ai_ascii; //Color_YELLOW;
	}
	return NULL;
}

static void r_core_setenv (RCore *core) {
	char *e = r_sys_getenv ("PATH");
	char *h = r_str_home (R2_HOME_BIN R_SYS_ENVSEP);
	char *n = r_str_newf ("%s%s", h, e);
	r_sys_setenv ("PATH", n);
	free (n);
	free (h);
	free (e);
}

static int mywrite(const ut8 *buf, int len) {
	return r_cons_memcat ((const char *)buf, len);
}

static bool exists_var(RPrint *print, ut64 func_addr, char *str) {
	char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", func_addr, 1, str);
	if (sdb_const_get_len (((RCore*)(print->user))->anal->sdb_fcns, name_key, NULL, 0)) {
		return true;
	}
	return false;
}

static bool r_core_anal_log(struct r_anal_t *anal, const char *msg) {
	RCore *core = anal->user;
	if (core->cfglog) {
		r_core_log_add (core, msg);
	}
	return true;
}

static bool r_core_anal_read_at(struct r_anal_t *anal, ut64 addr, ut8 *buf, int len) {
	return r_io_read_at (anal->iob.io, addr, buf, len);
}

static void r_core_break (RCore *core) {
	// if we are not in the main thread we hold in a lock
	RCoreTask *task = r_core_task_self (core);
	r_core_task_continue (task);
}

static void *r_core_sleep_begin (RCore *core) {
	RCoreTask *task = r_core_task_self (core);
	r_core_task_sleep_begin (task);
	return task;
}

static void r_core_sleep_end (RCore *core, void *user) {
	RCoreTask *task = (RCoreTask *)user;
	r_core_task_sleep_end (task);
}

static void init_autocomplete (RCore* core) {
	core->autocomplete = R_NEW0 (RCoreAutocomplete);
	/* flags */
	r_core_autocomplete_add (core->autocomplete, "s", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "s+", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "b", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "f", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "?", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "?v", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "ad", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "bf", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "ag", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "db", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "f-", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "fr", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "tf", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "/a", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "/v", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "/r", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "/re", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aav", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aep", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aef", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "afb", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "afc", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "axg", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "axt", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "axf", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "dcu", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "ag", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "agfl", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aecu", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aesu", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "aeim", R_CORE_AUTOCMPLT_FLAG, true);
	r_core_autocomplete_add (core->autocomplete, "afi", R_CORE_AUTOCMPLT_FCN, true);
	r_core_autocomplete_add (core->autocomplete, "afcf", R_CORE_AUTOCMPLT_FCN, true);
	/* evars */
	r_core_autocomplete_add (core->autocomplete, "e", R_CORE_AUTOCMPLT_EVAL, true);
	r_core_autocomplete_add (core->autocomplete, "et", R_CORE_AUTOCMPLT_EVAL, true);
	r_core_autocomplete_add (core->autocomplete, "e?", R_CORE_AUTOCMPLT_EVAL, true);
	r_core_autocomplete_add (core->autocomplete, "e!", R_CORE_AUTOCMPLT_EVAL, true);
	/* cfg.editor */
	r_core_autocomplete_add (core->autocomplete, "-", R_CORE_AUTOCMPLT_MINS, true);
	/* breakpoints */
	r_core_autocomplete_add (core->autocomplete, "db-", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbd", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbe", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbs", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbte", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbtd", R_CORE_AUTOCMPLT_BRKP, true);
	r_core_autocomplete_add (core->autocomplete, "dbts", R_CORE_AUTOCMPLT_BRKP, true);
	/* Project */
	r_core_autocomplete_add (core->autocomplete, "Po", R_CORE_AUTOCMPLT_PRJT, true);
	/* zignatures */
	r_core_autocomplete_add (core->autocomplete, "zs", R_CORE_AUTOCMPLT_ZIGN, true);
	/* flag spaces */
	r_core_autocomplete_add (core->autocomplete, "fs", R_CORE_AUTOCMPLT_FLSP, true);
	/* macros */
	r_core_autocomplete_add (core->autocomplete, ".(", R_CORE_AUTOCMPLT_MACR, true);
	r_core_autocomplete_add (core->autocomplete, "(-", R_CORE_AUTOCMPLT_MACR, true);
	/* file path */
	r_core_autocomplete_add (core->autocomplete, "o", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "idp", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "idpi", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "L", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "obf", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, ".", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "o+", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "oc", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "r2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rabin2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rasm2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rahash2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rax2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rafind2", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "cd", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "on", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "op", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wf", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "rm", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wF", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wp", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "Sd", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "Sl", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "to", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "pm", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "/m", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "zos", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "zfd", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "zfs", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "zfz", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "cat", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wta", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wtf", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "wxf", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "dml", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "vim", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "less", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (r_core_autocomplete_add (core->autocomplete, "ls", R_CORE_AUTOCMPLT_DFLT, true), "-l", R_CORE_AUTOCMPLT_FILE, true);
	/* theme */
	r_core_autocomplete_add (core->autocomplete, "eco", R_CORE_AUTOCMPLT_THME, true);
	/* just for hints */
	int i;
	for (i = 0; i < radare_argc && radare_argv[i]; i++) {
		if (!r_core_autocomplete_find (core->autocomplete, radare_argv[i], true)) {
			r_core_autocomplete_add (core->autocomplete, radare_argv[i], R_CORE_AUTOCMPLT_DFLT, true);
		}
	}
}

static const char *colorfor_cb(void *user, ut64 addr, bool verbose) {
	return r_core_anal_optype_colorfor ((RCore *)user, addr, verbose);
}

static char *hasrefs_cb(void *user, ut64 addr, bool verbose) {
	return r_core_anal_hasrefs ((RCore *)user, addr, verbose);
}

static char *get_comments_cb(void *user, ut64 addr) {
	return r_core_anal_get_comments ((RCore *)user, addr);
}

R_API bool r_core_init(RCore *core) {
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8 *)calloc (R_CORE_BLOCKSIZE + 1, 1);
	if (!core->block) {
		eprintf ("Cannot allocate %d byte(s)\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return false;
	}
	r_core_setenv (core);
	core->ev = r_event_new (core);
	core->lock = r_th_lock_new (true);
	core->max_cmd_depth = R_CORE_CMD_DEPTH + 1;
	core->cmd_depth = core->max_cmd_depth;
	core->sdb = sdb_new (NULL, "r2kv.sdb", 0); // XXX: path must be in home?
	core->lastsearch = NULL;
	core->cmdfilter = NULL;
	core->switch_file_view = 0;
	core->cmdremote = 0;
	core->incomment = false;
	core->config = NULL;
	core->http_up = false;
	ZERO_FILL (core->root_cmd_descriptor);
	core->print = r_print_new ();
	core->print->user = core;
	core->print->num = core->num;
	core->print->offname = r_core_print_offname;
	core->print->cb_printf = r_cons_printf;
	core->print->cb_color = r_cons_rainbow_get;
	core->print->write = mywrite;
	core->print->exists_var = exists_var;
	core->print->disasm = __disasm;
	core->print->colorfor = colorfor_cb;
	core->print->hasrefs = hasrefs_cb;
	core->print->get_comments = get_comments_cb;
	core->print->use_comments = false;
	core->rtr_n = 0;
	core->blocksize_max = R_CORE_BLOCKSIZE_MAX;
	core->task_id_next = 0;
	core->tasks = r_list_newf ((RListFree)r_core_task_decref);
	core->tasks_queue = r_list_new ();
	core->oneshot_queue = r_list_newf (free);
	core->oneshots_enqueued = 0;
	core->tasks_lock = r_th_lock_new (true);
	core->tasks_running = 0;
	core->oneshot_running = false;
	core->main_task = r_core_task_new (core, false, NULL, NULL, NULL);
	r_list_append (core->tasks, core->main_task);
	core->current_task = NULL;
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
	core->panels_tmpcfg = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = true;
	core->yank_buf = r_buf_new();
	core->num = r_num_new (&num_callback, &str_callback, core);
	core->curasmstep = 0;
	core->egg = r_egg_new ();
	r_egg_setup (core->egg, R_SYS_ARCH, R_SYS_BITS, 0, R_SYS_OS);

	core->undos = r_list_newf ((RListFree)r_core_undo_free);
	core->fixedarch = false;
	core->fixedbits = false;

	/* initialize libraries */
	core->cons = r_cons_new ();
	if (core->cons->refcnt == 1) {
		core->cons = r_cons_singleton ();
		if (core->cons->line) {
			core->cons->line->user = core;
			core->cons->line->cb_editor = \
				(RLineEditorCb)&r_core_editor;
		}
#if __EMSCRIPTEN__
		core->cons->user_fgets = NULL;
#else
		core->cons->user_fgets = (void *)r_core_fgets;
#endif
		//r_line_singleton()->user = (void *)core;
		r_line_hist_load (R2_HOME_HISTORY);
	}
	core->print->cons = core->cons;
	r_cons_bind (&core->print->consbind);

	// We save the old num ad user, in order to restore it after free
	core->lang = r_lang_new ();
	core->lang->cmd_str = (char *(*)(void *, const char *))r_core_cmd_str;
	core->lang->cmdf = (int (*)(void *, const char *, ...))r_core_cmdf;
	r_core_bind_cons (core);
	core->lang->cb_printf = r_cons_printf;
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->assembler = r_asm_new ();
	core->assembler->num = core->num;
	r_asm_set_user_ptr (core->assembler, core);
	core->anal = r_anal_new ();
	core->anal->ev = core->ev;
	core->anal->log = r_core_anal_log;
	core->anal->read_at = r_core_anal_read_at;
	core->anal->meta_spaces.cb_printf = r_cons_printf;
	core->anal->cb.on_fcn_new = on_fcn_new;
	core->anal->cb.on_fcn_delete = on_fcn_delete;
	core->anal->cb.on_fcn_rename = on_fcn_rename;
	core->print->sdb_types = core->anal->sdb_types;
	core->assembler->syscall = r_syscall_ref (core->anal->syscall); // BIND syscall anal/asm
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
	core->io->cb_core_post_write = core_post_write_callback;
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	core->flags = r_flag_new ();
	core->flags->cb_printf = r_cons_printf;
	core->graph = r_agraph_new (r_cons_canvas_new (1, 1));
	core->graph->need_reload_nodes = false;
	core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
	if (sizeof (ut64) * core->asmqjmps_size < core->asmqjmps_size) {
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
	r_core_bind (core, &(core->fs->cob));
	r_io_bind (core->io, &(core->bin->iob));
	r_flag_bind (core->flags, &(core->anal->flb));
	r_anal_bind (core->anal, &(core->parser->analb));

	r_core_bind (core, &(core->anal->coreb));

	core->file = NULL;
	core->files = r_list_newf ((RListFree)r_core_file_free);
	core->offset = 0LL;
	core->prompt_offset = 0LL;
	r_core_cmd_init (core);
	core->dbg = r_debug_new (true);

	r_io_bind (core->io, &(core->dbg->iob));
	r_io_bind (core->io, &(core->dbg->bp->iob));
	r_core_bind (core, &core->dbg->corebind);
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	//r_debug_use (core->dbg, "native");
// XXX pushing unititialized regstate results in trashed reg values
//	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->io->cb_printf = r_cons_printf;
	core->dbg->cb_printf = r_cons_printf;
	core->dbg->bp->cb_printf = r_cons_printf;
	// initialize config before any corebind
	r_core_config_init (core);

	r_core_loadlibs_init (core);
	//r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (core->assembler, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64) {
		r_config_set_i (core->config, "asm.bits", 64);
	} else {
		if (R_SYS_BITS & R_SYS_BITS_32) {
			r_config_set_i (core->config, "asm.bits", 32);
		}
	}
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH, core->anal->bits);
	update_sdb (core);
	{
		char *a = r_str_r2_prefix (R2_FLAGS);
		if (a) {
			char *file = r_str_newf ("%s/tags.r2", a);
			(void)r_core_run_script (core, file);
			free (file);
			free (a);
		}
	}
	init_autocomplete (core);
	return 0;
}

R_API void r_core_bind_cons(RCore *core) {
	core->cons->num = core->num;
	core->cons->cb_editor = (RConsEditorCallback)r_core_editor;
	core->cons->cb_break = (RConsBreakCallback)r_core_break;
	core->cons->cb_sleep_begin = (RConsSleepBeginCallback)r_core_sleep_begin;
	core->cons->cb_sleep_end = (RConsSleepEndCallback)r_core_sleep_end;
	core->cons->cb_task_oneshot = (RConsQueueTaskOneshot) r_core_task_enqueue_oneshot;
	core->cons->user = (void*)core;
}

R_API RCore *r_core_fini(RCore *c) {
	if (!c) {
		return NULL;
	}
	r_core_task_break_all (c);
	r_core_task_join (c, NULL, -1);
	r_core_wait (c);
	/* TODO: it leaks as shit */
	//update_sdb (c);
	// avoid double free
	r_core_free_autocomplete (c);
	r_event_free (c->ev);
	R_FREE (c->cmdlog);
	r_th_lock_free (c->lock);
	R_FREE (c->lastsearch);
	R_FREE (c->cons->pager);
	R_FREE (c->panels_tmpcfg);
	R_FREE (c->cmdqueue);
	R_FREE (c->lastcmd);
	r_list_free (c->visual.tabs);
	R_FREE (c->block);
	r_core_autocomplete_free (c->autocomplete);

	r_list_free (c->undos);
	r_num_free (c->num);
	// TODO: sync or not? sdb_sync (c->sdb);
	// TODO: sync all dbs?
	//r_core_file_free (c->file);
	//c->file = NULL;
	r_list_free (c->files);
	r_list_free (c->watchers);
	r_list_free (c->scriptstack);
	r_list_free (c->tasks);
	r_list_free (c->tasks_queue);
	r_list_free (c->oneshot_queue);
	r_th_lock_free (c->tasks_lock);
	c->rcmd = r_cmd_free (c->rcmd);
	r_list_free (c->cmd_descriptors);
	c->anal = r_anal_free (c->anal);
	c->assembler = r_asm_free (c->assembler);
	c->print = r_print_free (c->print);
	c->bin = r_bin_free (c->bin); // XXX segfaults rabin2 -c
	c->lang = r_lang_free (c->lang); // XXX segfaults
	c->dbg = r_debug_free (c->dbg);
	r_io_free (c->io);
	r_config_free (c->config);
	/* after r_config_free, the value of I.teefile is trashed */
	/* rconfig doesnt knows how to deinitialize vars, so we
	should probably need to add a r_config_free_payload callback */
	r_cons_free ();
	r_cons_singleton ()->teefile = NULL; // HACK
	r_search_free (c->search);
	r_flag_free (c->flags);
	r_fs_free (c->fs);
	r_egg_free (c->egg);
	r_lib_free (c->lib);
	r_buf_free (c->yank_buf);
	r_agraph_free (c->graph);
	R_FREE (c->asmqjmps);
	sdb_free (c->sdb);
	r_core_log_free (c->log);
	r_parse_free (c->parser);
	R_FREE (c->times);
	return NULL;
}

R_API RCore *r_core_free(RCore *c) {
	// must wait all threads first
	if (c) {
		r_core_fini (c);
		free (c);
	}
	return NULL;
}

R_API void r_core_prompt_loop(RCore *r) {
	int ret;
	do {
		if (r_core_prompt (r, false) < 1) {
			break;
		}
//			if (lock) r_th_lock_enter (lock);
		if ((ret = r_core_prompt_exec (r))==-1) {
			eprintf ("Invalid command\n");
		}
/*			if (lock) r_th_lock_leave (lock);
		if (rabin_th && !r_th_wait_async (rabin_th)) {
			eprintf ("rabin thread end \n");
			r_th_kill_free (rabin_th);
			r_th_lock_free (lock);
			lock = NULL;
			rabin_th = NULL;
		}
*/
	} while (ret != R_CORE_CMD_EXIT);
}

static int prompt_flag (RCore *r, char *s, size_t maxlen) {
	const char DOTS[] = "...";
	const RFlagItem *f = r_flag_get_at (r->flags, r->offset, false);
	if (!f) {
		return false;
	}
	if (f->offset < r->offset) {
		snprintf (s, maxlen, "%s + %" PFMT64u, f->name, r->offset - f->offset);
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
	const RBinSection *sec = r_bin_get_section_at (r_bin_cur_object (r->bin), r->offset, true);
	if (!sec) {
		return;
	}
	r_str_ncpy (s, sec->name, maxlen - 2);
	strcat (s, ":");
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
	char tmp[128];
	char *filename = strdup ("");
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");
	const char *BEGIN = "";
	const char *END = "";
	const char *remote = "";

	if (cmdprompt && *cmdprompt) {
		r_core_cmd (r, cmdprompt, 0);
	}

	if (r_config_get_i (r->config, "scr.prompt.file")) {
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
		unsigned int seggrn = r_config_get_i (r->config, "asm.seggrn");

		a = ((r->offset >> 16) << (16 - seggrn));
		b = (r->offset & 0xffff);
		snprintf (tmp, 128, "%04x:%04x", a, b);
	} else {
		char p[64], sec[32];
		int promptset = false;

		sec[0] = '\0';
		if (r_config_get_i (r->config, "scr.prompt.flag")) {
			promptset = prompt_flag (r, p, sizeof (p));
		}
		if (r_config_get_i (r->config, "scr.prompt.sect")) {
			prompt_sec (r, sec, sizeof (sec));
		}

		if (!promptset) {
			snprintf (p, sizeof (p), "0x%08" PFMT64x, r->offset);
		}
		snprintf (tmp, sizeof (tmp), "%s%s", sec, p);
	}

	chop_prompt (filename, tmp, 128);
	char *prompt = r_str_newf ("%s%s[%s%s]>%s ", filename, BEGIN, remote,
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
	if (ret == -2) {
		return R_CORE_CMD_EXIT; // ^D
	}
	if (ret == -1) {
		return false; // FD READ ERROR
	}
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
	//int ret = r_core_cmd (r, r->cmdqueue, true);
	if (r->cons && r->cons->use_tts) {
		const char *buf = r_cons_get_buffer();
		r_sys_tts (buf, true);
		r->cons->use_tts = false;
	}
	r_cons_flush ();
	if (r->cons && r->cons->line && r->cons->line->zerosep) {
		r_cons_zero ();
	}
	return ret;
}

R_API int r_core_seek_size(RCore *core, ut64 addr, int bsize) {
	ut8 *bump;
	int ret = false;
	if (bsize < 0) {
		return false;
	}
	if (bsize == core->blocksize) {
		return true;
	}
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
	core->offset = addr;
	if (bsize < 1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize>core->blocksize_max) {
		eprintf ("bsize is bigger than `bm`. dimmed to 0x%x > 0x%x\n",
			bsize, core->blocksize_max);
		bsize = core->blocksize_max;
	}
	bump = realloc (core->block, bsize + 1);
	if (!bump) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		ret = false;
	} else {
		ret = true;
		core->block = bump;
		core->blocksize = bsize;
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core);
	}
	return ret;
}

R_API int r_core_block_size(RCore *core, int bsize) {
	return r_core_seek_size (core, core->offset, bsize);
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int diff, inc = (times >= 0)? 1: -1;
	ut64 seek = core->offset;
	if (!align) {
		return false;
	}
	diff = core->offset%align;
	if (!times) {
		diff = -diff;
	} else if (diff) {
		if (inc > 0) {
			diff += align-diff;
		} else {
			diff = -diff;
		}
		if (times) {
			times -= inc;
		}
	}
	while ((times*inc) > 0) {
		times -= inc;
		diff += align*inc;
	}
	if (diff < 0 && -diff > seek) {
		seek = diff = 0;
	}
	return r_core_seek (core, seek+diff, 1);
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAsmOp op = {0};
	ut8 buf[64];
	r_asm_set_pc (core->assembler, addr);
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	int ret = r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
	char *str = (ret > 0)? strdup (r_strbuf_get (&op.buf_asm)): NULL;
	r_asm_op_fini (&op);
	return str;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr) {
	ut8 buf[64];
	RAnalOp *op = R_NEW (RAnalOp);
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	r_anal_op (core->anal, op, addr, buf, sizeof (buf), R_ANAL_OP_MASK_ALL);
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
R_API bool r_core_serve(RCore *core, RIODesc *file) {
	ut8 cmd, flg, *ptr = NULL, buf[1024];
	int i, pipefd = -1;
	ut64 x;

	RIORap *rior = (RIORap *)file->data;
	if (!rior|| !rior->fd) {
		eprintf ("rap: cannot listen.\n");
		return false;
	}
	RSocket *fd = rior->fd;
	eprintf ("RAP Server started (rap.loop=%s)\n",
			r_config_get (core->config, "rap.loop"));
	r_cons_break_push (rap_break, rior);
reaccept:
	while (!r_cons_is_breaked ()) {
		RSocket *c = r_socket_accept (fd);
		if (!c) {
			break;
		}
		if (r_cons_is_breaked ()) {
			goto out_of_function;
		}
		if (!c) {
			eprintf ("rap: cannot accept\n");
			r_socket_free (c);
			goto out_of_function;
		}
		eprintf ("rap: client connected\n");
		for (;!r_cons_is_breaked ();) {
			if (!r_socket_read (c, &cmd, 1)) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					r_socket_free (c);
					goto reaccept;
				}
				goto out_of_function;
			}
			switch ((ut8)cmd) {
			case RMT_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				eprintf ("open (%d): ", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				ptr = malloc (cmd + 1);
				//XXX cmd is ut8..so <256 if (cmd<RMT_MAX)
				if (!ptr) {
					eprintf ("Cannot malloc in rmt-open len = %d\n", cmd);
				} else {
					ut64 baddr = r_config_get_i (core->config, "bin.laddr");
					r_socket_read_block (c, ptr, cmd);
					ptr[cmd] = 0;
					ut32 perm = R_PERM_R;
					if (flg & R_PERM_W) {
						perm |= R_PERM_W;
					}
					if (r_core_file_open (core, (const char *)ptr, perm, 0)) {
						int fd = r_io_fd_get_current (core->io);
						r_core_bin_load (core, NULL, baddr);
						r_io_map_add (core->io, fd, perm, 0, 0, r_io_fd_size (core->io, fd));
						if (core->file) {
							pipefd = fd;
						} else {
							pipefd = -1;
						}
						eprintf ("(flags: %d) len: %d filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					} else {
						pipefd = -1;
						eprintf ("Cannot open file (%s)\n", ptr);
						r_socket_close (c);
						goto out_of_function; //XXX: Close conection and goto accept
					}
				}
				buf[0] = RMT_OPEN | RMT_REPLY;
				r_write_be32 (buf + 1, pipefd);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				free (ptr);
				ptr = NULL;
				break;
			case RMT_READ:
				r_socket_read_block (c, (ut8*)&buf, 4);
				i = r_read_be32 (buf);
				ptr = (ut8 *)malloc (i + core->blocksize + 5);
				if (ptr) {
					r_core_block_read (core);
					ptr[0] = RMT_READ | RMT_REPLY;
					if (i > RMT_MAX) {
						i = RMT_MAX;
					}
					if (i > core->blocksize) {
						r_core_block_size (core, i);
					}
					if (i + 128 < core->blocksize) {
						r_core_block_size (core, i);
					}
					r_write_be32 (ptr + 1, i);
					memcpy (ptr + 5, core->block, i); //core->blocksize);
					r_socket_write (c, ptr, i + 5);
					r_socket_flush (c);
					free (ptr);
					ptr = NULL;
				} else {
					eprintf ("Cannot read %d byte(s)\n", i);
					r_socket_free (c);
					// TODO: reply error here
					goto out_of_function;
				}
				break;
			case RMT_CMD:
				{
				char *cmd = NULL, *cmd_output = NULL;
				char bufr[8], *bufw = NULL;
				ut32 cmd_len = 0;
				int i;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				i = r_read_be32 (bufr);
				if (i > 0 && i < RMT_MAX) {
					if ((cmd = malloc (i + 1))) {
						r_socket_read_block (c, (ut8*)cmd, i);
						cmd[i] = '\0';
						eprintf ("len: %d cmd:'%s'\n", i, cmd);
						fflush (stdout);
						cmd_output = r_core_cmd_str (core, cmd);
						free (cmd);
					} else {
						eprintf ("rap: cannot malloc\n");
					}
				} else {
					eprintf ("rap: invalid length '%d'\n", i);
				}
				/* write */
				if (cmd_output) {
					cmd_len = strlen (cmd_output) + 1;
				} else {
					cmd_output = strdup ("");
					cmd_len = 0;
				}
#if DEMO_SERVER_SENDS_CMD_TO_CLIENT
				static bool once = true;
				/* TODO: server can reply a command request to the client only here */
				if (once) {
					const char *cmd = "pd 4";
					int cmd_len = strlen (cmd) + 1;
					ut8 *b = malloc (cmd_len + 5);
					b[0] = RMT_CMD;
					r_write_be32 (b + 1, cmd_len);
					strcpy ((char *)b+ 5, cmd);
					r_socket_write (c, b, 5 + cmd_len);
					r_socket_flush (c);

					/* read response */
					r_socket_read (c, b, 5);
					if (b[0] == (RMT_CMD | RMT_REPLY)) {
						ut32 n = r_read_be32 (b + 1);
						eprintf ("REPLY %d\n", n);
						if (n > 0) {
							ut8 *res = calloc (1, n);
							r_socket_read (c, res, n);
							eprintf ("RESPONSE(%s)\n", (const char *)res);
							free (res);
						}
					}
					r_socket_flush (c);
					free (b);
					once = false;
				}
#endif
				bufw = malloc (cmd_len + 5);
				bufw[0] = (ut8) (RMT_CMD | RMT_REPLY);
				r_write_be32 (bufw + 1, cmd_len);
				memcpy (bufw + 5, cmd_output, cmd_len);
				r_socket_write (c, bufw, cmd_len+5);
				r_socket_flush (c);
				free (bufw);
				free (cmd_output);
				break;
				}
			case RMT_WRITE:
				r_socket_read (c, buf, 4);
				x = r_read_at_be32 (buf, 0);
				ptr = malloc (x);
				r_socket_read (c, ptr, x);
				int ret = r_core_write_at (core, core->offset, ptr, x);
				buf[0] = RMT_WRITE | RMT_REPLY;
				r_write_be32 (buf + 1, ret);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				free (ptr);
				ptr = NULL;
				break;
			case RMT_SEEK:
				r_socket_read_block (c, buf, 9);
				x = r_read_at_be64 (buf, 1);
				if (buf[0] == 2) {
					if (core->file) {
						x = r_io_fd_size (core->io, core->file->fd);
					} else {
						x = 0;
					}
				} else {
					if (buf[0] == 0) {
						r_core_seek (core, x, 1); //buf[0]);
					}
					x = core->offset;
				}
				buf[0] = RMT_SEEK | RMT_REPLY;
				r_write_be64 (buf + 1, x);
				r_socket_write (c, buf, 9);
				r_socket_flush (c);
				break;
			case RMT_CLOSE:
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				i = r_read_be32 (buf);
				{
				//FIXME: Use r_socket_close
				int ret = close (i);
				r_write_be32 (buf + 1, ret);
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
				goto out_of_function;
			}
		}
		eprintf ("client: disconnected\n");
		r_socket_free (c);
	}
out_of_function:
	r_cons_break_pop ();
	return false;
}

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf;
	if ((buf = malloc (len))) {
		while (from < to) {
			ut64 delta = to-from;
			if (delta < len) {
				len = (int)delta;
			}
			if (!r_io_read_at (core->io, from, buf, len)) {
				eprintf ("Cannot read at 0x%"PFMT64x"\n", from);
				break;
			}
			for (ret = 0; ret < len;) {
				int done = cb (core, from, buf+ret, len-ret);
				if (done < 1) { /* interrupted */
					free (buf);
					return false;
				}
				ret += done;
			}
			from += len;
		}
		free (buf);
	} else {
		eprintf ("Cannot allocate blocksize\n");
	}
	return true;
}

R_API char *r_core_editor (const RCore *core, const char *file, const char *str) {
	const bool interactive = r_config_get_i (core->config, "scr.interactive");
	const char *editor = r_config_get (core->config, "cfg.editor");
	char *name = NULL, *ret = NULL;
	int len, fd;

	if (!interactive || !editor || !*editor) {
		return NULL;
	}
	if (file && *file != '*') {
		name = strdup (file);
		fd = r_sandbox_open (file, O_RDWR, 0644);
	} else {
		fd = r_file_mkstemp (file, &name);
	}
	if (fd == -1) {
		free (name);
		return NULL;
	}
	if (str) {
		write (fd, str, strlen (str));
	}
	close (fd);

	if (name && (!editor || !*editor || !strcmp (editor, "-"))) {
		RCons *cons = r_cons_singleton ();
		void *tmp = cons->cb_editor;
		cons->cb_editor = NULL;
		r_cons_editor (name, NULL);
		cons->cb_editor = tmp;
	} else {
		if (editor && name) {
			r_sys_cmdf ("%s '%s'", editor, name);
		}
	}
	ret = name? r_file_slurp (name, &len): 0;
	if (ret) {
		if (len && ret[len - 1] == '\n') {
			ret[len - 1] = 0; // chop
		}
		if (!file) {
			r_file_rm (name);
		}
	}
	free (name);
	return ret;
}

/* weak getters */
R_API RCons *r_core_get_cons (RCore *core) {
	return core->cons;
}

R_API RConfig *r_core_get_config (RCore *core) {
	return core->config;
}

R_API RBin *r_core_get_bin (RCore *core) {
	return core->bin;
}

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
	RBuffer *b = NULL;
	char code[1024];
	int num;

	//arch check
	if (strcmp (core->anal->cur->arch, "x86")) {
		eprintf ("architecture not yet supported!\n");
		return 0;
	}

	num = r_syscall_get_num (core->anal->syscall, name);

	//bits check
	switch (core->assembler->bits) {
	case 32:
		if (strcmp (name, "setup") && !num ) {
			eprintf ("syscall not found!\n");
			return 0;
		}
		break;
	case 64:
		if (strcmp (name, "read") && !num ) {
			eprintf ("syscall not found!\n");
			return 0;
		}
		break;
	default:
		eprintf ("syscall not found!\n");
		return 0;
	}

	snprintf (code, sizeof (code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%s);\n"
		":int3\n" /// XXX USE trap
		"}\n", num, args);
	r_egg_reset (core->egg);
	// TODO: setup arch/bits/os?
	r_egg_load (core->egg, code, 0);

	if (!r_egg_compile (core->egg)) {
		eprintf ("Cannot compile.\n");
	}
	if (!r_egg_assemble (core->egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
	}
	if ((b = r_egg_get_bin (core->egg))) {
#if 0
		if (b->length > 0) {
			for (i = 0; i < b->length; i++) {
				r_cons_printf ("%02x", b->buf[i]);
			}
			r_cons_printf ("\n");
		}
#endif
	}
	return b;
}

static bool isValidAddress (RCore *core, ut64 addr) {
	// check if address is mapped
	RIOMap* map = r_io_map_get (core->io, addr);
	if (!map) {
		return false;
	}
	st64 fdsz = (st64)r_io_fd_size (core->io, map->fd);
	if (fdsz > 0 && map->delta > fdsz) {
		return false;
	}
	// check if associated file is opened
	RIODesc *desc = r_io_desc_get (core->io, map->fd);
	if (!desc) {
		return false;
	}
	// check if current map->fd is null://
	if (!strncmp (desc->name, "null://", 7)) {
		return false;
	}
	return true;
}

R_API int r_core_search_value_in_range(RCore *core, RInterval search_itv, ut64 vmin,
				     ut64 vmax, int vsize, bool asterisk, inRangeCb cb) {
	int i, match, align = core->search->align, hitctr = 0;
	bool vinfun = r_config_get_i (core->config, "anal.vinfun");
	bool vinfunr = r_config_get_i (core->config, "anal.vinfunrange");
	ut8 buf[4096];
	ut64 v64, value = 0, size;
	ut64 from = search_itv.addr, to = r_itv_end (search_itv);
	ut32 v32;
	ut16 v16;
	if (from >= to) {
		eprintf ("Error: from must be lower than to\n");
		return -1;
	}
	bool maybeThumb = false;
	if (align && core->anal->cur && core->anal->cur->arch) {
		if (!strcmp (core->anal->cur->arch, "arm") && core->anal->bits != 64) {
			maybeThumb = true;
		}
	}

	if (vmin >= vmax) {
		eprintf ("Error: vmin must be lower than vmax\n");
		return -1;
	}
	if (to == UT64_MAX) {
		eprintf ("Error: Invalid destination boundary\n");
		return -1;
	}
	r_cons_break_push (NULL, NULL);

	while (from < to) {
		size = R_MIN (to - from, sizeof (buf));
		memset (buf, 0xff, sizeof (buf)); // probably unnecessary
		if (r_cons_is_breaked ()) {
			goto beach;
		}
		bool res = r_io_read_at_mapped (core->io, from, buf, size);
		if (!res || !memcmp (buf, "\xff\xff\xff\xff", 4) || !memcmp (buf, "\x00\x00\x00\x00", 4)) {
			if (!isValidAddress (core, from)) {
				ut64 next = r_io_map_next_address (core->io, from);
				if (next == UT64_MAX) {
					from += sizeof (buf);
				} else {
					from += (next - from);
				}
				continue;
			}
		}
		for (i = 0; i <= (size - vsize); i++) {
			void *v = (buf + i);
			ut64 addr = from + i;
			if (r_cons_is_breaked ()) {
				goto beach;
			}
			if (align && (addr) % align) {
				continue;
			}
			match = false;
			int left = size - i;
			if (vsize > left) {
				break;
			}
			switch (vsize) {
			case 1: value = *(ut8 *)v; match = (buf[i] >= vmin && buf[i] <= vmax); break;
			case 2: v16 = *(uut16 *)v; match = (v16 >= vmin && v16 <= vmax); value = v16; break;
			case 4: v32 = *(uut32 *)v; match = (v32 >= vmin && v32 <= vmax); value = v32; break;
			case 8: v64 = *(uut64 *)v; match = (v64 >= vmin && v64 <= vmax); value = v64; break;
			default: eprintf ("Unknown vsize %d\n", vsize); return -1;
			}
			if (match && !vinfun) {
				if (vinfunr) {
					if (r_anal_get_fcn_in_bounds (core->anal, addr, R_ANAL_FCN_TYPE_NULL)) {
						match = false;
					}
				} else {
					if (r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL)) {
						match = false;
					}
				}
			}
			if (match && value) {
				bool isValidMatch = true;
				if (align && (value % align)) {
					// ignored .. unless we are analyzing arm/thumb and lower bit is 1
					isValidMatch = false;
					if (maybeThumb && (value & 1)) {
						isValidMatch = true;
					}
				}
				if (isValidMatch) {
					cb (core, addr, value, vsize, asterisk, hitctr);
					hitctr++;
				}
			}
		}
		if (size == to-from) {
			break;
		}
		from += size-vsize+1;
	}
beach:
	r_cons_break_pop ();
	return hitctr;
}

R_API RCoreAutocomplete *r_core_autocomplete_add(RCoreAutocomplete *parent, const char* cmd, int type, bool lock) {
	if (!parent || !cmd || type < 0 || type >= R_CORE_AUTOCMPLT_END) {
		return NULL;
	}
	RCoreAutocomplete *autocmpl = R_NEW0 (RCoreAutocomplete);
	if (!autocmpl) {
		return NULL;
	}
	RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds + 1) * sizeof(RCoreAutocomplete**));
	if (!updated) {
		free (autocmpl);
		return NULL;
	}
	parent->subcmds = updated;
	parent->subcmds[parent->n_subcmds] = autocmpl;
	parent->n_subcmds++;
	autocmpl->cmd = strdup (cmd);
	autocmpl->locked = lock;
	autocmpl->type = type;
	autocmpl->length = strlen (cmd);
	return autocmpl;
}

R_API void r_core_autocomplete_free(RCoreAutocomplete *obj) {
	if (!obj) {
		return;
	}
	int i;
	for (i = 0; i < obj->n_subcmds; ++i) {
		r_core_autocomplete_free (obj->subcmds[i]);
		obj->subcmds[i] = NULL;
	}
	free (obj->subcmds);
	free ((char*) obj->cmd);
	free (obj);
}

R_API RCoreAutocomplete *r_core_autocomplete_find(RCoreAutocomplete *parent, const char* cmd, bool exact) {
	if (!parent || !cmd) {
		return false;
	}
	int len = strlen (cmd);
	int i;
	for (i = 0; i < parent->n_subcmds; ++i) {
		if (exact && len == parent->subcmds[i]->length && !strncmp (cmd, parent->subcmds[i]->cmd, len)) {
			return parent->subcmds[i];
		} else if (!exact && !strncmp (cmd, parent->subcmds[i]->cmd, len)) {
			return parent->subcmds[i];
		}
	}
	return NULL;
}

R_API bool r_core_autocomplete_remove(RCoreAutocomplete *parent, const char* cmd) {
	if (!parent || !cmd) {
		return false;
	}
	int i, j;
	for (i = 0; i < parent->n_subcmds; i++) {
		RCoreAutocomplete *ac = parent->subcmds[i];
		if (ac->locked) {
			continue;
		}
		// if (!strncmp (parent->subcmds[i]->cmd, cmd, parent->subcmds[i]->length)) {
		if (r_str_glob (ac->cmd, cmd)) {
			for (j = i + 1; j < parent->n_subcmds; ++j) {
				parent->subcmds[j - 1] = parent->subcmds[j];
				parent->subcmds[j] = NULL;
			}
			r_core_autocomplete_free (ac);
			RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds - 1) * sizeof (RCoreAutocomplete*));
			if (!updated && (parent->n_subcmds - 1) > 0) {
				eprintf ("Something really bad has happen.. this should never ever happen..\n");
				return false;
			}
			parent->subcmds = updated;
			parent->n_subcmds--;
			i--;
		}
	}
	return false;
}
