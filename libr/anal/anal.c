/* radare - LGPL - Copyright 2009-2017 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include <config.h>

R_LIB_VERSION(r_anal);

static RAnalPlugin *anal_static_plugins[] = {
	R_ANAL_STATIC_PLUGINS
};

R_API void r_anal_set_limits(RAnal *anal, ut64 from, ut64 to) {
	free (anal->limit);
	anal->limit = R_NEW0 (RAnalRange);
	if (anal->limit) {
		anal->limit->from = from;
		anal->limit->to = to;
	}
}

R_API void r_anal_unset_limits(RAnal *anal) {
	R_FREE (anal->limit);
}

static void meta_unset_for(void *user, int idx) {
	RSpaces *s = (RSpaces*)user;
	RAnal *anal = (RAnal*)s->user;
	r_meta_space_unset_for (anal, idx);
}

static int meta_count_for(void *user, int idx) {
	RSpaces *s = (RSpaces*)user;
	RAnal *anal = (RAnal*)s->user;
	return r_meta_space_count_for (anal, idx);
}

static void zign_unset_for(void *user, int idx) {
	RSpaces *s = (RSpaces*)user;
	RAnal *anal = (RAnal*)s->user;
	r_sign_space_unset_for (anal, idx);
}

static int zign_count_for(void *user, int idx) {
	RSpaces *s = (RSpaces*)user;
	RAnal *anal = (RAnal*)s->user;
	return r_sign_space_count_for (anal, idx);
}

static void zign_rename_for(void *user, int idx, const char *oname, const char *nname) {
	RSpaces *s = (RSpaces*)user;
	RAnal *anal = (RAnal*)s->user;
	r_sign_space_rename_for (anal, idx, oname, nname);
}

R_API RAnal *r_anal_new() {
	int i;
	RAnal *anal = R_NEW0 (RAnal);
	if (!anal) {
		return NULL;
	}
	anal->os = strdup (R_SYS_OS);
	anal->reflines = anal->reflines2 = NULL;
	anal->esil_goto_limit = R_ANAL_ESIL_GOTO_LIMIT;
	anal->limit = NULL;
	anal->opt.nopskip = true; // skip nops in code analysis
	anal->opt.hpskip = false; // skip `mov reg,reg` and `lea reg,[reg]`
	anal->decode = true; // slow slow if not used
	anal->gp = 0LL;
	anal->sdb = sdb_new0 ();
	anal->opt.noncode = false; // do not analyze data by default
	r_space_new (&anal->meta_spaces, "CS", meta_unset_for, meta_count_for, NULL, anal);
	r_space_new (&anal->zign_spaces, "zs", zign_unset_for, zign_count_for, zign_rename_for, anal);
	anal->sdb_fcns = sdb_ns (anal->sdb, "fcns", 1);
	anal->sdb_meta = sdb_ns (anal->sdb, "meta", 1);
	anal->sdb_hints = sdb_ns (anal->sdb, "hints", 1);
	anal->sdb_xrefs = sdb_ns (anal->sdb, "xrefs", 1);
	anal->sdb_types = sdb_ns (anal->sdb, "types", 1);
	anal->sdb_cc = sdb_ns (anal->sdb, "cc", 1);
	anal->sdb_zigns = sdb_ns (anal->sdb, "zigns", 1);
	anal->cb_printf = (PrintfCallback) printf;
	(void)r_anal_pin_init (anal);
	(void)r_anal_xrefs_init (anal);
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->split = true; // used from core
	anal->syscall = r_syscall_new ();
	r_io_bind_init (anal->iob);
	r_flag_bind_init (anal->flb);
	anal->reg = r_reg_new ();
	anal->last_disasm_reg = NULL;
	anal->stackptr = 0;
	anal->bits_ranges = r_list_newf (free);
	anal->lineswidth = 0;
	anal->fcns = r_anal_fcn_list_new ();
#if USE_NEW_FCN_STORE
	anal->fcnstore = r_listrange_new ();
#endif
	anal->refs = r_anal_ref_list_new ();
	anal->types = r_anal_type_list_new ();
	r_anal_set_bits (anal, 32);
	anal->plugins = r_list_newf ((RListFree) r_anal_plugin_free);
	if (anal->plugins) {
		for (i = 0; anal_static_plugins[i]; i++) {
			r_anal_add (anal, anal_static_plugins[i]);
		}
	}
	return anal;
}

R_API void r_anal_plugin_free (RAnalPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

R_API RAnal *r_anal_free(RAnal *a) {
	if (!a) {
		return NULL;
	}
	/* TODO: Free anals here */
	R_FREE (a->cpu);
	R_FREE (a->os);
	R_FREE (a->zign_path);
	r_list_free (a->plugins);
	a->fcns->free = r_anal_fcn_free;
	r_list_free (a->fcns);
	r_space_free (&a->meta_spaces);
	r_space_free (&a->zign_spaces);
	r_anal_pin_fini (a);
	r_list_free (a->refs);
	r_list_free (a->types);
	r_reg_free (a->reg);
	r_anal_op_free (a->queued);
	r_list_free (a->bits_ranges);
	a->sdb = NULL;
	r_syscall_free (a->syscall);
	sdb_ns_free (a->sdb);
	if (a->esil) {
		r_anal_esil_free (a->esil);
		a->esil = NULL;
	}
	free (a->last_disasm_reg);
	memset (a, 0, sizeof (RAnal));
	free (a);
	return NULL;
}

R_API void r_anal_set_user_ptr(RAnal *anal, void *user) {
	anal->user = user;
}

R_API int r_anal_add(RAnal *anal, RAnalPlugin *foo) {
	if (foo->init) {
		foo->init (anal->user);
	}
	r_list_append (anal->plugins, foo);
	return true;
}

// TODO: Must be deprecated
R_API void r_anal_list(RAnal *anal) {
	RAnalPlugin *h;
	RListIter *it;
	r_list_foreach (anal->plugins, it, h) {
		anal->cb_printf ("anal %-10s %s\n", h->name, h->desc);
	}
}

R_API bool r_anal_use(RAnal *anal, const char *name) {
	RListIter *it;
	RAnalPlugin *h;

	bool change = anal && anal->cur && strcmp (anal->cur->name, name);
	r_list_foreach (anal->plugins, it, h) {
		if (!strcmp (h->name, name)) {
#if 0
			// regression happening here for asm.emu
			if (anal->cur && anal->cur == h) {
				return true;
			}
#endif
			anal->cur = h;
			r_anal_set_reg_profile (anal);
			if (change) {
				r_anal_set_fcnsign (anal, NULL);
			}
#if 1
			/* invalidate esil state? really ? */
			if (anal->esil) {
				r_anal_esil_free (anal->esil);
				anal->esil = NULL;
			}
#endif
			return true;
		}
	}
	return false;
}

R_API char *r_anal_get_reg_profile(RAnal *anal) {
	return (anal && anal->cur && anal->cur->get_reg_profile)
		? anal->cur->get_reg_profile (anal) : NULL;
}

// deprecate.. or at least reuse get_reg_profile...
R_API bool r_anal_set_reg_profile(RAnal *anal) {
	bool ret = false;
	if (anal && anal->cur && anal->cur->set_reg_profile) {
		ret = anal->cur->set_reg_profile (anal);
	} else {
		char *p = r_anal_get_reg_profile (anal);
		if (p && *p) {
			r_reg_set_profile_string (anal->reg, p);
			ret = true;
		}
		free (p);
	}
	return ret;
}

R_API bool r_anal_set_fcnsign(RAnal *anal, const char *name) {
#define FCNSIGNPATH R2_PREFIX "/share/radare2/" R2_VERSION "/fcnsign"
	char *file = NULL;
	const char *arch = (anal->cur && anal->cur->arch) ? anal->cur->arch : R_SYS_ARCH;
	if (name && *name) {
		file = sdb_fmt (0, "%s/%s.sdb", FCNSIGNPATH, name);
	} else {
		file = sdb_fmt (0, "%s/%s-%s-%d.sdb", FCNSIGNPATH,
			anal->os, arch, anal->bits);
	}
	if (r_file_exists (file)) {
		sdb_close (anal->sdb_fcnsign);
		sdb_free (anal->sdb_fcnsign);
		anal->sdb_fcnsign = sdb_new (0, file, 0);
		sdb_ns_set (anal->sdb, "fcnsign", anal->sdb_fcnsign);
		return (anal->sdb_fcnsign != NULL);
	}
	return false;
}

R_API const char *r_anal_get_fcnsign(RAnal *anal, const char *sym) {
	return sdb_const_get (anal->sdb_fcnsign, sym, 0);
}

R_API int r_anal_set_triplet(RAnal *anal, const char *os, const char *arch, int bits) {
	if (!os || !*os) {
		os = R_SYS_OS;
	}
	if (!arch || !*arch) {
		arch = anal->cur? anal->cur->arch: R_SYS_ARCH;
	}
	if (bits < 1) {
		bits = anal->bits;
	}
	free (anal->os);
	anal->os = strdup (os);
	r_anal_set_bits (anal, bits);
	return r_anal_use (anal, arch);
}

R_API bool r_anal_set_os(RAnal *anal, const char *os) {
	return r_anal_set_triplet (anal, os, NULL, -1);
}

R_API bool r_anal_set_bits(RAnal *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 32:
	case 64:
		if (anal->bits != bits) {
			anal->bits = bits;
			r_anal_set_fcnsign (anal, NULL);
			r_anal_set_reg_profile (anal);
		}
		return true;
	}
	return false;
}

R_API void r_anal_set_cpu(RAnal *anal, const char *cpu) {
	free (anal->cpu);
	anal->cpu = cpu ? strdup (cpu) : NULL;
}

R_API int r_anal_set_big_endian(RAnal *anal, int bigend) {
	anal->big_endian = bigend;
	anal->reg->big_endian = bigend;
	return true;
}

R_API ut8 *r_anal_mask(RAnal *anal, int size, const ut8 *data, ut64 at) {
	RAnalOp *op = NULL;
	ut8 *ret = NULL;
	int oplen, idx = 0;

	if (!data) {
		return NULL;
	}

	if (anal->cur && anal->cur->anal_mask) {
		return anal->cur->anal_mask (anal, size, data, at);
	}

	op = r_anal_op_new ();
	ret = malloc (size);
	memset (ret, 0xff, size);

	while (idx < size) {
		if ((oplen = r_anal_op (anal, op, at, data + idx, size - idx)) < 1) {
			break;
		}
		if ((op->ptr != UT64_MAX || op->jump != UT64_MAX) && op->nopcode != 0) {
			memset (ret + idx + op->nopcode, 0, oplen - op->nopcode);
		}
		idx += oplen;
	}

	free (op);

	return ret;
}

R_API void r_anal_trace_bb(RAnal *anal, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFunction *fcni;
	RListIter *iter2;
	fcni = r_anal_get_fcn_in (anal, addr, 0);
	if (fcni) {
		r_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr >= bbi->addr && addr < (bbi->addr + bbi->size)) {
				bbi->traced = true;
				break;
			}
		}
	}
}

R_API RList* r_anal_get_fcns (RAnal *anal) {
	// avoid received to free this thing
	anal->fcns->free = NULL;
	return anal->fcns;
}

R_API bool r_anal_project_save(RAnal *anal, const char *prjfile) {
	if (prjfile && *prjfile) {
		return r_anal_xrefs_save (anal, prjfile);
	}
	return false;
}

R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr, const char *str) {
	int len;
	ut8 *buf;
	RAnalOp *op = R_NEW0 (RAnalOp);
	if (!op) {
		return NULL;
	}
	buf = calloc (1, strlen (str) + 1);
	if (!buf) {
		free (op);
		return NULL;
	}
	len = r_hex_str2bin (str, buf);
	r_anal_op (anal, op, addr, buf, len);
	free (buf);
	return op;
}

R_API bool r_anal_op_is_eob (RAnalOp *op) {
	if (op->eob) {
		return true;
	}
	switch (op->type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_TRAP:
		return true;
	default:
		return false;
	}
}

R_API int r_anal_purge (RAnal *anal) {
	sdb_reset (anal->sdb_fcns);
	sdb_reset (anal->sdb_meta);
	sdb_reset (anal->sdb_hints);
	sdb_reset (anal->sdb_xrefs);
	sdb_reset (anal->sdb_types);
	sdb_reset (anal->sdb_zigns);
	r_list_free (anal->fcns);
	anal->fcns = r_anal_fcn_list_new ();
#if USE_NEW_FCN_STORE
	r_listrange_free (anal->fcnstore);
	anal->fcnstore = r_listrange_new ();
#endif
	r_list_free (anal->refs);
	anal->refs = r_anal_ref_list_new ();
	r_list_free (anal->types);
	anal->types = r_anal_type_list_new ();
	return 0;
}

R_API int r_anal_archinfo(RAnal *anal, int query) {
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	case R_ANAL_ARCHINFO_ALIGN:
		if (anal && anal->cur && anal->cur->archinfo) {
			return anal->cur->archinfo (anal, query);
		}
		break;
	}
	return -1;
}

static int nonreturn_print_commands(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strncmp (v, "func", strlen ("func") + 1)) {
		char *query = sdb_fmt (-1, "func.%s.noreturn", k);
		if (sdb_bool_get (anal->sdb_types, query, NULL)) {
			anal->cb_printf ("tnn %s\n", k);
		}
	}
	if (!strncmp (k, "addr.", 5)) {
		anal->cb_printf ("tna 0x%s %s\n", k + 5, v);
	}
	return 1;
}

static int nonreturn_print(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strncmp (v, "func", strlen ("func") + 1)) {
		const char *query = sdb_fmt (-1, "func.%s.noreturn", k);
		if (sdb_bool_get (anal->sdb_types, query, NULL)) {
			anal->cb_printf ("%s\n", k);
		}
	}
	if (!strncmp (k, "addr.", 5)) {
		char *off = strdup (k + 5);
		char *ptr = strstr (off, ".noret");
		if (ptr) {
			*ptr = 0;
			anal->cb_printf ("0x%s\n", off);
		}
		free (off);
	}
	return 1;
}

R_API void r_anal_noreturn_list(RAnal *anal, int mode) {
	switch (mode) {
	case 1:
	case '*':
	case 'r':
		sdb_foreach (anal->sdb_types, nonreturn_print_commands, anal);
		break;
	default:
		sdb_foreach (anal->sdb_types, nonreturn_print, anal);
		break;
	}
}

#define K_NORET_ADDR(x) sdb_fmt (-1, "addr.%"PFMT64x".noreturn", x)
#define K_NORET_FUNC(x) sdb_fmt (-1, "func.%s.noreturn", x)

R_API bool r_anal_noreturn_add(RAnal *anal, const char *name, ut64 addr) {
	const char *tmp_name = NULL;
	char *fnl_name = NULL;
	if (sdb_bool_set (anal->sdb_types, K_NORET_ADDR (addr), true, 0)) {
		return true;
	}
	if (name && *name) {
		tmp_name = name;
	} else {
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, -1);
		RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
		if (!fcn && !fi) {
			eprintf ("Cant find Function at given address\n");
			return false;
		}
		tmp_name = fcn ? fcn->name: fi->name;
	}
	if (r_anal_type_func_exist (anal, tmp_name)) {
		fnl_name = strdup (tmp_name);
	} else if (!(fnl_name = r_anal_type_func_guess (anal, (char *)tmp_name))) {
		eprintf ("Cant find prototype for %s in types databse\n", tmp_name);
		return false;
	}
	sdb_bool_set (anal->sdb_types, K_NORET_FUNC(fnl_name), true, 0);
	free (fnl_name);
	return true;
}

static int noreturn_dropall(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strcmp (v, "func")) {
		sdb_unset (anal->sdb_types, K_NORET_FUNC(k), 0);
	}
	return 1;
}

R_API int r_anal_noreturn_drop(RAnal *anal, const char *expr) {
	if (!strcmp (expr, "*")) {
		sdb_foreach (anal->sdb_types, noreturn_dropall, anal);
		return true;
	} else {
		const char *fcnname = NULL;
		char *tmp;
		if (!strncmp (expr, "0x", 2)) {
			ut64 n = r_num_math (NULL, expr);
			RAnalFunction *fcn = r_anal_get_fcn_in (anal, n, -1);
			if (!fcn) {
				eprintf ("can't find function at 0x%"PFMT64x"\n", n);
				return false;
			}
			fcnname = fcn->name;
		} else {
			fcnname = expr;
		}
		if (r_anal_type_func_exist (anal, fcnname)) {
			sdb_unset (anal->sdb_types, K_NORET_FUNC (fcnname), 0);
			return true;
		} else if ((tmp = r_anal_type_func_guess (anal, (char *)fcnname))) {
			sdb_unset (anal->sdb_types, K_NORET_FUNC (fcnname), 0);
			free (tmp);
			return true;
		} else {
			eprintf ("Cant find prototype for %s in types databse", fcnname);
			return false;
		}
	}
}
static bool r_anal_noreturn_at_name(RAnal *anal, const char *name) {
	if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC(name), NULL)) {
		return true;
	}
	char *tmp = r_anal_type_func_guess (anal, (char *)name);
	if (tmp) {
		if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC(tmp), NULL)) {
			free (tmp);
			return true;
		}
		free (tmp);
	}
	return false;
}

R_API bool r_anal_noreturn_at_addr(RAnal *anal, ut64 addr) {
	if (sdb_bool_get (anal->sdb_types, K_NORET_ADDR(addr), NULL)) {
		return true;
	}
	return false;
}

R_API bool r_anal_noreturn_at(RAnal *anal, ut64 addr) {
	if (r_anal_noreturn_at_addr (anal, addr)) {
		return true;
	}
	/* XXX this is very slow */
	RAnalFunction *f = r_anal_get_fcn_at (anal, addr, 0);
	if (f) {
		if (r_anal_noreturn_at_name (anal, f->name)) {
			return true;
		}
	}
	int oss = anal->flb.f->space_strict;
	int ofs = anal->flb.f->space_idx;
	anal->flb.set_fs (anal->flb.f, "imports");
	anal->flb.f->space_strict = true;
	RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
	if (!fi) {
		anal->flb.set_fs (anal->flb.f, "symbols");
		fi = anal->flb.get_at (anal->flb.f, addr, false);
	}
	anal->flb.f->space_idx = ofs;
	anal->flb.f->space_strict = oss;
	if (fi) {
		if (r_anal_noreturn_at_name (anal, fi->name)) {
			return true;
		}
	}
	return false;
}

// based on anal hint we construct a list of RAnalRange to handle
// better arm/thumb though maybe handy in other contexts
R_API void r_anal_build_range_on_hints(RAnal *a) {
	if (a->bits_hints_changed) {
		SdbListIter *iter;
		RListIter *it;
		SdbKv *kv;
		RAnalRange *range;
		int range_bits = 0;
		// construct again the range from hint to handle properly arm/thumb
		r_list_free (a->bits_ranges);
		a->bits_ranges = r_list_newf ((RListFree)free);
		SdbList *sdb_range = sdb_foreach_list (a->sdb_hints, true);
		//just grab when hint->bit changes with the previous one
		ls_foreach (sdb_range, iter, kv) {
			RAnalHint *hint = r_anal_hint_from_string (a, sdb_atoi (kv->key + 5), kv->value);
			if (hint->bits && range_bits != hint->bits) {
				RAnalRange *range = R_NEW0 (RAnalRange);
				if (range) {
					range->bits = hint->bits;
					range->from = hint->addr;
					range->to = UT64_MAX;
					r_list_append (a->bits_ranges, range);
				}
			} else {
				//remove this hint is not needed
				r_anal_hint_unset_bits (a, hint->addr);
			}
			range_bits = hint->bits;
			r_anal_hint_free (hint);
		}
		//close ranges addr
		r_list_foreach (a->bits_ranges, it, range) {
			if (it->n && it->n->data) {
				range->to = ((RAnalRange *)(it->n->data))->from;
			}
		}
		ls_free (sdb_range);
		a->bits_hints_changed = false;
	}
}

R_API void r_anal_bind(RAnal *anal, RAnalBind *b) {
	if (b) {
		b->anal = anal;
		b->get_fcn_in = r_anal_get_fcn_in;
	}
}
