/* radare - LGPL - Copyright 2009-2025 - pancake, nibble */

#include <r_anal.h>
#include <config.h>
#include "../config.h"

R_LIB_VERSION(r_anal);

#define DEFAULT_FCNPREFIX_RADIUS 0x1000

static RAnalPlugin *anal_static_plugins[] = {
	R_ANAL_STATIC_PLUGINS
};

static const char *r_anal_choose_fcnprefix(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, "fcn");

	const char *defpfx = anal->opt.defprefix;
	if (R_STR_ISEMPTY (defpfx)) {
		defpfx = "fcn";
	}
	if (!anal->opt.dynprefix || !anal->flb.f) {
		return defpfx;
	}
	if (!anal->flb.f) {
		return defpfx;
	}
	const char *marker = anal->opt.prefix_marker;
	if (R_STR_ISEMPTY (marker)) {
		marker = "pfx.fcn.";
	}
	ut64 radius = anal->opt.prefix_radius ? anal->opt.prefix_radius : DEFAULT_FCNPREFIX_RADIUS;
#if 0
	RFlagItem *fi = r_flag_closest_in_space (anal->flb.f, "prefix", addr, radius);
	if (fi && !r_str_startswith (fi->name, marker)) {
		return defpfx;
	}
#else
	// Find closest flag in "prefix" space and validate marker
	RFlagItem *fi = r_flag_closest_with_prefix (anal->flb.f, marker, addr, radius);
#endif
	if (!fi || R_STR_ISEMPTY (fi->name)) {
		return defpfx;
	}
	const char *suffix = fi->name + strlen (marker);
	return *suffix? suffix: defpfx;
}

R_API void r_anal_set_limits(RAnal *anal, ut64 from, ut64 to) {
	free (anal->limit);
	anal->limit = R_NEW0 (RAnalRange);
	anal->limit->from = from;
	anal->limit->to = to;
}

R_API void r_anal_unset_limits(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	R_FREE (anal->limit);
}

static void meta_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_meta_space_unset_for (anal, se->data.unset.space);
}

static void meta_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = r_meta_space_count_for (anal, se->data.count.space);
}

static void zign_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_sign_space_unset_for (anal, se->data.unset.space);
}

static void zign_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = r_sign_space_count_for (anal, se->data.count.space);
}

static void zign_rename_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_sign_space_rename_for (anal, se->data.rename.space,
		se->data.rename.oldname, se->data.rename.newname);
}

void r_anal_hint_storage_init(RAnal *a);
void r_anal_hint_storage_fini(RAnal *a);

static void r_meta_item_free(void *_item) {
	if (_item) {
		RAnalMetaItem *item = _item;
		free (item->str);
		free (item);
	}
}

// Take nullable RArchConfig as argument?
R_API RAnal *r_anal_new(void) {
	int i;
	RAnal *anal = R_NEW0 (RAnal);
	if (!r_str_constpool_init (&anal->constpool)) {
		free (anal);
		return NULL;
	}
	anal->cmpval = UT64_MAX;
	anal->lea_jmptbl_ip = UT64_MAX;
	anal->bb_tree = NULL;
	anal->ht_addr_fun = ht_up_new0 ();
	anal->ht_name_fun = ht_pp_new0 ();
	anal->config = r_arch_config_new ();
	anal->arch = r_arch_new ();
	anal->esil_goto_limit = R_ESIL_GOTO_LIMIT;
	anal->opt.nopskip = true; // skip nops in code analysis
	anal->opt.hpskip = false; // skip `mov reg,reg` and `lea reg,[reg]`
	anal->gp = 0LL;
	anal->sdb = sdb_new0 ();
	anal->cxxabi = R_ANAL_CPP_ABI_ITANIUM;
	anal->opt.depth = 32;
	anal->opt.noncode = false; // do not analyze data by default
	anal->lock = r_th_lock_new (true);
	r_anal_backtrace_init (anal);
	r_spaces_init (&anal->meta_spaces, "CS");
	r_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_UNSET, meta_unset_for, NULL);
	r_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_COUNT, meta_count_for, NULL);

	r_spaces_init (&anal->zign_spaces, "zs");
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_UNSET, zign_unset_for, NULL);
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_COUNT, zign_count_for, NULL);
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_RENAME, zign_rename_for, NULL);
	r_anal_hint_storage_init (anal);
	anal->threads = r_list_newf (free);
	r_interval_tree_init (&anal->meta, r_meta_item_free);
	anal->sdb_types = sdb_ns (anal->sdb, "types", 1);
	anal->sdb_fmts = sdb_ns (anal->sdb, "spec", 1);
	anal->sdb_cc = sdb_ns (anal->sdb, "cc", 1);
	anal->sdb_zigns = sdb_ns (anal->sdb, "zigns", 1);
	anal->sdb_classes = sdb_ns (anal->sdb, "classes", 1);
	anal->sdb_classes_attrs = sdb_ns (anal->sdb_classes, "attrs", 1);
	anal->zign_path = strdup ("");
	anal->cb_printf = (PrintfCallback) printf;
	anal->esil = r_esil_new (4096, 0, 1);
	anal->esil->anal = anal;
	(void)r_anal_pin_init (anal);
	(void)r_anal_xrefs_init (anal);
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->syscall = r_syscall_new ();
	r_flag_bind_init (anal->flb);
	anal->reg = r_reg_new ();
	anal->last_disasm_reg = NULL;
	anal->stackptr = 0;
	anal->lineswidth = 0;
	anal->fcns = r_list_newf ((RListFree)r_anal_function_free);
	anal->leaddrs = NULL;
	anal->imports = r_list_newf (free);
	anal->plugins = r_list_newf ((RListFree) r_anal_plugin_free);
	if (anal->plugins) {
		for (i = 0; anal_static_plugins[i]; i++) {
			r_anal_plugin_add (anal, anal_static_plugins[i]);
		}
	}
	R_DIRTY_SET (anal);
	return anal;
}

R_API bool r_anal_plugin_remove(RAnal *anal, RAnalPlugin *plugin) {
	R_RETURN_VAL_IF_FAIL (anal && plugin, false);
	// XXX TODO
	return true;
}

R_API void r_anal_plugin_free(RAnalPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

void __block_free_rb(RBNode *node, void *user);

R_API void r_anal_free(RAnal *a) {
	if (!a) {
		return;
	}
	/* TODO: Free anals here */
	free (a->pincmd);
	r_list_free (a->fcns);
	ht_up_free (a->ht_addr_fun);
	ht_pp_free (a->ht_name_fun);
	set_u_free (a->visited);
	r_anal_hint_storage_fini (a);
	r_th_lock_free (a->lock);
	r_interval_tree_fini (&a->meta);
	r_unref (a->config);
	a->arch->esil = NULL;
	r_arch_free (a->arch);
	a->arch = NULL;
	free (a->zign_path);
	free (a->opt.tparser);
	r_list_free (a->plugins);
	r_rbtree_free (a->bb_tree, __block_free_rb, NULL);
	r_spaces_fini (&a->meta_spaces);
	r_spaces_fini (&a->zign_spaces);
	r_anal_pin_fini (a);
	r_syscall_free (a->syscall);
	r_reg_free (a->reg);
	r_anal_xrefs_free (a);
	r_list_free (a->threads);
	r_list_free (a->leaddrs);
	sdb_free (a->sdb);
	a->esil->anal = NULL;
	r_esil_free (a->esil);
	free (a->last_disasm_reg);
	r_list_free (a->imports);
	r_str_constpool_fini (&a->constpool);
	r_anal_backtrace_fini (a);
	free (a);
}

R_API void r_anal_set_user_ptr(RAnal *anal, void *user) {
	anal->user = user;
}

R_API int r_anal_plugin_add(RAnal *anal, RAnalPlugin *foo) {
	R_RETURN_VAL_IF_FAIL (anal && foo, -1);
	if (foo->init) {
		foo->init (anal->user);
	}
	r_list_append (anal->plugins, foo);
	return true;
}

R_API char *r_anal_mnemonics(RAnal *anal, int id, bool json) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RArchSession *session = R_UNWRAP3 (anal, arch, session);
	RArchPluginMnemonicsCallback am = R_UNWRAP3 (session, plugin, mnemonics);
	return am? am (session, id, json): NULL;
}

R_API bool r_anal_use(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	if (anal->arch) {
		bool res = r_arch_use (anal->arch, anal->config, name);
		if (res) {
	//		anal->cur = NULL;
			r_anal_set_reg_profile (anal, NULL);
			return true;
		}
	}
	// R_LOG_DEBUG ("no plugin found");
	return false;
}

R_API char *r_anal_get_reg_profile(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RArchSession *session = R_UNWRAP3 (anal, arch, session);
	RArchPluginRegistersCallback regs = R_UNWRAP3 (session, plugin, regs);
	return regs? regs (session): NULL;
}

// R2_600 review this:
// deprecate.. or at least reuse get_reg_profile...
R_DEPRECATE R_API bool r_anal_set_reg_profile(RAnal *anal, const char *p) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	char *rp = NULL;
	bool ret = false;
	if (!p) {
		rp = r_anal_get_reg_profile (anal);
		p = (const char *)rp;
	}
	if (R_STR_ISNOTEMPTY (p)) {
		ret = r_reg_set_profile_string (anal->reg, p);
	}
	free (rp);
	return ret;
}

R_API bool r_anal_set_triplet(RAnal *anal, const char * R_NULLABLE os, const char * R_NULLABLE arch, int bits) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	if (R_STR_ISEMPTY (os)) {
		os = R_SYS_OS;
	}
	if (R_STR_ISEMPTY (arch)) {
		arch = anal->config? anal->config->arch: R_SYS_ARCH;
	}
	if (bits < 1) {
		bits = anal->config->bits;
	}
	if (anal->config && anal->config->os && !strcmp (anal->config->os, os)) {
		free (anal->config->os);
		anal->config->os = strdup (os);
	}
	if (bits != anal->config->bits) {
		r_anal_set_bits (anal, bits);
	}
	return true;
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	R_RETURN_IF_FAIL (s && path);
	Sdb *db = sdb_new (0, path, 0);
	if (db) {
		sdb_merge (s, db);
		sdb_close (db);
		sdb_free (db);
	}
}

R_API bool r_anal_set_os(RAnal *anal, const char *os) {
	R_RETURN_VAL_IF_FAIL (anal && os, false);
	Sdb *types = anal->sdb_types;
	const char *dir_prefix = r_sys_prefix (NULL);
	SdbGperf *gp = r_anal_get_gperf_types (os);
	if (gp) {
		Sdb *gd = sdb_new0 ();
		sdb_open_gperf (gd, gp);
		sdb_reset (anal->sdb_types);
		sdb_merge (anal->sdb_types, gd);
		sdb_close (gd);
		sdb_free (gd);
		return r_anal_set_triplet (anal, os, NULL, -1);
	}
	// char *ff = r_str_newf ("types-%s.sdb", os);
	// char *dbpath = r_file_new (dir_prefix, r2_sdb_fcnsign, ff, NULL);
	char *dbpath = r_str_newf ("%s%s%s%stypes-%s.sdb",
		dir_prefix, R_SYS_DIR, R2_SDB_FCNSIGN, R_SYS_DIR, os);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	free (dbpath);
	return r_anal_set_triplet (anal, os, NULL, -1);
}

R_API bool r_anal_set_bits(RAnal *anal, int bits) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	int obits = anal->config->bits;
	r_arch_config_set_bits (anal->config, bits);
	r_arch_set_bits (anal->arch, bits);
	if (bits != obits) {
		r_anal_set_reg_profile (anal, NULL);
	}
	return true;
}

// see 'aobm' command
R_API ut8 *r_anal_mask(RAnal *anal, int size, const ut8 *data, ut64 at) {
	R_RETURN_VAL_IF_FAIL (anal && data && size > 0, NULL);

	RAnalOp *op = r_anal_op_new ();
	if (!op) {
		return NULL;
	}
	ut8 *ret = r_mem_set (0xff, size);
	if (!ret) {
		free (op);
		return NULL;
	}

	// TODO: use the bitfliping thing to guess the mask in here
	int idx = 0;
	while (idx < size) {
		int oplen = r_anal_op (anal, op, at, data + idx, size - idx, R_ARCH_OP_MASK_BASIC);
		if (oplen < 1) {
			break;
		}
		if ((op->ptr != UT64_MAX || op->jump != UT64_MAX) && op->nopcode != 0) {
			memset (ret + idx + op->nopcode, 0, oplen - op->nopcode);
		}
		idx += oplen;
		at += oplen;
		R_FREE (op->mnemonic);
	}

	r_anal_op_free (op);
	return ret;
}

R_API void r_anal_trace_bb(RAnal *anal, ut64 addr) {
	R_RETURN_IF_FAIL (anal);
	RAnalBlock *bb = r_anal_get_block_at (anal, addr);
	if (bb && !bb->traced) {
		bb->traced = true;
		R_DIRTY_SET (anal);
	}
}

R_API RList* r_anal_get_fcns(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	// avoid received to free this thing
	anal->fcns->free = NULL;
	return anal->fcns;
}

R_API bool r_anal_op_is_eob(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op, false);
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

R_API void r_anal_purge(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	r_anal_hint_clear (anal);
	r_interval_tree_fini (&anal->meta);
	r_interval_tree_init (&anal->meta, r_meta_item_free);
	sdb_reset (anal->sdb_types);
	sdb_reset (anal->sdb_zigns);
	sdb_reset (anal->sdb_classes);
	sdb_reset (anal->sdb_classes_attrs);
	r_anal_pin_fini (anal);
	r_anal_pin_init (anal);
	sdb_reset (anal->sdb_cc);
	r_list_free (anal->fcns);
	anal->fcns = r_list_newf ((RListFree)r_anal_function_free);
	r_anal_purge_imports (anal);
}

static int default_archinfo(int res, int q) {
	if (res < 1) {
		return 1;
	}
	return res;
}

// XXX deprecate. use r_arch_info() when all anal plugs get moved
// XXX this function should NEVER return -1. it should provide all valid values, even if the delegate does not
R_API R_DEPRECATE int r_anal_archinfo(RAnal *anal, int query) { // R2_590
	R_RETURN_VAL_IF_FAIL (anal, -1);
	int res = -1;
	if (anal->arch->session) {
		const char *const a = anal->arch->session? anal->arch->session->config->arch: "";
		const char *const b = anal->config->arch;
		if (!strcmp (a, b)) {
			res = r_arch_info (anal->arch, query);
		}
	}
	return default_archinfo (res, query);
}

R_API bool r_anal_is_aligned(RAnal *anal, const ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	const int align = r_anal_archinfo (anal, R_ARCH_INFO_CODE_ALIGN);
	return align <= 1 || !(addr % align);
}

static bool __nonreturn_print_commands(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strcmp (v, "func")) {
		char *query = r_str_newf ("func.%s.noreturn", k);
		if (sdb_bool_get (anal->sdb_types, query, NULL)) {
			anal->cb_printf ("tnn %s\n", k);
		}
		free (query);
	}
	if (r_str_startswith (k, "addr.")) {
		anal->cb_printf ("tna 0x%s %s\n", k + 5, v);
	}
	return true;
}

static bool __nonreturn_print(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (r_str_startswith (k, "func.") && strstr (k, ".noreturn")) {
		char *s = strdup (k + 5);
		char *d = strchr (s, '.');
		if (d) {
			*d = 0;
		}
		anal->cb_printf ("%s\n", s);
		free (s);
	}
	if (r_str_startswith (k, "addr.")) {
		char *off;
		if (!(off = strdup (k + strlen ("addr.")))) {
			return 1;
		}
		char *ptr = strstr (off, ".noreturn");
		if (ptr) {
			*ptr = 0;
			anal->cb_printf ("0x%s\n", off);
		}
		free (off);
	}
	return true;
}

R_API void r_anal_noreturn_list(RAnal *anal, int mode) {
	switch (mode) {
	case 1:
	case '*':
	case 'r':
		sdb_foreach (anal->sdb_types, __nonreturn_print_commands, anal);
		break;
	default:
		sdb_foreach (anal->sdb_types, __nonreturn_print, anal);
		break;
	}
}

#define K_NORET_ADDR(x) r_strf ("addr.%"PFMT64x".noreturn", x)
#define K_NORET_FUNC(x) r_strf ("func.%s.noreturn", x)

R_API bool r_anal_noreturn_add(RAnal *anal, const char * R_NULLABLE name, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	r_strf_buffer (128);
	const char *tmp_name = NULL;
	Sdb *TDB = anal->sdb_types;
	char *fnl_name = NULL;
	if (addr != UT64_MAX) {
		if (sdb_bool_set (TDB, K_NORET_ADDR (addr), true, 0)) {
			RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
			if (fcn) {
				fcn->is_noreturn = true;
			}
			return true;
		}
	}
	if (R_STR_ISNOTEMPTY (name)) {
		tmp_name = name;
	} else {
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, -1);
		RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
		if (!fcn && !fi) {
			R_LOG_ERROR ("Can't find Function at given address");
			return false;
		}
		tmp_name = fcn ? fcn->name: fi->name;
		if (fcn) {
			if (!fcn->is_noreturn) {
				fcn->is_noreturn = true;
				R_DIRTY_SET (anal);
			}
		}
	}
	if (r_type_func_exist (TDB, tmp_name)) {
		fnl_name = strdup (tmp_name);
	} else if (!(fnl_name = r_type_func_guess (TDB, tmp_name))) {
		if (addr == UT64_MAX) {
			if (name) {
				sdb_bool_set (TDB, K_NORET_FUNC (name), true, 0);
			} else {
				R_LOG_WARN ("Can't find prototype for: %s", tmp_name);
			}
		} else {
			R_LOG_WARN ("Can't find prototype for: %s", tmp_name);
		}
		//return false;
	}
	if (fnl_name) {
		sdb_bool_set (TDB, K_NORET_FUNC (fnl_name), true, 0);
		free (fnl_name);
	}
	return true;
}

R_API bool r_anal_noreturn_drop(RAnal *anal, const char *expr) {
	R_RETURN_VAL_IF_FAIL (anal && expr, false);
	r_strf_buffer (64);
	Sdb *TDB = anal->sdb_types;
	const char *fcnname = r_str_trim_head_ro (expr);
	if (r_str_startswith (fcnname, "0x")) {
		ut64 n = r_num_math (NULL, fcnname);
		sdb_unset (TDB, K_NORET_ADDR (n), 0);
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, n, -1);
		if (!fcn) {
			R_LOG_DEBUG ("can't find function at 0x%"PFMT64x, n);
			return false;
		}
		fcnname = fcn->name;
	}
	sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
#if 0
	char *tmp;
	// unnsecessary checks, imho the noreturn db should be pretty simple to allow forward and custom declarations without having to define the function prototype before
	if (r_type_func_exist (TDB, fcnname)) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		return true;
	} else if ((tmp = r_type_func_guess (TDB, (char *)fcnname))) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		free (tmp);
		return true;
	}
	eprintf ("Can't find prototype for %s in types database\n", fcnname);
#endif
	return false;
}

static bool r_anal_noreturn_at_name(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && name, false);
	r_strf_buffer (128);
	if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC (name), NULL)) {
		return true;
	}
	char *tmp = r_type_func_guess (anal->sdb_types, name);
	if (tmp) {
		if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC (tmp), NULL)) {
			free (tmp);
			return true;
		}
		free (tmp);
	}
	if (r_str_startswith (name, "reloc.")) {
		return r_anal_noreturn_at_name (anal, name + 6);
	}
	return false;
}

R_API bool r_anal_noreturn_at_addr(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	r_strf_buffer (64);
	return sdb_bool_get (anal->sdb_types, K_NORET_ADDR (addr), NULL);
}

static bool noreturn_recurse(RAnal *anal, ut64 addr) {
	RAnalOp op = {0};
	ut8 bbuf[0x10] = {0};
	ut64 recurse_addr = UT64_MAX;
	if (!addr || addr == UT64_MAX) {
		return false;
	}
	if (!anal->iob.read_at (anal->iob.io, addr, bbuf, sizeof (bbuf))) {
		R_LOG_ERROR ("Couldn't read buffer");
		return false;
	}
	if (r_anal_op (anal, &op, addr, bbuf, sizeof (bbuf), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL) < 1) {
		return false;
	}
	switch (op.type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_JMP:
		if (op.jump == UT64_MAX) {
			recurse_addr = op.ptr;
		} else {
			recurse_addr = op.jump;
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		recurse_addr = op.ptr;
		break;
	case R_ANAL_OP_TYPE_CCALL:
	case R_ANAL_OP_TYPE_CALL:
		recurse_addr = op.jump;
		break;
	}
	if (recurse_addr == UT64_MAX || recurse_addr == addr) {
		return false;
	}
	return r_anal_noreturn_at (anal, recurse_addr);
}

R_API bool r_anal_noreturn_at(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	if (addr == UT64_MAX) {
		return false;
	}
	if (r_anal_noreturn_at_addr (anal, addr)) {
		return true;
	}
	/* XXX this is very slow */
	RAnalFunction *f = r_anal_get_function_at (anal, addr);
	if (f) {
		if (r_anal_noreturn_at_name (anal, f->name)) {
			return true;
		}
	}
	RFlagItem *fi = anal->flag_get (anal->flb.f, false, addr);
	if (fi) {
		if (r_anal_noreturn_at_name (anal, fi->realname ? fi->realname : fi->name)) {
			return true;
		}
	}
	if (anal->opt.recursive_noreturn) {
		return noreturn_recurse (anal, addr);
	}
	return false;
}

R_API const char * R_NONNULL r_anal_fcn_prefix_at(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, "fcn");
	return r_anal_choose_fcnprefix (anal, addr);
}

R_API void r_anal_bind(RAnal *anal, RAnalBind *b) {
	R_RETURN_IF_FAIL (anal && b);
	b->anal = anal;
	b->get_fcn_in = r_anal_get_fcn_in;
	b->get_hint = r_anal_hint_get;
	b->encode = (RAnalEncode)r_anal_opasm; // TODO rename to encode.. and use r_arch_encode when all plugs are moved
	b->decode = (RAnalDecode)r_anal_op; // TODO rename to decode
	b->opinit = r_anal_op_init;
	b->mnemonics = r_anal_mnemonics;
	b->opfini = r_anal_op_fini;
	b->use = r_anal_use;
}

R_API RList *r_anal_preludes(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	if (anal->arch->session) {
		const char *const a = anal->arch->session? anal->arch->session->config->arch: "";
		const char *const b = anal->config->arch;
		if (!strcmp (a, b)) {
			RList *l = r_list_newf ((RListFree)r_search_keyword_free);
			RList *ap = r_arch_session_preludes (anal->arch->session);
			RListIter *iter;
			char *s;
			r_list_foreach (ap, iter, s) {
				r_list_append (l, r_search_keyword_new_hexstr (s, NULL));
			}
			r_list_free (ap);
			return l;
		}
	}
	return NULL;
}

R_API bool r_anal_is_prelude(RAnal *anal, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	if (addr == UT64_MAX) {
		return false;
	}
	ut8 *owned = NULL;
	RFlagItem *flag = anal->flag_get (anal->flb.f, false, addr); // XXX should get a list
	if (flag) {
		if (r_str_startswith (flag->name, "func.")) {
			return true;
		}
		if (r_str_startswith (flag->name, "fcn.")) {
			return true;
		}
		if (r_str_startswith (flag->name, "sym.")) {
			return true;
		}
	}
	if (!data) {
		const int maxis = r_anal_archinfo (anal, R_ARCH_INFO_MAXOP_SIZE);
		owned = malloc (maxis);
		if (!owned) {
			return false;
		}
		data = owned;
		(void)anal->iob.read_at (anal->iob.io, addr, (ut8 *) owned, maxis);
	}
	RList *l = r_anal_preludes (anal);
	if (l) {
		RSearchKeyword *kw;
		RListIter *iter;
		r_list_foreach (l, iter, kw) {
			int ks = kw->keyword_length;
			if (len >= ks && !memcmp (data, kw->bin_keyword, ks)) {
				r_list_free (l);
				free (owned);
				return true;
			}
		}
		r_list_free (l);
	}
	free (owned);
	return false;
}

R_API void r_anal_add_import(RAnal *anal, const char *imp) {
	RListIter *it;
	const char *eimp;
	r_list_foreach (anal->imports, it, eimp) {
		if (!strcmp (eimp, imp)) {
			return;
		}
	}
	char *cimp = strdup (imp);
	if (!cimp) {
		return;
	}
	R_DIRTY_SET (anal);
	r_list_push (anal->imports, cimp);
}

R_API void r_anal_remove_import(RAnal *anal, const char *imp) {
	RListIter *it;
	const char *eimp;
	r_list_foreach (anal->imports, it, eimp) {
		if (!strcmp (eimp, imp)) {
			R_DIRTY_SET (anal);
			r_list_delete (anal->imports, it);
			return;
		}
	}
}

R_API void r_anal_purge_imports(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	r_list_purge (anal->imports);
	R_DIRTY_SET (anal);
}

R_API bool r_anal_cmd(RAnal *anal, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (anal && cmd, false);
	RListIter *iter;
	RAnalPlugin *ap;
	r_list_foreach (anal->plugins, iter, ap) {
		if (ap->cmd && ap->cmd (anal, cmd)) {
			return true;
		}
	}
	return false;
}
