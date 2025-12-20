/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>
#include <r_types_base.h>
#include <r_util/r_cfloat.h>
#include <r_util/r_print.h>

#define NODECB(w, x, y) r_config_set_cb(cfg, w, x, y)
#define NODEICB(w, x, y) r_config_set_i_cb(cfg, w, x, y)
#define SETDESC(x, y) r_config_node_desc(x, y)
#define SETOPTIONS(x, ...) set_options(x, __VA_ARGS__)
#define SETI(x, y, z) SETDESC(r_config_set_i(cfg, x, y), z)
#define SETICB(w, x, y, z) SETDESC(NODEICB(w, x, y), z)
#define SETS(x, y, z) SETDESC(r_config_set(cfg, x, y), z)
#define SETCB(w, x, y, z) SETDESC(NODECB(w, x, y), z)
#define SETB(x, y, z) SETDESC(NODECB(x, y, boolify_var_cb), z)

static bool boolify_var_cb(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value || r_str_is_false (node->value)) {
		free (node->value);
		node->value = strdup (r_str_bool (node->i_value));
	}
	return true;
}

static void set_options(RConfigNode *node, ...) {
	va_list argp;
	char *option = NULL;
	va_start (argp, node);
	option = va_arg (argp, char *);
	while (option) {
		r_config_node_add_option (node, option);
		option = va_arg (argp, char *);
	}
	va_end (argp);
}

static bool isGdbPlugin(RCore *core) {
	RIOPlugin *plugin = R_UNWRAP4 (core, io, desc, plugin);
	return plugin && plugin->meta.name && !strcmp (plugin->meta.name, "gdb");
}

static void print_node_options(void *user, RConfigNode *node) {
	if (node->options) {
		RListIter *iter;
		char *option;
		RCore *core = (RCore *)user;
		r_list_foreach (node->options, iter, option) {
			r_cons_printf (core->cons, "%s\n", option);
		}
	}
}

static int compareName(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->name && b->name? strcmp (a->name, b->name): 0);
}

static int compareNameLen(const RAnalFunction *a, const RAnalFunction *b) {
	if (!a || !b || !a->name || !b->name) {
		return 0;
	}
	size_t la = strlen (a->name);
	size_t lb = strlen (a->name);
	return (la > lb) - (la < lb);
}

static int compareAddress(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->addr && b->addr? (a->addr > b->addr) - (a->addr < b->addr): 0);
}

static int compareType(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->diff->type && b->diff->type? (a->diff->type > b->diff->type) - (a->diff->type < b->diff->type): 0);
}

static int compareSize(const RAnalFunction *a, const RAnalFunction *b) {
	ut64 sa, sb;
	// return a && b && a->_size < b->_size;
	if (!a || !b) {
		return 0;
	}
	sa = r_anal_function_realsize (a);
	sb = r_anal_function_realsize (b);
	return (sa > sb) - (sa < sb);
}

static int compareDist(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->diff->dist && b->diff->dist? (a->diff->dist > b->diff->dist) - (a->diff->dist < b->diff->dist): 0);
}

static bool cb_diff_sort(void *_core, void *_node) {
	RConfigNode *node = _node;
	const char *column = node->value;
	RCore *core = _core;
	if (column && *column != '?') {
		if (!strcmp (column, "name")) {
			core->anal->columnSort = (RListComparator)compareName;
		} else if (!strcmp (column, "namelen")) {
			core->anal->columnSort = (RListComparator)compareNameLen;
		} else if (!strcmp (column, "addr")) {
			core->anal->columnSort = (RListComparator)compareAddress;
		} else if (!strcmp (column, "type")) {
			core->anal->columnSort = (RListComparator)compareType;
		} else if (!strcmp (column, "size")) {
			core->anal->columnSort = (RListComparator)compareSize;
		} else if (!strcmp (column, "dist")) {
			core->anal->columnSort = (RListComparator)compareDist;
		} else {
			goto fail;
		}
		return true;
	}
fail:
	R_LOG_INFO ("e diff.sort = [name, namelen, addr, type, size, dist]");
	return false;
}

// more copypasta
bool ranal2_list(RCore *core, const char *arch, int fmt) {
	return false;
#if 0
	int i;
	const char *feat2, *feat;
	RAnal *a = core->anal;
	char *bits;
	RAnalPlugin *h;
	RListIter *iter;
	bool any = false;
	PJ *pj = NULL;
	if (fmt == 'j') {
		pj = pj_new ();
		if (!pj) {
			return false;
		}
		pj_o (pj);
	}
	if (R_STR_ISNOTEMPTY (arch)) {
		r_list_foreach (a->plugins, iter, h) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++) {
					r_cons_println (core->cons, r_str_word_get0 (c, i));
					any = true;
				}
				free (c);
				break;
			}
		}
		if (!any) {
			RArch *ai = core->anal->arch;
			RArchPlugin *arp;
			r_list_foreach (ai->plugins, iter, arp) {
				if (arp->cpus && !strcmp (arch, arp->meta.name)) {
					char *c = strdup (arp->cpus);
					int n = r_str_split (c, ',');
					for (i = 0; i < n; i++) {
						r_cons_println (core->cons, r_str_word_get0 (c, i));
						any = true;
					}
					free (c);
					break;
				}
			}
		}
	} else {
		r_list_foreach (a->plugins, iter, h) {
			RStrBuf *sb = r_strbuf_new ("");
			if (h->bits & 8) {
				r_strbuf_append (sb, "8");
			}
			if (h->bits & 16) {
				r_strbuf_appendf (sb, "%s16", sb->len? ",": "");
			}
			if (h->bits & 32) {
				r_strbuf_appendf (sb, "%s32", sb->len? ",": "");
			}
			if (h->bits & 64) {
				r_strbuf_appendf (sb, "%s64", sb->len? ",": "");
			}
			if (!h->bits) {
				r_strbuf_appendf (sb, "%s0", sb->len? ",": "");
			}
			bits = r_strbuf_drain (sb);
			feat = "__";
			feat = "_d";
			feat2 = "__";
			if (fmt == 'q') {
				r_cons_println (core->cons, h->name);
			} else if (fmt == 'j') {
				const char *license = "GPL";
				pj_k (pj, h->name);
				pj_o (pj);
				pj_k (pj, "bits");
				pj_a (pj);
				if (h->bits & 8) {
					pj_i (pj, 8);
				}
				if (h->bits & 16) {
					pj_i (pj, 16);
				}
				if (h->bits & 32) {
					pj_i (pj, 32);
				}
				if (h->bits & 64) {
					pj_i (pj, 64);
				}
				pj_end (pj);
				pj_ks (pj, "license", license);
				pj_ks (pj, "description", h->desc);
				pj_ks (pj, "features", feat);
				pj_end (pj);
			} else {
				r_cons_printf (core->cons, "%s%s  %-11s  %-11s %-7s %s\n",
						feat, feat2, bits, h->name,
						r_str_get_fail (h->license, "unknown"), h->desc);
			}
			any = true;
			free (bits);
		}
	}
	if (fmt == 'j') {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
	return any;
#endif
}

static inline void __setsegoff(RConfig *cfg, const char *asmarch, int asmbits) {
	int autoseg = r_str_startswith (asmarch, "x86") && asmbits == 16;
	r_config_set (cfg, "asm.addr.segment", r_str_bool (autoseg));
}

static bool cb_debug_hitinfo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->hitinfo = node->i_value;
	return true;
}

static bool cb_anal_flagends(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.flagends = node->i_value;
	return true;
}

static bool cb_anal_icods(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.icods = node->i_value;
	return true;
}

static bool cb_anal_jmpretpoline(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.retpoline = node->i_value;
	return true;
}

static bool cb_anal_jmptailcall(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.tailcall = node->i_value;
	return true;
}

static bool cb_anal_jmptailcall_delta(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.tailcall_delta = node->i_value;
	return true;
}

static bool cb_analdepth(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.depth = node->i_value;
	return true;
}

static bool cb_analgraphdepth(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.graph_depth = node->i_value;
	return true;
}

static bool cb_anal_delay(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.delay = node->i_value;
	return true;
}

static bool cb_analvars(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.vars = node->i_value;
	return true;
}

static bool cb_analvars_stackname(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.varname_stack = node->i_value;
	return true;
}

static bool cb_analvars_newstack(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.var_newstack = node->i_value;
	return true;
}

static bool cb_anal_nonull(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.nonull = node->i_value;
	return true;
}

static bool cb_anal_ignbithints(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.ignbithints = node->i_value;
	return true;
}

static bool cb_analsleep(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->sleep = node->i_value;
	return true;
}

static bool cb_analmaxrefs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->maxreflines = node->i_value;
	return true;
}

static bool cb_analnorevisit(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.norevisit = node->i_value;
	return true;
}

static bool cb_analnopskip(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.nopskip = node->i_value;
	return true;
}

static bool cb_analhpskip(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.hpskip = node->i_value;
	return true;
}

static bool cb_analarch(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	if (*node->value) {
		if (r_anal_use (core->anal, node->value)) {
			if (core->print) {
				core->print->reg = core->anal->reg;
				core->print->get_register = r_reg_get;
			}
			return true;
		}
		char *p = strchr (node->value, '.');
		if (p) {
			char *arch = strdup (node->value);
			arch[p - node->value] = 0;
			free (node->value);
			node->value = arch;
			if (r_anal_use (core->anal, node->value)) {
				if (core->print) {
					core->print->reg = core->anal->reg;
					core->print->get_register = r_reg_get;
				}
				return true;
			}
		}
		const char *aa = r_config_get (core->config, "asm.arch");
		if (!aa || strcmp (aa, node->value)) {
			R_LOG_ERROR ("anal.arch: cannot find '%s'", node->value);
		} else {
			r_config_set (core->config, "anal.arch", "null");
			return true;
		}
	}
	return false;
}

static void update_archdecoder_options(RCore *core, RConfigNode *node) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->arch && node);
	r_config_node_purge_options (node);
	RListIter *it;
	RArchPlugin *ap;
	r_list_foreach (core->anal->arch->plugins, it, ap) {
		if (ap->meta.name) {
			SETOPTIONS (node, ap->meta.name, NULL);
		}
	}
}

static bool cb_archdecoder(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	R_RETURN_VAL_IF_FAIL (node && core && core->anal && core->anal->arch, false);
	if (*node->value == '?') {
		update_archdecoder_options (core, node);
		print_node_options (user, node);
		return false;
	}
	if (*node->value) {
		if (r_arch_use_decoder (core->anal->arch, node->value)) {
			return true;
		}
		R_LOG_ERROR ("arch.decoder: cannot find '%s'", node->value);
	}
	return false;
}

static bool cb_archdecoder_getter(RCore *core, RConfigNode *node) {
	R_RETURN_VAL_IF_FAIL (node && core && core->anal && core->anal->arch, false);
	free (node->value);
	if (core->anal->arch->cfg && core->anal->arch->cfg->decoder) {
		node->value = strdup (core->anal->arch->cfg->decoder);
		return true;
	}
	node->value = strdup ("null");
	return true;
}

static bool cb_arch_platform(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *name = node->value;
	RArch *arch = core->anal->arch;
	if (strstr (name, "?")) {
		r_arch_platform_list (arch);
	} else {
		if (arch->platform) {
			char *f = r_arch_platform_unset (arch, arch->platform);
			r_core_run_script (core, f);
			free (f);
			arch->platform = NULL;
		}
		char *f = r_arch_platform_set (arch, name);
		if (f) {
			r_core_run_script (core, f);
			free (f);
		}
	}
	return true;
}

static bool cb_archbits(void *user, void *data) {
	R_RETURN_VAL_IF_FAIL (user && data, false);
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_arch_set_bits (core->anal->arch, node->i_value);
	return true;
}

static bool cb_archbits_getter(RCore *core, RConfigNode *node) {
	R_RETURN_VAL_IF_FAIL (node && core && core->anal && core->anal->arch, false);
	if (core->anal->arch->cfg) {
		node->i_value = core->anal->arch->cfg->bits;
	}
	return true;
}

static bool cb_archendian(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	R_RETURN_VAL_IF_FAIL (node && core && core->anal && core->anal->arch, false);
	if (!strcmp (node->value, "big") || !strcmp (node->value, "bigswap")) {
		r_arch_set_endian (core->anal->arch, R_SYS_ENDIAN_BIG);
		return true;
	}
	if (!strcmp (node->value, "little") || !strcmp (node->value, "littleswap")) {
		r_arch_set_endian (core->anal->arch, R_SYS_ENDIAN_LITTLE);
		return true;
	}
	return false;
}

static bool cb_analrecont(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.recont = node->i_value;
	return true;
}

static bool cb_analijmp(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.ijmp = node->i_value;
	return true;
}

static bool cb_asmsubvarmin(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->parse->minval = node->i_value;
	return true;
}

static bool cb_asmsubtail(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->parse->subtail = node->i_value;
	return true;
}

static bool cb_scrlast(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->context->lastEnabled = node->i_value;
	return true;
}

static bool cb_scr_histfilter(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->line->histfilter = node->i_value;
	return true;
}

static bool cb_scr_vi(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->line->enable_vi_mode = node->i_value;
	return true;
}

static bool cb_scr_prompt_mode(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->line->prompt_mode = node->i_value;
	return true;
}

static bool cb_scr_wideoff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->wide_offsets = node->i_value;
	return true;
}

static bool cb_scrrainbow(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_RAINBOW;
		r_core_cmd_call (core, "ecr");
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_RAINBOW);
		r_core_cmd_call (core, "ecoo");
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_asmpseudo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->pseudo = node->i_value;
	return true;
}

static bool cb_assembly_spp(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->use_spp = node->i_value;
	return true;
}

static bool cb_asmsubsec(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SECSUB;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_SECSUB);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_asm_var_summary(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		RCore *core = (RCore *)user;
		const char help[] =
			"0 # same as afv output\n"
			"1 # simplified args+vars list\n"
			"2 # short summary\n"
			"3 # compact oneliner for args + vars\n"
			"4 # compact oneliner with args+vars regs+mem range\n";
		r_cons_println (core->cons, help);
		return false;
	}
	return true;
}

static bool cb_asmassembler(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			/* print more verbose help instead of plain option values */
			ranal2_list (core, NULL, node->value[1]);
			return false;
		}
		RConfigNode *asm_arch_node = r_config_node_get (core->config, "asm.arch");
		if (asm_arch_node) {
			print_node_options (user, asm_arch_node);
		}
		return false;
	}
	r_asm_use_assembler (core->rasm, node->value);
	return true;
}

static void update_cmdpdc_options(RCore *core, RConfigNode *node) {
	R_RETURN_IF_FAIL (core && core->rasm && node);
	RListIter *iter;
	r_config_node_purge_options (node);
	char *opts = r_core_cmd_str (core, "e cmd.pdc=?");
	RList *optl = r_str_split_list (opts, "\n", 0);
	char *opt;
	r_list_foreach (optl, iter, opt) {
		SETOPTIONS (node, opt, NULL);
	}
	r_list_free (optl);
	free (opts);
}

static void update_asmcpu_options(RCore *core, RConfigNode *node) {
	RListIter *iter;
	R_RETURN_IF_FAIL (core && core->rasm);
	const char *arch = r_config_get (core->config, "asm.arch");
	if (!arch || !*arch) {
		return;
	}
	r_config_node_purge_options (node);
	RArchPlugin *h;
	r_list_foreach (core->anal->arch->plugins, iter, h) {
		if (h->cpus && !strcmp (arch, h->meta.name)) {
			char *c = strdup (h->cpus);
			int i, n = r_str_split (c, ',');
			for (i = 0; i < n; i++) {
				const char *word = r_str_word_get0 (c, i);
				if (word && *word) {
					node->options->free = free;
					SETOPTIONS (node, word, NULL);
				}
			}
			free (c);
		}
	}
}
static void list_cpus(RCore *core) {
	RArchPlugin *ap = R_UNWRAP5 (core, anal, arch, session, plugin);
	if (ap && ap->cpus) {
		char *c = strdup (ap->cpus);
		int i, n = r_str_split (c, ',');
		for (i = 0; i < n; i++) {
			r_cons_println (core->cons, r_str_word_get0 (c, i));
		}
		free (c);
	}
}

static bool cb_asmcpu(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		list_cpus (core);
#if 0
		update_asmcpu_options (core, node);
#endif
		return 0;
	}
	r_arch_config_set_cpu (core->rasm->config, node->value);
	const int v = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
	if (v >= 0) {
		core->anal->config->codealign = v;
	}
	r_config_set_i (core->config, "arch.codealign", (v != -1)? v: 0);
	return true;
}

static void update_asmarch_options(RCore *core, RConfigNode *node) {
	RArchPlugin *h;
	RListIter *iter;
	if (core && node && core->rasm) {
		r_config_node_purge_options (node);
		r_list_foreach (core->anal->arch->plugins, iter, h) {
			if (h->meta.name) {
				SETOPTIONS (node, h->meta.name, NULL);
			}
		}
	}
}

static void update_asmbits_options(RCore *core, RConfigNode *node) {
	if (core && core->rasm && node) {
		int bits = core->rasm->config->bits;
		int i;
		r_config_node_purge_options (node);
		for (i = 1; i <= bits; i <<= 1) {
			if (i & bits) {
				char *a = r_str_newf ("%d", i);
				SETOPTIONS (node, a, NULL);
				free (a);
			}
		}
	}
}

static bool cb_asmarch(void *user, void *data) {
	RCore *core = (RCore *)user;
	R_RETURN_VAL_IF_FAIL (core && core->anal, false);
	RConfigNode *node = (RConfigNode *)data;

	if (R_STR_ISEMPTY (node->value)) {
		return false;
	}

	int bits = R_SYS_BITS;
	if (core->anal->config && core->anal->config->bits) {
		bits = core->anal->config->bits;
	}
	if (*node->value == '?') {
		update_asmarch_options (core, node);
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			/* print more verbose help instead of plain option values */
			ranal2_list (core, NULL, node->value[1]);
			return false;
		} else {
			print_node_options (user, node);
			return false;
		}
	}
	r_egg_setup (core->egg, node->value, bits, 0, R_SYS_OS);

	if (!r_asm_use (core->rasm, node->value)) {
		R_LOG_ERROR ("asm.arch: cannot find '%s'", node->value);
		return false;
	}
	r_config_set (core->config, "asm.parser", node->value);

	if (core->anal->cur && ! (core->anal->config->bits & core->anal->config->bits)) {
		r_config_set_i (core->config, "asm.bits", bits);
	} else if (core->anal->cur && ! (core->rasm->config->bits & core->anal->config->bits)) {
		r_config_set_i (core->config, "asm.bits", bits);
	}

	r_debug_set_arch (core->dbg, node->value, bits);
	if (!r_config_set (core->config, "anal.arch", node->value)) {
		char *p, *s = strdup (node->value);
		if (s) {
			p = strchr (s, '.');
			if (p) {
				*p = 0;
			}
			if (!r_config_set (core->config, "anal.arch", s)) {
				/* fall back to the anal.null plugin */
				r_config_set (core->config, "anal.arch", "null");
			}
			free (s);
		}
	}
	// set codealign
	if (core->anal) {
		const char *asmcpu = r_config_get (core->config, "asm.cpu");
		const char *asmos = r_config_get (core->config, "asm.os");
		if (!r_syscall_setup (core->anal->syscall, node->value, core->anal->config->bits, asmcpu, asmos)) {
			// R_LOG_ERROR ("asm.arch: Cannot setup syscall '%s/%s' from '%s'",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
	}
	// if (!strcmp (node->value, "bf"))
	//	r_config_set (core->config, "dbg.backend", "bf");
	__setsegoff (core->config, node->value, core->rasm->config->bits);

	// set a default endianness
	int bigbin = r_bin_is_big_endian (core->bin);
	if (bigbin == -1 /* error: no endianness detected in binary */) {
		bigbin = r_config_get_b (core->config, "cfg.bigendian");
	}

	// try to set endian of RAsm to match binary
	r_asm_set_big_endian (core->rasm, bigbin);

	RConfigNode *asmcpu = r_config_node_get (core->config, "asm.cpu");
	if (asmcpu) {
		r_arch_config_set_cpu (core->rasm->config, asmcpu->value);
		update_asmcpu_options (core, asmcpu);
	}
	{
		int v = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
		r_config_set_i (core->config, "arch.codealign", (v != -1)? v: 0);
	}
	/* reload types and cc info */
	// changing asm.arch changes anal.arch
	// changing anal.arch sets types db
	// so ressetting is redundant and may lead to bugs
	// 1 case this is useful is when sdb_types is null
	if (!core->anal->sdb_types) {
		r_core_anal_type_init (core);
	}
	r_core_anal_cc_init (core);
	if (core->print) {
		core->print->reg = core->anal->reg;
		core->print->get_register = r_reg_get;
	}

	return true;
}

static bool cb_dbgbpsize(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->bpsize = node->i_value;
	return true;
}

static bool cb_dbgbtdepth(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->btdepth = node->i_value;
	return true;
}

static bool cb_asmbits(void *user, void *data) {
	R_RETURN_VAL_IF_FAIL (user && data, false);
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;

	if (*node->value == '?') {
		update_asmbits_options (core, node);
		print_node_options (user, node);
		return false;
	}

	bool ret = false;
	int bits = node->i_value;
	if (!bits) {
		return false;
	}
	if (bits == core->rasm->config->bits && bits == core->dbg->bits) {
		if (core->print) {
			core->print->reg = core->anal->reg;
			core->print->get_register = r_reg_get;
		}
		// early optimization
		return true;
	}
	if (bits > 0) {
		ret = r_asm_set_bits (core->rasm, bits);
		if (!r_anal_set_bits (core->anal, bits)) {
			R_LOG_ERROR ("asm.arch: Cannot setup '%d' bits analysis engine", bits);
			ret = false;
		}
	}
	r_debug_set_arch (core->dbg, core->anal->config->arch, bits);
	const bool load_from_debug = r_config_get_b (core->config, "cfg.debug");
	if (load_from_debug) {
		RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
		if (plugin && plugin->reg_profile) {
// XXX. that should depend on the plugin, not the host os
#if R2__WINDOWS__
#if !defined(_WIN64)
			core->dbg->bits = R_SYS_BITS_PACK (32);
#else
			core->dbg->bits = R_SYS_BITS_PACK (64);
#endif
#endif
			char *rp = plugin->reg_profile (core->dbg);
			if (rp) {
				r_reg_set_profile_string (core->dbg->reg, rp);
				r_reg_set_profile_string (core->anal->reg, rp);
				free (rp);
			}
		}
	} else {
		(void)r_anal_set_reg_profile (core->anal, NULL);
	}
	r_core_anal_cc_init (core);
	const char *asmos = r_config_get (core->config, "asm.os");
	const char *asmarch = r_config_get (core->config, "asm.arch");
	const char *asmcpu = r_config_get (core->config, "asm.cpu");
	if (core->anal) {
		if (!r_syscall_setup (core->anal->syscall, asmarch, bits, asmcpu, asmos)) {
			// R_LOG_ERROR ("asm.arch: Cannot setup syscall '%s/%s' from '%s'",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
		__setsegoff (core->config, asmarch, core->anal->config->bits);
		if (core->dbg) {
			r_bp_use (core->dbg->bp, asmarch, core->anal->config->bits);
			r_config_set_i (core->config, "dbg.bpsize", r_bp_size (core->dbg->bp));
		}
		/* set codealign */
		int v = r_anal_archinfo (core->anal, R_ARCH_INFO_CODE_ALIGN);
		r_config_set_i (core->config, "arch.codealign", (v != -1)? v: 0);
	}
	if (core->print) {
		core->print->reg = core->anal->reg;
		core->print->get_register = r_reg_get;
	}
	return ret;
}

static bool cb_flag_realnames(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->flags->realnames = node->i_value;
	return true;
}

static bool cb_flag_autospace(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->flags) {
		core->flags->autospace = node->i_value;
	}
	return true;
}

static bool cb_asmlineswidth(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->lineswidth = node->i_value;
	return true;
}

static bool cb_emustr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		r_config_set_b (core->config, "asm.emu", true);
	}
	return true;
}

static bool cb_emuskip(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons,
				"Concatenation of meta types encoded as characters:\n"
				"'d': data\n'c': code\n's': string\n'f': format\n'm': magic\n"
				"'h': hide\n'C': comment\n'r': run\n"
				"(default is 'ds' to skip data and strings)\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	}
	return true;
}

static bool cb_tableformat(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	return true;
}

static bool cb_jsonencoding(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (node->value[1] && node->value[1] == '?') {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons,
				"choose either: \n"
				"none (default)\n"
				"base64 - encode the json string values as base64\n"
				"hex - convert the string to a string of hexpairs\n"
				"array - convert the string to an array of chars\n"
				"strip - strip non-printable characters\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	}
	return true;
}

static bool cb_jsonencoding_numbers(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (node->value[1] && node->value[1] == '?') {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons,
				"choose either: \n"
				"none (default)\n"
				"string - encode the json number values as strings\n"
				"hex - encode the number values as hex, then as a string\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	}
	return true;
}

static bool cb_asm_invhex(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->config->invhex = node->i_value;
	return true;
}

static bool cb_arch_codealign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	int align = node->i_value;
	if (align < 0) {
		align = 0;
	}
	core->rasm->config->codealign = align;
	core->anal->config->codealign = align;
	return true;
}

static bool cb_asmos(void *user, void *data) {
	RCore *core = (RCore *)user;
	int asmbits = r_config_get_i (core->config, "asm.bits");
	RConfigNode *node = (RConfigNode *)data;

	if (*node->value == '?') {
		print_node_options (user, node);
		return 0;
	}
	if (!node->value[0]) {
		free (node->value);
		node->value = strdup (R_SYS_OS);
	}
	RConfigNode *asmarch = r_config_node_get (core->config, "asm.arch");
	if (asmarch) {
		const char *asmcpu = r_config_get (core->config, "asm.cpu");
		r_syscall_setup (core->anal->syscall, asmarch->value, core->anal->config->bits, asmcpu, node->value);
		__setsegoff (core->config, asmarch->value, asmbits);
	}
	r_anal_set_os (core->anal, node->value);
	r_core_anal_cc_init (core);
	return true;
}

static void update_cfgcharsets_options(RCore *core, RConfigNode *node) {
	r_config_node_purge_options (node);
	char *lst = r_muta_list (core->muta, R_MUTA_TYPE_CHARSET, 'q');
	if (!lst) {
		return;
	}
	RList *chs = r_str_split_list (lst, "\n", 0);
	RListIter *iter;
	char *name;
	r_list_foreach (chs, iter, name) {
		SETOPTIONS (node, name, NULL);
	}
	r_list_free (chs);
	free (lst);
}

static void update_asmparser_options(RCore *core, RConfigNode *node) {
	RListIter *iter;
	RList *plugins = R_UNWRAP3 (core, rasm, sessions);
	if (core && node && plugins) {
		RAsmPluginSession *aps;
		r_config_node_purge_options (node);
		r_list_foreach (plugins, iter, aps) {
			RAsmPlugin *p = aps->plugin;
			SETOPTIONS (node, p->meta.name, NULL);
		}
	}
}

static bool cb_asmparser(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		update_asmparser_options (core, node);
		print_node_options (user, node);
		return false;
	}
	return r_asm_use_parser (core->rasm, node->value);
}

typedef struct {
	const char *name;
	const char *aliases;
} namealiases_pair;

static bool cb_binstrenc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		RCore *core = (RCore *)user;
		print_node_options (user, node);
		r_cons_printf (core->cons,
			"  -- if string's 2nd & 4th bytes are 0 then utf16le else "
			"if 2nd - 4th & 6th bytes are 0 & no char > 0x10ffff then utf32le else "
			"if utf8 char detected then utf8 else latin1\n");
		return false;
	}
	const namealiases_pair names[] = {
		{ "guess", NULL },
		{ "latin1", "ascii" },
		{ "utf8", "utf-8" },
		{ "utf16le", "utf-16le,utf16-le" },
		{ "utf32le", "utf-32le,utf32-le" },
		{ "utf16be", "utf-16be,utf16-be" },
		{ "utf32be", "utf-32be,utf32-be" }
	};
	int i;
	char *enc = strdup (node->value);
	if (!enc) {
		return false;
	}
	r_str_case (enc, false);
	for (i = 0; i < R_ARRAY_SIZE (names); i++) {
		const namealiases_pair *pair = &names[i];
		if (!strcmp (pair->name, enc) || r_str_cmp_list (pair->aliases, enc, ',')) {
			free (node->value);
			node->value = strdup (pair->name);
			free (enc);
			if (core->bin) {
				free (core->bin->strenc);
				core->bin->strenc = !strcmp (node->value, "guess")? NULL: strdup (node->value);
				r_bin_reset_strings (core->bin);
			}
			return true;
		}
	}
	R_LOG_ERROR ("Unknown encoding: %s", node->value);
	free (enc);
	return false;
}

static bool cb_binfilter(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->filter = node->i_value;
	return true;
}

/* BinDemangleCmd */
static bool cb_bdc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.demangle_usecmd = node->i_value;
	return true;
}

static bool cb_useldr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.use_ldr = node->i_value;
	return true;
}

static bool cb_nofp(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->strings_nofp = node->i_value;
	return true;
}

static bool cb_binat(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->binat = node->i_value;
	return true;
}

static bool cb_usextr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.use_xtr = node->i_value;
	return true;
}

static bool cb_binlimit(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.limit = node->i_value;
	return true;
}

static bool cb_strpurge(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		RCore *core = (RCore *)user;
		r_cons_printf (core->cons,
			"There can be multiple entries separated by commas. No whitespace before/after entries.\n"
			"Possible entries:\n"
			"  all          : purge all strings\n"
			"  true         : use the false_positive() classifier in cbin.c\n"
			"  addr         : purge string at addr\n"
			"  addr1-addr2  : purge all strings in the range addr1-addr2 inclusive\n"
			"  !addr        : prevent purge of string at addr by prev entries\n"
			"  !addr1-addr2 : prevent purge of strings in range addr1-addr2 inclusive by prev entries\n"
			"Neither !true nor !false is supported.\n"
			"\n"
			"Examples:\n"
			"  e bin.str.purge=true,0-0xff,!0x1a\n"
			"    -- purge strings using the false_positive() classifier in cbin.c and also strings \n"
			"       with addresses in the range 0-0xff, but not the string at 0x1a.\n"
			"  e bin.str.purge=all,!0x1000-0x1fff\n"
			"    -- purge all strings except the strings with addresses in the range 0x1000-0x1fff.\n");
		return false;
	}
	free (core->bin->strpurge);
	core->bin->strpurge = !*node->value || !strcmp (node->value, "false")
		? NULL
		: strdup (node->value);
	return true;
}

static bool cb_maxname(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	core->rasm->parse->maxflagnamelen = node->i_value;
	return true;
}

static bool cb_midflags(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	return true;
}

static bool cb_strfilter(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons,
				"Valid values for bin.str.filter:\n"
				"a  only alphanumeric printable\n"
				"8  only strings with utf8 chars\n"
				"p  file/directory paths\n"
				"e  email-like addresses\n"
				"u  urls\n"
				"i  IPv4 address-like strings\n"
				"U  only uppercase strings\n"
				"f  format-strings\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	} else {
		core->bin->strfilter = node->value[0];
	}
	return true;
}

static bool cb_binforce(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_bin_force_plugin (core->bin, node->value);
	return true;
}

static bool cb_asmsyntax(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	} else {
		int syntax = r_asm_syntax_from_string (node->value);
		if (syntax == -1) {
			return false;
		}
		r_arch_config_set_syntax (core->rasm->config, syntax);
	}
	return true;
}

static bool cb_dirzigns(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free (core->anal->zign_path);
	core->anal->zign_path = strdup (node->value);
	return true;
}

static bool cb_cfg_regnums(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	((RCorePriv *)core->priv)->regnums = node->i_value;
	return true;
}

static bool cb_bigendian(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	// bp, asm, arch, anal, should have a single RArchConfig instance
	int endianType = node->i_value? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_NONE;
	bool isbig = r_asm_set_big_endian (core->rasm, node->i_value);
	if (core->dbg && core->dbg->bp) {
		core->dbg->bp->endian = isbig;
	}
	core->rasm->config->endian = endianType;
	r_arch_set_endian (core->anal->arch, endianType);
	return true;
}

static bool cb_cfg_prompt_format(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	const char *value = node->value;
	if (!value) {
		return false;
	}
	if (!strcmp (value, "?")) {
		RCore *core = (RCore *)user;
		r_core_prompt_format_help (core);
		return false;
	}
	return true;
}

static bool cb_cfg_float(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *value = node->value;
	if (!value) {
		return false;
	}
	RCFloatProfile profile;
	if (!strcmp (value, "ieee754")) {
		profile = R_CFLOAT_PROFILE_BINARY64; // default IEEE 754
	} else if (r_str_startswith (value, "custom:")) {
		// Parse custom:sign_bits,exp_bits,mant_bits,bias,big_endian,explicit_leading_bit
		const char *params = value + 7; // skip "custom:"
		char *dup = strdup (params);
		if (!dup) {
			return false;
		}
		RList *list = r_str_split_list (dup, ",", 0);
		if (r_list_length (list) != 6) {
			r_list_free (list);
			free (dup);
			return false;
		}
		int sign_bits = atoi (r_list_get_n (list, 0));
		int exp_bits = atoi (r_list_get_n (list, 1));
		int mant_bits = atoi (r_list_get_n (list, 2));
		int bias = atoi (r_list_get_n (list, 3));
		bool big_endian = atoi (r_list_get_n (list, 4));
		bool explicit_leading_bit = atoi (r_list_get_n (list, 5));
		r_list_free (list);
		free (dup);
		// Validate ranges
		if (sign_bits < 0 || exp_bits < 0 || mant_bits < 0 || sign_bits + exp_bits + mant_bits > 64) {
			return false;
		}
		profile.sign_bits = sign_bits;
		profile.exp_bits = exp_bits;
		profile.mant_bits = mant_bits;
		profile.bias = bias;
		profile.big_endian = big_endian;
		profile.explicit_leading_bit = explicit_leading_bit;
	} else {
		// Check if it's a named profile
		const RCFloatProfile *p = r_cfloat_profile_from_name (value);
		if (p) {
			profile = *p;
		} else {
			return false;
		}
	}
	// Set the profile in the arch config
	if (core->rasm && core->rasm->config) {
		core->rasm->config->cfloat_profile = profile;
	}
	if (core->anal && core->anal->arch && core->anal->arch->cfg) {
		core->anal->arch->cfg->cfloat_profile = profile;
	}
	return true;
}

static bool cb_cfgcharset(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *cf = r_str_trim_head_ro (node->value);
	if (!*cf) {
		r_muta_session_free (core->charset_session);
		core->charset_session = NULL;
		return true;
	}
	if (*cf == '?') {
		char *lst = r_muta_list (core->muta, R_MUTA_TYPE_CHARSET, 'q');
		if (lst) {
			r_cons_println (core->cons, lst);
			free (lst);
		}
		return false;
	}
	r_muta_session_free (core->charset_session);
	core->charset_session = r_muta_use (core->muta, cf);
	bool rc = core->charset_session != NULL;
	if (rc) {
		r_sys_setenv ("RABIN2_CHARSET", cf);
	} else {
		R_LOG_WARN ("Cannot load muta charset '%s'", cf);
	}
	return rc;
}

static bool cb_cfgdatefmt(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_str_ncpy (core->print->datefmt, node->value, sizeof (core->print->datefmt));
	return true;
}

static bool cb_timezone(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->datezone = node->i_value;
	return true;
}

static bool cb_codevar(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free (core->print->codevarname);
	core->print->codevarname = strdup (node->value);
	return true;
}

static bool cb_cfgcorelog(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cfglog = node->i_value;
	return true;
}

static bool cb_cfgdebug(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!core) {
		return false;
	}
	if (core->dbg && node->i_value) {
		const char *dbgbackend = r_config_get (core->config, "dbg.backend");
		r_config_set (core->config, "anal.in", "dbg.map");
		r_config_set (core->config, "search.in", "dbg.map");
		r_debug_use (core->dbg, dbgbackend);
		if (!strcmp (r_config_get (core->config, "cmd.prompt"), "")) {
			r_config_set (core->config, "cmd.prompt", ".dr*");
		}
		if (!strcmp (dbgbackend, "bf")) {
			r_config_set (core->config, "asm.arch", "bf");
		}
		if (core->io->desc) {
			r_debug_select (core->dbg, r_io_fd_get_pid (core->io, core->io->desc->fd), r_io_fd_get_tid (core->io, core->io->desc->fd));
		}
	} else {
		r_debug_use (core->dbg, NULL);
	}
	return true;
}

static bool cb_dirhome(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (node->value) {
		r_sys_setenv (R_SYS_HOME, node->value);
	}
	return true;
}

static bool cb_dir_cache(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (node->value) {
		r_sys_setenv ("XDG_CACHE_HOME", node->value);
	}
	return true;
}

static bool cb_dir_projects(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	char *value = R_STR_ISNOTEMPTY (node->value)? node->value: NULL;
	if (value) {
		char *newva = r_file_abspath (value);
		free (node->value);
		node->value = newva;
	}
	return true;
}

static bool cb_dirtmp(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	char *value = R_STR_ISNOTEMPTY (node->value)? node->value: NULL;
	if (value) {
		char *newva = r_file_abspath (value);
		free (node->value);
		node->value = newva;
	}
	return true;
}

static bool cb_dirsrc(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	free (core->bin->srcdir);
	core->bin->srcdir = strdup (node->value);
	return true;
}

static bool cb_dirsrc_base(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	free (core->bin->srcdir);
	if (R_STR_ISNOTEMPTY (node->value)) {
		core->bin->srcdir = strdup (node->value);
	} else {
		core->bin->srcdir = NULL;
	}
	return true;
}

static bool cb_cfgsanbox_grain(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (strstr (node->value, "?")) {
		static RCoreHelpMessage help_msg_grain = {
			"Usage:", "e cfg.sandbox.grain=arg[,arg...]", "set grain types to mask out", "Grain types:", "", "", "", "all", "", "", "none", "", "", "disk", "", "", "files", "", "", "exec", "", "", "socket", "", NULL
		};
		r_core_cmd_help ((RCore *)user, help_msg_grain);
		return false;
	}
	int gt = R_SANDBOX_GRAIN_NONE;
	if (strstr (node->value, "all")) {
		gt = R_SANDBOX_GRAIN_ALL;
	} else if (strstr (node->value, "none")) {
		gt = R_SANDBOX_GRAIN_NONE;
	} else {
		if (strstr (node->value, "exec")) {
			gt |= R_SANDBOX_GRAIN_EXEC;
		}
		if (strstr (node->value, "socket") || strstr (node->value, "net")) {
			gt |= R_SANDBOX_GRAIN_SOCKET;
		}
		if (strstr (node->value, "file") || strstr (node->value, "files")) {
			gt |= R_SANDBOX_GRAIN_FILES;
		}
		if (strstr (node->value, "disk")) {
			gt |= R_SANDBOX_GRAIN_DISK;
		}
	}
	return r_sandbox_grain (gt);
}

static bool cb_cfgsanbox(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	int ret = r_sandbox_enable (node->i_value);
	if (node->i_value != ret) {
		R_LOG_ERROR ("Cannot disable sandbox");
	}
	return (!node->i_value && ret)? 0: 1;
}

static bool cb_str_escbslash(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->esc_bslash = node->i_value;
	return true;
}

static bool cb_completion_maxtab(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->line->completion.args_limit = node->i_value;
	return true;
}

static bool cb_cfg_fortunes_type(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		RList *types = r_core_fortune_types (core);
		char *typ;
		RListIter *iter;
		r_list_foreach (types, iter, typ) {
			r_cons_println (core->cons, typ);
		}
		r_list_free (types);
		return false;
	}
	return true;
}

static bool cb_cmdpdc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_cons_printf (core->cons, "pdc\n");
		RListIter *iter;
		RCorePlugin *cp;
		r_list_foreach (core->rcmd->plist, iter, cp) {
			if (!strcmp (cp->meta.name, "r2retdec")) {
				r_cons_println (core->cons, "pdz");
			} else if (!strcmp (cp->meta.name, "decai")) {
				r_cons_println (core->cons, "decai");
			} else if (!strcmp (cp->meta.name, "r2jadx")) {
				r_cons_println (core->cons, "r2jadx");
			} else if (!strcmp (cp->meta.name, "r2ghidra")) {
				r_cons_println (core->cons, "pdg");
			}
		}
		RConfigNode *r2dec = r_config_node_get (core->config, "r2dec.asm");
		if (r2dec) {
			r_cons_printf (core->cons, "pdd\n");
		}
		return false;
	}
	return true;
}

static bool cb_cmdlog(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	R_FREE (core->cmdlog);
	core->cmdlog = strdup (node->value);
	return true;
}

static bool cb_defprefix(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.defprefix = node->value;
	return true;
}
static bool cb_dynprefix(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.dynprefix = node->i_value;
	return true;
}
static bool cb_cmdtimes(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cmdtimes = node->value;
	return true;
}

static RCoreTaskMode taskmode_from_string(const char *s) {
	if (s) {
		if (r_str_startswith (s, "coop")) {
			return R_CORE_TASK_MODE_COOP;
		}
		if (r_str_startswith (s, "thread")) {
			return R_CORE_TASK_MODE_THREAD;
		}
		if (r_str_startswith (s, "fork")) {
			return R_CORE_TASK_MODE_FORK;
		}
	}
	return R_CORE_TASK_MODE_COOP; // default
}

static bool cb_cfg_taskmode(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_cons_printf (core->cons, "coop\nthread\nfork\n");
		return false;
	}
	RCoreTaskMode mode = taskmode_from_string (node->value);
	r_core_task_set_default_mode (&core->tasks, mode);
	return true;
}

static bool cb_prefix_marker(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.prefix_marker = node->value;
	return true;
}

static bool cb_prefix_radius(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.prefix_radius = (ut64)node->i_value;
	return true;
}

static bool cb_cmdrepeat(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cmdrepeat = node->i_value;
	return true;
}

static bool cb_scrnull(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->null = node->i_value;
	return true;
}

static bool cb_scr_color_ophex(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOROP;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_COLOROP);
	}
	r_config_set_b (core->config, "log.color", node->i_value);
	return true;
}

static bool cb_color(void *user, void *data) {
	RCore *core = (RCore *)user;
	const int limit = core->cons->context->color_limit;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_cons_printf (core->cons, "Possible values:\n"
					"  0 - disable colors\n"
					"  1 - ansi 16 colors\n"
					"  2 - 256 colors\n"
					"  3 - 16 million colors (truecolor)\n"
					"Maximum supported by your terminal: %d\n",
			limit);
		return false;
	}
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOR;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_COLOR);
	}
	if (!strcmp (node->value, "true")) {
		node->i_value = 1;
	} else if (!strcmp (node->value, "false")) {
		node->i_value = 0;
	}
	int requested_mode = R_MIN (node->i_value, COLOR_MODE_16M);
	if (requested_mode > limit) {
		R_LOG_WARN ("Color mode %d requested but terminal only supports %d", requested_mode, limit);
		// core->cons->context->color_mode = R_MIN (requested_mode, limit);
	}
	core->cons->context->color_mode = requested_mode;

	// Regenerate palette strings for new color mode (escape sequences differ per mode)
	r_cons_pal_reload (core->cons);
	r_print_set_flags (core->print, core->print->flags);
	r_log_set_colors (node->i_value);
	return true;
}

static bool cb_color_getter(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	node->i_value = core->cons->context->color_mode;
	char buf[128];
	r_config_node_value_format_i (buf, sizeof (buf), core->cons->context->color_mode, node);
	if (!node->value || strcmp (node->value, buf) != 0) {
		free (node->value);
		node->value = strdup (buf);
	}
	return true;
}

// R2R test/db/cmd/cmd_pd_bugs
static bool cb_reloff(void *user, void *data) {
	const char options[] = "func\nflag\nmaps\ndmap\nfmap\nsect\nsymb\nlibs\nfile\n";
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value) {
		char *pos = strstr (options, node->value);
		size_t len = strlen (node->value);
		if (pos && pos[len] == '\n') {
			return true;
		}
		if (strchr (node->value, '?')) {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons, options);
		} else {
			R_LOG_ERROR ("Invalid value, try `-e asm.addr.relto=?`");
		}
		return false;
	}
	return true;
}

static bool cb_decoff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_ADDRDEC;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_ADDRDEC);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_dbgbep(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	return true;
}

static bool cb_dbg_btalgo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	free (core->dbg->btalgo);
	core->dbg->btalgo = strdup (node->value);
	return true;
}

static bool cb_dbg_maxsnapsize(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->maxsnapsize = r_num_math (core->num, node->value);
	return true;
}

static bool cb_dbg_wrap(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->want_ptrace_wrap = node->i_value;
	return true;
}

static bool cb_dbg_libs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free (core->dbg->glob_libs);
	core->dbg->glob_libs = strdup (node->value);
	return true;
}

static bool cb_dbg_unlibs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free (core->dbg->glob_unlibs);
	core->dbg->glob_unlibs = strdup (node->value);
	return true;
}

static bool cb_dbg_bpinmaps(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->bp->bpinmaps = node->i_value;
	return true;
}

static bool cb_dbg_forks(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace_forks = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_gdb_page_size(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value < 64) { // 64 is hardcoded min packet size
		return false;
	}
	if (isGdbPlugin (core)) {
		char cmd[64];
		snprintf (cmd, sizeof (cmd), "page_size %" PFMT64d, node->i_value);
		free (r_io_system (core->io, cmd));
	}
	return true;
}

static bool cb_dbg_gdb_retries(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value <= 0) {
		return false;
	}
	if (isGdbPlugin (core)) {
		r_strf_var (cmd, 64, "retries %" PFMT64d, node->i_value);
		free (r_io_system (core->io, cmd));
	}
	return true;
}

static bool cb_dbg_execs(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
#if __linux__
	RCore *core = (RCore *)user;
	core->dbg->trace_execs = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
#else
	if (node->i_value) {
		R_LOG_WARN ("dbg.execs is not supported in this platform");
	}
#endif
	return true;
}

static bool cb_dbg_clone(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace_clone = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_follow_child(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->follow_child = node->i_value;
	return true;
}

static bool cb_dbg_trace_continue(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace_continue = node->i_value;
	return true;
}

static bool cb_dbg_aftersc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace_aftersyscall = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_runprofile(void *user, void *data) {
	RCore *r = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free ((void *)r->io->runprofile);
	if (!node || !*(node->value)) {
		r->io->runprofile = NULL;
	} else {
		r->io->runprofile = strdup (node->value);
	}
	return true;
}

static bool cb_dbg_args(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!node || !*(node->value)) {
		core->io->args = NULL;
	} else {
		core->io->args = strdup (node->value);
	}
	return true;
}

static bool cb_dbgstatus(void *user, void *data) {
	RCore *r = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (r_config_get_b (r->config, "cfg.debug")) {
		if (node->i_value) {
			r_config_set (r->config, "cmd.prompt", ".dr*; drd; sr PC;pi 1;s-");
		} else {
			r_config_set (r->config, "cmd.prompt", ".dr*");
		}
	}
	return true;
}

static bool cb_dbgbackend(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_debug_plugin_list (core->dbg, 'q');
		return false;
	}
	// TODO: probably not necessary
	if (!strcmp (node->value, "bf")) {
		r_config_set (core->config, "asm.arch", "bf");
	}
	if (r_debug_use (core->dbg, node->value)) {
		RDebugPlugin *plugin = R_UNWRAP3 (core->dbg, current, plugin);
		if (plugin) {
			const char *name = plugin->meta.name;
			// cmd_aei (core);
			free (node->value);
			node->value = strdup (name);
		}
	} else {
		R_LOG_ERROR ("Cannot find a valid debug plugin");
	}
	return true;
}

static bool cb_gotolimit(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!r_sandbox_enable (0)) {
		if (core->anal->esil) {
			core->anal->esil_goto_limit = node->i_value;
		}
	}
	return true;
}

static bool cb_esilverbose(void *user, void *data) {
	RCore *core = user;
	RConfigNode *node = data;
	if (core->anal->esil) {
		core->anal->esil->verbose = node->i_value;
	}
	return true;
}

static bool cb_esilstackdepth(void *user, void *data) {
	RConfigNode *node = data;
	if (node->i_value < 3) {
		R_LOG_ERROR ("esil.stack.depth must be greater than 2");
		node->i_value = 32;
	}
	return true;
}

static bool cb_esiltraprevert(void *user, void *data) {
	RCore *core = user;
	RConfigNode *node = data;
	if (node->i_value) {
		core->esil.cfg |= R_CORE_ESIL_TRAP_REVERT_CONFIG;
	} else {
		core->esil.cfg &= ~R_CORE_ESIL_TRAP_REVERT_CONFIG;
	}
	return true;
}

static bool cb_fixrows(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = data;
	core->cons->fix_rows = (int)node->i_value;
	return true;
}

static bool cb_fixcolumns(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->fix_columns = atoi (node->value);
	return true;
}

static bool cb_rows(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->force_rows = node->i_value;
	return true;
}

static bool cb_cmd_hexcursor(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->cfmt = node->value;
	return true;
}

static bool cb_hexcompact(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COMPACT;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_COMPACT);
	}
	return true;
}

static bool cb_hex_pairs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->pairs = node->i_value;
	return true;
}

static bool cb_hex_section(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SECTION;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_SECTION;
	}
	return true;
}

static bool cb_hex_align(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_ALIGN;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_ALIGN;
	}
	return true;
}

static bool cb_io_unalloc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_UNALLOC;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_UNALLOC;
	}
	return true;
}

static bool cb_io_unalloc_ch(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->io_unalloc_ch = *node->value? node->value[0]: ' ';
	return true;
}

static bool cb_io_overlay(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->overlay = node->i_value;
	return true;
}

static bool cb_hex_header(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_HEADER;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_HEADER;
	}
	return true;
}

static bool cb_hex_bytes(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
	} else {
		core->print->flags |= R_PRINT_FLAGS_NONHEX;
	}
	return true;
}

static bool cb_hex_ascii(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags &= ~R_PRINT_FLAGS_NONASCII;
	} else {
		core->print->flags |= R_PRINT_FLAGS_NONASCII;
	}
	return true;
}

static bool cb_hex_style(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_STYLE;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_STYLE;
	}
	return true;
}

static bool cb_hex_hdroff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_HDROFF;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_HDROFF;
	}
	return true;
}

static bool cb_hexcomments(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COMMENT;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_COMMENT;
	}
	return true;
}

static bool cb_iopcache(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if ((bool)node->i_value) {
		if (core) {
			r_config_set_b (core->config, "io.pcache.read", true);
			r_config_set_b (core->config, "io.pcache.write", true);
		}
	} else {
		if (core && core->io) {
			r_io_desc_cache_fini_all (core->io);
			r_config_set_b (core->config, "io.pcache.read", false);
			r_config_set_b (core->config, "io.pcache.write", false);
		}
	}
	return true;
}

static bool cb_iopcacheread(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 1;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 2;
			if (! (core->io->p_cache & 2)) {
				r_io_desc_cache_fini_all (core->io);
				r_config_set_b (core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

static bool cb_iopcachewrite(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 2;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 1;
			if (! (core->io->p_cache & 1)) {
				r_io_desc_cache_fini_all (core->io);
				r_config_set_b (core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

R_API bool r_core_esil_cmd(REsil *esil, const char *cmd, ut64 a1, ut64 a2) {
	if (cmd && *cmd) {
		RCore *core = esil->anal->user;
		r_core_cmdf (core, "%s %" PFMT64d " %" PFMT64d, cmd, a1, a2);
		return core->num->value;
	}
	return false;
}

static bool cb_cmd_esil_ioer(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_ioer);
		core->anal->esil->cmd_ioer = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_todo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_todo);
		core->anal->esil->cmd_todo = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_intr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_intr);
		core->anal->esil->cmd_intr = strdup (node->value);
	}
	return true;
}

static bool cb_mdevrange(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->mdev_range);
		core->anal->esil->mdev_range = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_pin(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal) {
		free (core->anal->pincmd);
		core->anal->pincmd = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_step(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_step);
		core->anal->esil->cmd_step = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_step_out(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_step_out);
		core->anal->esil->cmd_step_out = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_mdev(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_mdev);
		core->anal->esil->cmd_mdev = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_trap(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		core->anal->esil->cmd_trap = strdup (node->value);
	}
	return true;
}

static bool cb_fsview(void *user, void *data) {
	int type = R_FS_VIEW_NORMAL;
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	if (!strcmp (node->value, "all")) {
		type = R_FS_VIEW_ALL;
	}
	if (!strstr (node->value, "del")) {
		type |= R_FS_VIEW_DELETED;
	}
	if (!strstr (node->value, "spe")) {
		type |= R_FS_VIEW_SPECIAL;
	}
	r_fs_view (core->fs, type);
	return true;
}

static bool cb_cmddepth(void *user, void *data) {
	RCore *core = (RCore *)user;
	int c = R_MAX (((RConfigNode *)data)->i_value, 0);
	core->max_cmd_depth = c;
	core->cur_cmd_depth = c;
	return true;
}

static bool cb_hexcols(void *user, void *data) {
	RCore *core = (RCore *)user;
	int c = R_MIN (1024, R_MAX (((RConfigNode *)data)->i_value, 0));
	core->print->cols = c; // & ~1;
	core->dbg->regcols = c / 4;
	return true;
}

static bool cb_hexstride(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	((RCore *)user)->print->stride = node->i_value;
	return true;
}

static bool cb_search_kwidx(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->search->n_kws = node->i_value;
	return true;
}

static bool cb_io_cache_mode(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->cachemode = node->i_value;
	return true;
}

static bool cb_io_cache_nodup(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->nodup = node->i_value;
	return true;
}

static bool cb_io_cache_read(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->io->cache.mode |= R_PERM_R;
	} else {
		core->io->cache.mode &= ~R_PERM_R;
	}
	return true;
}

static bool cb_io_cache_write(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->io->cache.mode |= R_PERM_W;
	} else {
		core->io->cache.mode &= ~R_PERM_W;
	}
	return true;
}

static bool cb_io_cache(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->io->cache.mode |= R_PERM_X;
	} else {
		core->io->cache.mode &= ~R_PERM_X;
	}
	return true;
}

#if 0
static bool cb_ioaslr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->aslr = (bool)node->i_value;
	return true;
}
#endif

static bool cb_binaslr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.fake_aslr = (bool)node->i_value;
	return true;
}

static bool cb_io_pava(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->pava = node->i_value;
	if (node->i_value && core->io->va) {
		R_LOG_WARN ("You may probably want to disable io.va too");
	}
	return true;
}

static bool cb_iova(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value != core->io->va) {
		core->io->va = node->i_value;
		/* ugly fix for r2 -d ... "r2 is going to die soon ..." */
		if (core->io->desc) {
			r_core_block_read (core);
		}
#if 0
		/* reload symbol information */
		if (r_list_length (r_bin_get_sections (core->bin)) > 0) {
			r_core_cmd0 (core, ".ia*");
		}
#endif
	}
	return true;
}

static bool cb_ioff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->ff = (bool)node->i_value;
	return true;
}

static bool cb_iomask(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->mask = node->i_value;
	core->flags->mask = node->i_value;
	return true;
}

static bool cb_io_oxff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->Oxff = (ut8)node->i_value;
	return true;
}

static bool cb_ioautofd(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->io->autofd = (bool)node->i_value;
	return true;
}

static bool cb_scr_color_grep(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;

	/* Let cons know we have a new pager. */
	core->cons->context->grep_color = node->i_value;
	return true;
}

static bool cb_scr_color_grep_highlight(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->context->grep_highlight = node->i_value;
	return true;
}

static bool cb_pager(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		R_LOG_INFO ("scr.pager must be '..' for internal less, or the path to a program in $PATH");
		return false;
	}
	/* Let cons know we have a new pager. */
	free (core->cons->pager);
	core->cons->pager = strdup (node->value);
	return true;
}

static bool cb_breaklines(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->break_lines = node->i_value;
	return true;
}

static bool cb_scr_gadgets(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->scr_gadgets = node->i_value;
	return true;
}

static bool cb_fps(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->fps = node->i_value;
	return true;
}

static bool cb_scrtheme(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value) {
		if (*node->value == '?') {
			r_core_cmd_call (core, "eco");
		} else {
			r_core_cmdf (core, "'eco %s", node->value);
		}
	}
	return true;
}

static bool cb_scrbreakword(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *arg = (*node->value)? node->value: NULL;
	r_cons_breakword (core->cons, arg);
	return true;
}

static bool cb_scrtimeout(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_cons_break_timeout (core->cons, node->i_value);
	return true;
}

static bool cb_scrcolumns(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	int n = atoi (node->value);
	core->cons->force_columns = n;
	core->dbg->regcols = n / 20;
	return true;
}

static bool cb_scrfgets(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->user_fgets = node->i_value
		? NULL
		: (void *)r_core_fgets;
	return true;
}

static bool cb_scrcss(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		R_LOG_TODO ("Not implemented");
		return false;
	}
	return true;
}

static bool cb_scrcss_prefix(void *user, void *data) {
	// do nothing for now
	return true;
}

static bool cb_scrhtml(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	RConsContext *ctx = core->cons->context;
	ctx->was_html = ctx->is_html;
	ctx->is_html = node->i_value;
	// TODO: control error and restore old value (return false?) show errormsg?
	return true;
}

static bool cb_scrhighlight(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_cons_highlight (core->cons, node->value);
	return true;
}

#if R2__WINDOWS__
static inline DWORD modevalue(DWORD mode, bool set) {
	if (set) {
		return mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	}
	return mode & ~ENABLE_VIRTUAL_TERMINAL_PROCESSING & ~ENABLE_WRAP_AT_EOL_OUTPUT;
}

static bool scr_vtmode(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (r_str_is_true (node->value)) {
		node->i_value = 1;
	}
	node->i_value = node->i_value > 2? 2: node->i_value;
	core->cons->line->vtmode = core->cons->vtmode = node->i_value;

	DWORD mode;
	HANDLE input = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (input, &mode);
	if (node->i_value == 2) {
		SetConsoleMode (input, mode & ENABLE_VIRTUAL_TERMINAL_INPUT);
		core->cons->term_raw = ENABLE_VIRTUAL_TERMINAL_INPUT;
	} else {
		SetConsoleMode (input, mode & ~ENABLE_VIRTUAL_TERMINAL_INPUT);
		core->cons->term_raw = 0;
	}
	HANDLE streams[] = { GetStdHandle (STD_OUTPUT_HANDLE), GetStdHandle (STD_ERROR_HANDLE) };
	int i;
	bool set = (node->i_value > 0);
	for (i = 0; i < R_ARRAY_SIZE (streams); i++) {
		GetConsoleMode (streams[i], &mode);
		SetConsoleMode (streams[i], modevalue (mode, set));
	}
	return true;
}
#endif

static bool cb_screcho(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->echo = node->i_value;
	return true;
}

static bool cb_scrlinesleep(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->linesleep = node->i_value;
	return true;
}

static bool cb_scr_maxpage(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->maxpage = node->i_value;
	return true;
}

static bool cb_scrpagesize(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->pagesize = node->i_value;
	return true;
}

static bool cb_scrflush(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->context->flush = node->i_value;
	return true;
}

static bool cb_scrstrconv(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			RCore *core = (RCore *)user;
			r_cons_printf (core->cons,
				"Valid values for scr.strconv:\n"
				"  asciiesc  convert to ascii with non-ascii chars escaped (see str.escbslash)\n"
				"  asciidot  non-printable chars are represented with a dot\n"
				"  pascal    takes the first byte as the length for the string\n"
				"  raw       perform no conversion from non-ascii chars\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	} else {
		free (core->print->strconv_mode);
		core->print->strconv_mode = strdup (node->value);
	}
	return true;
}

static bool cb_graphformat(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		RCore *core = (RCore *)user;
		r_cons_printf (core->cons, "png\njpg\npdf\nps\nsvg\njson\n");
		return false;
	}
	return true;
}

static bool cb_exectrap(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	if (core->anal && core->anal->esil) {
		core->anal->esil->exectrap = node->i_value;
	}
	return true;
}

static bool cb_iotrap(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	if (core->anal && core->anal->esil) {
		core->anal->esil->iotrap = node->i_value;
	}
	return true;
}

static bool cb_romem(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	if (node->i_value) {
		core->esil.cfg |= R_CORE_ESIL_RO;
	} else {
		core->esil.cfg &= ~R_CORE_ESIL_RO;
	}
	return true;
}

static bool cb_esilnonull(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	RCore *core = (RCore *)user;
	if (node->i_value) {
		core->esil.cfg |= R_CORE_ESIL_NONULL;
	} else {
		core->esil.cfg &= ~R_CORE_ESIL_NONULL;
	}
	return true;
}

static bool cb_scr_bgfill(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_BGFILL;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_BGFILL);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_scrint(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value && r_sandbox_enable (0)) {
		return false;
	}
	core->cons->context->is_interactive = node->i_value;
	return true;
}

static bool cb_scrnkey(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	return true;
}

static bool cb_scrclippy(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		print_node_options (user, node);
		return false;
	}
	return true;
}

static bool cb_scr_demo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	RCons *cons = core->cons;
	cons->context->demo = node->i_value;
	if (cons->line) {
		cons->line->demo = node->i_value;
	}
	return true;
}

static bool cb_scr_histblock(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->histblock = node->i_value;
	return true;
}

static bool cb_scr_histsize(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_line_hist_set_size (core->cons->line, node->i_value);
	return true;
}

static bool cb_scr_limit(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->context->buffer_limit = node->i_value;
	return true;
}

static bool cb_scrprompt(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->scr_prompt = node->i_value;
	core->cons->line->echo = node->i_value;
	return true;
}

static bool cb_scrrows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_rows = n;
	return true;
}

static bool cb_contiguous(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->search->contiguous = node->i_value;
	return true;
}

static bool cb_searchalign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return true;
}

static bool cb_segoff(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SEGOFF;
	} else {
		core->print->flags &= (((ut32)-1) &(~R_PRINT_FLAGS_SEGOFF));
	}
	return true;
}

static bool cb_asm_addr_segment_bits(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->rasm->config->seggrn = node->i_value;
	return true;
}

static bool cb_stopthreads(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->stop_all_threads = node->i_value;
	return true;
}

static bool cb_scr_prompt_popup(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->show_autocomplete_widget = node->i_value;
	return true;
}

static bool cb_swstep(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->swstep = node->i_value;
	return true;
}

static bool cb_consbreak(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->consbreak = node->i_value;
	return true;
}

static bool cb_config_file_output(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->teefile = node->value;
	return true;
}

static bool cb_trace(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace->enabled = node->i_value;
	return true;
}

static bool cb_tracetag(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->dbg->trace->tag = node->i_value;
	return true;
}

static bool cb_utf8(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	r_cons_set_utf8 (core->cons, (bool)node->i_value);
	return true;
}

static bool cb_utf8_curvy(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->use_utf8_curvy = node->i_value;
	return true;
}

static bool cb_dotted(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->cons->dotted_lines = node->i_value;
	return true;
}

static bool cb_zoombyte(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	switch (*node->value) {
	case 'p':
	case 'f':
	case 's':
	case '0':
	case 'F':
	case 'e':
	case 'h':
		core->print->zoom->mode = *node->value;
		break;
	default:
		R_LOG_ERROR ("Invalid zoom.byte value. See pz? for help");
		r_cons_printf (core->cons, "pzp\npzf\npzs\npz0\npzF\npze\npzh\n");
		return false;
	}
	return true;
}

static bool cb_analverbose(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->verbose = node->i_value;
	return true;
}

static bool cb_binverbose(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.verbose = node->i_value;
	return true;
}

static bool cb_prjname(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *prjname = node->value;
	if (*prjname == '?') {
		r_core_project_list (core, 0);
		return false;
	}
	if (r_project_is_loaded (core->prj)) {
		if (*prjname) {
			if (!strcmp (prjname, core->prj->name)) {
				return true;
			}
			if (r_project_rename (core->prj, prjname)) {
				return true;
			}
			R_LOG_ERROR ("Cannot rename project");
		} else {
			r_project_close (core->prj);
		}
	} else {
		if (*prjname) {
			if (r_project_open (core->prj, prjname, NULL)) {
				return true;
			}
			R_LOG_ERROR ("Cannot open project");
		} else {
			return true;
		}
	}
	return false;
}

static bool cb_rawstr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.rawstr = node->i_value;
	return true;
}
static bool cb_bin_classes(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const ut64 req = R_BIN_REQ_CLASSES;
	if (node->i_value) {
		core->bin->filter_rules |= req;
	} else {
		core->bin->filter_rules &= ~req;
	}
	return true;
}

static bool cb_debase64(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->bin->options.debase64 = node->i_value;
	return true;
}

static bool cb_binstrings(void *user, void *data) {
	const ut64 req = R_BIN_REQ_STRINGS;
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->bin->filter_rules |= req;
	} else {
		core->bin->filter_rules &= ~req;
	}
	return true;
}

static bool cb_demangle_trylib(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!core || !core->bin) {
		return false;
	}
	core->bin->options.demangle_trylib = node->i_value;
	return true;
}

static bool cb_bindbginfo(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!core || !core->bin) {
		return false;
	}
	core->bin->want_dbginfo = node->i_value;
	return true;
}

static bool cb_binprefix(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!core || !core->bin) {
		return false;
	}
	if (node->value && *node->value) {
		if (!strcmp (node->value, "auto")) {
			if (!core->bin->file) {
				return false;
			}
			char *name = (char *)r_file_basename (core->bin->file);
			if (name) {
				r_name_filter (name, strlen (name));
				r_str_filter (name, strlen (name));
				core->bin->prefix = strdup (name);
				free (name);
			}
		} else {
			core->bin->prefix = node->value;
		}
	}
	return true;
}

static bool cb_binmaxstrbuf(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core->bin) {
		int v = node->i_value;
		ut64 old_v = core->bin->options.maxstrbuf;
		if (v < 1) {
			v = 4; // HACK
		}
		core->bin->options.maxstrbuf = v;
		if (v > old_v) {
			r_bin_reset_strings (core->bin);
		}
		return true;
	}
	return true;
}

static bool cb_binmaxsymlen(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core->bin) {
		core->bin->options.maxsymlen = node->i_value;
		return true;
	}
	return true;
}

static bool cb_binmaxstr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core->bin) {
		int v = node->i_value;
		if (v < 1) {
			v = 0; // HACK
		}
		core->bin->options.maxstrlen = v;
		r_bin_reset_strings (core->bin);
		return true;
	}
	return true;
}

static bool cb_binminstr(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core->bin) {
		int v = node->i_value;
		if (v < 1) {
			v = 4; // HACK
		}
		core->bin->options.minstrlen = v;
		r_bin_reset_strings (core->bin);
		return true;
	}
	return true;
}

static bool cb_binstralign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (core->bin) {
		core->bin->options.str_align = R_MAX ((int)node->i_value, 0);
		r_bin_reset_strings (core->bin);
		return true;
	}
	return true;
}

static bool cb_searchin(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			r_cons_printf (core->cons, "Valid values for search.in (depends on .from/.to and io.va):\n"
						"range              search between .from/.to boundaries\n"
						"flag               find boundaries in ranges defined by flags larger than 1 byte\n"
						"flag:[glob]        find boundaries in flags matching given glob and larger than 1 byte\n"
						"block              search in the current block\n"
						"io.map             search in current map\n"
						"io.maps            search in all maps\n"
						"io.maps.[rwx]      search in all r-w-x io maps\n"
						"bin.segment        search in current mapped segment\n"
						"bin.segments       search in all mapped segments\n"
						"bin.segments.[rwx] search in all r-w-x segments\n"
						"bin.section        search in current mapped section\n"
						"bin.sections       search in all mapped sections\n"
						"bin.sections.[rwx] search in all r-w-x sections\n"
						"dbg.stack          search in the stack\n"
						"dbg.heap           search in the heap\n"
						"dbg.map            search in current memory map\n"
						"dbg.maps           search in all memory maps\n"
						"dbg.maps.[rwx]     search in all executable marked memory maps\n"
						"anal.fcn           search in the current function\n"
						"anal.bb            search in the current basic-block\n");
		} else {
			print_node_options (user, node);
		}
		return false;
	}
	// Set anal.noncode if exec bit set in anal.in
	if (r_str_startswith (node->name, "anal")) {
		core->anal->opt.noncode = (strchr (node->value, 'x') == NULL);
	}
	return true;
}

static int __dbg_swstep_getter(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	node->i_value = core->dbg->swstep;
	return true;
}

static bool cb_dirpfx(RCore *core, RConfigNode *node) {
	r_sys_prefix (node->value);
	return true;
}

static bool cb_analsyscc(RCore *core, RConfigNode *node) {
	if (core && core->anal) {
		if (*node->value == '?') {
			r_core_cmd_call (core, "afcl");
			return false;
		}
		r_anal_set_syscc_default (core->anal, node->value);
	}
	return true;
}

static bool cb_analcc_getter(RCore *core, RConfigNode *node) {
	const char *cc = r_anal_cc_default (core->anal);
	if (cc) {
		free (node->value);
		node->value = strdup (cc);
	}
	return true;
}

static bool cb_analcc(RCore *core, RConfigNode *node) {
	if (core && core->anal) {
		node->getter = (RConfigCallback)cb_analcc_getter;
		if (*node->value == '?') {
			r_core_cmd_call (core, "afcl");
			return false;
		}
		r_anal_set_cc_default (core->anal, node->value);
	}
	return true;
}

static bool cb_anal_roregs(RCore *core, RConfigNode *node) {
	R_RETURN_VAL_IF_FAIL (core && core->anal && core->anal->reg, false);
	r_reg_ro_reset (core->anal->reg, node->value);
	return true;
}

static bool cb_anal_gp(RCore *core, RConfigNode *node) {
	ut64 gpv = node->i_value;
	gpv = (gpv == UT64_MAX)? gpv: (gpv + 0xf) & ~ (ut64)0xf;
	node->i_value = gpv;
	core->anal->gp = gpv;
	r_reg_setv (core->anal->reg, "gp", gpv);
	core->anal->config->gp = gpv;
	return true;
}

static bool cb_anal_cs(RCore *core, RConfigNode *node) {
	// core->anal->cs = node->i_value;
	core->rasm->config->segbas = node->i_value;
	return true;
}

static bool cb_anal_from(RCore *core, RConfigNode *node) {
	if (r_config_get_b (core->config, "anal.limits")) {
		r_anal_set_limits (core->anal,
			r_config_get_i (core->config, "anal.from"),
			r_config_get_i (core->config, "anal.to"));
	}
	return true;
}

static bool cb_anal_fixed_bits(void *user, void *_node) {
	RConfigNode *node = _node;
	RCore *core = (RCore *)user;
	core->fixedbits = node->i_value;
	return true;
}

static bool cb_anal_fixed_arch(void *user, void *_node) {
	RConfigNode *node = _node;
	RCore *core = (RCore *)user;
	core->fixedarch = node->i_value;
	return true;
}

static bool cb_anal_fixed_thumb(void *user, void *_node) {
	RConfigNode *node = _node;
	RCore *core = (RCore *)user;
	core->anal->opt.armthumb = !node->i_value;
	return true;
}

static bool cb_anal_limits(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	if (node->i_value) {
		r_anal_set_limits (core->anal,
			r_config_get_i (core->config, "anal.from"),
			r_config_get_i (core->config, "anal.to"));
	} else {
		r_anal_unset_limits (core->anal);
	}
	return 1;
}

static bool cb_anal_noret_refs(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	core->anal->opt.recursive_noreturn = node->i_value;
	return 1;
}

static bool cb_anal_slow(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	core->anal->opt.slow = node->i_value;
	return 1;
}

static bool cb_anal_noret(void *user, RConfigNode *node) {
	RCore *core = (RCore *)user;
	core->anal->opt.propagate_noreturn = node->i_value;
	return 1;
}

static bool cb_anal_jmptbl(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.jmptbl = node->i_value;
	return true;
}

static bool cb_anal_cjmpref(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.cjmpref = node->i_value;
	return true;
}

static bool cb_anal_jmpref(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.jmpref = node->i_value;
	return true;
}

static bool cb_anal_jmpabove(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.jmpabove = node->i_value;
	return true;
}

static bool cb_anal_loads(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.loads = node->i_value;
	return true;
}

static bool cb_anal_followdatarefs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.followdatarefs = node->i_value;
	return true;
}

static bool cb_anal_jmpmid(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.jmpmid = node->i_value;
	return true;
}

static bool cb_anal_searchstringrefs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.searchstringrefs = node->i_value;
	return true;
}

static bool cb_anal_pushret(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.pushret = node->i_value;
	return true;
}

static bool cb_anal_types_parser(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (!strcmp (node->value, "?")) {
		RAnalPlugin *p;
		RListIter *iter;
		r_list_foreach (core->anal->plugins, iter, p) {
			if (p->tparse_text || p->tparse_file) {
				r_cons_println (core->cons, p->meta.name);
			}
		}
	} else {
		free (core->anal->opt.tparser);
		core->anal->opt.tparser = strdup (node->value);
	}
	return true;
}

static bool cb_anal_brokenrefs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.followbrokenfcnsrefs = node->i_value;
	return true;
}

static bool cb_anal_trycatch(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.trycatch = node->i_value;
	return true;
}

static bool cb_anal_bb_max_size(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.bb_max_size = node->i_value;
	return true;
}

static bool cb_asmabi(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	free (core->anal->config->abi);
	core->anal->config->abi = strdup (node->value);
	return true;
}

static bool cb_anal_cxxabi(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;

	if (*node->value == '?') {
		print_node_options (user, node);
		return false;
	}

	if (*node->value) {
		if (!strcmp (node->value, "itanium")) {
			core->anal->cxxabi = R_ANAL_CPP_ABI_ITANIUM;
			return true;
		} else if (!strcmp (node->value, "msvc")) {
			core->anal->cxxabi = R_ANAL_CPP_ABI_MSVC;
			return true;
		}
		R_LOG_ERROR ("Supported values: itanium, msvc");
	}
	return false;
}

static bool cb_linesto(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	ut64 from = (ut64)r_config_get_i (core->config, "lines.from");
	int io_sz = r_io_size (core->io);
	ut64 to = r_num_math (core->num, node->value);
	if (to == 0) {
		core->print->lines_cache_sz = -1;
		return true;
	}
	if (to > from + io_sz) {
		R_LOG_ERROR ("lines.to: can't exceed addr 0x%08" PFMT64x " 0x%08" PFMT64x " %d", from, to, io_sz);
		return true;
	}
	if (to > from) {
		core->print->lines_cache_sz = r_core_lines_initcache (core, from, to);
	} else {
		R_LOG_ERROR ("Invalid range 0x%08" PFMT64x " .. 0x%08" PFMT64x, from, to);
	}
	return true;
}

static bool cb_linesabs(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->print->lines_abs = node->i_value;
	if (core->print->lines_abs && core->print->lines_cache_sz <= 0) {
		ut64 from = (ut64)r_config_get_i (core->config, "lines.from");
		const char *to_str = r_config_get (core->config, "lines.to");
		ut64 to = r_num_math (core->num, (to_str && *to_str)? to_str: "$s");
		core->print->lines_cache_sz = r_core_lines_initcache (core, from, to);
		if (core->print->lines_cache_sz == -1) {
			R_LOG_ERROR ("\"lines.from\" and \"lines.to\" must be set");
		} else {
			R_LOG_INFO ("Found %d lines", core->print->lines_cache_sz - 1);
		}
	}
	return true;
}

static bool cb_malloc(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->value) {
		const char *valid[] = {
			"glibc",
			"macos",
			"windows",
			"jemalloc",
			NULL
		};
		const char *nv = node->value;
		if (core->dbg) {
			int i;
			for (i = 0; valid[i]; i++) {
				if (!strcmp (valid[i], nv)) {
					core->dbg->malloc = data;
				}
			}
		}
	}
	return true;
}

static bool cb_config_log_level(void *user, void *nodeptr) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)nodeptr;
	if (!strcmp (node->value, "?")) {
		int i;
		for (i = 0;; i++) {
			const char *lm = r_log_level_tostring (i);
			if (!strcmp (lm, "UNKN")) {
				break;
			}
			char *llm = strdup (lm);
			r_str_case (llm, false);
			r_cons_printf (core->cons, "%d  %s\n", i, llm);
			free (llm);
		}
		return false;
	}
	int ll = r_log_level_fromstring (node->value);
	if (ll != -1) {
		r_log_set_level (ll);
		return true;
	}
	r_log_set_level (node->i_value);
	return true;
}

static bool cb_config_log_traplevel(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_traplevel (node->i_value);
	return true;
}

static bool cb_config_log_ts(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_show_ts (node->i_value);
	return true;
}

static bool cb_config_log_filter(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	const char *value = node->value;
	r_log_set_filter (value);
	return true;
}

static bool cb_config_log_file(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	const char *value = node->value;
	r_log_set_file (value);
	return true;
}

static bool cb_log_origin(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_show_origin (r_str_is_true (node->value));
	return true;
}

static bool cb_log_source(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_show_source (r_str_is_true (node->value));
	return true;
}

static bool cb_config_log_colors(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_colors (r_str_is_true (node->value));
	return true;
}

static bool cb_log_cons(void *user, int level, const char *origin, const char *msg) {
	if (!msg) {
		// log level doesn't match
		return false;
	}
	RCore *core = (RCore *)user;
	const char *levelstr = r_log_level_tostring (level);
	const char *originstr = origin? origin: "";
	r_cons_printf (core->cons, "%s: [%s] %s\n", levelstr, originstr, msg);
	return true;
}

static bool cb_config_log_cons(void *coreptr, void *nodeptr) {
	RCore *core = (RCore *)coreptr;
	RConfigNode *node = (RConfigNode *)nodeptr;
	if (r_str_is_true (node->value)) {
		r_config_set_b (core->config, "log.quiet", true);
		r_log_add_callback (cb_log_cons, NULL);
	} else {
		r_config_set_b (core->config, "log.quiet", false);
		r_log_del_callback (cb_log_cons);
	}
	return true;
}

static bool cb_config_log_quiet(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_quiet (r_str_is_true (node->value));
	return true;
}

static bool cb_dbg_verbose(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	const char *value = node->value;
	switch (value[0]) {
	case 't':
	case 'T':
		core->dbg->verbose = true;
		break;
	default:
		core->dbg->verbose = false;
		break;
	}
	return true;
}

static bool cb_prjvctype(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = data;
	char *git = r_file_path ("git");
	bool have_git = git != NULL;
	free (git);
	if (*node->value == '?') {
		if (have_git) {
			r_cons_println (core->cons, "git");
		}
		r_cons_println (core->cons, "rvc");
		return true;
	}
	if (!strcmp (node->value, "git")) {
		if (have_git) {
			return true;
		}
		return false;
	}
	if (!strcmp (node->value, "rvc")) {
		return true;
	}
	R_LOG_ERROR ("Unknown version control '%s'", node->value);
	return false;
}

R_API int r_core_config_init(RCore *core) {
	int i;
	char *p, *tmpdir;
	RConfigNode *n;
	RConfig *cfg = core->config = r_config_new (core);
	if (!cfg) {
		return 0;
	}
	cfg->num = core->num;
	/* dir.prefix is used in other modules, set it first */
	{
		char *pfx = r_sys_getenv ("R2_PREFIX");
#if R2__WINDOWS__
		const char *invoke_dir = r_sys_prefix (NULL);
		if (!pfx && invoke_dir) {
			pfx = strdup (invoke_dir);
		}
#endif
		if (!pfx) {
			pfx = strdup (R2_PREFIX);
		}
		SETCB ("dir.prefix", pfx, (RConfigCallback)&cb_dirpfx, "Default prefix r2 was compiled for");
		free (pfx);
	}
#if __ANDROID__
	{ // use dir.home and also adjust check for permissions in directory before choosing a home
		char *h = r_sys_getenv (R_SYS_HOME);
		if (h) {
			if (!strcmp (h, "/")) {
				r_sys_setenv (R_SYS_HOME, "/data/local/tmp");
			}
			free (h);
		}
	}
#endif
	SETCB ("cmd.times", "", &cb_cmdtimes, "run when a command is repeated (number prefix)");
	SETCB ("cfg.taskmode", "thread", &cb_cfg_taskmode, "default execution mode for new core tasks (core, thread, fork)");
	/* pdb */
	SETS ("pdb.useragent", "microsoft-symbol-server/6.11.0001.402", "User agent for Microsoft symbol server");
	SETS ("pdb.server", "https://msdl.microsoft.com/download/symbols", "Space separated list of base URLs for Microsoft symbol servers");
	{
		char *pdb_path = r_xdg_datadir ("pdb");
		SETS ("pdb.symstore", pdb_path? pdb_path: "", "path to downstream symbol store"); // XXX rename to dir.pdb
		R_FREE (pdb_path);
	}
	SETI ("pdb.extract", 1, "avoid extract of the pdb file, just download");
	SETI ("pdb.autoload", false, "automatically load the required pdb files for loaded DLLs");

	/* anal */
	SETB ("anal.onchange", "false", "automatically reanalyze function if any byte has changed (EXPERIMENTAL)");
	SETI ("anal.fcnalign", 0, "use ArchInfo.funcAlign if zero, otherwise override (used by aap and others)");
	SETCB ("anal.prefix.default", "fcn", &cb_defprefix, "fallback prefix for function names");
	SETCB ("anal.prefix.dynamic", "false", &cb_dynprefix, "enable dynamic prefix resolution");
	SETCB ("anal.prefix.marker", "pfx.fcn.", &cb_prefix_marker, "flag name prefix to identify dynamic prefixes");
	SETICB ("anal.prefix.radius", 0x1000, &cb_prefix_radius, "max distance to consider a flag as valid for prefix assignment");
	const char *analcc = r_anal_cc_default (core->anal);
	SETCB ("anal.cc", analcc? analcc: "", (RConfigCallback)&cb_analcc, "specify default calling convention");
	const char *analsyscc = r_anal_syscc_default (core->anal);
	SETCB ("anal.syscc", analsyscc? analsyscc: "", (RConfigCallback)&cb_analsyscc, "specify default syscall calling convention");
	SETCB ("anal.verbose", "false", &cb_analverbose, "show RAnal warnings when analyzing code");
	SETB ("anal.mask", "false", "use the smart aobm command to compute the binary mask of the instruction"); // TODO: must be true by default
	SETB ("anal.a2f", "false", "use the new WIP analysis algorithm (core/p/a2f), anal.depth ignored atm");
	SETCB ("anal.roregs", "gp,zero", (RConfigCallback)&cb_anal_roregs, "comma separated list of register names to be readonly");
	SETICB ("anal.cs", 0, (RConfigCallback)&cb_anal_cs, "set the value for the x86-16 CS segment register (see asm.addr.segment and asm.addr.segment.bits)");
	SETICB ("anal.gp", 0, (RConfigCallback)&cb_anal_gp, "set the value of the GP register (MIPS)");
	SETB ("anal.fixed.gp", "true", "set gp register to anal.gp before emulating each instruction in aae");
	SETCB ("anal.fixed.arch", "false", &cb_anal_fixed_arch, "permit arch changes during analysis");
	SETCB ("anal.fixed.bits", "false", &cb_anal_fixed_bits, "permit bits changes during analysis (arm/thumb)");
	SETCB ("anal.fixed.thumb", "true", &cb_anal_fixed_thumb, "permit switching between arm:32 and arm:16 during analysis");
	SETCB ("anal.limits", "false", (RConfigCallback)&cb_anal_limits, "restrict analysis to address range [anal.from:anal.to]");
	SETCB ("anal.noret.refs", "false", (RConfigCallback)&cb_anal_noret_refs, "recursive no return checks (EXPERIMENTAL)");
	SETCB ("anal.slow", "true", (RConfigCallback)&cb_anal_slow, "uses emulation and deeper analysis for better results");
	SETS ("anal.emu", "true", "run aaef after analysis");
	SETS ("anal.emumem", "false", "run aaef with memory cache enabled after analysis (EXPERIMENTAL)");
	SETCB ("anal.noret", "true", (RConfigCallback)&cb_anal_noret, "propagate noreturn attributes (EXPERIMENTAL)");
	SETCB ("anal.limits", "false", (RConfigCallback)&cb_anal_limits, "restrict analysis to address range [anal.from:anal.to]");
	SETICB ("anal.from", -1, (RConfigCallback)&cb_anal_from, "lower limit on the address range for analysis");
	SETICB ("anal.to", -1, (RConfigCallback)&cb_anal_from, "upper limit on the address range for analysis");
	n = NODECB ("anal.in", "io.maps.x", &cb_searchin); // TODO: use io.sections.x seems to break db/anal/calls.. why?
	n = NODECB ("anal.in", "bin.ormaps.x", &cb_searchin); // R2R db/anal/calls
	SETDESC (n, "specify search boundaries for analysis");
	SETOPTIONS (n, "range", "block", "bin.segment", "bin.segments", "bin.segments.x", "bin.segments.r", "bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x", "bin.ormaps.x", "io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x", "dbg.stack", "dbg.heap", "dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x", "anal.fcn", "anal.bb", NULL);
	SETI ("anal.timeout", 0, "stop analyzing after N seconds (0 = no timeout)");
	SETCB ("anal.flagends", "true", &cb_anal_flagends, "end function when a flag is found");
	SETCB ("anal.icods", "true", &cb_anal_icods, "analyze indirect code references");
	SETCB ("anal.jmp.retpoline", "true", &cb_anal_jmpretpoline, "analyze retpolines, may be slower if not needed");
	SETCB ("anal.jmp.tailcall", "true", &cb_anal_jmptailcall, "consume a branch as a call if delta is a function");
	SETICB ("anal.jmp.tailcall.delta", 0, &cb_anal_jmptailcall_delta, "consume a branch as a call if delta is big");

	SETCB ("anal.delay", "true", &cb_anal_delay, "enable delay slot analysis if supported by the architecture");
#if __wasi__
	SETICB ("anal.depth", 32, &cb_analdepth, "max depth at code analysis");
#else
	SETICB ("anal.depth", 128, &cb_analdepth, "max depth at code analysis");
#endif
	SETICB ("anal.graph_depth", 256, &cb_analgraphdepth, "max depth for path search");
	SETICB ("anal.sleep", 0, &cb_analsleep, "sleep N usecs every so often during analysis. Avoid 100% CPU usage");
	SETCB ("anal.ignbithints", "false", &cb_anal_ignbithints, "ignore the ahb hints (only obey asm.bits)");
	SETI ("anal.symsort", 0, "sort symbols before 'aaa'nalysis (-1: backward, 0: no sort, 1: forward");
	SETB ("anal.imports", "true", "run af@@@i in aa for better noreturn propagation");
	SETB ("anal.calls", "false", "make basic af analysis walk into calls");
	SETB ("anal.autoname", "false", "speculatively set a name for the functions, may result in some false positives");
	SETB ("anal.hasnext", "false", "continue analysis after each function");
	SETICB ("anal.nonull", 0, &cb_anal_nonull, "do not analyze regions of N null bytes");
	SETB ("anal.esil", "false", "use the new ESIL code analysis");
	SETB ("anal.strings", "false", "flag strings when performing analysis (see af,aar, e bin.strings)");
	SETS ("anal.types.spec", "gcc", "set profile for specifying format chars used in type analysis");
	SETB ("anal.types.verbose", "false", "verbose output from type analysis");
	SETB ("anal.types.constraint", "false", "enable constraint types analysis for variables");
	SETB ("anal.types.rollback", "false", "enable state rollback for type propagation recovery");
	SETCB ("anal.vars", "true", &cb_analvars, "analyze local variables and arguments");
	SETCB ("anal.vars.stackname", "false", &cb_analvars_stackname, "name variables based on their offset on the stack");
	SETCB ("anal.vars.newstack", "false", &cb_analvars_newstack, "use new sp-relative variable analysis (EXPERIMENTAL)");
	SETB ("anal.vinfun", "false", "search values in functions (aav) (false by default to only find on non-code)");
	SETB ("anal.vinfunrange", "false", "search values outside function ranges (requires anal.vinfun=false)\n");
	SETCB ("anal.norevisit", "false", &cb_analnorevisit, "do not visit function analysis twice (EXPERIMENTAL)");
	SETCB ("anal.nopskip", "true", &cb_analnopskip, "skip nops at the beginning of functions");
	SETCB ("anal.hpskip", "false", &cb_analhpskip, "skip `mov reg, reg` and `lea reg, [reg] at the beginning of functions");
	n = NODECB ("anal.arch", R_SYS_ARCH, &cb_analarch);
	SETDESC (n, "select the architecture to use");
	// SETCB ("anal.cpu", R_SYS_ARCH, &cb_analcpu, "specify the anal.cpu to use");
	SETS ("anal.prelude", "", "specify an hexpair to find preludes in code");
	SETCB ("anal.recont", "false", &cb_analrecont, "end block after splitting a basic block instead of error"); // testing
	SETCB ("anal.jmp.indir", "false", &cb_analijmp, "follow the indirect jumps in function analysis"); // testing
	SETI ("anal.ptrdepth", 3, "maximum number of nested pointers to follow in analysis");
	n = NODECB ("arch.decoder", "null", &cb_archdecoder);
	SETDESC (n, "select the instruction decoder to use");
	update_archdecoder_options (core, n);
	r_config_set_getter (cfg, "arch.decoder", (RConfigCallback)cb_archdecoder_getter);
	SETICB ("arch.bits", R_SYS_BITS, &cb_archbits, "word size in bits at arch decoder");
	r_config_set_getter (cfg, "arch.bits", (RConfigCallback)cb_archbits_getter);
	SETCB ("arch.platform", "", &cb_arch_platform, "define arch platform to use");
	n = NODECB ("arch.endian", R_SYS_ENDIAN? "big": "little", &cb_archendian);
	SETDESC (n, "set arch endianness");
	SETOPTIONS (n, "big", "little", "bigswap", "littleswap", NULL);
	// SETCB ("arch.autoselect", "false", &cb_archautoselect, "automagically select matching decoder on arch related config changes (has no effect atm)");

	SETCB ("anal.jmp.tbl", "true", &cb_anal_jmptbl, "analyze jump tables in switch statements");

	SETCB ("anal.jmp.cref", "false", &cb_anal_cjmpref, "create references for conditional jumps");
	SETCB ("anal.jmp.ref", "true", &cb_anal_jmpref, "create references for unconditional jumps");

	SETCB ("anal.jmp.above", "true", &cb_anal_jmpabove, "jump above function pointer");
	SETCB ("anal.loads", "false", &cb_anal_loads, "define as dword/string/qword when analyzing load instructions");
	SETCB ("anal.datarefs", "false", &cb_anal_followdatarefs, "follow data references for code coverage");
	SETCB ("anal.brokenrefs", "false", &cb_anal_brokenrefs, "follow function references as well if function analysis was failed");
	SETCB ("anal.jmp.mid", "true", &cb_anal_jmpmid, "continue analysis after jump to middle of instruction (x86 only)");

	SETCB ("anal.refstr", "false", &cb_anal_searchstringrefs, "search string references in data references");
	SETCB ("anal.trycatch", "false", &cb_anal_trycatch, "honor try.X.Y.{from,to,catch} flags");
	SETCB ("anal.bb.maxsize", "512K", &cb_anal_bb_max_size, "maximum basic block size");
	SETCB ("anal.pushret", "false", &cb_anal_pushret, "analyze push+ret as jmp");
	SETCB ("anal.types.plugin", "", &cb_anal_types_parser, "use the new c parser instead of tcc");

	n = NODECB ("anal.cxxabi", "itanium", &cb_anal_cxxabi);
	SETDESC (n, "select C++ RTTI ABI");
	SETOPTIONS (n, "itanium", "msvc", NULL);
	SETCB ("asm.abi", "", &cb_asmabi, "specify the abi taken from bin headeres or compiler details");

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
	n = NODECB ("dbg.malloc", "glibc", &cb_malloc);
#elif __APPLE__
	n = NODECB ("dbg.malloc", "macos", &cb_malloc);
#elif R2__WINDOWS__
	n = NODECB ("dbg.malloc", "windows", &cb_malloc);
#else
	n = NODECB ("dbg.malloc", "jemalloc", &cb_malloc);
#endif
	SETDESC (n, "choose malloc structure parser");
	SETOPTIONS (n, "glibc", "jemalloc", NULL);
	SETS ("dbg.glibc.path", "", "if not empty, use the given path to resolve the libc");
	SETS ("dbg.glibc.version", "", "if not empty, assume the given libc version");
	SETI ("dbg.glibc.main_arena", 0x0, "main_arena address");
#if __GLIBC_MINOR__ > 25
	SETB ("dbg.glibc.tcache", "true", "parse the tcache (glibc.minor > 2.25.x)");
#else
	SETB ("dbg.glibc.tcache", "false", "parse the tcache (glibc.minor > 2.25.x)");
#endif
#if __x86_64__
	SETI ("dbg.glibc.ma_offset", 0x000000, "main_arena offset from his symbol");
	SETI ("dbg.glibc.fc_offset", 0x00280, "first chunk offset from brk_start");
#else
	SETI ("dbg.glibc.ma_offset", 0x1bb000, "main_arena offset from his symbol");
	SETI ("dbg.glibc.fc_offset", 0x148, "first chunk offset from brk_start");
#endif
	SETB ("dbg.glibc.demangle", "false", "demangle linked-lists pointers introduced in glibc 2.32");
	SETB ("esil.prestep", "true", "step before esil evaluation in `de` commands");
	SETI ("esil.maxsteps", 0, "If !=0 defines the maximum amount of steps to perform on aesu/aec/..");
	SETS ("esil.fillstack", "", "initialize ESIL stack with (random, debruijn, sequence, zeros, ...)");
	SETICB ("esil.verbose", 0, &cb_esilverbose, "show ESIL verbose level (0, 1, 2)");
	SETICB ("esil.gotolimit", core->anal->esil_goto_limit, &cb_gotolimit, "maximum number of gotos per ESIL expression");
	SETICB ("esil.stack.depth", 256, &cb_esilstackdepth, "number of elements that can be pushed on the esilstack");
	SETI ("esil.stack.size", 0xf0000, "set stack size in ESIL VM");
	SETI ("esil.stack.addr", 0x100000, "set stack address in ESIL VM");
	SETS ("esil.stack.pattern", "0", "specify fill pattern to initialize the stack (0, w, d, i)");
	SETI ("esil.addr.size", 64, "maximum address size in accessed by the ESIL VM");
	SETB ("esil.breakoninvalid", "false", "break esil execution when instruction is invalid");
	SETI ("esil.timeout", 0, "a timeout (in seconds) for when we should give up emulating");
	SETCB ("esil.traprevert", "false", &cb_esiltraprevert, "Revert the entire expression, when esil traps, instead of just the pc");
	SETCB ("cfg.debug", "false", &cb_cfgdebug, "debugger mode");
	/* asm */
	// asm.os needs to be first, since other asm.* depend on it
	n = NODECB ("asm.os", R_SYS_OS, &cb_asmos);
	SETDESC (n, "select operating system (kernel)");
	SETOPTIONS (n, "ios", "dos", "darwin", "linux", "freebsd", "openbsd", "netbsd", "windows", "s110", NULL);
	SETI ("asm.xrefs.fold", 5, "maximum number of xrefs to be displayed as list (use columns above)");
	SETB ("asm.xrefs.code", "true", "show the code xrefs (generated by jumps instead of calls)");
	SETI ("asm.xrefs.max", 20, "maximum number of xrefs to be displayed without folding");
	SETCB ("asm.invhex", "false", &cb_asm_invhex, "show invalid instructions as hexadecimal numbers");
	SETB ("asm.instr", "true", "display the disassembled instruction");
	SETB ("asm.meta", "true", "display the code/data/format conversions in disasm");
	SETB ("asm.bytes", "true", "display the bytes of each instruction");
	SETB ("asm.bytes.align", "false", "align bytes at right (left padding space)");
	SETB ("asm.bytes.asbits", "false", "show instruction bits instead of bytes");
	SETB ("asm.bytes.right", "false", "display the bytes at the right of the disassembly");
	SETB ("asm.bytes.ascmt", "false", "display bytes as comments (see asm.bytes.right)");
	SETB ("asm.bytes.ascii", "false", "display the bytes in ascii characters instead of hex");
	SETB ("asm.bytes.opcolor", "false", "colorize bytes depending on opcode size + variant information");
	SETI ("asm.types", 1, "display the fcn types in calls (0=no,1=quiet,2=verbose)");
	SETB ("asm.midcursor", "false", "cursor in visual disasm mode breaks the instruction");
	SETICB ("arch.codealign", 0, &cb_arch_codealign, "only recognize as valid instructions aligned to this value");
	SETB ("asm.sub.jmp", "true", "always substitute jump, call and branch targets in disassembly");
	SETB ("asm.hints", "true", "disable all asm.hint* if false");
	SETB ("asm.hint.jmp", "false", "show jump hints [numbers] in disasm");
	SETB ("asm.hint.call", "true", "show call hints [numbers] in disasm");
	SETB ("asm.hint.call.indirect", "true", "Hints for indirect call intructions go to the call destination");
	SETB ("asm.hint.lea", "false", "show LEA hints [numbers] in disasm");
	SETB ("asm.hint.imm", "false", "show immediate hints [numbers] in disasm");
	SETB ("asm.hint.emu", "false", "show asm.emu hints [numbers] in disasm");
	SETB ("asm.hint.cdiv", "false", "show CDIV hints optimization hint");
	SETI ("asm.hint.pos", 1, "shortcut hint position (-1, 0, 1)");
	SETB ("asm.slow", "true", "perform slow analysis operations in disasm");
	SETB ("asm.decode", "false", "use code analysis as a disassembler");
	SETI ("asm.imm.base", 0, "Specify the default base for immediates in disassembly");
	SETB ("asm.imm.str", "true", "show immediates values as strings");
	SETB ("asm.imm.trim", "false", "remove all offsets and constants from disassembly");
	SETB ("asm.indent", "false", "indent disassembly based on refline/bb depth (EXPERIMENTAL)");
	SETI ("asm.indentspace", 2, "how many spaces to indent the code");
	SETB ("asm.dwarf", "false", "show dwarf comment at disassembly");
	SETB ("asm.dwarf.abspath", "false", "show absolute path in asm.dwarf");
	SETB ("asm.dwarf.file", "true", "show filename of asm.dwarf in pd");
	SETB ("asm.esil", "false", "show ESIL instead of mnemonic");
	SETB ("asm.nodup", "false", "do not show dupped instructions (collapse disasm)");
	SETB ("asm.emu", "false", "run ESIL emulation analysis on disasm");
	SETB ("emu.pre", "false", "run ESIL emulation starting at the closest flag in pd");
	SETB ("asm.refptr", "true", "show refpointer information in disasm");
	SETB ("emu.lazy", "false", "do not emulate all instructions with aae (optimization)");
	SETS ("emu.maxsize", "128M", "do not emulate regions larger than maxsize bytes. Default: 128M");
	SETB ("emu.stack", "false", "create a temporary fake stack when emulating in disasm (asm.emu)");
	SETCB ("emu.str", "false", &cb_emustr, "show only strings if any in the asm.emu output");
	SETB ("emu.bb", "false", "emulate basic blocks (see: abe, aeb and afbd)");
	SETB ("emu.str.lea", "true", "disable this in ARM64 code to remove some false positives");
	SETB ("emu.str.off", "false", "always show offset when printing asm.emu strings");
	SETB ("emu.str.inv", "true", "color-invert emu.str strings");
	SETB ("emu.str.flag", "true", "also show flag (if any) for asm.emu string");
	SETB ("emu.write", "false", "allow asm.emu to modify memory (WARNING)");
	SETB ("emu.ssa", "false", "perform SSA checks and show the ssa reg names as comments");
	n = NODECB ("emu.skip", "ds", &cb_emuskip);
	SETDESC (n, "skip metadata of given types in asm.emu");
	SETOPTIONS (n, "d", "c", "s", "f", "m", "h", "C", "r", NULL);
	SETB ("asm.sub.names", "true", "replace numeric values by flags (e.g. 0x4003e0 -> sym.imp.printf)");
	SETS ("asm.strip", "", "strip all instructions given comma separated types");
	SETB ("asm.optype", "false", "show opcode type next to the instruction bytes");
	SETB ("asm.flags", "true", "show flags");
	SETB ("asm.flags.prefix", "true", "show ;-- before the flags");
	SETICB ("asm.flags.maxname", 0, &cb_maxname, "maximum length of flag name with smart chopping");
	SETI ("asm.flags.limit", 0, "maximum number of flags to show in a single offset");
	SETB ("asm.flags.right", "false", "show flags as comments at the right side of the disassembly");
	SETB ("asm.flags.offset", "false", "show offset in flags");
	SETB ("asm.flags.inbytes", "false", "display flags inside the bytes space");
	SETB ("asm.flags.inoffset", "false", "display flags inside the offset column");
	SETB ("asm.flags.inline", "false", "display flags in line separated by commas instead of newlines");
	n = NODEICB ("asm.flags.middle", 2, &cb_midflags);
	SETOPTIONS (n, "0 = do not show flag", "1 = show without realign", "2 = realign at middle flag", "3 = realign at middle flag if sym.*", NULL);
	SETDESC (n, "realign disassembly if there is a flag in the middle of an instruction");
	SETCB ("asm.flags.real", "false", &cb_flag_realnames, "show flags' unfiltered realnames instead of names, except realnames from demangling");
	SETCB ("cfg.autoflagspace", "false", &cb_flag_autospace, "automatically assign flagspace based on registered name prefixes");
	SETB ("asm.lbytes", "true", "align disasm bytes to left");
	SETB ("asm.lines", "true", "show ASCII-art lines at disassembly");
	SETB ("asm.lines.fcn", "true", "show function boundary lines");
	SETICB ("asm.lines.maxref", 0, &cb_analmaxrefs, "maximum number of reflines to be analyzed and displayed in asm.lines with pd");
	SETB ("asm.lines.jmp", "true", "show flow lines at jumps");
	SETI ("asm.lines.limit", 4096 * 4, "dont show control flow lines if function is larger than X bytes");
	SETB ("asm.lines.split", "false", "show up/down lines splitted form");
	SETB ("asm.lines.bb", "false", "show empty line after every basic block");
	SETB ("asm.lines.call", "false", "enable call lines");
	SETB ("asm.lines.ret", "false", "show separator lines after ret");
	SETB ("asm.lines.out", "true", "show out of block lines");
	SETB ("asm.lines.right", "false", "show lines before opcode instead of offset");
	SETB ("asm.lines.wide", "false", "put a space between lines");
	SETB ("asm.fcnsig", "true", "show function signature in disasm");
	SETICB ("asm.lines.width", 7, &cb_asmlineswidth, "number of columns for program flow arrows");
	SETICB ("asm.sub.varmin", 0x100, &cb_asmsubvarmin, "minimum value to substitute in instructions (asm.sub.var)");
	SETCB ("asm.sub.tail", "false", &cb_asmsubtail, "replace addresses with prefix .. syntax");
	SETB ("asm.middle", "false", "allow disassembling jumps in the middle of an instruction");
	SETB ("asm.bbmiddle", "true", "realign disassembly if a basic block starts in the middle of an instruction");
	SETB ("asm.noisy", "true", "show comments considered noisy but possibly useful");
	SETB ("hex.addr", "true", "show address/offset in hexdump (px)");
	SETB ("scr.square", "true", "use square pixels or not");
	SETCB ("scr.wideoff", "false", &cb_scr_wideoff, "adjust offsets to match asm.bits");
	SETCB ("scr.rainbow", "false", &cb_scrrainbow, "shows rainbow colors depending of address");
	SETCB ("scr.last", "true", &cb_scrlast, "cache last output after flush to make _ command work (disable for performance)");
	SETB ("asm.addr", "true", "show offsets in disassembly");
	SETB ("asm.addr.base36", "false", "use base36 for addresses");
	SETCB ("asm.addr.segment", "false", &cb_segoff, "show segmented address in prompt (x86-16)");
	SETICB ("asm.addr.segment.bits", 4, &cb_asm_addr_segment_bits, "segment granularity in bits (x86-16)");
	SETCB ("asm.addr.base10", "false", &cb_decoff, "show address in base 10 instead of hexadecimal");
	SETCB ("asm.addr.relto", "", &cb_reloff, "show offset relative to fun,map,sec,flg");
	SETB ("asm.addr.focus", "false", "show only the addresses that branch or located at the beginning of a basic block");
	SETB ("asm.section", "false", "show section name before offset");
	SETB ("asm.section.perm", "false", "show section permissions in the disasm");
	SETB ("asm.section.name", "true", "show section name in the disasm");
	SETI ("asm.section.col", 20, "columns width to show asm.section");
	SETCB ("asm.sub.section", "false", &cb_asmsubsec, "show offsets in disasm prefixed with section/map name");
	SETCB ("asm.pseudo", "false", &cb_asmpseudo, "enable pseudo syntax");
	SETB ("asm.pseudo.linear", "false", "visual disassemble with pdcl instead of pd (EXPERIMENTAL)");
	SETB ("asm.size", "false", "show size of opcodes in disassembly (pd)");
	SETB ("asm.stackptr", "false", "show stack pointer at disassembly");
	SETB ("asm.cyclespace", "false", "indent instructions depending on CPU-cycles");
	SETB ("asm.cycles", "false", "show CPU-cycles taken by instruction at disassembly");
	SETI ("asm.tabs", 0, "use tabs in disassembly");
	SETB ("asm.tabs.once", "false", "only tabulate the opcode, not the arguments");
	SETI ("asm.tabs.off", 0, "tabulate spaces after the offset");
	SETB ("asm.trace", "false", "show execution traces for each opcode");
	SETB ("asm.trace.stats", "true", "indent disassembly with trace.count information");
	SETB ("asm.trace.color", "true", "indent disassembly with trace.count information");
	SETB ("asm.trace.space", "false", "indent disassembly with trace.count information");
	SETB ("asm.ucase", "false", "use uppercase syntax at disassembly");
	SETB ("asm.capitalize", "false", "use camelcase at disassembly");
	SETB ("asm.var", "true", "show local function variables in disassembly");
	SETB ("asm.var.access", "false", "show accesses of local variables");
	SETB ("asm.sub.var", "true", "substitute variables in disassembly");
	SETICB ("asm.var.summary", 4, &cb_asm_var_summary, "show variables summary instead of full list in disasm (0, 1, 2, 3, 4)");
	SETB ("asm.sub.varonly", "true", "substitute the entire variable expression with the local variable name (e.g. [local10h] instead of [ebp+local10h])");
	SETB ("asm.sub.reg", "false", "substitute register names with their associated role name (drp~=)");
	SETB ("asm.sub.rel", "true", "substitute pc relative expressions in disasm");
	SETB ("asm.family", "false", "show family name in disasm");
	SETB ("asm.symbol", "false", "show symbol+delta instead of absolute offset");
	SETB ("asm.anal", "false", "analyze code and refs while disassembling (see anal.strings)");
	SETI ("asm.symbol.col", 40, "columns width to show asm.section");
	SETCB ("asm.assembler", "", &cb_asmassembler, "set the plugin name to use when assembling");
	SETCB ("asm.spp", "false", &cb_assembly_spp, "use the Simple PreProcessor (SPP) while assembling");
	RConfigNode *asmcpu = NODECB ("asm.cpu", R_SYS_ARCH, &cb_asmcpu);
	SETDESC (asmcpu, "set the kind of asm.arch cpu");
	RConfigNode *asmarch = NODECB ("asm.arch", R_SYS_ARCH, &cb_asmarch);
	SETDESC (asmarch, "set the arch to be used by asm");
	/* we need to have both asm.arch and asm.cpu defined before updating options */
	update_asmarch_options (core, asmarch);
	update_asmcpu_options (core, asmcpu);
	n = NODECB ("asm.parser", "x86.pseudo", &cb_asmparser);
	SETDESC (n, "set the asm parser to use");
	update_asmparser_options (core, n);
	n = NODECB ("asm.syntax", "intel", &cb_asmsyntax);
	SETDESC (n, "select assembly syntax");
	SETOPTIONS (n, "att", "intel", "masm", "jz", "regnum", NULL);
	SETI ("asm.nbytes", 6, "number of bytes for each opcode at disassembly");
	SETB ("asm.bytes.space", "false", "separate hexadecimal bytes with a whitespace");
	SETICB ("asm.bits", R_SYS_BITS, &cb_asmbits, "word size in bits at assembler");
	n = r_config_node_get (cfg, "asm.bits");
	update_asmbits_options (core, n);
	SETB ("asm.functions", "true", "show functions in disassembly");
	SETB ("asm.xrefs", "true", "show xrefs in disassembly");
	SETB ("asm.demangle", "true", "show demangled symbols in disasm");
	SETB ("asm.describe", "false", "show opcode description");
	SETS ("asm.highlight", "", "highlight current line");
	SETB ("asm.marks", "true", "show marks before the disassembly");

	// options for the comments in the disassembly
	SETB ("asm.anos", "true", "show annotations (see ano command)");
	SETB ("asm.comments", "true", "show comments in disassembly view (see 'e asm.cmt.')");
	SETB ("asm.cmt.wrap", "true", "wrap long comments lines on top ignoring asm.cmt.right");
	SETB ("asm.cmt.calls", "true", "show callee function related info as comments in disasm");
	SETB ("asm.cmt.user", "false", "show user comments even if asm.comments is false");
	SETB ("asm.cmt.pseudo", "false", "show pseudo disasm as comments (see asm.pseudo)");
	SETB ("asm.cmt.refs", "false", "show flag and comments from refs in disasm");
	SETB ("asm.cmt.patch", "false", "show patch comments in disasm");
	SETB ("asm.cmt.off", "nodup", "show offset comment in disasm (true, false, nodup)");
	SETB ("asm.cmt.fold", "false", "fold comments, toggle with Vz");
	SETB ("asm.cmt.token", ";", "token to use before printing a comment");
	SETB ("asm.cmt.strings", "true", "show comment strings referenced by aop.ptr");
	SETB ("asm.cmt.flgrefs", "true", "show comment flags associated to branch reference");
	SETB ("asm.cmt.right", "true", "show comments at right of disassembly if they fit in screen");
	SETB ("asm.cmt.esil", "false", "show ESIL expressions as comments");
	SETI ("asm.cmt.col", 71, "column to align comments");
	SETB ("asm.payloads", "false", "show payload bytes in disasm");

	/* bin */
	SETS ("bin.hashlimit", "10M", "only compute hash when opening a file if smaller than this size");
	SETCB ("bin.usextr", "true", &cb_usextr, "use extract plugins when loading files");
	SETCB ("bin.useldr", "true", &cb_useldr, "use loader plugins when loading files");
	SETS ("bin.types", "true", "parse and load filetype and language file header structs");
	SETICB ("bin.limit", 0, &cb_binlimit, "stop parsing after finding N symbols/relocs/strings");
	SETCB ("bin.str.purge", "", &cb_strpurge, "purge strings (e bin.str.purge=? provides more detail)");
	SETS ("bin.str.real", "false", "set the realname in rbin.strings for better disasm (EXPERIMENTAL)");
	SETCB ("bin.str.nofp", "false", &cb_nofp, "set to true to reduce the false positive strings (EXPERIMENTAL)");
	SETCB ("bin.at", "false", &cb_binat, "RBin.cur depends on RCore.offset");
	SETB ("bin.libs", "false", "try to load libraries after loading main binary");
	n = NODECB ("bin.str.filter", "", &cb_strfilter);
	SETDESC (n, "filter strings");
	SETOPTIONS (n, "a", "8", "p", "e", "u", "i", "U", "f", NULL);
	SETCB ("bin.filter", "true", &cb_binfilter, "filter symbol names to fix dupped names");
	SETCB ("bin.force", "", &cb_binforce, "force that rbin plugin");
	SETS ("bin.cache", "false", "use io.cache.read if bin needs to patch relocs");
	SETS ("bin.lang", "", "language for bin.demangle");
	SETB ("bin.demangle", "true", "import demangled symbols from RBin");
	SETCB ("bin.demangle.trylib", "false", &cb_demangle_trylib, "try to use system available libraries to demangle");
	SETCB ("bin.demangle.usecmd", "false", &cb_bdc, "run xcrun swift-demangle and similar if available (SLOW) (see bin.demangle.trylib)");
	SETB ("bin.demangle.pfxlib", "false", "show library name on demangled symbols names");
	SETI ("bin.baddr", -1, "base address of the binary");
	SETI ("bin.laddr", 0, "base address for loading library ('*.so')");
	SETCB ("bin.dbginfo", "true", &cb_bindbginfo, "load debug information at startup if available");
	SETB ("bin.relocs", "true", "load relocs information at startup if available");
	SETB ("bin.relocs.apply", "false", "apply reloc information");
	SETICB ("bin.maxsymlen", 0, &cb_binmaxsymlen, "maximum length for symbol names");
	SETICB ("bin.str.min", 0, &cb_binminstr, "minimum string length for r_bin");
	SETICB ("bin.str.max", 0, &cb_binmaxstr, "maximum string length for r_bin");
	SETICB ("bin.str.align", 0, &cb_binstralign, "only consider strings aligned to this value (0 = disabled)");
	SETICB ("bin.str.maxbuf", 1024 * 1024 * 10, &cb_binmaxstrbuf, "maximum size of range to load strings from");
	n = NODECB ("bin.str.enc", "guess", &cb_binstrenc);
	SETDESC (n, "default string encoding of binary");
	SETOPTIONS (n, "ascii", "latin1", "utf8", "utf16le", "utf32le", "utf16be", "utf32be", "guess", NULL);
	SETCB ("bin.prefix", "", &cb_binprefix, "prefix all symbols/sections/relocs with a specific string");
	SETCB ("bin.str.raw", "false", &cb_rawstr, "load strings from raw binaries");
	SETCB ("bin.strings", "true", &cb_binstrings, "load strings from rbin on startup");
	SETCB ("bin.str.debase64", "false", &cb_debase64, "try to debase64 all strings");
	SETCB ("bin.classes", "true", &cb_bin_classes, "load classes from rbin on startup");
	SETCB ("bin.verbose", "false", &cb_binverbose, "show RBin warnings when loading binaries");

	/* prj */
	SETCB ("prj.name", "", &cb_prjname, "name of current project");
	SETB ("prj.files", "false", "save the target binary inside the project directory");
	SETB ("prj.vc", "true", "use your version control system of choice (rvc, git) to manage projects");
	SETB ("prj.zip", "false", "use ZIP format for project files");
	SETB ("prj.gpg", "false", "TODO: encrypt project with GnuPGv2");
	SETB ("prj.history", "false", "per-project command history");
	SETB ("prj.sandbox", "false", "sandbox r2 while loading project files");
	SETB ("prj.alwasyprompt", "false", "even when the project is already saved, ask the user to save the project when qutting");

	/* cfg */
	SETCB ("cfg.codevar", "", &cb_codevar, "define alternative variable name for `pc` (print-code) subcommands");
	n = SETCB ("cfg.charset", "", &cb_cfgcharset, "specify encoding to use when printing strings");
	update_cfgcharsets_options (core, n);
	SETB ("cfg.r2wars", "false", "enable some tweaks for the r2wars game");
	SETB ("cfg.plugins", "true", "load plugins at startup");
	SETCB ("time.fmt", "%Y-%m-%d %H:%M:%S %u", &cb_cfgdatefmt, "Date format (%Y-%m-%d %H:%M:%S %u)");
	SETICB ("time.zone", 0, &cb_timezone, "time zone, in hours relative to GMT: +2, -1,..");
	SETCB ("cfg.corelog", "false", &cb_cfgcorelog, "log changes using the T api needed for realtime syncing");
	p = r_sys_getenv ("EDITOR");
#if R2__WINDOWS__
	r_config_set (cfg, "cfg.editor", r_str_get_fail (p, "notepad"));
#else
	r_config_set (cfg, "cfg.editor", r_str_get_fail (p, "vi"));
#endif
	free (p);
	r_config_desc (cfg, "cfg.editor", "select default editor program, portable %EDITOR");
	char *whoami = r_sys_whoami ();
	SETS ("cfg.user", whoami, "set current username/pid");
	free (whoami);
	SETS ("dir.fortunes", R2_DATDIR "/radare2/" R2_VERSION "/fortunes", "directory to load fortune files from");
	SETB ("cfg.fortunes", "true", "if enabled show tips at start");
	RList *fortune_types = r_core_fortune_types (core);
	char *fts = r_str_list_join (fortune_types, ",");
	r_list_free (fortune_types);
	char *fortune_desc = r_str_newf ("type of fortunes to show(%s)", fts);
	SETCB ("cfg.fortunes.type", fts, &cb_cfg_fortunes_type, fortune_desc);
	free (fts);
	free (fortune_desc);
	SETB ("cfg.fortunes.clippy", "false", "use ?E instead of ?e");
	SETB ("cfg.fortunes.tts", "false", "speak out the fortune");
	SETS ("cfg.prefixdump", "dump", "filename prefix for automated dumps");
	SETCB ("cfg.sandbox", "false", &cb_cfgsanbox, "sandbox mode disables systems and open on upper directories");
	SETCB ("cfg.sandbox.grain", "all", &cb_cfgsanbox_grain, "select which sand grains must pass the filter (all, net, files, socket, exec, disk)");
	SETB ("cfg.wseek", "false", "Seek after write");
	SETCB ("cfg.bigendian", "false", &cb_bigendian, "use little (false) or big (true) endianness");
	SETCB ("cfg.float", "ieee754", &cb_cfg_float, "FPU profile for floating point operations (use -e cfg.float=? for list)");
	SETI ("cfg.cpuaffinity", 0, "run on cpuid");
	// TODO: This is an experimental feature because it conflicts with the way RFlags are handled, that would work for 'get' but not for 'set' and may confuse some logic out there.. also slow downs some codepaths
	SETCB ("cfg.regnums", "false", &cb_cfg_regnums, "Query register values before flags in RNum calls (EXPERIMENTAL)");

	/* log */
	SETICB ("log.level", R_LOG_LEVEL_DEFAULT, cb_config_log_level, "Target log level/severity (0:FATAL 1:ERROR 2:INFO 3:WARN 4:TODO 5:DEBUG)");
	SETCB ("log.ts", "false", cb_config_log_ts, "Show timestamp in log messages");

	SETICB ("log.traplevel", 0, cb_config_log_traplevel, "Log level for trapping R2 when hit");
	SETCB ("log.filter", "", cb_config_log_filter, "Filter only messages matching given origin");
	SETCB ("log.origin", "false", cb_log_origin, "Show [origin] in log messages");
	SETCB ("log.source", "false", cb_log_source, "Show source [file:line] in the log message");
	SETCB ("log.color", "true", cb_config_log_colors, "Should the log output use colors");
	SETCB ("log.quiet", "false", cb_config_log_quiet, "Be quiet, dont log anything to console");
	SETCB ("log.cons", "false", cb_config_log_cons, "Log messages using rcons (handy for monochannel r2pipe)");

	// zign
	SETS ("zign.prefix", "sign", "default prefix for zignatures matches");
	SETI ("zign.maxsz", 500, "maximum zignature length");
	SETI ("zign.minsz", 16, "minimum zignature length for matching");
	SETI ("zign.mincc", 10, "minimum cyclomatic complexity for matching");
	SETB ("zign.dups", "false", "allow duplicate zignatures");
	SETB ("zign.graph", "true", "use graph metrics for matching");
	SETB ("zign.bytes", "true", "use bytes patterns for matching");
	SETB ("zign.offset", "false", "use original offset for matching");
	SETB ("zign.refs", "true", "use references for matching");
	SETB ("zign.hash", "true", "use Hash for matching");
	SETB ("zign.types", "true", "use types for matching");
	SETB ("zign.autoload", "false", "autoload all zignatures located in dir.zigns");
	SETS ("zign.diff.bthresh", "1.0", "threshold for diffing zign bytes [0, 1] (see zc?)");
	SETS ("zign.diff.gthresh", "1.0", "threshold for diffing zign graphs [0, 1] (see zc?)");
	SETS ("zign.threshold", "0.0", "minimum similarity required for inclusion in zb output");
	SETB ("zign.mangled", "false", "use the manged name for zignatures (EXPERIMENTAL)");

	/* diff */
	SETCB ("diff.sort", "addr", &cb_diff_sort, "specify function diff sorting column see (e diff.sort=?)");
	SETI ("diff.from", 0, "set source diffing address for px (uses cc command)");
	SETI ("diff.to", 0, "set destination diffing address for px (uses cc command)");
	SETB ("diff.bare", "false", "never show function names in diff output");
	SETB ("diff.levenstein", "false", "use faster (and buggy) levenstein algorithm for buffer distance diffing");

	/* dir */
	SETI ("dir.depth", 10, "maximum depth when searching recursively for files");
	{
		char *path = r_str_newf (R_JOIN_2_PATHS ("%s", R2_SDB_MAGIC), r_config_get (core->config, "dir.prefix"));
		SETS ("dir.magic", path, "path to r_magic files");
		free (path);
		path = r_str_newf (R_JOIN_2_PATHS ("%s", R2_PLUGINS), r_config_get (core->config, "dir.prefix"));
		SETS ("dir.plugins", path, "path to plugin files to be loaded at startup");
		free (path);
	}
	SETCB ("dir.source.base", "", &cb_dirsrc_base, "path to trim out from the one in dwarf");
	SETCB ("dir.source", "", &cb_dirsrc, "path to find source files");
	SETS ("dir.debuglink", "/usr/lib/debug/", "default path for debuglink files (idl* command)");
	SETS ("dir.types", "/usr/include", "default colon-separated list of paths to find C headers to cparse types");
	SETS ("dir.libs", "", "specify path to find libraries to load when bin.libs=true");
#if __EMSCRIPTEN__ || __wasi__
	p = strdup ("/tmp");
#else
	p = r_sys_getenv (R_SYS_HOME);
#endif
	SETCB ("dir.home", r_str_get_fail (r_str_get (p), "/"), &cb_dirhome, "path for the home directory");
	free (p);
	p = r_file_tmpdir ();
	if (R_STR_ISEMPTY (p)) {
		free (p);
		p = strdup ("/tmp");
	}
	SETCB ("dir.tmp", r_str_get (p), &cb_dirtmp, "path of the tmp directory");
	free (p);
	char *cd = r_xdg_cachedir (NULL);
	SETCB ("dir.cache", r_str_get (cd), &cb_dir_cache, "override default cache directory (XDG_CACHE_HOME)");
	free (cd);
	char *prjdir = r_xdg_datadir ("projects");
	SETCB ("dir.projects", r_str_get (prjdir), &cb_dir_projects, "default path for projects");
	free (prjdir);
	char *zigndir = r_xdg_datadir ("zigns");
	SETCB ("dir.zigns", r_str_get (zigndir), &cb_dirzigns, "default path for zignatures (see zo command)");
	free (zigndir);
	SETS ("stack.reg", "SP", "which register to use as stack pointer in the visual debug");
	SETB ("stack.bytes", "true", "show bytes instead of words in stack");
	SETB ("stack.annotated", "false", "show annotated hexdump in visual debug");
	SETI ("stack.size", 64, "size in bytes of stack hexdump in visual debug");
	SETI ("stack.delta", 0, "delta for the stack dump");

	/* cmd */
	SETICB ("cmd.depth", 10, &cb_cmddepth, "maximum command depth");
	SETS ("cmd.undo", "true", "stack `uc` undo commands when running some commands like w, af, CC, ..");
	SETS ("cmd.bp", "", "run when a breakpoint is hit");
	SETS ("cmd.onsyscall", "", "run when a syscall is hit");
	SETICB ("cmd.hitinfo", 1, &cb_debug_hitinfo, "show info when a tracepoint/breakpoint is hit");
	SETS ("cmd.stack", "", "command to display the stack in visual debug mode");
	SETS ("cmd.cprompt", "", "column visual prompt commands");
	SETS ("cmd.gprompt", "", "graph visual prompt commands");
	SETS ("cmd.hit", "", "run when a search hit is found");
#if R2__UNIX__
	SETS ("cmd.usr1", "", "run when SIGUSR1 signal is received");
	SETS ("cmd.usr2", "", "run when SIGUSR2 signal is received");
#endif
	SETS ("cmd.open", "", "run when file is opened");
	SETS ("cmd.exit", "", "run command before leaving the shell (atexit)");
	SETS ("cmd.load", "", "run when binary is loaded");
	SETS ("cmd.bbgraph", "", "show the output of this command in the graph basic blocks");
	RConfigNode *cmdpdc = NODECB ("cmd.pdc", "", &cb_cmdpdc);
	SETDESC (cmdpdc, "select pseudo-decompiler command to run after pdc");
	update_cmdpdc_options (core, cmdpdc);
	SETCB ("cmd.log", "", &cb_cmdlog, "every time a new T log is added run this command");
	SETS ("cmd.prompt", "", "prompt commands");
	SETCB ("cmd.repeat", "false", &cb_cmdrepeat, "empty command an alias for '..' (repeat last command)");
	SETS ("dbg.linkurl", "https://debuginfod.debian.net", "debuginfo daemon server URL (see idld command and DEBUGINFOD_URLS env)");
	SETS ("cmd.fcn.new", "", "run when new function is analyzed");
	SETS ("cmd.fcn.delete", "", "run when a function is deleted");
	SETS ("cmd.fcn.rename", "", "run when a function is renamed");
	SETS ("cmd.visual", "", "replace current print mode");
	SETS ("cmd.vprompt", "", "commands to run (before) the visual prompt");
	SETS ("cmd.vprompt2", "", "commands to execute (after) the visual prompt");
	SETS ("cmd.step", "", "run command on every debugger step");

	SETCB ("cmd.esil.pin", "", &cb_cmd_esil_pin, "command to execute everytime a pin is hit by the program counter");
	SETCB ("cmd.esil.step", "", &cb_cmd_esil_step, "command to run before performing a step in the emulator");
	SETCB ("cmd.esil.stepout", "", &cb_cmd_esil_step_out, "command to run after performing a step in the emulator");
	SETCB ("cmd.esil.mdev", "", &cb_cmd_esil_mdev, "command to run when memory device address is accessed");
	SETCB ("cmd.esil.intr", "", &cb_cmd_esil_intr, "command to run when an esil interrupt happens");
	SETCB ("cmd.esil.trap", "", &cb_cmd_esil_trap, "command to run when an esil trap happens");
	SETCB ("cmd.esil.todo", "", &cb_cmd_esil_todo, "command to run when the esil instruction contains TODO");
	SETCB ("cmd.esil.ioer", "", &cb_cmd_esil_ioer, "command to run when esil fails to IO (invalid read/write)");

	SETCB ("dbg.maxsnapsize", "32M", &cb_dbg_maxsnapsize, "dont make snapshots of maps bigger than a specific size");
	SETCB ("dbg.wrap", "false", &cb_dbg_wrap, "enable the ptrace-wrap abstraction layer (needed for debugging from iaito)");
	SETCB ("dbg.libs", "", &cb_dbg_libs, "If set stop when loading matching libname");
	SETB ("dbg.skipover", "false", "make dso perform a dss (same goes for esil and visual/graph");
#if __APPLE__
	// SETB ("dbg.hwbp", "true", "use hardware breakpoints instead of software ones when enabled");
#endif
	SETB ("dbg.hwbp", "false", "use hardware breakpoints instead of software ones when enabled");
	SETCB ("dbg.unlibs", "", &cb_dbg_unlibs, "If set stop when unloading matching libname");
	SETCB ("dbg.verbose", "false", &cb_dbg_verbose, "Verbose debug output");
	SETB ("dbg.slow", "false", "show stack and regs in visual mode in a slow but verbose mode");
	SETB ("dbg.funcarg", "false", "display arguments to function call in visual mode");

	SETCB ("dbg.forks", "false", &cb_dbg_forks, "stop execution if fork() is done (see dbg.threads)");
	n = NODECB ("dbg.btalgo", "fuzzy", &cb_dbg_btalgo);
	SETDESC (n, "select backtrace algorithm");
	SETOPTIONS (n, "default", "fuzzy", "anal", "trace", NULL);
	SETCB ("dbg.threads", "false", &cb_stopthreads, "stop all threads when debugger breaks (see dbg.forks)");
	SETCB ("dbg.clone", "false", &cb_dbg_clone, "stop execution if new thread is created");
	SETCB ("dbg.aftersyscall", "true", &cb_dbg_aftersc, "stop execution before the syscall is executed (see dcs)");
	SETCB ("dbg.profile", "", &cb_runprofile, "path to RRunProfile file (or base64:string)");
	SETCB ("dbg.args", "", &cb_dbg_args, "set the args of the program to debug");
	SETCB ("dbg.follow.child", "false", &cb_dbg_follow_child, "continue tracing the child process on fork. By default the parent process is traced");
	SETCB ("dbg.trace.continue", "true", &cb_dbg_trace_continue, "trace every instruction between the initial PC position and the PC position at the end of continue's execution");
	SETB ("dbg.trace.inrange", "false", "while tracing, avoid following calls outside specified range");
	SETB ("dbg.trace.libs", "true", "trace library code too");
	SETB ("dbg.trace.eval", "true", "evaluate instructions when tracing (analtp workaround)");
	SETCB ("dbg.trace", "false", &cb_trace, "trace program execution (see asm.trace)");
	SETICB ("dbg.trace.tag", 0, &cb_tracetag, "trace tag");
	/* debug */
	SETCB ("dbg.status", "false", &cb_dbgstatus, "set cmd.prompt to '.dr*' or '.dr*;drd;sr PC;pi 1;s-'");
#if DEBUGGER
	SETCB ("dbg.backend", "native", &cb_dbgbackend, "select the debugger backend");
#else
	SETCB ("dbg.backend", "esil", &cb_dbgbackend, "select the debugger backend");
#endif
	n = NODECB ("dbg.bep", "loader", &cb_dbgbep);
	SETDESC (n, "Break on entrypoint");
	SETOPTIONS (n, "loader", "entry", "constructor", "main", NULL);
	if (core->cons->rows > 30) { // HACKY
		r_config_set_i (cfg, "dbg.follow", 64);
	} else {
		r_config_set_i (cfg, "dbg.follow", 32);
	}
	r_config_desc (cfg, "dbg.follow", "follow program counter when pc > core->addr + dbg.follow");
	SETB ("dbg.rebase", "true", "rebase anal/meta/comments/flags when reopening file in debugger");
	SETCB ("dbg.swstep", "false", &cb_swstep, "force use of software steps (code analysis+breakpoint)");
	SETB ("dbg.exitkills", "true", "kill process on exit");
	SETS ("dbg.exe.path", "", "path to binary being debugged");
	SETCB ("dbg.execs", "false", &cb_dbg_execs, "stop execution if new thread is created");
	SETICB ("dbg.gdb.page_size", 4096, &cb_dbg_gdb_page_size, "page size on gdb target (useful for QEMU)");
	SETICB ("dbg.gdb.retries", 10, &cb_dbg_gdb_retries, "number of retries before gdb packet read times out");
	SETCB ("dbg.consbreak", "false", &cb_consbreak, "sigint handle for attached processes");

	r_config_set_getter (cfg, "dbg.swstep", (RConfigCallback)__dbg_swstep_getter);
// TODO: This should be specified at first by the debug backend when attaching
#if __i386__ || __x86_64__
	SETICB ("dbg.bpsize", 1, &cb_dbgbpsize, "size of software breakpoints");
#else
	// __arm__ || __mips__ || __loongarch__
	SETICB ("dbg.bpsize", 4, &cb_dbgbpsize, "size of software breakpoints");
#endif
	SETB ("dbg.bpsysign", "false", "ignore system breakpoints");
	SETCB ("dbg.bpinmaps", "true", &cb_dbg_bpinmaps, "activate breakpoints only if they are inside a valid map");
	SETB ("dbg.bpforuntil", "true", "honor breakpoints when performing 'dcu', 'dsu'");
	SETICB ("dbg.btdepth", 128, &cb_dbgbtdepth, "depth of backtrace");

	/* filesystem */
	n = NODECB ("fs.view", "normal", &cb_fsview);
	SETDESC (n, "set visibility options for filesystems");
	SETOPTIONS (n, "all", "normal", "deleted", "special", NULL);
	n = SETS ("fs.cwd", "/", "current working directory (see 'ms' command)");

	/* hexdump */
	SETCB ("hex.header", "true", &cb_hex_header, "show header in hexdump");
	SETCB ("hex.bytes", "true", &cb_hex_bytes, "show bytes column in hexdump");
	SETCB ("hex.ascii", "true", &cb_hex_ascii, "show ascii column in hexdump");
	SETCB ("hex.hdroff", "true", &cb_hex_hdroff, "show aligned 1 byte in header instead of delta nibble");
	SETCB ("hex.style", "false", &cb_hex_style, "improve the hexdump header style");
	SETCB ("hex.pairs", "true", &cb_hex_pairs, "show bytes paired in 'px' hexdump");
	SETCB ("hex.align", "false", &cb_hex_align, "align hexdump with flag + flagsize");
	SETCB ("hex.section", "false", &cb_hex_section, "show section name before the offset");
	SETCB ("hex.compact", "false", &cb_hexcompact, "show smallest 16 byte col hexdump (60 columns)");
	SETCB ("cmd.hexcursor", "", &cb_cmd_hexcursor, "if set and cursor is enabled display given pf format string");
	SETI ("hex.flagsz", 0, "If non zero, overrides the flag size in pxa");
	SETICB ("hex.cols", 16, &cb_hexcols, "number of columns in hexdump");
	SETI ("hex.depth", 5, "maximal level of recurrence while telescoping memory");
	SETB ("hex.onechar", "false", "number of columns in hexdump");
	SETICB ("hex.stride", 0, &cb_hexstride, "line stride in hexdump (default is 0)");
	SETCB ("hex.comments", "true", &cb_hexcomments, "show comments in 'px' hexdump");

	/* http */
	SETB ("http.log", "true", "show HTTP requests processed");
	SETS ("http.sync", "", "remote HTTP server to sync events with");
	SETB ("http.colon", "false", "only accept the : command");
	SETS ("http.logfile", "", "specify a log file instead of stderr for http requests");
	SETB ("http.cors", "false", "enable CORS");
	SETS ("http.referer", "", "csfr protection if set");
	SETB ("http.dirlist", "false", "enable directory listing");
	SETS ("http.allow", "", "only accept clients from the comma separated IP list");
#if R2__WINDOWS__
	r_config_set (cfg, "http.browser", "start");
#else
	{
		/* bin_name, standard_path, http.browser value override */
		static const char *bin_data[] = {
			"openURL", "/usr/bin/openURL", "", // iOS ericautils
			"termux-open",
			TERMUX_PREFIX "/bin/termux-open",
			"",
			"toolbox",
			"/system/bin/toolbox",
			"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d",
			"xdg-open",
			"/usr/bin/xdg-open",
			"",
			"open",
			"/usr/bin/open",
			"",
			NULL
		};
		int i;
		bool fallback = true;

		/* Attempt to find binary in path before falling back to
		 * standard locations */
		for (i = 0; bin_data[i]; i += 3) {
			const char *bin_name = bin_data[i];
			const char *standard_path = bin_data[i + 1];
			const char *browser_override = bin_data[i + 2];
			const char *path;

			/* Try to find bin in path */
			char *bin_path = r_file_path (bin_name);
			path = bin_path;

			/* Not in path, but expected location exists */
			if (!path && r_file_exists (standard_path)) {
				path = standard_path;
			}

			if (path) {
				r_config_set (cfg, "http.browser", r_str_get_fail (browser_override, path));
				fallback = false;
			}

			free (bin_path);
		}

		if (fallback) {
			r_config_set (cfg, "http.browser", "firefox");
		}
		r_config_desc (cfg, "http.browser", "command to open HTTP URLs");
	}
#endif
	SETI ("http.maxsize", 0, "maximum file size for upload");
	SETS ("http.index", "index.html", "main html file to check in directory");
	SETS ("http.bind", "localhost", "server address (use 'public' for binding to 0.0.0.0)");
	char *www = r_xdg_datadir ("www");
	if (www) {
		SETS ("http.homeroot", www, "http home root directory");
		free (www);
	}
#if R2_USE_BUNDLE_PREFIX
	{
		char *wwwroot = r_file_new (r_sys_prefix (NULL), "www", NULL);
		SETS ("http.root", wwwroot, "http root directory");
		free (wwwroot);
	}
#elif R2__WINDOWS__
	{
		char *wwwroot = r_str_newf ("%s\\share\\www", r_sys_prefix (NULL));
		SETS ("http.root", wwwroot, "http root directory");
		free (wwwroot);
	}
#else
	SETS ("http.root", R2_WWWROOT, "http root directory");
#endif
	SETS ("http.port", "9090", "http server port");
	SETS ("http.basepath", "/", "define base path for http requests");
	SETS ("http.maxport", "9999", "last HTTP server port");
	SETS ("http.ui", "m", "default webui (m, t, f)");
	SETB ("http.sandbox", "true", "sandbox the HTTP server");
	SETB ("http.channel", "false", "use the new threadchannel based webserver (EXPERIMENTAL)");
	SETI ("http.timeout", 3, "disconnect clients after N seconds of inactivity");
	SETI ("http.dietime", 0, "kill server after N seconds with no client");
	SETB ("http.verbose", "false", "output server logs to stdout");
	SETB ("http.upget", "false", "/up/ answers GET requests, in addition to POST");
	SETB ("http.upload", "false", "enable file uploads to /up/<filename>");
	SETS ("http.uri", "", "address of HTTP proxy");
	SETB ("http.auth", "false", "enable/disable HTTP Authentification");
	SETS ("http.authtok", "r2admin:r2admin", "http authentification user:password token");
	p = r_sys_getenv ("R2_HTTP_AUTHFILE");
	SETS ("http.authfile", r_str_get (p), "http authentification user file");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc (cfg, "http.uproot", "path where files are uploaded");

	/* graph */
	SETB ("graph.aeab", "false", "show aeab info on each basic block instead of disasm");
	SETI ("graph.zoom", 0, "default zoom value when rendering the graph");
	SETB ("graph.trace", "false", "fold all non-traced basic blocks");
	SETB ("graph.dummy", "true", "create dummy nodes in the graph for better layout (20% slower)");
	SETB ("graph.mini", "false", "render a minigraph next to the graph in braile art");
	SETB ("graph.few", "false", "show few basic blocks in the graph");
	SETB ("graph.comments", "true", "show disasm comments in graph");
	SETB ("graph.cmtright", "false", "show comments at right");
	SETCB ("graph.gv.format", "gif", &cb_graphformat, "graph image extension when using 'w' format (png, jpg, pdf, ps, svg, json)");
	SETB ("graph.refs", "false", "hraph references in callgraphs (.agc*;aggi)");
	SETB ("graph.json.usenames", "true", "use names instead of addresses in Global Call Graph (agCj)");
	SETI ("graph.edges", 2, "0=no edges, 1=simple edges, 2=avoid collisions");
	SETI ("graph.layout", 0, "graph layout (0=vertical, 1=horizontal)");
	SETI ("graph.linemode", 1, "graph edges (0=diagonal, 1=square)");
	SETS ("graph.font", "Courier", "Font for dot graphs");
	SETB ("graph.addr", "false", "show addresses in graphs");
	SETB ("graph.bytes", "false", "show opcode bytes in graphs");
	SETI ("graph.bb.maxwidth", 0, "maximum width for the basic blocks in the graph");
	SETI ("graph.from", UT64_MAX, "lower bound address when drawing global graphs");
	SETI ("graph.to", UT64_MAX, "upper bound address when drawing global graphs");
	SETI ("graph.scroll", 5, "scroll speed in ascii-art graph");
	SETB ("graph.invscroll", "false", "invert scroll direction in ascii-art graph");
	SETS ("graph.title", "", "title of the graph");
	SETB ("graph.body", "true", "show body of the nodes in the graph");
	SETB ("graph.bubble", "false", "show nodes as bubbles");
	SETB ("graph.ntitles", "true", "display title of node");
	SETS ("graph.gv.node", "", "graphviz node style. (color=gray, style=filled shape=box)");
	SETS ("graph.gv.edge", "", "graphviz edge style. (arrowhead=\"vee\")");
	SETS ("graph.gv.spline", "", "graphviz spline style. (splines=\"ortho\")");
	SETS ("graph.gv.graph", "", "graphviz global style attributes. (bgcolor=white)");
	SETS ("graph.gv.current", "false", "highlight the current node in graphviz graph.");
	SETB ("graph.nodejmps", "true", "enables shortcuts for every node.");
	SETB ("graph.hints", "true", "show true (t) and false (f) hints for conditional edges in graph");
	SETCB ("graph.dotted", "false", &cb_dotted, "dotted lines for conditional jumps in graph");

	/* hud */
	SETS ("hud.path", "", "set a custom path for the HUD file");

	SETCB ("esil.exectrap", "false", &cb_exectrap, "trap when executing code in non-executable memory");
	SETCB ("esil.iotrap", "true", &cb_iotrap, "invalid read or writes produce a trap exception");
	SETCB ("esil.romem", "false", &cb_romem, "set memory as read-only for ESIL");
	SETB ("esil.stats", "false", "statistics from ESIL emulation stored in sdb");
	SETCB ("esil.nonull", "false", &cb_esilnonull, "prevent memory read, memory write at null pointer");
	SETCB ("esil.mdev.range", "", &cb_mdevrange, "specify a range of memory to be handled by cmd.esil.mdev");
	SETB ("esil.dfg.mapinfo", "false", "use mapinfo for esil dfg");
	SETB ("esil.dfg.maps", "false", "set ro maps for esil dfg");

	/* table encodings */
	SETI ("cfg.table.maxcol", 0, "Define maximum column width in tables");
	SETB ("cfg.table.wrap", "false", "Wrap text to not exceed maxcol");
	n = SETCB ("cfg.table.format", "", cb_tableformat, "Change the default output format for tables");
	SETOPTIONS (n, "simple", NULL);
	SETOPTIONS (n, "fancy", NULL);
	SETOPTIONS (n, "html", NULL);
	SETOPTIONS (n, "json", NULL);
	SETOPTIONS (n, "csv", NULL);
	SETOPTIONS (n, "tsv", NULL);
	SETOPTIONS (n, "sql", NULL);
	SETOPTIONS (n, "r2", NULL);

	/* json encodings */
	n = NODECB ("cfg.json.str", "none", &cb_jsonencoding);
	SETDESC (n, "encode strings from json outputs using the specified option");
	SETOPTIONS (n, "none", "base64", "strip", "hex", "array", NULL);

	n = NODECB ("cfg.json.num", "none", &cb_jsonencoding_numbers);
	SETDESC (n, "encode numbers from json outputs using the specified option");
	SETOPTIONS (n, "none", "string", "hex", NULL);

	/* scr */
#if __EMSCRIPTEN__ || __wasi__
	r_config_set_b_cb (cfg, "scr.fgets", true, cb_scrfgets);
#else
	r_config_set_b_cb (cfg, "scr.fgets", false, cb_scrfgets);
#endif
	r_config_desc (cfg, "scr.fgets", "use fgets() instead of dietline for prompt input");
	SETCB ("scr.echo", "false", &cb_screcho, "show rcons output in realtime to stderr and buffer");
	SETS ("scr.loopnl", "false", "add a newline after every command executed in @@ loops");
	SETICB ("scr.linesleep", 0, &cb_scrlinesleep, "flush sleeping some ms in every line");
	SETICB ("scr.maxtab", 4096, &cb_completion_maxtab, "change max number of auto completion suggestions");
	SETICB ("scr.maxpage", 102400, &cb_scr_maxpage, "change max chars to print before prompting the user");
	SETICB ("scr.pagesize", 1, &cb_scrpagesize, "flush in pages when scr.linesleep is != 0");
	SETCB ("scr.flush", "false", &cb_scrflush, "force flush to console in realtime (breaks scripting)");
	SETB ("scr.slow", "true", "do slow stuff on visual mode like RFlag.get_at(true)");
#if R2__WINDOWS__
	SETICB ("scr.vtmode", core->cons->vtmode? 1: 0, &scr_vtmode, "use VT sequences on Windows (0: Disable, 1: Shell, 2: Visual)");
#else
	SETI ("scr.vtmode", 0, "windows specific configuration that have no effect on other OSs");
#endif
#if __ANDROID__
	// SETB ("scr.responsive", "true", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETI ("scr.wheel.speed", 1, "mouse wheel speed");
#else
	SETI ("scr.wheel.speed", 4, "mouse wheel speed");
#endif
	SETB ("scr.responsive", "false", "auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETB ("scr.wheel.nkey", "false", "use sn/sp and scr.nkey on wheel instead of scroll");
	// RENAME TO scr.mouse
	SETB ("scr.wheel", "true", "mouse wheel in Visual; temporaryly disable/reenable by right click/Enter)");
	SETB ("scr.cursor", "false", "keyboard controlled cursor in visual and panels");
	SETB ("scr.cursor.limit", "true", "limit print cursor within screen boundaries");
	SETS ("scr.layout", "", "name of the selected panels layout to load as default");
	SETCB ("scr.breakword", "", &cb_scrbreakword, "emulate console break (^C) when a word is printed (useful for pD)");
	SETCB ("scr.breaklines", "false", &cb_breaklines, "break lines in Visual instead of truncating them");
	SETCB ("scr.gadgets", "true", &cb_scr_gadgets, "run pg in prompt, visual and panels");
	SETB ("scr.panelborder", "false", "specify panels border active area (0 by default)");
	SETCB ("scr.theme", "default", &cb_scrtheme, "specify the theme name to load on startup (See 'ec?')");
	SETICB ("scr.timeout", 0, &cb_scrtimeout, "check for timeout during the break.(push|pop) contexts");
	SETICB ("scr.cols", 0, &cb_scrcolumns, "force console column count (width)");
	SETB ("scr.dumpcols", "false", "prefer pC commands before p ones");
	SETCB ("scr.rows", "0", &cb_scrrows, "force console row count (height) ");
	SETI ("scr.notch", 0, "force console row count (height) (duplicate?)");
	SETICB ("scr.rows", 0, &cb_rows, "force console row count (height) (duplicate?)");
	SETCB ("scr.fps", "false", &cb_fps, "show FPS in Visual");
	SETICB ("scr.rows.fix", 0, &cb_fixrows, "Workaround for Linux TTY");
	SETICB ("scr.cols.fix", 0, &cb_fixcolumns, "workaround for Prompt iOS SSH client");
	SETCB ("scr.highlight", "", &cb_scrhighlight, "highlight that word at RCons level");
#if __EMSCRIPTEN__ || __wasi__
	SETCB ("scr.interactive", "false", &cb_scrint, "start in interactive mode");
#else
	SETCB ("scr.interactive", "true", &cb_scrint, "start in interactive mode");
#endif
	SETCB ("scr.bgfill", "false", &cb_scr_bgfill, "fill background for ascii art when possible");
	SETI ("scr.feedback", 1, "set visual feedback level (1=arrow on jump, 2=every key (useful for videos))");
	SETCB ("scr.html", "false", &cb_scrhtml, "disassembly uses HTML syntax");
	SETCB ("scr.css", "false", &cb_scrcss, "make scr.html use css instead of hardcoded colors (TODO)");
	SETCB ("scr.css.prefix", "", &cb_scrcss_prefix, "hardcoded prefix for the css output (see ecc command)");
	n = NODECB ("scr.nkey", "flag", &cb_scrnkey);
	SETDESC (n, "select visual seek mode (affects n/N visual commands)");
	SETOPTIONS (n, "fun", "hit", "flag", NULL);
	SETCB ("scr.pager", "", &cb_pager, "system program (or '..') to use when output exceeds screen boundaries");
	SETI ("scr.scrollbar", 0, "show flagzone (fz) scrollbar in visual mode (0=no,1=right,2=top,3=bottom)");
	SETB ("scr.randpal", "false", "random color palete or just get the next one from 'eco'");
	SETCB ("scr.highlight.grep", "false", &cb_scr_color_grep_highlight, "highlight (INVERT) the grepped words");
	SETCB ("scr.prompt.popup", "false", &cb_scr_prompt_popup, "show widget dropdown for autocomplete");
	SETB ("scr.prompt.code", "false", "show last command return code in the prompt");
	SETCB ("scr.prompt.vi", "false", &cb_scr_vi, "use vi mode for input prompt");
	SETS ("scr.prompt.tabhelp", "true", "show command help when pressing the TAB key");
	SETCB ("scr.prompt.mode", "false", &cb_scr_prompt_mode, "set prompt color based on vi mode");
	SETB ("scr.prompt.file", "false", "show user prompt file (used by r2 -q)");
	SETB ("scr.prompt.prj", "false", "show currently used project in prompt");
	SETB ("scr.prompt.flag", "false", "show flag name in the prompt");
	SETB ("scr.prompt.sect", "false", "show section name in the prompt");
	SETCB ("scr.prompt.format", "", &cb_cfg_prompt_format, "format string for r2 prompt (supports $(...) command substitution and ${COLOR} placeholders)");
	SETCB ("scr.vprompt.format", "", &cb_cfg_prompt_format, "format string for visual prompt (supports $(...) command substitution and ${COLOR} placeholders)");
	SETB ("scr.tts", "false", "use tts if available by a command (see ic)");
	SETCB ("scr.prompt", "true", &cb_scrprompt, "show user prompt (used by r2 -q)");
	SETICB ("scr.limit", 0, &cb_scr_limit, "stop printing after N bytes");
	const int default_color = (core->print->flags & R_PRINT_FLAGS_COLOR)? core->cons->context->color_limit: COLOR_MODE_DISABLED;
	SETICB ("scr.color", default_color, &cb_color, "enable colors (0: none, 1: ansi, 2: 256 colors, 3: truecolor)");
	r_config_set_getter (cfg, "scr.color", (RConfigCallback)cb_color_getter);
	SETCB ("scr.color.grep", "false", &cb_scr_color_grep, "enable colors when using ~grep");
	SETB ("scr.color.pipe", "false", "enable colors when using pipes");
	SETB ("scr.color.ops", "true", "colorize numbers and registers in opcodes");
	SETB ("scr.color.regs", "false", "colorize each register differently");
	SETB ("scr.rainbow.regs", "false", "use static rainbow color palette for registers (requires scr.color.regs to be enabled, overrides theme colors)");
	SETCB ("scr.color.ophex", "false", &cb_scr_color_ophex, "colorize in hexdump depending on opcode type (px)");
	SETB ("scr.color.args", "true", "colorize arguments and variables of functions");
	SETB ("scr.color.bytes", "true", "colorize bytes that represent the opcodes of the instruction");
	SETCB ("scr.null", "false", &cb_scrnull, "show no output");
	SETCB ("scr.utf8", r_str_bool (r_cons_is_utf8 ()), &cb_utf8, "show UTF-8 characters instead of ANSI");
	SETCB ("scr.utf8.curvy", "false", &cb_utf8_curvy, "show curved UTF-8 corners (requires scr.utf8)");
	SETCB ("scr.demo", "false", &cb_scr_demo, "use demoscene effects if available");
	SETS ("scr.analbar", "false", "show progressbar for aaa instead of logging what its doing");
	SETCB ("scr.hist.block", "true", &cb_scr_histblock, "use blocks for histogram");
	SETCB ("scr.hist.filter", "true", &cb_scr_histfilter, "filter history for matching lines when using up/down keys");
#if __EMSCRIPTEN__ || __wasi__
	SETB ("scr.hist.save", "false", "always save history on exit");
#else
	SETB ("scr.hist.save", "true", "always save history on exit");
#endif
	SETICB ("scr.hist.size", R_LINE_HISTSIZE, &cb_scr_histsize, "set input lines history size");
	n = NODECB ("scr.strconv", "asciiesc", &cb_scrstrconv); // TODO: move this into asm. or sthg else?
	SETDESC (n, "convert string before display");
	SETOPTIONS (n, "asciiesc", "asciidot", "raw", "pascal", NULL); // TODO: add ebcdic here and other charset plugins here!!
	SETB ("scr.confirmquit", "false", "Confirm on quit");
	SETB ("scr.progressbar", "false", "display a progress bar when running scripts.");
	n = NODECB ("scr.clippy", "clippy", &cb_scrclippy);
	SETDESC (n, "default clippy avatar for ?E command");
	SETOPTIONS (n, "clippy", "orangg", "croco", "cybercat", NULL);

	/* str */
	SETCB ("str.escbslash", "false", &cb_str_escbslash, "escape the backslash"); // XXX this is the only var starting with 'str.'

	/* search */
	SETCB ("search.contiguous", "true", &cb_contiguous, "accept contiguous/adjacent search hits");
	SETB ("search.verbose", "false", "make the output of search commands verbose");
	SETICB ("search.align", 0, &cb_searchalign, "only catch aligned search hits");
	SETI ("search.chunk", 0, "chunk size for /+ (default size is asm.bits/8");
	SETI ("search.esilcombo", 8, "stop search after N consecutive hits");
	SETI ("search.distance", 0, "search string distance");
	SETB ("search.badpages", "true", "scan and stop searching when finding bad pages");
	SETB ("search.flags", "true", "all search results are flagged, otherwise only printed");
	SETB ("search.named", "false", "name flags with given string instead of search.prefix");
	SETB ("search.overlap", "false", "look for overlapped search hits");
	SETI ("search.maxhits", 0, "maximum number of hits (0: no limit)");
	SETI ("search.from", -1, "search start address");
	n = NODECB ("search.in", "io.maps", &cb_searchin);
	SETDESC (n, "specify search boundaries");
	SETOPTIONS (n, "raw", "flag", "flag:", "block", "bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x", "io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x", "dbg.stack", "dbg.heap", "dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x", "anal.fcn", "anal.bb", NULL);
	SETICB ("search.kwidx", 0, &cb_search_kwidx, "store last search index count");
	SETS ("search.prefix", "hit", "prefix name in search hits label");
	SETB ("search.show", "true", "show search results");
	SETI ("search.to", -1, "search end address");

	/* rop */
	SETI ("rop.len", 5, "maximum ROP gadget length");
	SETB ("rop.sdb", "false", "cache results in sdb (experimental)");
	SETB ("rop.db", "true", "categorize rop gadgets in sdb");
	SETB ("rop.subchains", "false", "display every length gadget from rop.len=X to 2 in /Rl");
	SETB ("rop.conditional", "false", "include conditional jump, calls and returns in ropsearch");
	SETB ("rop.comments", "false", "display comments in rop search output");

	/* io */
	SETCB ("io.cache", "false", &cb_io_cache, "change both of io.cache.{read,write}");
	SETCB ("io.cache.read", "true", &cb_io_cache_read, "enable read cache for vaddr (or paddr when io.va=0)");
	SETCB ("io.cache.write", "true", &cb_io_cache_write, "enable write cache for vaddr (or paddr when io.va=0)");
	SETCB ("io.cache.nodup", "false", &cb_io_cache_nodup, "do not cache duplicated cache writes");
	SETCB ("io.cache.auto", "false", &cb_io_cache_mode, "automatic cache all reads in the IO backend"); // renamed to slurp?
	/* pcache */
	SETCB ("io.pcache", "false", &cb_iopcache, "io.cache for p-level");
	SETCB ("io.pcache.write", "false", &cb_iopcachewrite, "enable write-cache");
	SETCB ("io.pcache.read", "false", &cb_iopcacheread, "enable read-cache");
	SETCB ("io.ff", "true", &cb_ioff, "fill invalid buffers with 0xff instead of returning error");
	SETB ("io.basemap", "false", "create a map at base address 0 when opening a file");
	SETICB ("io.mask", 0, &cb_iomask, "mask addresses before resolving as maps");
	SETB ("io.exec", "true", "see !!r2 -h~-x");
	SETICB ("io.0xff", 0xff, &cb_io_oxff, "use this value instead of 0xff to fill unallocated areas");
	// SETCB ("dbg.aslr", "false", &cb_ioaslr, "disable ASLR for spawn and such");
	SETCB ("bin.aslr", "false", &cb_binaslr, "pick a random bin.baddr to simulate ASLR for static analysis");
	SETCB ("io.va", "true", &cb_iova, "use virtual address layout");
	SETB ("io.voidwrites", "true", "handle writes to fully unmapped areas as valid operations (requires io.va to be set)");
	SETI ("io.mapinc", 0x10000000, "increment map address when overlap with r_io_map_locate");
	SETCB ("io.pava", "false", &cb_io_pava, "use EXPERIMENTAL paddr -> vaddr address mode");
	SETCB ("io.autofd", "true", &cb_ioautofd, "change fd when opening a new file");
	SETCB ("io.unalloc", "false", &cb_io_unalloc, "check each byte if it's allocated");
	SETCB ("io.unalloc.ch", ".", &cb_io_unalloc_ch, "char to display if byte is unallocated");
	SETCB ("io.overlay", "true", &cb_io_overlay, "honor io overlay");

	/* file */
	SETB ("file.info", "true", "RBin info loaded");
	SETS ("file.type", "", "type of current file");
	SETI ("file.loadalign", 1024, "alignment of load addresses");
#if R2_600
	SETCB ("file.log", "", cb_config_log_file, "Save log messages to given filename (alias for log.file)");
	SETCB ("file.output", "", &cb_config_file_output, "pipe output to file of this name (scr.tee)");
#else
	SETCB ("log.file", "", cb_config_log_file, "Save log messages to given filename");
	SETCB ("scr.tee", "", &cb_config_file_output, "pipe output to file of this name (same as file.output)");
#endif
	/* rap */
	SETB ("rap.loop", "true", "run rap as a forever-listening daemon (=:9090)");

	/* nkeys */
	SETS ("key.s", "", "override step into action");
	SETS ("key.S", "", "override step over action");
	{
		char buf[128];
		for (i = 1; i < 13; i++) {
			snprintf (buf, sizeof (buf), "key.f%d", i);
			snprintf (buf + 10, sizeof (buf) - 10, "run this when F%d key is pressed in visual mode", i);
			switch (i) {
			default: p = ""; break;
			}
			r_config_set (cfg, buf, p);
			r_config_desc (cfg, buf, buf + 10);
		}
	}

	/* zoom */
	SETCB ("zoom.byte", "h", &cb_zoombyte, "zoom callback to calculate each byte (See pz? for help)");
	SETI ("zoom.from", 0, "zoom start address");
	SETI ("zoom.maxsz", 512, "zoom max size of block");
	SETI ("zoom.to", 0, "zoom end address");
	n = NODECB ("zoom.in", "io.map", &cb_searchin);
	SETDESC (n, "specify boundaries for zoom");
	SETOPTIONS (n, "raw", "block", "bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x", "io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x", "dbg.stack", "dbg.heap", "dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x", "anal.fcn", "anal.bb", NULL);
	/* lines */
	SETI ("lines.from", 0, "start address for line seek");
	SETCB ("lines.to", "$s", &cb_linesto, "end address for line seek");
	SETCB ("lines.abs", "false", &cb_linesabs, "enable absolute line numbers");
	/* RVC */
	{
		char *p = r_file_path ("git");
		SETS ("prj.vc.message", "", "default commit message for rvc/git");
		if (R_STR_ISNOTEMPTY (p)) {
			SETCB ("prj.vc.type", "git", &cb_prjvctype, "what should projects use as a vc");
		} else {
			SETB ("prj.vc", "false", "use your version control system of choice (rvc, git) to manage projects");
			/*The follwing is just a place holder*/
			SETCB ("prj.vc.type", "rvc", &cb_prjvctype, "what should projects use as a vc");
		}
		free (p);
	}
	r_config_lock (cfg, true);
	return true;
}

R_API void r_core_parse_radare2rc(RCore *r) {
	char *rcfile = r_sys_getenv ("R2_RCFILE");
	char *homerc = NULL;
	if (!R_STR_ISEMPTY (rcfile)) {
		homerc = rcfile;
	} else {
		free (rcfile);
		homerc = r_file_home (".radare2rc");
	}
	if (homerc && r_file_is_regular (homerc)) {
		R_LOG_DEBUG ("user script loaded from %s", homerc);
		r_core_cmd_file (r, homerc);
	}
	R_FREE (homerc);
	char *configdir = r_xdg_configdir (NULL);
	if (configdir) {
		homerc = r_file_new (configdir, "radare2", "rc", NULL);
		if (homerc && r_file_is_regular (homerc)) {
			R_LOG_DEBUG ("user script loaded from %s", homerc);
			r_core_cmd_file (r, homerc);
		}
		free (homerc);
		homerc = r_file_new (configdir, "radare2", "rc.d", NULL);
		free (configdir);
	}
	if (homerc) {
		if (r_file_is_directory (homerc)) {
			char *file;
			RListIter *iter;
			RList *files = r_sys_dir (homerc);
			r_list_foreach (files, iter, file) {
				if (*file != '.') {
					char *path = r_file_new (homerc, file, NULL);
					if (r_file_is_regular (path)) {
						R_LOG_DEBUG ("user script loaded from %s", homerc);
						r_core_cmd_file (r, path);
					}
					free (path);
				}
			}
			r_list_free (files);
		}
		free (homerc);
	}
}

R_API void r_core_config_update(RCore *core) {
	RConfigNode *cmdpdc = r_config_node_get (core->config, "cmd.pdc");
	update_cmdpdc_options (core, cmdpdc);
}
