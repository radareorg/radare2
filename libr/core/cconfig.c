/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_core.h>
#include <r_types_base.h>

#define NODECB(w,x,y) r_config_set_cb (cfg,w,x,y)
#define NODEICB(w,x,y) r_config_set_i_cb (cfg,w,x,y)
#define SETDESC(x,y) r_config_node_desc (x,y)
#define SETOPTIONS(x, ...) set_options (x, __VA_ARGS__)
#define SETI(x,y,z) SETDESC (r_config_set_i (cfg,x,y), z)
#define SETICB(w,x,y,z) SETDESC (NODEICB (w,x,y), z)
#define SETPREF(x,y,z) SETDESC (r_config_set (cfg,x,y), z)
#define SETCB(w,x,y,z) SETDESC (NODECB (w,x,y), z)
#define SETBPREF(x,y,z) SETDESC (NODECB (x,y,boolify_var_cb), z)

static bool boolify_var_cb(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
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
	if (core->io && core->io->desc && core->io->desc->plugin) {
		if (core->io->desc->plugin->name && !strcmp (core->io->desc->plugin->name, "gdb")) {
			return true;
		}
	}
	return false;
}

static void print_node_options(RConfigNode *node) {
	if (node->options) {
		RListIter *iter;
		char *option;
		r_list_foreach (node->options, iter, option) {
			r_cons_printf ("%s\n", option);
		}
	}
}

static int compareName(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->name && b->name ?  strcmp (a->name, b->name) : 0);
}

static int compareNameLen(const RAnalFunction *a, const RAnalFunction *b) {
	size_t la, lb;
	if (!a || !b || !a->name || !b->name) {
		return 0;
	}
	la = strlen (a->name);
	lb = strlen (a->name);
	return (la > lb) - (la < lb);
}

static int compareAddress(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->addr && b->addr ? (a->addr > b->addr) - (a->addr < b->addr) : 0);
}

static int compareType(const RAnalFunction *a, const RAnalFunction *b) {
	return (a && b && a->diff->type && b->diff->type ?
			(a->diff->type > b->diff->type) - (a->diff->type < b->diff->type) : 0);
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
	return (a && b && a->diff->dist && b->diff->dist ?
			(a->diff->dist > b->diff->dist) - (a->diff->dist < b->diff->dist) : 0);
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
	eprintf ("e diff.sort = [name, namelen, addr, type, size, dist]\n");
	return false;
}

static const char *has_esil(RCore *core, const char *name) {
	RListIter *iter;
	RAnalPlugin *h;
	r_return_val_if_fail (core && core->anal && name, NULL);
	r_list_foreach (core->anal->plugins, iter, h) {
		if (h->name && !strcmp (name, h->name)) {
			return h->esil? "Ae": "A_";
		}
	}
	return "__";
}

// copypasta from binr/rasm2/rasm2.c
bool rasm2_list(RCore *core, const char *arch, int fmt) {
	int i;
	const char *feat2, *feat;
	RAsm *a = core->rasm;
	char bits[32];
	RAsmPlugin *h;
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
	r_list_foreach (a->plugins, iter, h) {
		if (arch && *arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++) {
					r_cons_println (r_str_word_get0 (c, i));
					any = true;
				}
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			/* The underscore makes it easier to distinguish the
			 * columns */
			if (h->bits & 8) {
				strcat (bits, "_8");
			}
			if (h->bits & 16) {
				strcat (bits, "_16");
			}
			if (h->bits & 32) {
				strcat (bits, "_32");
			}
			if (h->bits & 64) {
				strcat (bits, "_64");
			}
			if (!*bits) {
				strcat (bits, "_0");
			}
			feat = "__";
			if (h->assemble && h->disassemble) {
				feat = "ad";
			}
			if (h->assemble && !h->disassemble) {
				feat = "a_";
			}
			if (!h->assemble && h->disassemble) {
				feat = "_d";
			}
			feat2 = has_esil (core, h->name);
			if (fmt == 'q') {
				r_cons_println (h->name);
			} else if (fmt == 'j') {
				const char *license = "GPL";
				pj_k (pj, h->name);
				pj_o (pj);
				pj_k (pj, "bits");
				pj_a (pj);
				pj_i (pj, 32);
				pj_i (pj, 64);
				pj_end (pj);
				pj_ks (pj, "license", license);
				pj_ks (pj, "description", h->desc);
				pj_ks (pj, "features", feat);
				pj_end (pj);
			} else {
				r_cons_printf ("%s%s  %-9s  %-11s %-7s %s\n",
						feat, feat2, bits, h->name,
						r_str_get_fail (h->license, "unknown"), h->desc);
			}
			any = true;
		}
	}
	if (fmt == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	return any;
}

// more copypasta
static bool ranal2_list(RCore *core, const char *arch, int fmt) {
	int i;
	const char *feat2, *feat;
	RAnal *a = core->anal;
	char bits[32];
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
	r_list_foreach (a->plugins, iter, h) {
		if (R_STR_ISNOTEMPTY (arch)) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++) {
					r_cons_println (r_str_word_get0 (c, i));
					any = true;
				}
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			/* The underscore makes it easier to distinguish the
			 * columns */
			if (h->bits & 8) {
				strcat (bits, "_8");
			}
			if (h->bits & 16) {
				strcat (bits, "_16");
			}
			if (h->bits & 32) {
				strcat (bits, "_32");
			}
			if (h->bits & 64) {
				strcat (bits, "_64");
			}
			if (!*bits) {
				strcat (bits, "_0");
			}
			feat = "__";
#if 0
			if (h->assemble && h->disassemble) {
				feat = "ad";
			}
			if (h->assemble && !h->disassemble) {
				feat = "a_";
			}
			if (!h->assemble && h->disassemble) {
				feat = "_d";
			}
#else
			feat = "_d";
#endif
			feat2 = has_esil (core, h->name);
			if (fmt == 'q') {
				r_cons_println (h->name);
			} else if (fmt == 'j') {
				const char *license = "GPL";
				pj_k (pj, h->name);
				pj_o (pj);
				pj_k (pj, "bits");
				pj_a (pj);
				pj_i (pj, 32);
				pj_i (pj, 64);
				pj_end (pj);
				pj_ks (pj, "license", license);
				pj_ks (pj, "description", h->desc);
				pj_ks (pj, "features", feat);
				pj_end (pj);
			} else {
				r_cons_printf ("%s%s  %-9s  %-11s %-7s %s\n",
						feat, feat2, bits, h->name,
						r_str_get_fail (h->license, "unknown"), h->desc);
			}
			any = true;
		}
	}
	if (fmt == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	return any;
}

static inline void __setsegoff(RConfig *cfg, const char *asmarch, int asmbits) {
	int autoseg = (!strncmp (asmarch, "x86", 3) && asmbits == 16);
	r_config_set (cfg, "asm.segoff", r_str_bool (autoseg));
}

static bool cb_debug_hitinfo(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->hitinfo = node->i_value;
	return true;
}

static bool cb_anal_jmpretpoline(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.retpoline = node->i_value;
	return true;
}
static bool cb_anal_jmptailcall(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.tailcall = node->i_value;
	return true;
}

static bool cb_analarmthumb(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.armthumb = node->i_value;
	return true;
}

static bool cb_analdepth(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
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
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.delay = node->i_value;
	return true;
}

static bool cb_analvars(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.vars = node->i_value;
	return true;
}

static bool cb_analvars_stackname(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	core->anal->opt.varname_stack = node->i_value;
	return true;
}

static bool cb_anal_nonull(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.nonull = node->i_value;
	return true;
}

static bool cb_analstrings(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value) {
		r_config_set (core->config, "bin.strings", "false");
	}
	return true;
}

static bool cb_anal_ignbithints(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.ignbithints = node->i_value;
	return true;
}

static bool cb_analsleep(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->sleep = node->i_value;
	return true;
}

static bool cb_analmaxrefs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->maxreflines = node->i_value;
	return true;
}

static bool cb_analnorevisit(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.norevisit = node->i_value;
	return true;
}

static bool cb_analnopskip(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.nopskip = node->i_value;
	return true;
}

static bool cb_analhpskip(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.hpskip = node->i_value;
	return true;
}

static void update_analarch_options(RCore *core, RConfigNode *node) {
	RAnalPlugin *h;
	RListIter *it;
	if (core && core->anal && node) {
		r_config_node_purge_options (node);
		r_list_foreach (core->anal->plugins, it, h) {
			if (h->name) {
				SETOPTIONS (node, h->name, NULL);
			}
		}
	}
}

static bool cb_analarch(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		update_analarch_options (core, node);
		print_node_options (node);
		return false;
	}
	if (*node->value) {
		if (r_anal_use (core->anal, node->value)) {
			return true;
		}
		char *p = strchr (node->value, '.');
		if (p) {
			char *arch = strdup (node->value);
			arch[p - node->value] = 0;
			free (node->value);
			node->value = arch;
			if (r_anal_use (core->anal, node->value)) {
				return true;
			}
		}
		const char *aa = r_config_get (core->config, "asm.arch");
		if (!aa || strcmp (aa, node->value)) {
			eprintf ("anal.arch: cannot find '%s'\n", node->value);
		} else {
			r_config_set (core->config, "anal.arch", "null");
			return true;
		}
	}
	return false;
}

#if 0
static bool cb_analcpu(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (strstr (node->value, "?")) {
		ranal2_list (core, r_config_get (core->config, "anal.arch"), node->value[1]);
	}
	// r_anal_set_cpu (core->anal, node->value);
	r_arch_set_cpu (core->anal->config, node->value);
	/* set pcalign */
	int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
 	if (v != -1) {
 		core->anal->config->pcalign = v;
 	}
	r_config_set_i (core->config, "asm.pcalign", (v != -1)? v: 0);
	return true;
}
#endif

static bool cb_analrecont(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.recont = node->i_value;
	return true;
}

static bool cb_analijmp(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.ijmp = node->i_value;
	return true;
}

static bool cb_asmsubvarmin(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->parser->minval = node->i_value;
	return true;
}

static bool cb_asmsubtail(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->parser->subtail = node->i_value;
	return true;
}

static bool cb_scrlast(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->context->lastEnabled = node->i_value;
	return true;
}

static bool cb_scr_histfilter(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->line->histfilter = node->i_value;
	return true;
}

static bool cb_scr_vi(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->line->enable_vi_mode = node->i_value;
	return true;
}

static bool cb_scr_prompt_mode(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->line->prompt_mode = node->i_value;
	return true;
}

static bool cb_scr_wideoff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->wide_offsets = node->i_value;
	return true;
}

static bool cb_scrrainbow(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_RAINBOW;
		r_core_cmd0 (core, "ecr");
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_RAINBOW);
		r_core_cmd0 (core, "ecoo");
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_asmpseudo(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->rasm->pseudo = node->i_value;
	return true;
}

static bool cb_asmsubsec(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SECSUB;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_SECSUB);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_asmassembler(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			/* print more verbose help instead of plain option values */
			rasm2_list (core, NULL, node->value[1]);
			return false;
		}
		RConfigNode* asm_arch_node = r_config_node_get (core->config, "asm.arch");
		if (asm_arch_node) {
			print_node_options (asm_arch_node);
		}
		return false;
	}
	r_asm_use_assembler (core->rasm, node->value);
	return true;
}

static void update_cmdpdc_options(RCore *core, RConfigNode *node) {
	r_return_if_fail (core && core->rasm && node);
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
	RAsmPlugin *h;
	RListIter *iter;
	r_return_if_fail (core && core->rasm);
	const char *arch = r_config_get (core->config, "asm.arch");
	if (!arch || !*arch) {
		return;
	}
	r_config_node_purge_options (node);
	r_list_foreach (core->rasm->plugins, iter, h) {
		if (h->cpus && !strcmp (arch, h->name)) {
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

static bool cb_asmcpu(void *user, void *data) {
// cb_analcpu (user, data);
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		update_asmcpu_options (core, node);
		// XXX not working const char *asm_arch = core->anal->config->arch;
		const char *asm_arch = r_config_get (core->config, "asm.arch");
		/* print verbose help instead of plain option listing */
		rasm2_list (core, asm_arch, node->value[1]);
		ranal2_list (core, asm_arch, node->value[1]);
		return 0;
	}
	r_asm_set_cpu (core->rasm, node->value);
	r_arch_set_cpu (core->rasm->config, node->value);
	int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
 	if (v != -1) {
 		core->anal->config->pcalign = v;
 	}
	r_config_set_i (core->config, "asm.pcalign", (v != -1)? v: 0);
	return true;
}

static void update_asmarch_options(RCore *core, RConfigNode *node) {
	RAsmPlugin *h;
	RListIter *iter;
	if (core && node && core->rasm) {
		r_config_node_purge_options (node);
		r_list_foreach (core->rasm->plugins, iter, h) {
			if (h->name) {
				SETOPTIONS (node, h->name, NULL);
			}
		}
	}
}

static void update_asmbits_options(RCore *core, RConfigNode *node) {
	if (core && core->rasm && core->rasm->cur && node) {
		int bits = core->rasm->cur->bits;
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
	char asmparser[32];
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	int bits = R_SYS_BITS;
	if (!*node->value || !core || !core->rasm) {
		return false;
	}
	const char *asmos = r_config_get (core->config, "asm.os");
	if (core && core->anal && core->anal->config->bits) {
		bits = core->anal->config->bits;
	}
	if (*node->value == '?') {
		update_asmarch_options (core, node);
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			/* print more verbose help instead of plain option values */
			rasm2_list (core, NULL, node->value[1]);
			return false;
		} else {
			print_node_options (node);
			return false;
		}
	}
	r_egg_setup (core->egg, node->value, bits, 0, R_SYS_OS);

	if (!r_asm_use (core->rasm, node->value)) {
		eprintf ("asm.arch: cannot find (%s)\n", node->value);
		return false;
	}
	//we should strdup here otherwise will crash if any r_config_set
	//free the old value
	char *asm_cpu = strdup (r_config_get (core->config, "asm.cpu"));
	if (core->rasm->cur) {
		const char *new_asm_cpu = core->rasm->cur->cpus;
		if (R_STR_ISNOTEMPTY (new_asm_cpu)) {
			char *nac = strdup (new_asm_cpu);
			char *comma = strchr (nac, ',');
			if (comma) {
				if (!*asm_cpu || (*asm_cpu && !strstr(nac, asm_cpu))) {
					*comma = 0;
					r_config_set (core->config, "asm.cpu", nac);
				}
			}
			free (nac);
		} else {
			r_config_set (core->config, "asm.cpu", "");
		}
		bits = core->rasm->cur->bits;
		if (8 & bits) {
			bits = 8;
		} else if (16 & bits) {
			bits = 16;
		} else if (32 & bits) {
			bits = 32;
		} else {
			bits = 64;
		}
		update_asmbits_options (core, r_config_node_get (core->config, "asm.bits"));
	}
	snprintf (asmparser, sizeof (asmparser), "%s.pseudo", node->value);
	r_config_set (core->config, "asm.parser", asmparser);
	if (core->rasm->cur && core->anal &&
	    !(core->rasm->cur->bits & core->anal->config->bits)) {
		r_config_set_i (core->config, "asm.bits", bits);
	}

	//r_debug_set_arch (core->dbg, r_sys_arch_id (node->value), bits);
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
	// set pcalign
	if (core->anal) {
		const char *asmcpu = r_config_get (core->config, "asm.cpu");
		if (!r_syscall_setup (core->anal->syscall, node->value, core->anal->config->bits, asmcpu, asmos)) {
			//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
	}
	//if (!strcmp (node->value, "bf"))
	//	r_config_set (core->config, "dbg.backend", "bf");
	__setsegoff (core->config, node->value, core->rasm->config->bits);

	// set a default endianness
	int bigbin = r_bin_is_big_endian (core->bin);
	if (bigbin == -1 /* error: no endianness detected in binary */) {
		bigbin = r_config_get_i (core->config, "cfg.bigendian");
	}

	// try to set endian of RAsm to match binary
	r_asm_set_big_endian (core->rasm, bigbin);

	r_asm_set_cpu (core->rasm, asm_cpu);
	free (asm_cpu);
	RConfigNode *asmcpu = r_config_node_get (core->config, "asm.cpu");
	if (asmcpu) {
		update_asmcpu_options (core, asmcpu);
	}
	{
		int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
		r_config_set_i (core->config, "asm.pcalign", (v != -1)? v: 0);
	}
	/* reload types and cc info */
	// changing asm.arch changes anal.arch
	// changing anal.arch sets types db
	// so ressetting is redundant and may lead to bugs
	// 1 case this is usefull is when sdb_types is null
	if (!core->anal || !core->anal->sdb_types) {
		r_core_anal_type_init (core);
	}
	r_core_anal_cc_init (core);

	return true;
}

static bool cb_dbgbpsize(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->bpsize = node->i_value;
	return true;
}

static bool cb_dbgbtdepth(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->btdepth = node->i_value;
	return true;
}

static bool cb_asmbits(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	if (*node->value == '?') {
		update_asmbits_options (core, node);
		print_node_options (node);
		return false;
	}

	bool ret = false;
	if (!core) {
		eprintf ("user can't be NULL\n");
		return false;
	}

	int bits = node->i_value;
	if (!bits) {
		return false;
	}
	if (bits == core->rasm->config->bits && bits == core->dbg->bits) {
		// early optimization
		return true;
	}
	if (bits > 0) {
		ret = r_asm_set_bits (core->rasm, bits);
		if (!ret) {
			RAsmPlugin *h = core->rasm->cur;
			if (!h) {
				eprintf ("e asm.bits: Cannot set value, no plugins defined yet\n");
				ret = true;
			}
			// else { eprintf ("Cannot set bits %d to '%s'\n", bits, h->name); }
		}
		if (!r_anal_set_bits (core->anal, bits)) {
			eprintf ("asm.arch: Cannot setup '%d' bits analysis engine\n", bits);
			ret = false;
		}
	}
	if (core->dbg && core->anal && core->anal->cur) {
		r_debug_set_arch (core->dbg, core->anal->cur->arch, bits);
		const bool load_from_debug = r_config_get_b (core->config, "cfg.debug");
		if (load_from_debug) {
			if (core->dbg->h && core->dbg->h->reg_profile) {
// XXX. that should depend on the plugin, not the host os
#if __WINDOWS__
#if !defined(_WIN64)
				core->dbg->bits = R_SYS_BITS_32;
#else
				core->dbg->bits = R_SYS_BITS_64;
#endif
#endif
				char *rp = core->dbg->h->reg_profile (core->dbg);
				r_reg_set_profile_string (core->dbg->reg, rp);
				r_reg_set_profile_string (core->anal->reg, rp);
				free (rp);
			}
		} else {
			(void)r_anal_set_reg_profile (core->anal, NULL);
		}
	}
	r_core_anal_cc_init (core);
	const char *asmos = r_config_get (core->config, "asm.os");
	const char *asmarch = r_config_get (core->config, "asm.arch");
	const char *asmcpu = r_config_get (core->config, "asm.cpu");
	if (core->anal) {
		if (!r_syscall_setup (core->anal->syscall, asmarch, bits, asmcpu, asmos)) {
			//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
		__setsegoff (core->config, asmarch, core->anal->config->bits);
		if (core->dbg) {
			r_bp_use (core->dbg->bp, asmarch, core->anal->config->bits);
			r_config_set_i (core->config, "dbg.bpsize", r_bp_size (core->dbg->bp));
		}
		/* set pcalign */
		int v = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
		r_config_set_i (core->config, "asm.pcalign", (v != -1)? v: 0);
	}
	return ret;
}

static void update_asmfeatures_options(RCore *core, RConfigNode *node) {
	int i, argc;

	if (core && core->rasm && core->rasm->cur) {
		if (core->rasm->cur->features) {
			char *features = strdup (core->rasm->cur->features);
			argc = r_str_split (features, ',');
			for (i = 0; i < argc; i++) {
				const char *feature = r_str_word_get0 (features, i);
				if (feature) {
					r_config_node_add_option (node, feature);
				}
			}
			free (features);
		}
	}
}

static bool cb_flag_realnames(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->flags->realnames = node->i_value;
	return true;
}

static bool cb_asmfeatures(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		update_asmfeatures_options (core, node);
		print_node_options (node);
		return 0;
	}
	R_FREE (core->rasm->config->features);
	if (node->value[0]) {
		core->rasm->config->features = strdup (node->value);
	}
	return 1;
}

static bool cb_asmlineswidth(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->anal->lineswidth = node->i_value;
	return true;
}

static bool cb_emustr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		r_config_set (core->config, "asm.emu", "true");
	}
	return true;
}

static bool cb_emuskip(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			r_cons_printf ("Concatenation of meta types encoded as characters:\n" \
				"'d': data\n'c': code\n's': string\n'f': format\n'm': magic\n" \
				"'h': hide\n'C': comment\n'r': run\n" \
				"(default is 'ds' to skip data and strings)\n");
		} else {
			print_node_options (node);
		}
		return false;
	}
	return true;
}

static bool cb_jsonencoding(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (node->value[1] && node->value[1] == '?') {
			r_cons_printf ("choose either: \n"\
			"none (default)\n" \
			"base64 - encode the json string values as base64\n" \
			"hex - convert the string to a string of hexpairs\n" \
			"array - convert the string to an array of chars\n" \
			"strip - strip non-printable characters\n");
		} else {
			print_node_options (node);
		}
		return false;
	}
	return true;
}

static bool cb_jsonencoding_numbers(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (node->value[1] && node->value[1] == '?') {
			r_cons_printf ("choose either: \n"\
			"none (default)\n" \
			"string - encode the json number values as strings\n" \
			"hex - encode the number values as hex, then as a string\n");
		} else {
			print_node_options (node);
		}
		return false;
	}
	return true;
}

static bool cb_asm_armimm(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->rasm->immdisp = node->i_value ? true : false;
	return true;
}

static bool cb_asm_invhex(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->rasm->config->invhex = node->i_value;
	return true;
}

static bool cb_asm_pcalign(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	int align = node->i_value;
	if (align < 0) {
		align = 0;
	}
	core->rasm->config->pcalign = align;
	core->anal->config->pcalign = align;
	return true;
}

static bool cb_asmos(void *user, void *data) {
	RCore *core = (RCore*) user;
	int asmbits = r_config_get_i (core->config, "asm.bits");
	RConfigNode *asmarch, *node = (RConfigNode*) data;

	if (*node->value == '?') {
		print_node_options (node);
		return 0;
	}
	if (!node->value[0]) {
		free (node->value);
		node->value = strdup (R_SYS_OS);
	}
	asmarch = r_config_node_get (core->config, "asm.arch");
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
	// static void autocomplete_charsets(RCore *core, RLineCompletion *completion, const char *str) {
	char *name;
	RListIter *iter;
	RList *chs = r_charset_list (core->print->charset);
	r_config_node_purge_options (node);
	r_list_foreach (chs, iter, name) {
		SETOPTIONS (node, name, NULL);
	}
	r_list_free (chs);
}

static void update_asmparser_options(RCore *core, RConfigNode *node) {
	RListIter *iter;
	RParsePlugin *parser;
	if (core && node && core->parser && core->parser->parsers) {
		r_config_node_purge_options (node);
		r_list_foreach (core->parser->parsers, iter, parser) {
			SETOPTIONS (node, parser->name, NULL);
		}
	}
}

static bool cb_asmparser(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		update_asmparser_options (core, node);
		print_node_options (node);
		return false;
	}
	return r_parse_use (core->parser, node->value);
}

typedef struct {
	const char *name;
	const char *aliases;
} namealiases_pair;

static bool cb_binstrenc(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (node);
		r_cons_printf ("  -- if string's 2nd & 4th bytes are 0 then utf16le else "
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
		{ "utf32be", "utf-32be,utf32-be" } };
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
				core->bin->strenc = !strcmp (node->value, "guess") ? NULL : strdup (node->value);
				r_bin_reset_strings (core->bin);
			}
			return true;
		}
	}
	eprintf ("Unknown encoding: %s\n", node->value);
	free (enc);
	return false;
}

static bool cb_binfilter(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->bin->filter = node->i_value;
	return true;
}

/* BinDemangleCmd */
static bool cb_bdc(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->bin->demangle_usecmd = node->i_value;
	return true;
}

static bool cb_useldr(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->bin->use_ldr = node->i_value;
	return true;
}

static bool cb_binat(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->binat = node->i_value;
	return true;
}

static bool cb_usextr(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->bin->use_xtr = node->i_value;
	return true;
}

static bool cb_strpurge(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_cons_printf (
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
	RCore *core = (RCore *) user;
	core->parser->maxflagnamelen = node->i_value;
	return true;
}

static bool cb_midflags(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		print_node_options (node);
		return false;
	}
	return true;
}

static bool cb_strfilter(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			r_cons_printf ("Valid values for bin.str.filter:\n"
				"a  only alphanumeric printable\n"
				"8  only strings with utf8 chars\n"
				"p  file/directory paths\n"
				"e  email-like addresses\n"
				"u  urls\n"
				"i  IPv4 address-like strings\n"
				"U  only uppercase strings\n"
				"f  format-strings\n");
		} else {
			print_node_options (node);
		}
		return false;
	} else {
		core->bin->strfilter = node->value[0];
	}
	return true;
}

static bool cb_binforce(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	r_bin_force_plugin (core->bin, node->value);
	return true;
}

static bool cb_asmsyntax(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		print_node_options (node);
		return false;
	} else {
		int syntax = r_asm_syntax_from_string (node->value);
		if (syntax == -1) {
			return false;
		}
		r_asm_set_syntax (core->rasm, syntax);
	}
	return true;
}

static bool cb_dirzigns(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	free (core->anal->zign_path);
	core->anal->zign_path = strdup (node->value);
	return true;
}

static bool cb_bigendian(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->rasm->config->big_endian = node->i_value;
	// Try to set endian based on preference, restrict by RAsmPlugin
	bool isbig = r_asm_set_big_endian (core->rasm, node->i_value);
	// the big endian should also be assigned to dbg->bp->endian
	if (core->dbg && core->dbg->bp) {
		core->dbg->bp->endian = isbig;
	}
	core->rasm->config->big_endian = node->i_value;
	return true;
}

static void list_available_plugins(const char *path) {
	RListIter *iter;
	const char *fn;
	RList *files = r_sys_dir (path);
	r_list_sort (files, (RListComparator)strcmp);
	r_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.' && r_str_endswith (fn, ".sdb")) {
			char *f = strdup (fn);
			f[strlen (f) - 4] = 0;
			r_cons_println (f);
			free (f);
		}
	}
	r_list_free (files);
}

static bool cb_cfgcharset(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	const char *cf = r_str_trim_head_ro (node->value);
	if (!*cf) {
		r_charset_close (core->print->charset);
		return true;
	}
	bool rc = false;
	if (*cf == '?') {
		const char *cs = R2_PREFIX R_SYS_DIR R2_SDB R_SYS_DIR "charsets" R_SYS_DIR;
		list_available_plugins (cs);
	} else {
		rc = r_charset_use (core->print->charset, cf);
		if (rc) {
			r_sys_setenv ("RABIN2_CHARSET", cf);
		} else {
			eprintf ("Warning: Cannot load charset file '%s'.\n", cf);
		}
	}
	return rc;
}

static bool cb_cfgdatefmt(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	snprintf (core->print->datefmt, 32, "%s", node->value);
	return true;
}

static bool cb_timezone(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->print->datezone = node->i_value;
	return true;
}

static bool cb_cfgcorelog(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cfglog = node->i_value;
	return true;
}

static bool cb_cfgdebug(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!core) {
		return false;
	}
	if (core->io) {
		core->io->va = !node->i_value;
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
			r_debug_select (core->dbg, r_io_fd_get_pid (core->io, core->io->desc->fd),
					r_io_fd_get_tid (core->io, core->io->desc->fd));
		}
	} else {
		r_debug_use (core->dbg, NULL);
	}
	return true;
}

static bool cb_dirhome(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (node->value) {
		r_sys_setenv (R_SYS_HOME, node->value);
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
	RConfigNode *node = (RConfigNode*) data;
	RCore *core = (RCore *)user;
	free (core->bin->srcdir);
	core->bin->srcdir = strdup (node->value);
	return true;
}

static bool cb_cfgsanbox_grain(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (strstr (node->value, "?")) {
		eprintf ("Usage: comma separated grain types to be masked out by the sandbox.\n");
		eprintf ("all, none, disk, files, exec, socket, exec\n");
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
	RConfigNode *node = (RConfigNode*) data;
	int ret = r_sandbox_enable (node->i_value);
	if (node->i_value != ret) {
		eprintf ("Cannot disable sandbox\n");
	}
	return (!node->i_value && ret)? 0: 1;
}

static bool cb_str_escbslash(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->print->esc_bslash = node->i_value;
	return true;
}

static bool cb_completion_maxtab(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->cons->line->completion.args_limit = node->i_value;
	return true;
}

static bool cb_cfg_fortunes(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	// TODO CN_BOOL option does not receive the right hand side of assignment as an argument
	if (*node->value == '?') {
		r_core_fortune_list (core);
		return false;
	}
	return true;
}

static bool cb_cfg_fortunes_type(void *user, void *data) {
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_core_fortune_list_types ();
		return false;
	}
	return true;
}

static bool cb_cmdpdc(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *)data;
	if (*node->value == '?') {
		r_cons_printf ("pdc\n");
		RListIter *iter;
		RCorePlugin *cp;
		r_list_foreach (core->rcmd->plist, iter, cp) {
			if (!strcmp (cp->name, "r2retdec")) {
				r_cons_printf ("pdz\n");
			} else if (!strcmp (cp->name, "r2ghidra")) {
				r_cons_printf ("pdg\n");
			}
		}
		RConfigNode *r2dec = r_config_node_get (core->config, "r2dec.asm");
		if (r2dec) {
			r_cons_printf ("pdd\n");
		}
		return false;
	}
	return true;
}

static bool cb_cmdlog(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	R_FREE (core->cmdlog);
	core->cmdlog = strdup (node->value);
	return true;
}

static bool cb_cmdtimes(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cmdtimes = node->value;
	return true;
}

static bool cb_cmdrepeat(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cmdrepeat = node->i_value;
	return true;
}

static bool cb_screrrmode(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		r_cons_printf ("Valid values: null, echo, buffer, quiet, flush\n");
		return false;
	}
	r_cons_errmodes (node->value);
	return true;
}

static bool cb_scrnull(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->null = node->i_value;
	return true;
}

static bool cb_scr_color_ophex(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOROP;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_COLOROP);
	}
	return true;
}

static bool cb_color(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
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
	r_cons_singleton ()->context->color_mode = (node->i_value > COLOR_MODE_16M)
		? COLOR_MODE_16M: node->i_value;
	r_cons_pal_update_event ();
	r_print_set_flags (core->print, core->print->flags);
	r_log_set_colors (node->i_value);
	return true;
}

static bool cb_color_getter(void *user, RConfigNode *node) {
	(void)user;
	node->i_value = r_cons_singleton ()->context->color_mode;
	char buf[128];
	r_config_node_value_format_i (buf, sizeof (buf), r_cons_singleton ()->context->color_mode, node);
	if (!node->value || strcmp (node->value, buf) != 0) {
		free (node->value);
		node->value = strdup (buf);
	}
	return true;
}

static bool cb_decoff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_ADDRDEC;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_ADDRDEC);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_dbgbep(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		print_node_options (node);
		return false;
	}
	return true;
}

static bool cb_dbg_btalgo(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		print_node_options (node);
		return false;
	}
	free (core->dbg->btalgo);
	core->dbg->btalgo = strdup (node->value);
	return true;
}

static bool cb_dbg_maxsnapsize(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->maxsnapsize = r_num_math (core->num, node->value);
	return true;
}

static bool cb_dbg_wrap(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->io->want_ptrace_wrap = node->i_value;
	return true;
}

static bool cb_dbg_libs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	free (core->dbg->glob_libs);
	core->dbg->glob_libs = strdup (node->value);
	return true;
}

static bool cb_dbg_unlibs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	free (core->dbg->glob_unlibs);
	core->dbg->glob_unlibs = strdup (node->value);
	return true;
}

static bool cb_dbg_bpinmaps(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->bp->bpinmaps = node->i_value;
	return true;
}

static bool cb_dbg_forks(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_forks = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_gdb_page_size(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value < 64) { // 64 is hardcoded min packet size
		return false;
	}
	if (isGdbPlugin (core)) {
		char cmd[64];
		snprintf (cmd, sizeof (cmd), "page_size %"PFMT64d, node->i_value);
		free (r_io_system (core->io, cmd));
	}
	return true;
}

static bool cb_dbg_gdb_retries(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value <= 0) {
		return false;
	}
	if (isGdbPlugin (core)) {
		char cmd[64];
		snprintf (cmd, sizeof (cmd), "retries %"PFMT64d, node->i_value);
		free (r_io_system (core->io, cmd));
	}
	return true;
}

static bool cb_dbg_execs(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
#if __linux__
	RCore *core = (RCore*) user;
	core->dbg->trace_execs = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
#else
	if (node->i_value) {
		eprintf ("Warning: dbg.execs is not supported in this platform.\n");
	}
#endif
	return true;
}

static bool cb_dbg_clone(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_clone = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_dbg_follow_child(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->follow_child = node->i_value;
	return true;
}

static bool cb_dbg_trace_continue(void *user, void *data) {
	RCore *core = (RCore*)user;
	RConfigNode *node = (RConfigNode*)data;
	core->dbg->trace_continue = node->i_value;
	return true;
}

static bool cb_dbg_aftersc(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_aftersyscall = node->i_value;
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_debug_attach (core->dbg, core->dbg->pid);
	}
	return true;
}

static bool cb_runprofile(void *user, void *data) {
	RCore *r = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	free ((void*)r->io->runprofile);
	if (!node || !*(node->value)) {
		r->io->runprofile = NULL;
	} else {
		r->io->runprofile = strdup (node->value);
	}
	return true;
}

static bool cb_dbg_args(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode*) data;
	if (!node || !*(node->value)) {
		core->io->args = NULL;
	} else {
		core->io->args = strdup (node->value);
	}
	return true;
}

static bool cb_dbgstatus(void *user, void *data) {
	RCore *r = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (r_config_get_b (r->config, "cfg.debug")) {
		if (node->i_value) {
			r_config_set (r->config, "cmd.prompt",
				".dr*; drd; sr PC;pi 1;s-");
		} else {
			r_config_set (r->config, "cmd.prompt", ".dr*");
		}
	}
	return true;
}

static bool cb_dbgbackend(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_debug_plugin_list (core->dbg, 'q');
		return false;
	}
	if (!strcmp (node->value, "bf")) {
		// hack
		r_config_set (core->config, "asm.arch", "bf");
	}
	r_debug_use (core->dbg, node->value);
	return true;
}

static bool cb_gotolimit(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot change gotolimit\n");
		return false;
	}
	if (core->anal->esil) {
		core->anal->esil_goto_limit = node->i_value;
	}
	return true;
}

static bool cb_esilverbose(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (core->anal->esil) {
		core->anal->esil->verbose = node->i_value;
	}
	return true;
}

static bool cb_esilstackdepth(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value < 3) {
		eprintf ("esil.stack.depth must be greater than 2\n");
		node->i_value = 32;
	}
	return true;
}

static bool cb_fixrows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_rows = (int)node->i_value;
	return true;
}

static bool cb_fixcolumns(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_columns = atoi (node->value);
	return true;
}

static bool cb_rows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->force_rows = node->i_value;
	return true;
}

static bool cb_cmd_hexcursor(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->cfmt = node->value;
	return true;
}

static bool cb_hexcompact(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COMPACT;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_COMPACT);
	}
	return true;
}

static bool cb_hex_pairs(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->pairs = node->i_value;
	return true;
}

static bool cb_hex_section(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SECTION;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_SECTION;
	}
	return true;
}

static bool cb_hex_align(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_ALIGN;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_ALIGN;
	}
	return true;
}

static bool cb_io_unalloc(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_UNALLOC;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_UNALLOC;
	}
	return true;
}

static bool cb_io_unalloc_ch(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->io_unalloc_ch = *node->value ? node->value[0] : ' ';
	return true;
}

static bool cb_hex_header(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_HEADER;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_HEADER;
	}
	return true;
}

static bool cb_hex_bytes(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags &= ~R_PRINT_FLAGS_NONHEX;
	} else {
		core->print->flags |= R_PRINT_FLAGS_NONHEX;
	}
	return true;
}

static bool cb_hex_ascii(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags &= ~R_PRINT_FLAGS_NONASCII;
	} else {
		core->print->flags |= R_PRINT_FLAGS_NONASCII;
	}
	return true;
}

static bool cb_hex_style(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_STYLE;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_STYLE;
	}
	return true;
}

static bool cb_hex_hdroff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_HDROFF;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_HDROFF;
	}
	return true;
}

static bool cb_hexcomments(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COMMENT;
	} else {
		core->print->flags &= ~R_PRINT_FLAGS_COMMENT;
	}
	return true;
}

static bool cb_iopcache(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
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
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 1;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 2;
			if (!(core->io->p_cache & 2)) {
				r_io_desc_cache_fini_all (core->io);
				r_config_set_b (core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

static bool cb_iopcachewrite(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if ((bool)node->i_value) {
		if (core && core->io) {
			core->io->p_cache |= 2;
		}
	} else {
		if (core && core->io && core->io->p_cache) {
			core->io->p_cache &= 1;
			if (!(core->io->p_cache & 1)) {
				r_io_desc_cache_fini_all (core->io);
				r_config_set_b (core->config, "io.pcache", false);
			}
		}
	}
	return true;
}

R_API bool r_core_esil_cmd(RAnalEsil *esil, const char *cmd, ut64 a1, ut64 a2) {
	if (cmd && *cmd) {
		RCore *core = esil->anal->user;
		r_core_cmdf (core, "%s %"PFMT64d" %" PFMT64d, cmd, a1, a2);
		return core->num->value;
	}
	return false;
}

static bool cb_cmd_esil_ioer(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_ioer);
		core->anal->esil->cmd_ioer = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_todo(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_todo);
		core->anal->esil->cmd_todo = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_intr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_intr);
		core->anal->esil->cmd_intr = strdup (node->value);
	}
	return true;
}

static bool cb_mdevrange(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->mdev_range);
		core->anal->esil->mdev_range = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_pin(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal) {
		free (core->anal->pincmd);
		core->anal->pincmd = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_step(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_step);
		core->anal->esil->cmd_step = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_step_out(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_step_out);
		core->anal->esil->cmd_step_out = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_mdev(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		free (core->anal->esil->cmd_mdev);
		core->anal->esil->cmd_mdev = strdup (node->value);
	}
	return true;
}

static bool cb_cmd_esil_trap(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core && core->anal && core->anal->esil) {
		core->anal->esil->cmd = r_core_esil_cmd;
		core->anal->esil->cmd_trap = strdup (node->value);
	}
	return true;
}

static bool cb_fsview(void *user, void *data) {
	int type = R_FS_VIEW_NORMAL;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		print_node_options (node);
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
	int c = R_MAX (((RConfigNode*)data)->i_value, 0);
	core->max_cmd_depth = c;
	core->cons->context->cmd_depth = c;
	return true;
}

static bool cb_hexcols(void *user, void *data) {
	RCore *core = (RCore *)user;
	int c = R_MIN (1024, R_MAX (((RConfigNode*)data)->i_value, 0));
	core->print->cols = c; // & ~1;
	core->dbg->regcols = c/4;
	return true;
}

static bool cb_hexstride(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	((RCore *)user)->print->stride = node->i_value;
	return true;
}

static bool cb_search_kwidx(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->n_kws = node->i_value;
	return true;
}

static bool cb_io_cache_mode(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->io->cachemode = true;
	} else {
		core->io->cachemode = false;
	}
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
		core->io->cached |= R_PERM_R;
	} else {
		core->io->cached &= ~R_PERM_R;
	}
	return true;
}

static bool cb_io_cache_write(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *)data;
	if (node->i_value) {
		core->io->cached |= R_PERM_W;
	} else {
		core->io->cached &= ~R_PERM_W;
	}
	return true;
}

static bool cb_io_cache(void *user, void *data) {
	(void)cb_io_cache_read (user, data);
	(void)cb_io_cache_write (user, data);
	return true;
}

static bool cb_ioaslr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->aslr = (bool)node->i_value;
	return true;
}

static bool cb_io_pava(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->pava = node->i_value;
	if (node->i_value && core->io->va) {
		eprintf ("Warning: You may probably want to disable io.va too.\n");
	}
	return true;
}

static bool cb_iova(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
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
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->ff = (bool)node->i_value;
	return true;
}

static bool cb_iomask(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->mask = node->i_value;
	core->flags->mask = node->i_value;
	return true;
}

static bool cb_io_oxff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->Oxff = (ut8)node->i_value;
	return true;
}

static bool cb_ioautofd(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->autofd = (bool)node->i_value;
	return true;
}

static bool cb_scr_color_grep(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	/* Let cons know we have a new pager. */
	core->cons->context->grep_color = node->i_value;
	return true;
}

static bool cb_scr_color_grep_highlight(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->context->grep_highlight = node->i_value;
	return true;
}

static bool cb_pager(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		eprintf ("Usage: scr.pager must be '..' for internal less, or the path to a program in $PATH\n");
		return false;
	}
	/* Let cons know we have a new pager. */
	free (core->cons->pager);
	core->cons->pager = strdup (node->value);
	return true;
}

static bool cb_breaklines(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->break_lines = node->i_value;
	return true;
}

static bool cb_scr_gadgets(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode *) data;
	core->scr_gadgets = node->i_value;
	return true;
}

static bool cb_fps(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fps = node->i_value;
	return true;
}

static bool cb_scrtheme(void* user, void* data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value) {
		if (*node->value == '?') {
			r_core_cmd0 (core, "eco");
		} else {
			r_core_cmdf (core, "eco %s", node->value);
		}
	}
	return true;
}

static bool cb_scrbreakword(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value) {
		r_cons_breakword (node->value);
	} else {
		r_cons_breakword (NULL);
	}
	return true;
}

static bool cb_scroptimize(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	RCore *core = (RCore*) user;
	core->cons->optimize = node->i_value;
	return true;
}

static bool cb_scrcolumns(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	RCore *core = (RCore*) user;
	int n = atoi (node->value);
	core->cons->force_columns = n;
	core->dbg->regcols = n / 20;
	return true;
}

static bool cb_scrfgets(void* user, void* data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	core->cons->user_fgets = node->i_value
		? NULL : (void *)r_core_fgets;
	return true;
}

static bool cb_scrhtml(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_context ()->is_html = node->i_value;
	// TODO: control error and restore old value (return false?) show errormsg?
	return true;
}

static bool cb_scrhighlight(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_highlight (node->value);
	return true;
}

#if __WINDOWS__
static bool scr_vtmode(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (r_str_is_true (node->value)) {
		node->i_value = 1;
	}
	node->i_value = node->i_value > 2 ? 2 : node->i_value;
	r_line_singleton ()->vtmode = r_cons_singleton ()->vtmode = node->i_value;

	DWORD mode;
	HANDLE input = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (input, &mode);
	if (node->i_value == 2) {
		SetConsoleMode (input, mode & ENABLE_VIRTUAL_TERMINAL_INPUT);
		r_cons_singleton ()->term_raw = ENABLE_VIRTUAL_TERMINAL_INPUT;
	} else {
		SetConsoleMode (input, mode & ~ENABLE_VIRTUAL_TERMINAL_INPUT);
		r_cons_singleton ()->term_raw = 0;
	}
	HANDLE streams[] = { GetStdHandle (STD_OUTPUT_HANDLE), GetStdHandle (STD_ERROR_HANDLE) };
	int i;
	if (node->i_value > 0) {
		for (i = 0; i < R_ARRAY_SIZE (streams); i++) {
			GetConsoleMode (streams[i], &mode);
			SetConsoleMode (streams[i],
				mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
	} else {
		for (i = 0; i < R_ARRAY_SIZE (streams); i++) {
			GetConsoleMode (streams[i], &mode);
			SetConsoleMode (streams[i],
				mode & ~ENABLE_VIRTUAL_TERMINAL_PROCESSING & ~ENABLE_WRAP_AT_EOL_OUTPUT);
		}
	}
	return true;
}
#endif

static bool cb_screcho(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->echo = node->i_value;
	return true;
}

static bool cb_scrlinesleep(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->linesleep = node->i_value;
	return true;
}

static bool cb_scr_maxpage(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->maxpage = node->i_value;
	return true;
}

static bool cb_scrpagesize(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->pagesize = node->i_value;
	return true;
}

static bool cb_scrflush(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_context ()->flush = node->i_value;
	return true;
}

static bool cb_scrstrconv(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			r_cons_printf ("Valid values for scr.strconv:\n"
				"  asciiesc  convert to ascii with non-ascii chars escaped\n"
				"  asciidot  convert to ascii with non-ascii chars turned into a dot (except control chars stated below)\n"
				"\n"
				"Ascii chars are in the range 0x20-0x7e. Always escaped control chars are alert (\\a),\n"
				"backspace (\\b), formfeed (\\f), newline (\\n), carriage return (\\r), horizontal tab (\\t)\n"
				"and vertical tab (\\v). Also, double quotes (\\\") are always escaped, but backslashes (\\\\)\n"
				"are only escaped if str.escbslash = true.\n");
		} else {
			print_node_options (node);
		}
		return false;
	} else {
		free ((char *)core->print->strconv_mode);
		core->print->strconv_mode = strdup (node->value);
	}
	return true;
}

static bool cb_graphformat(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		r_cons_printf ("png\njpg\npdf\nps\nsvg\njson\n");
		return false;
	}
	return true;
}

static bool cb_exectrap(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	RCore *core = (RCore*) user;
	if (core->anal && core->anal->esil) {
		core->anal->esil->exectrap = node->i_value;
	}
	return true;
}

static bool cb_iotrap(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	RCore *core = (RCore*) user;
	if (core->anal && core->anal->esil) {
		core->anal->esil->iotrap = node->i_value;
	}
	return true;
}

static bool cb_scr_bgfill(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_BGFILL;
	} else {
		core->print->flags &= (~R_PRINT_FLAGS_BGFILL);
	}
	r_print_set_flags (core->print, core->print->flags);
	return true;
}

static bool cb_scrint(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value && r_sandbox_enable (0)) {
		return false;
	}
	r_cons_singleton ()->context->is_interactive = node->i_value;
	return true;
}

static bool cb_scrnkey(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		print_node_options (node);
		return false;
	}
	return true;
}

static bool cb_scr_demo(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->context->demo = node->i_value;
	return true;
}

static bool cb_scr_histblock(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->histblock = node->i_value;
	return true;
}

static bool cb_scrprompt(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->scr_prompt = node->i_value;
	r_line_singleton ()->echo = node->i_value;
	return true;
}

static bool cb_scrrows(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_rows = n;
	return true;
}

static bool cb_contiguous(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->contiguous = node->i_value;
	return true;
}

static bool cb_searchalign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return true;
}

static bool cb_segoff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_SEGOFF;
	} else {
		core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SEGOFF));
	}
	return true;
}

static bool cb_seggrn(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->rasm->config->seggrn = node->i_value;
	return true;
}

static bool cb_stopthreads(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->stop_all_threads = node->i_value;
	return true;
}

static bool cb_scr_prompt_popup(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->show_autocomplete_widget = node->i_value;
	return true;
}

static bool cb_swstep(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->swstep = node->i_value;
	return true;
}

static bool cb_consbreak(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->consbreak = node->i_value;
	return true;
}

static bool cb_teefile(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->teefile = node->value;
	return true;
}

static bool cb_trace(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->enabled = node->i_value;
	return true;
}

static bool cb_tracetag(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->tag = node->i_value;
	return true;
}

static bool cb_utf8(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_set_utf8 ((bool)node->i_value);
	return true;
}

static bool cb_utf8_curvy(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->use_utf8_curvy = node->i_value;
	return true;
}

static bool cb_dotted(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->dotted_lines = node->i_value;
	return true;
}

static bool cb_zoombyte(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	switch (*node->value) {
	case 'p': case 'f': case 's': case '0':
	case 'F': case 'e': case 'h':
		core->print->zoom->mode = *node->value;
		break;
	default:
		eprintf ("Invalid zoom.byte value. See pz? for help\n");
		r_cons_printf ("pzp\npzf\npzs\npz0\npzF\npze\npzh\n");
		return false;
	}
	return true;
}

static bool cb_analverbose(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->anal->verbose = node->i_value;
	return true;
}

static bool cb_binverbose(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->bin->verbose = node->i_value;
	return true;
}

static bool cb_prjname(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
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
			eprintf ("Cannot rename project.\n");
		} else {
			r_project_close (core->prj);
		}
	} else {
		if (*prjname) {
			if (r_project_open (core->prj, prjname, NULL)) {
				return true;
			}
			eprintf ("Cannot open project.\n");
		} else {
			return true;
		}
	}
	return false;
}

static bool cb_rawstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->bin->rawstr = node->i_value;
	return true;
}

static bool cb_debase64(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->bin->debase64 = node->i_value;
	return true;
}

static bool cb_binstrings(void *user, void *data) {
	const ut32 req = R_BIN_REQ_STRINGS;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->bin->filter_rules |= req;
	} else {
		core->bin->filter_rules &= ~req;
	}
	return true;
}

static bool cb_demangle_trylib(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (!core || !core->bin) {
		return false;
	}
	core->bin->demangle_trylib = node->i_value;
	return true;
}

static bool cb_bindbginfo(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (!core || !core->bin) {
		return false;
	}
	core->bin->want_dbginfo = node->i_value;
	return true;
}

static bool cb_binprefix(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
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
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		ut64 old_v = core->bin->maxstrbuf;
		if (v < 1) {
			v = 4; // HACK
		}
		core->bin->maxstrbuf = v;
		if (v>old_v) {
			r_bin_reset_strings (core->bin);
		}
		return true;
	}
	return true;
}

static bool cb_binmaxsymlen(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		core->bin->maxsymlen = node->i_value;
		return true;
	}
	return true;
}

static bool cb_binmaxstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		if (v < 1) {
			v = 4; // HACK
		}
		core->bin->maxstrlen = v;
		r_bin_reset_strings (core->bin);
		return true;
	}
	return true;
}

static bool cb_binminstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		if (v < 1) {
			v = 4; // HACK
		}
		core->bin->minstrlen = v;
		r_bin_reset_strings (core->bin);
		return true;
	}
	return true;
}

static bool cb_searchin(void *user, void *data) {
	RCore *core = (RCore*)user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		if (strlen (node->value) > 1 && node->value[1] == '?') {
			r_cons_printf ("Valid values for search.in (depends on .from/.to and io.va):\n"
			"raw                search in raw io (ignoring bounds)\n"
			"flag               find boundaries on flag in current offset bigger than 1 byte\n"
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
			print_node_options (node);
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
	RCore *core = (RCore*)user;
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
			r_core_cmd0 (core, "afcl");
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
			r_core_cmd0 (core, "afcl");
			return false;
		}
		r_anal_set_cc_default (core->anal, node->value);
	}
	return true;
}

static bool cb_anal_roregs(RCore *core, RConfigNode *node) {
	if (core && core->anal && core->anal->reg) {
		r_list_free (core->anal->reg->roregs);
		core->anal->reg->roregs = r_str_split_duplist (node->value, ",", true);
	}
	return true;
}

static bool cb_anal_gp(RCore *core, RConfigNode *node) {
	core->anal->gp = node->i_value;
	return true;
}

static bool cb_anal_cs(RCore *core, RConfigNode *node) {
	// core->anal->cs = node->i_value;
	core->rasm->config->segbas = node->i_value;
	return true;
}

static bool cb_anal_from(RCore *core, RConfigNode *node) {
	if (r_config_get_i (core->config, "anal.limits")) {
		r_anal_set_limits (core->anal,
				r_config_get_i (core->config, "anal.from"),
				r_config_get_i (core->config, "anal.to"));
	}
	return true;
}

static bool cb_anal_limits(void *user, RConfigNode *node) {
	RCore *core = (RCore*)user;
	if (node->i_value) {
		r_anal_set_limits (core->anal,
				r_config_get_i (core->config, "anal.from"),
				r_config_get_i (core->config, "anal.to"));
	} else {
		r_anal_unset_limits (core->anal);
	}
	return 1;
}

static bool cb_anal_rnr(void *user, RConfigNode *node) {
	RCore *core = (RCore*)user;
	core->anal->recursive_noreturn = node->i_value;
	return 1;
}

static bool cb_anal_jmptbl(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.jmptbl = node->i_value;
	return true;
}

static bool cb_anal_cjmpref(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.cjmpref = node->i_value;
	return true;
}

static bool cb_anal_jmpref(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.jmpref = node->i_value;
	return true;
}

static bool cb_anal_jmpabove(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.jmpabove = node->i_value;
	return true;
}

static bool cb_anal_loads(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.loads = node->i_value;
	return true;
}

static bool cb_anal_followdatarefs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.followdatarefs = node->i_value;
	return true;
}

static bool cb_anal_jmpmid(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.jmpmid = node->i_value;
	return true;
}

static bool cb_anal_searchstringrefs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.searchstringrefs = node->i_value;
	return true;
}

static bool cb_anal_pushret(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.pushret = node->i_value;
	return true;
}

static bool cb_anal_brokenrefs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.followbrokenfcnsrefs = node->i_value;
	return true;
}

static bool cb_anal_trycatch(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.trycatch = node->i_value;
	return true;
}

static bool cb_anal_bb_max_size(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->opt.bb_max_size = node->i_value;
	return true;
}

static bool cb_anal_cxxabi(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;

	if (*node->value == '?') {
		print_node_options (node);
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
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	ut64 from = (ut64)r_config_get_i (core->config, "lines.from");
	int io_sz = r_io_size (core->io);
	ut64 to = r_num_math (core->num, node->value);
	if (to == 0) {
		core->print->lines_cache_sz = -1;
		return true;
	}
	if (to > from + io_sz) {
		R_LOG_ERROR ("lines.to: can't exceed addr 0x%08"PFMT64x" 0x%08"PFMT64x" %d", from, to, io_sz);
		return true;
	}
	if (to > from) {
		core->print->lines_cache_sz = r_core_lines_initcache (core, from, to);
	} else {
		R_LOG_ERROR ("Invalid range 0x%08"PFMT64x" .. 0x%08"PFMT64x, from, to);
	}
	return true;
}

static bool cb_linesabs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->print->lines_abs = node->i_value;
	if (core->print->lines_abs && core->print->lines_cache_sz <= 0) {
		ut64 from = (ut64)r_config_get_i (core->config, "lines.from");
		const char *to_str = r_config_get (core->config, "lines.to");
		ut64 to = r_num_math (core->num, (to_str && *to_str) ? to_str : "$s");
		core->print->lines_cache_sz = r_core_lines_initcache (core, from, to);
		if (core->print->lines_cache_sz == -1) {
			eprintf ("ERROR: \"lines.from\" and \"lines.to\" must be set\n");
		} else {
			eprintf ("Found %d lines\n", core->print->lines_cache_sz-1);
		}
	}
	return true;
}

static bool cb_malloc(void *user, void *data) {
 	RCore *core = (RCore*) user;
 	RConfigNode *node = (RConfigNode*) data;

 	if (node->value) {
 		if (!strcmp ("jemalloc", node->value) || !strcmp ("glibc", node->value)) {
			if (core->dbg) {
				core->dbg->malloc = data;
			}
 		}

 	}
	return true;
}

static bool cb_log_config_level(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_level (node->i_value);
	return true;
}

static bool cb_log_config_traplevel(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_traplevel (node->i_value);
	return true;
}

static bool cb_log_config_ts(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_show_ts (node->i_value);
	return true;
}

static bool cb_log_config_filter(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	const char *value = node->value;
	r_log_set_filter (value);
	return true;
}

static bool cb_log_config_file(void *coreptr, void *nodeptr) {
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

static bool cb_log_config_colors(void *coreptr, void *nodeptr) {
	RConfigNode *node = (RConfigNode *)nodeptr;
	r_log_set_colors (r_str_is_true (node->value));
	return true;
}

static bool cb_log_config_quiet(void *coreptr, void *nodeptr) {
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
	RConfigNode *node = data;
	char *p = r_file_path ("git");
	bool found = (p && (*p == 'g' ||*p == '/'));
	free (p);
	if (*node->value == '?') {
		if (found) {
			r_cons_println ("git");
		}
		r_cons_println ("rvc");
		return true;
	}
	if (!strcmp (node->value, "git")) {
		if (found) {
			return true;
		}
		return false;
	}
	if (!strcmp (node->value, "rvc")) {
		return true;
	}
	R_LOG_ERROR ("Unknown version control '%s'.", node->value);
	return false;
}

R_API int r_core_config_init(RCore *core) {
	int i;
	char buf[128], *p, *tmpdir;
	RConfigNode *n;
	RConfig *cfg = core->config = r_config_new (core);
	if (!cfg) {
		return 0;
	}
	cfg->cb_printf = r_cons_printf;
	cfg->num = core->num;
	/* dir.prefix is used in other modules, set it first */
	{
		char *pfx = r_sys_getenv("R2_PREFIX");
#if __WINDOWS__
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
	/* pdb */
	SETPREF ("pdb.useragent", "microsoft-symbol-server/6.11.0001.402", "User agent for Microsoft symbol server");
	SETPREF ("pdb.server", "https://msdl.microsoft.com/download/symbols", "Semi-colon separated list of base URLs for Microsoft symbol servers");
	{
		char *pdb_path = r_str_home (R2_HOME_PDB);
		SETPREF ("pdb.symstore", pdb_path, "path to downstream symbol store");
		R_FREE(pdb_path);
	}
	SETI ("pdb.extract", 1, "avoid extract of the pdb file, just download");
	SETI ("pdb.autoload", false, "automatically load the required pdb files for loaded DLLs");

	/* anal */
	SETBPREF ("anal.onchange", "false", "automatically reanalyze function if any byte has changed (EXPERIMENTAL)");
	SETPREF ("anal.fcnprefix", "fcn",  "prefix new function names with this");
	const char *analcc = r_anal_cc_default (core->anal);
	SETCB ("anal.cc", analcc? analcc: "", (RConfigCallback)&cb_analcc, "specify default calling convention");
	const char *analsyscc = r_anal_syscc_default (core->anal);
	SETCB ("anal.syscc", analsyscc? analsyscc: "", (RConfigCallback)&cb_analsyscc, "specify default syscall calling convention");
	SETCB ("anal.verbose", "false", &cb_analverbose, "show RAnal warnings when analyzing code");
	SETBPREF ("anal.a2f", "false",  "use the new WIP analysis algorithm (core/p/a2f), anal.depth ignored atm");
	SETCB ("anal.roregs", "gp,zero", (RConfigCallback)&cb_anal_roregs, "comma separated list of register names to be readonly");
	SETICB ("anal.cs", 0, (RConfigCallback)&cb_anal_cs, "set the value for the x86-16 CS segment register (see asm.seggrn and asm.segoff)");
	SETICB ("anal.gp", 0, (RConfigCallback)&cb_anal_gp, "set the value of the GP register (MIPS)");
	SETBPREF ("anal.gpfixed", "true", "set gp register to anal.gp before emulating each instruction in aae");
	SETCB ("anal.limits", "false", (RConfigCallback)&cb_anal_limits, "restrict analysis to address range [anal.from:anal.to]");
	SETCB ("anal.rnr", "false", (RConfigCallback)&cb_anal_rnr, "recursive no return checks (EXPERIMENTAL)");
	SETCB ("anal.limits", "false", (RConfigCallback)&cb_anal_limits, "restrict analysis to address range [anal.from:anal.to]");
	SETICB ("anal.from", -1, (RConfigCallback)&cb_anal_from, "lower limit on the address range for analysis");
	SETICB ("anal.to", -1, (RConfigCallback)&cb_anal_from, "upper limit on the address range for analysis");
	n = NODECB ("anal.in", "io.maps.x", &cb_searchin);
	SETDESC (n, "specify search boundaries for analysis");
	SETOPTIONS (n, "range", "block",
		"bin.segment", "bin.segments", "bin.segments.x", "bin.segments.r", "bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"anal.fcn", "anal.bb",
	NULL);
	SETI ("anal.timeout", 0, "stop analyzing after a couple of seconds");
	SETCB ("anal.jmp.retpoline", "true", &cb_anal_jmpretpoline, "analyze retpolines, may be slower if not needed");
	SETICB ("anal.jmp.tailcall", 0, &cb_anal_jmptailcall, "consume a branch as a call if delta is big");

	SETCB ("anal.armthumb", "false", &cb_analarmthumb, "aae computes arm/thumb changes (lot of false positives ahead)");
	SETCB ("anal.delay", "true", &cb_anal_delay, "enable delay slot analysis if supported by the architecture");
	SETICB ("anal.depth", 64, &cb_analdepth, "max depth at code analysis"); // XXX: warn if depth is > 50 .. can be problematic
	SETICB ("anal.graph_depth", 256, &cb_analgraphdepth, "max depth for path search");
	SETICB ("anal.sleep", 0, &cb_analsleep, "sleep N usecs every so often during analysis. Avoid 100% CPU usage");
	SETCB ("anal.ignbithints", "false", &cb_anal_ignbithints, "ignore the ahb hints (only obey asm.bits)");
	SETBPREF ("anal.calls", "false", "make basic af analysis walk into calls");
	SETBPREF ("anal.autoname", "false", "speculatively set a name for the functions, may result in some false positives");
	SETBPREF ("anal.hasnext", "false", "continue analysis after each function");
	SETICB ("anal.nonull", 0, &cb_anal_nonull, "do not analyze regions of N null bytes");
	SETBPREF ("anal.esil", "false", "use the new ESIL code analysis");
	SETCB ("anal.strings", "false", &cb_analstrings, "identify and register strings during analysis (aar only)");
	SETPREF ("anal.types.spec", "gcc",  "set profile for specifying format chars used in type analysis");
	SETBPREF ("anal.types.verbose", "false", "verbose output from type analysis");
	SETBPREF ("anal.types.constraint", "false", "enable constraint types analysis for variables");
	SETCB ("anal.vars", "true", &cb_analvars, "analyze local variables and arguments");
	SETCB ("anal.vars.stackname", "false", &cb_analvars_stackname, "name variables based on their offset on the stack");
	SETBPREF ("anal.vinfun", "true",  "search values in functions (aav) (false by default to only find on non-code)");
	SETBPREF ("anal.vinfunrange", "false",  "search values outside function ranges (requires anal.vinfun=false)\n");
	SETCB ("anal.norevisit", "false", &cb_analnorevisit, "do not visit function analysis twice (EXPERIMENTAL)");
	SETCB ("anal.nopskip", "true", &cb_analnopskip, "skip nops at the beginning of functions");
	SETCB ("anal.hpskip", "false", &cb_analhpskip, "skip `mov reg, reg` and `lea reg, [reg] at the beginning of functions");
	n = NODECB ("anal.arch", R_SYS_ARCH, &cb_analarch);
	SETDESC (n, "select the architecture to use");
	update_analarch_options (core, n);
	// SETCB ("anal.cpu", R_SYS_ARCH, &cb_analcpu, "specify the anal.cpu to use");
	SETPREF ("anal.prelude", "", "specify an hexpair to find preludes in code");
	SETCB ("anal.recont", "false", &cb_analrecont, "end block after splitting a basic block instead of error"); // testing
	SETCB ("anal.jmp.indir", "false", &cb_analijmp, "follow the indirect jumps in function analysis"); // testing
	SETI ("anal.ptrdepth", 3, "maximum number of nested pointers to follow in analysis");
	SETICB ("asm.lines.maxref", 0, &cb_analmaxrefs, "maximum number of reflines to be analyzed and displayed in asm.lines with pd");

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

	n = NODECB ("anal.cxxabi", "itanium", &cb_anal_cxxabi);
	SETDESC (n, "select C++ RTTI ABI");
	SETOPTIONS (n, "itanium", "msvc", NULL);

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
	n = NODECB ("dbg.malloc", "glibc", &cb_malloc);
#else
	n = NODECB ("dbg.malloc", "jemalloc", &cb_malloc);
#endif
	SETDESC (n, "choose malloc structure parser");
	SETOPTIONS (n, "glibc", "jemalloc", NULL);
#if __GLIBC_MINOR__ > 25
	SETBPREF ("dbg.glibc.tcache", "true", "parse the tcache (glibc.minor > 2.25.x)");
#else
	SETBPREF ("dbg.glibc.tcache", "false", "parse the tcache (glibc.minor > 2.25.x)");
#endif
#if __x86_64__
	SETI ("dbg.glibc.ma_offset", 0x000000, "main_arena offset from his symbol");
	SETI ("dbg.glibc.fc_offset", 0x00280, "first chunk offset from brk_start");
#else
	SETI ("dbg.glibc.ma_offset", 0x1bb000, "main_arena offset from his symbol");
	SETI ("dbg.glibc.fc_offset", 0x148, "first chunk offset from brk_start");
#endif
	SETBPREF ("dbg.glibc.demangle", "false", "demangle linked-lists pointers introduced in glibc 2.32");
	SETBPREF ("esil.prestep", "true", "step before esil evaluation in `de` commands");
	SETI ("esil.maxsteps", 0, "If !=0 defines the maximum amount of steps to perform on aesu/aec/..");
	SETPREF ("esil.fillstack", "", "initialize ESIL stack with (random, debrujn, sequence, zeros, ...)");
	SETICB ("esil.verbose", 0, &cb_esilverbose, "show ESIL verbose level (0, 1, 2)");
	SETICB ("esil.gotolimit", core->anal->esil_goto_limit, &cb_gotolimit, "maximum number of gotos per ESIL expression");
	SETICB ("esil.stack.depth", 256, &cb_esilstackdepth, "number of elements that can be pushed on the esilstack");
	SETI ("esil.stack.size", 0xf0000, "set stack size in ESIL VM");
	SETI ("esil.stack.addr", 0x100000, "set stack address in ESIL VM");
	SETPREF ("esil.stack.pattern", "0", "specify fill pattern to initialize the stack (0, w, d, i)");
	SETI ("esil.addr.size", 64, "maximum address size in accessed by the ESIL VM");
	SETBPREF ("esil.breakoninvalid", "false", "break esil execution when instruction is invalid");
	SETI ("esil.timeout", 0, "a timeout (in seconds) for when we should give up emulating");
	SETCB ("cfg.debug", "false", &cb_cfgdebug, "debugger mode");
	/* asm */
	//asm.os needs to be first, since other asm.* depend on it
	n = NODECB ("asm.os", R_SYS_OS, &cb_asmos);
	SETDESC (n, "select operating system (kernel)");
	SETOPTIONS (n, "ios", "dos", "darwin", "linux", "freebsd", "openbsd", "netbsd", "windows", "s110", NULL);
	SETI ("asm.xrefs.fold", 5,  "maximum number of xrefs to be displayed as list (use columns above)");
	SETBPREF ("asm.xrefs.code", "true",  "show the code xrefs (generated by jumps instead of calls)");
	SETI ("asm.xrefs.max", 20,  "maximum number of xrefs to be displayed without folding");
	SETCB ("asm.invhex", "false", &cb_asm_invhex, "show invalid instructions as hexadecimal numbers");
	SETBPREF ("asm.instr", "true", "display the disassembled instruction");
	SETBPREF ("asm.meta", "true", "display the code/data/format conversions in disasm");
	SETBPREF ("asm.bytes", "true", "display the bytes of each instruction");
	SETBPREF ("asm.bytes.right", "false", "display the bytes at the right of the disassembly");
	SETBPREF ("asm.bytes.opcolor", "false", "colorize bytes depending on opcode size + variant information");
	SETI ("asm.types", 1, "display the fcn types in calls (0=no,1=quiet,2=verbose)");
	SETBPREF ("asm.midcursor", "false", "cursor in visual disasm mode breaks the instruction");
	SETBPREF ("asm.cmt.flgrefs", "true", "show comment flags associated to branch reference");
	SETBPREF ("asm.cmt.right", "true", "show comments at right of disassembly if they fit in screen");
	SETBPREF ("asm.cmt.esil", "false", "show ESIL expressions as comments");
	SETI ("asm.cmt.col", 71, "column to align comments");
	SETICB ("asm.pcalign", 0, &cb_asm_pcalign, "only recognize as valid instructions aligned to this value");
	// maybe rename to asm.cmt.calls
	SETBPREF ("asm.calls", "true", "show callee function related info as comments in disasm");
	SETBPREF ("asm.comments", "true", "show comments in disassembly view");
	SETBPREF ("asm.usercomments", "false", "show user comments even if asm.comments is false");
	SETBPREF ("asm.sub.jmp", "true", "always substitute jump, call and branch targets in disassembly");
	SETBPREF ("asm.hints", "true", "disable all asm.hint* if false");
	SETBPREF ("asm.hint.jmp", "false", "show jump hints [numbers] in disasm");
	SETBPREF ("asm.hint.call", "true", "show call hints [numbers] in disasm");
	SETBPREF ("asm.hint.call.indirect", "true", "Hints for indirect call intructions go to the call destination");
	SETBPREF ("asm.hint.lea", "false", "show LEA hints [numbers] in disasm");
	SETBPREF ("asm.hint.imm", "false", "show immediate hints [numbers] in disasm");
	SETBPREF ("asm.hint.emu", "false", "show asm.emu hints [numbers] in disasm");
	SETBPREF ("asm.hint.cdiv", "false", "show CDIV hints optimization hint");
	SETI ("asm.hint.pos", 1, "shortcut hint position (-1, 0, 1)");
	SETBPREF ("asm.slow", "true", "perform slow analysis operations in disasm");
	SETBPREF ("asm.decode", "false", "use code analysis as a disassembler");
	SETICB ("asm.imm.arm", false,  &cb_asm_armimm, "display # for immediates in ARM");
	SETBPREF ("asm.imm.str", "true", "show immediates values as strings");
	SETBPREF ("asm.imm.trim", "false", "remove all offsets and constants from disassembly");
	SETBPREF ("asm.indent", "false", "indent disassembly based on reflines depth");
	SETI ("asm.indentspace", 2, "how many spaces to indent the code");
	SETBPREF ("asm.dwarf", "false", "show dwarf comment at disassembly");
	SETBPREF ("asm.dwarf.abspath", "false", "show absolute path in asm.dwarf");
	SETBPREF ("asm.dwarf.file", "true", "show filename of asm.dwarf in pd");
	SETBPREF ("asm.esil", "false", "show ESIL instead of mnemonic");
	SETBPREF ("asm.nodup", "false", "do not show dupped instructions (collapse disasm)");
	SETBPREF ("asm.emu", "false", "run ESIL emulation analysis on disasm");
	SETBPREF ("emu.pre", "false", "run ESIL emulation starting at the closest flag in pd");
	SETBPREF ("asm.refptr", "true", "show refpointer information in disasm");
	SETBPREF ("emu.lazy", "false", "do not emulate all instructions with aae (optimization)");
	SETBPREF ("emu.stack", "false", "create a temporary fake stack when emulating in disasm (asm.emu)");
	SETCB ("emu.str", "false", &cb_emustr, "show only strings if any in the asm.emu output");
	SETBPREF ("emu.str.lea", "true", "disable this in ARM64 code to remove some false positives");
	SETBPREF ("emu.str.off", "false", "always show offset when printing asm.emu strings");
	SETBPREF ("emu.str.inv", "true", "color-invert emu.str strings");
	SETBPREF ("emu.str.flag", "true", "also show flag (if any) for asm.emu string");
	SETBPREF ("emu.write", "false", "allow asm.emu to modify memory (WARNING)");
	SETBPREF ("emu.ssa", "false", "perform SSA checks and show the ssa reg names as comments");
	n = NODECB ("emu.skip", "ds", &cb_emuskip);
	SETDESC (n, "skip metadata of given types in asm.emu");
	SETOPTIONS (n, "d", "c", "s", "f", "m", "h", "C", "r", NULL);
	SETBPREF ("asm.sub.names", "true", "replace numeric values by flags (e.g. 0x4003e0 -> sym.imp.printf)");
	SETPREF ("asm.strip", "", "strip all instructions given comma separated types");
	SETBPREF ("asm.optype", "false", "show opcode type next to the instruction bytes");
	SETBPREF ("asm.lines.fcn", "true", "show function boundary lines");
	SETBPREF ("asm.flags", "true", "show flags");
	SETICB ("asm.flags.maxname", 0, &cb_maxname, "maximum length of flag name with smart chopping");
	SETI ("asm.flags.limit", 0, "maximum number of flags to show in a single offset");
	SETBPREF ("asm.flags.offset", "false", "show offset in flags");
	SETBPREF ("asm.flags.inbytes", "false",  "display flags inside the bytes space");
	SETBPREF ("asm.flags.inline", "false",  "display flags in line separated by commas instead of newlines");
	n = NODEICB ("asm.flags.middle", 2, &cb_midflags);
	SETOPTIONS (n, "0 = do not show flag", "1 = show without realign", "2 = realign at middle flag",
		"3 = realign at middle flag if sym.*", NULL);
	SETDESC (n, "realign disassembly if there is a flag in the middle of an instruction");
	SETCB ("asm.flags.real", "false", &cb_flag_realnames,
	       "show flags' unfiltered realnames instead of names, except realnames from demangling");
	SETBPREF ("asm.lbytes", "true", "align disasm bytes to left");
	SETBPREF ("asm.lines", "true", "show ASCII-art lines at disassembly");
	SETBPREF ("asm.lines.jmp", "true", "show flow lines at jumps");
	SETBPREF ("asm.lines.bb", "false", "show empty line after every basic block");
	SETBPREF ("asm.lines.call", "false", "enable call lines");
	SETBPREF ("asm.lines.ret", "false", "show separator lines after ret");
	SETBPREF ("asm.lines.out", "true", "show out of block lines");
	SETBPREF ("asm.lines.right", "false", "show lines before opcode instead of offset");
	SETBPREF ("asm.lines.wide", "false", "put a space between lines");
	SETBPREF ("asm.fcnsig", "true", "show function signature in disasm");
	SETICB ("asm.lines.width", 7, &cb_asmlineswidth, "number of columns for program flow arrows");
	SETICB ("asm.sub.varmin", 0x100, &cb_asmsubvarmin, "minimum value to substitute in instructions (asm.sub.var)");
	SETCB ("asm.sub.tail", "false", &cb_asmsubtail, "replace addresses with prefix .. syntax");
	SETBPREF ("asm.middle", "false", "allow disassembling jumps in the middle of an instruction");
	SETBPREF ("asm.bbmiddle", "true", "realign disassembly if a basic block starts in the middle of an instruction");
	SETBPREF ("asm.noisy", "true", "show comments considered noisy but possibly useful");
	SETBPREF ("asm.offset", "true", "show offsets in disassembly");
	SETBPREF ("hex.offset", "true", "show offsets in hex-dump");
	SETBPREF ("scr.square", "true", "use square pixels or not");
	SETCB ("scr.wideoff", "false", &cb_scr_wideoff, "adjust offsets to match asm.bits");
	SETCB ("scr.rainbow", "false", &cb_scrrainbow, "shows rainbow colors depending of address");
	SETCB ("scr.last", "true", &cb_scrlast, "cache last output after flush to make _ command work (disable for performance)");
	SETBPREF ("asm.reloff", "false", "show relative offsets instead of absolute address in disasm");
	SETBPREF ("asm.reloff.flags", "false", "show relative offsets to flags (not only functions)");
	SETBPREF ("asm.section", "false", "show section name before offset");
	SETBPREF ("asm.section.perm", "false", "show section permissions in the disasm");
	SETBPREF ("asm.section.name", "true", "show section name in the disasm");
	SETI ("asm.section.col", 20, "columns width to show asm.section");
	SETCB ("asm.sub.section", "false", &cb_asmsubsec, "show offsets in disasm prefixed with section/map name");
	SETCB ("asm.pseudo", "false", &cb_asmpseudo, "enable pseudo syntax");
	SETBPREF ("asm.size", "false", "show size of opcodes in disassembly (pd)");
	SETBPREF ("asm.stackptr", "false", "show stack pointer at disassembly");
	SETBPREF ("asm.cyclespace", "false", "indent instructions depending on CPU-cycles");
	SETBPREF ("asm.cycles", "false", "show CPU-cycles taken by instruction at disassembly");
	SETI ("asm.tabs", 0, "use tabs in disassembly");
	SETBPREF ("asm.tabs.once", "false", "only tabulate the opcode, not the arguments");
	SETI ("asm.tabs.off", 0, "tabulate spaces after the offset");
	SETBPREF ("asm.trace", "false", "show execution traces for each opcode");
	SETBPREF ("asm.trace.space", "false", "indent disassembly with trace.count information");
	SETBPREF ("asm.ucase", "false", "use uppercase syntax at disassembly");
	SETBPREF ("asm.capitalize", "false", "use camelcase at disassembly");
	SETBPREF ("asm.var", "true", "show local function variables in disassembly");
	SETBPREF ("asm.var.access", "false", "show accesses of local variables");
	SETBPREF ("asm.sub.var", "true", "substitute variables in disassembly");
	SETI ("asm.var.summary", 0, "show variables summary instead of full list in disasm (0, 1, 2)");
	SETBPREF ("asm.sub.varonly", "true", "substitute the entire variable expression with the local variable name (e.g. [local10h] instead of [ebp+local10h])");
	SETBPREF ("asm.sub.reg", "false", "substitute register names with their associated role name (drp~=)");
	SETBPREF ("asm.sub.rel", "true", "substitute pc relative expressions in disasm");
	SETBPREF ("asm.cmt.fold", "false", "fold comments, toggle with Vz");
	SETBPREF ("asm.family", "false", "show family name in disasm");
	SETBPREF ("asm.symbol", "false", "show symbol+delta instead of absolute offset");
	SETBPREF ("asm.anal", "false", "analyze code and refs while disassembling (see anal.strings)");
	SETI ("asm.symbol.col", 40, "columns width to show asm.section");
	SETCB ("asm.assembler", "", &cb_asmassembler, "set the plugin name to use when assembling");
	SETBPREF ("asm.minicols", "false", "only show the instruction in the column disasm");
	RConfigNode *asmcpu = NODECB ("asm.cpu", R_SYS_ARCH, &cb_asmcpu);
	SETDESC (asmcpu, "set the kind of asm.arch cpu");
	RConfigNode *asmarch = NODECB ("asm.arch", R_SYS_ARCH, &cb_asmarch);
	SETDESC (asmarch, "set the arch to be used by asm");
	/* we need to have both asm.arch and asm.cpu defined before updating options */
	update_asmarch_options (core, asmarch);
	update_asmcpu_options (core, asmcpu);
	n = NODECB ("asm.features", "", &cb_asmfeatures);
	SETDESC (n, "specify supported features by the target CPU");
	update_asmfeatures_options (core, n);
	n = NODECB ("asm.parser", "x86.pseudo", &cb_asmparser);
	SETDESC (n, "set the asm parser to use");
	update_asmparser_options (core, n);
	SETCB ("asm.segoff", "false", &cb_segoff, "show segmented address in prompt (x86-16)");
	SETCB ("asm.decoff", "false", &cb_decoff, "show segmented address in prompt (x86-16)");
	SETICB ("asm.seggrn", 4, &cb_seggrn, "segment granularity in bits (x86-16)");
	n = NODECB ("asm.syntax", "intel", &cb_asmsyntax);
	SETDESC (n, "select assembly syntax");
	SETOPTIONS (n, "att", "intel", "masm", "jz", "regnum", NULL);
	SETI ("asm.nbytes", 6, "number of bytes for each opcode at disassembly");
	SETBPREF ("asm.bytes.space", "false", "separate hexadecimal bytes with a whitespace");
#if R_SYS_BITS == R_SYS_BITS_64
	SETICB ("asm.bits", 64, &cb_asmbits, "word size in bits at assembler");
#else
	SETICB ("asm.bits", 32, &cb_asmbits, "word size in bits at assembler");
#endif
	n = r_config_node_get(cfg, "asm.bits");
	update_asmbits_options (core, n);
	SETBPREF ("asm.functions", "true", "show functions in disassembly");
	SETBPREF ("asm.xrefs", "true", "show xrefs in disassembly");
	SETBPREF ("asm.demangle", "true", "show demangled symbols in disasm");
	SETBPREF ("asm.describe", "false", "show opcode description");
	SETPREF ("asm.highlight", "", "highlight current line");
	SETBPREF ("asm.marks", "true", "show marks before the disassembly");
	SETBPREF ("asm.cmt.refs", "false", "show flag and comments from refs in disasm");
	SETBPREF ("asm.cmt.patch", "false", "show patch comments in disasm");
	SETBPREF ("asm.cmt.off", "nodup", "show offset comment in disasm (true, false, nodup)");
	SETBPREF ("asm.payloads", "false", "show payload bytes in disasm");

	/* bin */
	SETPREF ("bin.hashlimit", "10M", "only compute hash when opening a file if smaller than this size");
	SETCB ("bin.usextr", "true", &cb_usextr, "use extract plugins when loading files");
	SETCB ("bin.useldr", "true", &cb_useldr, "use loader plugins when loading files");
	SETCB ("bin.str.purge", "", &cb_strpurge, "purge strings (e bin.str.purge=? provides more detail)");
	SETPREF ("bin.str.real", "false", "set the realname in rbin.strings for better disasm (EXPERIMENTAL)");
	SETBPREF ("bin.b64str", "false", "try to debase64 the strings");
	SETCB ("bin.at", "false", &cb_binat, "RBin.cur depends on RCore.offset");
	SETBPREF ("bin.libs", "false", "try to load libraries after loading main binary");
	n = NODECB ("bin.str.filter", "", &cb_strfilter);
	SETDESC (n, "filter strings");
	SETOPTIONS (n, "a", "8", "p", "e", "u", "i", "U", "f", NULL);
	SETCB ("bin.filter", "true", &cb_binfilter, "filter symbol names to fix dupped names");
	SETCB ("bin.force", "", &cb_binforce, "force that rbin plugin");
	SETPREF ("bin.cache", "false", "use io.cache.read if bin needs to patch relocs");
	SETPREF ("bin.lang", "", "language for bin.demangle");
	SETBPREF ("bin.demangle", "true", "import demangled symbols from RBin");
	SETCB("bin.demangle.trylib", "true", &cb_demangle_trylib, "try to use system available libraries to demangle");
	SETBPREF ("bin.demangle.libs", "false", "show library name on demangled symbols names");
	SETI ("bin.baddr", -1, "base address of the binary");
	SETI ("bin.laddr", 0, "base address for loading library ('*.so')");
	SETCB ("bin.dbginfo", "true", &cb_bindbginfo, "load debug information at startup if available");
	SETBPREF ("bin.relocs", "true", "load relocs information at startup if available");
	SETICB ("bin.minstr", 0, &cb_binminstr, "minimum string length for r_bin");
	SETICB ("bin.maxsymlen", 0, &cb_binmaxsymlen, "maximum length for symbol names");
	SETICB ("bin.maxstr", 0, &cb_binmaxstr, "maximum string length for r_bin");
	SETICB ("bin.maxstrbuf", 1024*1024*10, & cb_binmaxstrbuf, "maximum size of range to load strings from");
	n = NODECB ("bin.str.enc", "guess", &cb_binstrenc);
	SETDESC (n, "default string encoding of binary");
	SETOPTIONS (n, "ascii", "latin1", "utf8", "utf16le", "utf32le", "utf16be", "utf32be", "guess", NULL);
	SETCB ("bin.prefix", "", &cb_binprefix, "prefix all symbols/sections/relocs with a specific string");
	SETCB ("bin.rawstr", "false", &cb_rawstr, "load strings from raw binaries");
	SETCB ("bin.strings", "true", &cb_binstrings, "load strings from rbin on startup");
	SETCB ("bin.debase64", "false", &cb_debase64, "try to debase64 all strings");
	SETBPREF ("bin.classes", "true", "load classes from rbin on startup");
	SETCB ("bin.verbose", "false", &cb_binverbose, "show RBin warnings when loading binaries");

	/* prj */
	SETCB ("prj.name", "", &cb_prjname, "name of current project");
	SETBPREF ("prj.files", "false", "save the target binary inside the project directory");
	SETBPREF ("prj.vc", "true", "use your version control system of choice (rvc, git) to manage projects");
	SETBPREF ("prj.zip", "false", "use ZIP format for project files");
	SETBPREF ("prj.gpg", "false", "TODO: encrypt project with GnuPGv2");
	SETBPREF ("prj.sandbox", "false", "sandbox r2 while loading project files");
	SETBPREF ("prj.alwasyprompt", "false", "even when the project is already\
			saved, ask the user to save the project when qutting");

	/* cfg */
	n = SETCB ("cfg.charset", "", &cb_cfgcharset, "specify encoding to use when printing strings");
	update_cfgcharsets_options (core, n);
	SETBPREF ("cfg.r2wars", "false", "enable some tweaks for the r2wars game");
	SETBPREF ("cfg.plugins", "true", "load plugins at startup");
	SETCB ("time.fmt", "%Y-%m-%d %H:%M:%S %u", &cb_cfgdatefmt, "Date format (%Y-%m-%d %H:%M:%S %u)");
	SETICB ("time.zone", 0, &cb_timezone, "time zone, in hours relative to GMT: +2, -1,..");
	SETCB ("cfg.corelog", "false", &cb_cfgcorelog, "log changes using the T api needed for realtime syncing");
	SETBPREF ("cfg.newtab", "false", "show descriptions in command completion");
	p = r_sys_getenv ("EDITOR");
#if __WINDOWS__
	r_config_set (cfg, "cfg.editor", r_str_get_fail (p, "notepad"));
#else
	r_config_set (cfg, "cfg.editor", r_str_get_fail (p, "vi"));
#endif
	free (p);
	r_config_desc (cfg, "cfg.editor", "select default editor program, portable %EDITOR");
	char *whoami = r_sys_whoami ();
	SETPREF ("cfg.user", whoami, "set current username/pid");
	free (whoami);
	SETCB ("cfg.fortunes", "true", &cb_cfg_fortunes, "if enabled show tips at start");
	RList *fortune_types = r_core_fortune_types ();
	if (!fortune_types) {
		fortune_types = r_list_newf (free);
		r_list_append (fortune_types, "tips");
		r_list_append (fortune_types, "fun");
	}
	char *fts = r_str_list_join (fortune_types, ",");
	r_list_free (fortune_types);
	char *fortune_desc = r_str_newf ("type of fortunes to show(%s)", fts);
	SETCB ("cfg.fortunes.type", fts, &cb_cfg_fortunes_type, fortune_desc);
	free (fts);
	free (fortune_desc);
	SETBPREF ("cfg.fortunes.clippy", "false", "use ?E instead of ?e");
	SETBPREF ("cfg.fortunes.tts", "false", "speak out the fortune");
	SETPREF ("cfg.prefixdump", "dump", "filename prefix for automated dumps");
	SETCB ("cfg.sandbox", "false", &cb_cfgsanbox, "sandbox mode disables systems and open on upper directories");
	SETCB ("cfg.sandbox.grain", "all", &cb_cfgsanbox_grain, "select which sand grains must pass the filter (all, net, files, socket, exec, disk)");
	SETBPREF ("cfg.wseek", "false", "Seek after write");
	SETCB ("cfg.bigendian", "false", &cb_bigendian, "use little (false) or big (true) endianness");
	SETI ("cfg.cpuaffinity", 0, "run on cpuid");

	/* log */
	// R2_LOGLEVEL / log.level
#if 0
	p = r_sys_getenv ("R2_LOGLEVEL");
	SETICB ("log.level", p? atoi(p): R_DEFAULT_LOGLVL, cb_log_config_level, "target log level/severity"\
	 " (0:SILLY, 1:DEBUG, 2:VERBOSE, 3:INFO, 4:WARN, 5:ERROR, 6:FATAL)"
	);
	free (p);
	// R2_LOGTRAP_LEVEL / log.traplevel
	p = r_sys_getenv ("R2_LOGTRAPLEVEL");
	SETICB ("log.traplevel", p ? atoi(p) : R_LOGLVL_FATAL, cb_log_config_traplevel, "log level for trapping R2 when hit"\
	 " (0:SILLY, 1:VERBOSE, 2:DEBUG, 3:INFO, 4:WARN, 5:ERROR, 6:FATAL)"
	);
	free (p);
	// R2_LOGFILE / log.file
	p = r_sys_getenv ("R2_LOGFILE");
	SETCB ("log.file", r_str_get (p), cb_log_config_file, "logging output filename / path");
	free (p);
	// R2_LOGSRCINFO / log.srcinfo
	p = r_sys_getenv ("R2_LOGSRCINFO");
	SETCB ("log.srcinfo", r_str_get_fail (p, "false"), cb_log_config_srcinfo, "should the log output contain src info (filename:lineno)");
	free (p);
	// R2_LOGCOLORS / log.colors
	p = r_sys_getenv ("R2_LOGCOLORS");
	SETCB ("log.colors", r_str_get_fail (p, "false"), cb_log_config_colors, "should the log output use colors (TODO)");
	free (p);

	SETCB ("log.events", "false", &cb_log_events, "remote HTTP server to sync events with");
#endif
	SETICB ("log.level", R_LOGLVL_DEFAULT, cb_log_config_level, "Target log level/severity (0:FATAL 1:ERROR 2:INFO 3:WARN 4:DEBUG)");
	SETCB ("log.ts", "false", cb_log_config_ts, "Show timestamp in log messages");

	SETICB ("log.traplevel", 0, cb_log_config_traplevel, "Log level for trapping R2 when hit");
	SETCB ("log.file", "", cb_log_config_file, "Logging output filename / path");
	SETCB ("log.filter", "", cb_log_config_filter, "Filter only messages matching given origin");
	SETCB ("log.origin", "false", cb_log_origin, "Show [origin] in log messages");
	SETCB ("log.color", "false", cb_log_config_colors, "Should the log output use colors");
	SETCB ("log.quiet", "false", cb_log_config_quiet, "Be quiet, dont log anything to console");

	// zign
	SETPREF ("zign.prefix", "sign", "default prefix for zignatures matches");
	SETI ("zign.maxsz", 500, "maximum zignature length");
	SETI ("zign.minsz", 16, "minimum zignature length for matching");
	SETI ("zign.mincc", 10, "minimum cyclomatic complexity for matching");
	SETBPREF ("zign.graph", "true", "use graph metrics for matching");
	SETBPREF ("zign.bytes", "true", "use bytes patterns for matching");
	SETBPREF ("zign.offset", "false", "use original offset for matching");
	SETBPREF ("zign.refs", "true", "use references for matching");
	SETBPREF ("zign.hash", "true", "use Hash for matching");
	SETBPREF ("zign.types", "true", "use types for matching");
	SETBPREF ("zign.autoload", "false", "autoload all zignatures located in " R_JOIN_2_PATHS ("~", R2_HOME_ZIGNS));
	SETPREF ("zign.diff.bthresh", "1.0", "threshold for diffing zign bytes [0, 1] (see zc?)");
	SETPREF ("zign.diff.gthresh", "1.0", "threshold for diffing zign graphs [0, 1] (see zc?)");
	SETPREF ("zign.threshold", "0.0", "minimum similarity required for inclusion in zb output");

	/* diff */
	SETCB ("diff.sort", "addr", &cb_diff_sort, "specify function diff sorting column see (e diff.sort=?)");
	SETI ("diff.from", 0, "set source diffing address for px (uses cc command)");
	SETI ("diff.to", 0, "set destination diffing address for px (uses cc command)");
	SETBPREF ("diff.bare", "false", "never show function names in diff output");
	SETBPREF ("diff.levenstein", "false", "use faster (and buggy) levenstein algorithm for buffer distance diffing");

	/* dir */
	SETI ("dir.depth", 10,  "maximum depth when searching recursively for files");
	{
		char *path = r_str_newf (R_JOIN_2_PATHS ("%s", R2_SDB_MAGIC), r_config_get (core->config, "dir.prefix"));
		SETPREF ("dir.magic", path, "path to r_magic files");
		free (path);
		path = r_str_newf (R_JOIN_2_PATHS ("%s", R2_PLUGINS), r_config_get (core->config, "dir.prefix"));
		SETPREF ("dir.plugins", path, "path to plugin files to be loaded at startup");
		free (path);
	}
	SETCB ("dir.source", "", &cb_dirsrc, "path to find source files");
	SETPREF ("dir.types", "/usr/include", "default colon-separated list of paths to find C headers to cparse types");
	SETPREF ("dir.libs", "", "specify path to find libraries to load when bin.libs=true");
#if __EMSCRIPTEN__ || __wasi__
	p = strdup ("/tmp");
#else
	p = r_sys_getenv (R_SYS_HOME);
#endif
	SETCB ("dir.home", r_str_get_fail (p, "/"), &cb_dirhome, "path for the home directory");
	free (p);
	p = r_sys_getenv (R_SYS_TMP);
	SETCB ("dir.tmp", r_str_get (p), &cb_dirtmp, "path of the tmp directory");
	free (p);
	SETCB ("dir.projects", R_JOIN_2_PATHS ("~", R2_HOME_PROJECTS), &cb_dir_projects, "default path for projects");
	SETCB ("dir.zigns", R_JOIN_2_PATHS ("~", R2_HOME_ZIGNS), &cb_dirzigns, "default path for zignatures (see zo command)");
	SETPREF ("stack.reg", "SP", "which register to use as stack pointer in the visual debug");
	SETBPREF ("stack.bytes", "true", "show bytes instead of words in stack");
	SETBPREF ("stack.anotated", "false", "show anotated hexdump in visual debug");
	SETI ("stack.size", 64,  "size in bytes of stack hexdump in visual debug");
	SETI ("stack.delta", 0,  "delta for the stack dump");

	SETCB ("dbg.maxsnapsize", "32M", &cb_dbg_maxsnapsize, "dont make snapshots of maps bigger than a specific size");
	SETCB ("dbg.wrap", "false", &cb_dbg_wrap, "enable the ptrace-wrap abstraction layer (needed for debugging from iaito)");
	SETCB ("dbg.libs", "", &cb_dbg_libs, "If set stop when loading matching libname");
	SETBPREF ("dbg.skipover", "false", "make dso perform a dss (same goes for esil and visual/graph");
#if __APPLE__
	SETBPREF ("dbg.hwbp", "true", "use hardware breakpoints instead of software ones when enabled");
#else
	SETBPREF ("dbg.hwbp", "false", "use hardware breakpoints instead of software ones when enabled");
#endif
	SETCB ("dbg.unlibs", "", &cb_dbg_unlibs, "If set stop when unloading matching libname");
	SETCB ("dbg.verbose", "false", &cb_dbg_verbose, "Verbose debug output");
	SETBPREF ("dbg.slow", "false", "show stack and regs in visual mode in a slow but verbose mode");
	SETBPREF ("dbg.funcarg", "false", "display arguments to function call in visual mode");

	SETCB ("dbg.bpinmaps", "true", &cb_dbg_bpinmaps, "activate breakpoints only if they are inside a valid map");
	SETCB ("dbg.forks", "false", &cb_dbg_forks, "stop execution if fork() is done (see dbg.threads)");
	n = NODECB ("dbg.btalgo", "fuzzy", &cb_dbg_btalgo);
	SETDESC (n, "select backtrace algorithm");
	SETOPTIONS (n, "default", "fuzzy", "anal", "trace", NULL);
	SETCB ("dbg.threads", "false", &cb_stopthreads, "stop all threads when debugger breaks (see dbg.forks)");
	SETCB ("dbg.clone", "false", &cb_dbg_clone, "stop execution if new thread is created");
	SETCB ("dbg.aftersyscall", "true", &cb_dbg_aftersc, "stop execution before the syscall is executed (see dcs)");
	SETCB ("dbg.profile", "", &cb_runprofile, "path to RRunProfile file");
	SETCB ("dbg.args", "", &cb_dbg_args, "set the args of the program to debug");
	SETCB ("dbg.follow.child", "false", &cb_dbg_follow_child, "continue tracing the child process on fork. By default the parent process is traced");
	SETCB ("dbg.trace.continue", "true", &cb_dbg_trace_continue, "trace every instruction between the initial PC position and the PC position at the end of continue's execution");
	SETBPREF ("dbg.trace.inrange", "false", "while tracing, avoid following calls outside specified range");
	SETBPREF ("dbg.trace.libs", "true", "trace library code too");
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
	r_config_desc (cfg, "dbg.follow", "follow program counter when pc > core->offset + dbg.follow");
	SETBPREF ("dbg.rebase", "true", "rebase anal/meta/comments/flags when reopening file in debugger");
	SETCB ("dbg.swstep", "false", &cb_swstep, "force use of software steps (code analysis+breakpoint)");
	SETBPREF ("dbg.exitkills", "true", "kill process on exit");
	SETPREF ("dbg.exe.path", "", "path to binary being debugged");
	SETCB ("dbg.execs", "false", &cb_dbg_execs, "stop execution if new thread is created");
	SETICB ("dbg.gdb.page_size", 4096, &cb_dbg_gdb_page_size, "page size on gdb target (useful for QEMU)");
	SETICB ("dbg.gdb.retries", 10, &cb_dbg_gdb_retries, "number of retries before gdb packet read times out");
	SETCB ("dbg.consbreak", "false", &cb_consbreak, "sigint handle for attached processes");

	r_config_set_getter (cfg, "dbg.swstep", (RConfigCallback)__dbg_swstep_getter);

// TODO: This should be specified at first by the debug backend when attaching
#if __arm__ || __mips__ || __loongarch__
	SETICB ("dbg.bpsize", 4, &cb_dbgbpsize, "size of software breakpoints");
#else
	SETICB ("dbg.bpsize", 1, &cb_dbgbpsize, "size of software breakpoints");
#endif
	SETBPREF ("dbg.bpsysign", "false", "ignore system breakpoints");
	SETICB ("dbg.btdepth", 128, &cb_dbgbtdepth, "depth of backtrace");


	/* cmd */
	SETCB ("cmd.demangle", "false", &cb_bdc, "run xcrun swift-demangle and similar if available (SLOW)");
	SETICB ("cmd.depth", 10, &cb_cmddepth, "maximum command depth");
	SETPREF ("cmd.bp", "", "run when a breakpoint is hit");
	SETPREF ("cmd.onsyscall", "", "run when a syscall is hit");
	SETICB ("cmd.hitinfo", 1, &cb_debug_hitinfo, "show info when a tracepoint/breakpoint is hit");
	SETPREF ("cmd.stack", "", "command to display the stack in visual debug mode");
	SETPREF ("cmd.cprompt", "", "column visual prompt commands");
	SETPREF ("cmd.gprompt", "", "graph visual prompt commands");
	SETPREF ("cmd.hit", "", "run when a search hit is found");
	SETPREF ("cmd.open", "", "run when file is opened");
	SETPREF ("cmd.load", "", "run when binary is loaded");
	RConfigNode *cmdpdc = NODECB ("cmd.pdc", "", &cb_cmdpdc);
	SETDESC (cmdpdc, "select pseudo-decompiler command to run after pdc");
	update_cmdpdc_options (core, cmdpdc);
	SETCB ("cmd.log", "", &cb_cmdlog, "every time a new T log is added run this command");
	SETPREF ("cmd.prompt", "", "prompt commands");
	SETCB ("cmd.repeat", "false", &cb_cmdrepeat, "empty command an alias for '..' (repeat last command)");
	SETPREF ("cmd.fcn.new", "", "run when new function is analyzed");
	SETPREF ("cmd.fcn.delete", "", "run when a function is deleted");
	SETPREF ("cmd.fcn.rename", "", "run when a function is renamed");
	SETPREF ("cmd.visual", "", "replace current print mode");
	SETPREF ("cmd.vprompt", "", "visual prompt commands");

	SETCB ("cmd.esil.pin", "", &cb_cmd_esil_pin, "command to execute everytime a pin is hit by the program counter");
	SETCB ("cmd.esil.step", "", &cb_cmd_esil_step, "command to run before performing a step in the emulator");
	SETCB ("cmd.esil.stepout", "", &cb_cmd_esil_step_out, "command to run after performing a step in the emulator");
	SETCB ("cmd.esil.mdev", "", &cb_cmd_esil_mdev, "command to run when memory device address is accessed");
	SETCB ("cmd.esil.intr", "", &cb_cmd_esil_intr, "command to run when an esil interrupt happens");
	SETCB ("cmd.esil.trap", "", &cb_cmd_esil_trap, "command to run when an esil trap happens");
	SETCB ("cmd.esil.todo", "", &cb_cmd_esil_todo, "command to run when the esil instruction contains TODO");
	SETCB ("cmd.esil.ioer", "", &cb_cmd_esil_ioer, "command to run when esil fails to IO (invalid read/write)");

	/* filesystem */
	n = NODECB ("fs.view", "normal", &cb_fsview);
	SETDESC (n, "set visibility options for filesystems");
	SETOPTIONS (n, "all", "deleted", "special", NULL);

	/* hexdump */
	SETCB ("hex.header", "true", &cb_hex_header, "show header in hexdump");
	SETCB ("hex.bytes", "true", &cb_hex_bytes, "show bytes column in hexdump");
	SETCB ("hex.ascii", "true", &cb_hex_ascii, "show ascii column in hexdump");
	SETCB ("hex.hdroff", "false", &cb_hex_hdroff, "show aligned 1 byte in header instead of delta nibble");
	SETCB ("hex.style", "false", &cb_hex_style, "improve the hexdump header style");
	SETCB ("hex.pairs", "true", &cb_hex_pairs, "show bytes paired in 'px' hexdump");
	SETCB ("hex.align", "false", &cb_hex_align, "align hexdump with flag + flagsize");
	SETCB ("hex.section", "false", &cb_hex_section, "show section name before the offset");
	SETCB ("hex.compact", "false", &cb_hexcompact, "show smallest 16 byte col hexdump (60 columns)");
	SETCB ("cmd.hexcursor", "", &cb_cmd_hexcursor, "if set and cursor is enabled display given pf format string");
	SETI ("hex.flagsz", 0, "If non zero, overrides the flag size in pxa");
	SETICB ("hex.cols", 16, &cb_hexcols, "number of columns in hexdump");
	SETI ("hex.depth", 5, "maximal level of recurrence while telescoping memory");
	SETBPREF ("hex.onechar", "false", "number of columns in hexdump");
	SETICB ("hex.stride", 0, &cb_hexstride, "line stride in hexdump (default is 0)");
	SETCB ("hex.comments", "true", &cb_hexcomments, "show comments in 'px' hexdump");

	/* http */
	SETBPREF ("http.log", "true", "show HTTP requests processed");
	SETPREF ("http.sync", "", "remote HTTP server to sync events with");
	SETBPREF ("http.colon", "false", "only accept the : command");
	SETPREF ("http.logfile", "", "specify a log file instead of stderr for http requests");
	SETBPREF ("http.cors", "false", "enable CORS");
	SETPREF ("http.referer", "", "csfr protection if set");
	SETBPREF ("http.dirlist", "false", "enable directory listing");
	SETPREF ("http.allow", "", "only accept clients from the comma separated IP list");
#if __WINDOWS__
	r_config_set (cfg, "http.browser", "start");
#else
	if (r_file_exists ("/usr/bin/openURL")) { // iOS ericautils
		r_config_set (cfg, "http.browser", "/usr/bin/openURL");
	} else if (r_file_exists (TERMUX_PREFIX "/bin/termux-open")) {
		r_config_set (cfg, "http.browser", TERMUX_PREFIX "/bin/termux-open");
	} else if (r_file_exists ("/system/bin/toolbox")) {
		r_config_set (cfg, "http.browser",
				"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d");
	} else if (r_file_exists ("/usr/bin/xdg-open")) {
		r_config_set (cfg, "http.browser", "xdg-open");
	} else if (r_file_exists ("/usr/bin/open")) {
		r_config_set (cfg, "http.browser", "open");
	} else {
		r_config_set (cfg, "http.browser", "firefox");
	}
	r_config_desc (cfg, "http.browser", "command to open HTTP URLs");
#endif
	SETI ("http.maxsize", 0, "maximum file size for upload");
	SETPREF ("http.index", "index.html", "main html file to check in directory");
	SETPREF ("http.bind", "localhost", "server address (use 'public' for binding to 0.0.0.0)");
	SETPREF ("http.homeroot", R_JOIN_2_PATHS ("~", R2_HOME_WWWROOT), "http home root directory");
#if __WINDOWS__
	{
		char *wwwroot = r_str_newf ("%s\\share\\www", r_sys_prefix (NULL));
		SETPREF ("http.root", wwwroot, "http root directory");
		free (wwwroot);
	}
#else
	SETPREF ("http.root", R2_WWWROOT, "http root directory");
#endif
	SETPREF ("http.port", "9090", "http server port");
	SETPREF ("http.basepath", "/", "define base path for http requests");
	SETPREF ("http.maxport", "9999", "last HTTP server port");
	SETPREF ("http.ui", "m", "default webui (m, t, f)");
	SETBPREF ("http.sandbox", "true", "sandbox the HTTP server");
	SETI ("http.timeout", 3, "disconnect clients after N seconds of inactivity");
	SETI ("http.dietime", 0, "kill server after N seconds with no client");
	SETBPREF ("http.verbose", "false", "output server logs to stdout");
	SETBPREF ("http.upget", "false", "/up/ answers GET requests, in addition to POST");
	SETBPREF ("http.upload", "false", "enable file uploads to /up/<filename>");
	SETPREF ("http.uri", "", "address of HTTP proxy");
	SETBPREF ("http.auth", "false", "enable/disable HTTP Authentification");
	SETPREF ("http.authtok", "r2admin:r2admin", "http authentification user:password token");
	p = r_sys_getenv ("R2_HTTP_AUTHFILE");
	SETPREF ("http.authfile", r_str_get (p), "http authentification user file");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc (cfg, "http.uproot", "path where files are uploaded");

	/* tcp */
	SETBPREF ("tcp.islocal", "false", "bind a loopback for tcp command server");

	/* graph */
	SETBPREF ("graph.aeab", "false", "show aeab info on each basic block instead of disasm");
	SETI ("graph.zoom", 0, "default zoom value when rendering the graph");
	SETBPREF ("graph.trace", "false", "fold all non-traced basic blocks");
	SETBPREF ("graph.dummy", "true", "create dummy nodes in the graph for better layout (20% slower)");
	SETBPREF ("graph.mini", "false", "render a minigraph next to the graph in braile art");
	SETBPREF ("graph.few", "false", "show few basic blocks in the graph");
	SETBPREF ("graph.comments", "true", "show disasm comments in graph");
	SETBPREF ("graph.cmtright", "false", "show comments at right");
	SETCB ("graph.gv.format", "gif", &cb_graphformat, "graph image extension when using 'w' format (png, jpg, pdf, ps, svg, json)");
	SETBPREF ("graph.refs", "false", "hraph references in callgraphs (.agc*;aggi)");
	SETBPREF ("graph.json.usenames", "true", "use names instead of addresses in Global Call Graph (agCj)");
	SETI ("graph.edges", 2, "0=no edges, 1=simple edges, 2=avoid collisions");
	SETI ("graph.layout", 0, "graph layout (0=vertical, 1=horizontal)");
	SETI ("graph.linemode", 1, "graph edges (0=diagonal, 1=square)");
	SETPREF ("graph.font", "Courier", "Font for dot graphs");
	SETBPREF ("graph.offset", "false", "show offsets in graphs");
	SETBPREF ("graph.bytes", "false", "show opcode bytes in graphs");
	SETBPREF ("graph.web", "false", "display graph in web browser (VV)");
	SETI ("graph.from", UT64_MAX, "lower bound address when drawing global graphs");
	SETI ("graph.to", UT64_MAX, "upper bound address when drawing global graphs");
	SETI ("graph.scroll", 5, "scroll speed in ascii-art graph");
	SETBPREF ("graph.invscroll", "false", "invert scroll direction in ascii-art graph");
	SETPREF ("graph.title", "", "title of the graph");
	SETBPREF ("graph.body", "true", "show body of the nodes in the graph");
	SETBPREF ("graph.bubble", "false", "show nodes as bubbles");
	SETBPREF ("graph.ntitles", "true", "display title of node");
	SETPREF ("graph.gv.node", "", "graphviz node style. (color=gray, style=filled shape=box)");
	SETPREF ("graph.gv.edge", "", "graphviz edge style. (arrowhead=\"vee\")");
	SETPREF ("graph.gv.spline", "", "graphviz spline style. (splines=\"ortho\")");
	SETPREF ("graph.gv.graph", "", "graphviz global style attributes. (bgcolor=white)");
	SETPREF ("graph.gv.current", "false", "highlight the current node in graphviz graph.");
	SETBPREF ("graph.nodejmps", "true", "enables shortcuts for every node.");
	SETBPREF ("graph.hints", "true", "show true (t) and false (f) hints for conditional edges in graph");
	SETCB ("graph.dotted", "false", &cb_dotted, "dotted lines for conditional jumps in graph");

	/* hud */
	SETPREF ("hud.path", "", "set a custom path for the HUD file");

	SETCB ("esil.exectrap", "false", &cb_exectrap, "trap when executing code in non-executable memory");
	SETCB ("esil.iotrap", "true", &cb_iotrap, "invalid read or writes produce a trap exception");
	SETBPREF ("esil.romem", "false", "set memory as read-only for ESIL");
	SETBPREF ("esil.stats", "false", "statistics from ESIL emulation stored in sdb");
	SETBPREF ("esil.nonull", "false", "prevent memory read, memory write at null pointer");
	SETCB ("esil.mdev.range", "", &cb_mdevrange, "specify a range of memory to be handled by cmd.esil.mdev");

	/* json encodings */
	n = NODECB ("cfg.json.str", "none", &cb_jsonencoding);
	SETDESC (n, "encode strings from json outputs using the specified option");
	SETOPTIONS (n, "none", "base64", "strip", "hex", "array", NULL);

	n = NODECB ("cfg.json.num", "none", &cb_jsonencoding_numbers);
	SETDESC (n, "encode numbers from json outputs using the specified option");
	SETOPTIONS (n, "none", "string", "hex", NULL);


	/* scr */
#if __EMSCRIPTEN__ || __wasi__
	r_config_set_cb (cfg, "scr.fgets", "true", cb_scrfgets);
#else
	r_config_set_cb (cfg, "scr.fgets", "false", cb_scrfgets);
#endif
	r_config_desc (cfg, "scr.fgets", "use fgets() instead of dietline for prompt input");
	SETCB ("scr.echo", "false", &cb_screcho, "show rcons output in realtime to stderr and buffer");
	SETPREF ("scr.loopnl", "false", "add a newline after every command executed in @@ loops");
	SETICB ("scr.linesleep", 0, &cb_scrlinesleep, "flush sleeping some ms in every line");
	SETICB ("scr.maxtab", 4096, &cb_completion_maxtab, "change max number of auto completion suggestions");
	SETICB ("scr.maxpage", 102400, &cb_scr_maxpage, "change max chars to print before prompting the user");
	SETICB ("scr.pagesize", 1, &cb_scrpagesize, "flush in pages when scr.linesleep is != 0");
	SETCB ("scr.flush", "false", &cb_scrflush, "force flush to console in realtime (breaks scripting)");
	SETBPREF ("scr.slow", "true", "do slow stuff on visual mode like RFlag.get_at(true)");
#if __WINDOWS__
	SETICB ("scr.vtmode", r_cons_singleton ()->vtmode,
		&scr_vtmode, "use VT sequences on Windows (0: Disable, 1: Output, 2: Input & Output)");
#else
	SETI ("scr.vtmode", 0, "windows specific configuration that have no effect on other OSs");
#endif
#if __ANDROID__
	// SETBPREF ("scr.responsive", "true", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETI ("scr.wheel.speed", 1, "mouse wheel speed");
#else
	SETI ("scr.wheel.speed", 4, "mouse wheel speed");
#endif
	SETBPREF ("scr.responsive", "false", "auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
	SETBPREF ("scr.wheel.nkey", "false", "use sn/sp and scr.nkey on wheel instead of scroll");
	// RENAME TO scr.mouse
	SETBPREF ("scr.wheel", "true", "mouse wheel in Visual; temporaryly disable/reenable by right click/Enter)");
	SETBPREF ("scr.cursor", "false", "keyboard controlled cursor in visual and panels");
	SETPREF ("scr.layout", "", "name of the selected panels layout to load as default");
	// DEPRECATED: USES hex.cols now SETI ("scr.colpos", 80, "Column position of cmd.cprompt in visual");
	SETCB ("scr.breakword", "", &cb_scrbreakword, "emulate console break (^C) when a word is printed (useful for pD)");
	SETCB ("scr.breaklines", "false", &cb_breaklines, "break lines in Visual instead of truncating them");
	SETCB ("scr.gadgets", "true", &cb_scr_gadgets, "run pg in prompt, visual and panels");
	SETBPREF ("scr.panelborder", "false", "specify panels border active area (0 by default)");
	SETCB ("scr.theme", "default", &cb_scrtheme, "specify the theme name to load on startup (See 'ec?')");
	SETICB ("scr.columns", 0, &cb_scrcolumns, "force console column count (width)");
	SETICB ("scr.optimize", 0, &cb_scroptimize, "optimize the amount of ansi escapes and spaces (0, 1, 2 passes)");
	SETBPREF ("scr.dumpcols", "false", "prefer pC commands before p ones");
	SETCB ("scr.rows", "0", &cb_scrrows, "force console row count (height) ");
	SETI ("scr.notch", 0, "force console row count (height) (duplicate?)");
	SETICB ("scr.rows", 0, &cb_rows, "force console row count (height) (duplicate?)");
	SETCB ("scr.fps", "false", &cb_fps, "show FPS in Visual");
	SETICB ("scr.fix.rows", 0, &cb_fixrows, "Workaround for Linux TTY");
	SETICB ("scr.fix.columns", 0, &cb_fixcolumns, "workaround for Prompt iOS SSH client");
	SETCB ("scr.highlight", "", &cb_scrhighlight, "highlight that word at RCons level");
	SETCB ("scr.interactive", "true", &cb_scrint, "start in interactive mode");
	SETCB ("scr.bgfill", "false", &cb_scr_bgfill, "fill background for ascii art when possible");
	SETI ("scr.feedback", 1, "set visual feedback level (1=arrow on jump, 2=every key (useful for videos))");
	SETCB ("scr.html", "false", &cb_scrhtml, "disassembly uses HTML syntax");
	n = NODECB ("scr.nkey", "flag", &cb_scrnkey);
	SETDESC (n, "select visual seek mode (affects n/N visual commands)");
	SETOPTIONS (n, "fun", "hit", "flag", NULL);
	SETCB ("scr.pager", "", &cb_pager, "system program (or '..') to use when output exceeds screen boundaries");
	SETI ("scr.scrollbar", 0, "show flagzone (fz) scrollbar in visual mode (0=no,1=right,2=top,3=bottom)");
	SETBPREF ("scr.randpal", "false", "random color palete or just get the next one from 'eco'");
	SETCB ("scr.highlight.grep", "false", &cb_scr_color_grep_highlight, "highlight (INVERT) the grepped words");
	SETCB ("scr.prompt.popup", "false", &cb_scr_prompt_popup, "show widget dropdown for autocomplete");
	SETCB ("scr.prompt.vi", "false", &cb_scr_vi, "use vi mode for input prompt");
	SETPREF ("scr.prompt.tabhelp", "true", "show command help when pressing the TAB key");
	SETCB ("scr.prompt.mode", "false", &cb_scr_prompt_mode,  "set prompt color based on vi mode");
	SETBPREF ("scr.prompt.file", "false", "show user prompt file (used by r2 -q)");
	SETBPREF ("scr.prompt.flag", "false", "show flag name in the prompt");
	SETBPREF ("scr.prompt.sect", "false", "show section name in the prompt");
	SETBPREF ("scr.tts", "false", "use tts if available by a command (see ic)");
	SETCB ("scr.prompt", "true", &cb_scrprompt, "show user prompt (used by r2 -q)");
	SETCB ("scr.tee", "", &cb_teefile, "pipe output to file of this name");
	SETPREF ("scr.seek", "", "seek to the specified address on startup");
	SETICB ("scr.color", (core->print->flags&R_PRINT_FLAGS_COLOR)?COLOR_MODE_16:COLOR_MODE_DISABLED, &cb_color, "enable colors (0: none, 1: ansi, 2: 256 colors, 3: truecolor)");
	r_config_set_getter (cfg, "scr.color", (RConfigCallback)cb_color_getter);
	SETCB ("scr.color.grep", "false", &cb_scr_color_grep, "enable colors when using ~grep");
	SETBPREF ("scr.color.pipe", "false", "enable colors when using pipes");
	SETBPREF ("scr.color.ops", "true", "colorize numbers and registers in opcodes");
	SETCB ("scr.color.ophex", "false", &cb_scr_color_ophex, "colorize in hexdump depending on opcode type (px)");
	SETBPREF ("scr.color.args", "true", "colorize arguments and variables of functions");
	SETBPREF ("scr.color.bytes", "true", "colorize bytes that represent the opcodes of the instruction");
	SETCB ("scr.null", "false", &cb_scrnull, "show no output");
	SETCB ("scr.errmode", "echo", &cb_screrrmode, "error string handling");
	SETCB ("scr.utf8", r_str_bool (r_cons_is_utf8()), &cb_utf8, "show UTF-8 characters instead of ANSI");
	SETCB ("scr.utf8.curvy", "false", &cb_utf8_curvy, "show curved UTF-8 corners (requires scr.utf8)");
	SETCB ("scr.demo", "false", &cb_scr_demo, "use demoscene effects if available");
	SETCB ("scr.hist.block", "true", &cb_scr_histblock, "use blocks for histogram");
	SETCB ("scr.hist.filter", "true", &cb_scr_histfilter, "filter history for matching lines when using up/down keys");
	SETBPREF ("scr.hist.save", "true", "always save history on exit");
	n = NODECB ("scr.strconv", "asciiesc", &cb_scrstrconv);
	SETDESC (n, "convert string before display");
	SETOPTIONS (n, "asciiesc", "asciidot", NULL);
	SETBPREF ("scr.confirmquit", "false", "Confirm on quit");
	SETBPREF ("scr.progressbar", "false", "display a progress bar when running scripts.");

	/* str */
	SETCB ("str.escbslash", "false", &cb_str_escbslash, "escape the backslash");

	/* search */
	SETCB ("search.contiguous", "true", &cb_contiguous, "accept contiguous/adjacent search hits");
	SETBPREF ("search.verbose", "true", "make the output of search commands verbose");
	SETICB ("search.align", 0, &cb_searchalign, "only catch aligned search hits");
	SETI ("search.chunk", 0, "chunk size for /+ (default size is asm.bits/8");
	SETI ("search.esilcombo", 8, "stop search after N consecutive hits");
	SETI ("search.distance", 0, "search string distance");
	SETBPREF ("search.flags", "true", "all search results are flagged, otherwise only printed");
	SETBPREF ("search.overlap", "false", "look for overlapped search hits");
	SETI ("search.maxhits", 0, "maximum number of hits (0: no limit)");
	SETI ("search.from", -1, "search start address");
	n = NODECB ("search.in", "io.maps", &cb_searchin);
	SETDESC (n, "specify search boundaries");
	SETOPTIONS (n, "raw", "flag", "block",
		"bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"anal.fcn", "anal.bb",
	NULL);
	SETICB ("search.kwidx", 0, &cb_search_kwidx, "store last search index count");
	SETPREF ("search.prefix", "hit", "prefix name in search hits label");
	SETBPREF ("search.show", "true", "show search results");
	SETI ("search.to", -1, "search end address");

	/* rop */
	SETI ("rop.len", 5, "maximum ROP gadget length");
	SETBPREF ("rop.sdb", "false", "cache results in sdb (experimental)");
	SETBPREF ("rop.db", "true", "categorize rop gadgets in sdb");
	SETBPREF ("rop.subchains", "false", "display every length gadget from rop.len=X to 2 in /Rl");
	SETBPREF ("rop.conditional", "false", "include conditional jump, calls and returns in ropsearch");
	SETBPREF ("rop.comments", "false", "display comments in rop search output");

	/* io */
	SETCB ("io.cache", "false", &cb_io_cache, "change both of io.cache.{read,write}");
	SETCB ("io.cache.auto", "false", &cb_io_cache_mode, "automatic cache all reads in the IO backend");
	SETCB ("io.cache.read", "false", &cb_io_cache_read, "enable read cache for vaddr (or paddr when io.va=0)");
	SETCB ("io.cache.nodup", "false", &cb_io_cache_nodup, "do not cache duplicated cache writes");
	SETCB ("io.cache.write", "false", &cb_io_cache_write, "enable write cache for vaddr (or paddr when io.va=0)");
	SETCB ("io.pcache", "false", &cb_iopcache, "io.cache for p-level");
	SETCB ("io.pcache.write", "false", &cb_iopcachewrite, "enable write-cache");
	SETCB ("io.pcache.read", "false", &cb_iopcacheread, "enable read-cache");
	SETCB ("io.ff", "true", &cb_ioff, "fill invalid buffers with 0xff instead of returning error");
	SETICB ("io.mask", 0, &cb_iomask, "mask addresses before resolving as maps");
	SETBPREF ("io.exec", "true", "see !!r2 -h~-x");
	SETICB ("io.0xff", 0xff, &cb_io_oxff, "use this value instead of 0xff to fill unallocated areas");
	SETCB ("io.aslr", "false", &cb_ioaslr, "disable ASLR for spawn and such");
	SETCB ("io.va", "true", &cb_iova, "use virtual address layout");
	SETCB ("io.pava", "false", &cb_io_pava, "use EXPERIMENTAL paddr -> vaddr address mode");
	SETCB ("io.autofd", "true", &cb_ioautofd, "change fd when opening a new file");
	SETCB ("io.unalloc", "false", &cb_io_unalloc, "check each byte if it's allocated");
	SETCB ("io.unalloc.ch", ".", &cb_io_unalloc_ch, "char to display if byte is unallocated");

	/* file */
	SETBPREF ("file.info", "true", "RBin info loaded");
	SETPREF ("file.offset", "", "offset where the file will be mapped at");
	SETPREF ("file.type", "", "type of current file");
	SETI ("file.loadalign", 1024, "alignment of load addresses");
	/* magic */
	SETI ("magic.depth", 100, "recursivity depth in magic description strings");

	/* rap */
	SETBPREF ("rap.loop", "true", "run rap as a forever-listening daemon (=:9090)");

	/* nkeys */
	SETPREF ("key.s", "", "override step into action");
	SETPREF ("key.S", "", "override step over action");
	for (i = 1; i < 13; i++) {
		snprintf (buf, sizeof (buf), "key.f%d", i);
		snprintf (buf + 10, sizeof (buf) - 10,
				"run this when F%d key is pressed in visual mode", i);
		switch (i) {
			default: p = ""; break;
		}
		r_config_set (cfg, buf, p);
		r_config_desc (cfg, buf, buf+10);
	}

	/* zoom */
	SETCB ("zoom.byte", "h", &cb_zoombyte, "zoom callback to calculate each byte (See pz? for help)");
	SETI ("zoom.from", 0, "zoom start address");
	SETI ("zoom.maxsz", 512, "zoom max size of block");
	SETI ("zoom.to", 0, "zoom end address");
	n = NODECB ("zoom.in", "io.map", &cb_searchin);
	SETDESC (n, "specify boundaries for zoom");
	SETOPTIONS (n, "raw", "block",
		"bin.section", "bin.sections", "bin.sections.rwx", "bin.sections.r", "bin.sections.rw", "bin.sections.rx", "bin.sections.wx", "bin.sections.x",
		"io.map", "io.maps", "io.maps.rwx", "io.maps.r", "io.maps.rw", "io.maps.rx", "io.maps.wx", "io.maps.x",
		"dbg.stack", "dbg.heap",
		"dbg.map", "dbg.maps", "dbg.maps.rwx", "dbg.maps.r", "dbg.maps.rw", "dbg.maps.rx", "dbg.maps.wx", "dbg.maps.x",
		"anal.fcn", "anal.bb",
	NULL);
	/* lines */
	SETI ("lines.from", 0, "start address for line seek");
	SETCB ("lines.to", "$s", &cb_linesto, "end address for line seek");
	SETCB ("lines.abs", "false", &cb_linesabs, "enable absolute line numbers");
	/* RVC */
	{
		char *p = r_file_path ("git");
		SETPREF ("prj.vc.message", "", "default commit message for rvc/git");
		if (strcmp (p, "git")) {
			SETCB ("prj.vc.type", "git", &cb_prjvctype, "what should projects use as a vc");
		} else {
			SETBPREF ("prj.vc", "false", "use your version control system of choice (rvc, git) to manage projects");
			/*The follwing is just a place holder*/
			SETCB ("prj.vc.type", "rvc", &cb_prjvctype, "what should projects use as a vc");
		}
		free (p);
	}
	r_config_lock (cfg, true);
	return true;
}

R_API void r_core_parse_radare2rc(RCore *r) {
	bool has_debug = r_sys_getenv_asbool ("R2_DEBUG");
	char *rcfile = r_sys_getenv ("R2_RCFILE");
	char *homerc = NULL;
	if (!R_STR_ISEMPTY (rcfile)) {
		homerc = rcfile;
	} else {
		free (rcfile);
		homerc = r_str_home (".radare2rc");
	}
	if (homerc && r_file_is_regular (homerc)) {
		if (has_debug) {
			eprintf ("USER CONFIG loaded from %s\n", homerc);
		}
		r_core_cmd_file (r, homerc);
	}
	free (homerc);
	homerc = r_str_home (R2_HOME_RC);
	if (homerc && r_file_is_regular (homerc)) {
		if (has_debug) {
			eprintf ("USER CONFIG loaded from %s\n", homerc);
		}
		r_core_cmd_file (r, homerc);
	}
	free (homerc);
	homerc = r_str_home (R2_HOME_RC_DIR);
	if (homerc) {
		if (r_file_is_directory (homerc)) {
			char *file;
			RListIter *iter;
			RList *files = r_sys_dir (homerc);
			r_list_foreach (files, iter, file) {
				if (*file != '.') {
					char *path = r_str_newf ("%s/%s", homerc, file);
					if (r_file_is_regular (path)) {
						if (has_debug) {
							eprintf ("USER CONFIG loaded from %s\n", homerc);
						}
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
