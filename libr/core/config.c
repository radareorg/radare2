/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <r_core.h>

#define SETI(x,y,z) r_config_node_desc(r_config_set_i(cfg,x,y), z);
#define SETICB(w,x,y,z) r_config_node_desc(r_config_set_i_cb(cfg,w,x,y), z);
#define SETPREF(x,y,z) r_config_node_desc(r_config_set(cfg,x,y), z);
#define SETCB(w,x,y,z) r_config_node_desc(r_config_set_cb(cfg,w,x,y), z);
#if LIL_ENDIAN
#define CFG_BIGENDIAN "false"
#else
#define CFG_BIGENDIAN "true"
#endif

static const char *has_esil(RCore *core, const char *name) {
	RListIter *iter;
	RAnalPlugin *h;
	RAnal *a = core->anal;
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (name, h->name)) {
			if (h->esil)
				return "Ae";
			return "A_";
		}
	}
	return "__";
}

// copypasta from binr/rasm2/rasm2.c
static void rasm2_list(RCore *core, const char *arch) {
	int i;
	const char *feat2, *feat;
	RAsm *a = core->assembler;
	char bits[32];
	RAsmPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h) {
		if (arch && *arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i=0;i<n;i++)
					r_cons_printf ("%s\n",
						r_str_word_get0 (c, i));
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			/* The underscore makes it easier to distinguish the
			 * columns */
			if (h->bits&8) strcat (bits, "_8");
			if (h->bits&16) strcat (bits, "_16");
			if (h->bits&32) strcat (bits, "_32");
			if (h->bits&64) strcat (bits, "_64");
			if (!*bits) strcat (bits, "_0");
			feat = "__";
			if (h->assemble && h->disassemble)  feat = "ad";
			if (h->assemble && !h->disassemble) feat = "a_";
			if (!h->assemble && h->disassemble) feat = "_d";
			feat2 = has_esil (core, h->name);
			r_cons_printf ("%s%s  %-9s  %-11s %-7s %s\n",
				feat, feat2, bits, h->name,
				h->license?h->license:"unknown", h->desc);
		}
	}
}

static inline void __setsegoff(RConfig *cfg, const char *asmarch, int asmbits) {
	if (!strcmp (asmarch, "x86"))
		r_config_set (cfg, "asm.segoff", (asmbits==16)?"true":"false");
}

static int cb_analeobjmp(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->eobjmp = node->i_value;
	return R_TRUE;
}

static int cb_analafterjmp(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->afterjmp = node->i_value;
	return R_TRUE;
}

static int cb_analsleep(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->sleep = node->i_value;
	return R_TRUE;
}

static int cb_analmaxrefs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->maxreflines = node->i_value;
	return R_TRUE;
}

static int cb_analnopskip (void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->nopskip = node->i_value;
	return R_TRUE;
}

static int cb_analbbsplit (void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->bbsplit = node->i_value;
	return R_TRUE;
}

static int cb_analarch(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_anal_list (core->anal);
		return R_FALSE;
	} else {
		if (*node->value) {
			if (!r_anal_use (core->anal, node->value)) {
				const char *aa = r_config_get (core->config, "asm.arch");
				if (!aa || strcmp (aa, node->value)) {
					eprintf ("anal.arch: cannot find '%s'\n", node->value);
				}
				return R_FALSE;
			}
		} else return R_FALSE;
	}
	return R_TRUE;
}

static int cb_analcpu(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_anal_set_cpu (core->anal, node->value);
	return R_TRUE;
}

static int cb_analsplit(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->split = node->i_value;
	return R_TRUE;
}

static int cb_analrecont(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->anal->recont = node->i_value;
	return R_TRUE;
}

static int cb_asmarch(void *user, void *data) {
	char asmparser[32];
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	const char *asmos = r_config_get (core->config, "asm.os");

	if (*node->value=='?') {
		rasm2_list (core, NULL);
		return R_FALSE;
	}
	r_egg_setup (core->egg, node->value, core->anal->bits, 0, R_SYS_OS);
	if (*node->value) {
		if (!r_asm_use (core->assembler, node->value)) {
			eprintf ("asm.arch: cannot find (%s)\n", node->value);
			return R_FALSE;
		}
	} else return R_FALSE;

	snprintf (asmparser, sizeof (asmparser), "%s.pseudo", node->value);
	r_config_set (core->config, "asm.parser", asmparser);
	if (!(core->assembler->cur->bits & core->anal->bits)) {
		int bits = core->assembler->cur->bits;
		if (8&bits) bits = 8;
		else if (16&bits) bits=16;
		else if (32&bits) bits=32;
		else bits=64;
		r_config_set_i (core->config, "asm.bits", bits);
	}
	if (!r_config_set (core->config, "anal.arch", node->value)) {
		char *p, *s = strdup (node->value);
		p = strchr (s, '.');
		if (p) *p = 0;
		if (!r_config_set (core->config, "anal.arch", s)) {
			/* fall back to the anal.null plugin */
			r_config_set (core->config, "anal.arch", "null");
		}
		free (s);
	}
	if (!r_syscall_setup (core->anal->syscall, node->value,
				asmos, core->anal->bits)) {
		//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
		//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
	}
	//if (!strcmp (node->value, "bf"))
	//	r_config_set (core->config, "dbg.backend", "bf");
	__setsegoff (core->config, node->value, core->assembler->bits);
	return R_TRUE;
}

static int cb_dbgbpsize(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->bpsize = node->i_value;
	return R_TRUE;
}

static int cb_asmbits(void *user, void *data) {
	const char *asmos, *asmarch;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	int ret;
	if (!core) {
		eprintf ("user can't be NULL\n");
		return R_FALSE;
	}

	ret = r_asm_set_bits (core->assembler, node->i_value);
	if (ret == R_FALSE) {
		RAsmPlugin *h = core->assembler->cur;
		if (h) {
			eprintf ("Cannot set bits %"PFMT64d" to '%s'\n",
					node->i_value, h->name);
		} else {
			eprintf ("e asm.bits: Cannot set value, no plugins defined yet\n");
			ret = R_TRUE;
		}
	}
	if (!r_anal_set_bits (core->anal, node->i_value)) {
		eprintf ("asm.arch: Cannot setup '%i' bits analysis engine\n", (int)node->i_value);
	}
	core->print->bits = node->i_value;
	if (core->dbg  && core->anal && core->anal->cur) {
		int load_from_debug = 0;
		r_debug_set_arch (core->dbg, core->anal->cur->arch, node->i_value);
		if (r_config_get_i (core->config, "cfg.debug")) {
			if (core->dbg->h && core->dbg->h->reg_profile) {
				char *rp = core->dbg->h->reg_profile (core->dbg);
				r_reg_set_profile_string (core->dbg->reg, rp);
				r_reg_set_profile_string (core->anal->reg, rp);
				free (rp);
			} else {
				load_from_debug = 1;
			}
		} else {
			if (core->anal->cur->set_reg_profile) {
				core->anal->cur->set_reg_profile (core->anal);
			} else {
				load_from_debug = 1;
			}
		}
		if (load_from_debug) {
			if (core->dbg->h && core->dbg->h->reg_profile) {
				char *rp = core->dbg->h->reg_profile (core->dbg);
				r_reg_set_profile_string (core->dbg->reg, rp);
				r_reg_set_profile_string (core->anal->reg, rp);
				free (rp);
			}
		}
	}

	asmos = r_config_get (core->config, "asm.os");
	asmarch = r_config_get (core->config, "asm.arch");
	if (core->anal) {
		if (!r_syscall_setup (core->anal->syscall, asmarch,
					asmos, node->i_value)) {
			//eprintf ("asm.arch: Cannot setup syscall '%s/%s' from '%s'\n",
			//	node->value, asmos, R2_LIBDIR"/radare2/"R2_VERSION"/syscall");
		}
		__setsegoff (core->config, asmarch, core->anal->bits);
	}
	return ret;
}

static int cb_asmfeatures(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	if (*node->value == '?') {
		if (core && core->assembler && core->assembler->cur) {
			if (core->assembler->cur->features) {
				char *feat = strdup (core->assembler->cur->features);
				r_str_replace_char (feat, ',','\n');
				r_cons_printf ("%s\n", feat);
				free (feat);
			}
		}
		return 0;
	}

	free (core->assembler->features);
	core->assembler->features = NULL;

	if (node->value[0])
		core->assembler->features = strdup (node->value);

	return 1;
}

static int cb_asmcpu(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value=='?') {
		rasm2_list (core, r_config_get (core->config, "asm.arch"));
		return 0;
	}
	r_asm_set_cpu (core->assembler, node->value);
	r_config_set (core->config, "anal.cpu", node->value);
	return R_TRUE;
}

static int cb_asmlineswidth(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->anal->lineswidth = node->i_value;
	return R_TRUE;
}

static int cb_asmos(void *user, void *data) {
	RCore *core = (RCore*) user;
	int asmbits = r_config_get_i (core->config, "asm.bits");
	RConfigNode *asmarch, *node = (RConfigNode*) data;

	if (*node->value=='?') {
		r_cons_printf ("dos\ndarwin\nlinux\nfreebsd\nopenbsd\nnetbsd\nwindows\n");
		return 0;
	}
	asmarch = r_config_node_get (core->config, "asm.arch");
	if (asmarch) {
		r_syscall_setup (core->anal->syscall, asmarch->value,
				node->value, core->anal->bits);
		__setsegoff (core->config, asmarch->value, asmbits);
	}
	//if (!ret) eprintf ("asm.os: Cannot setup syscall os/arch for '%s'\n", node->value);
	return R_TRUE;
}

static int cb_asmparser(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX this is wrong? snprintf(buf, 127, "parse_%s", node->value),
	return r_parse_use (core->parser, node->value);
	// TODO: control error and restore old value (return false?) show errormsg?
	//return R_TRUE;
}

static int cb_binforce(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	r_bin_force_plugin (core->bin, node->value);
	return R_TRUE;
}

static int cb_asmsyntax(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_cons_printf ("att\nintel\njz\nregnum\n");
		return R_FALSE;
	} else if (!strcmp (node->value, "regnum")) {
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_REGNUM);
	} else if (!strcmp (node->value, "jz")) {
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_JZ);
	} else if (!strcmp (node->value, "intel")) {
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_INTEL);
	} else if (!strcmp (node->value, "att")) {
		r_asm_set_syntax (core->assembler, R_ASM_SYNTAX_ATT);
	} else return R_FALSE;
	return R_TRUE;
}

static int cb_bigendian(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->assembler->big_endian = node->i_value;
	core->anal->big_endian = node->i_value;
	core->anal->reg->big_endian = node->i_value;
	core->print->big_endian = node->i_value;
	return R_TRUE;
}

static int cb_cfgdatefmt(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	snprintf (core->print->datefmt, 32, "%s", node->value);
	return R_TRUE;
}

static int cb_timezone(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->print->datezone = node->i_value;
	return R_TRUE;
}

static int cb_cfgdebug(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (!core) return R_FALSE;
	if (core->io)
		core->io->debug = node->i_value;
	if (core->dbg && node->i_value) {
		const char *dbgbackend = r_config_get (core->config, "dbg.backend");
		core->bin->is_debugger = R_TRUE;
		r_debug_use (core->dbg, dbgbackend);
		if (!strcmp (dbgbackend, "bf"))
			r_config_set (core->config, "asm.arch", "bf");
		if (core->file) {
			r_debug_select (core->dbg, core->file->desc->fd,
					core->file->desc->fd);
		}
	} else {
		if (core->dbg) r_debug_use (core->dbg, NULL);
		core->bin->is_debugger = R_FALSE;
	}
	r_config_set (core->config, "io.raw", "true");
	return R_TRUE;
}

static int cb_cfgsanbox(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	int ret = r_sandbox_enable (node->i_value);
	if (node->i_value != ret)
		eprintf ("Cannot disable sandbox\n");
	return (!node->i_value && ret)? 0: 1;
}

static int cb_cmdrepeat(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cmdrepeat = node->i_value;
	return R_TRUE;
}

static int cb_scrnull(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->cons->null = node->i_value;
	return R_TRUE;
}

static int cb_color(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		core->print->flags |= R_PRINT_FLAGS_COLOR;
	} else {
		//c:core->print->flags ^= R_PRINT_FLAGS_COLOR;
		core->print->flags &= (~R_PRINT_FLAGS_COLOR);
	}
	r_print_set_flags (core->print, core->print->flags);
	return R_TRUE;
}

static int cb_dbgbep(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (*node->value == '?') {
		r_cons_printf ("loader\nentry\nconstructor\nmain\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int cb_dbg_forks(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_forks = node->i_value;
	r_debug_attach (core->dbg, core->dbg->pid);
	return R_TRUE;
}

static int cb_dbg_execs(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_execs = node->i_value;
	r_debug_attach (core->dbg, core->dbg->pid);
	return R_TRUE;
}

static int cb_dbg_clone(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	core->dbg->trace_clone = node->i_value;
	r_debug_attach (core->dbg, core->dbg->pid);
	return R_TRUE;
}

static int cb_runprofile(void *user, void *data) {
	RCore *r = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	free ((void*)r->io->runprofile);
	if (!node || !*(node->value))
		r->io->runprofile = NULL;
	else r->io->runprofile = strdup (node->value);
	return R_TRUE;
}

static int cb_dbgstatus(void *user, void *data) {
	RCore *r = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	if (r_config_get_i (r->config, "cfg.debug")) {
		if (node->i_value)
			r_config_set (r->config, "cmd.prompt",
				".dr* ; drd ; sr pc;pi 1;s-");
		else r_config_set (r->config, "cmd.prompt", ".dr*");
	}
	return R_TRUE;
}

static int cb_dbgbackend(void *user, void *data) {
	RCore *core = (RCore*) user;
	RConfigNode *node = (RConfigNode*) data;
	// XXX: remove this spagetti
	if (!strcmp (node->value, "bf"))
		r_config_set (core->config, "asm.arch", "bf");
	r_debug_use (core->dbg, node->value);
	return R_TRUE;
}

static int cb_gotolimit(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot change gotolimit\n");
		return R_FALSE;
	}
	if (core->anal->esil)
		core->anal->esil_goto_limit = node->i_value;
	return R_TRUE;
}

static int cb_esildebug (void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (core->anal->esil)
		core->anal->esil->debug = node->i_value;
	return R_TRUE;
}

static int cb_fixrows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_rows = node->i_value;
	return R_TRUE;
}

static int cb_fixcolumns(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fix_columns = node->i_value;
	return R_TRUE;
}

static int cb_rows(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->force_rows = node->i_value;
	return R_TRUE;
}

static int cb_hexpairs(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->print->pairs = node->i_value;
	return R_TRUE;
}

static int cb_fsview(void *user, void *data) {
	int type = R_FS_VIEW_NORMAL;
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (*node->value == '?') {
		eprintf ("Values: all|deleted|special\n");
		return R_FALSE;
	}
	if (!strcmp (node->value, "all"))
		type = R_FS_VIEW_ALL;
	if (!strstr (node->value, "del"))
		type |= R_FS_VIEW_DELETED;
	if (!strstr (node->value, "spe"))
		type |= R_FS_VIEW_SPECIAL;
	r_fs_view (core->fs, type);
	return R_TRUE;
}

static int cb_cmddepth(void *user, void *data) {
	int c = R_MAX (((RConfigNode*)data)->i_value, 0);
	((RCore *)user)->cmd_depth = c;
	return R_TRUE;
}

static int cb_hexcols(void *user, void *data) {
	int c = R_MIN (128, R_MAX (((RConfigNode*)data)->i_value, 0));
	((RCore *)user)->print->cols = c & ~1;
	return R_TRUE;
}

static int cb_hexstride(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	((RCore *)user)->print->stride = node->i_value;
	return R_TRUE;
}

static int cb_search_kwidx(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->n_kws = node->i_value;
	return R_TRUE;
}

static int cb_ioenforce(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	int perm = node->i_value;
	core->io->enforce_rwx = 0;
	if (perm & 1) core->io->enforce_rwx |= R_IO_READ;
	if (perm & 2) core->io->enforce_rwx |= R_IO_WRITE;
	return R_TRUE;
}

static int cb_iosectonly(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->sectonly = node->i_value? 1: 0;
	return R_TRUE;
}

static int cb_iobuffer(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value) {
		ut64 from, to;
		from = r_config_get_i (core->config, "io.buffer.from");
		to = r_config_get_i (core->config, "io.buffer.to");
		if (from>=to) {
			eprintf ("ERROR: io.buffer.from >= io.buffer.to"
					" (0x%"PFMT64x" >= 0x%"PFMT64x")\n", from, to);
		} else r_io_buffer_load (core->io, from, (int)(to-from));
	} else r_io_buffer_close (core->io);
	r_core_block_read (core, 0);
	return R_TRUE;
}

static int cb_iocache(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_io_cache_enable (core->io, node->i_value, node->i_value);
	return R_TRUE;
}

static int cb_iova(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value != core->io->va) {
		core->io->va = node->i_value;
		if (r_io_desc_get (core->io, core->io->raised))			//ugly fix for r2 -d ... "r2 is going to die soon ..."
			r_core_block_read (core, 0);
		// reload symbol information
		if (r_list_length (r_bin_get_sections (core->bin))>0)
			r_core_cmd0 (core, ".ia*");
	}
	return R_TRUE;
}

static int cb_iozeromap(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->zeromap = node->i_value;
	return R_TRUE;
}

static int cb_ioraw(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	r_io_set_raw (core->io, node->i_value);
	return R_TRUE;
}

static int cb_ioff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->ff = node->i_value;
	return R_TRUE;
}

static int cb_ioautofd(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->autofd = node->i_value;
	return R_TRUE;
}

static int cb_iovio(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->io->vio = node->i_value;
	return R_TRUE;
}

static int cb_pager(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;

	/* Let cons know we have a new pager. */
	core->cons->pager = node->value;
	return R_TRUE;
}

static int cb_fps(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->fps = node->i_value;
	return R_TRUE;
}

static int cb_rgbcolors(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	RCore *core = (RCore *) user;
	if (node->i_value) {
		r_cons_singleton()->truecolor =
			(r_config_get_i (core->config, "scr.truecolor"))?2:1;
	} else {
		r_cons_singleton()->truecolor = 0;
	}
	return R_TRUE;
}

static int cb_scrcolumns(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_columns = n;
	return R_TRUE;
}

static int cb_scrfgets(void* user, void* data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode*) data;
	if (node->i_value)
		core->cons->user_fgets = NULL;
	else core->cons->user_fgets = (void *)r_core_fgets;
	return R_TRUE;
}

static int cb_scrhtml(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton ()->is_html = node->i_value;
	// TODO: control error and restore old value (return false?) show errormsg?
	return R_TRUE;
}

static int cb_scrhighlight(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_highlight (node->value);
	return R_TRUE;
}

static int cb_screcho(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->echo = node->i_value;
	return R_TRUE;
}

static int cb_scrint(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value && r_sandbox_enable (0)) {
		return R_FALSE;
	}
	r_cons_singleton()->is_interactive = node->i_value;
	return R_TRUE;
}

static int cb_scrnkey(void *user, void *data) {
	RConfigNode *node = (RConfigNode*) data;
	if (!strcmp (node->value, "help") || *node->value == '?') {
		r_cons_printf ("scr.nkey = fun, hit, flag\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int cb_scrprompt(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_line_singleton()->echo = node->i_value;
	return R_TRUE;
}

static int cb_scrrows(void* user, void* data) {
	RConfigNode *node = (RConfigNode*) data;
	int n = atoi (node->value);
	((RCore *)user)->cons->force_rows = n;
	return R_TRUE;
}

static int cb_contiguous(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->contiguous = node->i_value;
	return R_TRUE;
}

static int cb_searchalign(void *user, void *data) {
	RCore *core = (RCore *)user;
	RConfigNode *node = (RConfigNode *) data;
	core->search->align = node->i_value;
	core->print->addrmod = node->i_value;
	return R_TRUE;
}

static int cb_segoff(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (node->i_value)
		core->print->flags |= R_PRINT_FLAGS_SEGOFF;
	else core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SEGOFF));
	return R_TRUE;
}

static int cb_stopthreads(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->stop_all_threads = node->i_value;
	return R_TRUE;
}

static int cb_swstep(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->swstep = node->i_value;
	return R_TRUE;
}

static int cb_teefile(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	r_cons_singleton()->teefile = node->value;
	return R_TRUE;
}

static int cb_anal_trace(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->anal) {
		if (node->i_value && !core->anal->esil) {
			r_core_cmd0 (core, "aei");
		}
		core->anal->trace = node->i_value;
	}
	return R_TRUE;
}

static int cb_trace(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->enabled = node->i_value;
	return R_TRUE;
}

static int cb_tracetag(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->dbg->trace->tag = node->i_value;
	return R_TRUE;
}

static int cb_truecolor(void *user, void *data) {
	RConfigNode *node = (RConfigNode *) data;
	if (r_cons_singleton()->truecolor)
		r_cons_singleton()->truecolor = (node->i_value)? 2: 1;
	return R_TRUE;
}

static int cb_utf8(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->utf8 = node->i_value;
	return R_TRUE;
}

static int cb_zoombyte(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	switch (*node->value) {
		case 'p': case 'f': case 's': case '0':
		case 'F': case 'e': case 'h':
			core->print->zoom->mode = *node->value;
			break;
		default:
			eprintf ("Invalid zoom.byte value. See pz? for help\n");
			return R_FALSE;
	}
	return R_TRUE;
}

static int cb_rawstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	core->bin->rawstr = node->i_value;
	return R_TRUE;
}

static int cb_binmaxstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		if (v<1) v = 4; // HACK
		core->bin->maxstrlen = v;
	// TODO: Do not refresh if nothing changed (minstrlen ?)
		r_core_bin_refresh_strings (core);
		return R_TRUE;
	}
	return R_TRUE;
}

static int cb_binminstr(void *user, void *data) {
	RCore *core = (RCore *) user;
	RConfigNode *node = (RConfigNode *) data;
	if (core->bin) {
		int v = node->i_value;
		if (v<1) v = 4; // HACK
		core->bin->minstrlen = v;
	// TODO: Do not refresh if nothing changed (minstrlen ?)
		r_core_bin_refresh_strings (core);
		return R_TRUE;
	}
	return R_TRUE;
}

static int cb_searchin(void *user, void *data) {
 	RConfigNode *node = (RConfigNode*) data;
 	if (*node->value == '?') {
		r_cons_printf ("raw\nblock\nfile\nio.maps\nio.maprange\nio.section\n" \
							"io.sections\nio.sections.write\nio.sections.exec\n" \
							"dbg.stack\ndbg.heap\ndbg.map\ndbg.maps\n"\
							"dbg.maps.exec\ndbg.maps.write\nanal.fcn\nanal.bb\n");
 		return R_FALSE;
 	}
 	return R_TRUE;
}

static int cb_fileloadmethod(void *user, void *data) {
 	RConfigNode *node = (RConfigNode*) data;
 	if (*node->value == '?') {
 		r_cons_printf ("fail\noverwrite\nappend\n");
 		return R_FALSE;
 	}
 	return R_TRUE;
}

static int __dbg_swstep_getter(void *user, RConfigNode *node) {
	RCore *core = (RCore*)user;
	node->i_value = core->dbg->swstep;
	return 1;
}

static int cb_anal_gp(RCore *core, RConfigNode *node) {
	core->anal->gp = node->i_value;
	return 1;
}

static int cb_anal_from(RCore *core, RConfigNode *node) {
	if (r_config_get_i (core->config, "anal.limits")) {
		r_anal_set_limits (core->anal,
				r_config_get_i (core->config, "anal.from"),
				r_config_get_i (core->config, "anal.to"));
	}
	return 1;
}

static int cb_anal_limits(void *user, RConfigNode *node) {
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

#define SLURP_LIMIT (10*1024*1024)
R_API int r_core_config_init(RCore *core) {
	int i;
	char buf[128], *p, *tmpdir;
	RConfig *cfg = core->config = r_config_new (core);
	cfg->printf = r_cons_printf;
	cfg->num = core->num;

	/* pdb */
	SETPREF("pdb.user_agent", "Microsoft-Symbol-Server/6.11.0001.402", "User agent for Microsoft symbol server");
	SETPREF("pdb.server", "http://msdl.microsoft.com/download/symbols", "Base URL for Microsoft symbol server");
	SETI("pdb.extract", 1, "Avoid extract of the pdb file, just download");

	/* anal */
	SETPREF("anal.a2f", "false",  "Use the new WIP analysis algorithm (core/p/a2f), anal.depth ignored atm");
	SETICB("anal.gp", 0, (RConfigCallback)&cb_anal_gp, "Set the value of the GP register (MIPS)");
	SETCB("anal.limits", "false", (RConfigCallback)&cb_anal_limits, "Restrict analysis to address range [anal.from:anal.to]");
	SETICB("anal.from", -1, (RConfigCallback)&cb_anal_from, "Lower limit on the address range for analysis");
	SETICB("anal.to", -1, (RConfigCallback)&cb_anal_from, "Upper limit on the address range for analysis");

	SETCB("anal.eobjmp", "false", &cb_analeobjmp, "jmp is end of block mode (option)");
	SETCB("anal.afterjmp", "false", &cb_analafterjmp, "Continue analysis after jmp/ujmp");
	SETI("anal.depth", 16, "Max depth at code analysis"); // XXX: warn if depth is > 50 .. can be problematic
	SETICB("anal.sleep", 0, &cb_analsleep, "Sleep N usecs every so often during analysis. Avoid 100% CPU usage");
	SETPREF("anal.hasnext", "true", "Continue analysis after each function");
	SETPREF("anal.esil", "false", "Use the new ESIL code analysis");
	SETCB("anal.nopskip", "true", &cb_analnopskip, "Skip nops at the beginning of functions");
	SETCB("anal.bbsplit", "true", &cb_analbbsplit, "Use the experimental basic block split for JMPs");
	SETCB("anal.arch", R_SYS_ARCH, &cb_analarch, "Specify the anal.arch to use");
	SETCB("anal.cpu", R_SYS_ARCH, &cb_analcpu, "Specify the anal.cpu to use");
	SETPREF("anal.prelude", "", "Specify an hexpair to find preludes in code");
	SETCB("anal.split", "true", &cb_analsplit, "Split functions into basic blocks in analysis");
	SETCB("anal.recont", "false", &cb_analrecont, "End block after splitting a basic block instead of error"); // testing
	SETCB("anal.trace", "false", &cb_anal_trace, "Record ESIL trace in log database");
	SETI("anal.ptrdepth", 3, "Maximum number of nested pointers to follow in analysis");
	SETICB("anal.maxreflines", 0, &cb_analmaxrefs, "Maximum number of reflines to be analyzed and displayed in asm.lines with pd");

	SETCB("esil.debug", "false", &cb_esildebug, "Show ESIL debug info");
	SETICB("esil.gotolimit", core->anal->esil_goto_limit, &cb_gotolimit, "Maximum number of gotos per ESIL expression");

	/* asm */
	//asm.os needs to be first, since other asm.* depend on it
	SETCB("asm.os", R_SYS_OS, &cb_asmos, "Select operating system (kernel) (linux, darwin, w32,..)");
	SETI("asm.maxrefs", 5,  "Maximum number of xrefs to be displayed as list (use columns above)");
	SETPREF("asm.bytes", "true",  "Display the bytes of each instruction");
	SETPREF("asm.flagsinbytes", "false",  "Display flags inside the bytes space");
	SETPREF("asm.midflags", "true", "Realign disassembly if there is a flag in the middle of an instruction");
	SETPREF("asm.cmtflgrefs", "true", "Show comment flags associated to branch refenrece");
	SETPREF("asm.cmtright", "true", "Show comments at right of disassembly if they fit in screen");
	SETI("asm.cmtcol", 70, "Align comments at column 60");
	SETPREF("asm.calls", "true", "Show calling convention calls as comments in disasm");
	SETPREF("asm.comments", "true", "Show comments in disassembly view");
	SETPREF("asm.decode", "false", "Use code analysis as a disassembler");
	SETPREF("asm.indent", "false", "Indent disassembly based on reflines depth");
	SETPREF("asm.dwarf", "false", "Show dwarf comment at disassembly");
	SETPREF("asm.esil", "false", "Show ESIL instead of mnemonic");
	SETPREF("asm.filter", "true", "Replace numeric values by flags (e.g. 0x4003e0 -> sym.imp.printf)");
	SETPREF("asm.fcnlines", "true", "Show function boundary lines");
	SETPREF("asm.flags", "true", "Show flags");
	SETPREF("asm.lbytes", "true", "Align disasm bytes to left");
	SETPREF("asm.lines", "true", "Show ASCII-art lines at disassembly");
	SETPREF("asm.linescall", "false", "Enable call lines");
	SETPREF("asm.linesout", "true", "Show out of block lines");
	SETPREF("asm.linesright", "false", "Show lines before opcode instead of offset");
	SETPREF("asm.linesstyle", "false", "Iterate the jump list backwards");
	SETPREF("asm.lineswide", "false", "Put a space between lines");
	SETICB("asm.lineswidth", 7, &cb_asmlineswidth, "Number of columns for program flow arrows");
	SETPREF("asm.middle", "false", "Allow disassembling jumps in the middle of an instruction");
	SETPREF("asm.offset", "true", "Show offsets at disassembly");
	SETPREF("asm.reloff", "false", "Show relative offsets instead of absolute address in disasm");
	SETPREF("asm.section", "false", "Show section name before offset");
	SETPREF("asm.pseudo", "false", "Enable pseudo syntax");
	SETPREF("asm.size", "false", "Show size of opcodes in disassembly (pd)");
	SETPREF("asm.stackptr", "false", "Show stack pointer at disassembly");
	SETPREF("asm.cyclespace", "false", "Indent instructions depending on CPU-cycles");
	SETPREF("asm.cycles", "false", "Show CPU-cycles taken by instruction at disassembly");
	SETI("asm.tabs", 0, "Use tabs in disassembly");
	SETPREF("asm.trace", "false", "Show execution traces for each opcode");
	SETPREF("asm.tracespace", "false", "Indent disassembly with trace.count information");
	SETPREF("asm.ucase", "false", "Use uppercase syntax at disassembly");
	SETPREF("asm.vars", "true", "Show local function variables in disassembly");
	SETPREF("asm.varxs", "false", "Show accesses of local variables");
	SETPREF("asm.varsub", "true", "Substitute variables in disassembly");
	SETPREF("asm.cmtfold", "false", "Fold comments, toggle with Vz");
	SETCB("asm.arch", R_SYS_ARCH, &cb_asmarch, "Set the arch to be used by asm");
	SETCB("asm.features", "", &cb_asmfeatures, "Specify supported features by the target CPU (=? for help)");
	SETCB("asm.cpu", R_SYS_ARCH, &cb_asmcpu, "Set the kind of asm.arch cpu");
	SETCB("asm.parser", "x86.pseudo", &cb_asmparser, "Set the asm parser to use");
	SETCB("asm.segoff", "false", &cb_segoff, "Show segmented address in prompt (x86-16)");
	SETCB("asm.syntax", "intel", &cb_asmsyntax, "Select assembly syntax");
	SETI("asm.nbytes", 6, "Number of bytes for each opcode at disassembly");
	SETPREF("asm.bytespace", "false", "Separate hexadecimal bytes with a whitespace");
	SETICB("asm.bits", 32, &cb_asmbits, "Word size in bits at assembler");
	SETPREF("asm.functions", "true", "Show functions in disassembly");
	SETPREF("asm.fcncalls", "true", "Show functions calls");
	SETPREF("asm.xrefs", "true", "Show xrefs in disassembly");
	SETPREF("asm.demangle", "true", "Show demangled symbols in disasm");
	SETPREF("asm.describe", "false", "Show opcode description");
	SETCB("bin.force", "", &cb_binforce, "Force that rbin plugin");
	SETPREF("bin.lang", "", "Language for bin.demangle");
	SETPREF("bin.demangle", "false", "Import demangled symbols from RBin");

	/* bin */
	SETI("bin.baddr", 0, "Base address of the binary");
	SETI("bin.laddr", 0, "Base address for loading library ('*.so')");
	SETPREF("bin.dwarf", "true", "Load dwarf information on startup if available");
	SETICB("bin.minstr", 0, &cb_binminstr, "Minimum string length for r_bin");
	SETICB("bin.maxstr", 0, &cb_binmaxstr, "Maximum string length for r_bin");
	SETCB("bin.rawstr", "false", &cb_rawstr, "Load strings from raw binaries");
	SETPREF("bin.strings", "true", "Load strings from rbin on startup");

	/* cfg */
	r_config_set_cb (cfg, "cfg.bigendian", CFG_BIGENDIAN, &cb_bigendian);
	SETPREF("cfg.plugins", "true", "Load plugins at startup");
	r_config_desc (cfg, "cfg.bigendian", "Use little (false) or big (true) endiannes");
	SETCB("time.fmt", "%Y-%m-%d %H:%M:%S %z", &cb_cfgdatefmt, "Date format (%Y-%m-%d %H:%M:%S %z)");
	SETICB("time.zone", 0, &cb_timezone, "Time zone, in hours relative to GMT: +2, -1,..");
	SETCB("cfg.debug", "false", &cb_cfgdebug, "Debugger mode");
	p = r_sys_getenv ("EDITOR");
#if __WINDOWS__ && !__CYGWIN__
	r_config_set (cfg, "cfg.editor", p? p: "notepad");
#else
	r_config_set (cfg, "cfg.editor", p? p: "vi");
#endif
	free (p);
	r_config_desc (cfg, "cfg.editor", "Select default editor program");
	SETPREF("cfg.user", r_sys_whoami (buf), "Set current username/pid");
	SETPREF("cfg.fortunes", "true", "If enabled show tips at start");
	SETPREF("cfg.fortunetype", "tips,fun", "Type of fortunes to show (tips, fun, nsfw)");
	SETI("cfg.hashlimit", SLURP_LIMIT, "If the file is bigger than hashlimit, do not compute hashes");
	SETPREF("cfg.prefixdump", "dump", "Filename prefix for automated dumps");
	SETCB("cfg.sandbox", "false", &cb_cfgsanbox, "Sandbox mode disables systems and open on upper directories");
	SETPREF("cfg.wseek", "false", "Seek after write");

	/* diff */
	SETI("diff.from", 0, "Set source diffing address for px (uses cc command)");
	SETI("diff.to", 0, "Set destination diffing address for px (uses cc command)");
	SETPREF("diff.bare", "false", "Never show function names in diff output");

	/* dir */
	SETPREF("dir.magic", R_MAGIC_PATH, "Path to r_magic files");
	SETPREF("dir.plugins", R2_LIBDIR"/radare2/"R2_VERSION"/", "Path to plugin files to be loaded at startup");
	SETPREF("dir.source", "", "Path to find source files");
	SETPREF("dir.types", "/usr/include", "Default path to look for cparse type files");
#if __ANDROID__
	SETPREF("dir.projects", "/data/data/org.radare2.installer/radare2/projects", "Default path for projects");
#else
	SETPREF("dir.projects", "~/"R2_HOMEDIR"/projects", "Default path for projects");
#endif
	SETPREF("stack.bytes", "true", "Show bytes instead of words in stack");
	SETPREF("stack.anotated", "false", "Show anotated hexdump in visual debug");
	SETI("stack.size", 64,  "Size of anotated hexdump in visual debug");
	SETI("stack.delta", 0,  "Delta for the stack dump");

	SETCB("dbg.forks", "false", &cb_dbg_forks, "Stop execution if fork() is done (see dbg.threads)");
	SETCB("dbg.threads", "false", &cb_stopthreads, "Stop all threads when debugger breaks (see dbg.forks)");
	SETCB("dbg.clone", "false", &cb_dbg_clone, "Stop execution if new thread is created");
	SETCB("dbg.execs", "false", &cb_dbg_execs, "Stop execution if new thread is created");
	SETCB("dbg.profile", "", &cb_runprofile, "Path to RRunProfile file");
	/* debug */
	SETCB("dbg.status", "false", &cb_dbgstatus, "Set cmd.prompt to '.dr*' or '.dr*;drd;sr pc;pi 1;s-'");
	SETCB("dbg.backend", "native", &cb_dbgbackend, "Select the debugger backend");
	SETCB("dbg.bep", "loader", &cb_dbgbep, "break on entrypoint (loader, entry, constructor, main)");
	if (core->cons->rows>30) // HACKY
		r_config_set_i (cfg, "dbg.follow", 64);
	else r_config_set_i (cfg, "dbg.follow", 32);
	r_config_desc (cfg, "dbg.follow", "Follow program counter when pc > core->offset + dbg.follow");
	SETCB("dbg.swstep", "false", &cb_swstep, "Force use of software steps (code analysis+breakpoint)");

	r_config_set_getter (cfg, "dbg.swstep", (RConfigCallback)__dbg_swstep_getter);

// TODO: This should be specified at first by the debug backend when attaching
#if __arm__ || __mips__
	SETICB("dbg.bpsize", 4, &cb_dbgbpsize, "Size of software breakpoints");
#else
	SETICB("dbg.bpsize", 1, &cb_dbgbpsize, "Size of software breakpoints");
#endif
	SETCB("dbg.trace", "false", &cb_trace, "Trace program execution (see asm.trace)");
	SETICB("dbg.trace.tag", 0, &cb_tracetag, "Trace tag");

	/* cmd */
	if (r_file_exists ("/usr/bin/xdot"))
		r_config_set (cfg, "cmd.graph", "!xdot a.dot");
	else if (r_file_exists ("/usr/bin/open"))
		r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!open a.gif");
	else if (r_file_exists ("/usr/bin/gqview"))
		r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!gqview a.gif");
	else if (r_file_exists ("/usr/bin/eog"))
		r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!eog a.gif");
	else if (r_file_exists ("/usr/bin/xdg-open"))
		r_config_set (cfg, "cmd.graph", "!dot -Tgif -oa.gif a.dot;!xdg-open a.gif");
	else r_config_set (cfg, "cmd.graph", "?e cannot find a valid picture viewer");
	r_config_desc (cfg, "cmd.graph", "Command executed by 'agv' command to view graphs");
	SETPREF("cmd.xterm", "xterm -bg black -fg gray -e", "xterm command to spawn with V@");
	SETICB("cmd.depth", 10, &cb_cmddepth, "Maximum command depth");
	SETPREF("cmd.bp", "", "Run when a breakpoint is hit");
	SETPREF("cmd.times", "", "Run when a command is repeated (number prefix)");
	SETPREF("cmd.stack", "", "Command to display the stack in visual debug mode");
	SETPREF("cmd.cprompt", "", "Column visual prompt commands");
	SETPREF("cmd.gprompt", "", "Graph visual prompt commands");
	SETPREF("cmd.hit", "", "Run when a search hit is found");
	SETPREF("cmd.open", "", "Run when file is opened");
	SETPREF("cmd.prompt", "", "Prompt commands");
	SETCB("cmd.repeat", "true", &cb_cmdrepeat, "Alias newline (empty command) as '..'");
	SETPREF("cmd.fcn.new", "", "Run when new function is analyzed");
	SETPREF("cmd.fcn.delete", "", "Run when a function is deleted");
	SETPREF("cmd.fcn.rename", "", "Run when a function is renamed");
	SETPREF("cmd.visual", "", "Replace current print mode");
	SETPREF("cmd.vprompt", "", "Visual prompt commands");

	/* filesystem */
	SETCB("fs.view", "normal", &cb_fsview, "Set visibility options for filesystems");

	/* hexdump */
	SETCB("hex.pairs", "true", &cb_hexpairs, "Show bytes paired in 'px' hexdump");
	SETI("hex.flagsz", 0, "If non zero, overrides the flag size in pxa");
	SETICB("hex.cols", 16, &cb_hexcols, "Number of columns in hexdump");
	SETPREF("hex.onechar", "false", "Number of columns in hexdump");
	SETICB("hex.stride", 0, &cb_hexstride, "Line stride in hexdump (default is 0)");

	/* http */
	SETPREF("http.cors", "false", "Enable CORS");
	SETPREF("http.dirlist", "false", "Enable directory listing");
	SETPREF("http.allow", "", "Only accept clients from the comma separated IP list");
#if __WINDOWS__
	r_config_set (cfg, "http.browser", "start");
#else
	if (r_file_exists ("/usr/bin/openURL")) // iOS ericautils
		r_config_set (cfg, "http.browser", "/usr/bin/openURL");
	else if (r_file_exists ("/system/bin/toolbox"))
		r_config_set (cfg, "http.browser",
				"LD_LIBRARY_PATH=/system/lib am start -a android.intent.action.VIEW -d");
	else if (r_file_exists ("/usr/bin/xdg-open"))
		r_config_set (cfg, "http.browser", "xdg-open");
	else if (r_file_exists ("/usr/bin/open"))
		r_config_set (cfg, "http.browser", "open");
	else r_config_set (cfg, "http.browser", "firefox");
	r_config_desc (cfg, "http.browser", "Command to open HTTP URLs");
#endif
	SETI("http.maxsize", 0, "Maximum file size for upload");
	SETPREF("http.bind", "localhost", "Server address");
#if __WINDOWS__
	SETPREF("http.root", "www", "Root directory");
#else
	SETPREF("http.root", R2_WWWROOT, "Root directory");
#endif
	SETPREF("http.port", "9090", "Server port");
#if __ANDROID__ || __IPHONE_2_0
	SETPREF("http.ui", "enyo", "Default webui (enyo, p, t)");
#else
	SETPREF("http.ui", "p", "Default webui (enyo, p, t)");
#endif
	SETPREF("http.sandbox", "false", "Sandbox the HTTP server");
	SETI("http.timeout", 3, "Disconnect clients after N seconds of inactivity");
	SETI("http.dietime", 0, "Kill server after N seconds with no client");
	SETPREF("http.verbose", "true", "Output server logs to stdout");
	SETPREF("http.upget", "false", "/up/ answers GET requests, in addition to POST");
	SETPREF("http.upload", "false", "Enable file uploads to /up/<filename>");
	SETPREF("http.uri", "", "Address of HTTP proxy");
	tmpdir = r_file_tmpdir ();
	r_config_set (cfg, "http.uproot", tmpdir);
	free (tmpdir);
	r_config_desc(cfg, "http.uproot", "Path where files are uploaded");

	/* graph */
	SETPREF("graph.font", "Courier", "Font for dot graphs");
	SETPREF("graph.offset", "false", "Show offsets in graphs");
	SETPREF("graph.web", "false", "Display graph in web browser (VV)");
	SETI("graph.from", UT64_MAX, "");
	SETI("graph.to", UT64_MAX, "");

	/* hud */
	SETPREF("hud.path", "", "Set a custom path for the HUD file");

	SETPREF("esil.romem", "false", "Set memory as read-only for ESIL");
	SETPREF("esil.stats", "false", "Statistics from ESIL emulation stored in sdb");

	/* scr */
#if __EMSCRIPTEN__
	r_config_set_cb (cfg, "scr.fgets", "true", cb_scrfgets);
#else
	r_config_set_cb (cfg, "scr.fgets", "false", cb_scrfgets);
#endif
	r_config_desc (cfg, "scr.fgets", "Use fgets() instead of dietline for prompt input");
	SETCB("scr.echo", "false", &cb_screcho, "Show rcons output in realtime to stderr and buffer");
	SETPREF("scr.colorops", "true", "Colorize numbers and registers in opcodes");
#if __ANDROID__
	SETPREF("scr.responsive", "true", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
#else
	SETPREF("scr.responsive", "false", "Auto-adjust Visual depending on screen (e.g. unset asm.bytes)");
#endif
	SETPREF("scr.wheel", "true", "Mouse wheel in Visual; temporaryly disable/reenable by right click/Enter)");
	SETPREF("scr.atport", "false", "V@ starts a background http server and spawns an r2 -C");
	SETI("scr.wheelspeed", 1, "Mouse wheel speed");
	// DEPRECATED: USES hex.cols now SETI("scr.colpos", 80, "Column position of cmd.cprompt in visual");
	SETICB("scr.columns", 0, &cb_scrcolumns, "Force console column count (width)");
	SETCB("scr.rows", "0", &cb_scrrows, "Force console row count (height) ");
	SETICB("scr.rows", 0, &cb_rows, "Force console row count (height) (duplicate?)");
	SETCB("scr.fps", "false", &cb_fps, "Show FPS in Visual");
	SETICB("scr.fix_rows", 0, &cb_fixrows, "Workaround for Linux TTY");
	SETICB("scr.fix_columns", 0, &cb_fixcolumns, "Workaround for Prompt iOS SSH client");
	SETCB("scr.highlight", "", &cb_scrhighlight, "Highlight that word at RCons level");
	SETCB("scr.interactive", "true", &cb_scrint, "Start in interactive mode");
	SETI("scr.feedback", 1, "Set visual feedback level (1=arrow on jump, 2=every key (useful for videos))");
	SETCB("scr.html", "false", &cb_scrhtml, "Disassembly uses HTML syntax");
	SETCB("scr.nkey", "hit", &cb_scrnkey, "Select the seek mode in visual");
	SETCB("scr.pager", "", &cb_pager, "Select pager program (when output overflows the window)");
	SETPREF("scr.pipecolor", "false", "Enable colors when using pipes");
	SETPREF("scr.promptfile", "false", "Show user prompt file (used by r2 -q)");
	SETCB("scr.prompt", "true", &cb_scrprompt, "Show user prompt (used by r2 -q)");
	SETCB("scr.tee", "", &cb_teefile, "Pipe output to file of this name");
	SETPREF("scr.seek", "", "Seek to the specified address on startup");
#if __WINDOWS__ && !__CYGWIN__
	r_config_set_cb (cfg, "scr.rgbcolor", "false", &cb_rgbcolors);
#else
	r_config_set_cb (cfg, "scr.rgbcolor", "true", &cb_rgbcolors);
#endif
	r_config_desc (cfg, "scr.rgbcolor", "Use RGB colors (not available on Windows)");
	SETCB("scr.truecolor", "false", &cb_truecolor, "Manage color palette (0: ansi 16, 1: 256, 2: 16M)");
	SETCB("scr.color", (core->print->flags&R_PRINT_FLAGS_COLOR)?"true":"false", &cb_color, "Enable colors");
	SETCB("scr.null", "false", &cb_scrnull, "Show no output");
	SETCB("scr.utf8", r_cons_is_utf8()?"true":"false",
		&cb_utf8, "Show UTF-8 characters instead of ANSI");
	SETPREF("scr.histsave", "true", "Always save history on exit");
	/* search */
	SETCB("search.contiguous", "true", &cb_contiguous, "Accept contiguous/adjacent search hits");
	SETICB("search.align", 0, &cb_searchalign, "Only catch aligned search hits");
	SETI("search.chunk", 0, "Chunk size for /+ (default size is asm.bits/8");
	SETI("search.esilcombo", 8, "Stop search after N consecutive hits");
	SETI("search.count", 0, "Start index number at search hits");
	SETI("search.distance", 0, "Search string distance");
	SETPREF("search.flags", "true", "All search results are flagged, otherwise only printed");
	SETI("search.maxhits", 0, "Maximum number of hits (0: no limit)");
	SETI("search.from", -1, "Search start address");
	SETCB("search.in", "file", &cb_searchin, "Specify search boundaries (raw, block, file, section)");
	SETICB("search.kwidx", 0, &cb_search_kwidx, "Store last search index count");
	SETPREF("search.prefix", "hit", "Prefix name in search hits label");
	SETPREF("search.show", "true", "Show search results");
	SETI("search.to", -1, "Search end address");

	/* rop */
	SETI("rop.len", 5, "Maximum ROP gadget length");
	SETPREF("rop.subchains", "false", "Display every length gadget from rop.len=X to 2 in /Rl");
	SETPREF("rop.conditional", "false", "Include conditional jump, calls and returns in ropsearch");
	SETPREF("rop.nx", "false", "Include NX/XN/XD sections in ropsearch");

	/* io */
	SETICB("io.enforce", 0, &cb_ioenforce, "Honor IO section permissions for 1=read , 2=write, 0=none");
	SETCB("io.buffer", "false", &cb_iobuffer, "Load and use buffer cache if enabled");
	SETCB("io.sectonly", "false", &cb_iosectonly, "Only read from sections (if any)");
	SETI("io.buffer.from", 0, "Lower address of buffered cache");
	SETI("io.buffer.to", 0, "Higher address of buffered cache");
	SETCB("io.cache", "false", &cb_iocache, "Enable cache for io changes");
	SETCB("io.raw", "false", &cb_ioraw, "Ignore maps/sections and use raw io");
	SETCB("io.ff", "true", &cb_ioff, "Fill invalid buffers with 0xff instead of returning error");
	SETCB("io.va", "true", &cb_iova, "Use virtual address layout");
	SETCB("io.zeromap", "0", &cb_iozeromap, "Double map the last opened file to address zero");
	SETCB("io.autofd", "true", &cb_ioautofd, "Change fd when opening a new file");
	SETCB("io.vio", "false", &cb_iovio, "Enable the new vio (reading only) (WIP)");

	/* file */
	SETPREF("file.analyze", "false", "Analyze file on load. Same as r2 -c aa ..");
	SETPREF("file.desc", "", "User defined file description (used by projects)");
	SETPREF("file.md5", "", "MD5 sum of current file");
	SETPREF("file.path", "", "Path of current file");
	SETPREF("file.project", "", "Name of current project");
	SETPREF("file.sha1", "", "SHA1 hash of current file");
	SETPREF("file.type", "", "Type of current file");
	SETCB("file.loadmethod", "fail", &cb_fileloadmethod, "What to do when load addresses overlap: fail, overwrite, or append (next available)");
	SETI("file.loadalign", 1024, "Alignment of load addresses");
	SETI("file.openmany", 1, "Maximum number of files opened at once");
	SETPREF("file.nowarn", "true", "Suppress file loading warning messages");
	SETPREF("file.location", "", "Is the file 'local', 'remote', or 'memory'");
	/* magic */
	SETI("magic.depth", 100, "Recursivity depth in magic description strings");

	/* rap */
	SETPREF("rap.loop", "true", "Run rap as a forever-listening daemon");

	/* nkeys */
	for (i=1; i<13; i++) {
		snprintf (buf, sizeof (buf), "key.f%d", i);
		snprintf (buf+10, sizeof (buf)-10,
				"Run this when F%d key is pressed in visual mode", i);
		switch (i) {
			case 2: p = "dbs $$"; break;
			case 7: p = "ds"; break;
			case 8: p = "dso"; break;
			case 9: p = "dc"; break;
			default: p = ""; break;
		}
		r_config_set (cfg, buf, p);
		r_config_desc (cfg, buf, buf+10);
	}

	/* zoom */
	SETCB("zoom.byte", "h", &cb_zoombyte, "Zoom callback to calculate each byte (See pz? for help)");
	SETI("zoom.from", 0, "Zoom start address");
	SETI("zoom.maxsz", 512, "Zoom max size of block");
	SETI("zoom.to", 0, "Zoom end address");

	r_config_lock (cfg, R_TRUE);
	return R_TRUE;
}
