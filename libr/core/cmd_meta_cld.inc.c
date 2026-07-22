/* radare2 - LGPL - Copyright 2009-2026 - nibble, pancake */

// Included by cmd_meta.inc.c -- implements the CLd command family: a source
// view of the current function reconstructed from the DWARF address<->line
// metadata (the same data behind CL). The output is wrapped in an RCodeMeta so
// it renders just like the other decompilers (pdc/pdd/pdg), can be plugged via
// `cmd.pdc=CLd` and consumed by frontends like iaito.

static RCoreHelpMessage help_msg_CLd = {
	"Usage: CLd", "[aoj*]", "decompile current function using DWARF line info (see CL, dir.source)",
	"CLd", "", "show reconstructed source for the current function",
	"CLda", "", "side by side disassembly and source columns",
	"CLdo", "", "show the associated offset next to each source line",
	"CLdj", "", "codemeta json with offset annotations (for frontends like iaito)",
	"CLd*", "", "emit CC comments mapping each address to its source line",
	NULL
};

typedef struct {
	ut64 addr; // lowest instruction address mapped to this source line
	char *cmt; // CC comments accumulated from the mapped addresses (or NULL)
} CLdLine;

static void cld_line_free(HtUPKv *kv) {
	CLdLine *cl = kv->value;
	if (cl) {
		free (cl->cmt);
		free (cl);
	}
}

typedef struct {
	char *file; // source file path as referenced by the addrline metadata
	ut64 min_addr; // lowest address seen for this file (used to order files)
	ut32 minline;
	ut32 maxline;
	HtUP *lines; // ut32 line -> CLdLine*
} CLdFile;

static void cld_file_free(CLdFile *f) {
	if (f) {
		free (f->file);
		ht_up_free (f->lines);
		free (f);
	}
}

static int cld_file_cmp(const void *a, const void *b) {
	const CLdFile *fa = a;
	const CLdFile *fb = b;
	if (fa->min_addr < fb->min_addr) {
		return -1;
	}
	return (fa->min_addr > fb->min_addr)? 1: 0;
}

static CLdFile *cld_file_get(RList *files, const char *file, ut64 addr, ut32 line) {
	RListIter *iter;
	CLdFile *f;
	r_list_foreach (files, iter, f) {
		if (!strcmp (f->file, file)) {
			return f;
		}
	}
	f = R_NEW0 (CLdFile);
	if (!f) {
		return NULL;
	}
	f->file = strdup (file);
	f->lines = ht_up_new (NULL, cld_line_free, NULL);
	f->min_addr = addr;
	f->minline = f->maxline = line;
	r_list_append (files, f);
	return f;
}

// resolve the on-disk path for a dwarf-referenced source file, honoring
// dir.source and dir.source.base. returns NULL when no readable file is found
static char *cld_resolve_path(RBin *bin, const char *file) {
	if (R_STR_ISEMPTY (file)) {
		return NULL;
	}
	char *filename = strdup (file);
	if (R_STR_ISNOTEMPTY (bin->srcdir_base) && r_str_startswith (filename, bin->srcdir_base)) {
		char *fn = strdup (filename + strlen (bin->srcdir_base));
		free (filename);
		filename = fn;
	}
	if (!r_file_exists (filename)) {
		const char *base = r_file_basename (file);
		if (strcmp (filename, base) && r_file_exists (base)) {
			free (filename);
			filename = strdup (base);
		} else if (R_STR_ISNOTEMPTY (bin->srcdir)) {
			char *nf = r_str_newf ("%s/%s", bin->srcdir, base);
			if (r_file_exists (nf)) {
				free (filename);
				filename = nf;
			} else {
				free (nf);
			}
		}
	}
	if (!r_file_exists (filename)) {
		R_FREE (filename);
	}
	return filename;
}

// gather, per source file, the lowest address and comments associated to each
// source line touched by the instructions of the given function
static RList *cld_collect(RCore *core, RAnalFunction *fcn) {
	RList *files = r_list_newf ((RListFree)cld_file_free);
	if (!files) {
		return NULL;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		int i;
		for (i = 0; i < bb->ninstr; i++) {
			ut64 addr = r_anal_bb_opaddr_i (bb, i);
			if (addr == UT64_MAX) {
				continue;
			}
			const RBinAddrline *al = r_bin_addrline_get (core->bin, addr);
			if (!al || al->line == 0) {
				continue;
			}
			const char *file = r_bin_addrline_str (core->bin, al->file);
			if (R_STR_ISEMPTY (file)) {
				continue;
			}
			CLdFile *f = cld_file_get (files, file, addr, al->line);
			if (!f) {
				continue;
			}
			if (addr < f->min_addr) {
				f->min_addr = addr;
			}
			if (al->line < f->minline) {
				f->minline = al->line;
			}
			if (al->line > f->maxline) {
				f->maxline = al->line;
			}
			CLdLine *cl = ht_up_find (f->lines, al->line, NULL);
			if (cl) {
				if (addr < cl->addr) {
					cl->addr = addr;
				}
			} else {
				cl = R_NEW0 (CLdLine);
				cl->addr = addr;
				ht_up_insert (f->lines, al->line, cl);
			}
			const char *cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (R_STR_ISNOTEMPTY (cmt)) {
				if (cl->cmt) {
					if (!strstr (cl->cmt, cmt)) {
						char *nc = r_str_newf ("%s; %s", cl->cmt, cmt);
						free (cl->cmt);
						cl->cmt = nc;
					}
				} else {
					cl->cmt = strdup (cmt);
				}
			}
		}
	}
	r_list_sort (files, cld_file_cmp);
	return files;
}

typedef struct {
	size_t start;
	size_t end;
	ut64 offset;
} CLdAnno;

static void cld_anno_add(RList *annos, size_t start, size_t end, ut64 offset) {
	if (end <= start) {
		return;
	}
	CLdAnno *a = R_NEW0 (CLdAnno);
	if (a) {
		a->start = start;
		a->end = end;
		a->offset = offset;
		r_list_append (annos, a);
	}
}

#define CLD_MAX_SPAN 0x10000

static RCodeMeta *cld_build(RCore *core, RAnalFunction *fcn) {
	RList *files = cld_collect (core, fcn);
	if (!files) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	RList *annos = r_list_newf (free);

	// header comment: tells the user (and iaito) which source maps here, so a
	// missing file can be created with cfg.editor and addr<->file registered
	const RBinAddrline *al0 = r_bin_addrline_get (core->bin, fcn->addr);
	const char *hdrfile = al0? r_bin_addrline_str (core->bin, al0->file): NULL;
	if (!hdrfile && !r_list_empty (files)) {
		hdrfile = ((CLdFile *)r_list_first (files))->file;
	}
	size_t hstart = r_strbuf_length (sb);
	if (al0 && al0->line > 0) {
		r_strbuf_appendf (sb, "// %s:%u @ 0x%08"PFMT64x" %s",
			r_str_get_fail (hdrfile, "?"), al0->line, fcn->addr, fcn->name);
	} else {
		r_strbuf_appendf (sb, "// %s @ 0x%08"PFMT64x" %s",
			r_str_get_fail (hdrfile, "?"), fcn->addr, fcn->name);
	}
	cld_anno_add (annos, hstart, r_strbuf_length (sb), fcn->addr);
	r_strbuf_append (sb, "\n");

	const bool multi = r_list_length (files) > 1;
	RListIter *iter;
	CLdFile *f;
	r_list_foreach (files, iter, f) {
		if (multi) {
			size_t sstart = r_strbuf_length (sb);
			r_strbuf_appendf (sb, "// --- %s ---", f->file);
			cld_anno_add (annos, sstart, r_strbuf_length (sb), f->min_addr);
			r_strbuf_append (sb, "\n");
		}
		char *path = cld_resolve_path (core->bin, f->file);
		ut32 maxline = f->maxline;
		if (maxline - f->minline > CLD_MAX_SPAN) {
			R_LOG_WARN ("CLd: source line span for %s is too large, truncating", f->file);
			maxline = f->minline + CLD_MAX_SPAN;
		}
		ut32 line;
		for (line = f->minline; line <= maxline; line++) {
			CLdLine *cl = ht_up_find (f->lines, line, NULL);
			if (!path && !cl) {
				// no source on disk: only emit references for mapped lines
				continue;
			}
			char *text = path? r_file_slurp_line (path, line, 0): NULL;
			size_t lstart = r_strbuf_length (sb);
			if (text) {
				r_strbuf_append (sb, text);
			} else if (!path && cl) {
				r_strbuf_appendf (sb, "// %s:%u", r_file_basename (f->file), line);
			}
			size_t lend = r_strbuf_length (sb);
			if (cl && cl->cmt) {
				char *c = strdup (cl->cmt);
				r_str_replace_ch (c, '\n', ' ', true);
				r_str_replace_ch (c, '\r', ' ', true);
				r_strbuf_appendf (sb, "%s// %s", (lend > lstart)? "  ": "", c);
				free (c);
			}
			r_strbuf_append (sb, "\n");
			free (text);
			if (cl) {
				// annotate the source text (so CLd* maps it as a CC comment) or
				// the whole emitted line when there is no text on this line
				size_t aend = (lend > lstart)? lend: r_strbuf_length (sb);
				cld_anno_add (annos, lstart, aend, cl->addr);
			}
		}
		free (path);
	}
	r_list_free (files);

	char *codestr = r_strbuf_drain (sb);
	RCodeMeta *cm = r_codemeta_new (codestr);
	free (codestr);
	if (cm) {
		CLdAnno *a;
		r_list_foreach (annos, iter, a) {
			RCodeMetaItem item = {0};
			item.type = R_CODEMETA_TYPE_OFFSET;
			item.start = a->start;
			item.end = a->end;
			item.offset.offset = a->offset;
			r_codemeta_add_item (cm, &item);
		}
	}
	r_list_free (annos);
	return cm;
}

static int cmd_meta_lineinfo_decompile(RCore *core, const char *input) {
	const char mode = *input;
	if (mode == '?') {
		r_cons_cmd_help (core->cons, help_msg_CLd);
		return 0;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, R_ANAL_FCN_TYPE_NULL);
	if (!fcn) {
		R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, core->addr);
		r_core_return_code (core, 1);
		return 1;
	}
	RCodeMeta *cm = cld_build (core, fcn);
	if (!cm) {
		r_core_return_code (core, 1);
		return 1;
	}
	char *out = NULL;
	RVecCodeMetaOffset *los = NULL;
	switch (mode) {
	case 'j': // "CLdj"
		out = r_codemeta_print_json (cm);
		if (out) {
			r_cons_println (core->cons, out);
		}
		break;
	case '*': // "CLd*"
		out = r_codemeta_print_comment_cmds (cm);
		if (out) {
			r_cons_print (core->cons, out);
		}
		break;
	case 'a': // "CLda"
		los = r_codemeta_line_offsets (cm);
		out = r_codemeta_print_disasm (cm, los, core->anal);
		if (out) {
			r_cons_print (core->cons, out);
		}
		break;
	case 'o': // "CLdo"
		los = r_codemeta_line_offsets (cm);
		out = r_codemeta_print2 (cm, los, core->anal);
		if (out) {
			r_cons_print (core->cons, out);
		}
		break;
	default: // "CLd"
		out = r_codemeta_print2 (cm, NULL, core->anal);
		if (out) {
			r_cons_print (core->cons, out);
		}
		break;
	}
	RVecCodeMetaOffset_free (los);
	free (out);
	r_codemeta_free (cm);
	r_core_return_code (core, 0);
	return 0;
}
