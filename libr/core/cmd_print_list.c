/* radare - LGPL - Copyright 2023-2026 - pancake */

#include <r_core.h>

struct treestate;
typedef void (*treefcn)(struct treestate *ts, int indent);

typedef struct treestate {
	RCore *core;
	int level;
	int layers;
	treefcn layer[4];
	RList list[4];
} TreeState;

static ut64 itemcmp(const void* a) {
	return r_str_hash64 ((const char *)a);
}

static RList *functions_for_file(TreeState *ts, const char *file) {
	RList *list = r_list_newf (free);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (ts->core->anal->fcns, iter, fcn) {
		if (strstr (fcn->name, ".str.") || strstr (fcn->name, "JTI")) {
			continue;
		}
		char *s = r_core_cmd_strf (ts->core, "CLf @ 0x%08"PFMT64x, fcn->addr);
		r_str_trim (s);
		if (s && *s && strstr (file, s)) {
			char *fstr = r_str_newf ("0x%08"PFMT64x" %s", fcn->addr, fcn->name);
			r_list_append (list, fstr);
			if (r_list_length (list) > 5) {
				break;
			}
		}
		free (s);
	}
	return list;
}

static void tree_files(struct treestate *ts, int indent) {
	RListIter *iter, *iter2;
	char *file;
	RBinFile *bf = r_bin_cur (ts->core->bin);
	if (!bf) {
		R_LOG_WARN ("Unable to find current bin file");
		return;
	}
	RList *files = r_bin_addrline_files (ts->core->bin);
	r_list_sort (files, (RListComparator)strcmp);
	r_list_uniq_inplace (files, (RListComparatorItem)itemcmp);
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (files, iter, file) {
		r_strbuf_pad (sb, ' ', indent);
		r_strbuf_appendf (sb, "%c %s\n", '+', file);
		RList *children = functions_for_file (ts, file);
		char *fcnstr;
		r_list_foreach (children, iter2, fcnstr) {
			r_strbuf_pad (sb, ' ', indent + 2);
			r_strbuf_appendf (sb, "%c %s\n", '-', fcnstr);
		}
		r_list_free (children);
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (ts->core->cons, s);
	free (s);
	r_list_free (files);
}

static void tree_functions(struct treestate *ts, int indent) {
	RListIter *iter;
	RAnalFunction *fcn;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (ts->core->anal->fcns, iter, fcn) {
		r_strbuf_pad (sb, ' ', indent);
		r_strbuf_appendf (sb, "%c 0x%08"PFMT64x" %s\n", '-', fcn->addr, fcn->name);
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (ts->core->cons, s);
	free (s);
}

R_API void r_print_list(RCore *core, const char *input) {
	TreeState ts = {0};
	ts.core = core;
	char *oargstr = strdup (input);
	char *argstr = oargstr;
	while (*argstr) {
		if (ts.layers > 3) {
			R_LOG_ERROR ("too many layers");
			break;
		}
		const char a = *argstr;
		if (a == ' ') {
			break;
		}
		if (a == 'l') {
			ts.layer[ts.layers++] = (treefcn)&tree_files;
		} else if (a == 'f') {
			ts.layer[ts.layers++] = (treefcn)&tree_functions;
		}
		argstr++;
	}
	free (oargstr);
	treefcn ptcb = ts.layer[0];
	if (ptcb != NULL) {
		ptcb (&ts, 0);
	}
}
