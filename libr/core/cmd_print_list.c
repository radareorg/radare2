/* radare - LGPL - Copyright 2023-2024 - pancake */

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

static ut64 itemcmp(const void* _a) {
	const char* a = _a;
	return r_str_hash64 (a);
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
	RList *files = r_list_newf (free);
	char *file;
	RBinFile *bf = r_bin_cur (ts->core->bin);
	if (!bf) {
		R_LOG_WARN ("Unable to find current bin file");
		return;
	}
	SdbList *ls = sdb_foreach_list (bf->sdb_addrinfo, false);
	// Use the parsed information from _raw and transform it to more useful format
	SdbListIter *sdbiter;
	SdbKv *kv;
	ls_foreach (ls, sdbiter, kv) {
		const char *key = kv->base.key;
		if (strchr (key, '/') || r_str_endswith (key, ".c")) {
			char *s = strdup (key);
			r_str_after (s, '|');
			const char *lastslash = r_str_rchr (s, "/", -1);
			if (lastslash) {
				r_list_append (files, strdup (lastslash + 1));
				free (s);
			} else {
				r_list_append (files, s);
			}
		}
	}
	r_list_sort (files, (RListComparator)strcmp);
	r_list_uniq_inplace (files, (RListComparatorItem)itemcmp);
	r_list_foreach (files, iter, file) {
		const char *pad = r_str_pad (' ', indent);
		r_kons_printf (ts->core->cons, "%s%c %s\n", pad, '+', file);
		RList *children = functions_for_file (ts, file);
		char *fcnstr;
		r_list_foreach (children, iter2, fcnstr) {
			const char *pad = r_str_pad (' ', indent + 2);
			r_kons_printf (ts->core->cons, "%s%c %s\n", pad, '-', fcnstr);
		}
		r_list_free (children);
	}
	r_list_free (files);
}

static void tree_functions(struct treestate *ts, int indent) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (ts->core->anal->fcns, iter, fcn) {
		const char *pad = r_str_pad (' ', indent);
		r_kons_printf (ts->core->cons, "%s%c 0x%08"PFMT64x" %s\n", pad, '-', fcn->addr, fcn->name);
	}
}

R_API void r_print_list(RCore *core, const char *input) {
	TreeState ts = {0};
	ts.core = core;
	// int level = 0;
	char *oargstr = strdup (input);
	char *argstr = oargstr;
	// char *arg = r_str_after (argstr, ' ');
	//bool dash = false;
	while (*argstr) {
		if (ts.layers > 3) {
			R_LOG_ERROR ("too many layers");
			break;
		}
		switch (*argstr) {
		case '-':
			// dash = true;
			// ignored on purpose
			break;
		case ' ':
			goto done;
		case 'l':
			ts.layer[ts.layers++] = (treefcn)&tree_files;
			break;
		case 'f':
			ts.layer[ts.layers++] = (treefcn)&tree_functions;
			break;
		default:
			break;
		}
		argstr++;
	}
done:
	free (oargstr);
	// RListIter *iter;
	// RPrintTreeCallback ptcb;
	treefcn ptcb = ts.layer[0];
	// ts.layer[0](&ts, 0);
	if (ptcb != NULL) {
		ptcb (&ts, 0);
	}
#if 0
	void *entry;
	RList *root = NULL;
	r_list_foreach (ts.levels, iter, ptcb) {
		ptcb (core, indent, NULL, NULL);
		r_list_foreach (root, iter, entry) {
			r_kons_printf ("L0 ..\n");
		}
		indent ++;
	}
#endif
}
