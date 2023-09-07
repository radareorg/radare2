/* radare - LGPL - Copyright 2023 - pancake */

#include <r_core.h>

typedef void (*treefcn)(RCore *core, int indent, const char *itype, const char *input);

static ut64 itemcmp(const void* _a) {
	const char* a = _a;
	return r_str_hash64 (a);
}
static void tree_files(RCore *core, int indent, const char *itype, const char *input) {
	RListIter *iter;
	if (itype && input) {
		//
	} else {
		RList *files = r_list_newf (free);
		char *file;
		RBinFile *bf = core->bin->cur;
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
			r_cons_printf ("%s%c %s\n", pad, '-', file);
		}
		r_list_free (files);
	}
}

static void tree_functions(RCore *core, int indent, const char *itype, const char *input) {
	RListIter *iter;
	RAnalFunction *fcn;
	if (itype && input) {
		//
	} else {
		r_list_foreach (core->anal->fcns, iter, fcn) {
			const char *pad = r_str_pad (' ', indent);
			r_cons_printf ("%s%c 0x%08"PFMT64x" %s\n", pad, '-', fcn->addr, fcn->name);
		}
	}
}

R_API void r_print_list(RCore *core, const char *input) {
	int level = 0;
	RList *levels = r_list_newf (NULL);
	char *oargstr = strdup (input);
	char *argstr = oargstr;
	char *arg = r_str_after (argstr, ' ');
	ut64 cur = core->offset;
	bool dash = false;
	while (*argstr) {
		switch (*argstr) {
		case '-':
			dash = true;
			// ignored on purpose
			break;
		case ' ':
			goto done;
		case 'l':
			r_list_append (levels, tree_files); //  (core, indent, cur));
			break;
		case 'f':
			r_list_append (levels, tree_functions); //  (core, indent, cur));
			break;
		default:
			break;
		}
		argstr++;
	}
done:
	free (oargstr);
	RListIter *iter;
	void *entry;
	// RPrintTreeCallback ptcb;
	treefcn ptcb;
	RList *root = NULL;
	int indent = 0;
	r_list_foreach (levels, iter, ptcb) {
		ptcb (core, indent, NULL, NULL);
		r_list_foreach (root, iter, entry) {
			r_cons_printf ("L0 ..\n");
		}
		indent ++;
	}
}
