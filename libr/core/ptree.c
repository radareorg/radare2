/* radare - LGPL - Copyright 2023 - pancake */

#include <r_core.h>

typedef void (*treefcn)(Rcore *core, int indent, const char *itype, const char *input);

static void tree_functions(RCore *core, int indent, const char *itype, const char *input) {
	RListIter *iter;
	RAnalFunction *fcn;
	if (itype && input) {
		if (true) {
		}
	} else {
		r_list_foreach (core->anal->fcns, iter, fcn) {
			const char *pad = r_str_pad (' ', indent);
			r_cons_printf ("%s%c 0x%08"PFMT64x" %s\n", pad, fcn->addr, fcn->name);
		}
	}
}

R_API void r_print_tree(RCore *core, const char *input) {
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
	RPrintTreeCallback ptcb;
	RList *root = NULL;
	r_list_foreach (root, iter, ptcb) {
		ptcb ();
		r_cons_printf ("L0 ..\n");
		r_list_foreach (root, iter, entry) {
			r_cons_printf ("L0 ..\n");
		}
	}
}
