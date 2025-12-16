/* radare - LGPL - Copyright 2023 - pancake, condret */

#include <r_arch.h>

static char *getroot(void) {
	return r_file_new (r_sys_prefix (NULL), R2_PLATFORM, NULL);
}

R_API char *r_arch_platform_unset(RArch *arch, const char *name) {
	R_RETURN_VAL_IF_FAIL (arch, NULL);
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	char *root = getroot ();
	char *fini = r_str_newf ("%s/%s-fini.r2", root, name);
	free (root);
	if (!r_file_exists (fini)) {
		R_FREE (fini);
		// r_core_cmdf (core, ". %s", fini);
	}
	return fini;
}

R_API char *r_arch_platform_set(RArch *arch, const char *name) {
	R_RETURN_VAL_IF_FAIL (arch, NULL);
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	char *root = getroot ();
	char *init = r_str_newf ("%s/%s-init.r2", root, name);
	if (r_file_exists (init)) {
		R_FREE (arch->platform);
		arch->platform = strdup (name);
	} else {
		R_FREE (init);
	}
	free (root);
	return init;
}

// TODO return list or char *
R_API void r_arch_platform_list(RArch *arch) {
	R_RETURN_IF_FAIL (arch);
	RListIter *iter;
	char *item;
	char *root = getroot ();
	RList *list = r_sys_dir (root);
	r_list_foreach (list, iter, item) {
		if (*item != '.' && r_str_endswith (item, "-init.r2")) {
			r_str_after (item, '-');
			if (*item) {
				printf ("%s\n", item);
			}
		}
	}
	r_list_free (list);
	free (root);
}
