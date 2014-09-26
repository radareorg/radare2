/* radare - LGPL - Copyright 2008-2013 - pancake */

#include <r_flags.h>
#include <r_cons.h>

R_API int r_flag_space_get(RFlag *f, const char *name) {
	int i;
	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] != NULL)
			if (!strcmp (name, f->spaces[i]))
				return i;
	}
	return -1;
}

R_API const char *r_flag_space_get_i (RFlag *f, int idx) {
	if (idx==-1 || idx>255 || !f || !f->spaces[idx] || !*f->spaces[idx])
		return "";
	return f->spaces[idx];
}

#if 0
void flag_space_init(struct r_flag_t *f) {
	static int init = 0;
	int i;
	if (init)
		return;
	init = 1;
	for(i=0;i<R_FLAG_SPACES_MAX;i++)
		f->space[i] = NULL;
}
#endif

R_API int r_flag_space_set(RFlag *f, const char *name) {
	int i;
	if (name == NULL || *name == '*') {
		f->space_idx = -1;
		return f->space_idx;
	}

	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] != NULL)
		if (!strcmp (name, f->spaces[i])) {
			f->space_idx = i;
			return f->space_idx;
		}
	}
	/* not found */
	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] == NULL) {
			f->spaces[i] = strdup (name);
			f->space_idx = i;
			break;
		}
	}
	return f->space_idx;
}

R_API int r_flag_space_list(RFlag *f, int mode) {
	const char *defspace = NULL;
	int i, j = 0;
	if (mode == 'j')
		r_cons_printf ("[");
	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) continue;
		if (mode=='j') {
			r_cons_printf ("%s{\"name\":\"%s\"%s}",
					j? ",":"", f->spaces[i],
					(i==f->space_idx)?
					",\"selected\":true":"");
		} else if (mode=='*') {
			r_cons_printf ("fs %s\n", f->spaces[i]);
			if (i==f->space_idx) defspace = f->spaces[i];
		} else {
			r_cons_printf ("%02d %c %s\n", j++,
					(i==f->space_idx)?'*':' ',
					f->spaces[i]);
		}
		j++;
	}
	if (defspace)
		r_cons_printf ("fs %s # current\n", defspace);
	if (mode == 'j')
		r_cons_printf ("]\n");
	return j;
}

R_API int r_flag_space_rename (RFlag *f, const char *oname, const char *nname) {
	int i;
	if (!oname) {
		if (f->space_idx == -1)
			return R_FALSE;
		oname = f->spaces[f->space_idx];
	}
	if (!nname) return R_FALSE;
	while (*oname==' ') oname++;
	while (*nname==' ') nname++;
	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i]  && !strcmp (oname, f->spaces[i])) {
			free (f->spaces[i]);
			f->spaces[i] = strdup (nname);
			return R_TRUE;
		}
	}
	return R_FALSE;
}
