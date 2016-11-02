/* radare - LGPL - Copyright 2015 - pancake */

#include <r_anal.h>

R_API int r_space_get(RSpaces *f, const char *name) {
	int i;
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (f->spaces[i]) {
			if (!strcmp (name, f->spaces[i])) {
				return i;
			}
		}
	}
	return -1;
}

R_API const char *r_space_get_i (RSpaces *f, int idx) {
	if (idx==-1 || idx>=R_SPACES_MAX|| !f || !f->spaces[idx] || !*f->spaces[idx]) {
		return "";
	}
	return f->spaces[idx];
}

R_API void r_space_init(RSpaces *f, void (*unset_for)(void*,int), int (*count_for)(void*,int), void *user) {
	int i;
	f->space_idx = -1;
	f->space_idx2 = -1;
	f->spacestack = r_list_new ();
	f->cb_printf = (PrintfCallback)printf;
	f->unset_for = unset_for;
	f->count_for = count_for;
	f->user = user;
	for (i = 0; i < R_SPACES_MAX; i++) {
		f->spaces[i] = NULL;
	}
}

R_API void r_space_fini(RSpaces *f) {
	int i;
	for (i = 0; i < R_SPACES_MAX; i++) {
		R_FREE (f->spaces[i]);
	}
	r_list_free (f->spacestack);
}

R_API int r_space_push(RSpaces *f, const char *name) {
	int ret = false;
	if (name && *name) {
		if (f->space_idx != -1 && f->spaces[f->space_idx]) {
			r_list_push (f->spacestack, f->spaces[f->space_idx]);
		} else {
			r_list_push (f->spacestack, "*");
		}
		r_space_set (f, name);
		ret = true;
	}
	return ret;
}

R_API int r_space_pop(RSpaces *f) {
	char *p = r_list_pop (f->spacestack);
	if (p) {
		if (*p) {
			r_space_set (f, p);
		}
		return true;
	}
	return false;
}

R_API int r_space_set(RSpaces *f, const char *name) {
	int i;
	if (!name || *name == '*') {
		f->space_idx = -1;
		return f->space_idx;
	}

	for (i = 0; i < R_SPACES_MAX; i++) {
		if (f->spaces[i] != NULL)
		if (!strcmp (name, f->spaces[i])) {
			f->space_idx = i;
			return f->space_idx;
		}
	}
	/* not found */
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			f->spaces[i] = strdup (name);
			f->space_idx = i;
			break;
		}
	}
	return f->space_idx;
}

R_API int r_space_unset (RSpaces *f, const char *fs) {
	int i, count = 0;
	if (!fs) {
		return r_space_set (f, NULL);
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			continue;
		}
		if (!fs || !strcmp (fs, f->spaces[i])) {
			if (f->space_idx == i) {
				f->space_idx = -1;
			}
			if (f->space_idx2 == i) {
				f->space_idx2 = -1;
			}
			R_FREE (f->spaces[i]);
			if (f->unset_for) {
				f->unset_for (f, i);
			}
			count++;
		}
	}
	return count;
}

static int r_space_count (RSpaces *f, int n) {
	if (f->count_for) {
		return f->count_for (f, n);
	}
	return 0;
}

R_API int r_space_list(RSpaces *f, int mode) {
	const char *defspace = NULL;
	int count, len, i, j = 0;
	if (mode == 'j') {
		f->cb_printf ("[");
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!f->spaces[i]) continue;
		count = r_space_count (f, i);
		if (mode=='j') {
			f->cb_printf ("%s{\"name\":\"%s\"%s,\"count\":%d}",
					j? ",":"", f->spaces[i],
					(i==f->space_idx)? ",\"selected\":true":"",
					count);
		} else if (mode=='*') {
			f->cb_printf ("fs %s\n", f->spaces[i]);
			if (i==f->space_idx) defspace = f->spaces[i];
		} else {
			#define INDENT 5
			char num0[64], num1[64], spaces[32];
			snprintf (num0, sizeof (num0), "%d", i);
			snprintf (num1, sizeof (num1), "%d", count);
			memset (spaces, ' ', sizeof (spaces));
			len = strlen (num0) + strlen (num1);
			if (len < INDENT) {
				spaces[INDENT-len] = 0;
			} else {
				spaces[0] = 0;
			}
			f->cb_printf ("%s%s %s %c %s\n", num0, spaces, num1,
					(i==f->space_idx)?'*':'.',
					f->spaces[i]);
		}
		j++;
	}
	if (defspace) {
		f->cb_printf ("fs %s # current\n", defspace);
	}
	if (mode == 'j') {
		f->cb_printf ("]\n");
	}
	return j;
}

R_API int r_space_rename (RSpaces *f, const char *oname, const char *nname) {
	int i;
	if (!oname) {
		if (f->space_idx == -1) {
			return false;
		}
		oname = f->spaces[f->space_idx];
	}
	if (!nname) {
		return false;
	}
	while (*oname==' ') {
		oname++;
	}
	while (*nname==' ') {
		nname++;
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (f->spaces[i]  && !strcmp (oname, f->spaces[i])) {
			free (f->spaces[i]);
			f->spaces[i] = strdup (nname);
			return true;
		}
	}
	return false;
}
