/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_flag.h>
#include <r_cons.h>

R_API int r_flag_space_get(RFlag *f, const char *name) {
	int i;
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] != NULL) {
			if (!strcmp (name, f->spaces[i])) {
				return i;
			}
		}
	}	
	return -1;
}

R_API const char *r_flag_space_get_i(RFlag *f, int idx) {
	if (idx == -1 || idx >= R_FLAG_SPACES_MAX || !f || !f->spaces[idx] || !*f->spaces[idx]) {
		return "";
	}
	return f->spaces[idx];
}

R_API const char *r_flag_space_cur(RFlag *f) {
	return r_flag_space_get_i (f, f->space_idx);
}

R_API int r_flag_space_push(RFlag *f, const char *name) {
	int ret = false;
	if (name && *name) {
		if (f->space_idx != -1 && f->spaces[f->space_idx]) {
			r_list_push (f->spacestack, f->spaces[f->space_idx]);
		} else {
			r_list_push (f->spacestack, "*");
		}
		r_flag_space_set (f, name);
		ret = true;
	}
	return ret;
}

R_API int r_flag_space_pop(RFlag *f) {
	char *p = r_list_pop (f->spacestack);
	if (p) {
		if (*p) {
			r_flag_space_set (f, p);
		}
		return true;
	}
	return false;
}

R_API int r_flag_space_set(RFlag *f, const char *name) {
	int i;
	if (!name || *name == '*') {
		f->space_idx = -1;
		return f->space_idx;
	}

	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] != NULL && !strcmp (name, f->spaces[i])) {
			f->space_idx = i;
			return f->space_idx;
		}
	}
	/* not found */
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			f->spaces[i] = strdup (name);
			f->space_idx = i;
			break;
		}
	}
	return f->space_idx;
}

R_API int r_flag_space_unset (RFlag *f, const char *fs) {
	RListIter *iter;
	RFlagItem *fi;
	int i, count = 0;
	for (i = 0; i<R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			continue;
		}
		if (!fs || !strcmp (fs, f->spaces[i])) {
			if (f->space_idx == i) {
				f->space_idx = -1;
			}
			R_FREE (f->spaces[i]);
			// remove all flags space references
			r_list_foreach (f->flags, iter, fi) {
				if (fi->space == i) {
					fi->space = -1;
				}
			}
			count++;
		}
	}
	return count;
}

static int r_flag_space_count(RFlag *f, int n) {
	RListIter *iter;
	int count = 0;
	RFlagItem *fi;
	if (n!=-1) {
		r_list_foreach (f->flags, iter, fi) {
			if (fi->space == n) {
				count++;
			}
		}
	}
	return count;
}

R_API int r_flag_space_list(RFlag *f, int mode) {
	const char *defspace = NULL;
	int count, len, i, j = 0;
	if (mode == 'j')
		f->cb_printf ("[");
	for (i=0; i<R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) continue;
		count = r_flag_space_count (f, i);
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
			memset(spaces, ' ', sizeof (spaces));
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

R_API int r_flag_space_rename (RFlag *f, const char *oname, const char *nname) {
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
	while (*oname==' ') oname++;
	while (*nname==' ') nname++;
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i]  && !strcmp (oname, f->spaces[i])) {
			free (f->spaces[i]);
			f->spaces[i] = strdup (nname);
			return true;
		}
	}
	return false;
}
