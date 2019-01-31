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
	r_return_val_if_fail (f, NULL);
	return r_flag_space_get_i (f, f->space_idx);
}

R_API bool r_flag_space_push(RFlag *f, const char *name) {
	r_return_val_if_fail (f && name, false);
	if (f->space_idx != -1 && f->spaces[f->space_idx]) {
		r_list_push (f->spacestack, f->spaces[f->space_idx]);
	} else {
		r_list_push (f->spacestack, "*");
	}
	r_flag_space_set (f, name);
	return true;
}

R_API bool r_flag_space_pop(RFlag *f) {
	r_return_val_if_fail (f, false);
	char *p = r_list_pop (f->spacestack);
	if (p) {
		if (*p) {
			r_flag_space_set (f, p);
		}
		return true;
	}
	return false;
}

R_API bool r_flag_space_set_i(RFlag *f, int idx) {
	int i;
	r_return_val_if_fail (f, false);
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i]) {
			f->space_idx = idx;
			return true;
		}
	}
	return false;
}

R_API int r_flag_space_set(RFlag *f, const char *name) {
	int i;
	if (!name || !*name || *name == '*') {
		f->space_idx = -1;
		return f->space_idx;
	}
	if (f->space_idx != -1) {
		if (!strcmp (name, f->spaces[f->space_idx])) {
			return f->space_idx;
		}
	}
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i] && !strcmp (name, f->spaces[i])) {
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

static bool unset_space(RFlagItem *fi, void *user) {
	fi->space = -1;
	return true;
}

R_API int r_flag_space_unset(RFlag *f, const char *fs) {
	r_return_val_if_fail (f, false);
	int i, count = 0;
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			continue;
		}
		if (!fs || !strcmp (fs, f->spaces[i])) {
			if (f->space_idx == i) {
				f->space_idx = -1;
			}
			R_FREE (f->spaces[i]);
			// remove all flags space references
			r_flag_foreach_space (f, i, unset_space, NULL);
			count++;
		}
	}
	return count;
}

static bool space_count(RFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

R_API int r_flag_space_count(RFlag *f, int n) {
	int count = 0;
	if (n != -1) {
		r_flag_foreach_space (f, n, space_count, &count);
	}
	return count;
}

R_API bool r_flag_space_rename (RFlag *f, const char *oname, const char *nname) {
	int i;
	r_return_val_if_fail (f && nname, false);
	if (!oname) {
		if (f->space_idx == -1) {
			return false;
		}
		oname = f->spaces[f->space_idx];
	}
	oname = r_str_trim_ro (oname);
	nname = r_str_trim_ro (nname);
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (f->spaces[i]  && !strcmp (oname, f->spaces[i])) {
			free (f->spaces[i]);
			f->spaces[i] = strdup (nname);
			return true;
		}
	}
	return false;
}
