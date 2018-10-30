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

R_API int r_flag_space_unset(RFlag *f, const char *fs) {
	RListIter *iter;
	RFlagItem *fi;
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
	if (n != -1) {
		r_list_foreach (f->flags, iter, fi) {
			if (fi->space == n) {
				count++;
			}
		}
	}
	return count;
}

R_API int r_flag_space_list(RFlag *f, int mode) {
	r_return_val_if_fail (f, -1);
	const char *defspace = NULL;
	int count, len, i, j = 0;
	bool allSelected = f->space_idx == -1;
	if (mode == 'j') {
		f->cb_printf ("[");
	}
	for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
		if (!f->spaces[i]) {
			continue;
		}
		count = r_flag_space_count (f, i);
		if (mode == 'q') {
			f->cb_printf ("%s\n", f->spaces[i]);
		} else if (mode == 'j') {
			f->cb_printf ("%s{\"name\":\"%s\",\"count\":%d,\"selected\":%s}",
					j? ",":"", f->spaces[i], count,
					(allSelected || i == f->space_idx)? "true":"false");
		} else if (mode=='*') {
			f->cb_printf ("fs %s\n", f->spaces[i]);
			if (i == f->space_idx) {
				defspace = f->spaces[i];
			}
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
					(allSelected || i==f->space_idx)?'*':'.',
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

static void print_space_stack(RFlag *f, int ordinal, char *name, bool selected, int mode) {
	bool first = ordinal == 0;
	switch (mode) {
	case 'j':
		if (!first) {
			f->cb_printf (",");
		}
		{
		char *ename = r_str_escape (name);
		f->cb_printf ("{\"ordinal\":%d,\"name\":\"%s\",\"selected\":%s}",
			ordinal, ename, selected? "true":"false");
		free (ename);
		}
		break;
	case '*':
		if (first) {
			f->cb_printf ("fs %s\n", name);
		} else {
			f->cb_printf ("fs+%s\n", name);
		}
		break;
	default:
		f->cb_printf ("%-2d %s%s\n", ordinal, name, selected? " (selected)":"");
		break;
	}
}

R_API int r_flag_space_stack_list(RFlag *f, int mode) {
	RListIter *iter;
	char *space;
	int i = 0;
	if (mode == 'j') {
		f->cb_printf ("[");
	}
	r_list_foreach (f->spacestack, iter, space) {
		print_space_stack (f, i++, space, false, mode);
	}
	if (f->space_idx == -1) {
		print_space_stack (f, i++, "*", true, mode);
	} else {
		if (f->spaces[f->space_idx]) {
			print_space_stack (f, i++, f->spaces[f->space_idx], true, mode);
		}
	}
	if (mode == 'j') {
		f->cb_printf ("]\n");
	}
	return i;
}
