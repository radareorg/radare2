/* radare - LGPL - Copyright 2015 - pancake */

#include <r_anal.h>

R_API void r_space_new(RSpaces *s, const char *name, void (*unset_for)(void*,int), int (*count_for)(void*,int), void (*rename_for)(void*,int,const char*,const char*), void *user) {
	int i;
	s->name = r_str_new (name);
	s->space_idx = -1;
	s->spacestack = r_list_new ();
	s->cb_printf = (PrintfCallback)printf;
	s->unset_for = unset_for;
	s->count_for = count_for;
	s->rename_for = rename_for;
	s->user = user;
	for (i = 0; i < R_SPACES_MAX; i++) {
		s->spaces[i] = NULL;
	}
}

R_API void r_space_free(RSpaces *s) {
	int i;
	for (i = 0; i < R_SPACES_MAX; i++) {
		R_FREE (s->spaces[i]);
	}
	r_list_free (s->spacestack);
	free (s->name);
}

R_API int r_space_get(RSpaces *s, const char *name) {
	int i;
	if (!name || *name == '*') {
		return -1;
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (s->spaces[i] && !strcmp (name, s->spaces[i])) {
			return i;
		}
	}
	return -1;
}

R_API const char *r_space_get_i(RSpaces *s, int idx) {
	if (idx==-1 || idx>=R_SPACES_MAX) {
		return "";
	}
	return s->spaces[idx];
}

R_API int r_space_add(RSpaces *s, const char *name) {
	int i;
	if (!name || *name == '*') {
		return -1;
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (s->spaces[i] && !strcmp (name, s->spaces[i])) {
			return i;
		}
	}
	// not found
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!s->spaces[i]) {
			s->spaces[i] = strdup (name);
			return i;
		}
	}
	return -1;
}

R_API bool r_space_push(RSpaces *s, const char *name) {
	int ret = false;
	if (name && *name) {
		if (s->space_idx >= 0 && s->spaces[s->space_idx]) {
			r_list_push (s->spacestack, s->spaces[s->space_idx]);
		} else {
			r_list_push (s->spacestack, "*");
		}
		r_space_set (s, name);
		ret = true;
	}
	return ret;
}

R_API bool r_space_pop(RSpaces *s) {
	char *p = r_list_pop (s->spacestack);
	if (p) {
		if (*p) {
			r_space_set (s, p);
		}
		return true;
	}
	return false;
}

R_API int r_space_set(RSpaces *s, const char *name) {
	s->space_idx = r_space_add (s, name);
	return s->space_idx;
}

R_API int r_space_unset (RSpaces *s, const char *name) {
	int i, count = 0;
	if (!name) {
		r_space_set (s, NULL);
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!s->spaces[i]) {
			continue;
		}
		if (!name || !strcmp (name, s->spaces[i])) {
			if (s->space_idx == i) {
				s->space_idx = -1;
			}
			R_FREE (s->spaces[i]);
			if (s->unset_for) {
				s->unset_for (s, i);
			}
			count++;
		}
	}
	return count;
}

static int r_space_count (RSpaces *s, int n) {
	if (s->count_for) {
		return s->count_for (s, n);
	}
	return 0;
}

R_API int r_space_list(RSpaces *s, int mode) {
	const char *defspace = NULL;
	int count, len, i, j = 0;
	if (mode == 'j') {
		s->cb_printf ("[");
	}
	for (i = 0; i < R_SPACES_MAX; i++) {
		if (!s->spaces[i]) {
			continue;
		}
		count = r_space_count (s, i);
		if (mode == 'j') {
			s->cb_printf ("%s{\"name\":\"%s\"%s,\"count\":%d}",
				j? ",": "", s->spaces[i],
				(i == s->space_idx)? ",\"selected\":true": "",
				count);
		} else if (mode == '*') {
			s->cb_printf ("%s %s\n", s->name, s->spaces[i]);
			if (i == s->space_idx) {
				defspace = s->spaces[i];
			}
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
			s->cb_printf ("%s%s %s %c %s\n", num0, spaces, num1,
					(i == s->space_idx)? '*': '.',
					s->spaces[i]);
		}
		j++;
	}
	if (defspace) {
		s->cb_printf ("%s %s # current\n", s->name, defspace);
	}
	if (mode == 'j') {
		s->cb_printf ("]\n");
	}
	return j;
}

R_API bool r_space_rename (RSpaces *s, const char *oname, const char *nname) {
	int i;

	if (!oname) {
		if (s->space_idx == -1) {
			return false;
		}
		oname = s->spaces[s->space_idx];
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

	if (r_space_get (s, nname) != -1) {
		eprintf ("error: dupplicated name\n");
		return false;
	}

	for (i = 0; i < R_SPACES_MAX; i++) {
		if (s->spaces[i] && !strcmp (oname, s->spaces[i])) {
			if (s->rename_for) {
				s->rename_for (s, i, oname, nname);
			}
			free (s->spaces[i]);
			s->spaces[i] = strdup (nname);
			return true;
		}
	}
	return false;
}
