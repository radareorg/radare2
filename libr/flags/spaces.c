/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_flags.h>

R_API const char *r_flag_space_get(struct r_flag_t *f, int idx) {
	if (idx==-1 || idx>255 || f->space[idx]=='\0')
		return "";
	return f->space[idx];
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

R_API void r_flag_space_set(RFlag *f, const char *name) {
	int i;
	if (name == NULL || *name == '*') {
		f->space_idx = -1;
		return;
	}

	for (i=0;i<R_FLAG_SPACES_MAX;i++) {
		if (f->space[i] != NULL)
		if (!strcmp (name, f->space[i])) {
			f->space_idx = i; //flag_space_idx = i;
			return;
		}
	}
	/* not found */
	for(i=0;i<R_FLAG_SPACES_MAX;i++) {
		if (f->space[i] == NULL) {
			f->space[i] = strdup (name);
			f->space_idx = i;
			break;
		}
	}
}

R_API void r_flag_space_list(RFlag *f) {
	int i,j = 0;
	for(i=0;i<R_FLAG_SPACES_MAX;i++) {
		if (f->space[i])
			printf("%02d %c %s\n", j++,
			(i==f->space_idx)?'*':' ', f->space[i]);
	}
}
