#ifndef R_SPACES_H
#define R_SPACES_H

#define R_SPACES_MAX 512

typedef struct r_space_t {
	int space_idx;
	int space_idx2;
	char *spaces[R_SPACES_MAX];
	RList *spacestack; // metaspaces
	PrintfCallback cb_printf;
	void (*unset_for)(void *user, int idx);
	int (*count_for)(void *user, int idx);
	void *user;
} RSpaces;

R_API void r_space_init(RSpaces *f, void (*unset_for)(void*, int), int (*count_for)(void *,int), void *user);
R_API void r_space_fini(RSpaces *f);
R_API int r_space_get(RSpaces *f, const char *name);
R_API const char *r_space_get_i(RSpaces *f, int idx);
R_API int r_space_push(RSpaces *f, const char *name);
R_API int r_space_pop(RSpaces *f);
R_API int r_space_set(RSpaces *f, const char *name);
R_API int r_space_unset(RSpaces *f, const char *fs);
R_API int r_space_list(RSpaces *f, int mode);
R_API int r_space_rename(RSpaces *f, const char *oname, const char *nname);
#endif //  R_SPACES_H
