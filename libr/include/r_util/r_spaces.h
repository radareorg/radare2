#ifndef R_SPACES_H
#define R_SPACES_H

#define R_SPACES_MAX 512

typedef struct r_space_t {
	char *name;
	int space_idx;
	char *spaces[R_SPACES_MAX];
	RList *spacestack; // metaspaces
	PrintfCallback cb_printf;
	void (*unset_for)(void *user, int idx);
	int (*count_for)(void *user, int idx);
	void *user;
} RSpaces;

R_API void r_space_init(RSpaces *s, const char *name, void (*unset_for)(void*,int), int (*count_for)(void*,int), void *user);
R_API void r_space_fini(RSpaces *s);
R_API int r_space_get(RSpaces *s, const char *name);
R_API const char *r_space_get_i(RSpaces *s, int idx);
R_API int r_space_push(RSpaces *s, const char *name);
R_API int r_space_pop(RSpaces *s);
R_API int r_space_set(RSpaces *s, const char *name);
R_API int r_space_unset(RSpaces *s, const char *fs);
R_API int r_space_list(RSpaces *s, int mode);
R_API int r_space_rename(RSpaces *s, const char *oname, const char *nname);
#endif //  R_SPACES_H
