#ifndef R_SPACES_H
#define R_SPACES_H

#define R_SPACES_MAX 512

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_space_t {
	char *name;
	int space_idx;
	char *spaces[R_SPACES_MAX];
	RList *spacestack;
	PrintfCallback cb_printf;
	void (*unset_for)(void *user, int idx);
	int (*count_for)(void *user, int idx);
	void (*rename_for)(void *user, int idx, const char *oname, const char *nname);
	void *user;
} RSpaces;

R_API void r_space_new(RSpaces *s, const char *name, void (*unset_for)(void*,int), int (*count_for)(void*,int), void (*rename_for)(void*,int,const char*,const char*), void *user);
R_API void r_space_free(RSpaces *s);
R_API int r_space_get(RSpaces *s, const char *name);
R_API const char *r_space_get_i(RSpaces *s, int idx);
R_API int r_space_add(RSpaces *s, const char *name);
R_API bool r_space_push(RSpaces *s, const char *name);
R_API bool r_space_pop(RSpaces *s);
R_API int r_space_set(RSpaces *s, const char *name);
R_API int r_space_unset (RSpaces *s, const char *name);
R_API int r_space_list(RSpaces *s, int mode);
R_API bool r_space_rename (RSpaces *s, const char *oname, const char *nname);

#ifdef __cplusplus
}
#endif

#endif //  R_SPACES_H
