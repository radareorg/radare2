/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#ifndef R_RVC_H
#define R_RVC_H 1


#ifdef __cplusplus
extern "C" {
#endif

#include <r_core.h>
#include <sdb.h>
typedef struct RvcBlob_t {
	char *fname;
	char *fhash;
} RvcBlob;
R_API int r_vc_git_init(const char *path);
R_API bool r_vc_git_branch(const char *path, const char *name);
R_API bool r_vc_git_checkout(const char *path, const char *name);
R_API int r_vc_git_add(const char *path, const char *fname);
R_API int r_vc_git_commit(const char *path, const char *message);

R_API bool r_vc_commit(const char *rp, const char *message, const char *author, const RList *files);
R_API bool r_vc_branch(const char *rp, const char *bname);
R_API bool r_vc_new(const char *path);
R_API bool r_vc_checkout(const char *rp, const char *bname);
R_API RList *r_vc_get_branches(const char *rp);
R_API char *r_vc_find_rp(const char *path);

R_API int r_vc_git_commit(const char *path, const char *message);
R_API int rvc_git_init(RCore *core, const char *rp);
R_API int rvc_git_commit(RCore *core, const char *rp, const char *message, const char *author, const RList *files);
R_API int rvc_git_branch(RCore *core, const char *rp, const char *bname);
R_API int rvc_git_checkout(RCore *core, const char *rp, const char *bname);
#ifdef __cplusplus
}
#endif

#endif
