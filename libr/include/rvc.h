/* radare - LGPL - Copyright 2021 - RHL120, pancake */

#ifndef R_RVC_H
#define R_RVC_H 1
#define BPREFIX "branches."

#ifdef __cplusplus
extern "C" {
#endif

#include <r_core.h>
#include <sdb.h>
typedef struct RvcBlob_t {
	char *fname;
	char *fhash;
} RvcBlob;

R_API bool r_vc_git_init(const char *path);
R_API bool r_vc_git_branch(const char *path, const char *name);
R_API bool r_vc_git_checkout(const char *path, const char *name);
R_API bool r_vc_git_add(const char *path, const char *fname);
R_API bool r_vc_git_commit(const char *path, const char *message);

R_API bool r_vc_commit(const char *rp, const char *message, const char *author, const RList *files);
R_API bool r_vc_branch(const char *rp, const char *bname);
R_API bool r_vc_new(const char *path);
R_API bool r_vc_checkout(const char *rp, const char *bname);
R_API RList *r_vc_get_branches(const char *rp);
R_API RList *r_vc_get_uncommitted(const char *rp);
R_API RList *r_vc_log(const char *rp);
R_API char *r_vc_current_branch(const char *rp);
R_API bool r_vc_reset(const char *rp);
R_API bool r_vc_clone(const char *src, const char *dst);

R_API bool rvc_git_init(const RCore *core, const char *rp);
R_API bool rvc_git_commit(RCore *core, const char *rp, const char *message, const char *author, const RList *files);
R_API bool rvc_git_branch(const RCore *core, const char *rp, const char *bname);
R_API bool rvc_git_checkout(const RCore *core, const char *rp, const char *bname);
R_API bool rvc_git_repo_exists(const RCore *core, const char *rp);

#ifdef __cplusplus
}
#endif

#endif
